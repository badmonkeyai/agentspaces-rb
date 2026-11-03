# frozen_string_literal: true

# Copyright 2026 Bad Monkey, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "securerandom"

module AgentSpaces
  module Capabilities
    # The agent side of the connector protocol (srad/agentspaces-js.md
    # JS-C-14, the Ruby twin of Java's DataQueryClient and AssetInvocations
    # and of the Python client's capabilities.connect): the
    # aspace:cap/data-query entries of DataQueryEntries.java and the
    # aspace:cap/asset-invoke entries of appendix F as Entry classes in Java
    # record order, so Space#write encodes the bytes the Java codec writes
    # (golden data_query_cbor, data_result_cbor, asset_change_cbor,
    # asset_invocation_cbor, asset_invocation_result_cbor); the canonical
    # query hash; a DataQueryClient that fetches by asset and parameters
    # pull-once; and AssetInvocations.invoke, one operation on an asset
    # through its card. A result counts only when its issuer is trusted
    # (ASF-009): the connectors the caller names, or, for an invocation, the
    # card's issuer. Readers drop the fields they do not know (JS-F-06). The
    # connector half (ConnectorRuntime) stays in Java and TypeScript.
    #
    #   client = DataQueryClient.new(peer, "analyst", trusted_connectors: [card["issuer"]])
    #   fetched = client.fetch("orders", { "region" => "eu" }, timeout: "30s")
    #   result = AssetInvocations.invoke(client.space, card, "reserve", { "sku" => "A-1", "qty" => "2" })
    module Connect
      # The schema names the Java SimpleSchemaRegistry gives the records: the binary class name plus #v1.
      DATA_QUERY_TYPE = "ai.badmonkey.agentspaces.connect.DataQueryEntries$DataQuery#v1"
      DATA_RESULT_TYPE = "ai.badmonkey.agentspaces.connect.DataQueryEntries$DataResult#v1"
      ASSET_CHANGE_TYPE = "ai.badmonkey.agentspaces.connect.DataQueryEntries$AssetChange#v1"
      ASSET_INVOCATION_TYPE = "ai.badmonkey.agentspaces.connect.AssetInvocations$AssetInvocation#v1"
      ASSET_INVOCATION_RESULT_TYPE = "ai.badmonkey.agentspaces.connect.AssetInvocations$AssetInvocationResult#v1"

      # The capability types the cards name in their access map, and the ad type the cards travel as.
      DATA_QUERY_CAPABILITY = "aspace:cap/data-query"
      ASSET_INVOKE_CAPABILITY = "aspace:cap/asset-invoke"
      ASSET_CARD_TYPE = "AssetCard"
      DEFAULT_DATA_SPACE = "data" # DataSpaces.DEFAULT_NAME

      ASSET_INVOKE_VERSION = 1 # AssetInvocations.VERSION (appendix F, JS-F-06)
      INVOKE_OPS = "invoke-ops" # the access key listing a card's operations, a comma list

      # The error codes an AssetInvocationResult carries when ok is false (appendix F).
      INVOKE_ERRORS = %w[unknown-operation bad-params refused-scope target-error timeout].freeze

      module_function

      # A string-to-string map as the wire carries it: every key and value a
      # String, the entries in canonical (wire v3) order.
      def canonical_strings(value)
        CBOR.canonical_map((value || {}).to_h { |k, v| [k.to_s, v.to_s] })
      end

      # DataQueryEntries.canonicalHash: multibase(sha-256) over the asset name
      # and the parameters in sorted key order, so parameter ordering never
      # splits the pull-once cache. Keys sort as Java's TreeMap<String> sorts
      # them, by UTF-16 code unit.
      def canonical_hash(asset, parameters)
        canonical = +asset.to_s
        (parameters || {}).map { |k, v| [k.to_s, v] }.sort_by { |k, _| k.encode(Encoding::UTF_16BE).b }
                          .each { |key, value| canonical << "|#{key}=#{value}" }
        Derive.id(canonical.encode(Encoding::UTF_8).b)
      end

      # The live AssetCards the ads stream carried, or only those of one asset.
      def asset_cards(peer, asset = nil)
        now = peer.now_ms
        peer.ads.values.filter_map do |e|
          e["ad"] if e["type"] == ASSET_CARD_TYPE && e["expires"] > now && (asset.nil? || e["ad"]["asset"] == asset)
        end
      end

      # AssetInvocations.invokeOps: the operations a card allows, its
      # invoke-ops comma list trimmed, in card order.
      def invoke_ops(card)
        listed = (card["access"] || {})[INVOKE_OPS] || ""
        listed.to_s.split(",").map(&:strip).reject(&:empty?)
      end

      # The peer id of an issuer agent id ("<peer>/<name>").
      def peer_of(issuer) = issuer.to_s.split("/", 2).first.to_s

      # One awaited entry: set by a watch callback on the reader thread, read
      # by the waiter, then re-read from the space between folds so a result
      # whose fold landed before the subscription, or whose block arrived
      # late, is found (DataQueryClient.await in Java, the read-through loop
      # in TypeScript).
      class Answer
        def initialize
          @lock = Mutex.new
          @ready = false
          @value = nil
        end

        def accept(value)
          @lock.synchronize do
            next if @ready

            @value = value
            @ready = true
          end
        end

        # The block is the trusted read of the space; returns the first value
        # from either source, or nil at the timeout. The space is pulled at
        # most once per read-through window and the wait wakes on a fold (JS-V-02).
        def wait(space, read_through, timeout)
          peer = space.peer
          read_through_seconds = Durations.seconds(read_through)
          deadline = monotonic + Durations.seconds(timeout)
          loop do
            seen = peer.fold_count
            ready, value = @lock.synchronize { [@ready, @value] }
            return value if ready

            found = yield
            return found unless found.nil?

            remaining = deadline - monotonic
            return nil if remaining <= 0

            peer.pull_space_paced(space.name, read_through_seconds)
            peer.await_fold([read_through_seconds, remaining].min, since: seen)
          end
        end

        private

        def monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    end

    # One query awaiting a connector (DataQueryEntries.DataQuery): the
    # canonical hash of (asset, parameters), the asset name from the card,
    # the parameters, and the asking agent for the audit trail.
    DataQuery = Entry.define(Connect::DATA_QUERY_TYPE, query_hash: String, asset: String, parameters: Hash,
                                                       requester: String) do
      def initialize(**values)
        super(**values, parameters: Connect.canonical_strings(values[:parameters]))
      end
    end

    # One answered query, leased for its freshness window
    # (DataQueryEntries.DataResult): rows as column-to-value maps, an error
    # message when the query failed (nil on success), and the connector that
    # executed against the source.
    DataResult = Entry.define(Connect::DATA_RESULT_TYPE, query_hash: String, asset: String, rows: [Hash],
                                                         error: String, served_by: String) do
      def initialize(**values)
        super(**values, rows: Array(values[:rows]).map { |row| Connect.canonical_strings(row) }.freeze)
      end
    end

    # One change a materializing provider pushed (DataQueryEntries.AssetChange),
    # leased for the asset's freshness window so the lease is the retention
    # policy; subscribe with Template.new(AssetChange, where: { asset: name }).
    AssetChange = Entry.define(Connect::ASSET_CHANGE_TYPE, asset: String, key: String, row: Hash,
                                                           served_by: String) do
      def initialize(**values)
        super(**values, row: Connect.canonical_strings(values[:row]))
      end
    end

    # One operation an agent asks a connector to run (appendix F,
    # AssetInvocations.AssetInvocation). v leads the record on the wire and
    # defaults to the current version when a sender omits it; invocation_id
    # is minted once by the client and constant across retries and takers,
    # so a target deduplicates on it (JS-C-04). Build it with keywords: v
    # comes first in member order.
    AssetInvocation = Entry.define(Connect::ASSET_INVOCATION_TYPE, v: Object, asset: String, operation: String,
                                                                   params: Hash, invocation_id: String) do
      def initialize(**values)
        super(**values, v: values[:v].nil? ? Connect::ASSET_INVOKE_VERSION : values[:v],
                        params: Connect.canonical_strings(values[:params]))
      end
    end

    # The connector's answer to an AssetInvocation (appendix F,
    # AssetInvocations.AssetInvocationResult), correlated by invocation_id.
    # When ok is false, error is one of Connect::INVOKE_ERRORS and result
    # carries rule (the rule that refused) and detail. ok is true only for
    # true itself, as in the Python client.
    AssetInvocationResult = Entry.define(Connect::ASSET_INVOCATION_RESULT_TYPE, v: Object, invocation_id: String,
                                                                                asset: String, operation: String,
                                                                                ok: Object, result: Hash,
                                                                                error: String) do
      def initialize(**values)
        super(**values, v: values[:v].nil? ? Connect::ASSET_INVOKE_VERSION : values[:v], ok: values[:ok] == true,
                        result: Connect.canonical_strings(values[:result]))
      end

      # An error result naming the rule that refused the invocation.
      def self.refused(invocation, error, rule, detail)
        new(invocation_id: invocation.invocation_id, asset: invocation.asset, operation: invocation.operation,
            ok: false, result: { "rule" => rule, "detail" => detail }, error: error)
      end
    end

    # One fetch's answer (DataQueryClient.Fetched): the result and whether a
    # live space result answered it with no new query.
    Fetched = Data.define(:result, :from_cache) do
      def from_cache? = from_cache
    end

    # The DataQueryClient of Java: fetch by asset and parameters, pull-once
    # by canonical hash. A live result under the hash answers at once and
    # costs the source nothing; otherwise a DataQuery is written and the
    # connector's DataResult awaited. trusted_connectors names the connector
    # peers whose results count (the issuers of their signed AssetCards);
    # empty accepts any admitted peer's. trust (a callable over issuer_peer
    # and asset) replaces that set with the caller's own rule (the shape of
    # the Java authorizer's CONNECTOR_SERVE check). The counters make the
    # economics observable: cache_hits is money the abstraction returned.
    class DataQueryClient
      attr_reader :peer, :requester, :space, :trust, :query_lease, :read_through, :cache_hits, :queries_sent

      def initialize(peer, requester, data_space: Connect::DEFAULT_DATA_SPACE, trusted_connectors: [], trust: nil,
                     query_lease: "1m", read_through: "100ms", agent: nil)
        @peer = peer
        @requester = requester
        @space = Space.new(peer, data_space, agent: agent, agent_name: requester)
        trusted = Set.new(trusted_connectors || [])
        @trust = trust || ->(issuer_peer, _asset) { trusted.empty? || trusted.include?(issuer_peer) }
        @query_lease = query_lease
        @read_through = read_through
        @cache_hits = 0   # fetches answered by a live space result, with no source execution
        @queries_sent = 0 # fetches that wrote a query entry for a connector to execute
      end

      # Fetches one asset query, pull-once: a trusted live result for the
      # canonical hash answers at once; otherwise a query is written and the
      # connector's result awaited. nil when no connector answered in time.
      def fetch(asset, parameters = {}, timeout: "30s")
        query_hash = Connect.canonical_hash(asset, parameters)
        template = Template.new(DataResult, where: { query_hash: query_hash })
        live = read_trusted(template)
        unless live.nil?
          @cache_hits += 1
          return Fetched.new(result: live, from_cache: true)
        end
        answer = Connect::Answer.new
        # Subscribe before writing the query so the answer cannot slip between
        # the write and the wait; the listener applies the same issuer filter.
        subscription = @space.watch(template) do |event|
          answer.accept(event.value) if event.kind == WRITTEN && trusted?(event.item.issuer, event.value)
        end
        begin
          @queries_sent += 1
          @space.write(DataQuery.new(query_hash: query_hash, asset: asset, parameters: parameters,
                                     requester: @requester), lease: @query_lease)
          result = answer.wait(@space, @read_through, timeout) { read_trusted(template) }
        ensure
          subscription.close
        end
        result.nil? ? nil : Fetched.new(result: result, from_cache: false)
      end

      def inspect = "#<AgentSpaces::Capabilities::DataQueryClient #{@requester}>"

      private

      def trusted?(issuer, result) = @trust.call(Connect.peer_of(issuer), result.asset) ? true : false

      def read_trusted(template)
        @space.entries(template, limit: 16).each { |e| return e.value if trusted?(e.issuer, e.value) }
        nil
      end
    end

    # AssetInvocations (appendix F): invoke one operation on an asset through
    # its AssetCard, and read the operations a card allows.
    module AssetInvocations
      VERSION = Connect::ASSET_INVOKE_VERSION
      INVOKE_OPS = Connect::INVOKE_OPS
      ERRORS = Connect::INVOKE_ERRORS
      AssetInvocation = Capabilities::AssetInvocation
      AssetInvocationResult = Capabilities::AssetInvocationResult

      module_function

      def invoke_ops(card) = Connect.invoke_ops(card)

      # AssetInvocations.invoke (JS-C-10): writes an AssetInvocation for the
      # card's asset into space (the connector's task space) and returns the
      # AssetInvocationResult the card's issuer writes for it, or nil at the
      # timeout. A result from any other peer is ignored (ASF-009). The
      # invocation id is minted here and carried in the entry; pass the
      # earlier id as invocation_id to retry an invocation, which reaches the
      # target under the same id (JS-C-04) and is answered from the
      # connector's remembered result rather than a second run.
      def invoke(space, card, operation, params = {}, timeout: "30s", invocation_id: nil, lease: "5m",
                 read_through: "100ms")
        asset = card["asset"].to_s
        issuer = card["issuer"].to_s
        invocation_id ||= SecureRandom.uuid
        template = Template.new(AssetInvocationResult, where: { invocation_id: invocation_id })
        from_issuer = lambda do
          space.entries(template, limit: 16).each { |e| return e.value if Connect.peer_of(e.issuer) == issuer }
          nil
        end
        answer = Connect::Answer.new
        # Subscribe before writing so the answer cannot slip between the write
        # and the wait; the read-through finds a result that landed before the
        # subscription (a retry of an answered one).
        subscription = space.watch(template) do |event|
          answer.accept(event.value) if event.kind == WRITTEN && Connect.peer_of(event.item.issuer) == issuer
        end
        begin
          space.write(AssetInvocation.new(asset: asset, operation: operation, params: params,
                                          invocation_id: invocation_id), lease: lease)
          answer.wait(space, read_through, timeout) { from_issuer.call }
        ensure
          subscription.close
        end
      end
    end
  end
end
