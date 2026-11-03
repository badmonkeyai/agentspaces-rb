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

require_relative "test_helper"
require "agentspaces/capabilities"

# The connector protocol's agent side from Ruby (srad/agentspaces-js.md
# JS-C-14, JS-F-06), the port of the Python client's test_connect.py: the
# five entries byte-identical to Java under the golden vectors, a query
# answered by a simulated connector over the in-memory fleet and the
# identical query served from the space, a result accepted only from a
# trusted connector, an invocation answered only by the card's issuer, and a
# retry under the same invocation id that never runs the target again.
class ConnectTest < Minitest::Test
  include GoldenHelpers
  include AgentSpaces
  include AgentSpaces::Capabilities

  GROUP = "zRbConnect"
  INVOCATION_ID = "6f1d2c3b-4a59-4e8f-9b7a-0c1d2e3f4a5b"
  ROWS = [{ "id" => "1", "region" => "eu", "amount" => "120.00" }, { "id" => "2", "region" => "us", "amount" => "80.00" },
          { "id" => "3", "region" => "eu", "amount" => "45.50" }].freeze

  # A connector on one peer of the fleet, the shape of the Java and
  # TypeScript ConnectorRuntime over a table asset with one invoke operation,
  # reserve: it publishes the AssetCard, answers a DataQuery with a
  # DataResult (counting executions), takes each AssetInvocation under the
  # claim lattice on its own thread, refuses an operation absent from
  # invoke-ops naming the rule, runs the target once per invocation id,
  # answers a repeat from its remembered result, writes the result, and
  # completes the take.
  class SimulatedConnector
    include AgentSpaces
    include AgentSpaces::Capabilities

    attr_reader :card, :space, :executed, :invoked, :repeated, :refused, :reserved, :errors

    def initialize(peer, asset: "orders", rows: ROWS, ops: ["reserve"], name: "rb-connector")
      @peer = peer
      @asset = asset
      @rows = rows
      @name = name
      @space = Space.new(peer, Connect::DEFAULT_DATA_SPACE, agent_name: name)
      @executed = @invoked = @repeated = @refused = 0
      @reserved = [] # the invocation ids the target ran under
      @results = {}
      @errors = []
      now = peer.now_ms
      @card = { "id" => "aspace://#{GROUP}/asset/#{asset}", "issuer" => peer.identity.peer_id, "group" => GROUP,
                "issued" => Instants.iso(now - (now % 1000)), "ttl" => "PT15M", "asset" => asset,
                "uri" => "postgres://ops/public.orders", "description" => "Customer order history",
                "shape" => "com.example.OrderRow#v1", "freshness" => "PT5M",
                "costHints" => CBOR.canonical_map({ "rows" => rows.size.to_s }),
                "access" => CBOR.canonical_map({ "mode" => "read-only,invoke", "query" => Connect::DATA_QUERY_CAPABILITY,
                                                 "invoke" => Connect::ASSET_INVOKE_CAPABILITY,
                                                 Connect::INVOKE_OPS => ops.join(",") }) }
      peer.publish_ad(Connect::ASSET_CARD_TYPE, @card)
      @space.watch(Template.new(DataQuery, where: { asset: asset })) { |event| on_query(event) }
      @running = true
      @thread = Thread.new { serve_invocations }
    end

    def close
      @running = false
      @thread.join(5)
    end

    private

    def on_query(event)
      return unless event.kind == WRITTEN

      query = event.value
      @executed += 1
      limit = Integer(query.parameters.fetch("limit", @rows.size))
      matched = @rows.select { |row| query.parameters.all? { |k, v| k == "limit" || row[k] == v } }.first(limit)
      @space.write(DataResult.new(query_hash: query.query_hash, asset: @asset, rows: matched, error: nil,
                                  served_by: @name), lease: "5m")
    end

    def serve_invocations
      template = Template.new(AssetInvocation, where: { asset: @asset })
      while @running
        taken = @space.take(template, lease: "30s", timeout: "500ms")
        next if taken.nil?

        invocation = taken.value
        remembered = @results[invocation.invocation_id]
        unless remembered.nil?
          @repeated += 1
          live = @space.entries(AssetInvocationResult, where: { invocation_id: invocation.invocation_id })
                       .select { |e| Connect.peer_of(e.issuer) == @peer.identity.peer_id }
          taken.complete(live.empty? ? remembered : nil, lease: "1h")
          next
        end
        ops = Connect.invoke_ops(@card)
        if ops.include?(invocation.operation)
          @invoked += 1
          @reserved << invocation.invocation_id
          result = AssetInvocationResult.new(invocation_id: invocation.invocation_id, asset: @asset,
                                             operation: invocation.operation, ok: true,
                                             result: { "reserved" => invocation.params.fetch("qty", "0"),
                                                       "invocationId" => invocation.invocation_id },
                                             error: nil)
        else
          @refused += 1
          result = AssetInvocationResult.refused(
            invocation, "unknown-operation", "invoke-ops",
            "'#{invocation.operation}' is not in the invoke-ops of asset '#{@asset}' (#{ops.join(',')})"
          )
        end
        @results[invocation.invocation_id] = result
        taken.complete(result, lease: "1h")
      end
    rescue StandardError => e
      @errors << e
    end
  end

  # An admitted peer that forges an answer to every query and invocation it
  # sees, synchronously on the write, so its forgery lands before the honest
  # connector's answer: what ASF-009 says a client must ignore.
  class Rogue
    include AgentSpaces
    include AgentSpaces::Capabilities

    attr_reader :forged

    def initialize(peer)
      @space = Space.new(peer, Connect::DEFAULT_DATA_SPACE, agent_name: "rogue")
      @forged = 0
      @space.watch(DataQuery) { |event| on_query(event) }
      @space.watch(AssetInvocation) { |event| on_invocation(event) }
    end

    private

    def on_query(event)
      return unless event.kind == WRITTEN

      @forged += 1
      @space.write(DataResult.new(query_hash: event.value.query_hash, asset: event.value.asset,
                                  rows: [{ "id" => "forged" }], error: nil, served_by: "rogue"), lease: "5m")
    end

    def on_invocation(event)
      return unless event.kind == WRITTEN

      @forged += 1
      invocation = event.value
      @space.write(AssetInvocationResult.new(invocation_id: invocation.invocation_id, asset: invocation.asset,
                                             operation: invocation.operation, ok: true,
                                             result: { "reserved" => "999" }, error: nil), lease: "5m")
    end
  end

  def setup
    @peers = []
    @connectors = []
  end

  def teardown
    @connectors.each(&:close)
    @connectors.each { |c| assert_empty c.errors }
    @peers.each(&:close)
  end

  def fleet(count)
    @peers = Testing::Network.fleet(GROUP, count)
  end

  def connector(peer, **options)
    c = SimulatedConnector.new(peer, **options)
    @connectors << c
    c
  end

  def bytes(value) = cbor(Entry.to_payload(value))

  def ids(result) = result.rows.map { |row| row["id"] }

  # ------------------------------------------------------------ the entries

  def test_the_connector_entries_encode_as_java_does_and_readers_drop_unknown_fields
    query_hash = Connect.canonical_hash("orders", { "region" => "eu", "limit" => "10" })
    assert_equal GOLDEN["data_query_canonical_hash"], query_hash
    assert_equal query_hash, Connect.canonical_hash("orders", { limit: "10", region: "eu" }), "parameter order never splits"
    assert_equal hex("data_query_cbor"),
                 bytes(DataQuery.new(query_hash: query_hash, asset: "orders", parameters: { "region" => "eu", "limit" => "10" },
                                     requester: "zPeer/analyst"))
    assert_equal hex("data_result_cbor"),
                 bytes(DataResult.new(query_hash: query_hash, asset: "orders",
                                      rows: [{ "id" => "1", "region" => "eu", "amount" => "120.00" },
                                             { "id" => "3", "region" => "eu", "amount" => "45.50" }],
                                      error: nil, served_by: "pg-connector"))
    assert_equal hex("asset_change_cbor"),
                 bytes(AssetChange.new(asset: "orders", key: "1", row: { "id" => "1", "region" => "eu", "amount" => "125.00" },
                                       served_by: "pg-connector"))
    invocation = AssetInvocation.new(asset: "do/Inventory", operation: "reserveStock",
                                     params: { "sku" => "A-1", "qty" => "2" }, invocation_id: INVOCATION_ID)
    assert_equal 1, invocation.v
    assert_equal hex("asset_invocation_cbor"), bytes(invocation)
    assert_equal hex("asset_invocation_result_cbor"),
                 bytes(AssetInvocationResult.new(invocation_id: INVOCATION_ID, asset: "do/Inventory",
                                                 operation: "reserveStock", ok: true, result: { "reserved" => "2" },
                                                 error: nil))
    # Parameters, rows, and params are string maps in canonical order, whatever was passed.
    assert_equal({ "qty" => "2", "sku" => "A-1" }, AssetInvocation.new(asset: "a", operation: "o",
                                                                     params: { sku: "A-1", qty: 2 },
                                                                     invocation_id: "i").params)
    # The bytes decode back to the same values; a field the reader does not
    # know is dropped and a missing version reads as the current one (JS-F-06).
    decoded = load(hex("asset_invocation_cbor"))
    assert_equal invocation, AssetInvocation.from_payload(decoded)
    later = decoded.merge("idempotency" => "once", "cost" => "3")
    later.delete("v")
    assert_equal Connect::ASSET_INVOKE_VERSION, AssetInvocation.from_payload(later).v
    assert_equal hex("asset_invocation_cbor"), bytes(AssetInvocation.from_payload(later))
    result = load(hex("asset_invocation_result_cbor"))
    assert_equal({ "reserved" => "2" }, AssetInvocationResult.from_payload(result.merge("schema" => "x")).result)
    assert_same false, AssetInvocationResult.from_payload(result.merge("ok" => "yes")).ok
    refused = AssetInvocationResult.refused(invocation, "unknown-operation", "invoke-ops", "no")
    assert_equal [false, "unknown-operation", { "detail" => "no", "rule" => "invoke-ops" }],
                 [refused.ok, refused.error, refused.result]
    assert_same AssetInvocation, AssetInvocations::AssetInvocation
  end

  # -------------------------------------------------------------- the cards

  def test_asset_cards_and_invoke_ops_read_the_cards_the_ads_stream_carried
    connector_peer, agent_peer = fleet(2)
    connector(connector_peer)
    assert eventually(2) { !Connect.asset_cards(agent_peer, "orders").empty? }
    cards = Connect.asset_cards(agent_peer)
    assert_equal 1, cards.size
    card = cards.first
    assert_equal connector_peer.identity.peer_id, card["issuer"]
    assert_equal "orders", card["asset"]
    assert_equal "aspace:cap/data-query", card["access"]["query"]
    assert_equal "aspace:cap/asset-invoke", card["access"]["invoke"]
    assert_equal ["reserve"], AssetInvocations.invoke_ops(card)
    assert_empty Connect.asset_cards(agent_peer, "shipments")
    assert_equal %w[reserve release], Connect.invoke_ops({ "access" => { "invoke-ops" => " reserve , release,, " } })
    assert_empty Connect.invoke_ops({ "access" => {} })
    assert_empty Connect.invoke_ops({})
    assert_equal "zPeer", Connect.peer_of("zPeer/agent")
  end

  # ------------------------------------------------------------ the queries

  def test_a_query_is_answered_by_the_connector_and_the_identical_one_is_served_from_the_space
    connector_peer, agent_peer = fleet(2)
    served = connector(connector_peer)
    client = DataQueryClient.new(agent_peer, "analyst", trusted_connectors: [connector_peer.identity.peer_id])
    fetched = client.fetch("orders", { "region" => "eu" }, timeout: "5s")
    refute_nil fetched
    refute fetched.from_cache?
    assert_equal %w[1 3], ids(fetched.result)
    assert_equal "rb-connector", fetched.result.served_by
    assert_nil fetched.result.error
    assert_equal 1, served.executed
    # The same query from another agent: the live result answers.
    again = DataQueryClient.new(agent_peer, "planner", trusted_connectors: [connector_peer.identity.peer_id])
    cached = again.fetch("orders", { region: "eu" }, timeout: "5s")
    refute_nil cached
    assert cached.from_cache
    assert_equal %w[1 3], ids(cached.result)
    assert_equal [1, 1, 0], [served.executed, again.cache_hits, again.queries_sent]
    assert_equal [0, 1], [client.cache_hits, client.queries_sent]
    # A different query executes once more.
    limited = client.fetch("orders", { "region" => "eu", "limit" => "1" }, timeout: "5s")
    assert_equal ["1"], ids(limited.result)
    assert_equal 2, served.executed
    # An asset nobody serves: nil at the timeout, the query written and left for a connector.
    assert_nil client.fetch("shipments", {}, timeout: "300ms")
    assert_equal 1, client.space.entries(DataQuery, where: { asset: "shipments" }).size
  end

  def test_a_result_counts_only_from_a_trusted_connector
    rogue_peer, connector_peer, agent_peer = fleet(3) # the rogue hears the query first
    rogue = Rogue.new(rogue_peer)
    connector(connector_peer)
    trusting = DataQueryClient.new(agent_peer, "analyst", trusted_connectors: [connector_peer.identity.peer_id])
    fetched = trusting.fetch("orders", { "region" => "us" }, timeout: "5s")
    refute_nil fetched
    assert_equal ["2"], ids(fetched.result)
    assert_equal "rb-connector", fetched.result.served_by
    assert_equal 1, rogue.forged, "the forgery was written and ignored"
    assert_equal 2, trusting.space.entries(DataResult).size
    # The cache check applies the same rule: the forged result under the hash is not a hit.
    assert_equal "rb-connector", trusting.fetch("orders", { "region" => "us" }, timeout: "5s").result.served_by
    # A caller's own trust rule, the shape of the authorizer's CONNECTOR_SERVE check.
    rogue_id = rogue_peer.identity.peer_id
    ruled = DataQueryClient.new(agent_peer, "auditor", trust: ->(issuer_peer, _asset) { issuer_peer == rogue_id })
    assert_equal "rogue", ruled.fetch("orders", { "region" => "us" }, timeout: "5s").result.served_by
  end

  # -------------------------------------------------------- the invocations

  # The invocations wait up to the library's default 30 s: the test checks who answers,
  # and a loaded host (the whole workspace gate) once took longer than 10 s.
  def test_an_invocation_is_answered_only_by_the_cards_issuer_and_a_retry_never_runs_the_target_again
    rogue_peer, connector_peer, agent_peer = fleet(3)
    rogue = Rogue.new(rogue_peer)
    served = connector(connector_peer)
    assert eventually(2) { !Connect.asset_cards(agent_peer, "orders").empty? }
    card = Connect.asset_cards(agent_peer, "orders").first
    space = Space.new(agent_peer, Connect::DEFAULT_DATA_SPACE, agent_name: "planner")
    result = AssetInvocations.invoke(space, card, "reserve", { "sku" => "A-1", "qty" => "2" }, timeout: "30s")
    refute_nil result
    assert_same true, result.ok
    assert_nil result.error
    assert_equal "2", result.result["reserved"]
    assert_equal result.invocation_id, result.result["invocationId"]
    assert_equal 1, rogue.forged, "the forged result landed first and was ignored"
    assert_equal [result.invocation_id], served.reserved
    assert_equal 1, served.invoked
    assert eventually(2) { space.entries(AssetInvocation).empty? }, "the take was completed"
    # A forced retry under the same id: answered, the target not run again, one result from the issuer.
    retry_result = AssetInvocations.invoke(space, card, "reserve", { "sku" => "A-1", "qty" => "2" }, timeout: "30s",
                                                                                                    invocation_id: result.invocation_id)
    refute_nil retry_result
    assert_same true, retry_result.ok
    assert_equal result.invocation_id, retry_result.invocation_id
    assert_equal [result.invocation_id], served.reserved
    assert eventually(5) { served.repeated == 1 }
    from_issuer = space.entries(AssetInvocationResult, where: { invocation_id: result.invocation_id })
                       .select { |e| Connect.peer_of(e.issuer) == card["issuer"] }
    assert_equal 1, from_issuer.size
    # An operation the card does not list is refused naming the rule and never run.
    refused = AssetInvocations.invoke(space, card, "drop", { "table" => "orders" }, timeout: "30s")
    refute_nil refused
    assert_same false, refused.ok
    assert_equal "unknown-operation", refused.error
    assert_equal "invoke-ops", refused.result["rule"]
    assert_includes refused.result["detail"], "'drop' is not in the invoke-ops of asset 'orders' (reserve)"
    assert_equal [result.invocation_id], served.reserved
    assert_equal 1, served.refused
    # Nobody serves the asset: nil at the timeout, and the forgery under that id is not an answer.
    orphan = card.merge("asset" => "shipments")
    assert_nil AssetInvocations.invoke(space, orphan, "reserve", {}, timeout: "400ms")
    assert_equal 4, rogue.forged
  end
end
