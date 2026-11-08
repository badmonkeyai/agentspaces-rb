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

module AgentSpaces
  module PDT
    # The PRef#v1 head record (srad/agentspaces-pdt.md 3.6 and 10.2, PD-R-01):
    # the bounds a reader checks before it trusts a head.
    module Refs
      TYPE = "ai.badmonkey.agentspaces.agent.pdt.PRef#v1"
      VERSION = 1
      NAME_TAG = "name"
      ROOT_TAG = "root"
      KIND_MAP = "map"
      KIND_SET = "set"
      KIND_VECTOR = "vector"
      KIND_BLOB = "blob"
      KIND_TREE = "tree"
      KINDS = [KIND_MAP, KIND_SET, KIND_VECTOR, KIND_BLOB, KIND_TREE].freeze
      MODE_MULTI = "multi"
      MODE_LINEAR = "linear"
      MAX_NAME_BYTES = 256
      MAX_BASE = 8
      INLINE_DELTA_BYTES = 32 * 1024
      MAX_ATTRS = 32
      MAX_ATTRS_BYTES = 4 * 1024
      MAX_MODE_BYTES = 32
      MAX_SEQ = 1 << 53
      MAX_BASE_STEPS = 64
      ISSUED_ATTR = "pdt.issued"
      ISSUER_ATTR = "pdt.issuer"
      LATER_HLC = "LATER_HLC"
      WHOLE_HEAD = "WHOLE_HEAD"
      NO_COMMON_BASE = "NO_COMMON_BASE"

      module_function

      # The first broken bound of the record, or nil.
      def violation(r)
        return "not a map" unless r.is_a?(Hash)
        return "unsupported PRef version #{r['v'].inspect}" if r["v"] != VERSION

        name = r["name"]
        return "empty name" unless name.is_a?(String) && !name.empty?
        return "name longer than #{MAX_NAME_BYTES} bytes" if name.b.bytesize > MAX_NAME_BYTES
        return "unknown kind #{r['kind'].inspect}" unless KINDS.include?(r["kind"])
        return "empty root" unless r["root"].is_a?(String) && !r["root"].empty?
        return "root is not a CID" unless Cids.cid?(r["root"])

        base = r["base"] || []
        return "base is not a list" unless base.is_a?(Array)
        return "more than #{MAX_BASE} bases" if base.size > MAX_BASE

        base.each do |b|
          return "empty base root" unless b.is_a?(String) && !b.empty?
          return "base root is not a CID" unless Cids.cid?(b)
        end
        seq = r["seq"]
        size = r["size"]
        return "negative seq" unless seq.is_a?(Integer) && seq >= 0
        return "seq above #{MAX_SEQ}" if seq > MAX_SEQ
        return "negative size" unless size.is_a?(Integer) && size >= 0

        unless r["nodes"].nil?
          return "nodes is not a list" unless r["nodes"].is_a?(Array)

          r["nodes"].each { |n| return "empty inline node" unless n.is_a?(String) && !n.empty? }
          return "inline nodes larger than #{INLINE_DELTA_BYTES} bytes" if r["nodes"].sum(&:bytesize) > INLINE_DELTA_BYTES
        end
        %w[mode sealing].each do |field|
          v = r[field]
          return "empty #{field}" unless v.is_a?(String) && !v.empty?
          return "#{field} longer than #{MAX_MODE_BYTES} bytes" if v.b.bytesize > MAX_MODE_BYTES
        end
        return "negative keyEpoch" if !r["keyEpoch"].nil? && (!r["keyEpoch"].is_a?(Integer) || r["keyEpoch"].negative?)

        attrs = r["attrs"]
        unless attrs.nil?
          return "attrs is not a map" unless attrs.is_a?(Hash)
          return "more than #{MAX_ATTRS} attrs" if attrs.size > MAX_ATTRS
          return "attrs larger than #{MAX_ATTRS_BYTES} bytes" if attrs.sum { |k, v| k.to_s.b.bytesize + v.to_s.b.bytesize } > MAX_ATTRS_BYTES
        end
        nil
      end

      def tags(record) = { NAME_TAG => record["name"], ROOT_TAG => record["root"] }

      def inline_bytes(record) = (record["nodes"] || []).sum(&:bytesize)

      # An HLC stamp as a comparable [physical, logical, node], decoded as
      # Java's HlcTimestamp.parse reads it, or [0, 0, ""] for a stamp that
      # does not decode (HLC logical counter, 2026-11-08 (Rust team report);
      # HLC canonical stamps, 2026-11-08). A head's stamp orders heads and
      # never reaches a clock, so a counter above the logical limit decodes.
      def hlc(stamp) = Wire.hlc_decode(stamp) || [0, 0, ""]

      # Whether text is an agent id as Java's AgentId.parse reads it:
      # <peerId>/<localName>, both parts non-empty.
      def agent_id?(text)
        return false unless text.is_a?(String)

        slash = text.index("/")
        !slash.nil? && slash.positive? && slash < text.length - 1
      end

      # One version of a ref as a reader keeps it, with the merge order's fields.
      Head = Struct.new(:root, :base, :seq, :size, :kind, :mode, :issuer, :issued, :entry_id, :expires_at_millis,
                        keyword_init: true) do
        # Heads.MERGE_ORDER: issued HLC, then the issuer's PeerId bytes, then the root.
        def order = [issued[0], issued[1], issuer.to_s.split("/", 2).first.to_s.b, root]

        def issuer_peer = issuer.to_s.split("/", 2).first
      end

      # A both-side decision a reader recorded (PD-R-05).
      PConflict = Struct.new(:name, :key, :winner_root, :loser_root, :reason, keyword_init: true)

      # The entries no other entry supersedes, equal roots folded (10.2).
      def heads_among(entries)
        superseded_below = {}
        entries.each do |h|
          by = h.seq >= MAX_SEQ ? 1 << 62 : h.seq
          h.base.each { |b| superseded_below[b] = [superseded_below.fetch(b, -1), by].max }
        end
        by_root = {}
        entries.sort_by(&:order).each do |h|
          by = superseded_below[h.root]
          next if !by.nil? && by > h.seq

          kept = by_root[h.root]
          by_root[h.root] = h if kept.nil? || h.seq > kept.seq
        end
        by_root.values.sort_by(&:order)
      end
    end

    # A reader's handle on one ref (PD-C-06): the live heads of a name in the ref
    # space, the inline deltas applied and the rest fetched, and deref as the
    # single head's value or the merge of 3.6.1. The Ruby face never writes a
    # head: swap lives on the JVM, Python, and TypeScript faces.
    class Ref
      attr_reader :name, :kind, :pdt, :conflicts

      def initialize(pdt, name, kind)
        @pdt = pdt
        @name = name
        @kind = kind
        @known = {}
        @ignored = Set.new
        @conflicts = []
        @listeners = []
        @lock = Mutex.new
        @stats = Hash.new(0)
      end

      def store = @pdt.store

      def stats = @stats.dup

      def on_conflict(&listener)
        @listeners << listener
        -> { @listeners.delete(listener) }
      end

      # Whether a root is held complete here.
      def held?(root) = store.has?(root) && store.complete?(root)

      # The heads in merge order (PD-R-02); a head whose root cannot load within the timeout is ignored.
      def heads(wait: true)
        @lock.synchronize { Refs.heads_among(loadable(live_entries, wait)) }
      end

      # The ref's value: the single head's, or the merge of 3.6.1; never writes.
      def deref
        @lock.synchronize do
          hs = Refs.heads_among(loadable(live_entries, true))
          return empty_value if hs.empty?

          materialize(hs)
        end
      end

      # The value at a root this reader holds.
      def at(root)
        raise NodeUnavailable.new(root, [], "root #{root} is not held complete here") unless held?(root)

        value_of(root)
      end

      # Up to n earlier versions held here, newest first, found by walking base links from the
      # current heads over the versions this reader has seen (PD-R-09), as the JVM face's history.
      def history(n = 10)
        return [] if n <= 0

        @lock.synchronize do
          hs = Refs.heads_among(loadable(live_entries, false))
          exclude = hs.map(&:root).to_set
          out = []
          seen = Set.new
          frontier = hs.map(&:root)
          while !frontier.empty? && out.size < n
            cid = frontier.shift
            next unless seen.add?(cid)

            version = @known[cid]
            next if version.nil?

            out << version if !exclude.include?(cid) && held?(cid)
            frontier.concat(version.base)
          end
          out
        end
      end

      # Every version this reader has seen a head for, newest first by seq, held or not.
      def versions
        @lock.synchronize { live_entries }
        @known.values.sort_by { |h| [-h.seq, h.order] }
      end

      private

      def loader(prefer = []) = @pdt.loader(prefer)

      def empty_value
        case @kind
        when Refs::KIND_MAP, Refs::KIND_TREE then {}
        when Refs::KIND_SET then Set.new
        when Refs::KIND_VECTOR then []
        else "".b
        end
      end

      def value_of(root, prefer = [])
        case @kind
        when Refs::KIND_MAP, Refs::KIND_TREE then PMap.load(root, loader(prefer))
        when Refs::KIND_SET then PSet.load(root, loader(prefer))
        when Refs::KIND_VECTOR then PVector.load(root, loader(prefer))
        when Refs::KIND_BLOB then PBlob.load(root, loader(prefer))
        end
      end

      # The live PRef entries of this name in the ref space, their inline deltas applied (PD-X-07).
      def live_entries
        peer = @pdt.peer
        now = peer.now_ms
        live = []
        peer.states.to_a.each do |entry_id, dto|
          record = dto["record"] || {}
          next unless record["type"] == Refs::TYPE && record["spaceId"] == @pdt.space_id && !dto["completed"]
          next unless (record["tags"] || {})[Refs::NAME_TAG] == @name
          next if (record["lease"] || {}).fetch("expiresAtMillis", 0).to_i <= now

          raw = peer.payload_of(dto)
          next if raw.nil?

          value = begin
            CBOR.load(raw)
          rescue CBOR::Error
            next
          end
          next unless Refs.violation(value).nil? && value["kind"] == @kind

          issued = Refs.hlc(record["issued"])
          issuer = record["issuer"].to_s
          # A rewrite carries the original head's stamp and issuer (PD-R-08).
          # As Java's Refs.toHead reads them, a pdt.issued that decodes
          # replaces the entry's own stamp, a pdt.issuer that parses replaces
          # the issuer, and a malformed attr leaves the entry's own (HLC
          # canonical stamps, 2026-11-08).
          attrs = value["attrs"] || {}
          stamped = Wire.hlc_decode(attrs[Refs::ISSUED_ATTR])
          unless stamped.nil?
            issued = stamped
            issuer = attrs[Refs::ISSUER_ATTR] if Refs.agent_id?(attrs[Refs::ISSUER_ATTR])
          end
          head = Refs::Head.new(root: value["root"], base: (value["base"] || []).dup.freeze, seq: value["seq"],
                                size: value["size"], kind: value["kind"], mode: value["mode"], issuer: issuer,
                                issued: issued, entry_id: entry_id,
                                expires_at_millis: record["lease"]["expiresAtMillis"].to_i)
          remember(head)
          apply_inline(head.root, value["nodes"]) if value["nodes"] && !held?(head.root) && !@ignored.include?(entry_id)
          live << head
        end
        live
      end

      # Keeps the largest-seq record per root with the union of its bases (10.2).
      def remember(head)
        known = @known[head.root]
        if known.nil? || head.seq > known.seq
          base = known ? (known.base + head.base).uniq : head.base
          @known[head.root] = head.dup.tap { |h| h.base = base.freeze }
        elsif !(head.base - known.base).empty?
          known.base = (known.base + head.base).uniq.freeze
        end
      end

      # Verifies inline nodes by a walk from the root through the store plus the inline set.
      def apply_inline(root, inline)
        by_digest = inline.to_h { |data| [Cids.sha256(data), data] }
        used = Set.new
        frontier = [root]
        seen = Set.new
        until frontier.empty?
          cid = frontier.pop
          next if seen.include?(cid)

          seen << cid
          data = store.get(cid)
          if data.nil?
            digest = Cids.parse(cid).digest
            data = by_digest[digest]
            next if data.nil?

            begin
              store.put_verified(cid, data)
            rescue NodeFormatError
              next
            end
            used << digest
          end
          frontier.concat(store.links(cid, data))
        end
        dropped = by_digest.size - used.size
        @stats[:nodes_dropped] += dropped if dropped.positive?
        @stats[:deltas_inline] += 1 unless used.empty?
      end

      # The heads whose roots are held here, fetching the rest from their issuers first.
      def loadable(heads, wait)
        fetches = []
        heads.each do |h|
          next if @ignored.include?(h.entry_id) || held?(h.root)
          next if @pdt.trees.nil?

          haves = @known.keys.select { |r| r != h.root && held?(r) }.first(Refs::MAX_BASE)
          fetches << [h, @pdt.trees.fetch_tree(h.root, haves: haves, prefer: [h.issuer_peer], timeout: @pdt.load_timeout)]
        end
        if wait && !fetches.empty?
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @pdt.load_timeout
          fetches.each { |_, f| f.wait([0.0, deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)].max) }
        end
        out = []
        heads.each do |h|
          next if @ignored.include?(h.entry_id)

          if held?(h.root)
            out << h
            @stats[:deltas_fetched] += 1 if fetches.any? { |fh, f| fh.equal?(h) && f.complete? }
          elsif wait
            @ignored << h.entry_id
            @stats[:heads_ignored] += 1
          end
        end
        out
      end

      def conflict(event)
        @conflicts << event
        @conflicts.shift while @conflicts.size > 256
        @stats[:conflicts] += 1
        @listeners.each do |l|
          l.call(event)
        rescue StandardError => e
          @pdt.peer.logger&.warn("pdt: conflict listener raised #{e.class}: #{e.message}")
        end
      end

      # One head: its value. Several: maps and sets merge key-wise against the lowest common base
      # held here, both-side conflicts taking the later head (LATER_HLC); without a held base, and
      # for vectors and blobs, the later head wins whole (3.6.1). A merged map or set is a plain
      # Hash or Set, since this reader writes no node.
      def materialize(heads)
        return value_of(heads.first.root, [heads.first.issuer_peer]) if heads.size == 1

        later = heads.last
        unless [Refs::KIND_MAP, Refs::KIND_SET, Refs::KIND_TREE].include?(@kind)
          heads[0...-1].each { |h| conflict(Refs::PConflict.new(name: @name, key: nil, winner_root: later.root, loser_root: h.root, reason: Refs::WHOLE_HEAD)) }
          return value_of(later.root, [later.issuer_peer])
        end
        base = common_base(heads)
        if base.nil?
          heads[0...-1].each { |h| conflict(Refs::PConflict.new(name: @name, key: nil, winner_root: later.root, loser_root: h.root, reason: Refs::NO_COMMON_BASE)) }
          return value_of(later.root, [later.issuer_peer])
        end
        base_entries = raw_map(base)
        merged = base_entries.dup
        heads.each_with_index do |h, i|
          mine = raw_map(h.root)
          (mine.keys | base_entries.keys).each do |key|
            before = base_entries[key]
            now = mine[key]
            next if before == now

            current = merged[key]
            if current == before || i.zero? || current == now
              now.nil? ? merged.delete(key) : merged[key] = now
            else
              # Both sides changed the key to different values: the head later in the merge order wins.
              merged[key] = now unless now.nil?
              merged.delete(key) if now.nil?
              loser = heads[0...i].reverse.find { |o| raw_map(o.root)[key] != before }
              conflict(Refs::PConflict.new(name: @name, key: Values.decode_value(key), winner_root: h.root,
                                           loser_root: loser ? loser.root : heads[i - 1].root, reason: Refs::LATER_HLC))
            end
          end
        end
        if @kind == Refs::KIND_SET
          Set.new(merged.keys.map { |k| Values.decode_value(k) })
        else
          merged.to_h { |k, v| [Values.decode_value(k), Values.decode_value(v)] }
        end
      end

      def raw_map(root)
        @raw_cache ||= {}
        @raw_cache[root] ||= PMap.load(root, loader).raw_entries.to_h
      end

      # The lowest common base of the heads over the versions seen, held complete here, within 64 steps.
      def common_base(heads)
        ancestors = heads.map { |h| ancestors_of(h.root) }
        common = ancestors.map(&:keys).reduce(:&)
        return nil if common.empty?

        candidate = common.min_by { |r| ancestors.sum { |a| a[r] } }
        held?(candidate) ? candidate : nil
      end

      def ancestors_of(root)
        depths = {}
        queue = [[root, 0]]
        until queue.empty?
          r, d = queue.shift
          next if depths.key?(r) || d > Refs::MAX_BASE_STEPS

          depths[r] = d
          (@known[r]&.base || []).each { |b| queue << [b, d + 1] }
        end
        depths
      end
    end

    # The reader over a peer's ref space (PD-C-06): one node store, the tree
    # fetcher over the content swarm, and a handle per ref name.
    class Pdt
      attr_reader :peer, :space, :space_id, :store, :trees, :load_timeout

      # peer: a connected AgentSpaces::Peer; space: the ref space's name (the
      # Spring starter's default is "pdt", Micronaut's "refs"); keys: content
      # keys by epoch for a group that seals nodes in transit (group-key).
      def initialize(peer, space: "pdt", store: nil, trees: nil, keys: {}, load_timeout: 10.0)
        @peer = peer
        @space = space.to_s
        @space_id = Derive.space_id_local("#{peer.group}/#{@space}")
        @store = store || NodeStore.new
        @trees = trees || Trees.new(peer, @store, keys: keys, load_timeout: load_timeout)
        @load_timeout = load_timeout
        @refs = {}
        peer.pull_space(@space) if peer.connected?
        peer.pull_ads if peer.connected?
      end

      def loader(prefer = []) = @trees.loader(prefer)

      def ref(name, kind: Refs::KIND_MAP)
        raise ArgumentError, "unknown kind #{kind.inspect}; one of #{Refs::KINDS.join(', ')}" unless Refs::KINDS.include?(kind)

        @refs[[name.to_s, kind]] ||= Ref.new(self, name.to_s, kind)
      end

      def map_ref(name) = ref(name, kind: Refs::KIND_MAP)
      def set_ref(name) = ref(name, kind: Refs::KIND_SET)
      def vector_ref(name) = ref(name, kind: Refs::KIND_VECTOR)
      def blob_ref(name) = ref(name, kind: Refs::KIND_BLOB)
      def tree_ref(name) = ref(name, kind: Refs::KIND_TREE)

      # A value by root alone, for a payloadRef a space entry carries (PD-C-06):
      # loaded when held or fetchable, else the root stays an opaque string.
      def value_at(root, kind: Refs::KIND_MAP, prefer: [])
        Cids.parse(root)
        case kind
        when Refs::KIND_MAP, Refs::KIND_TREE then PMap.load(root, loader(prefer))
        when Refs::KIND_SET then PSet.load(root, loader(prefer))
        when Refs::KIND_VECTOR then PVector.load(root, loader(prefer))
        when Refs::KIND_BLOB then PBlob.load(root, loader(prefer))
        else raise ArgumentError, "unknown kind #{kind.inspect}"
        end
      end

      def stats
        totals = Hash.new(0)
        @refs.each_value { |r| r.stats.each { |k, v| totals[k] += v } }
        { "refs" => @refs.size, "nodesHeld" => @store.size, "bytesHeld" => @store.bytes_used,
          "deltasInline" => totals[:deltas_inline], "deltasFetched" => totals[:deltas_fetched],
          "conflicts" => totals[:conflicts], "headsIgnored" => totals[:heads_ignored],
          "nodesDropped" => totals[:nodes_dropped] }.merge(@trees.stats.transform_keys(&:to_s))
      end
    end
  end
end
