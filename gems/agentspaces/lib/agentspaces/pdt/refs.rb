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
      # PDT 2 phase 7 (P2-C-02, P2-F-06; srad/agentspaces-pdt2.md 6.10.3, rule 8): a head whose
      # tree holds a node of a kind outside annex H's level-1 set is version 2, and a level-2
      # reader reads both versions.
      VERSION_2 = 2
      NAME_TAG = "name"
      ROOT_TAG = "root"
      KIND_MAP = "map"
      KIND_SET = "set"
      KIND_VECTOR = "vector"
      KIND_BLOB = "blob"
      KIND_TREE = "tree"
      # PDT 2 phase 7 (P2-C-02): a DataScript database, a db root over dn nodes, always version 2.
      KIND_DB = "db"
      KINDS = [KIND_MAP, KIND_SET, KIND_VECTOR, KIND_BLOB, KIND_TREE, KIND_DB].freeze
      MODE_MULTI = "multi"
      MODE_LINEAR = "linear"
      SEALING_NONE = "none"
      SEALING_GROUP_KEY = "group-key"
      MAX_NAME_BYTES = 256
      MAX_BASE = 8
      # Swarm retries (ROBUSTNESS.md 10.3 E3): the first wait before a root whose fetch failed is
      # fetched again, in seconds; each later failure doubles it up to UNLOADABLE_BACKOFF load timeouts.
      RETRY_BASE = 1.0
      UNLOADABLE_BACKOFF = 4
      INLINE_DELTA_BYTES = 32 * 1024
      MAX_ATTRS = 32
      MAX_ATTRS_BYTES = 4 * 1024
      MAX_MODE_BYTES = 32
      MAX_SEQ = 1 << 53
      MAX_BASE_STEPS = 64
      # The most version-graph entries a reader keeps per ref, as Java's Refs.KNOWN_CAPACITY bounds them.
      KNOWN_CAPACITY = 4096
      ISSUED_ATTR = "pdt.issued"
      ISSUER_ATTR = "pdt.issuer"
      # The base the merge reads as the kind's empty value, as Java's Refs names it.
      EMPTY_BASE = ""
      LATER_HLC = "LATER_HLC"
      WHOLE_HEAD = "WHOLE_HEAD"
      NO_COMMON_BASE = "NO_COMMON_BASE"
      # The attrs whose values a reader falls back from when they are no stamp
      # or no agent id, so they hold any item (HLC round six, 2026-11-08 (R1)).
      RESERVED_ATTRS = [ISSUED_ATTR, ISSUER_ATTR].freeze
      # The values a Java int holds, the type of a PRef's v.
      JAVA_INT = (-(1 << 31)..((1 << 31) - 1))
      # HLC round six, 2026-11-08 (F1, F3): the PRef#v1 fields in the order
      # Java's record declares them and writes them, each with the kind of
      # item it holds, and true for the fields Java leaves out when null.
      FIELDS = [["v", :int], ["name", :text], ["kind", :text], ["root", :text], ["base", :texts], ["seq", :long],
                ["size", :long], ["nodes", :bytes, true], ["mode", :text], ["sealing", :text], ["keyEpoch", :long, true],
                ["attrs", :attrs, true]].freeze

      module_function

      # HLC round six, 2026-11-08 (F1, F3, R1): the PRef a payload holds, or
      # nil when the payload is undecodable. A PRef is a protocol record: its
      # fields arrive in FIELDS order, each of its kind with no coercion, the
      # optional ones absent when null, its attrs keys are text in the RFC 8949
      # order (shorter UTF-8 key first, then bytewise) with text under every
      # key outside RESERVED_ATTRS. CBOR.load refuses a payload that differs
      # from the re-encoding of what it decodes to, so no relabelled form of
      # a signed head decodes.
      def decode(raw)
        value = CBOR.load(raw)
        value.instance_of?(Hash) && fields?(value) ? value : nil
      rescue CBOR::Error
        nil
      end

      def fields?(record)
        fields = FIELDS.reject { |name, _, optional| optional && !record.key?(name) }
        record.keys == fields.map(&:first) && fields.all? { |name, kind, _| kind?(record[name], kind) }
      end
      private_class_method :fields?

      def kind?(value, kind)
        case kind
        when :int then value.is_a?(Integer) && JAVA_INT.cover?(value)
        when :long then value.is_a?(Integer) && Wire::JAVA_LONG.cover?(value)
        when :text then text?(value)
        when :texts then value.is_a?(Array) && value.all? { |item| text?(item) }
        when :bytes then value.is_a?(Array) && value.all? { |item| item.is_a?(String) && item.encoding == Encoding::BINARY }
        when :attrs then attrs?(value)
        end
      end
      private_class_method :kind?

      def attrs?(attrs)
        return false unless attrs.is_a?(Hash) && attrs.keys.all? { |key| text?(key) }
        return false unless attrs.keys == attrs.keys.sort_by { |key| [key.bytesize, key.b] }

        attrs.all? { |key, value| RESERVED_ATTRS.include?(key) || text?(value) }
      end
      private_class_method :attrs?

      # Whether a decoded value is a CBOR text string; the decoder hands a byte
      # string over as a binary String.
      def text?(value) = value.is_a?(String) && value.encoding != Encoding::BINARY
      private_class_method :text?

      # The first broken bound of the record, or nil.
      def violation(r)
        return "not a map" unless r.is_a?(Hash)
        return "unsupported PRef version #{r['v'].inspect}" unless [VERSION, VERSION_2].include?(r["v"])
        return "a db head is version #{VERSION_2}, found #{r['v']}" if r["kind"] == KIND_DB && r["v"] != VERSION_2

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
          # HLC round six, 2026-11-08 (R1): the bound counts the UTF-8 bytes of
          # the keys and of the text values alone, so a value that is no text,
          # which only pdt.issued and pdt.issuer may hold, counts nothing.
          bytes = attrs.sum { |k, v| k.to_s.b.bytesize + (text?(v) ? v.b.bytesize : 0) }
          return "attrs larger than #{MAX_ATTRS_BYTES} bytes" if bytes > MAX_ATTRS_BYTES
        end
        nil
      end

      def tags(record) = { NAME_TAG => record["name"], ROOT_TAG => record["root"] }

      # A PRef record in the order Java's record declares its fields (PDT 2 phase
      # 7, P2-X-06); nodes and attrs leave the wire when nil, and a Ruby writer
      # names no keyEpoch, since it writes no sealed-nodes tree.
      def record(name:, kind:, root:, base:, seq:, size:, nodes:, mode:, sealing:, version: VERSION, attrs: nil)
        out = { "v" => version, "name" => name, "kind" => kind, "root" => root, "base" => base, "seq" => seq, "size" => size }
        out["nodes"] = nodes unless nodes.nil?
        out["mode"] = mode
        out["sealing"] = sealing
        out["attrs"] = CBOR.canonical_map(attrs) unless attrs.nil?
        out
      end

      def inline_bytes(record) = (record["nodes"] || []).sum(&:bytesize)

      # An HLC stamp as a comparable [physical, logical, node] when the strict
      # parser accepts it, or [0, 0, ""] for any other (HLC logical counter,
      # 2026-11-08 (Rust team report)). A counter above the logical limit
      # orders nothing, as Java's Refs reads it (HLC round four, 2026-11-08 (D2)).
      def hlc(stamp) = Wire.hlc_parse(stamp) || [0, 0, ""]

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

      # Notes a failed fetch of a key, a head's root or a vg node, in retries
      # (key => [failures, next due]): the next is due after RETRY_BASE seconds
      # doubling with each failure up to UNLOADABLE_BACKOFF load timeouts, with
      # a random spread of up to half (swarm retries, ROBUSTNESS.md 10.3 E3).
      def back_off(retries, key, load_timeout)
        failures = (retries[key]&.first || 0) + 1
        pause = [[Refs::RETRY_BASE, load_timeout * Refs::UNLOADABLE_BACKOFF].max,
                 Refs::RETRY_BASE * (2**[failures - 1, 20].min)].min
        retries[key] = [failures, Process.clock_gettime(Process::CLOCK_MONOTONIC) + pause + rand * pause / 2]
      end
    end

    # A handle on one ref (PD-C-06): the live heads of a name in the ref space,
    # the inline deltas applied and the rest fetched, and deref as the single
    # head's value or the merge of 3.6.1.
    #
    # PDT 2 phase 7 (P2-X-06; srad/agentspaces-pdt2.md 4.11): swap writes in
    # multi mode. It reads the heads, gives the block the current value as plain
    # Ruby (a Hash, a Set, an Array, or a binary String; a text as a PText this
    # writer edits), builds the tree of the block's value with Build, and writes
    # a head whose base lists the heads it read and whose seq is one more than
    # their largest (PD-R-03), with the new nodes inline when they total at most
    # 32 KiB (PD-X-07) and its vg node named in pdt.ancestry (P2-V-01). The
    # tick renews this writer's live heads at half their lease and cancels its
    # superseded heads CANCEL_GRACE_MS after they fall below the lowest common
    # base of the held heads, as Java's Refs does, so no head is renewed for
    # the life of the process.
    class Ref
      # One head entry this writer wrote, for renewal and cancellation.
      Own = Struct.new(:entry_id, :root, :base, :renewed_at, :superseded_at, :displaced)

      attr_reader :name, :kind, :pdt, :conflicts

      def initialize(pdt, name, kind)
        @pdt = pdt
        @name = name
        @kind = kind
        @known = {}
        # PDT 2 phase 1 (P2-V-01, P2-V-02): the vg node CID each version
        # names, by root, from a head's pdt.ancestry or a chain link, and the
        # vg nodes read, by the root they describe; each keeps at most
        # Refs::KNOWN_CAPACITY roots, the eldest leaving first, as in Java.
        @ancestry = {}
        @chain = {}
        # The vg nodes a walk could not get, [failures, next due] by CID, at most
        # Refs::KNOWN_CAPACITY (P2-V-02; swarm retries, ROBUSTNESS.md 10.2).
        @chain_misses = {}
        # PDT 2 phase 7 (P2-C-02): the BlobIdentity a blob head claims, by root, first seen, as Java's Refs keeps it.
        @claims = {}
        @own = {}
        @ignored = Set.new
        # Swarm retries (ROBUSTNESS.md 10.3 E3): late heads counted by [entry, cause] while live,
        # the fetch under way per root, and the roots whose fetch failed: [failures, next due].
        @late = Set.new
        @fetching = {}
        @retries = {}
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

      # The BlobIdentity a blob head of a root claims (pdt.blake3 and pdt.bao), or nil.
      def claim(root)
        @lock.synchronize do
          live_entries
          @claims[root]
        end
      end

      # A window of the blob ref's value verified against the identity its head claims
      # (PDT 2 phase 7, P2-C-02); ArgumentError when the head claims none.
      def read_verified(offset, length)
        blob = deref
        claim = claim(blob.root)
        raise ArgumentError, "the head of #{@name} at #{blob.root} names no BLAKE3 identity (pdt.blake3, pdt.bao)" if claim.nil?

        blob.read_verified(offset, length, claim)
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
        when Refs::KIND_BLOB then "".b
        end
      end

      def value_of(root, prefer = [])
        case @kind
        when Refs::KIND_MAP, Refs::KIND_TREE then PMap.load(root, loader(prefer))
        when Refs::KIND_SET then PSet.load(root, loader(prefer))
        when Refs::KIND_VECTOR then PVector.load(root, loader(prefer))
        when Refs::KIND_BLOB then PBlob.load(root, loader(prefer))
        when Refs::KIND_DB then DbReader.new(root, loader(prefer))
        end
      end

      # The live PRef entries of this name in the ref space, their inline deltas applied (PD-X-07).
      def live_entries
        peer = @pdt.peer
        now = peer.now_ms
        live = []
        ids = Set.new
        peer.states.to_a.each do |entry_id, dto|
          record = dto["record"] || {}
          # PDT 2 phase 7 (P2-X-06): a cancelled head is gone, and a renewed one lives to its renewed lease
          next unless record["type"] == Refs::TYPE && record["spaceId"] == @pdt.space_id && AgentSpaces::Peer.present?(dto)
          next unless (record["tags"] || {})[Refs::NAME_TAG] == @name

          expires_at = AgentSpaces::Peer.lease_of(dto).fetch("expiresAtMillis", 0).to_i
          next if expires_at <= now

          ids << entry_id
          raw = peer.payload_of(dto)
          next if raw.nil?

          value = Refs.decode(raw)
          # A PRef that names another ref or kind is no head of this one, as
          # Java's Refs.toHead reads it (HLC round five, 2026-11-08, adversary
          # pass on E10 and E16). HLC round six, 2026-11-08 (R3): an
          # undecodable PRef, one that breaks a bound, and one that names
          # another ref or kind count once in headsIgnored while the entry
          # stays live, as Java counts them.
          unless value && Refs.violation(value).nil? && value["name"] == @name && value["kind"] == @kind
            ignore(entry_id)
            next
          end

          issued = Refs.hlc(record["issued"])
          issuer = record["issuer"].to_s
          # A rewrite carries the original head's stamp and issuer (PD-R-08).
          # As Java's Refs.toHead reads them, a pdt.issued the strict parser
          # accepts replaces the entry's own stamp, and with it a pdt.issuer
          # replaces the issuer when present. A pdt.issued the parser refuses,
          # or a pdt.issuer that does not parse as an agent id, leaves the
          # entry's own stamp and issuer together; the attrs are advisory, so
          # nothing is refused or counted (HLC round four, 2026-11-08 (D2)).
          # A pdt.issuer present as null falls back the same way, so it never
          # pairs pdt.issued with the entry's issuer (HLC round five,
          # 2026-11-08 (E10)).
          # HLC round six, 2026-11-08 (R2): a pdt.issued past this reader's
          # wall + MAX_DRIFT + the skew margin falls back the same way, so a
          # rewrite cannot win every conflict by stamping ahead.
          attrs = value["attrs"] || {}
          stamped = Wire.hlc_parse(attrs[Refs::ISSUED_ATTR])
          stamped = nil if stamped && Wire.hlc_far_future(stamped[0], now)
          named = attrs.key?(Refs::ISSUER_ATTR)
          original = attrs[Refs::ISSUER_ATTR]
          if stamped && (!named || Wire.agent_id?(original))
            issued = stamped
            issuer = original if named
          end
          head = Refs::Head.new(root: value["root"], base: (value["base"] || []).dup.freeze, seq: value["seq"],
                                size: value["size"], kind: value["kind"], mode: value["mode"], issuer: issuer,
                                issued: issued, entry_id: entry_id, expires_at_millis: expires_at)
          remember(head)
          vg = Ancestry.cid(value)
          keep(@ancestry, head.root, vg) if vg
          claim = BlobIdentity.read(attrs) if @kind == Refs::KIND_BLOB
          keep(@claims, head.root, claim) if claim
          apply_inline(head.root, value["nodes"]) if value["nodes"] && !held?(head.root) && !@ignored.include?(entry_id)
          live << head
        end
        # Ignored entries are remembered only while they are live, so the set
        # stays bounded by the live entries, as Java's Refs retains them.
        @ignored.keep_if { |id| ids.include?(id) }
        @late.keep_if { |entry_id, _| ids.include?(entry_id) }
        live
      end

      def ignore(entry_id)
        @stats[:heads_ignored] += 1 if @ignored.add?(entry_id)
      end

      # Counts a live head as late for a cause, once per entry and cause (swarm retries).
      def late(entry_id, cause)
        @stats[:heads_late] += 1 if @late.add?([entry_id, cause])
      end

      # Keeps the largest-seq record per root with the union of its bases (10.2),
      # the larger-seq record's bases first, as Java's Refs.toHead orders them
      # (HLC round six, 2026-11-08 (R4)).
      def remember(head)
        known = @known[head.root]
        if known.nil? || head.seq > known.seq
          base = known ? (head.base + known.base).uniq : head.base
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

      # The heads whose roots are held here, fetching the rest from their
      # issuers first. A head whose root has not loaded within the timeout is
      # late, never ignored: the fetch goes on, a failed one is fetched again
      # after a backoff from the other members before the issuer, and the head
      # joins the heads once its root is held, as Java's Refs reads every live
      # head whose root it holds (HLC round six, 2026-11-08 (R3); swarm
      # retries, ROBUSTNESS.md 10.3 E3).
      def loadable(heads, wait)
        fetches = []
        heads.each do |h|
          next if @ignored.include?(h.entry_id) || held?(h.root)
          next if @pdt.trees.nil?

          f = fetch(h)
          fetches << [h, f] unless f.nil?
        end
        if wait && !fetches.empty?
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @pdt.load_timeout
          fetches.each { |_, f| f.wait([0.0, deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)].max) }
        end
        settle_fetches
        out = []
        heads.each do |h|
          if held?(h.root)
            out << h
            @stats[:deltas_fetched] += 1 if fetches.any? { |fh, f| fh.equal?(h) && f.complete? }
          elsif wait && !@ignored.include?(h.entry_id)
            running = @fetching[h.root]
            late(h.entry_id, running && !running.done? ? :timeout : :failed_fetch)
          end
        end
        out
      end

      # The fetch of a head's root: the one under way, else a new one unless a
      # failed one's backoff still runs; a retry asks the other members before
      # the issuer (swarm retries).
      def fetch(head)
        running = @fetching[head.root]
        return running if running && !running.done?

        retry_at = @retries[head.root]
        return nil if retry_at && Process.clock_gettime(Process::CLOCK_MONOTONIC) < retry_at[1]

        prefer = retry_at ? @pdt.trees.sources - [head.issuer_peer] : [head.issuer_peer]
        haves = @known.keys.select { |r| r != head.root && held?(r) }.first(Refs::MAX_BASE)
        @fetching[head.root] = @pdt.trees.fetch_tree(head.root, haves: haves, prefer: prefer, timeout: @pdt.load_timeout)
      end

      # Forgets finished fetches; a failed one schedules the next after the
      # backoff of Refs.back_off.
      def settle_fetches
        @fetching.delete_if do |root, f|
          next false unless f.done?

          if f.complete? || held?(root)
            @retries.delete(root)
          else
            Refs.back_off(@retries, root, @pdt.load_timeout)
          end
          true
        end
      end

      public

      # A live head whose fetch failed is fetched again once its backoff ends,
      # with no read needed; Pdt#tick calls it (swarm retries).
      def retry_due
        @lock.synchronize do
          settle_fetches
          live = live_entries
          roots = live.map(&:root).to_set
          @retries.keep_if { |root, _| roots.include?(root) }
          now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          live.each do |h|
            due = @retries[h.root]
            next if due.nil? || now < due[1] || @ignored.include?(h.entry_id) || @fetching.key?(h.root) || held?(h.root)

            fetch(h)
          end
        end
      end

      # The engine's periodic work, which Pdt#tick runs: fetches due again, then
      # this writer's own heads renewed or cancelled (PDT 2 phase 7, P2-X-06).
      def tick
        retry_due
        @lock.synchronize { tend_own }
      end

      # Applies the block to the current value and writes the result as a new head
      # in multi mode (PDT 2 phase 7, P2-X-06; PD-R-03); returns the block's value.
      # An unchanged value writes nothing. The block runs with no lock held, and
      # the head's base is the heads read before it ran.
      def swap
        if @kind == Refs::KIND_DB
          raise ArgumentError, "Ruby reads db refs and writes none; write db refs from agentspaces-datascript, " \
                               "the Clojure DataScript face"
        end

        heads, current = @lock.synchronize do
          read = Refs.heads_among(loadable(live_entries, true))
          linear = read.find { |h| h.mode != Refs::MODE_MULTI }
          if linear
            raise ArgumentError, "#{@name} holds a #{linear.mode} head, and Ruby writes multi mode only; " \
                                 "use mode multi for a ref a Ruby agent writes"
          end

          [read, read.empty? ? empty_value : plain(materialize(read))]
        end
        value = yield(current)
        @lock.synchronize { publish(heads, value) }
        value
      end

      private

      # A value as plain Ruby, a text owned by this writer's replica so the block can edit it.
      def plain(value)
        case value
        when PMap then value.to_h.transform_values { |v| owned(v) }
        when Hash then value.transform_values { |v| owned(v) }
        when PSet then value.to_set
        when PVector then value.to_a.map { |v| owned(v) }
        when PBlob then value.read_all
        else value
        end
      end

      def owned(value) = value.is_a?(PText) ? value.with_replica(@pdt.replica) : value

      # The tree of a value of this ref's kind, written: [root, size, whether it holds a text].
      def build(value, flusher)
        case @kind
        when Refs::KIND_MAP, Refs::KIND_TREE
          raise ArgumentError, "a #{@kind} ref's value is a Hash, found #{value.class}" unless value.is_a?(Hash)

          items = value.map { |k, v| [Values.encode_value(k), Values.encode_value(v)] }
          root = Build::MapNode.of(items)
          [flusher.cid_of(root), root.cnt, items.flatten.any? { |item| PText.value?(item) }]
        when Refs::KIND_SET
          raise ArgumentError, "a set ref's value is a Set or an Array, found #{value.class}" unless value.is_a?(Set) || value.is_a?(Array)

          keys = value.to_a.map { |k| Values.encode_value(k) }
          root = Build::MapNode.of(keys.map { |k| [k, CBOR.dump(nil)] })
          [flusher.cid_of(root), root.cnt, keys.any? { |k| PText.value?(k) }]
        when Refs::KIND_VECTOR
          raise ArgumentError, "a vector ref's value is an Array, found #{value.class}" unless value.is_a?(Array)

          items = value.map { |v| Values.encode_value(v) }
          [flusher.cid_of(Build::VecBuild.of(items.map { |item| Build.spill(item) })), items.size,
           items.any? { |item| PText.value?(item) }]
        when Refs::KIND_BLOB
          raise ArgumentError, "a blob ref's value is a String of bytes, found #{value.class}" unless value.is_a?(String)

          [Build.blob(value.b, flusher), value.bytesize, false]
        end
      end

      # Writes the head of a new version over the heads read (PD-R-03, PD-X-07, P2-F-06).
      def publish(heads, value)
        flusher = Build::Flusher.new(store)
        root, size, text = build(value, flusher)
        return if heads.size == 1 && heads[0].root == root

        delta = flusher.written.values
        inline = !delta.empty? && delta.sum(&:bytesize) <= Refs::INLINE_DELTA_BYTES ? delta : nil
        base = heads.map(&:root).last(Refs::MAX_BASE)
        seq = [heads.map(&:seq).max || 0, Refs::MAX_SEQ - 1].min + 1
        # rule 8 of 6.10.3: a head whose tree holds a level-2 kind, here a text, is version 2
        record = Refs.record(name: @name, kind: @kind, root: root, base: base, seq: seq, size: size, nodes: inline,
                             mode: Refs::MODE_MULTI, sealing: @pdt.sealing, version: text ? Refs::VERSION_2 : Refs::VERSION,
                             attrs: { Ancestry::ATTR => write_ancestry(root, base) })
        bad = Refs.violation(record)
        raise ArgumentError, "the new head of #{@name} would be ignored by every reader: #{bad}" if bad

        entry_id = @pdt.write_head(record)
        now = @pdt.peer.now_ms
        superseded = heads.map(&:root).to_set
        @own.each_value do |own|
          own.displaced = true if own.root == root
          own.superseded_at ||= now if superseded.include?(own.root)
        end
        @own[entry_id] = Own.new(entry_id, root, base, now, nil, false)
        live_entries
      end

      # Writes the vg node of a new version beside its delta and returns its CID
      # (P2-V-01, as Java's Refs.writeAncestry): the root, the bases, this writer, a
      # stamp of now, and a link to the vg node of each base that has one. A linked
      # node this store lacks is fetched, so a walk that reads this node finds the
      # next one here.
      def write_ancestry(root, base)
        previous = base.filter_map { |b| @ancestry[b] }
        wanted = previous.reject { |cid| store.has?(cid) }
        unless wanted.empty? || @pdt.trees.nil?
          @pdt.trees.fetch_nodes(wanted, prefer: base.filter_map { |b| @known[b]&.issuer_peer }.uniq)
        end
        writer = @pdt.writer
        node = VgNode.new(root, base, writer, "#{@pdt.peer.now_ms}:0:#{writer}", previous.map { |cid| Nodes::Link.new(cid) })
        cid = store.put(node.encode)
        keep(@ancestry, root, cid)
        keep(@chain, root, node)
        cid
      end

      # Renews this writer's live heads at half their lease and cancels a
      # superseded one after the grace; an own head no longer present is forgotten.
      def tend_own
        return if @own.empty?

        peer = @pdt.peer
        now = peer.now_ms
        live = live_entries
        live_ids = live.to_set(&:entry_id)
        live_roots = live.to_set(&:root)
        below = cancellable(live)
        @own.values.each do |own|
          next @own.delete(own.entry_id) unless live_ids.include?(own.entry_id)

          superseded = below.include?(own.root) || (own.displaced && own.base.none? { |b| live_roots.include?(b) })
          own.superseded_at = superseded ? own.superseded_at || now : nil
          if own.superseded_at
            next if now - own.superseded_at < @pdt.cancel_grace_ms

            peer.cancel_entry(@pdt.space, own.entry_id)
            @own.delete(own.entry_id)
          elsif now - own.renewed_at >= @pdt.head_lease_ms / 2
            peer.renew_entry(@pdt.space, own.entry_id, lease_millis: @pdt.head_lease_ms)
            own.renewed_at = now
          end
        end
      end

      # The roots strictly below the lowest common base of the held heads, bounded
      # by the heads still arriving, so a head only an unloadable successor lists
      # stays live (Java's cancellation rule).
      def cancellable(live)
        heads = Refs.heads_among(live.select { |h| held?(h.root) })
        return Set.new if heads.empty?

        walks = heads.map { |h| ancestors(h.root) }
        bounds = live.reject { |h| held?(h.root) || @retries.key?(h.root) }.map { |h| ancestors(h.root).to_set }
        others = walks[0...-1].map(&:to_set) + bounds
        lowest = walks.last.find { |root| others.all? { |w| w.include?(root) } }
        return Set.new if lowest.nil?

        ancestors(lowest).drop(1).to_set
      end

      # The roots a version reaches over the bases this reader knows, breadth first and itself first.
      def ancestors(root)
        out = []
        seen = Set.new
        queue = [[root, 0]]
        until queue.empty?
          cid, depth = queue.shift
          next unless seen.add?(cid)

          out << cid
          next if depth >= Refs::MAX_BASE_STEPS

          (@known[cid]&.base || @chain[cid]&.bases || []).each { |b| queue << [b, depth + 1] }
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

      # One head: its value. Several: maps and sets merge key-wise against the lowest common base,
      # both-side conflicts taking the later head (LATER_HLC); without a base, and for vectors and
      # blobs, the later head wins whole (3.6.1). A merged map or set is a plain Hash or Set, since
      # this reader writes no node.
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
        base_entries = base == Refs::EMPTY_BASE ? {} : raw_map(base)
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
            elsif (union = text_union(current, now))
              # PDT 2 phase 7 (P2-T-05): two texts changed on both sides take their union, which raises no conflict
              merged[key] = union
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

      # The union of two text values, or nil when either is none or they disagree (P2-T-03).
      def text_union(mine, theirs)
        return nil if mine.nil? || theirs.nil? || !PText.value?(mine) || !PText.value?(theirs)

        PText.union(mine, theirs)
      end

      def raw_map(root)
        @raw_cache ||= {}
        @raw_cache[root] ||= PMap.load(root, loader).raw_entries.to_h
      end

      # The lowest common base of the heads (PD-R-06) as Java's Refs.commonBase
      # picks it: the first root in the breadth-first base walk of the latest
      # head that every other head's walk reaches, fetched from the heads'
      # issuers when this reader does not hold it, and nil when that fetch
      # fails. When the walks share no root but every walk ends at first
      # versions within the step limit, the two writers started from nothing
      # and the empty value is their base (HLC round five, 2026-11-08 (E16)).
      # Heads that are all first versions (each record names no base) have
      # the empty value as their base before any walk, whatever bases earlier
      # records of their roots named (HLC round six, 2026-11-08 (R4)).
      #
      # PDT 2 phase 1 (P2-V-02): the walks read a version's bases from its vg
      # node when this reader never saw its entry, the chain nodes it lacks
      # fetched by NODE_WANT from the heads' issuers first, then the writer of
      # every version this reader knows and each chain node's writer, as Java's
      # Refs.commonBase walks them. A head's writer may lack the node of its
      # base, which the base's own writer then alone holds (chain walk sources,
      # srad/agentspaces-pdt2.md 10.20).
      def common_base(heads)
        return Refs::EMPTY_BASE if heads.all? { |h| h.base.empty? }

        sources = (heads.map(&:issuer_peer) + @known.each_value.map(&:issuer_peer)).uniq
        reader = ChainReader.new(@pdt.trees, store, sources, @pdt.load_timeout, @chain_misses, @stats)
        walks = heads.map { |h| base_walk(h.root, reader) }
        others = walks[0...-1].map { |w| w[:roots].to_set }
        candidate = walks.last[:roots].find { |r| others.all? { |o| o.include?(r) } }
        return walks.all? { |w| w[:ends_at_first] } ? Refs::EMPTY_BASE : nil if candidate.nil?

        held?(candidate) || fetch_base(candidate, heads) ? candidate : nil
      end

      # The roots reachable from a root over base links, breadth first and the
      # root itself first, at most MAX_BASE_STEPS links deep, as Java's
      # Refs.walk walks them: a root first reached at that step joins the walk
      # and its bases are not followed. A version reads its bases from the
      # entries seen and, when no entry of it was seen, from its vg node (PDT 2
      # phase 1, P2-V-02); a version neither describes ends the walk there.
      # The walk ends at first versions when every root it reaches has bases
      # this reader can read and every version it reaches at step
      # MAX_BASE_STEPS has no base, so a revert cycle within the limit ends at
      # first versions and a version at the limit with a base does not,
      # wherever that base lies (HLC round five, 2026-11-08 (E16)).
      def base_walk(root, reader)
        roots = []
        seen = Set.new
        ends_at_first = true
        queue = [[root, 0]]
        until queue.empty?
          cid, depth = queue.shift
          next unless seen.add?(cid)

          roots << cid
          bases = bases_of(cid, reader)
          if bases.nil?
            ends_at_first = false
            next
          end
          if depth >= Refs::MAX_BASE_STEPS
            ends_at_first &&= bases.empty?
            next
          end
          learn_parents(cid, bases, reader)
          bases.each { |b| queue << [b, depth + 1] unless seen.include?(b) }
        end
        { roots: roots, ends_at_first: ends_at_first }
      end

      # The bases of a version: from the entries seen, else from its vg node; nil when neither describes it.
      def bases_of(root, reader)
        version = @known[root]
        return version.base unless version.nil?

        chain_node(root, reader)&.bases
      end

      # The vg node of a version: read before, or read now through the CID its
      # head or a child's link names. A CID whose bytes are held and name no
      # usable node is forgotten, so the version reads as one without
      # ancestry. A node that is late stays the version's vg node, so the next
      # walk asks again and the next version this writer writes still links it
      # (chain walk sources, srad/agentspaces-pdt2.md 10.20).
      def chain_node(root, reader)
        node = @chain[root]
        return node unless node.nil?

        cid = @ancestry[root]
        return nil if cid.nil?

        reader.prefetch([cid])
        bytes = store.get(cid)
        return nil if bytes.nil?

        node = Ancestry.node(cid, root, bytes)
        if node.nil?
          @ancestry.delete(root)
          return nil
        end
        keep(@chain, root, node)
        reader.read(node)
        node
      end

      # Learns the vg node of each base of a version that neither the entries
      # seen nor an earlier link describe: the version's own node links one
      # per base, so its links are read and each kept under the base it
      # describes.
      def learn_parents(root, bases, reader)
        return unless bases.any? { |b| !@known.key?(b) && !@ancestry.key?(b) && !@chain.key?(b) }

        child = chain_node(root, reader)
        return if child.nil?

        links = child.previous.map(&:cid)
        reader.prefetch(links)
        links.each do |cid|
          bytes = store.get(cid)
          parent = bytes && Ancestry.node(cid, nil, bytes)
          next unless parent && bases.include?(parent.root)

          keep(@ancestry, parent.root, cid)
          keep(@chain, parent.root, parent)
          reader.read(parent)
        end
      end

      # Puts a root's entry unless one is there, the eldest leaving past Refs::KNOWN_CAPACITY.
      def keep(map, root, value)
        return if map.key?(root)

        map[root] = value
        map.shift if map.size > Refs::KNOWN_CAPACITY
      end

      # Fetches a common base this reader does not hold from the heads' issuers,
      # the held heads as haves, as Java's Refs.commonBase does, and from the
      # writer its vg node names when this reader never saw its entry (P2-V-02);
      # true when the base is held complete afterwards.
      def fetch_base(root, heads)
        haves = heads.map(&:root).select { |r| held?(r) }
        prefer = heads.map(&:issuer_peer).uniq
        node = @chain[root]
        prefer |= [node.issuer.split("/", 2).first] if !@known.key?(root) && node
        @pdt.trees.fetch_tree(root, haves: haves, prefer: prefer, timeout: @pdt.load_timeout).wait(@pdt.load_timeout)
        return false unless held?(root)

        @stats[:bases_fetched] += 1
        true
      end
    end

    # Where a base walk's vg nodes come from (PDT 2 phase 1, P2-V-02), as
    # Java's Refs.ChainReader: the store, then one bare NODE_WANT batch per
    # call to the sources common_base names and the writer of each node read,
    # bounded by the load timeout, until the first batch that fails ends the
    # fetching for the walk, so a walk with no reachable holder costs one
    # timeout at most.
    # A node the walk could not get, since a batch did not bring it or the
    # walk met it after the batch that failed, waits out the backoff of
    # Refs.back_off, the rule of a failed head fetch, and a walk during the
    # backoff leaves the link out at once and counts it in chainNodesMissed
    # (PDT 2 phase 7 gate; swarm retries, ROBUSTNESS.md 10.2).
    class ChainReader
      def initialize(trees, store, sources, timeout, misses, stats)
        @trees = trees
        @store = store
        @sources = sources.dup
        @timeout = timeout
        @misses = misses
        @stats = stats
        @missed = Set.new
        @failed = false
      end

      # A node read names its writer, who holds the nodes it linked: a source for the rest of the walk.
      def read(node)
        writer = node.issuer.split("/", 2).first
        @sources << writer unless @sources.include?(writer)
      end

      def prefetch(cids)
        return if @trees.nil?

        now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        missing = []
        cids.each do |c|
          next if @store.has?(c)

          if @failed
            miss(c, true)
          elsif @misses.key?(c) && now < @misses[c][1]
            miss(c, false)
          elsif missing.size < Tree::MAX_WANT_CIDS
            missing << c
          end
        end
        return if missing.empty?

        @failed = !@trees.fetch_nodes(missing, prefer: @sources, timeout: @timeout).wait(@timeout)
        missing.each { |c| @store.has?(c) ? @misses.delete(c) : miss(c, true) }
      end

      private

      # Leaves a vg node out of this walk, counted once; a node that failed now starts or doubles its backoff.
      def miss(cid, failed_now)
        return unless @missed.add?(cid)

        @stats[:chain_nodes_missed] += 1
        return unless failed_now

        Refs.back_off(@misses, cid, @timeout)
        @misses.shift if @misses.size > Refs::KNOWN_CAPACITY
      end
    end

    # The reader over a peer's ref space (PD-C-06): one node store, the tree
    # fetcher over the content swarm, and a handle per ref name.
    class Pdt
      # A head's write lease (PD-R-08) and the wait before a writer cancels its superseded head (PD-R-03), as Java's.
      HEAD_LEASE_MS = 10 * 60 * 1000
      CANCEL_GRACE_MS = 2000

      attr_reader :peer, :space, :space_id, :store, :trees, :load_timeout, :writer, :replica, :sealing, :head_lease_ms,
                  :cancel_grace_ms

      # peer: a connected AgentSpaces::Peer; space: the ref space's name (the
      # Spring starter's default is "pdt", Micronaut's "refs"); keys: content
      # keys by epoch for a group that seals nodes in transit (group-key).
      # PDT 2 phase 7 (P2-X-06): agent_name names the writer of the heads this
      # face writes (peer id/agent_name), whose replica id edits texts.
      def initialize(peer, space: "pdt", store: nil, trees: nil, keys: {}, load_timeout: 10.0, agent_name: "ruby",
                     head_lease_ms: HEAD_LEASE_MS, cancel_grace_ms: CANCEL_GRACE_MS)
        raise ArgumentError, "a cancel grace is at least #{CANCEL_GRACE_MS} ms" if cancel_grace_ms < CANCEL_GRACE_MS

        @peer = peer
        @space = space.to_s
        @space_id = Derive.space_id_local("#{peer.group}/#{@space}")
        @store = store || NodeStore.new
        @trees = trees || Trees.new(peer, @store, keys: keys, load_timeout: load_timeout)
        @load_timeout = load_timeout
        @agent_name = agent_name
        @writer = peer.identity.agent(agent_name)
        @replica = PText.replica_of(@writer)
        @sealing = keys.empty? ? Refs::SEALING_NONE : Refs::SEALING_GROUP_KEY
        @head_lease_ms = head_lease_ms
        @cancel_grace_ms = cancel_grace_ms
        @refs = {}
        peer.pull_space(@space) if peer.connected?
        peer.pull_ads if peer.connected?
      end

      def loader(prefer = []) = @trees.loader(prefer)

      # Drives the fetches in flight and fetches again the live heads whose
      # fetch failed, once their backoff ends (swarm retries, ROBUSTNESS.md 10.3
      # E3), renews and cancels this writer's own heads, and renews the
      # advertisement of a face that serves (PDT 2 phase 7, P2-X-06); a host
      # calls it on its tick.
      def tick
        @trees.tick
        @refs.each_value(&:tick)
      end

      # Asks the group's content stores to hold a tree this face holds complete
      # (PDT 2 phase 7, P2-C-02): writes one SignedPin naming the stores chosen
      # (Stores.store_for); lease in seconds; returns [the pin's terms, the cards].
      def store_for(root, copies:, lease:, tier: nil, max_price: nil, space: Stores::CONTENT_SPACE)
        Stores.store_for(self, root, copies: copies, lease: lease, tier: tier, max_price: max_price, space: space)
      end

      # Writes one head entry and serves its nodes from then on (PDT 2 phase 7, P2-X-06).
      def write_head(record)
        entry_id = @peer.write_entry(@space, Refs::TYPE, record, agent_name: @agent_name, lease_millis: @head_lease_ms,
                                                               tags: Refs.tags(record))
        @trees.serve!
        entry_id
      end

      def ref(name, kind: Refs::KIND_MAP)
        raise ArgumentError, "unknown kind #{kind.inspect}; one of #{Refs::KINDS.join(', ')}" unless Refs::KINDS.include?(kind)

        @refs[[name.to_s, kind]] ||= Ref.new(self, name.to_s, kind)
      end

      def map_ref(name) = ref(name, kind: Refs::KIND_MAP)
      def set_ref(name) = ref(name, kind: Refs::KIND_SET)
      def vector_ref(name) = ref(name, kind: Refs::KIND_VECTOR)
      def blob_ref(name) = ref(name, kind: Refs::KIND_BLOB)
      def tree_ref(name) = ref(name, kind: Refs::KIND_TREE)
      def db_ref(name) = ref(name, kind: Refs::KIND_DB)

      # A value by root alone, for a payloadRef a space entry carries (PD-C-06):
      # loaded when held or fetchable, else the root stays an opaque string.
      def value_at(root, kind: Refs::KIND_MAP, prefer: [])
        Cids.parse(root)
        case kind
        when Refs::KIND_MAP, Refs::KIND_TREE then PMap.load(root, loader(prefer))
        when Refs::KIND_SET then PSet.load(root, loader(prefer))
        when Refs::KIND_VECTOR then PVector.load(root, loader(prefer))
        when Refs::KIND_BLOB then PBlob.load(root, loader(prefer))
        when Refs::KIND_DB then DbReader.new(root, loader(prefer))
        else raise ArgumentError, "unknown kind #{kind.inspect}"
        end
      end

      def stats
        totals = Hash.new(0)
        @refs.each_value { |r| r.stats.each { |k, v| totals[k] += v } }
        { "refs" => @refs.size, "nodesHeld" => @store.size, "bytesHeld" => @store.bytes_used,
          "deltasInline" => totals[:deltas_inline], "deltasFetched" => totals[:deltas_fetched],
          "conflicts" => totals[:conflicts], "headsIgnored" => totals[:heads_ignored], "headsLate" => totals[:heads_late],
          "nodesDropped" => totals[:nodes_dropped], "basesFetched" => totals[:bases_fetched],
          "chainNodesMissed" => totals[:chain_nodes_missed] }.merge(@trees.stats.transform_keys(&:to_s))
      end
    end
  end
end
