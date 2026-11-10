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
    # What the typed readers of the level-2 kinds share (PDT 2 phase 0).
    module Kinds
      module_function

      # Decodes a node of one kind and checks that every key the kind requires is present.
      def node(bytes, cid, kind, required)
        node = Nodes.decode(bytes, cid)
        raise NodeFormatError.new("kind '#{node[Nodes::KIND_KEY]}' where a '#{kind}' node belongs", cid) if node[Nodes::KIND_KEY] != kind

        required.each { |key| raise NodeFormatError.new("a '#{kind}' node lacks '#{key}'", cid) unless node.key?(key) }
        node
      end

      # Builds a typed value, turning the constructor's refusal into a refusal of the node.
      def build(cid)
        yield
      rescue ArgumentError => e
        raise if e.is_a?(NodeFormatError)

        raise NodeFormatError.new(e.message, cid)
      end

      def uint?(value) = value.is_a?(Integer) && value.between?(0, Nodes::MAX_INT)

      # A value's own frozen copy of a String argument (PDT 2 phase 0): text
      # in UTF-8, so ids and datoms order, compare, and hash by the bytes the
      # wire carries, and bytes as they are. Java's records are immutable, and
      # the frozen copy keeps a caller's later change from skipping the
      # constructor's checks. Other values pass through to those checks.
      def own(value)
        return value unless value.is_a?(String)
        return value.dup.freeze if value.encoding == Encoding::BINARY || !value.valid_encoding?

        value.encode(Encoding::UTF_8).freeze
      rescue EncodingError => e
        raise ArgumentError, "text with no UTF-8 form: #{e.message}"
      end
    end

    DbRoot = Struct.new(:schema, :max_eid, :max_tx, :branching, :eavt, :aevt, :avet, :tail)

    # The root of a DataScript database, kind db (PDT 2 phase 0, P2-D-01;
    # srad/agentspaces-pdt2.md 3.1.1): { k:"db", v: 1, s: schema, me: max-eid,
    # mt: max-tx, bf: branching-factor, i: { aevt, avet, eavt: link },
    # t: tail link or null }. The Java build pinned the key 3.1.1 lacked for
    # the tail that 3.1.3 links (10.4, phase 0): t is always present and
    # links the dn tail node, inline or not, or is null when every datom sits
    # in the indexes. The schema is an embedded map whose keys are the
    # keywords' print forms, or a spilled link to one.
    class DbRoot
      VERSION = 1
      BRANCHING = 128
      REQUIRED = %w[v s me mt bf i t].freeze

      def initialize(schema, max_eid, max_tx, branching, eavt, aevt, avet, tail)
        super
        freeze
        raise ArgumentError, "a db schema is an embedded item" unless schema.is_a?(Nodes::Embedded)
        raise ArgumentError, "a db schema is a map, or a spilled link to one" unless schema?(schema.bytes)
        raise ArgumentError, "max-eid and max-tx are non-negative" unless Kinds.uint?(max_eid) && Kinds.uint?(max_tx)
        raise ArgumentError, "a db root's branching factor is at least 2, found #{branching.inspect}" unless Kinds.uint?(branching) && branching >= 2
        raise ArgumentError, "a db root links its three indexes" unless [eavt, aevt, avet].all?(Nodes::Link)
        raise ArgumentError, "a db root's tail is a link or nil" unless tail.nil? || tail.is_a?(Nodes::Link)
      end

      def encode
        Nodes.encode({ Nodes::KIND_KEY => Nodes::KIND_DB, "v" => VERSION, "s" => schema, "me" => max_eid, "mt" => max_tx,
                       "bf" => branching, "i" => { "eavt" => eavt, "aevt" => aevt, "avet" => avet }, "t" => tail })
      end

      # Reads a db root; refuses another kind, another version, a missing key, or a broken field.
      def self.decode(bytes, cid = nil)
        node = Kinds.node(bytes, cid, Nodes::KIND_DB, REQUIRED)
        raise NodeFormatError.new("db root version #{node['v']}; this release reads version #{VERSION}", cid) if node["v"] != VERSION

        index = node["i"]
        Kinds.build(cid) do
          new(node["s"], node["me"], node["mt"], node["bf"], index["eavt"], index["aevt"], index["avet"], node["t"])
        end
      end

      private

      def schema?(item)
        Nodes.link_shaped?(item) || AgentSpaces::CBOR.load(item).is_a?(Hash)
      rescue AgentSpaces::CBOR::Error
        false
      end
    end

    DnNode = Struct.new(:level, :index, :datoms, :children)

    # A DataScript sorted-set node, kind dn (PDT 2 phase 0, P2-D-01; 3.1.1):
    # a leaf { k:"dn", l: 0, x: index, e: [datom...] }, a branch with
    # l >= 1 and c: [link...] whose e holds the largest key of each child in
    # the order of c, or a tail { k:"dn", l: 0, x: "tail", e: [datom...] }
    # with the datoms of one or more transactions in transaction order. The
    # comparator that orders a leaf or a branch is fixed by x; the reader of
    # P2-D-09 checks the order, since it owns the comparators.
    class DnNode
      EAVT = "eavt"
      AEVT = "aevt"
      AVET = "avet"
      TAIL = "tail"
      INDEXES = [EAVT, AEVT, AVET, TAIL].freeze
      REQUIRED = %w[l x e].freeze

      def initialize(level, index, datoms, children)
        super(level, Kinds.own(index), datoms.dup.freeze, children.dup.freeze)
        freeze
        unless INDEXES.include?(self.index)
          raise ArgumentError, "a dn node names index '#{self.index}'; the indexes are eavt, aevt, avet and tail"
        end
        raise ArgumentError, "a dn level is non-negative" unless Kinds.uint?(level)
        raise ArgumentError, "a dn node holds datoms" unless self.datoms.all?(Datom)
        raise ArgumentError, "a dn node links its children" unless self.children.all?(Nodes::Link)
        raise ArgumentError, "a tail is a leaf, found level #{level}" if index == TAIL && level != 0
        raise ArgumentError, "an empty tail is no node: the db root's 't' is null instead" if index == TAIL && self.datoms.empty?
        raise ArgumentError, "a leaf carries no 'c'" if level.zero? && !self.children.empty?
        return if level.zero? || (!self.datoms.empty? && self.children.size == self.datoms.size)

        raise ArgumentError, "a branch holds one link per key, found #{self.children.size} links for #{self.datoms.size} keys"
      end

      # The canonical node bytes; a leaf and a tail carry no c key.
      def encode
        node = { Nodes::KIND_KEY => Nodes::KIND_DN, "l" => level, "x" => index, "e" => datoms }
        node["c"] = children if level.positive?
        Nodes.encode(node)
      end

      def self.decode(bytes, cid = nil)
        node = Kinds.node(bytes, cid, Nodes::KIND_DN, REQUIRED)
        level = node["l"]
        raise NodeFormatError.new("a 'dn' node lacks 'c': a branch links its children", cid) if level.positive? && !node.key?("c")
        raise NodeFormatError.new("a leaf carries no 'c'", cid) if level.zero? && node.key?("c")

        Kinds.build(cid) { new(level, node["x"], node["e"], node.fetch("c", [])) }
      end
    end

    RrRoot = Struct.new(:count, :shift, :trie, :tail)

    # The root of an RRB vector that still holds a relaxed node, kind rr
    # (PDT 2 phase 0, P2-R-01; 3.7): { k:"rr", n: count, s: shift,
    # r: link or null, t: [tail] }, the vr shape over a trie of rv interior
    # nodes and v leaves. A head whose tree holds an rr or rv node is
    # PRef.v 2; the packed form is a vr tree (6.10.3, rule 2).
    class RrRoot
      WIDTH = 32
      BITS = 5
      REQUIRED = %w[n s r t].freeze

      def initialize(count, shift, trie, tail)
        super(count, shift, trie, tail.dup.freeze)
        freeze
        raise ArgumentError, "an rr shift is a positive multiple of #{BITS}, found #{shift.inspect}" unless Kinds.uint?(shift) && shift >= BITS && (shift % BITS).zero?
        raise ArgumentError, "an rr tail holds at most #{WIDTH} elements, found #{self.tail.size}" if self.tail.size > WIDTH
        raise ArgumentError, "an rr trie is a link or nil" unless trie.nil? || trie.is_a?(Nodes::Link)
        if !Kinds.uint?(count) || count < self.tail.size || (trie.nil? && count != self.tail.size)
          raise ArgumentError, "an rr count of #{count.inspect} does not fit a tail of #{self.tail.size}#{' and no trie' if trie.nil?}"
        end
        # an rv node holds at least one child, so a linked trie holds an element
        raise ArgumentError, "an rr root links a trie but its count of #{count} leaves the trie no element" if trie && count == self.tail.size
      end

      def encode = Nodes.encode({ Nodes::KIND_KEY => Nodes::KIND_RR, "n" => count, "s" => shift, "r" => trie, "t" => tail })

      def self.decode(bytes, cid = nil)
        node = Kinds.node(bytes, cid, Nodes::KIND_RR, REQUIRED)
        Kinds.build(cid) { new(node["n"], node["s"], node["r"], node["t"]) }
      end
    end

    RvNode = Struct.new(:children, :sizes)

    # An interior node of an RRB vector, kind rv (PDT 2 phase 0, P2-R-01;
    # 3.7): { k:"rv", c: [link...], z: [cumulative sizes] }, z present only
    # on a relaxed node, one whose children are not all full.
    class RvNode
      REQUIRED = %w[c].freeze

      def initialize(children, sizes)
        super(children.dup.freeze, sizes&.dup&.freeze)
        freeze
        unless self.children.size.between?(1, RrRoot::WIDTH) && self.children.all?(Nodes::Link)
          raise ArgumentError, "an rv node links 1 to #{RrRoot::WIDTH} children, found #{self.children.size}"
        end
        return if self.sizes.nil?
        raise ArgumentError, "an rv size table holds one size per child" if self.sizes.size != self.children.size

        increasing = self.sizes.all? { |size| Kinds.uint?(size) } && ([0] + self.sizes).each_cons(2).all? { |a, b| b > a }
        raise ArgumentError, "an rv size table is strictly increasing from above 0" unless increasing
      end

      # The canonical node bytes; a dense node carries no z key.
      def encode
        node = { Nodes::KIND_KEY => Nodes::KIND_RV, "c" => children }
        node["z"] = sizes unless sizes.nil?
        Nodes.encode(node)
      end

      def self.decode(bytes, cid = nil)
        node = Kinds.node(bytes, cid, Nodes::KIND_RV, REQUIRED)
        Kinds.build(cid) { new(node["c"], node["z"]) }
      end
    end

    VgNode = Struct.new(:root, :bases, :issuer, :issued, :previous)

    # A node of the persisted version graph, kind vg (PDT 2 phase 0, P2-V-01;
    # 3.10): { k:"vg", r: root, b: [base roots], i: issuer, t: issued,
    # p: [links to earlier vg nodes] }. A head names its node by the reserved
    # attribute pdt.ancestry; no value root links a vg node and no head
    # carries one inline (6.10.3, rule 4). The Java build pinned two points:
    # r and b are CIDs held as text, so a walk of the chain never reaches the
    # value trees, and p is a list with at most one link per base, so a merge
    # keeps the lineage of both parents.
    class VgNode
      REQUIRED = %w[r b i t p].freeze

      def initialize(root, bases, issuer, issued, previous)
        super(Kinds.own(root), bases.map { |base| Kinds.own(base) }.freeze, Kinds.own(issuer), Kinds.own(issued),
              previous.dup.freeze)
        freeze
        raise ArgumentError, "a vg node names at most #{Refs::MAX_BASE} bases, found #{self.bases.size}" if self.bases.size > Refs::MAX_BASE
        raise ArgumentError, "a vg node names its root and bases by CID" unless Cids.cid?(self.root) && self.bases.all? { |b| Cids.cid?(b) }
        raise ArgumentError, "a vg node links at most one earlier vg node per base" if self.previous.size > self.bases.size
        unless self.previous.all? { |link| link.is_a?(Nodes::Link) && link.structured? }
          raise ArgumentError, "a vg node links earlier vg nodes, which are dag-cbor"
        end
        raise ArgumentError, "a vg issuer is <peerId>/<localName>, found #{self.issuer.inspect}" unless Wire.agent_id?(self.issuer)
        raise ArgumentError, "a vg issued stamp is canonical, found #{self.issued.inspect}" if Wire.hlc_decode(self.issued).nil?
      end

      def encode
        Nodes.encode({ Nodes::KIND_KEY => Nodes::KIND_VG, "r" => root, "b" => bases, "i" => issuer, "t" => issued,
                       "p" => previous })
      end

      def self.decode(bytes, cid = nil)
        node = Kinds.node(bytes, cid, Nodes::KIND_VG, REQUIRED)
        Kinds.build(cid) { new(node["r"], node["b"], node["i"], node["t"], node["p"]) }
      end
    end

    BoNode = Struct.new(:size, :parents, :children)

    # A node of a blob's Bao outboard, kind bo (PDT 2 phase 0, P2-B-02; 3.5):
    # { k:"bo", g: 4, n: size, p: parent chaining values, c: [links to child
    # bo nodes] }, over chunk groups of 2^g BLAKE3 chunks (16 KiB, decision
    # 10), reached only through the attribute pdt.bao (6.10.3, rule 5). The
    # Java build pinned the split rule, so every port cuts the same tree:
    # p is one byte string of parent pairs (left then right chaining value,
    # 64 bytes) in pre-order; a node over at most LEAF_GROUPS groups (8 MiB,
    # PDT 2 phase 4 measures, P2-Q-PRF-05) is a leaf holding its subtree's
    # groups - 1 parents; a larger node over G
    # groups takes the smallest j >= 1 with G <= LEAF_GROUPS * FANOUT^j, links
    # one child per aligned block of LEAF_GROUPS * FANOUT^(j-1) groups, and
    # holds the parents above the cut, one fewer than its children. The shape
    # is a function of n alone, which the constructor checks.
    class BoNode
      GROUP_LOG = 4
      GROUP_BYTES = 1024 << GROUP_LOG
      PARENT_BYTES = 64
      LEAF_GROUPS = 1 << 9
      FANOUT = 1 << 4
      REQUIRED = %w[g n p c].freeze

      # The chunk groups a blob of size bytes holds: at least one, since an empty blob is one empty chunk.
      def self.groups(size) = [1, (size + GROUP_BYTES - 1) / GROUP_BYTES].max

      # The byte counts of the child blocks of a node over size bytes; empty for a leaf.
      def self.child_sizes(size)
        groups = groups(size)
        return [] if groups <= LEAF_GROUPS

        block = LEAF_GROUPS
        block *= FANOUT while groups > block * FANOUT
        block_bytes = block * GROUP_BYTES
        (0...size).step(block_bytes).map { |start| [block_bytes, size - start].min }
      end

      def initialize(size, parents, children)
        # parents are bytes, so a String in any encoding keeps its bytes
        super(size, parents.is_a?(String) ? parents.b.freeze : parents, children.dup.freeze)
        freeze
        raise ArgumentError, "a bo size is non-negative" unless Kinds.uint?(size)
        raise ArgumentError, "a bo node's parents are a byte string" unless parents.is_a?(String)
        raise ArgumentError, "a bo node links its children" unless self.children.all?(Nodes::Link)

        blocks = BoNode.child_sizes(size)
        if self.children.size != blocks.size
          raise ArgumentError, "a bo node over #{BoNode.groups(size)} groups has #{blocks.size} children, found #{self.children.size}"
        end
        expected = (blocks.empty? ? BoNode.groups(size) : blocks.size) - 1
        return if self.parents.bytesize == expected * PARENT_BYTES

        raise ArgumentError, "a bo node over #{size} bytes takes #{expected} parents, found #{self.parents.bytesize} bytes"
      end

      def encode
        Nodes.encode({ Nodes::KIND_KEY => Nodes::KIND_BO, "g" => GROUP_LOG, "n" => size, "p" => parents, "c" => children })
      end

      def self.decode(bytes, cid = nil)
        node = Kinds.node(bytes, cid, Nodes::KIND_BO, REQUIRED)
        if node["g"] != GROUP_LOG
          raise NodeFormatError.new("a bo node of group size 2^#{node['g']} chunks; this release reads 2^#{GROUP_LOG} (decision 10)", cid)
        end

        Kinds.build(cid) { new(node["n"], node["p"], node["c"]) }
      end
    end
  end
end
