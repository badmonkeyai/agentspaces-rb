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
    # A node of the CHAMP trie (srad/agentspaces-pdt.md 3.2 and 10.2, PD-V-01,
    # PD-V-07): kind m, or mc past level 51. The key's hash is sha256 of its
    # canonical CBOR; level d reads bits 5d..5d+4 of the digest as a big-endian
    # bit string. A node loaded lazily is checked at its level (PD-N-04).
    class ChampNode
      COLLISION_LEVEL = 52
      NOT_FOUND = Object.new.freeze

      attr_reader :collision, :datamap, :nodemap, :keys, :values, :children, :cid
      attr_accessor :cnt

      def self.index(digest, level)
        first = level * 5
        idx = 0
        limit = digest.bytesize * 8
        5.times do |i|
          bit = first + i
          v = bit < limit ? (digest.getbyte(bit >> 3) >> (7 - (bit & 7))) & 1 : 0
          idx = (idx << 1) | v
        end
        idx
      end

      def self.popcount_below(mask, bit) = (mask & (bit - 1)).to_s(2).count("1")

      def initialize(collision, datamap, nodemap, keys, values, children, cid)
        @collision = collision
        @datamap = datamap
        @nodemap = nodemap
        @keys = keys
        @values = values
        @children = children
        @cnt = -1
        @cid = cid
      end

      def self.load(cid, level, loader)
        node = decode(cid, loader.load(cid), false)
        node.verify_at(level)
        node
      end

      def self.load_root(cid, data)
        node = decode(cid, data, true)
        node.verify_at(0)
        node
      end

      def self.decode(cid, data, root)
        node = Nodes.decode(data, cid)
        kind = node["k"]
        raise NodeFormatError.new("expected a map node, found kind '#{kind}'", cid) unless [Nodes::KIND_M, Nodes::KIND_MC].include?(kind)

        e = node["e"] || []
        raise NodeFormatError.new("entry list has an odd length #{e.size}", cid) if e.size.odd?

        keys = []
        values = []
        (e.size / 2).times do |i|
          key = e[2 * i].bytes
          raise NodeFormatError.new("entry #{i} has a bare link item as its key; keys never spill", cid) if Values.link_item?(key)

          keys << key
          values << Values.ref_of(e[(2 * i) + 1].bytes)
        end
        raise NodeFormatError.new("'cnt' on a node that is not a map root", cid) if node.key?("cnt") && !root

        if kind == Nodes::KIND_MC
          (1...keys.size).each do |i|
            raise NodeFormatError.new("collision node keys out of order", cid) if (keys[i - 1] <=> keys[i]) >= 0
          end
          return new(true, 0, 0, keys, values, [], cid)
        end
        datamap = node.fetch("d", 0)
        nodemap = node.fetch("n", 0)
        raise NodeFormatError.new("datamap or nodemap above 32 bits", cid) if datamap > 0xFFFFFFFF || nodemap > 0xFFFFFFFF
        raise NodeFormatError.new("datamap and nodemap share a slot", cid) unless (datamap & nodemap).zero?

        entries = datamap.to_s(2).count("1")
        raise NodeFormatError.new("datamap names #{entries} slots for #{keys.size} entries", cid) if entries != keys.size

        c = node["c"] || []
        kids = nodemap.to_s(2).count("1")
        raise NodeFormatError.new("nodemap names #{kids} slots for #{c.size} children", cid) if kids != c.size

        n = new(false, datamap, nodemap, keys, values, c.map(&:cid), cid)
        n.cnt = node["cnt"] if node.key?("cnt")
        n
      end

      def verify_at(level)
        if collision && level < COLLISION_LEVEL
          raise NodeFormatError.new("collision node at level #{level}; keys collide only past level #{COLLISION_LEVEL - 1}", cid)
        end
        if !collision && level >= COLLISION_LEVEL
          raise NodeFormatError.new("map node at level #{level}; keys past level #{COLLISION_LEVEL - 1} sit in a collision node", cid)
        end
        return if collision

        remaining = datamap
        keys.each_with_index do |key, i|
          slot = (remaining & -remaining).bit_length - 1
          remaining &= remaining - 1
          named = ChampNode.index(Cids.sha256(key), level)
          if named != slot
            raise NodeFormatError.new("entry #{i} sits in slot #{slot} at level #{level} where its key digest names slot #{named}", cid)
          end
        end
      end

      def child(i, level, loader)
        ref = children[i]
        return ref if ref.is_a?(ChampNode)

        loaded = ChampNode.load(ref, level, loader)
        children[i] = loaded
        loaded
      end

      def find(digest, level, key, loader)
        node = self
        loop do
          if node.collision
            i = node.keys.index(key)
            return i.nil? ? NOT_FOUND : node.values[i]
          end
          bit = 1 << ChampNode.index(digest, level)
          if (node.datamap & bit) != 0
            i = ChampNode.popcount_below(node.datamap, bit)
            return node.keys[i] == key ? node.values[i] : NOT_FOUND
          end
          return NOT_FOUND if (node.nodemap & bit).zero?

          level += 1
          node = node.child(ChampNode.popcount_below(node.nodemap, bit), level, loader)
        end
      end

      # Every [key bytes, value ref] under this node, entries before children, in slot order.
      def entries(level, loader)
        out = []
        stack = [[self, level]]
        until stack.empty?
          node, lvl = stack.pop
          out.concat(node.keys.zip(node.values))
          (node.children.size - 1).downto(0) { |i| stack << [node.child(i, lvl + 1, loader), lvl + 1] }
        end
        out
      end
    end

    # A persistent map read from a node store (PD-C-06): get by key, iteration,
    # and count, loading nodes on demand through the loader. The Ruby face
    # reads only; assoc and dissoc live on the JVM, Python, and TypeScript
    # faces. Keys and values are any CBOR value.
    class PMap
      include Enumerable

      attr_reader :root, :loader

      def self.load(root, loader)
        Cids.parse(root)
        node = ChampNode.load_root(root, loader.load(root))
        new(root, node, loader)
      end

      def initialize(root, node, loader)
        @root = root
        @node = node
        @loader = loader
      end

      def get(key, default = nil)
        kb = Values.encode_value(key)
        ref = @node.find(Cids.sha256(kb), 0, kb, @loader)
        return default if ref.equal?(ChampNode::NOT_FOUND)

        Values.decode_value(Values.resolve(ref, @loader))
      end

      def [](key) = get(key)

      def fetch(key)
        kb = Values.encode_value(key)
        ref = @node.find(Cids.sha256(kb), 0, kb, @loader)
        raise KeyError, "key not found: #{key.inspect}" if ref.equal?(ChampNode::NOT_FOUND)

        Values.decode_value(Values.resolve(ref, @loader))
      end

      def key?(key)
        kb = Values.encode_value(key)
        !@node.find(Cids.sha256(kb), 0, kb, @loader).equal?(ChampNode::NOT_FOUND)
      end

      # The count the root node carries; a count below zero walks the tree.
      def count
        return @node.cnt if @node.cnt >= 0

        @node.entries(0, @loader).size
      end
      alias size count
      alias length count

      def empty? = count.zero?

      def raw_entries = @node.entries(0, @loader).map { |k, v| [k, Values.resolve(v, @loader)] }

      def each
        return enum_for(:each) unless block_given?

        raw_entries.each { |k, v| yield Values.decode_value(k), Values.decode_value(v) }
      end

      def keys = @node.entries(0, @loader).map { |k, _| Values.decode_value(k) }

      def to_h
        out = {}
        each { |k, v| out[k] = v }
        out
      end

      def ==(other) = other.is_a?(PMap) && other.root == root
      alias eql? ==
      def hash = root.hash

      def inspect = "#<AgentSpaces::PDT::PMap #{root} count=#{count}>"
    end

    # A persistent set: a map whose values are null (PD-V-02).
    class PSet
      include Enumerable

      def self.load(root, loader) = new(PMap.load(root, loader))

      def initialize(pmap)
        @map = pmap
      end

      def root = @map.root

      def include?(element) = @map.key?(element)
      alias contains? include?
      alias member? include?

      def count = @map.count
      alias size count

      def empty? = count.zero?

      def each(&block)
        return enum_for(:each) unless block

        @map.keys.each(&block)
      end

      def to_set = Set.new(to_a)

      def as_map = @map

      def ==(other) = other.is_a?(PSet) && other.root == root
      alias eql? ==
      def hash = root.hash

      def inspect = "#<AgentSpaces::PDT::PSet #{root} count=#{count}>"
    end
  end
end
