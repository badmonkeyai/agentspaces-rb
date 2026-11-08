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
    # An interior or leaf node of the vector trie (srad/agentspaces-pdt.md 3.2
    # and 10.2, PD-V-03): {k:"v", c:[links]} or {k:"v", e:[items]}, 32 slots.
    class VecNode
      BITS = 5
      WIDTH = 1 << BITS
      MASK = WIDTH - 1

      attr_reader :leaf, :slots, :cid

      def initialize(leaf, slots, cid)
        @leaf = leaf
        @slots = slots
        @cid = cid
      end

      def self.decode(cid, data)
        node = Nodes.decode(data, cid)
        raise NodeFormatError.new("expected a vector node, found kind '#{node['k']}'", cid) if node["k"] != Nodes::KIND_V

        has_c = node.key?("c")
        has_e = node.key?("e")
        raise NodeFormatError.new("a vector node holds either 'c' or 'e'", cid) if has_c == has_e

        list = has_c ? node["c"] : node["e"]
        raise NodeFormatError.new("vector node with #{list.size} slots; 1 to 32 expected", cid) if list.empty? || list.size > WIDTH
        raise NodeFormatError.new("vector leaf with #{list.size} items; a leaf in the trie holds exactly 32", cid) if has_e && list.size != WIDTH

        slots = has_c ? list.map(&:cid) : list.map { |e| Values.ref_of(e.bytes) }
        new(has_e, slots, cid)
      end

      def item(i)
        raise NodeFormatError.new("vector node has #{slots.size} slots where index #{i} was expected", cid) if i.negative? || i >= slots.size

        slots[i]
      end

      def child(i, loader)
        ref = item(i)
        return ref if ref.is_a?(VecNode)

        loaded = VecNode.decode(ref, loader.load(ref))
        slots[i] = loaded
        loaded
      end
    end

    # The root of a vector: {k:"vr", n, s, r, t}, the tail outside the trie as
    # Clojure's PersistentVector keeps it.
    class VecRoot
      BITS = VecNode::BITS
      WIDTH = VecNode::WIDTH
      MASK = VecNode::MASK

      attr_reader :n, :shift, :tail, :cid

      def self.tailoff(n) = n < WIDTH ? 0 : ((n - 1) >> BITS) << BITS

      def self.shift_for(n)
        off = tailoff(n)
        s = BITS
        s += BITS while off.positive? && ((off - 1) >> s) >= WIDTH
        s
      end

      def initialize(n, shift, trie, tail, cid)
        @n = n
        @shift = shift
        @trie = trie
        @tail = tail
        @cid = cid
      end

      def self.decode(cid, data)
        node = Nodes.decode(data, cid)
        raise NodeFormatError.new("expected a vector root, found kind '#{node['k']}'", cid) if node["k"] != Nodes::KIND_VR

        n = node.fetch("n", 0)
        shift = node.fetch("s", BITS)
        if n > 0x7FFFFFFF || shift < BITS || shift > 30 || (shift % BITS) != 0
          raise NodeFormatError.new("vector root with count #{n} and shift #{shift}", cid)
        end

        trie = node["r"]&.cid
        t = node["t"] || []
        raise NodeFormatError.new("vector tail of #{t.size} elements", cid) if t.size > WIDTH
        if t.size != n - tailoff(n) || trie.nil? != tailoff(n).zero?
          raise NodeFormatError.new("vector tail and trie do not match the count #{n}", cid)
        end
        if shift != shift_for(n)
          raise NodeFormatError.new("vector root with shift #{shift} where the count #{n} implies #{shift_for(n)}", cid)
        end

        new(n, shift, trie, t.map { |e| Values.ref_of(e.bytes) }, cid)
      end

      def tailoff = VecRoot.tailoff(n)

      def trie_node(loader)
        return @trie if @trie.is_a?(VecNode)

        loaded = VecNode.decode(@trie, loader.load(@trie))
        @trie = loaded
        loaded
      end

      def leaf_for(i, loader)
        node = trie_node(loader)
        level = shift
        while level.positive?
          node = node.child((i >> level) & MASK, loader)
          level -= BITS
        end
        node
      end

      def nth(i, loader)
        raise IndexError, "index #{i} of a vector of #{n}" if i.negative? || i >= n

        off = tailoff
        return tail[i - off] if i >= off

        leaf_for(i, loader).item(i & MASK)
      end
    end

    # A persistent vector read from a node store (PD-C-06): nth, iteration, and
    # count. The Ruby face reads only.
    class PVector
      include Enumerable

      attr_reader :root, :loader

      def self.load(root, loader)
        Cids.parse(root)
        new(root, VecRoot.decode(root, loader.load(root)), loader)
      end

      def initialize(root, node, loader)
        @root = root
        @node = node
        @loader = loader
      end

      def nth(i) = Values.decode_value(Values.resolve(@node.nth(Integer(i), @loader), @loader))

      def [](i)
        i = Integer(i)
        i += count if i.negative?
        return nil if i.negative? || i >= count

        nth(i)
      end

      def count = @node.n
      alias size count
      alias length count

      def empty? = count.zero?

      def last = count.zero? ? nil : nth(count - 1)

      def each
        return enum_for(:each) unless block_given?

        count.times { |i| yield nth(i) }
      end

      def ==(other) = other.is_a?(PVector) && other.root == root
      alias eql? ==
      def hash = root.hash

      def inspect = "#<AgentSpaces::PDT::PVector #{root} count=#{count}>"
    end
  end
end
