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
    #
    # PDT 2 phase 7 (P2-C-02, P2-R-04; srad/agentspaces-pdt2.md 3.7): under an rr
    # root a leaf holds 1 to 32 items, and an interior node whose children are not
    # all full, the last one aside, is relaxed: kind rv with z, the cumulative
    # element counts of its children (sizes). decode_relaxed reads both kinds at a
    # known level, as Java's VecNode.decodeRelaxed reads them.
    class VecNode
      BITS = 5
      WIDTH = 1 << BITS
      MASK = WIDTH - 1

      attr_reader :leaf, :slots, :sizes, :cid

      def initialize(leaf, slots, cid, sizes = nil)
        @leaf = leaf
        @slots = slots
        @cid = cid
        @sizes = sizes
      end

      def self.decode(cid, data)
        node = decode_v(cid, data)
        raise NodeFormatError.new("vector leaf with #{node.slots.size} items; a leaf in the trie holds exactly 32", cid) if node.leaf && node.slots.size != WIDTH

        node
      end

      # A v node of 1 to 32 slots.
      def self.decode_v(cid, data)
        node = Nodes.decode(data, cid)
        raise NodeFormatError.new("expected a vector node, found kind '#{node['k']}'", cid) if node["k"] != Nodes::KIND_V

        has_c = node.key?("c")
        has_e = node.key?("e")
        raise NodeFormatError.new("a vector node holds either 'c' or 'e'", cid) if has_c == has_e

        list = has_c ? node["c"] : node["e"]
        raise NodeFormatError.new("vector node with #{list.size} slots; 1 to 32 expected", cid) if list.empty? || list.size > WIDTH

        slots = has_c ? list.map(&:cid) : list.map { |e| Values.ref_of(e.bytes) }
        new(has_e, slots, cid)
      end

      # Reads a node of a relaxed tree at a known level (P2-R-04): a v leaf of 1 to
      # 32 items at level 0, a dense v interior node above it, or an rv node whose
      # size table describes a relaxed node. It refuses by name an rv node without z
      # (a dense interior node is a v node), a size table a radix index would read
      # the same way, a child that holds more elements than its level holds, and a
      # node that does not hold the count its parent gives it.
      def self.decode_relaxed(cid, data, level, count)
        node = Nodes.kind_of(data) == Nodes::KIND_RV ? decode_rv(cid, data, level) : decode_dense(cid, data, level)
        width = node.slots.size
        capacity = 1 << level
        fits = node.sizes ? node.sizes.last == count : (width - 1) * capacity < count && count <= width * capacity
        return node if fits

        raise NodeFormatError.new("a vector node of #{width} slots at level #{level} does not hold the #{count} elements " \
                                  "its parent counts under it", cid)
      end

      def self.decode_dense(cid, data, level)
        node = decode_v(cid, data)
        return node if node.leaf == level.zero?

        raise NodeFormatError.new("a vector #{node.leaf ? 'leaf' : 'interior node'} at level #{level}", cid)
      end
      private_class_method :decode_dense

      def self.decode_rv(cid, data, level)
        raise NodeFormatError.new("an rv node where a vector leaf belongs", cid) if level.zero?

        rv = RvNode.decode(data, cid)
        raise NodeFormatError.new("an rv node without z; a dense interior node is a v node", cid) if rv.sizes.nil?

        capacity = 1 << level
        previous = 0
        dense = true
        rv.sizes.each_with_index do |size, i|
          raise NodeFormatError.new("an rv size of #{size} passes the 2^31 - 1 elements a vector holds", cid) if size > 0x7FFFFFFF
          if size - previous > capacity
            raise NodeFormatError.new("an rv child holds #{size - previous} elements, more than the #{capacity} its level holds", cid)
          end

          dense &&= i == rv.sizes.size - 1 || size - previous == capacity
          previous = size
        end
        raise NodeFormatError.new("a size table on a dense node; a dense interior node is a v node", cid) if dense

        new(false, rv.children.map(&:cid), cid, rv.sizes)
      end
      private_class_method :decode_rv

      # The elements under child j of a node at a level that holds count elements:
      # from the size table when relaxed, else a full child but the last.
      def child_count(j, level, count)
        return sizes[j] - (j.zero? ? 0 : sizes[j - 1]) if sizes

        last = slots.size - 1
        j < last ? 1 << level : count - (last << level)
      end

      # The child that holds a local index: by radix when dense, by binary search when relaxed.
      def locate(level, index)
        return index >> level if sizes.nil?

        sizes.bsearch_index { |size| size > index } || sizes.size - 1
      end

      # The elements before child j.
      def before(level, j)
        return j << level if sizes.nil?

        j.zero? ? 0 : sizes[j - 1]
      end

      # Child j of a relaxed node at a level, read and checked against the count it holds, and kept.
      def relaxed_child(j, level, count, loader)
        ref = item(j)
        return ref if ref.is_a?(VecNode)

        slots[j] = VecNode.decode_relaxed(ref, loader.load(ref), level, count)
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

      attr_reader :n, :shift, :tail, :cid, :relaxed

      def self.tailoff(n) = n < WIDTH ? 0 : ((n - 1) >> BITS) << BITS

      def self.shift_for(n)
        off = tailoff(n)
        s = BITS
        s += BITS while off.positive? && ((off - 1) >> s) >= WIDTH
        s
      end

      def initialize(n, shift, trie, tail, cid, relaxed: false)
        @n = n
        @shift = shift
        @trie = trie
        @tail = tail
        @cid = cid
        @relaxed = relaxed
      end

      def self.decode(cid, data)
        return decode_rr(cid, data) if Nodes.kind_of(data) == Nodes::KIND_RR

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

      # An rr root (PDT 2 phase 7, P2-R-04): the shape RrRoot checks, a count a
      # vector can hold, and a shift of at most 30; the nodes below load on demand.
      def self.decode_rr(cid, data)
        rr = RrRoot.decode(data, cid)
        raise NodeFormatError.new("rr root with count #{rr.count} and shift #{rr.shift}", cid) if rr.count > 0x7FFFFFFF || rr.shift > 30

        new(rr.count, rr.shift, rr.trie&.cid, rr.tail.map { |e| Values.ref_of(e.bytes) }, cid, relaxed: true)
      end

      def tailoff = relaxed ? n - tail.size : VecRoot.tailoff(n)

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
        return relaxed_nth(i, loader) if relaxed

        leaf_for(i, loader).item(i & MASK)
      end

      private

      # An index of a relaxed trie: down from the root by binary search on a relaxed
      # node and by radix on a dense one, each node checked against the count its
      # parent gives it, as Java's Rrb.leafAt walks it.
      def relaxed_nth(i, loader)
        count = tailoff
        unless @trie.is_a?(VecNode)
          @trie = VecNode.decode_relaxed(@trie, loader.load(@trie), shift, count)
        end
        node = @trie
        level = shift
        base = 0
        while level.positive?
          j = node.locate(level, i - base)
          base += node.before(level, j)
          count = node.child_count(j, level, count)
          node = node.relaxed_child(j, level - BITS, count, loader)
          level -= BITS
        end
        node.item(i - base)
      end
    end

    # A persistent vector read from a node store (PD-C-06): nth, iteration, and
    # count, over a vr root or, from PDT 2 phase 7 (P2-C-02), a relaxed rr root.
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

      # Whether the root is an rr root, a tree that lacks the vr shape (P2-R-01).
      def relaxed? = @node.relaxed

      # The packed form (PDT 2 phase 7, P2-R-03): the vr vector of the same
      # elements, written into a store; its root CID, which equals the root a vr
      # writer gives these elements.
      def pack(store)
        packed = Build::VecBuild.of(Array.new(count) { |i| @node.nth(i, @loader) })
        Build::Flusher.new(store).cid_of(packed)
      end

      def ==(other) = other.is_a?(PVector) && other.root == root
      alias eql? ==
      def hash = root.hash

      def inspect = "#<AgentSpaces::PDT::PVector #{root} count=#{count}>"
    end
  end
end
