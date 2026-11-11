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
    # The writer of the Ruby face (PDT 2 phase 7, P2-X-06; srad/agentspaces-pdt.md
    # 3.1 to 3.3 and 10.2): it builds the canonical tree of a value, the tree Java,
    # Python, and TypeScript build for the same value, and writes the nodes the
    # store lacks. Every layout is a function of the value, so a build from the
    # entries gives the root an edit gives: a CHAMP map places each key at the
    # shallowest level its digest prefix sets apart, a vr vector's shape follows
    # its count, and a blob's chunks and prolly nodes follow its bytes.
    #
    # A value slot holds the CBOR item of a value (a binary String), or a spilled
    # node under the rules of PD-N-05: above VALUE_LIMIT an x node, a t node for a
    # text value (P2-T-02), and above TREE_LIMIT a CHAMP sub-map (an ordered x
    # envelope when the map's keys are not in canonical order), a vr sub-vector,
    # or a blob tree for a byte string. A text CID names a node already stored.
    module Build
      VALUE_LIMIT = 1024
      TREE_LIMIT = 4096
      MAX_X_VALUE = Nodes::MAX_NODE_BYTES - 7
      WIDTH = 32
      BITS = 5
      MASK = WIDTH - 1
      # A prolly node closes after an entry whose CID digest opens below this (average fanout 32).
      BOUNDARY = 0x08000000
      MIN_FANOUT = 4
      MAX_FANOUT = 256

      # Hashes new nodes bottom up and writes those the store lacks (PD-V-08);
      # written keeps each node it stored, the delta a head may carry.
      class Flusher
        attr_reader :store, :written

        def initialize(store)
          @store = store
          @written = {}
        end

        def write(bytes, codec = Cids::DAG_CBOR)
          cid = Cids.of(bytes, codec)
          @written[cid] = bytes.b if @store.put_verified(cid, bytes)
          cid
        end

        # The CID of a slot that names a node: one stored, or a spilled node flushed now.
        def cid_of(ref) = ref.is_a?(String) ? ref : ref.cid || ref.flush(self)
      end

      # A node in memory, named by the flusher.
      class Node
        attr_reader :cid

        def flush(flusher)
          @cid = flusher.write(encode(flusher))
        end
      end

      # A value spill: {k:"x", v: item}.
      class XNode < Node
        def initialize(value)
          super()
          @value = value
        end

        def encode(_flusher) = Nodes.encode({ Nodes::KIND_KEY => Nodes::KIND_X, "v" => Nodes::Embedded.new(@value) })
      end

      # A text value above VALUE_LIMIT, spilled to the t node of the same leaf
      # (P2-T-02); the node bytes are computed at once, so a text past the node
      # bound is refused when it enters the value, as Java's TextNode refuses it.
      class TextNode < Node
        def initialize(value)
          super()
          @node = PText.leaf_of(value).encode
        rescue NodeFormatError => e
          raise ArgumentError, "a text value whose t node exceeds the 1 MiB node bound; " \
                               "split it into smaller texts: #{e.message}"
        end

        def encode(_flusher) = @node
      end

      # A byte string above TREE_LIMIT: the blob tree of its content.
      class BlobNode < Node
        def initialize(content)
          super()
          @content = content
        end

        def flush(flusher)
          @cid = Build.blob(@content, flusher)
        end
      end

      # A map whose keys are not in canonical order, kept in its written order:
      # an x node whose value links the vr of its keys and values.
      class OrderedNode < Node
        def initialize(items)
          super()
          @items = items
        end

        def encode(flusher) = XNode.new(Nodes.link_item(flusher.cid_of(@items))).encode(flusher)
      end

      # A CHAMP node under construction: kind m, or mc past level 51.
      class MapNode < Node
        attr_accessor :cnt

        def initialize(collision = false, datamap = 0, nodemap = 0, keys = [], values = [], children = [])
          super()
          @collision = collision
          @datamap = datamap
          @nodemap = nodemap
          @keys = keys
          @values = values
          @children = children
          @cnt = nil
        end

        # The root of a map of [key item, value item] pairs, every value spilled by
        # the rules, with its count; a key given twice keeps its last value.
        def self.of(entries)
          root = new
          count = 0
          entries.each do |key, value|
            Build.check_key(key)
            count += 1 if root.assoc(Cids.sha256(key), 0, key, Build.spill(value)) == :added
          end
          root.cnt = count
          root
        end

        def assoc(digest, level, key, value)
          return assoc_collision(key, value) if @collision

          bit = 1 << ChampNode.index(digest, level)
          if (@datamap & bit) != 0
            i = ChampNode.popcount_below(@datamap, bit)
            if @keys[i] == key
              @values[i] = value
              return :replaced
            end
            sub = MapNode.pair(@keys[i], @values[i], Cids.sha256(@keys[i]), key, value, digest, level + 1)
            @keys.delete_at(i)
            @values.delete_at(i)
            @datamap &= ~bit
            @nodemap |= bit
            @children.insert(ChampNode.popcount_below(@nodemap, bit), sub)
            return :added
          end
          return @children[ChampNode.popcount_below(@nodemap, bit)].assoc(digest, level + 1, key, value) if (@nodemap & bit) != 0

          @datamap |= bit
          at = ChampNode.popcount_below(@datamap, bit)
          @keys.insert(at, key)
          @values.insert(at, value)
          :added
        end

        # Two entries whose digests share the bits above level: a node that sets them apart.
        def self.pair(k1, v1, d1, k2, v2, d2, level)
          first = (k1 <=> k2).negative?
          return new(true, 0, 0, first ? [k1, k2] : [k2, k1], first ? [v1, v2] : [v2, v1]) if level >= ChampNode::COLLISION_LEVEL

          i1 = ChampNode.index(d1, level)
          i2 = ChampNode.index(d2, level)
          return new(false, 0, 1 << i1, [], [], [pair(k1, v1, d1, k2, v2, d2, level + 1)]) if i1 == i2

          lower = i1 < i2
          new(false, (1 << i1) | (1 << i2), 0, lower ? [k1, k2] : [k2, k1], lower ? [v1, v2] : [v2, v1])
        end

        def encode(flusher)
          entries = @keys.zip(@values).flat_map { |k, v| [Nodes::Embedded.new(k), Build.embed(v, flusher)] }
          return Nodes.encode({ Nodes::KIND_KEY => Nodes::KIND_MC, "e" => entries }) if @collision

          node = { Nodes::KIND_KEY => Nodes::KIND_M, "d" => @datamap, "n" => @nodemap, "e" => entries,
                   "c" => @children.map { |c| Nodes::Link.new(flusher.cid_of(c)) } }
          node["cnt"] = @cnt unless @cnt.nil?
          Nodes.encode(node)
        end

        private

        # A collision node keeps its keys in byte order.
        def assoc_collision(key, value)
          at = @keys.index { |k| (k <=> key) >= 0 } || @keys.size
          if @keys[at] == key
            @values[at] = value
            return :replaced
          end
          @keys.insert(at, key)
          @values.insert(at, value)
          :added
        end
      end

      # A node of the vector trie under construction, kind v: a leaf of element slots or an interior node.
      class VecTrieNode < Node
        attr_reader :slots

        def initialize(leaf, slots)
          super()
          @leaf = leaf
          @slots = slots
        end

        def encode(flusher)
          return Nodes.encode({ Nodes::KIND_KEY => Nodes::KIND_V, "e" => @slots.map { |s| Build.embed(s, flusher) } }) if @leaf

          Nodes.encode({ Nodes::KIND_KEY => Nodes::KIND_V, "c" => @slots.map { |c| Nodes::Link.new(flusher.cid_of(c)) } })
        end
      end

      # A vr vector under construction (PD-V-03): Clojure's PersistentVector conj,
      # the tail outside the trie, so the shape is a function of the count.
      class VecBuild < Node
        def initialize
          super()
          @count = 0
          @shift = BITS
          @trie = nil
          @tail = []
        end

        # A vector of slots in order, each an item already spilled or a node.
        def self.of(slots)
          vector = new
          slots.each { |slot| vector.conj(slot) }
          vector
        end

        def conj(slot)
          tailoff = @count < WIDTH ? 0 : ((@count - 1) >> BITS) << BITS
          if @count - tailoff < WIDTH
            @tail << slot
          else
            leaf = VecTrieNode.new(true, @tail)
            if @trie.nil?
              @trie = VecTrieNode.new(false, [leaf])
            elsif (@count >> BITS) > (1 << @shift)
              @trie = VecTrieNode.new(false, [@trie, path(@shift, leaf)])
              @shift += BITS
            else
              push_tail(@shift, @trie, leaf)
            end
            @tail = [slot]
          end
          @count += 1
          self
        end

        def encode(flusher)
          Nodes.encode({ Nodes::KIND_KEY => Nodes::KIND_VR, "n" => @count, "s" => @shift,
                         "r" => @trie.nil? ? nil : Nodes::Link.new(flusher.cid_of(@trie)),
                         "t" => @tail.map { |s| Build.embed(s, flusher) } })
        end

        private

        def path(level, node) = level.zero? ? node : VecTrieNode.new(false, [path(level - BITS, node)])

        def push_tail(level, parent, leaf)
          sub = ((@count - 1) >> level) & MASK
          if level == BITS
            parent.slots << leaf
          elsif sub < parent.slots.size
            push_tail(level - BITS, parent.slots[sub], leaf)
          else
            parent.slots << path(level - BITS, leaf)
          end
        end
      end

      module_function

      # The embedded item a slot writes: its own bytes, or the link item of the node it names.
      def embed(ref, flusher)
        return Nodes::Embedded.new(ref) if ref.is_a?(String) && ref.encoding == Encoding::BINARY

        Nodes::Embedded.new(Nodes.link_item(flusher.cid_of(ref)))
      end

      def check_key(key)
        return unless Nodes.link_shaped?(key)

        raise ArgumentError, "a key must not be a bare link item (CBOR tag 42 over a CID): a link item in a map node " \
                             "names a spilled node; hold a CID as text"
      end

      # Applies PD-N-05 to one encoded value: the item itself, or the node it spills to.
      def spill(item)
        if Nodes.link_shaped?(item)
          raise ArgumentError, "a value must not be a bare link item (CBOR tag 42 over a CID): a link item in a value " \
                               "slot names a spilled node; hold a CID as text"
        end
        return item if item.bytesize <= VALUE_LIMIT
        return TextNode.new(item) if PText.value?(item)

        major = item.getbyte(0) >> 5
        info = item.getbyte(0) & 0x1F
        if item.bytesize > TREE_LIMIT
          if major == 5 && info == 31
            return canonical_keys?(item) ? sub_map(item) : sub_ordered(item)
          elsif major == 4 && info != 31
            return VecBuild.of(elements(item).map { |element| spill(element) })
          elsif major == 2 && info != 31
            return BlobNode.new(item.byteslice(header_length(info)..))
          end
        end
        if item.bytesize > MAX_X_VALUE
          raise ArgumentError, "a value of #{item.bytesize} CBOR bytes exceeds the #{MAX_X_VALUE} bytes an x node can " \
                               "hold under the 1 MiB node bound; store a value this large as a byte string, " \
                               "which becomes a blob, or split it into a map or a vector"
        end
        XNode.new(item)
      end

      def header_length(info) = info < 24 ? 1 : 1 + (1 << (info - 24))

      # The [key item, value item] pairs of an indefinite map item.
      def pairs(item)
        out = []
        p = 1
        while p < item.bytesize && item.getbyte(p) != 0xFF
          key_end = Nodes.skip(item, p)
          value_end = Nodes.skip(item, key_end)
          out << [item.byteslice(p...key_end), item.byteslice(key_end...value_end)]
          p = value_end
        end
        out
      end

      # The element items of a definite array item.
      def elements(item)
        info = item.getbyte(0) & 0x1F
        p = header_length(info)
        n = info < 24 ? info : item.byteslice(1, p - 1).unpack1({ 2 => "C", 3 => "n", 5 => "N", 9 => "Q>" }.fetch(p))
        Array.new(n) do
          finish = Nodes.skip(item, p)
          element = item.byteslice(p...finish)
          p = finish
          element
        end
      end

      # Whether an indefinite map's keys come in canonical order (shorter first, then bytewise), the order the
      # Java codec gives a map and a CHAMP reassembly restores.
      def canonical_keys?(item) = pairs(item).map { |k, _| [k.bytesize, k] }.each_cons(2).all? { |a, b| (a <=> b).negative? }

      def sub_map(item) = MapNode.of(pairs(item))

      def sub_ordered(item)
        OrderedNode.new(VecBuild.of(pairs(item).flat_map do |key, value|
          check_key(key)
          [spill(key), spill(value)]
        end))
      end

      # Writes the blob tree of some bytes (PD-B-01, PD-B-02): FastCDC chunks as raw
      # nodes, then prolly levels of b nodes until one root is left; the root CID.
      def blob(content, flusher)
        chunks = FastCdc.chunks(content)
        return flusher.write("".b, Cids::RAW) if chunks.empty?

        level = chunks.map { |chunk| [flusher.write(chunk, Cids::RAW), chunk.bytesize] }
        height = 0
        while level.size > 1
          height += 1
          level = groups(level).map do |entries|
            node = { Nodes::KIND_KEY => Nodes::KIND_B, "h" => height, "c" => entries.map { |cid, _| Nodes::Link.new(cid) },
                     "z" => entries.map { |_, size| size } }
            [flusher.write(Nodes.encode(node)), entries.sum { |_, size| size }]
          end
        end
        level[0][0]
      end

      # One level's entries cut into nodes: a node closes at MAX_FANOUT, or after
      # MIN_FANOUT entries at an entry whose CID digest opens below BOUNDARY.
      def groups(level)
        out = []
        current = []
        level.each do |entry|
          current << entry
          next unless current.size >= MAX_FANOUT || (current.size >= MIN_FANOUT && Cids.parse(entry[0]).digest.unpack1("N") < BOUNDARY)

          out << current
          current = []
        end
        out << current unless current.empty?
        out
      end
    end
  end
end
