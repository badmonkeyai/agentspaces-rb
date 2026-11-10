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
    CharId = Struct.new(:replica, :counter)

    # A character id of a text leaf: the replica and the counter (PDT 2 phase
    # 0, P2-T-01; srad/agentspaces-pdt2.md 3.9).
    class CharId
      def initialize(replica, counter)
        super(Kinds.own(replica), counter)
        freeze
        raise ArgumentError, "a character id names a non-empty replica" unless TextRun.text?(replica) && !replica.empty?
        raise ArgumentError, "a character counter is non-negative, found #{counter.inspect}" unless Kinds.uint?(counter)
      end

      # The order of character ids: the replica's UTF-8 bytes unsigned, then the counter.
      def order_key = [replica.b, counter]

      def to_s = "#{replica}:#{counter}"
    end

    TextRun = Struct.new(:replica, :counter, :parent, :side, :length, :deleted, :text)

    # One run of a text leaf, kind t (PDT 2 phase 0, P2-T-01; 3.9): a maximal
    # sequence of characters from one replica with consecutive counters, each
    # after the first the right child of the one before it. On the wire the
    # definite array [replica, counter, parent, side, length, deleted, text].
    # The Java build pinned three points 3.9 leaves open, so every port
    # writes the same bytes: parent is the Fugue parent of the run's first
    # character as a CharId, or nil under the document root; length counts
    # Unicode code points; a deleted run keeps its ids and drops its text.
    class TextRun
      LEFT = "L"
      RIGHT = "R"

      def self.text?(value) = value.is_a?(String) && value.encoding != Encoding::BINARY && value.valid_encoding?

      def initialize(replica, counter, parent, side, length, deleted, text)
        super(Kinds.own(replica), counter, parent, Kinds.own(side), length, deleted, Kinds.own(text))
        freeze
        check
      end

      private

      def check
        raise ArgumentError, "a run names a non-empty replica" unless TextRun.text?(replica) && !replica.empty?
        raise ArgumentError, "a run counter is non-negative, found #{counter.inspect}" unless Kinds.uint?(counter)
        raise ArgumentError, "a run parent is a character id or nil" unless parent.nil? || parent.is_a?(CharId)
        raise ArgumentError, "a run side is L or R, found '#{side}'" unless [LEFT, RIGHT].include?(side)
        # the document root is the leftmost neighbour of every insert, so Fugue gives it right children only
        raise ArgumentError, "a child of the document root hangs on its right, found side L" if parent.nil? && side == LEFT
        raise ArgumentError, "a run length is at least 1, found #{length.inspect}" unless length.is_a?(Integer) && length >= 1
        raise ArgumentError, "a run's counters pass 2^63 - 1" if counter > Nodes::MAX_INT - length
        raise ArgumentError, "a run's deleted flag is true or false" unless [true, false].include?(deleted)
        raise ArgumentError, "a run's text is UTF-8 text" unless TextRun.text?(text)
        raise ArgumentError, "a deleted run carries no text" if deleted && !text.empty?
        return if deleted || text.length == length

        raise ArgumentError, "a live run of length #{length} holds #{text.length} code points"
      end
    end

    TextLeaf = Struct.new(:runs)

    # A text leaf, kind t (PDT 2 phase 0, P2-T-01; 3.9): a Fugue sequence
    # stored as runs, { k:"t", r: [run...], v: 1 }. A writer puts a value
    # that holds text under a PRef.v 2 head (6.10.3, rule 3).
    #
    # One canonical form, so two replicas that hold the same characters write
    # the same bytes: the runs are maximal (a character continues the run
    # before it exactly when it comes from the same replica with the next
    # counter, hangs as the right child of that character, and shares its
    # deleted flag), and they are sorted by the id of their first character.
    # Every parent names a character of the leaf, and the parents form a tree
    # under the document root. The text reads in Fugue order: a character's
    # left children, the character, then its right children, same-side
    # siblings in id order. The union of two leaves is the union of their
    # characters, deleted when either side deleted it, which is Fugue's merge.
    class TextLeaf
      VERSION = 1
      REQUIRED = %w[r v].freeze
      # PDT 2 phase 0 (P2-T-01, gate finding G1): the most characters, live and
      # deleted, one leaf holds, the node byte bound. A deleted run costs no text
      # bytes, so this caps the tombstones the node bound leaves open, and every
      # reader checks it before it expands a run.
      MAX_CHARS = Nodes::MAX_NODE_BYTES

      # One character: its parent and side, whether it is deleted, and the character when live.
      Char = Struct.new(:parent, :left, :deleted, :char) do
        def join(id, other)
          if parent != other.parent || left != other.left || (!deleted && !other.deleted && char != other.char)
            raise ArgumentError, "two leaves disagree on character #{id}"
          end

          gone = deleted || other.deleted
          Char.new(parent, left, gone, gone ? nil : char)
        end
      end

      def initialize(runs)
        super(runs.dup.freeze)
        freeze
        chars = TextLeaf.expand(self.runs)
        raise ArgumentError, "the runs are not in canonical form: maximal, sorted by id" unless TextLeaf.compress(chars) == self.runs

        TextLeaf.order(chars)
      end

      # The canonical leaf of some runs, in any order and split anywhere.
      def self.of(runs) = new(compress(expand(runs)))

      # The union of two leaves: every character of either, deleted when either deleted it.
      def union(other)
        merged = TextLeaf.expand(runs)
        TextLeaf.expand(other.runs).each do |id, char|
          merged[id] = merged.key?(id) ? merged[id].join(id, char) : char
        end
        TextLeaf.new(TextLeaf.compress(merged))
      end

      # The runs as they read in Fugue order (PDT 2 phase 7, P2-T-05, as Java's
      # TextLeaf.pieces): characters of one run that sit next to each other, each
      # piece a TextRun whose text holds its live characters.
      def pieces
        chars = TextLeaf.expand(runs)
        order = TextLeaf.order(chars)
        out = []
        i = 0
        while i < order.size
          start = order[i]
          first = chars[start]
          text = +""
          j = i
          loop do
            last = order[j]
            text << chars[last].char unless chars[last].deleted
            j += 1
            break unless j < order.size && TextLeaf.continues?(last, order[j], chars[order[j]], first.deleted)
          end
          out << TextRun.new(start.replica, start.counter, first.parent, first.left ? TextRun::LEFT : TextRun::RIGHT, j - i,
                             first.deleted, text)
          i = j
        end
        out
      end

      def self.continues?(last, id, char, deleted)
        id.replica == last.replica && id.counter == last.counter + 1 && char.parent == last && !char.left &&
          char.deleted == deleted
      end

      # The live text in Fugue order.
      def text
        chars = TextLeaf.expand(runs)
        TextLeaf.order(chars).filter_map { |id| chars[id].char unless chars[id].deleted }.join
      end

      def encode = Nodes.encode({ Nodes::KIND_KEY => Nodes::KIND_T, "r" => runs, "v" => VERSION })

      # Reads a t node; refuses another kind, another version, or runs out of canonical form.
      def self.decode(bytes, cid = nil)
        node = Kinds.node(bytes, cid, Nodes::KIND_T, REQUIRED)
        raise NodeFormatError.new("text leaf version #{node['v']}; this release reads version #{VERSION}", cid) if node["v"] != VERSION

        Kinds.build(cid) { new(node["r"]) }
      end

      # Every character of some runs by id.
      def self.expand(runs)
        if runs.sum(&:length) > MAX_CHARS
          raise ArgumentError, "a text leaf holds at most #{MAX_CHARS} characters, live and deleted"
        end

        chars = {}
        runs.each do |run|
          live = run.deleted ? [] : run.text.chars
          run.length.times do |i|
            id = CharId.new(run.replica, run.counter + i)
            parent = i.zero? ? run.parent : CharId.new(run.replica, run.counter + i - 1)
            raise ArgumentError, "character #{id} appears twice" if chars.key?(id)

            chars[id] = Char.new(parent, i.zero? && run.side == TextRun::LEFT, run.deleted, live[i])
          end
        end
        chars
      end

      # The maximal runs of some characters, sorted by the id of their first character.
      def self.compress(chars)
        out = []
        start = first = last = nil
        length = 0
        text = +""
        chars.keys.sort_by(&:order_key).each do |id|
          char = chars[id]
          continues = !last.nil? && id.replica == last.replica && id.counter == last.counter + 1 &&
                      char.parent == last && !char.left && char.deleted == first.deleted
          unless continues
            out << run(start, first, length, text) unless start.nil?
            start = id
            first = char
            length = 0
            text = +""
          end
          length += 1
          text << char.char unless char.deleted
          last = id
        end
        out << run(start, first, length, text) unless start.nil?
        out
      end

      def self.run(start, first, length, text)
        TextRun.new(start.replica, start.counter, first.parent, first.left ? TextRun::LEFT : TextRun::RIGHT, length,
                    first.deleted, text)
      end
      private_class_method :run

      # The character ids in Fugue order, walked with an explicit stack so a
      # long run (a chain of right children) costs no call depth; refuses a
      # parent outside the leaf and parents that form a cycle.
      def self.order(chars)
        lefts = Hash.new { |h, k| h[k] = [] }
        rights = Hash.new { |h, k| h[k] = [] }
        roots = []
        chars.keys.sort_by(&:order_key).each do |id|
          parent = chars[id].parent
          next roots << id if parent.nil?
          raise ArgumentError, "the parent #{parent} of #{id} is not in the leaf" unless chars.key?(parent)

          (chars[id].left ? lefts : rights)[parent] << id
        end
        out = []
        stack = roots.reverse.map { |id| [id, false] }
        until stack.empty?
          id, emit = stack.pop
          next out << id if emit

          rights.fetch(id, []).reverse_each { |child| stack << [child, false] }
          stack << [id, true]
          lefts.fetch(id, []).reverse_each { |child| stack << [child, false] }
        end
        raise ArgumentError, "the runs' parents form a cycle that the document root does not reach" if out.size != chars.size

        out
      end
    end
  end
end
