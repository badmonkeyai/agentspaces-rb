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

require "digest"

module AgentSpaces
  module PDT
    # A text that merges (PDT 2 phase 7, P2-C-02 and P2-T-05; srad/agentspaces-pdt2.md
    # 3.9, as Java's PText): a Fugue sequence of characters with ids, edited by one
    # replica at a time, stored as a t leaf of runs (TextLeaf). Positions and lengths
    # count Unicode code points, as the runs do.
    #
    # An insert follows Fugue: the new characters hang as the right child of the
    # character before the position when it has no right child, else as the left
    # child of the next character in Fugue order (deleted ones included), and each
    # further character as the right child of the one before it. A replica numbers
    # its characters from one more than the largest counter it holds, so typing at
    # the cursor extends one run. A delete keeps the characters' ids and drops their
    # text. merge is the union of two texts, which every replica computes alike.
    #
    # As a value a text is the wire encoding of its leaf's map {k:"t", r:[run...],
    # v:1}, the map indefinite as every embedded item is, a run the array [replica,
    # counter, parent, side, length, deleted, text] and a parent [replica, counter]
    # or nil; value? and leaf_of read that form strictly. A text read from a ref
    # has no replica until the reader names one (with_replica, or Ref#swap, which
    # names the writer's), since only a replica edits.
    class PText
      MAX_CHARS = TextLeaf::MAX_CHARS
      # The first bytes of every text value: an indefinite map whose first key k holds "t".
      PREFIX = ["bf616b6174"].pack("H*").freeze
      VALUE_KEYS = %w[k r v].freeze

      # Characters of one run that sit next to each other in Fugue order;
      # last_right says whether the last of them has a right child anywhere.
      Piece = Struct.new(:replica, :counter, :length, :deleted, :text, :parent, :left, :last_right) do
        def visible = deleted ? 0 : length

        def first = CharId.new(replica, counter)

        def last = CharId.new(replica, counter + length - 1)

        # The first k characters; the last of them has the next one as its right child.
        def head(k) = Piece.new(replica, counter, k, deleted, deleted ? "" : text[0, k], parent, left, true)

        # The characters from k on; the first of them is the right child of the one before.
        def tail(k)
          Piece.new(replica, counter + k, length - k, deleted, deleted ? "" : text[k..], CharId.new(replica, counter + k - 1),
                    false, last_right)
        end

        def as_deleted = Piece.new(replica, counter, length, true, "", parent, left, last_right)

        def with_right = Piece.new(replica, counter, length, deleted, text, parent, left, true)

        def run = TextRun.new(replica, counter, parent, left ? TextRun::LEFT : TextRun::RIGHT, length, deleted, text)
      end

      attr_reader :replica, :length

      # The replica id of an agent: the first five bytes of the SHA-256 of its id's text as eight base32 characters.
      def self.replica_of(agent_id) = Cids.base32_lower(Digest::SHA256.digest(agent_id.to_s.encode(Encoding::UTF_8).b)[0, 5])

      def self.empty(replica) = new(replica, [], nil)

      # The text of a leaf, edited by a replica (nil reads only).
      def self.of(leaf, replica = nil)
        runs = leaf.runs.sort_by { |run| CharId.new(run.replica, run.counter).order_key }
        keys = runs.map { |run| CharId.new(run.replica, run.counter).order_key }
        right_parents = runs.select { |run| run.parent && run.side == TextRun::RIGHT }.to_set(&:parent)
        pieces = leaf.pieces.map do |p|
          last = CharId.new(p.replica, p.counter + p.length - 1)
          at = keys.bsearch_index { |key| (key <=> last.order_key).positive? }
          run = runs[(at || runs.size) - 1]
          inside = last.counter < run.counter + run.length - 1
          Piece.new(p.replica, p.counter, p.length, p.deleted, p.text, p.parent, p.side == TextRun::LEFT,
                    inside || right_parents.include?(last))
        end
        new(replica, pieces, leaf)
      end

      # Whether some CBOR bytes are a text in its value form.
      def self.value?(bytes)
        return false unless bytes.b.start_with?(PREFIX)

        leaf_of(bytes)
        true
      rescue ArgumentError
        false
      end

      # The leaf of a text value, read strictly: exactly the three keys, runs in
      # canonical form, and bytes that are the value form of the leaf they read as.
      def self.leaf_of(bytes)
        map = begin
          CBOR.load(bytes)
        rescue CBOR::Error => e
          raise ArgumentError, "a text value is one CBOR map in the wire encoding: #{e.message}"
        end
        unless map.is_a?(Hash) && map.keys == VALUE_KEYS && map["k"] == Nodes::KIND_T && map["r"].is_a?(Array) &&
               map["v"] == TextLeaf::VERSION
          raise ArgumentError, "a text value is {k:\"t\", r:[run...], v:1}"
        end

        leaf = TextLeaf.new(map["r"].map { |item| run_of(item) })
        raise ArgumentError, "the bytes are not the value form of the text they read as" unless to_wire(leaf) == bytes.b

        leaf
      end

      def self.run_of(item)
        unless item.is_a?(Array) && item.size == 7 && item[0].is_a?(String) && item[3].is_a?(String) &&
               [true, false].include?(item[5]) && item[6].is_a?(String) && item[1].is_a?(Integer) && item[4].is_a?(Integer)
          raise ArgumentError, "a text run is [replica, counter, parent, side, length, deleted, text]"
        end

        parent = item[2]
        unless parent.nil? || (parent.is_a?(Array) && parent.size == 2 && parent[0].is_a?(String) && parent[1].is_a?(Integer))
          raise ArgumentError, "a run's parent is [replica, counter] or null"
        end

        TextRun.new(item[0], item[1], parent && CharId.new(parent[0], parent[1]), item[3], item[4], item[5], item[6])
      end
      private_class_method :run_of

      # The value form of a leaf.
      def self.to_wire(leaf)
        runs = leaf.runs.map do |r|
          [r.replica, r.counter, r.parent && [r.parent.replica, r.parent.counter], r.side, r.length, r.deleted, r.text]
        end
        CBOR.dump({ "k" => Nodes::KIND_T, "r" => runs, "v" => TextLeaf::VERSION })
      end

      # The union of two text values, or nil when they disagree on a character or
      # the union would pass the 1 MiB node bound as a t node, so the merge's later
      # head decides the key on every replica alike.
      def self.union(a, b)
        merged = leaf_of(a).union(leaf_of(b))
        merged.encode
        to_wire(merged)
      rescue ArgumentError
        nil
      end

      def initialize(replica, pieces, leaf)
        unless replica.nil? || (replica.is_a?(String) && !replica.empty?)
          raise ArgumentError, "a replica is non-empty text, found #{replica.inspect}"
        end

        @replica = replica
        @pieces = pieces.freeze
        @length = pieces.sum(&:visible)
        @chars = pieces.sum(&:length)
        @next = (pieces.select { |p| p.replica == replica }.map { |p| p.counter + p.length - 1 }.max || -1) + 1
        @leaf = leaf
      end

      def to_s = @pieces.map(&:text).join

      # The canonical leaf of the characters, maximal runs in id order.
      def leaf = @leaf ||= TextLeaf.of(@pieces.map(&:run))

      def to_wire = PText.to_wire(leaf)

      def with_replica(other) = PText.new(other, @pieces, @leaf)

      # The text with characters inserted before a position (0 to length).
      def insert(pos, text)
        editable!
        raise IndexError, "position #{pos} of a text of #{@length}" if pos.negative? || pos > @length

        k = text.length
        return self if k.zero?
        raise ArgumentError, "a text holds at most #{MAX_CHARS} characters, live and deleted" if k > MAX_CHARS - @chars

        if pos.zero?
          # the document root: a right child while the text is empty, else a left child of the first character
          first = @pieces.empty? ? nil : @pieces[0].first
          return edited([fresh(k, text, first, !@pieces.empty?)] + @pieces)
        end
        i = visible_index(pos - 1)
        offset = pos - 1 - @pieces[0...i].sum(&:visible)
        p = @pieces[i]
        middle =
          if offset < p.length - 1
            # the character before the position has a right child, the next one of its piece
            rest = p.tail(offset + 1)
            [p.head(offset + 1), fresh(k, text, rest.first, true), rest]
          elsif !p.last_right && p.replica == @replica && p.counter + p.length == @next
            # this replica's last character, with no right child: the run goes on
            [Piece.new(p.replica, p.counter, p.length + k, false, p.text + text, p.parent, p.left, false)]
          elsif !p.last_right
            [p.with_right, fresh(k, text, p.last, false)]
          else
            [p, fresh(k, text, @pieces[i + 1].first, true)]
          end
        edited(@pieces[0...i] + middle + @pieces[(i + 1)..])
      end

      # The text with len live characters deleted from pos on.
      def delete(pos, len)
        editable!
        raise IndexError, "range [#{pos}, #{pos + len}) of a text of #{@length}" if pos.negative? || len.negative? || pos + len > @length
        return self if len.zero?

        out = []
        at = 0
        finish = pos + len
        @pieces.each do |p|
          from = [pos, at].max - at
          to = [finish, at + p.visible].min - at
          at += p.visible
          if p.deleted || from >= to
            out << p
            next
          end
          rest = p
          if from.positive?
            out << rest.head(from)
            rest = rest.tail(from)
          end
          if to - from < rest.length
            out << rest.head(to - from).as_deleted << rest.tail(to - from)
          else
            out << rest.as_deleted
          end
        end
        edited(out)
      end

      # The union of two texts: every character of either, deleted when either deleted it, edited by this replica.
      def merge(other) = PText.of(leaf.union(other.leaf), @replica)

      def ==(other) = other.is_a?(PText) && leaf == other.leaf
      alias eql? ==
      def hash = leaf.hash

      def inspect = "#<AgentSpaces::PDT::PText #{to_s.inspect} replica=#{@replica.inspect}>"

      private

      def editable!
        return unless @replica.nil?

        raise ArgumentError, "a text read from a ref edits under a replica: with_replica(PText.replica_of(agent id)), " \
                             "or edit it inside Ref#swap"
      end

      def fresh(k, text, parent, left) = Piece.new(@replica, @next, k, false, text, parent, left, false)

      def edited(pieces) = PText.new(@replica, pieces, nil)

      # The piece that holds a live position.
      def visible_index(position)
        at = 0
        @pieces.each_with_index do |p, i|
          return i if position < at + p.visible

          at += p.visible
        end
        raise IndexError, "position #{position} of a text of #{@length}"
      end
    end
  end
end
