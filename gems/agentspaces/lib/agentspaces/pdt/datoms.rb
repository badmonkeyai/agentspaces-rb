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
    Datom = Struct.new(:e, :a, :v, :tx)

    # One datom of a dn node (PDT 2 phase 0, P2-D-01; srad/agentspaces-pdt2.md
    # 3.1.1): on the wire the definite array [e, a, v, tx], the entity and the
    # transaction as integers within a Java long (a negative transaction marks
    # a retraction, so tx is never 0), the attribute as the keyword's print
    # form (":ns/name"). Nodes reads and writes the array; this value holds one
    # decoded datom and refuses a value outside the grammar: an Integer (an
    # integer, or a ref under a :db.type/ref attribute), text (a String in any
    # encoding but BINARY, a keyword as its print form), true or false, bytes
    # (a BINARY String), a finite Float (always float64), a Nodes::Link (a
    # value spilled out of line, PD-N-05), or a Tagged pair.
    class Datom
      def initialize(e, a, v, tx)
        super(e, Kinds.own(a), Kinds.own(v), tx)
        freeze
        raise ArgumentError, "a datom's entity is an integer within a Java long" unless e.is_a?(Integer) && AgentSpaces::CBOR::LONG.cover?(e)
        raise ArgumentError, "a datom's attribute is text" unless a.is_a?(String) && a.encoding != Encoding::BINARY
        raise ArgumentError, "a datom's tx is an integer within a Java long" unless tx.is_a?(Integer) && AgentSpaces::CBOR::LONG.cover?(tx)
        raise ArgumentError, "a datom's tx is non-zero: its sign marks a retraction" if tx.zero?
        return if value?(v)

        raise ArgumentError, "a datom value is an integer within a Java long, text, a boolean, bytes, a finite " \
                             "float64, a link, or a tagged pair, found #{v.inspect}"
      end

      private

      def value?(v)
        case v
        when Integer then AgentSpaces::CBOR::LONG.cover?(v)
        when Float then v.finite?
        when true, false, String, Nodes::Link, Tagged then true
        else false
        end
      end

      Tagged = Struct.new(:tag, :inner)

      # A tagged datom value, [tag, inner] on the wire (3.1.1): UUID over the
      # 16 bytes of a UUID, INSTANT over epoch milliseconds, BIGINT over the
      # minimal big-endian two's complement bytes of a big integer, as Java's
      # BigInteger.toByteArray writes them.
      class Tagged
        UUID = "u"
        INSTANT = "i"
        BIGINT = "n"
        RULES = { UUID => "16 bytes", INSTANT => "an integer of epoch milliseconds",
                  BIGINT => "its minimal two's complement bytes" }.freeze

        def initialize(tag, inner)
          super(tag, Kinds.own(inner))
          freeze
          raise ArgumentError, "unknown value tag '#{tag}'" unless RULES.key?(tag)
          raise ArgumentError, "a #{tag} value holds #{RULES[tag]}" unless inner?(tag, inner)
        end

        private

        def inner?(tag, inner)
          return inner.is_a?(Integer) && AgentSpaces::CBOR::LONG.cover?(inner) if tag == INSTANT
          return false unless inner.is_a?(String) && inner.encoding == Encoding::BINARY

          tag == UUID ? inner.bytesize == 16 : minimal?(inner)
        end

        # Non-empty, and no leading byte that only repeats the next byte's sign.
        def minimal?(bytes)
          return false if bytes.empty?
          return true if bytes.bytesize == 1

          first = bytes.getbyte(0)
          second = bytes.getbyte(1)
          !(first.zero? && second < 0x80) && !(first == 0xFF && second >= 0x80)
        end
      end
    end
  end
end
