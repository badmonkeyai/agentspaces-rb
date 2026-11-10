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
    # A refusal of PD-N-04, naming the rule and the CID when known.
    class NodeFormatError < ArgumentError
      attr_reader :rule, :cid

      def initialize(rule, cid = nil)
        @rule = rule
        @cid = cid
        super(cid ? "#{cid}: #{rule}" : rule)
      end
    end

    # A node a value needed could not be loaded (PD-V-06).
    class NodeUnavailable < RuntimeError
      attr_reader :cid, :sources

      def initialize(cid, sources = [], message = nil)
        @cid = cid
        @sources = sources
        super(message || "node #{cid} is not available (sources tried: #{sources.inspect})")
      end
    end

    # The node codec (srad/agentspaces-pdt.md 3.1 and 10.2; PD-N-01, PD-N-03,
    # PD-N-04): a structured node is a CBOR map with text keys in the RFC 8949
    # deterministic form (definite lengths, shortest integers, keys sorted by
    # length then bytes, the DAG-CBOR order), a link is tag 42 over 0x00 and
    # the binary CID, and an application key or value is an embedded CBOR item
    # spliced in unchanged and recovered by skipping one item. Both directions
    # refuse an embedded item outside the wire encoding (check_embedded). A
    # bare link item in a value slot names a spilled node (PD-N-05) and counts
    # as a link of the node.
    #
    # Schemas: m {d, n, e, c, cnt}, mc {e}, v {c | e}, vr {n, s, r, t},
    # b {h, c, z}, x {v}, sn {ct, ep, ln, nc}. PDT 2 phase 0
    # (srad/agentspaces-pdt2.md 3; P2-D-01, P2-R-01, P2-T-01, P2-V-01,
    # P2-B-02) adds the seven level-2 kinds: db {v, s, me, mt, bf, i, t},
    # dn {l, x, e, c}, rr {n, s, r, t}, rv {c, z}, t {r, v},
    # vg {r, b, i, t, p}, and bo {g, n, p, c}, whose typed readers live in
    # kinds.rb and text.rb. Kinds s, tm, and ec are reserved (P2-F-04).
    module Nodes
      MAX_NODE_BYTES = 1024 * 1024
      MAX_LINKS = 1024
      MAX_DEPTH = 64
      LINK_TAG = 42
      KIND_KEY = "k"
      KIND_M = "m"
      KIND_MC = "mc"
      KIND_V = "v"
      KIND_VR = "vr"
      KIND_B = "b"
      KIND_X = "x"
      # The sealed envelope of the sealed-nodes mode (PD-P-05, srad/agentspaces-pdt.md 10.2):
      # {k:"sn", ct: ciphertext and tag, ep: epoch, ln: [links of the plaintext], nc: nonce}.
      # This face walks it (its links are in the clear) and does not open it.
      KIND_SN = "sn"
      # PDT 2 phase 0 (srad/agentspaces-pdt2.md 3): the level-2 kinds, which
      # live only under a PRef.v 2 head (db, dn, rr, rv, t) or behind the
      # attributes pdt.ancestry (vg) and pdt.bao (bo) (6.10.3, rules 1 to 8).
      KIND_DB = "db"
      KIND_DN = "dn"
      KIND_RR = "rr"
      KIND_RV = "rv"
      KIND_T = "t"
      KIND_VG = "vg"
      KIND_BO = "bo"
      # PDT 2 phase 0 (P2-F-04): s (sorted map), tm (text marks), ec (erasure-coded stripe).
      RESERVED_KINDS = %w[s tm ec].freeze
      # An sn node may reach 1 MiB plus 48 KiB; every other kind keeps the 1 MiB bound.
      MAX_SEALED_NODE_BYTES = MAX_NODE_BYTES + 48 * 1024

      UINT = :uint
      LINK = :link
      LINK_OR_NULL = :link_or_null
      LINKS = :links
      EMBEDDED = :embedded
      EMBEDDEDS = :embeddeds
      UINTS = :uints
      BYTES = :bytes
      # PDT 2 phase 0 (P2-D-01, P2-T-01, P2-V-01): the strict field types of the level-2 kinds.
      TEXT = :text
      CID = :cid
      CIDS = :cids
      INDEX = :index
      DATOMS = :datoms
      RUNS = :runs
      # The keys of a db root's index map, in DAG-CBOR order (PDT 2 phase 0, P2-D-01).
      INDEX_KEYS = %w[aevt avet eavt].freeze
      # The largest integer a node holds: Java's NodeCodec reads every head into a long.
      MAX_INT = (1 << 63) - 1
      SCHEMAS = {
        KIND_M => { "d" => UINT, "n" => UINT, "e" => EMBEDDEDS, "c" => LINKS, "cnt" => UINT },
        KIND_MC => { "e" => EMBEDDEDS },
        KIND_V => { "c" => LINKS, "e" => EMBEDDEDS },
        KIND_VR => { "n" => UINT, "s" => UINT, "r" => LINK_OR_NULL, "t" => EMBEDDEDS },
        KIND_B => { "h" => UINT, "c" => LINKS, "z" => UINTS },
        KIND_X => { "v" => EMBEDDED },
        KIND_SN => { "ct" => BYTES, "ep" => UINT, "ln" => LINKS, "nc" => BYTES },
        KIND_DB => { "v" => UINT, "s" => EMBEDDED, "me" => UINT, "mt" => UINT, "bf" => UINT, "i" => INDEX,
                     "t" => LINK_OR_NULL },
        KIND_DN => { "l" => UINT, "x" => TEXT, "e" => DATOMS, "c" => LINKS },
        KIND_RR => { "n" => UINT, "s" => UINT, "r" => LINK_OR_NULL, "t" => EMBEDDEDS },
        KIND_RV => { "c" => LINKS, "z" => UINTS },
        KIND_T => { "r" => RUNS, "v" => UINT },
        KIND_VG => { "r" => CID, "b" => CIDS, "i" => TEXT, "t" => TEXT, "p" => LINKS },
        KIND_BO => { "g" => UINT, "n" => UINT, "p" => BYTES, "c" => LINKS }
      }.freeze

      LINK_BYTES = 1 + Cids::BINARY_LENGTH
      LINK_ITEM_LENGTH = 4 + LINK_BYTES
      LINK_PREFIX = [0xD8, LINK_TAG, 0x58, LINK_BYTES, 0x00].pack("C*").freeze

      # A link to another node.
      Link = Struct.new(:cid) do
        def structured? = Cids.codec_of(cid) == Cids::DAG_CBOR
      end

      # One application CBOR item, as CBOR.dump produced it.
      Embedded = Struct.new(:bytes)

      module_function

      def compare_key(key)
        encoded = key.to_s.b
        [encoded.bytesize, encoded]
      end

      # ---------------------------------------------------------------- links

      # The CBOR item a value slot carries for a spilled node.
      def link_item(cid) = LINK_PREFIX + Cids.binary(cid)

      def link_shaped?(item)
        item.bytesize == LINK_ITEM_LENGTH && item.byteslice(0, 5) == LINK_PREFIX
      end

      def link_cid(item) = Cids.from_binary(item.byteslice(5, Cids::BINARY_LENGTH))

      # The CID an embedded item names when it is exactly a link item, else nil.
      def spilled_link(item)
        return nil unless link_shaped?(item)

        link_cid(item)
      rescue ArgumentError => e
        raise NodeFormatError, "spilled value link refused: #{e.message}"
      end

      # ---------------------------------------------------------------- encode

      def header(major, value)
        m = major << 5
        if value < 24 then [m | value].pack("C")
        elsif value < 0x100 then [m | 24, value].pack("CC")
        elsif value < 0x10000 then [m | 25, value].pack("Cn")
        elsif value < 0x100000000 then [m | 26, value].pack("CN")
        else [m | 27, value].pack("CQ>")
        end
      end

      def schema_of(kind)
        raise NodeFormatError, "'#{KIND_KEY}' must be a text string" unless kind.is_a?(String)
        raise NodeFormatError, "kind '#{kind}' is reserved and has no schema in this release" if RESERVED_KINDS.include?(kind)

        SCHEMAS.fetch(kind) { raise NodeFormatError, "unknown kind '#{kind}'" }
      end

      def uint!(key, value)
        unless value.is_a?(Integer) && value >= 0 && value <= MAX_INT
          raise NodeFormatError, "'#{key}' must be an unsigned integer up to 2^63 - 1, found #{value.inspect}"
        end

        value
      end

      # PDT 2 phase 0 (P2-D-01): a signed integer within a Java long, major type 0 or 1.
      def sint(key, value)
        unless value.is_a?(Integer) && AgentSpaces::CBOR::LONG.cover?(value)
          raise NodeFormatError, "'#{key}' must be an integer within a Java long, found #{value.inspect}"
        end

        value.negative? ? header(1, -1 - value) : header(0, value)
      end

      # PDT 2 phase 0: CBOR text from a String that is text (any encoding but
      # BINARY, the byte-string encoding) and valid UTF-8.
      def text_item(key, value)
        unless value.is_a?(String) && value.encoding != Encoding::BINARY
          raise NodeFormatError, "'#{key}' must hold text, found #{value.inspect}"
        end

        utf8 = value.encode(Encoding::UTF_8)
        raise NodeFormatError, "'#{key}' text is not valid UTF-8" unless utf8.valid_encoding?

        header(3, utf8.bytesize) + utf8.b
      rescue EncodingError
        raise NodeFormatError, "'#{key}' text is not valid UTF-8"
      end

      # PDT 2 phase 0 (P2-V-01): a CID held as text, so a vg node names roots without linking them.
      def cid_item(key, value)
        raise NodeFormatError, "'#{key}' must hold a CID as text, found #{value.inspect}" unless Cids.cid?(value)

        text_item(key, value)
      end

      def list!(key, value)
        raise NodeFormatError, "'#{key}' must be a list" unless value.is_a?(Array)

        header(4, value.size)
      end

      # The canonical bytes of a node: k and the keys of its kind's schema.
      # Values: Integer, Link, Embedded (or raw item bytes), Array of those, nil for r.
      def encode(node)
        raise NodeFormatError, "node has no '#{KIND_KEY}' field" unless node.key?(KIND_KEY)

        kind = node[KIND_KEY]
        schema = schema_of(kind)
        node.each_key do |key|
          raise NodeFormatError, "key '#{key}' outside the schema of kind '#{kind}'" if key != KIND_KEY && !schema.key?(key)
        end
        keys = node.keys.sort_by { |k| compare_key(k) }
        out = String.new(encoding: Encoding::BINARY)
        out << header(5, keys.size)
        links = 0
        link = lambda do |key, value|
          raise NodeFormatError, "'#{key}' must hold a link, found #{value.class}" unless value.is_a?(Link)

          links += 1
          raise NodeFormatError, "node has more than #{MAX_LINKS} links" if links > MAX_LINKS

          out << header(6, LINK_TAG) << header(2, LINK_BYTES) << 0x00 << Cids.binary(value.cid)
        end
        embedded = lambda do |key, value, key_slot = false|
          bytes = value.is_a?(Embedded) ? value.bytes : value
          raise NodeFormatError, "'#{key}' must hold an embedded CBOR item, found #{value.class}" unless bytes.is_a?(String)

          bytes = bytes.b
          raise NodeFormatError, "'#{key}' embedded item has trailing bytes" if skip(bytes, 0) != bytes.bytesize

          check_embedded(key, bytes, key_slot)

          if link_shaped?(bytes)
            links += 1
            raise NodeFormatError, "node has more than #{MAX_LINKS} links" if links > MAX_LINKS
          end
          out << bytes
        end
        keys.each do |key|
          encoded = key.b
          out << header(3, encoded.bytesize) << encoded
          value = node[key]
          if key == KIND_KEY
            out << header(3, kind.b.bytesize) << kind.b
            next
          end
          case schema[key]
          when UINT then out << header(0, uint!(key, value))
          when LINK then link.call(key, value)
          when LINK_OR_NULL then value.nil? ? out << 0xF6 : link.call(key, value)
          when LINKS
            raise NodeFormatError, "'#{key}' must be a list" unless value.is_a?(Array)

            out << header(4, value.size)
            value.each { |item| link.call(key, item) }
          when EMBEDDED then embedded.call(key, value)
          when EMBEDDEDS
            raise NodeFormatError, "'#{key}' must be a list" unless value.is_a?(Array)

            out << header(4, value.size)
            keyed = keyed?(kind, key)
            value.each_with_index { |item, i| embedded.call(key, item, keyed && i.even?) }
          when UINTS
            raise NodeFormatError, "'#{key}' must be a list" unless value.is_a?(Array)

            out << header(4, value.size)
            value.each { |item| out << header(0, uint!(key, item)) }
          when BYTES
            raise NodeFormatError, "'#{key}' must be a byte string" unless value.is_a?(String)

            out << header(2, value.bytesize) << value.b
          when TEXT then out << text_item(key, value)
          when CID then out << cid_item(key, value)
          when CIDS
            out << list!(key, value)
            value.each { |item| out << cid_item(key, item) }
          when INDEX
            unless value.is_a?(Hash) && value.keys.sort == INDEX_KEYS
              raise NodeFormatError, "'#{key}' must map exactly aevt, avet and eavt to links, found #{value.inspect}"
            end

            out << header(5, INDEX_KEYS.size)
            INDEX_KEYS.each do |index|
              out << text_item(key, index)
              link.call(key, value[index])
            end
          when DATOMS
            out << list!(key, value)
            value.each do |item|
              raise NodeFormatError, "'#{key}' must hold datoms, found #{item.class}" unless item.is_a?(Datom)

              write_datom(out, key, item, link)
            end
          when RUNS
            out << list!(key, value)
            value.each do |item|
              raise NodeFormatError, "'#{key}' must hold text runs, found #{item.class}" unless item.is_a?(TextRun)

              write_run(out, key, item)
            end
          end
        end
        raise NodeFormatError, "node of #{out.bytesize} bytes exceeds #{bound_of(kind)} bytes" if out.bytesize > bound_of(kind)

        out
      end

      # A datom as the definite array [e, a, v, tx] (PDT 2 phase 0, P2-D-01;
      # srad/agentspaces-pdt2.md 3.1.1). A Link value is a spilled value and a
      # link of the node; a float is always float64.
      def write_datom(out, key, datom, link)
        out << header(4, 4) << sint(key, datom.e) << text_item(key, datom.a)
        v = datom.v
        case v
        when Integer then out << sint(key, v)
        when true then out << 0xF5
        when false then out << 0xF4
        when Float then out << 0xFB << [v].pack("G")
        when Nodes::Link then link.call(key, v)
        when Datom::Tagged
          out << header(4, 2) << text_item(key, v.tag)
          out << (v.inner.is_a?(Integer) ? sint(key, v.inner) : header(2, v.inner.bytesize) + v.inner)
        when String
          out << (v.encoding == Encoding::BINARY ? header(2, v.bytesize) + v : text_item(key, v))
        end
        out << sint(key, datom.tx)
      end

      # A run as the definite array [replica, counter, parent, side, length,
      # deleted, text] (PDT 2 phase 0, P2-T-01; srad/agentspaces-pdt2.md 3.9).
      def write_run(out, key, run)
        out << header(4, 7) << text_item(key, run.replica) << header(0, run.counter)
        if run.parent.nil?
          out << 0xF6
        else
          out << header(4, 2) << text_item(key, run.parent.replica) << header(0, run.parent.counter)
        end
        out << text_item(key, run.side) << header(0, run.length) << (run.deleted ? 0xF5 : 0xF4) << text_item(key, run.text)
      end

      # ---------------------------------------------------------------- decode

      # A cursor over node bytes.
      class In
        attr_accessor :pos
        attr_reader :links

        def initialize(bytes)
          @b = bytes
          @pos = 0
          @links = 0
        end

        def peek
          raise NodeFormatError, "truncated node" if @pos >= @b.bytesize

          @b.getbyte(@pos)
        end

        def u8
          v = peek
          @pos += 1
          v
        end

        def bytes(count)
          start = @pos
          advance(count)
          @b.byteslice(start, count)
        end

        def advance(count)
          raise NodeFormatError, "truncated node" if count.negative? || count > @b.bytesize - @pos

          @pos += count
        end

        def slice(start, length) = @b.byteslice(start, length)

        def argument(info)
          case info
          when 0..23 then info
          when 24 then u8
          when 25 then (u8 << 8) | u8
          when 26 then 4.times.reduce(0) { |v, _| (v << 8) | u8 }
          when 27 then 8.times.reduce(0) { |v, _| (v << 8) | u8 }
          when 28, 29, 30 then raise NodeFormatError, "reserved additional information #{info}"
          else raise NodeFormatError, "indefinite length in a structured field"
          end
        end

        def header(major, what)
          initial = u8
          raise NodeFormatError, "'#{what}' must be CBOR major type #{major}, found major type #{initial >> 5}" if initial >> 5 != major

          info = initial & 0x1F
          raise NodeFormatError, "'#{what}' uses an indefinite length" if info == 31

          value = argument(info)
          # Java's NodeCodec reads every head into a long and refuses one past it.
          raise NodeFormatError, "'#{what}' integer above 2^63 - 1" if value > MAX_INT

          shortest = case info
                     when 24 then value >= 24
                     when 25 then value >= 0x100
                     when 26 then value >= 0x10000
                     when 27 then value >= 0x100000000
                     else true
                     end
          raise NodeFormatError, "'#{what}' integer not in shortest form" unless shortest

          value
        end

        def text(what)
          length = header(3, what)
          raise NodeFormatError, "truncated node" if length > @b.bytesize - @pos

          s = @b.byteslice(@pos, length).force_encoding(Encoding::UTF_8)
          raise NodeFormatError, "'#{what}' is not UTF-8" unless s.valid_encoding?

          @pos += length
          s
        end

        def link(what)
          @links += 1
          raise NodeFormatError, "node has more than #{MAX_LINKS} links" if @links > MAX_LINKS

          tag = header(6, what)
          raise NodeFormatError, "'#{what}' carries tag #{tag}; a link is tag #{LINK_TAG}" if tag != LINK_TAG

          length = header(2, what)
          raise NodeFormatError, "'#{what}' link of #{length} bytes; a link holds 0x00 and a 36-byte CID" if length != LINK_BYTES
          raise NodeFormatError, "'#{what}' link does not start with the 0x00 identity byte" if u8 != 0x00
          raise NodeFormatError, "truncated node" if Cids::BINARY_LENGTH > @b.bytesize - @pos

          raw = @b.byteslice(@pos, Cids::BINARY_LENGTH)
          @pos += Cids::BINARY_LENGTH
          begin
            Link.new(Cids.from_binary(raw))
          rescue ArgumentError => e
            raise NodeFormatError, "'#{what}' link refused: #{e.message}"
          end
        end

        # PDT 2 phase 0 (P2-D-01): a signed integer under its shortest head, within a Java long.
        def sint(what)
          return -1 - header(1, what) if peek >> 5 == 1

          header(0, what)
        end

        def bool(what)
          initial = u8
          return initial == 0xF5 if [0xF4, 0xF5].include?(initial)

          raise NodeFormatError, format("'%s' must be a boolean, found initial byte 0x%02x", what, initial)
        end

        # PDT 2 phase 0 (P2-V-01): a CID held as text.
        def cid_text(what)
          value = text(what)
          raise NodeFormatError, "'#{what}' must hold a CID as text, found '#{value}'" unless Cids.cid?(value)

          value
        end

        # One datom [e, a, v, tx] under the value grammar of 3.1.1 (PDT 2 phase 0, P2-D-01).
        def datom(what)
          raise NodeFormatError, "'#{what}' datom must hold four items" if header(4, what) != 4

          e = sint(what)
          a = text(what)
          v = datom_value(what)
          tx = sint(what)
          Datom.new(e, a, v, tx)
        rescue ArgumentError => refused
          raise if refused.is_a?(NodeFormatError)

          raise NodeFormatError, "'#{what}' datom refused: #{refused.message}"
        end

        def datom_value(what)
          initial = peek
          case initial >> 5
          when 0, 1 then sint(what)
          when 2 then bytes(header(2, what))
          when 3 then text(what)
          when 6 then link(what)
          when 4 then tagged(what)
          when 7 then simple_value(what, initial)
          else
            raise NodeFormatError, "'#{what}' datom value of major type #{initial >> 5}; the grammar holds integers, " \
                                   "bytes, text, links, tagged pairs, booleans and float64"
          end
        end

        def tagged(what)
          raise NodeFormatError, "'#{what}' tagged datom value must hold two items" if header(4, what) != 2

          tag = text(what)
          inner =
            case tag
            when Datom::Tagged::INSTANT
              raise NodeFormatError, "'#{what}' instant value must hold an integer" unless [0, 1].include?(peek >> 5)

              sint(what)
            when Datom::Tagged::UUID, Datom::Tagged::BIGINT then bytes(header(2, what))
            else raise NodeFormatError, "'#{what}' unknown value tag '#{tag}'"
            end
          Datom::Tagged.new(tag, inner)
        end

        def simple_value(what, initial)
          case initial
          when 0xF4, 0xF5 then bool(what)
          when 0xFB
            advance(1)
            value = bytes(8).unpack1("G")
            raise NodeFormatError, "'#{what}' float value is not finite" unless value.finite?

            value
          when 0xFA then raise NodeFormatError, "'#{what}' float value is float32; a datom float is float64"
          when 0xF9 then raise NodeFormatError, "'#{what}' float value is a half float; a datom float is float64"
          when 0xF6 then raise NodeFormatError, "'#{what}' datom value is null"
          else raise NodeFormatError, format("'%s' datom value is simple value 0x%02x", what, initial)
          end
        end

        # One run [replica, counter, parent, side, length, deleted, text] (PDT 2 phase 0, P2-T-01).
        def run(what)
          raise NodeFormatError, "'#{what}' run must hold seven items" if header(4, what) != 7

          replica = text(what)
          counter = header(0, what)
          parent = nil
          if peek == 0xF6
            advance(1)
          else
            raise NodeFormatError, "'#{what}' run parent must be null or [replica, counter]" if header(4, what) != 2

            parent = CharId.new(text(what), header(0, what))
          end
          TextRun.new(replica, counter, parent, text(what), header(0, what), bool(what), text(what))
        rescue ArgumentError => refused
          raise if refused.is_a?(NodeFormatError)

          raise NodeFormatError, "'#{what}' run refused: #{refused.message}"
        end

        def embedded(what, key_slot)
          start = @pos
          Nodes.skip_item(self, 0)
          item = @b.byteslice(start, @pos - start)
          Nodes.check_embedded(what, item, key_slot)
          if Nodes.link_shaped?(item)
            @links += 1
            raise NodeFormatError, "node has more than #{MAX_LINKS} links" if @links > MAX_LINKS
          end
          Embedded.new(item)
        end
      end

      def skip_item(inp, depth)
        raise NodeFormatError, "CBOR nesting deeper than #{MAX_DEPTH} levels" if depth > MAX_DEPTH

        initial = inp.u8
        major = initial >> 5
        info = initial & 0x1F
        if major == 7
          case info
          when 24 then inp.advance(1)
          when 25 then inp.advance(2)
          when 26 then inp.advance(4)
          when 27 then inp.advance(8)
          when 28, 29, 30 then raise NodeFormatError, "reserved additional information #{info}"
          when 31 then raise NodeFormatError, "unexpected break code"
          end
          return
        end
        if info == 31
          case major
          when 2, 3
            while inp.peek != 0xFF
              chunk = inp.u8
              raise NodeFormatError, "malformed indefinite string chunk" if chunk >> 5 != major || (chunk & 0x1F) == 31

              inp.advance(inp.argument(chunk & 0x1F))
            end
            inp.advance(1)
          when 4
            skip_item(inp, depth + 1) while inp.peek != 0xFF
            inp.advance(1)
          when 5
            while inp.peek != 0xFF
              skip_item(inp, depth + 1)
              skip_item(inp, depth + 1)
            end
            inp.advance(1)
          else
            raise NodeFormatError, "indefinite length on major type #{major}"
          end
          return
        end
        argument = inp.argument(info)
        case major
        when 0, 1 then nil
        when 2, 3 then inp.advance(argument)
        when 4 then argument.times { skip_item(inp, depth + 1) }
        when 5
          argument.times do
            skip_item(inp, depth + 1)
            skip_item(inp, depth + 1)
          end
        when 6
          # HLC round six, 2026-11-08 (S2): a tag is no container, so its
          # content sits at the tag's own depth, as Java's NodeCodec counts it
          # (Jackson counts a decimal's tag 4 array as the level); a chain of
          # tags reads in a loop.
          while inp.peek >> 5 == 6
            tag = inp.u8
            raise NodeFormatError, "indefinite length on major type 6" if (tag & 0x1F) == 31

            inp.argument(tag & 0x1F)
          end
          skip_item(inp, depth)
        end
      end

      # Skips one field value of a node. HLC round six, 2026-11-08 (S2, Java
      # change JD-4): each element of a definite list counts its nesting from
      # zero, as Java's NodeCodec.skipField counts it, since the item rules
      # judge an embedded item by its own bytes; the node's list adds no level.
      def skip_field(inp)
        initial = inp.peek
        return skip_item(inp, 0) if initial >> 5 != 4 || (initial & 0x1F) == 31

        inp.advance(1)
        inp.argument(initial & 0x1F).times { skip_item(inp, 0) }
      end

      # Checks an embedded item against the wire encoding (HLC round six,
      # 2026-11-08, F2, definition 2.4, Java change JD-4): every application
      # key and value is a document under rules S1 to S12, so the big-number
      # tags 2, 3, and 4 stand in it and no other tag does. A bare link item in
      # a value slot, a spilled value (PD-N-05), is the one exception; a key
      # never spills, so a link item in a key slot is refused.
      def check_embedded(what, item, key_slot)
        return if !key_slot && link_shaped?(item)

        CBOR.load(item)
      rescue CBOR::Error => e
        raise NodeFormatError, "'#{what}' #{key_slot ? 'key item' : 'embedded item'} breaks the wire encoding: #{e.message}"
      end

      # Whether a field of a kind is an entry list whose even slots hold keys.
      def keyed?(kind, key) = [KIND_M, KIND_MC].include?(kind) && key == "e"

      # The offset just past one CBOR item of any form (the embedded-item rule).
      def skip(data, offset)
        inp = In.new(data.b)
        inp.pos = offset
        skip_item(inp, 0)
        inp.pos
      end

      # {k: "sn", ...} with five keys: the only node that may pass the 1 MiB bound.
      SEALED_PREFIX = "\xA5\x61\x6B\x62\x73\x6E".b.freeze

      def scan(data)
        if data.bytesize > MAX_NODE_BYTES && !data.b.start_with?(SEALED_PREFIX)
          raise NodeFormatError, "node of #{data.bytesize} bytes exceeds #{MAX_NODE_BYTES} bytes (1 MiB)"
        end
        if data.bytesize > MAX_SEALED_NODE_BYTES
          raise NodeFormatError, "node of #{data.bytesize} bytes exceeds #{MAX_SEALED_NODE_BYTES} bytes (1 MiB + 48 KiB)"
        end

        inp = In.new(data)
        entries = inp.header(5, "node")
        kind = nil
        offsets = {}
        previous = nil
        entries.times do
          key = inp.text("key")
          unless previous.nil?
            raise NodeFormatError, "duplicate key '#{key}'" if compare_key(previous) == compare_key(key)
            raise NodeFormatError, "keys out of canonical order: '#{key}' after '#{previous}'" if (compare_key(previous) <=> compare_key(key)).positive?
          end
          previous = key
          offsets[key] = inp.pos
          if key == KIND_KEY
            kind = inp.text(KIND_KEY)
          else
            skip_field(inp)
          end
        end
        raise NodeFormatError, "trailing bytes after the node map" if inp.pos != data.bytesize
        raise NodeFormatError, "node has no '#{KIND_KEY}' field" if kind.nil?
        raise NodeFormatError, "node of #{data.bytesize} bytes exceeds #{MAX_NODE_BYTES} bytes (1 MiB)" if data.bytesize > bound_of(kind)

        [kind, offsets]
      end

      def read_field(inp, key, field, keyed)
        case field
        when UINT then inp.header(0, key)
        when LINK then inp.link(key)
        when LINK_OR_NULL
          if inp.peek == 0xF6
            inp.advance(1)
            nil
          else
            inp.link(key)
          end
        when LINKS then Array.new(inp.header(4, key)) { inp.link(key) }
        when EMBEDDED then inp.embedded(key, false)
        when EMBEDDEDS then Array.new(inp.header(4, key)) { |i| inp.embedded(key, keyed && i.even?) }
        when UINTS then Array.new(inp.header(4, key)) { inp.header(0, key) }
        when BYTES then inp.bytes(inp.header(2, key))
        when TEXT then inp.text(key)
        when CID then inp.cid_text(key)
        when CIDS then Array.new(inp.header(4, key)) { inp.cid_text(key) }
        when INDEX then read_index(inp, key)
        when DATOMS then Array.new(inp.header(4, key)) { inp.datom(key) }
        when RUNS then Array.new(inp.header(4, key)) { inp.run(key) }
        end
      end

      # The db root's index map (PDT 2 phase 0, P2-D-01): exactly aevt, avet, eavt, in that order, each a link.
      def read_index(inp, key)
        refused = "'#{key}' must map exactly aevt, avet and eavt to links, in that order"
        raise NodeFormatError, refused if inp.header(5, key) != INDEX_KEYS.size

        INDEX_KEYS.to_h do |index|
          raise NodeFormatError, refused if inp.text(key) != index

          [index, inp.link(key)]
        end
      end

      # The byte bound of a kind: the sealed bound for an sn envelope, 1 MiB otherwise.
      def bound_of(kind)
        kind == KIND_SN ? MAX_SEALED_NODE_BYTES : MAX_NODE_BYTES
      end

      # A node in canonical key order: Integers, Links, Arrays, and Embedded items.
      def decode(data, cid = nil)
        data = data.b
        kind, offsets = scan(data)
        schema = schema_of(kind)
        inp = In.new(data)
        node = {}
        offsets.each do |key, offset|
          if key == KIND_KEY
            node[key] = kind
            next
          end
          field = schema[key]
          raise NodeFormatError, "key '#{key}' outside the schema of kind '#{kind}'" if field.nil?

          inp.pos = offset
          node[key] = read_field(inp, key, field, keyed?(kind, key))
        end
        node
      rescue NodeFormatError => e
        raise if e.cid || cid.nil?

        raise NodeFormatError.new(e.rule, cid)
      end

      def kind_of(data) = scan(data.b)[0]

      # The linked CIDs of a node in field order, spilled-value links included; none for a raw chunk.
      def links(data, cid = nil)
        return [] if cid && Cids.codec_of(cid) == Cids::RAW

        node = decode(data, cid)
        kind = node[KIND_KEY]
        out = []
        node.each do |key, value|
          next if key == KIND_KEY

          case SCHEMAS[kind][key]
          when EMBEDDED, EMBEDDEDS
            items = value.is_a?(Array) ? value : [value]
            keyed = keyed?(kind, key)
            items.each_with_index do |item, i|
              next if keyed && i.even?

              spilled = spilled_link(item.bytes)
              out << spilled unless spilled.nil?
            end
          when LINK, LINK_OR_NULL then out << value.cid unless value.nil?
          when LINKS then value.each { |link| out << link.cid }
          # PDT 2 phase 0 (P2-D-01): the index roots, and a spilled datom value as in an embedded slot
          when INDEX then value.each_value { |link| out << link.cid }
          when DATOMS then value.each { |d| out << d.v.cid if d.v.is_a?(Link) }
          end
        end
        out
      end
    end
  end
end
