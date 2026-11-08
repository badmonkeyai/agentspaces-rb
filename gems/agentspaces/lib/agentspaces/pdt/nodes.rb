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
    # spliced in unchanged and recovered by skipping one item. A bare link item
    # in a value slot names a spilled node (PD-N-05) and counts as a link of
    # the node.
    #
    # Schemas: m {d, n, e, c, cnt}, mc {e}, v {c | e}, vr {n, s, r, t},
    # b {h, c, z}, x {v}. Kinds s and rr are reserved.
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
      RESERVED_KINDS = %w[s rr].freeze
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
      SCHEMAS = {
        KIND_M => { "d" => UINT, "n" => UINT, "e" => EMBEDDEDS, "c" => LINKS, "cnt" => UINT },
        KIND_MC => { "e" => EMBEDDEDS },
        KIND_V => { "c" => LINKS, "e" => EMBEDDEDS },
        KIND_VR => { "n" => UINT, "s" => UINT, "r" => LINK_OR_NULL, "t" => EMBEDDEDS },
        KIND_B => { "h" => UINT, "c" => LINKS, "z" => UINTS },
        KIND_X => { "v" => EMBEDDED },
        KIND_SN => { "ct" => BYTES, "ep" => UINT, "ln" => LINKS, "nc" => BYTES }
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
        raise NodeFormatError, "'#{key}' must be an unsigned integer, found #{value.inspect}" unless value.is_a?(Integer) && value >= 0

        value
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
        embedded = lambda do |key, value|
          bytes = value.is_a?(Embedded) ? value.bytes : value
          raise NodeFormatError, "'#{key}' must hold an embedded CBOR item, found #{value.class}" unless bytes.is_a?(String)

          bytes = bytes.b
          raise NodeFormatError, "'#{key}' embedded item has trailing bytes" if skip(bytes, 0) != bytes.bytesize

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
            value.each { |item| embedded.call(key, item) }
          when UINTS
            raise NodeFormatError, "'#{key}' must be a list" unless value.is_a?(Array)

            out << header(4, value.size)
            value.each { |item| out << header(0, uint!(key, item)) }
          when BYTES
            raise NodeFormatError, "'#{key}' must be a byte string" unless value.is_a?(String)

            out << header(2, value.bytesize) << value.b
          end
        end
        raise NodeFormatError, "node of #{out.bytesize} bytes exceeds #{bound_of(kind)} bytes" if out.bytesize > bound_of(kind)

        out
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

        def embedded
          start = @pos
          Nodes.skip_item(self, 0)
          item = @b.byteslice(start, @pos - start)
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
        when 6 then skip_item(inp, depth + 1)
        end
      end

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
            skip_item(inp, 0)
          end
        end
        raise NodeFormatError, "trailing bytes after the node map" if inp.pos != data.bytesize
        raise NodeFormatError, "node has no '#{KIND_KEY}' field" if kind.nil?
        raise NodeFormatError, "node of #{data.bytesize} bytes exceeds #{MAX_NODE_BYTES} bytes (1 MiB)" if data.bytesize > bound_of(kind)

        [kind, offsets]
      end

      def read_field(inp, key, field)
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
        when EMBEDDED then inp.embedded
        when EMBEDDEDS then Array.new(inp.header(4, key)) { inp.embedded }
        when UINTS then Array.new(inp.header(4, key)) { inp.header(0, key) }
        when BYTES then inp.bytes(inp.header(2, key))
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
          node[key] = read_field(inp, key, field)
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
            keyed = [KIND_M, KIND_MC].include?(kind) && key == "e"
            items.each_with_index do |item, i|
              next if keyed && i.even?

              spilled = spilled_link(item.bytes)
              out << spilled unless spilled.nil?
            end
          when LINK, LINK_OR_NULL then out << value.cid unless value.nil?
          when LINKS then value.each { |link| out << link.cid }
          end
        end
        out
      end
    end
  end
end
