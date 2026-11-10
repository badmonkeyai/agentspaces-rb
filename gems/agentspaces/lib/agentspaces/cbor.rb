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

require "bigdecimal"

module AgentSpaces
  # CBOR (RFC 8949) in the AgentSpaces wire encoding (HLC round six,
  # 2026-11-08, F3): the image of Java's CborCodec encoder, which every
  # implementation writes and reads byte for byte. Maps are indefinite-length
  # (0xBF ... 0xFF) with unique text keys in insertion order (a Hash stands
  # for a Java record, whose components keep their declared order), arrays
  # and byte strings are definite, every head is the shortest, text is
  # definite up to TEXT_CHUNK UTF-16 code units and in Jackson's chunks past
  # it, an Integer inside a Java long is a plain integer and any other one a
  # tag 2 or 3 bignum, a BigDecimal is a normalized tag 4 decimal, a Float is
  # a float64 (0xFB) and a CBOR::Float32 a float32 (0xFA), each NaN is Java's
  # one NaN, and the simple values are false, true, and null. A String in
  # Encoding::BINARY is a byte string; any other String is text.
  #
  # CBOR.load decodes exactly one such document and refuses anything else:
  # an item the encoding does not define, nesting past MAX_DEPTH levels, and
  # any document whose re-encoding differs from the bytes received, so a
  # signature over the received bytes and one over the decoded value cover
  # the same bytes in every implementation.
  module CBOR
    # Deepest container nesting accepted (ASF-018). HLC round six, 2026-11-08
    # (S2): the two-element array of a tag 4 decimal counts as a level, as
    # Jackson counts it, and an empty innermost container counts like any other.
    MAX_DEPTH = 64
    BREAK = 0xFF
    # The values a Java long holds; an Integer outside them travels as a bignum.
    LONG = (-(1 << 63)..((1 << 63) - 1))
    # HLC round six, 2026-11-08 (S9, reference rule): the longest bignum
    # magnitude in bytes, alone or as a decimal's mantissa. Java's reader
    # refuses a longer one (Jackson's StreamReadConstraints maxNumberLength),
    # and the bound keeps a decimal's digit conversion short.
    MAX_BIGNUM_BYTES = 1000
    # HLC round six, 2026-11-08 (S9): the exponents of a tag 4 decimal.
    DECIMAL_EXPONENTS = (-((1 << 31) - 1)..((1 << 31) - 1))
    # HLC round six, 2026-11-08 (S6): the most UTF-16 code units Jackson
    # writes as one definite text. A longer string goes out as an
    # indefinite-length text of chunks this long, a chunk one unit shorter
    # where the boundary would split a surrogate pair.
    TEXT_CHUNK = 3996
    # HLC round six, 2026-11-08 (S10): the one NaN of each width, the bits of
    # Java's Double.NaN and Float.NaN.
    NAN64 = ["7FF8000000000000"].pack("H*").freeze
    NAN32 = ["7FC00000"].pack("H*").freeze

    # A CBOR item that does not decode, or a value that does not encode.
    class Error < ArgumentError; end

    # HLC round six, 2026-11-08 (F2): a float32 application value, as Java
    # writes a float. Ruby has one Float class, so the width travels in this
    # wrapper; it holds the value its four bytes hold and re-encodes as 0xFA.
    class Float32
      attr_reader :value

      def initialize(value)
        @value = Float(value).nan? ? Float::NAN : [Float(value)].pack("g").unpack1("g")
      end

      def to_f = @value

      def ==(other) = other.is_a?(Float32) && CBOR.dump(self) == CBOR.dump(other)
      alias eql? ==

      def hash = [Float32, CBOR.dump(self)].hash

      def inspect = "#<AgentSpaces::CBOR::Float32 #{@value}>"
    end

    module_function

    # Encodes a Ruby value in the wire encoding; raises CBOR::Error for a
    # value the encoding cannot hold.
    def dump(value)
      out = String.new(capacity: 64, encoding: Encoding::BINARY)
      encode(value, out)
      out
    end

    # Decodes exactly one CBOR document under the wire encoding; raises
    # CBOR::Error for anything else (HLC round six, 2026-11-08, F3).
    def load(data)
      raise Error, "a CBOR document is a byte string, not #{data.class}" unless data.is_a?(String)

      data = data.b
      value, offset = decode(data, 0, 0)
      raise Error, "trailing bytes after CBOR item at offset #{offset}" if offset != data.bytesize
      raise Error, "the document is not in the wire encoding: its re-encoding differs" unless dump(value) == data

      value
    end

    # A copy of a map-valued field with its entries in canonical order
    # (shorter UTF-8 key first, then bytewise; RFC 8949 4.2.1), the order the
    # Java codec writes every map in as of wire v3. Apply it to maps a
    # signature covers (tags, costHints, spaceBindings, resourceHints,
    # parameters, access, a DIGEST's digests), never to a Hash that stands
    # for a record.
    def canonical_map(value)
      value.to_h.sort_by { |k, _| key = k.to_s.b; [key.bytesize, key] }.to_h
    end

    def head(major, value, out)
      if value < 24
        out << ((major << 5) | value)
      elsif value < 0x100
        out << ((major << 5) | 24) << value
      elsif value < 0x10000
        out << ((major << 5) | 25) << [value].pack("n")
      elsif value < 0x100000000
        out << ((major << 5) | 26) << [value].pack("N")
      else
        out << ((major << 5) | 27) << [value].pack("Q>")
      end
    end
    private_class_method :head

    def encode(value, out)
      case value
      when nil then out << 0xF6
      when true then out << 0xF5
      when false then out << 0xF4
      when Integer then integer(value, out)
      when Float then out << 0xFB << (value.nan? ? NAN64 : [value].pack("G"))
      when Float32 then out << 0xFA << (value.value.nan? ? NAN32 : [value.value].pack("g"))
      when BigDecimal then decimal(value, out)
      when String
        if value.encoding == Encoding::BINARY
          head(2, value.bytesize, out)
          out << value
        else
          text(value, out)
        end
      when Symbol then text(value.name, out)
      when Array
        head(4, value.size, out)
        value.each { |item| encode(item, out) }
      when Hash then map(value, out)
      else
        raise Error, "cannot encode #{value.class}"
      end
    end
    private_class_method :encode

    # HLC round six, 2026-11-08 (S4, S9): a plain integer inside a Java long,
    # else tag 2 (positive) or 3 (negative) over the magnitude as Java's
    # BigInteger.toByteArray() writes it, big-endian and minimal two's
    # complement, so a leading zero byte appears only before a byte of 0x80
    # or more. Jackson reads tag 3 over m as -m, and Java is the reference.
    def integer(value, out)
      if LONG.cover?(value)
        value >= 0 ? head(0, value, out) : head(1, -1 - value, out)
        return
      end
      digits = value.abs.to_s(16)
      digits = "0#{digits}" if digits.size.odd?
      magnitude = [digits].pack("H*")
      magnitude = "\x00".b + magnitude if magnitude.getbyte(0) >= 0x80
      raise Error, "a bignum magnitude passes #{MAX_BIGNUM_BYTES} bytes" if magnitude.bytesize > MAX_BIGNUM_BYTES

      out << (value.positive? ? 0xC2 : 0xC3)
      head(2, magnitude.bytesize, out)
      out << magnitude
    end
    private_class_method :integer

    # HLC round six, 2026-11-08 (S9, F2): a BigDecimal as a normalized tag 4
    # decimal, [exponent, mantissa] with no trailing decimal zero in the
    # mantissa and zero as [0, 0], the exponent within DECIMAL_EXPONENTS.
    def decimal(value, out)
      raise Error, "a decimal is finite: #{value}" unless value.finite?

      if value.zero?
        out << 0xC4 << 0x82 << 0x00 << 0x00
        return
      end
      # BigDecimal#split never ends its digits in a zero, so the mantissa it
      # gives is already the normalized one.
      sign, digits, _, exponent = value.split
      # JRuby holds the exponent split gives (one past the leading digit's) in
      # a Java int, so one past 2^31 - 1 wraps negative, where a magnitude of
      # 1 or more always has a positive one.
      exponent += 1 << 32 if exponent < 1 && value.abs >= 1
      exponent -= digits.size
      raise Error, "a decimal exponent lies outside a Java int scale: #{exponent}"         unless DECIMAL_EXPONENTS.cover?(exponent)

      out << 0xC4 << 0x82
      integer(exponent, out)
      integer(sign * Integer(digits, 10), out)
    end
    private_class_method :decimal

    # HLC round six, 2026-11-08 (S8): a map's keys are unique text. A Symbol
    # key writes as its name, so a Hash whose Symbol and String keys name the
    # same text cannot encode.
    def map(value, out)
      out << 0xBF
      names = value.keys.map do |key|
        case key
        when Symbol then key.name
        when String
          raise Error, "a map key is text, not a byte string" if key.encoding == Encoding::BINARY

          key
        else
          raise Error, "a map key is text, not #{key.class}"
        end
      end
      raise Error, "two map keys name the same text" if value.keys.any?(Symbol) && names.uniq.size != names.size

      value.each_value.with_index do |item, index|
        text(names[index], out)
        encode(item, out)
      end
      out << BREAK
    end
    private_class_method :map

    # A UTF-8 text as Jackson's CBORGenerator writes it: definite up to
    # TEXT_CHUNK UTF-16 code units, else indefinite in chunks of at most
    # TEXT_CHUNK units that never split a character (HLC round six,
    # 2026-11-08 (S6)).
    def text(value, out)
      value = value.encode(Encoding::UTF_8) unless value.encoding == Encoding::UTF_8
      raise Error, "cannot encode a text that is not valid UTF-8" unless value.valid_encoding?

      if value.bytesize <= TEXT_CHUNK || utf16_units(value) <= TEXT_CHUNK
        head(3, value.bytesize, out)
        out << value.b
        return
      end
      out << 0x7F
      chunk = String.new(encoding: Encoding::BINARY)
      units = 0
      value.each_char do |char|
        width = char.ord > 0xFFFF ? 2 : 1
        if units + width > TEXT_CHUNK
          head(3, chunk.bytesize, out)
          out << chunk
          chunk = String.new(encoding: Encoding::BINARY)
          units = 0
        end
        chunk << char.b
        units += width
      end
      head(3, chunk.bytesize, out)
      out << chunk << BREAK
    end
    private_class_method :text

    # The length of a UTF-8 text in UTF-16 code units, as Java counts it.
    # The length of a text in UTF-16 code units, the length Jackson chunks
    # text by and a stamp is bounded by (HLC round seven, 2026-11-08).
    def utf16_units(value) = value.length + value.each_char.count { |char| char.ord > 0xFFFF }

    def need(data, offset, count)
      raise Error, "truncated CBOR item" if offset + count > data.bytesize
    end
    private_class_method :need

    # One item at offset with depth containers around it. The decoder refuses
    # the items the encoding never writes; load's re-encoding comparison
    # refuses every other form the encoding does not write (a longer head, a
    # small or padded bignum, an unnormalized decimal, another NaN, other text
    # chunks).
    def decode(data, offset, depth)
      need(data, offset, 1)
      initial = data.getbyte(offset)
      major = initial >> 5
      info = initial & 0x1F
      offset += 1

      if major == 7
        case info
        when 20 then return [false, offset]
        when 21 then return [true, offset]
        when 22 then return [nil, offset]
        when 26
          need(data, offset, 4)
          return [Float32.new(data.byteslice(offset, 4).unpack1("g")), offset + 4]
        when 27
          need(data, offset, 8)
          return [data.byteslice(offset, 8).unpack1("G"), offset + 8]
        else
          # HLC round six, 2026-11-08 (S10, S11, S12): undefined, every
          # unassigned simple value, a half float, and a lone break.
          raise Error, format("CBOR item 0x%02x is not in the wire encoding", initial)
        end
      end

      raise Error, format("unsupported CBOR head 0x%02x", initial) if info.between?(28, 30)

      if info == 31
        # HLC round six, 2026-11-08 (S5, S7, S8): only text and maps have an
        # indefinite length on this wire.
        return indefinite_text(data, offset) if major == 3
        return indefinite_map(data, offset, depth) if major == 5

        raise Error, format("CBOR major type %d has no indefinite length on this wire", major)
      end

      length, offset = argument(data, offset, info)
      case major
      when 0, 1
        # HLC round six, 2026-11-08 (S4): an argument past a Java long is a bignum's.
        raise Error, "a plain CBOR integer lies outside a Java long" if length > LONG.max

        [major.zero? ? length : -1 - length, offset]
      when 2
        need(data, offset, length)
        [data.byteslice(offset, length), offset + length]
      when 3
        need(data, offset, length)
        [utf8(data.byteslice(offset, length)), offset + length]
      when 4
        enter(depth)
        # HLC round six, 2026-11-08 (S1): every item takes at least one byte,
        # so a count past the bytes left is a truncated item, refused before
        # anything is sized by it.
        need(data, offset, length)
        items = Array.new(length) do
          item, offset = decode(data, offset, depth + 1)
          item
        end
        [items, offset]
      when 5 then raise Error, "a definite-length map is not in the wire encoding"
      when 6 then tagged(data, offset, length, depth)
      end
    end
    private_class_method :decode

    # The argument of a head whose additional information is below 28.
    def argument(data, offset, info)
      return [info, offset] if info < 24

      width = 1 << (info - 24)
      need(data, offset, width)
      [data.byteslice(offset, width).unpack1(%w[C n N Q>][info - 24]), offset + width]
    end
    private_class_method :argument

    # HLC round six, 2026-11-08 (S2): one more container level.
    def enter(depth)
      raise Error, "CBOR nesting deeper than #{MAX_DEPTH} levels" if depth >= MAX_DEPTH
    end
    private_class_method :enter

    # HLC round six, 2026-11-08 (S8): an indefinite map of unique text keys.
    def indefinite_map(data, offset, depth)
      enter(depth)
      result = {}
      loop do
        need(data, offset, 1)
        initial = data.getbyte(offset)
        break if initial == BREAK
        raise Error, "a CBOR map key is a text string" unless initial >> 5 == 3

        key, offset = decode(data, offset, depth + 1)
        raise Error, "the CBOR map key #{key.inspect} occurs twice" if result.key?(key)

        result[key], offset = decode(data, offset, depth + 1)
      end
      [result, offset + 1]
    end
    private_class_method :indefinite_map

    # HLC round six, 2026-11-08 (S9, F2): tag 2 or 3 over a definite byte
    # string reads as an Integer (Jackson reads tag 3 over m as -m), and tag 4
    # over [exponent, mantissa] as a BigDecimal, whose two-element array is a
    # container level. Every other tag, 42 included, is refused here; a
    # persistent-tree node reads its links with its own codec.
    def tagged(data, offset, tag, depth)
      need(data, offset, 1)
      content = data.getbyte(offset)
      case tag
      when 2, 3
        raise Error, "tag #{tag} encloses a definite-length byte string" unless content >> 5 == 2 && (content & 0x1F) < 28

        length, = argument(data, offset + 1, content & 0x1F)
        raise Error, "a bignum magnitude passes #{MAX_BIGNUM_BYTES} bytes" if length > MAX_BIGNUM_BYTES

        bytes, offset = decode(data, offset, depth)
        magnitude = bytes.empty? ? 0 : bytes.unpack1("H*").to_i(16)
        [tag == 2 ? magnitude : -magnitude, offset]
      when 4
        raise Error, "tag 4 encloses a two-element array" unless content == 0x82

        enter(depth)
        need(data, offset + 1, 1)
        raise Error, "the exponent of tag 4 is a plain integer" unless data.getbyte(offset + 1) >> 5 <= 1

        exponent, offset = decode(data, offset + 1, depth + 1)
        raise Error, "the exponent of tag 4 lies outside a Java int scale" unless DECIMAL_EXPONENTS.cover?(exponent)

        need(data, offset, 1)
        initial = data.getbyte(offset)
        raise Error, "the mantissa of tag 4 is an integer or a bignum" \
          unless initial >> 5 <= 1 || [0xC2, 0xC3].include?(initial)

        mantissa, offset = decode(data, offset, depth + 1)
        [BigDecimal("#{mantissa}e#{exponent}"), offset]
      else
        raise Error, "CBOR tag #{tag} is refused; only the big-number tags 2, 3, and 4 decode"
      end
    end
    private_class_method :tagged

    # Text bytes as a UTF-8 String, refused unless well-formed shortest-form
    # UTF-8 with no encoded surrogate (HLC round six, 2026-11-08 (S6)).
    def utf8(bytes)
      text = bytes.force_encoding(Encoding::UTF_8)
      raise Error, "invalid UTF-8 in a CBOR text string" unless text.valid_encoding?

      text
    end
    private_class_method :utf8

    # An indefinite-length text (RFC 8949 3.2.3) whose chunks start at offset:
    # definite text chunks up to the break, each well-formed UTF-8 on its own.
    # Load's comparison then holds the chunks to Jackson's (S6).
    def indefinite_text(data, offset)
      text = String.new(encoding: Encoding::UTF_8)
      loop do
        need(data, offset, 1)
        initial = data.getbyte(offset)
        break if initial == BREAK
        raise Error, "an indefinite-length text holds a chunk that is no definite text" \
          unless initial >> 5 == 3 && (initial & 0x1F) < 28

        chunk, offset = decode(data, offset, 0)
        text << chunk
      end
      [text, offset + 1]
    end
    private_class_method :indefinite_text
  end
end
