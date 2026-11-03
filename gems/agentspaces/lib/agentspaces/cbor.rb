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
  # CBOR (RFC 8949) encoded byte for byte as the Java codec's Jackson CBOR
  # encodes it, which the golden vectors prove: maps are indefinite-length
  # (0xBF ... 0xFF) with keys in insertion order (a Hash stands for a Java
  # record, whose components keep their declared order), arrays are definite,
  # text and byte strings are definite with minimal heads, integers use the
  # minimal width, and every Float is a float64 (0xFB). A String in
  # Encoding::BINARY is a byte string; any other String is text. Ruby keeps
  # Integer and Float apart, so no wrapper type is needed for doubles.
  module CBOR
    # Deepest container nesting accepted; hostile deep nesting overflows the stack.
    MAX_DEPTH = 64
    BREAK = 0xFF
    UINT64_MAX = (1 << 64) - 1

    # A CBOR item that does not decode, or a value that does not encode.
    class Error < ArgumentError; end

    module_function

    # Encodes a Ruby value the way the Java codec encodes its equivalent.
    def dump(value)
      out = String.new(capacity: 64, encoding: Encoding::BINARY)
      encode(value, out)
      out
    end

    # Decodes exactly one CBOR item; definite and indefinite forms are both
    # accepted, and trailing bytes are refused so malformed or smuggled input
    # is loud (ASF-042).
    def load(data)
      data = data.b
      value, offset = decode(data, 0, 0)
      raise Error, "trailing bytes after CBOR item at offset #{offset}" if offset != data.bytesize

      value
    end

    # A copy of a map-valued field with its entries in canonical order
    # (shorter UTF-8 key first, then bytewise; RFC 8949 4.2.1), the order the
    # Java codec writes every map in as of wire v3. Apply it to maps a
    # signature covers (tags, costHints, spaceBindings, resourceHints,
    # parameters, access), never to a Hash that stands for a record.
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
      when Integer
        if value >= 0
          raise Error, "integer #{value} exceeds 64 bits" if value > UINT64_MAX

          head(0, value, out)
        else
          raise Error, "integer #{value} exceeds 64 bits" if -1 - value > UINT64_MAX

          head(1, -1 - value, out)
        end
      when Float
        out << 0xFB << [value].pack("G")
      when String
        if value.encoding == Encoding::BINARY
          head(2, value.bytesize, out)
          out << value
        else
          bytes = value.encode(Encoding::UTF_8).b
          head(3, bytes.bytesize, out)
          out << bytes
        end
      when Symbol
        encode(value.name, out)
      when Array
        head(4, value.size, out)
        value.each { |item| encode(item, out) }
      when Hash
        # Indefinite-length map in the Hash's own order, matching Java's
        # streaming object encoder; map-valued fields are put in canonical
        # order where they are built (canonical_map).
        out << 0xBF
        value.each do |key, item|
          encode(key, out)
          encode(item, out)
        end
        out << BREAK
      else
        raise Error, "cannot encode #{value.class}"
      end
    end
    private_class_method :encode

    def need(data, offset, count)
      raise Error, "truncated CBOR item" if offset + count > data.bytesize
    end
    private_class_method :need

    def decode(data, offset, depth)
      raise Error, "CBOR nesting too deep" if depth > MAX_DEPTH

      need(data, offset, 1)
      initial = data.getbyte(offset)
      major = initial >> 5
      info = initial & 0x1F
      offset += 1

      # Major 7 carries simple values and floats, never a length head.
      if major == 7
        case info
        when 20 then return [false, offset]
        when 21 then return [true, offset]
        when 22, 23 then return [nil, offset]
        when 25
          need(data, offset, 2)
          return [half(data.byteslice(offset, 2).unpack1("n")), offset + 2]
        when 26
          need(data, offset, 4)
          return [data.byteslice(offset, 4).unpack1("g"), offset + 4]
        when 27
          need(data, offset, 8)
          return [data.byteslice(offset, 8).unpack1("G"), offset + 8]
        else
          raise Error, format("unsupported CBOR simple value 0x%02x", initial)
        end
      end

      length =
        if info == 31 then nil
        elsif info < 24 then info
        elsif info == 24
          need(data, offset, 1)
          offset += 1
          data.getbyte(offset - 1)
        elsif info == 25
          need(data, offset, 2)
          offset += 2
          data.byteslice(offset - 2, 2).unpack1("n")
        elsif info == 26
          need(data, offset, 4)
          offset += 4
          data.byteslice(offset - 4, 4).unpack1("N")
        elsif info == 27
          need(data, offset, 8)
          offset += 8
          data.byteslice(offset - 8, 8).unpack1("Q>")
        else
          raise Error, format("unsupported CBOR head 0x%02x", initial)
        end

      case major
      when 0 then [length, offset]
      when 1 then [-1 - length, offset]
      when 2
        raise Error, "indefinite byte strings are not used on this wire" if length.nil?

        need(data, offset, length)
        [data.byteslice(offset, length), offset + length]
      when 3
        raise Error, "indefinite text strings are not used on this wire" if length.nil?

        need(data, offset, length)
        text = data.byteslice(offset, length).force_encoding(Encoding::UTF_8)
        raise Error, "invalid UTF-8 in a CBOR text string" unless text.valid_encoding?

        [text, offset + length]
      when 4
        items = []
        if length.nil?
          loop do
            need(data, offset, 1)
            break if data.getbyte(offset) == BREAK

            item, offset = decode(data, offset, depth + 1)
            items << item
          end
          return [items, offset + 1]
        end
        length.times do
          item, offset = decode(data, offset, depth + 1)
          items << item
        end
        [items, offset]
      when 5
        result = {}
        if length.nil?
          loop do
            need(data, offset, 1)
            break if data.getbyte(offset) == BREAK

            key, offset = decode(data, offset, depth + 1)
            value, offset = decode(data, offset, depth + 1)
            result[key] = value
          end
          return [result, offset + 1]
        end
        length.times do
          key, offset = decode(data, offset, depth + 1)
          value, offset = decode(data, offset, depth + 1)
          result[key] = value
        end
        [result, offset]
      else
        raise Error, format("unsupported CBOR item 0x%02x", initial)
      end
    end
    private_class_method :decode

    # IEEE 754 half precision to a Float.
    def half(bits)
      exponent = (bits >> 10) & 0x1F
      mantissa = bits & 0x3FF
      value =
        if exponent.zero? then mantissa * (2.0**-24)
        elsif exponent == 31 then mantissa.zero? ? Float::INFINITY : Float::NAN
        else (mantissa + 1024) * (2.0**(exponent - 25))
        end
      bits.anybits?(0x8000) ? -value : value
    end
    private_class_method :half
  end
end
