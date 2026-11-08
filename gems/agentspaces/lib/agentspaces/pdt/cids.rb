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
    # CIDs of persistent tree nodes (srad/agentspaces-pdt.md 3.1 and 10.2,
    # PD-N-02): "b" + base32lower(0x01, codec, 0x12 0x20, sha256), codec 0x71
    # (dag-cbor) for a structured node and 0x55 (raw) for a blob chunk. The
    # binary form is the 36 bytes after the multibase prefix. A codec or
    # multihash this module does not know is refused by name.
    module Cids
      DAG_CBOR = 0x71
      RAW = 0x55
      SHA2_256 = 0x12
      DIGEST_LENGTH = 32
      BINARY_LENGTH = 4 + DIGEST_LENGTH
      TEXT_LENGTH = 59
      ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
      INDEX = ALPHABET.each_char.with_index.to_h.freeze
      CODEC_NAMES = { DAG_CBOR => "dag-cbor", RAW => "raw" }.freeze

      Parsed = Struct.new(:codec, :digest) do
        def structured? = codec == DAG_CBOR
      end

      module_function

      # RFC 4648 base32, lower case, unpadded.
      def base32_lower(data)
        out = +""
        buffer = 0
        bits = 0
        data.each_byte do |b|
          buffer = (buffer << 8) | b
          bits += 8
          while bits >= 5
            out << ALPHABET[(buffer >> (bits - 5)) & 0x1F]
            bits -= 5
          end
        end
        out << ALPHABET[(buffer << (5 - bits)) & 0x1F] if bits.positive?
        out
      end

      def base32_decode(text)
        out = String.new(encoding: Encoding::BINARY)
        buffer = 0
        bits = 0
        text.each_char do |c|
          value = INDEX[c]
          raise ArgumentError, "not a base32 character: #{c.inspect}" if value.nil?

          buffer = (buffer << 5) | value
          bits += 5
          if bits >= 8
            bits -= 8
            out << ((buffer >> bits) & 0xFF)
          end
        end
        raise ArgumentError, "base32 padding bits are not zero" unless (buffer & ((1 << bits) - 1)).zero?

        out
      end

      def sha256(data) = Digest::SHA256.digest(data.b)

      # The CID of some bytes under a codec.
      def of(data, codec = DAG_CBOR)
        raise ArgumentError, format("unknown codec 0x%02x", codec) unless CODEC_NAMES.key?(codec)

        of_digest(sha256(data), codec)
      end

      def of_digest(digest, codec)
        "b" + base32_lower([0x01, codec, SHA2_256, DIGEST_LENGTH].pack("C*") + digest.b)
      end

      # The text form of a binary CID, validated.
      def from_binary(binary)
        raise ArgumentError, "a binary CID is #{BINARY_LENGTH} bytes, got #{binary.bytesize}" if binary.bytesize != BINARY_LENGTH

        text = "b" + base32_lower(binary)
        parse(text)
        text
      end

      # The 36 binary bytes of a CID.
      def binary(cid)
        parse(cid)
        base32_decode(cid[1..])
      end

      # The codec and digest of a CID; refuses anything outside the pinned form by name.
      def parse(cid)
        unless cid.is_a?(String) && cid.length == TEXT_LENGTH && cid.start_with?("b")
          raise ArgumentError, "not a base32 CIDv1 of a sha2-256 digest: #{cid.inspect}"
        end

        raw = base32_decode(cid[1..])
        raise ArgumentError, "not a CIDv1: #{cid}" if raw.bytesize != BINARY_LENGTH || raw.getbyte(0) != 0x01

        codec = raw.getbyte(1)
        raise ArgumentError, format("unknown codec 0x%02x in %s", codec, cid) unless CODEC_NAMES.key?(codec)
        unless raw.getbyte(2) == SHA2_256
          raise ArgumentError, format("unknown multihash 0x%02x in %s; sha2-256 (0x12) is the one this release reads",
                                      raw.getbyte(2), cid)
        end
        raise ArgumentError, "digest length #{raw.getbyte(3)} in #{cid}; sha2-256 digests are 32 bytes" if raw.getbyte(3) != DIGEST_LENGTH

        Parsed.new(codec, raw.byteslice(4, DIGEST_LENGTH))
      end

      def cid?(value)
        parse(value)
        true
      rescue ArgumentError, TypeError
        false
      end

      def codec_of(cid) = parse(cid).codec

      # Whether bytes hash to a CID (PD-N-06).
      def verifies?(cid, data)
        parse(cid).digest == sha256(data)
      rescue ArgumentError
        false
      end
    end
  end
end
