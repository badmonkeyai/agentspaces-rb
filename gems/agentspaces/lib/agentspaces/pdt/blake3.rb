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
    # BLAKE3 as far as a bo node needs it (PDT 2 phase 0, P2-B-02;
    # srad/agentspaces-pdt2.md 3.5): the parent compression that joins two
    # chaining values, so a reader checks that a bo node's root pair hashes to
    # the blob's identity, and the identity's CID form, CIDv1 raw over the
    # BLAKE3 multihash 0x1e. The compression follows the BLAKE3 specification
    # (section 2.2): seven rounds of the G function over 32-bit words.
    #
    # PDT 2 phase 7 (P2-C-02): the chunk compression and the tree over chunks,
    # so a reader hashes a chunk group of a verified window to its chaining
    # value (group_cv) and a blob of one group to its hash (root), as Java's
    # Blake3.groupCv and treeRoot compute them.
    module Blake3
      IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19].freeze
      PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8].freeze
      # The message word order of each of the seven rounds.
      SCHEDULE = (1...7).each_with_object([(0...16).to_a]) { |_, rounds| rounds << PERMUTATION.map { |i| rounds.last[i] } }.freeze
      BLOCK_LEN = 64
      CHUNK_LEN = 1024
      CHUNK_START = 1 << 0
      CHUNK_END = 1 << 1
      PARENT = 1 << 2
      ROOT = 1 << 3
      MASK = 0xFFFFFFFF
      MULTIHASH = 0x1E
      DIGEST_LENGTH = 32

      module_function

      # The chaining value of a parent node over two 32-byte chaining values;
      # with root: true, the root's hash, which is the blob's BLAKE3 digest.
      def parent(left, right, root: false)
        block = left.b + right.b
        raise ArgumentError, "a parent joins two 32-byte chaining values" if block.bytesize != BLOCK_LEN

        compress(IV, block.unpack("V16"), 0, BLOCK_LEN, PARENT | (root ? ROOT : 0)).pack("V8")
      end

      # The BLAKE3 hash of some bytes, through the tree of chunk chaining values.
      def root(data) = subtree(data.b, 0, data.bytesize, 0, true).pack("V8")

      # The chaining value of a chunk group whose first chunk is chunk first_chunk
      # of its blob, as a non-root subtree: the value a bo parent above it joins.
      def group_cv(data, first_chunk) = subtree(data.b, 0, data.bytesize, first_chunk, false).pack("V8")

      # The chaining value (or root words) of the chunks in a range, split as
      # BLAKE3 splits a tree: the largest power of two below the count on the left.
      def subtree(data, offset, length, first_chunk, root)
        chunks = [1, (length + CHUNK_LEN - 1) / CHUNK_LEN].max
        return chunk(data, offset, length, first_chunk, root) if chunks == 1

        left_chunks = 1 << ((chunks - 1).bit_length - 1)
        left_bytes = left_chunks * CHUNK_LEN
        left = subtree(data, offset, left_bytes, first_chunk, false)
        right = subtree(data, offset + left_bytes, length - left_bytes, first_chunk + left_chunks, false)
        compress(IV, left + right, 0, BLOCK_LEN, PARENT | (root ? ROOT : 0))
      end
      private_class_method :subtree

      def chunk(data, offset, length, counter, root)
        cv = IV
        blocks = [1, (length + BLOCK_LEN - 1) / BLOCK_LEN].max
        blocks.times do |b|
          size = [BLOCK_LEN, length - (b * BLOCK_LEN)].min
          block = data.byteslice(offset + (b * BLOCK_LEN), size)
          block += "\0".b * (BLOCK_LEN - size) if size < BLOCK_LEN
          flags = (b.zero? ? CHUNK_START : 0) | (b == blocks - 1 ? CHUNK_END | (root ? ROOT : 0) : 0)
          cv = compress(cv, block.unpack("V16"), counter, size, flags)
        end
        cv
      end
      private_class_method :chunk

      # The BLAKE3 digest an identity CID names: "b" + base32lower(0x01, 0x55
      # (raw), 0x1e, 0x20, digest), in its one canonical text. Refuses any
      # other codec or multihash by name.
      def identity_digest(text)
        unless text.is_a?(String) && text.length == Cids::TEXT_LENGTH && text.start_with?("b")
          raise ArgumentError, "not a base32 CIDv1 of a BLAKE3 digest: #{text.inspect}"
        end

        raw = Cids.base32_decode(text[1..])
        version, codec, multihash, length = raw.unpack("C4")
        raise ArgumentError, "not a CIDv1: #{text}" if raw.bytesize != Cids::BINARY_LENGTH || version != 0x01
        raise ArgumentError, format("codec 0x%02x in %s; a BLAKE3 identity is raw (0x55)", codec, text) if codec != Cids::RAW
        raise ArgumentError, format("multihash 0x%02x in %s; a BLAKE3 identity is 0x1e", multihash, text) if multihash != MULTIHASH
        raise ArgumentError, "digest length #{length} in #{text}; BLAKE3 digests are 32 bytes" if length != DIGEST_LENGTH

        raw.byteslice(4, DIGEST_LENGTH)
      end

      # The compression of one block of sixteen words under a chaining value: the
      # first eight words of the output, the next chaining value.
      def compress(cv, m, counter, block_len, flags)
        v = cv + IV.first(4) + [counter & MASK, counter >> 32, block_len, flags]
        SCHEDULE.each do |w|
          g(v, 0, 4, 8, 12, m[w[0]], m[w[1]])
          g(v, 1, 5, 9, 13, m[w[2]], m[w[3]])
          g(v, 2, 6, 10, 14, m[w[4]], m[w[5]])
          g(v, 3, 7, 11, 15, m[w[6]], m[w[7]])
          g(v, 0, 5, 10, 15, m[w[8]], m[w[9]])
          g(v, 1, 6, 11, 12, m[w[10]], m[w[11]])
          g(v, 2, 7, 8, 13, m[w[12]], m[w[13]])
          g(v, 3, 4, 9, 14, m[w[14]], m[w[15]])
        end
        Array.new(8) { |i| v[i] ^ v[i + 8] }
      end
      private_class_method :compress

      def g(v, a, b, c, d, x, y)
        v[a] = (v[a] + v[b] + x) & MASK
        v[d] = rotr(v[d] ^ v[a], 16)
        v[c] = (v[c] + v[d]) & MASK
        v[b] = rotr(v[b] ^ v[c], 12)
        v[a] = (v[a] + v[b] + y) & MASK
        v[d] = rotr(v[d] ^ v[a], 8)
        v[c] = (v[c] + v[d]) & MASK
        v[b] = rotr(v[b] ^ v[c], 7)
      end
      private_class_method :g

      def rotr(word, bits) = ((word >> bits) | (word << (32 - bits))) & MASK
      private_class_method :rotr
    end
  end
end
