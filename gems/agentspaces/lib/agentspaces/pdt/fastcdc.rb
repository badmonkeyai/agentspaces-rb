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
    # The content-defined chunker a writer cuts blobs with (PDT 2 phase 7,
    # P2-X-06; srad/agentspaces-pdt.md 3.3 and 10.2, PD-B-01): FastCDC in the
    # per-byte form of the 2016 paper, normalized chunking level 2 with
    # cut-point skipping, pinned so every language cuts pdt_fastcdc_cuts at the
    # same offsets. Minimum 16 KiB, average 64 KiB, maximum 256 KiB; GEAR[i]
    # is the big-endian first eight bytes of sha256 of the byte i; the rolling
    # hash h = (h << 1) + GEAR[b] over unsigned 64-bit arithmetic starts at
    # zero at index MIN of the chunk; the chunk ends at the first index i >= MIN
    # where, after folding byte i, the top 18 bits of h are zero while the
    # chunk is shorter than the average and the top 14 bits after, else at MAX
    # or at the end. The hash runs as two 32-bit halves, so Ruby keeps every
    # step in fixed-size integers.
    module FastCdc
      MIN_SIZE = 16 * 1024
      AVG_SIZE = 64 * 1024
      MAX_SIZE = 256 * 1024
      WORD = 0xFFFFFFFF
      # The top 18 and top 14 bits of the upper half: MASK_S 0xFFFFC00000000000 and MASK_L 0xFFFC000000000000.
      MASK_S_HIGH = 0xFFFFC000
      MASK_L_HIGH = 0xFFFC0000
      GEAR = Array.new(256) { |i| Digest::SHA256.digest(i.chr.b).unpack("NN") }.freeze

      module_function

      # The length of the chunk that starts at offset with length bytes following it.
      def cut(data, offset, length)
        n = length
        return n if n <= MIN_SIZE

        normal = AVG_SIZE
        if n >= MAX_SIZE
          n = MAX_SIZE
        elsif n <= normal
          normal = n
        end
        high = 0
        low = 0
        i = MIN_SIZE
        while i < n
          gear = GEAR[data.getbyte(offset + i)]
          low = (low << 1) + gear[1]
          high = ((high << 1) + gear[0] + (low >> 32)) & WORD
          low &= WORD
          return i if (high & (i < normal ? MASK_S_HIGH : MASK_L_HIGH)).zero?

          i += 1
        end
        i
      end

      # The bytes of a binary String in chunks, in order; the empty string has none.
      def chunks(data)
        data = data.b
        out = []
        offset = 0
        while offset < data.bytesize
          length = cut(data, offset, data.bytesize - offset)
          out << data.byteslice(offset, length)
          offset += length
        end
        out
      end
    end
  end
end
