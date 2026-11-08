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
    # A blob read from a node store (srad/agentspaces-pdt.md 3.3 and 10.2,
    # PD-B-07, PD-C-06): a raw chunk when the blob has one chunk, else a
    # prolly tree of {k:"b", h, c, z} nodes over raw chunks. A read seeks by
    # the z sums and loads only the chunks that hold the range; every chunk
    # is checked against the length the tree claims. The Ruby face reads only.
    class PBlob
      Entry = Struct.new(:cid, :length)
      Located = Struct.new(:cid, :start, :length)

      attr_reader :root, :size, :height, :loader

      def self.load(root, loader)
        parsed = Cids.parse(root)
        data = loader.load(root)
        return new(root, data.bytesize, 0, loader, data.empty? ? [] : [Entry.new(root, data.bytesize)]) if parsed.codec == Cids::RAW

        node = decode_b(root, data)
        new(root, node["z"].sum, node["h"], loader, nil)
      end

      def self.decode_b(cid, data)
        node = Nodes.decode(data, cid)
        raise NodeFormatError.new("kind '#{node['k']}' where a blob node was expected", cid) if node["k"] != Nodes::KIND_B

        links = node["c"] || []
        sizes = node["z"] || []
        raise NodeFormatError.new("blob node with #{links.size} links and #{sizes.size} sizes", cid) if links.empty? || links.size != sizes.size
        raise NodeFormatError.new("blob node without a height", cid) unless node["h"].is_a?(Integer) && node["h"] >= 1

        node
      end

      def initialize(root, size, height, loader, chunks)
        @root = root
        @size = size
        @height = height
        @loader = loader
        @chunks = chunks
      end

      # The chunks in order, walking the tree once.
      def chunks
        return @chunks unless @chunks.nil?

        leaves = []
        collect(root, size, leaves, 1)
        @chunks = leaves
      end

      # The bytes of a range, loading only the chunks that hold it.
      def read(offset = 0, length = nil)
        length = size - offset if length.nil?
        raise IndexError, "range #{offset}+#{length} outside a blob of #{size} bytes" if offset.negative? || length.negative? || offset + length > size

        out = String.new(encoding: Encoding::BINARY)
        pos = offset
        finish = offset + length
        while pos < finish
          located = seek(pos)
          data = chunk(Entry.new(located.cid, located.length))
          take = [finish, located.start + located.length].min - pos
          out << data.byteslice(pos - located.start, take)
          pos += take
        end
        out
      end

      def read_all = chunks.map { |e| chunk(e) }.join.b

      def ==(other) = other.is_a?(PBlob) && other.root == root
      alias eql? ==
      def hash = root.hash

      def inspect = "#<AgentSpaces::PDT::PBlob #{root} size=#{size}>"

      private

      def load_node(cid, under)
        node = PBlob.decode_b(cid, @loader.load(cid))
        held = node["z"].sum
        raise NodeFormatError.new("blob node holds #{held} bytes where its parent claims #{under}", cid) if held != under

        node
      end

      def collect(cid, under, leaves, depth)
        if Cids.codec_of(cid) == Cids::RAW
          leaves << Entry.new(cid, under)
          return
        end
        raise NodeFormatError.new("tree deeper than #{Nodes::MAX_DEPTH} levels", cid) if depth > Nodes::MAX_DEPTH

        node = load_node(cid, under)
        node["c"].zip(node["z"]).each { |link, z| collect(link.cid, z, leaves, depth + 1) }
      end

      def seek(offset)
        raise IndexError, "offset #{offset} outside a blob of #{size} bytes" if offset.negative? || offset >= size

        cid = root
        start = 0
        under = size
        depth = 1
        while Cids.codec_of(cid) != Cids::RAW
          raise NodeFormatError.new("tree deeper than #{Nodes::MAX_DEPTH} levels", cid) if depth > Nodes::MAX_DEPTH

          node = load_node(cid, under)
          sizes = node["z"]
          i = 0
          while i < sizes.size - 1 && offset >= start + sizes[i]
            start += sizes[i]
            i += 1
          end
          cid = node["c"][i].cid
          under = sizes[i]
          depth += 1
        end
        Located.new(cid, start, under)
      end

      def chunk(entry)
        data = @loader.load(entry.cid)
        raise NodeFormatError.new("chunk of #{data.bytesize} bytes where the tree claims #{entry.length}", entry.cid) if data.bytesize != entry.length

        data
      end
    end
  end
end
