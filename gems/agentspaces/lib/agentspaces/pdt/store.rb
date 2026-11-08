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
    # The node store of a reader (srad/agentspaces-pdt.md 3.4, PD-S-01): nodes
    # by CID in memory, verified on the way in, with the reachability walks a
    # tree fetch and a head check need (complete?, missing, reachable) and the
    # root pins a reader keeps while it reads. The Ruby face reads only, so
    # there is no retention set and no collector: the store is bounded by the
    # roots a caller pins, and unpin drops the nodes nothing else reaches.
    class NodeStore
      attr_reader :pins

      def initialize
        @nodes = {}
        @pins = Hash.new(0)
        @lock = Mutex.new
      end

      def has?(cid) = @lock.synchronize { @nodes.key?(cid) }

      def get(cid) = @lock.synchronize { @nodes[cid] }

      # Stores bytes under the CID they hash to; refuses a mismatch by name.
      def put_verified(cid, bytes)
        bytes = bytes.b
        raise NodeFormatError.new("bytes do not hash to the CID", cid) unless Cids.verifies?(cid, bytes)
        raise NodeFormatError.new("node of #{bytes.bytesize} bytes exceeds 1 MiB", cid) if bytes.bytesize > Nodes::MAX_NODE_BYTES

        @lock.synchronize do
          return false if @nodes.key?(cid)

          @nodes[cid] = bytes
          true
        end
      end

      # Stores bytes under their CID and returns it.
      def put(bytes, codec = Cids::DAG_CBOR)
        cid = Cids.of(bytes, codec)
        put_verified(cid, bytes)
        cid
      end

      def remove(cid) = @lock.synchronize { @nodes.delete(cid) }

      def cids = @lock.synchronize { @nodes.keys }

      def size = @lock.synchronize { @nodes.size }

      def bytes_used = @lock.synchronize { @nodes.values.sum(&:bytesize) }

      # The links of a held node (none for a raw chunk or a node that does not decode).
      def links(cid, data = nil)
        data ||= get(cid)
        return [] if data.nil? || Cids.codec_of(cid) == Cids::RAW

        Nodes.links(data, cid)
      rescue NodeFormatError
        []
      end

      def pin(root)
        Cids.parse(root)
        @lock.synchronize { @pins[root] += 1 }
      end

      # Drops one pin; on the last, removes every node no other pinned root reaches.
      def unpin(root)
        count = @lock.synchronize do
          @pins[root] -= 1
          @pins.delete(root) if @pins[root] <= 0
          @pins[root]
        end
        collect if count.zero?
        count
      end

      def pinned = @lock.synchronize { @pins.keys }

      # Removes every node no pinned root (or extra root) reaches; returns how many.
      def collect(extra_roots = [])
        keep = {}
        (pinned + extra_roots).each { |root| reachable(root).each { |c| keep[c] = true } }
        removed = 0
        @lock.synchronize do
          @nodes.keys.each do |cid|
            next if keep[cid]

            @nodes.delete(cid)
            removed += 1
          end
        end
        removed
      end

      # Every CID reachable from a root that the store holds.
      def reachable(root) = walk(root)[0]

      # The CIDs a root reaches that the store lacks.
      def missing(root) = walk(root)[1]

      def complete?(root) = missing(root).empty?

      # How many nodes under a root are held.
      def held_under(root) = reachable(root).size

      private

      def walk(root)
        seen = {}
        missing = {}
        stack = [[root, 0]]
        until stack.empty?
          cid, depth = stack.pop
          next if seen.key?(cid) || missing.key?(cid)

          data = get(cid)
          if data.nil?
            missing[cid] = true
            next
          end
          seen[cid] = true
          next if depth >= Nodes::MAX_DEPTH

          links(cid, data).each { |link| stack << [link, depth + 1] }
        end
        [seen.keys, missing.keys]
      end
    end
  end
end
