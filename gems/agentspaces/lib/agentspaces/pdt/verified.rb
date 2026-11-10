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
    # A window of a blob that does not verify against the identity its claim names (PDT 2 phase 7, P2-C-02).
    class VerificationError < IOError; end

    BlobIdentity = Struct.new(:identity, :bao)

    # What a head claims about a blob (PDT 2 phase 7, P2-C-02; srad/agentspaces-pdt2.md
    # 3.5 and 6.10.3, rule 10): its BLAKE3 identity under pdt.blake3 and the root of its
    # bo outboard under pdt.bao. The attributes are advisory, so a pair that does not
    # read as two canonical CIDs of the expected codec and hash reads as absent.
    class BlobIdentity
      BLAKE3_ATTR = "pdt.blake3"
      BAO_ATTR = "pdt.bao"

      def initialize(identity, bao)
        super
        freeze
        Blake3.identity_digest(identity)
        raise ArgumentError, "pdt.bao names a dag-cbor node, found #{bao.inspect}" unless Cids.cid?(bao) && Cids.codec_of(bao) == Cids::DAG_CBOR
      end

      # The claim in a record's attributes when both read, else nil.
      def self.read(attrs)
        identity = (attrs || {})[BLAKE3_ATTR]
        bao = (attrs || {})[BAO_ATTR]
        return nil unless identity.is_a?(String) && bao.is_a?(String)

        new(identity, bao)
      rescue ArgumentError
        nil
      end

      def digest = Blake3.identity_digest(identity)
    end

    # A window of a blob read through its Bao outboard (PDT 2 phase 7, P2-C-02, as
    # Java's VerifiedWindow): the walk of the bo nodes that cover the window's chunk
    # groups, from the root the claim names, checks each parent pair on the way
    # against the value above it, the top pair with BLAKE3's root flag against the
    # identity, and each child node's size against what its parent claims, so it
    # ends with the expected chaining value of every group in the window. Each
    # group then reads from the blob tree and counts only when its chaining value
    # equals the expected one; a blob of one group hashes as the root. Any break
    # raises VerificationError naming the node or the group, and no byte of a
    # group that does not verify is returned.
    class VerifiedWindow
      GROUP = BoNode::GROUP_BYTES

      # The verified bytes of a window of a blob (a PBlob) under a claim (a BlobIdentity).
      def self.read(blob, claim, offset, length)
        if offset.negative? || length.negative? || offset + length > blob.size
          raise IndexError, "range #{offset}+#{length} outside a blob of #{blob.size} bytes"
        end
        return "".b if length.zero?

        new(blob, claim, offset, length).bytes
      end

      Walk = Struct.new(:cid, :node, :blocks, :first_group, :per_leaf, :first, :last) do
        def overlaps?(from, to) = first_group + (from * per_leaf) <= last && first_group + (to * per_leaf) > first
      end

      def initialize(blob, claim, offset, length)
        @blob = blob
        @claim = claim
        @offset = offset
        @length = length
        @expected = {}
      end

      def bytes
        first = @offset / GROUP
        last = (@offset + @length - 1) / GROUP
        root = node(@claim.bao)
        if root.size != @blob.size
          raise VerificationError, "the outboard #{@claim.bao} covers #{root.size} bytes where the blob #{@blob.root} " \
                                   "holds #{@blob.size}"
        end
        walk(@claim.bao, root, 0, @claim.digest, true, first, last)
        out = String.new(encoding: Encoding::BINARY)
        (first..last).each do |g|
          start = g * GROUP
          group = @blob.read(start, [@blob.size, start + GROUP].min - start)
          cv = BoNode.groups(@blob.size) == 1 ? Blake3.root(group) : Blake3.group_cv(group, g << BoNode::GROUP_LOG)
          if cv != @expected[g]
            raise VerificationError, "chunk group #{g} (bytes #{start} to #{start + group.bytesize}) does not verify " \
                                     "against the identity #{@claim.identity}"
          end
          from = [@offset, start].max
          out << group.byteslice(from - start, [@offset + @length, start + group.bytesize].min - from)
        end
        out
      end

      private

      def node(cid)
        BoNode.decode(@blob.loader.load(cid), cid)
      rescue NodeFormatError, NodeUnavailable => e
        raise VerificationError, "the outboard node #{cid} does not read: #{e.message}"
      end

      # Walks one bo node whose subtree starts at group first_group and must chain to cv.
      def walk(cid, node, first_group, cv, root, first, last)
        blocks = BoNode.child_sizes(node.size)
        per_leaf = blocks.empty? ? 1 : BoNode.groups(blocks[0])
        leaves = blocks.empty? ? BoNode.groups(node.size) : blocks.size
        descend(Walk.new(cid, node, blocks, first_group, per_leaf, first, last), 0, 0, leaves, cv, root)
      end

      # Descends the pre-order parents of leaves [from, to), whose subtree value is cv,
      # from parent pair pair: BLAKE3 puts the largest power of two below the count on the left.
      def descend(w, pair, from, to, cv, root)
        if to - from == 1
          group_start = w.first_group + (from * w.per_leaf)
          return @expected[group_start] = cv if w.blocks.empty?

          child = w.node.children[from].cid
          node = node(child)
          if node.size != w.blocks[from]
            raise VerificationError, "the outboard node #{child} covers #{node.size} bytes where its parent #{w.cid} " \
                                     "claims #{w.blocks[from]}"
          end
          return walk(child, node, group_start, cv, false, w.first, w.last)
        end
        at = pair * BoNode::PARENT_BYTES
        left = w.node.parents.byteslice(at, Blake3::DIGEST_LENGTH)
        right = w.node.parents.byteslice(at + Blake3::DIGEST_LENGTH, Blake3::DIGEST_LENGTH)
        if Blake3.parent(left, right, root: root) != cv
          raise VerificationError, "the outboard node #{w.cid} does not chain to the identity #{@claim.identity} at parent #{pair}"
        end

        mid = from + (1 << ((to - from - 1).bit_length - 1))
        descend(w, pair + 1, from, mid, left, false) if w.overlaps?(from, mid)
        descend(w, pair + 1 + (mid - from - 1), mid, to, right, false) if w.overlaps?(mid, to)
      end
    end
  end
end
