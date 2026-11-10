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
    # Application keys and values inside nodes (srad/agentspaces-pdt.md 10.2,
    # PD-N-05): a key or value is one CBOR item, embedded as CBOR.dump wrote
    # it, and a value slot that holds a bare link item names a spilled node: an
    # x node holding the item whole, an m or vr sub-tree, a blob tree, or an x
    # envelope whose v links a vr of keys and values (an ordered map) or a
    # chunk (a byte string). resolve reassembles the CBOR bytes of any of them.
    module Values
      module_function

      # The canonical CBOR of a key the CHAMP hashes, or of a value a writer
      # stores: a PText in its value form (PDT 2 phase 7, P2-T-05).
      def encode_value(value)
        case value
        when Raw then value.bytes
        when PText then value.to_wire
        else CBOR.dump(value)
        end
      end

      # A value from its CBOR item; a text in its value form reads as a PText
      # (PDT 2 phase 7, P2-C-02, P2-T-05), with no replica until a writer names one.
      def decode_value(bytes) = PText.value?(bytes) ? PText.of(PText.leaf_of(bytes)) : CBOR.load(bytes)

      # A key or value given as exact CBOR bytes, for a form CBOR.dump does not
      # produce (a 32-bit float, a definite map).
      Raw = Struct.new(:bytes)

      def link_item?(item) = Nodes.link_shaped?(item)

      # The in-memory reference of a decoded value slot: the bytes, or the CID of a spilled node.
      def ref_of(item) = link_item?(item) ? Nodes.link_cid(item) : item

      # The CBOR bytes of a value reference, loading and reassembling a spilled node.
      def resolve(ref, loader, depth = 0)
        return ref if ref.is_a?(String) && !Cids.cid?(ref)
        raise NodeFormatError.new("spilled values nested deeper than #{Nodes::MAX_DEPTH} levels", ref) if depth > Nodes::MAX_DEPTH

        cid = ref
        data = loader.load(cid)
        return byte_string(data) if Cids.codec_of(cid) == Cids::RAW

        case Nodes.kind_of(data)
        when Nodes::KIND_X then resolve_x(cid, data, loader, depth)
        when Nodes::KIND_M then reassemble_map(ChampNode.load_root(cid, data), loader, depth)
        when Nodes::KIND_VR then reassemble_array(VecRoot.decode(cid, data), loader, depth)
        when Nodes::KIND_B then byte_string(read_blob(cid, data, loader))
        # PDT 2 phase 7 (P2-T-05): a text spilled to its t node reads as its value form
        when Nodes::KIND_T then PText.to_wire(TextLeaf.decode(data, cid))
        else raise NodeFormatError.new("a spilled value cannot be a node of kind '#{Nodes.kind_of(data)}'", cid)
        end
      end

      # An x node holds the item whole, or, when v is a bare link item, is an
      # envelope: vr links an ordered map (bf, the items in order, ff), raw or
      # b links a byte string (phase 4, 10.2).
      def resolve_x(cid, data, loader, depth)
        node = Nodes.decode(data, cid)
        item = node["v"].bytes
        return item unless link_item?(item)

        inner = Nodes.link_cid(item)
        inner_data = loader.load(inner)
        return byte_string(inner_data) if Cids.codec_of(inner) == Cids::RAW

        case Nodes.kind_of(inner_data)
        when Nodes::KIND_VR
          root = VecRoot.decode(inner, inner_data)
          raise NodeFormatError.new("an ordered-map envelope links a vector of #{root.n} items; keys and values pair up", inner) if root.n.odd?

          out = String.new(encoding: Encoding::BINARY) << 0xBF
          root.n.times { |i| out << resolve(root.nth(i, loader), loader, depth + 1) }
          out << 0xFF
        when Nodes::KIND_B then byte_string(read_blob(inner, inner_data, loader))
        else raise NodeFormatError.new("an x envelope links a node of kind '#{Nodes.kind_of(inner_data)}'", inner)
        end
      end

      def reassemble_map(root, loader, depth)
        entries = root.entries(0, loader).sort_by { |key, _| [key.bytesize, key] }
        out = String.new(encoding: Encoding::BINARY) << 0xBF
        entries.each do |key, value|
          out << key << resolve(value, loader, depth + 1)
        end
        out << 0xFF
      end

      def reassemble_array(root, loader, depth)
        out = String.new(encoding: Encoding::BINARY) << Nodes.header(4, root.n)
        root.n.times { |i| out << resolve(root.nth(i, loader), loader, depth + 1) }
        out
      end

      def byte_string(raw) = Nodes.header(2, raw.bytesize) + raw.b

      # Reads a blob tree depth first with an explicit stack, bounded by the tree depth.
      def read_blob(root, root_bytes, loader)
        out = String.new(encoding: Encoding::BINARY)
        stack = [[root, 1]]
        until stack.empty?
          cid, depth = stack.pop
          data = cid == root ? root_bytes : loader.load(cid)
          if Cids.codec_of(cid) == Cids::RAW
            out << data
            next
          end
          raise NodeFormatError.new("tree deeper than #{Nodes::MAX_DEPTH} levels", cid) if depth >= Nodes::MAX_DEPTH

          node = Nodes.decode(data, cid)
          raise NodeFormatError.new("expected a blob node, found kind '#{node['k']}'", cid) if node["k"] != Nodes::KIND_B

          (node["c"] || []).reverse_each { |link| stack << [link.cid, depth + 1] }
        end
        out
      end
    end

    # Loads node bytes from the store alone (PD-V-06): a node it lacks is NodeUnavailable.
    class StoreLoader
      def initialize(store)
        @store = store
      end

      def load(cid)
        data = @store.get(cid)
        raise NodeUnavailable.new(cid, [], "node #{cid} is not in the store") if data.nil?

        data
      end
    end

    # Reads the store and otherwise fetches through the callable (one CID to
    # bytes, raising NodeUnavailable), the reader's loader of PD-V-06.
    class StoreThenFetchLoader
      def initialize(store, fetch)
        @store = store
        @fetch = fetch
      end

      def load(cid)
        data = @store.get(cid)
        return data unless data.nil?

        data = @fetch.call(cid)
        raise NodeUnavailable.new(cid, [], "node #{cid} could not be fetched") if data.nil?

        data
      end
    end
  end
end
