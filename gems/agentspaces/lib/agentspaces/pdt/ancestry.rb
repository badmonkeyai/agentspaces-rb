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
    # A head's ancestry, the reserved attribute ATTR (PDT 2 phase 0, P2-V-01;
    # srad/agentspaces-pdt2.md 3.10 and 6.10.3, rule 9). A head is a record
    # every member reads and a strict reader refuses a field it does not know,
    # so the CID of the head's vg node rides in attrs beside pdt.issued and
    # pdt.issuer, the PRef schema keeps its twelve fields, and a level-1
    # reader passes the attribute through as text. The attribute is
    # advisory: a reader uses it only when its text is a CIDv1 of codec
    # dag-cbor over sha2-256 and the node it names hashes to it and decodes as
    # a vg node of the head's own root; otherwise the head reads as one
    # without ancestry (P2-V-02), and nothing is refused or struck.
    module Ancestry
      ATTR = "pdt.ancestry"

      module_function

      # The CID a decoded PRef head names under ATTR when the text is a usable one, else nil.
      def cid(head)
        text = (head["attrs"] || {})[ATTR]
        Cids.cid?(text) && Cids.codec_of(text) == Cids::DAG_CBOR ? text : nil
      end

      # The vg node of a head from the bytes a store or a fetch returned for cid(head), or nil.
      def read(head, bytes)
        named = cid(head)
        named && node(named, head["root"], bytes)
      end

      # A vg node from the bytes held or fetched for a CID (PDT 2 phase 1,
      # P2-V-02), as Java's Ancestry.read(cid, root, bytes): a head's node must
      # describe root, and a node a chain link names (root nil) may describe
      # any root. Nil when the bytes hash to another CID, decode as no vg
      # node, or describe another root.
      def node(cid, root, bytes)
        return nil unless Cids.of(bytes, Cids::DAG_CBOR) == cid

        found = VgNode.decode(bytes, cid)
        root.nil? || found.root == root ? found : nil
      rescue NodeFormatError
        nil
      end
    end
  end
end
