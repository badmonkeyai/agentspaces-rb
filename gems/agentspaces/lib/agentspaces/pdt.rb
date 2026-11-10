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

require_relative "pdt/cids"
require_relative "pdt/nodes"
require_relative "pdt/datoms"
require_relative "pdt/text"
require_relative "pdt/kinds"
require_relative "pdt/db"
require_relative "pdt/blake3"
require_relative "pdt/store"
require_relative "pdt/values"
require_relative "pdt/champ"
require_relative "pdt/vector"
require_relative "pdt/blob"
require_relative "pdt/fastcdc"
require_relative "pdt/build"
require_relative "pdt/ptext"
require_relative "pdt/verified"
require_relative "pdt/tree"
require_relative "pdt/refs"
require_relative "pdt/ancestry"
require_relative "pdt/store_records"
require_relative "pdt/stores"

module AgentSpaces
  # Persistent data trees, the reading face (srad/agentspaces-pdt.md PD-C-06):
  # the node codec and CIDs of 3.1, PMap, PSet, PVector, and PBlob read over a
  # node store that NODE_WANT and TREE_WANT fetches fill, and the deref of a
  # PRef head in a ref space. A root a Ruby agent meets as a payloadRef it
  # does not read stays an opaque string.
  #
  # PDT 2 phase 0 (srad/agentspaces-pdt2.md 8, P2-C-02) adds the readers and
  # writers of the level-2 kinds (db, dn, rr, rv, t, vg, bo), the store
  # records StorePin and StoreReceipt, and the advisory pdt.ancestry
  # attribute. This face stays at PDT feature level 1 on the content swarm
  # (6.10.2): it advertises no pdt parameter and sends no level-2 form.
  #
  # PDT 2 phase 7 (P2-C-02, P2-X-06) reads PRef.v 2 heads and db refs through
  # DbReader, relaxed vectors, texts (PText), and BLAKE3 ranges through a Bao
  # outboard (PBlob#read_verified); writes signed pins (Pdt#store_for); and
  # writes heads: Ref#swap in multi mode with inline deltas, the tree built by
  # Build, and a serving side that answers NODE_WANT and TREE_WANT.
  #
  #   pdt = AgentSpaces::PDT::Pdt.new(peer, space: "pdt")
  #   facts = pdt.map_ref("facts").deref      # a PMap: facts["k"], facts.count, facts.each
  #   pdt.map_ref("facts").history(5)         # the versions seen, newest first
  #   pdt.map_ref("facts").swap { |m| m.merge("k" => 1) }  # a new head over the heads read
  #   pdt.tick                                # on the host's tick: retries, renewals, cancels
  module PDT
  end
end
