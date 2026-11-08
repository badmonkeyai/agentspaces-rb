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
require_relative "pdt/store"
require_relative "pdt/values"
require_relative "pdt/champ"
require_relative "pdt/vector"
require_relative "pdt/blob"
require_relative "pdt/tree"
require_relative "pdt/refs"

module AgentSpaces
  # Persistent data trees, the reading face (srad/agentspaces-pdt.md PD-C-06):
  # the node codec and CIDs of 3.1, PMap, PSet, PVector, and PBlob read over a
  # node store that NODE_WANT and TREE_WANT fetches fill, and the deref of a
  # PRef head in a ref space. A root a Ruby agent meets as a payloadRef it
  # does not read stays an opaque string.
  #
  #   pdt = AgentSpaces::PDT::Pdt.new(peer, space: "pdt")
  #   facts = pdt.map_ref("facts").deref      # a PMap: facts["k"], facts.count, facts.each
  #   pdt.map_ref("facts").history(5)         # the versions seen, newest first
  module PDT
  end
end
