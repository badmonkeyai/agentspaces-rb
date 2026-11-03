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

# Loadable on its own (require "agentspaces/capabilities") and from
# agentspaces.rb, which defines the Binder before it would require this file.
require_relative "../agentspaces" unless defined?(AgentSpaces::Binder)

module AgentSpaces
  # Layer 4 from Ruby (L3L4-COVERAGE.md 6.4): the capability services over
  # the peer's PIPE_DATA pipes, in the protocols the Java providers speak.
  # The Ruby twin of the Python client's agentspaces.capabilities.
  #
  # - Pipes: the multiplexer, Pipes.new(peer).
  # - Aggregate, Settle, Estimate: push-sum and rosters (aspace:cap/aggregate).
  # - HashingEmbedder, Semantic: the hashing embedder and the query pipe
  #   (aspace:cap/semantic-discovery).
  # - RemoteActions: the actions other agents' cards declare, invoked through spaces.
  # - OrderedLog: the Raft client of the ordered log (aspace:cap/ordered-log,
  #   JS-V-05); OrderedLog#take submits a claim command to the advertised
  #   leader and observes the commit through the space.
  # - DataQueryClient, AssetInvocations: the agent side of the connector
  #   protocol (aspace:cap/data-query and aspace:cap/asset-invoke, JS-C-14).
  #
  # The Raft voter, the fleet-wide join modes, reduces, and the connector
  # runtime stay in Java (and TypeScript).
  module Capabilities
  end
end

require_relative "capabilities/pipes"
require_relative "capabilities/aggregate"
require_relative "capabilities/semantic"
require_relative "capabilities/remote"
require_relative "capabilities/connect"
require_relative "capabilities/ordered"
