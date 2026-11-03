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
  module Capabilities
    # The capability pipes (TECH-SPEC 8, CapabilityPipes): one PIPE_DATA
    # envelope per frame, addressed to a member, carrying {capability,
    # payload}; handlers by capability type on the receiving side. At most
    # one per peer, shared by the capabilities built on it.
    class Pipes
      attr_reader :peer, :random

      def initialize(peer, random: Random.new)
        @peer = peer
        @random = random
      end

      # Registers a handler for one capability's frames: a callable over
      # (from_peer_id, payload bytes), or the block.
      def on_capability(capability_type, handler = nil, &block)
        handler ||= block
        raise ArgumentError, "on_capability needs a handler or a block" if handler.nil?

        @peer.pipe_handlers[capability_type] = handler
      end

      # One frame to a member; via names the relays the member declared (its
      # relay.via hint or a holding's via), extending the path the seed
      # carries the frame along (SPEC 5.4, v0.1.23). Python calls this send;
      # Ruby keeps Object#send.
      def send_pipe(to, capability_type, payload, via: nil)
        @peer.send_pipe(to, capability_type, payload, via: via)
      end

      # The members a frame can reach (those that signed a frame on our
      # connection), this peer excluded. A member known only from the peers
      # stream is left out: a dial-only peer cannot address it directly.
      def members
        own = @peer.identity.peer_id
        @peer.reachable.to_a.reject { |m| m == own }
      end

      # n members at random (PeerSampler.randomMembers).
      def random_members(count) = members.shuffle(random: @random).first(count)

      # One member at random, or nil when none is reachable.
      def sample(ids) = ids.empty? ? nil : ids.sample(random: @random)
    end
  end
end
