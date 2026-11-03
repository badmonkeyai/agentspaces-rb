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

require "monitor"
require "set"
require "timeout"

require_relative "agentspaces/version"
require_relative "agentspaces/cbor"
require_relative "agentspaces/crypto"
require_relative "agentspaces/identity"
require_relative "agentspaces/wire"
require_relative "agentspaces/session"
require_relative "agentspaces/revocation"
require_relative "agentspaces/channel"
require_relative "agentspaces/tls"
require_relative "agentspaces/web_transports"
require_relative "agentspaces/peer"
require_relative "agentspaces/beacon"
require_relative "agentspaces/social"
require_relative "agentspaces/bootstrap"
require_relative "agentspaces/entry"
require_relative "agentspaces/template"
require_relative "agentspaces/space"
require_relative "agentspaces/vote"
require_relative "agentspaces/agent"
require_relative "agentspaces/binder"
require_relative "agentspaces/config"
require_relative "agentspaces/capabilities"

# AgentSpaces for Ruby: a wire-compatible peer of the AgentSpaces fleet
# (SPEC v0.1.23, wire version 3), the Layer 3 verbs over typed entries, and
# an agent DSL whose classes bind to the next def. See README.md.
module AgentSpaces
  # Forked children drop the connections they inherited (SRAD RB-W-10).
  module ForkHook
    def _fork
      pid = super
      AgentSpaces::Peer.after_fork_in_child! if pid.zero?
      pid
    end
  end
  Process.singleton_class.prepend(ForkHook)
end
