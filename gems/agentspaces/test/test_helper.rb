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

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "json"
require "minitest/autorun"
require "agentspaces"
require "agentspaces/testing"

# The vectors the Java codec produced (tools/golden/GoldenVectors.java); a
# vendored copy of agentspaces-spec/golden.json.
GOLDEN = JSON.parse(File.read(File.join(__dir__, "golden.json")))

module GoldenHelpers
  def hex(name) = [GOLDEN.fetch(name)].pack("H*")

  def golden_identity = AgentSpaces::Identity.from_pkcs8(hex("private_key_pkcs8"))

  def golden_agent
    golden_identity.subordinate("python", GOLDEN["certificate_verify_at"], "PT24H",
                                key: AgentSpaces::Identity.from_pkcs8(hex("agent_private_key_pkcs8")))
  end

  def ms(iso) = AgentSpaces::Instants.parse_millis(iso)

  # A peer whose clock is pinned, so golden frames stamped 2025 are judged at their own time.
  def peer_at(iso_or_ms, founder: nil)
    now = iso_or_ms.is_a?(String) ? ms(iso_or_ms) : iso_or_ms
    AgentSpaces::Peer.new(golden_identity, GOLDEN["group_id"], clock: -> { now / 1000.0 }, founder: founder)
  end

  def cbor(value) = AgentSpaces::CBOR.dump(value)

  def load(bytes) = AgentSpaces::CBOR.load(bytes)

  # Waits up to timeout seconds for the block to be truthy.
  def eventually(timeout = 5.0)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    loop do
      value = yield
      return value if value
      return yield if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.025
    end
  end
end
