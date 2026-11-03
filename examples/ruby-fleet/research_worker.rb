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

# Example 27: a Ruby worker on example 02's research fleet. Start the Java
# coordinator first, from the root of an AgentSpaces checkout
# (https://github.com/badmonkeyai/agentspaces):
#
#   mvn -q -pl examples/example-02-research-fleet exec:java -Dexec.args="coordinator 7467"
#
# then:
#
#   ruby research_worker.rb 127.0.0.1:7467        (or tls://host:port for a TLS seed)
#
# The coordinator publishes six ResearchTask entries and waits for six
# Finding entries; this worker takes each task under the LEASE_RACE claim
# lattice, writes the finding as its own attested agent, and completes the
# take. The coordinator prints each finding and who wrote it.

$LOAD_PATH.unshift(File.expand_path("../../gems/agentspaces/lib", __dir__))
require_relative "agents/researcher"
$stdout.sync = true

seed = ARGV.fetch(0, "127.0.0.1:7467")
AgentSpaces.serve(group: "research-fleet", founding: "research-fleet-demo-v1", seeds: [seed]) do |peer|
  puts "ruby worker #{peer.identity.peer_id} joined #{peer.group[0, 12]}... through #{seed}"
  peer.bind(Researcher.new, agent: peer.identity.renewing_subordinate("rb-worker", "PT24H"))
end
