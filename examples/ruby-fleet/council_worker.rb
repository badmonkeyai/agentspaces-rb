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

# The council worker of the cross-language proof (CouncilCrossLanguageTest
# in the AgentSpaces repository's example 02): a Ruby member of the Java coordinator's council. It joins the research fleet,
# binds an agent that takes the coordinator's tasks and votes on its
# proposal, contributes its load to the push-sum epoch, answers semantic
# queries over the pipe, and serves the remote action its card declares.
# Start the Java side first, from the root of an AgentSpaces checkout:
#
#   mvn -q -pl examples/example-02-research-fleet exec:java \
#       -Dexec.mainClass=ai.badmonkey.agentspaces.examples.fleet.CouncilFleet -Dexec.args="7470 1 20"
#
# then:
#
#   ruby council_worker.rb 127.0.0.1 7470 10 [max-seconds]

$LOAD_PATH.unshift(File.expand_path("../../gems/agentspaces/lib", __dir__))
require_relative "agents/researcher"
$stdout.sync = true

# The council member: research, a ballot, and the decision it records.
class Councillor
  include AgentSpaces::Agent
  agent "rb-researcher", description: "Researches topics in Ruby and sits on the council", goals: %w[research vote]

  class << self
    attr_accessor :completed, :decided
  end
  self.completed = 0

  take ResearchTask, space: "tasks", lease: "30s", poll_timeout: "2s", produces: Finding,
                     description: "Researches one topic in Ruby"
  def research(task)
    self.class.completed += 1
    puts "  [rb] took and completed '#{task.topic}' (#{self.class.completed})"
    Finding.new(topic: task.topic, summary: "researched in ruby: #{task.topic}", worker: "rb-worker")
  end

  ballot space: "votes", prefix: "council:"
  def judge(proposal)
    puts "  [rb] ballot on #{proposal.proposal_id}: yes"
    "yes"
  end

  on_decision space: "votes", prefix: "council:"
  def record(decision)
    self.class.decided = decision
    puts "  [rb] decision #{decision.proposal_id} -> #{decision.winner} #{decision.tally}"
    nil
  end
end

host = ARGV.fetch(0, "127.0.0.1")
port = Integer(ARGV.fetch(1, "7470"))
value = Float(ARGV.fetch(2, "10"))
max_seconds = Float(ARGV.fetch(3, "90"))

identity = AgentSpaces::Identity.generate
peer = AgentSpaces::Peer.new(identity, AgentSpaces::Derive.group_id_from_founding("research-fleet-demo-v1"))
puts "ruby council worker #{identity.peer_id}"
peer.connect(host, port)
sleep 1
peer.pull_ads
pipes = AgentSpaces::Capabilities::Pipes.new(peer)
aggregate = AgentSpaces::Capabilities::Aggregate.new(pipes)
AgentSpaces::Capabilities::Semantic.new(pipes) # answers the coordinator's semantic queries from this cache
bound = peer.bind(Councillor.new, agent: identity.renewing_subordinate("rb-worker", "PT24H"))
aggregate.start("load", value)
aggregate.run(interval_seconds: 0.25)
settled = nil
# One watch for the whole run: a settle streak needs three ticks with new
# frames, and the coordinator pushes about once a second.
aggregate.on_estimate(->(epoch) { epoch == "load" }, AgentSpaces::Capabilities::Settle.after(3, 0.01)) do |estimate|
  settled = estimate.value
  puts format("  [rb] epoch load settled at %.3f", settled)
end
deadline = Time.now + max_seconds
begin
  while Time.now < deadline && peer.connected?
    peer.pull_space("tasks")
    peer.pull_space("votes")
    sleep 0.5
  end
ensure
  bound.close
  aggregate.close
  peer.close
end
puts "ruby council worker done: #{Councillor.completed} tasks, decision " \
     "#{Councillor.decided&.winner || 'none'}, estimate #{settled.inspect}"
exit(Councillor.completed >= 1 && Councillor.decided && settled ? 0 : 1)
