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

require_relative "test_helper"

# The "How to use AI with AgentSpaces" snippets (docs/how-to-use-ai.md), each the body of one
# test here (SRAD RB-O-01): an agent that completes work another peer writes,
# a crashed worker whose task reappears, and a vote two agents decide.
class ReadmeExamplesTest < Minitest::Test
  # README: entries and the agent
  Ticket = AgentSpaces::Entry.define("readme.Ticket#v1", ticket_id: String, text: String, priority: Integer)
  Triage = AgentSpaces::Entry.define("readme.Triage#v1", ticket_id: String, queue: String, by: String)

  class Triager
    include AgentSpaces::Agent
    agent "triager", description: "Routes support tickets to a queue", goals: ["triage"]

    take Ticket, space: "tickets", lease: "30s", where: { priority: 1.. }, produces: Triage
    def route(ticket)
      queue = ticket.text.match?(/refund|charge/i) ? "billing" : "support"
      Triage.new(ticket_id: ticket.ticket_id, queue: queue, by: "triager")
    end
  end
  # README end

  def until_true(timeout = 10)
    deadline = Time.now + timeout
    sleep 0.05 until yield || Time.now > deadline
    yield
  end

  def test_build_an_agent_and_hand_it_work_from_another_peer
    # README: 1
    worker, desk = AgentSpaces::Testing::Network.fleet("zReadme", 2)
    bound = worker.bind(Triager.new, agent: worker.identity.renewing_subordinate("triager", "PT24H"))

    desk.space("tickets") << Ticket.new(ticket_id: "t-1", text: "Refund my last charge", priority: 2)
    triage = desk.space("tickets").read(Triage, timeout: "10s")
    # => #<data Triage ticket_id="t-1", queue="billing", by="triager">
    # README end
    assert_equal "billing", triage.queue
    assert_equal %w[route], bound.card["actions"].map { |a| a["name"] }
  ensure
    bound&.close
    [worker, desk].each { |p| p&.close }
  end

  def test_a_crashed_workers_take_reappears
    # README: 2
    clock = AgentSpaces::Testing::TestClock.new
    crasher, survivor, desk = AgentSpaces::Testing::Network.fleet("zReadmeCrash", 3, clock: clock)
    desk.space("tickets") << Ticket.new(ticket_id: "t-2", text: "Password reset", priority: 1)

    # The first worker takes the ticket and dies before it completes the take.
    taken = crasher.space("tickets").take(Ticket, lease: "5s", timeout: "5s")
    crasher.close

    # Nobody else can take it while the lease holds; once it lapses, the entry reappears.
    assert_nil survivor.space("tickets").take(Ticket, lease: "5s", timeout: 1)
    clock.advance(6_000)
    retaken = survivor.space("tickets").take(Ticket, lease: "30s", timeout: "5s")
    retaken.complete(Triage.new(ticket_id: retaken.value.ticket_id, queue: "support", by: "survivor"))
    # README end
    assert_equal "t-2", taken.value.ticket_id
    assert_equal taken.entry_id, retaken.entry_id
    assert until_true { desk.space("tickets").all(Triage).map(&:by) == ["survivor"] }
  ensure
    [crasher, survivor, desk].each { |p| p&.close }
  end

  # README: 3
  class Reviewer
    include AgentSpaces::Agent
    agent "reviewer", description: "Votes on releases"

    def initialize(answer) = @answer = answer

    ballot space: "votes", prefix: "release:"
    def judge(proposal) = proposal.question.include?("0.5.0") ? @answer : nil
  end
  # README end

  def test_two_agents_decide_a_vote
    # README: 3 continued
    a, b, chair = AgentSpaces::Testing::Network.fleet("zReadmeVote", 3)
    bound = [a.bind(Reviewer.new("ship")), b.bind(Reviewer.new("ship"))]
    AgentSpaces::Votes.propose(chair, "votes", "release:0.5.0", "Ship 0.5.0?", %w[ship hold], 2)

    decision = until_true { AgentSpaces::Votes.decision(chair.states, "release:0.5.0") }
    # => {"proposalId" => "release:0.5.0", "winner" => "ship", "tally" => {"ship" => 2, "hold" => 0}}
    # README end
    assert_equal "ship", decision["winner"]
    assert_equal({ "ship" => 2, "hold" => 0 }, decision["tally"])
  ensure
    bound&.each(&:close)
    [a, b, chair].each { |p| p&.close }
  end
end
