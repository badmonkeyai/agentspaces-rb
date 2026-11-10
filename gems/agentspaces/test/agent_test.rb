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
require_relative "space_test"

# The agent DSL (definition-time checks, the clause model) and the Ruby
# binder over two in-memory peers: every verb and return convention.
class AgentTest < Minitest::Test
  include GoldenHelpers
  include AgentSpaces

  class Researcher
    include AgentSpaces::Agent
    agent "researcher", description: "Researches topics", goals: ["research"]

    attr_reader :seen, :audited

    def initialize
      @seen = []
      @audited = []
    end

    take Shop::Task, space: "tasks", lease: "1m", poll_timeout: "500ms", where: { priority: 1.. },
                     pre: ["topic.open"], post: ["topic.researched"], cost: "low", produces: Shop::Finding
    def research(task)
      @seen << task.topic
      raise "no take context" if AgentSpaces::TakeContext.current.nil?

      Shop::Finding.new(topic: task.topic, summary: "researched #{task.topic}")
    end

    notify Shop::Finding, space: "tasks"
    def audit(finding) = (@audited << finding.summary) && nil

    bid(Shop::Task, space: "tasks") { |task| task.priority > 3 ? 1.0 : 10.0 }
  end

  class Panelist
    include AgentSpaces::Agent
    agent "panelist", description: "Votes", goals: ["decide"]
    attr_reader :decided

    def initialize = @decided = []

    ballot space: "votes", prefix: "rel:"
    def judge(proposal) = proposal.question.include?("ship") ? "yes" : nil

    on_decision space: "votes", prefix: "rel:", result_space: "ledger", produces: Shop::Verdict
    def record(decision)
      @decided << decision.proposal_id
      Shop::Verdict.new(proposal_id: decision.proposal_id, winner: decision.winner)
    end
  end

  def setup
    @peer, @other = Testing::Network.fleet("zRubyAgents", 2)
  end

  def teardown
    [@peer, @other].each(&:close)
  end

  def test_the_clause_model_records_each_macro_against_its_def
    model = Researcher.agentspaces_model
    assert_equal "researcher", model.name
    assert_equal %i[take notify bid], model.clauses.map(&:verb)
    assert_equal %i[research audit bid_2], model.clauses.map(&:method_name)
    take = model.clauses.first
    assert_equal Shop::Task, take.cue
    assert_equal "1m", take.options[:lease]
    assert_equal [Shop::Finding], take.produces
    assert_equal __FILE__, take.location.path
  end

  def test_definition_errors_name_the_location_the_value_and_the_accepted_values
    error = assert_raises(DefinitionError) do
      Class.new do
        include AgentSpaces::Agent
        take Shop::Task, space: "tasks", lese: "1m"
      end
    end
    assert_match(/agent_test.rb:\d+: take has no option :lese; accepted: space, group, lease/, error.message)
    error = assert_raises(DefinitionError) do
      Class.new do
        include AgentSpaces::Agent
        take Shop::Task, space: "tasks", lease: "30 seconds"
      end
    end
    assert_match(/lease "30 seconds" is not a duration; accepted forms: "250ms"/, error.message)
    error = assert_raises(DefinitionError) do
      Class.new do
        include AgentSpaces::Agent
        take Shop::Task, space: "tasks", where: { priorty: 1 }
      end
    end
    assert_match(/no field priorty; fields are topic, priority/, error.message)
    assert_raises(DefinitionError) { Class.new { include AgentSpaces::Agent; take(Shop::Task, lease: "1m") { nil } } }
    assert_raises(DefinitionError) { Class.new { include AgentSpaces::Agent; take(String, space: "x") { nil } } }
    assert_raises(DefinitionError) { Class.new { include AgentSpaces::Agent; notify(Shop::Task, space: "x", on: "GONE") { nil } } }
    assert_raises(DefinitionError) { Class.new { include AgentSpaces::Agent; join(space: "x", key: "k", parts: [], mode: "local") { nil } } }
    error = assert_raises(DefinitionError) { Class.new { include AgentSpaces::Agent; take(Shop::Task, space: "x", pre: "ready") { nil } } }
    assert_match(/pre "ready" is not a list of at most 32 texts/, error.message)
    assert_raises(DefinitionError) { Class.new { include AgentSpaces::Agent; take(Shop::Task, space: "x", post: %w[a] * 33) { nil } } }
    error = assert_raises(DefinitionError) { Class.new { include AgentSpaces::Agent; take(Shop::Task, space: "x", cost: "x" * 65) { nil } } }
    assert_match(/cost is a text of at most 64 characters/, error.message)
    dangling = Class.new do
      include AgentSpaces::Agent
      take Shop::Task, space: "tasks"
    end
    error = assert_raises(DefinitionError) { dangling.agentspaces_model }
    assert_match(/take has no following def/, error.message)
  end

  def test_an_agent_takes_notifies_bids_and_publishes_its_card
    researcher = Researcher.new
    bound = @peer.bind(researcher, agent: @peer.identity.renewing_subordinate("rb-worker", "PT24H"))
    card = bound.card
    assert card["agent"].end_with?("/rb-worker")
    assert_equal "Researches topics", card["description"]
    assert_equal ["research"], card["goals"]
    assert_equal ["com.acme.Finding#v1", "com.acme.Task#v1"], card["consumes"].sort
    assert_equal ["com.acme.Finding#v1"], card["produces"]
    assert_equal({ "com.acme.Task#v1" => "tasks" }, card["spaceBindings"])
    assert_equal %w[audit research], card["actions"].map { |a| a["name"] }
    assert_nil card["actions"].first["contract"], "an action with no pre, post, or cost carries no contract"
    assert_equal({ "pre" => ["topic.open"], "post" => ["topic.researched"], "cost" => "low", "methods" => [] },
                 card["actions"].last["contract"])
    refute_nil card["agentCertificate"]
    # The certificate covers the card's issue instant, or Java's discovery refuses the card.
    assert AgentSpaces::Certificates.covers?(card["agentCertificate"], AgentSpaces::Instants.parse_millis(card["issued"]))
    assert_equal 1, eventually { @other.cards.size }
    @other.space("tasks") << Shop::Task.new(topic: "crdts", priority: 5)
    assert eventually(10) { researcher.audited == ["researched crdts"] }
    assert_equal ["crdts"], researcher.seen
    assert_equal ["researched crdts"], @peer.space("tasks").all(Shop::Finding).map(&:summary)
    assert_equal 1.0, @peer.claims.values.first["claim"]["bid"]
    done = eventually(10) { @peer.states.values.find { |dto| dto["completed"] } }
    assert done["signer"].end_with?("/rb-worker")
  ensure
    bound&.close
  end

  def test_a_ballot_casts_once_per_proposal_and_a_decision_fires_once_at_quorum
    panelist = Panelist.new
    bound = Binder.new(@peer, publish_card: false).bind(panelist)
    Votes.propose(@other, "votes", "rel:1", "ship 1.0?", %w[yes no], 2)
    Votes.propose(@other, "votes", "ops:2", "ship?", %w[yes no], 1)
    assert eventually { Votes.tally(@peer.states, "rel:1")["yes"] == 1 }
    assert_empty Votes.ballots(@peer.states, "ops:2")
    assert_nil Votes.decision(@peer.states, "rel:1")
    Votes.cast(@other, "votes", "rel:1", "no")
    assert eventually { panelist.decided == ["rel:1"] }
    decided = Votes.decision(@peer.states, "rel:1")
    assert_equal "no", decided["winner"]
    assert_equal({ "yes" => 1, "no" => 1 }, decided["tally"])
    assert_equal "no", eventually { @peer.space("ledger").all(Shop::Verdict).first }.winner
    @peer.states.values.each { |dto| @peer.fold_state(dto.dup) }
    sleep 0.3
    assert_equal ["rel:1"], panelist.decided
  ensure
    bound&.close
  end

  class Dispatcher
    include AgentSpaces::Agent
    agent "dispatcher"

    take Shop::Task, space: "tasks", poll_timeout: "300ms", produces: [Shop::Finding, Shop::Verdict]
    def dispatch(task)
      case task.topic
      when "tagged" then AgentSpaces::Tagged.of(Shop::Finding.new(topic: "tagged", summary: "t"), region: "eu")
      when "fork" then [Shop::Finding.new(topic: "f1", summary: "a"), Shop::Finding.new(topic: "f2", summary: "b")]
      when "motion" then AgentSpaces::Motion.new(proposal_id: "m-1", question: "ship?", options: %w[yes no], quorum: 1,
                                    space: "votes")
      end
    end
  end

  def test_tagged_fork_motion_and_nil_returns_dispatch_as_java_does
    bound = @peer.bind(Dispatcher.new, publish_card: false)
    tasks = @other.space("tasks")
    %w[tagged fork motion nothing].each { |t| tasks << Shop::Task.new(topic: t, priority: 1) }
    assert eventually(10) { @other.space("tasks").entries(Shop::Finding, tags: { region: "eu" }).size == 1 }
    assert eventually(10) { (@other.space("tasks").all(Shop::Finding).map(&:topic) & %w[f1 f2]).size == 2 }
    assert eventually(10) { Votes.proposals(@other.states).key?("m-1") }
    assert eventually(10) { @other.states.values.count { |d| d["completed"] } == 4 }
  ensure
    bound&.close
  end

  Order = AgentSpaces::Entry.define("com.acme.Order#v1", order_id: String, item: String)
  Payment = AgentSpaces::Entry.define("com.acme.Payment#v1", order_id: String, amount: Float)
  Release = AgentSpaces::Entry.define("com.acme.Release#v1", order_id: String)

  class Joiner
    include AgentSpaces::Agent
    attr_reader :fired

    def initialize = @fired = []

    join space: "orders", key: "order_id", parts: [AgentSpaces::Part.new(type: Order), AgentSpaces::Part.new(type: Payment)],
         produces: Release
    def release(joined)
      @fired << joined.key
      Release.new(order_id: joined.key) if joined.get(Payment).amount.positive?
    end

    propose Order, space: "orders", vote: "votes", options: %w[ship hold], quorum: 1, prefix: "order:",
                   key: "order_id"
    def ask(order) = "ship #{order.item}?"
  end

  def test_a_local_join_fires_once_per_key_and_a_propose_opens_one_vote_per_key
    joiner = Joiner.new
    bound = @peer.bind(joiner, publish_card: false)
    orders = @other.space("orders")
    orders << Order.new(order_id: "o-1", item: "kite")
    orders << Order.new(order_id: "o-1", item: "kite again")
    sleep 0.3
    assert_empty joiner.fired
    orders << Payment.new(order_id: "o-1", amount: 4)
    assert eventually { joiner.fired == ["o-1"] }
    assert_equal "o-1", eventually { @other.space("orders").all(Release).first }.order_id
    assert eventually { Votes.proposals(@other.states).keys == ["order:o-1"] }
    assert_equal "ship kite?", Votes.proposals(@other.states)["order:o-1"]["question"]
  ensure
    bound&.close
  end

  class Ordered
    include AgentSpaces::Agent

    ordered_take Shop::Task, space: "tasks"
    def run(task) = task
  end

  def test_an_ordered_verb_refuses_the_wire_engine_naming_the_jruby_face
    error = assert_raises(EngineUnsupported) { @peer.bind(Ordered.new) }
    assert_match(/runs on the Java binder; bind this agent with the JRuby face/, error.message)
  end

  def test_a_raising_body_lapses_the_take_and_counts_the_failure
    crasher = AgentSpaces.agent("crasher") do
      take(Shop::Task, space: "tasks", lease: "1m", poll_timeout: "300ms") { |_task| raise "boom" }
    end
    bound = @peer.bind(crasher, publish_card: false)
    @other.space("tasks") << Shop::Task.new(topic: "x", priority: 1)
    assert eventually { bound.failures >= 1 }
    entry_id = @peer.states.keys.first
    refute @peer.states[entry_id]["completed"]
  ensure
    bound&.close
  end
end
