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
require "agentspaces/capabilities"

module L4
  Task = AgentSpaces::Entry.define("com.acme.L4Task#v1", topic: String, priority: Integer)
  Finding = AgentSpaces::Entry.define("com.acme.L4Finding#v1", topic: String, summary: String)
  Report = AgentSpaces::Entry.define("com.acme.L4Report#v1", epoch: String, value: Float)

  class Researcher
    include AgentSpaces::Agent
    agent "researcher", description: "Researches topics and writes findings", goals: %w[research summarize]

    take Task, space: "tasks", lease: "30s", poll_timeout: "300ms", description: "Researches one topic",
               produces: Finding
    def research(task) = Finding.new(topic: task.topic, summary: "researched #{task.topic}")
  end

  class Supervisor
    include AgentSpaces::Agent
    agent "supervisor"
    attr_reader :reports

    def initialize = @reports = []

    on_estimate epochs: "load", ticks: 2, tolerance: 0.01, result_space: "reports"
    def settled(estimate)
      @reports << estimate
      Report.new(epoch: estimate.epoch_id, value: estimate.value)
    end
  end
end

# Layer 4 from Ruby without a socket (L3L4-COVERAGE.md 6.4), the port of the
# Python client's test_layer4.py: the capability pipes between peers on an
# in-memory network, push-sum and rosters, the frames pinned by the golden
# aggregate vectors, the hashing embedder matching Java, semantic queries
# local and remote, remote actions through a bound agent, and the estimate
# clause.
class CapabilitiesTest < Minitest::Test
  include GoldenHelpers
  include AgentSpaces
  include AgentSpaces::Capabilities

  GROUP = "zRubyLayer4"

  def setup
    @network = Testing::Network.new
    @peers = []
    @closers = []
  end

  def teardown
    @closers.each(&:call)
    @peers.each(&:close)
  end

  # n peers of one network that have introduced themselves to each other.
  def fleet(count = 2)
    added = Array.new(count) { Testing::NetPeer.new(@network, GROUP) }
    added.each(&:introduce)
    @peers.concat(added)
    added
  end

  def aggregate(peer, **options)
    agg = Aggregate.new(Pipes.new(peer), **options)
    @closers << -> { agg.close }
    agg
  end

  # ------------------------------------------------------------- aggregate

  def test_push_sum_converges_to_the_fleet_mean_and_rosters_count_members
    a, b = fleet
    assert_equal [b.identity.peer_id], a.members.keys
    assert_equal [a.identity.peer_id], b.members.keys
    agg_a = aggregate(a)
    agg_b = aggregate(b)
    agg_a.start("load", 10.0)
    agg_b.start("load", 30.0)
    agg_a.start("n", 0.0, "count")
    agg_b.start("n", 0.0, "count")
    agg_a.start("peak", 10.0, "max")
    agg_b.start("peak", 30.0, "max")
    agg_a.start("total", 10, "sum")
    agg_b.start("total", 30, "sum")
    assert_nil agg_a.estimate("load"), "nothing exchanged yet"
    12.times do
      agg_a.tick
      agg_b.tick
    end
    assert_in_delta 20.0, agg_a.estimate("load"), 0.01
    assert_in_delta 20.0, agg_b.estimate("load"), 0.01
    assert_equal 2.0, agg_a.estimate("n")
    assert_equal 2.0, agg_b.estimate("n")
    assert_equal 30.0, agg_a.estimate("peak")
    assert_equal 30.0, agg_b.estimate("peak")
    assert_in_delta 40.0, agg_a.estimate("total"), 0.05
    assert_kind_of Float, agg_a.estimate("n")
    assert_equal Set["load", "n", "peak", "total"], agg_a.epochs
    assert_raises(ArgumentError) { agg_a.start("x", 1.0, "median") }
  end

  def test_the_aggregate_pushes_the_java_frame_union_byte_for_byte
    golden = Testing::NetPeer.new(@network, GROUP, identity: golden_identity)
    sink = Testing::NetPeer.new(@network, GROUP)
    @peers.push(golden, sink)
    [golden, sink].each(&:introduce)
    aggregate(sink, advertise: true)
    frames = []
    sink.pipe_handlers[Aggregate::TYPE] = ->(_from, payload) { frames << payload }
    # A value of 9.0 at weight 1.0 halves to the golden share (4.5, 0.5).
    share = aggregate(golden)
    share.start("golden", 9.0)
    share.tick
    assert_equal [hex("aggregate_share_frame_cbor")], frames
    frames.clear
    extremum = aggregate(golden)
    extremum.start("golden", 4.5, "max")
    extremum.tick
    assert_equal [hex("aggregate_extremum_frame_cbor")], frames
    frames.clear
    roster = aggregate(golden)
    assert_equal Integer(GOLDEN["aggregate_roster_token"]), roster.self_token
    roster.start("golden", 0.0, "count")
    roster.tick
    assert_equal [hex("aggregate_roster_frame_cbor")], frames
    # The advertisement names the capability in Java field order.
    ad = roster.describe
    assert_equal %w[id issuer group issued ttl capabilityType version binding parameters costHints], ad.keys
    assert_equal({ "modes" => "sum,avg,count,min,max" }, ad["parameters"])
  end

  def test_await_settled_and_on_estimate_fire_on_the_tick
    a, b = fleet
    agg_a = aggregate(a)
    agg_b = aggregate(b)
    agg_a.start("load", 10.0)
    agg_b.start("load", 30.0)
    fired = Thread::Queue.new
    closer = agg_a.on_estimate(->(e) { e == "load" }, Settle.after(2, 0.01)) { |est| fired << est }
    agg_a.run(interval_seconds: 0.05)
    agg_b.run(interval_seconds: 0.05)
    settled = agg_a.await_settled("load", Settle.after(2, 0.01), timeout_seconds: 10)
    refute_nil settled
    assert_in_delta 20.0, settled, 0.5
    assert eventually { fired.size == 1 }
    sleep 0.3
    assert_equal 1, fired.size
    estimate = fired.pop
    assert_equal "load", estimate.epoch_id
    assert_equal "avg", estimate.mode
    assert_operator estimate.ticks, :>=, 3
    assert_nil agg_a.await_settled("missing", Settle::FIRST, timeout_seconds: 0.3)
  ensure
    closer&.call
  end

  def test_settle_rules_refuse_negative_values_and_judge_relative_change
    assert_raises(ArgumentError) { Settle.after(-1, 0.0) }
    assert_raises(ArgumentError) { Settle.after(1, -0.1) }
    rule = Settle.after(2, 0.01)
    refute rule.stable?(nil, 1.0)
    assert rule.stable?(100.0, 100.5)
    refute rule.stable?(100.0, 102.0)
    assert_equal Settle.new(ticks: 0, tolerance: 0.0), Settle::FIRST
  end

  # -------------------------------------------------------------- semantic

  def test_the_hashing_embedder_matches_java
    assert_equal 99_162_322, HashingEmbedder.java_hash("hello")
    assert_equal 0, HashingEmbedder.java_hash("")
    assert_equal(-2_147_483_648, HashingEmbedder.java_hash("polygenelubricants"), "the int32 wrap")
    e = HashingEmbedder.new
    v = e.embed("Researches topics research com.acme.Task#v1")
    assert_equal 256, v.size
    assert_in_delta 1.0, v.sum { |x| x * x }, 1e-9
    assert_equal [0.0] * 256, e.embed(nil)
    # "hello" hashes to 99162322: bucket floorMod(99162322, 256), positive sign.
    assert_equal 1.0, e.embed("hello")[99_162_322 % 256]
    # A negative hash lands in its floorMod bucket with a negative sign.
    h = HashingEmbedder.java_hash("polygenelubricants")
    assert_equal(-1.0, e.embed("polygenelubricants")[h % 256])
    assert_raises(ArgumentError) { HashingEmbedder.new(0) }
  end

  def test_semantic_queries_rank_cards_locally_and_fetch_them_remotely
    a, b = fleet
    sem_a = Semantic.new(Pipes.new(a))
    sem_b = Semantic.new(Pipes.new(b))
    bound = Binder.new(a).bind(L4::Researcher.new)
    # A's card is in A's cache and reached B on the ads stream.
    assert_equal [bound.card["agent"]], sem_a.query("research topics findings").map { |m| m.ad["agent"] }
    assert_operator sem_b.query("research topics").first.score, :>, 0.2
    assert_empty sem_a.query("quantum chromodynamics")
    # A newcomer with an empty cache learns the card through the query pipe.
    c = Testing::NetPeer.new(@network, GROUP)
    @peers << c
    c.introduce
    a.introduce # the group's members reach the newcomer on the peers stream
    b.introduce
    sem_c = Semantic.new(Pipes.new(c))
    assert_empty sem_c.query("research topics")
    hits = sem_c.remote_query("research topics", limit: 5, timeout_seconds: 2)
    assert_equal [bound.card["agent"]], hits.map { |m| m.ad["agent"] }
    assert_equal bound.card["id"], c.cards.first["id"]
    assert_raises(ArgumentError) { sem_c.query("x", limit: 0) }
  ensure
    bound&.close
  end

  def test_text_of_indexes_each_advertisement_kind_as_java_does
    card = { "description" => "d", "goals" => %w[g1 g2], "consumes" => ["c"], "produces" => ["p"],
             "actions" => [{ "name" => "n", "description" => "nd" }] }
    assert_equal "d g1 g2 c p n nd", Semantic.text_of("AgentCard", card)
    assert_equal "d a u s", Semantic.text_of("AssetCard", { "description" => "d", "asset" => "a", "uri" => "u",
                                                             "shape" => "s" })
    assert_equal "aspace:cap/aggregate pipe {modes=sum,avg}",
                 Semantic.text_of("CapabilityAdvertisement", { "capabilityType" => "aspace:cap/aggregate",
                                                               "binding" => "pipe",
                                                               "parameters" => { "modes" => "sum,avg" } })
    assert_equal "jobs a b", Semantic.text_of("SpaceAdvertisement", { "spaceName" => "jobs",
                                                                       "schemaHints" => %w[a b] })
    assert_equal "aspace://x", Semantic.text_of("Other", { "id" => "aspace://x" })
  end

  # ---------------------------------------------------------------- remote

  def test_a_remote_action_from_a_card_is_invoked_through_the_task_space
    a, b = fleet
    bound = Binder.new(a).bind(L4::Researcher.new)
    found = RemoteActions.actions(b)
    assert_equal [["research", "com.acme.L4Task#v1", "com.acme.L4Finding#v1", "tasks"]],
                 found.map { |x| [x.name, x.consumes, x.produces, x.space] }
    assert_equal "Researches one topic", found.first.description
    assert_equal bound.card["agent"], found.first.agent
    result = RemoteActions.invoke(b, found.first, L4::Task.new(topic: "crdts", priority: 2),
                                  result_type: L4::Finding, timeout_seconds: 15)
    assert_equal L4::Finding.new(topic: "crdts", summary: "researched crdts"), result
    # The result correlated on the shared field: a second call with another topic gets its own.
    assert_equal L4::Finding.new(topic: "raft", summary: "researched raft"),
                 RemoteActions.invoke(b, found.first, L4::Task.new(topic: "raft", priority: 1),
                                      result_type: L4::Finding, timeout_seconds: 15)
  ensure
    bound&.close
  end

  def test_a_card_without_declared_actions_yields_its_bound_pairs
    a, b = fleet
    now = a.now_ms
    card = Wire.agent_card(GROUP, a.identity, "legacy", Instants.iso(now - (now % 1000)), "PT10M", "Old style",
                           [], ["com.acme.In#v1"], ["com.acme.Out#v1"], {}, { "com.acme.In#v1" => "inbox" })
    a.publish_ad("AgentCard", card)
    found = RemoteActions.actions(b)
    assert_equal [["legacy_com.acme.In#v1", "com.acme.In#v1", "com.acme.Out#v1", "inbox", "Old style"]],
                 found.map { |x| [x.name, x.consumes, x.produces, x.space, x.description] }
    assert RemoteActions.shared_fields?({ "topic" => "x", "n" => 1 }, { "topic" => "x", "other" => 2 })
    refute RemoteActions.shared_fields?({ "topic" => "x" }, { "topic" => "y" })
  end

  # ------------------------------------------------------- the estimate clause

  def test_the_estimate_clause_reacts_once_when_the_epoch_settles
    a, b = fleet
    agg_a = aggregate(a)
    agg_b = aggregate(b)
    supervisor = L4::Supervisor.new
    bound = Binder.new(a, publish_card: false, aggregate: agg_a).bind(supervisor)
    agg_a.start("load", 10.0)
    agg_b.start("load", 30.0)
    agg_a.run(interval_seconds: 0.05)
    agg_b.run(interval_seconds: 0.05)
    report = eventually(10) { b.space("reports").all(L4::Report).first }
    refute_nil report
    assert_equal "load", report.epoch
    assert_in_delta 20.0, report.value, 0.5
    sleep 0.3
    assert_equal 1, supervisor.reports.size
  ensure
    bound&.close
  end

  # -------------------------------------------------- hardening (2026-10-09)

  def test_shares_go_only_to_members_that_advertise_the_aggregate
    a, b = fleet
    bystander = Testing::NetPeer.new(@network, GROUP) # a member with no aggregate
    @peers << bystander
    bystander.introduce
    a.introduce
    b.introduce
    agg_a = aggregate(a)
    agg_b = aggregate(b)
    assert_equal [b.identity.peer_id], agg_a.participants.sort
    assert_includes Pipes.new(a).members, bystander.identity.peer_id
    agg_a.start("load", 10.0)
    agg_b.start("load", 30.0)
    40.times do
      agg_a.tick
      agg_b.tick
    end
    assert_in_delta 20.0, agg_a.estimate("load"), 0.01
    assert_in_delta 20.0, agg_b.estimate("load"), 0.01
    refute_includes aggregate(bystander, advertise: false).epochs, "load"
  end

  def test_a_node_nobody_pushes_to_does_not_settle_and_a_lone_node_does
    a, b, c = fleet(3)
    agg_a = aggregate(a)
    agg_b = aggregate(b)
    agg_c = aggregate(c)
    # A pushes to B, B and C push to each other: nobody ever pushes to A.
    b_id = b.identity.peer_id
    c_id = c.identity.peer_id
    agg_a.define_singleton_method(:participants) { [b_id] }
    agg_b.define_singleton_method(:participants) { [c_id] }
    agg_c.define_singleton_method(:participants) { [b_id] }
    agg_a.start("load", 10.0)
    agg_b.start("load", 30.0)
    agg_c.start("load", 20.0)
    fired_a = Thread::Queue.new
    fired_b = Thread::Queue.new
    agg_a.on_estimate(->(e) { e == "load" }, Settle.after(2, 0.01)) { |est| fired_a << est.value }
    agg_b.on_estimate(->(e) { e == "load" }, Settle.after(2, 0.01)) { |est| fired_b << est.value }
    30.times do
      agg_a.tick
      agg_b.tick
      agg_c.tick
    end
    assert_equal 10.0, agg_a.estimate("load"), "the hazard: stable by construction, far from the fleet"
    assert eventually(2) { fired_b.size == 1 }
    assert_equal 0, fired_a.size
    # A node with nobody to exchange with settles on its own ticks.
    lone = Testing::NetPeer.new(Testing::Network.new, GROUP)
    @peers << lone
    agg = aggregate(lone)
    agg.start("load", 12.5)
    fired = Thread::Queue.new
    agg.on_estimate(->(e) { e == "load" }, Settle.after(2, 0.01)) { |est| fired << est.value }
    5.times { agg.tick }
    assert eventually(2) { fired.size == 1 }
    assert_equal 12.5, fired.pop
  end

  def test_a_malformed_or_hostile_frame_changes_nothing
    a, b = fleet
    agg_b = aggregate(b)
    agg_a = aggregate(a)
    agg_a.start("load", 10.0)
    pipes = Pipes.new(b)
    pipes.send_pipe(a.identity.peer_id, Aggregate::TYPE, "\xFF".b)
    pipes.send_pipe(a.identity.peer_id, Aggregate::TYPE, CBOR.dump([1, 2]))
    pipes.send_pipe(a.identity.peer_id, Aggregate::TYPE,
                    CBOR.dump(Wire.aggregate_frame(share: { "epochId" => "load", "value" => Float::NAN,
                                                            "weight" => 1.0 })))
    pipes.send_pipe(a.identity.peer_id, Aggregate::TYPE,
                    CBOR.dump(Wire.aggregate_frame(share: { "epochId" => "load", "value" => 1.0, "weight" => -1.0 })))
    pipes.send_pipe(a.identity.peer_id, Aggregate::TYPE,
                    CBOR.dump(Wire.aggregate_frame(share: { "epochId" => "load", "value" => "x", "weight" => 1.0 })))
    assert_equal 10.0, agg_a.estimate("load")
    refute_nil agg_b
  end
end
