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
require "logger"
require "stringio"

module TimingParity
  Task = AgentSpaces::Entry.define("com.acme.TimingTask#v1", topic: String)

  class ShortLeases
    include AgentSpaces::Agent
    agent "short"

    take Task, space: "tasks", lease: "5s"
    def quick(task) = task

    notify Task, space: "tasks", lease: "20s", ttl_override: "a demo that wants fast lapses"
    def heard(_event) = nil
  end

  class Defaults
    include AgentSpaces::Agent
    agent "defaults"

    take Task, space: "tasks"
    def work(task) = task
  end

  class Estimator
    include AgentSpaces::Agent
    agent "estimator"

    on_estimate epochs: "load", settle: "PT40S", tolerance: 0.01
    def settled(_estimate) = nil
  end

  # No rule: 8 s, as Java's @OnEstimate (DRIFT-FROM-PHASE6 item 5).
  class Unruled
    include AgentSpaces::Agent
    agent "unruled"

    attr_reader :fired

    def initialize = @fired = Thread::Queue.new

    on_estimate epochs: "load", tolerance: 0.01
    def settled(estimate) = @fired << estimate.value
  end

  class AtOnce
    include AgentSpaces::Agent
    agent "at-once"

    on_estimate epochs: "load", settle: "0s"
    def settled(_estimate) = nil
  end

  class Both
    include AgentSpaces::Agent
    agent "both"

    on_estimate epochs: "load", settle: "PT8S", ticks: 8
    def settled(_estimate) = nil
  end
end

# Push-sum in rounds of a second with settle spans in time, the TTL floor
# and its 1.5x cycle rule, and the advertisement cache's change signal
# (SPEC v0.1.36 §8, §9.5; srad/agentspaces-event-loop.md EL-T-06, EL-T-16,
# EL-E-03, EL-E-04).
class TimingParityTest < Minitest::Test
  include AgentSpaces
  include AgentSpaces::Capabilities
  include GoldenHelpers

  GROUP = "zRubyTiming"

  def setup
    @peers = []
    @closers = []
    @log = StringIO.new
    @logger = Logger.new(@log)
  end

  def teardown
    @closers.each(&:call)
    @peers.each(&:close)
  end

  def aggregate(peer)
    agg = Aggregate.new(Pipes.new(peer))
    @closers << -> { agg.close }
    agg
  end

  # ------------------------------------------------------------ push-sum

  def test_a_settle_rule_reads_rounds_of_a_second_and_spans_in_time
    assert_in_delta 1.0, Aggregate::ROUND_PERIOD
    assert_equal Settle.after(8, 0.01), Settle.after("PT8S", 0.01)
    assert_equal Settle.after(40, 0.0), Settle.span("40s", 0.0), "example 18's settle of 40 s is 40 rounds"
    assert_equal 3, Settle.span(2.5, 0.0).ticks, "a span rounds up to whole rounds"
    assert_in_delta 40.0, Settle.after(40, 0.0).span_seconds
    assert_raises(ArgumentError) { Settle.span(-1, 0.0) }
    assert_equal [[:key, :interval_seconds]], Aggregate.instance_method(:run).parameters
  end

  def test_an_epoch_heard_and_then_quiet_settles_at_its_last_move_plus_the_span
    time = VirtualTime.new
    a, b = Testing::Network.fleet(GROUP, 2, time: time)
    @peers.push(a, b)
    agg_a = aggregate(a)
    agg_b = aggregate(b)
    agg_a.start("load", 10.0)
    agg_b.start("load", 30.0)
    fired = Thread::Queue.new
    agg_a.on_estimate(->(e) { e == "load" }, Settle.after(3, 0.01)) { |est| fired << est.value }
    agg_b.tick # b pushes to a once: a has heard the epoch
    agg_a.tick
    agg_b.close # b goes quiet, as a quiet Java member stops its rounds
    2.times do
      time.advance(1.0)
      agg_a.tick
    end
    assert_equal 0, fired.size, "two quiet seconds are not the three the rule asks for"
    time.advance(1.0)
    agg_a.tick
    assert eventually(2) { fired.size == 1 }, "quiet for the span: settled with no further frame"
  end

  def test_the_round_thread_runs_while_an_epoch_is_active_and_sleeps_when_all_are_quiet
    time = VirtualTime.new
    lone = Testing::NetPeer.new(Testing::Network.new, GROUP, time: time)
    @peers << lone
    agg = aggregate(lone)
    refute agg.active?, "nothing known, no watch: no rounds"
    agg.start("load", 1.0)
    assert agg.active?
    time.advance(Aggregate::QUIET_AFTER)
    refute agg.active?, "quiet for #{Aggregate::QUIET_AFTER} s"
    closer = agg.on_estimate(->(e) { e == "other" }, Settle::FIRST) { |_| nil }
    assert agg.active?, "a watch that waits keeps the rounds going"
    closer.call
    refute agg.active?
  end

  def test_the_estimate_clause_takes_its_settle_as_a_span
    peer = Testing::NetPeer.new(Testing::Network.new, GROUP)
    @peers << peer
    agg = aggregate(peer)
    Binder.new(peer, aggregate: agg, publish_card: false).bind(TimingParity::Estimator.new)
    settle = agg.instance_variable_get(:@watches).first[:settle]
    assert_equal 40, settle.ticks, "settle: \"PT40S\" waits 40 rounds of a second, as Java's @OnEstimate(settle)"
  end

  def test_an_estimate_clause_with_no_rule_waits_8_s_on_the_peers_time
    time = VirtualTime.new
    a, b = Testing::Network.fleet(GROUP, 2, time: time)
    @peers.push(a, b)
    agg_a = aggregate(a)
    agg_b = aggregate(b)
    agent = TimingParity::Unruled.new
    Binder.new(a, aggregate: agg_a, publish_card: false).bind(agent)
    assert_equal 8, agg_a.instance_variable_get(:@watches).first[:settle].ticks
    agg_a.start("load", 10.0)
    agg_b.start("load", 30.0)
    agg_b.tick
    agg_a.tick
    agg_b.close
    7.times do
      time.advance(1.0)
      agg_a.tick
    end
    assert_equal 0, agent.fired.size, "seven quiet seconds do not settle an unruled estimate"
    time.advance(1.0)
    agg_a.tick
    assert eventually(2) { agent.fired.size == 1 }, "eight do"
  end

  def test_an_estimate_clause_opts_into_the_first_estimate_and_refuses_both_rules
    peer = Testing::NetPeer.new(Testing::Network.new, GROUP)
    @peers << peer
    agg = aggregate(peer)
    Binder.new(peer, aggregate: agg, publish_card: false).bind(TimingParity::AtOnce.new)
    assert_equal 0, agg.instance_variable_get(:@watches).first[:settle].ticks, "settle: \"0s\" fires at once"
    error = assert_raises(ArgumentError) do
      Binder.new(peer, aggregate: agg, publish_card: false).bind(TimingParity::Both.new)
    end
    assert_match(/not both/, error.message)
  end

  # --------------------------------------------------------- the TTL floor

  def test_a_ttl_under_the_floor_warns_once_and_strict_refuses_it
    floor = TtlFloor.new(logger: @logger)
    floor.check("agentspaces.relay.path-ttl", 30_000)
    floor.check("agentspaces.relay.path-ttl", 30_000)
    assert_equal 1, @log.string.scan("path-ttl=30000 ms is under 60 s").size, "warned once per key"
    floor.check("take.lease", 30_000, registered_default: 30_000)
    floor.check("long", 120_000)
    assert_equal [:warned], floor.findings.map(&:verdict), "a registered default and a long TTL pass silently"

    strict = TtlFloor.new(strict: true, overrides: { "agentspaces.session.hello" => "the replay window is the defence" },
                          logger: @logger)
    assert_raises(TtlFloorError) { strict.check("agentspaces.relay.path-ttl", 30_000) }
    strict.check("agentspaces.session.hello", 10_000)
    assert_equal %i[refused overridden], strict.findings.map(&:verdict)
    assert_raises(ArgumentError) { TtlFloor.new(overrides: { "x" => " " }) }
  end

  def test_a_ttl_shorter_than_one_and_a_half_renewal_cycles_warns
    floor = TtlFloor.new(logger: @logger)
    floor.check_cycle("card", 600_000, 300_000)
    assert_empty floor.findings, "twice its cycle is generous"
    floor.check_cycle("card", 600_000, 500_000)
    assert_equal [:warned], floor.findings.map(&:verdict)
    assert_match(/less than 1.5 times its cycle/, @log.string)
  end

  def test_the_binder_checks_every_clause_lease_against_the_floor
    peer = Testing::NetPeer.new(Testing::Network.new, GROUP)
    @peers << peer
    peer.ttl_floor = TtlFloor.new(logger: @logger)
    Binder.new(peer, publish_card: false).bind(TimingParity::Defaults.new).close
    assert_empty peer.ttl_floor.findings, "clause defaults pass"
    Binder.new(peer, publish_card: false).bind(TimingParity::ShortLeases.new).close
    findings = peer.ttl_floor.findings.to_h { |f| [f.key, f.verdict] }
    assert_equal :warned, findings["binder.TimingParity::ShortLeases.quick.lease"]
    assert_equal :overridden, findings["binder.TimingParity::ShortLeases.heard.lease"]

    peer.ttl_floor = TtlFloor.new(strict: true, logger: @logger)
    assert_raises(TtlFloorError) { Binder.new(peer, publish_card: false).bind(TimingParity::ShortLeases.new) }
  end

  def test_the_configuration_names_the_floor_and_checks_its_own_cycles
    config = Config.load({ "agentspaces" => { "groups" => [{ "name" => "g", "founding" => "x" }],
                                              "card-refresh-millis" => 500_000,
                                              "ttl" => { "strict" => true,
                                                         "expert-overrides" => { "binder.X.y.lease" => "why" } } } })
    assert config.ttl_strict
    assert_equal({ "binder.X.y.lease" => "why" }, config.ttl_overrides)
    error = assert_raises(TtlFloorError) { config.ttl_floor(logger: @logger) }
    assert_match(/card-refresh-millis/, error.message)
  end

  def test_a_self_ad_interval_past_its_ttl_margin_warns
    peer = Testing::NetPeer.new(Testing::Network.new, GROUP)
    @peers << peer
    peer.ttl_floor = TtlFloor.new(logger: @logger)
    peer.peer_ad_interval = 300.0
    assert_empty peer.ttl_floor.findings
    peer.peer_ad_interval = 500.0
    assert_equal ["agentspaces.peer-ad-interval-millis"], peer.ttl_floor.findings.map(&:key)
  end

  # ------------------------------------------ the advertisement cache's signal

  def test_the_ads_cache_signals_its_changes_and_names_the_next_card_lapse
    time = VirtualTime.new
    peer = Testing::NetPeer.new(Testing::Network.new, GROUP, time: time)
    @peers << peer
    seen = peer.ads_version
    refute peer.await_ads_change(seen, 0), "no change, no wait"
    now = time.wall_ms
    card = Wire.agent_card(GROUP, peer.identity, "a", Instants.iso(now - (now % 1000)), "PT10M", "", [], [], [], {}, {})
    peer.publish_ad("AgentCard", card)
    assert peer.await_ads_change(seen, 0)
    assert_equal now - (now % 1000) + 600_000, peer.next_card_expiry_ms
  end
end
