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

module HeldTake
  Job = AgentSpaces::Entry.define("com.acme.HeldJob#v1", topic: String)
  Outcome = AgentSpaces::Entry.define("com.acme.HeldOutcome#v1", topic: String)

  # Renews its take through the context before and after the test releases it.
  class Renewer
    include AgentSpaces::Agent
    agent "renewer"

    attr_reader :started, :go, :answers

    def initialize
      @started = Thread::Queue.new
      @go = Thread::Queue.new
      @answers = Thread::Queue.new
    end

    take Job, space: "tasks", lease: "1m", poll_timeout: "500ms"
    def work(_job)
      @started << renew_once
      @go.pop
      @answers << renew_once
      nil
    end

    def renew_once
      AgentSpaces::TakeContext.current.renew
      :renewed
    rescue ArgumentError => e
      e.message
    end
  end
end

# C05 (owner decision 2026-11-23): the hold stays judged on the wall-time
# lease, and every wake or wall step re-checks the takes held here at once;
# a lapsed one stops renewing and its result is late. And item 11 of
# DRIFT-FROM-PHASE6 as it applies to Ruby: the renewals a handler makes
# through its take end once its agent is unbound, or its holder revoked.
# Virtual time; nothing waits out a lease.
class HeldTakeTest < Minitest::Test
  include AgentSpaces

  GROUP = "zRubyHeldTake"

  def setup
    @time = VirtualTime.new
    @writer, @reader = Testing::Network.fleet(GROUP, 2, time: @time)
    @spaces = [@writer, @reader].to_h { |peer| [peer, peer.space("tasks")] }
    @id = @spaces[@writer].write(HeldTake::Job.new(topic: "held"), lease: "10m")
  end

  def teardown
    @bound&.close(timeout: 1)
    [@writer, @reader].each(&:close)
  end

  def take(lease = "1m") = @spaces[@reader].take(HeldTake::Job, lease: lease, timeout: "2s")

  def outcomes = @spaces[@writer].entries(HeldTake::Outcome)

  def test_a_wake_past_the_lease_stops_the_renewals_and_makes_the_result_late
    taken = take
    lapses = []
    taken.on_lapse { lapses << :lapsed }
    @reader.run_due # the loop's first turn
    @time.suspend(120) # Linux: the wall moved two minutes, the monotonic clock did not
    @reader.run_due
    assert taken.lapsed?, "the wake judged the 1 min lease at once"
    assert_equal [:lapsed], lapses, "and told its keepalive"
    assert_equal 1, @reader.held_takes_lapsed
    assert_equal 1, @reader.loop_stats[:held_takes_lapsed]
    error = assert_raises(ArgumentError) { taken.renew }
    assert_match(/not renewed/, error.message)
    error = assert_raises(ArgumentError) { taken.complete(HeldTake::Outcome.new(topic: "late")) }
    assert_match(/late/, error.message)
    assert_empty outcomes, "no result was written"
  end

  def test_a_late_loop_wake_rechecks_too
    taken = take
    @reader.run_due
    @time.advance(90) # macOS counts the sleep on both clocks: the loop just wakes late
    @reader.run_due
    assert taken.lapsed?
  end

  def test_a_step_within_the_lease_keeps_the_take
    taken = take
    @reader.run_due
    @time.suspend(20)
    @reader.run_due
    assert_equal 1, @reader.wall_steps, "a wall step was judged"
    refute taken.lapsed?
    assert_equal 0, @reader.held_takes_lapsed
    refute_nil taken.renew, "a take still live renews"
    refute_nil taken.complete(HeldTake::Outcome.new(topic: "in time"))
  end

  # C05, the live half (cross-client review): the wake tells a take still
  # held, so a keepalive renews it at once; a lapsed one is not told.
  def test_a_wake_tells_a_take_still_held_and_not_a_lapsed_one
    live = take("10m")
    wakes = []
    live.on_wake { wakes << :live }
    @reader.run_due
    @time.suspend(20)
    @reader.run_due
    assert_equal [:live], wakes, "the step inside the lease told the take"
    @time.suspend(1200)
    @reader.run_due
    assert live.lapsed?
    assert_equal [:live], wakes, "a lapsed take is not told to renew"
  end

  # ----------------------------------- C05's lapse, owner decision 2 of 2026-11-23

  # A better claim of the writer's on the entry, at the take's epoch and
  # stamped before the take's own: the lattice keeps it over the take's.
  def displace(taken)
    own = @reader.claim_of(taken.entry_id)
    holder = @writer.identity.agent("rival")
    stamp = Wire.hlc_now(holder, Wire.hlc_physical(own["stamp"]) - 5)
    better = Wire.signed_claim(Wire.take_claim(taken.entry_id, own["spaceId"], own["epoch"], stamp, holder, 0.0,
                                               @time.wall_ms + 60_000), @writer.identity)
    @reader.fold_claim(taken.entry_id, better)
    refute_equal taken.holder, @reader.claim_of(taken.entry_id)["holder"], "the better claim is held here now"
  end

  def test_a_take_whose_claim_is_no_longer_ours_lapses_at_the_next_wake
    taken = take("10m")
    lapses = []
    taken.on_lapse { lapses << :lapsed }
    @reader.run_due
    displace(taken)
    @time.suspend(20) # a wake well inside the take's own 10 min lease
    @reader.run_due
    assert taken.lapsed?, "a claim no longer ours is a lapse, whatever the lease"
    assert_equal [:lapsed], lapses
    assert_equal 1, @reader.held_takes_lapsed
    error = assert_raises(ArgumentError) { taken.renew }
    assert_match(/not renewed/, error.message)
    error = assert_raises(ArgumentError) { taken.complete(HeldTake::Outcome.new(topic: "late")) }
    assert_match(/late/, error.message)
    assert_empty outcomes, "the result completed nothing"
    assert_equal 1, @reader.late_takes
    assert_equal 1, @reader.loop_stats[:late_takes]
  end

  def test_a_result_after_the_claim_moved_is_late_and_counted_once_with_no_wake
    taken = take("10m")
    displace(taken)
    2.times do
      error = assert_raises(ArgumentError) { taken.complete(HeldTake::Outcome.new(topic: "late")) }
      assert_match(/late/, error.message)
    end
    assert taken.lapsed?
    assert_empty outcomes
    assert_equal 1, @reader.late_takes, "one late take, however often its result is offered"
    assert_equal 0, @reader.held_takes_lapsed, "no wake found it"
  end

  def test_a_result_after_the_wall_lease_ended_is_late_with_no_wake
    taken = take("1m")
    @time.step_wall(61) # the wall passed the lease; the loop has not turned since
    error = assert_raises(ArgumentError) { taken.complete(HeldTake::Outcome.new(topic: "late")) }
    assert_match(/late/, error.message)
    assert_empty outcomes
    assert_equal 1, @reader.late_takes
  end

  def test_a_result_in_time_is_not_late
    taken = take("1m")
    refute_nil taken.complete(HeldTake::Outcome.new(topic: "in time"))
    assert_equal 0, @reader.late_takes
    refute taken.lapsed?
  end

  def test_a_take_its_handler_gave_up_is_no_late_take_at_a_later_wake
    assert_raises(RuntimeError) do
      @spaces[@reader].take(HeldTake::Job, lease: "1m", timeout: "2s") { raise "the handler failed" }
    end
    @reader.run_due
    @time.suspend(120)
    @reader.run_due
    assert_equal 0, @reader.held_takes_lapsed, "a take given up is not judged again"
    assert_equal 0, @reader.late_takes
  end

  def test_a_revoked_holders_take_is_not_renewed
    taken = take
    @reader.revocations.peers[@reader.identity.peer_id] = :revoked
    error = assert_raises(ArgumentError) { taken.renew }
    assert_match(/revoked/, error.message)
  end

  def test_an_unbound_agents_handler_renewals_stop
    agent = HeldTake::Renewer.new
    @bound = Binder.new(@reader, publish_card: false).bind(agent)
    assert_equal :renewed, agent.started.pop(timeout: 10), "a bound agent's handler renews its take"
    @bound.close(timeout: 0) # unbound while the handler runs
    agent.go << :go
    answer = agent.answers.pop(timeout: 10)
    assert_match(/renewer is unbound/, answer, "the renewal through its context ends with the binding")
  end
end
