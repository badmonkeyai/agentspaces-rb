# frozen_string_literal: true

# Copyright 2026 Bad Monkey, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require_relative "test_helper"

module Settle
  Job = AgentSpaces::Entry.define("com.acme.SettleJob#v1", topic: String)
  Outcome = AgentSpaces::Entry.define("com.acme.SettleOutcome#v1", topic: String)
end

# The settle guarantee, SPEC 7.4 (v0.1.35, 2026-11-15), as it binds this client. A take
# wins an entry only while every rival claim reaches it within the settle window. A claim
# that arrives later can displace a take that already won its window, and a holder that
# learns of the better claim before it completes MUST NOT complete: Taken#complete raises,
# and neither its result nor its completion goes out. Before, the result was written first
# and the completion was sent regardless.
class SettleGuaranteeTest < Minitest::Test
  include AgentSpaces

  GROUP = "zRubySettle"

  def setup
    @clock = Testing::TestClock.new
    @writer, @reader, @third = Testing::Network.fleet(GROUP, 3, clock: @clock)
    @spaces = [@writer, @reader, @third].to_h { |peer| [peer, peer.space("tasks")] }
  end

  def teardown
    [@writer, @reader, @third].each(&:close)
  end

  def write_job = @spaces[@writer].write(Settle::Job.new(topic: "contested"), lease: "10m")

  def take = @spaces[@reader].take(Settle::Job, lease: "1m", timeout: "2s")

  # A rival's claim on the entry at the take's epoch, stamped before the take's own: it wins the lattice.
  def earlier_rival_claim(taken)
    own = @reader.claim_of(taken.entry_id)
    holder = @third.identity.agent("rival")
    stamp = Wire.hlc_now(holder, Wire.hlc_physical(own["stamp"]) - 5)
    Wire.signed_claim(Wire.take_claim(taken.entry_id, own["spaceId"], own["epoch"], stamp, holder, 0.0,
                                      @reader.now_ms + 60_000), @third.identity)
  end

  def outcomes(peer) = @spaces[peer].entries(Settle::Outcome)

  def test_a_take_displaced_by_an_earlier_claim_after_its_window_writes_no_result_and_does_not_complete
    id = write_job
    taken = take
    refute_nil taken
    assert_equal id, taken.entry_id
    @reader.fold_claim(id, earlier_rival_claim(taken)) # reaches the reader after its window
    refute_equal taken.holder, @reader.claim_of(id)["holder"], "the earlier claim displaced the take"

    error = assert_raises(ArgumentError) { taken.complete(Settle::Outcome.new(topic: "done by the reader")) }
    assert_match(/displaced/, error.message)
    [@writer, @reader, @third].each do |peer|
      assert_empty outcomes(peer), "no result was written"
      refute peer.states[id]["completed"], "no completion went out"
    end
  end

  def test_a_take_whose_claim_lapsed_writes_no_result
    id = write_job
    taken = take
    refute_nil taken
    @clock.advance(61_000)
    assert_raises(ArgumentError) { taken.complete(Settle::Outcome.new(topic: "late")) }
    [@writer, @reader, @third].each do |peer|
      assert_empty outcomes(peer)
      refute peer.states[id]["completed"]
    end
  end

  # The take lease and the live claim (SPEC 7.4, 2026-11-15), as Java and TypeScript judge them.

  def test_take_judged_within_is_the_window_and_its_follow_up_wait
    assert_equal 900, Peer.take_judged_within_millis(600)
    assert_equal 400, Peer.take_judged_within_millis(200), "a short window's follow-up wait is the window itself"
    assert_equal 0, Peer.take_judged_within_millis(0)
  end

  def test_a_take_whose_lease_cannot_outlast_its_window_and_follow_up_wait_is_refused_at_once
    id = write_job
    [600, 800, 900].each do |lease|
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      error = assert_raises(ArgumentError) do
        @reader.take_entry("tasks", Settle::Job.schema, lease_millis: lease, settle_seconds: 0.6, timeout_seconds: 30.0)
      end
      assert_match(/must exceed 900 ms/, error.message)
      # Refused before any work: the 30 s timeout is the ceiling a doomed take used to run to.
      assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 5.0, "refused at once"
      assert_nil @reader.claim_of(id), "no doomed #{lease} ms claim went out"
    end
    assert_equal id, @reader.take_entry("tasks", Settle::Job.schema, lease_millis: 1_500, settle_seconds: 0.6,
                                                                     timeout_seconds: 30.0)
  end

  # A late wake (a busy interpreter, a laptop that slept) can judge the race after the take's own
  # claim lapsed. That claim is free for any taker already, so the take must not return the entry
  # as held. The clock here jumps past each claim's expiry while the take waits.
  def test_a_take_whose_claim_lapsed_before_it_was_judged_does_not_win
    id = write_job
    reader = @reader
    clock = @clock
    epochs = []
    reader.define_singleton_method(:await_fold) do |max_seconds, since: nil|
      claim = claim_of(id)
      if claim && claim["holder"].to_s.start_with?("#{identity.peer_id}/")
        epochs << Integer(claim["epoch"])
        clock.advance(Integer(claim["expiresAtMillis"]) + 1 - clock.millis) # woke after the claim's expiry
      end
      super(max_seconds, since: since)
    end
    assert_nil reader.take_entry("tasks", Settle::Job.schema, lease_millis: 1_000, settle_seconds: 0.05,
                                                              timeout_seconds: 1.0)
    refute_empty epochs, "the take claimed and was judged at least once"
    assert_equal (1..epochs.size).to_a, epochs, "each lapsed claim was succeeded, never kept"
  end

  def test_a_take_that_still_holds_writes_its_result_and_completes
    id = write_job
    taken = take
    refute_nil taken
    refute_nil taken.complete(Settle::Outcome.new(topic: "done"))
    [@writer, @reader, @third].each do |peer|
      assert_equal 1, outcomes(peer).size
      assert peer.states[id]["completed"]
    end
  end
end
