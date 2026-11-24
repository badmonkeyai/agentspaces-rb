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

module DisplacedPull
  Job = AgentSpaces::Entry.define("com.acme.PullJob#v1", topic: String)
end

# The winner's targeted rounds toward the holders its claim displaced
# (srad/agentspaces-event-loop.md phase 6, owner decision 4 of 2026-11-23;
# Java's ReplicatedSpace.displacedPulls; peer_settle.rb). The reader takes
# and its claim is kept; the third peer is the displaced holder, which
# answers a DIGEST addressed to it as a Java holder does, with a PULL_RESP
# carrying its completion. This peer runs no periodic rounds and its seed
# pulls bring nothing here (NetPeer#pull_space is a no-op), so only the
# targeted round can bring the completion. Time is virtual.
class DisplacedPullTest < Minitest::Test
  include AgentSpaces

  GROUP = "zRubyDisplacedPull"

  def setup
    @time = VirtualTime.new
    @writer, @reader, @third = Testing::Network.fleet(GROUP, 3, time: @time)
    @spaces = [@writer, @reader, @third].to_h { |peer| [peer, peer.space("tasks")] }
    @id = @spaces[@writer].write(DisplacedPull::Job.new(topic: "contested"), lease: "10m")
    @present = @writer.states[@id]
    @taken = @spaces[@reader].take(DisplacedPull::Job, lease: "1m", timeout: "2s")
    assert_equal @id, @taken.entry_id
    @asked = Hash.new { |h, k| h[k] = [] } # DIGESTs addressed to each peer, by virtual instant
    asked = @asked
    time = @time
    @reader.define_singleton_method(:send_frame) do |kind, body, to = nil|
      asked[to] << time.mono if kind == "DIGEST" && to
      super(kind, body, to)
    end
    @answer = nil # what the displaced holder answers with, or nil for silence
  end

  def teardown
    [@writer, @reader, @third].each(&:close)
  end

  # A claim on the entry at the reader's epoch by holder (of peer's), stamped
  # offset ms after the reader's own, so the reader's claim displaces it.
  def rival_claim(peer, name, offset)
    own = @reader.claim_of(@id)
    holder = peer.identity.agent(name)
    stamp = Wire.hlc_now(holder, Wire.hlc_physical(own["stamp"]) + offset)
    Wire.signed_claim(Wire.take_claim(@id, own["spaceId"], own["epoch"], stamp, holder, 0.0, @time.wall_ms + 60_000),
                      peer.identity)
  end

  def completion_of(peer) = Wire.sign_state(@present.merge("completed" => true), peer.identity, nil, @time.wall_ms)

  # The displaced holder answers a DIGEST addressed to it, as Java's
  # GossipBus.onDigest does, with a PULL_RESP holding its completion.
  def holder_answers(completion)
    test = self
    @third.define_singleton_method(:on_digest) do |sender, body, _relayed|
      digest = Wire.decode_body("DIGEST", body)
      test.assert_equal ["space:tasks"], digest["digests"].keys, "a round of the entry's space"
      deltas = { "space:tasks" => Peer.sync_delta_bytes([completion], {}) }
      send_frame("PULL_RESP", Peer.pull_resp_body(deltas), sender)
    end
  end

  def test_a_displaced_holder_is_pulled_by_the_winner_within_one_targeted_round
    holder_answers(completion_of(@third))
    @reader.fold_claim(@id, rival_claim(@third, "rival", +5))
    assert_equal @taken.holder, @reader.claim_of(@id)["holder"], "the reader's claim is kept"
    refute @reader.knows_displaced_completion?(@id), "the claim alone is half the evidence"
    assert_equal 0, @reader.displaced_pull_rounds, "nothing is sent from the fold itself"
    @reader.run_due
    assert_equal 1, @reader.displaced_pull_rounds, "one targeted round, at once"
    assert_equal 1, @asked[@third.identity.peer_id].size, "addressed to the displaced holder"
    assert @reader.knows_displaced_completion?(@id), "its answer paired the evidence"
    @time.advance(60)
    @reader.run_due
    assert_equal 1, @reader.displaced_pull_rounds, "the line ended once the completion was noted"
    assert_equal 0, @reader.displaced_pulls_open
  end

  def test_rounds_go_at_once_then_after_1_2_4_8_and_16_s_and_at_most_six
    @reader.fold_claim(@id, rival_claim(@third, "rival", +5)) # a silent holder
    at = ->(elapsed) { @time.advance(elapsed - (@time.mono - @start)) && @reader.run_due }
    @start = @time.mono
    @reader.run_due
    expected = { 0.5 => 1, 1.0 => 2, 2.9 => 2, 3.0 => 3, 7.0 => 4, 15.0 => 5, 31.0 => 6, 58.0 => 6 }
    expected.each do |elapsed, rounds|
      at.call(elapsed)
      assert_equal rounds, @reader.displaced_pull_rounds, "rounds by #{elapsed} s"
    end
    instants = @asked[@third.identity.peer_id].map { |t| (t - @start).round(3) }
    assert_equal [0.0, 1.0, 3.0, 7.0, 15.0, 31.0], instants
    assert_equal 0, @reader.displaced_pulls_open, "the rounds are spent"
  end

  def test_a_holder_displaced_later_is_asked_at_once
    @reader.fold_claim(@id, rival_claim(@third, "rival", +5))
    @reader.run_due
    @time.advance(0.4)
    @reader.run_due
    assert_equal 1, @reader.displaced_pull_rounds
    @reader.fold_claim(@id, rival_claim(@writer, "rival2", +7))
    @reader.run_due
    assert_equal 1, @asked[@writer.identity.peer_id].size, "the new holder at once, not at the 1 s round"
    # As Java's pullDisplacedHolders: a round asks every holder of the line.
    assert_equal 2, @asked[@third.identity.peer_id].size
  end

  def test_the_rounds_end_when_the_winner_completes_the_entry
    @reader.fold_claim(@id, rival_claim(@third, "rival", +5))
    @reader.run_due
    assert_equal 1, @reader.displaced_pull_rounds
    @taken.complete
    @time.advance(5)
    @reader.run_due
    assert_equal 1, @reader.displaced_pull_rounds, "a completed entry is no open take"
    assert_equal 0, @reader.displaced_pulls_open
  end

  def test_the_rounds_end_when_the_claim_lapses
    @reader.fold_claim(@id, rival_claim(@third, "rival", +5))
    @reader.run_due
    @time.step_wall(61) # past the take's 1 min lease on the wall clock
    @time.advance(1)
    @reader.run_due
    assert_equal 1, @reader.displaced_pull_rounds, "a lapsed claim is no open take"
    assert_equal 0, @reader.displaced_pulls_open
  end

  def test_a_renewal_or_a_losing_claim_starts_no_round
    @reader.fold_claim(@id, rival_claim(@third, "rival", -5)) # the rival's claim wins: the reader is displaced
    @reader.run_due
    assert_equal 0, @reader.displaced_pull_rounds
    assert_empty @asked
  end
end
