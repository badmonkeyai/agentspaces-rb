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

module Pairing
  Job = AgentSpaces::Entry.define("com.acme.PairJob#v1", topic: String)
  Outcome = AgentSpaces::Entry.define("com.acme.PairOutcome#v1", topic: String)
  Chore = AgentSpaces::Entry.define("com.acme.PairChore#v1", topic: String)
end

# The settle guarantee's second rule with its evidence paired, and the
# displaced holder's re-offer (SPEC v0.1.36 §7.4, "Pairing the evidence";
# peer_settle.rb). The reader takes and its claim is kept; the third peer is
# the rival whose claim the reader's displaces (stamped later at the same
# epoch), or the better claim that displaces the reader's (stamped earlier).
# Every frame is delivered by hand where the order matters; time is virtual.
class SettlePairingTest < Minitest::Test
  include AgentSpaces

  GROUP = "zRubyPairing"

  def setup
    @time = VirtualTime.new
    @writer, @reader, @third = Testing::Network.fleet(GROUP, 3, time: @time)
    @spaces = [@writer, @reader, @third].to_h { |peer| [peer, peer.space("tasks")] }
    @id = @spaces[@writer].write(Pairing::Job.new(topic: "contested"), lease: "10m")
    @present = @writer.states[@id]
    @taken = @spaces[@reader].take(Pairing::Job, lease: "1m", timeout: "2s")
    assert_equal @id, @taken.entry_id
  end

  def teardown
    [@writer, @reader, @third].each(&:close)
  end

  # A claim of the third peer's on the entry at the reader's epoch, stamped
  # offset ms from the reader's own: later loses the lattice, earlier wins it.
  def rival_claim(offset)
    own = @reader.claim_of(@id)
    holder = @third.identity.agent("rival")
    stamp = Wire.hlc_now(holder, Wire.hlc_physical(own["stamp"]) + offset)
    Wire.signed_claim(Wire.take_claim(@id, own["spaceId"], own["epoch"], stamp, holder, 0.0, @time.wall_ms + 60_000),
                      @third.identity)
  end

  # The rival's completion, signed by its holder: it authenticates only under its own claim.
  def completion_under(_claim)
    Wire.sign_state(@present.merge("completed" => true), @third.identity, nil, @time.wall_ms)
  end

  def outcomes(peer) = @spaces[peer].entries(Pairing::Outcome)

  def test_the_winner_pairs_a_displaced_claim_and_its_completion_and_acknowledges_it
    claim = rival_claim(+5)
    @reader.fold_claim(@id, claim)
    assert_equal @taken.holder, @reader.claim_of(@id)["holder"], "the reader's claim is kept"
    refute @reader.knows_displaced_completion?(@id), "a claim alone is half the evidence"
    @reader.fold_state(completion_under(claim)) # another frame: the completion did not authenticate on its own
    refute @reader.states[@id]["completed"], "the displaced completion itself stays dropped"
    assert @reader.knows_displaced_completion?(@id)

    error = assert_raises(ArgumentError) { @taken.complete(Pairing::Outcome.new(topic: "done twice")) }
    assert_match(/acknowledged/, error.message)
    assert_equal 1, @reader.acknowledged_completions
    [@writer, @reader, @third].each do |peer|
      assert_empty outcomes(peer), "no second result"
      assert peer.states[@id]["completed"], "the acknowledgement completed the entry everywhere"
    end
    assert_equal 0, @reader.duplicate_completions
  end

  def test_the_pair_is_judged_in_either_order
    claim = rival_claim(+5)
    @reader.fold_state(completion_under(claim))
    refute @reader.knows_displaced_completion?(@id)
    @reader.fold_claim(@id, claim)
    assert @reader.knows_displaced_completion?(@id), "the claim arriving second completes the pair"
  end

  def test_a_completion_under_no_displaced_claim_is_no_evidence
    stranger = Wire.sign_state(@present.merge("completed" => true), Identity.generate, nil, @time.wall_ms)
    @reader.fold_state(stranger)
    @reader.fold_claim(@id, rival_claim(+5))
    refute @reader.knows_displaced_completion?(@id), "the completion does not verify under the rival's claim"
    refute_nil @taken.complete(Pairing::Outcome.new(topic: "done"))
  end

  def test_both_holders_did_the_work_and_the_winner_counts_the_duplicate_once
    refute_nil @taken.complete(Pairing::Outcome.new(topic: "done by the reader"))
    claim = rival_claim(+5)
    @reader.fold_claim(@id, claim)
    @reader.fold_state(completion_under(claim))
    assert_equal 1, @reader.duplicate_completions
    @reader.fold_state(completion_under(claim))
    assert_equal 1, @reader.duplicate_completions, "once per entry"
    assert_equal 0, @reader.acknowledged_completions
  end

  def test_a_take_that_learns_of_the_displaced_completion_in_its_window_comes_back_empty
    @taken.renew # the setup's take stays; a second job for a fresh take
    id = @spaces[@writer].write(Pairing::Job.new(topic: "second"), lease: "10m")
    present = @writer.states[id]
    reader = @reader
    third = @third
    time = @time
    injected = false
    reader.define_singleton_method(:await_fold) do |max_seconds, since: nil|
      own = claim_of(id)
      if !injected && own && own["holder"].to_s.start_with?("#{identity.peer_id}/")
        injected = true
        holder = third.identity.agent("rival")
        stamp = Wire.hlc_now(holder, Wire.hlc_physical(own["stamp"]) + 5)
        rival = Wire.signed_claim(Wire.take_claim(id, own["spaceId"], own["epoch"], stamp, holder, 0.0,
                                                  time.wall_ms + 60_000), third.identity)
        fold_claim(id, rival)
        fold_state(Wire.sign_state(present.merge("completed" => true), third.identity, nil, time.wall_ms))
      end
      super(max_seconds, since: since)
    end
    taken = @spaces[@reader].take(Pairing::Job, lease: "1m", timeout: "2s") { |_value, _t| flunk "no work" }
    assert_nil taken, "the take acknowledged the completion and came back empty"
    assert injected
    assert @writer.states[id]["completed"]
    assert_equal 1, @reader.acknowledged_completions
  end

  # The displaced holder's side: the reader completed with its own work, then a better claim arrives.
  def complete_then_displace
    sent = []
    reader = @reader
    reader.define_singleton_method(:send_frame) do |kind, body, to = nil|
      sent << CBOR.load(body)["itemId"] if kind == "RUMOR"
      super(kind, body, to)
    end
    refute_nil @taken.complete(Pairing::Outcome.new(topic: "done by the reader"))
    sent.clear
    @reader.fold_claim(@id, rival_claim(-5))
    refute_equal @taken.holder, @reader.claim_of(@id)["holder"], "the better claim displaced the reader's"
    sent
  end

  def test_the_displaced_holder_offers_its_claim_again_at_once_then_on_a_stale_offer_with_backoff
    sent = complete_then_displace
    @reader.run_due
    assert_equal 1, @reader.displaced_reoffers, "the first offer goes at once"
    assert_match(/\Ac:#{@id}:/, sent.last)
    @reader.fold_state(@present) # a replica still offers the entry present
    @reader.run_due
    assert_equal 1, @reader.displaced_reoffers, "no sooner than 1 s after the first"
    @time.advance(1.0)
    @reader.run_due
    assert_equal 1, @reader.displaced_reoffers, "and only when a replica still offers it present"
    @reader.fold_state(@present)
    @reader.run_due
    assert_equal 2, @reader.displaced_reoffers
    assert_equal 2, sent.uniq.size, "each offer has its own item id, so the seed forwards it"
  end

  def test_the_re_offers_stop_after_six
    complete_then_displace
    @reader.run_due
    5.times do |i|
      @time.advance(2**i)
      @reader.fold_state(@present)
      @reader.run_due
    end
    assert_equal 6, @reader.displaced_reoffers
    @time.advance(64)
    @reader.fold_state(@present)
    @reader.run_due
    assert_equal 6, @reader.displaced_reoffers, "at most six offers in all"
  end

  def test_the_re_offers_stop_once_the_claim_nears_the_drift_ceiling
    complete_then_displace
    @reader.run_due
    @time.advance((Certificates::MAX_DRIFT_MILLIS / 2 / 1000) + 1)
    @reader.fold_state(@present)
    @reader.run_due
    assert_equal 1, @reader.displaced_reoffers, "a claim past half the drift ceiling is offered no more"
  end

  # Spirit review: a laptop sleep while backing off (macOS counts it on both
  # clocks). The claim lapsed meanwhile, so the line ends with no burst of
  # offers on wake, as Java's offerDisplaced judges it.
  def test_a_sleep_while_backing_off_past_the_claim_ends_the_re_offers
    complete_then_displace
    @reader.run_due
    assert_equal 1, @reader.displaced_reoffers
    @time.advance(3600)
    @reader.run_due
    @reader.fold_state(@present)
    @reader.run_due
    assert_equal 1, @reader.displaced_reoffers, "no offer of a claim that lapsed during the sleep"
  end

  # Round 2a (owner decision 2026-11-23): the backoff between offers is a
  # local period on the monotonic base. A wall step back of five minutes no
  # longer holds the next offer for five minutes, and a step forward does
  # not fire it before its second has passed.
  def test_the_re_offer_backoff_ignores_a_wall_step
    complete_then_displace
    @reader.run_due
    assert_equal 1, @reader.displaced_reoffers
    @time.step_wall(10) # forward: the wall says the backoff passed; it has not
    @reader.fold_state(@present)
    @reader.run_due
    assert_equal 1, @reader.displaced_reoffers, "a step forward does not fire the offer early"
    @time.step_wall(-310) # back, five minutes behind where the offer went out
    @time.advance(1.0)
    @reader.fold_state(@present)
    @reader.run_due
    assert_equal 2, @reader.displaced_reoffers, "a step back does not hold the offer for its length"
  end

  # ------------------------- owner decision 1 of 2026-11-23: the holder answers

  # The reader's frames to the group are lost (a dial-only peer whose rumors
  # the seed holding the better claim drops, SPEC 11a.4); its answers to an
  # addressed DIGEST still go. Returns the PULL_RESPs the third peer reads.
  def lose_the_readers_rumors
    @reader.define_singleton_method(:send_frame) do |kind, body, to = nil|
      next if kind == "RUMOR"

      super(kind, body, to)
    end
    answers = []
    @third.define_singleton_method(:handle) do |env, relayed: false|
      answers << Wire.decode_body("PULL_RESP", env["body"]) if env["kind"] == "PULL_RESP"
      super(env, relayed: relayed)
    end
    answers
  end

  # A DIGEST of the third peer's to the reader, as an envelope the reader
  # reads relayed by its seed.
  def relayed_digest(space, text = "".b)
    body = Wire.digest_body({ "space:#{space}" => text })
    env = Wire.envelope(GROUP, "DIGEST", @third.identity.peer_id, Wire.hlc_now(@third.identity.peer_id, @time.wall_ms),
                        body, @reader.identity.peer_id)
    @reader.handle(env, relayed: true)
  end

  def sync_of(answer) = Schema.load("SpaceWire.SyncDelta", answer["deltas"]["space:tasks"])

  # End to end, Ruby to Ruby: the winner's targeted round reaches a
  # displaced Ruby holder, which answers it with its completion, and the
  # winner pairs the evidence (before, a Ruby holder answered only its
  # seed, and the round brought nothing).
  def test_a_displaced_ruby_holder_answers_the_winners_targeted_round_and_the_winner_pairs_it
    answers = lose_the_readers_rumors
    own = @reader.claims[@id]
    refute_nil @taken.complete(Pairing::Outcome.new(topic: "done by the reader"))
    assert @third.states[@id].then { |dto| Peer.present?(dto) }, "the completion never left the reader"
    better = rival_claim(-5)
    @third.fold_claim(@id, better) # the third peer's own claim, which displaces the reader's
    @reader.fold_claim(@id, better)
    @third.fold_claim(@id, own) # the reader's claim reaches the winner after its own: it files a line
    @third.run_due
    assert_equal 1, @third.displaced_pull_rounds, "the winner's round went to the reader"
    assert_equal 1, answers.size, "the displaced holder answered it"
    assert_equal 1, @reader.displaced_digest_answers
    assert @third.knows_displaced_completion?(@id), "the winner paired the reader's claim and completion"
  end

  def test_another_members_relayed_digest_draws_only_the_displaced_entry
    answers = lose_the_readers_rumors
    other = @spaces[@reader].write(Pairing::Job.new(topic: "written, lost, nobody's business"), lease: "10m")
    assert_nil @third.states[other]
    own = @reader.claims[@id]
    refute_nil @taken.complete(Pairing::Outcome.new(topic: "done by the reader"))
    @reader.fold_claim(@id, rival_claim(-5))
    relayed_digest("tasks") # an empty digest: the asker holds nothing of the space
    assert_equal 1, answers.size
    sync = sync_of(answers.first)
    assert_equal [@id], sync["states"].map { |dto| dto["record"]["entryId"] }, "the displaced entry alone"
    assert sync["states"].first["completed"], "with the reader's completion"
    assert_equal({ @id => own }, sync["claims"], "and the reader's own claim, not the lattice's")
    relayed_digest("elsewhere")
    assert_equal 1, answers.size, "a space with nothing displaced draws nothing"
    assert_equal 0, @reader.digests_answered, "no seed round was answered"
  end

  def test_a_member_with_nothing_displaced_or_completed_answers_no_relayed_digest
    lose_the_readers_rumors
    @spaces[@reader].write(Pairing::Job.new(topic: "mine"), lease: "10m")
    relayed_digest("tasks")
    assert_equal 1, @reader.ignored_kinds["DIGEST"]
    assert_equal 0, @reader.displaced_digest_answers
    assert_equal 0, @reader.pull_resps_sent
  end

  # Owner decision 1, aligned with the core (GossipBus.onDigestDisplacedOnly,
  # ReplicatedSpace.displacedFor): a relayed DIGEST draws only the entries
  # whose claim made here a better claim displaced, with or without a
  # completion under it; another completion of this peer's own work draws
  # nothing.
  def test_a_relayed_digest_draws_a_displaced_claim_made_here_and_no_other_own_completion
    answers = lose_the_readers_rumors
    chore = @spaces[@reader].write(Pairing::Chore.new(topic: "the reader's own, uncontested"), lease: "10m")
    done = @spaces[@reader].take(Pairing::Chore, lease: "1m", timeout: "2s")
    assert_equal chore, done.entry_id
    done.complete
    assert @reader.states[chore]["completed"], "the reader completed it"
    relayed_digest("tasks")
    assert_empty answers, "a completion nothing displaced draws nothing"
    assert_equal 1, @reader.ignored_kinds["DIGEST"]
    own = @reader.claims[@id]
    @reader.fold_claim(@id, rival_claim(-5)) # displaced, with no completion under it
    relayed_digest("tasks")
    assert_equal 1, answers.size, "the displaced claim made here draws an answer"
    sync = sync_of(answers.first)
    assert_equal({ @id => own }, sync["claims"], "the reader's displaced claim alone")
    assert_equal [@id], sync["states"].map { |dto| dto["record"]["entryId"] }, "nothing of the uncontested entry"
    assert_equal 1, @reader.displaced_digest_answers
  end

  def test_relayed_digests_are_answered_under_the_askers_pace
    answers = lose_the_readers_rumors
    refute_nil @taken.complete(Pairing::Outcome.new(topic: "done by the reader"))
    @reader.fold_claim(@id, rival_claim(-5))
    (Peer::RELAYED_ANSWER_BURST + 2).times { relayed_digest("tasks") }
    assert_equal Peer::RELAYED_ANSWER_BURST, answers.size, "a burst of #{Peer::RELAYED_ANSWER_BURST}"
    assert_equal 2, @reader.relayed_answers_paced
    @time.advance(1.0 / Peer::RELAYED_ANSWER_RATE)
    relayed_digest("tasks")
    assert_equal Peer::RELAYED_ANSWER_BURST + 1, answers.size, "then #{Peer::RELAYED_ANSWER_RATE} a second"
  end

  def test_a_holder_that_did_not_complete_offers_nothing
    @reader.fold_claim(@id, rival_claim(-5))
    @reader.run_due
    assert_equal 0, @reader.displaced_reoffers
  end
end
