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

module RbeAdv
  Job = AgentSpaces::Entry.define("com.acme.RbeAdvJob#v1", topic: String)
  Outcome = AgentSpaces::Entry.define("com.acme.RbeAdvOutcome#v1", topic: String)
end

# The adversarial review of replication by entry on the Ruby peer (SPEC
# v0.1.35 7.2 to 7.4; srad/replication-by-entry.md phase 8, deferred to the
# combined testing round). Each test shows one defect the review found, now
# fixed at its root:
#
# - a renewal that read the entry before a cancel landed wrote its present
#   copy over the withdrawal, so the entry was live again here and the
#   renewal carried a lease past the withdrawal's own to every replica, the
#   one thing the per-entry horizon's safety argument rules out;
# - a completion that read the entry before a cancel landed dropped the
#   cancel's removes here;
# - a reordered older card replaced the member's newer one, so a member that
#   had dropped wire.horizon=1 counted as hinted again;
# - a take judged its win without asking whether its own claim was still in
#   force, and accepted a lease no longer than the window that judges it;
# - Taken recorded whichever claim it found after the take returned, so a
#   rival claim folding in between became the claim the completion checked;
# - an entry first learned with its lease already lapsed raised WRITTEN.
class RbeAdversaryTest < Minitest::Test
  include AgentSpaces

  GROUP = "zRubyRbeAdv"
  T0 = 1_800_000_000_000
  MINUTE = 60_000
  HOUR = 60 * MINUTE
  TYPE = "com.acme.RbeAdvJob#v1"

  # A peer that keeps what it sends instead of writing to a connection.
  class CapturingPeer < Peer
    attr_reader :sent

    def initialize(identity, group, clock:)
      super(identity, group, clock: clock)
      @sent = []
    end

    private

    def send_frame(kind, body, to = nil) = @sent << [kind, body, to]
  end

  def setup
    @clock = Testing::TestClock.new(T0)
  end

  def now = @clock.millis

  # Runs block once, inside the next call of Wire.sign_state, as another
  # thread's fold would land between a read of the entry and the write back.
  def interleave_once_in_signing(&block)
    original = Wire.method(:sign_state)
    fired = false
    Wire.define_singleton_method(:sign_state) do |*args|
      unless fired
        fired = true
        block.call
      end
      original.call(*args)
    end
    original
  end

  def restore_signing(original)
    Wire.define_singleton_method(:sign_state, original)
  end

  def item_ids(peer) = peer.sent.select { |kind, _, _| kind == "RUMOR" }.map { |_, body, _| CBOR.load(body)["itemId"] }

  # ------------------------------------------------------------ renewal and completion races

  def test_a_renewal_that_races_a_cancel_never_brings_the_withdrawn_entry_back
    p = CapturingPeer.new(Identity.generate, GROUP, clock: @clock)
    id = p.write_entry("tasks", TYPE, { "topic" => "t" }, lease_millis: 10 * MINUTE)
    withdrawn_expiry = T0 + (10 * MINUTE)
    original = interleave_once_in_signing { p.cancel_entry("tasks", id) }
    begin
      assert_raises(ArgumentError) { p.renew_entry("tasks", id, lease_millis: HOUR) }
    ensure
      restore_signing(original)
    end
    refute Peer.present?(p.states[id]), "the cancel stands: the entry is not live again here"
    assert_equal withdrawn_expiry, Horizon.expiry_of(p.states[id]),
                 "no lease past the withdrawal's own, which the per-entry horizon relies on"
    refute(item_ids(p).any? { |item| item.start_with?("r:#{id}:") }, "no renewal went out after the cancel")
  end

  def test_a_renewal_that_races_another_renewal_keeps_the_longer_lease
    p = CapturingPeer.new(Identity.generate, GROUP, clock: @clock)
    id = p.write_entry("tasks", TYPE, { "topic" => "t" }, lease_millis: 10 * MINUTE)
    original = interleave_once_in_signing { p.renew_entry("tasks", id, lease_millis: 2 * HOUR) }
    begin
      p.renew_entry("tasks", id, lease_millis: HOUR)
    ensure
      restore_signing(original)
    end
    assert_equal T0 + (2 * HOUR), Horizon.expiry_of(p.states[id]), "a renewal never shortens, even racing another"
  end

  def test_a_completion_that_races_a_cancel_neither_completes_nor_drops_the_withdrawal
    writer = Identity.generate
    p = CapturingPeer.new(Identity.generate, GROUP, clock: @clock)
    _, body = Wire.entry_delta("tasks", GROUP, TYPE, CBOR.dump({ "topic" => "t" }), writer, "w", 10 * MINUTE,
                               now_ms: now)
    write = CBOR.load(CBOR.load(body)["payload"])["state"]
    id = write["record"]["entryId"]
    p.fold_state(write)
    holder = p.identity.agent("ruby")
    claim = Wire.take_claim(id, write["record"]["spaceId"], 1, Wire.hlc_now(holder, now), holder, 0.0, now + MINUTE)
    p.fold_claim(id, Wire.signed_claim(claim, p.identity))
    cancel = Wire.sign_state(write.merge("removes" => write["adds"]), writer, nil, now)
    original = interleave_once_in_signing { p.fold_state(cancel) }
    begin
      assert_raises(ArgumentError) { p.complete_entry("tasks", id) }
    ensure
      restore_signing(original)
    end
    state = p.states[id]
    refute state["completed"], "a withdrawn entry is held by nobody, so nobody completes it"
    assert Horizon.withdrawn_all?(state), "the cancel's removes stay"
  end

  # ------------------------------------------------------------ the view's cards

  def card(member, issued_ms, hints)
    ad = Wire.peer_advertisement(GROUP, member, Instants.iso(issued_ms - (issued_ms % 1000)), "PT10M", hints)
    Wire.signed_peer_ad(ad, member)
  end

  def deliver(peer, member, signed, stamp)
    peer.handle(Wire.envelope(GROUP, "RUMOR", member.peer_id, "#{now}:#{stamp}:#{member.peer_id}",
                              Wire.rumor_body("peers", "peer:#{member.peer_id}:#{stamp}", 1, signed)))
  end

  def test_a_reordered_older_card_never_brings_back_a_hint_the_member_dropped
    p = CapturingPeer.new(Identity.generate, GROUP, clock: @clock)
    member = Identity.generate
    older = card(member, now, { Horizon::HINT => "1" })
    @clock.advance(2000)
    newer = card(member, now, {}) # the member restarted on a release that may shorten its renewals
    deliver(p, member, newer, 1)
    deliver(p, member, older, 2) # gossip hands the older card over late
    assert_nil (p.members[member.peer_id]["resourceHints"] || {})[Horizon::HINT], "the newer card stands"
    refute p.send(:view_hinted?, now), "a member whose current card lacks the hint keeps the legacy horizon"
    # And it vouches for none of that member's withdrawals.
    _, body = Wire.entry_delta("tasks", GROUP, TYPE, CBOR.dump({ "topic" => "t" }), member, "w", MINUTE, now_ms: now)
    write = CBOR.load(CBOR.load(body)["payload"])["state"]
    refute p.send(:writers_vouched?, write.merge("removes" => write["adds"]), now + HOUR, 0)
  end

  # ------------------------------------------------------------ the take's win

  def test_a_take_whose_lease_cannot_outlast_its_window_is_refused_at_once
    p = CapturingPeer.new(Identity.generate, GROUP, clock: @clock)
    error = assert_raises(ArgumentError) do
      p.take_entry("tasks", TYPE, lease_millis: 900, settle_seconds: 0.6, timeout_seconds: 0.1)
    end
    assert_match(/900 ms/, error.message)
  end

  def test_a_take_whose_claim_lapsed_during_its_window_does_not_win_with_it
    writer, reader = Testing::Network.fleet(GROUP, 2, clock: @clock)
    id = writer.space("tasks").write(RbeAdv::Job.new(topic: "lapse"), lease: "10m")
    clock = @clock
    advanced = false
    # A busy interpreter wakes the take late: the claim (one second) lapsed in its settle window.
    reader.define_singleton_method(:sleep) do |seconds|
      unless advanced
        advanced = true
        clock.advance(1001)
      end
      super(seconds)
    end
    won = reader.take_entry("tasks", TYPE, lease_millis: 1000, settle_seconds: 0.6, timeout_seconds: 5.0)
    assert_equal id, won
    claim = reader.claim_of(id)
    assert_operator claim["expiresAtMillis"], :>, reader.now_ms, "a take returns only a claim still in force"
    assert_equal 2, claim["epoch"], "the lapsed first claim did not win; a fresh one did"
  ensure
    [writer, reader].each { |peer| peer&.close }
  end

  def test_taken_holds_the_claim_its_take_won_not_a_rival_that_folded_after
    writer, reader, third = Testing::Network.fleet(GROUP, 3, clock: @clock)
    id = writer.space("tasks").write(RbeAdv::Job.new(topic: "contested"), lease: "10m")
    rival = lambda do |entry_id|
      own = reader.claim_of(entry_id)
      holder = third.identity.agent("rival")
      stamp = Wire.hlc_now(holder, Wire.hlc_physical(own["stamp"]) - 5)
      Wire.signed_claim(Wire.take_claim(entry_id, own["spaceId"], own["epoch"], stamp, holder, 0.0,
                                        reader.now_ms + 60_000), third.identity)
    end
    # The rival's earlier claim folds after the take judged its win and before Taken reads the claim.
    reader.define_singleton_method(:take_entry) do |*args, **options|
      won = super(*args, **options)
      fold_claim(won, rival.call(won)) if won
      won
    end
    taken = reader.space("tasks").take(RbeAdv::Job, lease: "1m", timeout: "2s")
    refute_nil taken
    assert_equal id, taken.entry_id
    assert_raises(ArgumentError) { taken.complete(RbeAdv::Outcome.new(topic: "done")) }
    [writer, reader, third].each do |peer|
      assert_empty peer.space("tasks").entries(RbeAdv::Outcome), "no result was written"
      refute peer.states[id]["completed"], "no completion anywhere"
    end
  ensure
    [writer, reader, third].each { |peer| peer&.close }
  end

  # ------------------------------------------------------------ WRITTEN only for a live entry

  def test_an_entry_first_learned_with_its_lease_lapsed_raises_no_written
    writer = Identity.generate
    p = CapturingPeer.new(Identity.generate, GROUP, clock: @clock)
    events = []
    p.space("tasks").watch(RbeAdv::Job) { |e| events << e.kind }
    _, body = Wire.entry_delta("tasks", GROUP, TYPE, CBOR.dump({ "topic" => "old" }), writer, "w", MINUTE,
                               now_ms: now)
    write = CBOR.load(CBOR.load(body)["payload"])["state"]
    @clock.advance(90_000) # lapsed, still inside its lapse horizon of two minutes here
    p.fold_state(write)
    assert p.states.key?(write["record"]["entryId"]), "held until its lapse horizon"
    refute_includes events, WRITTEN, "no reader here could have seen it live"
  end
end
