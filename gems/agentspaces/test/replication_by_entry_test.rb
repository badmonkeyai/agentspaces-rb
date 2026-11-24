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

require "logger"
require "stringio"
require_relative "test_helper"

module Rbe
  Job = AgentSpaces::Entry.define("com.acme.RbeJob#v1", topic: String)
end

# Replication by entry as it binds the Ruby peer (SPEC v0.1.35 7.2, 7.3 and
# annex I.6; srad/replication-by-entry.md RE-L-03): the renewal rule, the
# collection horizons with the per-entry rule, its two halves and the drift
# floor, the door, the budgeted get-space with its continuation, and
# completed on arrival. The golden entries renew_clamp_cases,
# lapse_horizon_cases and horizon_mode_cases pin the numbers.
class ReplicationByEntryTest < Minitest::Test
  include AgentSpaces
  include GoldenHelpers

  GROUP = "zRubyRbe"
  T0 = 1_800_000_000_000
  MINUTE = 60_000
  HOUR = 60 * MINUTE
  TYPE = "com.acme.RbeJob#v1"

  # A peer that keeps what it sends instead of writing to a connection.
  class CapturingPeer < Peer
    attr_reader :sent

    def initialize(identity, group, clock:, horizon: AgentSpaces::Horizon::PER_ENTRY, logger: nil)
      super(identity, group, clock: clock, horizon: horizon, logger: logger)
      @sent = []
    end

    def partner!(peer_id) = @seed_peer = peer_id

    private

    def send_frame(kind, body, to = nil) = @sent << [kind, body, to]
  end

  def setup
    @clock = Testing::TestClock.new(T0)
    @identity = Identity.generate
    @stamps = 0
  end

  def peer(horizon: Horizon::PER_ENTRY) = CapturingPeer.new(@identity, GROUP, clock: @clock, horizon: horizon)

  def now = @clock.millis

  def space_id = Derive.space_id_local("#{GROUP}/tasks")

  # A member's card, issued now, delivered as the peers stream delivers it.
  def advertise(peer, member, hints)
    issued = Instants.iso(now - (now % 1000))
    ad = Wire.peer_advertisement(GROUP, member, issued, "PT10M", hints)
    @stamps += 1
    peer.handle(Wire.envelope(GROUP, "RUMOR", member.peer_id, "#{now}:#{@stamps}:#{member.peer_id}",
                              Wire.rumor_body("peers", "peer:#{member.peer_id}:#{@stamps}", 1,
                                              Wire.signed_peer_ad(ad, member))))
  end

  # A signed write by writer, leased lease ms from now.
  def write_by(writer, lease, payload = { "topic" => "t" })
    _, body = Wire.entry_delta("tasks", GROUP, TYPE, CBOR.dump(payload), writer, "w", lease, now_ms: now)
    CBOR.load(CBOR.load(body)["payload"])["state"]
  end

  # The writer's cancel of dto, signed now: removes cover adds, the lease register as it was.
  def cancel_by(writer, dto)
    Wire.sign_state(dto.merge("removes" => dto["adds"]), writer, nil, now)
  end

  # Advances the clock by millis in steps of five minutes, the member re-advertising
  # at each as a live member does, so its card never lapses on the way.
  def live_for(peer, member, millis)
    while millis.positive?
      step = [millis, 5 * MINUTE].min
      @clock.advance(step)
      millis -= step
      advertise(peer, member, { Horizon::HINT => "1" })
    end
  end

  def judge_rounds(peer, rounds = Horizon::ENGAGE_ROUNDS + 1)
    rounds.times do
      peer.collect_garbage
      @clock.advance(1000)
    end
  end

  # ------------------------------------------------------------ golden numbers

  def test_renew_clamp_cases_through_the_peer
    cases = GOLDEN.fetch("renew_clamp_cases")
    assert_equal 5, cases.size
    cases.each do |c|
      assert_equal c["expiry"], Horizon.renewed_expiry(c["current"], c["now"], c["extension"]), c.inspect
      clock = Testing::TestClock.new(c["now"])
      p = CapturingPeer.new(@identity, GROUP, clock: clock)
      id = p.write_entry("tasks", TYPE, { "topic" => "t" }, lease_millis: c["current"] - c["now"])
      sent = p.sent.size
      assert_equal c["expiry"], p.renew_entry("tasks", id, lease_millis: c["extension"]), c.inspect
      assert_equal c["expiry"], Horizon.expiry_of(p.states[id]), c.inspect
      assert_equal(c["expiry"] == c["current"] ? sent : sent + 1, p.sent.size,
                   "a renewal that leaves the lease sends nothing: #{c.inspect}")
    end
  end

  # One state of each kind the golden cases name, with its lease expiring at expiry.
  def state_of(kind, expiry)
    dot = { "replica" => "zWriter", "counter" => 1 }
    {
      "adds" => [dot], "removes" => kind.start_with?("withdrawn") ? [dot] : [],
      "completed" => %w[completed withdrawn_completed].include?(kind),
      "leaseValue" => { "holder" => "zWriter/w", "expiresAtMillis" => expiry, "kind" => "WRITE" }
    }
  end

  def test_lapse_horizon_cases
    cases = GOLDEN.fetch("lapse_horizon_cases")
    assert_equal 12, cases.size
    cases.each do |c|
      dto = state_of(c["state"], c["expiry"])
      assert_equal c["horizon"], Horizon.collection_horizon(dto, c["max_lease"], Horizon::LEGACY), c.inspect
    end
  end

  def test_horizon_mode_cases
    cases = GOLDEN.fetch("horizon_mode_cases")
    assert_equal 64, cases.size
    assert_equal %w[lapsed withdrawn completed withdrawn_completed].sort, cases.map { |c| c["state"] }.uniq.sort
    cases.each do |c|
      rule = { "legacy" => Horizon::LEGACY, "per-entry" => Horizon::PER_ENTRY }.fetch(c["mode"])
      dto = state_of(c["state"], c["expiry"])
      assert_equal c["horizon"], Horizon.collection_horizon(dto, c["max_lease"], rule), c.inspect
      assert_equal c["collectable"], Horizon.collectable?(dto, c["now"], c["max_lease"], rule), c.inspect
    end
  end

  def test_the_text_digest_hashes_are_the_golden_ones
    state = CBOR.load(hex("delta_cbor"))["state"]
    assert_equal GOLDEN["space_state_hash"], TextDigest.state_hash(state)
    assert_equal TextDigest.state_hash(state), TextDigest.state_hash(state.merge("adds" => state["adds"] * 2)),
                 "a dot set hashes by membership"
    refute_equal TextDigest.state_hash(state), TextDigest.state_hash(state.merge("completed" => true))
    claim = CBOR.load(hex("claim_delta_cbor"))["claim"]["claim"]
    assert_equal GOLDEN["space_claim_hash"], TextDigest.claim_hash(claim)
    GOLDEN["java_double_strings"].each { |input, text| assert_equal text, TextDigest.java_double(Float(input)), input }
    assert_equal "c:a=2\ne:a=3\ne:b=1\na:e:z=9\n".b, TextDigest.digest({ "e:b" => "1", "c:a" => "2", "e:a" => "3" },
                                                                      ["e:z=9"])
    # Java's TreeMap orders by UTF-16 code units, where U+FF5E sorts after a surrogate pair.
    assert_equal "e:\u{1F600}=1\ne:\u{FF5E}=2\n".b, TextDigest.digest({ "e:\u{FF5E}" => "2", "e:\u{1F600}" => "1" })
  end

  # ------------------------------------------------------------ the renewal rule

  def test_a_renewal_never_shortens_and_one_that_would_sends_nothing
    p = peer
    id = p.write_entry("tasks", TYPE, { "topic" => "t" }, lease_millis: 10 * MINUTE)
    stamp = p.states[id]["leaseStamp"]
    @clock.advance(MINUTE)
    sent = p.sent.size
    assert_equal T0 + (10 * MINUTE), p.renew_entry("tasks", id, lease_millis: 2 * MINUTE)
    assert_equal [sent, stamp, 1], [p.sent.size, p.states[id]["leaseStamp"], p.renewals_kept]
    assert_equal T0 + MINUTE + (20 * MINUTE), p.renew_entry("tasks", id, lease_millis: 20 * MINUTE)
    assert_equal sent + 1, p.sent.size
    assert_equal "RUMOR", p.sent.last[0]
    assert_raises(ArgumentError) { p.renew_entry("tasks", id, lease_millis: -1) }
  end

  def test_a_renewal_needs_the_entry_present_and_unexpired_here
    p = peer
    lapsing = p.write_entry("tasks", TYPE, { "topic" => "a" }, lease_millis: MINUTE)
    cancelled = p.write_entry("tasks", TYPE, { "topic" => "b" }, lease_millis: HOUR)
    completed = p.write_entry("tasks", TYPE, { "topic" => "c" }, lease_millis: HOUR)
    p.cancel_entry("tasks", cancelled)
    p.states[completed] = p.states[completed].merge("completed" => true)
    @clock.advance(MINUTE)
    sent = p.sent.size
    [lapsing, cancelled, completed].each do |id|
      error = assert_raises(ArgumentError) { p.renew_entry("tasks", id, lease_millis: HOUR) }
      assert_match(/is not renewed/, error.message)
    end
    assert_equal sent, p.sent.size, "a refused renewal sends nothing"
    other = Identity.generate
    foreign = write_by(other, HOUR)
    p.fold_state(foreign)
    assert_raises(ArgumentError) { p.renew_entry("tasks", foreign["record"]["entryId"]) }
  end

  def test_a_take_renewal_reads_extend_the_same_way
    p = peer
    id = p.write_entry("tasks", TYPE, { "topic" => "t" }, lease_millis: HOUR)
    holder = @identity.agent("ruby")
    claim = Wire.take_claim(id, space_id, 1, Wire.hlc_now(holder, now), holder, 0.0, now + (2 * MINUTE))
    p.claims[id] = Wire.signed_claim(claim, @identity)
    sent = p.sent.size
    assert_equal now + (2 * MINUTE), p.renew_claim("tasks", id, lease_millis: MINUTE)
    assert_equal sent, p.sent.size
    assert_equal now + (5 * MINUTE), p.renew_claim("tasks", id, lease_millis: 5 * MINUTE)
    assert_equal sent + 1, p.sent.size
    @clock.advance(6 * MINUTE)
    assert_raises(ArgumentError) { p.renew_claim("tasks", id, lease_millis: MINUTE) }
  end

  # RE-H-01, as Java's ReplicatedSpace.noteShortening: the first renewal of a space that asked for
  # less than the lease had left is logged once, at info; renewals_kept counts every one.
  def test_a_shortening_renewal_is_logged_once_per_space_and_counted_every_time
    log = StringIO.new
    p = CapturingPeer.new(@identity, GROUP, clock: @clock, logger: Logger.new(log))
    id = p.write_entry("tasks", TYPE, { "topic" => "t" }, lease_millis: 10 * MINUTE)
    other = p.write_entry("notes", TYPE, { "topic" => "n" }, lease_millis: 10 * MINUTE)
    holder = @identity.agent("ruby")
    claim = Wire.take_claim(id, space_id, 1, Wire.hlc_now(holder, now), holder, 0.0, now + (5 * MINUTE))
    p.claims[id] = Wire.signed_claim(claim, @identity)
    assert_equal T0 + (10 * MINUTE), p.renew_entry("tasks", id, lease_millis: 10 * MINUTE)
    assert_empty log.string, "a renewal that asks for exactly what is left shortens nothing"
    p.renew_entry("tasks", id, lease_millis: 2 * MINUTE)
    p.renew_entry("tasks", id, lease_millis: MINUTE)
    p.renew_claim("tasks", id, lease_millis: MINUTE)
    lines = log.string.lines
    assert_equal 1, lines.size, "one line for the space, however many renewals asked for less"
    assert_match(/INFO.*space tasks: the write lease of entry #{id} was renewed for #{8 * MINUTE} ms less/, lines[0])
    assert_match(/never shortens a lease \(SPEC 7\.2\)\. Cancel and write again/, lines[0])
    p.renew_entry("notes", other, lease_millis: MINUTE)
    assert_equal 2, log.string.lines.size, "another space logs its own first shortening"
    assert_match(/space notes: the write lease of entry #{other}/, log.string.lines[1])
    assert_equal 5, p.renewals_kept, "every kept renewal counts, the logged and the silent"
  end

  def test_the_shortening_log_can_be_turned_off_and_the_count_runs_on
    log = StringIO.new
    p = CapturingPeer.new(@identity, GROUP, clock: @clock, logger: Logger.new(log))
    p.renew_shortening_log = false
    id = p.write_entry("tasks", TYPE, { "topic" => "t" }, lease_millis: 10 * MINUTE)
    p.renew_entry("tasks", id, lease_millis: MINUTE)
    assert_empty log.string
    assert_equal 1, p.renewals_kept
  end

  def test_a_subscription_renewal_never_shortens_its_lease
    p = peer
    subscription = p.space("tasks").notify(Rbe::Job, lease: "10m") { |_| nil }
    subscription.renew("1m")
    @clock.advance(2 * MINUTE)
    refute subscription.lapsed?(now), "a shorter renewal kept the ten minutes"
    subscription.renew("20m")
    @clock.advance(15 * MINUTE)
    refute subscription.lapsed?(now)
    @clock.advance(10 * MINUTE)
    subscription.renew("1h")
    refute subscription.open?, "a lapsed subscription is not renewed: it closes as lapsed"
    assert_equal "lapsed", subscription.reason
  end

  # ------------------------------------------------------------ the horizons

  def test_the_peer_advertises_the_horizon_hint_unless_legacy
    assert_equal "1", peer.wire_hints[Horizon::HINT]
    refute peer(horizon: Horizon::LEGACY).wire_hints.key?(Horizon::HINT)
    assert_raises(ArgumentError) { CapturingPeer.new(@identity, GROUP, clock: @clock, horizon: :sometimes) }
  end

  def test_the_legacy_horizons_lapse_complete_and_withdraw
    p = peer(horizon: Horizon::LEGACY)
    writer = Identity.generate
    long = write_by(writer, HOUR) # the space's longest lease: 2 x maxLease is two hours
    p.fold_state(long)
    lapse = write_by(writer, MINUTE)
    p.fold_state(lapse)
    withdrawn = write_by(writer, 10 * MINUTE)
    p.fold_state(cancel_by(writer, withdrawn))
    assert_equal HOUR, p.max_lease_millis("tasks")
    @clock.advance(MINUTE + (5 * MINUTE))
    assert_equal [lapse["record"]["entryId"]], p.collect_garbage, "a lapse keeps five minutes, not two leases"
    @clock.advance((10 * MINUTE) + (2 * HOUR) - (6 * MINUTE) - 1)
    assert_empty p.collect_garbage - [long["record"]["entryId"]]
    @clock.advance(1)
    assert_includes p.collect_garbage, withdrawn["record"]["entryId"]
    assert_equal :legacy, p.horizon_mode("tasks")
    assert_equal 3, p.states_collected
  end

  def test_the_drift_floor_keeps_a_withdrawal_ten_minutes_under_both_rules
    [Horizon::LEGACY, Horizon::PER_ENTRY].each do |rule|
      @clock = Testing::TestClock.new(T0)
      p = peer(horizon: rule)
      id = p.write_entry("tasks", TYPE, { "topic" => "t" }, lease_millis: MINUTE)
      p.cancel_entry("tasks", id)
      @clock.advance(MINUTE + (2 * MINUTE) + 1) # past 2 x maxLease, which the floor overrides
      assert_empty p.collect_garbage, rule.to_s
      @clock.advance((8 * MINUTE) - 2)
      assert_empty p.collect_garbage, rule.to_s
      @clock.advance(1)
      assert_equal [id], p.collect_garbage, rule.to_s
    end
  end

  def test_the_per_entry_horizon_engages_settles_and_collects_a_vouched_withdrawal_early
    p = peer
    member = Identity.generate
    advertise(p, member, { Horizon::HINT => "1" })
    p.fold_state(write_by(member, HOUR)) # the longest lease: one hour
    judge_rounds(p)
    assert_equal :settling, p.horizon_mode("tasks")
    assert_equal 1, p.horizon_tracker("tasks").engagements
    # One maximum lease plus the grace, the member re-advertising as it does.
    13.times do
      @clock.advance(5 * MINUTE)
      advertise(p, member, { Horizon::HINT => "1" })
      p.collect_garbage
    end
    assert_equal :per_entry, p.horizon_mode("tasks")
    assert_equal 1, p.horizon_tracker("tasks").settlements
    write = write_by(member, HOUR)
    expiry = Horizon.expiry_of(write)
    p.fold_state(cancel_by(member, write))
    live_for(p, member, HOUR + (10 * MINUTE) - 1)
    refute_includes p.collect_garbage, write["record"]["entryId"]
    @clock.advance(1)
    assert_equal expiry + (10 * MINUTE), now
    assert_includes p.collect_garbage, write["record"]["entryId"], "L + max(5 min, MAX_DRIFT), not L + 2 h"
  end

  # Settles the per-entry rule with one hinted member in view, which writes an
  # hour lease, and returns the peer.
  def settled_peer(member)
    p = peer
    advertise(p, member, { Horizon::HINT => "1" })
    p.fold_state(write_by(member, HOUR))
    judge_rounds(p)
    13.times do
      @clock.advance(5 * MINUTE)
      advertise(p, member, { Horizon::HINT => "1" })
      p.collect_garbage
    end
    assert_equal :per_entry, p.horizon_mode("tasks")
    p
  end

  def test_the_writers_half_keeps_a_newcomers_withdrawal_on_the_legacy_horizon
    p = settled_peer(Identity.generate)
    newcomer = Identity.generate
    advertise(p, newcomer, { Horizon::HINT => "1" })
    write = write_by(newcomer, 10 * MINUTE)
    p.fold_state(cancel_by(newcomer, write))
    @clock.advance(20 * MINUTE)
    advertise(p, newcomer, { Horizon::HINT => "1" })
    refute_includes p.collect_garbage, write["record"]["entryId"],
                    "a writer in view for less than maxLease + 5 min is not vouched for"
    assert_equal :per_entry, p.horizon_mode("tasks"), "the view's half still allows it"
    # A writer the view never held keeps the legacy horizon too.
    stranger = Identity.generate
    gone = write_by(stranger, 10 * MINUTE)
    p.fold_state(cancel_by(stranger, gone))
    @clock.advance(20 * MINUTE)
    refute_includes p.collect_garbage, gone["record"]["entryId"]
    @clock.advance(2 * HOUR)
    assert_includes p.collect_garbage, gone["record"]["entryId"], "L + 2 x maxLease at the latest"
  end

  def test_an_unhinted_member_in_view_disengages_at_once
    member = Identity.generate
    p = settled_peer(member)
    older = Identity.generate
    advertise(p, older, {}) # an older release, without the hint
    own = p.write_entry("tasks", TYPE, { "topic" => "t" }, lease_millis: 10 * MINUTE)
    p.cancel_entry("tasks", own)
    5.times do # both stay live members, re-advertising
      @clock.advance(4 * MINUTE)
      advertise(p, member, { Horizon::HINT => "1" })
      advertise(p, older, {})
    end
    @clock.advance(1)
    refute_includes p.collect_garbage, own, "L + 10 min passed, but the legacy rule keeps L + 2 x maxLease"
    assert_equal :legacy, p.horizon_mode("tasks")
    assert_equal 1, p.horizon_tracker("tasks").disengagements
    # A member heard from without any card counts as lacking the hint too.
    q = settled_peer(Identity.generate)
    q.write_entry("tasks", TYPE, { "topic" => "held" }, lease_millis: HOUR) # a space with a state is judged
    q.collect_garbage
    assert_equal :per_entry, q.horizon_mode("tasks")
    stranger = Identity.generate
    q.handle(Wire.envelope(GROUP, "PING", stranger.peer_id, "#{now}:99:#{stranger.peer_id}", Wire.ping_body(1)))
    q.collect_garbage
    assert_equal :legacy, q.horizon_mode("tasks")
  end

  def test_the_door_refuses_a_collected_tombstone_and_acknowledges_it
    p = peer(horizon: Horizon::LEGACY)
    writer = Identity.generate
    write = write_by(writer, MINUTE)
    withdrawn = cancel_by(writer, write)
    p.fold_state(withdrawn)
    id = write["record"]["entryId"]
    @clock.advance(MINUTE + (10 * MINUTE))
    assert_equal [id], p.collect_garbage
    p.fold_state(withdrawn) # a lagging partner offers it again
    p.fold_state(write)     # and the old present copy, long lapsed
    refute p.states.key?(id), "a collected tombstone never returns"
    assert_equal 2, p.states_refused_collected
    digest = p.text_digest("tasks")
    assert_includes digest, "a:#{TextDigest.state_line(id, withdrawn)}\n"
    assert_includes digest, "a:#{TextDigest.state_line(id, write)}\n"
    @clock.advance(2 * HOUR)
    refute_includes p.text_digest("tasks"), "a:", "a collected tombstone's acknowledgement is forgotten past its horizon"
  end

  def test_collection_drops_the_claim_the_block_and_the_watch_marks
    network = Testing::Network.new
    a = Testing::NetPeer.new(network, GROUP, clock: @clock)
    space = a.space("tasks")
    events = []
    space.watch(Rbe::Job) { |e| events << e.kind }
    big = "x" * (Wire::INLINE_PAYLOAD_LIMIT + 10)
    id = space.write(Rbe::Job.new(topic: big), lease: "1m")
    ref = a.states[id]["record"]["payloadRef"]
    refute_nil ref
    assert a.blocks.key?(ref)
    taken = space.take(Rbe::Job, lease: "30s", timeout: "3s")
    refute_nil taken
    taken.complete
    assert_equal %w[WRITTEN TAKEN COMPLETED], events
    @clock.advance(MINUTE + (2 * MINUTE))
    assert_equal [id], a.collect_garbage
    refute a.claims.key?(id)
    refute a.blocks.key?(ref), "a block no remaining entry names goes with its entry"
    marks = space.instance_variable_get(:@watchers).values.first[2]
    assert_empty marks
  ensure
    a&.close
  end

  # ------------------------------------------------------------ the budgeted pull

  def deliver_pull(peer, partner, deltas, remainder = nil)
    body = { "deltas" => CBOR.canonical_map(deltas) }
    body["remainder"] = CBOR.canonical_map(remainder) unless remainder.nil?
    @stamps += 1
    peer.handle(Wire.envelope(GROUP, "PULL_RESP", partner.peer_id, "#{now}:#{@stamps}:#{partner.peer_id}",
                              CBOR.dump(body), peer.identity.peer_id))
  end

  def sync(states) = CBOR.dump({ "states" => states, "claims" => {} })

  def digests_sent(peer) = peer.sent.select { |kind, _| kind == "DIGEST" }.map { |_, body| Wire.decode_body("DIGEST", body) }

  def test_a_partner_without_wire_ae_2_gets_the_unbudgeted_get_space
    p = peer
    partner = Identity.generate
    p.partner!(partner.peer_id)
    advertise(p, partner, { Horizon::HINT => "1" })
    p.pull_space("tasks")
    sent = digests_sent(p)
    assert_equal 1, sent.size
    refute sent.first.key?("budget")
    assert_equal "".b, sent.first["digests"]["space:tasks"]
  end

  def test_a_budgeted_get_space_continues_with_the_text_digest_until_nothing_is_left
    p = peer
    partner = Identity.generate
    p.partner!(partner.peer_id)
    advertise(p, partner, { "wire.ae" => "2", Horizon::HINT => "1" })
    p.pull_budget = 4096
    p.pull_space("tasks")
    revocations, first = digests_sent(p)
    refute revocations.key?("budget"), "the revocation streams go unbudgeted, ahead of the space"
    assert_equal Revocation::STREAMS.sort, revocations["digests"].keys.sort
    assert_equal({ "digests" => { "space:tasks" => "".b }, "budget" => 4096 }, first)
    writer = Identity.generate
    newest = write_by(writer, HOUR)
    deliver_pull(p, partner, { "space:tasks" => sync([newest]) }, { "space:tasks" => 2 })
    continuation = digests_sent(p).last
    assert_equal 4096, continuation["budget"]
    assert_equal "e:#{newest['record']['entryId']}=#{TextDigest.state_hash(newest)}\n".b,
                 continuation["digests"]["space:tasks"]
    assert_equal 1, p.pull_continuations
    older = [write_by(writer, HOUR), write_by(writer, HOUR)]
    deliver_pull(p, partner, { "space:tasks" => sync(older) }, { "space:tasks" => 0 })
    assert_equal 3, digests_sent(p).size, "a remainder of 0 ends the pull"
    assert_equal 3, p.states.size
    # A late duplicate of an answer, with nothing new in it, sends nothing.
    deliver_pull(p, partner, { "space:tasks" => sync([newest]) }, { "space:tasks" => 2 })
    assert_equal 3, digests_sent(p).size
    # The next pull starts from what this replica holds.
    p.pull_space("tasks")
    lines = digests_sent(p).last["digests"]["space:tasks"].split("\n")
    assert_equal 3, lines.size
    assert(lines.all? { |line| line.start_with?("e:") })
  end

  def test_a_budgeted_pull_whose_answer_brings_nothing_new_stops_and_counts
    p = peer
    partner = Identity.generate
    p.partner!(partner.peer_id)
    advertise(p, partner, { "wire.ae" => "2" })
    held = write_by(Identity.generate, HOUR)
    p.fold_state(held)
    p.pull_space("tasks")
    deliver_pull(p, partner, { "space:tasks" => sync([held]) }, { "space:tasks" => 5 })
    assert_equal 2, digests_sent(p).size, "no continuation after an answer that changed nothing"
    assert_equal [0, 1], [p.pull_continuations, p.pulls_stalled]
    # An unasked remainder is ignored: no budgeted pull is open.
    deliver_pull(p, partner, { "space:tasks" => sync([write_by(Identity.generate, HOUR)]) }, { "space:tasks" => 5 })
    assert_equal 2, digests_sent(p).size
  end

  def test_a_lost_answer_leaves_the_next_pull_to_repair
    p = peer
    partner = Identity.generate
    p.partner!(partner.peer_id)
    advertise(p, partner, { "wire.ae" => "2" })
    p.pull_space("tasks")
    p.pull_space("tasks") # a take polling again while the answer is in flight does not double the pull
    assert_equal 2, digests_sent(p).size
    @clock.advance(Peer::PULL_ANSWER_WAIT_MILLIS)
    p.pull_space("tasks") # the first answer never came: past the wait, the next pull asks again
    assert_equal 4, digests_sent(p).size
    deliver_pull(p, partner, { "space:tasks" => sync([write_by(Identity.generate, HOUR)]) }, { "space:tasks" => 1 })
    assert_equal 5, digests_sent(p).size
    assert_equal 1, p.pull_continuations
  end

  def test_no_budget_when_the_partners_card_lapsed_or_the_budget_is_off
    p = peer
    partner = Identity.generate
    p.partner!(partner.peer_id)
    advertise(p, partner, { "wire.ae" => "2" })
    p.pull_budget = nil
    p.pull_space("tasks")
    refute digests_sent(p).last.key?("budget")
    p.pull_budget = Peer::DEFAULT_PULL_BUDGET
    @clock.advance(11 * MINUTE)
    p.pull_space("tasks")
    refute digests_sent(p).last.key?("budget"), "a lapsed card is no evidence of wire.ae=2"
    assert_raises(ArgumentError) { p.pull_budget = 0 }
  end

  # ------------------------------------------------------------ completed on arrival

  def completed_elsewhere(payload_topic)
    network = Testing::Network.new
    a = Testing::NetPeer.new(network, GROUP, clock: @clock)
    space = a.space("tasks")
    id = space.write(Rbe::Job.new(topic: payload_topic), lease: "10m")
    taken = space.take(Rbe::Job, lease: "1m", timeout: "3s")
    refute_nil taken
    taken.complete
    [a, id]
  ensure
    a&.close
  end

  def test_an_entry_first_learned_completed_raises_completed_and_never_written
    a, id = completed_elsewhere("late")
    p = peer
    events = []
    p.space("tasks").watch(Rbe::Job) { |e| events << [e.kind, e.value.topic] }
    p.fold_claim(id, a.claims[id])
    p.fold_state(a.states[id])
    assert_equal [%w[COMPLETED late]], events
    p.fold_state(a.states[id]) # redelivered
    assert_equal 1, events.size
  end

  def test_a_completed_bulk_entry_whose_block_is_not_held_raises_nothing_and_fetches_nothing
    a, id = completed_elsewhere("y" * (Wire::INLINE_PAYLOAD_LIMIT + 10))
    p = peer
    events = []
    p.space("tasks").watch(Rbe::Job) { |e| events << e.kind }
    p.fold_claim(id, a.claims[id])
    p.fold_state(a.states[id])
    assert_empty events
    refute(p.sent.any? { |kind, _| kind == "BLOCK_WANT" }, "no block is fetched for an event alone")
  end
end
