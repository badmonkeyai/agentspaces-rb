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
require "pp"
require "tmpdir"

# ROBUSTNESS.md 6a at the socket: late, replayed, unknown, and malformed
# frames are the normal case and never stop the reader; a lost socket is a
# hiccup; the owner's close is final; a forked child never speaks on the
# parent's connection.
class RobustnessTest < Minitest::Test
  include AgentSpaces

  GROUP = "zRubyRobustness"

  # A peer whose sends are captured.
  class CapturingPeer < Peer
    attr_reader :sent

    def initialize(clock: nil)
      super(AgentSpaces::Identity.generate, GROUP, clock: clock)
      @sent = []
    end

    private

    def send_frame(kind, body, to = nil) = @sent << [kind, body, to]
  end

  def frame(sender, kind, body, to, stamp)
    Wire.decode_frame(Wire.encode_frame(Wire.envelope(GROUP, kind, sender.peer_id, stamp, body, to), sender))
  end

  def stamp(ms, logical = 0) = "#{ms}:#{logical}:other"

  def kinds(peer) = peer.sent.map(&:first)

  def eventually(timeout = 5.0)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    sleep 0.05 until yield || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
    yield
  end

  def test_a_replayed_frame_is_dropped_and_counted
    peer = CapturingPeer.new
    other = Identity.generate
    now = peer.now_ms
    ping = frame(other, "PING", Wire.ping_body(7), peer.identity.peer_id, stamp(now, 1))
    peer.handle(ping)
    assert_equal ["ACK"], kinds(peer)
    2.times { peer.handle(ping) }
    assert_equal ["ACK"], kinds(peer), "a replayed probe earns no second ACK"
    assert_equal 2, peer.frames.replayed
    peer.handle(frame(other, "PING", Wire.ping_body(8), peer.identity.peer_id, stamp(now, 2)))
    assert_equal %w[ACK ACK], kinds(peer)
  end

  def test_stale_and_far_ahead_frames_are_dropped_quietly
    peer = CapturingPeer.new
    other = Identity.generate
    now = peer.now_ms
    peer.handle(frame(other, "PING", Wire.ping_body(1), peer.identity.peer_id,
                      stamp(now - Wire::MAX_FRAME_AGE_MILLIS - 1000)))
    peer.handle(frame(other, "PING", Wire.ping_body(2), peer.identity.peer_id,
                      stamp(now + Wire::MAX_HLC_SKEW_MILLIS + 60_000)))
    assert_empty peer.sent
    assert_equal [1, 1], [peer.frames.stale, peer.frames.ahead]
    peer.handle(frame(other, "PING", Wire.ping_body(3), peer.identity.peer_id, stamp(now - (Wire::MAX_FRAME_AGE_MILLIS / 2))))
    peer.handle(frame(other, "PING", Wire.ping_body(4), peer.identity.peer_id, stamp(now + (Wire::MAX_HLC_SKEW_MILLIS / 2))))
    assert_equal %w[ACK ACK], kinds(peer)
  end

  # HLC logical counter, 2026-11-08 (Rust team report): one signed stamp just
  # under the skew ceiling with a huge logical counter must never reach the
  # clock or any fold, and the clock carries into the next millisecond
  # instead of growing the counter past the shared limit.
  LIMIT = 65_536
  # The largest logical counter the Java and Rust clocks hold (a signed 32-bit int).
  HOSTILE_LOGICAL = 2_147_483_647
  WALL = 1_800_000_000_000

  def clock_node = "hlc-#{SecureRandom.hex(6)}"

  def tuple(stamp) = Wire.hlc_tuple(stamp).first(2)

  def hostile_stamp(now, node = "other") = "#{now + Wire::MAX_HLC_SKEW_MILLIS - 1000}:#{HOSTILE_LOGICAL}:#{node}"

  def test_the_clock_refuses_a_logical_counter_above_the_limit_and_accepts_the_limit
    node = clock_node
    assert_equal [WALL, 0], tuple(Wire.hlc_now(node, WALL))
    Wire.hlc_observe(node, hostile_stamp(WALL), WALL)
    Wire.hlc_observe(node, "#{WALL + 1000}:#{LIMIT + 1}:other", WALL)
    assert_equal [WALL, 1], tuple(Wire.hlc_now(node, WALL)), "the hostile stamps never reached the clock"
    Wire.hlc_observe(node, "#{WALL + 1000}:#{LIMIT}:other", WALL)
    assert_equal [WALL + 1001, 0], tuple(Wire.hlc_now(node, WALL)), "the clock merges a stamp at the limit and carries it"
    assert_equal LIMIT, Wire::HLC_LOGICAL_LIMIT
  end

  def test_a_counter_at_the_limit_carries_into_the_next_millisecond
    node = clock_node
    stamps = Array.new(LIMIT + 1) { Wire.hlc_now(node, WALL) }
    assert_equal [WALL, LIMIT], tuple(stamps.last)
    assert_equal [WALL + 1, 0], tuple(Wire.hlc_now(node, WALL))
  end

  def test_stamps_after_an_accepted_limit_stamp_never_repeat_and_always_increase
    node = clock_node
    Wire.hlc_observe(node, "#{WALL + 5}:#{LIMIT}:other", WALL)
    stamps = Array.new(3 * LIMIT) { Wire.hlc_now(node, WALL) }
    assert_equal stamps.size, stamps.uniq.size
    stamps.map { |s| tuple(s) }.each_cons(2) { |a, b| assert_operator (a <=> b), :<, 0, "#{a} then #{b}" }
    assert(stamps.all? { |s| tuple(s)[1] <= LIMIT })
  end

  def test_the_peer_refuses_and_counts_a_frame_whose_logical_counter_is_above_the_limit
    peer = CapturingPeer.new
    other = Identity.generate
    now = peer.now_ms
    peer.handle(frame(other, "PING", Wire.ping_body(1), peer.identity.peer_id, hostile_stamp(now)))
    peer.handle(frame(other, "PING", Wire.ping_body(2), peer.identity.peer_id, "#{now}:#{LIMIT + 1}:other"))
    assert_empty peer.sent
    assert_equal 2, peer.frames.refused
    assert_equal 2, peer.frames.to_h["refused"]
    assert_operator Wire.hlc_physical(Wire.hlc_now(peer.identity.peer_id, now)), :<=, now,
                    "the refused frame never reached the clock"
    peer.handle(frame(other, "PING", Wire.ping_body(3), peer.identity.peer_id, "#{now}:#{LIMIT}:other"))
    assert_equal ["ACK"], kinds(peer)
  end

  # A write by writer whose record is issued at issued and whose lease stamp
  # is lease_stamp, both signed as the issuer signs them.
  def signed_write(writer, issued, lease_stamp, now)
    _, body = Wire.entry_delta("tasks", GROUP, "com.acme.Task#v1", CBOR.dump({ "topic" => "t" }), writer, "w",
                               60_000, now_ms: now)
    dto = CBOR.load(CBOR.load(body)["payload"])["state"]
    record = dto["record"]
    record["issued"] = issued
    record["sig"] = writer.sign(CBOR.dump(Wire.sign_view_of(record)))
    dto["leaseStamp"] = lease_stamp
    Wire.sign_state(dto, writer)
  end

  # The same entry renewed by its issuer under lease_stamp, a minute later.
  def signed_renewal(writer, dto, lease_stamp, now)
    renewal = dto.dup
    renewal["leaseStamp"] = lease_stamp
    renewal["leaseValue"] = dto["leaseValue"].merge("expiresAtMillis" => now + 120_000)
    Wire.sign_state(renewal, writer)
  end

  def test_the_peer_refuses_a_folded_record_or_lease_stamp_above_the_limit
    peer = CapturingPeer.new
    writer = Identity.generate
    issuer = writer.agent("w")
    now = peer.now_ms
    hostile = hostile_stamp(now, issuer)
    refused = signed_write(writer, hostile, hostile, now)
    peer.fold_state(refused)
    refute peer.states.key?(refused["record"]["entryId"]), "the peer refuses a record issued above the limit"

    honest = signed_write(writer, "#{now}:#{LIMIT}:#{issuer}", "#{now}:#{LIMIT}:#{issuer}", now)
    entry_id = honest["record"]["entryId"]
    peer.fold_state(honest)
    assert peer.states.key?(entry_id), "the peer folds a record issued at the limit"

    peer.fold_state(signed_renewal(writer, honest, hostile, now))
    assert_equal "#{now}:#{LIMIT}:#{issuer}", peer.states[entry_id]["leaseStamp"], "the peer refuses the hostile renewal"
    renewed = "#{now + 1}:0:#{issuer}"
    peer.fold_state(signed_renewal(writer, honest, renewed, now))
    assert_equal renewed, peer.states[entry_id]["leaseStamp"]
    assert_equal now + 120_000, peer.states[entry_id]["leaseValue"]["expiresAtMillis"]
  end

  def test_the_peer_refuses_a_folded_claim_whose_stamp_is_above_the_limit
    peer = CapturingPeer.new
    writer = Identity.generate
    now = peer.now_ms
    write = signed_write(writer, "#{now}:0:#{writer.agent('w')}", "#{now}:0:#{writer.agent('w')}", now)
    entry_id = write["record"]["entryId"]
    peer.fold_state(write)
    taker = Identity.generate
    holder = taker.agent("t")
    space_id = write["record"]["spaceId"]
    hostile = Wire.take_claim(entry_id, space_id, 1, hostile_stamp(now, holder), holder, 0.0, now + 60_000)
    peer.fold_claim(entry_id, Wire.signed_claim(hostile, taker))
    assert_nil peer.claim_of(entry_id), "the peer refuses a claim stamped above the limit"
    honest = Wire.take_claim(entry_id, space_id, 1, "#{now}:#{LIMIT}:#{holder}", holder, 0.0, now + 60_000)
    peer.fold_claim(entry_id, Wire.signed_claim(honest, taker))
    assert_equal honest, peer.claim_of(entry_id)
  end

  # HLC logical counter, 2026-11-08 (Rust team report), round two: every
  # merge and ordering point reads a stamp as Java's HlcTimestamp.parse reads
  # it, so a negative, unreadable, or fractional counter never reaches the
  # clock, the claim lattice, or a lease.
  HOSTILE_COUNTERS = %w[-1 x 0x10001 1.5].freeze

  def test_the_strict_parser_accepts_only_what_java_parses_within_the_limit
    assert_equal [5, 0, "n"], Wire.hlc_parse("5:0:n")
    assert_equal [0, LIMIT, "n"], Wire.hlc_parse("0:#{LIMIT}:n")
    assert_equal [(2**63) - 1, 0, "n"], Wire.hlc_parse("#{(2**63) - 1}:0:n")
    refused = ["5:-1:n", "5:x:n", "5:0x10001:n", "5:1.5:n", "5:1e3:n", "5::n", "5:+1:n", "5: 1:n", "5:1_0:n",
               "5:#{LIMIT + 1}:n", "-5:0:n", "+5:0:n", "1.5:0:n", "5e3:0:n", ":0:n", "#{2**63}:0:n", "5:0:",
               "5:0", "5", "", "5:0:a:b", nil, 5, ["5:0:n"]]
    refused.each do |stamp|
      assert_nil Wire.hlc_parse(stamp), "the parser refuses #{stamp.inspect}"
      refute Wire.hlc_acceptable?(stamp), "the parser refuses #{stamp.inspect}"
      assert_raises(ArgumentError, "#{stamp.inspect} has no tuple") { Wire.hlc_tuple(stamp) }
    end
  end

  def test_the_peer_refuses_and_counts_frames_with_a_negative_unreadable_or_fractional_counter
    peer = CapturingPeer.new
    other = Identity.generate
    now = peer.now_ms
    HOSTILE_COUNTERS.each_with_index do |counter, i|
      peer.handle(frame(other, "PING", Wire.ping_body(i), peer.identity.peer_id, "#{now + 1000}:#{counter}:other"))
    end
    assert_empty peer.sent
    assert_equal HOSTILE_COUNTERS.size, peer.frames.refused
    stamp = Wire.hlc_now(peer.identity.peer_id, now)
    assert_operator tuple(stamp)[1], :>=, 0, "the clock holds no negative counter"
    assert_operator Wire.hlc_physical(stamp), :<=, now, "no refused frame reached the clock"
    peer.handle(frame(other, "PING", Wire.ping_body(9), peer.identity.peer_id, stamp(now, 3)))
    assert_equal ["ACK"], kinds(peer)
  end

  def test_the_drift_cap_holds_after_a_carry_so_an_honest_receiver_admits_the_next_stamp
    node = clock_node
    Wire.hlc_observe(node, "#{WALL + Wire::MAX_HLC_SKEW_MILLIS}:#{LIMIT}:other", WALL)
    carried = Wire.hlc_now(node, WALL)
    assert_equal [WALL + Wire::MAX_HLC_SKEW_MILLIS, 0], tuple(carried), "the carry lands on the cap"
    receiver = Wire::FrameFilter.new
    assert receiver.admit({ "from" => node, "stamp" => carried }, WALL), "a receiver's ASF-020 check admits it"
    assert_equal 0, receiver.ahead

    beyond = clock_node
    Wire.hlc_observe(beyond, "#{WALL + Wire::MAX_HLC_SKEW_MILLIS + 60_000}:7:other", WALL)
    assert_equal [WALL + Wire::MAX_HLC_SKEW_MILLIS - 1, 8], tuple(Wire.hlc_now(beyond, WALL)),
                 "a stamp past the cap merges one millisecond inside it"
  end

  def test_the_peer_refuses_and_counts_states_with_a_negative_unreadable_or_fractional_stamp
    peer = CapturingPeer.new
    writer = Identity.generate
    issuer = writer.agent("w")
    now = peer.now_ms
    HOSTILE_COUNTERS.each do |counter|
      hostile = "#{now}:#{counter}:#{issuer}"
      refused = signed_write(writer, hostile, "#{now}:0:#{issuer}", now)
      peer.fold_state(refused)
      refute peer.states.key?(refused["record"]["entryId"]), "the peer refuses a record issued at #{counter}"
    end
    honest = signed_write(writer, "#{now}:0:#{issuer}", "#{now}:0:#{issuer}", now)
    entry_id = honest["record"]["entryId"]
    peer.fold_state(honest)
    HOSTILE_COUNTERS.each do |counter|
      peer.fold_state(signed_renewal(writer, honest, "#{now + 1}:#{counter}:#{issuer}", now))
    end
    assert_equal "#{now}:0:#{issuer}", peer.states[entry_id]["leaseStamp"], "no hostile renewal merged"
    assert_equal 2 * HOSTILE_COUNTERS.size, peer.refused_stamps["states"]
    renewed = "#{now + 1}:0:#{issuer}"
    peer.fold_state(signed_renewal(writer, honest, renewed, now))
    assert_equal renewed, peer.states[entry_id]["leaseStamp"], "a later honest renewal merges"
  end

  def test_the_peer_refuses_and_counts_hostile_claims_and_a_later_honest_claim_still_merges
    peer = CapturingPeer.new
    writer = Identity.generate
    now = peer.now_ms
    write = signed_write(writer, "#{now}:0:#{writer.agent('w')}", "#{now}:0:#{writer.agent('w')}", now)
    entry_id = write["record"]["entryId"]
    space_id = write["record"]["spaceId"]
    peer.fold_state(write)
    taker = Identity.generate
    holder = taker.agent("t")
    hostile = HOSTILE_COUNTERS.map do |counter|
      Wire.signed_claim(Wire.take_claim(entry_id, space_id, 1, "#{now}:#{counter}:#{holder}", holder, 0.0,
                                        now + 60_000), taker)
    end
    hostile.each { |signed| peer.fold_claim(entry_id, signed) }
    assert_nil peer.claim_of(entry_id), "no hostile claim folded"
    assert_equal HOSTILE_COUNTERS.size, peer.refused_stamps["claims"]
    honest = Wire.signed_claim(Wire.take_claim(entry_id, space_id, 1, "#{now}:5:#{holder}", holder, 0.0,
                                               now + 60_000), taker)
    peer.fold_claim(entry_id, honest)
    assert_equal honest["claim"], peer.claim_of(entry_id), "a later honest claim merges"
    hostile.each do |signed|
      assert_equal honest, Wire.merge_claims(signed, honest), "the lattice never keeps a hostile claim"
      assert_equal honest, Wire.merge_claims(honest, signed)
    end
  end

  # HLC canonical stamps, 2026-11-08: a stamp is "<physical>:<logical>:<node>"
  # with no leading zero, ASCII digits alone, physical within a signed 64-bit
  # integer, and a node with no colon and no control character, so the bytes
  # a signer signed always equal the stamp's re-encoding. The peer refuses
  # every other text wherever it decodes, merges, orders, or deduplicates a stamp.
  NON_CANONICAL = ["007:0:n", "5:03:n", "00:0:n", "0:00:n", "05:0:n", "5:0:a\nb", "5:0:a\u0000b", "5:0:a\u007Fb",
                   "5:0:\t", "5:0:a\u001Fb", "５:0:n", "5:٥:n", "5 :0:n", "5:0 :n", " 5:0:n", "5:0:n".b,
                   "5:0:\xFF".dup.force_encoding(Encoding::UTF_8), "#{'9' * 400}:0:n", "5:#{'9' * 400}:n"].freeze

  def test_the_parser_reads_only_the_canonical_stamp_grammar
    assert_equal [0, 0, "n"], Wire.hlc_parse("0:0:n")
    assert_equal [10, 100, "n"], Wire.hlc_parse("10:100:n")
    assert_equal [5, 0, "z6Mk/agent one ñ\u{1F600}"], Wire.hlc_parse("5:0:z6Mk/agent one ñ\u{1F600}")
    NON_CANONICAL.each do |stamp|
      assert_nil Wire.hlc_parse(stamp), "the parser refuses #{stamp.inspect}"
      assert_nil Wire.hlc_decode(stamp), "the decoder refuses #{stamp.inspect}"
      assert_raises(ArgumentError, "#{stamp.inspect} has no physical part") { Wire.hlc_physical(stamp) }
    end
  end

  def test_the_decoder_reads_a_counter_above_the_limit_that_merge_points_refuse
    above = "5:#{LIMIT + 1}:n"
    assert_equal [5, LIMIT + 1, "n"], Wire.hlc_decode(above), "Java's HlcTimestamp.parse reads it"
    assert_equal 5, Wire.hlc_physical(above)
    assert_nil Wire.hlc_parse(above), "no merge point accepts it"
    assert_equal [5, HOSTILE_LOGICAL, "n"], Wire.hlc_decode("5:#{HOSTILE_LOGICAL}:n")
    assert_nil Wire.hlc_decode("5:#{HOSTILE_LOGICAL + 1}:n"), "Java's Integer.parseInt refuses it"
  end

  def test_the_peer_refuses_and_counts_frames_whose_stamp_is_not_canonical
    peer = CapturingPeer.new
    other = Identity.generate
    now = peer.now_ms
    stamps = ["0#{now}:1:other", "#{now}:01:other", "#{now}:1:other".b, "#{now}:1:ot\u0007her"]
    stamps.each_with_index do |stamp, i|
      peer.handle(frame(other, "PING", Wire.ping_body(i), peer.identity.peer_id, stamp))
    end
    assert_empty peer.sent
    assert_equal stamps.size, peer.frames.refused
    peer.handle(frame(other, "PING", Wire.ping_body(9), peer.identity.peer_id, "#{now}:1:other"))
    assert_equal ["ACK"], kinds(peer), "the canonical stamp is fresh, so the refused texts left no replay trace"
  end

  def test_a_non_canonical_claim_signed_over_its_raw_text_never_replaces_an_honest_claim
    peer = CapturingPeer.new
    writer = Identity.generate
    now = peer.now_ms
    write = signed_write(writer, "#{now}:0:#{writer.agent('w')}", "#{now}:0:#{writer.agent('w')}", now)
    entry_id = write["record"]["entryId"]
    space_id = write["record"]["spaceId"]
    peer.fold_state(write)
    honest_holder = Identity.generate
    honest = Wire.signed_claim(Wire.take_claim(entry_id, space_id, 1, "#{now}:5:#{honest_holder.agent('t')}",
                                               honest_holder.agent("t"), 0.0, now + 60_000), honest_holder)
    peer.fold_claim(entry_id, honest)
    rival_holder = Identity.generate
    rival = rival_holder.agent("t")
    forged = ["0#{now}:0:#{rival}", "#{now}:00:#{rival}", "#{now}:0:#{rival}".b].map do |stamp|
      Wire.signed_claim(Wire.take_claim(entry_id, space_id, 1, stamp, rival, 0.0, now + 60_000), rival_holder)
    end
    forged.each do |signed|
      assert Wire.verify_claim_proof(signed, now), "the rival signed the raw text"
      2.times { peer.fold_claim(entry_id, signed) }
      assert_equal honest["claim"], peer.claim_of(entry_id), "#{signed['claim']['stamp'].inspect} never wins"
      assert_equal honest, Wire.merge_claims(honest, signed)
      assert_equal honest, Wire.merge_claims(signed, honest)
    end
    assert_equal forged.size, peer.refused_stamps["claims"], "each distinct refused claim counts once"
  end

  # HLC canonical stamps, 2026-11-08: the peer counts a refused state or claim
  # after its signature verifies, and once per distinct one, as Java's
  # ReplicatedSpace does, so a forger cannot inflate the count and an honest
  # partner re-offering one state every round counts once.
  def test_the_peer_counts_a_refused_state_or_claim_after_verification_and_once_per_distinct_one
    peer = CapturingPeer.new
    writer = Identity.generate
    issuer = writer.agent("w")
    now = peer.now_ms
    hostile = hostile_stamp(now, issuer)
    forged = signed_write(writer, hostile, hostile, now).merge("stateSig" => "\x00".b * 64)
    3.times { peer.fold_state(forged) }
    assert_equal 0, peer.refused_stamps["states"], "an unverified state counts nothing"
    refused = signed_write(writer, hostile, hostile, now)
    3.times { peer.fold_state(refused) }
    assert_equal 1, peer.refused_stamps["states"], "a re-offered state counts once"
    refute peer.states.key?(refused["record"]["entryId"])
    peer.fold_state(signed_write(writer, hostile, hostile, now))
    assert_equal 2, peer.refused_stamps["states"], "a distinct state counts again"

    write = signed_write(writer, "#{now}:0:#{issuer}", "#{now}:0:#{issuer}", now)
    entry_id = write["record"]["entryId"]
    space_id = write["record"]["spaceId"]
    peer.fold_state(write)
    taker = Identity.generate
    holder = taker.agent("t")
    claim = Wire.take_claim(entry_id, space_id, 1, hostile_stamp(now, holder), holder, 0.0, now + 60_000)
    unsigned = Wire.signed_claim(claim, taker).merge("signature" => "\x00".b * 64)
    3.times { peer.fold_claim(entry_id, unsigned) }
    assert_equal 0, peer.refused_stamps["claims"], "an unverified claim counts nothing"
    signed = Wire.signed_claim(claim, taker)
    3.times { peer.fold_claim(entry_id, signed) }
    assert_equal 1, peer.refused_stamps["claims"], "a re-offered claim counts once"
    assert_nil peer.claim_of(entry_id)
  end

  # An agent-signed write by agent whose state carries signed_at, signed as
  # the agent signs it.
  def agent_signed_write(writer, agent, now, signed_at)
    _, body = Wire.entry_delta("tasks", GROUP, "com.acme.Task#v1", CBOR.dump({ "topic" => "t" }), writer, nil,
                               60_000, agent: agent, now_ms: now)
    dto = CBOR.load(CBOR.load(body)["payload"])["state"]
    record = dto["record"]
    view = Wire.state_sign_view(record["spaceId"], record["entryId"], dto["adds"], dto["removes"],
                                dto["leaseStamp"], dto["leaseValue"], false, agent.agent_id, signed_at)
    dto.merge("stateSig" => agent.sign(CBOR.dump(view)), "signedAt" => signed_at)
  end

  # HLC canonical stamps, 2026-11-08: signedAt never reaches a clock, so the
  # peer reads it as Java's HlcTimestamp.parse does and does not judge it
  # against the logical limit; a signedAt that does not decode fails the
  # state's verification.
  def test_the_peer_does_not_judge_signed_at_against_the_logical_limit
    peer = CapturingPeer.new
    writer = Identity.generate
    now = peer.now_ms
    agent = writer.subordinate("w", Instants.iso(now - 60_000), "PT1H")
    above = agent_signed_write(writer, agent, now, "#{now}:#{LIMIT + 1}:#{agent.agent_id}")
    peer.fold_state(above)
    assert peer.states.key?(above["record"]["entryId"]), "a signedAt above the limit folds, as in Java"
    malformed = agent_signed_write(writer, agent, now, "0#{now}:0:#{agent.agent_id}")
    peer.fold_state(malformed)
    refute peer.states.key?(malformed["record"]["entryId"]), "a signedAt that does not decode never verifies"
    assert_equal 0, peer.refused_stamps["states"]
  end

  # HLC canonical stamps, 2026-11-08: the receiver's filters run in the
  # order of SPEC 9: the parse, the stale window, the replay memory, the
  # far-future check, and the logical limit.
  def test_the_frame_filter_judges_a_stamp_in_the_spec_order
    peer = CapturingPeer.new
    other = Identity.generate
    now = peer.now_ms
    over = frame(other, "PING", Wire.ping_body(1), peer.identity.peer_id, "#{now}:#{LIMIT + 1}:other")
    2.times { peer.handle(over) }
    assert_equal [1, 1], [peer.frames.refused, peer.frames.replayed], "the replay memory runs before the limit"
    far = frame(other, "PING", Wire.ping_body(2), peer.identity.peer_id,
                "#{now + Wire::MAX_HLC_SKEW_MILLIS + 60_000}:#{LIMIT + 1}:other")
    2.times { peer.handle(far) }
    assert_equal [1, 1, 2], [peer.frames.ahead, peer.frames.refused, peer.frames.replayed],
                 "the far-future check runs after the replay memory and before the limit"
    peer.handle(frame(other, "PING", Wire.ping_body(3), peer.identity.peer_id,
                      "#{now - Wire::MAX_FRAME_AGE_MILLIS - 1000}:#{LIMIT + 1}:other"))
    assert_equal [1, 1], [peer.frames.stale, peer.frames.refused], "the stale window runs before the limit"
    assert_empty peer.sent
  end

  # HLC canonical stamps, 2026-11-08: a frame past the receiver's wall time
  # plus the drift bound by at most the five-second skew margin drops and
  # counts as skewed; one further ahead drops and counts as ahead.
  def test_a_frame_within_the_skew_margin_counts_as_skewed_and_one_beyond_it_as_ahead
    peer = CapturingPeer.new(clock: -> { WALL / 1000.0 })
    other = Identity.generate
    now = peer.now_ms
    ceiling = now + Wire::MAX_HLC_SKEW_MILLIS
    assert_equal 5_000, Wire::HLC_SKEW_MARGIN_MILLIS
    [ceiling + 1, ceiling + Wire::HLC_SKEW_MARGIN_MILLIS].each_with_index do |physical, i|
      peer.handle(frame(other, "PING", Wire.ping_body(i), peer.identity.peer_id, stamp(physical)))
    end
    assert_equal [2, 0], [peer.frames.skewed, peer.frames.ahead]
    peer.handle(frame(other, "PING", Wire.ping_body(7), peer.identity.peer_id,
                      stamp(ceiling + Wire::HLC_SKEW_MARGIN_MILLIS + 1)))
    assert_equal [2, 1], [peer.frames.skewed, peer.frames.ahead]
    assert_equal 2, peer.frames.to_h["skewed"]
    assert_empty peer.sent
    peer.handle(frame(other, "PING", Wire.ping_body(8), peer.identity.peer_id, stamp(ceiling)))
    assert_equal ["ACK"], kinds(peer), "a stamp on the ceiling passes"
  end

  def test_an_honest_peer_dragged_to_the_ceiling_meets_a_lagging_receiver_as_skewed
    sender = clock_node
    Wire.hlc_observe(sender, "#{WALL + Wire::MAX_HLC_SKEW_MILLIS}:#{LIMIT}:attacker", WALL)
    carried = Wire.hlc_now(sender, WALL)
    receiver = Wire::FrameFilter.new
    refute receiver.admit({ "from" => sender, "stamp" => carried }, WALL - 2_000)
    assert_equal [1, 0], [receiver.skewed, receiver.ahead], "a receiver two seconds behind drops it as skewed"
  end

  # HLC canonical stamps, 2026-11-08: Java's String.compareTo orders the node
  # of a stamp and the holder of a claim by UTF-16 code units, which put
  # U+1F600 (D83D DE00) before U+FF61, the reverse of code point order.
  def test_the_peer_orders_nodes_and_holders_by_utf16_code_units_as_java_does
    taker = Identity.generate
    low = taker.agent("\u{1F600}")
    high = taker.agent("｡")
    assert_operator Wire.hlc_order("5:0:#{low}") <=> Wire.hlc_order("5:0:#{high}"), :<, 0

    peer = CapturingPeer.new
    writer = Identity.generate
    now = peer.now_ms
    write = signed_write(writer, "#{now}:0:#{writer.agent('w')}", "#{now}:0:#{writer.agent('w')}", now)
    entry_id = write["record"]["entryId"]
    space_id = write["record"]["spaceId"]
    peer.fold_state(write)
    claim_of = lambda do |holder|
      Wire.signed_claim(Wire.take_claim(entry_id, space_id, 1, "#{now}:0:#{holder}", holder, 0.0, now + 60_000), taker)
    end
    peer.fold_claim(entry_id, claim_of.call(high))
    peer.fold_claim(entry_id, claim_of.call(low))
    assert_equal low, peer.claim_of(entry_id)["holder"], "the lattice keeps the claim Java keeps"

    first = "#{now + 1}:0:#{high}"
    peer.fold_state(signed_renewal(writer, write, first, now))
    peer.fold_state(signed_renewal(writer, write, "#{now + 1}:0:#{low}", now))
    assert_equal first, peer.states[entry_id]["leaseStamp"], "the lease keeps the stamp Java keeps"
  end

  def test_kinds_this_peer_does_not_speak_are_ignored_and_counted
    peer = CapturingPeer.new
    other = Identity.generate
    now = peer.now_ms
    %w[HAVE GRAFT PRUNE BATCH DIGEST CHANNEL_HELLO].each_with_index do |kind, i|
      peer.handle(frame(other, kind, CBOR.dump({ "anything" => i }), peer.identity.peer_id, stamp(now, i)))
    end
    assert_empty peer.sent
    assert_equal 6, peer.ignored_kinds.values.sum
    assert_equal 1, peer.ignored_kinds["HAVE"]
    peer.handle(frame(other, "PING", Wire.ping_body(9), peer.identity.peer_id, stamp(now, 99)))
    assert_equal ["ACK"], kinds(peer), "still answering afterwards"
  end

  def test_a_malformed_body_under_a_good_signature_never_corrupts_state
    peer = CapturingPeer.new
    other = Identity.generate
    now = peer.now_ms
    %w[RUMOR PULL_RESP PING PIPE_DATA].each_with_index do |kind, i|
      peer.handle(frame(other, kind, "\xFF\x01\x02".b, peer.identity.peer_id, stamp(now, i)))
    rescue StandardError
      nil # the reader catches this per frame
    end
    assert_empty peer.states
    assert_empty peer.claims
    peer.handle(frame(other, "PING", Wire.ping_body(5), peer.identity.peer_id, stamp(now, 50)))
    assert_equal ["ACK"], kinds(peer)
  end

  def test_a_hostile_length_prefix_drops_the_connection_and_the_peer_reconnects
    seed = Testing::FakeSeed.new
    peer = Peer.new(Identity.generate, GROUP)
    peer.reconnect_interval = 0.1
    peer.connect("127.0.0.1", seed.port)
    assert eventually { seed.kinds(0).size >= 2 }
    seed.connections[0].write([Wire::MAX_FRAME_BYTES + 1].pack("N"))
    assert eventually { peer.reconnects == 1 }
    assert eventually { seed.kinds(1).first == "RUMOR" }
  ensure
    peer&.close
    seed&.close
  end

  def test_a_lost_socket_is_reconnected_and_the_peer_reintroduces_and_repulls
    seed = Testing::FakeSeed.new
    peer = Peer.new(Identity.generate, GROUP)
    peer.reconnect_interval = 0.1
    peer.connect("127.0.0.1", seed.port)
    peer.pull_space("work")
    assert eventually { seed.kinds(0).size >= 3 }
    assert_equal %w[RUMOR DIGEST DIGEST], seed.kinds(0)
    seed.drop(0)
    assert eventually { seed.kinds(1).size >= 3 }
    assert_equal %w[RUMOR DIGEST DIGEST], seed.kinds(1).first(3)
    assert_equal 1, peer.reconnects
    assert peer.connected?
  ensure
    peer&.close
    seed&.close
    refute peer.running?
  end

  def test_close_by_the_owner_is_final
    seed = Testing::FakeSeed.new
    peer = Peer.new(Identity.generate, GROUP)
    peer.reconnect_interval = 0.1
    peer.connect("127.0.0.1", seed.port)
    sleep 0.2
    peer.close
    sleep 0.5
    assert_equal 1, seed.connections.size, "no reconnect after the owner's close"
    assert_equal 0, peer.reconnects
  ensure
    seed&.close
  end

  def test_a_seed_that_is_down_is_retried_until_it_listens_again
    seed = Testing::FakeSeed.new
    port = seed.port
    peer = Peer.new(Identity.generate, GROUP)
    peer.reconnect_interval = 0.1
    peer.connect("127.0.0.1", port)
    assert eventually { seed.kinds.size >= 2 }
    seed.close
    sleep 0.3
    assert_equal 0, peer.reconnects
    again = Testing::FakeSeed.new(port)
    assert eventually { again.kinds.size >= 2 }
    assert_equal %w[RUMOR DIGEST], again.kinds.first(2)
    assert_equal 1, peer.reconnects
  ensure
    peer&.close
    again&.close
  end

  def test_connect_any_fails_over_and_names_every_seed_that_refused
    dead = TCPServer.new("127.0.0.1", 0)
    dead_port = dead.addr[1]
    dead.close
    peer = Peer.new(Identity.generate, GROUP)
    error = assert_raises(NoSeedError) { peer.connect_any(["127.0.0.1:#{dead_port}", "dtls://127.0.0.1:1"]) }
    assert_match(/127.0.0.1:#{dead_port}: ECONNREFUSED/, error.message)
    seed = Testing::FakeSeed.new
    chosen = peer.connect_any(["127.0.0.1:#{dead_port}", "quic://127.0.0.1:2", seed.seed])
    assert_equal seed.port, chosen.port
  ensure
    peer&.close
    seed&.close
  end

  def test_a_forked_child_never_speaks_on_the_parents_connection
    skip "JRuby cannot fork" unless Process.respond_to?(:fork) && RUBY_ENGINE != "jruby"
    seed = Testing::FakeSeed.new
    peer = Peer.new(Identity.generate, GROUP)
    peer.connect("127.0.0.1", seed.port)
    assert eventually { seed.kinds(0).size >= 2 }
    before = seed.kinds(0).size
    reader, writer = IO.pipe
    pid = fork do
      reader.close
      outcome = begin
        peer.write_entry("tasks", "com.acme.Task#v1", { "topic" => "from the child" })
        "wrote"
      rescue ForkError => e
        e.message
      end
      writer.write(outcome)
      writer.close
      exit!(0)
    end
    writer.close
    Process.wait(pid)
    outcome = reader.read
    assert_match(/started in process #{Process.pid}.*AgentSpaces.after_fork/, outcome)
    sleep 0.2
    assert_equal before, seed.kinds(0).size, "the child sent nothing on the inherited socket"
    assert peer.connected?, "the parent's connection survives the child"
    peer.write_entry("tasks", "com.acme.Task#v1", { "topic" => "from the parent" })
    assert eventually { seed.kinds(0).size == before + 1 }
  ensure
    peer&.close
    seed&.close
  end

  def test_the_peer_re_leases_its_self_advertisement
    seed = Testing::FakeSeed.new
    peer = Peer.new(Identity.generate, GROUP)
    peer.peer_ad_interval = 0.3
    peer.connect("127.0.0.1", seed.port)
    assert eventually(3) { seed.kinds(0).count("RUMOR") >= 3 }
  ensure
    peer&.close
    seed&.close
  end

  def test_doctor_runs_every_primitive_and_names_the_library
    report = Crypto.doctor
    assert_match(/OpenSSL/, report["openssl"])
    assert_includes report["checks"], "Ed25519"
  end

  def test_identities_never_print_their_keys
    identity = Identity.generate
    agent = identity.renewing_subordinate("x", "PT1H")
    [identity.inspect, identity.to_s, agent.inspect, PP.pp(identity, +"")].each do |text|
      refute_includes text, identity.pkcs8.unpack1("H*")
      refute_match(/@private/, text)
    end
  end

  def test_the_keystore_matches_javas_layout_and_refuses_damage
    Dir.mktmpdir do |dir|
      identity = Identity.load_or_create(dir)
      assert_equal 0o600, File.stat(File.join(dir, "peer.key")).mode & 0o777
      assert_equal 32, File.binread(File.join(dir, "peer.pub")).bytesize
      assert_equal identity.peer_id, Identity.load_or_create(dir).peer_id
      File.chmod(0o644, File.join(dir, "peer.key"))
      error = assert_raises(ArgumentError) { Identity.load_or_create(dir) }
      assert_match(/readable by group or others/, error.message)
      File.chmod(0o600, File.join(dir, "peer.key"))
      File.binwrite(File.join(dir, "peer.pub"), Identity.generate.public_raw)
      assert_raises(ArgumentError) { Identity.load_or_create(dir) }
      agent = Identity.agent_keys(dir, identity.peer_id, "worker")
      assert File.exist?(File.join(dir, identity.peer_id, "worker", "agent.key"))
      assert_equal agent.peer_id, Identity.agent_keys(dir, identity.peer_id, "worker").peer_id
      assert_raises(ArgumentError) { Identity.agent_keys(dir, "..", "worker") }
    end
  end
end
