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

  # Delivers a space delta (a Hash, or raw CBOR bytes) in a RUMOR from sender.
  def rumor(peer, sender, delta, n)
    payload = delta.is_a?(Hash) ? CBOR.dump(delta) : delta
    peer.handle(frame(sender, "RUMOR", Wire.rumor_body("space:tasks", "w:#{n}", Wire::HOPS, payload), nil,
                      "#{peer.now_ms}:#{n}:#{sender.peer_id}"))
  end

  # Delivers raw frame bytes to peer inside a RELAY_FRAME from sender.
  def relay(peer, sender, raw, n)
    peer.handle(frame(sender, "RELAY_FRAME", Wire.relay_frame_body(peer.identity.peer_id, raw),
                      peer.identity.peer_id, "#{peer.now_ms}:#{1000 + n}:#{sender.peer_id}"))
  end

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
    assert_equal [1, 1], [peer.frames.stale, peer.frames.far_future]
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
    assert_equal 2, peer.frames.logical_refused
    assert_equal 2, peer.frames.to_h["framesLogicalRefused"]
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

  # HLC round four, 2026-11-08 (D3): a frame whose stamp does not decode is
  # an undecodable carrier, so Wire.decode_frame refuses it and the reader
  # counts it in malformed_frames, as Java's PeerNode counts it in framesDropped.
  def test_a_frame_with_a_negative_unreadable_or_fractional_counter_does_not_decode
    peer = CapturingPeer.new
    other = Identity.generate
    now = peer.now_ms
    HOSTILE_COUNTERS.each_with_index do |counter, i|
      raw = Wire.encode_frame(Wire.envelope(GROUP, "PING", other.peer_id, "#{now + 1000}:#{counter}:other",
                                            Wire.ping_body(i), peer.identity.peer_id), other)
      assert_nil Wire.decode_frame(raw), "a frame stamped with counter #{counter} does not decode"
      relay(peer, other, raw, i)
    end
    assert_empty peer.sent
    assert_equal HOSTILE_COUNTERS.size, peer.malformed_frames
    assert_equal 0, peer.frames.logical_refused
    stamp = Wire.hlc_now(peer.identity.peer_id, now)
    assert_operator tuple(stamp)[1], :>=, 0, "the clock holds no negative counter"
    assert_operator Wire.hlc_physical(stamp), :<, now + 1000, "no refused frame reached the clock"
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
    assert_equal 0, receiver.far_future

    beyond = clock_node
    Wire.hlc_observe(beyond, "#{WALL + Wire::MAX_HLC_SKEW_MILLIS + 60_000}:7:other", WALL)
    assert_equal [WALL + Wire::MAX_HLC_SKEW_MILLIS - 1, 8], tuple(Wire.hlc_now(beyond, WALL)),
                 "a stamp past the cap merges one millisecond inside it"
  end

  def test_the_peer_drops_and_counts_states_with_a_negative_unreadable_or_fractional_stamp_as_undecodable
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
    assert_equal 2 * HOSTILE_COUNTERS.size, peer.deltas_undecodable
    assert_equal 0, peer.stamps_logical_refused
    renewed = "#{now + 1}:0:#{issuer}"
    peer.fold_state(signed_renewal(writer, honest, renewed, now))
    assert_equal renewed, peer.states[entry_id]["leaseStamp"], "a later honest renewal merges"
  end

  def test_the_peer_drops_and_counts_undecodable_claims_and_a_later_honest_claim_still_merges
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
    assert_equal HOSTILE_COUNTERS.size, peer.deltas_undecodable
    assert_equal 0, peer.stamps_logical_refused
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

  def test_a_frame_whose_stamp_is_not_canonical_does_not_decode_and_leaves_no_replay_trace
    peer = CapturingPeer.new
    other = Identity.generate
    now = peer.now_ms
    stamps = ["0#{now}:1:other", "#{now}:01:other", "#{now}:1:other".b, "#{now}:1:ot\u0007her"]
    stamps.each_with_index do |stamp, i|
      raw = Wire.encode_frame(Wire.envelope(GROUP, "PING", other.peer_id, stamp, Wire.ping_body(i),
                                            peer.identity.peer_id), other)
      assert_nil Wire.decode_frame(raw), "#{stamp.inspect} does not decode"
      relay(peer, other, raw, 100 + i)
    end
    assert_empty peer.sent
    assert_equal stamps.size, peer.malformed_frames
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
      assert Wire.verify_claim_proof(signed), "the rival signed the raw text"
      2.times { peer.fold_claim(entry_id, signed) }
      assert_equal honest["claim"], peer.claim_of(entry_id), "#{signed['claim']['stamp'].inspect} never wins"
      assert_equal honest, Wire.merge_claims(honest, signed)
      assert_equal honest, Wire.merge_claims(signed, honest)
    end
    assert_equal 2 * forged.size, peer.deltas_undecodable, "each undecodable offer counts at the drop"
    assert_equal 0, peer.stamps_logical_refused
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
    assert_equal 0, peer.stamps_logical_refused, "an unverified state counts nothing"
    refused = signed_write(writer, hostile, hostile, now)
    3.times { peer.fold_state(refused) }
    assert_equal 1, peer.stamps_logical_refused, "a re-offered state counts once"
    refute peer.states.key?(refused["record"]["entryId"])
    peer.fold_state(signed_write(writer, hostile, hostile, now))
    assert_equal 2, peer.stamps_logical_refused, "a distinct state counts again"

    write = signed_write(writer, "#{now}:0:#{issuer}", "#{now}:0:#{issuer}", now)
    entry_id = write["record"]["entryId"]
    space_id = write["record"]["spaceId"]
    peer.fold_state(write)
    taker = Identity.generate
    holder = taker.agent("t")
    claim = Wire.take_claim(entry_id, space_id, 1, hostile_stamp(now, holder), holder, 0.0, now + 60_000)
    unsigned = Wire.signed_claim(claim, taker).merge("signature" => "\x00".b * 64)
    3.times { peer.fold_claim(entry_id, unsigned) }
    assert_equal 2, peer.stamps_logical_refused, "an unverified claim counts nothing"
    signed = Wire.signed_claim(claim, taker)
    3.times { peer.fold_claim(entry_id, signed) }
    assert_equal 3, peer.stamps_logical_refused, "a re-offered claim counts once"
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

  # HLC round four, 2026-11-08 (D1): an agent-signed state's signedAt is a
  # stamp like any other. A signedAt above the logical limit is refused
  # after the state's signatures verify and counts once per distinct state;
  # a signedAt that does not decode makes its carrier undecodable.
  def test_the_peer_refuses_a_signed_at_above_the_limit_after_verification_and_counts_it_once
    peer = CapturingPeer.new
    writer = Identity.generate
    now = peer.now_ms
    agent = writer.subordinate("w", Instants.iso(now - 60_000), "PT1H")
    above = agent_signed_write(writer, agent, now, "#{now}:#{LIMIT + 1}:#{agent.agent_id}")
    forged = above.merge("stateSig" => "\x00".b * 64)
    peer.fold_state(forged)
    assert_equal 0, peer.stamps_logical_refused, "an unverified state counts nothing"
    3.times { peer.fold_state(above) }
    refute peer.states.key?(above["record"]["entryId"]), "a signedAt above the limit never folds"
    assert_equal 1, peer.stamps_logical_refused, "the refusal counts once per distinct state"
    at_limit = agent_signed_write(writer, agent, now, "#{now}:#{LIMIT}:#{agent.agent_id}")
    peer.fold_state(at_limit)
    assert peer.states.key?(at_limit["record"]["entryId"]), "a signedAt at the limit folds"
    malformed = agent_signed_write(writer, agent, now, "0#{now}:0:#{agent.agent_id}")
    rumor(peer, writer, { "state" => malformed, "claimEntry" => nil, "claim" => nil }, 1)
    refute peer.states.key?(malformed["record"]["entryId"]), "a signedAt that does not decode never folds"
    assert_equal [1, 1], [peer.deltas_undecodable, peer.stamps_logical_refused]
  end

  # HLC round four, 2026-11-08 (D3): a stamp on the wire is a CBOR text of
  # definite length, untagged, in shortest-form UTF-8, whose text is in the
  # canonical grammar. Each item below in a stamp's place is not a stamp.
  NOT_STAMPS = {
    "indefinite-length text" => ->(t) { "\x7F".b + CBOR.dump(t) + "\xFF".b },
    "tagged text" => ->(t) { "\xD8\x20".b + CBOR.dump(t) },
    "overlong UTF-8" => ->(t) { RobustnessTest.raw_text(t.b.sub(":", "\xC0\xBA".b)) },
    "a surrogate in UTF-8" => ->(t) { RobustnessTest.raw_text(t.b + "\xED\xA0\x80".b) },
    "byte string" => ->(t) { CBOR.dump(t.b) },
    "number" => ->(_t) { CBOR.dump(5) },
    "map" => ->(t) { CBOR.dump({ "stamp" => t }) },
    "non-canonical text" => ->(t) { CBOR.dump("0#{t}") },
    # HLC round five, 2026-11-08 (E1): a stamp sits under its shortest length
    # header; the same text under a two-, four-, or eight-byte length is no stamp.
    "a two-byte length header" => ->(t) { "\x79".b + [t.bytesize].pack("n") + t.b },
    "a four-byte length header" => ->(t) { "\x7A".b + [t.bytesize].pack("N") + t.b },
    "an eight-byte length header" => ->(t) { "\x7B".b + [t.bytesize].pack("Q>") + t.b }
  }.freeze

  # A CBOR text item over bytes that need not be valid UTF-8, which the
  # encoder refuses to write (HLC round six, 2026-11-08 (S6)).
  def self.raw_text(bytes)
    item = CBOR.dump(bytes.b)
    item.setbyte(0, item.getbyte(0) + 0x20)
    item
  end

  # bytes with the one CBOR text item of marker replaced by raw.
  def swap(bytes, marker, raw)
    item = CBOR.dump(marker)
    assert_equal 1, bytes.b.scan(item).size, "the marker sits once in the carrier"
    bytes.b.sub(item) { raw }
  end

  # HLC round four, 2026-11-08 (D3, D5): any other item in the place of a
  # record's issued, a lease stamp, a signedAt, or a claim's stamp makes the
  # whole space delta undecodable. The peer drops it at the decode, counts it
  # in deltas_undecodable, and never counts it as a refused stamp.
  def test_a_space_delta_with_anything_but_a_canonical_text_in_a_stamps_place_is_undecodable_and_counted
    peer = CapturingPeer.new
    writer = Identity.generate
    issuer = writer.agent("w")
    now = peer.now_ms
    agent = writer.subordinate("a", Instants.iso(now - 60_000), "PT1H")
    taker = Identity.generate
    holder = taker.agent("t")
    honest = "#{now}:0:#{issuer}"
    places = {
      "issued" => [issuer, ->(m) { { "state" => signed_write(writer, m, honest, now), "claimEntry" => nil, "claim" => nil } }],
      "leaseStamp" => [issuer, ->(m) { { "state" => signed_write(writer, honest, m, now), "claimEntry" => nil, "claim" => nil } }],
      "signedAt" => [agent.agent_id,
                     ->(m) { { "state" => agent_signed_write(writer, agent, now, m), "claimEntry" => nil, "claim" => nil } }],
      "a claim's stamp" => [holder, lambda do |m|
        entry_id = SecureRandom.uuid
        claim = Wire.take_claim(entry_id, Derive.space_id_local("#{GROUP}/tasks"), 1, m, holder, 0.0, now + 60_000)
        { "state" => nil, "claimEntry" => entry_id, "claim" => Wire.signed_claim(claim, taker) }
      end]
    }
    n = 0
    places.each do |place, (node, build)|
      marker = "#{now}:4242:#{node}"
      NOT_STAMPS.each do |name, item|
        delta = build.call(marker)
        rumor(peer, writer, swap(CBOR.dump(delta), marker, item.call(marker)), n += 1)
        assert_equal n, peer.deltas_undecodable, "#{name} as #{place} makes its carrier undecodable"
        entry_id = delta["state"] ? delta["state"]["record"]["entryId"] : delta["claimEntry"]
        refute peer.states.key?(entry_id), "#{name} as #{place} folds nothing"
        assert_nil peer.claim_of(entry_id), "#{name} as #{place} claims nothing"
      end
      control = build.call(marker)
      rumor(peer, writer, control, n + 1000)
      folded = control["state"] ? peer.states.key?(control["state"]["record"]["entryId"]) : peer.claim_of(control["claimEntry"])
      assert folded, "the same carrier with a canonical #{place} folds"
    end
    assert_equal [n, 0, 0], [peer.deltas_undecodable, peer.stamps_logical_refused, peer.malformed_frames]
  end

  # HLC round four, 2026-11-08 (D3, D5): a PULL_RESP carries one delta per
  # stream. A sync delta with one undecodable stamp drops whole, as Java's
  # applySyncDelta drops it, and the peer still folds every other stream.
  def test_a_pull_response_drops_an_undecodable_sync_delta_whole_and_keeps_the_rest
    peer = CapturingPeer.new
    writer = Identity.generate
    issuer = writer.agent("w")
    now = peer.now_ms
    honest = "#{now}:0:#{issuer}"
    beside, kept, last = Array.new(3) { signed_write(writer, honest, honest, now) }
    bytes_issued = signed_write(writer, honest.b, honest, now)
    deltas = CBOR.canonical_map({ "space:garbage" => "\xFF\x01".b,
                                  "space:mixed" => CBOR.dump({ "states" => [beside, bytes_issued], "claims" => {} }),
                                  "space:tasks" => CBOR.dump({ "states" => [kept], "claims" => {} }),
                                  "ads" => "\xFF".b,
                                  "space:last" => CBOR.dump({ "states" => [last], "claims" => {} }) })
    peer.handle(frame(writer, "PULL_RESP", CBOR.dump({ "deltas" => deltas }), peer.identity.peer_id, stamp(now, 1)))
    refute peer.states.key?(beside["record"]["entryId"]), "the undecodable sync delta drops whole"
    refute peer.states.key?(bytes_issued["record"]["entryId"])
    assert peer.states.key?(kept["record"]["entryId"]), "a later stream still folds"
    assert peer.states.key?(last["record"]["entryId"]), "a stream after an undecodable ads delta still folds"
    assert_equal [2, 1, 0], [peer.deltas_undecodable, peer.malformed_frames, peer.stamps_logical_refused]
  end

  # HLC round four, 2026-11-08 (D3): a frame whose stamp is anything but a
  # canonical CBOR text does not decode, even under a signature over its raw
  # bytes, and the peer counts it as a malformed frame.
  def test_a_frame_with_anything_but_a_canonical_text_in_its_stamp_does_not_decode
    peer = CapturingPeer.new
    other = Identity.generate
    marker = "#{peer.now_ms}:4242:#{other.peer_id}"
    env = CBOR.dump(Wire.envelope(GROUP, "PING", other.peer_id, marker, Wire.ping_body(1), peer.identity.peer_id))
    signed = lambda do |raw_env|
      "\xBF".b + CBOR.dump("envelope") + raw_env + CBOR.dump("senderPublicKey") + CBOR.dump(other.public_raw) +
        CBOR.dump("signature") + CBOR.dump(other.sign(raw_env)) + "\xFF".b
    end
    refute_nil Wire.decode_frame(signed.call(env)), "the frame with its canonical stamp decodes"
    NOT_STAMPS.each_with_index do |(name, item), i|
      raw = signed.call(swap(env, marker, item.call(marker)))
      assert_nil Wire.decode_frame(raw), "a stamp as #{name} does not decode"
      relay(peer, other, raw, i)
    end
    assert_equal [NOT_STAMPS.size, 0], [peer.malformed_frames, peer.frames.logical_refused]
    assert_empty peer.sent
  end

  # HLC round four, 2026-11-08 (D4): a folded state or claim stamped past
  # the receiver's wall + MAX_DRIFT + the skew margin waits: the peer neither
  # merges nor counts it, and it merges when a later offer finds the wall caught up.
  def test_a_state_or_claim_past_the_skew_margin_is_deferred_and_merges_once_the_wall_catches_up
    wall = WALL
    peer = CapturingPeer.new(clock: -> { wall / 1000.0 })
    writer = Identity.generate
    issuer = writer.agent("w")
    margin = WALL + Wire::MAX_HLC_SKEW_MILLIS + Wire::HLC_SKEW_MARGIN_MILLIS
    held = signed_write(writer, "#{margin}:0:#{issuer}", "#{margin}:0:#{issuer}", WALL)
    peer.fold_state(held)
    entry_id = held["record"]["entryId"]
    assert peer.states.key?(entry_id), "a stamp on the margin merges"
    past = signed_write(writer, "#{margin + 1}:0:#{issuer}", "#{margin + 1}:0:#{issuer}", WALL)
    renewal = signed_renewal(writer, held, "#{margin + 1}:0:#{issuer}", WALL)
    taker = Identity.generate
    holder = taker.agent("t")
    claim = Wire.signed_claim(Wire.take_claim(entry_id, held["record"]["spaceId"], 1, "#{margin + 1}:0:#{holder}",
                                              holder, 0.0, WALL + 60_000), taker)
    3.times do
      peer.fold_state(past)
      peer.fold_state(renewal)
      peer.fold_claim(entry_id, claim)
    end
    refute peer.states.key?(past["record"]["entryId"]), "a record past the margin waits"
    assert_equal "#{margin}:0:#{issuer}", peer.states[entry_id]["leaseStamp"], "a lease stamp past the margin waits"
    assert_nil peer.claim_of(entry_id), "a claim past the margin waits"
    assert_equal [0, 0, 0], [peer.stamps_logical_refused, peer.stamps_far_future_refused, peer.deltas_undecodable],
                 "a deferral refuses nothing"
    # HLC round five, 2026-11-08 (E2): each distinct deferred offer counts once.
    assert_equal 3, peer.stamps_far_future_deferred, "the record, the renewal, and the claim each count once"
    wall += 1
    peer.fold_state(past)
    peer.fold_state(renewal)
    peer.fold_claim(entry_id, claim)
    assert peer.states.key?(past["record"]["entryId"]), "the record merges once the wall catches up"
    assert_equal "#{margin + 1}:0:#{issuer}", peer.states[entry_id]["leaseStamp"]
    assert_equal claim["claim"], peer.claim_of(entry_id)
    assert_equal [0, 0, 3], [peer.stamps_logical_refused, peer.stamps_far_future_refused,
                             peer.stamps_far_future_deferred]
  end

  # HLC round four, 2026-11-08 (D4, D5): a stamp more than an hour past the
  # skew margin is hostile, so the peer refuses the state or claim after it
  # verifies and counts it once per distinct offer; one on that hour waits.
  # HLC round five, 2026-11-08 (E2, E5): a hostile far-future refusal counts
  # in stamps_far_future_refused alone, and the peer judges every offer
  # afresh against its wall, so the refused offer merges once the wall catches up.
  def test_a_state_or_claim_an_hour_past_the_skew_margin_is_refused_and_counted_once
    wall = WALL
    peer = CapturingPeer.new(clock: -> { wall / 1000.0 })
    writer = Identity.generate
    issuer = writer.agent("w")
    assert_equal 3_600_000, Wire::HLC_DEFER_WINDOW_MILLIS
    hour = WALL + Wire::MAX_HLC_SKEW_MILLIS + Wire::HLC_SKEW_MARGIN_MILLIS + Wire::HLC_DEFER_WINDOW_MILLIS
    waits = signed_write(writer, "#{hour}:0:#{issuer}", "#{hour}:0:#{issuer}", WALL)
    peer.fold_state(waits)
    refute peer.states.key?(waits["record"]["entryId"])
    assert_equal [0, 1], [peer.stamps_far_future_refused, peer.stamps_far_future_deferred],
                 "a stamp on the hour waits and counts as deferred"
    hostile = signed_write(writer, "#{hour + 1}:0:#{issuer}", "#{hour + 1}:0:#{issuer}", WALL)
    3.times { peer.fold_state(hostile) }
    refute peer.states.key?(hostile["record"]["entryId"])
    assert_equal 1, peer.stamps_far_future_refused, "a hostile record counts once"
    held = signed_write(writer, "#{WALL}:0:#{issuer}", "#{WALL}:0:#{issuer}", WALL)
    peer.fold_state(held)
    entry_id = held["record"]["entryId"]
    2.times { peer.fold_state(signed_renewal(writer, held, "#{hour + 1}:0:#{issuer}", WALL)) }
    assert_equal "#{WALL}:0:#{issuer}", peer.states[entry_id]["leaseStamp"]
    assert_equal 2, peer.stamps_far_future_refused, "a hostile lease stamp counts once"
    taker = Identity.generate
    holder = taker.agent("t")
    claim = Wire.signed_claim(Wire.take_claim(entry_id, held["record"]["spaceId"], 1, "#{hour + 1}:0:#{holder}",
                                              holder, 0.0, hour + 60_000), taker)
    2.times { peer.fold_claim(entry_id, claim) }
    assert_nil peer.claim_of(entry_id)
    assert_equal 3, peer.stamps_far_future_refused, "a hostile claim counts once"
    assert_equal [0, 1], [peer.stamps_logical_refused, peer.stamps_far_future_deferred],
                 "a far-future refusal never counts as a logical one"
    wall = hour - Wire::MAX_HLC_SKEW_MILLIS
    peer.fold_state(hostile)
    peer.fold_claim(entry_id, claim)
    assert peer.states.key?(hostile["record"]["entryId"]), "the refused record merges once the wall catches up"
    assert_equal claim["claim"], peer.claim_of(entry_id), "the refused claim merges once the wall catches up"
    assert_equal [0, 3, 1], [peer.stamps_logical_refused, peer.stamps_far_future_refused,
                             peer.stamps_far_future_deferred]
  end

  # HLC round four, 2026-11-08 (D5): the peer keys a refused state on its
  # entry id, issued, and signed view, and a refused claim on its signed map
  # and entry id, so a relay that re-encodes either with other unsigned
  # content counts no second refusal. The counters carry Java's names.
  def test_the_peer_keys_a_refused_state_or_claim_on_its_signed_content
    peer = CapturingPeer.new
    writer = Identity.generate
    issuer = writer.agent("w")
    now = peer.now_ms
    hostile = hostile_stamp(now, issuer)
    refused = signed_write(writer, hostile, hostile, now)
    [refused, refused.merge("relayed" => 1), refused.to_a.reverse.to_h].each { |dto| peer.fold_state(dto) }
    assert_equal 1, peer.stamps_logical_refused, "one state under other unsigned content counts once"
    write = signed_write(writer, "#{now}:0:#{issuer}", "#{now}:0:#{issuer}", now)
    peer.fold_state(write)
    entry_id = write["record"]["entryId"]
    taker = Identity.generate
    holder = taker.agent("t")
    claim = Wire.signed_claim(Wire.take_claim(entry_id, write["record"]["spaceId"], 1, hostile_stamp(now, holder),
                                              holder, 0.0, now + 60_000), taker)
    [claim, claim.merge("relayed" => 1), claim.to_a.reverse.to_h].each { |signed| peer.fold_claim(entry_id, signed) }
    assert_equal 2, peer.stamps_logical_refused, "one claim under other unsigned content counts once"
    assert_equal %w[framesFarFuture framesFarFutureSkewed framesLogicalRefused framesReplayed framesStale],
                 peer.frames.to_h.keys.sort
  end

  # An agent-signed write by agent, its record and lease stamped at now_ms
  # under a certificate covering three hours from WALL. The agent signs the
  # state at WALL, since signedAt keeps the drift ceiling, as in Java's
  # ForgedStateRejectionTest (HLC round five, 2026-11-08 (E4)).
  def agent_write_at(writer, agent, now_ms)
    agent_signed_write(writer, agent, now_ms, "#{WALL}:0:#{agent.agent_id}")
  end

  def agent_claim_at(holder_peer, agent, entry_id, space_id, now_ms)
    claim = Wire.take_claim(entry_id, space_id, 1, Wire.hlc_now(agent.agent_id, now_ms), agent.agent_id, 0.0,
                            now_ms + 60_000)
    Wire.signed_claim(claim, holder_peer, agent)
  end

  # HLC round five, 2026-11-08 (E4): an agent certificate keeps its own
  # validity window and no longer bounds a record's or claim's stamp at
  # now + MAX_DRIFT; the peer then judges the stamp as for a peer-signed
  # carrier: it merges within the skew margin, waits within the hour past
  # it, and refuses and counts it beyond.
  def test_an_agent_signed_record_or_claim_meets_the_far_future_rule_of_a_peer_signed_one
    wall = WALL
    peer = CapturingPeer.new(clock: -> { wall / 1000.0 })
    writer = Identity.generate
    taker = Identity.generate
    certified = Instants.iso(WALL - 60_000)
    ceiling = WALL + Wire::MAX_HLC_SKEW_MILLIS
    skewed = writer.subordinate("skewed", certified, "PT3H")
    within = agent_write_at(writer, skewed, ceiling + 3_000)
    peer.fold_state(within)
    entry_id = within["record"]["entryId"]
    space_id = within["record"]["spaceId"]
    assert peer.states.key?(entry_id), "an agent record within the skew margin merges"
    holder = taker.subordinate("skewed", certified, "PT3H")
    claim = agent_claim_at(taker, holder, entry_id, space_id, ceiling + 3_000)
    assert Wire.verify_claim_proof(claim), "the certificate verifies a claim past the drift bound"
    peer.fold_claim(entry_id, claim)
    assert_equal claim["claim"], peer.claim_of(entry_id), "an agent claim within the skew margin merges"

    waiting = writer.subordinate("waiting", certified, "PT3H")
    deferred = agent_write_at(writer, waiting, ceiling + Wire::HLC_SKEW_MARGIN_MILLIS + 60_000)
    2.times { peer.fold_state(deferred) }
    refute peer.states.key?(deferred["record"]["entryId"]), "an agent record within the hour waits"
    assert_equal [1, 0], [peer.stamps_far_future_deferred, peer.stamps_far_future_refused]

    beyond = ceiling + Wire::HLC_SKEW_MARGIN_MILLIS + Wire::HLC_DEFER_WINDOW_MILLIS + 1
    hostile_writer = writer.subordinate("hostile", certified, "PT3H")
    hostile = agent_write_at(writer, hostile_writer, beyond)
    2.times { peer.fold_state(hostile) }
    hostile_holder = taker.subordinate("hostile", certified, "PT3H")
    hostile_claim = agent_claim_at(taker, hostile_holder, deferred["record"]["entryId"],
                                   deferred["record"]["spaceId"], beyond)
    2.times { peer.fold_claim(deferred["record"]["entryId"], hostile_claim) }
    refute peer.states.key?(hostile["record"]["entryId"])
    assert_nil peer.claim_of(deferred["record"]["entryId"])
    assert_equal [2, 1, 0], [peer.stamps_far_future_refused, peer.stamps_far_future_deferred,
                             peer.stamps_logical_refused], "each hostile agent record and claim counts once"

    wall = ceiling + Wire::HLC_SKEW_MARGIN_MILLIS + 60_000 - Wire::MAX_HLC_SKEW_MILLIS
    peer.fold_state(deferred)
    assert peer.states.key?(deferred["record"]["entryId"]), "the deferred agent record merges once the wall catches up"
  end

  # HLC round six, 2026-11-08 (F4): an agent-signed state's signedAt meets
  # the far-future rule of every other stamp (D4) where the certificate's
  # drift ceiling dropped it uncounted: it merges up to wall + MAX_DRIFT + the
  # skew margin, waits as deferred up to an hour past that, counted once, and
  # beyond is hostile, refused and counted once. A deferred state merges once
  # the wall catches up.
  def test_an_agent_signed_states_signed_at_meets_the_far_future_rule
    wall = WALL
    peer = CapturingPeer.new(clock: -> { wall / 1000.0 })
    writer = Identity.generate
    agent = writer.subordinate("w", Instants.iso(WALL - 60_000), "PT3H")
    margin = WALL + Certificates::MAX_DRIFT_MILLIS + Wire::HLC_SKEW_MARGIN_MILLIS
    on = agent_signed_write(writer, agent, WALL, "#{margin}:0:#{agent.agent_id}")
    peer.fold_state(on)
    assert peer.states.key?(on["record"]["entryId"]), "a signedAt on the skew margin merges"
    past = agent_signed_write(writer, agent, WALL, "#{margin + 1}:0:#{agent.agent_id}")
    hostile = agent_signed_write(writer, agent, WALL,
                                 "#{margin + Wire::HLC_DEFER_WINDOW_MILLIS + 1}:0:#{agent.agent_id}")
    [past, hostile].each { |dto| 2.times { peer.fold_state(dto) } }
    refute peer.states.key?(past["record"]["entryId"]), "a signedAt past the margin waits"
    refute peer.states.key?(hostile["record"]["entryId"]), "a signedAt an hour further is refused"
    assert_equal [1, 1, 0], [peer.stamps_far_future_deferred, peer.stamps_far_future_refused,
                             peer.stamps_logical_refused], "each counts once, as the rule counts any stamp"
    wall = WALL + 1
    peer.fold_state(past)
    assert peer.states.key?(past["record"]["entryId"]), "the deferred state merges once the wall catches up"
  end

  # HLC round five, 2026-11-08 (E7): a state with no lease stamp or no lease
  # value decodes, and the peer drops it before any judgement, as Java's
  # mergeState does, since a lease register holds nothing without both: it
  # merges nothing, waits for nothing, and counts in no counter.
  def test_a_state_without_its_lease_stamp_or_value_decodes_and_merges_nothing
    peer = CapturingPeer.new(clock: -> { WALL / 1000.0 })
    writer = Identity.generate
    issuer = writer.agent("w")
    held = signed_write(writer, "#{WALL}:0:#{issuer}", "#{WALL}:0:#{issuer}", WALL)
    peer.fold_state(held)
    entry_id = held["record"]["entryId"]
    [{ "leaseStamp" => nil }, { "leaseValue" => nil }, { "leaseStamp" => nil, "leaseValue" => nil }].each do |gap|
      fresh = signed_write(writer, "#{WALL}:0:#{issuer}", "#{WALL}:0:#{issuer}", WALL)
      renewal = signed_renewal(writer, held, "#{WALL + 1}:0:#{issuer}", WALL)
      [Wire.sign_state(fresh.merge(gap), writer), Wire.sign_state(renewal.merge(gap), writer),
       Wire.sign_state(renewal.merge(gap).merge("record" => nil, "entryId" => entry_id), writer)].each do |dto|
        delta = CBOR.load(CBOR.dump({ "state" => dto, "claimEntry" => nil, "claim" => nil }))
        Schema.check("SpaceWire.Delta", delta) # a state missing its lease stamp or value decodes
        peer.fold_state(delta["state"])
      end
      refute peer.states.key?(fresh["record"]["entryId"]), "a write missing #{gap.keys.join(' and ')} merges nothing"
    end
    assert_equal held, peer.states[entry_id], "no state missing its lease changes the held one"
    assert_empty peer.pending_states
    assert_equal [0, 0, 0, 0], [peer.deltas_undecodable, peer.stamps_logical_refused,
                                peer.stamps_far_future_refused, peer.stamps_far_future_deferred]
  end

  # HLC round five, 2026-11-08 (E6): the peer checks a state's or claim's
  # signatures, then its actor's revocation, then its stamps, so a revoked
  # actor's state or claim counts in no stamp counter.
  def test_a_revoked_actors_state_or_claim_counts_in_no_stamp_counter
    peer = CapturingPeer.new(clock: -> { WALL / 1000.0 })
    writer = Identity.generate
    issuer = writer.agent("w")
    taker = Identity.generate
    holder = taker.agent("t")
    honest = signed_write(writer, "#{WALL}:0:#{issuer}", "#{WALL}:0:#{issuer}", WALL)
    peer.fold_state(honest)
    entry_id = honest["record"]["entryId"]
    space_id = honest["record"]["spaceId"]
    far = WALL + Wire::MAX_HLC_SKEW_MILLIS + Wire::HLC_SKEW_MARGIN_MILLIS
    states = [signed_write(writer, hostile_stamp(WALL, issuer), hostile_stamp(WALL, issuer), WALL),
              signed_write(writer, "#{far + 1}:0:#{issuer}", "#{far + 1}:0:#{issuer}", WALL),
              signed_write(writer, "#{far + Wire::HLC_DEFER_WINDOW_MILLIS + 1}:0:#{issuer}",
                           "#{far + Wire::HLC_DEFER_WINDOW_MILLIS + 1}:0:#{issuer}", WALL)]
    claims = [hostile_stamp(WALL, holder), "#{far + 1}:0:#{holder}",
              "#{far + Wire::HLC_DEFER_WINDOW_MILLIS + 1}:0:#{holder}"].map do |stamp|
      Wire.signed_claim(Wire.take_claim(entry_id, space_id, 1, stamp, holder, 0.0, WALL + 60_000), taker)
    end
    peer.revocations.peers[writer.peer_id] = :revoked
    peer.revocations.peers[taker.peer_id] = :revoked
    states.each { |dto| peer.fold_state(dto) }
    claims.each { |signed| peer.fold_claim(entry_id, signed) }
    assert_equal [0, 0, 0], [peer.stamps_logical_refused, peer.stamps_far_future_refused,
                             peer.stamps_far_future_deferred], "a revoked actor counts in no stamp counter"
    assert_equal [entry_id], peer.states.keys
    assert_nil peer.claim_of(entry_id)
  end

  # HLC round six, 2026-11-08 (F3, P1): a claim travels as Java's TakeClaim
  # record writes it, entryId, spaceId, epoch, stamp, holder, bid,
  # expiresAtMillis. A claim whose fields arrive in another order is
  # undecodable even when its holder signed that order (superseding E13's
  # re-ordering), and the peer signs and keeps a claim in record order.
  def test_a_claim_out_of_record_order_is_undecodable_whichever_order_its_holder_signed
    peer = CapturingPeer.new
    writer = Identity.generate
    now = peer.now_ms
    write = signed_write(writer, "#{now}:0:#{writer.agent('w')}", "#{now}:0:#{writer.agent('w')}", now)
    peer.fold_state(write)
    entry_id = write["record"]["entryId"]
    taker = Identity.generate
    holder = taker.agent("t")
    claim = Wire.take_claim(entry_id, write["record"]["spaceId"], 1, "#{now}:0:#{holder}", holder, 0.0, now + 60_000)
    assert_equal %w[entryId spaceId epoch stamp holder bid expiresAtMillis], claim.keys
    signed = Wire.signed_claim(claim, taker)
    reversed = claim.to_a.reverse.to_h
    [signed.merge("claim" => reversed),
     signed.merge("claim" => reversed, "signature" => taker.sign(CBOR.dump(reversed)))].each_with_index do |relabel, n|
      rumor(peer, writer, Wire.claim_delta(entry_id, relabel), 400 + n)
    end
    assert_nil peer.claim_of(entry_id), "a claim out of record order never folds"
    assert_equal 2, peer.deltas_undecodable, "each counts as undecodable"
    rumor(peer, writer, Wire.claim_delta(entry_id, signed), 402)
    assert_equal claim.keys, peer.claim_of(entry_id).keys, "the peer keeps the claim in record order"
    assert_equal CBOR.dump(claim), CBOR.dump(peer.claim_of(entry_id))
  end

  # HLC round six, 2026-11-08 (F1): a claim's epoch and expiresAtMillis are
  # plain integers within a Java long and its bid a finite float64, so a
  # claim whose number arrives as any other CBOR type (a double, a float32, a
  # decimal or bignum tag, text, null, an integer bid) is undecodable, even
  # under its holder's signature over those bytes. The peer drops the
  # carrier whole, the state beside the claim included, counts it in
  # deltas_undecodable, and counts nothing in the stamp counters.
  def test_a_claim_number_in_another_cbor_type_drops_its_carrier_as_undecodable
    peer = CapturingPeer.new
    writer = Identity.generate
    now = peer.now_ms
    taker = Identity.generate
    holder = taker.agent("t")
    expiry = now + 45_000
    {
      "an epoch as the double 1.75" => ["epoch", CBOR.dump(1.75)],
      "an epoch as the double 1.0" => ["epoch", CBOR.dump(1.0)],
      "an epoch as tag 4 1.5" => ["epoch", "\xC4\x82\x20\x0F".b],
      "an epoch as tag 2 over 01" => ["epoch", "\xC2\x41\x01".b],
      "an epoch as the text 1" => ["epoch", CBOR.dump("1")],
      "an epoch under a longer head" => ["epoch", "\x18\x01".b],
      "a bid as the text 0" => ["bid", CBOR.dump("0")],
      "a bid as the integer 0" => ["bid", CBOR.dump(0)],
      "a bid as a float32" => ["bid", CBOR.dump(CBOR::Float32.new(0.0))],
      "a bid as tag 4 1.25" => ["bid", "\xC4\x82\x21\x18\x7D".b],
      "a null bid" => ["bid", CBOR.dump(nil)],
      "an expiry as text" => ["expiresAtMillis", CBOR.dump(expiry.to_s)],
      "an expiry as a double" => ["expiresAtMillis", CBOR.dump(expiry.to_f)],
      "a null expiry" => ["expiresAtMillis", CBOR.dump(nil)]
    }.each_with_index do |(name, (field, sent)), n|
      entry = signed_write(writer, "#{now}:0:#{writer.agent('w')}", "#{now}:0:#{writer.agent('w')}", now)
      entry_id = entry["record"]["entryId"]
      claim = Wire.take_claim(entry_id, entry["record"]["spaceId"], 1, "#{now}:0:#{holder}", holder, 0.0, expiry)
      delta = replace_claim_field(CBOR.dump({ "state" => entry, "claimEntry" => entry_id, "claim" => nil }), claim,
                                  field, sent, name, taker)
      rumor(peer, writer, delta, 300 + n)
      assert_nil peer.claim_of(entry_id), "#{name} never folds"
      refute peer.states.key?(entry_id), "#{name} drops its carrier whole"
      assert_equal n + 1, peer.deltas_undecodable, "#{name} counts as undecodable"
    end
    assert_equal [0, 0, 0], [peer.stamps_logical_refused, peer.stamps_far_future_refused,
                             peer.stamps_far_future_deferred]
  end

  # HLC round five, 2026-11-08 (E8, the claim number rows): a claim's epoch
  # and expiresAtMillis are Java longs and its bid a Java double. Where Java's
  # typed decode refuses a claim, the carrier holds no claim Java reads: an
  # epoch below 1 or missing, an epoch or expiry past a Java long, a bid with
  # no finite double, a boolean, byte string, array, or map in a numeric
  # field, an empty entryId or spaceId, or a holder that is no agent id. The
  # peer drops that carrier whole, the state beside the claim included, and
  # counts it in deltas_undecodable, as Java does, and it counts nothing in
  # the stamp counters. HLC round six, 2026-11-08 (S9, F1): no bignum or
  # decimal stands in a protocol field, whatever its value.
  def test_a_claim_java_cannot_decode_drops_its_carrier_and_counts_as_undecodable
    peer = CapturingPeer.new
    writer = Identity.generate
    now = peer.now_ms
    taker = Identity.generate
    holder = taker.agent("t")
    expiry = now + 45_000
    long_max = (1 << 63) - 1
    {
      "an expiry as tag 2 2^64" => [{}, "expiresAtMillis", "\xC2\x49\x01#{"\x00" * 8}".b],
      "an expiry below a Java long" => [{}, "expiresAtMillis", CBOR.dump(-(1 << 63) - 1)],
      "an epoch as tag 2 2^63" => [{}, "epoch", "\xC2\x49\x00\x80#{"\x00" * 7}".b],
      "an epoch past a Java long" => [{}, "epoch", CBOR.dump(long_max + 1)],
      "a bid as tag 4 1E+1000" => [{}, "bid", "\xC4\x82\x19\x03\xE8\x01".b],
      "an epoch -1 as tag 2 over ff" => [{ "epoch" => -1 }, "epoch", "\xC2\x41\xFF".b],
      "an epoch -1 as tag 3 over 01" => [{ "epoch" => -1 }, "epoch", "\xC3\x41\x01".b],
      "an epoch -1" => [{ "epoch" => -1 }, nil, nil],
      "an epoch 0" => [{ "epoch" => 0 }, nil, nil],
      "an epoch 128 as tag 2 over 80" => [{ "epoch" => 128 }, "epoch", "\xC2\x41\x80".b],
      "a null epoch" => [{}, "epoch", CBOR.dump(nil)],
      "a boolean epoch" => [{}, "epoch", CBOR.dump(true)],
      "a byte string expiry" => [{}, "expiresAtMillis", CBOR.dump("\x01".b)],
      "an array bid" => [{}, "bid", CBOR.dump([0])],
      "an empty spaceId" => [{ "spaceId" => "" }, nil, nil],
      "a holder with a second slash" => [{ "holder" => "#{holder}/x" }, nil, nil]
    }.each_with_index do |(name, (overrides, field, sent)), n|
      entry = signed_write(writer, "#{now}:0:#{writer.agent('w')}", "#{now}:0:#{writer.agent('w')}", now)
      entry_id = entry["record"]["entryId"]
      claim = Wire.take_claim(entry_id, entry["record"]["spaceId"], 1, "#{now}:0:#{holder}", holder, 0.0, expiry)
                .merge(overrides)
      delta = CBOR.dump({ "state" => entry, "claimEntry" => entry_id, "claim" => Wire.signed_claim(claim, taker) })
      delta = replace_claim_field(delta, claim, field, sent, name) unless sent.nil?
      rumor(peer, writer, delta, 200 + n)
      assert_nil peer.claim_of(entry_id), "#{name} never folds"
      refute peer.states.key?(entry_id), "#{name} drops its carrier whole"
      assert_equal n + 1, peer.deltas_undecodable, "#{name} counts as undecodable"
    end
    assert_equal [0, 0, 0], [peer.stamps_logical_refused, peer.stamps_far_future_refused,
                             peer.stamps_far_future_deferred]
    honest = signed_write(writer, "#{now}:0:#{writer.agent('w')}", "#{now}:0:#{writer.agent('w')}", now)
    entry_id = honest["record"]["entryId"]
    claim = Wire.take_claim(entry_id, honest["record"]["spaceId"], long_max, "#{now}:0:#{holder}", holder, 0.0,
                            -(1 << 63))
    sync = { "states" => [honest], "claims" => { entry_id => Wire.signed_claim(claim, taker) } }
    peer.handle(frame(writer, "PULL_RESP", CBOR.dump({ "deltas" => { "space:tasks" => CBOR.dump(sync) } }),
                      peer.identity.peer_id, stamp(now, 1)))
    assert peer.states.key?(entry_id), "a sync delta whose claim holds Java's extreme longs decodes"
    assert_equal 16, peer.deltas_undecodable
    bad = sync.merge("claims" => { entry_id => Wire.signed_claim(claim.merge("epoch" => 0), taker) })
    other = signed_write(writer, "#{now}:0:#{writer.agent('w')}", "#{now}:0:#{writer.agent('w')}", now)
    bad["states"] = [other]
    peer.handle(frame(writer, "PULL_RESP", CBOR.dump({ "deltas" => { "space:tasks" => CBOR.dump(bad) } }),
                      peer.identity.peer_id, stamp(now, 2)))
    refute peer.states.key?(other["record"]["entryId"]), "a sync delta with an undecodable claim drops whole"
    assert_equal 17, peer.deltas_undecodable
  end

  # The encoded delta with one claim field's encoded value replaced by sent.
  # With signer, the delta's null claim becomes the claim as sent, signed by
  # signer over those bytes.
  def replace_claim_field(delta, claim, field, sent, name, signer = nil)
    signed_value = CBOR.dump(field) + CBOR.dump(claim[field])
    unless signer.nil?
      raw = CBOR.dump(claim)
      assert_equal 1, raw.scan(signed_value).size, "#{name}: the field appears once"
      raw = raw.sub(signed_value) { CBOR.dump(field) + sent }
      signed = "\xBF".b + CBOR.dump("claim") + raw + CBOR.dump("holderKey") + CBOR.dump(signer.public_raw) +
               CBOR.dump("signature") + CBOR.dump(signer.sign(raw)) + "\xFF".b
      return delta.sub(CBOR.dump("claim") + CBOR.dump(nil)) { CBOR.dump("claim") + signed }
    end
    assert_equal 1, delta.scan(signed_value).size, "#{name}: the field appears once"
    delta.sub(signed_value) { CBOR.dump(field) + sent }
  end

  # HLC round five, 2026-11-08 (E14): the refused-offer and deferred-offer
  # memories hold 4096 keys each and evict the least recently used one, so an
  # offer re-sent every round stays remembered while 4096 others pass.
  def test_the_offer_memories_evict_the_least_recently_used_key
    wall = WALL
    peer = CapturingPeer.new(clock: -> { wall / 1000.0 })
    taker = Identity.generate
    holder = taker.agent("t")
    space_id = Derive.space_id_local("#{GROUP}/tasks")
    deferred_at = WALL + Wire::MAX_HLC_SKEW_MILLIS + Wire::HLC_SKEW_MARGIN_MILLIS + 1
    { refused: [hostile_stamp(WALL, holder), :stamps_logical_refused],
      deferred: ["#{deferred_at}:0:#{holder}", :stamps_far_future_deferred] }.each do |name, (stamp, counter)|
      offer = lambda do
        entry_id = SecureRandom.uuid
        [entry_id, Wire.signed_claim(Wire.take_claim(entry_id, space_id, 1, stamp, holder, 0.0, WALL + 60_000), taker)]
      end
      kept = offer.call
      peer.fold_claim(*kept)
      (Peer::REFUSED_STAMP_MEMORY - 1).times { peer.fold_claim(*offer.call) }
      assert_equal Peer::REFUSED_STAMP_MEMORY, peer.public_send(counter), "#{name}: every distinct offer counts"
      peer.fold_claim(*kept)
      peer.fold_claim(*offer.call)
      peer.fold_claim(*kept)
      assert_equal Peer::REFUSED_STAMP_MEMORY + 1, peer.public_send(counter),
                   "#{name}: the offer re-sent last stays remembered"
    end
  end

  # HLC round five, 2026-11-08 (E11): no peer can send a lone surrogate
  # (U+D800 to U+DFFF) as UTF-8, so the clock and the identity refuse a node
  # or agent name holding one, in whatever encoding it comes.
  def test_the_clock_and_the_identity_refuse_a_lone_surrogate
    identity = Identity.generate
    ["n\xED\xA0\x80".dup.force_encoding(Encoding::UTF_8), "\xED\xBF\xBF".dup.force_encoding(Encoding::UTF_8),
     "\xD8\x00".dup.force_encoding(Encoding::UTF_16BE), "\x00\xDC".dup.force_encoding(Encoding::UTF_16LE)].each do |node|
      assert_raises(ArgumentError, "the clock refuses #{node.dump}") { Wire.hlc_now(node, WALL) }
      assert_raises(ArgumentError, "the identity refuses #{node.dump}") { identity.agent(node) }
    end
    node = "#{clock_node}\u{FFFD}"
    assert_equal [WALL, 0, node], Wire.hlc_parse(Wire.hlc_now(node, WALL)), "U+FFFD itself is a character"
  end

  # HLC round four, 2026-11-08 (D6): a peer never emits a stamp whose node
  # breaks the grammar, so the clock refuses such a node and an identity
  # refuses an agent name that would make one.
  def test_the_clock_and_the_identity_refuse_a_node_outside_the_stamp_grammar
    ["", "a:b", "a\nb", "a\u0000b", "a\u007Fb", "\xFF".dup.force_encoding(Encoding::UTF_8), "ab".b, nil, 5].each do |node|
      assert_raises(ArgumentError, "the clock refuses the node #{node.inspect}") { Wire.hlc_now(node, WALL) }
    end
    node = "#{clock_node}/agent one ñ"
    assert_equal [WALL, 0, node], Wire.hlc_parse(Wire.hlc_now(node, WALL))
    identity = Identity.generate
    ["", "a/b", "a:b", "a\tb", "\u007F", "\xFF".dup.force_encoding(Encoding::UTF_8), nil].each do |name|
      assert_raises(ArgumentError, "the identity refuses the agent name #{name.inspect}") { identity.agent(name) }
    end
    assert_equal "#{identity.peer_id}/worker one", identity.agent("worker one")
    assert_raises(ArgumentError) { identity.subordinate("a:b", Instants.iso(WALL), "PT1H") }
  end

  # HLC round six, 2026-11-08 (R5): an agent id on the wire is Java's
  # AgentId, <peerId>/<localName>, with no "/" and no ":" in the local name.
  # A record issuer, a claim holder, or a certificate's agent outside the
  # grammar makes its carrier undecodable, even under an honest signature.
  def test_an_agent_id_outside_the_grammar_makes_its_carrier_undecodable
    peer = CapturingPeer.new
    writer = Identity.generate
    now = peer.now_ms
    write = signed_write(writer, "#{now}:0:#{writer.agent('w')}", "#{now}:0:#{writer.agent('w')}", now)
    peer.fold_state(write)
    entry_id = write["record"]["entryId"]
    taker = Identity.generate
    ["#{taker.peer_id}/t:1", "#{taker.peer_id}/t/1", "/t", "#{taker.peer_id}/"].each_with_index do |holder, n|
      assert_equal false, Wire.agent_id?(holder), "#{holder.inspect} is no agent id"
      claim = Wire.take_claim(entry_id, write["record"]["spaceId"], 1, "#{now}:#{n}:#{taker.peer_id}", holder, 0.0,
                              now + 60_000)
      rumor(peer, writer, Wire.claim_delta(entry_id, Wire.signed_claim(claim, taker)), 500 + n)
    end
    assert_nil peer.claim_of(entry_id)
    assert_equal 4, peer.deltas_undecodable
    certificate = Certificates.sign(Certificates.build("#{writer.peer_id}/a:b", taker.public_raw, Instants.iso(now),
                                                       "PT1H"), writer)
    rumor(peer, writer, { "state" => write.merge("agentCertificate" => certificate), "claimEntry" => nil,
                          "claim" => nil }, 504)
    assert_equal 5, peer.deltas_undecodable, "a certificate's agent outside the grammar is undecodable"
  end

  # HLC round six, 2026-11-08 (R6): a rival's claim whose stamp lies more
  # than the drift ceiling plus Java's 200 ms settle window in the past
  # cannot contest a held entry (ReplicatedSpace.mergeClaim). At wall T the
  # bound is T-600200: a rival at T-600201 leaves the holder at T-600050 in
  # place, and a rival at T-600199 races it and takes it with the lower stamp.
  def test_a_far_past_claim_contests_a_held_claim_only_inside_javas_settle_window
    [[600_201, 600_050], [600_199, 600_199]].each do |rival_age, winner_age|
      peer = CapturingPeer.new(clock: -> { WALL / 1000.0 })
      writer = Identity.generate
      issued = "#{WALL - 1_000}:0:#{writer.agent('w')}"
      write = signed_write(writer, issued, issued, WALL)
      peer.fold_state(write)
      entry_id = write["record"]["entryId"]
      space_id = write["record"]["spaceId"]
      claim_at = lambda do |age, n|
        taker = Identity.generate
        holder = taker.agent("t")
        Wire.claim_delta(entry_id, Wire.signed_claim(Wire.take_claim(entry_id, space_id, 1, "#{WALL - age}:0:#{holder}",
                                                                     holder, 0.0, WALL + 1_000), taker))
      end
      rumor(peer, writer, claim_at.call(600_050, 0), 0)
      rumor(peer, writer, claim_at.call(rival_age, 1), 1)
      assert_equal WALL - winner_age, Wire.hlc_physical(peer.claim_of(entry_id)["stamp"]),
                   "a rival at T-#{rival_age} leaves the claim at T-#{winner_age}"
      assert_equal 0, peer.deltas_undecodable
    end
  end

  # HLC round six, 2026-11-08 (R10): a claim for an entry this replica never
  # held leaves the claim map once its expiry passes, so the map stays
  # bounded under churn, and a claim on an entry the replica holds stays.
  def test_claims_for_entries_never_held_leave_once_they_expire
    wall = WALL
    peer = CapturingPeer.new(clock: -> { wall / 1000.0 })
    writer = Identity.generate
    write = signed_write(writer, "#{WALL}:0:#{writer.agent('w')}", "#{WALL}:0:#{writer.agent('w')}", WALL)
    peer.fold_state(write)
    held = write["record"]["entryId"]
    space_id = write["record"]["spaceId"]
    taker = Identity.generate
    holder = taker.agent("t")
    claim_on = lambda do |entry_id, n|
      Wire.claim_delta(entry_id, Wire.signed_claim(Wire.take_claim(entry_id, space_id, 1, "#{wall}:#{n}:#{holder}",
                                                                   holder, 0.0, wall + 1_000), taker))
    end
    rumor(peer, writer, claim_on.call(held, 0), 0)
    rounds = 10
    per_round = 600
    n = 0
    rounds.times do
      per_round.times { rumor(peer, writer, claim_on.call(SecureRandom.uuid, n += 1), n) }
      wall += 2_000
    end
    assert_equal rounds * per_round, n
    assert_operator peer.claims.size, :<=, (2 * per_round) + 2, "the claim map stays bounded"
    assert peer.claims.key?(held), "a claim on a held entry stays after its expiry"
    assert_equal 0, peer.deltas_undecodable
  end

  # HLC round six, 2026-11-08 (R10): a pass over the claim map keeps every
  # live claim on an entry this replica never held, as Java's
  # dropOrphanedClaims keeps it; only an expired one leaves.
  def test_a_live_claim_on_an_entry_never_held_survives_the_pass_over_the_claim_map
    peer = CapturingPeer.new(clock: -> { WALL / 1000.0 })
    writer = Identity.generate
    taker = Identity.generate
    holder = taker.agent("t")
    space_id = Derive.space_id_local("#{GROUP}/tasks")
    count = Peer::CLAIMS_PRUNE_FLOOR + 8
    count.times do |n|
      entry_id = SecureRandom.uuid
      claim = Wire.take_claim(entry_id, space_id, 1, "#{WALL}:#{n}:#{holder}", holder, 0.0, WALL + 60_000)
      rumor(peer, writer, Wire.claim_delta(entry_id, Wire.signed_claim(claim, taker)), n)
    end
    assert_equal count, peer.claims.size, "every live claim stays through the pass"
    assert_equal 0, peer.deltas_undecodable
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
    assert_equal [1, 1], [peer.frames.logical_refused, peer.frames.replayed], "the replay memory runs before the limit"
    far = frame(other, "PING", Wire.ping_body(2), peer.identity.peer_id,
                "#{now + Wire::MAX_HLC_SKEW_MILLIS + 60_000}:#{LIMIT + 1}:other")
    2.times { peer.handle(far) }
    assert_equal [1, 1, 2], [peer.frames.far_future, peer.frames.logical_refused, peer.frames.replayed],
                 "the far-future check runs after the replay memory and before the limit"
    peer.handle(frame(other, "PING", Wire.ping_body(3), peer.identity.peer_id,
                      "#{now - Wire::MAX_FRAME_AGE_MILLIS - 1000}:#{LIMIT + 1}:other"))
    assert_equal [1, 1], [peer.frames.stale, peer.frames.logical_refused], "the stale window runs before the limit"
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
    assert_equal [2, 0], [peer.frames.far_future_skewed, peer.frames.far_future]
    peer.handle(frame(other, "PING", Wire.ping_body(7), peer.identity.peer_id,
                      stamp(ceiling + Wire::HLC_SKEW_MARGIN_MILLIS + 1)))
    assert_equal [2, 1], [peer.frames.far_future_skewed, peer.frames.far_future]
    assert_equal 2, peer.frames.to_h["framesFarFutureSkewed"]
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
    assert_equal [1, 0], [receiver.far_future_skewed, receiver.far_future],
                 "a receiver two seconds behind drops it as skewed"
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

  # Swarm retries (ROBUSTNESS.md 10.3 E5): rounds of seed dials back off from
  # the interval to six times it with a spread, and go on past the old window
  # until the owner closes the peer.
  def test_reconnect_rounds_back_off_and_go_on_until_the_owner_closes_the_peer
    peer = Peer.new(Identity.generate, GROUP)
    peer.reconnect_interval = 0.02
    peer.reconnect_window = 0.1
    dials = []
    dialer = Object.new
    dialer.define_singleton_method(:open) do |_seed, identity:|
      dials << Process.clock_gettime(Process::CLOCK_MONOTONIC)
      peer.instance_variable_set(:@running, false) if dials.size >= 8 # the owner closes the peer
      raise Errno::ECONNREFUSED, "refused"
    end
    peer.define_singleton_method(:dialer_for) { |_scheme| dialer }
    peer.instance_variable_set(:@running, true)
    peer.instance_variable_set(:@seed, AgentSpaces::Seed.new(scheme: "tcp", host: "127.0.0.1", port: 9))
    refute peer.send(:reconnect)
    assert_equal 8, dials.size, "the dials went on past the window"
    gaps = dials.each_cons(2).map { |a, b| b - a }
    assert_operator gaps[0], :>=, 0.02
    assert_operator gaps[2], :>=, 0.08
    assert(gaps.all? { |g| g <= (0.12 * 1.25) + 0.05 }, gaps.inspect)
  end

  # Swarm retries, the gate's adversarial review (ROBUSTNESS.md 10.6): a seed
  # that accepts every dial and closes it at once, as one that refuses this
  # peer or is still starting does, gets the paused rounds of a refused dial.
  # A link that ends within the reconnect interval counts as a failed round.
  def test_a_seed_that_drops_each_link_at_once_gets_the_backoff_and_no_dial_loop
    server = TCPServer.new("127.0.0.1", 0)
    dials = []
    acceptor = Thread.new do
      loop do
        link = server.accept
        dials << Process.clock_gettime(Process::CLOCK_MONOTONIC)
        link.close
      end
    rescue IOError, SystemCallError
      nil
    end
    peer = Peer.new(Identity.generate, GROUP)
    peer.reconnect_interval = 0.1
    peer.connect("127.0.0.1", server.addr[1])
    sleep 1.5
    peer.close
    count = dials.size
    assert_operator count, :>=, 2
    assert_operator count, :<=, 8, "#{count} dials in 1.5 s"
    gaps = dials.each_cons(2).map { |a, b| b - a }
    assert(gaps.all? { |g| g >= 0.09 }, gaps.inspect)
  ensure
    server&.close
    acceptor&.join(1)
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
