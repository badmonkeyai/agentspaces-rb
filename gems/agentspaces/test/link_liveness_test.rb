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

module LinkRound
  Job = AgentSpaces::Entry.define("com.acme.LinkJob#v1", topic: String)
end

# Round 2a of the event-loop parity (owner decisions 2026-11-23;
# .parity-wt/PARITY-ruby.md): the dead-seed rule (peer_link.rb), the wake
# that cuts a reconnect pause short, and the dial-only peer's answer to its
# seed's DIGEST (peer_answer.rb). Every timed case runs on virtual time over
# an in-memory channel: nothing here waits out a timer.
class LinkLivenessTest < Minitest::Test
  include AgentSpaces
  include GoldenHelpers

  GROUP = "zRubyLinkRound"

  # An in-memory link: what the peer sends is decoded and kept; what the
  # test delivers is read by the peer's reader; a drop makes the reader's
  # read fail as a reset would.
  class FakeChannel
    attr_reader :seed, :sent

    def initialize(seed)
      @seed = seed
      @inbox = Thread::Queue.new
      @sent = []
      @lock = Mutex.new
      @closed = false
    end

    def send_frame(frame)
      raise IOError, "closed" if @closed

      env = AgentSpaces::Wire.decode_frame(frame)
      @lock.synchronize { @sent << env } if env
    end

    def read_frame
      frame = @inbox.pop
      raise IOError, "closed" if frame == :closed

      frame
    end

    def deliver(frame) = @inbox << frame

    # The reader's hook for bytes of a frame still arriving (FrameChannel#on_bytes=).
    attr_accessor :on_bytes

    # Bytes of a large frame arrive; the frame is not yet whole.
    def trickle = @on_bytes&.call

    def drop = @inbox << :closed

    def close
      @closed = true
      @inbox << :closed
    end

    def closed? = @closed

    def attested_peer = nil

    def kinds = @lock.synchronize { @sent.map { |env| env["kind"] } }
  end

  # A dialer over FakeChannels: each open is one channel, in order.
  class FakeDialer < AgentSpaces::Dialer
    attr_reader :channels

    def initialize
      super
      @channels = []
      @lock = Mutex.new
    end

    def schemes = ["tcp"]

    def open(seed, identity: nil, timeout: 10)
      channel = FakeChannel.new(seed)
      @lock.synchronize { @channels << channel }
      channel
    end

    def count = @lock.synchronize { @channels.size }
  end

  SEED_A = "127.0.0.1:7101"
  SEED_B = "127.0.0.1:7102"

  def setup
    @peers = []
    @time = VirtualTime.new
    @dialer = FakeDialer.new
    @seed_identity = Identity.generate
  end

  def teardown = @peers.each(&:close)

  def dialled_peer(seeds = [SEED_A, SEED_B])
    peer = Peer.new(Identity.generate, GROUP, time: @time, dialers: [@dialer])
    @peers << peer
    peer.reconnect_interval = 0.01
    peer.connect_any(seeds)
    peer.run_due
    peer
  end

  # A frame from the seed, addressed to the peer and signed by the seed.
  def from_seed(peer, kind, body)
    stamp = Wire.hlc_now(@seed_identity.peer_id, @time.wall_ms)
    Wire.encode_frame(Wire.envelope(GROUP, kind, @seed_identity.peer_id, stamp, body, peer.identity.peer_id),
                      @seed_identity)
  end

  def pings(channel) = channel.kinds.count("PING")

  # ------------------------------------------------------ the dead-seed rule

  def test_a_seed_silent_for_45_seconds_is_pinged
    peer = dialled_peer
    link = @dialer.channels.first
    peer.advance(44.9)
    assert_equal 0, pings(link), "no PING while the seed may still speak"
    peer.advance(0.2)
    assert_equal 1, pings(link), "one PING once the link has been silent 45 s"
    assert peer.link_asked?
    ping = link.sent.reverse.find { |env| env["kind"] == "PING" }
    assert_kind_of Integer, Wire.decode_body("PING", ping["body"])["nonce"]
    assert_equal 1, peer.seed_pings
    assert_equal 0, peer.wake_pings, "a silence PING is no wake's"
  end

  def test_a_seed_that_does_not_answer_is_left_for_the_next_within_the_ping_timeout
    peer = dialled_peer
    link = @dialer.channels.first
    link.deliver(from_seed(peer, "PING", Wire.ping_body(1))) # the seed's probe names it the holder
    assert eventually { peer.resource_hints["relay.via"] == @seed_identity.peer_id }
    peer.advance(45.1)
    assert_equal 1, pings(link)
    peer.advance(1.8)
    refute link.closed?, "the PING still has time to be answered"
    assert_equal 0, peer.links_silent
    peer.advance(0.3)
    assert link.closed?, "no answer within the 2 s ping timeout (SPEC 9.4): the link is dead"
    assert_equal 1, peer.links_silent
    assert eventually { @dialer.count == 2 }, "the reader failed over"
    assert_equal SEED_B, @dialer.channels.last.seed.authority, "to the next seed first"
    assert eventually { peer.connected? }
    assert_nil peer.resource_hints["relay.via"], "the hint no longer names the seed it left"
    assert eventually { @dialer.channels.last.kinds.first == "RUMOR" }, "and it introduced itself there"
  end

  # Found by the full run (Harmonization): the reader clears the link only
  # once it sees the close, so a loop on virtual time could judge the
  # closed link again before that, PING it and close it again at every
  # backstop, 37 times in ten idle minutes. A link the duty closed is not
  # judged again.
  def test_a_link_the_duty_closed_is_not_judged_again_before_the_reader_sees_it
    peer = dialled_peer
    link = @dialer.channels.first
    # The reader does not see this close: it stays blocked, as it may be
    # for a while under load.
    link.define_singleton_method(:close) { @closed = true }
    peer.advance(45.1)
    peer.advance(2.1)
    assert link.closed?
    assert_equal 1, peer.links_silent
    peer.advance(600)
    assert_equal 1, pings(link), "one PING, not one per backstop"
    assert_equal 1, peer.links_silent
    link.drop # the reader sees it now and fails over
    assert eventually { @dialer.count == 2 && peer.connected? }
  end

  def test_a_seed_that_answers_the_ping_is_kept
    peer = dialled_peer
    link = @dialer.channels.first
    peer.advance(45.1)
    assert peer.link_asked?
    link.deliver(from_seed(peer, "ACK", Wire.ack_body(7)))
    assert eventually { !peer.link_asked? }, "the ACK was read"
    peer.advance(15.1)
    refute link.closed?
    assert_equal 0, peer.links_silent
    assert_equal 1, @dialer.count
    peer.advance(29.8)
    assert_equal 1, pings(link), "the next PING waits 45 s from the ACK"
    peer.advance(0.2)
    assert_equal 2, pings(link)
  end

  def test_bytes_of_a_frame_still_arriving_answer_the_ping
    peer = dialled_peer
    link = @dialer.channels.first
    peer.advance(45.1)
    assert peer.link_asked?
    peer.advance(1.5)
    link.trickle # a large frame on a slow link: the seed is writing
    refute peer.link_asked?, "bytes in flight answer the PING"
    peer.advance(1.0)
    refute link.closed?, "a slow frame is no dead seed"
    assert_equal 0, peer.links_silent
    peer.advance(43.9)
    assert_equal 1, pings(link), "the next PING waits 45 s from the last bytes"
    peer.advance(0.2)
    assert_equal 2, pings(link)
  end

  def test_a_busy_seed_is_never_pinged
    peer = dialled_peer
    link = @dialer.channels.first
    9.times do |i|
      peer.advance(20)
      link.deliver(from_seed(peer, "PING", Wire.ping_body(100 + i)))
      assert eventually { link.kinds.count("ACK") == i + 1 }
    end
    assert_equal 0, pings(link), "a seed whose own probes keep the link busy is never asked"
  end

  # --------------------------------------------- a wake during a reconnect pause

  def test_a_wake_during_a_reconnect_pause_redials_at_once
    peer = dialled_peer([SEED_A])
    peer.reconnect_interval = 60.0 # the link below ends at once: a pause of 60 to 75 s of real time
    @dialer.channels.first.drop
    assert eventually { !peer.connected? }
    assert_equal 1, @dialer.count, "pausing before it dials again"
    @time.advance(7200) # a laptop sleep as macOS counts it: the loop wakes late
    peer.run_due
    assert_equal 1, peer.resumes
    assert eventually(3.0) { @dialer.count == 2 }, "the wake cut the pause short and dialled"
    assert eventually { peer.connected? }
  end

  # ------------------------------------------- a wake while the link is up

  # Harmonization rule 3 (owner decision 2026-11-23): a wake with the link up
  # PINGs the seed at once, without closing the link; no answer within the
  # 2 s ping timeout fails over to the next seed at once, however young the
  # link (reconnect_interval 60 s here would otherwise pause 54 to 66 s).
  def test_a_wake_while_linked_pings_and_fails_over_on_silence
    peer = dialled_peer
    peer.reconnect_interval = 60.0
    link = @dialer.channels.first
    @time.advance(7200) # a laptop sleep as macOS counts it: the loop wakes late
    peer.run_due
    assert_equal 1, peer.resumes
    assert eventually { pings(link) == 1 }, "the wake asked the seed"
    refute link.closed?, "and kept the link while it waits"
    @time.advance(Peer::LINK_ANSWER - 0.1)
    peer.run_due
    refute link.closed?, "within the ping timeout"
    assert_equal 1, @dialer.count
    @time.advance(0.2)
    peer.run_due
    assert link.closed?, "no answer in 2 s: the link is dead"
    assert_equal 1, peer.links_silent
    assert eventually(3.0) { @dialer.count == 2 && peer.connected? }, "failed over at once, with no pause"
    assert_equal SEED_B, @dialer.channels.last.seed.authority, "to the next seed; the silent one is last"
  end

  def test_a_wake_while_linked_keeps_a_seed_that_answers
    peer = dialled_peer
    link = @dialer.channels.first
    rumors = link.kinds.count("RUMOR")
    @time.advance(7200)
    peer.run_due
    assert eventually { pings(link) == 1 }
    link.deliver(from_seed(peer, "ACK", "".b))
    assert eventually { !peer.link_asked? }, "the answer was heard"
    @time.advance(Peer::LINK_ANSWER + 1)
    peer.run_due
    refute link.closed?
    assert_equal 0, peer.links_silent
    assert_equal 1, @dialer.count, "no redial"
    assert_operator link.kinds.count("RUMOR"), :>, rumors, "the peer introduced itself again on the link it kept"
  end

  # ------------------------------ the members after a wake (owner decision 3)

  def card_of(who, issued_ms)
    ad = Wire.peer_advertisement(GROUP, who, Instants.iso(issued_ms - (issued_ms % 1000)), "PT10M")
    Wire.signed_peer_ad(ad, who)
  end

  # The "view" digests the peer sent on a link, each as the ids it names.
  def view_pulls(channel)
    channel.sent.select { |env| env["kind"] == "DIGEST" }.filter_map do |env|
      CBOR.load(env["body"])["digests"]["view"]&.split("\n")
    end
  end

  # A process frozen past every card's TTL (SIGSTOP, a long GC or VM pause:
  # both clocks ran, the loop wakes 700 s late). The members' cards lapsed
  # only because this peer was frozen: they are probed (a view pull through
  # the seed, naming none of them) and stay in view until the answer, which
  # brings back the one the seed still holds; the other leaves then.
  def test_a_frozen_peer_reprobes_the_members_before_it_drops_them
    peer = dialled_peer
    link = @dialer.channels.first
    stays, gone = Array.new(2) { Identity.generate }
    both = [stays.peer_id, gone.peer_id].sort
    [stays, gone].each { |who| peer.send(:accept_peer_ad, card_of(who, @time.wall_ms)) }
    assert_equal both, peer.view_members.sort
    @time.advance(700)
    peer.run_due
    assert_equal 1, peer.resumes, "the late wake is a wake"
    assert_equal 1, peer.loop_stats[:view_reprobes]
    assert_equal both, peer.view_members.sort, "probed, not dropped"
    refute peer.send(:view_hinted?, peer.now_ms), "and judged as lacking the hint meanwhile"
    assert eventually { view_pulls(link).include?([peer.identity.peer_id]) },
           "the view pulled at once, naming none of the lapsed cards"
    answer = Peer.pull_resp_body({ "view" => CBOR.dump([card_of(stays, @time.wall_ms)]) })
    link.deliver(from_seed(peer, "PULL_RESP", answer))
    others = -> { peer.view_members - [@seed_identity.peer_id] } # the seed is heard from now
    assert eventually { others.call == [stays.peer_id] }, "the answer kept one; the other left with it"
  end

  # Cross-client check (2026-11-23): a frozen process's wake counts in
  # late_wakes, as the core's lateWakes and every client's late_wakes; a
  # wake a wall step explains (a suspend) does not, and neither does a loop
  # exactly 30 s late ("more than 30 s").
  def test_a_frozen_process_counts_one_late_wake_and_a_suspend_none
    peer = dialled_peer
    peer.run_due
    @time.advance(700)
    peer.run_due
    assert_equal 1, peer.resumes
    assert_equal 1, peer.loop_stats[:late_wakes], "a frozen process: a late wake"
    @time.suspend(700)
    peer.run_due
    assert_equal 2, peer.resumes, "a suspend is a wake too"
    assert_equal 1, peer.loop_stats[:late_wakes], "explained by its wall step: no late wake"
    peer.send(:judge_time, @time.mono, Peer::KEEPALIVE_TTL)
    assert_equal 1, peer.loop_stats[:late_wakes], "exactly 30 s late: no wake"
    peer.send(:judge_time, @time.mono, Peer::KEEPALIVE_TTL + 0.001)
    assert_equal 2, peer.loop_stats[:late_wakes]
  end

  def test_a_reprobe_with_no_answer_ends_at_its_bound
    peer = dialled_peer
    who = Identity.generate
    peer.send(:accept_peer_ad, card_of(who, @time.wall_ms))
    @time.suspend(700) # Linux: the wall moved, the monotonic clock did not
    peer.run_due
    assert_equal [who.peer_id], peer.view_members, "probed, not dropped"
    bound = peer.send(:view_reprobe_wait)
    assert_in_delta 11.25, bound, 1e-9
    peer.advance(bound - 0.5)
    assert_equal [who.peer_id], peer.view_members, "still waiting on the answer"
    peer.advance(1.0)
    assert_empty peer.view_members, "no answer by the bound: judged by its card"
  end

  # A relink after the wake pulls the view with the join (SPEC 5.2) and
  # names no lapsed card, so the seed's answer brings those members back.
  def test_the_joins_view_digest_names_no_lapsed_card
    peer = dialled_peer
    lapsed, live = Array.new(2) { Identity.generate }
    peer.send(:accept_peer_ad, card_of(lapsed, @time.wall_ms - 700_000))
    peer.send(:accept_peer_ad, card_of(live, @time.wall_ms))
    assert_equal [live.peer_id, peer.identity.peer_id].sort, peer.view_digest.split("\n")
  end

  def test_a_close_during_a_reconnect_pause_ends_the_reader_at_once
    peer = dialled_peer([SEED_A])
    peer.reconnect_interval = 60.0
    @dialer.channels.first.drop
    assert eventually { !peer.connected? }
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    peer.close
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 1.0,
                    "the close woke the pause; the reader was not left to the 2 s join"
    assert_equal 1, @dialer.count
  end

  # ------------------------------------------------- the answer to a DIGEST

  # A seed and a dial-only peer of an in-memory network; the dial-only
  # peer's link is to the seed.
  def digest_pair
    seed, dialled, stranger = Testing::Network.fleet(GROUP, 3, time: @time)
    @peers.push(seed, dialled, stranger)
    dialled.instance_variable_set(:@seed_peer, seed.identity.peer_id)
    lost = []
    dropping = [true]
    dialled.define_singleton_method(:send_frame) do |kind, body, to = nil|
      next lost << kind if kind == "RUMOR" && dropping[0]

      super(kind, body, to)
    end
    [seed, dialled, stranger, dropping]
  end

  def digest_from(asker, to, space)
    asker.send(:send_frame, "DIGEST", Wire.digest_body({ "space:#{space}" => asker.text_digest(space) }), to.identity.peer_id)
  end

  def test_a_dial_only_peer_answers_its_seeds_digest_and_a_lost_rumor_is_repaired
    seed, dialled, _stranger, dropping = digest_pair
    id = dialled.space("tasks").write(LinkRound::Job.new(topic: "lost on the link"), lease: "10m")
    dialled.renew_entry("tasks", id, lease_millis: 1_200_000) # a renewal: the joined state is no longer one signed state
    dropping[0] = false
    assert_nil seed.states[id], "the write's rumor never reached the seed"

    digest_from(seed, dialled, "tasks")
    assert_equal 1, dialled.pull_resps_sent, "the dial-only peer answered with a PULL_RESP"
    refute_nil seed.states[id], "the seed folded the repaired state: it verified there"
    assert_equal dialled.states[id]["leaseValue"], seed.states[id]["leaseValue"], "with the renewed lease"
    assert_equal dialled.text_digest("tasks"), seed.text_digest("tasks")

    digest_from(seed, dialled, "tasks")
    assert_equal 2, dialled.digests_answered
    assert_equal 1, dialled.pull_resps_sent, "nothing to send once the seed holds it all"
  end

  def test_a_lost_claim_is_repaired_too
    seed, dialled, = digest_pair
    id = seed.space("tasks").write(LinkRound::Job.new(topic: "claimed"), lease: "10m")
    holder = dialled.identity.agent("ruby")
    own = Wire.signed_claim(Wire.take_claim(id, seed.states[id]["record"]["spaceId"], 1,
                                            Wire.hlc_now(holder, @time.wall_ms), holder, 0.0, @time.wall_ms + 60_000),
                            dialled.identity)
    dialled.fold_claim(id, own) # held here; its rumor never left
    assert_nil seed.claim_of(id)
    digest_from(seed, dialled, "tasks")
    assert_equal holder, seed.claim_of(id)["holder"]
  end

  def test_a_digest_from_any_member_but_the_link_holder_is_ignored
    _seed, dialled, stranger, dropping = digest_pair
    dialled.space("tasks").write(LinkRound::Job.new(topic: "mine"), lease: "10m")
    dropping[0] = false
    digest_from(stranger, dialled, "tasks")
    assert_equal 1, dialled.ignored_kinds["DIGEST"]
    assert_equal 0, dialled.digests_answered
    assert_equal 0, dialled.pull_resps_sent
  end

  def test_an_answer_is_cut_to_the_askers_budget_with_its_remainder
    seed, dialled, = digest_pair
    3.times { |i| dialled.space("tasks").write(LinkRound::Job.new(topic: "job #{i}"), lease: "10m") }
    answers = []
    seed.define_singleton_method(:handle) do |env, relayed: false|
      answers << Wire.decode_body("PULL_RESP", env["body"]) if env["kind"] == "PULL_RESP"
      super(env, relayed: relayed)
    end
    seed.send(:send_frame, "DIGEST", Wire.digest_body({ "space:tasks" => "".b }, budget: 64), dialled.identity.peer_id)
    assert_equal 1, answers.size
    assert_equal({ "space:tasks" => 2 }, answers[0]["remainder"], "the first state always goes; two are left")
    sync = Schema.load("SpaceWire.SyncDelta", answers[0]["deltas"]["space:tasks"])
    assert_equal 1, sync["states"].size
  end

  def test_the_answer_bodies_have_the_reference_bytes
    plain = hex("pull_resp_body_cbor")
    resp = Wire.decode_body("PULL_RESP", plain)
    assert_equal plain, Peer.pull_resp_body(resp["deltas"])
    budgeted = hex("pull_resp_remainder_body_cbor")
    resp = Wire.decode_body("PULL_RESP", budgeted)
    assert_equal budgeted, Peer.pull_resp_body(resp["deltas"], resp["remainder"])
    delta = resp["deltas"]["space:tasks"]
    sync = Schema.load("SpaceWire.SyncDelta", delta)
    assert_equal delta, Peer.sync_delta_bytes(sync["states"], sync["claims"])
  end

  # ------------------------------------- bytes of a frame still arriving

  # A frame over a socket pair, written in pieces by a thread; returns the
  # frame read and how often the channel's on_bytes hook ran.
  def read_over_pair(body, pieces: 1, hooked: true)
    reader_io, writer_io = UNIXSocket.pair
    channel = FrameChannel.new(reader_io, nil)
    calls = 0
    channel.on_bytes = -> { calls += 1 } if hooked
    wire = [body.bytesize].pack("N") + body
    step = (wire.bytesize + pieces - 1) / pieces
    writer = Thread.new { wire.bytes.each_slice(step) { |slice| writer_io.write(slice.pack("C*")) } }
    frame = channel.read_frame
    writer.join
    [frame, calls]
  ensure
    reader_io&.close
    writer_io&.close
  end

  # Owner decision 4 of 2026-11-23: bytes of a frame still arriving count as
  # the seed's answer everywhere, so every hooked read reports each piece,
  # the length prefix's included, whatever the frame's size (before, only a
  # read past READ_STEP did). Boundaries: 1 byte, READ_STEP, READ_STEP + 1
  # and 3 x READ_STEP + 7, each in pieces; one piece; and the unhooked path.
  def test_every_hooked_read_reports_its_pieces_whatever_its_size
    step = FrameChannel::READ_STEP
    [[1, 1], [200, 4], [step, 4], [step + 1, 4], [(3 * step) + 7, 9]].each_with_index do |(size, pieces), i|
      body = Random.new(i + 1).bytes(size)
      frame, calls = read_over_pair(body, pieces: pieces)
      assert_equal body, frame, "#{size} bytes in #{pieces} pieces"
      assert_equal Encoding::BINARY, frame.encoding
      assert_operator calls, :>=, 2, "#{size} bytes: the prefix and the body each report (#{calls})"
    end
    body = Random.new(9).bytes(300)
    frame, calls = read_over_pair(body, pieces: 1)
    assert_equal body, frame, "one piece"
    assert_operator calls, :>=, 2
    big = Random.new(3).bytes((3 * step) + 7)
    frame, calls = read_over_pair(big, pieces: 3, hooked: false)
    assert_equal big, frame, "no hook: the plain read"
    assert_equal 0, calls
  end

  # The link judged end to end over a real socket on virtual time: a small
  # frame (a few hundred bytes, far under READ_STEP) whose first bytes
  # arrive inside the 2 s after the PING keeps the link, as a large one did.
  def test_bytes_of_a_small_frame_still_arriving_answer_the_ping_over_a_socket
    pair = []
    dialer = Class.new(AgentSpaces::Dialer) do
      define_method(:schemes) { ["tcp"] }
      define_method(:open) do |seed, identity: nil, timeout: 10|
        ours, theirs = UNIXSocket.pair
        pair << theirs
        Thread.new { loop { theirs.readpartial(4096) } rescue nil } # the seed drains what the peer sends, to EOF
        FrameChannel.new(ours, seed)
      end
    end.new
    peer = Peer.new(Identity.generate, GROUP, time: @time, dialers: [dialer])
    @peers << peer
    peer.reconnect_interval = 0.01
    peer.connect_any([SEED_A])
    peer.run_due
    assert eventually { peer.connected? }
    seed_side = pair.first
    peer.advance(45.1)
    assert peer.link_asked?, "the silent seed was asked"
    peer.advance(1.5)
    frame = from_seed(peer, "PING", Wire.ping_body(5))
    assert_operator frame.bytesize, :<, FrameChannel::READ_STEP
    seed_side.write([frame.bytesize].pack("N") + frame.byteslice(0, 10)) # the prefix and the first bytes
    assert eventually { !peer.link_asked? }, "bytes of a small frame still arriving answer the PING"
    peer.advance(1.0)
    assert_equal 0, peer.links_silent, "a slow small frame is no dead seed"
    assert peer.connected?
    seed_side.write(frame.byteslice(10..)) # the rest: the frame is whole and read
    peer.advance(2.5)
    assert_equal 0, peer.links_silent
    assert peer.connected?
  ensure
    pair.each { |io| io.close unless io.closed? }
  end

  def test_a_body_cut_short_ends_the_channel
    reader_io, writer_io = UNIXSocket.pair
    channel = FrameChannel.new(reader_io, nil)
    channel.on_bytes = -> {}
    writer_io.write([FrameChannel::READ_STEP + 10].pack("N") + ("x" * 100))
    writer_io.close
    assert_raises(EOFError) { channel.read_frame }
  ensure
    reader_io&.close
  end
end
