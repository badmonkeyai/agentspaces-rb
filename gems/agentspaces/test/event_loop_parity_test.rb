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

module LoopParity
  Job = AgentSpaces::Entry.define("com.acme.LoopJob#v1", topic: String)
end

# The Ruby peer's timing against SPEC v0.1.36 (§5.2, §7.3, §9.5) and the
# reference implementation's event loop (srad/agentspaces-event-loop.md; the
# parity notes' Ruby section): due work in place of the 0.25 s ticker and
# sweep, the keepalive bound, monotonic periods, the wall-step signal and the
# resume, the issue clock, relay.via following the link, and the watchdog.
# Every timed case runs on VirtualTime: nothing here waits out a timer.
class EventLoopParityTest < Minitest::Test
  include AgentSpaces
  include GoldenHelpers

  GROUP = "zRubyLoop"

  def setup
    @seeds = []
    @peers = []
  end

  def teardown
    @peers.each(&:close)
    @seeds.each(&:close)
  end

  def seed
    Testing::FakeSeed.new.tap { |s| @seeds << s }
  end

  # A peer on virtual time dialled to a fake seed, its introductions counted.
  def virtual_peer(time = VirtualTime.new, **options)
    peer = Peer.new(Identity.generate, GROUP, time: time, **options)
    @peers << peer
    calls = []
    peer.define_singleton_method(:introduce) do
      calls << time.mono
      super()
    end
    [peer, calls]
  end

  # The self-advertisements a seed received, decoded, with their item ids.
  def peer_ads(fake, connection = nil)
    fake.received.each_with_index.filter_map do |env, _|
      next unless env["kind"] == "RUMOR"

      rumor = Wire.decode_body("RUMOR", env["body"])
      next unless rumor["streamId"] == "peers"
      next if connection && !fake.kinds(connection).include?("RUMOR")

      signed = Schema.load("PeerNode.SignedPeerAd", rumor["payload"])
      [Schema.load("PeerAdvertisement", signed["adBytes"]), rumor["itemId"]]
    end
  end

  def member_ad(time, identity, hints = {})
    now = time.wall_ms
    ad = Wire.peer_advertisement(GROUP, identity, Instants.iso(now - (now % 1000)), "PT10M", hints)
    Wire.signed_peer_ad(ad, identity)
  end

  # ------------------------------------------------------------- keepalive

  def test_the_keepalive_re_leases_at_its_interval_from_the_last_introduction
    fake = seed
    time = VirtualTime.new
    peer, calls = virtual_peer(time)
    peer.connect("127.0.0.1", fake.port)
    start = time.mono
    assert eventually { peer_ads(fake).size == 1 }, "the dial introduced the peer"
    assert_equal [start], calls, "connect's own introduction"
    calls.clear
    peer.run_due
    assert_empty calls, "it counts as the first: the keepalive waits its interval"

    peer.advance(29.9)
    assert_empty calls, "nothing before the 30 s interval"
    peer.advance(0.1)
    assert_equal [start + 30.0], calls
    peer.introduce # an introduction from elsewhere (a hint change) restarts the count
    # A FakeSeed answers no PING: its own probe keeps the link heard, as a
    # real seed's do, or the dead-seed rule (peer_link.rb) would ask the
    # silent link at 45 s and close it at 47 s, inside this window.
    prober = Identity.generate
    fake.send_to_last(Wire.encode_frame(Wire.envelope(GROUP, "PING", prober.peer_id,
                                                      Wire.hlc_now(prober.peer_id, time.wall_ms),
                                                      Wire.ping_body(1), peer.identity.peer_id), prober))
    assert eventually { fake.kinds.include?("ACK") }, "the probe was read"
    calls.clear # the probe may draw an introduction too, at the same instant
    peer.advance(29.0)
    assert_empty calls
    peer.advance(1.0)
    assert_equal 1, calls.size
    assert eventually { peer_ads(fake).size == 5 }, "connect, 30 s, the hint change, the probe's answer and 60 s"
  end

  def test_the_keepalive_runs_at_half_the_bound_once_the_group_outgrows_the_probe_cycle
    fake = seed
    time = VirtualTime.new
    peer, calls = virtual_peer(time)
    peer.connect("127.0.0.1", fake.port)
    members = Array.new(7) { Identity.generate }
    members.first(6).each { |m| peer.send(:accept_peer_ad, member_ad(time, m)) }
    assert_equal 6, peer.view_size
    assert_in_delta 30.0, peer.re_lease_period, 1e-9, "a cycle of 7 x 4 s stays inside the 30 s bound"
    peer.send(:accept_peer_ad, member_ad(time, members.last))
    assert_in_delta 15.0, peer.re_lease_period, 1e-9, "a cycle of 8 x 4 s has outgrown it: half the bound"
    start = time.mono
    calls.clear
    peer.advance(45.0)
    assert_equal [15.0, 30.0, 45.0], calls.map { |t| (t - start).round(6) }
    peer.peer_ad_interval = 10.0
    assert_in_delta 10.0, peer.re_lease_period, 1e-9, "a shorter configured interval stands"
  end

  def test_an_idle_peer_wakes_for_its_deadlines_not_on_a_fixed_tick
    fake = seed
    time = VirtualTime.new
    peer, = virtual_peer(time)
    peer.connect("127.0.0.1", fake.port)
    peer.space("tasks").watch(LoopParity::Job) { |_| nil }
    before = peer.loop_stats[:runs]
    peer.advance(600.0)
    runs = peer.loop_stats[:runs] - before
    # The backstop (15 s) and the keepalive (30 s) at most: about 40 runs in
    # ten minutes, where a 0.25 s ticker and sweep took 4,800.
    assert_operator runs, :<=, 45, "#{runs} runs in 10 idle minutes"
    assert_equal :ok, peer.loop_health[:state]
  end

  def test_a_real_peer_runs_one_loop_and_no_ticker_or_sweep_thread
    fake = seed
    peer = Peer.new(Identity.generate, GROUP)
    @peers << peer
    peer.connect("127.0.0.1", fake.port)
    peer.space("tasks").watch(LoopParity::Job) { |_| nil }
    names = Thread.list.map(&:name)
    assert_includes names, "agentspaces-loop"
    refute_includes names, "agentspaces-ticker"
    refute_includes names, "agentspaces-sweep"
    assert_includes peer.watchdog.watching, peer.node_loop
  end

  # ----------------------------------------------------------- the sweep

  def test_a_watch_hears_expired_at_the_lapse_and_a_lease_lapses_at_its_expiry
    time = VirtualTime.new
    writer, reader = Testing::Network.fleet(GROUP, 2, time: time)
    @peers.push(writer, reader)
    events = []
    space = reader.space("tasks")
    space.watch(LoopParity::Job, kinds: [EXPIRED]) { |e| events << e.kind }
    subscription = space.notify(LoopParity::Job, lease: "3s") { |_| nil }
    writer.space("tasks").write(LoopParity::Job.new(topic: "short"), lease: "5s")
    reader.advance(2.9)
    assert subscription.open?
    reader.advance(0.1)
    refute subscription.open?, "the subscription lapsed at its own expiry"
    assert_equal "lapsed", subscription.reason
    reader.advance(1.9)
    assert_empty events, "nothing before the lease's expiry"
    reader.advance(0.1)
    assert_equal [EXPIRED], events, "EXPIRED at the lapse"
  end

  def test_collection_runs_at_the_horizon
    time = VirtualTime.new
    writer, reader = Testing::Network.fleet(GROUP, 2, time: time, dialled: true)
    @peers.push(writer, reader)
    id = writer.space("tasks").write(LoopParity::Job.new(topic: "lapses"), lease: "2s")
    reader.run_due
    # A lapse keeps min(2 x the longest lease, 5 min) past its expiry: 4 s.
    reader.advance(5.9)
    assert reader.states.key?(id)
    reader.advance(0.1)
    refute reader.states.key?(id), "collected at its horizon"
    assert_equal 1, reader.states_collected
  end

  # ------------------------------------------------ wall steps and resume

  def test_a_wall_step_back_is_seen_and_drops_nothing
    fake = seed
    time = VirtualTime.new
    peer, calls = virtual_peer(time)
    peer.connect("127.0.0.1", fake.port)
    peer.run_due
    calls.clear
    time.step_wall(-300)
    peer.run_due
    assert_equal 1, peer.wall_steps
    assert_equal 0, peer.resumes
    assert_empty calls, "a back step introduces nothing"
    peer.advance(29.0)
    assert_empty calls, "the keepalive keeps its monotonic pace across the step"
    peer.advance(1.0)
    assert_equal 1, calls.size
  end

  # A resume with the link up re-introduces this peer on that link and
  # PINGs the seed (Harmonization rule 3, 2026-11-23); this FakeSeed never
  # answers, so 2 s later the dead-seed rule fails over and the seed (the
  # only one) is dialled again at once, and introduced to again.
  def test_a_forward_step_past_the_keepalive_bound_rejoins_and_pings_the_seed
    fake = seed
    time = VirtualTime.new
    peer, calls = virtual_peer(time)
    peer.reconnect_interval = 0.05
    peer.connect("127.0.0.1", fake.port)
    peer.run_due
    calls.clear
    time.suspend(7200) # Linux: the wall moved two hours, the monotonic clock did not
    peer.run_due
    assert_equal 1, peer.resumes
    assert_equal 1, calls.size, "introduced again at once, on the link it holds"
    assert eventually { peer_ads(fake).size == 2 }
    assert eventually { fake.kinds(0).include?("PING") }, "and the seed was asked"
    assert_equal 1, fake.connections.size, "the link was not closed on the wake"
    time.advance(Peer::LINK_ANSWER - 0.1)
    peer.run_due
    assert_equal 1, fake.connections.size, "within the ping timeout the link stands"
    time.advance(0.2)
    peer.run_due
    assert_equal 1, peer.links_silent
    assert eventually { fake.connections.size == 2 }, "no answer in 2 s: the seed was dialled again"
    assert eventually { calls.size == 2 }, "and the peer introduced itself on the new link"
  end

  def test_a_wake_late_past_the_keepalive_bound_is_an_absence_too
    fake = seed
    time = VirtualTime.new
    peer, = virtual_peer(time)
    peer.reconnect_interval = 0.05
    peer.connect("127.0.0.1", fake.port)
    peer.run_due
    time.advance(120) # macOS counts a suspend on both clocks: the loop just wakes late
    peer.run_due
    assert_equal 1, peer.resumes
    assert eventually { fake.kinds(0).include?("PING") }
    time.advance(Peer::LINK_ANSWER + 0.1)
    peer.run_due
    assert eventually { fake.connections.size == 2 }
  end

  def test_a_pinned_test_clock_is_no_wall_step
    clock = Testing::TestClock.new
    peer = Peer.new(Identity.generate, GROUP, clock: clock)
    @peers << peer
    peer.run_due
    clock.advance(600_000)
    peer.run_due
    assert_equal 0, peer.wall_steps
    assert_equal 0, peer.resumes
  end

  # -------------------------------------------------------- issue clock

  def test_a_changed_self_ad_in_the_same_second_is_issued_after_the_last
    fake = seed
    time = VirtualTime.new(wall_ms: 1_767_225_600_400)
    peer, = virtual_peer(time)
    peer.connect("127.0.0.1", fake.port)
    peer.resource_hints["relay.via"] = "zSeedPeer" # what an addressed frame from the seed sets
    peer.introduce
    peer.introduce # the same content again
    ads = nil
    assert eventually { (ads = peer_ads(fake)).size == 3 }
    issued = ads.map { |ad, _| Instants.parse_millis(ad["issued"]) }
    assert_equal [1_767_225_600_000, 1_767_225_600_001, 1_767_225_600_001], issued,
                 "the change takes the next millisecond, the same content keeps it"
    assert_equal 3, ads.map(&:last).uniq.size, "each introduction has its own gossip item id"
    assert_equal "zSeedPeer", ads.last.first["resourceHints"]["relay.via"]
  end

  def test_a_changed_card_in_the_same_second_is_issued_after_the_last
    time = VirtualTime.new
    peer = Testing::NetPeer.new(Testing::Network.new, GROUP, time: time)
    @peers << peer
    card = ->(version) do
      now = time.wall_ms
      { "id" => "aspace://#{GROUP}/cap/test/#{peer.identity.peer_id}", "issuer" => peer.identity.peer_id,
        "group" => GROUP, "issued" => Instants.iso(now - (now % 1000)), "ttl" => "PT15M",
        "capabilityType" => "aspace:cap/test", "version" => version, "binding" => "pipe",
        "parameters" => {}, "costHints" => {} }
    end
    peer.publish_ad("CapabilityAdvertisement", card.call("0.1"))
    first = peer.ads.values.first["ad"]["issued"]
    peer.publish_ad("CapabilityAdvertisement", card.call("0.2"))
    second = peer.ads.values.first["ad"]
    assert_equal "0.2", second["version"], "the changed card replaced the held one"
    assert_equal Instants.parse_millis(first) + 1, Instants.parse_millis(second["issued"])
  end

  # ------------------------------------------------------- relay.via

  def addressed(peer, from)
    Wire.envelope(GROUP, "ACK", from.peer_id, Wire.hlc_now(from.peer_id, peer.now_ms), "".b, peer.identity.peer_id)
  end

  def test_relay_via_names_only_the_member_this_peer_holds_a_link_to
    a = seed
    b = seed
    seed_a = Identity.generate
    seed_b = Identity.generate
    peer = Peer.new(Identity.generate, GROUP)
    @peers << peer
    peer.reconnect_interval = 0.05
    peer.connect_any([a.seed, b.seed])
    peer.handle(addressed(peer, seed_a))
    assert eventually { peer_ads(a).last&.first&.dig("resourceHints", "relay.via") == seed_a.peer_id }
    a.close
    assert eventually { peer_ads(b).size >= 1 }, "the peer failed over to the next seed"
    refute peer_ads(b).first.first["resourceHints"].key?("relay.via"),
           "the introduction to the new seed names no holder it left"
    assert_nil peer.seed_peer
    peer.handle(addressed(peer, seed_b))
    assert eventually { peer_ads(b).last.first.dig("resourceHints", "relay.via") == seed_b.peer_id }
  end

  # ------------------------------------------------------- the watchdog

  def counting_loop(time = TimeSource::SYSTEM)
    loop = NodeLoop.new("test", time: time)
    runs = Queue.new
    loop.duty(:beat) do |now|
      runs << now
      nil
    end
    [loop, runs]
  end

  def test_the_watchdog_restarts_a_loop_whose_thread_died
    loop, runs = counting_loop
    loop.start
    watchdog = Watchdog.manual(TimeSource::SYSTEM)
    watchdog.register(loop)
    assert eventually { runs.size >= 1 }
    loop.thread.kill
    loop.thread.join(1)
    found = watchdog.check
    assert_equal [[loop, :dead]], found
    assert_equal 1, loop.generation
    assert eventually { runs.size >= 2 }, "every duty asked once on the new thread"
    assert loop.thread.alive?
  ensure
    loop&.stop
  end

  def test_a_wedged_duty_is_fenced_and_the_loop_goes_on_without_it
    loop, runs = counting_loop
    release = Queue.new
    stuck = Queue.new
    loop.duty(:stuck) do |_now|
      stuck << :in
      release.pop
      nil
    end
    loop.start
    watchdog = Watchdog.manual(TimeSource::SYSTEM)
    watchdog.register(loop)
    stuck.pop # the duty is running on the loop's thread
    found = watchdog.check(TimeSource::SYSTEM.mono + Watchdog::WEDGE + 1)
    assert_equal [[loop, :wedged]], found
    before = runs.size
    loop.wake(:beat)
    assert eventually { runs.size > before }, "the keepalive-side duties run on the new generation"
    loop.wake(:stuck)
    loop.wake(:beat)
    assert eventually { runs.size > before + 1 }
    assert_equal 0, stuck.size, "the wedged duty is fenced: no second copy while the first runs"
    release << :go
    assert eventually { loop.stats[:duties][:stuck][:runs] == 1 }
    loop.wake(:stuck)
    assert eventually { stuck.size == 1 }, "returned, it runs again when asked"
    release << :go
  ensure
    release&.push(:go)
    loop&.stop
  end

  def test_three_re_initialisations_in_ten_minutes_turn_the_loop_down
    loop, = counting_loop
    states = []
    loop.on_health { |h| states << h[:state] }
    loop.start
    watchdog = Watchdog.manual(TimeSource::SYSTEM)
    watchdog.register(loop)
    3.times do
      loop.thread.kill
      loop.thread.join(1)
      watchdog.check
    end
    assert_equal :down, loop.health[:state]
    assert_match(/3 re-initialisations/, loop.health[:reasons].first)
    assert_includes states, :down
  ensure
    loop&.stop
  end

  def test_a_duty_that_raises_three_times_is_backed_off_and_degrades_the_loop
    time = VirtualTime.new
    loop = NodeLoop.new("test", time: time)
    fail_now = true
    loop.duty(:flaky) do |now|
      raise IOError, "boom" if fail_now

      now + 10
    end
    3.times do
      loop.wake(:flaky)
      loop.run_due
    end
    assert_equal :degraded, loop.health[:state]
    assert_match(/flaky backed off/, loop.health[:reasons].first)
    fail_now = false
    time.advance(1.0)
    loop.run_due
    assert_equal :ok, loop.health[:state]
  end

  def test_a_missed_deadline_is_found_and_the_loop_re_armed
    loop, runs = counting_loop
    loop.start
    watchdog = Watchdog.manual(TimeSource::SYSTEM)
    watchdog.register(loop)
    assert eventually { runs.size >= 1 }
    assert_empty watchdog.check, "a parked loop inside its deadline is healthy"
    found = watchdog.check(loop.armed_at + Watchdog::GRACE + 0.5)
    assert_equal [[loop, :missed_fire]], found
    assert eventually { runs.size >= 2 }
  ensure
    loop&.stop
  end

  def test_the_watchdog_starts_a_dead_reader_again
    fake = seed
    time = VirtualTime.new
    watchdog = Watchdog.manual(time)
    peer, = virtual_peer(time, watchdog: watchdog)
    peer.connect("127.0.0.1", fake.port)
    assert eventually { fake.connections.size == 1 }, "the seed holds the link before it writes on it"
    reader = peer.instance_variable_get(:@reader)
    reader.kill
    reader.join(1)
    assert_includes watchdog.check.map(&:last), :reader_dead
    assert_equal 1, peer.reader_restarts
    seed_identity = Identity.generate
    ping = Wire.encode_frame(Wire.envelope(GROUP, "PING", seed_identity.peer_id,
                                           Wire.hlc_now(seed_identity.peer_id, peer.now_ms),
                                           Wire.ping_body(7), peer.identity.peer_id), seed_identity)
    fake.send_to_last(ping)
    assert eventually { fake.kinds.include?("ACK") }, "the new reader answers PINGs"
  end

  def test_a_frame_handler_held_past_the_bound_is_reported_by_kind
    fake = seed
    time = VirtualTime.new
    watchdog = Watchdog.manual(time, wedge: 0.0)
    peer, = virtual_peer(time, watchdog: watchdog)
    entered = Queue.new
    release = Queue.new
    peer.on_state = lambda do |_dto|
      entered << :in
      release.pop
    end
    peer.connect("127.0.0.1", fake.port)
    assert eventually { fake.connections.size == 1 }, "the seed holds the link before it writes on it"
    other = Identity.generate
    _, body = Wire.entry_delta("tasks", GROUP, LoopParity::Job.schema, CBOR.dump({ "topic" => "slow" }), other, "w",
                               60_000, now_ms: peer.now_ms)
    fake.send_to_last(Wire.encode_frame(Wire.envelope(GROUP, "RUMOR", other.peer_id,
                                                      Wire.hlc_now(other.peer_id, peer.now_ms), body, nil), other))
    entered.pop
    assert_includes watchdog.check.map(&:last), :frame_held
    assert_equal 1, peer.loop_stats[:held_frames]["RUMOR"]
    assert_empty watchdog.check.map(&:last) - [], "reported once per frame"
  ensure
    release&.push(:go)
  end
end
