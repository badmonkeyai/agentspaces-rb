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

# Round 2b part 1 of the event-loop parity and its Harmonization (owner
# decisions 2026-11-23; .parity-wt/PARITY-ruby.md): the one redial table
# (5, 10, 20, 30 s, then 5 s again, spread by up to 10 % either way, reset
# only by the end of a link that held 5 s and by a wake) and staggered seed
# dials (list order, 250 ms apart or at once after a refusal, the first to
# open wins, the seed just lost last). The pauses are taken from the
# reconnect at a gate the test opens, the stagger and a link's age run on a
# fake clock, so nothing here waits out a pause or a stagger; the loop runs
# on virtual time.
class RedialTableTest < Minitest::Test
  include AgentSpaces
  include GoldenHelpers

  GROUP = "zRubyRedialTable"
  SEED_A = "127.0.0.1:7201"
  SEED_B = "127.0.0.1:7202"
  SEED_C = "127.0.0.1:7203"

  # A random source that always draws the same value.
  class FixedRandom
    def initialize(value) = @value = value
    def rand = @value
  end

  # An in-memory link the peer's reader blocks on until it is dropped.
  class FakeChannel
    attr_reader :seed
    attr_accessor :on_bytes

    def initialize(seed)
      @seed = seed
      @inbox = Thread::Queue.new
      @closed = false
    end

    def send_frame(_frame)
      raise IOError, "closed" if @closed
    end

    def read_frame
      raise IOError, "closed" if @inbox.pop == :closed
    end

    def drop = @inbox << :closed

    def close
      @closed = true
      @inbox << :closed
    end

    def closed? = @closed

    def attested_peer = nil
  end

  # A dialer whose seeds answer, refuse, or hang until released, as the
  # test sets each one (by host:port); every dial is recorded.
  class FakeDialer < AgentSpaces::Dialer
    attr_reader :channels

    def initialize
      super
      @lock = Mutex.new
      @hanging = 0
      @behaviour = Hash.new(:open)
      @refusals = Hash.new(0)
      @dials = []
      @channels = []
    end

    def schemes = ["tcp"]

    # :open, :refuse, or a Thread::Queue the dial waits on before it opens.
    def set(authority, behaviour) = @lock.synchronize { @behaviour[authority] = behaviour }

    # The next n dials of authority are refused, whatever its behaviour.
    def refuse(authority, n) = @lock.synchronize { @refusals[authority] = n }

    def dials = @lock.synchronize { @dials.dup }

    # Dials that wait at their gate now.
    def hanging = @lock.synchronize { @hanging }

    def open(seed, identity: nil, timeout: 10)
      authority = seed.authority
      behaviour = @lock.synchronize do
        @dials << authority
        if @refusals[authority].positive?
          @refusals[authority] -= 1
          :refuse
        else
          @behaviour[authority]
        end
      end
      raise Errno::ECONNREFUSED, authority if behaviour == :refuse

      if behaviour.is_a?(Thread::Queue)
        @lock.synchronize { @hanging += 1 }
        begin
          behaviour.pop
        ensure
          @lock.synchronize { @hanging -= 1 }
        end
      end
      channel = FakeChannel.new(seed)
      @lock.synchronize { @channels << channel }
      channel
    end
  end

  def setup
    @peers = []
    @gates = []
    @time = VirtualTime.new
    @dialer = FakeDialer.new
  end

  def teardown
    @gates.each(&:close)
    @peers.each(&:close)
  end

  def new_peer(spread_draw = 0.5)
    peer = Peer.new(Identity.generate, GROUP, time: @time, dialers: [@dialer])
    @peers << peer
    peer.instance_variable_set(:@redial_random, FixedRandom.new(spread_draw))
    peer
  end

  def monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)

  # A clock that moves only when told: the round of dials and a link's age
  # are judged on it.
  class FakeClock
    attr_reader :waits

    def initialize
      @now = 1000.0
      @waits = []
      @lock = Mutex.new
    end

    def now = @lock.synchronize { @now }
    def advance(seconds) = @lock.synchronize { @now += seconds }

    def waited(seconds)
      @lock.synchronize do
        @waits << seconds
        @now += seconds
      end
    end
  end

  # Puts the peer's round of dials and its links' age on a fake clock. A
  # stagger wait returns an event when one is due; once every dial in
  # flight waits at its gate (nothing on its way), the wait runs out at once
  # and the clock moves on by the wait, as if that time had passed.
  def fake_clock(peer)
    clock = FakeClock.new
    dialer = @dialer
    peer.define_singleton_method(:redial_clock) { clock.now }
    peer.define_singleton_method(:dial_wait) do |events, seconds, in_flight|
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
      loop do
        event = events.pop(timeout: 0)
        return event if event
        if dialer.hanging == in_flight # every dial in flight is silent
          return events.pop(timeout: 5) if seconds.nil? # (a test that hangs them all fails here)

          clock.waited(seconds)
          return nil
        end
        raise "the dials did not settle" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

        Thread.pass
      end
    end
    clock
  end

  def seeds(*authorities) = authorities.map { |a| Seed.parse(a) }

  # Every pause the reconnect takes is recorded and held at a gate: one
  # token lets one pause end (as if its time had passed); a cut (a wake)
  # still shows, since the pause ends through the peer's own wait.
  def gate_pauses(peer)
    pauses = Thread::Queue.new
    gate = Thread::Queue.new
    @gates << gate
    peer.define_singleton_method(:reconnect_wait) do |seconds|
      pauses << seconds
      gate.pop
      super(0)
    end
    [pauses, gate]
  end

  # The pause the reconnect takes next (it waits at the gate meanwhile).
  def next_pause(pauses) = pauses.pop(timeout: 5) || flunk("no pause within 5 s")

  # The link the peer holds has lasted long enough to count as held.
  def age_link(peer) = peer.instance_variable_set(:@link_since, monotonic - 3600)

  # -------------------------------------------------------- the table itself

  def test_the_pauses_follow_the_table_and_wrap_to_its_start
    peer = new_peer
    pauses = Array.new(10) { peer.send(:redial_pause) }
    assert_equal [5.0, 10.0, 20.0, 30.0, 5.0, 10.0, 20.0, 30.0, 5.0, 10.0], pauses
    assert_equal [5.0, 10.0, 20.0, 30.0], Peer::REDIAL_TABLE
    assert_equal 2, peer.send(:redial_position)
  end

  def test_a_shorter_reconnect_interval_scales_the_whole_table
    peer = new_peer
    peer.reconnect_interval = 0.05
    pauses = Array.new(5) { peer.send(:redial_pause) }
    [0.05, 0.1, 0.2, 0.3, 0.05].zip(pauses).each { |want, got| assert_in_delta want, got, 1e-9 }
  end

  def test_the_spread_stays_within_ten_percent_either_way
    low = new_peer(0.0)
    assert_in_delta 4.5, low.send(:redial_pause), 1e-9
    high = new_peer(1.0 - Float::EPSILON)
    assert_operator high.send(:redial_pause), :<, 5.5
    peer = new_peer
    peer.instance_variable_set(:@redial_random, Random.new(20_261_123))
    drawn = Array.new(4000) { peer.send(:redial_pause) }
    drawn.each_slice(4) do |slice|
      Peer::REDIAL_TABLE.zip(slice).each do |base, pause|
        assert_operator pause, :>=, base * 0.9
        assert_operator pause, :<, base * 1.1
      end
    end
    firsts = drawn.each_slice(4).map(&:first)
    assert(firsts.any? { |p| p < 4.75 } && firsts.any? { |p| p > 5.25 }, "the spread reaches both sides")
  end

  # ------------------------------------------------ reset on success and wake

  def test_a_link_that_held_starts_the_table_again
    peer = new_peer
    pauses, gate = gate_pauses(peer)
    peer.connect_any([SEED_A])
    age_link(peer)
    @dialer.refuse(SEED_A, 2)
    @dialer.channels.last.drop
    assert_equal 5.0, next_pause(pauses)
    gate << :go
    assert_equal 10.0, next_pause(pauses)
    gate << :go
    assert eventually { peer.connected? }, "the third round answered"
    assert_equal 2, peer.send(:redial_position), "the position stays until the link proves itself"
    age_link(peer)
    @dialer.refuse(SEED_A, 1)
    @dialer.channels.last.drop
    assert_equal 5.0, next_pause(pauses), "the link held: the table started again, not at 20 s"
    gate << :go
    assert eventually { peer.connected? }
  end

  def test_a_link_that_ends_at_once_is_a_failed_round_and_moves_on
    peer = new_peer
    pauses, gate = gate_pauses(peer)
    peer.connect_any([SEED_A])
    age_link(peer)
    @dialer.refuse(SEED_A, 1)
    @dialer.channels.last.drop
    assert_equal 5.0, next_pause(pauses)
    gate << :go
    assert eventually { peer.connected? }
    @dialer.channels.last.drop # within the reconnect interval of its dial
    assert_equal 10.0, next_pause(pauses), "a quick drop takes the next pause"
    gate << :go
    assert eventually { peer.connected? }
  end

  # Harmonization rule 1 on a fake clock: a link that held 4 s ends as a
  # failed round and waits the next step; one that held 6 s resets the table
  # and is redialled at once.
  def test_a_4_s_link_waits_the_next_step_and_a_6_s_link_resets
    peer = new_peer
    clock = fake_clock(peer)
    pauses, gate = gate_pauses(peer)
    peer.connect_any([SEED_A])
    @dialer.refuse(SEED_A, 1)
    clock.advance(6)
    @dialer.channels.last.drop
    assert_equal 5.0, next_pause(pauses), "held 6 s: redialled at once, refused, then 5 s"
    gate << :go
    assert eventually { peer.connected? }
    assert_equal 1, peer.send(:redial_position)
    clock.advance(4)
    @dialer.channels.last.drop
    assert_equal 10.0, next_pause(pauses), "held 4 s: a failed round, the next step"
    gate << :go
    assert eventually { peer.connected? }
    assert_equal 2, peer.send(:redial_position), "the new link proved nothing yet"
    clock.advance(4.999)
    @dialer.channels.last.drop
    assert_equal 20.0, next_pause(pauses), "just under 5 s is still a failed round"
    gate << :go
    assert eventually { peer.connected? }
    clock.advance(6)
    dials = @dialer.dials.size
    @dialer.channels.last.drop
    assert eventually { @dialer.dials.size == dials + 1 && peer.connected? }, "held 6 s: redialled at once"
    assert_empty pauses, "with no pause"
    assert_equal 0, peer.send(:redial_position), "and the table starts again"
  end

  def test_a_wake_starts_the_table_again_and_dials_at_once
    peer = new_peer
    pauses, gate = gate_pauses(peer)
    peer.connect_any([SEED_A])
    peer.run_due # the loop's first turn: a later late turn is an absence
    age_link(peer)
    @dialer.set(SEED_A, :refuse)
    @dialer.channels.last.drop
    assert_equal 5.0, next_pause(pauses)
    gate << :go
    assert_equal 10.0, next_pause(pauses)
    gate << :go
    assert_equal 20.0, next_pause(pauses)
    assert_equal 3, peer.send(:redial_position)
    @time.advance(7200) # a laptop sleep: the loop wakes late
    peer.run_due
    assert_equal 1, peer.resumes
    assert_equal 0, peer.send(:redial_position), "the wake reset the position"
    dials = @dialer.dials.size
    gate << :go # the pause ends through the peer's wait, which sees the wake
    assert_equal 5.0, next_pause(pauses), "the table started again, not at 30 s"
    assert_equal dials + 1, @dialer.dials.size, "and it dialled at once"
  end

  # Harmonization rule 3: a wake with the link up resets the table and asks
  # the seed with a PING; it does not close the link. A seed silent for the
  # 2 s ping timeout is failed over at once, though the link was young: its
  # end is a failed round, but the wake already started the table again and
  # the failover cuts the pause.
  def test_a_wake_while_the_link_is_up_resets_the_table_and_asks_the_seed
    peer = new_peer
    pauses, gate = gate_pauses(peer)
    peer.connect_any([SEED_A])
    peer.run_due # the loop's first turn: a later late turn is an absence
    peer.instance_variable_set(:@redial_position, 3)
    @time.advance(7200)
    peer.run_due
    assert_equal 1, peer.resumes
    assert_equal 0, peer.send(:redial_position), "the wake reset the position"
    assert peer.link_asked?, "the wake asked the seed"
    assert_equal 1, peer.seed_pings
    assert_equal 1, peer.wake_pings, "a wake's PING"
    # The old names stay one release as aliases (owner decision 4, 2026-11-23).
    assert_equal [1, 1], [peer.link_pings, peer.resume_rejoins]
    stats = peer.loop_stats
    assert_equal({ seed_pings: 1, wake_pings: 1, links_silent: 0, resumes: 1, link_pings: 1, resume_rejoins: 1 },
                 stats.slice(:seed_pings, :wake_pings, :links_silent, :resumes, :link_pings, :resume_rejoins))
    assert peer.connected?, "the link stands while the PING waits"
    assert_equal 1, @dialer.dials.size, "and nothing was dialled"
    @dialer.set(SEED_A, :refuse)
    @time.advance(Peer::LINK_ANSWER + 0.1)
    peer.run_due # no answer: the dead-seed rule ends the link
    assert_equal 1, peer.links_silent
    assert_equal 5.0, next_pause(pauses), "not 30 s: the wake reset the position"
    dials = @dialer.dials.size
    gate << :go # the failover had already cut the pause
    assert_equal 5.0, next_pause(pauses), "the cut pause started the table again"
    assert_equal dials + 1, @dialer.dials.size, "and dialled at once"
  end

  # ---------------------------------------------------- staggered seed dials

  def test_a_silent_first_seed_costs_250_ms
    peer = new_peer
    clock = fake_clock(peer)
    hang = Thread::Queue.new
    @gates << hang
    @dialer.set(SEED_A, hang)
    started = clock.now
    assert_equal SEED_B, peer.connect_any([SEED_A, SEED_B, SEED_C]).authority
    assert_in_delta 0.25, clock.now - started, 1e-9, "one stagger, not the 10 s connect timeout"
    assert_equal [0.25], clock.waits
    assert_equal [SEED_A, SEED_B], @dialer.dials, "C was never dialled: B won first"
  end

  # At most MAX_DIALS_AT_ONCE (16) dials are in flight, as in Rust, Python
  # and TypeScript: with 16 silent seeds out, the 17th (which would answer)
  # waits for a slot and is not dialled.
  def test_at_most_sixteen_dials_are_in_flight
    assert_equal 16, Peer::MAX_DIALS_AT_ONCE
    peer = new_peer
    clock = fake_clock(peer)
    hang = Thread::Queue.new
    @gates << hang
    silent = (0...16).map { |i| "127.0.0.1:#{7300 + i}" }
    silent.each { |a| @dialer.set(a, hang) }
    spare = "127.0.0.1:7316"
    result = Thread.new { peer.send(:dial_first, seeds(*silent, spare)) }
    assert eventually { @dialer.hanging == 16 }
    Thread.pass until result.status == "sleep" || !result.alive?
    assert result.alive?, "the round waits for a slot rather than dialling the 17th"
    assert_equal silent, @dialer.dials
    assert_equal [0.25] * 15, clock.waits
    hang << :go # one silent seed answers: it wins, and the 17th never starts
    seed, channel, = result.value
    refute_nil channel
    refute_equal spare, seed.authority
    assert_equal 16, @dialer.dials.size
  end

  def test_two_silent_seeds_cost_two_staggers
    peer = new_peer
    clock = fake_clock(peer)
    hang = Thread::Queue.new
    @gates << hang
    @dialer.set(SEED_A, hang)
    @dialer.set(SEED_B, hang)
    seed, channel, failures = peer.send(:dial_first, seeds(SEED_A, SEED_B, SEED_C))
    assert_equal SEED_C, seed.authority
    refute_nil channel
    assert_empty failures
    assert_equal [0.25, 0.25], clock.waits, "C started 500 ms in"
  end

  def test_a_refused_dial_starts_the_next_at_once
    peer = new_peer
    clock = fake_clock(peer)
    @dialer.set(SEED_A, :refuse)
    @dialer.set(SEED_B, :refuse)
    seed, channel, failures = peer.send(:dial_first, seeds(SEED_A, SEED_B, SEED_C))
    assert_equal SEED_C, seed.authority
    refute_nil channel
    assert_empty clock.waits, "no stagger after a refusal"
    assert_equal [SEED_A, SEED_B, SEED_C], @dialer.dials
    assert_equal 2, failures.size
    assert_match SEED_A, failures[0]
    assert_match SEED_B, failures[1]
  end

  def test_the_first_seed_that_answers_keeps_its_place
    peer = new_peer
    clock = fake_clock(peer)
    assert_equal SEED_A, peer.connect_any([SEED_A, SEED_B, SEED_C]).authority
    assert_equal [SEED_A], @dialer.dials, "it answered within its stagger: no other seed was dialled"
    assert_empty clock.waits
  end

  def test_a_late_connection_is_closed
    peer = new_peer
    fake_clock(peer)
    hang = Thread::Queue.new
    @gates << hang
    @dialer.set(SEED_A, hang)
    assert_equal SEED_B, peer.connect_any([SEED_A, SEED_B]).authority
    assert_equal [SEED_B], @dialer.channels.map { |c| c.seed.authority }
    hang << :go # the silent dial opens after the winner
    assert eventually { @dialer.channels.size == 2 }
    late = @dialer.channels.last
    assert_equal SEED_A, late.seed.authority
    assert eventually { late.closed? }, "a later answer is closed at once"
    refute @dialer.channels.first.closed?
    assert peer.connected?
    # One set of counter names in every client (owner decision 4, 2026-11-23).
    assert_equal 2, peer.seed_dials
    assert eventually { peer.late_seed_channels == 1 }
    assert_equal({ seed_dials: 2, late_seed_channels: 1 }, peer.loop_stats.slice(:seed_dials, :late_seed_channels))
  end

  def test_every_seed_refusing_names_each_one_in_list_order
    peer = new_peer
    fake_clock(peer)
    [SEED_A, SEED_B, SEED_C].each { |s| @dialer.set(s, :refuse) }
    error = assert_raises(NoSeedError) { peer.connect_any([SEED_A, SEED_B, SEED_C]) }
    assert_match(/#{SEED_A}.*#{SEED_B}.*#{SEED_C}/, error.message)
    assert_equal [SEED_A, SEED_B, SEED_C], @dialer.dials
  end

  def test_the_seed_just_lost_is_tried_last
    peer = new_peer
    clock = fake_clock(peer)
    pauses, gate = gate_pauses(peer)
    assert_equal SEED_A, peer.connect_any([SEED_A, SEED_B, SEED_C]).authority
    clock.advance(3600) # the link held
    hang = Thread::Queue.new
    @gates << hang
    @dialer.set(SEED_B, hang)
    @dialer.set(SEED_C, hang)
    @dialer.channels.last.drop
    assert eventually { @dialer.channels.size == 2 && peer.connected? }
    assert_equal SEED_A, @dialer.channels.last.seed.authority, "B and C were silent; A, tried last, answered"
    assert_equal [SEED_A, SEED_B, SEED_C, SEED_A], @dialer.dials, "B, then C, then the seed just lost"
    assert_equal [0.25, 0.25], clock.waits, "A started 500 ms in"
    hang << :go << :go # both silent dials open late
    assert eventually { @dialer.channels.size == 4 }
    assert eventually { @dialer.channels[2..].all?(&:closed?) }, "the late connections are closed"
    refute @dialer.channels[1].closed?
    assert_empty pauses, "one round answered: no pause"
    gate << :go
  end

  # The order is the list's, the seed just lost moved last, never a rotation
  # (Harmonization, rule 2, as Rust, Python and TypeScript): linked to B of
  # A, B, C, the round dials A, then C, then B.
  def test_losing_the_middle_seed_dials_the_list_in_order_with_it_last
    peer = new_peer
    clock = fake_clock(peer)
    pauses, gate = gate_pauses(peer)
    @dialer.set(SEED_A, :refuse)
    assert_equal SEED_B, peer.connect_any([SEED_A, SEED_B, SEED_C]).authority
    clock.advance(3600) # the link held
    hang = Thread::Queue.new
    @gates << hang
    @dialer.set(SEED_A, hang)
    @dialer.set(SEED_C, hang)
    @dialer.channels.last.drop
    assert eventually { @dialer.channels.size == 2 && peer.connected? }
    assert_equal [SEED_A, SEED_B, SEED_A, SEED_C, SEED_B], @dialer.dials, "A, then C, then the seed just lost"
    assert_equal SEED_B, @dialer.channels.last.seed.authority
    hang << :go << :go
    assert eventually { @dialer.channels.size == 4 && @dialer.channels[2..].all?(&:closed?) }
    assert_empty pauses, "one round answered: no pause"
    gate << :go
  end

  def test_after_a_failed_link_the_next_seed_leads_and_the_failed_one_is_last
    peer = new_peer
    clock = fake_clock(peer)
    pauses, gate = gate_pauses(peer)
    assert_equal SEED_A, peer.connect_any([SEED_A, SEED_B, SEED_C]).authority
    clock.advance(3600)
    hang = Thread::Queue.new
    @gates << hang
    @dialer.set(SEED_B, hang)
    @dialer.channels.last.drop
    assert eventually { @dialer.channels.size == 2 && peer.connected? }
    assert_equal SEED_C, @dialer.channels.last.seed.authority, "B was silent for its stagger; C answered"
    assert_equal [SEED_A, SEED_B, SEED_C], @dialer.dials, "the seed that failed was not dialled"

    hang << :go # B's silent dial opens late and is closed
    assert eventually { @dialer.channels.size == 3 && @dialer.channels.last.closed? && @dialer.hanging.zero? }

    # Every other seed refuses: the one that failed (C) is dialled last, at once.
    clock.advance(3600)
    @dialer.set(SEED_A, :refuse)
    @dialer.set(SEED_B, :refuse)
    waits = clock.waits.size
    @dialer.channels[1].drop # the link to C
    assert eventually { @dialer.channels.size == 4 && peer.connected? }
    assert_equal SEED_C, @dialer.channels.last.seed.authority
    assert_equal [SEED_A, SEED_B, SEED_C, SEED_A, SEED_B, SEED_C], @dialer.dials,
                 "A first, B once A refused, C once both had"
    assert_equal waits, clock.waits.size, "refusals start the next at once"
    assert_empty pauses, "one round answered: no pause"
    gate << :go
  end
end
