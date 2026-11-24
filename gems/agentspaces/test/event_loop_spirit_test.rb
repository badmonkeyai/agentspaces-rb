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
require "agentspaces/capabilities"

module LoopSpirit
  Job = AgentSpaces::Entry.define("com.acme.SpiritJob#v1", topic: String)

  class Worker
    include AgentSpaces::Agent
    agent "spirit-worker"

    take Job, space: "tasks"
    def work(job) = job
  end
end

# The spirit review of the Ruby event-loop parity (.parity-wt/PARITY-ruby.md,
# "Spirit review"): the feature interactions the first pass did not name.
# Each case failed before its fix. Every timed case runs on virtual time or
# on explicit instants: nothing here waits out a timer.
class EventLoopSpiritTest < Minitest::Test
  include AgentSpaces
  include AgentSpaces::Capabilities
  include GoldenHelpers

  GROUP = "zRubySpirit"

  def setup
    @seeds = []
    @peers = []
    @closers = []
  end

  def teardown
    @closers.each(&:call)
    @peers.each(&:close)
    @seeds.each(&:close)
  end

  def member_ad(time, identity)
    now = time.wall_ms
    ad = Wire.peer_advertisement(GROUP, identity, Instants.iso(now - (now % 1000)), "PT10M", {})
    Wire.signed_peer_ad(ad, identity)
  end

  # ------------------------------------------------- the backstop's sweep

  # Java's NodeLoop sweeps every participant once a backstop has passed since
  # the last sweep, whatever else is due (NodeLoop.java: sweep = now -
  # backstopAt >= 0). The Ruby loop armed its backstop only when nothing was
  # due sooner, so a duty due every few seconds (a busy sweep or collection)
  # kept a missed ask from ever being caught.
  def test_the_backstop_asks_every_duty_even_while_another_is_due_often
    time = VirtualTime.new
    loop = NodeLoop.new("spirit", time: time)
    asked = []
    loop.duty(:busy) { |now| now + 5.0 }
    loop.duty(:stale) do |now|
      asked << now
      now + 1000.0 # a deadline a change moved earlier without asking
    end
    start = time.mono
    loop.advance(31.0)
    assert_equal [0.0, 15.0, 30.0], asked.map { |t| (t - start).round(6) },
                 "asked at once, then at every backstop, though :busy is due every 5 s"
    assert_operator loop.backstop_runs, :>=, 2
  end

  # A group that outgrows the probe cycle moves the keepalive to half the
  # 30 s bound. The member card that grows it asks the keepalive, so the next
  # re-lease is 15 s after the last introduction, not the 30 s deadline set
  # before the group grew (a 30 s judge would have no margin).
  def test_a_group_that_outgrows_the_probe_cycle_asks_the_keepalive_at_once
    fake = Testing::FakeSeed.new.tap { |s| @seeds << s }
    time = VirtualTime.new
    peer = Peer.new(Identity.generate, GROUP, time: time)
    @peers << peer
    intros = []
    peer.define_singleton_method(:introduce) do
      intros << time.mono
      super()
    end
    peer.connect("127.0.0.1", fake.port)
    start = time.mono
    peer.node_loop.duty(:busy) { |now| now + 5.0 } # the store keeps the loop busy
    peer.advance(15.5) # one backstop sweep has passed at 15 s, with the group still small
    7.times { peer.send(:accept_peer_ad, member_ad(time, Identity.generate)) }
    assert_in_delta 15.0, peer.re_lease_period, 1e-9
    peer.advance(1.0)
    assert_equal 2, intros.size, "the re-lease came at once, 15.5 s after the dial's introduction"
    assert_operator intros.last - start, :<=, 16.5
  end

  # --------------------------------------------------- the watchdog's pause

  # Java's watchdog judges every age from a check that began late (a pause of
  # the process: a suspend on macOS, whose monotonic clock counts the sleep,
  # a frozen container, a debugger), since the loops could not run either.
  # The Ruby watchdog re-initialised the loop for a "missed fire" after every
  # laptop sleep, and three sleeps in ten minutes turned the peer DOWN.
  # Virtual clocks a loop thread runs on: the test moves them, and a wake
  # makes the thread run at the moved instant.
  class SteppedTime < VirtualTime
    def real? = true
  end

  def test_a_check_that_began_late_judges_ages_from_itself
    time = SteppedTime.new
    loop = NodeLoop.new("spirit", time: time)
    loop.duty(:beat) { |_now| nil }
    loop.start
    assert eventually { loop.armed_at }
    watchdog = Watchdog.manual(time)
    watchdog.register(loop)
    assert_empty watchdog.check
    3.times do
      time.advance(7200) # a laptop sleep as macOS counts it: both clocks moved
      assert_empty watchdog.check(time.mono, late: 7200 - Watchdog::PERIOD),
                   "a paused process is no evidence against its loop"
      armed = loop.armed_at
      loop.wake # the loop runs as soon as the process does
      assert eventually { loop.armed_at != armed }
      time.advance(Watchdog::PERIOD)
      assert_empty watchdog.check, "the next check, on time, finds the loop re-armed"
    end
    assert_equal 0, loop.generation, "three sleeps re-initialised nothing"
    assert_equal :ok, loop.health[:state], "and turned nothing DOWN"
    time.advance(7200)
    assert_empty watchdog.check(time.mono, late: 7200 - Watchdog::PERIOD)
    time.advance(Watchdog::PERIOD) # this time the loop does not run after the pause
    assert_equal [[loop, :missed_fire]], watchdog.check, "a loop still stuck after a pause is found past its grace"
  ensure
    loop&.stop
  end

  # ------------------------------------------- the resume's check of the link

  # A resume asks the seed this peer holds a link to (EL-C-14 as harmonized
  # 2026-11-23: a wake while linked PINGs the seed). A seed that answers
  # keeps the link: no redial, no move to the next seed, and the relay.via
  # hint still names the member holding the link. (Before the round the
  # resume closed the link, and once the reconnect began with the next seed,
  # so every laptop sleep moved a peer with several seeds to another one.)
  def test_a_resume_keeps_the_link_to_a_seed_that_answers
    a = Testing::FakeSeed.new.tap { |s| @seeds << s }
    b = Testing::FakeSeed.new.tap { |s| @seeds << s }
    time = VirtualTime.new
    peer = Peer.new(Identity.generate, GROUP, time: time)
    @peers << peer
    peer.reconnect_interval = 0.05
    peer.connect_any([a.seed, b.seed])
    assert eventually { a.connections.size == 1 }
    holder = Identity.generate
    peer.handle(Wire.envelope(GROUP, "ACK", holder.peer_id, Wire.hlc_now(holder.peer_id, peer.now_ms), "".b,
                              peer.identity.peer_id))
    assert_equal holder.peer_id, peer.resource_hints["relay.via"]
    peer.run_due
    time.suspend(7200)
    peer.run_due
    assert_equal 1, peer.resumes
    assert eventually { a.kinds(0).include?("PING") }, "the wake asked the seed"
    assert peer.link_asked?
    a.send_to_last(Wire.encode_frame(Wire.envelope(GROUP, "ACK", holder.peer_id,
                                                   Wire.hlc_now(holder.peer_id, peer.now_ms), "".b,
                                                   peer.identity.peer_id), holder))
    assert eventually { !peer.link_asked? }, "the answer was heard"
    time.advance(Peer::LINK_ANSWER + 1)
    peer.run_due
    assert_equal 0, peer.links_silent
    assert peer.connected?
    assert_equal 1, a.connections.size, "the link held: no redial"
    assert_equal 0, b.connections.size, "not the next seed"
    assert_equal holder.peer_id, peer.resource_hints["relay.via"], "the hint still names the member holding the link"
  end

  # ---------------------------------------- cards across a wall step

  # Java converts the card refresh on the stepped clock (EL-C-12): after a
  # forward wall step (a Linux suspend), every card it publishes is renewed
  # at once. Ruby renewed its AgentCards on a thread that waited 300 real
  # seconds, so after a suspend the cards stayed lapsed in every other
  # member's view until that wait ended.
  def test_an_agent_card_is_renewed_at_once_after_a_suspend
    time = VirtualTime.new
    peer = Testing::NetPeer.new(Testing::Network.new, GROUP, time: time)
    @peers << peer
    bound = Binder.new(peer).bind(LoopSpirit::Worker.new)
    @closers << -> { bound.close }
    peer.run_due
    card = -> { peer.ads.values.find { |e| e["type"] == "AgentCard" } }
    first = card.call["expires"]
    time.suspend(7200) # the wall moved two hours, the monotonic clock did not
    peer.run_due
    renewed = card.call
    assert_operator renewed["expires"], :>, time.wall_ms, "the card is live again at once"
    assert_operator renewed["expires"], :>, first
  end

  # And on an idle peer the card is renewed on its refresh by the loop: no
  # extra thread per agent, and on virtual time with no wait.
  def test_an_agent_card_is_renewed_on_its_refresh
    time = VirtualTime.new
    peer = Testing::NetPeer.new(Testing::Network.new, GROUP, time: time)
    @peers << peer
    bound = Binder.new(peer, card_refresh: 300).bind(LoopSpirit::Worker.new)
    @closers << -> { bound.close }
    peer.advance(25 * 60.0)
    card = peer.ads.values.find { |e| e["type"] == "AgentCard" }
    assert_operator card["expires"], :>, time.wall_ms, "still live after 25 idle minutes"
    bound.close
    peer.advance(15 * 60.0)
    assert(peer.ads.values.none? { |e| e["type"] == "AgentCard" && e["expires"] > time.wall_ms },
           "a closed agent's card is renewed no more")
  end

  # The push-sum card (PT15M) was published once at the start and never
  # renewed, so after 15 minutes every other member stopped pushing shares
  # to this peer (a share goes only to a member whose card is live).
  def test_the_aggregate_card_is_renewed_while_the_aggregate_runs
    time = VirtualTime.new
    peer = Testing::NetPeer.new(Testing::Network.new, GROUP, time: time)
    @peers << peer
    agg = Aggregate.new(Pipes.new(peer))
    @closers << -> { agg.close }
    peer.advance(40 * 60.0)
    card = peer.ads.values.find { |e| e["ad"]["capabilityType"] == Aggregate::TYPE }
    assert_operator card["expires"], :>, time.wall_ms, "still live after 40 minutes"
  end
end
