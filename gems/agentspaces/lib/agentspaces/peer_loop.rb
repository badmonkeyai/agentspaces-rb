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

module AgentSpaces
  # The peer's timing as SPEC v0.1.36 restates it (§5.2, §7.3, §9.5) and the
  # reference implementation's event loop built it (srad/agentspaces-event-loop.md;
  # the parity notes' Ruby section), kept apart from peer.rb:
  #
  # - the loop of due work (NodeLoop) with three duties in place of the
  #   0.25 s ticker and the 0.25 s sweep loop: the self-advertisement's
  #   re-lease (the keepalive), the collection past the horizon, and the
  #   watches' sweep, each at its own deadline and asked by the changes that
  #   move it;
  # - the keepalive bound: the re-lease runs at the configured interval, and
  #   at half the 30 s keepalive bound once the group's quiet probe cycle
  #   has outgrown it, so a member that judges this peer at 30 s (a 0.6.0
  #   Java member) never drops it, as the Rust peer's re_lease_period does;
  # - local periods on the monotonic base of the time source, the wall-step
  #   signal, and the resume after a suspend: a forward wall step, or a loop
  #   wake late by more than the keepalive bound, re-introduces this peer at
  #   once and PINGs its seed, failing over when it does not answer within
  #   2 s (EL-C-14 as harmonized 2026-11-23: a thin client checks its link
  #   on wake, and redials at once only when it has none), re-checks its
  #   held takes, and re-probes the members through a view pull before it
  #   judges them by elapsed time (owner decision 3 of 2026-11-23: a loop
  #   wake more than 30 s late with no wall step, a frozen process, is a
  #   wake too);
  # - the issue clock: a changed advertisement or card is issued after the
  #   last one under its id (§10.16, the same-millisecond audit);
  # - relay.via follows the link: the member this peer dialled, known from
  #   the transport's attestation or from its first addressed frame, and
  #   never a seed it no longer holds a link to (SPEC 5.2, the targeted relay);
  # - the watchdog's view of the loop and of the reader: a reader that died
  #   while the peer runs is started again, and a frame handler held past
  #   the wedge bound (a watch callback that blocks the reader, and with it
  #   every PING answer) is reported by frame kind.
  class Peer
    # The keepalive bound every Java member keeps (GroupMembership.KEEPALIVE_TTL)
    # and the TTL a 0.6.0 Java member judges this peer by.
    KEEPALIVE_TTL = 30.0
    # Java's probe period and quiet stretch, for the probe cycle a group of
    # this size runs (GroupMembership.Config defaults, MAX_QUIET_STRETCH).
    PROBE_INTERVAL = 1.0
    QUIET_STRETCH = 4
    # A change of more than this in wall minus monotonic is a wall step (TS-6).
    WALL_STEP_THRESHOLD = 1.0
    # The least gap between two collection runs that found nothing due, so an
    # approximate horizon never spins the loop.
    COLLECT_MIN_GAP = 1.0
    # A frame handler past this is slow: counted by kind.
    SLOW_FRAME = 0.1
    # How many issue instants the issue clock remembers.
    ISSUE_MEMORY = 4096
    # How many held takes the wake re-check follows; past it the oldest goes.
    HELD_TAKES_MAX = 4096

    # Runs whatever is due now (a test on virtual time calls it after moving
    # the clock); returns the loop's next due on the monotonic base.
    def run_due = @node_loop.run_due

    # On virtual time: moves the clock by seconds, running each deadline at
    # its own instant, as the loop thread would.
    def advance(seconds) = @node_loop.advance(seconds)

    # :ok, :degraded or :down with reasons (EL-H-14): the loop's own health,
    # and :down when the watchdog escalated it.
    def loop_health = @node_loop.health

    # Listens for each change of loop_health.
    def on_loop_health(&listener) = @node_loop.on_health(&listener)

    # The loop's counters, the reader's, and the time judgements'.
    def loop_stats
      # resume_rejoins and link_pings are the old names of resumes and
      # seed_pings, kept for one release.
      @node_loop.stats.merge(wall_steps: @wall_steps, resumes: @resumes, resume_rejoins: @resumes,
                             reader_restarts: @reader_restarts, slow_frames: @slow_frames.dup,
                             held_frames: @held_frames.dup, keepalive_period: re_lease_period,
                             links_silent: links_silent, seed_pings: seed_pings, wake_pings: wake_pings,
                             link_pings: seed_pings, seed_dials: seed_dials, late_seed_channels: late_seed_channels,
                             held_takes_lapsed: held_takes_lapsed, late_takes: late_takes,
                             view_reprobes: view_reprobes, late_wakes: @state_lock.synchronize { @late_wakes })
    end

    # Held takes a wake or a wall step found lapsed, and stopped renewing
    # (C05, owner decisions 5 and 2 of 2026-11-23): the claim no longer this
    # take's, or its wall-time lease ended.
    def held_takes_lapsed = @state_lock.synchronize { @held_takes_lapsed }

    # Results that arrived after their take lapsed: each completed nothing
    # and wrote nothing (C05, owner decision 2 of 2026-11-23; the core's
    # lateTakes). Counted once per take.
    def late_takes = @state_lock.synchronize { @late_takes }

    # How often the self-advertisement is re-leased now: the configured
    # interval, unless the group's quiet probe cycle (one member per probe
    # period, stretched four times when quiet) has outgrown the 30 s
    # keepalive bound; past that the probes no longer reach every member
    # inside that bound, so the re-lease is the keepalive and runs at half
    # the bound at most (SPEC 5.2; the Rust peer's re_lease_period).
    def re_lease_period
      cycle = (view_size + 1) * PROBE_INTERVAL * QUIET_STRETCH
      cycle < KEEPALIVE_TTL ? @peer_ad_interval : [@peer_ad_interval, KEEPALIVE_TTL / 2].min
    end

    # The members of this peer's view: a live card, or heard from lately, or
    # a member the re-probe after a wake still waits on (reprobing?).
    def view_members
      now = now_ms
      local = local_ms
      @state_lock.synchronize do
        @members.keys.select do |member|
          card = @member_cards[member]
          member != @identity.peer_id &&
            ((card && card[0] > now) || @heard_at.fetch(member, -Float::INFINITY) > local - VIEW_HEARD_MILLIS ||
             reprobing?(member, now, local))
        end
      end
    end

    # The re-probes of the members wakes started (owner decision 3).
    def view_reprobes = @state_lock.synchronize { @view_reprobes }

    def view_size = view_members.size

    # The earliest wall instant a watch waits on moved to at most at_ms (a
    # Space's fold or a renewal): the sweep duty is asked when it is earlier
    # than the one it holds.
    def sweep_hint(at_ms)
      return if at_ms.nil?

      earlier = @state_lock.synchronize do
        next false unless @sweep_due_ms.nil? || at_ms < @sweep_due_ms

        @sweep_due_ms = at_ms
        true
      end
      @node_loop.wake(:sweep) if earlier
    end

    # A card this peer publishes and keeps live (keep_card); close stops
    # its renewal.
    class KeptCard
      attr_reader :refresh

      def initialize(peer, refresh, publish)
        @peer = peer
        @refresh = refresh
        @publish = publish
        @mono_at = nil
        @wall_at = nil
        @open = true
      end

      def open? = @open

      def close
        @open = false
        @peer.send(:forget_card, self)
        nil
      end

      # Internal, for the loop's cards duty.
      def mark(mono, wall)
        @mono_at = mono
        @wall_at = wall
      end

      def due?(mono, wall) = mono - @mono_at >= @refresh || wall - @wall_at >= @refresh * 1000

      def next_due(mono, wall) = [@mono_at + @refresh, mono + ((@wall_at + (@refresh * 1000) - wall) / 1000.0)].min

      def publish! = @publish.call
    end

    # Keeps a card live that the caller has just published: the block
    # publishes it again every refresh seconds on the monotonic base, and at
    # once when the card's age on the wall clock reaches refresh, so after a
    # forward wall step or a suspend the card is renewed in the loop's next
    # turn, as Java converts its card refresh on the stepped clock (EL-C-12).
    # A loop duty, not a thread per card. Returns a handle; close stops it.
    def keep_card(refresh_seconds, &publish)
      raise ArgumentError, "keep_card needs a block that publishes the card" if publish.nil?

      refresh = Float(refresh_seconds)
      raise ArgumentError, "a card refresh is positive: #{refresh}" unless refresh.positive?

      card = KeptCard.new(self, refresh, publish)
      card.mark(@time.mono, now_ms)
      @state_lock.synchronize { @kept_cards << card }
      start_loop unless @closed
      @node_loop.wake(:cards)
      card
    end

    private

    def forget_card(card) = @state_lock.synchronize { @kept_cards.delete(card) }

    # The cards duty: each kept card due on either clock is published again.
    def run_cards(now)
      wall = now_ms
      cards = @state_lock.synchronize { @kept_cards.dup }
      cards.each do |card|
        next unless card.open? && card.due?(now, wall)

        card.mark(now, wall)
        begin
          card.publish!
        rescue StandardError => e
          @logger&.warn("agentspaces: a card renewal failed: #{e.class}: #{e.message}")
        end
      end
      cards.select(&:open?).map { |card| card.next_due(now, wall) }.min
    end

    # Monotonic milliseconds of the time source, for local periods.
    def local_ms = (@time.mono * 1000).to_i

    def init_loop(watchdog)
      @node_loop = NodeLoop.new("peer #{@identity.peer_id[0, 16]}", time: @time, logger: @logger)
      # A wall-following source (a pinned test clock) is judged by no watchdog,
      # as the reference implementation's is not: its base is the test's.
      following = @time.respond_to?(:wall_following?) && @time.wall_following?
      @watchdog = watchdog || (@time.real? && !following ? Watchdog.system : Watchdog.manual(@time))
      @node_loop.watchdog = @watchdog
      @node_loop.on_turn = method(:judge_time)
      @reader_watch = ReaderWatch.new(self)
      @wall_steps = 0
      @resumes = 0
      @late_wakes = 0
      @reader_restarts = 0
      @slow_frames = Hash.new(0)
      @held_frames = Hash.new(0)
      @handling = nil
      @last_drift = nil
      @introduced_at = nil
      @introduce_now = false
      @last_peer_item = 0
      @issued = {}
      @sweep_due_ms = nil
      @collect_due_ms = nil
      @kept_cards = []
      @held_takes = {}
      @view_reprobe = nil
      @view_reprobes = 0
      @view_repull_due = false
      @held_takes_lapsed = 0
      @late_takes = 0
      # Set by the first dial: the keepalive and the collection are a
      # connected peer's; an in-process test peer sweeps its watches only.
      @dialled = false
      @node_loop.duty(:self_ad, kind: :protocol) { |now| run_self_ad(now) }
      @node_loop.duty(:reoffer, kind: :protocol) { |now| run_reoffers(now) }
      @node_loop.duty(:displaced_pull, kind: :protocol) { |now| run_displaced_pulls(now) }
      @node_loop.duty(:collect) { |now| run_collect(now) }
      @node_loop.duty(:sweep) { |now| run_sweep(now) }
      @node_loop.duty(:cards) { |now| run_cards(now) }
    end

    # Starts the loop's thread (real time) and its watch; idempotent. The
    # first dial and the first observer start it.
    def start_loop
      @node_loop.logger ||= @logger
      @node_loop.start
      @watchdog.register(@node_loop)
      @watchdog.register(@reader_watch)
      @node_loop.wake
    end

    def stop_loop
      @watchdog.unregister(@reader_watch)
      @watchdog.unregister(@node_loop)
      @node_loop.stop
    end

    # ---------------------------------------------------------------- duties

    # The keepalive: the self-advertisement re-leased at re_lease_period from
    # the last introduction, whoever sent it, and at once when a resume asks.
    def run_self_ad(now)
      return nil unless @dialled

      period = re_lease_period
      return now + period unless connected?

      if @introduce_now || @introduced_at.nil? || now - @introduced_at >= period
        @introduce_now = false
        introduce
      end
      repull = @state_lock.synchronize { @view_repull_due.tap { @view_repull_due = false } }
      pull_view if repull || cards_ending?
      @introduced_at + period
    end

    # ------------------------------------------------- the re-probe after a wake

    # Owner decision 3 of 2026-11-23: after a wake, a member whose card
    # lapsed, or who was last heard from too long ago, only because this
    # peer was frozen or asleep is probed before it is judged, not dropped.
    # A dial-only peer probes the members through its seed: it pulls the
    # view at once (the cards that lapsed are left out of its digest, so the
    # seed sends each member's current card), and until the answer comes,
    # or view_reprobe_wait passes, such a member stays in view_members and
    # counts in the horizon's view as lacking the hint (view_hinted?), the
    # cautious side. A member the answer does not bring back leaves then.
    # The writer's stay (writers_vouched?) is not carried across the
    # absence: a lapsed card restarts it, which only delays a collection.

    # The re-probe's bound: the dead-seed rule's answer (LINK_ANSWER) and one
    # redial step at its widest, times the 1.5 a TTL keeps over its cycle.
    def view_reprobe_wait = 1.5 * (LINK_ANSWER + (REDIAL_TABLE.first * (1 + REDIAL_SPREAD)))

    # A wake absent seconds long starts a re-probe of the members.
    def start_view_reprobe(absent)
      absent_ms = (absent * 1000).ceil
      @state_lock.synchronize do
        @view_reprobe = { until_local: local_ms + (view_reprobe_wait * 1000), wall_before: now_ms - absent_ms,
                          local_before: local_ms - absent_ms }
        @view_repull_due = true
        @view_reprobes += 1
      end
    end

    # The seed's answer to a view pull came: the re-probe ends, and the view
    # is judged by the cards it brought.
    def view_answered = @state_lock.synchronize { @view_reprobe = nil }

    # Whether member is in view only pending the re-probe: its card was live
    # before the absence, or it was heard from within VIEW_HEARD_MILLIS of
    # it. Called under @state_lock.
    def reprobing?(member, _now, local)
      probe = @view_reprobe
      return false if probe.nil?
      if local >= probe[:until_local]
        @view_reprobe = nil
        return false
      end

      card = @member_cards[member]
      (card && card[0] > probe[:wall_before]) ||
        @heard_at.fetch(member, -Float::INFINITY) > probe[:local_before] - VIEW_HEARD_MILLIS
    end

    # A member card held that ends sooner than this is left out of the view
    # digest this peer sends its seed, so the seed sends the member's current
    # card (SPEC 5.2, the "view" stream): a member that refreshes its card
    # only to the members it holds a link to (a Java member's direct refresh
    # never reaches a dial-only peer) stays in view_members while the seed
    # holds it, and leaves when the seed no longer does (the mixed idle run of
    # 2026-11-23: every such card lapsed at 10 minutes).
    VIEW_REFRESH_MARGIN_MS = 180_000

    # Whether a live member card held ends within VIEW_REFRESH_MARGIN_MS (a
    # lapsed one asks nothing more: its member left).
    def cards_ending?
      now = now_ms
      horizon = now + VIEW_REFRESH_MARGIN_MS
      @state_lock.synchronize { @member_cards.any? { |_, card| card[0] > now && card[0] <= horizon } }
    end

    # Pulls the membership view from the seed, naming only the cards held that
    # end later than VIEW_REFRESH_MARGIN_MS from now.
    def pull_view
      horizon = now_ms + VIEW_REFRESH_MARGIN_MS
      fresh = @state_lock.synchronize { @member_cards.select { |_, card| card[0] > horizon }.keys }
      @view_pulls = (@view_pulls || 0) + 1
      digest = (fresh | [@identity.peer_id]).sort.map { |id| "#{id}\n" }.join.b
      send_frame("DIGEST", Wire.digest_body({ "view" => digest }))
    end

    # The view pulls cards_ending? asked for.
    def view_pulls = @view_pulls || 0

    # The collection past the horizon (SPEC 7.3), at the earliest horizon a
    # held state reaches or the next judgement the horizon mode waits on.
    def run_collect(now)
      return nil unless @dialled

      wall = now_ms
      due = @state_lock.synchronize { @collect_due_ms }
      begin
        collect_garbage(wall) if due.nil? || wall >= due
      rescue StandardError => e
        @logger&.warn("agentspaces: collection failed: #{e.class}: #{e.message}")
      end
      due = next_collect_ms(wall)
      @state_lock.synchronize { @collect_due_ms = due }
      return nil if due.nil?

      now + [(due - wall) / 1000.0, COLLECT_MIN_GAP].max
    end

    # The watches' sweep (EXPIRED, REAPPEARED, lapsed subscriptions) at the
    # earliest lapse a watching Space waits on.
    def run_sweep(now)
      wall = now_ms
      observers = @state_lock.synchronize { @observers.dup }.select(&:watching?)
      due = @state_lock.synchronize { @sweep_due_ms }
      if due.nil? || wall >= due
        observers.each do |observer|
          observer.sweep
        rescue StandardError => e
          @logger&.warn("agentspaces: a watch sweep failed: #{e.class}: #{e.message}")
        end
      end
      wall = now_ms
      due = observers.filter_map { |o| o.respond_to?(:next_sweep_ms) ? o.next_sweep_ms(wall) : wall + 1000 }.min
      @state_lock.synchronize { @sweep_due_ms = due }
      return nil if due.nil?

      # Still due right after a sweep: something it could not judge (an
      # observer that raised) is judged again in a second, never in a spin.
      delay = (due - wall) / 1000.0
      now + (delay.positive? ? delay : 1.0)
    end

    # ------------------------------------------------------ time judgements

    # Each loop turn: a wall step asks every duty again (their wall-anchored
    # deadlines are converted afresh); a forward step or a late wake longer
    # than the keepalive bound is an absence, and this peer rejoins.
    def judge_time(now, late)
      return unless steps_judged?

      drift = (@time.wall_ms / 1000.0) - now
      step = @last_drift.nil? ? 0.0 : drift - @last_drift
      @last_drift = drift
      if step.abs > WALL_STEP_THRESHOLD
        @wall_steps += 1
        @node_loop.wake
      end
      recheck_held_takes if step.abs > WALL_STEP_THRESHOLD || late > WALL_STEP_THRESHOLD
      # A wake more than 30 s late that no wall step explains: a frozen
      # process (owner decision 3), counted as the core's lateWakes.
      @state_lock.synchronize { @late_wakes += 1 } if late > KEEPALIVE_TTL && step.abs <= WALL_STEP_THRESHOLD
      resume(step.positive? ? step : late) if step > KEEPALIVE_TTL || late > KEEPALIVE_TTL
    end

    # ----------------------------------------------------------- held takes

    # C05 (owner decisions 5 and 2 of 2026-11-23): a take's lease is a
    # wall-clock stamp, and the renewals that keep it run on local periods,
    # which a sleep does not advance on every system. So on every wake (a
    # loop turn late by more than a second) and every wall step, each take
    # held here is judged at once. A take has lapsed when its claim is no
    # longer ours (another holder's or epoch's, or none) or its wall-time
    # lease has expired: it stops renewing (its keepalive ends, renew
    # raises), and its result is late (complete raises, writing nothing,
    # counted in late_takes). Nothing is judged on a schedule; between wakes
    # a renewal or a result judges the take itself (Taken#lapsed_at?).

    # A Taken this peer now holds (Taken#initialize); the oldest is dropped
    # past HELD_TAKES_MAX, and any no longer held here on the way.
    def note_held_take(taken)
      wall = now_ms
      @state_lock.synchronize do
        @held_takes.delete_if { |held, _| held.done? || !held.held_here?(wall) } if @held_takes.size >= HELD_TAKES_MAX
        @held_takes[taken] = true
        @held_takes.shift while @held_takes.size > HELD_TAKES_MAX
      end
    end

    # A take completed, given up, or lapsed: no longer followed.
    def release_held_take(taken) = @state_lock.synchronize { @held_takes.delete(taken) }

    # A result arrived after its take lapsed (Taken#complete).
    def count_late_take = @state_lock.synchronize { @late_takes += 1 }

    # Judges each held take now: one whose claim is no longer ours or whose
    # wall-time lease expired lapses (no renewal, a late result); one still
    # held tells its wake listeners, so a keepalive renews it at once.
    def recheck_held_takes
      wall = now_ms
      lapsed = []
      live = []
      @state_lock.synchronize do
        @held_takes.delete_if do |taken, _|
          next true if taken.done?
          if taken.held_here?(wall)
            live << taken
            next false
          end

          lapsed << taken unless taken.lapsed?
          true
        end
        @held_takes_lapsed += lapsed.size
      end
      lapsed.each do |taken|
        why = if taken.lease_lapsed?(wall) then "its lease ended while this peer was away"
              else "its claim is no longer this take's"
              end
        @logger&.info("agentspaces: the take of #{taken.entry_id} lapsed (#{why}); it is no longer renewed and its " \
                      "result is late")
        taken.send(:lapse!)
      end
      live.each { |taken| taken.send(:woke!) } # a keepalive renews a take still held at once
    end

    # A pinned wall clock (a test's clock:) moves on its own schedule, which
    # is no step; only the system's clocks and virtual time are judged.
    def steps_judged? = !(@time.respond_to?(:wall_following?) && @time.wall_following?)

    # After an absence the members may have dropped this peer: it sends its
    # self-advertisement at once (SPEC 9.5), and the redial table starts
    # again (Harmonization, rules 1 and 3, owner decision 2026-11-23, one
    # rule for every client). Holding a link from before the absence, it
    # PINGs the seed and the dead-seed rule judges the link: no answer
    # within LINK_ANSWER (2 s) fails over to the next seed at once, an
    # answer keeps the link. With no link, a reconnect pausing between
    # rounds of dials dials at once. Either way the members are re-probed
    # before they are judged (start_view_reprobe, owner decision 3).
    def resume(absent)
      @resumes += 1
      @introduce_now = true
      start_view_reprobe(absent)
      @node_loop.wake(:self_ad)
      channel = @channel
      if @running && @seed && channel
        @logger&.info("agentspaces: back after about #{absent.round} s away; asking the seed whether the link holds")
        redial_reset
        link_ask_on_wake
      else
        @logger&.info("agentspaces: back after about #{absent.round} s away; introducing this peer again")
        # The pause may have slept through the network's return (round 2a).
        wake_redial! if @running && @seed
      end
    end

    # ------------------------------------------------------- the issue clock

    # The issue instant of an advertisement under id: base, unless one with
    # other content was already issued at base or later, which makes it the
    # millisecond after that one; the same content keeps its instant (it is
    # the same card).
    def issue_ms(id, fingerprint, base)
      @state_lock.synchronize do
        last = @issued.delete(id)
        ms = if last.nil? || base > last[1] then base
             elsif last[0] == fingerprint then last[1]
             else last[1] + 1
             end
        @issued[id] = [fingerprint, ms]
        @issued.shift while @issued.size > ISSUE_MEMORY
        ms
      end
    end

    def after_last_issue(ad)
      return ad unless ad.is_a?(Hash) && ad["id"].is_a?(String) && ad["issued"].is_a?(String)

      base = Instants.parse_millis(ad["issued"])
      ms = issue_ms(ad["id"], CBOR.dump(ad.except("issued")).hash, base)
      ms == base ? ad : ad.merge("issued" => Instants.iso(ms))
    end

    # ---------------------------------------------------------- the relay hint

    # After a dial: relay.via names the member this peer now holds a link to.
    # The transport's attestation names it at once; otherwise the first
    # addressed frame does (handle). A link to another seed than before clears
    # the hint, so no member probes this peer through a holder it left.
    def adopt_link_holder(previous_seed)
      attested = @channel&.attested_peer
      if attested.is_a?(String) && attested != @identity.peer_id
        @seed_peer = attested
        @resource_hints["relay.via"] = attested
      elsif previous_seed != @seed
        @seed_peer = nil
        @resource_hints.delete("relay.via")
      end
    end

    # ------------------------------------------------------------ the reader

    def handle_timed(env)
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      @handling = [env["kind"].to_s, started]
      handle(env)
    ensure
      @handling = nil
      took = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
      @state_lock.synchronize { @slow_frames[env["kind"].to_s] += 1 } if took > SLOW_FRAME
    end

    # The watchdog's judgement of the reader: a dead reader while the peer
    # runs is started again (it dials when it finds no channel); a frame
    # handler held past the wedge bound is reported once by kind, since every
    # frame behind it waits, the PINGs that keep this peer in the views too.
    def check_reader(wedge)
      return nil unless @running && !@closed

      reader = @reader
      if reader && !reader.alive?
        @reader_restarts += 1
        @logger&.warn("agentspaces: the reader thread died; starting it again")
        @reader = start_thread("agentspaces-reader") { read_loop }
        return :reader_dead
      end
      handling = @handling
      return nil if handling.nil? || handling.equal?(@held_reported)

      held = Process.clock_gettime(Process::CLOCK_MONOTONIC) - handling[1]
      return nil unless held > wedge

      @held_reported = handling
      @state_lock.synchronize { @held_frames[handling[0]] += 1 }
      @logger&.warn("agentspaces: the reader has handled one #{handling[0]} frame for #{held.round(1)} s; every " \
                    "frame behind it waits, PING answers included (a watch callback runs on the reader: return promptly)")
      :frame_held
    end

    # The reader as the watchdog sees it.
    class ReaderWatch
      def initialize(peer)
        @peer = peer
      end

      # The held-frame judgement is a report on the reader's own clock; a
      # pause (judge_from) restarts nothing here.
      def watchdog_check(_now, wedge:, **)
        @peer.send(:check_reader, wedge)
      end

      def inspect = "#<AgentSpaces::Peer::ReaderWatch #{@peer.identity.peer_id}>"
    end
  end
end
