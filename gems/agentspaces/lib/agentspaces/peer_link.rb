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
  # The liveness of this dial-only peer's one link (owner decision 2026-11-23,
  # one rule for every dial-only client; .parity-wt/PARITY-ruby.md, Round 2a):
  #
  # - The dead-seed rule. A link this peer has read nothing from for
  #   LINK_QUIET seconds (1.5 times the 30 s keepalive bound) is asked: a
  #   PING to the seed, which answers every PING at once with an ACK (SPEC
  #   5.2). A link still silent LINK_ANSWER seconds (the 2 s ping timeout)
  #   after the PING is dead:
  #   a seed whose host lost power, a lost NAT mapping or a partition sends
  #   no FIN, and the reader would otherwise block until TCP gives up, which
  #   takes minutes, while relay.via names a holder with no link. The link
  #   is closed, so the reader fails over to the next seed (or dials the one
  #   seed again with the cycling backoff), and the hint follows the new
  #   holder. Any frame read off the link counts as hearing the seed, so a
  #   seed whose own probes keep the link busy is never asked.
  # - A wake from sleep (Harmonization, owner decision 2026-11-23, one rule
  #   for every client). With the link up, the seed is asked at once: a PING
  #   under the dead-seed rule, so a seed that does not answer within
  #   LINK_ANSWER is failed over at once, and one that answers keeps the
  #   link (this peer introduces itself again on it). With no link, a
  #   reconnect pausing between rounds dials at once: the pauses wait on a
  #   condition the resume signals, so a laptop that woke mid-backoff does
  #   not wait out the rest of a pause of up to 33 s first. Either way the
  #   redial table starts again.
  # - The redial table (owner decision 2026-11-23, one table for the core
  #   and every client; Round 2b part 1): the pauses between failed rounds
  #   of dials follow REDIAL_TABLE, 5, 10, 20, 30 s, then wrap to 5 s, each
  #   spread by up to REDIAL_SPREAD either way so the clients of a seed that
  #   restarts do not redial it in lockstep. The table is static; each peer
  #   keeps its position in it, and only two things put it back to 0: the
  #   end of a link that held for at least reconnect_interval (5 s), and a
  #   wake. A link that ends sooner counts as a failed round and waits the
  #   next step.
  # - Staggered seed dials (Harmonization, owner decision 2026-11-23; RFC
  #   8305, "Happy Eyeballs"): a round dials its seeds in list order, each
  #   DIAL_STAGGER (250 ms) after the one before, or at once when a dial
  #   refuses. The first to open wins; the seeds not yet dialled are not
  #   dialled, and a dial that opens after the win is closed at once. The
  #   list after a lost link starts at the next seed and ends with the seed
  #   just lost, so that one is tried last.
  #
  # The judgement is a duty of the peer's loop (:link) at its own deadlines,
  # on the time source's monotonic base, and uses existing frames only
  # (PING, ACK). A pinned test clock (clock:) moves on its own schedule, so
  # on such a source the link is judged on the system's monotonic clock.
  class Peer
    # Silence on the link this long asks the seed with a PING.
    LINK_QUIET = 45.0
    # A PING unanswered this long, with nothing else read meanwhile, ends the
    # link: the ping timeout a prober gives each PING (SPEC 9.4, 2 s; the
    # core's GroupMembership; Python's LINK_ANSWER_S). Bytes of a frame still
    # arriving count as an answer (FrameChannel#on_bytes=).
    LINK_ANSWER = 2.0
    # While a frame handler holds the reader the silence is this peer's own:
    # the link is judged again this much later.
    LINK_HELD_RECHECK = 1.0
    # The pauses between failed rounds of dials, in seconds at the default
    # reconnect_interval of 5 s (a test's shorter interval scales them all),
    # cycling: after 30 s the next pause is 5 s again.
    REDIAL_TABLE = [5.0, 10.0, 20.0, 30.0].freeze
    # Each pause is spread uniformly by up to this fraction either way.
    REDIAL_SPREAD = 0.1
    # How long one dial of one seed may take.
    DIAL_TIMEOUT = 10
    # How long after one dial of a round the next seed's dial starts, unless
    # a dial refused sooner (RFC 8305's connection attempt delay).
    DIAL_STAGGER = 0.25
    # The most dials of one round in flight at once (a hostname seed may
    # expand to many addresses).
    MAX_DIALS_AT_ONCE = 16

    # Links closed because the seed went silent and left a PING unanswered.
    def links_silent = @link_lock.synchronize { @links_silent }

    # PINGs this peer sent to ask its seed: after LINK_QUIET of silence, and
    # on a wake (one counter name in every client, owner decision 2026-11-23,
    # the core's naming style: seed_pings, wake_pings, links_silent,
    # resumes, seed_dials, late_seed_channels).
    def seed_pings = @link_lock.synchronize { @seed_pings }

    # Of seed_pings, the ones a wake sent with the link up (rule 3).
    def wake_pings = @link_lock.synchronize { @wake_pings }

    # Seed dials started, one per seed per round of dials.
    def seed_dials = @link_lock.synchronize { @seed_dials }

    # Channels that opened after another seed of the round had won, and were closed.
    def late_seed_channels = @link_lock.synchronize { @late_seed_channels }

    # Deprecated: seed_pings's old name, kept for one release.
    def link_pings = seed_pings

    # Whether a PING to the seed waits for its answer.
    def link_asked? = @link_lock.synchronize { !@link_asked_at.nil? }

    private

    def init_link
      @link_lock = Mutex.new
      @link_heard_at = nil
      @link_asked_at = nil
      @link_wake_ask = false # the PING waiting for its answer was a wake's
      @links_silent = 0
      @seed_pings = 0
      @wake_pings = 0
      @seed_dials = 0
      @late_seed_channels = 0
      @redial_lock = Mutex.new
      @redial_cond = ConditionVariable.new
      @redial_now = false
      @redial_position = 0 # this peer's place in REDIAL_TABLE
      @redial_random = Random.new
      @node_loop.duty(:link, kind: :protocol) { |now| run_link(now) }
    end

    # The clock the link is judged on: the time source's monotonic base, or
    # the system's under a pinned test clock.
    def link_clock = steps_judged? ? @time.mono : monotonic

    # A new link: heard as of its dial, nothing asked, and judged from now.
    # Bytes of a frame still arriving on it count as hearing the seed.
    def link_opened
      channel = @channel
      channel.on_bytes = method(:link_heard) if channel.respond_to?(:on_bytes=)
      @link_lock.synchronize do
        @link_heard_at = link_clock
        @link_asked_at = nil
        @link_wake_ask = false
      end
      @redial_lock.synchronize { @redial_now = false }
      @node_loop.wake(:link)
    end

    # The reader read a frame off the link (any frame, before it is decoded),
    # or a piece of a large one.
    def link_heard
      at = link_clock
      @link_lock.synchronize do
        @link_heard_at = at
        @link_asked_at = nil
        @link_wake_ask = false
      end
    end

    # A wake from sleep with the link up (Harmonization, rule 3): the seed is
    # asked at once, whatever the link's quiet, and the dead-seed rule
    # judges the answer. A PING already waiting is not sent again.
    def link_ask_on_wake
      at = link_clock
      ask = @link_lock.synchronize do
        @link_wake_ask = true
        next false unless @link_asked_at.nil?

        @link_heard_at ||= at
        @link_asked_at = at
        @seed_pings += 1
        @wake_pings += 1
        true
      end
      send_frame("PING", Wire.ping_body(rand(1 << 62)), @seed_peer) if ask
      @node_loop.wake(:link)
    end

    # The :link duty: asks a silent link, and closes one that left its PING
    # unanswered. Returns the next judgement on the loop's base.
    def run_link(now)
      return nil unless @dialled && @running && !@closed

      channel = @channel
      return nil if channel.nil? # the next dial asks this duty again
      # A link this duty closed stays @channel until the reader sees the
      # close; it is not judged (and pinged, and closed) again meanwhile.
      return nil if channel.equal?(@link_dropped)
      return now + LINK_HELD_RECHECK unless @handling.nil?

      at = link_clock
      action, due = @link_lock.synchronize do
        @link_heard_at ||= at
        if @link_asked_at.nil?
          quiet_until = @link_heard_at + LINK_QUIET
          next [nil, quiet_until] if at < quiet_until

          @link_asked_at = at
          @seed_pings += 1
          [:ask, at + LINK_ANSWER]
        elsif at < @link_asked_at + LINK_ANSWER
          [nil, @link_asked_at + LINK_ANSWER]
        else
          @link_asked_at = nil
          @links_silent += 1
          woke = @link_wake_ask
          @link_wake_ask = false
          [woke ? :fail_over : :drop, nil]
        end
      end
      case action
      when :ask
        send_frame("PING", Wire.ping_body(rand(1 << 62)), @seed_peer)
      when :drop, :fail_over
        @logger&.warn("agentspaces: the seed #{@seed} sent nothing for #{(at - @link_heard_at).round} s and left " \
                      "a PING unanswered; closing the link to dial the next seed")
        # After a wake the failover dials at once, however young the link
        # was: the wake already started the table again (rule 3).
        redial_now! if action == :fail_over
        @link_dropped = channel
        channel.close # the reader dials the other seeds first, in list order, this one last
        return nil
      end
      now + (due - at)
    end

    # The next pause between rounds of dials: the table's entry at this
    # peer's position, scaled to reconnect_interval and spread by up to
    # REDIAL_SPREAD either way. The position moves on and wraps.
    def redial_pause
      @redial_lock.synchronize do
        base = REDIAL_TABLE[@redial_position] * (@reconnect_interval / REDIAL_TABLE.first)
        @redial_position = (@redial_position + 1) % REDIAL_TABLE.size
        base * (1 + (REDIAL_SPREAD * ((2 * @redial_random.rand) - 1)))
      end
    end

    # The table starts again: a link held, or a wake.
    def redial_reset = @redial_lock.synchronize { @redial_position = 0 }

    # This peer's position in REDIAL_TABLE.
    def redial_position = @redial_lock.synchronize { @redial_position }

    # A pause between rounds of dials, cut short when a resume asks for a
    # dial now (wake_redial!) or the peer closes. Returns whether it was cut;
    # a cut pause starts the table again.
    def reconnect_wait(seconds)
      deadline = monotonic + seconds
      @redial_lock.synchronize do
        until @redial_now || !@running
          left = deadline - monotonic
          break unless left.positive?

          @redial_cond.wait(@redial_lock, left)
        end
        cut = @redial_now
        @redial_now = false
        @redial_position = 0 if cut
        cut
      end
    end

    # A round of dials starts now: a dial asked for earlier is spent.
    def redial_started = @redial_lock.synchronize { @redial_now = false }

    # Asks a reconnect pausing between rounds to dial at once.
    def redial_now!
      @redial_lock.synchronize do
        @redial_now = true
        @redial_cond.broadcast
      end
    end

    # A wake: the table starts again, and a reconnect pausing between rounds
    # (or about to) dials at once.
    def wake_redial!
      @redial_lock.synchronize do
        @redial_position = 0
        @redial_now = true
        @redial_cond.broadcast
      end
    end

    # Dials one seed. Raises what the dialer raises.
    def open_seed(seed, timeout)
      dialer = dialer_for(seed.scheme)
      raise IOError, "no dialer serves the #{seed.scheme} scheme" if dialer.nil?

      dialer.open(seed, identity: @identity, timeout: timeout)
    end

    def dial_failure(seed, error) = "#{seed}: #{error.class.name.split('::').last} #{error.message}"

    # A refusal of the network or the transport: expected, and not logged.
    EXPECTED_DIAL_ERRORS = [SystemCallError, IOError, SocketError, OpenSSL::SSL::SSLError, Timeout::Error].freeze

    # The clock a round of dials and a link's age are judged on (a test
    # swaps in a fake one).
    def redial_clock = monotonic

    # Waits for the next event of a round of dials, with in_flight dials
    # not yet reported: up to seconds, or until one arrives when seconds is
    # nil. Returns nil when the wait ran out (a test swaps in a wait on a
    # fake clock, which in_flight lets it judge).
    def dial_wait(events, seconds, _in_flight) = seconds.nil? ? events.pop : events.pop(timeout: seconds)

    # Dials the seeds in list order, staggered (owner decision 2026-11-23,
    # the connection attempt delay of RFC 8305, "Happy Eyeballs"): each dial
    # starts DIAL_STAGGER after the one before, or at once when a dial
    # refuses, each on its own thread, at most MAX_DIALS_AT_ONCE in flight.
    # The first to open wins and is returned at once; no seed left in the
    # list is dialled after it, and a dial still in flight that opens later
    # is closed as it opens. So a first seed that answers keeps its place,
    # and a silent one costs the others DIAL_STAGGER, never a connect
    # timeout. Returns [seed, channel, failures]: seed and channel are nil
    # when every dial failed, and failures names, in list order, each seed
    # that refused before the answer.
    def dial_first(seeds, timeout: DIAL_TIMEOUT, stagger: DIAL_STAGGER)
      events = Thread::Queue.new
      lock = Mutex.new
      won = false
      failures = {}
      dial = lambda do |index, seed|
        channel = begin
          open_seed(seed, timeout)
        rescue StandardError => e
          # Anything but a refusal is a fault in a dialer, counted as a
          # refusal and logged.
          unless EXPECTED_DIAL_ERRORS.any? { |k| e.is_a?(k) }
            @logger&.warn("agentspaces: dialling #{seed} failed: #{e.class}: #{e.message}")
          end
          next events << [:refused, index, seed, e]
        end
        next events << [:open, index, seed, channel] if lock.synchronize { won ? false : (won = true) }

        @link_lock.synchronize { @late_seed_channels += 1 }
        begin
          channel.close # a later answer: the round has its link
        rescue StandardError
          nil
        end
      end

      started = 0
      in_flight = 0
      start_next_at = redial_clock
      loop do
        can_start = started < seeds.size && in_flight < MAX_DIALS_AT_ONCE
        if can_start && (in_flight.zero? || redial_clock >= start_next_at)
          @link_lock.synchronize { @seed_dials += 1 }
          thread = Thread.new(started, seeds[started], &dial)
          thread.name = "agentspaces-dial"
          thread.report_on_exception = false
          started += 1
          in_flight += 1
          start_next_at = redial_clock + stagger
          next
        end
        break if in_flight.zero?

        event = dial_wait(events, can_start ? [start_next_at - redial_clock, 0].max : nil, in_flight)
        next if event.nil? # the stagger ran out: the next seed starts

        in_flight -= 1
        kind, index, seed, value = event
        return [seed, value, failures.sort.map(&:last)] if kind == :open

        failures[index] = dial_failure(seed, value)
        start_next_at = redial_clock # a refusal starts the next dial at once
      end
      [nil, nil, failures.sort.map(&:last)]
    end
  end
end
