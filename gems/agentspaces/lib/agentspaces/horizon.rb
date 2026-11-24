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
  # The collection horizons and the renewal rule of SPEC 7.2 and 7.3
  # (v0.1.35; srad/replication-by-entry.md RE-H-02 to RE-H-04, RE-L-03), as
  # Java's SpaceStateCrdt and ReplicatedSpace compute them. The golden
  # entries renew_clamp_cases, lapse_horizon_cases and horizon_mode_cases pin
  # every number here.
  module Horizon
    # The hint a member advertises when every writer behind it renews by the
    # rule of SPEC 7.2 and renews each identity from one node at a time.
    HINT = "wire.horizon"
    # Java's HorizonMode names, as horizon_mode reports them.
    LEGACY = :legacy
    PER_ENTRY = :per_entry
    # The grace a lapse keeps past its expiry, at most (SPEC 7.3). A lapse is
    # judged from the lease register every replica holds alike, so it needs a
    # grace past skew and never two maximum leases.
    LAPSED_GRACE_MILLIS = 5 * 60 * 1000
    # The least a withdrawn entry keeps past its expiry under either rule: the
    # clock drift ceiling of SPEC 11 (owner decision 22, 2026-11-15). Any two
    # conforming clocks are within it, so once one replica collects at
    # L + MAX_DRIFT every other clock reads L or later, and every copy of the
    # entry, whose expiry is at most L, has lapsed wherever it arrives.
    WITHDRAWN_DRIFT_FLOOR_MILLIS = 10 * 60 * 1000
    # The ceiling on a lease the horizon reckons with (Java's MAX_TRACKED_LEASE_MILLIS).
    MAX_TRACKED_LEASE_MILLIS = 24 * 60 * 60 * 1000
    # Fully hinted rounds the view must hold before the per-entry rule engages
    # (Java's DEFAULT_HORIZON_ENGAGE_ROUNDS), so a card that flaps does not move
    # the mode each time it does.
    ENGAGE_ROUNDS = 3

    module_function

    # The expiry of a renewal under SPEC 7.2: at least extension past now, and
    # never before the current expiry.
    def renewed_expiry(current, now, extension) = [Integer(current), Integer(now) + Integer(extension)].max

    # The write lease's expiry a state carries (its lease register).
    def expiry_of(dto) = Integer(Peer.lease_of(dto).fetch("expiresAtMillis", 0))

    # Whether the removes of a state cover every add: a withdrawal, even when completed too.
    def withdrawn_all?(dto)
      removed = Array(dto["removes"]).to_set { |dot| [dot["replica"], dot["counter"]] }
      Array(dto["adds"]).all? { |dot| removed.include?([dot["replica"], dot["counter"]]) }
    end

    # How long a state is kept past its own lease expiry (SpaceStateCrdt.keepMillis):
    # - completed: 2 x maxLease under both rules, and when it is also withdrawn
    #   never less than the drift floor, so it never goes before a copy that is
    #   withdrawn alone;
    # - present (a lapse): min(2 x maxLease, 5 min) under both rules;
    # - withdrawn: 2 x maxLease under the legacy rule, 5 minutes under the
    #   per-entry rule, and never less than the drift floor under either.
    def keep_millis(dto, max_lease, rule)
      twice = 2 * [Integer(max_lease), 0].max
      if dto["completed"]
        return withdrawn_all?(dto) ? [twice, WITHDRAWN_DRIFT_FLOOR_MILLIS].max : twice
      end
      return [twice, LAPSED_GRACE_MILLIS].min if Peer.present?(dto)

      [rule == PER_ENTRY ? LAPSED_GRACE_MILLIS : twice, WITHDRAWN_DRIFT_FLOOR_MILLIS].max
    end

    # The instant from which the state is collectable under rule.
    def collection_horizon(dto, max_lease, rule = LEGACY) = expiry_of(dto) + keep_millis(dto, max_lease, rule)

    # Whether the state is a collectable tombstone at now under rule: no
    # longer live, and its horizon passed. A present entry is never
    # collectable before its lease lapses.
    def collectable?(dto, now, max_lease, rule = LEGACY)
      expiry = expiry_of(dto)
      return false if Peer.present?(dto) && expiry > now

      expiry + keep_millis(dto, max_lease, rule) <= now
    end

    # Where one space stands on the per-entry horizon (Java's
    # ReplicatedSpace.HorizonMode): :legacy, :waiting (the view is fully
    # hinted, not yet for ENGAGE_ROUNDS rounds), :settling (engaged, waiting
    # one maximum lease plus the grace, so that every copy a member renewed
    # while its card lacked the hint has lapsed and passed its own lapse
    # horizon), and :per_entry. A member without the hint in view disengages
    # it at once (SPEC 7.3: MUST stop at the first judgement whose view holds
    # one).
    class Mode
      attr_reader :engagements, :settlements, :disengagements

      def initialize
        @lock = Mutex.new
        @state = :legacy
        @streak = 0
        @counted_at = nil
        @engaged_at = nil
        @engagements = 0
        @settlements = 0
        @disengagements = 0
      end

      def state = @lock.synchronize { @state }

      # Judges the rule at now and moves the mode. hinted: this peer advertises
      # the hint and every member of its view does too. round_ms: one gossip
      # period of the group. Returns LEGACY or PER_ENTRY.
      def judge(hinted, now, round_ms:, max_lease:, rounds: ENGAGE_ROUNDS)
        @lock.synchronize do
          unless hinted
            @disengagements += 1 if %i[settling per_entry].include?(@state)
            @state = :legacy
            @streak = 0
            @counted_at = nil
            return LEGACY
          end
          count_round(now, [round_ms, 1].max, rounds) if %i[legacy waiting].include?(@state)
          settle(now, max_lease) if @state == :settling
          @state == :per_entry ? PER_ENTRY : LEGACY
        end
      end

      # When the mode next needs a judgement to move on (epoch ms): the next
      # round of the engagement count, or the end of the settling wait; nil
      # when it waits on nothing but the view. 0 for a first judgement.
      def next_judgement_ms(round_ms, max_lease)
        @lock.synchronize do
          case @state
          when :legacy, :waiting then @counted_at.nil? ? 0 : @counted_at + [round_ms, 1].max
          when :settling then @engaged_at + [Integer(max_lease), 0].max + LAPSED_GRACE_MILLIS
          end
        end
      end

      private

      def count_round(now, round_ms, rounds)
        if @counted_at.nil? || now < @counted_at
          @counted_at = now # the first hinted judgement, or a clock that stepped back
        elsif now - @counted_at >= round_ms
          @streak += 1
          @counted_at = now
        end
        if @streak >= rounds
          @engaged_at = now
          @state = :settling
          @engagements += 1
        else
          @state = :waiting
        end
      end

      def settle(now, max_lease)
        wait = [Integer(max_lease), 0].max + LAPSED_GRACE_MILLIS
        if now < @engaged_at
          @engaged_at = now # the clock stepped back: the wait counts from here
        elsif now - @engaged_at >= wait
          @state = :per_entry
          @settlements += 1
        end
      end
    end
  end
end
