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
  # Replication by entry as it binds a Ruby peer (SPEC v0.1.35 7.2, 7.3 and
  # annex I.6; srad/replication-by-entry.md RE-L-03), kept apart from peer.rb
  # so the replica's bookkeeping reads in one place:
  #
  # - the collection horizons: the lapse horizon, the legacy and per-entry
  #   rules for a withdrawal with the drift floor, the per-entry rule read
  #   from the membership view with its hysteresis (the view's half) and per
  #   withdrawal from its writers (the writer's half), the sweep that collects
  #   past the horizon, and the door that refuses a state re-offered past it;
  # - the budgeted get-space toward a partner whose card carries wire.ae=2,
  #   continued with this replica's text digest while the answer's remainder
  #   says states were left out and the answer brought something new;
  # - the acknowledgements a replica that sends space digests writes for the
  #   states it refused at its door.
  #
  # A Ruby peer runs no trie audit, so it never advertises wire.ae=2, never
  # sends tree or ids, and answers its link holder's text digests of spaces,
  # and another member's only for its displaced claims and completions
  # (peer_answer.rb); every other DIGEST it receives is ignored.
  class Peer
    # The default budget of a get-space toward a wire.ae=2 partner (SPEC annex I.6, The budget).
    DEFAULT_PULL_BUDGET = 1_048_576
    # The audit hint a partner's card carries when it answers a budget.
    AUDIT_HINT = "wire.ae"
    # The most continuations one budgeted pull sends before it waits for the next
    # pull: at the default budget, about 4 GiB of states.
    MAX_PULL_CONTINUATIONS = 4096
    # A text digest above this many bytes is not sent: the pull falls back to the
    # empty digest, whose budgeted answer still arrives newest first.
    MAX_TEXT_DIGEST_BYTES = 4 * 1024 * 1024
    # Door acknowledgements kept per space, the least recently refused forgotten
    # first (rule R7 of SPEC 9.2).
    ACK_CAP = 8192
    # How long a door acknowledgement of a collected tombstone outlives the last
    # refusal at least (SPEC 7.3; the reference implementation's five minutes).
    COLLECTED_ACK_HOLD_MILLIS = 5 * 60 * 1000
    # A member heard from this recently counts in the view even with no live
    # card, and then as lacking the hint (SPEC 7.3: a member whose card the
    # replica has not received counts as lacking it). The card's own TTL.
    VIEW_HEARD_MILLIS = 10 * 60 * 1000
    # How long a budgeted pull waits for its answer before a new pull of the
    # same space asks again: a pull in flight is not doubled, and a lost
    # answer is repaired by the next pull after this wait.
    PULL_ANSWER_WAIT_MILLIS = 5000
    # One gossip round when the founding names none: Java's default period.
    DEFAULT_ROUND_MILLIS = 1000

    # The budget this peer asks for in a get-space toward a wire.ae=2 partner,
    # in bytes, or nil to keep the unbudgeted get-space toward every partner.
    attr_reader :pull_budget, :horizon_setting

    # Whether the first renewal of each space that asked for less than its lease
    # had left is logged at info (RE-H-01, Java's node setting
    # agentspaces.space.renew-shortening-log); true by default. renewals_kept
    # counts every such renewal either way.
    attr_accessor :renew_shortening_log

    def pull_budget=(bytes)
      raise ArgumentError, "a pull budget is a positive number of bytes, or nil: #{bytes.inspect}" \
        unless bytes.nil? || (bytes.is_a?(Integer) && bytes.positive?)

      @pull_budget = bytes
    end

    # Entries collected past their horizon since the peer started.
    def states_collected = @state_lock.synchronize { @states_collected }

    # States the door refused because they were past their collection horizon.
    def states_refused_collected = @state_lock.synchronize { @states_refused_collected }

    # Continuations of budgeted get-spaces sent, each with this replica's text digest.
    def pull_continuations = @state_lock.synchronize { @pull_continuations }

    # Budgeted pulls that ended with states still left out, because an answer
    # brought nothing new or the continuation bound was reached; the next pull
    # starts again from this replica's digest.
    def pulls_stalled = @state_lock.synchronize { @pulls_stalled }

    # Renewals that left the lease as it was, because the extension ended before
    # the current expiry (SPEC 7.2: a renewal never shortens).
    def renewals_kept = @state_lock.synchronize { @renewals_kept }

    # The longest lease observed in a space, capped at a day, the horizon's measure.
    def max_lease_millis(space) = @state_lock.synchronize { @max_leases.fetch(space_id_of(space), 0) }

    # Where a space stands on the per-entry horizon: :legacy, :waiting,
    # :settling or :per_entry, as last judged.
    def horizon_mode(space) = horizon_tracker(space)&.state || :legacy

    # The Horizon::Mode of a space, for its engagement counts, or nil before its first judgement.
    def horizon_tracker(space)
      sid = space_id_of(space)
      @state_lock.synchronize { @horizon_modes.key?(sid) ? @horizon_modes[sid] : nil }
    end

    # The text digest of one space by name, as this replica would send it.
    def text_digest(space)
      sid = space_id_of(space)
      summary = {}
      @state_lock.synchronize do
        @states.each { |id, dto| summary["e:#{id}"] = TextDigest.state_hash(dto) if (dto["record"] || {})["spaceId"] == sid }
        @claims.each do |id, signed|
          claim = signed["claim"]
          summary["c:#{id}"] = TextDigest.claim_hash(claim) if claim["spaceId"] == sid
        end
      end
      TextDigest.digest(summary, acknowledged_lines(sid, now_ms))
    end

    # Whether the payload of a state is here without a fetch: inline, or a block already held.
    def payload_held?(dto)
      record = dto["record"] || {}
      ref = record["payloadRef"]
      !record["payload"].nil? || !(ref.is_a?(String) && !ref.empty?) || @blocks.key?(ref)
    end

    # Collects every entry past its collection horizon (SPEC 7.3) and returns
    # the collected ids: the state, its claim, any recordless state pending for
    # it, and a block no remaining entry names. Watches forget the entries too.
    # The connected peer's loop calls it at the earliest horizon (next_collect_ms).
    def collect_garbage(now = now_ms)
      hinted = view_hinted?(now)
      rules = {}
      collected = []
      @state_lock.synchronize do
        @states.each do |entry_id, dto|
          sid = (dto["record"] || {})["spaceId"]
          rules[sid] ||= judge_horizon(sid, hinted, now)
          collected << entry_id if collectable_under?(dto, now, sid, rules[sid])
        end
        next if collected.empty?

        refs = collected.filter_map { |entry_id| @states.delete(entry_id).dig("record", "payloadRef") }
        collected.each do |entry_id|
          @signed_states.delete(entry_id)
          @claims.delete(entry_id)
          @pending_states.delete(entry_id)
        end
        unless refs.empty?
          held = @states.each_value.filter_map { |dto| dto.dig("record", "payloadRef") }.to_set
          refs.each { |ref| @blocks.delete(ref) unless held.include?(ref) }
        end
        @states_collected += collected.size
      end
      forget_settle(collected) unless collected.empty?
      notify_observers { |o| o.states_collected(collected) if o.respond_to?(:states_collected) } unless collected.empty?
      collected
    end

    private

    def init_replication(horizon)
      unless [Horizon::PER_ENTRY, Horizon::LEGACY].include?(horizon)
        raise ArgumentError, "horizon is :per_entry or :legacy: #{horizon.inspect}"
      end

      @horizon_setting = horizon
      # Advertised once the renewal rule of SPEC 7.2 is enforced here, which it is:
      # issuer only, present and unexpired, never shorter (RE-L-03).
      @wire_hints[Horizon::HINT] = "1" if horizon == Horizon::PER_ENTRY
      @horizon_modes = Hash.new { |h, sid| h[sid] = Horizon::Mode.new }
      @max_leases = {}
      @heard_at = {}
      @member_cards = {}
      @member_stays = {}
      @acks = {}
      @pull_budget = DEFAULT_PULL_BUDGET
      @budgeted_pulls = {}
      @states_collected = 0
      @states_refused_collected = 0
      @pull_continuations = 0
      @pulls_stalled = 0
      @renewals_kept = 0
      @renew_shortening_log = true
      @renew_shortening_logged = Set.new
      @changes = 0
    end

    def space_id_of(space)
      Derive.space_id_local("#{@group}/#{space}").tap { |sid| note_space_name(sid, space) }
    end

    # Counts a renewal that left the lease as it was, and logs the first one of a
    # space that asked for less than the lease had left (RE-H-01), as Java's
    # ReplicatedSpace.noteShortening logs it: a caller that still asks for a
    # shorter lease learns once that it kept the longer one, without a line per call.
    def note_renewal_kept(space, entry_id, lease, current, requested)
      first = @state_lock.synchronize do
        @renewals_kept += 1
        requested < current && @renew_shortening_log && @renew_shortening_logged.add?(space.to_s)
      end
      return unless first

      @logger&.info("agentspaces: space #{space}: the #{lease} lease of entry #{entry_id} was renewed for " \
                    "#{current - requested} ms less than it had left, and kept the longer lease: a renewal " \
                    "never shortens a lease (SPEC 7.2). Cancel and write again for a shorter one. Logged once " \
                    "for this space; renewals_kept counts every such renewal.")
    end

    # Records a lease this replica observed in a space, for the horizon (Java's observeLease).
    def observe_lease(space_id, lease_millis)
      return if space_id.nil? || !lease_millis.is_a?(Integer) || lease_millis <= 0

      capped = [lease_millis, Horizon::MAX_TRACKED_LEASE_MILLIS].min
      @state_lock.synchronize { @max_leases[space_id] = capped if capped > @max_leases.fetch(space_id, 0) }
    end

    # The lease a state's register spans: its expiry less its lease stamp's physical time.
    def observe_state_lease(space_id, dto)
      expires = Peer.lease_of(dto)["expiresAtMillis"]
      observe_lease(space_id, Integer(expires) - Wire.hlc_physical(dto["leaseStamp"])) if expires.is_a?(Integer)
    rescue ArgumentError, TypeError
      nil
    end

    # A frame from a member: it is in the view while heard from lately.
    # On the monotonic base (local_ms): a wall step neither ends the window
    # nor holds a silent member in it (SPEC 9.5).
    def heard_from(member) = @state_lock.synchronize { @heard_at[member] = local_ms }

    # Remembers a member's card for the view: when it lapses, and whether it
    # carries the hint. A hinted card that follows no live hinted card starts
    # the member's stay, from which the writer's half counts.
    def note_member_card(ad)
      member = ad["issuer"]
      expires = Instants.parse_millis(ad["issued"]) + Instants.parse_duration_millis(ad["ttl"])
      hinted = (ad["resourceHints"] || {})[Horizon::HINT] == "1"
      now = now_ms
      joined = @state_lock.synchronize do
        previous = @member_cards[member]
        @member_cards[member] = [expires, hinted]
        if !hinted
          @member_stays.delete(member)
        elsif previous.nil? || !previous[1] || previous[0] <= now
          @member_stays[member] = now
        end
        previous.nil? || previous[0] <= now
      end
      # A member new to the view may grow the group past the probe cycle,
      # which shortens the keepalive (re_lease_period): the keepalive is
      # asked now, not at the deadline it set for the smaller group.
      @node_loop&.wake(:self_ad) if joined
    rescue ArgumentError, TypeError
      nil
    end

    # Whether this peer advertises the hint and every member of its view does
    # too. The view is every member with a live card or heard from lately; a
    # member whose card is missing, lapsed or unhinted lacks the hint.
    def view_hinted?(now)
      return false unless @horizon_setting == Horizon::PER_ENTRY

      local = local_ms
      @state_lock.synchronize do
        @members.keys.all? do |member|
          card = @member_cards[member]
          live = !card.nil? && card[0] > now
          # A member the re-probe after a wake waits on is in view, and lacks
          # the hint until its card comes back (owner decision 3, peer_loop.rb).
          in_view = live || @heard_at.fetch(member, -Float::INFINITY) > local - VIEW_HEARD_MILLIS ||
                    reprobing?(member, now, local)
          !in_view || (live && card[1])
        end
      end
    end

    # The rule a space may apply now, moving its mode (the view's half).
    def judge_horizon(space_id, hinted, now)
      @horizon_modes[space_id].judge(hinted, now, round_ms: round_millis, max_lease: @max_leases.fetch(space_id, 0))
    end

    def round_millis
      period = @founding&.dig("advertisement", "gossip", "period")
      period ? [Instants.parse_duration_millis(period), 1].max : DEFAULT_ROUND_MILLIS
    rescue ArgumentError, TypeError
      DEFAULT_ROUND_MILLIS
    end

    # Whether every node that wrote a withdrawn state is one this replica
    # vouches for (the writer's half of SPEC 7.3): itself, or a hinted member
    # in view whose current stay has lasted one maximum lease plus the grace,
    # so whatever it renewed before it came into sight has lapsed and passed
    # its own lapse horizon. The writer is the replica of each add dot, set by
    # the write and never changed.
    def writers_vouched?(dto, now, max_lease)
      adds = Array(dto["adds"])
      return false if adds.empty?

      settle = [max_lease, 0].max + Horizon::LAPSED_GRACE_MILLIS
      adds.all? do |dot|
        writer = dot["replica"]
        next true if writer == @identity.peer_id

        card = @member_cards[writer]
        unless card && card[0] > now && card[1]
          @member_stays.delete(writer)
          next false
        end
        since = (@member_stays[writer] ||= now)
        since + settle <= now
      end
    end

    # Whether this replica collects a state now under the mode it judged: by the
    # state's rule, except that a withdrawal the per-entry mode cannot vouch
    # for keeps the later of the legacy horizon and the per-entry one, so a
    # writer leaving the view never brings a withdrawal's horizon closer.
    def collectable_under?(dto, now, space_id, mode)
      max_lease = @max_leases.fetch(space_id, 0)
      rule = mode
      withdrawal = !dto["completed"] && !Peer.present?(dto)
      rule = Horizon::LEGACY if mode == Horizon::PER_ENTRY && withdrawal && !writers_vouched?(dto, now, max_lease)
      by_rule = Horizon.collectable?(dto, now, max_lease, rule)
      return by_rule unless mode == Horizon::PER_ENTRY && rule == Horizon::LEGACY

      by_rule && Horizon.collectable?(dto, now, max_lease, Horizon::PER_ENTRY)
    end

    # The door of SPEC 7.3: a state offered past its collection horizon, by
    # the same rule and clock as the sweep, is refused, so a collected
    # tombstone never comes back from a lagging partner. Returns whether it refused.
    def refused_at_door?(dto, record)
      sid = record["spaceId"]
      observe_state_lease(sid, dto)
      now = now_ms
      hinted = view_hinted?(now)
      refuse = @state_lock.synchronize { collectable_under?(dto, now, sid, judge_horizon(sid, hinted, now)) }
      return false unless refuse

      entry_id = record["entryId"]
      held = @state_lock.synchronize do
        @states_refused_collected += 1
        @states.key?(entry_id)
      end
      # Acknowledged only for an entry this replica holds no state for (SPEC 7.3).
      unless held
        horizon = Horizon.collection_horizon(dto, @max_leases.fetch(sid, 0), Horizon::LEGACY)
        acknowledge(sid, TextDigest.state_line(entry_id, dto), [now + COLLECTED_ACK_HOLD_MILLIS, horizon].max)
      end
      true
    end

    # Keeps an a:<line> for a state refused after its signatures verified, so a
    # partner answering this replica's digest stops offering it. forget_at nil
    # keeps it until the cap lets it go.
    def acknowledge(space_id, line, forget_at = nil)
      return if space_id.nil?

      @state_lock.synchronize do
        lines = (@acks[space_id] ||= {})
        lines.delete(line)
        lines[line] = forget_at
        lines.shift while lines.size > ACK_CAP
      end
    end

    def acknowledged_lines(space_id, now)
      @state_lock.synchronize do
        lines = @acks[space_id]
        next [] if lines.nil?

        lines.delete_if { |_, forget_at| !forget_at.nil? && forget_at <= now }
        lines.keys
      end
    end

    # A state merged here changed what this replica holds: progress for a budgeted pull.
    def note_change = @state_lock.synchronize { @changes += 1 }

    def change_count = @state_lock.synchronize { @changes }

    # The member that answers this peer's unaddressed DIGEST: the remote end of its connection.
    def pull_partner
      @seed_peer || @channel&.attested_peer || @session&.remote
    end

    # Whether the partner's (by default the pull partner's) current card
    # carries wire.ae=2, so a budget may go toward it (SPEC annex I.6: never
    # toward a card without the hint).
    def budgeted_partner?(partner = pull_partner)
      return false if @pull_budget.nil?
      return false if partner.nil?

      ad = @members[partner]
      card = @member_cards[partner]
      !ad.nil? && !card.nil? && card[0] > now_ms && (ad["resourceHints"] || {})[AUDIT_HINT] == "2"
    end

    # A budgeted pull of one space: the revocation streams unbudgeted first,
    # so the registry is in before the records it judges, then the space under
    # the budget, by this replica's text digest when it holds any of the space
    # and by the empty digest otherwise. A pull whose request is still in
    # flight on this connection, sent less than PULL_ANSWER_WAIT_MILLIS ago,
    # is not doubled; past that wait its answer counts as lost and the pull
    # starts again. Returns whether it sent.
    def pull_space_budgeted(space)
      stream = "space:#{space}"
      now = now_ms
      fresh = @state_lock.synchronize do
        open = @budgeted_pulls[stream]
        next false if open && open[:channel].equal?(@channel) && now - open[:sent_at] < PULL_ANSWER_WAIT_MILLIS

        @budgeted_pulls[stream] = { sent: 0, sent_at: now, channel: @channel }
        true
      end
      return false unless fresh

      send_frame("DIGEST", Wire.digest_body(Revocation::STREAMS.to_h { |s| [s, "".b] }))
      send_frame("DIGEST", Wire.digest_body({ stream => space_digest_or_empty(space) }, budget: @pull_budget))
      true
    end

    def space_digest_or_empty(space)
      digest = text_digest(space)
      digest.bytesize > MAX_TEXT_DIGEST_BYTES ? "".b : digest
    end

    # After a PULL_RESP: a budgeted pull whose answer left states out
    # (remainder above 0) asks again at once with this replica's text digest
    # under the same budget, since the empty digest would draw the same newest
    # states again. It stops when nothing is left, when an answer brought
    # nothing new (everything in it refused, deferred or already held), or at
    # the continuation bound; the next pull starts again from the digest.
    def continue_budgeted_pulls(remainder, progressed)
      return if remainder.nil?

      remainder.each do |stream, left|
        next unless stream.start_with?("space:")

        open = @state_lock.synchronize { @budgeted_pulls[stream] }
        next if open.nil?

        if left.zero? || !budgeted_partner?
          @state_lock.synchronize { @budgeted_pulls.delete(stream) }
        elsif !progressed || open[:sent] >= MAX_PULL_CONTINUATIONS
          @state_lock.synchronize do
            @budgeted_pulls.delete(stream)
            @pulls_stalled += 1
          end
        else
          @state_lock.synchronize do
            @budgeted_pulls[stream] = open.merge(sent: open[:sent] + 1, sent_at: now_ms)
            @pull_continuations += 1
          end
          space = stream.delete_prefix("space:")
          send_frame("DIGEST", Wire.digest_body({ stream => space_digest_or_empty(space) }, budget: @pull_budget))
        end
      end
    end

    # The earliest wall instant (epoch ms) at which the collection has work:
    # the soonest collection horizon of a held state under the rule its
    # space's mode applies now (an unvouched withdrawal under the per-entry
    # mode by the later of the two rules, and by the per-entry one once its
    # writers' stays vouch for it), or the next judgement the horizon mode
    # waits on to engage or settle; nil when nothing is held.
    def next_collect_ms(now)
      hinted = view_hinted?(now)
      @state_lock.synchronize do
        return nil if @states.empty?

        modes = {}
        times = []
        @states.each_value do |dto|
          sid = (dto["record"] || {})["spaceId"]
          mode = (modes[sid] ||= @horizon_modes.key?(sid) ? @horizon_modes[sid].state : :legacy)
          times << horizon_due(dto, now, sid, mode == :per_entry ? Horizon::PER_ENTRY : Horizon::LEGACY)
        end
        modes.each_key do |sid|
          next unless hinted && @horizon_modes.key?(sid)

          wait = @horizon_modes[sid].next_judgement_ms(round_millis, @max_leases.fetch(sid, 0))
          times << wait unless wait.nil?
        end
        times.compact.min
      end
    end

    # A state merged here: the collection is asked when its horizon is earlier
    # than the one the collection waits for.
    def collect_hint(dto)
      return unless @dialled

      sid = (dto["record"] || {})["spaceId"]
      at = Horizon.collection_horizon(dto, @state_lock.synchronize { @max_leases.fetch(sid, 0) }, Horizon::PER_ENTRY)
      earlier = @state_lock.synchronize do
        next false unless @collect_due_ms.nil? || at < @collect_due_ms

        @collect_due_ms = at
        true
      end
      @node_loop.wake(:collect) if earlier
    rescue ArgumentError, TypeError
      nil
    end

    # Under the lock: one state's horizon under the mode's rule, as
    # collectable_under? judges it.
    def horizon_due(dto, now, sid, mode)
      max_lease = @max_leases.fetch(sid, 0)
      withdrawal = !dto["completed"] && !Peer.present?(dto)
      unless mode == Horizon::PER_ENTRY && withdrawal
        return Horizon.collection_horizon(dto, max_lease, mode)
      end

      per_entry = Horizon.collection_horizon(dto, max_lease, Horizon::PER_ENTRY)
      legacy = Horizon.collection_horizon(dto, max_lease, Horizon::LEGACY)
      vouched = writers_vouch_at(dto, now, max_lease)
      vouched.nil? ? [legacy, per_entry].max : [[per_entry, vouched].max, [legacy, per_entry].max].min
    rescue ArgumentError, TypeError
      nil
    end

    # Under the lock: when every writer of a withdrawal will vouch for it
    # (writers_vouched?), if each has a live hinted card now; nil otherwise.
    def writers_vouch_at(dto, now, max_lease)
      settle = [max_lease, 0].max + Horizon::LAPSED_GRACE_MILLIS
      Array(dto["adds"]).map do |dot|
        writer = dot["replica"]
        next now if writer == @identity.peer_id

        card = @member_cards[writer]
        return nil unless card && card[0] > now && card[1]

        @member_stays.fetch(writer, now) + settle
      end.max
    end
  end
end
