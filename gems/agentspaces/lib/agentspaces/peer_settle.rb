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
  # The settle guarantee's second rule and its evidence (SPEC v0.1.36 §7.4,
  # "Pairing the evidence"; srad/agentspaces-event-loop.md §10.20, the store
  # race), as the reference implementation's ReplicatedSpace keeps it:
  #
  # - Rule two, the winner's side. A holder whose claim the lattice keeps,
  #   and that learns before it completes of the authentic completion of a
  #   holder its claim displaced, made under that holder's live claim, does
  #   not do the work again: it completes the entry under its own claim with
  #   no result (an acknowledgement every replica authenticates), and its take
  #   comes back empty, or its complete raises, writing no result.
  # - The evidence, paired. The lattice keeps one claim per entry, so the
  #   displaced claim and the completion made under it reach the winner in
  #   different frames, in either order, or the claim not at all once the
  #   one frame carrying both is lost. The winner keeps, per entry and
  #   bounded (four of each), the verified claims its claim displaced and the
  #   completions it dropped for want of their claim, and judges each pair
  #   when its second half arrives, from any frame.
  # - The displaced holder's re-offer. A holder that completed an entry with
  #   its own work and then adopts a better claim offers its own claim again:
  #   at once, then whenever a replica still offers the entry present, no
  #   sooner than 1 s, 2 s, 4 s, and so on after the previous offer, at most
  #   six offers, while the claim is live and less than half the drift
  #   ceiling old. A Java winner in a mixed group pairs it with the
  #   completion its anti-entropy brings.
  # - Rule three's count. When both holders did the work, the replica that
  #   holds the better claim counts the displaced holder's authentic
  #   completion once per entry (duplicate_completions).
  # - The winner's targeted rounds (srad/agentspaces-event-loop.md phase 6,
  #   owner decision 4 of 2026-11-23; Java's ReplicatedSpace.displacedPulls).
  #   A displaced holder's completion may have only one source, the holder
  #   itself (the writer drops it, SPEC 11a.4), and this peer pulls only
  #   through its seed, which drops it too when it holds the better claim.
  #   So while its own take of the entry is open, a winner holding displaced
  #   claims sends each displaced holder an anti-entropy round of its own: a
  #   DIGEST of the space's text digest addressed to that holder (relayed by
  #   the seed when the holder is not the seed), which a Java holder answers
  #   with a PULL_RESP carrying its completion. At once, then after 1, 2, 4,
  #   8 and 16 s on the monotonic base, at most DISPLACED_PULL_MAX rounds; a
  #   holder displaced later is asked at once. The line ends when the
  #   completion is noted, this peer completes the entry, its claim no longer
  #   holds or lapsed, or the entry is gone. One more duty on the CSP loop
  #   (:displaced_pull); nothing runs while no line is open.
  #
  # No frame, field or vector changes. One deviation: a re-offer's gossip item
  # id carries the offer's millisecond (c:<entry>:<stamp>:<ms>, the form a
  # claim renewal already uses), since a dial-only peer's one path is its
  # seed, which saw the first offer's id and would forward a repeat of it to
  # nobody.
  class Peer
    # At most this many displaced claims, or unproven completions, per entry.
    DISPLACED_PER_ENTRY = 4
    # At most this many entries in each settle memory; the oldest goes first.
    SETTLE_MEMORY = 1024
    # The offers of one displaced claim, and the first backoff between them.
    REOFFER_MAX = 6
    REOFFER_BACKOFF_MILLIS = 1000
    # At most this many targeted rounds toward the displaced holders of one
    # entry; the first goes at once, the next after REOFFER_BACKOFF_MILLIS,
    # doubling (Java's DISPLACED_PULL_MAX).
    DISPLACED_PULL_MAX = 6

    # Completions made here with this peer's own work whose displaced rival's
    # authentic completion arrived afterwards: both did the work (rule three).
    def duplicate_completions = @state_lock.synchronize { @duplicate_completions }

    # Completions made here under this peer's claim to acknowledge a displaced
    # holder's completion (rule two), each with no result.
    def acknowledged_completions = @state_lock.synchronize { @acknowledged_completions }

    # Offers of a displaced claim of this peer's sent again.
    def displaced_reoffers = @state_lock.synchronize { @reoffers_sent }

    # Targeted anti-entropy rounds this peer opened toward holders its claim
    # displaced (owner decision 4; Java's displacedPullRounds).
    def displaced_pull_rounds = @state_lock.synchronize { @displaced_pull_rounds }

    # The entries whose displaced holders this peer is still pulling.
    def displaced_pulls_open = @state_lock.synchronize { @displaced_pulls.size }

    # Whether this peer's take of the entry is to acknowledge a displaced
    # holder's authentic completion rather than do the work again (rule two).
    def knows_displaced_completion?(entry_id)
      @state_lock.synchronize do
        held = claim_of(entry_id)
        !held.nil? && @outbid_completions[entry_id] == Integer(held["epoch"])
      end
    end

    # Whether the take (holder, epoch) of the entry is to acknowledge a
    # displaced holder's completion: Taken#complete asks before it writes a result.
    def outbid_completion?(entry_id, holder, epoch)
      @state_lock.synchronize do
        held = claim_of(entry_id)
        !held.nil? && held["holder"] == holder && !epoch.nil? && Integer(held["epoch"]) == epoch &&
          @outbid_completions[entry_id] == epoch
      end
    end

    private

    def init_settle
      @displaced_claims = {}
      @unproven_completions = {}
      @outbid_completions = {}
      @completed_here = {}
      @displaced_own = {}
      @displaced_here = {}
      @displaced_pulls = {}
      @space_names = {}
      @duplicate_completions = 0
      @acknowledged_completions = 0
      @reoffers_sent = 0
      @displaced_pull_rounds = 0
    end

    def own_holder?(holder) = holder.to_s.start_with?("#{@identity.peer_id}/")

    # The PeerID of an agent id (peer/agent), or nil.
    def holder_peer(holder)
      peer = holder.to_s.split("/", 2).first
      peer.nil? || peer.empty? ? nil : peer
    end

    # The space name behind a space id, for the spaces this peer has named
    # (a take, a Space, a digest); bounded like the settle memories.
    def note_space_name(space_id, name)
      return if @space_names.nil? # before init_settle

      @state_lock.synchronize { bounded_put(@space_names, space_id, name.to_s) unless @space_names[space_id] == name.to_s }
    end

    def space_name_of(space_id) = @state_lock.synchronize { @space_names[space_id] }

    def bounded_put(map, key, value)
      map.delete(key)
      map[key] = value
      map.shift while map.size > SETTLE_MEMORY
    end

    # After a verified claim merged (fold_claim): held was the claim before,
    # winner the one the lattice keeps. A rival claim this peer's claim kept
    # out is evidence for rule two; a better claim over an entry this peer
    # completed with its own work starts the re-offers of its own claim.
    def settle_after_claim(entry_id, signed, held, winner)
      return if held.nil?

      note_displaced_here(entry_id, winner.equal?(held) || winner == held ? signed : held, winner)
      mine = held["claim"]
      if winner.equal?(held) || winner == held
        return if signed == held || !own_holder?(mine["holder"]) || signed["claim"]["holder"] == mine["holder"]

        pull = @state_lock.synchronize do
          lines = (@displaced_claims[entry_id] ||= [])
          unless lines.include?(signed)
            lines.shift if lines.size >= DISPLACED_PER_ENTRY
            lines << signed
          end
          @displaced_claims.shift while @displaced_claims.size > SETTLE_MEMORY
          arm_displaced_pull(entry_id, signed["claim"])
        end
        @node_loop.wake(:displaced_pull) if pull
        judge_displaced(entry_id)
      elsif own_holder?(mine["holder"]) && winner["claim"]["holder"] != mine["holder"]
        adopt_displaced_own(entry_id, held)
      end
    end

    # Files a targeted round toward the holder of a claim this peer's claim
    # displaced (owner decision 4): the first at once; a holder newly
    # displaced on a line whose rounds already started is asked at once too.
    # Called under @state_lock; returns whether a round is due.
    def arm_displaced_pull(entry_id, displaced)
      peer = holder_peer(displaced["holder"])
      return false if peer.nil? || peer == @identity.peer_id

      local = local_ms
      pull = @displaced_pulls[entry_id]
      if pull.nil?
        pull = { holders: [], rounds: 0, next_local: local, space_id: displaced["spaceId"] }
        bounded_put(@displaced_pulls, entry_id, pull)
      end
      return false if pull[:holders].include?(peer)

      pull[:holders].shift if pull[:holders].size >= DISPLACED_PER_ENTRY
      pull[:holders] << peer
      pull[:next_local] = [pull[:next_local], local].min if pull[:rounds].positive?
      true
    end

    # The :displaced_pull duty: opens the targeted rounds that are due and
    # drops the lines whose take is no longer open here (this peer's agent
    # no longer holds the claim, the claim lapsed, the entry is no longer
    # present, the displaced completion is already noted) or whose rounds
    # are spent. The backoff is a local period on the monotonic base; the
    # claim's expiry is judged on the wall clock its stamps are on. Returns
    # the next round's deadline on the loop's base, or nil.
    def run_displaced_pulls(now)
      wall = now_ms
      local = local_ms
      rounds = []
      next_local = nil
      @state_lock.synchronize do
        @displaced_pulls.delete_if do |entry_id, pull|
          held = claim_of(entry_id)
          state = @states[entry_id]
          open = !held.nil? && own_holder?(held["holder"]) && !state.nil? && Peer.present?(state) &&
                 Integer(held["expiresAtMillis"]) > wall && @outbid_completions[entry_id] != Integer(held["epoch"])
          next true if !open || pull[:rounds] >= DISPLACED_PULL_MAX

          if local >= pull[:next_local]
            space = @space_names[pull[:space_id]]
            pull[:holders].each { |peer| rounds << [peer, space] } unless space.nil?
            pull[:next_local] = local + (REOFFER_BACKOFF_MILLIS << pull[:rounds])
            pull[:rounds] += 1
          end
          next_local = [next_local, pull[:next_local]].compact.min
          false
        end
        rounds.uniq!
        @displaced_pull_rounds += rounds.size
      end
      rounds.each do |peer, space|
        pull_from_displaced(peer, space)
      rescue StandardError => e
        @logger&.debug("agentspaces: a targeted round toward displaced holder #{peer[0, 16]} failed " \
                       "(#{e.class}: #{e.message}); the next one is due on its backoff")
      end
      next_local.nil? ? nil : now + ((next_local - local) / 1000.0)
    end

    # One targeted anti-entropy round: this replica's text digest of the
    # space, addressed to the displaced holder (through the seed when the
    # holder is another member), budgeted only toward a card with wire.ae=2.
    def pull_from_displaced(peer, space)
      digests = { "space:#{space}" => space_digest_or_empty(space) }
      body = if budgeted_partner?(peer) then Wire.digest_body(digests, budget: @pull_budget)
             else Wire.digest_body(digests)
             end
      send_addressed("DIGEST", body, peer)
    end

    # A claim made here that a better claim of another peer displaced, the
    # first one lost per entry, whether or not this peer completed under it
    # (Java's displacedHere): what another member's DIGEST draws (owner
    # decision 1 of 2026-11-23, peer_answer.rb).
    def note_displaced_here(entry_id, lost, kept)
      return if lost.nil? || kept.nil? || lost == kept
      return unless own_holder?(lost["claim"]["holder"]) && !own_holder?(kept["claim"]["holder"])

      @state_lock.synchronize { bounded_put(@displaced_here, entry_id, lost) unless @displaced_here.key?(entry_id) }
    end

    # The displaced claims made here still worth sending, by entry id
    # (Java's pruneDisplacedHere and displacedFor): a line goes once its
    # claim lapsed, its stamp nears the drift ceiling, or the entry was
    # collected; each displaced claim still offered again joins. Nothing
    # else this peer completed is among them. Called under @state_lock.
    def displaced_lines
      wall = now_ms
      @displaced_here.delete_if do |entry_id, signed|
        claim = signed["claim"]
        Integer(claim["expiresAtMillis"]) <= wall || !@states.key?(entry_id) ||
          wall - Wire.hlc_physical(claim["stamp"]) > Certificates::MAX_DRIFT_MILLIS / 2
      end
      lines = @displaced_here.dup
      @displaced_own.each { |entry_id, line| lines[entry_id] ||= line[:claim] }
      lines
    end

    # This peer completed the entry with its own work under held, which a
    # better claim now displaces: offer held again, the first offer at once.
    def adopt_displaced_own(entry_id, held)
      due = @state_lock.synchronize do
        done = @completed_here[entry_id]
        next false unless done && done[0] == Integer(held["claim"]["epoch"]) && !@displaced_own.key?(entry_id)

        bounded_put(@displaced_own, entry_id, { claim: held, space: done[1], offers: 0, next_local: local_ms, due: true })
        true
      end
      @node_loop.wake(:reoffer) if due
    end

    # A completion merge_state dropped because it does not authenticate under
    # the claim this replica holds: while that claim is this peer's, the
    # completion may be a displaced holder's whose claim comes in another frame.
    def remember_unproven(dto, record)
      entry_id = record["entryId"]
      return if entry_id.nil? || !dto["stateSig"].is_a?(String)

      known = @state_lock.synchronize do
        held = claim_of(entry_id)
        next false if held.nil? || !own_holder?(held["holder"]) || held["holder"] == dto["signer"]

        lines = (@unproven_completions[entry_id] ||= [])
        unless lines.any? { |d| d["stateSig"] == dto["stateSig"] }
          lines.shift if lines.size >= DISPLACED_PER_ENTRY
          lines << dto
        end
        @unproven_completions.shift while @unproven_completions.size > SETTLE_MEMORY
        @displaced_claims.key?(entry_id)
      end
      judge_displaced(entry_id) if known
    end

    # Each dropped completion of the entry judged against each claim this
    # peer's claim displaced: the pair authenticates as the delta that first
    # carried both would have.
    def judge_displaced(entry_id)
      claims, states = @state_lock.synchronize do
        [@displaced_claims[entry_id]&.dup, @unproven_completions[entry_id]&.dup]
      end
      return if claims.nil? || states.nil?

      states.each do |dto|
        claims.each do |signed|
          note_outbid_completion(entry_id, signed, dto) if dto["signer"].nil? || signed["claim"]["holder"] == dto["signer"]
        end
      end
    end

    # A state offered present while this peer's displaced claim waits for its
    # next offer: the replica it came from has not heard of the completion.
    def stale_offered(dto)
      return if dto.nil? || dto["completed"] || !Peer.present?(dto)

      entry_id = (dto["record"] || {})["entryId"] || dto["entryId"]
      due = @state_lock.synchronize do
        line = @displaced_own[entry_id]
        next false if line.nil? || local_ms < line[:next_local]

        line[:due] = true
      end
      @node_loop.wake(:reoffer) if due
    end

    # The re-offer duty: each due displaced claim sent again as the claim
    # delta it first travelled in; a line ends when its offers are spent, its
    # claim lapsed or nears the drift ceiling, or the entry was collected.
    #
    # The backoff between offers is a local period on the monotonic base
    # (owner decision 2026-11-23, round 2a): a wall step back neither holds
    # the next offer for the step's length nor does a step forward fire it
    # early. The claim's expiry and age stay judged on the wall clock, which
    # its stamps are on.
    def run_reoffers(_now)
      wall = now_ms
      local = local_ms
      offers = []
      @state_lock.synchronize do
        @displaced_own.delete_if do |entry_id, line|
          claim = line[:claim]["claim"]
          stamped = Wire.hlc_physical(claim["stamp"])
          spent = line[:offers] >= REOFFER_MAX || Integer(claim["expiresAtMillis"]) <= wall ||
                  wall - stamped > Certificates::MAX_DRIFT_MILLIS / 2 || !@states.key?(entry_id)
          next true if spent

          if line[:due] && local >= line[:next_local]
            line[:next_local] = local + (REOFFER_BACKOFF_MILLIS << line[:offers])
            line[:offers] += 1
            line[:due] = false
            offers << [entry_id, line[:claim], line[:space]]
          end
          false
        end
        @reoffers_sent += offers.size
      end
      offers.each do |entry_id, signed, space|
        send_frame("RUMOR", Wire.rumor_body("space:#{space}", "c:#{entry_id}:#{signed['claim']['stamp']}:#{wall}",
                                            Wire::HOPS, Wire.claim_delta(entry_id, signed)))
      end
      nil
    end

    # Judges a completion this replica dropped, against the displaced claim
    # it was made under (ReplicatedSpace.noteOutbidCompletion): while this
    # peer's claim holds the entry present, the completion is noted so the
    # take acknowledges it instead of doing the work; when this peer already
    # completed with its own work, it is the duplicate rule three counts. A
    # revoked holder's completion is no evidence.
    def note_outbid_completion(entry_id, proof, received)
      return unless received["completed"]

      displaced = proof["claim"]
      return unless displaced["entryId"] == entry_id

      duplicate = nil
      dto = received
      @state_lock.synchronize do
        held = claim_of(entry_id)
        state = @states[entry_id]
        now = now_ms
        return if held.nil? || state.nil? || !own_holder?(held["holder"]) || held["holder"] == displaced["holder"]
        return if Integer(displaced["epoch"]) > Integer(held["epoch"])
        return unless Wire.merge_claims(@claims[entry_id], proof) == @claims[entry_id] # the held claim displaces it

        if Peer.present?(state)
          return if Integer(held["expiresAtMillis"]) <= now || Integer(displaced["expiresAtMillis"]) <= now
          return if @outbid_completions[entry_id] == Integer(held["epoch"])

          duplicate = false
        elsif state["completed"] && @completed_here[entry_id]&.first == Integer(held["epoch"])
          duplicate = true
        else
          return
        end
        dto = received.merge("record" => state["record"]) if dto["record"].nil?
      end
      record = dto["record"] || {}
      certificate = proof["holderCertificate"] || {}
      return if @revocations.refuses?(displaced["holder"], certificate["agentPublicKey"], signing_ms(dto, nil))
      return unless record["spaceId"] == displaced["spaceId"] && Wire.verify_claim_proof(proof)
      return unless verify_state(dto, record, proof)

      counted = @state_lock.synchronize do
        held = claim_of(entry_id)
        next false if held.nil? || Integer(held["epoch"]) < Integer(displaced["epoch"])

        if duplicate
          next false unless @completed_here[entry_id]&.first == Integer(held["epoch"])

          @completed_here.delete(entry_id)
          @duplicate_completions += 1
          true
        else
          bounded_put(@outbid_completions, entry_id, Integer(held["epoch"])) if Peer.present?(@states[entry_id] || {})
          false
        end
      end
      return unless counted

      @logger&.info("agentspaces: entry #{entry_id} was completed twice: here, and by #{displaced['holder']}, whose " \
                    "claim lost the race but heard of the winner later than the settle window (SPEC 7.4); the " \
                    "shared state keeps one completion")
    rescue ArgumentError, TypeError, KeyError
      nil
    end

    # Records a completion: with this peer's own work (a later displaced
    # completion is then a duplicate), or as the acknowledgement of one.
    def note_completed(entry_id, epoch, space, acknowledgement)
      @state_lock.synchronize do
        @outbid_completions.delete(entry_id)
        if acknowledgement
          @acknowledged_completions += 1
        elsif epoch
          bounded_put(@completed_here, entry_id, [epoch, space.to_s])
        end
      end
    end

    # Whether completing (holder, epoch) now acknowledges a displaced
    # holder's completion: the line is noted for that exact claim.
    def acknowledging?(entry_id, holder, epoch)
      held = claim_of(entry_id)
      return false if held.nil? || (holder && held["holder"] != holder)

      epoch ||= Integer(held["epoch"])
      @state_lock.synchronize { @outbid_completions[entry_id] == epoch && Integer(held["epoch"]) == epoch }
    end

    # Entries collected past their horizon take their settle memories along.
    def forget_settle(entry_ids)
      @state_lock.synchronize do
        entry_ids.each do |entry_id|
          [@displaced_claims, @unproven_completions, @outbid_completions, @completed_here,
           @displaced_own, @displaced_here, @displaced_pulls].each { |map| map.delete(entry_id) }
        end
      end
    end
  end
end
