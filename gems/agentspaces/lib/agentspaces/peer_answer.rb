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
  # The dial-only peer answers its seed's DIGEST (owner decision 2026-11-23;
  # .parity-wt/PARITY-ruby.md, Round 2a). The seed's anti-entropy round
  # toward this peer sends its text digest of each space (SPEC 5.3); this
  # peer answers with one PULL_RESP holding every signed state and claim it
  # holds of those spaces that the seed's digest does not list (nor
  # acknowledge with an a: line), as Java's ReplicatedSpace.deltaFor and
  # GossipBus.answerPull build it. A rumor of this peer's own that was lost
  # on its only link is so repaired at the seed's next round, rather than
  # never.
  #
  # Bounds and limits:
  # - The member this peer holds its link to is answered in full, for a
  #   DIGEST read off that link (not one relayed).
  # - Any other member's DIGEST, relayed by the seed or not (owner decision
  #   1 of 2026-11-23), is answered as the core answers it: only for the
  #   spaces where this peer holds a claim made here that a better claim of
  #   another peer displaced, with or without its completion, with only those
  #   entries: the displaced claim, and the entry's state (which carries the
  #   completion) where the asker's digest lacks them. Another completion of
  #   this peer's own work draws nothing.
  #   That is the winner's targeted round toward a displaced holder
  #   (peer_settle.rb): a displaced holder's completion may have only one
  #   source, this peer, since the writer and a seed holding the better
  #   claim drop it (SPEC 11a.4). Such answers are paced per asker by the
  #   Rust peer's answer bucket, a burst of RELAYED_ANSWER_BURST and
  #   RELAYED_ANSWER_RATE a second on the monotonic base; past it the DIGEST
  #   is dropped and counted (relayed_answers_paced). A DIGEST that would bring
  #   nothing is ignored and counted, as before, so no other member can make
  #   this peer upload what the seed already serves.
  # - Only text digests (digests) of space streams are answered. This peer
  #   advertises neither wire.hashes nor wire.ae=2, so no member sends it
  #   hashes, want, tree or ids (the core also reads hashes from a member
  #   other than its seed, answering with want; a member never sends them
  #   here); a body carrying an annex I.6 field
  #   this reader does not name is undecodable and counted as malformed.
  # - A relay cannot sign a state it did not author, so the answer forwards
  #   the most advanced signed state seen for each entry (Java's
  #   recordSignedState and advances), not the joined state.
  # - Unbudgeted, the answer stops at MAX_TEXT_DIGEST_BYTES of delta, the
  #   rest going at the next round, and carries no remainder (a partner
  #   without wire.ae=2 drops a PULL_RESP that carries one). A body with a
  #   budget is answered within it, in Java's offer order, with remainder.
  #
  # Existing frames and records only: DIGEST in, PULL_RESP (Bodies.PullResp
  # over SpaceWire.SyncDelta) out.
  class Peer
    # Bytes of a SyncDelta beside its items, and of a PULL_RESP beside its
    # deltas (Java's DELTA_BASE and PULL_RESP_BASE).
    SYNC_DELTA_BASE = 32
    PULL_RESP_BASE = 32
    # The most an asker's budget draws (Java's TrieAudit.BUDGET_CEILING).
    ANSWER_BUDGET_CEILING = 4 << 20
    # Another member's DIGESTs answered for displaced entries, per asker: a
    # burst and a rate a second (the Rust peer's ANSWER_BURST, ANSWER_RATE).
    RELAYED_ANSWER_BURST = 16
    RELAYED_ANSWER_RATE = 4
    # At most this many askers' buckets are kept; the oldest goes first.
    RELAYED_ANSWER_ASKERS = 1024

    # DIGESTs from the link holder this peer answered, and the PULL_RESPs it sent for them.
    def digests_answered = @state_lock.synchronize { @digests_answered }

    def pull_resps_sent = @state_lock.synchronize { @pull_resps_sent }

    # Other members' DIGESTs this peer answered for its displaced claims made
    # here (owner decision 1 of 2026-11-23), and those dropped past
    # the asker's pace.
    def displaced_digest_answers = @state_lock.synchronize { @displaced_digest_answers }

    def relayed_answers_paced = @state_lock.synchronize { @relayed_answers_paced }

    # The signed state this peer would forward for an entry, or nil.
    def signed_state(entry_id) = @state_lock.synchronize { @signed_states[entry_id] }

    # The SyncDelta bytes of a list of signed states and a map of signed claims by entry id.
    def self.sync_delta_bytes(states, claims)
      CBOR.dump({ "states" => states, "claims" => CBOR.canonical_map(claims) })
    end

    # The PULL_RESP body of per-stream delta bytes, with remainder only when given.
    def self.pull_resp_body(deltas, remainder = nil)
      body = { "deltas" => CBOR.canonical_map(deltas) }
      body["remainder"] = CBOR.canonical_map(remainder) unless remainder.nil?
      CBOR.dump(body)
    end

    private

    def init_answers
      @signed_states = {}
      @digests_answered = 0
      @pull_resps_sent = 0
      @displaced_digest_answers = 0
      @relayed_answers_paced = 0
      @answer_buckets = {}
    end

    # Remembers the most advanced signed state seen for an entry (Java's
    # recordSignedState). Called under @state_lock with a verified state.
    def record_signed_state(entry_id, dto)
      current = @signed_states[entry_id]
      @signed_states[entry_id] = dto if current.nil? || state_advances?(dto, current)
    end

    # ReplicatedSpace.advances: a completion dominates, then more removes,
    # then the newer lease register, then at least as many adds.
    def state_advances?(a, b)
      return a["completed"] ? true : false if (a["completed"] ? true : false) != (b["completed"] ? true : false)

      removes = Array(a["removes"]).size <=> Array(b["removes"]).size
      return removes.positive? unless removes.zero?

      stamps = Wire.hlc_order(a["leaseStamp"]) <=> Wire.hlc_order(b["leaseStamp"])
      return stamps.positive? unless stamps.zero?

      Array(a["adds"]).size >= Array(b["adds"]).size
    end

    # Whether sender is the member at the other end of this peer's one link.
    def link_holder?(sender) = !sender.nil? && sender == pull_partner

    def on_digest(sender, body, relayed)
      seed_round = !relayed && link_holder?(sender)
      only = seed_round ? nil : displaced_answerable
      if !seed_round && (only.empty? || sender.nil? || sender == @identity.peer_id)
        @ignored_kinds["DIGEST"] += 1
        return
      end
      digest = begin
        Wire.decode_body("DIGEST", body)
      rescue CBOR::Error
        @malformed_frames += 1
        return
      end
      return answer_digest(sender, digest) if seed_round
      return @state_lock.synchronize { @relayed_answers_paced += 1 } unless pace_answer(sender)

      answer_digest(sender, digest, only: only)
    end

    # The entries another member's DIGEST may draw (owner decision 1, as the
    # core's ReplicatedSpace.displacedFor): each whose claim made here a
    # better claim of another peer displaced, with or without a completion
    # under it, by entry id, with that claim to send along. Another
    # completion of this peer's own work is not among them.
    def displaced_answerable = @state_lock.synchronize { displaced_lines }

    # Spends one of sender's answers: a bucket of RELAYED_ANSWER_BURST that
    # fills at RELAYED_ANSWER_RATE a second on the monotonic base.
    def pace_answer(sender)
      now = local_ms
      @state_lock.synchronize do
        tokens, at = @answer_buckets.delete(sender) || [RELAYED_ANSWER_BURST.to_f, now]
        tokens = [tokens + ((now - at) * RELAYED_ANSWER_RATE / 1000.0), RELAYED_ANSWER_BURST.to_f].min
        spent = tokens >= 1
        @answer_buckets[sender] = [spent ? tokens - 1 : tokens, now]
        @answer_buckets.shift while @answer_buckets.size > RELAYED_ANSWER_ASKERS
        spent
      end
    end

    # One PULL_RESP for the space streams of a seed's text digests; with
    # only (another member's DIGEST), for those entries alone, sent back
    # through the seed when the asker is another member.
    def answer_digest(sender, digest, only: nil)
      texts = digest["digests"] || {}
      budget = digest["budget"]
      cap = budget.nil? ? MAX_TEXT_DIGEST_BYTES : [budget, ANSWER_BUDGET_CEILING].min
      remainder = budget.nil? ? nil : {}
      deltas = {}
      used = PULL_RESP_BASE
      texts.keys.sort.each do |stream|
        next unless stream.start_with?("space:")

        overhead = (2 * (stream.bytesize + 9)) + 9
        bytes, left = space_answer(stream.delete_prefix("space:"), texts[stream], cap - used - overhead, deltas.empty?,
                                   only)
        next if bytes.nil?

        remainder[stream] = left unless remainder.nil?
        next if bytes.empty?

        deltas[stream] = bytes
        used += bytes.bytesize + overhead
      end
      @state_lock.synchronize { only.nil? ? @digests_answered += 1 : @displaced_digest_answers += 1 }
      return if deltas.empty?

      body = Peer.pull_resp_body(deltas, remainder)
      only.nil? ? send_frame("PULL_RESP", body, sender) : send_addressed("PULL_RESP", body, sender)
      @state_lock.synchronize { @pull_resps_sent += 1 }
    end

    # The delta of one space against the partner's text digest, within room
    # bytes (the first item always when first), and the count of items left
    # out; nil when this peer holds nothing of the space. With only, the
    # entries it names alone, each with the claim it names.
    def space_answer(space, text, room, first, only = nil)
      sid = space_id_of(space)
      remote = text.to_s.dup.force_encoding(Encoding::UTF_8).split("\n").to_set
      offers = []
      by_id = {} # an entry's offer, so its claim joins it without a scan
      @state_lock.synchronize do
        held = false
        @states.each do |entry_id, dto|
          next unless (dto["record"] || {})["spaceId"] == sid
          next if only && !only.key?(entry_id)

          held = true
          line = TextDigest.state_line(entry_id, dto)
          next if remote.include?(line) || remote.include?("a:#{line}")

          signed = @signed_states[entry_id] # a relay forwards only what it holds signed
          next if signed.nil?

          offers << (by_id[entry_id] = [entry_id, signed, Peer.present?(dto), nil])
        end
        (only ? only.compact : @claims).each do |entry_id, signed|
          claim = signed["claim"]
          next unless claim["spaceId"] == sid

          held = true
          line = "c:#{entry_id}=#{TextDigest.claim_hash(claim)}"
          next if remote.include?(line) || remote.include?("a:#{line}")

          offer = by_id[entry_id]
          offer ? offer[3] = signed : offers << [entry_id, nil, false, signed]
        end
        return nil unless held
      end
      bounded_answer(offers, room, first)
    end

    # Java's bounded: present states, then tombstones, then claims alone;
    # newest lease stamp first; then by id. Stops before the item that would
    # pass room, the first one always taken when first.
    def bounded_answer(offers, room, first)
      offers.sort_by! do |id, state, present, claim|
        rank = state.nil? ? 2 : (present ? 0 : 1)
        stamp = state.nil? ? claim&.dig("claim", "stamp") : state["leaseStamp"]
        [rank, stamp.nil? ? 1 : 0, stamp.nil? ? [] : Wire.hlc_order(stamp).map { |part| negate(part) }, id.b]
      end
      states = []
      claims = {}
      used = SYNC_DELTA_BASE
      taken = 0
      offers.each do |id, state, _present, claim|
        size = state.nil? ? 0 : CBOR.dump(state).bytesize
        size += CBOR.dump(claim).bytesize + id.bytesize + 9 unless claim.nil?
        break if used + size > room && !(first && taken.zero?)

        used += size
        taken += 1
        states << state unless state.nil?
        claims[id] = claim unless claim.nil?
      end
      left = offers.size - taken
      return ["".b, left] if taken.zero?

      [Peer.sync_delta_bytes(states, claims), left]
    end

    # A sort key part reversed (newest first): numbers negated, texts by their bytes inverted.
    def negate(part)
      part.is_a?(Numeric) ? -part : part.to_s.b.bytes.map { |b| 255 - b } + [256]
    end
  end
end
