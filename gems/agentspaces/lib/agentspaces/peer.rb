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
  # No seed accepted a connection.
  class NoSeedError < IOError; end

  # A peer was used in a process forked after it started.
  class ForkError < StandardError; end

  # A wire-compatible AgentSpaces peer: joins a fleet in the dial-only posture
  # (SPEC 5.4), stays a live member by answering probes and re-leasing its
  # self-advertisement, writes signed entries into replicated spaces, folds
  # what anti-entropy and gossip bring, and takes under the LEASE_RACE claim
  # lattice. It is the Ruby twin of the Python and TypeScript peers, on the
  # same golden vectors.
  class Peer
    SCHEMES_SKIPPED = %w[dtls udp quic webrtc].freeze
    # The race allowance a contesting claim's stamp gets past the drift
    # ceiling: Java's default ReplicatedSpace settle window, 200 ms (HLC round
    # six, 2026-11-08, R6).
    CONTEST_SETTLE_MILLIS = 200

    @live = ObjectSpace::WeakMap.new
    class << self
      # Every peer started in this process, for the fork hook.
      attr_reader :live

      # Called in a forked child: every inherited peer drops its connection
      # without a word to the remote and refuses further use.
      def after_fork_in_child!
        @live.each_value(&:inherited!)
      end
    end

    # The wire hint that says this client accepts a renew, cancel, or complete
    # whose EntryStateDto carries no record (SPEC v0.1.17 §9 hints;
    # srad/agentspaces-pdt.md 3.9, PD-L-04).
    RECORDLESS_HINT = "wire.recordless"
    # The wire hint that says every decoder of this client reads the v0.1.32
    # AppCard and AgentCard schemas and their value rules (SPEC §9 hints,
    # §6.1a.2; AppCard origin and formats, 2026-11-09, FR-6), and the level
    # this build reads. Level 1 advertises no hint, so a test builds a mixed
    # fleet.
    APPCARD_HINT = "wire.appcard"
    APPCARD_LEVEL = 2
    # The advertisement cache's bounds (SPEC §6.3 v0.1.32, FR-11): the most
    # advertisements it holds and the most bytes of their encodings.
    AD_CACHE_MAX_ENTRIES = 8192
    AD_CACHE_MAX_BYTES = 33_554_432
    # A resolution that fails a check of its parts document (FR-15). The
    # cached stub stays and nobody is struck.
    class ResolveError < StandardError; end
    # Recordless states held for entries whose record has not arrived: at most this many.
    MAX_PENDING_STATES = 1024
    # How many distinct refused states and claims the peer remembers, so an
    # offer it already counted counts once (HLC canonical stamps, 2026-11-08),
    # and how many distinct deferred ones; each memory evicts its least
    # recently offered key (HLC round five, 2026-11-08 (E14)).
    REFUSED_STAMP_MEMORY = 4096
    # The record each non-space stream's PULL_RESP delta holds (HLC round
    # six, 2026-11-08, F3): AdCache.Delta, and RevocationRegistry's array of
    # SignedRevocation.
    # The fewest claims the claim map holds before prune_claims runs (R10).
    CLAIMS_PRUNE_FLOOR = 1024
    PULL_DELTAS = {
      "ads" => "AdCache.Delta",
      Revocation::PEER_STREAM => [:list, "RevocationRegistry.SignedRevocation"],
      Revocation::CREDENTIAL_STREAM => [:list, "RevocationRegistry.SignedRevocation"]
    }.freeze

    attr_reader :identity, :group, :states, :claims, :members, :reachable, :ads, :pipe_handlers, :revocations,
                :founding, :frames, :ignored_kinds, :malformed_frames, :reconnects, :seed_peer, :resource_hints,
                :blocks, :relayed_frames, :relay_signals, :clock, :seeds, :logger, :wire_hints, :pending_states
    attr_accessor :on_state, :on_claim, :reconnect_interval, :reconnect_window, :peer_ad_interval, :pinned_invite,
                  :refresh_seeds, :delegation
    # :session (the default and dev-local's): advertise wire.session=1 and,
    # on a connection the transport cannot attest, run session attestation
    # with a member that advertises it too; :signed: sign every frame.
    attr_accessor :channel_auth
    attr_reader :session, :session_frames_sent, :session_peers
    attr_reader :ad_cache_max_entries, :ad_cache_max_bytes, :spill_max_fetch_bytes
    # Where resolve fetches a stub's parts document (SPEC §6.1a.5): an object
    # whose get(root, size) returns the document's bytes, raising
    # ArgumentError when it refuses the artifact for its length. resolve
    # checks the bytes against spill.root, so any source may serve them. A
    # content swarm attaches here; with none attached, resolve fails a stub.
    attr_accessor :spill_store

    # clock: a callable returning epoch seconds (a Float); tests pin it.
    # founder: the founder's PeerID when known from configuration.
    # appcard_level: the AppCard level advertised under wire.appcard (1 or 2).
    # ad_cache_max_entries, ad_cache_max_bytes: the cache's bounds.
    # spill_max_fetch_bytes: the largest parts document resolve fetches.
    def initialize(identity, group, clock: nil, founder: nil, dialers: nil, logger: nil, appcard_level: APPCARD_LEVEL,
                   ad_cache_max_entries: AD_CACHE_MAX_ENTRIES, ad_cache_max_bytes: AD_CACHE_MAX_BYTES,
                   spill_max_fetch_bytes: Cards::CARD_SPILL_MAX_FETCH_BYTES)
      unless [1, APPCARD_LEVEL].include?(appcard_level) && appcard_level.is_a?(Integer)
        raise ArgumentError, "this build reads AppCard levels 1 to #{APPCARD_LEVEL}: #{appcard_level.inspect}"
      end

      @ad_cache_max_entries = positive!(ad_cache_max_entries, "ad_cache_max_entries")
      @ad_cache_max_bytes = positive!(ad_cache_max_bytes, "ad_cache_max_bytes")
      @spill_max_fetch_bytes = positive!(spill_max_fetch_bytes, "spill_max_fetch_bytes")
      @identity = identity
      @group = group
      @clock = clock || -> { Time.now.to_f }
      @configured_founder = founder
      @dialers = (dialers || [TcpDialer.new, TlsDialer.new, WsDialer.new, HttpDialer.new]).to_h { |d| [d, d.schemes] }
      @logger = logger
      @channel = nil
      @states = {}
      @claims = {}
      @claims_prune_at = CLAIMS_PRUNE_FLOOR
      @members = {}
      @reachable = Set.new
      @ads = {}
      @ad_bytes = 0
      @ads_refused_cache_full = 0
      @app_cards_downgraded = 0
      @cards_oversize_inline = 0
      @card_size_warned = {}
      @spills_refused = 0
      @spills_over_limit = 0
      @spill_store = nil
      @pipe_handlers = {}
      @revocations = Revocation::Registry.new(-> { founder_id }, -> { @group })
      @running = false
      @founding = nil
      @founding_lock = Mutex.new
      @founding_ready = ConditionVariable.new
      @frames = Wire::FrameFilter.new
      @ignored_kinds = Hash.new(0)
      @malformed_frames = 0
      @stamps_logical_refused = 0
      @stamps_far_future_refused = 0
      @stamps_far_future_deferred = 0
      @deltas_undecodable = 0
      @refused_offers = {}
      @deferred_offers = {}
      @seed = nil
      @seeds = []
      @refresh_seeds = nil
      @resource_hints = {}
      # The wire hints beside the resource hints in the self-advertisement:
      # wire.recordless says a recordless renew, cancel, or complete is accepted.
      @wire_hints = { RECORDLESS_HINT => "1" }
      @wire_hints[APPCARD_HINT] = APPCARD_LEVEL.to_s if appcard_level == APPCARD_LEVEL
      # Recordless states by entry id, kept without an event until the whole
      # DTO arrives through anti-entropy (PD-L-02).
      @pending_states = {}
      @pinned_invite = nil
      @delegation = nil
      @pulled_spaces = Set.new
      @pulled_ads = false
      @seed_peer = nil
      @max_path_hops = 4
      @relayed_frames = 0
      @relay_signals = []
      @blocks = {}
      @block_asked = {}
      @reconnect_interval = 5.0
      @reconnect_window = 600.0
      # When the current link was dialed, and how many links in a row ended
      # within the reconnect interval: such a link counts as a failed round of
      # dials (swarm retries, ROBUSTNESS.md 10.6).
      @link_since = 0.0
      @quick_drops = 0
      @peer_ad_interval = 30.0
      @reconnects = 0
      @fold_lock = Mutex.new
      @fold_condition = ConditionVariable.new
      @fold_count = 0
      @last_pull = {}
      @state_lock = Monitor.new
      @pid = Process.pid
      @inherited = false
      @threads = []
      @observers = []
      @closed = false
      @channel_auth = :session
      @session = nil
      @session_frames_sent = 0
      @session_peers = Set.new
      Peer.live[object_id] = self
    end

    # ------------------------------------------------------------- lifecycle

    # Dials one seed and introduces this peer to the group.
    def connect(host, port = nil, scheme: "tcp", timeout: 10)
      seed = port.nil? ? Seed.parse(host) : Seed.new(scheme: scheme, host: host.to_s, port: Integer(port))
      open_channel(seed, timeout: timeout)
      introduce
      announce_channel
      pull_revocations
      self
    end

    # Dials the seeds in order until one accepts, and remembers them all: a
    # lost socket fails over to the next seed inside the reconnect window. A
    # hostname expands to every address, each its own seed. Returns the seed
    # connected to; raises NoSeedError naming every seed and its failure.
    def connect_any(seeds)
      expanded = expand_seeds(seeds)
      raise NoSeedError, "no seeds to dial" if expanded.empty?

      @seeds = expanded
      failures = []
      expanded.each do |seed|
        connect(seed)
        return seed
      rescue SystemCallError, IOError, SocketError, OpenSSL::SSL::SSLError => e
        failures << "#{seed}: #{e.class.name.split('::').last} #{e.message}"
      end
      raise NoSeedError, "no seed accepted a connection: #{failures.join('; ')}"
    end

    # Joins a self-certifying group knowing only its GroupID and a seed
    # (SPEC 5.1, 10.1): sends an unaddressed GROUP_AD_WANT, waits for a
    # GROUP_AD whose body verifies to exactly that GroupID, ignoring every
    # answer that fails, and only then introduces this peer. A group started
    # from a founding: text has no signed founding and cannot be joined by id.
    def join_by_group_id(host, port, group_id, timeout: 10.0, scheme: "tcp", path: nil)
      @group = group_id
      @founding_lock.synchronize { @founding = nil }
      open_channel(Seed.new(scheme: scheme, host: host.to_s, port: Integer(port), path: path))
      deadline = monotonic + timeout
      asked_at = nil
      @founding_lock.synchronize do
        while @founding.nil?
          remaining = deadline - monotonic
          break if remaining <= 0

          if asked_at.nil? || monotonic - asked_at >= 2.0
            @founding_lock.unlock
            begin
              send_frame(Wire::KIND_GROUP_AD_WANT, "".b)
            ensure
              @founding_lock.lock
            end
            asked_at = monotonic
          end
          @founding_ready.wait(@founding_lock, [remaining, 0.5].min)
        end
      end
      if @founding.nil?
        close
        raise Timeout::Error, "no verified GROUP_AD for #{group_id} from #{host}:#{port} within #{timeout}s; " \
                              "a group started from a founding: text has no signed founding and cannot be joined by id"
      end
      introduce
      pull_revocations
      @founding
    end

    # Adopts a founding verified elsewhere (a beacon document) before dialing.
    def adopt_founding!(signed, group_id)
      @group = group_id
      @founding_lock.synchronize do
        @founding = signed
        @founding_ready.broadcast
      end
    end

    def close
      @running = false
      @closed = true
      channel = @channel
      @channel = nil
      channel&.close
      wake_fold_waiters
      @threads.each { |t| t.join(2) unless t == Thread.current }
      @threads.clear
      nil
    end

    def connected? = @running && !@channel.nil?

    def running? = @running

    def now_ms = (@clock.call * 1000).to_i

    def founder_id
      return @configured_founder if @configured_founder

      @founding&.dig("advertisement", "issuer")
    end

    def self.aggregate_roster_token(peer_id) = Wire.aggregate_roster_token(peer_id)

    # Marks a peer inherited by a forked child; see Peer.after_fork_in_child!.
    def inherited!
      return if Process.pid == @pid

      @inherited = true
      @running = false
      @channel&.abandon
      @channel = nil
    end

    # ------------------------------------------------------------- protocol

    # Publishes this peer's leased self-advertisement (SPEC 5.2).
    def introduce
      now = now_ms
      hints = @resource_hints.merge(@wire_hints)
      hints = hints.merge(Session::HINT => "1") if @channel_auth == :session
      ad = Wire.peer_advertisement(@group, @identity, Instants.iso(now - (now % 1000)), "PT10M", hints)
      send_frame("RUMOR", Wire.rumor_body("peers", "peer:#{@identity.peer_id}:#{now}", Wire::HOPS,
                                          Wire.signed_peer_ad(ad, @identity)))
    end

    # Writes one signed entry into a replicated space; returns its id. With
    # agent (an AgentIdentity) the entry is the agent's own and stored
    # AGENT_ATTESTED everywhere. Tags travel inside the signed record.
    def write_entry(space, type_name, value, agent_name: "ruby", lease_millis: 600_000, agent: nil, tags: nil)
      check_fork!
      if agent && @revocations.refuses?(agent.agent_id, agent.public_raw, nil)
        raise ArgumentError, "#{agent.agent_id} is revoked in this group"
      end

      payload = CBOR.dump(value)
      payload_ref = nil
      if payload.bytesize > Wire::INLINE_PAYLOAD_LIMIT
        payload_ref = put_block(payload)
        payload = nil
      end
      entry_id, body = Wire.entry_delta(space, @group, type_name, payload, @identity, agent_name, lease_millis,
                                        agent: agent, now_ms: now_ms, tags: tags, payload_ref: payload_ref)
      send_frame("RUMOR", body)
      # The writer holds its own entry too, so a local read sees it at once.
      delta = CBOR.load(CBOR.load(body)["payload"])
      fold_state(delta["state"]) if delta["state"].is_a?(Hash)
      entry_id
    end

    # Publishes an advertisement this peer issued on the "ads" stream. An
    # AppCard or AgentCard passes the card rules of SPEC v0.1.32 first
    # (issue_card).
    def publish_ad(ad_type, ad)
      ad = issue_card(ad_type, ad) if CARD_TYPES.include?(ad_type)
      stored = Wire.stored_ad(ad_type, ad, @identity)
      accept_ad(stored)
      item_id = "#{ad['id']}:#{Instants.parse_millis(ad['issued'])}"
      send_frame("RUMOR", Wire.rumor_body("ads", item_id, Wire::HOPS, CBOR.dump(stored)))
    end

    # Anti-entropy pull (SPEC 5.3): an empty digest; the partner answers with
    # every state this replica lacks. The revocation streams ride along.
    def pull_space(space)
      @pulled_spaces << space
      digests = { "space:#{space}" => "".b }
      Revocation::STREAMS.each { |s| digests[s] = "".b }
      send_frame("DIGEST", Wire.digest_body(digests))
    end

    # Pulls unless pulled within settle_seconds; returns whether a pull went out.
    def pull_space_paced(space, settle_seconds)
      now = monotonic
      return false if now - @last_pull.fetch(space, -Float::INFINITY) < settle_seconds

      @last_pull[space] = now
      pull_space(space)
      true
    end

    def pull_revocations
      send_frame("DIGEST", Wire.digest_body(Revocation::STREAMS.to_h { |s| [s, "".b] }))
    end

    def pull_ads
      @pulled_ads = true
      send_frame("DIGEST", Wire.digest_body({ "ads" => "".b }))
    end

    def fold_count = @fold_count

    # Blocks until the next fold or max_seconds. With since (a fold_count
    # snapshot taken before a scan) a fold between the scan and the wait
    # counts too. Returns whether a fold woke the wait.
    def await_fold(max_seconds, since: nil)
      deadline = monotonic + [max_seconds.to_f, 0.0].max
      @fold_lock.synchronize do
        seen = since.nil? ? @fold_count : since
        while @fold_count == seen
          remaining = deadline - monotonic
          return false if remaining <= 0 || !@running

          @fold_condition.wait(@fold_lock, remaining)
        end
        true
      end
    end

    # The full card of a stub (SPEC §6.1a.5; AppCard origin and formats,
    # 2026-11-09, FR-15): a card without spill as it stands, and otherwise the
    # stub completed from its parts document, which the spill store fetches by
    # root. A size above spill_max_fetch_bytes fails before any fetch and
    # counts in spills_over_limit; a document of another length or another
    # content root, one that does not decode as the kind's parts record, or one
    # whose non-empty fields are not exactly spill.parts fails and counts in
    # spills_refused. Either failure raises ResolveError. An error the store
    # raises for any other reason (no holder served the document) propagates
    # uncounted. No failure touches the cached stub or strikes anyone.
    def resolve(card)
      spill = card["spill"]
      return card if spill.nil?

      if spill["size"] > @spill_max_fetch_bytes
        count(:@spills_over_limit)
        raise ResolveError, "the parts document of #{card['id']} is #{spill['size']} bytes, above the fetch bound of " \
                            "#{@spill_max_fetch_bytes}"
      end
      store = @spill_store
      raise ResolveError, "no content swarm serves this group, so the stub #{card['id']} stays a stub" if store.nil?

      complete_stub(card, spill, store)
    end

    def ads_refused_cache_full = @state_lock.synchronize { @ads_refused_cache_full }

    # The sum of the encodings the advertisement cache holds.
    def ad_cache_bytes = @state_lock.synchronize { @ad_bytes }

    def app_cards_downgraded = @state_lock.synchronize { @app_cards_downgraded }

    def cards_oversize_inline = @state_lock.synchronize { @cards_oversize_inline }

    def spills_refused = @state_lock.synchronize { @spills_refused }

    def spills_over_limit = @state_lock.synchronize { @spills_over_limit }

    # Admits a StoredAd as AdCache.accept does: the signature, the issuer
    # derived from the key, and the TTL not yet passed.
    # HLC round six, 2026-11-08 (F3): the StoredAd and its adBytes hold to
    # their records, the ad to the one its adType names (AdCache.AD_TYPES);
    # an unknown adType or a relabelled ad is undecodable and dropped.
    def accept_ad(stored)
      Schema.check("AdCache.StoredAd", stored)
      ad_type, ad_bytes, key, signature = stored.values
      return nil unless Schema::AD_TYPES.include?(ad_type) && ad_bytes && signature && key&.bytesize == 32
      return nil unless Crypto.port.verify(key, ad_bytes, signature)

      ad = Schema.load(ad_type, ad_bytes)
      return nil unless ad["issuer"] == Derive.id(key)

      issued = Instants.parse_millis(ad["issued"])
      expires = issued + Instants.parse_duration_millis(ad["ttl"])
      return nil if expires <= now_ms

      entry = { "type" => stored["adType"], "ad" => ad, "stored" => stored, "issuer" => ad["issuer"],
                "expires" => expires, "bytes" => ad_bytes.bytesize }
      @state_lock.synchronize { admit_ad(entry, issued) }
    rescue CBOR::Error, ArgumentError, TypeError, NoMethodError
      nil
    end

    # The live AgentCards the ads stream carried, without the cards of a
    # revoked peer or a revoked agent or agent key (AdCache.refuseIssuers and
    # refuseAgents, SPEC 6.1 v0.1.13: a revoked agent advertises nothing).
    def cards
      now = now_ms
      @ads.values.select { |e| e["type"] == "AgentCard" && e["expires"] > now && !revoked_card?(e["ad"]) }
          .map { |e| e["ad"] }
    end

    # Whether a card's issuer, or its agent or agent key, is revoked.
    def revoked_card?(card)
      @revocations.peer_revoked?(card["issuer"].to_s) ||
        @revocations.refuses?(card["agent"], card["agentPublicKey"], nil)
    end

    # One capability frame to a member (CapabilityPipes.send).
    def send_pipe(to, capability, payload, via: nil)
      send_addressed("PIPE_DATA", CBOR.dump({ "capability" => capability, "payload" => payload.b }), to, via: via)
    end

    # The relay an addressed frame to `to` goes through: the seed for
    # everyone but the seed itself.
    def relay_for(to)
      return nil if @seed.nil? || @seed_peer.nil? || to == @seed_peer

      @seed_peer
    end

    def send_addressed(kind, body, to, via: nil)
      relay = relay_for(to)
      return send_frame(kind, body, to) if relay.nil?

      inner = Wire.encode_frame(Wire.envelope(@group, kind, @identity.peer_id,
                                              Wire.hlc_now(@identity.peer_id, now_ms), body, to), @identity)
      path = [relay] + (via || []).reject { |v| v == relay || v == to }.first([@max_path_hops - 1, 0].max)
      @relayed_frames += 1
      if path.size > 1
        send_frame("RELAY_FRAME", Wire.relay_frame_body(to, inner, path, 0), relay)
      else
        send_frame("RELAY_FRAME", Wire.relay_frame_body(to, inner), relay)
      end
    end

    # ------------------------------------------------------------- payloads

    # The payload bytes of an entry's record: inline, or a block held here. A
    # block not yet held starts its transfer and returns nil.
    def payload_of(dto)
      record = dto["record"] || {}
      payload = record["payload"]
      return payload unless payload.nil?

      ref = record["payloadRef"]
      return "\xF6".b unless ref.is_a?(String) && !ref.empty?

      data = @blocks[ref]
      want_block(ref, dto) if data.nil?
      data
    end

    def want_block(cid, dto = nil)
      now = monotonic
      return if now - @block_asked.fetch(cid, -Float::INFINITY) < 1.0

      @block_asked[cid] = now
      targets = []
      key = dto && dto["issuerPublicKey"]
      targets << Derive.id(key) if key.is_a?(String)
      targets << @seed_peer if @seed_peer && !targets.include?(@seed_peer)
      targets.each do |target|
        send_addressed("BLOCK_WANT", Wire.block_want_body(cid), target) unless target == @identity.peer_id
      end
    end

    def put_block(data)
      cid = Wire.block_cid(data)
      @blocks[cid] = data.b
      cid
    end

    # The decoded value of an entry's payload as [value], or nil while the
    # payload is not held or when it is no document of the wire encoding:
    # such an entry stays replicated, since its signature covers the bytes,
    # and every read skips its value (HLC round six, 2026-11-08, F3 section 3.1).
    def value_of(dto)
      raw = payload_of(dto)
      raw && [CBOR.load(raw)]
    rescue CBOR::Error
      nil
    end

    # Decoded values of known live entries of one schema type.
    def find(type_name)
      @states.values.filter_map do |dto|
        record = dto["record"] || {}
        next unless record["type"] == type_name && !dto["completed"]

        value_of(dto)&.first
      end
    end

    # ----------------------------------------------------------- the folds

    # Folds one received state DTO: verified (record and transition), refused
    # when its actor is revoked, judged for its stamps, then joined as the
    # Java CRDT joins it. HLC round five, 2026-11-08 (E6): the revocation
    # check runs before the stamp checks, so a revoked actor's state counts
    # in no stamp counter.
    # HLC round six, 2026-11-08 (F1, F3): a state that does not hold to
    # SpaceWire.EntryStateDto is undecodable and counts in deltas_undecodable,
    # as the carrier that brought it would (space_delta).
    def fold_state(dto)
      return count_undecodable unless decodes?("SpaceWire.EntryStateDto", dto)

      merge_state(dto)
    end

    # Folds one signed claim after validating its bindings, bounds, proof,
    # and holder (ASF-002, ASF-004, ASF-033). HLC round five, 2026-11-08
    # (E6): signatures and certificate first, then the holder's revocation,
    # then the stamp checks, so a revoked holder's claim counts in no stamp
    # counter. HLC round six, 2026-11-08 (F1, F3): a claim that does not hold
    # to SpaceWire.SignedClaim (a TakeClaim in record order whose numbers have
    # their declared types) is undecodable and counts in deltas_undecodable.
    def fold_claim(entry_id, signed)
      return count_undecodable unless decodes?("SpaceWire.SignedClaim", signed)

      claim = signed["claim"]
      return unless claim["entryId"] == entry_id
      return unless Wire.verify_claim_proof(signed)

      epoch = claim["epoch"]
      expires = claim["expiresAtMillis"]

      certificate = signed["holderCertificate"] || {}
      return if @revocations.refuses?(claim["holder"], certificate["agentPublicKey"], nil)
      # HLC logical counter, 2026-11-08 (Rust team report): the peer drops a
      # claim whose stamp the strict parser refuses. It counts the refusal
      # after verification, once per distinct claim, as Java's mergeClaim does
      # (HLC canonical stamps, 2026-11-08).
      return refuse_claim(entry_id, claim, :logical) unless Wire.hlc_acceptable?(claim["stamp"])

      stamped = Wire.hlc_physical(claim["stamp"])
      # HLC round four, 2026-11-08 (D4): a claim stamped past the skew margin
      # waits for a later offer; one an hour further is hostile.
      lead = Wire.hlc_far_future(stamped, now_ms)
      return refuse_claim(entry_id, claim, :far_future) if lead == :hostile

      current = claim_of(entry_id)
      observed = (current || {}).fetch("epoch", 0).to_i
      return if epoch > observed + Wire::MAX_CLAIM_EPOCH_JUMP || expires > now_ms + Wire::MAX_CLAIM_HOLD_MILLIS

      issued = (@states[entry_id] || {}).dig("record", "issued")
      # SPEC 7.4/11 (ReplicatedSpace): a claim cannot predate the entry it
      # answers, and a rival holder's claim older than the drift and settle
      # bounds arrives too late to contest the current one.
      return if issued && stamped < Wire.hlc_physical(issued) - Certificates::MAX_DRIFT_MILLIS
      return if current && current["holder"] != claim["holder"] &&
                stamped < now_ms - Certificates::MAX_DRIFT_MILLIS - CONTEST_SETTLE_MILLIS
      # HLC round five, 2026-11-08 (E2): a claim that passes every other check
      # but runs past the skew margin waits, counted once per distinct claim,
      # as Java's mergeClaim defers it only when it finds no violation.
      return defer_offer(claim_offer_key(entry_id, claim)) if lead == :deferred

      winner = @state_lock.synchronize { @claims[entry_id] = Wire.merge_claims(@claims[entry_id], signed) }
      @on_claim&.call(entry_id, winner)
      notify_observers { |o| o.claim_folded(entry_id, winner) }
      wake_fold_waiters
    end

    def claim_of(entry_id) = @claims[entry_id]&.fetch("claim")

    # The entry's current lease: the state's lease register, which supersedes the
    # lease its record was written with (SPEC 7.3), as Java's EntryState and the
    # TypeScript client read it. A renewal moves the register, so reads, takes and
    # the sweep follow it (lease renewals, 2026-11-09).
    def self.lease_of(dto) = dto["leaseValue"] || (dto["record"] || {})["lease"] || {}

    # Whether the entry of dto is present, as Java's EntryState.present judges
    # it: uncompleted, with an add dot no remove covers. A cancel's removes
    # cover the adds, so a withdrawn entry is absent from reads and takes at
    # once (core cancel events, 2026-11-09).
    def self.present?(dto)
      return false if dto["completed"]

      removed = Array(dto["removes"]).map { |dot| [dot["replica"], dot["counter"]] }
      Array(dto["adds"]).any? { |dot| !removed.include?([dot["replica"], dot["counter"]]) }
    end

    # Merges a state that holds to its record: fold_state's, and a recordless
    # state's over the record this replica holds.
    def merge_state(dto)
      # HLC round five, 2026-11-08 (E7): a state without its lease stamp or
      # lease value decodes, but a lease register holds nothing without both,
      # so the peer drops it before any judgement, as Java's mergeState does.
      return if dto["leaseStamp"].nil? || dto["leaseValue"].nil?
      return fold_recordless(dto) if dto["record"].nil?

      record = dto["record"]
      entry_id = record["entryId"]
      return unless entry_id && dots_bound_to_issuer?(dto, record) && verify_state(dto, record)

      if refused_for_revocation?(dto, record)
        @state_lock.synchronize { @pending_states.delete(entry_id) }
        return
      end
      # HLC logical counter, 2026-11-08 (Rust team report): the peer drops a
      # state whose issue stamp, lease stamp, or signedAt the strict parser
      # refuses. It counts the refusal after verification, once per distinct
      # state, as Java's ReplicatedSpace does (HLC canonical stamps,
      # 2026-11-08; HLC round four, 2026-11-08 (D1)).
      return refuse_state(dto, record, :logical) unless state_stamps_acceptable?(dto, record)

      # HLC round four, 2026-11-08 (D4): a record or lease stamp past the skew
      # margin waits for a later offer; one an hour further is hostile.
      case Wire.hlc_far_future(state_lead_ms(dto, record), now_ms)
      when :deferred then return defer_offer(state_offer_key(dto, record))
      when :hostile then return refuse_state(dto, record, :far_future)
      end

      pending = @state_lock.synchronize { @pending_states.delete(entry_id) }
      # The read and the write share one critical section, so a completion that lands meanwhile
      # is joined, never overwritten (core cancel events, 2026-11-09).
      previous = nil
      merged = @state_lock.synchronize do
        previous = @states[entry_id]
        @states[entry_id] = previous.nil? ? dto : join(previous, dto)
      end
      @on_state&.call(merged)
      notify_observers { |o| o.state_folded(merged) }
      # Core cancel events, 2026-11-09: a cancel that withdraws an entry present here is
      # announced, and each Space raises EXPIRED for it, as Java's ReplicatedSpace does.
      if !previous.nil? && Peer.present?(previous) && !Peer.present?(merged) && !merged["completed"]
        notify_observers { |o| o.state_withdrawn(merged) }
      end
      wake_fold_waiters
      fold_recordless(pending) unless pending.nil?
    end

    # A renew, cancel, or complete without its record (srad/agentspaces-pdt.md
    # 3.9, PD-L-01, PD-L-02): merged through every check with the record this
    # replica holds, else kept pending with no event until anti-entropy ships
    # the whole DTO. The entry id is the DTO's entryId or the one the rumor
    # item named.
    def fold_recordless(dto)
      entry_id = dto["entryId"]
      return unless entry_id.is_a?(String) && !entry_id.empty?

      previous = @state_lock.synchronize { @states[entry_id] }
      if previous.nil?
        @state_lock.synchronize do
          @pending_states.shift while @pending_states.size >= MAX_PENDING_STATES
          @pending_states[entry_id] = dto
        end
        return
      end
      full = dto.merge("record" => previous["record"])
      %w[issuerPublicKey agentCertificate].each do |carried|
        full[carried] = previous[carried] if full[carried].nil? && !previous[carried].nil?
      end
      merge_state(full)
    end

    # Fills entryId of a recordless state from the rumor item id (r:<id>:<stamp>,
    # d:<id>) when the DTO does not carry one.
    def name_recordless(state, item_id)
      return state unless state.is_a?(Hash) && state["record"].nil? && !state["entryId"] && item_id.is_a?(String)

      parts = item_id.split(":")
      state["entryId"] = parts[1] if parts.size >= 2 && %w[r d x c].include?(parts[0])
      state
    end


    # Verified states and claims refused for a logical counter above the
    # limit, each distinct one once (HLC logical counter, 2026-11-08 (Rust
    # team report); HLC round four, 2026-11-08 (D5)). Java's
    # ReplicatedSpace.stampsLogicalRefused. A Ruby peer keeps no per-member
    # strikes, so these counts are its record.
    def stamps_logical_refused = @state_lock.synchronize { @stamps_logical_refused }

    # Verified states and claims refused as hostile, each distinct one once:
    # a stamp more than Wire::HLC_DEFER_WINDOW_MILLIS past the skew margin
    # (HLC round five, 2026-11-08 (E2)). Java's
    # ReplicatedSpace.stampsFarFutureRefused.
    def stamps_far_future_refused = @state_lock.synchronize { @stamps_far_future_refused }

    # Verified states and claims deferred because a stamp runs past the skew
    # margin by at most Wire::HLC_DEFER_WINDOW_MILLIS, each distinct one once
    # (HLC round five, 2026-11-08 (E2)). Java's
    # ReplicatedSpace.stampsFarFutureDeferred.
    def stamps_far_future_deferred = @state_lock.synchronize { @stamps_far_future_deferred }

    # Space deltas dropped whole because they do not decode, or because a
    # stamp they carry does not decode (HLC round four, 2026-11-08 (D3, D5)).
    # Java's ReplicatedSpace.deltasUndecodable.
    def deltas_undecodable = @state_lock.synchronize { @deltas_undecodable }

    # ----------------------------------------------------------- take/complete

    # Takes one entry under LEASE_RACE (SPEC 7.4): publish a signed claim,
    # wait one settle window, and win when the lattice still says so. Returns
    # the entry id, or nil when out-arbitrated or nothing matched. matches is
    # a callable over (payload Hash, tags Hash); bid a Float or a callable.
    def take_entry(space, type_name, agent_name: "ruby", lease_millis: 60_000, settle_seconds: 0.6,
                   timeout_seconds: 15.0, agent: nil, matches: nil, bid: 0.0)
      check_fork!
      holder = agent.nil? ? @identity.agent(agent_name) : agent.agent_id
      return nil if @revocations.refuses?(holder, agent&.public_raw, nil)

      space_id = Derive.space_id_local("#{@group}/#{space}")
      deadline = monotonic + timeout_seconds
      while monotonic < deadline && @running
        pull_space_paced(space, settle_seconds)
        seen = fold_count
        now = now_ms
        claimed = false
        available(type_name, now).each do |entry_id, dto|
          record = dto["record"] || {}
          next unless record["spaceId"] == space_id

          value = value_of(dto)
          next if value.nil?

          payload = value.first
          next if matches && !matches.call(payload, record["tags"] || {})

          price = bid.respond_to?(:call) ? Float(bid.call(payload)) : Float(bid)
          # The list above is a snapshot, and each claim before this one waited out a
          # settle window: judge this entry again against the claims folded since, as
          # the TypeScript take does, so a lost race moves on to an entry nobody holds
          # rather than claiming one after another that faster members already took.
          now = now_ms
          current = claim_of(entry_id)
          next if current && current.fetch("expiresAtMillis", 0).to_i > now
          next unless Peer.present?(@states[entry_id] || {}) # completed or withdrawn meanwhile

          epoch = current ? Integer(current["epoch"]) + 1 : 1
          claim = Wire.take_claim(entry_id, space_id, epoch, Wire.hlc_now(holder, now), holder, price,
                                  now + lease_millis)
          signed = Wire.signed_claim(claim, @identity, agent)
          @state_lock.synchronize { @claims[entry_id] = Wire.merge_claims(@claims[entry_id], signed) }
          send_frame("RUMOR", Wire.rumor_body("space:#{space}", "c:#{entry_id}:#{claim['stamp']}", Wire::HOPS,
                                              Wire.claim_delta(entry_id, signed)))
          claimed = true
          sleep(settle_seconds)
          pull_space_paced(space, settle_seconds)
          await_fold([settle_seconds, 0.3].min)
          winner = claim_of(entry_id)
          # core cancel events, 2026-11-09: an entry completed or withdrawn during the settle
          # window is nobody's, so a cancel that folded meanwhile leaves the take empty
          if winner && winner["holder"] == holder && Integer(winner["epoch"]) == epoch &&
             Peer.present?(@states[entry_id] || {})
            return entry_id
          end
        end
        await_fold([settle_seconds, deadline - monotonic].min, since: seen) unless claimed
      end
      nil
    end

    # Completes a held entry: its state with the monotone completed flag set,
    # re-signed by the holder and carrying the winning claim. An entry this
    # replica holds completed or withdrawn is held by nobody, as Java's
    # complete refuses it (core cancel events, 2026-11-09).
    def complete_entry(space, entry_id, agent: nil)
      check_fork!
      dto = @states.fetch(entry_id).dup
      raise ArgumentError, "#{entry_id} is not held here: it is completed or withdrawn" unless Peer.present?(dto)

      dto["completed"] = true
      dto = Wire.sign_state(dto, @identity, agent, now_ms)
      @state_lock.synchronize { @states[entry_id] = dto }
      proof = @claims[entry_id]
      send_frame("RUMOR", Wire.rumor_body("space:#{space}", "d:#{entry_id}", Wire::HOPS,
                                          CBOR.dump({ "state" => dto, "claimEntry" => proof ? entry_id : nil,
                                                      "claim" => proof })))
    end

    # Cancels an entry this peer (or agent) wrote, as Java's EntryHandle.cancel
    # does (PDT 2 phase 7, P2-X-06): a state whose removes cover its adds,
    # signed by the issuer, so every replica withdraws the entry; the replica
    # keeps its tombstone until the collection horizon (SPEC 7.3). Watches
    # here hear EXPIRED at once, and every other member's when the withdrawal
    # folds there. An entry this replica holds completed or withdrawn stays as
    # it is and nothing goes out, since an issuer's signature over a completed
    # state verifies nowhere.
    def cancel_entry(space, entry_id, agent: nil)
      check_fork!
      previous = @states.fetch(entry_id)
      issuer = (previous["record"] || {})["issuer"].to_s
      if agent && agent.agent_id != issuer
        raise ArgumentError, "#{entry_id} was written by #{issuer}, not #{agent.agent_id}"
      end
      if agent.nil? && !issuer.start_with?("#{@identity.peer_id}/")
        raise ArgumentError, "#{entry_id} was written by #{issuer}, not by this peer"
      end
      return unless Peer.present?(previous)

      now = now_ms
      dto = Wire.sign_state(previous.merge("removes" => union_dots(previous["removes"], previous["adds"])), @identity,
                            agent, now)
      merge_state(dto)
      send_frame("RUMOR", Wire.rumor_body("space:#{space}", "x:#{entry_id}:#{now}", Wire::HOPS,
                                          CBOR.dump({ "state" => dto, "claimEntry" => nil, "claim" => nil })))
    end

    # Renews this peer's write of an entry (SPEC 7.3); only the issuer renews.
    def renew_entry(space, entry_id, lease_millis: 600_000, agent: nil)
      check_fork!
      dto = @states.fetch(entry_id).dup
      issuer = (dto["record"] || {})["issuer"].to_s
      if agent && agent.agent_id != issuer
        raise ArgumentError, "#{entry_id} was written by #{issuer}, not #{agent.agent_id}"
      end
      if agent.nil? && !issuer.start_with?("#{@identity.peer_id}/")
        raise ArgumentError, "#{entry_id} was written by #{issuer}, not by this peer"
      end

      now = now_ms
      dto["leaseStamp"] = Wire.hlc_now(issuer, now)
      dto["leaseValue"] = { "holder" => issuer, "expiresAtMillis" => now + lease_millis, "kind" => "WRITE" }
      dto = Wire.sign_state(dto, @identity, agent, now)
      @state_lock.synchronize { @states[entry_id] = dto }
      send_frame("RUMOR", Wire.rumor_body("space:#{space}", "r:#{entry_id}:#{now}", Wire::HOPS,
                                          CBOR.dump({ "state" => dto, "claimEntry" => nil, "claim" => nil })))
    end

    # Renews this peer's take of an entry: the held claim re-signed with the
    # same epoch, stamp, holder, and bid and a later expiry, which the claim
    # lattice prefers (expiry descending), as Java renews a TakenEntry. A
    # renewal keeps the claim's stamp, so certificates judge it at that stamp.
    def renew_claim(space, entry_id, lease_millis:, agent: nil)
      check_fork!
      signed = @claims[entry_id]
      holder = agent.nil? ? nil : agent.agent_id
      claim = signed && signed["claim"]
      if claim.nil? || (holder ? claim["holder"] != holder : !claim["holder"].to_s.start_with?("#{@identity.peer_id}/"))
        raise ArgumentError, "#{entry_id} is not held by #{holder || @identity.peer_id}"
      end
      raise ArgumentError, "#{entry_id} is completed" if (@states[entry_id] || {})["completed"]

      renewed = claim.merge("expiresAtMillis" => now_ms + Integer(lease_millis))
      proof = Wire.signed_claim(renewed, @identity, agent)
      @state_lock.synchronize { @claims[entry_id] = Wire.merge_claims(@claims[entry_id], proof) }
      send_frame("RUMOR", Wire.rumor_body("space:#{space}", "c:#{entry_id}:#{renewed['stamp']}:#{now_ms}", Wire::HOPS,
                                          Wire.claim_delta(entry_id, proof)))
      renewed["expiresAtMillis"]
    end

    # A Space of this peer's group by name (see AgentSpaces::Space).
    def space(name, agent: nil, agent_name: "ruby")
      Space.new(self, name, agent: agent, agent_name: agent_name)
    end

    # Binds an agent object through the Ruby binder; returns its Bound handle.
    def bind(agent_object, agent: nil, **options)
      Binder.new(self, agent: agent, **options).bind(agent_object)
    end

    # Registers a Space for fold events; the first one starts the sweep that
    # judges lease expiry by the clock (EXPIRED, REAPPEARED, lapsed watches).
    def add_observer(observer)
      @state_lock.synchronize do
        @observers << observer
        start_thread("agentspaces-sweep") { sweep_loop } if @observers.size == 1
      end
    end

    def remove_observer(observer) = @state_lock.synchronize { @observers.delete(observer) }

    def closed? = @closed

    # The handler of one verified envelope; public so in-memory transports
    # and tests can deliver frames.
    def handle(env, relayed: false)
      return unless @frames.admit(env, now_ms)

      Wire.hlc_observe(@identity.peer_id, env["stamp"], now_ms)
      kind = env["kind"]
      body = env["body"] || "".b
      sender = env["from"]
      if sender.is_a?(String) && sender != @identity.peer_id
        @members[sender] ||= {}
        @reachable << sender unless relayed
        if !relayed && @seed && env["to"] == @identity.peer_id && @seed_peer != sender
          # Over our one connection an addressed frame is the seed's own; it is
          # the relay we declare, so members behind other seeds reach us.
          @seed_peer = sender
          @resource_hints["relay.via"] = sender
          introduce
        end
      end
      maybe_session_hello(sender) if !relayed && sender != @identity.peer_id && !%w[RUMOR SESSION_HELLO].include?(kind)
      case kind
      when "SESSION_HELLO" then on_session_hello(env)
      when "PING" then send_frame("ACK", Wire.ack_body(Wire.decode_body(kind, body)["nonce"]))
      when "PIPE_DATA" then on_pipe(sender, Wire.decode_body(kind, body))
      when "RELAY_FRAME"
        relay = Wire.decode_body(kind, body)
        return unless relay["target"] == @identity.peer_id

        inner = Wire.decode_frame(relay["frame"] || "".b)
        # HLC round four, 2026-11-08 (D3): an inner frame that does not
        # decode counts as malformed, as one read from the connection does.
        @malformed_frames += 1 if inner.nil?
        handle(inner, relayed: true) if inner && inner["kind"] != "RELAY_FRAME" && accepts?(inner)
      when "BLOCK_WANT"
        want = Wire.decode_body(kind, body)
        data = @blocks[want["cid"]]
        send_addressed("BLOCK", Wire.block_body(want["cid"], data), sender) if data
      when "BLOCK"
        block = Wire.decode_body(kind, body)
        if block["bytes"].is_a?(String) && @block_asked.key?(block["cid"]) && Wire.block_cid(block["bytes"]) == block["cid"]
          @blocks[block["cid"]] = block["bytes"]
          wake_fold_waiters
        end
      when Wire::KIND_GROUP_AD then on_group_ad(body)
      when "RUMOR" then on_rumor(Wire.decode_body(kind, body))
      when "PULL_RESP" then on_pull_resp(Wire.decode_body(kind, body))
      else
        @ignored_kinds[kind.to_s] += 1
      end
    end

    # The reader filter: a verified envelope for our group that is either
    # unaddressed or addressed to us (ASF-010).
    def accepts?(env)
      !env.nil? && env["group"] == @group && (env["to"].nil? || env["to"] == @identity.peer_id)
    end

    def inspect = "#<AgentSpaces::Peer #{@identity.peer_id} group=#{@group} connected=#{connected?}>"

    private

    def monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    CARD_TYPES = %w[AppCard AgentCard].freeze
    private_constant :CARD_TYPES

    def positive!(value, name)
      raise ArgumentError, "#{name} must be a positive integer: #{value.inspect}" unless value.is_a?(Integer) && value.positive?

      value
    end

    def count(counter) = @state_lock.synchronize { instance_variable_set(counter, instance_variable_get(counter) + 1) }

    # The card this peer signs (SPEC v0.1.32 §6.1a.2 and §6.1a.5; AppCard
    # origin and formats, 2026-11-09). A dial-only client cannot see every
    # member's hints, so its gate stays closed (FR-7): an AppCard leaves out
    # origin, formats, and a host whose signOn is idp, and counts in
    # app_cards_downgraded. It runs no content swarm, so it issues no stub,
    # and a card past the spill threshold travels inline in full and counts
    # in cards_oversize_inline (FR-12). A card past the warning threshold logs
    # a warning once per id and size (FR-13). A card that breaks its schema
    # raises Schema::Error.
    def issue_card(ad_type, card)
      raise ArgumentError, "this client runs no content swarm, so it issues no stub: #{card['id']}" if card.key?("spill")

      # A card Java's constructors refuse reaches no reader, so it never goes out.
      Schema.check(ad_type, card)
      if ad_type == "AppCard"
        stripped = Cards.without_gated_fields(card)
        count(:@app_cards_downgraded) unless stripped == card
        card = stripped
      end
      size = CBOR.dump(card).bytesize
      warn_card_size(ad_type, card, size)
      count(:@cards_oversize_inline) if size > Cards::CARD_SPILL_THRESHOLD_BYTES
      card
    end

    def warn_card_size(ad_type, card, size)
      return if size <= Cards::CARD_SPILL_WARN_BYTES

      previous = @state_lock.synchronize do
        held = @card_size_warned[card["id"]]
        @card_size_warned[card["id"]] = size
        held
      end
      return if previous == size

      fate = if size <= Cards::CARD_SPILL_THRESHOLD_BYTES then "it travels inline until it passes the threshold"
             else "it travels inline, since this client runs no content swarm"
             end
      kind = ad_type == "AppCard" ? "AppCard (kind #{card['kind']})" : ad_type
      @logger&.warn("#{kind} #{card['id']} encodes to #{size} bytes, past the #{Cards::CARD_SPILL_WARN_BYTES}-byte " \
                    "warning; the spill threshold is #{Cards::CARD_SPILL_THRESHOLD_BYTES} bytes, and #{fate}")
    end

    def complete_stub(card, spill, store)
      document = store.get(spill["root"], spill["size"])
      unless document.bytesize == spill["size"]
        raise ArgumentError, "the parts document is #{document.bytesize} bytes; the stub states #{spill['size']}"
      end
      # This client runs no content swarm whose piece check would refuse other
      # bytes, so it checks the root itself (AppCard origin and formats,
      # 2026-11-09, FR-15).
      root = Cards.content_root(document)
      raise ArgumentError, "the parts document's content root #{root} is not spill.root" unless root == spill["root"]

      kind = Cards.kind_of(card)
      full = Cards.card_complete(card, Schema.load("#{kind}.Parts", document))
      Schema.check(kind, full)
      full
    rescue ArgumentError, CBOR::Error => e
      count(:@spills_refused)
      raise ResolveError, "the parts document of #{card['id']} does not complete its stub: #{e.message}"
    end

    # The cache's admission (AdCache.admit; SPEC §6.3 v0.1.32, FR-11): a new id
    # needs room under both bounds and a newer version room under the byte
    # budget, judged again after the expired entries leave; a refusal keeps
    # what the cache holds and counts. An older or equal version leaves the
    # held one in place and counts nothing, as AdCache.admit does. Returns the
    # held entry, or nil when the cache refused the advertisement.
    def admit_ad(entry, issued)
      id = entry["ad"]["id"]
      held = @ads[id]
      return held if held && Instants.parse_millis(held["ad"]["issued"]) >= issued

      unless ad_fits?(id, entry)
        evict_expired_ads
        unless ad_fits?(id, entry)
          @ads_refused_cache_full += 1
          return nil
        end
      end
      previous = @ads[id]
      @ad_bytes += entry["bytes"] - previous.to_h["bytes"].to_i
      @ads[id] = entry
    end

    def ad_fits?(id, entry)
      previous = @ads[id]
      return @ads.size < @ad_cache_max_entries && @ad_bytes + entry["bytes"] <= @ad_cache_max_bytes if previous.nil?

      @ad_bytes - previous["bytes"].to_i + entry["bytes"] <= @ad_cache_max_bytes
    end

    def evict_expired_ads
      now = now_ms
      @ads.delete_if do |_, held|
        expired = held["expires"] <= now
        @ad_bytes -= held["bytes"].to_i if expired
        expired
      end
    end

    def check_fork!
      return unless @inherited || Process.pid != @pid

      raise ForkError, "this peer was started in process #{@pid} and is used in #{Process.pid}; " \
                       "call AgentSpaces.after_fork (or start a new Peer) in the child"
    end

    def dialer_for(scheme)
      @dialers.each { |dialer, schemes| return dialer if schemes.include?(scheme) }
      nil
    end

    def expand_seeds(seeds)
      expanded = []
      Array(seeds).each do |value|
        seed = Seed.parse(value)
        if dialer_for(seed.scheme).nil?
          @logger&.warn("agentspaces: skipping seed #{seed}: no dialer for the #{seed.scheme} scheme")
          next
        end
        # A web seed keeps its name: the Host header, SNI, and the
        # certificate's host check all need it.
        unless %w[tcp tls].include?(seed.scheme)
          expanded << seed unless expanded.include?(seed)
          next
        end
        addresses = begin
          Addrinfo.getaddrinfo(seed.host, seed.port, nil, :STREAM).map(&:ip_address).uniq
        rescue SocketError
          [seed.host]
        end
        addresses = [seed.host] if addresses.empty?
        addresses.each do |address|
          candidate = seed.with(host: address)
          expanded << candidate unless expanded.include?(candidate)
        end
      end
      expanded
    end

    def open_channel(seed, timeout: 10)
      check_fork!
      dialer = dialer_for(seed.scheme)
      raise IOError, "no dialer serves the #{seed.scheme} scheme" if dialer.nil?

      @channel = dialer.open(seed, identity: @identity, timeout: timeout)
      @link_since = monotonic
      @session = nil # a session ends with its connection
      @seed = seed
      @running = true
      start_thread("agentspaces-reader") { read_loop }
      start_thread("agentspaces-ticker") { tick_loop } if @threads.none? { |t| t.name == "agentspaces-ticker" }
    end

    def start_thread(name, &block)
      thread = Thread.new do
        Thread.current.name = name
        block.call
      end
      thread.report_on_exception = false
      @threads << thread
      thread
    end

    # Sends one signed frame over the current channel; a failed send closes
    # the channel and the reader reconnects.
    def send_frame(kind, body, to = nil)
      channel = @channel
      return if channel.nil?

      session = @session
      # An unaddressed frame under a confirmed session is addressed to the
      # session's peer, so it can travel tagged (the Java node addresses too).
      to ||= session.remote if session&.confirmed
      env = Wire.envelope(@group, kind, @identity.peer_id, Wire.hlc_now(@identity.peer_id, now_ms), body, to)
      key = session&.key_for(to, kind)
      frame = if key
                @session_frames_sent += 1
                Session.encode_frame(env, key)
              else
                Wire.encode_frame(env, @identity)
              end
      channel.send_frame(frame)
    rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
      channel&.close
    end

    def read_loop
      while @running
        channel = @channel
        break if channel.nil?

        begin
          frame = channel.read_frame
          begin
            env, auth = Wire.decode_frame_detailed(frame, attested: channel.attested_peer,
                                                          session: @session&.established)
            # A frame under the session proves the other end holds the key.
            @session.confirmed = true if auth == :session && @session
            if env.nil?
              @malformed_frames += 1
            elsif accepts?(env)
              handle(env)
            end
          rescue StandardError
            # One hostile frame must not kill the reader (ASF-015).
            @malformed_frames += 1
          end
        rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
          channel.close
          @channel = nil if @channel.equal?(channel)
          break unless @running && @seed && reconnect
        end
      end
    end

    # Re-leases the self-advertisement on the advertisement interval, so a
    # long-running peer stays a member past the advertisement's TTL.
    def tick_loop
      last = monotonic
      while @running
        sleep 0.25
        next unless monotonic - last >= @peer_ad_interval

        last = monotonic
        introduce if connected?
      end
    end

    def candidate_seeds
      return @seed ? [@seed] : [] if @seeds.empty?

      index = @seeds.index(@seed)
      index.nil? ? @seeds.dup : @seeds[(index + 1)..] + @seeds[0..index]
    end

    # After a lost connection: dials again (every seed, the next first), then
    # re-introduces and re-pulls (ROBUSTNESS.md 3.6). The pauses between rounds
    # back off from reconnect_interval to six times it (5, 10, 20, 30 s) with a
    # random spread, so the clients of a seed that restarts do not all dial it at
    # once, and the dials go on until the owner closes the peer (swarm retries,
    # ROBUSTNESS.md 10.3 E5). A link that ended within reconnect_interval of
    # its dial counts as a failed round, so a seed that accepts each dial and
    # drops it at once gets the same pauses and no dial loop (ROBUSTNESS.md
    # 10.6). A bootstrapped peer reads its beacon document again every
    # reconnect_window with nothing reachable, and keeps the seeds it has when
    # the beacon is unreachable too.
    def reconnect
      if monotonic - @link_since < @reconnect_interval
        @quick_drops += 1
        sleep(reconnect_pause(@quick_drops))
      else
        @quick_drops = 0
      end
      deadline = monotonic + @reconnect_window
      rounds = 0
      while @running
        if monotonic >= deadline
          deadline = monotonic + @reconnect_window
          unless @refresh_seeds.nil?
            fresh = begin
              expand_seeds(@refresh_seeds.call)
            rescue StandardError
              []
            end
            @seeds = fresh unless fresh.empty?
          end
        end
        candidate_seeds.each do |seed|
          return false unless @running

          begin
            @channel = dialer_for(seed.scheme).open(seed, identity: @identity)
            @link_since = monotonic
            @session = nil
          rescue SystemCallError, IOError, SocketError, OpenSSL::SSL::SSLError
            next
          end
          @seed = seed
          @reconnects += 1
          introduce
          announce_channel
          pull_revocations
          pull_ads if @pulled_ads
          @pulled_spaces.to_a.each { |space| pull_space(space) }
          return true
        end
        rounds += 1
        sleep(reconnect_pause(rounds))
      end
      false
    end

    # The pause after the rounds-th failed round of dials: reconnect_interval
    # doubling to six times it, with a random spread of up to a quarter.
    def reconnect_pause(rounds)
      [6 * @reconnect_interval, @reconnect_interval * (2**[rounds - 1, 3].min)].min * (1 + (rand / 4))
    end

    def notify_observers
      @observers.dup.each do |observer|
        yield observer
      rescue StandardError => e
        @logger&.warn("agentspaces: observer failed: #{e.class}: #{e.message}")
      end
    end

    def sweep_loop
      until @closed
        sleep 0.25
        @observers.dup.each do |observer|
          observer.sweep if observer.watching?
        rescue StandardError
          nil
        end
      end
    end

    # Opens this peer's half of a session (PeerNode.maybeSessionHello): once
    # per connection, in session mode, toward a member whose advertisement
    # carries the hint, on a connection the transport could not attest. A
    # frame past the introduction proves the member admitted us.
    def maybe_session_hello(peer)
      channel = @channel
      return if @channel_auth != :session || channel.nil? || !@session_peers.include?(peer)
      return unless channel.attested_peer.nil?

      session = (@session ||= Session.new(@identity.peer_id))
      send_session_hello(session, peer, nil) if session.may_open?(now_ms)
    end

    # Sends this peer's half (opening when echo is nil), fully signed.
    def send_session_hello(session, peer, echo)
      session.sent!(now_ms, !echo.nil?)
      env = Wire.envelope(@group, "SESSION_HELLO", @identity.peer_id, Wire.hlc_now(@identity.peer_id, now_ms),
                          session.hello(peer, echo), peer)
      @channel&.send_frame(Wire.encode_frame(env, @identity))
    rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
      nil
    end

    # Handles a SESSION_HELLO (PeerNode.onSessionHello): it counts only when
    # it names this peer and is younger than the age window; an opening
    # hello is answered with this peer's half echoing the opener's nonce.
    def on_session_hello(env)
      channel = @channel
      return if @channel_auth != :session || channel.nil? || !channel.attested_peer.nil?

      hello = Session.parse_hello(env["body"] || "".b)
      return if hello.nil? || hello[:remote] != @identity.peer_id
      return if now_ms - Wire.hlc_physical(env["stamp"]) > Session::HELLO_MAX_AGE_MILLIS

      session = (@session ||= Session.new(@identity.peer_id))
      send_session_hello(session, env["from"], hello[:nonce]) if session.accept(env["from"], hello) == :answer
    end

    # On a connection the transport attested, announce that this peer
    # accepts channel-attested frames there (SPEC 5.6), so the remote stops
    # signing every frame toward it; the announcement itself is signed.
    def announce_channel
      remote = @channel&.attested_peer
      send_frame("CHANNEL_HELLO", Wire.channel_hello_body(true, remote), remote) if remote
    end

    def wake_fold_waiters
      @fold_lock.synchronize do
        @fold_count += 1
        @fold_condition.broadcast
      end
    end

    def on_pipe(sender, frame)
      if frame["capability"] == Wire::RELAY_SIGNAL_CAPABILITY
        @relay_signals << Schema.load("PeerNode.RelaySignal", frame["payload"])
        @relay_signals.shift while @relay_signals.size > 64
        return
      end
      @pipe_handlers[frame["capability"]]&.call(sender, frame["payload"] || "".b)
    end

    def on_rumor(rumor)
      stream = rumor["streamId"].to_s
      if Revocation::STREAMS.include?(stream)
        @revocations.accept(stream, rumor["payload"], now_ms)
      elsif stream == "peers"
        accept_peer_ad(rumor["payload"])
      elsif stream == "ads"
        accept_ad(CBOR.load(rumor["payload"]))
      elsif stream.start_with?("space:")
        delta = space_delta(rumor["payload"], "SpaceWire.Delta")
        return if delta.nil?

        # Claim before state: a completion authenticates against the claim.
        fold_claim(delta["claimEntry"], delta["claim"]) if delta["claimEntry"] && delta["claim"].is_a?(Hash)
        fold_state(name_recordless(delta["state"], rumor["itemId"])) if delta["state"].is_a?(Hash)
      end
    end

    # One delta per stream. A delta that does not decode drops alone, and
    # the peer folds the rest of the response (HLC round four, 2026-11-08 (D5)):
    # a space delta counts in deltas_undecodable, any other in malformed_frames.
    def on_pull_resp(resp)
      resp["deltas"].each do |stream, delta_bytes|
        next if delta_bytes.empty?

        if stream.start_with?("space:")
          sync = space_delta(delta_bytes, "SpaceWire.SyncDelta")
          next if sync.nil?

          (sync["claims"] || {}).each { |entry_id, signed| fold_claim(entry_id, signed) }
          (sync["states"] || []).each { |dto| fold_state(dto) }
          next
        end
        record = PULL_DELTAS[stream]
        next if record.nil?

        delta = begin
          Schema.load(record, delta_bytes)
        rescue CBOR::Error
          @malformed_frames += 1
          next
        end
        if stream == "ads"
          (delta["ads"] || []).each { |stored| accept_ad(stored) }
        else
          (delta || []).each { |signed| @revocations.accept_signed(stream, signed, now_ms) }
        end
      end
    end

    # A space delta decoded from bytes under record (SpaceWire.Delta from a
    # RUMOR, SpaceWire.SyncDelta from a PULL_RESP), or nil, counted in
    # deltas_undecodable, when it does not decode, so the whole carrier drops
    # as Java's ReplicatedSpace drops it (HLC round four, 2026-11-08 (D3, D5)).
    # HLC round six, 2026-11-08 (F1, F3): it decodes only in the wire
    # encoding and under its record, each stamp a canonical stamp, each
    # agent id in the AgentId grammar, and each number in its declared type.
    def space_delta(bytes, record)
      delta = Schema.load(record, bytes)
      prune_claims
      delta
    rescue CBOR::Error
      count_undecodable
    end

    # HLC round six, 2026-11-08 (R10): drops each claim on an entry this
    # replica does not hold once the claim's expiry passes, so claims on
    # entries it never held (this peer collects no entry) cannot grow the
    # claim map without bound. It runs between carriers, never inside one, so
    # a completion still finds the claim it travels with, and it runs when
    # the map has doubled since the last pass, so the work stays proportional
    # to the claims folded.
    def prune_claims
      @state_lock.synchronize do
        next if @claims.size < @claims_prune_at

        now = now_ms
        @claims.delete_if { |entry_id, signed| !@states.key?(entry_id) && signed["claim"]["expiresAtMillis"] <= now }
        @claims_prune_at = [2 * @claims.size, CLAIMS_PRUNE_FLOOR].max
      end
    end

    # Whether a decoded value holds to a record of the wire encoding (HLC
    # round six, 2026-11-08, F1 and F3).
    def decodes?(record, value)
      Schema.check(record, value)
      true
    rescue CBOR::Error
      false
    end

    def count_undecodable
      @state_lock.synchronize { @deltas_undecodable += 1 }
      nil
    end

    # A GROUP_AD answer: accepted only while a join by GroupID is pending and
    # only when it passes the four checks and derives to the wanted group.
    def on_group_ad(body)
      @founding_lock.synchronize do
        return unless @founding.nil?

        signed = Wire.decode_body(Wire::KIND_GROUP_AD, body)
        return unless Founding.verify(signed) == @group

        @founding = signed
        @founding_ready.broadcast
      end
    end

    # HLC round six, 2026-11-08 (F3): the SignedPeerAd and its
    # PeerAdvertisement hold to their records (ad-02 to ad-06).
    def accept_peer_ad(payload)
      signed = Schema.load("PeerNode.SignedPeerAd", payload)
      ad_bytes = signed["adBytes"]
      key = signed["publicKey"]
      return unless key&.bytesize == 32 && Crypto.port.verify(key, ad_bytes, signed["signature"])

      ad = Schema.load("PeerAdvertisement", ad_bytes)
      return unless ad["issuer"] == Derive.id(key) && ad["issuer"] != @identity.peer_id

      @members[ad["issuer"]] = ad
      if @channel_auth == :session && (ad["resourceHints"] || {})[Session::HINT] == "1"
        @session_peers << ad["issuer"]
      else
        @session_peers.delete(ad["issuer"])
      end
    rescue CBOR::Error, TypeError
      nil
    end

    def join(previous, incoming)
      merged = previous.dup
      merged["adds"] = union_dots(previous["adds"], incoming["adds"])
      merged["removes"] = union_dots(previous["removes"], incoming["removes"])
      if lease_newer?(incoming["leaseStamp"], previous["leaseStamp"])
        merged["leaseStamp"] = incoming["leaseStamp"]
        merged["leaseValue"] = incoming["leaseValue"]
      end
      merged["completed"] = previous["completed"] ? true : (incoming["completed"] ? true : false)
      merged
    end

    # Whether an incoming lease stamp supersedes the held one. fold_state
    # admits only stamps the strict parser accepts, and only states that
    # carry a lease stamp (HLC round five, 2026-11-08 (E7)).
    def lease_newer?(incoming, held)
      (Wire.hlc_order(incoming) <=> Wire.hlc_order(held)).positive?
    end

    # HLC logical counter, 2026-11-08 (Rust team report): the stamps a state
    # carries, as ReplicatedSpace.stampsAcceptable reads them. The record's
    # issue stamp is required, and the lease stamp and an agent-signed
    # state's signedAt are judged when present: signedAt is a stamp like any
    # other (HLC round four, 2026-11-08 (D1)).
    def state_stamps_acceptable?(dto, record)
      Wire.hlc_acceptable?(record["issued"]) &&
        %w[leaseStamp signedAt].all? { |field| dto[field].nil? || Wire.hlc_acceptable?(dto[field]) }
    end

    # The latest of the stamps the far-future rule judges in a state: the
    # record's issue stamp, the lease stamp, and an agent-signed state's
    # signedAt (HLC round six, 2026-11-08 (F4)), which the certificate's
    # drift ceiling no longer judges in verify_state.
    def state_lead_ms(dto, record)
      [record["issued"], dto["leaseStamp"], dto["signedAt"]].compact.map { |stamp| Wire.hlc_physical(stamp) }.max
    end

    # The key a state offer is judged under: its entry id, its issue stamp,
    # and its signed view, as Java's stateOfferKey builds it (HLC round four,
    # 2026-11-08 (D5)).
    def state_offer_key(dto, record)
      view = Crypto.port.sha256(state_view_bytes(dto, record)).unpack1("H*")
      "state:#{record['entryId']}=#{record['issued']}/#{view}"
    end

    # The key a claim offer is judged under: its encoding and its entry id,
    # as Java's claimOfferKey builds it (HLC round four, 2026-11-08 (D5)).
    def claim_offer_key(entry_id, claim)
      "claim:#{Crypto.port.sha256(CBOR.dump(claim)).unpack1('H*')}@#{entry_id}"
    end

    # Counts a verified state refused for its stamps, under reason :logical
    # or :far_future.
    def refuse_state(dto, record, reason) = refuse_offer(state_offer_key(dto, record), reason)

    # Counts a verified claim refused for its stamp, under reason :logical
    # or :far_future.
    def refuse_claim(entry_id, claim, reason) = refuse_offer(claim_offer_key(entry_id, claim), reason)

    # Counts one refusal once per distinct offer: a partner re-offering it
    # every anti-entropy round, or a relay re-encoding its unsigned content,
    # counts once (HLC canonical stamps, 2026-11-08). HLC round five,
    # 2026-11-08 (E2): a logical refusal counts in stamps_logical_refused and
    # a hostile far-future one in stamps_far_future_refused.
    def refuse_offer(key, reason)
      return unless remember_offer(@refused_offers, key)

      @state_lock.synchronize do
        if reason == :logical
          @stamps_logical_refused += 1
        else
          @stamps_far_future_refused += 1
        end
      end
      nil
    end

    # Counts one deferral once per distinct offer, so a partner re-offering
    # it every round before the wall catches up counts once (HLC round five,
    # 2026-11-08 (E2)).
    def defer_offer(key)
      @state_lock.synchronize { @stamps_far_future_deferred += 1 } if remember_offer(@deferred_offers, key)
      nil
    end

    # Records key in memory and returns whether it was new. A key offered
    # again moves to the young end, and past REFUSED_STAMP_MEMORY keys the
    # least recently offered one leaves (HLC round five, 2026-11-08 (E14)).
    # The peer judges every offer afresh; the memory only stops a second
    # count (HLC round five, 2026-11-08 (E5)).
    def remember_offer(memory, key)
      @state_lock.synchronize do
        if memory.key?(key)
          memory[key] = memory.delete(key)
          next false
        end
        memory[key] = true
        memory.shift if memory.size > REFUSED_STAMP_MEMORY
        true
      end
    end

    # The bytes a state's signature covers (StateSignView).
    def state_view_bytes(dto, record)
      CBOR.dump(Wire.state_sign_view(record["spaceId"], record["entryId"], dto["adds"] || [], dto["removes"] || [],
                                     dto["leaseStamp"], dto["leaseValue"], dto["completed"] ? true : false,
                                     dto["signer"], dto["signedAt"]))
    end

    def union_dots(left, right)
      seen = {}
      (Array(left) + Array(right)).each do |dot|
        seen[[dot["replica"].to_s, dot["counter"].to_i]] = dot if dot.is_a?(Hash)
      end
      seen.keys.sort.map { |k| seen[k] }
    end

    # Authenticates a received state DTO: the record signature and the state
    # signature. The party is the claim holder for a completion and the
    # issuer otherwise; an agent-attested party's transitions must be
    # agent-signed (A6, v0.1.13).
    # Whether every dot of a state names its record issuer's peer as the
    # replica, as Java's ReplicatedSpace.dotsBoundToIssuer requires (ASF-025):
    # a writer adds and removes only its own dots, so a state whose dots name
    # another replica drops uncounted (HLC round six, 2026-11-08, reference
    # rule; vector delta-13).
    def dots_bound_to_issuer?(dto, record)
      issuer_peer = record["issuer"].to_s.split("/", 2).first
      (Array(dto["adds"]) + Array(dto["removes"])).all? { |dot| dot.is_a?(Hash) && dot["replica"] == issuer_peer }
    end

    def verify_state(dto, record)
      issuer_key = dto["issuerPublicKey"]
      return false unless issuer_key.is_a?(String) && issuer_key.bytesize == 32

      return false unless Wire.verify_record(record, issuer_key, dto["agentCertificate"])

      state_sig = dto["stateSig"]
      return false unless state_sig.is_a?(String)

      if dto["completed"]
        signed = @claims[record["entryId"]]
        return false unless signed

        claim = signed["claim"] || {}
        return false unless claim["entryId"] == record["entryId"] && claim["spaceId"] == record["spaceId"]
        return false unless Wire.verify_claim_proof(signed)

        signer_key = signed["holderKey"]
        party = claim["holder"]
        party_attested = !signed["holderCertificate"].nil?
      else
        signer_key = issuer_key
        party = record["issuer"]
        party_attested = !dto["agentCertificate"].nil?
      end
      return false unless signer_key.is_a?(String) && signer_key.bytesize == 32

      signer = dto["signer"]
      view = state_view_bytes(dto, record)
      unless signer.nil?
        certificate = dto["stateCertificate"]
        signed_ms = Wire.hlc_physical(dto["signedAt"])
        return signer == party && certificate.is_a?(Hash) &&
               Certificates.verify_covering(certificate, signer_key, party, signed_ms) &&
               Crypto.port.verify(certificate["agentPublicKey"], view, state_sig)
      end
      return false if party_attested

      Crypto.port.verify(signer_key, view, state_sig)
    rescue ArgumentError, TypeError
      false
    end

    # SPEC 5.6's freeze rule at merge.
    def refused_for_revocation?(dto, record)
      if dto["completed"]
        signed = @claims[record["entryId"]] || {}
        holder = (signed["claim"] || {})["holder"]
        certificate = signed["holderCertificate"] || {}
        return !holder.nil? && @revocations.refuses?(holder, certificate["agentPublicKey"], signing_ms(dto, nil))
      end
      issuer = record["issuer"]
      certificate = dto["agentCertificate"] || {}
      state_certificate = dto["stateCertificate"] || {}
      lease_ms = begin
        Wire.hlc_physical(dto["leaseStamp"])
      rescue ArgumentError, TypeError
        nil
      end
      return false if issuer.nil?

      @revocations.refuses?(issuer, certificate["agentPublicKey"], signing_ms(dto, lease_ms)) ||
        (!dto["signer"].nil? && @revocations.refuses?(issuer, state_certificate["agentPublicKey"],
                                                      signing_ms(dto, nil)))
    end

    def signing_ms(dto, fallback)
      dto["signedAt"] ? Wire.hlc_physical(dto["signedAt"]) : fallback
    rescue ArgumentError, TypeError
      fallback
    end

    def available(type_name, now)
      @states.to_a.select do |entry_id, dto|
        record = dto["record"] || {}
        # completed, or withdrawn by a cancel (core cancel events, 2026-11-09)
        next false unless record["type"] == type_name && Peer.present?(dto)
        next false if Peer.lease_of(dto).fetch("expiresAtMillis", 0).to_i <= now

        claim = claim_of(entry_id)
        !(claim && claim.fetch("expiresAtMillis", 0).to_i > now)
      end
    end
  end
end
