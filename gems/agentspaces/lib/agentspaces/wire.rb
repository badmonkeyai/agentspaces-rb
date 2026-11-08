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

require "securerandom"

module AgentSpaces
  # The wire protocol (SPEC 9): signed CBOR envelopes, the bodies this peer
  # speaks, and the entry-record structures for space writes. Every Hash here
  # lists its keys in the Java record's field order, because the envelope
  # signature covers the canonical CBOR and byte order is meaning.
  module Wire
    # The wire version every envelope carries and the only one a receiver accepts.
    VERSION = 3
    KIND_GROUP_AD_WANT = "GROUP_AD_WANT"
    KIND_GROUP_AD = "GROUP_AD"
    # Largest frame accepted or sent, mirroring the JVM transport cap (ASF-016).
    MAX_FRAME_BYTES = 8 * 1024 * 1024
    # Payloads above this travel as a block and the record carries a reference (SPEC 7.1).
    INLINE_PAYLOAD_LIMIT = 64 * 1024
    # ASF-004 bounds, mirroring ReplicatedSpace.
    MAX_CLAIM_EPOCH_JUMP = 1 << 20
    MAX_CLAIM_HOLD_MILLIS = 24 * 60 * 60 * 1000
    # How far ahead of this peer's wall clock a remote stamp may run (ASF-020/043).
    MAX_HLC_SKEW_MILLIS = 10 * 60 * 1000
    # HLC canonical stamps, 2026-11-08: how far past wall + MAX_HLC_SKEW_MILLIS
    # a frame's stamp may run and still read as host clock skew. An attacker
    # can drag an honest peer's clock to its own wall + MAX_HLC_SKEW_MILLIS,
    # and a receiver whose wall trails that peer's by a few seconds then sees
    # its frames just past the bound; the filter drops and counts them as
    # skewed, where a Java receiver strikes nobody for them.
    HLC_SKEW_MARGIN_MILLIS = 5_000
    # HLC logical counter, 2026-11-08 (Rust team report): the largest logical
    # counter a remote stamp may carry. Every merge point refuses a stamp above
    # it, and the local clock carries into the next millisecond at it, so a
    # signed stamp with a saturated counter can never freeze this clock or a
    # replica's leases and claims. An honest counter resets every millisecond
    # and stays far below 2^16; Java, Rust, Python, and TypeScript share the value.
    HLC_LOGICAL_LIMIT = 65_536
    # The largest physical part Java's Long.parseLong reads.
    HLC_PHYSICAL_MAX = (2**63) - 1
    # The largest logical part Java's Integer.parseInt reads. A stamp whose
    # counter lies above HLC_LOGICAL_LIMIT and at most this decodes, so a
    # signature over it verifies, and every merge point then refuses it.
    HLC_LOGICAL_DECODE_MAX = (2**31) - 1
    # HLC canonical stamps, 2026-11-08: the one stamp text every
    # implementation decodes. Physical and logical parts are "0" or a non-zero
    # ASCII digit followed by ASCII digits, with no sign, fraction, exponent,
    # whitespace, or leading zero, and no more digits than the largest value
    # of each part holds; the node is non-empty and holds no colon and no
    # control character (U+0000..U+001F, U+007F). The text of a stamp that
    # matches equals its re-encoding, so a signer's bytes and a reader's
    # stamp never differ.
    HLC_STAMP = /\A(0|[1-9][0-9]{0,18}):(0|[1-9][0-9]{0,9}):([^:\x00-\x1F\x7F]+)\z/
    # ROBUSTNESS.md 3.3 and 3.4: the stale bound and the replay memory.
    MAX_FRAME_AGE_MILLIS = 5 * 60 * 1000
    FRAME_FILTER_CAPACITY = 4096
    RELAY_SIGNAL_CAPABILITY = "aspace:cap/relay-signal"
    HOPS = 6

    # Admits each verified frame once, fresh, judging its stamp in the order
    # of SPEC 9 as Java's PeerNode does (HLC canonical stamps, 2026-11-08).
    # It drops each refusal silently and counts it:
    # 1. refused, a stamp that does not decode (Wire.hlc_decode);
    # 2. stale, a stamp older than MAX_FRAME_AGE_MILLIS;
    # 3. replayed, a (sender, stamp) pair it has seen; the memory records
    #    every fresh frame before the checks below, as Java's does;
    # 4. skewed, a stamp past wall + MAX_HLC_SKEW_MILLIS by at most
    #    HLC_SKEW_MARGIN_MILLIS, and ahead, a stamp further past it;
    # 5. refused, a logical counter above HLC_LOGICAL_LIMIT.
    # A Ruby peer keeps no strikes, so these counts are its whole record.
    class FrameFilter
      attr_reader :stale, :ahead, :skewed, :refused, :replayed

      def initialize(capacity = FRAME_FILTER_CAPACITY)
        @seen = {}
        @capacity = capacity
        @stale = 0
        @ahead = 0
        @skewed = 0
        @refused = 0
        @replayed = 0
        @lock = Mutex.new
      end

      def admit(env, now_ms)
        stamp = env["stamp"]
        decoded = Wire.hlc_decode(stamp)
        @lock.synchronize do
          if decoded.nil?
            @refused += 1
            return false
          end
          physical, logical = decoded
          if now_ms - physical > MAX_FRAME_AGE_MILLIS
            @stale += 1
            return false
          end
          # A decoded stamp is canonical, so its text is the replay key.
          key = "#{env['from']}|#{stamp}"
          if @seen.key?(key)
            @replayed += 1
            return false
          end
          @seen[key] = true
          @seen.shift if @seen.size > @capacity
          past = physical - now_ms - MAX_HLC_SKEW_MILLIS
          if past > HLC_SKEW_MARGIN_MILLIS
            @ahead += 1
            return false
          end
          if past.positive?
            @skewed += 1
            return false
          end
          if logical > HLC_LOGICAL_LIMIT
            @refused += 1
            return false
          end
          true
        end
      end

      def to_h
        { "stale" => @stale, "ahead" => @ahead, "skewed" => @skewed, "refused" => @refused, "replayed" => @replayed }
      end
    end

    @hlc_lock = Mutex.new
    @hlc_state = {}

    class << self
      # A fresh hybrid-logical-clock stamp in the Java string form: physical
      # time never runs backwards, and the logical counter increments within
      # one millisecond, so stamps after an observed remote stamp sort after it.
      # A counter at HLC_LOGICAL_LIMIT carries into the next millisecond, so the
      # clock never repeats a stamp and never sends a counter a receiver refuses
      # (HLC logical counter, 2026-11-08 (Rust team report)).
      def hlc_now(node, now_ms = nil)
        wall = now_ms.nil? ? (Time.now.to_f * 1000).to_i : Integer(now_ms)
        physical, logical = @hlc_lock.synchronize do
          physical, logical = @hlc_state.fetch(node, [0, -1])
          if wall > physical
            physical = wall
            logical = 0
          elsif logical >= HLC_LOGICAL_LIMIT
            physical += 1
            logical = 0
          else
            logical += 1
          end
          @hlc_state[node] = [physical, logical]
        end
        "#{physical}:#{logical}:#{node}"
      end

      # The physical milliseconds of an HLC stamp string: its signing time.
      # Raises ArgumentError for a stamp that does not decode. A signing time
      # never reaches a clock, so it is not judged against HLC_LOGICAL_LIMIT,
      # as Java reads a record's, claim's, or state's signedAt.
      def hlc_physical(stamp)
        decoded = hlc_decode(stamp) or raise ArgumentError, "not a canonical HLC stamp: #{stamp.inspect}"
        decoded.first
      end

      # The decoder every stamp read shares (HLC canonical stamps,
      # 2026-11-08): [physical, logical, node] for UTF-8 text in the
      # canonical grammar (HLC_STAMP) whose physical part fits a signed
      # 64-bit integer and whose logical part fits a signed 32-bit integer,
      # as Java's HlcTimestamp.parse reads it, and nil for anything else,
      # a CBOR byte string included.
      def hlc_decode(stamp)
        return nil unless stamp.is_a?(String) && [Encoding::UTF_8, Encoding::US_ASCII].include?(stamp.encoding)
        return nil unless stamp.valid_encoding?

        match = HLC_STAMP.match(stamp)
        return nil if match.nil?

        physical = Integer(match[1], 10)
        logical = Integer(match[2], 10)
        return nil if physical > HLC_PHYSICAL_MAX || logical > HLC_LOGICAL_DECODE_MAX

        [physical, logical, match[3]]
      end

      # The strict parser every merge and ordering point shares (HLC logical
      # counter, 2026-11-08 (Rust team report); HLC canonical stamps,
      # 2026-11-08): the decoded stamp when its logical counter is at most
      # HLC_LOGICAL_LIMIT, and nil for anything else.
      def hlc_parse(stamp)
        decoded = hlc_decode(stamp)
        decoded unless decoded.nil? || decoded[1] > HLC_LOGICAL_LIMIT
      end

      # True when the strict parser accepts a stamp, the test every merge
      # point applies before it folds a remote stamp (HLC logical counter,
      # 2026-11-08 (Rust team report)).
      def hlc_acceptable?(stamp) = !hlc_parse(stamp).nil?

      # A stamp as a comparable [physical, logical, node]; raises
      # ArgumentError for a stamp the strict parser refuses, so no ordering
      # ever compares a hostile counter.
      def hlc_tuple(stamp)
        hlc_parse(stamp) or raise ArgumentError, "not an acceptable HLC stamp: #{stamp.inspect}"
      end

      # A stamp's sort key in Java's HlcTimestamp order: physical, logical,
      # then the node by UTF-16 code units (HLC canonical stamps, 2026-11-08).
      # Raises ArgumentError for a stamp the strict parser refuses.
      def hlc_order(stamp)
        physical, logical, node = hlc_tuple(stamp)
        [physical, logical, java_order(node)]
      end

      # A String's sort key in Java's String.compareTo order, by UTF-16 code
      # units, where Ruby's String#<=> orders UTF-8 bytes, the code point
      # order: U+1F600 (D83D DE00) sorts before U+FF61 in Java and after it
      # in Ruby (HLC canonical stamps, 2026-11-08). Text that is not valid
      # Unicode keeps its byte order.
      def java_order(text)
        text.to_s.encode(Encoding::UTF_16BE).b
      rescue EncodingError
        text.to_s.b
      end

      # Merges a remote stamp into the local clock. The clock ignores a stamp
      # the strict parser refuses, and it clamps a remote physical part at one
      # millisecond inside the skew ceiling, so a carry after the merge lands
      # at most on the ceiling and a receiver's far-future check (ASF-020,
      # strictly greater than wall + MAX_HLC_SKEW_MILLIS) never strikes this
      # honest peer (HLC logical counter, 2026-11-08 (Rust team report)).
      def hlc_observe(node, stamp, now_ms = nil)
        parsed = hlc_parse(stamp)
        return if parsed.nil?

        wall = now_ms.nil? ? (Time.now.to_f * 1000).to_i : Integer(now_ms)
        remote = [[parsed[0], wall + MAX_HLC_SKEW_MILLIS - 1].min, parsed[1]]
        @hlc_lock.synchronize do
          current = @hlc_state.fetch(node, [0, -1])
          @hlc_state[node] = remote if (remote <=> current).positive?
        end
      end

      # An Envelope in field order: ver, group, kind, from, to, stamp, body.
      def envelope(group, kind, sender, stamp, body, to = nil)
        { "ver" => VERSION, "group" => group, "kind" => kind, "from" => sender, "to" => to,
          "stamp" => stamp, "body" => body.b }
      end

      # Signs and encodes an envelope into a frame (WireCodec.Signed).
      def encode_frame(env, identity)
        CBOR.dump({ "envelope" => env, "senderPublicKey" => identity.public_raw,
                    "signature" => identity.sign(CBOR.dump(env)) })
      end

      # Decodes and verifies a frame; returns the envelope Hash or nil. The
      # version check runs before any signature work (SPEC 9). A frame with
      # neither key nor signature is a channel-attested frame, accepted only
      # when the connection attests exactly its sender (SPEC 5.6).
      def decode_frame(frame, attested: nil, session: nil) = decode_frame_detailed(frame, attested:, session:)&.first

      # [envelope, auth] with auth :signed, :attested, or :session, or nil.
      # A session frame (no key, a 32-byte tag) is accepted on the connection
      # whose session names its sender when the tag verifies; a hello is
      # accepted only fully signed (SPEC 5.6).
      def decode_frame_detailed(frame, attested: nil, session: nil)
        signed = CBOR.load(frame)
        return nil unless signed.is_a?(Hash)

        env = signed["envelope"]
        return nil unless env.is_a?(Hash)
        return nil unless env["ver"].is_a?(Integer) && env["ver"] == VERSION

        key = signed["senderPublicKey"]
        signature = signed["signature"]
        hello = %w[SESSION_HELLO CHANNEL_HELLO].include?(env["kind"])
        if key.nil? && signature.nil?
          return !hello && attested && attested == env["from"] ? [env, :attested] : nil
        end
        if key.nil?
          peer, session_key = session
          return nil if hello || peer.nil? || peer != env["from"] || !signature.is_a?(String)
          return nil unless signature.bytesize == Session::MAC_LENGTH

          expected = Crypto.port.hmac_sha256(session_key, CBOR.dump(env)).b
          return Crypto.port.equal?(expected, signature.b) ? [env, :session] : nil
        end
        return nil unless key.is_a?(String) && key.bytesize == 32
        return nil unless Derive.id(key) == env["from"]
        return nil unless signature.is_a?(String) && Crypto.port.verify(key, CBOR.dump(env), signature)

        [env, :signed]
      rescue CBOR::Error, ArgumentError, TypeError, EncodingError
        nil
      end

      # ---------------------------------------------------------------- bodies

      def ping_body(nonce) = CBOR.dump({ "nonce" => nonce })

      def ack_body(nonce) = CBOR.dump({ "nonce" => nonce, "onBehalf" => nil })

      def rumor_body(stream_id, item_id, hops, payload)
        CBOR.dump({ "streamId" => stream_id, "itemId" => item_id, "hopsRemaining" => hops, "payload" => payload.b })
      end

      def digest_body(digests) = CBOR.dump({ "digests" => digests })

      # Bodies.ChannelHello: this node accepts channel-attested frames on a
      # connection whose remote end it attested as attested_remote.
      def channel_hello_body(accepts_bare, attested_remote)
        CBOR.dump({ "acceptsBare" => accepts_bare, "attestedRemote" => attested_remote })
      end

      # A RELAY_FRAME body (SPEC 5.4): the origin's complete signed frame for target.
      def relay_frame_body(target, frame, path = nil, hop = nil)
        body = { "target" => target, "frame" => frame.b }
        unless path.nil?
          body["path"] = path.to_a
          body["hop"] = hop.nil? ? 0 : Integer(hop)
        end
        CBOR.dump(body)
      end

      def block_cid(data) = Base58.multibase(Crypto.port.sha256(data.b))

      def block_want_body(cid) = CBOR.dump({ "cid" => cid })

      def block_body(cid, data) = CBOR.dump({ "cid" => cid, "bytes" => data.b })

      # The GROUP_AD_WANT envelope: the wanted group and an empty body.
      def group_ad_want_envelope(group, sender, stamp, to = nil)
        envelope(group, KIND_GROUP_AD_WANT, sender, stamp, "".b, to)
      end

      # The GROUP_AD body: the SignedGroupAdvertisement as canonical CBOR.
      def group_ad_body(signed)
        CBOR.dump({ "advertisement" => signed["advertisement"], "founderPublicKey" => signed["founderPublicKey"],
                    "signature" => signed["signature"] })
      end

      # ------------------------------------------------- capability payloads

      # The aggregate Roster's participant token: the first 8 bytes of
      # sha-256(PeerID) read big-endian as a signed int64.
      def aggregate_roster_token(peer_id) = Crypto.port.sha256(peer_id.encode(Encoding::UTF_8).b)[0, 8].unpack1("q>")

      # The aspace:cap/aggregate payload: exactly one variant, the rest null.
      def aggregate_frame(share: nil, extremum: nil, histogram: nil, roster: nil)
        variants = [share, extremum, histogram, roster]
        raise ArgumentError, "an aggregate Frame carries exactly one variant" unless variants.compact.size == 1

        { "share" => share, "extremum" => extremum, "histogram" => histogram, "roster" => roster }
      end

      def learn_content_id(encoding) = Derive.id(encoding)

      def learn_exchange(model_id, token, kind, round, inline: nil, cid: nil)
        { "modelId" => model_id, "token" => Integer(token), "kind" => kind, "round" => Integer(round),
          "inline" => inline, "cid" => cid }
      end

      # A PeerAdvertisement with no endpoints: the dial-only NAT posture.
      def peer_advertisement(group, identity, issued_iso, ttl_iso = "PT10M", resource_hints = nil)
        hints = (resource_hints || {}).to_h { |k, v| [k.to_s, v.to_s] }
        { "id" => "aspace://#{group}/peer/#{identity.peer_id}", "issuer" => identity.peer_id, "group" => group,
          "issued" => issued_iso, "ttl" => ttl_iso, "endpoints" => [], "roles" => [],
          "resourceHints" => CBOR.canonical_map(hints) }
      end

      # AdCache.StoredAd, the "ads" stream payload (SPEC 6.2).
      def stored_ad(ad_type, ad, identity)
        ad_bytes = CBOR.dump(ad)
        { "adType" => ad_type, "adBytes" => ad_bytes, "publicKey" => identity.public_raw,
          "signature" => identity.sign(ad_bytes) }
      end

      # The "peers" stream payload: PeerNode.SignedPeerAd.
      def signed_peer_ad(ad, identity)
        ad_bytes = CBOR.dump(ad)
        CBOR.dump({ "adBytes" => ad_bytes, "publicKey" => identity.public_raw, "signature" => identity.sign(ad_bytes) })
      end

      # --------------------------------------------------------- space writes

      # ReplicatedSpace's SignView: the record identity the signature covers.
      def sign_view(entry_id, space_id, type_name, payload, issuer, issued, key_epoch: nil, tags: nil,
                    payload_ref: nil)
        view = { "entryId" => entry_id, "spaceId" => space_id, "type" => type_name, "payload" => payload,
                 "payloadRef" => payload_ref, "issuer" => issuer, "issued" => issued,
                 "tags" => CBOR.canonical_map(tags || {}) }
        view["keyEpoch"] = key_epoch unless key_epoch.nil?
        view
      end

      # The SignView for an already-built record, from its own fields.
      def sign_view_of(record)
        view = { "entryId" => record["entryId"], "spaceId" => record["spaceId"], "type" => record["type"],
                 "payload" => record["payload"], "payloadRef" => record["payloadRef"], "issuer" => record["issuer"],
                 "issued" => record["issued"], "tags" => record["tags"] || {} }
        view["keyEpoch"] = record["keyEpoch"] unless record["keyEpoch"].nil?
        view
      end

      # TECH-SPEC 7.2's record rule: peer-signed, or agent-signed under a
      # peer certificate judged at the record's own issue stamp.
      def verify_record(record, issuer_public_raw, certificate, now_ms)
        return false unless issuer_public_raw.is_a?(String) && issuer_public_raw.bytesize == 32

        issuer = record["issuer"]
        return false unless issuer.is_a?(String) && issuer.start_with?("#{Derive.id(issuer_public_raw)}/")

        signature = record["sig"]
        return false unless signature.is_a?(String)

        view = CBOR.dump(sign_view_of(record))
        return Crypto.port.verify(issuer_public_raw, view, signature) if certificate.nil?

        signed_at = hlc_physical(record["issued"])
        return false unless Certificates.verify_at(certificate, issuer_public_raw, issuer, signed_at, now_ms)

        Crypto.port.verify(certificate["agentPublicKey"], view, signature)
      rescue ArgumentError, TypeError
        false
      end

      def sorted_dots(dots) = dots.sort_by { |d| [d["replica"].to_s, d["counter"].to_i] }

      # ReplicatedSpace's StateSignView (SPEC 11a); an agent-signed state
      # appends signer and signedAt.
      def state_sign_view(space_id, entry_id, adds, removes, lease_stamp, lease_value, completed, signer = nil,
                          signed_at = nil)
        view = { "spaceId" => space_id, "entryId" => entry_id, "adds" => sorted_dots(adds),
                 "removes" => sorted_dots(removes), "leaseStamp" => lease_stamp, "leaseValue" => lease_value,
                 "completed" => completed }
        view["signer"] = signer unless signer.nil?
        view["signedAt"] = signed_at unless signed_at.nil?
        view
      end

      # Signs a state DTO's mutable fields as its actor and returns the DTO.
      def sign_state(dto, identity, agent = nil, now_ms = nil)
        record = dto["record"] || {}
        signer = signed_at = certificate = nil
        unless agent.nil?
          signer = agent.agent_id
          signed_at = hlc_now(agent.agent_id, now_ms)
          certificate = agent.certificate_covering(hlc_physical(signed_at))
          raise ArgumentError, "#{agent.agent_id} holds no certificate covering #{signed_at}" if certificate.nil?
        end
        view = state_sign_view(record["spaceId"], record["entryId"], dto["adds"] || [], dto["removes"] || [],
                               dto["leaseStamp"], dto["leaseValue"], dto["completed"] ? true : false, signer,
                               signed_at)
        signed = dto.reject { |k, _| %w[stateSig stateCertificate signer signedAt].include?(k) }
        signed["stateSig"] = (agent || identity).sign(CBOR.dump(view))
        # EntryStateDto field order: ... stateSig, agentCertificate,
        # stateCertificate, signer, signedAt; the v0.1.13 fields omitted when absent.
        signed["agentCertificate"] = signed.delete("agentCertificate") if signed.key?("agentCertificate")
        unless agent.nil?
          signed["stateCertificate"] = certificate
          signed["signer"] = signer
          signed["signedAt"] = signed_at
        end
        signed
      end

      # Builds a full write delta; returns [entry_id, rumor_body_bytes].
      def entry_delta(space_name, group, type_name, payload, identity, agent_name, lease_millis, agent: nil,
                      now_ms: nil, tags: nil, payload_ref: nil)
        entry_id = SecureRandom.uuid
        space_id = Derive.space_id_local("#{group}/#{space_name}")
        issuer = agent.nil? ? identity.agent(agent_name) : agent.agent_id
        issued = hlc_now(issuer, now_ms)
        view = sign_view(entry_id, space_id, type_name, payload, issuer, issued, tags: tags, payload_ref: payload_ref)
        certificate = nil
        unless agent.nil?
          certificate = agent.certificate_covering(hlc_physical(issued))
          raise ArgumentError, "#{issuer} holds no certificate covering #{issued}" if certificate.nil?
        end
        signature = (agent || identity).sign(CBOR.dump(view))
        expires = (now_ms.nil? ? (Time.now.to_f * 1000).to_i : Integer(now_ms)) + Integer(lease_millis)
        record = { "entryId" => entry_id, "spaceId" => space_id, "type" => type_name, "payload" => payload,
                   "payloadRef" => payload_ref, "issuer" => issuer, "issued" => issued,
                   "lease" => { "holder" => issuer, "expiresAtMillis" => expires, "kind" => "WRITE" },
                   "tags" => view["tags"], "sig" => signature }
        dto = { "record" => record, "issuerPublicKey" => identity.public_raw,
                "adds" => [{ "replica" => identity.peer_id, "counter" => 1 }], "removes" => [],
                "leaseStamp" => issued,
                "leaseValue" => { "holder" => issuer, "expiresAtMillis" => expires, "kind" => "WRITE" },
                "completed" => false }
        dto["agentCertificate"] = certificate unless certificate.nil?
        dto = sign_state(dto, identity, agent, now_ms)
        delta = CBOR.dump({ "state" => dto, "claimEntry" => nil, "claim" => nil })
        [entry_id, rumor_body("space:#{space_name}", "w:#{entry_id}", HOPS, delta)]
      end

      # ----------------------------------------------------------- take claims

      # A TakeClaim in field order. The bid is a Float so it encodes as a CBOR
      # double, matching Java.
      def take_claim(entry_id, space_id, epoch, stamp, holder, bid, expires_at_millis)
        { "entryId" => entry_id, "spaceId" => space_id, "epoch" => epoch, "stamp" => stamp, "holder" => holder,
          "bid" => Float(bid), "expiresAtMillis" => expires_at_millis }
      end

      # A SignedClaim: the claim, the holder's peer key, the holder's signature;
      # an agent's claim appends the certificate covering the claim's stamp.
      def signed_claim(claim, identity, agent = nil)
        signed = { "claim" => claim, "holderKey" => identity.public_raw,
                   "signature" => (agent || identity).sign(CBOR.dump(claim)) }
        unless agent.nil?
          certificate = agent.certificate_covering(hlc_physical(claim["stamp"]))
          raise ArgumentError, "#{agent.agent_id} holds no certificate covering #{claim['stamp']}" if certificate.nil?

          signed["holderCertificate"] = certificate
        end
        signed
      end

      # TECH-SPEC 7.6's proof rule, as ReplicatedSpace.verifyClaim applies it.
      def verify_claim_proof(signed, now_ms)
        claim = signed["claim"]
        holder_key = signed["holderKey"]
        signature = signed["signature"]
        return false unless claim.is_a?(Hash) && holder_key.is_a?(String) && holder_key.bytesize == 32
        return false unless signature.is_a?(String)

        holder = claim["holder"]
        return false unless holder.is_a?(String) && holder.start_with?("#{Derive.id(holder_key)}/")

        certificate = signed["holderCertificate"]
        return Crypto.port.verify(holder_key, CBOR.dump(claim), signature) if certificate.nil?

        stamped = hlc_physical(claim["stamp"])
        return false unless Certificates.verify_at(certificate, holder_key, holder, stamped, now_ms)

        Crypto.port.verify(certificate["agentPublicKey"], CBOR.dump(claim), signature)
      rescue ArgumentError, TypeError
        false
      end

      def claim_delta(entry_id, signed) = CBOR.dump({ "state" => nil, "claimEntry" => entry_id, "claim" => signed })

      # The claim lattice's total order (SPEC 7.4): the smallest key wins.
      # Epoch descending, bid ascending, HLC stamp ascending, holder
      # ascending, expiry descending; identical to TakeClaim.merge, strings
      # compared as Java compares them (HLC canonical stamps, 2026-11-08).
      def claim_sort_key(claim)
        [-Integer(claim.fetch("epoch", 0)), Float(claim.fetch("bid", 0.0)), hlc_order(claim["stamp"]),
         java_order(claim.fetch("holder", "")), -Integer(claim.fetch("expiresAtMillis", 0))]
      end

      # Joins two signed claims. A side whose stamp the strict parser refuses
      # never wins, so a hostile claim cannot make every later honest claim on
      # its entry raise (HLC logical counter, 2026-11-08 (Rust team report)).
      def merge_claims(left, right)
        left = nil unless left.nil? || hlc_acceptable?((left["claim"] || {})["stamp"])
        right = nil unless right.nil? || hlc_acceptable?((right["claim"] || {})["stamp"])
        return right if left.nil?
        return left if right.nil?

        (claim_sort_key(left["claim"]) <=> claim_sort_key(right["claim"])) <= 0 ? left : right
      end

      # ------------------------------------------------------------- AgentCards

      # An AgentCard in Java field order; agentPublicKey, actions, and
      # agentCertificate append and are omitted when absent.
      def agent_card(group, identity, local_name, issued_iso, ttl_iso, description, goals, consumes, produces,
                     cost_hints, space_bindings, agent_public_raw: nil, actions: nil, agent_certificate: nil)
        agent = identity.agent(local_name)
        card = { "id" => "aspace://#{group}/agent/#{agent}", "issuer" => identity.peer_id, "group" => group,
                 "issued" => issued_iso, "ttl" => ttl_iso, "agent" => agent, "description" => description,
                 "goals" => goals, "consumes" => consumes, "produces" => produces,
                 "costHints" => CBOR.canonical_map(cost_hints), "spaceBindings" => CBOR.canonical_map(space_bindings) }
        if agent_certificate && (agent_public_raw.nil? || agent_certificate["agentPublicKey"] != agent_public_raw ||
                                 agent_certificate["agent"] != agent)
          raise ArgumentError, "a card's certificate must certify its agent and agentPublicKey"
        end
        card["agentPublicKey"] = agent_public_raw unless agent_public_raw.nil?
        card["actions"] = actions if actions && !actions.empty?
        card["agentCertificate"] = agent_certificate unless agent_certificate.nil?
        card
      end

      # A CardAction in Java field order: name, description, consumes,
      # produces, space (omitted when absent), kind.
      def card_action(name, description, consumes, produces, kind, space = nil)
        action = { "name" => name, "description" => description, "consumes" => consumes, "produces" => produces }
        action["space"] = space unless space.nil?
        action["kind"] = kind
        action
      end
    end
  end
end
