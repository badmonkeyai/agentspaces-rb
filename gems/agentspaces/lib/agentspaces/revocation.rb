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
  # Revocations (SPEC 5.6, v0.1.13): the revocations stream's peer
  # revocations and the credential-revocations stream's revocations of agents,
  # agent keys, X.509 leaves, and join credentials, verified as a Java member
  # verifies them except for the CA-rooted path, which this peer does not
  # carry (a CA-rooted record is ignored, never trusted). A registry keeps one
  # record per target under Java's total order: authority (founder, then the
  # agent's own peer), then the newer issued, then the larger SHA-256.
  module Revocation
    PEER_STREAM = "revocations"
    CREDENTIAL_STREAM = "credential-revocations"
    STREAMS = [PEER_STREAM, CREDENTIAL_STREAM].freeze
    KEY_COMPROMISE = "key-compromise"
    REASONS = [KEY_COMPROMISE, "retired", "superseded", "privilege-withdrawn", "unspecified"].freeze
    KINDS = %w[AGENT AGENT_KEY X509_LEAF JOIN_CREDENTIAL].freeze
    # The record each stream's adBytes holds (HLC round six, 2026-11-08, F3).
    RECORDS = { PEER_STREAM => "RevocationAdvertisement", CREDENTIAL_STREAM => "CredentialRevocation" }.freeze
    FOUNDER = 3
    OWN_PEER = 1
    MAX_ISSUED_SKEW_MILLIS = 10 * 60 * 1000
    MAX_RETAINED = 4096

    module_function

    # CredentialRevocation.Target.canonical: the target's text within its kind.
    def canonical_target(target)
      case target["kind"]
      when "AGENT" then target["agent"]
      when "AGENT_KEY" then "#{target['agent']}##{target['keyFingerprint'].unpack1('H*')}"
      when "X509_LEAF" then target["certificateFingerprint"].unpack1("H*")
      else target["credentialHash"].unpack1("H*")
      end
    end

    # CredentialRevocation.idFor: aspace://<group>/revocation/<kind>/<canonical>.
    def revocation_id(group, target) = "aspace://#{group}/revocation/#{target['kind'].downcase}/#{canonical_target(target)}"

    def valid_target?(target)
      return false unless target.is_a?(Hash) && KINDS.include?(target["kind"])

      sized = ->(key) { target[key].is_a?(String) && target[key].bytesize == 32 }
      case target["kind"]
      when "AGENT" then target["agent"].is_a?(String)
      when "AGENT_KEY" then target["agent"].is_a?(String) && sized.call("keyFingerprint")
      when "X509_LEAF" then sized.call("certificateFingerprint")
      else sized.call("credentialHash")
      end
    end

    # One group's accepted revocations as a peer holds and applies them.
    class Registry
      attr_reader :peers, :credentials

      # founder and group are callables returning the founder's PeerID and the
      # group id, or nil.
      def initialize(founder, group = nil)
        @founder = founder
        @group = group
        @peers = {}
        @credentials = {}
        @lock = Mutex.new
      end

      # Verifies and accepts one rumor payload (a CBOR SignedRevocation).
      def accept(stream, payload, now_ms)
        accept_signed(stream, CBOR.load(payload), now_ms)
      rescue CBOR::Error
        false
      end

      # Verifies and accepts one decoded SignedRevocation; returns whether it
      # newly revoked its target. HLC round six, 2026-11-08 (F1, F3): the
      # SignedRevocation and its adBytes hold to their records, and one that
      # does not is undecodable and accepts nothing.
      def accept_signed(stream, signed, now_ms)
        record = RECORDS[stream]
        return false if record.nil?

        Schema.check("RevocationRegistry.SignedRevocation", signed)
        ad_bytes, key, signature = signed.values
        return false unless ad_bytes && signature && key&.bytesize == 32

        ad = Schema.load(record, ad_bytes)

        issued = Instants.parse_millis(ad["issued"])
        return false unless Derive.id(key) == ad["issuer"]
        return false unless Crypto.port.verify(key, ad_bytes, signature)
        return false if issued > now_ms + MAX_ISSUED_SKEW_MILLIS

        group = @group&.call
        return false unless group.nil? || group == ad["group"]

        digest = Crypto.port.sha256(ad_bytes).unpack1("H*")
        stream == PEER_STREAM ? accept_peer(ad, issued, digest) : accept_credential(ad, issued, digest)
      rescue ArgumentError, TypeError, NoMethodError
        false
      end

      def peer_revoked?(peer_id) = @peers.key?(peer_id)

      # RevocationView.refuses: a newly arriving signature by agent_id is
      # refused when its peer is revoked, or its agent-wide or (given the key)
      # key revocation refuses signing_ms under the freeze rule.
      def refuses?(agent_id, agent_key, signing_ms)
        return false unless agent_id.is_a?(String) && agent_id.include?("/")
        return true if peer_revoked?(agent_id.split("/", 2).first)

        whole = @credentials["AGENT:#{agent_id}"]
        return true if whole && refuses_at?(whole[3], signing_ms)

        if agent_key.is_a?(String)
          fingerprint = Crypto.port.sha256(agent_key).unpack1("H*")
          one = @credentials["AGENT_KEY:#{agent_id}##{fingerprint}"]
          return true if one && refuses_at?(one[3], signing_ms)
        end
        false
      end

      private

      def accept_peer(ad, issued, digest)
        founder = @founder.call
        revoked = ad["revoked"]
        return false unless founder && ad["issuer"] == founder && revoked.is_a?(String)

        keep(@peers, revoked, [FOUNDER, issued, digest, ad])
      end

      def accept_credential(ad, issued, digest)
        target = ad["target"]
        return false unless Revocation.valid_target?(target) && REASONS.include?(ad["reason"])
        return false unless ad["id"] == Revocation.revocation_id(ad["group"], target)

        effective = ad["effectiveFrom"]
        return false if !effective.nil? && Instants.parse_millis(effective) > issued

        issuer = ad["issuer"]
        rank =
          if issuer == @founder.call then FOUNDER
          elsif %w[AGENT AGENT_KEY].include?(target["kind"]) && target["agent"].to_s.start_with?("#{issuer}/")
            OWN_PEER
          end
        return false if rank.nil?

        keep(@credentials, "#{target['kind']}:#{Revocation.canonical_target(target)}", [rank, issued, digest, ad])
      end

      def refuses_at?(ad, signing_ms)
        return true if ad["reason"] == KEY_COMPROMISE || signing_ms.nil?

        Integer(signing_ms) >= Instants.parse_millis(ad["effectiveFrom"] || ad["issued"])
      end

      # One record per target under the total order (rank, issued, hash).
      def keep(table, key, candidate)
        @lock.synchronize do
          held = table[key]
          if held.nil?
            return false if table.size >= MAX_RETAINED

            table[key] = candidate
            return true
          end
          table[key] = candidate if (candidate[0, 3] <=> held[0, 3]).positive?
          false
        end
      end
    end
  end
end
