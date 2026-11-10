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
  # The protocol records of the wire encoding (HLC round six, 2026-11-08, F1
  # and F3, rules P1 to P4), generated from Java's serializers: each record's
  # fields in wire order with their kinds and presence rules. Schema.load
  # decodes a document (CBOR.load proves its items and its re-encoding) and
  # then holds the decoded value to its record, so a carrier whose fields
  # arrive out of order, absent, null where the record omits them, unknown,
  # or with another CBOR type (an epoch as a float or text, a bid as an
  # integer, a byte string where text belongs) is undecodable. The decoded
  # Hash keeps the arrival order, so a value that passes re-encodes to the
  # bytes received.
  #
  # Kinds: :int and :long (a plain integer within a Java int or long),
  # :double (a float64; TakeClaim's check keeps its bid finite), :boolean, :text, :bytes, :id (non-empty text:
  # PeerId, GroupId, SpaceId, EntryId), :agent (an AgentId, R5), :stamp (a
  # canonical HLC stamp), :instant and :duration (text exactly as Java's
  # Instant and Duration print it), [:enum, names], [:list, kind],
  # [:set, kind] (unique, ordered by encoded bytes), [:map, kind] (text keys
  # in the RFC 8949 order, no null value), and a record name. Presence:
  # :always (present, null allowed unless the kind is primitive or NON_NULL
  # names the record), :required
  # (present and never null, a Java constructor's requireNonNull), :null
  # (absent when null, never null), :empty (absent when null or empty).
  module Schema
    # A protocol record that does not hold to its schema: an undecodable carrier.
    class Error < CBOR::Error; end

    INT = (-(1 << 31)..((1 << 31) - 1))
    PRIMITIVE = %i[int long double boolean].freeze
    ENVELOPE_KINDS = %w[PING PING_REQ ACK RUMOR DIGEST PULL_RESP QUERY QUERY_HIT BLOCK_WANT BLOCK PIPE_DATA BATCH
                        HAVE GRAFT PRUNE RELAY_FRAME CHANNEL_HELLO SESSION_HELLO GROUP_AD_WANT GROUP_AD].freeze
    MEMBERSHIP = [:enum, %w[OPEN INVITE POLICY]].freeze
    STRATEGY = [:enum, %w[LEASE_RACE AUCTION ORDERED]].freeze
    TEXTS = %i[list text].freeze
    TEXT_MAP = %i[map text].freeze
    AD_HEAD = [["id", :text], ["issuer", :id], ["group", :id], ["issued", :instant], ["ttl", :duration]].freeze

    RECORDS = {
      "WireCodec.Signed" => [["envelope", "Envelope", :required], ["senderPublicKey", :bytes], ["signature", :bytes]],
      "Envelope" => [["ver", :int], ["group", :id], ["kind", [:enum, ENVELOPE_KINDS]], ["from", :id], ["to", :id],
                     ["stamp", :stamp, :required], ["body", :bytes]],
      "Bodies.Ping" => [["nonce", :long], ["root", :bytes, :null], ["hashes", %i[map bytes], :null],
                        ["have", [:list, "Bodies.HaveItem"], :null]],
      "Bodies.PingReq" => [["target", :id], ["nonce", :long]],
      "Bodies.Ack" => [["nonce", :long], ["onBehalf", :id], ["root", :bytes, :null],
                       ["hashes", %i[map bytes], :null], ["have", [:list, "Bodies.HaveItem"], :null]],
      "Bodies.Rumor" => [["streamId", :text], ["itemId", :text], ["hopsRemaining", :int], ["payload", :bytes]],
      "Bodies.Digest" => [["digests", %i[map bytes]], ["hashes", %i[map bytes], :null], ["want", TEXTS, :null]],
      "Bodies.PullResp" => [["deltas", %i[map bytes]]],
      "Bodies.RelayFrame" => [["target", :id], ["frame", :bytes], ["path", %i[list id], :null], ["hop", :int, :null]],
      "Bodies.Batch" => [["frames", %i[list bytes]]],
      "Bodies.Have" => [["items", [:list, "Bodies.HaveItem"]]],
      "Bodies.HaveItem" => [["streamId", :text], ["hash", :bytes]],
      "Bodies.Graft" => [["streamId", :text], ["hash", :bytes]],
      "Bodies.Prune" => [["streamId", :text], ["hash", :bytes]],
      "Bodies.SessionHello" => [["ephemeralKey", :bytes], ["nonce", :bytes], ["remote", :id], ["echo", :bytes]],
      "Bodies.ChannelHello" => [["acceptsBare", :boolean], ["attestedRemote", :id]],
      "BlockExchange.Want" => [["cid", :text]],
      "BlockExchange.Block" => [["cid", :text], ["bytes", :bytes]],
      "PeerNode.SignedPeerAd" => [["adBytes", :bytes], ["publicKey", :bytes], ["signature", :bytes]],
      "PeerNode.RelayPipeFrame" => [["capability", :text], ["payload", :bytes]],
      "PeerNode.RelaySignal" => [["target", :id], ["failedHop", :id], ["reason", :text]],
      "CapabilityPipes.PipeFrame" => [["capability", :text], ["payload", :bytes]],
      "SignedGroupAdvertisement" => [["advertisement", "GroupAdvertisement"], ["founderPublicKey", :bytes],
                                     ["signature", :bytes]],
      "GroupFounding.FoundingFields" => [["name", :text], ["founder", :id], ["issued", :instant],
                                         ["ttl", :duration], ["membershipPolicy", MEMBERSHIP],
                                         ["defaultStrategy", STRATEGY],
                                         ["gossip", "GroupAdvertisement.GossipParameters"]],
      "GroupFounding.FoundingDocument" => [["fields", "GroupFounding.FoundingFields"], ["signature", :bytes]],
      "JoinCredentials.CredentialView" => [["candidate", :id], ["group", :id]],
      "JoinCredentials.Credential" => [["founderKey", :bytes], ["signature", :bytes]],
      "JoinCredentials.DelegationView" => [["inviteKey", :bytes], ["group", :id], ["notAfterMillis", :long],
                                           ["label", :text]],
      "JoinCredentials.Delegation" => [["founderKey", :bytes], ["inviteKey", :bytes], ["group", :id],
                                       ["notAfterMillis", :long], ["label", :text], ["signature", :bytes]],
      "JoinCredentials.DelegatedCredential" => [["delegation", "JoinCredentials.Delegation"], ["signature", :bytes]],
      "RevocationRegistry.SignedRevocation" => [["adBytes", :bytes], ["publicKey", :bytes], ["signature", :bytes]],
      "AdCache.StoredAd" => [["adType", :text], ["adBytes", :bytes], ["publicKey", :bytes], ["signature", :bytes]],
      "AdCache.Delta" => [["ads", [:list, "AdCache.StoredAd"]]],
      "DiscoveryService.AdQuery" => [["queryId", :text], ["asker", :id], ["adType", :text],
                                     ["fieldEquals", TEXT_MAP]],
      "DiscoveryService.QueryHits" => [["queryId", :text], ["hits", [:list, "AdCache.StoredAd"]]],
      "AgentCard" => AD_HEAD + [["agent", :agent], ["description", :text], ["goals", TEXTS], ["consumes", TEXTS],
                                ["produces", TEXTS], ["costHints", TEXT_MAP], ["spaceBindings", TEXT_MAP],
                                ["agentPublicKey", :bytes, :null], ["actions", [:list, "CardAction"], :null],
                                ["agentCertificate", "AgentCertificate", :null], ["ui", "UiDeclaration", :null],
                                ["spill", "CardSpill", :null]],
      # AppCard origin and formats, 2026-11-09 (SPEC v0.1.32 §6.1a.2 and
      # §6.1a.5): origin, formats, and spill append after host, each omitted
      # when absent, so a card without them keeps its v0.1.31 bytes.
      "AppCard" => AD_HEAD + [["name", :text], ["kind", :text], ["shape", :text], ["owner", :text],
                              ["reads", TEXTS], ["actions", TEXTS], ["idpClient", :text], ["url", :text],
                              ["pkg", :text], ["version", :text], ["views", TEXTS], ["ui", "AppCard.Ui", :null],
                              ["host", "AppCard.Host", :null], ["origin", "AppCard.Origin", :null],
                              ["formats", TEXTS, :null], ["spill", "CardSpill", :null]],
      "AppCard.Origin" => [["system", :text], ["ref", :text], ["version", :text], ["attrs", TEXT_MAP, :null]],
      "AppCard.Parts" => [["reads", TEXTS], ["actions", TEXTS], ["views", TEXTS], ["ui", "AppCard.Ui", :null]],
      "AgentCard.Parts" => [["actions", [:list, "CardAction"], :null], ["ui", "UiDeclaration", :null]],
      "CardSpill" => [["root", :text], ["size", :long], ["parts", TEXTS]],
      "AppCard.Ui" => [["protocol", :text], ["version", :text], ["catalogIds", TEXTS], ["agent", :text],
                       ["transport", :text], ["surfaces", TEXTS],
                       ["components", [:list, "UiDeclaration.Component"], :empty]],
      "AppCard.Host" => [["url", :text], ["port", :int], ["hostAgent", :text], ["path", :text], ["signOn", :text],
                         ["publishedBy", :text], ["publishedAt", :instant], ["status", :text]],
      "AssetCard" => AD_HEAD + [["asset", :text], ["uri", :text], ["description", :text], ["shape", :text],
                                ["freshness", :text], ["costHints", TEXT_MAP], ["access", TEXT_MAP]],
      "CapabilityAdvertisement" => AD_HEAD + [["capabilityType", :text], ["version", :text], ["binding", :text],
                                              ["parameters", TEXT_MAP], ["costHints", TEXT_MAP]],
      "CredentialRevocation" => AD_HEAD + [["target", "CredentialRevocation.Target"], ["reason", :text],
                                           ["effectiveFrom", :instant, :null], ["evidence", :bytes, :null]],
      "CredentialRevocation.Target" => [["kind", :text], ["agent", :agent, :null], ["keyFingerprint", :bytes, :null],
                                        ["x509Issuer", :text, :null], ["x509Serial", :text, :null],
                                        ["certificateFingerprint", :bytes, :null],
                                        ["credentialHash", :bytes, :null]],
      "GroupAdvertisement" => AD_HEAD + [["name", :text], ["membershipPolicy", MEMBERSHIP],
                                         ["defaultStrategy", STRATEGY],
                                         ["gossip", "GroupAdvertisement.GossipParameters"]],
      "GroupAdvertisement.GossipParameters" => [["fanout", :int], ["period", :duration]],
      "ModelCard" => AD_HEAD + [["name", :text], ["version", :text], ["tasks", TEXTS], ["modality", :text],
                                ["limits", TEXT_MAP], ["licence", :text], ["provenance", TEXT_MAP],
                                ["evals", TEXT_MAP], ["costHints", TEXT_MAP], ["residency", TEXT_MAP],
                                ["engine", :text], ["servers", %i[list id]]],
      "PeerAdvertisement" => AD_HEAD + [["endpoints", [:list, "PeerAdvertisement.Endpoint"]],
                                        ["roles", [:set, [:enum, %w[RENDEZVOUS RELAY]]]],
                                        ["resourceHints", TEXT_MAP]],
      "PeerAdvertisement.Endpoint" => [["transport", :text], ["address", :text], ["priority", :int]],
      "RevocationAdvertisement" => AD_HEAD + [["revoked", :id], ["reason", :text], ["successor", :id],
                                              ["evidence", :bytes, :null]],
      "SpaceAdvertisement" => AD_HEAD + [["spaceName", :text], ["schemaHints", TEXTS], ["strategy", STRATEGY],
                                         ["admission", [:enum, %w[GROUP ALLOWLIST CREDENTIAL AUTHORIZER]]],
                                         ["replication", [:enum, %w[FULL TAG_SHARDED]]]],
      "CardAction" => [["name", :text], ["description", :text], ["consumes", TEXTS], ["produces", TEXTS],
                       ["space", :text, :null], ["kind", :text], ["contract", "CardAction.Contract", :null]],
      "CardAction.Contract" => [["pre", TEXTS], ["post", TEXTS], ["cost", :text], ["methods", TEXTS]],
      "UiDeclaration" => [["protocol", :text], ["version", :text], ["components", [:list, "UiDeclaration.Component"]],
                          ["entries", "UiDeclaration.Entries"], ["catalogIds", TEXTS]],
      "UiDeclaration.Component" => [["id", :text], ["catalogId", :text], ["component", :text], ["entry", :text],
                                    ["controls", TEXTS], ["role", :text]],
      "UiDeclaration.Entries" => [["reads", TEXTS], ["writes", TEXTS]],
      "AgentCertificate" => [["agent", :agent, :required], ["agentPublicKey", :bytes, :required],
                             ["issued", :instant, :required], ["ttl", :duration, :required],
                             ["peerSignature", :bytes], ["encryptionPublicKey", :bytes, :null]],
      "SpaceWire.Delta" => [["state", "SpaceWire.EntryStateDto"], ["claimEntry", :id],
                            ["claim", "SpaceWire.SignedClaim"]],
      "SpaceWire.SyncDelta" => [["states", [:list, "SpaceWire.EntryStateDto"]],
                                ["claims", [:map, "SpaceWire.SignedClaim"]]],
      "SpaceWire.EntryStateDto" => [["record", "EntryRecord", :null], ["issuerPublicKey", :bytes],
                                    ["adds", [:list, "Dot"]], ["removes", [:list, "Dot"]], ["leaseStamp", :stamp],
                                    ["leaseValue", "LeaseInfo"], ["completed", :boolean], ["stateSig", :bytes],
                                    ["agentCertificate", "AgentCertificate", :null],
                                    ["stateCertificate", "AgentCertificate", :null], ["signer", :text, :null],
                                    ["signedAt", :stamp, :null], ["entryId", :id, :null]],
      "SpaceWire.SignedClaim" => [["claim", "TakeClaim"], ["holderKey", :bytes], ["signature", :bytes],
                                  ["holderCertificate", "AgentCertificate", :null]],
      "TakeClaim" => [["entryId", :id, :required], ["spaceId", :id, :required], ["epoch", :long],
                      ["stamp", :stamp, :required], ["holder", :agent, :required], ["bid", :double],
                      ["expiresAtMillis", :long]],
      "EntryRecord" => [["entryId", :id, :required], ["spaceId", :id, :required], ["type", :text, :required],
                        ["payload", :bytes], ["payloadRef", :text], ["issuer", :agent, :required],
                        ["issued", :stamp, :required], ["lease", "LeaseInfo", :required],
                        ["tags", TEXT_MAP, :required], ["sig", :bytes], ["keyEpoch", :long, :null]],
      "Dot" => [["replica", :text, :required], ["counter", :long]],
      "LeaseInfo" => [["holder", :agent, :required], ["expiresAtMillis", :long],
                      ["kind", [:enum, %w[WRITE TAKE]], :required]],
      "ReplicatedSpace.SignView" => [["entryId", :id], ["spaceId", :id], ["type", :text], ["payload", :bytes],
                                     ["payloadRef", :text], ["issuer", :agent], ["issued", :stamp],
                                     ["tags", TEXT_MAP], ["keyEpoch", :long, :null]],
      "ReplicatedSpace.StateSignView" => [["spaceId", :id], ["entryId", :id], ["adds", [:list, "Dot"]],
                                          ["removes", [:list, "Dot"]], ["leaseStamp", :stamp],
                                          ["leaseValue", "LeaseInfo"], ["completed", :boolean],
                                          ["signer", :text, :null], ["signedAt", :stamp, :null]],
      "OrderedTakes.ClaimCommand" => [["entryId", :id], ["claim", "TakeClaim"], ["holderKey", :bytes],
                                      ["signature", :bytes], ["holderCertificate", "AgentCertificate", :null]],
      "VoteCapability.Proposal" => [["proposalId", :text], ["question", :text], ["options", TEXTS], ["quorum", :int]],
      "VoteCapability.Ballot" => [["proposalId", :text], ["option", :text], ["voter", :text]],
      "VoteCapability.Decision" => [["proposalId", :text], ["winner", :text], ["tally", %i[map int]],
                                    ["granularity", [:enum, %w[PEER AGENT]]]],
      # HLC round seven, 2026-11-08: the records that travel inside
      # PipeFrame.payload (SPEC annex I), read as Java's fromWire reads them.
      # This client reads no gossip-learning exchange; SemHit.adBytes reads on
      # the advertisement path and a Raft command is a ClaimCommand document.
      "PushSumAggregate.Frame" => [["share", "PushSumAggregate.Share"], ["extremum", "PushSumAggregate.Extremum"],
                                   ["histogram", "PushSumAggregate.Histogram"],
                                   ["roster", "PushSumAggregate.Roster"]],
      "PushSumAggregate.Share" => [["epochId", :text], ["value", :double], ["weight", :double]],
      "PushSumAggregate.Extremum" => [["epochId", :text], ["max", :boolean], ["value", :double]],
      "PushSumAggregate.Histogram" => [["epochId", :text], ["lo", :double], ["hi", :double],
                                       ["buckets", %i[list double]]],
      "PushSumAggregate.Roster" => [["epochId", :text], ["members", %i[list long]]],
      "SemanticDiscovery.SemQuery" => [["nonce", :long], ["text", :text], ["limit", :int]],
      "SemanticDiscovery.SemResponse" => [["nonce", :long], ["hits", [:list, "SemanticDiscovery.SemHit"]]],
      "SemanticDiscovery.SemHit" => [["adType", :text], ["adBytes", :bytes], ["publicKey", :bytes],
                                     ["signature", :bytes]],
      "RaftMessages.Frame" => [["requestVote", "RaftMessages.RequestVote"], ["voteReply", "RaftMessages.VoteReply"],
                               ["appendEntries", "RaftMessages.AppendEntries"],
                               ["appendReply", "RaftMessages.AppendReply"],
                               ["clientSubmit", "RaftMessages.ClientSubmit"]],
      "RaftMessages.RequestVote" => [["term", :long], ["candidate", :id], ["lastLogIndex", :long],
                                     ["lastLogTerm", :long]],
      "RaftMessages.VoteReply" => [["term", :long], ["granted", :boolean]],
      "RaftMessages.AppendEntries" => [["term", :long], ["leader", :id], ["prevLogIndex", :long],
                                       ["prevLogTerm", :long], ["entries", [:list, "RaftMessages.LogEntry"]],
                                       ["leaderCommit", :long]],
      "RaftMessages.AppendReply" => [["term", :long], ["follower", :id], ["success", :boolean],
                                     ["matchIndex", :long]],
      "RaftMessages.ClientSubmit" => [["command", :bytes]],
      "RaftMessages.LogEntry" => [["term", :long], ["command", :bytes]]
    }.freeze

    # The checks a Java record's constructor makes past its field types: a
    # record that fails one does not decode in Java.
    # HLC round six, 2026-11-08 (reference rule): EntryRecord's and
    # AgentCertificate's checks join them, so a delta that carries such a
    # record is undecodable here as in Java.
    CONSTRUCTOR_CHECKS = {
      "TakeClaim" => lambda do |claim|
        if !claim["epoch"].positive? then "epoch must be positive"
        elsif !claim["bid"].finite? then "bid must be finite"
        else true
        end
      end,
      "LeaseInfo" => ->(lease) { lease["expiresAtMillis"].positive? || "expiresAtMillis must be positive" },
      "Dot" => ->(dot) { dot["counter"].positive? || "counter must be positive" },
      "EntryRecord" => lambda do |record|
        payload = record["payload"]
        if payload.nil? == record["payloadRef"].nil? then "holds exactly one of payload and payloadRef"
        elsif payload && payload.bytesize > Wire::INLINE_PAYLOAD_LIMIT then "holds an inline payload past 64 KiB"
        elsif record.key?("keyEpoch") && record["keyEpoch"] < 1 then "names key epoch 1 or later, or none"
        else true
        end
      end,
      # AppCard origin and formats, 2026-11-09 (FR-1 to FR-5, FR-14): the
      # closed card values, the origin and formats grammars, and the stub's
      # rules, as the Java card records' constructors check them.
      "AppCard" => ->(card) { Cards.app_card_check(card) },
      "AppCard.Ui" => ->(ui) { Cards.app_ui_check(ui) },
      "AppCard.Host" => ->(host) { Cards.host_check(host) },
      "AppCard.Origin" => ->(origin) { Cards.origin_check(origin) },
      "AppCard.Parts" => ->(parts) { Cards.app_parts_check(parts) },
      "CardSpill" => ->(spill) { Cards.spill_check(spill) },
      "AgentCard" => ->(card) { Cards.agent_card_check(card) },
      "UiDeclaration" => ->(ui) { Cards.ui_declaration_check(ui) },
      "UiDeclaration.Entries" => ->(entries) { Cards.ui_entries_check(entries) },
      "UiDeclaration.Component" => ->(component) { Cards.ui_component_check(component) },
      "AgentCertificate" => lambda do |certificate|
        key = certificate["encryptionPublicKey"]
        if certificate["ttl"] == "PT0S" then "ttl must be positive"
        elsif key && key.bytesize != 32 then "an encryption key is a raw 32-byte X25519 key"
        else true
        end
      end
    }.freeze

    # HLC round six, 2026-11-08 (reference rule): the records whose Java
    # constructors refuse a null in every field the record always writes
    # (requireNonNull, or a null Java rewrites to a default it then writes
    # differently, which F3 refuses), each with the fields that may still be
    # null. Java's reader judged every field of each with a null. A field of
    # any other record that the record always writes may be null.
    NON_NULL = {
      "Envelope" => %w[to], "RevocationAdvertisement" => %w[successor]
    }.merge(%w[AgentCard AppCard AppCard.Ui AppCard.Host AppCard.Origin AppCard.Parts AssetCard CapabilityAdvertisement
               CardAction CardSpill CardAction.Contract CredentialRevocation CredentialRevocation.Target GroupAdvertisement
               GroupAdvertisement.GossipParameters GroupFounding.FoundingFields GroupFounding.FoundingDocument
               ModelCard PeerAdvertisement PeerAdvertisement.Endpoint SignedGroupAdvertisement SpaceAdvertisement
               UiDeclaration UiDeclaration.Component UiDeclaration.Entries].to_h { |name| [name, []] }).freeze

    # The adType names a StoredAd may carry (AdCache.AD_TYPES), each also the
    # name of its record here.
    AD_TYPES = %w[PeerAdvertisement GroupAdvertisement SpaceAdvertisement CapabilityAdvertisement AgentCard AssetCard
                  ModelCard AppCard].freeze

    module_function

    # Decodes a document and holds it to kind (a record name or a kind
    # expression); returns the value or raises Schema::Error (a CBOR::Error).
    def load(kind, bytes)
      value = CBOR.load(bytes)
      check(kind, value)
      value
    end

    # Raises Schema::Error unless value holds to kind.
    def check(kind, value, path = kind_name(kind))
      case kind
      when String then record(kind, value, path)
      when Array then compound(kind, value, path)
      else scalar(kind, value, path)
      end
    end

    def kind_name(kind) = kind.is_a?(String) ? kind : kind.inspect
    private_class_method :kind_name

    def record(name, value, path)
      fields = RECORDS.fetch(name)
      fail!(path, "a #{name} is a map") unless value.is_a?(Hash)
      expected = fields.filter_map do |field, _, presence|
        field if value.key?(field) || !%i[null empty].include?(presence)
      end
      fail!(path, "fields #{value.keys.inspect} are not #{name}'s #{expected.inspect} in order") \
        unless value.keys == expected

      fields.each do |field, kind, presence = :always|
        next unless value.key?(field)

        item = value[field]
        if item.nil?
          fail!("#{path}.#{field}", "is null") if presence != :always || PRIMITIVE.include?(kind) || !nullable?(name, field)
          next
        end
        fail!("#{path}.#{field}", "is empty, and absent when empty") if presence == :empty && item == []
        check(kind, item, "#{path}.#{field}")
      end
      verdict = CONSTRUCTOR_CHECKS[name]&.call(value)
      fail!(path, verdict) if verdict.is_a?(String)
    end
    private_class_method :record

    def nullable?(name, field) = !NON_NULL.key?(name) || NON_NULL[name].include?(field)
    private_class_method :nullable?

    def compound(kind, value, path)
      shape, inner = kind
      case shape
      when :enum then fail!(path, "names no #{inner.inspect}") unless text?(value) && inner.include?(value)
      when :list, :set
        fail!(path, "is an array") unless value.is_a?(Array)
        value.each_with_index { |item, i| check(inner, item, "#{path}[#{i}]") }
        set_order(value, path) if shape == :set
      when :map
        fail!(path, "is a map") unless value.is_a?(Hash)
        keys = value.keys.map(&:b)
        fail!(path, "keys are not in the RFC 8949 order") unless keys == keys.sort_by { |key| [key.bytesize, key] }

        value.each { |key, item| check(inner, item, "#{path}[#{key.inspect}]") }
      end
    end
    private_class_method :compound

    # A set travels once per element, ordered by the elements' encoded bytes,
    # shorter first, then bytewise (JC-4).
    def set_order(value, path)
      encoded = value.map { |item| CBOR.dump(item) }
      fail!(path, "elements repeat") unless encoded.uniq.size == encoded.size
      fail!(path, "elements are not in their encoded order") unless encoded == encoded.sort_by { |e| [e.bytesize, e] }
    end
    private_class_method :set_order

    def scalar(kind, value, path)
      ok =
        case kind
        when :int then value.is_a?(Integer) && INT.cover?(value)
        when :long then value.is_a?(Integer) && CBOR::LONG.cover?(value)
        # any float64, as Java reads a double field (HLC round seven, 2026-11-08)
        when :double then value.is_a?(Float)
        when :boolean then [true, false].include?(value)
        when :bytes then value.is_a?(String) && value.encoding == Encoding::BINARY
        when :text then text?(value)
        when :id then text?(value) && !value.empty?
        when :agent then Wire.agent_id?(value)
        when :stamp then !Wire.hlc_decode(value).nil?
        when :instant then text?(value) && Instants.canonical_instant?(value)
        when :duration then text?(value) && Instants.canonical_duration?(value)
        else raise ArgumentError, "no schema kind #{kind.inspect}"
        end
      fail!(path, "is not a #{kind}: #{value.inspect[0, 80]}") unless ok
    end
    private_class_method :scalar

    def text?(value) = value.is_a?(String) && value.encoding != Encoding::BINARY
    private_class_method :text?

    def fail!(path, message) = raise(Error, "#{path} #{message}")
    private_class_method :fail!
  end
end
