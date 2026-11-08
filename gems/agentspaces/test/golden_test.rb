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

require_relative "test_helper"

# Cross-language golden tests: the Java codec produced every expected byte
# string in golden.json, and these tests prove the Ruby encoder reproduces
# each one exactly. Ed25519 is deterministic (RFC 8032), so even the
# signatures must match byte for byte.
class GoldenTest < Minitest::Test
  include GoldenHelpers
  include AgentSpaces

  ENTRY = "11111111-2222-3333-4444-555555555555"
  TASK = "GoldenVectors$ResearchTask#v1"

  def test_identity_and_derivations_match_java
    identity = golden_identity
    assert_equal hex("public_key_raw"), identity.public_raw
    assert_equal GOLDEN["peer_id"], identity.peer_id
    assert_equal GOLDEN["peer_id"], Derive.id(hex("public_key_raw"))
    assert_equal GOLDEN["group_id"], Derive.group_id_from_founding("research-fleet-demo-v1")
    assert_equal GOLDEN["space_id"], Derive.space_id_local("#{GOLDEN['group_id']}/tasks")
    assert_equal hex("private_key_pkcs8"), identity.pkcs8
  end

  def test_ping_envelope_bytes_and_signature_match_java
    identity = golden_identity
    assert_equal hex("ping_body_cbor"), Wire.ping_body(42)
    env = Wire.envelope(GOLDEN["group_id"], "PING", GOLDEN["peer_id"], GOLDEN["hlc_encoded"], hex("ping_body_cbor"),
                        GOLDEN["peer_id"])
    assert_equal hex("ping_envelope_cbor"), cbor(env)
    assert_equal hex("ping_envelope_signature"), identity.sign(cbor(env))
    assert_equal hex("ping_frame_cbor"), Wire.encode_frame(env, identity)
  end

  def test_ruby_verifies_java_frames_and_refuses_a_tampered_one
    env = Wire.decode_frame(hex("ping_frame_cbor"))
    refute_nil env
    assert_equal "PING", env["kind"]
    assert_equal GOLDEN["peer_id"], env["from"]
    tampered = hex("ping_frame_cbor").dup
    tampered.setbyte(-1, tampered.getbyte(-1) ^ 0x01)
    assert_nil Wire.decode_frame(tampered)
  end

  def test_membership_intro_matches_java
    identity = golden_identity
    ad = Wire.peer_advertisement(GOLDEN["group_id"], identity, "2026-01-01T00:00:00Z")
    ad["endpoints"] = [{ "transport" => "tcp", "address" => "127.0.0.1:7460", "priority" => 0 }]
    assert_equal hex("peer_ad_cbor"), cbor(ad)
    assert_equal hex("signed_peer_ad_cbor"), Wire.signed_peer_ad(ad, identity)
    item_id = "peer:#{identity.peer_id}:1767225600000"
    assert_equal hex("intro_rumor_body_cbor"), Wire.rumor_body("peers", item_id, 6, hex("signed_peer_ad_cbor"))
  end

  def test_space_write_matches_java
    identity = golden_identity
    payload = cbor({ "topic" => "golden vectors", "priority" => 3 })
    assert_equal hex("task_payload_cbor"), payload
    # The same payload from a Ruby entry.
    task = Entry.define(TASK, topic: String, priority: Integer)
    assert_equal payload, cbor(task.new(topic: "golden vectors", priority: 3).to_payload)

    view = Wire.sign_view(ENTRY, GOLDEN["space_id"], TASK, payload, identity.agent("python"), GOLDEN["hlc_encoded"])
    assert_equal hex("sign_view_cbor"), cbor(view)
    assert_equal hex("record_signature"), identity.sign(cbor(view))
    lease = { "holder" => identity.agent("python"), "expiresAtMillis" => 1_735_693_200_000, "kind" => "WRITE" }
    record = { "entryId" => ENTRY, "spaceId" => GOLDEN["space_id"], "type" => TASK, "payload" => payload,
               "payloadRef" => nil, "issuer" => identity.agent("python"), "issued" => GOLDEN["hlc_encoded"],
               "lease" => lease, "tags" => {}, "sig" => hex("record_signature") }
    adds = [{ "replica" => identity.peer_id, "counter" => 1 }]
    state_view = Wire.state_sign_view(GOLDEN["space_id"], ENTRY, adds, [], GOLDEN["hlc_encoded"], lease, false)
    assert_equal hex("state_sign_view_cbor"), cbor(state_view)
    state_sig = identity.sign(cbor(state_view))
    assert_equal hex("state_signature"), state_sig
    dto = { "record" => record, "issuerPublicKey" => identity.public_raw, "adds" => adds, "removes" => [],
            "leaseStamp" => GOLDEN["hlc_encoded"], "leaseValue" => lease, "completed" => false,
            "stateSig" => state_sig }
    assert_equal hex("entry_state_dto_cbor"), cbor(dto)
    assert_equal hex("delta_cbor"), cbor({ "state" => dto, "claimEntry" => nil, "claim" => nil })
  end

  def test_subordinate_agent_certificate_and_record_match_java
    identity = golden_identity
    issued = GOLDEN["certificate_verify_at"]
    agent = golden_agent
    assert_equal identity.agent("python"), agent.agent_id
    assert_equal hex("agent_public_key_raw"), agent.public_raw
    assert_equal hex("agent_certificate_unsigned_cbor"), cbor(Certificates.body(agent.certificate))
    assert_equal hex("agent_certificate_signature"), agent.certificate["peerSignature"]
    assert_equal hex("agent_certificate_cbor"), cbor(agent.certificate)
    now = ms(issued)
    assert Certificates.verify(load(hex("agent_certificate_cbor")), identity.public_raw, identity.agent("python"), now)
    day = Instants.parse_duration_millis("PT24H")
    assert Certificates.verify(agent.certificate, identity.public_raw, identity.agent("python"), now + day - 1)
    refute Certificates.verify(agent.certificate, identity.public_raw, identity.agent("python"), now + day)

    view = hex("sign_view_cbor")
    sig = agent.sign(view)
    assert_equal hex("record_signature_agent_key"), sig
    assert Identity.verify(agent.public_raw, view, sig)
    refute Identity.verify(identity.public_raw, view, sig)

    lease = { "holder" => identity.agent("python"), "expiresAtMillis" => 1_735_693_200_000, "kind" => "WRITE" }
    record = { "entryId" => ENTRY, "spaceId" => GOLDEN["space_id"], "type" => TASK,
               "payload" => hex("task_payload_cbor"), "payloadRef" => nil, "issuer" => identity.agent("python"),
               "issued" => GOLDEN["hlc_encoded"], "lease" => lease, "tags" => {}, "sig" => sig }
    dto = { "record" => record, "issuerPublicKey" => identity.public_raw,
            "adds" => [{ "replica" => identity.peer_id, "counter" => 1 }], "removes" => [],
            "leaseStamp" => GOLDEN["hlc_encoded"], "leaseValue" => lease, "completed" => false,
            "stateSig" => hex("state_signature"), "agentCertificate" => agent.certificate }
    assert_equal hex("entry_state_with_certificate_cbor"), cbor(dto)
    assert_equal hex("delta_with_certificate_cbor"), cbor({ "state" => dto, "claimEntry" => nil, "claim" => nil })
    assert Wire.verify_record(record, identity.public_raw, agent.certificate, now)

    # A6: that state is peer-signed on an agent-attested entry and refused;
    # the agent-signed state lands.
    peer = peer_at(now)
    peer.fold_state(load(hex("delta_with_certificate_cbor"))["state"])
    assert_empty peer.states
    signer = identity.agent("python")
    signed_at = GOLDEN["hlc_encoded"]
    state_view = Wire.state_sign_view(record["spaceId"], record["entryId"], dto["adds"], [], signed_at, lease, false,
                                      signer, signed_at)
    assert_equal hex("state_sign_view_agent_cbor"), cbor(state_view)
    agent_state_sig = agent.sign(cbor(state_view))
    assert_equal hex("state_signature_agent_key"), agent_state_sig
    agent_dto = dto.except("agentCertificate").merge("stateSig" => agent_state_sig,
                                                     "agentCertificate" => agent.certificate,
                                                     "stateCertificate" => agent.certificate, "signer" => signer,
                                                     "signedAt" => signed_at)
    assert_equal hex("entry_state_agent_signed_cbor"), cbor(agent_dto)
    assert_equal hex("delta_agent_signed_cbor"), cbor({ "state" => agent_dto, "claimEntry" => nil, "claim" => nil })
    peer.fold_state(load(hex("delta_agent_signed_cbor"))["state"])
    peer.fold_state(load(hex("delta_cbor"))["state"])
    assert_equal [ENTRY], peer.states.keys
  end

  def test_three_names_from_one_peer_tally_as_one_voter
    peer = peer_at(GOLDEN["certificate_verify_at"])
    (1..3).each { |i| peer.fold_state(load(hex("vote_three_names_one_peer_delta_#{i}"))["state"]) }
    assert_equal 3, peer.states.size
    proposal = GOLDEN["vote_three_names_one_peer_proposal"]
    assert_equal({ "approve" => 1, "reject" => 0 }, Votes.tally(peer.states, proposal, %w[approve reject]))
    assert_equal({ "approve" => 0, "reject" => 0 },
                 Votes.tally(peer.states, proposal, %w[approve reject], Votes::AGENT))
    assert_equal({}, Votes.tally(peer.states, proposal, permits: ->(_agent) { false }))
    forged = peer.states.dup
    first = forged.keys.first
    forged[first] = forged[first].merge("record" => forged[first]["record"].merge(
      "issuer" => golden_identity.agent("someone-else")
    ))
    assert_equal 1, Votes.tally(forged, proposal)["approve"]
  end

  def test_digest_body_matches_java
    assert_equal hex("digest_body_cbor"), Wire.digest_body({ "peers" => "x".b })
  end

  def test_decoder_round_trips_every_golden_vector
    names = GOLDEN.keys.select { |n| n.end_with?("_cbor", "_delta") }
    assert_operator names.size, :>=, 35
    names.each do |name|
      # A persistent-tree node is a definite-length map (srad/agentspaces-pdt.md 10.2), not a
      # Jackson record; PdtTest reads the node vectors through the node codec.
      next if name == "adv_deep_nesting_cbor"

      raw = hex(name)
      assert_equal raw, cbor(load(raw)), name
    end
  end

  def test_wire_version_matches_java
    assert_equal 3, GOLDEN["wire_version"]
    assert_equal 3, Wire::VERSION
    assert_equal 3, Wire.envelope("g", "PING", "p", "1:0:p", "")["ver"]
  end

  def test_agent_card_and_stored_ad_match_java
    identity = golden_identity
    card = { "id" => "aspace://#{GOLDEN['group_id']}/agent/#{identity.peer_id}/python", "issuer" => identity.peer_id,
             "group" => GOLDEN["group_id"], "issued" => "2026-01-01T00:00:00Z", "ttl" => "PT15M",
             "agent" => identity.agent("python"), "description" => "Researches a topic and writes a finding",
             "goals" => ["research"], "consumes" => [TASK], "produces" => ["GoldenVectors$Finding#v1"],
             "costHints" => { "tokens" => "low" }, "spaceBindings" => { TASK => "tasks" } }
    assert_equal hex("agent_card_cbor"), cbor(card)
    keyed = card.merge("agentPublicKey" => hex("agent_public_key_raw"))
    assert_equal hex("agent_card_with_key_cbor"), cbor(keyed)
    assert_equal hex("agent_card_with_key_signature"), identity.sign(cbor(keyed))
    signature = identity.sign(cbor(card))
    assert_equal hex("agent_card_signature"), signature
    stored = { "adType" => "AgentCard", "adBytes" => cbor(card), "publicKey" => identity.public_raw,
               "signature" => signature }
    assert_equal hex("signed_agent_card_cbor"), cbor(stored)
  end

  def test_space_advertisement_and_space_id_match_java
    space_ad = { "id" => "aspace://#{GOLDEN['group_id']}/tasks", "issuer" => GOLDEN["peer_id"],
                 "group" => GOLDEN["group_id"], "issued" => "2026-01-01T00:00:00Z", "ttl" => "PT15M",
                 "spaceName" => "tasks", "schemaHints" => [TASK], "strategy" => "LEASE_RACE",
                 "admission" => "ALLOWLIST", "replication" => "TAG_SHARDED" }
    assert_equal hex("space_ad_cbor"), cbor(space_ad)
    assert_equal GOLDEN["space_ad_space_id"], Derive.id(cbor(space_ad))
  end

  def test_aggregate_frames_match_java
    assert_equal hex("aggregate_share_frame_cbor"),
                 cbor(Wire.aggregate_frame(share: { "epochId" => "golden", "value" => 4.5, "weight" => 0.5 }))
    assert_equal hex("aggregate_extremum_frame_cbor"),
                 cbor(Wire.aggregate_frame(extremum: { "epochId" => "golden", "max" => true, "value" => 4.5 }))
    assert_equal hex("aggregate_histogram_frame_cbor"),
                 cbor(Wire.aggregate_frame(histogram: { "epochId" => "golden", "lo" => 0.0, "hi" => 10.0,
                                                        "buckets" => [1.0, 0.0, 2.0, 0.5] }))
    token = Wire.aggregate_roster_token(GOLDEN["peer_id"])
    assert_equal(-7_559_124_713_570_419_099, token)
    assert_equal Integer(GOLDEN["aggregate_roster_token"]), token
    assert_equal hex("aggregate_roster_frame_cbor"),
                 cbor(Wire.aggregate_frame(roster: { "epochId" => "golden", "members" => [token] }))
    assert_includes hex("aggregate_roster_frame_cbor"), ["3b68e767e0853dc19a"].pack("H*")
    assert_equal [token], load(hex("aggregate_roster_frame_cbor"))["roster"]["members"]
    assert_raises(ArgumentError) { Wire.aggregate_frame }
  end

  def test_gossip_learn_exchanges_match_java
    encoding = hex("learn_model_encoding")
    assert_equal [1.0, 2.5, -3.0].pack("G3"), encoding
    assert_equal GOLDEN["learn_content_id"], Wire.learn_content_id(encoding)
    assert_equal hex("learn_exchange_offer_cbor"), cbor(Wire.learn_exchange("golden-model", 7, "OFFER", 2, inline: encoding))
    assert_equal hex("learn_exchange_accept_cbor"),
                 cbor(Wire.learn_exchange("golden-model", 7, "ACCEPT", 3, inline: encoding))
    assert_equal hex("learn_exchange_busy_cbor"), cbor(Wire.learn_exchange("golden-model", 7, "BUSY", 0))
  end

  def test_take_claims_match_java
    identity = golden_identity
    claim = Wire.take_claim(ENTRY, GOLDEN["space_id"], 1, GOLDEN["hlc_encoded"], identity.agent("python"), 0,
                            1_735_693_200_000)
    assert_equal hex("take_claim_cbor"), cbor(claim)
    assert_equal hex("take_claim_signature"), identity.sign(cbor(claim))
    assert_equal hex("claim_delta_cbor"), Wire.claim_delta(ENTRY, Wire.signed_claim(claim, identity))
  end

  def test_agent_signed_claims_match_java
    identity = golden_identity
    agent = golden_agent
    claim = load(hex("take_claim_cbor"))
    assert_equal hex("take_claim_agent_signature"), agent.sign(hex("take_claim_cbor"))
    signed = Wire.signed_claim(claim, identity, agent)
    assert_equal cbor(load(hex("claim_delta_cbor"))["claim"]), cbor(Wire.signed_claim(claim, identity))
    assert_equal hex("claim_delta_with_certificate_cbor"), Wire.claim_delta(ENTRY, signed)
    now = ms(GOLDEN["certificate_verify_at"])
    assert Wire.verify_claim_proof(signed, now)
    refute Wire.verify_claim_proof(signed.merge("holderCertificate" => nil), now)
  end

  def test_claim_lattice_order_matches_the_java_merge
    base = Wire.take_claim("e", "s", 1, "100:0:node-a", "peer/a", 0.0, 1000)
    higher_epoch = Wire.take_claim("e", "s", 2, "200:0:node-b", "peer/b", 0.0, 1000)
    cheaper = Wire.take_claim("e", "s", 1, "200:0:node-b", "peer/b", -1.0, 1000)
    earlier = Wire.take_claim("e", "s", 1, "50:0:node-b", "peer/b", 0.0, 1000)
    winner = ->(a, b) { Wire.merge_claims({ "claim" => a }, { "claim" => b })["claim"] }
    assert_equal higher_epoch, winner.call(base, higher_epoch)
    assert_equal cheaper, winner.call(base, cheaper)
    assert_equal earlier, winner.call(base, earlier)
    assert_equal base, winner.call(base, base)
  end

  def test_a_record_sealed_under_epoch_two_names_its_epoch
    identity = golden_identity
    record = load(hex("entry_record_key_epoch_cbor"))
    assert_equal 2, record["keyEpoch"]
    view = Wire.sign_view(record["entryId"], record["spaceId"], record["type"], record["payload"], record["issuer"],
                          record["issued"], key_epoch: 2)
    assert_equal hex("sign_view_key_epoch_cbor"), cbor(view)
    assert_equal hex("sign_view_key_epoch_cbor"), cbor(Wire.sign_view_of(record))
    assert Wire.verify_record(record, identity.public_raw, nil, 0)
    assert_equal "#{GOLDEN['space_id']}|#{record['entryId']}|2", GOLDEN["content_key_aad_epoch_2"]
    plain = load(hex("entry_state_dto_cbor"))["record"]
    assert_equal hex("sign_view_cbor"), cbor(Wire.sign_view_of(plain))
  end

  def test_a_certificate_can_certify_the_agents_encryption_key
    identity = golden_identity
    certificate = load(hex("agent_certificate_with_encryption_cbor"))
    assert_equal hex("agent_encryption_public_key_raw"), certificate["encryptionPublicKey"]
    assert_equal hex("agent_certificate_with_encryption_unsigned_cbor"), cbor(Certificates.body(certificate))
    assert Certificates.verify(certificate, identity.public_raw, identity.agent("python"),
                               ms(GOLDEN["certificate_verify_at"]))
  end

  def test_credential_revocations_from_the_agents_own_peer_apply_the_freeze_rule
    identity = golden_identity
    registry = Revocation::Registry.new(-> {}, -> { GOLDEN["group_id"] })
    now = ms("2026-06-01T00:00:00Z")
    %w[agent agent_key].each do |kind|
      assert registry.accept(Revocation::CREDENTIAL_STREAM, hex("signed_credential_revocation_#{kind}_cbor"), now),
             kind
    end
    issued = ms("2026-01-01T00:00:00Z")
    agent = identity.agent("python")
    refute registry.refuses?(agent, nil, issued - (90 * 60 * 1000))
    assert registry.refuses?(agent, nil, issued - (30 * 60 * 1000))
    assert registry.refuses?(agent, nil, nil)
    assert registry.refuses?(agent, hex("agent_public_key_raw"), 0)
    refute registry.refuses?(identity.agent("sibling"), nil, issued)
    stranger = Identity.generate
    ad = hex("credential_revocation_agent_cbor")
    fresh = Revocation::Registry.new(-> {}, -> { GOLDEN["group_id"] })
    refute fresh.accept_signed(Revocation::CREDENTIAL_STREAM,
                               { "adBytes" => ad, "publicKey" => stranger.public_raw, "signature" => stranger.sign(ad) },
                               now)
  end

  def test_a_card_declares_its_actions_and_carries_its_certificate
    identity = golden_identity
    certificate = load(hex("agent_certificate_cbor"))
    card = Wire.agent_card(GOLDEN["group_id"], identity, "python", GOLDEN["certificate_verify_at"], "PT15M",
                           "Researches a topic and writes a finding", ["research"], [TASK],
                           ["GoldenVectors$Finding#v1"], { "tokens" => "low" }, { TASK => "tasks" },
                           agent_public_raw: hex("agent_public_key_raw"),
                           actions: [Wire.card_action("research", "Researches a topic and writes a finding", [TASK],
                                                      ["GoldenVectors$Finding#v1"], "take", "tasks")],
                           agent_certificate: certificate)
    assert_equal hex("agent_card_with_actions_cbor"), cbor(card)
    assert_equal hex("agent_card_with_actions_signature"), identity.sign(cbor(card))
  end

  def test_epoch_commitment_and_wrap_binding_reencode
    %w[epoch_commitment_cbor wrap_binding_v2_cbor].each { |n| assert_equal hex(n), cbor(load(hex(n))) }
    assert Identity.verify(golden_identity.public_raw, hex("epoch_commitment_cbor"), hex("epoch_proof_signature"))
  end

  def stamp(offset_ms, logical = 0)
    "#{Wire.hlc_physical(GOLDEN['hlc_encoded']) + offset_ms}:#{logical}:#{GOLDEN['peer_id']}"
  end

  def agent_dto(adds, removes, lease_stamp, lease_value, completed, signed_at)
    identity = golden_identity
    agent = golden_agent
    record = load(hex("entry_state_agent_signed_cbor"))["record"]
    signer = identity.agent("python")
    view = Wire.state_sign_view(GOLDEN["space_id"], ENTRY, adds, removes, lease_stamp, lease_value, completed, signer,
                                signed_at)
    [view, { "record" => record, "issuerPublicKey" => identity.public_raw, "adds" => adds, "removes" => removes,
             "leaseStamp" => lease_stamp, "leaseValue" => lease_value, "completed" => completed,
             "stateSig" => agent.sign(cbor(view)), "agentCertificate" => agent.certificate,
             "stateCertificate" => agent.certificate, "signer" => signer, "signedAt" => signed_at }]
  end

  def test_agent_signed_renew_cancel_and_complete_match_java_and_fold
    identity = golden_identity
    python = identity.agent("python")
    adds = [{ "replica" => identity.peer_id, "counter" => 1 }]
    write_lease = { "holder" => python, "expiresAtMillis" => 1_735_693_200_000, "kind" => "WRITE" }
    t0 = Wire.hlc_physical(GOLDEN["hlc_encoded"])
    cases = {
      "renew" => [adds, [], stamp(60_000), { "holder" => python, "expiresAtMillis" => t0 + 7_200_000, "kind" => "WRITE" },
                  false, stamp(60_000, 1)],
      "cancel" => [adds, adds, GOLDEN["hlc_encoded"], write_lease, false, stamp(120_000)],
      "complete" => [adds, [], GOLDEN["hlc_encoded"], write_lease, true, stamp(180_000)]
    }
    claim_proof = load(hex("claim_delta_with_certificate_cbor"))["claim"]
    cases.each do |name, args|
      view, dto = agent_dto(*args)
      assert_equal hex("state_sign_view_agent_#{name}_cbor"), cbor(view), name
      assert_equal hex("entry_state_agent_#{name}_cbor"), cbor(dto), name
      delta = if name == "complete"
                { "state" => dto, "claimEntry" => ENTRY, "claim" => claim_proof }
              else
                { "state" => dto, "claimEntry" => nil, "claim" => nil }
              end
      assert_equal hex("delta_agent_#{name}_cbor"), cbor(delta), name

      peer = peer_at(GOLDEN["certificate_verify_at"])
      peer.fold_state(load(hex("delta_agent_signed_cbor"))["state"])
      decoded = load(hex("delta_agent_#{name}_cbor"))
      peer.fold_claim(decoded["claimEntry"], decoded["claim"]) if decoded["claim"]
      peer.fold_state(decoded["state"])
      held = peer.states[ENTRY]
      case name
      when "renew"
        assert_equal stamp(60_000), held["leaseStamp"]
        assert_equal t0 + 7_200_000, held["leaseValue"]["expiresAtMillis"]
      when "cancel" then assert_equal adds, held["removes"]
      else
        assert_equal true, held["completed"]
        assert_equal golden_agent.certificate, held["stateCertificate"]
      end
    end
  end

  def test_a_completion_without_its_claim_is_refused
    peer = peer_at(GOLDEN["certificate_verify_at"])
    peer.fold_state(load(hex("delta_agent_signed_cbor"))["state"])
    peer.fold_state(load(hex("delta_agent_complete_cbor"))["state"])
    assert_equal false, peer.states[ENTRY]["completed"]
  end

  def test_a_state_signed_outside_its_window_or_beyond_the_drift_ceiling_is_refused
    { "adv_agent_state_out_of_window_delta" => -3_600_000, "adv_agent_state_drift_delta" => 660_000 }.each do |n, off|
      state = load(hex(n))["state"]
      assert_equal stamp(off), state["signedAt"], n
      peer = peer_at(GOLDEN["certificate_verify_at"])
      peer.fold_state(state)
      assert_empty peer.states, n
    end
    caught_up = peer_at(Wire.hlc_physical(GOLDEN["hlc_encoded"]) + 60_000)
    caught_up.fold_state(load(hex("adv_agent_state_drift_delta"))["state"])
    assert_equal [ENTRY], caught_up.states.keys
  end

  def test_an_out_of_window_agent_claim_is_refused
    peer = peer_at(GOLDEN["certificate_verify_at"])
    delta = load(hex("adv_claim_cert_out_of_window_delta"))
    assert_equal stamp(-3_600_000), delta["claim"]["claim"]["stamp"]
    refute Wire.verify_claim_proof(delta["claim"], ms(GOLDEN["certificate_verify_at"]))
    peer.fold_claim(delta["claimEntry"], delta["claim"])
    assert_empty peer.claims
    control = load(hex("claim_delta_with_certificate_cbor"))
    peer.fold_claim(control["claimEntry"], control["claim"])
    assert_equal [ENTRY], peer.claims.keys
  end

  def test_a_relabelled_key_epoch_never_verifies
    identity = golden_identity
    relabelled = load(hex("adv_key_epoch_relabelled_record_cbor"))
    genuine = load(hex("entry_record_key_epoch_cbor"))
    assert_equal 3, relabelled["keyEpoch"]
    assert_equal genuine["sig"], relabelled["sig"]
    assert Wire.verify_record(genuine, identity.public_raw, nil, 0)
    refute Wire.verify_record(relabelled, identity.public_raw, nil, 0)
    peer = peer_at(GOLDEN["certificate_verify_at"])
    peer.fold_state(load(hex("adv_key_epoch_relabelled_delta"))["state"])
    assert_empty peer.states
    peer.fold_state(load(hex("delta_key_epoch_cbor"))["state"])
    assert_equal 2, peer.states[ENTRY]["record"]["keyEpoch"]
  end

  def test_leaf_and_join_credential_revocations_need_the_founder
    now = ms("2026-06-01T00:00:00Z")
    expected = {
      "x509_leaf" => { "kind" => "X509_LEAF", "x509Issuer" => "CN=golden-leaf,O=Bad Monkey", "x509Serial" => "0a1b2c3d",
                       "certificateFingerprint" => Crypto.port.sha256("golden-leaf-der") },
      "join_credential" => { "kind" => "JOIN_CREDENTIAL",
                             "credentialHash" => Crypto.port.sha256("golden-join-credential") }
    }
    founded = Revocation::Registry.new(-> { GOLDEN["peer_id"] }, -> { GOLDEN["group_id"] })
    stranger = Revocation::Registry.new(-> { Identity.generate.peer_id }, -> { GOLDEN["group_id"] })
    expected.each do |kind, target|
      ad = load(hex("credential_revocation_#{kind}_cbor"))
      assert_equal target, ad["target"], kind
      assert_equal Revocation.revocation_id(GOLDEN["group_id"], target), ad["id"]
      signed = hex("signed_credential_revocation_#{kind}_cbor")
      assert founded.accept(Revocation::CREDENTIAL_STREAM, signed, now), kind
      refute stranger.accept(Revocation::CREDENTIAL_STREAM, signed, now), kind
    end
    assert_equal ["X509_LEAF:#{expected['x509_leaf']['certificateFingerprint'].unpack1('H*')}",
                  "JOIN_CREDENTIAL:#{expected['join_credential']['credentialHash'].unpack1('H*')}"].sort,
                 founded.credentials.keys.sort
  end

  def test_a_cross_issuer_revocation_is_refused
    signed = load(hex("adv_credential_revocation_cross_issuer_cbor"))
    ad = load(signed["adBytes"])
    assert_equal Derive.id(hex("adv_forger_public_key_raw")), ad["issuer"]
    assert_equal({ "kind" => "AGENT", "agent" => golden_identity.agent("python") }, ad["target"])
    now = ms("2026-06-01T00:00:00Z")
    [GOLDEN["peer_id"], nil].each do |founder|
      registry = Revocation::Registry.new(-> { founder }, -> { GOLDEN["group_id"] })
      refute registry.accept(Revocation::CREDENTIAL_STREAM, hex("adv_credential_revocation_cross_issuer_cbor"), now)
      refute registry.refuses?(golden_identity.agent("python"), hex("agent_public_key_raw"), 0)
    end
  end

  def test_a_record_under_a_renewed_certificate_matches_java_and_is_judged_at_signing_time
    identity = golden_identity
    verify_at = ms(GOLDEN["certificate_verify_at"])
    signed_at = ms(GOLDEN["renewed_certificate_signed_at"])
    now = [verify_at]
    agent = identity.renewing_subordinate("python", "PT24H",
                                          key: Identity.from_pkcs8(hex("agent_private_key_pkcs8")),
                                          clock: -> { now[0] / 1000.0 })
    assert_equal hex("agent_certificate_cbor"), cbor(agent.certificate)
    now[0] = verify_at + (13 * 3600 * 1000)
    assert agent.renew_if_due
    now[0] = signed_at
    renewed = agent.certificate_covering(signed_at)
    assert_equal hex("renewed_agent_certificate_cbor"), cbor(renewed)

    python = identity.agent("python")
    stamp = "#{signed_at}:0:#{identity.peer_id}"
    state_stamp = "#{signed_at}:1:#{identity.peer_id}"
    entry = "44444444-5555-6666-7777-888888888888"
    view = Wire.sign_view(entry, GOLDEN["space_id"], TASK, hex("task_payload_cbor"), python, stamp)
    assert_equal hex("sign_view_renewed_certificate_cbor"), cbor(view)
    lease = { "holder" => python, "expiresAtMillis" => signed_at + 3_600_000, "kind" => "WRITE" }
    record = { "entryId" => entry, "spaceId" => GOLDEN["space_id"], "type" => TASK,
               "payload" => hex("task_payload_cbor"), "payloadRef" => nil, "issuer" => python, "issued" => stamp,
               "lease" => lease, "tags" => {}, "sig" => agent.sign(cbor(view)) }
    adds = [{ "replica" => identity.peer_id, "counter" => 21 }]
    state_view = Wire.state_sign_view(GOLDEN["space_id"], entry, adds, [], stamp, lease, false, python, state_stamp)
    dto = { "record" => record, "issuerPublicKey" => identity.public_raw, "adds" => adds, "removes" => [],
            "leaseStamp" => stamp, "leaseValue" => lease, "completed" => false,
            "stateSig" => agent.sign(cbor(state_view)), "agentCertificate" => renewed, "stateCertificate" => renewed,
            "signer" => python, "signedAt" => state_stamp }
    assert_equal hex("entry_state_renewed_certificate_cbor"), cbor(dto)
    assert_equal hex("delta_renewed_certificate_cbor"), cbor({ "state" => dto, "claimEntry" => nil, "claim" => nil })

    long_after = signed_at + (30 * 3600 * 1000)
    first = load(hex("agent_certificate_cbor"))
    assert Certificates.verify_at(renewed, identity.public_raw, python, signed_at, long_after)
    refute Certificates.verify(renewed, identity.public_raw, python, long_after)
    refute Certificates.verify_at(first, identity.public_raw, python, signed_at, signed_at)
    peer = peer_at(GOLDEN["renewed_certificate_signed_at"])
    peer.fold_state(load(hex("delta_renewed_certificate_cbor"))["state"])
    assert_equal [entry], peer.states.keys
    behind = peer_at(GOLDEN["certificate_verify_at"])
    behind.fold_state(load(hex("delta_renewed_certificate_cbor"))["state"])
    assert_empty behind.states
  end

  def test_filter_grammar_decides_as_java_does
    GOLDEN["filter_grammar_cases"].each do |c|
      assert_equal c["matches"], Filters.parse(c["filter"])[1].call(c["value"]), c.inspect
    end
    GOLDEN["filter_grammar_malformed"].each do |clause|
      error = assert_raises(ArgumentError) { Filters.parse(clause) }
      assert_match(/malformed field filter/, error.message)
    end
    assert Filters.parse("a<b<=c")[1].call("a")
    assert Filters.parse("topic=a in b")[1].call("a in b")
  end
end
