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

# Self-certifying groups (SPEC 4.4, 5.1) and the join-by-GroupID bootstrap
# (SPEC 9, 10.1) against the golden vectors, and the adversarial inputs
# every client must refuse without crashing its reader.
class FoundingTest < Minitest::Test
  include GoldenHelpers
  include AgentSpaces

  def found = Founding.found(golden_identity, "golden-fleet", "OPEN", "LEASE_RACE", 3, "PT1S",
                             "2026-01-01T00:00:00Z", "PT24H")

  def test_founding_fields_and_signature_match_java
    fields = Founding.fields("golden-fleet", GOLDEN["peer_id"], "2026-01-01T00:00:00Z", "PT24H", "OPEN", "LEASE_RACE",
                             3, "PT1S")
    assert_equal hex("founding_fields_cbor"), cbor(fields)
    signature = golden_identity.sign(cbor(fields))
    assert_equal hex("founding_signature"), signature
    document = Founding.document(fields, signature)
    assert_equal hex("founding_document_cbor"), cbor(document)
    assert_equal GOLDEN["founding_group_id"], Derive.group_id_from_founding_document(cbor(document))
  end

  def test_found_reproduces_the_java_advertisement
    signed = found
    ad = signed["advertisement"]
    assert_equal GOLDEN["founding_group_id"], ad["group"]
    assert_equal GOLDEN["founding_ad_id"], ad["id"]
    assert_equal hex("group_ad_cbor"), cbor(ad)
    assert_equal hex("signed_group_ad_cbor"), cbor(signed)
    assert_equal hex("signed_group_ad_cbor"), Wire.group_ad_body(signed)
  end

  def test_the_four_checks_accept_the_genuine_founding_and_refuse_the_hostile_ones
    assert_equal GOLDEN["founding_group_id"], Founding.verify(found)
    assert_equal GOLDEN["founding_group_id"], Founding.verify(load(hex("signed_group_ad_cbor")))
    %w[adv_group_ad_wrong_id_cbor adv_group_ad_forged_signature_cbor].each do |name|
      signed = load(hex(name))
      assert_kind_of Hash, signed
      assert_nil Founding.verify(signed), name
    end
    forged = load(hex("adv_group_ad_forged_signature_cbor"))
    assert_nil Founding.verify(forged.merge("founderPublicKey" => hex("adv_forger_public_key_raw")))
  end

  def test_verification_tolerates_malformed_shapes
    signed = found
    assert_nil Founding.verify(nil)
    assert_nil Founding.verify({})
    assert_nil Founding.verify(signed.merge("founderPublicKey" => "\x00".b * 31))
    assert_nil Founding.verify(signed.merge("signature" => 42))
    assert_nil Founding.verify(signed.merge("advertisement" => signed["advertisement"].except("gossip")))
    assert_nil Founding.verify(signed.merge("advertisement" => signed["advertisement"].merge(
      "gossip" => { "fanout" => "3", "period" => "PT1S" }
    )))
    assert_nil Founding.verify(signed.merge("advertisement" => signed["advertisement"].merge(
      "id" => "aspace://#{GOLDEN['group_id']}"
    )))
  end

  def test_group_ad_want_and_group_ad_frames_match_java
    identity = golden_identity
    env = Wire.group_ad_want_envelope(GOLDEN["founding_group_id"], GOLDEN["peer_id"], GOLDEN["hlc_encoded"],
                                      GOLDEN["peer_id"])
    assert_equal hex("group_ad_want_envelope_cbor"), cbor(env)
    assert_equal hex("group_ad_want_frame_cbor"), Wire.encode_frame(env, identity)
    assert_nil Wire.group_ad_want_envelope("g", "p", "1:0:p")["to"]
    body = Wire.group_ad_body(found)
    env = Wire.envelope(GOLDEN["founding_group_id"], Wire::KIND_GROUP_AD, GOLDEN["peer_id"], GOLDEN["hlc_encoded"],
                        body, GOLDEN["peer_id"])
    assert_equal hex("group_ad_envelope_cbor"), cbor(env)
    assert_equal hex("group_ad_frame_cbor"), Wire.encode_frame(env, identity)
  end

  def test_a_frame_of_another_wire_version_is_dropped_before_verification
    identity = golden_identity
    env = Wire.group_ad_want_envelope(GOLDEN["founding_group_id"], GOLDEN["peer_id"], GOLDEN["hlc_encoded"],
                                      GOLDEN["peer_id"])
    refute_nil Wire.decode_frame(Wire.encode_frame(env, identity))
    [1, 2, 4, "3", nil, true].each do |bad|
      assert_nil Wire.decode_frame(Wire.encode_frame(env.merge("ver" => bad), identity)), bad.inspect
    end
  end

  def joiner
    golden_seconds = Integer(GOLDEN["hlc_encoded"].split(":").first) / 1000.0
    Peer.new(golden_identity, GOLDEN["founding_group_id"], clock: -> { golden_seconds + 1 })
  end

  def drive(peer, frame)
    env = Wire.decode_frame(frame)
    refute_nil env
    peer.handle(env) if peer.accepts?(env)
  end

  def test_the_join_path_accepts_the_verified_group_ad_and_ignores_hostile_ones
    %w[adv_group_ad_wrong_id_cbor adv_group_ad_forged_signature_cbor].each do |name|
      peer = joiner
      physical, logical, node = GOLDEN["hlc_encoded"].split(":")
      earlier = "#{physical}:#{Integer(logical) - 1}:#{node}"
      hostile = Wire.envelope(GOLDEN["founding_group_id"], Wire::KIND_GROUP_AD, GOLDEN["peer_id"], earlier, hex(name),
                              GOLDEN["peer_id"])
      drive(peer, Wire.encode_frame(hostile, golden_identity))
      assert_nil peer.founding, name
      drive(peer, hex("group_ad_frame_cbor"))
      assert_equal load(hex("signed_group_ad_cbor")), peer.founding
    end
  end

  def test_a_genuine_document_for_another_group_does_not_complete_the_join
    other = Founding.found(golden_identity, "other-fleet", "OPEN", "LEASE_RACE", 3, "PT1S", "2026-01-01T00:00:00Z",
                           "PT24H")
    peer = joiner
    peer.send(:on_group_ad, Wire.group_ad_body(other))
    assert_nil peer.founding
  end

  def test_join_by_group_id_times_out_without_a_verified_answer_and_names_the_cause
    seed = Testing::FakeSeed.new
    peer = Peer.new(golden_identity, nil)
    error = assert_raises(Timeout::Error) do
      peer.join_by_group_id("127.0.0.1", seed.port, GOLDEN["founding_group_id"], timeout: 0.3)
    end
    assert_match(/founding: text has no signed founding/, error.message)
    assert_equal GOLDEN["founding_group_id"], peer.group
    refute peer.connected?
    wants = seed.received.select { |e| e["kind"] == Wire::KIND_GROUP_AD_WANT }
    refute_empty wants
    assert(wants.all? { |e| e["to"].nil? && e["body"].empty? })
  ensure
    seed&.close
  end

  # ---------------------------------------------------------------- adversarial

  def test_hostile_claims_never_enter_the_lattice
    %w[adv_claim_bad_signature_delta adv_claim_transplanted_delta adv_claim_nan_bid_delta adv_claim_epoch_zero_delta
       adv_claim_epoch_jump_delta adv_claim_eternal_delta].each do |name|
      peer = Peer.new(golden_identity, GOLDEN["group_id"])
      delta = load(hex(name))
      peer.fold_claim(delta["claimEntry"], delta["claim"])
      assert_empty peer.claims, name
    end
  end

  def test_deep_nesting_is_refused_bounded
    assert_raises(CBOR::Error) { load(hex("adv_deep_nesting_cbor")) }
  end

  def test_tampered_misaddressed_and_foreign_frames_fail
    assert_nil Wire.decode_frame(hex("adv_frame_bad_signature"))
    env = Wire.decode_frame(hex("adv_frame_wrong_destination"))
    refute_nil env
    assert_equal GOLDEN["adv_frame_wrong_destination_to"], env["to"]
    peer = Peer.new(golden_identity, GOLDEN["group_id"])
    assert peer.accepts?(Wire.decode_frame(hex("ping_frame_cbor")))
    refute peer.accepts?(env)
    refute Peer.new(golden_identity, "zSomeOtherGroup").accepts?(Wire.decode_frame(hex("ping_frame_cbor")))
    refute peer.accepts?(nil)
    assert_equal GOLDEN["max_frame_bytes"], Wire::MAX_FRAME_BYTES
  end

  def test_hostile_certificates_never_authenticate_a_record
    control = peer_at(GOLDEN["certificate_verify_at"])
    control.fold_state(load(hex("delta_agent_signed_cbor"))["state"])
    assert_equal 1, control.states.size
    %w[adv_cert_wrong_peer_delta adv_cert_wrong_agent_delta adv_cert_expired_delta adv_cert_uncertified_key_delta
       adv_cert_peer_signed_record_delta adv_legacy_state_on_attested_entry_delta_cbor delta_with_certificate_cbor
       adv_agent_state_peer_key_delta adv_agent_state_wrong_signer_delta].each do |name|
      peer = peer_at(GOLDEN["certificate_verify_at"])
      peer.fold_state(load(hex(name))["state"])
      assert_empty peer.states, name
    end
    ["2024-12-31T00:30:00Z", GOLDEN["certificate_verify_at"]].each do |at|
      peer = peer_at(at)
      peer.fold_state(load(hex("adv_cert_expired_delta"))["state"])
      assert_empty peer.states, at
    end
  end

  def test_hostile_certified_claims_never_enter_the_lattice
    control = peer_at(GOLDEN["certificate_verify_at"])
    good = load(hex("claim_delta_with_certificate_cbor"))
    control.fold_claim(good["claimEntry"], good["claim"])
    assert_equal [good["claimEntry"]], control.claims.keys
    %w[adv_claim_cert_peer_signed_delta adv_claim_cert_expired_delta adv_claim_cert_wrong_holder_delta
       adv_claim_predates_issue_delta].each do |name|
      peer = peer_at(GOLDEN["certificate_verify_at"])
      # A receiver holding the entry refuses a claim that predates its issue stamp.
      peer.fold_state(load(hex("delta_cbor"))["state"]) if name == "adv_claim_predates_issue_delta"
      delta = load(hex(name))
      peer.fold_claim(delta["claimEntry"], delta["claim"])
      assert_empty peer.claims, name
    end
  end

  def test_every_hostile_adv_input_is_covered
    covered = %w[adv_claim_bad_signature_delta adv_claim_transplanted_delta adv_claim_nan_bid_delta
                 adv_claim_epoch_zero_delta adv_claim_epoch_jump_delta adv_claim_eternal_delta adv_deep_nesting_cbor
                 adv_frame_bad_signature adv_frame_wrong_destination adv_frame_wrong_destination_to
                 adv_group_ad_wrong_id_cbor adv_group_ad_forged_signature_cbor adv_forger_private_key_pkcs8
                 adv_forger_public_key_raw adv_cert_wrong_peer_delta adv_cert_wrong_agent_delta adv_cert_expired_delta
                 adv_cert_uncertified_key_delta adv_cert_peer_signed_record_delta adv_claim_cert_peer_signed_delta
                 adv_claim_cert_expired_delta adv_claim_cert_wrong_holder_delta
                 adv_legacy_state_on_attested_entry_dto_cbor adv_legacy_state_on_attested_entry_delta_cbor
                 adv_agent_state_peer_key_delta adv_agent_state_wrong_signer_delta adv_agent_state_out_of_window_delta
                 adv_agent_state_drift_delta adv_claim_cert_out_of_window_delta adv_claim_predates_issue_delta
                 adv_key_epoch_relabelled_record_cbor adv_key_epoch_relabelled_delta adv_key_wrap_wrong_group_cbor
                 adv_key_wrap_wrong_group_binding_cbor adv_key_wrap_wrong_epoch_cbor
                 adv_key_wrap_wrong_epoch_binding_cbor adv_key_wrap_wrong_rotator_cbor
                 adv_key_wrap_wrong_rotator_binding_cbor adv_credential_revocation_cross_issuer_cbor
                 adv_app_card_kind_realm_cbor adv_app_card_sign_on_tenant_cbor adv_app_card_formats_empty_cbor
                 adv_app_card_origin_attrs_empty_cbor adv_app_card_formats_bound_cbor adv_app_card_formats_upper_cbor
                 adv_app_card_formats_duplicate_cbor adv_app_card_formats_parameter_cbor
                 adv_app_card_origin_system_cbor adv_app_card_origin_attrs_prefix_cbor
                 adv_app_card_origin_ref_bound_cbor adv_app_card_spill_placeholder_cbor
                 adv_app_card_spill_parts_order_cbor adv_app_card_spill_parts_unknown_cbor
                 adv_app_card_spill_parts_empty_cbor adv_app_card_spill_root_codec_cbor
                 adv_app_card_spill_size_zero_cbor adv_agent_card_spill_actions_cbor]
    assert_equal [], GOLDEN.keys.grep(/\Aadv_/) - covered
  end
end
