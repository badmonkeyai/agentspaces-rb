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

# HLC round six, 2026-11-08 (F1, F2, F3): the wire encoding every
# implementation shares. A receiver checks a document's items (S1 to S12),
# reads a protocol record under its schema (P1 to P4), and refuses the
# carrier as undecodable unless re-encoding what it decoded gives exactly the
# bytes it received. The vectors are the definition's own
# (wire-encoding-vectors.json, a copy of the round's vectors.json): Java
# signed the base carriers with the golden fixture key, and each relabel
# keeps that signature over an altered form. The persistent-tree head vectors
# (carrier pref) belong to the PDT owner's suite.
class WireEncodingTest < Minitest::Test
  include AgentSpaces
  include GoldenHelpers

  VECTORS = JSON.parse(File.read(File.join(__dir__, "wire-encoding-vectors.json"))).fetch("vectors")
  ENTRY = "11111111-2222-3333-4444-555555555555"
  # The vectors' stamps lie at this physical time.
  STAMPED = 1_800_000_000_000

  def bytes(hex) = [hex.delete(" ")].pack("H*")

  def vectors(carrier) = VECTORS.select { |v| v["carrier"] == carrier }

  # A receiver whose wall clock reads the vectors' signing time.
  def receiver = Peer.new(Identity.generate, GOLDEN["group_id"], clock: -> { (STAMPED + 1_000) / 1000.0 })

  def test_every_document_vector_decodes_as_the_encoding_says
    vectors("document").each do |v|
      raw = bytes(v["hex"])
      if v["verdict"] == "accept"
        value = CBOR.load(raw)
        assert_equal raw, CBOR.dump(value), "#{v['id']} re-encodes to its own bytes (#{v['why']})"
      else
        assert_raises(CBOR::Error, "#{v['id']} is undecodable (#{v['rule']}: #{v['why']})") { CBOR.load(raw) }
      end
    end
  end

  # A frame decodes when its envelope verifies and its body reads under the
  # body schema of its kind; anything else is an undecodable frame.
  def frame_verdict(raw)
    env, = Wire.decode_frame_detailed(raw)
    return "refuse-undecodable" if env.nil?

    Wire.decode_body(env["kind"], env["body"])
    "accept"
  rescue CBOR::Error
    "refuse-undecodable"
  end

  def test_every_frame_vector_decodes_as_the_encoding_says
    vectors("frame").each do |v|
      assert_equal v["verdict"], frame_verdict(bytes(v["hex"])), "#{v['id']} (#{v['rule']}: #{v['why']})"
    end
  end

  # F1, P2: a frame its sender signed, with an envelope kind no constant
  # names, or a RUMOR body whose int field holds a float or whose text field
  # holds a byte string, is undecodable, as Java's reader refuses each. The
  # signature cannot catch these, since the sender signed the bytes as sent.
  def test_a_signed_frame_with_a_field_of_another_kind_is_undecodable
    sender = Identity.generate
    stamp = "#{STAMPED}:0:#{sender.peer_id}"
    unknown = Wire.envelope(GOLDEN["group_id"], "BOGUS", sender.peer_id, stamp, Wire.ping_body(1))
    assert_nil Wire.decode_frame(Wire.encode_frame(unknown, sender)), "an unknown kind does not decode"
    {
      "hopsRemaining as a float" => { "streamId" => "space:tasks", "itemId" => "i", "hopsRemaining" => 3.0, "payload" => "".b },
      "streamId as a byte string" => { "streamId" => "space:tasks".b, "itemId" => "i", "hopsRemaining" => 3, "payload" => "".b }
    }.each do |name, rumor|
      env = Wire.envelope(GOLDEN["group_id"], "RUMOR", sender.peer_id, stamp, CBOR.dump(rumor))
      decoded = Wire.decode_frame(Wire.encode_frame(env, sender))
      refute_nil decoded, "the envelope of #{name} verifies"
      assert_raises(Schema::Error, "a body with #{name} is undecodable") { Wire.decode_body("RUMOR", decoded["body"]) }
    end
  end

  # A space delta in a RUMOR: an accepted one merges its state or claim, and
  # a refused one merges nothing and counts once in deltas_undecodable.
  def test_every_space_delta_vector_folds_as_the_encoding_says
    sender = Identity.generate
    vectors("space-delta").each do |v|
      peer = receiver
      body = Wire.rumor_body("space:tasks", "w:#{ENTRY}", Wire::HOPS, bytes(v["hex"]))
      env = Wire.envelope(GOLDEN["group_id"], "RUMOR", sender.peer_id, "#{STAMPED}:0:#{sender.peer_id}", body)
      peer.handle(Wire.decode_frame(Wire.encode_frame(env, sender)))
      merged = peer.states.key?(ENTRY) || peer.claims.key?(ENTRY)
      # delta-13 decodes, and its fold then drops it under the dot binding
      # (test_a_state_whose_dots_name_another_replica_merges_nothing).
      if v["id"] == "delta-13"
        refute merged, "delta-13 names replicas other than its issuer's peer"
        assert_equal 0, peer.deltas_undecodable, "delta-13 counts nothing"
      elsif v["verdict"] == "accept"
        assert merged, "#{v['id']} merges (#{v['why']})"
        assert_equal 0, peer.deltas_undecodable, "#{v['id']} counts nothing"
      else
        refute merged, "#{v['id']} merges nothing (#{v['rule']}: #{v['why']})"
        assert_equal 1, peer.deltas_undecodable, "#{v['id']} counts as undecodable (#{v['rule']}: #{v['why']})"
      end
    end
  end

  # HLC round six, 2026-11-08 (S1, F3): a space delta whose array head
  # claims more items than its bytes hold is undecodable and counts once in
  # deltas_undecodable, whatever the count; no other error leaves the fold.
  def test_a_space_delta_whose_array_head_outruns_its_bytes_counts_as_undecodable
    sender = Identity.generate
    ["9B FF FF FF FF FF FF FF FF", "BF 65 73 74 61 74 65 9B 7F FF FF FF FF FF FF FF FF",
     "BF 65 73 74 61 74 65 9B 06 64 DF 7A 6B C4 61 73 FF"].each_with_index do |hex, n|
      peer = receiver
      body = Wire.rumor_body("space:tasks", "w:#{ENTRY}", Wire::HOPS, bytes(hex))
      env = Wire.envelope(GOLDEN["group_id"], "RUMOR", sender.peer_id, "#{STAMPED}:#{n}:#{sender.peer_id}", body)
      peer.handle(Wire.decode_frame(Wire.encode_frame(env, sender)))
      assert_equal 1, peer.deltas_undecodable, "#{hex} counts as undecodable"
    end
  end

  # P1: a field omitted when empty (AppCard.Ui.components) that arrives as
  # another item is a wrong-typed field (F1), refused as Schema::Error.
  def test_an_omit_when_empty_field_of_another_type_is_a_schema_error
    ui = { "protocol" => "a2ui", "version" => "1", "catalogIds" => [], "agent" => "a", "transport" => "t",
           "surfaces" => [], "components" => 5 }
    assert_raises(Schema::Error) { Schema.check("AppCard.Ui", ui) }
  end

  # Reference rule (HLC round six, 2026-11-08): a record Java's constructor
  # refuses does not decode in Java, so its delta is undecodable there. An
  # EntryRecord holds exactly one of payload and payloadRef, an inline
  # payload of at most 64 KiB, and a keyEpoch of 1 or more when present; an
  # AgentCertificate holds a positive ttl and a 32-byte encryption key when
  # it holds one. Each such delta counts once in deltas_undecodable.
  def test_a_record_javas_constructor_refuses_makes_its_delta_undecodable
    base = CBOR.load(bytes(VECTORS.find { |v| v["id"] == "delta-01" }["hex"]))
    record = ->(delta) { delta["state"]["record"] }
    certificate = { "agent" => "#{golden_identity.peer_id}/a", "agentPublicKey" => "\x01".b * 32,
                    "issued" => "2026-01-01T00:00:00Z", "ttl" => "PT1H", "peerSignature" => "\x02".b * 64 }
    with_certificate = lambda do |delta, changes|
      state = delta["state"]
      rebuilt = {}
      state.each do |key, value|
        rebuilt[key] = value
        rebuilt["agentCertificate"] = certificate.merge(changes) if key == "stateSig"
      end
      delta["state"] = rebuilt
    end
    cases = {
      "payload and payloadRef both set" => ->(d) { record.call(d)["payloadRef"] = "zcid" },
      "neither payload nor payloadRef" => ->(d) { record.call(d)["payload"] = nil },
      "an inline payload past 64 KiB" => ->(d) { record.call(d)["payload"] = "\x00".b * ((64 * 1024) + 1) },
      "keyEpoch 0" => ->(d) { record.call(d)["keyEpoch"] = 0 },
      "a certificate ttl of zero" => ->(d) { with_certificate.call(d, "ttl" => "PT0S") },
      "a 31-byte encryption key" => ->(d) { with_certificate.call(d, "encryptionPublicKey" => "\x03".b * 31) }
    }
    sender = Identity.generate
    cases.each_with_index do |(name, change), n|
      delta = Marshal.load(Marshal.dump(base))
      change.call(delta)
      assert_raises(Schema::Error, "#{name} does not decode") { Schema.load("SpaceWire.Delta", CBOR.dump(delta)) }
      peer = receiver
      body = Wire.rumor_body("space:tasks", "w:#{ENTRY}", Wire::HOPS, CBOR.dump(delta))
      env = Wire.envelope(GOLDEN["group_id"], "RUMOR", sender.peer_id, "#{STAMPED}:#{n}:#{sender.peer_id}", body)
      peer.handle(Wire.decode_frame(Wire.encode_frame(env, sender)))
      assert_equal 1, peer.deltas_undecodable, "#{name} counts as undecodable"
    end
    kept = Marshal.load(Marshal.dump(base))
    with_certificate.call(kept, "encryptionPublicKey" => "\x03".b * 32)
    record.call(kept)["keyEpoch"] = 1
    Schema.load("SpaceWire.Delta", CBOR.dump(kept))
  end

  def test_every_signed_peer_ad_vector_admits_as_the_encoding_says
    vectors("signed-peer-ad").each do |v|
      peer = receiver
      peer.send(:accept_peer_ad, bytes(v["hex"]))
      admitted = peer.members.key?(golden_identity.peer_id)
      assert_equal v["verdict"] == "accept", admitted, "#{v['id']} (#{v['rule']}: #{v['why']})"
    end
  end

  # F3: a revocation and a stored advertisement whose issuer signed bytes
  # outside its record (an unknown field, an issued instant Java prints
  # without the fraction, a ttl Java prints as PT10M) do not decode, and
  # neither is admitted; the honest form of each is.
  def test_a_signed_revocation_or_stored_ad_outside_its_record_is_not_admitted
    identity = golden_identity
    now = Instants.parse_millis("2026-06-01T00:00:00Z")
    revocation = CBOR.load(hex("credential_revocation_agent_cbor"))
    variants = { "honest" => revocation, "an unknown field" => revocation.merge("note" => "x"),
                 "issued with a .000 fraction" => revocation.merge("issued" => "2026-01-01T00:00:00.000Z") }
    variants.each do |name, ad|
      bytes = CBOR.dump(ad)
      registry = Revocation::Registry.new(-> {}, -> { GOLDEN["group_id"] })
      accepted = registry.accept_signed(Revocation::CREDENTIAL_STREAM,
                                        { "adBytes" => bytes, "publicKey" => identity.public_raw,
                                          "signature" => identity.sign(bytes) }, now)
      assert_equal name == "honest", accepted, "a revocation with #{name}"
    end
    peer = receiver
    issued = Instants.iso(STAMPED - (STAMPED % 1000))
    capability = { "id" => "aspace://#{peer.group}/cap/x", "issuer" => identity.peer_id, "group" => peer.group,
                   "issued" => issued, "ttl" => "PT10M", "capabilityType" => "x", "version" => "1",
                   "binding" => "b", "parameters" => {}, "costHints" => {} }
    { "honest" => capability, "an unknown field" => capability.merge("note" => "x"),
      "a ttl of PT600S" => capability.merge("ttl" => "PT600S") }.each do |name, ad|
      peer = receiver
      peer.send(:accept_ad, Wire.stored_ad("CapabilityAdvertisement", ad, identity))
      assert_equal name == "honest", peer.ads.key?(ad["id"]), "an advertisement with #{name}"
    end
  end

  # ------------------------------------------------ AppCard kind, origin, formats

  # AppCard origin and formats, 2026-11-09 (SPEC §6.1a.2 v0.1.32, FR-1 to
  # FR-5): the closed kind, the open origin and formats with their bounds, and
  # signOn idp or none. A card the Java constructor refuses does not decode.
  def app_card = CBOR.load(hex("app_card_origin_formats_cbor"))

  def host_card = CBOR.load(hex("app_card_host_cbor"))

  def refused_app_card(card, why)
    error = assert_raises(Schema::Error, "refused: #{card.inspect[0, 120]}") { Schema.check("AppCard", card) }
    assert_match why, error.message
  end

  def utf16_units(count) = ("\u{1F600}" * (count / 2)) + ("a" * (count % 2))

  def test_the_app_card_vectors_decode_and_re_encode_to_their_bytes
    %w[app_card_origin_formats_cbor app_card_host_cbor app_card_spill_cbor].each do |name|
      assert_equal hex(name), CBOR.dump(Schema.load("AppCard", hex(name))), name
    end
    assert_equal hex("agent_card_ui_cbor"), CBOR.dump(Schema.load("AgentCard", hex("agent_card_ui_cbor")))
    assert_equal "idp", host_card["host"]["signOn"]
    assert_equal %w[example-widgets agentspaces-viz], host_card["ui"]["catalogIds"]
    assert_equal %w[realm.reads realm.format realm.namespace], app_card["origin"]["attrs"].keys
  end

  def test_the_kinds_are_closed_and_no_kind_is_tied_to_an_origin
    assert_equal %w[peer fed gateway assembled], Cards::APP_CARD_KINDS
    Cards::APP_CARD_KINDS.each { |kind| Schema.check("AppCard", app_card.merge("kind" => kind)) }
    console = app_card.merge("origin" => { "system" => "console", "ref" => "example-console/board", "version" => "" })
    Schema.check("AppCard", console)
    Schema.check("AppCard", console.merge("kind" => "assembled"))
    refused_app_card(app_card.merge("kind" => "realm"), /kind/)
    refused_app_card(app_card.merge("kind" => ""), /kind/)
    refused_app_card(app_card.merge("shape" => "tablet"), /shape/)
    refused_app_card(app_card.merge("name" => " "), /name/)
    refused_app_card(app_card.merge("version" => ""), /version/)
    refused_app_card(app_card.merge("views" => Array.new(65) { |i| "v#{i}" }), /at most 64/)
    a2ui = host_card.dup
    a2ui.delete("ui")
    refused_app_card(a2ui.merge("host" => host_card["host"]), /a2ui/)
  end

  def test_sign_on_is_idp_or_none_and_the_host_holds_its_values
    assert_equal %w[idp none], Cards::APP_CARD_SIGN_ONS
    host = host_card["host"]
    Schema.check("AppCard", host_card.merge("host" => host.merge("signOn" => "none")))
    { "signOn" => "tenant", "status" => "paused", "url" => " ", "port" => 65_536, "path" => "" }.each do |field, value|
      refused_app_card(host_card.merge("host" => host.merge(field => value)), /#{field == "url" ? "url" : field}/)
    end
    ui = host_card["ui"]
    refused_app_card(host_card.merge("ui" => ui.merge("transport" => "feed")), /transport/)
    refused_app_card(host_card.merge("ui" => ui.merge("protocol" => "")), /protocol/)
    refused_app_card(host_card.merge("ui" => ui.merge("surfaces" => Array.new(65) { |i| "s#{i}" })), /surfaces/)
  end

  def test_a_component_role_is_closed
    card = CBOR.load(hex("agent_card_ui_cbor"))
    component = card["ui"]["components"][0]
    assert_equal %w[panel control row], Cards::UI_ROLES
    [{ "role" => "widget" }, { "role" => "" }, { "id" => " " }, { "controls" => Array.new(17) { |i| "c#{i}" } }].each do |change|
      changed = card.merge("ui" => card["ui"].merge("components" => [component.merge(change)] + card["ui"]["components"][1..]))
      assert_raises(Schema::Error, change.inspect) { Schema.check("AgentCard", changed) }
    end
  end

  def test_origin_holds_its_grammar_and_bounds
    origin = app_card["origin"]
    attrs = origin["attrs"]
    Schema.check("AppCard", app_card.merge("origin" => origin.merge("system" => "com.example.catalog", "attrs" => nil).compact))
    Schema.check("AppCard", app_card.merge("origin" => origin.merge("ref" => utf16_units(256), "version" => "v" * 64)))
    [["system", "Realm Two"], ["system", "-realm"], ["system", "realm-"], ["system", "r" * 65], ["system", ""],
     ["ref", ""], ["ref", utf16_units(257)], ["ref", "a\u0001b"], ["version", "v" * 65], ["version", "1\u007F"]].each do |field, value|
      refused_app_card(app_card.merge("origin" => origin.merge(field => value).merge("attrs" => nil).compact), /origin\.#{field}/)
    end
    refused_app_card(app_card.merge("origin" => origin.merge("attrs" => { "namespace" => "x" })), /attrs key/)
    refused_app_card(app_card.merge("origin" => origin.merge("attrs" => { "realm." => "x" })), /attrs key/)
    refused_app_card(app_card.merge("origin" => origin.merge("attrs" => { "realm.Upper" => "x" })), /attrs key/)
    long_key = "realm.#{'k' * 123}"
    refused_app_card(app_card.merge("origin" => origin.merge("attrs" => { long_key => "x" })), /attrs key/)
    Schema.check("AppCard", app_card.merge("origin" => origin.merge("attrs" => { long_key[0, 128] => "" })))
    refused_app_card(app_card.merge("origin" => origin.merge("attrs" => { "realm.a" => "x" * 257 })), /attrs value/)
    refused_app_card(app_card.merge("origin" => origin.merge("attrs" => { "realm.a" => "\n" })), /attrs value/)
    nine = CBOR.canonical_map((1..9).to_h { |i| ["realm.k#{i}", "v"] })
    refused_app_card(app_card.merge("origin" => origin.merge("attrs" => nine)), /attrs holds 1 to 8/)
    refused_app_card(app_card.merge("origin" => origin.merge("attrs" => {})), /attrs holds 1 to 8/)
    assert_equal attrs.keys, CBOR.canonical_map(attrs.to_a.reverse.to_h).keys, "attrs travel in the P2 key order"
  end

  def test_formats_hold_media_types_and_vocabulary_iris
    Schema.check("AppCard", app_card.merge("formats" => ["text/csv", "https://example.org/ns#", "urn:x:y",
                                                         "application/vnd.example+json"]))
    Schema.check("AppCard", app_card.merge("formats" => Array.new(16) { |i| "text/t#{i}" }))
    Schema.check("AppCard", app_card.merge("formats" => ["urn:#{'x' * 252}"]))
    [[[], /formats holds 1 to 16/], [Array.new(17) { |i| "text/t#{i}" }, /formats holds 1 to 16/],
     [%w[text/html text/html], /repeats/], [["Application/Geo+JSON"], /media type/], [["text/html;charset=utf-8"], /media type/],
     [["text"], /media type/], [[""], /1 to 256/], [["urn:#{'x' * 253}"], /1 to 256/], [["Urn:x"], /IRI/],
     [["1urn:x"], /IRI/], [["urn:a b"], /IRI/], [["urn:a\u00A0b"], /IRI/], [["urn:a\u3000b"], /IRI/]].each do |formats, why|
      refused_app_card(app_card.merge("formats" => formats), why)
    end
  end

  # The refusal vectors of AppCard origin and formats, 2026-11-09 (issue
  # §9.6): each is refused for the rule it pins, never by accident.
  def test_every_app_card_refusal_vector_is_refused_for_its_rule
    {
      "adv_app_card_kind_realm_cbor" => [/kind/, "AppCard"], "adv_app_card_sign_on_tenant_cbor" => [/signOn/, "AppCard"],
      "adv_app_card_formats_empty_cbor" => [/formats holds/, "AppCard"],
      "adv_app_card_origin_attrs_empty_cbor" => [/attrs holds/, "AppCard"],
      "adv_app_card_formats_bound_cbor" => [/formats holds/, "AppCard"],
      "adv_app_card_formats_upper_cbor" => [/media type/, "AppCard"],
      "adv_app_card_formats_duplicate_cbor" => [/repeats/, "AppCard"],
      "adv_app_card_formats_parameter_cbor" => [/media type/, "AppCard"],
      "adv_app_card_origin_system_cbor" => [/origin\.system/, "AppCard"],
      "adv_app_card_origin_attrs_prefix_cbor" => [/attrs key/, "AppCard"],
      "adv_app_card_origin_ref_bound_cbor" => [/origin\.ref/, "AppCard"],
      "adv_app_card_spill_placeholder_cbor" => [/placeholder/, "AppCard"],
      "adv_app_card_spill_parts_order_cbor" => [/order/, "AppCard"],
      "adv_app_card_spill_parts_unknown_cbor" => [/outside the spill set/, "AppCard"],
      "adv_app_card_spill_parts_empty_cbor" => [/at least one/, "AppCard"],
      "adv_app_card_spill_root_codec_cbor" => [/root/, "AppCard"],
      "adv_app_card_spill_size_zero_cbor" => [/size/, "AppCard"],
      "adv_agent_card_spill_actions_cbor" => [/placeholder/, "AgentCard"]
    }.each do |name, (why, record)|
      error = assert_raises(Schema::Error, name) { Schema.load(record, hex(name)) }
      assert_match why, error.message, name
    end
  end

  # Reference rule (HLC round six, 2026-11-08): Java's advertisement, card,
  # founding, and envelope records refuse a null in every field they always
  # write (requireNonNull, or a null Java rewrites to a default and writes
  # differently), except Envelope.to and RevocationAdvertisement.successor.
  # Java's reader judged each field below null; this reader refuses the same.
  def test_a_null_where_javas_record_refuses_one_is_undecodable
    group = GOLDEN["group_id"]
    peer = golden_identity.peer_id
    head = ->(kind) { { "id" => "aspace://#{group}/#{kind}/x", "issuer" => peer, "group" => group,
                        "issued" => "2026-01-01T00:00:00Z", "ttl" => "PT10M" } }
    samples = {
      "PeerAdvertisement" => CBOR.load(CBOR.load(bytes(VECTORS.find { |v| v["id"] == "ad-01" }["hex"]))["adBytes"]),
      "CredentialRevocation" => CBOR.load(hex("credential_revocation_agent_cbor")),
      "AgentCard" => CBOR.load(hex("agent_card_ui_cbor")),
      "SignedGroupAdvertisement" => CBOR.load(hex("signed_group_ad_cbor")),
      "GroupFounding.FoundingDocument" => CBOR.load(hex("founding_document_cbor")),
      "AppCard" => CBOR.load(hex("app_card_host_cbor")),
      "Envelope" => CBOR.load(bytes(VECTORS.find { |v| v["id"] == "frame-01" }["hex"]))["envelope"],
      "AssetCard" => head.call("asset").merge("asset" => "a", "uri" => "u", "description" => "d", "shape" => "s",
                                              "freshness" => "f", "costHints" => {}, "access" => {}),
      "CapabilityAdvertisement" => head.call("cap").merge("capabilityType" => "x", "version" => "1", "binding" => "b",
                                                          "parameters" => {}, "costHints" => {}),
      "ModelCard" => head.call("model").merge("name" => "n", "version" => "1", "tasks" => [], "modality" => "m",
                                              "limits" => {}, "licence" => "l", "provenance" => {}, "evals" => {},
                                              "costHints" => {}, "residency" => {}, "engine" => "e", "servers" => [peer]),
      "RevocationAdvertisement" => head.call("revocation").merge("revoked" => peer, "reason" => "retired",
                                                                 "successor" => peer),
      "CardAction.Contract" => { "pre" => [], "post" => [], "cost" => "c", "methods" => [] }
    }
    # The fields, by their path from each sample, that Java's reader lets be
    # null; every other field reached from a sample, nested records included,
    # is refused as null.
    nullable = { "Envelope" => %w[to],
                 "RevocationAdvertisement" => %w[successor], "AgentCard" => %w[agentCertificate.peerSignature] }
    walk = lambda do |value, path, out|
      case value
      when Hash then value.each { |key, item| out << (path + [key]); walk.call(item, path + [key], out) }
      when Array then value.each_with_index { |item, i| walk.call(item, path + [i], out) }
      end
      out
    end
    samples.each do |record, sample|
      Schema.check(record, sample)
      walk.call(sample, [], []).each do |path|
        changed = Marshal.load(Marshal.dump(sample))
        parent = path[0..-2].reduce(changed) { |node, key| node[key] }
        next if parent[path.last].nil? || parent.is_a?(Array)

        parent[path.last] = nil
        field = path.join(".")
        if nullable.fetch(record, []).include?(field)
          Schema.load(record, CBOR.dump(changed))
        else
          assert_raises(Schema::Error, "#{record} with #{field} null does not decode") do
            Schema.load(record, CBOR.dump(changed))
          end
        end
      end
    end
  end

  # R5: on the wire an agent id is Java's AgentId: a non-empty peer id, "/",
  # and a non-empty local name with no "/" and no ":". Java's AgentId takes
  # every other character, a control character included, so a record naming
  # such an agent decodes here as in Java. Identity#agent stays stricter,
  # since an agent id is the node of every stamp its agent signs (HLC round
  # four, 2026-11-08 (D6)).
  def test_an_agent_id_on_the_wire_follows_javas_agent_id_grammar
    peer = golden_identity.peer_id
    { "a" => true, "a\u0001" => true, "a\u007F" => true, "\u0000" => true, "a b" => true, "a:b" => false,
      "a/b" => false, "" => false }.each do |local, decodes|
      lease = CBOR.dump({ "holder" => "#{peer}/#{local}", "expiresAtMillis" => 5, "kind" => "WRITE" })
      assert_equal decodes, Wire.agent_id?("#{peer}/#{local}"), local.inspect
      if decodes
        Schema.load("LeaseInfo", lease)
      else
        assert_raises(Schema::Error, "#{local.inspect} does not decode") { Schema.load("LeaseInfo", lease) }
      end
    end
    assert_raises(ArgumentError) { golden_identity.agent("a\u0001") }
  end

  # P2: a bid of -0.0 is a distinct finite double, which Java's
  # Double.compare orders below 0.0, so it wins the lattice (claim-20).
  def test_a_bid_of_negative_zero_wins_over_a_bid_of_zero_as_java_orders_it
    zero = CBOR.load(bytes(VECTORS.find { |v| v["id"] == "claim-01" }["hex"]))["claim"]
    negative = CBOR.load(bytes(VECTORS.find { |v| v["id"] == "claim-20" }["hex"]))["claim"]
    assert_same negative, Wire.merge_claims(zero, negative)
    assert_same negative, Wire.merge_claims(negative, zero)
  end

  # Section 3.2: a StateSignView sorts its dots by replica in Java's
  # String.compareTo order, UTF-16 code units, where U+1F600 sorts before
  # U+E000 (delta-13 carries them the other way round on the wire).
  def test_a_state_view_sorts_its_dots_by_utf16_code_units
    dots = [{ "replica" => "\u{E000}", "counter" => 1 }, { "replica" => "\u{1F600}", "counter" => 1 }]
    assert_equal ["\u{1F600}", "\u{E000}"], Wire.sorted_dots(dots).map { |d| d["replica"] }
  end

  # HLC round six, 2026-11-08 (reference rule): as Java's
  # ReplicatedSpace.dotsBoundToIssuer (ASF-025), a received state whose adds
  # or removes name a replica other than its record issuer's peer id merges
  # nothing and counts nothing. delta-13 carries valid signatures over dots
  # U+E000 and U+1F600, so only the binding drops it.
  def test_a_state_whose_dots_name_another_replica_merges_nothing
    peer = receiver
    sender = Identity.generate
    raw = bytes(VECTORS.find { |v| v["id"] == "delta-13" }["hex"])
    state = CBOR.load(raw)["state"]
    assert peer.send(:verify_state, state, state["record"]), "delta-13's record and state signatures verify"
    body = Wire.rumor_body("space:tasks", "w:#{ENTRY}", Wire::HOPS, raw)
    env = Wire.envelope(GOLDEN["group_id"], "RUMOR", sender.peer_id, "#{STAMPED}:0:#{sender.peer_id}", body)
    peer.handle(Wire.decode_frame(Wire.encode_frame(env, sender)))
    assert_equal [], peer.states.keys, "no state merges"
    assert_equal [0, 0, 0, 0], [peer.deltas_undecodable, peer.stamps_logical_refused, peer.stamps_far_future_refused,
                                peer.stamps_far_future_deferred], "no counter moves"
  end

  # A peer whose sends are captured as [kind, body, to].
  class CapturingPeer < Peer
    attr_reader :sent

    def initialize(identity, group, clock:)
      super
      @sent = []
    end

    private

    def send_frame(kind, body, to = nil) = @sent << [kind, body, to]
  end

  # Holds one carrier this peer wrote to its record, and each document
  # nested in it to the record it carries.
  def assert_carrier(kind, body)
    decoded = Wire.decode_body(kind, body)
    return unless kind == "RUMOR"

    payload = decoded["payload"]
    case decoded["streamId"]
    when "peers" then Schema.load("PeerAdvertisement", Schema.load("PeerNode.SignedPeerAd", payload)["adBytes"])
    when "ads"
      stored = Schema.load("AdCache.StoredAd", payload)
      Schema.load(stored["adType"], stored["adBytes"])
    else Schema.load("SpaceWire.Delta", payload)
    end
  end

  # F3, section 6 item 8: every carrier this peer writes for honest traffic
  # holds to its record, so a strict receiver of any implementation reads
  # it. A DIGEST's digests map travels in the RFC 8949 order (frame-29),
  # where the clients wrote space:<name> before peers (frame-28).
  def test_every_carrier_this_peer_writes_holds_to_its_record
    now = STAMPED
    identity = Identity.generate
    peer = CapturingPeer.new(identity, GOLDEN["group_id"], clock: -> { now / 1000.0 })
    agent = identity.subordinate("a", Instants.iso(now - 60_000), "PT1H")
    peer.introduce
    peer.pull_space("tasks")
    peer.pull_revocations
    peer.pull_ads
    written = peer.write_entry("tasks", "com.acme.WireTask#v1", { "n" => 1 }, tags: { "zz" => "1", "10" => "2", "b" => "3" })
    by_agent = peer.write_entry("tasks", "com.acme.WireTask#v1", { "n" => 2 }, agent: agent)
    peer.renew_entry("tasks", written)
    peer.renew_entry("tasks", by_agent, agent: agent)
    space_id = Derive.space_id_local("#{peer.group}/tasks")
    claim = Wire.take_claim(by_agent, space_id, 1, Wire.hlc_now(agent.agent_id, now), agent.agent_id, -0.0, now + 60_000)
    signed = Wire.signed_claim(claim, identity, agent)
    Schema.check("SpaceWire.SignedClaim", signed)
    peer.claims[by_agent] = signed
    peer.renew_claim("tasks", by_agent, lease_millis: 30_000, agent: agent)
    peer.complete_entry("tasks", by_agent, agent: agent)
    card = Wire.agent_card(peer.group, identity, "a", Instants.iso(now - (now % 1000)), "PT15M", "an agent", ["g"],
                           ["c"], ["p"], { "zz" => "1", "b" => "2" }, {}, agent_public_raw: agent.public_raw,
                           actions: [Wire.card_action("act", "acts", ["c"], ["p"], "write", "tasks")],
                           agent_certificate: agent.certificate)
    peer.publish_ad("AgentCard", card)
    peer.send_pipe(Identity.generate.peer_id, "aspace:cap/test", "\x01".b)
    ping = Wire.envelope(peer.group, "PING", identity.peer_id, "#{now}:0:#{identity.peer_id}", Wire.ping_body(7))
    peer.handle(ping)
    kinds = peer.sent.map(&:first)
    assert_equal %w[RUMOR DIGEST DIGEST DIGEST RUMOR RUMOR RUMOR RUMOR RUMOR RUMOR RUMOR PIPE_DATA ACK], kinds
    peer.sent.each { |kind, body, _| assert_carrier(kind, body) }
    digests = Wire.decode_body("DIGEST", peer.sent[1][1])["digests"].keys
    assert_equal %w[revocations space:tasks credential-revocations], digests
    founding = Founding.found(identity, "g", "OPEN", "LEASE_RACE", 3, "PT1S", "2026-01-01T00:00:00Z", "PT24H")
    Schema.check("SignedGroupAdvertisement", founding)
    Schema.check("AgentCertificate", agent.certificate)
    session = Session.new(identity.peer_id)
    Wire.decode_body("SESSION_HELLO", session.hello(Identity.generate.peer_id, nil))
    Wire.decode_body("RELAY_FRAME", Wire.relay_frame_body(identity.peer_id, "\x01".b, [identity.peer_id], 0))
    Wire.decode_body("BLOCK_WANT", Wire.block_want_body("zcid"))
    Wire.decode_body("BLOCK", Wire.block_body("zcid", "\x01".b))
    Wire.decode_body("CHANNEL_HELLO", Wire.channel_hello_body(true, identity.peer_id))
    Schema.load("OrderedTakes.ClaimCommand",
                Capabilities::OrderedLog.claim_command(by_agent, claim, identity.public_raw, signed["signature"],
                                                       agent.certificate))
    delegation = Social.delegate(identity, peer.group, Identity.generate.public_raw, now + 60_000, "invite")
    Schema.load("JoinCredentials.Delegation", Base64Text.decode(delegation))
  end

  # F2: an application value keeps its exact type through a write and a
  # read: an Integer past a Java long, a BigDecimal, and a float32.
  def test_an_application_reads_back_bignums_decimals_and_float32s
    now = STAMPED
    peer = CapturingPeer.new(Identity.generate, GOLDEN["group_id"], clock: -> { now / 1000.0 })
    value = { "big" => 1 << 70, "neg" => -(1 << 64), "price" => BigDecimal("12.50"), "ratio" => CBOR::Float32.new(1.5),
              "id" => 7 }
    peer.write_entry("tasks", "com.acme.Exact#v1", value)
    read = peer.find("com.acme.Exact#v1").first
    assert_equal({ "big" => 1 << 70, "neg" => -(1 << 64), "price" => BigDecimal("12.5"),
                   "ratio" => CBOR::Float32.new(1.5), "id" => 7 }, read)
    assert_kind_of BigDecimal, read["price"]
    assert_equal CBOR.dump(value), CBOR.dump(read), "the value re-encodes to the bytes it was written as"
  end

  # Section 3.1: a payload that is no document of the wire encoding leaves
  # its entry replicated, since the signature covers its bytes, and every
  # read skips its value.
  def test_a_payload_outside_the_wire_encoding_replicates_and_every_read_skips_it
    now = STAMPED
    writer = Identity.generate
    peer = CapturingPeer.new(Identity.generate, GOLDEN["group_id"], clock: -> { now / 1000.0 })
    honest_id, honest = Wire.entry_delta("tasks", peer.group, "com.acme.WireTask#v1", CBOR.dump({ "n" => 1 }), writer, "w",
                                         60_000, now_ms: now)
    java_id, java = Wire.entry_delta("tasks", peer.group, "com.acme.WireTask#v1", bytes("BF 61 6E C2 41 01 FF"), writer, "w",
                                     60_000, now_ms: now)
    [honest, java].each_with_index do |body, n|
      env = Wire.envelope(peer.group, "RUMOR", writer.peer_id, "#{now}:#{n}:#{writer.peer_id}", body)
      peer.handle(env)
    end
    assert_equal [honest_id, java_id].sort, peer.states.keys.sort, "both entries replicate"
    assert_nil peer.value_of(peer.states[java_id])
    assert_equal [{ "n" => 1 }], peer.find("com.acme.WireTask#v1")
    assert_equal [1], peer.space("tasks").all(Entry.define("com.acme.WireTask#v1", n: Integer)).map(&:n)
  end
end
