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
require "agentspaces/bootstrap"

# The invite key and the delegated credential against the social golden
# vector (SRAD DB-X-07): every derivation from the secret, the founder's
# delegation, the candidate's credential, both hashes, the signed view, and
# both key renderings must match the Java bytes exactly. The vendored copy in
# test/ is the one the suite reads; the sibling module's copy, when present,
# is read too so a regenerated vector cannot drift from the vendored one.
class SocialTest < Minitest::Test
  include AgentSpaces

  VENDORED = File.join(__dir__, "social-golden.json")
  SIBLING = File.expand_path("../../../../agentspaces-bootstrap-social/golden/social-golden.json", __dir__)
  PATHS = [VENDORED] + (File.exist?(SIBLING) ? [SIBLING] : [])

  # Runs the block once per golden copy, as the Python fixture is parametrized.
  def each_golden
    PATHS.each { |path| yield JSON.parse(File.read(path)) }
  end

  def unhex(text) = [text].pack("H*")

  def hex(bytes) = bytes.unpack1("H*")

  def ms(iso) = Instants.parse_millis(iso)

  def secret_of(golden) = Social::GroupSecret.new(unhex(golden["secret_hex"]))

  def test_vendored_golden_matches_the_sibling_when_present
    skip "no sibling golden" unless File.exist?(SIBLING)
    assert_equal JSON.parse(File.read(VENDORED)), JSON.parse(File.read(SIBLING))
  end

  def test_secret_derivations_match_java
    each_golden do |golden|
      secret = secret_of(golden)
      assert_equal golden["hkdf_salt"].b, Social::SALT
      assert_equal golden["code"], secret.code
      assert_equal 16, secret.code.size
      assert_equal golden["invite_private_seed_hex"], hex(secret.invite_private_seed)
      assert_equal golden["invite_public_key_hex"], hex(secret.invite_public_key)
      assert_equal golden["content_key_hex"], hex(secret.content_key)
      assert_equal 32, secret.content_key.bytesize
      assert_equal secret, Social::GroupSecret.new(secret.bytes)
      assert_equal secret.hash, Social::GroupSecret.new(secret.bytes).hash
    end
  end

  def test_identities_from_seeds_match_java
    each_golden do |golden|
      assert_equal golden["founder_peer_id"], Identity.from_seed(unhex(golden["founder_seed_hex"])).peer_id
      assert_equal golden["candidate_peer_id"], Identity.from_seed(unhex(golden["candidate_seed_hex"])).peer_id
    end
  end

  def test_the_ruby_founder_reproduces_the_golden_founding
    each_golden do |golden|
      founder = Identity.from_seed(unhex(golden["founder_seed_hex"]))
      # Java: GroupFounding.found(founder, "weekend-hack", INVITE, LEASE_RACE,
      # GossipParameters.defaults(), issued, Duration.ofDays(365)).
      signed = Founding.found(founder, "weekend-hack", "INVITE", "LEASE_RACE", 3, "PT1S", golden["founding_issued"],
                              "PT8760H")
      assert_equal Base64Text.decode(golden["founding_cbor_base64"]), CBOR.dump(signed)
      assert_equal golden["group_id"], signed["advertisement"]["group"]
    end
  end

  def test_the_delegation_decodes_and_hashes
    each_golden do |golden|
      info = Social.delegation_info(golden["delegation_base64"])
      assert_equal golden["founder_peer_id"], info["founder"]
      assert_equal golden["invite_public_key_hex"], hex(info["invite_key"])
      assert_equal golden["group_id"], info["group"]
      assert_equal ms(golden["delegation_not_after"]), info["not_after_millis"]
      assert_equal golden["delegation_label"], info["label"]
      assert_equal golden["group_id"], Social.delegation_group(golden["delegation_base64"])
      assert_equal golden["delegation_hash_hex"], hex(Social.delegation_hash(golden["delegation_base64"]))
      # The decoded record re-encodes to the same bytes: the field order is Java's.
      assert_equal Base64Text.decode(golden["delegation_base64"]),
                   CBOR.dump(Social.decode_delegation(golden["delegation_base64"]))
    end
  end

  def test_the_ruby_founder_signs_the_same_delegation
    each_golden do |golden|
      founder = Identity.from_seed(unhex(golden["founder_seed_hex"]))
      delegation = Social.delegate(founder, golden["group_id"], secret_of(golden).invite_public_key,
                                   ms(golden["delegation_not_after"]), golden["delegation_label"])
      assert_equal golden["delegation_base64"], delegation
    end
  end

  def test_the_delegated_credential_is_reproduced_byte_for_byte
    each_golden do |golden|
      secret = secret_of(golden)
      credential = Social.issue_delegated(golden["delegation_base64"], secret.invite_private_seed,
                                          golden["candidate_peer_id"])
      assert_equal golden["credential"], credential
      assert credential.start_with?(Social::DELEGATED_PREFIX)
      # The invite Identity signs the same bytes as its seed.
      assert_equal credential, Social.issue_delegated(golden["delegation_base64"], secret.invite_key,
                                                      golden["candidate_peer_id"])
      assert_equal golden["credential_hash_hex"], hex(Social.credential_hash(credential))
      assert_equal golden["delegation_hash_hex"], hex(Social.delegation_hash(credential))
      assert_equal golden["credential_view_cbor_hex"],
                   hex(CBOR.dump(Social.credential_view(golden["candidate_peer_id"], golden["group_id"])))
    end
  end

  def test_the_credential_admits_exactly_the_candidate_in_the_window
    each_golden do |golden|
      credential = golden["credential"]
      issued = ms(golden["founding_issued"])
      not_after = ms(golden["delegation_not_after"])
      issuer = golden["founder_peer_id"]
      group = golden["group_id"]
      candidate = golden["candidate_peer_id"]
      admits = ->(*args) { Social.delegated_credential_admits?(*args) }
      assert admits.call(credential, candidate, issuer, group, issued)
      assert admits.call(credential, candidate, issuer, group, not_after + Social::EXPIRY_SKEW_MILLIS)
      refute admits.call(credential, candidate, issuer, group, not_after + Social::EXPIRY_SKEW_MILLIS + 1)
      refute admits.call(credential, golden["founder_peer_id"], issuer, group, issued), "another candidate"
      refute admits.call(credential, candidate, candidate, group, issued), "not the founder's group"
      refute admits.call(credential, candidate, issuer, "zOther", issued), "another group"
      refute admits.call("not a credential", candidate, issuer, group, issued)
      refute admits.call("#{credential[0...-8]}AAAAAAA=", candidate, issuer, group, issued), "tampered"
    end
  end

  def test_a_credential_under_another_invite_key_is_refused
    each_golden do |golden|
      other = Social::GroupSecret.random
      forged = Social.issue_delegated(golden["delegation_base64"], other.invite_private_seed,
                                      golden["candidate_peer_id"])
      refute Social.delegated_credential_admits?(forged, golden["candidate_peer_id"], golden["founder_peer_id"],
                                                 golden["group_id"], ms(golden["founding_issued"]))
    end
  end

  RENDERINGS = { "invite_key_compact" => :compact, "invite_key_url" => :url,
                 "invite_key_compact_with_host_and_delegation" => :compact,
                 "invite_key_url_with_delegation" => :url }.freeze

  def test_both_renderings_parse_to_the_secret_and_render_back
    each_golden do |golden|
      RENDERINGS.each do |name, renders|
        key = Social::InviteKey.parse(golden[name])
        assert_equal secret_of(golden), key.secret, name
        assert_equal golden["code"], key.code, name
        assert_equal golden[name], key.public_send(renders), name
        if name.include?("delegation")
          assert_equal "beacon.example.org", key.host
          assert_equal golden["delegation_base64"], key.delegation
          assert_equal "https://beacon.example.org/j/#{golden['code']}", key.document_url
        else
          assert_equal Social::DEFAULT_HOST, key.host
          assert_nil key.delegation
        end
        # The two renderings of one key are each other's.
        assert_equal key.url, Social::InviteKey.parse(key.compact).url
        assert_equal key.compact, Social::InviteKey.parse(key.url).compact
      end
    end
  end

  def test_a_key_read_aloud_survives
    each_golden do |golden|
      compact = golden["invite_key_compact"]
      spaced = compact.sub("-000G", "- 000G").sub("G40R", "G40R ")
      [compact.downcase, spaced, "  #{compact}\n"].each do |text|
        assert_equal compact, Social::InviteKey.parse(text).compact, text.inspect
      end
    end
    # Crockford: O reads as 0, I and L as 1, dashes and case are ignored.
    assert_equal Social.base32_decode("011"), Social.base32_decode("o-i-l")
    assert_equal "\x00\x01\xff".b, Social.base32_decode(Social.base32_encode("\x00\x01\xff".b).downcase)
    assert_raises(Social::Error) { Social.base32_decode("U") }
  end

  def test_a_code_that_does_not_belong_to_the_secret_is_refused
    each_golden do |golden|
      code = golden["code"]
      compact = golden["invite_key_compact"]
      wrong = compact.sub("-#{code}-", "-#{code[0...-1]}0-")
      refute_equal compact, wrong
      assert_raises(ArgumentError) { Social::InviteKey.parse(wrong) }
      url = golden["invite_key_url"].sub("/j/#{code}", "/j/#{code[0...-1]}0")
      assert_raises(ArgumentError) { Social::InviteKey.parse(url) }
      ["", "aspace-inv2-x-y", "https://host/x#y", "https://host/j/#{code}", "aspace-inv1-#{code}"].each do |bad|
        assert_raises(ArgumentError, bad) { Social::InviteKey.parse(bad) }
      end
      assert_raises(ArgumentError) { Social::InviteKey.parse(nil) }
    end
  end

  def test_a_url_key_keeps_a_non_default_port
    each_golden do |golden|
      url = golden["invite_key_url"].sub("https://s.agentspaces.dev/", "https://beacon.test:8443/")
      key = Social::InviteKey.parse(url)
      assert_equal "beacon.test:8443", key.host
      assert_equal url, key.url
      assert_equal "#{golden['invite_key_compact']}@beacon.test:8443", key.compact
      assert_equal "beacon.test:8443", Social::InviteKey.parse(key.compact).host
    end
  end

  def test_hints_for_carries_the_credential_under_the_join_key
    each_golden do |golden|
      key = Social::InviteKey.parse(golden["invite_key_url_with_delegation"])
      hints = Social.hints_for(key, key.delegation, golden["candidate_peer_id"])
      assert_equal({ "aspace:join" => golden["credential"] }, hints)
    end
  end

  # JoinCredentials.judge in Ruby: past the window the golden credential is
  # "expired", not "invalid", so join_invite no longer refuses a peer the
  # members may re-admit from their admission memory (SPEC 5.1, v0.1.20).
  def test_judge_tells_expiry_from_forgery
    each_golden do |golden|
      credential = golden["credential"]
      issued = ms(golden["founding_issued"])
      not_after = ms(golden["delegation_not_after"])
      issuer = golden["founder_peer_id"]
      group = golden["group_id"]
      candidate = golden["candidate_peer_id"]
      judge = ->(*args) { Social.judge_delegated_credential(*args) }
      assert_equal "valid", judge.call(credential, candidate, issuer, group, issued)
      assert_equal "valid", judge.call(credential, candidate, issuer, group, not_after + Social::EXPIRY_SKEW_MILLIS)
      assert_equal "expired",
                   judge.call(credential, candidate, issuer, group, not_after + Social::EXPIRY_SKEW_MILLIS + 1)
      assert_equal "invalid", judge.call(credential, golden["founder_peer_id"], issuer, group, issued)
      assert_equal "invalid", judge.call(credential, candidate, candidate, group, issued)
      assert_equal "invalid", judge.call("d1:AAAA", candidate, issuer, group, issued)
    end
  end

  # Python's lenient base64 reading, which every decoded key and credential
  # goes through: each row is what CPython 3.14's base64.b64decode answered
  # (nil for a refusal).
  PYTHON_B64 = {
    "AA==" => "00", "A A==\n" => "00", "" => "", "AA==AA==" => "000000", "AAAA=" => "000000",
    "AA=A=" => "0000", "A=A==" => "00", "AAAA====" => "000000", "AA===" => "00", "AB==" => "00",
    "=AA==" => "00", "QQ==QQ==" => "410410", "AAA==" => "0000", "AA\n==" => "00", "AA=\n=" => "00",
    "AA=x=" => "000c", "AAA=A" => "000000", "AA==A===" => "0000", "====" => "", "AB=CD===" => "001083",
    "AA==trailing" => nil, "AA==AAAA" => nil, "AA=A" => nil, "AA==A" => nil, "A===" => nil, "AA=" => nil,
    "A=" => nil, "AAAAA===" => nil, "AAAAAA=" => nil, "AAA" => nil, "AAAA=AA=" => nil, "A" => nil
  }.freeze

  def test_base64_reads_as_python_does
    PYTHON_B64.each do |text, want|
      if want.nil?
        assert_raises(ArgumentError, text.inspect) { Base64Text.decode(text) }
      else
        assert_equal unhex(want), Base64Text.decode(text), text.inspect
      end
    end
    assert_raises(TypeError) { Base64Text.decode(5) }
    assert_raises(ArgumentError) { Base64Text.decode("AAé==") }
    assert_equal "AA==", Base64Text.encode("\x00".b)
  end
end
