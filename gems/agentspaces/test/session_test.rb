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

# Session attestation (SPEC 5.6) against the Java node's golden vectors, and
# the state machine's tie, echo, and confirmation rules.
class SessionTest < Minitest::Test
  include GoldenHelpers
  include AgentSpaces

  def test_the_session_vectors_match_the_java_nodes
    a_priv = Crypto.port.x25519_from_raw(hex("session_a_scalar"))
    b_priv = Crypto.port.x25519_from_raw(hex("session_b_scalar"))
    assert_equal hex("session_a_public"), a_priv.raw_public_key.b
    assert_equal hex("session_b_public"), b_priv.raw_public_key.b
    a_nonce = hex("session_a_nonce")
    b_nonce = hex("session_b_nonce")
    key = Session.derive_key(a_priv, "zA", a_nonce, hex("session_b_public"), "zB", b_nonce)
    assert_equal hex("session_key"), key
    assert_equal key, Session.derive_key(b_priv, "zB", b_nonce, hex("session_a_public"), "zA", a_nonce)
    assert_equal hex("session_hello_cbor"), Session.hello_body(hex("session_a_public"), a_nonce, "zB", nil)
    assert_equal hex("session_answer_cbor"), Session.hello_body(hex("session_b_public"), b_nonce, "zA", a_nonce)
    env = load(hex("session_envelope_cbor"))
    assert_equal hex("session_frame_cbor"), Session.encode_frame(env, key)
    decoded, auth = Wire.decode_frame_detailed(hex("session_frame_cbor"), session: ["zA", key])
    assert_equal :session, auth
    assert_equal "PING", decoded["kind"]
    assert_nil Wire.decode_frame(hex("session_frame_cbor"), session: ["zB", key]), "a session names its sender"
    assert_nil Wire.decode_frame(hex("session_frame_cbor"), session: ["zA", "x".b * 32]), "a wrong key never verifies"
    assert_nil Wire.decode_frame(hex("session_frame_cbor")), "no session, no frame"
  end

  def test_two_sessions_agree_and_the_lower_peer_id_opens_when_both_do
    low = Session.new("zA")
    high = Session.new("zB")
    low.sent!(0, false)
    high.sent!(0, false)
    low_hello = Session.parse_hello(low.hello("zB", nil))
    high_hello = Session.parse_hello(high.hello("zA", nil))
    assert_nil low.accept("zB", high_hello), "the lower PeerID stays the opener and waits"
    assert_equal :answer, high.accept("zA", low_hello)
    answer = Session.parse_hello(high.hello("zA", low.nonce))
    assert_equal :confirmed, low.accept("zB", answer)
    assert_equal low.key, high.key
    assert low.confirmed
    refute high.confirmed, "the answerer signs until the opener's first session frame verifies"
    assert_nil low.accept("zC", answer), "one session per connection, with one peer"
    assert_nil low.key_for("zB", "SESSION_HELLO"), "hellos are always fully signed"
    assert_equal low.key, low.key_for("zB", "PING")
  end

  def test_an_answer_that_echoes_another_nonce_is_refused
    opener = Session.new("zA")
    opener.sent!(0, false)
    forged = Session.parse_hello(Session.new("zB").hello("zA", "n".b * 32))
    assert_nil opener.accept("zB", forged)
    assert_nil opener.key
  end

  def test_a_hello_is_accepted_only_fully_signed
    identity = Identity.generate
    env = Wire.envelope("g", "SESSION_HELLO", identity.peer_id, "1:0:x", Session.new(identity.peer_id).hello("zB", nil))
    bare = CBOR.dump({ "envelope" => env, "senderPublicKey" => nil, "signature" => nil })
    tagged = Session.encode_frame(env, "k".b * 32)
    assert_nil Wire.decode_frame(bare, attested: identity.peer_id)
    assert_nil Wire.decode_frame(tagged, session: [identity.peer_id, "k".b * 32])
    refute_nil Wire.decode_frame(Wire.encode_frame(env, identity))
  end
end
