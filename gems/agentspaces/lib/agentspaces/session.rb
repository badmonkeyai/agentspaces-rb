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
  # Session attestation (SPEC 5.6, v0.1.17): on a connection the transport
  # cannot attest (tcp, ws, http), one fully signed SESSION_HELLO each way
  # establishes a key, after which frames carry an HMAC-SHA-256 tag under it
  # in place of the Ed25519 signature. The Ruby twin of the Java node's
  # session logic and of the TypeScript Session, byte for byte: the hello
  # body, the key derivation, the session frame, the age rule, the tie rule
  # when both ends open at once, and key confirmation.
  class Session
    # How old a hello may be, by its stamp, and still be answered.
    HELLO_MAX_AGE_MILLIS = 30_000
    # How long an unanswered opening hello stands before it may be repeated.
    HELLO_RETRY_MILLIS = 5_000
    # The resource hint a node advertises when it runs the SESSION mode.
    HINT = "wire.session"
    # A session frame carries exactly this many bytes in the signature field.
    MAC_LENGTH = 32
    INFO = "agentspaces session v1".b

    # Bodies.SessionHello in Java record order.
    def self.hello_body(ephemeral_key, nonce, remote, echo)
      CBOR.dump({ "ephemeralKey" => ephemeral_key.b, "nonce" => nonce.b, "remote" => remote, "echo" => echo&.b })
    end

    # The hello a body decodes to, or nil when it is not one.
    def self.parse_hello(body)
      hello = CBOR.load(body)
      return nil unless hello.is_a?(Hash)

      key = hello["ephemeralKey"]
      nonce = hello["nonce"]
      echo = hello["echo"]
      return nil unless key.is_a?(String) && key.bytesize == 32 && nonce.is_a?(String)
      return nil unless nonce.bytesize.between?(16, 64) && hello["remote"].is_a?(String)
      return nil unless echo.nil? || echo.is_a?(String)

      { key: key, nonce: nonce, remote: hello["remote"], echo: echo }
    rescue CBOR::Error
      nil
    end

    # PeerNode.deriveSessionKey: HKDF-SHA-256 over the X25519 agreement, empty
    # salt, info "agentspaces session v1" || lower PeerID || 0 || higher
    # PeerID || 0 || lower's nonce || higher's nonce, 32 bytes.
    def self.derive_key(own_private, own_peer_id, own_nonce, remote_key, remote_peer_id, remote_nonce)
      shared = Crypto.port.x25519(own_private, remote_key)
      first, second, first_nonce, second_nonce =
        if own_peer_id < remote_peer_id then [own_peer_id, remote_peer_id, own_nonce, remote_nonce]
        else [remote_peer_id, own_peer_id, remote_nonce, own_nonce]
        end
      info = INFO + first.b + "\x00".b + second.b + "\x00".b + first_nonce.b + second_nonce.b
      Crypto.port.hkdf_sha256(shared, salt: "".b, info: info, length: MAC_LENGTH).b
    end

    # WireCodec.encodeSession: no key, and the HMAC of the canonical envelope.
    def self.encode_frame(env, key)
      CBOR.dump({ "envelope" => env, "senderPublicKey" => nil,
                  "signature" => Crypto.port.hmac_sha256(key, CBOR.dump(env)).b })
    end

    attr_reader :ephemeral_public, :nonce, :remote, :key
    attr_accessor :confirmed

    def initialize(own_peer_id, ephemeral: nil, nonce: nil)
      @own = own_peer_id
      @ephemeral = ephemeral || Crypto.port.generate_x25519
      @ephemeral_public = @ephemeral.raw_public_key.b
      @nonce = (nonce || Crypto.port.random_bytes(32)).b
      @hello_sent = false
      @hello_sent_at = 0
      @answered = false
      @remote = nil
      @key = nil
      @confirmed = false
      @lock = Mutex.new
    end

    # The hello body for the remote peer (opening when echo is nil).
    def hello(remote, echo) = Session.hello_body(@ephemeral_public, @nonce, remote, echo)

    # Whether an opening hello may go out now.
    def may_open?(now_ms)
      @key.nil? && !@answered && !(@hello_sent && now_ms - @hello_sent_at < HELLO_RETRY_MILLIS)
    end

    def sent!(now_ms, answering)
      @hello_sent = true
      @hello_sent_at = now_ms
      @answered = answering
    end

    # Takes the remote's half: refuses a second peer or a repeat; when both
    # ends opened at once the lower PeerID stays the opener; an answer must
    # echo this end's nonce. Returns :answer, :confirmed, or nil.
    def accept(from, hello)
      @lock.synchronize do
        return nil if !@key.nil? || (!@remote.nil? && @remote != from)

        opening = hello[:echo].nil?
        if opening
          return nil if @hello_sent && !@answered && @own < from
        elsif !@hello_sent || @answered || !Crypto.port.equal?(hello[:echo].b, @nonce)
          return nil
        end
        @remote = from
        @key = Session.derive_key(@ephemeral, @own, @nonce, hello[:key], from, hello[:nonce])
        @confirmed = !opening
        opening ? :answer : :confirmed
      end
    end

    # The key to tag a frame for to with, or nil while unconfirmed or for another peer.
    def key_for(to, kind)
      return nil unless @confirmed && @key && to && to == @remote
      return nil if %w[SESSION_HELLO CHANNEL_HELLO].include?(kind)

      @key
    end

    # [peer, key] for the decoder, or nil.
    def established = @key && @remote ? [@remote, @key] : nil

    def inspect = "#<AgentSpaces::Session remote=#{@remote.inspect} confirmed=#{@confirmed}>"
  end
end
