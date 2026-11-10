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

require_relative "cbor"
require_relative "crypto"
require_relative "identity"
require_relative "beacon"

module AgentSpaces
  # The invite key and the delegated credential (SRAD discovery 3.8,
  # appendix F; Java GroupSecret, InviteKey, Base32Crockford,
  # JoinCredentials). One 128-bit group secret yields, by HKDF-SHA256 under
  # the salt "aspace-inv1", the invite signing key ("invite-sign"), the
  # content key ("content-key"), and the one-way lookup code ("lookup", 80
  # bits). The founder signs a delegation of the invite public key once; a
  # holder of the secret then signs its own PeerID under it and presents the
  # result as the aspace:join hint. Every derivation and every CBOR shape
  # here is bit-identical to the Java side, which test/social-golden.json pins.
  module Social
    # Text that is not an invite key, a delegation, or a credential (Python's ValueError).
    class Error < ArgumentError; end

    # The HKDF salt, also the key format's version tag.
    SALT = "aspace-inv1".b.freeze
    SECRET_LENGTH = 16
    CODE_LENGTH = 10
    # The built-in default social beacon, omitted from compact keys.
    DEFAULT_HOST = "s.agentspaces.dev"
    PREFIX = "aspace-inv1-"
    # The resource-hint key a candidate carries its join credential under.
    HINT_KEY = "aspace:join"
    # The prefix of a delegated credential string (JoinCredentials.DELEGATED_PREFIX).
    DELEGATED_PREFIX = "d1:"
    # The clock skew a delegation's expiry is judged with, as advertisements allow.
    EXPIRY_SKEW_MILLIS = 10 * 60 * 1000

    BASE32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    BASE32_DECODE = BASE32_ALPHABET.each_char.with_index.to_h.merge("O" => 0, "I" => 1, "L" => 1).freeze

    module_function

    # ------------------------------------------------------------------ HKDF

    # HKDF (RFC 5869) with HMAC-SHA-256, as Java Hkdf.derive: an empty salt
    # is a zero key of the hash length.
    def hkdf_sha256(ikm, salt, info, length)
      raise Error, "length out of range: #{length}" if length <= 0 || length > 255 * 32

      port = Crypto.port
      prk = port.hmac_sha256(salt.nil? || salt.empty? ? ("\x00".b * 32) : salt.b, ikm.b)
      output = String.new(encoding: Encoding::BINARY)
      block = String.new(encoding: Encoding::BINARY)
      counter = 1
      while output.bytesize < length
        block = port.hmac_sha256(prk, block + info.b + counter.chr).b
        output << block
        counter += 1
      end
      output.byteslice(0, length)
    end

    # ------------------------------------------------------- Crockford base32

    # Crockford base32, no padding: no I, L, O, U, so a key read aloud survives.
    def base32_encode(data)
      out = +""
      buffer = 0
      bits = 0
      data.b.each_byte do |byte|
        buffer = (buffer << 8) | byte
        bits += 8
        while bits >= 5
          out << BASE32_ALPHABET[(buffer >> (bits - 5)) & 31]
          bits -= 5
        end
      end
      out << BASE32_ALPHABET[(buffer << (5 - bits)) & 31] if bits.positive?
      out
    end

    # Case-insensitive; dashes and spaces are ignored; O reads as 0 and I and
    # L as 1. Any other character outside the alphabet is refused.
    def base32_decode(text)
      out = String.new(encoding: Encoding::BINARY)
      buffer = 0
      bits = 0
      text.upcase.each_char do |char|
        next if ["-", " "].include?(char)

        value = BASE32_DECODE[char]
        raise Error, "not a Crockford base32 character: #{char.inspect}" if value.nil?

        buffer = (buffer << 5) | value
        bits += 5
        next unless bits >= 8

        out << ((buffer >> (bits - 8)) & 0xFF)
        bits -= 8
      end
      out
    end

    # ------------------------------------------------------ the group secret

    # The 128 bits the creator draws and every holder derives from.
    class GroupSecret
      def initialize(secret)
        unless secret.is_a?(String) && secret.bytesize == SECRET_LENGTH
          raise Error, "a group secret is #{SECRET_LENGTH} bytes"
        end

        @secret = secret.b.freeze
      end

      def self.random = new(Crypto.port.random_bytes(SECRET_LENGTH))

      # The raw 16 bytes (Python's .bytes).
      def bytes = @secret

      # The invite signing key's 32-byte Ed25519 seed (RFC 8032 private key).
      def invite_private_seed = derive("invite-sign", 32)

      # The invite signing key pair.
      def invite_key = Identity.from_seed(invite_private_seed)

      # The raw public half of the invite signing key.
      def invite_public_key = invite_key.public_raw

      # The group's content key, epoch 0, 32 bytes.
      def content_key = derive("content-key", 32)

      def content_key_base64 = Base64Text.encode(content_key)

      # The lookup code: 80 bits of a one-way derivation, 16 characters.
      def code = Social.base32_encode(derive("lookup", CODE_LENGTH))

      def ==(other) = other.is_a?(GroupSecret) && Crypto.port.equal?(@secret, other.bytes)
      alias eql? ==

      def hash = @secret.hash

      def inspect = "GroupSecret[#{code}]"
      alias to_s inspect

      private

      def derive(info, length) = Social.hkdf_sha256(@secret, SALT, info, length)
    end

    # ---------------------------------------------------------- the invite key

    # One key, two renderings. Compact, for a text message:
    # aspace-inv1-<code>-<secret>[-<delegation>][@host[:port]], the host
    # present only when the beacon is not the default. URL, for a phone:
    # https://<host>/j/<code>#<secret>[.<delegation>]; the server receives
    # the path only. delegation is the base64 delegation string (public data)
    # or nil, in which case the beacon document's invite field carries it.
    class InviteKey
      attr_reader :host, :code, :secret, :delegation

      def initialize(host, code, secret, delegation = nil)
        @host = host.strip.downcase
        @code = code.strip.upcase
        @secret = secret
        @delegation = delegation
      end

      def self.of(secret, delegation = nil, host: DEFAULT_HOST) = new(host, secret.code, secret, delegation)

      def compact
        out = PREFIX + @code + "-" + Social.base32_encode(@secret.bytes)
        out += "-" + Social.base32_encode(Base64Text.decode(@delegation)) unless @delegation.nil?
        out += "@" + @host if @host != DEFAULT_HOST
        out
      end

      def url
        out = "https://#{@host}/j/#{@code}##{Social.base32_encode(@secret.bytes)}"
        out += "." + Social.base32_encode(Base64Text.decode(@delegation)) unless @delegation.nil?
        out
      end

      # The beacon's base URL.
      def beacon(scheme = "https") = "#{scheme}://#{@host}"

      # The document URL at the beacon: /j/<code>.
      def document_url(scheme = "https") = "#{scheme}://#{@host}/j/#{@code}"

      def with_delegation(delegation) = InviteKey.new(@host, @code, @secret, delegation)

      def with_host(host) = InviteKey.new(host, @code, @secret, @delegation)

      # Parses either rendering; case and spaces inside segments are forgiven.
      # Raises Social::Error when the text is not an invite key or the code
      # does not belong to the secret.
      def self.parse(text)
        raise Error, "not an invite key" unless text.is_a?(String)

        t = text.strip
        return parse_url(t) if t.downcase.start_with?("https://", "http://")

        t = t.delete(" \n\t")
        raise Error, "not an invite key: it does not start with #{PREFIX}" unless t.downcase.start_with?(PREFIX)

        rest = t[PREFIX.size..]
        host = DEFAULT_HOST
        at = rest.rindex("@")
        unless at.nil?
          host = rest[(at + 1)..].strip
          rest = rest[0...at]
        end
        segments = rest.split("-", -1)
        raise Error, "not an invite key: expected code-secret[-delegation]" if segments.size < 2 || segments.size > 3

        secret = secret_of(segments[1])
        code = segments[0].upcase
        raise Error, "not an invite key: the code does not belong to the secret" if code != secret.code

        delegation = segments.size == 3 ? Base64Text.encode(Social.base32_decode(segments[2])) : nil
        new(host, code, secret, delegation)
      end

      def self.parse_url(text)
        parts = Beacon.urlsplit(text.delete(" "))
        path = parts.path
        j = path.index("/j/")
        if j.nil? || parts.fragment.strip.empty?
          raise Error, "not an invite link: expected https://host/j/<code>#<secret>"
        end

        code = path[(j + 3)..].split("/", 2).first.to_s
        fragment = parts.fragment
        dot = fragment.index(".")
        secret = secret_of(dot.nil? ? fragment : fragment[0...dot])
        raise Error, "not an invite link: the code does not belong to the secret" if code.upcase != secret.code

        delegation = dot.nil? ? nil : Base64Text.encode(Social.base32_decode(fragment[(dot + 1)..]))
        hostname = parts.hostname.to_s
        hostname = "[#{hostname}]" if hostname.include?(":")
        port = parts.port
        # Python's rule, kept: a port is dropped when it is 443 (or 0), for http too.
        host = hostname + (port.nil? || port.zero? || port == 443 ? "" : ":#{port}")
        raise Error, "not an invite link: no host" if hostname.empty?

        new(host, code, secret, delegation)
      end

      def self.secret_of(segment)
        decoded = Social.base32_decode(segment)
        raise Error, "not an invite key: the secret is #{decoded.bytesize} bytes" if decoded.bytesize != SECRET_LENGTH

        GroupSecret.new(decoded)
      end
      private_class_method :parse_url, :secret_of

      def inspect = "#{PREFIX}#{@code}-...#{@host == DEFAULT_HOST ? '' : "@#{@host}"}"
      alias to_s inspect
    end

    # ------------------------------------------ delegations and credentials (CBOR)
    # The Java records of JoinCredentials, as Hashes in declared field order;
    # a GroupId or PeerId is its text, a byte[] a binary String.

    # DelegationView: the bytes a founder signs when delegating.
    def delegation_view(invite_key, group, not_after_millis, label)
      { "inviteKey" => invite_key.b, "group" => group, "notAfterMillis" => Integer(not_after_millis),
        "label" => label }
    end

    # CredentialView: the bytes the invite key (or a founder) signs per candidate.
    def credential_view(candidate, group) = { "candidate" => candidate, "group" => group }

    # JoinCredentials.delegate: the founder signs the invite key bound to the
    # group with an expiry and a label; returns the base64 delegation string.
    def delegate(founder, group, invite_public_key, not_after_millis, label)
      unless invite_public_key.is_a?(String) && invite_public_key.bytesize == 32
        raise Error, "an invite key is a raw 32-byte Ed25519 public key"
      end

      text = label.nil? || label.empty? ? "" : label
      view = delegation_view(invite_public_key, group, not_after_millis, text)
      delegation = { "founderKey" => founder.public_raw.b, "inviteKey" => invite_public_key.b, "group" => group,
                     "notAfterMillis" => Integer(not_after_millis), "label" => text,
                     "signature" => founder.sign(CBOR.dump(view)) }
      Base64Text.encode(CBOR.dump(delegation))
    end

    # The Delegation record a delegation string carries, in declared field
    # order. Raises Social::Error when the string is not a delegation: a
    # JoinCredentials.Delegation in the wire encoding (HLC round six,
    # 2026-11-08, F3) whose keys, signature, and group are present.
    def decode_delegation(delegation)
      parsed = begin
        Schema.load("JoinCredentials.Delegation", Base64Text.decode(delegation.strip))
      rescue StandardError
        raise Error, "not a delegation string"
      end
      unless bytes?(parsed["founderKey"]) && bytes?(parsed["inviteKey"]) && bytes?(parsed["signature"]) &&
             text?(parsed["group"])
        raise Error, "not a delegation string"
      end

      { "founderKey" => parsed["founderKey"], "inviteKey" => parsed["inviteKey"], "group" => parsed["group"],
        "notAfterMillis" => parsed["notAfterMillis"], "label" => text?(parsed["label"]) ? parsed["label"] : "",
        "signature" => parsed["signature"] }
    end

    # JoinCredentials.describe: founder (PeerID), invite_key, group,
    # not_after_millis, label.
    def delegation_info(delegation)
      d = decode_delegation(delegation)
      { "founder" => Derive.id(d["founderKey"]), "invite_key" => d["inviteKey"], "group" => d["group"],
        "not_after_millis" => d["notAfterMillis"], "label" => d["label"] }
    end

    # The GroupID a delegation names.
    def delegation_group(delegation) = decode_delegation(delegation)["group"]

    # JoinCredentials.issueDelegated: the invite key's signature over
    # (candidate, group) under the delegation, as the d1: credential string.
    # invite_signing_key is the invite Identity or its 32-byte seed.
    def issue_delegated(delegation, invite_signing_key, candidate)
      parsed = decode_delegation(delegation)
      key = signing_identity(invite_signing_key)
      view = CBOR.dump(credential_view(candidate, parsed["group"]))
      credential = { "delegation" => parsed, "signature" => key.sign(view) }
      DELEGATED_PREFIX + Base64Text.encode(CBOR.dump(credential))
    end

    # The DelegatedCredential record of a d1: credential string.
    def decode_delegated(credential)
      raise Error, "not a delegated credential" unless credential.is_a?(String) &&
                                                       credential.strip.start_with?(DELEGATED_PREFIX)

      parsed = begin
        Schema.load("JoinCredentials.DelegatedCredential", Base64Text.decode(strip_prefix(credential.strip)))
      rescue StandardError
        raise Error, "not a delegated credential"
      end
      unless parsed["delegation"].is_a?(Hash) && bytes?(parsed["signature"])
        raise Error, "not a delegated credential"
      end

      delegation = decode_delegation(Base64Text.encode(CBOR.dump(parsed["delegation"])))
      { "delegation" => delegation, "signature" => parsed["signature"] }
    end

    # JoinCredentials.hash: SHA-256 of the credential's decoded bytes, which
    # a JOIN_CREDENTIAL revocation names to refuse one holder.
    def credential_hash(credential)
      Crypto.port.sha256(Base64Text.decode(strip_prefix(credential.strip)))
    end

    # JoinCredentials.delegationHash: SHA-256 of the delegation's bytes, from
    # a delegation string or a delegated credential; revoking it refuses
    # every credential issued under it.
    def delegation_hash(delegation_or_credential)
      text = delegation_or_credential.strip
      delegation = text.start_with?(DELEGATED_PREFIX) ? decode_delegated(text)["delegation"] : decode_delegation(text)
      Crypto.port.sha256(CBOR.dump(delegation))
    end

    # The delegation half of JoinCredentials.verify: the founder key hashes
    # to the founding's issuer, the delegation names the group, it has not
    # expired at now_ms (ten minutes of skew allowed), and the founder's
    # signature verifies over the DelegationView.
    def delegation_verifies?(delegation, group_ad_issuer, group_id, now_ms)
      return false if delegation.fetch("founderKey").bytesize != 32 || delegation.fetch("inviteKey").bytesize != 32
      return false if Derive.id(delegation["founderKey"]) != group_ad_issuer
      return false if delegation.fetch("group") != group_id
      return false if Integer(now_ms) - EXPIRY_SKEW_MILLIS > Integer(delegation.fetch("notAfterMillis"))

      view = CBOR.dump(delegation_view(delegation["inviteKey"], delegation["group"], delegation["notAfterMillis"],
                                       delegation.fetch("label")))
      Identity.verify(delegation["founderKey"], view, delegation.fetch("signature"))
    rescue KeyError, TypeError, ArgumentError, NoMethodError
      false
    end

    # JoinCredentials.admits for the delegated shape, with public data only:
    # the delegation verifies against the founding's issuer and group at
    # now_ms, and the invite key's signature verifies over (candidate,
    # group). Revocation is the caller's (the peer's registry).
    def delegated_credential_admits?(credential, candidate, group_ad_issuer, group_id, now_ms)
      parsed = begin
        decode_delegated(credential)
      rescue Error
        return false
      end
      delegation = parsed["delegation"]
      return false unless delegation_verifies?(delegation, group_ad_issuer, group_id, now_ms)

      Identity.verify(delegation["inviteKey"], CBOR.dump(credential_view(candidate, group_id)), parsed["signature"])
    end

    # JoinCredentials.judge for the delegated shape: "valid", "expired"
    # (every check but the expiry passes), or "invalid". A member admitted
    # while the delegation was valid is re-admitted under the same credential
    # after it expires (SPEC 5.1, v0.1.20), so expiry alone is not a refusal
    # for a peer that joined in time.
    def judge_delegated_credential(credential, candidate, group_ad_issuer, group_id, now_ms)
      parsed = begin
        decode_delegated(credential)
      rescue Error
        return "invalid"
      end
      delegation = parsed["delegation"]
      not_after = Integer(delegation["notAfterMillis"])
      # Judge everything but the expiry by asking at an instant inside the window.
      return "invalid" unless delegation_verifies?(delegation, group_ad_issuer, group_id, not_after)

      view = CBOR.dump(credential_view(candidate, group_id))
      return "invalid" unless Identity.verify(delegation["inviteKey"], view, parsed["signature"])

      Integer(now_ms) - EXPIRY_SKEW_MILLIS > not_after ? "expired" : "valid"
    end

    # SocialGroups.hintsFor: the aspace:join hint a holder of a key presents.
    def hints_for(key, delegation, self_peer_id)
      { HINT_KEY => issue_delegated(delegation, key.secret.invite_private_seed, self_peer_id) }
    end

    # ------------------------------------------------------------- internals

    def signing_identity(identity_or_seed)
      return identity_or_seed if identity_or_seed.is_a?(Identity)
      return Identity.from_seed(identity_or_seed.b) if identity_or_seed.is_a?(String) && identity_or_seed.bytesize == 32

      raise Error, "an invite signing key is an Identity or its 32-byte seed"
    end

    def strip_prefix(encoded) = encoded.start_with?(DELEGATED_PREFIX) ? encoded[DELEGATED_PREFIX.size..] : encoded

    def bytes?(value) = value.is_a?(String) && value.encoding == Encoding::BINARY

    def text?(value) = value.is_a?(String) && value.encoding != Encoding::BINARY

    private_class_method :signing_identity, :strip_prefix, :bytes?, :text?
  end
end
