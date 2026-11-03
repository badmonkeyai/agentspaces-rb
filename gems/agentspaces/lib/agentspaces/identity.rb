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

require "fileutils"
require "securerandom"

module AgentSpaces
  # Base58 (Bitcoin alphabet) and the multibase "z" prefix the Java side uses.
  module Base58
    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    module_function

    def encode(data)
      bytes = data.b
      zeros = bytes.bytes.take_while(&:zero?).size
      number = bytes.empty? ? 0 : bytes.unpack1("H*").to_i(16)
      encoded = +""
      while number.positive?
        number, digit = number.divmod(58)
        encoded.prepend(ALPHABET[digit])
      end
      ("1" * zeros) + encoded
    end

    def decode(text)
      zeros = text.each_char.take_while { |c| c == "1" }.size
      number = 0
      text.each_char do |c|
        digit = ALPHABET.index(c)
        raise ArgumentError, "not base58: #{c.inspect}" if digit.nil?

        number = (number * 58) + digit
      end
      hex = number.zero? ? "" : number.to_s(16)
      hex = "0#{hex}" if hex.size.odd?
      (("\x00" * zeros) + [hex].pack("H*")).b
    end

    def multibase(data) = "z#{encode(data)}"
  end

  # Self-certifying names (SPEC 4.1, 4.4): multibase(sha-256(material)).
  module Derive
    module_function

    def id(material) = Base58.multibase(Crypto.port.sha256(material.b))

    # GroupId.fromFounding over literal founding text or bytes.
    def group_id_from_founding(founding) = id(founding)

    # GroupId.fromFounding over the canonical founding document bytes.
    def group_id_from_founding_document(document_bytes) = id(document_bytes)

    # SpaceId.local: the hash of "local:" + name.
    def space_id_local(name) = id("local:#{name}")
  end

  # java.time.Instant and java.time.Duration text, as Java prints them.
  module Instants
    INSTANT = /\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z\z/
    DURATION = /\APT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)(?:\.(\d{1,9}))?S)?\z/

    module_function

    # "2026-01-01T00:00:00Z" (optional fraction) to epoch milliseconds.
    def parse_millis(iso)
      match = iso.is_a?(String) && INSTANT.match(iso)
      raise ArgumentError, "not an ISO-8601 instant: #{iso.inspect}" unless match

      year, month, day, hour, minute, second, fraction = match.captures
      millis = Time.utc(year.to_i, month.to_i, day.to_i, hour.to_i, minute.to_i, second.to_i).to_i * 1000
      millis += fraction.ljust(9, "0")[0, 3].to_i if fraction
      millis
    end

    # "PT24H", "PT1H30M", "PT0.5S" (never days) to milliseconds.
    def parse_duration_millis(iso)
      match = iso.is_a?(String) && iso != "PT" && DURATION.match(iso)
      raise ArgumentError, "not an ISO-8601 duration: #{iso.inspect}" unless match

      hours, minutes, seconds, fraction = match.captures
      millis = ((hours.to_i * 3600) + (minutes.to_i * 60) + seconds.to_i) * 1000
      millis += fraction.ljust(9, "0")[0, 3].to_i if fraction
      millis
    end

    # Epoch milliseconds as java.time.Instant prints them: whole seconds bare,
    # otherwise three fraction digits.
    def iso(millis)
      seconds, fraction = Integer(millis).divmod(1000)
      text = Time.at(seconds).utc.strftime("%Y-%m-%dT%H:%M:%S")
      fraction.zero? ? "#{text}Z" : format("%<t>s.%<f>03dZ", t: text, f: fraction)
    end
  end

  # Founding documents (SPEC 4.4, 5.1; Java GroupFounding).
  module Founding
    URI_PREFIX = "aspace://"
    MEMBERSHIP_POLICIES = %w[OPEN INVITE POLICY].freeze
    CONFLICT_STRATEGIES = %w[LEASE_RACE AUCTION ORDERED].freeze

    module_function

    # GroupFounding.FoundingFields in canonical field order: the immutable
    # fields no later party may change. ttl and period are java.time Duration
    # strings as Java prints them, because the signature covers these bytes.
    def fields(name, founder_peer_id, issued_iso, ttl_iso, policy, strategy, fanout, period_iso)
      { "name" => name, "founder" => founder_peer_id, "issued" => issued_iso, "ttl" => ttl_iso,
        "membershipPolicy" => policy, "defaultStrategy" => strategy,
        "gossip" => { "fanout" => Integer(fanout), "period" => period_iso } }
    end

    def document(fields, signature) = { "fields" => fields, "signature" => signature }

    # A GroupAdvertisement in Java record order, re-derivable from the fields.
    def advertisement(group_id, fields)
      { "id" => URI_PREFIX + group_id, "issuer" => fields["founder"], "group" => group_id,
        "issued" => fields["issued"], "ttl" => fields["ttl"], "name" => fields["name"],
        "membershipPolicy" => fields["membershipPolicy"], "defaultStrategy" => fields["defaultStrategy"],
        "gossip" => { "fanout" => fields["gossip"]["fanout"], "period" => fields["gossip"]["period"] } }
    end

    # GroupFounding.found: the SignedGroupAdvertisement
    # {advertisement, founderPublicKey, signature}.
    def found(identity, name, policy, strategy, fanout, period_iso, issued_iso, ttl_iso)
      founding = fields(name, identity.peer_id, issued_iso, ttl_iso, policy, strategy, fanout, period_iso)
      signature = identity.sign(CBOR.dump(founding))
      group_id = Derive.group_id_from_founding_document(CBOR.dump(document(founding, signature)))
      { "advertisement" => advertisement(group_id, founding), "founderPublicKey" => identity.public_raw,
        "signature" => signature }
    end

    # GroupFounding.fieldsOf: the founding fields an advertisement carries,
    # rebuilt in canonical order from a possibly hostile advertisement.
    def fields_of(ad)
      gossip = ad.fetch("gossip")
      fanout = gossip.fetch("fanout")
      raise ArgumentError, "gossip.fanout is not an integer" unless fanout.is_a?(Integer)

      text = [ad["name"], ad["issuer"], ad["issued"], ad["ttl"], ad["membershipPolicy"],
              ad["defaultStrategy"], gossip["period"]]
      raise ArgumentError, "founding field is not text" unless text.all?(String)

      fields(ad["name"], ad["issuer"], ad["issued"], ad["ttl"], ad["membershipPolicy"],
             ad["defaultStrategy"], fanout, gossip["period"])
    end

    # GroupFounding.verify, the four-check receiver rule of SPEC 5.1: returns
    # the verified GroupID, or nil.
    def verify(signed)
      return nil unless signed.is_a?(Hash)

      ad = signed["advertisement"]
      key = signed["founderPublicKey"]
      signature = signed["signature"]
      return nil unless ad.is_a?(Hash) && key.is_a?(String) && signature.is_a?(String)
      return nil unless key.bytesize == 32 && Derive.id(key) == ad["issuer"]

      founding = fields_of(ad)
      return nil unless Crypto.port.verify(key, CBOR.dump(founding), signature)

      group_id = Derive.group_id_from_founding_document(CBOR.dump(document(founding, signature)))
      return nil unless group_id == ad["group"] && ad["id"] == URI_PREFIX + group_id

      group_id
    rescue KeyError, ArgumentError, TypeError, NoMethodError
      nil
    end
  end

  # Subordinate agent certificates (SPEC 4.2, 11a.3; TECH-SPEC 7.2).
  module Certificates
    # How far a signing time may lead the receiver's clock (the HLC drift ceiling).
    MAX_DRIFT_MILLIS = 10 * 60 * 1000

    module_function

    # An AgentCertificate in Java record order; encryptionPublicKey is
    # appended and omitted when absent. Unsigned when peer_signature is nil.
    def build(agent, agent_public_raw, issued_iso, ttl_iso, peer_signature = nil, encryption_public_raw = nil)
      certificate = { "agent" => agent, "agentPublicKey" => agent_public_raw, "issued" => issued_iso,
                      "ttl" => ttl_iso, "peerSignature" => peer_signature }
      certificate["encryptionPublicKey"] = encryption_public_raw unless encryption_public_raw.nil?
      certificate
    end

    def body(certificate)
      build(certificate["agent"], certificate["agentPublicKey"], certificate["issued"], certificate["ttl"],
            nil, certificate["encryptionPublicKey"])
    end

    # The window [issued, issued + ttl) covers signing_ms.
    def covers?(certificate, signing_ms)
      issued = Instants.parse_millis(certificate["issued"])
      signing_ms >= issued && signing_ms < issued + Instants.parse_duration_millis(certificate["ttl"])
    end

    # AgentCertificates.verifyAt: judged at the signing time of what it certifies.
    def verify_at(certificate, peer_public_raw, expected_agent, signing_ms, receiver_now_ms)
      return false unless certificate.is_a?(Hash)
      return false unless covers?(certificate, signing_ms)
      return false if signing_ms > receiver_now_ms + MAX_DRIFT_MILLIS

      verify(certificate, peer_public_raw, expected_agent, signing_ms)
    rescue ArgumentError, TypeError, NoMethodError
      false
    end

    # AgentCertificates.sign: only the peer the agent name belongs to may certify it.
    def sign(body, peer)
      raise ArgumentError, "certificate for #{body['agent']} cannot be issued by #{peer.peer_id}" \
        unless body["agent"].to_s.start_with?("#{peer.peer_id}/")

      unsigned = self.body(body)
      unsigned.merge("peerSignature" => peer.sign(CBOR.dump(unsigned)))
    end

    # AgentCertificates.verify: unexpired at now_ms (expiry inclusive), naming
    # exactly expected_agent of the peer peer_public_raw hashes to.
    def verify(certificate, peer_public_raw, expected_agent, now_ms)
      return false unless certificate.is_a?(Hash)

      signature = certificate["peerSignature"]
      agent_key = certificate["agentPublicKey"]
      agent = certificate["agent"]
      encryption_key = certificate["encryptionPublicKey"]
      return false unless signature.is_a?(String) && agent_key.is_a?(String) && agent_key.bytesize == 32
      return false unless encryption_key.nil? || (encryption_key.is_a?(String) && encryption_key.bytesize == 32)
      return false unless peer_public_raw.is_a?(String) && peer_public_raw.bytesize == 32
      return false unless agent.is_a?(String) && agent == expected_agent
      return false unless agent.start_with?("#{Derive.id(peer_public_raw)}/")

      expires = Instants.parse_millis(certificate["issued"]) + Instants.parse_duration_millis(certificate["ttl"])
      return false if now_ms >= expires

      Crypto.port.verify(peer_public_raw, CBOR.dump(body(certificate)), signature)
    rescue ArgumentError, TypeError, NoMethodError
      false
    end
  end

  # KeyFiles.write: an atomic replace through a temporary file in the same
  # directory, owner-only (0600) for a secret, flushed to disk first.
  module KeyFiles
    module_function

    def write(path, data, secret:)
      directory = File.dirname(File.expand_path(path))
      FileUtils.mkdir_p(directory)
      temp = File.join(directory, ".#{secret ? 'key' : 'pub'}-#{Process.pid}-#{SecureRandom.hex(4)}.tmp")
      File.open(temp, File::WRONLY | File::CREAT | File::EXCL | File::BINARY, secret ? 0o600 : 0o644) do |f|
        f.write(data)
        f.flush
        f.fsync
      end
      File.rename(temp, path)
    ensure
      FileUtils.rm_f(temp) if temp && File.exist?(temp)
    end
  end

  # A subordinate agent identity: the agent's own Ed25519 key plus the
  # peer-signed certificate that vouches for it. A renewing identity
  # re-issues its certificate at half-life and keeps earlier ones so a claim
  # whose stamp a renewal kept stays certifiable.
  class AgentIdentity
    RETAINED = 256

    attr_reader :agent_id, :public_raw, :certificate

    def initialize(agent_id, key, certificate, peer: nil, ttl_iso: nil, clock: nil, encryption_public_raw: nil)
      @agent_id = agent_id
      @key = key
      @public_raw = key.public_raw
      @certificate = certificate
      @peer = peer
      @ttl_iso = ttl_iso
      @clock = clock || -> { Time.now.to_f }
      @encryption_public_raw = encryption_public_raw
      @issued = [certificate]
      @lock = Mutex.new
    end

    def local_name = @agent_id.split("/", 2).last

    def renewing? = !@peer.nil?

    # Re-issues the certificate once half its lifetime has passed.
    def renew_if_due(now_ms = nil)
      return false if @peer.nil?

      now_ms = now_ms.nil? ? (@clock.call * 1000).to_i : Integer(now_ms)
      @lock.synchronize do
        issued = Instants.parse_millis(@certificate["issued"])
        ttl = Instants.parse_duration_millis(@certificate["ttl"])
        return false if now_ms < issued + (ttl / 2)

        body = Certificates.build(@agent_id, @public_raw, Instants.iso(now_ms), @ttl_iso, nil, @encryption_public_raw)
        @certificate = Certificates.sign(body, @peer)
        @issued << @certificate
        @issued.shift while @issued.size > RETAINED
        true
      end
    end

    # The newest held certificate whose window covers signing_ms, or nil.
    def certificate_covering(signing_ms)
      renew_if_due
      @lock.synchronize do
        @issued.reverse_each do |certificate|
          return certificate if Certificates.covers?(certificate, Integer(signing_ms))
        rescue ArgumentError, TypeError
          next
        end
      end
      nil
    end

    def sign(message)
      renew_if_due
      @key.sign(message)
    end

    def inspect = "#<AgentSpaces::AgentIdentity #{@agent_id}>"
    alias to_s inspect

    def pretty_print(pp) = pp.text(inspect)
  end

  # An Ed25519 peer identity with the Java-compatible PeerID.
  class Identity
    SAFE_NAME = /\A[A-Za-z0-9._-]{1,64}\z/

    attr_reader :public_raw, :peer_id

    def initialize(private_key)
      @private = private_key
      @public_raw = private_key.raw_public_key.b
      @peer_id = Derive.id(@public_raw)
    end

    def self.generate = new(Crypto.port.generate_ed25519)

    # An identity from a 32-byte Ed25519 seed (RFC 8032), as Java
    # Ed25519.fromSeed builds one.
    def self.from_seed(seed)
      raise ArgumentError, "an Ed25519 seed is 32 bytes" unless seed.is_a?(String) && seed.bytesize == 32

      new(Crypto.port.ed25519_from_seed(seed.b))
    end

    def self.from_pkcs8(der) = new(Crypto.port.ed25519_from_pkcs8(der.b))

    def self.verify(public_raw, message, signature) = Crypto.port.verify(public_raw, message, signature)

    def sign(message) = Crypto.port.sign(@private, message).b

    # The AgentID string form: "<peerId>/<localName>".
    def agent(local_name) = "#{@peer_id}/#{local_name}"

    # PeerIdentity.subordinate: certifies a fresh (or given) agent key.
    def subordinate(local_name, issued_iso, ttl_iso = "PT1H", key: nil)
      key ||= Identity.generate
      body = Certificates.build(agent(local_name), key.public_raw, issued_iso, ttl_iso)
      AgentIdentity.new(agent(local_name), key, Certificates.sign(body, self))
    end

    # PeerIdentity.renewingSubordinate: an agent key whose certificate this
    # peer re-issues at half-life, judged at signing time by receivers.
    def renewing_subordinate(local_name, ttl_iso = "PT24H", key: nil, clock: nil, encryption_public_raw: nil)
      clock ||= -> { Time.now.to_f }
      key ||= Identity.generate
      now_ms = (clock.call * 1000).to_i
      body = Certificates.build(agent(local_name), key.public_raw, Instants.iso(now_ms), ttl_iso, nil,
                                encryption_public_raw)
      AgentIdentity.new(agent(local_name), key, Certificates.sign(body, self), peer: self, ttl_iso: ttl_iso,
                                                                                 clock: clock,
                                                                                 encryption_public_raw:)
    end

    # Signs an X.509 certificate with the identity key (a channel
    # certificate's endorsement, SPEC 5.6); the key never enters TLS.
    def endorse_certificate(certificate) = certificate.sign(@private, nil)

    # The private key as PKCS#8 DER, the form Java's keystore writes.
    def pkcs8 = @private.private_to_der.b

    def save_pkcs8(path) = KeyFiles.write(path, pkcs8, secret: true)

    # FileKeystore.loadOrCreate: peer.key (PKCS#8 DER, owner-only) and
    # peer.pub (raw 32 bytes), the layout a Java peer reads, minted when absent.
    def self.load_or_create(directory, private_name = "peer.key", public_name = "peer.pub", allow_readable: false)
      private_path = File.join(directory, private_name)
      public_path = File.join(directory, public_name)
      has_private = File.exist?(private_path)
      has_public = File.exist?(public_path)
      if has_private != has_public
        present, missing = has_private ? [private_path, public_path] : [public_path, private_path]
        raise ArgumentError, "corrupt keystore: #{present} exists but #{missing} does not"
      end
      unless has_private
        identity = generate
        KeyFiles.write(private_path, identity.pkcs8, secret: true)
        KeyFiles.write(public_path, identity.public_raw, secret: false)
        return identity
      end
      mode = File.stat(private_path).mode & 0o077
      if mode.nonzero? && !allow_readable
        raise ArgumentError, "#{private_path} is readable by group or others (mode " \
                             "#{format('%o', File.stat(private_path).mode & 0o777)}); chmod 600 it"
      end
      identity = from_pkcs8(File.binread(private_path))
      public = File.binread(public_path)
      raise ArgumentError, "corrupt keystore: #{public_path} is not a raw Ed25519 public key" if public.bytesize != 32

      probe = Crypto.port.random_bytes(32)
      unless verify(public, probe, identity.sign(probe))
        raise ArgumentError, "corrupt keystore: #{private_path} does not belong to the public key in #{public_path}"
      end

      identity
    end

    # AgentKeystore.signingKeys: <dir>/<peer-id>/<local-name>/agent.key and
    # agent.pub. Names that could escape the directory are refused.
    def self.agent_keys(directory, peer_id, local_name)
      [[peer_id, "peer id"], [local_name, "agent name"]].each do |name, what|
        unless name.is_a?(String) && SAFE_NAME.match?(name) && ![".", ".."].include?(name)
          raise ArgumentError, "#{what} #{name.inspect} is not a safe file name"
        end
      end
      load_or_create(File.join(directory, peer_id, local_name), "agent.key", "agent.pub")
    end

    def inspect = "#<AgentSpaces::Identity #{@peer_id}>"
    alias to_s inspect

    def pretty_print(pp) = pp.text(inspect)
  end
end
