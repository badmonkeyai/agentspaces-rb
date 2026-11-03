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

require "openssl"
require "securerandom"

module AgentSpaces
  # The crypto seam (SRAD RB-B-07): Ed25519, X25519, HKDF-SHA-256,
  # HMAC-SHA-256, SHA-256, random bytes, and a constant-time comparison.
  # OpenSSLCrypto is the default and needs nothing beyond the openssl
  # default gem on OpenSSL 1.1.1 or later. Install another port with
  # AgentSpaces::Crypto.port = MyPort.new.
  module Crypto
    # A primitive the installed OpenSSL build cannot run.
    class Unavailable < StandardError; end

    # The default port over Ruby's openssl library.
    class OpenSSLCrypto
      def generate_ed25519 = OpenSSL::PKey.generate_key("ED25519")

      def ed25519_from_seed(seed) = OpenSSL::PKey.new_raw_private_key("ED25519", seed)

      def ed25519_from_pkcs8(der)
        key = OpenSSL::PKey.read(der)
        raise ArgumentError, "not an Ed25519 PKCS#8 key" unless key.oid == "ED25519"

        key
      end

      def ed25519_public(raw) = OpenSSL::PKey.new_raw_public_key("ED25519", raw)

      def sign(key, message) = key.sign(nil, message)

      def verify(public_raw, message, signature)
        return false unless public_raw.is_a?(String) && public_raw.bytesize == 32
        return false unless signature.is_a?(String) && signature.bytesize == 64

        ed25519_public(public_raw).verify(nil, signature, message)
      rescue OpenSSL::PKey::PKeyError
        false
      end

      def generate_x25519 = OpenSSL::PKey.generate_key("X25519")

      def x25519_from_raw(raw) = OpenSSL::PKey.new_raw_private_key("X25519", raw)

      def x25519(private_key, peer_public_raw)
        private_key.derive(OpenSSL::PKey.new_raw_public_key("X25519", peer_public_raw))
      end

      def hkdf_sha256(ikm, salt:, info:, length:)
        OpenSSL::KDF.hkdf(ikm, salt: salt, info: info, length: length, hash: "SHA256")
      end

      def hmac_sha256(key, message) = OpenSSL::HMAC.digest("SHA256", key, message)

      def sha256(data) = OpenSSL::Digest::SHA256.digest(data)

      def random_bytes(count) = SecureRandom.random_bytes(count)

      def equal?(left, right)
        left.bytesize == right.bytesize && OpenSSL.fixed_length_secure_compare(left, right)
      end
    end

    # The JRuby port (SRAD RB-B-08): jruby-openssl signs and verifies
    # Ed25519 but has no X25519, so key agreement runs on the JDK's own
    # provider (JEP 324). Everything else is OpenSSLCrypto's.
    class JdkCrypto < OpenSSLCrypto
      # An X25519 key with the raw accessors OpenSSL::PKey keys have.
      class X25519Key
        attr_reader :raw_private_key, :raw_public_key

        def initialize(private_key, raw_public_key)
          @private_key = private_key
          @raw_private_key = private_key.getScalar.get.to_s.b
          @raw_public_key = raw_public_key
        end

        attr_reader :private_key
      end

      def generate_x25519
        pair = java.security.KeyPairGenerator.getInstance("X25519").generateKeyPair
        X25519Key.new(pair.getPrivate, JdkCrypto.u_bytes(pair.getPublic.getU))
      end

      def x25519_from_raw(raw)
        spec = java.security.spec.XECPrivateKeySpec.new(java.security.spec.NamedParameterSpec::X25519, raw.to_java_bytes)
        key = java.security.KeyFactory.getInstance("X25519").generatePrivate(spec)
        public_raw = x25519_public_of(raw)
        X25519Key.new(key, public_raw)
      end

      def x25519(private_key, peer_public_raw)
        u = JdkCrypto.u_integer(peer_public_raw)
        spec = java.security.spec.XECPublicKeySpec.new(java.security.spec.NamedParameterSpec::X25519, u)
        public_key = java.security.KeyFactory.getInstance("X25519").generatePublic(spec)
        agreement = javax.crypto.KeyAgreement.getInstance("X25519")
        agreement.init(private_key.private_key)
        agreement.doPhase(public_key, true)
        String.from_java_bytes(agreement.generateSecret).b
      end

      # The public u-coordinate for a raw private scalar: agreement with the base point 9.
      def x25519_public_of(raw)
        base = ("\x09".b + ("\x00".b * 31))
        key = java.security.spec.XECPrivateKeySpec.new(java.security.spec.NamedParameterSpec::X25519, raw.to_java_bytes)
        private_key = java.security.KeyFactory.getInstance("X25519").generatePrivate(key)
        agreement = javax.crypto.KeyAgreement.getInstance("X25519")
        agreement.init(private_key)
        spec = java.security.spec.XECPublicKeySpec.new(java.security.spec.NamedParameterSpec::X25519, JdkCrypto.u_integer(base))
        agreement.doPhase(java.security.KeyFactory.getInstance("X25519").generatePublic(spec), true)
        String.from_java_bytes(agreement.generateSecret).b
      end

      # RFC 7748 u-coordinates are 32 little-endian bytes; Java holds a BigInteger.
      def self.u_bytes(big) = [Integer(big.to_s).to_s(16).rjust(64, "0")].pack("H*").reverse.b

      def self.u_integer(raw) = java.math.BigInteger.new(raw.b.reverse.unpack1("H*"), 16)
    end

    @port = RUBY_ENGINE == "jruby" ? JdkCrypto.new : OpenSSLCrypto.new

    class << self
      attr_accessor :port

      # Runs one operation of every primitive and raises Unavailable naming the
      # one that failed and the OpenSSL build, before any socket opens.
      def doctor
        checks = {
          "Ed25519" => lambda {
            key = port.generate_ed25519
            raise "verify failed" unless port.verify(key.raw_public_key, "probe", port.sign(key, "probe"))
          },
          "Ed25519 PKCS#8" => -> { port.ed25519_from_pkcs8(port.generate_ed25519.private_to_der) },
          "X25519" => lambda {
            a = port.generate_x25519
            b = port.generate_x25519
            raise "agreement failed" unless port.x25519(a, b.raw_public_key) == port.x25519(b, a.raw_public_key)
          },
          "HKDF-SHA-256" => -> { port.hkdf_sha256("k", salt: "", info: "i", length: 32) },
          "HMAC-SHA-256" => -> { port.hmac_sha256("k", "m") }
        }
        checks.each do |name, check|
          check.call
        rescue StandardError, NotImplementedError => e
          raise Unavailable, "#{name} is unavailable in #{OpenSSL::OPENSSL_LIBRARY_VERSION} " \
                             "(#{e.class}: #{e.message}); AgentSpaces needs OpenSSL 1.1.1 or later"
        end
        { "openssl" => OpenSSL::OPENSSL_LIBRARY_VERSION, "ruby" => RUBY_DESCRIPTION, "checks" => checks.keys }
      end
    end
  end
end
