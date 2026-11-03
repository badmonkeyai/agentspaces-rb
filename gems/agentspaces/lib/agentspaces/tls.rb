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

require "ipaddr"
require "openssl"

module AgentSpaces
  # Channel certificates (SPEC 5.6): a fresh EC P-256 key for TLS in a
  # self-signed X.509 certificate whose signature is the peer's Ed25519
  # identity signature over the TBSCertificate (id-Ed25519, RFC 8410), with
  # the raw identity key in the subject CN as multibase base58btc. The TLS
  # handshake proves possession of the P-256 key; the endorsement binds the
  # channel to PeerID = multibase(sha-256(identity key)). No CA participates.
  module ChannelCertificate
    module_function

    # Returns [tls_key, certificate] for identity, as Java ChannelCertificate.generate.
    def generate(identity)
      key = OpenSSL::PKey::EC.generate("prime256v1")
      name = OpenSSL::X509::Name.new([["CN", Base58.multibase(identity.public_raw), OpenSSL::ASN1::UTF8STRING]])
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = OpenSSL::BN.new(SecureRandom.random_bytes(9).unpack1("H*"), 16)
      cert.subject = name
      cert.issuer = name
      cert.public_key = key
      now = Time.now - 3600
      cert.not_before = now
      cert.not_after = now + (365 * 24 * 3600)
      identity.endorse_certificate(cert)
      [key, cert]
    end

    # The PeerID a presented certificate attests, or nil: the signature
    # algorithm is id-Ed25519, the CN decodes to a 32-byte key, and that key's
    # signature over the TBSCertificate verifies.
    def attest(certificate)
      return nil unless certificate.is_a?(OpenSSL::X509::Certificate)
      # MRI's openssl names the algorithm; JRuby's reports the OID.
      return nil unless ["ED25519", "1.3.101.112"].include?(certificate.signature_algorithm.to_s.upcase)

      cn = certificate.subject.to_a.find { |field, _, _| field == "CN" }&.at(1)
      return nil if cn.nil? || cn.size > 64 || !cn.start_with?("z")

      raw = Base58.decode(cn[1..])
      return nil unless raw.bytesize == 32
      return nil unless certificate.verify(Crypto.port.ed25519_public(raw))

      Derive.id(raw)
    rescue OpenSSL::X509::CertificateError, OpenSSL::PKey::PKeyError, ArgumentError
      nil
    end
  end

  # A FrameChannel over TLS 1.3 that knows the PeerID the handshake attested.
  class TlsChannel < FrameChannel
    attr_reader :attested_peer

    def initialize(io, remote, attested_peer)
      super(io, remote)
      @attested_peer = attested_peer
    end

    def abandon
      # A forked child closes its descriptor without a close_notify alert.
      @io.to_io.close unless @io.to_io.closed?
    rescue IOError, SystemCallError
      nil
    end
  end

  # The tls binding: length-prefixed frames inside TLS 1.3 (RFC 8446). Both
  # ends present channel certificates; the remote end is attested from the
  # certificate it presented, and a remote that presents none connects
  # unattested with every frame still signed. No session resumption and no
  # early data, so every attestation rests on a full handshake.
  class TlsDialer < Dialer
    # require_attested: refuse a remote that attests no PeerID.
    def initialize(require_attested: true)
      super()
      @require_attested = require_attested
      @credentials = {}
      @lock = Mutex.new
    end

    def schemes = ["tls"]

    def open(seed, identity:, timeout: 10)
      ssl, attested = TlsDialer.connect(seed, identity: identity, timeout: timeout, credentials: credentials(identity),
                                              require_attested: @require_attested)
      TlsChannel.new(ssl, seed, attested)
    end

    # A TLS 1.3 connection presenting identity's channel certificate; returns
    # [ssl_socket, attested_peer_id_or_nil]. With require_attested the remote
    # must present an endorsed channel certificate; without it (wss, https) a
    # certificate the system roots trust for the host also connects, unattested,
    # and identity then binds in band by session attestation.
    def self.connect(seed, identity:, timeout:, credentials:, require_attested:, alpn: nil)
      key, cert = credentials
      context = OpenSSL::SSL::SSLContext.new
      context.min_version = OpenSSL::SSL::TLS1_3_VERSION
      context.cert = cert
      context.key = key
      context.session_cache_mode = OpenSSL::SSL::SSLContext::SESSION_CACHE_OFF
      context.alpn_protocols = alpn if alpn
      context.verify_mode = OpenSSL::SSL::VERIFY_PEER
      if require_attested
        # The CA chain proves nothing here; the endorsement is checked after
        # the handshake against the PeerID the certificate names.
        context.verify_callback = ->(_preverified, _store) { true }
      else
        context.cert_store = OpenSSL::X509::Store.new.tap(&:set_default_paths)
        context.verify_callback = lambda do |preverified, store|
          preverified || (store.error_depth.zero? && !ChannelCertificate.attest(store.current_cert).nil?)
        end
      end
      socket = Dialer.tcp(seed.host, seed.port, timeout)
      ssl = OpenSSL::SSL::SSLSocket.new(socket, context)
      ssl.sync_close = true
      ssl.hostname = seed.host unless ip?(seed.host)
      ssl.connect
      attested = ChannelCertificate.attest(ssl.peer_cert)
      if attested.nil?
        if require_attested
          ssl.close
          raise OpenSSL::SSL::SSLError, "#{seed} presented no endorsed channel certificate"
        end
        ssl.post_connection_check(seed.host)
      end
      [ssl, attested]
    rescue StandardError
      socket&.close unless ssl
      raise
    end

    def self.ip?(host)
      IPAddr.new(host)
      true
    rescue IPAddr::InvalidAddressError
      false
    end

    # The channel certificate for an identity, generated once per dialer.
    def credentials(identity) = @lock.synchronize { @credentials[identity.peer_id] ||= ChannelCertificate.generate(identity) }
  end
end
