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

require "net/http"
require "socket"
require "uri"

module AgentSpaces
  # The ws and wss bindings (SPEC 5.5, v0.1.21): one frame per binary
  # WebSocket message (RFC 6455), no length prefix, subprotocol aspace.1, the
  # 8 MiB frame cap enforced with close code 1009 and a text message refused
  # with 1003. A client masks every frame it sends and refuses a masked one.
  class WsChannel < FrameChannel
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    SUBPROTOCOL = "aspace.1"

    attr_reader :attested_peer

    def initialize(io, remote, attested_peer = nil)
      super(io, remote)
      @attested_peer = attested_peer
      @closed_sent = false
    end

    # The opening handshake over an already connected io. Blocking reads
    # under a watchdog that closes the socket at the deadline: a select on
    # the socket would miss what the TLS layer already buffered (on MRI and
    # on JRuby alike).
    def self.handshake(io, seed, path, timeout: 10)
      raw = io.respond_to?(:to_io) ? io.to_io : io
      expired = false
      watchdog = Thread.new do
        sleep timeout
        expired = true
        raw.close unless raw.closed?
      rescue IOError, SystemCallError
        nil
      end
      key = [Crypto.port.random_bytes(16)].pack("m0")
      io.write("GET #{path} HTTP/1.1\r\nHost: #{seed.authority}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" \
               "Sec-WebSocket-Key: #{key}\r\nSec-WebSocket-Version: 13\r\n" \
               "Sec-WebSocket-Protocol: #{SUBPROTOCOL}\r\n\r\n")
      status = read_line(io)
      raise IOError, "#{seed} answered the upgrade with #{status.strip.inspect}" unless status.start_with?("HTTP/1.1 101")

      headers = {}
      while (line = read_line(io)) != "\r\n"
        name, value = line.split(":", 2)
        headers[name.to_s.strip.downcase] = value.to_s.strip
      end
      accept = [OpenSSL::Digest::SHA1.digest(key + GUID)].pack("m0")
      raise IOError, "#{seed} sent a wrong Sec-WebSocket-Accept" unless headers["sec-websocket-accept"] == accept
      raise IOError, "#{seed} did not select #{SUBPROTOCOL}" unless headers["sec-websocket-protocol"] == SUBPROTOCOL
    rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
      raise IOError, "no upgrade answer from #{seed} in #{timeout}s" if expired

      raise
    ensure
      watchdog&.kill
    end

    def self.read_line(io)
      line = +""
      until line.end_with?("\r\n")
        char = io.read(1)
        raise EOFError, "connection closed during the upgrade" if char.nil?

        line << char
        raise IOError, "upgrade header line too long" if line.bytesize > 8192
      end
      line
    end

    def send_frame(frame)
      raise ArgumentError, "frame of #{frame.bytesize} bytes exceeds the cap" if frame.bytesize > Wire::MAX_FRAME_BYTES

      write_message(0x2, frame)
    end

    # The next binary message, reassembled from its fragments; pings are
    # answered on the way.
    def read_frame
      message = nil
      loop do
        fin, opcode, payload = read_ws_frame
        case opcode
        when 0x9 then write_message(0xA, payload)
        when 0xA then next
        when 0x8
          write_close(1000)
          raise EOFError, "closed by the remote (#{payload.bytesize >= 2 ? payload.unpack1('n') : 'no code'})"
        when 0x1
          write_close(1003)
          raise IOError, "a text message is not a frame"
        when 0x2, 0x0
          raise IOError, "a continuation without a message" if opcode.zero? && message.nil?

          message = opcode == 0x2 ? payload : message + payload
          if message.bytesize > Wire::MAX_FRAME_BYTES
            write_close(1009)
            raise IOError, "frame too large"
          end
          return message.b if fin
        else
          write_close(1002)
          raise IOError, "unknown WebSocket opcode #{opcode}"
        end
      end
    end

    def close
      write_close(1000)
    rescue IOError, SystemCallError
      nil
    ensure
      super
    end

    # A forked child drops the descriptor without a close frame or alert.
    def abandon
      @closed_sent = true
      raw = @io.respond_to?(:to_io) ? @io.to_io : @io
      raw.close unless raw.closed?
    rescue IOError, SystemCallError
      nil
    end

    # payload XOR the repeated 4-byte mask (RFC 6455 5.3), as one bignum XOR
    # so an 8 MiB frame costs no per-byte Ruby loop.
    def self.mask(payload, mask)
      length = payload.bytesize
      return "".b if length.zero?

      key = (mask.b * ((length + 3) / 4)).byteslice(0, length)
      xored = payload.b.unpack1("H*").to_i(16) ^ key.unpack1("H*").to_i(16)
      [xored.to_s(16).rjust(length * 2, "0")].pack("H*")
    end

    private

    def read_ws_frame
      head = read_exact(2)
      first = head.getbyte(0)
      second = head.getbyte(1)
      if second.anybits?(0x80)
        write_close(1002)
        raise IOError, "a server frame must not be masked"
      end
      length = second & 0x7F
      length = read_exact(2).unpack1("n") if length == 126
      length = read_exact(8).unpack1("Q>") if length == 127
      if length > Wire::MAX_FRAME_BYTES
        write_close(1009)
        raise IOError, "frame too large"
      end
      [first.anybits?(0x80), first & 0x0F, length.zero? ? "".b : read_exact(length)]
    end

    def write_message(opcode, payload)
      mask = Crypto.port.random_bytes(4)
      length = payload.bytesize
      header = [0x80 | opcode].pack("C")
      header << if length < 126 then [0x80 | length].pack("C")
                elsif length < 65_536 then [0x80 | 126, length].pack("Cn")
                else [0x80 | 127, length].pack("CQ>")
                end
      @send_lock.synchronize { @io.write(header, mask, WsChannel.mask(payload, mask)) }
    end

    def write_close(code)
      return if @closed_sent || @io.closed?

      @closed_sent = true
      write_message(0x8, [code].pack("n"))
    rescue IOError, SystemCallError
      nil
    end
  end

  # Dials ws (plain) and wss (TLS 1.3) seeds; the path defaults to /aspace.
  class WsDialer < Dialer
    DEFAULT_PATH = "/aspace"

    def initialize(tls_dialer: TlsDialer.new(require_attested: false))
      super()
      @tls = tls_dialer
    end

    def schemes = %w[ws wss]

    def open(seed, identity:, timeout: 10)
      io, attested =
        if seed.scheme == "wss"
          TlsDialer.connect(seed, identity: identity, timeout: timeout, credentials: @tls.credentials(identity),
                                  require_attested: false, alpn: ["http/1.1"])
        else
          [Dialer.tcp(seed.host, seed.port, timeout), nil]
        end
      WsChannel.handshake(io, seed, seed.path || DEFAULT_PATH, timeout: timeout)
      WsChannel.new(io, seed, attested)
    rescue StandardError
      io&.close
      raise
    end
  end

  # The http and https bindings (SPEC annex C): POST P/open answers 201 with
  # a session location; POST P/s/<sid>/up carries batches of length-prefixed
  # frames under a rising Aspace-Seq (a batch whose answer was lost is sent
  # again under the same number); GET P/s/<sid>/down long-polls the server's
  # batch under Aspace-Ack; DELETE ends the session. A session is one
  # connection, unattested; identity binds in band by session attestation.
  class HttpChannel < FrameChannel
    MEDIA_TYPE = "application/vnd.agentspaces.frames"
    MAX_BATCH_FRAMES = 64
    UPLOAD_BYTES = 1024 * 1024
    MAX_BODY = 9 * 1024 * 1024
    CLOSED = Object.new.freeze

    attr_reader :session_uri

    def initialize(session_uri, remote, long_poll: 25, idle_timeout: 60, tls: nil)
      @session_uri = session_uri
      @remote = remote
      @long_poll = long_poll
      @idle = idle_timeout
      @tls = tls
      @inbound = Thread::Queue.new
      @outbound = Thread::Queue.new
      @closed = false
      @send_lock = Mutex.new
      @threads = [Thread.new { upload_loop }, Thread.new { download_loop }]
      @threads.each { |t| t.report_on_exception = false }
    end

    def self.encode_batch(frames)
      raise ArgumentError, "more than #{MAX_BATCH_FRAMES} frames in one body" if frames.size > MAX_BATCH_FRAMES

      body = frames.map { |f| [f.bytesize].pack("N") + f.b }.join.b
      raise ArgumentError, "body of #{body.bytesize} bytes exceeds #{MAX_BODY}" if body.bytesize > MAX_BODY

      body
    end

    # Decodes a body; a bad length prefix, too many frames, or an oversize
    # frame raises before any copy of the rest.
    def self.decode_batch(body)
      raise ArgumentError, "body exceeds #{MAX_BODY} bytes" if body.bytesize > MAX_BODY

      frames = []
      offset = 0
      while offset < body.bytesize
        raise ArgumentError, "truncated length prefix" if body.bytesize - offset < 4

        length = body.byteslice(offset, 4).unpack1("l>")
        offset += 4
        if length <= 0 || length > Wire::MAX_FRAME_BYTES || length > body.bytesize - offset
          raise ArgumentError, "bad frame length #{length}"
        end

        frames << body.byteslice(offset, length)
        offset += length
        raise ArgumentError, "more than #{MAX_BATCH_FRAMES} frames in one body" if frames.size > MAX_BATCH_FRAMES
      end
      frames
    end

    def attested_peer = nil

    def send_frame(frame)
      raise IOError, "the session is closed" if @closed
      raise ArgumentError, "frame of #{frame.bytesize} bytes exceeds the cap" if frame.bytesize > Wire::MAX_FRAME_BYTES

      @outbound << frame.b
    end

    def read_frame
      frame = @inbound.pop
      if frame.equal?(CLOSED)
        @inbound << CLOSED # every later read ends the same way
        raise EOFError, @end_reason || "the session ended"
      end

      frame
    end

    def close
      return if @closed

      finish("closed by this end")
      begin
        HttpChannel.client(@session_uri, 5, @tls).request(Net::HTTP::Delete.new(@session_uri))
      rescue StandardError
        nil
      end
      @threads.each do |t|
        next if t == Thread.current

        t.kill unless t.join(1) # a long poll in flight ends with the session
      end
    end

    def closed? = @closed

    def abandon
      @closed = true
      @inbound << CLOSED
    end

    private

    def finish(reason)
      return if @closed

      @closed = true
      @end_reason = reason
      @inbound << CLOSED
      @outbound << CLOSED
    end

    def http(read_timeout) = HttpChannel.client(@session_uri, read_timeout, @tls)

    # A Net::HTTP for uri; over https it presents credentials ([key, cert])
    # and trusts the system roots or an identity-endorsed leaf.
    def self.client(uri, read_timeout, credentials, open_timeout: 10)
      client = Net::HTTP.new(uri.host, uri.port)
      client.open_timeout = open_timeout
      client.read_timeout = read_timeout
      if uri.scheme == "https"
        client.use_ssl = true
        client.min_version = OpenSSL::SSL::TLS1_3_VERSION
        client.verify_mode = OpenSSL::SSL::VERIFY_PEER
        client.cert_store = OpenSSL::X509::Store.new.tap(&:set_default_paths)
        # An endorsed leaf names a PeerID, not a host, so the host check runs
        # here, and only on a leaf the system roots vouch for.
        client.verify_hostname = false
        host = uri.host
        client.verify_callback = lambda do |preverified, store|
          next preverified unless store.error_depth.zero?
          next true unless ChannelCertificate.attest(store.current_cert).nil?

          preverified && OpenSSL::SSL.verify_certificate_identity(store.current_cert, host)
        end
        if credentials
          client.cert = credentials[1]
          client.key = credentials[0]
        end
      end
      client
    end

    FAILURES = [IOError, SystemCallError, Timeout::Error, OpenSSL::SSL::SSLError, Net::HTTPBadResponse].freeze

    def upload_loop
      seq = 0
      client = nil
      until @closed
        first = @outbound.pop
        break if first.equal?(CLOSED)

        batch = [first]
        bytes = first.bytesize
        while batch.size < MAX_BATCH_FRAMES && !@outbound.empty?
          peeked = @outbound.pop
          if peeked.equal?(CLOSED) || bytes + peeked.bytesize > UPLOAD_BYTES
            @outbound << peeked # back for the next batch, or the close marker
            break
          end
          batch << peeked
          bytes += peeked.bytesize
        end
        seq += 1
        body = HttpChannel.encode_batch(batch)
        failing_since = nil
        until @closed
          request = Net::HTTP::Post.new(URI("#{@session_uri}/up"))
          request["Content-Type"] = MEDIA_TYPE
          request["Aspace-Seq"] = seq.to_s
          request.body = body
          begin
            client ||= http(30).tap(&:start)
            response = client.request(request)
            break if response.code == "204"

            return finish("upload answered #{response.code}")
          rescue *FAILURES
            failing_since ||= monotonic
            return finish("upload idle timeout") if monotonic - failing_since > @idle

            client = drop(client)
            sleep 0.5 # the same batch again, under the same number
          end
        end
      end
    ensure
      drop(client)
    end

    def download_loop
      ack = 0
      client = nil
      failing_since = nil
      until @closed
        request = Net::HTTP::Get.new(URI("#{@session_uri}/down"))
        request["Aspace-Ack"] = ack.to_s
        request["Accept"] = MEDIA_TYPE
        begin
          client ||= http(@long_poll + 15).tap(&:start)
          response = client.request(request)
          failing_since = nil
          next if response.code == "204"
          return finish("download answered #{response.code}") unless response.code == "200"

          seq = Integer(response["Aspace-Seq"] || "-1", 10)
          frames = HttpChannel.decode_batch((response.body || "").b)
          # A batch already delivered comes again when an ack was lost.
          if seq == ack + 1
            frames.each { |frame| @inbound << frame }
            ack = seq
          end
        rescue *FAILURES, ArgumentError
          return if @closed

          failing_since ||= monotonic
          return finish("download idle timeout") if monotonic - failing_since > @idle

          client = drop(client)
          sleep 0.5
        end
      end
    ensure
      drop(client)
    end

    def drop(client)
      client&.finish if client&.started?
      nil
    rescue IOError, SystemCallError
      nil
    end

    def monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  # Dials http and https seeds; the exchange path defaults to /aspace/h.
  class HttpDialer < Dialer
    DEFAULT_PATH = "/aspace/h"

    def initialize(long_poll: 25, idle_timeout: 60, tls_dialer: TlsDialer.new(require_attested: false))
      super()
      @long_poll = long_poll
      @idle = idle_timeout
      @tls = tls_dialer
    end

    def schemes = %w[http https]

    def open(seed, identity:, timeout: 10)
      base = URI("#{seed.scheme}://#{seed.authority}#{seed.path || DEFAULT_PATH}")
      credentials = seed.scheme == "https" ? @tls.credentials(identity) : nil
      response = Dialer.within(timeout) do |remaining|
        HttpChannel.client(base, timeout, credentials, open_timeout: remaining)
                   .request(Net::HTTP::Post.new(URI("#{base}/open")))
      end
      location = response["Location"]
      raise IOError, "#{base}/open answered #{response.code}" unless response.code == "201" && location

      HttpChannel.new(URI.join("#{base}/open", location), seed, long_poll: @long_poll, idle_timeout: @idle,
                                                              tls: credentials)
    end
  end
end
