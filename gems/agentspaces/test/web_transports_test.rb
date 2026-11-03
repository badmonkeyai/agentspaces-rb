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
require "digest"

# The ws and http dialers (SPEC 5.5 and annex C) against in-process fakes of
# the listener side: the upgrade and its accept check, client masking at
# every length boundary, fragments with a ping between them, the close codes
# for a text message (1003), an oversize frame (1009), and a masked server
# frame (1002); the batch codec's limits, an upload repeated under the same
# Aspace-Seq when its answer is lost, a download batch delivered once when the
# server repeats it, the end of a session the server forgot (410), and a peer
# introducing itself over each binding.
class WebTransportsTest < Minitest::Test
  include AgentSpaces

  GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

  # One WebSocket listener connection at a time: answers the upgrade (or
  # misanswers it on request), records each client frame as [fin, opcode,
  # masked, payload], and writes raw server frames on request. With tls:
  # (an identity) it listens for wss behind that identity's channel
  # certificate; greeting: rides in the same write as the 101 answer.
  class FakeWs
    attr_reader :request_line, :frames

    def initialize(answer: :good, tls: nil, greeting: nil)
      @server = TCPServer.new("127.0.0.1", 0)
      @answer = answer
      @tls = tls
      @greeting = greeting
      @frames = Thread::Queue.new
      @ready = Thread::Queue.new
      @thread = Thread.new { serve }
      @thread.report_on_exception = false
    end

    def port = @server.addr[1]

    def seed(path = nil) = "#{@tls ? 'wss' : 'ws'}://127.0.0.1:#{port}#{path}"

    def wait_connected = @ready.pop

    def next_frame = Timeout.timeout(5) { @frames.pop }

    def write_raw(bytes) = @io.write(bytes)

    def self.frame(opcode, payload, fin: true, masked: false)
      head = [(fin ? 0x80 : 0) | opcode].pack("C")
      bit = masked ? 0x80 : 0
      length = payload.bytesize
      head << if length < 126 then [bit | length].pack("C")
              elsif length < 65_536 then [bit | 126, length].pack("Cn")
              else [bit | 127, length].pack("CQ>")
              end
      return head + payload.b unless masked

      head + "\x00\x00\x00\x00".b + payload.b
    end

    def close
      @thread.kill
      @io&.close
      @server.close
    end

    private

    def serve
      @io = @server.accept
      if @tls
        key, cert = AgentSpaces::ChannelCertificate.generate(@tls)
        context = OpenSSL::SSL::SSLContext.new
        context.min_version = OpenSSL::SSL::TLS1_3_VERSION
        context.cert = cert
        context.key = key
        # The fake asks for no client certificate: jruby-openssl ignores a
        # server verify_callback and would refuse the endorsed one.
        context.verify_mode = OpenSSL::SSL::VERIFY_NONE
        @io = OpenSSL::SSL::SSLSocket.new(@io, context).tap(&:accept)
      end
      @request_line = @io.gets
      headers = {}
      while (line = @io.gets) != "\r\n"
        name, value = line.split(":", 2)
        headers[name.strip.downcase] = value.strip
      end
      accept = [Digest::SHA1.digest(headers["sec-websocket-key"] + GUID)].pack("m0")
      case @answer
      when :good
        @io.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" \
                  "Sec-WebSocket-Accept: #{accept}\r\nSec-WebSocket-Protocol: aspace.1\r\n\r\n" +
                  (@greeting ? FakeWs.frame(0x2, @greeting) : "".b))
      when :wrong_accept
        @io.write("HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: AAAA\r\n" \
                  "Sec-WebSocket-Protocol: aspace.1\r\n\r\n")
      when :no_protocol
        @io.write("HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: #{accept}\r\n\r\n")
      when :refused
        @io.write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
      when :silent
        sleep
      end
      @ready << true
      loop { @frames << read_client_frame }
    end

    def read_client_frame
      first, second = @io.read(2).bytes
      length = second & 0x7F
      length = @io.read(2).unpack1("n") if length == 126
      length = @io.read(8).unpack1("Q>") if length == 127
      mask = second.anybits?(0x80) ? @io.read(4) : nil
      payload = length.zero? ? "".b : @io.read(length).b
      payload = AgentSpaces::WsChannel.mask(payload, mask) if mask
      [first.anybits?(0x80), first & 0x0F, !mask.nil?, payload]
    end
  end

  # An annex C listener: one session, frames uploaded per Aspace-Seq (a
  # repeated number is answered and not delivered again), a queue of server
  # batches for the long poll, and switches that lose the first upload's
  # answer, repeat the first download batch, or forget the session.
  class FakeExchange
    attr_reader :uploads, :seqs, :acks, :deleted, :lose_first_upload, :repeat_first_batch
    attr_accessor :gone

    def initialize(lose_first_upload: false, repeat_first_batch: false)
      @server = TCPServer.new("127.0.0.1", 0)
      @uploads = Thread::Queue.new
      @seqs = []
      @acks = []
      @batches = Thread::Queue.new
      @next_seq = 1
      @delivered_up = 0
      @deleted = false
      @gone = false
      @lose_first_upload = lose_first_upload
      @repeat_first_batch = repeat_first_batch
      @lock = Mutex.new
      @threads = []
      @acceptor = Thread.new { loop { conn = @server.accept; @threads << Thread.new { serve(conn) } } }
      @acceptor.report_on_exception = false
    end

    def port = @server.addr[1]

    def seed = "http://127.0.0.1:#{port}"

    def push(*frames) = @batches << frames

    def next_upload = Timeout.timeout(5) { @uploads.pop }

    def close
      @acceptor.kill
      @threads.each(&:kill)
      @server.close
    end

    private

    def serve(conn)
      while (line = conn.gets)
        verb, path, = line.split(" ")
        headers = {}
        while (header = conn.gets) != "\r\n"
          name, value = header.split(":", 2)
          headers[name.strip.downcase] = value.strip
        end
        body = headers["content-length"] ? conn.read(Integer(headers["content-length"])) : ""
        break unless answer(conn, verb, path, headers, body.b)
      end
    rescue IOError, SystemCallError
      nil
    ensure
      conn.close unless conn.closed?
    end

    def respond(conn, status, headers = {}, body = "".b)
      head = +"HTTP/1.1 #{status}\r\nContent-Length: #{body.bytesize}\r\n"
      headers.each { |k, v| head << "#{k}: #{v}\r\n" }
      conn.write(head + "\r\n", body)
      true
    end

    def answer(conn, verb, path, headers, body)
      return respond(conn, "410 Gone") if @gone && path.start_with?("/aspace/h/s/")

      case [verb, path]
      in ["POST", "/aspace/h/open"] then respond(conn, "201 Created", "Location" => "/aspace/h/s/sid-1")
      in ["POST", "/aspace/h/s/sid-1/up"]
        seq = Integer(headers["aspace-seq"])
        @lock.synchronize do
          @seqs << seq
          if seq == @delivered_up + 1
            AgentSpaces::HttpChannel.decode_batch(body).each { |frame| @uploads << frame }
            @delivered_up = seq
          end
        end
        if @lose_first_upload
          @lose_first_upload = false
          return false # the batch arrived, its answer is lost with the connection
        end
        respond(conn, "204 No Content")
      in ["GET", "/aspace/h/s/sid-1/down"]
        ack = Integer(headers["aspace-ack"])
        @lock.synchronize { @acks << ack }
        if @repeat_first_batch && ack == 1 && @first_batch
          @repeat_first_batch = false # as if the answer that carried it was lost
          return respond(conn, "200 OK", { "Aspace-Seq" => "1" }, AgentSpaces::HttpChannel.encode_batch(@first_batch))
        end
        @pending = nil if @pending && ack >= @pending[0]
        if @pending.nil?
          frames = begin
            Timeout.timeout(1) { @batches.pop }
          rescue Timeout::Error
            nil
          end
          return respond(conn, "204 No Content") if frames.nil?

          @pending = [@next_seq, frames]
          @first_batch ||= frames
          @next_seq += 1
        end
        seq, frames = @pending
        respond(conn, "200 OK", { "Aspace-Seq" => seq.to_s, "Content-Type" => AgentSpaces::HttpChannel::MEDIA_TYPE },
                AgentSpaces::HttpChannel.encode_batch(frames))
      in ["DELETE", "/aspace/h/s/sid-1"]
        @deleted = true
        respond(conn, "204 No Content")
      else respond(conn, "404 Not Found")
      end
    end
  end

  def setup
    @identity = Identity.generate
  end

  def ws_open(fake, path = nil)
    channel = WsDialer.new.open(Seed.parse(fake.seed(path)), identity: @identity, timeout: 5)
    fake.wait_connected
    channel
  end

  # ------------------------------------------------------------------ ws

  def test_upgrade_takes_the_default_path_and_round_trips_masked_frames
    fake = FakeWs.new
    channel = ws_open(fake)
    assert_equal "GET /aspace HTTP/1.1\r\n", fake.request_line
    [0, 1, 125, 126, 65_535, 65_536].each do |length|
      payload = Random.bytes(length).b
      channel.send_frame(payload)
      fin, opcode, masked, got = fake.next_frame
      assert fin
      assert_equal 0x2, opcode
      assert masked, "a client frame is always masked"
      assert_equal payload, got, "length #{length}"
      fake.write_raw(FakeWs.frame(0x2, payload))
      assert_equal payload, channel.read_frame, "server frame of #{length}"
    end
  ensure
    channel&.close
    fake&.close
  end

  # The 101 answer and the first frame arrive in one TLS record, so the
  # upgrade reader must serve bytes the TLS layer already holds.
  def test_wss_attests_the_listener_and_reads_a_frame_sent_with_the_answer
    listener = Identity.generate
    fake = FakeWs.new(tls: listener, greeting: "hello over wss".b)
    channel = ws_open(fake)
    assert_equal listener.peer_id, channel.attested_peer
    assert_equal "hello over wss", channel.read_frame
    channel.send_frame("back".b)
    assert_equal "back", fake.next_frame.last
  ensure
    channel&.close
    fake&.close
  end

  def test_a_seed_path_reaches_the_request_line
    fake = FakeWs.new
    channel = ws_open(fake, "/fleet/ws")
    assert_equal "GET /fleet/ws HTTP/1.1\r\n", fake.request_line
  ensure
    channel&.close
    fake&.close
  end

  def test_fragments_reassemble_around_a_ping_that_is_answered
    fake = FakeWs.new
    channel = ws_open(fake)
    fake.write_raw(FakeWs.frame(0x2, "one-", fin: false) + FakeWs.frame(0x9, "are you there") +
                   FakeWs.frame(0x0, "two-", fin: false) + FakeWs.frame(0x0, "three"))
    assert_equal "one-two-three", channel.read_frame
    fin, opcode, _, payload = fake.next_frame
    assert fin
    assert_equal [0xA, "are you there"], [opcode, payload]
  ensure
    channel&.close
    fake&.close
  end

  def test_text_oversize_and_masked_server_frames_close_with_their_codes
    { [0x1, "hello", false] => 1003, [0x2, "x", true] => 1002 }.each do |(opcode, payload, masked), code|
      fake = FakeWs.new
      channel = ws_open(fake)
      fake.write_raw(FakeWs.frame(opcode, payload, masked: masked))
      assert_raises(IOError) { channel.read_frame }
      _, close_opcode, _, body = fake.next_frame
      assert_equal [0x8, code], [close_opcode, body.unpack1("n")]
    ensure
      channel&.close
      fake&.close
    end
    fake = FakeWs.new
    channel = ws_open(fake)
    # Only the header: the length alone closes the channel, nothing is read past it.
    fake.write_raw([0x82, 127, Wire::MAX_FRAME_BYTES + 1].pack("CCQ>"))
    assert_raises(IOError) { channel.read_frame }
    _, close_opcode, _, body = fake.next_frame
    assert_equal [0x8, 1009], [close_opcode, body.unpack1("n")]
  ensure
    channel&.close
    fake&.close
  end

  def test_a_remote_close_ends_the_channel_and_is_answered
    fake = FakeWs.new
    channel = ws_open(fake)
    fake.write_raw(FakeWs.frame(0x8, [1001].pack("n")))
    assert_raises(EOFError) { channel.read_frame }
    _, opcode, _, body = fake.next_frame
    assert_equal [0x8, 1000], [opcode, body.unpack1("n")]
  ensure
    channel&.close
    fake&.close
  end

  def test_a_bad_upgrade_answer_is_refused
    %i[wrong_accept no_protocol refused].each do |answer|
      fake = FakeWs.new(answer: answer)
      assert_raises(IOError, answer.to_s) { WsDialer.new.open(Seed.parse(fake.seed), identity: @identity) }
    ensure
      fake&.close
    end
  end

  def test_a_silent_listener_times_the_upgrade_out
    fake = FakeWs.new(answer: :silent)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    assert_raises(IOError) { WsDialer.new.open(Seed.parse(fake.seed), identity: @identity, timeout: 1) }
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 3
  ensure
    fake&.close
  end

  def test_a_peer_introduces_itself_over_ws
    fake = FakeWs.new
    peer = Peer.new(@identity, "zRbWs")
    Thread.new { peer.connect(fake.seed) }.tap { |t| t.report_on_exception = false }
    fake.wait_connected
    _, _, _, frame = fake.next_frame
    env = Wire.decode_frame(frame)
    assert_equal @identity.peer_id, env["from"]
  ensure
    peer&.close
    fake&.close
  end

  # ---------------------------------------------------------------- http

  def test_the_batch_codec_round_trips_and_refuses_bad_bodies
    frames = ["a".b, ("b" * 300).b, Random.bytes(70_000).b]
    assert_equal frames, HttpChannel.decode_batch(HttpChannel.encode_batch(frames))
    assert_equal [], HttpChannel.decode_batch("".b)
    assert_raises(ArgumentError) { HttpChannel.decode_batch("\x00\x00\x00".b) }
    assert_raises(ArgumentError) { HttpChannel.decode_batch([0].pack("N")) }
    assert_raises(ArgumentError) { HttpChannel.decode_batch([10].pack("N") + "short") }
    assert_raises(ArgumentError) { HttpChannel.decode_batch([Wire::MAX_FRAME_BYTES + 1].pack("N")) }
    assert_raises(ArgumentError) { HttpChannel.decode_batch(([1].pack("N") + "x") * 65) }
    assert_equal 64, HttpChannel.decode_batch(([1].pack("N") + "x") * 64).size
    assert_raises(ArgumentError) { HttpChannel.encode_batch(["x"] * 65) }
  end

  def test_an_exchange_session_carries_frames_both_ways_and_deletes_on_close
    fake = FakeExchange.new
    channel = HttpDialer.new(long_poll: 2).open(Seed.parse(fake.seed), identity: @identity)
    %w[one two three].each { |f| channel.send_frame(f.b) }
    assert_equal %w[one two three], Array.new(3) { fake.next_upload }
    assert_equal fake.seqs.sort, fake.seqs, "Aspace-Seq rises"
    fake.push("down-1".b, "down-2".b)
    fake.push("down-3".b)
    assert_equal %w[down-1 down-2 down-3], Array.new(3) { channel.read_frame }
    sleep 0.3
    assert_includes fake.acks, 2, "the second batch is acknowledged"
    channel.close
    assert fake.deleted
    assert_raises(EOFError) { channel.read_frame }
  ensure
    fake&.close
  end

  def test_an_upload_whose_answer_is_lost_is_sent_again_under_the_same_number
    fake = FakeExchange.new(lose_first_upload: true)
    channel = HttpDialer.new(long_poll: 2).open(Seed.parse(fake.seed), identity: @identity)
    channel.send_frame("once".b)
    assert_equal "once", fake.next_upload
    channel.send_frame("next".b)
    assert_equal "next", fake.next_upload
    assert_equal [1, 1, 2], fake.seqs
    assert_raises(ThreadError) { fake.uploads.pop(true) } # "once" arrived once
  ensure
    channel&.close
    fake&.close
  end

  def test_a_repeated_download_batch_is_delivered_once
    fake = FakeExchange.new(repeat_first_batch: true)
    channel = HttpDialer.new(long_poll: 2).open(Seed.parse(fake.seed), identity: @identity)
    fake.push("first".b)
    assert_equal "first", channel.read_frame
    fake.push("second".b)
    assert_equal "second", channel.read_frame
    refute fake.repeat_first_batch, "the server did repeat the batch"
  ensure
    channel&.close
    fake&.close
  end

  def test_a_forgotten_session_ends_the_channel
    fake = FakeExchange.new
    channel = HttpDialer.new(long_poll: 1).open(Seed.parse(fake.seed), identity: @identity)
    fake.gone = true
    assert_raises(EOFError) { Timeout.timeout(5) { channel.read_frame } }
    assert_raises(IOError) { channel.send_frame("late".b) }
  ensure
    channel&.close
    fake&.close
  end

  def test_a_peer_introduces_itself_over_http
    fake = FakeExchange.new
    peer = Peer.new(@identity, "zRbHttp")
    Thread.new { peer.connect(fake.seed) }.tap { |t| t.report_on_exception = false }
    env = Wire.decode_frame(fake.next_upload)
    assert_equal @identity.peer_id, env["from"]
  ensure
    peer&.close
    fake&.close
  end

  def test_an_early_timeout_is_tried_again_and_a_late_one_raises
    calls = 0
    result = Dialer.within(10) do |remaining|
      calls += 1
      assert_operator remaining, :>, 9
      raise Errno::ETIMEDOUT if calls < 3

      :connected
    end
    assert_equal [:connected, 3], [result, calls]
    calls = 0
    assert_raises(Errno::ETIMEDOUT) do
      Dialer.within(0.2) do
        calls += 1
        sleep 0.15
        raise Errno::ETIMEDOUT
      end
    end
    assert_equal 1, calls, "a timeout past half the deadline is real"
  end

  def test_plain_web_seeds_to_a_remote_host_need_allow_plain
    %w[ws://10.1.2.3:7702 http://10.1.2.3:7702].each do |seed|
      error = assert_raises(ConfigError) { AgentSpaces.start(group: "g", founding: "f", seeds: [seed]) }
      assert_match(/allow_plain/, error.message)
    end
  end
end
