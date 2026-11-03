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

require "socket"
require "timeout"

module AgentSpaces
  # A seed the peer dials: scheme, host, port, and for ws and http an
  # optional path. Parses "host:port", "tcp://host:port", "tls://host:port",
  # "ws://host:port/aspace", and [host, port] pairs.
  Seed = Data.define(:scheme, :host, :port, :path) do
    def initialize(scheme:, host:, port:, path: nil) = super

    def self.parse(value, default_port: 7500)
      return value if value.is_a?(Seed)
      return new(scheme: "tcp", host: value[0].to_s, port: Integer(value[1])) if value.is_a?(Array)

      text = value.to_s.strip
      scheme = "tcp"
      if (m = text.match(%r{\A([a-z][a-z0-9+.-]*)://(.+)\z}))
        scheme = m[1]
        text = m[2]
      end
      path = nil
      if (slash = text.index("/"))
        path = text[slash..]
        text = text[0...slash]
      end
      host, port = if text.start_with?("[")
                     close = text.index("]")
                     raise ArgumentError, "bad seed #{value.inspect}" if close.nil?

                     [text[1...close], text[(close + 2)..]]
                   elsif text.count(":") == 1
                     text.split(":", 2)
                   else
                     [text, nil]
                   end
      raise ArgumentError, "bad seed #{value.inspect}" if host.nil? || host.empty?

      new(scheme: scheme, host: host, port: port.nil? || port.empty? ? default_port : Integer(port, 10), path: path)
    end

    def authority = "#{host.include?(':') ? "[#{host}]" : host}:#{port}"

    def to_s = "#{scheme}://#{authority}#{path}"
  end

  # One connection that carries whole frames. The stream bindings frame each
  # one with a 4-byte big-endian length (SPEC 9).
  class FrameChannel
    attr_reader :remote

    def initialize(io, remote)
      @io = io
      @remote = remote
      @send_lock = Mutex.new
    end

    def send_frame(frame)
      raise ArgumentError, "frame of #{frame.bytesize} bytes exceeds the cap" if frame.bytesize > Wire::MAX_FRAME_BYTES

      @send_lock.synchronize { @io.write([frame.bytesize].pack("N"), frame) }
    end

    # The next frame, or EOFError when the remote closed. A length outside
    # (0, MAX_FRAME_BYTES] cannot be resynchronized and ends the channel.
    def read_frame
      header = read_exact(4)
      length = header.unpack1("l>")
      raise IOError, "bad frame length #{length}" if length <= 0 || length > Wire::MAX_FRAME_BYTES

      read_exact(length)
    end

    def close
      @io.close unless @io.closed?
    rescue IOError, SystemCallError
      nil
    end

    def closed? = @io.closed?

    # Closes this process's descriptor without a word to the remote: what a
    # forked child does with a connection it inherited.
    def abandon = close

    def attested_peer = nil

    private

    def read_exact(count)
      data = @io.read(count)
      raise EOFError, "connection closed" if data.nil? || data.bytesize < count

      data.b
    end
  end

  # Opens FrameChannels for the schemes it serves.
  class Dialer
    EARLY_TIMEOUTS = [Errno::ETIMEDOUT, IO::TimeoutError, Timeout::Error].freeze

    def schemes = []

    def open(seed, identity:, timeout: 10) = raise(NotImplementedError)

    # A TCP socket to host:port with Nagle off. Ruby 3.4 made Happy Eyeballs
    # v2 the default; the peer dials literal addresses in its own order, so
    # the fallback is off where it exists.
    def self.tcp(host, port, timeout)
      fast_fallback = Socket.method(:tcp).parameters.any? { |_, name| name == :fast_fallback }
      socket = within(timeout) do |remaining|
        Socket.tcp(host, port, connect_timeout: remaining, **(fast_fallback ? { fast_fallback: false } : {}))
      end
      socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
      socket
    end

    # Runs the block with the time left, again when it times out early. On
    # JRuby 10.1 a connect with a timeout fails at once about one time in a
    # hundred on loopback (ETIMEDOUT after a millisecond); a timeout that
    # comes before half the deadline is that fault and is tried again.
    def self.within(timeout)
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      attempts = 0
      begin
        attempts += 1
        yield [timeout - (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started), 0.001].max
      rescue *EARLY_TIMEOUTS
        early = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started < timeout / 2.0
        retry if early && attempts < 5
        raise
      end
    end
  end

  # The tcp binding: length-prefixed frames over a socket, every frame signed.
  class TcpDialer < Dialer
    def schemes = ["tcp"]

    def open(seed, identity: nil, timeout: 10) = FrameChannel.new(Dialer.tcp(seed.host, seed.port, timeout), seed)
  end
end
