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

require "agentspaces"
require "socket"

module AgentSpaces
  # Test support (SRAD RB-T-04): a pinned clock, an in-memory network of
  # peers wired without sockets, and a fake seed over real TCP.
  module Testing
    # A pinned clock in milliseconds; advance moves it. Callable as a Peer clock.
    class TestClock
      attr_reader :millis

      def initialize(millis = (Time.now.to_f * 1000).to_i)
        @millis = millis
        @lock = Mutex.new
      end

      def call = @lock.synchronize { @millis / 1000.0 }

      def advance(millis) = @lock.synchronize { @millis += Integer(millis) }

      def to_proc = method(:call).to_proc
    end

    # Peers by id: an addressed frame goes to its peer, a rumor to every other.
    class Network
      attr_reader :peers

      def initialize
        @peers = {}
      end

      def add(peer)
        @peers[peer.identity.peer_id] = peer
        peer
      end

      # n peers of one group that have introduced themselves to each other.
      def self.fleet(group, count, clock: nil)
        network = new
        peers = Array.new(count) { NetPeer.new(network, group, clock: clock) }
        peers.each(&:introduce)
        peers
      end
    end

    # A peer of a Network: sends are delivered in-process, and a rumor of its
    # own folds here as well (gossip hands it back to us).
    class NetPeer < Peer
      def initialize(network, group, clock: nil, identity: nil)
        super(identity || Identity.generate, group, clock: clock)
        @network = network
        @running = true
        network.add(self)
      end

      def connected? = !closed?

      def pull_space(_space) = nil

      def pull_revocations = nil

      private

      def send_frame(kind, body, to = nil)
        env = Wire.envelope(group, kind, identity.peer_id, Wire.hlc_now(identity.peer_id, now_ms), body, to)
        targets = to ? [@network.peers[to]].compact : @network.peers.reject { |id, _| id == identity.peer_id }.values
        targets.each { |target| target.handle(env) if !target.closed? && target.accepts?(env) }
        return unless kind == "RUMOR" && to.nil?

        rumor = CBOR.load(body)
        return unless rumor["streamId"].to_s.start_with?("space:")

        delta = CBOR.load(rumor["payload"])
        fold_claim(delta["claimEntry"], delta["claim"]) if delta["claimEntry"] && delta["claim"].is_a?(Hash)
        fold_state(delta["state"]) if delta["state"].is_a?(Hash)
      end
    end

    # A seed over real TCP that records the frames it receives, per
    # connection, and can drop a connection, for tests of the reconnect path.
    class FakeSeed
      attr_reader :port, :connections

      def initialize(port = 0)
        @server = TCPServer.new("127.0.0.1", port)
        @port = @server.addr[1]
        @log = []
        @lock = Mutex.new
        @connections = []
        @running = true
        @thread = Thread.new { accept_loop }
        @thread.report_on_exception = false
      end

      def seed = "127.0.0.1:#{@port}"

      # Every verified envelope received so far, in arrival order.
      def received = @lock.synchronize { @log.map(&:last) }

      # The kinds received, on one connection (by index) or on all.
      def kinds(connection = nil)
        @lock.synchronize do
          @log.select { |index, _| connection.nil? || index == connection }.map { |_, env| env["kind"] }
        end
      end

      def send_to_last(frame)
        io = @connections.last
        io.write([frame.bytesize].pack("N"), frame)
      end

      def drop(index) = @connections[index]&.close

      def drop_connections = @connections.each { |c| c.close unless c.closed? }

      def close
        @running = false
        # JRuby keeps a listener blocked in accept open after close, so the
        # accept thread stops first.
        @thread.kill
        @thread.join(1)
        @server.close unless @server.closed?
        drop_connections
      end

      private

      def accept_loop
        while @running
          io = @server.accept
          unless @running
            io.close
            break
          end
          index = @connections.size
          @connections << io
          reader = Thread.new { read_loop(io, index) }
          reader.report_on_exception = false
        end
      rescue IOError, SystemCallError
        nil
      end

      def read_loop(io, index)
        loop do
          header = io.read(4)
          break if header.nil? || header.bytesize < 4

          frame = io.read(header.unpack1("N"))
          break if frame.nil?

          env = Wire.decode_frame(frame)
          @lock.synchronize { @log << [index, env] } if env
        end
      rescue IOError, SystemCallError
        nil
      end
    end
  end
end
