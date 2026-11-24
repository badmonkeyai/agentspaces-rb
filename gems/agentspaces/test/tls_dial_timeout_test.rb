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

# The TLS dial honours its timeout through the handshake, not only the TCP
# connect (Round 2b part 1 review). Seeds are dialled concurrently, so a seed
# whose kernel accepts the connection but that never answers the handshake
# must not keep a dial thread and its socket for ever on each round.
class TlsDialTimeoutTest < Minitest::Test
  include AgentSpaces

  def setup
    @server = TCPServer.new("127.0.0.1", 0)
    @accepted = Thread::Queue.new
    @acceptor = Thread.new do
      loop { @accepted << @server.accept } # accepts and never speaks
    rescue IOError, SystemCallError
      nil
    end
  end

  def teardown
    @server.close
    @acceptor.join(1)
    @accepted.close
    while (socket = @accepted.pop(timeout: 0))
      socket.close
    end
  end

  def seed = Seed.parse("tls://127.0.0.1:#{@server.addr[1]}")

  def test_a_handshake_that_never_answers_ends_at_the_dial_timeout_and_closes_its_socket
    dialer = TlsDialer.new
    outcome = Thread::Queue.new
    dial = Thread.new do
      dialer.open(seed, identity: Identity.generate, timeout: 0.3)
      outcome << :opened
    rescue StandardError => e
      outcome << e
    end
    result = outcome.pop(timeout: 3)
    dial.kill
    refute_nil result, "the handshake hung past ten times its timeout"
    assert_kind_of IOError, result, "a handshake timeout is a refusal the round expects"
    assert_match(/no TLS answer/, result.message)
    server_side = @accepted.pop(timeout: 1)
    refute_nil server_side
    assert closed_by_dialler?(server_side), "the dial closed its socket when it gave up"
  end

  # Reads past the ClientHello to the end of the stream, within a second.
  def closed_by_dialler?(socket)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 1
    loop do
      left = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      return false unless left.positive? && socket.wait_readable(left)

      chunk = socket.read_nonblock(4096, exception: false)
      return true if chunk.nil?
    end
  rescue IOError, SystemCallError
    true
  end
end
