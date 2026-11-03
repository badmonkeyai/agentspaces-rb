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
require "pp"
require "tmpdir"

# ROBUSTNESS.md 6a at the socket: late, replayed, unknown, and malformed
# frames are the normal case and never stop the reader; a lost socket is a
# hiccup; the owner's close is final; a forked child never speaks on the
# parent's connection.
class RobustnessTest < Minitest::Test
  include AgentSpaces

  GROUP = "zRubyRobustness"

  # A peer whose sends are captured.
  class CapturingPeer < Peer
    attr_reader :sent

    def initialize
      super(AgentSpaces::Identity.generate, GROUP)
      @sent = []
    end

    private

    def send_frame(kind, body, to = nil) = @sent << [kind, body, to]
  end

  def frame(sender, kind, body, to, stamp)
    Wire.decode_frame(Wire.encode_frame(Wire.envelope(GROUP, kind, sender.peer_id, stamp, body, to), sender))
  end

  def stamp(ms, logical = 0) = "#{ms}:#{logical}:other"

  def kinds(peer) = peer.sent.map(&:first)

  def eventually(timeout = 5.0)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    sleep 0.05 until yield || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
    yield
  end

  def test_a_replayed_frame_is_dropped_and_counted
    peer = CapturingPeer.new
    other = Identity.generate
    now = peer.now_ms
    ping = frame(other, "PING", Wire.ping_body(7), peer.identity.peer_id, stamp(now, 1))
    peer.handle(ping)
    assert_equal ["ACK"], kinds(peer)
    2.times { peer.handle(ping) }
    assert_equal ["ACK"], kinds(peer), "a replayed probe earns no second ACK"
    assert_equal 2, peer.frames.replayed
    peer.handle(frame(other, "PING", Wire.ping_body(8), peer.identity.peer_id, stamp(now, 2)))
    assert_equal %w[ACK ACK], kinds(peer)
  end

  def test_stale_and_far_ahead_frames_are_dropped_quietly
    peer = CapturingPeer.new
    other = Identity.generate
    now = peer.now_ms
    peer.handle(frame(other, "PING", Wire.ping_body(1), peer.identity.peer_id,
                      stamp(now - Wire::MAX_FRAME_AGE_MILLIS - 1000)))
    peer.handle(frame(other, "PING", Wire.ping_body(2), peer.identity.peer_id,
                      stamp(now + Wire::MAX_HLC_SKEW_MILLIS + 60_000)))
    assert_empty peer.sent
    assert_equal [1, 1], [peer.frames.stale, peer.frames.ahead]
    peer.handle(frame(other, "PING", Wire.ping_body(3), peer.identity.peer_id, stamp(now - (Wire::MAX_FRAME_AGE_MILLIS / 2))))
    peer.handle(frame(other, "PING", Wire.ping_body(4), peer.identity.peer_id, stamp(now + (Wire::MAX_HLC_SKEW_MILLIS / 2))))
    assert_equal %w[ACK ACK], kinds(peer)
  end

  def test_kinds_this_peer_does_not_speak_are_ignored_and_counted
    peer = CapturingPeer.new
    other = Identity.generate
    now = peer.now_ms
    %w[HAVE GRAFT PRUNE BATCH DIGEST CHANNEL_HELLO].each_with_index do |kind, i|
      peer.handle(frame(other, kind, CBOR.dump({ "anything" => i }), peer.identity.peer_id, stamp(now, i)))
    end
    assert_empty peer.sent
    assert_equal 6, peer.ignored_kinds.values.sum
    assert_equal 1, peer.ignored_kinds["HAVE"]
    peer.handle(frame(other, "PING", Wire.ping_body(9), peer.identity.peer_id, stamp(now, 99)))
    assert_equal ["ACK"], kinds(peer), "still answering afterwards"
  end

  def test_a_malformed_body_under_a_good_signature_never_corrupts_state
    peer = CapturingPeer.new
    other = Identity.generate
    now = peer.now_ms
    %w[RUMOR PULL_RESP PING PIPE_DATA].each_with_index do |kind, i|
      peer.handle(frame(other, kind, "\xFF\x01\x02".b, peer.identity.peer_id, stamp(now, i)))
    rescue StandardError
      nil # the reader catches this per frame
    end
    assert_empty peer.states
    assert_empty peer.claims
    peer.handle(frame(other, "PING", Wire.ping_body(5), peer.identity.peer_id, stamp(now, 50)))
    assert_equal ["ACK"], kinds(peer)
  end

  def test_a_hostile_length_prefix_drops_the_connection_and_the_peer_reconnects
    seed = Testing::FakeSeed.new
    peer = Peer.new(Identity.generate, GROUP)
    peer.reconnect_interval = 0.1
    peer.connect("127.0.0.1", seed.port)
    assert eventually { seed.kinds(0).size >= 2 }
    seed.connections[0].write([Wire::MAX_FRAME_BYTES + 1].pack("N"))
    assert eventually { peer.reconnects == 1 }
    assert eventually { seed.kinds(1).first == "RUMOR" }
  ensure
    peer&.close
    seed&.close
  end

  def test_a_lost_socket_is_reconnected_and_the_peer_reintroduces_and_repulls
    seed = Testing::FakeSeed.new
    peer = Peer.new(Identity.generate, GROUP)
    peer.reconnect_interval = 0.1
    peer.connect("127.0.0.1", seed.port)
    peer.pull_space("work")
    assert eventually { seed.kinds(0).size >= 3 }
    assert_equal %w[RUMOR DIGEST DIGEST], seed.kinds(0)
    seed.drop(0)
    assert eventually { seed.kinds(1).size >= 3 }
    assert_equal %w[RUMOR DIGEST DIGEST], seed.kinds(1).first(3)
    assert_equal 1, peer.reconnects
    assert peer.connected?
  ensure
    peer&.close
    seed&.close
    refute peer.running?
  end

  def test_close_by_the_owner_is_final
    seed = Testing::FakeSeed.new
    peer = Peer.new(Identity.generate, GROUP)
    peer.reconnect_interval = 0.1
    peer.connect("127.0.0.1", seed.port)
    sleep 0.2
    peer.close
    sleep 0.5
    assert_equal 1, seed.connections.size, "no reconnect after the owner's close"
    assert_equal 0, peer.reconnects
  ensure
    seed&.close
  end

  def test_a_seed_that_is_down_is_retried_until_it_listens_again
    seed = Testing::FakeSeed.new
    port = seed.port
    peer = Peer.new(Identity.generate, GROUP)
    peer.reconnect_interval = 0.1
    peer.connect("127.0.0.1", port)
    assert eventually { seed.kinds.size >= 2 }
    seed.close
    sleep 0.3
    assert_equal 0, peer.reconnects
    again = Testing::FakeSeed.new(port)
    assert eventually { again.kinds.size >= 2 }
    assert_equal %w[RUMOR DIGEST], again.kinds.first(2)
    assert_equal 1, peer.reconnects
  ensure
    peer&.close
    again&.close
  end

  def test_connect_any_fails_over_and_names_every_seed_that_refused
    dead = TCPServer.new("127.0.0.1", 0)
    dead_port = dead.addr[1]
    dead.close
    peer = Peer.new(Identity.generate, GROUP)
    error = assert_raises(NoSeedError) { peer.connect_any(["127.0.0.1:#{dead_port}", "dtls://127.0.0.1:1"]) }
    assert_match(/127.0.0.1:#{dead_port}: ECONNREFUSED/, error.message)
    seed = Testing::FakeSeed.new
    chosen = peer.connect_any(["127.0.0.1:#{dead_port}", "quic://127.0.0.1:2", seed.seed])
    assert_equal seed.port, chosen.port
  ensure
    peer&.close
    seed&.close
  end

  def test_a_forked_child_never_speaks_on_the_parents_connection
    skip "JRuby cannot fork" unless Process.respond_to?(:fork) && RUBY_ENGINE != "jruby"
    seed = Testing::FakeSeed.new
    peer = Peer.new(Identity.generate, GROUP)
    peer.connect("127.0.0.1", seed.port)
    assert eventually { seed.kinds(0).size >= 2 }
    before = seed.kinds(0).size
    reader, writer = IO.pipe
    pid = fork do
      reader.close
      outcome = begin
        peer.write_entry("tasks", "com.acme.Task#v1", { "topic" => "from the child" })
        "wrote"
      rescue ForkError => e
        e.message
      end
      writer.write(outcome)
      writer.close
      exit!(0)
    end
    writer.close
    Process.wait(pid)
    outcome = reader.read
    assert_match(/started in process #{Process.pid}.*AgentSpaces.after_fork/, outcome)
    sleep 0.2
    assert_equal before, seed.kinds(0).size, "the child sent nothing on the inherited socket"
    assert peer.connected?, "the parent's connection survives the child"
    peer.write_entry("tasks", "com.acme.Task#v1", { "topic" => "from the parent" })
    assert eventually { seed.kinds(0).size == before + 1 }
  ensure
    peer&.close
    seed&.close
  end

  def test_the_peer_re_leases_its_self_advertisement
    seed = Testing::FakeSeed.new
    peer = Peer.new(Identity.generate, GROUP)
    peer.peer_ad_interval = 0.3
    peer.connect("127.0.0.1", seed.port)
    assert eventually(3) { seed.kinds(0).count("RUMOR") >= 3 }
  ensure
    peer&.close
    seed&.close
  end

  def test_doctor_runs_every_primitive_and_names_the_library
    report = Crypto.doctor
    assert_match(/OpenSSL/, report["openssl"])
    assert_includes report["checks"], "Ed25519"
  end

  def test_identities_never_print_their_keys
    identity = Identity.generate
    agent = identity.renewing_subordinate("x", "PT1H")
    [identity.inspect, identity.to_s, agent.inspect, PP.pp(identity, +"")].each do |text|
      refute_includes text, identity.pkcs8.unpack1("H*")
      refute_match(/@private/, text)
    end
  end

  def test_the_keystore_matches_javas_layout_and_refuses_damage
    Dir.mktmpdir do |dir|
      identity = Identity.load_or_create(dir)
      assert_equal 0o600, File.stat(File.join(dir, "peer.key")).mode & 0o777
      assert_equal 32, File.binread(File.join(dir, "peer.pub")).bytesize
      assert_equal identity.peer_id, Identity.load_or_create(dir).peer_id
      File.chmod(0o644, File.join(dir, "peer.key"))
      error = assert_raises(ArgumentError) { Identity.load_or_create(dir) }
      assert_match(/readable by group or others/, error.message)
      File.chmod(0o600, File.join(dir, "peer.key"))
      File.binwrite(File.join(dir, "peer.pub"), Identity.generate.public_raw)
      assert_raises(ArgumentError) { Identity.load_or_create(dir) }
      agent = Identity.agent_keys(dir, identity.peer_id, "worker")
      assert File.exist?(File.join(dir, identity.peer_id, "worker", "agent.key"))
      assert_equal agent.peer_id, Identity.agent_keys(dir, identity.peer_id, "worker").peer_id
      assert_raises(ArgumentError) { Identity.agent_keys(dir, "..", "worker") }
    end
  end
end
