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

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__), File.expand_path("../../agentspaces/lib", __dir__))
require "minitest/autorun"
require "socket"
require "agentspaces/jruby"

module JLedger
  Line = AgentSpaces::Entry.define("rbjr.ledger.Line#v1", line_id: String, memo: String)
end

# Replication by entry against the Java node (SPEC v0.1.35 annex I.6;
# srad/replication-by-entry.md RE-L-03): a Java node on wire.ae=2 holds a
# space larger than the budget a pure-Ruby peer asks for, and the Ruby peer
# joins it by budgeted get-spaces, continued with its own text digest while
# the answers' remainder says states were left out. The Java node reads the
# Ruby digest's lines, so it answers only what the Ruby replica lacks, and
# the Ruby peer advertises wire.horizon=1, which the Java node reads.
class BudgetInteropTest < Minitest::Test
  FOUNDING = "rbjr-ledger-v1"
  LINES = 60

  def free_port
    server = TCPServer.new("127.0.0.1", 0)
    server.addr[1]
  ensure
    server&.close
  end

  def eventually(timeout = 30)
    deadline = Time.now + timeout
    sleep 0.1 until (value = yield) || Time.now > deadline
    value || yield
  end

  def test_a_ruby_peer_joins_a_java_space_by_budgeted_pulls_and_continuations
    port = free_port
    node = AgentSpaces::JRuby::Fleet.start(
      "security" => { "profile" => "dev-local" }, "bind" => "127.0.0.1:#{port}", "tick-millis" => 100,
      "groups" => [{ "name" => "ledger", "founding" => FOUNDING, "seeds" => [], "spaces" => ["lines"] }]
    )
    LINES.times { |i| node.write("lines", JLedger::Line.new(line_id: "l-#{i}", memo: "m" * 400), lease: "1h") }

    peer = AgentSpaces::Peer.new(AgentSpaces::Identity.generate, AgentSpaces::Derive.group_id_from_founding(FOUNDING))
    peer.pull_budget = 4096
    peer.connect("127.0.0.1:#{port}")
    # The Java node's card, with wire.ae=2, reaches the peer on the peers stream.
    assert eventually { peer.send(:budgeted_partner?) }, "the Java node's card carries wire.ae=2"
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    peer.pull_space("lines")
    lines = peer.space("lines")
    assert eventually { lines.all(JLedger::Line, limit: 1000).size == LINES }, "every line arrives"
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    puts format("budgeted join: %<n>d lines, %<c>d continuations, %<s>.2f s", n: LINES, c: peer.pull_continuations,
                                                                             s: elapsed)
    assert_operator peer.pull_continuations, :>=, 5, "a 4 KiB budget cannot carry about 30 KB in one answer"
    assert_equal 0, peer.pulls_stalled
    assert_equal LINES, peer.states.size
    # The Java space reads the Ruby peer's wire.horizon=1: with every member of
    # its view hinted, it leaves the legacy mode and counts rounds to engage.
    space = node.java_space("lines")
    peer.space("lines").write(JLedger::Line.new(line_id: "hinted", memo: "m"), lease: "1h")
    assert eventually(10) { space.horizonMode.to_s != "LEGACY" }, "the Java node counts the Ruby peer as hinted"
    # A Ruby peer on the legacy setting advertises no hint, and the Java node
    # disengages at its next judgement, which a write it merges brings.
    legacy = AgentSpaces::Peer.new(AgentSpaces::Identity.generate, AgentSpaces::Derive.group_id_from_founding(FOUNDING),
                                   horizon: :legacy)
    legacy.connect("127.0.0.1:#{port}")
    assert eventually(10) {
      legacy.space("lines").write(JLedger::Line.new(line_id: "legacy-#{rand(1 << 30)}", memo: "m"), lease: "1h")
      space.horizonMode.to_s == "LEGACY"
    }, "a member without wire.horizon=1 in view disengages the Java node's per-entry horizon"
  ensure
    legacy&.close
    peer&.close
    node&.close
  end
end
