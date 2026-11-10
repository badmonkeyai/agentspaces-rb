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

# HLC round seven, 2026-11-08: the gaps SPEC §9.3 left after round six, as
# they bind this client, settled by the reference rule (Java's behaviour
# unless it breaks F1 or F3).
#
# 1. A bignum holds at most 1000 bytes, alone or as a decimal's mantissa (S9).
# 5. A stamp is one definite text of at most 3996 UTF-16 units: a longer text
#    travels only in Jackson's chunks and is no stamp, a pdt.issued included,
#    and a clock's node leaves room for the longest physical and logical parts.
# 6. The aggregate, semantic-discovery and Raft pipe payloads decode under
#    their SPEC annex I schemas and the canonical-bytes rule, as Java's
#    fromWire reads them; a double field takes any float64.
# 7. The vector copy is byte for byte the shared file.
# 8. A beacon document that carries a signature arrives as exactly its
#    canonical JSON (the beacon-document vectors).

require_relative "test_helper"

class HlcRoundSevenTest < Minitest::Test
  include AgentSpaces

  VECTORS_FILE = File.join(__dir__, "wire-encoding-vectors.json")
  SHARED = File.expand_path("../../../../agentspaces/tools/wire-encoding/vectors.json", __dir__)
  PREFIX = "1800000000000:0:"

  def test_the_vector_copy_is_the_shared_file_byte_for_byte
    skip "the shared file lives in the agentspaces checkout" unless File.exist?(SHARED)
    assert_equal File.binread(SHARED), File.binread(VECTORS_FILE)
  end

  # 1 ------------------------------------------------------------------------

  def test_the_codec_reads_and_writes_no_bignum_past_1000_bytes
    widest = (1 << 7991) + 1
    assert_equal 1004, CBOR.dump(widest).bytesize
    assert_equal widest, CBOR.load(CBOR.dump(widest))
    [1 << 7999, -(1 << 7999), BigDecimal("#{(1 << 7999) + 1}e-1")].each do |value|
      assert_raises(CBOR::Error) { CBOR.dump(value) }
    end
    assert_raises(CBOR::Error) { CBOR.load(["c25903e901#{'11' * 1000}"].pack("H*")) }
    assert_raises(CBOR::Error) { CBOR.load(["c48220c25903e901#{'11' * 1000}"].pack("H*")) }
    # the decoder stops at the bignum's head, before it reads the magnitude or the item after it
    error = assert_raises(CBOR::Error) { CBOR.load(["82c25903e901#{'11' * 1000}ff"].pack("H*")) }
    assert_match(/bignum magnitude passes 1000 bytes/, error.message)
  end

  # 5 ------------------------------------------------------------------------

  def test_a_stamp_past_3996_utf16_units_is_no_stamp
    edge = PREFIX + ("n" * (3996 - PREFIX.size))
    refute_nil Wire.hlc_decode(edge)
    assert_nil Wire.hlc_decode("#{edge}n")
    pairs = PREFIX + ("\u{1F600}" * ((3996 - PREFIX.size) / 2))
    refute_nil Wire.hlc_decode(pairs)
    assert_nil Wire.hlc_decode("#{pairs}n")
    assert_nil Wire.hlc_decode(CBOR.load(CBOR.dump("#{edge}n")))
  end

  def test_a_clock_refuses_a_node_that_could_carry_a_stamp_past_3996_units
    longest = "n" * 3965
    assert_equal 3996, "#{(1 << 63) - 1}:#{(1 << 31) - 1}:#{longest}".size
    assert Wire.hlc_now(longest, 1_800_000_000_000).end_with?(longest)
    assert_raises(ArgumentError) { Wire.hlc_now("#{longest}n", 1_800_000_000_000) }
  end

  # 6 ------------------------------------------------------------------------

  # Capability pipes that hand a test the handler and keep what the capability sends.
  class StubPipes
    Identity = Struct.new(:peer_id)
    Peer = Struct.new(:identity, :ads) do
      def now_ms = 1_800_000_000_000
    end

    attr_reader :peer, :handlers, :sent

    def initialize
      @peer = Peer.new(Identity.new("zSelf"), {})
      @handlers = {}
      @sent = []
    end

    def on_capability(type, handler = nil, &block) = @handlers[type] = handler || block
    def send_pipe(_to, _type, payload, via: nil) = @sent << [payload, via]
    def members = []
  end

  def frame(**variant)
    CBOR.dump({ "share" => nil, "extremum" => nil, "histogram" => nil, "roster" => nil }
                .merge(variant.transform_keys(&:to_s)))
  end

  def aggregate_hears?(payload)
    pipes = StubPipes.new
    aggregate = Capabilities::Aggregate.new(pipes, advertise: false)
    pipes.handlers["aspace:cap/aggregate"].call("zPeer", payload)
    aggregate.exchanged
  end

  def test_an_aggregate_frame_decodes_under_its_schema_a_nan_extremum_included
    assert aggregate_hears?(frame(extremum: { "epochId" => "e", "max" => true, "value" => Float::NAN }))
    assert aggregate_hears?(frame(share: { "epochId" => "e", "value" => 1.0, "weight" => 0.5 }))
    assert aggregate_hears?(frame(roster: { "epochId" => "e", "members" => [-5, 7] }))
    refute aggregate_hears?(frame(share: { "epochId" => "e", "value" => 1, "weight" => 0.5 }))
    refute aggregate_hears?(frame(share: { "epochId" => "e", "value" => CBOR::Float32.new(1.0), "weight" => 0.5 }))
    refute aggregate_hears?(frame(share: { "epochId" => "e", "value" => 1.0, "weight" => 0.5, "x" => 1 }))
    refute aggregate_hears?(frame(roster: { "epochId" => "e", "members" => [1.0] }))
    refute aggregate_hears?(CBOR.dump({ "share" => { "epochId" => "e", "value" => 1.0, "weight" => 0.5 } }))
  end

  def test_a_semantic_query_decodes_under_its_schema
    pipes = StubPipes.new
    Capabilities::Semantic.new(pipes)
    hear = pipes.handlers["aspace:cap/semantic-discovery"]
    hear.call("zPeer", CBOR.dump({ "nonce" => 3, "text" => "tasks", "limit" => 4 }))
    assert_equal 1, pipes.sent.size
    [{ "nonce" => 3, "text" => "tasks", "limit" => 4.0 }, { "nonce" => "3", "text" => "tasks", "limit" => 4 },
     { "nonce" => 3, "text" => "tasks", "limit" => 4, "x" => 1 },
     { "text" => "tasks", "nonce" => 3, "limit" => 4 }].each { |relabel| hear.call("zPeer", CBOR.dump(relabel)) }
    assert_equal 1, pipes.sent.size
  end

  def test_a_raft_frame_decodes_under_its_schema
    ordered = Capabilities::OrderedLog
    assert_equal({ "clientSubmit" => { "command" => "cmd".b } },
                 ordered.parse_frame(ordered.client_submit_frame("cmd".b)))
    vote = { "term" => 2, "candidate" => "zPeer", "lastLogIndex" => 0, "lastLogTerm" => 0 }
    assert_equal({ "requestVote" => vote }, ordered.parse_frame(ordered.raft_frame(requestVote: vote)))
    assert_nil ordered.parse_frame(ordered.raft_frame(requestVote: vote.merge("term" => 2.0)))
    assert_nil ordered.parse_frame(CBOR.dump({ "clientSubmit" => { "command" => "cmd".b } }))
    assert_nil ordered.parse_frame(ordered.raft_frame(clientSubmit: { "command" => "cmd" }))
  end

  def test_a_take_claim_keeps_its_finite_bid_while_a_double_field_takes_any_float64
    Schema.check("PushSumAggregate.Extremum", { "epochId" => "e", "max" => false, "value" => Float::INFINITY })
    claim = { "entryId" => "e", "spaceId" => "s", "epoch" => 1, "stamp" => "1:0:n", "holder" => "zPeer/w",
              "bid" => Float::NAN, "expiresAtMillis" => 5 }
    assert_raises(Schema::Error) { Schema.check("TakeClaim", claim) }
    Schema.check("TakeClaim", claim.merge("bid" => -0.0))
  end

  # 8 ------------------------------------------------------------------------

  def test_every_beacon_vector_reads_exactly_as_its_verdict_says
    beacons = JSON.parse(File.read(VECTORS_FILE)).fetch("vectors").select { |v| v["carrier"] == "beacon-document" }
    assert_equal 40, beacons.size
    beacons.each do |v|
      body = [v["hex"]].pack("H*")
      if v["verdict"] == "accept"
        signer = Beacon.verify_document(Beacon.parse_document(body), allow_unsigned: true)
        v["signer"].nil? ? assert_nil(signer, v["id"]) : assert_equal(v["signer"], signer, v["id"])
      else
        assert_raises(Beacon::Error, "#{v['id']}: #{v['why']}") do
          Beacon.verify_document(Beacon.parse_document(body), allow_unsigned: true)
        end
      end
    end
  end
end
