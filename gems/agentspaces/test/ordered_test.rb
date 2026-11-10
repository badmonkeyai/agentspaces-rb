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
require "agentspaces/capabilities"

# The Raft client of the ordered log from Ruby (srad/agentspaces-js.md
# JS-V-05 under JS-V-13), the port of the Python client's test_ordered.py:
# the Raft frame union and the ClientSubmit pinned by the golden raft_*
# vectors, the ClaimCommand in Java record order, and a client that submits
# to the advertised leader, follows a follower's leader hint, and observes
# the commit through the space, against a simulated log that applies the
# OrderedTakes.onCommand rule.
class OrderedTest < Minitest::Test
  include GoldenHelpers
  include AgentSpaces
  include AgentSpaces::Capabilities

  GROUP = "zRbOrdered"
  JOB = "com.acme.Job#v1"

  # Three voters of a NetPeer fleet: a ClientSubmit at the leader commits its
  # command and every voter applies it by OrderedTakes.onCommand (the holder
  # key is the claim holder's peer, the claim is bound to its entry, the
  # epoch is the committed epoch plus one); a follower forwards a submit to
  # the leader under its leader hint; the leader gossips an installed claim
  # as a signed claim delta, which is how a client observes the commit.
  class SimulatedLog
    include AgentSpaces
    include AgentSpaces::Capabilities

    attr_reader :submits, :forwarded, :installed, :rejected, :refused

    def initialize(voters, space_name, leader_index: 0, term: 1)
      @voters = voters
      @space_name = space_name
      @leader = voters[leader_index]
      @term = term
      @submits = voters.to_h { |v| [v.identity.peer_id, 0] }
      @forwarded = 0
      @installed = [] # entryId:epoch, once each
      @rejected = []  # not the next generation of its entry
      @refused = []   # unbound or inauthentic commands
      voters.each { |voter| voter.pipe_handlers[OrderedLog::TYPE] = handler(voter) }
    end

    # The leader appends, the log replicates, every voter applies in order.
    def commit(command)
      installed = nil
      @voters.each { |voter| installed = apply(voter, command) || installed }
      return if installed.nil?

      entry_id, signed = installed
      # The leader's own gossip; send_frame is the peer's private transport.
      @leader.send(:send_frame, "RUMOR", Wire.rumor_body("space:#{@space_name}", "c:#{entry_id}:#{signed['claim']['stamp']}",
                                                         6, Wire.claim_delta(entry_id, signed)))
    end

    # Every voter's ordered-log advertisement as RaftLog.describe publishes it.
    def advertise
      @voters.each do |voter|
        now = voter.now_ms
        parameters = { "members" => @voters.size.to_s, "term" => @term.to_s,
                       "role" => voter.equal?(@leader) ? "leader" : "follower" }
        parameters["leaseUntil"] = Instants.iso(now + 5_000) if voter.equal?(@leader)
        voter.publish_ad("CapabilityAdvertisement", {
                           "id" => "aspace://#{GROUP}/cap/ordered-log/#{voter.identity.peer_id}",
                           "issuer" => voter.identity.peer_id, "group" => GROUP,
                           "issued" => Instants.iso(now - (now % 1000)), "ttl" => "PT15M",
                           "capabilityType" => OrderedLog::TYPE, "version" => "0.1", "binding" => "pipe",
                           "parameters" => CBOR.canonical_map(parameters), "costHints" => {}
                         })
      end
    end

    private

    def handler(voter)
      lambda do |_sender, payload|
        frame = OrderedLog.parse_frame(payload)
        next if frame.nil? || !frame.key?("clientSubmit")

        @submits[voter.identity.peer_id] += 1
        unless voter.equal?(@leader)
          @forwarded += 1
          voter.send_pipe(@leader.identity.peer_id, OrderedLog::TYPE, payload) # RaftLog.submit's hint
          next
        end
        commit(frame["clientSubmit"]["command"])
      end
    end

    def apply(voter, command)
      parsed = begin
        CBOR.load(command)
      rescue CBOR::Error
        return nil
      end
      claim = parsed["claim"]
      holder_key = parsed["holderKey"]
      entry_id = parsed["entryId"]
      if !claim.is_a?(Hash) || !holder_key.is_a?(String) || !parsed["signature"].is_a?(String) ||
         claim["entryId"] != entry_id || !claim["holder"].to_s.start_with?("#{Derive.id(holder_key)}/")
        note(@refused, "#{entry_id}:#{(claim || {})['epoch']}")
        return nil
      end
      committed = (voter.claim_of(entry_id) || {}).fetch("epoch", 0).to_i
      epoch = Integer(claim["epoch"])
      if epoch != committed + 1
        note(@rejected, "#{entry_id}:#{epoch}")
        return nil
      end
      signed = { "claim" => claim, "holderKey" => holder_key, "signature" => parsed["signature"] }
      signed["holderCertificate"] = parsed["holderCertificate"] unless parsed["holderCertificate"].nil?
      voter.fold_claim(entry_id, signed) # the space's own verifier: an inauthentic command is dropped
      if (voter.claim_of(entry_id) || {}).fetch("epoch", -1).to_i != epoch
        note(@refused, "#{entry_id}:#{epoch}")
        return nil
      end
      note(@installed, "#{entry_id}:#{epoch}")
      [entry_id, signed]
    end

    # Once per command, whichever voter judged it first: every voter reaches the same verdict.
    def note(record, item) = record.include?(item) ? nil : record << item
  end

  # A dial-only client's reachable set: the seed it dialed and nothing else,
  # whatever frames the seed relays to it.
  class Reach < Set
    def initialize(allowed)
      @allowed = Set.new(allowed)
      super
    end

    def add(peer_id) = @allowed.include?(peer_id) ? super : self
    alias << add
  end

  def setup
    @peers = []
  end

  def teardown
    @peers.each(&:close)
  end

  def log_fleet(clients: 1, leader_index: 0)
    @peers = Testing::Network.fleet(GROUP, 3 + clients)
    voters = @peers.first(3)
    log = SimulatedLog.new(voters, "jobs", leader_index: leader_index)
    log.advertise
    [voters, @peers.drop(3), log]
  end

  def pid(peer) = peer.identity.peer_id

  # ------------------------------------------------------------ the frames

  def test_the_raft_frames_encode_as_the_java_records_do
    assert_equal hex("raft_request_vote_cbor"),
                 OrderedLog.raft_frame(requestVote: { "term" => 3, "candidate" => "zA", "lastLogIndex" => 7,
                                                      "lastLogTerm" => 2 })
    assert_equal hex("raft_vote_reply_cbor"), OrderedLog.raft_frame("voteReply" => { "term" => 3, "granted" => true })
    assert_equal hex("raft_append_entries_cbor"),
                 OrderedLog.raft_frame(appendEntries: { "term" => 3, "leader" => "zA", "prevLogIndex" => 7,
                                                        "prevLogTerm" => 2,
                                                        "entries" => [{ "term" => 3, "command" => "cmd".b }],
                                                        "leaderCommit" => 6 })
    assert_equal hex("raft_append_reply_cbor"),
                 Ordered.raft_frame(appendReply: { "term" => 3, "follower" => "zB", "success" => true,
                                                   "matchIndex" => 8 })
    assert_equal hex("raft_client_submit_cbor"), OrderedLog.client_submit_frame("cmd")
    assert_equal({ "clientSubmit" => { "command" => "cmd".b } },
                 OrderedLog.parse_frame(OrderedLog.client_submit_frame("cmd")))
    assert_nil OrderedLog.parse_frame("\x01".b)
    assert_nil OrderedLog.parse_frame("\xFF".b)
    assert_raises(ArgumentError) { OrderedLog.raft_frame(heartbeat: {}) }
  end

  def test_a_claim_command_carries_the_holders_proof_in_record_order
    identity = Identity.generate
    space_id = Derive.space_id_local("#{GROUP}/jobs")
    claim = Wire.take_claim("e-1", space_id, 1, Wire.hlc_now(identity.agent("w"), 1_700_000_000_000),
                            identity.agent("w"), 0.0, 1_700_000_060_000)
    signed = Wire.signed_claim(claim, identity)
    command = load(OrderedLog.claim_command("e-1", claim, identity.public_raw, signed["signature"]))
    assert_equal %w[entryId claim holderKey signature], command.keys
    assert_equal claim, command["claim"]
    assert_equal identity.public_raw, command["holderKey"]
    assert Identity.verify(command["holderKey"], cbor(command["claim"]), command["signature"])
    # An agent holder: its certificate rides in the appended field and the proof verifies as a SignedClaim.
    agent = identity.renewing_subordinate("clerk", "PT24H")
    now = (Time.now.to_f * 1000).to_i # inside the certificate's window, which opens at the real clock
    claim = Wire.take_claim("e-2", space_id, 1, Wire.hlc_now(agent.agent_id, now), agent.agent_id, 0.0, now + 60_000)
    signed = Wire.signed_claim(claim, identity, agent)
    command = load(Ordered.claim_command("e-2", claim, identity.public_raw, signed["signature"],
                                         signed["holderCertificate"]))
    assert_equal %w[entryId claim holderKey signature holderCertificate], command.keys
    assert Wire.verify_claim_proof({ "claim" => command["claim"], "holderKey" => command["holderKey"],
                                     "signature" => command["signature"],
                                     "holderCertificate" => command["holderCertificate"] })
  end

  # ------------------------------------------------------------ the client

  def test_a_client_takes_exactly_once_through_the_log_and_observes_the_commit
    voters, (client,), log = log_fleet
    ordered_log = OrderedLog.new(Pipes.new(client))
    assert_equal Set.new(voters.map { |v| pid(v) }), Set.new(ordered_log.members.map(&:peer))
    assert_equal pid(voters[0]), ordered_log.leader
    assert_equal pid(voters[0]), ordered_log.submit_target
    leader = ordered_log.members.find { |m| m.role == "leader" }
    assert_equal 1, leader.term
    refute_nil leader.lease_until_ms
    job = voters[1].write_entry("jobs", JOB, { "jobId" => "job-1", "payload" => "settle the invoice" })
    taken = ordered_log.take("jobs", JOB, agent_name: "rb-worker", lease_millis: 60_000, timeout_seconds: 5.0)
    assert_equal job, taken
    assert_equal ["#{job}:1"], log.installed
    assert_empty log.rejected
    assert_empty log.refused
    assert_equal 1, log.submits[pid(voters[0])]
    assert_equal 0, log.forwarded
    holder = client.identity.agent("rb-worker")
    voters.each do |voter|
      assert_equal holder, voter.claim_of(job)["holder"]
      assert_equal 1, voter.claim_of(job)["epoch"]
    end
    client.complete_entry("jobs", taken)
    assert(voters.all? { |v| v.states[job]["completed"] })
    # Through the Space: the same take as a Taken, completed with a result.
    second = voters[2].write_entry("jobs", JOB, { "jobId" => "job-2", "payload" => "file the return" })
    held = client.space("jobs").take(JOB, lease: "1m", timeout: "5s", through: ordered_log)
    refute_nil held
    assert_equal second, held.entry_id
    assert_equal "job-2", held.value.payload["jobId"]
    held.complete
    assert_equal ["#{job}:1", "#{second}:1"], log.installed
    assert(voters.all? { |v| v.states[second]["completed"] })
  end

  def test_an_attested_agent_takes_through_the_log_with_its_own_signature
    voters, (client,), log = log_fleet
    agent = client.identity.renewing_subordinate("clerk", "PT24H")
    job = voters[0].write_entry("jobs", JOB, { "jobId" => "job-3", "payload" => "x" })
    taken = OrderedLog.new(Pipes.new(client)).take("jobs", JOB, lease_millis: 60_000, timeout_seconds: 5.0, agent: agent)
    assert_equal job, taken
    assert_equal ["#{job}:1"], log.installed
    voters.each do |voter|
      signed = voter.claims[job]
      assert_equal agent.agent_id, signed["claim"]["holder"]
      refute_nil signed["holderCertificate"]
    end
    client.complete_entry("jobs", taken, agent: agent)
    assert(voters.all? { |v| v.states[job]["completed"] })
  end

  def test_the_client_follows_a_followers_leader_hint_when_the_leader_is_out_of_reach
    voters, (client,), log = log_fleet(leader_index: 2)
    # Dial-only behind the first voter; the peer exposes no setter, so the test swaps the set.
    client.instance_variable_set(:@reachable, Reach.new([pid(voters[0])]))
    ordered_log = OrderedLog.new(Pipes.new(client))
    assert_equal pid(voters[2]), ordered_log.leader
    assert_equal pid(voters[0]), ordered_log.submit_target, "a reachable member forwards"
    job = voters[1].write_entry("jobs", JOB, { "jobId" => "job-4", "payload" => "y" })
    assert_equal job, ordered_log.take("jobs", JOB, agent_name: "rb-worker", lease_millis: 60_000, timeout_seconds: 5.0)
    assert_equal 1, log.forwarded
    assert_equal 1, log.submits[pid(voters[0])]
    assert_equal 1, log.submits[pid(voters[2])]
    assert_equal ["#{job}:1"], log.installed
    assert_equal [pid(voters[0])], client.reachable.to_a
  end

  def test_a_generation_installs_once_and_a_duplicate_a_jump_or_an_unbound_claim_is_refused
    voters, (first, second), log = log_fleet(clients: 2)
    job = voters[0].write_entry("jobs", JOB, { "jobId" => "job-5", "payload" => "z" })
    assert_equal job, OrderedLog.new(Pipes.new(first)).take("jobs", JOB, agent_name: "rb-worker", lease_millis: 60_000,
                                                                          timeout_seconds: 5.0)
    winner = first.identity.agent("rb-worker")
    space_id = Derive.space_id_local("#{GROUP}/jobs")
    rival = OrderedLog.new(Pipes.new(second))
    now = second.now_ms
    loser = second.identity.agent("rb-worker")
    command = lambda do |epoch, entry_id: job, holder: loser, signer: second.identity|
      claim = Wire.take_claim(job, space_id, epoch, Wire.hlc_now(holder, now), holder, 0.0, now + 60_000)
      signed = Wire.signed_claim(claim, signer)
      OrderedLog.claim_command(entry_id, claim, signer.public_raw, signed["signature"])
    end
    assert rival.submit(command.call(1)), "the same generation again: the log already decided it"
    assert rival.submit(command.call(3)), "a jump past the next generation"
    assert_equal ["#{job}:1", "#{job}:3"], log.rejected
    assert rival.submit(command.call(2, entry_id: "other-entry")), "the claim is bound to its entry"
    assert rival.submit(command.call(2, holder: winner)), "the key is not the named holder's peer"
    assert_equal ["other-entry:2", "#{job}:2"], log.refused
    assert_equal ["#{job}:1"], log.installed
    voters.each do |voter|
      assert_equal winner, voter.claim_of(job)["holder"]
      assert_equal 1, voter.claim_of(job)["epoch"]
    end
    # A second client cannot take the held entry: nothing is submitted while the claim is live.
    assert_nil rival.take("jobs", JOB, agent_name: "rb-worker", lease_millis: 60_000, timeout_seconds: 1.0)
    assert_equal 5, log.submits[pid(voters[0])]
  end

  def test_without_a_log_in_the_ads_a_take_submits_nothing_and_returns_at_its_timeout
    @peers = Testing::Network.fleet(GROUP, 2)
    writer, client = @peers
    writer.write_entry("jobs", JOB, { "jobId" => "job-6", "payload" => "w" })
    ordered_log = OrderedLog.new(Pipes.new(client))
    assert_empty ordered_log.members
    assert_nil ordered_log.leader
    assert_nil ordered_log.submit_target
    refute ordered_log.submit("cmd".b)
    assert_nil ordered_log.take("jobs", JOB, agent_name: "rb-worker", lease_millis: 60_000, timeout_seconds: 0.5)
    assert_empty client.claims
  end

  def test_a_matches_filter_narrows_the_candidates
    voters, (client,), log = log_fleet
    voters[0].write_entry("jobs", JOB, { "jobId" => "job-7", "payload" => "skip" })
    wanted = voters[0].write_entry("jobs", JOB, { "jobId" => "job-8", "payload" => "take" })
    ordered_log = OrderedLog.new(Pipes.new(client))
    taken = ordered_log.take("jobs", JOB, agent_name: "rb-worker", lease_millis: 60_000, timeout_seconds: 5.0,
                                          matches: ->(payload, _tags) { payload["payload"] == "take" })
    assert_equal wanted, taken
    assert_equal ["#{wanted}:1"], log.installed
  end
end
