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

module AgentSpaces
  # The QUORUM vote (SPEC 8, TECH-SPEC 8.4), as Java's VoteCapability counts
  # it, over the ballot states a Peer has folded. Ballots are ordinary
  # entries of the reserved type below; the voter is the entry's
  # authenticated issuer, and a ballot whose declared voter differs is a
  # forgery. Under PEER one peer is one counted ballot however many names it
  # writes; under AGENT each agent counts once, and only an AGENT_ATTESTED
  # record is eligible.
  module Votes
    BALLOT_TYPE = "ai.badmonkey.agentspaces.capabilities.vote.VoteCapability$Ballot#v1"
    PROPOSAL_TYPE = "ai.badmonkey.agentspaces.capabilities.vote.VoteCapability$Proposal#v1"
    PEER = "PEER"
    AGENT = "AGENT"

    # A proposal as a ballot method sees it.
    Proposal = Data.define(:proposal_id, :question, :options, :quorum)

    # A closed vote as a decision method sees it.
    Decision = Data.define(:proposal_id, :winner, :tally)

    module_function

    # The folded, present ballot records for one proposal: [record, dto, ballot].
    def ballots(states, proposal_id)
      states.values.filter_map do |dto|
        record = dto["record"] || {}
        next if record["type"] != BALLOT_TYPE || dto["completed"]

        adds = Array(dto["adds"]).map { |d| [d["replica"], d["counter"]] }
        removes = Array(dto["removes"]).map { |d| [d["replica"], d["counter"]] }
        next if (adds - removes).empty?

        ballot = begin
          CBOR.load(record["payload"] || "".b)
        rescue CBOR::Error
          next
        end
        [record, dto, ballot] if ballot.is_a?(Hash) && ballot["proposalId"] == proposal_id
      end
    end

    # Votes per option. permits is the authorizer's per-agent answer;
    # options zero-fills and spoils ballots for options the proposal lacks.
    def tally(states, proposal_id, options = nil, granularity = PEER, permits: nil)
      result = Array(options).to_h { |o| [o, 0] }
      counted = Set.new
      ballots(states, proposal_id).each do |record, dto, ballot|
        issuer = record["issuer"]
        next unless issuer.is_a?(String) && ballot["voter"] == issuer

        option = ballot["option"]
        next if options && !options.include?(option)
        next if granularity == AGENT && dto["agentCertificate"].nil?
        next if permits && !permits.call(issuer)

        key = granularity == AGENT ? issuer : issuer.split("/", 2).first
        next if counted.include?(key)

        counted << key
        result[option] = result.fetch(option, 0) + 1
      end
      result
    end

    # The open proposals by id, from the folded Proposal records.
    def proposals(states)
      found = {}
      states.values.each do |dto|
        record = dto["record"] || {}
        next if record["type"] != PROPOSAL_TYPE || dto["completed"]

        proposal = begin
          CBOR.load(record["payload"] || "".b)
        rescue CBOR::Error
          next
        end
        found[proposal["proposalId"]] ||= proposal if proposal.is_a?(Hash) && proposal["proposalId"].is_a?(String)
      end
      found
    end

    # Opens a proposal; idempotent on the id. Returns the entry id, or nil
    # when the proposal was already open.
    def propose(peer, space, proposal_id, question, options, quorum, lease_millis: 3_600_000, agent: nil,
                agent_name: "ruby")
      return nil if proposals(peer.states).key?(proposal_id)

      payload = { "proposalId" => proposal_id, "question" => question, "options" => options.to_a,
                  "quorum" => Integer(quorum) }
      peer.write_entry(space, PROPOSAL_TYPE, payload, agent_name: agent_name, lease_millis: lease_millis, agent: agent)
    end

    # Casts this agent's ballot: a Ballot whose voter is the authenticated writer.
    def cast(peer, space, proposal_id, option, lease_millis: 3_600_000, agent: nil, agent_name: "ruby")
      voter = agent.nil? ? peer.identity.agent(agent_name) : agent.agent_id
      payload = { "proposalId" => proposal_id, "option" => option, "voter" => voter }
      peer.write_entry(space, BALLOT_TYPE, payload, agent_name: agent_name, lease_millis: lease_millis, agent: agent)
    end

    # The QUORUM decision as Java closes it: once distinct counted voters
    # reach the quorum, the option with the most votes wins, ties broken to
    # the lexicographically first option. nil while open or unknown.
    def decision(states, proposal_id, granularity = PEER, permits: nil)
      proposal = proposals(states)[proposal_id]
      return nil if proposal.nil?

      options = Array(proposal["options"])
      counts = tally(states, proposal_id, options, granularity, permits: permits)
      voters = counts.values.sum
      return nil if voters.zero? || voters < proposal.fetch("quorum", 0).to_i

      winner = options.min_by { |o| [-counts.fetch(o, 0), o] }
      { "proposalId" => proposal_id, "winner" => winner, "tally" => counts }
    end

    # The push-sum epoch that carries one option's preference share.
    def preference_epoch(vote_id, option) = "vote:#{vote_id}:#{option}"

    # VoteCapability.castPreference: 1 to the chosen option, 0 to the others.
    def cast_preference(aggregate, vote_id, options, preference)
      options.each { |o| aggregate.start(preference_epoch(vote_id, o), o == preference ? 1.0 : 0.0) }
    end

    # VoteCapability.leader: the option with the highest estimated share.
    def leader(aggregate, vote_id, options)
      best = nil
      best_share = -1.0
      options.each do |option|
        estimate = aggregate.estimate(preference_epoch(vote_id, option))
        if estimate && estimate > best_share
          best = option
          best_share = estimate
        end
      end
      best
    end
  end
end
