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
  module Capabilities
    # A member's view of the ordered log, from its advertisement: role is
    # "leader", "follower", or "candidate"; lease_until_ms is the leader's
    # lease, nil for the others.
    LogMember = Data.define(:peer, :role, :term, :lease_until_ms)

    # The Raft client of the ordered log (srad/agentspaces-js.md JS-V-05,
    # JS-V-13; reviews/L3L4-COVERAGE.md "a Raft client, not a Raft voter"):
    # a Ruby peer submits a signed claim command to the log's leader (named
    # by the leader's aspace:cap/ordered-log advertisement, or forwarded by
    # any member of the log under its leader hint) and observes the commit
    # through the space, where the committed claim arrives as a signed claim
    # delta. An ordered take is therefore exactly once fleet-wide: the log
    # decides each generation, and only the holder the log committed
    # completes. This is the client half of Java's OrderedTakes; the voter
    # stays in Java (JS-F-18).
    #
    #   log = OrderedLog.new(Pipes.new(peer))
    #   entry_id = log.take("jobs", JOB_TYPE, agent_name: "rb-worker", lease_millis: 60_000, timeout_seconds: 10)
    #   peer.complete_entry("jobs", entry_id)
    #   held = peer.space("jobs").take(JOB_TYPE, lease: "1m", through: log)
    class OrderedLog
      TYPE = "aspace:cap/ordered-log" # RaftLog.TYPE
      FRAME_FIELDS = %w[requestVote voteReply appendEntries appendReply clientSubmit].freeze

      # RaftMessages.Frame, the union of the five Raft messages in Java
      # record order with every absent field null (golden raft_*):
      # OrderedLog.raft_frame("clientSubmit" => { "command" => "...".b }).
      # Keys are the Java field names, as Strings or Symbols.
      def self.raft_frame(parts = {}, **named)
        given = parts.to_h.merge(named).transform_keys(&:to_s)
        unknown = given.keys - FRAME_FIELDS
        raise ArgumentError, "not Raft frame fields: #{unknown.sort.join(', ')}" unless unknown.empty?

        CBOR.dump(FRAME_FIELDS.to_h { |field| [field, given[field]] })
      end

      # A Frame carrying one ClientSubmit (golden raft_client_submit_cbor).
      def self.client_submit_frame(command) = raft_frame("clientSubmit" => { "command" => command.b })

      # OrderedTakes.ClaimCommand: the claim, the holder's peer key, the
      # holder's signature over the claim's canonical bytes, and (for an agent
      # holder) the certificate covering the claim's stamp, omitted otherwise.
      # The voters install it only when the key derives to the claim holder's
      # peer, the claim is bound to entry_id, and its epoch is the committed
      # epoch plus one.
      def self.claim_command(entry_id, claim, peer_public_raw, signature, holder_certificate = nil)
        command = { "entryId" => entry_id, "claim" => claim, "holderKey" => peer_public_raw.b,
                    "signature" => signature.b }
        command["holderCertificate"] = holder_certificate unless holder_certificate.nil?
        CBOR.dump(command)
      end

      # The Frame a member received, as a Hash of the present fields, or nil
      # when it is no RaftMessages.Frame in the wire encoding, as Java's
      # fromWire reads one (HLC round seven, 2026-11-08): what a test voter
      # (or a future Ruby voter) dispatches on.
      def self.parse_frame(payload)
        Schema.load("RaftMessages.Frame", payload).compact
      rescue CBOR::Error
        nil
      end

      attr_reader :pipes
      attr_accessor :pull_interval_seconds, :attempt_seconds

      # One ads and space pull per interval while waiting, as a take's settle
      # window paces its pulls (JS-V-02); an attempt resubmits after
      # attempt_seconds undecided.
      def initialize(pipes, pull_interval_seconds: 0.6, attempt_seconds: 3.0)
        @pipes = pipes
        @pull_interval_seconds = pull_interval_seconds
        @attempt_seconds = attempt_seconds
      end

      def peer = @pipes.peer

      # The log's members as their live advertisements describe them.
      def members
        now = peer.now_ms
        peer.ads.values.filter_map do |entry|
          next unless entry["type"] == "CapabilityAdvertisement" && entry["expires"] > now &&
                      entry["ad"]["capabilityType"] == TYPE

          parameters = entry["ad"]["parameters"] || {}
          lease_until = begin
            parameters["leaseUntil"].nil? ? nil : Instants.parse_millis(parameters["leaseUntil"].to_s)
          rescue ArgumentError, TypeError
            nil
          end
          term = begin
            raw = parameters["term"]
            if raw.is_a?(Numeric) then raw.to_i
            elsif raw.nil? || raw == "" then 0
            else Integer(raw.to_s, 10)
            end
          rescue ArgumentError, TypeError, FloatDomainError
            0
          end
          LogMember.new(peer: entry["issuer"], role: parameters["role"].to_s, term: term, lease_until_ms: lease_until)
        end
      end

      # The leader whose lease has not lapsed, by the highest term, or nil.
      def leader
        now = peer.now_ms
        leaders = members.select { |m| m.role == "leader" && (m.lease_until_ms.nil? || m.lease_until_ms > now) }
        leaders.max_by(&:term)&.peer
      end

      # Where a submit goes: the leader when this peer can reach it, else any
      # reachable member of the log, which forwards it under its leader hint.
      def submit_target
        reachable = peer.reachable
        chosen = leader
        return chosen if chosen && reachable.include?(chosen)

        members.find { |m| reachable.include?(m.peer) }&.peer
      end

      # Submits one command as a ClientSubmit; returns whether a target was known.
      def submit(command)
        target = submit_target
        return false if target.nil?

        @pipes.send_pipe(target, TYPE, OrderedLog.client_submit_frame(command))
        true
      end

      # OrderedTakes.take as a client: claims a matching live entry through
      # the log and returns its id once the log committed this peer's claim
      # for the generation it asked for, or nil at the timeout. With agent
      # (an AgentIdentity) the claim is the agent's, signed by its key with
      # its certificate in the command (v0.1.13). matches, a callable over
      # (payload, tags), narrows the candidates. The caller completes the
      # entry as after any take; a command lost to a leader election is
      # resubmitted on the next scan. Space#take(..., through: log) calls this.
      def take(space, type_name, agent_name: "ruby", lease_millis: 60_000, timeout_seconds: 15.0, agent: nil,
               matches: nil)
        peer = self.peer
        holder = agent.nil? ? peer.identity.agent(agent_name) : agent.agent_id
        return nil if peer.revocations.refuses?(holder, agent&.public_raw, nil)

        space_id = Derive.space_id_local("#{peer.group}/#{space}")
        deadline = monotonic + timeout_seconds
        while monotonic < deadline && peer.running?
          # The log's advertisements name the leader.
          peer.pull_ads if peer.pull_space_paced(space, @pull_interval_seconds)
          seen = peer.fold_count
          now = peer.now_ms
          submitted = false
          peer.states.to_a.each do |entry_id, dto|
            record = dto["record"] || {}
            next if record["type"] != type_name || dto["completed"] || record["spaceId"] != space_id

            lease = dto["leaseValue"] || record["lease"] || {}
            next if lease.fetch("expiresAtMillis", 0).to_i <= now

            current = peer.claim_of(entry_id)
            next if current && current.fetch("expiresAtMillis", 0).to_i > now

            value = peer.value_of(dto)
            next if value.nil?

            payload = value.first
            next if matches && !matches.call(payload || {}, record["tags"] || {})

            epoch = current ? Integer(current["epoch"]) + 1 : 1
            claim = Wire.take_claim(entry_id, space_id, epoch, Wire.hlc_now(holder, now), holder, 0.0,
                                    now + lease_millis)
            signed = Wire.signed_claim(claim, peer.identity, agent)
            command = OrderedLog.claim_command(entry_id, claim, peer.identity.public_raw, signed["signature"],
                                               signed["holderCertificate"])
            break unless submit(command) # no member of the log reachable yet: pull the ads again

            submitted = true
            # The log decides this generation within a bounded attempt, observed
            # as the committed claim folding from the space; undecided, the next
            # scan resubmits.
            attempt = [deadline, monotonic + @attempt_seconds].min
            while monotonic < attempt
              peer.await_fold([@pull_interval_seconds, attempt - monotonic].min)
              decided = peer.claim_of(entry_id)
              if decided && decided.fetch("epoch", 0).to_i >= epoch
                if decided["holder"] == holder && Integer(decided["epoch"]) == epoch &&
                   !(peer.states[entry_id] || {})["completed"]
                  return entry_id
                end

                break # someone else won this generation; try another entry
              end
              peer.pull_space_paced(space, @pull_interval_seconds)
            end
            break # re-scan (and resubmit when still undecided)
          end
          peer.await_fold([@pull_interval_seconds, deadline - monotonic].min, since: seen) unless submitted
        end
        nil
      end

      def inspect = "#<AgentSpaces::Capabilities::OrderedLog #{peer.identity.peer_id}>"

      private

      def monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end

    # The Python client's module-level names for the ordered log.
    module Ordered
      TYPE = OrderedLog::TYPE

      module_function

      def raft_frame(parts = {}, **named) = OrderedLog.raft_frame(parts, **named)
      def client_submit_frame(command) = OrderedLog.client_submit_frame(command)
      def claim_command(...) = OrderedLog.claim_command(...)
      def parse_frame(payload) = OrderedLog.parse_frame(payload)
    end
  end
end
