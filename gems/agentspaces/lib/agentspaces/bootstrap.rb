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

require_relative "../agentspaces" unless defined?(AgentSpaces::Peer)
require_relative "beacon"
require_relative "social"

module AgentSpaces
  # Peer#bootstrap spent its join_timeout: the message and the attributes say
  # how many times the document was fetched, how many seeds were dialed and
  # how many of them connected. It is an IOError, as the NoSeedError of a
  # failed dial is, so a caller that caught that one still catches this (the
  # Python BootstrapTimeout is a TimeoutError, an OSError, for the same reason).
  class BootstrapTimeout < IOError
    attr_reader :fetches, :dialed, :connected

    def initialize(message = nil, fetches: 0, dialed: 0, connected: 0)
      super(message)
      @fetches = fetches
      @dialed = dialed
      @connected = connected
    end
  end

  # The discovery half of the peer (SRAD DB-X-01, DB-X-07): a join through a
  # beacon document and a join with an invite key.
  class Peer
    # The slices a join through a document waits in (ISSUE-BootstrapRobustness FR-4).
    JOIN_SLICE_FIRST = 1.0
    JOIN_SLICE_MAX = 5.0

    # Joins through a beacon document (SRAD DB-X-01): fetches and verifies
    # the document at url (https unless allow_plain; signed by beacon_peer
    # when pinned), selects the group (by group_id, else the only one),
    # verifies its founding advertisement with the four checks of SPEC 5.1
    # against group_id when given, and dials the seeds this peer has a
    # dialer for in priority order. Returns the verified
    # SignedGroupAdvertisement, kept on founding.
    #
    # timeout bounds one attempt (one fetch, one dial of one seed) and
    # join_timeout the whole call. A first attempt that succeeds asks once
    # and dials once. Otherwise the call keeps asking inside the budget, in
    # slices of 1 s, 2 s, 4 s, then 5 s each: at the start of each slice it
    # fetches the document again when the previous fetch failed with an
    # IOError or named no seed, and dials again, once per slice, every seed
    # that refused. A refusal (a bad scheme, a document or founding that does
    # not verify, a founding for another id, a group the document does not
    # carry) raises Beacon::Error at once. When the budget runs out the call
    # raises BootstrapTimeout with the counts and the last error.
    def bootstrap(url, group_id: nil, allow_plain: false, beacon_peer: nil, timeout: 3.0, join_timeout: 10.0,
                  allow_unsigned: false)
      deadline = monotonic + join_timeout
      fetches = 0
      dialed = []
      connected = 0
      last_error = nil
      founding = nil
      seeds = []
      slice = JOIN_SLICE_FIRST
      transports = dialable_transports
      refresh = lambda do
        fresh = Beacon.fetch_beacon_document(url, allow_plain: allow_plain, beacon_peer: beacon_peer, timeout: timeout,
                                             allow_unsigned: allow_unsigned)
        Beacon.seeds_of(Beacon.group_from_document(fresh, group_id: @group), transports)
      end

      loop do
        started = monotonic
        if seeds.empty?
          fetches += 1
          begin
            doc = Beacon.fetch_beacon_document(url, allow_plain: allow_plain, beacon_peer: beacon_peer,
                                                    timeout: [timeout, [deadline - started, 0.001].max].min,
                                                    allow_unsigned: allow_unsigned)
            group = Beacon.group_from_document(doc, group_id: group_id)
            founding = adopt_document_founding(group, group_id)
            seeds = expand_seeds(Beacon.seeds_of(group, transports))
            if seeds.empty?
              last_error = Beacon::Error.new("the beacon document names no #{transports.join('/')} seed for " \
                                             "#{group['name'].inspect}")
            else
              @refresh_seeds = refresh
            end
          rescue IOError, SystemCallError => e
            # The beacon is unreachable or answered an error: ask again.
            last_error = e
          end
        end
        seeds.each do |seed|
          remaining = deadline - monotonic
          break if remaining <= 0

          dialed << seed unless dialed.include?(seed)
          @seeds = seeds
          begin
            dial_seed(seed, [timeout, remaining].min)
          rescue SystemCallError, IOError, SocketError, OpenSSL::SSL::SSLError, Timeout::Error => e
            last_error = e
            next
          end
          connected += 1
          return founding
        end
        now = monotonic
        wait = [slice - (now - started), deadline - now].min
        sleep(wait) if wait.positive?
        if monotonic >= deadline
          raise BootstrapTimeout.new(
            "no join through #{url} within #{format('%g', join_timeout)}s: #{fetches} fetch(es), " \
            "#{connected} of #{dialed.size} seed(s) connected; last error: #{last_error&.message || 'none'}",
            fetches: fetches, dialed: dialed.size, connected: connected
          )
        end
        slice = [slice * 2, JOIN_SLICE_MAX].min
      end
    end

    # Joins a group for friends with an invite key (SRAD DB-X-07): parses the
    # key, fetches the social beacon's document at /j/<code>, takes the
    # delegation from the key or the document's invite field, derives this
    # peer's delegated credential with the invite signing key and carries it
    # in the self-advertisement under aspace:join, verifies the document's
    # founding against the delegation's group, and dials the seeds. Returns
    # [content_key, group_id]: the 32-byte content key, epoch 0, and the
    # verified GroupID.
    def join_invite(key_text, allow_plain: false, timeout: 3.0, allow_unsigned: false)
      key = Social::InviteKey.parse(key_text)
      scheme = allow_plain ? "http" : "https"
      doc = Beacon.fetch_beacon_document(key.document_url(scheme), allow_plain: allow_plain, timeout: timeout,
                                         allow_unsigned: allow_unsigned)
      groups = doc["groups"]
      groups = [] if Beacon.falsy?(groups)
      group = nil
      unless key.delegation.nil?
        begin
          group = Beacon.group_from_document(doc, group_id: Social.delegation_group(key.delegation))
        rescue ArgumentError
          group = nil
        end
      end
      if group.nil?
        raise Beacon::Error, "the beacon knows no group under #{key.code}" if !groups.is_a?(Array) || groups.size != 1

        group = groups[0] # a social beacon serves one group per code
        raise Beacon::Error, "the beacon document's group is not an object" unless group.is_a?(Hash)
      end
      delegation = Beacon.falsy?(key.delegation) ? group["invite"] : key.delegation
      if Beacon.falsy?(delegation)
        raise Beacon::Error, "the invite key carries no delegation and the beacon document has none"
      end

      group_id = Social.delegation_group(delegation)
      founding = adopt_document_founding(group, group_id)
      credential = Social.issue_delegated(delegation, key.secret.invite_private_seed, @identity.peer_id)
      issuer = founding["advertisement"]["issuer"]
      verdict = Social.judge_delegated_credential(credential, @identity.peer_id, issuer, group_id, now_ms)
      if verdict == "invalid"
        raise Social::Error, "the invite key's delegation does not admit this peer to the group " \
                             "(not the founder's, or for another group)"
      end

      # An expired delegation still admits a peer the members admitted while
      # it was valid (SPEC 5.1, v0.1.20); a newcomer is refused by the members.
      @resource_hints[Social::HINT_KEY] = credential
      @delegation = delegation
      # Keep this key and join with it next time: it carries the delegation
      # this peer was admitted under, so a restart presents the same
      # credential even after the founder re-delegated at the beacon.
      @pinned_invite = key.with_delegation(delegation).compact
      transports = dialable_transports
      seeds = Beacon.seeds_of(group, transports)
      if seeds.empty?
        raise Beacon::Error, "the beacon document names no #{transports.join('/')} seed for #{group['name'].inspect}"
      end

      @refresh_seeds = lambda do
        fresh = Beacon.fetch_beacon_document(key.document_url(scheme), allow_plain: allow_plain, timeout: timeout,
                                             allow_unsigned: allow_unsigned)
        Beacon.seeds_of(Beacon.group_from_document(fresh, group_id: @group), transports)
      end
      connect_any(seeds)
      [key.secret.content_key, group_id]
    end

    private

    # Verifies a document group's founding exactly as join_by_group_id
    # verifies a GROUP_AD answer (the four checks, then the id this peer
    # wants) and joins on it: the group, the founding, and the founder are
    # set before any socket is dialed.
    def adopt_document_founding(group, expected_group_id)
      derived = Beacon.verified_group_id(group, expected_group_id)
      adopt_founding!(Beacon.founding_of(group), derived)
      @founding
    end

    # The schemes this peer has a dialer for, the transports a document's
    # seeds are filtered by (Python dials tcp alone).
    def dialable_transports = @dialers.values.flatten.map(&:to_s).uniq

    # Peer#connect with the attempt's bound on the dial.
    def dial_seed(seed, timeout) = connect(seed.host, seed.port, scheme: seed.scheme, timeout: timeout)
  end
end
