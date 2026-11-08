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
require_relative "beacon_test"
require "agentspaces/bootstrap"

# The peer's bootstrap paths (SRAD DB-X-01, DB-X-07): connect_any dials seeds
# in order and fails over to the next on a lost socket; bootstrap joins
# through a served document; join_invite derives the credential from the
# golden key, carries it under aspace:join, and verifies the founding against
# the delegation's group. The seeds are AgentSpaces::Testing::FakeSeed.
class BootstrapTest < Minitest::Test
  include AgentSpaces

  SOCIAL = JSON.parse(File.read(File.join(__dir__, "social-golden.json")))

  # A dialer that refuses every seed and records the dials.
  class RefusingDialer < Dialer
    attr_reader :dialed

    def initialize(schemes = ["tcp"])
      super()
      @schemes = schemes
      @dialed = []
    end

    def schemes = @schemes

    def open(seed, identity: nil, timeout: 10)
      @dialed << [seed.scheme, seed.host, seed.port, timeout]
      raise Errno::ECONNREFUSED, "#{seed.host}:#{seed.port}"
    end
  end

  def teardown
    @cleanup&.reverse_each do |thing|
      thing.close
    rescue StandardError
      nil
    end
  end

  def track(thing)
    (@cleanup ||= []) << thing
    thing
  end

  def dead_port
    probe = TCPServer.new("127.0.0.1", 0)
    port = probe.addr[1]
    probe.close
    port
  end

  def monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)

  def wait_until(seconds = 5.0)
    deadline = monotonic + seconds
    sleep 0.05 until monotonic >= deadline || yield
  end

  def tcp(host, port) = Seed.new(scheme: "tcp", host: host, port: port)

  def ms(iso) = Instants.parse_millis(iso)

  def first_rumor(seed) = seed.received.find { |e| e["kind"] == "RUMOR" }

  def self_ad(seed)
    rumor = CBOR.load(first_rumor(seed)["body"])
    assert_equal "peers", rumor["streamId"]
    CBOR.load(CBOR.load(rumor["payload"])["adBytes"])
  end

  # Replaces Beacon.http_get for the block: each call pops the next answer,
  # an exception to raise or the bytes to return; the last answer repeats.
  def stub_http_get(answers)
    calls = []
    original = Beacon.method(:http_get)
    Beacon.singleton_class.send(:remove_method, :http_get)
    Beacon.define_singleton_method(:http_get) do |url, timeout, _allow_plain|
      calls << [url, timeout]
      answer = answers.size > 1 ? answers.shift : answers[0]
      raise answer if answer.is_a?(Exception)

      answer
    end
    yield calls
  ensure
    Beacon.singleton_class.send(:remove_method, :http_get) if Beacon.singleton_class.method_defined?(:http_get)
    Beacon.define_singleton_method(:http_get, original) if original
  end

  def founding(founder)
    Founding.found(founder, "research-fleet", "OPEN", "LEASE_RACE", 3, "PT1S", "2026-10-14T00:00:00Z", "PT8760H")
  end

  def document_for(issuer, signed, seeds)
    group = Beacon.document_group("research-fleet", signed["advertisement"]["group"],
                                  Base64Text.encode(CBOR.dump(signed)), seeds)
    Beacon.sign_document(issuer, "2026-10-14T00:00:00Z", 300, [group])
  end

  # A served document with a dtls seed no Ruby dialer serves (Python's test
  # uses tls, which the Ruby peer dials) and the fake seed's tcp one.
  def served_document(issuer, founder, seed)
    signed = founding(founder)
    doc = document_for(issuer, signed, [["dtls", "seed-a.corp.example:7500"], ["tcp", "127.0.0.1:#{seed.port}"]])
    [signed, track(BeaconTestServer.new(Beacon.document_json(doc)))]
  end

  # A served document whose only tcp seed is 127.0.0.1:port.
  def served_document_at(issuer, founder, port)
    signed = founding(founder)
    [signed, track(BeaconTestServer.new(Beacon.document_json(document_for(issuer, signed,
                                                                           [["tcp", "127.0.0.1:#{port}"]]))))]
  end

  # ----------------------------------------------------------- connect_any

  def test_connect_any_dials_in_order_and_fails_over_to_the_next_seed
    first = track(Testing::FakeSeed.new)
    second = track(Testing::FakeSeed.new)
    dead = dead_port
    peer = track(Peer.new(Identity.generate, "zBootstrap"))
    peer.reconnect_interval = 0.1
    chosen = peer.connect_any([["127.0.0.1", dead], ["127.0.0.1", first.port], ["127.0.0.1", second.port]])
    assert_equal tcp("127.0.0.1", first.port), chosen
    assert_equal chosen, peer.instance_variable_get(:@seed)
    wait_until { first.kinds.size >= 2 }
    assert_equal %w[RUMOR DIGEST], first.kinds.first(2)
    assert_empty second.kinds
    # The first seed drops the link: the peer fails over to the next, not back to the first.
    first.drop(0)
    wait_until { second.kinds.size >= 2 }
    assert_equal %w[RUMOR DIGEST], second.kinds.first(2), "re-introduced at the next seed"
    assert_equal tcp("127.0.0.1", second.port), peer.instance_variable_get(:@seed)
    assert_equal 1, peer.reconnects
    assert_equal 1, first.connections.size
    assert peer.connected?
  end

  def test_connect_any_raises_when_no_seed_accepts_and_tries_each_once
    dialer = RefusingDialer.new
    peer = Peer.new(Identity.generate, "zBootstrap", dialers: [dialer])
    assert_raises(NoSeedError) { peer.connect_any([["127.0.0.1", 1], ["127.0.0.1", 2], ["127.0.0.1", 1]]) }
    assert_equal [["127.0.0.1", 1], ["127.0.0.1", 2]], dialer.dialed.map { |d| d[1, 2] }, "in order, duplicates folded"
    refute peer.connected?
    assert_raises(NoSeedError) { peer.connect_any([]) }
  end

  def test_a_hostname_seed_is_resolved_to_its_addresses
    peer = Peer.new(Identity.generate, "zBootstrap")
    expanded = peer.send(:expand_seeds, [["localhost", 7500]])
    assert_includes expanded, tcp("127.0.0.1", 7500)
    assert(expanded.all? { |s| s.port == 7500 })
    assert_equal [tcp("no-such-host.invalid.", 1)], peer.send(:expand_seeds, [["no-such-host.invalid.", 1]])
  end

  # ------------------------------------------------------------- bootstrap

  def test_bootstrap_joins_through_a_served_document
    issuer = Identity.generate
    founder = Identity.generate
    seed = track(Testing::FakeSeed.new)
    signed, served = served_document(issuer, founder, seed)
    group_id = signed["advertisement"]["group"]
    peer = track(Peer.new(Identity.generate, nil))
    result = peer.bootstrap(served.url, group_id: group_id, allow_plain: true, beacon_peer: issuer.peer_id)
    assert_equal signed, result
    assert_equal signed, peer.founding
    assert_equal group_id, peer.group
    assert_equal founder.peer_id, peer.founder_id, "the founder is known for revocations"
    assert_equal [tcp("127.0.0.1", seed.port)], peer.seeds, "the dtls seed is not this client's"
    wait_until { seed.kinds.size >= 2 }
    assert_equal %w[RUMOR DIGEST], seed.kinds.first(2)
    assert_equal group_id, self_ad(seed)["group"]
    assert_equal [tcp("127.0.0.1", seed.port)], peer.refresh_seeds.call
  end

  def test_bootstrap_refuses_a_founding_for_another_group_before_dialing
    issuer = Identity.generate
    founder = Identity.generate
    seed = track(Testing::FakeSeed.new)
    signed, served = served_document(issuer, founder, seed)
    peer = track(Peer.new(Identity.generate, nil))
    assert_raises(Beacon::Error) { peer.bootstrap(served.url, group_id: "zNotThisGroup", allow_plain: true) }
    assert_raises(Beacon::Error) { peer.bootstrap(served.url, group_id: signed["advertisement"]["group"]) }
    assert_raises(Beacon::Error) do
      peer.bootstrap(served.url, allow_plain: true, beacon_peer: Identity.generate.peer_id)
    end
    sleep 0.2
    assert_empty seed.connections
    refute peer.connected?
  end

  def test_bootstrap_without_a_group_id_takes_the_only_group
    issuer = Identity.generate
    founder = Identity.generate
    seed = track(Testing::FakeSeed.new)
    signed, served = served_document(issuer, founder, seed)
    peer = track(Peer.new(Identity.generate, nil))
    peer.bootstrap(served.url, allow_plain: true)
    assert_equal signed["advertisement"]["group"], peer.group
    wait_until { seed.kinds.size >= 1 }
    assert_equal "RUMOR", seed.kinds.first
  end

  # A peer with a dialer for another scheme takes that scheme's seeds too, in
  # the document's order, and fails over from them to the tcp one.
  def test_bootstrap_dials_the_schemes_the_peer_has_dialers_for
    issuer = Identity.generate
    seed = track(Testing::FakeSeed.new)
    signed = founding(Identity.generate)
    doc = document_for(issuer, signed, [["dtls", "127.0.0.9:7502"], ["tls", "127.0.0.9:7501"],
                                        ["tcp", "127.0.0.1:#{seed.port}"]])
    served = track(BeaconTestServer.new(Beacon.document_json(doc)))
    tls = RefusingDialer.new(["tls"])
    peer = track(Peer.new(Identity.generate, nil, dialers: [TcpDialer.new, tls]))
    peer.bootstrap(served.url, group_id: signed["advertisement"]["group"], allow_plain: true, timeout: 2.0)
    assert_equal [["tls", "127.0.0.9", 7501]], tls.dialed.map { |d| d[0, 3] }
    assert_operator tls.dialed.first[3], :<=, 2.0, "the dial is held to the per-attempt timeout"
    assert_equal [Seed.new(scheme: "tls", host: "127.0.0.9", port: 7501), tcp("127.0.0.1", seed.port)], peer.seeds
    assert peer.connected?
    assert_equal tcp("127.0.0.1", seed.port), peer.instance_variable_get(:@seed)
  end

  # ------------------------------------------------- bootstrap keeps asking
  # The join through a document waits in slices inside join_timeout (the
  # shape of the Java join by id, ISSUE-BootstrapRobustness FR-4): a beacon
  # or a seed that starts a few seconds after the client is reached on a
  # later slice; a budget that runs out raises BootstrapTimeout with the counts.

  def test_bootstrap_that_succeeds_at_once_fetches_once_and_dials_once
    issuer = Identity.generate
    seed = track(Testing::FakeSeed.new)
    signed, served = served_document(issuer, Identity.generate, seed)
    peer = track(Peer.new(Identity.generate, nil))
    started = monotonic
    result = peer.bootstrap(served.url, group_id: signed["advertisement"]["group"], allow_plain: true)
    assert_operator monotonic - started, :<, 1.0, "no slice was waited"
    assert_equal signed, result
    assert_equal 1, served.requests_made.size, "the document was fetched once"
    wait_until { seed.kinds.size >= 1 }
    assert_equal 1, seed.connections.size, "the seed was dialed once"
  end

  def test_bootstrap_fetches_again_when_the_beacon_answers_late
    issuer = Identity.generate
    founder = Identity.generate
    seed = track(Testing::FakeSeed.new)
    signed = founding(founder)
    url = "http://127.0.0.1:1#{Beacon::WELL_KNOWN}"
    late = Beacon::FetchError.new("GET #{url}: HTTP 503 starting")
    body = Beacon.document_json(document_for(issuer, signed, [["tcp", "127.0.0.1:#{seed.port}"]]))
    stub_http_get([late, body]) do |calls|
      peer = track(Peer.new(Identity.generate, nil))
      started = monotonic
      result = peer.bootstrap(url, group_id: signed["advertisement"]["group"], allow_plain: true,
                                   beacon_peer: issuer.peer_id)
      elapsed = monotonic - started
      assert_equal signed, result
      assert peer.connected?
      assert_equal 2, calls.size, "asked again on the second slice"
      assert(calls.all? { |_, t| t <= 3.0 }, "each fetch is held to the per-attempt timeout")
      assert_operator elapsed, :>=, 0.9
      assert_operator elapsed, :<, 3.0, "joined on the 1 s slice, took #{elapsed.round(2)}s"
      wait_until { seed.kinds.size >= 1 }
      assert_equal "RUMOR", seed.kinds.first
    end
  end

  def test_bootstrap_fetches_again_when_the_document_names_no_seed_yet
    issuer = Identity.generate
    founder = Identity.generate
    seed = track(Testing::FakeSeed.new)
    signed = founding(founder)
    empty = document_for(issuer, signed, [["dtls", "seed-a.corp.example:7500"]])
    full = document_for(issuer, signed, [["tcp", "127.0.0.1:#{seed.port}"]])
    stub_http_get([Beacon.document_json(empty), Beacon.document_json(full)]) do |calls|
      peer = track(Peer.new(Identity.generate, nil))
      peer.bootstrap("http://127.0.0.1:1#{Beacon::WELL_KNOWN}", group_id: signed["advertisement"]["group"],
                                                                 allow_plain: true)
      assert_equal 2, calls.size
      assert peer.connected?
      assert_equal [tcp("127.0.0.1", seed.port)], peer.seeds
      assert_equal signed, peer.founding, "the founding of the document that named the seed"
    end
  end

  def test_bootstrap_dials_again_a_seed_that_starts_late
    issuer = Identity.generate
    dead = dead_port
    signed, served = served_document_at(issuer, Identity.generate, dead)
    late = []
    starter = Thread.new do
      sleep 0.4
      late << track(Testing::FakeSeed.new(dead))
    end
    peer = track(Peer.new(Identity.generate, nil))
    started = monotonic
    result = peer.bootstrap(served.url, group_id: signed["advertisement"]["group"], allow_plain: true)
    elapsed = monotonic - started
    starter.join
    assert_equal signed, result
    assert peer.connected?
    assert_equal 1, served.requests_made.size, "a document that named a seed is not fetched again"
    assert_operator elapsed, :>=, 0.9
    assert_operator elapsed, :<, 3.0, "reached on the second slice, took #{elapsed.round(2)}s"
    wait_until { late.any? && late[0].kinds.size >= 1 }
    assert_equal 1, late[0].connections.size, "one dial per slice reached it"
  end

  def test_bootstrap_reports_the_counts_when_the_budget_is_spent
    issuer = Identity.generate
    signed, served = served_document_at(issuer, Identity.generate, dead_port)
    peer = track(Peer.new(Identity.generate, nil))
    started = monotonic
    error = assert_raises(IOError) do
      peer.bootstrap(served.url, group_id: signed["advertisement"]["group"], allow_plain: true, join_timeout: 1.5)
    end
    elapsed = monotonic - started
    assert_operator elapsed, :>=, 1.4
    assert_operator elapsed, :<, 2.5, "finished near the budget, took #{elapsed.round(2)}s"
    assert_kind_of BootstrapTimeout, error
    assert_equal [1, 1, 0], [error.fetches, error.dialed, error.connected]
    assert_includes error.message, "1 fetch(es)"
    assert_includes error.message, "0 of 1 seed(s) connected"
    assert_match(/refused/i, error.message)
    assert_equal 1, served.requests_made.size, "the document named a seed, so it was not fetched again"
    refute peer.connected?
  end

  def test_bootstrap_counts_every_fetch_when_the_beacon_never_answers
    stub_http_get([Beacon::FetchError.new("connection refused")]) do |calls|
      peer = Peer.new(Identity.generate, nil)
      started = monotonic
      error = assert_raises(BootstrapTimeout) do
        peer.bootstrap("http://127.0.0.1:1/.well-known/agentspaces/beacon.json", allow_plain: true,
                                                                                join_timeout: 1.5)
      end
      elapsed = monotonic - started
      assert_operator elapsed, :>=, 1.4
      assert_operator elapsed, :<, 2.5
      assert_equal 2, calls.size, "asked at 0 s and at 1 s"
      assert_equal 2, error.fetches
      assert_equal 0, error.dialed
      assert_includes error.message, "2 fetch(es), 0 of 0 seed(s) connected"
      assert_includes error.message, "connection refused"
    end
  end

  # ------------------------------------------------------------ join_invite

  def social_document(issuer, seed, delegation: nil, founding: nil)
    group = Beacon.document_group("weekend-hack", SOCIAL["group_id"], founding || SOCIAL["founding_cbor_base64"],
                                  [["tcp", "127.0.0.1:#{seed.port}"]], invite: delegation)
    Beacon.sign_document(issuer, SOCIAL["founding_issued"], 300, [group])
  end

  def candidate = Identity.from_seed([SOCIAL["candidate_seed_hex"]].pack("H*"))

  def test_join_invite_derives_the_golden_credential_and_carries_it_as_the_join_hint
    seed = track(Testing::FakeSeed.new)
    issued_s = ms(SOCIAL["founding_issued"]) / 1000.0
    # The compact key carries no delegation: it comes from the document's invite field.
    doc = social_document(Identity.generate, seed, delegation: SOCIAL["delegation_base64"])
    stub_http_get([Beacon.document_json(doc)]) do |calls|
      peer = track(Peer.new(candidate, nil, clock: -> { issued_s }))
      content_key, group_id = peer.join_invite(SOCIAL["invite_key_compact"])
      assert_equal ["https://s.agentspaces.dev/j/#{SOCIAL['code']}"], calls.map(&:first)
      assert_equal SOCIAL["group_id"], group_id
      assert_equal SOCIAL["group_id"], peer.group
      assert_equal SOCIAL["content_key_hex"], content_key.unpack1("H*")
      assert_equal({ "aspace:join" => SOCIAL["credential"] }, peer.resource_hints)
      assert_equal SOCIAL["delegation_base64"], peer.delegation
      assert_equal CBOR.load(Base64Text.decode(SOCIAL["founding_cbor_base64"])), peer.founding
      wait_until { seed.kinds.size >= 2 }
      ad = self_ad(seed)
      # The join hint rides beside the session hint, as the Java node's does in SESSION mode, and
      # beside the recordless wire hint (srad/agentspaces-pdt.md PD-L-04).
      assert_equal({ "aspace:join" => SOCIAL["credential"], Session::HINT => "1", Peer::RECORDLESS_HINT => "1" },
                   ad["resourceHints"])
      assert_equal SOCIAL["candidate_peer_id"], ad["issuer"]
      assert_equal SOCIAL["group_id"], ad["group"]
      # The hint is bound into the signed advertisement bytes.
      signed = CBOR.load(CBOR.load(first_rumor(seed)["body"])["payload"])
      assert Identity.verify(signed["publicKey"], signed["adBytes"], signed["signature"])
      assert_equal [tcp("127.0.0.1", seed.port)], peer.refresh_seeds.call
    end
  end

  def test_join_invite_takes_the_delegation_from_the_key_and_the_host_from_it
    seed = track(Testing::FakeSeed.new)
    issued_s = ms(SOCIAL["founding_issued"]) / 1000.0
    stub_http_get([Beacon.document_json(social_document(Identity.generate, seed))]) do |calls| # no invite field
      peer = track(Peer.new(candidate, nil, clock: -> { issued_s }))
      content_key, group_id = peer.join_invite(SOCIAL["invite_key_url_with_delegation"], allow_plain: true)
      assert_equal ["http://beacon.example.org/j/#{SOCIAL['code']}"], calls.map(&:first)
      assert_equal SOCIAL["group_id"], group_id
      assert_equal SOCIAL["credential"], peer.resource_hints["aspace:join"]
      assert_equal 32, content_key.bytesize
    end
  end

  # Past the delegation's window a restarted friend still joins: the members
  # that admitted it re-admit it from memory (SPEC 5.1, v0.1.20), so the
  # client does not refuse an expired delegation, and it exposes the key
  # pinned to the delegation so the next start presents the same credential.
  def test_join_invite_after_the_window_still_presents_the_credential_and_pins_the_key
    seed = track(Testing::FakeSeed.new)
    late_s = (ms(SOCIAL["delegation_not_after"]) + 86_400_000) / 1000.0
    doc = social_document(Identity.generate, seed, delegation: SOCIAL["delegation_base64"])
    stub_http_get([Beacon.document_json(doc)]) do
      peer = track(Peer.new(candidate, nil, clock: -> { late_s }))
      peer.join_invite(SOCIAL["invite_key_compact"])
      assert_equal({ "aspace:join" => SOCIAL["credential"] }, peer.resource_hints)
      pinned = Social::InviteKey.parse(peer.pinned_invite)
      assert_equal SOCIAL["delegation_base64"], pinned.delegation
      assert_equal SOCIAL["code"], pinned.code
    end
  end

  def test_join_invite_refuses_a_document_whose_founding_is_not_the_delegations_group
    seed = track(Testing::FakeSeed.new)
    issued_s = ms(SOCIAL["founding_issued"]) / 1000.0
    other = Founding.found(Identity.generate, "weekend-hack", "INVITE", "LEASE_RACE", 3, "PT1S",
                           SOCIAL["founding_issued"], "PT8760H")
    doc = social_document(Identity.generate, seed, delegation: SOCIAL["delegation_base64"],
                                                   founding: Base64Text.encode(CBOR.dump(other)))
    doc["groups"][0]["id"] = "aspace://#{other['advertisement']['group']}"
    doc = Beacon.sign_document(Identity.generate, SOCIAL["founding_issued"], 300, doc["groups"])
    stub_http_get([Beacon.document_json(doc)]) do
      peer = track(Peer.new(Identity.generate, nil, clock: -> { issued_s }))
      assert_raises(ArgumentError) { peer.join_invite(SOCIAL["invite_key_compact"]) }
      refute_includes peer.resource_hints, "aspace:join"
      refute peer.connected?
      assert_empty seed.connections
    end
  end

  # Since SPEC v0.1.20 an expired delegation is the members' call, not the
  # client's: they re-admit a peer they admitted in time and refuse a
  # newcomer. The client still refuses what can never admit: a document and
  # a key with no delegation.
  def test_join_invite_leaves_an_expired_delegation_to_the_members_and_refuses_a_document_without_one
    seed = track(Testing::FakeSeed.new)
    stub_http_get([Beacon.document_json(social_document(Identity.generate, seed))]) do
      peer = track(Peer.new(Identity.generate, nil))
      assert_raises(ArgumentError) { peer.join_invite(SOCIAL["invite_key_compact"]) }
    end
  end

  def test_the_self_advertisement_carries_canonical_resource_hints
    identity = Identity.generate
    ad = Wire.peer_advertisement("zG", identity, "2026-10-14T00:00:00Z", "PT10M",
                                 { "zz" => "1", "aspace:join" => "d1:x", "a" => "2" })
    assert_equal %w[a zz aspace:join], ad["resourceHints"].keys, "shorter keys first, then bytewise"
    assert_equal({}, Wire.peer_advertisement("zG", identity, "2026-10-14T00:00:00Z")["resourceHints"])
  end
end
