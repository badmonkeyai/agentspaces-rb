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

require "logger"
require "stringio"
require_relative "test_helper"
require "agentspaces/cli"

# AppCard origin and formats, 2026-11-09 (SPEC §6.1a.5 v0.1.32, FR-6, FR-7,
# FR-12 to FR-15): a card past the spill threshold travels as a stub whose
# parts sit in a content-swarm document. This client runs no content swarm,
# so it never spills and issues none of the gated fields (a dial-only client
# cannot see every member's hints); it reads every stub and resolves one
# through the spill store attached to the peer.
class CardSpillTest < Minitest::Test
  include AgentSpaces
  include GoldenHelpers

  NOW = Instants.parse_millis("2026-11-09T09:05:00Z")

  # The parts documents a holder serves, by root (Java's MemorySpillStore).
  class MemoryStore
    attr_reader :gets

    def initialize(documents = {})
      @documents = documents
      @gets = 0
    end

    def get(root, _size)
      @gets += 1
      @documents.fetch(root) { raise IOError, "no holder serves #{root}" }
    end
  end

  def app_stub = CBOR.load(hex("app_card_spill_cbor"))

  def agent_stub = CBOR.load(hex("agent_card_spill_cbor"))

  def app_parts = Schema.load("AppCard.Parts", hex("app_card_parts_cbor"))

  def agent_parts = Schema.load("AgentCard.Parts", hex("agent_card_parts_cbor"))

  def peer(**options)
    Peer.new(Identity.generate, "zApps", clock: -> { NOW / 1000.0 }, **options)
  end

  # ------------------------------------------------------------- the records

  def test_the_constants_and_spill_sets_match_java
    assert_equal GOLDEN["card_spill_threshold_bytes"], Cards::CARD_SPILL_THRESHOLD_BYTES
    assert_equal GOLDEN["card_spill_warn_bytes"], Cards::CARD_SPILL_WARN_BYTES
    assert_equal 65_536, Cards::CARD_SPILL_PIECE_SIZE
    assert_equal 16_777_216, Cards::CARD_SPILL_MAX_FETCH_BYTES
    assert_equal (2**53) - 1, Cards::CARD_SPILL_MAX_SIZE
    assert_equal 59, Cards::CARD_SPILL_ROOT_LENGTH
    assert_equal %w[reads actions views ui], Cards::APP_CARD_SPILL_SET
    assert_equal %w[actions ui], Cards::AGENT_CARD_SPILL_SET
  end

  def test_each_stub_names_its_parts_document_by_root_and_length
    [["app_card_spill_cbor", "AppCard", "app_card_parts_cbor"],
     ["agent_card_spill_cbor", "AgentCard", "agent_card_parts_cbor"]].each do |stub_name, kind, parts_name|
      stub = Schema.load(kind, hex(stub_name))
      document = hex(parts_name)
      assert_equal document, CBOR.dump(Schema.load("#{kind}.Parts", document)), parts_name
      assert_equal Cards.content_root(document), stub["spill"]["root"], stub_name
      assert_equal document.bytesize, stub["spill"]["size"], stub_name
    end
  end

  # Java's three-piece content root (golden content_root_cidv1): pieces of
  # 65,536 bytes of 0x01 and 0x02, then 100 bytes of 0x03.
  def test_the_content_root_splits_a_document_into_pieces_as_java_does
    document = ("\x01".b * 65_536) + ("\x02".b * 65_536) + ("\x03".b * 100)
    assert_equal GOLDEN["content_root_cidv1"], Cards.content_root(document)
  end

  def test_parts_stub_and_complete_round_trip_both_kinds
    [[app_stub, app_parts, "AppCard"], [agent_stub, agent_parts, "AgentCard"]].each do |stub, parts, kind|
      full = Cards.card_complete(stub, parts)
      Schema.check(kind, full)
      refute full.key?("spill")
      assert_equal CBOR.dump(parts), CBOR.dump(Cards.card_parts(full)), kind
      assert_equal CBOR.dump(stub), CBOR.dump(Cards.card_stub(full, stub["spill"])), kind
      assert_raises(ArgumentError) { Cards.card_parts(stub) }
      assert_raises(ArgumentError) { Cards.card_complete(full, parts) }
    end
    full = Cards.card_complete(app_stub, app_parts)
    assert_equal app_parts["ui"], full["ui"]
    assert_equal Schema::RECORDS["AppCard"].map(&:first) & full.keys, full.keys, "the fields in record order"
    assert_raises(ArgumentError) { Cards.card_stub(full, app_stub["spill"].merge("parts" => %w[reads ui])) }
    assert_raises(ArgumentError) { Cards.card_complete(app_stub, app_parts.merge("views" => [])) }
  end

  def test_parts_lists_only_the_non_empty_fields_in_field_order
    full = Cards.card_complete(app_stub, app_parts)
    assert_equal %w[reads views ui], Cards.non_empty_parts(Cards.card_parts(full))
    bare = full.merge("reads" => [], "views" => [])
    bare.delete("ui")
    assert_equal [], Cards.non_empty_parts(Cards.card_parts(bare.merge("shape" => "static")))
    assert_equal %w[actions ui], Cards.non_empty_parts(agent_parts)
  end

  def test_a_stub_holds_its_rules
    spill = app_stub["spill"]
    root = spill["root"]
    [root.upcase, root[0..-2], "#{root[0..-2]}z", root.sub(/\Ab/, "z")].each do |bad|
      assert_raises(Schema::Error, bad) { Schema.check("AppCard", app_stub.merge("spill" => spill.merge("root" => bad))) }
    end
    [0, -1, 2**53].each do |size|
      assert_raises(Schema::Error, size.to_s) { Schema.check("AppCard", app_stub.merge("spill" => spill.merge("size" => size))) }
    end
    Schema.check("AppCard", app_stub.merge("spill" => spill.merge("size" => (2**53) - 1)))
    assert_raises(Schema::Error) { Schema.check("AppCard", app_stub.merge("spill" => spill.merge("parts" => %w[reads reads ui]))) }
    assert_raises(Schema::Error) { Schema.check("AppCard", app_stub.merge("reads" => ["zApps/items"])) }
    assert_raises(Schema::Error) { Schema.check("AppCard", app_stub.merge("spill" => spill.merge("parts" => %w[reads views]))) }
    agent = agent_stub
    assert_raises(Schema::Error) { Schema.check("AgentCard", agent.merge("spill" => agent["spill"].merge("parts" => %w[ui actions]))) }
    assert_raises(Schema::Error) { Schema.check("AgentCard", agent.merge("spill" => agent["spill"].merge("parts" => %w[goals]))) }
    assert_raises(Schema::Error) do
      Schema.check("AgentCard", agent.except("spill").merge("ui" => agent_parts["ui"], "spill" => agent["spill"]))
    end
  end

  # ---------------------------------------------------------------- the hint

  def test_the_peer_advertises_the_app_card_level
    assert_equal "2", peer.wire_hints[Peer::APPCARD_HINT]
    assert_equal "wire.appcard", Peer::APPCARD_HINT
    refute peer(appcard_level: 1).wire_hints.key?(Peer::APPCARD_HINT)
    [0, 3, "2"].each { |level| assert_raises(ArgumentError) { peer(appcard_level: level) } }
  end

  # ------------------------------------------------------------ the publisher

  def app_card_with(**fields)
    CBOR.load(hex("app_card_host_cbor")).merge("issued" => "2026-11-09T09:00:00Z").merge(fields.transform_keys(&:to_s))
  end

  def test_a_dial_only_peer_issues_no_gated_field
    publisher = peer
    mine = publisher.identity.peer_id
    gated = app_card_with(issuer: mine, id: "aspace://zApps/app/#{mine}/support-chat", origin: { "system" => "console", "ref" => "example-console/chat", "version" => "" },
                          formats: ["text/html"])
    publisher.publish_ad("AppCard", gated)
    held = publisher.ads[gated["id"]]["ad"]
    refute held.key?("origin")
    refute held.key?("formats")
    refute held.key?("host"), "an idp host is a v0.1.32 value"
    assert_equal 1, publisher.app_cards_downgraded
    none = app_card_with(issuer: mine, id: "aspace://zApps/app/#{mine}/support-chat", host: CBOR.load(hex("app_card_host_cbor"))["host"].merge("signOn" => "none"))
    publisher.publish_ad("AppCard", none.merge("id" => "#{none['id']}-open"))
    assert_equal "none", publisher.ads["#{none['id']}-open"]["ad"]["host"]["signOn"]
    assert_equal 1, publisher.app_cards_downgraded, "a card with nothing gated is issued as it stands"
    assert_raises(ArgumentError) { publisher.publish_ad("AppCard", app_stub) }
  end

  # An old writer's card that Java's constructors refuse never goes out: every
  # reader would drop it (kind realm, signOn tenant, a broken origin).
  def test_publish_refuses_a_card_no_reader_decodes
    publisher = peer
    mine = publisher.identity.peer_id
    sent = []
    publisher.define_singleton_method(:send_frame) { |kind, _body| sent << kind }
    host = CBOR.load(hex("app_card_host_cbor"))["host"]
    [app_card_with(kind: "realm"), app_card_with(host: host.merge("signOn" => "tenant")),
     app_card_with(origin: { "system" => "Realm Two", "ref" => "r", "version" => "" }),
     app_card_with(formats: ["Text/HTML"])].each_with_index do |card, n|
      card = card.merge("issuer" => mine, "id" => "aspace://zApps/app/#{mine}/old-#{n}")
      assert_raises(Schema::Error, n.to_s) { publisher.publish_ad("AppCard", card) }
    end
    assert_empty sent
    assert_equal 0, publisher.app_cards_downgraded
    assert_raises(ArgumentError) { publisher.publish_ad("AgentCard", agent_stub) }
  end

  # An AgentCard of an exact encoded size, each under a later issued so the
  # cache takes it as a newer version: a long text travels in chunks, so
  # a short goal tops the description up.
  def big_agent_card(identity, bytes)
    @second = (@second || -1) + 1
    issued = format("2026-11-09T09:00:%02dZ", @second)
    card = ->(n, m) { Wire.agent_card("zApps", identity, "big", issued, "PT15M", "d" * n, ["g" * m], [], [], {}, {}) }
    n = bytes - CBOR.dump(card.call(0, 0)).bytesize
    n -= 1 while CBOR.dump(card.call(n, 0)).bytesize > bytes
    m = (0..32).find { |k| CBOR.dump(card.call(n, k)).bytesize == bytes }
    card.call(n, m)
  end

  def test_a_large_card_warns_once_and_travels_inline
    log = StringIO.new
    identity = Identity.generate
    publisher = Peer.new(identity, "zApps", clock: -> { NOW / 1000.0 }, logger: Logger.new(log))
    under_warning = big_agent_card(identity, Cards::CARD_SPILL_WARN_BYTES)
    assert_equal Cards::CARD_SPILL_WARN_BYTES, CBOR.dump(under_warning).bytesize
    publisher.publish_ad("AgentCard", under_warning)
    assert_empty log.string
    warned = big_agent_card(identity, Cards::CARD_SPILL_WARN_BYTES + 1)
    2.times { publisher.publish_ad("AgentCard", warned) }
    assert_equal 1, log.string.scan("past the 57344-byte warning").size, "once per card id and size"
    assert_match(/AgentCard #{Regexp.escape(warned['id'])} encodes to 57345 bytes/, log.string)
    assert_match(/spill threshold is 65536 bytes/, log.string)
    assert_equal 0, publisher.cards_oversize_inline
    at_threshold = big_agent_card(identity, Cards::CARD_SPILL_THRESHOLD_BYTES)
    publisher.publish_ad("AgentCard", at_threshold)
    assert_equal 0, publisher.cards_oversize_inline, "a card of 65,536 bytes is not oversize"
    over = big_agent_card(identity, Cards::CARD_SPILL_THRESHOLD_BYTES + 1)
    publisher.publish_ad("AgentCard", over)
    assert_equal 1, publisher.cards_oversize_inline
    assert_equal over, publisher.ads[over["id"]]["ad"], "it travels inline in full"
    assert_match(/encodes to 65537 bytes.*travels inline, since this client runs no content swarm/, log.string)
  end

  # --------------------------------------------------------------- resolution

  def test_resolve_completes_a_stub_from_its_parts_document
    reader = peer
    card = CBOR.load(hex("app_card_host_cbor"))
    assert_same card, reader.resolve(card), "a card without spill resolves to itself"
    store = MemoryStore.new(app_stub["spill"]["root"] => hex("app_card_parts_cbor"),
                            agent_stub["spill"]["root"] => hex("agent_card_parts_cbor"))
    reader.spill_store = store
    assert_equal Cards.card_complete(app_stub, app_parts), reader.resolve(app_stub)
    assert_equal Cards.card_complete(agent_stub, agent_parts), reader.resolve(agent_stub)
    assert_equal 0, reader.spills_refused
  end

  def test_resolve_fails_without_a_store_and_above_the_fetch_bound
    reader = peer
    error = assert_raises(Peer::ResolveError) { reader.resolve(app_stub) }
    assert_match(/no content swarm/, error.message)
    assert_equal Cards::CARD_SPILL_MAX_FETCH_BYTES, reader.spill_max_fetch_bytes
    small = peer(spill_max_fetch_bytes: 451)
    small.spill_store = store = MemoryStore.new
    assert_raises(Peer::ResolveError) { small.resolve(app_stub) }
    assert_equal 1, small.spills_over_limit
    assert_equal 0, store.gets, "it fails before any fetch"
    assert_raises(ArgumentError) { peer(spill_max_fetch_bytes: 0) }
  end

  # A stub that names served by its own root and length, so only the rule a
  # case targets refuses it.
  def naming(stub, served)
    stub.merge("spill" => stub["spill"].merge("root" => Cards.content_root(served), "size" => served.bytesize))
  end

  def refused(stub, served)
    reader = peer
    reader.spill_store = MemoryStore.new(stub["spill"]["root"] => served)
    error = assert_raises(Peer::ResolveError) { reader.resolve(stub) }
    assert_equal 1, reader.spills_refused
    error.message
  end

  def test_a_document_that_does_not_complete_its_stub_is_refused_and_counted
    document = hex("app_card_parts_cbor")
    assert_match(/453 bytes; the stub states 452/, refused(app_stub, document + "\x00".b))
    longer = app_stub.merge("spill" => app_stub["spill"].merge("size" => document.bytesize + 1))
    assert_match(/452 bytes; the stub states 453/, refused(longer, document), "a document of another length than spill.size")
    wrong_parts = CBOR.dump(app_parts.merge("views" => []))
    ["\xFF".b * 452, wrong_parts + ("\x00".b * (452 - wrong_parts.bytesize))].each do |served|
      message = refused(naming(app_stub, served), served)
      refute_match(/content root|the stub states|the parts document holds/, message, "a document that does not decode")
    end
    assert_match(/the parts document holds \["reads", "ui"\] where the stub names/,
                 refused(naming(app_stub, wrong_parts), wrong_parts), "non-empty fields other than spill.parts")
    foreign = CBOR.dump(agent_parts.merge("actions" => [agent_parts["actions"][0].merge("name" => "other")]))
    assert_match(/not an action of the card/, refused(naming(agent_stub, foreign), foreign),
                 "a document that completes into a card Java's AgentCard refuses")
  end

  # A holder that serves other bytes of the same length and shape: the root
  # names the document's bytes, so the reader refuses it (FR-15, issue §7.2).
  def test_a_tampered_document_of_the_same_length_and_shape_is_refused
    forged = CBOR.dump(app_parts.merge("views" => app_parts["views"].map { |view| view.tr("a", "b") }))
    assert_equal hex("app_card_parts_cbor").bytesize, forged.bytesize
    assert_equal Cards.non_empty_parts(app_parts), Cards.non_empty_parts(Schema.load("AppCard.Parts", forged))
    reader = peer
    reader.spill_store = MemoryStore.new(app_stub["spill"]["root"] => forged)
    error = assert_raises(Peer::ResolveError) { reader.resolve(app_stub) }
    assert_match(/content root .* is not spill.root/, error.message)
    assert_equal 1, reader.spills_refused
  end

  def test_a_store_refusal_counts_and_a_fetch_failure_does_not
    refusing = Object.new
    def refusing.get(root, size) = raise(ArgumentError, "the artifact #{root} is 9 bytes; the stub states #{size}")
    reader = peer
    reader.spill_store = refusing
    assert_raises(Peer::ResolveError) { reader.resolve(app_stub) }
    assert_equal 1, reader.spills_refused
    reader.spill_store = MemoryStore.new
    assert_raises(IOError) { reader.resolve(app_stub) }
    assert_equal 1, reader.spills_refused, "no holder served it: no check failed"
  end

  def test_status_names_the_parts_a_cached_card_spilled
    issuer = Identity.generate
    stub = agent_stub.merge("id" => "aspace://zApps/agent/#{issuer.peer_id}/researcher", "issuer" => issuer.peer_id,
                            "agent" => "#{issuer.peer_id}/researcher")
    reader = peer
    refute_nil reader.accept_ad(Wire.stored_ad("AgentCard", stub, issuer))
    out = StringIO.new
    cli = CLI.new(out: out, err: StringIO.new)
    cli.define_singleton_method(:sleep) { |_seconds| nil }
    start = AgentSpaces.method(:start)
    AgentSpaces.define_singleton_method(:start) { |*_args, **_options| reader }
    begin
      assert_equal 0, cli.run(%w[status fleet.yaml])
    ensure
      AgentSpaces.define_singleton_method(:start, start)
    end
    assert_match(%r{  #{Regexp.escape(stub['agent'])}: Researches a topic and writes a finding\n    spilled: actions, ui \(in its parts document\)\n},
                 out.string)
  end

  def test_a_failed_resolution_keeps_the_cached_stub
    issuer = Identity.from_pkcs8(hex("private_key_pkcs8"))
    stub = app_stub.merge("issuer" => issuer.peer_id, "id" => "aspace://zApps/app/#{issuer.peer_id}/example-board")
    reader = peer
    refute_nil reader.accept_ad(Wire.stored_ad("AppCard", stub, issuer))
    reader.spill_store = MemoryStore.new(stub["spill"]["root"] => "\x00".b * 452)
    assert_raises(Peer::ResolveError) { reader.resolve(stub) }
    assert_equal stub, reader.ads[stub["id"]]["ad"]
  end
end
