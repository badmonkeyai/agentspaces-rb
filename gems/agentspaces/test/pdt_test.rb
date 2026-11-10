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

# The persistent trees, read from Ruby (srad/agentspaces-pdt.md PD-C-06,
# PD-N-07, PD-L-04): every pdt_* and content_* tree vector of the vendored
# golden.json decodes by kind and re-encodes byte for byte, maps, vectors, and
# blobs read over a node store, a PRef head derefs with its inline delta
# applied and several heads merge as 3.6.1 says, the tree exchange fetches a
# root from a holder with the pinned message forms, and a recordless renew
# merges over a held record or waits for it.
class PdtTest < Minitest::Test
  include GoldenHelpers
  include AgentSpaces::PDT

  T0 = "2025-01-01T00:00:00Z"
  ENTRY = "11111111-2222-3333-4444-555555555555"

  def store_with(*names)
    store = NodeStore.new
    names.each { |name| store.put(hex(name)) }
    store
  end

  # ------------------------------------------------------------------ cids and nodes

  def test_cids_parse_and_refuse_by_name
    root, *chunks = GOLDEN["pdt_blob_small"].split(",")
    parsed = Cids.parse(root)
    assert_equal Cids::DAG_CBOR, parsed.codec
    assert_equal 32, parsed.digest.bytesize
    assert_equal root, Cids.from_binary(Cids.binary(root))
    assert chunks.all? { |c| Cids.codec_of(c) == Cids::RAW }
    assert Cids.cid?(root)
    refute Cids.cid?(root[0..-2])
    refute Cids.cid?("z#{root[1..]}")
    bad_codec = "b" + Cids.base32_lower([0x01, 0x70, 0x12, 0x20].pack("C*") + parsed.digest)
    error = assert_raises(ArgumentError) { Cids.parse(bad_codec) }
    assert_includes error.message, "unknown codec"
    bad_hash = "b" + Cids.base32_lower([0x01, 0x71, 0x1E, 0x20].pack("C*") + parsed.digest)
    error = assert_raises(ArgumentError) { Cids.parse(bad_hash) }
    assert_includes error.message, "multihash"
  end

  def test_every_node_vector_decodes_by_kind_and_reencodes_byte_for_byte
    kinds = { "pdt_map_empty" => "m", "pdt_map_small" => "m", "pdt_map_deep" => "m", "pdt_node_dagcbor" => "m",
              "pdt_node_embedded" => "m", "pdt_vector_tail" => "vr", "pdt_vector_deep" => "vr" }
    kinds.each do |name, kind|
      data = hex(name)
      node = Nodes.decode(data, Cids.of(data))
      assert_equal kind, node["k"], name
      assert_equal data, Nodes.encode(node), "#{name} re-encodes"
      assert_equal kind, Nodes.kind_of(data)
    end
    assert_equal hex("pdt_map_small"), hex("pdt_node_dagcbor")
    deep = Nodes.decode(hex("pdt_map_deep"))
    assert_equal 100, deep["cnt"]
    assert_equal 25, Nodes.links(hex("pdt_map_deep")).size
    assert_equal 0, Nodes.links(hex("pdt_map_small")).size
    tail = Nodes.decode(hex("pdt_vector_tail"))
    assert_equal [10, 5, nil, 10], [tail["n"], tail["s"], tail["r"], tail["t"].size]
    vdeep = Nodes.decode(hex("pdt_vector_deep"))
    assert_equal [1100, 10, 1100 - 1088], [vdeep["n"], vdeep["s"], vdeep["t"].size]
    assert_equal [vdeep["r"].cid], Nodes.links(hex("pdt_vector_deep"))
    embedded = Nodes.decode(hex("pdt_node_embedded"))
    items = embedded["e"].map(&:bytes)
    assert_includes items, ["bf61780161796374776fff"].pack("H*") # the indefinite-length map CborCodec writes
    assert_includes items, ["fa3fc00000"].pack("H*")             # the 32-bit float
    # the bounds of PD-N-04 are refused by name
    error = assert_raises(NodeFormatError) { Nodes.decode(["a1616b6173"].pack("H*")) }
    assert_includes error.message, "reserved"
    error = assert_raises(NodeFormatError) { Nodes.decode(["a1616b6171"].pack("H*")) }
    assert_includes error.message, "unknown kind"
    error = assert_raises(NodeFormatError) { Nodes.decode(["a2616b616d617a00"].pack("H*")) }
    assert_includes error.message, "outside the schema"
    # a sealed node (PD-P-05) decodes as an sn envelope: its kind, epoch, and links in the clear
    # are what a keyless holder walks; opening it takes the epoch's key, which this face has not
    sealed = Nodes.decode(hex("pdt_sealed_node"))
    assert_equal "sn", sealed["k"]
    assert_equal 3, sealed["ep"]
    assert_equal [], sealed["ln"]
    assert_equal 12, sealed["nc"].bytesize
    assert_equal hex("pdt_map_small").bytesize + 16, sealed["ct"].bytesize
    assert_equal [], Nodes.links(hex("pdt_sealed_node"))
  end

  # ------------------------------------------------------------------ maps

  def test_maps_read_their_entries_and_counts_from_the_vectors
    store = store_with("pdt_map_empty", "pdt_map_small", "pdt_map_deep", "pdt_node_embedded")
    loader = StoreLoader.new(store)
    empty = PMap.load(Cids.of(hex("pdt_map_empty")), loader)
    assert_equal 0, empty.count
    assert_empty empty.to_h
    small = PMap.load(Cids.of(hex("pdt_map_small")), loader)
    assert_equal 2, small.count
    assert_equal 1, small["a"]
    assert_equal "two", small.fetch("b")
    assert_nil small["c"]
    assert small.key?("a")
    refute small.key?("zz")
    assert_equal({ "a" => 1, "b" => "two" }, small.to_h)
    assert_equal %w[a b].sort, small.keys.sort
    assert_raises(KeyError) { small.fetch("c") }
    embedded = PMap.load(Cids.of(hex("pdt_node_embedded")), loader)
    assert_equal({ "x" => 1, "y" => "two" }, embedded["rec"])
    # Java's 1.5f reads as a float32 and keeps its width (HLC round six, 2026-11-08 (F2))
    assert_equal AgentSpaces::CBOR::Float32.new(1.5), embedded["f"]
    deep = PMap.load(Cids.of(hex("pdt_map_deep")), loader)
    assert_equal 100, deep.count
    # a key that sits inline in the root reads; one under a child this store lacks says which node
    root_keys = Nodes.decode(hex("pdt_map_deep"))["e"].each_slice(2).map { |k, _| AgentSpaces::CBOR.load(k.bytes) }
    refute_empty root_keys
    root_keys.each { |k| assert_equal Integer(k[1..]), deep[k] }
    under_child = ((0...100).map { |i| "k#{i}" } - root_keys).first
    error = assert_raises(NodeUnavailable) { deep[under_child] }
    assert_includes Nodes.links(hex("pdt_map_deep")), error.cid
    error = assert_raises(NodeUnavailable) { deep.to_h }
    assert Cids.cid?(error.cid)
    # a set is a map read as its keys
    set = PSet.load(Cids.of(hex("pdt_map_small")), loader)
    assert_equal 2, set.count
    assert set.include?("a")
    assert_equal Set.new(%w[a b]), set.to_set
  end

  # HLC round six, 2026-11-08 (F2, definition 2.4, Java change JD-4): every
  # embedded item of a node is an application value under rules S1 to S12,
  # judged by its own bytes, so a node holding an item Java's NodeCodec
  # refuses does not decode here either. Each node is the golden
  # pdt_node_embedded with its 1.5f replaced by the item.
  EMBEDDED_FLOAT = "fa3fc00000"

  def node_holding(item_hex)
    golden = GOLDEN.fetch("pdt_node_embedded")
    assert_equal 1, golden.scan(EMBEDDED_FLOAT).size
    [golden.sub(EMBEDDED_FLOAT, item_hex)].pack("H*")
  end

  def test_a_node_whose_embedded_item_breaks_the_wire_encoding_does_not_decode
    {
      "c24101" => "tag 2 inside a long (S9)",
      "c482211896" => "tag 4 unnormalized 1.50 (S9)",
      "c4823a7fffffff01" => "tag 4 exponent -2^31 (S9)",
      "c06161" => "tag 0 over text",
      "c11a5f000000" => "tag 1 over an int",
      "d9d9f701" => "tag 55799 over an int",
      "d82a420001" => "tag 42 over bytes 00 01, no CID (PD-N-05)",
      "7f6161ff" => "indefinite text of one chunk (S6)",
      "a1616101" => "definite map (S8)",
      "f93e00" => "half float (S10)",
      "fbfff8000000000000" => "a NaN Java does not write (S10)",
      "1801" => "an integer under a wider head (S3)",
      "f7" => "undefined (S11)",
      "bf616101616102ff" => "duplicate map key (S8)"
    }.each do |item, why|
      assert_raises(NodeFormatError, "the node holding #{item} (#{why}) does not decode") { Nodes.decode(node_holding(item)) }
    end
  end

  def test_a_node_whose_embedded_items_keep_the_wire_encoding_decodes
    {
      "c249010000000000000000" => 1 << 64,
      "c349008000000000000001" => -(1 << 63) - 1,
      "c482200f" => BigDecimal("1.5"),
      "c48200c24e04ee2d6d415b85acef8100000001" => BigDecimal("100000000000000000000000000000001"),
      "bf616201616102ff" => { "b" => 1, "a" => 2 }
    }.each do |item, value|
      embedded = Nodes.decode(node_holding(item))["e"][1]
      assert_equal [item].pack("H*"), embedded.bytes
      assert_equal value, AgentSpaces::CBOR.load(embedded.bytes), "the node holding #{item} decodes"
    end
  end

  # HLC round six, 2026-11-08 (S2, JD-4): the node's own list adds no level
  # to an embedded item and a tag adds none to its content, as Java's
  # NodeCodec counts them, so an item of 64 containers decodes in a node, and
  # so does a decimal inside 63; one of 65 does not.
  def test_an_embedded_item_counts_its_nesting_from_its_own_bytes
    nest = ->(levels, inner) { levels.times.reduce(inner) { |value, _| [value] } }
    [nest.call(64, 1), nest.call(63, BigDecimal("1.5"))].each do |value|
      item = AgentSpaces::CBOR.dump(value)
      assert_equal item, Nodes.decode(node_holding(item.unpack1("H*")))["e"][1].bytes
    end
    assert_raises(NodeFormatError) { Nodes.decode(node_holding("81" * 65 + "01")) }
  end

  # HLC round six, 2026-11-08 (JD-4): a key never spills, so a link item in a
  # key slot is refused, as every reader refuses tag 42 outside a node's own
  # layer; the encoder refuses what the decoder refuses.
  def test_a_link_item_stands_only_in_a_value_slot
    link = Nodes.link_item(Cids.of(hex("pdt_map_empty"))).unpack1("H*")
    golden = GOLDEN.fetch("pdt_node_embedded")
    assert_raises(NodeFormatError) { Nodes.decode([golden.sub("6166", link)].pack("H*")) }
    assert_equal [link].pack("H*"), Nodes.decode(node_holding(link))["e"][1].bytes
    node = { "k" => "x", "v" => Nodes::Embedded.new(["c24101"].pack("H*")) }
    assert_raises(NodeFormatError) { Nodes.encode(node) }
    assert_raises(NodeFormatError) { Nodes.encode({ "k" => "mc", "e" => [Nodes::Embedded.new([link].pack("H*")), "\x01".b] }) }
  end

  def test_a_node_at_the_wrong_level_or_with_a_wrong_slot_is_refused
    store = store_with("pdt_map_small")
    data = hex("pdt_map_small")
    error = assert_raises(NodeFormatError) { ChampNode.load(Cids.of(data), 1, StoreLoader.new(store)) }
    assert_includes error.message, "'cnt' on a node that is not a map root"
    inner = Nodes.decode(data).tap { |n| n.delete("cnt") }
    child = store.put(Nodes.encode(inner))
    error = assert_raises(NodeFormatError) { ChampNode.load(child, 1, StoreLoader.new(store)) }
    assert_includes error.message, "slot"
    mc = Nodes.encode({ "k" => "mc", "e" => [AgentSpaces::CBOR.dump("a"), AgentSpaces::CBOR.dump(1)] })
    error = assert_raises(NodeFormatError) { ChampNode.load_root(Cids.of(mc), mc) }
    assert_includes error.message, "collision node at level 0"
  end

  # ------------------------------------------------------------------ vectors

  def test_vectors_read_by_index_and_iterate
    store = store_with("pdt_vector_tail", "pdt_vector_deep")
    loader = StoreLoader.new(store)
    tail = PVector.load(Cids.of(hex("pdt_vector_tail")), loader)
    assert_equal 10, tail.count
    assert_equal (0..9).to_a, tail.to_a
    assert_equal 9, tail[-1]
    assert_equal 9, tail.last
    assert_nil tail[10]
    assert_raises(IndexError) { tail.nth(10) }
    deep = PVector.load(Cids.of(hex("pdt_vector_deep")), loader)
    assert_equal 1100, deep.count
    assert_equal 1095, deep[1095] # in the tail
    assert_equal 1099, deep.last
    error = assert_raises(NodeUnavailable) { deep[5] } # under the trie this store lacks
    assert_equal Nodes.decode(hex("pdt_vector_deep"))["r"].cid, error.cid
  end

  # ------------------------------------------------------------------ blobs

  def blob_fixture
    stream = java_random_bytes(42, 100 * 1024)
    cuts = GOLDEN["pdt_fastcdc_cuts"].split(",").map(&:to_i).take_while { |c| c < stream.bytesize } + [stream.bytesize]
    chunks = cuts.each_with_index.map { |cut, i| stream.byteslice(i.zero? ? 0 : cuts[i - 1], cut - (i.zero? ? 0 : cuts[i - 1])) }
    store = NodeStore.new
    entries = chunks.map { |c| PBlob::Entry.new(store.put(c, Cids::RAW), c.bytesize) }
    root_node = Nodes.encode({ "k" => "b", "h" => 1, "c" => entries.map { |e| Nodes::Link.new(e.cid) }, "z" => entries.map(&:length) })
    [stream, store, store.put(root_node), entries]
  end

  def test_the_small_blob_vector_names_the_root_and_every_chunk_and_reads_back
    stream, store, root, entries = blob_fixture
    expected = GOLDEN["pdt_blob_small"].split(",")
    assert_equal expected[0], root
    assert_equal expected[1..], entries.map(&:cid)
    blob = PBlob.load(root, StoreLoader.new(store))
    assert_equal 100 * 1024, blob.size
    assert_equal 1, blob.height
    assert_equal expected[1..], blob.chunks.map(&:cid)
    assert_equal stream, blob.read_all
    assert_equal stream.byteslice(49_000, 2_000), blob.read(49_000, 2_000)
    assert_equal stream.byteslice(0, 10), blob.read(0, 10)
    assert_equal stream.byteslice(entries[0].length, 5), blob.read(entries[0].length, 5)
    assert_raises(IndexError) { blob.read(100 * 1024, 1) }
    # a single raw chunk is its own blob
    single = PBlob.load(entries[0].cid, StoreLoader.new(store))
    assert_equal entries[0].length, single.size
    assert_equal stream.byteslice(0, entries[0].length), single.read_all
    # a spilled byte-string value reassembles through the blob tree
    assert_equal AgentSpaces::CBOR.dump(stream), Values.resolve(root, StoreLoader.new(store))
  end

  # ------------------------------------------------------------------ refs

  def pref_dto(peer, pdt, name, pref, issued_ms, entry_id: "e-#{pref['root'][-8..]}", issuer: nil)
    issuer ||= "#{peer.identity.peer_id}/app"
    record = { "entryId" => entry_id, "spaceId" => pdt.space_id, "type" => Refs::TYPE,
               "payload" => AgentSpaces::CBOR.dump(pref), "issuer" => issuer,
               "issued" => "#{issued_ms}:0:#{issuer.split('/').first}",
               "lease" => { "expiresAtMillis" => peer.now_ms + 600_000 }, "tags" => Refs.tags(pref) }
    { "record" => record, "completed" => false, "adds" => [{ "replica" => issuer.split("/").first, "counter" => 1 }],
      "removes" => [] }
  end

  def pref(name, kind, root, base: [], seq: 1, size: 0, nodes: nil)
    r = { "v" => 1, "name" => name, "kind" => kind, "root" => root, "base" => base, "seq" => seq, "size" => size }
    r["nodes"] = nodes unless nodes.nil?
    r.merge("mode" => "multi", "sealing" => "none")
  end

  def test_the_ref_vectors_decode_within_bounds_and_a_head_applies_its_inline_delta
    record = load(hex("pdt_ref_cbor"))
    assert_nil Refs.violation(record)
    assert_equal Cids.of(hex("pdt_map_deep")), record["root"]
    assert_equal [Cids.of(hex("pdt_map_small"))], record["base"]
    assert_equal({ "name" => "facts", "root" => record["root"] }, Refs.tags(record))
    assert_equal record["nodes"].sum(&:bytesize), Refs.inline_bytes(record)
    assert_equal hex("pdt_map_deep"), record["nodes"][0]
    minimal = load(hex("pdt_ref_min_cbor"))
    assert_nil Refs.violation(minimal)
    assert_equal Cids.of(hex("pdt_map_empty")), minimal["root"]
    refute minimal.key?("nodes")
    refute minimal.key?("attrs")
    assert_equal "root is not a CID", Refs.violation(minimal.merge("root" => "not-a-cid"))
    assert_match(/seq above/, Refs.violation(minimal.merge("seq" => Refs::MAX_SEQ + 1)))
    assert_equal "more than 8 bases", Refs.violation(minimal.merge("base" => [record["root"]] * 9))
    assert_equal "unknown kind \"tuple\"", Refs.violation(minimal.merge("kind" => "tuple"))
    assert_equal "mode longer than 32 bytes", Refs.violation(minimal.merge("mode" => "x" * 33))
    assert_nil Refs.violation(minimal.merge("mode" => "later")) # an open set

    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt")
    assert_equal AgentSpaces::Derive.space_id_local("#{GOLDEN['group_id']}/pdt"), pdt.space_id
    peer.states["e-deep"] = pref_dto(peer, pdt, "facts", record, ms(T0), entry_id: "e-deep")
    facts = pdt.map_ref("facts")
    # the two inline nodes land by the walk from the root; 24 children stay missing, so the head
    # is not loadable here and, with no holder to ask, is ignored after the wait
    assert_empty facts.heads(wait: false)
    assert_equal 2, pdt.store.size
    assert_equal 24, pdt.store.missing(record["root"]).size
    assert_equal 1, facts.stats[:deltas_inline]
    assert_empty facts.history(5) # no head is held, so no earlier version is reachable
    versions = facts.versions
    assert_equal [record["root"]], versions.map(&:root)
    assert_equal [2, 100, record["base"]], [versions[0].seq, versions[0].size, versions[0].base]
    assert_equal 0, pdt.stats["headsIgnored"]
    # the minimal head's root is the empty map; held, it derefs
    peer.states["e-empty"] = pref_dto(peer, pdt, "empty", minimal.merge("name" => "empty"), ms(T0), entry_id: "e-empty")
    pdt.store.put(hex("pdt_map_empty"))
    value = pdt.map_ref("empty").deref
    assert_kind_of PMap, value
    assert_equal 0, value.count
    assert_equal 1, pdt.map_ref("empty").heads.size
    assert_empty pdt.map_ref("nothing").deref
  end

  # An entry whose tags name the ref while its PRef names another ref is no
  # head of it, as Java's Refs.toHead reads it (HLC round five, 2026-11-08,
  # adversary pass on E10 and E16).
  def test_an_entry_whose_pref_names_another_ref_is_no_head_of_it
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt")
    stray = map_node(pdt.store, { "a" => 1 })
    dto = pref_dto(peer, pdt, "facts", pref("other", "map", stray, size: 1), ms(T0), entry_id: "e-stray")
    dto["record"]["tags"] = { Refs::NAME_TAG => "facts", Refs::ROOT_TAG => stray }
    peer.states["e-stray"] = dto
    facts = pdt.map_ref("facts")
    assert_empty facts.heads
    assert_empty facts.deref
    assert_empty facts.versions
  end

  # A one-node CHAMP root for keys that fall in distinct level-0 slots.
  def map_node(store, entries)
    slots = entries.to_h { |k, v| [ChampNode.index(Cids.sha256(AgentSpaces::CBOR.dump(k)), 0), [k, v]] }
    assert_equal entries.size, slots.size, "keys share a level-0 slot; pick others"
    datamap = slots.keys.sum { |s| 1 << s }
    e = slots.keys.sort.flat_map { |s| slots[s].map { |x| AgentSpaces::CBOR.dump(x) } }
    store.put(Nodes.encode({ "k" => "m", "d" => datamap, "n" => 0, "e" => e, "c" => [], "cnt" => entries.size }))
  end

  # HLC logical counter, 2026-11-08 (Rust team report): a reader orders
  # heads only by stamps the strict parser accepts, and falls back to the
  # record's own stamp for any other. HLC round four, 2026-11-08 (D2): a
  # counter above the logical limit orders nothing either.
  def test_the_head_order_reads_no_negative_unreadable_fractional_or_above_limit_stamp
    assert_equal [5, 3, "n"], Refs.hlc("5:3:n")
    assert_equal [5, AgentSpaces::Wire::HLC_LOGICAL_LIMIT, "n"], Refs.hlc("5:#{AgentSpaces::Wire::HLC_LOGICAL_LIMIT}:n")
    ["5:-1:n", "5:x:n", "5:0x10001:n", "5:1.5:n", "-5:0:n", "5:#{AgentSpaces::Wire::HLC_LOGICAL_LIMIT + 1}:n",
     nil].each do |stamp|
      assert_equal [0, 0, ""], Refs.hlc(stamp), "the reader ignores #{stamp.inspect}"
    end
  end

  # HLC round four, 2026-11-08 (D2): Java's Refs rule. A rewrite's pdt.issued
  # orders its head with pdt.issuer, or with the entry's own issuer when
  # pdt.issuer is absent. A pdt.issued that is not canonical or carries a
  # counter above the logical limit, or a pdt.issuer that does not parse as
  # an agent id, leaves the head on the entry's own stamp and the entry's own
  # issuer together; nothing is refused or counted for it. HLC round five,
  # 2026-11-08 (E10): an absent, null, or non-text pdt.issued, and a
  # pdt.issuer present as null or as anything other than text, fall back the
  # same way; a null pdt.issuer never pairs pdt.issued with the entry's issuer.
  def test_a_head_orders_by_its_pdt_issued_and_issuer_attrs_as_javas_refs_rule_reads_them
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt")
    store = pdt.store
    first = map_node(store, { "a" => 1 })
    later = map_node(store, { "b" => 2 })
    writer = "#{AgentSpaces::Identity.generate.peer_id}/app"
    original = "#{AgentSpaces::Identity.generate.peer_id}/origin"
    peer.states["e-first"] = pref_dto(peer, pdt, "facts", pref("facts", "map", first, size: 1), ms(T0) + 1000,
                                      entry_id: "e-first")
    rewrite = lambda do |attrs|
      peer.states["e-later"] = pref_dto(peer, pdt, "facts", pref("facts", "map", later, size: 1).merge("attrs" => attrs),
                                        ms(T0) + 2000, entry_id: "e-later", issuer: writer)
      pdt.map_ref("facts").heads
    end
    heads = rewrite.call({ Refs::ISSUED_ATTR => "#{ms(T0)}:0:x", Refs::ISSUER_ATTR => original })
    assert_equal [later, first], heads.map(&:root), "the pair orders the rewrite first"
    assert_equal [[ms(T0), 0], original], [heads[0].issued.first(2), heads[0].issuer]
    heads = rewrite.call({ Refs::ISSUED_ATTR => "#{ms(T0)}:0:x" })
    assert_equal [later, first], heads.map(&:root), "pdt.issued alone orders the head"
    assert_equal writer, heads[0].issuer, "without pdt.issuer the head keeps the entry's issuer"
    above = AgentSpaces::Wire::HLC_LOGICAL_LIMIT + 1
    stamps = ["#{ms(T0)}:#{above}:x", "0#{ms(T0)}:0:x", "#{ms(T0)}:-1:x", "#{ms(T0)}:0:x".b, 5, nil, ["#{ms(T0)}:0:x"]]
    # A CBOR byte string is not text, whatever agent id its bytes spell (HLC round five, 2026-11-08 (E10)).
    issuers = ["no-slash", "/app", "#{writer.split('/').first}/", "#{writer}/deeper", 5, nil, [original], original.b]
    malformed = stamps.map { |s| { Refs::ISSUED_ATTR => s, Refs::ISSUER_ATTR => original } } +
                issuers.map { |i| { Refs::ISSUED_ATTR => "#{ms(T0)}:0:x", Refs::ISSUER_ATTR => i } } +
                [{ Refs::ISSUER_ATTR => original }]
    malformed.each do |attrs|
      heads = rewrite.call(attrs)
      assert_equal [first, later], heads.map(&:root), "#{attrs.inspect} orders nothing"
      assert_equal [[ms(T0) + 2000, 0], writer], [heads[1].issued.first(2), heads[1].issuer],
                   "#{attrs.inspect} leaves the entry's own stamp and issuer"
      assert_equal 0, pdt.stats["headsIgnored"], "#{attrs.inspect} drops no head"
    end
  end

  # The PRef of vectors pref-01 to pref-12 in /tmp/r6/vectors.json, a first
  # version of "facts" whose attrs vary.
  PREF_ROOT = "bafyreidkjik5s2clmhamebg4pk5jwpgeddo7x3bscmbb763flasgl3w4pi"
  PREF_STAMP = "1800000000000:0:z6M1N9PyyHGkJfLZRmQ4VjAypZUi5uuUm8UDMHK1YfieJ"
  PREF_ISSUER = "z6M1N9PyyHGkJfLZRmQ4VjAypZUi5uuUm8UDMHK1YfieJ/java"

  # The fields arrive in Java's declared order, a field Refs::FIELDS does not
  # name last, so each refused form below breaks only the rule it names.
  def wire_pref(fields = {})
    all = { "v" => 1, "name" => "facts", "kind" => "map", "root" => PREF_ROOT, "base" => [], "seq" => 1, "size" => 0,
            "mode" => "multi", "sealing" => "none" }.merge(fields)
    declared = Refs::FIELDS.map(&:first)
    declared.filter_map { |name| [name, all[name]] if all.key?(name) }.to_h.merge(all.except(*declared))
  end

  # Bytes with one run of hex replaced, for an item no encoder writes.
  def splice(value, from, to)
    hexed = AgentSpaces::CBOR.dump(value).unpack1("H*")
    assert_includes hexed, from
    [hexed.sub(from, to)].pack("H*")
  end

  # HLC round six, 2026-11-08 (F1, F3, R1): a PRef is a protocol record. It
  # decodes only when its fields arrive in Java's declared order, each of the
  # kind Java's record holds, the optional ones absent when null, its attrs
  # keys text in the RFC 8949 order with text under every key but pdt.issued
  # and pdt.issuer, and its bytes equal their own re-encoding. The two
  # reserved attrs hold any canonical item, since a reader falls back from a
  # value that is no stamp or no agent id.
  def test_a_pref_decodes_only_in_the_wire_encoding_with_every_field_in_order_and_of_its_kind
    accepted = {
      "pref-01" => wire_pref("attrs" => { Refs::ISSUED_ATTR => PREF_STAMP, Refs::ISSUER_ATTR => PREF_ISSUER }),
      "pref-02" => wire_pref("attrs" => { Refs::ISSUED_ATTR => 5 }),
      "pref-03" => wire_pref("attrs" => { Refs::ISSUED_ATTR => nil, Refs::ISSUER_ATTR => nil }),
      "pref-04" => wire_pref("attrs" => { Refs::ISSUER_ATTR => "\x01\x02".b }),
      "pref-05" => wire_pref("attrs" => { Refs::ISSUED_ATTR => [1, { "a" => 2 }] }),
      "pref-08" => wire_pref("attrs" => { "user" => "a", Refs::ISSUED_ATTR => PREF_STAMP }),
      "empty attrs" => wire_pref("attrs" => {}),
      "nodes and keyEpoch" => wire_pref("nodes" => ["\x01".b], "keyEpoch" => 0)
    }
    accepted.each do |label, value|
      raw = cbor(value)
      assert_equal value, Refs.decode(raw), "#{label} decodes"
    end
    %w[pdt_ref_cbor pdt_ref_min_cbor].each { |name| assert_equal load(hex(name)), Refs.decode(hex(name)), name }

    stamp_field = cbor(Refs::ISSUED_ATTR).unpack1("H*")
    refused = {
      "pref-06" => cbor(wire_pref("attrs" => { "user" => 5 })),
      "pref-07" => cbor(wire_pref("attrs" => { "user" => nil })),
      "pref-09" => cbor(wire_pref("attrs" => { Refs::ISSUED_ATTR => PREF_STAMP, "user" => "a" })),
      "pref-10" => splice(wire_pref("attrs" => { Refs::ISSUED_ATTR => 5 }), "#{stamp_field}05", "#{stamp_field}1805"),
      "pref-11" => cbor(wire_pref("seq" => 1.0)),
      "pref-12" => cbor(wire_pref("attrs" => nil)),
      "a list under another key" => cbor(wire_pref("attrs" => { "user" => ["a"] })),
      "a byte string under another key" => cbor(wire_pref("attrs" => { "user" => "a".b })),
      "a name as a byte string" => cbor(wire_pref("name" => "facts".b)),
      "a root as a byte string" => cbor(wire_pref("root" => PREF_ROOT.b)),
      "a base root as a byte string" => cbor(wire_pref("base" => [PREF_ROOT.b])),
      "a null base" => cbor(wire_pref("base" => nil)),
      "a mode as an integer" => cbor(wire_pref("mode" => 5)),
      "text where node bytes belong" => cbor(wire_pref("nodes" => ["node"])),
      "nodes present as null" => cbor(wire_pref("nodes" => nil)),
      "keyEpoch present as null" => cbor(wire_pref("keyEpoch" => nil)),
      "v as a double" => cbor(wire_pref("v" => 1.0)),
      "v past a Java int" => cbor(wire_pref("v" => 1 << 31)),
      "seq past a Java long" => cbor(wire_pref("seq" => 1 << 63)),
      "seq as a tag 2 bignum" => splice(wire_pref, "63736571" "01", "63736571" "c24101"),
      "seq as a tag 4 decimal" => splice(wire_pref, "63736571" "01", "63736571" "c4820001"),
      "seq under a wide head" => splice(wire_pref, "63736571" "01", "63736571" "1801"),
      "a missing field" => cbor(wire_pref.except("sealing")),
      "an unknown field" => cbor(wire_pref("extra" => "x")),
      "fields out of order" => cbor(wire_pref.to_a.rotate.to_h),
      "a definite map" => ["a9#{cbor(wire_pref).unpack1('H*')[2...-2]}"].pack("H*"),
      "trailing bytes" => cbor(wire_pref) + "\x00".b,
      "an array" => cbor([wire_pref])
    }
    refused.each { |label, raw| assert_nil Refs.decode(raw), "#{label} is undecodable" }
  end

  # HLC round six, 2026-11-08 (R1): the 4 KiB attrs bound counts the UTF-8
  # bytes of the keys and of the text values alone, so a non-text value under
  # pdt.issued or pdt.issuer counts nothing toward it.
  def test_the_attrs_bound_counts_the_utf8_bytes_of_keys_and_text_values
    room = Refs::MAX_ATTRS_BYTES - Refs::ISSUED_ATTR.bytesize - "k".bytesize
    at_bound = { Refs::ISSUED_ATTR => 5, "k" => "x" * room }
    assert_nil Refs.violation(wire_pref("attrs" => at_bound)), "an integer under pdt.issued counts nothing"
    assert_nil Refs.violation(wire_pref("attrs" => at_bound.merge(Refs::ISSUED_ATTR => ["y" * 5000])))
    assert_match(/attrs larger than/, Refs.violation(wire_pref("attrs" => at_bound.merge(Refs::ISSUED_ATTR => "y"))))
    assert_match(/attrs larger than/, Refs.violation(wire_pref("attrs" => { "k" => "\u00e9" * (Refs::MAX_ATTRS_BYTES / 2) })),
                 "a two-byte letter counts two bytes")
  end

  # HLC round six, 2026-11-08 (R3): a reader ignores an entry whose PRef is
  # undecodable, breaks a bound, or names another ref or another kind, and
  # counts it once in headsIgnored while the entry stays live, as Java's
  # Refs.toHead counts it. The reader forgets an ignored entry once it is
  # gone, so the ignored set stays bounded by the live entries, and the same
  # entry id written again counts again, as Java's retainAll over the live
  # ids has it.
  def test_an_undecodable_out_of_bound_or_stray_pref_is_ignored_and_counted_once_while_live
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt")
    good = map_node(pdt.store, { "a" => 1 })
    facts = pdt.map_ref("facts")
    peer.states["e-good"] = pref_dto(peer, pdt, "facts", pref("facts", "map", good, size: 1), ms(T0), entry_id: "e-good")
    bad = {
      "e-attr" => pref("facts", "map", good, size: 1).merge("attrs" => { "user" => 5 }),
      "e-bound" => pref("facts", "map", good, size: 1).merge("mode" => "m" * 33),
      "e-kind" => pref("facts", "set", good, size: 1),
      "e-name" => pref("other", "map", good, size: 1),
      "e-seq" => pref("facts", "map", good, size: 1).merge("seq" => 1.0)
    }
    bad.each do |id, value|
      peer.states[id] = pref_dto(peer, pdt, "facts", value, ms(T0) + 1000, entry_id: id)
      peer.states[id]["record"]["tags"] = { Refs::NAME_TAG => "facts", Refs::ROOT_TAG => good }
    end
    trailing = pref_dto(peer, pdt, "facts", pref("facts", "map", good, size: 1), ms(T0) + 1000, entry_id: "e-trailing")
    trailing["record"]["payload"] += "\x00".b
    peer.states["e-trailing"] = trailing
    2.times do
      assert_equal [good], facts.heads.map(&:root)
      assert_equal({ "a" => 1 }, facts.deref.to_h)
    end
    assert_equal bad.size + 1, pdt.stats["headsIgnored"], "each ignored entry counts once"
    gone = peer.states.delete("e-attr")
    facts.heads
    peer.states["e-attr"] = gone
    facts.heads
    assert_equal bad.size + 2, pdt.stats["headsIgnored"], "an entry that left and came back counts again"
  end

  # HLC round six, 2026-11-08 (R3): a head whose root failed to load counts
  # once in headsIgnored, and it joins the heads as soon as the reader holds
  # its root, as Java's Refs reads every live head whose root it holds.
  def test_a_head_late_after_a_failed_load_joins_the_heads_once_its_root_is_held
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt", load_timeout: 0.05)
    elsewhere = NodeStore.new
    root = map_node(elsewhere, { "a" => 1 })
    peer.states["e-late"] = pref_dto(peer, pdt, "facts", pref("facts", "map", root, size: 1), ms(T0), entry_id: "e-late")
    facts = pdt.map_ref("facts")
    assert_empty facts.heads
    # swarm retries (ROBUSTNESS.md 10.3 E3): a root still loading is late, apart from the heads ignored for a fault
    assert_equal 0, pdt.stats["headsIgnored"]
    assert_equal 1, pdt.stats["headsLate"]
    pdt.store.put(elsewhere.get(root))
    assert_equal [root], facts.heads.map(&:root)
    assert_equal({ "a" => 1 }, facts.deref.to_h)
    assert_equal 1, pdt.stats["headsLate"], "the entry counts once"
  end

  # Swarm retries (ROBUSTNESS.md 10.3 E3): a holder that lacked the root is
  # benched for it, not dropped; the head is late, never ignored; and the tick
  # fetches it again once the holder serves it, with no read in between.
  def test_a_late_head_is_fetched_again_by_the_tick_once_a_holder_serves_it
    bench = TreeFetch.const_defined?(:MISSING_BENCH, false) ? TreeFetch::MISSING_BENCH : nil
    retry_base = Refs.const_defined?(:RETRY_BASE, false) ? Refs::RETRY_BASE : nil
    swap_const(TreeFetch, :MISSING_BENCH, 0.05)
    swap_const(Refs, :RETRY_BASE, 0.05)
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt", load_timeout: 0.3)
    holder = FakeHolder.new(peer, pdt.trees, NodeStore.new) # holds nothing yet
    elsewhere = NodeStore.new
    root = map_node(elsewhere, { "a" => 1, "b" => 2 })
    peer.states["e-late"] = pref_dto(peer, pdt, "facts", pref("facts", "map", root, size: 2), ms(T0), entry_id: "e-late")
    facts = pdt.map_ref("facts")
    assert_empty facts.heads
    assert_equal 0, pdt.stats["headsIgnored"]
    elsewhere.cids.each { |c| holder.store.put(elsewhere.get(c)) } # the holder's own fetch ran on
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
    until pdt.store.complete?(root) || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      pdt.tick if pdt.respond_to?(:tick)
      sleep 0.02
    end
    assert_equal [root], facts.heads.map(&:root), "fetched again once the holder serves it"
    assert_equal({ "a" => 1, "b" => 2 }, facts.deref.to_h)
  ensure
    swap_const(TreeFetch, :MISSING_BENCH, bench)
    swap_const(Refs, :RETRY_BASE, retry_base)
  end

  def swap_const(owner, name, value)
    owner.send(:remove_const, name) if owner.const_defined?(name, false)
    owner.const_set(name, value) unless value.nil?
  end

  # HLC round six, 2026-11-08 (R2): a pdt.issued whose physical time lies
  # past the reader's wall + MAX_DRIFT + the 5 s skew margin orders nothing,
  # so a rewrite cannot win every conflict by stamping ahead: the head keeps
  # the entry's own stamp and issuer (E10). A stamp at that bound still
  # orders the head.
  def test_a_pdt_issued_past_the_drift_bound_and_margin_falls_back_to_the_entrys_own_pair
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt")
    first = map_node(pdt.store, { "a" => 1 })
    later = map_node(pdt.store, { "b" => 2 })
    writer = "#{AgentSpaces::Identity.generate.peer_id}/app"
    original = "#{AgentSpaces::Identity.generate.peer_id}/origin"
    peer.states["e-first"] = pref_dto(peer, pdt, "facts", pref("facts", "map", first, size: 1), ms(T0) + 1000,
                                      entry_id: "e-first")
    bound = ms(T0) + AgentSpaces::Wire::MAX_HLC_SKEW_MILLIS + AgentSpaces::Wire::HLC_SKEW_MARGIN_MILLIS
    heads_at = lambda do |physical|
      attrs = { Refs::ISSUED_ATTR => "#{physical}:0:x", Refs::ISSUER_ATTR => original }
      peer.states["e-later"] = pref_dto(peer, pdt, "facts", pref("facts", "map", later, size: 1).merge("attrs" => attrs),
                                        ms(T0) + 2000, entry_id: "e-later", issuer: writer)
      pdt.map_ref("facts").heads
    end
    heads = heads_at.call(bound)
    assert_equal [[bound, 0], original], [heads[1].issued.first(2), heads[1].issuer], "a stamp at the bound orders the head"
    [bound + 1, bound + AgentSpaces::Wire::HLC_DEFER_WINDOW_MILLIS + 1].each do |physical|
      heads = heads_at.call(physical)
      assert_equal [first, later], heads.map(&:root)
      assert_equal [[ms(T0) + 2000, 0], writer], [heads[1].issued.first(2), heads[1].issuer],
                   "a stamp #{physical - bound} ms past the bound falls back"
      assert_equal 0, pdt.stats["headsIgnored"]
    end
  end

  def test_several_heads_merge_key_wise_against_the_common_base_and_a_both_side_change_takes_the_later_head
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt")
    store = pdt.store
    base = map_node(store, { "a" => 1, "b" => 2, "c" => 3 })
    left = map_node(store, { "a" => 1, "b" => 20, "c" => 3 })           # changed b
    right = map_node(store, { "a" => 10, "b" => 2 })                    # changed a, removed c
    other = "#{AgentSpaces::Identity.generate.peer_id}/app"
    peer.states["e-base"] = pref_dto(peer, pdt, "facts", pref("facts", "map", base, seq: 1, size: 3), ms(T0), entry_id: "e-base")
    peer.states["e-left"] = pref_dto(peer, pdt, "facts", pref("facts", "map", left, base: [base], seq: 2, size: 3), ms(T0) + 1000, entry_id: "e-left")
    peer.states["e-right"] = pref_dto(peer, pdt, "facts", pref("facts", "map", right, base: [base], seq: 2, size: 2), ms(T0) + 2000,
                                      entry_id: "e-right", issuer: other)
    facts = pdt.map_ref("facts")
    assert_equal [left, right], facts.heads.map(&:root)
    assert_equal({ "a" => 10, "b" => 20 }, facts.deref)
    assert_empty facts.conflicts
    # both sides change a: the head with the later issued HLC wins and the reader records the decision
    clash = map_node(store, { "a" => 7, "b" => 2, "c" => 3 })
    peer.states["e-right"] = pref_dto(peer, pdt, "facts", pref("facts", "map", clash, base: [base], seq: 2, size: 3), ms(T0) + 2000,
                                      entry_id: "e-right", issuer: other)
    left_first = map_node(store, { "a" => 5, "b" => 20, "c" => 3 })
    peer.states["e-left"] = pref_dto(peer, pdt, "facts", pref("facts", "map", left_first, base: [base], seq: 2, size: 3), ms(T0) + 1000, entry_id: "e-left")
    seen = []
    facts.on_conflict { |c| seen << c }
    assert_equal({ "a" => 7, "b" => 20, "c" => 3 }, facts.deref)
    assert_equal 1, seen.size
    assert_equal ["facts", "a", clash, left_first, Refs::LATER_HLC], [seen[0].name, seen[0].key, seen[0].winner_root, seen[0].loser_root, seen[0].reason]
    assert_equal 1, pdt.stats["conflicts"]
    # a vector ref takes the later head whole
    tail = store.put(hex("pdt_vector_tail"))
    one = store.put(Nodes.encode({ "k" => "vr", "n" => 1, "s" => 5, "r" => nil, "t" => [AgentSpaces::CBOR.dump(42)] }))
    peer.states["v-1"] = pref_dto(peer, pdt, "list", pref("list", "vector", tail, seq: 1, size: 10), ms(T0), entry_id: "v-1")
    peer.states["v-2"] = pref_dto(peer, pdt, "list", pref("list", "vector", one, seq: 1, size: 1), ms(T0) + 5000, entry_id: "v-2", issuer: other)
    list = pdt.vector_ref("list")
    assert_equal [42], list.deref.to_a
    assert_equal Refs::WHOLE_HEAD, list.conflicts.last.reason
    # a successor supersedes its base: one head, no merge
    peer.states["e-merge"] = pref_dto(peer, pdt, "facts", pref("facts", "map", base, base: [left_first, clash], seq: 3, size: 3), ms(T0) + 9000, entry_id: "e-merge")
    assert_equal [base], facts.heads.map(&:root)
    assert_equal({ "a" => 1, "b" => 2, "c" => 3 }, facts.deref.to_h)
    assert_equal [left_first, clash], facts.history(10).map(&:root) # the earlier versions under the head
    assert_equal 5, facts.versions.size # base, left, right, clash, left_first: every version seen
  end

  # HLC round five, 2026-11-08 (E16): when the base walks of the heads share
  # no version but every walk ends at a first version (base []) within the
  # 64-step limit, the empty value is the shared base, so the merge keeps
  # every key of both writers. A walk that reaches a version this reader
  # never saw, or runs past the limit, does not end at a first version, and
  # the later head wins whole as before.
  def test_two_writers_whose_histories_start_from_empty_and_share_no_version_merge_to_the_union_of_keys
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt")
    store = pdt.store
    other = "#{AgentSpaces::Identity.generate.peer_id}/app"
    a1 = map_node(store, { "a" => 1 })
    a2 = map_node(store, { "a" => 1, "b" => 2 })
    c1 = map_node(store, { "c" => 3 })
    c2 = map_node(store, { "c" => 3, "d" => 4 })
    peer.states["e-a1"] = pref_dto(peer, pdt, "facts", pref("facts", "map", a1, seq: 1, size: 1), ms(T0), entry_id: "e-a1")
    peer.states["e-c1"] = pref_dto(peer, pdt, "facts", pref("facts", "map", c1, seq: 1, size: 1), ms(T0) + 1000,
                                   entry_id: "e-c1", issuer: other)
    facts = pdt.map_ref("facts")
    assert_equal({ "a" => 1, "c" => 3 }, facts.deref, "two first versions merge from the empty value")
    peer.states["e-a2"] = pref_dto(peer, pdt, "facts", pref("facts", "map", a2, base: [a1], seq: 2, size: 2), ms(T0) + 2000,
                                   entry_id: "e-a2")
    peer.states["e-c2"] = pref_dto(peer, pdt, "facts", pref("facts", "map", c2, base: [c1], seq: 2, size: 2), ms(T0) + 3000,
                                   entry_id: "e-c2", issuer: other)
    assert_equal [a2, c2], facts.heads.map(&:root)
    assert_equal({ "a" => 1, "b" => 2, "c" => 3, "d" => 4 }, facts.deref, "every key of both writers survives the merge")
    assert_empty facts.conflicts
    # a base this reader never saw leaves one walk short of a first version: the later head wins whole
    unseen = Cids.of("a version nobody announced".b, Cids::DAG_CBOR)
    peer.states["e-c2"] = pref_dto(peer, pdt, "facts", pref("facts", "map", c2, base: [unseen], seq: 2, size: 2), ms(T0) + 3000,
                                   entry_id: "e-c2", issuer: other)
    lone = pdt.map_ref("lone")
    peer.states.delete("e-a1")
    peer.states.delete("e-c1")
    peer.states.transform_values! { |dto| retag(dto, "lone") }
    assert_equal({ "c" => 3, "d" => 4 }, lone.deref.to_h)
    assert_equal [Refs::NO_COMMON_BASE], lone.conflicts.map(&:reason)
  end

  # A PRef state moved under another ref name, its record and tags with it.
  def retag(dto, name)
    pref = AgentSpaces::CBOR.load(dto["record"]["payload"]).merge("name" => name)
    record = dto["record"].merge("payload" => AgentSpaces::CBOR.dump(pref), "tags" => Refs.tags(pref))
    dto.merge("record" => record)
  end

  # HLC round five, 2026-11-08 (E16): a walk that runs past the 64-step limit
  # before its first version does not end at one, so two such histories
  # sharing no version keep the later head whole.
  def test_a_history_longer_than_the_step_limit_does_not_end_at_a_first_version
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt")
    store = pdt.store
    other = "#{AgentSpaces::Identity.generate.peer_id}/app"
    chain = (0..Refs::MAX_BASE_STEPS + 1).map { |i| map_node(store, { "long" => i }) }
    chain.each_with_index do |root, i|
      base = i.zero? ? [] : [chain[i - 1]]
      peer.states["e-long-#{i}"] = pref_dto(peer, pdt, "facts", pref("facts", "map", root, base: base, seq: i + 1, size: 1),
                                            ms(T0) + i, entry_id: "e-long-#{i}")
    end
    short = map_node(store, { "short" => 1 })
    peer.states["e-short"] = pref_dto(peer, pdt, "facts", pref("facts", "map", short, seq: 1, size: 1), ms(T0) + 100_000,
                                      entry_id: "e-short", issuer: other)
    facts = pdt.map_ref("facts")
    assert_equal [chain.last, short], facts.heads.map(&:root)
    assert_equal({ "short" => 1 }, facts.deref.to_h)
    assert_equal [Refs::NO_COMMON_BASE], facts.conflicts.map(&:reason)
    # one version shorter, the first version sits exactly MAX_BASE_STEPS links below the head, the
    # walk ends at it, and the merge keeps both keys
    peer.states.delete("e-long-0")
    trimmed = chain[1..]
    trimmed.each_with_index do |root, i|
      base = i.zero? ? [] : [trimmed[i - 1]]
      peer.states["e-long-#{i + 1}"] = pref_dto(peer, pdt, "facts", pref("facts", "map", root, base: base, seq: i + 1, size: 1),
                                                ms(T0) + i + 1, entry_id: "e-long-#{i + 1}")
    end
    fresh = Pdt.new(peer, space: "pdt", store: store).map_ref("facts")
    assert_equal [trimmed.last, short], fresh.heads.map(&:root)
    assert_equal({ "long" => Refs::MAX_BASE_STEPS + 1, "short" => 1 }, fresh.deref)
  end

  # HLC round five, 2026-11-08 (E16): a walk ends at first versions when
  # every root it reaches is a version this reader knows and no version it
  # reaches at step MAX_BASE_STEPS has a base, as Java's Refs.walk judges it.
  # A writer that reverts to its first version r0 announces r0 again with
  # base [r1], and the reader keeps the union of r0's bases, so neither r0
  # nor r1 holds an empty base. The walk still reaches every version within
  # the limit, the empty value is the base, and the merge keeps every key of
  # both writers (graph G6 of the round-five conformance probe).
  def test_a_revert_cycle_ends_at_first_versions_and_merges_from_the_empty_value
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt")
    store = pdt.store
    other = "#{AgentSpaces::Identity.generate.peer_id}/app"
    bs = (0..2).map { |i| map_node(store, { "b" => i }) }
    bs.each_with_index do |root, i|
      peer.states["e-b#{i}"] = pref_dto(peer, pdt, "facts", pref("facts", "map", root, base: i.zero? ? [] : [bs[i - 1]],
                                                                                     seq: i + 1, size: 1),
                                        ms(T0) + i, entry_id: "e-b#{i}", issuer: other)
    end
    r0 = map_node(store, { "r" => 0 })
    r1 = map_node(store, { "r" => 1 })
    [[r0, [], 1], [r1, [r0], 2], [r0, [r1], 3]].each_with_index do |(root, base, seq), i|
      peer.states["e-r#{i}"] = pref_dto(peer, pdt, "facts", pref("facts", "map", root, base: base, seq: seq, size: 1),
                                        ms(T0) + 1000 + i, entry_id: "e-r#{i}")
    end
    facts = pdt.map_ref("facts")
    assert_equal [bs[2], r0], facts.heads.map(&:root)
    assert_equal({ "b" => 2, "r" => 0 }, facts.deref)
    assert_empty facts.conflicts
  end

  # HLC round five, 2026-11-08 (E16): a version first reached at step
  # MAX_BASE_STEPS ends the walk at a first version only when it has no base,
  # as Java's Refs.walk judges it, even when the walk already reached its
  # base by a shorter path. Here the head xh names x63 and the first version
  # w, the chain x63 down to x0 puts x0 at step 64, and x0 names w; the walk
  # does not end at first versions, so the heads share no base and the later
  # head wins whole (graph G7 of the round-five conformance probe).
  def test_a_version_at_the_step_limit_with_a_base_leaves_the_walk_short_of_first_versions
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt")
    store = pdt.store
    other = "#{AgentSpaces::Identity.generate.peer_id}/app"
    b0 = map_node(store, { "b" => 0 })
    peer.states["e-b0"] = pref_dto(peer, pdt, "facts", pref("facts", "map", b0, seq: 1, size: 1), ms(T0), entry_id: "e-b0",
                                                                                                         issuer: other)
    w = map_node(store, { "w" => 1 })
    peer.states["e-w"] = pref_dto(peer, pdt, "facts", pref("facts", "map", w, seq: 1, size: 1), ms(T0) + 1, entry_id: "e-w")
    xs = (0...Refs::MAX_BASE_STEPS).map { |i| map_node(store, { "x" => i }) }
    xs.each_with_index do |root, i|
      peer.states["e-x#{i}"] = pref_dto(peer, pdt, "facts", pref("facts", "map", root, base: i.zero? ? [w] : [xs[i - 1]],
                                                                                     seq: i + 2, size: 1),
                                        ms(T0) + 10 + i, entry_id: "e-x#{i}")
    end
    xh = map_node(store, { "xh" => 1 })
    peer.states["e-xh"] = pref_dto(peer, pdt, "facts", pref("facts", "map", xh, base: [xs.last, w], seq: 300, size: 1),
                                   ms(T0) + 1000, entry_id: "e-xh")
    facts = pdt.map_ref("facts")
    assert_equal [b0, xh], facts.heads.map(&:root)
    assert_equal({ "xh" => 1 }, facts.deref.to_h)
    assert_equal [Refs::NO_COMMON_BASE], facts.conflicts.map(&:reason)
  end

  # HLC round five, 2026-11-08 (E16): one branch that reaches a first version
  # does not make the walk end at first versions while another branch runs
  # past the step limit, so the later head still wins whole.
  def test_a_walk_with_one_branch_past_the_step_limit_does_not_end_at_first_versions
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt")
    store = pdt.store
    other = "#{AgentSpaces::Identity.generate.peer_id}/app"
    f = map_node(store, { "f" => 1 })
    peer.states["e-f"] = pref_dto(peer, pdt, "facts", pref("facts", "map", f, seq: 1, size: 1), ms(T0), entry_id: "e-f")
    chain = (0..Refs::MAX_BASE_STEPS).map { |i| map_node(store, { "link" => i }) }
    chain.each_with_index do |root, i|
      base = i.zero? ? [] : [chain[i - 1]]
      peer.states["e-link-#{i}"] = pref_dto(peer, pdt, "facts", pref("facts", "map", root, base: base, seq: i + 1, size: 1),
                                            ms(T0) + 10 + i, entry_id: "e-link-#{i}")
    end
    head = map_node(store, { "head" => 1 })
    peer.states["e-head"] = pref_dto(peer, pdt, "facts", pref("facts", "map", head, base: [chain.last, f], seq: 300, size: 1),
                                     ms(T0) + 1000, entry_id: "e-head")
    lone = map_node(store, { "lone" => 1 })
    peer.states["e-lone"] = pref_dto(peer, pdt, "facts", pref("facts", "map", lone, seq: 1, size: 1), ms(T0) + 5000,
                                     entry_id: "e-lone", issuer: other)
    facts = pdt.map_ref("facts")
    assert_equal [head, lone], facts.heads.map(&:root)
    assert_equal({ "lone" => 1 }, facts.deref.to_h)
    assert_equal [Refs::NO_COMMON_BASE], facts.conflicts.map(&:reason)
  end

  # HLC round five, 2026-11-08 (E16): the reader picks the base as Java's
  # Refs.commonBase does, the first root in the breadth-first base walk of
  # the latest head that every other head's walk reaches, whatever its depth
  # in the other walks.
  def test_the_common_base_is_the_first_shared_root_in_the_latest_heads_breadth_first_walk
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt")
    store = pdt.store
    other = "#{AgentSpaces::Identity.generate.peer_id}/app"
    x = map_node(store, { "x" => 1 })
    y = map_node(store, { "y" => 1 })
    p = map_node(store, { "p" => 1 })
    qs = (1..4).map { |i| map_node(store, { "q" => i }) }
    h1 = map_node(store, { "h1" => 1 })
    h2 = map_node(store, { "x" => 1, "y" => 1, "h2" => 1 })
    put = lambda do |id, root, base, seq, at, issuer = nil|
      peer.states[id] = pref_dto(peer, pdt, "facts", pref("facts", "map", root, base: base, seq: seq, size: 1), ms(T0) + at,
                                 entry_id: id, issuer: issuer)
    end
    put.call("e-x", x, [], 1, 0)
    put.call("e-y", y, [], 1, 1)
    put.call("e-p", p, [y], 2, 2)
    put.call("e-q4", qs[3], [x], 2, 3)
    put.call("e-q3", qs[2], [qs[3]], 3, 4)
    put.call("e-q2", qs[1], [qs[2]], 4, 5)
    put.call("e-q1", qs[0], [qs[1]], 5, 6)
    # h1's walk: h1, y (depth 1), q1..q4, x (depth 5); h2, the later head: h2, x (depth 1), p, y (depth 2)
    put.call("e-h1", h1, [y, qs[0]], 6, 10)
    put.call("e-h2", h2, [x, p], 3, 20, other)
    facts = pdt.map_ref("facts")
    assert_equal [h1, h2], facts.heads.map(&:root)
    # against x, h1 removed x and h2 added y and h2; against y the result would hold x instead of y
    assert_equal({ "h1" => 1, "y" => 1, "h2" => 1 }, facts.deref)
    assert_empty facts.conflicts
  end

  # HLC round five, 2026-11-08 (E16): as Java's Refs.commonBase does, a
  # common base this reader does not hold, here one it never saw a head of,
  # is fetched from the heads' issuers before the merge, and the fetch
  # counts in basesFetched.
  def test_a_common_base_held_by_an_issuer_is_fetched_before_the_merge
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt", load_timeout: 5.0)
    holder_store = NodeStore.new
    holder = FakeHolder.new(peer, pdt.trees, holder_store)
    issuer = "#{holder.id}/app"
    base = map_node(holder_store, { "a" => 1, "b" => 2, "c" => 3 })
    left = map_node(pdt.store, { "a" => 1, "b" => 20, "c" => 3 })
    right = map_node(pdt.store, { "a" => 10, "b" => 2 })
    refute pdt.store.has?(base)
    peer.states["e-left"] = pref_dto(peer, pdt, "facts", pref("facts", "map", left, base: [base], seq: 2, size: 3), ms(T0) + 1000,
                                     entry_id: "e-left", issuer: issuer)
    peer.states["e-right"] = pref_dto(peer, pdt, "facts", pref("facts", "map", right, base: [base], seq: 2, size: 2), ms(T0) + 2000,
                                      entry_id: "e-right", issuer: issuer)
    facts = pdt.map_ref("facts")
    assert_equal [left, right], facts.heads.map(&:root)
    assert_equal({ "a" => 10, "b" => 20 }, facts.deref)
    assert_empty facts.conflicts
    assert pdt.store.complete?(base)
    assert_equal 1, pdt.stats["basesFetched"]
  end

  # HLC round six, 2026-11-08 (R4): as Java's Refs.commonBase, heads that are
  # all first versions merge from the empty value before any walk, even when
  # this reader once saw records of the same roots that named a base. Here
  # each head's earlier record named x, and a walk over the known versions
  # would pick x as the base and drop the key a.
  def test_heads_that_are_all_first_versions_merge_from_the_empty_value_whatever_their_known_bases
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt")
    store = pdt.store
    other = "#{AgentSpaces::Identity.generate.peer_id}/app"
    x = map_node(store, { "a" => 1 })
    a = map_node(store, { "a" => 1, "b" => 2 })
    c = map_node(store, { "c" => 3 })
    facts = pdt.map_ref("facts")
    peer.states["e-a"] = pref_dto(peer, pdt, "facts", pref("facts", "map", a, base: [x], seq: 2, size: 2), ms(T0), entry_id: "e-a")
    peer.states["e-c"] = pref_dto(peer, pdt, "facts", pref("facts", "map", c, base: [x], seq: 2, size: 1), ms(T0) + 1,
                                  entry_id: "e-c", issuer: other)
    assert_equal [a, c], facts.heads.map(&:root)
    peer.states["e-a"] = pref_dto(peer, pdt, "facts", pref("facts", "map", a, seq: 1, size: 2), ms(T0) + 10, entry_id: "e-a")
    peer.states["e-c"] = pref_dto(peer, pdt, "facts", pref("facts", "map", c, seq: 1, size: 1), ms(T0) + 11,
                                  entry_id: "e-c", issuer: other)
    assert_equal [[a, []], [c, []]], facts.heads.map { |h| [h.root, h.base] }
    assert_equal({ "a" => 1, "b" => 2, "c" => 3 }, facts.deref)
    assert_empty facts.conflicts
  end

  # HLC round six, 2026-11-08 (R4): as Java's Refs.toHead keeps a version, a
  # record with a larger seq for a known root puts its own bases first and
  # the bases earlier records named after them, so the breadth-first walk,
  # and with it the common base, follows the newer record's bases first.
  # Here r was seen with base [p] and then, recreated, with base [q]; the
  # latest head l names r, the other head o names p and q, and the walk from
  # l reaches q before p.
  def test_a_recreated_versions_newer_bases_lead_the_breadth_first_walk
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt")
    store = pdt.store
    other = "#{AgentSpaces::Identity.generate.peer_id}/app"
    p = map_node(store, { "a" => 1 })
    q = map_node(store, { "b" => 2 })
    r = map_node(store, { "r" => 1 })
    o = map_node(store, { "a" => 1, "b" => 2, "o" => 1 })
    l = map_node(store, { "b" => 2, "l" => 1 })
    put = lambda do |id, root, base, seq, at, issuer = nil|
      peer.states[id] = pref_dto(peer, pdt, "facts", pref("facts", "map", root, base: base, seq: seq, size: 1), ms(T0) + at,
                                 entry_id: id, issuer: issuer)
    end
    put.call("e-p", p, [], 1, 0)
    put.call("e-q", q, [], 1, 1)
    put.call("e-r2", r, [p], 2, 2)
    put.call("e-r5", r, [q], 5, 3)
    put.call("e-o", o, [p, q], 2, 4, other)
    put.call("e-l", l, [r], 6, 5)
    facts = pdt.map_ref("facts")
    assert_equal [o, l], facts.heads.map(&:root)
    assert_equal [q, p], facts.versions.find { |v| v.root == r }.base
    # against q, o added a and l kept it out of its own change; against p, l would have removed a
    assert_equal({ "a" => 1, "b" => 2, "o" => 1, "l" => 1 }, facts.deref)
    assert_empty facts.conflicts
  end

  # ------------------------------------------------------------------ the tree exchange

  def test_the_tree_message_vectors_encode_byte_for_byte_and_bounds_are_refused
    want = load(hex("content_node_want_cbor"))
    assert_equal hex("content_node_want_cbor"), cbor(Tree.node_want(want["req"], want["cids"]))
    assert_nil Tree.violation(want)
    answer = load(hex("content_nodes_cbor"))
    assert_equal hex("content_nodes_cbor"), cbor(Tree.nodes_message(answer["req"], answer["nodes"], nil, nil, answer["missing"]))
    assert_nil Tree.violation(answer)
    tw = load(hex("content_tree_want_cbor"))
    assert_equal hex("content_tree_want_cbor"), cbor(Tree.tree_want(tw["req"], tw["root"], tw["haves"], tw["budget"]))
    assert_equal Tree::MAX_TREE_BUDGET, tw["budget"]
    assert_nil Tree.violation(tw)
    te = load(hex("content_tree_end_cbor"))
    assert_equal hex("content_tree_end_cbor"), cbor(Tree.tree_end(te["req"], te["frontier"], te["reason"]))
    assert_equal Tree::END_BUDGET, te["reason"]
    assert_nil Tree.violation(te)
    refute_nil Tree.violation(want.merge("cids" => []))
    refute_nil Tree.violation(want.merge("cids" => want["cids"] * 300))
    refute_nil Tree.violation(tw.merge("budget" => 0))
    refute_nil Tree.violation(tw.merge("haves" => tw["haves"] * 65))
    refute_nil Tree.violation(te.merge("reason" => 9))
    refute_nil Tree.violation(answer.merge("nodes" => nil))
    # PDT 2 phase 4 measures (owner default of 2026-11-09): every port refuses a sealed NODES that carries deltas;
    # Ruby reads the six level-1 fields alone, so its field rule refuses the pair
    sealed = Tree.nodes_message(answer["req"], nil, "\x01\x02".b, 0, nil)
    assert_nil Tree.violation(sealed)
    assert_match(/in order/, Tree.violation(sealed.merge("deltas" => [])))
    manifest = load(hex("content_manifest_tree_cbor"))
    assert_equal "tree", manifest["layout"]
    assert_equal Cids::DAG_CBOR, Cids.codec_of(manifest["root"])
    assert_equal hex("content_manifest_tree_cbor"), cbor(manifest)
  end

  # A holder that answers this peer's NODE_WANT and TREE_WANT from its own store, through the
  # pipe handler the fetcher registered, as a Java member would.
  class FakeHolder
    include AgentSpaces::PDT

    attr_reader :id, :frames, :store

    def initialize(peer, trees, store, seal: nil)
      @id = AgentSpaces::Identity.generate.peer_id
      @trees = trees
      @store = store
      @frames = []
      @seal = seal
      @refuse = false
      peer.members[@id] = {}
      far = peer.now_ms + 600_000
      peer.ads["aspace://#{peer.group}/cap/content-swarm/#{@id}"] =
        { "type" => "CapabilityAdvertisement", "issuer" => @id, "expires" => far,
          "ad" => { "capabilityType" => Tree::TYPE, "issued" => "2025-01-01T00:00:00Z",
                    "parameters" => { "trees" => "1", "sealing" => seal ? "group-key" : "none" } } }
      holders = peer.instance_variable_get(:@fake_holders) || peer.instance_variable_set(:@fake_holders, {})
      holders[@id] = self
      return if peer.singleton_methods.include?(:send_pipe)

      peer.define_singleton_method(:send_pipe) do |to, capability, payload, via: nil|
        msg = AgentSpaces::CBOR.load(payload)
        target = holders[to]
        next if target.nil?

        target.frames << [to, capability, msg, via]
        target.answer(msg)
      end
    end

    def refuse! = @refuse = true

    # Answers every NODE_WANT with whatever it holds, asked for or not.
    def forge! = @forge = true

    def reply(msg) = @trees.on_frame(@id, AgentSpaces::CBOR.dump(msg))

    def nodes(req, list, missing)
      if @seal
        plain = AgentSpaces::CBOR.dump(list)
        aad = Tree.sealing_aad(@seal[:recipient], req)
        cipher = OpenSSL::Cipher.new("aes-256-gcm").encrypt
        cipher.key = @seal[:key]
        nonce = Random.new(7).bytes(12)
        cipher.iv = nonce
        cipher.auth_data = aad
        sealed = nonce + cipher.update(plain) + cipher.final + cipher.auth_tag
        Tree.nodes_message(req, nil, sealed, @seal[:epoch], missing)
      else
        Tree.nodes_message(req, list, nil, nil, missing)
      end
    end

    def answer(msg)
      case msg["t"]
      when Tree::NODE_WANT
        return reply(Tree.reject(msg["cids"].first, Tree::TREE_INDEX, 1)) if @refuse
        return reply(nodes(msg["req"], @store.cids.map { |c| @store.get(c) }, nil)) if @forge

        found = msg["cids"].filter_map { |c| @store.get(c) }
        missing = msg["cids"].reject { |c| @store.has?(c) }
        reply(nodes(msg["req"], found, missing.empty? ? nil : missing))
      when Tree::TREE_WANT
        skip = (msg["haves"] || []).flat_map { |h| @store.reachable(h) }.to_set
        queue = @store.links(msg["root"])
        sent = []
        until queue.empty?
          cid = queue.shift
          next if skip.include?(cid) || sent.include?(cid)

          data = @store.get(cid)
          next if data.nil?

          sent << cid
          queue.concat(@store.links(cid, data))
        end
        reply(nodes(msg["req"], sent.map { |c| @store.get(c) }, nil)) unless sent.empty?
        reply(Tree.tree_end(msg["req"], [], Tree::END_DONE))
      end
    end
  end

  def test_a_tree_is_fetched_from_a_holder_verified_node_by_node
    _stream, holder_store, root, entries = blob_fixture
    peer = peer_at(T0)
    store = NodeStore.new
    trees = Trees.new(peer, store, load_timeout: 5.0)
    holder = FakeHolder.new(peer, trees, holder_store)
    assert trees.advertises_trees?(holder.id)
    assert_equal [holder.id], trees.sources([holder.id])
    fetch = trees.fetch_tree(root, prefer: [holder.id])
    assert fetch.wait(5.0), fetch.failure.to_s
    assert store.complete?(root)
    assert_equal 3, store.size
    assert_equal [Tree::NODE_WANT, Tree::TREE_WANT], holder.frames.map { |f| f[2]["t"] }
    assert_equal [root], holder.frames[0][2]["cids"]
    assert_equal root, holder.frames[1][2]["root"]
    assert_equal 3, fetch.nodes_received
    assert_equal 2, fetch.round_trips
    # the fetched blob reads back through the store, and a second fetch of a held root is a no-op
    assert_equal holder_store.get(entries[0].cid), PBlob.load(root, trees.loader).read(0, entries[0].length)
    assert trees.fetch_tree(root).wait(1.0)
    assert_equal 2, holder.frames.size
    # a bare load of one node this store lacks asks the holder, and a node nobody holds says so
    store.remove(entries[1].cid)
    assert_equal holder_store.get(entries[1].cid), trees.load(entries[1].cid, prefer: [holder.id])
    nowhere = Cids.of("nowhere".b)
    error = assert_raises(NodeUnavailable) { trees.load(nowhere, prefer: [holder.id], timeout: 0.5) }
    assert_includes error.message, "could not be fetched" # the caller's wait ended; the batch goes on (swarm retries)
    assert_includes error.sources, holder.id
    # a refusal drops the source and the fetch fails naming it
    holder.refuse!
    store.remove(entries[1].cid)
    bare = trees.fetch_nodes([entries[1].cid], prefer: [holder.id], timeout: 2.0)
    refute bare.wait(2.0)
    assert_includes bare.failure, "every source refused"
    assert_equal 1, trees.stats[:tree_requests_rejected]
    # PDT 2 phase 7 (P2-X-06): the face serves what its store holds and names the rest missing
    trees.on_frame(holder.id, AgentSpaces::CBOR.dump(Tree.node_want(99, [root, entries[1].cid])))
    assert_equal [Tree::NODES, 99, [store.get(root)], [entries[1].cid]],
                 holder.frames.last[2].values_at("t", "req", "nodes", "missing")
  end

  # PDT 2 phase 0 (srad/agentspaces-pdt2.md 6.10.2, P2-F-05, P2-C-02): the
  # Ruby face stays at PDT feature level 1. A member that advertises pdt = "2"
  # beside trees = "1" still serves it the level-1 forms, the face writes no
  # sketch, and the level-2 forms (TREE_END reason 5, tag 12) are no message
  # of its level.
  def test_the_ruby_face_stays_at_pdt_level_one_and_sends_a_level_two_member_level_one_forms
    _stream, holder_store, root, _entries = blob_fixture
    peer = peer_at(T0)
    trees = Trees.new(peer, NodeStore.new, load_timeout: 5.0)
    holder = FakeHolder.new(peer, trees, holder_store)
    peer.ads.each_value { |e| e["ad"]["parameters"]["pdt"] = "2" if e["issuer"] == holder.id }
    assert_equal [holder.id], trees.sources([holder.id])
    assert trees.fetch_tree(root, prefer: [holder.id]).wait(5.0)
    want = holder.frames.map { |f| f[2] }.find { |m| m["t"] == Tree::TREE_WANT }
    assert want.key?("sketch")
    assert_nil want["sketch"]
    assert_raises(ArgumentError) { Tree.tree_want(1, root, nil, 1024, "\x61".b) }
    assert_equal "unknown TREE_END reason", Tree.violation(Tree.tree_end(1, [], 5))
    assert_equal "not a tree message: tag 12", Tree.violation({ "t" => 12, "req" => 1 })
  end

  def test_a_node_that_matches_nothing_strikes_its_sender_and_a_sealed_answer_opens_with_the_epoch_key
    _stream, holder_store, root, _entries = blob_fixture
    peer = peer_at(T0)
    store = NodeStore.new
    trees = Trees.new(peer, store, load_timeout: 2.0)
    holder = FakeHolder.new(peer, trees, holder_store)
    forged = holder_store.dup
    bogus = NodeStore.new
    bogus.put("not the root".b, Cids::RAW)
    bad = FakeHolder.new(peer, trees, bogus)
    bad.forge!
    # the bad holder answers the root request with a node that hashes to nothing asked for
    fetch = trees.fetch_tree(root, prefer: [bad.id, holder.id])
    assert fetch.wait(5.0), fetch.failure.to_s
    assert_equal 1, trees.stats[:nodes_struck]
    assert store.complete?(root)
    assert_nil forged.get(Cids.of("x".b))
    # group-key mode: a sealed NODES opens under the epoch key with the AAD of this recipient
    key = Random.new(3).bytes(32)
    sealed_store = NodeStore.new
    sealed_peer = peer_at(T0)
    sealed_trees = Trees.new(sealed_peer, sealed_store, keys: { 4 => key }, load_timeout: 2.0)
    sealing = FakeHolder.new(sealed_peer, sealed_trees, holder_store, seal: { key: key, epoch: 4, recipient: sealed_peer.identity.peer_id })
    assert sealed_trees.fetch_tree(root, prefer: [sealing.id]).wait(5.0)
    assert sealed_store.complete?(root)
    keyless = Trees.new(peer_at(T0), NodeStore.new, load_timeout: 1.0)
    FakeHolder.new(keyless.peer, keyless, holder_store, seal: { key: key, epoch: 4, recipient: keyless.peer.identity.peer_id })
    refute keyless.fetch_tree(root).wait(2.0)
    assert_equal 1, keyless.stats[:nodes_unopenable]
  end

  def test_a_head_held_by_a_member_is_fetched_from_its_issuer_on_deref
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt", load_timeout: 5.0)
    holder_store = store_with("pdt_map_empty", "pdt_map_small", "pdt_vector_tail")
    holder = FakeHolder.new(peer, pdt.trees, holder_store)
    small = Cids.of(hex("pdt_map_small"))
    peer.states["h-1"] = pref_dto(peer, pdt, "facts", pref("facts", "map", small, seq: 1, size: 2), ms(T0), entry_id: "h-1", issuer: "#{holder.id}/app")
    value = pdt.map_ref("facts").deref
    assert_equal({ "a" => 1, "b" => "two" }, value.to_h)
    assert_equal 1, pdt.stats["deltasFetched"]
    assert_equal holder.id, holder.frames.first[0]
    tail = Cids.of(hex("pdt_vector_tail"))
    assert_equal (0..9).to_a, pdt.value_at(tail, kind: "vector", prefer: [holder.id]).to_a
    assert_equal 2, pdt.value_at(small).count
  end

  # ------------------------------------------------------------------ PDT 2 phase 1

  # PDT 2 phase 1 (P2-V-02): a reader that joined after the entry of a
  # version lapsed reads that version's bases from its vg node, fetched by
  # NODE_WANT from the heads' issuers. Here left descends from base through
  # mid, whose entry this reader never saw, and right from base directly:
  # over the chain the walks meet at base and the merge is key-wise; with no
  # usable pdt.ancestry the walk stops at mid and the later head wins whole.
  def test_a_late_joiner_walks_the_vg_chain_past_versions_whose_entries_are_gone
    holder_store = NodeStore.new
    reader = lambda do
      peer = peer_at(T0)
      pdt = Pdt.new(peer, space: "pdt", load_timeout: 5.0)
      [peer, pdt, FakeHolder.new(peer, pdt.trees, holder_store)]
    end
    peer, pdt, holder = reader.call
    writer = "#{holder.id}/app"
    base = map_node(holder_store, { "a" => 1, "b" => 2, "c" => 3 })
    mid = map_node(NodeStore.new, { "a" => 1, "b" => 5, "c" => 3 })
    left = map_node(holder_store, { "a" => 1, "b" => 20, "c" => 3 })
    right = map_node(holder_store, { "a" => 10, "b" => 2 })
    vg = lambda do |root, bases, links, step|
      holder_store.put(VgNode.new(root, bases, writer, "#{ms(T0) + step}:0:golden", links.map { |l| Nodes::Link.new(l) }).encode)
    end
    vg_base = vg.call(base, [], [], 0)
    vg_mid = vg.call(mid, [base], [vg_base], 1)
    vg_left = vg.call(left, [mid], [vg_mid], 2)
    vg_right = vg.call(right, [base], [vg_base], 3)
    heads = lambda do |p, d, left_vg|
      p.states["e-left"] = pref_dto(p, d, "facts", pref("facts", "map", left, base: [mid], seq: 3, size: 3)
        .merge("attrs" => { Ancestry::ATTR => left_vg }), ms(T0) + 2000, entry_id: "e-left", issuer: writer)
      p.states["e-right"] = pref_dto(p, d, "facts", pref("facts", "map", right, base: [base], seq: 2, size: 2)
        .merge("attrs" => { Ancestry::ATTR => vg_right }), ms(T0) + 3000, entry_id: "e-right", issuer: writer)
      d.map_ref("facts")
    end
    facts = heads.call(peer, pdt, vg_left)
    assert_equal [left, right], facts.heads.map(&:root)
    assert_equal({ "a" => 10, "b" => 20 }, facts.deref)
    assert_empty facts.conflicts
    assert pdt.store.complete?(base), "the common base was fetched from the issuer"
    assert [vg_left, vg_mid, vg_base].all? { |c| pdt.store.has?(c) }, "the walk fetched the chain from left to base"
    refute pdt.store.has?(vg_right), "a walk fetches only the nodes it reads: right's base was already described"
    assert holder.frames.any? { |f| f[2]["t"] == Tree::NODE_WANT && f[2]["cids"].include?(vg_left) }
    # a pdt.ancestry naming the vg node of another root is no ancestry: the walk stops at mid
    [vg_right, Cids.of("no node".b)].each do |forged|
      p, d, = reader.call
      lone = heads.call(p, d, forged)
      assert_equal({ "a" => 10, "b" => 2 }, lone.deref.to_h, "ancestry #{forged}")
      assert_equal [Refs::NO_COMMON_BASE], lone.conflicts.map(&:reason)
    end
  end

  # Swarm retries (ROBUSTNESS.md 10.2) for the chain walk of P2-V-02, as the
  # PDT 2 phase 7 gate built it in TypeScript (srad/agentspaces-pdt2.md
  # 10.17): a vg node nobody serves costs a merge one ask. The node then waits
  # out a backoff of its own, the rule of a failed head fetch, so the next
  # merge leaves the link out and counts it with no ask and no wait, where
  # each merge used to ask again and wait the load timeout. Once the backoff
  # ends and a holder serves the node, a read walks the chain to the base.
  def test_a_chain_node_nobody_serves_is_asked_once_and_later_merges_wait_out_its_backoff
    retry_base = Refs::RETRY_BASE
    swap_const(Refs, :RETRY_BASE, 0.3)
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt", load_timeout: 0.5)
    holder_store = NodeStore.new
    holder = FakeHolder.new(peer, pdt.trees, holder_store)
    writer = "#{holder.id}/app"
    # left descends from base through mid, whose entry this reader never saw, and right from base directly
    base = map_node(holder_store, { "a" => 1, "b" => 2 })
    mid = map_node(NodeStore.new, { "a" => 1, "b" => 5 })
    left = map_node(holder_store, { "a" => 1, "b" => 20 })
    right = map_node(holder_store, { "a" => 10, "b" => 2 })
    unserved = NodeStore.new # the chain, which no member serves yet
    vg = lambda do |root, bases, links, step|
      unserved.put(VgNode.new(root, bases, writer, "#{ms(T0) + step}:0:golden", links.map { |l| Nodes::Link.new(l) }).encode)
    end
    vg_base = vg.call(base, [], [], 0)
    vg_mid = vg.call(mid, [base], [vg_base], 1)
    { "e-left" => [left, mid, vg_mid, 2], "e-right" => [right, base, vg_base, 3] }.each do |entry_id, (root, parent, link, step)|
      peer.states[entry_id] = pref_dto(peer, pdt, "facts", pref("facts", "map", root, base: [parent], seq: step, size: 2)
        .merge("attrs" => { Ancestry::ATTR => vg.call(root, [parent], [link], step) }), ms(T0) + (1000 * step),
                                       entry_id: entry_id, issuer: writer)
    end
    facts = pdt.map_ref("facts")
    chain = unserved.cids
    asks = -> { holder.frames.count { |f| f[2]["t"] == Tree::NODE_WANT && f[2]["cids"].intersect?(chain) } }
    assert_equal({ "a" => 10, "b" => 2 }, facts.deref.to_h, "with no base the later head wins whole")
    assert_equal 1, asks.call, "the merge asked for the chain once"
    missed = pdt.stats["chainNodesMissed"]
    assert_operator missed, :>, 0, "the walk counted the links it left out"
    2.times do # the second outlasts the first ask's batch
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      assert_equal({ "a" => 10, "b" => 2 }, facts.deref.to_h)
      assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 0.25, "a later merge waits for nothing"
    end
    assert_equal 1, asks.call, "and asks for nothing while the nodes' backoff runs"
    assert_operator pdt.stats["chainNodesMissed"], :>, missed, "each later merge counts the links it left out"
    unserved.cids.each { |c| holder_store.put(unserved.get(c)) }
    sleep 1.1 # past the nodes' backoff (0.3 s) and the batch's bench of the holder that lacked them (1 s), each with its spread
    assert_equal({ "a" => 10, "b" => 20 }, facts.deref.to_h, "past the backoff the walk reaches the base")
  ensure
    swap_const(Refs, :RETRY_BASE, retry_base)
  end

  # PDT 2 phase 1 (P2-X-09): the Ruby face reads the content-swarm messages it
  # receives as their records' own encodings under the annex I schemas: every
  # field the record names, in its order, of its type, and canonical CID text.
  # A message that is not, and a tag that is no message of this level, is
  # dropped and counted in treeMessagesDropped and strikes nobody; a piece
  # message (tags 1 to 7) is left to the handler before this one.
  def test_a_content_swarm_message_outside_its_schema_is_dropped_counted_and_strikes_nobody
    peer = peer_at(T0)
    trees = Trees.new(peer, NodeStore.new, load_timeout: 1.0)
    cid = Cids.of("x".b)
    padded = cid[0...-1] + Cids::ALPHABET[Cids::ALPHABET.index(cid[-1]) ^ 1]
    refute Cids.cid?(padded), "a CID text with non-zero padding bits is not canonical"
    nodes = Tree.nodes_message(1, ["n".b], nil, nil, nil)
    tree_end = Tree.tree_end(1, [cid], Tree::END_DONE)
    assert_nil Tree.violation(nodes)
    assert_nil Tree.violation(tree_end)
    broken = [
      nodes.merge("extra" => 1),
      nodes.reject { |k, _| k == "missing" },
      nodes.to_a.reverse.to_h,
      nodes.merge("sealed" => "s".b, "nodes" => nil, "epoch" => "4"),
      nodes.merge("req" => 1 << 31),
      tree_end.merge("frontier" => [padded]),
      tree_end.merge("reason" => 1 << 40),
      Tree.reject(cid, Tree::TREE_INDEX, 1).merge("reason" => "1"),
      { "t" => 12, "req" => 1 },
      { "t" => 99 },
      { "t" => "9", "req" => 1 }
    ]
    broken.each { |msg| assert trees.on_frame("sender", cbor(msg)), msg.inspect }
    assert trees.on_frame("sender", "\xFF".b), "an undecodable payload"
    assert_equal broken.size + 1, trees.stats[:tree_messages_dropped]
    assert_equal 0, trees.stats[:struck_senders]
    refute trees.on_frame("sender", cbor({ "t" => 3, "root" => cid }))
    refute trees.on_frame("sender", cbor(Tree.reject(cid, 2, 1))), "a piece REJECT is not the tree's"
    assert_equal broken.size + 1, trees.stats[:tree_messages_dropped]
  end

  # ------------------------------------------------------------------ the record-free renew

  def test_the_peer_advertises_the_recordless_hint
    peer = peer_at(T0)
    assert_equal({ "wire.recordless" => "1", "wire.appcard" => "2" }, peer.wire_hints)
    sent = []
    peer.define_singleton_method(:send_frame) { |kind, body, to = nil| sent << [kind, body, to] }
    peer.introduce
    assert_equal 1, sent.size
    rumor = load(sent[0][1])
    ad = load(load(rumor["payload"])["adBytes"])
    assert_equal({ "wire.appcard" => "2", "wire.session" => "1", "wire.recordless" => "1" }, ad["resourceHints"])
    peer.channel_auth = :signed
    peer.introduce
    ad = load(load(load(sent[1][1])["payload"])["adBytes"])
    assert_equal({ "wire.appcard" => "2", "wire.recordless" => "1" }, ad["resourceHints"])
  end

  def test_a_recordless_renew_merges_over_a_held_record_and_waits_for_a_missing_one
    delta = load(hex("state_delta_recordless_cbor"))
    recordless = delta["state"]
    assert_nil recordless["record"]
    assert_equal ENTRY, recordless["entryId"]
    full = load(hex("delta_cbor"))["state"]
    before = full["leaseValue"]["expiresAtMillis"]
    now = ms(GOLDEN["certificate_verify_at"])
    # the record is held: the renew lands and the later lease stamp wins
    peer = peer_at(now)
    events = []
    peer.on_state = ->(dto) { events << dto }
    peer.fold_state(full)
    assert_equal [ENTRY], peer.states.keys
    peer.fold_state(recordless.dup)
    merged = peer.states[ENTRY]
    assert_equal recordless["leaseValue"]["expiresAtMillis"], merged["leaseValue"]["expiresAtMillis"]
    assert_operator merged["leaseValue"]["expiresAtMillis"], :>, before
    assert_equal recordless["leaseStamp"], merged["leaseStamp"]
    assert_equal full["record"], merged["record"]
    assert_equal 2, events.size
    assert_empty peer.pending_states
    # the record is not held: the state waits with no entry and no event until the whole DTO arrives
    late = peer_at(now)
    late_events = []
    late.on_state = ->(dto) { late_events << dto }
    late.fold_state(recordless.dup)
    assert_empty late.states
    assert_equal [ENTRY], late.pending_states.keys
    assert_empty late_events
    late.fold_state(full)
    assert_equal recordless["leaseValue"]["expiresAtMillis"], late.states[ENTRY]["leaseValue"]["expiresAtMillis"]
    assert_empty late.pending_states
    assert_equal 2, late_events.size
    # a forged recordless state fails the state signature and never lands
    forged = recordless.dup.merge("leaseValue" => recordless["leaseValue"].merge("expiresAtMillis" => recordless["leaseValue"]["expiresAtMillis"] + 1))
    peer.fold_state(forged)
    assert_equal recordless["leaseValue"]["expiresAtMillis"], peer.states[ENTRY]["leaseValue"]["expiresAtMillis"]
    # the rumor item id names the entry when the DTO does not, and a bounded pending set drops the oldest
    unnamed = recordless.dup.tap { |s| s.delete("entryId") }
    assert_equal ENTRY, peer.name_recordless(unnamed, "r:#{ENTRY}:123")["entryId"]
    bounded = peer_at(now)
    # HLC round five, 2026-11-08 (E7): a pending state carries its lease, since the peer drops one without it.
    # HLC round six, 2026-11-08 (F3): each is a whole EntryStateDto, its record omitted as Java omits it.
    (AgentSpaces::Peer::MAX_PENDING_STATES + 5).times do |i|
      bounded.fold_state(recordless.merge("entryId" => "p-#{i}"))
    end
    assert_equal AgentSpaces::Peer::MAX_PENDING_STATES, bounded.pending_states.size
    refute bounded.pending_states.key?("p-0")
  end
end
