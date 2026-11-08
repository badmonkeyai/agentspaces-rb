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

  # new java.util.Random(seed).nextBytes(new byte[n]): the 48-bit LCG, little-endian ints.
  def java_random_bytes(seed, n)
    mask = (1 << 48) - 1
    s = (seed ^ 0x5DEECE66D) & mask
    out = String.new(encoding: Encoding::BINARY)
    while out.bytesize < n
      s = ((s * 0x5DEECE66D) + 0xB) & mask
      rnd = s >> 16
      [4, n - out.bytesize].min.times do
        out << (rnd & 0xFF)
        rnd >>= 8
      end
    end
    out
  end

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
    assert_in_delta 1.5, embedded["f"], 0.0
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
    { "record" => record, "completed" => false, "adds" => [], "removes" => [] }
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
  # record's own stamp for any other.
  def test_the_head_order_reads_no_negative_unreadable_or_fractional_stamp
    assert_equal [5, 3, "n"], Refs.hlc("5:3:n")
    ["5:-1:n", "5:x:n", "5:0x10001:n", "5:1.5:n", "-5:0:n", nil].each do |stamp|
      assert_equal [0, 0, ""], Refs.hlc(stamp), "the reader ignores #{stamp.inspect}"
    end
  end

  # HLC canonical stamps, 2026-11-08: a rewrite's pdt.issued attr orders its
  # head as Java's Refs.toHead reads it: HlcTimestamp.parse, which reads a
  # counter above the logical limit, with or without a pdt.issuer beside it,
  # and the entry's own stamp when the attr does not decode.
  def test_a_head_orders_by_its_pdt_issued_attr_as_java_reads_it
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt")
    store = pdt.store
    first = map_node(store, { "a" => 1 })
    later = map_node(store, { "b" => 2 })
    other = "#{AgentSpaces::Identity.generate.peer_id}/app"
    peer.states["e-first"] = pref_dto(peer, pdt, "facts", pref("facts", "map", first, size: 1), ms(T0) + 1000,
                                      entry_id: "e-first")
    above = AgentSpaces::Wire::HLC_LOGICAL_LIMIT + 1
    rewrite = lambda do |attrs|
      peer.states["e-later"] = pref_dto(peer, pdt, "facts", pref("facts", "map", later, size: 1).merge("attrs" => attrs),
                                        ms(T0) + 2000, entry_id: "e-later", issuer: other)
      pdt.map_ref("facts").heads
    end
    heads = rewrite.call({ Refs::ISSUED_ATTR => "#{ms(T0)}:#{above}:x", Refs::ISSUER_ATTR => other })
    assert_equal [later, first], heads.map(&:root), "the attr above the limit orders the rewrite first"
    assert_equal [ms(T0), above], heads[0].issued.first(2)
    heads = rewrite.call({ Refs::ISSUED_ATTR => "#{ms(T0)}:0:x" })
    assert_equal [later, first], heads.map(&:root), "pdt.issued alone orders the head"
    assert_equal other, heads[0].issuer
    ["0#{ms(T0)}:0:x", "#{ms(T0)}:-1:x", "#{ms(T0)}:0:x".b].each do |malformed|
      heads = rewrite.call({ Refs::ISSUED_ATTR => malformed, Refs::ISSUER_ATTR => other })
      assert_equal [first, later], heads.map(&:root), "#{malformed.inspect} leaves the entry's own stamp"
      assert_equal [ms(T0) + 2000, 0], heads[1].issued.first(2)
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
    error = assert_raises(NodeUnavailable) { trees.load(nowhere, prefer: [holder.id], timeout: 2.0) }
    assert_includes error.message, "not held by any source"
    assert_includes error.sources, holder.id
    # a refusal drops the source and the fetch fails naming it
    holder.refuse!
    store.remove(entries[1].cid)
    bare = trees.fetch_nodes([entries[1].cid], prefer: [holder.id], timeout: 2.0)
    refute bare.wait(2.0)
    assert_includes bare.failure, "every source refused"
    assert_equal 1, trees.stats[:tree_requests_rejected]
    # a reader that holds nothing refuses to serve, by policy
    trees.on_frame(holder.id, AgentSpaces::CBOR.dump(Tree.node_want(99, [root])))
    assert_equal [Tree::REJECT, root, Tree::TREE_INDEX, 3], holder.frames.last[2].values_at("t", "root", "index", "reason")
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

  # ------------------------------------------------------------------ the record-free renew

  def test_the_peer_advertises_the_recordless_hint
    peer = peer_at(T0)
    assert_equal({ "wire.recordless" => "1" }, peer.wire_hints)
    sent = []
    peer.define_singleton_method(:send_frame) { |kind, body, to = nil| sent << [kind, body, to] }
    peer.introduce
    assert_equal 1, sent.size
    rumor = load(sent[0][1])
    ad = load(load(rumor["payload"])["adBytes"])
    assert_equal({ "wire.session" => "1", "wire.recordless" => "1" }, ad["resourceHints"])
    peer.channel_auth = :signed
    peer.introduce
    ad = load(load(load(sent[1][1])["payload"])["adBytes"])
    assert_equal({ "wire.recordless" => "1" }, ad["resourceHints"])
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
    (AgentSpaces::Peer::MAX_PENDING_STATES + 5).times { |i| bounded.fold_state({ "record" => nil, "entryId" => "p-#{i}" }) }
    assert_equal AgentSpaces::Peer::MAX_PENDING_STATES, bounded.pending_states.size
    refute bounded.pending_states.key?("p-0")
  end
end
