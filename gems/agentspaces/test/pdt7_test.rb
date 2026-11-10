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
require_relative "pdt2_test"

# PDT 2 phase 7 (srad/agentspaces-pdt2.md 8; P2-C-02, P2-X-06), read and
# written from Ruby: PRef.v 2 heads and db refs, the DataScript reader of the
# sample database, relaxed vectors and their packed form, text values, BLAKE3
# ranges verified through a Bao outboard, the signed pins Ruby writes, and the
# writer of P2-X-06 (Ref#swap in multi mode with inline deltas, and the serving
# side that answers NODE_WANT and TREE_WANT).
class Pdt7Test < Minitest::Test
  include GoldenHelpers
  include AgentSpaces::PDT

  T0 = "2025-01-01T00:00:00Z"

  def parts(name) = GOLDEN.fetch(name).split(",")

  def unhex(text) = [text].pack("H*")

  # The state of an entry its issuer added and nobody removed.
  def present(record)
    { "record" => record, "completed" => false, "adds" => [{ "replica" => record["issuer"].split("/").first, "counter" => 1 }],
      "removes" => [] }
  end

  # A loader over a node store that counts the nodes a read asks for.
  class CountingLoader
    attr_reader :loads

    def initialize(store)
      @store = store
      @loads = []
    end

    def load(cid)
      @loads << cid
      data = @store.get(cid)
      raise NodeUnavailable, cid if data.nil?

      data
    end
  end

  # ------------------------------------------------------------------ P2-F-06, PRef.v 2 and kind db

  def test_a_level_two_reader_reads_a_version_two_head_and_a_db_head_is_version_two
    record = Refs.decode(hex("pdt_ref_v2_cbor"))
    refute_nil record
    assert_equal [2, "graph", "db", "linear"], record.values_at("v", "name", "kind", "mode")
    assert_nil Refs.violation(record)
    assert_equal hex("pdt_ref_v2_cbor"), cbor(record)
    assert_includes Refs::KINDS, Refs::KIND_DB
    assert_equal "a db head is version 2, found 1", Refs.violation(record.merge("v" => 1))
    assert_equal "unsupported PRef version 3", Refs.violation(record.merge("v" => 3))
    map_head = Refs.decode(hex("pdt_ref_cbor"))
    assert_nil Refs.violation(map_head.merge("v" => 2)), "a map head whose tree holds a level-2 kind is version 2"
  end

  # ------------------------------------------------------------------ P2-C-02, the db reader

  def sample_store
    root, *blobs = parts("pdt_db_sample")
    store = NodeStore.new
    blobs.each { |blob| store.put(unhex(blob)) }
    [store, root]
  end

  def answers
    GOLDEN.fetch("pdt_db_sample_answers").split(",").to_h do |pair|
      name, leaf = pair.split("=", 2)
      [name, DnNode.decode(unhex(leaf)).datoms.map { |d| [d.e, d.a, d.v] }]
    end
  end

  def test_the_golden_sample_answers_as_datascript_does
    store, root = sample_store
    loader = CountingLoader.new(store)
    db = DbReader.new(root, loader)
    assert_equal [root], loader.loads, "the reader reads the root and nothing else"
    assert_equal 126, db.max_eid
    read = ->(index, *components) { db.datoms(index, *components).map { |d| [d.e, d.a, d.v] } }
    expected = answers
    assert_equal %w[eavt_7 eavt_126 aevt_name avet_name_ada avet_friend_9 entity_42 lookup_email_p42 avet_name_person7],
                 expected.keys
    assert_equal 1001, read.call("eavt").size
    assert_equal expected["eavt_7"], read.call("eavt", 7)
    assert_equal expected["eavt_126"], read.call("eavt", 126)
    assert_equal expected["aevt_name"], read.call("aevt", ":p/name")
    assert_equal expected["avet_name_ada"], read.call("avet", ":p/name", "Ada")
    assert_equal expected["avet_friend_9"], read.call("avet", ":p/friend", 9)
    assert_equal expected["entity_42"], read.call("eavt", 42)
    assert_equal expected["lookup_email_p42"], read.call("avet", ":p/email", "p42@example.org")
    assert_equal [], read.call("avet", ":p/name", "Person 7")
    assert_equal [], expected["avet_name_person7"]
    assert_equal 42, db.lookup(":p/email", "p42@example.org")
    assert_equal [":tag/odd"], db.entity(7)[":p/tag"]
    assert_equal "Ada", db.entity(7)[":p/name"]
    error = assert_raises(ArgumentError) { db.datoms("avet", ":p/score") }
    assert_includes error.message, ":db/index"
    assert_raises(ArgumentError) { db.lookup(":p/name", "Ada") }
  end

  def test_an_entity_reads_only_its_own_path
    store, root = sample_store
    loader = CountingLoader.new(store)
    db = DbReader.new(root, loader)
    db.entity(42)
    depth_plus_root_and_tail = 5
    assert_operator loader.loads.size, :<=, depth_plus_root_and_tail
  end

  def test_values_compare_as_datascript_value_compare_does
    big = ->(n) { Datom::Tagged.new(Datom::Tagged::BIGINT, [n.to_s(16).rjust(2, "0")].pack("H*")) }
    uuid = ->(hex) { Datom::Tagged.new(Datom::Tagged::UUID, [hex].pack("H*")) }
    instant = ->(ms) { Datom::Tagged.new(Datom::Tagged::INSTANT, ms) }
    [[":a/c", ":a.b/c", -1], [":a", ":a/b", -1], [":b", ":a/b", -1], ["\u{FFFF}", "\u{1F600}", 1],
     [1, 1.0, 0], [1, 1.5, -1], [2, big.call(2), 0], [big.call(5), 6, -1], [1, true, 1], [true, "x", -1],
     [":x", "x", -1], ["\x01".b, "x", -1], [big.call(5), "s", -1], [1.5, true, 1], [false, true, -1],
     [uuid.call("80" + "00" * 15), uuid.call("00" * 16), -1], [instant.call(5), instant.call(6), -1],
     [instant.call(5), uuid.call("00" * 16), -1], ["\\:x", "B", -1], ["\\b", "a", 1], ["\\:x", ":x", 1],
     ["\\:x", "\\:x", 0], [":", "a", -1], [":", ":a", 1]].each do |x, y, sign|
      assert_equal sign, DbReader.compare_values(x, y), "#{x.inspect} against #{y.inspect}"
      assert_equal(-sign, DbReader.compare_values(y, x), "#{y.inspect} against #{x.inspect}")
    end
    assert_equal 0, DbReader.compare_values("\x01".b, "\x01".b)
    assert_nil DbReader.compare_values("\x01".b, "\x02".b), "DataScript orders two byte arrays by identity hash"
  end

  def test_a_leaf_out_of_comparator_order_or_a_retraction_in_an_index_is_refused_by_name
    tx = 0x20000001
    store = NodeStore.new
    out_of_order = DnNode.new(0, DnNode::EAVT, [Datom.new(2, ":a/b", 1, tx), Datom.new(1, ":a/b", 1, tx)], [])
    retraction = DnNode.new(0, DnNode::AEVT, [Datom.new(1, ":a/b", 1, -tx)], [])
    empty = DnNode.new(0, DnNode::AVET, [], [])
    links = [out_of_order, retraction, empty].map { |n| Nodes::Link.new(store.put(n.encode)) }
    schema = Nodes::Embedded.new(cbor({}))
    root = store.put(DbRoot.new(schema, 2, tx, 128, links[0], links[1], links[2], nil).encode)
    db = DbReader.new(root, StoreLoader.new(store))
    error = assert_raises(NodeFormatError) { db.datoms("eavt").to_a }
    assert_includes error.message, "datoms out of eavt order"
    error = assert_raises(NodeFormatError) { db.datoms("aevt").to_a }
    assert_includes error.message, "an index holds assertions only"
  end

  def test_a_db_ref_derefs_to_a_reader_of_its_head
    store, root = sample_store
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt", store: store)
    head = Refs.decode(hex("pdt_ref_v2_cbor")).merge("root" => root, "name" => "sample")
    record = { "entryId" => "e-db", "spaceId" => pdt.space_id, "type" => Refs::TYPE, "payload" => cbor(head),
               "issuer" => "#{peer.identity.peer_id}/app", "issued" => "#{ms(T0)}:0:#{peer.identity.peer_id}",
               "lease" => { "expiresAtMillis" => peer.now_ms + 600_000 }, "tags" => Refs.tags(head) }
    peer.states["e-db"] = present(record)
    db = pdt.db_ref("sample").deref
    assert_kind_of DbReader, db
    assert_equal 42, db.lookup(":p/email", "p42@example.org")
    assert_equal 0, pdt.stats["headsIgnored"]
    assert_equal 1, pdt.db_ref("sample").heads.size
  end

  # ------------------------------------------------------------------ P2-X-06, the writer builds Java's trees

  def build_root(node)
    store = NodeStore.new
    flusher = Build::Flusher.new(store)
    [flusher.cid_of(node), store, flusher]
  end

  def test_the_writer_builds_the_map_vectors_byte_for_byte
    root, store, = build_root(Build::MapNode.of([]))
    assert_equal hex("pdt_map_empty"), store.get(root)
    root, store, = build_root(Build::MapNode.of([[cbor("a"), cbor(1)], [cbor("b"), cbor("two")]]))
    assert_equal hex("pdt_map_small"), store.get(root)
    deep = (0...100).map { |i| [cbor("k#{i}"), cbor(i)] }
    root, store, flusher = build_root(Build::MapNode.of(deep.reverse))
    assert_equal hex("pdt_map_deep"), store.get(root)
    assert_equal store.size, flusher.written.size, "every node is new to an empty store"
    map = PMap.load(root, StoreLoader.new(store))
    assert_equal 100, map.count
    assert_equal 42, map["k42"]
    embedded = Build::MapNode.of([[cbor("rec"), cbor({ "x" => 1, "y" => "two" })], [cbor("f"), unhex("fa3fc00000")]])
    root, store, = build_root(embedded)
    assert_equal hex("pdt_node_embedded"), store.get(root)
    # a key given twice keeps its last value and counts once
    root, store, = build_root(Build::MapNode.of([[cbor("a"), cbor(0)], [cbor("a"), cbor(1)], [cbor("b"), cbor("two")]]))
    assert_equal hex("pdt_map_small"), store.get(root)
  end

  def test_the_writer_builds_the_vector_vectors_byte_for_byte
    root, store, = build_root(Build::VecBuild.of((0...10).map { |i| cbor(i) }))
    assert_equal hex("pdt_vector_tail"), store.get(root)
    root, store, = build_root(Build::VecBuild.of((0...1100).map { |i| cbor(i) }))
    assert_equal hex("pdt_vector_deep"), store.get(root)
    assert_equal (0...1100).to_a, PVector.load(root, StoreLoader.new(store)).to_a
    # past 32 x 32 elements the trie grows a level
    big = (0...(32 * 32 + 33)).map { |i| cbor(i) }
    root, store, = build_root(Build::VecBuild.of(big))
    vector = PVector.load(root, StoreLoader.new(store))
    assert_equal big.size, vector.count
    assert_equal 1056, vector[1056]
  end

  def test_the_chunker_cuts_the_pinned_stream_and_the_writer_builds_the_small_blob
    stream = java_random_bytes(42, 2 * 1024 * 1024)
    cuts = []
    offset = 0
    20.times do
      offset += FastCdc.cut(stream, offset, stream.bytesize - offset)
      cuts << offset
    end
    assert_equal GOLDEN.fetch("pdt_fastcdc_cuts").split(",").map(&:to_i), cuts
    root, *chunks = parts("pdt_blob_small")
    store = NodeStore.new
    flusher = Build::Flusher.new(store)
    assert_equal root, Build.blob(java_random_bytes(42, 100 * 1024), flusher)
    assert_equal chunks.sort, (flusher.written.keys - [root]).sort
    assert_equal Cids.of("".b, Cids::RAW), Build.blob("".b, flusher)
  end

  def test_values_spill_as_java_spills_them
    store = NodeStore.new
    flusher = Build::Flusher.new(store)
    loader = StoreLoader.new(store)
    small = cbor("x" * 100)
    assert_equal small, Build.spill(small)
    [cbor("x" * 2000), cbor((0...2000).to_a), cbor((0...500).to_h { |i| ["k#{i}", i] }),
     cbor((0...500).to_h { |i| ["k#{i}", i] }.to_a.reverse.to_h), cbor(java_random_bytes(7, 40_000)),
     cbor((0...300).map { |i| "v#{i}" })].each do |item|
      spilled = Build.spill(item)
      refute_kind_of String, spilled
      cid = flusher.cid_of(spilled)
      assert_equal item, Values.resolve(cid, loader), "a spilled value reads back as its item"
    end
    assert_raises(ArgumentError) { Build.spill(Nodes.link_item(Cids.of("x".b))) }
    assert_raises(ArgumentError) { Build::MapNode.of([[Nodes.link_item(Cids.of("x".b)), cbor(1)]]) }
  end

  # ------------------------------------------------------------------ P2-R-04, relaxed vectors

  def splice_store
    root, packed, *nodes = parts("pdt_rr_splice")
    store = NodeStore.new
    nodes.each { |node| store.put(unhex(node)) }
    [store, root, packed]
  end

  def test_the_relaxed_splice_reads_its_elements_and_packs_to_the_vr_root_of_them
    store, root, packed = splice_store
    vector = PVector.load(root, StoreLoader.new(store))
    assert vector.relaxed?
    expected = (0...500).to_a + [-1] + (500...1100).to_a
    assert_equal 1101, vector.count
    assert_equal expected, vector.to_a
    assert_equal(-1, vector[500])
    assert_equal 1099, vector[1100]
    assert_equal packed, vector.pack(NodeStore.new)
    dense = Build::VecBuild.of(expected.map { |i| cbor(i) })
    assert_equal packed, Build::Flusher.new(NodeStore.new).cid_of(dense), "the packed root is the vr root of the elements"
    vector.pack(store)
    refute PVector.load(packed, StoreLoader.new(store)).relaxed?
    assert_equal expected, PVector.load(packed, StoreLoader.new(store)).to_a
  end

  def test_a_relaxed_tree_that_breaks_its_shape_is_refused_by_name
    store, root, = splice_store
    rr = RrRoot.decode(store.get(root), root)
    interior = store.get(rr.trie.cid)
    # an rv node without z is refused where a relaxed tree reads it
    rv = RvNode.decode(interior)
    refute_nil rv.sizes, "the splice's top node is relaxed"
    bare = store.put(RvNode.new(rv.children, nil).encode)
    forged = store.put(RrRoot.new(rr.count, rr.shift, Nodes::Link.new(bare), rr.tail).encode)
    error = assert_raises(NodeFormatError) { PVector.load(forged, StoreLoader.new(store)).to_a }
    assert_includes error.message, "an rv node without z"
    # a size table whose last count disagrees with the root's count
    longer = store.put(RrRoot.new(rr.count + 1, rr.shift, rr.trie, rr.tail).encode)
    error = assert_raises(NodeFormatError) { PVector.load(longer, StoreLoader.new(store))[0] }
    assert_includes error.message, "does not hold the"
    error = assert_raises(NodeFormatError) do
      PVector.load(store.put(RrRoot.new(rr.count, 35, rr.trie, rr.tail).encode), StoreLoader.new(store))
    end
    assert_includes error.message, "shift 35"
    dense = (0...64).map { |i| cbor(i) }
    leaves = [dense[0, 32], dense[32, 32]].map { |e| Nodes::Link.new(store.put(Nodes.encode({ "k" => "v", "e" => e.map { |x| Nodes::Embedded.new(x) } }))) }
    table = store.put(RvNode.new(leaves, [32, 64]).encode)
    forged = store.put(RrRoot.new(65, 5, Nodes::Link.new(table), [cbor(64)]).encode)
    error = assert_raises(NodeFormatError) { PVector.load(forged, StoreLoader.new(store))[3] }
    assert_includes error.message, "a size table on a dense node"
  end

  # ------------------------------------------------------------------ P2-T-05, text values

  def test_the_text_edits_replay_byte_for_byte_and_merge_to_the_pinned_union
    alice_hex, bob_hex, union_hex, text = parts("pdt_text_edits")
    base = PText.empty("alice").insert(0, "Hello world").insert(5, ";")
    assert_equal "Hello; world", base.to_s
    alice = base.delete(0, 1).insert(0, "J")
    bob = base.with_replica("bob").insert(12, "!").insert(7, "big ")
    assert_equal unhex(alice_hex), alice.leaf.encode
    assert_equal unhex(bob_hex), bob.leaf.encode
    assert_equal unhex(union_hex), alice.merge(bob).leaf.encode
    assert_equal unhex(union_hex), bob.merge(alice).leaf.encode
    assert_equal text, alice.merge(bob).to_s
    assert_equal "Jello; big world!", text
    assert_equal "Jello; world", alice.to_s
    assert_equal "Hello; big world!", bob.to_s
    read = PText.of(TextLeaf.decode(unhex(alice_hex)), "alice")
    assert_equal alice, read
    assert_equal "Jxello; world", read.insert(1, "x").to_s
    assert_equal alice.insert(1, "x").leaf, read.insert(1, "x").leaf, "a text read back edits as the one written"
  end

  def test_the_text_value_form_reads_strictly
    value = hex("pdt_text_value")
    assert PText.value?(value)
    leaf = PText.leaf_of(value)
    assert_equal TextLeaf.decode(hex("pdt_text_runs")), leaf
    assert_equal value, PText.to_wire(leaf)
    text = Values.decode_value(value)
    assert_kind_of PText, text
    assert_equal "Ab\u{1F600}cé!", text.to_s
    assert_nil text.replica
    assert_raises(ArgumentError) { text.insert(0, "x") }
    assert_equal "xAb\u{1F600}cé!", text.with_replica("carol").insert(0, "x").to_s
    map = load(value)
    refute PText.value?(cbor(map.merge("v" => 2)))
    refute PText.value?(cbor(map.to_a.reverse.to_h)), "keys out of order"
    refute PText.value?(cbor(map.merge("x" => 1)))
    refute PText.value?(cbor({ "k" => "t", "r" => map["r"].reverse, "v" => 1 })), "runs out of canonical order"
    refute PText.value?(cbor("text"))
  end

  def test_a_map_of_texts_spills_its_long_text_to_a_t_node_and_reads_both
    root_hex, t_hex = parts("pdt_text_spill")
    note = PText.of(PText.leaf_of(hex("pdt_text_value")))
    doc = PText.empty("alice").insert(0, "x" * 1100)
    built = Build::MapNode.of([[cbor("doc"), doc.to_wire], [cbor("note"), note.to_wire]])
    root, store, = build_root(built)
    assert_equal unhex(root_hex), store.get(root)
    assert_equal [unhex(t_hex)], store.cids.reject { |c| c == root }.map { |c| store.get(c) }
    map = PMap.load(root, StoreLoader.new(store))
    assert_equal "x" * 1100, map["doc"].to_s
    assert_equal note, map["note"]
  end

  def test_a_replica_id_is_eight_base32_characters_of_the_agents_sha256
    agent, replica = parts("pdt_text_replica")
    assert_equal replica, PText.replica_of(agent)
    assert_equal 8, replica.length
  end

  # ------------------------------------------------------------------ P2-C-02, BLAKE3 ranges

  def small_blob
    stream = java_random_bytes(42, 100 * 1024)
    store = NodeStore.new
    root = Build.blob(stream, Build::Flusher.new(store))
    bao = store.put(unhex(parts("pdt_bo_small")[0]))
    [stream, store, root, BlobIdentity.new(parts("pdt_bo_small")[1], bao)]
  end

  def test_blake3_hashes_as_the_reference_and_the_small_stream_hashes_to_its_identity
    # the reference implementation's answers for the empty input and for "abc"
    assert_equal "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", Blake3.root("".b).unpack1("H*")
    assert_equal "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85", Blake3.root("abc".b).unpack1("H*")
    stream, = small_blob
    assert_equal Blake3.identity_digest(parts("pdt_bo_small")[1]), Blake3.root(stream)
    # the outboard's parents are the chaining values of the stream's groups
    node = BoNode.decode(unhex(parts("pdt_bo_small")[0]))
    groups = (0...7).map { |g| Blake3.group_cv(stream.byteslice(g * BoNode::GROUP_BYTES, BoNode::GROUP_BYTES), g << BoNode::GROUP_LOG) }
    assert_equal groups[0] + groups[1], node.parents.byteslice(2 * 64, 64), "the pair over groups 0 and 1, in pre-order"
  end

  def test_a_window_of_a_blob_verifies_group_by_group_against_its_identity
    stream, store, root, claim = small_blob
    blob = PBlob.load(root, StoreLoader.new(store))
    [[0, 1], [20_000, 50_000], [(16 * 1024) - 1, 2], [0, 100 * 1024], [(100 * 1024) - 7, 7]].each do |offset, length|
      assert_equal stream.byteslice(offset, length), blob.read_verified(offset, length, claim), "#{offset}+#{length}"
    end
    assert_equal "".b, blob.read_verified(5, 0, claim)
    assert_raises(IndexError) { blob.read_verified(100 * 1024, 1, claim) }
    # another blob of the same size read under this claim: the outboard chains, its first group does not verify
    other = PBlob.load(Build.blob(java_random_bytes(43, 100 * 1024), Build::Flusher.new(store)), StoreLoader.new(store))
    error = assert_raises(VerificationError) { other.read_verified(0, 10, claim) }
    assert_includes error.message, "chunk group 0"
    # a node outside the outboard's chain, or of another size, fails before any byte
    parents = BoNode.decode(store.get(claim.bao)).parents.dup
    parents.setbyte(0, parents.getbyte(0) ^ 1)
    forged = BlobIdentity.new(claim.identity, store.put(BoNode.new(100 * 1024, parents, []).encode))
    error = assert_raises(VerificationError) { blob.read_verified(0, 10, forged) }
    assert_includes error.message, "does not chain to the identity"
    shorter = BlobIdentity.new(claim.identity, store.put(BoNode.new(100, "".b, []).encode))
    assert_includes assert_raises(VerificationError) { blob.read_verified(0, 10, shorter) }.message, "covers 100 bytes"
    missing = BlobIdentity.new(claim.identity, Cids.of("absent".b))
    assert_includes assert_raises(VerificationError) { blob.read_verified(0, 10, missing) }.message, "does not read"
  end

  def test_a_window_past_the_first_leaf_of_the_split_outboard_verifies_through_the_root
    split, identity, full_leaf, last_leaf = parts("pdt_bo_split")
    leaf = BoNode.new(5000, "".b, [])
    assert_equal last_leaf, Cids.of(leaf.encode)
    tail = java_random_bytes(42, 5000, skip: 8 * 1024 * 1024)
    store = NodeStore.new
    bao = store.put(unhex(split))
    store.put(leaf.encode)
    # a blob tree whose first 8 MiB sit in chunks this reader never loads, and whose last chunk holds the tail
    front = (0...32).map { |i| [Cids.of("never loaded #{i}".b, Cids::RAW), 256 * 1024] }
    chunks = front + [[store.put(tail, Cids::RAW), 5000]]
    root = store.put(Nodes.encode({ "k" => "b", "h" => 1, "c" => chunks.map { |c, _| Nodes::Link.new(c) }, "z" => chunks.map(&:last) }))
    blob = PBlob.load(root, StoreLoader.new(store))
    claim = BlobIdentity.new(identity, bao)
    window = (8 * 1024 * 1024) + 100
    assert_equal tail.byteslice(100, 4000), blob.read_verified(window, 4000, claim)
    refute store.has?(full_leaf), "the window reads the root and the last leaf alone"
    error = assert_raises(VerificationError) { blob.read_verified(0, 10, claim) }
    assert_includes error.message, "does not read", "a window over the first leaf needs that leaf"
  end

  def test_a_blob_head_names_its_identity_and_a_ref_reads_a_verified_window
    stream, store, root, claim = small_blob
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt", store: store)
    attrs = { BlobIdentity::BAO_ATTR => claim.bao, BlobIdentity::BLAKE3_ATTR => claim.identity }
    head = Refs.decode(hex("pdt_ref_min_cbor")).merge("name" => "file", "kind" => "blob", "root" => root,
                                                       "size" => stream.bytesize, "attrs" => AgentSpaces::CBOR.canonical_map(attrs))
    record = { "entryId" => "e-blob", "spaceId" => pdt.space_id, "type" => Refs::TYPE, "payload" => cbor(head),
               "issuer" => "#{peer.identity.peer_id}/app", "issued" => "#{ms(T0)}:0:#{peer.identity.peer_id}",
               "lease" => { "expiresAtMillis" => peer.now_ms + 600_000 }, "tags" => Refs.tags(head) }
    peer.states["e-blob"] = present(record)
    ref = pdt.blob_ref("file")
    assert_equal claim, ref.claim(root)
    assert_equal stream.byteslice(1000, 30_000), ref.read_verified(1000, 30_000)
    assert_nil BlobIdentity.read({ "pdt.blake3" => claim.bao, "pdt.bao" => claim.bao }), "an identity of another hash reads as absent"
    assert_nil BlobIdentity.read({ "pdt.blake3" => claim.identity }), "a claim needs both attributes"
  end

  # ------------------------------------------------------------------ P2-X-06, Ruby writes

  GROUP = "zRubyPdtWrites"

  def fleet(count)
    clock = AgentSpaces::Testing::TestClock.new
    [clock, AgentSpaces::Testing::Network.fleet(GROUP, count, clock: clock)]
  end

  # The decoded PRef heads of a name a peer holds present, oldest seq first, with their entry ids.
  def heads_of(peer, name)
    peer.states.filter_map do |entry_id, dto|
      record = dto["record"] || {}
      next unless record["type"] == Refs::TYPE && (record["tags"] || {})["name"] == name && AgentSpaces::Peer.present?(dto)

      [entry_id, Refs.decode(peer.payload_of(dto))]
    end.sort_by { |_, head| head["seq"] }
  end

  def test_a_swap_writes_a_head_with_its_delta_inline_and_another_member_reads_it
    _clock, (a, b) = fleet(2)
    writer = Pdt.new(a, space: "pdt")
    reader = Pdt.new(b, space: "pdt")
    value = writer.map_ref("facts").swap { |current| current.merge("a" => 1, "b" => "two") }
    assert_equal({ "a" => 1, "b" => "two" }, value)
    (_, head), = heads_of(a, "facts")
    small = Cids.of(hex("pdt_map_small"))
    assert_equal [1, "facts", "map", small, [], 1, 2, [hex("pdt_map_small")], "multi", "none"],
                 head.values_at("v", "name", "kind", "root", "base", "seq", "size", "nodes", "mode", "sealing")
    assert_nil Refs.violation(head)
    vg = Ancestry.cid(head)
    refute_nil vg, "a Ruby head names its vg node (P2-V-01)"
    node = Ancestry.node(vg, small, writer.store.get(vg))
    assert_equal [small, [], "#{a.identity.peer_id}/ruby", []], [node.root, node.bases, node.issuer, node.previous]
    assert_equal({ "a" => 1, "b" => "two" }, reader.map_ref("facts").deref.to_h)
    assert_equal 1, reader.stats["deltasInline"]
    assert_equal 0, reader.stats["deltasFetched"]
    # the writer advertises the tree exchange at feature level 1: trees "1" and no pdt parameter (P2-C-02)
    assert reader.trees.advertises_trees?(a.identity.peer_id)
    assert_equal({ "sealing" => "none", "trees" => "1" }, reader.trees.ad_parameters(a.identity.peer_id))
    # the reader fetches the vg node from the writer, who serves it by NODE_WANT
    assert reader.trees.fetch_nodes([vg], prefer: [a.identity.peer_id], timeout: 2.0).wait(2.0)
    assert_equal writer.store.get(vg), reader.store.get(vg)
  end

  def test_a_second_swap_supersedes_the_first_and_the_writer_cancels_its_old_head_after_the_grace
    clock, (a, b) = fleet(2)
    writer = Pdt.new(a, space: "pdt")
    reader = Pdt.new(b, space: "pdt")
    ref = writer.map_ref("facts")
    ref.swap { |m| m.merge("a" => 1, "b" => "two") }
    ref.swap { |m| m.merge("a" => 2) }
    (first_id, first), (_, second) = heads_of(a, "facts")
    assert_equal [2, [first["root"]]], second.values_at("seq", "base")
    chain = Ancestry.node(Ancestry.cid(second), second["root"], writer.store.get(Ancestry.cid(second)))
    assert_equal [[first["root"]], [Ancestry.cid(first)]], [chain.bases, chain.previous.map(&:cid)]
    assert_equal({ "a" => 2, "b" => "two" }, reader.map_ref("facts").deref.to_h)
    assert_equal 1, reader.map_ref("facts").heads.size
    # within the grace the superseded head stays, so a lagging reader still finds its base
    clock.advance(1_000)
    writer.tick
    assert AgentSpaces::Peer.present?(b.states.fetch(first_id))
    clock.advance(1_500)
    writer.tick
    refute AgentSpaces::Peer.present?(b.states.fetch(first_id)), "the writer cancelled its superseded head"
    assert_equal [second["root"]], heads_of(b, "facts").map { |_, h| h["root"] }
    # an unchanged value writes nothing
    ref.swap { |m| m }
    assert_equal 1, heads_of(a, "facts").size
  end

  def test_a_cancelled_head_is_no_head_and_a_renewed_one_lives_past_its_first_lease
    peer = peer_at(T0)
    pdt = Pdt.new(peer, space: "pdt")
    pdt.store.put(hex("pdt_map_small"))
    head = Refs.decode(hex("pdt_ref_min_cbor")).merge("root" => Cids.of(hex("pdt_map_small")), "size" => 2)
    record = { "entryId" => "e-1", "spaceId" => pdt.space_id, "type" => Refs::TYPE, "payload" => cbor(head),
               "issuer" => "#{peer.identity.peer_id}/app", "issued" => "#{ms(T0)}:0:#{peer.identity.peer_id}",
               "lease" => { "expiresAtMillis" => peer.now_ms - 1 }, "tags" => Refs.tags(head) }
    renewed = present(record).merge("leaseValue" => { "expiresAtMillis" => peer.now_ms + 600_000 })
    peer.states["e-1"] = renewed
    assert_equal 1, pdt.map_ref("facts").heads.size
    peer.states["e-1"] = renewed.merge("removes" => renewed["adds"])
    assert_empty pdt.map_ref("facts").heads, "a head whose removes cover its adds was cancelled"
  end

  def test_the_writer_renews_its_live_head_at_half_its_lease
    clock, (a,) = fleet(1)
    writer = Pdt.new(a, space: "pdt")
    writer.map_ref("facts").swap { { "a" => 1 } }
    (entry_id, _), = heads_of(a, "facts")
    expires = AgentSpaces::Peer.lease_of(a.states.fetch(entry_id))["expiresAtMillis"]
    clock.advance(Pdt::HEAD_LEASE_MS / 2)
    writer.tick
    assert_operator AgentSpaces::Peer.lease_of(a.states.fetch(entry_id))["expiresAtMillis"], :>, expires
  end

  def test_a_delta_past_the_inline_bound_is_fetched_from_the_writer_that_serves_it
    _clock, (a, b) = fleet(2)
    writer = Pdt.new(a, space: "pdt")
    reader = Pdt.new(b, space: "pdt", load_timeout: 5.0)
    big = (0...3000).to_h { |i| ["key-#{i}", "value-#{i}" * 3] }
    writer.map_ref("big").swap { big }
    (_, head), = heads_of(a, "big")
    assert_nil head["nodes"], "a delta past 32 KiB travels by request"
    value = reader.map_ref("big").deref
    assert_equal 3000, value.count
    assert_equal big["key-2999"], value["key-2999"]
    assert_equal 1, reader.stats["deltasFetched"]
    assert_operator writer.stats["nodes_served"], :>, 1
    # a value built in Ruby has the root Java gives the same entries, so a second writer's equal map is one root
    other = Build::Flusher.new(NodeStore.new).cid_of(Build::MapNode.of(big.map { |k, v| [cbor(k), cbor(v)] }))
    assert_equal other, head["root"]
  end

  def test_sets_vectors_and_blobs_swap_and_read_back
    _clock, (a, b) = fleet(2)
    writer = Pdt.new(a, space: "pdt")
    reader = Pdt.new(b, space: "pdt", load_timeout: 5.0)
    writer.set_ref("tags").swap { |s| s | Set["red", "blue"] }
    assert_equal Set["red", "blue"], reader.set_ref("tags").deref.to_set
    writer.vector_ref("log").swap { |v| v + (0...1100).to_a }
    assert_equal (0...1100).to_a, reader.vector_ref("log").deref.to_a
    assert_equal Cids.of(hex("pdt_vector_deep")), heads_of(a, "log").last[1]["root"]
    stream = java_random_bytes(42, 100 * 1024)
    writer.blob_ref("file").swap { stream }
    assert_equal parts("pdt_blob_small")[0], heads_of(a, "file").last[1]["root"]
    assert_equal stream, reader.blob_ref("file").deref.read_all
    assert_equal stream.bytesize, heads_of(a, "file").last[1]["size"]
    error = assert_raises(ArgumentError) { writer.map_ref("facts").swap { [1, 2] } }
    assert_includes error.message, "a map ref's value is a Hash"
    assert_raises(ArgumentError) { writer.db_ref("graph").swap { |db| db } }
  end

  def test_a_swap_refuses_a_ref_whose_heads_are_linear
    _clock, (a,) = fleet(1)
    writer = Pdt.new(a, space: "pdt")
    writer.map_ref("facts").swap { { "a" => 1 } }
    (entry_id, head), = heads_of(a, "facts")
    a.states.delete(entry_id)
    a.write_entry("pdt", Refs::TYPE, head.merge("mode" => "linear"), tags: Refs.tags(head))
    error = assert_raises(ArgumentError) { writer.map_ref("facts").swap { |m| m.merge("b" => 2) } }
    assert_includes error.message, "linear"
  end

  def test_texts_merge_by_union_and_a_head_that_holds_a_text_is_version_two
    _clock, (a, b) = fleet(2)
    c = AgentSpaces::Testing::Network.fleet(GROUP, 1).first # a writer the others do not hear until it is told
    writer = Pdt.new(a, space: "pdt")
    reader = Pdt.new(b, space: "pdt")
    lone = Pdt.new(c, space: "pdt")
    writer.map_ref("doc").swap { { "body" => PText.empty(writer.replica).insert(0, "Hello"), "n" => 1 } }
    (first_id, first), = heads_of(a, "doc")
    assert_equal 2, first["v"], "a value that holds a text writes PRef.v 2 (rule 3)"
    c.fold_state(a.states.fetch(first_id))
    body = reader.map_ref("doc").deref["body"]
    assert_kind_of PText, body
    assert_equal "Hello", body.to_s
    lone.map_ref("doc").swap { |m| m.merge("body" => m["body"].insert(5, " world"), "n" => 3) }
    writer.map_ref("doc").swap { |m| m.merge("body" => m["body"].insert(0, "Hi "), "n" => 2) }
    (lone_id, _), = heads_of(c, "doc").select { |_, h| h["seq"] == 2 }
    [a, b].each { |peer| peer.fold_state(c.states.fetch(lone_id)) }
    events = []
    reader.map_ref("doc").on_conflict { |e| events << e }
    merged = reader.map_ref("doc").deref
    assert_equal "Hi Hello world", merged["body"].to_s, "two texts changed on both sides take their union"
    assert_equal [["n", Refs::LATER_HLC]], events.map { |e| [e.key, e.reason] }
    writer.map_ref("doc").swap { |m| m.merge("n" => 4) }
    third = heads_of(a, "doc").last[1]
    assert_equal 3, third["seq"]
    assert_equal 2, third["base"].size
    assert_equal "Hi Hello world", reader.map_ref("doc").deref["body"].to_s
  end

  # ------------------------------------------------------------------ P2-X-06, the serving side

  # The frames a peer's tree exchange sends, decoded, by recipient.
  def recording(peer)
    sent = []
    peer.define_singleton_method(:send_pipe) { |to, _capability, payload, via: nil| sent << [to, AgentSpaces::CBOR.load(payload)] }
    sent
  end

  def served_tree
    store = NodeStore.new
    old = Build::Flusher.new(store).cid_of(Build::MapNode.of((0...3000).map { |i| [cbor("k#{i}"), cbor(i)] }))
    root = Build::Flusher.new(store).cid_of(Build::MapNode.of((0...3001).map { |i| [cbor("k#{i}"), cbor(i)] }))
    [store, old, root]
  end

  def test_the_serving_side_walks_a_tree_under_the_askers_haves_and_budget
    store, old, root = served_tree
    peer = peer_at(T0)
    trees = Trees.new(peer, store)
    sent = recording(peer)
    asker = AgentSpaces::Identity.generate.peer_id
    ask = ->(msg) { trees.on_frame(asker, cbor(msg)) }
    ask.call(Tree.tree_want(1, root, nil, Tree::MAX_TREE_BUDGET))
    nodes, finish = sent.map(&:last)
    assert_equal [Tree::NODES, 1], nodes.values_at("t", "req")
    assert_equal store.reachable(root).size, nodes["nodes"].size, "the whole tree under no haves"
    assert_equal [Tree::TREE_END, 1, [], Tree::END_DONE], finish.values_at("t", "req", "frontier", "reason")
    sent.clear
    ask.call(Tree.tree_want(2, root, [old], Tree::MAX_TREE_BUDGET))
    delta = sent.first[1]["nodes"]
    assert_operator delta.size, :<, store.reachable(root).size / 4, "the haves prune what the asker holds"
    refute_includes delta, store.get(old)
    sent.clear
    ask.call(Tree.tree_want(3, root, nil, 1))
    assert_equal 1, sent.first[1]["nodes"].size, "a budget sends at least the first node"
    assert_equal Tree::END_BUDGET, sent.last[1]["reason"]
    refute_empty sent.last[1]["frontier"]
    sent.clear
    ask.call(Tree.tree_want(4, root, [Cids.of("a root this face never held".b)], Tree::MAX_TREE_BUDGET))
    assert_equal Tree::END_HAVES_NOT_HELD, sent.last[1]["reason"], "a walk that holds none of the haves sends two levels"
    sent.clear
    absent = Cids.of("absent".b)
    ask.call(Tree.tree_want(5, absent, nil, 1024))
    assert_equal [[asker, Tree.reject(absent, Tree::TREE_INDEX, Tree::REASON_NOT_HELD)]], sent
    assert_operator trees.stats[:nodes_served], :>, 0
  end

  def test_the_serving_side_seals_under_the_write_epoch_and_refuses_when_the_group_seals_without_a_key
    store, _old, root = served_tree
    asker = AgentSpaces::Identity.generate.peer_id
    keyed_peer = peer_at(T0)
    key = Random.new(5).bytes(32)
    keyed = Trees.new(keyed_peer, store, keys: { 3 => "\x01".b * 32, 4 => key })
    sent = recording(keyed_peer)
    keyed.on_frame(asker, cbor(Tree.node_want(9, [root])))
    message = sent.last[1]
    assert_equal [nil, 4], message.values_at("nodes", "epoch")
    assert_equal [store.get(root)], Tree.open_nodes([key], message["sealed"], Tree.sealing_aad(asker, 9))
    assert_equal "group-key", keyed.describe["parameters"]["sealing"]
    plain_peer = peer_at(T0)
    plain = Trees.new(plain_peer, store)
    sent = recording(plain_peer)
    sealer = AgentSpaces::Identity.generate.peer_id
    plain_peer.ads["sealer"] = { "type" => "CapabilityAdvertisement", "issuer" => sealer, "expires" => plain_peer.now_ms + 60_000,
                                 "ad" => { "capabilityType" => Tree::TYPE, "issued" => T0,
                                           "parameters" => { "trees" => "1", "sealing" => "group-key" } } }
    plain.on_frame(asker, cbor(Tree.node_want(10, [root])))
    assert_equal [[asker, Tree.reject(root, Tree::TREE_INDEX, Tree::REASON_POLICY)]], sent
  end

  # ------------------------------------------------------------------ P2-C-02, signed pins

  def store_card(peer, free: "2145336164352", blind: "false", waiting: false, price: "2")
    card = load(hex("asset_card_content_store_cbor"))
    now = peer.now_ms
    card = card.merge("id" => "aspace://#{peer.group}/asset/content-store/site/#{peer.identity.peer_id}",
                      "issuer" => peer.identity.peer_id, "group" => peer.group,
                      "issued" => AgentSpaces::Instants.iso(now - (now % 1000)), "costHints" => { "pricePerGibMonth" => price })
    access = card["access"].merge("free" => free, "blind" => blind)
    access["waiting"] = "authorizer" if waiting
    card.merge("access" => AgentSpaces::CBOR.canonical_map(access))
  end

  def test_the_store_card_vector_reads_and_the_chooser_ranks_by_price_then_room
    card = AgentSpaces::Schema.load("AssetCard", hex("asset_card_content_store_cbor"))
    assert_equal hex("asset_card_content_store_cbor"), cbor(card)
    at = AgentSpaces::Instants.parse_millis(card["issued"]) + 1
    assert_equal [card], StoreChooser.choose([card], bytes: 1_000, copies: 2, now_ms: at)
    assert_empty StoreChooser.choose([card], bytes: 2_145_336_164_353, copies: 1, now_ms: at), "no room"
    assert_empty StoreChooser.choose([card], bytes: 1, copies: 1, now_ms: at + (15 * 60 * 1000)), "expired"
    assert_empty StoreChooser.choose([card], bytes: 1, copies: 1, tier: "cold", now_ms: at)
    assert_empty StoreChooser.choose([card], bytes: 1, copies: 1, max_price: 1, now_ms: at)
    blind = card.merge("access" => card["access"].merge("blind" => "true"))
    assert_empty StoreChooser.choose([blind], bytes: 1, copies: 1, now_ms: at), "a blind store holds sealed content only"
    assert_equal [blind], StoreChooser.choose([blind], bytes: 1, copies: 1, sealed: true, now_ms: at)
    cheap = card.merge("issuer" => "zCheap", "costHints" => {})
    roomy = card.merge("issuer" => "zRoomy", "access" => card["access"].merge("free" => "2199023255552"))
    assert_equal %w[zCheap zRoomy], StoreChooser.choose([card, roomy, cheap], bytes: 1, copies: 2, now_ms: at).map { |c| c["issuer"] }
    unreadable = card.merge("access" => card["access"].merge("free" => "01"))
    assert_empty StoreChooser.choose([unreadable], bytes: 1, copies: 1, now_ms: at), "a value not in canonical decimal"
  end

  def test_a_ruby_requester_writes_a_signed_pin_naming_its_stores_and_serves_the_tree
    _clock, (a, s, w) = fleet(3)
    pdt = Pdt.new(a, space: "pdt")
    pdt.map_ref("facts").swap { |m| m.merge("a" => 1, "b" => "two") }
    root = Cids.of(hex("pdt_map_small"))
    s.publish_ad("AssetCard", store_card(s))
    w.publish_ad("AssetCard", store_card(w, waiting: true))
    pin, chosen = pdt.store_for(root, copies: 2, lease: 7_200)
    assert_equal [s.identity.peer_id], chosen.map { |c| c["issuer"] }, "a waiting store takes no pins"
    entries = s.states.values.select { |dto| dto.dig("record", "type") == SignedPin::TYPE }
    assert_equal 1, entries.size
    record = entries.first["record"]
    signed = SignedPin.decode(s.payload_of(entries.first))
    assert_nil SignedPin.violation(signed)
    assert SignedPin.consented?(signed, GROUP)
    assert_equal pin, signed["pin"]
    assert_equal [root, StorePin::KIND_TREE, 7_200, 1, a.identity.peer_id, [], { "pdt.stores" => s.identity.peer_id }],
                 signed["pin"].values_at("root", "kind", "lease", "copies", "requester", "haves", "attrs")
    assert_equal 1, signed["left"]
    assert_equal({ "root" => root, "requester" => a.identity.peer_id }, record["tags"])
    assert_equal record["lease"]["expiresAtMillis"], signed["notAfter"], "the signature lasts as long as the entry"
    assert_operator signed["notAfter"] - a.now_ms, :<=, 3_600_000, "a pin entry lives at most an hour"
    # the store fetches the tree from its requester, who serves it
    assert Trees.new(s, NodeStore.new).fetch_tree(root, prefer: [a.identity.peer_id], timeout: 2.0).wait(2.0)
    error = assert_raises(ArgumentError) { pdt.store_for(Cids.of("not held".b), copies: 1, lease: 60) }
    assert_includes error.message, "not complete"
    error = assert_raises(ArgumentError) { pdt.store_for(root, copies: 1, lease: 60, tier: "cold") }
    assert_includes error.message, "no content store fits"
  end

  # ------------------------------------------------------------------ P2-C-02, feature level 1

  def test_the_level_two_content_swarm_forms_are_no_messages_of_the_ruby_face_and_strike_nobody
    {
      "content_nodes_deltas_cbor" => "are not", "content_tree_end_sketch_cbor" => "are not",
      "content_challenge_cbor" => "tag 12", "content_tree_want_sketch_cbor" => "root is not a cid"
    }.each do |name, rule|
      assert_includes Tree.violation(load(hex(name))), rule, name
    end
    peer = peer_at(T0)
    trees = Trees.new(peer, NodeStore.new)
    sent = recording(peer)
    holder = AgentSpaces::Identity.generate.peer_id
    %w[content_nodes_deltas_cbor content_tree_end_sketch_cbor content_challenge_cbor content_tree_want_sketch_cbor].each do |name|
      trees.on_frame(holder, hex(name))
    end
    assert_equal 4, trees.stats[:tree_messages_dropped]
    assert_equal 0, trees.stats[:struck_senders]
    assert_empty sent, "a level-1 face answers no sketch and no challenge"
    # a push bundle rides a stream this face does not follow: the peer folds nothing from it
    states = peer.states.size
    peer.handle(AgentSpaces::Wire.envelope(peer.group, "RUMOR", holder, "#{ms(T0)}:0:#{holder}",
                                           AgentSpaces::Wire.rumor_body("pdt:pdt:facts", "b:1", 3, hex("pdt_push_bundle_cbor"))))
    assert_equal states, peer.states.size
    bundle = load(hex("pdt_push_bundle_cbor"))
    assert_equal [1, 3, 0, 1, [hex("pdt_map_small")]], bundle.values_at("v", "seq", "part", "parts", "nodes")
  end

  # Every PDT 2 vector golden.json holds after the first design is read by a test of this suite or of pdt2_test.rb,
  # or is a level-2 form a level-1 face never receives (P2-C-02, P2-O-02).
  READ_HERE = %w[pdt_ref_v2_cbor pdt_db_sample pdt_db_sample_answers pdt_rr_splice pdt_text_edits pdt_text_value
                 pdt_text_spill pdt_text_replica content_nodes_deltas_cbor content_challenge_cbor
                 asset_card_content_store_cbor content_tree_want_sketch_cbor content_tree_end_sketch_cbor
                 pdt_push_bundle_cbor].freeze
  # The frame a level-2 holder sends only to a level-2 asker, and the RIBLT symbols of a level-2 sketch (6.10.2).
  LEVEL_TWO_ONLY = %w[pdt_dcz_frame pdt_riblt_symbols].freeze

  def test_every_pdt2_vector_is_read_by_the_ruby_suite
    keys = GOLDEN.keys
    pdt2 = keys[(keys.index("pdt_sealed_node") + 1)..].select { |k| k.start_with?("pdt_", "content_", "asset_card_content") }
    assert_equal pdt2.sort, (Pdt2Test::PDT2_VECTORS + READ_HERE + LEVEL_TWO_ONLY).sort
    source = File.read(__FILE__)
    tests = source[0...source.index("  READ_HERE = ")] + source[source.index("  def test_every_pdt2_vector")..]
    READ_HERE.each { |name| assert_includes tests, "\"#{name}\"", "a test of this suite reads #{name}" }
  end
end
