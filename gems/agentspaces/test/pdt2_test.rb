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

# PDT 2 phase 0 (srad/agentspaces-pdt2.md 8, P2-C-02), read from Ruby: every
# PDT 2 vector of the vendored golden.json decodes through the node codec and
# its kind's typed reader and re-encodes byte for byte (P2-D-01, P2-R-01,
# P2-T-01, P2-V-01, P2-B-02), the store records read strictly from their own
# bytes (P2-S-02), and a head names its version graph node by the advisory
# attribute pdt.ancestry (6.10.3, rule 9).
class Pdt2Test < Minitest::Test
  include GoldenHelpers
  include AgentSpaces::PDT

  TX1 = 536_870_913
  TX2 = 536_870_914
  PDT2_VECTORS = %w[pdt_db_root pdt_dn_leaf pdt_dn_branch pdt_dn_tail pdt_datom_values pdt_store_pin_cbor
                    pdt_store_receipt_cbor pdt_blake3_identity pdt_bo_small pdt_bo_split pdt_rr_relaxed
                    pdt_rr_packed pdt_text_runs pdt_text_merge pdt_vg_chain pdt_ref_ancestry_cbor pdt_vg_merge
                    pdt_signed_pin_cbor pdt_signed_pin_consent_cbor pdt_manifest_tree_cbor].freeze
  SIGNED_PIN_GROUP = "zGolden"
  SIGNED_PIN_NOT_AFTER = 1_792_323_600_000

  def parts(name) = GOLDEN.fetch(name).split(",")

  def unhex(text) = [text].pack("H*")

  def cid(bytes) = Cids.of(bytes)

  def counting(from) = (from...(from + 32)).to_a.pack("C*")

  def requester = AgentSpaces::Derive.id(counting(0))

  def holder = AgentSpaces::Derive.id(counting(32))

  def datom(e, a, v, tx) = Datom.new(e, a, v, tx)

  def age1 = datom(1, ":person/age", 36, TX1)
  def name1 = datom(1, ":person/name", "Ada", TX1)
  def age2 = datom(2, ":person/age", 45, TX1)
  def name2 = datom(2, ":person/name", "Grace", TX1)

  # ------------------------------------------------------------------ every vector

  def test_the_vendored_golden_json_holds_every_pdt2_vector
    assert_equal PDT2_VECTORS.sort, PDT2_VECTORS.select { |name| GOLDEN.key?(name) }.sort
  end

  def test_every_pdt2_node_vector_decodes_by_kind_and_reencodes_byte_for_byte
    nodes = { "pdt_dn_leaf" => "dn", "pdt_dn_tail" => "dn", "pdt_datom_values" => "dn", "pdt_text_runs" => "t",
              "pdt_rr_packed" => "vr" }.map { |name, kind| [GOLDEN.fetch(name), kind] }
    nodes += parts("pdt_db_root").zip(%w[db dn dn]) + parts("pdt_dn_branch").zip(%w[dn dn dn])
    nodes += parts("pdt_rr_relaxed").zip(%w[rr rv]) + parts("pdt_vg_chain").zip(%w[vg vg])
    nodes += [[parts("pdt_bo_small")[0], "bo"], [parts("pdt_bo_split")[0], "bo"]]
    nodes += parts("pdt_text_merge").take(3).map { |text| [text, "t"] }
    assert_equal 20, nodes.size
    nodes.each do |text, kind|
      data = unhex(text)
      node = Nodes.decode(data, cid(data))
      assert_equal kind, node["k"]
      assert_equal kind, Nodes.kind_of(data)
      assert_equal data, Nodes.encode(node), "a #{kind} node re-encodes"
    end
  end

  # ------------------------------------------------------------------ P2-D-01

  def test_the_database_vectors_decode_as_the_golden_database
    root, aevt_hex, avet_hex = parts("pdt_db_root")
    db = DbRoot.decode(unhex(root))
    assert_equal unhex(root), db.encode
    assert_equal [DbRoot::BRANCHING, 2, TX2], [db.branching, db.max_eid, db.max_tx]
    assert_equal({ ":person/name" => { ":db/index" => true } }, load(db.schema.bytes))
    assert_equal cid(hex("pdt_dn_leaf")), db.eavt.cid
    assert_equal cid(unhex(aevt_hex)), db.aevt.cid
    assert_equal cid(unhex(avet_hex)), db.avet.cid
    assert_equal cid(hex("pdt_dn_tail")), db.tail.cid, "the tail travels linked from the root (10.4, phase 0)"
    assert_equal [db.aevt.cid, db.avet.cid, db.eavt.cid, db.tail.cid], Nodes.links(unhex(root))

    eavt = DnNode.decode(hex("pdt_dn_leaf"))
    aevt = DnNode.decode(unhex(aevt_hex))
    avet = DnNode.decode(unhex(avet_hex))
    assert_equal [0, "eavt", [age1, name1, age2, name2], []], [eavt.level, eavt.index, eavt.datoms, eavt.children]
    assert_equal [age1, age2, name1, name2], aevt.datoms
    assert_equal %w[Ada Grace], avet.datoms.map(&:v)
    tail = DnNode.decode(hex("pdt_dn_tail"))
    assert_equal DnNode::TAIL, tail.index
    assert_equal [datom(2, ":person/age", 45, -TX2), datom(2, ":person/age", 46, TX2)], tail.datoms
    [hex("pdt_dn_leaf"), hex("pdt_dn_tail"), unhex(aevt_hex), unhex(avet_hex)].each do |bytes|
      assert_equal bytes, DnNode.decode(bytes).encode
    end
    assert_equal hex("pdt_dn_leaf"), DnNode.new(0, "eavt", [age1, name1, age2, name2], []).encode
  end

  def test_the_branch_vector_keys_each_child_by_its_largest_datom
    branch, first, second = parts("pdt_dn_branch").map { |text| unhex(text) }
    node = DnNode.decode(branch)
    assert_equal 1, node.level
    assert_equal [cid(first), cid(second)], node.children.map(&:cid)
    assert_equal [name1, name2], node.datoms
    assert_equal [[age1, name1], [age2, name2]], [DnNode.decode(first).datoms, DnNode.decode(second).datoms]
    assert_equal branch, node.encode
    assert_equal [cid(first), cid(second)], Nodes.links(branch)
  end

  def test_the_datom_values_vector_holds_one_datom_per_value_form
    leaf = DnNode.decode(hex("pdt_datom_values"))
    assert_equal hex("pdt_datom_values"), leaf.encode
    values = leaf.datoms.to_h { |d| [d.a, d.v] }
    assert_equal Datom::Tagged.new("n", "\x40\x00\x00\x00\x00\x00\x00\x00\x00".b), values[":v/bigint"]
    assert_equal 2**70, values[":v/bigint"].inner.unpack1("H*").to_i(16)
    assert_equal true, values[":v/bool"]
    assert_equal "\x00\x01\x02".b, values[":v/bytes"]
    assert_equal Encoding::BINARY, values[":v/bytes"].encoding
    assert_equal 1.5, values[":v/float"]
    assert_equal Datom::Tagged.new("i", 1_792_320_000_000), values[":v/instant"]
    assert_equal(-7, values[":v/int"])
    assert_equal ":status/active", values[":v/keyword"]
    assert_equal 2, values[":v/ref"]
    assert_equal Nodes::Link.new(Cids.of("\x00".b * 5000, Cids::RAW)), values[":v/spill"]
    assert_equal "Ada ✓", values[":v/text"]
    assert_equal Encoding::UTF_8, values[":v/text"].encoding
    assert_equal Datom::Tagged.new("u", unhex("0123456789abcdeffedcba9876543210")), values[":v/uuid"]
    assert_equal(-TX2, leaf.datoms.last.tx, "a retraction")
    assert_equal [values[":v/spill"].cid], Nodes.links(hex("pdt_datom_values"))
    assert_equal hex("pdt_datom_values"), DnNode.new(0, "eavt", leaf.datoms, []).encode
  end

  # A one-datom eavt leaf whose datom item is the given hex.
  def leaf_with(datom_hex) = unhex("a4616581#{datom_hex}616b62646e616c0061786465617674")

  def test_a_datom_outside_the_grammar_is_refused_by_name
    good = "8401" + "623a61" + "%s" + "01"
    assert_equal [datom(1, ":a", 5, 1)], DnNode.decode(leaf_with(format(good, "05"))).datoms
    {
      "f6" => "null", "fa3fc00000" => "float32", "f93e00" => "half float", "fb7ff8000000000000" => "not finite",
      "a0" => "major type 5", "8261786100" => "unknown value tag", "8261754100" => "16 bytes",
      "82616e420001" => "two's complement", "826169f5" => "integer", "f7" => "simple value"
    }.each do |item, rule|
      error = assert_raises(NodeFormatError, item) { DnNode.decode(leaf_with(format(good, item))) }
      assert_includes error.message, rule, item
    end
    error = assert_raises(NodeFormatError) { DnNode.decode(leaf_with("8401623a610500")) }
    assert_includes error.message, "tx"
    error = assert_raises(NodeFormatError) { DnNode.decode(leaf_with("8301623a6105")) }
    assert_includes error.message, "four items"
    # an integer past a Java long is refused on both sides of zero, as Java's reader refuses it
    error = assert_raises(NodeFormatError) { DnNode.decode(leaf_with("841b8000000000000000623a610501")) }
    assert_includes error.message, "2^63 - 1"
    error = assert_raises(NodeFormatError) { DnNode.decode(leaf_with("843b8000000000000000623a610501")) }
    assert_includes error.message, "2^63 - 1"
    assert_equal(-(2**63), DnNode.decode(leaf_with("843b7fffffffffffffff623a610501")).datoms[0].e)
    negative = DnNode.new(0, "eavt", [datom(-5, ":a", -(2**63), -1)], [])
    assert_equal leaf_with("8424623a613b7fffffffffffffff20"), negative.encode, "a negative entity is major type 1"
    assert_equal negative, DnNode.decode(negative.encode)
    [[1, ":a", 2**63, 1], [1, ":a", Float::INFINITY, 1], [1, ":a", nil, 1], [1, ":a", 5, 0], [1, "".b, 5, 1]].each do |args|
      assert_raises(ArgumentError, args.inspect) { Datom.new(*args) }
    end
    assert_raises(ArgumentError) { Datom::Tagged.new("n", "\x00\x01".b) }
  end

  def test_a_dn_node_whose_shape_breaks_the_rules_is_refused
    leaf = [age1]
    link = Nodes::Link.new(cid(hex("pdt_dn_leaf")))
    assert_raises(ArgumentError) { DnNode.new(0, "vaet", leaf, []) }
    assert_raises(ArgumentError) { DnNode.new(1, "tail", leaf, [link]) }
    assert_raises(ArgumentError) { DnNode.new(0, "tail", [], []) }
    assert_raises(ArgumentError) { DnNode.new(0, "eavt", leaf, [link]) }
    assert_raises(ArgumentError) { DnNode.new(1, "eavt", leaf, []) }
    error = assert_raises(NodeFormatError) { DnNode.decode(unhex(parts("pdt_vg_chain")[1])) }
    assert_includes error.message, "kind 'vg'"
  end

  def test_a_db_root_that_breaks_its_rules_is_refused
    db = DbRoot.decode(unhex(parts("pdt_db_root")[0]))
    list_schema = Nodes::Embedded.new(cbor([1]))
    assert_raises(ArgumentError) { DbRoot.new(list_schema, 2, TX2, 128, db.eavt, db.aevt, db.avet, nil) }
    assert_raises(ArgumentError) { DbRoot.new(db.schema, 2, TX2, 1, db.eavt, db.aevt, db.avet, nil) }
    assert_raises(ArgumentError) { DbRoot.new(db.schema, -1, TX2, 128, db.eavt, db.aevt, db.avet, nil) }
    untailed = DbRoot.new(db.schema, 2, TX2, 128, db.eavt, db.aevt, db.avet, nil)
    assert_nil DbRoot.decode(untailed.encode).tail
    node = Nodes.decode(untailed.encode)
    error = assert_raises(NodeFormatError) { DbRoot.decode(Nodes.encode(node.merge("v" => 2))) }
    assert_includes error.message, "version 2"
    error = assert_raises(NodeFormatError) { Nodes.encode(node.merge("i" => node["i"].except("avet"))) }
    assert_includes error.message, "aevt, avet and eavt"
    error = assert_raises(NodeFormatError) { DbRoot.decode(Nodes.encode(node.except("t"))) }
    assert_includes error.message, "lacks 't'"
    # the index map's entries travel in the DAG-CBOR order aevt, avet, eavt; another order is refused
    bytes = untailed.encode
    at = bytes.index("\xA3\x64aevt".b) + 1
    swapped = bytes.byteslice(0, at) + bytes.byteslice(at + 46, 46) + bytes.byteslice(at, 46) + bytes.byteslice(at + 92..)
    error = assert_raises(NodeFormatError) { Nodes.decode(swapped) }
    assert_includes error.message, "in that order"
  end

  # ------------------------------------------------------------------ P2-S-02

  def test_the_store_record_vectors_read_strictly_and_reencode
    pin = StorePin.decode(hex("pdt_store_pin_cbor"))
    assert_nil StorePin.violation(pin)
    assert_equal cid(hex("pdt_map_deep")), pin["root"]
    assert_equal [cid(hex("pdt_map_small"))], pin["haves"]
    assert_equal requester, pin["requester"]
    assert_equal({ "root" => pin["root"], "requester" => requester }, StorePin.tags(pin))
    built = StorePin.build(root: pin["root"], kind: StorePin::KIND_TREE, lease: 86_400, copies: 2, requester: requester,
                           haves: pin["haves"], attrs: { "purpose" => "golden" })
    assert_equal hex("pdt_store_pin_cbor"), cbor(built)
    assert_equal "ai.badmonkey.agentspaces.agent.content.StorePin#v1", StorePin::TYPE
    unordered = StorePin.build(root: pin["root"], kind: StorePin::KIND_ARTIFACT, lease: 1, copies: 1, requester: requester,
                               attrs: { "zz" => "1", "a" => "2" })
    assert_equal %w[a zz], StorePin.decode(cbor(unordered))["attrs"].keys, "attrs travel in the RFC 8949 order"
    assert_equal [], unordered["haves"]

    receipt = StoreReceipt.decode(hex("pdt_store_receipt_cbor"))
    assert_nil StoreReceipt.violation(receipt)
    assert_equal [pin["root"], holder, 12_345, 1_792_406_400_000, true],
                 receipt.values_at("root", "holder", "bytes", "until", "blind")
    assert_equal({ "root" => pin["root"], "holder" => holder }, StoreReceipt.tags(receipt))
    built = StoreReceipt.build(root: pin["root"], holder: holder, bytes: 12_345, until_ms: 1_792_406_400_000, blind: true)
    assert_equal hex("pdt_store_receipt_cbor"), cbor(built)
    assert_equal "ai.badmonkey.agentspaces.agent.content.StoreReceipt#v1", StoreReceipt::TYPE
  end

  # ------------------------------------------------------------------ PDT 2 follow-ups, 2026-11-09, F1 and F3

  def test_the_signed_pin_vector_rebuilds_from_its_requesters_seed_and_carries_its_consent
    alice = AgentSpaces::Identity.from_seed(counting(64))
    pin = StorePin.build(root: cid(hex("pdt_map_deep")), kind: StorePin::KIND_TREE, lease: 86_400, copies: 2,
                         requester: alice.peer_id, haves: [cid(hex("pdt_map_small"))], attrs: { "pdt.stores" => holder })
    assert_equal hex("pdt_signed_pin_consent_cbor"), SignedPin.consent_bytes(pin, SIGNED_PIN_GROUP, SIGNED_PIN_NOT_AFTER)
    signed = SignedPin.sign(pin, SIGNED_PIN_GROUP, SIGNED_PIN_NOT_AFTER, alice)
    assert_equal hex("pdt_signed_pin_cbor"), cbor(signed)
    read = SignedPin.decode(hex("pdt_signed_pin_cbor"))
    assert_equal signed, read
    assert_nil SignedPin.violation(read)
    assert_equal hex("pdt_signed_pin_cbor"), cbor(read)
    assert_equal 2, read["left"]
    assert SignedPin.consented?(read, SIGNED_PIN_GROUP)
    refute SignedPin.consented?(read, "zOther"), "a consent in one group is none in another"
    assert_equal({ "root" => pin["root"], "requester" => alice.peer_id }, SignedPin.tags(read))
    assert_equal "ai.badmonkey.agentspaces.agent.content.SignedPin#v1", SignedPin::TYPE
  end

  def test_a_pin_its_requester_did_not_sign_is_no_consent_and_a_signed_pin_reads_strictly
    alice = AgentSpaces::Identity.generate
    mallory = AgentSpaces::Identity.generate
    terms = lambda do |who, copies = 1|
      StorePin.build(root: cid(hex("pdt_map_deep")), kind: StorePin::KIND_TREE, lease: 86_400, copies: copies,
                     requester: who.peer_id, attrs: { "pdt.stores" => "zA" })
    end
    forged = SignedPin.sign(terms.call(mallory), "zStores", SIGNED_PIN_NOT_AFTER, mallory)
    renamed = forged.merge("pin" => terms.call(alice))
    assert_nil SignedPin.violation(renamed)
    refute SignedPin.consented?(renamed, "zStores"), "the key is not the requester's"
    refute SignedPin.consented?(renamed.merge("key" => alice.public_raw), "zStores")
    # mallory's own key over the very consent bytes of terms naming alice verifies, so the key binding refuses it
    consent = SignedPin.consent_bytes(terms.call(alice), "zStores", SIGNED_PIN_NOT_AFTER)
    own_key = renamed.merge("sig" => mallory.sign(consent))
    assert AgentSpaces::Identity.verify(mallory.public_raw, consent, own_key["sig"])
    refute SignedPin.consented?(own_key, "zStores"), "a forger's own key over terms naming alice"
    honest = SignedPin.sign(terms.call(alice, 2), "zStores", SIGNED_PIN_NOT_AFTER, alice)
    refute SignedPin.consented?(honest.merge("pin" => terms.call(alice, 3)), "zStores"), "changed terms"
    refute SignedPin.consented?(honest.merge("notAfter" => SIGNED_PIN_NOT_AFTER + 1), "zStores"), "a later deadline"
    assert SignedPin.consented?(honest.merge("left" => 1), "zStores"), "a store counts the copies down"
    assert_raises(ArgumentError) { SignedPin.sign(terms.call(alice), "zStores", SIGNED_PIN_NOT_AFTER, mallory) }
    [honest.merge("holder" => "zForger"), honest.except("left"), honest.to_a.reverse.to_h, honest.merge("left" => true),
     honest.merge("left" => 1 << 31), honest.merge("key" => alice.public_raw.unpack1("H*")),
     honest.merge("pin" => honest["pin"].merge("extra" => 1)), honest.merge("pin" => nil)].each do |broken|
      assert_nil SignedPin.decode(cbor(broken)), broken.inspect
    end
    {
      { "v" => 2 } => "unsupported SignedPin version 2", { "left" => 3 } => "left 3 is outside 1 to 2 copies",
      { "left" => 0 } => "left 0 is outside 1 to 2 copies", { "notAfter" => -1 } => "negative notAfter",
      { "key" => "\0".b * 31 } => "key is not 32 bytes", { "sig" => "\0".b * 63 } => "sig is not 64 bytes",
      { "pin" => honest["pin"].merge("root" => "root") } => "root is not a CID"
    }.each { |change, message| assert_equal message, SignedPin.violation(honest.merge(change)) }
  end

  # Ruby holds no content-swarm manifest reader (it joins the content swarm by the tree exchange alone), so the
  # tree manifest of F3 is read here as the vector it is: no piece table, a dag-cbor root, its bytes kept.
  def test_the_tree_manifest_vector_names_the_small_blob_without_a_piece_table
    manifest = load(hex("pdt_manifest_tree_cbor"))
    assert_equal "tree", manifest["layout"]
    assert_nil manifest["table"]
    assert_nil manifest["tableRef"]
    assert_equal parts("pdt_blob_small").first, manifest["root"]
    assert_equal Cids::DAG_CBOR, Cids.codec_of(manifest["root"])
    assert_equal [102_400, 65_536, 2], manifest.values_at("size", "pieceSize", "pieces")
    assert_equal hex("pdt_manifest_tree_cbor"), cbor(manifest)
  end

  def test_a_store_record_with_a_field_unknown_out_of_order_null_or_of_another_type_does_not_decode
    pin = StorePin.decode(hex("pdt_store_pin_cbor"))
    receipt = StoreReceipt.decode(hex("pdt_store_receipt_cbor"))
    [pin.merge("extra" => "x"), pin.except("haves"), pin.except("attrs").merge("attrs" => nil),
     pin.merge("haves" => nil), pin.merge("lease" => "86400"), pin.merge("copies" => 1 << 31),
     pin.merge("requester" => ""), pin.merge("attrs" => { "zz" => "1", "a" => "2" }), pin.merge("attrs" => { "a" => 1 }),
     pin.to_a.reverse.to_h].each do |broken|
      assert_nil StorePin.decode(cbor(broken)), broken.inspect
    end
    assert_equal pin.except("attrs"), StorePin.decode(cbor(pin.except("attrs")))
    [receipt.merge("extra" => 1), receipt.merge("blind" => 1), receipt.merge("bytes" => 1.0), receipt.except("until"),
     receipt.merge("root" => nil)].each do |broken|
      assert_nil StoreReceipt.decode(cbor(broken)), broken.inspect
    end
    assert_nil StorePin.decode("\xff".b)
  end

  def test_a_store_record_outside_its_bounds_is_named
    pin = StorePin.decode(hex("pdt_store_pin_cbor"))
    {
      { "v" => 2 } => "unsupported StorePin version 2", { "root" => "x" } => "root is not a CID",
      { "kind" => "map" } => "unknown kind map", { "lease" => 0 } => "lease of 0 seconds", { "copies" => 0 } => "copies below 1",
      { "haves" => [pin["root"]] * 9 } => "more than 8 haves", { "haves" => ["x"] } => "have is not a CID",
      { "attrs" => (1..33).to_h { |i| [format("k%02d", i), "v"] } } => "more than 32 attrs",
      { "attrs" => { "a" => "x" * 4096 } } => "attrs larger than 4096 bytes"
    }.each { |change, rule| assert_equal rule, StorePin.violation(pin.merge(change)) }
    assert_nil StorePin.violation(pin.merge("kind" => StorePin::KIND_ARTIFACT))
    receipt = StoreReceipt.decode(hex("pdt_store_receipt_cbor"))
    {
      { "v" => 0 } => "unsupported StoreReceipt version 0", { "root" => "x" } => "root is not a CID",
      { "bytes" => -1 } => "negative bytes", { "until" => -1 } => "negative until"
    }.each { |change, rule| assert_equal rule, StoreReceipt.violation(receipt.merge(change)) }
  end

  # ------------------------------------------------------------------ P2-B-02

  def root_hash(node) = Blake3.parent(node.parents.byteslice(0, 32), node.parents.byteslice(32, 32), root: true)

  def test_the_outboard_vectors_reach_their_identities
    identity = GOLDEN.fetch("pdt_blake3_identity")
    assert identity.start_with?("bafkr4i")
    assert_equal 32, Blake3.identity_digest(identity).bytesize

    small, small_identity = parts("pdt_bo_small")
    node = BoNode.decode(unhex(small))
    assert_equal [100 * 1024, 6 * 64, []], [node.size, node.parents.bytesize, node.children]
    assert_equal Blake3.identity_digest(small_identity), root_hash(node)
    assert_equal unhex(small), node.encode

    split, split_identity, *children = parts("pdt_bo_split")
    node = BoNode.decode(unhex(split))
    assert_equal (2**23) + 5000, node.size, "a full leaf of 8 MiB and one more group (PDT 2 phase 4 measures)"
    assert_equal children, node.children.map(&:cid)
    assert_equal BoNode::PARENT_BYTES, node.parents.bytesize, "two children, one parent above the cut"
    assert_equal Blake3.identity_digest(split_identity), root_hash(node)
    assert_equal unhex(split), node.encode
    assert_equal children, Nodes.links(unhex(split))
    # a pair that is no root hashes elsewhere
    refute_equal Blake3.identity_digest(split_identity), Blake3.parent(node.parents.byteslice(0, 32),
                                                                       node.parents.byteslice(32, 32), root: false)
  end

  def test_an_identity_outside_the_blake3_raw_form_is_refused_by_name
    digest = Blake3.identity_digest(GOLDEN.fetch("pdt_blake3_identity"))
    { [0x01, 0x55, 0x12, 0x20] => "multihash", [0x01, 0x71, 0x1E, 0x20] => "codec" }.each do |prefix, rule|
      text = "b" + Cids.base32_lower(prefix.pack("C*") + digest)
      error = assert_raises(ArgumentError) { Blake3.identity_digest(text) }
      assert_includes error.message, rule
    end
    canonical = GOLDEN.fetch("pdt_blake3_identity")
    last = Cids::ALPHABET[Cids::INDEX[canonical[-1]] | 1]
    assert_raises(ArgumentError, "unused trailing bits") { Blake3.identity_digest(canonical[0..-2] + last) }
    assert_raises(ArgumentError) { Blake3.identity_digest(canonical[0..-2]) }
    assert_raises(ArgumentError) { Blake3.identity_digest(cid(hex("pdt_map_small"))) }
  end

  def test_a_bo_node_whose_parents_or_children_the_size_does_not_imply_is_refused
    small = BoNode.decode(unhex(parts("pdt_bo_small")[0]))
    split = BoNode.decode(unhex(parts("pdt_bo_split")[0]))
    assert_raises(ArgumentError) { BoNode.new(small.size + (16 * 1024), small.parents, []) }
    assert_raises(ArgumentError) { BoNode.new(small.size, small.parents.byteslice(0, 64), []) }
    assert_raises(ArgumentError) { BoNode.new(split.size, split.parents, split.children.take(1)) }
    assert_raises(ArgumentError) { BoNode.new(-1, "".b, []) }
    assert_equal "".b, BoNode.new(0, "".b, []).parents, "an empty blob is one group, no parent"
    assert_equal [], BoNode.child_sizes(2**23)
    assert_equal [2**23, 5000], BoNode.child_sizes((2**23) + 5000)
    # past 2^13 groups a block is 2^13 groups, so 2^13 + 1 groups cut into one full block and one group
    assert_equal [2**27, 16 * 1024], BoNode.child_sizes((2**27) + (16 * 1024))
    assert_equal [2**23] * 3, BoNode.child_sizes(3 * (2**23))
    assert_equal [2**23] * 16, BoNode.child_sizes(2**27), "2^13 groups still cut into blocks of 2^9"
    node = Nodes.decode(small.encode)
    error = assert_raises(NodeFormatError) { BoNode.decode(Nodes.encode(node.merge("g" => 5))) }
    assert_includes error.message, "group size"
  end

  # ------------------------------------------------------------------ P2-R-01

  def v_leaf(from, to) = Nodes.encode({ "k" => "v", "e" => (from...to).map { |i| cbor(i) } })

  def test_the_relaxed_vector_holds_the_elements_of_the_packed_one
    root_hex, interior_hex = parts("pdt_rr_relaxed")
    root = RrRoot.decode(unhex(root_hex))
    interior = RvNode.decode(unhex(interior_hex))
    assert_equal cid(unhex(interior_hex)), root.trie.cid
    assert_equal [32, 40, 72, 96], interior.sizes
    elements = []
    interior.children.each_with_index do |child, i|
      from = i.zero? ? 0 : interior.sizes[i - 1]
      leaf = v_leaf(from, interior.sizes[i])
      assert_equal cid(leaf), child.cid
      elements.concat(Nodes.decode(leaf)["e"])
    end
    elements.concat(root.tail)
    assert_equal root.count, elements.size
    assert_equal (0...100).to_a, elements.map { |e| load(e.bytes) }
    packed = Nodes.decode(hex("pdt_rr_packed"))
    assert_equal ["vr", 100], packed.values_at("k", "n"), "the packed form is the vr root (3.7)"
    assert_equal unhex(root_hex), root.encode
    assert_equal unhex(interior_hex), interior.encode
    assert_equal unhex(interior_hex), RvNode.new(interior.children, interior.sizes).encode
  end

  def test_an_rrb_node_that_breaks_its_shape_is_refused
    root = RrRoot.decode(unhex(parts("pdt_rr_relaxed")[0]))
    interior = RvNode.decode(unhex(parts("pdt_rr_relaxed")[1]))
    assert_raises(ArgumentError) { RrRoot.new(100, 4, root.trie, root.tail) }
    assert_raises(ArgumentError) { RrRoot.new(100, 5, root.trie, root.tail * 9) }
    assert_raises(ArgumentError) { RrRoot.new(5, 5, nil, root.tail) }
    assert_raises(ArgumentError) { RrRoot.new(4, 5, root.trie, root.tail) }
    assert_equal 4, RrRoot.new(4, 5, nil, root.tail).count
    assert_raises(ArgumentError) { RvNode.new([], nil) }
    assert_raises(ArgumentError) { RvNode.new(interior.children * 9, nil) }
    assert_raises(ArgumentError) { RvNode.new(interior.children, [32, 40, 40, 96]) }
    assert_raises(ArgumentError) { RvNode.new(interior.children, [32, 40, 72]) }
    dense = RvNode.new(interior.children, nil)
    assert_nil RvNode.decode(dense.encode).sizes
    refute Nodes.decode(dense.encode).key?("z")
  end

  # ------------------------------------------------------------------ P2-T-01

  def test_the_text_vectors_read_and_merge_in_fugue_order
    runs = TextLeaf.decode(hex("pdt_text_runs"))
    assert_equal "Ab\u{1F600}cé!", runs.text
    assert_equal hex("pdt_text_runs"), runs.encode
    assert_equal [TextRun.new("alice", 0, nil, "R", 4, false, "Ab\u{1F600}c"),
                  TextRun.new("alice", 4, CharId.new("alice", 1), "L", 2, true, ""),
                  TextRun.new("bob", 0, CharId.new("alice", 3), "R", 2, false, "é!")], runs.runs
    alice, bob, merged, text = parts("pdt_text_merge")
    alice = TextLeaf.decode(unhex(alice))
    bob = TextLeaf.decode(unhex(bob))
    merged = TextLeaf.decode(unhex(merged))
    assert_equal merged, alice.union(bob)
    assert_equal merged, bob.union(alice)
    assert_equal "bXYc", text
    assert_equal text, merged.text
    assert_equal "abc", alice.text
    assert_equal "XYc", bob.text
  end

  def test_text_runs_order_replicas_by_their_utf8_bytes
    # U+FF5E sorts below U+1F600 by UTF-8 bytes and above it by UTF-16 units
    low = "\u{FF5E}"
    high = "\u{1F600}"
    leaf = TextLeaf.of([TextRun.new(high, 0, nil, "R", 1, false, "a"), TextRun.new(low, 0, nil, "R", 1, false, "b")])
    assert_equal [low, high], leaf.runs.map(&:replica)
    assert_equal "ba", leaf.text
  end

  def test_text_runs_out_of_canonical_form_or_shape_are_refused
    whole = TextRun.new("alice", 0, nil, "R", 2, false, "ab")
    split = [TextRun.new("alice", 0, nil, "R", 1, false, "a"), TextRun.new("alice", 1, CharId.new("alice", 0), "R", 1, false, "b")]
    assert_equal [whole], TextLeaf.of(split).runs
    error = assert_raises(ArgumentError) { TextLeaf.new(split) }
    assert_includes error.message, "canonical"
    bob = TextRun.new("bob", 0, CharId.new("alice", 0), "R", 1, false, "x")
    assert_raises(ArgumentError) { TextLeaf.new([bob, whole]) }
    assert_raises(ArgumentError) { TextLeaf.new([bob]) }
    assert_raises(ArgumentError) { TextLeaf.new([TextRun.new("a", 0, CharId.new("a", 1), "R", 1, false, "x"),
                                                 TextRun.new("a", 1, CharId.new("a", 0), "L", 1, false, "y")]) }
    assert_raises(ArgumentError) { TextRun.new("", 0, nil, "R", 1, false, "a") }
    assert_raises(ArgumentError) { TextRun.new("a", 0, nil, "L", 1, false, "a") }
    assert_raises(ArgumentError) { TextRun.new("a", 0, nil, "X", 1, false, "a") }
    assert_raises(ArgumentError) { TextRun.new("a", 0, nil, "R", 0, false, "") }
    assert_raises(ArgumentError) { TextRun.new("a", 0, nil, "R", 1, true, "a") }
    assert_raises(ArgumentError) { TextRun.new("a", 0, nil, "R", 2, false, "a") }
    assert_raises(ArgumentError) { TextRun.new("a", -1, nil, "R", 1, false, "a") }
    assert_raises(ArgumentError) { TextRun.new("a", (2**63) - 1, nil, "R", 1, false, "a") }
    assert_raises(ArgumentError) { TextLeaf.new([whole]).union(TextLeaf.new([TextRun.new("alice", 0, nil, "R", 2, false, "ac")])) }
    deleted = TextLeaf.new([whole]).union(TextLeaf.new([TextRun.new("alice", 0, nil, "R", 2, true, "")]))
    assert_equal "", deleted.text
    node = Nodes.decode(hex("pdt_text_runs"))
    error = assert_raises(NodeFormatError) { TextLeaf.decode(Nodes.encode(node.merge("v" => 2))) }
    assert_includes error.message, "version 2"
  end

  # PDT 2 phase 0 (P2-T-01, gate finding G1): a deleted run costs no text
  # bytes, so without a bound a 29-byte node naming one deleted run of 2^40
  # characters would expand forever in every port; a leaf holds at most
  # MAX_CHARS characters, live and deleted, checked before expansion, as Java does.
  def test_a_text_leaf_holds_at_most_the_node_byte_bound_of_characters
    assert_equal Nodes::MAX_NODE_BYTES, TextLeaf::MAX_CHARS
    full = TextLeaf.new([TextRun.new("alice", 0, nil, "R", TextLeaf::MAX_CHARS, true, "")])
    assert_equal "", full.text
    over = assert_raises(ArgumentError) { TextLeaf.new([TextRun.new("alice", 0, nil, "R", TextLeaf::MAX_CHARS + 1, true, "")]) }
    assert_includes over.message, "at most 1048576 characters"
    over = assert_raises(ArgumentError) do
      TextLeaf.of([TextRun.new("alice", 0, nil, "R", TextLeaf::MAX_CHARS, true, ""), TextRun.new("bob", 0, nil, "R", 1, false, "b")])
    end
    assert_includes over.message, "at most 1048576 characters"
    over = assert_raises(ArgumentError) { full.union(TextLeaf.new([TextRun.new("bob", 0, nil, "R", 1, false, "b")])) }
    assert_includes over.message, "at most 1048576 characters"
    hostile = Nodes.encode({ "k" => "t", "r" => [TextRun.new("a", 0, nil, "R", 2**40, true, "")], "v" => 1 })
    assert_equal 29, hostile.bytesize
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    over = assert_raises(NodeFormatError) { TextLeaf.decode(hostile) }
    assert_includes over.message, "at most 1048576 characters"
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 1
  end

  # PDT 2 phase 0 (P2-T-01): a leaf orders and writes replicas by their UTF-8
  # bytes whatever encoding the caller's strings carry, so it writes the
  # bytes Java writes (this pair from Java's TextLeaf) and merges with the
  # leaf it decodes.
  def test_text_runs_hold_utf8_whatever_encoding_the_caller_gives
    utf16 = ->(text) { text.encode(Encoding::UTF_16LE) }
    leaf = TextLeaf.of([TextRun.new(utf16["a"], 0, nil, "R", 1, false, utf16["x"]),
                        TextRun.new(utf16["\u0100"], 0, nil, "R", 1, false, "y")])
    java = unhex("a3616b617461728287616100f6615201f461788762c48000f6615201f46179617601")
    assert_equal java, leaf.encode
    assert_equal leaf, TextLeaf.decode(java)
    latin1 = TextLeaf.of([TextRun.new("\u00e9".encode(Encoding::ISO_8859_1), 0, nil, "R", 1, false, "x")])
    utf8 = TextLeaf.of([TextRun.new("\u00e9", 0, nil, "R", 1, false, "x")])
    assert_equal utf8, latin1.union(utf8)
    assert_equal CharId.new("\u00e9", 0), CharId.new("\u00e9".encode(Encoding::ISO_8859_1), 0)
    assert_equal datom(1, ":a", "v", 1), datom(1, utf16[":a"], utf16["v"], 1), "a datom's text reads as the decoded datom's"
    assert_equal DnNode.new(0, "eavt", [age1], []), DnNode.new(0, utf16["eavt"], [age1], [])
    deep = VgNode.decode(unhex(parts("pdt_vg_chain")[0]))
    assert_equal deep, VgNode.new(utf16[deep.root], deep.bases.map(&utf16), utf16[deep.issuer], utf16[deep.issued], deep.previous)
    # parents are bytes: a String in another encoding keeps its bytes
    outboard = BoNode.new(16_385, utf16["x" * 32], [])
    assert_equal ("x\0".b * 32), outboard.parents
    assert_equal outboard, BoNode.decode(outboard.encode)
  end

  # PDT 2 phase 0 (P2-T-01; 3.9): left children, the character, then right
  # children, each side's siblings in id order; the text and bytes are Java's.
  def test_same_side_siblings_read_in_id_order
    root = CharId.new("alice", 0)
    leaf = TextLeaf.of([TextRun.new("carol", 0, root, "R", 1, false, "2"), TextRun.new("carol", 1, root, "L", 1, false, "4"),
                        TextRun.new("alice", 0, nil, "R", 1, false, "x"), TextRun.new("bob", 0, root, "R", 1, false, "1"),
                        TextRun.new("bob", 1, root, "L", 1, false, "3")])
    assert_equal "34x12", leaf.text
    assert_equal unhex("a3616b61746172858765616c69636500f6615201f461788763626f62008265616c69636500615201f46131" \
                       "8763626f62018265616c69636500614c01f4613387656361726f6c008265616c69636500615201f46132" \
                       "87656361726f6c018265616c69636500614c01f46134617601"), leaf.encode
  end

  def test_a_run_whose_deleted_flag_is_no_boolean_or_whose_parent_is_absent_is_refused
    good = hex("pdt_text_runs")
    # the first run's deleted flag, false (0xf4), sits after "alice", 0, null, "R", 4
    flag = good.index(["8765616c69636500f6615204f4"].pack("H*")) + 12
    %w[f6 f7 00].each do |item|
      broken = good.byteslice(0, flag) + [item].pack("H*") + good.byteslice(flag + 1..)
      error = assert_raises(NodeFormatError, item) { TextLeaf.decode(broken) }
      assert_includes error.message, "boolean", item
    end
    error = assert_raises(ArgumentError) { TextLeaf.new([TextRun.new("a", 0, CharId.new("z", 0), "R", 1, false, "x")]) }
    assert_includes error.message, "not in the leaf"
  end

  # ------------------------------------------------------------------ P2-V-01

  def test_the_version_graph_vectors_chain_and_the_head_names_its_node
    deep_hex, small_hex = parts("pdt_vg_chain")
    deep = VgNode.decode(unhex(deep_hex))
    small = VgNode.decode(unhex(small_hex))
    assert_equal cid(hex("pdt_map_deep")), deep.root
    assert_equal [cid(hex("pdt_map_small"))], deep.bases
    assert_equal [cid(unhex(small_hex))], deep.previous.map(&:cid)
    assert_equal ["#{requester}/writer", "1792320000001:0:golden"], [deep.issuer, deep.issued]
    assert_equal [cid(hex("pdt_map_small")), [], []], [small.root, small.bases, small.previous]
    assert_equal [cid(unhex(small_hex))], Nodes.links(unhex(deep_hex)), "a vg node links no root"
    assert_equal unhex(deep_hex), deep.encode

    head = Refs.decode(hex("pdt_ref_ancestry_cbor"))
    assert_equal 1, head["v"], "ancestry needs no new record version (rule 9)"
    assert_nil Refs.violation(head)
    assert_equal hex("pdt_ref_ancestry_cbor"), cbor(head)
    assert_equal cid(unhex(deep_hex)), Ancestry.cid(head)
    assert_equal deep, Ancestry.read(head, unhex(deep_hex))
  end

  def test_an_ancestry_that_names_no_usable_vg_node_reads_as_none
    deep_hex, small_hex = parts("pdt_vg_chain")
    head = Refs.decode(hex("pdt_ref_ancestry_cbor"))
    assert_nil Ancestry.read(head, unhex(small_hex)), "bytes of another node"
    other_root = head.merge("root" => cid(hex("pdt_map_small")))
    small_head = other_root.merge("attrs" => { Ancestry::ATTR => cid(unhex(small_hex)) })
    assert_nil Ancestry.read(head.merge("root" => cid(hex("pdt_map_empty"))), unhex(deep_hex)), "a vg node of another root"
    deep = VgNode.decode(unhex(deep_hex))
    restamped = VgNode.new(deep.root, deep.bases, deep.issuer, "1792320000002:0:golden", deep.previous).encode
    assert_nil Ancestry.read(head, restamped), "a vg node of the head's root that does not hash to the named CID"
    assert_equal VgNode.decode(unhex(small_hex)), Ancestry.read(small_head, unhex(small_hex))
    leaf = hex("pdt_dn_leaf")
    assert_nil Ancestry.read(head.merge("attrs" => { Ancestry::ATTR => cid(leaf) }), leaf), "no vg node"
    [nil, {}, { Ancestry::ATTR => "x" }, { Ancestry::ATTR => Cids.of(unhex(deep_hex), Cids::RAW) }].each do |attrs|
      assert_nil Ancestry.cid(head.merge("attrs" => attrs)), attrs.inspect
    end
  end

  # PDT 2 phase 1 (P2-V-01): a merge version's vg node names both bases and
  # links the node of each base in the order of its bases, so a walk of the
  # chain keeps the lineage of both parents.
  def test_the_merge_version_links_each_base_node_in_the_order_of_its_bases
    deep_hex, small_hex = parts("pdt_vg_chain")
    bytes = hex("pdt_vg_merge")
    merge = VgNode.decode(bytes, cid(bytes))
    assert_equal cid(hex("pdt_map_empty")), merge.root
    assert_equal [cid(hex("pdt_map_deep")), cid(hex("pdt_map_small"))], merge.bases
    assert_equal [cid(unhex(deep_hex)), cid(unhex(small_hex))], merge.previous.map(&:cid)
    assert_equal ["#{requester}/writer", "1792320000002:0:golden"], [merge.issuer, merge.issued]
    assert_equal bytes, merge.encode
    assert_equal bytes, Nodes.encode(Nodes.decode(bytes))
  end

  # PDT 2 phase 1 (P2-V-02): a node a chain link names may describe any root,
  # and a node a head names only the head's own; both hash to the CID asked for.
  def test_a_chain_link_reads_any_root_and_a_head_only_its_own
    deep_hex, small_hex = parts("pdt_vg_chain")
    small = unhex(small_hex)
    assert_equal VgNode.decode(small), Ancestry.node(cid(small), nil, small)
    assert_equal VgNode.decode(small), Ancestry.node(cid(small), cid(hex("pdt_map_small")), small)
    assert_nil Ancestry.node(cid(small), cid(hex("pdt_map_deep")), small), "a node of another root"
    assert_nil Ancestry.node(cid(unhex(deep_hex)), nil, small), "bytes of another node"
    leaf = hex("pdt_dn_leaf")
    assert_nil Ancestry.node(cid(leaf), nil, leaf), "no vg node"
  end

  def test_a_vg_node_that_breaks_its_rules_is_refused
    deep = VgNode.decode(unhex(parts("pdt_vg_chain")[0]))
    raw = Nodes::Link.new(Cids.of("x".b, Cids::RAW))
    assert_raises(ArgumentError) { VgNode.new(deep.root, [deep.root] * 9, deep.issuer, deep.issued, []) }
    assert_raises(ArgumentError) { VgNode.new(deep.root, [], deep.issuer, deep.issued, deep.previous) }
    assert_raises(ArgumentError) { VgNode.new(deep.root, deep.bases, deep.issuer, deep.issued, [raw]) }
    assert_raises(ArgumentError) { VgNode.new(deep.root, deep.bases, "no-agent", deep.issued, []) }
    assert_raises(ArgumentError) { VgNode.new(deep.root, deep.bases, deep.issuer, "01:0:golden", []) }
    node = Nodes.decode(deep.encode)
    error = assert_raises(NodeFormatError) { Nodes.encode(node.merge("r" => "not-a-cid")) }
    assert_includes error.message, "CID as text"
    vg = deep.encode
    root = vg.index(deep.root)
    no_cid = vg.byteslice(0, root) + ("x" * deep.root.bytesize) + vg.byteslice(root + deep.root.bytesize..)
    error = assert_raises(NodeFormatError) { Nodes.decode(no_cid) }
    assert_includes error.message, "CID as text"
  end

  # ------------------------------------------------------------------ kinds

  def test_the_reserved_kinds_have_no_schema
    %w[s tm ec].each do |kind|
      error = assert_raises(NodeFormatError) { Nodes.encode({ "k" => kind }) }
      assert_includes error.message, "reserved"
      error = assert_raises(NodeFormatError) { Nodes.decode(unhex(format("a1616b%02x%s", 0x60 + kind.bytesize, kind.unpack1("H*")))) }
      assert_includes error.message, "reserved"
    end
  end

  # PDT 2 phase 0 (P2-F-04, SPEC 9.2): a node of a level-2 kind with a key
  # its schema does not name is refused, as Java's NodeCodec refuses it.
  def test_every_pdt2_node_vector_with_an_unknown_key_is_refused
    nodes = %w[pdt_dn_leaf pdt_dn_tail pdt_datom_values pdt_text_runs].map { |name| hex(name) }
    nodes += (parts("pdt_db_root") + parts("pdt_rr_relaxed") + parts("pdt_vg_chain")).map { |text| unhex(text) }
    nodes += [parts("pdt_bo_small")[0], parts("pdt_bo_split")[0]].map { |text| unhex(text) }
    assert_equal %w[bo db dn rr rv t vg], nodes.map { |data| Nodes.kind_of(data) }.uniq.sort
    # the keys of 3.1.1, 3.5, 3.7, 3.9 and 3.10, as Java's NodeCodec names them
    { "db" => %w[v s me mt bf i t], "dn" => %w[l x e c], "rr" => %w[n s r t], "rv" => %w[c z], "t" => %w[r v],
      "vg" => %w[r b i t p], "bo" => %w[g n p c] }.each do |kind, keys|
      assert_equal keys.sort, Nodes::SCHEMAS.fetch(kind).keys.sort, kind
    end
    nodes.each do |data|
      count = data.getbyte(0) & 0x1F
      # "zz" (0x627a7a) sorts after every one- and two-letter key of these kinds
      widened = [0xA0 | (count + 1)].pack("C") + data.byteslice(1..) + ["627a7a00"].pack("H*")
      error = assert_raises(NodeFormatError, Nodes.kind_of(data)) { Nodes.decode(widened) }
      assert_includes error.message, "outside the schema", Nodes.kind_of(data)
    end
  end

  # PDT 2 phase 0: Java's records are immutable, so a Ruby value refuses a
  # change that would skip its constructor's checks and write bytes no
  # reader accepts.
  def test_the_pdt2_values_refuse_a_change_after_construction
    link = Nodes::Link.new(cid(hex("pdt_dn_leaf")))
    tagged = Datom::Tagged.new(Datom::Tagged::UUID, "\0".b * 16)
    run = TextRun.new("alice", 0, nil, "R", 1, false, "x")
    db = DbRoot.decode(unhex(parts("pdt_db_root")[0]))
    values = [age1, tagged, CharId.new("alice", 0), run, TextLeaf.new([run]), db, DnNode.new(0, "eavt", [age1], []),
              RrRoot.new(1, 5, nil, [Nodes::Embedded.new(cbor(1))]), RvNode.new([link], nil),
              VgNode.decode(unhex(parts("pdt_vg_chain")[1])), BoNode.new(0, "".b, [])]
    values.each do |value|
      assert_predicate value, :frozen?, value.class.name
      assert_raises(FrozenError, value.class.name) { value[0] = value[0] }
    end
  end

  def test_a_bigint_with_a_redundant_sign_byte_or_a_leaf_with_c_is_refused
    assert_raises(ArgumentError) { Datom::Tagged.new(Datom::Tagged::BIGINT, "\xFF\x80".b) }
    assert_equal "\xFF\x7F".b, Datom::Tagged.new(Datom::Tagged::BIGINT, "\xFF\x7F".b).inner
    node = Nodes.decode(hex("pdt_dn_leaf"))
    error = assert_raises(NodeFormatError) { DnNode.decode(Nodes.encode(node.merge("c" => []))) }
    assert_includes error.message, "leaf carries no 'c'"
  end

  def test_a_header_past_a_java_long_is_refused_as_javas_reader_refuses_it
    error = assert_raises(NodeFormatError) { Nodes.decode(unhex("a2616b627672616e1b8000000000000000")) }
    assert_includes error.message, "2^63 - 1"
    error = assert_raises(NodeFormatError) { Nodes.encode({ "k" => "vr", "n" => 2**63 }) }
    assert_includes error.message, "unsigned integer"
  end
end
