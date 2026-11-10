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
require "digest"

# HLC round six, 2026-11-08 (F2, F3, S1 to S12): the CBOR rules every
# implementation shares. CBOR.load decodes a document only in the wire
# encoding, the image of Java's CborCodec encoder: a stamp is a definite,
# untagged text under its shortest head; text past 3996 UTF-16 code units
# travels in Jackson's chunks and no other text is chunked; an integer
# inside a Java long is plain and any other one a minimal tag 2 or 3 bignum;
# a decimal is a normalized tag 4; and the decoder refuses every other tag,
# every ill-formed or overlong UTF-8 text, and every document whose
# re-encoding differs from its bytes. The encoder writes each value in that
# one form, so an Integer and a BigDecimal re-encode to the bytes they came from.
class CborTest < Minitest::Test
  include AgentSpaces

  def bytes(hex) = [hex.delete(" ")].pack("H*")

  # ISSUE-HlcCanonicalStamps.md 14.5: rows 1 to 4 are stamps, rows 5 to 26 are not.
  STAMP_ROWS = {
    1 => "65 35 3A 30 3A 6E",
    2 => "78 19 31 37 36 32 35 36 30 30 30 30 30 30 30 3A 36 35 35 33 36 3A 7A 50 65 65 72",
    3 => "66 35 3A 30 3A C3 B1",
    4 => "68 35 3A 30 3A F0 9F 98 80"
  }.freeze
  ROW2_TEXT = "31 37 36 32 35 36 30 30 30 30 30 30 30 3A 36 35 35 33 36 3A 7A 50 65 65 72"
  NOT_STAMP_ROWS = {
    5 => "78 05 35 3A 30 3A 6E",
    6 => "79 00 05 35 3A 30 3A 6E",
    7 => "7A 00 00 00 05 35 3A 30 3A 6E",
    8 => "7B 00 00 00 00 00 00 00 05 35 3A 30 3A 6E",
    9 => "79 00 19 #{ROW2_TEXT}",
    10 => "7F 65 35 3A 30 3A 6E FF",
    11 => "7F 62 35 3A 63 30 3A 6E FF",
    21 => "45 35 3A 30 3A 6E",
    22 => "05",
    23 => "FB 40 14 00 00 00 00 00 00",
    24 => "A0",
    25 => "81 65 35 3A 30 3A 6E",
    26 => "F6"
  }.freeze
  # Rows 12 to 20 do not decode as CBOR at all on this wire: tags no encoder
  # writes (0, 32, and 55799) and ill-formed UTF-8.
  UNDECODABLE_ROWS = {
    12 => "C0 65 35 3A 30 3A 6E",
    13 => "D8 20 65 35 3A 30 3A 6E",
    14 => "D9 D9 F7 65 35 3A 30 3A 6E",
    15 => "66 35 3A 30 3A C1 AE",
    16 => "67 35 3A 30 3A E0 81 AE",
    17 => "66 35 C0 BA 30 3A 6E",
    18 => "67 35 3A 30 3A ED A0 80",
    19 => "65 35 3A 30 3A FF",
    20 => "66 35 3A 30 3A 6E 80"
  }.freeze

  def test_rows_one_to_four_decode_as_stamps
    STAMP_ROWS.each do |row, hex|
      refute_nil Wire.hlc_decode(CBOR.load(bytes(hex))), "row #{row} is a stamp"
    end
  end

  # Rows 5 to 11 hold a stamp's text under a longer head or in chunks it
  # does not need (S3, S6), and row 24 is a definite-length map (S8): none
  # is a document of the wire encoding.
  def test_rows_five_to_eleven_and_a_definite_map_do_not_decode
    NOT_STAMP_ROWS.slice(5, 6, 7, 8, 9, 10, 11, 24).each do |row, hex|
      assert_raises(CBOR::Error, "row #{row} does not decode") { CBOR.load(bytes(hex)) }
      assert_raises(CBOR::Error, "row #{row} as a map value does not decode") do
        CBOR.load("\xBF\x61k".b + bytes(hex) + "\xFF".b)
      end
    end
  end

  def test_every_other_item_decodes_and_is_no_stamp
    NOT_STAMP_ROWS.slice(21, 22, 23, 25, 26).each do |row, hex|
      value = CBOR.load(bytes(hex))
      assert_nil Wire.hlc_decode(value), "row #{row} is not a stamp"
      refute Wire.hlc_acceptable?(value), "row #{row} is not an acceptable stamp"
      assert_raises(ArgumentError, "row #{row} has no physical part") { Wire.hlc_physical(value) }
    end
  end

  def test_tags_and_ill_formed_utf8_do_not_decode_anywhere
    UNDECODABLE_ROWS.each do |row, hex|
      item = bytes(hex)
      assert_raises(CBOR::Error, "row #{row} does not decode") { CBOR.load(item) }
      assert_raises(CBOR::Error, "row #{row} as a map value does not decode") do
        CBOR.load("\xBF\x61k".b + item + "\xFF".b)
      end
      assert_raises(CBOR::Error, "row #{row} in an array does not decode") { CBOR.load("\x82\x01".b + item) }
    end
  end

  # S4, S9: a value inside a Java long is a plain integer under its shortest
  # head; past it, tag 2 or 3 over the magnitude as BigInteger.toByteArray()
  # writes it, a leading zero only before a byte of 0x80 or more. Jackson
  # reads tag 3 over m as -m.
  INTEGERS = {
    0 => "00", 23 => "17", 24 => "18 18", -1 => "20", -25 => "38 18", 255 => "18 FF", 65_536 => "1A 00 01 00 00",
    (1 << 63) - 1 => "1B 7F FF FF FF FF FF FF FF", -(1 << 63) => "3B 7F FF FF FF FF FF FF FF",
    1 << 63 => "C2 49 00 80 00 00 00 00 00 00 00", -(1 << 63) - 1 => "C3 49 00 80 00 00 00 00 00 00 01",
    1 << 64 => "C2 49 01 00 00 00 00 00 00 00 00", -(1 << 64) => "C3 49 01 00 00 00 00 00 00 00 00",
    (1 << 72) - 1 => "C2 4A 00 FF FF FF FF FF FF FF FF FF"
  }.freeze

  def test_an_integer_travels_plain_inside_a_java_long_and_as_a_minimal_bignum_past_it
    INTEGERS.each do |value, hex|
      assert_equal bytes(hex), CBOR.dump(value), "#{value} encodes as the encoding writes it"
      assert_equal value, CBOR.load(bytes(hex)), "#{hex} decodes to #{value}"
      assert_kind_of Integer, CBOR.load(bytes(hex))
    end
  end

  # S9: a bignum names a value outside a Java long in its one minimal form,
  # and Jackson's forms of a small BigInteger are no longer documents.
  def test_a_bignum_inside_a_java_long_or_with_padding_does_not_decode
    {
      "BigInteger 5 as tag 2" => "C2 41 05", "tag 2 over no bytes" => "C2 40", "tag 3 over no bytes" => "C3 40",
      "tag 2 over 80" => "C2 41 80", "tag 3 over FF" => "C3 41 FF", "tag 2 with a leading zero" => "C2 42 00 05",
      "tag 2 2^64 with a redundant zero" => "C2 4A 00 01 00 00 00 00 00 00 00 00",
      "tag 3 over 2^63, which is Long.MIN_VALUE" => "C3 48 80 00 00 00 00 00 00 00",
      "tag 2 with its top bit set" => "C2 48 80 00 00 00 00 00 00 00",
      "2^63 as a plain integer" => "1B 80 00 00 00 00 00 00 00", "-2^63-1 as a plain integer" => "3B 80 00 00 00 00 00 00 00",
      "an integer under a longer head" => "18 05"
    }.each do |name, hex|
      assert_raises(CBOR::Error, "#{name} does not decode") { CBOR.load(bytes(hex)) }
    end
  end

  # HLC round six, 2026-11-08 (S9, reference rule): Java's reader refuses a
  # bignum whose magnitude passes 1000 bytes (Jackson's StreamReadConstraints
  # maxNumberLength), alone or as a decimal's mantissa, so this codec neither
  # reads nor writes one. Ruby took 23 seconds to read a decimal whose
  # mantissa held a million bytes, and a frame holds eight times that.
  def test_a_bignum_past_1000_bytes_does_not_decode_or_encode
    magnitude = ->(n) { "\x7F".b + ("\xFF".b * (n - 1)) }
    [999, 1000].each do |n|
      value = magnitude.call(n).unpack1("H*").to_i(16)
      assert_equal value, CBOR.load(bytes("C2 59 #{format('%04X', n)}") + magnitude.call(n)), "#{n} bytes decode"
      assert_equal(-value, CBOR.load(bytes("C3 59 #{format('%04X', n)}") + magnitude.call(n)), "#{n} bytes decode")
      assert_equal BigDecimal(value), CBOR.load(bytes("C4 82 00 C2 59 #{format('%04X', n)}") + magnitude.call(n))
    end
    too_long = magnitude.call(1001)
    { "tag 2" => "C2 59 03 E9", "tag 3" => "C3 59 03 E9", "a decimal's mantissa" => "C4 82 00 C2 59 03 E9",
      "a million bytes in a mantissa" => "C4 82 00 C2 5A 00 0F 42 40" }.each do |name, hex|
      content = name.start_with?("a million") ? "\x7F".b + ("\xFF".b * 999_999) : too_long
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      assert_raises(CBOR::Error, "#{name} past 1000 bytes does not decode") { CBOR.load(bytes(hex) + content) }
      assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 1.0, "#{name} is refused at once"
    end
    assert_raises(CBOR::Error) { CBOR.dump(too_long.unpack1("H*").to_i(16)) }
    assert_raises(CBOR::Error) { CBOR.dump(BigDecimal(too_long.unpack1("H*").to_i(16))) }
  end

  # S9, F2: a BigDecimal travels as tag 4 [exponent, mantissa], normalized:
  # no trailing decimal zero in the mantissa, zero as [0, 0], the mantissa
  # plain inside a Java long under its shortest head, else a bignum.
  DECIMALS = {
    "1.5" => "C4 82 20 0F", "1.50" => "C4 82 20 0F", "0" => "C4 82 00 00", "-0.0" => "C4 82 00 00",
    "-0.001" => "C4 82 22 20", "1E+3" => "C4 82 03 01", "1000" => "C4 82 03 01", "-12.5" => "C4 82 20 38 7C",
    "2.147483648" => "C4 82 28 1A 80 00 00 00", "1e2147483647" => "C4 82 1A 7F FF FF FF 01",
    "1e-2147483647" => "C4 82 3A 7F FF FF FE 01",
    "1180591620717411303424" => "C4 82 00 C2 49 40 00 00 00 00 00 00 00 00"
  }.freeze

  def test_a_big_decimal_travels_as_a_normalized_tag_4
    DECIMALS.each do |text, hex|
      value = BigDecimal(text)
      assert_equal bytes(hex), CBOR.dump(value), "#{text} encodes as the encoding writes it"
      assert_equal value, CBOR.load(bytes(hex)), "#{hex} decodes to #{text}"
      assert_kind_of BigDecimal, CBOR.load(bytes(hex))
    end
    thirty_three = BigDecimal("100000000000000000000000000000001")
    assert_equal thirty_three, CBOR.load(CBOR.dump(thirty_three)), "a 33-digit mantissa stays exact"
    %w[NaN Infinity -Infinity 1e2147483648 1e-2147483648].each do |text|
      assert_raises(CBOR::Error, "#{text} has no tag 4") { CBOR.dump(BigDecimal(text)) }
    end
  end

  def test_an_unnormalized_or_out_of_range_decimal_does_not_decode
    {
      "1.50 as [-2, 150], as Jackson keeps the scale" => "C4 82 21 18 96", "zero with an exponent" => "C4 82 01 00",
      "trailing zeros" => "C4 82 20 18 64", "a mantissa under an eight-byte head" => "C4 82 22 1B 00 00 00 00 80 00 00 00",
      "the exponent -2^31" => "C4 82 3A 7F FF FF FF 01", "a bignum mantissa inside a long" => "C4 82 00 C2 41 05"
    }.each do |name, hex|
      assert_raises(CBOR::Error, "#{name} does not decode") { CBOR.load(bytes(hex)) }
    end
  end

  # S10: a Float is a float64 and a CBOR::Float32 a float32, each NaN is
  # Java's one NaN of its width, and a half float is no document.
  def test_floats_keep_their_width_and_java_s_one_nan
    assert_equal bytes("FB 3F F8 00 00 00 00 00 00"), CBOR.dump(1.5)
    assert_equal bytes("FB 80 00 00 00 00 00 00 00"), CBOR.dump(-0.0)
    assert_equal bytes("FA 3F C0 00 00"), CBOR.dump(CBOR::Float32.new(1.5))
    assert_equal CBOR::Float32.new(1.5), CBOR.load(bytes("FA 3F C0 00 00"))
    assert_equal 1.5, CBOR.load(bytes("FB 3F F8 00 00 00 00 00 00"))
    payload = ["7FF8000000000001"].pack("H*").unpack1("G")
    negative = ["FFF8000000000000"].pack("H*").unpack1("G")
    [Float::NAN, payload, negative].each do |nan|
      assert_equal bytes("FB 7F F8 00 00 00 00 00 00"), CBOR.dump(nan), "every NaN writes as Java's Double.NaN"
    end
    assert_equal bytes("FA 7F C0 00 00"), CBOR.dump(CBOR::Float32.new(["7FC00001"].pack("H*").unpack1("g")))
    assert CBOR.load(bytes("FB 7F F8 00 00 00 00 00 00")).nan?
    ["FB 7F F8 00 00 00 00 00 01", "FB FF F8 00 00 00 00 00 00", "FA 7F C0 00 01", "F9 3E 00", "F7"].each do |hex|
      assert_raises(CBOR::Error, "#{hex} does not decode") { CBOR.load(bytes(hex)) }
    end
  end

  # S8: a map's keys are unique text. The encoder refuses an Integer or byte
  # string key and a Hash whose Symbol and String keys name the same text,
  # and the decoder refuses a non-text key and a repeated one.
  def test_a_map_holds_unique_text_keys
    assert_equal bytes("BF 61 61 01 FF"), CBOR.dump({ a: 1 })
    [{ 1 => 2 }, { "k".b => 1 }, { a: 1, "a" => 2 }, { nil => 1 }].each do |map|
      assert_raises(CBOR::Error, "#{map.inspect} does not encode") { CBOR.dump(map) }
    end
    ["BF 01 02 FF", "BF 41 61 01 FF", "BF 61 61 01 61 61 02 FF", "A1 61 61 01", "BF F6 01 FF"].each do |hex|
      assert_raises(CBOR::Error, "#{hex} does not decode") { CBOR.load(bytes(hex)) }
    end
    assert_raises(CBOR::Error, "the encoder writes only valid UTF-8") { CBOR.dump("\xFF".dup.force_encoding(Encoding::UTF_8)) }
  end

  # S1: a document is a byte string holding one item.
  def test_only_a_byte_string_holds_a_document
    [nil, 5, ["\x01"]].each { |data| assert_raises(CBOR::Error, "#{data.inspect} is no document") { CBOR.load(data) } }
    assert_raises(CBOR::Error, "a second item does not decode") { CBOR.load(bytes("01 01")) }
  end

  # S8, S9: a tag never stands as a map key; the same tag as a map value decodes.
  def test_a_tag_as_a_map_key_does_not_decode
    ["BF C2 49 01 00 00 00 00 00 00 00 00 61 78 FF", "BF C4 82 00 01 61 78 FF", "BF 61 6B 01 C4 82 00 01 61 78 FF",
     "BF C0 61 61 61 78 FF"].each do |hex|
      assert_raises(CBOR::Error, "#{hex} does not decode") { CBOR.load(bytes(hex)) }
    end
    assert_equal({ "x" => 1 << 64 }, CBOR.load(bytes("BF 61 78 C2 49 01 00 00 00 00 00 00 00 00 FF")))
  end

  # S9: every tag the protocol does not define stays refused, and a
  # big-number tag over any item the encoding does not write under it is no item.
  def test_every_other_tag_and_every_malformed_big_number_is_refused
    {
      "tag 0" => "C0 61 61", "tag 1" => "C1 1A 00 00 00 01", "tag 6" => "C6 F6", "tag 24" => "D8 18 41 00",
      "tag 32" => "D8 20 61 61", "tag 42" => "D8 2A 41 00", "tag 55799" => "D9 D9 F7 A0",
      "an eight-byte tag 1" => "DB 00 00 00 00 00 00 00 01 01",
      "tag 2 over text" => "C2 61 41", "tag 2 over an indefinite byte string" => "C2 5F 41 01 FF",
      "tag 3 over an integer" => "C3 01", "tag 2 with nothing after it" => "C2",
      "tag 4 over three items" => "C4 83 01 02 03", "tag 4 over an indefinite array" => "C4 9F 01 02 FF",
      "tag 4 over a map" => "C4 A0", "tag 4 over a byte string" => "C4 41 00",
      "tag 4 with a float exponent" => "C4 82 F9 3C 00 01", "tag 4 with a float mantissa" => "C4 82 01 F9 3C 00",
      "tag 4 with a bignum exponent" => "C4 82 C2 41 01 01", "tag 4 with a decimal mantissa" => "C4 82 01 C4 82 01 01",
      "tag 4 with a text mantissa" => "C4 82 01 61 31",
      "tag 4 with an exponent above a Java int" => "C4 82 1A 80 00 00 00 01",
      "tag 4 with an exponent below a Java int" => "C4 82 3A 80 00 00 00 01",
      "tag 4 with an eight-byte exponent" => "C4 82 1B 00 00 00 01 00 00 00 00 01"
    }.each do |name, hex|
      assert_raises(CBOR::Error, "#{name} does not decode") { CBOR.load(bytes(hex)) }
      assert_raises(CBOR::Error, "#{name} as a map value does not decode") do
        CBOR.load("\xBF\x61k".b + bytes(hex) + "\xFF".b)
      end
    end
  end

  # S6: only a text past 3996 UTF-16 code units is chunked, so an
  # indefinite-length text of fewer units, or none, does not decode.
  def test_a_short_indefinite_length_text_does_not_decode
    ["7F 62 61 62 61 63 FF", "7F FF", "BF 61 6B 7F 62 61 62 61 63 FF FF"].each do |hex|
      assert_raises(CBOR::Error, "#{hex} does not decode") { CBOR.load(bytes(hex)) }
    end
  end

  def test_an_indefinite_length_text_holds_only_definite_well_formed_text_chunks
    {
      "a byte-string chunk" => "7F 41 61 FF",
      "a nested indefinite chunk" => "7F 7F 61 61 FF FF",
      "an integer chunk" => "7F 01 FF",
      "a chunk that splits a character" => "7F 61 C3 61 B1 FF",
      "an overlong chunk" => "7F 62 C0 BA FF",
      "a surrogate chunk" => "7F 63 ED A0 80 FF",
      "no break" => "7F 61 61"
    }.each do |name, hex|
      assert_raises(CBOR::Error, "#{name} does not decode") { CBOR.load(bytes(hex)) }
    end
  end

  # The digests of the bytes Jackson 2.21.7 (the Java codec) writes for each
  # string, from CBORMapper.writeValueAsBytes.
  JACKSON = {
    "a" * 3996 => "b374879b1b818070d1e6782349df0bbb4215308960f584a327f33a44447fec72",
    "a" * 4096 => "fc5e50e3db975ba62019c6032a8152ca56fcef7173db84a240eb8ad7933f2083",
    "#{'a' * 3995}\u{1F600}b" => "b34ae7af6fa1404f7570820067aaac665895bc8f9f44c1933e2ceb1de64ba1f6",
    "\u{1F600}" * 2000 => "50c896ec28bb325dabeb875637626e764972aeb36cdeca64dbe5734cfab2c87e",
    "ñ" * 9000 => "73969a0482957c8970bd599a2f29aab9addb44d56f17f9d6ddbd2cd792c29c69"
  }.freeze

  def test_the_encoder_writes_a_long_string_in_jacksons_chunks
    JACKSON.each do |text, digest|
      encoded = CBOR.dump(text)
      assert_equal digest, Digest::SHA256.hexdigest(encoded), "#{text.length} characters encode as Jackson's"
      assert_equal text, CBOR.load(encoded)
      assert_equal encoded, CBOR.dump(CBOR.load(encoded))
    end
    chunked = CBOR.dump("a" * 4096)
    assert_raises(CBOR::Error, "other chunks of the same text do not decode") do
      CBOR.load(bytes("7F 61 61 79 0F 9C") + ("a" * 3996).b + bytes("78 63") + ("a" * 99).b + bytes("FF"))
    end
    assert_raises(CBOR::Error, "a long text as one definite string does not decode") do
      CBOR.load(bytes("79 10 00") + ("a" * 4096).b)
    end
    assert_equal "a" * 4096, CBOR.load(chunked)
    assert_equal "53a6171aa8ae4d248fa591097e785f06d7a8404e1dfd99df18120dd14939924b",
                 Digest::SHA256.hexdigest(CBOR.dump({ "k" * 4000 => "v" })), "a long key encodes as Jackson's"
    # Jackson's chunks: 3996 UTF-16 code units each, one fewer when the
    # boundary would split a surrogate pair.
    assert_equal bytes("7F 79 0F 9C") + ("a" * 3996).b + bytes("78 64") + ("a" * 100).b + bytes("FF"),
                 CBOR.dump("a" * 4096)
    assert_equal bytes("7F 79 0F 9B") + ("a" * 3995).b + bytes("65 F0 9F 98 80 62 FF"),
                 CBOR.dump("#{'a' * 3995}\u{1F600}b")
  end

  # F3: a frame decodes only when its text is in Jackson's form. A Java
  # signer's chunked string verifies; any other form of the same text, other
  # chunks, a short indefinite text, or a long definite one, makes the frame
  # undecodable, whatever its signature covers.
  def test_a_frame_verifies_over_its_text_in_jacksons_form_alone
    signer = Identity.generate
    long = "g" * 5000
    env = Wire.envelope(long, "PING", signer.peer_id, "#{(Time.now.to_f * 1000).to_i}:0:#{signer.peer_id}",
                        Wire.ping_body(1))
    signed = lambda do |raw_env|
      "\xBF".b + CBOR.dump("envelope") + raw_env + CBOR.dump("senderPublicKey") + CBOR.dump(signer.public_raw) +
        CBOR.dump("signature") + CBOR.dump(signer.sign(raw_env)) + "\xFF".b
    end
    jackson = CBOR.dump(env)
    assert_includes jackson, bytes("7F 79 0F 9C"), "the group travels in Jackson's chunks"
    assert_equal long, Wire.decode_frame(signed.call(jackson))["group"]
    halves = bytes("7F 79 09 C4") + ("g" * 2500).b + bytes("79 09 C4") + ("g" * 2500).b + bytes("FF")
    other_chunks = jackson.sub(CBOR.dump(long)) { halves }
    refute_equal jackson, other_chunks
    assert_nil Wire.decode_frame(signed.call(other_chunks)), "other chunks re-encode in Jackson's"
    definite = jackson.sub(CBOR.dump(long)) { bytes("79 13 88") + long.b }
    assert_nil Wire.decode_frame(signed.call(definite)), "a definite long text re-encodes in Jackson's chunks"
    short = Wire.envelope("grp", "PING", signer.peer_id, env["stamp"], Wire.ping_body(1))
    chunked = CBOR.dump(short).sub(CBOR.dump("grp")) { bytes("7F 61 67 62 72 70 FF") }
    assert_equal "grp", Wire.decode_frame(signed.call(CBOR.dump(short)))["group"]
    assert_nil Wire.decode_frame(signed.call(chunked)), "a short indefinite text re-encodes definite"
  end

  # An integer has no indefinite length (RFC 8949 3.2), so additional
  # information 31 under major type 0 or 1 is no CBOR item, wherever it stands.
  def test_an_integer_head_with_indefinite_length_does_not_decode
    heads = { "a bare unsigned head" => "1F", "a bare negative head" => "3F",
              "an unsigned head as a map value" => "BF 61 6B 1F FF", "a negative head in an array" => "82 01 3F" }
    heads.each do |name, hex|
      assert_raises(CBOR::Error, "#{name} does not decode") { CBOR.load(bytes(hex)) }
    end
  end

  # HLC round six, 2026-11-08 (S1, F3): an array head that claims more items
  # than bytes remain is a truncated item, refused as CBOR::Error before the
  # decoder sizes anything by the count. A count near 2^63 raised
  # ArgumentError, one past it RangeError, and one in between NoMemoryError,
  # which no reader rescues, so one frame stopped the peer's read loop.
  def test_an_array_head_claiming_more_items_than_bytes_remain_is_truncated
    heads = { "2^28 items" => "9A 10 00 00 00", "about 4.6e17 items" => "9B 06 64 DF 7A 6B C4 61 73 FF",
              "2^63-1 items" => "9B 7F FF FF FF FF FF FF FF", "2^64-1 items" => "9B FF FF FF FF FF FF FF FF",
              "two items, one present" => "82 01", "an array value of a map" => "BF 61 6B 9B 7F FF FF FF FF FF FF FF FF" }
    heads.each do |name, hex|
      error = assert_raises(CBOR::Error, "#{name} is a truncated item") { CBOR.load(bytes(hex)) }
      assert_match(/truncated/, error.message, name)
    end
  end
end
