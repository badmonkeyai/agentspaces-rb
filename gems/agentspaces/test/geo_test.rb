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
require "json"

# srad/agentspaces-geo.md GEO-F-01: the GeoFeature in the Ruby client encodes
# to the bytes of the Java vector of agentspaces-a2ui-geo (copied into
# test/a2ui_vectors), and its builder refuses what the Java record refuses,
# naming the field.
class GeoTest < Minitest::Test
  Geo = AgentSpaces::Geo
  VECTORS = File.join(__dir__, "a2ui_vectors")
  AT = "2026-11-12T09:14:03Z"

  def hex_of(value) = AgentSpaces::CBOR.dump(value).unpack1("H*")

  def test_a_feature_encodes_to_the_java_vector
    fields = JSON.parse(File.read(File.join(VECTORS, "geo_feature.json")))
    hex = File.read(File.join(VECTORS, "geo_feature_cbor.hex")).strip
    built = Geo.feature(fields["id"], fields["kind"], fields["geometry"], at: fields["at"], properties: fields["properties"],
                                                                          label: fields["label"], style: fields["style"],
                                                                          severity: fields["severity"], links: fields["links"])
    assert_equal hex, hex_of(built)
    assert_equal fields, AgentSpaces::CBOR.load([hex].pack("H*"))
    ship = Geo.point("ship-217", "track.ship.cargo", -3.0123, 53.4087, at: AT, label: "MV Northgate",
                                                                        properties: { mmsi: "235012345", speed_kn: 11.2, destination: "Berth 4" },
                                                                        style: { icon: "ship", color: "#8888cc", heading: 74 },
                                                                        severity: "info", links: [{ rel: "bound-for", id: "berth-4" }])
    assert_equal hex, hex_of(ship), "the point builder gives the same bytes"
    plain = Geo.point("a", "k", 0.5, 0.5, at: AT)
    refute plain.key?("severity")
    refute plain.key?("links")
    assert_equal "https://badmonkey.ai/agentspaces/a2ui-geo/v1/GeoFeature", Geo::SCHEMA
  end

  def test_shapes_and_bounds
    berth = Geo.polygon("berth-4", "area.berth", [[[-3.01, 53.40], [-3.00, 53.40], [-3.00, 53.41], [-3.01, 53.41], [-3.01, 53.40]]], at: AT)
    assert_equal [-3.01, 53.40, -3.00, 53.41], Geo.bounds(berth)
    assert_equal "LineString", Geo.line("r", "route.ferry", [[-3.0, 53.4], [-3.1, 53.45]], at: AT)["geometry"]["type"]
  end

  def test_a_feature_that_breaks_a_rule_is_refused_by_name
    point = { "type" => "Point", "coordinates" => [0, 0] }
    {
      -> { Geo.point("", "track.ship", 0, 0, at: AT) } => /id/,
      -> { Geo.point("x" * 129, "track.ship", 0, 0, at: AT) } => /id/,
      -> { Geo.point("a", "Track Ship", 0, 0, at: AT) } => /kind/,
      -> { Geo.point("a", "k", 181, 0, at: AT) } => /longitude/,
      -> { Geo.point("a", "k", 0, -91, at: AT) } => /latitude/,
      -> { Geo.point("a", "k", Float::NAN, 0, at: AT) } => /finite/,
      -> { Geo.line("a", "route", [[0.0, 0.0]], at: AT) } => /two positions/,
      -> { Geo.polygon("a", "area", [[[0, 0], [1, 0], [1, 1], [0, 1]]], at: AT) } => /closed/,
      -> { Geo.feature("a", "k", { "type" => "GeometryCollection", "geometries" => [] }, at: AT) } => /GeometryCollection/,
      -> { Geo.point("a", "k", 0, 0, at: AT, style: { font: "Comic Sans" }) } => /style\.font/,
      -> { Geo.point("a", "k", 0, 0, at: AT, style: { color: "url(javascript:x)" }) } => /style\.color/,
      -> { Geo.point("a", "k", 0, 0, at: AT, style: { opacity: 2 }) } => /style\.opacity/,
      -> { Geo.point("a", "k", 0, 0, at: AT, style: { icon: "skull" }) } => /style\.icon/,
      -> { Geo.point("a", "k", 0, 0, at: AT, label: "x" * 121) } => /label/,
      -> { Geo.point("a", "k", 0, 0, at: AT, severity: "panic") } => /severity/,
      -> { Geo.point("a", "k", 0, 0, at: AT, properties: { a: { b: { c: { d: 1 } } } }) } => /depth/,
      -> { Geo.point("a", "k", 0, 0, at: AT, properties: { blob: "x" * 70_000 }) } => /64 KiB/,
      -> { Geo.line("a", "route", Array.new(10_001) { |i| [i * 0.00001, 0.0] }, at: AT) } => /10000 positions/,
      -> { Geo.point("a", "k", 0, 0, at: AT, links: Array.new(65) { |i| { rel: "near", id: "f-#{i}" } }) } => /64 links/,
      -> { Geo.feature("a", "k", point, at: AT, schema_version: 2) } => /schemaVersion/,
      -> { Geo.feature("a", "k", point, at: AT, type: "FeatureCollection") } => /type/,
      # a geometry holds only type, coordinates and a bbox (GEO-Q-12)
      -> { Geo.feature("a", "k", point.merge("blob" => "x" * 500_000), at: AT) } => /geometry\.blob/,
      -> { Geo.feature("a", "k", point.merge("crs" => { "type" => "name" }), at: AT) } => /geometry\.crs/,
      -> { Geo.feature("a", "k", point.merge("bbox" => [0, 0, 1]), at: AT) } => /geometry\.bbox/,
      # Java refuses a null property value, so the builder does
      -> { Geo.point("a", "k", 0, 0, at: AT, properties: { eta: nil }) } => /properties\.eta/,
      -> { Geo.point("a", "k", 0, 0, at: AT, style: { color: nil }) } => /style\.color/,
      # at is an instant as Java prints it
      -> { Geo.point("a", "k", 0, 0, at: "yesterday") } => /at/,
      -> { Geo.point("a", "k", 0, 0, at: "2026-11-12") } => /at/,
      -> { Geo.point("a", "k", 0, 0, at: "2026-11-12 09:14:03 UTC") } => /at/,
      # a link's rel and id are non-blank and counted in UTF-16 units
      -> { Geo.point("a", "k", 0, 0, at: AT, links: [{ rel: " ", id: "x" }]) } => /rel/,
      -> { Geo.point("a", "k", 0, 0, at: AT, links: [{ rel: "near", id: "  " }]) } => /link's id/,
      -> { Geo.point("a", "k", 0, 0, at: AT, links: [{ rel: "near", id: "\u{1F6A2}" * 100 }]) } => /link's id/
    }.each do |make, match|
      error = assert_raises(ArgumentError) { make.call }
      assert_match match, error.message
    end
  end

  def test_at_is_written_as_java_prints_an_instant
    at_of = ->(at) { Geo.point("a", "k", 0, 0, at: at)["at"] }
    assert_equal "2026-11-12T09:14:03Z", at_of.call(Time.utc(2026, 11, 12, 9, 14, 3))
    assert_equal "2026-11-12T09:14:03.250Z", at_of.call(Time.utc(2026, 11, 12, 9, 14, 3, 250_000))
    assert_equal "2026-11-12T09:14:03.123456Z", at_of.call(Time.utc(2026, 11, 12, 9, 14, 3, 123_456))
    assert_equal "2026-11-12T09:14:03Z", at_of.call(Time.new(2026, 11, 12, 10, 14, 3, "+01:00")), "in UTC"
    assert_equal "2026-11-12T09:14:03.120Z", at_of.call("2026-11-12T09:14:03.120Z")
  end

  def test_a_geometry_may_carry_a_bbox
    f = Geo.feature("a", "k", { "type" => "Point", "coordinates" => [1, 2], "bbox" => [1, 2, 1, 2] }, at: AT)
    assert_equal [1, 2, 1, 2], f["geometry"]["bbox"]
  end

  def test_a_feature_kind_names_a_look_once
    k = Geo.feature_kind("track.ship", label: "Ships", style: { icon: "ship", color: "#8888cc" }, fields: %w[mmsi])
    assert Geo.covers?(k, "track.ship.cargo")
    refute Geo.covers?(k, "track.shipyard")
    assert Geo.kind_matches?("track.ship*", "track.ship.cargo")
    refute Geo.kind_matches?("area.berth", "area.berths")
    assert_raises(ArgumentError) { Geo.feature_kind("track.ship", style: { color: "blue" }) }
  end

  def test_a_feature_kind_encodes_to_the_java_vector
    fields = JSON.parse(File.read(File.join(VECTORS, "feature_kind.json")))
    hex = File.read(File.join(VECTORS, "feature_kind_cbor.hex")).strip
    k = Geo.feature_kind(fields["kind"], label: fields["label"], style: fields["style"], fields: fields["fields"])
    assert_equal hex, hex_of(k)
  end
end
