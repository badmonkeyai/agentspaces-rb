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

require "json"

module AgentSpaces
  # The GeoFeature of agentspaces-a2ui-geo in the Ruby client
  # (srad/agentspaces-geo.md 3.1, GEO-F-01). A feature is a GeoJSON Feature
  # (RFC 7946) with the foreign members schemaVersion, kind, label, style, at,
  # severity and links. Geo.feature returns it as a Hash with its keys in Java's
  # declared order and its maps in canonical order, so it encodes to the bytes
  # the Java vector pins; it refuses what the Java record refuses, naming the
  # field. Write it with its schema:
  #
  #   ship = AgentSpaces::Geo.point("ship-217", "track.ship.cargo", -3.0123, 53.4087,
  #                                 at: Time.now, label: "MV Northgate",
  #                                 style: { "icon" => "ship", "heading" => 74 })
  #   space.write(ship, schema: AgentSpaces::Geo::SCHEMA, lease: "5m", tags: { kind: ship["kind"] })
  #
  # +at+ is a Time, or the text Java's Instant prints ("2026-11-12T09:14:03Z");
  # the builder writes a Time in that text, in UTC.
  module Geo
    NAMESPACE = "https://badmonkey.ai/agentspaces/a2ui-geo/v1/"
    SCHEMA = "#{NAMESPACE}GeoFeature".freeze
    KIND_SCHEMA = "#{NAMESPACE}FeatureKind".freeze
    SPACE = "features"
    MAX_POSITIONS = 10_000
    MAX_PROPERTIES_BYTES = 64 * 1024
    MAX_LINKS = 64
    GEOMETRIES = %w[Point MultiPoint LineString MultiLineString Polygon MultiPolygon].freeze
    SEVERITIES = %w[info warning serious critical].freeze
    ICONS = %w[dot pin truck van car plane ship person arrow].freeze
    KIND = /\A[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)*\z/
    HEX = /\A#[0-9a-fA-F]{6}\z/
    RANGES = { "opacity" => [0, 1], "width" => [1, 8], "size" => [1, 64], "heading" => [0, 360] }.freeze

    module_function

    # A feature, checked as the Java record checks it.
    def feature(id, kind, geometry, at:, properties: nil, label: "", style: nil, severity: nil, links: nil,
                schema_version: 1, type: "Feature")
      raise ArgumentError, "a GeoFeature has schemaVersion 1: #{schema_version}" unless schema_version == 1
      raise ArgumentError, "a GeoFeature's type is Feature, as GeoJSON's: #{type}" unless type == "Feature"
      unless id.is_a?(String) && !id.strip.empty? && utf16(id) <= 128 && id.each_char.none? { |c| c.ord < 0x20 || c.ord == 0x7f }
        raise ArgumentError, "a GeoFeature's id is 1 to 128 characters with no control character"
      end

      check_kind(kind, "GeoFeature")
      geometry = stringify(geometry)
      check_geometry(geometry)
      properties = stringify(properties || {})
      # Java's reader refuses a null in a map field, so a feature that held one would never be read
      properties.each { |k, v| raise ArgumentError, "properties.#{k} is nil; leave the key out instead" if v.nil? }
      properties.each { |k, v| depth("properties.#{k}", v, 1) }
      size = JSON.generate(properties).bytesize
      raise ArgumentError, "a GeoFeature's properties are at most 64 KiB: #{size} bytes" if size > MAX_PROPERTIES_BYTES

      label ||= ""
      if utf16(label) > 120 || label.each_char.any? { |c| c.ord < 0x20 && c != "\t" }
        raise ArgumentError, "a GeoFeature's label is at most 120 characters with no control character"
      end

      style = stringify(style || {})
      check_style(style)
      raise ArgumentError, "a GeoFeature has an at, an ISO-8601 instant" if at.nil? || at.to_s.empty?

      at = instant_text(at)
      raise ArgumentError, "a GeoFeature's severity is one of #{SEVERITIES.join(', ')}: #{severity}" unless severity.nil? || SEVERITIES.include?(severity)

      out = (links || []).map do |link|
        link = stringify(link)
        rel = link["rel"].to_s
        other = link["id"].to_s
        raise ArgumentError, "a link's rel is 1 to 64 characters" unless text?(rel, 64)
        raise ArgumentError, "a link's id is 1 to 128 characters" unless text?(other, 128)

        { "rel" => rel, "id" => other }
      end
      raise ArgumentError, "a GeoFeature has at most 64 links: #{out.size}" if out.size > MAX_LINKS

      f = { "schemaVersion" => 1, "type" => "Feature", "id" => id, "geometry" => canonical(geometry),
            "properties" => canonical(properties), "kind" => kind, "label" => label, "style" => canonical(style),
            "at" => at }
      f["severity"] = severity unless severity.nil?
      f["links"] = out unless out.empty?
      f
    end

    # A point at a longitude and a latitude, WGS 84.
    def point(id, kind, lon, lat, **rest) = feature(id, kind, { "type" => "Point", "coordinates" => [lon, lat] }, **rest)

    # A line through at least two positions, each [lon, lat].
    def line(id, kind, positions, **rest) = feature(id, kind, { "type" => "LineString", "coordinates" => positions.map(&:to_a) }, **rest)

    # A polygon: rings of positions, the first the outline, each closed.
    def polygon(id, kind, rings, **rest)
      feature(id, kind, { "type" => "Polygon", "coordinates" => rings.map { |r| r.map(&:to_a) } }, **rest)
    end

    # The bounds of a feature as [west, south, east, north].
    def bounds(feature)
      b = [Float::INFINITY, Float::INFINITY, -Float::INFINITY, -Float::INFINITY]
      walk = lambda do |c|
        if c.is_a?(Array) && c.first.is_a?(Numeric)
          b = [[b[0], c[0]].min, [b[1], c[1]].min, [b[2], c[0]].max, [b[3], c[1]].max]
        elsif c.is_a?(Array)
          c.each { |x| walk.call(x) }
        end
      end
      walk.call(feature["geometry"]["coordinates"])
      b
    end

    # A kind's look, checked as the Java record checks it; write it with KIND_SCHEMA.
    def feature_kind(kind, label: "", style: nil, fields: nil, schema_version: 1)
      raise ArgumentError, "a FeatureKind has schemaVersion 1: #{schema_version}" unless schema_version == 1

      check_kind(kind, "FeatureKind")
      style = stringify(style || {})
      check_style(style)
      { "schemaVersion" => 1, "kind" => kind, "label" => label.to_s.strip.empty? ? kind : label,
        "style" => canonical(style), "fields" => (fields || []).map(&:to_s) }
    end

    # A binding's kind filter: a pattern ending in * takes every kind that
    # starts with what comes before it.
    def kind_matches?(pattern, kind) = pattern.end_with?("*") ? kind.start_with?(pattern[0..-2]) : pattern == kind

    # Whether a FeatureKind covers a feature's kind: the same, or it followed by a dot and more.
    def covers?(feature_kind, kind) = kind == feature_kind["kind"] || kind.start_with?("#{feature_kind['kind']}.")

    # Refuses a geometry outside RFC 7946 and 3.1, naming what breaks.
    def check_geometry(g)
      t = g.is_a?(Hash) ? g["type"] : nil
      raise ArgumentError, "a GeoFeature's geometry is not a GeometryCollection; publish one feature per geometry" if t == "GeometryCollection"
      raise ArgumentError, "a GeoFeature's geometry.type is one of #{GEOMETRIES.join(', ')}: #{t}" unless GEOMETRIES.include?(t)

      # only the members RFC 7946 gives a geometry: any other would ride past
      # the position and size bounds to every page
      g.each do |key, v|
        case key
        when "type", "coordinates" then nil
        when "bbox"
          unless v.is_a?(Array) && [4, 6].include?(v.size) && v.all? { |x| x.is_a?(Numeric) && x.to_f.finite? }
            raise ArgumentError, "a GeoFeature's geometry.bbox is 4 or 6 finite numbers: #{v.inspect}"
          end
        when "crs" then raise ArgumentError, "a GeoFeature's geometry.crs is reserved: version 1 has none, and its absence means WGS 84"
        else raise ArgumentError, "geometry.#{key} is not a geometry member; a geometry has type, coordinates and an optional bbox"
        end
      end
      c = g["coordinates"]
      case t
      when "Point" then position(c)
      when "MultiPoint" then list(c, "a MultiPoint").each { |p| position(p) }
      when "LineString" then line_of(c)
      when "MultiLineString" then list(c, "a MultiLineString").each { |x| line_of(x) }
      when "Polygon" then polygon_of(c)
      else list(c, "a MultiPolygon").each { |x| polygon_of(x) }
      end
      n = count(c)
      raise ArgumentError, "a GeoFeature's geometry has at most 10000 positions: #{n}" if n > MAX_POSITIONS
    end

    # Refuses a style outside the closed grammar of 3.1, naming the key.
    def check_style(style, prefix = "style")
      style.each do |k, v|
        where = "#{prefix}.#{k}"
        if %w[color fill stroke].include?(k)
          raise ArgumentError, "#{where} is a hex colour #rrggbb: #{v}" unless v.is_a?(String) && HEX.match?(v)
        elsif RANGES.key?(k)
          lo, hi = RANGES[k]
          raise ArgumentError, "#{where} is a number from #{lo} to #{hi}: #{v}" unless v.is_a?(Numeric) && v.to_f.finite? && v.between?(lo, hi)
        elsif k == "icon"
          raise ArgumentError, "#{where} is one of #{ICONS.join(', ')}: #{v}" unless ICONS.include?(v)
        else
          raise ArgumentError, "#{where} is not a style key; the keys are color, fill, stroke, opacity, width, icon, size and heading"
        end
      end
    end

    def position(p)
      unless p.is_a?(Array) && p.size.between?(2, 3) && p.all?(Numeric)
        raise ArgumentError, "a position is [longitude, latitude] or [longitude, latitude, altitude]: #{p.inspect}"
      end
      raise ArgumentError, "a position's numbers are finite: #{p.inspect}" unless p.all? { |x| x.to_f.finite? }
      raise ArgumentError, "a position's longitude is from -180 to 180: #{p[0]}" unless p[0].between?(-180, 180)
      raise ArgumentError, "a position's latitude is from -90 to 90: #{p[1]}" unless p[1].between?(-90, 90)
    end

    def list(c, what)
      raise ArgumentError, "#{what}'s coordinates are a list of at least 1" unless c.is_a?(Array) && !c.empty?

      c
    end

    def line_of(c)
      l = list(c, "a LineString")
      raise ArgumentError, "a LineString has at least two positions" if l.size < 2

      l.each { |p| position(p) }
    end

    def polygon_of(c)
      list(c, "a Polygon").each do |ring|
        r = list(ring, "a Polygon's ring")
        raise ArgumentError, "a Polygon's ring has at least four positions and is closed (its last is its first)" if r.size < 4

        r.each { |p| position(p) }
        raise ArgumentError, "a Polygon's ring is closed: its last position is its first" unless r.first.map(&:to_f) == r.last.map(&:to_f)
      end
    end

    def count(c)
      return 1 if c.is_a?(Array) && c.first.is_a?(Numeric)

      c.is_a?(Array) ? c.sum { |x| count(x) } : 0
    end

    def depth(where, v, level)
      case v
      when Hash
        raise ArgumentError, "#{where} nests past a depth of 2; flatten it" if level >= 2 && !v.empty?

        v.each { |k, x| depth("#{where}.#{k}", x, level + 1) }
      when Array
        raise ArgumentError, "#{where} nests past a depth of 2; flatten it" if level >= 2 && v.any? { |x| x.is_a?(Hash) || x.is_a?(Array) }

        v.each { |x| depth(where, x, level + 1) }
      when String, Numeric, true, false, nil then nil
      else raise ArgumentError, "#{where} is a string, a number, a boolean, a list or an object: #{v.class}"
      end
    end

    def check_kind(kind, record)
      return if kind.is_a?(String) && kind.length <= 64 && KIND.match?(kind)

      raise ArgumentError, "a #{record}'s kind is a dotted lower-case name such as track.ship: #{kind}"
    end

    # A value with string keys at every depth.
    def stringify(v)
      case v
      when Hash then v.to_h { |k, x| [k.to_s, stringify(x)] }
      when Array then v.map { |x| stringify(x) }
      else v
      end
    end

    # A value with every map in it, at any depth, in canonical order, as Java's codec writes every map.
    def canonical(v)
      case v
      when Hash then CBOR.canonical_map(v.transform_values { |x| canonical(x) })
      when Array then v.map { |x| canonical(x) }
      else v
      end
    end

    def utf16(text) = text.encode("UTF-16LE").bytesize / 2

    # Whether +v+ is non-blank text of at most +most+ UTF-16 code units, as
    # Java counts a string's length.
    def text?(v, most) = v.is_a?(String) && !v.strip.empty? && utf16(v) <= most

    # +at+ as the text Java's Instant prints and reads back to the same bytes:
    # a Time is written so, in UTC, with a fraction of 3, 6 or 9 digits only
    # when not zero; a string must already be so ("2026-11-12T09:14:03Z").
    # Time#to_s or a +00:00 offset would be refused by every Java reader.
    def instant_text(at)
      if at.is_a?(Time)
        utc = at.getutc
        nsec = utc.nsec
        digits = if nsec.zero? then 0
                 elsif (nsec % 1_000_000).zero? then 3
                 elsif (nsec % 1000).zero? then 6
                 else 9
                 end
        text = utc.strftime("%Y-%m-%dT%H:%M:%S") + (digits.zero? ? "" : format(".%09d", nsec)[0, digits + 1]) + "Z"
        raise ArgumentError, "a GeoFeature's at is in the years 0000 to 9999: #{text}" unless Instants.canonical_instant?(text)

        return text
      end
      return at if at.is_a?(String) && Instants.canonical_instant?(at)

      raise ArgumentError, "a GeoFeature's at is an instant as Java prints it, such as 2026-11-12T09:14:03Z: #{at.inspect}"
    end
  end
end
