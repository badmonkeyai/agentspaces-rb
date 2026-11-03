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

module AgentSpaces
  # Durations as the Ruby API takes them: an Integer or a Float is seconds
  # (the convention of sleep and Timeout.timeout); a String uses the forms
  # Java's Durations.parse reads ("250ms", "10m", "2h", "PT5M"); an object
  # that responds to to_f (an ActiveSupport::Duration) counts as its seconds.
  # The Python client reads an int as milliseconds; this API does not.
  module Durations
    UNITS = { "ns" => 1e-6, "us" => 1e-3, "ms" => 1.0, "s" => 1_000.0, "m" => 60_000.0, "h" => 3_600_000.0,
              "d" => 86_400_000.0 }.freeze
    FORMS = '"250ms", "30s", "10m", "2h", "PT10M", or a number of seconds'

    module_function

    def millis(value)
      case value
      when true, false, nil then raise ArgumentError, "not a duration: #{value.inspect}; use #{FORMS}"
      when Integer then value * 1000
      when Float then (value * 1000).round
      when String then parse(value)
      else
        raise ArgumentError, "not a duration: #{value.inspect}; use #{FORMS}" unless value.respond_to?(:to_f)

        (value.to_f * 1000).round
      end
    end

    def seconds(value) = millis(value) / 1000.0

    def parse(text)
      stripped = text.strip
      if stripped.upcase.start_with?("PT")
        parts = stripped.upcase.scan(/([0-9.]+)([HMS])/)
        raise ArgumentError, "not a duration: #{text.inspect}; use #{FORMS}" if parts.empty?

        return parts.sum { |amount, unit| amount.to_f * { "H" => 3_600_000, "M" => 60_000, "S" => 1_000 }[unit] }.to_i
      end
      m = stripped.match(/\A([0-9]+)\s*([a-z]+)\z/)
      raise ArgumentError, "not a duration: #{text.inspect}; use #{FORMS}" if m.nil? || !UNITS.key?(m[2])

      (m[1].to_i * UNITS[m[2]]).to_i
    end

    def valid?(value)
      millis(value)
      true
    rescue ArgumentError
      false
    end
  end

  # Entry types: Data subclasses with a schema name, typed fields, and a map
  # from Ruby members (snake_case) to wire names (camelCase).
  #
  #   Order = AgentSpaces::Entry.define("shop.Order#v1", order_id: String, item: String, priority: Integer)
  #   Quote = AgentSpaces::Entry.define("shop.Quote#v1", item: String, price: Float, notes: [String])
  #
  # A field type is String, Integer, Float, :boolean, :bytes, :instant, an
  # Array of one type, Hash, Object, or another Entry class; a Hash spec
  # ({ type: String, wire: "traceID" }) overrides the wire name. A Float
  # field widens an Integer, because a signed double must encode as one.
  module Entry
    Field = Data.define(:name, :wire, :type)

    # A record whose schema this process has not registered: the schema name
    # and the decoded payload, so a peer can relay and show what it cannot type.
    Unknown = Data.define(:schema, :payload)

    # Class methods every entry class gains.
    module ClassMethods
      attr_reader :schema, :fields

      def wire_names = @fields.to_h { |f| [f.name, f.wire] }

      def field(name) = @fields.find { |f| f.name == name.to_sym || f.wire == name.to_s }

      # The entry from its wire payload: unknown wire fields are ignored and a
      # missing field is nil.
      def from_payload(payload)
        raise ArgumentError, "#{schema} payload is not a map" unless payload.is_a?(Hash)

        new(**@fields.to_h { |f| [f.name, Entry.decode_value(f.type, payload[f.wire])] })
      end

      def inspect = "#{name || 'Entry'}(#{schema})"
    end

    # Instance methods every entry gains.
    module InstanceMethods
      def initialize(**values)
        fields = self.class.fields
        unknown = values.keys.map(&:to_sym) - fields.map(&:name)
        unless unknown.empty?
          raise ArgumentError, "#{self.class.schema} has no field #{unknown.join(', ')}; " \
                               "fields are #{fields.map(&:name).join(', ')}"
        end
        super(**fields.to_h { |f| [f.name, Entry.coerce(f, values[f.name])] })
      end

      def schema = self.class.schema

      # The wire payload: wire names in declared member order.
      def to_payload = self.class.fields.to_h { |f| [f.wire, Entry.encode_value(f.type, public_send(f.name))] }
    end

    module_function

    # Defines an entry class and registers it under its schema name.
    def define(schema, **specs, &block)
      raise ArgumentError, "a schema name is a non-empty String" unless schema.is_a?(String) && !schema.empty?

      fields = specs.map do |name, spec|
        type, wire = spec.is_a?(Hash) && spec.key?(:type) ? [spec[:type], spec[:wire]] : [spec, nil]
        validate_type!(schema, name, type)
        Field.new(name: name.to_sym, wire: (wire || camel(name)).to_s, type: type)
      end
      klass = Data.define(*fields.map(&:name))
      klass.instance_variable_set(:@schema, schema)
      klass.instance_variable_set(:@fields, fields.freeze)
      klass.extend(ClassMethods)
      klass.prepend(InstanceMethods)
      klass.class_eval(&block) if block
      Registry.register(schema, klass)
      klass
    end

    def entry_class?(value) = value.is_a?(Class) && value.singleton_class.include?(ClassMethods)

    # "order_id" to "orderId".
    def camel(name)
      head, *rest = name.to_s.split("_")
      ([head] + rest.map { |part| part[0].to_s.upcase + part[1..].to_s }).join
    end

    def validate_type!(schema, name, type)
      return if [String, Integer, Float, Hash, Object, :boolean, :bytes, :instant].include?(type)
      return if entry_class?(type)
      return validate_type!(schema, name, type.first) if type.is_a?(Array) && type.size == 1

      raise ArgumentError, "#{schema} field #{name}: unknown type #{type.inspect}; use String, Integer, Float, " \
                           ":boolean, :bytes, :instant, [Type], Hash, Object, or an Entry class"
    end

    def coerce(field, value)
      coerce_value(field.type, value, field.name)
    end

    def coerce_value(type, value, name)
      return nil if value.nil?

      if type.is_a?(Array)
        raise ArgumentError, "#{name} expects a list" unless value.is_a?(Array)

        return value.map { |v| coerce_value(type.first, v, name) }.freeze
      end
      # Compared with ==: `case type when Float` would ask whether type is a Float.
      if type == Float
        raise ArgumentError, "#{name} expects a number, got #{value.inspect}" unless value.is_a?(Numeric)

        Float(value)
      elsif type == Integer
        return value if value.is_a?(Integer)
        return value.to_i if value.is_a?(Float) && value.finite? && value == value.floor

        raise ArgumentError, "#{name} expects an integer, got #{value.inspect}"
      elsif type == String || type == :instant
        return value.to_s if value.is_a?(Symbol)
        raise ArgumentError, "#{name} expects a String, got #{value.inspect}" unless value.is_a?(String)

        value
      elsif type == :boolean
        raise ArgumentError, "#{name} expects true or false, got #{value.inspect}" unless [true, false].include?(value)

        value
      elsif type == :bytes
        raise ArgumentError, "#{name} expects bytes (a String), got #{value.inspect}" unless value.is_a?(String)

        value.b
      elsif type == Hash
        raise ArgumentError, "#{name} expects a Hash, got #{value.inspect}" unless value.is_a?(Hash)

        value
      else
        return value unless entry_class?(type)
        return value if value.is_a?(type)
        return type.from_payload(value.transform_keys(&:to_s)) if value.is_a?(Hash)

        raise ArgumentError, "#{name} expects a #{type.schema}, got #{value.inspect}"
      end
    end

    def encode_value(type, value)
      return nil if value.nil?
      return value.map { |v| encode_value(type.first, v) } if type.is_a?(Array)
      return value.to_payload if value.respond_to?(:to_payload)
      return CBOR.canonical_map(value.to_h { |k, v| [k.to_s, plain(v)] }) if value.is_a?(Hash)

      plain(value)
    end

    def plain(value)
      case value
      when Hash then CBOR.canonical_map(value.to_h { |k, v| [k.to_s, plain(v)] })
      when Array then value.map { |v| plain(v) }
      when Symbol then value.to_s
      else value.respond_to?(:to_payload) ? value.to_payload : value
      end
    end

    def decode_value(type, value)
      return nil if value.nil?
      return Array(value).map { |v| decode_value(type.first, v) } if type.is_a?(Array)
      return type.from_payload(value) if entry_class?(type) && value.is_a?(Hash)
      return Float(value) if type == Float && value.is_a?(Numeric)

      value
    end

    # The wire payload of an entry value: an Entry's fields, or a Hash as is.
    def to_payload(value)
      return value.to_payload if value.respond_to?(:to_payload)
      return value.transform_keys(&:to_s) if value.is_a?(Hash)

      raise TypeError, "cannot encode #{value.class} as an entry payload; define it with AgentSpaces::Entry.define"
    end

    # The schema name of an Entry class, an entry, an Unknown, or a String.
    def schema_of(type_or_value)
      case type_or_value
      when String then type_or_value
      when Unknown then type_or_value.schema
      else
        return type_or_value.schema if entry_class?(type_or_value)
        return type_or_value.class.schema if entry_class?(type_or_value.class)

        raise TypeError, "#{type_or_value.inspect} is not an Entry and names no schema"
      end
    end

    # An entry from its wire payload: the class's, the registered class's,
    # or Unknown.
    def decode(type, payload, schema = nil)
      return type.from_payload(payload) if entry_class?(type)

      registered = Registry.lookup(schema || type.to_s)
      return registered.from_payload(payload) if registered

      Unknown.new(schema: schema || type.to_s, payload: payload)
    end
  end

  # The explicit table from schema name to Entry class. Decoding resolves a
  # schema here and nowhere else: no wire string ever reaches const_get.
  module Registry
    @classes = {}
    @lock = Mutex.new

    class << self
      def register(schema, klass)
        @lock.synchronize do
          previous = @classes[schema]
          if previous && previous.fields.map { |f| [f.wire, f.type] } != klass.fields.map { |f| [f.wire, f.type] }
            raise ArgumentError, "#{schema} is already registered with fields " \
                                 "#{previous.fields.map(&:wire).join(', ')}"
          end
          @classes[schema] = klass
        end
      end

      def lookup(schema) = @classes[schema]

      def schemas = @classes.keys
    end
  end
end
