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
  # The Java Matchers as module functions, each a callable over the field's
  # decoded value. A where: value that is a plain object means eq, a Range
  # means the comparison its ends give, an Array means one_of, nil means
  # is_null, and a Regexp a match judged with a timeout on this replica.
  module Matchers
    # The compiled form of a Regexp matcher runs under this timeout (seconds).
    REGEXP_TIMEOUT = 0.1

    module_function

    def eq(expected) = ->(v) { v == expected }
    def ne(unexpected) = ->(v) { v != unexpected }
    def gt(bound) = ->(v) { compare(v, bound) { |c| c.positive? } }
    def gte(bound) = ->(v) { compare(v, bound) { |c| c >= 0 } }
    def lt(bound) = ->(v) { compare(v, bound) { |c| c.negative? } }
    def lte(bound) = ->(v) { compare(v, bound) { |c| c <= 0 } }
    def one_of(*alternatives) = ->(v) { alternatives.flatten.include?(v) }
    def contains(fragment) = ->(v) { v.is_a?(String) && v.include?(fragment) }
    def is_null = ->(v) { v.nil? } # rubocop:disable Naming/PredicateName
    def not_null = ->(v) { !v.nil? }
    def present = not_null

    def compare(value, bound)
      return false if value.nil?

      c = value <=> bound
      !c.nil? && yield(c)
    end

    def matches(pattern)
      regexp = Regexp.new(pattern.source, pattern.options, timeout: REGEXP_TIMEOUT)
      lambda do |v|
        v.is_a?(String) && regexp.match?(v)
      rescue Regexp::TimeoutError
        false
      end
    end

    # The callable a where: or tags: value compiles to.
    def compile(spec)
      case spec
      when Proc, Method then spec
      when Range then range(spec)
      when Array then one_of(*spec)
      when Regexp then matches(spec)
      when nil then is_null
      else spec.respond_to?(:call) ? spec : eq(spec)
      end
    end

    def range(spec)
      lambda do |v|
        next false if v.nil?
        next false if spec.begin && !compare(v, spec.begin) { |c| c >= 0 }
        next true if spec.end.nil?

        compare(v, spec.end) { |c| spec.exclude_end? ? c.negative? : c <= 0 }
      rescue ArgumentError, TypeError, NoMethodError
        false
      end
    end
  end

  # The portable field filter grammar (SPEC 7.2; Java FieldFilter, Python
  # parse_filter, TypeScript parseFilter): "field op literal" with =, !=, <,
  # <=, >, >=, or "field in a,b,c", compared numerically when both sides are
  # decimal numbers and as strings otherwise.
  module Filters
    OPS = ["!=", "<=", ">=", "=", "<", ">", " in "].freeze
    NUMBER = /\A[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?\z/

    module_function

    def form(value)
      case value
      when true then "true"
      when false then "false"
      else value.to_s
      end
    end

    def compare(form, literal)
      f = form.strip
      l = literal.strip
      if NUMBER.match?(f) && NUMBER.match?(l)
        Rational(f) <=> Rational(l)
      else
        form <=> literal
      end
    end

    # Returns [field, predicate]; raises ArgumentError on a malformed clause.
    def parse(clause)
      text = clause.to_s.strip
      best = -1
      best_op = ""
      OPS.each do |op|
        at = text.index(op)
        next if at.nil?

        if best.negative? || at < best || (at == best && op.size > best_op.size)
          best = at
          best_op = op
        end
      end
      if best <= 0
        raise ArgumentError, "malformed field filter '#{clause}'; use \"field=value\", \"field!=value\", " \
                             "\"field<value\", \"field<=value\", \"field>value\", \"field>=value\", or \"field in a,b,c\""
      end
      field = text[0...best].strip
      literal = text[(best + best_op.size)..].strip
      op = best_op.strip
      if op == "in"
        elements = literal.split(",").map(&:strip)
        return [field, ->(v) { !v.nil? && elements.any? { |e| compare(form(v), e).zero? } }]
      end
      test = lambda do |v|
        next op == "!=" if v.nil?

        c = compare(form(v), literal)
        { "=" => c.zero?, "!=" => !c.zero?, "<" => c.negative?, "<=" => c <= 0, ">" => c.positive?,
          ">=" => c >= 0 }.fetch(op)
      end
      [field, test]
    end
  end

  # A query: the entry type (an Entry class or a schema String), field
  # conditions, tag conditions, and clauses of the portable grammar. Field
  # keys are Ruby members or wire names; on an Entry class an unknown key is
  # refused here, naming the fields.
  class Template
    attr_reader :type, :schema, :filter

    def self.of(type, **options, &filter)
      return type if type.is_a?(Template) && options.empty? && filter.nil?

      new(type, **options, &filter)
    end

    def initialize(type, where: nil, tags: nil, filters: [], &filter)
      @type = type.is_a?(Template) ? type.type : type
      @schema = Entry.schema_of(@type)
      @where = {}
      @tags = {}
      clauses = Array(filters).dup
      case where
      when nil then nil
      when Hash
        where.each { |key, spec| add(@where, wire_key(key), Matchers.compile(spec)) }
      when String, Array then clauses.concat(Array(where))
      else raise ArgumentError, "where: is a Hash of matchers or clause Strings, got #{where.inspect}"
      end
      clauses.each do |clause|
        field, test = Filters.parse(clause)
        add(@where, wire_key(field), test)
      end
      (tags || {}).each { |key, spec| add(@tags, key.to_s, Matchers.compile(spec)) }
      @filter = filter
    end

    # Whether a decoded payload and its tags meet every condition. The local
    # block filter is judged separately, on the decoded entry (#accepts?).
    def matches(payload, tags = {})
      payload ||= {}
      @where.all? { |field, test| test.call(payload[field]) } && matches_tags(tags || {})
    end

    def matches_tags(tags) = @tags.all? { |key, test| test.call(tags[key]) }

    def accepts?(value) = @filter.nil? || @filter.call(value)

    def decode(payload) = Entry.decode(@type, payload, @schema)

    def fields = @where.keys

    def inspect = "#<AgentSpaces::Template #{@schema} where=#{@where.keys} tags=#{@tags.keys}>"

    private

    def add(table, key, test)
      previous = table[key]
      table[key] = previous.nil? ? test : ->(v) { previous.call(v) && test.call(v) }
    end

    def wire_key(key)
      return key.to_s unless Entry.entry_class?(@type)

      field = @type.field(key)
      if field.nil?
        raise ArgumentError, "#{@schema} has no field #{key}; fields are #{@type.fields.map(&:name).join(', ')}"
      end

      field.wire
    end
  end
end
