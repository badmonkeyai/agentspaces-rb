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
  # A clause or an agent definition that cannot be bound; raised when the
  # class body evaluates, naming the source location, the value at fault,
  # and the accepted values.
  class DefinitionError < ArgumentError
    attr_reader :location

    def initialize(message, location = nil)
      @location = location
      super(location ? "#{location.path}:#{location.lineno}: #{message}" : message)
    end
  end

  # One part of a join (@Part): its entry class, the space it lives in (the
  # join's by default), the key field (the join's by default) or key tag,
  # whether it is optional, how many are needed, and its conditions.
  Part = Data.define(:type, :space, :key, :key_tag, :optional, :at_least, :where, :tags, :filters) do
    def initialize(type:, space: nil, key: nil, key_tag: nil, optional: false, at_least: 1, where: nil, tags: nil,
                   filters: [])
      super
    end
  end

  # What a join method receives (Joined in Java): the key and the parts by class.
  class Joined
    attr_reader :key

    def initialize(key, parts)
      @key = key
      @parts = parts
    end

    def get(type)
      found = @parts[type] || []
      raise KeyError, "no #{type.inspect} part for key #{@key.inspect}" if found.empty?

      found.first
    end

    def find(type) = (@parts[type] || []).first

    def all(type) = (@parts[type] || []).dup

    def has?(type) = !(@parts[type] || []).empty?

    def parts = @parts.transform_values(&:dup)
  end

  # The clause model (SRAD 6.3): the plain data the macros record per clause,
  # read by both engines, the checker, and the CLI.
  ClauseModel = Data.define(:verb, :method_name, :cue, :options, :produces, :location)

  # The agent model: the spec plus every clause, in declaration order.
  AgentModel = Data.define(:name, :description, :goals, :clauses, :space_refs, :capability_refs)

  # The agent DSL. Include it and declare verbs above the methods they bind:
  #
  #   class Fulfiller
  #     include AgentSpaces::Agent
  #     agent "fulfiller", description: "Ships orders"
  #
  #     take Order, space: "orders", lease: "30s", produces: Shipment
  #     def ship(order) = Shipment.new(order_id: order.order_id, item: order.item, by: "fulfiller")
  #   end
  #
  # Options are the Java annotation attributes in snake_case; every macro
  # validates them when the class body evaluates.
  module Agent
    REQUIRED = Object.new.freeze
    DURATIONS = %i[lease poll_timeout result_lease within].freeze
    COMMON_RESULT = { result_space: nil, result_lease: "1h", produces: nil }.freeze
    # The action's contract for a planner (SPEC 6.1b), on the verbs whose Java
    # annotation declares it; the card carries it when any term is set.
    CONTRACT = { pre: nil, post: nil, cost: "" }.freeze
    CONTRACT_TERMS = 32
    COST_LENGTH = 64

    # The accepted options per verb, with defaults; REQUIRED marks the ones a
    # clause must name. Derived from the Java annotations' attributes.
    OPTIONS = {
      take: { space: REQUIRED, group: nil, lease: "10m", poll_timeout: "1s", tags: nil, where: nil, description: "",
              **CONTRACT, **COMMON_RESULT },
      notify: { space: REQUIRED, group: nil, on: WRITTEN, lease: "1h", tags: nil, where: nil, description: "",
                **COMMON_RESULT },
      bid: { space: REQUIRED, group: nil },
      ballot: { space: REQUIRED, group: nil, prefix: "", lease: "1h" },
      on_decision: { space: REQUIRED, group: nil, prefix: "", **COMMON_RESULT },
      propose: { space: REQUIRED, group: nil, vote: REQUIRED, options: REQUIRED, quorum: REQUIRED, prefix: "",
                 key: nil, key_tag: nil, lease: "1h", where: nil, tags: nil, description: "" },
      join: { space: REQUIRED, group: nil, key: REQUIRED, parts: REQUIRED, within: "1h", mode: "local",
              max_open: 10_000, description: "", **COMMON_RESULT },
      on_estimate: { epochs: "", ticks: 0, tolerance: 0.0, **COMMON_RESULT },
      ordered_take: { space: REQUIRED, group: nil, lease: "30s", poll_timeout: "2s", tags: nil, where: nil,
                      description: "", **CONTRACT, **COMMON_RESULT },
      # The accumulator lives in the reduce's own space, so no result_space.
      reduce: { space: REQUIRED, group: nil, key: nil, key_tag: nil, mode: "leased", lease: "30s", poll_timeout: "1s",
                tags: nil, where: nil, max_open: 10_000, description: "", produces: nil }
    }.freeze

    # The verbs the Java binder alone runs today (SRAD RB-A-08).
    JVM_ONLY = %i[ordered_take reduce].freeze
    JOIN_MODES = %w[local leased ordered].freeze
    REDUCE_MODES = %w[leased ordered].freeze
    VERBS_WITH_CUE = %i[take notify bid propose ordered_take].freeze

    def self.included(base)
      base.extend(ClassMethods)
      base.instance_variable_set(:@agentspaces_clauses, [])
      base.instance_variable_set(:@agentspaces_space_refs, {})
      base.instance_variable_set(:@agentspaces_capability_refs, {})
    end

    # The macros.
    module ClassMethods
      def agent(name, description: "", goals: [])
        @agentspaces_spec = { name: name.to_s, description: description.to_s, goals: Array(goals).map(&:to_s) }
      end

      def take(cue, **options, &block) = agentspaces_clause(:take, cue, options, block)
      def notify(cue, **options, &block) = agentspaces_clause(:notify, cue, options, block)
      def bid(cue, **options, &block) = agentspaces_clause(:bid, cue, options, block)
      def propose(cue, **options, &block) = agentspaces_clause(:propose, cue, options, block)
      def ordered_take(cue, **options, &block) = agentspaces_clause(:ordered_take, cue, options, block)

      # A ballot method receives a Votes::Proposal and returns an option or nil.
      def ballot(cue = Votes::Proposal, **options, &block) = agentspaces_clause(:ballot, cue, options, block)

      # A decision method receives a Votes::Decision once the quorum closes.
      def on_decision(cue = Votes::Decision, **options, &block)
        agentspaces_clause(:on_decision, cue, options, block)
      end

      # A join method receives a Joined once every required part is present.
      def join(**options, &block) = agentspaces_clause(:join, Joined, options, block)

      def reduce(cue, **options, &block) = agentspaces_clause(:reduce, cue, options, block)

      # An estimate method receives an aggregate estimate once it settles.
      def on_estimate(**options, &block) = agentspaces_clause(:on_estimate, nil, options, block)

      # @SpaceRef: a reader the engine fills with the named Space at bind.
      def space_ref(reader, name)
        @agentspaces_space_refs[reader.to_sym] = name.to_s
        attr_reader reader
      end

      # @CapabilityRef: a reader the engine fills with a capability client.
      def capability(reader, kind)
        @agentspaces_capability_refs[reader.to_sym] = kind.to_sym
        attr_reader reader
      end

      # The agent model, refusing a macro with no following def.
      def agentspaces_model
        if @agentspaces_pending
          raise DefinitionError.new("#{@agentspaces_pending[:verb]} has no following def", @agentspaces_pending[:location])
        end

        spec = @agentspaces_spec || { name: default_agent_name, description: "", goals: [] }
        AgentModel.new(name: spec[:name], description: spec[:description], goals: spec[:goals],
                       clauses: @agentspaces_clauses.dup.freeze, space_refs: @agentspaces_space_refs.dup,
                       capability_refs: @agentspaces_capability_refs.dup)
      end

      def method_added(name)
        super
        return if @agentspaces_defining || @agentspaces_pending.nil?

        pending = @agentspaces_pending
        @agentspaces_pending = nil
        agentspaces_record(pending, name)
      end

      private

      def default_agent_name
        base = (self.name || "agent").split("::").last
        base[0].downcase + base[1..]
      end

      def agentspaces_clause(verb, cue, options, block)
        location = caller_locations(2, 1).first
        if @agentspaces_pending
          raise DefinitionError.new("#{@agentspaces_pending[:verb]} on line #{@agentspaces_pending[:location].lineno} " \
                                    "has no following def before this #{verb}", location)
        end
        options = agentspaces_validate(verb, cue, options, location)
        pending = { verb: verb, cue: cue, options: options, location: location }
        if block
          name = :"#{verb}_#{@agentspaces_clauses.size}"
          @agentspaces_defining = true
          begin
            define_method(name, &block)
          ensure
            @agentspaces_defining = false
          end
          agentspaces_record(pending, name)
        else
          @agentspaces_pending = pending
        end
        nil
      end

      def agentspaces_record(pending, method_name)
        if @agentspaces_clauses.any? { |c| c.method_name == method_name }
          raise DefinitionError.new("method #{method_name} already carries a clause", pending[:location])
        end

        produces = Array(pending[:options].delete(:produces))
        @agentspaces_clauses << ClauseModel.new(verb: pending[:verb], method_name: method_name, cue: pending[:cue],
                                                options: pending[:options].freeze, produces: produces.freeze,
                                                location: pending[:location])
      end

      def agentspaces_validate(verb, cue, options, location)
        accepted = OPTIONS.fetch(verb)
        unknown = options.keys - accepted.keys
        unless unknown.empty?
          raise DefinitionError.new("#{verb} has no option #{unknown.map(&:inspect).join(', ')}; accepted: " \
                                    "#{accepted.keys.join(', ')}", location)
        end
        missing = accepted.select { |k, v| v.equal?(REQUIRED) && !options.key?(k) }.keys
        raise DefinitionError.new("#{verb} needs #{missing.join(', ')}", location) unless missing.empty?

        if VERBS_WITH_CUE.include?(verb) && !Entry.entry_class?(cue)
          raise DefinitionError.new("#{verb} needs an Entry class as its cue, got #{cue.inspect}; " \
                                    "define it with AgentSpaces::Entry.define", location)
        end
        merged = accepted.reject { |_, v| v.equal?(REQUIRED) }.merge(options)
        DURATIONS.each do |key|
          next unless merged.key?(key) && !merged[key].nil?
          next if Durations.valid?(merged[key])

          raise DefinitionError.new("#{key} #{merged[key].inspect} is not a duration; accepted forms: " \
                                    "#{Durations::FORMS}", location)
        end
        if Entry.entry_class?(cue) && (merged[:where] || merged[:tags])
          begin
            Template.new(cue, where: merged[:where], tags: merged[:tags])
          rescue ArgumentError => e
            raise DefinitionError.new(e.message, location)
          end
        end
        modes = verb == :reduce ? REDUCE_MODES : JOIN_MODES
        if merged.key?(:mode) && !modes.include?(merged[:mode].to_s)
          raise DefinitionError.new("mode #{merged[:mode].inspect} is not one of #{modes.join(', ')}", location)
        end
        if verb == :reduce && merged[:key].nil? == merged[:key_tag].nil?
          raise DefinitionError.new("reduce names exactly one of key and key_tag", location)
        end
        if verb == :notify
          kinds = Array(merged[:on]).map(&:to_s)
          bad = kinds - EVENT_KINDS
          raise DefinitionError.new("notify on: #{bad.join(', ')} is not one of #{EVENT_KINDS.join(', ')}", location) \
            unless bad.empty? && !kinds.empty?

          merged[:on] = kinds
        end
        if verb == :propose
          if Array(merged[:options]).size < 2 || !merged[:quorum].to_i.positive?
            raise DefinitionError.new("propose needs at least two options and a positive quorum", location)
          end
          if merged[:key] && merged[:key_tag]
            raise DefinitionError.new("propose names both key and key_tag; choose one", location)
          end
        end
        if verb == :join
          parts = Array(merged[:parts])
          unless !parts.empty? && parts.all?(Part)
            raise DefinitionError.new("join parts: is a non-empty list of AgentSpaces::Part", location)
          end
          parts.each do |part|
            unless Entry.entry_class?(part.type)
              raise DefinitionError.new("join part type #{part.type.inspect} is not an Entry class", location)
            end
          end
        end
        %i[pre post].each do |key|
          terms = merged[key]
          next if terms.nil? || (terms.is_a?(Array) && terms.size <= CONTRACT_TERMS && terms.all?(String))

          raise DefinitionError.new("#{key} #{terms.inspect} is not a list of at most #{CONTRACT_TERMS} texts", location)
        end
        if merged.key?(:cost) && !(merged[:cost].is_a?(String) && merged[:cost].length <= COST_LENGTH)
          raise DefinitionError.new("cost is a text of at most #{COST_LENGTH} characters, got #{merged[:cost].inspect}",
                                    location)
        end
        Array(merged[:produces]).each do |type|
          next if Entry.entry_class?(type) || type.is_a?(String)

          raise DefinitionError.new("produces: #{type.inspect} is not an Entry class or a schema name", location)
        end
        merged
      end
    end
  end

  # An agent built from a block, for scripts and tests:
  #
  #   pricer = AgentSpaces.agent("pricer") do
  #     take(Order, space: "orders", produces: Quote) { |order| Quote.new(...) }
  #   end
  def self.agent(name, description: "", goals: [], &block)
    klass = Class.new do
      include Agent

      agent name, description: description, goals: goals
    end
    klass.class_eval(&block)
    klass.new
  end
end
