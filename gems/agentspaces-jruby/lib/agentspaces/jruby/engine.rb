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
  module JRuby
    # Routes each call of the generated interface to the Ruby method, with
    # Java records converted to Ruby entries on the way in and back on the
    # way out (SRAD S6).
    class ProxyHandler
      include java.lang.reflect.InvocationHandler

      def initialize(object, model, records)
        @object = object
        @records = records
        @clauses = model.clauses.to_h { |c| [c.method_name.to_s, c] }
      end

      def invoke(proxy, method, args)
        name = method.getName
        case name
        when "toString" then return "AgentSpaces::JRuby proxy for #{@object.class}"
        when "hashCode" then return java.lang.System.identityHashCode(proxy)
        when "equals" then return proxy.equal?(args&.first)
        end
        clause = @clauses.fetch(name)
        ruby_args = convert_in(clause, args.to_a)
        result = @object.public_send(clause.method_name, *ruby_args)
        convert_out(clause, result)
      end

      private

      def convert_in(clause, args)
        case clause.verb
        when :ballot
          p = args.first
          [Votes::Proposal.new(proposal_id: p.proposalId, question: p.question, options: p.options.to_a,
                               quorum: p.quorum)]
        when :on_decision
          d = args.first
          [Votes::Decision.new(proposal_id: d.proposalId, winner: d.winner,
                               tally: d.tally.to_h { |k, v| [k.to_s, Integer(v)] })]
        when :join
          joined = args.first
          parts = clause.options[:parts].to_h do |part|
            [part.type, joined.all(@records.java_class(part.type)).to_a.map { |r| @records.to_ruby(part.type, r) }]
          end
          [AgentSpaces::Joined.new(joined.key, parts)]
        when :reduce
          accumulator = clause.produces.first
          [@records.to_ruby(accumulator, args[0]), @records.to_ruby(clause.cue, args[1])]
        else
          [@records.to_ruby(clause.cue, args.first)]
        end
      end

      def convert_out(clause, result)
        case result
        when nil then nil
        when String then result
        when Float, Integer then clause.verb == :bid ? result.to_f : result
        when AgentSpaces::Tagged
          tags = java.util.LinkedHashMap.new
          result.tags.each { |k, v| tags.put(k.to_s, v.to_s) }
          Java::AiBadmonkeyAgentspacesAgent::Tagged.of(convert_out(clause, result.value), tags)
        when Array
          Java::AiBadmonkeyAgentspacesAgent::Entries.of(JRuby.to_java_tree([]).tap do |list|
            result.each { |e| list.add(convert_out(clause, e)) }
          end)
        when AgentSpaces::Motion
          options = java.util.ArrayList.new
          result.options.each { |o| options.add(o) }
          lease = Java::AiBadmonkeyAgentspacesApiSpace::Lease.of(java.time.Duration.ofMillis(Durations.millis(result.lease)))
          space = result.space || clause.options[:vote]
          Java::AiBadmonkeyAgentspacesAgentCapability::Motion.in(space, result.proposal_id, result.question, options,
                                                                  result.quorum, lease)
        else
          raise EngineUnsupported, "#{result.class} has no Java form" unless Entry.entry_class?(result.class)

          @records.ensure([result.class])
          @records.to_java(result.class, result)
        end
      end
    end

    # The JavaEngine: an AgentModel to a generated annotated interface and a
    # proxy over it, bound through FleetRuntime.bind (AgentBinder.annotationOf
    # reads the annotations from the interface).
    class JavaEngine
      attr_reader :records

      # One compiler, one record table, and one interface cache per process:
      # a generated class exists once, whatever the number of fleets.
      def self.shared
        @shared_lock ||= Mutex.new
        @shared_lock.synchronize do
          @shared ||= begin
            compiler = Compiler.new
            at_exit { compiler.close }
            [compiler, Records.new(compiler), {}, Mutex.new]
          end
        end
      end

      def initialize(runtime)
        @runtime = runtime
        @compiler, @records, @interfaces, @lock = JavaEngine.shared
      end

      def bind(object)
        model = object.class.agentspaces_model
        entries = model.clauses.flat_map do |c|
          types = [c.cue, *c.produces]
          types += c.options[:parts].map(&:type) if c.verb == :join
          types.select { |t| Entry.entry_class?(t) }
        end.uniq
        names = @records.ensure(entries)
        iface = interface_for(model, names)
        proxy = java.lang.reflect.Proxy.newProxyInstance(iface.getClassLoader, [iface].to_java(java.lang.Class),
                                                         ProxyHandler.new(object, model, @records))
        @runtime.bind(proxy).to_a
      end

      def close = nil

      private

      def interface_for(model, names)
        @lock.synchronize do
          name, source = JavaSource.interface(model, names)
          @interfaces[name] ||= @compiler.compile({ name => source }).loadClass(name)
        end
      end
    end

    # A fleet member on the Java node: AgentSpaces::JRuby::Fleet.start(config)
    # binds the starter's whole key set through PropertiesLoader.map and
    # FleetRuntime.start; bind(agent) runs the agent on the Java binder.
    class Fleet
      attr_reader :runtime

      def self.start(source = nil, **options)
        JRuby.load_jars!
        tree = Config.normalize(source.is_a?(Hash) || source.nil? ? (source || {}) : load_tree(source))
        tree = tree.fetch("agentspaces", tree)
        tree = Config.merge_options(tree, Config.normalize(options))
        new(Java::AiBadmonkeyAgentspacesRuntime::FleetRuntime.start(
              Java::AiBadmonkeyAgentspacesRuntime::PropertiesLoader.map(JRuby.to_java_tree(java_shape(tree)))
            ))
      end

      def self.load_tree(source)
        text = File.exist?(source.to_s) ? File.read(source) : source.to_s
        YAML.safe_load(text, permitted_classes: [], aliases: true) || {}
      end

      # The starter's property shape: spaces as objects with a name.
      def self.java_shape(tree)
        tree.merge("groups" => Array(tree["groups"]).map do |group|
          group.merge("spaces" => Array(group["spaces"]).map { |s| s.is_a?(Hash) ? s : { "name" => s.to_s } })
        end)
      end

      def initialize(runtime)
        @runtime = runtime
        @engine = JavaEngine.new(runtime)
      end

      # Binds an agent object; returns the Java binder's Bound handles.
      def bind(object) = @engine.bind(object)

      # The Java Space of the first (or the named) group.
      def java_space(name, group: nil)
        context = group ? @runtime.context(group) : @runtime.context
        context.group.space(name)
      end

      # Forms this node's member of an ordered log over a space and registers
      # it, so ordered_take agents naming that space can be bound: the Java
      # OrderedTakes.over wiring of example 12, with the log on the peer tick.
      # members: every member's PeerID, the same list on every member (one
      # voter per peer); agent: the agent name the coordinator takes as, by
      # default the one the registered space writes as (the binder requires
      # the two to agree, since only the claim's holder can complete it).
      def ordered(space, members:, agent: nil, seed: Random.rand(1 << 31), group: nil)
        context = (group ? @runtime.context(group) : @runtime.context).group
        writer = context.space(space).writer
        agent ||= writer.isPresent ? writer.get.localName : "app"
        peer_id = Java::AiBadmonkeyAgentspacesCommonId::PeerId
        ids = members.map { |m| m.is_a?(String) ? peer_id.of(m) : m }
        coordinator = Java::AiBadmonkeyAgentspacesCapabilitiesOrderedlog::OrderedTakes.over(
          context.pipes, Java::AiBadmonkeyAgentspacesCommonCodec::CborCodec.defaultCodec, @runtime.identity,
          agent.to_s, java.util.ArrayList.new(ids), java.time.InstantSource.system, seed, context.space(space)
        )
        context.ordered(space, coordinator)
        coordinator
      end

      # Writes a Ruby entry into a space through the Java node.
      def write(space, entry, lease: "10m")
        @engine.records.ensure([entry.class])
        record = @engine.records.to_java(entry.class, entry)
        lease = Java::AiBadmonkeyAgentspacesApiSpace::Lease.of(java.time.Duration.ofMillis(Durations.millis(lease)))
        java_space(space).write(record, lease)
      end

      # Every live entry of a type in a space, as Ruby entries.
      def all(space, entry_class, limit: 100)
        @engine.records.ensure([entry_class])
        klass = @engine.records.java_class(entry_class)
        template = Java::AiBadmonkeyAgentspacesApiSpace::Template.of(klass)
        java_space(space).readAll(template, limit).to_a.map { |r| @engine.records.to_ruby(entry_class, r) }
      end

      def records = @engine.records

      def peer_id = @runtime.identity.peerId.value

      def close
        @runtime.close
        @engine.close
      end
    end

    # Names an existing Java class for an Entry, so the JRuby face uses it
    # instead of generating a record (call before the first bind or write).
    def self.java_class(entry, java_class_name)
      JavaEngine.shared[1].explicit(entry, java_class_name)
    end
  end
end
