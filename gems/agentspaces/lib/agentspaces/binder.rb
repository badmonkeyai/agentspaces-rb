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
  # A verb the engine cannot run (an ordered verb on the wire peer).
  class EngineUnsupported < DefinitionError; end

  # A capability the binder was not given.
  class CapabilityUnavailable < StandardError; end

  # A bound agent: its loops and subscriptions, closed together.
  class Bound
    attr_reader :binder, :name, :card, :failures

    def initialize(binder, name)
      @binder = binder
      @name = name
      @card = nil
      @threads = []
      @subscriptions = []
      @running = true
      @stop_lock = Mutex.new
      @stopped = ConditionVariable.new
      @failures = 0
    end

    def running? = @running

    # Sleeps up to seconds; returns true when the agent was closed meanwhile.
    def wait_stopped(seconds)
      @stop_lock.synchronize do
        @stopped.wait(@stop_lock, seconds) if @running
        !@running
      end
    end

    def close(timeout: 5)
      @stop_lock.synchronize do
        @running = false
        @stopped.broadcast
      end
      @subscriptions.each(&:close)
      @threads.each { |t| t.join(timeout) unless t == Thread.current }
      nil
    end

    def card_hash = @card&.dup

    # Internal: what the binder hands the bound agent.
    def add_thread(thread) = @threads << thread
    def add_subscription(subscription) = @subscriptions << subscription
    def card=(card)
      @card = card
    end

    def failed! = @failures += 1

    def inspect = "#<AgentSpaces::Bound #{@name} running=#{@running}>"
  end

  # Runs agents declared with AgentSpaces::Agent over one Peer (the
  # WireEngine of SRAD 3.3). agent (an AgentIdentity) makes every record the
  # agent's own attested one; agent_name names the peer-signed agent
  # otherwise. The card is published on bind and republished every
  # card_refresh seconds while the agent stays bound.
  class Binder
    attr_reader :peer, :agent, :agent_name

    def initialize(peer, agent: nil, agent_name: nil, publish_card: true, card_ttl: "PT10M", card_refresh: 300,
                   aggregate: nil, vote_space: nil, logger: nil, strict_produces: false, capabilities: {})
      @peer = peer
      @agent = agent
      @agent_name = agent_name
      @publish_card = publish_card
      @card_ttl = card_ttl
      @card_refresh = card_refresh
      @aggregate = aggregate
      @vote_space = vote_space
      @logger = logger || peer.logger
      @strict_produces = strict_produces
      @capabilities = capabilities
      @spaces = {}
    end

    def space(name)
      @spaces[name] ||= Space.new(@peer, name, agent: @agent, agent_name: @agent_name || "ruby")
    end

    # Binds one agent object; returns its Bound handle.
    def bind(object)
      model = model_of(object)
      @agent_name ||= model.name
      bound = Bound.new(self, model.name)
      model.clauses.each do |clause|
        if Agent::JVM_ONLY.include?(clause.verb) || (clause.verb == :join && clause.options[:mode].to_s != "local")
          raise EngineUnsupported.new("#{clause.verb} #{clause.options[:mode]} runs on the Java binder; bind this " \
                                      "agent with the JRuby face (agentspaces-jruby) or remove the clause",
                                      clause.location)
        end
      end
      fill_refs(object, model)
      consumes = []
      produces = []
      bindings = {}
      actions = []
      # Bids first, so AUCTION spaces are priced before any take runs.
      model.clauses.select { |c| c.verb == :bid }.each do |clause|
        method = object.method(clause.method_name)
        space(clause.options[:space]).bid_function = ->(payload) { Float(method.call(clause.cue.from_payload(payload))) }
      end
      model.clauses.each do |clause|
        method = object.method(clause.method_name)
        produced = clause.produces.map { |p| Entry.schema_of(p) }
        case clause.verb
        when :bid then next
        when :take, :notify
          schema = Entry.schema_of(clause.cue)
          consumes << schema
          produces.concat(produced)
          bindings[schema] = clause.options[:space] if clause.verb == :take
          actions << Wire.card_action(clause.method_name.to_s, clause.options[:description].to_s, [schema], produced,
                                      clause.verb.to_s, clause.options[:space])
          clause.verb == :take ? start_take(bound, method, clause) : start_notify(bound, method, clause)
        when :propose
          schema = Entry.schema_of(clause.cue)
          consumes << schema
          bindings[Votes::PROPOSAL_TYPE] ||= clause.options[:vote]
          actions << Wire.card_action(clause.method_name.to_s, clause.options[:description].to_s, [schema],
                                      [Votes::PROPOSAL_TYPE], "propose", clause.options[:space])
          start_propose(bound, method, clause)
        when :ballot then start_ballot(bound, method, clause)
        when :on_decision then start_decision(bound, method, clause)
        when :join
          part_schemas = clause.options[:parts].map { |p| Entry.schema_of(p.type) }
          consumes.concat(part_schemas)
          produces.concat(produced)
          actions << Wire.card_action(clause.method_name.to_s, clause.options[:description].to_s, part_schemas,
                                      produced, "join", clause.options[:space])
          start_join(bound, method, clause)
        when :on_estimate then start_estimate(bound, method, clause)
        end
      end
      if @publish_card
        publish = -> { bound.card = publish_card(model, consumes, produces, bindings, actions) }
        publish.call
        start_card_refresh(bound, publish)
      end
      bound
    end

    private

    def model_of(object)
      unless object.class.respond_to?(:agentspaces_model)
        raise ArgumentError, "#{object.class} does not include AgentSpaces::Agent"
      end

      object.class.agentspaces_model
    end

    def fill_refs(object, model)
      model.space_refs.each { |reader, name| object.instance_variable_set(:"@#{reader}", space(name)) }
      model.capability_refs.each do |reader, kind|
        client = kind == :aggregate ? @aggregate : @capabilities[kind]
        raise CapabilityUnavailable, "#{object.class}##{reader} needs the #{kind} capability; pass it to the Binder" \
          if client.nil?

        object.instance_variable_set(:"@#{reader}", client)
      end
    end

    def publish_card(model, consumes, produces, bindings, actions)
      now = @peer.now_ms
      issued_ms = now - (now % 1000)
      certificate = nil
      agent_key = nil
      local_name = @agent_name
      unless @agent.nil?
        agent_key = @agent.public_raw
        # A card's certificate must cover the card's own issue instant (SPEC
        # 6.1). Whole seconds round down, so a certificate minted earlier in
        # this same second does not cover it; the card then carries the
        # certificate's own instant.
        certificate = @agent.certificate_covering(issued_ms)
        if certificate.nil?
          certificate = @agent.certificate_covering(now)
          issued_ms = Instants.parse_millis(certificate["issued"]) if certificate
        end
        local_name = @agent.local_name
      end
      issued = Instants.iso(issued_ms)
      card = Wire.agent_card(@peer.group, @peer.identity, local_name, issued, @card_ttl, model.description,
                             model.goals, consumes.uniq, produces.uniq, {}, bindings,
                             agent_public_raw: agent_key, actions: actions.sort_by { |a| a["name"] },
                             agent_certificate: certificate)
      @peer.publish_ad("AgentCard", card)
      card
    end

    def start_card_refresh(bound, publish)
      spawn(bound, "card") do
        until bound.wait_stopped(@card_refresh)
          begin
            publish.call
          rescue StandardError => e
            log(bound, "card refresh", e)
          end
        end
      end
    end

    def spawn(bound, label, &block)
      thread = Thread.new do
        Thread.current.name = "#{bound.name}.#{label}"
        block.call
      end
      thread.report_on_exception = false
      bound.add_thread(thread)
      thread
    end

    # Off the delivery thread, as the Java binder runs reactions.
    def react(bound, label, &block)
      thread = Thread.new do
        Thread.current.name = "#{bound.name}.#{label}"
        block.call
      rescue StandardError => e
        bound.failed!
        log(bound, label, e)
      end
      thread.report_on_exception = false
      thread
    end

    def log(bound, label, error)
      @logger&.warn("agentspaces: #{bound.name}.#{label} failed: #{error.class}: #{error.message}")
    end

    def template_for(clause)
      Template.new(clause.cue, where: clause.options[:where], tags: clause.options[:tags])
    end

    def check_produces(bound, clause, value)
      return if clause.produces.empty? || !value.respond_to?(:schema)
      return if clause.produces.any? { |p| Entry.schema_of(p) == value.schema }

      message = "#{bound.name}.#{clause.method_name} wrote #{value.schema}, which produces: does not declare"
      raise ArgumentError, message if @strict_produces

      @logger&.warn("agentspaces: #{message}")
    end

    # The dispatch of a method's return (AgentBinder.dispatch): nothing for
    # nil; each element of an Array on its own (the fork); a Motion proposed
    # in its vote space; a Contribution started on the aggregate; a Tagged
    # written with its tags; any other value written as the next entry.
    def write_result(bound, clause, result, default_space)
      case result
      when nil then nil
      when Array
        result.each do |element|
          raise ArgumentError, "#{bound.name} returned a fork inside a fork" if element.is_a?(Array)

          write_result(bound, clause, element, default_space)
        end
        nil
      when Motion then move(bound, result)
      when Contribution
        raise CapabilityUnavailable, "#{bound.name} returned a Contribution and the binder has no aggregate" \
          if @aggregate.nil?

        @aggregate.start(result.epoch_id, result.value, result.mode)
        nil
      else
        target = clause.options[:result_space] ? space(clause.options[:result_space]) : default_space
        lease = clause.options[:result_lease] || "1h"
        value = result.is_a?(Tagged) ? result.value : result
        check_produces(bound, clause, value)
        result.is_a?(Tagged) ? target.write(result.value, lease: lease, tags: result.tags) : target.write(result, lease: lease)
      end
    end

    def move(bound, motion)
      target = motion.space || @vote_space
      if target.nil?
        raise ArgumentError, "#{bound.name} returned a Motion naming no space and the binder has no vote_space"
      end

      Votes.propose(@peer, target, motion.proposal_id, motion.question, motion.options, motion.quorum,
                    lease_millis: Durations.millis(motion.lease), agent: @agent, agent_name: @agent_name)
      nil
    end

    # The leased subscription every reacting binding shares: notify under
    # lease, renewed at half-lease while the agent stays bound.
    def subscribe(bound, space, template, lease, kinds: nil, &on_event)
      lease_ms = Durations.millis(lease)
      subscription = space.notify(template, lease: "#{lease_ms}ms", kinds: kinds, &on_event)
      bound.add_subscription(subscription)
      half = [lease_ms / 2000.0, 0.05].max
      spawn(bound, "renew") do
        until bound.wait_stopped(half)
          break unless subscription.open?

          subscription.renew
        end
      end
    end

    def start_take(bound, method, clause)
      space = space(clause.options[:space])
      template = template_for(clause)
      lease = clause.options[:lease]
      poll = clause.options[:poll_timeout]
      spawn(bound, clause.method_name.to_s) do
        while bound.running? && @peer.connected?
          taken = begin
            space.take(template, lease: lease, timeout: poll)
          rescue StandardError => e
            log(bound, "#{clause.method_name} take", e)
            bound.wait_stopped(0.5)
            next
          end
          next if taken.nil?

          result = begin
            TakeContext.with(taken) { method.arity == 1 ? method.call(taken.value) : method.call(taken.value, taken) }
          rescue StandardError => e
            # The lease lapses and the entry reappears for another worker.
            bound.failed!
            log(bound, "#{clause.method_name} (entry #{taken.entry_id})", e)
            next
          end
          begin
            if result.nil? || result.is_a?(Motion) || result.is_a?(Contribution) || result.is_a?(Array) ||
               clause.options[:result_space]
              # The take is finished first: a failed open or fork cannot make
              # a completed task reappear (ISSUE-Motion FR-4).
              taken.complete
              write_result(bound, clause, result, space)
            else
              value = result.is_a?(Tagged) ? result.value : result
              check_produces(bound, clause, value)
              taken.complete(value, lease: clause.options[:result_lease], tags: result.is_a?(Tagged) ? result.tags : nil)
            end
          rescue StandardError => e
            log(bound, "#{clause.method_name} complete", e)
          end
        end
      end
    end

    def start_notify(bound, method, clause)
      space = space(clause.options[:space])
      subscribe(bound, space, template_for(clause), clause.options[:lease], kinds: clause.options[:on]) do |event|
        react(bound, clause.method_name.to_s) do
          write_result(bound, clause, method.arity == 1 ? method.call(event.value) : method.call(event.value, event),
                       space)
        end
      end
    end

    def start_ballot(bound, method, clause)
      space = space(clause.options[:space])
      prefix = clause.options[:prefix].to_s
      lease_ms = Durations.millis(clause.options[:lease])
      cast_for = Set.new
      lock = Mutex.new
      subscription = space.watch(Votes::PROPOSAL_TYPE) do |event|
        proposal = event.value.payload
        pid = proposal["proposalId"]
        next unless pid.is_a?(String) && pid.start_with?(prefix)
        next unless lock.synchronize { cast_for.add?(pid) }

        react(bound, clause.method_name.to_s) do
          option = method.call(Votes::Proposal.new(proposal_id: pid, question: proposal["question"].to_s,
                                                   options: Array(proposal["options"]),
                                                   quorum: proposal.fetch("quorum", 0).to_i))
          unless option.nil?
            Votes.cast(@peer, space.name, pid, option.to_s, lease_millis: lease_ms, agent: @agent,
                                                            agent_name: @agent_name)
          end
        end
      end
      bound.add_subscription(subscription)
    end

    def start_decision(bound, method, clause)
      space = space(clause.options[:space])
      prefix = clause.options[:prefix].to_s
      fired = Set.new
      lock = Mutex.new
      check = lambda do |pid|
        next unless pid.is_a?(String) && pid.start_with?(prefix)

        decided = Votes.decision(@peer.states, pid)
        next if decided.nil?
        next unless lock.synchronize { fired.add?(pid) }

        react(bound, clause.method_name.to_s) do
          decision = Votes::Decision.new(proposal_id: pid, winner: decided["winner"], tally: decided["tally"])
          write_result(bound, clause, method.call(decision), space)
        end
      end
      bound.add_subscription(space.watch(Votes::BALLOT_TYPE) { |e| check.call(e.value.payload["proposalId"]) })
      bound.add_subscription(space.watch(Votes::PROPOSAL_TYPE) { |e| check.call(e.value.payload["proposalId"]) })
    end

    def start_estimate(bound, method, clause)
      raise CapabilityUnavailable, "#{clause.method_name} needs an aggregate: Binder.new(peer, aggregate: ...)" \
        if @aggregate.nil?

      prefix = clause.options[:epochs].to_s
      target = clause.options[:result_space] ? space(clause.options[:result_space]) : nil
      closer = @aggregate.on_estimate(->(epoch) { epoch.start_with?(prefix) },
                                      Capabilities::Settle.after(clause.options[:ticks].to_i,
                                                                 clause.options[:tolerance].to_f)) do |estimate|
        result = method.call(estimate)
        target&.write(result, lease: clause.options[:result_lease]) unless result.nil?
      rescue StandardError => e
        log(bound, clause.method_name.to_s, e)
      end
      bound.add_subscription(Struct.new(:closer) { def close = closer.call }.new(closer))
    end

    def start_propose(bound, method, clause)
      cue_space = space(clause.options[:space])
      options = clause.options
      keys = Array(options[:key]).map(&:to_s)
      key_tag = options[:key_tag]&.to_s
      prefix = options[:prefix].to_s
      opened = Set.new
      lock = Mutex.new
      subscribe(bound, cue_space, template_for(clause), options[:lease], kinds: [WRITTEN]) do |event|
        key =
          if key_tag then event.item.tags[key_tag]
          elsif !keys.empty?
            payload = event.value.to_payload
            parts = keys.map { |k| payload[clause.cue.field(k)&.wire || k] }
            parts.any?(&:nil?) ? nil : parts.map(&:to_s).join(":")
          end
        next if (!keys.empty? || key_tag) && key.nil?

        proposal_id = key.nil? ? nil : prefix + key
        next if proposal_id && !lock.synchronize { opened.add?(proposal_id) }

        react(bound, clause.method_name.to_s) do
          next if proposal_id && Votes.proposals(@peer.states).key?(proposal_id)

          result = method.call(event.value)
          if result.nil?
            lock.synchronize { opened.delete(proposal_id) }
          elsif result.is_a?(Motion)
            move(bound, result.space ? result : result.with(space: options[:vote]))
          else
            raise ArgumentError, "#{bound.name}.#{clause.method_name} names no key and returned no Motion" \
              if proposal_id.nil?

            Votes.propose(@peer, options[:vote], proposal_id, result.to_s, options[:options], options[:quorum],
                          lease_millis: Durations.millis(options[:lease]), agent: @agent, agent_name: @agent_name)
          end
        rescue StandardError
          lock.synchronize { opened.delete(proposal_id) }
          raise
        end
      end
    end

    def start_join(bound, method, clause)
      options = clause.options
      join_space = space(options[:space])
      parts = options[:parts]
      within_ms = Durations.millis(options[:within])
      max_open = options[:max_open].to_i
      state = {}
      fired = Set.new
      lock = Mutex.new
      key_of = lambda do |part, value, tags|
        next tags[part.key_tag.to_s] if part.key_tag

        field = (part.key || options[:key]).to_s
        raw = value.to_payload[part.type.field(field)&.wire || field]
        raw&.to_s
      end
      complete = lambda do |st|
        parts.reject(&:optional).all? { |p| (st[:parts][p.type] || []).size >= [1, p.at_least].max }
      end
      parts.each do |part|
        part_space = part.space ? space(part.space) : join_space
        template = Template.new(part.type, where: part.where, tags: part.tags, filters: part.filters || [])
        subscribe(bound, part_space, template, "1h", kinds: [WRITTEN]) do |event|
          key = key_of.call(part, event.value, event.item.tags)
          next if key.nil?

          now = @peer.now_ms
          ready = lock.synchronize do
            next false if fired.include?(key)

            state.delete_if { |_, st| now - st[:since] > within_ms }
            st = state[key]
            if st.nil?
              state.delete(state.keys.first) if state.size >= max_open
              st = state[key] = { parts: {}, seen: Set.new, since: now }
            end
            next false unless st[:seen].add?(event.item.entry_id)

            (st[:parts][part.type] ||= []) << event.value
            complete.call(st) && fired.add?(key) ? true : false
          end
          next unless ready

          react(bound, clause.method_name.to_s) do
            st = lock.synchronize { state.delete(key) }
            next if st.nil?

            begin
              write_result(bound, clause, method.call(Joined.new(key, st[:parts])), join_space)
            rescue StandardError
              lock.synchronize { fired.delete(key) }
              raise
            end
          end
        end
      end
    end
  end
end
