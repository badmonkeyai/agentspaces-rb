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
  # An entry as the space holds it: the value, its id, its tags, who issued
  # it, when its write lease ends, and whether it is completed or taken.
  Item = Data.define(:entry_id, :value, :tags, :issuer, :expires_at_millis, :completed, :taken)

  # What a watch delivers: WRITTEN, TAKEN, COMPLETED, EXPIRED, or REAPPEARED.
  Event = Data.define(:kind, :item) do
    def value = item.value
  end

  WRITTEN = "WRITTEN"
  TAKEN = "TAKEN"
  COMPLETED = "COMPLETED"
  EXPIRED = "EXPIRED"
  REAPPEARED = "REAPPEARED"
  EVENT_KINDS = [WRITTEN, TAKEN, COMPLETED, EXPIRED, REAPPEARED].freeze

  # A result written with tags (Tagged.of in Java).
  Tagged = Data.define(:value, :tags) do
    def self.of(value, **tags) = new(value: value, tags: tags.transform_keys(&:to_s))
  end

  # This peer's contribution to a push-sum epoch, as a return value.
  Contribution = Data.define(:epoch_id, :value, :mode) do
    def initialize(epoch_id:, value:, mode: "avg") = super(epoch_id: epoch_id, value: Float(value), mode: mode)
  end

  # A vote opened as a return value: proposed once per proposal id.
  Motion = Data.define(:proposal_id, :question, :options, :quorum, :space, :lease) do
    def initialize(proposal_id:, question:, options:, quorum:, space: nil, lease: "1h")
      raise ArgumentError, "a motion needs at least two options" if options.size < 2
      raise ArgumentError, "quorum must be positive" unless quorum.to_i.positive?

      super(proposal_id: proposal_id, question: question, options: options.to_a.freeze, quorum: Integer(quorum),
            space: space, lease: lease)
    end
  end

  # The take a worker method runs under, through fiber storage, which child
  # fibers and threads inherit; the binder sets it around the call, so a
  # lease keepalive finds it without a parameter.
  module TakeContext
    module_function

    def current = Fiber[:agentspaces_take]

    def with(taken)
      previous = Fiber[:agentspaces_take]
      Fiber[:agentspaces_take] = taken
      yield taken
    ensure
      Fiber[:agentspaces_take] = previous
    end
  end

  # A watch handle; close stops the deliveries. A leased subscription closes
  # itself when its lease lapses on the peer's clock unless renewed; the
  # binder renews at half-lease. reason is "closed" or "lapsed" once closed.
  class Subscription
    attr_reader :reason

    def initialize(space, key)
      @space = space
      @key = key
      @lease_millis = nil
      @expires_ms = nil
      @closed = false
      @reason = nil
      @on_close = []
    end

    def open? = !@closed

    def renew(lease = nil)
      return if @closed

      millis = lease.nil? ? @lease_millis : Durations.millis(lease)
      return if millis.nil?

      @lease_millis = millis
      @expires_ms = @space.peer.now_ms + millis
    end

    def renew_millis(millis)
      @lease_millis = millis
      renew
    end

    def lapsed?(now_ms) = !@expires_ms.nil? && @expires_ms <= now_ms

    def on_close(&listener) = @on_close << listener

    def close(reason = "closed")
      return if @closed

      @closed = true
      @reason = reason
      @space.unwatch(@key)
      @on_close.each do |listener|
        listener.call(reason)
      rescue StandardError
        nil
      end
    end
  end

  # A held entry: complete it, with a result or without, or renew it.
  class Taken
    attr_reader :space, :entry_id, :value, :lease_millis

    def initialize(space, entry_id, value, lease_millis)
      @space = space
      @entry_id = entry_id
      @value = value
      @lease_millis = lease_millis
    end

    # Completes the take, writing result first (into the take's space, or
    # result_space) so a caller correlating on it sees it with the completion.
    def complete(result = nil, lease: "1h", tags: nil, result_space: nil)
      result_id = nil
      unless result.nil?
        target = result_space || @space
        target = @space.peer.space(target, agent: @space.agent, agent_name: @space.agent_name) if target.is_a?(String)
        result_id = target.write(result, lease: lease, tags: tags)
      end
      @space.peer.complete_entry(@space.name, @entry_id, agent: @space.agent)
      result_id
    end

    # Extends the take's claim by lease (default: the take's own lease);
    # returns the new expiry in epoch milliseconds.
    def renew(lease = nil)
      millis = lease.nil? ? @lease_millis : Durations.millis(lease)
      @space.peer.renew_claim(@space.name, @entry_id, lease_millis: millis, agent: @space.agent)
    end

    def inspect = "#<AgentSpaces::Taken #{@entry_id} #{@value.inspect}>"
  end

  # One space of the peer's group, by name: the Layer 3 verbs over typed
  # entries. agent (an AgentIdentity) makes every write, take, and completion
  # that agent's own attested record; agent_name names the peer-signed agent
  # otherwise.
  class Space
    DEFAULT_WRITE_LEASE = "10m"

    attr_reader :peer, :name, :agent, :agent_name
    attr_accessor :bid_function

    def initialize(peer, name, agent: nil, agent_name: "ruby")
      @peer = peer
      @name = name.to_s
      @agent = agent
      @agent_name = agent_name
      @bid_function = nil
      @watchers = {}
      @next_key = 0
      @lock = Mutex.new
      @space_id = Derive.space_id_local("#{peer.group}/#{@name}")
      peer.add_observer(self)
    end

    # ----------------------------------------------------------------- verbs

    # Writes an entry; returns its id. A Hash needs schema:.
    def write(value, lease: DEFAULT_WRITE_LEASE, tags: nil, schema: nil)
      schema ||= Entry.schema_of(value)
      @peer.write_entry(@name, schema, Entry.to_payload(value), agent_name: @agent_name,
                                                                lease_millis: Durations.millis(lease), agent: @agent,
                                                                tags: tags&.to_h { |k, v| [k.to_s, v.to_s] })
    end

    def <<(value)
      write(value)
      self
    end

    # Every live entry matching the template, with its metadata.
    def entries(type, limit: 100, include_taken: true, **options, &filter)
      template = Template.of(type, **options, &filter)
      now = @peer.now_ms
      found = []
      @peer.states.to_a.each do |entry_id, dto|
        record = dto["record"] || {}
        # completed, or withdrawn by a cancel (core cancel events, 2026-11-09)
        next unless record["type"] == template.schema && mine?(dto) && Peer.present?(dto)

        lease = Peer.lease_of(dto)
        next if lease.fetch("expiresAtMillis", 0).to_i <= now

        value = @peer.value_of(dto)
        next if value.nil?

        payload = value.first
        tags = record["tags"] || {}
        next unless template.matches(payload, tags)

        claim = @peer.claim_of(entry_id)
        taken = !claim.nil? && claim.fetch("expiresAtMillis", 0).to_i > now
        next if taken && !include_taken

        # An authentic entry whose payload does not fit its registered shape
        # (a forged field type) is skipped, so one member cannot fail a read.
        value = decode_or_nil(template, payload)
        next if value.nil? || !template.accepts?(value)

        found << Item.new(entry_id: entry_id, value: value, tags: tags.dup.freeze, issuer: record["issuer"],
                          expires_at_millis: lease.fetch("expiresAtMillis", 0).to_i, completed: false, taken: taken)
        break if found.size >= limit
      end
      found.freeze
    end

    # The values of every live matching entry, as a frozen Array.
    def all(type, limit: 100, **options, &filter)
      entries(type, limit: limit, **options, &filter).map(&:value).freeze
    end
    alias read_all all

    # The first match, waiting up to timeout for one: the space is pulled at
    # most once per settle window and the wait wakes on a fold.
    def read(type, timeout: nil, settle: "600ms", **options, &filter)
      template = Template.of(type, **options, &filter)
      settle_seconds = Durations.seconds(settle)
      deadline = monotonic + (timeout.nil? ? 0 : Durations.seconds(timeout))
      loop do
        seen = @peer.fold_count
        found = entries(template, limit: 1)
        return found.first.value unless found.empty?

        remaining = deadline - monotonic
        return nil if remaining <= 0

        @peer.pull_space_paced(@name, settle_seconds)
        @peer.await_fold([settle_seconds, remaining].min, since: seen)
      end
    end

    # An exclusive take of one matching entry under the space's strategy; the
    # bid function prices it under AUCTION. With a block, the block runs on
    # the taken entry and the take completes with its result (an entry), with
    # no result on nil, and lapses when the block raises. With through: (an
    # ordered-log client) the claim goes through the fleet's ordered log.
    def take(type, lease: "1m", timeout: "15s", through: nil, **options, &block)
      template = Template.of(type, **options)
      millis = Durations.millis(lease)
      matches = ->(payload, tags) { template.matches(payload, tags) }
      entry_id =
        if through
          through.take(@name, template.schema, agent_name: @agent_name, lease_millis: millis,
                                               timeout_seconds: Durations.seconds(timeout), agent: @agent,
                                               matches: matches)
        else
          @peer.take_entry(@name, template.schema, agent_name: @agent_name, lease_millis: millis,
                                                   timeout_seconds: Durations.seconds(timeout), agent: @agent,
                                                   matches: matches, bid: @bid_function || 0.0)
        end
      return nil if entry_id.nil?

      dto = @peer.states.fetch(entry_id)
      taken = Taken.new(self, entry_id, template.decode(@peer.value_of(dto)&.first), millis)
      return taken if block.nil?

      result = TakeContext.with(taken) { block.call(taken.value, taken) }
      result.is_a?(Tagged) ? taken.complete(result.value, tags: result.tags) : taken.complete(result)
      result
    end

    def complete(taken, result = nil, lease: "1h", tags: nil) = taken.complete(result, lease: lease, tags: tags)

    # Delivers events for matching entries as they fold, once per entry and
    # kind, on the peer's reader thread: return promptly.
    def watch(type, kinds: nil, **options, &callback)
      raise ArgumentError, "watch needs a block" if callback.nil?

      template = Template.of(type, **options)
      wanted = kinds.nil? ? nil : Array(kinds).map(&:to_s)
      @lock.synchronize do
        key = @next_key
        @next_key += 1
        subscription = Subscription.new(self, key)
        @watchers[key] = [template, callback, Set.new, subscription, wanted]
        subscription
      end
    end

    # The leased push subscription of the Java space: events reach the block
    # as they fold, and the subscription lapses after lease unless renewed.
    def notify(type, lease: "1h", **options, &callback)
      subscription = watch(type, **options, &callback)
      subscription.renew(lease)
      subscription
    end

    # An Enumerator fed by a watch: space.stream(Order).lazy.select { ... }.first(3).
    def stream(type, **options)
      Enumerator.new do |yielder|
        queue = Thread::Queue.new
        subscription = watch(type, **options) { |event| queue << event }
        begin
          loop { yielder << queue.pop.value }
        ensure
          subscription.close
        end
      end
    end

    def inspect = "#<AgentSpaces::Space #{@name}>"

    # --------------------------------------------------------- observer hooks

    def unwatch(key) = @lock.synchronize { @watchers.delete(key) }

    # Stops this Space's watches and removes it from the peer's observers.
    def close
      @watchers.values.each { |w| w[3].close }
      @peer.remove_observer(self)
    end

    def watching? = !@watchers.empty?

    def mine?(dto) = (dto["record"] || {})["spaceId"] == @space_id

    def state_folded(dto)
      return unless mine?(dto)

      if dto["completed"]
        deliver(dto, COMPLETED)
      elsif Peer.present?(dto)
        deliver(dto, WRITTEN) # a withdrawn entry learned late is history, not news
      end
    end

    # EXPIRED for a cancel that withdrew an entry present here, the kind Java's
    # ReplicatedSpace and LocalSpace raise for a cancel, once per entry with the
    # sweep's (core cancel events, 2026-11-09).
    def state_withdrawn(dto)
      deliver(dto, EXPIRED) if mine?(dto)
    end

    def claim_folded(entry_id, _signed)
      dto = @peer.states[entry_id]
      return if dto.nil? || !mine?(dto) || !Peer.present?(dto)

      deliver(dto, TAKEN)
    end

    # Closes every lapsed subscription, then delivers EXPIRED once per entry
    # whose write lease lapsed while open and REAPPEARED once per lapsed
    # claim epoch on an entry still open.
    def sweep
      return if @watchers.empty?

      now = @peer.now_ms
      @watchers.values.each { |w| w[3].close("lapsed") if w[3].lapsed?(now) }
      return if @watchers.empty?

      @peer.states.to_a.each do |entry_id, dto|
        # a cancel already delivered a withdrawn entry's EXPIRED (core cancel events, 2026-11-09)
        next if !mine?(dto) || !Peer.present?(dto)

        lease = Peer.lease_of(dto)
        if lease.fetch("expiresAtMillis", 0).to_i <= now
          deliver(dto, EXPIRED)
          next
        end
        claim = @peer.claim_of(entry_id)
        deliver(dto, REAPPEARED, "#{REAPPEARED}:#{claim['epoch']}") if claim && claim.fetch("expiresAtMillis", 0).to_i <= now
      end
    end

    private

    def monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    def decode_or_nil(template, payload)
      template.decode(payload)
    rescue ArgumentError, TypeError, NoMethodError => e
      @peer.logger&.warn("agentspaces: #{template.schema} entry skipped: #{e.message}")
      nil
    end

    def deliver(dto, kind, mark = nil)
      return if @watchers.empty?

      record = dto["record"] || {}
      value = @peer.value_of(dto)
      return if value.nil?

      payload = value.first
      tags = record["tags"] || {}
      now = @peer.now_ms
      @watchers.values.each do |template, callback, delivered, subscription, wanted|
        if subscription.lapsed?(now)
          subscription.close("lapsed")
          next
        end
        next if wanted && !wanted.include?(kind)
        next unless record["type"] == template.schema && template.matches(payload, tags)

        seen = [record["entryId"], mark || kind]
        next if delivered.include?(seen)

        value = decode_or_nil(template, payload)
        next if value.nil? || !template.accepts?(value)
        # the fold and the sweep thread both deliver EXPIRED, for a cancel and for a lapse:
        # one claims the mark (core cancel events, 2026-11-09)
        next unless @lock.synchronize { delivered.add?(seen) }

        lease = Peer.lease_of(dto)
        item = Item.new(entry_id: record["entryId"], value: value, tags: tags.dup.freeze, issuer: record["issuer"],
                        expires_at_millis: lease.fetch("expiresAtMillis", 0).to_i, completed: kind == COMPLETED,
                        taken: kind == TAKEN)
        callback.call(Event.new(kind: kind, item: item))
      end
    end
  end
end
