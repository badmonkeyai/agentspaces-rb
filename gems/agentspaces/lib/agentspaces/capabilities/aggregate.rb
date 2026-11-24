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
  module Capabilities
    # When an estimate counts as settled: unchanged within a relative
    # tolerance for ticks consecutive gossip rounds of Aggregate::ROUND_PERIOD
    # (about a second each, as Java's PushSumAggregate.Settle since SPEC
    # v0.1.36 §8 and §9.5); Settle::FIRST is the first estimate present.
    Settle = Data.define(:ticks, :tolerance) do
      def initialize(ticks: 0, tolerance: 0.0)
        ticks = Integer(ticks)
        tolerance = Float(tolerance)
        raise ArgumentError, "ticks and tolerance are not negative" if ticks.negative? || tolerance.negative?

        super(ticks: ticks, tolerance: tolerance)
      end

      # after(8, t) counts eight rounds; after("PT8S", t), after("8s", t) or
      # after(8.0, t) is the same rule in time: the span in rounds of
      # ROUND_PERIOD, rounded up (Java's Settle.after(Duration, double)).
      def self.after(ticks_or_span, tolerance)
        return new(ticks: ticks_or_span, tolerance: tolerance) if ticks_or_span.is_a?(Integer)

        span(ticks_or_span, tolerance)
      end

      # A settle rule in time: the estimate unchanged for span (a duration as
      # Durations reads it), counted in rounds of ROUND_PERIOD, rounded up.
      def self.span(span, tolerance)
        millis = Durations.millis(span)
        raise ArgumentError, "a settle span is not negative: #{span.inspect}" if millis.negative?

        round = (Aggregate::ROUND_PERIOD * 1000).round
        new(ticks: (millis + round - 1) / round, tolerance: tolerance)
      end

      # How long the rule asks an estimate to stay unchanged, in seconds.
      def span_seconds = ticks * Aggregate::ROUND_PERIOD

      # Whether current is within the tolerance of previous, relative to the larger.
      def stable?(previous, current)
        return false if previous.nil?

        scale = [previous.abs, current.abs, 1e-12].max
        (current - previous).abs <= tolerance * scale
      end
    end
    Settle::FIRST = Settle.new(ticks: 0, tolerance: 0.0)

    # One settled estimate, as an on_estimate listener receives it.
    Estimate = Data.define(:epoch_id, :mode, :value, :ticks)

    # The push-sum aggregate (SPEC 8.2, PushSumAggregate): AVG by push-sum,
    # SUM and COUNT by the gossiped roster, MIN and MAX by extremum frames;
    # estimates, settle rules, and estimate listeners. One node's share of
    # every epoch it joined or heard about.
    #
    #   aggregate = Aggregate.new(pipes)
    #   aggregate.start("load", 12.5)
    #   aggregate.run                                 # one round a second on a thread
    #   value = aggregate.await_settled("load", Settle.after("PT3S", 0.01), timeout_seconds: 20)
    class Aggregate
      TYPE = "aspace:cap/aggregate"
      MODES = %w[avg sum count min max].freeze
      # One gossip round (Java's PushSumAggregate.ROUND_PERIOD since SPEC
      # v0.1.36): a settle rule's ticks are rounds of this length.
      ROUND_PERIOD = 1.0
      # An epoch neither started here nor heard from for this long is quiet,
      # as Java's push-sum epoch going quiet (SPEC 9.5: 30 s): with every
      # epoch quiet and no watch waiting, the round thread sleeps until a
      # frame, a start or a watch wakes it.
      QUIET_AFTER = 30.0
      # How often this node's aggregate card is published again (the card
      # refresh Java's static providers live on: 5 minutes, half and more
      # inside the card's 15 minutes).
      CARD_REFRESH = 300.0

      attr_reader :pipes, :self_token
      attr_accessor :exchanged

      def initialize(pipes, advertise: true)
        @pipes = pipes
        @self_token = Wire.aggregate_roster_token(pipes.peer.identity.peer_id)
        @received = {}  # epoch => frames heard, the settle evidence
        @epochs = {}    # epoch => [value, weight]
        @rosters = {}   # epoch => Set of roster tokens
        @extrema = {}   # epoch => [max?, value]
        @declared = {}
        @ticks = {}
        @watches = []
        @heard_at = {} # epoch => monotonic seconds of its last frame or start
        @lock = Mutex.new
        @wake = Thread::Queue.new
        @thread = nil
        @running = false
        @exchanged = false
        pipes.on_capability(TYPE, method(:on_frame))
        return unless advertise && pipes.peer.respond_to?(:publish_ad)

        advertise!
        # The card (PT15M) is renewed on the card refresh while the
        # aggregate runs, and at once after a suspend, by the peer's loop: a
        # member pushes shares only to a member whose card is live.
        @kept_card = pipes.peer.keep_card(CARD_REFRESH) { advertise! } if pipes.peer.respond_to?(:keep_card)
      end

      # ---------------------------------------------------------- participants

      # This node's CapabilityAdvertisement for the aggregate, in Java field
      # order (CapabilityAdvertisement: id, issuer, group, issued, ttl,
      # capabilityType, version, binding, parameters, costHints).
      def describe
        peer = @pipes.peer
        now = peer.now_ms
        { "id" => "aspace://#{peer.group}/cap/aggregate/#{peer.identity.peer_id}",
          "issuer" => peer.identity.peer_id, "group" => peer.group,
          "issued" => Instants.iso(now - (now % 1000)), "ttl" => "PT15M",
          "capabilityType" => TYPE, "version" => "0.1", "binding" => "pipe",
          "parameters" => CBOR.canonical_map({ "modes" => "sum,avg,count,min,max" }), "costHints" => {} }
      end

      # Publishes the advertisement on the ads stream, so other members'
      # participant rules admit this node (re-publish within the TTL).
      def advertise! = @pipes.peer.publish_ad("CapabilityAdvertisement", describe)
      alias advertise advertise!

      # The reachable members that advertise the aggregate. A share pushed to
      # a member without one is mass lost (the receiver never mixes it back),
      # so a share goes only to a member whose advertisement is live.
      def participants
        peer = @pipes.peer
        now = peer.now_ms
        advertised = peer.ads.values.filter_map do |e|
          e["issuer"] if e["type"] == "CapabilityAdvertisement" && e["expires"] > now &&
                         e["ad"]["capabilityType"] == TYPE
        end
        @pipes.members.select { |m| advertised.include?(m) }
      end

      # --------------------------------------------------------------- joining

      # Joins an epoch with this node's value under mode.
      def start(epoch_id, value, mode = "avg")
        mode = mode.to_s.downcase
        raise ArgumentError, "unknown mode #{mode.inspect}; use one of #{MODES.join(', ')}" unless MODES.include?(mode)

        value = Float(value)
        @lock.synchronize do
          @heard_at[epoch_id] = mono
          @declared[epoch_id] = mode
          if %w[avg sum].include?(mode)
            e = (@epochs[epoch_id] ||= [0.0, 0.0])
            e[0] += value
            e[1] += 1.0
          end
          (@rosters[epoch_id] ||= Set.new) << @self_token if %w[sum count].include?(mode)
          merge_extremum(epoch_id, mode == "max", value) if %w[min max].include?(mode)
        end
        @wake << true
        nil
      end

      # The epochs this node joined or heard about.
      def epochs = @lock.synchronize { known_epochs }

      # ------------------------------------------------------------------ tick

      # One protocol round: halve each push-sum mass and push the other half
      # to one sampled participant; push each roster and extremum whole. A
      # node with no participant holds its mass and, with nobody to exchange
      # with at all, judges its settle rules on its own ticks.
      def tick
        @exchanged = true
        target = @pipes.sample(participants)
        if target.nil?
          # Mass held is mass kept: halve only when a participant takes the other half.
          evaluate_watches(alone: @pipes.members.empty?)
          return
        end
        frames = @lock.synchronize do
          out = []
          @epochs.each do |epoch_id, e|
            e[0] /= 2
            e[1] /= 2
            out << Wire.aggregate_frame(share: { "epochId" => epoch_id, "value" => Float(e[0]),
                                                 "weight" => Float(e[1]) })
          end
          @extrema.each do |epoch_id, ex|
            next if ex[1].nan?

            out << Wire.aggregate_frame(extremum: { "epochId" => epoch_id, "max" => ex[0], "value" => Float(ex[1]) })
          end
          @rosters.each do |epoch_id, members|
            out << Wire.aggregate_frame(roster: { "epochId" => epoch_id, "members" => members.to_a.sort })
          end
          out
        end
        frames.each { |frame| @pipes.send_pipe(target, TYPE, CBOR.dump(frame)) }
        evaluate_watches(alone: false)
      end

      # A tick for a node that cannot exchange: marks the node exchanged so
      # its own value is the estimate (Java's tick does the same).
      def tick_alone = @exchanged = true

      # Runs a round every interval_seconds (ROUND_PERIOD by default) on a
      # thread until close, while any epoch is active or a watch waits; with
      # everything quiet the thread sleeps until a frame, a start or a new
      # watch wakes it (SPEC 9.5: rounds at deadlines, no fixed-rate tick).
      def run(interval_seconds: ROUND_PERIOD)
        return if @thread

        @running = true
        @thread = Thread.new do
          Thread.current.name = "aggregate-round"
          while @running && @pipes.peer.connected?
            busy = active?
            tick if busy
            break unless @running

            @wake.pop(timeout: busy ? interval_seconds : nil)
            @wake.clear
          end
        end
        @thread.report_on_exception = false
        nil
      end

      # Whether a round is worth running: an epoch started or heard within
      # QUIET_AFTER, or a watch still waiting on an epoch.
      def active?
        now = mono
        @lock.synchronize do
          @heard_at.any? { |_, at| now - at < QUIET_AFTER } ||
            @watches.any? { |w| w[:tracks].empty? || w[:tracks].values.any? { |t| !t[:fired] } }
        end
      end

      def close
        @kept_card&.close
        @running = false
        @wake << true
        @thread&.join(2)
        @thread = nil
      end

      # -------------------------------------------------------------- estimate

      # The current estimate under the declared mode (AVG for epochs only
      # heard about), a Float, or nil before any exchange.
      def estimate(epoch_id)
        @lock.synchronize do
          case @declared.fetch(epoch_id, "avg")
          when "avg" then mean(epoch_id)
          when "sum"
            average = mean(epoch_id)
            n = (@rosters[epoch_id] || []).size
            average.nil? || n.zero? ? nil : average * n
          when "count"
            n = (@rosters[epoch_id] || []).size
            n.zero? ? nil : Float(n)
          else
            ex = @extrema[epoch_id]
            ex.nil? || ex[1].nan? ? nil : ex[1]
          end
        end
      end

      # Blocks until the epoch's estimate settles under the rule, on the
      # protocol tick; the value, or nil at the timeout.
      def await_settled(epoch_id, settle = Settle::FIRST, timeout_seconds: 30.0)
        queue = Thread::Queue.new
        closer = on_estimate(->(e) { e == epoch_id }, settle) { |estimate| queue << estimate.value }
        begin
          queue.pop(timeout: timeout_seconds)
        ensure
          closer.call
        end
      end

      # Calls the listener (a callable or the block) once per matching epoch
      # when its estimate has settled under the rule, evaluated on the tick,
      # on a thread of its own. epochs is a callable over the epoch id.
      # Returns a callable that closes the watch.
      def on_estimate(epochs, settle = Settle::FIRST, listener = nil, &block)
        listener ||= block
        raise ArgumentError, "on_estimate needs a listener or a block" if listener.nil?

        watch = { epochs: epochs, settle: settle, listener: listener, tracks: {} }
        @lock.synchronize { @watches << watch }
        @wake << true
        -> { @lock.synchronize { @watches.delete_if { |w| w.equal?(watch) } } && nil }
      end

      def inspect = "#<AgentSpaces::Capabilities::Aggregate #{@pipes.peer.identity.peer_id}>"

      private

      def mean(epoch_id)
        e = @epochs[epoch_id]
        return nil if e.nil? || e[1].zero? || !@exchanged

        e[0] / e[1]
      end

      def known_epochs = Set.new(@epochs.keys) | @rosters.keys | @extrema.keys | @declared.keys

      # The monotonic base of the round and the quiet span: the peer's time
      # source when it has one.
      def mono
        peer = @pipes.peer
        peer.respond_to?(:time) && peer.time ? peer.time.mono : Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      # A tick counts toward a settle rule only when this node heard a frame
      # for the epoch since the track last judged it: halving keeps the local
      # ratio, so a node nobody pushes to is stable by construction and says
      # nothing about the fleet. A node with nobody to exchange with judges
      # every tick, its own value being the only estimate there is. An epoch
      # heard and then quiet for as long as the rule's span settles with no
      # further frame (Java's EL-T-16: at its last move plus the settle span),
      # so a watch here never waits on members that went quiet.
      def evaluate_watches(alone: false)
        epoch_ids, watches, heard = @lock.synchronize { [known_epochs.to_a, @watches.dup, @heard_at.dup] }
        clock = mono
        epoch_ids.each do |epoch_id|
          ticks = @ticks[epoch_id] = @ticks.fetch(epoch_id, 0) + 1
          now = estimate(epoch_id)
          receipts = @lock.synchronize { @received.fetch(epoch_id, 0) }
          watches.each do |watch|
            next unless watch[:epochs].call(epoch_id)

            track = (watch[:tracks][epoch_id] ||= { last: nil, stable: 0, fired: false, seen: 0 })
            next if track[:fired] || now.nil?

            settle = watch[:settle]
            quiet = receipts.positive? && receipts <= track[:seen] && heard.key?(epoch_id) &&
                    clock - heard[epoch_id] >= settle.span_seconds && settle.stable?(track[:last], now)
            # No new evidence: the streak neither grows nor resets, unless the epoch went quiet.
            next if receipts <= track[:seen] && !alone && !quiet

            track[:seen] = receipts
            track[:stable] = settle.stable?(track[:last], now) ? track[:stable] + 1 : 0
            track[:last] = now
            next unless track[:stable] >= settle.ticks || quiet

            track[:fired] = true
            estimate = Estimate.new(epoch_id: epoch_id, mode: @declared.fetch(epoch_id, "avg"), value: now,
                                    ticks: ticks)
            listener = watch[:listener]
            thread = Thread.new { listener.call(estimate) }
            thread.report_on_exception = false
          end
        end
      end

      # Called under the lock.
      def merge_extremum(epoch_id, is_max, value)
        ex = (@extrema[epoch_id] ||= [is_max, Float::NAN])
        ex[1] = value if ex[1].nan? || (ex[0] ? value > ex[1] : value < ex[1])
      end

      # HLC round seven, 2026-11-08: a frame decodes as Java's fromWire reads
      # it, under its annex I schema and the canonical-bytes rule, or it is
      # dropped unheard.
      def on_frame(_sender, payload)
        frame = begin
          Schema.load("PushSumAggregate.Frame", payload)
        rescue CBOR::Error
          return
        end

        @exchanged = true
        @wake << true
        share = frame["share"]
        extremum = frame["extremum"]
        roster = frame["roster"]
        heard = [share, extremum, roster, frame["histogram"]].find do |part|
          part.is_a?(Hash) && part["epochId"].is_a?(String)
        end&.fetch("epochId")
        @lock.synchronize do
          unless heard.nil?
            @received[heard] = @received.fetch(heard, 0) + 1
            @heard_at[heard] = mono
          end
          if share.is_a?(Hash) && share["epochId"].is_a?(String)
            value = share["value"]
            weight = share["weight"]
            if value.finite? && weight.finite? && weight >= 0.0
              e = (@epochs[share["epochId"]] ||= [0.0, 0.0])
              e[0] += value
              e[1] += weight
            end
          elsif extremum.is_a?(Hash) && extremum["epochId"].is_a?(String)
            merge_extremum(extremum["epochId"], extremum["max"], extremum["value"])
          elsif roster.is_a?(Hash) && roster["epochId"].is_a?(String) && !roster["members"].nil?
            (@rosters[roster["epochId"]] ||= Set.new).merge(roster["members"])
          end
        end
      end
    end
  end
end
