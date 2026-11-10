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
    # tolerance for ticks consecutive ticks; Settle::FIRST is the first
    # estimate present.
    Settle = Data.define(:ticks, :tolerance) do
      def initialize(ticks: 0, tolerance: 0.0)
        ticks = Integer(ticks)
        tolerance = Float(tolerance)
        raise ArgumentError, "ticks and tolerance are not negative" if ticks.negative? || tolerance.negative?

        super(ticks: ticks, tolerance: tolerance)
      end

      def self.after(ticks, tolerance) = new(ticks: ticks, tolerance: tolerance)

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
    #   aggregate.run(interval_seconds: 0.3)          # ticks on a thread
    #   value = aggregate.await_settled("load", Settle.after(3, 0.01), timeout_seconds: 20)
    class Aggregate
      TYPE = "aspace:cap/aggregate"
      MODES = %w[avg sum count min max].freeze

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
        @lock = Mutex.new
        @thread = nil
        @running = false
        @exchanged = false
        pipes.on_capability(TYPE, method(:on_frame))
        advertise! if advertise && pipes.peer.respond_to?(:publish_ad)
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
          @declared[epoch_id] = mode
          if %w[avg sum].include?(mode)
            e = (@epochs[epoch_id] ||= [0.0, 0.0])
            e[0] += value
            e[1] += 1.0
          end
          (@rosters[epoch_id] ||= Set.new) << @self_token if %w[sum count].include?(mode)
          merge_extremum(epoch_id, mode == "max", value) if %w[min max].include?(mode)
        end
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

      # Ticks on a thread until close.
      def run(interval_seconds: 0.3)
        return if @thread

        @running = true
        @thread = Thread.new do
          Thread.current.name = "aggregate-tick"
          while @running && @pipes.peer.connected?
            tick
            sleep(interval_seconds)
          end
        end
        @thread.report_on_exception = false
        nil
      end

      def close
        @running = false
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

      # A tick counts toward a settle rule only when this node heard a frame
      # for the epoch since the track last judged it: halving keeps the local
      # ratio, so a node nobody pushes to is stable by construction and says
      # nothing about the fleet. A node with nobody to exchange with judges
      # every tick, its own value being the only estimate there is.
      def evaluate_watches(alone: false)
        epoch_ids, watches = @lock.synchronize { [known_epochs.to_a, @watches.dup] }
        epoch_ids.each do |epoch_id|
          ticks = @ticks[epoch_id] = @ticks.fetch(epoch_id, 0) + 1
          now = estimate(epoch_id)
          receipts = @lock.synchronize { @received.fetch(epoch_id, 0) }
          watches.each do |watch|
            next unless watch[:epochs].call(epoch_id)

            track = (watch[:tracks][epoch_id] ||= { last: nil, stable: 0, fired: false, seen: 0 })
            next if track[:fired] || now.nil?
            # No new evidence: the streak neither grows nor resets.
            next if receipts <= track[:seen] && !alone

            track[:seen] = receipts
            settle = watch[:settle]
            track[:stable] = settle.stable?(track[:last], now) ? track[:stable] + 1 : 0
            track[:last] = now
            next unless track[:stable] >= settle.ticks

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
        share = frame["share"]
        extremum = frame["extremum"]
        roster = frame["roster"]
        heard = [share, extremum, roster, frame["histogram"]].find do |part|
          part.is_a?(Hash) && part["epochId"].is_a?(String)
        end&.fetch("epochId")
        @lock.synchronize do
          @received[heard] = @received.fetch(heard, 0) + 1 unless heard.nil?
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
