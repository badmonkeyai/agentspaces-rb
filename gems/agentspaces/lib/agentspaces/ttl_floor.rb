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
  # A configured TTL under the floor with no override, refused under strict.
  class TtlFloorError < ArgumentError; end

  # The start-up check of configured TTLs, leases and expiries (SPEC v0.1.36
  # §9.5, TTLs; srad/agentspaces-event-loop.md §3.11, EL-E-03, EL-E-04: the
  # Ruby twin of Java's TtlFloor). Principle 8: "TTLs need to be generous;
  # any TTL under 60 s is probably too fast, unless someone really knows what
  # they are doing."
  #
  # - A value equal to its registered default passes silently.
  # - A key with an expert override (a reason) passes, logged once.
  # - Any other value under 60 s logs a warning naming the key, the value and
  #   the principle, or raises TtlFloorError under strict.
  # - check_cycle applies the owner's rule beside it: a TTL that something
  #   renews should be about 1.5 times the cycle that renews it; one shorter
  #   warns (or raises under strict) unless an override names it.
  #
  # Keys read as an operator writes them (agentspaces.card-refresh-millis)
  # or as the binder names a clause (binder.<AgentClass>.<method>.<option>).
  # Configuration: agentspaces.ttl.strict and agentspaces.ttl.expert-overrides
  # (a map of key to reason); a binder clause takes ttl_override: "<reason>".
  class TtlFloor
    FLOOR_MILLIS = 60_000
    # How far a TTL should exceed the cycle that renews it.
    CYCLE_MARGIN = 1.5

    Finding = Data.define(:key, :millis, :verdict, :reason)

    attr_reader :strict, :overrides

    def self.lenient(logger: nil) = new(logger: logger)

    def initialize(strict: false, overrides: {}, logger: nil)
      overrides = (overrides || {}).to_h { |k, v| [k.to_s, v] }
      overrides.each do |key, reason|
        if reason.nil? || reason.to_s.strip.empty?
          raise ArgumentError, "the expert override of #{key} names no reason (principle 8: the reason is the point)"
        end
      end
      @strict = strict == true
      @overrides = overrides.freeze
      @logger = logger
      @findings = []
      @told = Set.new
      @lock = Mutex.new
    end

    attr_writer :logger

    # Checks one configured value in milliseconds (nil passes).
    def check(key, millis, registered_default: nil, override_reason: nil)
      return if millis.nil? || millis == registered_default
      return if overridden?(key, millis, override_reason)
      return if millis >= FLOOR_MILLIS

      refuse_or_warn(key, millis, "#{key}=#{millis} ms is under 60 s. Principle 8 (SPEC 9.5; " \
                                  "srad/agentspaces-event-loop.md 3.11): TTLs need to be generous, and one under " \
                                  "60 s is probably too fast unless someone really knows what they are doing; name " \
                                  "the reason in agentspaces.ttl.expert-overrides[#{key}] (or ttl_override: beside " \
                                  "a binder clause)")
    end

    # Checks a TTL against the cycle that renews it (both in milliseconds).
    def check_cycle(key, ttl_millis, cycle_millis, override_reason: nil)
      return if ttl_millis.nil? || cycle_millis.nil? || ttl_millis >= CYCLE_MARGIN * cycle_millis
      return if overridden?(key, cycle_millis, override_reason)

      refuse_or_warn(key, cycle_millis, "#{key}: a renewal every #{cycle_millis} ms leaves a #{ttl_millis} ms TTL " \
                                        "less than #{CYCLE_MARGIN} times its cycle, so one late renewal lets it " \
                                        "lapse (SPEC 9.5: a TTL about 1.5 times the cycle that renews it)")
    end

    # What the check found so far, oldest first.
    def findings = @lock.synchronize { @findings.dup }

    private

    def overridden?(key, millis, override_reason)
      reason = override_reason.to_s.strip.empty? ? @overrides[key] : override_reason
      return false if reason.nil?

      if tell?(key)
        @logger&.info("agentspaces: TTL expert override: #{key}=#{millis} ms (#{reason})")
        record(Finding.new(key: key, millis: millis, verdict: :overridden, reason: reason.to_s))
      end
      true
    end

    def refuse_or_warn(key, millis, message)
      if @strict
        record(Finding.new(key: key, millis: millis, verdict: :refused, reason: ""))
        raise TtlFloorError, "#{message}, or turn agentspaces.ttl.strict off"
      end
      return unless tell?(key)

      @logger&.warn("agentspaces: #{message}")
      record(Finding.new(key: key, millis: millis, verdict: :warned, reason: ""))
    end

    def tell?(key) = @lock.synchronize { @told.add?(key) ? true : false }

    def record(finding) = @lock.synchronize { @findings << finding }
  end
end
