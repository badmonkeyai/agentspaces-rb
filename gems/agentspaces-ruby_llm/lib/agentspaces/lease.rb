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

require "agentspaces"

module AgentSpaces
  # Lease keepalive (SRAD RB-L-02): renews a take's lease on a timer thread
  # while a block runs, so a long model call inside a verb body keeps its
  # entry. The keepalive stops when the block returns or raises; a renewal
  # that fails is raised in the caller once the block finishes.
  #
  # every defaults to half the take's lease, as the Java binder renews a
  # held take (SPEC 9.5: a lease about 1.5 times the cycle that renews it or
  # more). A cycle no shorter than the lease could never renew in time and is
  # refused; one that leaves less than that margin is warned about.
  module Lease
    module_function

    def keepalive(taken = TakeContext.current, every: nil)
      raise ArgumentError, "keepalive needs a take; call it inside a take body or pass one" if taken.nil?

      lease = taken.respond_to?(:lease_millis) ? taken.lease_millis : nil
      seconds = every.nil? ? lease.to_f / 2000.0 : Durations.seconds(every)
      raise ArgumentError, "keepalive needs every: when the take names no lease" unless seconds.positive?
      if lease && seconds * 1000 >= lease
        raise ArgumentError, "a renewal every #{seconds} s cannot keep a #{lease} ms lease: it lapses first"
      end
      if lease && seconds * 1000 * TtlFloor::CYCLE_MARGIN > lease
        warn "agentspaces: a renewal every #{seconds} s leaves the #{lease} ms lease less than " \
             "#{TtlFloor::CYCLE_MARGIN} times its cycle; one late renewal lets it lapse"
      end
      stop = Thread::Queue.new
      failure = nil
      # C05 (owner decisions 5 and 2 of 2026-11-23): a take found lapsed (its
      # claim no longer its own, or its wall-time lease ended) stops renewing
      # at once, not at the next cycle, and the block's result is late: the
      # lapse is raised once the block finishes.
      taken.on_lapse { stop << :lapsed } if taken.respond_to?(:on_lapse)
      # A wake whose lease still holds renews at once: the cycle's wait runs
      # on a monotonic clock that did not count the sleep, so it would come
      # late on the wall-time lease.
      unwake = taken.on_wake { stop << :wake } if taken.respond_to?(:on_wake)
      renewer = Thread.new do
        loop do
          signal = stop.pop(timeout: seconds)
          if signal == :lapsed
            failure = ArgumentError.new("the take of #{taken.entry_id} lapsed (its claim is no longer this " \
                                        "take's, or its lease ended): its result is late")
            break
          end
          break if signal && signal != :wake

          taken.renew
        rescue StandardError => e
          failure = e
          break
        end
      end
      renewer.report_on_exception = false
      result = yield taken
      stop << :done
      renewer.join
      raise failure if failure

      result
    ensure
      unwake&.call
      stop << :done if stop
      renewer&.join(1)
    end
  end
end
