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
  # One time source per peer (SPEC v0.1.36 §9.5; srad/agentspaces-event-loop.md
  # §3.1 and §3.6, the Ruby side of EL-C-04 and EL-C-06): wall time for what a
  # peer reads (stamps, leases, expiries, issue instants), and a monotonic
  # base for local periods (the re-lease cadence, the collection and sweep
  # deadlines, the watchdog's judgements), so a wall-clock step neither
  # fires every period at once nor holds one back.
  #
  # A time source answers:
  # - wall_ms: wall time in epoch milliseconds;
  # - mono: monotonic seconds (a Float), the base of every local period;
  # - real?: whether the clocks move by themselves, so a loop may sleep on
  #   them (a virtual source is moved by its test and runs no thread).
  module TimeSource
    # The real clocks: Time.now for the wall, CLOCK_MONOTONIC for periods.
    #
    # A wall callable (a Peer's clock:, epoch seconds; a test's TestClock)
    # makes a wall-following source, the reference implementation's
    # compatibility rule for a plain clock (srad/agentspaces-event-loop.md
    # §10.16 step 2): local periods follow that clock (held from going
    # backwards), so a test that moves it moves them as before; no wall step
    # is judged on it, no watchdog judges its loop, and its loop looks again
    # at least every MAX_WAIT_FOLLOWING seconds of real time, since the clock
    # jumps without telling anyone. A peer's waits stay on the system's
    # monotonic clock, so a pinned clock never stops one.
    class System
      MAX_WAIT_FOLLOWING = 0.25

      def initialize(wall = nil)
        @wall = wall
        @last = nil
        @lock = Mutex.new
      end

      def wall_ms = @wall.nil? ? (Time.now.to_f * 1000).to_i : (@wall.call * 1000).to_i

      def mono
        return Process.clock_gettime(Process::CLOCK_MONOTONIC) if @wall.nil?

        @lock.synchronize { @last = [@last || -Float::INFINITY, Float(@wall.call)].max }
      end

      def real? = true

      # Whether local periods follow a pinned wall clock.
      def wall_following? = !@wall.nil?

      # The longest a loop on this source sleeps (nil: its own backstop).
      def max_wait = @wall.nil? ? nil : MAX_WAIT_FOLLOWING

      def inspect = @wall.nil? ? "#<AgentSpaces::TimeSource::System>" : "#<AgentSpaces::TimeSource::System wall=pinned>"
    end

    SYSTEM = System.new

    module_function

    # The source a peer runs on: time when given, else the system's with the
    # wall clock replaced by clock when that is given.
    def of(time: nil, clock: nil)
      return time unless time.nil?

      clock.nil? ? SYSTEM : System.new(clock)
    end
  end

  # Virtual time for tests (srad/agentspaces-event-loop.md §3.1, VirtualTime):
  # both clocks stand still until the test moves them, so a test of a period,
  # a deadline, a suspend or a wall step runs in microseconds and waits for
  # nothing. A peer on virtual time starts no loop thread: the test runs its
  # due work with Peer#run_due after each move.
  #
  #   time = AgentSpaces::VirtualTime.new
  #   peer = AgentSpaces::Peer.new(identity, group, time: time)
  #   time.advance(30)       # both clocks, 30 s
  #   peer.run_due           # whatever fell due runs now
  #   time.step_wall(-300)   # an NTP step back of 5 minutes, wall only
  #   time.suspend(7200)     # a suspend as Linux counts it: the wall moves, the monotonic clock does not
  class VirtualTime
    def initialize(wall_ms: 1_767_225_600_000, mono: 1_000.0)
      @wall_ms = Integer(wall_ms)
      @mono = Float(mono)
      @lock = Mutex.new
    end

    def wall_ms = @lock.synchronize { @wall_ms }

    def mono = @lock.synchronize { @mono }

    def real? = false

    def wall_following? = false

    def max_wait = nil

    # Callable as a Peer clock: epoch seconds.
    def call = wall_ms / 1000.0

    # Moves both clocks by seconds.
    def advance(seconds)
      seconds = Float(seconds)
      raise ArgumentError, "virtual time only moves forward: #{seconds}" if seconds.negative?

      @lock.synchronize do
        @mono += seconds
        @wall_ms += (seconds * 1000).round
      end
      self
    end

    # Steps the wall clock alone, either way (an NTP step).
    def step_wall(seconds) = @lock.synchronize { @wall_ms += (Float(seconds) * 1000).round } && self

    # A suspend as Linux counts it: the wall clock moves on and the
    # monotonic clock does not (macOS counts the suspend in both; advance is
    # that case, and the loop sees it as a late wake).
    def suspend(seconds) = step_wall(seconds)

    def inspect = "#<AgentSpaces::VirtualTime wall_ms=#{wall_ms} mono=#{mono}>"
  end
end
