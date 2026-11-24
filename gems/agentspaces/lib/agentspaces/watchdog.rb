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
  # The out-of-loop liveness check (srad/agentspaces-event-loop.md §3.9,
  # EL-H-01 to EL-H-08, the Ruby equivalent): one per process, on a fixed
  # check of 2 s, started with the first watched thing and stopped with the
  # last. Each watched thing answers watchdog_check(now, grace:, wedge:,
  # judge_from:) and
  # re-initialises itself on what it finds (a NodeLoop: dead, wedged, a
  # missed wake, a missed deadline; a peer's reader: dead, or a frame
  # handler held past the wedge bound). The watchdog runs no protocol work
  # and takes no lock a duty can hold (WD-1).
  #
  # A manual watchdog (Watchdog.manual) runs no thread: a test calls check.
  # The process watchdog is itself watched: each loop turn reports to it,
  # and a watchdog thread found dead or silent for three periods is
  # restarted (EL-H-12).
  class Watchdog
    PERIOD = 2.0
    # The slack past a deadline or a wake before it counts as missed. The
    # reference implementation's is 250 ms; a Ruby thread can wait that long
    # for the interpreter lock on a busy host, so this one allows 1 s.
    GRACE = 1.0
    WEDGE = 5.0
    ESCALATE_AFTER = 3
    ESCALATE_WINDOW = 600.0

    attr_reader :period, :grace, :wedge, :checks, :restarts

    @system_lock = Mutex.new
    class << self
      # The process watchdog (one per process, made again after a fork).
      def system
        @system_lock.synchronize do
          @system = nil if @system_pid != Process.pid
          @system_pid = Process.pid
          @system ||= new(TimeSource::SYSTEM, threaded: true)
        end
      end

      # A watchdog with no thread, judged by the test on its own time source.
      def manual(time, **bounds) = new(time, threaded: false, **bounds)
    end

    def initialize(time, threaded:, period: PERIOD, grace: GRACE, wedge: WEDGE)
      @time = time
      @threaded = threaded
      @period = Float(period)
      @grace = Float(grace)
      @wedge = Float(wedge)
      @watched = []
      @lock = Mutex.new
      @thread = nil
      @stop = nil
      @checks = 0
      @heartbeat = nil
      @restarts = 0
      @findings = Hash.new(0)
      @late_checks = 0
      @last_late = false
      @judge_from = nil
    end

    def register(watched)
      @lock.synchronize do
        @watched << watched unless @watched.include?(watched)
        start_thread if @threaded && (@thread.nil? || !@thread.alive?)
      end
      self
    end

    def unregister(watched)
      stop = nil
      @lock.synchronize do
        @watched.delete(watched)
        if @watched.empty? && @thread
          stop = @stop
          @thread = nil
        end
      end
      stop&.push(:stop)
      self
    end

    def watching = @lock.synchronize { @watched.dup }

    # Checks that began more than the grace after their park ended.
    attr_reader :late_checks

    # One check of everything watched at now; returns the findings as
    # [watched, detection] pairs. late is how long after its park ended the
    # check began (the threaded watchdog measures it; a test passes it).
    # Past the grace, after a check that was on time, the process was
    # paused (a laptop sleep, which macOS's monotonic clock counts, a frozen
    # container, a debugger): the loops could not run either, so every age
    # this check and later ones judge counts from this check at the earliest.
    # Lateness on consecutive checks is load and moves nothing, and the start
    # moves at most once per wedge bound (Java's Watchdog.check, §10.10 of
    # the event-loop record). A dead thread is judged regardless.
    def check(now = @time.mono, late: 0.0)
      @heartbeat = now
      @checks += 1
      paused = late > @grace
      if paused
        @late_checks += 1
        @judge_from = now if !@last_late && (@judge_from.nil? || now - @judge_from >= @wedge)
      end
      @last_late = paused
      found = []
      watching.each do |watched|
        detection = watched.watchdog_check(now, grace: @grace, wedge: @wedge, judge_from: @judge_from)
        next if detection.nil?

        @findings[detection] += 1
        found << [watched, detection]
      rescue StandardError => e
        warn "agentspaces: the watchdog's check of #{watched.inspect} raised #{e.class}: #{e.message}"
      end
      found
    end

    # Detections by kind since the process started.
    def findings = @findings.dup

    # A loop turn reports here; a threaded watchdog dead or silent for three
    # periods is started again.
    def heartbeat_seen(now)
      return unless @threaded

      stale = @heartbeat && now - @heartbeat > 3 * @period
      dead = !@thread.nil? && !@thread.alive?
      return unless stale || dead

      @lock.synchronize do
        next if @watched.empty?

        @restarts += 1
        @stop&.push(:stop)
        start_thread
      end
    end

    def inspect = "#<AgentSpaces::Watchdog watching=#{@watched.size} checks=#{@checks}>"

    private

    def start_thread
      stop = Thread::Queue.new
      @stop = stop
      @heartbeat = @time.mono
      @thread = Thread.new do
        Thread.current.report_on_exception = false
        loop do
          parked = @time.mono
          break unless stop.pop(timeout: @period).nil?

          now = @time.mono
          check(now, late: [now - parked - @period, 0.0].max)
        end
      end
      @thread.name = "agentspaces-watchdog"
    end
  end
end
