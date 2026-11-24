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
  # A peer's loop of due work (SPEC v0.1.36 §9.5; srad/agentspaces-event-loop.md
  # §3.2 and §3.3, the Ruby side of EL-P-09): each duty runs when its deadline
  # falls due or when something asks it, and returns its next deadline; the
  # loop sleeps in between, so an idle peer wakes only for real deadlines and
  # the backstop. It replaces the 0.25 s ticker and the 0.25 s sweep loop.
  #
  # The shape is a sequential process (CSP): one thread that selects over a
  # wake channel (a Thread::Queue) and its timer (the pop's timeout), never
  # an actor. Asking a duty sets its flag and sends one token on the channel.
  #
  # A duty is a block over now (monotonic seconds) that returns its next due
  # time on the same base, or nil for "only when asked". A run that is not
  # due does nothing (DW-1), so the backstop and an early wake are always
  # safe. A duty that raises three runs in a row is backed off from 1 s,
  # doubling to the backstop (a :protocol duty never past 1 s), and the loop
  # reads :degraded until it runs clean (EL-H-07).
  #
  # The watchdog (Watchdog) judges the loop from outside: a dead thread, a
  # run wedged past its bound, a wake or a deadline missed past its grace.
  # It re-initialises the loop: a new generation on a new thread, every duty
  # asked once, a wedged duty fenced until its old run returns, nothing
  # queued lost (EL-H-04, EL-H-05). Three re-initialisations in ten minutes
  # escalate: health :down, logged, and every health listener told (EL-H-08).
  #
  # On a virtual time source (VirtualTime) the loop starts no thread: a test
  # calls run_due, or advance, which runs every deadline at its own instant.
  class NodeLoop
    # The longest the loop sleeps whatever its next due (decision 3: the
    # reference implementation's backstop after its phase-6 audit). A
    # backstop run asks every duty once.
    BACKSTOP = 15.0
    # A duty that raises this many runs in a row is backed off.
    THROWS_BEFORE_BACKOFF = 3
    # A run past this long is slow: counted and named, not a detection.
    SLOW_RUN = 0.1

    Duty = Struct.new(:name, :kind, :block, :due, :asked, :throws, :backoff, :held_until, :in_run, :runs, :slow,
                      :last_error, keyword_init: true)

    attr_reader :name, :time, :generation, :runs, :wakes, :timer_wakes, :backstop_runs, :throws_total, :reinits,
                :run_started_at, :running_duty, :armed_at, :wake_raised_at, :thread, :escalated, :detections
    attr_accessor :on_turn, :logger, :watchdog

    def initialize(name, time:, logger: nil, backstop: BACKSTOP)
      @name = name
      @time = time
      @logger = logger
      @backstop = [Float(backstop), time.respond_to?(:max_wait) ? time.max_wait : nil].compact.min
      @duties = {}
      @lock = Mutex.new
      @wake_channel = Thread::Queue.new
      @generation = 0
      @runs = 0
      @wakes = 0
      @timer_wakes = 0
      @backstop_runs = 0
      @backstop_at = nil
      @throws_total = 0
      @reinits = []
      @detections = Hash.new(0)
      @run_started_at = nil
      @running_duty = nil
      @armed_at = nil
      @wake_raised_at = nil
      @thread = nil
      @started = false
      @stopping = false
      @escalated = nil
      @health_listeners = []
      @last_health = :ok
      @on_turn = nil
    end

    # Registers a duty. kind :protocol marks a duty whose deadline a peer
    # reads on the wire (the keepalive): it is never backed off past 1 s.
    # The block receives now (monotonic seconds) and returns the next due
    # time, or nil to wait to be asked. The duty is asked once at once.
    def duty(name, kind: :local, &block)
      raise ArgumentError, "a duty needs a block" if block.nil?

      @lock.synchronize do
        @duties[name] = Duty.new(name: name, kind: kind, block: block, due: nil, asked: true, throws: 0, backoff: 0.0,
                                 held_until: nil, in_run: false, runs: 0, slow: 0, last_error: nil)
      end
      signal
      self
    end

    def duty_names = @lock.synchronize { @duties.keys }

    # The next due time of one duty (monotonic seconds), or nil.
    def due_of(name) = @lock.synchronize { @duties[name]&.due }

    # Asks one duty (or every duty) to run at the next turn.
    def wake(name = nil)
      @lock.synchronize do
        if name.nil?
          @duties.each_value { |d| d.asked = true }
        elsif (d = @duties[name])
          d.asked = true
        else
          return self
        end
        @wake_raised_at ||= @time.mono
      end
      signal
      self
    end

    # Runs every duty asked or due at now, once, in registration order, and
    # returns the earliest next due (or nil). Serial within a generation: a
    # run of an older generation stops before its next duty (WD-3).
    def run_due(now = @time.mono, generation = @generation)
      late = @armed_at.nil? ? 0.0 : now - @armed_at
      # A backstop has passed since the last sweep: every duty is asked, as
      # Java's NodeLoop sweeps (sweep = now - backstopAt >= 0), whatever else
      # is due meanwhile; a run that is not due does nothing (DW-1), so only
      # a duty whose own judgement finds work acts, and a change that asked
      # nobody is caught here at the latest, however busy another duty keeps
      # the loop.
      sweep = @backstop_at.nil? || now >= @backstop_at
      @on_turn&.call(now, late)
      @lock.synchronize do
        @runs += 1
        @backstop_runs += 1 if sweep && !@backstop_at.nil?
        @duties.each_value { |d| d.asked = true } if sweep
        @wake_raised_at = nil
      end
      @backstop_at = now + @backstop if sweep
      @duties.values.each do |duty|
        break unless generation == @generation

        run_duty(duty, now, generation) if claim(duty, now)
      end
      next_due = earliest_due
      @armed_at = next_due.nil? ? @backstop_at : [next_due, @backstop_at].min
      next_due
    end

    # On a virtual source: moves time by seconds, running every deadline at
    # its own instant on the way, as the loop thread would on real time.
    def advance(seconds)
      raise ArgumentError, "advance drives a virtual time source" if @time.real?

      remaining = Float(seconds)
      run_due if @armed_at.nil?
      spins = 0
      while remaining.positive?
        step = [[@armed_at - @time.mono, 0.0].max, remaining].min
        spins = step.zero? ? spins + 1 : 0
        raise "loop #{@name}: a duty is due again at once, #{spins} runs without time passing" if spins > 1000

        @time.advance(step)
        remaining -= step
        run_due
      end
      self
    end

    # Starts the loop's thread (on a real time source only).
    def start
      return self unless @time.real?

      @lock.synchronize do
        return self if @started

        @started = true
        @stopping = false
      end
      spawn_thread(@generation)
      self
    end

    def started? = @started && !@stopping

    def stop
      @stopping = true
      @started = false
      signal
      thread = @thread
      thread&.join(2) unless thread == Thread.current
      @thread = nil
      self
    end

    # --------------------------------------------------------------- health

    # :ok, :degraded (a duty backed off) or :down (escalated), with reasons.
    def health
      reasons = []
      backed = @lock.synchronize { @duties.values.select { |d| d.throws >= THROWS_BEFORE_BACKOFF } }
      backed.each { |d| reasons << "duty #{d.name} backed off after #{d.throws} throws (#{d.last_error})" }
      return { state: :down, reasons: [@escalated] + reasons } if @escalated
      return { state: :degraded, reasons: reasons } unless reasons.empty?

      { state: :ok, reasons: [] }
    end

    # Calls listener with each change of health (a Hash as health returns).
    def on_health(&listener) = @lock.synchronize { @health_listeners << listener } && self

    # Counters for operators and tests.
    def stats
      @lock.synchronize do
        { runs: @runs, wakes: @wakes, timer_wakes: @timer_wakes, generation: @generation,
          throws: @throws_total, reinits: @reinits.size, detections: @detections.dup,
          backstop_runs: @backstop_runs,
          slow: @duties.transform_values(&:slow).reject { |_, v| v.zero? },
          duties: @duties.transform_values { |d| { due: d.due, runs: d.runs, throws: d.throws } } }
      end
    end

    # --------------------------------------------------------- the watchdog

    # One judgement by the watchdog at now (monotonic seconds); returns the
    # detection (a Symbol) or nil. Never takes a lock a duty holds.
    # judge_from: the instant ages count from at the earliest, after a pause
    # of the process (Watchdog#check); a dead thread is judged regardless.
    def watchdog_check(now, grace:, wedge:, judge_from: nil)
      return nil unless @started && !@stopping

      from = ->(at) { judge_from && at < judge_from ? judge_from : at }
      started_at = @run_started_at
      raised_at = @wake_raised_at
      armed_at = @armed_at
      detection =
        if @thread.nil? || !@thread.alive?
          :dead
        elsif started_at && now - from.call(started_at) > wedge
          @wedge_reported == started_at ? nil : :wedged
        elsif started_at.nil? && raised_at && now - from.call(raised_at) > grace
          :missed_wake
        elsif started_at.nil? && armed_at && now > from.call(armed_at) + grace
          :missed_fire
        end
      return nil if detection.nil?

      @wedge_reported = started_at if detection == :wedged
      reinitialise(detection, now)
      detection
    end

    # A new generation on a new thread, every duty asked once; a duty still
    # running in the old generation stays fenced until it returns.
    def reinitialise(reason, now = @time.mono)
      old = @thread
      running = @running_duty
      gen = @lock.synchronize do
        @detections[reason] += 1
        @generation += 1
        @reinits << now
        @reinits.shift while @reinits.size.positive? && now - @reinits.first > Watchdog::ESCALATE_WINDOW
        @duties.each_value { |d| d.asked = true }
        @run_started_at = nil
        @armed_at = nil
        @backstop_at = nil # the new generation's first run sweeps every duty
        @generation
      end
      stack = old&.backtrace&.first(8)&.join("\n    ")
      @logger&.warn("agentspaces: loop #{@name} re-initialised (#{reason}#{running ? ", duty #{running}" : ''}); " \
                    "generation #{gen}#{stack ? "; the old thread was at\n    #{stack}" : ''}")
      if @reinits.size >= Watchdog::ESCALATE_AFTER && @escalated.nil?
        escalate("#{@reinits.size} re-initialisations within #{Watchdog::ESCALATE_WINDOW.to_i} s, the last for #{reason}")
      end
      spawn_thread(gen) if @started && !@stopping
      signal # a parked thread of the old generation wakes and leaves
      announce_health
      gen
    rescue ThreadError
      gen
    end

    def escalate(reason)
      @escalated = reason
      @logger&.error("agentspaces: loop #{@name} is DOWN: #{reason}")
      announce_health
    end

    def inspect = "#<AgentSpaces::NodeLoop #{@name} generation=#{@generation} runs=#{@runs}>"

    private

    def signal
      @wakes += 1
      @wake_channel << true
    end

    # Whether the duty runs now, marked running in the same step, so two
    # callers of run_due (the loop's thread and a test, or two generations)
    # never run one duty twice at once. A backed-off duty waits out its hold
    # even when asked; the ask keeps until then.
    def claim(duty, now)
      @lock.synchronize do
        next false if duty.in_run
        next false if duty.held_until && now < duty.held_until
        next false unless duty.asked || (!duty.due.nil? && duty.due <= now)

        duty.asked = false
        duty.in_run = true
        @running_duty = duty.name
        @run_started_at = now
        true
      end
    end

    def run_duty(duty, now, generation)
      real_start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      next_due = nil
      begin
        next_due = duty.block.call(now)
        @lock.synchronize do
          duty.throws = 0
          duty.backoff = 0.0
          duty.held_until = nil
        end
      rescue StandardError => e
        next_due = throw_of(duty, now, e)
      ensure
        took = Process.clock_gettime(Process::CLOCK_MONOTONIC) - real_start
        @lock.synchronize do
          duty.in_run = false
          duty.runs += 1
          duty.slow += 1 if took > SLOW_RUN
          duty.due = next_due.nil? ? nil : Float(next_due)
          if generation == @generation
            @running_duty = nil
            @run_started_at = nil
          end
        end
        # A fenced duty back from a re-initialised loop: the new generation
        # learns its next due now rather than at the backstop.
        signal unless generation == @generation
      end
      announce_health
    end

    def throw_of(duty, now, error)
      held = @lock.synchronize do
        @throws_total += 1
        duty.throws += 1
        duty.last_error = "#{error.class}: #{error.message}"
        next nil if duty.throws < THROWS_BEFORE_BACKOFF

        cap = duty.kind == :protocol ? 1.0 : [@backstop, 1.0].max
        duty.backoff = duty.backoff.zero? ? 1.0 : [duty.backoff * 2, cap].min
        duty.held_until = now + duty.backoff
      end
      @logger&.warn("agentspaces: loop #{@name}: duty #{duty.name} raised #{error.class}: #{error.message}")
      held.nil? ? now + 1.0 : held
    end

    def earliest_due
      @lock.synchronize do
        @duties.values.filter_map do |d|
          next nil if d.in_run # fenced: its return signals the loop
          next [now_for_asked, d.held_until || 0.0].max if d.asked

          d.held_until && d.due ? [d.due, d.held_until].max : d.due
        end.min
      end
    end

    def now_for_asked = @time.mono

    def announce_health
      current = health
      listeners = @lock.synchronize do
        next [] if current[:state] == @last_health

        @last_health = current[:state]
        @health_listeners.dup
      end
      listeners.each do |listener|
        listener.call(current)
      rescue StandardError
        nil
      end
    end

    def spawn_thread(gen)
      thread = Thread.new do
        Thread.current.report_on_exception = false
        body(gen)
      end
      thread.name = "agentspaces-loop" # named by the spawner, so it carries its name from the start
      @thread = thread
    end

    # The process: run what is due, then select over the wake channel and
    # the timer until the earliest due or the backstop.
    def body(gen)
      until @stopping || gen != @generation
        next_due = run_due(@time.mono, gen)
        break if @stopping || gen != @generation

        @watchdog&.heartbeat_seen(@time.mono)
        armed = @armed_at || next_due
        wait = armed.nil? ? @backstop : (armed - @time.mono).clamp(0.0, @backstop)
        woke = wait.zero? ? true : @wake_channel.pop(timeout: wait)
        @timer_wakes += 1 if woke.nil?
        @wake_channel.clear
      end
    end
  end
end
