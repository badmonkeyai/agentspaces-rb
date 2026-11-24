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

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__), File.expand_path("../../agentspaces/lib", __dir__))
require "minitest/autorun"
require "agentspaces/ruby_llm"

# The keepalive's cycle (SPEC v0.1.36 §9.5: a lease about 1.5 times the cycle
# that renews it or more): half the take's lease by default, as the Java
# binder renews a held take; a cycle the lease cannot outlast is refused.
class LeaseCycleTest < Minitest::Test
  # A take whose renewals are counted, with a short lease so the test waits
  # a few hundredths of a second, not a real lease.
  class CountingTake
    attr_reader :lease_millis, :renewals

    def initialize(lease_millis)
      @lease_millis = lease_millis
      @renewals = Thread::Queue.new
    end

    def renew = @renewals << :renewed
  end

  def test_the_cycle_defaults_to_half_the_lease
    taken = CountingTake.new(80)
    value = AgentSpaces::Lease.keepalive(taken) do
      2.times { taken.renewals.pop(timeout: 1) || flunk("no renewal within a second at a 40 ms cycle") }
      :answer
    end
    assert_equal :answer, value
  end

  # A take a wake finds lapsed (C05) tells its listeners, as Taken#on_lapse does.
  class LapsingTake < CountingTake
    def initialize(lease_millis)
      super
      @listeners = []
    end

    def entry_id = "e1"

    def on_lapse(&listener) = @listeners << listener

    def lapse! = @listeners.each(&:call)
  end

  # C05: the keepalive stops at once when the take lapses, not at its next
  # cycle (an hour here), and the block's result is late: the lapse raises.
  def test_a_lapse_stops_the_keepalive_at_once_and_the_result_is_late
    taken = LapsingTake.new(7_200_000)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    error = assert_raises(ArgumentError) do
      AgentSpaces::Lease.keepalive(taken) do
        taken.lapse!
        :answer
      end
    end
    assert_match(/lapsed.*late/, error.message)
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 5, "no wait for the 1 h cycle"
    assert_equal 0, taken.renewals.size, "nothing renewed after the lapse"
  end

  # A take a wake finds still held (C05) tells its wake listeners, as Taken#on_wake does.
  class WakingTake < LapsingTake
    def initialize(lease_millis)
      super
      @wakes = []
    end

    def on_wake(&listener)
      @wakes << listener
      -> { @wakes.delete(listener) }
    end

    def wake! = @wakes.each(&:call)
  end

  # C05, the live half (cross-client review): a wake whose lease still holds
  # renews at once, as the TypeScript and Rust keepalives and Python's binder
  # do, not at the next cycle on a monotonic clock that did not count the sleep.
  def test_a_wake_inside_the_lease_renews_at_once
    taken = WakingTake.new(7_200_000)
    AgentSpaces::Lease.keepalive(taken) do
      taken.wake!
      taken.renewals.pop(timeout: 2) || flunk("no renewal at the wake: it waited for the 1 h cycle")
    end
    assert_equal 0, taken.renewals.size, "one renewal for the one wake"
  end

  def test_a_cycle_the_lease_cannot_outlast_is_refused
    error = assert_raises(ArgumentError) { AgentSpaces::Lease.keepalive(CountingTake.new(1_000), every: 1.0) { nil } }
    assert_match(/lapses first/, error.message)
  end

  def test_a_cycle_without_margin_is_warned_about
    _, err = capture_io { AgentSpaces::Lease.keepalive(CountingTake.new(1_000), every: 0.8) { :ok } }
    assert_match(/less than 1.5 times its cycle/, err)
  end
end
