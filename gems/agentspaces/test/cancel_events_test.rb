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

require_relative "test_helper"

module Desk
  Job = AgentSpaces::Entry.define("com.acme.CancelJob#v1", topic: String)
end

# Core cancel events, 2026-11-09 (SPEC 7.2, v0.1.32 draft note): a cancel travels as the
# issuer's signed state whose removes cover its adds. Once it folds here the entry is gone
# from reads and takes, and every watch hears EXPIRED, the kind a lapse raises, as Java's
# ReplicatedSpace and LocalSpace raise it. A redelivered cancel raises nothing more, a cancel
# and a lapse raise one EXPIRED between them, completion dominates a concurrent cancel, a
# holder whose replica merged the withdrawal cannot complete, and an entry learned first as
# withdrawn raises nothing.
class CancelEventsTest < Minitest::Test
  include GoldenHelpers
  include AgentSpaces

  GROUP = "zRubyCancel"

  def setup
    @clock = Testing::TestClock.new
    @writer, @reader, @third = Testing::Network.fleet(GROUP, 3, clock: @clock)
    @events = {}
    @spaces = {}
    [@writer, @reader, @third].each do |peer|
      @events[peer] = []
      @spaces[peer] = peer.space("tasks")
      @spaces[peer].watch(Desk::Job) { |event| @events[peer] << [event.kind, event.item.entry_id] }
    end
  end

  def teardown
    [@writer, @reader, @third].each(&:close)
  end

  def write_job(lease: "10m") = @spaces[@writer].write(Desk::Job.new(topic: "withdraw me"), lease: lease)

  # The writer's cancel of an entry, signed as the writer's replica would sign it.
  def cancel_of(entry_id)
    dto = @writer.states.fetch(entry_id)
    Wire.sign_state(dto.merge("removes" => dto["adds"]), @writer.identity, nil, @writer.now_ms)
  end

  def kinds(peer, entry_id) = @events[peer].select { |_, id| id == entry_id }.map(&:first)

  def assert_gone(peer, space = @spaces.fetch(peer))
    assert_empty space.entries(Desk::Job)
    assert_empty peer.send(:available, Desk::Job.schema, peer.now_ms)
  end

  def test_a_folded_cancel_raises_expired_once_at_every_member_and_the_entry_is_gone
    id = write_job
    cancel = cancel_of(id)
    [@writer, @reader, @third].each { |peer| peer.fold_state(cancel) }
    [@writer, @reader, @third].each do |peer|
      assert_equal [WRITTEN, EXPIRED], kinds(peer, id)
      assert_gone(peer)
    end
  end

  def test_a_redelivered_cancel_raises_no_second_expired
    id = write_job
    cancel = cancel_of(id)
    @reader.fold_state(cancel)
    @reader.fold_state(cancel)
    @reader.fold_state(cancel.reject { |key, _| key == "record" }.merge("issuerPublicKey" => nil, "entryId" => id))
    @spaces[@reader].sweep
    assert_equal [WRITTEN, EXPIRED], kinds(@reader, id)
    assert_gone(@reader)
  end

  def test_a_cancel_and_a_lapse_raise_one_expired_between_them_in_either_order
    lapse_first = write_job(lease: "1m")
    @clock.advance(120_000)
    @spaces[@reader].sweep
    @reader.fold_state(cancel_of(lapse_first))
    assert_equal [WRITTEN, EXPIRED], kinds(@reader, lapse_first), "the lapse, then the cancel"

    cancel_first = write_job(lease: "1m")
    @third.fold_state(cancel_of(cancel_first))
    @clock.advance(120_000)
    @spaces[@third].sweep
    assert_equal [WRITTEN, EXPIRED], kinds(@third, cancel_first), "the cancel, then the lapse"

    unswept = write_job(lease: "1m")
    @clock.advance(120_000) # lapsed, but no sweep ran before the cancel merged
    @writer.fold_state(cancel_of(unswept))
    @spaces[@writer].sweep
    assert_equal [WRITTEN, EXPIRED], kinds(@writer, unswept), "the cancel of a lapsed, unswept entry"
  end

  def test_a_holder_whose_replica_merged_the_withdrawal_cannot_complete
    id = write_job
    assert_equal id, @reader.take_entry("tasks", Desk::Job.schema, settle_seconds: 0.0, timeout_seconds: 2.0)
    @reader.fold_state(cancel_of(id))
    error = assert_raises(ArgumentError) { @reader.complete_entry("tasks", id) }
    assert_match(/withdrawn/, error.message)
    refute @third.states[id]["completed"], "no completion went out"
    assert_equal [WRITTEN, TAKEN, EXPIRED], kinds(@reader, id)
  end

  def test_a_cancel_that_folds_during_the_takers_settle_window_leaves_the_take_empty
    id = write_job
    taking = Thread.new { @reader.take_entry("tasks", Desk::Job.schema, settle_seconds: 0.3, timeout_seconds: 0.8) }
    assert eventually { @third.claim_of(id) }, "the claim went out: the take now waits out its settle window"
    @reader.fold_state(cancel_of(id))
    assert_nil taking.value, "the take found the entry withdrawn"
    # the test network hands the claim back to its sender, so the claim in force raised TAKEN first
    assert_equal [WRITTEN, TAKEN, EXPIRED], kinds(@reader, id)
  end

  def test_completion_dominates_a_concurrent_cancel
    id = write_job
    cancel = cancel_of(id)
    assert_equal id, @reader.take_entry("tasks", Desk::Job.schema, settle_seconds: 0.0, timeout_seconds: 2.0)
    @third.fold_state(cancel) # the cancel reaches the third member first
    @reader.complete_entry("tasks", id) # the completion reaches the writer and the third member
    [@writer, @reader].each { |peer| peer.fold_state(cancel) }
    assert_equal [WRITTEN, TAKEN, EXPIRED, COMPLETED], kinds(@third, id)
    [@writer, @reader].each do |peer|
      assert_equal [WRITTEN, TAKEN, COMPLETED], kinds(peer, id), "completed first, the cancel raises nothing"
    end
    [@writer, @reader, @third].each do |peer|
      assert peer.states[id]["completed"]
      assert_gone(peer)
    end
  end

  # A completion that lands while a fold of the same entry runs stays: the fold reads the entry and writes its
  # join in one critical section (core cancel events, 2026-11-09). The step after the first critical section that
  # read the entry stands in for the holder's thread, which completes there.
  def test_a_completion_that_lands_while_a_fold_of_the_entry_runs_stays_completed
    id = write_job
    assert_equal id, @reader.take_entry("tasks", Desk::Job.schema, settle_seconds: 0.0, timeout_seconds: 2.0)
    read = false
    @reader.states.define_singleton_method(:[]) do |key|
      read = true if key == id
      super(key)
    end
    lock = @reader.instance_variable_get(:@state_lock)
    reader = @reader
    folding = Thread.current
    landed = false
    depth = 0
    between = Object.new
    between.define_singleton_method(:synchronize) do |&section|
      depth += 1
      result = begin
        lock.synchronize(&section)
      ensure
        depth -= 1
      end
      if depth.zero? && read && !landed && Thread.current == folding
        landed = true
        reader.complete_entry("tasks", id)
      end
      result
    end
    @reader.instance_variable_set(:@state_lock, between)

    @reader.fold_state(@writer.states.fetch(id)) # a partner offers the write again
    assert landed, "the completion landed during the fold"
    assert @reader.states[id]["completed"], "the fold kept the holder's completion"
    assert_gone(@reader)
  end

  # Only the entry's issuer may cancel it (SPEC 11a.4, core cancel events, 2026-11-09).
  def test_a_cancel_that_another_member_signs_withdraws_nothing_and_raises_nothing
    id = write_job
    dto = @writer.states.fetch(id)
    forged = Wire.sign_state(dto.merge("removes" => dto["adds"]), @reader.identity, nil, @reader.now_ms)
    [@writer, @third].each do |peer|
      peer.fold_state(forged)
      assert_equal [WRITTEN], kinds(peer, id)
      assert_equal [id], @spaces[peer].entries(Desk::Job).map(&:entry_id), "the entry stays"
    end
  end

  def test_an_entry_learned_first_withdrawn_raises_nothing
    id = write_job
    late = Peer.new(Identity.generate, GROUP, clock: @clock)
    seen = []
    space = late.space("tasks")
    space.watch(Desk::Job) { |event| seen << event.kind }
    late.fold_state(cancel_of(id))
    late.fold_state(@writer.states.fetch(id))
    assert late.states.key?(id), "the tombstone is held"
    assert_empty seen, "a withdrawn entry learned late is history"
    assert_gone(late, space)
  ensure
    late&.close
  end
end
