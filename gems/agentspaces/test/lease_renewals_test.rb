# frozen_string_literal: true

# Copyright 2026 Bad Monkey, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require_relative "test_helper"

module Desk
  RenewJob = AgentSpaces::Entry.define("com.acme.RenewJob#v1", topic: String)
end

# Lease renewals, 2026-11-09 (SPEC 7.3): a renewal is a later stamp in the state's
# lease register, re-signed by the issuer. The register supersedes the lease the
# record was written with, as Java's EntryState and the TypeScript client read it,
# so reads, takes, the sweep and an event's expiry all follow the renewed lease.
# Before this fix a renewed entry vanished, and raised EXPIRED, at its first lease.
class LeaseRenewalsTest < Minitest::Test
  include AgentSpaces

  GROUP = "zRubyRenew"

  def setup
    @clock = Testing::TestClock.new
    @writer, @reader = Testing::Network.fleet(GROUP, 2, clock: @clock)
    @events = {}
    @spaces = {}
    [@writer, @reader].each do |peer|
      @events[peer] = []
      @spaces[peer] = peer.space("tasks")
      @spaces[peer].watch(Desk::RenewJob) { |event| @events[peer] << [event.kind, event.item.entry_id] }
    end
  end

  def teardown
    [@writer, @reader].each(&:close)
  end

  def kinds(peer, entry_id) = @events[peer].select { |_, id| id == entry_id }.map(&:first)

  def ids(peer) = @spaces[peer].entries(Desk::RenewJob).map(&:entry_id)

  def takeable(peer) = peer.send(:available, Desk::RenewJob.schema, peer.now_ms).map(&:first)

  def test_a_renewal_keeps_the_entry_past_its_first_lease_on_every_member
    id = @spaces[@writer].write(Desk::RenewJob.new(topic: "keep me"), lease: "1m")
    @clock.advance(30_000)
    @writer.renew_entry("tasks", id, lease_millis: 600_000)
    renewed_until = @writer.now_ms + 600_000
    @clock.advance(60_000) # past the first lease, inside the renewed one

    [@writer, @reader].each do |peer|
      assert_equal [id], ids(peer)
      assert_equal [id], takeable(peer)
      assert_equal renewed_until, @spaces[peer].entries(Desk::RenewJob).first.expires_at_millis
      @spaces[peer].sweep
      assert_equal [WRITTEN], kinds(peer, id)
    end

    @clock.advance(600_000) # past the renewed lease
    [@writer, @reader].each do |peer|
      assert_empty ids(peer)
      assert_empty takeable(peer)
      @spaces[peer].sweep
      @spaces[peer].sweep
      assert_equal [WRITTEN, EXPIRED], kinds(peer, id)
    end
  end

  def test_an_older_renewal_arriving_late_moves_nothing
    id = @spaces[@writer].write(Desk::RenewJob.new(topic: "keep me"), lease: "1m")
    @clock.advance(20_000)
    dto = @writer.states.fetch(id)
    issuer = dto["record"]["issuer"]
    earlier = renewal_of(dto, issuer)
    @clock.advance(20_000)
    later = renewal_of(dto, issuer)
    @reader.fold_state(later)
    @reader.fold_state(earlier) # last writer wins by stamp, not by arrival

    assert_equal later["leaseValue"]["expiresAtMillis"], @spaces[@reader].entries(Desk::RenewJob).first.expires_at_millis
  end

  private

  # The writer's renewal of an entry at the clock's time, signed as the writer would sign it.
  def renewal_of(dto, issuer)
    now = @writer.now_ms
    renewed = dto.merge("leaseStamp" => Wire.hlc_now(issuer, now),
                        "leaseValue" => { "holder" => issuer, "expiresAtMillis" => now + 600_000, "kind" => "WRITE" })
    Wire.sign_state(renewed, @writer.identity, nil, now)
  end
end
