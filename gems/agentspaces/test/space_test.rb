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

module Shop
  Task = AgentSpaces::Entry.define("com.acme.Task#v1", topic: String, priority: Integer)
  Finding = AgentSpaces::Entry.define("com.acme.Finding#v1", topic: String, summary: String)
  Verdict = AgentSpaces::Entry.define("com.acme.Verdict#v1", proposal_id: String, winner: String)
  Quote = AgentSpaces::Entry.define("com.acme.Quote#v1", item: String, price: Float, notes: [String])
end

# Entries, templates, and the Layer 3 verbs over two in-memory peers.
class SpaceTest < Minitest::Test
  include GoldenHelpers
  include AgentSpaces

  GROUP = "zRubySpaceTest"

  def setup
    @writer, @reader = Testing::Network.fleet(GROUP, 2)
  end

  def teardown
    [@writer, @reader].each(&:close)
  end

  def test_entries_are_data_with_typed_fields_and_camel_case_wire_names
    quote = Shop::Quote.new(item: "kite", price: 3, notes: [:fast])
    assert_equal 3.0, quote.price
    assert_kind_of Float, quote.price
    assert_equal ["fast"], quote.notes
    assert_equal({ "item" => "kite", "price" => 3.0, "notes" => ["fast"] }, quote.to_payload)
    verdict = Shop::Verdict.new(proposal_id: "p-1", winner: "yes")
    assert_equal({ "proposalId" => "p-1", "winner" => "yes" }, verdict.to_payload)
    assert_equal verdict, Shop::Verdict.from_payload({ "proposalId" => "p-1", "winner" => "yes", "extra" => 1 })
    assert_equal "com.acme.Verdict#v1", verdict.schema
    case verdict
    in { winner: "yes", proposal_id: }
      assert_equal "p-1", proposal_id
    end
    error = assert_raises(ArgumentError) { Shop::Task.new(topc: "x") }
    assert_match(/no field topc; fields are topic, priority/, error.message)
    assert_raises(ArgumentError) { Shop::Task.new(topic: "x", priority: 2.5) }
    assert_equal 2, Shop::Task.new(topic: "x", priority: 2.0).priority
    assert_nil Shop::Task.new(topic: "x").priority
    legacy = Entry.define("com.acme.Legacy#v1", trace_id: { type: String, wire: "traceID" })
    assert_equal({ "traceID" => "t" }, legacy.new(trace_id: "t").to_payload)
    assert_raises(ArgumentError) { Entry.define("com.acme.Task#v1", other: String) }
  end

  def test_durations_read_numbers_as_seconds_and_strings_as_java_reads_them
    assert_equal 30_000, Durations.millis(30)
    assert_equal 1500, Durations.millis(1.5)
    assert_equal 250, Durations.millis("250ms")
    assert_equal 600_000, Durations.millis("10m")
    assert_equal 600_000, Durations.millis("PT10M")
    assert_equal 5400_000, Durations.millis("PT1H30M")
    error = assert_raises(ArgumentError) { Durations.millis("30 seconds") }
    assert_match(/use "250ms"/, error.message)
    assert_raises(ArgumentError) { Durations.millis(true) }
  end

  def test_templates_match_with_the_java_matcher_semantics_and_ruby_idioms
    m = Matchers
    t = Template.new(Shop::Task, where: { priority: m.gte(3), topic: m.contains("index") },
                                 tags: { region: m.one_of("eu", "uk") })
    assert_equal "com.acme.Task#v1", t.schema
    assert t.matches({ "topic" => "indexing", "priority" => 3 }, { "region" => "eu" })
    refute t.matches({ "topic" => "indexing", "priority" => 2 }, { "region" => "eu" })
    refute t.matches({ "topic" => "indexing", "priority" => 3 }, { "region" => "us" })
    assert Template.new(Shop::Task, where: { priority: 3.. }).matches({ "priority" => 4 })
    refute Template.new(Shop::Task, where: { priority: 3.. }).matches({ "priority" => 2 })
    refute Template.new(Shop::Task, where: { priority: 3.. }).matches({ "priority" => nil })
    assert Template.new(Shop::Task, where: { priority: ...5 }).matches({ "priority" => 4 })
    refute Template.new(Shop::Task, where: { priority: ...5 }).matches({ "priority" => 5 })
    assert Template.new(Shop::Task, where: { topic: %w[a b] }).matches({ "topic" => "b" })
    assert Template.new(Shop::Task, where: { topic: /^ind/ }).matches({ "topic" => "index" })
    assert Template.new(Shop::Task, where: { topic: nil }).matches({})
    assert Template.new(Shop::Task, where: { priority: ->(p) { p.odd? } }).matches({ "priority" => 3 })
    assert Template.new(Shop::Task, where: "priority>=3").matches({ "priority" => 3 })
    assert Template.new(Shop::Task, where: ["priority>=3", "topic in a,b"]).matches({ "priority" => 3, "topic" => "a" })
    error = assert_raises(ArgumentError) { Template.new(Shop::Task, where: { priorty: 1 }) }
    assert_match(/no field priorty; fields are topic, priority/, error.message)
  end

  def test_tags_ride_inside_the_signed_record_and_filter_reads
    space = @writer.space("tasks")
    space.write(Shop::Task.new(topic: "eu-task", priority: 1), tags: { region: "eu" })
    space << Shop::Task.new(topic: "plain", priority: 2)
    view = @reader.space("tasks")
    assert_equal ["eu-task"], view.all(Shop::Task, tags: { region: "eu" }).map(&:topic)
    assert_equal %w[eu-task plain], view.all(Shop::Task).map(&:topic).sort
    assert_equal "plain", view.read(Shop::Task, where: { priority: 2 }).topic
    assert_predicate view.all(Shop::Task), :frozen?
    assert_equal ["eu-task"], view.all(Shop::Task) { |t| t.topic.start_with?("eu") }.map(&:topic)
    # A tampered tag breaks the signature and the record is dropped.
    _, body = Wire.entry_delta("tasks", GROUP, "com.acme.Task#v1", cbor({ "topic" => "t", "priority" => 1 }),
                               @writer.identity, "writer", 60_000, tags: { "region" => "eu" })
    state = load(load(body)["payload"])["state"]
    state["record"]["tags"] = { "region" => "us" }
    before = @reader.states.size
    @reader.fold_state(state)
    assert_equal before, @reader.states.size
  end

  def test_take_with_a_block_completes_with_the_result_and_sets_the_context
    @writer.space("tasks") << Shop::Task.new(topic: "index", priority: 5)
    space = @reader.space("tasks")
    events = []
    space.watch(Shop::Task) { |e| events << e.kind }
    context = nil
    finding = space.take(Shop::Task, where: { priority: 5.. }, lease: "1m", timeout: "3s") do |task|
      context = TakeContext.current
      Shop::Finding.new(topic: task.topic, summary: "done")
    end
    assert_equal "done", finding.summary
    refute_nil context
    assert_nil TakeContext.current
    assert_equal ["done"], eventually { space.all(Shop::Finding).map(&:summary).then { |s| s.empty? ? nil : s } }
    assert_empty space.all(Shop::Task)
    assert_equal [TAKEN, COMPLETED], events
    assert_equal ["done"], eventually { @writer.space("tasks").all(Shop::Finding).map(&:summary).then { |s| s.empty? ? nil : s } }
    assert_nil space.take(Shop::Task, timeout: 0.5)
  end

  def test_a_forged_field_type_skips_that_entry_and_never_fails_the_read
    @writer.space("tasks") << Shop::Task.new(topic: "good", priority: 1)
    @writer.write_entry("tasks", "com.acme.Task#v1", { "topic" => "bad", "priority" => "not a number" })
    assert_equal ["good"], @reader.space("tasks").all(Shop::Task).map(&:topic)
  end

  def test_a_raising_block_leaves_the_take_to_lapse
    @writer.space("tasks") << Shop::Task.new(topic: "boom", priority: 1)
    space = @reader.space("tasks")
    assert_raises(RuntimeError) { space.take(Shop::Task, lease: "1m", timeout: "3s") { raise "worker crashed" } }
    entry_id = @reader.states.keys.first
    refute @reader.states[entry_id]["completed"]
    refute_nil @reader.claim_of(entry_id)
  end

  def test_watch_delivers_each_entry_once_per_kind_and_close_stops_it
    space = @reader.space("tasks")
    seen = []
    sub = space.watch(Shop::Task, tags: { region: "eu" }) { |e| seen << [e.kind, e.value.topic] }
    @writer.space("tasks").write(Shop::Task.new(topic: "a", priority: 1), tags: { region: "eu" })
    @writer.space("tasks").write(Shop::Task.new(topic: "b", priority: 1), tags: { region: "us" })
    first = @reader.states.values.find { |dto| load(dto["record"]["payload"])["topic"] == "a" }
    @reader.fold_state(first.dup)
    assert_equal [[WRITTEN, "a"]], seen
    sub.close
    @writer.space("tasks").write(Shop::Task.new(topic: "c", priority: 1), tags: { region: "eu" })
    assert_equal [[WRITTEN, "a"]], seen
    refute sub.open?
  end

  def test_a_leased_notify_lapses_unless_renewed_and_expired_is_delivered
    clock = Testing::TestClock.new
    writer, reader = Testing::Network.fleet("zRubyLease", 2, clock: clock)
    kinds = []
    sub = reader.space("timers").notify(Shop::Task, lease: "5s", kinds: [EXPIRED]) { |e| kinds << e.kind }
    writer.space("timers").write(Shop::Task.new(topic: "t", priority: 1), lease: "2s")
    clock.advance(3000)
    assert eventually { kinds == [EXPIRED] }
    clock.advance(3000)
    assert eventually { !sub.open? }
    assert_equal "lapsed", sub.reason
  ensure
    writer&.close
    reader&.close
  end

  def test_an_agent_signed_write_take_and_completion_land_as_the_agents_own
    agent = @reader.identity.renewing_subordinate("worker", "PT24H")
    @writer.space("tasks") << Shop::Task.new(topic: "x", priority: 1)
    space = @reader.space("tasks", agent: agent)
    space.take(Shop::Task, timeout: "3s") { |t| Shop::Finding.new(topic: t.topic, summary: "by agent") }
    done = eventually { @reader.states.values.find { |dto| dto["completed"] } }
    assert done["signer"].end_with?("/worker")
    assert eventually { @writer.states.values.any? { |dto| dto["completed"] } }
    finding = eventually { @writer.states.values.find { |dto| dto["record"]["type"] == "com.acme.Finding#v1" } }
    refute_nil finding["agentCertificate"]
    assert_equal agent.agent_id, finding["record"]["issuer"]
  end
end
