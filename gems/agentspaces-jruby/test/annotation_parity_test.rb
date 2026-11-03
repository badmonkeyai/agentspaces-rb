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
require "agentspaces/jruby"

# SRAD RB-Q-MNT-02: every macro option is a Java annotation attribute in
# snake_case, and every Java attribute is either a macro option or named
# here as one the DSL leaves to its default. A new attribute in the core
# fails this test until the table below or the DSL says what to do with it.
class AnnotationParityTest < Minitest::Test
  # Ruby-only options: produces on verbs whose Java return type carries it.
  RUBY_ONLY = { on_decision: %w[produces], on_estimate: %w[epochs ticks produces], reduce: [] }.freeze

  # Java attributes the DSL leaves at their defaults, with the reason.
  JAVA_DEFAULTS = {
    on_decision: %w[lease],                       # the decision watch's lease: the binder's default
    propose: %w[subscriptionLease],               # renewed by the binder at half-lease
    join: %w[name settle lease ticketLease takeLease pollTimeout],  # LEASED and ORDERED tuning
    reduce: %w[name accumulatorLease subscriptionLease],
    on_estimate: %w[prefix settleTicks tolerance group resultSpace resultLease description]
  }.freeze

  JAVA = { take: "SpaceTake", notify: "SpaceNotify", bid: "BidFunction", ballot: "Ballot", on_decision: "OnDecision",
           propose: "Propose", join: "SpaceJoin", ordered_take: "OrderedTake", reduce: "SpaceReduce",
           on_estimate: "OnEstimate" }.freeze

  def setup = AgentSpaces::JRuby.load_jars!

  def camel(name) = name.to_s.gsub(/_([a-z])/) { Regexp.last_match(1).upcase }

  def test_every_option_is_an_attribute_and_every_attribute_is_accounted_for
    AgentSpaces::Agent::OPTIONS.each do |verb, options|
      annotation = Java::JavaLang::Class.forName("ai.badmonkey.agentspaces.agent.annotation.#{JAVA.fetch(verb)}",
                                                 true, AgentSpaces::JRuby.loader)
      java = annotation.getDeclaredMethods.map(&:getName).sort
      ruby = options.keys.map { |k| camel(k) }
      extra = ruby - java - RUBY_ONLY.fetch(verb, []).map { |k| camel(k) }
      extra -= %w[options vote quorum] if verb == :propose
      extra -= %w[mode] if verb == :join && java.include?("mode")
      assert_empty extra, "#{verb}: options with no Java attribute"
      missing = java - ruby - JAVA_DEFAULTS.fetch(verb, [])
      assert_empty missing, "#{verb}: Java attributes the DSL does not carry"
    end
  end
end
