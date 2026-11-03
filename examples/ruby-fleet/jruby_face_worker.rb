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

# Example 27 on the JRuby face: the same Researcher class that research_worker.rb
# binds on the pure-Ruby peer, bound here on the Java binder of a Java node.
# The entries resolve to example 02's own Java records (ResearchFleet$ResearchTask
# and ResearchFleet$Finding), found on the class path under their schema names.
# Start the Java coordinator first, from the root of an AgentSpaces checkout
# (https://github.com/badmonkeyai/agentspaces):
#
#   mvn -q -pl examples/example-02-research-fleet exec:java -Dexec.args="coordinator 7467"
#
# then, under JRuby, with the vendored jars (`rake jruby:jars`) and example
# 02's classes on AGENTSPACES_CLASSPATH (the path below assumes the AgentSpaces
# checkout sits beside this repository):
#
#   export AGENTSPACES_CLASSPATH="$(ls ../../gems/agentspaces-jruby/jars/*.jar | tr '\n' ':')\
#   ../../../agentspaces/examples/example-02-research-fleet/target/classes"
#   jruby jruby_face_worker.rb 127.0.0.1:7467 7470
#
# The second argument is the port this node listens on.

$LOAD_PATH.unshift(File.expand_path("../../gems/agentspaces/lib", __dir__),
                   File.expand_path("../../gems/agentspaces-jruby/lib", __dir__))
require "agentspaces/jruby"
require_relative "agents/researcher"
$stdout.sync = true

seed = ARGV.fetch(0, "127.0.0.1:7467")
port = ARGV.fetch(1, "7470")
fleet = AgentSpaces::JRuby::Fleet.start(
  "security" => { "profile" => "dev-local" }, "bind" => "127.0.0.1:#{port}",
  "groups" => [{ "name" => "research-fleet", "founding" => "research-fleet-demo-v1", "seeds" => [seed],
                 "spaces" => ["tasks"] }]
)
fleet.bind(Researcher.new)
puts "jruby face #{fleet.peer_id} joined through #{seed}; ResearchTask is " \
     "#{fleet.records.java_class(ResearchTask).getName}"
trap("INT") { exit }
at_exit { fleet.close }
sleep
