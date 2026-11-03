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

# The Java records of example 02, named as the Java schema registry names them.
ResearchTask = AgentSpaces::Entry.define(
  "ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$ResearchTask#v1", topic: String, priority: Integer
)
Finding = AgentSpaces::Entry.define(
  "ai.badmonkey.agentspaces.examples.fleet.ResearchFleet$Finding#v1", topic: String, summary: String, worker: String
)

# Takes research tasks and writes findings.
class Researcher
  include AgentSpaces::Agent
  agent "rb-worker", description: "Researches a topic in Ruby", goals: ["research"]

  take ResearchTask, space: "tasks", lease: "30s", poll_timeout: "2s", produces: Finding
  def research(task)
    puts "ruby worker: took #{task.topic} (priority #{task.priority})"
    Finding.new(topic: task.topic, summary: "researched in ruby: #{task.topic}", worker: "rb-worker")
  end
end
