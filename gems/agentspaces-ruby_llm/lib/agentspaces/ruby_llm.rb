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
require "agentspaces/lease"
require "ruby_llm"

module AgentSpaces
  # The fleet's agents as RubyLLM tools (SRAD 3.8, RB-L-01). Every
  # invocable action a cached AgentCard declares becomes one RubyLLM::Tool
  # whose execute writes the input entry into the action's task space and
  # awaits the correlated result through remote actions. A card names a
  # schema and not its fields, so a tool's parameters come from the Entry
  # class this process registered for the consumed schema; an action whose
  # schema is not registered takes one `input` object.
  #
  #   chat = RubyLLM.chat.with_tools(*AgentSpaces::RubyLLM.tools(peer))
  module RubyLLM
    TYPES = { String => "string", Integer => "integer", Float => "number", :boolean => "boolean",
              :instant => "string", Hash => "object" }.freeze

    module_function

    # One tool instance per action; timeout bounds each invocation (seconds).
    def tools(peer, timeout: 30, only: nil, agent: nil)
      Capabilities::RemoteActions.actions(peer).filter_map do |action|
        next if only && !Array(only).include?(action.name)

        tool_class(peer, action, timeout: timeout, agent: agent).new
      end
    end

    # The RubyLLM::Tool subclass for one remote action.
    def tool_class(peer, action, timeout: 30, agent: nil)
      entry = Registry.lookup(action.consumes)
      Class.new(::RubyLLM::Tool) do
        @tool_name = AgentSpaces::RubyLLM.tool_name(action)
        description "#{action.description} (an AgentSpaces agent, #{action.agent}; takes #{action.consumes}, " \
                    "returns #{action.produces})"
        if entry
          entry.fields.each do |field|
            parameter field.name, type: AgentSpaces::RubyLLM.json_type(field.type),
                                  description: "#{field.wire} of #{action.consumes}", required: true
          end
        else
          parameter :input, type: "object", description: "the #{action.consumes} entry, as its wire fields"
        end

        define_method(:execute) do |**arguments|
          value = entry ? entry.new(**arguments) : arguments.fetch(:input).transform_keys(&:to_s)
          result = Capabilities::RemoteActions.invoke(peer, action, value, timeout_seconds: timeout, agent: agent)
          next { error: "no result from #{action.agent} within #{timeout}s; the task stays leased" } if result.nil?

          Capabilities::RemoteActions.payload_of(result)
        rescue ArgumentError => e
          { error: e.message }
        end
      end
    end

    # A tool name a provider accepts: [a-zA-Z0-9_-], at most 64 characters.
    def tool_name(action) = action.name.to_s.gsub(/[^a-zA-Z0-9_-]/, "_")[0, 64]

    def json_type(type)
      return "array" if type.is_a?(Array)
      return "object" if Entry.entry_class?(type)

      TYPES.fetch(type, "string")
    end
  end
end
