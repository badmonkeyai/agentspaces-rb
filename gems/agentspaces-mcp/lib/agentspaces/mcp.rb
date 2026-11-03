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

require "json"
require "agentspaces"
require "mcp"

module AgentSpaces
  # A fleet's remote actions as Model Context Protocol tools (SRAD RB-L-03),
  # served by the official Ruby SDK: one MCP::Tool per action a cached
  # AgentCard declares. Calling a tool writes its input entry into the
  # action's task space and answers with the correlated result as JSON text.
  #
  #   server = AgentSpaces::MCP.server(peer, name: "shop-fleet")
  #   MCP::Server::Transports::StdioTransport.new(server).open
  module MCP
    TYPES = { String => "string", Integer => "integer", Float => "number", :boolean => "boolean",
              :instant => "string", Hash => "object" }.freeze

    module_function

    def tools(peer, timeout: 30, agent: nil)
      Capabilities::RemoteActions.actions(peer).map { |action| tool(peer, action, timeout: timeout, agent: agent) }
    end

    def server(peer, name: "agentspaces", timeout: 30, agent: nil)
      ::MCP::Server.new(name: name, tools: tools(peer, timeout: timeout, agent: agent))
    end

    # The MCP::Tool subclass for one action.
    def tool(peer, action, timeout: 30, agent: nil)
      entry = Registry.lookup(action.consumes)
      schema =
        if entry
          { properties: entry.fields.to_h { |f| [f.name.to_s, { type: json_type(f.type), description: f.wire }] },
            required: entry.fields.map { |f| f.name.to_s } }
        else
          { properties: { "input" => { type: "object", description: "the #{action.consumes} entry's wire fields" } },
            required: ["input"] }
        end
      ::MCP::Tool.define(name: action.name.to_s.gsub(/[^a-zA-Z0-9_.-]/, "_")[0, 128],
                         description: "#{action.description} (AgentSpaces agent #{action.agent}; " \
                                      "#{action.consumes} -> #{action.produces})",
                         input_schema: schema) do |server_context: nil, **arguments|
        _ = server_context
        value = entry ? entry.new(**arguments.transform_keys(&:to_sym)) : arguments.fetch(:input).transform_keys(&:to_s)
        result = Capabilities::RemoteActions.invoke(peer, action, value, timeout_seconds: timeout, agent: agent)
        if result.nil?
          ::MCP::Tool::Response.new([{ type: "text", text: "no result within #{timeout}s; the task stays leased" }],
                                    error: true)
        else
          payload = Capabilities::RemoteActions.payload_of(result)
          ::MCP::Tool::Response.new([{ type: "text", text: JSON.generate(payload) }])
        end
      end
    end

    def json_type(type)
      return "array" if type.is_a?(Array)
      return "object" if Entry.entry_class?(type)

      TYPES.fetch(type, "string")
    end
  end
end
