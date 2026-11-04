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

require "digest"
require "json"
require "openssl"
require "agentspaces"
require "mcp"

module AgentSpaces
  # A fleet's remote actions as Model Context Protocol tools (SRAD RB-L-03),
  # served by the official Ruby SDK: one MCP::Tool per action the live,
  # unrevoked AgentCards declare. Calling a tool writes its input entry into
  # the action's task space and answers with the correlated result as JSON text.
  #
  #   gateway = AgentSpaces::MCP.gateway(peer, name: "shop-fleet", refresh_every: 5)
  #   MCP::Server::Transports::StdioTransport.new(gateway.server).open
  #
  # Replicas of one worker declare the same action; they are one tool, and a
  # call reaches whichever replica takes the task. Two different actions that
  # share a name get names with a stable suffix.
  module MCP
    TYPES = { String => "string", Integer => "integer", Float => "number", :boolean => "boolean",
              :instant => "string", Hash => "object" }.freeze
    MAX_NAME = 128

    # One tool: its name, the representative action, and how many cards offer it.
    Offering = Data.define(:name, :action, :replicas)

    module_function

    # The tools the peer's cards offer now, sorted by name. `only` keeps the
    # actions it answers truthy for; nil keeps them all.
    def offerings(peer, only: nil)
      actions = Capabilities::RemoteActions.actions(peer)
      actions = actions.select { |a| only.call(a) } if only
      groups = actions.group_by { |a| [a.name.to_s, a.consumes, a.produces, a.space] }
      by_base = groups.keys.group_by { |key| base_name(key[0]) }
      by_base.flat_map do |base, keys|
        keys.map do |key|
          name = keys.size == 1 ? base : suffixed(base, key)
          Offering.new(name: name, action: groups[key].first, replicas: groups[key].size)
        end
      end.sort_by(&:name)
    end

    def tools(peer, timeout: 30, agent: nil, only: nil, authorize: nil)
      offerings(peer, only: only).map do |offering|
        tool(peer, offering, timeout: timeout, agent: agent, only: only, authorize: authorize)
      end
    end

    # A server over the tools the cards offer when it is built. A call to a
    # tool whose action the fleet no longer offers is refused; use `gateway`
    # for a tool list that follows the fleet.
    def server(peer, name: "agentspaces", timeout: 30, agent: nil, only: nil, authorize: nil)
      ::MCP::Server.new(name: name, tools: tools(peer, timeout: timeout, agent: agent, only: only, authorize: authorize))
    end

    def gateway(peer, refresh_every: nil, **options)
      Gateway.new(peer, refresh_every: refresh_every, **options)
    end

    # A Streamable HTTP transport (a Rack app) for a server or gateway. HTTP
    # reaches beyond this process, so a token_verifier is required unless
    # allow_unauthenticated is true; the verified token reaches `authorize`.
    def http(server_or_gateway, token_verifier: nil, allow_unauthenticated: false, **transport_options)
      if token_verifier.nil? && !allow_unauthenticated
        raise ArgumentError, "an HTTP MCP endpoint invokes fleet actions for whoever reaches it: pass a " \
                             "token_verifier (for instance AgentSpaces::MCP::StaticTokens), or " \
                             "allow_unauthenticated: true behind an authenticating proxy"
      end
      server = server_or_gateway.respond_to?(:server) ? server_or_gateway.server : server_or_gateway
      ::MCP::Server::Transports::StreamableHTTPTransport.new(server, token_verifier: token_verifier,
                                                                     **transport_options)
    end

    # The MCP::Tool for one offering. The call is refused when the fleet no
    # longer offers the action, or when `authorize` (called with the action
    # and the verified token, nil over stdio) answers falsy.
    def tool(peer, offering, timeout: 30, agent: nil, only: nil, authorize: nil)
      action = offering.action
      tool_name = offering.name
      entry = Registry.lookup(action.consumes)
      ::MCP::Tool.define(name: tool_name, description: description(action, offering.replicas),
                         input_schema: schema(action, entry)) do |server_context: nil, **arguments|
        auth = server_context.respond_to?(:auth_info) ? server_context.auth_info : nil
        # The block runs as the SDK's tool class, so this module's functions are named in full.
        unless AgentSpaces::MCP.offerings(peer, only: only).any? { |o| o.name == tool_name }
          next AgentSpaces::MCP.error("#{tool_name} is no longer offered by the fleet")
        end
        if authorize && !authorize.call(action, auth)
          next AgentSpaces::MCP.error("not authorized to invoke #{tool_name}")
        end

        value = entry ? entry.new(**arguments.transform_keys(&:to_sym)) : arguments.fetch(:input).transform_keys(&:to_s)
        result = Capabilities::RemoteActions.invoke(peer, action, value, timeout_seconds: timeout, agent: agent)
        if result.nil?
          AgentSpaces::MCP.error("no result within #{timeout}s; the task stays leased")
        else
          ::MCP::Tool::Response.new([{ type: "text", text: JSON.generate(Capabilities::RemoteActions.payload_of(result)) }])
        end
      end
    end

    def error(text) = ::MCP::Tool::Response.new([{ type: "text", text: text }], error: true)

    def description(action, replicas)
      offered = replicas > 1 ? "; #{replicas} replicas" : ""
      "#{action.description} (AgentSpaces agent #{action.agent}; #{action.consumes} -> #{action.produces}#{offered})"
    end

    def schema(action, entry)
      if entry
        { properties: entry.fields.to_h { |f| [f.name.to_s, { type: json_type(f.type), description: f.wire }] },
          required: entry.fields.map { |f| f.name.to_s } }
      else
        { properties: { "input" => { type: "object", description: "the #{action.consumes} entry's wire fields" } },
          required: ["input"] }
      end
    end

    def base_name(name) = name.gsub(/[^a-zA-Z0-9_.-]/, "_")[0, MAX_NAME]

    # base_<8 hex>: the same action keeps the same name on every refresh and gateway.
    def suffixed(base, key)
      tag = Digest::SHA256.hexdigest(JSON.generate(key))[0, 8]
      "#{base[0, MAX_NAME - 9]}_#{tag}"
    end

    def json_type(type)
      return "array" if type.is_a?(Array)
      return "object" if Entry.entry_class?(type)

      TYPES.fetch(type, "string")
    end

    # A server whose tool list follows the fleet: `refresh` rebuilds it from
    # the cards and, when it changed, tells connected clients
    # (notifications/tools/list_changed). With refresh_every (seconds) a
    # thread refreshes on that interval until `close`.
    class Gateway
      attr_reader :server

      def initialize(peer, name: "agentspaces", timeout: 30, agent: nil, only: nil, authorize: nil, refresh_every: nil)
        @peer = peer
        @options = { timeout: timeout, agent: agent, only: only, authorize: authorize }
        @lock = Mutex.new
        @names = []
        @server = ::MCP::Server.new(name: name, tools: [])
        refresh
        @thread = start(refresh_every) if refresh_every
      end

      # The tool names now offered.
      def tool_names = @lock.synchronize { @names.dup }

      # Rebuilds the tools; returns true when the list changed.
      def refresh
        tools = MCP.tools(@peer, **@options)
        names = tools.map(&:name_value)
        changed = @lock.synchronize do
          next false if names == @names

          @names = names
          @server.tools = tools.to_h { |t| [t.name_value, t] }
          true
        end
        @server.notify_tools_list_changed if changed
        changed
      end

      def close
        @thread&.kill
        @thread = nil
      end

      private

      def start(interval)
        Thread.new do
          Thread.current.name = "agentspaces-mcp-refresh"
          loop do
            sleep interval
            begin
              refresh
            rescue StandardError => e
              warn "agentspaces-mcp: refresh failed: #{e.class}: #{e.message}"
            end
          end
        end
      end
    end

    # A token verifier for fixed bearer tokens, each with its scopes:
    #   StaticTokens.new("s3cret" => %w[orders:write])
    # Tokens compare in constant time. For identity providers use the SDK's
    # MCP::Server::OAuth::JWTVerifier or IntrospectionVerifier instead.
    class StaticTokens
      def initialize(tokens)
        @tokens = tokens.to_h { |token, scopes| [token.to_s, Array(scopes).map(&:to_s)] }
        raise ArgumentError, "StaticTokens needs at least one token" if @tokens.empty?
        raise ArgumentError, "a token may not be blank" if @tokens.keys.any? { |t| t.strip.empty? }
      end

      def verify(token)
        presented = token.to_s
        match = @tokens.keys.find do |known|
          known.bytesize == presented.bytesize && OpenSSL.fixed_length_secure_compare(known, presented)
        end
        match && ::MCP::Server::OAuth::AccessToken.new(token: match, scopes: @tokens[match])
      end
    end
  end
end
