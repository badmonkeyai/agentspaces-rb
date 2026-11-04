# agentspaces-mcp

AgentSpaces for the Model Context Protocol: a fleet's remote actions as MCP tools on the official Ruby SDK, over the [`agentspaces`](https://github.com/badmonkeyai/agentspaces-rb) wire peer.

```ruby
gateway = AgentSpaces::MCP.gateway(peer, name: "shop-fleet", refresh_every: 5)
MCP::Server::Transports::StdioTransport.new(gateway.server).open
```

## What a client sees

- One MCP tool per action the peer's live AgentCards declare. Cards of a revoked peer, agent, or agent key are left out.
- Replicas of one worker declare the same action and appear as one tool; a call reaches whichever replica takes the task. Two different actions that share a name get stable names with a short suffix (`ship_1a2b3c4d`).
- The client's model chooses among the tools by name, description, and input schema. The input schema is typed when the gateway process defines the consumed entry class; otherwise the tool takes one `input` object of wire fields.
- Calling a tool writes its input entry into the action's task space and answers with the correlated result as JSON text. A call to an action the fleet no longer offers is refused.

## Keeping the list current

`AgentSpaces::MCP.server(peer)` builds a fixed list from the cards held at that moment. `AgentSpaces::MCP.gateway(peer)` returns a gateway whose `refresh` rebuilds the list and sends `notifications/tools/list_changed` to connected clients when it changed; with `refresh_every:` (seconds) it refreshes on that interval until `close`.

## Choosing and guarding actions

```ruby
AgentSpaces::MCP.gateway(peer,
  only: ->(action) { action.space == "orders" },                     # what is offered at all
  authorize: ->(action, token) { token&.scopes&.include?("orders:write") }) # checked on every call
```

`authorize` receives the action and the verified token (an `MCP::Server::OAuth::AccessToken`, or nil over stdio). Every call writes as the gateway's peer, or as `agent:` when given.

## Streamable HTTP

```ruby
app = AgentSpaces::MCP.http(gateway,
  token_verifier: AgentSpaces::MCP::StaticTokens.new(ENV.fetch("MCP_TOKEN") => %w[orders:write]))
# mount `app` as a Rack app
```

An HTTP endpoint invokes fleet actions for whoever reaches it, so `http` requires a `token_verifier` unless you pass `allow_unauthenticated: true` (for instance behind an authenticating proxy). `StaticTokens` compares fixed bearer tokens in constant time; for an identity provider use the SDK's `MCP::Server::OAuth::JWTVerifier` or `IntrospectionVerifier`. Other options pass through to `MCP::Server::Transports::StreamableHTTPTransport`.

The `mcp` gem 1.8 or newer, Ruby 3.3 or newer. See the [repository README](https://github.com/badmonkeyai/agentspaces-rb).

Apache License 2.0, Copyright 2026 Bad Monkey, Inc.
