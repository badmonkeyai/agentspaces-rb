# agentspaces-mcp

AgentSpaces for the Model Context Protocol: a fleet's remote actions as MCP tools on the official Ruby SDK, over the [`agentspaces`](https://github.com/badmonkeyai/agentspaces-rb) wire peer.

```ruby
server = AgentSpaces::MCP.server(peer, name: "shop-fleet")
MCP::Server::Transports::StdioTransport.new(server).open
```

- One MCP tool per action the peer's cached AgentCards declare when the server is built; call `AgentSpaces::MCP.server` again to pick up cards that arrived later.
- Calling a tool writes its input entry into the action's task space and answers with the correlated result as JSON text.
- Any transport the `mcp` gem offers, stdio or Streamable HTTP.

The `mcp` gem 1.0 or newer, Ruby 3.3 or newer. See the [repository README](https://github.com/badmonkeyai/agentspaces-rb).

Apache License 2.0, Copyright 2026 Bad Monkey, Inc.
