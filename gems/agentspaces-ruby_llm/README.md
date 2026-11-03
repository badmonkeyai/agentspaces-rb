# agentspaces-ruby_llm

AgentSpaces for [RubyLLM](https://rubyllm.com): the fleet's agents as model tools, over the [`agentspaces`](https://github.com/badmonkeyai/agentspaces-rb) wire peer.

```ruby
chat = RubyLLM.chat.with_tools(*AgentSpaces::RubyLLM.tools(peer))
```

- One RubyLLM tool per invocable action the peer's cached AgentCards declare; a model's tool call writes the input entry into the action's task space and awaits the correlated result.
- `AgentSpaces::Lease.keepalive` renews a take's lease on a timer while the take's body waits on a model, so a slow call does not hand the work to another member.

RubyLLM 2.1 or newer, Ruby 3.3 or newer. See the [repository README](https://github.com/badmonkeyai/agentspaces-rb#how-to-use-ai-with-agentspaces).

Apache License 2.0, Copyright 2026 Bad Monkey, Inc.
