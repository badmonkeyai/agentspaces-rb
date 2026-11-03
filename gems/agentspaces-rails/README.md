# agentspaces-rails

AgentSpaces for Rails: a Railtie over the [`agentspaces`](https://github.com/badmonkeyai/agentspaces-rb) wire peer.

```ruby
# Gemfile
gem "agentspaces-rails"
```

- `config/agentspaces.yml`, read through `config_for`, in the shape of the shared AgentSpaces fleet YAML.
- Agent classes in `app/agents`, served by `bin/rails agentspaces:work` (a `Procfile` line).
- `AgentSpaces::Rails.peer` in the web process, started lazily once per process; a forked Puma, Unicorn, or Passenger worker starts its own.
- A fleet outage raises `AgentSpaces::Unavailable` when a request needs the fleet and never stops the application from booting.
- `write.agentspaces`, `take.agentspaces`, and `complete.agentspaces` notifications.

Rails 8.1 or newer, Ruby 3.3 or newer. See the [repository README](https://github.com/badmonkeyai/agentspaces-rb#rails) for a configuration example.

Apache License 2.0, Copyright 2026 Bad Monkey, Inc.
