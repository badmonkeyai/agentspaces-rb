# Rails

Written for: Ruby developers who build with agentspaces-rb.

```ruby
# Gemfile
gem "agentspaces-rails"
```

```yaml
# config/agentspaces.yml
default: &default
  agentspaces:
    keystore: <%= Rails.root.join("tmp/keys") %>
    groups:
      - name: shop
        founding: shop-v1
        seeds: <%= ENV.fetch("AGENTSPACES_SEEDS", "127.0.0.1:7700").split(",") %>
production:
  <<: *default
```

Put agent classes in `app/agents`, run them with `bin/rails agentspaces:work` (a `Procfile` line), and write from controllers and jobs with `AgentSpaces::Rails.peer.space("orders") << order`. The web process starts its peer lazily, once per process, and a forked Puma, Unicorn, or Passenger worker starts its own. A fleet outage raises `AgentSpaces::Unavailable` when a request needs the fleet and never stops the application from booting. `write.agentspaces`, `take.agentspaces`, and `complete.agentspaces` notifications carry the space, the schema, and the entry id.
