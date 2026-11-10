# agentspaces-rb (Ruby)

**AgentSpaces for Ruby**, from Bad Monkey AI. A Ruby peer is a real member of a peer-to-peer fleet: class macros name the work an agent takes, entries are `Data` classes, and the same agent classes run on MRI as a wire peer and on JRuby over the Java binder.

## Quick start: build your first agent in Ruby

An agent is a method. The class macro above it names the work it takes, and its return value is the next entry in the space. Entries are `Data` classes with typed fields. A Ruby peer is a real member of the fleet: it holds its own Ed25519 identity, signs what it writes, and takes work under the same lease rules as a JVM peer. It dials out to a seed, so the quick start starts one.

**1. Install the gem.** Ruby 3.3 or newer with OpenSSL 1.1.1 or newer. macOS's system Ruby (2.6 on LibreSSL) cannot run it; install a current Ruby with Homebrew (`brew install ruby`), rbenv, or mise.

```
gem install agentspaces
```

Until the gem is on RubyGems.org, run from a clone: `export RUBYLIB=$PWD/agentspaces-rb/gems/agentspaces/lib`.

**2. Start a seed.** Any AgentSpaces peer with a listener will do. The Node service host is a seed in one command and needs no code. Its fleet file has the same shape as the Spring starter's YAML. The `dev-local` profile signs every frame over plain loopback TCP. Use it on a laptop and never on a shared network.

`seed.yaml`:

```yaml
agentspaces:
  security:
    profile: dev-local          # signed frames on loopback TCP; never on a shared network
  bind: 127.0.0.1:7700
  tick-millis: 250
  groups:
    - name: shop
      founding: shop-v1
      spaces: [ orders ]
```

```
npx agentspaces-node run seed.yaml
```

**3. Write the agent.** `Entry.define` names each entry's wire schema; the snake_case members travel under camelCase wire names (`order_id` is `orderId`). `take` says which space the method below it takes from and how long it may hold an entry.

`fulfiller.rb`:

```ruby
require "agentspaces"

Order    = AgentSpaces::Entry.define("shop.Order#v1",    order_id: String, item: String)
Shipment = AgentSpaces::Entry.define("shop.Shipment#v1", order_id: String, item: String, by: String)

class Fulfiller
  include AgentSpaces::Agent
  agent "fulfiller", description: "Ships orders"

  take Order, space: "orders", lease: "30s", produces: Shipment
  def ship(order) = Shipment.new(order_id: order.order_id, item: order.item, by: "fulfiller")
end

fleet = { group: "shop", founding: "shop-v1", seeds: ["127.0.0.1:7700"] }

if ARGV.empty?
  AgentSpaces.serve(**fleet) { |peer| peer.bind(Fulfiller.new) }
else
  AgentSpaces.start(**fleet) do |peer|
    peer.bind(Fulfiller.new)
    orders = peer.space("orders")
    orders << Order.new(order_id: "o-1", item: ARGV[0])
    puts orders.read(Shipment, timeout: "30s").inspect
    peer.close
  end
end
```

**4. Run two instances.** The first only ships. The second also writes an order, prints the shipment, and exits.

```
ruby fulfiller.rb
ruby fulfiller.rb kite
# => #<data Shipment order_id="o-1", item="kite", by="fulfiller">
```

Either instance can take the order, because both run the same agent.

**5. Kill one.** Add `puts "shipping #{order.order_id}"` and `sleep 10` at the top of `ship`. Start both instances, write an order from the second, and run `kill -9` on whichever instance prints `shipping`. If you killed the first instance, the second prints the shipment. If you killed the second, the first prints `shipping o-1` again when the 30-second lease lapses.

## What it is

- A pure-Ruby wire peer for MRI 3.3 or newer and JRuby 10, checked against the shared golden vectors.
- The agent DSL, the capability clients, and readers for persistent values and databases on refs.
- Gems for JRuby, Rails, RubyLLM tools, and MCP.
- The `agentspaces` command line.
- Dials `tcp`, `tls`, `ws`, `wss`, `http`, and `https`, with session attestation.

## Add it to your build

```
gem install agentspaces
```

Until the gem is on RubyGems.org, run from a clone: `export RUBYLIB=$PWD/agentspaces-rb/gems/agentspaces/lib`. [Rails](docs/rails.md) and [JRuby](docs/jruby.md) add the other gems.

## Where to read next

1. **[The developer guide](https://www.badmonkey.ai/agentspaces/developer-guide.html#ol-ruby)**: its Ruby section maps these gems onto the Java chapters.
2. **[The Ruby guide](https://www.badmonkey.ai/agentspaces/ruby-guide.html)**: a newcomer's walk from a first agent to capabilities, Rails, and values that change.
3. **[The examples](examples/)**: a Ruby worker that drains a Java coordinator, and the council worker.
4. **[The documents](docs/README.md)**: everything this README leaves out, one topic per document, each with the reader it is written for.

## License

Apache License 2.0, Copyright 2026 Bad Monkey, Inc. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions are welcome under the Developer Certificate of Origin; see [CONTRIBUTING.md](CONTRIBUTING.md). Report a vulnerability privately, as [SECURITY.md](SECURITY.md) describes.
