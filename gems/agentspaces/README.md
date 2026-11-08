# agentspaces-rb (Ruby)

## Introducing AgentSpaces by Bad Monkey AI

**A peer-to-peer coordination fabric for agents, services, and the people who work with them.**

AgentSpaces is a P2P framework to quickly discover and join P2P networks, where agents, software services, and people share assets, queries, results, and coordinate. The framework helps you build fleets of agents, tie in other software, and coordinate across them with a replicated tuple space, quorum building, and more. Agents post work, claim tasks, publish results, vote on decisions, and recover from each other's failures. There is no broker, no registry, no scheduler, and no server to keep alive. Coordination is peer-to-peer, secured end to end, and replicated across the fleet.

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

## About agentspaces-rb

The Ruby bindings of AgentSpaces. Ruby has two doors into a fleet, and this repository builds both on one agent DSL:

| Gem | What it is |
|---|---|
| `agentspaces` | A pure-Ruby wire peer for MRI 3.3 or newer and JRuby 10: SPEC v0.1.23, wire version 3, byte-identical to the Java codec on all 212 golden vectors. Dial-only, over `tcp`, `tls`, `ws`, `wss`, `http`, and `https`, with session attestation where the transport attests nobody. Entries, the space verbs, the agent DSL and its Ruby binder, the capability clients (vote, aggregate, semantic discovery, remote actions, the connector clients, the ordered-log client), beacon documents, invite keys, and bootstrap, configuration from the shared fleet YAML, and the `agentspaces` CLI. No native extension; one runtime dependency (`logger`). |
| `agentspaces-jruby` | The same agent classes bound through the Java binder of `agentspaces-runtime` under JRuby, with every transport the Java node offers and the verbs only the Java binder runs today (`ordered_take`, `reduce`, the leased and ordered join modes). |
| `agentspaces-ruby_llm` | The fleet's AgentCards as RubyLLM tools, and `AgentSpaces::Lease.keepalive` for a take whose body waits on a model. |
| `agentspaces-mcp` | A fleet's remote actions as MCP tools on the official Ruby SDK, over stdio or Streamable HTTP. |
| `agentspaces-rails` | A Railtie: `config/agentspaces.yml` through `config_for`, agent classes in `app/agents`, `bin/rails agentspaces:work`, fork safety for Puma, Unicorn, and Passenger, and `ActiveSupport::Notifications` around the verbs. |

The wire peer joins a fleet as the Python and TypeScript clients do. It introduces its signed self-advertisement, answers membership probes, re-leases that advertisement every 30 seconds, and folds what anti-entropy and gossip bring. It verifies every frame, record, state transition, claim, card, and revocation before it acts on one, and it takes work under the LEASE_RACE claim lattice with the same total order as Java's `TakeClaim.merge`. Example 27 (`examples/ruby-fleet`) works beside the Java examples of the [AgentSpaces repository](https://github.com/badmonkeyai/agentspaces): `research_worker.rb` drains the tasks of example 02's Java coordinator over any of the six bindings, `council_worker.rb` sits on example 02's council beside Python and TypeScript workers, and `jruby_face_worker.rb` runs the same researcher on the Java binder under JRuby.

## How to use AI with AgentSpaces

At the end of this section you will have run three fleets inside one Ruby process, over in-memory peers, with no Java, no network, and no model key:

- an agent on one peer that completes work a second peer writes;
- a worker that dies in the middle of a take, whose task reappears once its lease lapses and is finished by another worker;
- two agents that decide a vote.

Each snippet is the body of one test in `gems/agentspaces/test/readme_examples_test.rb`, verbatim. Run them with `ruby -Igems/agentspaces/lib -Igems/agentspaces/test gems/agentspaces/test/readme_examples_test.rb`.

### 1. Build an agent and hand it work from another peer

An entry names its wire schema, and an agent class carries one macro per verb above the method it binds. Entries and agents are plain Ruby; the binder runs the loops.

```ruby
Ticket = AgentSpaces::Entry.define("readme.Ticket#v1", ticket_id: String, text: String, priority: Integer)
Triage = AgentSpaces::Entry.define("readme.Triage#v1", ticket_id: String, queue: String, by: String)

class Triager
  include AgentSpaces::Agent
  agent "triager", description: "Routes support tickets to a queue", goals: ["triage"]

  take Ticket, space: "tickets", lease: "30s", where: { priority: 1.. }, produces: Triage
  def route(ticket)
    queue = ticket.text.match?(/refund|charge/i) ? "billing" : "support"
    Triage.new(ticket_id: ticket.ticket_id, queue: queue, by: "triager")
  end
end
```

```ruby
worker, desk = AgentSpaces::Testing::Network.fleet("zReadme", 2)
bound = worker.bind(Triager.new, agent: worker.identity.renewing_subordinate("triager", "PT24H"))

desk.space("tickets") << Ticket.new(ticket_id: "t-1", text: "Refund my last charge", priority: 2)
triage = desk.space("tickets").read(Triage, timeout: "10s")
# => #<data Triage ticket_id="t-1", queue="billing", by="triager">
```

The agent signs as its own subordinate key (`renewing_subordinate`), so every peer stores its work as `AGENT_ATTESTED`. The method body is where a model call goes: whatever it returns is the next entry.

### 2. A crashed worker's take reappears

```ruby
clock = AgentSpaces::Testing::TestClock.new
crasher, survivor, desk = AgentSpaces::Testing::Network.fleet("zReadmeCrash", 3, clock: clock)
desk.space("tickets") << Ticket.new(ticket_id: "t-2", text: "Password reset", priority: 1)

# The first worker takes the ticket and dies before it completes the take.
taken = crasher.space("tickets").take(Ticket, lease: "5s", timeout: "5s")
crasher.close

# Nobody else can take it while the lease holds; once it lapses, the entry reappears.
assert_nil survivor.space("tickets").take(Ticket, lease: "5s", timeout: 1)
clock.advance(6_000)
retaken = survivor.space("tickets").take(Ticket, lease: "30s", timeout: "5s")
retaken.complete(Triage.new(ticket_id: retaken.value.ticket_id, queue: "support", by: "survivor"))
```

### 3. Two agents decide a vote

```ruby
class Reviewer
  include AgentSpaces::Agent
  agent "reviewer", description: "Votes on releases"

  def initialize(answer) = @answer = answer

  ballot space: "votes", prefix: "release:"
  def judge(proposal) = proposal.question.include?("0.5.0") ? @answer : nil
end
```

```ruby
a, b, chair = AgentSpaces::Testing::Network.fleet("zReadmeVote", 3)
bound = [a.bind(Reviewer.new("ship")), b.bind(Reviewer.new("ship"))]
AgentSpaces::Votes.propose(chair, "votes", "release:0.5.0", "Ship 0.5.0?", %w[ship hold], 2)

decision = until_true { AgentSpaces::Votes.decision(chair.states, "release:0.5.0") }
# => {"proposalId" => "release:0.5.0", "winner" => "ship", "tally" => {"ship" => 2, "hold" => 0}}
```

## Coming from Python or TypeScript

| Python | TypeScript | Ruby |
|---|---|---|
| `@entry("shop.Order#v1")` on a dataclass | an entry class | `Order = AgentSpaces::Entry.define("shop.Order#v1", order_id: String, ...)` |
| `@agent("fulfiller")` | `@agent` | `include AgentSpaces::Agent` and `agent "fulfiller"` |
| `@space_take("orders", lease="30s")` | `@spaceTake` | `take Order, space: "orders", lease: "30s"` above the `def` |
| `@space_notify`, `@bid_function`, `@ballot`, `@on_decision`, `@propose`, `@space_join` | the same | `notify`, `bid`, `ballot`, `on_decision`, `propose`, `join` |
| `Template(Task, where={"priority": gte(3)})` | `Template` | `where: { priority: 3.. }` (a Range), `Matchers.gte(3)`, or `"priority>=3"` |
| `Space(peer, "orders")` | `new Space(peer, "orders")` | `peer.space("orders")` |
| `space.take(t)` then `taken.complete(r)` | the same | the same, or `space.take(Order) { \|o\| result }` |
| `duration_millis(30)` is **30 ms** | milliseconds | **numbers are seconds**: `lease: 30` is 30 s; strings (`"250ms"`, `"10m"`, `"PT10M"`) as Java reads them |

## The cross-language guarantee

`gems/agentspaces/test/golden.json` is a vendored copy of `golden.json` from the [AgentSpaces specification](https://github.com/badmonkeyai/agentspaces-spec), the vectors the Java codec produced (`tools/golden/GoldenVectors.java` in the core repository). The suite reproduces every encoding and every signature byte for byte (RFC 8032 signing is deterministic), re-encodes every vector to its own bytes, and refuses each of the 36 hostile `adv_*` inputs as Java does. Refresh the copy with the specification's `sync-golden.sh`; with the specification checked out beside this repository, `rake golden:check` refuses a drift.

Ruby keeps `Integer` and `Float` apart, so the CBOR codec needs no wrapper type: a `Float` always encodes as a float64 and an entry field declared `Float` widens an `Integer` on assignment, which is what a Java `double` component needs.

## On a network

The peer is generous in what it accepts and cautious in what it sends. Every verified frame passes a `FrameFilter` first, which judges its stamp in the order of SPEC §9. A stamp is the canonical text `<physical>:<logical>:<node>`: digits with no leading zero, sign, fraction, or exponent, a physical part within a signed 64-bit integer, and a node with no colon and no control character, so the bytes a signer signed always equal the stamp's re-encoding. The filter drops a stamp that does not decode (`peer.frames.refused`), a stale stamp older than five minutes (`.stale`), a sender-and-stamp pair it has seen (`.replayed`), a stamp past the HLC drift bound by at most the five-second skew margin (`.skewed`) or further (`.ahead`), and a logical counter above 65536 (`Wire::HLC_LOGICAL_LIMIT`, `.refused`), each without a reply. The peer decodes every stamp with `Wire.hlc_decode` and orders or merges only those the strict parser `Wire.hlc_parse` accepts, comparing nodes and holders by UTF-16 code units as Java does. It never merges a folded record, lease stamp, or claim whose stamp that parser refuses, and it counts each refusal in `peer.refused_stamps` after the signature verifies, once per distinct state or claim. The local clock carries into the next millisecond at the limit and clamps a remote stamp one millisecond inside the drift bound, so one hostile stamp cannot freeze the clock, a lease, or a take, and a carry never pushes an honest peer past a receiver's drift check. A kind the peer does not speak counts in `peer.ignored_kinds`, a body that does not decode in `peer.malformed_frames`, and the reader goes on. A lost connection is a hiccup: the peer re-dials every 5 seconds for 10 minutes, failing over across its seeds, then re-introduces itself and re-pulls revocations, advertisements, and spaces. `close` by the owner is final.

- **TLS.** A `tls://host:port` seed dials TLS 1.3 and presents a channel certificate: a fresh P-256 key in a certificate the peer's Ed25519 identity key signs, with the identity key in the CN (SPEC §5.6). The peer attests the remote end the same way and refuses one that attests nobody. On an attested connection it announces `CHANNEL_HELLO`, so a Java node stops signing every frame toward it, and it accepts the bare frames that follow from exactly the attested sender. Tested against a Java seed with `requireAttestation(true)`.
- **WebSocket and HTTP.** A `ws://` or `wss://` seed dials RFC 6455 with the `aspace.1` subprotocol (default path `/aspace`); an `http://` or `https://` seed runs the specification's long-poll exchange (default path `/aspace/h`), for networks that pass only HTTP. `wss` and `https` attest a listener that presents an endorsed channel certificate, or trust the system roots and check the host name.
- **Session attestation.** On a connection the transport cannot attest (`tcp`, `ws`, `http`), the peer exchanges one fully signed `SESSION_HELLO` each way with a member that advertises `wire.session=1`, derives a key over X25519 and HKDF, and from then on tags its frames with HMAC-SHA-256 in place of an Ed25519 signature.
- **Plain transports.** A `tcp`, `ws`, or `http` seed to a non-loopback host is refused unless the configuration sets `allow_plain: true`, because `dev-local` signs every frame and encrypts nothing.
- **Forks.** A peer records the pid that started it. A forked child closes the connections it inherited without a word to the remote, and any use of an inherited peer raises `AgentSpaces::ForkError`, naming `AgentSpaces.after_fork`.
- **Keys.** `Identity.load_or_create(dir)` writes `peer.key` (PKCS#8 DER, owner-only, atomic rename) and `peer.pub`, the layout a Java peer reads, and refuses a key file others can read. `inspect`, `to_s`, and `pp` of an identity print its PeerID and nothing secret.

## The command line

```
agentspaces id [keystore]                    print the PeerID of a keystore, creating it when absent
agentspaces check <file-or-dir>...           load agent classes without a peer, check every clause, print the cards
agentspaces doctor                           run every crypto primitive and name the OpenSSL build
agentspaces status <fleet.yaml>              join, print members, spaces, and cards, and leave
agentspaces work <fleet.yaml> <files>...     bind every agent class and serve until SIGTERM
agentspaces console <fleet.yaml>             IRB with `peer` and `space(name)` bound
```

`agentspaces check` is the definition checker: every macro validates its options when the class body evaluates, so `check` reports a misspelled option, a duration that does not parse, a `where:` key that names no field, or a macro with no `def` below it, as `file:line: error: message`, without a fleet.

## Rails

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

## JRuby

```ruby
require "agentspaces/jruby"

fleet = AgentSpaces::JRuby::Fleet.start("agentspaces.yaml")   # every starter key binds
fleet.bind(Fulfiller.new)                                      # the same class, through the Java binder
```

The JRuby face writes Java source for each agent shape (an interface whose methods carry the Java annotations) and for each entry the classpath does not already hold (a record), compiles it with the JDK's compiler, and binds a `java.lang.reflect.Proxy` over the interface. It needs a JDK, Java 21 or newer, and the jars `rake jruby:jars` vendors. The pure-Ruby wire peer runs on JRuby as well; its X25519 runs on the JDK's provider there, since jruby-openssl has none.

An `ordered_take` agent needs an ordered log over its space. Each node forms its member of the log with the same list of voters, one per node, before it binds:

```ruby
members = nodes.map(&:peer_id)                     # the same list on every node
nodes.each { |node| node.ordered("payments", members: members) }
nodes.each { |node| node.bind(Clerk.new) }         # each payment confirmed once, fleet-wide
```

An entry whose schema names a Java class on the class path binds to that class instead of a generated record. Put a build's `target/classes` or its jar on `AGENTSPACES_CLASSPATH` beside the vendored jars; `examples/ruby-fleet/jruby_face_worker.rb` binds the Researcher of example 27 on example 02's own Java records this way.

## Run it

```
cd agentspaces-rb
bundle install
bundle exec rake test           # the core suite on MRI
bundle exec rake rails:test     # the Rails gem
bundle exec rake ai:test        # the RubyLLM and MCP gems
bundle exec rake all            # all of the above, then the golden-copy check
bundle exec rake build          # the four pure-Ruby gems into pkg/
bundle exec rake verify         # tests, then the golden-copy check
```

Under JRuby, with Maven and a JDK 21 or newer:

```
bundle exec rake test           # the core suite on JRuby
bundle exec rake jruby:jars     # vendor the agentspaces-runtime jars into gems/agentspaces-jruby/jars
bundle exec rake jruby:test     # the JRuby face
bundle exec rake jruby:build    # the agentspaces-jruby gem, jars included, into pkg/
```

The suites run on loopback and in-process fakes and need no network. `jruby:jars` resolves the AgentSpaces Java artifacts from Maven Central, or from the local repository after `mvn install` in the core.

## Scope

Built: the wire peer (`tcp`, `tls`, `ws`, `wss`, `http`, `https`, session attestation on the unattested bindings, join by GroupID with the four founding checks, revocations, the claim lattice, agent identities and the two-key rule, blocks, relay paths), entries, the space verbs, the agent DSL with every verb the Python binder runs (take, notify, bid, ballot, decision, propose, LOCAL join) and every return convention, the capability clients, beacon documents (an unsigned one is refused unless `allow_unsigned: true`, as Java's reader does from 0.5.0), invite keys and bootstrap, the shared fleet YAML, the CLI, the Rails, RubyLLM, and MCP gems, and the JRuby face. Not built yet: a listener or serving half (a Ruby process cannot be a seed; the Node host is the one-command seed), the content swarm, the gossip-learning learner, RBS signatures, and the Active Job adapter. The ordered verbs bind on the JRuby face only; there `fleet.ordered("payments", members: peer_ids)` forms each node's member of the ordered log.

## Releasing

The five gems share one version, `AgentSpaces::VERSION` in `gems/agentspaces/lib/agentspaces/version.rb`, which follows the AgentSpaces core.

1. Set the version, and the `agentspaces.version` of `gems/agentspaces-jruby/pom.xml` to match.
2. Move the `Unreleased` notes of `CHANGELOG.md` under the version.
3. On MRI: `bundle exec rake all build`. Under JRuby: `bundle exec rake test jruby:jars jruby:test jruby:build`. The Java artifacts of that version must already be on Maven Central.
4. Tag the commit `v<version>` and push the tag.
5. Push the gems with an owner's account, which requires MFA: `gem push pkg/agentspaces-<version>.gem` first, then the other four.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md). Report a vulnerability privately, as [SECURITY.md](SECURITY.md) describes.

## Licence

Apache License 2.0, Copyright 2026 Bad Monkey, Inc. See `LICENSE` and `NOTICE`.
