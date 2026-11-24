# JRuby

Written for: Ruby developers who build with agentspaces-rb.

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

A renewal on the JRuby face is the Java node's (SPEC v0.1.35 §7.2), and the MRI peer behaves the same way:

- `renew(extension)` sets the lease to at least `extension` from now. It never shortens it: the new expiry is `max(current, now + extension)`.
- A renewal that would end sooner succeeds and leaves the lease as it was.
- Only the issuer renews, and only an entry that is present and unexpired on the renewing node.
- A take's renewal and a subscription's renewal read "extend" the same way.
- To end an entry sooner, cancel it. To shorten its lease, cancel it and write it again.

An entry whose schema names a Java class on the class path binds to that class instead of a generated record. Put a build's `target/classes` or its jar on `AGENTSPACES_CLASSPATH` beside the vendored jars; `examples/ruby-fleet/jruby_face_worker.rb` binds the Researcher of example 27 on example 02's own Java records this way.
