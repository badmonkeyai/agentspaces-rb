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

An entry whose schema names a Java class on the class path binds to that class instead of a generated record. Put a build's `target/classes` or its jar on `AGENTSPACES_CLASSPATH` beside the vendored jars; `examples/ruby-fleet/jruby_face_worker.rb` binds the Researcher of example 27 on example 02's own Java records this way.
