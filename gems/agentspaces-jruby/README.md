# agentspaces-jruby

AgentSpaces on JRuby: the agent classes of the [`agentspaces`](https://github.com/badmonkeyai/agentspaces-rb) gem, bound through the Java binder of `agentspaces-runtime`.

```ruby
require "agentspaces/jruby"

fleet = AgentSpaces::JRuby::Fleet.start("agentspaces.yaml")   # every starter key binds
fleet.bind(Fulfiller.new)                                      # the same class, through the Java binder
```

- Every transport the Java node offers, and the verbs only the Java binder runs: `ordered_take`, `reduce`, and the leased and ordered join modes.
- `fleet.ordered(space, members:)` forms the node's member of an ordered log, so exactly-once clerks need no Java wiring.
- An entry whose schema names a Java class on the class path binds to that class; add jars or class directories with `AGENTSPACES_CLASSPATH`.

JRuby 10.1 on a JDK 21 or newer: the face compiles Java source for each agent shape with the JDK's compiler. The gem carries the `agentspaces-runtime` jars of its version. See the [repository README](https://github.com/badmonkeyai/agentspaces-rb#jruby).

Apache License 2.0, Copyright 2026 Bad Monkey, Inc.
