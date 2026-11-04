# Changelog

All notable changes to AgentSpaces for Ruby. The five gems share one version,
which follows the AgentSpaces core.

## Unreleased: 0.5.0

The first release, on SPEC v0.1.23 and wire version 3. Not yet on RubyGems.org.

### `agentspaces`

- A pure-Ruby wire peer for MRI 3.3 or newer and JRuby 10.1, with no native
  extension and one runtime dependency (`logger`). It reproduces all 212
  golden vectors of the specification byte for byte and refuses the 36
  hostile ones.
- Dials `tcp`, `tls`, `ws`, `wss`, `http`, and `https`. The `tls` dialer
  presents an Ed25519-endorsed channel certificate, attests the remote,
  announces `CHANNEL_HELLO`, and accepts bare frames from exactly the attested
  sender. On a connection no transport attests, session attestation
  (`SESSION_HELLO`, HMAC-SHA-256 tags) binds the remote's identity in band.
- Joins by GroupID with the four founding checks, applies revocations, takes
  under the LEASE_RACE claim lattice (a claim may not predate its entry),
  re-leases its self-advertisement, fails over across seeds after a lost
  connection, and refuses use in a forked child.
- Entries as `Data` classes with typed fields and camelCase wire names; the
  space verbs with ranges, arrays, and regexps as matchers and blocks as take
  bodies; numbers as seconds.
- The agent DSL: class macros (`take`, `notify`, `bid`, `ballot`,
  `on_decision`, `propose`, `join`) above plain methods, validated when the
  class loads, bound by a Ruby binder with every return convention.
- The capability clients (vote, aggregate, semantic discovery, remote actions,
  the connector clients, the ordered-log client), beacon documents, invite
  keys, and bootstrap.
- The `agentspaces` command: `id`, `check`, `doctor`, `status`, `work`,
  `console`.
- `Peer#cards` leaves out the cards of a revoked peer, agent, or agent key,
  as Java's ad cache does, so remote actions, RubyLLM tools, and MCP tools
  never offer a revoked agent.

### `agentspaces-jruby`

- The same agent classes bound through the Java binder of
  `agentspaces-runtime`, by compiling an annotated interface and records per
  agent shape, with the verbs only the Java binder runs (`ordered_take`,
  `reduce`, the leased and ordered join modes).
- `Fleet#ordered` forms a node's member of an ordered log, so exactly-once
  clerks run with no Java wiring.
- An entry whose schema names a Java class on `AGENTSPACES_CLASSPATH` (a jar
  or a class directory) binds to that class.

### `agentspaces-rails`, `agentspaces-ruby_llm`, `agentspaces-mcp`

- A Railtie: `config/agentspaces.yml`, agent classes in `app/agents`,
  `bin/rails agentspaces:work`, fork safety, notifications.
- A fleet's AgentCards as RubyLLM tools, and lease keepalive for a take whose
  body waits on a model.
- A fleet's remote actions as MCP tools on the official Ruby SDK (`mcp` 1.8
  or newer). Replicas of one worker are one tool, and different actions that
  share a name get stable suffixed names (two replicas used to stop the server
  with `MCP::ToolNotUnique`). `MCP.gateway` refreshes the tool list and sends
  `notifications/tools/list_changed`, and a call to an action no longer
  offered is refused. `only:` limits what is offered and `authorize:` checks
  every call against the verified token. `MCP.http` builds the Streamable HTTP
  transport and requires a `token_verifier` unless `allow_unauthenticated:
  true`; `MCP::StaticTokens` verifies fixed bearer tokens.

### Proved against the other runtimes

- Example 27's worker drains the Java coordinator of the AgentSpaces
  repository's example 02 over every binding, from MRI and from JRuby.
- A Ruby councillor sits on example 02's Java council beside the Python and
  TypeScript workers.
- Three JRuby-face clerks on one ordered log confirm payments written from
  JRuby and from MRI, each exactly once.
