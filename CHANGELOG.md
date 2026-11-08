# Changelog

All notable changes to AgentSpaces for Ruby. The five gems share one version,
which follows the AgentSpaces core.

## Unreleased: 0.5.0

The first release, on SPEC v0.1.23 and wire version 3. Not yet on RubyGems.org.

### `agentspaces`

- The peer refuses a remote HLC stamp whose logical counter is above 65536
  (`Wire::HLC_LOGICAL_LIMIT`) at every merge point: a frame, a folded record
  or lease stamp, and a folded claim. The local clock carries into the next
  millisecond at the limit and never repeats a stamp (HLC logical counter,
  2026-11-08 (Rust team report)).
- Round two: one strict parser, `Wire.hlc_parse`, reads every stamp the peer
  merges or orders as Java's `HlcTimestamp.parse` reads it, so the peer also
  refuses a negative, unreadable (`x`, `0x10001`), fractional, or missing
  part. Frames count in `peer.frames.refused` (formerly `.logical`), states
  and claims in `peer.refused_stamps`; `Wire.merge_claims` never keeps a
  claim with a refused stamp, so no hostile claim wedges its entry. The
  clock clamps a remote physical part at one millisecond inside the drift
  bound, so a carry lands at most on the bound (HLC logical counter,
  2026-11-08 (Rust team report)).
- Round three (HLC canonical stamps, 2026-11-08): the peer decodes a stamp
  only in the canonical grammar (no leading zero, ASCII digits, no control
  character in the node, text and never a CBOR byte string), so a claim
  signed over `007:0:n` can no longer replace an honest claim. The
  `FrameFilter` judges a stamp in the order of SPEC §9 and counts a frame
  just past the drift bound, within the five-second skew margin, in
  `peer.frames.skewed`. The peer counts a refused state or claim after its
  signature verifies, once per distinct one, no longer judges `signedAt`
  against the logical limit, orders nodes and holders by UTF-16 code units,
  and reads a PDT head's `pdt.issued` as Java's `Refs` reads it.
- `AgentSpaces::PDT`, the reading face of the persistent data trees
  (srad/agentspaces-pdt.md PD-C-06): the node codec and CIDs, `PMap`, `PSet`,
  `PVector`, and `PBlob` over a node store that `NODE_WANT` and `TREE_WANT`
  fetches fill from members advertising `trees`, and `Pdt#map_ref(name).deref`
  with inline deltas applied, the rest fetched from the head's issuer, and
  several heads merged as the Java reader merges them. Reading only. Every
  `pdt_*` and `content_*` tree vector of golden.json passes.
- The peer advertises `wire.recordless` and accepts a renew, cancel, or
  complete whose state carries no record: merged over the record it holds, or
  pending without an event until the whole DTO arrives (PD-L-04).
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
