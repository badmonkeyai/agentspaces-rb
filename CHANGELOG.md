# Changelog

All notable changes to AgentSpaces for Ruby. The five gems share one version,
which follows the AgentSpaces core.

## Unreleased: 0.6.0

The first release, on SPEC v0.1.33 and wire version 3. Not yet on RubyGems.org.

### `agentspaces`

- SPEC v0.1.32 cards (AppCard origin and formats, 2026-11-09). The schema
  reads `AppCard.origin`, `AppCard.formats`, and `spill` on both card kinds,
  with the records `AppCard.Origin`, `AppCard.Parts`, `AgentCard.Parts`, and
  `CardSpill`, and refuses what Java's card records refuse: a kind outside
  `peer`, `fed`, `gateway`, and `assembled` (`realm` included), `signOn`
  `tenant`, a broken origin or formats grammar or bound, a closed role,
  transport, or status outside its set, and a stub that breaks the spill
  rules. All 18 refusal vectors of golden.json are refused for their rule.
  The peer advertises `wire.appcard=2` (`appcard_level: 1` advertises
  nothing), issues no gated field since a dial-only client cannot see every
  member's hints (`app_cards_downgraded`), and never spills: a card past
  65,536 bytes travels inline (`cards_oversize_inline`) and one past 57,344
  bytes logs a warning once per id and size. `peer.resolve(card)` completes a
  stub through `peer.spill_store` (`spills_refused`, `spills_over_limit`,
  `spill_max_fetch_bytes:`), and remote actions resolve a stub before they
  offer its actions. The advertisement cache gains an entry bound and a byte
  budget (`ad_cache_max_entries:` 8,192, `ad_cache_max_bytes:` 32 MiB,
  `ads_refused_cache_full`). The semantic text of an AppCard adds its origin
  and formats, and `agentspaces status` names the parts a card spilled.
- Card review fixes (AppCard origin and formats, 2026-11-09). `resolve`
  checks the parts document's content root against `spill.root`, since this
  client runs no content swarm whose piece check would refuse other bytes,
  and counts a document of another root in `spills_refused`. The cache leaves
  a held advertisement in place for an older or equal version and counts
  nothing, as Java's `AdCache` does, where it used to replace on an equal
  `issued`. `publish_ad` raises `Schema::Error` on an AppCard or AgentCard
  that Java's card records refuse, such as kind `realm` or `signOn` `tenant`,
  so the card never goes out.
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
- Round four (HLC round four, 2026-11-08): the peer refuses an agent-signed
  state whose `signedAt` carries a counter above 65536, after its signatures
  verify, which supersedes round three's reading of `signedAt`. A PDT head's
  `pdt.issued` orders the head only when the strict parser accepts it and
  `pdt.issuer` is absent or parses as an agent id; otherwise the head keeps
  the entry's own stamp and issuer together. A stamp is a definite-length,
  untagged CBOR text in shortest-form UTF-8: a frame with any other item in
  its stamp's place counts in `peer.malformed_frames`, and a space delta with
  one drops whole and counts in `peer.deltas_undecodable`, while the rest of a
  pull response still folds. A state or claim stamped past the drift bound
  and skew margin waits uncounted until a later offer finds the wall caught
  up, and one more than an hour further is refused. Refusals count in
  `peer.stamps_logical_refused`, once per distinct signed content, which
  replaces `peer.refused_stamps`; the frame counters follow Java's names
  (`peer.frames.logical_refused`, `.far_future`, `.far_future_skewed`, and
  `to_h` keys `framesLogicalRefused`, `framesFarFuture`,
  `framesFarFutureSkewed`, `framesStale`, `framesReplayed`). `Wire.hlc_now`
  and `Identity#agent` refuse a node outside the stamp grammar.
- Round six (HLC round six, 2026-11-08): the codec writes and reads the
  AgentSpaces wire encoding. `CBOR.load` refuses a document unless its
  re-encoding equals its bytes, so a longer head, a short chunked text, a
  definite map, a duplicate or non-text key, a half float, another NaN,
  undefined, an unassigned simple value, an indefinite byte string or array,
  trailing bytes, a 65th level (a decimal's array counts), a small or padded
  bignum, a bignum magnitude past 1000 bytes (Java's bound), an array head
  that claims more items than bytes remain, and an unnormalized decimal no
  longer decode. The encoder writes an `Integer` past a Java long as a tag 2
  or 3 bignum (refusing one past 1000 bytes), a `BigDecimal` as a
  normalized tag 4, a `CBOR::Float32` as a float32, and only Java's NaN, and
  it refuses a non-text key and colliding Symbol and String keys.
  `AgentSpaces::Schema` holds every protocol record the peer reads to Java's
  field order, presence, and CBOR types, so a relabelled or coerced frame,
  delta, claim, advertisement, revocation, founding, or join credential is
  undecodable, as is a record Java's constructor refuses (a null in an
  advertisement, card, founding, or envelope field other than `Envelope.to`
  and `RevocationAdvertisement.successor`, an entry record with both or
  neither of `payload` and `payloadRef`, a payload past 64 KiB, a key epoch
  below 1, a certificate with a zero ttl or an encryption key of another
  length than 32 bytes); this supersedes round five's claim re-ordering
  (`Wire.canonical_claim`) and number coercions. A DIGEST's map travels
  sorted, a state's dots sort by UTF-16 code units, a bid of -0.0 wins over
  0.0, an agent id's local name holds no `:` (and, as in Java's `AgentId`,
  may hold a control character on the wire), an agent-signed state's
  `signedAt` meets the far-future rule (deferred, then refused) where the
  certificate's drift bound dropped it (`Certificates.verify_at` is gone),
  claims on entries the peer never held leave once they expire, and a read
  skips a payload outside the wire encoding (`Peer#value_of`).
- `AgentSpaces::PDT`, the reading face of the persistent data trees
  (srad/agentspaces-pdt.md PD-C-06): the node codec and CIDs, `PMap`, `PSet`,
  `PVector`, and `PBlob` over a node store that `NODE_WANT` and `TREE_WANT`
  fetches fill from members advertising `trees`, and `Pdt#map_ref(name).deref`
  with inline deltas applied, the rest fetched from the head's issuer, and
  several heads merged as the Java reader merges them. Every `pdt_*` and
  `content_*` tree vector of golden.json passes.
- The peer advertises `wire.recordless` and accepts a renew, cancel, or
  complete whose state carries no record: merged over the record it holds, or
  pending without an event until the whole DTO arrives (PD-L-04).
- PDT 2 phase 7 (srad/agentspaces-pdt2.md, P2-X-06): the face writes.
  `Ref#swap` gives its block the current value as plain Ruby (a Hash, a Set,
  an Array, or a binary String), builds the tree of the block's value with
  `PDT::Build`, and writes a multi-mode head over the heads it read, with the
  new nodes inline up to 32 KiB and its `vg` node named in `pdt.ancestry`.
  `Build` gives the root Java gives the same value: the CHAMP map, the `vr`
  vector, the FastCDC blob tree, and the spill rules reproduce
  `pdt_map_small`, `pdt_map_deep`, `pdt_node_embedded`, `pdt_vector_deep`,
  `pdt_fastcdc_cuts`, and `pdt_blob_small` byte for byte. `Pdt#tick` renews
  the writer's live heads at half their lease and cancels a superseded head
  two seconds after it falls below the lowest common base (`Peer#cancel_entry`,
  a state whose removes cover its adds). The tree exchange now serves:
  `NODE_WANT` from the store with the rest named missing, `TREE_WANT` as a
  breadth-first walk under the asker's haves and budget, `REJECT` reason 1 for
  a root it lacks, sealing under the write epoch's key in `group-key` mode, and
  an advertisement of `trees` "1" with no `pdt` parameter once it writes.
  A reader skips a head whose entry was cancelled and keeps a renewed head to
  its renewed lease, where it read only `completed` and the first lease.
- PDT 2 phase 7 (P2-C-02): the face reads `PRef.v` 2 heads and `db` refs
  through `DbReader` (`datoms`, `entity`, `lookup` over the sample of
  `pdt_db_sample`), relaxed `rr` vectors with the refusals of 3.7 and their
  packed `vr` root (`pdt_rr_splice`), texts as `PText` with Fugue's insert and
  delete, the strict value form, the `t` spill, and the union a merge takes
  for two texts changed on both sides (`pdt_text_*`), and windows of a blob
  verified 16 KiB group by group against `pdt.blake3` through the `bo` walk of
  `pdt.bao` (`PBlob#read_verified`, `Ref#read_verified`). `Pdt#store_for`
  chooses content stores from their cards (`StoreChooser`), writes one
  `SignedPin` naming them, and serves the tree. The face stays at feature
  level 1, so the level-2 forms are no messages of its own.
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
- `take` and `ordered_take` accept `pre:`, `post:`, and `cost:`, the
  planner contract of SPEC §6.1b, and the binder writes it on the take's card
  action when any term is set. A list of more than 32 texts or a cost hint
  past 64 characters fails at definition (2026-11-09).

### `agentspaces-jruby`

- The same agent classes bound through the Java binder of
  `agentspaces-runtime`, by compiling an annotated interface and records per
  agent shape, with the verbs only the Java binder runs (`ordered_take`,
  `reduce`, the leased and ordered join modes).
- `Fleet#ordered` forms a node's member of an ordered log, so exactly-once
  clerks run with no Java wiring.
- An entry whose schema names a Java class on `AGENTSPACES_CLASSPATH` (a jar
  or a class directory) binds to that class.
- `take` and `ordered_take` carry `pre:`, `post:`, and `cost:` onto the
  compiled `@SpaceTake` and `@OrderedTake`, so the Java binder publishes the
  action's planner contract (2026-11-09).

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
