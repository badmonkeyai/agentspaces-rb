# What Ruby supports

Written for: Ruby developers who build with agentspaces-rb, and anyone who compares it with the other AgentSpaces clients.

The `agentspaces` gem runs a pure-Ruby wire peer on MRI. It does not yet run every feature of the Java core, or every feature of the Python and TypeScript clients. This page lists what it runs today, and what is on the Ruby roadmap. The AgentSpaces team checked each line against the gem's code and tests, and against the Python client, the TypeScript client, and the Java core, on 2026-11-10.

The JRuby face (`agentspaces-jruby`) binds the same agent classes through the Java binder, so on JRuby an agent gets the Java node's transports, its listener, and its verbs. The lists below describe the MRI wire peer.

## What Ruby supports today

| Area | What the Ruby peer does |
|---|---|
| Wire | Wire version 3 of SPEC v0.1.33. The suite decodes and re-encodes every encoded vector of the shared `golden.json` to the same bytes, reproduces the vectors of each feature on this page byte for byte, and refuses every hostile `adv_*` input as Java does. |
| Joining a fleet | Joins by founding text, or by GroupID with the four founding checks. Reads beacon documents, joins with invite keys, runs bootstrap, and reads the shared fleet YAML. |
| Identity and trust | Ed25519 identities, agent certificates and the two-key rule, the claim lattice, revocations, blocks, and relay paths. |
| Transports | Dials `tcp`, `tls`, `ws`, `wss`, `http`, and `https`. A plain seed on a non-loopback host needs `allow_plain: true`. |
| TLS | `tls` and `wss` run TLS 1.3 with a channel certificate and attest the remote end. On `tcp`, `ws`, and `http` the peer runs session attestation. The Java council test runs the Ruby worker over `tls` with attestation required. |
| Spaces | `write`, `read`, `all`, `entries`, `take`, `complete`, `renew`, `watch`, `notify`, and `stream`. A take may claim through the ordered log: `space.take(Type, through: log)`. |
| Agent verbs | `take`, `notify`, `bid`, `ballot`, `on_decision`, `propose`, the local `join`, and `on_estimate`, with every return convention of the Python binder. |
| Cards | Publishes each bound agent's AgentCard with its actions and republishes it while the agent stays bound. `publish_ad` sends any advertisement. Reads and checks AgentCards, AppCards (with `host`, `origin`, `formats`, and `ui`), AssetCards, ModelCards, and the capability, space, and group advertisements. Resolves a spilled card through an attached spill store. |
| Capabilities | Votes, the push-sum aggregate, semantic discovery, remote actions, the connector clients (`DataQueryClient`, `AssetInvocations`), and the ordered-log client. |
| Semantic discovery | Ranks AgentCards, AssetCards, ModelCards, AppCards, and capability and space advertisements with the hashing embedder of Java's default, over its own cache and over the pipe. |
| Persistent values, PDT 1 | Maps, sets, vectors, and blobs on refs. `deref`, `history`, and `swap` in multi mode, with the delta inline up to 32 KiB. `tick` renews the writer's heads and cancels the superseded ones. The reader merges concurrent heads as the Java reader does. The peer fetches nodes with `NODE_WANT` and `TREE_WANT`, and serves its own trees once it writes. |
| Persistent values, PDT 2 | Reads version 2 heads, `db` refs (`DbReader`), relaxed vectors, texts (`PText`), and BLAKE3-verified windows of a blob (`read_verified`). Writes texts, the version graph (`pdt.ancestry`), and signed store pins (`store_for`). |
| A2UI | Checks the `ui` declarations of AgentCards and AppCards, including AppCards of the `a2ui` shape. |
| The council | Sits on the Java council of example 02 beside the Python and TypeScript workers: it takes tasks, votes, adds to the push-sum epoch, answers semantic queries, and serves the remote action its card declares. |
| Gems and tools | The `agentspaces` CLI, and the JRuby, Rails, RubyLLM, and MCP gems. |

## On the Ruby roadmap

Each row names a feature the MRI peer does not run yet, and which other client runs it today.

| Feature | What Ruby does today | Python | TypeScript | Java |
|---|---|---|---|---|
| A listener, so a Ruby process can be a seed | dials only; use the Node host or a Java peer as the seed | no | yes, the Node host | yes |
| `dtls`, `udp`, `quic`, and `webrtc` | skips a seed of these schemes | no | `webrtc` | yes |
| The content swarm: publish and fetch large artifacts by manifest, holdings, and pieces | none | yes | yes | yes |
| Spilling a large card to the content swarm | sends the card inline and counts `cards_oversize_inline` | yes | yes | yes |
| Publishing an AppCard's `origin`, `formats`, or `idp` host | drops them and counts `app_cards_downgraded` | yes | yes | yes |
| A card publisher that reissues a card until you withdraw it | `publish_ad` sends a card once | `withdraw_ad` | `withdrawAd` | yes |
| The A2UI records `ChatMessage`, `SharedFile`, `WorkingOn`, and `ChatProgress`, and the component builders | none | yes | yes | yes |
| UI declarations on an agent (`ui_component`) | none | yes | yes | yes |
| The `data_use` hook | none | yes | yes | no |
| The commerce records `Mandate` and `Order` | none | yes | yes | yes |
| PDT feature level 2 on the content swarm: sketch reconciliation (negentropy and RIBLT), `dcz` deltas, and eager push | stays at level 1 and fetches each larger delta on request | yes | yes | yes |
| `swap` on a ref in linear mode | refuses the swap | yes | yes | yes |
| Writing `db` refs | reads them only | no | no | yes |
| `ordered_take`, `reduce`, and the leased and ordered joins | raises `EngineUnsupported`; the JRuby face runs them | no | yes | yes |
| The gossip-learning learner | encodes the exchange records only | no | no | yes |
| RBS signatures and an Active Job adapter | none | | | |
