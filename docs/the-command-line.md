# The command line

Written for: Ruby developers who build with agentspaces-rb.

```
agentspaces id [keystore]                    print the PeerID of a keystore, creating it when absent
agentspaces check <file-or-dir>...           load agent classes without a peer, check every clause, print the cards
agentspaces doctor                           run every crypto primitive and name the OpenSSL build
agentspaces status <fleet.yaml>              join, print members, spaces, and cards, and leave
agentspaces work <fleet.yaml> <files>...     bind every agent class and serve until SIGTERM
agentspaces console <fleet.yaml>             IRB with `peer` and `space(name)` bound
```

`agentspaces check` is the definition checker: every macro validates its options when the class body evaluates, so `check` reports a misspelled option, a duration that does not parse, a `where:` key that names no field, or a macro with no `def` below it, as `file:line: error: message`, without a fleet.
