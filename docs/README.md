# agentspaces-rb documents

Written for: anyone who read the README and wants the rest of the story.

The README is short by design: what this is, the quick start, and how to add it to a build. Everything else lives here, one topic per document.

| Document | Written for | What it holds |
|---|---|---|
| [About agentspaces-rb](about.md) | Ruby developers who build with agentspaces-rb | What AgentSpaces is, and what this project adds to it. |
| [How to use AI with AgentSpaces](how-to-use-ai.md) | Ruby developers who build with agentspaces-rb | Tested walk-throughs that build an agent, hand it work from another peer, and survive a crash. |
| [Coming from Python or TypeScript](coming-from-python-or-typescript.md) | Ruby developers who build with agentspaces-rb | Coming from Python or TypeScript |
| [The cross-language guarantee](the-cross-language-guarantee.md) | Ruby developers who build with agentspaces-rb | `gems/agentspaces/test/golden.json` is a vendored copy of `golden.json` from the AgentSpaces specification, the vectors the Java codec produced. |
| [On a network](on-a-network.md) | Ruby developers who build with agentspaces-rb | The peer is strict in what it accepts and cautious in what it sends. |
| [The command line](the-command-line.md) | Ruby developers who build with agentspaces-rb | `agentspaces check` is the definition checker: every macro validates its options when the class body evaluates. |
| [Rails](rails.md) | Ruby developers who build with agentspaces-rb | Put agent classes in `app/agents`, run them with `bin/rails agentspaces:work` (a `Procfile` line). |
| [JRuby](jruby.md) | Ruby developers who build with agentspaces-rb | fleet = AgentSpaces::JRuby::Fleet.start("agentspaces.yaml") # every starter key binds fleet.bind(Fulfiller.new) # the same class. |
| [Run it](run-it.md) | Ruby developers who build with agentspaces-rb | Under JRuby, with Maven and a JDK 21 or newer: |
| [Scope](scope.md) | Ruby developers who build with agentspaces-rb | Built: the wire peer (`tcp`, `tls`, `ws`, `wss`, `http`, `https`, session attestation on the unattested bindings. |
| [Releasing](releasing.md) | maintainers who release the gems | The five gems share one version, `AgentSpaces::VERSION` in `gems/agentspaces/lib/agentspaces/version.rb`, which follows the AgentSpaces core. |
| [Contributing and security](contributing-and-security.md) | contributors | See CONTRIBUTING.md and the code of conduct. |
