# Contributing to AgentSpaces for Ruby

Thank you for your interest in contributing. AgentSpaces for Ruby is an
Apache 2.0 project from Bad Monkey, Inc., and everything in this repository
stays Apache 2.0.

This repository holds the Ruby bindings: the pure-Ruby wire peer, entries,
the space verbs, the agent DSL and its binder, the capability clients,
bootstrap, the CLI, and the optional gems for Rails, RubyLLM, MCP, and JRuby.
The protocol is the
[AgentSpaces specification](https://github.com/badmonkeyai/agentspaces-spec);
the Java libraries the JRuby face binds live in the
[AgentSpaces core repository](https://github.com/badmonkeyai/agentspaces).

## Before you start

- **Questions and ideas** are welcome as [GitHub issues](https://github.com/badmonkeyai/agentspaces-rb/issues).
- **Security issues** must not be filed as public issues. See
  [SECURITY.md](SECURITY.md) for private reporting.
- **Code of conduct:** by participating you agree to the
  [code of conduct](CODE_OF_CONDUCT.md).

## The rules a change must keep

- **The golden vectors decide conformance.** `gems/agentspaces/test/golden.json`
  is a vendored copy of `agentspaces-spec/golden.json`. Every byte the peer
  signs or hashes must match it; refresh the copy with the specification's
  `sync-golden.sh`, never by hand. A change that needs a new frame, entry
  type, or wire rule is a ticket against the specification first.
- **One DSL, two engines.** The agent DSL records a clause model and nothing
  else. The Ruby binder and the Java binder (the JRuby face) each run it.
- **Ruby idiom first, mirrored names second.** Entries are `Data`, numbers
  are seconds, matchers are ranges and arrays; option names are the Java
  annotation attributes in snake_case.
- **Stdlib first.** The core gem depends on `logger` alone. Anything heavier
  goes in an optional gem.
- **Nothing from the wire becomes code.** Decode through the registry, load
  configuration with `YAML.safe_load`, never `const_get` a wire string.

## Building and testing

Ruby 3.3 or newer with OpenSSL 1.1.1 or newer. macOS's system Ruby (2.6 on
LibreSSL) cannot run it; install one with Homebrew, rbenv, or mise.

```
bundle install
bundle exec rake all         # the core, Rails, RubyLLM, and MCP suites, then the golden-copy check
bundle exec rake build       # the four pure-Ruby gems into pkg/
```

Under JRuby 10.1 with a JDK 21 or newer and Maven:

```
bundle exec rake test        # the core suite on JRuby
bundle exec rake jruby:jars jruby:test
```

The suites run on loopback and in-process fakes and need no network. Give
every test that starts a peer or a listener a timeout, and close both when
the test ends; run a new test on both engines, since JRuby's sockets and
OpenSSL differ from MRI's in ways that only show under load.

## Pull requests

Open an issue first for anything beyond a fix. Keep the change small, add the
test that fails without it, and sign off your commits (DCO): `git commit -s`.
CI runs the MRI matrix, the JRuby suites, and a dependency scan on every push
and pull request.
