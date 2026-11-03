# Security Policy

AgentSpaces for Ruby is a wire-compatible peer of the AgentSpaces fleet: it
holds its own Ed25519 identity, verifies every frame, record, claim, card,
and revocation before it acts on one, and signs everything it writes. It
inherits the security model of the AgentSpaces core (signed, self-certifying
peers and agents; the threat model in the AgentSpaces specification, SPEC
§11) and adds three rules of its own: no wire or configuration string becomes
code, keys never print, and a forked child never speaks on its parent's
connection.

## Reporting a vulnerability

Please report vulnerabilities **privately** via GitHub's security advisories:

> https://github.com/badmonkeyai/agentspaces-rb/security/advisories/new

A vulnerability in the AgentSpaces protocol or the core libraries belongs in
the core repository's advisories instead:
https://github.com/badmonkeyai/agentspaces/security/advisories/new

Do not open public issues for suspected vulnerabilities, and do not include
exploit details in public discussions until a fix is released.

We will acknowledge your report within five business days, keep you informed
of progress, credit you in the advisory unless you prefer otherwise, and
coordinate the disclosure timeline with you. There is currently no bug bounty
program.

Questions can be sent to `oss [at] badmonkey.ai`

## Scope

In scope: anything that lets an attacker violate a guarantee the fleet
claims through this peer. For example:

- a forged, replayed, or transplanted frame, record, claim, or revocation
  that the Ruby peer accepts where the Java peer refuses it (the 36 hostile
  inputs of the golden vectors are the baseline);
- a bare or session-tagged frame accepted from anyone but the peer its
  channel or session attests, or a session key another party can derive;
- a wire or configuration string that reaches `const_get`, `eval`,
  `Marshal.load`, or an unsafe YAML load;
- a private key, invite key, or token that `inspect`, `to_s`, `pp`, a log
  line, or an exception message prints;
- a key file written readable by others, or a torn key write;
- a forked process that signs or sends on its parent's connection.

Out of scope: the `dev-local` profile on a shared network (it signs every
frame and encrypts nothing, says so, and refuses a non-loopback seed unless
`allow_plain: true`), and denial of service by a member you admitted.
