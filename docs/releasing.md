# Releasing

Written for: maintainers who release the gems.

The five gems share one version, `AgentSpaces::VERSION` in `gems/agentspaces/lib/agentspaces/version.rb`, which follows the AgentSpaces core.

1. Set the version, and the `agentspaces.version` of `gems/agentspaces-jruby/pom.xml` to match.
2. Move the `Unreleased` notes of `CHANGELOG.md` under the version.
3. On MRI: `bundle exec rake all build`. Under JRuby: `bundle exec rake test jruby:jars jruby:test jruby:build`. The Java artifacts of that version must already be on Maven Central.
4. Tag the commit `v<version>` and push the tag.
5. Push the gems with an owner's account, which requires MFA: `gem push pkg/agentspaces-<version>.gem` first, then the other four.
