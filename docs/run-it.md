# Run it

Written for: Ruby developers who build with agentspaces-rb.

```
cd agentspaces-rb
bundle install
bundle exec rake test           # the core suite on MRI
bundle exec rake rails:test     # the Rails gem
bundle exec rake ai:test        # the RubyLLM and MCP gems
bundle exec rake all            # all of the above, then the golden-copy check
bundle exec rake build          # the four pure-Ruby gems into pkg/
bundle exec rake verify         # tests, then the golden-copy check
```

Under JRuby, with Maven and a JDK 21 or newer:

```
bundle exec rake test           # the core suite on JRuby
bundle exec rake jruby:jars     # vendor the agentspaces-runtime jars into gems/agentspaces-jruby/jars
bundle exec rake jruby:test     # the JRuby face
bundle exec rake jruby:build    # the agentspaces-jruby gem, jars included, into pkg/
```

The suites run on loopback and in-process fakes and need no network. `jruby:jars` resolves the AgentSpaces Java artifacts from Maven Central, or from the local repository after `mvn install` in the core.
