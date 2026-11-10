# frozen_string_literal: true

# Copyright 2026 Bad Monkey, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "agentspaces"

module AgentSpaces
  # The agentspaces command (SRAD RB-T-01, RB-T-02).
  class CLI
    USAGE = <<~TEXT
      usage:
        agentspaces id [keystore-dir]                   print the PeerID of a keystore (default ./keys), creating it when absent
        agentspaces check <file-or-dir>...              load agent classes without a peer, check every clause, print their cards
        agentspaces doctor                              run every crypto primitive and name the OpenSSL build
        agentspaces status <fleet.yaml> [--group name]  join, print members, spaces, and cards, and leave
        agentspaces work <fleet.yaml> <file-or-dir>...  bind every agent class the files define and serve until SIGTERM
        agentspaces console <fleet.yaml>                open IRB with `peer` and `space(name)` bound
        agentspaces version
    TEXT

    def initialize(out: $stdout, err: $stderr)
      @out = out
      @err = err
    end

    def run(argv)
      command, *rest = argv
      case command
      when "id" then id(rest.first || "keys")
      when "check" then check(rest)
      when "doctor" then doctor
      when "status" then status(rest)
      when "work" then work(rest)
      when "console" then console(rest)
      when "version", "--version" then @out.puts("agentspaces #{VERSION} (SPEC v#{SPEC_VERSION}, wire #{WIRE_VERSION})")
      else
        @err.puts(USAGE)
        return 2
      end
      0
    rescue DefinitionError, ConfigError, Crypto::Unavailable, NoSeedError, Timeout::Error, ArgumentError => e
      @err.puts("agentspaces: #{e.message}")
      1
    end

    private

    def id(directory)
      @out.puts(Identity.load_or_create(directory).peer_id)
    end

    def doctor
      report = Crypto.doctor
      @out.puts("ruby:    #{report['ruby']}")
      @out.puts("openssl: #{report['openssl']}")
      report["checks"].each { |check| @out.puts("ok       #{check}") }
    end

    # Loads the files and returns every class that includes AgentSpaces::Agent.
    def load_agents(paths)
      raise ArgumentError, "name at least one file or directory" if paths.empty?

      before = agent_classes
      files = paths.flat_map { |p| File.directory?(p) ? Dir[File.join(p, "**", "*.rb")].sort : [p] }
      files.each { |file| load(File.expand_path(file)) }
      agent_classes - before
    end

    def agent_classes = ObjectSpace.each_object(Class).select { |c| c.include?(Agent) && c.respond_to?(:agentspaces_model) }

    def check(paths)
      failures = 0
      begin
        classes = load_agents(paths)
      rescue DefinitionError => e
        @err.puts("#{e.message.sub(/\A([^:]+:\d+): /, '\1: error: ')}")
        raise SystemExit, 1
      end
      classes.sort_by(&:to_s).each do |klass|
        model = klass.agentspaces_model
        @out.puts("#{klass} (agent #{model.name}): #{model.clauses.size} clause(s)")
        model.clauses.each do |clause|
          produces = clause.produces.map { |p| Entry.schema_of(p) }
          cue = clause.cue && Entry.entry_class?(clause.cue) ? clause.cue.schema : clause.cue.inspect
          @out.puts("  #{clause.method_name}: #{clause.verb} #{cue} in #{clause.options[:space] || '-'}" \
                    "#{produces.empty? ? '' : " -> #{produces.join(', ')}"}")
          if Agent::JVM_ONLY.include?(clause.verb)
            @out.puts("    note: #{clause.verb} binds on the JRuby face only")
          end
        end
      rescue DefinitionError => e
        failures += 1
        @err.puts(e.message.sub(/\A([^:]+:\d+): /, '\1: error: '))
      end
      @out.puts("no agent classes found") if classes.empty?
      raise SystemExit, 1 if failures.positive?
    end

    def status(args)
      config, group = config_args(args)
      peer = AgentSpaces.start(config, group: group)
      sleep 2
      @out.puts("peer     #{peer.identity.peer_id}")
      @out.puts("group    #{peer.group}")
      @out.puts("members  #{peer.members.size} (#{peer.reachable.size} reachable)")
      peer.members.each_key { |m| @out.puts("  #{m}") }
      cards = peer.cards
      @out.puts("cards    #{cards.size}")
      cards.each do |card|
        @out.puts("  #{card['agent']}: #{card['description']}")
        @out.puts("    spilled: #{card['spill']['parts'].join(', ')} (in its parts document)") if card["spill"]
        Array(card["actions"]).each do |a|
          @out.puts("    #{a['name']} (#{a['kind']}) #{Array(a['consumes']).join(', ')} -> #{Array(a['produces']).join(', ')}")
        end
      end
      @out.puts("frames   #{peer.frames.to_h.map { |k, v| "#{k}=#{v}" }.join(' ')} malformed=#{peer.malformed_frames}")
      peer.close
    end

    def work(args)
      config = args.shift or raise ArgumentError, "work needs a fleet file"
      classes = load_agents(args)
      raise ArgumentError, "no agent classes in #{args.join(', ')}" if classes.empty?

      AgentSpaces.serve(config) do |peer|
        classes.each do |klass|
          bound = peer.bind(klass.new)
          @out.puts("bound #{klass} as #{bound.name}")
        end
        @out.puts("serving on #{peer.group[0, 12]}... until SIGTERM")
      end
    end

    def console(args)
      config, group = config_args(args)
      tree = Config.normalize(config.is_a?(String) && File.exist?(config) ? YAML.safe_load_file(config) : {})
      tree = tree.fetch("agentspaces", tree)
      if Config::LISTENER_KEYS.any? { |k| tree.key?(k) }
        raise ConfigError, "the console never serves; remove #{(Config::LISTENER_KEYS & tree.keys).join(', ')} " \
                           "from the configuration it opens"
      end
      require "irb"
      peer = AgentSpaces.start(config, group: group)
      @out.puts("agentspaces console: peer #{peer.identity.peer_id} in #{peer.group}; try space(\"tasks\").all(\"...#v1\")")
      workspace = ConsoleBinding.new(peer).instance_eval { binding }
      IRB.setup(nil)
      irb = IRB::Irb.new(IRB::WorkSpace.new(workspace))
      irb.run(IRB.conf)
    ensure
      peer&.close
    end

    def config_args(args)
      config = args.shift or raise ArgumentError, "name a fleet file"
      group = nil
      if (index = args.index("--group"))
        group = args[index + 1]
      end
      [config, group]
    end

    # What the console's prompt sees.
    class ConsoleBinding
      attr_reader :peer

      def initialize(peer) = @peer = peer

      def space(name) = peer.space(name)
    end
  end
end
