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
require "active_support"
require "active_support/notifications"

module AgentSpaces
  # AgentSpaces for Rails (SRAD 3.7, RB-H-01 to RB-H-04). The configuration
  # is config/agentspaces.yml, read through config_for so ERB and
  # environments work, holding the shared agentspaces: subtree; single keys
  # can be overridden in config.agentspaces.overrides. Agent classes live in
  # app/agents. A web process holds a peer lazily (AgentSpaces::Rails.peer)
  # to write and invoke; a worker process (bin/rails agentspaces:work) binds
  # every agent class and serves until SIGTERM.
  module Rails
    class << self
      attr_accessor :app

      # The configuration Hash AgentSpaces.start reads.
      def configuration
        raise ConfigError, "AgentSpaces::Rails is not attached to an application" if app.nil?

        settings = app.config.agentspaces
        tree = begin
          app.config_for(settings.config_name || :agentspaces).to_h
        rescue RuntimeError => e
          raise ConfigError, "#{e.message}; create config/agentspaces.yml with an agentspaces: subtree" \
            unless e.message.include?("Could not load configuration")

          raise ConfigError, "config/agentspaces.yml is missing; it holds the agentspaces: fleet subtree"
        end
        tree = Config.normalize(tree)
        tree = tree.fetch("agentspaces", tree)
        tree.merge(Config.normalize(settings.overrides.to_h))
      end

      # The process's peer, started lazily once per pid (see AgentSpaces.peer).
      def peer = AgentSpaces.peer(configuration, logger: ::Rails.logger)

      # The agent classes under app/agents, eager loaded through Zeitwerk.
      def agent_classes
        path = app.root.join(app.config.agentspaces.agents_path)
        ::Rails.autoloaders.main.eager_load_dir(path.to_s) if path.directory?
        ObjectSpace.each_object(Class).select do |klass|
          klass.include?(AgentSpaces::Agent) && klass.name && agent_file?(klass, path)
        end.sort_by(&:name)
      end

      def agent_file?(klass, path)
        source = Object.const_source_location(klass.name)&.first
        source.nil? || source.start_with?(path.to_s)
      end
    end

    # ActiveSupport::Notifications around the space verbs:
    # write.agentspaces, take.agentspaces, complete.agentspaces.
    module Instrumentation
      def write(value, **options)
        payload = { space: name, schema: options[:schema] || Entry.schema_of(value) }
        ActiveSupport::Notifications.instrument("write.agentspaces", payload) do
          payload[:entry_id] = super
        end
      end

      def take(type, **options, &block)
        payload = { space: name, schema: Template.of(type).schema }
        ActiveSupport::Notifications.instrument("take.agentspaces", payload) do
          result = super
          payload[:taken] = !result.nil?
          result
        end
      end
    end

    # Instrumentation of completions.
    module TakenInstrumentation
      def complete(result = nil, **options)
        ActiveSupport::Notifications.instrument("complete.agentspaces",
                                                space: space.name, entry_id: entry_id) { super }
      end
    end

    # The worker process: binds every agent class and serves until SIGTERM.
    class Worker
      def initialize(app, out: $stdout)
        @app = app
        @out = out
      end

      def run
        classes = Rails.agent_classes
        raise ConfigError, "no agent classes under #{@app.config.agentspaces.agents_path}" if classes.empty?

        AgentSpaces.serve(Rails.configuration, logger: ::Rails.logger,
                                               drain: @app.config.agentspaces.drain_timeout) do |peer|
          classes.each do |klass|
            bound = peer.bind(klass.new)
            @out.puts("agentspaces: bound #{klass} as #{bound.name}")
          end
          @out.puts("agentspaces: worker #{peer.identity.peer_id} serving #{peer.group[0, 12]}...")
        end
      end
    end
  end
end

require "agentspaces/rails/railtie" if defined?(::Rails::Railtie)
