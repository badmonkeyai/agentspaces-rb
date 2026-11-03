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

require "rails/railtie"

module AgentSpaces
  module Rails
    # Attaches AgentSpaces to a Rails application.
    class Railtie < ::Rails::Railtie
      config.agentspaces = ActiveSupport::OrderedOptions.new
      config.agentspaces.config_name = :agentspaces
      config.agentspaces.agents_path = "app/agents"
      config.agentspaces.drain_timeout = 30
      config.agentspaces.instrument = true
      config.agentspaces.overrides = {}

      initializer "agentspaces.attach" do |app|
        AgentSpaces::Rails.app = app
        if app.config.agentspaces.instrument
          AgentSpaces::Space.prepend(AgentSpaces::Rails::Instrumentation)
          AgentSpaces::Taken.prepend(AgentSpaces::Rails::TakenInstrumentation)
        end
      end

      # A forked Puma, Unicorn, or Passenger worker starts its own peer.
      initializer "agentspaces.fork" do
        ActiveSupport::ForkTracker.after_fork { AgentSpaces.after_fork } if defined?(ActiveSupport::ForkTracker)
      end

      rake_tasks do
        load File.expand_path("tasks.rake", __dir__)
      end
    end
  end
end
