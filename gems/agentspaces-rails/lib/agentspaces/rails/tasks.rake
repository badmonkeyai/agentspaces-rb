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

namespace :agentspaces do
  desc "Bind every agent class under app/agents and serve until SIGTERM"
  task work: :environment do
    AgentSpaces::Rails::Worker.new(Rails.application).run
  end

  desc "Print the fleet configuration AgentSpaces reads"
  task config: :environment do
    puts AgentSpaces::Rails.configuration.inspect
  end
end
