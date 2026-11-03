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

require_relative "../agentspaces/lib/agentspaces/version"

Gem::Specification.new do |spec|
  spec.name = "agentspaces-rails"
  spec.version = AgentSpaces::VERSION
  spec.authors = ["Bad Monkey, Inc."]
  spec.email = ["oss@badmonkey.ai"]
  spec.summary = "AgentSpaces for Rails: a Railtie, app/agents, a worker process, fork safety, and instrumentation."
  spec.homepage = "https://github.com/badmonkeyai/agentspaces-rb"
  spec.license = "Apache-2.0"
  spec.required_ruby_version = ">= 3.3"
  spec.metadata = {
    "source_code_uri" => "#{spec.homepage}/tree/main/gems/agentspaces-rails",
    "changelog_uri" => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "bug_tracker_uri" => "#{spec.homepage}/issues",
    "documentation_uri" => "#{spec.homepage}#readme",
    "rubygems_mfa_required" => "true"
  }
  spec.files = Dir["lib/**/*.{rb,rake}", "README.md", "LICENSE", "NOTICE"]
  spec.require_paths = ["lib"]
  spec.add_dependency "agentspaces", AgentSpaces::VERSION
  spec.add_dependency "railties", ">= 8.1"
end
