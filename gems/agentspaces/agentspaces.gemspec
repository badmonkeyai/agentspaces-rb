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

require_relative "lib/agentspaces/version"

Gem::Specification.new do |spec|
  spec.name = "agentspaces"
  spec.version = AgentSpaces::VERSION
  spec.authors = ["Bad Monkey, Inc."]
  spec.email = ["oss@badmonkey.ai"]
  spec.summary = "AgentSpaces for Ruby: a wire-compatible peer of the AgentSpaces fleet and an agent DSL."
  spec.description = <<~TEXT
    A pure-Ruby AgentSpaces peer (SPEC v#{AgentSpaces::SPEC_VERSION}, wire version #{AgentSpaces::WIRE_VERSION}):
    joins Java, Python, and TypeScript fleets over tcp, tls, WebSocket, or HTTP, verifies every frame, writes signed
    entries, takes work under the lease-race claim lattice, and binds agents declared with class
    macros above plain methods. No native extension; OpenSSL from Ruby's standard library.
  TEXT
  spec.homepage = "https://github.com/badmonkeyai/agentspaces-rb"
  spec.license = "Apache-2.0"
  spec.required_ruby_version = ">= 3.3"
  spec.metadata = {
    "source_code_uri" => "#{spec.homepage}/tree/main/gems/agentspaces",
    "changelog_uri" => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "bug_tracker_uri" => "#{spec.homepage}/issues",
    "documentation_uri" => "#{spec.homepage}#readme",
    "rubygems_mfa_required" => "true"
  }
  spec.files = Dir["lib/**/*.rb", "exe/*", "README.md", "LICENSE", "NOTICE"]
  spec.bindir = "exe"
  spec.executables = ["agentspaces"]
  spec.require_paths = ["lib"]
  # Ruby 4.0 moved logger from the default gems to the bundled gems.
  spec.add_dependency "logger", ">= 1.5"
  # The CBOR decoder reads Jackson's tag 4 as a BigDecimal (HLC round five,
  # 2026-11-08 (E8)), and Ruby 3.4 moved bigdecimal to the bundled gems.
  spec.add_dependency "bigdecimal", ">= 3.1"
end
