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

require "rake/testtask"

GOLDEN_SOURCE = File.expand_path("../agentspaces-spec/golden.json", __dir__)
GOLDEN_COPY = File.expand_path("gems/agentspaces/test/golden.json", __dir__)

Rake::TestTask.new(:test) do |t|
  t.libs << "gems/agentspaces/lib" << "gems/agentspaces/test"
  t.test_files = FileList["gems/agentspaces/test/*_test.rb"]
  t.warning = false
end

namespace :golden do
  desc "Refuse when the vendored golden.json differs from a sibling agentspaces-spec checkout"
  task :check do
    unless File.exist?(GOLDEN_SOURCE)
      puts "golden.json: no agentspaces-spec checkout beside this repository; the vendored copy stands"
      next
    end
    if File.binread(GOLDEN_SOURCE) != File.binread(GOLDEN_COPY)
      abort "golden.json differs from agentspaces-spec/golden.json; run agentspaces-spec/sync-golden.sh"
    end
    puts "golden.json matches agentspaces-spec/golden.json"
  end
end

namespace :rails do
  Rake::TestTask.new(:test) do |t|
    t.libs << "gems/agentspaces/lib" << "gems/agentspaces-rails/lib"
    t.test_files = FileList["gems/agentspaces-rails/test/*_test.rb"]
    t.warning = false
  end
end

namespace :ai do
  Rake::TestTask.new(:test) do |t|
    t.libs << "gems/agentspaces/lib" << "gems/agentspaces-ruby_llm/lib" << "gems/agentspaces-mcp/lib"
    t.test_files = FileList["gems/agentspaces-ruby_llm/test/*_test.rb", "gems/agentspaces-mcp/test/*_test.rb"]
    t.warning = false
  end
end

desc "Every MRI suite: the core, Rails, RubyLLM, and MCP"
task all: %i[test rails:test ai:test golden:check]

namespace :jruby do
  desc "Copy the agentspaces-runtime jars into gems/agentspaces-jruby/jars (needs Maven)"
  task :jars do
    Dir.chdir("gems/agentspaces-jruby") do
      sh "mvn -q dependency:copy-dependencies -DoutputDirectory=jars -DincludeScope=runtime"
    end
  end

  desc "Build the agentspaces-jruby gem, with its vendored jars, into pkg/"
  task :build do
    abort "gems/agentspaces-jruby/jars is empty; run `rake jruby:jars` first" if Dir["gems/agentspaces-jruby/jars/*.jar"].empty?
    build_gem("agentspaces-jruby")
  end

  desc "The JRuby face suite (run under jruby)"
  task :test do
    sh "jruby -Igems/agentspaces/lib -Igems/agentspaces-jruby/lib -e 'Dir[%(gems/agentspaces-jruby/test/*_test.rb)].each { |f| require File.expand_path(f) }'"
  end
end

PURE_GEMS = %w[agentspaces agentspaces-rails agentspaces-ruby_llm agentspaces-mcp].freeze

def build_gem(name)
  require_relative "gems/agentspaces/lib/agentspaces/version"
  mkdir_p "pkg"
  Dir.chdir("gems/#{name}") do
    sh "gem build #{name}.gemspec --output ../../pkg/#{name}-#{AgentSpaces::VERSION}#{name == 'agentspaces-jruby' ? '-java' : ''}.gem"
  end
end

desc "Build the four pure-Ruby gems into pkg/"
task :build do
  PURE_GEMS.each { |name| build_gem(name) }
end

desc "Tests, then the golden-copy check"
task verify: %i[test golden:check]

task default: :verify
