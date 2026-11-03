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

require_relative "test_helper"

# SRAD RB-Q-SEC-02: no code path turns a wire or configuration string into
# code. The scan covers every gem's lib/ directory.
class ForbiddenCallsTest < Minitest::Test
  FORBIDDEN = {
    "Marshal.load" => /Marshal\.(load|restore)/,
    "YAML.load (use safe_load)" => /YAML\.(load|unsafe_load|load_file)\b/,
    "eval of a string" => /(?<![\w.])eval\s*\(|class_eval\s*\(\s*["'<%]|module_eval\s*\(\s*["'<%]/,
    "const_get" => /const_get/,
    "constantize" => /constantize/,
    "Kernel#open on a path" => /(?<![\w.])(?<!def )open\s*\(/
  }.freeze

  def test_no_gem_source_turns_data_into_code
    root = File.expand_path("../..", __dir__)
    files = Dir[File.join(root, "*", "lib", "**", "*.rb")]
    refute_empty files
    findings = files.flat_map do |file|
      File.readlines(file).each_with_index.filter_map do |line, i|
        next if line.lstrip.start_with?("#")

        FORBIDDEN.filter_map { |name, pattern| "#{file}:#{i + 1}: #{name}" if line.match?(pattern) }.first
      end
    end
    assert_empty findings
  end
end
