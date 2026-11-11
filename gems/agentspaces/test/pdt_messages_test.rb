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
begin
  require "prism"
rescue LoadError
  nil # the guard skips on a Ruby without Prism; MRI 3.3 and later ship it
end

# A user reads the messages of the PDT library. A message says what went wrong
# and what to do, in plain words, and names no internal design id such as
# PD-N-04 or P2-X-06. This guard lexes every file under lib/agentspaces/pdt and
# fails on string content that names an id. Comments stay out of its reach.
class PdtMessagesTest < Minitest::Test
  include GoldenHelpers
  include AgentSpaces::PDT

  PDT_LIB = File.expand_path("../lib/agentspaces/pdt", __dir__)

  # A design id: a prefix, one or two letter groups, and a number, as in
  # PD-N-04 or P2-Q-SEC-05; or an ISSUE- name.
  DESIGN_ID = /\b[A-Z][A-Z0-9]{1,3}-[A-Z](?:-[A-Z]{1,4})?-\d{1,3}\b|\bISSUE-[A-Z][A-Za-z]/

  def offences(source, name = "<source>")
    Prism.lex(source).value.filter_map do |token, _state|
      next unless token.type == :STRING_CONTENT && token.value.match?(DESIGN_ID)

      "#{name}:#{token.location.start_line}: #{token.value.inspect}"
    end
  end

  def test_no_message_in_the_pdt_library_names_a_design_id
    skip "Prism is not available on this Ruby" unless defined?(Prism)
    files = Dir[File.join(PDT_LIB, "**", "*.rb")]
    assert_operator files.size, :>, 5, "the pdt library is where it was"
    found = files.flat_map { |file| offences(File.read(file), file.delete_prefix("#{PDT_LIB}/")) }
    assert_empty found, "string literals that name a design id; say what to do instead"
  end

  def test_the_guard_finds_an_id_in_a_string_and_skips_one_in_a_comment
    skip "Prism is not available on this Ruby" unless defined?(Prism)
    source = <<~'RUBY'
      # PD-N-04 in a comment
      def f(x)
        a = "bound (PD-N-04)"
        b = "#{x} (P2-Q-SEC-05)"
        c = "HKDF-SHA-256, UTF-8, PDT 2"
        raise ArgumentError, 'see ISSUE-Motion'
      end
    RUBY
    assert_equal %w[3 4 6], offences(source).map { |hit| hit.split(":")[1] }
  end

  def test_a_value_too_large_for_an_x_node_says_how_to_store_it
    error = assert_raises(ArgumentError) { Build.spill(cbor("t" * (2 * 1024 * 1024))) }
    assert_includes error.message, "node bound; store a value this large as a byte string, which becomes a blob"
  end
end
