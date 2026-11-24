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

# A loaded version that a loaded head supersedes through a version still loading is
# no head (Java's Refs.heads; its spoiler scenario SC-I4). With the middle of a chain
# late, heads_among read base links only among the loaded versions, so the version
# below the late one was read as a head and merged in: a key a later version removed
# came back for that read, and Ref#swap's merge would write it back for every reader.
class PdtLateMiddleTest < Minitest::Test
  Refs = AgentSpaces::PDT::Refs

  def version(label, seq, *base)
    Refs::Head.new(root: "root-#{label}", base: base.map { |b| "root-#{b}" }, seq: seq, size: 1, kind: "map",
                   mode: "multi", issuer: "p/agent", issued: [1_000 + seq, 0, "n"], entry_id: "e-#{label}",
                   expires_at_millis: 9_999_999)
  end

  # A <- X <- H, and F beside them; X is still loading here, the rest loaded.
  def setup
    @a = version("a", 1)
    @x = version("x", 2, "a")
    @h = version("h", 3, "x")
    @f = version("f", 4)
    @live = [@a, @x, @h, @f]
    late = @x
    live = @live
    @ref = AgentSpaces::PDT::Ref.allocate
    @ref.instance_variable_set(:@ignored, Set.new)
    @ref.define_singleton_method(:live_entries) { live }
    @ref.define_singleton_method(:loadable) { |heads, _wait| heads.reject { |h| h.equal?(late) } }
  end

  def roots(heads) = heads.map(&:root).to_set

  def test_the_rule_alone_reads_the_version_below_a_late_middle_as_a_head
    assert_equal roots([@a, @h, @f]), roots(Refs.heads_among([@a, @h, @f]))
  end

  def test_a_late_middle_version_makes_no_ancestor_a_head
    assert_equal roots([@h, @f]), roots(@ref.send(:current_heads, true)), "A is superseded by H through X, still loading"
  end

  def test_the_fold_finds_every_version_a_loaded_one_supersedes_through_live_ones
    folded = Refs.superseded_by([@a, @h, @f], @live)
    assert_includes folded, [@a.root, @a.entry_id]
    assert_includes folded, [@x.root, @x.entry_id]
    refute_includes folded, [@h.root, @h.entry_id]
    refute_includes folded, [@f.root, @f.entry_id]
  end

  def test_with_nothing_loading_the_heads_are_the_rule_s_own
    @ref.define_singleton_method(:loadable) { |heads, _wait| heads.dup }
    assert_equal roots([@h, @f]), roots(@ref.send(:current_heads, true))
  end
end
