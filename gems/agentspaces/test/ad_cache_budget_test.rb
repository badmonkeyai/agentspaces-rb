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

# AppCard origin and formats, 2026-11-09 (SPEC §6.3 v0.1.32, FR-11): the
# advertisement cache bounds its entries by count and by bytes, the sum of
# the encodings it holds, as Java's AdCache does. A new id that would pass
# either bound, or a newer version that would pass the byte budget, is
# refused after the expired entries leave; the held version stays, the
# refusal counts in ads_refused_cache_full, and nobody is struck.
class AdCacheBudgetTest < Minitest::Test
  include AgentSpaces
  include GoldenHelpers

  START = Instants.parse_millis("2026-11-09T09:00:00Z")

  def setup
    @now = START
    @issuer = Identity.generate
  end

  def peer(**bounds) = Peer.new(Identity.generate, "zApps", clock: -> { @now / 1000.0 }, **bounds)

  # A signed AssetCard of an exact encoded size.
  def stored(name, bytes, issued: START, ttl: "PT10M")
    card = { "id" => "aspace://zApps/asset/#{@issuer.peer_id}/#{name}", "issuer" => @issuer.peer_id, "group" => "zApps",
             "issued" => Instants.iso(issued), "ttl" => ttl, "asset" => name, "uri" => "u", "description" => "",
             "shape" => "s", "freshness" => "f", "costHints" => {}, "access" => {} }
    padding = bytes - CBOR.dump(card).bytesize
    padding -= 1 while CBOR.dump(card.merge("description" => "d" * padding)).bytesize > bytes
    card["description"] = "d" * padding
    assert_equal bytes, CBOR.dump(card).bytesize
    Wire.stored_ad("AssetCard", card, @issuer)
  end

  def test_the_defaults_match_java
    assert_equal 8192, Peer::AD_CACHE_MAX_ENTRIES
    assert_equal 33_554_432, Peer::AD_CACHE_MAX_BYTES
    cache = peer
    assert_equal 8192, cache.ad_cache_max_entries
    assert_equal 33_554_432, cache.ad_cache_max_bytes
    assert_equal 0, cache.ad_cache_bytes
    [{ ad_cache_max_entries: 0 }, { ad_cache_max_bytes: 0 }, { ad_cache_max_bytes: 1.5 }].each do |bad|
      assert_raises(ArgumentError, bad.inspect) { peer(**bad) }
    end
  end

  def test_a_new_id_past_the_entry_bound_is_refused_until_an_entry_expires
    cache = peer(ad_cache_max_entries: 2)
    refute_nil cache.accept_ad(stored("a", 400, ttl: "PT1M"))
    refute_nil cache.accept_ad(stored("b", 400))
    assert_nil cache.accept_ad(stored("c", 400))
    assert_equal 1, cache.ads_refused_cache_full
    assert_equal 800, cache.ad_cache_bytes
    @now += 61_000
    refute_nil cache.accept_ad(stored("c", 400)), "the expired entry leaves first"
    assert_equal %w[b c], cache.ads.values.map { |e| e["ad"]["asset"] }.sort
    assert_equal 800, cache.ad_cache_bytes
  end

  def test_a_new_id_past_the_byte_budget_is_refused_and_one_that_fits_exactly_enters
    cache = peer(ad_cache_max_bytes: 1000)
    refute_nil cache.accept_ad(stored("a", 600))
    assert_nil cache.accept_ad(stored("b", 401))
    assert_equal 1, cache.ads_refused_cache_full
    refute_nil cache.accept_ad(stored("c", 400))
    assert_equal 1000, cache.ad_cache_bytes
    assert_nil cache.accept_ad(stored("huge", 1001)), "an ad larger than the budget never enters"
    assert_nil peer(ad_cache_max_bytes: 1000).accept_ad(stored("huge", 1001))
    assert_equal 2, cache.ads_refused_cache_full
  end

  def test_a_newer_version_past_the_budget_is_refused_and_the_held_one_stays
    cache = peer(ad_cache_max_bytes: 1000)
    refute_nil cache.accept_ad(stored("a", 500))
    refute_nil cache.accept_ad(stored("b", 400))
    grown = stored("a", 601, issued: START + 1000)
    assert_nil cache.accept_ad(grown)
    assert_equal Instants.iso(START), cache.ads[grown_id = CBOR.load(grown["adBytes"])["id"]]["ad"]["issued"],
                 "the held version stays"
    assert_equal 500, cache.ads[grown_id]["stored"]["adBytes"].bytesize
    assert_equal 1, cache.ads_refused_cache_full
    assert_equal 900, cache.ad_cache_bytes
    refute_nil cache.accept_ad(stored("a", 600, issued: START + 2000))
    assert_equal 1000, cache.ad_cache_bytes
    refute_nil cache.accept_ad(stored("a", 300, issued: START + 3000))
    assert_equal 700, cache.ad_cache_bytes, "a version that shrinks replaces"
    cache.accept_ad(stored("a", 900, issued: START))
    assert_equal 700, cache.ad_cache_bytes, "an older version leaves the held one in place"
    assert_equal 1, cache.ads_refused_cache_full
  end

  # An equal version leaves the held one in place and counts nothing, as
  # Java's AdCache.admit does; only a newer version meets the budget.
  def test_an_equal_version_leaves_the_held_one_and_counts_nothing
    cache = peer(ad_cache_max_bytes: 1000)
    refute_nil cache.accept_ad(stored("a", 600))
    refute_nil cache.accept_ad(stored("b", 300))
    id = CBOR.load(stored("a", 600)["adBytes"])["id"]
    [700, 500].each do |bytes|
      held = cache.accept_ad(stored("a", bytes))
      assert_equal 600, held["bytes"], bytes.to_s
      assert_equal 600, cache.ads[id]["bytes"], bytes.to_s
    end
    assert_equal 900, cache.ad_cache_bytes
    assert_equal 0, cache.ads_refused_cache_full
  end

  def test_the_sum_follows_expiry
    cache = peer(ad_cache_max_bytes: 1000)
    cache.accept_ad(stored("a", 700, ttl: "PT1M"))
    @now += 61_000
    refute_nil cache.accept_ad(stored("b", 700, issued: START + 61_000))
    assert_equal 700, cache.ad_cache_bytes
    assert_equal 0, cache.ads_refused_cache_full
  end
end
