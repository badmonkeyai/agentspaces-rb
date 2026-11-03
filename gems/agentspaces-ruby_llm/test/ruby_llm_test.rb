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

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__), File.expand_path("../../agentspaces/lib", __dir__))
require "minitest/autorun"
require "agentspaces/ruby_llm"
require "agentspaces/testing"

module LShop
  Order = AgentSpaces::Entry.define("rbllm.Order#v1", order_id: String, item: String, quantity: Integer)
  Quote = AgentSpaces::Entry.define("rbllm.Quote#v1", order_id: String, price: Float)
end

# RubyLLM tools from the fleet's AgentCards, and lease keepalive.
class RubyLLMTest < Minitest::Test
  class Pricer
    include AgentSpaces::Agent
    agent "pricer", description: "Prices an order"

    take LShop::Order, space: "orders", lease: "30s", poll_timeout: "300ms", produces: LShop::Quote,
                       description: "Quotes a price for an order"
    def quote(order) = LShop::Quote.new(order_id: order.order_id, price: 4.25 * order.quantity)
  end

  def setup
    @worker, @assistant = AgentSpaces::Testing::Network.fleet("zRubyLLM", 2)
    @bound = @worker.bind(Pricer.new)
    deadline = Time.now + 5
    sleep 0.05 until !@assistant.cards.empty? || Time.now > deadline
  end

  def teardown
    @bound&.close
    [@worker, @assistant].each(&:close)
  end

  def test_each_card_action_is_a_tool_with_the_entrys_fields_as_parameters
    tools = AgentSpaces::RubyLLM.tools(@assistant, timeout: 10)
    assert_equal ["quote"], tools.map(&:name)
    tool = tools.first
    assert_kind_of RubyLLM::Tool, tool
    assert_match(/Quotes a price for an order/, tool.description)
    schema = tool.parameters_schema
    assert_equal %w[order_id item quantity], schema["properties"].keys
    assert_equal "integer", schema["properties"]["quantity"]["type"]
    result = tool.call(order_id: "o-1", item: "kite", quantity: 2)
    assert_equal({ "orderId" => "o-1", "price" => 8.5 }, result)
  end

  def test_an_invalid_argument_returns_an_error_the_model_can_read
    tool = AgentSpaces::RubyLLM.tools(@assistant, timeout: 1).first
    result = tool.call(order_id: "o-2", item: "kite", quantity: "many")
    assert_kind_of Hash, result
    assert_match(/quantity|integer|Invalid/i, result[:error].to_s)
  end

  def test_keepalive_renews_the_lease_while_a_long_call_runs
    @bound.close
    @assistant.space("orders") << LShop::Order.new(order_id: "o-3", item: "kite", quantity: 1)
    space = @worker.space("orders")
    taken = space.take(LShop::Order, lease: "2s", timeout: "5s")
    before = @worker.claim_of(taken.entry_id)["expiresAtMillis"]
    value = AgentSpaces::Lease.keepalive(taken, every: 0.2) do
      sleep 0.7
      :model_answer
    end
    after = @worker.claim_of(taken.entry_id)["expiresAtMillis"]
    assert_equal :model_answer, value
    assert_operator after, :>, before
    # The other peer folded the renewed claim: the take is still this worker's, with the later expiry.
    theirs = @assistant.claim_of(taken.entry_id)
    assert_equal after, theirs["expiresAtMillis"]
    assert_equal @worker.claim_of(taken.entry_id)["stamp"], theirs["stamp"]
  end
end
