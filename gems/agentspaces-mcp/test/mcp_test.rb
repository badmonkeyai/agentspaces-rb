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
require "agentspaces/mcp"
require "agentspaces/testing"

module MShop
  Order = AgentSpaces::Entry.define("rbmcp.Order#v1", order_id: String, item: String)
  Shipment = AgentSpaces::Entry.define("rbmcp.Shipment#v1", order_id: String, by: String)
end

# A fleet's actions served as MCP tools through the official SDK.
class MCPTest < Minitest::Test
  class Fulfiller
    include AgentSpaces::Agent
    agent "fulfiller", description: "Ships orders"

    take MShop::Order, space: "orders", lease: "30s", poll_timeout: "300ms", produces: MShop::Shipment
    def ship(order) = MShop::Shipment.new(order_id: order.order_id, by: "mcp-fleet")
  end

  def test_tools_list_and_call_reach_the_fleet
    worker, gateway = AgentSpaces::Testing::Network.fleet("zRubyMCP", 2)
    bound = worker.bind(Fulfiller.new)
    deadline = Time.now + 5
    sleep 0.05 until !gateway.cards.empty? || Time.now > deadline
    server = AgentSpaces::MCP.server(gateway, name: "shop", timeout: 10)
    listed = server.handle({ jsonrpc: "2.0", id: 1, method: "tools/list" })
    tool = listed[:result][:tools].first
    assert_equal "ship", tool[:name]
    assert_equal %w[order_id item], tool[:inputSchema][:required]
    called = server.handle({ jsonrpc: "2.0", id: 2, method: "tools/call",
                             params: { name: "ship", arguments: { order_id: "o-1", item: "kite" } } })
    text = called[:result][:content].first[:text]
    assert_equal({ "orderId" => "o-1", "by" => "mcp-fleet" }, JSON.parse(text))
    refute called[:result][:isError]
  ensure
    bound&.close
    [worker, gateway].each { |p| p&.close }
  end
end
