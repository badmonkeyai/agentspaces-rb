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

require "minitest/autorun"
require "agentspaces"
require "agentspaces/mcp"
require "agentspaces/testing"
require "rack/mock"

module MShop
  Order = AgentSpaces::Entry.define("rbmcp.Order#v1", order_id: String, item: String)
  Shipment = AgentSpaces::Entry.define("rbmcp.Shipment#v1", order_id: String, by: String)
  Return = AgentSpaces::Entry.define("rbmcp.Return#v1", order_id: String)
end

# A fleet's actions served as MCP tools through the official SDK.
class MCPTest < Minitest::Test
  class Fulfiller
    include AgentSpaces::Agent
    agent "fulfiller", description: "Ships orders"

    take MShop::Order, space: "orders", lease: "30s", poll_timeout: "300ms", produces: MShop::Shipment
    def ship(order) = MShop::Shipment.new(order_id: order.order_id, by: "mcp-fleet")
  end

  # A different action that happens to share the name "ship".
  class Returns
    include AgentSpaces::Agent
    agent "returns", description: "Ships returns back"

    take MShop::Return, space: "returns", lease: "30s", poll_timeout: "300ms", produces: MShop::Shipment
    def ship(ret) = MShop::Shipment.new(order_id: ret.order_id, by: "returns")
  end

  # Records the notifications a server sends, as a transport would deliver them.
  class RecordingTransport < MCP::Transport
    attr_reader :sent

    def initialize(server)
      super
      @sent = []
    end

    def send_notification(method, params = nil, **) = @sent << [method, params]
  end

  def setup
    @bound = []
    @peers = []
  end

  def teardown
    @bound.each(&:close)
    @peers.each(&:close)
  end

  def fleet(count)
    peers = AgentSpaces::Testing::Network.fleet("zRubyMCP", count)
    @peers.concat(peers)
    peers
  end

  def bind(peer, agent) = @bound << peer.bind(agent)

  def wait_for(seconds = 5)
    deadline = Time.now + seconds
    sleep 0.05 until yield || Time.now > deadline
    assert yield, "condition not met within #{seconds}s"
  end

  def call(server, name, arguments, id: 2)
    server.handle({ jsonrpc: "2.0", id: id, method: "tools/call", params: { name: name, arguments: arguments } })[:result]
  end

  def listed(server) = server.handle({ jsonrpc: "2.0", id: 1, method: "tools/list" })[:result][:tools]

  def test_tools_list_and_call_reach_the_fleet
    worker, gateway = fleet(2)
    bind(worker, Fulfiller.new)
    wait_for { !gateway.cards.empty? }
    server = AgentSpaces::MCP.server(gateway, name: "shop", timeout: 10)
    tool = listed(server).first
    assert_equal "ship", tool[:name]
    assert_equal %w[order_id item], tool[:inputSchema][:required]
    called = call(server, "ship", { order_id: "o-1", item: "kite" })
    assert_equal({ "orderId" => "o-1", "by" => "mcp-fleet" }, JSON.parse(called[:content].first[:text]))
    refute called[:isError]
  end

  def test_replicas_of_one_worker_are_one_tool
    a, b, gateway = fleet(3)
    bind(a, Fulfiller.new)
    bind(b, Fulfiller.new)
    wait_for { gateway.cards.size >= 2 }
    server = AgentSpaces::MCP.server(gateway, timeout: 10) # two cards declaring "ship" used to raise ToolNotUnique
    tools = listed(server)
    assert_equal ["ship"], tools.map { |t| t[:name] }
    assert_includes tools.first[:description], "2 replicas"
    called = call(server, "ship", { order_id: "o-2", item: "kite" })
    refute called[:isError]
    assert_equal "o-2", JSON.parse(called[:content].first[:text])["orderId"]
  end

  def test_different_actions_sharing_a_name_get_stable_distinct_names
    a, b, gateway = fleet(3)
    bind(a, Fulfiller.new)
    bind(b, Returns.new)
    wait_for { gateway.cards.size >= 2 }
    names = AgentSpaces::MCP.offerings(gateway).map(&:name)
    assert_equal 2, names.uniq.size
    assert(names.all? { |n| n.match?(/\Aship_[0-9a-f]{8}\z/) }, names.inspect)
    assert_equal names, AgentSpaces::MCP.offerings(gateway).map(&:name), "the same names on every build"
    server = AgentSpaces::MCP.server(gateway, timeout: 10)
    returns = listed(server).find { |t| t[:description].include?("rbmcp.Return#v1") }
    called = call(server, returns[:name], { order_id: "r-1" })
    assert_equal "returns", JSON.parse(called[:content].first[:text])["by"]
  end

  def test_a_revoked_agents_card_offers_no_tool_and_its_tool_refuses_calls
    worker, gateway = fleet(2)
    bind(worker, Fulfiller.new)
    wait_for { !gateway.cards.empty? }
    server = AgentSpaces::MCP.server(gateway, timeout: 10)
    agent = gateway.cards.first["agent"]
    # As an accepted credential revocation of the agent leaves it in the registry.
    gateway.revocations.credentials["AGENT:#{agent}"] = [2, 0, "test", { "reason" => "RETIRED", "issued" => "1970-01-01T00:00:00Z" }]
    assert_empty gateway.cards, "a revoked agent advertises nothing"
    assert_empty AgentSpaces::MCP.offerings(gateway)
    called = call(server, "ship", { order_id: "o-3", item: "kite" })
    assert called[:isError]
    assert_match(/no longer offered/, called[:content].first[:text])
  end

  def test_a_revoked_peers_cards_are_dropped
    worker, gateway = fleet(2)
    bind(worker, Fulfiller.new)
    wait_for { !gateway.cards.empty? }
    gateway.revocations.peers[worker.identity.peer_id] = [1, 0, "test", {}]
    assert_empty gateway.cards
  end

  def test_the_gateway_follows_the_fleet_and_tells_clients
    a, b, gateway_peer = fleet(3)
    bind(a, Fulfiller.new)
    wait_for { !gateway_peer.cards.empty? }
    gateway = AgentSpaces::MCP.gateway(gateway_peer, timeout: 10)
    transport = RecordingTransport.new(gateway.server)
    assert_equal ["ship"], gateway.tool_names
    refute gateway.refresh, "nothing changed"
    assert_empty transport.sent
    bind(b, Returns.new)
    wait_for { gateway_peer.cards.size >= 2 }
    assert gateway.refresh
    assert_equal 2, gateway.tool_names.size
    assert_equal [["notifications/tools/list_changed", nil]], transport.sent
    assert_equal 2, listed(gateway.server).size
  ensure
    gateway&.close
  end

  def test_the_gateway_refreshes_on_an_interval
    a, b, gateway_peer = fleet(3)
    bind(a, Fulfiller.new)
    wait_for { !gateway_peer.cards.empty? }
    gateway = AgentSpaces::MCP.gateway(gateway_peer, timeout: 10, refresh_every: 0.1)
    bind(b, Returns.new)
    wait_for { gateway.tool_names.size == 2 }
  ensure
    gateway&.close
  end

  def test_only_limits_what_is_offered
    a, b, gateway = fleet(3)
    bind(a, Fulfiller.new)
    bind(b, Returns.new)
    wait_for { gateway.cards.size >= 2 }
    server = AgentSpaces::MCP.server(gateway, only: ->(action) { action.consumes == "rbmcp.Order#v1" })
    assert_equal ["ship"], listed(server).map { |t| t[:name] }
  end

  def test_authorize_sees_the_action_and_the_token
    worker, gateway = fleet(2)
    bind(worker, Fulfiller.new)
    wait_for { !gateway.cards.empty? }
    seen = []
    policy = lambda do |action, auth|
      seen << [action.consumes, auth]
      false
    end
    server = AgentSpaces::MCP.server(gateway, timeout: 10, authorize: policy)
    called = call(server, "ship", { order_id: "o-4", item: "kite" })
    assert called[:isError]
    assert_match(/not authorized/, called[:content].first[:text])
    assert_equal [["rbmcp.Order#v1", nil]], seen, "over stdio there is no token"
  end

  def test_http_needs_a_token_verifier_unless_told_otherwise
    _, gateway = fleet(2)
    server = AgentSpaces::MCP.server(gateway)
    error = assert_raises(ArgumentError) { AgentSpaces::MCP.http(server) }
    assert_match(/token_verifier/, error.message)
    assert AgentSpaces::MCP.http(server, allow_unauthenticated: true, stateless: true)
  end

  def test_static_tokens_verify_in_constant_time_and_carry_scopes
    tokens = AgentSpaces::MCP::StaticTokens.new("s3cret" => %w[orders:write])
    assert_equal %w[orders:write], tokens.verify("s3cret").scopes
    assert_nil tokens.verify("s3creT")
    assert_nil tokens.verify("")
    assert_raises(ArgumentError) { AgentSpaces::MCP::StaticTokens.new({}) }
    assert_raises(ArgumentError) { AgentSpaces::MCP::StaticTokens.new(" " => []) }
  end

  def test_streamable_http_refuses_without_a_token_and_serves_with_one
    worker, gateway = fleet(2)
    bind(worker, Fulfiller.new)
    wait_for { !gateway.cards.empty? }
    granted = []
    policy = lambda do |_action, auth|
      granted << auth&.scopes
      auth&.scopes&.include?("orders:write")
    end
    server = AgentSpaces::MCP.server(gateway, timeout: 10, authorize: policy)
    app = AgentSpaces::MCP.http(server, token_verifier: AgentSpaces::MCP::StaticTokens.new("s3cret" => %w[orders:write]),
                                        stateless: true, enable_json_response: true)
    post = lambda do |body, token|
      headers = { "CONTENT_TYPE" => "application/json", "HTTP_ACCEPT" => "application/json, text/event-stream",
                  "HTTP_HOST" => "127.0.0.1", input: JSON.generate(body) }
      headers["HTTP_AUTHORIZATION"] = "Bearer #{token}" if token
      Rack::MockRequest.new(app).post("/mcp", headers)
    end
    list = { jsonrpc: "2.0", id: 1, method: "tools/list" }
    assert_equal 401, post.call(list, nil).status
    assert_equal 401, post.call(list, "wrong").status
    listed = post.call(list, "s3cret")
    assert_equal 200, listed.status, listed.body
    assert_equal ["ship"], JSON.parse(listed.body)["result"]["tools"].map { |t| t["name"] }
    called = post.call({ jsonrpc: "2.0", id: 2, method: "tools/call",
                         params: { name: "ship", arguments: { order_id: "o-5", item: "kite" } } }, "s3cret")
    assert_equal 200, called.status, called.body
    result = JSON.parse(called.body)["result"]
    refute result["isError"], result.inspect
    assert_equal "o-5", JSON.parse(result["content"].first["text"])["orderId"]
    assert_equal [%w[orders:write]], granted, "the verified token reached the policy"
  end
end
