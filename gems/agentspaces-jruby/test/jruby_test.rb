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
require "socket"
require "agentspaces/jruby"

module JShop
  Order = AgentSpaces::Entry.define("rbjr.shop.Order#v1", order_id: String, item: String, quantity: Integer,
                                                          notes: [String])
  Shipment = AgentSpaces::Entry.define("rbjr.shop.Shipment#v1", order_id: String, item: String, by: String,
                                                                weight: Float)
  Receipt = AgentSpaces::Entry.define("rbjr.shop.Receipt#v1", order_id: String)
end

# The JRuby face: the same agent DSL bound through the Java binder over a
# FleetRuntime, with records generated from the Ruby entries.
class JRubyFaceTest < Minitest::Test
  class Fulfiller
    include AgentSpaces::Agent
    agent "jr-fulfiller", description: "Ships orders on the Java binder", goals: ["ship"]
    attr_reader :audited

    def initialize = @audited = Queue.new

    take JShop::Order, space: "orders", lease: "30s", where: { quantity: 1.. }, pre: ["order.paid"],
                       post: ["order.shipped"], cost: "PT2M", produces: JShop::Shipment
    def ship(order)
      JShop::Shipment.new(order_id: order.order_id, item: order.item, by: "jruby", weight: order.quantity)
    end

    notify JShop::Shipment, space: "orders", produces: JShop::Receipt
    def audit(shipment)
      @audited << shipment.order_id
      JShop::Receipt.new(order_id: shipment.order_id)
    end

    ballot space: "votes", prefix: "rel:"
    def judge(proposal) = proposal.question.include?("ship") ? "yes" : nil
  end

  def free_port
    server = TCPServer.new("127.0.0.1", 0)
    server.addr[1]
  ensure
    server&.close
  end

  def fleet(port, seeds = [])
    AgentSpaces::JRuby::Fleet.start(
      "security" => { "profile" => "dev-local" }, "bind" => "127.0.0.1:#{port}", "tick-millis" => 100,
      "groups" => [{ "name" => "shop", "founding" => "rbjr-shop-v1", "seeds" => seeds, "spaces" => %w[orders votes] }]
    )
  end

  def eventually(timeout = 20)
    deadline = Time.now + timeout
    sleep 0.1 until (value = yield) || Time.now > deadline
    value || yield
  end

  def test_a_ruby_agent_binds_on_the_java_binder_and_serves_a_second_member
    port = free_port
    worker = fleet(port)
    fulfiller = Fulfiller.new
    bound = worker.bind(fulfiller)
    assert_equal 1, bound.size, "one Bound per group the agent names"
    card = bound.first.card
    assert_equal "jr-fulfiller", card.agent.localName
    assert_equal %w[audit judge ship], card.actions.to_a.map(&:name).sort
    contract = card.actions.to_a.find { |a| a.name == "ship" }.contract
    assert_equal [["order.paid"], ["order.shipped"], "PT2M"], [contract.pre.to_a, contract.post.to_a, contract.cost]
    assert_includes card.consumes.to_a, "rbjr.shop.Order#v1"

    client = fleet(free_port, ["127.0.0.1:#{port}"])
    client.write("orders", JShop::Order.new(order_id: "o-1", item: "kite", quantity: 2, notes: ["fragile"]))
    shipment = eventually { client.all("orders", JShop::Shipment).first }
    assert_equal JShop::Shipment.new(order_id: "o-1", item: "kite", by: "jruby", weight: 2.0), shipment
    assert_equal "o-1", fulfiller.audited.pop(timeout: 10)
    assert_equal "o-1", eventually { client.all("orders", JShop::Receipt).first }&.order_id
  ensure
    client&.close
    worker&.close
  end

  class Clerk
    include AgentSpaces::Agent
    ordered_take JShop::Order, space: "orders", pre: ["order.paid"], cost: "1", produces: JShop::Receipt
    def file(order) = JShop::Receipt.new(order_id: order.order_id)
  end

  def test_an_ordered_take_compiles_to_ordered_take_and_the_java_binder_judges_it
    worker = fleet(free_port)
    error = assert_raises(Java::JavaLang::IllegalStateException, Java::JavaLang::IllegalArgumentException) do
      worker.bind(Clerk.new)
    end
    assert_match(/ordered|log/i, error.message)
    source = AgentSpaces::JRuby::JavaSource.interface(Clerk.agentspaces_model,
                                                      { JShop::Order => "rbjr.shop.Order",
                                                        JShop::Receipt => "rbjr.shop.Receipt" }).last
    assert_includes source, "@ai.badmonkey.agentspaces.agent.annotation.OrderedTake(space = \"orders\""
    assert_includes source, 'pre = {"order.paid"}, cost = "1"'
    refute_includes source, "post ="
  ensure
    worker&.close
  end

  def test_hostile_option_values_never_reach_java_source_unescaped
    names = { JShop::Order => "rbjr.shop.Order" }
    literal = AgentSpaces::JRuby::JavaSource.literal("\"); System.exit(1); (\"\\ \n")
    assert_equal '"\\"); System.exit(1); (\\"\\\\\\u2028\\012"', literal
    assert_raises(AgentSpaces::EngineUnsupported) { AgentSpaces::JRuby::JavaSource.identifier!("ship!", "method") }
    assert_raises(AgentSpaces::EngineUnsupported) { AgentSpaces::JRuby::JavaSource.class_name("../evil#v1") }
    assert_raises(AgentSpaces::EngineUnsupported) do
      AgentSpaces::JRuby::JavaSource.where_clauses(JShop::Order, { item: /kite/ })
    end
    assert_equal ["quantity>=1", "quantity<5", "item in a,b", "orderId=x"],
                 AgentSpaces::JRuby::JavaSource.where_clauses(JShop::Order, { quantity: 1...5, item: %w[a b],
                                                                              order_id: "x" })
    source = AgentSpaces::JRuby::JavaSource.record(JShop::Order, names)
    assert_includes source, "public record Order(String orderId, String item, long quantity, java.util.List<String> notes)"
  end
end
