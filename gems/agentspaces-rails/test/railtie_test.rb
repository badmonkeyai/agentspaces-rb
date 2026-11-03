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
ENV["RAILS_ENV"] = "test"
ENV["SHOP_SEEDS"] = "127.0.0.1:7811,127.0.0.1:7812"
require "fileutils"
require "tmpdir"
require "minitest/autorun"
require "rails"
require "agentspaces/rails"
require "agentspaces/testing"

ROOT = Dir.mktmpdir("agentspaces-rails")
FileUtils.mkdir_p(File.join(ROOT, "config"))
FileUtils.mkdir_p(File.join(ROOT, "app", "agents"))
File.write(File.join(ROOT, "config", "agentspaces.yml"), <<~YAML)
  default: &default
    agentspaces:
      tick-millis: 250
      groups:
        - name: shop
          founding: shop-v1
          seeds: <%= ENV.fetch("SHOP_SEEDS", "127.0.0.1:7700").split(",") %>
          spaces: [orders]
  test:
    <<: *default
YAML
File.write(File.join(ROOT, "app", "agents", "fulfiller.rb"), <<~RUBY)
  Order = AgentSpaces::Entry.define("shop.Order#v1", order_id: String, item: String)
  Shipment = AgentSpaces::Entry.define("shop.Shipment#v1", order_id: String, item: String, by: String)

  class Fulfiller
    include AgentSpaces::Agent
    agent "fulfiller", description: "Ships orders"

    take Order, space: "orders", lease: "30s", produces: Shipment
    def ship(order) = Shipment.new(order_id: order.order_id, item: order.item, by: "rails")
  end
RUBY

# The dummy application.
class DummyApp < Rails::Application
  config.root = ROOT
  config.eager_load = false
  config.logger = Logger.new(nil)
  config.secret_key_base = "x" * 64
  config.agentspaces.overrides = { "card-refresh-millis" => 60_000 }
end
DummyApp.initialize!

# The Railtie: configuration through config_for, app/agents through
# Zeitwerk, instrumentation of the space verbs, and the fork hook.
class RailtieTest < Minitest::Test
  def test_the_configuration_is_config_for_with_erb_environments_and_overrides
    config = AgentSpaces::Rails.configuration
    assert_equal 250, config["tick-millis"]
    assert_equal 60_000, config["card-refresh-millis"]
    group = config["groups"].first
    assert_equal "shop", group["name"]
    assert_equal ["127.0.0.1:7811", "127.0.0.1:7812"], group["seeds"]
    parsed = AgentSpaces::Config.load(config)
    assert_equal %w[orders], parsed.groups.first.spaces
  end

  def test_agent_classes_load_from_app_agents_through_zeitwerk
    classes = AgentSpaces::Rails.agent_classes
    assert_equal ["Fulfiller"], classes.map(&:name)
    assert_equal "fulfiller", classes.first.agentspaces_model.name
  end

  def test_the_space_verbs_publish_notifications
    events = []
    subscriber = ActiveSupport::Notifications.subscribe(/\.agentspaces\z/) do |name, _s, _f, _id, payload|
      events << [name, payload[:space], payload[:schema]]
    end
    AgentSpaces::Rails.agent_classes # app/agents defines the entries beside the agent
    writer, taker = AgentSpaces::Testing::Network.fleet("zRubyRails", 2)
    order = ::Order.new(order_id: "o-1", item: "kite")
    writer.space("orders") << order
    taker.space("orders").take(::Order, timeout: "3s") { |o| ::Shipment.new(order_id: o.order_id, item: o.item, by: "t") }
    names = events.map(&:first)
    assert_includes events, ["write.agentspaces", "orders", "shop.Order#v1"]
    assert_includes events, ["take.agentspaces", "orders", "shop.Order#v1"]
    assert_includes names, "complete.agentspaces"
  ensure
    ActiveSupport::Notifications.unsubscribe(subscriber) if subscriber
    writer&.close
    taker&.close
  end

  def test_the_worker_task_is_registered
    DummyApp.load_tasks
    assert Rake::Task.task_defined?("agentspaces:work")
    assert Rake::Task.task_defined?("agentspaces:config")
  end

  def test_a_fleet_outage_raises_unavailable_without_stopping_the_process
    error = assert_raises(AgentSpaces::Unavailable) { AgentSpaces::Rails.peer }
    assert_match(/no fleet reachable/, error.message)
  end
end
