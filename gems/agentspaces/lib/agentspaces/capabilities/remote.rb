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

module AgentSpaces
  module Capabilities
    # One invocable action a card declares: a take binding (a task space and
    # the schema it consumes and produces).
    RemoteAction = Data.define(:card, :name, :description, :consumes, :produces, :space) do
      def agent = card["agent"]
    end

    # Remote actions (RemoteActions, RemoteAction): the actions the fleet's
    # AgentCards declare, invoked by writing the input into the task space
    # and awaiting the correlated result.
    module RemoteActions
      module_function

      # Every invocable action the cached cards declare: a declared take
      # action with one consumed and one produced schema and a space, or, for
      # a card without declared actions, each (consumes, produces, binding) pair.
      # A spilled card is resolved first, since its actions sit in its parts
      # document; one this peer cannot resolve offers no action (AppCard
      # origin and formats, 2026-11-09).
      def actions(peer)
        found = []
        resolved_cards(peer).each do |card|
          declared = Array(card["actions"])
          unless declared.empty?
            declared.each do |a|
              next unless a["kind"] == "take" && a["space"] && !a["space"].to_s.empty?
              next unless Array(a["consumes"]).size == 1 && Array(a["produces"]).size == 1

              description = a["description"].to_s.empty? ? card["description"].to_s : a["description"]
              found << RemoteAction.new(card: card, name: a["name"], description: description,
                                        consumes: a["consumes"][0], produces: a["produces"][0], space: a["space"])
            end
            next
          end
          bindings = card["spaceBindings"] || {}
          Array(card["consumes"]).each do |consumed|
            space = bindings[consumed]
            Array(card["produces"]).each do |produced|
              next if space.nil? || space.to_s.empty?

              found << RemoteAction.new(card: card, name: "#{card['agent'].to_s.split('/').last}_#{consumed}",
                                        description: card["description"].to_s, consumes: consumed,
                                        produces: produced, space: space)
            end
          end
        end
        found
      end

      def resolved_cards(peer)
        peer.cards.filter_map do |card|
          peer.resolve(card)
        rescue StandardError => e
          peer.logger&.debug("remote actions: #{card['id']} stays a stub: #{e.message}")
          nil
        end
      end
      private_class_method :resolved_cards

      # Correlation.sharedFields: every field both carry is equal.
      def shared_fields?(input_payload, candidate)
        input_payload.all? { |k, v| !candidate.key?(k) || candidate[k] == v }
      end

      # Writes value into the action's task space and awaits the first result
      # (of the produced schema, decoded as result_type when given) not
      # present before the write whose shared fields match; nil at the
      # timeout (seconds). A Hash value is written under the consumed schema.
      def invoke(peer, action, value, result_type: nil, timeout_seconds: 30.0, result_space: nil, lease: "10m",
                 agent: nil, agent_name: "ruby")
        task_space = Space.new(peer, action.space, agent: agent, agent_name: agent_name)
        results = Space.new(peer, result_space || action.space, agent: agent, agent_name: agent_name)
        template = Template.new(result_type || action.produces)
        input_payload = Entry.to_payload(value)
        baseline = results.entries(template, limit: 1_000).to_set(&:entry_id)
        task_space.write(value, lease: lease, schema: value.is_a?(Hash) ? action.consumes : nil)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout_seconds
        while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
          results.entries(template, limit: 1_000).each do |e|
            next if baseline.include?(e.entry_id)
            return e.value if shared_fields?(input_payload, payload_of(e.value))
          end
          peer.pull_space(results.name)
          sleep 0.1
        end
        nil
      ensure
        # The call's two spaces leave the peer's observers with it.
        task_space&.close
        results&.close
      end

      # The wire payload of a decoded value: an Entry's, an Unknown's, or a Hash.
      def payload_of(value)
        case value
        when Hash then value
        when Entry::Unknown then value.payload || {}
        else value.respond_to?(:to_payload) ? value.to_payload : {}
        end
      end
    end
  end
end
