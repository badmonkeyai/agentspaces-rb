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

require "delegate"
require "ipaddr"
require "yaml"

module AgentSpaces
  # A configuration the peer cannot run.
  class ConfigError < ArgumentError; end

  # No fleet is reachable for a request that needs one.
  class Unavailable < StandardError; end

  # The fleet configuration: the agentspaces: subtree of the YAML every host
  # reads (the Spring starter, Micronaut, the plain-Java runtime, Groovy, the
  # Node host), in kebab-case keys or their snake_case Ruby forms. The wire
  # peer honours the keys a dial-only peer can use, logs once the ones it
  # cannot (bind, advertise, roles, listener blocks), and ignores the rest,
  # as the Node host ignores keys it does not use. SRAD appendix C.
  class Config
    Group = Data.define(:name, :founding, :group_id, :join, :join_timeout_millis, :seeds, :spaces)

    LISTENER_KEYS = %w[bind advertise roles].freeze
    HONOURED = %w[keystore tick-millis peer-ad-interval-millis card-refresh-millis security groups identity
                  allow-plain transport capabilities coalesce-millis multicast].freeze

    attr_reader :keystore, :tick_millis, :peer_ad_interval_millis, :card_refresh_millis, :profile, :groups,
                :agent_keys, :agent_keystore, :allow_plain, :ignored

    # source: a Hash (with or without the agentspaces: key), a path to a YAML
    # file, or YAML text. Keyword options are the same keys in Ruby form.
    def self.load(source = nil, **options)
      tree =
        case source
        when nil then {}
        when Hash then source
        when String
          text = source.include?("\n") || !File.exist?(source) ? source : File.read(source)
          YAML.safe_load(text, permitted_classes: [], aliases: true) || {}
        else raise ConfigError, "a configuration is a Hash, a YAML path, or YAML text, got #{source.class}"
        end
      tree = normalize(tree)
      tree = tree.fetch("agentspaces", tree)
      new(merge_options(tree, normalize(options)))
    end

    def self.normalize(value)
      case value
      when Hash then value.to_h { |k, v| [k.to_s.tr("_", "-"), normalize(v)] }
      when Array then value.map { |v| normalize(v) }
      else value
      end
    end

    # Ruby shorthand: group:, founding:, group_id:, join:, seeds:, spaces: name one group.
    def self.merge_options(tree, options)
      tree = tree.dup
      shorthand = options.slice("group", "founding", "group-id", "join", "seeds", "spaces")
      rest = options.except(*shorthand.keys)
      unless shorthand.empty?
        group = { "name" => shorthand["group"] || "default" }.merge(shorthand.except("group"))
        tree["groups"] = [group] + Array(tree["groups"])
      end
      tree.merge(rest) { |_k, a, b| a.is_a?(Hash) && b.is_a?(Hash) ? a.merge(b) : b }
    end

    def initialize(tree)
      @ignored = []
      tree.each_key do |key|
        @ignored << key if LISTENER_KEYS.include?(key)
      end
      @keystore = tree["keystore"]
      @tick_millis = Integer(tree.fetch("tick-millis", 250))
      @peer_ad_interval_millis = Integer(tree.fetch("peer-ad-interval-millis", 30_000))
      @card_refresh_millis = Integer(tree.fetch("card-refresh-millis", 300_000))
      security = tree["security"] || {}
      @profile = (security["profile"] || "dev-local").to_s
      identity = tree["identity"] || {}
      @agent_keys = identity["agent-keys"]
      @agent_keystore = identity["agent-keystore"]
      @allow_plain = tree["allow-plain"] == true
      @groups = Array(tree["groups"]).map { |g| group(g) }
      raise ConfigError, "the configuration names no group; add agentspaces.groups[] with a name" if @groups.empty?
    end

    def group_named(name = nil)
      return @groups.first if name.nil?

      @groups.find { |g| g.name == name.to_s } || raise(ConfigError, "no group #{name} in the configuration")
    end

    private

    def group(tree)
      tree = { "name" => tree } if tree.is_a?(String)
      name = tree["name"] or raise ConfigError, "every group needs a name"
      founding = tree["founding"]
      group_id = tree["group-id"]
      join = tree["join"]
      group_id ||= join.delete_prefix(Founding::URI_PREFIX) if join.is_a?(String)
      raise ConfigError, "group #{name} needs founding, group-id, or join" if founding.nil? && group_id.nil?

      seeds = Array(tree["seeds"]).map { |s| Seed.parse(s) }
      spaces = Array(tree["spaces"]).map { |s| s.is_a?(Hash) ? s["name"] : s }.compact.map(&:to_s)
      Group.new(name: name.to_s, founding: founding, group_id: group_id, join: join,
                join_timeout_millis: Integer(tree.fetch("join-timeout-millis", 10_000)), seeds: seeds, spaces: spaces)
    end
  end

  class << self
    # Starts a peer from a configuration (see Config.load) and joins its
    # first group (or group:). A founding: text derives the GroupID; a
    # join: aspace://<id> or group-id: joins by id and needs a group that was
    # founded with a signed founding document.
    def start(source = nil, group: nil, logger: nil, clock: nil, **options, &block)
      options[:group] = group if source.nil? && group
      config = Config.load(source, **options)
      chosen = source.nil? ? config.groups.first : config.group_named(group)
      config.ignored.each { |key| logger&.warn("agentspaces: #{key} is a listener setting; this peer is dial-only") }
      check_seeds!(config, chosen)
      identity = config.keystore ? Identity.load_or_create(config.keystore) : Identity.generate
      group_id = chosen.group_id || Derive.group_id_from_founding(chosen.founding)
      peer = Peer.new(identity, group_id, logger: logger, clock: clock)
      peer.peer_ad_interval = config.peer_ad_interval_millis / 1000.0
      if chosen.founding.nil?
        join_by_id(peer, chosen, group_id)
      else
        peer.connect_any(chosen.seeds)
      end
      chosen.spaces.each { |space| peer.pull_space(space) }
      peer.pull_ads
      block ? yield(peer) : peer
    end
    alias connect start

    # Starts a peer, yields it (bind agents there), blocks until SIGINT or
    # SIGTERM, then unbinds every agent bound through the yielded peer,
    # waits up to drain seconds, and closes the peer.
    def serve(source = nil, drain: 30, **options)
      peer = start(source, **options)
      bound = []
      collector = BoundCollector.new(peer, bound)
      yield collector if block_given?
      stop = Thread::Queue.new
      previous = %w[INT TERM].to_h { |sig| [sig, Signal.trap(sig) { stop << sig }] }
      stop.pop
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + drain
      bound.each { |b| b.close(timeout: [deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC), 0.1].max) }
      peer
    ensure
      previous&.each { |sig, handler| Signal.trap(sig, handler || "DEFAULT") }
      peer&.close
    end

    # The process's lazily started peer (a web process's): one per pid.
    def peer(source = nil, **options)
      @peer_lock ||= Mutex.new
      @peer_lock.synchronize do
        @peer = nil if @peer && (@peer_pid != Process.pid || @peer.closed?)
        @peer_config = [source, options] unless source.nil? && options.empty?
        if @peer.nil?
          raise Unavailable, "AgentSpaces.peer has no configuration; call AgentSpaces.peer(config) once" \
            if @peer_config.nil?

          begin
            @peer = start(@peer_config[0], **@peer_config[1])
          rescue NoSeedError, Timeout::Error => e
            raise Unavailable, "no fleet reachable: #{e.message}"
          end
          @peer_pid = Process.pid
        end
        @peer
      end
    end

    # Restarts the lazily started peer in a forked child (Puma's
    # on_worker_boot, Unicorn's after_fork, Passenger's starting_worker_process).
    def after_fork
      @peer_lock = Mutex.new
      @peer = nil
      nil
    end

    private

    def join_by_id(peer, group, group_id)
      raise ConfigError, "group #{group.name} joins by id and names no seed" if group.seeds.empty?

      errors = []
      group.seeds.each do |seed|
        peer.join_by_group_id(seed.host, seed.port, group_id, timeout: group.join_timeout_millis / 1000.0,
                                                              scheme: seed.scheme, path: seed.path)
        return
      rescue SystemCallError, IOError, Timeout::Error => e
        errors << "#{seed}: #{e.message}"
      end
      raise NoSeedError, "no seed answered the join of #{group_id}: #{errors.join('; ')}"
    end

    def check_seeds!(config, group)
      group.seeds.each do |seed|
        next unless %w[tcp ws http].include?(seed.scheme)
        next if config.allow_plain || loopback?(seed.host)

        raise ConfigError, "seed #{seed} is plain #{seed.scheme} to a non-loopback host; the #{config.profile} " \
                           "profile signs every frame but encrypts nothing, so set allow_plain: true for a closed " \
                           "network or use a tls://, wss://, or https:// seed"
      end
    end

    def loopback?(host)
      return true if host == "localhost"

      IPAddr.new(host).loopback?
    rescue IPAddr::InvalidAddressError
      false
    end
  end

  # What AgentSpaces.serve yields: the peer, recording what it binds so the
  # drain unbinds it.
  class BoundCollector < SimpleDelegator
    def initialize(peer, bound)
      super(peer)
      @bound = bound
    end

    def bind(object, **options)
      handle = __getobj__.bind(object, **options)
      @bound << handle
      handle
    end
  end
end
