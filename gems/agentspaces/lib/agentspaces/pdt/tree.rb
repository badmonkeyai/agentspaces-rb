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

require "openssl"
require "set"

module AgentSpaces
  module PDT
    # The tree exchange over the content swarm (srad/agentspaces-pdt.md 3.5 and
    # 10.2; PD-X-01 to PD-X-06, PD-C-06): tags 8 to 11 inside
    # aspace:cap/content-swarm pipe frames. The Ruby face is a fetcher only: it
    # asks NODE_WANT and TREE_WANT of members whose newest content-swarm
    # advertisement carries trees = "1", verifies every node against a CID it
    # asked for or reached through a verified parent, drops an unsolicited
    # answer, and strikes a sender whose node matches nothing. It serves no
    # node: a dial-only peer holds nothing a holder cannot serve better.
    module Tree
      TYPE = "aspace:cap/content-swarm"
      NODE_WANT = 8
      NODES = 9
      TREE_WANT = 10
      TREE_END = 11
      REJECT = 5
      TREE_INDEX = -1
      END_DONE = 1
      END_BUDGET = 2
      END_HAVES_NOT_HELD = 3
      END_WALK_CAP = 4
      MAX_WANT_CIDS = 256
      MAX_NODES_BYTES = 4 * 1024 * 1024
      MAX_HAVES = 64
      MAX_TREE_BUDGET = 64 * 1024 * 1024
      MAX_FRONTIER = 1024
      SEALING_AAD_PREFIX = "aspace:pdt|"
      TREES_PARAMETER = "trees"
      TREES_VERSION = "1"
      SEALING_GROUP_KEY = "group-key"

      module_function

      def node_want(req, cids) = { "t" => NODE_WANT, "req" => Integer(req), "cids" => cids.to_a }

      def nodes_message(req, nodes, sealed, epoch, missing)
        { "t" => NODES, "req" => Integer(req), "nodes" => nodes, "sealed" => sealed, "epoch" => epoch, "missing" => missing }
      end

      def tree_want(req, root, haves, budget, sketch = nil)
        { "t" => TREE_WANT, "req" => Integer(req), "root" => root, "haves" => haves, "budget" => Integer(budget), "sketch" => sketch }
      end

      def tree_end(req, frontier, reason) = { "t" => TREE_END, "req" => Integer(req), "frontier" => frontier.to_a, "reason" => Integer(reason) }

      def reject(root, index, reason) = { "t" => REJECT, "root" => root, "index" => Integer(index), "reason" => Integer(reason) }

      def cid_list(value, bound, what)
        return "#{what} is not a list" unless value.is_a?(Array)
        return "#{what} names more than #{bound} cids" if value.size > bound

        value.each { |c| return "#{what} carries a malformed cid" unless Cids.cid?(c) }
        nil
      end

      # The first broken bound of a tree message (PD-X-02), or nil.
      def violation(msg)
        return "not a map" unless msg.is_a?(Hash)

        t = msg["t"]
        return "req is not an integer" unless msg["req"].is_a?(Integer)

        case t
        when NODE_WANT
          return "a NODE_WANT names at least one cid" unless msg["cids"].is_a?(Array) && !msg["cids"].empty?

          cid_list(msg["cids"], MAX_WANT_CIDS, "cids")
        when NODES
          plain = msg["nodes"]
          sealed = msg["sealed"]
          return "a NODES carries exactly one of nodes and sealed" if plain.nil? == sealed.nil?
          return "epoch is present exactly when sealed is" if sealed.nil? != msg["epoch"].nil?

          if !plain.nil?
            return "nodes is not a list of byte strings" unless plain.is_a?(Array) && plain.all? { |n| n.is_a?(String) }
            return "a NODES carries at most #{MAX_NODES_BYTES} bytes of nodes" if plain.sum(&:bytesize) > MAX_NODES_BYTES
          elsif !sealed.is_a?(String) || sealed.bytesize > MAX_NODES_BYTES
            return "a NODES carries at most #{MAX_NODES_BYTES} sealed bytes"
          end
          msg["missing"].nil? ? nil : cid_list(msg["missing"], MAX_WANT_CIDS, "missing")
        when TREE_WANT
          return "root is not a cid" unless Cids.cid?(msg["root"])

          unless msg["haves"].nil?
            bad = cid_list(msg["haves"], MAX_HAVES, "haves")
            return bad if bad
          end
          budget = msg["budget"]
          return "budget is not in (0, #{MAX_TREE_BUDGET}]" unless budget.is_a?(Integer) && budget.positive? && budget <= MAX_TREE_BUDGET

          nil
        when TREE_END
          bad = cid_list(msg["frontier"], MAX_FRONTIER, "frontier")
          return bad if bad
          return "unknown TREE_END reason" unless [END_DONE, END_BUDGET, END_HAVES_NOT_HELD, END_WALK_CAP].include?(msg["reason"])

          nil
        else
          "not a tree message: tag #{t}"
        end
      end

      def sealing_aad(recipient, req) = "#{SEALING_AAD_PREFIX}#{recipient}|#{req}".b

      # Opens a sealed node list (group-key mode): nonce || ciphertext || tag under
      # AES-256-GCM with the AAD, trying each key; nil when none opens it.
      def open_nodes(keys, sealed, aad)
        return nil if sealed.bytesize < 12 + 16

        nonce = sealed.byteslice(0, 12)
        tag = sealed.byteslice(sealed.bytesize - 16, 16)
        ciphertext = sealed.byteslice(12, sealed.bytesize - 28)
        keys.each do |key|
          cipher = OpenSSL::Cipher.new("aes-256-gcm").decrypt
          cipher.key = key
          cipher.iv = nonce
          cipher.auth_tag = tag
          cipher.auth_data = aad
          begin
            plain = cipher.update(ciphertext) + cipher.final
          rescue OpenSSL::Cipher::CipherError
            next
          end
          value = begin
            CBOR.load(plain)
          rescue CBOR::Error
            return nil
          end
          return value if value.is_a?(Array) && value.all? { |n| n.is_a?(String) }

          return nil
        end
        nil
      end
    end

    # One fetch: a tree under a root (every node absent under the haves), or a
    # bare batch of nodes. Frames arrive on the peer's read thread; a caller
    # waits on the fetch from its own.
    class TreeFetch
      Request = Struct.new(:req, :source, :kind, :cids, :subtree, :sent_at)

      attr_reader :root, :bare, :haves, :failure, :nodes_received, :bytes_received, :sources, :struck, :round_trips

      def initialize(trees, root, haves, prefer, timeout, bare: nil)
        @trees = trees
        @root = root
        @bare = bare
        @haves = haves.first(Tree::MAX_HAVES)
        @prefer = prefer
        @timeout = timeout
        @store = trees.store
        @lock = Mutex.new
        @cv = ConditionVariable.new
        @done = false
        @failure = nil
        @expected = {}
        (bare || [root]).each { |c| @expected[c] = true }
        @frontier = []
        @in_flight = {}
        @outstanding = {}
        @missing_at = Hash.new { |h, k| h[k] = Set.new }
        @dropped = Set.new
        @timeouts = Hash.new(0)
        @sources = []
        @tree_want_sent = false
        @outbox = []
        @nodes_received = 0
        @bytes_received = 0
        @struck = 0
        @round_trips = 0
        @started_at = monotonic
      end

      def monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      def done? = @done

      def complete?
        return @failure.nil? && @done if @done

        false
      end

      def start
        with_lock do
          @sources = @trees.sources(@prefer)
          schedule
        end
        self
      end

      # Waits up to timeout seconds (the fetch's own by default) for completion; whether it completed.
      def wait(timeout = nil)
        deadline = monotonic + (timeout || @timeout)
        until @done
          now = monotonic
          break if now >= deadline

          with_lock do
            tick_locked(now)
            @cv.wait(@lock, [0.05, deadline - now].min) if !@done && @outbox.empty?
          end
        end
        with_lock { finish("timed out after #{@timeout}s (sources tried: #{@sources.inspect})") unless @done }
        complete?
      end

      # Times out stale requests and retries them on another source.
      def tick
        with_lock { tick_locked(monotonic) }
      end

      def progress
        @lock.synchronize do
          { "root" => @root, "complete" => complete?, "nodesReceived" => @nodes_received, "bytesReceived" => @bytes_received,
            "outstanding" => @outstanding.size, "frontier" => @frontier.size, "sources" => @sources - @dropped.to_a,
            "roundTrips" => @round_trips, "failure" => @failure }
        end
      end

      # ---- frames (called by Trees on the read thread)

      def on_nodes(sender, msg)
        with_lock do
          request = @outstanding[msg["req"]]
          return if request.nil? || request.source != sender || @done

          nodes = @trees.open(sender, msg["req"], msg)
          if nodes.nil?
            @trees.count(:nodes_unopenable)
            release(request)
            drop(sender)
            schedule
            return
          end
          @round_trips += 1
          nodes.each do |data|
            if accept(request, data)
              @nodes_received += 1
              @bytes_received += data.bytesize
            else
              @struck += 1
              @trees.count(:nodes_struck)
              @trees.strike(sender)
              drop(sender)
              release(request)
              schedule
              return
            end
          end
          Array(msg["missing"]).each { |c| @missing_at[sender] << c }
          release(request) if request.kind == :node_want
          schedule
        end
      end

      def on_tree_end(sender, msg)
        with_lock do
          request = @outstanding[msg["req"]]
          return if request.nil? || request.source != sender || @done

          Array(msg["frontier"]).each do |cid|
            next if @store.has?(cid)

            @expected[cid] = true
            @frontier << cid unless @frontier.include?(cid) || @in_flight.key?(cid)
          end
          release(request)
          schedule
        end
      end

      def on_reject(sender, msg)
        with_lock do
          hits = @outstanding.values.select do |r|
            r.source == sender && (r.kind == :tree_want ? r.subtree == msg["root"] : r.cids.first == msg["root"])
          end
          return if hits.empty? || @done

          @trees.count(:tree_requests_rejected)
          hits.each { |r| release(r) }
          drop(sender)
          schedule
        end
      end

      private

      # Runs the body under the lock, then sends what it queued with the lock released, so a
      # holder that answers on this thread (an in-memory transport) never re-enters the lock.
      def with_lock
        result = @lock.synchronize { yield }
        loop do
          batch = @lock.synchronize { @outbox.dup.tap { @outbox.clear } }
          break if batch.empty?

          batch.each { |to, msg| @trees.send_message(to, msg) }
        end
        result
      end

      def finish(failure)
        @failure = failure
        @done = true
        @cv.broadcast
        @trees.finished(self)
      end

      def live_sources = @sources.reject { |s| @dropped.include?(s) }

      def drop(source) = @dropped << source

      def release(request)
        @outstanding.delete(request.req)
        @in_flight.delete_if { |_, req| req == request.req }
      end

      def tick_locked(now)
        return if @done

        stale = @outstanding.values.select { |r| now - r.sent_at > @trees.request_timeout }
        stale.each do |r|
          release(r)
          @timeouts[r.source] += 1
          drop(r.source) if @timeouts[r.source] >= 2
        end
        schedule unless stale.empty?
      end

      def complete_now?
        if @bare
          @bare.all? { |c| @store.has?(c) }
        else
          @store.has?(@root) && @store.complete?(@root)
        end
      end

      def unobtainable?
        return false if @bare.nil?

        live = live_sources
        @bare.any? { |c| !@store.has?(c) && live.all? { |s| @missing_at[s].include?(c) } }
      end

      def schedule
        return if @done

        if complete_now?
          @done = true
          @cv.broadcast
          @trees.finished(self)
          return
        end
        sources = live_sources
        if sources.empty?
          return finish("no member advertises the tree exchange (content-swarm parameter trees)") if @sources.empty?

          return finish("every source refused, timed out, or was struck (sources tried: #{@sources.inspect})")
        end
        return finish("not held by any source (sources tried: #{@sources.inspect})") if unobtainable?

        if @bare.nil?
          holder = sources.find { |s| !@missing_at[s].include?(@root) }
          if !@store.has?(@root)
            unless @in_flight.key?(@root)
              return finish("root #{@root} is not held by any source (sources tried: #{@sources.inspect})") if holder.nil?

              send_node_want(holder, [@root])
            end
          elsif !@tree_want_sent
            @tree_want_sent = true
            refresh_expected(@root)
            send_tree_want(holder || sources.first, @root)
          end
        end
        @frontier = @frontier.reject { |c| @store.has?(c) } unless @bare
        # A subtree walk in flight brings the frontier under it: ask for the rest once it closes (PD-X-04).
        return if @bare.nil? && @outstanding.values.any? { |r| r.kind == :tree_want }

        wanted = (@bare || @frontier).reject { |c| @store.has?(c) || @in_flight.key?(c) }
        return if wanted.empty?

        i = 0
        wanted.each_slice(Tree::MAX_WANT_CIDS) do |batch|
          source = nil
          sources.size.times do
            candidate = sources[i % sources.size]
            i += 1
            next if batch.all? { |c| @missing_at[candidate].include?(c) }

            source = candidate
            break
          end
          next if source.nil?

          send_node_want(source, batch.reject { |c| @missing_at[source].include?(c) })
        end
      end

      def refresh_expected(cid)
        @store.links(cid).each do |link|
          next if @store.has?(link)

          @expected[link] = true
          @frontier << link unless @frontier.include?(link) || @in_flight.key?(link)
        end
      end

      def send_node_want(source, cids)
        return if cids.empty?

        req = @trees.next_req
        cids.each { |c| @in_flight[c] = req }
        @outstanding[req] = Request.new(req, source, :node_want, cids, nil, monotonic)
        @trees.register(req, self)
        @outbox << [source, Tree.node_want(req, cids)]
      end

      def send_tree_want(source, subtree)
        req = @trees.next_req
        @outstanding[req] = Request.new(req, source, :tree_want, [], subtree, monotonic)
        @trees.register(req, self)
        @outbox << [source, Tree.tree_want(req, subtree, @haves.empty? ? nil : @haves, @trees.budget)]
      end

      # Verifies one node against what this fetch asked for or reached (PD-X-04); stores it and
      # extends the frontier with the links the store lacks.
      def accept(request, data)
        digest = Cids.sha256(data)
        candidates = [Cids.of_digest(digest, Cids::DAG_CBOR), Cids.of_digest(digest, Cids::RAW)]
        cid = candidates.find { |c| (request.kind == :node_want && request.cids.include?(c)) || @expected.key?(c) }
        return false if cid.nil?

        begin
          @store.put_verified(cid, data)
        rescue NodeFormatError
          return false
        end
        @in_flight.delete(cid)
        @frontier.delete(cid)
        return true if @bare

        links = begin
          @store.links(cid, data)
        rescue NodeFormatError
          []
        end
        links.each do |link|
          next if @store.has?(link)

          @expected[link] = true
          @frontier << link unless @frontier.include?(link) || @in_flight.key?(link)
        end
        true
      end
    end

    # The fetcher attached to a peer: the content-swarm pipe handler for tags 8
    # to 11, the sources that advertise trees, and the fetches in flight.
    class Trees
      attr_reader :peer, :store, :request_timeout, :budget, :load_timeout, :stats

      def initialize(peer, store, keys: {}, load_timeout: 10.0, request_timeout: 5.0, budget: Tree::MAX_TREE_BUDGET)
        @peer = peer
        @store = store
        @keys = keys
        @load_timeout = load_timeout
        @request_timeout = request_timeout
        @budget = budget
        @req = 0
        @by_req = {}
        @fetches = []
        @lock = Mutex.new
        @stats = Hash.new(0)
        previous = peer.pipe_handlers[Tree::TYPE]
        peer.pipe_handlers[Tree::TYPE] = lambda do |sender, payload|
          handled = on_frame(sender, payload)
          previous&.call(sender, payload) unless handled
        end
      end

      def count(name) = @lock.synchronize { @stats[name] += 1 }

      def strike(sender)
        @lock.synchronize { @stats[:struck_senders] += 1 }
        @peer.logger&.warn("pdt: #{sender} sent a node that matches nothing this fetch asked for")
      end

      def next_req = @lock.synchronize { @req += 1 }

      def register(req, fetch) = @lock.synchronize { @by_req[req] = fetch }

      def finished(fetch)
        @lock.synchronize do
          @fetches.delete(fetch)
          @by_req.delete_if { |_, f| f.equal?(fetch) }
        end
      end

      def active_fetches = @lock.synchronize { @fetches.dup }

      def send_message(to, msg)
        @peer.send_pipe(to, Tree::TYPE, CBOR.dump(msg), via: @peer.relay_for(to))
      end

      # The newest unexpired content-swarm advertisement's parameters of a member, or nil.
      def ad_parameters(peer_id)
        now = @peer.now_ms
        best = nil
        @peer.ads.each_value do |e|
          ad = e["ad"] || {}
          next unless e["type"] == "CapabilityAdvertisement" && e["issuer"] == peer_id && ad["capabilityType"] == Tree::TYPE
          next if e.fetch("expires", 0) <= now

          best = ad if best.nil? || ad["issued"].to_s > best["issued"].to_s
        end
        best.nil? ? nil : (best["parameters"] || {})
      end

      # Whether a member's newest content-swarm advertisement carries trees = "1" (PD-X-01).
      def advertises_trees?(peer_id)
        params = ad_parameters(peer_id)
        !params.nil? && params[Tree::TREES_PARAMETER] == Tree::TREES_VERSION
      end

      # The members tags 8 to 11 may go to, the preferred ones first.
      def sources(prefer = [])
        own = @peer.identity.peer_id
        ordered = prefer.to_a + @peer.members.keys
        ordered.uniq.reject { |m| m == own }.select { |m| advertises_trees?(m) }
      end

      # Every node under root absent under the haves this store holds (PD-X-05, PD-X-06).
      def fetch_tree(root, haves: [], prefer: [], timeout: nil)
        Cids.parse(root)
        @lock.synchronize do
          existing = @fetches.find { |f| f.root == root && f.bare.nil? && !f.done? }
          return existing if existing

          f = TreeFetch.new(self, root, haves, prefer, timeout || @load_timeout)
          @fetches << f
          f
        end.start
      end

      # A bare batch: the nodes named, following no links.
      def fetch_nodes(cids, prefer: [], timeout: nil)
        cids.each { |c| Cids.parse(c) }
        f = TreeFetch.new(self, nil, [], prefer, timeout || @load_timeout, bare: cids.to_a)
        @lock.synchronize { @fetches << f }
        f.start
      end

      # The bytes of one node: the store, else a bare batch waited for (PD-V-06).
      def load(cid, prefer: [], timeout: nil)
        data = @store.get(cid)
        return data unless data.nil?

        f = fetch_nodes([cid], prefer: prefer, timeout: timeout)
        f.wait(timeout || @load_timeout)
        data = @store.get(cid)
        raise NodeUnavailable.new(cid, f.sources, "node #{cid} could not be fetched: #{f.failure || 'timed out'}") if data.nil?

        data
      end

      # A loader over the store that fetches what it lacks from the preferred members.
      def loader(prefer = []) = StoreThenFetchLoader.new(@store, ->(cid) { load(cid, prefer: prefer) })

      def open(sender, req, msg)
        return msg["nodes"] unless msg["nodes"].nil?
        return nil if @keys.empty?

        epoch = msg["epoch"]
        keys = @keys.key?(epoch) ? [@keys[epoch]] : @keys.values
        Tree.open_nodes(keys, msg["sealed"], Tree.sealing_aad(@peer.identity.peer_id, req))
      end

      # Routes one content-swarm frame; true when it was a tree frame.
      def on_frame(sender, payload)
        msg = begin
          CBOR.load(payload)
        rescue CBOR::Error
          return false
        end
        return false unless msg.is_a?(Hash)

        case msg["t"]
        when Tree::NODES, Tree::TREE_END
          if (bad = Tree.violation(msg))
            count(:tree_messages_dropped)
            @peer.logger&.debug("pdt: dropped a tag #{msg['t']} frame from #{sender}: #{bad}")
            return true
          end
          f = @lock.synchronize { @by_req[msg["req"]] }
          return true if f.nil?

          msg["t"] == Tree::NODES ? f.on_nodes(sender, msg) : f.on_tree_end(sender, msg)
          true
        when Tree::NODE_WANT, Tree::TREE_WANT
          # A dial-only reader serves nothing: refuse by policy so the asker moves on.
          count(:tree_requests_refused)
          root = msg["t"] == Tree::TREE_WANT ? msg["root"] : Array(msg["cids"]).first
          send_message(sender, Tree.reject(root, Tree::TREE_INDEX, 3)) if root.is_a?(String)
          true
        when Tree::REJECT
          return false unless msg["index"] == Tree::TREE_INDEX

          active_fetches.each { |f| f.on_reject(sender, msg) }
          true
        else
          false
        end
      end
    end
  end
end
