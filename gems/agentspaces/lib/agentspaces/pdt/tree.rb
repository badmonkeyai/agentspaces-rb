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
    # aspace:cap/content-swarm pipe frames. The fetcher asks NODE_WANT and
    # TREE_WANT of members whose newest content-swarm advertisement carries
    # trees = "1", verifies every node against a CID it asked for or reached
    # through a verified parent, drops an unsolicited answer, and strikes a
    # sender whose node matches nothing.
    #
    # PDT 2 phase 7 (P2-X-06): the face also serves. It answers NODE_WANT with
    # the nodes its store holds and names the rest missing, and TREE_WANT with a
    # breadth-first walk under the asker's haves and budget closed by TREE_END,
    # as Java's TreeServer does; it refuses a root it lacks with REJECT reason 1,
    # and refuses by policy when the group seals nodes and it holds no content
    # key. Once its Pdt writes a head it advertises trees = "1" and no pdt
    # parameter, so it stays at PDT feature level 1 (P2-C-02).
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
      # PDT 2 phase 7 (P2-X-06): the most nodes one TREE_WANT walk reaches, and
      # the levels a walk sends when it holds none of the asker's haves.
      MAX_WALK_NODES = 100_000
      LEVELS_WITHOUT_HAVES = 2
      # The CBOR framing one node adds inside a NODES, and that of the message,
      # its list, and a seal's nonce and tag, which the packer counts.
      NODE_FRAMING_BYTES = 5
      MESSAGE_FRAMING_BYTES = 33
      REASON_NOT_HELD = 1
      REASON_POLICY = 3
      SEALING_AAD_PREFIX = "aspace:pdt|"
      TREES_PARAMETER = "trees"
      TREES_VERSION = "1"
      SEALING_NONE = "none"
      SEALING_GROUP_KEY = "group-key"
      ADVERTISEMENT_TTL = "PT15M"
      # The advertisement is published again at a third of its time to live.
      ADVERTISE_EVERY = 300
      # PDT 2 phase 1 (P2-X-09): the fields of each message this face reads,
      # in the order Java's Messages records declare and write them (annex I);
      # Java writes a null field as null, so every field is present.
      FIELDS = { NODE_WANT => %w[t req cids], NODES => %w[t req nodes sealed epoch missing],
                 TREE_WANT => %w[t req root haves budget sketch], TREE_END => %w[t req frontier reason],
                 REJECT => %w[t root index reason] }.freeze
      # The piece messages (tags 1 to 7), which this face leaves to the handler before it.
      PIECE_TAGS = (1..7)
      # The values a Java long holds, the type of NODES.epoch.
      JAVA_LONG = (-(1 << 63)..((1 << 63) - 1))

      module_function

      def node_want(req, cids) = { "t" => NODE_WANT, "req" => Integer(req), "cids" => cids.to_a }

      def nodes_message(req, nodes, sealed, epoch, missing)
        { "t" => NODES, "req" => Integer(req), "nodes" => nodes, "sealed" => sealed, "epoch" => epoch, "missing" => missing }
      end

      # PDT 2 phase 0 (srad/agentspaces-pdt2.md 6.10.2, P2-C-02): this face
      # stays at PDT feature level 1, so its TREE_WANT always carries a null
      # sketch, the level-1 form, and it never reconciles by sketch.
      def tree_want(req, root, haves, budget)
        { "t" => TREE_WANT, "req" => Integer(req), "root" => root, "haves" => haves, "budget" => Integer(budget), "sketch" => nil }
      end

      def tree_end(req, frontier, reason) = { "t" => TREE_END, "req" => Integer(req), "frontier" => frontier.to_a, "reason" => Integer(reason) }

      def reject(root, index, reason) = { "t" => REJECT, "root" => root, "index" => Integer(index), "reason" => Integer(reason) }

      def cid_list(value, bound, what)
        return "#{what} is not a list" unless value.is_a?(Array)
        return "#{what} names more than #{bound} cids" if value.size > bound

        value.each { |c| return "#{what} carries a malformed cid" unless cid_text?(c) }
        nil
      end

      # A CID in its one canonical text form, a text string and never a byte string.
      def cid_text?(value) = value.is_a?(String) && value.encoding != Encoding::BINARY && Cids.cid?(value)

      def bytes?(value) = value.is_a?(String) && value.encoding == Encoding::BINARY

      def int?(value) = value.is_a?(Integer) && Refs::JAVA_INT.cover?(value)

      # The first broken bound of a tree message (PD-X-02), or nil. PDT 2
      # phase 1 (P2-X-09): a message reads as its record's own encoding
      # under its annex I schema, as Java's Messages.decode reads it through
      # CborCodec.fromWire; CBOR.load already refused bytes that are not the
      # wire encoding of what they decode to.
      def violation(msg)
        return "not a map" unless msg.is_a?(Hash)

        t = msg["t"]
        fields = FIELDS[t]
        return "not a tree message: tag #{t}" if fields.nil?
        return "fields #{msg.keys.inspect} are not #{fields.inspect} in order" unless msg.keys == fields
        return "req is not a Java int" unless t == REJECT || int?(msg["req"])

        case t
        when REJECT
          return "root is not text" unless msg["root"].is_a?(String) && msg["root"].encoding != Encoding::BINARY

          int?(msg["index"]) && int?(msg["reason"]) ? nil : "index or reason is not a Java int"
        when NODE_WANT
          return "a NODE_WANT names at least one cid" unless msg["cids"].is_a?(Array) && !msg["cids"].empty?

          cid_list(msg["cids"], MAX_WANT_CIDS, "cids")
        when NODES
          plain = msg["nodes"]
          sealed = msg["sealed"]
          return "a NODES carries exactly one of nodes and sealed" if plain.nil? == sealed.nil?
          return "epoch is present exactly when sealed is" if sealed.nil? != msg["epoch"].nil?

          if !plain.nil?
            return "nodes is not a list of byte strings" unless plain.is_a?(Array) && plain.all? { |n| bytes?(n) }
            return "a NODES carries at most #{MAX_NODES_BYTES} bytes of nodes" if plain.sum(&:bytesize) > MAX_NODES_BYTES
          elsif !bytes?(sealed) || sealed.bytesize > MAX_NODES_BYTES
            return "a NODES carries at most #{MAX_NODES_BYTES} sealed bytes"
          elsif !JAVA_LONG.cover?(msg["epoch"]) || !msg["epoch"].is_a?(Integer)
            return "epoch is not a Java long"
          end
          msg["missing"].nil? ? nil : cid_list(msg["missing"], MAX_WANT_CIDS, "missing")
        when TREE_WANT
          return "root is not a cid" unless cid_text?(msg["root"])
          return "sketch is not a byte string" unless msg["sketch"].nil? || bytes?(msg["sketch"])

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
        end
      end

      def sealing_aad(recipient, req) = "#{SEALING_AAD_PREFIX}#{recipient}|#{req}".b

      # Seals a node list (group-key mode): nonce || ciphertext || tag under AES-256-GCM with the AAD.
      def seal_nodes(key, nodes, aad)
        cipher = OpenSSL::Cipher.new("aes-256-gcm").encrypt
        cipher.key = key
        nonce = cipher.random_iv
        cipher.auth_data = aad
        nonce + cipher.update(CBOR.dump(nodes)) + cipher.final + cipher.auth_tag
      end

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

      # Swarm retries (ROBUSTNESS.md 10.3 E3): a missing answer benches its source for that CID
      # alone, MISSING_BENCH seconds doubling with each such answer up to MISSING_BENCH_MAX, with a
      # random spread; a source whose requests time out twice sits out SIT_OUT seconds; a request
      # times out after the larger of the configured timeout and eight smoothed round trips.
      MISSING_BENCH = 1.0
      MISSING_BENCH_MAX = 16.0
      SIT_OUT = 60.0

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
        @benched = Hash.new { |h, k| h[k] = {} }
        @dropped = Set.new
        @timeouts = Hash.new(0)
        @srtt = {}
        @sitting_out = {}
        @stalled_since = nil
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
      # The deadline ends the caller's wait alone: the fetch goes on, and fails by itself only once no
      # source has answered for its timeout (swarm retries, ROBUSTNESS.md 10.3 E3).
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
          rtt = monotonic - request.sent_at
          @srtt[sender] = @srtt.key?(sender) ? (@srtt[sender] * 7 + rtt) / 8 : rtt
          @timeouts[sender] = 0
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
          now = monotonic
          Array(msg["missing"]).each { |c| lack(sender, c, now) }
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

      def live_sources
        now = monotonic
        @sources.reject { |s| @dropped.include?(s) || @sitting_out.fetch(s, 0) > now }
      end

      def drop(source) = @dropped << source

      def release(request)
        @outstanding.delete(request.req)
        @in_flight.delete_if { |_, req| req == request.req }
      end

      def tick_locked(now)
        return if @done

        stale = @outstanding.values.select { |r| now - r.sent_at > request_timeout(r.source) }
        stale.each do |r|
          release(r)
          @timeouts[r.source] += 1
          next if @timeouts[r.source] < 2

          @timeouts[r.source] = 0
          @sitting_out[r.source] = now + SIT_OUT
        end
        schedule
        return if @done

        # nothing asked of anyone: every source lacks what is left, sits out, or there is none
        if @outstanding.empty?
          @stalled_since ||= now
          finish("no source answered for #{@timeout}s (sources tried: #{@sources.inspect})") if now - @stalled_since > @timeout
        else
          @stalled_since = nil
        end
      end

      def request_timeout(source)
        srtt = @srtt[source]
        srtt.nil? ? @trees.request_timeout : [@trees.request_timeout, 8 * srtt].max
      end

      def lacks?(source, cid, now)
        bench = @benched[source][cid]
        !bench.nil? && now < bench[0]
      end

      def lack(source, cid, now)
        bench = (@benched[source][cid] ||= [0.0, 0])
        return if now < bench[0]

        bench[1] += 1
        pause = [MISSING_BENCH_MAX, MISSING_BENCH * (2**(bench[1] - 1))].min
        bench[0] = now + pause + rand * pause / 2
      end

      def complete_now?
        if @bare
          @bare.all? { |c| @store.has?(c) }
        else
          @store.has?(@root) && @store.complete?(@root)
        end
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
          return finish("every source refused or was struck (sources tried: #{@sources.inspect})") if (@sources - @dropped.to_a).empty?

          return # the sources that timed out sit out a while; the tick fails the fetch if none comes back
        end

        now = monotonic
        if @bare.nil?
          holder = sources.find { |s| !lacks?(s, @root, now) }
          if !@store.has?(@root)
            send_node_want(holder, [@root]) unless @in_flight.key?(@root) || holder.nil?
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
            next if batch.all? { |c| lacks?(candidate, c, now) }

            source = candidate
            break
          end
          next if source.nil?

          send_node_want(source, batch.reject { |c| lacks?(source, c, now) })
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

    # The tree exchange attached to a peer: the content-swarm pipe handler for
    # tags 8 to 11, the sources that advertise trees, the fetches in flight, and
    # (PDT 2 phase 7, P2-X-06) the holder side that serves this store's nodes.
    class Trees
      attr_reader :peer, :store, :request_timeout, :budget, :load_timeout, :stats

      # keys: content keys by epoch (group-key); write_epoch: the epoch whose key seals what this face serves.
      def initialize(peer, store, keys: {}, write_epoch: keys.keys.max, load_timeout: 10.0, request_timeout: 5.0,
                     budget: Tree::MAX_TREE_BUDGET)
        @peer = peer
        @store = store
        @keys = keys
        @write_epoch = write_epoch
        @advertised_at = nil
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

      # Whether any member's current advertisement says the group seals nodes in transit (PD-P-03).
      def group_seals?
        now = @peer.now_ms
        @peer.ads.each_value.any? do |e|
          ad = e["ad"] || {}
          e["type"] == "CapabilityAdvertisement" && ad["capabilityType"] == Tree::TYPE && e.fetch("expires", 0) > now &&
            (ad["parameters"] || {})["sealing"] == Tree::SEALING_GROUP_KEY
        end
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

      # A bare batch: the nodes named, following no links; a load past its deadline joins the batch
      # still in flight for the same nodes (swarm retries).
      def fetch_nodes(cids, prefer: [], timeout: nil)
        cids.each { |c| Cids.parse(c) }
        @lock.synchronize do
          existing = @fetches.find { |f| f.bare == cids.to_a && !f.done? }
          return existing if existing

          f = TreeFetch.new(self, nil, [], prefer, timeout || @load_timeout, bare: cids.to_a)
          @fetches << f
          f
        end.start
      end

      # Times out stale requests, asks benched sources again, and fails the fetches
      # no source answers; renews the advertisement of a face that serves.
      def tick
        active_fetches.each(&:tick)
        advertise if !@advertised_at.nil? && Process.clock_gettime(Process::CLOCK_MONOTONIC) - @advertised_at >= Tree::ADVERTISE_EVERY
      end

      # Advertises the tree exchange once, so members fetch this face's nodes (PDT 2 phase 7, P2-X-06).
      def serve!
        advertise if @advertised_at.nil?
      end

      # This face's content-swarm CapabilityAdvertisement, in Java field order: the
      # tree exchange (trees = "1") and its sealing, and no pdt parameter, since the
      # face stays at feature level 1 (P2-C-02); it serves no piece.
      def describe
        now = @peer.now_ms
        id = @peer.identity.peer_id
        { "id" => "aspace://#{@peer.group}/cap/content-swarm/#{id}", "issuer" => id, "group" => @peer.group,
          "issued" => Instants.iso(now - (now % 1000)), "ttl" => Tree::ADVERTISEMENT_TTL, "capabilityType" => Tree::TYPE,
          "version" => "0.1", "binding" => "pipe",
          "parameters" => CBOR.canonical_map({ "sealing" => @keys.empty? ? Tree::SEALING_NONE : Tree::SEALING_GROUP_KEY,
                                                Tree::TREES_PARAMETER => Tree::TREES_VERSION }),
          "costHints" => {} }
      end

      def advertise
        @peer.publish_ad("CapabilityAdvertisement", describe)
        @advertised_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
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

      # Routes one content-swarm frame; false for a piece message, which the
      # handler before this one reads. PDT 2 phase 1 (P2-X-09): any other
      # frame that is not a message of this face's level in its record's own
      # encoding is dropped, counted in treeMessagesDropped, and strikes
      # nobody, as Java and TypeScript count it.
      def on_frame(sender, payload)
        msg = begin
          CBOR.load(payload)
        rescue CBOR::Error
          nil
        end
        t = msg["t"] if msg.is_a?(Hash)
        return false if Tree::PIECE_TAGS.include?(t) && !(t == Tree::REJECT && msg["index"] == Tree::TREE_INDEX)

        if (bad = Tree.violation(msg))
          count(:tree_messages_dropped)
          @peer.logger&.debug("pdt: dropped a content-swarm frame from #{sender}: #{bad}")
          return true
        end
        case t
        when Tree::NODES, Tree::TREE_END
          f = @lock.synchronize { @by_req[msg["req"]] }
          return true if f.nil?

          msg["t"] == Tree::NODES ? f.on_nodes(sender, msg) : f.on_tree_end(sender, msg)
          true
        when Tree::NODE_WANT
          serve_node_want(sender, msg)
          true
        when Tree::TREE_WANT
          serve_tree_want(sender, msg)
          true
        when Tree::REJECT
          active_fetches.each { |f| f.on_reject(sender, msg) }
          true
        end
      end

      private

      def refuse(sender, root, reason)
        count(:tree_requests_refused)
        send_message(sender, Tree.reject(root, Tree::TREE_INDEX, reason))
      end

      # Why this face cannot answer: the group seals and it holds no key for its write epoch.
      def cannot_seal? = @keys.empty? ? group_seals? : !@keys.key?(@write_epoch)

      # One NODES to an asker, sealed under the write epoch's key in group-key mode.
      def send_nodes(to, req, batch, missing)
        message = if @keys.empty?
                    Tree.nodes_message(req, batch, nil, nil, missing)
                  else
                    sealed = Tree.seal_nodes(@keys.fetch(@write_epoch), batch, Tree.sealing_aad(to, req))
                    Tree.nodes_message(req, nil, sealed, @write_epoch, missing)
                  end
        send_message(to, message)
        @lock.synchronize do
          @stats[:nodes_served] += batch.size
          @stats[:bytes_served] += batch.sum(&:bytesize)
        end
      end

      # Sends node bytes packed under the NODES bound, missing on the last message.
      def packed(to, req, nodes, missing)
        batch = []
        size = Tree::MESSAGE_FRAMING_BYTES
        nodes.each do |data|
          if !batch.empty? && size + data.bytesize + Tree::NODE_FRAMING_BYTES > Tree::MAX_NODES_BYTES
            send_nodes(to, req, batch, nil)
            batch = []
            size = Tree::MESSAGE_FRAMING_BYTES
          end
          batch << data
          size += data.bytesize + Tree::NODE_FRAMING_BYTES
        end
        send_nodes(to, req, batch, missing)
      end

      def serve_node_want(sender, msg)
        wanted = msg["cids"]
        return refuse(sender, wanted.first, Tree::REASON_POLICY) if cannot_seal?

        found = wanted.filter_map { |cid| @store.get(cid) }
        missing = wanted.reject { |cid| @store.has?(cid) }
        packed(sender, msg["req"], found, missing.empty? ? nil : missing)
      end

      # A breadth-first walk from the root that skips every node a held haves root
      # reaches, stops at the budget or the walk cap, and closes with TREE_END and
      # the frontier; when the asker names haves and this face holds none, the walk
      # sends the top two levels and closes with END_HAVES_NOT_HELD (S3 of 6.4).
      def serve_tree_want(sender, msg)
        root = msg["root"]
        return refuse(sender, root, Tree::REASON_POLICY) if cannot_seal?
        return refuse(sender, root, Tree::REASON_NOT_HELD) unless @store.has?(root)

        haves = (msg["haves"] || []).uniq - [root]
        held = haves.select { |h| @store.has?(h) }
        prune = Set.new
        walked = 0
        held.each do |h|
          reach = @store.reachable(h)
          walked += reach.size
          prune.merge(reach)
          break if walked >= Tree::MAX_WALK_NODES
        end
        two_levels = !haves.empty? && held.empty?
        queue = [[root, 0]]
        sent = Set.new
        frontier = []
        nodes = []
        spent = 0
        reason = Tree::END_DONE
        until queue.empty?
          cid, level = queue.first
          if prune.include?(cid) || sent.include?(cid)
            queue.shift
            next
          end
          if two_levels && level >= Tree::LEVELS_WITHOUT_HAVES
            frontier << queue.shift[0]
            next
          end
          data = @store.get(cid)
          if data.nil?
            queue.shift
            next
          end
          if spent + data.bytesize > msg["budget"] && !sent.empty?
            reason = Tree::END_BUDGET
            break
          end
          if walked >= Tree::MAX_WALK_NODES
            reason = Tree::END_WALK_CAP
            break
          end
          queue.shift
          sent << cid
          spent += data.bytesize
          walked += 1
          nodes << data
          @store.links(cid, data).each { |link| queue << [link, level + 1] unless prune.include?(link) || sent.include?(link) }
        end
        reason = Tree::END_HAVES_NOT_HELD if two_levels && reason == Tree::END_DONE
        packed(sender, msg["req"], nodes, nil)
        rest = (frontier + queue.map(&:first)).uniq.reject { |c| sent.include?(c) || prune.include?(c) }
        send_message(sender, Tree.tree_end(msg["req"], rest.first(Tree::MAX_FRONTIER), reason))
      end
    end
  end
end
