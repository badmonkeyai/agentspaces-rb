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
    # HashingEmbedder: a signed bag of hashed tokens, L2-normalized, the
    # vectors of the Java default (Java's String.hashCode over the same
    # tokens), as the Python client computes them.
    class HashingEmbedder
      # The tokens are split as the Python client splits them: on runs of
      # characters that are not letters, numbers, underscore, #, /, . or -
      # (Python's \w), and a bare "_" is dropped. Java's pattern
      # ([^\p{L}\p{N}#/.-]+) also splits on underscore, so a token with an
      # inner underscore ranks slightly differently from Java on both clients.
      TOKENS = %r{[^\p{L}\p{N}_#/.\-]+}

      attr_reader :dimensions

      def identity = "hashing"

      # Java's String.hashCode: UTF-16 code units, 31-multiplicative, int32.
      def self.java_hash(text)
        h = 0
        text.to_s.encode(Encoding::UTF_16BE).unpack("n*").each { |unit| h = ((31 * h) + unit) & 0xFFFFFFFF }
        h >= 0x80000000 ? h - 0x100000000 : h
      end

      def initialize(dimensions = 256)
        raise ArgumentError, "dimensions must be positive" unless Integer(dimensions).positive?

        @dimensions = Integer(dimensions)
      end

      # The embedding of text as an Array of Floats; nil embeds to zeros.
      def embed(text)
        vector = Array.new(@dimensions, 0.0)
        return vector if text.nil?

        text.to_s.downcase.split(TOKENS).each do |token|
          next if token.empty? || token == "_"

          h = HashingEmbedder.java_hash(token)
          bucket = h % @dimensions # Ruby's % on Integers is Java's floorMod
          vector[bucket] += h >= 0 ? 1.0 : -1.0
        end
        norm = Math.sqrt(vector.sum { |v| v * v })
        norm.positive? ? vector.map { |v| v / norm } : vector
      end

      def self.cosine(a, b)
        return 0.0 if a.size != b.size

        dot = a.zip(b).sum { |x, y| x * y }
        na = Math.sqrt(a.sum { |x| x * x })
        nb = Math.sqrt(b.sum { |y| y * y })
        na.zero? || nb.zero? ? 0.0 : dot / (na * nb)
      end
    end

    # Semantic discovery (SPEC 8, SemanticDiscovery): local ranking of the
    # cached advertisements by the hashing embedder, and the query pipe that
    # asks other members for their best matches. Queries over the peer's
    # advertisement cache, local and remote.
    class Semantic
      TYPE = "aspace:cap/semantic-discovery"
      MIN_SCORE = 0.2

      # One ranked advertisement.
      Match = Data.define(:ad_type, :ad, :score)

      attr_reader :pipes, :peer, :embedder

      # SemanticDiscovery.textOf: what an advertisement is indexed by. A
      # CapabilityAdvertisement's parameters print as Java's Map.toString
      # ({k=v, k=v}), which tokenizes as Java's and Python's text does.
      def self.text_of(ad_type, ad)
        case ad_type
        when "AgentCard"
          text = "#{ad['description']} #{Array(ad['goals']).join(' ')} #{Array(ad['consumes']).join(' ')} " \
                 "#{Array(ad['produces']).join(' ')}"
          Array(ad["actions"]).each { |action| text += " #{action['name']} #{action['description']}" }
          text
        when "AssetCard" then "#{ad['description']} #{ad['asset']} #{ad['uri']} #{ad['shape']}"
        when "CapabilityAdvertisement"
          parameters = (ad["parameters"] || {}).map { |k, v| "#{k}=#{v}" }.join(", ")
          "#{ad['capabilityType']} #{ad['binding']} {#{parameters}}"
        when "SpaceAdvertisement" then "#{ad['spaceName']} #{Array(ad['schemaHints']).join(' ')}"
        else ad["id"].to_s
        end
      end

      def initialize(pipes, embedder: nil)
        @pipes = pipes
        @peer = pipes.peer
        @embedder = embedder || HashingEmbedder.new
        @nonce = 0
        @pending = {}
        @lock = Mutex.new
        pipes.on_capability(TYPE, method(:on_frame))
      end

      # Local-first ranking of the cached advertisements by cosine score.
      def query(text, limit: 10)
        raise ArgumentError, "limit must be positive" unless limit.positive?

        ranked(text).first(limit).map { |score, entry| Match.new(ad_type: entry["type"], ad: entry["ad"], score: score) }
      end

      # Asks up to three members for their best matches (SemQuery), folds the
      # hits into the cache, then ranks locally.
      def remote_query(text, limit: 10, timeout_seconds: 2.0)
        targets = @pipes.random_members(3)
        unless targets.empty?
          answered = Thread::Queue.new
          nonce = @lock.synchronize do
            @nonce += 1
            @pending[@nonce] = answered
            @nonce
          end
          begin
            frame = CBOR.dump({ "nonce" => nonce, "text" => text, "limit" => Integer(limit) })
            targets.each { |target| @pipes.send_pipe(target, TYPE, frame) }
            answered.pop(timeout: timeout_seconds)
          ensure
            @lock.synchronize { @pending.delete(nonce) }
          end
        end
        query(text, limit: limit)
      end

      def inspect = "#<AgentSpaces::Capabilities::Semantic #{@peer.identity.peer_id}>"

      private

      # [score, ad cache entry] pairs at or above MIN_SCORE, best first, ties
      # in cache order (Python's sort is stable; Ruby's sort_by is not).
      def ranked(text)
        q = @embedder.embed(text)
        now = @peer.now_ms
        scored = []
        @peer.ads.values.each_with_index do |entry, index|
          next if entry["expires"] <= now

          score = HashingEmbedder.cosine(q, @embedder.embed(Semantic.text_of(entry["type"], entry["ad"])))
          scored << [score, index, entry] if score >= MIN_SCORE
        end
        scored.sort_by { |score, index, _| [-score, index] }.map { |score, _, entry| [score, entry] }
      end

      def on_frame(sender, payload)
        frame = begin
          CBOR.load(payload)
        rescue CBOR::Error
          return
        end
        return unless frame.is_a?(Hash)

        if frame["text"].is_a?(String)
          answer(sender, frame)
        elsif frame["hits"].is_a?(Array)
          frame["hits"].each { |hit| @peer.accept_ad(hit) if hit.is_a?(Hash) && hit["adType"] }
          nonce = frame.fetch("nonce", -1)
          waiter = @lock.synchronize { @pending[nonce.is_a?(Numeric) ? Integer(nonce) : nonce] }
          waiter&.push(true)
        end
      end

      def answer(sender, query)
        limit = query.fetch("limit", 10)
        limit = [[limit.is_a?(Numeric) ? Integer(limit) : 10, 16].min, 1].max
        hits = ranked(query["text"]).first(limit).map do |_, entry|
          stored = entry["stored"]
          { "adType" => stored["adType"], "adBytes" => stored["adBytes"], "publicKey" => stored["publicKey"],
            "signature" => stored["signature"] }
        end
        @pipes.send_pipe(sender, TYPE, CBOR.dump({ "nonce" => query.fetch("nonce", 0), "hits" => hits }))
      end
    end
  end
end
