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
  module PDT
    # Chooses content stores by their asset cards (PDT 2 phase 7, P2-C-02, as
    # Java's planner StoreChooser; srad/agentspaces-pdt2.md 3.2.1). It reads the
    # card's text values (rule 19 of 6.10.3): free and maxObject in canonical
    # decimal, blind as true or false, tier as hot or cold, and the
    # pricePerGibMonth cost hint. A card with a value it cannot read is skipped.
    # Only an unexpired card of kind content-store with room for the root
    # counts; a blind store only for sealed content; the tier and the highest
    # price when named; no store the caller avoids. The rest rank by price (no
    # hint is free), then by free bytes, most first, then by issuer, one card
    # per store, at most the copies asked.
    module StoreChooser
      KIND = "content-store"
      PRICE_HINT = "pricePerGibMonth"
      # The access key of a card whose store takes no pins yet (PDT 2 follow-ups, F2).
      WAITING = "waiting"

      module_function

      # The cards to ask, best first.
      def choose(cards, bytes:, copies:, now_ms:, sealed: false, tier: nil, max_price: nil, avoid: [])
        fit = cards.filter_map { |card| read(card, bytes, sealed, tier, max_price, avoid, now_ms) }
        fit.sort_by! { |card, free, price| [price, -free, card["issuer"]] }
        chosen = {}
        fit.each do |card, _, _|
          break if chosen.size == copies

          chosen[card["issuer"]] ||= card
        end
        chosen.values
      end

      def read(card, bytes, sealed, tier, max_price, avoid, now_ms)
        access = card["access"] || {}
        expires = Instants.parse_millis(card["issued"]) + Instants.parse_duration_millis(card["ttl"])
        return nil if access["kind"] != KIND || expires <= now_ms || avoid.include?(card["issuer"])

        free = decimal(access["free"])
        max_object = decimal(access["maxObject"])
        hint = (card["costHints"] || {})[PRICE_HINT]
        price = hint.nil? ? 0 : decimal(hint)
        return nil if free.nil? || max_object.nil? || price.nil? || !%w[true false].include?(access["blind"])
        return nil if free < bytes || max_object < bytes || (access["blind"] == "true" && !sealed)
        return nil if (!tier.nil? && access["tier"] != tier) || (!max_price.nil? && price > max_price)

        [card, free, price]
      end
      private_class_method :read

      # Canonical decimal text: no sign, no leading zero, within a Java long.
      def decimal(text)
        return nil unless text.is_a?(String) && text.match?(/\A(0|[1-9][0-9]{0,18})\z/)

        value = Integer(text, 10)
        value <= CBOR::LONG.last ? value : nil
      end
      private_class_method :decimal
    end

    # A requester's pins (PDT 2 phase 7, P2-C-02, as Java's Stores.storeFor;
    # srad/agentspaces-pdt2.md 3.2.2 and 10.9): it chooses stores for a tree this
    # face holds complete from the content-store cards the ads carry, skips a
    # store that waits for an authorizer, puts the stores already holding the
    # root first, and writes one SignedPin into the group's content space,
    # signed by this peer as the requester and naming the chosen stores in
    # pdt.stores (owner ruling R1), under an entry lease of the pin's lease, at
    # most PIN_ENTRY_LEASE, which the signature's deadline matches. The face
    # then serves the tree, so a store that takes the pin fetches it from here.
    module Stores
      STORES_ATTR = "pdt.stores"
      PIN_ENTRY_LEASE_MS = 60 * 60 * 1000
      CONTENT_SPACE = "content"

      module_function

      # Writes the pin of a held tree root; [the pin's terms, the chosen cards].
      def store_for(pdt, root, copies:, lease:, tier: nil, max_price: nil, space: CONTENT_SPACE)
        peer = pdt.peer
        unless Cids.codec_of(root) == Cids::DAG_CBOR && pdt.store.has?(root) && pdt.store.complete?(root)
          raise ArgumentError, "tree root #{root} is not complete in this face's store"
        end

        bytes = pdt.store.reachable(root).sum { |cid| pdt.store.get(cid).bytesize }
        sealed = Nodes.kind_of(pdt.store.get(root)) == Nodes::KIND_SN
        now = peer.now_ms
        cards = peer.ads.values.filter_map do |e|
          e["ad"] if e["type"] == "AssetCard" && e["ad"].dig("access", "kind") == StoreChooser::KIND &&
                     !e["ad"]["access"].key?(StoreChooser::WAITING)
        end
        holders = receipts(peer, space, root)
        need = { now_ms: now, sealed: sealed, tier: tier, max_price: max_price }
        chosen = StoreChooser.choose(cards.select { |c| holders.include?(c["issuer"]) }, bytes: 0, copies: copies, **need)
        if chosen.size < copies
          chosen += StoreChooser.choose(cards, bytes: bytes, copies: copies - chosen.size,
                                               avoid: chosen.map { |c| c["issuer"] }, **need)
        end
        raise ArgumentError, "no content store fits #{bytes} bytes of #{root}" if chosen.empty?

        pin = StorePin.build(root: root, kind: StorePin::KIND_TREE, lease: [1, Integer(lease)].max, copies: chosen.size,
                             requester: peer.identity.peer_id, attrs: { STORES_ATTR => chosen.map { |c| c["issuer"] }.join(",") })
        bad = StorePin.violation(pin)
        raise ArgumentError, bad if bad

        entry = [pin["lease"] * 1000, PIN_ENTRY_LEASE_MS].min
        signed = SignedPin.sign(pin, peer.group, now + entry, peer.identity)
        peer.write_entry(space, SignedPin::TYPE, signed, lease_millis: entry, tags: SignedPin.tags(signed))
        pdt.trees.serve!
        [pin, chosen]
      end

      # The stores whose live receipts, each signed by the holder it names, name the root.
      def receipts(peer, space, root)
        space_id = Derive.space_id_local("#{peer.group}/#{space}")
        now = peer.now_ms
        peer.states.values.filter_map do |dto|
          record = dto["record"] || {}
          next unless record["type"] == StoreReceipt::TYPE && record["spaceId"] == space_id && Peer.present?(dto)

          receipt = StoreReceipt.decode(peer.payload_of(dto) || "".b)
          next if receipt.nil? || StoreReceipt.violation(receipt) || receipt["root"] != root || receipt["until"] <= now

          receipt["holder"] if record["issuer"].to_s.split("/", 2).first == receipt["holder"]
        end.uniq
      end
      private_class_method :receipts
    end
  end
end
