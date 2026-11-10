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
    # The content store's entry records (PDT 2 phase 0, P2-S-02;
    # srad/agentspaces-pdt2.md 3.2.2 and 6.10.4): protocol records read from
    # their own wire encoding alone, as Java's @WireRecord reads them. Each
    # decodes under CBOR.load (items and re-encoding) and then holds to its
    # annex I schema: its fields in order, each of its kind, attrs absent when
    # null, so a payload with a field the schema does not name is
    # undecodable. The types travel ungated: a level-1 replica stores and
    # replicates the entries without decoding them, and a change of shape
    # takes a new type name (P2-F-08). A field whose kind is another record's
    # fields holds that record.
    module StoreRecords
      module_function

      # The record a payload holds, or nil when the payload is undecodable.
      def decode(fields, raw)
        conform(fields, AgentSpaces::CBOR.load(raw))
      rescue AgentSpaces::CBOR::Error
        nil
      end

      # The value when it holds to the fields, or nil.
      def conform(fields, value)
        return nil unless value.instance_of?(Hash)

        present = fields.reject { |name, _, optional| optional && !value.key?(name) }
        return nil unless value.keys == present.map(&:first)

        present.each do |name, kind|
          nested = kind.is_a?(Array) && kind.first.is_a?(Array)
          return nil if nested && conform(kind, value[name]).nil?

          Schema.check(kind, value[name]) unless nested
        end
        value
      end
    end

    # A member's request that a content store hold a root (P2-S-02, 3.2.2):
    # written to the group's content space as a signed, leased entry tagged
    # root and requester, and taken by a store that can honour it.
    # StorePin { v: int, root: String, kind: String, lease: long, copies: int,
    # requester: PeerId, haves: list<String>, attrs: map<String,String> ?null }.
    module StorePin
      TYPE = "ai.badmonkey.agentspaces.agent.content.StorePin#v1"
      VERSION = 1
      KIND_TREE = "tree"
      KIND_ARTIFACT = "artifact"
      ROOT_TAG = "root"
      REQUESTER_TAG = "requester"
      MAX_HAVES = 8
      MAX_ATTRS = 32
      MAX_ATTRS_BYTES = 4 * 1024
      FIELDS = [["v", :int], ["root", :text], ["kind", :text], ["lease", :long], ["copies", :int], ["requester", :id],
                ["haves", %i[list text]], ["attrs", %i[map text], true]].freeze

      module_function

      # The pin as Java writes it: its fields in order, attrs in the RFC 8949 order and absent when nil.
      def build(root:, kind:, lease:, copies:, requester:, haves: [], attrs: nil)
        pin = { "v" => VERSION, "root" => root, "kind" => kind, "lease" => lease, "copies" => copies,
                "requester" => requester, "haves" => haves.to_a }
        pin["attrs"] = AgentSpaces::CBOR.canonical_map(attrs) unless attrs.nil?
        pin
      end

      def decode(raw) = StoreRecords.decode(FIELDS, raw)

      def tags(pin) = { ROOT_TAG => pin["root"], REQUESTER_TAG => pin["requester"] }

      # The first bound of 3.2.2 the pin breaks, or nil.
      def violation(pin)
        attrs = pin["attrs"] || {}
        if pin["v"] != VERSION then "unsupported StorePin version #{pin['v']}"
        elsif !Cids.cid?(pin["root"]) then "root is not a CID"
        elsif ![KIND_TREE, KIND_ARTIFACT].include?(pin["kind"]) then "unknown kind #{pin['kind']}"
        elsif pin["lease"] < 1 then "lease of #{pin['lease']} seconds"
        elsif pin["copies"] < 1 then "copies below 1"
        elsif pin["haves"].size > MAX_HAVES then "more than #{MAX_HAVES} haves"
        elsif !pin["haves"].all? { |have| Cids.cid?(have) } then "have is not a CID"
        elsif attrs.size > MAX_ATTRS then "more than #{MAX_ATTRS} attrs"
        elsif attrs.sum { |k, v| k.b.bytesize + v.b.bytesize } > MAX_ATTRS_BYTES then "attrs larger than #{MAX_ATTRS_BYTES} bytes"
        end
      end
    end

    # The pin entry a content store takes (PDT 2 follow-ups, 2026-11-09, F1):
    # the requester's StorePin terms under the requester's Ed25519 signature,
    # so a store charges only the member who signed them. SignedPin { v: int,
    # pin: StorePin, left: int, notAfter: long (epoch millis), key: bytes,
    # sig: bytes }. The signature covers consent_bytes, the canonical CBOR of
    # { purpose, group, pin, notAfter }, under key, whose peer id is the
    # pin's requester; left counts the copies still to place, which a store
    # that forwards a copy lowers by one, and no store takes the pin after
    # notAfter.
    module SignedPin
      TYPE = "ai.badmonkey.agentspaces.agent.content.SignedPin#v1"
      VERSION = 1
      # The text a consent opens with, so the signature serves no other record of the requester's key.
      PURPOSE = "agentspaces.store-pin"
      KEY_BYTES = 32
      SIG_BYTES = 64
      FIELDS = [["v", :int], ["pin", StorePin::FIELDS], ["left", :int], ["notAfter", :long], ["key", :bytes],
                ["sig", :bytes]].freeze

      module_function

      # What a requester signs: the canonical CBOR of { purpose, group, pin, notAfter } in that order.
      def consent_bytes(pin, group, not_after)
        AgentSpaces::CBOR.dump({ "purpose" => PURPOSE, "group" => group, "pin" => pin, "notAfter" => not_after })
      end

      # The signed pin of a requester's terms for every copy they ask, as Java writes it; ArgumentError when
      # the terms name another requester, since only that member signs them.
      def sign(pin, group, not_after, requester)
        unless pin["requester"] == requester.peer_id
          raise ArgumentError, "the pin names requester #{pin['requester']}, and only that member signs it"
        end

        { "v" => VERSION, "pin" => pin, "left" => pin["copies"], "notAfter" => not_after, "key" => requester.public_raw.b,
          "sig" => requester.sign(consent_bytes(pin, group, not_after)) }
      end

      def decode(raw) = StoreRecords.decode(FIELDS, raw)

      def tags(signed) = StorePin.tags(signed["pin"])

      # The first broken rule of the version, the pin's bounds, the copies left, the deadline's sign, and the
      # key and signature lengths, or nil; consented? checks the signature.
      def violation(signed)
        pin = signed["pin"]
        terms = StorePin.violation(pin)
        if signed["v"] != VERSION then "unsupported SignedPin version #{signed['v']}"
        elsif terms then terms
        elsif !(1..pin["copies"]).cover?(signed["left"]) then "left #{signed['left']} is outside 1 to #{pin['copies']} copies"
        elsif signed["notAfter"].negative? then "negative notAfter"
        elsif signed["key"].bytesize != KEY_BYTES then "key is not 32 bytes"
        elsif signed["sig"].bytesize != SIG_BYTES then "sig is not 64 bytes"
        end
      end

      # Whether the requester the terms name signed them for this group and deadline: the key's peer id is the
      # requester's and the signature verifies over consent_bytes.
      def consented?(signed, group)
        key = signed["key"]
        key.bytesize == KEY_BYTES && AgentSpaces::Derive.id(key) == signed["pin"]["requester"] &&
          AgentSpaces::Identity.verify(key, consent_bytes(signed["pin"], group, signed["notAfter"]), signed["sig"])
      end
    end

    # A content store's statement that it holds a root for a pin (P2-S-02,
    # 3.2.2), tagged root and holder as a Holding is; a possession challenge
    # checks it (P2-S-07). StoreReceipt { v: int, root: String, holder: PeerId,
    # bytes: long, until: long (epoch millis), blind: boolean }.
    module StoreReceipt
      TYPE = "ai.badmonkey.agentspaces.agent.content.StoreReceipt#v1"
      VERSION = 1
      ROOT_TAG = "root"
      HOLDER_TAG = "holder"
      FIELDS = [["v", :int], ["root", :text], ["holder", :id], ["bytes", :long], ["until", :long],
                ["blind", :boolean]].freeze

      module_function

      # The receipt as Java writes it; until_ms is the record's until, a Ruby keyword.
      def build(root:, holder:, bytes:, until_ms:, blind:)
        { "v" => VERSION, "root" => root, "holder" => holder, "bytes" => bytes, "until" => until_ms, "blind" => blind }
      end

      def decode(raw) = StoreRecords.decode(FIELDS, raw)

      def tags(receipt) = { ROOT_TAG => receipt["root"], HOLDER_TAG => receipt["holder"] }

      # The first broken rule of the version, the root, and the signs of the counts, or nil.
      def violation(receipt)
        if receipt["v"] != VERSION then "unsupported StoreReceipt version #{receipt['v']}"
        elsif !Cids.cid?(receipt["root"]) then "root is not a CID"
        elsif receipt["bytes"].negative? then "negative bytes"
        elsif receipt["until"].negative? then "negative until"
        end
      end
    end
  end
end
