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
  # The AppCard and AgentCard rules of SPEC v0.1.32 (AppCard origin and
  # formats, 2026-11-09): the closed values a reader checks at decode, the
  # bounds and grammars of AppCard.origin and AppCard.formats, and the card
  # spill (SPEC §6.1a.5). A card whose encoding passes the spill threshold
  # travels as a stub: its spill-set fields sit at their placeholders and a
  # content-swarm document named by spill.root holds their full values.
  #
  # The checks return true or the reason Java's record constructor refuses
  # the value; Schema runs them after each record's field checks, so a card
  # Java would not build does not decode here either.
  module Cards
    # How an app connects, a closed set; no kind is tied to an origin.
    # assembled: a static app assembled from extracted data and served as is,
    # which reads nothing live.
    APP_CARD_KINDS = %w[peer fed gateway assembled].freeze
    APP_CARD_SHAPES = %w[web desktop static a2ui].freeze
    APP_CARD_TRANSPORTS = %w[views a2a].freeze
    # idp: the identity provider of whoever runs the host, enforced at its
    # door (the default); none: no sign-on.
    APP_CARD_SIGN_ONS = %w[idp none].freeze
    APP_CARD_STATUSES = %w[serving stopped].freeze
    UI_ROLES = %w[panel control row].freeze
    APP_CARD_MAX_TERMS = 64
    UI_MAX_COMPONENTS = 32
    UI_MAX_CONTROLS = 16
    UI_MAX_ENTRIES = 64
    AGENT_CARD_MAX_ACTIONS = 64
    APP_CARD_MAX_FORMATS = 16
    APP_CARD_MAX_FORMAT_LENGTH = 256
    ORIGIN_MAX_REF = 256
    ORIGIN_MAX_VERSION = 64
    ORIGIN_MAX_ATTRS = 8
    ORIGIN_MAX_ATTR_KEY = 128
    ORIGIN_MAX_ATTR_VALUE = 256

    # The fields a stub moves into its parts document, in field order.
    APP_CARD_SPILL_SET = %w[reads actions views ui].freeze
    AGENT_CARD_SPILL_SET = %w[actions ui].freeze
    # A card whose encoding is more than this many bytes spills: the inline
    # limit of a payload (SPEC §7.1).
    CARD_SPILL_THRESHOLD_BYTES = 65_536
    # A publisher warns once a card's encoding passes this many bytes (56 KiB).
    CARD_SPILL_WARN_BYTES = 57_344
    # The piece size of a parts document, so every implementation computes
    # the same root for the same bytes.
    CARD_SPILL_PIECE_SIZE = 65_536
    # The default bound on a parts document a reader fetches.
    CARD_SPILL_MAX_FETCH_BYTES = 16_777_216
    # The largest spill.size: 2^53 - 1, which every implementation holds exactly.
    CARD_SPILL_MAX_SIZE = (2**53) - 1
    CARD_SPILL_ROOT_LENGTH = 59

    SYSTEM = /\A[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?\z/
    KEY_TAIL = /\A[a-z0-9.-]+\z/
    # A media type under the restricted names of RFC 6838 §4.2, lower-case, with no parameter.
    MEDIA_TYPE = %r{\A[a-z0-9][a-z0-9!\#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!\#$&^_.+-]{0,126}\z}
    # The scheme of a vocabulary IRI (RFC 3987 §2.2).
    SCHEME = /\A[a-z][a-z0-9+.-]*\z/
    CONTROL = /[\u0000-\u001F\u007F]/
    # A control character or a code unit of the Unicode White_Space property, as Java's AppCard tests it.
    WHITESPACE_OR_CONTROL = /[\u0000- \u007F\u0085   -     　]/
    # Text Java's String.isBlank reads as blank (Character.isWhitespace on every code point).
    JAVA_BLANK = /\A[\t\n\v\f\r\u001C-\u001F   -  -    　]*\z/

    module_function

    # The card kind of a card value: an AgentCard names its agent.
    def kind_of(card) = card.key?("agent") ? "AgentCard" : "AppCard"

    def spill_set(kind) = kind == "AgentCard" ? AGENT_CARD_SPILL_SET : APP_CARD_SPILL_SET

    # The names of a parts value's non-empty fields, in field order: what spill.parts lists.
    def non_empty_parts(parts)
      %w[reads actions views ui].select do |field|
        value = parts[field]
        field == "ui" ? !value.nil? : !(value.nil? || value.empty?)
      end
    end

    # The full values of a card's spill set (AppCard.Parts or AgentCard.Parts).
    def card_parts(card)
      raise ArgumentError, "a stub's parts are in its spill document; resolve the card first" if card.key?("spill")

      if kind_of(card) == "AgentCard"
        card.slice("actions", "ui")
      else
        parts = { "reads" => card["reads"], "actions" => card["actions"], "views" => card["views"] }
        card.key?("ui") ? parts.merge("ui" => card["ui"]) : parts
      end
    end

    # The stub of a full card: every spill-set field at its placeholder ([]
    # for an AppCard's lists, absent otherwise) and spill set.
    def card_stub(card, spill)
      named = non_empty_parts(card_parts(card))
      raise ArgumentError, "a stub moves every non-empty part #{named}: #{spill['parts']}" unless spill["parts"] == named

      stub = card.except("ui", *(kind_of(card) == "AgentCard" ? ["actions"] : []))
      stub = stub.merge("reads" => [], "actions" => [], "views" => []) if kind_of(card) == "AppCard"
      stub.merge("spill" => spill)
    end

    # The full card of a stub: the parts document's values in place and no spill.
    def card_complete(stub, parts)
      spill = stub["spill"]
      raise ArgumentError, "only a stub completes; this card carries its parts inline" if spill.nil?

      named = non_empty_parts(parts)
      unless named == spill["parts"]
        raise ArgumentError, "the parts document holds #{named} where the stub names #{spill['parts']}"
      end

      merged = stub.except("spill").merge(parts)
      Schema::RECORDS.fetch(kind_of(stub)).filter_map { |field,| [field, merged[field]] if merged.key?(field) }.to_h
    end

    # The content root of a parts document (SPEC annex G): the CIDv1 (raw,
    # sha2-256) of its table of piece digests over CARD_SPILL_PIECE_SIZE
    # pieces. spill.root names a document's bytes through it.
    def content_root(document)
      table = (0...document.bytesize).step(CARD_SPILL_PIECE_SIZE)
                                     .map { |at| PDT::Cids.sha256(document.byteslice(at, CARD_SPILL_PIECE_SIZE)) }
      PDT::Cids.of_digest(PDT::Cids.sha256(table.join), PDT::Cids::RAW)
    end

    # An AppCard as a v0.1.31 reader decodes it: without origin, formats, and
    # a host whose signOn is idp (FR-7).
    def without_gated_fields(card)
      stripped = card.except("origin", "formats")
      stripped.delete("host") if stripped.dig("host", "signOn") == "idp"
      stripped
    end

    # ------------------------------------------------------------- the checks

    # A length in UTF-16 code units, as Java counts it.
    def units(text) = text.encode(Encoding::UTF_16LE).bytesize / 2

    def blank?(text) = JAVA_BLANK.match?(text)

    def app_card_check(card)
      if blank?(card["name"]) then "an AppCard needs a name"
      elsif !APP_CARD_KINDS.include?(card["kind"]) then "kind must be one of #{APP_CARD_KINDS}: #{card['kind']}"
      elsif !APP_CARD_SHAPES.include?(card["shape"]) then "shape must be one of #{APP_CARD_SHAPES}: #{card['shape']}"
      elsif blank?(card["version"]) then "version is blank, which Java's AppCard writes as 1"
      elsif %w[reads actions views].any? { |f| card[f].size > APP_CARD_MAX_TERMS }
        "an AppCard carries at most #{APP_CARD_MAX_TERMS} reads, actions, and views"
      elsif card.key?("formats") && (bad = formats_violation(card["formats"])) then bad
      elsif card.key?("spill") && (bad = stub_violation(card, APP_CARD_SPILL_SET)) then bad
      elsif card["shape"] == "a2ui" && !card.key?("ui") && !Array(card.dig("spill", "parts")).include?("ui")
        "an a2ui app names its surfaces in ui"
      else true
      end
    end

    def app_ui_check(ui)
      if blank?(ui["protocol"]) || blank?(ui["version"]) then "ui.protocol and ui.version are set, which Java writes for blank"
      elsif !APP_CARD_TRANSPORTS.include?(ui["transport"])
        "ui.transport must be one of #{APP_CARD_TRANSPORTS}: #{ui['transport']}"
      elsif ui.fetch("components", []).size > UI_MAX_COMPONENTS
        "an AppCard's ui carries at most #{UI_MAX_COMPONENTS} components"
      elsif ui["catalogIds"].size > APP_CARD_MAX_TERMS || ui["surfaces"].size > APP_CARD_MAX_TERMS
        "an AppCard's ui carries at most #{APP_CARD_MAX_TERMS} catalogs and surfaces"
      else true
      end
    end

    def host_check(host)
      if blank?(host["url"]) then "a host names the url end users open"
      elsif !(0..65_535).cover?(host["port"]) then "host.port is a port number or 0: #{host['port']}"
      elsif blank?(host["path"]) then "host.path is blank, which Java's Host writes as /"
      elsif !APP_CARD_SIGN_ONS.include?(host["signOn"]) then "host.signOn must be one of #{APP_CARD_SIGN_ONS}: #{host['signOn']}"
      elsif !APP_CARD_STATUSES.include?(host["status"]) then "host.status must be one of #{APP_CARD_STATUSES}: #{host['status']}"
      else true
      end
    end

    # FR-2: the origin's grammar and bounds.
    def origin_check(origin)
      system = origin["system"]
      ref = origin["ref"]
      version = origin["version"]
      if !SYSTEM.match?(system)
        "origin.system is 1 to 64 of [a-z0-9.-], starting and ending with a letter or digit: #{system}"
      elsif ref.empty? || units(ref) > ORIGIN_MAX_REF || CONTROL.match?(ref)
        "origin.ref is 1 to #{ORIGIN_MAX_REF} code units with no control character"
      elsif units(version) > ORIGIN_MAX_VERSION || CONTROL.match?(version)
        "origin.version is 0 to #{ORIGIN_MAX_VERSION} code units with no control character"
      elsif origin.key?("attrs") then attrs_violation(system, origin["attrs"]) || true
      else true
      end
    end

    def attrs_violation(system, attrs)
      return "origin.attrs holds 1 to #{ORIGIN_MAX_ATTRS} entries, or is absent" if attrs.empty? || attrs.size > ORIGIN_MAX_ATTRS

      prefix = "#{system}."
      attrs.each do |key, value|
        if units(key) > ORIGIN_MAX_ATTR_KEY || !key.start_with?(prefix) || !KEY_TAIL.match?(key.delete_prefix(prefix))
          return "an origin.attrs key is #{prefix} then [a-z0-9.-]+, at most #{ORIGIN_MAX_ATTR_KEY} code units: #{key}"
        end
        if units(value) > ORIGIN_MAX_ATTR_VALUE || CONTROL.match?(value)
          return "the origin.attrs value of #{key} is 0 to #{ORIGIN_MAX_ATTR_VALUE} code units with no control character"
        end
      end
      nil
    end

    # FR-3: 1 to 16 distinct entries, each a lower-case media type without
    # parameter or a vocabulary IRI.
    def formats_violation(formats)
      return "formats holds 1 to #{APP_CARD_MAX_FORMATS} entries, or is absent" if formats.empty? || formats.size > APP_CARD_MAX_FORMATS
      return "formats repeats an entry: #{formats}" unless formats.uniq.size == formats.size

      formats.each do |format|
        return "a format is 1 to #{APP_CARD_MAX_FORMAT_LENGTH} code units" if format.empty? || units(format) > APP_CARD_MAX_FORMAT_LENGTH

        scheme, colon, = format.partition(":")
        if colon.empty?
          return "a media type in formats is lower-case type/subtype with no parameter: #{format}" unless MEDIA_TYPE.match?(format)
        elsif !SCHEME.match?(scheme) || WHITESPACE_OR_CONTROL.match?(format)
          return "a vocabulary IRI in formats has a scheme and no whitespace or control character: #{format}"
        end
      end
      nil
    end

    # CardSpill: a content root of codec raw over sha2-256, a size of 1 to
    # 2^53 - 1, and at least one distinct part name.
    def spill_check(spill)
      if !root?(spill["root"]) then "spill.root is not a content root of codec raw over sha2-256: #{spill['root']}"
      elsif !(1..CARD_SPILL_MAX_SIZE).cover?(spill["size"]) then "spill.size lies outside 1 to 2^53 - 1: #{spill['size']}"
      elsif spill["parts"].empty? then "spill.parts names at least one field"
      elsif spill["parts"].uniq.size != spill["parts"].size then "spill.parts repeats a name: #{spill['parts']}"
      else true
      end
    end

    def root?(text)
      text.length == CARD_SPILL_ROOT_LENGTH && PDT::Cids.codec_of(text) == PDT::Cids::RAW
    rescue ArgumentError
      false
    end

    # FR-14: the part names lie within the kind's spill set in its order, and
    # every spill-set field holds its placeholder.
    def stub_violation(card, spill_set)
      last = -1
      card["spill"]["parts"].each do |part|
        at = spill_set.index(part)
        return "spill.parts names #{part}, outside the spill set #{spill_set}" if at.nil?
        return "spill.parts breaks the field order of #{spill_set}: #{card['spill']['parts']}" if at <= last

        last = at
      end
      placeholders = spill_set == AGENT_CARD_SPILL_SET ? card.slice("actions", "ui").empty? : stub_lists_empty?(card)
      placeholders ? nil : "a stub holds each spill-set field at its placeholder; its parts are in the spill document"
    end

    def stub_lists_empty?(card) = %w[reads actions views].all? { |f| card[f].empty? } && !card.key?("ui")

    def app_parts_check(parts)
      return true if %w[reads actions views].all? { |f| parts[f].size <= APP_CARD_MAX_TERMS }

      "an AppCard carries at most #{APP_CARD_MAX_TERMS} reads, actions, and views"
    end

    def agent_card_check(card)
      actions = card["actions"]
      certificate = card["agentCertificate"]
      if certificate && (certificate["agentPublicKey"] != card["agentPublicKey"] || certificate["agent"] != card["agent"])
        "a card's agent certificate must certify exactly its agent and agentPublicKey"
      elsif actions && actions.size > AGENT_CARD_MAX_ACTIONS then "a card declares at most #{AGENT_CARD_MAX_ACTIONS} actions"
      elsif actions && actions.map { |a| a["name"] }.uniq.size != actions.size then "action names must be unique within a card"
      elsif card.key?("spill") && (bad = stub_violation(card, AGENT_CARD_SPILL_SET)) then bad
      elsif (control = foreign_control(card)) then "a ui control names #{control}, which is not an action of the card"
      else true
      end
    end

    def foreign_control(card)
      names = Array(card["actions"]).map { |a| a["name"] }
      Array(card.dig("ui", "components")).flat_map { |c| c["controls"] }.find { |control| !names.include?(control) }
    end

    def ui_declaration_check(ui)
      components = ui["components"]
      if blank?(ui["protocol"]) || blank?(ui["version"]) then "ui.protocol and ui.version are set, which Java writes for blank"
      elsif components.size > UI_MAX_COMPONENTS then "a ui declaration carries at most #{UI_MAX_COMPONENTS} components"
      elsif components.map { |c| c["id"] }.uniq.size != components.size then "ui component ids must be unique within a card"
      elsif ui["catalogIds"].empty? && !components.empty? then "ui.catalogIds is empty, which Java derives from the components"
      else true
      end
    end

    def ui_entries_check(entries)
      return true if entries["reads"].size <= UI_MAX_ENTRIES && entries["writes"].size <= UI_MAX_ENTRIES

      "a ui declaration names at most #{UI_MAX_ENTRIES} entry types per list"
    end

    def ui_component_check(component)
      if %w[id catalogId component].any? { |f| blank?(component[f]) } then "a ui component names an id, a catalog, and a component"
      elsif !UI_ROLES.include?(component["role"]) then "a ui component's role is one of #{UI_ROLES}: #{component['role']}"
      elsif component["controls"].size > UI_MAX_CONTROLS then "a ui component names at most #{UI_MAX_CONTROLS} controls"
      else true
      end
    end
  end
end
