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

require "json"
require "net/http"
require "uri"

require_relative "cbor"
require_relative "crypto"
require_relative "identity"
require_relative "channel"

module AgentSpaces
  # Base64 text as Python's base64 module reads and writes it: encoding is
  # standard, padded, and unwrapped; decoding is lenient as CPython 3.14's
  # binascii.a2b_base64 is (characters outside the alphabet and padding
  # inside the text are skipped) and refuses a final quantum that is one
  # character, or two or three without the padding that completes it.
  # Earlier CPython releases may read text that continues after padding
  # differently; such text is nothing an encoder writes.
  module Base64Text
    ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    TABLE = ALPHABET.each_char.with_index.to_h.freeze

    module_function

    def encode(data) = [data.b].pack("m0").force_encoding(Encoding::UTF_8)

    def decode(text)
      raise TypeError, "base64 text is a String, not #{text.class}" unless text.is_a?(String)
      raise ArgumentError, "base64 text contains only ASCII characters" unless text.b.ascii_only?

      out = String.new(encoding: Encoding::BINARY)
      quad = 0
      left = 0
      pads = 0
      text.b.each_char do |char|
        if char == "="
          pads += 1
          next
        end
        value = TABLE[char]
        next if value.nil?

        pads = 0
        case quad
        when 0
          left = value
          quad = 1
        when 1
          out << ((left << 2) | (value >> 4))
          left = value & 0x0F
          quad = 2
        when 2
          out << ((left << 4) | (value >> 2))
          left = value & 0x03
          quad = 3
        else
          out << ((left << 6) | value)
          quad = 0
        end
      end
      raise ArgumentError, "invalid base64: a quantum of one character" if quad == 1
      raise ArgumentError, "invalid base64: incorrect padding" if quad.positive? && quad + pads < 4

      out
    end
  end

  # The beacon document (SRAD discovery 3.5, appendix C; Java BeaconDocument,
  # UrlLocator): one JSON document a beacon serves at
  # /.well-known/agentspaces/beacon.json (a social beacon under /j/<code>)
  # carrying, per group, the name, the aspace:// id, the founding
  # advertisement (base64 CBOR), the seeds, the wire hints, and, at a social
  # beacon, the public delegation; document-wide the issuer PeerID, its raw
  # key, the issue time, a TTL, and the issuer's Ed25519 signature over the
  # canonical bytes: every field but signature, in declared order, map keys
  # sorted, no whitespace, exactly as Jackson writes them. A signed document
  # arrives as exactly its canonical JSON, signature last (HLC round seven,
  # 2026-11-08); a reader ignores unknown fields of an unsigned one. The
  # document never carries a content key, a credential, or a membership
  # hint. A document is a Hash with String keys, as JSON parses it.
  module Beacon
    # A document, a group, or a founding the reader refuses (Python's ValueError).
    class Error < ArgumentError; end

    # The beacon is unreachable or answered an HTTP error (Python's OSError).
    class FetchError < IOError; end

    VERSION = 1
    WELL_KNOWN = "/.well-known/agentspaces/beacon.json"
    # The largest document accepted (UrlLocator.Options.maxBytes).
    MAX_DOCUMENT_BYTES = 64 * 1024
    # The redirects one fetch follows, each held to the same scheme policy.
    MAX_REDIRECTS = 2
    FORBIDDEN_PARAMETERS = %w[content-key contentkey credential membership hints secret invite-secret
                              join-credential].freeze
    URI_PREFIX = "aspace://"
    # The transports this client dials by default: plain TCP. A peer with
    # more dialers passes their schemes to seeds_of.
    CLIENT_TRANSPORTS = %w[tcp].freeze
    USER_AGENT = "agentspaces-ruby/1"

    # urllib.parse.urlsplit's result, with its hostname and port rules.
    SplitUrl = Data.define(:scheme, :netloc, :path, :query, :fragment) do
      def hostname
        name, = hostinfo
        return nil if name.nil? || name.empty?

        bare, percent, zone = name.partition("%")
        bare.downcase + percent + zone
      end

      def port
        _, text = hostinfo
        return nil if text.nil?
        raise Error, "port could not be cast to integer value as #{text.inspect}" unless text.match?(/\A[0-9]+\z/)

        value = Integer(text, 10)
        raise Error, "port out of range 0-65535" unless value.between?(0, 65_535)

        value
      end

      private

      def hostinfo
        info = netloc.rpartition("@").last
        _, open, bracketed = info.partition("[")
        if open.empty?
          name, _, text = info.partition(":")
        else
          name, _, rest = bracketed.partition("]")
          text = rest.partition(":").last
        end
        [name, text.empty? ? nil : text]
      end
    end

    module_function

    # ---------------------------------------------------------- the document

    # BeaconDocument.Group: seeds are [transport, address] pairs or seed
    # Hashes, numbered by position. Parameters by a forbidden name are
    # refused: a document never carries a secret.
    def document_group(name, group_id = nil, founding = nil, seeds = nil, wire: nil, multicast: nil, parameters: nil,
                       invite: nil)
      (parameters || {}).each_key do |key|
        next unless FORBIDDEN_PARAMETERS.include?(key.to_s.downcase)

        raise Error, "a beacon document never carries #{key.to_s.inspect}"
      end
      group = { "name" => name }
      group["id"] = group_id.start_with?(URI_PREFIX) ? group_id : URI_PREFIX + group_id unless group_id.nil?
      group["founding"] = founding unless founding.nil?
      group["seeds"] = (seeds || []).each_with_index.map do |seed, i|
        seed.is_a?(Hash) ? seed : { "transport" => seed[0], "address" => seed[1], "priority" => i }
      end
      group["wire"] = wire.to_h unless wire.nil?
      group["multicast"] = multicast unless multicast.nil?
      group["parameters"] = parameters.to_h unless parameters.nil?
      group["invite"] = invite unless invite.nil?
      group
    end

    # The bytes the signature covers: every known field but signature, in
    # declared order (v, issuer, issuerKey, issued, ttl, groups), nil fields
    # omitted, map keys sorted, no whitespace. Returns a binary String.
    def canonical_bytes(doc) = jackson_json(canonical_body(doc), true)

    # BeaconDocument.signed: a document issued and signed by issuer.
    def sign_document(issuer, issued_iso, ttl_seconds, groups)
      doc = { "v" => VERSION, "issuer" => issuer.peer_id, "issuerKey" => Base64Text.encode(issuer.public_raw),
              "issued" => issued_iso, "ttl" => Integer(ttl_seconds), "groups" => groups.to_a.dup }
      doc["signature"] = Base64Text.encode(issuer.sign(canonical_bytes(doc)))
      doc
    end

    # The document as one line of JSON, signature last (Python's to_json;
    # named so it does not shadow Object#to_json): Java's toBytes, which
    # Jackson's text writer writes, so a code point past U+FFFF stays as it
    # is. Returns a binary String.
    def document_json(doc)
      body = canonical_body(doc)
      body["signature"] = text_field(doc["signature"], "signature") unless doc["signature"].nil?
      jackson_json(body, false)
    end

    # BeaconDocument.signer: the PeerID the carried key hashes to, when it
    # equals issuer and the signature verifies under it; else nil.
    def document_signer(doc)
      key = Base64Text.decode(doc["issuerKey"] || "")
      signature = Base64Text.decode(doc["signature"] || "")
      return nil if key.bytesize != 32 || signature.empty? || !doc["issuer"].is_a?(String)

      signer = Derive.id(key)
      return nil if signer != doc["issuer"]

      Identity.verify(key, canonical_bytes(doc), signature) ? signer : nil
    rescue ArgumentError, TypeError
      nil
    end

    # UrlLocator.hint's checks (0.5.0): a carried signature must verify; a
    # document with no signature is refused unless allow_unsigned (Java's
    # agentspaces.bootstrap.url-allow-unsigned), because an unsigned document
    # lets whoever serves it choose the seeds; and a pinned beacon_peer must be
    # the verified signer whatever allow_unsigned says. Returns the signer
    # (nil for an allowed unsigned document); raises Beacon::Error otherwise.
    def verify_document(doc, beacon_peer = nil, allow_unsigned: false)
      raise Error, "not a beacon document" if !doc.is_a?(Hash) || int_or_zero(doc["v"]) < 1

      signer = document_signer(doc)
      raise Error, "the beacon document's signature does not verify" if !doc["signature"].nil? && signer.nil?
      if doc["signature"].nil? && !allow_unsigned && beacon_peer.nil?
        raise Error, "the beacon document carries no signature, and an unsigned document lets its publisher " \
                     "choose the seeds; pass allow_unsigned: true (agentspaces.bootstrap.url-allow-unsigned) to " \
                     "accept one"
      end
      if !beacon_peer.nil? && signer != beacon_peer
        raise Error, "the beacon document is not signed by the pinned beacon #{beacon_peer}"
      end

      signer
    end

    # -------------------------------------------------------------- fetching

    # One GET, at most MAX_REDIRECTS redirects each held to the same scheme
    # policy, the body capped at MAX_DOCUMENT_BYTES. Tests replace it on the
    # module (fetch_beacon_document calls Beacon.http_get).
    def http_get(url, timeout, allow_plain)
      current = url
      redirects = 0
      loop do
        uri = URI.parse(current)
        outcome = get_once(uri, timeout)
        return outcome unless outcome.is_a?(URI::Generic)

        raise FetchError, "GET #{url}: redirect limit" if redirects >= MAX_REDIRECTS

        check_scheme(outcome.to_s, allow_plain)
        redirects += 1
        current = outcome.to_s
      end
    rescue URI::InvalidURIError => e
      raise Error, "GET #{url}: #{e.message}"
    end

    # Refuses a URL that is not https (http only with allow_plain) or names no host.
    def check_scheme(url, allow_plain)
      parts = urlsplit(url)
      scheme = parts.scheme.downcase
      unless scheme == "https" || (scheme == "http" && allow_plain)
        raise Error, "refusing #{url}: only https (allow_plain permits http)"
      end
      raise Error, "refusing #{url}: no host" if parts.hostname.nil?
    end

    # Fetches, parses, and verifies a beacon document: https only unless
    # allow_plain; at most 64 KiB; a carried signature must verify under a
    # key hashing to issuer; with beacon_peer that signer is required.
    # Raises Beacon::Error (policy, shape, signature) or Beacon::FetchError.
    def fetch_beacon_document(url, allow_plain: false, beacon_peer: nil, timeout: 3.0, allow_unsigned: false)
      check_scheme(url, allow_plain)
      body = begin
        Beacon.http_get(url, timeout, allow_plain)
      rescue FetchError, Error
        raise
      rescue SystemCallError, SocketError, IOError, Timeout::Error, OpenSSL::SSL::SSLError, Net::HTTPBadResponse,
             Net::ProtocolError => e
        raise FetchError, "GET #{url}: #{e.message}"
      end
      doc = begin
        parse_document(body)
      rescue Error => e
        raise Error, "GET #{url}: #{e.message}"
      end
      verify_document(doc, beacon_peer, allow_unsigned: allow_unsigned)
      doc
    end

    # The document the JSON bytes body hold. An unsigned document reads
    # leniently in form, with whitespace, any member order, and unknown
    # members, while every member it names holds its Java type, signed or not
    # (SPEC v0.1.32 9.3, 2026-11-09): a group name sent as a number or a ttl
    # sent as text refuses it, as Java's reader refuses it. A document that
    # carries a signature must be exactly its canonical JSON, document_json of
    # what it decodes to, as Java's
    # BeaconDocument.parse requires (HLC round seven, 2026-11-08, owner ruling
    # F3 applied to the beacon document): the signature covers
    # canonical_bytes, which are then the bytes received less the signature
    # member, so whitespace, another member order, an unknown or repeated
    # member, another escape, or a number in another form refuses the
    # document instead of relabelling it. Raises Beacon::Error otherwise.
    def parse_document(body)
      text = body.dup.force_encoding(Encoding::UTF_8)
      raise Error, "not a JSON document" unless text.valid_encoding?

      doc = begin
        JSON.parse(text, allow_nan: true, allow_duplicate_key: true)
      rescue JSON::ParserError
        raise Error, "not a JSON document"
      end
      raise Error, "not a beacon document" unless doc.is_a?(Hash)

      refuse_malformed_groups(doc)
      canonical_body(doc)
      if !doc["signature"].nil? && document_json(doc).b != body.b
        raise Error, "a signed beacon document is not its canonical JSON"
      end
      if !doc["signature"].nil? && !(canonical_base64?(doc["signature"]) && canonical_base64?(doc["issuerKey"]))
        raise Error, "a signed beacon document's signature or key is not canonical base64"
      end

      doc
    end

    # ------------------------------------------------------------- selection

    # The bare GroupID of an aspace://<id> URI or a bare id.
    def parse_group_id(text)
      return nil unless text.is_a?(String) && !text.strip.empty?

      text = text.strip
      text.start_with?(URI_PREFIX) ? text[URI_PREFIX.size..] : text
    end

    # The group a document carries: by id when given, else by name, else the
    # only group (a social beacon serves one per code). Raises Beacon::Error
    # when there is no such group.
    def group_from_document(doc, group_id: nil, name: nil)
      groups = Array(doc["groups"]).grep(Hash)
      unless group_id.nil?
        wanted = parse_group_id(group_id)
        found = groups.find { |group| parse_group_id(group["id"]) == wanted }
        raise Error, "the beacon document carries no group #{group_id}" if found.nil?

        return found
      end
      unless name.nil?
        found = groups.find { |group| group["name"] == name }
        raise Error, "the beacon document carries no group named #{name.inspect}" if found.nil?

        return found
      end
      return groups[0] if groups.size == 1

      raise Error, "the beacon document carries #{groups.size} groups; name one"
    end

    # The decoded SignedGroupAdvertisement a group carries, or nil.
    def founding_of(group)
      founding = group["founding"]
      return nil if falsy?(founding)

      begin
        Schema.load("SignedGroupAdvertisement", Base64Text.decode(founding))
      rescue ArgumentError, TypeError
        raise Error, "the founding of #{group['name'].inspect} is not a SignedGroupAdvertisement in base64 CBOR"
      end
    end

    # The GroupID the group's founding verifies to (the four checks of SPEC
    # 5.1), which must also be the group's id and, when given, the expected
    # id. Raises Beacon::Error otherwise.
    def verified_group_id(group, expected = nil)
      signed = founding_of(group)
      raise Error, "the beacon document carries no founding for #{group['name'].inspect}" if signed.nil?

      derived = Founding.verify(signed)
      raise Error, "the founding of #{group['name'].inspect} does not verify" if derived.nil?
      if !group["id"].nil? && parse_group_id(group["id"]) != derived
        raise Error, "the founding of #{group['name'].inspect} derives to #{derived}, not its id"
      end
      if !expected.nil? && parse_group_id(expected) != derived
        raise Error, "the founding of #{group['name'].inspect} derives to #{derived}, not #{expected}"
      end

      derived
    end

    # host:port ([v6]:port) as [host, port].
    def seed_address(address)
      text = address.to_s.strip
      if text.start_with?("[")
        host, _, port = text[1..].partition("]")
        port = port.sub(/\A:+/, "")
      else
        host, _, port = text.rpartition(":")
      end
      raise Error, "not a seed address: #{address.inspect}" if host.empty? || !port.match?(/\A[0-9]+\z/)

      [host, Integer(port, 10)]
    end

    # The group's seeds this client can dial, by priority (stable), as Seed
    # values whose scheme is the seed's transport. Python returns (host,
    # port) pairs because it dials tcp alone; a Seed keeps the scheme for a
    # peer with more dialers.
    def seeds_of(group, transports = CLIENT_TRANSPORTS)
      seeds = Array(group["seeds"]).grep(Hash).each_with_index
                                   .sort_by { |seed, i| [int_or_zero(seed["priority"]), i] }.map(&:first)
      seeds.filter_map do |seed|
        transport = falsy?(seed["transport"]) ? "tcp" : seed["transport"].to_s.downcase
        next if !transports.include?(transport) || falsy?(seed["address"])

        host, port = seed_address(seed["address"])
        Seed.new(scheme: transport, host: host, port: port)
      rescue Error
        nil
      end
    end

    # ------------------------------------------------------------- internals

    # urllib.parse.urlsplit: leading C0 controls and spaces stripped, tab and
    # newline characters removed, then scheme, netloc, path, query, fragment.
    def urlsplit(url)
      text = url.to_s.sub(/\A[\x00-\x20]+/, "").delete("\t\r\n")
      scheme = ""
      colon = text.index(":")
      if colon&.positive? && text[0].match?(/[A-Za-z]/) && text[0...colon].match?(/\A[A-Za-z0-9+\-.]+\z/)
        scheme = text[0...colon].downcase
        text = text[(colon + 1)..]
      end
      netloc = ""
      if text.start_with?("//")
        ends = %w[/ ? #].filter_map { |c| text.index(c, 2) }.min || text.size
        netloc = text[2...ends]
        text = text[ends..]
        raise Error, "invalid IPv6 URL" if netloc.include?("[") != netloc.include?("]")
      end
      fragment = ""
      text, fragment = text.split("#", 2) if text.include?("#")
      query = ""
      text, query = text.split("?", 2) if text.include?("?")
      SplitUrl.new(scheme: scheme, netloc: netloc, path: text.to_s, query: query.to_s, fragment: fragment.to_s)
    end

    # One request; the body (a binary String), or the URI a redirect names.
    def get_once(uri, timeout)
      raise Error, "GET #{uri}: no host" if uri.hostname.nil? || uri.hostname.empty?

      http = Net::HTTP.new(uri.hostname, uri.port)
      http.use_ssl = uri.scheme.to_s.downcase == "https"
      http.open_timeout = timeout
      http.read_timeout = timeout
      http.write_timeout = timeout
      http.ssl_timeout = timeout if http.use_ssl?
      # The headers are explicit: JSON accepted, and identity so the cap
      # counts the bytes on the wire as the Python fetch does.
      request = Net::HTTP::Get.new(uri.request_uri, "Accept" => "application/json", "User-Agent" => USER_AGENT,
                                                    "Accept-Encoding" => "identity")
      http.start do |connection|
        connection.request(request) do |response|
          code = response.code.to_i
          if [301, 302, 303, 307, 308].include?(code)
            location = response["location"]
            raise FetchError, "GET #{uri}: HTTP #{code} without a location" if location.nil? || location.empty?

            return URI.join(uri.to_s, location)
          end
          raise FetchError, "GET #{uri}: HTTP #{code} #{response.message}" if code >= 300 || code < 200
          raise Error, "GET #{uri}: HTTP #{code}" if code != 200

          return read_capped(response, uri)
        end
      end
    end

    def read_capped(response, uri)
      body = String.new(encoding: Encoding::BINARY)
      response.read_body do |chunk|
        body << chunk.b
        next if body.bytesize <= MAX_DOCUMENT_BYTES

        raise Error, "GET #{uri}: the document exceeds #{MAX_DOCUMENT_BYTES} bytes"
      end
      body
    end

    # What Java's Group record refuses in a document signed or not: a group
    # that is no object or has no name, a seed that is no object, and a
    # parameter by a forbidden name (HLC round seven, 2026-11-08).
    def refuse_malformed_groups(doc)
      groups = doc["groups"]
      (groups.is_a?(Array) ? groups : []).each do |group|
        raise Error, "not a beacon document: a group is no object with a name" unless group.is_a?(Hash) && !group["name"].nil?

        seeds = group["seeds"]
        raise Error, "not a beacon document: a seed is no object" if seeds.is_a?(Array) && !seeds.all?(Hash)

        parameters = group["parameters"]
        if parameters.is_a?(Hash) && parameters.keys.any? { |key| FORBIDDEN_PARAMETERS.include?(key.to_s.downcase) }
          raise Error, "a beacon document never carries a secret"
        end
      end
    end

    # Java's field types: an int (v, a seed's priority, a wire hint) and a
    # long (ttl).
    JAVA_INT = (-(1 << 31)..(1 << 31) - 1).freeze
    JAVA_LONG = (-(1 << 63)..(1 << 63) - 1).freeze

    # Every known field but signature, in declared order (v, issuer,
    # issuerKey, issued, ttl, groups), nil fields omitted, each of its Java
    # type or a Beacon::Error (HLC round seven, 2026-11-08).
    def canonical_body(doc)
      body = { "v" => java_integer(doc["v"], JAVA_INT, "v") }
      %w[issuer issuerKey issued].each { |key| body[key] = text_field(doc[key], key) unless doc[key].nil? }
      body["ttl"] = java_integer(doc["ttl"], JAVA_LONG, "ttl")
      groups = doc["groups"].nil? ? [] : doc["groups"]
      raise Error, "groups are a list" unless groups.is_a?(Array)

      body["groups"] = groups.map { |group| canonical_group(group) }
      body
    end

    def canonical_group(group)
      raise Error, "a group is an object with a name" unless group.is_a?(Hash) && group["name"].is_a?(String)

      out = { "name" => group["name"] }
      %w[id founding].each { |key| out[key] = text_field(group[key], key) unless group[key].nil? }
      seeds = group["seeds"].nil? ? [] : group["seeds"]
      raise Error, "seeds are a list of objects" unless seeds.is_a?(Array) && seeds.all?(Hash)

      out["seeds"] = seeds.map do |seed|
        { "transport" => text_field(seed["transport"], "transport"), "address" => text_field(seed["address"], "address"),
          "priority" => java_integer(seed["priority"], JAVA_INT, "priority") }
      end
      unless group["wire"].nil?
        out["wire"] = sorted_map(group["wire"], "wire") { |v, what| v.nil? ? nil : java_integer(v, JAVA_INT, what) }
      end
      out["multicast"] = text_field(group["multicast"], "multicast") unless group["multicast"].nil?
      out["parameters"] = sorted_map(group["parameters"], "parameters") { |v, what| text_field(v, what) } unless group["parameters"].nil?
      out["invite"] = text_field(group["invite"], "invite") unless group["invite"].nil?
      out
    end

    # A JSON integer the Java field holds; nil reads as Java's default 0.
    def java_integer(value, range, what)
      return 0 if value.nil?
      raise Error, "#{what} is no integer a Java #{range == JAVA_INT ? 'int' : 'long'} holds" unless
        value.is_a?(Integer) && range.cover?(value)

      value
    end

    def text_field(value, what)
      raise Error, "#{what} is not text" unless value.nil? || value.is_a?(String)

      value
    end

    # A Map<String, X> as Jackson's ORDER_MAP_ENTRIES_BY_KEYS writes it: keys
    # in String.compareTo order, UTF-16 code units.
    def sorted_map(map, what)
      raise Error, "#{what} is not an object" unless map.is_a?(Hash)

      map.keys.sort_by { |key| Wire.java_order(key) }.to_h { |key| [key, yield(map[key], "#{what}.#{key}")] }
    end

    # Whether text is absent or the padded standard base64 of its bytes.
    def canonical_base64?(text)
      text.nil? || (text.is_a?(String) && [text.unpack1("m0")].pack("m0") == text)
    rescue ArgumentError
      false
    end

    # Jackson's compact JSON of the canonical body: no whitespace, members in
    # the order built. The signed bytes come from Jackson's byte writer, which
    # writes each UTF-16 surrogate as an upper-case \uXXXX escape.
    def jackson_json(value, signed)
      out = +""
      write_json(value, out, signed)
      out.b
    end

    JSON_ESCAPES = { '"' => '\\"', "\\" => "\\\\", "\n" => "\\n", "\r" => "\\r", "\t" => "\\t", "\b" => "\\b",
                     "\f" => "\\f" }.freeze

    def write_json(value, out, signed)
      case value
      when nil then out << "null"
      when Integer then out << value.to_s
      when String then write_json_string(value, out, signed)
      when Array
        out << "["
        value.each_with_index do |item, i|
          out << "," if i.positive?
          write_json(item, out, signed)
        end
        out << "]"
      else
        out << "{"
        value.each_with_index do |(key, item), i|
          out << "," if i.positive?
          write_json_string(key, out, signed)
          out << ":"
          write_json(item, out, signed)
        end
        out << "}"
      end
    end

    # A string as Jackson writes it: the quote, the backslash and the short
    # escapes, any other control character as upper-case \u00XX, and past
    # U+FFFF, in the signed bytes, the two surrogates escaped.
    def write_json_string(text, out, signed)
      utf8 = text.encoding == Encoding::UTF_8 ? text : text.dup.force_encoding(Encoding::UTF_8)
      raise Error, "a JSON string is not valid UTF-8" unless utf8.valid_encoding?

      pattern = signed ? /["\\\x00-\x1f]|[^\u0000-\uffff]/ : /["\\\x00-\x1f]/
      out << '"'
      out << utf8.gsub(pattern) do |c|
        if JSON_ESCAPES.key?(c) then JSON_ESCAPES[c]
        elsif c.ord < 0x20 then format("\\u%04X", c.ord)
        else
          code = c.ord - 0x10000
          format("\\u%04X\\u%04X", 0xD800 + (code >> 10), 0xDC00 + (code & 0x3FF))
        end
      end
      out << '"'
    end

    # Python truthiness for the values a JSON document carries.
    def falsy?(value)
      value.nil? || value == false || (value.is_a?(Numeric) && value.zero?) ||
        (value.respond_to?(:empty?) && value.empty?)
    end

    # int(value) as Python computes it for JSON values.
    def py_int(value)
      case value
      when true then 1
      when false then 0
      when Integer then value
      when Float
        raise ArgumentError, "cannot convert float #{value} to integer" if value.nan? || value.infinite?

        value.truncate
      when String then Integer(value.strip.delete_prefix("+"), 10)
      else raise TypeError, "int() argument must be a string or a number, not #{value.class}"
      end
    end

    # int(value or 0), the reading the canonical form gives v, ttl, and priority.
    def int_or_zero(value) = falsy?(value) ? 0 : py_int(value)

    private_class_method :get_once, :read_capped, :canonical_body, :canonical_group, :java_integer, :text_field,
                         :sorted_map, :canonical_base64?, :refuse_malformed_groups, :jackson_json, :write_json, :write_json_string
  end
end
