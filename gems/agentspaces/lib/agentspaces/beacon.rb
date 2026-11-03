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
  # sorted, no whitespace, exactly as Jackson writes them. A reader ignores
  # unknown fields. The document never carries a content key, a credential,
  # or a membership hint. A document is a Hash with String keys, as JSON
  # parses it.
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
    def canonical_bytes(doc) = jackson_json(canonical_body(doc))

    # BeaconDocument.signed: a document issued and signed by issuer.
    def sign_document(issuer, issued_iso, ttl_seconds, groups)
      doc = { "v" => VERSION, "issuer" => issuer.peer_id, "issuerKey" => Base64Text.encode(issuer.public_raw),
              "issued" => issued_iso, "ttl" => Integer(ttl_seconds), "groups" => groups.to_a.dup }
      doc["signature"] = Base64Text.encode(issuer.sign(canonical_bytes(doc)))
      doc
    end

    # The document as one line of JSON, signature last (Python's to_json;
    # named so it does not shadow Object#to_json). Returns a binary String.
    def document_json(doc)
      body = canonical_body(doc)
      body["signature"] = doc["signature"] unless doc["signature"].nil?
      jackson_json(body)
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
      text = body.dup.force_encoding(Encoding::UTF_8)
      raise Error, "GET #{url}: not a JSON document" unless text.valid_encoding?

      doc = begin
        JSON.parse(text, allow_nan: true, allow_duplicate_key: true)
      rescue JSON::ParserError
        raise Error, "GET #{url}: not a JSON document"
      end
      verify_document(doc, beacon_peer, allow_unsigned: allow_unsigned)
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

      signed = begin
        CBOR.load(Base64Text.decode(founding))
      rescue ArgumentError, TypeError
        raise Error, "the founding of #{group['name'].inspect} is not base64 CBOR"
      end
      signed.is_a?(Hash) ? signed : nil
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

    def canonical_body(doc)
      body = { "v" => int_or_zero(doc["v"]) }
      %w[issuer issuerKey issued].each { |key| body[key] = doc[key] unless doc[key].nil? }
      body["ttl"] = int_or_zero(doc["ttl"])
      groups = doc["groups"]
      groups = [] if falsy?(groups)
      raise TypeError, "groups is not a list" unless groups.is_a?(Array)

      body["groups"] = groups.map { |group| canonical_group(group) }
      body
    end

    def canonical_group(group)
      raise TypeError, "a group is not an object" unless group.is_a?(Hash)

      out = { "name" => group["name"] }
      %w[id founding].each { |key| out[key] = group[key] unless group[key].nil? }
      seeds = group["seeds"]
      seeds = [] if falsy?(seeds)
      raise TypeError, "seeds is not a list" unless seeds.is_a?(Array)

      out["seeds"] = seeds.map do |seed|
        raise TypeError, "a seed is not an object" unless seed.is_a?(Hash)

        { "transport" => seed["transport"], "address" => seed["address"],
          "priority" => int_or_zero(seed["priority"]) }
      end
      unless group["wire"].nil?
        out["wire"] = group["wire"].to_h.sort_by { |k, _| k.to_s }.to_h { |k, v| [k, py_int(v)] }
      end
      out["multicast"] = group["multicast"] unless group["multicast"].nil?
      out["parameters"] = group["parameters"].to_h.sort_by { |k, _| k.to_s }.to_h unless group["parameters"].nil?
      out["invite"] = group["invite"] unless group["invite"].nil?
      out
    end

    # Jackson's compact JSON as the Python twin writes it: no whitespace,
    # non-ASCII unescaped, control characters as short escapes or upper-case
    # \u00XX. Python upper-cases every "\u00xx" run of the encoded text,
    # including one that follows an escaped backslash (a literal "«"
    # in a value); this does the same so the signed bytes stay identical.
    def jackson_json(value)
      text = +""
      write_json(value, text)
      text.gsub(/\\u00([0-9a-f]{2})/) { "\\u00#{Regexp.last_match(1).upcase}" }.b
    end

    JSON_ESCAPES = { '"' => '\\"', "\\" => "\\\\", "\n" => "\\n", "\r" => "\\r", "\t" => "\\t", "\b" => "\\b",
                     "\f" => "\\f" }.freeze

    def write_json(value, out)
      case value
      when nil then out << "null"
      when true then out << "true"
      when false then out << "false"
      when Integer then out << value.to_s
      when Float
        raise ArgumentError, "out of range float values are not JSON compliant" if value.nan? || value.infinite?

        out << python_float(value)
      when String, Symbol then write_json_string(value.to_s, out)
      when Array
        out << "["
        value.each_with_index do |item, i|
          out << "," if i.positive?
          write_json(item, out)
        end
        out << "]"
      when Hash
        out << "{"
        value.each_with_index do |(key, item), i|
          out << "," if i.positive?
          write_json_string(json_key(key), out)
          out << ":"
          write_json(item, out)
        end
        out << "}"
      else
        raise TypeError, "#{value.class} is not JSON serializable"
      end
    end

    def write_json_string(text, out)
      utf8 = text.encoding == Encoding::UTF_8 ? text : text.dup.force_encoding(Encoding::UTF_8)
      raise ArgumentError, "a JSON string is not valid UTF-8" unless utf8.valid_encoding?

      out << '"'
      out << utf8.gsub(/["\\\x00-\x1f]/) { |c| JSON_ESCAPES[c] || format("\\u%04x", c.ord) }
      out << '"'
    end

    # json.dumps keys: text as is; numbers, booleans and null by their JSON text.
    def json_key(key)
      case key
      when String, Symbol then key.to_s
      when nil then "null"
      when true, false then key.to_s
      when Float then python_float(key)
      else key.to_s
      end
    end

    # Python's float repr: the shortest round-trip digits (Ruby's), written
    # fixed when the decimal exponent lies in [-4, 16) and as "1.5e+16"
    # otherwise. Built from the digits alone, because MRI and JRuby print
    # large floats differently.
    def python_float(value)
      return value.to_s if value.zero?

      m = value.abs.to_s.match(/\A(\d+)(?:\.(\d+))?(?:e([+-]?\d+))?\z/i)
      digits = m[1] + m[2].to_s
      point = m[1].size + m[3].to_i
      lead = digits[/\A0*/].size
      digits = digits[lead..]
      point -= lead
      digits = digits.sub(/0+\z/, "")
      digits = "0" if digits.empty?
      exponent = point - 1
      text =
        if exponent >= -4 && exponent < 16
          if point <= 0 then "0.#{'0' * -point}#{digits}"
          elsif point >= digits.size then "#{digits}#{'0' * (point - digits.size)}.0"
          else "#{digits[0...point]}.#{digits[point..]}"
          end
        else
          mantissa = digits.size > 1 ? "#{digits[0]}.#{digits[1..]}" : digits
          "#{mantissa}e#{exponent.negative? ? '-' : '+'}#{exponent.abs.to_s.rjust(2, '0')}"
        end
      value.negative? ? "-#{text}" : text
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

    private_class_method :get_once, :read_capped, :canonical_body, :canonical_group, :write_json, :write_json_string,
                         :json_key, :python_float
  end
end
