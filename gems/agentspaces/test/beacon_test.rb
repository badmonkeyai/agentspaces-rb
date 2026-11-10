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

require_relative "test_helper"
require "agentspaces/bootstrap"

# One document (or any bytes) served over loopback HTTP by a TCPServer, since
# webrick is not a default gem: each request is recorded as [path, Accept]
# and answered once, then the connection is closed.
class BeaconTestServer
  attr_reader :requests, :url

  def initialize(body, status: 200, path: AgentSpaces::Beacon::WELL_KNOWN)
    @body = body.b
    @status = status
    @path = path
    @requests = []
    @lock = Mutex.new
    @server = TCPServer.new("127.0.0.1", 0)
    @url = "http://127.0.0.1:#{@server.addr[1]}#{path}"
    @thread = Thread.new { accept_loop }
    @thread.report_on_exception = false
  end

  def requests_made = @lock.synchronize { @requests.dup }

  def close
    @server.close unless @server.closed?
    @thread.join(1)
  end

  private

  def accept_loop
    loop do
      client = @server.accept
      worker = Thread.new { answer(client) }
      worker.report_on_exception = false
    end
  rescue IOError, SystemCallError
    nil
  end

  def answer(client)
    request_line = client.gets
    return if request_line.nil?

    headers = {}
    while (line = client.gets) && line != "\r\n" && line != "\n"
      name, value = line.split(":", 2)
      headers[name.strip.downcase] = value.to_s.strip
    end
    path = request_line.split(" ")[1]
    @lock.synchronize { @requests << [path, headers["accept"]] }
    status, body = path == @path ? [@status, @body] : [404, "".b]
    client.write("HTTP/1.1 #{status} #{status == 200 ? 'OK' : 'Status'}\r\nContent-Type: application/json\r\n" \
                 "Content-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n")
    client.write(body)
  rescue IOError, SystemCallError
    nil
  ensure
    client&.close
  end
end

# The beacon document (SRAD 3.5, appendix C) fetched from a loopback HTTP
# server: a signed document verifies, a tampered one is refused, a pinned
# beacon is honoured, http needs allow_plain, and the body is capped.
class BeaconTest < Minitest::Test
  include AgentSpaces

  # A document Java's BeaconDocument.signed wrote for the issuer seeded
  # 0x10..0x2f (the golden founder) at 2026-10-14T00:00:00Z, ttl 300: one
  # full group (a non-ASCII, quoted, control-character parameter included)
  # and one bare group.
  JAVA_SIGNED_DOCUMENT = <<~'JSON'.chomp
    {"v":1,"issuer":"zhRv4SRobYBddjUoVn2YuPutUyi8zmqUhchSpL2uvotR","issuerKey":"d3bocLkzVPKgskwj8qNsxOgOIjIYwbl5Jv3QGDlqK5s=","issued":"2026-10-14T00:00:00Z","ttl":300,"groups":[{"name":"weekend-hack","id":"aspace://zG","founding":"AA==","seeds":[{"transport":"tls","address":"seed-a.corp.example:7500","priority":0},{"transport":"tcp","address":"127.0.0.1:7500","priority":1}],"wire":{"batch":1,"session":1},"multicast":"239.255.42.99:7787","parameters":{"a":"ü \"q\" \u0001","region":"eu-west-1"},"invite":"QQ=="},{"name":"bare","seeds":[]}],"signature":"7gGY0YkDJfdrSzjbeVZTjkV+zr4o9H1MqVC8Ab7D4qoWMiuFt4qUEF99yidhtIJxzZAcvl3QbA23ST6zY02gAw=="}
  JSON
  JAVA_CANONICAL_BYTES = <<~'JSON'.chomp
    {"v":1,"issuer":"zhRv4SRobYBddjUoVn2YuPutUyi8zmqUhchSpL2uvotR","issuerKey":"d3bocLkzVPKgskwj8qNsxOgOIjIYwbl5Jv3QGDlqK5s=","issued":"2026-10-14T00:00:00Z","ttl":300,"groups":[{"name":"weekend-hack","id":"aspace://zG","founding":"AA==","seeds":[{"transport":"tls","address":"seed-a.corp.example:7500","priority":0},{"transport":"tcp","address":"127.0.0.1:7500","priority":1}],"wire":{"batch":1,"session":1},"multicast":"239.255.42.99:7787","parameters":{"a":"ü \"q\" \u0001","region":"eu-west-1"},"invite":"QQ=="},{"name":"bare","seeds":[]}]}
  JSON

  def founding(founder, name = "research-fleet")
    Founding.found(founder, name, "OPEN", "LEASE_RACE", 3, "PT1S", "2026-10-14T00:00:00Z", "PT8760H")
  end

  def document(issuer, founder)
    signed = founding(founder)
    group = Beacon.document_group("research-fleet", signed["advertisement"]["group"],
                                  Base64Text.encode(CBOR.dump(signed)),
                                  [["tls", "seed-a.corp.example:7500"], ["tcp", "127.0.0.1:7500"]],
                                  wire: { "session" => 1, "batch" => 1 }, parameters: { "region" => "eu-west-1" })
    other = Beacon.document_group("other", nil, nil, [["tcp", "127.0.0.1:7600"]])
    Beacon.sign_document(issuer, "2026-10-14T00:00:00Z", 300, [group, other])
  end

  def serve(body, **options)
    server = BeaconTestServer.new(body, **options)
    yield server
  ensure
    server&.close
  end

  def seed(host, port) = Seed.new(scheme: "tcp", host: host, port: port)

  def test_canonical_bytes_are_jacksons
    issuer = Identity.generate
    group = Beacon.document_group("g", "zG", "AA==", [["tcp", "h:1"]], wire: { "session" => 1, "batch" => 1 },
                                                                       multicast: "239.255.42.99:7787",
                                                                       parameters: { "b" => "2", "a" => "1" },
                                                                       invite: "QQ==")
    doc = Beacon.sign_document(issuer, "2026-10-14T00:00:00Z", 300, [group])
    key = Base64Text.encode(issuer.public_raw)
    assert_equal(("{\"v\":1,\"issuer\":\"#{issuer.peer_id}\",\"issuerKey\":\"#{key}\"," \
                  '"issued":"2026-10-14T00:00:00Z","ttl":300,"groups":[{"name":"g","id":"aspace://zG",' \
                  '"founding":"AA==","seeds":[{"transport":"tcp","address":"h:1","priority":0}],' \
                  '"wire":{"batch":1,"session":1},"multicast":"239.255.42.99:7787",' \
                  '"parameters":{"a":"1","b":"2"},"invite":"QQ=="}]}').b, Beacon.canonical_bytes(doc))
    # Unknown fields and pretty whitespace do not change the signed bytes.
    reparsed = JSON.parse(JSON.pretty_generate(doc.merge("extra" => 1)))
    reparsed["groups"][0]["unknown"] = "x"
    assert_equal Beacon.canonical_bytes(doc), Beacon.canonical_bytes(reparsed)
    assert_equal issuer.peer_id, Beacon.verify_document(reparsed, issuer.peer_id)
    assert_equal doc, JSON.parse(Beacon.document_json(doc))
    assert_raises(Beacon::Error) { Beacon.document_group("g", parameters: { "content-key" => "x" }) }
    assert_raises(Beacon::Error) { Beacon.document_group("g", parameters: { "Join-Credential" => "x" }) }
  end

  def test_a_served_signed_document_verifies_and_selects
    issuer = Identity.generate
    founder = Identity.generate
    doc = document(issuer, founder)
    serve(Beacon.document_json(doc)) do |served|
      fetched = Beacon.fetch_beacon_document(served.url, allow_plain: true)
      assert_equal doc, fetched
      assert_equal "application/json", served.requests_made[0][1]
      group_id = founding(founder)["advertisement"]["group"]
      by_id = Beacon.group_from_document(fetched, group_id: group_id)
      assert_equal "research-fleet", by_id["name"]
      assert_same by_id, Beacon.group_from_document(fetched, group_id: "aspace://#{group_id}")
      assert_equal "other", Beacon.group_from_document(fetched, name: "other")["name"]
      assert_raises(Beacon::Error) { Beacon.group_from_document(fetched) } # two groups: name one
      assert_raises(Beacon::Error) { Beacon.group_from_document(fetched, group_id: "zNope") }
      assert_equal group_id, Beacon.verified_group_id(by_id)
      assert_equal group_id, Beacon.verified_group_id(by_id, group_id)
      assert_raises(Beacon::Error) { Beacon.verified_group_id(by_id, "zOther") }
      assert_raises(Beacon::Error) { Beacon.verified_group_id(Beacon.group_from_document(fetched, name: "other")) }
      # The tls seed is not this client's; the tcp one is, in priority order.
      assert_equal [seed("127.0.0.1", 7500)], Beacon.seeds_of(by_id)
      assert_equal [Seed.new(scheme: "tls", host: "seed-a.corp.example", port: 7500), seed("127.0.0.1", 7500)],
                   Beacon.seeds_of(by_id, %w[tls tcp])
    end
  end

  def test_a_tampered_signature_or_body_is_refused
    issuer = Identity.generate
    founder = Identity.generate
    doc = document(issuer, founder)
    bad_signature = doc.merge("signature" => Base64Text.encode("\x00".b * 64))
    bad_body = JSON.parse(JSON.generate(doc))
    bad_body["groups"][0]["seeds"][1]["address"] = "evil.example:7500"
    wrong_issuer = doc.merge("issuer" => Identity.generate.peer_id)
    [bad_signature, bad_body, wrong_issuer].each do |body|
      serve(Beacon.document_json(body)) do |served|
        assert_raises(Beacon::Error) { Beacon.fetch_beacon_document(served.url, allow_plain: true) }
      end
    end
  end

  def test_the_pinned_beacon_is_honoured
    issuer = Identity.generate
    founder = Identity.generate
    doc = document(issuer, founder)
    serve(Beacon.document_json(doc)) do |served|
      assert_equal doc, Beacon.fetch_beacon_document(served.url, allow_plain: true, beacon_peer: issuer.peer_id)
      assert_raises(Beacon::Error) do
        Beacon.fetch_beacon_document(served.url, allow_plain: true, beacon_peer: Identity.generate.peer_id)
      end
    end
    # 0.5.0, as Java's UrlLocator: an unsigned document is refused unless
    # allow_unsigned, and a pin requires the signature whatever it says.
    unsigned = doc.except("signature")
    serve(Beacon.document_json(unsigned)) do |served|
      error = assert_raises(Beacon::Error) { Beacon.fetch_beacon_document(served.url, allow_plain: true) }
      assert_match(/carries no signature.*allow_unsigned: true/, error.message)
      assert_equal unsigned, Beacon.fetch_beacon_document(served.url, allow_plain: true, allow_unsigned: true)
      assert_raises(Beacon::Error) do
        Beacon.fetch_beacon_document(served.url, allow_plain: true, beacon_peer: issuer.peer_id, allow_unsigned: true)
      end
    end
  end

  def test_plain_http_needs_allow_plain_and_the_body_is_capped
    issuer = Identity.generate
    founder = Identity.generate
    doc = document(issuer, founder)
    serve(Beacon.document_json(doc)) do |served|
      assert_raises(Beacon::Error) { Beacon.fetch_beacon_document(served.url) }
      assert_empty served.requests_made, "refused before any request"
      assert_raises(Beacon::Error) { Beacon.fetch_beacon_document("ftp://127.0.0.1/x", allow_plain: true) }
      assert_raises(Beacon::Error) { Beacon.fetch_beacon_document("https:///x") }
    end
    serve("[#{'1,' * (Beacon::MAX_DOCUMENT_BYTES / 2)}1]") do |big|
      error = assert_raises(Beacon::Error) { Beacon.fetch_beacon_document(big.url, allow_plain: true) }
      assert_match(/exceeds/, error.message)
    end
    serve("{}", status: 404) do |missing|
      assert_raises(IOError) { Beacon.fetch_beacon_document(missing.url, allow_plain: true) }
    end
    serve("not json") do |garbled|
      assert_raises(Beacon::Error) { Beacon.fetch_beacon_document(garbled.url, allow_plain: true) }
    end
  end

  def test_a_redirect_is_held_to_the_scheme_policy_and_the_limit
    issuer = Identity.generate
    doc = document(issuer, Identity.generate)
    serve(Beacon.document_json(doc), path: "/doc") do |target|
      hops = [target.url]
      redirectors = Array.new(3) do
        redirector = RedirectServer.new(hops.last)
        hops << redirector.url
        redirector
      end
      begin
        # Two redirects are followed; a third is refused.
        assert_equal doc, Beacon.fetch_beacon_document(hops[2], allow_plain: true)
        assert_raises(IOError) { Beacon.fetch_beacon_document(hops[3], allow_plain: true) }
      ensure
        redirectors.each(&:close)
      end
    end
  end

  def test_a_document_java_signed_verifies_and_its_canonical_bytes_are_reproduced
    doc = JSON.parse(JAVA_SIGNED_DOCUMENT)
    issuer = Identity.from_seed((0x10...0x30).to_a.pack("C*"))
    assert_equal issuer.peer_id, doc["issuer"]
    assert_equal JAVA_CANONICAL_BYTES.b, Beacon.canonical_bytes(doc)
    assert_equal issuer.peer_id, Beacon.verify_document(doc, issuer.peer_id)
    assert_equal JAVA_SIGNED_DOCUMENT.b, Beacon.document_json(doc)
    # The same document re-signed by the Ruby issuer carries Java's signature exactly.
    resigned = Beacon.sign_document(issuer, doc["issued"], doc["ttl"], doc["groups"])
    assert_equal doc["signature"], resigned["signature"]
  end

  # SRAD dtls-support DT-C-01: a dtls or udp seed is skipped for the next one this client speaks.
  def test_seeds_skip_datagram_schemes_this_client_cannot_dial
    group = { "seeds" => [
      { "transport" => "dtls", "address" => "10.0.0.5:7502", "priority" => 0 },
      { "transport" => "udp", "address" => "10.0.0.5:7503", "priority" => 1 },
      { "transport" => "tcp", "address" => "10.0.0.5:7500", "priority" => 2 }
    ] }
    assert_equal [seed("10.0.0.5", 7500)], Beacon.seeds_of(group)
  end

  # JS-N-05 (srad/agentspaces-js.md): the client dials tcp alone by default and
  # skips every other scheme a beacon document may list, in priority order,
  # so a mixed fleet still reaches it.
  def test_the_client_skips_the_schemes_it_cannot_dial
    group = { "seeds" => [
      { "transport" => "wss", "address" => "fleet.example.com:443/aspace", "priority" => 0 },
      { "transport" => "webrtc", "address" => "sig", "priority" => 1 },
      { "transport" => "https", "address" => "fleet.example.com:443/aspace/h", "priority" => 2 },
      { "transport" => "dtls", "address" => "10.0.0.5:7502", "priority" => 3 },
      { "transport" => "ws", "address" => "10.0.0.5:7503", "priority" => 4 },
      { "transport" => "http", "address" => "10.0.0.5:7503/aspace/h", "priority" => 5 },
      { "transport" => "tcp", "address" => "10.0.0.5:7500", "priority" => 6 }
    ] }
    assert_equal [seed("10.0.0.5", 7500)], Beacon.seeds_of(group)
    assert_equal ["tcp"], Beacon::CLIENT_TRANSPORTS
  end

  def test_seed_addresses_and_priorities_read_as_python_reads_them
    assert_equal ["::1", 7500], Beacon.seed_address("[::1]:7500")
    assert_equal ["host", 1], Beacon.seed_address(" host:1 ")
    assert_raises(Beacon::Error) { Beacon.seed_address("host") }
    assert_raises(Beacon::Error) { Beacon.seed_address("host:x") }
    # Equal priorities keep the document's order; a missing transport is tcp.
    group = { "seeds" => [{ "address" => "a:1", "priority" => 1 }, { "transport" => "TCP", "address" => "b:2" },
                          { "transport" => "tcp", "address" => "c:3", "priority" => 1 }, "junk",
                          { "transport" => "tcp", "address" => "bad" }] }
    assert_equal [seed("b", 2), seed("a", 1), seed("c", 3)], Beacon.seeds_of(group)
  end

  # The canonical encoder against the bytes Jackson writes (HLC round seven,
  # 2026-11-08): the text writer of BeaconDocument.toBytes keeps a code point
  # past U+FFFF as it is, the byte writer of canonicalBytes escapes each of its
  # surrogates, and a literal backslash before "u00ab" keeps its case.
  def test_the_json_encoder_matches_jackson
    {
      "plain" => ['"plain"', '"plain"'], "tab\tnl\ncr\rbs\bff\f" => ['"tab\\tnl\\ncr\\rbs\\bff\\f"'] * 2,
      "\u0000\u001f\u007f" => ["\"\\u0000\\u001F\u007f\""] * 2, "quote\"back\\" => ['"quote\\"back\\\\"'] * 2,
      "slash/ ü\u{1f600}" => ["\"slash/ ü\u{1f600}\"", '"slash/ ü\\uD83D\\uDE00"'],
      "\\u00ab" => ['"\\\\u00ab"'] * 2
    }.each do |text, (served, signed)|
      assert_equal served.b, Beacon.send(:jackson_json, text, false), text.inspect
      assert_equal signed.b, Beacon.send(:jackson_json, text, true), text.inspect
    end
    assert_equal '[1,null,{"k":[]}]'.b, Beacon.send(:jackson_json, [1, nil, { "k" => [] }], true)
  end

  # One 302 to a fixed location.
  class RedirectServer
    attr_reader :url

    def initialize(location)
      @server = TCPServer.new("127.0.0.1", 0)
      @url = "http://127.0.0.1:#{@server.addr[1]}/hop"
      @thread = Thread.new do
        loop do
          client = @server.accept
          nil while (line = client.gets) && line != "\r\n"
          client.write("HTTP/1.1 302 Found\r\nLocation: #{location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
          client.close
        end
      rescue IOError, SystemCallError
        nil
      end
      @thread.report_on_exception = false
    end

    def close
      @server.close unless @server.closed?
      @thread.join(1)
    end
  end
end
