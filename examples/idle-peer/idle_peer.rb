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

# A dial-only Ruby peer that joins a group through one seed and stays idle,
# for the mixed idle liveness check (DRIFT-FROM-PHASE6 item 2; the spirit
# of EL-P-02 and EL-P-03: tools/conformance/mixed/idle.mjs starts one beside
# its TypeScript members). It speaks the line protocol of the Java
# IdleMember on stdin and stdout:
#
#   ruby examples/idle-peer/idle_peer.rb <founding> <port[,port...]> [host]
#
# Several ports are several seeds on the host, dialled in list order 250 ms
# apart (connect_any); a lost seed fails over to the next.
#
#   READY <peerId>                    once dialled
#   view  -> VIEW <peerId>=<m1,m2,...>   its view: a live card, or heard from lately
#   via   -> VIA <relay.via or ->         the member this peer names as its relay
#   loop  -> LOOP <peerId>=health:<ok|degraded|down>;resumes:<n>;links_silent:<n>;seed_pings:<n>;seed_dials:<n>;reconnects:<n>
#   quit  -> BYE                          closes the peer and exits
#
# The peer names the seed it dialled in relay.via (from the seed's first
# addressed frame, or the transport's attestation), so 0.7.0 Java members
# probe it through that seed.

$LOAD_PATH.unshift(File.expand_path("../../gems/agentspaces/lib", __dir__))
require "agentspaces"
$stdout.sync = true

founding, port, host = ARGV
abort "usage: ruby idle_peer.rb <founding> <port[,port...]> [host]" if founding.nil? || port.nil?

identity = AgentSpaces::Identity.generate
peer = AgentSpaces::Peer.new(identity, AgentSpaces::Derive.group_id_from_founding(founding))
ports = port.split(",")
if ports.size == 1
  peer.connect(host || "127.0.0.1", Integer(port))
else
  peer.connect_any(ports.map { |p| "#{host || '127.0.0.1'}:#{Integer(p)}" })
end
me = identity.peer_id
# The background writes of the live run: `write <n>` writes a mixed.Note#v1 {from: ruby, n} into notes (1 min lease),
# `notes` answers, per writer, the highest n held there.
NOTES = "notes"
NOTE_TYPE = "mixed.Note#v1"
peer.pull_space(NOTES)
puts "READY #{me}"

$stdin.each_line do |line|
  case line.strip
  when "view"
    puts "VIEW #{me}=#{peer.view_members.sort.join(',')}"
  when "via"
    puts "VIA #{peer.resource_hints['relay.via'] || '-'}"
  when "loop"
    stats = peer.loop_stats
    health = peer.loop_health
    state = health.is_a?(Hash) ? health[:state] : health
    puts "LOOP #{me}=health:#{state};resumes:#{stats[:resumes]};links_silent:#{stats[:links_silent]};" \
         "seed_pings:#{stats[:seed_pings]};seed_dials:#{stats[:seed_dials]};reconnects:#{peer.reconnects}"
  when /\Awrite (\d+)\z/
    n = Integer(Regexp.last_match(1))
    peer.write_entry(NOTES, NOTE_TYPE, { "from" => "ruby", "n" => n }, lease_millis: 60_000)
    puts "WROTE #{n}"
  when "notes"
    highest = Hash.new(-1)
    peer.find(NOTE_TYPE).each do |note|
      next unless note.is_a?(Hash) && note.key?("from")

      highest[note["from"]] = [highest[note["from"]], Integer(note["n"])].max
    end
    puts "NOTES #{highest.sort.map { |k, v| "#{k}:#{v}" }.join(' ')}"
  when "quit"
    peer.close
    puts "BYE"
    break
  when ""
    next
  else
    puts "ERROR unknown command #{line.strip}"
  end
end
peer.close unless peer.closed?
