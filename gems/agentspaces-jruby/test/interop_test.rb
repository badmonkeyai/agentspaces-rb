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

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__), File.expand_path("../../agentspaces/lib", __dir__))
require "minitest/autorun"
require "open3"
require "rbconfig"
require "socket"
require "tmpdir"
require "agentspaces/jruby"

module JDesk
  Payment = AgentSpaces::Entry.define("rbjr.desk.Payment#v1", payment_id: String, amount: Integer)
  Confirmation = AgentSpaces::Entry.define("rbjr.desk.Confirmation#v1", payment_id: String, clerk: String)
end

# JRuby interop: the exactly-once desk of example 12 with Ruby clerks. Three
# JRuby-face nodes form one ordered log over the payments space and bind an
# ordered_take clerk each on the Java binder; a pure-Ruby wire peer in this
# process and a pure-Ruby peer on MRI in a child process write payments into
# the same fleet over tcp. Every payment is confirmed exactly once, whichever
# clerk the log's commit order picks, and both pure-Ruby peers read every
# confirmation back.
class InteropTest < Minitest::Test
  FOUNDING = "rbjr-desk-v1"

  class Clerk
    include AgentSpaces::Agent
    agent "jr-clerk", description: "Confirms payments exactly once", goals: ["confirm"]

    def initialize(name, filed)
      @name = name
      @filed = filed
    end

    ordered_take JDesk::Payment, space: "payments", produces: JDesk::Confirmation
    def confirm(payment)
      @filed << [payment.payment_id, @name]
      JDesk::Confirmation.new(payment_id: payment.payment_id, clerk: @name)
    end
  end

  MRI_WRITER = <<~RUBY
    require "agentspaces"
    Payment = AgentSpaces::Entry.define("rbjr.desk.Payment#v1", payment_id: String, amount: Integer)
    Confirmation = AgentSpaces::Entry.define("rbjr.desk.Confirmation#v1", payment_id: String, clerk: String)
    ids = %w[mri-1 mri-2 mri-3]
    AgentSpaces.start(group: "desk", founding: "#{FOUNDING}", seeds: [ARGV[0]]) do |peer|
      payments = peer.space("payments")
      ids.each_with_index { |id, i| payments << Payment.new(payment_id: id, amount: 10 * (i + 1)) }
      deadline = Time.now + 60
      seen = []
      until (seen = payments.all(Confirmation).map(&:payment_id) & ids).size == ids.size || Time.now > deadline
        sleep 0.2
      end
      puts "engine=\#{RUBY_ENGINE} confirmed=\#{seen.sort.join(',')}"
      peer.close
      exit(seen.size == ids.size ? 0 : 1)
    end
  RUBY

  def free_port
    server = TCPServer.new("127.0.0.1", 0)
    server.addr[1]
  ensure
    server&.close
  end

  def fleet(port, seeds)
    AgentSpaces::JRuby::Fleet.start(
      "security" => { "profile" => "dev-local" }, "bind" => "127.0.0.1:#{port}", "tick-millis" => 100,
      "groups" => [{ "name" => "desk", "founding" => FOUNDING, "seeds" => seeds, "spaces" => ["payments"] }]
    )
  end

  def eventually(timeout = 30)
    deadline = Time.now + timeout
    sleep 0.2 until (value = yield) || Time.now > deadline
    value || yield
  end

  # The MRI binary, when one is installed beside this JRuby.
  def mri
    candidates = [ENV.fetch("RUBY", nil), "/opt/homebrew/opt/ruby/bin/ruby", "/usr/local/opt/ruby/bin/ruby"]
    candidates.compact.find do |path|
      File.executable?(path) && `#{path} -e 'print RUBY_ENGINE, " ", RUBY_VERSION >= "3.3"' 2>/dev/null` == "ruby true"
    end
  end

  def test_ruby_clerks_on_one_ordered_log_confirm_every_payment_once_for_jruby_and_mri_writers
    first = free_port
    nodes = [fleet(first, [])] + Array.new(2) { fleet(free_port, ["127.0.0.1:#{first}"]) }
    members = nodes.map(&:peer_id)
    filed = Queue.new
    nodes.each_with_index do |node, i|
      node.ordered("payments", members: members, seed: 1000 + i)
      node.bind(Clerk.new("clerk-#{i + 1}", filed))
    end

    writer = AgentSpaces::Peer.new(AgentSpaces::Identity.generate, AgentSpaces::Derive.group_id_from_founding(FOUNDING))
    writer.connect("127.0.0.1:#{first}")
    writer.pull_space("payments")
    payments = writer.space("payments")
    jruby_ids = %w[jr-1 jr-2 jr-3 jr-4]
    jruby_ids.each_with_index { |id, i| payments.write(JDesk::Payment.new(payment_id: id, amount: i + 1)) }

    ids = jruby_ids.dup
    ruby = mri
    if ruby
      Dir.mktmpdir do |dir|
        script = File.join(dir, "mri_writer.rb")
        File.write(script, MRI_WRITER)
        lib = File.expand_path("../../agentspaces/lib", __dir__)
        out, status = Open3.capture2e({ "RUBYLIB" => lib }, ruby, script, "127.0.0.1:#{first}")
        assert status.success?, "the MRI writer: #{out}"
        assert_match(/engine=ruby confirmed=mri-1,mri-2,mri-3/, out)
      end
      ids += %w[mri-1 mri-2 mri-3]
    end

    confirmed = eventually { (c = payments.all(JDesk::Confirmation)).size >= ids.size && c }
    assert_equal ids.sort, confirmed.map(&:payment_id).sort, "one confirmation per payment"
    sleep 1 # time for a duplicate to show if the log let one through
    runs = []
    runs << filed.pop until filed.empty?
    assert_equal ids.sort, runs.map(&:first).sort, "each payment ran on exactly one clerk"
    assert_empty payments.all(JDesk::Payment), "every payment was taken"
    skip "no MRI 3.3+ beside this JRuby; the in-process writer alone ran" unless ruby
  ensure
    writer&.close
    nodes&.each(&:close)
  end
end
