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
  # The text digest of a replicated space (TECH-SPEC 7.5 and 10.3): one line
  # `e:<entryId>=<stateHash>` per held state and `c:<entryId>=<claimHash>`
  # per held claim, in Java's TreeMap order, then an `a:<line>` for each line
  # the replica refused at its door. The state hash is Java's
  # `Integer.toHexString(Objects.hash(adds, removes, lease.stamp, completed))`
  # and the claim hash `epoch:stamp:bid:expiresAtMillis` with the bid as
  # `Double.toString` prints it, so a partner reading the digest finds a
  # line equal to its own for every state both hold alike and sends only the
  # rest. The golden vectors space_state_hash, space_claim_hash and
  # java_double_strings pin the arithmetic.
  #
  # A Ruby peer sends this digest only to continue a budgeted get-space whose
  # answer left states out (SPEC annex I.6, The budget; srad/replication-by-entry.md
  # RE-L-03): sending the empty digest again would draw the same newest states again.
  # It also reads its seed's digest of this form to answer it (peer_answer.rb).
  module TextDigest
    INT_RANGE = 1 << 32
    private_constant :INT_RANGE

    module_function

    # A value wrapped to a Java int, as Java's int arithmetic wraps it.
    def int32(value)
      v = value % INT_RANGE
      v >= (1 << 31) ? v - INT_RANGE : v
    end

    # String.hashCode: UTF-16 code units, 31-chained, wrapped to an int.
    def string_hash(text)
      text.to_s.encode(Encoding::UTF_16BE).unpack("n*").reduce(0) { |h, unit| int32((31 * h) + unit) }
    end

    # Long.hashCode: (int) (v ^ (v >>> 32)) over the long's two's complement.
    def long_hash(value)
      v = Integer(value) % (1 << 64)
      int32((v ^ (v >> 32)) & 0xFFFF_FFFF)
    end

    # A record's hash as java.lang.runtime.ObjectMethods derives it: 31-chained from 0.
    def record_hash(components) = components.reduce(0) { |h, c| int32((31 * h) + c) }

    # Objects.hash (Arrays.hashCode): 31-chained from 1.
    def objects_hash(components) = components.reduce(1) { |h, c| int32((31 * h) + c) }

    # A Set<Dot>'s hash: the sum of its members' Dot(replica, counter) hashes, each member once.
    def dot_set_hash(dots)
      seen = {}
      Array(dots).each do |dot|
        next unless dot.is_a?(Hash)

        seen[[dot["replica"].to_s, Integer(dot["counter"] || 0)]] = true
      end
      seen.keys.reduce(0) { |h, (replica, counter)| int32(h + record_hash([string_hash(replica), long_hash(counter)])) }
    end

    # An HlcTimestamp(physical, logical, node) record's hash, from its text form.
    def stamp_hash(stamp)
      physical, logical, node = stamp.to_s.split(":", 3)
      physical = physical.to_s.match?(/\A\d+\z/) ? Integer(physical, 10) : 0
      record_hash([long_hash(physical), int32(logical.to_i), string_hash(node.to_s)])
    end

    # Integer.toHexString: two's complement, lower case, no padding.
    def java_hex(value) = (value % INT_RANGE).to_s(16)

    # ReplicatedSpace.stateHash over the state a peer holds (its wire DTO).
    def state_hash(dto)
      java_hex(objects_hash([dot_set_hash(dto["adds"]), dot_set_hash(dto["removes"]),
                             stamp_hash(dto["leaseStamp"] || "0:0:"), dto["completed"] ? 1231 : 1237]))
    end

    # ReplicatedSpace.claimHash: epoch:stamp:bid:expiresAtMillis.
    def claim_hash(claim)
      "#{Integer(claim['epoch'])}:#{claim['stamp']}:#{java_double(Float(claim['bid'] || 0.0))}:" \
        "#{Integer(claim['expiresAtMillis'])}"
    end

    # The state line of one held state.
    def state_line(entry_id, dto) = "e:#{entry_id}=#{state_hash(dto)}"

    # Double.toString: the shortest digits that read back to the value, always
    # with a fraction digit, in computerized scientific notation (1.0E7,
    # 1.5E-5) outside [1e-3, 1e7). Ruby's Float#to_s gives the same shortest
    # digits, so only the layout differs.
    def java_double(value)
      return "NaN" if value.nan?
      return value.positive? ? "Infinity" : "-Infinity" if value.infinite?
      return (1.0 / value).negative? ? "-0.0" : "0.0" if value.zero?

      sign = value.negative? ? "-" : ""
      magnitude = value.abs
      # Java prints the smallest subnormal with two digits.
      return "#{sign}4.9E-324" if magnitude == Float::MIN * Float::EPSILON
      # Ruby prints this range plainly, as Java does, with the same digits.
      return "#{sign}#{magnitude}" if magnitude >= 1e-3 && magnitude < 1e7

      digits, exponent = shortest_digits(magnitude)
      mantissa = digits.size == 1 ? "#{digits}.0" : "#{digits[0]}.#{digits[1..]}"
      "#{sign}#{mantissa}E#{exponent}"
    end

    # The significant digits of Float#to_s for a positive finite value, with
    # no leading or trailing zeros, and the decimal exponent of the first.
    def shortest_digits(magnitude)
      text = magnitude.to_s
      mantissa, exp = text.split("e")
      whole, fraction = mantissa.split(".")
      digits = whole + fraction.to_s
      exponent = exp.to_i + whole.size - 1
      stripped = digits.sub(/\A0+/, "")
      exponent -= digits.size - stripped.size
      stripped = stripped.sub(/0+\z/, "")
      [stripped.empty? ? "0" : stripped, exponent]
    end
    private_class_method :shortest_digits

    # The digest bytes from a map of keys (e:<id>, c:<id>) to hashes, in
    # Java's TreeMap order (UTF-16 code units), each line ending in LF, then
    # the acknowledged lines as a:<line>.
    def digest(summary, acknowledged = [])
      keys = summary.keys.sort_by { |key| key.encode(Encoding::UTF_16BE).b }
      out = +""
      keys.each { |key| out << key << "=" << summary[key] << "\n" }
      acknowledged.each { |line| out << "a:" << line << "\n" }
      out.b
    end
  end
end
