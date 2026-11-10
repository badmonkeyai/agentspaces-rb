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
    # The DataScript database reader (PDT 2 phase 7, P2-C-02; srad/agentspaces-pdt2.md
    # 3.1.5 and P2-D-09): a lazy reader over the db root and dn nodes of 3.1.1 that
    # answers datoms, entity, and lookup as DataScript answers them, without Datalog,
    # as the Python and TypeScript readers do.
    #
    # DbReader.new(root, loader) reads the root node and nothing else. A read walks
    # one index from its root, loading only the nodes whose key range meets the
    # components, and applies the tail (the datoms of the transactions not yet
    # folded) over the index: a retraction removes the datom it names, and an
    # assertion adds one. The loader is any object with load(cid) -> bytes;
    # Pdt#loader reads the node store and fetches what it lacks.
    #
    # The comparators are DataScript's: eavt, aevt, and avet order datoms by their
    # components in the index's order, the attribute as a Clojure keyword (a keyword
    # without a namespace first, then the namespace, then the name), and the value by
    # value-compare: numbers by value across long, double, and big integer, values of
    # two classes by the class name, text by UTF-16 code unit, a UUID by its two
    # signed halves, and an instant by its milliseconds. A text of a colon and a name
    # is a keyword's print form; a text that starts with a backslash is the string
    # after it, the escape the Clojure face writes. DataScript orders two byte arrays
    # by identity hash, so a byte array component reads by equality and never seeks.
    #
    # value-compare is no total order, so the reader checks neighbours only: each
    # leaf holds its datoms in its index's order, and each node lies between the
    # branch key before its own and its own branch key. It refuses anything else by
    # name.
    class DbReader
      COMPONENTS = { DnNode::EAVT => %i[e a v], DnNode::AEVT => %i[a e v], DnNode::AVET => %i[a v e] }.freeze
      # DataScript's implicit schema, merged under every database's own.
      IMPLICIT_SCHEMA = { ":db/ident" => { ":db/unique" => ":db.unique/identity" } }.freeze
      # The decoded nodes a reader keeps, the least recently used leaving first.
      CACHE_NODES = 1024
      KEYWORD = "clojure.lang.Keyword"
      STRING = "java.lang.String"
      BYTES = "[B"
      TAGGED_CLASS = { Datom::Tagged::UUID => "java.util.UUID", Datom::Tagged::INSTANT => "java.util.Date",
                       Datom::Tagged::BIGINT => "clojure.lang.BigInt" }.freeze

      attr_reader :root

      # The sign of a <=> b as -1, 0, or 1.
      def self.sign(a, b) = (a <=> b).clamp(-1, 1)

      # Big-endian UTF-16 code units, which compare byte by byte in Java's String order.
      def self.utf16(text) = text.encode(Encoding::UTF_16BE).b

      # A keyword's print form as Clojure's Symbol.compareTo orders it: no namespace
      # first, then the namespace, then the name; Symbol.intern splits at the first
      # slash unless the name is a slash.
      def self.keyword_key(text)
        body = text[1..]
        cut = body.index("/")
        return [0, "".b, utf16(body)] if cut.nil? || body == "/"

        [1, utf16(body[0...cut]), utf16(body[(cut + 1)..])]
      end

      # The integer a big integer's minimal two's complement bytes hold.
      def self.bigint(bytes)
        value = bytes.unpack1("H*").to_i(16)
        bytes.getbyte(0) >= 0x80 ? value - (1 << (8 * bytes.bytesize)) : value
      end

      def self.number(v)
        return v if v.is_a?(Integer) || v.is_a?(Float)
        return bigint(v.inner) if v.is_a?(Datom::Tagged) && v.tag == Datom::Tagged::BIGINT

        nil
      end

      # A keyword's print form: a colon and a name. A lone colon is a string.
      def self.keyword?(text) = text.length > 1 && text.start_with?(":")

      # The string a text value stands for: the Clojure face writes a string that
      # starts with a colon or a backslash with one more backslash in front.
      def self.string(text) = text.start_with?("\\") ? text[1..] : text

      def self.text?(v) = v.is_a?(String) && v.encoding != Encoding::BINARY

      def self.class_name(v)
        case v
        when true, false then "java.lang.Boolean"
        when Integer then "java.lang.Long"
        when Float then "java.lang.Double"
        when Datom::Tagged then TAGGED_CLASS.fetch(v.tag)
        when String then text?(v) ? (keyword?(v) ? KEYWORD : STRING) : BYTES
        else raise ArgumentError, "no datom value: #{v.inspect}"
        end
      end

      # DataScript's value-compare over two datom values as -1, 0, or 1, or nil for
      # two byte arrays of different content, which DataScript orders by identity hash.
      def self.compare_values(x, y)
        nx = number(x)
        ny = number(y)
        unless nx.nil? || ny.nil?
          # Clojure's Numbers.compare widens a long or a big integer to a double beside a double
          return sign(nx.to_f, ny.to_f) if nx.is_a?(Float) || ny.is_a?(Float)

          return sign(nx, ny)
        end
        cx = class_name(x)
        cy = class_name(y)
        return sign(cx, cy) if cx != cy
        return x == y ? 0 : nil if cx == BYTES
        return sign(keyword_key(x), keyword_key(y)) if cx == KEYWORD
        return sign(utf16(string(x)), utf16(string(y))) if cx == STRING

        if x.is_a?(Datom::Tagged)
          return sign(x.inner.unpack("q>q>"), y.inner.unpack("q>q>")) if x.tag == Datom::Tagged::UUID

          return sign(x.inner, y.inner)
        end
        # two booleans: false before true
        sign(x ? 1 : 0, y ? 1 : 0)
      end

      def self.compare_component(field, datom, value)
        case field
        when :a then sign(keyword_key(datom.a), keyword_key(value))
        when :v then compare_values(datom.v, value)
        else sign(datom.public_send(field), value)
        end
      end

      # Where a datom lies against the components: before them (-1), among them (0),
      # after them (1), or nil when a byte array leaves the order unknown.
      def self.compare_prefix(datom, fields, components)
        fields.zip(components).each do |field, value|
          c = compare_component(field, datom, value)
          return c unless c&.zero?
        end
        0
      end

      def self.compare_datoms(index, x, y)
        fields = COMPONENTS.fetch(index)
        c = compare_prefix(x, fields, fields.map { |f| y.public_send(f) })
        c&.zero? ? sign(x.tx.abs, y.tx.abs) : c
      end

      # An order, or unknown in its place when byte arrays leave it unknown.
      def self.known(order, unknown) = order.nil? ? unknown : order

      # The key of a value under DataScript's datom equality: numbers by value, the rest by class and value.
      def self.value_key(v)
        n = number(v)
        return ["number", n.is_a?(Float) && n.finite? && n == n.floor ? n.to_i : n] unless n.nil?

        [class_name(v), v]
      end

      def initialize(root, loader)
        @root = root
        @loader = loader
        @db = DbRoot.decode(loader.load(root), root)
        @nodes = {}
        @index_roots = { DnNode::EAVT => @db.eavt, DnNode::AEVT => @db.aevt, DnNode::AVET => @db.avet }
      end

      def max_eid = @db.max_eid

      # The database's schema under DataScript's implicit one, attribute to properties.
      def schema
        @schema ||= begin
          item = @db.schema.bytes
          item = Values.resolve(Nodes.link_cid(item), @loader) if Nodes.link_shaped?(item)
          own = CBOR.load(item)
          unless own.is_a?(Hash) && own.all? { |a, p| DbReader.text?(a) && p.is_a?(Hash) }
            raise NodeFormatError.new("a db schema maps each attribute to a map of its properties", @root)
          end

          IMPLICIT_SCHEMA.merge(own)
        end
      end

      # The datoms of an index whose leading components equal the components, in
      # index order, as (d/datoms db index c1 c2 c3) returns them.
      def datoms(index, *components)
        raise ArgumentError, "unknown index #{index}; the indexes are eavt, aevt and avet" unless COMPONENTS.key?(index)
        raise ArgumentError, "a read names at most three components" if components.size > 3
        if index == DnNode::AVET && !components.empty? && !indexed.include?(components[0])
          raise ArgumentError, "attribute #{components[0]} should be marked as :db/index true to read avet"
        end

        fields = COMPONENTS[index].first(components.size)
        added = tail.values.compact.select do |d|
          in_index?(index, d) && DbReader.compare_prefix(d, fields, components)&.zero?
        end
        added = added.sort { |x, y| DbReader.known(DbReader.compare_datoms(index, x, y), 0) }
        merge(index, range(index, fields, components), added)
      end

      # The attributes of an entity as (d/touch (d/entity db e)) holds them: one value
      # for a cardinality-one attribute, an array in index order for a cardinality-many one.
      def entity(e)
        out = {}
        datoms(DnNode::EAVT, e).each do |d|
          if many.include?(d.a)
            (out[d.a] ||= []) << d.v
          else
            out[d.a] = d.v
          end
        end
        out
      end

      # The entity of the lookup ref [a v], as (d/entid db [a v]) resolves it, or nil.
      def lookup(a, v)
        raise ArgumentError, "lookup attribute #{a} is not :db/unique" unless unique.include?(a)

        datoms(DnNode::AVET, a, v).first&.e
      end

      private

      def attrs(&test) = schema.select { |_, p| test.call(p) }.keys.to_set

      def unique = @unique ||= attrs { |p| p.key?(":db/unique") }

      def many = @many ||= attrs { |p| p[":db/cardinality"] == ":db.cardinality/many" }

      # DataScript's rschema puts unique, ref, :db/index true, and tuple attributes in avet.
      def indexed
        @indexed ||= attrs do |p|
          p.key?(":db/unique") || p[":db/valueType"] == ":db.type/ref" || p[":db/index"] == true || p.key?(":db/tupleAttrs")
        end
      end

      # The tail applied in transaction order: each datom's key to its last assertion, or nil after a retraction.
      def tail
        @tail ||= begin
          applied = {}
          unless @db.tail.nil?
            node = load_node(@db.tail.cid)
            if node.index != DnNode::TAIL
              raise NodeFormatError.new("the db root's 't' links index #{node.index}, expected the tail", @db.tail.cid)
            end

            node.datoms.each do |d|
              applied[[d.e, d.a, DbReader.value_key(d.v)]] = d.tx.positive? ? d : nil
            end
          end
          applied
        end
      end

      def in_index?(index, datom) = index != DnNode::AVET || indexed.include?(datom.a)

      def merge(index, stored, added)
        Enumerator.new do |out|
          i = 0
          stored.each do |d|
            while i < added.size && DbReader.known(DbReader.compare_datoms(index, added[i], d), 0).negative?
              out << added[i]
              i += 1
            end
            out << d
          end
          added[i..].each { |d| out << d }
        end
      end

      def range(index, fields, components)
        Enumerator.new do |out|
          scan(index, @index_roots[index].cid, nil, nil, nil, fields, components) do |d|
            c = DbReader.compare_prefix(d, fields, components)
            break if !c.nil? && c.positive?
            next if c != 0 && !(c.nil? && matches?(d, fields, components))

            out << d unless tail.key?([d.e, d.a, DbReader.value_key(d.v)])
          end
        end
      end

      def matches?(datom, fields, components)
        fields.zip(components).all? do |field, value|
          field == :v ? DbReader.compare_values(datom.v, value)&.zero? : datom.public_send(field) == value
        end
      end

      def scan(index, cid, level, low, high, fields, components, &block)
        node = load_node(cid)
        check(index, cid, node, level, low, high)
        if node.level.zero?
          node.datoms.each(&block)
          return
        end
        start = 0
        start += 1 while start < node.datoms.size && DbReader.compare_prefix(node.datoms[start], fields, components) == -1
        (start...node.datoms.size).each do |j|
          scan(index, node.children[j].cid, node.level - 1, j.zero? ? low : node.datoms[j - 1], node.datoms[j], fields,
               components, &block)
        end
      end

      # The node's place in its index: its index, its level one below its parent's,
      # and its datoms above the key before its branch key and at most that key.
      def check(index, cid, node, level, low, high)
        raise NodeFormatError.new("expected a node of index #{index}, found index #{node.index}", cid) if node.index != index
        if !level.nil? && node.level != level
          raise NodeFormatError.new("a child of a level #{level + 1} branch sits at level #{node.level}", cid)
        end
        return if node.datoms.empty?

        if (!low.nil? && DbReader.known(DbReader.compare_datoms(index, node.datoms[0], low), 1) <= 0) ||
           (!high.nil? && DbReader.known(DbReader.compare_datoms(index, node.datoms[-1], high), 0).positive?)
          raise NodeFormatError.new("a datom sits outside its branch key's range in #{index}", cid)
        end
      end

      def load_node(cid)
        node = @nodes.delete(cid)
        if node.nil?
          read = DnNode.decode(@loader.load(cid), cid)
          node = DnNode.new(read.level, read.index, read.datoms.map { |d| resolved(cid, d) }, read.children)
          check_leaf(cid, node) unless node.index == DnNode::TAIL
          @nodes.shift if @nodes.size >= CACHE_NODES
        end
        @nodes[cid] = node
      end

      def check_leaf(cid, node)
        if node.datoms.any? { |d| d.tx.negative? }
          raise NodeFormatError.new("an index holds assertions only, found a retraction in #{node.index}", cid)
        end
        return if node.level.positive?

        node.datoms.each_cons(2) do |x, y|
          next if DbReader.known(DbReader.compare_datoms(node.index, x, y), -1).negative?

          raise NodeFormatError.new("datoms out of #{node.index} order", cid)
        end
      end

      # A datom whose spilled value (PD-N-05) reads as the value it names.
      def resolved(cid, datom)
        return datom unless datom.v.is_a?(Nodes::Link)

        Datom.new(datom.e, datom.a, CBOR.load(Values.resolve(datom.v.cid, @loader)), datom.tx)
      rescue ArgumentError => e
        raise if e.is_a?(NodeFormatError)

        raise NodeFormatError.new("a spilled datom value is no datom value: #{e.message}", cid)
      end
    end
  end
end
