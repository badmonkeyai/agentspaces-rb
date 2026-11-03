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

unless RUBY_ENGINE == "jruby"
  raise LoadError, "agentspaces-jruby runs on JRuby; on MRI the wire peer (AgentSpaces.start) is the Ruby face"
end

require "java"
require "jruby"
require "fileutils"
require "tmpdir"
require "agentspaces"
require "agentspaces/jruby/java_source"

module AgentSpaces
  # The JRuby face (SRAD 3.6): the agent DSL bound through the Java binder,
  # over the published AgentSpaces artifacts. The same classes that bind on
  # the wire peer bind here, and the verbs only the Java binder runs today
  # (ordered_take, reduce, the leased and ordered join modes) bind too.
  module JRuby
    JARS = File.expand_path("../../jars", __dir__)

    class << self
      # The jar paths: AGENTSPACES_CLASSPATH (path-separated) or the vendored
      # jars/ directory that `rake jruby:jars` fills.
      def jars
        from_env = ENV["AGENTSPACES_CLASSPATH"].to_s.split(File::PATH_SEPARATOR).reject(&:empty?)
        list = from_env.empty? ? Dir[File.join(JARS, "*.jar")].sort : from_env
        if list.empty?
          raise LoadError, "agentspaces-jruby found no jars: run `rake jruby:jars` at the repository root, or set " \
                           "AGENTSPACES_CLASSPATH to the agentspaces-runtime classpath"
        end
        list
      end

      # Jars load by require; a class directory (a build's target/classes)
      # joins the class path as a directory URL.
      def load_jars!
        @load_jars ||= begin
          jars.each { |entry| File.directory?(entry) ? $CLASSPATH << "#{File.expand_path(entry)}/" : require(entry) }
          true
        end
      end

      def loader = ::JRuby.runtime.getJRubyClassLoader

      # A Ruby Hash to java.util collections, recursively.
      def to_java_tree(value)
        case value
        when Hash
          map = java.util.LinkedHashMap.new
          value.each { |k, v| map.put(k.to_s, to_java_tree(v)) }
          map
        when Array
          list = java.util.ArrayList.new
          value.each { |v| list.add(to_java_tree(v)) }
          list
        else value
        end
      end
    end

    # Compiles generated Java source with the JDK's compiler into a fresh
    # directory and loads it in a child of JRuby's class loader. Needs a JDK
    # (javax.tools); a JRE alone binds annotated Java classes only.
    class Compiler
      def initialize
        @directory = Dir.mktmpdir("agentspaces-jruby")
        @loaders = []
        @lock = Mutex.new
      end

      def compile(sources)
        @lock.synchronize do
          out = File.join(@directory, "c#{@loaders.size}")
          src = File.join(out, "src")
          FileUtils.mkdir_p(src)
          files = sources.map do |name, text|
            path = File.join(src, *name.split("."))
            path = "#{path}.java"
            FileUtils.mkdir_p(File.dirname(path))
            File.write(path, text)
            path
          end
          compiler = javax.tools.ToolProvider.getSystemJavaCompiler
          raise EngineUnsupported, "no Java compiler (javax.tools) in this JVM; run on a JDK" if compiler.nil?

          classpath = (JRuby.jars + @loaders.map(&:first)).join(File::PATH_SEPARATOR)
          errors = java.io.ByteArrayOutputStream.new
          status = compiler.run(nil, nil, errors, "-d", out, "-classpath", classpath, "-proc:none", "-nowarn", *files)
          raise EngineUnsupported, "generated Java did not compile:\n#{errors}" unless status.zero?

          parent = @loaders.empty? ? JRuby.loader : @loaders.last.last
          loader = java.net.URLClassLoader.new([java.io.File.new(out).toURI.toURL].to_java(java.net.URL), parent)
          @loaders << [out, loader]
          loader
        end
      end

      def latest_loader = @loaders.empty? ? JRuby.loader : @loaders.last.last

      def close = FileUtils.rm_rf(@directory)
    end

    # Entry classes and their Java record classes: an existing class on the
    # classpath under the schema's binary name, a class named with
    # AgentSpaces::JRuby.java_class, or a record generated from the fields.
    class Records
      def initialize(compiler)
        @compiler = compiler
        @java = {}
        @names = {}
        @explicit = {}
      end

      def explicit(entry, java_class_name) = @explicit[entry] = java_class_name

      # Java source names for the entries, generating records where needed.
      def ensure(entries)
        all = expand(entries)
        missing = all.reject { |e| @names.key?(e) }
        generate = []
        missing.each do |entry|
          name = @explicit[entry] || JavaSource.class_name(entry.schema)
          existing = find_class(name)
          if existing
            @java[entry] = existing
            @names[entry] = existing.getCanonicalName
          elsif name.include?("$")
            raise EngineUnsupported, "#{entry.schema} names the nested class #{name}, which is not on the " \
                                     "classpath; add its jar to AGENTSPACES_CLASSPATH"
          else
            @names[entry] = name
            generate << entry
          end
        end
        unless generate.empty?
          sources = generate.to_h { |e| [@names[e], JavaSource.record(e, @names)] }
          loader = @compiler.compile(sources)
          generate.each { |e| @java[e] = loader.loadClass(@names[e]) }
        end
        @names
      end

      def java_class(entry) = @java.fetch(entry)

      def names = @names

      # A Java record to the Ruby entry.
      def to_ruby(entry, record)
        return nil if record.nil?

        entry.from_payload(plain(record))
      end

      # A Ruby entry to the Java record, through its canonical constructor.
      def to_java(entry, value)
        return nil if value.nil?

        klass = java_class(entry)
        components = klass.getRecordComponents
        raise EngineUnsupported, "#{klass.getName} is not a record" if components.nil?

        payload = value.to_payload
        args = components.map do |component|
          field = entry.fields.find { |f| f.wire == component.getName }
          raw = field.nil? ? nil : value.public_send(field.name)
          raw = payload[component.getName] if field.nil?
          java_value(component.getType, component.getGenericType, raw, field&.type)
        end
        klass.getDeclaredConstructor(*components.map(&:getType)).newInstance(*args)
      end

      private

      def expand(entries)
        seen = []
        queue = entries.dup
        until queue.empty?
          entry = queue.shift
          next if seen.include?(entry)

          seen << entry
          entry.fields.each do |f|
            type = f.type.is_a?(Array) ? f.type.first : f.type
            queue << type if Entry.entry_class?(type)
          end
        end
        seen.reverse
      end

      def find_class(name)
        java.lang.Class.forName(name, true, @compiler.latest_loader)
      rescue java.lang.ClassNotFoundException, NameError
        nil
      end

      def plain(value)
        if value.is_a?(java.lang.Record)
          value.getClass.getRecordComponents.to_h { |c| [c.getName, plain(c.getAccessor.invoke(value))] }
        elsif value.is_a?(java.util.List) then value.to_a.map { |v| plain(v) }
        elsif value.is_a?(java.util.Map) then value.to_h { |k, v| [k.to_s, plain(v)] }
        elsif value.is_a?(Java::byte[]) then String.from_java_bytes(value).b
        else value
        end
      end

      def java_value(type, generic, raw, ruby_type)
        return nil if raw.nil? && !type.isPrimitive
        return raw.to_java(:long) if type == java.lang.Long::TYPE || type == java.lang.Long.java_class
        return raw.to_java(:int) if type == java.lang.Integer::TYPE || type == java.lang.Integer.java_class
        return Float(raw).to_java(:double) if type == java.lang.Double::TYPE || type == java.lang.Double.java_class
        return raw.to_java(:float) if type == java.lang.Float::TYPE
        return raw ? true : false if type == java.lang.Boolean::TYPE
        return raw.to_java_bytes if type.isArray && type.getComponentType == java.lang.Byte::TYPE

        if type.isRecord
          entry = @java.key(type)
          return to_java(entry, raw) if entry
        end
        if java.util.List.java_class.isAssignableFrom(type)
          element = generic.respond_to?(:getActualTypeArguments) ? generic.getActualTypeArguments.first : nil
          list = java.util.ArrayList.new
          Array(raw).each do |v|
            element_class = element.is_a?(java.lang.Class) ? element : java.lang.Object.java_class
            list.add(java_value(element_class, element, v, ruby_type.is_a?(Array) ? ruby_type.first : nil))
          end
          return list
        end
        return JRuby.to_java_tree(raw.to_h { |k, v| [k.to_s, v] }) if java.util.Map.java_class.isAssignableFrom(type)

        raw.respond_to?(:to_payload) ? to_java(raw.class, raw) : raw
      end
    end
  end
end

require "agentspaces/jruby/engine"
