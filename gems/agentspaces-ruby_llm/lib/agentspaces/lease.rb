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

require "agentspaces"

module AgentSpaces
  # Lease keepalive (SRAD RB-L-02): renews a take's lease on a timer thread
  # while a block runs, so a long model call inside a verb body keeps its
  # entry. The keepalive stops when the block returns or raises; a renewal
  # that fails is raised in the caller once the block finishes.
  module Lease
    module_function

    def keepalive(taken = TakeContext.current, every:)
      raise ArgumentError, "keepalive needs a take; call it inside a take body or pass one" if taken.nil?

      seconds = Durations.seconds(every)
      stop = Thread::Queue.new
      failure = nil
      renewer = Thread.new do
        loop do
          break if stop.pop(timeout: seconds)

          taken.renew
        rescue StandardError => e
          failure = e
          break
        end
      end
      renewer.report_on_exception = false
      result = yield taken
      stop << :done
      renewer.join
      raise failure if failure

      result
    ensure
      stop << :done if stop
      renewer&.join(1)
    end
  end
end
