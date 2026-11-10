# How to use AI with AgentSpaces

Written for: Ruby developers who build with agentspaces-rb.

At the end of this section you will have run three fleets inside one Ruby process, over in-memory peers, with no Java, no network, and no model key:

- an agent on one peer that completes work a second peer writes;
- a worker that dies in the middle of a take, whose task reappears once its lease lapses and is finished by another worker;
- two agents that decide a vote.

Each snippet is the body of one test in `gems/agentspaces/test/readme_examples_test.rb`, verbatim. Run them with `ruby -Igems/agentspaces/lib -Igems/agentspaces/test gems/agentspaces/test/readme_examples_test.rb`.

## 1. Build an agent and hand it work from another peer

An entry names its wire schema, and an agent class carries one macro per verb above the method it binds. Entries and agents are plain Ruby; the binder runs the loops.

```ruby
Ticket = AgentSpaces::Entry.define("readme.Ticket#v1", ticket_id: String, text: String, priority: Integer)
Triage = AgentSpaces::Entry.define("readme.Triage#v1", ticket_id: String, queue: String, by: String)

class Triager
  include AgentSpaces::Agent
  agent "triager", description: "Routes support tickets to a queue", goals: ["triage"]

  take Ticket, space: "tickets", lease: "30s", where: { priority: 1.. }, produces: Triage
  def route(ticket)
    queue = ticket.text.match?(/refund|charge/i) ? "billing" : "support"
    Triage.new(ticket_id: ticket.ticket_id, queue: queue, by: "triager")
  end
end
```

```ruby
worker, desk = AgentSpaces::Testing::Network.fleet("zReadme", 2)
bound = worker.bind(Triager.new, agent: worker.identity.renewing_subordinate("triager", "PT24H"))

desk.space("tickets") << Ticket.new(ticket_id: "t-1", text: "Refund my last charge", priority: 2)
triage = desk.space("tickets").read(Triage, timeout: "10s")
# => #<data Triage ticket_id="t-1", queue="billing", by="triager">
```

The agent signs as its own subordinate key (`renewing_subordinate`), so every peer stores its work as `AGENT_ATTESTED`. The method body is where a model call goes: whatever it returns is the next entry.

## 2. A crashed worker's take reappears

```ruby
clock = AgentSpaces::Testing::TestClock.new
crasher, survivor, desk = AgentSpaces::Testing::Network.fleet("zReadmeCrash", 3, clock: clock)
desk.space("tickets") << Ticket.new(ticket_id: "t-2", text: "Password reset", priority: 1)

# The first worker takes the ticket and dies before it completes the take.
taken = crasher.space("tickets").take(Ticket, lease: "5s", timeout: "5s")
crasher.close

# Nobody else can take it while the lease holds; once it lapses, the entry reappears.
assert_nil survivor.space("tickets").take(Ticket, lease: "5s", timeout: 1)
clock.advance(6_000)
retaken = survivor.space("tickets").take(Ticket, lease: "30s", timeout: "5s")
retaken.complete(Triage.new(ticket_id: retaken.value.ticket_id, queue: "support", by: "survivor"))
```

## 3. Two agents decide a vote

```ruby
class Reviewer
  include AgentSpaces::Agent
  agent "reviewer", description: "Votes on releases"

  def initialize(answer) = @answer = answer

  ballot space: "votes", prefix: "release:"
  def judge(proposal) = proposal.question.include?("0.5.0") ? @answer : nil
end
```

```ruby
a, b, chair = AgentSpaces::Testing::Network.fleet("zReadmeVote", 3)
bound = [a.bind(Reviewer.new("ship")), b.bind(Reviewer.new("ship"))]
AgentSpaces::Votes.propose(chair, "votes", "release:0.5.0", "Ship 0.5.0?", %w[ship hold], 2)

decision = until_true { AgentSpaces::Votes.decision(chair.states, "release:0.5.0") }
# => {"proposalId" => "release:0.5.0", "winner" => "ship", "tally" => {"ship" => 2, "hold" => 0}}
```
