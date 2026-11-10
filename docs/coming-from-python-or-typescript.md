# Coming from Python or TypeScript

Written for: Ruby developers who build with agentspaces-rb.

| Python | TypeScript | Ruby |
|---|---|---|
| `@entry("shop.Order#v1")` on a dataclass | an entry class | `Order = AgentSpaces::Entry.define("shop.Order#v1", order_id: String, ...)` |
| `@agent("fulfiller")` | `@agent` | `include AgentSpaces::Agent` and `agent "fulfiller"` |
| `@space_take("orders", lease="30s")` | `@spaceTake` | `take Order, space: "orders", lease: "30s"` above the `def` |
| `@space_notify`, `@bid_function`, `@ballot`, `@on_decision`, `@propose`, `@space_join` | the same | `notify`, `bid`, `ballot`, `on_decision`, `propose`, `join` |
| `Template(Task, where={"priority": gte(3)})` | `Template` | `where: { priority: 3.. }` (a Range), `Matchers.gte(3)`, or `"priority>=3"` |
| `Space(peer, "orders")` | `new Space(peer, "orders")` | `peer.space("orders")` |
| `space.take(t)` then `taken.complete(r)` | the same | the same, or `space.take(Order) { \|o\| result }` |
| `duration_millis(30)` is **30 ms** | milliseconds | **numbers are seconds**: `lease: 30` is 30 s; strings (`"250ms"`, `"10m"`, `"PT10M"`) as Java reads them |
