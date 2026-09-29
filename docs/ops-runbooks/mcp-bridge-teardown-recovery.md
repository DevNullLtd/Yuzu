# Runbook: MCP progress-bridge teardown incomplete

**Alerts:** `YuzuMcpBridgeTeardownIncomplete` (attempt-level, may self-heal),
`YuzuMcpBridgeTeardownRetryExhausted` (the one that matters - permanent retention),
`YuzuMcpMaintenanceTickFailing`, `YuzuMcpBridgeRecordsNearCap`,
`YuzuMcpProgressBridgeAtCapacity`
**Severity:** warning. **This is not a page.** Nothing is losing data, and the fix is
disruptive, so do it deliberately rather than immediately.

## What has happened

The MCP progress bridge correlates an execution's events onto a client's live SSE
stream. When a correlated request finishes, a background sweep tears its record down.
It publishes any decided terminal result **first**, so a later failure cannot lose it,
then settles the three things it owns in order: the **bus subscription**, the
**streamed admission charge**, and the **records_ map entry**.

Each step is contained separately, so a failure settles some and retains the rest.
**A retained record is retried**, from where it stopped, on a later sweep tick - up to
`Config::teardown_retry_max` retries beyond the first attempt (4 total attempts by
default; #2513). Each retry runs on a fresh tick, never the same one that failed, so a
fault surviving every attempt has had multiple ticks to self-heal. A record that
exhausts its retry budget behaves exactly as it always did before #2513: held until the
process restarts, and evidenced by `yuzu_mcp_bridge_teardown_retry_total{outcome=
"exhausted"}`.

`yuzu_mcp_bridge_teardown_incomplete_total{reason}` names which step failed on a given
attempt - it fires once per failed step **per attempt**, so a record retried three times
moves this counter three times even though it is one strand, not three:

| reason | settled on THIS attempt | retained (until a retry succeeds, or the budget exhausts) |
|---|---|---|
| `unsubscribe` | the terminal disposition **if there was one** - most teardowns (session death, pin-ack, arming reap, done reap) publish nothing at all, and even a memory-pressure teardown delivers nothing if its publish failed. Every failure row carries the terminal's fate as well as the mechanical failure, in one of four forms: the frame **was published**; the intended terminal failed and the **fallback was published instead**; the publish **POISONED the session** (session-wide - every later attach 410s, client must re-initialize); or the frame **could not be built**, nothing published and this teardown did not poison. (A fifth form, "the frame was built but publishing threw, poison state indeterminate", existed before #2531/#2523 made the publish ladder `noexcept` - it is no longer reachable and the enum value that named it was retired.) A retry whose terminal was already resolved by a prior attempt never re-publishes, re-poisons, or re-synthesizes - it replays the same disposition. | the record, its admission charge, and its bus subscription - which also stops that execution's channel and replay buffer being collected |
| `release_charge` | the terminal disposition (whatever the row names) and the subscription - **the record is now RETAINED, not erased** (#2513: erasing on this failure made sense only when nothing could retry; under retry the record is the only handle back to the leaked charge) | the record and one per-session streamed admission slot |
| `erase` | the terminal disposition (whatever the row names), the subscription, AND the charge - reaching this step means both prior steps already settled | the record and one global record slot |

This table is a summary keyed on one reason at a time. The audit row is authoritative
in every case: it names what was actually published, and a retry's own row
(`mcp.bridge.teardown_retry`) says whether it recovered or is still retry-eligible.
Trust the row over the table.

A retained record also pins that session's whole stream state, its replay ring and any
pinned finals, past normal session garbage collection.

**Client results are never lost.** Every execution remains durably fetchable by
`execution_id` via `get_execution_status` / `query_responses`. What degrades is live
progress streaming, not correctness.

## What it is not

This counter is **defence in depth, not the out-of-memory signal**. On current code all
three steps are find/erase and node operations that allocate nothing, so only a mutex
failure can reach them - which in practice does not happen. TEST-BACKED, not just
asserted in a comment (#2519): a dedicated allocation-budget probe
(`tests/unit/server/test_mcp_bridge_alloc_budget.cpp`, Linux-only, non-sanitizer build)
replaces the global allocator and asserts zero allocations across all three steps, over
N teardowns in one sweep. If you are chasing allocation pressure, the counter you want
is `yuzu_mcp_stream_terminal_publish_failures_total`.

If `teardown_incomplete` is moving at all, treat it as a genuine anomaly worth a bug
report, not routine noise.

## Impact assessment

1. **Is it growing, or did it happen once, or did it recover?** `teardown_incomplete`
   moving alone is not yet a strand - a retry may still be in flight. Check
   `yuzu_mcp_bridge_teardown_retry_total{outcome}` next: `recovered` means the strand
   resolved on its own; `exhausted` means it did not and retention is now permanent for
   that record.
2. **How close is the bridge to its cap?** `yuzu_mcp_bridge_records_active` against the
   256-record cap. Below ~80% there is no user-visible impact at all.
3. **Is anything being refused?** `yuzu_mcp_bridge_reject_total{reason="global_cap"}`
   moving means the table is full: every `execute_instruction` carrying a
   `progressToken` is silently falling back to the plain (poll) path. Clients that poll
   are unaffected; clients relying on live progress stop receiving it.
4. **Load or strand?** This is the distinction that matters. Ordinary load recedes on
   its own, and so does a `teardown_incomplete` movement that resolves via retry. Only
   `teardown_retry_total{outcome="exhausted"}` moving means that share of the occupancy
   is now permanent and will not recede without a restart.

## Remediation

**The only remediation for an EXHAUSTED strand is a process restart**, and it is more
disruptive than the condition:

- A restart drops **every** live MCP session and in-flight streamed request, fleet-wide,
  not just the stranded ones. Clients must re-initialize.
- The condition that provokes a teardown failure is resource pressure - which is exactly
  when a restart is riskiest and when the server may struggle to come back cleanly.

So:

- **`teardown_incomplete` moved but `teardown_retry_total{outcome="exhausted"}` did
  not:** do nothing. The record is either still retrying or already recovered - wait for
  the next few sweep ticks (seconds) before treating this as an incident at all.
- **Not near the cap, and exhausted:** do nothing now. Record the occurrence, file a bug
  with the `reason` label and surrounding logs (`MCP bridge teardown incomplete
  [reason=...]` / `MCP bridge teardown retry exhausted [...]`), and fold the restart into
  the next planned maintenance window.
- **Near or at the cap, and exhausted:** schedule a restart. Check host memory headroom
  first. Prefer a rolling restart if more than one replica is serving MCP.
- **Near the cap but nothing exhausted:** this is load, not a strand. Do not restart -
  look for a client holding many warm sessions with never-terminating executions.

## Evidence

Every incomplete teardown attempt emits, in order of reliability:

1. An operator log line: `MCP bridge teardown incomplete [reason=<reason>
   execution_id=<id>]: resource retained (retry-eligible on a later sweep)` on any
   attempt still within `Config::teardown_retry_max`, or `... resource retained
   until shutdown` once the budget is spent. The field is `reason`, matching the
   metric label, so the same value greps both.
2. `yuzu_mcp_bridge_teardown_incomplete_total{reason}` above.
3. An audit row - `mcp.bridge.<claim-verb>` (`done_reap` / `pin_acked` / `session_dead` /
   `arming_reaped` / `forced_expire`) on the FIRST attempt, `mcp.bridge.teardown_retry` on
   every retry attempt - with `result=failure` and a `detail` naming what was retained.

A retry that finally settles the record (mechanically - subscription, charge, and
map entry all resolved) additionally emits, once:

4. `yuzu_mcp_bridge_teardown_retry_total{outcome="recovered"}`, and a
   `mcp.bridge.teardown_retry` row whose `result` follows the terminal's fate, not
   the retention strand's - `success` only if the terminal was delivered or none
   was owed. A retry can recover the retention strand while replaying a terminal a
   PRIOR attempt already poisoned or never built; that row still reads
   `result=failure` (same `"recovered on a retry attempt"` detail) - see
   `docs/user-manual/audit-log.md`'s `mcp.bridge.teardown_retry` row for the full
   rule. Do not read `outcome="recovered"` alone as proof the client got its
   result; check `result` too.

A retry that exhausts `Config::teardown_retry_max` instead emits, once, in place of (4):

4. An operator log line: `MCP bridge teardown retry exhausted [execution_id=<id>
   attempts=<n>]: resource retained until shutdown`.
5. `yuzu_mcp_bridge_teardown_retry_total{outcome="exhausted"}` - **this is the one to
   alert on**; `teardown_incomplete` and `recovered` moving alone are not yet incidents.

The log lines exist because the metrics and the audit rows both route through guards
that swallow failures; under severe pressure all of them can be lost, so the log is the
floor. If you have a metric but no log line, or vice versa, that itself is worth
reporting.

## If the row says the session was poisoned

A poisoned stream is **session-wide**: every later attach on that session returns 410,
not just the affected request. The client must re-initialize the MCP session to stream
again. Poisoning has two distinct triggers, not one: a double publish failure on the
teardown ladder (travels with allocation pressure - see the audit row for which
disposition), or `shutdown()` reclaiming a record whose teardown was still claimed but
unresolved when the process exited (`mcp.bridge.shutdown_reap`, #2517 - unrelated to
memory pressure, and evidenced by its own aggregate audit row rather than a per-record
one). Either way, results remain fetchable by `execution_id` throughout, and no
server-side action other than the usual restart decision applies.

## If `yuzu_mcp_bridge_projection_degraded_total` is non-zero

A different failure from the ones above, reached by the same broken-mutex fault, so the
two alerts often fire together. A projection could not retake the record lock at the end
of its batch and released its projection claim **without** it.

Releasing the claim is deliberate and is the better half of the trade: a claim left set
excludes that record from every consumer until the process restarts. It used to be
worse still: before #2489, a deferred record ended the whole pressure pass, so one
wedged record stalled ring-only pressure relief for every session. The pass now
advances past a defer, so the damage is confined to the wedged record itself. What is
lost instead is that batch's settle bookkeeping:

- a progress-only batch loses **nothing** - the claim release is a complete recovery;
- a batch holding a terminal payload that had not yet been published loses that payload
  permanently (it cannot be put back and nothing re-latches it). The request is then
  answered by the success-shaped fallback final - `status:"unknown"` plus the
  `execution_id` - rather than its real result.

**What to do.** No bridge-specific remediation exists; the affected request has already
been answered. Treat a non-zero value as a host-level signal: the fault is a failing
`pthread_mutex_lock`, which on a healthy box does not happen. Check the same host for
`yuzu_mcp_bridge_teardown_incomplete_total`, for OOM-killer activity, and for thread or
file-descriptor exhaustion. Clients that saw a fallback final can fetch the real result
with `GET /api/v1/executions/{execution_id}`; a restart clears nothing here, because
nothing is retained - the record itself is reclaimed normally.

## Known gaps

Tracked follow-ups an on-call engineer may hit:

- **#2514** - the maintenance thread has other unguarded blocks, so severe pressure can still abort the process from a different call site.
- **#2515** - `shutdown()`'s walk still aborts on the FIRST THROWN EXCEPTION anywhere in its single outer `try` (records_/streamed_unpinned_ never cleared, remaining records never unsubscribed, no log/counter/audit) - unchanged by #2517. What #2517 fixed is narrower: a record `shutdown()` reaches NORMALLY (no exception) that was claimed-but-abandoned by a raced sweep is now poisoned and evidenced (`mcp.bridge.shutdown_reap`), where it used to be silently reclaimed with no signal at all. #2515's exception-aborts-the-walk gap is still open.
- **#2518** - a wedged audit database can stall this thread every tick.

## Related

- `docs/user-manual/metrics.md` - full metric reference
- `docs/user-manual/audit-log.md` - the `mcp.bridge.*` verb family and its `result` values
- `docs/mcp-server.md` - progress-bridge design and the degradation contract
