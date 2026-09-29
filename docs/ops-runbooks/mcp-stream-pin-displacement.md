# Runbook: MCP replay-ring pin displacement / unpinned final

**Alerts:** `YuzuMcpStreamPinDisplaced`, `YuzuMcpStreamFinalUnpinned`,
`YuzuMcpBridgePinReleaseFailed`, `YuzuMcpStreamedPinSlotsWedged`
**Severity:** warning.

For `YuzuMcpStreamPinDisplaced` and `YuzuMcpStreamFinalUnpinned`: **not a page, no
remediation.** No data is lost, no restart helps, clients recover on their own. What
these want from you is a judgement — whether a genuine accounting bug should be filed.

`YuzuMcpStreamedPinSlotsWedged` is **also different**: it means clients are being
REFUSED, which is a user-visible lockout rather than a diagnostic. See its own section
below — the "no remediation" line above does not apply to it either.

`YuzuMcpBridgePinReleaseFailed` is **different** and the "no remediation" line does not
apply to it: it needs a genuinely broken platform mutex, so any nonzero value is a signal about
the HOST, not about MCP. Treat it as you would any other host-fault signal; the MCP-side
consequence (a session one call over its cap for the lifetime of the over-admitted call) is the
minor half.

## What has happened

Every streamed MCP request's final response frame is committed to the session's replay
ring and **pinned** (exempt from ring eviction) so a client that reconnects late can
still resume it. `YuzuMcpStreamPinDisplaced` means a session's pin slots were all full
and the oldest pin was displaced to make room.

The derivation lives in `server/core/src/mcp_stream.hpp`'s `What a FULL PIN-SLOT SET means` block. The statement below is this document's own self-contained summary — you may not have that file — so if the answer changes, change the derivation there first and then propagate to every operator surface, this one included.

The short version, for triage only: a full slot set is a **signal to corroborate, not a
verdict**. A *successful* #2740 reclaim cannot cause one — it releases a pin and adds a
charge, so the session stays *at* cap. Only two paths can, each with its own counter,
and step 2 below is how you rule them out.

- `yuzu_mcp_stream_final_unpinned_total` moving is a different and worse condition than
  displacement: a final was committed with **no pin at all**, meaning the displacement
  path was bypassed or the array was sized to zero. Treat it as genuine drift without
  the rule-out below.

## Client impact

Worst case, a client resuming a displaced-and-since-evicted terminal gets its session
terminated with a coherent `404`, re-initializes, and fetches the result durably by
`execution_id` — the standard eviction ladder, no silent gap. Most of the time there
is no client impact at all.

A displaced final is **not** "delivered". These frames are ring-only; nothing delivers
one except a resume.

## What to do

1. **Capture.** The stream metric family (`yuzu_mcp_stream_*`, `yuzu_mcp_bridge_*`) and
   any `mcp.stream.attach` / `mcp.stream.close` audit rows around the increment. **Do
   NOT gather `mcp.bridge.pin_displaced_for_admission` rows here** — step 2's rule-out
   table below explains why: a successful reclaim explains zero displacement, so those
   rows are not evidence for this investigation and pulling them in only dilutes the
   capture with noise from an unrelated, benign counter.

2. **Corroborate before concluding.** The alert fires on any displacement, so the
   rule-out is yours to do. A **successful** #2740 reclaim cannot have caused it — the
   reclaim releases one pin and adds one charge, so the session stays *at* cap and a
   slot is always free. Only two paths can, and each increment of them explains exactly
   one slot:

   | counter | what it means | explains how much? |
   |---|---|---|
   | `yuzu_mcp_bridge_pin_release_raced_total` | the release lost a race (#2795) | at most one slot, per increment |
   | `yuzu_mcp_bridge_pin_release_failed_total` | the release threw and was contained (#2805) | one slot, per increment |
   | `yuzu_mcp_bridge_pin_displaced_for_admission_total` | a successful reclaim | **zero — NOT a cause. Do not rule out against it.** |

   The third row is listed precisely so you do not have to wonder why it is missing. A
   successful reclaim releases a pin and adds a charge, so the session stays *at* cap and
   nothing is displaced; it is ordinary, expected traffic, and counting it here would let
   routine client churn explain away real drift. Displacement in excess of what the first
   two rows explain is the residue worth filing.

3. **File, unless the rule-out is clean and complete.** Title: "MCP streamed-POST
   admission accounting drift", attach the capture. The interesting question is how
   `pinned_count() + unpinned` and the admission cap disagreed. **When in doubt, file** —
   this alert is diagnostic, a spurious report costs a triage pass, and a suppressed
   real one costs exactly the bug this alert exists to surface.

4. **Do not restart the server**: the counters are cumulative diagnostics, the degraded
   behavior is self-limiting, and a restart destroys the in-memory session state you
   would want to inspect.

## A rising `pin_displaced_for_admission` rate — not a page, a query

`yuzu_mcp_bridge_pin_displaced_for_admission_total` is **not alertable** (see its row in
`docs/user-manual/metrics.md` for the full explanation — do not restate it here). But an
operator who notices it climbing, for whatever reason, has a documented way to find out
who is causing it without new instrumentation: every reclaim is also an audit row.

```
GET /api/v1/audit?action=mcp.bridge.pin_displaced_for_admission&limit=1000
```

Add `&principal=<name>` to scope to a candidate you already suspect. Each row's
`target_id` is the reclaimed call's `execution_id` — empty specifically for an orphan
(no surviving record to name), never for the ordinary case — and `detail` says whether it
was a parked final or an orphan. There is no `session_id` field on this row; if you need a
time window rather than a principal, the legacy `GET /api/audit` endpoint additionally
takes `since`/`until` and `offset` (parameters `/api/v1/audit` does not have). **A response
at exactly `limit` rows is not proof you have everything** — `/api/v1/audit` truncates
silently, and its `total`/`page_size` fields describe what came back, not what matched
([#2881](https://github.com/Tr3kkR/Yuzu/issues/2881)); scope further with `&principal=`,
or fall back to the legacy endpoint. There, `since`/`until` alone only bounds the time
window — it does not by itself guarantee you retrieved everything inside that window if
more rows matched than one call returns. The reliable recipe is both together: freeze a
bounded window with `since`/`until` first, then page exhaustively through it with `offset`.
A `503` from either endpoint is the deny-on-degrade behavior `YuzuAuditReadDegraded`
covers, not "no matching rows" — treat it as an audit-store availability problem and
retry once that alert clears, not as a clean result.

If the rate correlates with a single principal, that is a client dropping connections
before its results land — ordinary, if unusually frequent, client behaviour, not a
server defect. If it does not correlate with any one principal, check
`mcp.bridge.forced_expire` (`GET /api/v1/audit?action=mcp.bridge.forced_expire&limit=1000`)
for server-side ring pressure tearing parked records down instead — the other of the two
causes metrics.md's row names.

## Why this procedure changed

An earlier revision told you to file unconditionally; the revision after that told you
to dismiss whenever any reclaim counter had moved. Both were wrong, in opposite
directions, and the second was worse — a successful reclaim explains **no** displacement
at all, so "a reclaim moved" cannot dismiss any of it.

That revision also told you to rule out #2795 by checking two counters, at a time when
the #2795 path incremented **neither** — it reset its own record before both counter
guards ran. The procedure therefore concluded "genuine drift" for precisely the case it
was written to excuse. `yuzu_mcp_bridge_pin_release_raced_total` exists because of that:
the residual had to become observable before any procedure about it could be honest.

A third revision briefly netted the reclaim counter out of the alert expression itself.
That was wrong for a more basic reason — a successful reclaim cannot cause a
displacement at all, so the subtraction removed real signal in proportion to ordinary
client churn. The alert is a plain threshold again and the rule-out lives here, where a
human can see which term applied.

## `YuzuMcpStreamedPinSlotsWedged` — a session is being refused, not merely degraded

This alert is the odd one out in this runbook and needs its own path. The three above are
diagnostics about a session that still works. This one fires on a **sustained** rate of
`yuzu_mcp_bridge_pin_slots_reject_total{held="pins"}` — streamed calls being REFUSED with
every slot held by a committed final rather than by a call in flight. A client is losing
service.

Read *sustained* strictly. Every healthy session passes through `pinned>0, unpinned==0`
during the charge-to-pin handover, so a single sample is not a wedge; the alert carries a
`for:` for exactly that reason and that `for:` is load-bearing, not tuning.

**Why 15 minutes, not something shorter.** States (1) and (2) below both clear on the
client's own retry — the streamed-POST `429` remediation carries `Retry-After` derived
from `kMcpStreamedPostRetryAfterMs` (30s, `mcp_stream.hpp`), so a conforming client
following it clears a genuine transient within tens of seconds, not minutes. `for: 15m`
is therefore roughly 30x that retry cadence, not a tight fit to it — the margin is
deliberate, not merely convenient: it also has to absorb a client that is slow to retry,
one that retries with backoff, and the charge-to-pin handover window itself (which is
well under a second). A shorter `for:` would trade that margin for faster detection of
state (3); this runbook's position is that the margin is worth more, since state (3) is
rare and self-recoverable by the client either way (step 3 below), while a page on a
slow-but-healthy retry cycle is a false one.

That margin is not free. A client retrying at or slower than the window's own 15 minutes —
a non-conforming client ignoring `Retry-After`, or one on a coarse fixed schedule — can
keep re-triggering a genuinely-wedged state (3) without ever producing a *sustained* rate
this rule can see, because each rejection's gap from the last is at least as wide as
`for: 15m` itself. Measured against the shipped rule: a 16-minute retry cadence never
fires through 95 simulated minutes, no matter how long it persists — the cliff sits
exactly at the window's own width, not somewhere below it. A cadence *faster* than the
window is a different case: successive rejections start overlapping inside the trailing
15-minute range before the previous one ages out, so the reading locks into "sustained"
and the alert does fire — but not immediately, and not after just the 15 minutes of
`for:` alone. Pinned by a promtool case (CASE 16, `tests/prometheus/yuzu-alerts.test.yml`):
for a 10-minute cadence, the reading first goes continuously sustained about a minute
after the first rejection, then still needs its own full 15 minutes of that before
`for:` is satisfied — roughly 16 minutes from the first rejection to the alert actually
firing, not 15. Silence from this alert is
therefore not evidence a slow-retrying client's session recovered — treat it as
unresolved, not clean, for any client retrying at or slower than 15 minutes, and note
that even a faster-but-still-slow cadence buys a genuine wedge a real head start over
`for:`'s own 15 minutes — 16 minutes for the pinned 10-minute cadence, and longer still
if measured from wedge onset rather than from the first rejection this alert can see.

The margin argument above also implicitly reasons about a single client's retry cadence.
The underlying counter carries no session dimension (see the scoping note in step 4
below), so a reading that looks sustained can equally be several different,
individually-transient rejections across different sessions overlapping in time, rather
than one client failing to recover — the alert cannot tell the two apart, and neither can
this derivation. Either way, a sustained reading is real signal worth investigating: the
ambiguity is about attribution (one client or several), not about whether something is
wrong.

**Since #2740 this should be rare**, because admission reclaims a slot rather than
refusing. A `pins` refusal that survives the reclaim means the reclaim found nothing to
take, which happens in three states:

1. a final still being WRITTEN by a live pump — clears on retry;
2. a transient decline while one of the session's records is mid-projection — clears on retry;
3. a slot genuinely stuck: an unreleasable pin the scan could not attribute.

**What to do.** Only (3) is a real wedge, and only (3) needs you.

1. Capture `yuzu_mcp_bridge_pin_slots_reject_total{held}` for both label values, the
   `yuzu_mcp_bridge_pin_*` family, and the affected session id from the `mcp.session.reject`
   audit rows (`target_type=McpSession`, `target_id`=the session id's first 8 characters —
   a prefix, not a guaranteed-unique key; corroborate against the metric capture above
   before treating two matching rows as the same session). `detail` carries
   `reason=post_pin_slots` for exactly this rejection — other reasons on the same action
   share the row shape but not the reason. `GET /api/v1/audit?action=mcp.session.reject&limit=1000`,
   filtering the `detail` field for `reason=post_pin_slots`; if you already have a candidate
   session id, the legacy `GET /api/audit?action=mcp.session.reject&target_id=<8 chars>` narrows
   directly (the `/api/v1/audit` route does not take `target_id`). **A response at exactly
   `limit` rows is not proof you have everything** — `/api/v1/audit` truncates silently, and
   its `total`/`page_size` fields describe what came back, not what matched
   ([#2881](https://github.com/Tr3kkR/Yuzu/issues/2881)); if you hit the cap, the legacy
   endpoint also takes `offset`, and `since`/`until` alone only bounds the time window — it
   does not guarantee completeness inside that window by itself. Freeze the window with
   `since`/`until` first, then page through it with `offset` if you need everything in it.
   A `503` from either endpoint is the deny-on-degrade behavior `YuzuAuditReadDegraded`
   covers, not "no matching rows" — treat it as an audit-store availability problem and
   retry once that alert clears, not as a clean result.
2. If the rate is falling on its own, it was (1) or (2). Nothing to do.
3. If it is flat and sustained with `held="pins"`, the session is wedged. **The client's
   recovery is its own**: it can resume with `Last-Event-ID` (which releases pins at or
   below the cursor) or re-initialize for a fresh session — both are in the `429`
   remediation text it already received. Results stay fetchable by `execution_id`
   regardless, so nothing is lost.
4. **Do not restart the server.** A restart drops every live MCP session and every
   in-flight streamed request fleet-wide — a far larger outage than the lockout you are
   looking at, and the client's own recovery in step 3 does not need it.

   Be aware you probably **cannot** tell from this alert whether one session is wedged or
   many: `yuzu_mcp_bridge_pin_slots_reject_total` carries only the `held` label and has no
   session dimension, so the paging signal cannot separate "one session refused repeatedly"
   from "many sessions refused once". The `mcp.session.reject` audit rows in step 1 give you
   the session ids you captured, not a population count. **If you cannot establish the scope, treat it as a
   single session and do not restart** — that is the safe direction, because a wedged
   session is self-recoverable by the client and a restart is not recoverable for anyone
   else. Escalate for a `session_id` label on that counter rather than guessing.

   A restart is only worth considering if you have INDEPENDENT evidence of a fleet-wide
   fault — many clients reporting failure, or another alert firing — and in that case you
   are no longer troubleshooting this one.
5. File it either way if you reach (3): a genuinely unattributable pin means the reclaim's
   orphan scan missed something, and that is a bug worth the report.

**Note this alert previously pointed at `mcp-bridge-teardown-recovery.md`**, which has
never covered it — that doc's subject is a mutex-failure teardown path, and its only
remediation is a process restart, which is wrong here for the reason in step 4. Tracked
as #2792.
