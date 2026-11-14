# #5712 — honest roster truncation: design note

Status: implemented on `feat/roster-truncation-5712`; plan reviewed in-session by the
enterprise-architect review agent before any code (verdict APPROVE WITH CHANGES, changes adopted; the
review output is not committed, so this is the author's relay, not an independent record). Acceptance criterion 2 of #5712 asked
for this note before the code; the decisions below are the ones that review attacked. Provenance:
an earlier implementation of #5712 and two follow-up issues filed with it were lost with a
previous working session and were not recovered, so this design is a reconstruction and the
filed follow-ups (#7549, #7550, #7551 and later) are a fresh set, not the original one.

## The defect

`OfflineEndpointStore::query_stale_within` kept `LIMIT kQueryRowCap` (100000) newest-first and
returned the capped set as a plain success. Every consumer then presented a partial roster as the
fleet: the Hardware list and its KPI strip undercounted with no banner, and the offline identity
fallback (`hw_identity_fn`) scanned the same capped set, so an enrolled offline device older than the
newest 100,000 read as "not found" (REST 404) — the harm #5531 fixed for a failed read, reached
through the cap instead.

## The trap (#5371)

The typed `PresenceReadError::Truncated` already existed, produced by `query_live_ids`. Reusing it
here would turn a steady state (a fleet over the cap) into a refusal that never clears: every
Hardware render would answer "retry shortly" forever. `Truncated` is the right answer for the
dispatch-safety presence read (fail closed); it is the wrong answer for a display read. So the roster
read **never** returns it.

## Decisions

**D1 — a typed partial, not an error.** `query_stale_within` returns
`std::expected<OfflineRoster, PresenceReadError>`, `OfflineRoster{rows, truncated}`. It queries
`LIMIT cap+1` (a count of exactly the cap is the complete set), trims to the cap and sets `truncated`.
The flag is derived per read, so it clears when the fleet drops back under the cap. `OfflineRoster` is
a plain aggregate: nothing converts a bare vector into one, so a consumer cannot ignore the flag by
accident. Rejected: paging (the list model filters and sorts the whole roster in memory, and KPIs
would stay partial); a second method or out-parameter (two reads, a race). Ties at the cut on
`last_heartbeat_ms` are arbitrary: the only index is on that column and a tiebreak could force a full
sort at fleet scale. The cap lives once, as `kOfflineRosterRowCap` in the store-free types header.

**D2 — honest partial on every surface, HTTP 200.**

| Surface | Partial state |
|---|---|
| Hardware list (HTML) | "Partial list" notice inside `#hw-results` (survives htmx re-renders and shows in the empty-result state), KPI counts marked `≥` |
| `GET /api/v1/hardware` + MCP `list_hardware_ci` (one shared builder) | `roster_truncated`, `roster_cap`; `total_matching`, `pagination.total`, `devices_omitted`, `kpis.*` documented as lower bounds; MCP output schema and description updated |
| Dashboard scoped estate | `at_least` now comes from the typed flag; a fleet of exactly the cap is exact (the old `rows.size() >= cap` heuristic called it partial) |
| Fleet topology REST + MCP | `offline_roster_truncated`; audit token on the 200 **and** the 413 row |
| Hostname map (Software, Quarantine) | display-only, deliberately silent, documented: a host past the cap shows its `agent_id` |

KPIs are **not** re-sourced from `fleet_state_counts`: that read is documented NOT CONFINED and the KPI
strip describes the caller's scoped roster. A truncated read is audited (`roster_truncated=1`) on the
list verbs. A scoped caller sees the one bit (their own rows can be among the missing; the Dashboard's
`at_least` already showed management-group-confined callers the same fact) and never a roster count.
`devices_omitted` is erased for confined callers on MCP; on REST it is emitted to confined callers
(a pre-existing divergence, unchanged here). The `roster_truncated` bit and the constant `roster_cap`
reach scoped callers INCLUDING service-scoped tokens (the Dashboard precedent covers
management-group-confined callers only; `DashboardSummaryRoutes` denies service-scoped tokens). It
discloses only the coarse fact "more than 100,000 roster rows in the window", not a count. ACCEPTED,
because a confined caller's own rows can be among the missing.

Truncation is per surface because the windows differ: 30 days for Hardware, 7 days for fleet
topology (viz).

A miss under truncation is not proof of absence: filters, search and sort run over the capped set.
The notice therefore also renders when the result is empty, and the REST/MCP descriptions point at the
exact per-device read.

**Viz is mostly unreachable as a partial.** `kMachinesMaxCeiling` equals the roster cap and the
`machines_max` gate runs after the merge, so a truncated merge is at least 100,000 machines: a 413 at
any `machines_max` below the ceiling. The flag is carried on that 413's audit row; a 200 with the flag
needs `machines_max=100000` with every live host inside the roster. The permanent 413 beyond that is
#7550, not fixed here.

**D3 — a point read for identity.** `OfflineEndpointStore::find_within(agent_id, window)` is a
primary-key lookup with the roster's own window predicate (`>=`), so it is exact at any fleet size and a
miss is a *confirmed* absence. The Hardware list and the point read use the same 30-day window. An
`agent_id` containing NUL or invalid UTF-8 is also a confirmed absence (no store error, no counter, no
warn), so the caller returns the same 404 "not found" as for any unknown id. `hw_identity_fn` uses it instead of scanning the roster; the live-session
short-circuit is unchanged. The scan overload of `offline_identity_row` is deleted, so a linear-scan path
cannot be reused. Consequential fixes with no code of their own: the decommission confirmation hostname
and the containment lens `identity_known` are correct beyond the cap. No new existence oracle: every
caller that renders the identity authorises first. The stored-data panel (`device_estate_routes.cpp`)
reads the identity even when its decommission gate is Denied/Unchecked but renders the hostname only on
Allowed, so nothing observable changes.

**D4 — observability.** A fleet over the cap is a steady state, so a per-read warn would be permanent
log spam. New unlabelled counter `yuzu_server_agent_presence_roster_truncated_total` (pre-seeded at 0,
one increment per truncated read, debug log; operational telemetry, not evidence: the audit rows are
the evidence of record), no alert (a threshold needs fleet data, the same posture
as its sibling family). `reason="truncated"` of the failure counter stays `query_live_ids`-only; the
point read counts failures under `op="find_within"`.

## Not fixed here (follow-ups)

- #7549 — the CI join (`list_device_ci(0)`) has its own silent 100,000-row cap, ordered by hostname.
- #7550 — fleet topology is a permanent 413 over the roster cap.
- #7551 — the CI record decides online from the local session map; the list uses `all_ids()`.
- The Hardware Online/Offline derivation uses `AgentRegistry::all_ids()` (`live_presence().value_or({})`),
  so on a failed or truncated live-presence read cross-replica agents silently read offline with no flag
  (#5007 tracks other callers; new follow-up #7566).
- No enumeration path past the cap: the cap applies before search and filters, and only a per-device
  point read by known id is exact (#7567).
- The KPI-adjacent figures (CI coverage tile, manufacturer breakdown, median memory, "Showing a-b of N")
  are not `>=`-marked; the notice states the counts are lower bounds.
- The per-render uncached full roster read (a perf sibling of #1783) and the silent hostname map past
  the cap are recorded here and in the user manual; neither is a correctness defect of this change.

## What would change this design

Evidence that any roster consumer feeds a dispatch or authorization decision rather than a display. That
consumer would have to fail closed. The five consumers (`build_hw_roster`, `hw_identity_fn`,
`hw_hostnames_fn`, the viz closure, the Dashboard scoped path) were each read for this and none does.
