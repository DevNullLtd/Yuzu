# Security review — Periodic access reviews (SOC 2 CC6.2)

**Date:** 2026-07-21
**Change:** `GET/POST /api/v1/access-reviews*` + `access_review_model.{hpp,cpp}` +
`access_review_store.{hpp,cpp}` + MCP twins (`export_access_review`,
`open_access_review`, `record_attestation`, `get_access_review`,
`list_access_reviews`, `close_access_review`)
**Branch:** `feat/auth-access-reviews`
**Control:** SOC 2 **CC6.2** (logical access — periodic review and, where
appropriate, revocation of access). Closes the `/auth-and-authz` gap
"Periodic access reviews with manager/security attestation" (previously
listed **MISSING**; Priority-2 item **13** — item 12 at the time this record
was written, renumbered on 2026-07-25 when a duplicate `10` in that section
was corrected).

> **Addendum (2026-11-03, #4752, amended 2026-11-04).** The statements below that `record_attestation` is an UPSERT
> that overwrites a prior decision (under "What shipped", and the `destructiveHint` rationale) are
> superseded: every decision is now kept and the reviewer must differ from the subject of the
> grant. See "Addendum (2026-11-03, #4752, amended 2026-11-04)" at the end of this document.

## What shipped

- **Export (stateless):** `GET /api/v1/access-reviews/export?format=json|csv`
  — every user/group/engine-principal's **direct** role grants right now,
  with `effective_permission_count`, last activity, `classification`,
  `lifecycle_state`, and `source` (provenance). Built by the pure read-model
  `access_review_model.hpp` (`build_access_review`), which reads `AuthDB`,
  `RbacStore`, and `EnginePrincipalStore` (required — a null pointer or a
  closed store fails the whole call), plus optional `ApiTokenStore`/
  `DirectorySync` enrichment. **Grant-table-driven (UP-1, hardening
  round):** the export's spine is the grant table, not any roster — a
  principal with zero grants produces no row (the export answers "who
  currently has access", not "who exists"), and a grant belonging to a
  principal outside every roster is surfaced as a `source="orphan"`,
  `lifecycle_state="unknown"` row rather than silently dropped. **CSV
  formula-injection neutralized (hardening round, CWE-1236):** any field
  whose first byte is `=`/`+`/`-`/`@`/tab/CR is `'`-prefixed before RFC-4180
  quoting.
- **Campaign list:** `GET /api/v1/access-reviews` (hardening round) lists
  every campaign's metadata (not its attestations), newest-first, capped at
  the most recent 500 — the surface an auditor needs to prove reviews ran
  on cadence without already knowing a `campaign_id` out-of-band.
- **Attestation campaigns (durable):** `POST /api/v1/access-reviews` opens a
  campaign that **freezes the complete current grant population** as
  `pending` attestation rows in one transaction; `POST
  /api/v1/access-reviews/{id}/attestations` records a reviewer decision
  (`attested`/`flagged_revoke`) against one frozen `(principal, role)` grant
  — recorded once and then final (an UPSERT until #4752, see "Update 2026-11-05" below); `POST
  /api/v1/access-reviews/{id}/close` closes the campaign; `GET
  /api/v1/access-reviews/{id}` returns the full evidentiary state
  (metadata + every attestation row + `pending_count`).
- **Store:** `AccessReviewStore` (`server/core/src/access_review_store.{hpp,cpp}`,
  schema `access_review_store`) — born-on-Postgres (ADR-0006), two tables
  (`access_review_campaign`, `access_review_attestation`), authoritative/
  fail-hard posture (ADR-0012 §1).
> **Addendum (2026-08-05, #2376) — read the "granted only to" claims below as
> RBAC-ON-scoped until #2376.** This document describes the `AccessReview`
> securable's grant model accurately, but that model only governed access when
> RBAC was *enabled*. RBAC ships **disabled** by default, and with it disabled
> the pre-RBAC legacy fallback in `require_permission` allowed every `Read` to
> any authenticated non-engine session — so on a default install the
> fleet-wide grant export was reachable by a plain `user` regardless of the
> dedicated securable this review cut. #2376 closes that with an admin floor
> that holds regardless of the RBAC toggle, which makes the statements below
> true unconditionally rather than only under RBAC-on. See
> `docs/security-reviews/authz-topology-floor-2026-08-05.md`.

- **RBAC:** new dedicated `AccessReview` securable type with two operations,
  `Read` (export/get/list) and `Attest` (open/attest/close), granted only to
  `Administrator` and a new seeded `Reviewer` role (`AccessReview:Read` +
  `AccessReview:Attest` only — 7 built-in roles total). **Round-2 fix
  (this review):** the original implementation gated these routes on the
  existing `AuditLog:Read`/`AuditLog:Attest` operations instead — see
  "#2225 round 2" below for why that over-disclosed and how the dedicated
  securable closes it.
- **MCP twins:** `export_access_review`, `open_access_review`,
  `record_attestation`, `get_access_review`, `list_access_reviews`
  (hardening round), `close_access_review` (hardening round) — JSON only;
  the REST `?format=csv` export has no MCP equivalent.
  `record_attestation` carries `destructiveHint:true` (hardening round —
  it writes a final, irreversible decision; it was a decision-overwriting UPSERT until #4752); every other twin is
  `destructiveHint:false`.
- **Audit actions:** `access_review.exported`, `.list` (hardening round),
  `.campaign_opened`, `.attested`, `.flagged`, `.closed`, `.get`.
- **Metrics (hardening round):** `yuzu_access_review_export_total{format}`,
  `yuzu_access_review_export_duration_seconds`,
  `yuzu_access_review_campaigns_opened_total`,
  `yuzu_access_review_attestations_total{decision}` — see "Metrics" below.

## Control / authz decision

### CC6.2 control mapping

- **`GET /api/v1/access-reviews/export`** is the **"role-assignment
  export"** half of CC6.2 — a point-in-time list of who has what access,
  pullable on demand for a spot-check or an offline CSV hand-off to an
  auditor. It is intentionally stateless: nothing is persisted by calling
  it, so pulling it repeatedly (e.g. to sanity-check a campaign before
  opening one) carries no side effect beyond its own audit row.
- **The attestation campaign** (`open_campaign` → `record_attestation` →
  `close_campaign`) is the **"manager/security sign-off"** half — the
  auditable proof that a *human* reviewer looked at each grant and made an
  explicit decision, not just that a list was generated. `pending_count` on
  a closed campaign is the "how complete was this review" number an
  auditor needs without re-deriving it from the attestation rows.
- Read together, the two pieces answer CC6.2's actual question: not just
  "what access exists" (the export alone) but "was it *reviewed*, by whom,
  when, and what did they decide" (the campaign).

**Why `access_review.*` is deliberately NOT in the `auth-sample` export
scope.** `GET /api/v1/audit/auth-sample` (`rest_api_v1.cpp`) samples audit
rows with `action_prefixes = {"auth.", "mfa.", "session.",
"engine_principal."}` — `access_review.*` is not, and should not be, added
to that list. `auth-sample` is CC7.2 evidence — a sampled proof that
*authentication* activity (logins, MFA challenges, session lifecycle,
engine-credential events) is being logged and monitored for anomalies; a
*sample* is the right shape for a high-volume, per-request event stream.
Access review is CC6.2 evidence with the opposite shape: a low-volume,
high-value, individually-consequential record (who reviewed what, and
decided what) that must be read **completely**, never sampled — a reviewer
or auditor needs every attestation on a campaign, not a pseudo-random
subset. It has its own dedicated, complete-by-construction export (`GET
/api/v1/access-reviews/export` and the campaign lifecycle), which is the
correct-shaped evidence surface for its own control, not a candidate for
folding into a sibling control's sampled stream.

### #2225 — global gate, not `authorize_list_read`

Every new list/fan-out read of **per-agent** data must use the ADR-0017
`authorize_list_read` admit-then-filter chokepoint (World A) — never a bare
global `require_permission`. This feature is a list read, and deliberately
does **not** use that chokepoint. This is a considered exception, not an
oversight, for three reasons:

1. **There is no per-agent boundary to filter against.** RBAC role
   assignments are fleet-wide facts about a *principal* (a user, a group, an
   engine principal), not facts scoped to a device or management group. The
   ADR-0017 gate exists specifically to stop a confined operator from seeing
   agents outside their groups; a role grant has no analogous "which
   management group is this grant in" dimension.
2. **A confinement-filtered slice would be worthless as evidence.** Even a
   contrived per-operator filter (e.g. "only show grants for principals who
   touch my devices") would produce a partial certification — and a partial
   certification is not a certification. An auditor signing off on CC6.2
   compliance needs the *complete* grant population, every time.
3. **The privileged surface is the gate itself, not a filter on top of it.**
   Requiring a dedicated permission (global, unconfined) for this feature is
   the same posture the shipped `GET /api/v1/audit/auth-sample` sibling
   already uses, and for the same reason: a dedicated read-only
   auditor/reviewer principal can be granted evidence access **without**
   also granting full `Administrator` authority (separation of duties) — a
   *stronger* CC6.3 least-privilege posture than folding this into
   `require_admin`, not a weaker one.

This first-round reasoning (why the gate is global/unconfined rather than
`authorize_list_read`-scoped) stands unchanged. What round 2 (this review)
corrected is **which permission** operationalizes it — see below.

### #2225 round 2 — reviewer-found over-disclosure via `AuditLog:Read`, fixed with a dedicated `AccessReview` securable

The original implementation of the above reasoning reused the existing
`AuditLog:Read`/`AuditLog:Attest` operations on the `AuditLog` securable as
the gate, on the assumption that `AuditLog:Read` was effectively
`Reviewer`-only. **A reviewer found this assumption false and the design
over-disclosing:** `AuditLog:Read` is also seeded to the built-in `Operator`
and `PlatformEngineer` roles (for the pre-existing `GET
/api/v1/audit/auth-sample` CC7.2 evidence route and the general audit-log
read routes), neither of which is granted `UserManagement:Read` (the
dedicated `/rbac/roles` permission) or, at the time, `Security:Read` (then
the `/engine-principals/{id}/roles` permission — that route moved to the
narrower `EnginePrincipal:Read` in #2376; see the addendum at the top). Under the original gate, an
`Operator` or `PlatformEngineer` — roles explicitly **denied** the
purpose-built routes for reading the fleet's role-assignment graph — could
still pull the *entire* grant population, every principal's every role, via
`GET /api/v1/access-reviews/export`. That is a materially broader
disclosure than either of the routes those roles are deliberately excluded
from, reached through a permission (`AuditLog:Read`) that predates this
feature and was never scoped with access-review disclosure in mind.

**The fix:** a new, dedicated RBAC securable type **`AccessReview`** with
exactly two operations, **`Read`** (export/get/list) and **`Attest`**
(open/attest/close), seeded **only** to `Administrator` and the `Reviewer`
role. The `Reviewer` role now holds `AccessReview:Read` +
`AccessReview:Attest` (no longer `AuditLog:Read`/`AuditLog:Attest`). The
`AuditLog:Attest` operation — added earlier in this PR solely to support
access reviews — is removed as unused now that `AccessReview:Attest`
exists; `AuditLog:Read` reverts to its pre-existing scope (`auth-sample`
export, general audit-log reads) and is no longer sufficient, by itself, to
reach any access-review route. `Operator`/`PlatformEngineer` keep
`AuditLog:Read` for their legitimate uses but hold no `AccessReview`
operation, so they can no longer reach `/api/v1/access-reviews*` in any
form.

This closes the over-disclosure while **preserving** every property
established in the three numbered reasons above: the gate is still global
and unconfined (reason 2 — a confinement-filtered slice remains worthless
as CC6.2 evidence), and it is still a dedicated RBAC-privileged operation
nobody gets by default (reason 3) — it is simply now a *narrow* securable
purpose-built for this feature instead of a *broad* one shared with
unrelated audit-log functionality. If anything, this is the stronger
reading of reason 3's least-privilege argument: the original design assumed
"`AuditLog:Read` ≈ `Reviewer`-only", which was false the moment `Operator`/
`PlatformEngineer` were seeded that permission for an unrelated purpose; a
securable dedicated to exactly one feature cannot silently widen the same
way as new roles are seeded onto a shared permission in the future.

The seeded `Reviewer` role operationalizes the fixed design: `AccessReview:Read`
+ `AccessReview:Attest`, nothing else — no `Write`/`Delete`/`Approve`/`Push`
on `AccessReview`, no `AuditLog` operation at all, and none of the write
access `Administrator` carries elsewhere. An organization appoints a
reviewer without handing them the keys to the platform, and without that
reviewer grant riding on (or being silently widened by) any other role's
unrelated `AuditLog:Read` grant.

### Disabled-user lifecycle honesty (round 2 fix)

A second, unrelated round-2 fix: a user who is disabled but still holds a
live role grant previously surfaced on the export as `source="orphan"`,
`lifecycle_state="unknown"` — indistinguishable from a genuinely orphaned
grant belonging to a principal absent from every roster. That mis-shown a
real, roster-matched user as if they didn't exist. The export now correctly
enriches a disabled user's row from the `AuthDB` roster like any other user
row, reporting `source="user"`, `lifecycle_state="disabled"`. This matters
for CC6.2 review quality specifically: a disabled-but-still-granted user is
exactly the kind of finding a periodic access review exists to catch (a
likely `flagged_revoke` candidate), and it must be presented as "a known
user whose account is disabled yet still holds access" — not conflated with
the `source="orphan"` bucket, which means "no roster entry could be found
for this grant at all" and carries a different investigative next step.

### PII judgment — `last_activity_ms`/`last_activity_kind` are NOT behavioral-PII-tier

The device-pages / DEX / Echo routed concern (see `docs/user-manual/
device-management.md` and `CLAUDE.md`'s "Device pages" row) establishes that
**behavioral-PII** access — per-device DEX signals, process trees, Echo
capture data — must funnel through `server/core/src/rest_audit.hpp`'s
`emit_behavioral_audit` chokepoint (REST fail-closed 503 + `Sec-Audit-Failed`
on an audit-persist failure; dashboard/MCP set-and-proceed). This feature's
`last_activity_ms`/`last_activity_kind` fields (a user's `AuthDB` last-login
epoch, or an engine principal's most recent credential `last_used_at`)
deliberately do **not** route through that funnel. This is a considered
classification decision, not an oversight:

- **What `emit_behavioral_audit` protects is fine-grained, per-signal
  behavioral telemetry** — which processes ran, which DEX observation types
  fired, which files/services were touched, on which specific device, at
  what granularity. That is data about what an *endpoint* (and by
  extension, potentially, the human using it) was *doing*.
- **`last_activity_ms`/`last_activity_kind` are a single coarse admin-
  activity timestamp per principal** — "when did this account last
  authenticate" or "when was this credential last used" — already visible
  to any `AuditLog:Read` holder via the ordinary audit log (`GET
  /api/v1/audit`) and the `auth-sample` export. It carries no per-device,
  per-process, or per-signal granularity; it is exactly the kind of coarse
  account-hygiene fact CC6.2/CC6.3 evidence is built from, not a new
  disclosure surface.
- **The existing gate is the correct-strength control for this data
  class.** These fields ride the SAME `AccessReview:Read` permission check
  that gates every other field on this row (roles,
  `effective_permission_count`, `classification`, `lifecycle_state`), and
  the export is self-audited
  (`access_review.exported`) exactly like the sibling `auth-sample` export.
  Layering the stricter fail-closed-503 behavioral-PII posture on top would
  be a mismatch of control strength to data sensitivity — and would make a
  transient audit-persist hiccup block a compliance export outright, which
  is the wrong failure mode for *this* surface (see "fail-loud on the read,
  set-and-proceed on the audit" below).
- **If a future field on this export ever gains per-device or per-signal
  granularity** (e.g. a per-device last-command-executed timestamp), that
  field would need to be re-evaluated against this same test and likely
  migrated to `emit_behavioral_audit` — this judgment is scoped to the two
  fields as they exist today, not a blanket exemption for the route.

### flag ≠ revoke — the enforcement boundary

`record_attestation`'s `decision:"flagged_revoke"` is **evidence only**. No
code path from this route calls `RbacStore::unassign_role`,
`EnginePrincipalStore::revoke`, or any other authorization-mutating
function — `AccessReviewStore::record_attestation` writes exactly one row
(`decision`, `reviewer`, `justification`, `decided_at_ms`) to
`access_review_attestation` and nothing else. This is deliberate, for two
reasons:

1. **A reviewer flagging a grant and an operator revoking it are different
   trust decisions with different blast radii.** A reviewer's job is to
   surface a *recommendation* ("I believe this access should be removed");
   actually removing it is a live authorization change that can break a
   dependent workflow or lock out a legitimate user, and belongs on the
   ordinary, individually-audited RBAC/engine-principal write surface
   (`unassign_role`, `revoke_certificate`, etc.), gated by *its own*
   permission (`Security:Write`/`Delete`, not `AccessReview:Attest`).
2. **Auto-revoking on a flag would make `AccessReview:Attest` a second, less-
   audited path to a real authorization change** — exactly the kind of
   confused-deputy shortcut the access-review surface must not become.
   Keeping flag and revoke on separate, separately-gated routes means the
   audit trail for an actual revocation always carries the permission and
   audit verb appropriate to *that* mutation, with the flag serving only as
   the recorded rationale an operator can point back to.

The two outcomes (`access_review.attested` vs `access_review.flagged`) are
separately-named audit verbs specifically so a SIEM rule (or a human
reviewing the log) can count/alert on flagged-for-revocation grants without
parsing a `decision` field out of a generic verb.

### Retention posture — born-on-PG, deliberately no prune

`AccessReviewStore` carries **no prune method**, unlike the `/auto` pre-
flight/deployment runs (`PreflightRunStore`/`DeploymentRunStore`), which are
operational scratch state pruned at 14 days. A **closed** access-review
campaign *is* the compliance evidence this feature exists to produce — it
persists indefinitely by default. This is intentional, not an unfinished
feature:

- Retaining every campaign forever is the conservative default for
  evidence a SOC 2 auditor may ask to see years later.
- Any future retention policy (e.g. a configurable retention floor tied to
  an auditor's actual evidence-window requirement) is an **explicit,
  separately-reviewed decision** — it must not be inherited by copying a
  prune cadence from an unrelated operational store.
- Construction is fail-**closed** per ADR-0012 §1 (matching
  `EnginePrincipalStore`, not the durability-on-top `PreflightRunStore`
  posture): a reachable database whose schema can't migrate refuses to
  start (`startup_failed_`), because a degraded evidence store serving
  partial writes is worse than the server refusing to boot.

### Fail-loud on the read, evidence-of-access on the write

- **`build_access_review` fails the WHOLE export on the first read error**
  (R1) — never a partial `vector<AccessReviewRow>`. A compliance export
  that silently drops rows on a transient failure is worse than one that
  fails loudly: an incomplete-but-200 export reads as "this is the complete
  list" when the truth is "the read partially failed" — a false negative in
  exactly the evidence this feature exists to produce. The REST route maps
  a `build_access_review` failure to `503`, never a 200 with fewer rows.
- **The export's own access is itself audited** (`access_review.exported`)
  so pulling evidence stays on the audit chain — mirroring
  `audit.auth_sample.exported`. Emission is best-effort: if the audit row
  fails to persist, the export still returns its data (evidence access
  should not be blocked by an audit-store hiccup), but the failure is made
  **visible** via a `Sec-Audit-Failed: true` response header rather than
  silently swallowed.

### Metrics (hardening round)

The feature previously carried zero metrics — an `sre` governance SHOULD.
Four bounded-label Prometheus series, wired in the REST handlers only (the
MCP twins are not double-counted), pre-seeded per
`docs/observability-conventions.md` so `absent()` alerts stay meaningful:

- `yuzu_access_review_export_total{format}` (counter, `format` ∈ {`json`,
  `csv`}) — exports pulled via `GET /api/v1/access-reviews/export`.
- `yuzu_access_review_export_duration_seconds` (histogram) — latency of the
  cross-principal grant-population read (`build_access_review`) behind the
  export.
- `yuzu_access_review_campaigns_opened_total` (counter) — campaigns opened
  via `POST /api/v1/access-reviews`.
- `yuzu_access_review_attestations_total{decision}` (counter, `decision` ∈
  {`attested`, `flagged_revoke`}) — reviewer decisions recorded via `POST
  /api/v1/access-reviews/{id}/attestations`.

See `docs/user-manual/metrics.md` → "Access review metrics" for the full
reference.

## Hard-invariant check

- Export is a `std::expected`-propagating read across `AuthDB`, `RbacStore`,
  and `EnginePrincipalStore` (required) plus optional `ApiTokenStore`/
  `DirectorySync` enrichment — first failure fails the whole call, never a
  partial result. ✅
- `AccessReviewStore` construction fail-closed (ADR-0012 §1); every
  mutator/completeness-reader returns a typed `std::expected`, never a
  silently-empty/no-op result. ✅
- `open_campaign` freezes the campaign row + every `pending` attestation row
  in **one transaction** — no partially-frozen campaign is observable. ✅
- `record_attestation`/`get_campaign`/`close_campaign` use a
  machine-checkable `"not_found: "` error prefix, mapped to `404`
  (REST)/`kInvalidParams` (MCP) distinctly from a genuine `503`/
  `kInternalError` store failure — a caller can tell "bad id" from
  "transient outage" without string-matching a human-readable message. ✅
- `record_attestation` never calls any RBAC/`EnginePrincipalStore` mutating
  function — grepped `access_review_store.cpp` for `unassign`/`revoke`/
  `delete_role` call sites: none. ✅
- Every route requires `AccessReview:Read` or `AccessReview:Attest`, and
  **every route — reads included — additionally runs
  `deny_engine_session`**: an
  engine-classed caller is structurally denied on every access-review
  route, not just the mutating ones, matching the engine-principal
  surface's own posture. ✅
- A2 discovery: all six routes (export, list, campaign-open, campaign-get,
  attestations, close) are enumerable in `GET /api/v1/openapi.json`. ✅
- **Grant-table-driven completeness (UP-1, hardening round).**
  `build_access_review` walks the grant table (`RbacStore::
  list_all_principal_roles_checked()`) directly rather than the three
  principal rosters — a principal holding a live grant always produces a
  row, even when no roster recognizes its `principal_id` (a since-deleted
  user, a stale IdP row, an OIDC/SSO principal minted outside every
  roster). Such a row is surfaced as `source="orphan"`,
  `lifecycle_state="unknown"` rather than silently dropped. This closes a
  real completeness gap the original roster-walk design had: a grant
  belonging to a principal outside every roster was previously invisible
  to the export — a false negative in exactly the evidence this feature
  exists to produce. ✅
- **CSV formula-injection neutralization (hardening round, CWE-1236).**
  `to_csv` prefixes any field whose first byte is `=`/`+`/`-`/`@`/tab/CR
  with a literal `'` before the RFC-4180 quoting pass. Several exported
  fields (principal id, display name, owner/email, role names) are
  influenceable by an external identity provider (SCIM `userName`, an
  engine principal's `display_name`), so this closes a genuine
  spreadsheet-formula-execution risk on the CSV export path, not a
  theoretical one. ✅

## Tests

- `access_review_model.hpp`/`.cpp` — pure read-model, unit-testable without
  a live server; covers the fail-on-first-error contract (R1) and the
  per-principal-type direct-grant computation (R2), including the
  deliberate group-vs-user divergence from `get_effective_permissions`.
- `access_review_store.hpp`/`.cpp` — freeze-at-open atomicity (R3),
  `not_found:`-prefixed error contract, idempotent-rejecting `close_campaign`.
- REST route tests cover the `400`/`403`/`404`/`503` matrix per route,
  `Sec-Audit-Failed` on a dropped export audit row, and the CSV
  `Content-Disposition` header.
- MCP tool tests cover the tier/RBAC gate, the `not_found:` → `kInvalidParams`
  mapping, and tool annotation shape (`readOnlyHint`/`destructiveHint`).

## Residual / follow-ups

- **User `last_activity_kind` is `"n/a"` for every row today.** `AuthDB` has
  no read accessor for a user's last-login timestamp yet — a noted,
  tracked follow-up, not a silently-shipped gap. Once added, the export
  should switch `last_activity_kind` to `"last_login"` for user rows the
  same way it already reports `"last_used"` for engine rows.
- **User rows show direct grants only.** Group-inherited access is not
  flattened onto the user's row; it is visible on the group's own row. A
  future "resolved effective access" column is a candidate follow-up but
  would need a new reverse group-membership bulk accessor `RbacStore` does
  not currently expose.
- **`source="scim"` is forward-compat, not yet populated** by any SCIM
  write path — reserved so the field does not need a schema/API change once
  SCIM-provisioned-user provenance is threaded through.
- ~~**No campaign-list endpoint.**~~ **CLOSED (hardening round).** `GET
  /api/v1/access-reviews` now lists every campaign's metadata, newest-first,
  capped at 500, with an MCP twin `list_access_reviews`.
- **No retention/archival policy beyond "keep forever."** `AccessReviewStore`
  deliberately carries no prune method (see "Retention posture" above); a
  future configurable retention floor tied to an auditor's actual
  evidence-window requirement is an explicit, separately-reviewed decision,
  not something this feature should default to.
- **No rate limit on the export route.** `GET /api/v1/access-reviews/export`
  has no request-rate cap of its own beyond the standard `AccessReview:Read`
  gate — a low-risk gap today (the route is admin/auditor-scoped and O(grant
  count) per call, not O(fleet size)), but worth a shared rate-limit
  primitive if/when one exists for other admin-read routes.
- **No "effective access per user" view.** The export is per-`(principal,
  role)`; there is no single call that resolves one user's fully-flattened
  effective access (direct grants + group-inherited grants) in one row —
  see the "user rows show direct grants only" item above.
- **`AuthDB` has no user last-login read accessor** (see the
  `last_activity_kind="n/a"` item above) — a shared prerequisite for both
  this export and a future user-activity dashboard.
- **No scheduled/recurring campaigns.** Opening a campaign is a manual,
  on-demand `POST /api/v1/access-reviews` call — there is no cron-style
  "open a new campaign automatically every quarter" primitive. An operator
  or an external scheduler (e.g. a cron'd `open_access_review` MCP call)
  must drive the cadence today.

## Addendum (2026-11-03, #4752, amended 2026-11-04): reviewer differs from the subject of the grant; every decision kept

**What changed.** The original design let a reviewer record a decision on a grant that named
them, and a later decision on the same grant overwrote the earlier one. Now:

- `POST /api/v1/access-reviews/{id}/attestations` and MCP `record_attestation` share one rule
  (`server/core/src/access_review_attest_gate.hpp`) that requires the reviewer to differ from the
  subject of the grant: a `user` grant whose `principal_id` equals the reviewer's account name
  (byte-exact), an engine principal the reviewer owns (revoked ones included), or a group the
  reviewer belongs to is refused with `403` and nothing is recorded. The `403` names no
  `permission`, because the caller already holds `AccessReview:Attest`. The rule applies to
  `Administrator` as well as `Reviewer`, and to an administrator with RBAC off. A lookup that
  cannot be answered fails closed (`503`, nothing recorded).
- Every decision is appended to `access_review_attestation_history` (schema v3) with the decision
  it replaced and a sequence number; the grant row keeps the latest decision and `decision_seq`.
  `GET /api/v1/access-reviews/{id}` and `get_access_review` return `decision_seq` and `history`.
  `record_attestation` keeps `destructiveHint:true`, now because the current decision is replaced
  with no route back to `pending`, not because the earlier decision is lost.
- Input bounds: `principal_type`, `principal_id` and `role_name` are 1 to 1024 bytes without NUL
  and `justification` is at most 4096 bytes; a grant keeps at most 100 decisions (the 100th is
  final: the 101st is refused with `400`, nothing written, and the grant can be reviewed again
  only in a new campaign, which freezes a fresh population; the history and audit rows identify who
  wrote the entries) and a history read returns at most the latest 100 entries
  of a grant (for rows written through the application path; rows added by other means, such as
  owner-level SQL with the guard triggers disabled, are outside that guarantee). Every entry except the latest also returns at most the first 64 characters of its
  justification (cut in SQL, counted in characters, so on a UTF8 database a multibyte character is never split; see
  "Database encoding" in `docs/auth-architecture.md`), flagged by `justification_truncated`: the
  per-grant limit alone does not bound a campaign with many grants (100 x 4096 bytes x grants, about
  410 MB of text per copy at 1000 grants, held in several copies by the REST, MCP and page paths). With the
  preview the response grows linearly with the number of frozen grants (the per-grant ceiling bounds one grant, not the
  response, because there is no cap on the factor); there is no per-campaign budget and the frozen grant count is not
  capped (a recorded residual, accepted by the project owner on 2026-11-04 at the measured figures).

  Measured 2026-11-04 on Linux (glibc), with a FRESH server process per case (baseline server peak RSS about 104 to 105 MB),
  one `GET /api/v1/access-reviews/{id}` on a campaign of 1000 frozen grants with 100 decisions each (built by
  inserting rows directly into a throwaway database), with the 64-character preview: 4096-character ASCII text,
  a 32.3 MB response and a server peak (`VmHWM`) of about 331 MB; 1024 four-byte (emoji) characters, 51.3 MB and
  about 464 MB; 4096 control characters, each escaped by JSON to six bytes, 105.0 MB and about 779 MB. With 200
  grants of ASCII text: 6.47 MB and about 154 MB. The same measurement with the former 512-character preview gave
  76.7 MB and about 716 MB (ASCII) and 371.1 MB and about 2.4 GB (control characters). For the three 1000-grant
  cases the peak was about 7 to 10 times the response, baseline included (the 200-grant case, which is mostly
  baseline, was about 24 times), allocator dependent. The 64-character cases were run three times each, in fresh
  processes, with peaks within about 1 percent of each other; the 512-character comparison is one run per case.
  They are measurements on one host, not a guarantee. About 50 MB more would be added by reviewer ids of about
  520 bytes (an estimate, not measured). The response is built whole in memory (the store result, the view
  structures, the JSON builders and the serialised body are live together), the route has no concurrency limit
  of its own, so each request in flight holds its own copies, and the MCP twin puts its payload in the result twice
  (2.04 to 2.16 times the REST body; at 1000 grants of 100 decisions each the peak memory is about 1.3 to 1.5 times
  the REST peak, about 453 MB against 323 MB and 1.09 GB against 0.75 GB, and about 1.14 times at 200 grants;
  fresh processes, three runs for each MCP figure and one for each REST figure in the comparison, VmHWM divided by
  1024). The Access page fragment peaks at about 195 MB for 1000 grants with 100 decisions each (about 255 MB with
  four-byte characters; it renders at most 1000 grants), a 27 to 46 MB body; the browser's own cost for it was not
  measured. No
  shipped deployment configuration sets a memory limit and the only shipped server-restart alert is
  `YuzuServerRestartLoop`; the sizing advice, the scaled break-even and the existing `yuzu_server_memory_bytes{type="rss"}` metric are in
  `docs/auth-architecture.md`, "The decision history". The full
  text of a superseded entry stays in the database and is not returned; an assessor obtains it with
  a database read of `access_review_store.access_review_attestation_history` (queries and caveats: "Obtaining the full
  justification of a superseded decision" in `docs/auth-architecture.md`). A success answers `{recorded, decision_seq, previous_decision}`.
- Audit shape: `target_id` is the campaign id alone and the grant is in `detail`, for every
  outcome that reaches the gate or the store (the refusal of an engine session and the
  unsupported-media-type refusal carry an empty `target_id`). Audit rows written before this
  build keep the old target shape (`<campaign>:<type>:<id>:<role>`), so archives hold both. A
  store fault that is not the caller's writes a `failure` row with a fixed message, not database
  text (the raw error goes to the server log). A refusal is `result=denied` with `sod_self_subject`, `sod_engine_owner` or
  `sod_group_member`; an unanswerable check is `result=failure` with `sod_check_unavailable
  store=engine|rbac`; a success carries `decision= previous= seq= sod=pass`. The metric
  `yuzu_access_review_attestation_refused_total{surface,reason}` covers both surfaces.

**Residuals, stated as limits.**

1. The engine-owner and group-member rules are a read before the write transaction (the store
   contract forbids a store consulting another store while it holds a lease). A change that lands
   between the read and the commit is not seen, and nothing re-reads after the commit. The user
   rule is decided in C++ from the arguments before any lease and has no such window. Revisit
   under epic #6060. Separately, both reads see the state at the moment of the attest: engine
   ownership is a live read, but group membership is read from Yuzu's stored membership, which an
   identity provider updates only when that member signs in. A change at the identity provider is
   not seen until that member next signs in interactively (a long-lived API or MCP token can
   outlast it), and a token that skips the
   membership refresh (for example Entra groups-overage) is not refreshed. For
   identity-provider-governed groups the rule is therefore not a current-membership check; a
   review of those groups at the identity provider at campaign close is the compensating step.
   An owner who transferred an engine, or a member who left a group, before attesting is
   admitted. For engine and group grants the history row does not record the ownership or
   membership basis: independence is evidenced by the `sod=pass` audit row (set-and-proceed, kept
   for the audit retention period), so export audit rows to the evidence store within that
   period; if that row was not persisted (`audit_persisted:false` on MCP, `Sec-Audit-Failed` on
   REST), treat that grant's independence as unevidenced. Recording the basis in the history
   row is tracked under #6060.
2. The history is append-only against the application path and ordinary SQL (triggers, `RESTRICT`
   keys and a deferred consistency check), not against the application's database credential, a
   role granted TRUNCATE, or a database administrator. A data-only restore into a migrated schema
   is refused; restore schema and data together. On these tables the owner can also run `DISABLE TRIGGER USER`
   (`DISABLE TRIGGER ALL` is refused to a non-superuser), drop a trigger, replace the guard function and `DROP TABLE`; nothing in Yuzu records either, or a
   `TRUNCATE`, so detection is database statement logging (`pgaudit` classes `ddl` and `write`, or `log_statement = mod`;
   `ddl` alone does not log a `TRUNCATE`) plus reconciling each grant's `decision_seq` with its history row count and
   the audit rows' `seq`; the reconciliation does not depend on logging. The audit rows are evidence independent of these tables,
   not of the database credential: the audit store is in the same database and has no guard triggers, so they are
   independent of it only to the extent audit rows are exported off the database. A closed campaign and its history
   persist indefinitely while audit rows are kept for the audit retention period (365 days by default), so after
   that period the campaign tables are the only on-database record unless the audit rows were exported. The authorised
   redaction procedure below also disables the triggers, and Yuzu does not audit it. The guard triggers protect the frozen grants, the decisions and the
   history; the campaign row (status, `closed_at_ms`, `closed_by`, title) is protected by the
   application only, which refuses further decisions on a closed campaign, so a database
   credential holder can reopen a closed campaign. Personal-data redaction has no application
   path. It is a database-administrator procedure that must cover the state row's latest reviewer
   and justification, the history rows, the subject id (part of a primary key and of a restricted
   foreign key, so redacting key columns is not feasible without rewriting keys and the frozen
   snapshot), the frozen `grant_snapshot` of each grant (it holds `display_name` and
   `owner_or_email`, an email address for a user; the state row's guard trigger pins it as
   immutable, so redacting it needs that trigger disabled too), the campaign's `title` (free
   text), `created_by` and `closed_by`, and the audit rows (kept for the audit retention period); "re-verify" means checking that the guard triggers are enabled again and
   that the consistency trigger holds. The procedure has not been exercised.
3. A person with two identities (a local account and an SSO identity) counts as two reviewers (the
   accepted exception in `docs/enterprise-readiness-soc2-first-customer.md`).
4. Every attestation audit row records the grant through the audit token filter, which folds
   spaces and a few separators, so two grants whose ids fold to the same audit text cannot be
   told apart in a row; this applies to success rows as well as refusal rows. `seq` numbers the
   decisions of one grant, so with the campaign id and the grant it identifies one history entry,
   subject to that folding.
5. The decision is committed before its audit row is written, and a failed audit write never undoes
   it. After a dropped connection the outcome of an attestation can be unknown: read the campaign
   and compare `decision_seq` before retrying; a retry appends an identical decision until the
   grant reaches its limit of 100 decisions, after which the request is refused. A
   superseded entry is returned truncated (and an earlier history entry shows at most its first 64
   characters), so match an earlier entry on those.
6. Under a continuous stream of attestations a `close` can wait up to the pool's lock timeout and
   answer `503`; retry it.
7. **Recorded residual and options under consideration (memory use of the history read).** The project owner
   ruled on 2026-11-04 to cut the preview of a superseded entry to 64 characters as the immediate response to the
   measured memory use of the history read (about 2.4 GB for the worst measured case with the former 512-character
   preview). The project owner also accepted the remaining exposure on 2026-11-04 at the measured figures. It is a recorded residual: there is no per-campaign budget, no cap on the number of
   frozen grants, no concurrency limit on the route and no shipped memory limit, so the response and its memory still
   grow linearly with the number of frozen grants and with the number of requests in flight (the scaled break-even is
   in `docs/auth-architecture.md`, "The decision history", and is not measured). The structural options under
   consideration are a per-grant history read (the campaign `GET` returning only each grant's latest decision), a
   streamed or paged response, a per-campaign budget and a concurrency cap on heavy reads. None is decided and none is
   scheduled by this record.

**Deployment.** A database that holds a `user` grant decided by the account it names makes the
server refuse to start (the schema v3 migration fails and the store does not open), on every boot,
until the database is replaced. Only that case is detected: decisions on engine or group grants
made by earlier builds are not checked and read as "previous: not recorded". This is the hard-cutover posture in `docs/user-manual/upgrading.md`
("Deployment contract (hard cutover)"): fresh database only.
