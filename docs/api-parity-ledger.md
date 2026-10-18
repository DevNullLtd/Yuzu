# API parity ledger

**What this is.** ADR-0031 INV-31-4
(`docs/adr/0031-presentation-core-engine-decomposition.md`) requires that
every capability the dashboard exposes is also reachable through the
versioned REST API - "there is no private core API." Per ADR-1005, the same
capability should also be reachable via MCP. Nobody has ever verified this
mechanically: `openapi_spec()` (`server/core/src/rest_api_v1.cpp`) is a
hand-typed literal whose own source comment admits it "is NOT generated from
the live route table and can under-report a route that exists." This ledger
+ `scripts/ci/check-api-parity.py` is the machine-checked backstop the ADR
calls "a deliverable of migration step 3" - and the foundation (#3991, "F1")
of the ~36-PR #2146 programme closing the gap the rest of this table
quantifies.

**How to read the table below.** One row per **domain** (a
`scripts/ci/api-parity/<domain>.json` file). Each domain file holds one row
per `/fragments/*` or unversioned legacy `/api/*` route registered anywhere
under `server/core/src/*.cpp`, keyed by `(method, canonical path)` - never
`file:line`, so moving a route between owner files (the concurrent
#2542/#2557 `HttpRouteSink` migration campaign is doing exactly that) never
churns the ledger. Each row records:

- `capability_id` - an id DERIVED from the method and path (it changes if a
  route is renamed, and the gate requires it to match).
- `rest_v1_twin` - the `/api/vN/*` route that serves the same capability, if
  one exists.
- `mcp_twin` - the MCP tool name that serves the same capability, if one
  exists.
- `status` - one of `twinned` (BOTH a REST v1 and an MCP twin exist and are
  verified against the current source; the `mcp_twin` is a tool name, or
  `resource:<uri>` for a fixed `kResources[]` entry; the gate cannot verify a
  resource-template twin yet, so such a row is ledgered `twinned-rest-only`,
  which overstates the gap relative to ADR-1005's 2026-09-14 addendum until
  the gate can verify templates - a temporary limitation, not a rule),
  `twinned-rest-only` / `twinned-mcp-only` (exactly one machine twin exists;
  counts as untwinned, because ADR-1005 expects both; for a NEW one-sided
  row, name the tracker for the missing side in an issue or an ADR-1005
  entry - the eight existing ones are tracked by #5963), `planned:#N` (tracked, not yet built -
  `#2146` is the generic placeholder used when no more specific tracking
  issue exists yet, and its row count may only shrink),
  `composed-of:<capability-ids>` (this row's capability is covered by the
  union of other ledgered capabilities, not a 1:1 twin),
  `exception:#<issue> revisit:<YYYY-MM-DD> <reason>` (a deliberate, reviewed
  exception with a tracking issue and a revisit date - an ADR-1005 ledger
  entry, not a free pass; the `<issue>` may be the originating or decision
  issue and need not be open, e.g. #520 and #2102 are closed as of
  2026-10-17; a few rows with no machine-checked dated revisit are
  grandfathered by `capability_id` in a size-pinned set in the script, named
  in ADR-1005's 2026-10-15 entry - extending it, swapping an id or rebinding
  an id to another row is caught only in review), or `retire` (the
  fragment route no longer exists; kept for history until the ledger row
  itself is deleted).

One further row shape exists (#5342): a row keyed on a registered
`/api/v1/*` route, legal ONLY with an `exception:` status. It records a
REST v1 capability that deliberately has no MCP twin - ADR-1005 expects one
by default, so the reviewed reason lives here instead of being implicit.
The two password routes (`POST /api/v1/users/me/password`,
`POST /api/v1/users/{name}/password`) are the first such rows (in
`scripts/ci/api-parity/rbac.json`): the self-service change is excluded
permanently (an MCP caller is a token, not the human), and the admin reset is
deferred to #5357, an MCP tool that takes no password argument (a
server-generated temporary password) because an approval ticket would store
and display one. Both are also recorded in ADR-1005's exception ledger
(`docs/adr/1005-headless-platform-use-case-engines.md`, "Grandfathered
surfaces" item 3). Every other v1 route stays out of the
ledger and is held to the OpenAPI check instead.

**What populated this first PR.** Every row was extracted mechanically by
`check-api-parity.py`'s lexical scanner (verified self-consistent against
this session's fresh measurement, AT THAT TIME: 173 registered `/api/v1/*`
routes, 133 OpenAPI path+method entries, 91 MCP tools, 278 fragment/legacy
routes, 40 routes registered but undocumented in OpenAPI - all seeded into
this PR's `ALLOWLIST_OPENAPI_MISSING`). Those OpenAPI/allowlist counts are
historical - #3992 backfilled 39 of the 40 shortly after, and this branch's
own allowlist was reconciled to match (commit `3871688f6`); do not hand-edit
this paragraph's numbers again to "fix" them, since they will drift the
same way on the next such change - the summary table below is the
generated, self-updating source of current counts. An initial version of the extractor matched
only dot-notation verb calls (`receiver.Get(...)`) and missed the ~107
arrow-notation registrations `server.cpp` makes directly on `web_server_`
(`web_server_->Get(...)`, the same false-negative class `docs/architecture.md`
"Route Registration" already documents from #2542) - undercounting the
fragment/legacy universe by 76 routes (202 vs the true 278) until fixed in
this same PR before push; see that section for the receiver-agnostic
extraction pattern this scanner now uses. Most rows default to `status: "planned:#2146"`
per #3991's own scoping - this PR's job was to build the machine-checked
scaffolding honestly, not to hunt down a precise tracking issue or verify
every capability's twin status by hand. **13 rows were hand-verified against
source** (the handler code, a same-store call, or an explicit "REST
sibling"/"mirrors POST ..." comment) and marked `twinned` - see the git
history of `scripts/ci/api-parity/*.json` for which, and `check-api-parity.py`'s
module docstring for the mechanical checks every other row is still held to.
The follow-on programme (#2146) files precise per-domain issues from the
`planned:#2146` rows this ledger now makes enumerable for the first time.

**What this is not.** A proof. `check-api-parity.py`'s own docstring says so
directly: it is a **lexical tripwire** (regex extraction, not a C++ parser),
the same general regex-extraction-plus-ratchet-baseline technique issue
#2557's in-progress inline-route gate uses for a different question
(inline-vs-sink route registration style, not REST/MCP/OpenAPI/fragment
parity) - as of this writing that gate lives only on the unmerged
`ci/inline-route-gate` branch, not `dev`, so treat it as a sibling *design*,
not a shipped file to depend on. A fully
general version needs a type-aware/clang-based approach - see #2572. This
ledger and its gate are also a deliberate **stopgap**: ADR-0032 interlock
(j) / issue #2678 will eventually generate the capability projection this
script hand-extracts today, and when that lands this ledger becomes (or is
superseded by) the diff harness comparing the generated projection against
the served surface - it does not compete with that work.

**Keeping it honest.** `scripts/ci/check-api-parity.py` runs as a CI
preflight step (no build required - pure source-tree lexical analysis) and
fails on: an extracted `/fragments/*` or legacy `/api/*` route with no
ledger row; a ledger row still claiming a route that no longer exists
(other than `status: "retire"`); a `twinned` row that lacks either twin, or a
`twinned*` row whose claimed REST or MCP twin does not actually exist in the
current extraction (a `resource:<uri>` twin must be a registered MCP
resource; an object-form `rest_v1_twin` is verified on a row of any
status); a duplicate `capability_id`; an `exception:` row without an issue,
a real revisit date and a reason (outside the grandfathered set); a
`capability_id` that is not the one derived from the row's method and path; a
grandfathered set whose size is not its pinned maximum, or that holds a stale
entry (a row gone, converted, or already in the strict shape - an extension
paired with a maximum raise, a swap of one id for another and a rebind keep
the size and are caught only in review); a registered
`/api/v1/*` route missing from OpenAPI and not in the allowlist; the total
untwinned-row count, or the generic `planned:#2146` row count, moving off its
own baseline recorded in the script (the generic count never rises; the
untwinned baseline shrinks as F2+ wires real twins, and rises only when a
change raises it with a stated reviewed reason - a newly-discovered fragment
route, or extraction-completeness catching up to a route that already
existed); and this document's generated block going stale relative to a
fresh render. Review-only, never checked by the gate: an issue's existence,
state or content; a revisit date having passed (dates are shape- and
window-checked, 2026-01-01..2028-12-31, but never lapse-checked); a
`twinned-rest-only` row silently becoming a dated exception; extending the
grandfather set together with its maximum, swapping an id, or rebinding an id
to a row with the same slug. Adding a NEW exception row is not mechanically
capped: it needs a maintainer ruling and shows in review. Twelve single-twin
rows were examined when the gate began requiring both twins on plain
`twinned`: eleven were reclassified (eight `twinned-rest-only`, three
`exception:#520`) and one, satisfied by an MCP resource twin, stays
`twinned`, moving the untwinned baseline from 216 to 227 without changing any
capability. See
`tests/unit/server/test_openapi_spec_completeness.cpp` for the in-process
unit-test half (RestApiV1's own `register_routes()` vs `openapi_spec()`,
plus `$ref` validity) - the #842 companion to this whole-tree script.

**REST-only exports (deliberate).** The software catalogue's exports - `format=csv` on
`GET /api/v1/inventory/software/catalogue` and `format=csv|json` on
`GET /api/v1/inventory/software` - have no MCP tool. An agent reads the same data page by page
through the cursor on `query_software_catalogue` / `query_installed_software`; a bulk file
download is a human/automation convenience, so the ledger rows for those routes are `twinned` on
the paged shape and the export mode is recorded here rather than as a separate row. Tracked by `#5699` (revisit by 2026-11-07); the exception is recorded in `docs/adr/1005-headless-platform-use-case-engines.md`.

**Known asymmetry on the raw-route pair.** The `q`, `kind`, `ecosystem` and `source` filters of
`GET /api/v1/inventory/software` are REST-only: `query_installed_software` takes `name`, `agent_id`,
`version`, `limit` and `cursor` only (an unknown argument name is ignored, as on the other read tools; only approval-gated tools validate argument names at dispatch). The row
stays `twinned` on the paged shape; the gap is recorded here so it is not silent. Tracked by `#5699` (revisit by 2026-11-07), with the same ADR-1005 exception entry.

**Known asymmetry on the audit pair.** `GET /api/v1/audit` and `query_audit_log` share one row set, but the MCP tool also publishes `has_more` and refuses a string filter over 1024 characters; the REST route does neither (a short page is its last page, and its filters are unbounded). The row stays `twinned`; the gap is recorded here and tracked by `#5887` (revisit by 2026-11-15).

**Known asymmetry on the dashboard API-token pair.** `POST /api/settings/api-tokens` and `DELETE /api/settings/api-tokens/{id}` apply the same permission, MFA step-up, store-availability, tier/TTL and ownership rules as `POST /api/v1/tokens` and `DELETE /api/v1/tokens/{id}`. They differ in being narrower or in shape: the form has no `scope_service` (no service-scoped minting) and takes `ttl_hours` where the REST route takes `expires_at`; its audit rows are written through `AuditStore::log` and carry no user-agent, principal-class or session-id stamp; and MCP `create_api_token` has no step-up, by design (an MCP-tier token is required, with approval at the supervised tier). The rows stay `twinned`. The Settings page cannot yet prompt for the step-up code, so an MFA-enrolled operator whose proof has expired is refused without feedback and must re-authenticate.

**Known asymmetry on the discovered-devices pair.** The legacy `GET /api/discovery/results` row is
`twinned` to `GET /api/v1/network/discovered-devices` / `list_discovered_devices`, but the raw route is
not retired and is not equivalent: it is unbounded (no `limit`, no `truncated`), returns the
`managed` and `agent_id` columns (the new twin deliberately omits them: nothing maintains the
flag yet), uses the `{devices,total}` shape, writes no `network.discovered.view` audit row and has
no explicit service-scoped denial of its own (it relies on the `Infrastructure:Read` gate). The
bounded, audited twin is the supported read for agents and integrations; hardening or retiring the
raw route is tracked by `#5856` (revisit by 2026-11-14).

## Summary

<!-- BEGIN GENERATED: check-api-parity.py - do not hand-edit; regenerate with `python3 scripts/ci/check-api-parity.py --render-doc` and splice between these markers -->

| Domain | Rows | Twinned | Untwinned |
|---|---:|---:|---:|
| devices | 21 | 8 | 13 |
| inventory | 4 | 4 | 0 |
| dex | 27 | 18 | 9 |
| guardian | 18 | 8 | 10 |
| tar | 12 | 3 | 9 |
| auto-preflight | 4 | 1 | 3 |
| auto-deploy | 6 | 3 | 3 |
| auto-verify | 3 | 0 | 3 |
| network | 3 | 2 | 1 |
| viz | 2 | 2 | 0 |
| executions | 6 | 0 | 6 |
| scope-result-sets | 1 | 0 | 1 |
| instructions | 27 | 14 | 13 |
| compliance-policy | 22 | 5 | 17 |
| settings | 26 | 7 | 19 |
| rbac | 13 | 2 | 11 |
| auth-mfa | 7 | 0 | 7 |
| engine-principals | 3 | 0 | 3 |
| access-reviews | 5 | 3 | 2 |
| ca-pki | 3 | 2 | 1 |
| ota | 15 | 1 | 14 |
| enrollment | 21 | 4 | 17 |
| other | 82 | 17 | 65 |
| **Total** | **331** | **104** | **227** |

Registered `/api/vN/*` routes: 251. OpenAPI `paths` entries: 250. Missing from OpenAPI: 1 (1 carried in `check-api-parity.py`'s `ALLOWLIST_OPENAPI_MISSING` pending F2, 0 unallowlisted). MCP tools: 191.

Ratchet baseline (untwinned rows; shrinks as routes are twinned, or rises only with a reviewed reason stated in the change that raises it): 227. Generic `planned:#2146` placeholder baseline (shrinks only; a new row names a specific issue): 176.

<!-- END GENERATED -->

## See also

- `docs/adr/0031-presentation-core-engine-decomposition.md` - INV-31-4, the
  invariant this ledger enforces.
- `docs/adr-1005-execution-plan.md` - the programme this PR (#3991, F1) is
  Phase 0 of; #2146 tracks the full ~36-PR closure plan.
- `docs/adr/0032-*.md` interlock (j) / issue #2678 - the generated-projection
  work this ledger is a stopgap for.
- `scripts/ci/check-capability-matrix.sh` - the ratchet-gate shape this
  script's baseline/allowlist mechanics are modeled on.
- Issue #2557's in-progress inline-route gate (unmerged `ci/inline-route-gate`
  branch, not yet on `dev`) - sibling lexical-gate design (different
  question, same general technique), owned by the concurrent #2542/#2557
  `HttpRouteSink` migration campaign.
- `docs/architecture.md` "Route Registration" - the receiver-agnostic
  `(\.|->)` extraction pattern this scanner uses, and the #2542 false
  negative it exists to avoid repeating.
