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

- `capability_id` - a stable slug for the underlying capability.
- `rest_v1_twin` - the `/api/v1/*` route that serves the same capability, if
  one exists.
- `mcp_twin` - the MCP tool name that serves the same capability, if one
  exists.
- `status` - one of `twinned` (a twin exists and is verified against the
  current source), `planned:#N` (tracked, not yet built - `#2146` is the
  generic placeholder used when no more specific tracking issue exists
  yet), `composed-of:<capability-ids>` (this row's capability is covered by
  the union of other ledgered capabilities, not a 1:1 twin),
  `exception:<note>` (a deliberate, reviewed reason this row will never get
  a twin - an ADR-1005 ledger entry, not a free pass), or `retire` (the
  fragment route no longer exists; kept for history until the ledger row
  itself is deleted).

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
(other than `status: "retire"`); a `twinned` row whose claimed REST or MCP
twin does not actually exist in the current extraction; a registered
`/api/v1/*` route missing from OpenAPI and not in the allowlist; the total
untwinned-row count growing past the baseline recorded in the script (the
baseline shrinks as F2+ wires real twins, and rises only when a change
raises it with a stated reviewed reason - a newly-discovered fragment route,
or extraction-completeness catching up to a route that already existed); and this
document's generated block going stale relative to a fresh render. See
`tests/unit/server/test_openapi_spec_completeness.cpp` for the in-process
unit-test half (RestApiV1's own `register_routes()` vs `openapi_spec()`,
plus `$ref` validity) - the #842 companion to this whole-tree script.

## Summary

<!-- BEGIN GENERATED: check-api-parity.py - do not hand-edit; regenerate with `python3 scripts/ci/check-api-parity.py --render-doc` and splice between these markers -->

| Domain | Rows | Twinned | Untwinned |
|---|---:|---:|---:|
| devices | 14 | 9 | 5 |
| inventory | 7 | 1 | 6 |
| dex | 26 | 18 | 8 |
| guardian | 16 | 6 | 10 |
| tar | 12 | 4 | 8 |
| auto-preflight | 4 | 1 | 3 |
| auto-deploy | 4 | 1 | 3 |
| auto-verify | 3 | 0 | 3 |
| network | 2 | 1 | 1 |
| viz | 2 | 2 | 0 |
| executions | 6 | 1 | 5 |
| scope-result-sets | 1 | 0 | 1 |
| instructions | 24 | 11 | 13 |
| compliance-policy | 19 | 6 | 13 |
| settings | 15 | 0 | 15 |
| rbac | 8 | 0 | 8 |
| auth-mfa | 7 | 0 | 7 |
| engine-principals | 1 | 0 | 1 |
| access-reviews | 2 | 0 | 2 |
| ca-pki | 3 | 2 | 1 |
| ota | 15 | 0 | 15 |
| enrollment | 19 | 5 | 14 |
| other | 74 | 13 | 61 |
| **Total** | **284** | **81** | **203** |

Registered `/api/vN/*` routes: 239. OpenAPI `paths` entries: 238. Missing from OpenAPI: 1 (1 carried in `check-api-parity.py`'s `ALLOWLIST_OPENAPI_MISSING` pending F2, 0 unallowlisted). MCP tools: 181.

Ratchet baseline (untwinned rows; shrinks as routes are twinned, or rises only with a reviewed reason stated in the change that raises it): 203.

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
