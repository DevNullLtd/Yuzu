#!/usr/bin/env python3
"""check-api-parity.py - F1 ledger conformance gate for the ADR-0031/#2146
REST/MCP/dashboard parity programme (issue #3991).

ADR-0031 INV-31-4 requires that every capability the dashboard exposes is
also reachable through the versioned REST API (and, per ADR-1005, through
MCP). Nobody has ever verified this mechanically: `openapi_spec()`
(server/core/src/rest_api_v1.cpp) is a hand-typed literal that the file's
own comment admits can under-report the live route table. This script is
the machine-checked backstop `docs/adr/0031-presentation-core-engine-
decomposition.md` calls "a deliverable of migration step 3" (INV-31-4) and
the unit-test half's sibling - `tests/unit/server/
test_openapi_spec_completeness.cpp` covers the in-process half for
`rest_api_v1.cpp` alone; this script is the exhaustive, whole-tree half.

WHAT THIS IS: a LEXICAL TRIPWIRE, NOT A PROOF. It regex-extracts route
registrations, the OpenAPI literal, and the MCP tool table as plain text -
it does not parse C++ and cannot see through indirection (a route
registered via a helper function that itself calls `sink.Get(...)`, a path
built from a runtime variable, a tool added through anything other than a
`kTools[]` array literal). A fully general version needs a type-aware /
clang-based approach - see #2572, which is the type-aware successor to the
sibling `scripts/ci/check-inline-route-registrations.py` lexical gate this
script's technique is modeled on (same general approach - regex extraction
+ a monotonic ratchet baseline - applied to a different question: REST/MCP/
OpenAPI/fragment parity, not inline-vs-sink route registration style).

FUTURE HOME: this ledger + gate is a deliberate STOPGAP. ADR-0032 interlock
(j) / issue #2678 will eventually generate the capability projection this
script hand-extracts; when that lands, this script becomes (or is replaced
by) the diff harness that compares the generated projection against the
served surface, rather than parsing source text by hand. Nothing here
competes with that work - see docs/api-parity-ledger.md's prose header.

WHAT IT CHECKS
  1. Every `/fragments/*` or unversioned `/api/*` route registered anywhere
     under server/core/src/*.cpp has a corresponding row in exactly one
     scripts/ci/api-parity/<domain>.json ledger file, keyed by (method,
     canonical path - see `canonicalize()`).
  1b. A ledger row keyed on a route that is not a registered fragment/
     legacy route is either status "retire" (stale), OR - the ONE other
     legal shape (#5342) - a registered `/api/v1/*` route ledgered with an
     `exception:` status: a REST v1 capability that deliberately has NO MCP
     twin (ADR-1005 requires one by default, so the reviewed reason is
     recorded here rather than left implicit). A v1-keyed row with any other
     status is an error - v1 routes are otherwise tracked by check 3, not
     the ledger.
  2. Every ledger row whose status is "twinned" names BOTH a `rest_v1_twin`
     and an `mcp_twin`; a row with only one uses "twinned-rest-only" /
     "twinned-mcp-only". An `mcp_twin` is a tool name, or `resource:<uri>`
     for a fixed kResources[] entry. Every named twin, and an object-form
     `rest_v1_twin` on a row of ANY status, must actually exist in
     the CURRENT extraction (a twin claim referencing a renamed/removed
     route, tool or resource is a lie, and this catches it going stale).
  2b. Every `composed-of:` row names capability ids that exist in the ledger.
  2c. An `exception:` status must read `exception:#<issue> revisit:<YYYY-MM-DD>
     <reason>`, except the grandfather set GRANDFATHERED_LEGACY_EXCEPTIONS.
     The set is size-pinned against GRANDFATHERED_MAX and each id must still
     be a free-form exception row; extending it (+1 id and +1 MAX together),
     swapping an id or rebinding is caught only in review. capability_ids are
     unique and equal the id derived from method and path, and a malformed
     ledger is reported alone.
  2d. Every strict-shaped exception row is pinned in STRICT_EXCEPTION_PINS by
     capability_id to its exact (issue, revisit date), and every pin must
     still name a strict row: a new, relabelled, re-dated, twinned or retired
     exception forces a visible edit to that table. The pin binds the id,
     issue and date, not the reason text (a different route changes the
     derived id, so its pin goes stale unless the new id collides). A
     revisit date at or before today + REVISIT_WARN_DAYS is ONE aggregated
     ::warning::, never a failure.
  2e. The kTools[] and kResources[] slices must contain no preprocessor line
     (a named error: the scan does not model conditional compilation).
     KNOWN LIMITS of these text scans (they are a fast pre-check, not a C++
     parser): kTools[] is not comment-stripped, so an entry wrapped in a block
     comment still counts as a tool, and a line inside a raw-string schema that
     starts with `#` is refused; kResources[] does not recognise char literals.
     None of these occurs in the tree today. Closing them needs a check against
     the compiled catalogue (the tool and resource names the server registers),
     which this script does not do.
     The MCP tool set is the UNION of the kTools[] slice and, in each
     `mcp_tools_*.cpp` under MCP_REGISTRY_DIR, the slice from the literal
     `constexpr ToolRecord kToolRecords[] = {` to the next `\n};` (a tool served
     from the registry seam is not in kTools[]). Same lexical scan, same
     preprocessor refusal, same entry pattern. A registry file with no anchor,
     a second anchor, zero entries, fewer than MIN_REGISTRY_FILES files, or a
     name already seen (in kTools[] or another file) is a named error.
  3. Every registered `/api/v1/*` route either appears in the OpenAPI
     `paths` table (openapi_spec() in rest_api_v1.cpp) or is named in this
     script's ALLOWLIST_OPENAPI_MISSING with a reason. F2's job is to
     shrink that allowlist to zero, not to add to it.
  4. The RATCHET: the total count of ledger rows whose status is not
     "twinned" ("untwinned") must not exceed BASELINE_UNTWINNED below. Like
     check-capability-matrix.sh's ratchet, this is BIDIRECTIONAL - an
     improvement (count decreases) must lower the constant in the same
     change, or a later regression back up to the old baseline would pass
     silently. The count of rows carrying exactly the generic `planned:#2146`
     status has its own bidirectional baseline, BASELINE_GENERIC_PLANNED.

USAGE
  check-api-parity.py                    # run the full gate (CI mode)
  check-api-parity.py --dump-json        # dump raw extraction as JSON (debug)
  check-api-parity.py --bootstrap        # add default rows for any
                                          # unledgered fragment/legacy route
                                          # (planned:#2146, both twins null)
                                          # to the right domain file. The gate
                                          # no longer lets planned:#2146 grow:
                                          # retag each new row with a specific
                                          # planned:#N or a strict exception
  check-api-parity.py --baseline-inventory
                                          # print current vs baseline counts
                                          # without failing on a ratchet
                                          # mismatch (exit 1 if the ledger is
                                          # malformed) - use when preparing
                                          # to lower a baseline
"""
import argparse
import datetime
import json
import os
import re
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVER_SRC = ROOT / "server" / "core" / "src"
LEDGER_DIR = ROOT / "scripts" / "ci" / "api-parity"
REST_API_V1_CPP = SERVER_SRC / "rest_api_v1.cpp"
MCP_SERVER_CPP = SERVER_SRC / "mcp_server.cpp"
# Per-domain tool records (`mcp_tools_*.cpp`, each holding one `kToolRecords[]`): a tool served
# from the registry seam is absent from kTools[]. Its own constant, so a selftest that patches
# only MCP_SERVER_CPP can still isolate the registry scan.
MCP_REGISTRY_DIR = SERVER_SRC
# The floor on registry files read: deleting every registry file would silently drop its tools
# from the catalogue this script reads, so it fails loudly instead. Raise it as domains land.
MIN_REGISTRY_FILES = 1
LEDGER_DOC = ROOT / "docs" / "api-parity-ledger.md"

DOC_BEGIN = ("<!-- BEGIN GENERATED: check-api-parity.py - do not hand-edit; "
             "regenerate with `python3 scripts/ci/check-api-parity.py "
             "--render-doc` and splice between these markers -->")
DOC_END = "<!-- END GENERATED -->"

VERBS = ("Get", "Post", "Put", "Delete", "Patch", "Options")

# ── RATCHET BASELINE ─────────────────────────────────────────────────────
# Total ledger rows (across every scripts/ci/api-parity/*.json file) whose
# status is NOT EXACTLY "twinned" - i.e. every "planned:#N", "exception:...",
# "composed-of:...", and "retire" row counts as untwinned. This baseline
# therefore has a floor above zero for as long as any row legitimately
# carries one of those non-"twinned" statuses (a `composed-of` or
# `exception` row is never expected to flip to "twinned" - it is a
# deliberate, reviewed classification, not a backlog item) - "0 untwinned"
# is not this gate's success criterion, "no regression from the reviewed
# baseline" is. May SHRINK as F2+ wires real REST/MCP twins and flips
# `planned` rows to "twinned". May also GROW, but ONLY for a reviewed reason
# stated in the same change that raises it - either a genuinely new route
# just registered, or (as in the #3991 fix that took this from 189 to 265)
# extraction-completeness catching up to a route that already existed but
# was previously invisible to the lexical scan; growth from a silent
# regression in the check itself is never legitimate. Lower (or, with a
# stated reason, raise) this in the SAME change that changes the real count -
# see check-capability-matrix.sh's CDX-P2-006 comment for why an un-adjusted
# baseline is not a real ratchet.
#
# #4035 (DEX read-twin batch, #2146 API-parity Batch A) flips most of the
# dex domain's rows from "planned:#2146" to "twinned" (2 device-status
# tools plus 8 genuinely-new REST+MCP twins), on top of origin/dev's own
# already-merged #4027/#4028/#4029/#4030/#4031/#4033/#4034 twins (237) --
# reconciled post-merge against the actual measured count below, not
# hand-added from either side's stale pre-merge value.
#
# #4036 (preflight/deploy read-twin batch) flips 2 more rows to "twinned"
# on top of origin/dev's 221 -- reconciled post-merge against the actual
# measured count, not hand-added.
#
# #4037 (api-parity #2146 Batch A): six guardian.json rows flip to "twinned"
# (get.fragments-device-guardian, get.fragments-guardian-events, get.fragments-
# guardian-guard-form, get.fragments-guardian-guard-param-page, get.fragments-
# guardian-guards, get.fragments-guardian-status) on top of origin/dev's 219 --
# reconciled post-merge against the actual measured count, not hand-added.
#
# #2146 Batch B2: seven rows flip to "twinned" -- post.api-scope-validate
# (mcp_twin: validate_scope) and six result-set fragment rows (mcp_twin:
# list_result_sets/create_result_set/get_result_set/delete_result_set/
# pin_result_set/unpin_result_set) -- on top of the prior 213, measured after
# the flip, not hand-added.
#
# feat/hardware-ci-view (governance Gate 3): +5 unledgered fragment routes
# bootstrapped (get.fragments-hardware-{list,ci,ci/actions,ci/result},
# get.fragments-inventory-software-devices); 2 immediately wired to their real
# REST v1 twins and flipped to "twinned" (hardware-list -> GET /api/v1/hardware,
# hardware-ci -> GET /api/v1/hardware/{id}); the remaining 3 have no REST/MCP
# twin yet (hardware-ci/actions, hardware-ci/result -- same "planned:#2146"
# class as the pre-existing device-live/run and device-live/result rows they
# sit alongside; inventory-software-devices -- a fleet-wide software search
# fragment with no REST twin proposed yet) -- net +3 untwinned, 206 -> 209.
#
# #2146 A2-R1 (merged into dev's 209 by the #4581-region dev-catch-up merge):
# get.api-executions-param-children flipped planned:#2146 -> twinned (GET
# /api/v1/executions/{id}/children + MCP get_execution_children) -- value
# below reconciled post-merge against the actual measured count (208), not
# hand-picked from either side's stale pre-merge number (212 vs 209).
#
# #2146 A2-R2 (merged into dev's 208 as #4652): response-query REST v1 + MCP
# twins land, flipping three legacy rows in scripts/ci/api-parity/other.json
# (GET /api/responses/{param}, .../aggregate, .../export) to "twinned"
# against the new /api/v1/responses/{id}, .../aggregate, .../export routes
# + their MCP twins (query_responses, aggregate_responses; export has no
# MCP twin) -- measured post-build at 205 (208 - 3), not hand-picked.
#
# #2146 A2-R4 (this dev-catch-up merge, on top of dev's 205): approval-review
# REST v1/MCP parity flips 2 other.json rows to "twinned" (GET /api/approvals
# -> GET /api/v1/approvals + list_pending_approvals; GET
# /api/approvals/pending/count -> GET /api/v1/approvals/pending/count +
# get_pending_approval_count) -- measured post-build at 203 (205 - 2), not
# hand-picked.
#
# #5342 (local-account password change + admin reset): +2 rows, both
# `exception:` rows keyed on the new REST v1 routes POST /api/v1/users/me/
# password and POST /api/v1/users/{param}/password in rbac.json - the first
# use of the v1-exception shape check 1b now admits (a REST v1 capability
# with a deliberate, reviewed "no MCP twin" reason). They are genuinely new
# routes, never expected to flip to "twinned", so the count rises 203 -> 205
# by design rather than regressing.
#
# 2026-10-06 (legacy /inventory fragment removal): the four dead
# /fragments/inventory/{devices,device,find,find/results} rows are deleted along
# with their routes (two `planned:#2146`, two `composed-of:`), so the count
# falls 205 -> 201 -- the value the checker itself reported after the deletion.
#
# Software catalogue REST routes: get.fragments-inventory-software-versions
# flips "planned:#2146" -> "twinned" (GET /api/v1/inventory/software/catalogue/versions;
# MCP twin get_software_versions, added with the MCP twins) and the title-catalogue row
# get.fragments-inventory-software is repointed at GET /api/v1/inventory/software/catalogue
# (already "twinned", count unchanged). The catalogue route's format=csv titles export is REST-only by design: a CSV
# body is a download for a person or a pipeline, not a structured tool result (the JSON route
# is the structured surface; its MCP twin, query_software_catalogue, now exists, and the
# remaining exception is recorded under ADR-1005 as #5699).
# Measured post-flip at 204 (205 - 1), not hand-picked.
#
# Merge of the two changes above: 205 - 4 (legacy rows deleted) - 1 (versions row twinned)
# = 200, the value the checker itself reported on the merged tree.
#
# MCP twins + raw-route exports (the second PR of the software catalogue): the
# get.fragments-inventory-software-devices row flips "planned:#2146" -> "twinned" (GET
# /api/v1/inventory/software + MCP query_installed_software, which gains version/cursor/source);
# the title-catalogue row gains its MCP twin query_software_catalogue and the versions row
# get_software_versions (both already "twinned", count unchanged). The raw route's
# format=csv|json export is REST-only by design, like the catalogue's CSV: an agent pages the
# same data through the MCP cursor. Measured post-flip at 199 (200 - 1), not hand-picked.
# DEX Alerts tab (posture PR-E): GET /fragments/dex/alerts is "composed-of" the legacy
# settings fragment (+1, 199 -> 200); the fragment's three POSTs stay planned:#2146.
#
# System "General and appearance" page: two UI-only fragments, GET
# /fragments/settings/general-runtime (composed-of:get.api-config) and GET
# /fragments/settings/analytics-events (composed-of:get.api-analytics-recent). Each composes an
# existing JSON route that is itself `planned:#2146` with no REST v1 or MCP twin (the legacy
# runtime-config and analytics routes), so there is no twin to point at and each counts as
# untwinned. Reviewed: a fragment is UI, not a machine surface (ADR-1005 Decision 4), and the
# routes they compose are the ledgered gap.
#
# Compliance page, policy fragments list: the new GET /fragments/policy-fragments HTML view
# is a `composed-of:get.api-policy-fragments` row (the JSON list stays the twinned capability),
# which counts as untwinned by design, so the count rises 199 -> 200.
#
# Device containment fragments (es-1): get.fragments-hardware-quarantine is "twinned" to GET
# /api/v1/quarantine (no MCP list tool exists; the gap is recorded on the row), and
# get.fragments-hardware-ci-containment is "composed-of:get.fragments-hardware-quarantine"
# (a single-device read of the same active-record set; REST has no per-device GET). One
# composed-of row, so 200 -> 201, measured by the checker, not hand-picked.
#
# Stored data panel (es-1): get.fragments-hardware-ci-stored-data is an "exception:" row (the
# erase it fronts is DELETE /api/v1/sle/agents/{id}, which has no ledger row to compose), so
# 201 -> 202, measured by the checker, not hand-picked.
#
# The DEX Alerts and policy-fragments changes above landed on 199 and merged together to 201
# (199 + 1 + 1). The two containment rows above landed on that, so merged with them the count
# is 203 (201 + 1 composed-of + 1 exception), the value the checker reports on the merged tree.
#
# Hardware record properties panel (device data, merged from dev): GET /fragments/hardware/ci/properties
# is "planned:#2146" (its data routes, /api/agents/{id}/properties*, are dashboard-only with no REST v1
# or MCP twin), so it deepens an untwinned surface by one row. Merged with the containment rows above
# the count is 204 (203 + 1), the value the checker reports on the merged tree.
#
# Home page (HM-1, measured on its own base at 200 = 199 + 1): +1 `composed-of:` row,
# GET /fragments/home/summary (readout, needs attention) over the existing hardware roster,
# approvals count, executions and fleet-compliance reads; a UI fragment. NOT a rule that such a
# fragment owes no twin: ADR-1005 Decision 4 says a dashboard fragment is not an API twin. The
# four Dashboard rows below are an owner-accepted TEMPORARY exception (review of PR #5859,
# 2026-10-15), so the baseline stays raised until the estate partition, activity and health
# reads have REST v1 and MCP twins; the next reader should not take it as precedent.
# Home panels (HM-2, measured on its own base at 204 = 201 + 3): +3. The three Home fragments
# (/fragments/home/policies, /fragments/home/activity, /fragments/home/health) are UI-only
# compositions over existing twinned or planned reads, so each is a composed-of row that
# counts untwinned.
# Both Home changes landed on 201 on their own base. Merged with the dev changes above (204) the
# four Home/Dashboard rows bring the count to 208 (204 + 4), the value the checker reports on the
# merged tree.
# Design delta 2026-10-14: the four rows above moved with their panels to the Dashboard and
# are now /fragments/dashboard/{summary,policies,activity,health} (same composed-of status,
# same count; a rename, not a new surface), so the count stays 208.
#
# Estate deployment read twins: GET /fragments/auto/deployments and .../detail are new routes
# ledgered "twinned" (GET /api/v1/deployments[/{id}] + MCP list_deployments / get_deployment,
# count unchanged). The new GET /fragments/auto/nvd status card is ledgered "exception"
# (grandfathered NVD surface, no get_nvd_status MCP): +1. Merged on top of the 201 above, the
# checker reported 202 on the merged tree.
#
# Network discovery read twin (Estate E-2): the unbounded legacy GET /api/discovery/results
# row flips "planned:#2146" -> "twinned" (GET /api/v1/network/discovered-devices + MCP
# list_discovered_devices); the new GET /fragments/network/discovered row is born "twinned"
# (count unchanged): -1 on its own. Combined with the +1 above the checker reported 201 on the
# merged tree, not a hand-added delta.
#
# Landing on dev's 208 (device containment, hardware properties and the Home/Dashboard rows, above),
# the two Estate changes net 0 on their own (+1 NVD status card exception, -1 discovery row
# twinned), so the count after this merge is the value the checker reports, set from its output.
#
# The System General page (this branch) adds the two composed-of fragments described above
# (general-runtime, analytics-events): +2. Landing on dev's 207 (after the audit filter parity
# flip below), the count is 209, the value the checker reports on the merged tree.
#
# Audit filter parity: get.api-audit flips "planned:#2146" -> "twinned" (GET /api/v1/audit +
# MCP query_audit_log, now at filter/paging parity), the checker reports 208 - 1 = 207 on the merged tree
# (dev's 208 above, less this flip).
#
# Merged onto the Estate changes: the count is the value the checker reports on the merged
# tree, set from its output.
#
# Access Users page (#5880): re-surfaces the untwinned Settings users list as two read-only
# fragments, GET /fragments/access/users/list (planned:#2146) and .../detail (composed-of the
# list), +2. A GET /api/v1/users twin is not built here; the Settings rows and these two
# are retired together when that twin lands.
#
# Tokens and principals page (#5880): re-surfaces the untwinned Settings token and principal
# lists as three read-only fragments, GET /fragments/access/tokens/list, .../principals/list
# and .../principals/detail (each planned:#2146), +3. The token list is not a twin of the
# self-only GET /api/v1/tokens (an administrator on a cookie session sees every owner). The two
# principal fragments share GET /api/v1/engine-principals' EnginePrincipal:Read gate but add the
# page's roles/credentials composition and an audit-gated revocation detail, so they are not
# ledgered as twins here. Merged with the 207 above, the two Access pages make 212 (207 + 2 + 3),
# the value the checker reports on the merged tree, not hand-picked. The maintainer accepted
# these rows as a TEMPORARY UI-only exception on 2026-10-15 (see the #5955 note below).
#
# Access pages merged onto the Estate changes: the count is the value the checker reports on the
# merged tree, set from its output.
#
# System General and Data pages (#5873): re-surfaces the untwinned General runtime and analytics
# events settings as GET /fragments/settings/general-runtime and /fragments/settings/analytics-events,
# +2. Merged with the Access pages (212 above), the count is 214, the value the checker reports on the
# merged tree, not hand-picked. The maintainer accepted these rows as a TEMPORARY UI-only exception
# on 2026-10-15 (see the #5955 note below).
#
# Integrations page, webhook panel (System pages SYS-5, #5872): the two webhook fragments
# (GET /fragments/settings/webhooks and .../{id}/deliveries) are `composed-of:` the legacy /api/webhooks
# routes, which are themselves `planned:#2146` with no REST v1 or MCP twin yet, so they cannot be
# `twinned`: +2. Merged with the General and Access rows above (214), the count is 216, the value the
# checker reports on the merged tree, not hand-picked. The maintainer accepted these rows as a TEMPORARY
# UI-only exception on 2026-10-15 (see the #5955 note below). The twins that would remove it are tracked
# in #5885.
#
# #5955: the maintainer accepted the UI-only fragment rows of the Dashboard, Integrations webhooks,
# General and Access pages (PRs #5859, #5872, #5873, #5880) on 2026-10-15 as TEMPORARY exceptions,
# not a general waiver (a new UI-only capability needs its own ruling); those 13 rows now carry
# `exception:#5955 revisit:...`. Rows with exactly one machine twin are no longer plain `twinned`:
# they carry `twinned-rest-only` / `twinned-mcp-only` (or, for the deliberate #520 no-MCP
# decisions, `exception:#520 revisit:...`), which count untwinned. 11 rows were reclassified that
# way, so 216 -> 227, with no change in capability; a 12th (settings developer plugins) is
# satisfied by the `resource:yuzu://plugin-docs` MCP resource twin and stays `twinned`.
#
# Audit and reviews page: three fragments over existing reads. The log is `twinned` to
# GET /api/v1/audit + query_audit_log and moves nothing. The authentication sample is
# `twinned-rest-only` (GET /api/v1/audit/auth-sample has no MCP tool) and retention is
# `exception:#520` (its REST twin is MCP-free by decision); both count untwinned: +2 on the 225 of dev, 227.
BASELINE_UNTWINNED = 227

# The generic "planned:#2146" placeholder means "tracked by nobody in particular". It may only
# SHRINK (a row flipped to a specific issue, a twin, or an exception); a new row names a specific
# issue. Bidirectional like BASELINE_UNTWINNED: lower it in the same change that removes rows.
GENERIC_PLANNED_STATUS = "planned:#2146"
GENERIC_PLANNED_ISSUE = 2146
BASELINE_GENERIC_PLANNED = 176

# A revisit date outside this window is a typo (9999-12-31), a shape error. A date at or before
# today + REVISIT_WARN_DAYS only produces ONE aggregated warning, never a failure.
REVISIT_MIN = datetime.date(2026, 1, 1)
REVISIT_MAX = datetime.date(2028, 12, 31)
REVISIT_WARN_DAYS = 14

# Every strict-shaped `exception:` row is pinned here by capability_id to its (issue, revisit date).
# A strict row must be a key with exactly that issue and date, and every key must still be a strict
# row (twinning or retiring an exception forces the pin edit). Adding, relabelling, re-dating or
# swapping the id of a strict exception is therefore a visible constant edit; a new exception needs its own
# recorded ruling, named in ADR-1005. The grandfather set below has no pins: a swap there stays
# review-enforced.
STRICT_EXCEPTION_PINS = {
    # #5955: temporary owner-accepted UI-only fragments (Dashboard, webhooks, General, Access).
    "get.fragments-access-principals-detail": (5955, "2026-11-30"),
    "get.fragments-access-principals-list": (5955, "2026-11-30"),
    "get.fragments-access-tokens-list": (5955, "2026-11-30"),
    "get.fragments-access-users-detail": (5955, "2026-11-30"),
    "get.fragments-access-users-list": (5955, "2026-11-30"),
    "get.fragments-dashboard-activity": (5955, "2026-11-30"),
    "get.fragments-dashboard-health": (5955, "2026-11-30"),
    "get.fragments-dashboard-policies": (5955, "2026-11-30"),
    "get.fragments-dashboard-summary": (5955, "2026-11-30"),
    "get.fragments-settings-analytics-events": (5955, "2026-11-30"),
    "get.fragments-settings-general-runtime": (5955, "2026-11-30"),
    "get.fragments-settings-webhooks": (5955, "2026-11-30"),
    "get.fragments-settings-webhooks-param-deliveries": (5955, "2026-11-30"),
    # #520: server administration surfaces stay REST-only (the #4028 settings reads, the #4031 enrollment/OIDC reads and the audit retention read).
    "get.fragments-access-audit-retention": (520, "2027-04-30"),
    "get.fragments-settings-analytics": (520, "2027-04-30"),
    "get.fragments-settings-auto-approve": (520, "2027-04-30"),
    "get.fragments-settings-data-retention": (520, "2027-04-30"),
    "get.fragments-settings-directory": (520, "2027-04-30"),
    "get.fragments-settings-gateway": (520, "2027-04-30"),
    "get.fragments-settings-https": (520, "2027-04-30"),
    "get.fragments-settings-mcp": (520, "2027-04-30"),
    "get.fragments-settings-pending": (520, "2027-04-30"),
    "get.fragments-settings-plugin-signing": (520, "2027-04-30"),
    "get.fragments-settings-server-config": (520, "2027-04-30"),
    "get.fragments-settings-tls": (520, "2027-04-30"),
    # #2102: stored-data fragment (ADR-1005 2026-07-13 SLE-erasure entry).
    "get.fragments-hardware-ci-stored-data": (2102, "2027-01-13"),
    # #5357: admin password reset has no MCP twin (ADR-1005 2026-10-04 passwords entry).
    "post.api-v1-users-param-password": (5357, "2027-01-04"),
}

# `exception:` rows must read `exception:#<issue> revisit:<YYYY-MM-DD> <reason>`. The rows named
# here carry no machine-checked dated revisit (ADR-1005's 2026-10-15 entry is the one home that
# names them and says why), so they are grandfathered by capability_id. The gate pins the set's size
# (len == GRANDFATHERED_MAX) and requires every id to still be a free-form `exception:` row;
# converting or removing a row means deleting its id AND lowering GRANDFATHERED_MAX in the same
# change. Extending the set (+1 id together with MAX+1), swapping one id for another and rebinding
# an id to a different row are NOT machine-enforced: they are caught only by review of the diff.
# Never extend this set to unblock a new exception.
GRANDFATHERED_MAX = 5
GRANDFATHERED_LEGACY_EXCEPTIONS = frozenset({
    "get.fragments-auto-nvd",
    "get.fragments-settings-nvd",
    "post.api-v1-users-me-password",
    "get.fragments-tar-process-tree-detail",
    "get.fragments-tar-process-tree-result",
})

# ── OpenAPI-missing allowlist (seed for F2) ──────────────────────────────
# Every /api/v1/* route registered today that has no OpenAPI `paths` entry.
# F2's job is to backfill openapi_spec() until this list is empty - it must
# only ever SHRINK. Each entry is [METHOD, canonical_path, reason].
ALLOWLIST_OPENAPI_MISSING = [
    # The 39-entry "F2 backlog" this list originally carried (device tokens,
    # license, sessions, agent plugin-policy, execution-statistics, the
    # result-sets/scope-walking cluster, software deployments/packages,
    # statistics/topology, and three misc singletons) was backfilled into
    # openapi_spec() by #3992 (merged to dev 2026-09-06) - see
    # changelog.d/3992-openapi-backfill.added.md. Removed here rather than
    # left stale, per this script's own "no stale allowlist entry" check.
    #
    # Blanket CORS preflight, not a discrete documentable capability - every
    # /api/v1/* path answers OPTIONS the same way (204, no body). Structural
    # exception, never an F2-style backlog item.
    ("OPTIONS", "/api/v1/{param}", "blanket CORS preflight handler (sink.Options(R\"(/api/v1/.*)\", ...)) - not a discrete capability, exempt from OpenAPI documentation"),
]

# ── Domain classification ────────────────────────────────────────────────
# Order matters - first match wins. Path-prefix rules are checked before
# the owner-file fallback, since several owner files (rest_api_v1.cpp,
# dashboard_routes.cpp) register routes across multiple domains.
DOMAINS = [
    "devices", "inventory", "dex", "guardian", "tar", "auto-preflight",
    "auto-deploy", "auto-verify", "network", "viz", "executions",
    "scope-result-sets", "instructions", "compliance-policy", "settings",
    "rbac", "auth-mfa", "engine-principals", "access-reviews", "ca-pki",
    "ota", "enrollment", "crypto", "other",
]

PATH_DOMAIN_RULES = [
    (re.compile(r"^/(fragments/)?device/dex"), "dex"),
    (re.compile(r"^/(fragments/)?dex/"), "dex"),
    (re.compile(r"^/fragments/network/"), "network"),
    (re.compile(r"^/(fragments/)?device/guardian"), "guardian"),
    (re.compile(r"^/(fragments/)?guardian/"), "guardian"),
    (re.compile(r"^/(fragments/)?tar/"), "tar"),
    (re.compile(r"^/fragments/auto/preflight"), "auto-preflight"),
    (re.compile(r"^/fragments/auto/deploy"), "auto-deploy"),
    (re.compile(r"^/fragments/auto/verify"), "auto-verify"),
    (re.compile(r"^/(fragments/)?viz/"), "viz"),
    (re.compile(r"^/fragments/scope-list"), "scope-result-sets"),
    (re.compile(r"^/fragments/create-group-form"), "devices"),
    (re.compile(r"^/fragments/device"), "devices"),
    (re.compile(r"^/fragments/devices"), "devices"),
    (re.compile(r"^/fragments/results"), "executions"),
    (re.compile(r"^/api/dashboard/(execute|group-from-results|tar-execute)"), "executions"),
    (re.compile(r"^/fragments/crypto/"), "crypto"),
    (re.compile(r"^/fragments/compliance"), "compliance-policy"),
    (re.compile(r"^/api/(compliance|polic(y|ies))"), "compliance-policy"),
    # Settings sub-panels: several are administrative UI over a capability
    # that has its OWN domain elsewhere in this list. Route those to the
    # capability's domain, not to the generic "settings" catch-all, so the
    # ledger groups by what the row is FOR rather than which .cpp happens to
    # register it. Order matters - specific sub-panel rules before the
    # generic /api/settings|/fragments/settings fallback below.
    (re.compile(r"^/(api|fragments)/settings/ca\b"), "ca-pki"),
    (re.compile(r"^/(api|fragments)/settings/(mfa|oidc)\b"), "auth-mfa"),
    (re.compile(r"^/fragments/settings/access-reviews"), "access-reviews"),
    (re.compile(r"^/fragments/settings/engine-principals"), "engine-principals"),
    (re.compile(r"^/(api|fragments)/settings/(users|api-tokens|tokens)\b"), "rbac"),
    (re.compile(r"^/(api|fragments)/settings/(pending-agents|pending|enrollment-tokens|auto-approve|directory)\b"), "enrollment"),
    (re.compile(r"^/(api|fragments)/settings/updates"), "ota"),
    (re.compile(r"^/(api|fragments)/settings/dex-alerts"), "dex"),
    (re.compile(r"^/fragments/settings/(nvd|tag-compliance)"), "compliance-policy"),
    (re.compile(r"^/(api|fragments)/settings/management-groups"), "devices"),
    (re.compile(r"^/(api|fragments)/settings"), "settings"),
    (re.compile(r"^/api/notifications"), "other"),
    (re.compile(r"^/api/webhooks"), "other"),
    (re.compile(r"^/api/workflow"), "instructions"),
    (re.compile(r"^/api/instructions"), "instructions"),
    (re.compile(r"^/api/product-packs"), "instructions"),
    (re.compile(r"^/api/patches/deployments"), "ota"),
    (re.compile(r"^/api/deployment-jobs"), "ota"),
    (re.compile(r"^/api/directory"), "enrollment"),
    (re.compile(r"^/api/help"), "other"),
]

OWNER_FILE_DOMAIN_FALLBACK = {
    "device_routes.cpp": "devices",
    "hardware_routes.cpp": "devices", # Hardware is THE device surface (round-3 plan) — /devices and
                                       # /device?id= 302-redirect here; same domain as device_routes.cpp.
    "device_ui.cpp": "devices",
    "inventory_routes.cpp": "inventory",
    "dex_routes.cpp": "dex",
    "dex_perf_ui.cpp": "dex",
    "dex_app_perf_ui.cpp": "dex",
    "guardian_routes.cpp": "guardian",
    "tar_tree_routes.cpp": "tar",
    "preflight_routes.cpp": "auto-preflight",
    "deployment_routes.cpp": "auto-deploy",
    "deployment_ui.cpp": "auto-deploy",
    "verify_routes.cpp": "auto-verify",
    "network_routes.cpp": "network",
    "viz_routes.cpp": "viz",
    "workflow_routes.cpp": "instructions",
    "crypto_routes.cpp": "crypto",
    "compliance_routes.cpp": "compliance-policy",
    "compliance_ui.cpp": "compliance-policy",
    "settings_routes.cpp": "settings",
    "auth_routes.cpp": "auth-mfa",
    "ca_routes.cpp": "ca-pki",
    "kek_routes.cpp": "ca-pki",
    "discovery_routes.cpp": "ota",
    "offload_routes.cpp": "ota",
    "file_retrieval_routes.cpp": "other",
    "plugin_config_routes.cpp": "settings",
    "webhook_routes.cpp": "other",
    "notification_routes.cpp": "other",
    "dashboard_routes.cpp": "executions",
    "dashboard_ui.cpp": "other",
    "rest_api_v1.cpp": "other",
}


def step_summary(text):
    """Appends `text` to the GitHub step summary (the run's front page) when
    GITHUB_STEP_SUMMARY names a file; any failure to write is ignored: a
    summary is a convenience and must never change the gate's result."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    except OSError:
        pass


def gh(kind, msg):
    # stderr, not stdout - --dump-json/--baseline-inventory print machine-
    # readable output to stdout and must stay uncontaminated by warnings.
    print(f"::{kind}::{msg}", file=sys.stderr, flush=True)


# ── Lexical helpers ──────────────────────────────────────────────────────

_FULL_LINE_COMMENT = re.compile(r"^[ \t]*//.*$", re.MULTILINE)


def strip_full_line_comments(text):
    """Blank out lines whose first non-whitespace token is `//`. Does NOT
    touch inline trailing comments (raw strings embed `https://` mid-line,
    which a naive inline-comment stripper would corrupt) - see module
    docstring / #3991 design notes."""
    return _FULL_LINE_COMMENT.sub("", text)


def parse_literal_at(text, pos):
    """If a C++ string or raw-string literal starts at/after `pos` (skipping
    only whitespace), return (content, end_pos). Otherwise return (None,
    pos) unchanged - caller decides what "not a literal" means."""
    i = pos
    n = len(text)
    while i < n and text[i] in " \t\r\n":
        i += 1
    if i >= n:
        return None, pos
    if text[i] == '"':
        j = i + 1
        buf = []
        while j < n and text[j] != '"':
            if text[j] == "\\" and j + 1 < n:
                buf.append(text[j + 1])
                j += 2
            else:
                buf.append(text[j])
                j += 1
        return "".join(buf), j + 1
    if text[i] == "R" and i + 1 < n and text[i + 1] == '"':
        j = i + 2
        delim_end = text.index("(", j)
        delim = text[j:delim_end]
        terminator = ")" + delim + '"'
        end = text.index(terminator, delim_end + 1)
        return text[delim_end + 1:end], end + len(terminator)
    return None, pos


def parse_adjacent_literals(text, pos):
    """Like `parse_literal_at`, but concatenates every C++ string/raw-string
    literal that is ADJACENT to the first - i.e. separated only by
    whitespace and/or full-line `//` comments - per ordinary C++ adjacent-
    string-literal concatenation (`"/api/v1" "/route"` is one string,
    `/api/v1/route`, at compile time). Mirrors the chunk-concatenation loop
    `extract_openapi_paths()` already needs for the MSVC-16KB-split case;
    without this, a route registration split across two adjacent literals
    (the natural place a human wraps a long path - at a version-prefix
    boundary, exactly like the existing split convention this script's own
    module docstring documents for the OpenAPI literal) silently truncates
    to the first chunk instead of erroring or warning, and a truncated path
    like "/api/v1" satisfies neither ledger bucket in `extract_all_routes`
    and is dropped with no requirement and no `::warning::` at all."""
    literal, end = parse_literal_at(text, pos)
    if literal is None:
        return None, pos
    parts = [literal]
    n = len(text)
    while True:
        i = end
        while i < n and text[i] in " \t\r\n":
            i += 1
        if text[i:i + 2] == "//":
            eol = text.index("\n", i)
            i = eol + 1
            while i < n and text[i] in " \t\r\n":
                i += 1
        nxt, nxt_end = parse_literal_at(text, i)
        if nxt is None:
            break
        parts.append(nxt)
        end = nxt_end
    return "".join(parts), end


_VERB_CALL = re.compile(r"\b(\w+)(?:\.|->)(" + "|".join(VERBS) + r")\s*\(")

# httplib::Client call sites (directory_sync.cpp, analytics_sinks.cpp,
# nvd_client.cpp, offload_target_store.cpp, webhook_store.cpp, oidc_provider.cpp,
# settings_routes.cpp - all outbound HTTP clients, never route registrations)
# always pass a runtime variable as their first argument, by construction -
# fetching a caller-supplied URL is the entire point of an httplib::Client.
# These receiver names are the verified, complete false-positive set (grepped
# across the whole tree at #3991-time, both `.` and `->` forms - see
# docs/architecture.md "Route Registration" for why the receiver-agnostic
# `(\.|->)` pattern is required at all: a dot-only grep silently missed
# server.cpp's ~107 `web_server_->{Get,Post,...}(` inline registrations, the
# exact false negative #2542 already documented once); a verb call through
# any OTHER receiver with no literal first argument is unexpected and still
# warns loudly below rather than being silently dropped.
_KNOWN_CLIENT_RECEIVERS = {"cli", "client"}


def extract_verb_calls(text, path):
    """Yields (method, raw_path_literal) for every `<receiver>.<Verb>(` call
    whose first argument is a string/raw-string literal starting with '/'.
    A call whose first argument is not a literal is reported via stderr WARN
    (never silently dropped) UNLESS the receiver is a known httplib::Client
    variable name (see `_KNOWN_CLIENT_RECEIVERS`) - route-registration sinks
    (`sink`, `svr`, and any future receiver name) always warn loudly on a
    non-literal first argument, since that would be a real extraction gap."""
    for m in _VERB_CALL.finditer(text):
        receiver = m.group(1)
        method = m.group(2).upper()
        literal, _end = parse_adjacent_literals(text, m.end())
        if literal is None:
            if receiver in _KNOWN_CLIENT_RECEIVERS:
                continue
            line = text.count("\n", 0, m.start()) + 1
            gh("warning",
               f"check-api-parity: {path}:{line}: verb call with no literal "
               f"first argument (skipped) - {text[m.start():m.start()+60]!r}")
            continue
        if not literal.startswith("/"):
            continue
        yield method, literal


def _mask_paren_groups(path):
    """Replace every balanced (...) run with a single NUL marker byte, so a
    capture group's own internal '/' (extremely common here - '([^/]+)' is
    the majority pattern) never causes a wrong path-segment split below.
    Handles nesting (depth-tracked) even though none of today's patterns
    nest; nothing in the char class or literal text outside parens is
    touched."""
    out = []
    depth = 0
    for ch in path:
        if ch == "(":
            if depth == 0:
                out.append("\x00")
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def canonicalize(path):
    """Collapse a regex-capture-group segment (registered routes) or a
    '{param}'-style segment (OpenAPI) into a single '{param}' token, so the
    two sides - and a route whose capture charset changes over time - key
    identically. See module docstring point 1. Splits on the PAREN-MASKED
    text (see `_mask_paren_groups`) so a capture group like '([^/]+)' - the
    majority pattern in this codebase - doesn't get sliced by its own
    internal '/'."""
    segs = _mask_paren_groups(path).split("/")
    out = []
    for seg in segs:
        if seg == "":
            out.append(seg)
            continue
        if re.fullmatch(r"\{[^{}]*\}", seg):
            out.append("{param}")
        elif "\x00" in seg or re.search(r"[\[\]*+?|\\]", seg):
            out.append("{param}")
        else:
            out.append(seg)
    return "/".join(out)


def classify_domain(canonical_path, owner_file):
    for rx, domain in PATH_DOMAIN_RULES:
        if rx.match(canonical_path):
            return domain
    return OWNER_FILE_DOMAIN_FALLBACK.get(owner_file, "other")


# ── Extraction ────────────────────────────────────────────────────────────

def extract_all_routes():
    """Returns (bucket_a, bucket_b): each a dict {(method, canonical_path):
    [(owner_file, raw_path), ...]} - fragments/legacy-api and versioned
    /api/vN/* registrations respectively, across every server/core/src/*.cpp
    file. bucket_b covers every /api/vN/ generation (v1, and #4144's v2 -
    the repo's first breaking-change route, docs/api-versioning-policy.md) -
    each is OpenAPI-completeness-checked the same way; a version bump is not
    a new tracking mechanism, it is the SAME mechanism at a new prefix."""
    bucket_a = {}
    bucket_b = {}
    versioned_api_re = re.compile(r"^/api/v\d+/")
    for f in sorted(SERVER_SRC.glob("*.cpp")):
        text = strip_full_line_comments(f.read_text(encoding="utf-8"))
        for method, raw in extract_verb_calls(text, f.name):
            if versioned_api_re.match(raw):
                bucket = bucket_b
            elif raw.startswith("/fragments/") or (
                raw.startswith("/api/") and not versioned_api_re.match(raw)
            ):
                bucket = bucket_a
            else:
                continue
            canon = canonicalize(raw)
            bucket.setdefault((method, canon), []).append((f.name, raw))
    return bucket_a, bucket_b


def extract_openapi_paths():
    """Parses the openapi_spec() literal out of rest_api_v1.cpp (concatenated
    raw-string chunks, MSVC C2026 16KB-cap split - see the source comment
    at rest_api_v1.cpp:664) and returns the set of (METHOD, canonical "/api/
    v1"+path, or "/api/v2"+path for a path-item carrying a "/v2" server
    override - #4144, the repo's first breaking-change route) tuples in its
    `paths` table, plus the parsed spec dict."""
    try:
        text = REST_API_V1_CPP.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as e:
        raise AnchorError(f"cannot read {REST_API_V1_CPP} ({_why(e)}) - the file this "
                          f"script scans for the openapi_spec() literal")
    anchor = _find_unique(text, "static const std::string spec =", "the openapi_spec() literal")
    if anchor < 0:
        raise AnchorError("the openapi_spec() literal (`static const std::string "
                          "spec =`) was not found in rest_api_v1.cpp - the lexical "
                          "anchor this script reads changed")
    pos = anchor + len("static const std::string spec =")
    chunks = []
    n = len(text)
    while True:
        i = pos
        while i < n and text[i] in " \t\r\n":
            i += 1
        # Skip a full C++ line comment between literal chunks.
        if text[i:i + 2] == "//":
            eol = text.index("\n", i)
            pos = eol + 1
            continue
        if text[i] == ";":
            pos = i + 1
            break
        literal, end = parse_literal_at(text, i)
        if literal is None:
            raise RuntimeError(
                f"check-api-parity: could not parse openapi_spec() literal "
                f"chunk at offset {i} (expected a string/raw-string literal "
                f"or ';')")
        chunks.append(literal)
        pos = end
    spec_json = "".join(chunks)
    spec = json.loads(spec_json)

    paths = set()
    methods = {"get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE",
               "patch": "PATCH", "options": "OPTIONS"}
    for path, ops in spec.get("paths", {}).items():
        if not isinstance(ops, dict):
            continue
        # A path-item's own "servers" override (OpenAPI 3.0.3 SS4.7.9.2) means
        # it resolves against a DIFFERENT base than the top-level "/api/v1"
        # servers[] entry - #4144's v2 route is the only one today, keyed
        # "/v2/..." precisely so this is a literal-prefix strip, not a guess.
        base = "/api/v1"
        servers = ops.get("servers")
        if isinstance(servers, list) and servers and path.startswith("/v2/"):
            base = "/api/v2"
            path = path[len("/v2"):]
        for m_lower, m_upper in methods.items():
            if m_lower in ops:
                paths.add((m_upper, canonicalize(base + path)))
    return paths, spec


_TOOLDEF_ENTRY = re.compile(r'^\s{4}\{"([A-Za-z0-9_]+)"', re.MULTILINE)


def _find_unique(text, anchor, label):
    """text.find(anchor), but a second copy of the declaration (a stale
    commented or conditionally compiled copy) is an error: the scan would read the
    first one."""
    n = text.count(anchor)
    if n > 1:
        raise AnchorError(f"{label} appears {n} times - the scan reads the first copy, "
                          f"so a stale, commented-out or unrelated second copy of the "
                          f"declaration text hides the live one: remove or reword it")
    return text.find(anchor)


class AnchorError(RuntimeError):
    """A lexical anchor in mcp_server.cpp is gone (renamed or reformatted):
    reported as a named error, never a traceback."""


def _why(e):
    """Short cause text: an OSError's strerror (the path is printed elsewhere)."""
    return e.strerror if isinstance(e, OSError) and e.strerror else str(e)[:120]


def _read_mcp_server_cpp():
    try:
        return MCP_SERVER_CPP.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as e:
        raise AnchorError(f"cannot read {MCP_SERVER_CPP} ({_why(e)}) - the "
                          f"file this script scans for kTools[] and kResources[]")


_REGISTRY_ANCHOR = "constexpr ToolRecord kToolRecords[] = {"


def _extract_registry_tools(seen):
    """Names from the kToolRecords[] slice of every mcp_tools_*.cpp in MCP_REGISTRY_DIR.
    `seen` maps each name already found to the source that declared it; a repeat (in kTools[]
    or in another file) is an AnchorError naming both sources, so the same tool can never be
    served twice. Returns the new names."""
    files = sorted(MCP_REGISTRY_DIR.glob("mcp_tools_*.cpp"))
    if len(files) < MIN_REGISTRY_FILES:
        raise AnchorError(f"found {len(files)} mcp_tools_*.cpp file(s) in {MCP_REGISTRY_DIR}, "
                          f"expected at least {MIN_REGISTRY_FILES} - a deleted or renamed "
                          f"registry file would silently drop its tools from the catalogue")
    found = set()
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as e:
            raise AnchorError(f"cannot read {path} ({_why(e)}) - a registry file this "
                              f"script scans for kToolRecords[]")
        start = _find_unique(text, _REGISTRY_ANCHOR, f"the kToolRecords[] declaration in {path.name}")
        end = text.find("\n};", start) if start >= 0 else -1
        if end < 0:
            raise AnchorError(f"kToolRecords[] was not found (or is unterminated) in {path.name} - "
                              f"the lexical anchor `{_REGISTRY_ANCHOR}` or its closing `}};` at "
                              f"column 0 changed")
        names = _TOOLDEF_ENTRY.findall(refuse_preprocessor_lines(text[start:end], f"kToolRecords[] in {path.name}"))
        if not names:
            raise AnchorError(f"kToolRecords[] in {path.name} yielded zero entries - the entry "
                              "layout (a 4-space-indented `{\"name\",` line, the lexical anchor "
                              "this script reads) changed")
        for name in names:
            if name in seen:
                raise AnchorError(f"MCP tool {name!r} is declared twice: in {seen[name]} and in "
                                  f"{path.name} - a tool is served from exactly one place")
            seen[name] = path.name
            found.add(name)
    return found


def extract_mcp_tools():
    """The MCP tool names: kTools[] in mcp_server.cpp, unioned with the per-domain registry
    records (mcp_tools_*.cpp). With no registry file the result is exactly the kTools[] set."""
    text = _read_mcp_server_cpp()
    start = _find_unique(text, "static const ToolDef kTools[] = {", "the kTools[] declaration")
    # Matching closing "};" at column 0, mirroring the array's own style.
    end = text.find("\n};", start) if start >= 0 else -1
    found = set(_TOOLDEF_ENTRY.findall(refuse_preprocessor_lines(text[start:end], "kTools[]"))) if end >= 0 else set()
    if not found:
        raise AnchorError("kTools[] was not found (or yielded zero entries) in "
                          "mcp_server.cpp - the array declaration or entry "
                          "layout (the lexical anchor this script reads) changed")
    return found | _extract_registry_tools({n: "kTools[] in mcp_server.cpp" for n in found})


_RESOURCE_ENTRY = re.compile(r'\{\s*"(yuzu://[^"]+)"')
_CPP_TOKEN = re.compile(
    r'"(?:\\.|[^"\\\n])*"|//[^\n]*|/\*.*?\*/', re.DOTALL)


def strip_cpp_comments(text):
    """Blanks `//` and `/* */` comments (newlines kept, so line numbers
    survive) without touching string literals: "yuzu://x" contains `//`. Char
    literals are not recognised (a quote character literal would open a string
    and hide the rest of its line; none occurs in kResources[]). Not raw-string
    aware, so it is applied to the small kResources[] array only."""
    def blank(m):
        t = m.group(0)
        return re.sub(r"[^\n]", " ", t) if t.startswith("/") else t
    return _CPP_TOKEN.sub(blank, text)


# A preprocessor line: `#` or its digraph `%:` first on the line, or right after anything that ends
# in `*/` (the end of a block comment, possibly one that began on an earlier line). Loose on
# purpose: it also refuses a raw-string line that happens to read `... */ #`, which fails loudly.
# Linear: `.*` backtracks over each `*/` once and the tail test is constant.
_PP_LINE = re.compile(r"\s*(?:#|%:)|.*\*/\s*(?:#|%:)")


def refuse_preprocessor_lines(text, what):
    """Raises AnchorError at the first line that is a preprocessor directive. The
    scan does not model #if/#ifdef/#define, so a conditionally compiled entry
    would be counted as served (or hidden); refusing is loud. A directive is a
    line that starts with `#` or the `%:` digraph, or has one right after a `*/`.
    kResources[] is comment-stripped first, so a comment may mention one;
    kTools[] is not (its raw string schemas hold `//` and `/*`), so a line
    inside a raw-string schema that starts with `#` fails here too, and a tool
    entry wrapped in a block comment there is still counted as a tool. LIMITS: a
    directive outside the slice is not scanned (one wrapping the whole array
    would break the build); `} #if 0` on a code line is not a directive; a
    trigraph is inert in C++23."""
    for n, line in enumerate(text.split("\n"), 1):
        if _PP_LINE.match(line):
            raise AnchorError(
                f"a preprocessor line at row {n} of the {what} slice (declaration = row 1: "
                f"{line.strip()[:40]!r}) - the scan does not model #if/#ifdef/#define, so "
                f"a conditionally compiled entry could be counted as served or hidden: "
                f"teach scripts/ci/check-api-parity.py the directive, move it out of the "
                f"array, or (for kTools[]) move the line out of the raw-string schema")
    return text


def parse_mcp_resources(text):
    """URIs of the fixed `static const ResourceDef kResources[] = {...};`
    entries (resource templates are not included). Comments are blanked first,
    string literals untouched ("yuzu://x" holds a `//`); extract_mcp_tools() has
    the same pre-existing comment weakness. Raises AnchorError when the array or
    its entries cannot be found, or when a preprocessor line sits inside it."""
    start = _find_unique(text, "static const ResourceDef kResources[] = {", "the kResources[] declaration")
    end = text.find("\n};", start) if start >= 0 else -1
    if end < 0:
        raise AnchorError("kResources[] was not found in mcp_server.cpp - the "
                          "array declaration (the lexical anchor) changed")
    body = refuse_preprocessor_lines(strip_cpp_comments(text[start:end]), "kResources[]")
    found = set(_RESOURCE_ENTRY.findall(body))
    if not found:
        raise AnchorError("kResources[] in mcp_server.cpp yielded zero "
                          "entries - the entry layout (the lexical anchor) "
                          "changed")
    return found


def extract_mcp_resources():
    return parse_mcp_resources(_read_mcp_server_cpp())


def all_ref_targets(node, out):
    """Walk the ENTIRE OpenAPI doc (not just literal `$ref` keys) collecting
    every string value that starts with '#/' - `discriminator.mapping`
    values are refs too (see rest_api_v1.cpp:713-717) and a naive
    '$ref'-key-only walk misses them."""
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, str) and v.startswith("#/"):
                out.add(v)
            else:
                all_ref_targets(v, out)
    elif isinstance(node, list):
        for v in node:
            all_ref_targets(v, out)


def resolve_ref(spec, ref):
    parts = ref.lstrip("#/").split("/")
    node = spec
    for p in parts:
        if not isinstance(node, dict) or p not in node:
            return False
        node = node[p]
    return True


# ── Ledger I/O ────────────────────────────────────────────────────────────

STATUS_RE = re.compile(
    r"(twinned|twinned-rest-only|twinned-mcp-only|retire|planned:#[1-9][0-9]*"
    r"|composed-of:[A-Za-z0-9_.:,\-]+|exception:.+)", re.ASCII)
EXCEPTION_RE = re.compile(
    r"exception:#([1-9][0-9]{0,8}) revisit:([0-9]{4}-[0-9]{2}-[0-9]{2}) (.+)", re.ASCII)
TWINNED_STATUSES = ("twinned", "twinned-rest-only", "twinned-mcp-only")
RESOURCE_TWIN_PREFIX = "resource:"
# A reason needs one character outside these categories (control, format, surrogate,
# private-use, unassigned, spaces/separators, combining marks); NUL is a control char.
_NON_CONTENT = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zs", "Zl", "Zp", "Mn", "Me"})
# Letters that render as nothing (Braille blank, Hangul fillers): visible to the category test, empty to a reader.
_INVISIBLE_FILLERS = frozenset("\u2800\u115f\u1160\u3164\uffa0")


def _reason_is_blank(reason):
    return not any(c not in _INVISIBLE_FILLERS and unicodedata.category(c) not in _NON_CONTENT
                   for c in reason)


def parse_exception(status):
    """(issue, date_str, reason) for a strict-shaped exception, else None."""
    m = EXCEPTION_RE.fullmatch(status)
    if not m or _reason_is_blank(m.group(3)):
        return None
    return int(m.group(1)), m.group(2), m.group(3)


def status_errors(status, capability_id, grandfathered):
    """Status-shape validation as a pure function (selftested): a list of
    error strings (empty = clean). An `exception:` status must be strict
    unless its capability_id is in the `grandfathered` set."""
    if not isinstance(status, str):
        return [f"status must be a string, got {type(status).__name__}"]
    if not STATUS_RE.fullmatch(status):
        return [f"invalid status {status!r}"]
    if not status.startswith("exception:"):
        return []
    parsed = parse_exception(status)
    if parsed:
        if parsed[0] == GENERIC_PLANNED_ISSUE:
            return [f"exception issue #{GENERIC_PLANNED_ISSUE} is the generic "
                    f"{GENERIC_PLANNED_STATUS} umbrella, not a ruling: {status!r}"]
        try:
            d = datetime.date.fromisoformat(parsed[1])
        except ValueError:
            return [f"exception revisit date {parsed[1]!r} is not a real date: {status!r}"]
        if not REVISIT_MIN <= d <= REVISIT_MAX:
            return [f"exception revisit date {parsed[1]!r} is outside "
                    f"{REVISIT_MIN}..{REVISIT_MAX}: {status!r}"]
        return []
    if capability_id in grandfathered:
        return []
    return [f"exception status must be 'exception:#<issue> revisit:<YYYY-MM-DD> "
            f"<reason>' (issue 1-999999999): convert the row to that shape; "
            f"do NOT extend GRANDFATHERED_LEGACY_EXCEPTIONS (review-enforced: "
            f"the gate only pins its size), got {status[:200]!r}"]


def revisit_lapse_warning(rows, today):
    """ONE aggregated warning string (or None) for strict exception rows whose
    revisit date is at or before today + REVISIT_WARN_DAYS. A WARNING only: a
    failure would turn CI red fleet-wide on the revisit date itself. `today` is
    injected so the selftest is deterministic."""
    try:
        horizon = today + datetime.timedelta(days=REVISIT_WARN_DAYS)
    except OverflowError:
        horizon = datetime.date.max
    due = []
    for row in rows.values():
        parsed = parse_exception(row["status"])
        if parsed:
            d = datetime.date.fromisoformat(parsed[1])
            if d <= horizon:
                due.append((d, parsed[0], row["capability_id"]))
    if not due:
        return None
    due.sort()
    lapsed = sum(1 for d, _i, _c in due if d < today)
    issues = ", ".join(f"#{n}" for n in sorted({i for _d, i, _c in due}))
    ids = ", ".join(c for _d, _i, c in due[:3])
    return (f"{len(due)} exception row(s) have a revisit date on or before {horizon} "
            f"(earliest {due[0][0]}, {lapsed} already past; issues {issues}; first: "
            f"{ids}{', ...' if len(due) > 3 else ''}): re-confirm each (pin, JSON row and "
            f"ADR date together), twin it, or retire it")


def pin_errors(ledger_rows, pins=None):
    """Identity pin over the strict-shaped exception rows (selftested): every
    strict row must be a key of `pins` with exactly that (issue, revisit date),
    and every key must still be a strict row."""
    if pins is None:
        pins = STRICT_EXCEPTION_PINS
    errors = []
    seen = set()
    for key, row in ledger_rows.items():
        parsed = parse_exception(row["status"])
        if not parsed:
            continue
        cid = row["capability_id"]
        seen.add(cid)
        actual = (parsed[0], parsed[1])
        where = f"{row['_file']}: {key[0]} {key[1]!r}"
        if cid not in pins:
            errors.append(f"{where} is a new exception (#{actual[0]} revisit {actual[1]}) "
                          f"that is not in STRICT_EXCEPTION_PINS - a new exception needs its "
                          f"own recorded ruling: name it in ADR-1005 and add the pin in THIS "
                          f"change (converting a grandfathered legacy row to the strict shape "
                          f"also needs its pin)")
        elif pins[cid] != actual:
            errors.append(f"{where} is exception #{actual[0]} revisit {actual[1]} but is "
                          f"pinned as #{pins[cid][0]} revisit {pins[cid][1]} - a changed "
                          f"exception needs a recorded ruling (a pure re-confirmation edits "
                          f"the pin, the JSON row and the ADR date together): name it in "
                          f"ADR-1005 and edit STRICT_EXCEPTION_PINS in THIS change")
    for cid in sorted(set(pins) - seen):
        errors.append(f"STRICT_EXCEPTION_PINS entry {cid!r} is stale (no strict exception row "
                      f"has that capability_id any more, e.g. it was twinned or retired) - "
                      f"remove the pin in THIS change")
    return errors


def stale_grandfather_errors(rows, grandfathered):
    """The grandfather set's size must equal GRANDFATHERED_MAX and every id
    must still name a NON-strict `exception:` row. This catches growth and
    stale ids; a swap or an extension paired with a MAX raise is review-only."""
    n = len(grandfathered)
    by_id = {r["capability_id"]: r for r in rows.values()}
    bad = {}
    for cid in sorted(grandfathered):
        row = by_id.get(cid)
        if row is None or not row["status"].startswith("exception:"):
            bad[cid] = "no longer names an exception row"
        elif parse_exception(row["status"]):
            bad[cid] = "already uses the strict shape"
    target = n - len(bad)  # the size every message below agrees on
    fix = ("remove this id and leave GRANDFATHERED_MAX alone" if n > GRANDFATHERED_MAX
           else f"remove it from the set and lower GRANDFATHERED_MAX to {target} in THIS change")
    errors = []
    if n > GRANDFATHERED_MAX:
        errors.append(f"GRANDFATHERED_LEGACY_EXCEPTIONS grew ({n} ids, "
                      f"GRANDFATHERED_MAX {GRANDFATHERED_MAX}): remove the added "
                      f"id(s); GRANDFATHERED_MAX is never raised")
    elif n < GRANDFATHERED_MAX:
        errors.append(f"GRANDFATHERED_LEGACY_EXCEPTIONS has {n} ids, fewer than "
                      f"GRANDFATHERED_MAX {GRANDFATHERED_MAX}: lower "
                      f"GRANDFATHERED_MAX to {target} in THIS change")
    errors += [f"GRANDFATHERED_LEGACY_EXCEPTIONS id {cid!r} {why} - {fix}" for cid, why in bad.items()]
    return errors


# An HTTP method as the ledger spells it: ASCII capitals only (the capability id and the
# gate's messages embed it, so no newline or other character may ride along).
_METHOD_RE = re.compile(r"[A-Z]{1,16}")
# A route path as the ledger spells it (letters, digits and `_ . : / { } -`, at most 200 characters):
# the gate's messages embed it, so no newline or other control character may ride along.
_PATH_RE = re.compile(r"[A-Za-z0-9_.:/{}-]{1,200}")


def row_shape_error(row):
    """Structural validation of one ledger row (pure, selftested): the first
    problem as a string, or None. Keeps later checks from raising."""
    if not isinstance(row, dict):
        return "row must be a JSON object"
    missing = {"method", "path", "capability_id", "rest_v1_twin",
               "mcp_twin", "status"} - row.keys()
    if missing:
        return f"missing field(s) {sorted(missing)}"
    if not all(isinstance(row[k], str) for k in ("method", "path", "capability_id")):
        return "method, path and capability_id must be strings"
    if not _METHOD_RE.fullmatch(row["method"]):
        return f"method must be 1-16 upper-case ASCII letters (GET, POST, ...), got {row['method'][:20]!r}"
    if not _PATH_RE.fullmatch(row["path"]):
        return f"path must be 1-200 characters from A-Z a-z 0-9 _ . : / {{ }} -, got {row['path'][:40]!r}"
    rest, mcp = row["rest_v1_twin"], row["mcp_twin"]
    # A bare-string rest_v1_twin is documentary prose on a non-twinned row.
    rest_ok = (all(isinstance(rest.get(k), str) for k in ("method", "path"))
               if isinstance(rest, dict) else rest is None or isinstance(rest, str))
    if not rest_ok or not (mcp is None or isinstance(mcp, str)):
        return ("rest_v1_twin must be null, a string or an object with string "
                "method and path; mcp_twin null or a string")
    if isinstance(rest, dict) and not _METHOD_RE.fullmatch(rest["method"]):
        return f"rest_v1_twin method must be 1-16 upper-case ASCII letters, got {rest['method'][:20]!r}"
    if isinstance(rest, dict) and not _PATH_RE.fullmatch(rest["path"]):
        return f"rest_v1_twin path must be 1-200 characters from A-Z a-z 0-9 _ . : / {{ }} -, got {rest['path'][:40]!r}"
    return None


def ledger_files():
    return sorted(LEDGER_DIR.glob("*.json"))


def load_ledger(ledger_dir=None):
    """Returns (rows, errors): rows is {(method, canonical_path): row_dict
    with '_domain' and '_file' added}; errors is a list of strings for
    malformed ledger content (duplicate key, bad status, etc.)."""
    rows = {}
    errors = []
    ids = {}
    ledger_dir = Path(ledger_dir) if ledger_dir is not None else LEDGER_DIR
    missing = [d for d in DOMAINS if not (ledger_dir / f"{d}.json").is_file()]
    if missing:
        errors.append(f"{ledger_dir}: ledger file(s) missing for declared domain(s) {missing} "
                      f"(a new domain's file is created by hand, containing [])")
    for f in sorted(ledger_dir.glob("*.json")):
        domain = f.stem
        if domain not in DOMAINS:
            # Not read further: an undeclared file's name is attacker-shaped text, so it is
            # quoted (bounded repr) and none of its content or name is used again.
            errors.append(f"{f.name[:60]!r}: filename is not one of the declared "
                          f"domains {DOMAINS}")
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (ValueError, OSError, RecursionError) as e:  # ValueError: bad JSON/UTF-8, >4300-digit ints
            errors.append(f"{f}: invalid JSON ({_why(e)})")
            continue
        if not isinstance(data, list):
            errors.append(f"{f}: top level must be a JSON array of rows")
            continue
        for idx, row in enumerate(data):
            shape = row_shape_error(row)
            if shape:
                errors.append(f"{f}[{idx}]: {shape}")
                continue
            for msg in status_errors(row["status"], row["capability_id"],
                                     GRANDFATHERED_LEGACY_EXCEPTIONS):
                errors.append(f"{f}[{idx}] ({row['method'][:20]!r} {row['path'][:40]!r}): {msg}")
            expected_id = capability_id_for(row["method"], row["path"])
            if row["capability_id"] != expected_id:
                errors.append(f"{f}[{idx}] ({row['method']} {row['path']}): "
                               f"capability_id {row['capability_id']!r} must be "
                               f"{expected_id!r} (derived from method and path)")
            if row["capability_id"] in ids:
                errors.append(f"{f}[{idx}]: duplicate capability_id "
                               f"{row['capability_id']!r} (already used at "
                               f"{ids[row['capability_id']]})")
            ids.setdefault(row["capability_id"], f"{f}[{idx}]")
            key = (row["method"], row["path"])
            if key in rows:
                errors.append(f"{f}[{idx}]: duplicate ledger key {key} "
                               f"(already defined in {rows[key]['_file']})")
                continue
            row = dict(row)
            row["_domain"] = domain
            row["_file"] = str(f)
            rows[key] = row
    return rows, errors


def capability_id_for(method, canonical_path):
    slug = re.sub(r"[^a-z0-9]+", "-", canonical_path.lower()).strip("-")
    return f"{method.lower()}.{slug}"


def bootstrap(bucket_a):
    rows, errors = load_ledger()
    if errors:
        for e in errors:
            gh("error", f"check-api-parity --bootstrap: refusing to write - "
                        f"existing ledger is malformed: {e}")
        return 1
    by_domain = {}
    added = 0
    for (method, canon), sources in bucket_a.items():
        if (method, canon) in rows:
            continue
        owner_file = sources[0][0]
        domain = classify_domain(canon, owner_file)
        by_domain.setdefault(domain, []).append({
            "method": method,
            "path": canon,
            "capability_id": capability_id_for(method, canon),
            "rest_v1_twin": None,
            "mcp_twin": None,
            "status": "planned:#2146",
        })
        added += 1
    for domain, new_rows in by_domain.items():
        f = LEDGER_DIR / f"{domain}.json"
        existing = json.loads(f.read_text(encoding="utf-8")) if f.exists() else []
        existing.extend(new_rows)
        existing.sort(key=lambda r: (r["path"], r["method"]))
        f.write_text(json.dumps(existing, indent=2, sort_keys=False) + "\n",
                     encoding="utf-8")
        print(f"check-api-parity --bootstrap: {f}: +{len(new_rows)} row(s)")
    print(f"check-api-parity --bootstrap: {added} row(s) added total")
    if added:
        print(f"check-api-parity --bootstrap: NOTE the new rows are "
              f"{GENERIC_PLANNED_STATUS}, which the gate no longer lets grow - "
              f"retag each with a specific planned:#N or a strict "
              f"exception:#N revisit:YYYY-MM-DD <reason>, and raise "
              f"BASELINE_UNTWINNED for each row that is not born twinned",
              file=sys.stderr)
    return 0


# ── Checks ────────────────────────────────────────────────────────────────

def render_doc_block(ledger_rows, bucket_b, openapi_paths, allowlist_set, mcp_tools):
    """Renders the docs/api-parity-ledger.md generated block: per-domain row/
    twinned/untwinned counts plus the overall totals this gate enforces.
    Deterministic (domains sorted) so a re-render of unchanged data
    byte-matches - required for the freshness check in run_check()."""
    by_domain = {}
    for row in ledger_rows.values():
        d = by_domain.setdefault(row["_domain"], {"total": 0, "twinned": 0})
        d["total"] += 1
        if row["status"] == "twinned":
            d["twinned"] += 1

    lines = [DOC_BEGIN, ""]
    lines.append("| Domain | Rows | Twinned | Untwinned |")
    lines.append("|---|---:|---:|---:|")
    total_rows = 0
    total_twinned = 0
    for domain in DOMAINS:
        d = by_domain.get(domain, {"total": 0, "twinned": 0})
        untwinned = d["total"] - d["twinned"]
        total_rows += d["total"]
        total_twinned += d["twinned"]
        lines.append(f"| {domain} | {d['total']} | {d['twinned']} | {untwinned} |")
    total_untwinned = total_rows - total_twinned
    lines.append(f"| **Total** | **{total_rows}** | **{total_twinned}** | "
                 f"**{total_untwinned}** |")
    lines.append("")
    missing_openapi = len(set(bucket_b) - openapi_paths)
    lines.append(f"Registered `/api/vN/*` routes: {len(bucket_b)}. OpenAPI "
                 f"`paths` entries: {len(openapi_paths)}. Missing from "
                 f"OpenAPI: {missing_openapi} ({len(allowlist_set)} carried "
                 f"in `check-api-parity.py`'s `ALLOWLIST_OPENAPI_MISSING` "
                 f"pending F2, {missing_openapi - len(allowlist_set)} "
                 f"unallowlisted). MCP tools: {len(mcp_tools)}.")
    lines.append("")
    lines.append(f"Ratchet baseline (untwinned rows; shrinks as routes are "
                 f"twinned, or rises only with a reviewed reason stated in "
                 f"the change that raises it): {BASELINE_UNTWINNED}. Generic "
                 f"`{GENERIC_PLANNED_STATUS}` placeholder baseline (shrinks "
                 f"only; a new row names a specific issue): "
                 f"{BASELINE_GENERIC_PLANNED}.")
    lines.append("")
    lines.append(DOC_END)
    return "\n".join(lines) + "\n"


def extract_doc_block(text):
    try:
        start = text.index(DOC_BEGIN)
        end = text.index(DOC_END, start) + len(DOC_END)
    except ValueError:
        return None
    return text[start:end] + "\n"


def _malformed_ledger_exit(mode, errors):
    """The informational modes print counts derived from the ledger; over a
    malformed ledger those are wrong, so say so and fail."""
    for e in errors:
        gh("error", f"check-api-parity {mode}: {e}")
    print("check-api-parity: counts unreliable: ledger is malformed", file=sys.stderr)
    return 1


def render_doc():
    ledger_rows, errors = load_ledger()
    if errors:
        return _malformed_ledger_exit("--render-doc", errors)
    bucket_a, bucket_b = extract_all_routes()
    openapi_paths, _spec = extract_openapi_paths()
    mcp_tools = extract_mcp_tools()
    allowlist_set = {(m, canonicalize(p)) for m, p, _r in ALLOWLIST_OPENAPI_MISSING}
    print(render_doc_block(ledger_rows, bucket_b, openapi_paths, allowlist_set, mcp_tools))
    return 0


def unmatched_ledger_row_errors(ledger_rows, bucket_a, bucket_b):
    """Check 1b as a pure function (selftested): every ledger row whose key is
    NOT a registered fragment/legacy route must be either status "retire", or
    an `exception:` row keyed on a registered /api/v1/* route (a v1
    capability with a recorded no-MCP-twin reason, #5342). Returns a list of
    error strings (empty = clean)."""
    errors = []
    for key, row in ledger_rows.items():
        if key in bucket_a:
            continue
        status = row["status"]
        if key in bucket_b:
            if not status.startswith("exception:"):
                errors.append(f"{row['_file']}: ledger row {key[0]} {key[1]} is "
                              f"keyed on a REST v1 route - the only legal status "
                              f"for a v1-keyed row is \"exception:#<issue> "
                              f"revisit:<YYYY-MM-DD> <reason>\" (a deliberate "
                              f"no-MCP-twin record; only the size-pinned "
                              f"grandfather set may omit the issue and date, "
                              f"and extending it is review-enforced); v1 routes are "
                              f"otherwise covered by the OpenAPI check, not the "
                              f"ledger")
            continue
        if status != "retire":
            errors.append(f"{row['_file']}: ledger row {key[0]} {key[1]} no "
                          f"longer matches any registered route - mark status "
                          f"\"retire\" or remove the row")
    return errors


def twin_errors(ledger_rows, all_extracted, mcp_tools, mcp_resources):
    """Check 2 as a pure function (selftested). `twinned` needs BOTH twins;
    `twinned-rest-only` a rest twin and no mcp twin; `twinned-mcp-only` the
    reverse. An mcp_twin is a tool name or `resource:<uri>` (a fixed
    kResources[] entry). Every named twin must exist in the extraction; an
    object-form rest_v1_twin is verified on a row of ANY status (an exception
    row too), while a bare string is documentary and unchecked."""
    errors = []
    for key, row in ledger_rows.items():
        status = row["status"]
        where = f"{row['_file']}: {key[0]} {key[1]}"
        rest, mcp = row["rest_v1_twin"], row["mcp_twin"]
        if isinstance(rest, dict):
            twin_key = (rest["method"], canonicalize(rest["path"]))
            if twin_key not in all_extracted:
                errors.append(f"{where} claims rest_v1_twin {twin_key} which is "
                              f"not currently registered")
        if status not in TWINNED_STATUSES:
            continue
        if status == "twinned":
            gap = [n for n, v in (("rest_v1_twin", rest), ("mcp_twin", mcp)) if not v]
            if gap:
                errors.append(f"{where} is status=twinned but {' and '.join(gap)} "
                              f"is missing - plain twinned needs BOTH twins (use "
                              f"twinned-rest-only / twinned-mcp-only if only one "
                              f"exists)")
        else:
            want_rest = status == "twinned-rest-only"
            if bool(rest) != want_rest or bool(mcp) == want_rest:
                errors.append(f"{where} is status={status} but has rest_v1_twin "
                              f"{'set' if rest else 'null'} and mcp_twin "
                              f"{'set' if mcp else 'null'} - it requires exactly "
                              f"{'rest_v1_twin' if want_rest else 'mcp_twin'}")
        if rest and not isinstance(rest, dict):
            errors.append(f"{where} is status={status} but rest_v1_twin is not a "
                          f"{{method, path}} object")
        if mcp and mcp.startswith(RESOURCE_TWIN_PREFIX):
            if mcp[len(RESOURCE_TWIN_PREFIX):] not in mcp_resources:
                errors.append(f"{where} claims mcp_twin {mcp!r} which is not in "
                              f"mcp_server.cpp's kResources[]")
        elif mcp and mcp not in mcp_tools:
            errors.append(f"{where} claims mcp_twin {mcp!r} which is not in "
                          f"the MCP tool catalogue (mcp_server.cpp's kTools[] plus the "
                          f"mcp_tools_*.cpp registry records)")
    return errors


def ratchet_errors(untwinned, generic_planned):
    """Check 4 as a pure function (selftested): both counts are pinned
    BIDIRECTIONALLY. A rise may also mean the baseline was over-lowered."""
    errors = []
    for label, const, actual, baseline, advice in (
            ("untwinned-row count", "BASELINE_UNTWINNED", untwinned,
             BASELINE_UNTWINNED,
             "RATCHET mode forbids this. Wire a real REST/MCP twin, or if this "
             "growth is a deliberate reviewed decision (a newly-discovered "
             "fragment route with no twin yet), raise BASELINE_UNTWINNED in "
             "THIS change"),
            (f"generic {GENERIC_PLANNED_STATUS} row count",
             "BASELINE_GENERIC_PLANNED", generic_planned,
             BASELINE_GENERIC_PLANNED,
             f"this count should never rise: investigate (a merge race, an "
             f"over-lowered constant, or a newly added {GENERIC_PLANNED_STATUS} "
             f"row - name a specific issue, a twin or an exception instead)")):
        if actual > baseline:
            errors.append(f"{label} grew ({baseline} -> {actual}) - {advice}. "
                          f"If you added no rows, {const} was over-lowered "
                          f"earlier: set it to {actual}. Then re-run --render-doc "
                          f"and splice the block.")
        elif actual < baseline:
            errors.append(f"{label} improved ({baseline} -> {actual}) but "
                          f"{const} was not lowered to match - the ratchet "
                          f"would not be sticky (a later regression back to "
                          f"{baseline} would pass). Lower {const} to {actual} "
                          f"in THIS change, then re-run --render-doc and splice "
                          f"the block.")
    return errors


def run_check(ledger_dir=None, doc_path=None, extracted=None, today=None):
    """The CI gate. The keyword arguments let the selftest drive the real
    wiring over a temporary ledger with synthetic extraction; CI passes none.
    `extracted` is (bucket_a, bucket_b, openapi_paths, mcp_tools, mcp_resources);
    `today` pins the revisit-lapse warning's clock."""
    ledger_rows, ledger_errors = load_ledger(ledger_dir)
    if ledger_errors:
        # Reported alone: every later check, above all the ratchet advice, is
        # only meaningful over a well-formed ledger.
        for e in ledger_errors:
            gh("error", f"check-api-parity: {e}")
        gh("error", "check-api-parity: ledger is malformed - the remaining "
                    "checks were skipped; fix the errors above first")
        return 1
    ledger_doc = Path(doc_path) if doc_path is not None else LEDGER_DOC
    if extracted is None:
        try:
            mcp_resources = extract_mcp_resources()
            mcp_tools = extract_mcp_tools()
        except AnchorError as e:
            gh("error", f"check-api-parity: {e}")
            return 1
        bucket_a, bucket_b = extract_all_routes()
        openapi_paths, _spec = extract_openapi_paths()
    else:
        bucket_a, bucket_b, openapi_paths, mcp_tools, mcp_resources = extracted

    ok = True
    # 0. the grandfather set is size-pinned to GRANDFATHERED_MAX (growth and
    #    shrinkage both fail); extend+bump, swap and rebind are review-only.
    for err in stale_grandfather_errors(ledger_rows, GRANDFATHERED_LEGACY_EXCEPTIONS):
        gh("error", f"check-api-parity: {err}")
        ok = False

    # 2d. every strict exception row is identity-pinned; a lapsing revisit date
    #     is ONE aggregated warning, never a failure.
    for err in pin_errors(ledger_rows):
        gh("error", f"check-api-parity: {err}")
        ok = False
    lapse = revisit_lapse_warning(ledger_rows, today or datetime.date.today())
    if lapse:
        gh("warning", f"check-api-parity: {lapse}")
        step_summary(f"### API parity: exception revisit dates\n\n{lapse}\n")

    # 1. every extracted fragment/legacy route must be ledgered.
    unledgered = sorted(set(bucket_a) - set(ledger_rows))
    for method, canon in unledgered:
        sources = bucket_a[(method, canon)]
        gh("error", f"check-api-parity: unledgered route {method} {canon} "
                    f"(registered in {sources[0][0]}) - add a row to "
                    f"scripts/ci/api-parity/<domain>.json. `--bootstrap` writes "
                    f"`planned:#2146`, which the gate no longer lets grow: "
                    f"retag the row with a specific `planned:#N` or a strict "
                    f"`exception:#N revisit:YYYY-MM-DD <reason>` (which also needs "
                    f"its STRICT_EXCEPTION_PINS entry; retagging a row you "
                    f"just bootstrapped brings the generic planned count back to "
                    f"its baseline, so lower BASELINE_GENERIC_PLANNED only when you "
                    f"retag a row the baseline already counted, and a row written "
                    f"directly as an exception leaves it alone) and raise "
                    f"BASELINE_UNTWINNED unless the row is born twinned")
        ok = False

    # 1b. stale ledger rows (route no longer registered) must be marked
    #     retire, not silently left twinned/planned against nothing; a
    #     v1-keyed row must be an `exception:` record (#5342).
    for err in unmatched_ledger_row_errors(ledger_rows, bucket_a, bucket_b):
        gh("error", f"check-api-parity: {err}")
        ok = False

    # 2. twinned rows must reference twins that actually exist, and a
    #    one-sided twin must use its own status, never plain `twinned`.
    all_extracted = set(bucket_a) | set(bucket_b)
    for err in twin_errors(ledger_rows, all_extracted, mcp_tools, mcp_resources):
        gh("error", f"check-api-parity: {err}")
        ok = False

    # 2b. composed-of rows must reference real capability ids in the ledger.
    all_capability_ids = {r["capability_id"] for r in ledger_rows.values()}
    for key, row in ledger_rows.items():
        if not row["status"].startswith("composed-of:"):
            continue
        ids = row["status"][len("composed-of:"):].split(",")
        for cid in ids:
            if cid not in all_capability_ids:
                gh("error", f"check-api-parity: {row['_file']}: {key[0]} {key[1]} "
                            f"composed-of references unknown capability id "
                            f"{cid!r}")
                ok = False

    # 3. every registered v1 route is in OpenAPI or the allowlist.
    allowlist_set = {(m, canonicalize(p)) for m, p, _reason in ALLOWLIST_OPENAPI_MISSING}
    for key in sorted(set(bucket_b) - openapi_paths):
        if key in allowlist_set:
            continue
        gh("error", f"check-api-parity: {key[0]} {key[1]} is registered but "
                    f"missing from openapi_spec()'s paths table, and is not "
                    f"in ALLOWLIST_OPENAPI_MISSING - either document it in "
                    f"the OpenAPI spec (preferred, closes part of F2) or add "
                    f"it to the allowlist with a reason")
        ok = False
    stale_allowlist = sorted(allowlist_set - (set(bucket_b) - openapi_paths))
    for key in stale_allowlist:
        gh("error", f"check-api-parity: ALLOWLIST_OPENAPI_MISSING entry "
                    f"{key[0]} {key[1]} is stale - it is now either "
                    f"documented in OpenAPI or no longer registered; remove "
                    f"it from the allowlist")
        ok = False

    # 4. ratchets on the untwinned-row count and the generic placeholder count.
    untwinned = sum(1 for r in ledger_rows.values() if r["status"] != "twinned")
    generic_planned = sum(1 for r in ledger_rows.values()
                          if r["status"] == GENERIC_PLANNED_STATUS)
    for err in ratchet_errors(untwinned, generic_planned):
        gh("error", f"check-api-parity: {err}")
        ok = False

    # 5. docs/api-parity-ledger.md's generated block must match a fresh
    #    render (same drift class check-capability-matrix.sh runs for
    #    docs/os-capability-matrix.md). Reuses `allowlist_set` from check 3.
    expected_block = render_doc_block(ledger_rows, bucket_b, openapi_paths,
                                       allowlist_set, mcp_tools)
    doc_text = ledger_doc.read_text(encoding="utf-8") if ledger_doc.exists() else ""
    actual_block = extract_doc_block(doc_text)
    if actual_block is None:
        gh("error", f"check-api-parity: {ledger_doc} has no "
                    f"'{DOC_BEGIN[:40]}...' / '{DOC_END}' generated block")
        ok = False
    elif actual_block != expected_block:
        gh("error", f"check-api-parity: {ledger_doc}'s generated block is "
                    f"stale - regenerate with `python3 scripts/ci/"
                    f"check-api-parity.py --render-doc` and splice it "
                    f"between the BEGIN/END GENERATED markers")
        ok = False

    if ok:
        print(f"check-api-parity: OK ({len(ledger_rows)} ledger rows, "
              f"{untwinned} untwinned == baseline {BASELINE_UNTWINNED}, "
              f"{generic_planned} generic {GENERIC_PLANNED_STATUS} == baseline "
              f"{BASELINE_GENERIC_PLANNED}; "
              f"{len(bucket_b)} v1 routes, {len(openapi_paths)} OpenAPI "
              f"entries, {len(allowlist_set)} allowlisted; {len(mcp_tools)} "
              f"MCP tools, {len(mcp_resources)} MCP resources)")
    return 0 if ok else 1


def dump_json():
    bucket_a, bucket_b = extract_all_routes()
    openapi_paths, _spec = extract_openapi_paths()
    mcp_tools = extract_mcp_tools()
    mcp_resources = extract_mcp_resources()
    out = {
        "fragments_and_legacy_api": sorted(f"{m} {p}" for m, p in bucket_a),
        "api_v1": sorted(f"{m} {p}" for m, p in bucket_b),
        "openapi_paths": sorted(f"{m} {p}" for m, p in openapi_paths),
        "mcp_tools": sorted(mcp_tools),
        "mcp_resources": sorted(mcp_resources),
        "counts": {
            "fragments_and_legacy_api": len(bucket_a),
            "api_v1": len(bucket_b),
            "openapi_paths": len(openapi_paths),
            "mcp_tools": len(mcp_tools),
            "mcp_resources": len(mcp_resources),
            "api_v1_missing_from_openapi": len(set(bucket_b) - openapi_paths),
        },
    }
    print(json.dumps(out, indent=2))
    return 0


def baseline_inventory():
    ledger_rows, ledger_errors = load_ledger()
    if ledger_errors:
        return _malformed_ledger_exit("--baseline-inventory", ledger_errors)
    bucket_a, bucket_b = extract_all_routes()
    openapi_paths, _spec = extract_openapi_paths()
    untwinned = sum(1 for r in ledger_rows.values() if r["status"] != "twinned")
    missing = sorted(set(bucket_b) - openapi_paths)
    allowlist_set = {(m, canonicalize(p)) for m, p, _r in ALLOWLIST_OPENAPI_MISSING}
    print(f"fragments/legacy routes extracted : {len(bucket_a)}")
    print(f"ledger rows                       : {len(ledger_rows)}")
    print(f"untwinned rows                     : {untwinned} "
          f"(baseline {BASELINE_UNTWINNED})")
    print(f"generic {GENERIC_PLANNED_STATUS} rows           : "
          f"{sum(1 for r in ledger_rows.values() if r['status'] == GENERIC_PLANNED_STATUS)} "
          f"(baseline {BASELINE_GENERIC_PLANNED})")
    print(f"api/v1 routes extracted            : {len(bucket_b)}")
    print(f"openapi paths                      : {len(openapi_paths)}")
    print(f"api/v1 missing from openapi        : {len(missing)} "
          f"({len(allowlist_set)} allowlisted, "
          f"{len(set(missing) - allowlist_set)} unallowlisted)")
    return 0


def _selftest_body():
    """Unit-tests the extraction/parsing/canonicalization logic itself against
    synthetic fixtures, per this repo's established precedent for CI tooling
    scripts of this shape (flake-retry.py, check-plugin-spawn-lexical.sh,
    tsan-gdb-capture.py all carry --selftest; #3443 is the governance finding
    that made it a standing expectation). Targets, in particular, the two
    concrete false-negative shapes this script has already shipped once each:
    a receiver-notation blind spot (dot-only vs `->`, the #3991 BLOCKING-1
    fix) and an adjacent-string-literal blind spot (the Doomgoose #4003
    review finding) - both are exactly the "route registration silently
    produces no requirement and no warning" failure class this script exists
    to prevent in the PRODUCT, and neither would be caught by running the
    script against the real tree, since the real tree doesn't (yet) contain
    either shape. Runs no filesystem I/O against the real source tree."""
    import contextlib
    import io
    import tempfile

    failures = []

    def check(cond, label):
        if not cond:
            failures.append(label)

    @contextlib.contextmanager
    def _patched(**kv):
        """Temporarily rebinds module globals so a fixture isolates one defect."""
        g = globals()
        saved = {k: g[k] for k in kv}
        g.update(kv)
        try:
            yield
        finally:
            g.update(saved)

    # -- parse_literal_at: the two literal forms it must recognise --------
    lit, end = parse_literal_at('"/api/v1/foo"', 0)
    check(lit == "/api/v1/foo", f"parse_literal_at: plain string, got {lit!r}")
    lit, end = parse_literal_at('R"(/api/v1/(bar)/baz)"', 0)
    check(lit == "/api/v1/(bar)/baz", f"parse_literal_at: raw string, got {lit!r}")
    lit, end = parse_literal_at('R"json({"a":1})json"', 0)
    check(lit == '{"a":1}', f"parse_literal_at: custom raw-string delimiter, got {lit!r}")
    lit, end = parse_literal_at("not_a_literal", 0)
    check(lit is None, "parse_literal_at: non-literal input must return None")
    lit, end = parse_literal_at(r'"esc\"aped"', 0)
    check(lit == 'esc"aped', f"parse_literal_at: escaped quote, got {lit!r}")

    # -- parse_adjacent_literals: the Doomgoose #4003 finding --------------
    # Two plain literals split at the natural version-prefix boundary - the
    # exact reported bypass (previously silently truncated to "/api/v1").
    lit, _end = parse_adjacent_literals('"/api/v1" "/route", h)', 0)
    check(lit == "/api/v1/route",
          f"parse_adjacent_literals: two plain literals must concatenate, got {lit!r}")
    # Raw string followed by a plain literal (mixed forms).
    lit, _end = parse_adjacent_literals('R"(/api/v1/foo)" "/bar", h)', 0)
    check(lit == "/api/v1/foo/bar",
          f"parse_adjacent_literals: raw+plain must concatenate, got {lit!r}")
    # Three-way split.
    lit, _end = parse_adjacent_literals('"/api" "/v1" "/three", h)', 0)
    check(lit == "/api/v1/three",
          f"parse_adjacent_literals: three-way split must concatenate, got {lit!r}")
    # A single literal (the common case) must still work unchanged.
    lit, _end = parse_adjacent_literals('"/api/v1/simple", h)', 0)
    check(lit == "/api/v1/simple",
          f"parse_adjacent_literals: single literal regressed, got {lit!r}")
    # A comment between two adjacent literals (legal C++) must not break it.
    lit, _end = parse_adjacent_literals('"/api/v1" // note\n"/commented", h)', 0)
    check(lit == "/api/v1/commented",
          f"parse_adjacent_literals: comment-separated literals, got {lit!r}")

    # -- extract_verb_calls: both known false-negative shapes, end-to-end -
    # Shape 1 (#3991 BLOCKING-1): arrow-notation receiver, not just dot.
    calls = list(extract_verb_calls('web_server_->Get("/api/legacy", h);', "s.cpp"))
    check(calls == [("GET", "/api/legacy")],
          f"extract_verb_calls: arrow-notation receiver, got {calls}")
    # Shape 2 (#4003 review): adjacent-literal split must not silently vanish.
    calls = list(extract_verb_calls('sink.Post("/api/v1" "/split", h);', "s.cpp"))
    check(calls == [("POST", "/api/v1/split")],
          f"extract_verb_calls: adjacent-literal call site, got {calls}")
    # A genuinely non-literal first argument on a route-sink receiver must
    # still be reported (never silently dropped) - this is `gh("warning",
    # ...)`, which prints rather than raising, so we only check it doesn't
    # crash and doesn't yield a route.
    calls = list(extract_verb_calls('sink.Get(kSomeConstant, h);', "s.cpp"))
    check(calls == [], "extract_verb_calls: non-literal first arg must yield nothing")
    # The known httplib::Client false-positive exemption must still apply.
    calls = list(extract_verb_calls('client.Get(url_var, h);', "s.cpp"))
    check(calls == [], "extract_verb_calls: known client receiver must be silently skipped")

    # -- canonicalize: paren-masking must not let a capture group's own '/'
    #    cause a wrong split, and must collapse both capture groups and
    #    {param}-style OpenAPI segments to the same token. -----------------
    check(canonicalize("/api/v1/tags/([^/]+)/([^/]+)") == "/api/v1/tags/{param}/{param}",
          "canonicalize: two capture groups")
    check(canonicalize("/api/v1/result-sets/{id}") == "/api/v1/result-sets/{param}",
          "canonicalize: OpenAPI {id}-style segment")
    check(canonicalize("/api/v1/plain") == "/api/v1/plain",
          "canonicalize: no-capture-group path is unchanged")

    # -- unmatched_ledger_row_errors: check 1b's legal shapes (#5342) -------
    def _row(status):
        return {"status": status, "_file": "x.json"}
    frag = ("GET", "/fragments/a")
    v1 = ("POST", "/api/v1/users/me/password")
    gone = ("GET", "/fragments/gone")
    errs = unmatched_ledger_row_errors(
        {frag: _row("planned:#1"), v1: _row("exception:no MCP twin"), gone: _row("retire")},
        {frag: []}, {v1: []})
    check(errs == [], f"1b: fragment/v1-exception/retire rows must be clean, got {errs}")
    errs = unmatched_ledger_row_errors({v1: _row("twinned")}, {}, {v1: []})
    check(len(errs) == 1 and "REST v1" in errs[0],
          f"1b: a v1-keyed row that is not exception: must be an error, got {errs}")
    errs = unmatched_ledger_row_errors({gone: _row("exception:x")}, {}, {})
    check(len(errs) == 1 and "retire" in errs[0],
          f"1b: an exception row on an UNREGISTERED route must still be stale, got {errs}")

    # -- status_errors: strict exception shape + grandfather set (#5955) ----
    span = REVISIT_MAX - REVISIT_MIN
    day_a = REVISIT_MIN + span // 3  # every fixture date derives from the window
    one_day = datetime.timedelta(days=1)
    gf = frozenset({"legacy.id"})
    strict = f"exception:#5955 revisit:{day_a} UI-only fragment"
    for ok_status in (strict, "twinned", "twinned-rest-only", "twinned-mcp-only", "retire",
                      "planned:#2146", "planned:#99", "composed-of:a.b,c-d",
                      f"exception:#7 revisit:{REVISIT_MIN} r", f"exception:#7 revisit:{REVISIT_MAX} r",
                      f"exception:#999999999 revisit:{day_a} r", f"exception:#7 revisit:{day_a} \u200bx",
                      f"exception:#7 revisit:{day_a} .",
                      "exception:#520 revisit:2027-04-30 r", "exception:#2102 revisit:2027-01-13 r",
                      "exception:#5357 revisit:2027-01-04 r"):
        check(status_errors(ok_status, "new.id", gf) == [], f"status: {ok_status!r} must be accepted")
    bad_head = f"exception:#7 revisit:{day_a} "
    for bad in ("exception:no issue or date", "x" + strict, f"exception:#5955 revisit:{day_a}",
                "exception:#5955 revisit:2026-13-45 r", "exception:#5955 revisit:9999-12-31 r",
                "exception:#5955 revisit:20261130 r", "exception:#5955 revisit:soon r",
                "exception:#5955 revisit:2026-W44-1 r", f"exception:#7 revisit:{REVISIT_MAX + one_day} r",
                f"exception:#7 revisit:{REVISIT_MIN - one_day} r", f"exception:# revisit:{day_a} r",
                f"exception:#0 revisit:{day_a} r", f"exception:#05955 revisit:{day_a} r",
                f"exception:#\u0665 revisit:{day_a} r", f"exception:#5\u0665 revisit:{day_a} r",
                f"exception:#7revisit:{day_a} r", f"exception:#7 revisit:{day_a}r",
                f"exception:#{'9' * 5000} revisit:{day_a} r", f"exception:#1000000000 revisit:{day_a} r",
                f"exception:#2146 revisit:{day_a} r", strict + "\n", "twinned\n", "planned:#2146\n",
                "planned:#0", "twinned-both") + tuple(
                bad_head + ch for ch in ("", "   ", "\u200b\u200b", "\u0301", "\x01", "\u0378",
                                         "\n", "\u2028", "\ue000", "\u20dd", "\u2800", "\u115f", "\u1160",
                                         "\u3164", "\uffa0")):
        check(len(status_errors(bad, "new.id", gf)) == 1, f"status: {bad[:80]!r} must be rejected")
    check(status_errors("exception:#520", "legacy.id", gf) == [], "status: a grandfathered legacy exception is accepted")
    errs = status_errors("exception:#520", "other.id", gf)
    check(len(errs) == 1 and "do NOT extend" in errs[0], f"status: a legacy-shaped exception outside the set, got {errs}")
    check(len(status_errors(None, "x", gf)) == 1, "status: a non-string status must be rejected without raising")

    def _lrow(cid, status):
        return {"capability_id": cid, "status": status, "_file": "x.json"}
    with _patched(GRANDFATHERED_MAX=1):
        check(stale_grandfather_errors({("GET", "/a"): _lrow("legacy.id", "exception:#520")}, gf) == [],
              "grandfather: a live legacy row is clean")
        for label, rows_g in (("gone", {}), ("converted", {("GET", "/a"): _lrow("legacy.id", "twinned")}),
                              ("already strict", {("GET", "/a"): _lrow("legacy.id", strict)})):
            check(len(stale_grandfather_errors(rows_g, gf)) == 1, f"grandfather: a {label} id must be stale")
        errs = stale_grandfather_errors({("GET", "/a"): _lrow("legacy.id", "exception:#520"),
                                         ("GET", "/b"): _lrow("legacy.two", "exception:#520")},
                                        frozenset({"legacy.id", "legacy.two"}))
        check(errs == ["GRANDFATHERED_LEGACY_EXCEPTIONS grew (2 ids, GRANDFATHERED_MAX 1): remove the added "
                       "id(s); GRANDFATHERED_MAX is never raised"], f"grandfather: growth text, got {errs}")
    with _patched(GRANDFATHERED_MAX=1):
        # n > MAX with a strict id: never advise raising/lowering the max.
        errs = stale_grandfather_errors({("GET", "/a"): _lrow("legacy.id", strict),
                                         ("GET", "/b"): _lrow("legacy.two", "exception:#520")},
                                        frozenset({"legacy.id", "legacy.two"}))
        check(len(errs) == 2 and "leave GRANDFATHERED_MAX alone" in errs[1]
              and "lower GRANDFATHERED_MAX" not in " ".join(errs), f"grandfather: grow + strict id text, got {errs}")
        for rows_g in ({}, {("GET", "/a"): _lrow("legacy.id", strict)}):
            errs = stale_grandfather_errors(rows_g, gf)
            check(len(errs) == 1 and "lower GRANDFATHERED_MAX to 0 in THIS change" in errs[0],
                  f"grandfather: stale-id advice at n <= MAX, got {errs}")
    with _patched(GRANDFATHERED_MAX=3):
        errs = stale_grandfather_errors({("GET", "/a"): _lrow("legacy.id", "exception:#520")}, gf)
        check(len(errs) == 1 and "lower GRANDFATHERED_MAX to 1 in THIS change" in errs[0],
              f"grandfather: shrink text, got {errs}")
    # One target size in EVERY message, computed from all stale ids (n - stale), sorted by id.
    live = {("GET", "/l"): _lrow("l.id", "exception:#520")}
    for mx, ids_, rows_g, want in ((3, "abc", {}, "0"), (5, "lbc", live, "1"), (5, "lb", live, "1")):
        sset = frozenset(f"{i}.id" for i in ids_)
        with _patched(GRANDFATHERED_MAX=mx):
            errs = stale_grandfather_errors(rows_g, sset)
        per_id = [e for e in errs if " id '" in e]
        check(len(per_id) == sum(1 for i in sset if i not in {"l.id"}) and all(
              f"lower GRANDFATHERED_MAX to {want} in THIS change" in e for e in errs),
              f"grandfather: every message targets {want} (MAX {mx}, ids {ids_}), got {errs}")
    with _patched(GRANDFATHERED_MAX=2):
        errs = stale_grandfather_errors({}, frozenset({"z.id", "a.id"}))
    check([e.split("'")[1] for e in errs] == ["a.id", "z.id"], f"grandfather: stale ids are reported sorted, got {errs}")
    check(len(GRANDFATHERED_LEGACY_EXCEPTIONS) == GRANDFATHERED_MAX, "constants: the real set matches its pinned size")

    # -- row_shape_error: hostile rows never raise ---------------------------
    good = {"method": "GET", "path": "/p", "capability_id": "g.p", "rest_v1_twin": None,
            "mcp_twin": None, "status": "retire"}
    check(row_shape_error(good) is None, "shape: a good row is clean")
    check(row_shape_error(dict(good, rest_v1_twin={"method": "GET", "path": "/x"}, mcp_twin="t")) is None,
          "shape: object rest twin + string mcp twin is clean")
    check(row_shape_error(dict(good, rest_v1_twin="POST /api/v1/x")) is None, "shape: a documentary string twin is clean")
    for bad_row, needle in (("a string", "JSON object"), (None, "JSON object"), ([1], "JSON object"),
                            ({"method": "GET"}, "missing"), (dict(good, path=None), "must be strings"),
                            (dict(good, capability_id=7), "must be strings"),
                            (dict(good, rest_v1_twin=5), "rest_v1_twin"), (dict(good, rest_v1_twin=["GET"]), "rest_v1_twin"),
                            (dict(good, rest_v1_twin={"method": "GET"}), "rest_v1_twin"),
                            (dict(good, rest_v1_twin={"method": 1, "path": "/x"}), "rest_v1_twin"),
                            (dict(good, mcp_twin=7), "mcp_twin"), (dict(good, mcp_twin={"a": 1}), "mcp_twin"),
                            (dict(good, method="get"), "upper-case"), (dict(good, method="GE T"), "upper-case"),
                            (dict(good, method=""), "upper-case"), (dict(good, method="G\u0415T"), "upper-case"),
                            (dict(good, method="GET\n::error::injected"), "upper-case"),
                            (dict(good, method="A" * 17), "upper-case"),
                            (dict(good, path="/x\n::error::injected"), "path must be"), (dict(good, path=""), "path must be"),
                            (dict(good, path="/x y"), "path must be"), (dict(good, path="/" + "a" * 200), "path must be"),
                            (dict(good, path="/x\u0435"), "path must be"),
                            (dict(good, rest_v1_twin={"method": "GET", "path": "/x\n::error::x"}), "rest_v1_twin path"),
                            (dict(good, rest_v1_twin={"method": "get", "path": "/x"}), "rest_v1_twin method"),
                            (dict(good, rest_v1_twin={"method": "GET\n::error::x", "path": "/x"}), "rest_v1_twin method")):
        err = row_shape_error(bad_row)
        check(err is not None and needle in err, f"shape: {bad_row!r} must be rejected with {needle!r}, got {err}")

    # -- parse_mcp_resources: fixed entries only, comments ignored ----------
    res = parse_mcp_resources(
        'static const ResourceDef kResources[] = {\n    {"yuzu://a", "A", "d", "m"},\n'
        '    /* {"yuzu://hidden", "H", "d", "m"}, */\n    // {"yuzu://hidden2", "H", "d", "m"},\n'
        '    /* multi-line\n       {"yuzu://hidden3", "H", "d", "m"},\n    */\n'
        '    {\n        "yuzu://b", "B", "see http://x // not a comment", "m"},\n};\n'
        'static const ResourceTemplateDef kResourceTemplates[] = {\n    {"yuzu://t/{n}", "T", "d", "m"},\n};\n')
    check(res == {"yuzu://a", "yuzu://b"}, f"resources: comments and templates are excluded, got {res}")
    res = parse_mcp_resources(
        'static const ResourceDef kResources[] = {\n'
        '    /* #if 0 */\n    {"yuzu://a", "A", "d", "m"},\n'
        '    // #if 0\n    {"yuzu://b", "B", "d", "m"},\n'
        '/* note:\n#if 0\n*/\n    {"yuzu://c", "C", "d", "m"},\n'
        '    {"yuzu://d", 1\'000}, // {"yuzu://dead", 1} it\'s\n};\n')
    check(res == {"yuzu://a", "yuzu://b", "yuzu://c", "yuzu://d"},
          f"resources: a comment may mention a directive, and an apostrophe in a comment or number is not special, got {res}")
    for directive in ("#if 0", "  #  ifdef NEVER", "#define X 1", "\t#endif", "/* c */ #if 0", "%:if 0", "  %: define X"):
        try:
            parse_mcp_resources('static const ResourceDef kResources[] = {\n    {"yuzu://a", "A"},\n'
                                + directive + '\n    {"yuzu://b", "B"},\n};\n')
            check(False, f"resources: the directive {directive!r} must raise AnchorError")
        except AnchorError as e:
            check("preprocessor line" in str(e) and "kResources[]" in str(e) and "row 3" in str(e),
                  f"resources: the error must name the array and line, got {e}")
    with tempfile.TemporaryDirectory(prefix="yuzu_test_api_parity_") as dk:
        kcpp = Path(dk) / "mcp_server.cpp"
        for directive in ("#if 0", "#ifdef NEVER", "  #  define X 1", "/* c */ #if 0", "%:if 0"):
            kcpp.write_text('static const ToolDef kTools[] = {\n    {"live_tool", "d"},\n' + directive
                            + '\n    {"dead_tool", "d"},\n#endif\n};\n', encoding="utf-8")
            try:
                with _patched(MCP_SERVER_CPP=kcpp):
                    extract_mcp_tools()
                check(False, f"tools: the directive {directive!r} must raise AnchorError")
            except AnchorError as e:
                check("preprocessor line" in str(e) and "kTools[]" in str(e) and "row 3" in str(e),
                      f"tools: the error must name the array and the line, got {e}")
        kcpp.write_text('static const ToolDef kTools[] = {\n    {"a", "d"},\n/* x\n*/ #if 0\n    {"b", "d"},\n#endif\n};\n', encoding="utf-8")
        try:
            with _patched(MCP_SERVER_CPP=kcpp):
                extract_mcp_tools()
            check(False, "tools: a directive after the tail of a block comment must raise AnchorError")
        except AnchorError as e:
            check("row 4" in str(e), f"tools: the error must give the row of the directive, got {e}")
        kcpp.write_text('static const ToolDef kTools[] = {\n    {"a", "d"},\n/*\n#if 0\n*/\n};\n', encoding="utf-8")
        check(_PP_LINE.match("/**/ " * 3000 + "x") is None and _PP_LINE.match("/*" * 3000 + "x") is None,
              "directive pattern: a long run of comments with no directive must not match (and must not backtrack)")
        check(_PP_LINE.match("*/ %:if 0") and _PP_LINE.match(" * b */ #if 0") and _PP_LINE.match("/* a */ /* b */ #if 0") and not _PP_LINE.match("/* a */ x #if 0"),
              "directive pattern: text before the closing '*/' of a multi-line comment may precede a directive; code after it may not")
        kcpp.write_text('static const ToolDef kTools[] = {\n    {"a", "d"},\n/* a\n b */ #if 0\n    {"b", "d"},\n#endif\n};\n', encoding="utf-8")
        try:
            with _patched(MCP_SERVER_CPP=kcpp):
                extract_mcp_tools()
            check(False, "tools: a directive after the tail line of a multi-line comment must raise")
        except AnchorError as e:
            check("row 4" in str(e), f"tools: the error must give the row of the directive, got {e}")
        check(_PP_LINE.match("/* a */ */ #if 0") and _PP_LINE.match("%:if 0") and not _PP_LINE.match("/* a */ || #"),
              "directive pattern: comments, a comment tail and the %: digraph precede a directive; code does not")
        try:
            with _patched(MCP_SERVER_CPP=kcpp):
                extract_mcp_tools()
            check(False, "tools: kTools[] is not comment-stripped, so '#if 0' inside a block comment must raise")
        except AnchorError as e:
            check("kTools[]" in str(e), f"tools: the error must name the array, got {e}")
        kcpp.write_text('static const ToolDef kTools[] = {\n    {"a", "d"},\n    // #if 0 is only a comment\n};\n',
                        encoding="utf-8")
        with _patched(MCP_SERVER_CPP=kcpp):
            tools_found = extract_mcp_tools()
        check(tools_found == {"a"}, f"tools: a comment line that mentions a directive is not a directive line, got {tools_found}")
        for label_a, body_a, fn_a, needle_a in (
                ("tools", 'static const ToolDef kTools[] = {\n    {"a", "d"},\n};\n// static const ToolDef kTools[] = {\n',
                 extract_mcp_tools, "kTools[] declaration appears 2 times"),
                ("resources", 'static const ResourceDef kResources[] = {\n    {"yuzu://a", "A"},\n};\n#if 0\n'
                              'static const ResourceDef kResources[] = {\n    {"yuzu://old", "O"},\n};\n#endif\n',
                 extract_mcp_resources, "kResources[] declaration appears 2 times")):
            kcpp.write_text(body_a, encoding="utf-8")
            try:
                with _patched(MCP_SERVER_CPP=kcpp):
                    fn_a()
                check(False, f"anchor: a second {label_a} declaration must raise AnchorError")
            except AnchorError as e:
                check(needle_a in str(e), f"anchor: the {label_a} ambiguity error must say so, got {e}")
    for bad_cpp, why in (("int x;\n", "was not found"),
                         ("static const ResourceDef kResources[] = {\n};\n", "zero entries")):
        try:
            parse_mcp_resources(bad_cpp)
            check(False, "resources: an anchor miss must raise AnchorError")
        except AnchorError as e:
            check("kResources[]" in str(e) and why in str(e),
                  f"resources: the error must name the symbol and say {why!r}, got {e}")

    # -- registry-resident tools: kTools[] UNION every mcp_tools_*.cpp kToolRecords[] -----------
    def _rec(*names):
        """A registry file body shaped like the real ones: the array in an anonymous namespace,
        each record opening `    {"name",` (4 spaces) and closing at column 0 with `};`."""
        rows = "".join(f'    {{"{n}",\n        "d", R"({{}})", R"({{}})", "Infrastructure", "Read",\n'
                       f'        ServiceScopeClass::denied, ToolEffect::read_only, true, "T", &handle_{n}}},\n'
                       for n in names)
        return f'namespace {{\nconstexpr ToolRecord kToolRecords[] = {{\n{rows}}};\n}}  // namespace\n'

    def _reg_extract(ktools_body, files, floor=0):
        """extract_mcp_tools() over a patched mcp_server.cpp + a patched registry dir."""
        with tempfile.TemporaryDirectory(prefix="yuzu_test_api_parity_") as dr:
            (Path(dr) / "mcp_server.cpp").write_text(ktools_body, encoding="utf-8")
            reg = Path(dr) / "reg"
            reg.mkdir()
            for fname, body in files.items():
                (reg / fname).write_text(body, encoding="utf-8")
            with _patched(MCP_SERVER_CPP=Path(dr) / "mcp_server.cpp", MCP_REGISTRY_DIR=reg, MIN_REGISTRY_FILES=floor):
                return extract_mcp_tools()

    kt = 'static const ToolDef kTools[] = {\n    {"legacy_a", "d"},\n    {"legacy_b", "d"},\n};\n'
    got = _reg_extract(kt, {})
    check(got == {"legacy_a", "legacy_b"}, f"registry: no registry file leaves exactly the kTools[] set, got {got}")
    got = _reg_extract(kt, {"mcp_tools_one.cpp": _rec("reg_x", "reg_y"), "mcp_tools_two.cpp": _rec("reg_z"),
                            "mcp_tools_orphan.hpp": _rec("legacy_a"), "mcp_other.cpp": _rec("legacy_a")})
    check(got == {"legacy_a", "legacy_b", "reg_x", "reg_y", "reg_z"},
          f"registry: the union covers every mcp_tools_*.cpp file and ignores other names, got {got}")
    for label, files, needles in (
            ("dup-across-files", {"mcp_tools_one.cpp": _rec("reg_x"), "mcp_tools_two.cpp": _rec("reg_x")},
             ("reg_x", "declared twice", "mcp_tools_one.cpp", "mcp_tools_two.cpp")),
            ("dup-within-file", {"mcp_tools_one.cpp": _rec("reg_x", "reg_x")},
             ("reg_x", "declared twice", "mcp_tools_one.cpp")),
            ("collides-with-ktools", {"mcp_tools_one.cpp": _rec("legacy_b")},
             ("legacy_b", "declared twice", "kTools[] in mcp_server.cpp", "mcp_tools_one.cpp")),
            ("zero-records", {"mcp_tools_one.cpp": "constexpr ToolRecord kToolRecords[] = {\n    // nothing\n};\n"},
             ("zero entries", "kToolRecords[]", "mcp_tools_one.cpp")),
            ("no-anchor", {"mcp_tools_one.cpp": "int nothing_here;\n"},
             ("kToolRecords[] was not found", "mcp_tools_one.cpp")),
            ("second-anchor", {"mcp_tools_one.cpp": _rec("reg_x") + "// constexpr ToolRecord kToolRecords[] = {\n"},
             ("kToolRecords[] declaration in mcp_tools_one.cpp appears 2 times",)),
            ("preprocessor-line", {"mcp_tools_one.cpp": _rec("reg_x").replace('    {"reg_x",', '#if 0\n    {"reg_x",')},
             ("preprocessor line", "kToolRecords[]", "mcp_tools_one.cpp", "row 2")),
            ("preprocessor-after-comment", {"mcp_tools_one.cpp": _rec("reg_x").replace('    {"reg_x",', '/* c */ #if 0\n    {"reg_x",')},
             ("preprocessor line", "kToolRecords[]")),
            ("unterminated", {"mcp_tools_one.cpp": 'constexpr ToolRecord kToolRecords[] = {\n    {"reg_x", "d"},\n'},
             ("unterminated", "mcp_tools_one.cpp"))):
        try:
            _reg_extract(kt, files)
            check(False, f"registry: {label} must raise AnchorError")
        except AnchorError as e:
            check(all(n in str(e) for n in needles), f"registry: {label}: error must contain {needles}, got {e}")
    try:
        _reg_extract(kt, {}, floor=1)
        check(False, "registry: fewer files than MIN_REGISTRY_FILES must raise AnchorError")
    except AnchorError as e:
        check("at least 1" in str(e), f"registry: the floor error must state the floor, got {e}")
    try:
        _reg_extract('static const ToolDef kTools[] = {\n    // nothing\n};\n', {"mcp_tools_one.cpp": _rec("reg_x")})
        check(False, "registry: an empty kTools[] must still raise even when a registry file has tools")
    except AnchorError as e:
        check("kTools[]" in str(e) and "zero entries" in str(e), f"registry: kTools[] emptiness stays its own error, got {e}")

    # -- twin_errors: one-sided twins, canonicalization, any-status rest twin
    def _trow(status, rest, mcp):
        return {"status": status, "_file": "x.json", "rest_v1_twin": rest, "mcp_twin": mcp}
    def _rt(path):
        return {"method": "GET", "path": path}
    rest_tw = _rt("/api/v1/a")
    routes, tools, resources = {("GET", "/api/v1/a"), ("GET", "/api/v1/tags/{param}")}, {"a_tool"}, {"yuzu://r"}
    k = ("GET", "/fragments/a")
    for status, rest, mcp, needle in (
            ("twinned", rest_tw, "a_tool", None), ("twinned", rest_tw, "resource:yuzu://r", None),
            ("twinned-rest-only", rest_tw, None, None), ("twinned-mcp-only", None, "a_tool", None),
            ("twinned", _rt("/api/v1/tags/{id}"), "a_tool", None),
            ("twinned", _rt("/api/v1/tags/([^/]+)"), "a_tool", None),
            ("twinned", rest_tw, None, "plain twinned needs BOTH"),
            ("twinned", None, "a_tool", "rest_v1_twin is missing"),
            ("twinned", None, None, "rest_v1_twin and mcp_twin is missing"),
            ("twinned-rest-only", rest_tw, "a_tool", "requires exactly rest_v1_twin"),
            ("twinned-rest-only", None, "a_tool", "requires exactly rest_v1_twin"),
            ("twinned-rest-only", None, None, "requires exactly rest_v1_twin"),
            ("twinned-mcp-only", rest_tw, "a_tool", "requires exactly mcp_twin"),
            ("twinned-mcp-only", None, None, "requires exactly mcp_twin"),
            ("twinned", rest_tw, "resource:yuzu://gone", "kResources"), ("twinned", rest_tw, "gone_tool", "kTools"),
            ("twinned", rest_tw, "yuzu://r", "kTools"), ("twinned", _rt("/api/v1/tags"), "a_tool", "not currently registered"),
            ("twinned-rest-only", "GET /api/v1/a", None, "not a {method, path} object"),
            ("exception:#520 revisit:2027-01-01 r", rest_tw, None, None),
            ("exception:#520 revisit:2027-01-01 r", _rt("/api/v1/gone"), None, "not currently registered"),
            ("exception:#520", "POST /api/v1/gone", None, None)):
        errs = twin_errors({k: _trow(status, rest, mcp)}, routes, tools, resources)
        check((not errs) if needle is None else (len(errs) == 1 and needle in errs[0]),
              f"twin: {status[:20]} rest={rest!r} mcp={mcp!r}: want {needle!r}, got {errs}")

    # -- ratchet_errors: both pins are bidirectional ------------------------
    with _patched(BASELINE_UNTWINNED=10, BASELINE_GENERIC_PLANNED=4):
        check(ratchet_errors(10, 4) == [], "ratchet: equal counts are clean")
        for u, g, text in ((11, 4, "BASELINE_UNTWINNED"), (9, 4, "Lower BASELINE_UNTWINNED to 9"),
                           (10, 5, "should never rise"), (10, 3, "Lower BASELINE_GENERIC_PLANNED to 3")):
            errs = ratchet_errors(u, g)
            check(len(errs) == 1 and text in errs[0] and "re-run --render-doc" in errs[0],
                  f"ratchet: ({u},{g}) want {text!r} and the splice hint, got {errs}")
        check("over-lowered" in ratchet_errors(10, 5)[0] and "investigate" in ratchet_errors(10, 5)[0],
              "ratchet: a planned rise says investigate and mentions over-lowering")

    # -- run_check wiring over a temporary ledger (positive control) --------
    def _mk(name, status, **kw):
        path = f"/fragments/{name}"
        row = {"method": "GET", "path": path, "capability_id": capability_id_for("GET", path),
               "rest_v1_twin": None, "mcp_twin": None, "status": status}
        row.update(kw)
        return row

    # A synthetic allowlist (not the real one) so the control cannot pass by accident.
    synthetic_allow = [("OPTIONS", "/api/v1/{param}", "synthetic"),
                       ("GET", "/api/v1/synthetic-undocumented", "synthetic")]
    opt_key = ("OPTIONS", canonicalize("/api/v1/{param}"))
    undoc_key = ("GET", "/api/v1/synthetic-undocumented")

    def _drive(rows, patch=None, doc="ok", synthetic=True, extra_files=None, tweak=None, skip_domains=(), today=None):
        """Writes a ledger dir, tunes the baselines, grandfather set and the
        OpenAPI allowlist to the synthetic ledger (then applies `patch`, the
        one defect under test), renders the matching generated doc, and runs
        the REAL run_check. `doc` is ok/missing/stale; `tweak` may mutate
        (bucket_a, bucket_b, openapi) before the doc is rendered."""
        legacy = frozenset(r["capability_id"] for r in rows if isinstance(r, dict)
                           and isinstance(r.get("status"), str)
                           and r["status"].startswith("exception:") and not parse_exception(r["status"]))
        with tempfile.TemporaryDirectory(prefix="yuzu_test_api_parity_") as d:
            for dom in DOMAINS:
                if dom not in skip_domains:
                    (Path(d) / f"{dom}.json").write_text(json.dumps(rows if dom == "other" else []), encoding="utf-8")
            for name, body in (extra_files or {}).items():
                (Path(d) / name).write_bytes(body if isinstance(body, bytes) else body.encode("utf-8"))
            with _patched(GRANDFATHERED_LEGACY_EXCEPTIONS=legacy, GRANDFATHERED_MAX=len(legacy)):
                loaded, load_errs = load_ledger(d)
            tuned, extracted = {}, None
            if not load_errs:
                tuned = {"BASELINE_UNTWINNED": sum(1 for r in loaded.values() if r["status"] != "twinned"),
                         "BASELINE_GENERIC_PLANNED": sum(1 for r in loaded.values()
                                                         if r["status"] == GENERIC_PLANNED_STATUS),
                         "GRANDFATHERED_LEGACY_EXCEPTIONS": legacy, "GRANDFATHERED_MAX": len(legacy),
                         "STRICT_EXCEPTION_PINS": {r["capability_id"]: parse_exception(r["status"])[:2]
                                                   for r in loaded.values() if parse_exception(r["status"])}}
                a_, b_, o_ = ({k_: [("s.cpp", k_[1])] for k_, r in loaded.items() if r["status"] != "retire"},
                              {("GET", "/api/v1/a"): [], opt_key: [], undoc_key: []}, {("GET", "/api/v1/a")})
                if tweak:
                    tweak(a_, b_, o_)
                extracted = (a_, b_, o_, tools, resources)
            tuned.update(patch or {})
            tuned["ALLOWLIST_OPENAPI_MISSING"] = synthetic_allow
            doc_path = Path(d) / "ledger.md"
            err = io.StringIO()
            with _patched(**tuned):
                if extracted and doc != "missing":
                    allow = {(m, canonicalize(p)) for m, p, _r in synthetic_allow}
                    block = render_doc_block(loaded, extracted[1], extracted[2], allow, tools)
                    doc_path.write_text(block.replace("| **Total**", "| **Total (old)**") if doc == "stale" else block,
                                        encoding="utf-8")
                with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                    rc = run_check(ledger_dir=d, doc_path=doc_path, extracted=extracted if synthetic else None,
                                   today=today)
            return rc, err.getvalue()

    def expect(label, result, rc, *needles, absent=()):
        got, out = result
        check(got == rc and all(n in out for n in needles) and not any(a in out for a in absent)
              and "Traceback" not in out, f"drive({label}): want rc={rc} with {needles}, got rc={got}: {out[:300]}")

    pl = _mk("pl", GENERIC_PLANNED_STATUS)
    base_rows = [_mk("tw", "twinned", rest_v1_twin=rest_tw, mcp_twin="a_tool"),
                 _mk("twr", "twinned", rest_v1_twin=rest_tw, mcp_twin="resource:yuzu://r"),
                 _mk("ro", "twinned-rest-only", rest_v1_twin=rest_tw), pl, _mk("pl99", "planned:#99"),
                 _mk("co", "composed-of:" + pl["capability_id"]),
                 _mk("leg", "exception:#520 free-form legacy text"),
                 _mk("s1", f"exception:#5955 revisit:{day_a} ui-only"),
                 _mk("s2", f"exception:#520 revisit:{day_a} r", rest_v1_twin=rest_tw), _mk("gone", "retire")]
    rc0, out0 = _drive(base_rows)
    check(rc0 == 0 and "::error::" not in out0, f"drive(control): the clean ledger must pass, got {rc0}: {out0[:300]}")

    def _no_a(a, b, o):
        a.pop(("GET", "/api/v1/a"), None)
    def _extra_route(a, b, o):
        a[("GET", "/fragments/not-in-ledger")] = [("s.cpp", "/fragments/x")]
    def _unlisted(a, b, o):
        b[("GET", "/api/v1/new")] = []
    def _no_options(a, b, o):
        b.pop(opt_key, None)
    leg2 = frozenset({"get.fragments-leg"})
    v1_row = _mk("v1x", "planned:#5", path="/api/v1/a", capability_id="get.api-v1-a")
    cases = (  # label, rows, kwargs, needles (each failing case differs from the control by ONE defect)
        ("missing-doc", base_rows, {"doc": "missing"}, ("has no",)),
        ("stale-doc", base_rows, {"doc": "stale"}, ("generated block is stale", "--render-doc")),
        ("bad-status", base_rows + [_mk("bad", "planned:#2146\n")], {}, ("invalid status",)),
        ("dup-id", base_rows + [_mk("a-b", "retire"), _mk("a/b", "retire")], {}, ("duplicate capability_id",)),
        ("dup-key", base_rows + [_mk("tw", "retire")], {}, ("duplicate ledger key",)),
        ("derived-id", base_rows + [_mk("zz", "retire", capability_id="get.fragments-s1")], {},
         ("must be 'get.fragments-zz'",)),
        ("malformed", ["not an object", _mk("n", None), dict(_mk("p", "retire"), path=None)], {},
         ("must be a JSON object", "status must be a string", "must be strings")),
        ("twin-dict-fields", base_rows + [_mk("t4", "retire", rest_v1_twin={"method": "GET"})], {}, ("rest_v1_twin must be",)),
        ("domain-guard", base_rows, {"extra_files": {"foo.json": "[]"}}, ("not one of the declared domains",)),
        ("top-level", base_rows, {"extra_files": {"tar.json": "5"}}, ("top level must be a JSON array",)),
        ("bad-bytes", base_rows, {"extra_files": {"tar.json": b"\xff\xfe\x00["}}, ("invalid JSON",)),
        ("bad-syntax", base_rows, {"extra_files": {"tar.json": "{bad"}}, ("invalid JSON",)),
        ("huge-int", base_rows, {"extra_files": {"tar.json": "1" * 5000}}, ("invalid JSON",)),
        ("too-deep", base_rows, {"extra_files": {"tar.json": "[" * 200000}}, ("invalid JSON",)),
        ("composed-of", base_rows + [_mk("c2", "composed-of:no.such.id")], {}, ("unknown capability id",)),
        ("plain-twinned", base_rows + [_mk("t2", "twinned", rest_v1_twin=rest_tw)], {}, ("plain twinned needs BOTH",)),
        ("bad-resource", base_rows + [_mk("t3", "twinned", rest_v1_twin=rest_tw, mcp_twin="resource:yuzu://gone")], {},
         ("kResources",)),
        ("exception-route", base_rows + [_mk("e2", f"exception:#520 revisit:{day_a} r", rest_v1_twin=_rt("/api/v1/gone"))],
         {}, ("not currently registered",)),
        ("new-free-form", base_rows + [_mk("e3", "exception:#520 legacy two")],
         {"patch": {"GRANDFATHERED_LEGACY_EXCEPTIONS": leg2, "GRANDFATHERED_MAX": 1}}, ("do NOT extend",)),
        ("stale-grandfather", base_rows, {"patch": {"GRANDFATHERED_LEGACY_EXCEPTIONS": frozenset({"ghost.id", "get.fragments-leg"}),
                                                    "GRANDFATHERED_MAX": 2}}, ("no longer names an exception row",)),
        ("grandfather-shrink", base_rows, {"patch": {"GRANDFATHERED_MAX": 5}}, ("lower GRANDFATHERED_MAX to 1",)),
        ("grandfather-grew", base_rows, {"patch": {"GRANDFATHERED_MAX": 0}}, ("is never raised",)),
        ("planned-rise", base_rows, {"patch": {"BASELINE_GENERIC_PLANNED": 0}}, ("this count should never rise",)),
        ("planned-fall", base_rows, {"patch": {"BASELINE_GENERIC_PLANNED": 2}}, ("Lower BASELINE_GENERIC_PLANNED to 1",)),
        ("untwinned-rise", base_rows, {"patch": {"BASELINE_UNTWINNED": 1}}, ("RATCHET",)),
        ("untwinned-fall", base_rows, {"patch": {"BASELINE_UNTWINNED": 99}}, ("Lower BASELINE_UNTWINNED",)),
        ("unledgered", base_rows, {"tweak": _extra_route}, ("unledgered route GET /fragments/not-in-ledger", "STRICT_EXCEPTION_PINS",
                                                                       "written directly as an exception leaves it alone")),
        ("v1-keyed", base_rows + [v1_row], {"tweak": _no_a}, ("keyed on a REST v1 route", "size-pinned", "extending it is review-enforced")),
        ("openapi-missing", base_rows, {"tweak": _unlisted}, ("registered but missing from openapi_spec()",)),
        ("stale-allowlist", base_rows, {"tweak": _no_options}, ("ALLOWLIST_OPENAPI_MISSING entry OPTIONS", "is stale")),
    )
    # Pins: each strict exception row is identity-pinned; a swap, relabel, re-date or stale pin fails.
    s1_id, s2_id = base_rows[7]["capability_id"], base_rows[8]["capability_id"]
    good_pins = {s1_id: (5955, str(day_a)), s2_id: (520, str(day_a))}
    pin_cases = (
        ("pin-new", {s2_id: good_pins[s2_id]}, ("not in STRICT_EXCEPTION_PINS", "recorded ruling")),
        ("pin-relabel", dict(good_pins, **{s1_id: (520, str(day_a))}), ("is pinned as #520",)),
        ("pin-redate", dict(good_pins, **{s1_id: (5955, str(day_a + one_day))}), ("is pinned as #5955 revisit",)),
        ("pin-stale", dict(good_pins, **{"get.fragments-ghost": (520, str(day_a))}), ("is stale", "get.fragments-ghost")),
    )
    for label, pins_c, needles in pin_cases:
        expect(label, _drive(base_rows, patch={"STRICT_EXCEPTION_PINS": pins_c}), 1, *needles)
    check(pin_errors({}, pins={}) == [], "pins: an empty ledger with no pins is clean")
    check(STRICT_EXCEPTION_PINS and all(isinstance(v, tuple) and len(v) == 2 for v in STRICT_EXCEPTION_PINS.values()),
          "pins: the real table maps capability ids to (issue, date)")

    # Lapse: ONE aggregated warning at the horizon, never a failure, deterministic via `today`.
    due_day = day_a
    lapse_rows = {(i, i): {"status": f"exception:#{520 + i} revisit:{due_day + i * one_day} r",
                           "capability_id": f"get.fragments-l{i}"} for i in range(5)}
    check(revisit_lapse_warning(lapse_rows, due_day - datetime.timedelta(days=REVISIT_WARN_DAYS + 5)) is None,
          "lapse: nothing due beyond the horizon -> no warning")
    w = revisit_lapse_warning(lapse_rows, due_day + 2 * one_day)
    check(w is not None and f"on or before {due_day + (2 + REVISIT_WARN_DAYS) * one_day}" in w and w.startswith("5 exception row(s)") and "2 already past" in w
          and "#520" in w and "get.fragments-l0" in w and w.endswith("or retire it") and ", ..." in w,
          f"lapse: one aggregated warning with counts, issues and the first ids, got {w}")
    for n_due, dots in ((3, False), (4, True)):
        rows_n = {k: v for k, v in lapse_rows.items() if k[0] < n_due}
        wn = revisit_lapse_warning(rows_n, due_day + 5 * one_day)
        check((", ..." in wn) == dots, f"lapse: an ellipsis only after the third id with {n_due} due, got {wn}")
    unsorted_rows = dict(reversed(list(lapse_rows.items())))
    wu = revisit_lapse_warning(unsorted_rows, due_day + 2 * one_day)
    check(wu == w and f"earliest {due_day}" in wu and "first: get.fragments-l0, get.fragments-l1, get.fragments-l2, ..." in wu
          and "get.fragments-l3" not in wu, f"lapse: the earliest rows lead and only three ids are named, got {wu}")
    check(REVISIT_WARN_DAYS == 14, "lapse: the docs say 14 days; change them together with REVISIT_WARN_DAYS")
    edge = {(0, 0): {"status": f"exception:#9 revisit:{due_day} r", "capability_id": "get.fragments-e"}}
    check(revisit_lapse_warning(edge, due_day - datetime.timedelta(days=REVISIT_WARN_DAYS)) is not None,
          "lapse: a date exactly at today + REVISIT_WARN_DAYS is due")
    check(revisit_lapse_warning(edge, due_day - datetime.timedelta(days=REVISIT_WARN_DAYS + 1)) is None,
          "lapse: one day beyond the horizon is not due")
    check(revisit_lapse_warning(edge, datetime.date.max) is not None, "lapse: a max date does not overflow")
    check(revisit_lapse_warning({(0, 0): {"status": "exception:#9 legacy", "capability_id": "x"}}, due_day) is None,
          "lapse: a grandfathered free-form row has no date to lapse")
    rc_l, out_l = _drive(base_rows, today=day_a + one_day)
    check(rc_l == 0 and out_l.count("::warning::check-api-parity: ") == 1 and "or retire it" in out_l
          and "::error::" not in out_l, f"lapse: run_check warns once and still passes, got {rc_l}: {out_l[:300]}")
    with tempfile.TemporaryDirectory(prefix="yuzu_test_api_parity_") as dsum:
        summ = Path(dsum) / "summary.md"
        summ.write_text("an earlier step\n", encoding="utf-8")
        for env_val, want in ((str(summ), True), (str(Path(dsum) / "no_such_dir" / "x.md"), False), (None, False)):
            saved = os.environ.get("GITHUB_STEP_SUMMARY")
            if env_val is None:
                os.environ.pop("GITHUB_STEP_SUMMARY", None)
            else:
                os.environ["GITHUB_STEP_SUMMARY"] = env_val
            try:
                rc_s, out_s = _drive(base_rows, today=day_a + one_day)
            finally:
                if saved is None:
                    os.environ.pop("GITHUB_STEP_SUMMARY", None)
                else:
                    os.environ["GITHUB_STEP_SUMMARY"] = saved
            check(rc_s == 0 and "::error::" not in out_s,
                  f"step summary: an unwritable or unset summary path never changes the result, got {rc_s}: {out_s[:200]}")
        body_s = summ.read_text(encoding="utf-8") if summ.exists() else ""
        check(body_s.startswith("an earlier step\n") and "exception revisit dates" in body_s
              and "or retire it" in body_s and body_s.count("###") == 1,
              f"step summary: the lapse notice is appended once, after what is already there, got {body_s!r}")
        os.environ["GITHUB_STEP_SUMMARY"] = str(summ)
        try:
            rc_s, out_s = _drive(base_rows, today=day_a - 100 * one_day)
        finally:
            os.environ.pop("GITHUB_STEP_SUMMARY", None)
        check(rc_s == 0 and summ.read_text(encoding="utf-8").count("###") == 1,
              "step summary: nothing is appended when no revisit date is near")
        check(os.environ.get("GITHUB_STEP_SUMMARY") is None, "step summary: the selftest leaves the variable as it found it")
    rc_l, out_l = _drive(base_rows, today=day_a - 100 * one_day)
    check(rc_l == 0 and "or retire it" not in out_l, f"lapse: no warning far from the date, got {out_l[:200]}")

    expect("odd-filename", _drive(base_rows, extra_files={"x\n::error::injected.json": "{bad"}), 1,
           "not one of the declared domains", absent=("\n::error::injected",))
    expect("bad-method", _drive(base_rows + [_mk("bm", "retire", method="GET\n::error::injected")]), 1,
           "method must be 1-16 upper-case", absent=("\n::error::injected",))
    expect("bad-path", _drive(base_rows + [_mk("bp", "retire", path="/x\n::error::injected")]), 1,
           "path must be", absent=("\n::error::injected",))
    expect("missing-domain", _drive(base_rows, skip_domains=("tar",)), 1, "missing for declared domain")
    expect("planned-lookalike", _drive(base_rows + [_mk("p21460", "planned:#21460")]), 0)
    for label, rows_c, kw, needles in cases:
        expect(label, _drive(rows_c, **kw), 1, *needles,
               absent=("BASELINE",) if label in ("bad-status", "malformed", "top-level") else ())

    with tempfile.TemporaryDirectory(prefix="yuzu_test_api_parity_") as dc:
        cpp = Path(dc) / "mcp_server.cpp"
        for label, body, needle in (("no-anchor", "int nothing_here;\n", "kResources[] was not found"),
                                    ("no-tools", 'static const ResourceDef kResources[] = {\n    {"yuzu://r", "R"},\n};\n',
                                     "kTools[] was not found"),
                                    ("bad-bytes", b"\xff\xfe\x00bad", "cannot read"), ("missing", None, "cannot read")):
            if body is not None:
                cpp.write_bytes(body if isinstance(body, bytes) else body.encode("utf-8"))
            target = cpp if body is not None else Path(dc) / "absent.cpp"
            expect("cpp-" + label, _drive(base_rows, patch={"MCP_SERVER_CPP": target}, synthetic=False), 1, needle,
                   absent=("[Errno",))
    with tempfile.TemporaryDirectory(prefix="yuzu_test_api_parity_") as dz:
        cpp = Path(dz) / "mcp_server.cpp"
        cpp.write_text('static const ResourceDef kResources[] = {\n    {"yuzu://r", "R", "d", "m"},\n};\n'
                       "static const ToolDef kTools[] = {\n    // nothing\n};\n", encoding="utf-8")
        expect("cpp-tools-empty", _drive(base_rows, patch={"MCP_SERVER_CPP": cpp}, synthetic=False), 1,
               "yielded zero entries", "kTools[]")
    with tempfile.TemporaryDirectory(prefix="yuzu_test_api_parity_") as dm:
        rest_cpp = Path(dm) / "rest_api_v1.cpp"  # synthetic: the selftest never reads the real tree
        rest_cpp.write_text('static const std::string spec = R"({"paths":{}})";\n', encoding="utf-8")
        empty_ledger = Path(dm) / "ledger"
        empty_ledger.mkdir()
        for dom in DOMAINS:
            (empty_ledger / f"{dom}.json").write_text("[]", encoding="utf-8")
        for mode in ("--render-doc", "--dump-json"):
            err = io.StringIO()
            with _patched(MCP_SERVER_CPP=Path(dm) / "absent.cpp", SERVER_SRC=Path(dm), REST_API_V1_CPP=rest_cpp,
                          LEDGER_DIR=empty_ledger), \
                    contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                rc_m = main([mode])
            check(rc_m == 1 and "::error::" in err.getvalue() and "cannot read" in err.getvalue()
                  and "Traceback" not in err.getvalue(), f"main({mode}): a lost source is a named error, got {rc_m}: {err.getvalue()[:200]}")
    # openapi_spec() anchor: an unreadable file or a lost anchor is a named error, never a traceback.
    with tempfile.TemporaryDirectory(prefix="yuzu_test_api_parity_") as dq:
        for label, body in (("missing", None), ("anchor", b"int nothing;\n"), ("bytes", b"\xff\xfe"),
                            ("twice", b'static const std::string spec = R"({})";\nstatic const std::string spec = 1;\n')):
            target = Path(dq) / f"rest_{label}.cpp"
            if body is not None:
                target.write_bytes(body)
            try:
                with _patched(REST_API_V1_CPP=target):
                    extract_openapi_paths()
                check(False, f"openapi: a {label} rest_api_v1.cpp must raise AnchorError")
            except AnchorError as e:
                check("openapi_spec()" in str(e), f"openapi: the error must name the literal, got {e}")
        # Informational modes refuse a malformed ledger, and read it before any source.
        bad_dir = Path(dq) / "bad"
        bad_dir.mkdir()
        for dom in DOMAINS:
            (bad_dir / f"{dom}.json").write_text(
                json.dumps([_mk("bad", "nonsense")] if dom == "other" else []), encoding="utf-8")
        gone = Path(dq) / "absent.cpp"
        for mode in ("--render-doc", "--baseline-inventory"):
            err = io.StringIO()
            with _patched(LEDGER_DIR=bad_dir, MCP_SERVER_CPP=gone, REST_API_V1_CPP=gone, SERVER_SRC=Path(dq)), \
                    contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                rc_i = main([mode])
            check(rc_i == 1 and "::error::" in err.getvalue() and "invalid status" in err.getvalue()
                  and "counts unreliable" in err.getvalue()
                  and "cannot read" not in err.getvalue() and "Traceback" not in err.getvalue(),
                  f"main({mode}): a malformed ledger must fail first with the unreliable note, got {rc_i}: {err.getvalue()[:300]}")
    # --dump-json lists the MCP resources next to the tools.
    with tempfile.TemporaryDirectory(prefix="yuzu_test_api_parity_") as dj:
        jcpp = Path(dj) / "mcp_server.cpp"
        jcpp.write_text('static const ResourceDef kResources[] = {\n    {"yuzu://r1", "R", "d", "m"},\n};\n'
                        'static const ToolDef kTools[] = {\n    {"t1", "d"},\n};\n', encoding="utf-8")
        jrest = Path(dj) / "rest_api_v1.cpp"
        jrest.write_text('static const std::string spec = R"({"paths":{}})";\n', encoding="utf-8")
        jsrc = Path(dj) / "src"
        jsrc.mkdir()
        out_j = io.StringIO()
        with _patched(MCP_SERVER_CPP=jcpp, REST_API_V1_CPP=jrest, SERVER_SRC=jsrc, MCP_REGISTRY_DIR=jsrc,
                      MIN_REGISTRY_FILES=0), \
                contextlib.redirect_stdout(out_j), contextlib.redirect_stderr(io.StringIO()):
            rc_j = main(["--dump-json"])
        dumped = json.loads(out_j.getvalue()) if rc_j == 0 else {}
        check(rc_j == 0 and dumped.get("mcp_resources") == ["yuzu://r1"] and dumped.get("mcp_tools") == ["t1"]
              and dumped.get("counts", {}).get("mcp_resources") == 1,
              f"dump-json: mcp_resources must be listed and counted, got rc={rc_j} {dumped}")
    with tempfile.TemporaryDirectory(prefix="yuzu_test_api_parity_") as dd:
        (Path(dd) / "devices.json").mkdir()
        _rows, errs = load_ledger(dd)
        check(any("devices.json" in e and "invalid JSON" in e for e in errs),
              f"load_ledger: a directory named *.json is a clean error, got {errs}")

    if failures:
        print("SELFTEST FAILURES:", *failures, sep="\n  ")
        return 1
    print("check-api-parity selftest: OK")
    return 0


def _selftest():
    """Runs the selftest with GITHUB_STEP_SUMMARY removed, so its synthetic revisit
    notices never land in the real run summary when CI sets the variable."""
    import tempfile
    saved = os.environ.pop("GITHUB_STEP_SUMMARY", None)
    # Hermetic against the real registry: the selftest fixtures patch MCP_SERVER_CPP alone, so the
    # registry scan reads an empty directory with no file floor (its own cases patch both back).
    saved_reg = (MCP_REGISTRY_DIR, MIN_REGISTRY_FILES)
    try:
        with tempfile.TemporaryDirectory(prefix="yuzu_test_api_parity_") as empty_registry:
            globals().update(MCP_REGISTRY_DIR=Path(empty_registry), MIN_REGISTRY_FILES=0)
            return _selftest_body()
    finally:
        globals().update(MCP_REGISTRY_DIR=saved_reg[0], MIN_REGISTRY_FILES=saved_reg[1])
        if saved is not None:
            os.environ["GITHUB_STEP_SUMMARY"] = saved


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dump-json", action="store_true",
                     help="dump raw extraction as JSON and exit")
    ap.add_argument("--bootstrap", action="store_true",
                     help="add default (planned:#2146) rows for any "
                          "currently-unledgered fragment/legacy route; the gate "
                          "does not let planned:#2146 grow, so retag each new row "
                          "with a specific planned:#N or a strict exception")
    ap.add_argument("--baseline-inventory", action="store_true",
                     help="print current vs baseline counts without failing on a ratchet "
                          "mismatch (exit 1 if the ledger is malformed)")
    ap.add_argument("--render-doc", action="store_true",
                     help="print docs/api-parity-ledger.md's generated block "
                          "(splice between the BEGIN/END GENERATED markers)")
    ap.add_argument("--selftest", action="store_true",
                     help="run internal extraction/parsing logic checks "
                          "against synthetic fixtures and exit (no real-tree "
                          "I/O)")
    args = ap.parse_args(argv)

    if args.selftest:
        return _selftest()
    try:
        if args.dump_json:
            return dump_json()
        if args.baseline_inventory:
            return baseline_inventory()
        if args.render_doc:
            return render_doc()
        if args.bootstrap:
            bucket_a, _bucket_b = extract_all_routes()
            return bootstrap(bucket_a)
        return run_check()
    except AnchorError as e:
        gh("error", f"check-api-parity: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
