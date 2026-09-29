# WS-0 — Split interlock certification (2026-09-08)

**Workstream:** WS-0 (Reconciliation & interlock certification) — the predecessor of every
presentation/core/engine split workstream. See `docs/presentation-core-split-delivery-matrix.md`.

**What this document is.** The human narrative half of WS-0's certification. It records, per
ADR-0032 sequencing-interlock item (a)–(n), the tree-verified status with its evidence: a
**re-runnable grep** where a symbol exists or is expected-and-absent (the gate-set cells a/b/c/d/h
and m), and an authoritative **file:line or ADR reference** where the cell is pure-absence with no
meaningful symbol to count (e/g/l/n — "nothing exists" is shown by the ADR naming it unbuilt, not by a
command). The gate-relevant cells carry the command; the rest carry the citation. The machine-readable half is
`tests/split_interlock_ledger.json`, enforced in CI by `tests/test_split_interlock_tripwire.py`
(wired into `.github/workflows/docs-lint.yml`). On any disagreement the **ledger + tree win over
this prose** — re-run the greps.

**Verified against** `origin/dev` @ `d2e89ffaade703ed0da31ee4cee0962438d7cc0a`. Every command below
was run against that ref (`git fetch origin dev` first). Re-stamp this line when re-certified.

> ⚠️ Current-state is grepped, never copied from an ADR status column. ADR-0032's own interlock
> table carries **stale** cells — (b), (a) and (m) — corrected here and, for the markdown itself,
> under #4124. This document is the authority (the matrix's own rule,
> `docs/presentation-core-split-delivery-matrix.md`); the ADR table is a lagging copy.

---

## 1. The merge-gate, and why it is now a test and not a sentence

ADR-0032's rule: **no ballot-A5 (engine-path) code merges into any binary until the unconditional
interlock set (a)–(d)+(h) has landed.** The falsifier the ADR names is *"a merged PR that admits
runs, mints grants or serves results"* before the substrate exists. A routed-concern row alone
cannot enforce that: governance runs from the **author's working tree**, so a branch predating the
routed table silently runs the old pipeline (CLAUDE.md, "Context discipline"), and Step 0's currency
check *reports*, it does not block. So WS-0 arms **two layers**:

1. **A hard CI tripwire** — `tests/test_split_interlock_tripwire.py`, run on the merge ref on every
   PR via `docs-lint.yml` (the same job as `test_issue_docs.py`, which binds on docs-only PRs the
   heavy platform jobs skip). It reads the ledger and fails if **any engine-path marker** appears in
   the code tree while **any of (a)–(d)+(h) is not green**, and fails if a cell is marked green while
   its substrate marker is **absent** (the false-certification guard).
2. **A routed-concern row** (`.claude/routed-concerns-access-control.md`) — the *semantic* layer:
   it routes any diff touching the interlock symbols **or the NVD-strangler paths**
   (`nvd_*` / `vuln_finding_store.*` / new `engine_principal_store` callers composing released facts)
   to `security-guardian` + `architect` with a BLOCKED-on-interlock verdict. It names ADR-0032's Rule
   as the policy-floor source, and it carries the **path trigger the symbol grep cannot**: `nvd_*`
   and `vuln_finding_store` already exist (server-side NVD sync), so a PR re-homing them behind an
   engine principal is an engine-path ballot with **zero** new interlock symbols — caught by human
   review, not by the grep.

**The two marker classes (why the tripwire does not deadlock the interlock).** Substrate symbols —
`use_case_run_id` (the D12 audit column, cell c), the release-log store (cell d), `evaluate_as_operator`
(cell b's seam), and the runtime capability-registry symbol (cell h) — are the very things WS-A6/#2675
must **land** to turn the gate green. Blocking their first occurrence would deadlock the interlock
against itself. So they are **substrate markers**: their appearance *flips a ledger cell*, routed to
reviewers under normal derivation, never blocked (cells a and m carry substrate markers too —
`engine_principal_store` and `class PrincipalQuota` — but only cell **a** is non-red today, so the
false-certification guard, which greps a cell's substrate only while that cell is green, exercises
exactly that one marker; `class PrincipalQuota`'s marker stays dormant while (m) is red/partial). Only **engine-path markers** — the
run-row store (`use_case_runs`), the invocation/result-scoped grants (`invocation_grant` /
`release_authorization`), the finalisation receipt, `served_from_run_id`, `released_input_digest`, and
the reaper metric family — block, and only while the gate is red. `plan_hash` is **excluded**: its hits
are the pre-existing dispatch-tag grammar (`compute_plan_hash`), not the ADR-0032 Execution-Plan hash.

**Tamper-evidence, and the acknowledged grep limit.** The ledger is a repo file editable in the very
PR the gate polices, so the tripwire alone is tamper-*evident*, not tamper-*proof*. Its load-bearing
constants — `gate_set`, `search_paths`/`exclude_paths`, the engine-path and substrate marker dicts (keys + regexes), and "every gate
cell has a substrate marker" — are **pinned against frozen values in
`tests/test_split_interlock_tripwire_selftest.py`**, so opening the gate requires editing those test
constants too: a loud, CI-failing, reviewable change the routed-concern row routes to security review,
not one silent JSON edit. The remaining limit is inherent to grep: a marker proves **string-presence,
not semantic existence** (a cell can be flipped green off an incidental match or a comment; a
renamed/synonym symbol or a gitignored generated file evades RULE 1; and the `nvd_*`/`vuln_finding`
disclosure path has no mechanical marker at all). The routed-concern **human review is the
compensating control** for substrate quality and those un-mechanizable cases — and (b)'s #2665
deny-precedence, being a semantic change to existing code with no symbol, **requires a human
attestation** to flip green, never RULE 2 alone.

Today the gate is **CLOSED** — cells (b), (c), (d), (h) are red — and the tripwire confirms no
engine-path marker has breached it.

---

## 2. The interlock ledger (a)–(n)

Command shape for a marker (pinned to the certified SHA, not mutable `origin/dev`): `git grep -nE '<regex>' d2e89ffaa -- . :(exclude)docs/ :(exclude).claude/
:(exclude)changelog.d/ :(exclude)governance.d/ :(exclude)tests/split_interlock_ledger.json
:(exclude)tests/test_split_interlock_tripwire*.py` — the whole tree minus the prose/evidence trees
(`docs/`, `.claude/`, `changelog.d/`, `governance.d/` — which legitimately name markers in prose) and
the self-naming test files (matching the tripwire's `search_paths`/`exclude_paths`), so a future engine
binary directory (`server/engine/`, `gateway/`, …) cannot be silently uncovered.

| # | Prerequisite | Status | Tree evidence (re-runnable) |
|---|---|---|---|
| **(a)** | Phase-4 engine principals | **GREEN** (ADR-0032 cell STALE) | RBAC-only enforcement ships: `auth_routes.cpp` `require_permission` engine branch (`principal_kind == "engine"`, ~L667–705) — no legacy/service fallback, 503 on store-unavailable, 403 on RBAC-off/no-grant; twin in `require_scoped_permission`. `git grep -c 'engine_principal_store' origin/dev -- server/` → 182 hits / 22 files. |
| **(b)** | admit-then-filter gate **+ deny-precedence + evaluate-as-operator seam** | **RED — two open halves** | Chokepoint SHIPPED + pinned: `authorize_list_read` `git grep -c … -- server/` → **66** (128 server+tests, 263 whole-tree), decl `rbac_store.hpp:340`; transport twin `require_list_read` `auth_routes.hpp:198`; pinned `tests/unit/server/test_list_read_confinement.cpp` `[1715]`. **#1715 landed ADDITIVE** → deny-precedence is **#2665 (OPEN)**. `evaluate_as_operator` = **0-in-code** → seam is **#2675 (OPEN)**. |
| **(c)** | D12 audit schema, indexed `use_case_run_id` | **RED** | `git grep -c 'use_case_run_id' d2e89ffaa -- server/ agents/ common/ proto/ sdk/` → **0** (20 whole-tree, docs/skills only). `AuditEvent` has a single `principal` field. |
| **(d)** | P7 release-log schema | **RED** | `git grep -c 'release_log\|ReleaseLog' d2e89ffaa -- server/ agents/ common/ proto/ sdk/` → **0** (one forward-reference *comment* at `authz_model.hpp:206`, §4 below). Born-on-PG store, ADR-0012. |
| **(e)** | G1 cross-process event transport | RED (gates Decision 9 only) | Buses process-local (`execution_event_bus.hpp`). Rides HA WS-2a `event_outbox`. |
| **(f)** | per-action mutability in the plugin ABI | RED (gates fact-dispatch only) | `sdk/include/yuzu/plugin.h:28` is ALREADY `YUZU_PLUGIN_ABI_VERSION 4` with `YuzuActionDescriptor` (action + per-OS legs, `:124-136`) — the v3→v4 bump SHIPPED. RED because no per-action **mutability** field exists yet; the real change is an append-only **v4→v5** bump, not v3→v4. |
| **(g)** | derived-state confinement | RED | Nothing exists (ADR-0032 (g): "Not a line of engine code has been written"). |
| **(h)** | runtime capability-declaration registry **+ credential columns** | **RED** | `git grep -c 'register_securable\|create_securable\|ratified_mapping' d2e89ffaa -- server/ agents/ common/ proto/ sdk/` → **0**. Securables are a compile-time `std::array<std::string_view, 27>` at `rbac_store.cpp:559`; the only INSERT is `seed_defaults()` (`:588`). Admitting/requesting-credential columns absent. **Marker pins the registry create-path only**; the credential columns (ADR-0032:956) live on `use_case_runs`/the Execution Plan (engine-path, un-mechanizable pre-gate), so flipping (h) green **requires a human attestation** they landed too — same pattern as (b)'s #2665. |
| **(i)** | execution semantics: outcome correlation + coverage envelope | RED | Coverage fields 0-in-code; `workflow_engine.cpp` marks a step successful on dispatch, uncorrelated. |
| **(j)** | capability projection (generated OpenAPI + `tools/list`) | RED (generated half) | `tools/list` iterates a compile-time array; OpenAPI a hand-typed literal. RED refers to the **generated** projection from core's registry (#2678). *(Corrected 2026-09-08: the INV-31-4 drift test against the hand-written OpenAPI DOES exist and is green — #842/#3991/#3992; only the generation half remains.)* |
| **(k)** | operational readiness (new stores in readyz + reaper liveness) | RED | Six new stores, none in `/readyz`; reaper has no liveness metric. |
| **(l)** | intra-module cross-run isolation | RED | Nothing exists (ADR-0032 (l)); the first module (vuln-mgmt) serves many operators from one deployment. |
| **(m)** | per-principal quota caps | **RED — PARTIAL** (not in gate set) | The **#1973 base cap** ships: `git grep -c 'class PrincipalQuota' d2e89ffaa -- server/` → **present** (`principal_quota.{hpp,cpp}`, `max_concurrency=16`, `rate_per_second=20`), wired into `agent_service_impl.cpp` / `mcp_server.cpp` / `mcp_stream.cpp`. But ADR-0032 (m) **also** requires the 2b §5 invocation-grant outstanding-count + issuance-rate caps + dual-side debit (engine-path, **0-in-code**). So ADR-0032's "none enforced" **overstates** the gap (the base cap ships) but is **not wholesale stale**. |
| **(n)** | credential predecessor/successor relation + terminal-reason classification | RED | Unbuilt (ADR-0032 (n)); 2b must be amended. |

**Unconditional merge-gate set (a)–(d)+(h): a=green, b/c/d/h=RED → gate CLOSED.** No engine-path code
may merge. (m) is informational — not in the gate set — and is **partial** (base cap only), so it does
not read green.

---

## 3. §1c ratification (split ⇎ HA decoupling) — CONFIRMED landed

PR **#4125** ("docs(split): §1c ratified — split↔HA decoupled") is **MERGED** (2026-09-08 06:53 UTC,
merge `4c3cc7d10`) and live on `origin/dev` HEAD. The ADR-1005 owner **Dave Rae** is cited at
`docs/ha-delivery-matrix.md:41,93`, `.claude/skills/ha/SKILL.md:82,199,243`,
`docs/presentation-core-split-delivery-matrix.md` (the WS-0 row + the "Relationship to HA" section) and
`.claude/skills/split/SKILL.md` (§1d) — line-number-free for the two files this PR itself edits, to
avoid re-drift.
The `/auth-and-authz` skill carries **no** §1c/split content and is therefore **not** a citation site
(correcting the earlier draft DoD, which listed it).

---

## 4. #2665 bottomed out, and the residual findings for #4124 / WS-A6

**Interlock (b) has two open halves, and neither is WS-0's to resolve — only to name:**
- **#2665 (OPEN, `decision`)** — the shipped `authorize_list_read` is *additive* (a global deny does
  not override a management-group allow); interlock (b) requires **deny-precedence**. This is the
  single engine-gate open **question** and is a human decision, not an implementation WS-0 can land.
- **#2675 (OPEN, `ready-for-agent`)** — the server-internal `evaluate_as_operator` seam (filter (4)
  evaluated as the admitting operator while the engine is the authenticated caller). Absent in code.

**Stale ADR-0032 cells for #4124** (markdown correction is #4124's scope, not WS-0's — appended here
as verified input, each with the nuance the correction must preserve so #4124 does not itself overclaim):
- cell **(a)** says Phase-4 "is not [shipped]" — **stale**: RBAC-only enforcement ships (`auth_routes.cpp`).
- cell **(m)** says "none is enforced" — **overstated, NOT wholesale stale**: the #1973 base per-principal
  cap ships, but the 2b §5 invocation-grant caps + dual-side debit remain genuinely unbuilt (engine-path).
  The #4124 correction must say "base cap shipped; invocation-grant caps unbuilt", **not** flip (m) to
  fully-shipped.
- cell **(h)** cites the securables array as `rbac_store.cpp:217-244, 21 entries`; the **locator is stale**
  (actual `:559`, 27 entries). Status (red) is unaffected — only the line/count reference drifted.
- cell **(f)** (ADR-0032 line 954) still says `plugin.h` "carries action names only; ABI v3→v4" — **stale**:
  the v3→v4 bump shipped (`plugin.h:28` is already v4, `YuzuActionDescriptor`). RED is still correct (no
  mutability field); the real change is an append-only **v4→v5**. Add to the #4124 correction alongside (a)/(m)/(h).

**#4124 should carry a remediation deadline.** A stale authoritative ADR sitting open indefinitely is a
contradictory-record risk (an auditor sampling ADR-0032 directly reads a false "not shipped" for a live
control); recommend #4124 be given an explicit due date rather than left "deferred with no target". The
machine-enforced ledger + this certification are the authoritative interim record (the ledger + tree
win over any prose, stated at the top of this document), which bounds the risk but does not remove it.

**Forward reference to unbuilt substrate (governance rule 3 — a truth finding WS-A6 owns):**
`server/core/src/authz_model.hpp:205–206` comments that `data_class`/`audit_verb` are *"emitted with
the release-log write"* — a write that does not exist ((d) is 0-in-code). Not a defect to fix in
WS-0 (the comment describes the intended (d) behaviour); recorded so WS-A6 reconciles the comment
when it lands the release-log write.

---

## 5. In-flight engine-path ballot sweep — CLEAN

No open PR and no remote branch/worktree is an engine-path ballot. All 6 open PRs (#4154, #4150,
#4149, #4145, #4144, #3382) are agent-plugin / docs / read-twin / route-move / CI changes; per-diff
marker grep matched only **#4149**, and solely on *relocated* `nvd_`/`vuln_finding_store` health-probe
reads (a move, no engine principal, no admission/grant/release-log) — flagged for awareness, not a
breach. The `feat/auth-engine-principals-4.*` branches are the engine **principal** auth actor class
(interlock prerequisite (a), all merged), **not** the ADR-0032 admission path. Certified: no
in-flight engine-path ballot threatens the merge-gate as of this ref.

---

## 6. Definition of done (WS-0)

- [x] Interlock ledger (a)–(n) certified against the tree with per-cell evidence — a re-runnable grep for
  the gate-set + m cells, an ADR/file:line citation for the pure-absence cells (§2); machine
  half `tests/split_interlock_ledger.json`.
- [x] Merge-gate armed: two marker classes + CI tripwire (`test_split_interlock_tripwire.py` in
  `docs-lint.yml`) + a self-test (`test_split_interlock_tripwire_selftest.py`) pinning the ledger's
  load-bearing constants so the gate is tamper-evident + routed-concern row with symbol **and** NVD-path
  triggers; `plan_hash` excluded.
- [x] §1c ratification confirmed landed (#4125), cited at four sites (two matrices, two skills) (§3).
- [x] #2665 named the single engine-gate open question; #2675 named the seam; both OPEN (§4).
- [x] In-flight engine-path ballot sweep clean (§5).
- [x] Matrix WS-0 row flipped planned→done + Verified line re-stamped in this PR.

**WS-0's own deliverables are complete (every box above checked).** One TRACKED FOLLOW-UP remains — it is
**not** a WS-0 deliverable and does not gate WS-0's "done" status: the ADR-0032 (a)/(m)/(f)/(h) staleness
(scoped per §4) + the `authz_model.hpp:206` forward-reference should be appended to **#4124** with a
remediation deadline (external issue action, pending operator go-ahead). The authoritative ledger + this
cert already carry the correct state, so nothing downstream reads the stale ADR as truth; #4124 is the
documentation cleanup of the ADR's own table.
