## Independent adjudication: `doc-2146-a2r1-api-versioning-policy-gap` (HIGH/BLOCKING, raised by compliance-officer)

**Conclusion up front: the `rejected` disposition is correct on the substance. I agree with it, on my own reading of the evidence and the policy text. No deprecation cycle, versioned tool name, or Security carve-out is required for this change.** Details and caveats below, including what I could not verify first-hand.

### 1. What I could and could not verify directly

A hard environmental limitation first: **this sandbox has no git repository.** The worktree's `.git` pointer targets `/home/dgr/Yuzu/.git/worktrees/yuzu-2146-a2-r1-exec-history`, and `/home/dgr/Yuzu` does not exist here. Every `git show` / `git log` invocation fails with `fatal: not a git repository`. So I could **not** personally run `git show origin/dev:server/core/src/mcp_server.cpp` or inspect commits `dedcd0c4f` / `2c8d2d42f`. Anyone reading this adjudication should weigh that: my conclusion rests on (a) everything observable in the working tree at branch tip, (b) the shipped-release record in `CHANGELOG.md`, and (c) two independently recorded git verifications in the governance ledger that I could not re-execute but could cross-check for consistency.

### 2. Evidence I did gather first-hand

- **Branch tip state** (`server/core/src/mcp_server.cpp`): `list_schedules` at line 890-899 carries `definition_id`/`enabled_only` in its input schema, and both the tool description and the handler comment (line 10809) annotate the filters as **`#2146 A2-R1`** - this branch's own work item. The strict-reject path (`param_bool_strict`, line 292, used at line 10823-10831) is present, with a comment describing the exact pre/post behavior the finding is about.
- **Shipped-release record**: `CHANGELOG.md` (711 KB, the assembled history of every shipped release) contains **zero occurrences of `enabled_only`** and zero occurrences of `api/v1/schedules` anywhere. `list_schedules` does appear (line 10277) in the shipped tool roster, with no filter parameters mentioned. If the `enabled_only` filter had ever shipped on any surface in any release, the changelog discipline this repo enforces (hook + CI gate on fragments) makes its total absence very hard to explain.
- **REST twin**: `GET /api/v1/schedules` in `workflow_routes.cpp:2336` annotates its own `definition_id`/`enabled_only` query params as **`#2146 A2-R1 (gov docs-writer/cpp-expert fix round)`** - i.e., the REST v1 filters are also this same branch's introduction, not pre-existing surface this branch narrowed.
- **Tests**: `tests/unit/server/test_mcp_server.cpp` filter tests and fixtures are all annotated `#2146 A2-R1`, and the fixture comment (line 952) describes a "pre-existing" path as the one *without* a schedule engine wired - consistent with the tool pre-existing but the filters being new.
- **Ledger**: `governance.d/2146-a2-r1-...nriP9M.jsonl` row 31 (the rejection) and row 33 both record direct git verification that `list_schedules` on `origin/dev` has the literal input schema `{"type":"object","properties":{}}` with zero `enabled_only` occurrences, and that `dedcd0c4f` (introduce) and `2c8d2d42f` (tighten) are ancestors of the branch head and **not** of `origin/dev`. Row 33's Gate-8 round-3 pass re-verified this independently of Astra and found the substance "factually sound" while objecting only to the missing `adjudicated_by` process fields.

Nothing I found in the tree contradicts the claimed sequence; several independent in-tree markers actively corroborate it.

### 3. My own reading of `docs/api-versioning-policy.md` (read in full, 33 lines)

The textual question is whether line 20's Breaking clause ("narrowing accepted input") reaches a parameter whose permissive form existed only between two commits of an unreleased branch. I say no, for three reasons grounded in the document's own text:

- **The policy binds surfaces, not commits.** Line 3 defines the binding scope as "all operator-facing machine surfaces **once published**", and line 12 defines the contract as what is discoverable live (`tools/list`, `openapi.json`). A commit state that never reached `dev`, `main`, or any release was never a published, discoverable, consumable surface. There was no "accepted input" in the contract sense to narrow.
- **Line 28's pre-1.0 clause** - the strongest anti-evasion language in the document - protects "any surface a customer or external engine consumes". The intermediate permissive parse of a not-yet-existent parameter was consumable by no one; it existed only inside this branch's own review loop.
- **The net diff against the published baseline is exactly line 18's Additive case**: "new optional request fields or parameters with backward-compatible defaults". Branch tip vs. `origin/dev` adds one optional boolean parameter, default off, strict from its first published moment. The counter-reading (any commit-to-commit narrowing anywhere in history is Breaking) would require a versioned tool name and a 90-day window for an ordinary intra-PR review fix, and would render line 18 dead letter for any parameter developed iteratively. That is not a plausible construction of the policy.

One condition load-bearing for this conclusion: the branch must merge with only the strict behavior visible. The tip satisfies this - the first published behavior of `enabled_only` will be the strict one.

### 4. Disposition

- **Finding `doc-2146-a2r1-api-versioning-policy-gap`: rejection upheld.** Classification: Additive per policy line 18, not Breaking per line 20. No versioned tool name, deprecation window, `upgrading.md` migration entry, or Security carve-out is owed, because none of the policy's triggering conditions (a published/consumed prior surface) exist.
- **Process note**: ledger row 33 correctly identified that row 31's rejection lacked `adjudicated_by`/`adjudication_rationale`. This consult constitutes that missing independent adjudication: I am not the branch author, not the raising agent, and not the party that argued the rejection, and my conclusion above is my own read, reached before and independently of relying on row 31's summary.
- **Scope limits of this adjudication**: I did not evaluate compliance-officer's systemic side-query (whether `param_int_strict` / #2970B-era tightenings narrowed *shipped* parameters). That question needs the same per-parameter git-history test applied against real release boundaries, and should not be pre-judged by this result either way. Separately, the open MEDIUM docs-writer finding on the stale changelog fragment is unaffected by this adjudication; documenting the strict-typing contract in the fragment remains reasonable, but framing it as a "breaking-change note" would be wrong given the conclusion above.

**Bottom line: `adjudicated_by: Kimi (K3 opine consult)` - disposition `rejected` confirmed as correct; no remediation required on the versioning-policy question.**
