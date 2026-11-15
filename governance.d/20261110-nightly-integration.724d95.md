> Rebase update — 2026-11-12: the local branch now uses `origin/dev` at `ea21d7f019770a2d0e6075ad7d27c7e90438dcb7`. The staged fix reapplied without conflicts and its patch content is unchanged apart from hunk offsets. The validation and governance results below certify the earlier `f4c2c95aa` base; full validation and governance have not been rerun on the new base.

# Nightly integration — final governance review

**Decision: PASS WITH DEFERRED — no unresolved introduced finding or blocking policy floor.**

Integrated `origin/dev` at `f4c2c95aa77bfc573614bdb381a010fc2a15d366` into local branch `fix/nightly-november-integration`. The fixes applied cleanly. This review covers the uncommitted worktree relative to that base, including corrections made during review; the base SHA itself does not contain the fixes. Nothing was pushed or published.

## Validation

| Validation | Result |
|---|---|
| Rocky9 fresh ASan+UBSan dependencies, full application and suite | PASS — 176/176 entries, zero failures/skips; 5626.46 seconds |
| Rocky9 fresh TSan dependencies, full application and suite | PASS — 176/176 entries, zero failures/skips; 5251.08 seconds |
| Gateway within each full suite | PASS — EUnit 1269 + 1538 cases; Common Test 61 cases |
| Gateway Dialyzer | PASS — 563 PLT files checked, 52 project files analyzed; no type warnings |
| Normal-exit shutdown repeats, per sanitizer | PASS — ten TLS processes (13 cases/206 assertions each) and ten lifetime processes (1 case/5 assertions each) |
| Shulgi fresh MSVC debug/release dependency and shared-runner integration | PASS — 40 successful processes plus four expected invalid-CLI failures |
| Dependency dry-runs after attribution fix | PASS — Linux ASan/TSan and Windows plans require no package changes |
| Local focused checks | PASS — sentinel 38, classifier 54, instruction runner 198 tests/one existing skip, MCP adapter, changelog lint |
| Narrow callback compiler checks | PASS — 24 variants across Homebrew Clang 23 and Apple Clang 21 |

The Windows runs validate fresh gRPC 1.81.1/OpenSSL 3.6.5 dependencies and the shared runner, **not the full Windows project suite**. Coverage-guard variants exercise ordinary exit; they collect no coverage metrics. The Clang checks are **not a whole macOS build**. Linux uses the existing sanitizer settings and existing DNS shim/libpq allowances; no new suppression was added to make this change pass. ASan leak detection remained enabled (`detect_leaks=1`); the existing configuration disables ODR detection (`detect_odr_violation=0`) and excludes UBSan null/alignment checks (`-fno-sanitize=null,alignment`). TSan retains the synchronous DNS shim and existing libpq-only suppressions. These are scoped sanitizer results, not unrestricted sanitizer guarantees. The full runs contain no skipped Meson entries; the separate Python test has its existing platform skip. The benign gpb plugin notice in Dialyzer is preserved in the log.

The first installer/build attempts and their corrections remain in the evidence; they were not counted as passes. Source corrections were frozen before the successful full campaigns. Parallel acceleration was limited to independent dependency/C++ compilation and isolated TLS repeats; an installer lock serialized TSan configuration/build against the main pipeline, and gateway work did not overlap between configurations.

## Gate ledger

| Gate / roles | Result | Unresolved blockers | Deferred |
|---|---|---:|---:|
| 0–1: currency, four routed-concern tables, change summary, Resource Ledger | Complete | 0 | 0 |
| 2: security-guardian, docs-writer | PASS after fixes and rereview | 0 | 0 |
| 3: architect, cpp-expert, cpp-safety, quality-engineer | PASS after fixes and runtime validation | 0 | 0 |
| 3: build-ci, cross-platform, gateway-erlang, release-deploy | PASS within explicitly recorded platform scope | 0 | 0 |
| 4: happy-path, unhappy-path, consistency-auditor | PASS | 0 | 0 |
| 5: chaos-injector | SKIPPED under canonical conditional rule; Gate 4 produced no new findings | 0 | 0 |
| 6: compliance-officer, sre, enterprise-readiness | PASS WITH DEFERRED | 0 | 1 |
| 6b: workflow-orchestrator synthesis | Complete, raw reports preserved below | 0 | 0 |
| 7–8: fixes, domain rerouting/rereview, runtime evidence and final disposition | PASS WITH DEFERRED | 0 | 1 unique finding |

Nine live findings: **eight fixed, one pre-existing linked**. The deferred count in the final row is the same finding as Gate 6, not an additional issue.

| Finding | Resolution |
|---|---|
| resource-ledger-001 | Scoped worker and OpenSSL ownership; cleanup precedes worker retirement. Fresh dependencies, full suites and ordinary-exit repeats pass. |
| root-build-001 | Regenerated patch against exact upstream context; strict application and actual Linux/MSVC builds pass. This was caused by the initial RAII correction and remains recorded. |
| docs-writer-001 | Probe working Python executables and fall back correctly; 38 regression checks pass. |
| quality-engineer-001 | Restored Catch2 duration argument. |
| compliance-officer-001 | Exact baseline MIT license and scoped NOTICE attribution included. |
| ledger-audit-001/002/003 | Fix citations, sequential-review wording and build provenance corrected by append-only records. |
| enterprise-readiness-001 | Pre-existing overdue A5 review date linked to active issue [#2990](https://github.com/DevNullLtd/Yuzu/issues/2990); no exception renewal or claim the underlying behavior is fixed. |

No severity downgrade, waiver or self-adjudicated exception was used. The original policy floors remain in the ledger history. Role agreement by the same sequential reviewer does not count as independent discovery. Modified-file reading coverage is collective and documented in the retained appendices. All source fixes were rerouted through their affected domains, including mandatory security/docs and C++ safety reviews. Historical pending statements below are superseded by this final section, not erased.

## Evidence identity and retention

Paired finding ledger: `governance.d/20261110-nightly-integration.724d95.jsonl`.

The final local/remote source comparison verified **6293 files** on the stated base with no mismatches. Content identity (sorted path, NUL, file SHA-256, newline; file contents/names, not modes): `f0fbe60b63478455e5570021e583782b372e521298aae612e56f9d5c7b9f4779`. Only the named append-only finding ledger is excluded from that source identity. This final report and closure evidence are added after testing and do not alter executable sources. Source-review patch identity: `3b36bd287e1238f3bcdaf708fa77280a46cffe007fb150132371a95834c0357a`.

Linux evidence archive: `/private/tmp/yuzu-nightly-governance/validation/evidence-bundle.tar.gz`, SHA-256 `8d1ae56a0ce8c42cf62009b7dcdb733212ecd809c4184e672956fe7270ad4103`, 130 files, 11085410 bytes. Includes test results/output, all repeat logs, build/configure/dependency logs, tool/package versions, source identity, scripts and patch artifacts. Credential values captured in environments are redacted in the portable bundle; owned raw originals remain on Rocky. Windows evidence: `/private/tmp/yuzu-nightly-governance/windows/evidence.tar.gz`, with results and exact compiled-worker proof alongside it. Source reports below are embedded so review reasoning does not rely on temporary paths alone. These are local retained artifacts, not a claim of published CI evidence.

Local test DB campaign: `governance-f4c2c95aa-20261111`. Full-suite retries were not needed. Final ledger lint and disposition checks are recorded with the closure evidence. No PR, remote comment, push or deployment was performed.

## Verbatim synthesis appendix

Gate6b workflow-orchestrator synthesis — presentation only, 2026-11-11
Canonical Gate6b and actual workflow-orchestrator brief read. This output preserves all source reports verbatim below. No severity/disposition adjudication, issue mutation or source edit. Every grouping is PROVISIONAL. Six distinct ledger issues remain distinct; same-theme issues at different locations are never merged. Gate2 alias security-guardian001 explicitly references the inventory's original manual-cleanup defect, so it is an echo of resource-ledger001, not a seventh independent discovery. Below operational bands and policy-floor gates are SEPARATE; native BLOCKING does not turn MEDIUM into HIGH.

| Provisional issue / source location | Maximum derived band; native labels | Policy-floor gate | Provenance / independence | Current report disposition |
|---|---|---|---|---|
| resource-ledger-001; ports/grpc/00017 original manual cleanup line42; security-guardian001 alias | MEDIUM (root ledger SHOULD from I5/E0; security alias I9 remains lower); native policy-floor / BLOCKING | New manual C++ cleanup outside RAII | Inventory/resource_ledger first; security/C++/later roles echoes; independently1, not multiple | Scoped worker+crypto guard source-corrected; artifact/runtime closure root-owned |
| root-build-001; ports/grpc/00017 context line28 | MEDIUM (root ledger SHOULD, I5/E0); native BLOCKING | Introduced supported-platform build break | Root actual Windows vcpkg first; later exact apply checks corroborate correction, not independent discovery; independently1 | Exact patch context source-corrected; real rebuild/run evidence pending consolidation; caused_by resource-ledger001 |
| docs-writer-001; sentinel original line92 | LOW (I5/I8 capped E6); native NICE | Introduced supported-platform CI break | Docs raised executable concern; root experimentally established it; one discovery chain, downstream echoes, independently1 | FIXED: executable probe/fallback,38/0 regression, corrected doc |
| quality-engineer-001; tests/meson.build80 | LOW (I8/E6); native NICE | None | QA first; subsequent source confirmations echoes, independently1 | FIXED in source: --durations=yes |
| compliance-officer-001; imported ports/grpc notice omission, remedy ports/LICENSE-vcpkg.txt1 + NOTICE82 | INFO (I9/E3); native LOW | None asserted by owner | Compliance/resource_ledger first; packaging/domain confirmation echoes, independently1 | CLOSED: exact baseline MIT notice+scoped NOTICE |
| enterprise-readiness-001; docs/agentic-first-principle.md123 #2990 | INFO (I9/E3); native LOW | None asserted by owner | Enterprise/resource_ledger first; root issue-state evidence corroborates tracking, independently1 | OPEN PRE-EXISTING overdue revisit; root may record linked-to-#2990, not exception renewal |

No new independent Gate4 findings. Gate5 SKIPPED by root per conditional rule; validation-scenario guidance is not a new finding. Source reviews now have complete collective modified-file coverage; that completion is explicitly collective and does not manufacture independent reviewers. Initial report timestamps/limitations remain verbatim and later addenda explain supersession.
Runtime limits: Windows normal-exit coverage-guard build is not instrumentation/coverage measurement; narrow callback macro harnesses are not whole dependency/platform builds; exact patch application is not execution; root-only unrestricted tests retain root provenance. Overall PASS withheld while fresh runtime campaign/final ledger dispositions remain pending. This synthesis does not decide whether a tracked exception can be accepted or re-date it.

VERBATIM SOURCE REPORT APPENDICES FOLLOW. Delimiters are presentation only; file contents between them are unchanged bytes.

===== BEGIN security-guardian.txt =====
Gate 2 security-guardian — initial review and immediate fix rereview
Scope: f4c2c95aa77bfc573614bdb381a010fc2a15d366 to working tree, including fragment. Read-only; no tests run by this reviewer. Root orchestrates gates.
Disposition: production/small-file security pass completed; NOT an unconditional Gate2 PASS. Large-file/domain coverage remains pending below.
Input proof: api_token_store.cpp contains successor->rotation_initiator != requesting_user. Current patch contains std::unique_ptr<ThreadState> worker(static_cast<ThreadState*>(arg)); and ~ScopedOpenSslThreadState() { OPENSSL_thread_stop(); }.

security-guardian-001 — original manual OpenSSL cleanup violates RAII policy floor; corrected in current working tree
Location: ports/grpc/00017-openssl-worker-cleanup.patch original added OPENSSL_thread_stop before delete worker (original preserved pre-fix-worker.patch); current lines 37-50.
Classification: resource ownership contract, not wording.
severity_native: BLOCKING. Policy-floor gate: manual resource cleanup in NEW C++ not RAII-wrapped, canonical governance policy. Operational band derivation bypassed by floor.
TRIGGER: secure OpenSSL worker callback owns implicit crypto state and returns through newly inserted manual cleanup; exceptional exit from ThreadBody skips that statement.
IMPACT: I9 for the demonstrated contract violation; actual exceptional-path operational impact not asserted as reproduced.
EXPOSURE: E0 background worker; E5 exceptional exit candidate. EPISTEMIC: likely from inspected code. No exception waiver adjudicated.
Provenance: explicitly identified in Gate1 resource-inventory entry5 before this review; NOT independently discovered by this agent.
Resolution: root replaced raw owning worker pointer/delete with unique_ptr, then declared noncopyable ScopedOpenSslThreadState, then invokes ThreadBody. Reverse destruction stops OpenSSL before ThreadState counter retirement. <memory> is already included in actual inspected gRPC 1.81 source. Inspected StartThread, ThreadBody and Quiesce: drain/unregistration occurs within ThreadBody; Quiesce waits living_thread_count. The guard's ordinary destructor is implicitly noexcept; no throwing C++ operation added. Source-level floor resolved without waiver. Full updated-overlay compilation/Windows/macOS coverage remains domain validation, not proven by this source review. No claim of OS thread join or arbitrary future TLS-destructor safety.

Security conclusions:
- Full production api_token_store.cpp/.hpp read. Added durable-initiator comparison is denial-only, after authoritative epoch expiry and before raw-cache reservation. It never authorizes raw-token recovery from durable storage. Existing fresh RAM entry/owner checks remain. Empty durable identity does not reveal a token. Existing transaction and secret scrub scope guards cover new false return.
- REST and MCP rotation callers pass authenticated session username; existing Security:Write and engine restrictions remain. MCP error classifier maps both in-progress cases to Conflict. Failure audit stays on existing caller paths. Existing human rotate and confirmation paths inspected for sibling consistency; no equivalent hole or new bypass identified. No new principal, endpoint, SQL schema, permission or cross-chokepoint author introduced.
- Full runner and new lifetime test read: suite engine ownership transfer avoids an extra strong ref at shutdown; Catch Session dies before runtime owner; promise captured by owning value protects timeout unwinding. Scope remains default suite engine; custom engines/caller threads not covered.
- Guardian changed synchronization test uses existing Rig teardown that releases BOTH watch and unwatch gates before draining/resetting engines. No new dangling parked-worker lifetime found in changed sequence.
- Both Erlang fixture modules fully read: explicit SHA256 signing changes fixtures, not trust/CRL verification policy. No added verification bypass.
- Full overlay recipe/patch set, five Dockerfiles and small scripts read. Pinned source and existing source hash retained; overlay copied before install. Interpreter fallback defect found and empirically reproduced by root, subsequently fixed by root, is not an independent security finding here. Current fallback and added test8 read; root reports 38 assertions passing.

Coverage:
Read all four routed concern tables completely in routing task; canonical Step0/matrix/ledger, actual security-guardian brief and supplied prompt; full actual api_token_store.cpp (3514 lines) and .hpp (1536 lines), recovering truncated chunks; all ports/grpc files; vcpkg-configuration.json; all five Dockerfiles; scripts/ci/detect-code-change.sh, sweep-test-databases.sh, current sentinel and sentinel test; both changed shell tests; both changed Erlang files; runner/new grpc runtime unit test; fragment. Full diffs read for all changed paths. Targeted REST/MCP callers, store error classifier, token regression, Guardian teardown and changed test sections, auth doc rotation contract. Actual audit worker source sections checked; audit-source provenance is not independently authenticated installed artifact evidence.
Pending full-file coverage (explicit, not waived): .github/workflows/ci.yml and tests/meson.build assigned to this agent's ensuing build-ci/cross-platform reviews; large Python tests, token-store test and Guardian test full files assigned QE/Gate3 integration; full large auth/CI docs not completed by docs-writer either (its reported coverage is changed sections plus relevant existing contracts). Required routed domain docs were not all read in entirety in this initial pass; normative security contract deep-read and domain summaries remain required before final Gate2 closure. Root must rerun/consolidate Gate2 after those reviews and any fixes. No false PASS claim for unreviewed files or docs.

Gate3 coverage addendum: this same reviewer completed literal full-file reads of ci.yml (1-3876) and tests/meson.build (1-4952), recovering the small truncated platform-security block. No additional security finding. Overlay/cache trust controls and platform test selection assessed in build-ci.txt/cross-platform.txt. Complete build-guide/windows-build/darwin-compat/troubleshooting now read. Large auth/CI docs and large unit/Python files retain the previous explicit pending status until root consolidates other reviewers; this addendum does not waive them. Reviewer subsequently ran sentinel 38/0 and classifier 54/0; initial report no-tests statement described initial Gate2 phase.

Coverage addendum: personally completed CI architecture801–2000 with no truncation, delegated to resource_ledger for aggregate full-document completion; see ci-doc-801-2000.txt. No new security finding.

Final Gate2 / Gate8 SOURCE closure — 2026-11-11
Root requested collective full-file coverage has now been completed, with exact provenance in source-coverage-addendum.txt: this reviewer read full production token cpp/hpp, workflow/Meson, overlay, runner/new test, small scripts/Docker/Erlang files; resource_ledger read full Guardian/token test/Python and auth document, plus CI1–800/2001–3513; this reviewer supplied full CI801–2000. This closes the initial mandatory modified-file reading residual collectively; it is not a claim that one reviewer independently read every file or revalidated every unchanged historical assertion.
Final current fix review: scoped unique_ptr worker followed by noncopyable crypto guard preserves cleanup-before-retirement and normal unwind, exact patch context checks pass; actual working Python probe/fallback fails before destructive invalidation when both interpreters fail; duration registration restored; NOTICE and parent exact MIT license inspected, compliance owner independently byte-matched baseline. License addition changes no authority/crypto algorithm/runtime code. No further security finding from completed context or current fixes. Original resource-ledger-001 (security report alias security-guardian-001) is source-corrected, without impossibility waiver. Root-build-001 is source-corrected by exact patch application, not dismissed as environment. Mandatory source-domain rereview is complete for security; fresh artifact/runtime verification remains pending ROOT. This is NOT overall governance PASS or evidence of complete native dependency sanitizer shutdown on all platforms.

===== END security-guardian.txt =====

===== BEGIN docs-writer.txt =====
Gate 2 — docs-writer review
Scope: /private/tmp/yuzu-nightly-integration f4c2c95aa → staged/working diff and changelog.d/20261110-nightly-shutdown-rotation.fixed.md. Read-only review; no source edits or remote writes.
Input proof: actual test_runner_main.cpp says “The historical exit-42 diagnosis was too broad: Catch2 itself returns 42 for assertion failures.” Actual new auth prose says “This is a denial check only: raw re-serve still requires the unexpired RAM entry and its matching operator”.

Instructions read: complete docs-writer-prompt.txt; actual .claude/agents/docs-writer.md; canonical governance policy floors/Gate1/Gate2/prose rules; routing.txt. Examined patch.diff in chunks and actual implementation/context for resource lifetime, cache scripts, test fixtures and rotation. Earlier resource-inventory.txt remains an inventory, not a review verdict or exception approval.

Findings: no independently established documentation defect requiring an edit. No stable finding IDs/severity derivations are fabricated for a clean result. This is a scoped documentation result, NOT full-governance approval.

Required-doc decisions and evidence:
1. Public rotation behavior is operator-visible, and the new fragment covers competing operators during publication. Date-based name and multiple bullets are explicitly permitted by changelog.d/README.md. Ran python3 scripts/assemble-changelog.py --check: exit 0, “Changelog fragment lint OK — 132 fragment(s)”. No CHANGELOG.md edit in scope.
2. Closed required-doc rule 1 (REST signature/body/error/permission): docs/user-manual/rest-api.md:1504 already documents in-flight rotation initiated by a different operator as 409. The new denial makes the publication-gap path use that documented conflict; no new HTTP status, permission, request body or response schema. Its grace-window row follows at 1505. I do NOT require a cosmetic REST edit merely to mark it touched. docs/auth-architecture.md:4877+ explicitly records durable-denial/RAM-reveal split and epoch precedence; store check is after epoch expiry and before try_reserve, consistent with that text.
3. Closed rule 2 (workflow/CLI/env/upgrade): no new operator workflow, production CLI flag, env var or schema migration was introduced. Dependency-maintainer workflow is documented in docs/build-guide.md:143+ and ports/grpc/README.txt:21–25: refresh the overlay on baseline bumps and rebuild instrumented dependencies. No extra user-manual upgrade entry justified by this diff alone.
4. Closed rule 4 (architectural invariant/store/ABI/release gate): no new store, public ABI pattern or release gate. Scoped test runtime RAII and dependency-overlay recipe do not establish a new cross-cutting production invariant requiring CLAUDE.md duplication.
5. Closed rule 5: no new audit action, permission or error code. Different-operator denial string already exists in the same method and REST matrix.
6. Routed update obligations: Guardian change fixes timing of an existing test, not production acknowledgement behavior. The R5 accepted-versus-acknowledged contract (docs/spark-stage2-guardian-consumer-design.md:339+) and legacy delta registry A3 already say pending arms hold acknowledgement. New comments correctly require earlier arms to settle before same-call acknowledgement is asserted. No new DEX signal, plugin action, migration or roadmap capability justifying catalogue/DSL/playbook entry. Read relevant Guardian/Spark, Windows implementation-plan and DEX catalogue sections to establish this boundary; did not claim all historical domain documents were exhaustively reread.

Changed prose and truth boundaries checked:
- Runner header and ports/grpc README distinguish default-engine ownership from custom engines/caller-owned threads. Actual patched worker source confirms ThreadBody then OPENSSL_thread_stop then delete ThreadState; Quiesce waits a living-thread counter, not OS-level TLS teardown. “not a general thread join” is accurate. The README's “does not cover custom engines” conservatively describes application ownership; a custom engine reusing the patched pool may benefit but is not owned/drained by the suite runner.
- Resource inventory flags new manual OPENSSL_thread_stop for cpp-safety policy adjudication. Wording cannot grant an exception. This report neither approves the implementation nor dismisses that issue as prose.
- The test regression comment says sanitizers cover process cleanup; unsanitized Windows/macOS retain hard_exit after suite teardown. The normal-exit intent must be evaluated with actual ASan/TSan/coverage macro legs by cross-platform/cpp-safety. No claim of completed fresh Windows validation is made here.
- Sentinel documentation matches file-name/content digest, relative config paths, refusal of nested directory symlinks, missing-input failure before cache mutation, and unchanged digest stream when overlay list is empty. Workflow canary key now includes ports/** and classifier matches those same dependency paths.
- Dockerfile changes copy ports before vcpkg install; changed cache comments match dependency layer inputs.
- Python fake-server comment correctly places logical request completion before response visibility; delayed socket writer illustrates the post-response scheduling gap. MCP fixture's stdin=None avoids communicate flushing an explicitly closed pipe.
- Gateway fixture changes explicitly set SHA-256 for RSA/EC while retaining EdDSA key selection. The claim that OTP ignores external digest for Ed keys is handed to gateway-erlang/security for domain truth verification; I did not execute OTP here.

Cross-domain validation question sent to root (not silently dismissed as wording):
New scripts/ci/vcpkg-triplet-sentinel.sh:92 unconditionally invokes python3; docs/ci-architecture.md:3221 says runners' python3. Existing tests/shell/test_build_examples_gating.sh:87–99 explains Windows runner provision guarantees python, never python3, and probes both to avoid Store aliases; docs/windows-build.md:16 separately says MSYS2 python3 exists but cannot open native C:/ paths. The sentinel cd's to the workspace and uses relative paths, so that path incompatibility by itself is NOT proof of failure. .github/workflows/ci.yml:2429 invokes the new sentinel on Windows. Asked root to have build-ci/cross-platform establish the actual current executable availability/version in that shell. I cannot derive a supported-platform break solely from contradictory historical interpreter comments; no invented blocking finding. This question is actionable validation context, not a speculative operational finding.

Coverage limitations:
Reviewed every changed diff section, new port files/README, and focused actual implementation/context; did NOT read tens of thousands of unchanged lines in all large modified files top-to-bottom. Consequently this does not satisfy the literal exhaustive-file-read instruction in the role brief; root must not represent it as that exhaustive sweep. Domain truth checks for installed gRPC 1.81.1 across all platforms, OTP EdDSA behavior, fresh Windows interpreter availability and full sanitizer closure remain with their assigned reviewers/validation. No live store changes, local C++ compile, sanitizer run, or gateway run performed by this docs reviewer.

FOLLOW-UP FINDING — supersedes initial no-findings statement for original reviewed snapshot
ID: docs-writer-001
Classification: truth / introduced CI interpreter compatibility defect; domain owner build-ci + cross-platform. Not wording-only and not an I7 omission.
Location (original snapshot): scripts/ci/vcpkg-triplet-sentinel.sh:92; docs/ci-architecture.md:3219–3221 original runners' python3 claim; tests/shell/test_build_examples_gating.sh:87–99 existing fallback rationale; .github/workflows/ci.yml:2429 Windows caller.
TRIGGER: python3 resolves to a nonworking App Execution Alias (reproducer shim exits 49), while a working python exists in PATH.
IMPACT: I5, CI dependency setup unavailable because sentinel exits 2 before hashing; I8, misleading generic overlay-hash failure although a usable interpreter is installed. No production data corruption or security bypass asserted.
EXPOSURE: E4 (specific interpreter/PATH configuration), E6 (the named wrong outcome is failure of the CI sentinel, not a production binary path; capped LOW). No E7 because this script gates CI.
EPISTEMIC: verified from root's disposable reproduction log /private/tmp/yuzu-nightly-governance/python-alias-before.log, which I read: existing normal/drift/first-run tests repeatedly report got 2 and overlay edit/add/remove checks fail. Reproduction performed by root, not falsely attributed to this reviewer. Current physical Windows host configuration was not separately measured.
Derived band: I5 MEDIUM, E4 no raise, E6 cap LOW. severity_native: NICE by band vocabulary; gating is BLOCKING by policy floor independently of operational band.
Policy floor/provenance: canonical .claude/skills/governance/SKILL.md policy floors: “a broken build or test leg on any supported platform that this change INTRODUCED or newly exposed”. This invocation newly requires working python3 despite repository's explicit supported Windows fallback contract and usable python; failure is introduced by unconditional interpreter selection. Root has established the candidate executable-failure configuration experimentally. This is not a mere pre-existing unavailable dependency.
Recommended correction: probe python3 then python with an actual interpreter invocation; preserve failure before cache mutation if neither works; add regression for a nonworking python3 with working python and update docs to the actual selection rule.
Disposition at report update: root has already applied an apparent probe/doc fix while this report was being finalized. Read current docs lines 3219–3221 and confirmed they now describe probing python3 then python and Windows aliases. Implementation and regression revalidation belong to Gate 8; not marked closed solely from changed prose. If consolidated with build-ci's same finding, retain this as duplicate provenance rather than counting twice.

Gate 8 docs-writer fix re-review:
Read actual unstaged fix diff for sentinel, new four-check regression, docs/ci-architecture.md and 00017 RAII patch. Independently ran bash scripts/ci/test-vcpkg-sentinel.sh: exit 0, 38 passed, 0 failed. This includes broken python3 alias -> working python, overlay hashed, both interpreters broken -> error, and installed state preserved. docs-writer-001 disposition: FIXED, verified by this reviewer; no exception adjudication needed. New docs accurately describe actual probe order and executable test. Fresh Windows binary integration remains separate from this disposable compatibility regression.
RAII patch comments now accurately describe declaration order: unique_ptr<ThreadState> worker precedes ScopedOpenSslThreadState, so reverse local destruction calls OPENSSL_thread_stop before destroying worker/publishing retirement. This supersedes resource-inventory entries 4–5's original raw/manual cleanup description; resource owner changed to unique_ptr plus scoped crypto-state owner, including ordinary C++ unwinding after construction. No independent manual-cleanup impossibility exception is needed for the revised shape. Full C++ exception/thread semantics and patched dependency build remain cpp-safety/cpp-expert scope.

Final Gate2 / Gate8 documentation SOURCE closure — 2026-11-11
This addendum is routing's final synthesis/review of original docs-writer plus resource_ledger's completed collective full-file review, not a new independent docs opinion. Actual docs-writer brief read. source-coverage-addendum.txt supersedes initial modified-file reading residual: full changed source/docs collectively covered with reviewer spans explicit, including auth6019/CI3513/token-test6480/Python2741+583. Changed contract checks remain as original required-doc decisions: operator competing-rotation409 already documented, raw RAM-only grace/restart limitation retained, fragment present, overlay refresh/rebuild and working-interpreter rule documented, no new API/permission/CLI/store/invariant requiring invented duplicate docs. Current RAII comments accurately state reverse-destruction order rather than thread join. Current NOTICE accurately scopes imported upstream files and excludes local00017/README; exact MIT notice closure belongs to compliance-officer001. No additional missing required-doc or wording finding identified. docs-writer001 remains source/test FIXED; quality-engineer001 duration source FIXED. The pre-existing A5 revisit debt enterprise-readiness001 remains separately visible and is not silently renewed. Runtime validation pending, not overall governance PASS.

===== END docs-writer.txt =====

===== BEGIN architect.txt =====
Gate 3 — architect (sequential role review, same reviewer as cpp-expert/cpp-safety)
Scope: base f4c2c95aa to current working tree; no source edits or remote writes.
Verdict: no remaining architecture finding identified in reviewed changes. This is a source-domain conclusion, not permission to bypass pending fresh platform validation.
Input proof: `successor->rotation_initiator != requesting_user` and `link_with: grpc_test_runner,` occur verbatim in current source.

Reasoning:
1. The only production token-store change is a denial within the existing transaction's two-active branch, after epoch expiry and before RAM reservation. Durable initiator is an existing column, not a new schema or persisted secret. It prevents a different operator's retry in the commit/publication gap; same operator still needs resident raw cache. No new authority source, capability, endpoint, grant, query-owner seam, public signature, or migration is introduced. Existing different-operator error contract remains applicable. ADR-0012 authoritative-store and one-lease boundaries remain intact: the added comparison acquires nothing, does no external work and calls no sibling store.
2. The new test-only static library owns the single server/regression main and links downward to Catch2 and grpcpp. Server tests link the library; the library does not link server tests or server core. Agent tests retain their own ordinary entry point for fork-without-exec isolation. No cycle or production server-to-agent dependency is added. The reused hard_exit header is an existing runner dependency, not a new architectural boundary crossing.
3. The overlay belongs at the dependency worker lifetime boundary: only the worker thread can release its own OpenSSL thread state. The runner owns suite default-engine lifetime, while per-fixture engines/threads remain their creators' responsibility. The docs/comments now explicitly state this limit. RAII guard ordering is proved in cpp-safety.txt and the exact upstream callback checks; no global cleanup primitive is added to shared common headers.
4. No proto or sdk ABI source changes occur; no ABI/version bump or wire migration is warranted. Guardian changes synchronize a fake mechanism and assertions in tests, not production execution or persistence semantics. Cache fingerprint change records overlay content as dependency identity, appropriate to the build layer; build-ci owns operational cache details.
5. No new product feature, store, schema, metric, permission or audit action needs a new capability/roadmap/audit-table entry. Existing auth architecture and build/CI docs describe the changed implementation; no changed normative architecture claim contradicting reviewed code was found.

Coverage: complete role brief and prompt (shared severity preamble previously read, role suffix checked); canonical Gate3/routing context; current C++ changed methods and test Meson diff; complete runner, grpc regression, Guardian test previously personally read; exact gRPC1.81.1 worker/header/default-engine source and overlay. Architecture core/dependency, storage, ABI and security sections read; ADR-0012 relevant decision clauses and store-playbook substrate/authoritative-store rules read. Complete token implementation/header coverage is shared with security-guardian, with changed method independently reviewed. Large unrelated architecture inventory/observability/roadmap/capability prose and full unchanged token-test file were not exhaustively reread; no claim of complete repository audit. Other-role detailed evidence: cpp-expert.txt, cpp-safety.txt, security-guardian.txt, docs-writer.txt.

No findings means no artificial severity derivation rows. Pending validation: fresh rebuilt overlay on Linux sanitizers and Windows/macOS as tracked by root; historical binaries do not establish current overlay correctness.

===== END architect.txt =====

===== BEGIN cpp-expert.txt =====
Gate 3 — cpp-expert (language/portability)
Scope: f4c2c95aa -> current /private/tmp/yuzu-nightly-integration working tree, including root's RAII fix. Sequential role review by resource_ledger agent; not an independent second opinion from this agent's preceding docs/resource work.
Input proof: revised patch's exact callback contains std::unique_ptr<ThreadState> worker(static_cast<ThreadState*>(arg)); then ScopedOpenSslThreadState crypto_state, then worker->ThreadBody().
Instructions: complete cpp-expert prompt; both Codex cpp skills; actual .claude/agents/cpp-expert.md and cpp-safety.md; complete docs/cpp-conventions.md and docs/ci-cpp23-troubleshooting.md; governance Gate3 matrix and shared severity/prose/floor rules; gate1/resource inventory/routing and available security-guardian.txt/docs-writer.txt read.

Findings: none remaining in inspected changed C++ after RAII correction. No fabricated severity derivations for a clean result. Original manual-cleanup floor is tracked as security-guardian-001, not rediscovered or self-waived here.

Evidence:
- Added denial is std::string comparison against a pointer into local active vector, after null/recognized-pair checks and epoch expiry, before cache reserve. No vector mutation or escaped borrowed pointer; false return uses existing transaction and secret scrub guards. Existing public error/expected contract remains; no C ABI/header layout change.
- New deterministic rotation test captures stack references only for synchronous hook invocation, uses explicit has_value before error/value access, and keeps pool/store/database destruction order correct. No new threading primitive or concurrency mutation beyond existing synchronous test hook.
- SuiteGrpcRuntime is noncopyable, with a user-declared destructor suppressing implicit moves. SetDefaultEventEngine takes shared_ptr by value and moves it into the global strong slot; runner retains no extra reference that would wedge WaitForSingleOwner. Declaration order destroys Catch Session before runtime, including early applyCommandLine return. gRPC C APIs retain their existing conventions; no plugin ABI seam touched. Existing fprintf diagnostic is moved, not a new formatting subsystem.
- Revised dependency patch uses C++11/17-compatible unique_ptr/local guard, valid under upstream C++17 as well as Yuzu C++23. <memory> already included in exact v1.81.1 worker source. Guard explicitly defaults constructor (required because copy ctor is user-declared), deletes copies, and has implicitly nonthrowing destructor around C cleanup. No C++23-only feature leaks into upstream gRPC target. ThreadState implicit destructor is accessible; private nested type is named in owning member's callback scope.
- Secure-target PRIVATE define does not affect grpc_unsecure/standalone targets. OpenSSL>=1.1 path calls stop; BoringSSL/LibreSSL/old-version/no-define paths omit it. No unconditional libcrypto symbol introduced on omitted branches.
- Runner ASan/TSan detection covers compiler macro and __has_feature families; coverage is passed explicitly to archive/agent via Meson. The static runner archive supplies one main to server and isolated regression; agent compiles ordinary runner without persistent pool. No new ODR/suppression duplication in a single target found by source graph inspection. Build-ci owns final linker validation.
- Guardian modified test uses chrono literals already in scope, synchronized gate methods and existing owning fixture teardown. Entire 2822-line Guardian file read in bounded chunks; no changed-line portability defect found. Pending-worker and inherited-latch checks remain distinct, with final synchronous assertion only after drain.

Exact source provenance and local checks:
Fetched official https://raw.githubusercontent.com/grpc/grpc/v1.81.1/src/core/lib/event_engine/thread_pool/work_stealing_thread_pool.cc and .h, plus .../default_event_engine.cc. Stored as grpc181-worker-upstream.cc/.h and grpc181-default-upstream.cc beside this report. Worker .cc byte-identical to prior audit grpc_thread_pool_181.cc. SHA256:
worker.cc 3213864f045b54cf6428c29ba7ee282c2c92ad50c348caacb91eb5ddf11390de
worker.h b7f901d74cde112d75501bb86ba9ac9def5b099da55425eba9adc8db20ec22fa
default.cc e95512f8480176967a03197a00559585862ab7ce9ff53d9c40f9aee8a101d873
Revised patch applied cleanly to worker source plus audit CMakeLists (PACKAGE_VERSION/gRPC_CPP_VERSION 1.81.1). Applied copy retained in cpp-check/. Overlay baseline files compare text-identical after CRLF normalization except intended patch recipe entry and port-version 1; no hidden source change inferred from byte-level line-ending differences.
Compiled exact extracted callback with Homebrew Clang 23.1.4 on arm64 macOS (not Apple Clang) -Wall -Wextra -Werror under C++17 and C++23 across secure OpenSSL3, secure1.1, old OpenSSL, BoringSSL, LibreSSL and unsecure macro branches: 12/12 compile+run PASS. Harness in cpp-check/callback.cpp verifies normal and thrown-ThreadBody guard-before-worker destruction. This is a narrow language/preprocessor check using stand-in ThreadState/crypto callback; it does NOT substitute for real dependency compile, OpenSSL semantics, OS threads or sanitizer evidence.

Coverage/provenance limits:
Full runner/new regression/Guardian source and all changed C++ diff reviewed; full rotation method, supporting pool rollback, helper and token test changed region independently read. Security-guardian reports full api_token_store.cpp/.hpp read; root authorized collective unchanged-line coverage reuse with that attribution. Token test is 6480 lines; only header/helper and changed/neighboring rotation regions personally read. Quality-engineer must close remainder if literal full-file coverage is required. No fresh MSVC/GCC full-target build performed by this reviewer. Root reports fresh RAII dependency rebuilds in progress; historical pre-RAII/older-gRPC Windows results are not current closure.

PASS — changed-code C++ language review; full-platform validation remains pending and is not waived.

===== END cpp-expert.txt =====

===== BEGIN cpp-safety.txt =====
Gate 3 — cpp-safety (ownership/lifetime)
Scope and reviewer provenance: same resource_ledger agent sequentially performs cpp-expert then cpp-safety on f4c2c95aa -> current worktree. This is a distinct domain analysis, not independent discovery or independent adjudication of our prior inventory. Complete shared preamble/role suffix and actual safety brief/skill read; see cpp-expert.txt for common source coverage and exact upstream provenance.
Input proof: new guard comment reads “Quiesce observes that retirement, not detached pthread/FLS teardown.”

Findings: no remaining concrete lifetime defect identified in changed code after root's RAII correction. The ORIGINAL new manual OPENSSL_thread_stop violated the canonical manual-cleanup floor (security-guardian-001). Current code resolves it with RAII; no documented-impossibility exception or adjudicated_by waiver is needed. Not recasting a floor as stylistic NICE.

Ownership proof against all 14 resource-inventory entries (including appended fix update):
1–3. SuiteGrpcRuntime acquires created engine into global owning slot, then one grpc_init reference. A completed object releases with grpc_shutdown_blocking then ShutdownDefaultEventEngine. Actual exact v1.81.1 default-engine source confirms strong/weak variant and WaitForSingleOwner after clearing the slot. Session/listeners are destroyed first in run_suite. Creation temporary is shared-owned before transfer; no later throwing C++ allocation added after installation in constructor. Existing APIs remain responsible for their internals. stdout/stderr/argv are borrowed, not closed. main's hard_exit is reached only after automatic suite/runtime destructors complete.
4–6. Callback receives existing upstream new ThreadState pointer through void*, immediately adopts into unique_ptr. Static cast reverses the exact pointer originally passed, no type punning. ScopedOpenSslThreadState declared second so its destructor executes first, before ThreadState auto_thread_counter_ decrements. Header confirms pool_ member outlives counter. LivingThreadCount's inspected mutex/condition-variable decrement/wait synchronizes retirement, so observer cannot pass that barrier before stop returns. ThreadBody drains callbacks and unregisters/deletes local queue before returning. RAII callback now cleans worker/crypto on ordinary C++ unwind as well; an exception that escapes the underlying thread ABI still has upstream fatal semantics and is NOT asserted recoverable. Detached worker remains upstream design; change supplies precise crypto lifetime barrier rather than an OS join. Lifeguard is separately stopped via notifications and does not dispatch user crypto callbacks. PosixEventEngine inspected destructor shuts timer manager then Quiesces executor. No claim that arbitrary custom TLS destructors may use OpenSSL after global cleanup.
7–8. Lifetime regression owns callback promise by shared_ptr value; future owns shared state; on timeout or REQUIRE exception local engine/future refs release while queued lambda retains its own promise. Worker bytes stack array does not escape RAND calls. set_value occurs once. Main thread and worker initialize crypto intentionally; guard cleanup is on the worker, not incorrectly on main. Shutdown still needs all caller-owned custom engines/threads released by fixtures; explicit README/runner contract states that boundary.
9–12. PostgresTestDb owns salted temp database; PgPool declared next, ApiTokenStore next. Reverse destruction clears store/callback/cache, drains/finishes pool, then drops DB. PostgresTestDb's admin PGconn and PGresult use PgConn/PgResult wrappers; failures log, no throwing destructor path added here. Store borrows pool; new callback borrows live locals synchronously and no destruction-time invocation found. Added production false return occurs under existing PgTxn; inspected run_in_txn destroys txn (rollback) before lease, including throw. Secret ScopeExit covers candidate_raw, grace_raw_out, cached_raw, raw_out; no new uncached-secret reveal or borrowed escape introduced. Callback's nested rejected rotations terminate before hook stage, no recursion owner cycle.
13–14. Guardian new parked File watch is held behind CountingMechanism mutex/CV. Rig owns mechanisms via SparkEngine; fm/sm aliases remain borrowed. Normal path releases hang, drains receipts and waits compliance. Failure path Rig::~Rig -> close releases both mechanisms' watch/unwatch gates before waiting for active workers, destroying GuardianEngine then SparkEngine then KV then temp files. AttachProbe captured by shared_ptr in engine hook, so no probe escape when local reference dies first. Existing bounded close wait reports failure before engine cleanup; this change does not create a new orphan owner or weaken it. No real OS watch handle introduced by fake mechanism.

Other routed safety surface: sweep-test-databases change only executable discovery. Read clock-guarded-retention rule and changed discovery with surrounding argv-based invocation/strict DB name guards. New path is selected as a quoted executable; no shell interpolation of external input introduced; SQL retention selection/deletion remains unchanged. No new process, fd, mapped library, BCrypt object, SQLite statement or raw C string introduced in changed first-party C++ beyond inventory's wrapped/transitive resources. Copied upstream patches retain original recipes apart from line-ending normalization; modified 00017 owns new cleanup.

Validation personally performed: exact upstream-tag fetch + clean patch apply; 12 callback compile/run macro cases under C++17/C++23, normal plus ordinary throw ordering (cpp-check/callback.cpp). These establish syntax/branch exclusion/local destruction order ONLY. Parent's fresh full Linux ASan/TSan and Windows overlay runs are pending at this report's timestamp; no green inference from old dependency binaries or synthetic harness.

Resource Ledger: complete for changed resource boundaries, with appended RAII fix update. Root should refresh consolidated Gate1 copy so downstream readers see current ownership rather than only original entries 4–5.
Sanitizer coverage needed: ASan/UBSan for teardown memory and TLS state; TSan for worker stop/count-quiescence ordering and fixtures; real Windows and macOS dependency build/runtime because detached pthread/FLS cleanup and static-link inclusion differ. Fresh RAII patch must be in tested dependency; historical Windows gRPC1.76 evidence is insufficient. Root reports that fresh builds are running.
PASS — source-level ownership review; validation pending, not an unconditional full-governance pass. Next roles: quality-engineer must close token test full-file read and evaluate negative controls/process-exit observations; build-ci/cross-platform must certify fresh dependency artifacts. SRE must retain custom-engine/caller-thread and blocked shutdown boundary in operational review.

===== END cpp-safety.txt =====

===== BEGIN quality-engineer.txt =====
Gate 3 — quality-engineer (sequential review by same reviewer as C++ roles)
Scope: current working diff from f4c2c95aa, including root RAII and Python-fallback fixes. No source edits.
Input proof: `REQUIRE(interleaved);` and `CHECK(same.error() == "rotation grace window elapsed; confirm or revoke");` are actual lines in the new publication regression.
Verdict: one LOW diagnostic convention finding; no false-green blocker identified. Whole-platform validation remains pending, not inferred from source review or historical runs.

quality-engineer-001 — new runtime test omits case duration argument
Location: tests/meson.build:80–81, grpc runtime lifetime registration.
TRIGGER: CI executes the new yuzu_grpc_runtime_tests registration.
IMPACT: I8, degraded but correct: individual Catch2 case timing is omitted, weakening timing/ranking diagnostics.
EXPOSURE: E6 (this omission affects test reporting only, not production execution); E0 not claimed because it is not production.
EPISTEMIC: verified source inspection; no runtime timing output observed here.
DERIVED BAND: LOW (I8 LOW, E6 caps LOW).
severity_native: NICE (brief supplies no alternative vocabulary; governance map applied).
BLOCKING: no. Policy floor: none; docs/testing/unit-test-conventions.md is a convention, not one of the three closed invariant sources.
Classification: test infrastructure convention, not missing required product documentation.
Provenance: unit-test-conventions "Suite placement": a new yuzu_*_tests entry carries '--durations=yes'.
Suggested fix: args: ['--durations=yes']. Root notified. Status at report time OPEN.

Coverage reasoning and evidence:
1. Token publication regression uses the real ephemeral pre-migrated PostgreSQL fixture and production store. The synchronous hook runs after commit and before raw-cache insertion, deterministically traversing the target gap without sleep/scheduler luck. A different operator must receive the specific denial, same operator must not recover uncached raw secret, interleaved is required, active count remains two, successful replay matches original raw secret, and epoch expiry still outranks operator denial. This can observe the changed branch; without it the different-operator assertion sees the former grace-expired error. Existing neighboring tests cover six racing callers and the two-active ceiling. Fixture schema isolates constant principal names across processes. Hook uses live locals synchronously and is never invoked by store destruction.
2. Standalone grpc test uses the SAME compiled entry point as server tests and runs in a fresh process, preventing unrelated fixtures from masking the weak-default ownership check. It drops its initial engine reference before REQUIRE_FALSE(observed.expired()), reacquires the actual default, initializes main crypto, schedules public/private RNG work, waits with a bounded future and observes success. Promise is shared-owned by callback, so REQUIRE timeout cannot leave stack captures. It is correctly registered for both relevant suites and linked to no-main Catch2.
3. The RNG test alone does not deterministically prove every detached TLS cleanup ordering. Its process exit under sanitizer is necessary closure evidence; unsanitized Windows/macOS hard_exit cannot prove global destructor safety. Runner enables ordinary exit for ASan/TSan/coverage, and explicit suite cleanup runs even with invalid CLI. Root is obtaining fresh rebuilt dependency validation. Do not mark blocking lifetime closure based on assertion-only or historical binary success.
4. Exact patched callback was compiled/run under c++17 and c++23, six secure/unsecure/vendor macro variants each, 12/12 PASS (cpp-check/validation.txt). Normal and thrown ThreadBody paths assert OpenSSL cleanup before worker destruction/counter retirement. This checks local RAII including failure unwind, but uses stand-in ThreadState/OpenSSL and is not a real sanitizer run. Deleted copy operations ensure the guard cannot be copied; current source owns ThreadState with unique_ptr.
5. Guardian regression's gate/order changes remove the scheduler-dependent selection of the blocked watcher: wait for x compliance before arming the hang, park a, assert pending, release/drain, await compliance, then verify inherited debt and final clean acknowledgment. Full 2822-line test file was read in prior C++ review, including Rig destructor releasing parked watch/unwatch calls before drain. Gates are released on teardown when REQUIRE unwinds; shared probe outlives worker use.
6. Cache sentinel shell regression independently rerun after Python-fallback correction: 38 passed, 0 failed, exit 0. Covers matching/no-op, first run, stale registry, missing manifest, overlay edit/add/remove (including spaced relative path), missing overlay fail-without-wipe, broken python3 alias using valid python, and both interpreters broken preserving installed state. Original supported-platform regression is recorded in docs-writer-001 and corrected; this is direct empirical closure, not inferred from prose.
7. No new parser/store/manager or changed input grammar calls for a new fuzz harness. Test coverage document is explicitly directionally accurate and already admits historical count drift; this diff does not justify reporting that pre-existing inventory as a new blocker. Existing giant tests are not mistaken for newly added coverage.

Read coverage/limits: complete role brief and prompt via shared full severity preamble plus role suffix; full unit-test-conventions; complete runner, new grpc regression, Guardian test, current sentinel regression; modified tests/meson.build hunks; token test header and full changed publication + neighboring concurrency/rotation cases, with method contract independently reviewed. Full api_token_store implementation/header collective coverage comes from security-guardian, not a claim this QA pass independently reread 5000 lines. The unchanged remainder of the 6480-line token test file is NOT full-file reviewed here; root must retain that limitation or assign residual coverage. Architecture/coverage reference docs were targeted reads; large unrelated tables are not represented as fully audited. Gateway fixture behavior, shell configure smoke real host execution, and fresh Linux/Windows/macOS integration are delegated to their owning reviewers and root validation, not passed by this report.

===== END quality-engineer.txt =====

===== BEGIN build-ci.txt =====
Gate3 build-ci review — current working tree, base f4c2c95aa77bfc573614bdb381a010fc2a15d366
Disposition: no additional independently discovered defect in reviewed change; source review complete for workflow/build graph and dependency overlay. Native fresh dependency execution pending root evidence. This is not a claim that the full platform matrix passed.

Instructions/coverage: complete supplied build-ci prompt and actual .claude/agents/build-ci.md; ci-cache skill; Windows MSVC skill; build-guide, windows-build, darwin-compat, ci-cpp23-troubleshooting read. Complete ci.yml (3876 lines), tests/meson.build (4952 lines), all ports/grpc files, all five Dockerfiles, configuration manifest, changed small shell scripts and tests read; any truncated reads recovered in bounded chunks. Large ci-architecture/auth docs remain targeted-section coverage, not full read. No source edits.

Build truth:
- Canary classifier includes vcpkg.json, vcpkg-configuration.json, triplets and ports; vcpkg cache key includes ports/**. Overlay config/content participates in persistent sentinel invalidation before configure. Bad/unavailable interpreter fails before removal; python3 AppExecutionAlias now falls back to working python.
- Cache restore/save pattern remains split. Save requires successful coherent install and cache miss with explicit status handling; trusted-fork cache-write restrictions remain. Persistent self-hosted local caches remain separate from GHA round trips. No added cache permission expansion.
- Docker dependency stages copy both overlay manifest and port directory before vcpkg install; pinned grpc source/hash and existing upstream patch stack retained. Sanitizer triplets remain static.
- New runner archive declares grpc dependency and uses Catch2 without library-provided main. Server links archive instead of a duplicate main TU; agent retains its direct runner without persistent default-engine owner. Coverage flag reaches runner archive and agent path. OpenSSL dependency uses system includes. New lifetime target is registered in both agent/server suites, included by cheap Linux agent and Windows agent suites, macOS non-docs selection, and nightly unfiltered runs.
- Windows hand-wired static protobuf/grpc/abseil closure and triplet overrides unchanged. No proto generation files changed. Existing gateway registration remains.

Validation by this reviewer: bash scripts/ci/test-vcpkg-sentinel.sh 38 passed/0 failed; bash tests/shell/test_detect_code_change.sh 54 passed/0 failed. No full build invoked by reviewer. Root owns fresh Linux/Windows runs.

Known original issue (root-discovered, not independent): sentinel unconditionally invoked python3, reproducing failure on Windows AppExecutionAlias. Current working source probes execution and falls back to python, with four new test8 assertions; source/test correction accepted. Preserve root finding identity/severity in shared ledger rather than duplicate it.

Windows execution plan reviewed: /private/tmp/yuzu-nightly-governance/windows/{build-bootstrap.sh,build-online.sh,build.sh,verify.py,meson.build,vcpkg.json}. Isolated native-MSVC setup, exact 9eec002df1cd109f8f104cd966a763daf9751489 baseline, copied project triplet/overlay, minimal grpc[codegen]/catch2/openssl/zlib manifest; custom runner archive links actual installed libs. Ten normal plus ten coverage launches assert five assertions/one case; invalid CLI verifies nonzero exit and runner epilogue. This can establish overlay compilation and focused runner shutdown, NOT full project Windows Meson graph or full Windows suite. Require root logs/results and installed/source patch identity before converting pending execution to passed. Root lock7ee7688ab99d governs resource ownership; reviewer did not access remote/build resources.

Correction addendum: current regenerated00017 passes independent git apply --check against pristine worker .orig and exact audit grpc CMake input. Root reports real Windows vcpkg now applies it. Earlier context defect was root-discovered, not independent reviewer finding. git diff --check flags nested patch context whitespace and preserved upstream recipe trailing space; not called clean. Windows YUZU_TEST_COVERAGE variant is normal-exit coverage-guard behavior only, no instrumentation/coverage metrics.

Attribution fix rereview: NOTICE and parent ports/LICENSE-vcpkg.txt read. Existing COPY ports/ ports/ in all five images carries license into builder. Canary hashFiles ports/** will change cache identity once; per-port recipe bytes/ABI remain same. No runtime source edit by this fix, so no rationale to restart unchanged binary compilation solely for attribution. Compliance owns obligation/exact upstream notice closure.

===== END build-ci.txt =====

===== BEGIN cross-platform.txt =====
Gate3 cross-platform review — current working tree, base f4c2c95aa77bfc573614bdb381a010fc2a15d366
Disposition: no additional independently discovered cross-platform defect; focused Windows execution remains pending root results. No blanket platform-matrix PASS.

Complete common supplied prompt read; cross-platform prompt differs only in role line, verified by diff. Actual cross-platform brief and build-ci brief read. Applied ci-cache and yuzu-windows-msvc skills. Read complete darwin-compat, windows-build, build-guide and ci-cpp23-troubleshooting. Full ci.yml/tests Meson, overlay/recipes, Dockerfiles and changed small scripts read with truncation recovered. Security report retains explicit pending full large-doc/test coverage.

Compatibility assessment:
- Secure-target compile definition scopes worker OpenSSL cleanup; BoringSSL/LibreSSL and pre-1.1 OpenSSL excluded. Standard unique_ptr and local deleted-copy scoped guard are valid across supported compilers, with existing <memory> include. Reverse scope order releases OpenSSL state before ThreadState destruction publishes worker retirement. This is not an OS join or a guarantee about later unrelated TLS destructors.
- Runner owns default EventEngine only in opted-in server/runtime archive; agent fork-without-exec tests retain thread-quiescent entry semantics. Scope guard preserves Session destruction first and runtime release afterwards. Runtime callback's owning promise avoids borrowed lifetime through timeout. No platform-specific syscall added.
- MSVC static grpc/proto/abseil and dynamic CRT selection remain unchanged. Runtime test is in suite agent as well as server, so supported Windows suite filtering includes it. macOS workflow also includes it. No changes to Darwin framework probes, min deployment target, Foundation/Objective-C++ or Windows plugin ABI.
- Root-discovered Windows python3 alias defect corrected with executable probe and python fallback, covered by sentinel test8; reviewer ran complete sentinel 38/0. Detector regression 54/0. This is a fix rereview with root provenance, not a new independent finding.
- All overlay consumers in five changed Dockerfiles now have overlay files before install; Linux ASan/TSan static triplets retained. No imported Linux-only compiler flags into Windows or Darwin paths introduced by change.

Evidence limit: source review is not native execution. Root's fresh Shulgi minimal manifest/native MSVC recipe inspected and suitable for dependency patch + normal/coverage runtime validation (10 launches each plus invalid CLI). It deliberately does not configure the entire project; report this scope alongside any passing output. Root owns lock and logs. No remote test run by reviewer. Existing/local macOS libraries cannot prove new overlay built unless provenance is captured. Root must combine its native/sanitizer evidence and Gate8 correction reruns before final closure.

Correction addendum: current regenerated00017 passes independent git apply --check against pristine worker .orig and exact audit grpc CMake input. Root reports real Windows vcpkg now applies it. Earlier context defect was root-discovered, not independent reviewer finding. git diff --check flags nested patch context whitespace and preserved upstream recipe trailing space; not called clean. Windows YUZU_TEST_COVERAGE variant is normal-exit coverage-guard behavior only, no instrumentation/coverage metrics.

===== END cross-platform.txt =====

===== BEGIN gateway-erlang.txt =====
Gate3 gateway-erlang — current working diff from f4c2c95aa
Disposition: no new source-domain finding. Full gateway suite/dialyzer evidence remains root-owned; not inferred from narrow helper execution.
Provenance: same reviewer as Gate2/build-ci/cross-platform, distinct role analysis, not independent convergence. Complete gateway prompt and brief read, truncations recovered; gateway-eunit and gateway-dialyzer skills read; complete erlang-gateway-build read with recovered middle. Both changed Erlang files previously read completely; changed fixtures reread.
Input proof: Config = public_key:pkix_test_data(#{root => Ca, peer => [{key, PeerKey}, {digest, sha256}]}).
Findings: none; no artificial severity rows.
The changes select SHA256 for RSA/EC root/leaf fixtures. Ed roots still omit a digest override and Ed leaf handling retains intrinsic algorithm. CRL signature algorithm selection stays unchanged. Existing equal-size PEM helper still compares actual encoded lengths and retries RSA generation rather than assuming the digest guarantees a fixed byte count. No production trust verification, CRL acceptance policy, supervision tree, connection lifecycle, proto, application dependency or OTP version change. No new bare process/link/timer/mock lifetime introduced.
Empirical evidence: scripts/erlang_toolchain.py find-otp selected /Users/nathan/.kerl/28.4/bin release28.4. Current yuzu_gw_crl_build.erl compiled into disposable gateway-check directory. Fresh BEAM minted root+leaf for ec/rsa/ed25519/ed448; decoded OIDs were EC1.2.840.10045.4.3.2, RSA1.2.840.113549.1.1.11, Ed25519 1.3.101.112, Ed448 1.3.101.113; exit0. This directly supports digest comment truth but is not the entire gateway suite or dialyzer. Root must attach compile/eunit(nonzero executed tests, no cancellation)/dialyzer results; helper passing does not waive those requirements.

===== END gateway-erlang.txt =====

===== BEGIN release-deploy.txt =====
Gate3 release-deploy — current working diff from f4c2c95aa
Disposition: no additional source-domain finding; full image build/runtime validation not performed by this reviewer.
Complete actual release-deploy brief and prompt read (shared prompt prefix byte-compared with fully read gateway prompt; role suffix read). Prior full five Dockerfile, overlay recipe/patches, build-guide and Windows/Darwin references reused; changed fragment read. Same reviewer as build-ci, not independent convergence.
Input proof: target_compile_definitions(grpc PRIVATE YUZU_GRPC_OPENSSL_WORKER_CLEANUP=1).
All five changed dependency stages copy vcpkg-configuration.json and ports before vcpkg install; overlay is therefore present when resolution runs. Source archive hash/baseline/imported upstream patches retained, local port revision bumps. Runtime stages retain existing selected binaries/libs and service identity/entrypoint/healthcheck/port topology; no build-source copy added to production runtime. No new schema/config/user-facing flag, migration, installer or OTA contract. Existing auth schema already contains initiator; this diff requires no DB schema migration. This is not permission to roll back to earlier deployment-contract-incompatible binaries; the existing fresh-database/roll-forward deployment contract still governs. Fragment covers worker cleanup and competing-rotation denial. Overlay README expressly requires refresh/review on baseline bumps and rebuild of instrumented dependencies, accurately avoiding a claim that baseline alone upgrades copied overlay.
Root-discovered patch-context defect: regenerated current00017 independently passes git apply --check against pristine worker .orig from cpp-check and audit grpc-CMakeLists-181.txt in disposable patch-check-current. This is correction verification, not independent discovery. Root real vcpkg applying and compiling is stronger downstream evidence, still separate from full image builds. git diff --check whitespace reports in nested patch blank context and preserved upstream recipe SHA line are not silently reported clean; arbitrary trim would alter patch/upstream fidelity.
Validation limits: root fresh Windows dependencies/direct runner are focused native validation; YUZU_TEST_COVERAGE variant exercises ordinary process exit under the coverage guard, not coverage instrumentation or metrics. Full Linux instrumented runs and real image/package matrix are separate. No remote writes/source edits by reviewer.

Attribution fix rereview: read complete added ports/LICENSE-vcpkg.txt and NOTICE diff. NOTICE names imported upstream recipe/CMake helpers/inherited patches at exact9eec commit, explicitly excludes Yuzu00017 and README. All five changed Dockerfiles use COPY ports/ ports/, so the parent license accompanies imported overlay sources into dependency stages. No per-port recipe/patch/runtime bytes changed by this attribution addition per root; no new build command/entrypoint. Compliance owner must certify upstream-license exactness/obligation closure; this domain review verifies packaging propagation, not a separate legal adjudication.

===== END release-deploy.txt =====

===== BEGIN happy-path.txt =====
Gate4 happy-path — normal-condition correctness
Scope: current working diff from f4c2c95aa. Complete role brief and shared prompt read; each role prompt prefix verified byte-identical and suffix read. Same reviewer sequential roles, NOT independent convergence. Full production token implementation/header, runner/lifetime test, overlay, workflow/Meson and small scripts reused from earlier direct reads. Previous security/C++/QA/architecture reports used with provenance. Large token/Python/full-doc residual reads owned by resource_ledger; no false full-file claim here. No source edits or remote writes. No new independent findings; severity derivation rows are not manufactured for reviewed nonfindings. Root execution evidence must be consolidated separately.

Input proof: raw_out = cached_raw;
Normal flow traces:
1. One active engine credential with no unresolved linkage: candidate generation outside DB lock, advisory-locked re-read, successor insert and predecessor stamp commit atomically. Post-commit cache publication remains conditional on pending pair. Return contains minted raw secret. Two linked active credentials, within epoch grace, matching durable owner, fresh RAM entry and matching RAM owner: return same cached secret. Added denial has no effect on this valid successful replay. No third credential minted on retry.
2. Server tests use one archive-owned entry point. Suite runtime acquires/installs default engine before Session, Session dies first, then grpc shutdown/default-engine cleanup, then ordinary or hard exit. New test actually drops its temporary strong ref and checks weak ref remains live, then schedules RNG and awaits result. Agent entry point retains scoped fixture semantics for fork tests.
3. Secure grpc worker drains ThreadBody; crypto guard declared after unique_ptr worker dies before ThreadState retirement. Secure/unsecure macro split prevents adding a libcrypto obligation to standalone/unsecure targets. Exact regenerated patch applies cleanly in review scratch; native dependency compilation is root-owned.
4. Sentinel matching cache leaves install intact, overlay content changes invalidate; classifier selects dependency edits; five Docker stages supply overlay before install. Earlier direct tests sentinel38/0 and classifier54/0.
5. Python fake completes its logical execute before exposing reply bytes, preserving serial-client max-inflight accounting; delayed write return intentionally widens handler-unwind gap. MCP staged subprocess clears already-closed stdin before communicate, so completion can collect output. Targeted reviewer test was blocked at sandbox socket bind and escalated retry aborted, NOT a test failure of this patch. Root reports complete unrestricted instructions198tests/1skip PASS and adapterOK in named logs; do not label that independent reviewer execution.
6. Gateway SHA256 fixture generation verified directly for all four key types as gateway-erlang.txt records. No production route/wire format change.
No claim that these source traces alone establish full end-to-end platform success. Root native normal-exit coverage-guard variant is not coverage instrumentation.

===== END happy-path.txt =====

===== BEGIN unhappy-path.txt =====
Gate4 unhappy-path — failure boundaries and state cross-product
Scope: current working diff from f4c2c95aa. Complete role brief and shared prompt read; each role prompt prefix verified byte-identical and suffix read. Same reviewer sequential roles, NOT independent convergence. Full production token implementation/header, runner/lifetime test, overlay, workflow/Meson and small scripts reused from earlier direct reads. Previous security/C++/QA/architecture reports used with provenance. Large token/Python/full-doc residual reads owned by resource_ledger; no false full-file claim here. No source edits or remote writes. No new independent findings; severity derivation rows are not manufactured for reviewed nonfindings. Root execution evidence must be consolidated separately.

Input proof: if (!try_reserve(successor->rotation_group, cached_raw, cached_user)) {
State/mutation matrix (source analysis, not executed database matrix):
States: S0 no active; S1 sole clean; S1L sole unresolved linkage; S2 linked overlap(pair); S2B malformed pair; SN>2; SR resolved/confirmed; SX expired grace; SP committed pair before RAM publication.
- rotate: S0 rejects; S1 mints atomically; S1L rejects before mint; S2 replays only fresh epoch+RAM+owner; S2B/SN reject without arbitration; SR behaves as clean sole unless caller selects stale linkage; SX rejects before durable-initiator test; SP different owner denied and same owner receives no raw secret because RAM absent. Empty durable identity does not confer authority; old RAM owner still required.
- confirm: S0 ambiguous/read-failure stays retryable; S1/SR classify exact supplied pin to terminal already-resolved/sole responses; S1L rejects; SN rejects; S2B rejects; S2/SP require exact successor pin, resolved initiator, proof of possession, then transactionally confirm successor/revoke predecessor/clear linkage. Missing RAM after restart can use durable identity for confirmation only, never secret recovery. Conflicting RAM/durable identities fail closed.
- manual revoke/delete: selected row invalidated; remaining pair member cleared under principal lock. On best-effort clear failure, survivor can retain linkage, but sweep cannot revoke it solely because partner was revoked: successor scan shape and live-used-partner EXISTS prevent that chain. New rotate guard does not change this existing degraded-state behavior.
- principal revoke: same advisory lock serializes bulk revoke with mint; returned hashes/groups drive invalidation and raw-secret eviction. No changed cache authority.
- sweep: rechecks live overlap/live used successor under lock; unused successor keeps predecessor usable; partially failed pair resolution rolls back transaction; duplicate/resolved pair becomes no-op. Newly added owner check does not bypass these guards.
Boundary transformations: lost mint response/restart loses raw grace cache but keeps durable pending identity; same owner cannot recover a secret from DB. Commit/publication reorder now rejects other owner before reserve. DB lease/SQL/commit failure preserves failure return and RAII rollback/scrub. Malformed/overfull pairs fail closed, rather than choosing a row. Operator revoke between cache publication steps is guarded by pending-pair recheck (existing contract, no broader claim of elimination of every concurrent TOCTOU).
Resource failures: REQUIRE timeout leaves callback owning promise; Guardian teardown releases watch/unwatch gates before drain. Blocked callback can delay runtime shutdown; no new bounded-shutdown guarantee is claimed. ThreadBody throw now invokes scoped crypto cleanup then worker owner; escaping underlying thread ABI still has upstream fatal semantics, not recovery. No added retry loop/fanout/network request, so added denial cannot itself amplify retries; shared classifier marks conflict terminal rather than retryable transient.
Cache missing overlay or unusable interpreters fail before deleting existing installation; partial install is not saved as coherent cache. Dependency patch context failure is surfaced by vcpkg and was root-discovered/corrected; independent current apply check passed.
Risk register for chaos (validation scenarios, not speculative defect claims): repeat actual rebuilt ASan/TSan process shutdown; inject worker throw with callback harness (cpp-safety has12cases); force commit/publication owner interleave; timeout callback then destroy fixture; missing/broken interpreter plus existing install preservation; overlay edit/add/remove; invalid CLI ordinary exit. Keep custom-engine/caller-owned-thread cleanup outside the default-suite guarantee. No new confirmed defect from this interrogation.

===== END unhappy-path.txt =====

===== BEGIN consistency-auditor.txt =====
Gate4 consistency-auditor — cross-component/time contracts
Scope: current working diff from f4c2c95aa. Complete role brief and shared prompt read; each role prompt prefix verified byte-identical and suffix read. Same reviewer sequential roles, NOT independent convergence. Full production token implementation/header, runner/lifetime test, overlay, workflow/Meson and small scripts reused from earlier direct reads. Previous security/C++/QA/architecture reports used with provenance. Large token/Python/full-doc residual reads owned by resource_ledger; no false full-file claim here. No source edits or remote writes. No new independent findings; severity derivation rows are not manufactured for reviewed nonfindings. Root execution evidence must be consolidated separately.

Input proof: error_msg = "rotation in progress by a different operator";
Contract traces:
- Durable initiator denies other operators after epoch expiry check and before RAM reservation; RAM and freshness remain sole source of raw-secret re-serve. Header/auth paragraph/changelog's denial-only/no-grace-extension claims match this order. Confirmation intentionally differs: durable identity can survive restart because presented secret proves possession; it does not mint/recover raw secret.
- Changed branch emits an existing exact error string, not new classifier vocabulary. Existing engine_store_error_class maps competing-operator and grace-elapsed errors to Conflict; REST and MCP use shared classification. Route-specific representation differs (HTTP versus JSON-RPC), not terminal/retry semantics. No classifier edits/new enum cases warrant exhaustive unrelated emitted-string redesign. Existing error tests plus token interleave regression cover contract; no new permission or audit action.
- Worker README says cleanup before retirement, not join; current RAII order enforces it. Runner owns suite default engine, agent remains scoped; no contradiction between archive wiring and documented fork requirement. Changelog normal-shutdown claim depends on rebuilt patch, not stale installed binaries.
- Overlay baseline9eec/port1/source1.81.1 align recipe/README; imported source hashes retained. All five Docker stages load same overlay. Sentinel hashes config and overlay contents; canary key includes ports/** and dependency classifier selects overlay changes. Self-hosted local caches versus cloud canary GHA cache distinctions are deliberate. No changed action SHA/dispatch input/runner label mismatch. Full ci.yml and tests/meson read in prior role; lifetime target includes both agent/server suites.
- Python inflight definition now matches adapter fixture's existing before-reply decrement: response-visible completion, not handler-return scheduling. MCP close+None preserves EOF and output collection semantics.
- Gateway EC/RSA fixture digest selection aligns contemporary crypto policy without changing Ed signature algorithm or production trust semantics; direct decoded OIDs verify comment truth.
Known prior findings retain their identities: security-guardian001 RAII floor corrected; root/docs-writer Python alias corrected; quality-engineer001 durations correction owned root; root-discovered patch-context correction passes current clean check. These are not separately rediscovered findings. Whitespace-only diff-check warnings in nested patch/upstream recipe retained explicitly rather than mislabeled clean.

Attribution fix rereview: NOTICE scopes Microsoft MIT attribution to imported upstream build files and excludes local00017/README. Parent license file exists and is copied with ports tree in all five images. No new inconsistency found; compliance retains truth/obligation decision.

===== END consistency-auditor.txt =====

===== BEGIN compliance-officer.txt =====
Compliance Review — sequential role review by resource_ledger, 2026-11-11
Input integrity echo: "The above copyright notice and this permission notice shall be included in all copies" (ports/LICENSE-vcpkg.txt:11). Full compliance prompt and actual compliance-officer brief read. Canonical Gate 6 consulted, together with Gate 1/resource inventory, routing and Gate 4 reports. This is the same reviewer as earlier C++/docs roles, not independent corroboration.

Coverage: original patch and current corrections; full modified source/doc coverage recorded precisely in source-coverage-addendum.txt. Consulted SOC 2 plan workstreams A–G at their requirements/evidence sections (not a claim to audit every historical implementation paragraph), full A5 exception ledger, relevant operator rotation/API references, NOTICE, overlay source and exact baseline vcpkg license. Root owns runtime validation; no duplicate loopback tests, remote writes or source edits performed here.

Control Impact:
- CC6.1/CC6.3: engine rotation now rejects a competing initiator from durable metadata before raw-secret RAM publication. This is a denial fence, never a substitute for same-owner RAM proof, grace deadline or epoch. Human ownership remains checked before token state work. No new grant population or privilege is created; existing access review artifacts remain applicable.
- CC7.2: no audit schema, retention policy, audit-action name or evidence-export membership changes. The guard uses existing error handling; it does not disclose secrets or introduce successful unaudited reveals. Auth architecture correctly describes the bounded improvement rather than claiming cross-replica raw-secret replay.
- CC8.1, Workstream F: worker cleanup and test-runtime ownership make ordinary exit observable to sanitizers; duration output retains per-case evidence. Overlay digest includes imported recipe/patch bytes so dependency identity tracks build inputs. Python alias fallback and strict patch application were real introduced defects, now source-corrected as recorded in other reports; historical green builds do not establish the corrected tree passes.
- Workstreams C/D: worker-local OpenSSL cleanup changes lifetime ordering, not algorithms, cipher policy, trust stores or key management. No new deployment privilege, network endpoint or persistent store. It must still pass the fresh supported-platform campaign.
- Workstream E: no collection, data classification, retention or deletion changes. Test PG fixtures are disposable test state, not product data migrations.

Finding compliance-officer-001 — imported vcpkg recipe omitted its required notice; CLOSED by current correction.
Location: original ports/grpc imported recipe/helpers/inherited patches; current remedy ports/LICENSE-vcpkg.txt:1 and NOTICE:82–87.
Classification: third-party attribution obligation, introduced by this overlay import; substantive source-license compliance, not prose wording.
TRIGGER: distribute the newly copied complete upstream recipe/helper/patch set without its copyright and permission notice.
IMPACT: I9 (no demonstrated operational impact). The actual defect is the omitted license condition. No security-control failure, data damage, wrong runtime result or outage is inferred from that omission.
EXPOSURE: E3, ordinary maintainer/source recipient exercising authorized distribution; no attacker privilege or non-default condition is required. No raise or cap applies.
EPISTEMIC STATUS: verified. Exact baseline 9eec002df1cd109f8f104cd966a763daf9751489 LICENSE.txt read from local vcpkg checkout; original imported tree lacked the MIT notice. README baseline attribution and gRPC's Apache license installation do not contain the separate vcpkg MIT permission text. After root's correction a byte comparison against git-show of that exact baseline returned True.
Derived band: INFO; severity_native: LOW (INFO absent in brief vocabulary). NON-BLOCKING by operational derivation. The schema does not provide a legal-impact category; do not manufacture one or infer legal penalties.
Policy floor: none of the closed floor sources establishes this license clause as a governance floor. Actual upstream retention requirement still warrants correction.
Resolution: CLOSED. Full exact copyright/permission/disclaimer is retained at ports/LICENSE-vcpkg.txt. NOTICE scopes it to the imported recipe/helpers/inherited patches and excludes local 00017 and README. Parent placement is valid for the copy being distributed; Docker COPY ports includes the notice (also checked by release/build reviewer). No per-port recipe bytes changed for this attribution fix. No new rebuild is asserted or required merely to prove byte retention.

Evidence Impact: preserve original defect IDs and correction provenance, fresh root campaign logs, per-case timing and exact overlay digest. Root reports instructions 198 tests/1 skip PASS and MCP adapter OK; these are root-attributed results, not executions by this reviewer. Homebrew Clang 23 callback results and separate Apple Clang 21 12/12 callback checks are distinct; neither proves a whole macOS dependency build. Full current Linux/Windows/sanitizer validation remains pending in this role report.
Policy Impact: no new product policy required. Attribution correction fulfills the identified import obligation. The overdue A5 exception is separately reported by enterprise-readiness, not silently renewed here.
Risk Impact: no newly demonstrated product risk after the source fixes; evidence completeness remains an explicit campaign gate. No compliance certification or operating-effectiveness claim is made.
Verdict: no open introduced compliance finding after license correction. Source-level Gate 8 rereview of NOTICE/license closes compliance-officer-001. Overall governance PASS is withheld pending root's fresh validation and final ledger adjudication.

===== END compliance-officer.txt =====

===== BEGIN sre.txt =====
Gate6 sre — operational readiness source review
Scope current working diff from f4c2c95aa, plus fixes. No new independently discovered finding. PASS for inspected source-domain reasoning; runtime/platform evidence remains root-owned and pending consolidation, not an unconditional governance PASS.
Complete sre prompt (shared prefix verified identical plus role suffix read) and actual sre brief read. Gate4 happy/unhappy/consistency reports fully available as same-reviewer context; other Gate2/3 reports read with provenance. Full runner, overlay, store implementation/header, five Dockerfiles, workflow/Meson, sentinel/sweep and small tests reused from prior direct reads. Workstream D of enterprise-readiness doc read; clock-guarded-retention seven-part rule/single-writer and ApiTokenStore disposition read (not claiming complete large per-store register). Current sweep executable-discovery region rechecked. No new metrics/audit/lifecycle-event schema or feature data schema to trigger extra metric/schema docs.
Input proof: ~ScopedOpenSslThreadState() { OPENSSL_thread_stop(); }

Observability: token competing-operator refusal follows existing error/audit path and terminal Conflict taxonomy; no retry loop or new error vocabulary. No newly introduced service, metric or health-check dependency needs new alerting. Runtime regression plus real sanitizer process-exit logs are the relevant teardown evidence; assertion-only execution cannot certify detached worker retirement. Sentinel fails visibly before install removal if no interpreter works; existing sweep failure accumulator still makes degraded sweeps red rather than hiding them.
Deployment: overlay refresh and rebuild obligations are explicit in README/build docs, and all dependency image stages carry the overlay before install. No service identity, port exposure, resource-limit or entrypoint hardening change. Exact regenerated patch applies in scratch; root real vcpkg build is necessary downstream proof. No new native config. Windows fallback probes execution rather than accepting a misleading AppExecutionAlias. Diff-check nested patch/upstream whitespace warnings remain disclosed.
Recovery: no changed store schema/backup target. Durable rotation identity already persists and survives restart for confirmation with proof-of-possession; raw-secret cache remains intentionally ephemeral, so restart cannot recover raw token by rotate. Unused successor guard preserves previous usable credential. Existing deployment hard-cutover constraints remain; no blanket mixed-version/rollback claim. RTO/RPO are not newly measured by this patch, and no availability SLO guarantee follows from source inspection.
Capacity: suite default engine is test-process ownership, not a new fleet production pool. Worker scoped cleanup adds no unbounded cache, queue, thread or retry. Guard runs before retirement count publication and leaves no extra strong reference. Pending/blocked user callback can still delay draining; README explicitly confines guarantee to suite default engine and calls out caller-owned engines/threads. No new forced timeout promised. Guardian teardown releases parked fake watch/unwatch before drain; failure timeout retains callback promise ownership. Existing principal-scoped transaction lock remains, with no new external work inside it.
Retention: sweep-test-databases changed only psql discovery (including D:/ci/pgbin layout). Name guards, server-clock cutoff, epoch/orphan thresholds, no-force orphan handling, per-instance error status and timeout paths unchanged. This review does not certify all historical retention passes as seven-part compliant or demand an unrelated redesign for path discovery.
Evidence boundaries: reviewer sentinel38/0, classifier54/0, gateway4key digest/OID check, patch apply-check. Root reports AppleClang callback12/12 and ongoing actual Windows/Linux builds; reports are attributed and not yet replaced with final logs here. Windows YUZU_TEST_COVERAGE exercises the normal-exit coverage-guard branch, NOT instrumentation or coverage metrics. Root unrestricted Python instructions198tests1skip PASS / adapterOK are separate evidence; reviewer loopback attempt failed sandbox bind and escalated retry was aborted. No further runtime/escalation tests performed.

===== END sre.txt =====

===== BEGIN enterprise-readiness.txt =====
Enterprise Readiness Review — sequential role review by resource_ledger, 2026-11-11
Input integrity echo: "The grace window is held in that replica's memory" (docs/user-manual/engine-principals.md:188). Full enterprise prompt and actual enterprise-readiness brief read, canonical Gate 6 and Gate 4 reports consulted. Same reviewer as prior roles; no independence claim.

Coverage: full changed source/doc reads as recorded in source-coverage-addendum.txt; CI 801–2000 read by routing with explicit attribution, remainder personally. Workstream G and framework A–F requirements consulted, A5 contract and every exception row read, human-token REST reference 1215–1276, engine operator rotation guide 158–228 and server-admin self-rotation note 845–873 checked. This is targeted operator-doc coverage, not a full user-manual audit. Current changelog fragments, NOTICE and exact license correction reviewed. Root owns runtime tests; no source changes or runtime test executions in this role.

Documentation Impact: rotation's deny-only publication guard agrees with the documented same-replica RAM grace window and competing-initiator denial. It introduces no endpoint shape, permission, new operator flag, migration or recovery workflow. Existing operator instructions already describe lost-secret recovery and replica/restart limitations. Architecture and security changelog describe the correction. Full build/CI docs match the overlay digest and corrected working-Python selection. No missing required documentation under the six enumerated cases identified. The test-runtime lifetime correction does not create a customer installation procedure.
Assurance Impact: the change improves a credential-rotation interleaving boundary and shutdown evidence; it does not establish cross-replica secret recovery, complete native-thread joining, certified crypto, or SOC 2 operating effectiveness. Customer statements must retain those existing limits. NOTICE now accurately scopes the imported MIT source and includes its exact notice; this closes the attribution concern without claiming local patch authorship belongs to upstream.
Deployment Impact: same platform topology, ports, service users and upgrade model. Source builds now include a pinned gRPC overlay and content-sensitive cache identity; this is documented. No destructive data migration or operator rollback command introduced. Fresh supported-platform results are still required before claiming release readiness.
Integration Impact: no changed IdP, SIEM, REST or MCP tool contract. Python regression fixtures do not add a production integration. A5 review remains mandatory even though no MCP tool is materially changed.

Finding enterprise-readiness-001 — A5 exception #2990 revisit is overdue; OPEN, PRE-EXISTING.
Location: docs/agentic-first-principle.md:123 (the row naming execute_instruction streamed-final FALLBACK; identify by #2990 if line numbering moves).
TRIGGER: Gate 6 on 2026-11-11 encounters an open exception whose revisit-by date is 2026-10-31, with no recorded closure or renewal.
IMPACT: I9, no demonstrated additional operational impact from the stale review date itself. The row describes a pre-existing typed-envelope gap; this finding does not claim to have newly tested or re-derived the runtime fault behavior, and does not equate an overdue date to a security bypass.
EXPOSURE: E3, ordinary governance maintainer/customer-assurance reviewer relying on the exception record. No raise or cap.
EPISTEMIC STATUS: verified from the literal ledger date and current review date. The record remains open; four other entries are marked closed and #5761 has future revisit 2027-01-12. No undated open entry found.
Derived band: INFO; native severity LOW. NON-BLOCKING by derived band.
Policy-floor provenance: none. Canonical Gate 6 and the role brief explicitly require flagging stale/undated exceptions, but neither creates a new member of the closed invariant-floor list. No self-granted waiver or renewal.
Classification/rationale: existing governance/assurance debt, unchanged by this diff and not newly exposed by its runtime behavior. Reported because every Gate 6 must review the ledger, rather than suppressed as out-of-scope wording.
Requested disposition: designated owner records actual revisit outcome for #2990 (closure evidence or justified new dated decision). Do not merely move the date to make the ledger look current. Root may record a non-blocking existing-debt disposition; this reviewer cannot adjudicate an exception.

Gate 8 attribution rereview: exact baseline MIT notice plus scoped NOTICE text resolves compliance-officer-001 for the enterprise assurance domain. Source fixes/durations/working-Python claims match current files. This does not close the fresh full-build/runtime evidence campaign.
Verdict: no open introduced enterprise-readiness finding; one pre-existing LOW/INFO stale-exception finding requiring explicit disposition. Overall governance/runtime PASS is not asserted. Next-role coverage: root consolidates actual fresh validation and dispositions; routing may synthesize these reports verbatim with maximum derived severity, without promoting sequential reviews to independent evidence.

Root-supplied read-only tracking evidence: GitHub plugin confirms #2990 OPEN, updated 2026-11-09, needs-triage only (no roadmap label). This supports an existing active tracked issue, not exception renewal. Candidate local disposition is linked-to-#2990; root owns terminal ledger disposition. KEEPLOCAL means no GitHub comment or other mutation by this reviewer. Underlying runtime severity remains outside this stale-metadata finding.

===== END enterprise-readiness.txt =====

===== BEGIN source-coverage-addendum.txt =====
Incremental full-source coverage addendum — 2026-11-11
Reviewer: resource_ledger, sequential QA/C++/docs roles, not independent opinions.

COMPLETED full reads:
- tests/unit/server/test_api_token_store.cpp: all 6480 lines, bounded contiguous chunks (1512–1610 read in prior role and all remaining intervals now read). Includes migrations, auth CRUD/IDOR, cache invalidation, semaphore races, engine and human rotations, group concurrency, clock guard, SQL fault/COMMIT failures, proof-of-possession, restart and stale-linkage cases.
- tests/test_instructions_runner_hardening.py: all 2741 lines, chunks 1–400,401–800,801–1200,1201–1600,1601–2000,2001–2400,2401–2741. Initial oversized/truncated read was replaced by these bounded full reads.
- tests/test_mcp_http_adapter_behaviour.py: all 583 lines, chunks 1–280 and281–583.
- docs/build-guide.md: all 162 lines.
Source echoes: `p.stdin = None`; `before_send=finish_execute`; `CHECK(confirm.error() == refused.error());`.

No introduced security/QA defect found from these completed full-file reads beyond existing recorded IDs. New FakeYuzu completion callback decrements once before response publication, including failure via finally; the delayed-return test widens the old overcount window. This observes serial client requests without counting a finished response's handler unwind as in-flight work. New adapter assignment removes only communicate's attempt to flush already-closed stdin; EOF already sent, stdout/stderr still drained and timeout still kills/reaps the child.
Token new publication hook is synchronous and uses the real committed state; different operator denial, same operator uncached rejection, replay, epoch precedence and two-row state all asserted. Full-file context contains no changed ownership/auth path that defeats those assertions. Existing comments retain historical drift (e.g. old declarations saying human rotation is unimplemented); those predate this diff and are not proof of current absence. Existing stochastic concurrency tests are supplemental, not the sole closure evidence for the new deterministic case. PostgreSQL sabotage stays within isolated fixture databases. No changed production parser or authority surface exists in the Python edits.
Build guide's changed overlay/runner ownership paragraph matches source: secure workers clean their own OpenSSL state before retirement; server suite pins/drains default engine; agent runner remains unpinned for fork tests. Baseline bump cannot replace an overlay and content fingerprint invalidation is implemented.

QA closure: quality-engineer-001 FIXED, current tests/meson.build:80–82 includes args: ['--durations=yes']; verified by direct source read. No runtime timings inferred.

Patch evidence correction / root-build-001:
Root reported actual Windows vcpkg git apply rejecting malformed blank-line context introduced during RAII rewrite, caused_by resource-ledger-001. Introduced supported-platform build failure is a BLOCKING POLICY FLOOR independent of numeric severity. My earlier general patch-application claim was inadequate: patch utility acceptance/fuzz is not exact git apply acceptance. Do not cite that earlier check as vcpkg closure.
Root regenerated 00017 against exact grpc1.81.1 audit source. Independently ran git apply --check --verbose in fresh exact-gitapply-check directory containing grpc_thread_pool_181.cc and grpc-CMakeLists-181.txt; exit0 and both hunks checked without offsets/fuzz. Output exact-gitapply-check/result.txt. Root additionally reports successful real vcpkg application on Windows and Linux: source defect CLOSED, full build/runtime campaign still pending. No code semantic change to RAII destruction order was required.
Callback compiler attribution remains Homebrew Clang23.1.4 for my12variant checks. Root separately reports AppleClang21.0.0 /usr/bin/clang++12/12 in cpp-check/apple-validation.txt; neither proves a whole macOS dependency build.

Runtime ownership: root owns runtime validation. My attempted focused Python test failed before execution at loopback bind EPERM; ensuing approval call was aborted after929s, so NO local successful test claim. Root reports full instructions198tests/1skip PASS45.409s and MCPadapterOK; use root log provenance. No further runtime approvals requested by this reviewer.

REMAINING full-read coverage: docs/auth-architecture.md6019 lines and docs/ci-architecture.md3513 lines. Prior changed-section reviews remain valid, but do not yet represent exhaustive reads. This addendum supersedes the earlier residual token/Python/build-guide coverage limitation only.

Auth full-file closure: docs/auth-architecture.md all 6019 lines read, including all dense service-scope paragraphs re-read after output truncation. New rotation publication paragraph matches actual engine denial-only durable check, same-caller unexpired RAM re-serve requirement, epoch precedence, human owner precheck. No newly introduced contradiction found. This is review of changed contract in full-document context, not revalidation of every historical claim against untouched implementations. CI full-file read remains pending.

CI full-file closure: docs/ci-architecture.md lines 1–3513 are now fully read collectively. This reviewer read 1–800 and 2001–3513; routing explicitly reports complete literal 801–2000 reads in six untruncated 200-line chunks. No newly introduced contradiction found. Overlay hashing/fallback claims match the corrected implementation; durations preserve evidence summaries; concurrency widths and healthcheck contracts are unchanged. This supersedes the earlier pending CI note. Full source/doc coverage requested by root is complete; it is not empirical revalidation of every untouched historical claim. Runtime campaign status remains separate and pending root evidence.

===== END source-coverage-addendum.txt =====

===== BEGIN gate8-routing.txt =====
Gate8 round3 fix routing — 2026-11-11
Read all FOUR current tables fully, row by row in this pass: routed-concerns.md lines1-57, access-control1-24, security-posture1-27, software-estate1-24. No truncation in these rereads. Canonical Gate3 matrix and Gate8 lines1436-1483 reread. This is actual fix-domain rerouting, not reuse of original roster.
Fix scope provided by orchestrator and inspected current files: ports/grpc/00017 (new unique_ptr + noncopyable scoped OpenSSL guard, then exact-source patch-context correction); scripts/ci/vcpkg-triplet-sentinel.sh and test-vcpkg-sentinel.sh interpreter fallback; docs/ci-architecture.md matching interpreter instructions; tests/meson.build durations. Current durations line confirmed args: ['--durations=yes']. No claim that full original diff is the fix diff.

Required reruns:
Gate2 security-guardian ALWAYS; docs-writer for CI doc and in-code prose.
Gate3 cpp-expert + cpp-safety: C++ embedded in dependency patch still C++, ownership/cleanup order/failure unwind. quality-engineer: shell regression and Meson test registration. build-ci: patch application, cache sentinel identity and installed-prefix preservation, Meson. cross-platform: native Windows interpreter fallback plus patched C++ across Windows/macOS/Linux. release-deploy: dependency overlay is consumed by all five production/build image recipes; no Dockerfile fix hunk, but changed dependency application affects release domain. This last selection is conservative Gate8 DOMAIN routing, not a claim of literal new Dockerfile edit.
Gate4 happy-path/unhappy-path: changed cleanup/error-path/interpreter logic; consistency-auditor: doc/script and build/patch/platform contract parity.
Gate5 re-evaluate chaos disposition and rerun relevant worker-unwind / failed-interpreter preservation cases against corrected artifact; no automatic exemption because original scenarios passed on older patch.
Gate6 sre: thread lifecycle and shutdown. compliance-officer: changed closure evidence/failure-mode proof; enterprise-readiness: corrected Windows readiness/CI instructions and deliverability. Retain normal-exit coverage-guard versus actual instrumentation distinction.
Gate1 update Resource Ledger entries4-5 from raw ownership/manual call to scoped owners; exact patch identity/provenance in validation evidence. Gate7 consolidate corrected statuses and any remaining validation. Gate8 only closes when required rerun conclusions and evidence are actually recorded.

No NEW compulsory architect/authdb/gateway-erlang/plugin-developer/dsl/performance review from this fix: no first-party server path/header/interface/schema, gateway/Erlang, plugin/YAML, scope/CEL, SQL/hot-authz change. Original required domain reviews remain required and are not canceled. Architect can conservatively recheck dependency ownership boundary, but direct matrix triggers not newly matched. Auth/crypto row below selects security due OpenSSL lifetime; no token/auth production behavior changed in fix. No new API surface triggers ADR1005.

Row-by-row disposition (line numbers identify complete reread rows; snippets are labels only):
routed-concerns.md:16 Executions-history ladder — `command_id → execution_id` correlation, the SSE `ExecutionEventBus`, and the dura — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:17 Compliance evaluation pipeline — `PolicyEvaluator` background thread (10s tick, 15s grace, ≥60s floor, 3600s d — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:18 `/auto` Pre-flight readiness — operator go/no-go checks across a device cohort before a fleet change. Born-on- — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:19 `/auto` Deploy (the ACT stage after pre-flight ASSESS) — stage + execute an installer on a pre-flight run's go — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:20 **Artifact signature verification — one detached-CMS chokepoint (#416/#3807).** `detached_signature.cpp` is th — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:21 C++23 conventions, naming, headers, plugin ABI boundary — MATCH: cpp-expert; embedded patch C++ source; cpp-conventions.
routed-concerns.md:22 C++ resource ownership and lifetime — fd/HANDLE/SOCKET/`FILE*`/SQLite/OpenSSL/BCrypt/C-string/thread/callback/ — MATCH: cpp-safety + security ownership proof; cpp-conventions (no ObjC addition).
routed-concerns.md:23 macOS workflow + Darwin pitfalls table — MATCH: cross-platform; shared patched worker affects Darwin; darwin-compat.
routed-concerns.md:24 Prometheus metrics, label set, audit envelope, event format, and the SHIPPED ALERT RULES — an alert-rule-only  — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:25 Response data types, audit envelope, inventory data for analytics — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:26 User manual / YAML defs / REST API / Substrate primitive registration — MATCH: docs-writer always and CI doc/in-code prose changed.
routed-concerns.md:27 Guardian / Guaranteed State — real-time agent-side policy enforcement (guard categories, YAML DSL, `__guard__` — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:28 Spark detection layer (ADR-0021) — `SparkEngine` is the agent's sole detection primitive (watchers multiplexed — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:29 Echo dashboard — frames, URLs, permissions. New source: CORE pattern (`docs/echo-implementer.md` §8), NOT the  — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:30 Device quarantine / containment — `QuarantineStore` (Postgres, ADR-0047) + the #881 dispatch gate (`make_conta — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:31 Scope walking — composable scope from previous query results (product differentiator). Result-set primitive, ` — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:32 System architecture — cross-cutting design reference (Operator/Server/Agent/Gateway, REST/MCP/dashboard surfac — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:33 Tag/scope DSL operator reference — `tag:X`, `props.X`, `ostype`, `hostname`, `arch`, `agent_version` resolutio — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:34 Agentic-first invariants A1–A5 — applies to every new MCP tool, REST route, dashboard fragment, or error site  — STANDING MATCH: consistency every PR; no new tool/route/error contract.
routed-concerns.md:35 Enterprise-platform parity matrix — competitor capability comparison and gap analysis (complements `docs/capab — STANDING MATCH: enterprise-readiness Gate6; no capability-map edit.
routed-concerns.md:36 CI cache patterns — split `actions/cache/restore` + paired `actions/cache/save` for GHA-hosted; local `runner. — MATCH: build-ci; sentinel installed-prefix coherence; ci-cache skill.
routed-concerns.md:37 Fleet visualization (3D) — REST surface, page-shell, renderer, and process-layer invariants for the 11-PR `fea — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:38 Network quality dashboard (`/network`) — MEASUREMENT-FIRST device/local-link health lens (interval retransmit  — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:39 Device pages (`/devices` + `/device?id=`) — SHARED device surface: Device info / DEX / Guardian lens tabs + "G — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:40 OS capability matrix — per-capability × per-OS snapshot of what the agent collects/enforces, each row citing i — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:41 Agent daily-sync framework + installed-software inventory (ADR-0016) — agent pushes per-source state daily ove — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:42 SQLite `sqlite3_changes()` after `step()` on a shared FULLMUTEX connection is a data race + correctness bug (r — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:43 **Clock-guarded retention** — any bulk delete whose cutoff comes from a wall clock (`now - window`) must be gu — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:44 **Server storage substrate — PostgreSQL**; agent stays SQLite (`agent.db` + federated edge warehouse). Server  — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:45 `common/include/` shared-header firewall between `server/core` and `agents/` (#2549) — pure decision code only — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:46 **Durable agent command idempotency (HA WS-0, ADR-2002)** — `CommandDedupStore` (`command_dedup.db`, agent SQL — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:47 **Agent OTA pull bounds (#913/#911)** — the per-peer admission gate on `DownloadUpdate` and its transfer watch — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:48 **Confined filesystem deletion — `confined_fs` (agent-core)** — the handle-relative primitive behind operator- — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:49 Unit-test conventions — shared helpers and fixtures: `unique_temp_path`/`TempDbFile`/`TempDir` (`yuzu_test_` u — NO literal tests/unit fix; quality-engineer nonetheless REQUIRED by tests/Meson matrix and fixes; unit-test-conventions applies registration duration.
routed-concerns.md:50 **Echo cursor sources** — sources whose durable state is an `echo_cursor` row, not a snapshot-diff baseline. * — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:51 **power_health `set_power_plan`** — the plugin surface's only destructive power action (`PowerManagement` secu — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:52 **`app_usage` agent plugin + ADR-0016 daily-sync source — machine-scope usage evidence.** Reads Echo's `usage` — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:53 **`execution_artifacts` plugin — Windows execution-evidence reads (ShimCache/AmCache/Prefetch).** Three read-o — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:54 app-usage server read surface — `GET /api/v1/forensics/agents/{id}/app-usage` + MCP `get_agent_app_usage`: `Fo — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:55 `windows_optional_features` plugin — Windows-only DISM read (`Inventory`, read-only, no enable/disable), via a — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:56 `peripherals` plugin — read-only USB/PCI/Thunderbolt inventory (`Inventory` securable, no mutation, no subproc — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:57 `printing` plugin — read-only queue/job inventory (`Inventory`; `jobs.document` = user content) plus the ONE m — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:5 Authentication, RBAC, headers, tokens, self-target principal-destruction guard (#397/#403). Every new list/fan — MATCH: security-guardian on crypto cleanup lifetime; not a new auth/RBAC/token behavior change.
routed-concerns-access-control.md:6 **Dispatch-caller approval provenance — `ExecuteGate` at the shared dispatch chokepoint (#1398).** Every dispa — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:7 **Service-scoped API token confinement — durable default-deny (guardian-confinement-2298 PR 3, "the flip")** — — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:8 PKI / internal CA — `ca_store` (`CaStore`, Postgres schema, ADR-0053; migrated off SQLite `ca.db`) holds cert  — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:9 AuthDB invariants — Postgres schema `auth` (ADR-0006; SQLite `auth.db` retired), fail-closed construction, `Se — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:10 **SCIM ↔ OIDC/SAML identity-link revoke chokepoint (ADR-2001, CC6.8)** — deprovisioning must sever every linke — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:11 Periodic Access Reviews (SOC 2 CC6.2): fleet-wide grant export + attestation-campaign lifecycle across all thr — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:12 Enterprise A&A roadmap — RBAC, OIDC, SAML, SCIM, MFA, AD/Entra, API tokens, session lifecycle, audit — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:13 MCP server architecture, tier-before-RBAC ordering, kill switches, audit pattern; Streamable HTTP transport (s — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:14 Per-device dispatch visibility (#1788) + the registry-independent authz model (ADR-0033 §2). CATASTROPHIC: (1) — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:15 **Dispatch targeting — omitted means the fleet, EXCEPT for a `Destructive`-classified pair.** **CATASTROPHIC-I — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:16 **Dispatch zero-reach cause discrimination: ONE shared classifier, FIVE hand-copied legacy cascades that diffe — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:17 Agent privilege model — dedicated `_yuzu` / `yuzu` / `NT SERVICE\YuzuAgent` account, narrow sudo NOPASSWD + LS — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:18 **Headless platform, process decomposition & access-control spine (ADR-1005 + ADR-0031/0032/0033)** — ADR-1005 — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:19 **Authorization-topology floor (#2376)** — `authz_topology_floor.hpp`'s `kTopologyFloor` is the SINGLE chokepo — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:20 **Pre-auth request-body cap (#2407)** - `body_cap_policy.hpp`'s `kBodyCapTable` is the SINGLE chokepoint; EXTE — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:21 **MFA step-up chokepoint**: `kStepUpPolicy` (`step_up_policy.hpp`) is the SINGLE table of mutating routes need — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:22 **Fenced leader election — `LeaderElector` + the singleton-loop gate (WS-3, ADR-2002 §3/§6/§10).** A COORDINAT — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:23 **Split merge-gate — ADR-0032 sequencing interlock (WS-0).** No engine-path code (admits a run / mints a grant — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:24 **A2/A1 RBAC administration surface — `is_rbac_administrator()` (`rbac_admin_predicate.hpp`) + the closed assi — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:17 `app_control` plugin — read-only Windows WDAC/AppLocker posture (`Security`, ExecuteGate::None): registry read — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:18 `firmware_posture` plugin — read-only firmware/BIOS vendor, version, update-pending posture (`Security`, Execu — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:19 `platform_security` plugin — read-only Secure Boot / code-signing posture (`Security:Read`, both actions `Read — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:20 `local_security_policy` plugin — read-only password/lockout/audit policy posture and sudoers content (`Securit — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:21 `system_hardening` plugin — read-only exploit-mitigation/kernel-hardening posture (`Security`, ExecuteGate::No — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:22 **Gateway-upstream peer authorization.** `GatewayPeerGuardedService` is the SOLE production registration of th — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:23 **Gateway origin trust — what address the gateway reports for an agent (`gateway_observed_peer`, audit `source — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:24 **Gateway mgmt-plane peer authorization (#1422, #6016).** `yuzu_gw_authz:check_mgmt_peer/1`, the :50063 `auth_ — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:25 `registry` writes (`set_value`, `delete_value`, `delete_key`). **CATASTROPHIC-IF-VIOLATED:** (1) Mutate only a — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:26 `registry` writes (`set_value`, `delete_value`, `delete_key`, `set_user_value`, `delete_user_value`, `apply`). — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:27 **Same-site gate for cookie-session writes: ONE pre-routing chokepoint.** `apply_same_site_write_gate` (`same_ — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-software-estate.md:17 **`browser_inventory` plugin (Forensics, default-off, per-user browser data)** — reads per-user Chromium-famil — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-software-estate.md:18 **`privacy_permissions` plugin (Forensics, default-off, per-app sensitive-permission grants — camera/microphon — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-software-estate.md:19 **`runtimes` plugin — read-only installed .NET/JVM/Python runtime inventory (`Inventory`, no subprocess; machi — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-software-estate.md:20 **`middleware` plugin: read-only installed-middleware inventory (`Inventory`, table-driven; IBM MQ on Linux as — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-software-estate.md:21 **`remote_access_audit` plugin (Forensics, default-off, per-account SSH key data)** — reads `/etc/ssh/sshd_con — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-software-estate.md:22 **Forensics tier on stored-response reads (#4990)**: rows written by plugins on the `Forensics` securable are  — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-software-estate.md:23 **`certificate_inventory` daily-sync source and `CertificateInventoryStore` (schema `certificate_inventory_sto — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-software-estate.md:24 **Software title normalisation layer** — `SoftwareTitleDimension` (the ADR-0012 §3 cross-store owner), the hou — NO MATCH: no named surface or semantic contract changed in fix.

Gate8 additional fix scope: NOTICE and ports/LICENSE-vcpkg.txt. Assessed against the full four-table reread above: User-manual/docs standing row MATCH (docs-writer); CI-cache row indirect build-ci contract because entire ports tree is copied/hashed; enterprise-parity standing Gate6 still applies. No access-control/security-posture/software-estate path or semantic row newly matched. Gate2 security always plus docs; Gate3 build-ci/release-deploy on dependency source packaging and QA attribution checks as relevant; Gate4 consistency on attribution-to-import boundary; Gate6 compliance MUST rerun (license/evidence) and enterprise docs/readiness. No new C++/gateway/runtime/retention surface from these two files; existing mandatory reruns remain. This is an additional fix-domain assessment, not a reason to repeat unrelated binary tests.

===== END gate8-routing.txt =====

===== BEGIN gate8-source-closure.txt =====
Gate8 source closure, not final runtime closure — 2026-11-11
Scope all fixes: RAII worker ownership, exact-source patch context, executable Python fallback+regression+CI docs, Meson duration option, MIT license+NOTICE.
Rerouting allfour full tables recorded gate8-routing.txt. Source verdict evidence is in security/docs final addenda, cpp-expert/cpp-safety/QA source-coverage-addendum, build-ci/cross-platform/release addenda, Gate4three reports, SRE, compliance and enterprise. No new introduced source defect remains identified. Root owns ensuring all required Gate8 attestations refer to final artifact hashes and recording terminal ledger dispositions; this file does not rewrite pending initial ledger rows.
Original findings preserved: resource-ledger001 and root-build001 source-corrected but empirical campaign still required; docs-writer001 fixed by current source and38/0 regression; quality-engineer001 fixed source flag; compliance-officer001 closed exact notice; enterprise-readiness001 pre-existing INFO revisit debt pending explicit root disposition. No waiver self-adjudicated. Gate5 conditional skip recorded separately. Final all-platform/runtime decision withheld until root incorporates fresh campaign results, not inferred from source coverage or narrow callback checks.

===== END gate8-source-closure.txt =====

===== BEGIN gate5-disposition.txt =====
Gate5 SKIPPED by root orchestrator: unhappy-path and consistency-auditor Gate4 reports contain no new findings. Their scenario suggestions are validation coverage guidance, not new speculative defects. Existing scenarios are covered by root repetitions/mock ordering checks and final artifact validation. This follows workflow-orchestrator conditional skip rule; no chaos PASS claim. Gate8 rerouting re-evaluated disposition and retains this skip while Gate4 remains finding-free.

===== END gate5-disposition.txt =====

FINAL METADATA / WINDOWS EVIDENCE UPDATE — 2026-11-11
Supersedes earlier six-finding count and open-disposition summary, not the historical report bytes. Final resource_ledger audit addendum verifies canonical field-wise live view: NINE findings = EIGHT fixed + enterprise-readiness001 linked-to-#2990. The three additional metadata findings below remain distinct PROVISIONAL groups (same ledger file but different defects). All original policy floors and caused_by links remain; native labels/derived severity are not re-adjudicated. independently1 per discovery chain, later confirmations echoes.

| Additional provisional ID | Defect | Derived band / native | Floor | Verified disposition |
|---|---|---|---|---|
| ledger-audit-001 | Missing precise fix source-address citations | INFO (I9/E3), native null, mapped NICE | None | FIXED: appended current patch35/45 and16/29 citations |
| ledger-audit-002 | QA prose could imply independent reporter despite same sequential reviewer | INFO (I9/E3), native null, mapped NICE | None | FIXED: source-rereview wording and final ledger18 citation |
| ledger-audit-003 | Root-observed build milestones lacked retained evidence addresses | INFO (I9/E3), native null, mapped NICE | None | FIXED: observer/scope/log hashes in milestone manifest; auditor verified all3 |

The original five introduced findings are fixed; overdue A5 metadata is linked-to-#2990, not silently renewed and not proof its underlying runtime gap is fixed. Original appendices retain earlier pending statements as history; final audit appendixed below supplies exact closure evidence/provenance.

Fresh Windows ROOT-EXECUTED focused validation complete: inspected build-windows-results.json and build-windows-debug-results.json, each normal10exit0 plus normal-exit coverage-guard10exit0, each mode invalidCLI exit1. Total40passing runner launches +4expected CLI failures, across native MSVC release/debug. release-proof.json records exact_match_to_current_patch=true, worker SHA2561634089138200ff4103c7a472397e67fca798328c19e02e24b477812567fd421, grpc1.81.1port1/OpenSSL3.6.5port2/Catch2 3.16.0 installed. Root owns execution/source artifact provenance; this reviewer inspected retained results, did not rerun. This is fresh dependency + shared runner validation, NOT fullWindowsproject suite, coverage instrumentation, or a wholemacOSdependency build. Root reports remote lock RELEASED.
LinuxASan+UBSan dependency build is still pending (root milestone1600/1918); full application/sanitizer tests remain pending. No overall governance/runtimePASS. Metadata/evidence source closure requires no reread/rebuild of unchanged source; source fixes and collective coverage stay closed, runtime campaign stays separate.

===== BEGIN final-ledger-source-audit.txt FINAL VERBATIM =====
Final ledger/source consistency audit — 2026-11-11
Read-only audit by resource_ledger; no runtime tests, network operations, source edits, waiver adjudication or severity changes.

Inputs: live governance.d/20261110-nightly-integration.724d95.jsonl; canonical governance merge/disposition/fix-evidence rules; role reports and source-coverage-addendum; retained original/round2/round3/round4 snapshots; current 00017 source; issue-2990-readonly.json. Distinctive source echo: "Quiesce observes that retirement, not detached pthread/FLS teardown."

Counting rule: findings are FIELD-WISE last-write-wins by recorded_at, ties pass_ordinal; list fields replace rather than union; the five attestation fields remain row-scoped. Reading only the last row would incorrectly discard original floors. Applying the canonical rule yields SIX live findings: resource-ledger-001, docs-writer-001, quality-engineer-001, root-build-001, compliance-officer-001 FIXED; enterprise-readiness-001 linked-to-#2990. All original floors remain in the live view. No unresolved row survives; no severity/floor de-escalation, refutation, self-waiver or fabricated exception appears. independent_reporters remains 1 throughout, consistent with sequential role reviews.

Source/fact consistency:
- Resource floor correction uses unique_ptr at patch:35 and ScopedOpenSslThreadState at :41–46; reverse destruction releases crypto state before worker retirement. No impossibility exception needed or granted. Fix does not prove native OS-thread join or cover arbitrary custom engines.
- Python fallback facts, I5/I8 + E4/E6 and independent policy floor match docs-writer original/follow-up and 38-check evidence. The floor is not lost merely because operational band maps NICE.
- Timing omission I8/E6, no floor, matches QA and explicit source closure at tests/meson.build:80–82. No timings are inferred from source.
- Malformed patch-context failure retains caused_by resource-ledger-001. Exact git-apply evidence supersedes inadequate permissive patch/fuzz evidence; it is not rewritten as if the first check had been sufficient.
- License original omission, exact-byte remedy and scoped attribution match compliance report. I9/E3 is retained without inventing a new legal-severity category or invariant floor.
- Stale A5 date is pre-existing metadata debt, not a newly severity-rated runtime gap. Linked row repeats impact and severity_mapped as required. Local issue evidence confirms #2990 open, updated 2026-11-09, needs-triage and no roadmap label. This is not a park or exception renewal. KEEPLOCAL explicitly overrides external comment; no unauthorized GitHub mutation was performed. Nothing here certifies the underlying fallback behavior fixed.

Snapshot verification: local SHA-256 reads exactly match ledger references:
patch.diff c5d2142fa6666c0c631095075744b0e94d1e6e089747cb4e39f645299649917a
round2-current.diff 3162a45c655724bcc1422efe2c9af21cf294f1e49a1a8b987a657ce6390d6325
round3-current.diff 5f109070b8fa4419a15ae713d6e4470ee1c12059f8beba059e52b26217433064
round4-source.patch 3b36bd287e1238f3bcdaf708fa77280a46cffe007fb150132371a95834c0357a
These identify review snapshots, not immutable commits of the current worktree or complete build inputs. Source manifest/campaign provenance remains root-owned.

Record-quality corrections requested to root (sparse append, never rewrite):
1. resource-ledger-001/root-build-001 fixed rows should explicitly cite fix file:line (canonical skill:1666), rather than only an implementation name plus working-diff hash. Suggested patch:35 and patch:16/:29 respectively. This is evidence-address normalization, not a new runtime defect or de-escalation.
2. quality-engineer-001 says "independently confirms" while the addendum explicitly identifies the same sequential reviewer. independent_reporters=1 is correct; clarify summary to "source rereview confirms" so readers do not infer another independent opinion.
3. Later Windows debug dependency and Linux host debug/release completion claims are root-reported; local STATE.txt still describes earlier in-progress work and initial domain reports do not carry those later observations. Root should cite retained command/log provenance for those specific milestones. This auditor has not independently observed those builds. This does not contradict root's newer observations or reopen proven source corrections.

Evidence limits: source fixes and local callback/macro/exact-apply checks do not imply fresh full runtime/sanitizer/application campaign success. Terminal ledger rows explicitly preserve that pending campaign; so do role reports. Clang provenance remains Homebrew Clang23 for reviewer's harness, Apple Clang21 for root's separate harness; neither is a whole macOS dependency build. Original pending coverage notes are superseded by explicit final coverage addenda, not silently erased.

Result: canonical live disposition/fact/provenance view is consistent, with the above small evidence-citation/independence-phrasing amendments requested. No new operational finding, severity reduction, self-waiver or overall governance PASS. Fresh runtime evidence remains pending. Root owns any ledger append and final decision.

FINAL CORRECTION VERIFICATION ADDENDUM — 2026-11-11
Read the appended ledger rows and build-milestones-20261111.json. Recomputed the same canonical field-wise live view: 22 physical rows, NINE live findings, EIGHT fixed and enterprise-readiness-001 linked-to-#2990. Three added ledger-audit observations carry I9/E3, NICE, native null and no floor; that preserves the original audit's absence of a native label and does not de-escalate another finding. Original rows remain present and floors/caused_by provenance survive.

All three requested record corrections are now verified CLOSED:
- ledger-audit-001: ledger lines 16–17 explicitly name current patch:35/:45 RAII ownership and :16/:29 exact upstream hunks. These are actual current source lines.
- ledger-audit-002: line 18 identifies tests/meson.build:81 and explicitly says same sequential reviewer, not additional independent reporter. Its first closure's adjacent-row citation is corrected by the final appended row, without rewriting history.
- ledger-audit-003: root milestone manifest names observer, scope, raw log paths and hashes, distinguishing host code-generation dependency from instrumented target and application/runtime validation. All THREE retained log SHA-256 values match the manifest exactly. Reading Linux log lines 52–90 confirms host debug/release processing completed before the ASan target starts. Windows retained debug log ends in debug package installation. The broader Windows progress log also contains later runner results; this addendum does not turn those into independently executed runtime validation or expand the scoped milestone claim. Root owns that runtime campaign and interpretation.

The earlier requested citation/provenance/independence-wording amendments are satisfied. Source-ledger consistency audit is complete with no remaining correction requested. This is a source/evidence-address audit only: it does not declare full runtime, sanitizer, platform or governance PASS, adjudicate an exception, or renew #2990.

===== END final-ledger-source-audit.txt =====


===== BEGIN DURABLE COPY routing.txt =====
Gate 0 routing audit — 2026-11-10
Scope: /private/tmp/yuzu-nightly-integration, base f4c2c95aa77bfc573614bdb381a010fc2a15d366, working/index diff against HEAD plus changelog.d/20261110-nightly-shutdown-rotation.fixed.md. 40 tracked changed paths + fragment. Root verified governance skill/four tables/CLAUDE/AGENTS byteidentical origin/dev. No source mutations or independent gates performed.

Read canonical governance Step 0, Gate 1 ledger contract and Gate 3 decision matrix/standing rules. Opened all four tables completely; recovered output-truncated rows individually. Reviewed changed-path list and substantive diffs to disambiguate semantic triggers.

MANDATORY DOMAIN ROSTER
architect: server/core/src/api_token_store.{cpp,hpp}; public rotation store contract; PostgreSQL store change.
cpp-expert + cpp-safety: every changed C++ unit and C++ source embedded in ports/grpc patches; callbacks, worker OpenSSL cleanup, EventEngine lifecycle.
quality-engineer: all tests, fixtures, new runtime process test, regression fixes (always include for fixes).
build-ci: tests/meson.build; workflows; vcpkg overlay, cache/sentinel/classifier; Docker dependency builds.
gateway-erlang: gateway test Erlang certificate/CRL builders.
cross-platform: shared test runner Windows/macOS exit guards, Windows sweep discovery, all-platform gRPC overlay.
release-deploy: five Dockerfile changes.
sre: background worker/callback lifetime and server-store row (also mandatory Gate 6).
security-guardian/docs-writer/consistency-auditor are mandatory gates independently and routed below. compliance-officer and enterprise-readiness remain mandatory Gate 6. happy/unhappy-path remain mandatory Gate 4. Chaos decision must follow Gate 4, not be pre-skipped.

MATCHED CONCERNS AND REQUIRED READING
- C++23 row: docs/cpp-conventions.md -> cpp-expert.
- Resource ownership/lifetime row: docs/cpp-conventions.md, docs/native-objcpp-conventions.md (no ObjC code here) -> cpp-safety + Gate2 ownership proof.
- macOS/Darwin row: docs/darwin-compat.md -> cross-platform for runner shutdown and patched dependency.
- User manual/docs row: .claude/agents/docs-writer.md -> docs-writer every change.
- Guardian/Guaranteed State row: semantic Guardian test changes in test_guardian_spark_reapply_skip_engine.cpp (async arms, inherited latch, generation persistence) -> security-guardian/docs-writer load docs/yuzu-guardian-design-v1.1.md, docs/yuzu-guardian-windows-implementation-plan.md, docs/dex-signal-catalog.md, docs/spark-legacy-delta-registry.md. No new DEX functionality; relevant parts are Guardian/Spark generation contracts.
- Spark detection row: same test modifies proof of Spark/Guardian async arm contract; load docs/adr/0021-spark-reflex-architecture.md, docs/spark-stage2-guardian-consumer-design.md, Guardian design and legacy delta registry for security/cpp-safety. Path pattern targets production spark/guardian_spark files; this is semantic test coverage of that invariant, not a claimed direct production path match. hard_exit call policy also changes at test runner consumer.
- Agentic-first row: consistency-auditor on every PR; docs/agentic-first-principle.md. No new API capability or handler.
- Enterprise parity row: enterprise-readiness Gate6 reading docs/enterprise-parity-plan.md.
- CI cache row: .github/workflows/ci.yml vcpkg installed cache key + overlay/sentinel coherence -> build-ci loads .claude/skills/ci-cache/SKILL.md.
- Server PostgreSQL substrate row: ApiTokenStore rotation change -> architect+sre load ADR-0006/0007/0008 (incl correction)/0010/0012, docs/postgres-store-playbook.md, docs/postgres-migration-ladder.md. security-guardian reviews durable initiator/raw-secret boundary; no secret-column/schema migration here. release-deploy also applies to Dockerfiles.
- Unit-test conventions row: tests/unit/** -> quality-engineer loads docs/testing/unit-test-conventions.md; review RAII teardown, helper lifetimes, shared-runner identifiers.
- Authentication/RBAC/header/token row: api_token_store.* durable operator deny before RAM publication, tests and auth architecture -> security-guardian loads docs/auth-architecture.md + docs/adr/0031-engine-principal-store.md + docs/adr/0041-rbac-store-postgres-migration.md update.
- Enterprise A&A roadmap row: auth-and-authz skill applies to token audit. Its inventory is visibly historical (claims no rotation although diff operates rotation); current code/docs and routed rows are authority. Read docs/auth-architecture.md and enterprise-readiness SOC2 section 3.2. AuthDB-specific agent is NOT triggered: no auth_db/auth_routes/auth/session_store edits.
- Clock-guarded retention row: sweep-test-databases.sh is a modified database reaper script. Its changed hunk only locates psql; selection/deletion policy is unchanged. Conservatively route cpp-safety+sre+compliance-officer to docs/clock-guarded-retention.md to confirm unchanged selection, not to demand a new production retention design for an executable-discovery edit.

NONMATCH EXPLANATIONS
No proto/schema or plugin ABI changes, no plugin source/catalogue/YAML, no CEL/DSL or scope traversal: plugin-developer/dsl-engineer are not selected. No SQLite query/BFS/get_*_ids/per-request authz hot path changed: performance is not selected; token rotation is an operator mutation.
No new capability/route/tool/fragment/ingress/approval gate: ADR-1005 new-surface question has no new surface to trace; no new body-cap/step-up/same-site/dispatch/confinement/topology-floor or split marker touched. Mandatory consistency still checks existing interface behavior.
Gateway test fixture SHA-256 changes do not touch gateway upstream auth wrapper, origin trust, mgmt auth mode/CRL keys, boot guards, mgmt events, config or production PKI signer: no extra production peer-authorization row match. gateway-erlang + security still review fixture cryptographic semantics.
No response/Forensics visibility, inventory store, software normalization, forensic plugin or security-posture plugin changed. All named plugin rows in security-posture/software-estate are nonmatches. Dockerfile.agent mention in local_security_policy row is explanatory, not a trigger for unrelated overlay COPY.
No metrics/audit/event label/envelope/schema additions; observability/schema-design rows not independently triggered. No common/include edits, OTA admission, confined filesystem, command dedup, quarantine, Echo cursor/DB, execution outbox, policy evaluator or preflight/deployment implementation changed.

RESOURCE LEDGER COMPLETENESS CHECKLIST (input to Gate1, not an ownership verdict)
1. SuiteGrpcRuntime: default EventEngine acquired CreateEventEngine, ownership transferred SetDefaultEventEngine; grpc_init ref balanced grpc_shutdown_blocking; ShutdownDefaultEventEngine after Session destruction. No copied owner; construction before grpc_init may throw. Trace library global-slot ownership and teardown implementation to prove failure behavior.
2. Patched gRPC ThreadState worker: existing new ThreadState/raw void* callback/delete worker ownership now releases worker-local OpenSSL state via OPENSSL_thread_stop BEFORE delete publishes retirement. Track detached thread, ThreadState, callback context, crypto per-thread state, secure-target-only compile guard, all failure/return paths. Manual delete is upstream pre-existing code/context, not new handwritten cleanup introduced by patch.
3. New runtime test: weak/shared EventEngine references, shared promise<bool> captured by async callback, future wait and exception/timeout unwind, OpenSSL RAND public/private worker state. Ensure fixture completion and engine drain outlive captured data on timeout.
4. Token regression: temporary PG database (_TPL), PgPool (4 connections), ApiTokenStore, reference-capturing test_hook_before_store_rotation_raw_ callback, nested rotation transactions/raw-secret cache. Capture references live until store destruction; reviewer should verify hook executes synchronously and no destruction-time callback.
5. Guardian test: hung FakeMechanism watch worker; release_hang normal path and fixture failure cleanup on any REQUIRE before release. No newly acquired raw handle, but an intentionally parked thread must have a proven unwind unblock/join path.
6. Python/shell/Erlang fixture temp dirs/processes/PEM keys and Docker build artifacts deserve quality/security review even though C++ ledger mandatory categories specifically focus the C++ change. Sweep script changes executable selection only; review argv and cross-runner destructive-database exclusion remains intact.

MEMORY SEARCH
Searched rg --files --hidden over /Users/nathan/.claude, /Users/nathan/.codex, /Users/nathan/.agents; then --hidden --no-ignore over /Users/nathan/.claude/projects and /Users/nathan/.codex for exact feedback_governance_run.md, feedback_test_quality.md, feedback_claude_md_scope.md. No exact files returned in those searched roots. Do not infer global absence. Broader filename search located feedback_governance_orchestrator_rate_limits.md and feedback_governance_consistency.md plus project_governance_ledger_sha_unresolvable_systemic.md under /Users/nathan/.claude/projects/-Users-nathan-Yuzu/memory; root may consult these related memories.

===== END DURABLE COPY routing.txt =====


===== BEGIN DURABLE COPY gate1.txt =====
Gate 1: latest origin/dev f4c2c95aa77bfc573614bdb381a010fc2a15d366 integrated by fast-forward then exact stash apply, clean. Scope is HEAD to working tree including staged changes and untracked changelog. No commits/publishing authorized in this run. Purpose: reproduce/fix nightly shutdown OpenSSL worker TLS lifetime, server test runtime ownership, token rotation interleaving denial, deterministic fixtures and dependency/cache integration. Resource ledger: resource-inventory.txt (14 entries). Routing: routing.txt (all four tables read). Fresh Linux full ASan/TSan and gateway validation in progress; historical Windows runner validation is not fresh overlay validation. All reviewers read actual diff/code, not conclusions alone. No source edits.

Commits in scope | Subject | Push state
f4c2c95aa77bfc573614bdb381a010fc2a15d366 | Merge pull request #7464 dispatch-denial-reason-rest-recheck | fetched upstream base; no new local commits
Working tree | nightly integration changes | local only, staged plus untracked changelog

Interfaces: ApiTokenStore rotation denial now respects durable initiator during commit-to-cache window; no new endpoint/schema/proto/plugin ABI. Secure grpc worker cleanup ordering; server-only Catch runner default engine ownership. CI overlay cache keys, change classifier and Docker contexts include overlay. Gateway fixture crypto digest choice only.
Security: closes competing-operator transient retry/error inconsistency without authorizing raw-token replay from durable identity. No new permissions. Worker cleanup closes shutdown race but requires RAII correction.
User impact: reliable sanitizer shutdown and correct competing token rotation rejection, no new flags or schema migration.
Prior validation: old base701750090 both full 171-entry configurations with corrected failed attempts; a772 targeted updated builds and suites; not evidence of fresh full f4c validation. Fresh full Linux validation pending. Windows old dependency runner-only 20 repetitions PASS, no updated Windows overlay proof.

Files touched | Delta
.github/workflows/ci.yml | Dependency integration configuration or operator-visible changelog
deploy/docker/Dockerfile.agent | Include overlay in dependency build context
deploy/docker/Dockerfile.agent.chisel | Include overlay in dependency build context
deploy/docker/Dockerfile.ci | Include overlay in dependency build context
deploy/docker/Dockerfile.server | Include overlay in dependency build context
deploy/docker/Dockerfile.server.chisel | Include overlay in dependency build context
docs/auth-architecture.md | Document changed ownership, denial or cache contract
docs/build-guide.md | Document changed ownership, denial or cache contract
docs/ci-architecture.md | Document changed ownership, denial or cache contract
gateway/apps/yuzu_gw/test/yuzu_gw_cert_files_tests.erl | Explicit fixture certificate SHA256 signing
gateway/apps/yuzu_gw/test/yuzu_gw_crl_build.erl | Explicit fixture certificate SHA256 signing
ports/grpc/00001-fix-uwp.patch | Pinned gRPC overlay recipe and secure-worker cleanup patch
ports/grpc/00002-static-linking-in-linux.patch | Pinned gRPC overlay recipe and secure-worker cleanup patch
ports/grpc/00004-link-gdi32-on-windows.patch | Pinned gRPC overlay recipe and secure-worker cleanup patch
ports/grpc/00005-fix-uwp-error.patch | Pinned gRPC overlay recipe and secure-worker cleanup patch
ports/grpc/00006-utf8-range.patch | Pinned gRPC overlay recipe and secure-worker cleanup patch
ports/grpc/00015-disable-download-archive.patch | Pinned gRPC overlay recipe and secure-worker cleanup patch
ports/grpc/00016-fix-plugin-targets.patch | Pinned gRPC overlay recipe and secure-worker cleanup patch
ports/grpc/00017-openssl-worker-cleanup.patch | Pinned gRPC overlay recipe and secure-worker cleanup patch
ports/grpc/README.txt | Pinned gRPC overlay recipe and secure-worker cleanup patch
ports/grpc/gRPCTargets-vcpkg-tools.cmake | Pinned gRPC overlay recipe and secure-worker cleanup patch
ports/grpc/portfile.cmake | Pinned gRPC overlay recipe and secure-worker cleanup patch
ports/grpc/vcpkg-cmake-wrapper.cmake | Pinned gRPC overlay recipe and secure-worker cleanup patch
ports/grpc/vcpkg.json | Pinned gRPC overlay recipe and secure-worker cleanup patch
scripts/ci/detect-code-change.sh | Overlay cache/classifier validation or Windows psql discovery
scripts/ci/sweep-test-databases.sh | Overlay cache/classifier validation or Windows psql discovery
scripts/ci/test-vcpkg-sentinel.sh | Overlay cache/classifier validation or Windows psql discovery
scripts/ci/vcpkg-triplet-sentinel.sh | Overlay cache/classifier validation or Windows psql discovery
server/core/src/api_token_store.cpp | Durable initiator denial during publication and regression
server/core/src/api_token_store.hpp | Durable initiator denial during publication and regression
tests/meson.build | Runtime ownership, deterministic regression fixtures or dependency integration validation
tests/shell/test_build_examples_gating.sh | Runtime ownership, deterministic regression fixtures or dependency integration validation
tests/shell/test_detect_code_change.sh | Runtime ownership, deterministic regression fixtures or dependency integration validation
tests/test_instructions_runner_hardening.py | Runtime ownership, deterministic regression fixtures or dependency integration validation
tests/test_mcp_http_adapter_behaviour.py | Runtime ownership, deterministic regression fixtures or dependency integration validation
tests/unit/server/test_api_token_store.cpp | Durable initiator denial during publication and regression
tests/unit/test_grpc_runtime_lifetime.cpp | Runtime ownership, deterministic regression fixtures or dependency integration validation
tests/unit/test_guardian_spark_reapply_skip_engine.cpp | Runtime ownership, deterministic regression fixtures or dependency integration validation
tests/unit/test_runner_main.cpp | Runtime ownership, deterministic regression fixtures or dependency integration validation
vcpkg-configuration.json | Dependency integration configuration or operator-visible changelog
changelog.d/20261110-nightly-shutdown-rotation.fixed.md | Dependency integration configuration or operator-visible changelog

Full resource ledger (owner/acquire/release/transfer/failure paths):
Gate 1 resource inventory — read-only source inspection, not a Gate 3 verdict
Scope: /private/tmp/yuzu-nightly-integration, diff f4c2c95aa through current working tree. Canonical policy read: .claude/skills/governance/SKILL.md lines 324–350 and 483–535. Root owns consolidated summary.
Input proof: new runner says “Keeping a second shared_ptr here would deadlock shutdown's wait for the last owner”; patched worker says “Release this thread's crypto state before publishing retirement”. Inspected actual /private/tmp/yuzu-nightly-audit/work_stealing_thread_pool_181_patched.cc StartThread/ThreadBody/Quiesce, not just patch prose. Also inspected /private/tmp/yuzu-nightly-audit/default_event_engine.cc; that latter file is supporting audit source, not independently established installed 1.81.1 provenance.

Resource | Owner / acquisition | Release / transfer / failure cleanup
1. Default EventEngine and pool: SuiteGrpcRuntime lifecycle owner; CreateEventEngine returns shared_ptr, moved by SetDefaultEventEngine into strong global default slot before grpc_init. No extra runner shared_ptr retained. Destructor calls grpc_shutdown_blocking then ShutdownDefaultEventEngine, whose inspected implementation removes slot and waits for single ownership. Catch Session is declared later and destroyed first on normal return, command-line error, or C++ unwind after completed construction. Create failure has ordinary temporary shared_ptr cleanup. Agent runner does not compile this owner. Installed-version behavior and any constructor partial-publication failure remain Gate 3 verification obligations.
2. gRPC C initialization reference: SuiteGrpcRuntime obtains one grpc_init reference after engine installation, balances with grpc_shutdown_blocking in destructor, noncopyable. No explicit manual cleanup outside owner. Other suite init refs, custom engines, and caller threads remain their individual fixtures' responsibility; this scope does not imply ownership of them.
3. Catch Session and listener resources: run_suite stack Session, applyCommandLine/session.run; destructor before SuiteGrpcRuntime, including early CLI failure. Existing PG testRunEnded cleanup executes during session.run; main hard_exit is now after run_suite destruction. Sanitizer/coverage paths return normally. stdout/stderr are borrowed process streams, only fprintf/fflush, not acquired/closed here; argc/argv borrowed for call duration.
4. Detached upstream EventEngine workers: existing StartThread constructs raw new ThreadState(shared_from_this()), transfers pointer as void* callback context to detached grpc_core::Thread and begins execution. Callback owns worker, ThreadBody runs, patched OPENSSL_thread_stop then existing delete worker. ThreadState owns pool shared_ptr and RAII living-thread counter. Quiesce signals workers and waits count zero (one if invoked by a pool worker), checks queue empty and resets lifeguard. No OS join is introduced: actual pthread/FLS destructors may follow count retirement. Thread creation failure and exceptions escaping ThreadBody remain pre-existing upstream behavior, not established safe by this inventory.
5. Worker OpenSSL per-thread state: acquired implicitly by callbacks' crypto operations; new patch explicitly releases via OPENSSL_thread_stop on same worker after ThreadBody, before ThreadState counter retirement. Limited to secure grpc compile target and OpenSSL >=1.1 excluding BoringSSL/LibreSSL. No transfer, no explicit library-context owner, no global OPENSSL_cleanup added. Normal callback return reaches release; exceptional escape would skip this statement. This is NEW MANUAL RESOURCE CLEANUP and requires canonical policy-floor handling: a RAII owner/scope guard or independently adjudicated documented-impossibility exception. No exception has been proposed or granted by this inventory agent; record adjudicated_by if an independent agent accepts one. ThreadState raw delete and ThreadBody queue delete pre-exist upstream; distinguish them from newly added OpenSSL cleanup.
6. Upstream local work queue / callback queue / thread-local bookkeeping: ThreadBody new BasicWorkQueue(pool_.get()), enrolls queue, borrows pool through ThreadState's shared_ptr. Fork path moves pending closures into pool queue; shutdown FinishDraining runs them; unenroll then delete queue before new OpenSSL stop. Existing raw callback contexts and bookkeeping retain upstream ownership. Patch cannot attest that arbitrary future thread-local destructors never reenter crypto; its exact boundary is callbacks drained and this thread's current OpenSSL state stopped before retirement.
7. Lifetime regression's EventEngine refs: temporary shared_ptr from GetDefaultEventEngine assigned to weak observed; temporary destroyed before expired assertion. observed.lock gives local shared owner through scheduling and future wait. All local refs destroyed on Catch REQUIRE unwinding as on success; timeout does not cancel queued work but suite-owned engine remains until runner teardown.
8. Lifetime regression promise/future/callback: make_shared<promise<bool>>, one future via get_future; lambda captures shared_ptr by value, EventEngine owns submitted callback until invocation/disposal. Main and lambda release their copies independently; future destroys its shared-state ref. Worker uses stack array<unsigned char,32> passed to RAND_bytes/RAND_priv_bytes only for call duration, no escape. Main-thread RAND_status and worker public/private DRBG allocate implicit OpenSSL thread state. Main state is process/main-thread lifecycle; worker state uses patched cleanup. Callback set_value is single-use; no borrowed stack capture. Timeout REQUIRE unwinds locals safely without invalidating callback's promise.
9. Rotation test PostgreSQL database: YUZU_REQUIRE_PG_DB_TPL creates stack PostgresTestDb from existing apitoken_pg_template. Missing DSN SKIPs before acquisition; unavailable database REQUIRE unwinds fixture. Helper owns salted database name/DSN; scoped PgConn/PgResult wrap admin handles/results. Destructor issues DROP DATABASE IF EXISTS WITH(FORCE), logging failure; this test does not call keep_until_run_end. Template itself uses pre-existing suite/template cleanup lifecycle.
10. Rotation test PgPool and ApiTokenStore: pool declared after DB, store after pool; reverse destruction destroys store, drains pool, then drops DB. PgPool size four owns pooled PGconn (network/TLS resources); destructor blocks until leases/connectors/waiters return and PQfinish closes idle handles. Store borrows pool reference. Test adds no persistent lease or transaction escape.
11. Rotation callback and borrowed test locals: store owns std::function test_hook_before_store_rotation_raw_, capture [&] borrows store, principal, now, interleaved. Called synchronously after transaction commit and before raw-cache publication; nested rejected rotations do not mint and do not recursively invoke hook. Borrowed locals live through invocations; closure destruction does not dereference them even though later-declared locals die before store. Stateless engine-referent callback has no borrowed resources. Returned minted/replay expected<string> values and principal/error strings own their storage; test does not add explicit secret scrubbing beyond existing store guards.
12. Production rotation denial: no new resource acquisition. successor/predecessor pointers borrow entries in local active vector, no mutation/escape before new check. New false return occurs inside existing with_txn_for callback; existing transaction/lease guards and function-scope raw-secret scrub guards remain responsible for rollback/release/scrub. Durable initiator string used only for comparison; no new secret copy or cache reservation. Epoch check still precedes denial; try_reserve still follows it. ApiToken header only documents this existing field's broader denial use.
13. Guardian modified test parked worker: existing Rig owns GuardianEngine/SparkEngine/KvStore via unique_ptr, TempDbFile and TempDir, fake mechanisms owned by SparkEngine with borrowed fm/sm aliases. New hang_next_watch acquires logical gate; wait_entered_hang observes worker parked; release_hang unblocks, drain_until_idle/wait_compliant settle before final sync. On REQUIRE failure before explicit release, Rig::~Rig -> close releases BOTH watch/unwatch gates on BOTH mechanisms before waiting for engine workers, resetting engine, stopping/resetting spark, nulling aliases, resetting KV. Existing bounded wait emits FAIL_CHECK on timeout; inventory does not assert that timeout proves all worker cleanup safe.
14. Guardian existing resources affected by new timing: file paths r1/a/x under TempDir; ofstream creates/closes each file in make_file; TempDir cleanup after engines, TempDbFile last. KV SQLite owned by KvStore. AttachProbe shared_ptr is retained by installed hook (existing helper); callbacks retain fixture borrowing contract. Mutex/CV locks use lock_guard/unique_lock; timed waits release locks on exit. No new OS fd, HANDLE, SOCKET, FILE*, sqlite3_stmt, mapped library, subprocess, BCrypt handle or allocated C string directly introduced in changed C++ beyond wrapped/transitive resources enumerated above.

Documentation boundary inventory (not docs/domain verdict): runner header, ports/grpc/README.txt and docs/build-guide.md explicitly split suite default-engine ownership, worker OpenSSL cleanup, and caller-owned/custom-engine obligations. They do not promise an OS-level join. README “does not cover custom engines” is conservative application scope; patched work-stealing pool code may be reused by such engines but their destruction is not ensured by SuiteGrpcRuntime. docs/auth-architecture.md describes denial-only durable identity and still-RAM-bound secret re-serve, matching resource distinction. docs/ci-architecture.md describes overlay hash invalidation, no extra C++ resource owner. New patch prose “so a caller may safely clean up OpenSSL after quiescence” depends on all other crypto-thread/engine ownership obligations; Gate 3 should preserve that conditional boundary.

No tests run, no source edits, no Gate 3 approval, no self-adjudicated manual-cleanup exception.

Governance domains and matched concerns:
Gate 0 routing audit — 2026-11-10
Scope: /private/tmp/yuzu-nightly-integration, base f4c2c95aa77bfc573614bdb381a010fc2a15d366, working/index diff against HEAD plus changelog.d/20261110-nightly-shutdown-rotation.fixed.md. 40 tracked changed paths + fragment. Root verified governance skill/four tables/CLAUDE/AGENTS byteidentical origin/dev. No source mutations or independent gates performed.

Read canonical governance Step 0, Gate 1 ledger contract and Gate 3 decision matrix/standing rules. Opened all four tables completely; recovered output-truncated rows individually. Reviewed changed-path list and substantive diffs to disambiguate semantic triggers.

MANDATORY DOMAIN ROSTER
architect: server/core/src/api_token_store.{cpp,hpp}; public rotation store contract; PostgreSQL store change.
cpp-expert + cpp-safety: every changed C++ unit and C++ source embedded in ports/grpc patches; callbacks, worker OpenSSL cleanup, EventEngine lifecycle.
quality-engineer: all tests, fixtures, new runtime process test, regression fixes (always include for fixes).
build-ci: tests/meson.build; workflows; vcpkg overlay, cache/sentinel/classifier; Docker dependency builds.
gateway-erlang: gateway test Erlang certificate/CRL builders.
cross-platform: shared test runner Windows/macOS exit guards, Windows sweep discovery, all-platform gRPC overlay.
release-deploy: five Dockerfile changes.
sre: background worker/callback lifetime and server-store row (also mandatory Gate 6).
security-guardian/docs-writer/consistency-auditor are mandatory gates independently and routed below. compliance-officer and enterprise-readiness remain mandatory Gate 6. happy/unhappy-path remain mandatory Gate 4. Chaos decision must follow Gate 4, not be pre-skipped.

MATCHED CONCERNS AND REQUIRED READING
- C++23 row: docs/cpp-conventions.md -> cpp-expert.
- Resource ownership/lifetime row: docs/cpp-conventions.md, docs/native-objcpp-conventions.md (no ObjC code here) -> cpp-safety + Gate2 ownership proof.
- macOS/Darwin row: docs/darwin-compat.md -> cross-platform for runner shutdown and patched dependency.
- User manual/docs row: .claude/agents/docs-writer.md -> docs-writer every change.
- Guardian/Guaranteed State row: semantic Guardian test changes in test_guardian_spark_reapply_skip_engine.cpp (async arms, inherited latch, generation persistence) -> security-guardian/docs-writer load docs/yuzu-guardian-design-v1.1.md, docs/yuzu-guardian-windows-implementation-plan.md, docs/dex-signal-catalog.md, docs/spark-legacy-delta-registry.md. No new DEX functionality; relevant parts are Guardian/Spark generation contracts.
- Spark detection row: same test modifies proof of Spark/Guardian async arm contract; load docs/adr/0021-spark-reflex-architecture.md, docs/spark-stage2-guardian-consumer-design.md, Guardian design and legacy delta registry for security/cpp-safety. Path pattern targets production spark/guardian_spark files; this is semantic test coverage of that invariant, not a claimed direct production path match. hard_exit call policy also changes at test runner consumer.
- Agentic-first row: consistency-auditor on every PR; docs/agentic-first-principle.md. No new API capability or handler.
- Enterprise parity row: enterprise-readiness Gate6 reading docs/enterprise-parity-plan.md.
- CI cache row: .github/workflows/ci.yml vcpkg installed cache key + overlay/sentinel coherence -> build-ci loads .claude/skills/ci-cache/SKILL.md.
- Server PostgreSQL substrate row: ApiTokenStore rotation change -> architect+sre load ADR-0006/0007/0008 (incl correction)/0010/0012, docs/postgres-store-playbook.md, docs/postgres-migration-ladder.md. security-guardian reviews durable initiator/raw-secret boundary; no secret-column/schema migration here. release-deploy also applies to Dockerfiles.
- Unit-test conventions row: tests/unit/** -> quality-engineer loads docs/testing/unit-test-conventions.md; review RAII teardown, helper lifetimes, shared-runner identifiers.
- Authentication/RBAC/header/token row: api_token_store.* durable operator deny before RAM publication, tests and auth architecture -> security-guardian loads docs/auth-architecture.md + docs/adr/0031-engine-principal-store.md + docs/adr/0041-rbac-store-postgres-migration.md update.
- Enterprise A&A roadmap row: auth-and-authz skill applies to token audit. Its inventory is visibly historical (claims no rotation although diff operates rotation); current code/docs and routed rows are authority. Read docs/auth-architecture.md and enterprise-readiness SOC2 section 3.2. AuthDB-specific agent is NOT triggered: no auth_db/auth_routes/auth/session_store edits.
- Clock-guarded retention row: sweep-test-databases.sh is a modified database reaper script. Its changed hunk only locates psql; selection/deletion policy is unchanged. Conservatively route cpp-safety+sre+compliance-officer to docs/clock-guarded-retention.md to confirm unchanged selection, not to demand a new production retention design for an executable-discovery edit.

NONMATCH EXPLANATIONS
No proto/schema or plugin ABI changes, no plugin source/catalogue/YAML, no CEL/DSL or scope traversal: plugin-developer/dsl-engineer are not selected. No SQLite query/BFS/get_*_ids/per-request authz hot path changed: performance is not selected; token rotation is an operator mutation.
No new capability/route/tool/fragment/ingress/approval gate: ADR-1005 new-surface question has no new surface to trace; no new body-cap/step-up/same-site/dispatch/confinement/topology-floor or split marker touched. Mandatory consistency still checks existing interface behavior.
Gateway test fixture SHA-256 changes do not touch gateway upstream auth wrapper, origin trust, mgmt auth mode/CRL keys, boot guards, mgmt events, config or production PKI signer: no extra production peer-authorization row match. gateway-erlang + security still review fixture cryptographic semantics.
No response/Forensics visibility, inventory store, software normalization, forensic plugin or security-posture plugin changed. All named plugin rows in security-posture/software-estate are nonmatches. Dockerfile.agent mention in local_security_policy row is explanatory, not a trigger for unrelated overlay COPY.
No metrics/audit/event label/envelope/schema additions; observability/schema-design rows not independently triggered. No common/include edits, OTA admission, confined filesystem, command dedup, quarantine, Echo cursor/DB, execution outbox, policy evaluator or preflight/deployment implementation changed.

RESOURCE LEDGER COMPLETENESS CHECKLIST (input to Gate1, not an ownership verdict)
1. SuiteGrpcRuntime: default EventEngine acquired CreateEventEngine, ownership transferred SetDefaultEventEngine; grpc_init ref balanced grpc_shutdown_blocking; ShutdownDefaultEventEngine after Session destruction. No copied owner; construction before grpc_init may throw. Trace library global-slot ownership and teardown implementation to prove failure behavior.
2. Patched gRPC ThreadState worker: existing new ThreadState/raw void* callback/delete worker ownership now releases worker-local OpenSSL state via OPENSSL_thread_stop BEFORE delete publishes retirement. Track detached thread, ThreadState, callback context, crypto per-thread state, secure-target-only compile guard, all failure/return paths. Manual delete is upstream pre-existing code/context, not new handwritten cleanup introduced by patch.
3. New runtime test: weak/shared EventEngine references, shared promise<bool> captured by async callback, future wait and exception/timeout unwind, OpenSSL RAND public/private worker state. Ensure fixture completion and engine drain outlive captured data on timeout.
4. Token regression: temporary PG database (_TPL), PgPool (4 connections), ApiTokenStore, reference-capturing test_hook_before_store_rotation_raw_ callback, nested rotation transactions/raw-secret cache. Capture references live until store destruction; reviewer should verify hook executes synchronously and no destruction-time callback.
5. Guardian test: hung FakeMechanism watch worker; release_hang normal path and fixture failure cleanup on any REQUIRE before release. No newly acquired raw handle, but an intentionally parked thread must have a proven unwind unblock/join path.
6. Python/shell/Erlang fixture temp dirs/processes/PEM keys and Docker build artifacts deserve quality/security review even though C++ ledger mandatory categories specifically focus the C++ change. Sweep script changes executable selection only; review argv and cross-runner destructive-database exclusion remains intact.

MEMORY SEARCH
Searched rg --files --hidden over /Users/nathan/.claude, /Users/nathan/.codex, /Users/nathan/.agents; then --hidden --no-ignore over /Users/nathan/.claude/projects and /Users/nathan/.codex for exact feedback_governance_run.md, feedback_test_quality.md, feedback_claude_md_scope.md. No exact files returned in those searched roots. Do not infer global absence. Broader filename search located feedback_governance_orchestrator_rate_limits.md and feedback_governance_consistency.md plus project_governance_ledger_sha_unresolvable_systemic.md under /Users/nathan/.claude/projects/-Users-nathan-Yuzu/memory; root may consult these related memories.

ROUND3 UPDATE: Worker owner now unique_ptr<ThreadState>; scoped noncopy crypto owner declared after worker calls OPENSSL_thread_stop before ThreadState retirement, on normal/unwind paths. First regenerated patch had bad context, corrected from exact upstream bytes and git apply --check verified separately. New durations option. Original resource inventory retained as initial-snapshot evidence.

===== END DURABLE COPY gate1.txt =====


===== BEGIN DURABLE COPY resource-inventory.txt =====
Gate 1 resource inventory — read-only source inspection, not a Gate 3 verdict
Scope: /private/tmp/yuzu-nightly-integration, diff f4c2c95aa through current working tree. Canonical policy read: .claude/skills/governance/SKILL.md lines 324–350 and 483–535. Root owns consolidated summary.
Input proof: new runner says “Keeping a second shared_ptr here would deadlock shutdown's wait for the last owner”; patched worker says “Release this thread's crypto state before publishing retirement”. Inspected actual /private/tmp/yuzu-nightly-audit/work_stealing_thread_pool_181_patched.cc StartThread/ThreadBody/Quiesce, not just patch prose. Also inspected /private/tmp/yuzu-nightly-audit/default_event_engine.cc; that latter file is supporting audit source, not independently established installed 1.81.1 provenance.

Resource | Owner / acquisition | Release / transfer / failure cleanup
1. Default EventEngine and pool: SuiteGrpcRuntime lifecycle owner; CreateEventEngine returns shared_ptr, moved by SetDefaultEventEngine into strong global default slot before grpc_init. No extra runner shared_ptr retained. Destructor calls grpc_shutdown_blocking then ShutdownDefaultEventEngine, whose inspected implementation removes slot and waits for single ownership. Catch Session is declared later and destroyed first on normal return, command-line error, or C++ unwind after completed construction. Create failure has ordinary temporary shared_ptr cleanup. Agent runner does not compile this owner. Installed-version behavior and any constructor partial-publication failure remain Gate 3 verification obligations.
2. gRPC C initialization reference: SuiteGrpcRuntime obtains one grpc_init reference after engine installation, balances with grpc_shutdown_blocking in destructor, noncopyable. No explicit manual cleanup outside owner. Other suite init refs, custom engines, and caller threads remain their individual fixtures' responsibility; this scope does not imply ownership of them.
3. Catch Session and listener resources: run_suite stack Session, applyCommandLine/session.run; destructor before SuiteGrpcRuntime, including early CLI failure. Existing PG testRunEnded cleanup executes during session.run; main hard_exit is now after run_suite destruction. Sanitizer/coverage paths return normally. stdout/stderr are borrowed process streams, only fprintf/fflush, not acquired/closed here; argc/argv borrowed for call duration.
4. Detached upstream EventEngine workers: existing StartThread constructs raw new ThreadState(shared_from_this()), transfers pointer as void* callback context to detached grpc_core::Thread and begins execution. Callback owns worker, ThreadBody runs, patched OPENSSL_thread_stop then existing delete worker. ThreadState owns pool shared_ptr and RAII living-thread counter. Quiesce signals workers and waits count zero (one if invoked by a pool worker), checks queue empty and resets lifeguard. No OS join is introduced: actual pthread/FLS destructors may follow count retirement. Thread creation failure and exceptions escaping ThreadBody remain pre-existing upstream behavior, not established safe by this inventory.
5. Worker OpenSSL per-thread state: acquired implicitly by callbacks' crypto operations; new patch explicitly releases via OPENSSL_thread_stop on same worker after ThreadBody, before ThreadState counter retirement. Limited to secure grpc compile target and OpenSSL >=1.1 excluding BoringSSL/LibreSSL. No transfer, no explicit library-context owner, no global OPENSSL_cleanup added. Normal callback return reaches release; exceptional escape would skip this statement. This is NEW MANUAL RESOURCE CLEANUP and requires canonical policy-floor handling: a RAII owner/scope guard or independently adjudicated documented-impossibility exception. No exception has been proposed or granted by this inventory agent; record adjudicated_by if an independent agent accepts one. ThreadState raw delete and ThreadBody queue delete pre-exist upstream; distinguish them from newly added OpenSSL cleanup.
6. Upstream local work queue / callback queue / thread-local bookkeeping: ThreadBody new BasicWorkQueue(pool_.get()), enrolls queue, borrows pool through ThreadState's shared_ptr. Fork path moves pending closures into pool queue; shutdown FinishDraining runs them; unenroll then delete queue before new OpenSSL stop. Existing raw callback contexts and bookkeeping retain upstream ownership. Patch cannot attest that arbitrary future thread-local destructors never reenter crypto; its exact boundary is callbacks drained and this thread's current OpenSSL state stopped before retirement.
7. Lifetime regression's EventEngine refs: temporary shared_ptr from GetDefaultEventEngine assigned to weak observed; temporary destroyed before expired assertion. observed.lock gives local shared owner through scheduling and future wait. All local refs destroyed on Catch REQUIRE unwinding as on success; timeout does not cancel queued work but suite-owned engine remains until runner teardown.
8. Lifetime regression promise/future/callback: make_shared<promise<bool>>, one future via get_future; lambda captures shared_ptr by value, EventEngine owns submitted callback until invocation/disposal. Main and lambda release their copies independently; future destroys its shared-state ref. Worker uses stack array<unsigned char,32> passed to RAND_bytes/RAND_priv_bytes only for call duration, no escape. Main-thread RAND_status and worker public/private DRBG allocate implicit OpenSSL thread state. Main state is process/main-thread lifecycle; worker state uses patched cleanup. Callback set_value is single-use; no borrowed stack capture. Timeout REQUIRE unwinds locals safely without invalidating callback's promise.
9. Rotation test PostgreSQL database: YUZU_REQUIRE_PG_DB_TPL creates stack PostgresTestDb from existing apitoken_pg_template. Missing DSN SKIPs before acquisition; unavailable database REQUIRE unwinds fixture. Helper owns salted database name/DSN; scoped PgConn/PgResult wrap admin handles/results. Destructor issues DROP DATABASE IF EXISTS WITH(FORCE), logging failure; this test does not call keep_until_run_end. Template itself uses pre-existing suite/template cleanup lifecycle.
10. Rotation test PgPool and ApiTokenStore: pool declared after DB, store after pool; reverse destruction destroys store, drains pool, then drops DB. PgPool size four owns pooled PGconn (network/TLS resources); destructor blocks until leases/connectors/waiters return and PQfinish closes idle handles. Store borrows pool reference. Test adds no persistent lease or transaction escape.
11. Rotation callback and borrowed test locals: store owns std::function test_hook_before_store_rotation_raw_, capture [&] borrows store, principal, now, interleaved. Called synchronously after transaction commit and before raw-cache publication; nested rejected rotations do not mint and do not recursively invoke hook. Borrowed locals live through invocations; closure destruction does not dereference them even though later-declared locals die before store. Stateless engine-referent callback has no borrowed resources. Returned minted/replay expected<string> values and principal/error strings own their storage; test does not add explicit secret scrubbing beyond existing store guards.
12. Production rotation denial: no new resource acquisition. successor/predecessor pointers borrow entries in local active vector, no mutation/escape before new check. New false return occurs inside existing with_txn_for callback; existing transaction/lease guards and function-scope raw-secret scrub guards remain responsible for rollback/release/scrub. Durable initiator string used only for comparison; no new secret copy or cache reservation. Epoch check still precedes denial; try_reserve still follows it. ApiToken header only documents this existing field's broader denial use.
13. Guardian modified test parked worker: existing Rig owns GuardianEngine/SparkEngine/KvStore via unique_ptr, TempDbFile and TempDir, fake mechanisms owned by SparkEngine with borrowed fm/sm aliases. New hang_next_watch acquires logical gate; wait_entered_hang observes worker parked; release_hang unblocks, drain_until_idle/wait_compliant settle before final sync. On REQUIRE failure before explicit release, Rig::~Rig -> close releases BOTH watch/unwatch gates on BOTH mechanisms before waiting for engine workers, resetting engine, stopping/resetting spark, nulling aliases, resetting KV. Existing bounded wait emits FAIL_CHECK on timeout; inventory does not assert that timeout proves all worker cleanup safe.
14. Guardian existing resources affected by new timing: file paths r1/a/x under TempDir; ofstream creates/closes each file in make_file; TempDir cleanup after engines, TempDbFile last. KV SQLite owned by KvStore. AttachProbe shared_ptr is retained by installed hook (existing helper); callbacks retain fixture borrowing contract. Mutex/CV locks use lock_guard/unique_lock; timed waits release locks on exit. No new OS fd, HANDLE, SOCKET, FILE*, sqlite3_stmt, mapped library, subprocess, BCrypt handle or allocated C string directly introduced in changed C++ beyond wrapped/transitive resources enumerated above.

Documentation boundary inventory (not docs/domain verdict): runner header, ports/grpc/README.txt and docs/build-guide.md explicitly split suite default-engine ownership, worker OpenSSL cleanup, and caller-owned/custom-engine obligations. They do not promise an OS-level join. README “does not cover custom engines” is conservative application scope; patched work-stealing pool code may be reused by such engines but their destruction is not ensured by SuiteGrpcRuntime. docs/auth-architecture.md describes denial-only durable identity and still-RAM-bound secret re-serve, matching resource distinction. docs/ci-architecture.md describes overlay hash invalidation, no extra C++ resource owner. New patch prose “so a caller may safely clean up OpenSSL after quiescence” depends on all other crypto-thread/engine ownership obligations; Gate 3 should preserve that conditional boundary.

No tests run, no source edits, no Gate 3 approval, no self-adjudicated manual-cleanup exception.

FIX-DIFF UPDATE: root revised 00017 after inventory. Entries 4–5 now use callback-local unique_ptr<ThreadState> worker, then noncopyable ScopedOpenSslThreadState crypto_state; reverse destruction releases OpenSSL state before worker counter retirement, normal return and ordinary C++ unwind. Acquisition remains upstream raw new ThreadState passed into callback and adopted immediately there. Original manual OPENSSL cleanup concern is removed by RAII shape, not by an exception. Updated comments distinguish count retirement from detached pthread/FLS teardown. Not a Gate 3 verdict.

===== END DURABLE COPY resource-inventory.txt =====


===== BEGIN DURABLE COPY gate8-routing.txt =====
Gate8 round3 fix routing — 2026-11-11
Read all FOUR current tables fully, row by row in this pass: routed-concerns.md lines1-57, access-control1-24, security-posture1-27, software-estate1-24. No truncation in these rereads. Canonical Gate3 matrix and Gate8 lines1436-1483 reread. This is actual fix-domain rerouting, not reuse of original roster.
Fix scope provided by orchestrator and inspected current files: ports/grpc/00017 (new unique_ptr + noncopyable scoped OpenSSL guard, then exact-source patch-context correction); scripts/ci/vcpkg-triplet-sentinel.sh and test-vcpkg-sentinel.sh interpreter fallback; docs/ci-architecture.md matching interpreter instructions; tests/meson.build durations. Current durations line confirmed args: ['--durations=yes']. No claim that full original diff is the fix diff.

Required reruns:
Gate2 security-guardian ALWAYS; docs-writer for CI doc and in-code prose.
Gate3 cpp-expert + cpp-safety: C++ embedded in dependency patch still C++, ownership/cleanup order/failure unwind. quality-engineer: shell regression and Meson test registration. build-ci: patch application, cache sentinel identity and installed-prefix preservation, Meson. cross-platform: native Windows interpreter fallback plus patched C++ across Windows/macOS/Linux. release-deploy: dependency overlay is consumed by all five production/build image recipes; no Dockerfile fix hunk, but changed dependency application affects release domain. This last selection is conservative Gate8 DOMAIN routing, not a claim of literal new Dockerfile edit.
Gate4 happy-path/unhappy-path: changed cleanup/error-path/interpreter logic; consistency-auditor: doc/script and build/patch/platform contract parity.
Gate5 re-evaluate chaos disposition and rerun relevant worker-unwind / failed-interpreter preservation cases against corrected artifact; no automatic exemption because original scenarios passed on older patch.
Gate6 sre: thread lifecycle and shutdown. compliance-officer: changed closure evidence/failure-mode proof; enterprise-readiness: corrected Windows readiness/CI instructions and deliverability. Retain normal-exit coverage-guard versus actual instrumentation distinction.
Gate1 update Resource Ledger entries4-5 from raw ownership/manual call to scoped owners; exact patch identity/provenance in validation evidence. Gate7 consolidate corrected statuses and any remaining validation. Gate8 only closes when required rerun conclusions and evidence are actually recorded.

No NEW compulsory architect/authdb/gateway-erlang/plugin-developer/dsl/performance review from this fix: no first-party server path/header/interface/schema, gateway/Erlang, plugin/YAML, scope/CEL, SQL/hot-authz change. Original required domain reviews remain required and are not canceled. Architect can conservatively recheck dependency ownership boundary, but direct matrix triggers not newly matched. Auth/crypto row below selects security due OpenSSL lifetime; no token/auth production behavior changed in fix. No new API surface triggers ADR1005.

Row-by-row disposition (line numbers identify complete reread rows; snippets are labels only):
routed-concerns.md:16 Executions-history ladder — `command_id → execution_id` correlation, the SSE `ExecutionEventBus`, and the dura — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:17 Compliance evaluation pipeline — `PolicyEvaluator` background thread (10s tick, 15s grace, ≥60s floor, 3600s d — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:18 `/auto` Pre-flight readiness — operator go/no-go checks across a device cohort before a fleet change. Born-on- — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:19 `/auto` Deploy (the ACT stage after pre-flight ASSESS) — stage + execute an installer on a pre-flight run's go — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:20 **Artifact signature verification — one detached-CMS chokepoint (#416/#3807).** `detached_signature.cpp` is th — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:21 C++23 conventions, naming, headers, plugin ABI boundary — MATCH: cpp-expert; embedded patch C++ source; cpp-conventions.
routed-concerns.md:22 C++ resource ownership and lifetime — fd/HANDLE/SOCKET/`FILE*`/SQLite/OpenSSL/BCrypt/C-string/thread/callback/ — MATCH: cpp-safety + security ownership proof; cpp-conventions (no ObjC addition).
routed-concerns.md:23 macOS workflow + Darwin pitfalls table — MATCH: cross-platform; shared patched worker affects Darwin; darwin-compat.
routed-concerns.md:24 Prometheus metrics, label set, audit envelope, event format, and the SHIPPED ALERT RULES — an alert-rule-only  — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:25 Response data types, audit envelope, inventory data for analytics — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:26 User manual / YAML defs / REST API / Substrate primitive registration — MATCH: docs-writer always and CI doc/in-code prose changed.
routed-concerns.md:27 Guardian / Guaranteed State — real-time agent-side policy enforcement (guard categories, YAML DSL, `__guard__` — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:28 Spark detection layer (ADR-0021) — `SparkEngine` is the agent's sole detection primitive (watchers multiplexed — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:29 Echo dashboard — frames, URLs, permissions. New source: CORE pattern (`docs/echo-implementer.md` §8), NOT the  — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:30 Device quarantine / containment — `QuarantineStore` (Postgres, ADR-0047) + the #881 dispatch gate (`make_conta — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:31 Scope walking — composable scope from previous query results (product differentiator). Result-set primitive, ` — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:32 System architecture — cross-cutting design reference (Operator/Server/Agent/Gateway, REST/MCP/dashboard surfac — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:33 Tag/scope DSL operator reference — `tag:X`, `props.X`, `ostype`, `hostname`, `arch`, `agent_version` resolutio — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:34 Agentic-first invariants A1–A5 — applies to every new MCP tool, REST route, dashboard fragment, or error site  — STANDING MATCH: consistency every PR; no new tool/route/error contract.
routed-concerns.md:35 Enterprise-platform parity matrix — competitor capability comparison and gap analysis (complements `docs/capab — STANDING MATCH: enterprise-readiness Gate6; no capability-map edit.
routed-concerns.md:36 CI cache patterns — split `actions/cache/restore` + paired `actions/cache/save` for GHA-hosted; local `runner. — MATCH: build-ci; sentinel installed-prefix coherence; ci-cache skill.
routed-concerns.md:37 Fleet visualization (3D) — REST surface, page-shell, renderer, and process-layer invariants for the 11-PR `fea — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:38 Network quality dashboard (`/network`) — MEASUREMENT-FIRST device/local-link health lens (interval retransmit  — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:39 Device pages (`/devices` + `/device?id=`) — SHARED device surface: Device info / DEX / Guardian lens tabs + "G — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:40 OS capability matrix — per-capability × per-OS snapshot of what the agent collects/enforces, each row citing i — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:41 Agent daily-sync framework + installed-software inventory (ADR-0016) — agent pushes per-source state daily ove — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:42 SQLite `sqlite3_changes()` after `step()` on a shared FULLMUTEX connection is a data race + correctness bug (r — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:43 **Clock-guarded retention** — any bulk delete whose cutoff comes from a wall clock (`now - window`) must be gu — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:44 **Server storage substrate — PostgreSQL**; agent stays SQLite (`agent.db` + federated edge warehouse). Server  — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:45 `common/include/` shared-header firewall between `server/core` and `agents/` (#2549) — pure decision code only — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:46 **Durable agent command idempotency (HA WS-0, ADR-2002)** — `CommandDedupStore` (`command_dedup.db`, agent SQL — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:47 **Agent OTA pull bounds (#913/#911)** — the per-peer admission gate on `DownloadUpdate` and its transfer watch — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:48 **Confined filesystem deletion — `confined_fs` (agent-core)** — the handle-relative primitive behind operator- — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:49 Unit-test conventions — shared helpers and fixtures: `unique_temp_path`/`TempDbFile`/`TempDir` (`yuzu_test_` u — NO literal tests/unit fix; quality-engineer nonetheless REQUIRED by tests/Meson matrix and fixes; unit-test-conventions applies registration duration.
routed-concerns.md:50 **Echo cursor sources** — sources whose durable state is an `echo_cursor` row, not a snapshot-diff baseline. * — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:51 **power_health `set_power_plan`** — the plugin surface's only destructive power action (`PowerManagement` secu — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:52 **`app_usage` agent plugin + ADR-0016 daily-sync source — machine-scope usage evidence.** Reads Echo's `usage` — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:53 **`execution_artifacts` plugin — Windows execution-evidence reads (ShimCache/AmCache/Prefetch).** Three read-o — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:54 app-usage server read surface — `GET /api/v1/forensics/agents/{id}/app-usage` + MCP `get_agent_app_usage`: `Fo — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:55 `windows_optional_features` plugin — Windows-only DISM read (`Inventory`, read-only, no enable/disable), via a — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:56 `peripherals` plugin — read-only USB/PCI/Thunderbolt inventory (`Inventory` securable, no mutation, no subproc — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns.md:57 `printing` plugin — read-only queue/job inventory (`Inventory`; `jobs.document` = user content) plus the ONE m — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:5 Authentication, RBAC, headers, tokens, self-target principal-destruction guard (#397/#403). Every new list/fan — MATCH: security-guardian on crypto cleanup lifetime; not a new auth/RBAC/token behavior change.
routed-concerns-access-control.md:6 **Dispatch-caller approval provenance — `ExecuteGate` at the shared dispatch chokepoint (#1398).** Every dispa — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:7 **Service-scoped API token confinement — durable default-deny (guardian-confinement-2298 PR 3, "the flip")** — — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:8 PKI / internal CA — `ca_store` (`CaStore`, Postgres schema, ADR-0053; migrated off SQLite `ca.db`) holds cert  — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:9 AuthDB invariants — Postgres schema `auth` (ADR-0006; SQLite `auth.db` retired), fail-closed construction, `Se — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:10 **SCIM ↔ OIDC/SAML identity-link revoke chokepoint (ADR-2001, CC6.8)** — deprovisioning must sever every linke — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:11 Periodic Access Reviews (SOC 2 CC6.2): fleet-wide grant export + attestation-campaign lifecycle across all thr — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:12 Enterprise A&A roadmap — RBAC, OIDC, SAML, SCIM, MFA, AD/Entra, API tokens, session lifecycle, audit — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:13 MCP server architecture, tier-before-RBAC ordering, kill switches, audit pattern; Streamable HTTP transport (s — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:14 Per-device dispatch visibility (#1788) + the registry-independent authz model (ADR-0033 §2). CATASTROPHIC: (1) — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:15 **Dispatch targeting — omitted means the fleet, EXCEPT for a `Destructive`-classified pair.** **CATASTROPHIC-I — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:16 **Dispatch zero-reach cause discrimination: ONE shared classifier, FIVE hand-copied legacy cascades that diffe — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:17 Agent privilege model — dedicated `_yuzu` / `yuzu` / `NT SERVICE\YuzuAgent` account, narrow sudo NOPASSWD + LS — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:18 **Headless platform, process decomposition & access-control spine (ADR-1005 + ADR-0031/0032/0033)** — ADR-1005 — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:19 **Authorization-topology floor (#2376)** — `authz_topology_floor.hpp`'s `kTopologyFloor` is the SINGLE chokepo — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:20 **Pre-auth request-body cap (#2407)** - `body_cap_policy.hpp`'s `kBodyCapTable` is the SINGLE chokepoint; EXTE — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:21 **MFA step-up chokepoint**: `kStepUpPolicy` (`step_up_policy.hpp`) is the SINGLE table of mutating routes need — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:22 **Fenced leader election — `LeaderElector` + the singleton-loop gate (WS-3, ADR-2002 §3/§6/§10).** A COORDINAT — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:23 **Split merge-gate — ADR-0032 sequencing interlock (WS-0).** No engine-path code (admits a run / mints a grant — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-access-control.md:24 **A2/A1 RBAC administration surface — `is_rbac_administrator()` (`rbac_admin_predicate.hpp`) + the closed assi — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:17 `app_control` plugin — read-only Windows WDAC/AppLocker posture (`Security`, ExecuteGate::None): registry read — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:18 `firmware_posture` plugin — read-only firmware/BIOS vendor, version, update-pending posture (`Security`, Execu — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:19 `platform_security` plugin — read-only Secure Boot / code-signing posture (`Security:Read`, both actions `Read — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:20 `local_security_policy` plugin — read-only password/lockout/audit policy posture and sudoers content (`Securit — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:21 `system_hardening` plugin — read-only exploit-mitigation/kernel-hardening posture (`Security`, ExecuteGate::No — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:22 **Gateway-upstream peer authorization.** `GatewayPeerGuardedService` is the SOLE production registration of th — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:23 **Gateway origin trust — what address the gateway reports for an agent (`gateway_observed_peer`, audit `source — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:24 **Gateway mgmt-plane peer authorization (#1422, #6016).** `yuzu_gw_authz:check_mgmt_peer/1`, the :50063 `auth_ — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:25 `registry` writes (`set_value`, `delete_value`, `delete_key`). **CATASTROPHIC-IF-VIOLATED:** (1) Mutate only a — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:26 `registry` writes (`set_value`, `delete_value`, `delete_key`, `set_user_value`, `delete_user_value`, `apply`). — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-security-posture.md:27 **Same-site gate for cookie-session writes: ONE pre-routing chokepoint.** `apply_same_site_write_gate` (`same_ — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-software-estate.md:17 **`browser_inventory` plugin (Forensics, default-off, per-user browser data)** — reads per-user Chromium-famil — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-software-estate.md:18 **`privacy_permissions` plugin (Forensics, default-off, per-app sensitive-permission grants — camera/microphon — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-software-estate.md:19 **`runtimes` plugin — read-only installed .NET/JVM/Python runtime inventory (`Inventory`, no subprocess; machi — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-software-estate.md:20 **`middleware` plugin: read-only installed-middleware inventory (`Inventory`, table-driven; IBM MQ on Linux as — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-software-estate.md:21 **`remote_access_audit` plugin (Forensics, default-off, per-account SSH key data)** — reads `/etc/ssh/sshd_con — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-software-estate.md:22 **Forensics tier on stored-response reads (#4990)**: rows written by plugins on the `Forensics` securable are  — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-software-estate.md:23 **`certificate_inventory` daily-sync source and `CertificateInventoryStore` (schema `certificate_inventory_sto — NO MATCH: no named surface or semantic contract changed in fix.
routed-concerns-software-estate.md:24 **Software title normalisation layer** — `SoftwareTitleDimension` (the ADR-0012 §3 cross-store owner), the hou — NO MATCH: no named surface or semantic contract changed in fix.

Gate8 additional fix scope: NOTICE and ports/LICENSE-vcpkg.txt. Assessed against the full four-table reread above: User-manual/docs standing row MATCH (docs-writer); CI-cache row indirect build-ci contract because entire ports tree is copied/hashed; enterprise-parity standing Gate6 still applies. No access-control/security-posture/software-estate path or semantic row newly matched. Gate2 security always plus docs; Gate3 build-ci/release-deploy on dependency source packaging and QA attribution checks as relevant; Gate4 consistency on attribution-to-import boundary; Gate6 compliance MUST rerun (license/evidence) and enterprise docs/readiness. No new C++/gateway/runtime/retention surface from these two files; existing mandatory reruns remain. This is an additional fix-domain assessment, not a reason to repeat unrelated binary tests.

Final metadata-only fixes ledger-audit001–003 reroute to compliance evidence, docs wording, consistency provenance and orchestrator synthesis. No runtime code/interface/thread/platform semantic change; no new C++/gateway/build rerun triggered by metadata alone. resource_ledger final audit verifies fixes. Current ninefinding/eightfixed+one linked view and Windows40+4focused results appended synthesis; Linux sanitizer campaign remains pending.

===== END DURABLE COPY gate8-routing.txt =====


===== BEGIN DURABLE COPY gate8-source-closure.txt =====
Gate8 source closure, not final runtime closure — 2026-11-11
Scope all fixes: RAII worker ownership, exact-source patch context, executable Python fallback+regression+CI docs, Meson duration option, MIT license+NOTICE.
Rerouting allfour full tables recorded gate8-routing.txt. Source verdict evidence is in security/docs final addenda, cpp-expert/cpp-safety/QA source-coverage-addendum, build-ci/cross-platform/release addenda, Gate4three reports, SRE, compliance and enterprise. No new introduced source defect remains identified. Root owns ensuring all required Gate8 attestations refer to final artifact hashes and recording terminal ledger dispositions; this file does not rewrite pending initial ledger rows.
Original findings preserved: resource-ledger001 and root-build001 source-corrected but empirical campaign still required; docs-writer001 fixed by current source and38/0 regression; quality-engineer001 fixed source flag; compliance-officer001 closed exact notice; enterprise-readiness001 pre-existing INFO revisit debt pending explicit root disposition. No waiver self-adjudicated. Gate5 conditional skip recorded separately. Final all-platform/runtime decision withheld until root incorporates fresh campaign results, not inferred from source coverage or narrow callback checks.

Routing synthesis/evidence addendum (not re-adjudication):

FINAL METADATA / WINDOWS EVIDENCE UPDATE — 2026-11-11
Supersedes earlier six-finding count and open-disposition summary, not the historical report bytes. Final resource_ledger audit addendum verifies canonical field-wise live view: NINE findings = EIGHT fixed + enterprise-readiness001 linked-to-#2990. The three additional metadata findings below remain distinct PROVISIONAL groups (same ledger file but different defects). All original policy floors and caused_by links remain; native labels/derived severity are not re-adjudicated. independently1 per discovery chain, later confirmations echoes.

| Additional provisional ID | Defect | Derived band / native | Floor | Verified disposition |
|---|---|---|---|---|
| ledger-audit-001 | Missing precise fix source-address citations | INFO (I9/E3), native null, mapped NICE | None | FIXED: appended current patch35/45 and16/29 citations |
| ledger-audit-002 | QA prose could imply independent reporter despite same sequential reviewer | INFO (I9/E3), native null, mapped NICE | None | FIXED: source-rereview wording and final ledger18 citation |
| ledger-audit-003 | Root-observed build milestones lacked retained evidence addresses | INFO (I9/E3), native null, mapped NICE | None | FIXED: observer/scope/log hashes in milestone manifest; auditor verified all3 |

The original five introduced findings are fixed; overdue A5 metadata is linked-to-#2990, not silently renewed and not proof its underlying runtime gap is fixed. Original appendices retain earlier pending statements as history; final audit appendixed below supplies exact closure evidence/provenance.

Fresh Windows ROOT-EXECUTED focused validation complete: inspected build-windows-results.json and build-windows-debug-results.json, each normal10exit0 plus normal-exit coverage-guard10exit0, each mode invalidCLI exit1. Total40passing runner launches +4expected CLI failures, across native MSVC release/debug. release-proof.json records exact_match_to_current_patch=true, worker SHA2561634089138200ff4103c7a472397e67fca798328c19e02e24b477812567fd421, grpc1.81.1port1/OpenSSL3.6.5port2/Catch2 3.16.0 installed. Root owns execution/source artifact provenance; this reviewer inspected retained results, did not rerun. This is fresh dependency + shared runner validation, NOT fullWindowsproject suite, coverage instrumentation, or a wholemacOSdependency build. Root reports remote lock RELEASED.
LinuxASan+UBSan dependency build is still pending (root milestone1600/1918); full application/sanitizer tests remain pending. No overall governance/runtimePASS. Metadata/evidence source closure requires no reread/rebuild of unchanged source; source fixes and collective coverage stay closed, runtime campaign stays separate.

===== END DURABLE COPY gate8-source-closure.txt =====


===== BEGIN DURABLE COPY source-coverage-addendum.txt =====
Incremental full-source coverage addendum — 2026-11-11
Reviewer: resource_ledger, sequential QA/C++/docs roles, not independent opinions.

COMPLETED full reads:
- tests/unit/server/test_api_token_store.cpp: all 6480 lines, bounded contiguous chunks (1512–1610 read in prior role and all remaining intervals now read). Includes migrations, auth CRUD/IDOR, cache invalidation, semaphore races, engine and human rotations, group concurrency, clock guard, SQL fault/COMMIT failures, proof-of-possession, restart and stale-linkage cases.
- tests/test_instructions_runner_hardening.py: all 2741 lines, chunks 1–400,401–800,801–1200,1201–1600,1601–2000,2001–2400,2401–2741. Initial oversized/truncated read was replaced by these bounded full reads.
- tests/test_mcp_http_adapter_behaviour.py: all 583 lines, chunks 1–280 and281–583.
- docs/build-guide.md: all 162 lines.
Source echoes: `p.stdin = None`; `before_send=finish_execute`; `CHECK(confirm.error() == refused.error());`.

No introduced security/QA defect found from these completed full-file reads beyond existing recorded IDs. New FakeYuzu completion callback decrements once before response publication, including failure via finally; the delayed-return test widens the old overcount window. This observes serial client requests without counting a finished response's handler unwind as in-flight work. New adapter assignment removes only communicate's attempt to flush already-closed stdin; EOF already sent, stdout/stderr still drained and timeout still kills/reaps the child.
Token new publication hook is synchronous and uses the real committed state; different operator denial, same operator uncached rejection, replay, epoch precedence and two-row state all asserted. Full-file context contains no changed ownership/auth path that defeats those assertions. Existing comments retain historical drift (e.g. old declarations saying human rotation is unimplemented); those predate this diff and are not proof of current absence. Existing stochastic concurrency tests are supplemental, not the sole closure evidence for the new deterministic case. PostgreSQL sabotage stays within isolated fixture databases. No changed production parser or authority surface exists in the Python edits.
Build guide's changed overlay/runner ownership paragraph matches source: secure workers clean their own OpenSSL state before retirement; server suite pins/drains default engine; agent runner remains unpinned for fork tests. Baseline bump cannot replace an overlay and content fingerprint invalidation is implemented.

QA closure: quality-engineer-001 FIXED, current tests/meson.build:80–82 includes args: ['--durations=yes']; verified by direct source read. No runtime timings inferred.

Patch evidence correction / root-build-001:
Root reported actual Windows vcpkg git apply rejecting malformed blank-line context introduced during RAII rewrite, caused_by resource-ledger-001. Introduced supported-platform build failure is a BLOCKING POLICY FLOOR independent of numeric severity. My earlier general patch-application claim was inadequate: patch utility acceptance/fuzz is not exact git apply acceptance. Do not cite that earlier check as vcpkg closure.
Root regenerated 00017 against exact grpc1.81.1 audit source. Independently ran git apply --check --verbose in fresh exact-gitapply-check directory containing grpc_thread_pool_181.cc and grpc-CMakeLists-181.txt; exit0 and both hunks checked without offsets/fuzz. Output exact-gitapply-check/result.txt. Root additionally reports successful real vcpkg application on Windows and Linux: source defect CLOSED, full build/runtime campaign still pending. No code semantic change to RAII destruction order was required.
Callback compiler attribution remains Homebrew Clang23.1.4 for my12variant checks. Root separately reports AppleClang21.0.0 /usr/bin/clang++12/12 in cpp-check/apple-validation.txt; neither proves a whole macOS dependency build.

Runtime ownership: root owns runtime validation. My attempted focused Python test failed before execution at loopback bind EPERM; ensuing approval call was aborted after929s, so NO local successful test claim. Root reports full instructions198tests/1skip PASS45.409s and MCPadapterOK; use root log provenance. No further runtime approvals requested by this reviewer.

REMAINING full-read coverage: docs/auth-architecture.md6019 lines and docs/ci-architecture.md3513 lines. Prior changed-section reviews remain valid, but do not yet represent exhaustive reads. This addendum supersedes the earlier residual token/Python/build-guide coverage limitation only.

Auth full-file closure: docs/auth-architecture.md all 6019 lines read, including all dense service-scope paragraphs re-read after output truncation. New rotation publication paragraph matches actual engine denial-only durable check, same-caller unexpired RAM re-serve requirement, epoch precedence, human owner precheck. No newly introduced contradiction found. This is review of changed contract in full-document context, not revalidation of every historical claim against untouched implementations. CI full-file read remains pending.

CI full-file closure: docs/ci-architecture.md lines 1–3513 are now fully read collectively. This reviewer read 1–800 and 2001–3513; routing explicitly reports complete literal 801–2000 reads in six untruncated 200-line chunks. No newly introduced contradiction found. Overlay hashing/fallback claims match the corrected implementation; durations preserve evidence summaries; concurrency widths and healthcheck contracts are unchanged. This supersedes the earlier pending CI note. Full source/doc coverage requested by root is complete; it is not empirical revalidation of every untouched historical claim. Runtime campaign status remains separate and pending root evidence.

===== END DURABLE COPY source-coverage-addendum.txt =====


===== BEGIN DURABLE COPY ci-doc-801-2000.txt =====
Delegated literal read coverage: docs/ci-architecture.md lines801–2000 complete, six bounded200-line chunks, no truncation. Sections: image healthcheck/dependency gates; pre-release detective QA and its measured limits; gateway pinned real-wire/peer boot/lexical checks; BigTam/WeeTam/BigMags topology and shared identity; Windows/Linux concurrency gates; test-phase partition, PGsmoke/full selection and historical timing/rebalance arithmetic. No new source/doc contradiction introduced by current shutdown/rotation/overlay diff identified. Current dual agent/server runtime label fits described platform suite selection; no concurrency widths/healthcheck tools/runner labels changed. Historical pre-release upgrade narrative is not a new authorization to bypass separate hard-cutover deployment contract. This reviewer did not re-read lines1–800 or2001–end in this delegation; resource_ledger owns those spans.

===== END DURABLE COPY ci-doc-801-2000.txt =====


===== BEGIN DURABLE COPY final-ledger-source-audit.txt =====
Final ledger/source consistency audit — 2026-11-11
Read-only audit by resource_ledger; no runtime tests, network operations, source edits, waiver adjudication or severity changes.

Inputs: live governance.d/20261110-nightly-integration.724d95.jsonl; canonical governance merge/disposition/fix-evidence rules; role reports and source-coverage-addendum; retained original/round2/round3/round4 snapshots; current 00017 source; issue-2990-readonly.json. Distinctive source echo: "Quiesce observes that retirement, not detached pthread/FLS teardown."

Counting rule: findings are FIELD-WISE last-write-wins by recorded_at, ties pass_ordinal; list fields replace rather than union; the five attestation fields remain row-scoped. Reading only the last row would incorrectly discard original floors. Applying the canonical rule yields SIX live findings: resource-ledger-001, docs-writer-001, quality-engineer-001, root-build-001, compliance-officer-001 FIXED; enterprise-readiness-001 linked-to-#2990. All original floors remain in the live view. No unresolved row survives; no severity/floor de-escalation, refutation, self-waiver or fabricated exception appears. independent_reporters remains 1 throughout, consistent with sequential role reviews.

Source/fact consistency:
- Resource floor correction uses unique_ptr at patch:35 and ScopedOpenSslThreadState at :41–46; reverse destruction releases crypto state before worker retirement. No impossibility exception needed or granted. Fix does not prove native OS-thread join or cover arbitrary custom engines.
- Python fallback facts, I5/I8 + E4/E6 and independent policy floor match docs-writer original/follow-up and 38-check evidence. The floor is not lost merely because operational band maps NICE.
- Timing omission I8/E6, no floor, matches QA and explicit source closure at tests/meson.build:80–82. No timings are inferred from source.
- Malformed patch-context failure retains caused_by resource-ledger-001. Exact git-apply evidence supersedes inadequate permissive patch/fuzz evidence; it is not rewritten as if the first check had been sufficient.
- License original omission, exact-byte remedy and scoped attribution match compliance report. I9/E3 is retained without inventing a new legal-severity category or invariant floor.
- Stale A5 date is pre-existing metadata debt, not a newly severity-rated runtime gap. Linked row repeats impact and severity_mapped as required. Local issue evidence confirms #2990 open, updated 2026-11-09, needs-triage and no roadmap label. This is not a park or exception renewal. KEEPLOCAL explicitly overrides external comment; no unauthorized GitHub mutation was performed. Nothing here certifies the underlying fallback behavior fixed.

Snapshot verification: local SHA-256 reads exactly match ledger references:
patch.diff c5d2142fa6666c0c631095075744b0e94d1e6e089747cb4e39f645299649917a
round2-current.diff 3162a45c655724bcc1422efe2c9af21cf294f1e49a1a8b987a657ce6390d6325
round3-current.diff 5f109070b8fa4419a15ae713d6e4470ee1c12059f8beba059e52b26217433064
round4-source.patch 3b36bd287e1238f3bcdaf708fa77280a46cffe007fb150132371a95834c0357a
These identify review snapshots, not immutable commits of the current worktree or complete build inputs. Source manifest/campaign provenance remains root-owned.

Record-quality corrections requested to root (sparse append, never rewrite):
1. resource-ledger-001/root-build-001 fixed rows should explicitly cite fix file:line (canonical skill:1666), rather than only an implementation name plus working-diff hash. Suggested patch:35 and patch:16/:29 respectively. This is evidence-address normalization, not a new runtime defect or de-escalation.
2. quality-engineer-001 says "independently confirms" while the addendum explicitly identifies the same sequential reviewer. independent_reporters=1 is correct; clarify summary to "source rereview confirms" so readers do not infer another independent opinion.
3. Later Windows debug dependency and Linux host debug/release completion claims are root-reported; local STATE.txt still describes earlier in-progress work and initial domain reports do not carry those later observations. Root should cite retained command/log provenance for those specific milestones. This auditor has not independently observed those builds. This does not contradict root's newer observations or reopen proven source corrections.

Evidence limits: source fixes and local callback/macro/exact-apply checks do not imply fresh full runtime/sanitizer/application campaign success. Terminal ledger rows explicitly preserve that pending campaign; so do role reports. Clang provenance remains Homebrew Clang23 for reviewer's harness, Apple Clang21 for root's separate harness; neither is a whole macOS dependency build. Original pending coverage notes are superseded by explicit final coverage addenda, not silently erased.

Result: canonical live disposition/fact/provenance view is consistent, with the above small evidence-citation/independence-phrasing amendments requested. No new operational finding, severity reduction, self-waiver or overall governance PASS. Fresh runtime evidence remains pending. Root owns any ledger append and final decision.

FINAL CORRECTION VERIFICATION ADDENDUM — 2026-11-11
Read the appended ledger rows and build-milestones-20261111.json. Recomputed the same canonical field-wise live view: 22 physical rows, NINE live findings, EIGHT fixed and enterprise-readiness-001 linked-to-#2990. Three added ledger-audit observations carry I9/E3, NICE, native null and no floor; that preserves the original audit's absence of a native label and does not de-escalate another finding. Original rows remain present and floors/caused_by provenance survive.

All three requested record corrections are now verified CLOSED:
- ledger-audit-001: ledger lines 16–17 explicitly name current patch:35/:45 RAII ownership and :16/:29 exact upstream hunks. These are actual current source lines.
- ledger-audit-002: line 18 identifies tests/meson.build:81 and explicitly says same sequential reviewer, not additional independent reporter. Its first closure's adjacent-row citation is corrected by the final appended row, without rewriting history.
- ledger-audit-003: root milestone manifest names observer, scope, raw log paths and hashes, distinguishing host code-generation dependency from instrumented target and application/runtime validation. All THREE retained log SHA-256 values match the manifest exactly. Reading Linux log lines 52–90 confirms host debug/release processing completed before the ASan target starts. Windows retained debug log ends in debug package installation. The broader Windows progress log also contains later runner results; this addendum does not turn those into independently executed runtime validation or expand the scoped milestone claim. Root owns that runtime campaign and interpretation.

The earlier requested citation/provenance/independence-wording amendments are satisfied. Source-ledger consistency audit is complete with no remaining correction requested. This is a source/evidence-address audit only: it does not declare full runtime, sanitizer, platform or governance PASS, adjudicate an exception, or renew #2990.

===== END DURABLE COPY final-ledger-source-audit.txt =====


===== BEGIN DURABLE COPY gate5-disposition.txt =====
Gate5 SKIPPED by root orchestrator: unhappy-path and consistency-auditor Gate4 reports contain no new findings. Their scenario suggestions are validation coverage guidance, not new speculative defects. Existing scenarios are covered by root repetitions/mock ordering checks and final artifact validation. This follows workflow-orchestrator conditional skip rule; no chaos PASS claim. Gate8 rerouting re-evaluated disposition and retains this skip while Gate4 remains finding-free.

===== END DURABLE COPY gate5-disposition.txt =====


===== BEGIN DURABLE COPY build-milestones-20261111.json =====
{
  "observed_at": "2026-11-11T05:00:54.372387+00:00",
  "observer": "root",
  "not_independent_reviewer_execution": true,
  "windows_debug": {
    "status": "dependency debug compile/install stage completed; release stage began",
    "logs": [
      "windows/grpc-debug-passed.log",
      "windows/build-short-path-progress.log"
    ],
    "scope": "fresh grpc1.81.1#1 overlay, MSVC; not application/runtime validation"
  },
  "linux_host": {
    "status": "host x64-linux grpc debug+release completed; ASan-target compile began",
    "log": "validation/deps-asan-progress.log",
    "lines": "52-90 host build/install;91+ ASan target",
    "scope": "uninstrumented code-generation host dependency only"
  },
  "runtime": "PENDING",
  "sha256": {
    "windows/grpc-debug-passed.log": "a5c9bf1e6623ad0aec3d7d9091490a00979cbcf1a80886c021673980b296ac76",
    "windows/build-short-path-progress.log": "f5af3b9568d0d6d8349b0faa1856b798071a85c2938991ddaf52db4fe8a770b4",
    "validation/deps-asan-progress.log": "643ac051e48f465c5fbb7f6fa9ba2e45894d10c284e10b0d29b605080aaee6a8"
  }
}

===== END DURABLE COPY build-milestones-20261111.json =====


===== BEGIN DURABLE COPY windows/build-windows-results.json =====
{
  "normal": {
    "exit_codes": {
      "0": 10
    },
    "invalid_cli_exit": 1
  },
  "coverage": {
    "exit_codes": {
      "0": 10
    },
    "invalid_cli_exit": 1
  }
}
===== END DURABLE COPY windows/build-windows-results.json =====


===== BEGIN DURABLE COPY windows/build-windows-debug-results.json =====
{
  "normal": {
    "exit_codes": {
      "0": 10
    },
    "invalid_cli_exit": 1
  },
  "coverage": {
    "exit_codes": {
      "0": 10
    },
    "invalid_cli_exit": 1
  }
}
===== END DURABLE COPY windows/build-windows-debug-results.json =====


===== BEGIN DURABLE COPY windows/release-proof.json =====
{
  "worker_sha256": "1634089138200ff4103c7a472397e67fca798328c19e02e24b477812567fd421",
  "exact_match_to_current_patch": true,
  "versions": [
    {
      "Package": "catch2",
      "Version": "3.16.0",
      "Depends": "vcpkg-cmake, vcpkg-cmake-config",
      "Architecture": "x64-windows",
      "Multi-Arch": "same",
      "Abi": "5b58a2a3bb356d32c11bfcece54c9e2c61e284517e2e44c4495dd82bb0b31974",
      "Description": "A modern, C++-native, test framework for unit-tests, TDD and BDD.",
      "Status": "install ok installed"
    },
    {
      "Package": "openssl",
      "Version": "3.6.5",
      "Port-Version": "2",
      "Depends": "vcpkg-cmake, vcpkg-cmake-config, vcpkg-cmake-get-vars",
      "Architecture": "x64-windows",
      "Multi-Arch": "same",
      "Abi": "ecd7576721607172e717a0789a23718802a278d1d49eec949c8fc4ed9b26c1ed",
      "Description": "OpenSSL is an open source project that provides a robust, commercial-grade, and full-featured toolkit for the Transport Layer Security (TLS) and Secure Sockets Layer (SSL) protocols. It is also a general-purpose cryptography library.",
      "Status": "install ok installed"
    },
    {
      "Package": "grpc",
      "Version": "1.81.1",
      "Port-Version": "1",
      "Depends": "abseil, c-ares, openssl, protobuf, re2, utf8-range, vcpkg-cmake, vcpkg-cmake-config, zlib",
      "Architecture": "x64-windows",
      "Multi-Arch": "same",
      "Abi": "8d5715897796f1ad8956c9cf1b659e78f4e9a99ab85c062e8438c03782b69967",
      "Description": "gRPC is a modern, open source, high-performance remote procedure call (RPC) framework that can run anywhere. gRPC enables client and server applications to communicate transparently, and simplifies the building of connected systems.",
      "Status": "install ok installed"
    }
  ],
  "release_results": {
    "normal": {
      "exit_codes": {
        "0": 10
      },
      "invalid_cli_exit": 1
    },
    "coverage": {
      "exit_codes": {
        "0": 10
      },
      "invalid_cli_exit": 1
    }
  },
  "scope": "MSVC release runner normal and ordinary-exit coverage guard; not coverage instrumentation or full project suite"
}

===== END DURABLE COPY windows/release-proof.json =====


## Pending root completion

Append fresh Linux dependency/application/sanitizer results, their exact source/artifact identity and durable log locations; reconcile any remaining platform/gateway campaign requirements; then record the final governance disposition. Until that update, this remains a draft with runtime pending.


## Final runtime closure audit

```text
Final evidence-to-source/governance closure audit — 2026-11-11
Reviewer resource_ledger, read-only local artifact inspection. No runtime tests, remote commands, network access or source changes. Runtime executions remain attributed to root/validation agent; this is a separate check of their retained evidence, not independent execution.

SOURCE IDENTITY VERIFIED: independently rehashed all 6293 current files described by source-manifest.json plus supplemental-license-manifest.json, excluding exactly the named append-only governance ledger. Zero mismatches. Computed sorted path+NUL+file-SHA256+LF content hash f0fbe60b63478455e5570021e583782b372e521298aae612e56f9d5c7b9f4779, identical to local/remote source-verification JSONs. Both records identify base f4c2c95aa77bfc573614bdb381a010fc2a15d366 and zero unmanifested files. This hash covers names/bytes, not file modes. Attribution supplemental files are included; no code/config exclusion is hidden behind the ledger exemption.

LINUX RESULTS VERIFIED: parsed actual newline-delimited Meson result streams without printing their environment objects. ASan:176 OK, zero failed flags, zero nonzero returncodes; tests-asan.exit=0. TSan:176 OK, zero failed flags, zero nonzero returncodes; tests-tsan.exit=0. No FAIL or SKIP result entries. Independently calculated observed wall intervals5626.46276140213s and5251.083094358444s, exactly matching summaries (not summed test durations, which overlap). Gateway summaries in each campaign show EUnit1269+1538 and Common Test61, all OK. These are executed counts, not empty-green gateway claims.

The retained run script configures ASan+UBSan with documented null/alignment exclusions, leak detection enabled and ODR detection disabled; TSan uses the repository's synchronous getaddrinfo shim. These are the tested configurations, not unrestricted sanitizer guarantees. Actual worker-object symbol artifacts for both installed libgrpc.a variants reference OPENSSL_thread_stop. Fresh dependency rebuild/artifact provenance is root/validation-owned and retained in the evidence bundle; host-only intermediate milestones are not confused with instrumented-target completion.

REPETITIONS: each sanitizer repeat log contains ten paired normal-exit successes. The exact repeat script uses set -euo pipefail and bounded timeout commands for [tls][handshake] then the dedicated runtime lifetime binary; a pair marker appears only after both return0. Thus10TLS+10lifetime successful launches per sanitizer,40 total. Unlike the earlier stand-in callback harness, this exercises the real shared runner/dependencies and ordinary process cleanup. It remains empirical finite-run evidence, not proof against every possible scheduler history.

GATEWAY/DIALYZER: retained dialyzer log reaches analysis of52project files without a reported warning/error; bundle contains validation/COMPLETE with literal complete. run.sh uses set -e and writes COMPLETE only after rebar3 dialyzer returns successfully. Combined with both real gateway result sets, this supports the reported gateway closure. No new gateway invocation performed by this reviewer.

WINDOWS SCOPE: retained debug and release result JSONs each show normal10xexit0 and coverage-guard10xexit0, plus invalid CLI exit1 for each mode. Total40focused successful launches and4expected invalid-CLI exits. release-proof records exact patched worker match and fresh dependency versions. These are shared-runner focused tests under MSVC, NOT the full Windows project suite. YUZU_TEST_COVERAGE enables ordinary-exit behavior; it is not a claim of coverage instrumentation. macOS coverage remains separate AppleClang callback/macro checks, not a whole macOS dependency/application build. No unsupported full-Windows/full-macOS statement is justified.

BUNDLE: independently hashed evidence-bundle.tar.gz =>8d1ae56a0ce8c42cf62009b7dcdb733212ecd809c4184e672956fe7270ad4103;130archive entries. Matches evidence-bundle-summary and bundle-integrity. Integrity record reports129indexed entries and40raw repeat logs with all file hashes matching; validation agent owns its complete per-entry verification. Root owns final durable evidence placement; credentials in raw test environment objects must not be printed into review prose.

GOVERNANCE: previously verified canonical field-wise live ledger remains9findings,8fixed+enterprise-readiness-001 linked-to-#2990, floors and caused_by history retained. No severity reduction or self-waiver is needed. The stale A5 metadata debt remains an existing linked issue, not renewed or claimed fixed. Fresh runtime evidence now supplies the previously pending empirical part of the C++ lifetime/build fixes. Historical pending statements in appendices should remain history and be explicitly superseded by final dated closure, not silently rewritten as if earlier reviews had this evidence.

CONCLUSION: supplied evidence supports closure of the pending Linux sanitizer/gateway and focused Windows campaigns for the reviewed source bytes. No new source/evidence inconsistency found. Root must append runtime-closure rows and update final report from its intentionally pending draft before publishing a final governance verdict. This audit does not enlarge platform scope or claim SOC2 certification/operating effectiveness. No further source change is requested.
```


## Final Linux validation record

```text
Rocky current-dev integration validation — COMPLETE / PASS

Base: f4c2c95aa77bfc573614bdb381a010fc2a15d366
Local source: /private/tmp/yuzu-nightly-integration
Remote source: /home/nathan/yuzu-openssl-integration/src
Verified source file count: 6293
Content SHA256: f0fbe60b63478455e5570021e583782b372e521298aae612e56f9d5c7b9f4779
Source hash covers frozen source plus supplemental NOTICE/license metadata.
Only excluded file is governance.d/20261110-nightly-integration.724d95.jsonl,
an append-only evidence ledger updated after the source freeze. Its frozen and
observed hashes remain recorded. All other covered file bytes/names match exactly.

Full configured Meson runs, each one clean invocation:
ASan+UBSan: 176 OK, 0 FAIL, 0 SKIP; 5626.46s (93m46s).
TSan:       176 OK, 0 FAIL, 0 SKIP; 5251.08s (87m31s).
Each includes 14 PG server shards, 4 non-PG server shards, agent/echo/runtime,
gateway and supporting checks. No sanitizer error markers in compiled outputs.
Each run executed EUnit shard A 1269 cases and shard B 1538 cases; CT 61 cases.
Gateway CT: ASan 138.89s; TSan 141.90s. Full dialyzer passed, 52 project files
and 563 PLT files under OTP 28.4.2; only the documented benign gpb plugin notice.

Fresh dependency overlay:
All 8 patches applied sequentially with git apply --check then git apply to the
exact upstream gRPC 1.81.1 archive. Both instrumented gRPC triplets rebuilt against
the final scoped RAII cleanup patch; gRPC 1.81.1#1, OpenSSL 3.6.5#2.
Installed secure worker objects reference OPENSSL_thread_stop in both triplets.
ASan full build passed 726 incremental steps. TSan scoped C++ build passed 600
steps, then the remaining full build passed 126 steps, including gateway.
Final vcpkg dry-runs for both triplets planned no rebuild/removal after license
metadata additions. Prior source, Git metadata and dependency installs preserved.

Repeated normal-exit regression:
Per sanitizer: 10 TLS processes, each 13 cases / 206 assertions; 10 lifetime
processes, each 1 case / 5 assertions; all passed and exited normally. Both early
fresh lifetime smokes also passed. ASan leak detection remained enabled.
TSan retained the existing DNS shim and compiled libpq-only suppressions; no new
suppression or teardown bypass. Old-base negative-control evidence is preserved
separately and is not claimed as a newly repeated current-base control.

Evidence:
validation-manifest.json, asan-summary.json, tsan-summary.json, source proofs,
full result JSON/logs and all 40 raw repeat logs are retained. Final bundle:
evidence-bundle.tar.gz — 11085410 bytes, 130 entries
SHA256: 8d1ae56a0ce8c42cf62009b7dcdb733212ecd809c4184e672956fe7270ad4103
All archive per-file hashes verified locally. Credential/DSN environment values
are redacted in the bundle; original evidence remains in owned validation dirs.

Run DB: /private/tmp/yuzu-nightly-audit/integration-validation.db
Run ID: governance-f4c2c95aa-20261111
No commit, push or publication performed by this validation work. This record
certifies the Rocky Linux sanitizer runs; Windows/macOS evidence is separate.
```


## Final disposition checks

```text
{
  "physical_rows": 24,
  "live_findings": 9,
  "dispositions": {
    "resource-ledger-001": "fixed",
    "docs-writer-001": "fixed",
    "quality-engineer-001": "fixed",
    "root-build-001": "fixed",
    "compliance-officer-001": "fixed",
    "enterprise-readiness-001": "linked-to-#2990",
    "ledger-audit-001": "fixed",
    "ledger-audit-002": "fixed",
    "ledger-audit-003": "fixed"
  },
  "original_floors_preserved_and_fixed": true,
  "ledger_lint_exit": 0,
  "canonical_park_check_exit": 4,
  "decision": "PASS WITH DEFERRED",
  "deferred_issue": 2990
}
```
