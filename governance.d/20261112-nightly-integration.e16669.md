# Nightly integration: governance and validation rerun

Run `20261112-nightly-integration.e16669`, 2026-11-12. **Final decision: PASS WITH DEFERRED.** Both full sanitizer suites passed; the only linked item is the pre-existing, nonblocking #2990 exception-review metadata finding. Everything remains local: no commit, push, PR, deployment or external issue comment was made by this run.

## Reviewed identity

Base and merge-base: `ea21d7f019770a2d0e6075ad7d27c7e90438dcb7`, branch `fix/nightly-november-integration`, plus the staged, uncommitted fix. The reviewed 45-path patch SHA-256 is `f282726ecf5fab4617d45c9f9fa921b1854421742eddbe304bc882d687828f35`. Its bytes remained unchanged throughout review and execution. The subsequent additions are this report and its paired ledger, not runtime changes.

The 282-file upstream rebase delta was integration context, not newly authored work. Review explicitly considered current PostgreSQL transaction behavior, installed-software teardown, build/CI changes and ADR-0035's Linux-server/native-agent platform boundary. Previous `20261110-nightly-integration.724d95` artifacts certify the older f4c base only and remain preserved.

All nine governance currency inputs matched the freshly fetched `origin/dev` at the start. All four routed-concern tables were read and matched row by row. Collective source coverage used prior complete reads only where byte identity was proven, plus fresh current deltas and caller/integration context. Sequential role reviews and shared evidence are not independent cold convergence.

## Gate results

| Gate | Roles / result | Blocking | Linked findings |
|---|---|---:|---:|
| 0–1 | Currency, routing, change summary and resource ledger complete | 0 | 0 |
| 2 | Security guardian and docs writer: PASS | 0 | 0 |
| 3 | Architect, quality engineer, C++ expert, C++ safety, build/CI, cross-platform, gateway/Erlang, release/deploy: PASS | 0 | 0 |
| 4 | Happy path, unhappy path, consistency: PASS | 0 | 0 |
| 5 | SKIPPED under canonical conditional rule: neither unhappy path nor consistency produced findings | 0 | 0 |
| 6 | Compliance and SRE: PASS; enterprise readiness: one pre-existing INFO finding | 0 | 1 |
| 6b | Severity-preserving synthesis complete; raw reports appended verbatim below | 0 | 0 |
| 7 | Finding linked locally to existing issue; all required current runtime checks passed | 0 | 1 |
| 8 | Evidence-only security, docs, compliance, consistency, SRE, build/CI, quality, cross-platform and enterprise review: PASS | 0 | 0 |

Gate 5 is a conditional skip, not a claim that chaos testing passed. The sole current finding is `enterprise-readiness-001`: the A5 exception associated with #2990 still has a revisit date of 2026-10-31. Derived INFO, mapped NICE, native LOW; I9/E3, verified, pre-existing, no policy floor. The reviewer knew the historical finding, so there are zero new cold independent reporters.

The paired append-only ledger has two physical rows and one live finding, terminal `linked-to-#2990`. Read-only issue evidence shows OPEN, needs-triage, not roadmap. This disposition addresses overdue review metadata only: it neither renews the exception nor regrades the underlying streamed-final runtime gap. No new issue was filed and no comment was posted. There are no unresolved blocking findings, no waiver, and no new code fix from this review round. Canonical park probe returned exit 4; ledger lint returned exit 0.

## Current runtime results

| Check | Result | Scope |
|---|---|---|
| Linux ASan + UBSan | 179/179 OK; zero failures, skips or timeouts; 5,816.75 s | Full configured Meson suite on current source |
| Linux TSan | 179/179 OK; zero failures, skips or timeouts; 5,382.03 s | Full configured Meson suite on current source |
| Gateway EUnit | 1,269 + 1,538 cases passed in each sanitizer campaign | Nonzero executed-case proof retained |
| Gateway Common Test | 61 cases passed in each campaign | Both final suite entries passed |
| Gateway Dialyzer | PASS, exit 0 | 52 project files / 563 PLT files analyzed |
| Linux shutdown repetitions | 40 successful normal-exit processes | Each sanitizer: 10 TLS processes (13 cases / 206 assertions each), 10 runtime processes (1 case / 5 assertions each) |
| Windows MSVC focused integration | 40 successful processes plus 4 expected invalid-CLI exit-1 cases | Debug/release, normal/coverage-guard runner paths; matching patched dependency inputs |
| Apple/Homebrew Clang | 24 callback/macro variants passed | C++17/C++23, supported crypto guards, normal/unwind paths in a stand-in harness |
| Sentinel and change classifier | 38 and 54 checks passed | Fresh local targeted regression checks |
| Final dependency checks | PASS, no packages required rebuilding | Both sanitizer configurations; pipeline exit 0 |

Both full Linux builds passed. TSan's scoped C++ build overlapped ASan execution under the shared dependency-install lock, with a command-closure check excluding gateway builds; full TSan compilation and all runtime tests still ran. Test suites used three workers and timeout multiplier four:

```sh
meson test -C build-linux-asan --no-rebuild --timeout-multiplier 4 --num-processes 3 --logbase testlog-governance-ea21d7f01 --print-errorlogs
meson test -C build-linux-tsan --no-rebuild --timeout-multiplier 4 --num-processes 3 --logbase testlog-governance-ea21d7f01 --print-errorlogs
# After sourcing scripts/ensure-erlang.sh, in gateway/:
rebar3 dialyzer
```

Instrumentation limits remain explicit: ASan used `detect_leaks=1:halt_on_error=1:detect_odr_violation=0`; UBSan used `print_stacktrace=1:halt_on_error=1`, with existing compile exclusions `-fno-sanitize=null,alignment`. TSan used `halt_on_error=1:second_deadlock_stack=1`, the existing DNS synchronization shim, and existing libpq-only compiled suppressions. No new suppression or retry was introduced to obtain these passes.

Linux used GCC 15.2, Meson 1.12.1 and OTP 28.4.2. The gRPC 1.81.1#1 / OpenSSL 3.6.5#2 dependency outputs were reused after proving overlay, triplet and manifest inputs byte-identical to the prior patched rebuild. Current installs were no-ops, not fresh dependency rebuilds.

Windows evidence is focused shared-runner/dependency integration, not a full Windows product, installer or sanitizer campaign. Coverage-guard mode exercises normal-exit behavior, not instrumentation coverage. Clang evidence is a narrow callback harness, not a full macOS application build. Current ADR-0035 supports Linux server and native Windows/macOS agent builds. These limitations are not substituted for the full Linux results.

## Source and evidence integrity

Remote post-run verification passed all 6,325 frozen files with no mismatch. Aggregate SHA-256: `bf9554715a98e887a22a354363874303a2da5efb716689b8eda2cec1ef885cd4`. Definition: SHA-256 of sorted path + NUL + file SHA-256 + LF; file bytes and names, not a claim about filesystem modes. Frozen manifest SHA-256: `6c7bbd2f0fbf1a085ebe09ce9c402e684974bec38ff6e187c3d2da61ee49c817`.

Only this report and `governance.d/20261112-nightly-integration.e16669.jsonl` are named evidence exclusions, created after source freeze. Old governance artifacts remain among the verified files. Local verification after report creation passed with no mismatch or unmanifested source file; the final closure refresh records this report’s updated evidence hash. No code/configuration file is excluded.

The sanitized Linux bundle has 134 regular-file members, 11,387,874 bytes, archive SHA-256 `83f0ede3395f4f0a6f4a414cee83c34a15533ad3cbd9a4d74e5d84aab8dab865`. Local verification checked every member hash and safe path. Captured credential/DSN values were redacted; raw originals remain in the owned validation directory.

Local evidence root: `/private/tmp/yuzu-nightly-governance-ea21d7f01`. Bundle: `validation/evidence-bundle.tar.gz`; structured summaries, source proofs and member verification are alongside it. Focused Windows evidence is in `windows/remote`; compiler evidence in `cpp-check`. Linux runner evidence remains at `/home/nathan/yuzu-openssl-integration/governance-validation-ea21d7f01` on Rocky. Test database: `/private/tmp/yuzu-nightly-audit/integration-validation.db`, run `governance-ea21d7f01-20261112`, finalized PASS with 20 gates.

## Final evidence review

Evidence-only Gate 8 completed with no new findings. All four routed tables were re-opened and matched against the two new evidence paths. Security, documentation, compliance, consistency, SRE, build/CI, quality, cross-platform and enterprise evidence reviews passed. No C++ or production behavior changed, so a new runtime rebuild or behavior review was not triggered. No runtime source change has been made since the reviewed patch. Raw reports below contain their original interim pending statements; the completed runtime results above supersede those execution statuses without rewriting reviewer text. Likewise the initial proposed issue linkage is now recorded in the paired ledger.

The supplemental staged whitespace probe reports unified-patch context blank-line prefixes and an unchanged imported portfile trailing space. These bytes are retained intentionally; this is not a claim that the unfiltered whitespace probe was clean.

## Gate 8 evidence review appendices

### gate8-routing-security.txt

```text
Gate 8 evidence-only routing/security review — COMPLETE; PASS, no new finding
Scope ONLY governance.d/20261112-nightly-integration.e16669.jsonl and paired .md. Root confirms reviewed production/source patch remains SHA-256 f282726ecf5fab4617d45c9f9fa921b1854421742eddbe304bc882d687828f35. This is not a new production change review.
Canonical Gate8 lines1436–1460 read; all four current tables opened/read row by row (access-control targeted line15 recovered after output truncation). Decisions below apply to path/behavior triggers, not mentions of code within evidence prose.

Required: Gate2 security-guardian always; docs-writer for report prose. Gate6 compliance-officer for evidence changes. Consistency-auditor under every-PR row and ledger/report contract consistency. Enterprise-readiness for assurance/validation-scope truth; conservative build-ci, quality-engineer, cross-platform and SRE evidence checks on claimed build/test/platform/runtime outcomes (truth ownership, not a claim their production path predicates changed).
Not rerouted: cpp-expert/cpp-safety (no C++/ownership source change), architect (no schema/system design/API/ABI change), gateway-erlang (no Erlang/proto change), plugin-developer, DSL, performance, authdb. Happy/unhappy not rerouted: no new behavior/logic/error path; no new chaos trigger. Source security pass cannot substitute for final artifact verification.

Row-by-row inventory, all nonmatched unless marked:

routed-concerns.md
16: Executions-history ladder -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
17: Compliance evaluation pipeline -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
18: `/auto` Pre-flight readiness -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
19: `/auto` Deploy (the ACT stage after pre-flight ASSESS) -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
20: **Artifact signature verification -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
21: C++23 conventions, naming, headers, plugin ABI boundary -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
22: C++ resource ownership and lifetime -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
23: macOS workflow + Darwin pitfalls table -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
24: Prometheus metrics, label set, audit envelope, event format, and the SHIPPED ALERT RULES -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
25: Response data types, audit envelope, inventory data for analytics -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
26: User manual / YAML defs / REST API / Substrate primitive registration -> MATCH: docs-writer on every change.
27: Guardian / Guaranteed State -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
28: Spark detection layer (ADR-0021) -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
29: Echo dashboard -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
30: Device quarantine / containment -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
31: Scope walking -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
32: System architecture -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
33: Tag/scope DSL operator reference -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
34: Agentic-first invariants A1–A5 -> MATCH: consistency-auditor on every PR; no MCP/REST capability change.
35: Enterprise-platform parity matrix -> MATCH: enterprise-readiness Gate6 assurance context; no capability-map/roadmap edit.
36: CI cache patterns -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
37: Fleet visualization (3D) -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
38: Network quality dashboard (`/network`) -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
39: Device pages (`/devices` + `/device?id=`) -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
40: OS capability matrix -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
41: Agent daily-sync framework + installed-software inventory (ADR-0016) -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
42: SQLite `sqlite3_changes()` after `step()` on a shared FULLMUTEX connection is a data race + correctness bug (reads `db->nChange` without the per-… -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
43: **Clock-guarded retention** -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
44: **Server storage substrate -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
45: `common/include/` shared-header firewall between `server/core` and `agents/` (#2549) -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
46: **Durable agent command idempotency (HA WS-0, ADR-2002)** -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
47: **Agent OTA pull bounds (#913/#911)** -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
48: **Confined filesystem deletion -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
49: Unit-test conventions -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
50: **Echo cursor sources** -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
51: **power_health `set_power_plan`** -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
52: **`app_usage` agent plugin + ADR-0016 daily-sync source -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
53: **`execution_artifacts` plugin -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
54: app-usage server read surface -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
55: `windows_optional_features` plugin -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
56: `peripherals` plugin -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
57: `printing` plugin -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.

routed-concerns-access-control.md
5: Authentication, RBAC, headers, tokens, self-target principal-destruction guard (#397/#403). Every new list/fan-out read of per-agent data MUST us… -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
6: **Dispatch-caller approval provenance -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
7: **Service-scoped API token confinement -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
8: PKI / internal CA -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
9: AuthDB invariants -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
10: **SCIM ↔ OIDC/SAML identity-link revoke chokepoint (ADR-2001, CC6.8)** -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
11: Periodic Access Reviews (SOC 2 CC6.2): fleet-wide grant export + attestation-campaign lifecycle across all three RBAC principal types. CATASTROPH… -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
12: Enterprise A&A roadmap -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
13: MCP server architecture, tier-before-RBAC ordering, kill switches, audit pattern; Streamable HTTP transport (sessions, GET SSE, progress bridge) … -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
14: Per-device dispatch visibility (#1788) + the registry-independent authz model (ADR-0033 §2). CATASTROPHIC: (1) **one intersection, not per-caller… -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
15: **Dispatch targeting -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
16: **Dispatch zero-reach cause discrimination: ONE shared classifier, FIVE hand-copied legacy cascades that differ from it.** NEW surfaces (`POST /a… -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
17: Agent privilege model -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
18: **Headless platform, process decomposition & access-control spine (ADR-1005 + ADR-0031/0032/0033)** -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
19: **Authorization-topology floor (#2376)** -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
20: **Pre-auth request-body cap (#2407)** - `body_cap_policy.hpp`'s `kBodyCapTable` is the SINGLE chokepoint; EXTEND, never fork. CATASTROPHIC: (1) t… -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
21: **MFA step-up chokepoint**: `kStepUpPolicy` (`step_up_policy.hpp`) is the SINGLE table of mutating routes needing a fresh MFA proof, run by `run_… -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
22: **Fenced leader election -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
23: **Split merge-gate -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
24: **A2/A1 RBAC administration surface -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.

routed-concerns-security-posture.md
17: `app_control` plugin -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
18: `firmware_posture` plugin -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
19: `platform_security` plugin -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
20: `local_security_policy` plugin -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
21: `system_hardening` plugin -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
22: **Gateway-upstream peer authorization.** `GatewayPeerGuardedService` is the SOLE production registration of the gateway-upstream service, on the … -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
23: **Gateway origin trust -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
24: **Gateway mgmt-plane peer authorization (#1422, #6016).** `yuzu_gw_authz:check_mgmt_peer/1`, the :50063 `auth_fun`, is the SOLE authz gate on fle… -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
25: `registry` writes (`set_value`, `delete_value`, `delete_key`). **CATASTROPHIC-IF-VIOLATED:** (1) Mutate only a CHECKED handle, never a path by na… -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
26: `registry` writes (`set_value`, `delete_value`, `delete_key`, `set_user_value`, `delete_user_value`, `apply`). **CATASTROPHIC-IF-VIOLATED:** (1) … -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
27: **Same-site gate for cookie-session writes: ONE pre-routing chokepoint.** `apply_same_site_write_gate` (`same_site_write_gate.hpp`), called once … -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
28: **`virtualization.runtime_posture` -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.

routed-concerns-software-estate.md
17: **`browser_inventory` plugin (Forensics, default-off, per-user browser data)** -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
18: **`privacy_permissions` plugin (Forensics, default-off, per-app sensitive-permission grants -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
19: **`runtimes` plugin -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
20: **`middleware` plugin: read-only installed-middleware inventory (`Inventory`, table-driven; IBM MQ on Linux as `ibm_mq`; no subprocess).** Invari… -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
21: **`remote_access_audit` plugin (Forensics, default-off, per-account SSH key data)** -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
22: **Forensics tier on stored-response reads (#4990)**: rows written by plugins on the `Forensics` securable are served only to a caller holding `Fo… -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
23: **`certificate_inventory` daily-sync source and `CertificateInventoryStore` (schema `certificate_inventory_store`).** CATASTROPHIC-IF-VIOLATED: (… -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.
24: **Software title normalisation layer** -> NO MATCH: neither evidence path modifies the row’s code/configuration/product contract.

Security ledger check: two rows represent one finding, original open then linked-to-#2990; no waiver, no severity or source/provenance mutation. INFO derives I9/E3, native LOW, no floor. Zero new independent reporters correctly discloses known historical finding. Root saved issue proof supports open needs-triage, not roadmap. Recorded park4/lint0 matches canonical clean exits. At initial review the report .md was not yet created; that initial pending state is closed by the final addendum below.

FINAL EVIDENCE-ONLY SECURITY ADDENDUM
Status: PASS, no new finding. Entire new report prefix read; pre-reviewed appendix reused only after direct byte comparison proved the current .md ends with exact synthesis.txt bytes (SHA256472ced5ae6ae2ba32762562e273eb1e29397d25c6443ea2a93cd365d8d19a385). This is complete report coverage with attributed byte-identical reuse, not a fresh independent reread of every appendix. Report reviewed SHA256: 621ac7250d48f7e7d36236eb25c42dd55fb515468421d3e0187650ebc6af650e. Actual security/enterprise/build-ci/QE/cross-platform briefs and canonical current preamble retained from this run; QE/platform briefs reloaded in full, build brief relevant current clauses reread. No source change/test/network operation.

The authored report accurately supersedes interim runtime-pending and proposed-linkage statements, leaving raw reports verbatim. Current ledger two rows/one live linked-to-#2990 remains unchanged in facts/severity and does not waive a runtime flaw. No raw token, private key, DSN credential or secret appears in the authored report/ledger. Reviewer attribution is collective and sequential, not invented independent convergence. Assertions of runtime PASS match current validation-results.json/VALIDATION.txt, ASan/TSan summaries and bundle-integrity.json read directly:179/179 each, gateway1269+1538 EUnit/61CT per campaign, Dialyzer52project/563PLT,40normal-exit Linux repeats,20validation gates. Bundle verification is validation-agent execution evidence consumed by this reviewer, not a second independent execution.

Bundle134members/11387874bytes/SHA25683f0ede3395f4f0a6f4a414cee83c34a15533ad3cbd9a4d74e5d84aab8dab865; verification records all member hashes/safe regular-file paths. Local source verification6325files/mismatch0/hashbf9554715a98e887a22a354363874303a2da5efb716689b8eda2cec1ef885cd4 agrees with report. Exactly the new ledger/report are named evidence exclusions; no production file excluded. Root will rerun final verifier after finishing Gate8 prose and record report hash. This final administrative closure is explicit, not a defect or a claim already performed.

No security/API/resource runtime change in this evidence-only delta. No new policy floor or new finding. Report's final Gate8-pending markers are expected until root combines parallel reviews; replacing them with the scoped completion and final identity results requires no production rerun. Any other material change requires review.

```

### gate8-docs-compliance.txt

```text
Gate 8 evidence-only docs-writer and compliance-officer review
2026-11-12; current base ea21d7f019770a2d0e6075ad7d27c7e90438dcb7. Separate sequential role perspectives, not independent cold convergence. Scope: current governance.d/20261112-nightly-integration.e16669.md and paired two-row ledger. No production/source change, tests, network or source edits by this reviewer.

Authority/coverage
Actual docs-writer and compliance-officer briefs freshly read in full; current canonical severity/prose and Gate7/8 contract retained from this run, relevant provenance/Gate8 portions refreshed. SOC2 Workstream F and its nonzero gateway case-evidence addendum freshly consulted. Root/routing owns the current all-four-table Gate8 walk (gate8-routing-security.txt); its evidence-only domain selection agrees with this scope. Read ALL newly authored report prose before the verbatim appendix, paired ledger already read in full, VALIDATION.txt and complete validation-results.json, final local and remote source-verification records, evidence-bundle-summary.json and bundle-integrity.json. Verified appendix as exact bytes rather than unnecessarily rereading all previously reviewed role reports.

Independent local read-only evidence checks: reviewed report SHA256 621ac7250d48f7e7d36236eb25c42dd55fb515468421d3e0187650ebc6af650e matches source-verification-local-final.json's named evidence hash. Report ends with the exact entire synthesis.txt bytes; its SHA256 472ced5ae6ae2ba32762562e273eb1e29397d25c6443ea2a93cd365d8d19a385 matches prose. These checks are artifact comparisons, not rerun runtime tests. Bundle member correctness and underlying raw runtime verification are attributed to validation agent's retained results, not independently re-executed here.

Docs-writer result: PASS; no new finding.
The 179/179 results, zero non-OK statuses, 5816.75/5382.03-second wall durations, EUnit1269+1538/CT61 executed cases, Dialyzer52/563 counts, 40 repeat processes, scoped Windows40+4, Clang24 variants and sentinel38/classifier54 all match the current structured/plain summaries. Report gives exact sanitizer settings, existing exclusions/shim/suppressions and honest dependency reuse. It distinguishes full configured Linux suites from narrow Windows/native-Clang tests, and coverage-guard execution from instrumentation coverage. It does not silently import historical f4c counts or claim fresh dependency rebuilds. Source proof limits bytes/names versus modes explicitly. Current linkage and completed runtime statuses are expressly separated from raw interim appendix wording, preserving history without misleading the reader.
No new product behavior, config, endpoint, DSL, plugin capability or migration is introduced by the evidence-only diff; no additional user-manual/REST/DSL/roadmap/changelog update is required for this reporting pass. Existing product-slice docs/changelog remain covered by earlier current-base reviews. Final Gate8-pending wording is honest while this review is underway, not a false PASS. Root must replace it with the actual final decision after all required reviewers finish.

Compliance review
Control Impact: Workstream F / CC8.1 change traceability and CC7.2 execution-evidence reliability. No production access-control, data-store/retention, cryptographic or audit-event behavior changes in this evidence-only diff. Report preserves current base, staged patch identity, historical boundary and non-independence disclosure.
Evidence Impact: Current local/remote source proofs both verify6325 files with empty mismatch/unmanifested lists, aggregate bf9554715a98e887a22a354363874303a2da5efb716689b8eda2cec1ef885cd4 and frozen manifest6c7bbd2f0fbf1a085ebe09ce9c402e684974bec38ff6e187c3d2da61ee49c817. Only the exact report/ledger are excluded; local final proof hashes both while remote records them absent. Old governance files remain covered. Thus the earlier checklist's evidence-exclusion gap is closed for the reviewed report bytes. Bundle records agree on134 files,11387874 bytes and archive83f0ede3395f4f0a6f4a414cee83c34a15533ad3cbd9a4d74e5d84aab8dab865, regular/safe paths and member checks. Summary names credential/DSN redaction without exposing values. Local evidence locations and owned remote raw originals provide traceability; this is not a claim of remote publication or permanent archival custody beyond retained artifacts.
Policy Impact: No policy revision or exception renewal. Ledger remains two physical rows/one live pre-existing INFO(NICE) finding, terminal linked-to-#2990, with impact restated, zero cold independent reporters and no floor. Current issue evidence is OPEN/needs-triage/not-roadmap. Report neither says it was promoted nor invents a renewal. KEEPLOCAL explains no external comment. Canonical jq exit4/linter0 are root-reported execution facts, not rerun by this reviewer.
Risk Impact: No new risk-register item or compliance defect from this evidence-only diff. Existing stale A5 review metadata remains visible and linked, not waived. Narrow platform and sanitizer limits are preserved; no whole-platform effectiveness claim added.
Verdict: PASS for evidence-only compliance review; zero new findings, zero de-escalations or self-waivers.

Finalization obligations, not new findings
Root still owns final Gate8 decision and conservative evidence-domain checks named in routing. After final report wording changes from pending to completed, refresh its named evidence hash/local proof and narrowly check final text against this review and actual other role outcomes. Do not claim this reviewed hash covers subsequently edited prose. Preserve synthesis verbatim. validation-results.json contains chronological gate notes such as earlier 'full compile pending'/'raw logs pending'; later full-build/bundle records and explicit top-level PASS resolve them, and final report correctly summarizes completed status rather than treating those old notes as current blockers. No evidence of a material contradiction found.

```

### gate8-consistency-sre.txt

```text
Gate 8 evidence-only consistency and SRE review — root
Reviewed new report/ledger against validation/VALIDATION.txt, structured sanitizer summaries, bundle-integrity.json, explicit source exclusions, current ledger checks, prior routing and SRE conclusions. Actual consistency and SRE briefs/current governance contract remain applied.
PASS, no finding. ASan179OK and TSan179OK, durations5816.75/5382.03, gateway1269+1538/61 each, Dialyzer52/563, forty Linux repeats, focused Windows40+4, Clang24 variants and sentinel38/classifier54 agree with execution evidence. Reused dependency outputs are disclosed. Existing instrumentation exclusions/suppressions are named; no new suppression or test retry is claimed. Platform scope remains explicit and no full Windows/macOS application claim is made.
The source aggregate remains6325 files/bf9554715a98e887a22a354363874303a2da5efb716689b8eda2cec1ef885cd4. Exact two new evidence paths alone are excluded; old governance artifacts remain verified. Local post-report verifier PASS with no mismatches/unmanifested files; final prose closure requires one final verifier invocation. Staged reviewed patch SHA remainsf282726ecf5fab4617d45c9f9fa921b1854421742eddbe304bc882d687828f35. Verbatim appendix suffix and SHA472ced5ae6ae2ba32762562e273eb1e29397d25c6443ea2a93cd365d8d19a385 checked programmatically.
Ledger two rows/one live nonblocking I9 finding linked2990, no exception renewal/waiver, agrees with report. Gate5 SKIP remains explicit. Final completed results correctly supersede interim pending text without rewriting raw reports. New evidence docs introduce no production observability, recovery, resource-lifetime or capacity change. Runtime and source-integrity work is complete; remaining closure is evidence-only reviewer verdicts and replacement of provisional Gate8/decision text.

```

### gate8-build-ci.txt

```text
Gate8 build-ci — evidence-only PASS
Reviewed report SHA256 621ac7250d48f7e7d36236eb25c42dd55fb515468421d3e0187650ebc6af650e and paired two-row ledger; unchanged source patch f282726ecf5fab4617d45c9f9fa921b1854421742eddbe304bc882d687828f35.
Actual current role brief/canonical preamble from this run applied. Entire authored report prefix read; byte-identical raw appendix reuse verified, not new independent convergence.
Current full ASan and TSan application builds/suites have actual current-base results. Dependency install/dryrun no-op is expressly reuse after exact input proof, not a fresh rebuild. Commands, workers3/timeout4, dependency versions and unchanged instrumentation/suppressions match structured evidence. Evidence-only files do not alter CI/Meson/cache/codegen. No new finding.
Root final evidence-only Gate8 prose completion/source-verifier rerun remains administrative closure; no additional production tests requested. No source edits/tests/network performed.

```

### gate8-quality-engineer.txt

```text
Gate8 quality-engineer — evidence-only PASS
Reviewed report SHA256 621ac7250d48f7e7d36236eb25c42dd55fb515468421d3e0187650ebc6af650e and paired two-row ledger; unchanged source patch f282726ecf5fab4617d45c9f9fa921b1854421742eddbe304bc882d687828f35.
Actual current role brief/canonical preamble from this run applied. Entire authored report prefix read; byte-identical raw appendix reuse verified, not new independent convergence.
179/179 configured entries for each sanitizer; no zero-case gateway claim (EUnit1269+1538,CT61).40Linux normal-exit repetitions distinguish13cases206assert TLS and1case5assert lifetime. Windows and stand-in harness scopes are clearly smaller than application suites; no coverage-percentage claim. Historic176-entry runs remain historical. No new finding.
Root final evidence-only Gate8 prose completion/source-verifier rerun remains administrative closure; no additional production tests requested. No source edits/tests/network performed.

```

### gate8-cross-platform.txt

```text
Gate8 cross-platform — evidence-only PASS
Reviewed report SHA256 621ac7250d48f7e7d36236eb25c42dd55fb515468421d3e0187650ebc6af650e and paired two-row ledger; unchanged source patch f282726ecf5fab4617d45c9f9fa921b1854421742eddbe304bc882d687828f35.
Actual current role brief/canonical preamble from this run applied. Entire authored report prefix read; byte-identical raw appendix reuse verified, not new independent convergence.
Current Windows40successful focused processes+4expected invalid-CLI failures is scoped to shared-runner/dependency integration, not full native product/installer or instrumentation.24fresh Apple/Homebrew Clang variants are stand-in callback/macro harness checks, not wholeMac. ADR0035 Linuxserver/nativeagent scope remains explicit. No new platform source changed; no new finding.
Root final evidence-only Gate8 prose completion/source-verifier rerun remains administrative closure; no additional production tests requested. No source edits/tests/network performed.

```

### gate8-enterprise-readiness.txt

```text
Gate8 enterprise-readiness — evidence-only PASS
Reviewed report SHA256 621ac7250d48f7e7d36236eb25c42dd55fb515468421d3e0187650ebc6af650e and paired two-row ledger; unchanged source patch f282726ecf5fab4617d45c9f9fa921b1854421742eddbe304bc882d687828f35.
Actual current role brief/canonical preamble from this run applied. Entire authored report prefix read; byte-identical raw appendix reuse verified, not new independent convergence.
Customer assurance accurately separates actual Linux full runtime results from narrow Windows/Clang checks and unchanged dependency-output reuse. Underlying #2990 exception is not renewed by linked-to disposition; existing INFO review-date finding persists locally with correct provenance. No invented full-platform or operating-effectiveness certification. Final report carries raw reviews and current source/ledger identity rather than relying solely on scratch reports. No new finding.
Root final evidence-only Gate8 prose completion/source-verifier rerun remains administrative closure; no additional production tests requested. No source edits/tests/network performed.

```

## Verbatim review appendix

The following synthesis is preserved byte-for-byte from `synthesis.txt`, SHA-256 `472ced5ae6ae2ba32762562e273eb1e29397d25c6443ea2a93cd365d8d19a385`. It includes the sixteen role reports, Gate 5 rationale, routing, resource inventory and Gate 1. Its provisional singleton is not an additional finding or a severity adjudication.

Gate 6b synthesis — PRESENTATION ONLY; CURRENT RUNTIME PENDING
Base ea21d7f019770a2d0e6075ad7d27c7e90438dcb7 plus staged patch SHA-256 f282726ecf5fab4617d45c9f9fa921b1854421742eddbe304bc882d687828f35.
Actual workflow-orchestrator brief and canonical Gate 6b contract applied. This pass neither re-adjudicates findings nor grants final governance PASS. Source reviews are complete; fresh current Linux sanitizer/full-suite and other required execution closure remain pending root validation.

Gate status
| Gate | Status | Roles |
| 0/1 | Source routing and inventory complete | currency, all four routed tables, summary/resource ledger |
| 2 | Source PASS; zero findings | security-guardian, docs-writer |
| 3 | Source PASS; zero findings | architect, quality-engineer, cpp-expert, cpp-safety, build-ci, cross-platform, gateway-erlang, release-deploy |
| 4 | Source PASS; zero findings | happy-path, unhappy-path, consistency-auditor |
| 5 | Conditional SKIP, not chaos PASS | root canonical decision in appendix |
| 6 | Source review complete; one pre-existing INFO | compliance-officer, sre, enterprise-readiness |
| 6b | Presentation complete | this synthesis |
| 7/8 | Root resolution/closure pending | no implied final approval |

Severity-ordered findings (every cluster PROVISIONAL)
| Cluster | Finding | File:line | Defect | Maximum derived severity | Native | Reporting role | Provenance |
| PROVISIONAL C1 | enterprise-readiness-001 | docs/agentic-first-principle.md:123 | A5 #2990 revisit date 2026-10-31 is overdue | INFO (I9/E3); NICE mapping | LOW | enterprise-readiness | pre-existing |
One singleton; no other findings to merge. Same file:line AND same defect is the only permitted merge criterion. No historical fixed findings are imported as live current findings. No validation guidance scenario becomes a finding.
Independently: 0 new cold reporters in this run; echoed/reverified: 1 current enterprise reporter already shown the historical finding. Other roles' references delegate to this finding and are not separate findings or independent confirmations. Direct date and saved-issue re-verification provides evidence without manufacturing convergence. The underlying runtime envelope gap is not regraded or waived here. Root may record an existing-issue linkage under KEEPLOCAL; the draft raising row remains open until disposition is recorded.

Evidence clarification (does not modify the raw appendices)
Root clarifies the 24 narrow compiler macro variants were freshly rerun for this current campaign using recorded Homebrew/Apple Clang toolchains. References calling those variants historical in raw reports are superseded by this evidence-status clarification only. This is not a compiler named Clang24 and not a full macOS application build. Current Windows evidence is 40 focused runner successes plus four expected CLI failures, with matching dependency outputs reused/no-op installation, not a fresh dependency rebuild or full Windows app/installer test. Coverage-guard mode tests normal exit and is not instrumentation coverage. Historical f4c Linux results remain historical. Current Linux runtime is pending.

Verbatim raw appendices follow. Byte length and SHA-256 delimit each embedded report; contents between BEGIN and END markers are copied without alteration. Final separator newline is outside the report bytes where needed. These appendices preserve scope limitations and interim evidence wording rather than silently rewriting source reports.

===== BEGIN security-guardian.txt bytes=5068 sha256=4c0d9b3b3c3139468734d342cd61de6974b2c71a554f13bd4694c0be7c05bbd7 =====
Gate 2 security-guardian — current base ea21d7f019770a2d0e6075ad7d27c7e90438dcb7 plus staged patch f282726ecf5fab4617d45c9f9fa921b1854421742eddbe304bc882d687828f35
Source-review PASS: no new finding or unresolved security policy floor identified. Runtime and overall governance remain pending. No tests, network mutations or source edits by this reviewer.

Authority/coverage: actual security brief, canonical shared severity/prose preamble and complete Gate2 template read; Gate1 summary/resource ledger read. All four CURRENT routing tables read row by row. Source echo: “this is denial only, never authority to reveal an uncached secret.” Prior complete full-file reads are reused only for identical bytes (source-identity.json). Complete current workflow/Meson deltas against frozen source freshly read, with current registration/cache context. resource_ledger owns current auth/build/CI prose and historical governance artifacts; its docs-writer report attributes prior full collective reads plus all current changes. NOTICE/license final corrections use supplemental-license-manifest.json, not initial frozen manifest. This is explicit collective continuity, not newly independent full rereading. Old f4c governance/runtime results remain historical.

Rotation: api_token_store.cpp:1649 checks the committed successor’s durable initiator AFTER epoch expiry and BEFORE try_reserve. Different operator cannot obtain cached_raw in the publication gap; same operator with no RAM entry still receives the grace conflict. Empty durable owner gives no reveal authority: existing fresh RAM owner remains required. No additional secret logging, durable raw token, permission, actor class or route is introduced. Borrowed successor points into local active vector throughout comparison. Existing ScopeExit is armed before candidate generation and scrubs all four plaintext slots, including early denial.

Current sibling proof: human rotate_token checks predecessor principal==requesting_user and authority inheritance inside the lock before its cache path (cpp:2148–2182). Engine REST caller at rest_api_v1.cpp:7091–7142 retains permission, session/engine denial, step-up and session username; MCP at mcp_server.cpp:29742–29825 retains tier-before-permission, engine denial and username. Both failure paths audit; engine_store_error_class.hpp:150 maps the unchanged “different operator” phrase to Conflict (REST409/MCP invalid params, no transient retry). Both successful reveals still require checked successor correlation and audit persistence. New denial does not mint or reserve, and does not bypass those later checks.

State cross-product: zero active/failed read refuses; one active mints only after bounds/referent validation and atomic insert+predecessor stamp; two linked active rows apply epoch→durable deny→RAM grace→RAM owner; malformed/two unrelated/>2 refuse. Confirm uses durable/RAM identity resolution and successor proof, never this denial as authority. Manual revoke resolves surviving linkage; sweep keeps an unused successor’s predecessor alive and refuses malformed state. New branch changes only two-active retry classification; no new transition/wedge/orphan. Upstream exec_params NUL refusal and PgTxn aborted-commit behavior preserve refusal: current pg_pool.cpp:402–430 rolls back callback false before returning lease, additionally rejects non-INTRANS callback success. Cache publication occurs only after with_txn_for succeeds.

Ownership: Gate1 ledger accounts for engine default slot/init ref, Catch Session, detached ThreadState, implicit worker OpenSSL state, callback/future, PG fixture/store/pool, Guardian fixture gates/threads/temp files. Current 00017 callback first adopts unique_ptr, then declares noncopyable OpenSSL guard, then calls ThreadBody. Destruction stops thread crypto BEFORE worker retirement; no manual cleanup exemption. This does not join native detached threads or guarantee arbitrary future TLS destructors/custom engines. Shared runner destroys Session then balances grpc_shutdown_blocking then drops default engine; no second retained shared_ptr deadlock. Lifetime promise captured by value survives timeout unwind. Agent runner excludes runtime owner, preserving fork-test quiescence.

Integration/security boundaries: ADR0035 agent-only Windows/macOS remains compatible with standalone regression (Catch/gRPC/OpenSSL only; no server source/libpq; agent suite label selected). Current cache inputs ports/** lie outside restored vcpkg_installed; save still requires producing install success. Sentinel and Docker overlay handling preserve dependency provenance; no untrusted shell input or broadened runtime authority. Gateway SHA256 fixture changes do not alter production peer/trust policy. Guardian and Python fixture completion changes do not alter product authorization. Root reports fresh focused Windows rerun40 success+4 expected CLI failures; this is not full Windows application coverage or instrumentation coverage. Linux current-base campaign remains root-owned/pending.
===== END security-guardian.txt =====

===== BEGIN docs-writer.txt bytes=5286 sha256=6617f0a473dfa4fb2857053eddf0d6f0e91170c6807c5c345ec8f855bb100b09 =====
Gate2 docs-writer — ea21d7f019770a2d0e6075ad7d27c7e90438dcb7 plus staged fix,2026-11-12
No new finding. No source edit, test execution, network mutation or fresh-runtime PASS in this role.
Input echo: "This is a denial check only: raw re-serve still requires the unexpired RAM entry and its matching operator" (current auth architecture). Full current actual docs-writer brief, Codex governance skill and canonical shared severity/prose preamble read. Canonical six required-doc classes, derived severity and floors govern; no invented native label for a clean result.

Coverage/provenance: prior complete full-file reads are reused only where SHA256 comparison proves current bytes identical to prior validation/source-manifest.json merged with validation/supplemental-license-manifest.json (the latter supplies NOTICE/license). This includes all modified C++/header/tests/Python, overlay files, Docker files, shell scripts, Erlang fixtures, NOTICE and changelog. Current changed resource/code boundaries independently reread. Entire oldbase auth6019/CI3513/build162 documents had prior complete collective reads, with CI801–2000 attributed to routing. Current upstream changes were reread in full with contextual sections, and every staged documentation hunk rereviewed. Upstream intersection consists of ci.yml, tests/meson.build and auth/build/CI docs; routing owns complete workflow/Meson current integration checks and all four current routed tables. Root explicitly accepts priorfull+verifiedidenticalbytes+allcurrentdeltas/context; this is not fabricated fresh literal rereading or independent convergence. Historical governance reports were authored/read and later audited in prior run; they identify basef4c and remain historical, never currentbase evidence.

Required-doc assessment:
1. REST reference current lines1514–1515 already specifies different-operator409 and grace expiry. New store denial uses the existing conflict classification, not a new signature/body/permission/status. Same-owner raw replay remains RAM-bound. No redundant REST edit required.
2. No new product CLI/env/operator workflow/migration. Existing credential rotation/recovery contract unchanged. Build guide documents overlay refresh/rebuild; agent fixture ownership remains scoped. No new upgrade note required for this staged fix.
3. changelog.d/20261110-nightly-shutdown-rotation.fixed.md covers worker cleanup and competing rotation. No CHANGELOG.md edit. Date-based fragment is allowed by existing convention; not claiming fresh lint executed.
4. No new public ABI/store/architectural invariant/release gate: test-runtime owner and dependency overlay are local implementation mechanisms. No CLAUDE duplication warranted.
5. No new audit-action/permission/error-code table member. Durable initiator check adds no secret reveal/audit-success path.
6. Current staged test fixture changes do not add product capability, plugin action, Guardian state-machine contract or DSL element. Routed reading requirements do not create invented per-change update obligations; routing owns current full-table matching.

Truth/context review:
- Runner/header/README/build-guide accurately distinguish suite default-engine ownership, secure-worker crypto cleanup before retirement, and independent caller-thread/custom-engine obligations. They do not promise native-thread join or arbitrary TLS destructor safety. Current scoped cleanup supersedes original manual-cleanup flaw; no exception granted.
- Upstream ADR0035 now retires Windows/macOS server CI/release support. Auth's two installer paragraphs are historical accordingly. Build/CI docs explain agent-only Windows/macOS, single Windows non-PG invocation, no server pg tests, retained provisioned PG services, and unchanged current default dependency profile. This staged overlay/runner change does not reinstate a supported Windows server or change the upstream retirement. Current runtime validation must reflect this base, not reuse old full-suite counts.
- CI overlay content/name digest, deterministic ordering, configuration-relative paths, missing-input failure, nested-directory-symlink refusal and working-python3→python probe match current byte-identical sentinel. Canary key/classifier includes ports/**; inherited interpreter defect is already corrected in the submitted source, not a new current finding.
- New comments around Guardian park/release timing express accepted-but-pending arm semantics, not automatic synchronous completion. Python logical completion precedes HTTP response publication; subprocess stdin=None follows explicit EOF. Gateway fixture digest wording remains domain-owned; no production trust policy change claimed.
- NOTICE scopes exact upstream MIT notice to imported recipe/helpers/inherited patches; local00017/README excluded. Existing historical governance PASS is expressly basef4c. New run must preserve that historical identity, not amend it to look like currentbase validation.

Verdict: PASS for docs source review within explicit collective coverage; no new wording, contradiction or missing required-doc finding. Current-base runtime and other gates remain pending. Next: current C++/architecture/QA roles and root's fresh campaign; do not turn this source review into overall governance PASS.
===== END docs-writer.txt =====

===== BEGIN architect.txt bytes=3468 sha256=fef8b687067b5ea285818d48351c27c204f4927f38d5762878269e9957318c23 =====
Gate3 architect — ea21d7f019770a2d0e6075ad7d27c7e90438dcb7 + staged fix,2026-11-12
No new architecture finding. Source review PASS, fresh currentbase campaign pending. Sequential review, not independent corroboration.
Actual architect brief and full canonical preamble read. Current Gate1 summary/resource inventory read. Prior full source reads reused only under verified identical bytes, current changed methods/build graph and upstream interaction deltas independently read. Reference context: architecture core/storage/ABI sections, ADR0012 pool/query-owner contract previously read, current ADR0035 binding status/decisions/ladder, Guardian R5 accepted-versus-acknowledged contract. No exhaustive untouched roadmap/observability inventory audit claimed. Source echo: "link_with: grpc_test_runner,".

1. Production denial belongs in ApiTokenStore's existing principal-advisory-locked two-active transaction. Existing durable initiator is used only to refuse another caller; no new authority/grant source or persisted plaintext. Same-owner replay retains RAM+deadline requirement, and epoch precedence remains. No new schema/query-owner seam/cross-store lease; no external call while the added comparison holds the transaction. Upstream NUL parameter rejection/PgTxn rollback correction strengthens fail-closed handling without moving cache publication before successful commit.
2. Shared test runner library depends downward on grpc/Catch and a pre-existing hard_exit header. Server tests and standalone lifetime regression consume it; it does not depend on server core or PostgreSQL. Agent tests use the ordinary main without a pinned pool. No cycle or production server→agent module dependency introduced.
3. Upstream ADR0035 is accepted and steps1/2 make Windows/macOS agent-only CI/release. The standalone crypto/runtime regression remains buildable in that agent-only graph, using dependencies still required by the agent. Naming its runner server-style lifecycle does not build a control-plane binary or reintroduce server support. Any current Windows evidence is focused shared-runner/agent integration, not a Windows server support promise. Root owns current graph/runtime verification.
4. Worker-local OpenSSL cleanup belongs at the upstream worker callback boundary, since another thread cannot clean that thread's state. Suite runtime owns default-engine drain, fixtures own custom/caller threads. No general native join or global crypto-cleanup authority is introduced, and comments preserve that scope.
5. Guardian change controls fake asynchronous arm completion before asserting generation acknowledgment; it respects R5 and changes no production state machine. Python response-order fixture similarly observes logical completion, not a new product concurrency primitive. No protobuf/SDK ABI file changed, no ABI/version migration warranted.
6. Overlay configuration/digest and Docker copy are build integration; baseline pin/source hash/imported notices retained. No new product feature, permission, metric or audit event requires invented roadmap/catalogue updates. Historical f4c governance record remains labeled with its old base and cannot close this base's campaign.

No finding IDs or synthetic severity facts generated for clean source review. No source edits/tests/network actions. Next evidence: currentbase Linux sanitizer campaign and focused supported endpoint-platform validation; old source-identical passes are historical only.
===== END architect.txt =====

===== BEGIN quality-engineer.txt bytes=3918 sha256=468a7cd7f3921e179559bb20ee17301b44619ae86daa83688fb3d8762d896a88 =====
Gate3 quality-engineer — ea21d7f019770a2d0e6075ad7d27c7e90438dcb7 + staged fix,2026-11-12
No new coverage/fixture finding. Source review PASS, empirical currentbase campaign not yet closed by this reviewer.
Actual QA brief and canonical preamble read, current unit-test-conventions fully loaded. Source echo: "REQUIRE(interleaved);". Sequential review, no independence claim. Prior full token6480/Guardian2822/Python2741+583/runner/lifetime-test reads are reused under verified identical current bytes. All changed test sections and fixture teardown/context reread; current Meson registration checked, routing covers complete current workflow/Meson. No tests/network/source edits here.

Regression validity:
- Publication test uses real isolated template-backed PG pool/store, synchronous postcommit/prepublication hook and explicit interleaved assertion. Different operator must get exact denial, same operator cannot obtain uncached secret, active-count remains2, later replay matches original, and epoch expiry retains precedence. This distinguishes the prior wrong conflict and guards against laundering durable identity into secret authority. It is deterministic scheduling, not an optimistic sleep. Upstream NUL refusal and PgTxn failure changes do not invalidate the normal ASCII fixture or transaction boundaries; error paths continue to unwind without cache publication.
- Standalone lifetime process uses real shared entry point. Weak ref expires without retained default-engine ownership; assertion would observe missing pin. Callback owns shared promise, uses public/private RNG, bounded wait, no stack capture. It cannot alone prove all detached TLS shutdown ordering: actual normal-exit sanitizer campaign is still required. Current tests/meson.build:81 retains --durations=yes, so old timing finding is not reintroduced.
- Worker guard's deleted copy operations plus prior exact macro/normal+unwind harness establish noncopyable shape for unchanged bytes. These narrow checks are not substituted for fresh actual dependency/process integration.
- Guardian waits x compliant before parking next watch, then waits hang entered, asserts pending generation, releases/drains and waits both compliant before final full_sync. Rig::close releases every gate before resetting owners on REQUIRE unwind. Existing salted paths/template DB names preserve cross-job isolation; no new fixed port/key.
- Instruction fixture decrements logical request count before HTTP publication (finally covers failure), delayed-return case observes old overcount. MCP fixture closes input then nulls Popen.stdin so communicate does not flush a closed handle; process output still drained and timeout reaps child. No production parser added requiring a new fuzz target.
- Current sentinel Test8 retains working-python fallback and neither-working preservation cases; classifier covers overlay input. Historical38/54checks remain evidence of oldbase executions only. Root can add current results separately.

Current upstream scope: ADR0035 removes server suites from Windows/macOS; it does not make the agent-only shared runtime regression unreachable (agent suite label, grpc/OpenSSL/Catch dependencies). Newly added upstream tests mean historical176-entry counts cannot be quoted as this base's full suite; Gate1 expects fresh179-entry campaign. Root reports current-input-hash-verified Windows40focused passes+4expectedCLI failures; that is root evidence, not my execution and not full Windows app coverage. New Linux campaign remains pending.

No new store/parser/feature requires new CRUD/fuzz inventory entry. Existing docs/test-coverage historical count drift is not an introduced finding. Current assertions can observe their intended branches, so no false-green floor established. Do not label source review alone closure of runtime lifetime findings; root must reconcile final exact source identities and actual results.
===== END quality-engineer.txt =====

===== BEGIN cpp-expert.txt bytes=3679 sha256=6243171d98efff1a7c1ab76e8e11bf121d2de77448c77b683724b7ac7fb0384d =====
Gate3 cpp-expert — ea21d7f019770a2d0e6075ad7d27c7e90438dcb7 + staged fix,2026-11-12
No new finding. Source review PASS; current-base runtime/build campaign pending, not overall governance PASS.
Read current Codex cpp-expert/cpp-safety skills, actual cpp-expert brief, cpp-conventions and cross-compiler troubleshooting, canonical full preamble. Sequential role by resource_ledger, no independent-convergence claim. Source echo: "std::unique_ptr<ThreadState> worker(static_cast<ThreadState*>(arg));".
Coverage: all modified C++/header/test/overlay bytes match prior completed full-file review under frozen SHA256 manifest; reused that full context explicitly, independently reread current full runner/lifetime regression/patch and changed token/Guardian code, current Meson runner registration, upstream pg_exec/pg_raii deltas and PgPool::run_in_txn. Routing owns full current token cpp/hpp and full Meson/workflow context. No tests or compiles run here.

Language/ABI review:
- Worker adopts correctly typed void* context immediately into unique_ptr. Local crypto owner is noncopyable, declared after worker; reverse destruction gives required cleanup-before-counter-retirement on normal return and C++ unwind. No C++23-only library feature is forced into upstream gRPC's C++17 target. Required memory include was already present in exact1.81.1 source reviewed previously; source/recipe/patch bytes unchanged.
- Cleanup macro is PRIVATE to secure grpc; unsecure/standalone objects do not acquire a libcrypto reference. BoringSSL/LibreSSL/old-OpenSSL exclusions preserved. Feature guards for GCC/Clang sanitizer detection remain mutually scoped; no duplicate main or new TSan-hook ODR definition within a binary.
- SuiteGrpcRuntime is noncopyable; compiler-generated move is unavailable due declared copy/destructor, avoiding duplicate shutdown. Catch Session declaration order handles CLI error and normal exit. Creation uses shared_ptr transfer without a second retained reference; agent test runner omits the persistent pool for fork tests. Existing diagnostic fprintf and hard-exit policy are retained behavior, not new production formatting/API code.
- Promise lambda owns shared_ptr, stack RNG buffer stays callback-local, cast of array size32 to int bounded, one future/get and single set_value. No borrowed-view escape or new plugin ABI/protobuf surface.
- Token predecessor/successor pointers reference the local active vector throughout denial; no vector mutation or invalidation. Existing expected<string> errors and scope-exit secret scrubbing are preserved. Header change documents durable denial only.

New-base interactions:
- Upstream pg::exec_params refuses embedded NUL with failing transaction status; new denial adds no parameters and cannot bypass it. PgTxn's rolled_back state is propagated through move and prevents rollback of later work; current run_in_txn keeps txn after Lease and rejects callbackfalse before commit. Current denial therefore unwinds rollback before returning lease, and upstream fail-closed behavior cannot publish a raw cache entry after failure.
- ADR0035 Windows/macOS agent-only graph does not exclude grpc itself: agent links it. New standalone runner/regression needs grpc/Catch/OpenSSL, no server or libpq dependency. Registering it in agent suite remains reachable without building server. Detailed current graph checks attributed to build-ci/cross-platform, fresh platform run evidence still pending.
Historical HomebrewClang23/AppleClang21 macro checks and prior f4c Linux/MSVC results support unchanged byte-level syntax, but are NOT currentbase integration results. No policy exception or new severity derivation needed.
===== END cpp-expert.txt =====

===== BEGIN cpp-safety.txt bytes=3810 sha256=0dea309f0a9f3a11e55ed631c647ce65dc689b1507b78b522380b8f6c9655891 =====
Gate3 cpp-safety — ea21d7f019770a2d0e6075ad7d27c7e90438dcb7 + staged fix,2026-11-12
No new ownership/lifetime finding. Resource Ledger: complete (resource-inventory.txt,14categories). Source review PASS; sanitizer coverage needed ASan/UBSan/TSan with current source/dependency identity. Runtime closure remains pending.
Current full canonical preamble, both C++ skills and actual safety brief read; cpp-conventions loaded. Same sequential reviewer as cpp-expert, not independent. Source echo: "ScopedOpenSslThreadState(const ScopedOpenSslThreadState&) = delete;". Coverage/provenance as cpp-expert; byte-identical prior full reads explicitly reused, current raw-boundary methods reread, no tests/network/source edits.

Ownership proof:
1. Suite runtime owns initialization reference and default engine lifecycle. Temporary engine shared_ptr transfers to gRPC slot; no extra long-lived reference causes shutdown wait cycle. grpc_init balances shutdown_blocking in noncopyable destructor, followed by default-engine shutdown. CatchSession/listeners destruct before runtime, also on CLI failure. stdout/stderr/argv borrowed, no close ownership introduced.
2. Detached gRPC thread context allocated upstream is immediately adopted in callback unique_ptr. ThreadState retains pool/counter. Scoped crypto destructor executes before that owner retires count. No raw new cleanup outside RAII remains; no exception waiver needed. Upstream detached native-thread behavior is unchanged: code does not promise OS join or cleanup of arbitrary custom-engine/caller crypto threads. App must own those separately. Existing upstream queue bookkeeping is not recast as a new cleanup defect.
3. Regression shared promise survives REQUIRE timeout and callback scheduling; local future/engine refs release on unwind. Callback owns array and only passes it synchronously to RAND functions. Main and worker OpenSSL state have separate lifetimes; worker cleanup is patched, main state remains process lifecycle. Process sanitizer exit is necessary evidence beyond assertion success.
4. Test PG fixture owns isolated database, then pool, then borrowing store in reverse-safe lifetime order. Synchronous hook borrows live principal/now/interleaved/store only during rotation call; nested rejected rotations never recurse through publication hook. Store closure destruction does not dereference dead locals. No fixed database-name cross-job collision.
5. Production denial acquires no new resource. Existing Lease/transaction guard and four-slot secret scrub guard handle all false/exception exits. Read current PgPool::run_in_txn402–430: callbackfalse rolls back before Lease destruction. Upstream pg_exec NUL refusal and PgTxn aborted-state handling retain this behavior; no commit-false secret publication.
6. Guardian parked watch is released on explicit path AND Rig::close even after REQUIRE unwind. Rig releases both watch/unwatch gates before waiting/resetting engine, then Spark, then KV/temp state. fm/sm are borrowed Spark-owned objects, aliases nulled at teardown. No added OS handle/temp-path/subprocess ownership outside inventory.
Mechanical changed-boundary scan found only known upstream raw ThreadState allocation, replacement delete, documented detached-thread context, and owned callbacks. Broader existing token/test raw resource sites were already fully read and remain byte-identical. There is no new shell construction, reinterpret/const cast or owning plugin C pointer.

Validation boundary: require fresh currentbase Linux ASan/UBSan/TSan, normal-exit TLS/lifetime repeats, and current agent-only Windows runner integration. Earlier f4c passes and exact unchanged macro harness are historical corroboration, not fresh closure. No new leak/UAF/double-release floor found, and no self-adjudication performed.
===== END cpp-safety.txt =====

===== BEGIN build-ci.txt bytes=3754 sha256=7924bef5d46ea67a8d3ccdb091dc889f080d22a9404f80bbbadb85e5b4ec09b1 =====
Gate3 build-ci — SOURCE PASS, runtime campaign pending; no new finding.
Scope: ea21d7f019770a2d0e6075ad7d27c7e90438dcb7 + staged patch f282726ecf5fab4617d45c9f9fa921b1854421742eddbe304bc882d687828f35. Gate1 and Gate2 security/docs context consumed. Canonical shared severity/prose rules govern, not older native severity examples. Read-only source review; no tests or network actions by this reviewer. Roles are sequential views by routing, not independent convergence. Prior full-file review is reused only for verified identical bytes, with all current deltas and integration context freshly read (source-identity.json, since-frozen.diff, domain-context.diff). Historical governance.d/20261110 artifacts remain old-base evidence.

Actual build-ci brief and ci-cache/yuzu-meson/yuzu-windows-msvc skills loaded; retained identical domain-doc reads plus current Windows doc changes and current build/CI doc review by resource_ledger. Old compiler/runner labels in the brief are not substituted for current CI/ADR0035.
- All current ci.yml and tests/meson.build differences versus prior complete reads inspected. New runtime source listed once; static runner owns main and links Catch2 without Main; server links runner while agent compiles ordinary main. Coverage definition reaches runner, ASan/TSan compiler detection remains on both relevant toolchains. System include treatment retained.
- Unconditional standalone runtime test is compatible with build_server=false: only Catch/gRPC/OpenSSL dependencies, no server objects/libpq. Its dual agent/server labels match agent selection (assert-suite-cover uses set intersection); current Windows explicit suites and macOS no-docs invocation select it. No Windows server support is reintroduced. Upstream new installed-software/runtime-posture test entries remain intact.
- Exact overlay is unchanged from reviewed pinned grpc1.81.1 port1 recipe plus00017, preserving inherited patches/tools/codegen features. Secure grpc PRIVATE macro excludes unsecure/standalone targets; OpenSSL guard covers supported OpenSSL and excludes BoringSSL/LibreSSL. <memory> already exists upstream. Root hand-wired Windows debug/release grpc/protobuf and static triplet retained.
- Canary cache hashes ports/** outside restored installed tree, then sentinel reconciles. Save still guards actual install success with explicit status function. Source classifier adds dependency paths so canary warms on overlay-only pushes. Sentinel hashes sorted names+bytes/config-relative roots, refuses missing overlay and nested directory symlink, probes executable Python before mutation; python fallback handles AppExecutionAlias. Existing 38-test historical evidence is not claimed freshly run by this role.
- Five Docker dependency stages COPY ports before install. Changes invalidate dependency cache rather than leaving overlay absent in image context. License parent included. Database sweep changes executable discovery only, retaining SQL/name/age safety logic.
- root Windows current-input proof and result JSON directly inspected: exact runner/patch/triplet hashes;40 successful launches and4 expected invalid-CLI exits. Dependencies were already current/no-op on rerun; this is not a fresh dependency rebuild on ea21, full Windows agent build, Meson graph execution or actual coverage instrumentation. Linux current179-entry campaign remains pending. Native Clang24 variant historical narrow checks are not a whole macOS application build. Whitespace warnings for nested patch blank context/upstream recipe fidelity are historical disclosed, not silently “clean”.
No introduced source build defect found. Required platform/application/runtime validation status belongs to root; source PASS is not overall governance PASS.
===== END build-ci.txt =====

===== BEGIN cross-platform.txt bytes=2864 sha256=1b7dd1fa0a07532c11f509f00ce946d7fd60726234d4e0636ea8f06887920770 =====
Gate3 cross-platform — SOURCE PASS, validation scope bounded; no new finding.
Scope: ea21d7f019770a2d0e6075ad7d27c7e90438dcb7 + staged patch f282726ecf5fab4617d45c9f9fa921b1854421742eddbe304bc882d687828f35. Gate1 and Gate2 security/docs context consumed. Canonical shared severity/prose rules govern, not older native severity examples. Read-only source review; no tests or network actions by this reviewer. Roles are sequential views by routing, not independent convergence. Prior full-file review is reused only for verified identical bytes, with all current deltas and integration context freshly read (source-identity.json, since-frozen.diff, domain-context.diff). Historical governance.d/20261110 artifacts remain old-base evidence.

Actual cross-platform brief and yuzu-windows-msvc skill loaded. docs/windows-build.md fully read current; docs/darwin-compat.md and ci-cpp23-troubleshooting.md identical to prior reviewed versions (verified). Current Windows document explicitly agent-only CI/release since ADR0035; retained local server commands do not reinstate support.
- Shared runner requires portable C++ ownership, no new platform syscall. Windows/MSVC and Clang/GCC sanitizer macros keep normal exit for ASan/TSan, coverage macro also excludes hard_exit. Linux always normal exit. Unsanitized Windows/macOS retain old hard_exit only after explicit Session/default-engine teardown.
- OpenSSL is required on Windows too; secure gRPC target reaches libcrypto using existing Windows manual dependency closure. No vcvars64 or external Windows LLVM path introduced. Catch2 debug suffix/CRT selection unchanged. The new standalone fixture is independent of server build gating and selected on agent-only platforms.
- Agent shared entry deliberately does not instantiate SuiteGrpcRuntime: fork-without-exec tests do not inherit a newly pinned thread pool. New upstream installed-software collector teardown does not change that ownership responsibility; fixtures still own custom engines/threads.
- Sentinel obtains a working python3 or python before deleting state. Configuration paths resolve relative to configuration directory, sorting/hashing independent of cwd; Windows psql discovery includes per-runner drive layout without deleting or provisioning services. No new /var-vs-/private/var path comparison or borrowed platform handle introduced.
- Root Windows exact-input proof/result JSON checked:40 launches pass (debug/release, ordinary/normal-exit coverage-guard),4 CLI failures expected. Dependency install no-op because matching prior outputs; no full Windows application suite or instrumented coverage claim. No fresh whole macOS build reported; earlier AppleClang/HomebrewClang24 narrow macro/callback variants only. Linux current-base sanitizer campaign pending. Supported graph reasoning is source evidence, not substitute native execution.
===== END cross-platform.txt =====

===== BEGIN gateway-erlang.txt bytes=2411 sha256=2b73c9e8e7c3d3d839f4ff817d3561179bbcb16c060d5342c53a41ac80f1492b =====
Gate3 gateway-erlang — SOURCE PASS, fresh gateway runtime/Dialyzer evidence pending; no new finding.
Scope: ea21d7f019770a2d0e6075ad7d27c7e90438dcb7 + staged patch f282726ecf5fab4617d45c9f9fa921b1854421742eddbe304bc882d687828f35. Gate1 and Gate2 security/docs context consumed. Canonical shared severity/prose rules govern, not older native severity examples. Read-only source review; no tests or network actions by this reviewer. Roles are sequential views by routing, not independent convergence. Prior full-file review is reused only for verified identical bytes, with all current deltas and integration context freshly read (source-identity.json, since-frozen.diff, domain-context.diff). Historical governance.d/20261110 artifacts remain old-base evidence.

Actual gateway-erlang brief loaded; erlang-gateway-build.md identical to prior complete read. Current full modified fixtures identical to frozen reviewed bytes; crl helper and cert-fixture changed sites freshly reread. Source echo: “EdDSA keeps its intrinsic digest; OTP ignores this option for Ed keys.”
- ca/2 EC/RSA explicitly request sha256 from pkix_test_root_cert, replacing the implicit SHA1 choice rejected by modern host crypto policies. Ed25519/Ed448 remain intrinsic algorithms. Leaf options supply sha256 for RSA/ordinary EC; Ed keys retain EdDSA semantics. Existing CRL sign/OID selection stays RSA-SHA256, EC-SHA384, EdDSA-none. Thus cert and CRL algorithms need not be identical; each cert/CRL signature describes its actual signer.
- equal_size_rsa_pems keeps its generated-equal-length search; validity-change fixture still tests bytes changing under same size/mtime, not an assumed ECDSA signature length. Salted temp directory cleanup and atomic replace unchanged. No new process, mock, link, ETS table, registered name, listener setting or proto field.
- Upstream gateway management identity defaults changed elsewhere; these fixtures do not alter authority/CRL validation. No weakened pin, EKU, CA or revocation decision. Older runtime helper probe evidence is explicitly historical, not rerun on current base.
- Current OTP pin remains28.4+ within28.x. Root validation must supply actual current EUnit/CT counts and mandatory Dialyzer result; compile alone is insufficient. Proper --dir and no accidental --module double-run requirements preserved. ADR0035 agent-only Windows does not itself remove gateway registration.
===== END gateway-erlang.txt =====

===== BEGIN release-deploy.txt bytes=2572 sha256=436fcdc3d2255fc908abb319631fef3d19bbe9549112b8a75762a6a83c42180e =====
Gate3 release-deploy — SOURCE PASS; no new finding, no publication authorized/performed.
Scope: ea21d7f019770a2d0e6075ad7d27c7e90438dcb7 + staged patch f282726ecf5fab4617d45c9f9fa921b1854421742eddbe304bc882d687828f35. Gate1 and Gate2 security/docs context consumed. Canonical shared severity/prose rules govern, not older native severity examples. Read-only source review; no tests or network actions by this reviewer. Roles are sequential views by routing, not independent convergence. Prior full-file review is reused only for verified identical bytes, with all current deltas and integration context freshly read (source-identity.json, since-frozen.diff, domain-context.diff). Historical governance.d/20261110 artifacts remain old-base evidence.

Actual release-deploy brief loaded. Its historical Windows/macOS server matrix and SQLite/rolling-upgrade narrative do not override current accepted ADR0035/Postgres/fresh-deployment contracts. No release skill invocation/tag/deployment is implied by this review.
- Every modified Dockerfile is byte-identical to previously fully reviewed source: agent, agent.chisel, ci, server, server.chisel COPY ports before dependency install. Build context includes parent license and complete inherited helpers/patches. Runtime users/CMD/TLS flags/certificate volume ownership/listeners remain unchanged; no key-bearing mount added to agent.
- Imported recipe remains pinned9eec002df1cd109f8f104cd966a763daf9751489; source archive SHA/inherited patches retained. Local00017 and README are excluded from Microsoft attribution, while ports/LICENSE-vcpkg.txt carries full MIT notice. NOTICE+license match supplemental final manifest, not initial pre-license source archive. No runtime rebuild is falsely inferred from an attribution-only correction.
- Current upstream ADR0035 release workflow now builds/ships agent-only Windows/macOS; staged changes do not restore deleted server installer or old archive. Linux server packaging and existing compose version pins unchanged. No new flag/env/schema or migration/rollback procedure; build guide documents explicit dependency rebuild because stale installed prefix cannot pick up patch automatically.
- Worker cleanup changes dependency runtime used in agent/server, so complete current application/sanitizer validation remains necessary; focused Windows repeated runner does not attest installers/images/full application. No Docker image rebuild/release smoke is claimed by this role. Historical f4c artifact retains old scope; current run needs its own ledger/report joined to ea21.
===== END release-deploy.txt =====

===== BEGIN happy-path.txt bytes=3997 sha256=ba13ab7670ce4a0be14dd84a5f43c373c6a6b5874c1fae8ac2da1a4b07abbc13 =====
Gate4 happy-path — SOURCE PASS; no findings
Base ea21d7f019770a2d0e6075ad7d27c7e90438dcb7 + staged patch f282726ecf5fab4617d45c9f9fa921b1854421742eddbe304bc882d687828f35. Current actual happy-path brief, canonical shared preamble/Gate4 contract, Gate1 and all eight Gate3 reports read. Same sequential reviewer as earlier C++/docs roles; no independence claim. Source echo: "return false; // txn dtor rolls back" (PgPool::run_in_txn).

Normal flow traces:
1. Engine rotation: REST authenticates/perm-checks Security:Write, refuses engine-class callers, step-ups each call and parses overlap; MCP retains tier/permission/engine restrictions and the existing step-up pipeline. Both pass authenticated username into the same store. Valid one-active input takes advisory lock, reads current rows, mints successor and stamps predecessor in one transaction, commits, checks pair still pending and publishes raw cache. Checked structural successor read supplies identifiers; successful reveal audit precedes secret response. REST retains no-store headers; MCP returns the existing payload. No new route/permission/schema.
2. Idempotency: same-operator retry within epoch and resident RAM grace returns the SAME successor secret, not another credential. Its request still owes step-up/reveal audit. During normal concurrent publication, different operator now gets existing conflict classification from durable initiator; same operator without a RAM entry still gets existing grace conflict. This does not turn a former successful duplicate into an error: uncached re-serve already failed. Epoch expiry remains first. The change does not extend grace or make restart/cross-replica replay successful. Human rotation retains its earlier owner check.
3. Upstream integration: valid text parameters pass new pg_exec NUL validation unchanged. PgPool retains lease→transaction declaration ordering; only callbacktrue with INTRANS commits. Added denialfalse cannot proceed to postcommit cache publication. PgTxn's upstream aborted-state correction adds no extra rollback on this successful path. Secret scope guard remains armed before generation.
4. Runtime: server/regression main installs sole default-engine ownership, initializes gRPC, runs Catch, destroys Session, blocks shutdown and clears default engine. Worker drains callbacks, scoped crypto cleanup runs, then unique_ptr retires worker count. Sanitizer/coverage returns normally; ordinary Windows/macOS applies retained hard_exit after explicit teardown. Agent main pins no pool. Lifetime regression actually schedules public/private RNG and observes completion, with shared-owned promise.
5. ADR0035 agent-only Windows/macOS still build standalone lifetime fixture using Catch/grpc/OpenSSL alone; no server/libpq edge. Current agent suite selection includes its dual label. No control-plane binary/support is reinstated.
6. Build flow: valid overlay configuration resolves paths relative to configuration, hashes sorted filenames/content, combines baseline/triplet/manifest inputs. Unchanged state is a no-op; changed overlay invalidates prefix/registry and next install rebuilds it. Python probe selects a working interpreter. Docker copies full ports before install; cache classifier/key agree, with attribution included.
7. Fixtures: Guardian settles x, parks a, observes pending, releases/drains and acknowledges only after clean sync. Instruction mock records logical completion before response visibility; MCP subprocess delivers EOF then communicates safely. Gateway valid RSA/EC fixtures request SHA256; Ed keys preserve intrinsic signing semantics.

No new CLI/env/plugin/proto surface requires an unrelated end-to-end trace. All traces are code reasoning, not tests executed here. Current Windows40focused passes+4expectedCLI results are root-owned and scoped; current Linux full campaign remains pending. Historical f4c reports do not substitute for it. No speculative failure list or artificial severity rows generated. Await Gate6.
===== END happy-path.txt =====

===== BEGIN unhappy-path.txt bytes=6016 sha256=7ea5c6da7aa908683706248d963c6d54151aa313174dfa98b7b226257f81d309 =====
Gate4 unhappy-path — ea21d7f019770a2d0e6075ad7d27c7e90438dcb7 + staged patch f282726ecf5fab4617d45c9f9fa921b1854421742eddbe304bc882d687828f35
Finding risk register: EMPTY. No new observed or code-supported defect, speculative allegation, or policy-floor violation. Source review complete; runtime campaign pending. This is not proof that all failures are impossible.

Read actual unhappy-path brief and canonical Gate4 contract; shared preamble already read in full this run. Consumed Gate1, security/docs, all eight Gate3 role reports. These are context, not independent rediscovery. Prior full reads retained only with byte identity; freshly traced current rotation/confirm/sweep and pg transaction boundaries, sentinel failure path, runner destruction, upstream platform graph. No tests/network/source edits.

Failure boundaries: operator→REST/MCP→principal-locked PG transaction→RAM publication; Catch session→gRPC default engine→detached worker→OpenSSL; config/filesystem→sentinel→installed-prefix/cache; fixture logical completion→socket/process publication. No new plugin/wire/network admission surface.

Mutation × state audit:
States: no active row; one clean predecessor; two valid linked rows (RAM absent/present/expired, durable owner empty/matching/different); malformed/overfull; resolved sole survivor; revoked/expired members.
Operations: initial mint, engine/human rotate, engine/human confirm, individual revoke with partner resolve, principal-wide revoke, presentation/last-used update, RAM scrub/eviction, automatic sweep. Initial mint’s separate ceiling/referent constraints unchanged. Rotate refuses no-active/malformed/overfull/unresolved state; one clean row atomically mints+stamps; linked retry applies epoch→durable denial→RAM freshness→RAM owner. Human rotate additionally rechecks predecessor ownership/authority under lock. Confirm positively classifies state and pins successor+initiator+proof; resolved/malformed states are terminal rather than retry storms. Individual revoke clears surviving linkage; principal revoke intentionally terminates credentials. Presentation changes last-used only. Sweep rechecks live, used successor and positive predecessor overlap under lock, then revokes+clears atomically. RAM cleanup never grants authority. These operations retain their existing semantics under the new denial; no newly introduced zero-credential terminal or unrecoverable pair was found.

The following are validation scenarios, NOT findings; no severity assigned to working behavior:
S1 Publication gap + competing operator: new durable check at api_token_store.cpp:1649 refuses before RAM reserve. Same operator gets existing grace conflict until publication. No raw secret disclosed.
S2 Lost response/restart: raw cache forfeited; durable identity permits only confirm identity resolution, still requiring exact successor/proof. It never reconstructs raw token. Recovery remains explicit confirm/revoke, not blind remint.
S3 Grace expiry + other operator: epoch refusal keeps precedence; same-owner stale RAM cannot extend window. Confirm uses separate identity semantics, not raw-reveal deadline.
S4 DB read/acquire/BEGIN/COMMIT failure: no success publication. PgPool402–430 callbackfalse rolls back before lease return; upstream NUL refusal aborts and PgTxn rejects aborted commit. ScopeExit scrubs plaintext locals. Sweeper commitfalse increments failed_pairs even after lambda chose revoke.
S5 Manual successor revoke between sweep scan/write: under-lock EXISTS requires live used successor; cleared overlap prevents predecessor retirement. Manual predecessor revoke clears survivor; failed best-effort resolution is surfaced as unresolved metadata, not fabricated clean state.
S6 Malformed/overfull/out-of-band rows: no arbitration or secret recovery. Empty durable owner does not bypass RAM owner; mismatch refuses. Sole residual metadata produces terminal inspect/recovery guidance.
S7 Reveal audit/readback failure after committed mint: REST/MCP withhold secret; partial state is acknowledged, retry policy distinguishes unavailable read from positively absent linked pair. New deny uses existing terminal Conflict mapping and failure audit.
S8 CLI failure/Catch unwind: Session destroyed before SuiteGrpcRuntime; balanced shutdown runs even when applyCommandLine returns error. Main hard_exit cannot precede run_suite destruction.
S9 Worker completion/timeout: callback retains shared promise; REQUIRE timeout cannot dangle stack capture. Scoped crypto stops before unique_ptr ThreadState retires count. Stuck/custom work still belongs to its fixture; no native-thread-join claim. Actual sanitizer normal exit is necessary evidence, not replaced by assertions.
S10 Agent fork and upstream collectors: agent entry does not pin pool; new installed-software teardown remains owned by agent/fixtures. Standalone regression uses its own process, compatible with ADR0035 agent-only builds.
S11 Missing/malformed overlay, unreadable input, broken Python alias: hashing/probing fails before invalidation; working python fallback selected. Warm stale prefix reconciled before install; canary save requires producer success. Existing removal-error behavior is unchanged, not a newly discovered fix regression.
S12 Fixture early failure/delayed response: Guardian Rig teardown releases parked gates before owners disappear; Python decrements logical inflight once before response and finally handles failure; closed subprocess stdin is nulled before communicate. Gateway digest fixtures alter no trust gate/process lifecycle.

Gate5 input: zero unhappy-path findings. Scenarios above may inform root’s current repeats/fault checks but do not manufacture a chaos-triggering finding. Root combines with consistency result for the conditional Gate5 decision. Current Windows40+4 focused observations are root evidence; current Linux sanitizer/full-suite status remains pending, historical176-entry results are not this base’s179-entry coverage.
===== END unhappy-path.txt =====

===== BEGIN consistency-auditor.txt bytes=4036 sha256=8a5d3030ea6080c64c8a04ad45e723256a408bf59471c481cc6f7df45c355d6c =====
Gate4 consistency-auditor — root, current ea21d7f019770a2d0e6075ad7d27c7e90438dcb7 plus staged fix
Actual current brief, canonical severity/policy preamble, Gate1 summary/resource/routing, current security/docs and domain reports read. Current agentic-first A1–A5 loaded (large-output middle recovered in bounded read); targeted current code/contracts traced. This is root's review, not an independent rediscovery of prior findings. No new finding; source PASS, runtime pending.

Temporal contract: ApiTokenStore cpp1649–1675 compares durable initiator only after epoch expiry and before RAM reservation. Durable presence can deny another operator but cannot mint/reveal a missing raw secret; same operator without RAM gets existing grace conflict, and retry after publication uses existing RAM owner. No new state/schema/identifier/timebase; existing transaction, linked-pair checks and raw scrub guards remain. New branch emits an already-existing exact message, not an unclassified error vocabulary. Shared engine_store_error_class.hpp150 maps both different-operator and grace expiry to Conflict; current REST rotate caller7095ff supplies authenticated session username and routes error through existing status/envelope/audit; MCP29760ff supplies same username and maps same shared Conflict to kInvalidParams (6883ff), no retry hint. Existing metadata and response shapes remain consistent. Different wire status numbers reflect protocol vocabulary, not semantic divergence. Human rotation remains own-predecessor-only before the analogous grace path.

No staged route/tool/permission/discovery/schema/handshake addition; A1/A2/A3/A5 new-capability backfill triggers do not arise merely because an existing denial classification becomes correct in a publication gap. A4 existing terminal-conflict behavior remains truthful. A5 existing overdue #2990 review-date row is unchanged/pre-existing; enterprise-readiness owns that finding/disposition, not a second issue here. No claim that fallback implementation is fixed.

Cross-runtime: callback patch/README/build guide consistently distinguish callbacks drained → implicit worker OpenSSL state released → ThreadState retirement, and explicitly do not claim OS-thread join/custom-engine coverage. Shared test runner owns server default engine; agent runner remains unpinned for fork quiescence. Current Meson standalone lifetime target has agent/server labels and only Catch/gRPC/OpenSSL dependencies, so upstream ADR0035 agent-only Windows/macOS does not silently omit it. Normal exit under sanitizer/coverage remains the observed boundary; coverage guard is not measured coverage. Root's Windows40+4 focused rerun and Clang24 stand-in checks cannot certify full platform application suites.

Dependency consistency: all five staged Docker contexts COPY ports/ before dependency use. Canary restore hash includes ports/** and existing compact prefix; restore fallback is a prefix of primary, save reuses cache-primary-key and remains guarded by producing install success and trust selection. Classifier ports/* case matches nested paths under bash semantics; new local sentinel38/0 and classifier54/0 checks passed on current worktree. Overlay baseline/recipe/local revision and private secure-target macro remain aligned; no new cache-sharing privilege or runner-label assumption. Existing local-runner persistent cache model unchanged. Exact MIT notice stays at overlay parent, scoped NOTICE prevents attributing local patch to upstream.

Gateway digest selection modifies test certificate generation only; no wire protocol/trust setting altered. Guardian accepted-but-pending fixture and Python response-publication observation now follow completion boundaries they assert; no product state semantics changed. Changelog and auth/build/CI descriptions agree with these bounded behaviors. Current run uses179 configured entries; prior176 counts are explicitly historical. No new consistency chaos candidate; finite runtime validation remains required before overall PASS.
===== END consistency-auditor.txt =====

===== BEGIN compliance-officer.txt bytes=4775 sha256=6e6bc2d1a3a476e99377a8449668b788afd1198dcf5532388fa213f7c615804e =====
Gate6 Compliance Review — ea21d7f019770a2d0e6075ad7d27c7e90438dcb7 + staged fix,2026-11-12
No new compliance finding. Source controls review PASS; full currentbase Linux campaign still pending, no overall governance/operating-effectiveness claim.

Actual current compliance-officer brief, canonical shared preamble and Gate6 contract read; current Gate1/resource ledger, Gate2/3 and all Gate4 reports consumed. Gate4 reports no findings; root's conditional Gate5 skip is not a chaos PASS. SOC2 plan workstreams A/B/C/E/F control/evidence requirements consulted afresh, D/G context retained from prior review. Full changed-source coverage uses exact-byte prior reads plus all current deltas/context as documented in docs-writer/C++ reports; this role is sequential, not independent rediscovery. Source echo: "The above copyright notice and this permission notice shall be included in all copies".

Control Impact:
- CC6.1/CC6.3, Workstream B: durable initiator refusal strengthens competing-operator handling during publication without changing grant populations, credential expiry, required step-up or same-owner RAM replay. Existing access-review artifacts continue to represent authorization; no new entitlement/source of secret authority. Existing route failure audit handles the new refusal; successful reveal remains separately audited before returning a secret.
- CC7.2: no audit retention, action names, exporter membership, evidence format or metric labels change. Raw tokens are not newly logged or persisted. Current PgTxn/parameter hardening upstream preserves failure/rollback and cannot cause cache publication after a failed transaction. Existing audit success/partial/failure distinctions remain honest.
- Workstream C: worker TLS state is cleaned by scoped ownership on its worker before retirement. This changes lifetime, not cipher strength, key storage, trust roots or peer verification. Test certificates use explicit allowed signing digests without weakening production verification. No new global crypto shutdown primitive or exception waiver.
- CC8.1, Workstream F: exact source/base and review history must remain distinct. Current review is ea21; old176-entry f4c results are historical. New runtime fixture retains duration output, normal-exit sanitizer evidence and producer-guarded dependency caching; it does not suppress failures to obtain green. ADR0035 agent-only Windows/macOS is upstream accepted scope, not a hidden reduction made by this fix.
- Workstream E: no new store/schema, customer collection, retention or deletion behavior. PG fixture databases/temp paths are isolated test resources; modified sweep code adds executable discovery only, not broader deletion authority.

License/ownership verification: current imported recipe/helpers/inherited patches retain exact pinned vcpkg MIT bytes. Read-only comparison against local git-show of9eec002df1cd109f8f104cd966a763daf9751489:LICENSE.txt returned True. NOTICE82–87 accurately excludes local00017/README from upstream attribution; COPY ports includes parent notice. Original omission was corrected before this run and is not re-raised as a new finding. Resource Ledger covers14categories; scoped worker/crypto owners need no manual-cleanup exception. Caller-owned engines/threads remain caller obligations.

Evidence Impact: root current sentinel38/classifier54 logs read; reported compiler checks are24macro variants (not a compiler named Clang24), using the recorded Homebrew/Apple toolchains. Windows40focused current-input-verified launches+4expectedCLI failures are root evidence, not full application or coverage instrumentation. Dependency-input-comparison records20paths unchanged since priorbase, so cache reuse/no-op install must not be described as a fresh full dependency rebuild. Current application source includes upstream changes and still requires fresh Linux full results with actual entry counts and source hash. Raw environment credentials must not be copied into review prose; preserve sanitized portable artifacts and ownership of originals.

Policy Impact: no new product policy or incident procedure required. Secure-SDLC evidence remains incomplete until runtime closes; source PASS does not certify scans/tests not yet observed. Historical governance artifacts retain their oldbase identity and the new ledger/report must carry this run separately.
Risk Impact: no newly demonstrated compliance risk. Existing overdue A5 #2990 review metadata belongs to enterprise-readiness's mandatory current ledger review, not silent renewal or an invented new runtime flaw here.
Verdict: no new findings; compliance source PASS with current runtime/evidence completion outstanding. No source edits, test executions, network calls or external mutations performed.
===== END compliance-officer.txt =====

===== BEGIN sre.txt bytes=2650 sha256=50aa0387d6b60602acbc3e0ea5798e6dd903c6912225dff9c1f48c7adbcc6319 =====
Operational Readiness Review — Gate 6
Base ea21d7f019770a2d0e6075ad7d27c7e90438dcb7 plus staged patch f282726ecf5fab4617d45c9f9fa921b1854421742eddbe304bc882d687828f35.
Root applied the actual sre brief, canonical governance severity rules and current SOC 2 Workstream D. Coverage is collective with the source-identity-verified prior full reads and fresh integration/context review described in Gate 1 and domain reports; it is not independent repeated full-file convergence.

Observability: No new metric, audit envelope, lifecycle event, production endpoint or health dependency is introduced. Rotation ownership denial follows the existing caller error/audit paths; current REST and MCP paths were traced in consistency review. No new monitoring contract or SLO is implied by the shutdown repair. Sanitizer exit and test counts must establish the runtime result rather than a successful build alone.
Deployment: All five changed Docker recipes copy the overlay before dependency installation. Cache/sentinel changes prevent an old dependency prefix from silently substituting for the patched runtime; documented dependency rebuild remains necessary on changed inputs. Current inputs are identical to the previously built patched dependencies, so current no-op installation is reuse, not a new dependency rebuild. No service users, mounts, listeners, release pins or deployment security settings change. Current ADR0035 Linux server / Windows and macOS agent scope governs, not historical server matrix text.
Recovery: No schema or backup format changes. The rotation guard preserves durable initiator denial ahead of RAM replay reservation; RAM-only secret replay does not become durable disaster recovery. Dependency rollback requires rebuilding against the selected recipe; it is not a database rollback. No RTO/RPO improvement is claimed.
Capacity: Worker OpenSSL cleanup occurs before retirement on the affected callback path, without a general claim of joining all native workers or custom EventEngines. Test runtime ownership is suite-bounded and teardown occurs through the normal exit path. No production unbounded queue, retry loop, cache or new pool is introduced. Build-host storage currently has about 76 GiB free; this is execution headroom, not a production capacity claim.
Verdict: SOURCE PASS, no new SRE finding. Empirical current-base Linux ASan/UBSan and TSan full-suite results remain pending. Windows evidence covers focused shared-runner/dependency integration only; Clang variants are narrow callback ownership checks, not a full macOS application build. No deployment or operating-effectiveness certification is implied.
===== END sre.txt =====

===== BEGIN enterprise-readiness.txt bytes=6413 sha256=405c8daf19679ae0167d7e3a8cf76ea03577ddd711b05cedc7be8cec5b394957 =====
Enterprise Readiness Review — current-base Gate 6
Base: ea21d7f019770a2d0e6075ad7d27c7e90438dcb7 plus staged change.
Patch SHA-256: f282726ecf5fab4617d45c9f9fa921b1854421742eddbe304bc882d687828f35.
Review date: 2026-11-12. Read-only source review; no tests, remote writes or exception renewal.

Authority and coverage
Actual .claude/agents/enterprise-readiness.md and canonical governance shared preamble/Gate 6 contract applied. Current A5 contract and all six exception rows read: four explicitly CLOSED entries (#2436, #2712, #2986, #2439), one future-dated open entry (#5761, 2027-01-12), and the stale open #2990 entry. Every entry has an issue reference; closed entries use closed status rather than a future revisit date. SOC 2 plan current sections reviewed: A/B requirements and evidence (40–100), credential-confirm control (472–484), C/D/E requirements (758–825), F/G (1053–1132), with relevant search/context. This is scoped reference-document reading, not a claim to freshly read all 1,251 lines. Current source and changed operator-doc coverage is collective and attributed to security-guardian, docs-writer, domain reports, happy-path, unhappy-path and consistency-auditor; prior full reads are reused only through the source-identity manifest and current-delta reviews. No claim of independent repeated full-file convergence.
Gate 1/resource ledger and Gate 2–4 conclusions inform this review. Root reports Gate 5 conditional SKIP because Gate 4 produced no findings requiring chaos work; validation scenario guidance is not a finding.

Documentation Impact
Authentication documentation now describes durable initiator denial before replay-cache reservation and confines secret replay to the same operator's live RAM state. The shipped change preserves the credential-confirm pinning control described in the SOC 2 plan. Existing REST/MCP permission and audit boundaries remain represented by current source reviews. No new store, network endpoint, configuration option, migration or data category requires a new operator or DPA contract. Build/CI documentation reflects shared test-runtime ownership and its limits; it makes no general native-thread join promise. Changelog and current-base evidence must retain their own scope; staged older governance artifacts are historical f4c evidence.

Assurance Impact
Workstream B's rotation control gains a stricter durable ownership check, not a new grant or permission model. Do not describe RAM-only replay as durable recovery, replica-wide secret retrieval, or a change to maker-checker confirmation. Workstream F evidence includes exact source/overlay identity and the restored MIT attribution for imported vcpkg materials. CI registration and test counts remain necessary evidence; a zero-case success would not establish effectiveness. Workstream G must continue disclosing the existing streamed-final envelope residual. One exception-review metadata finding follows.

Finding enterprise-readiness-001
Title: A5 streamed-final exception has an overdue revisit date.
Location: docs/agentic-first-principle.md:123 (also summarized at line 111).
Introduced by this change: no; pre-existing and previously recorded in the historical governance run.
TRIGGER: Gate 6 on 2026-11-12 encounters the open #2990 exception with revisit-by 2026-10-31 and no closure or renewed date in the current ledger.
IMPACT: I9 — no demonstrated additional operational impact from the stale review metadata itself. This finding does not re-derive, lower, waive or renew the underlying runtime envelope gap.
EXPOSURE: E3 — normal governance/customer-assurance review of the exception record; no additional applicable exposure raises or caps.
EPISTEMIC STATUS: verified for the document/date mismatch by direct current-file reading. Issue status is attributed to root's saved read-only response issue-2990-readonly.json, not a new network query by this reviewer: open, needs-triage, no milestone, updated 2026-11-09T09:34:05Z.
Derived severity: INFO (I9, E3, no modifiers). Native severity: LOW. Blocking: no. Policy floor: none.
Evidence/provenance: current row and saved issue response corroborate the old finding; this is a current re-verification of an existing defect, not a second independent discovery. Historical enterprise-readiness-001 is a different run identity.
Recommendation: retain an explicit local linked-to-#2990 disposition and have its owner review the expired exception metadata. A fresh date must reflect an actual review; this report does not supply one. Issue URL: https://github.com/DevNullLtd/Yuzu/issues/2990 . KEEPLOCAL: no external issue/comment or roadmap mutation performed.

Deployment Impact
The staged overlay remains pinned to the project baseline with deterministic cache invalidation and Docker COPY coverage, including parent license notice. It does not change supported production topology. Current upstream ADR-0035 limits the server to Linux and Windows/macOS to agent builds; an unconditional standalone shared-runtime test fixture has no server/libpq dependency and does not reverse that boundary. Focused Windows runner validation does not establish full agent packaging or enterprise installer compatibility. No new installer changes are in the staged slice.

Integration Impact
No new ports, IdP protocols, SIEM formats or external credentials. Existing rotation denials retain REST/MCP error classification and audit paths; this source conclusion does not claim an independently executed live customer integration. Test-only gateway certificate signing changes preserve the production trust boundary.

Verdict
Source review complete with one non-blocking pre-existing INFO finding above; no newly introduced enterprise-readiness defect identified. Overall governance/runtime verdict remains pending. Root's current Windows evidence covers 40 successful focused runner executions and four expected CLI failures over matching debug/release dependency outputs; current dependency installs were no-op reuse, not fresh rebuilds. The coverage environment exercises the normal-exit coverage-guard branch, not instrumentation coverage. No full Windows project/installer or full macOS build claim is made. Historical 24 narrow native Clang variants and historical f4c Linux campaigns are not current whole-platform validation. Fresh current Linux sanitizer/full-test campaign remains pending root/validation evidence.
===== END enterprise-readiness.txt =====

===== BEGIN gate5.txt bytes=353 sha256=4847a21ee221d3dfb7842d25da1cf78fec362d78ddfdfc8ff187256598e07301 =====
Gate 5: SKIPPED under the canonical conditional gate. Current Gate 4 happy-path, unhappy-path and consistency-auditor reviews report no findings requiring chaos analysis. The unhappy-path scenario list is validation guidance, not a finding. This is not a claim that chaos testing passed. Linux sanitizer/runtime validation remains required and pending.
===== END gate5.txt =====

===== BEGIN routing.txt bytes=19798 sha256=17da5031ce169253b4498add3605382dd3c1947601f8ec2ec45393f7ff93505d =====
Gate 0/1 ROUTING — current staged delta at ea21d7f019770a2d0e6075ad7d27c7e90438dcb7
Scope: 45 staged paths. f4c2c95aa77bfc573614bdb381a010fc2a15d366→ea21d7f01 is integration context, not 282 newly authored files. Historical governance.d/20261110-nightly-integration.724d95.* describes OLD BASE, not this run.
Currency: see currency.txt; all nine paths byte-identical origin/dev. Root reports successful fresh git fetch this turn and origin/dev==ea21d7f01; reviewer comparison itself read-only.
Read canonical Step0/preamble/Gate2/matrix and actual workflow-orchestrator/security briefs. Canonical derived bands and independent floors override older agent native severity prose.
Memory search: rg --files --hidden across ~/.claude, ~/.codex and both checkout .claude roots found no matching feedback_governance_run.md, feedback_test_quality.md, feedback_claude_md_scope.md. This is a searched-location result, not global absence.
Every row below was opened/read; nonmatches refer to STAGED delta only, not upstream context.

TABLE routed-concerns.md
16: NO DIRECT MATCH: Executions-history ladder — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
17: NO DIRECT MATCH: Compliance evaluation pipeline — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
18: NO DIRECT MATCH: `/auto` Pre-flight readiness — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
19: NO DIRECT MATCH: `/auto` Deploy (the ACT stage after pre-flight ASSESS) — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
20: NO DIRECT MATCH: **Artifact signature verification — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
21: MATCH: C++23 conventions, naming, headers, plugin ABI boundary — C++23: cpp-expert; docs/cpp-conventions.md
22: MATCH: C++ resource ownership and lifetime — C++ ownership: cpp-safety + security; cpp-conventions/native-objcpp docs
23: MATCH: macOS workflow + Darwin pitfalls table — Darwin-affecting shared runner/overlay: cross-platform; darwin-compat
24: NO DIRECT MATCH: Prometheus metrics, label set, audit envelope, event format, and the SHIPPED ALERT RULES — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
25: NO DIRECT MATCH: Response data types, audit envelope, inventory data for analytics — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
26: MATCH: User manual / YAML defs / REST API / Substrate primitive registration — Every change: docs-writer brief
27: MATCH: Guardian / Guaranteed State — Guardian test: security + docs; Guardian design, Windows implementation, DEX catalog, Spark delta registry
28: MATCH: Spark detection layer (ADR-0021) — Conservative semantic match: Guardian Spark test; security + cpp-safety; Spark ADR0021/consumer design/delta registry.
29: NO DIRECT MATCH: Echo dashboard — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
30: NO DIRECT MATCH: Device quarantine / containment — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
31: NO DIRECT MATCH: Scope walking — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
32: NO DIRECT MATCH: System architecture — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
33: NO DIRECT MATCH: Tag/scope DSL operator reference — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
34: MATCH: Agentic-first invariants A1–A5 — Every PR: consistency; agentic-first-principle; no new route/tool
35: NO DIRECT MATCH: Enterprise-platform parity matrix — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
36: MATCH: CI cache patterns — vcpkg cache wiring: build-ci; ci-cache skill
37: NO DIRECT MATCH: Fleet visualization (3D) — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
38: NO DIRECT MATCH: Network quality dashboard (`/network`) — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
39: NO DIRECT MATCH: Device pages (`/devices` + `/device?id=`) — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
40: NO DIRECT MATCH: OS capability matrix — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
41: NO DIRECT MATCH: Agent daily-sync framework + installed-software inventory (ADR-0016) — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
42: NO DIRECT MATCH: SQLite `sqlite3_changes()` after `step()` on a shared FULLMUTEX connection is a data race + correctness bug (r — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
43: MATCH: **Clock-guarded retention** — Test DB sweep classification: conservatively cpp-safety/sre/compliance clock-guarded retention context; no new production prune
44: MATCH: **Server storage substrate — ApiTokenStore: architect+sre; ADR0006/7/8/10/12, PG playbook/ladder; no new schema/secret column
45: NO DIRECT MATCH: `common/include/` shared-header firewall between `server/core` and `agents/` (#2549) — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
46: NO DIRECT MATCH: **Durable agent command idempotency (HA WS-0, ADR-2002)** — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
47: NO DIRECT MATCH: **Agent OTA pull bounds (#913/#911)** — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
48: NO DIRECT MATCH: **Confined filesystem deletion — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
49: MATCH: Unit-test conventions — Unit tests: QE; unit-test conventions
50: NO DIRECT MATCH: **Echo cursor sources** — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
51: NO DIRECT MATCH: **power_health `set_power_plan`** — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
52: NO DIRECT MATCH: **`app_usage` agent plugin + ADR-0016 daily-sync source — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
53: NO DIRECT MATCH: **`execution_artifacts` plugin — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
54: NO DIRECT MATCH: app-usage server read surface — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
55: NO DIRECT MATCH: `windows_optional_features` plugin — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
56: NO DIRECT MATCH: `peripherals` plugin — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
57: NO DIRECT MATCH: `printing` plugin — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.

TABLE routed-concerns-access-control.md
5: MATCH: Authentication, RBAC, headers, tokens, self-target principal-destruction guard (#397/#403). Every new list/fan — Token rotation: security; auth architecture + engine principal ADR0031 + RBAC ADR0041
6: NO DIRECT MATCH: **Dispatch-caller approval provenance — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
7: NO DIRECT MATCH: **Service-scoped API token confinement — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
8: NO DIRECT MATCH: PKI / internal CA — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
9: NO DIRECT MATCH: AuthDB invariants — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
10: NO DIRECT MATCH: **SCIM ↔ OIDC/SAML identity-link revoke chokepoint (ADR-2001, CC6.8)** — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
11: NO DIRECT MATCH: Periodic Access Reviews (SOC 2 CC6.2): fleet-wide grant export + attestation-campaign lifecycle across all thr — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
12: MATCH: Enterprise A&A roadmap — Auth review: auth-and-authz skill; current auth architecture overrides stale inventory
13: NO DIRECT MATCH: MCP server architecture, tier-before-RBAC ordering, kill switches, audit pattern; Streamable HTTP transport (s — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
14: NO DIRECT MATCH: Per-device dispatch visibility (#1788) + the registry-independent authz model (ADR-0033 §2). CATASTROPHIC: (1) — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
15: NO DIRECT MATCH: **Dispatch targeting — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
16: NO DIRECT MATCH: **Dispatch zero-reach cause discrimination: ONE shared classifier, FIVE hand-copied legacy cascades that diffe — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
17: NO DIRECT MATCH: Agent privilege model — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
18: NO DIRECT MATCH: **Headless platform, process decomposition & access-control spine (ADR-1005 + ADR-0031/0032/0033)** — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
19: NO DIRECT MATCH: **Authorization-topology floor (#2376)** — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
20: NO DIRECT MATCH: **Pre-auth request-body cap (#2407)** - `body_cap_policy.hpp`'s `kBodyCapTable` is the SINGLE chokepoint; EXTE — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
21: NO DIRECT MATCH: **MFA step-up chokepoint**: `kStepUpPolicy` (`step_up_policy.hpp`) is the SINGLE table of mutating routes need — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
22: NO DIRECT MATCH: **Fenced leader election — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
23: NO DIRECT MATCH: **Split merge-gate — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
24: NO DIRECT MATCH: **A2/A1 RBAC administration surface — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.

TABLE routed-concerns-security-posture.md
17: NO DIRECT MATCH: `app_control` plugin — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
18: NO DIRECT MATCH: `firmware_posture` plugin — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
19: NO DIRECT MATCH: `platform_security` plugin — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
20: NO DIRECT MATCH: `local_security_policy` plugin — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
21: NO DIRECT MATCH: `system_hardening` plugin — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
22: NO DIRECT MATCH: **Gateway-upstream peer authorization.** `GatewayPeerGuardedService` is the SOLE production registration of th — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
23: NO DIRECT MATCH: **Gateway origin trust — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
24: NO DIRECT MATCH: **Gateway mgmt-plane peer authorization (#1422, #6016).** `yuzu_gw_authz:check_mgmt_peer/1`, the :50063 `auth_ — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
25: NO DIRECT MATCH: `registry` writes (`set_value`, `delete_value`, `delete_key`). **CATASTROPHIC-IF-VIOLATED:** (1) Mutate only a — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
26: NO DIRECT MATCH: `registry` writes (`set_value`, `delete_value`, `delete_key`, `set_user_value`, `delete_user_value`, `apply`). — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
27: NO DIRECT MATCH: **Same-site gate for cookie-session writes: ONE pre-routing chokepoint.** `apply_same_site_write_gate` (`same_ — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
28: NO DIRECT MATCH: **`virtualization.runtime_posture` — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.

TABLE routed-concerns-software-estate.md
17: NO DIRECT MATCH: **`browser_inventory` plugin (Forensics, default-off, per-user browser data)** — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
18: NO DIRECT MATCH: **`privacy_permissions` plugin (Forensics, default-off, per-app sensitive-permission grants — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
19: NO DIRECT MATCH: **`runtimes` plugin — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
20: NO DIRECT MATCH: **`middleware` plugin: read-only installed-middleware inventory (`Inventory`, table-driven; IBM MQ on Linux as — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
21: NO DIRECT MATCH: **`remote_access_audit` plugin (Forensics, default-off, per-account SSH key data)** — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
22: NO DIRECT MATCH: **Forensics tier on stored-response reads (#4990)**: rows written by plugins on the `Forensics` securable are  — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
23: NO DIRECT MATCH: **`certificate_inventory` daily-sync source and `CertificateInventoryStore` (schema `certificate_inventory_sto — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.
24: NO DIRECT MATCH: **Software title normalisation layer** — No staged change to this row’s listed files or specified behavior; upstream changes considered separately as integration context.

Gate 3 mandatory roster: architect (public store contract/server core), cpp-expert and cpp-safety (C++ plus raw callback owner), quality-engineer (fixes/tests), build-ci (Meson/workflow/vcpkg/cache), cross-platform (shared runner, Windows/macOS normal-vs-hard exit, overlay), gateway-erlang (two Erlang fixture files), release-deploy (five Dockerfiles/overlay packaging). Mandatory Gate2 security/docs; Gate4 happy/unhappy/consistency; Gate6 compliance/sre/enterprise.
No staged plugin/ABI/proto/DSL source change: plugin-developer/dsl-engineer not triggered. No changed per-authentication hot path/get_*_ids/SQLite BFS/query: performance not triggered (operator rotation adds bounded comparison in existing mutation transaction). AuthDB source/session store untouched: authdb not triggered. No new principal, route, permission, dispatch surface, MFA gate, same-site gate, listener configuration, Forensics or runtime-posture plugin behavior. Existing caller parity still must be traced.
Additional loaded context: gateway fixture signing requires erlang-gateway-build and PKI semantics even without direct PKI row match. Test name includes guardian_spark: conservatively load Spark ADR0021/consumer design for teardown truth, though no listed production spark file changed.
Integration impact: upstream accepted ADR0035 retires Windows/macOS server support and changes CI/release to agent-only; current unconditional gRPC regression target and runtime defines must honor that supported scope. Upstream installed-software v3 adds bounded collector ownership/teardown; shared agent runner intentionally does not pin a pool because fork-without-exec death tests require thread quiescence. Upstream Pg exec_params refuses embedded NUL and PgTxn commit rejects aborted txn rather than reporting success; token transaction error cleanup must be rechecked. Upstream RBAC engine-grant/topology and settings caching/audit changes require current caller context, not old auth conclusions. New virtualization runtime-posture routed row does not directly match staged paths.
Gate1 resource inventory/summary supplied separately by root/resource_ledger; this routing report is not a substitute for the mandatory ownership ledger. No runtime tests executed by this reviewer; old validation cannot be represented as new-base full coverage.
===== END routing.txt =====

===== BEGIN resource-inventory.txt bytes=9379 sha256=c8da7ced84b10bdf864e78ee09bf99f71ecacf57cf1854ecc4f5058d8860640a =====
Gate 1 Resource Ledger — current-base rereview, 2026-11-12
Base ea21d7f019770a2d0e6075ad7d27c7e90438dcb7 plus staged fix. This is inventory, not Gate3 approval. Read current canonical Gate1/resource policy and actual current C++ diff, runner, lifetime test, callback patch and rotation branch. Source echo: "Quiesce observes that retirement, not detached pthread/FLS teardown."
All modified C++/header/test files and complete ports/grpc overlay are byte-identical to the prior fully read final source, verified by SHA256 against prior frozen manifest. Their ownership analysis is reused explicitly, with current branch/source checks; old runtime results are NOT current-base validation. Upstream f4c..ea21 intersection with staged paths is limited to workflow, tests/meson.build, auth/build/CI docs. No production token or runner C++ changed upstream. Build graph now includes ADR0035 agent-only platform scope; domain review must confirm current registration, not assume old Windows server coverage. Raw-resource scan and current exact-patch semantics remain Gate3 duties.

Resource | Owner / acquisition | Release / transfer / failure cleanup
1. Default EventEngine and pool: SuiteGrpcRuntime lifecycle owner; CreateEventEngine returns shared_ptr, moved by SetDefaultEventEngine into strong global default slot before grpc_init. No extra runner shared_ptr retained. Destructor calls grpc_shutdown_blocking then ShutdownDefaultEventEngine, whose inspected implementation removes slot and waits for single ownership. Catch Session is declared later and destroyed first on normal return, command-line error, or C++ unwind after completed construction. Create failure has ordinary temporary shared_ptr cleanup. Agent runner does not compile this owner. Installed-version behavior and any constructor partial-publication failure remain Gate 3 verification obligations.
2. gRPC C initialization reference: SuiteGrpcRuntime obtains one grpc_init reference after engine installation, balances with grpc_shutdown_blocking in destructor, noncopyable. No explicit manual cleanup outside owner. Other suite init refs, custom engines, and caller threads remain their individual fixtures' responsibility; this scope does not imply ownership of them.
3. Catch Session and listener resources: run_suite stack Session, applyCommandLine/session.run; destructor before SuiteGrpcRuntime, including early CLI failure. Existing PG testRunEnded cleanup executes during session.run; main hard_exit is now after run_suite destruction. Sanitizer/coverage paths return normally. stdout/stderr are borrowed process streams, only fprintf/fflush, not acquired/closed here; argc/argv borrowed for call duration.
4. Detached upstream EventEngine workers: existing StartThread allocates new ThreadState(shared_from_this()), transfers void* context to detached grpc_core::Thread callback, and callback immediately adopts it in unique_ptr<ThreadState>. ThreadState holds the pool shared_ptr and living-thread counter. The callback-local owner releases on normal return or ordinary C++ unwind. Upstream thread creation failure/termination behavior is unchanged. No native OS-thread join is introduced; quiescence counts retirement.
5. Worker implicit OpenSSL thread state: crypto callbacks acquire it on that worker. Noncopyable ScopedOpenSslThreadState is declared after the unique_ptr and its destructor calls OPENSSL_thread_stop before worker destruction/counter retirement, on normal return and ordinary unwind. No transfer or global context ownership. Guard applies only secure grpc with supported OpenSSL >=1.1, excluding BoringSSL/LibreSSL. New cleanup is RAII-wrapped; no manual-cleanup exception proposed or self-adjudicated.
6. Upstream local work queue / callback queue / thread-local bookkeeping: ThreadBody new BasicWorkQueue(pool_.get()), enrolls queue, borrows pool through ThreadState's shared_ptr. Fork path moves pending closures into pool queue; shutdown FinishDraining runs them; unenroll then delete queue before new OpenSSL stop. Existing raw callback contexts and bookkeeping retain upstream ownership. Patch cannot attest that arbitrary future thread-local destructors never reenter crypto; its exact boundary is callbacks drained and this thread's current OpenSSL state stopped before retirement.
7. Lifetime regression's EventEngine refs: temporary shared_ptr from GetDefaultEventEngine assigned to weak observed; temporary destroyed before expired assertion. observed.lock gives local shared owner through scheduling and future wait. All local refs destroyed on Catch REQUIRE unwinding as on success; timeout does not cancel queued work but suite-owned engine remains until runner teardown.
8. Lifetime regression promise/future/callback: make_shared<promise<bool>>, one future via get_future; lambda captures shared_ptr by value, EventEngine owns submitted callback until invocation/disposal. Main and lambda release their copies independently; future destroys its shared-state ref. Worker uses stack array<unsigned char,32> passed to RAND_bytes/RAND_priv_bytes only for call duration, no escape. Main-thread RAND_status and worker public/private DRBG allocate implicit OpenSSL thread state. Main state is process/main-thread lifecycle; worker state uses patched cleanup. Callback set_value is single-use; no borrowed stack capture. Timeout REQUIRE unwinds locals safely without invalidating callback's promise.
9. Rotation test PostgreSQL database: YUZU_REQUIRE_PG_DB_TPL creates stack PostgresTestDb from existing apitoken_pg_template. Missing DSN SKIPs before acquisition; unavailable database REQUIRE unwinds fixture. Helper owns salted database name/DSN; scoped PgConn/PgResult wrap admin handles/results. Destructor issues DROP DATABASE IF EXISTS WITH(FORCE), logging failure; this test does not call keep_until_run_end. Template itself uses pre-existing suite/template cleanup lifecycle.
10. Rotation test PgPool and ApiTokenStore: pool declared after DB, store after pool; reverse destruction destroys store, drains pool, then drops DB. PgPool size four owns pooled PGconn (network/TLS resources); destructor blocks until leases/connectors/waiters return and PQfinish closes idle handles. Store borrows pool reference. Test adds no persistent lease or transaction escape.
11. Rotation callback and borrowed test locals: store owns std::function test_hook_before_store_rotation_raw_, capture [&] borrows store, principal, now, interleaved. Called synchronously after transaction commit and before raw-cache publication; nested rejected rotations do not mint and do not recursively invoke hook. Borrowed locals live through invocations; closure destruction does not dereference them even though later-declared locals die before store. Stateless engine-referent callback has no borrowed resources. Returned minted/replay expected<string> values and principal/error strings own their storage; test does not add explicit secret scrubbing beyond existing store guards.
12. Production rotation denial: no new resource acquisition. successor/predecessor pointers borrow entries in local active vector, no mutation/escape before new check. New false return occurs inside existing with_txn_for callback; existing transaction/lease guards and function-scope raw-secret scrub guards remain responsible for rollback/release/scrub. Durable initiator string used only for comparison; no new secret copy or cache reservation. Epoch check still precedes denial; try_reserve still follows it. ApiToken header only documents this existing field's broader denial use.
13. Guardian modified test parked worker: existing Rig owns GuardianEngine/SparkEngine/KvStore via unique_ptr, TempDbFile and TempDir, fake mechanisms owned by SparkEngine with borrowed fm/sm aliases. New hang_next_watch acquires logical gate; wait_entered_hang observes worker parked; release_hang unblocks, drain_until_idle/wait_compliant settle before final sync. On REQUIRE failure before explicit release, Rig::~Rig -> close releases BOTH watch/unwatch gates on BOTH mechanisms before waiting for engine workers, resetting engine, stopping/resetting spark, nulling aliases, resetting KV. Existing bounded wait emits FAIL_CHECK on timeout; inventory does not assert that timeout proves all worker cleanup safe.
14. Guardian existing resources affected by new timing: file paths r1/a/x under TempDir; ofstream creates/closes each file in make_file; TempDir cleanup after engines, TempDbFile last. KV SQLite owned by KvStore. AttachProbe shared_ptr is retained by installed hook (existing helper); callbacks retain fixture borrowing contract. Mutex/CV locks use lock_guard/unique_lock; timed waits release locks on exit. No new OS fd, HANDLE, SOCKET, FILE*, sqlite3_stmt, mapped library, subprocess, BCrypt handle or allocated C string directly introduced in changed C++ beyond wrapped/transitive resources enumerated above.


Resource prose boundaries: current README/runner/build guide distinguish worker cleanup, suite default-engine ownership and caller-owned/custom-engine obligations. Durable initiator comparison is denial-only, never new secret authority. No new C ABI handle/fd/socket/SQLite/OpenSSL allocated-object ownership omitted from changed C++ beyond the wrapped/transitive resources above. No source edits, tests or network actions in this inventory. Fresh runtime validation pending root/validation agent.
===== END resource-inventory.txt =====

===== BEGIN gate1.txt bytes=13533 sha256=0cd9998b3d9e99810b8933e219569506f5be2838c7afa83a1b75b580b4797bdd =====
Gate1 — current-base integration review
Base ea21d7f019770a2d0e6075ad7d27c7e90438dcb7; branch fix/nightly-november-integration, staged uncommitted patch, no publication. HEAD contains upstream only; review range HEAD..INDEX/WORKTREE. Prior f4c..ea21 282 files are upstream integration context, not newly authored scope. Patch contents preserved by rebase ignoring hunk offsets.
Behavior: secure gRPC workers release implicit OpenSSL thread state through scoped guard before unique_ptr worker retirement. Server shared Catch entry owns/drains default EventEngine and balances grpc init; agent entry remains thread-quiescent. Normal exit under sanitizers/coverage, explicit teardown before old hard-exit policy. Real lifetime regression exercises installed runner. Engine token rotation compares durable initiator before cache publication; denial only, epoch/fresh RAM rules retained. Guardian and Python fixtures synchronize observed completion; gateway fixtures specify compatible cert digests. CI sentinel hashes overlay files with working Python fallback, canary classification/cache and Docker contexts carry overlay. Windows psql discovery includes known runner installation. Exact vcpkg license attribution included.
Interfaces: no new REST/MCP route, schema, wire format or plugin ABI. Existing rotation denial classification narrows an erroneous conflict reason; no expanded authority. Dependency/build cache behavior changes. Tests/CI/docs updated; security surface net restricted/neutral.
Current upstream context: ADR0035 Windows/macOS agent-only, CI/release layout; installed-software collector/scheduler lifetime; PgTxn commit and exec_params hardening; tests/Meson/caller additions. Review those interactions at currentHEAD.
Validation at thisHEAD: local source snapshot6325 files frozen; Rocky sync verified, ASan configure/deps check passed and application compiling, full179-entry suites pending. Windows focused rerun pending evidence check. Old176entry suites/governance remain explicitly historical f4c evidence, not current passes. No waiver/independence inflation.
Roles: Gate2security/docs; Gate3architect,cpp-expert,cpp-safety,QE,build-ci,cross-platform,gateway-erlang,release-deploy; Gate4happy/unhappy/consistency; conditionalGate5; Gate6compliance/sre/enterprise; Gate6bworkflow-orchestrator synthesis then fixes/rerouting. Exact rowbyrow match in routing.txt; full resource inventory appended below.

Patch SHA256 f282726ecf5fab4617d45c9f9fa921b1854421742eddbe304bc882d687828f35
Changed paths:
.github/workflows/ci.yml
NOTICE
changelog.d/20261110-nightly-shutdown-rotation.fixed.md
deploy/docker/Dockerfile.agent
deploy/docker/Dockerfile.agent.chisel
deploy/docker/Dockerfile.ci
deploy/docker/Dockerfile.server
deploy/docker/Dockerfile.server.chisel
docs/auth-architecture.md
docs/build-guide.md
docs/ci-architecture.md
gateway/apps/yuzu_gw/test/yuzu_gw_cert_files_tests.erl
gateway/apps/yuzu_gw/test/yuzu_gw_crl_build.erl
governance.d/20261110-nightly-integration.724d95.jsonl
governance.d/20261110-nightly-integration.724d95.md
ports/LICENSE-vcpkg.txt
ports/grpc/00001-fix-uwp.patch
ports/grpc/00002-static-linking-in-linux.patch
ports/grpc/00004-link-gdi32-on-windows.patch
ports/grpc/00005-fix-uwp-error.patch
ports/grpc/00006-utf8-range.patch
ports/grpc/00015-disable-download-archive.patch
ports/grpc/00016-fix-plugin-targets.patch
ports/grpc/00017-openssl-worker-cleanup.patch
ports/grpc/README.txt
ports/grpc/gRPCTargets-vcpkg-tools.cmake
ports/grpc/portfile.cmake
ports/grpc/vcpkg-cmake-wrapper.cmake
ports/grpc/vcpkg.json
scripts/ci/detect-code-change.sh
scripts/ci/sweep-test-databases.sh
scripts/ci/test-vcpkg-sentinel.sh
scripts/ci/vcpkg-triplet-sentinel.sh
server/core/src/api_token_store.cpp
server/core/src/api_token_store.hpp
tests/meson.build
tests/shell/test_build_examples_gating.sh
tests/shell/test_detect_code_change.sh
tests/test_instructions_runner_hardening.py
tests/test_mcp_http_adapter_behaviour.py
tests/unit/server/test_api_token_store.cpp
tests/unit/test_grpc_runtime_lifetime.cpp
tests/unit/test_guardian_spark_reapply_skip_engine.cpp
tests/unit/test_runner_main.cpp
vcpkg-configuration.json

Gate 1 Resource Ledger — current-base rereview, 2026-11-12
Base ea21d7f019770a2d0e6075ad7d27c7e90438dcb7 plus staged fix. This is inventory, not Gate3 approval. Read current canonical Gate1/resource policy and actual current C++ diff, runner, lifetime test, callback patch and rotation branch. Source echo: "Quiesce observes that retirement, not detached pthread/FLS teardown."
All modified C++/header/test files and complete ports/grpc overlay are byte-identical to the prior fully read final source, verified by SHA256 against prior frozen manifest. Their ownership analysis is reused explicitly, with current branch/source checks; old runtime results are NOT current-base validation. Upstream f4c..ea21 intersection with staged paths is limited to workflow, tests/meson.build, auth/build/CI docs. No production token or runner C++ changed upstream. Build graph now includes ADR0035 agent-only platform scope; domain review must confirm current registration, not assume old Windows server coverage. Raw-resource scan and current exact-patch semantics remain Gate3 duties.

Resource | Owner / acquisition | Release / transfer / failure cleanup
1. Default EventEngine and pool: SuiteGrpcRuntime lifecycle owner; CreateEventEngine returns shared_ptr, moved by SetDefaultEventEngine into strong global default slot before grpc_init. No extra runner shared_ptr retained. Destructor calls grpc_shutdown_blocking then ShutdownDefaultEventEngine, whose inspected implementation removes slot and waits for single ownership. Catch Session is declared later and destroyed first on normal return, command-line error, or C++ unwind after completed construction. Create failure has ordinary temporary shared_ptr cleanup. Agent runner does not compile this owner. Installed-version behavior and any constructor partial-publication failure remain Gate 3 verification obligations.
2. gRPC C initialization reference: SuiteGrpcRuntime obtains one grpc_init reference after engine installation, balances with grpc_shutdown_blocking in destructor, noncopyable. No explicit manual cleanup outside owner. Other suite init refs, custom engines, and caller threads remain their individual fixtures' responsibility; this scope does not imply ownership of them.
3. Catch Session and listener resources: run_suite stack Session, applyCommandLine/session.run; destructor before SuiteGrpcRuntime, including early CLI failure. Existing PG testRunEnded cleanup executes during session.run; main hard_exit is now after run_suite destruction. Sanitizer/coverage paths return normally. stdout/stderr are borrowed process streams, only fprintf/fflush, not acquired/closed here; argc/argv borrowed for call duration.
4. Detached upstream EventEngine workers: existing StartThread allocates new ThreadState(shared_from_this()), transfers void* context to detached grpc_core::Thread callback, and callback immediately adopts it in unique_ptr<ThreadState>. ThreadState holds the pool shared_ptr and living-thread counter. The callback-local owner releases on normal return or ordinary C++ unwind. Upstream thread creation failure/termination behavior is unchanged. No native OS-thread join is introduced; quiescence counts retirement.
5. Worker implicit OpenSSL thread state: crypto callbacks acquire it on that worker. Noncopyable ScopedOpenSslThreadState is declared after the unique_ptr and its destructor calls OPENSSL_thread_stop before worker destruction/counter retirement, on normal return and ordinary unwind. No transfer or global context ownership. Guard applies only secure grpc with supported OpenSSL >=1.1, excluding BoringSSL/LibreSSL. New cleanup is RAII-wrapped; no manual-cleanup exception proposed or self-adjudicated.
6. Upstream local work queue / callback queue / thread-local bookkeeping: ThreadBody new BasicWorkQueue(pool_.get()), enrolls queue, borrows pool through ThreadState's shared_ptr. Fork path moves pending closures into pool queue; shutdown FinishDraining runs them; unenroll then delete queue before new OpenSSL stop. Existing raw callback contexts and bookkeeping retain upstream ownership. Patch cannot attest that arbitrary future thread-local destructors never reenter crypto; its exact boundary is callbacks drained and this thread's current OpenSSL state stopped before retirement.
7. Lifetime regression's EventEngine refs: temporary shared_ptr from GetDefaultEventEngine assigned to weak observed; temporary destroyed before expired assertion. observed.lock gives local shared owner through scheduling and future wait. All local refs destroyed on Catch REQUIRE unwinding as on success; timeout does not cancel queued work but suite-owned engine remains until runner teardown.
8. Lifetime regression promise/future/callback: make_shared<promise<bool>>, one future via get_future; lambda captures shared_ptr by value, EventEngine owns submitted callback until invocation/disposal. Main and lambda release their copies independently; future destroys its shared-state ref. Worker uses stack array<unsigned char,32> passed to RAND_bytes/RAND_priv_bytes only for call duration, no escape. Main-thread RAND_status and worker public/private DRBG allocate implicit OpenSSL thread state. Main state is process/main-thread lifecycle; worker state uses patched cleanup. Callback set_value is single-use; no borrowed stack capture. Timeout REQUIRE unwinds locals safely without invalidating callback's promise.
9. Rotation test PostgreSQL database: YUZU_REQUIRE_PG_DB_TPL creates stack PostgresTestDb from existing apitoken_pg_template. Missing DSN SKIPs before acquisition; unavailable database REQUIRE unwinds fixture. Helper owns salted database name/DSN; scoped PgConn/PgResult wrap admin handles/results. Destructor issues DROP DATABASE IF EXISTS WITH(FORCE), logging failure; this test does not call keep_until_run_end. Template itself uses pre-existing suite/template cleanup lifecycle.
10. Rotation test PgPool and ApiTokenStore: pool declared after DB, store after pool; reverse destruction destroys store, drains pool, then drops DB. PgPool size four owns pooled PGconn (network/TLS resources); destructor blocks until leases/connectors/waiters return and PQfinish closes idle handles. Store borrows pool reference. Test adds no persistent lease or transaction escape.
11. Rotation callback and borrowed test locals: store owns std::function test_hook_before_store_rotation_raw_, capture [&] borrows store, principal, now, interleaved. Called synchronously after transaction commit and before raw-cache publication; nested rejected rotations do not mint and do not recursively invoke hook. Borrowed locals live through invocations; closure destruction does not dereference them even though later-declared locals die before store. Stateless engine-referent callback has no borrowed resources. Returned minted/replay expected<string> values and principal/error strings own their storage; test does not add explicit secret scrubbing beyond existing store guards.
12. Production rotation denial: no new resource acquisition. successor/predecessor pointers borrow entries in local active vector, no mutation/escape before new check. New false return occurs inside existing with_txn_for callback; existing transaction/lease guards and function-scope raw-secret scrub guards remain responsible for rollback/release/scrub. Durable initiator string used only for comparison; no new secret copy or cache reservation. Epoch check still precedes denial; try_reserve still follows it. ApiToken header only documents this existing field's broader denial use.
13. Guardian modified test parked worker: existing Rig owns GuardianEngine/SparkEngine/KvStore via unique_ptr, TempDbFile and TempDir, fake mechanisms owned by SparkEngine with borrowed fm/sm aliases. New hang_next_watch acquires logical gate; wait_entered_hang observes worker parked; release_hang unblocks, drain_until_idle/wait_compliant settle before final sync. On REQUIRE failure before explicit release, Rig::~Rig -> close releases BOTH watch/unwatch gates on BOTH mechanisms before waiting for engine workers, resetting engine, stopping/resetting spark, nulling aliases, resetting KV. Existing bounded wait emits FAIL_CHECK on timeout; inventory does not assert that timeout proves all worker cleanup safe.
14. Guardian existing resources affected by new timing: file paths r1/a/x under TempDir; ofstream creates/closes each file in make_file; TempDir cleanup after engines, TempDbFile last. KV SQLite owned by KvStore. AttachProbe shared_ptr is retained by installed hook (existing helper); callbacks retain fixture borrowing contract. Mutex/CV locks use lock_guard/unique_lock; timed waits release locks on exit. No new OS fd, HANDLE, SOCKET, FILE*, sqlite3_stmt, mapped library, subprocess, BCrypt handle or allocated C string directly introduced in changed C++ beyond wrapped/transitive resources enumerated above.


Resource prose boundaries: current README/runner/build guide distinguish worker cleanup, suite default-engine ownership and caller-owned/custom-engine obligations. Durable initiator comparison is denial-only, never new secret authority. No new C ABI handle/fd/socket/SQLite/OpenSSL allocated-object ownership omitted from changed C++ beyond the wrapped/transitive resources above. No source edits, tests or network actions in this inventory. Fresh runtime validation pending root/validation agent.
===== END gate1.txt =====
