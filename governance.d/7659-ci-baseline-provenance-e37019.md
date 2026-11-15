# PR #7659 — CI baseline provenance correction

Status: **PASS** for this incremental CI inventory repair. Source review, local positive/negative controls and native Windows validation complete. This is a fresh incremental governance run over pushed `a11759af636a4c1da53a9dcec74eba172232973c`, not a rewrite of the prior governance report or a claim all CI jobs passed.

The Windows toolchain-contract target failed because its inventory counted five immutable SHA citations as live baseline pins: NOTICE, ports/grpc/README.txt and three historical governance reports. Root reproduced76 checks passed/1 failed locally. CI retained34 other Windows targets passing; the failed target is not retroactively marked green.

The two-path repair adds Get-ActiveBaselineReferences and two regression checks, plus a changelog bullet. The classifier retains the existing docs/reviews exclusion, adds governance.d and exact NOTICE/ports/grpc/README.txt attribution files, and retains every other path. Actual inventory is20 references,5 historical exclusions,15 active consumers matching the updater list. Unlisted scripts and other overlay files remain checked. This does not change dependency resolution, OpenSSL/gRPC production code or the separate obligation to refresh/review the full copied overlay when updating its upstream source.

All nine canonical instruction files match local origin/dev946d90383; all four routing tables were reread (81 rows,3 standing matches/78 nonmatches). Security, docs, build-ci, cross-platform, QA, happy/unhappy/consistency, compliance, SRE and enterprise source reviews found no introduced review findings. Gate5 is conditionally skipped because Gate4 found none; the active-pin negative control is QA regression validation, not an invented chaos pass. No C++ resource ledger applies; no resource acquisition or new process invocation was added.

Verified local retained logs show before76/1, repaired79/0, and a live-pin negative control78/1 failing the original inventory assertion while both new regression checks pass. Root retained control-provenance.txt: the negative control appends the live SHA temporarily to tracked scripts/check-compose-versions.sh, runs the actual PowerShell check and gets exit1, then restores exact original bytes in finally. Positive repair exits0. Native Windows uses a fresh task-owned6,379-file source snapshot/index, executes the exact reviewed test hash d258c5d4f30bc9ab74e796843a2695bb0ce1845d2c3b5389fece571a3039b5a6 and passes79/79 exit0. windows-contract.json and log agree. No host runner/service/registry configuration changes were required; root reports Shulgi lease released after completion. These checks concern the inventory contract only; they do not certify the whole Windows CI matrix, Linux canary or macOS results on a later commit.

Historical CI finding ci-baseline-provenance-001 retains test-only LOW operational impact and the supported-test-leg policy floor in both rows; its fixed disposition is supported by repaired native Windows execution, not a floor waiver. It is captured in a new ledger rather than reopening or mutating the preceding19-row ledger/report. The new two-row ledger records original open and terminal fixed states; every row carries disposition. Independent targeted ledger lint exits0. The source claim covers only the two changed paths and the inventory test. Root reports prior-head Linux/macOS CI passing and canary pending; this report does not independently certify those jobs or claim CI on the forthcoming repair commit has passed. No old review finding severity is changed, no suppression or updater consumer removed, no external publication by reviewers.

## Final artifact identity and process

Reviewed source hashes are recorded in identity.json and rechecked after validation. All nine instruction currency comparisons are true against origin/dev946d90383de751648a741943701b5411902b8bbe. No source changed during review. This new fragment is created exclusively and written once as a complete two-row prepared artifact; root will exclusively create the repository fragment and lint it before commit. There was no in-place schema repair in this run. The prior500k report and19-row ledger remain immutable history, including their disclosed deviations.

Gate summary: Gate1 scope/resource applicability complete; Gate2 security/docs PASS; Gate3 build-ci/cross-platform/QA PASS; Gate4 happy/unhappy/consistency PASS; Gate5 conditionalSKIP; Gate6 compliance/SRE/enterprise PASS; Gate7 original CI defect fixed; Gate8 re-review/runtime evidence and ledger schema complete. Review roles were grouped across two reviewers and are not claimed as eleven independent discoveries. No new review finding was raised; the CI-origin finding is separately retained.

Commit/push and CI verification on the resulting commit remain root-owned subsequent work. This incremental PASS is not permission to discard the prior failed Windows job or declare the complete PR's external CI green early.

===== BEGIN VERBATIM gate1.txt =====
Incremental CI baseline-provenance repair, separate run after pushed HEAD recorded in identity.json. Scope two paths only; prior published500k governance report immutable.
The Windows toolchain inventory interpreted historical review/provenance SHA references as active baseline consumers, causing one of35 CI targets to fail. Production executables and dependency selection unchanged. Extract a pure path classifier that retains existing docs/reviews exclusion and adds governance.d plus exact NOTICE and ports/grpc/README.txt attribution files; regression checks retain active/unlisted pins and other overlay files. Inventory still git-greps current pinned SHA, requires valid updater file list and toolchain-contract membership, and rejects any unlisted active reference.
No C++ resource ledger triggered. No new process/resource acquisition: existing pwsh child checks unchanged; helper filters strings only. No REST/proto/ABI/store/auth/crypto/CLI surface changes. Gate3 build-ci, cross-platform, QA selected; mandatory security/docs, all correctness roles and operations evidence review. All-four routed rowwalk delegated fresh. Canonical skill sharedseverity applies; nine instructioncurrency files compared against local origin/dev with results identity.json. No independent fetch or CI runtime execution by this reviewer.
Parent reports local reproduction76PASS1FAIL, repaired79PASS0FAIL. Actual negative control and nativeWindows validation pending; initial CI failure remains retained. Review pending means no push/CI PASS claim.

===== END VERBATIM gate1.txt =====

===== BEGIN VERBATIM docs-routing-correctness.txt =====
Incremental CI provenance repair — docs, routing, correctness and enterprise review
2026-11-15. Scope: current diff in deploy/windows/Test-ToolchainContract.ps1 and only the added final changelog bullet. Earlier runtime implementation and historical governance report are unchanged context, not reopened/re-authored evidence. Canonical governance severity/prose rules and docs/happy-path/unhappy-path/consistency/enterprise briefs applied.

Verdict: no new source finding in assigned roles. Source review only; parent-reported local79 PASS is not independently executed here. Negative control/native validation and subsequent CI remain parent-owned; the prior Windows CI failure must remain a failed historical run, not retroactively relabeled green.

Gate2 docs: added comment and changelog accurately distinguish immutable historical SHA citations from active baseline consumers. NOTICE:82–87 attributes the copied port to a specific upstream commit; ports/grpc/README.txt:3–5 identifies copied baseline/revision. Its21–25 full-overlay-refresh instruction remains intact: a future baseline update must still refresh/review the copied source rather than merely edit the attribution SHA. This test change does not itself refresh dependencies, prove future overlay compatibility or disable that obligation. The new changelog describes inventory classification, not broader dependency correctness. No new operator CLI/env/workflow/API/permission/schema or production behavior requires manual/API updates. Existing PR fragment is extended; no direct CHANGELOG.md edit.

Gate4 happy-path: Get-ActiveBaselineReferences preserves input order and returns entries outside two historical-document prefixes and exact NOTICE/ports-grpc-README paths. Existing docs/reviews exclusion moves unchanged into the helper. New regression asserts historical-set removal; retained-set regression compares exact ordered strings and includes vcpkg.json, toolchain-contract.json, an unlisted new consumer and portfile.cmake. The actual inventory invokes this same helper, then checks every remaining path against the updater list and keeps the mandatory toolchain-contract.json membership assertion. Current git-grep lists20 tracked SHA-reference files; five newly exempt references are NOTICE, ports/grpc/README.txt and three governance .md reports. Remaining15 references match the updater's15 paths. No current active pin disappears from inventory.

Gate4 unhappy-path: new tracked live consumer outside the narrowly named provenance locations remains in the missing-reference set and fails the real gate. Other overlay files are not exempted. No broad ports/*, docs/* or all-markdown exclusion is added. Missing grep matches/grep error still returnfalse via LASTEXITCODE; missing updater-list parse also remainsfalse. No catch/continue-on-error/success override added. PowerShell array wrapping preserves zero/one/many filtering results. The regression examples alone do not prove native execution or actual-gate negative-control sensitivity; root must retain those observed results separately. No new concrete risk finding requiring a chaos design.

Gate4 consistency: exact path roles now agree with updater intent: workflow's files array is active consumers; attribution/history are evidence about source identity, not instructions selecting a dependency. The helper is shared between fixtures and production inventory assertion. Copied-source SHA is not automatically rewritten and historical review report remains immutable. Runtime source identity and prior qualification are not relabeled to include this later CI-test change; new touched-file hashes below identify it.

Enterprise: no customer topology, privilege, data handling, public contract or deployment surface changes. Preserving attribution and review history improves assurance evidence fidelity without asserting a new security control. WorkstreamG/A5 checked; #2990 revisit2026-10-31 remains the already-linked historical metadata observation, not a new discovery or renewed exception. Current CI must still qualify this amendment. No whole-PR CI PASS follows from source review or local check count.

Fresh routing: reopened all four current tables and matched every current concern's trigger/doc against both paths and the incremental semantics. 81 rows:3 matches,78 nonmatches. Standing matched rows are main:26 docs-writer every change; main:34 consistency-auditor everyPR; main:35 enterprise-readiness Gate6. Governance decision matrix also selects build-ci and Windows/cross-platform domain for this CI/toolchain test; these roles are separate from this report. Main:36 cache row does not match: no cache key/save/restore/scope wiring changes. No C++/Erlang/authz/Guardian/metrics/storage/Forensics route is newly touched by prior unchanged changelog bullets or filenames mentioned as examples. No new mandated per-change document update is found.

Exact row walk:

.claude/routed-concerns.md SHA256 278fb55d0b8f3d3e09fb377aeeb2eb77c5ec35c2590846b02eadcc3f4cc07f44; 42 rows, 3 matches, 39 no-matches.
16: NO MATCH Executions-history ladder — `command_id → execution_id` correlation, the SSE `ExecutionEventBus`, the durable `event_outbox`. **CATASTROPHIC-IF-V
17: NO MATCH Compliance evaluation pipeline — the `PolicyEvaluator` thread drives check→verdict→status. CATASTROPHIC: `policy_eval_thread_` joins BEFORE the s
18: NO MATCH `/auto` Pre-flight readiness — operator go/no-go checks before a fleet change; born-on-PG `PreflightRunStore` (fail-CLOSED construction, 14-day p
19: NO MATCH `/auto` Deploy — stage + execute an installer on a go-cohort via `content_dist`; born-on-PG `DeploymentRunStore`. CATASTROPHIC: every store mutat
20: NO MATCH **Artifact signature verification — one detached-CMS chokepoint (#416/#3807).** `detached_signature.cpp` is the SINGLE detached-CMS verifier, sha
21: NO MATCH C++23 conventions, naming, headers, plugin ABI boundary
22: NO MATCH C++ resource ownership and lifetime — fd/HANDLE/SOCKET/`FILE*`/SQLite/OpenSSL/BCrypt/C-string/thread/callback/temp-path ownership, RAII, `string_
23: NO MATCH macOS workflow + Darwin pitfalls table
24: NO MATCH Prometheus metrics, label set, audit envelope, event format, and the SHIPPED ALERT RULES — an alert-rule-only edit (no metric touched) still rout
25: NO MATCH Response data types, audit envelope, inventory data for analytics
26: MATCH User manual / YAML defs / REST API / Substrate primitive registration
27: NO MATCH Guardian / Guaranteed State — agent-side enforcement (`__guard__` wire protocol; §24 invariants) + DEX families (ruleless `rule_id="__observation
28: NO MATCH Spark detection layer (ADR-0021) — `SparkEngine` is the agent's sole detection primitive. CATASTROPHIC: (1) `GuardianEngine::reconcile_rule_locke
29: NO MATCH Echo dashboard — frames, URLs, permissions. CATASTROPHIC: new sources use the CORE pattern (`docs/echo-implementer.md` §8) and streaming ones imp
30: NO MATCH Device quarantine / containment — `QuarantineStore` (ADR-0047), the containment gate (`dispatch_confined_arms.hpp`), the reconciler, the agent pl
31: NO MATCH Scope walking — composable scope from previous query results (product differentiator). Result-set primitive, `result_sets.db`, `from_result_set:<
32: NO MATCH System architecture — cross-cutting design reference (Operator/Server/Agent/Gateway, REST/MCP/dashboard surfaces, plugin ABI boundary)
33: NO MATCH Tag/scope DSL operator reference — `tag:X`, `props.X`, `ostype`, `hostname`, `arch`, `agent_version` resolution; recipes for asset tagging
34: MATCH Agentic-first invariants A1–A5 — every new MCP tool, REST route, dashboard fragment or error site. A5: every new/materially-changed MCP tool ship
35: MATCH Enterprise-platform parity matrix — competitor capability comparison and gap analysis (complements `docs/capability-map.md`)
36: NO MATCH CI cache patterns — GHA-hosted: split `actions/cache/restore` + paired `actions/cache/save`; self-hosted: local `runner.tool_cache`; **never `sav
37: NO MATCH Fleet visualization (3D) — REST surface, page-shell, renderer, and process-layer invariants for the 11-PR `feat/viz-engine` ladder
38: NO MATCH Network quality dashboard (`/network`) — MEASUREMENT-FIRST device/local-link health lens. `yuzu.net_retrans_pct` is an INTERVAL delta, NOT the di
39: NO MATCH Device pages (`/devices` + `/device?id=`) — device info / DEX / Guardian lens tabs + "Get live info"; each kind has its own `device.live.<kind>` 
40: NO MATCH OS capability matrix — curated per-capability × per-OS snapshot, each row citing its in-code source; it **will drift** (durable fix: generate it 
41: NO MATCH Agent daily-sync framework + installed-software inventory (ADR-0016) — per-source daily push over `ReportInventory` (hash-skip): #1 `installed_so
42: NO MATCH SQLite `sqlite3_changes()` after `step()` on a shared FULLMUTEX connection is a data race + correctness bug (FULLMUTEX serialises calls, not the 
43: NO MATCH **Clock-guarded retention** — any bulk delete with a wall-clock cutoff (`now - window`) must be guarded and capped, never a bare `DELETE ... WHER
44: NO MATCH **Server storage substrate — PostgreSQL**; agent stays SQLite. Server fails CLOSED at boot — NO SQLite fallback — when `--postgres-dsn`/`YUZU_POS
45: NO MATCH `common/include/` shared-header firewall between `server/core` and `agents/` (#2549) — pure decision code only. The closed set of named I/O excep
46: NO MATCH **Durable agent command idempotency (HA WS-0, ADR-2002)** — `CommandDedupStore` (agent SQLite) replays the ORIGINAL terminal outcome on a duplica
47: NO MATCH **Agent OTA pull bounds (#913/#911)** — the per-peer admission gate on `DownloadUpdate` and its transfer watchdog. **CATASTROPHIC, four silently-
48: NO MATCH **Confined filesystem deletion — `confined_fs` (agent-core)** — the handle-relative primitive behind operator-triggered file deletion. CATASTROPH
49: NO MATCH Unit-test conventions — the shared helpers and fixtures (`unique_temp_path`/`TempDbFile`/`TempDir` and the `yuzu_test_` prefix, the CI-runner sal
50: NO MATCH **Echo cursor sources** — durable state is an `echo_cursor` row, not a snapshot-diff baseline. **CATASTROPHIC-IF-VIOLATED:** a lost/invalid curso
51: NO MATCH **power_health `set_power_plan`** — the only destructive power action (`PowerManagement`, admin-or-approval). NOT gaps, do not "fix": `ScheduleRu
52: NO MATCH **`app_usage` agent plugin + ADR-0016 daily-sync source — machine-scope usage evidence.** Reads Echo's `usage` fold read-only, never writes `echo
53: NO MATCH **`execution_artifacts` plugin — Windows ShimCache/AmCache/Prefetch reads** (read-only; `Forensics`, `AdminOrApproval`, single-target, audited, d
54: NO MATCH app-usage server read surface (`GET /api/v1/forensics/agents/{id}/app-usage` + MCP `get_agent_app_usage`). CATASTROPHIC: `Forensics:Read` SCOPED 
55: NO MATCH `windows_optional_features` plugin — Windows-only, read-only DISM read (`Inventory`, no enable/disable) via agent-core's bounded DISM-call primit
56: NO MATCH `peripherals` plugin — read-only USB/PCI/Thunderbolt inventory (`Inventory` securable, no mutation, no subprocess).
57: NO MATCH `printing` plugin — read-only queue/job inventory (`Inventory`; `jobs.document` = user content) + the ONE mutating action `printing.clear_queue` 

.claude/routed-concerns-access-control.md SHA256 65f60e57c9473e156a2a12f1613be4540a487848a58cd5dc1d4a105edd3145a2; 20 rows, 0 matches, 20 no-matches.
5: NO MATCH Authentication, RBAC, headers, tokens, self-target principal-destruction guard (#397/#403). CATASTROPHIC: every new list/fan-out read of per-agen
6: NO MATCH **Dispatch-caller approval provenance — `ExecuteGate` at the shared dispatch chokepoint (#1398).** Every dispatchable `(plugin,action)` pair carr
7: NO MATCH **Service-scoped API token confinement — durable default-deny (guardian-confinement-2298 PR 3, "the flip")** — a service-scoped token (`session->
8: NO MATCH PKI / internal CA — `ca_store` (`CaStore`, ADR-0053) holds cert metadata + CRL versions + the root key's opaque `key_ref` ONLY; the CA root **pri
9: NO MATCH AuthDB invariants — Postgres schema `auth` (ADR-0006; SQLite `auth.db` retired), fail-closed construction, `SecretCodec` (TOTP, ADR-0010 first co
10: NO MATCH **SCIM ↔ OIDC/SAML identity-link revoke chokepoint (ADR-2001, CC6.8)** — deprovisioning must sever every linked identity, not just the SCIM recor
11: NO MATCH Periodic Access Reviews (SOC 2 CC6.2): fleet-wide grant export + attestation campaigns. CATASTROPHIC-IF-VIOLATED: (1) the #2225 global gate is de
12: NO MATCH Enterprise A&A roadmap — RBAC, OIDC, SAML, SCIM, MFA, AD/Entra, API tokens, session lifecycle, audit
13: NO MATCH MCP server architecture, tier-before-RBAC ordering, kill switches, audit pattern; Streamable HTTP transport (sessions, GET SSE, progress bridge) 
14: NO MATCH Per-device dispatch visibility (#1788) + the registry-independent authz model (ADR-0033 §2). CATASTROPHIC: (1) **one intersection** — `dispatch_c
15: NO MATCH **Dispatch targeting — omitted means the fleet, EXCEPT for a `Destructive`-classified pair.** **CATASTROPHIC-IF-VIOLATED, every clause stated in 
16: NO MATCH **Dispatch zero-reach cause discrimination: ONE shared classifier, FIVE hand-copied legacy cascades that differ from it.** NEW surfaces (`POST /a
17: NO MATCH Agent privilege model — dedicated `_yuzu` / `yuzu` / `NT SERVICE\YuzuAgent` account, narrow sudo NOPASSWD + LSA privileges, per-plugin privilege 
18: NO MATCH **Headless platform, process decomposition & access-control spine (ADR-1005 + ADR-0031/0032/0033)** — every capability reachable by an authentica
19: NO MATCH **Authorization-topology floor (#2376)** — `authz_topology_floor.hpp`'s `kTopologyFloor` is the SINGLE chokepoint deciding which reads require ad
20: NO MATCH **Pre-auth request-body cap (#2407)** - `body_cap_policy.hpp`'s `kBodyCapTable` is the SINGLE chokepoint; EXTEND, never fork. CATASTROPHIC: (1) t
21: NO MATCH **MFA step-up chokepoint**: `kStepUpPolicy` (`step_up_policy.hpp`) is the SINGLE table of mutating routes needing a fresh MFA proof, run by `run_
22: NO MATCH **Fenced leader election — `LeaderElector` + the singleton-loop gate (WS-3, ADR-2002 §3/§6/§10)** — stops a second replica DOUBLE-DISPATCHING des
23: NO MATCH **Split merge-gate — ADR-0032 sequencing interlock (WS-0).** No engine-path code (admits a run / mints a grant / writes the release log / serves-
24: NO MATCH **A2/A1 RBAC administration surface — `is_rbac_administrator()` (`rbac_admin_predicate.hpp`) + the closed assignable-role list (`rbac_assignable_

.claude/routed-concerns-security-posture.md SHA256 794313b2bb2bf91d44dedb2fd8177df7803c31ebbffc84afef6e3bd4b051b783; 11 rows, 0 matches, 11 no-matches.
17: NO MATCH `app_control` plugin — read-only Windows WDAC/AppLocker posture (`Security`, ExecuteGate::None): registry reads (`CI\Policy`, `SrpV2`), a `CiPoli
18: NO MATCH `firmware_posture` plugin — read-only firmware/BIOS vendor, version, update-pending posture (`Security`, ExecuteGate::None): fwupd is only ever l
19: NO MATCH `platform_security` plugin — read-only Secure Boot / code-signing posture (`Security:Read`, both actions `ReadOnly`/`None`, no mutation). CATASTR
20: NO MATCH `local_security_policy` plugin — read-only password/lockout/audit policy posture and sudoers content (`Security` securable, `ExecuteGate::None`, 
21: NO MATCH `system_hardening` plugin — read-only exploit-mitigation/kernel-hardening posture (`Security`, ExecuteGate::None). **CATASTROPHIC-IF-VIOLATED:** 
22: NO MATCH **Gateway-upstream peer authorization.** `GatewayPeerGuardedService` is the SOLE production registration of the gateway-upstream service, on the 
23: NO MATCH **Gateway origin trust — what address the gateway reports for an agent (`gateway_observed_peer`, audit `source_ip`).** CATASTROPHIC-IF-VIOLATED: 
24: NO MATCH **Gateway mgmt-plane peer authorization (#1422, #6016).** `yuzu_gw_authz:check_mgmt_peer/1`, the :50063 `auth_fun`, is the SOLE authz gate on fle
25: NO MATCH `registry` writes (`set_value`, `delete_value`, `delete_key`, `set_user_value`, `delete_user_value`, `apply`). **CATASTROPHIC-IF-VIOLATED:** (1) 
26: NO MATCH **Same-site gate for cookie-session writes: ONE pre-routing chokepoint.** `apply_same_site_write_gate` (`same_site_write_gate.hpp`), called once 
27: NO MATCH **`virtualization.runtime_posture` — agent read access to a container-runtime control socket (Linux; `Security:Read`, ExecuteGate::None).** CATAS

.claude/routed-concerns-software-estate.md SHA256 33019f1c396ecf9237a459cbb586131eb9185084a949a2228bef543693a68a9c; 8 rows, 0 matches, 8 no-matches.
17: NO MATCH **`browser_inventory` plugin (Forensics, default-off, per-user browser data)** — per-user Chromium-family profile state (`browsers`/`profiles`; `
18: NO MATCH **`privacy_permissions` plugin (Forensics, default-off, per-app sensitive-permission grants — camera/microphone/location/full-disk-access).** Lin
19: NO MATCH **`runtimes` plugin — read-only installed .NET/JVM/Python runtime inventory (`Inventory`, no subprocess; machine-scope roots only, a per-user roo
20: NO MATCH **`middleware` plugin: read-only installed-middleware inventory (`Inventory`, table-driven; IBM MQ on Linux as `ibm_mq`; no subprocess).** Invari
21: NO MATCH **`remote_access_audit` plugin (Forensics, default-off, per-account SSH key data)** — reads `/etc/ssh/sshd_config` (Include followed) and each ac
22: NO MATCH **Forensics tier on stored-response reads (#4990)**: rows written by plugins on the `Forensics` securable are served only to a caller holding GLO
23: NO MATCH **`certificate_inventory` daily-sync source and `CertificateInventoryStore` (schema `certificate_inventory_store`).** CATASTROPHIC-IF-VIOLATED: (
24: NO MATCH **Software title normalisation layer** — `SoftwareTitleDimension` (the ADR-0012 §3 cross-store owner), the hourly `SoftwareNormalizationJob`, the

Reviewed source SHA256:
deploy/windows/Test-ToolchainContract.ps1: d258c5d4f30bc9ab74e796843a2695bb0ce1845d2c3b5389fece571a3039b5a6
changelog.d/20261110-nightly-shutdown-rotation.fixed.md: 15924c88e11e4a18cb8aa9472f3a701597ee45c89db0eaf416cb7afa9e89972f

===== END VERBATIM docs-routing-correctness.txt =====

===== BEGIN VERBATIM domain-security-ops.txt =====
Incremental active-baseline inventory repair review

Scope: only deploy/windows/Test-ToolchainContract.ps1 current diff and last changelog bullet. Prior 500k historical report remains immutable; no full-PR reopening or new whole-PR CI claim. Applied canonical governance severity/policy preamble already read verbatim in this review thread. Relevant security, build-ci, cross-platform, QA, compliance and SRE briefs and Windows/enterprise evidence requirements applied. One reviewer performing separate role passes, not six independent reporters.

Reviewed source SHA256s:
deploy/windows/Test-ToolchainContract.ps1 d258c5d4f30bc9ab74e796843a2695bb0ce1845d2c3b5389fece571a3039b5a6
changelog.d/20261110-nightly-shutdown-rotation.fixed.md 15924c88e11e4a18cb8aa9472f3a701597ee45c89db0eaf416cb7afa9e89972f
Distinctive line: $activeReferences = @(Get-ActiveBaselineReferences $references)

Gate2 security: SOURCE PASS, no findings. This is a test-side inventory classification, not a bypass of Assert-VcpkgCheckout, contract parsing, pin equality, checkout validation or runtime TLS controls. Existing fail-closed handling of git grep errors and mandatory contract inventory membership remains. No executable shell interpolation, credentials, permissions, download or cryptographic dependency changes. Exact NOTICE and ports/grpc/README.txt exclusions do not exempt the overlay directory or arbitrary README files; governance.d and existing docs/reviews are evidence namespaces, not live build configuration.

Gate3 build-ci: SOURCE PASS, no findings. Read actual updater .github/workflows/vcpkg-baseline-update.yml: explicit15-file list, global old/new SHA replacement only within that list, verification that old SHA no longer remains in listed files. Current actual contract baseline9eec002df1cd109f8f104cd966a763daf9751489 has20 tracked references:15 active,5 excluded, zero missing active references. Excluded current paths are NOTICE, ports/grpc/README.txt and three governance.d reports. Active15 exactly match updater list (six workflows, three Dockerfiles, vcpkg manifest/configuration, Windows provision/contract and macOS/build docs). The new helper replaces only the discovery filter; updater behavior is unchanged. The port README explicitly requires refreshing the copied recipe/reapplying patch/rebuilding sanitizer dependencies on an upstream refresh; its attribution SHA is not an active registry pin. NOTICE cites the copied recipe origin/licensing. Blind updater replacement would falsify both without refreshing the copy.

Gate3 cross-platform: SOURCE PASS, no findings. PowerShell7 required already; new helper uses existing Where-Object patterns and array wrapping, with no native APIs, MSVC activation or tool-resolution changes. git grep repository paths use forward-slash form; the filter matches that form, not native filesystem separators. Wrapper @() retains empty/single/multiple array behavior. Existing -notlike docs/reviews behavior is preserved. Case-insensitive PowerShell matching is consistent with existing test conventions and Windows paths; no broadly named live source directory is excluded. Native Windows execution remains separate required validation, not inferred from source inspection or macOS pwsh.

Gate3 QA: SOURCE PASS, no findings. Added assertions reject all four documented exclusion classes and retain vcpkg.json, toolchain contract, a new unknown scripts consumer and another file within ports/grpc. The actual inventory assertion still fails for a retained tracked consumer absent from the updater list, and Check records failure/exception and final script returns1. Unit examples alone do not establish end-to-end negative sensitivity: parent-owned temporary tracked live-pin injection should fail the actual inventory, then clean restored source pass. Parent reports local79PASS; not rerun by this reviewer. Native and negative runs are pending at this source review. No claiming those complete.

Gate6 compliance: SOURCE PASS, no findings. CC8.1/CC7.2 provenance improves by keeping historical records and copied upstream attribution immutable while continuing active-pin synchronization enforcement. No updater permissions, review gate, artifact retention, policy or production audit behavior changes. Changelog accurately describes exclusion from inventory, not an automatic overlay upgrade or new dependency version. Preserve pushed a11759af6 Windows CI1/35 failure as historical failure; new repair validation cannot retroactively mark that run green.

Gate6 SRE: SOURCE PASS, no findings. Removes a false dependency inventory failure without suppressing real missing active consumers. No service lifecycle, resource budget, metrics/alerts, recovery mechanism or deployment configuration changes. No need for a runtime health signal for this test-only helper. Failure observability remains existing named Check output plus nonzero aggregate exit. No broad retry/continue-on-error is added.

Validation performed here: read-only git diff, current tracked SHA-reference inventory compared with actual updater list, source hashes and relevant producer/consumer inspection. No source, ledger, remote, toolchain or build mutation. This report certifies source review only. Parent owns local/native/negative proof and post-push CI.

===== END VERBATIM domain-security-ops.txt =====

===== BEGIN VERBATIM control-provenance.txt =====
Local PowerShell negative control, 2026-11-15:
Saved exact bytes of tracked scripts/check-compose-versions.sh; temporarily appended a comment containing vcpkg.json builtin-baseline SHA. This path is outside updater's live consumer list and outside every history/provenance exclusion. Ran pwsh -NoProfile -File deploy/windows/Test-ToolchainContract.ps1; exit1,78passed1failed, specifically the inventory coverage check. Bothnewclassification checks passed. A Python finally restored exactoriginalbytes; rootverifiedgitdiff contains only intendedPS1/changelogpaths. No temporary control remains in source.
Before patch localtestexit1,76passed1failed. Afterpatch localtestexit0,79passed0failed.
Native Windows: fresh task-owned source snapshot of all6379trackedfiles from a11759af6 plus uncommitted two-file correction, tarred locally and extracted under C:/Users/natha/AppData/Local/Temp/yuzu_test_ci_provenance_7659. Own gitindex initialized/core.autocrlffalse/gitadd to ensure gitgrep sees all trackedsource. Same unchanged dependencies/hostinstalls; test hermetic, no runner/service/registry state writes. ActualtestSHA d258c5d4f30bc9ab74e796843a2695bb0ce1845d2c3b5389fece571a3039b5a6; exit0,79passed0failed. Script run-windows-ci-provenance.py and archive/source manifest retained in parentcampaign. Lease9aeb4825f5b7 released after testprocesscompleted.

===== END VERBATIM control-provenance.txt =====

===== BEGIN VERBATIM windows-contract.json =====
{
  "exit": 0,
  "test_sha256": "d258c5d4f30bc9ab74e796843a2695bb0ce1845d2c3b5389fece571a3039b5a6",
  "summary": [
    "79 passed, 0 failed"
  ]
}
===== END VERBATIM windows-contract.json =====

===== BEGIN VERBATIM windows-contract.log =====
Testing toolchain contract: C:\Users\natha\AppData\Local\Temp\yuzu_test_ci_provenance_7659\deploy\windows\toolchain-contract.json
  PASS  Visual Studio Installer exit codes classify success, reboot, and failure
  PASS  installer exit policy sends direct and WinGet reboot results to its handler
  PASS  installer exit policy accepts zero and rejects a hard failure
  PASS  all required SDK artifact files pass the live path adapter
  PASS  deleting live windows_sdk_header fails with that artifact identity
  PASS  deleting live windows_sdk_lib fails with that artifact identity
  PASS  deleting live windows_sdk_rc fails with that artifact identity
  PASS  a live path probe error fails closed with its diagnostic cause
  PASS  a complete matching manifest passes all executable probes
  PASS  a JSON-materialised ISO timestamp remains valid on day 13 or later
  PASS  manifest-only migration preserves a 1-runner topology and adds SDK evidence
  PASS  manifest-only migration preserves a 4-runner topology and adds SDK evidence
  PASS  manifest builder preserves build_jobs from provisioner ordered-dictionary pins
  PASS  manifest-only migration rejects a topology inconsistent with runner_count
  PASS  a passing child assertion reaches atomic replacement and retains the prior manifest
  PASS  a failing child assertion preserves the prior manifest and removes its candidate
  PASS  a failed pre-replace worker recheck preserves the prior manifest and removes its candidate
  PASS  an omitted Windows SDK library fails before executing a probe
  PASS  a stale Windows SDK artifact version fails before executable probes
  PASS  a Windows SDK artifact from another target directory fails before executable probes
  PASS  a Windows SDK artifact under an inactive root fails before executable probes
  PASS  the host contract default probe adapter retains module scope
  PASS  the default command resolver selects the first PATH match when duplicates exist
  PASS  the shared effective-command resolver selects the first duplicate git
  PASS  pinned Python skips installation
  PASS  stale Python installs once and re-resolves the effective command
  PASS  Python that remains stale after installation fails closed
  PASS  deleting the contract tool probes fails before executing anything
  PASS  duplicate contract probes fail before executing anything
  PASS  a legacy manifest with no schema fails before executing a probe
  PASS  an unknown manifest schema fails before executing a probe
  PASS  a stale manifest pin fails against the repository contract
  PASS  deleting a host-pin compatibility list fails before executing anything
  PASS  a provisioning target omitted from host compatibility fails before probes
  PASS  duplicate compatible host versions fail before executing probes
  PASS  unknown compatible host-pin names fail before executing probes
  PASS  a live Python drift fails even when the manifest claims the right pin
  PASS  an explicitly accepted old host stays green during a two-phase pin rollout
  PASS  unparseable probe output fails closed
  PASS  a probe execution error fails closed
  PASS  duplicate tool identities fail before executing a probe
  PASS  a partial per-runner inventory fails before executing a probe
  PASS  a manifest copied from another host fails before executing a probe
  PASS  duplicate per-agent PostgreSQL resources fail before executing a probe
  PASS  numerically aliased PostgreSQL ports fail before executing a probe
  PASS  path-aliased telemetry databases fail before executing a probe
  PASS  an effective PATH command that differs from the recorded tool fails
  PASS  an installed Erlang OTP version below the claimed pin fails
  PASS  the job-scoped effective vcpkg checkout passes at the reviewed baseline
  PASS  a job-scoped vcpkg checkout at the wrong HEAD fails closed
  PASS  a modified job-scoped vcpkg tracked tree fails closed
  PASS  a stale effective vcpkg executable fails even at the pinned checkout
  PASS  missing vcpkg tool-release metadata fails closed
  PASS  deleting the job-scoped baseline pin fails before executing a probe
  PASS  the job vcpkg default probe adapter retains module scope
  PASS  a hung executable probe is killed at its one-second test deadline
  PASS  the provisioning script remains syntactically valid
  PASS  the manifest-only updater remains syntactically valid
  PASS  the job-scoped vcpkg assertion script remains syntactically valid
  PASS  the vcpkg wrapper uses the shared first-match command resolver
  PASS  the standalone assertion models runner-local MSYS2 PATH without leaking it
  PASS  the authenticated PostgreSQL probe uses the bounded process primitive
  PASS  provisioning parameter defaults equal every reviewed pin
  PASS  the provisioner compares every reviewed pin before its first Step
  PASS  a Visual Studio reboot-required result stops before manifest emission
  PASS  fresh and existing Build Tools paths both apply installer exit policy
  PASS  the provisioner reconciles Python before pip or later provisioning steps
  PASS  the emitted manifest carries the reviewed schema
  PASS  the deployed runner-control bundle contains contract, module, and assertion
  PASS  the manifest-only updater is drained, live-asserted, and atomic
  PASS  Windows CI gates the effective checkout after Setup vcpkg and before install
  PASS  Windows release gates the host manifest and effective vcpkg checkout
  PASS  Windows nightly requires the host manifest without an optional guard
  PASS  baseline inventory preserves immutable evidence and overlay provenance
  PASS  baseline inventory retains unlisted live pins and other overlay files
  PASS  the baseline updater covers every active tracked SHA reference
  PASS  Assert-Toolchain exits 1 when the host manifest is missing
  PASS  Assert-Toolchain exits 1 at the incompatible-schema seam
  PASS  Assert-Toolchain exits 1 at the schema-less seam (bridge retired)

79 passed, 0 failed

===== END VERBATIM windows-contract.log =====

===== BEGIN VERBATIM ledger-validation.txt =====
Command: python3 scripts/ci/check-governance-ledger.py --files /private/tmp/yuzu-nightly-governance-d6256469a/ci-provenance-review/7659-ci-baseline-provenance-e37019.jsonl
Exit: 0
check-governance-ledger: OK — 1 fragment(s) lint clean

===== END VERBATIM ledger-validation.txt =====

===== BEGIN VERBATIM identity.json =====
{
  "captured_at": "2026-11-15T08:54:59.392163+00:00",
  "head": "a11759af636a4c1da53a9dcec74eba172232973c",
  "origin_dev": "946d90383de751648a741943701b5411902b8bbe",
  "files": {
    "deploy/windows/Test-ToolchainContract.ps1": "d258c5d4f30bc9ab74e796843a2695bb0ce1845d2c3b5389fece571a3039b5a6",
    "changelog.d/20261110-nightly-shutdown-rotation.fixed.md": "15924c88e11e4a18cb8aa9472f3a701597ee45c89db0eaf416cb7afa9e89972f"
  },
  "instruction_currency": {
    ".claude/skills/governance/SKILL.md": true,
    ".codex/skills/governance/SKILL.md": true,
    ".claude/routed-concerns.md": true,
    ".claude/routed-concerns-access-control.md": true,
    ".claude/routed-concerns-security-posture.md": true,
    ".claude/routed-concerns-software-estate.md": true,
    "AGENTS.md": true,
    "CLAUDE.md": true,
    "scripts/ci/check-governance-ledger.py": true
  }
}
===== END VERBATIM identity.json =====

===== BEGIN VERBATIM 7659-ci-baseline-provenance-e37019.jsonl =====
{"schema_version": 1, "run_id": "7659-ci-baseline-provenance-e37019", "commit_range": "a11759af636a4c1da53a9dcec74eba172232973c..two-path working repair", "reporter": "root-ci-validation", "recorded_by": "root", "source": "governance-agent", "reviewed_at_sha": "a11759af636a4c1da53a9dcec74eba172232973c", "recorded_at": "2026-11-15T08:55:47.898988+00:00", "pass_ordinal": 1, "finding_id": "ci-baseline-provenance-001", "severity_native": "LOW", "severity_mapped": "NICE", "trigger": "Windows toolchain inventory git-greps current baseline SHA after historical governance/provenance files carry that SHA; all matches except docs/reviews are treated as active updater consumers.", "impact": ["I8"], "exposure": ["E6"], "epistemic_status": "verified", "independent_reporters": 1, "policy_floor": "a broken build or test leg on any supported platform that this change INTRODUCED or newly exposed", "provenance": "newly-reachable", "file": "deploy/windows/Test-ToolchainContract.ps1", "line": 990, "summary": "Pushed a11759 Windows CI has1 failed target/35: baseline reference inventory mistakes NOTICE, ports/grpc/README.txt and3 historical governance records for live baseline pins. Root reproduced locally76PASS1FAIL. Historical attribution must remain tied to actual copied port/review source rather than be rewritten as current dependency configuration. Other34 Windows targets passed. Derived operational severity LOW/NICE is test-only I8/E6; supported Windows test-leg policy floor independently gates until repaired validation.", "classification": "truth-contradiction", "classification_rationale": "Inventory labels immutable historical source attribution as an active baseline consumer, contrary to file semantics. Actual CI check fails; this is not a speculative production crypto defect.", "disposition": "open", "adjudicated_by": null, "caused_by": null, "waiver_rationale": null}
{"schema_version": 1, "run_id": "7659-ci-baseline-provenance-e37019", "commit_range": "a11759af636a4c1da53a9dcec74eba172232973c..two-path working repair", "reporter": "root-ci-validation", "recorded_by": "root", "source": "governance-agent", "reviewed_at_sha": "a11759af636a4c1da53a9dcec74eba172232973c plus reviewed two-path repair; Test-ToolchainContract.ps1 SHA256 d258c5d4f30bc9ab74e796843a2695bb0ce1845d2c3b5389fece571a3039b5a6", "recorded_at": "2026-11-15T08:59:13.046181+00:00", "pass_ordinal": 2, "finding_id": "ci-baseline-provenance-001", "severity_native": "LOW", "severity_mapped": "NICE", "trigger": "Windows toolchain inventory git-greps current baseline SHA after historical governance/provenance files carry that SHA; all matches except docs/reviews are treated as active updater consumers.", "impact": ["I8"], "exposure": ["E6"], "epistemic_status": "verified", "independent_reporters": 1, "policy_floor": "a broken build or test leg on any supported platform that this change INTRODUCED or newly exposed", "provenance": "newly-reachable", "file": "deploy/windows/Test-ToolchainContract.ps1", "line": 990, "summary": "Fixed reference classification separates immutable review/source attribution from live baseline pins. Source reviews cover all affected domains and81 routed rows. Local old76PASS1FAIL becomes79PASS0FAIL. Temporarily adding current SHA to tracked unlisted scripts/check-compose-versions.sh produces78PASS1FAIL at inventory assertion, proving active-consumer detection survives; exact original bytes restored in finally. Native Windows fresh task-owned6379-file snapshot/index runs exact reviewed PowerShell SHA and passes79/79 exit0; no host configuration changes. Original a11759 Windows CI34PASS1FAIL retained. Supported-test-leg policy floor is resolved by repaired native execution, not waived or removed. See paired report, windows-contract.json/log and control-provenance.txt.", "classification": "truth-contradiction", "classification_rationale": "Inventory labels immutable historical source attribution as an active baseline consumer, contrary to file semantics. Actual CI check fails; this is not a speculative production crypto defect.", "disposition": "fixed", "adjudicated_by": null, "caused_by": null, "waiver_rationale": null}

===== END VERBATIM 7659-ci-baseline-provenance-e37019.jsonl =====
