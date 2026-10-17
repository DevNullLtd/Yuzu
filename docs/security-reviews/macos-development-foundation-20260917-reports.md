# macOS development foundation — verbatim review reports

These are the source reports for the [governance summary](macos-development-foundation-20260917.md). Each report is preserved verbatim below, including historical open/pending statements and later closure addenda. Read the summary and append-only ledger for final dispositions. Role sections covered by the same reviewer do not imply independent reviewers. Temporary reproduction paths identify private run evidence, not shipped dependencies or enduring public artifacts.

---

Source: `gate1.md`

# macOS foundation integration governance

Scope: PINNED base 1972d3e2a8c0beec9c71a4aa0fc2492d2619b4e1 through HEAD 6eb78e12e989c735e8dad115836a17c64974f476 and full working/index tree in /private/tmp/yuzu-macos-foundation-pr. Use git diff 1972d3e2a, not current origin/dev two-dot: origin/dev advanced during initial fetch to a0ed5ecc. Nine original packaging commits cherry-picked; staged new helper/docs/checker changes are INCLUDED. Not a clean-tree-only review. Original checkout unrelated work excluded.

Commits: ed4e90b29 development bundle; ef65c8e3b recovery hardening; 6cb78b944 resource ledger; 02f9703b1 recovery security; acf109114 staged input validation; 746d95570 collision preflight; ad0a9d2fe historical governance; df5c13554 system etc alias; 6eb78e12e installer relocation. Local, not pushed at review start.

37 files, +3212/-274: opt-in macOS signed ES app bundle and external plugins; profile identity/device/trust preflight; exact13.3 MachO closure; immutable disabledOTA startup and runtimeguard; final-byte sharedCMS verifierCLI; root-owned transactional installer/recovery/uninstall preserving data/identity; EndpointSecurity SDK detection; deploymentflags vcpkg+ObjectiveC++. New staged changes: read-only device-registration helper; explicit opt-in existing-session targeted command/native marker checker with terminalSUCCESS, ESdrop/hash/PIDchecks; runbook/links; .agent-runs Git+Docker exclusions.

Interfaces: new local packaging CLI and verifier CLI; existing HTTP commands consumer only, no newREST/proto/store/ABI/security grants. Development root service is opt-in. Checker does not enroll/install/restart or grantFDA. Does not implement Spark/Reflex/Guardian/DEX or change prefer_spark=false. ProductionTLS/notarization/oldestOSqualification remain separate. Historical live evidence093fc3bb8 does NOT validate this rebased artifact.

Resources: docs/resource-ledgers/macos-es-development-bundle.md records updater shared ownership, gRPC server/service shutdown ordering, scoped thread, temp paths, sidecarfd/flock and backups, condition-variable synchronization. Must check actual rebased C++ inventory and append integration review range, not reuse historic pass.

Validation at start (root report): ESenabled currentdev native agent+twoCatch2binaries build0; plugin/cert tests build0; Pythonpackaging28passed, checker10passed. Full suites in progress. No fresh artifact installed. No live mutations allowed for reviewers.

Routed rowwalk (both complete): artifactCMS->security+cppsafety; C++23->expert; ownership->safety/security; Darwin->crossplatform; Guardian/Spark published truth/no cutover->security/docs; TAR source/build->plugin/crossplatform/safety; tests->quality; power_health mesonpath->architect/security/safety/consistency/docs; new dispatchcaller->architect/security targeting and ADR1005 publicspine; privilege->security/crossplatform; anycapability->consistency; buildmatrix->build-ci; packaging->release-deploy; fleetread checker uses existing authenticatedAPI not newauthz; no newauth/RBAC/store/proto/retention/corechokepoints. Gate3 roster: architect,cpp-expert,cpp-safety,quality-engineer,build-ci,plugin-developer,cross-platform,release-deploy. Gate6compliance/sre/enterprise mandatory. No performance hotpath or Erlang changes.

Governance policy and both tables/CLAUDE byte-identical origin/dev after successful fresh fetch. Reviewer reads are read-only; only report materials may be written under /private/tmp/yuzu-macos-foundation-review. Never alter code, commit, push, or mutate live services.

---

Source: `gate2-security.md`

# Gate 2 — security-guardian, review and fix verification

Scope: pinned `1972d3e2a8c0beec9c71a4aa0fc2492d2619b4e1` through the full index/working tree at HEAD `6eb78e12e989c735e8dad115836a17c64974f476`, not moving `origin/dev`. No services, stores, signing assets, or product files mutated.

**Completed initial-review verdict: SHOULD / MEDIUM remaining; no open HIGH/CRITICAL finding.** All 38 modified product/source/doc files have now been read top-to-bottom, including the 312,689-byte upgrade manual added during review. SEC-3 is open while receipt adoption is implemented; Gate 8 must verify that fix before a clean PASS claim. The original HIGH finding and two MEDIUM regressions remain below as review history.

Input-integrity echo: `const bool rolled_back = rollback_if_needed();` from the added `Updater::perform_startup_maintenance()` body. Reviewed the supplied gate1 and shared-preamble completely, including the impact/exposure derivation and coverage requirements.

## SEC-1 — ignored legacy signature rejection (HIGH / BLOCKING)

- **Locations:** `deploy/packaging/macos/preinstall:124`, `postinstall:109`, `uninstall.sh:43`; their `legacy_app_is_managed()` functions and conditional callers.
- **TRIGGER:** an existing legacy `YuzuAgent.app` whose signature verification fails but whose displayed TeamIdentifier/Authority, Info.plist identifier, and original embedded profile still match. Modifying another sealed file produces exactly this kind of state.
- **IMPACT:** **I1** — the signature-based ownership check does not hold. An unverified tree is classified as package-owned and becomes eligible for privileged retirement/deletion rather than retention for inspection. The packaging README expressly promises strict signature verification before that classification. I2 is not needed for the finding's gate; the disposable reproduction does not claim actual user-data deletion.
- **EXPOSURE:** **E3**, an ordinary authorized installation/uninstall; **E4**, a pre-existing legacy-development bundle. No unauthenticated or privilege-escalation exposure is asserted.
- **EPISTEMIC STATUS:** **verified** for the classification failure, via actual Bash execution of each extracted function with deterministic tool results; not a live installed-machine attack.
- **PROVENANCE:** introduced in the reviewed change.
- **POLICY FLOOR:** none needed.
- **DERIVATION:** I1 gives HIGH; E3/E4 do not reduce it. Native HIGH and derived HIGH agree.

Every real caller invokes this function in an `if`/`||` conditional. Bash therefore disables `errexit` within the function. The bare `codesign --verify` failure does not terminate it; later successful metadata checks overwrite its return status. All three variants returned `MANAGED` with verification explicitly returning 1.

Reproduction: `python3 /private/tmp/yuzu-macos-foundation-review/repro-legacy-signature.py` returned:

```text
preinstall exit 0 MANAGED
postinstall exit 0 MANAGED
uninstall.sh exit 0 MANAGED
```

**Disposition: FIXED.** All three functions now explicitly return failure on verification rejection. Independent rerun of the same extracted-function reproduction returns `REJECTED` for preinstall, postinstall and uninstall. Added product regression invokes each actual function through conditional context with metadata agreeing, requiring both the valid-positive and invalid-negative cases. The postinstall profile-presence test also now explicitly returns failure.

## SEC-2 — loose builder drops nested plugins and required manifest (MEDIUM)

- **Original locations:** `deploy/packaging/macos/build-pkg.sh:120–127`; consumer `postinstall:255`.
- **TRIGGER:** supported Meson layout with the executable under `agents/core/` and plugins under `agents/plugins/<name>/`, not flattened `plugins/`.
- **IMPACT:** I6, the produced loose package cannot install: its required incoming plugin manifest is absent and the plugins are omitted. No signature bypass or silent installed-success is asserted.
- **EXPOSURE:** E3, authorized package builder/installer; E4, selection of the loose lane/nested layout.
- **EPISTEMIC STATUS:** verified with actual builder code from immutable HEAD `6eb78e12e` and mocked `lipo`/package-assembly tools; no Installer execution.
- **PROVENANCE:** introduced; the pinned-base builder had recursive discovery fallback.
- **POLICY FLOOR:** null. **Native/derived:** MEDIUM (I6, no raising exposure), nonblocking.

`repro-loose-package.py --original` returns builder exit 0 with `TAR_MISSING` and `MANIFEST_MISSING`. Postinstall expressly requires that manifest. **Disposition: FIXED** by restored nested discovery, duplicate-basename rejection, and unconditional empty-manifest initialization. The same stable-source harness against the working tree returns builder exit 0 with `TAR_PRESENT` and `MANIFEST_PRESENT`. Flat/empty/duplicate regressions were added by the implementer; no live pkg install is claimed.

## SEC-3 — original loose installations cannot upgrade (MEDIUM)

- **Original locations:** `deploy/packaging/macos/postinstall:156–170`; preinstall snapshot manifest handling.
- **TRIGGER:** upgrade a loose package installed by the pinned-base installer, which installed `tar.dylib` but never created `package-files.list`.
- **IMPACT:** I6, normal upgrade is unavailable because the original package's own plugin is classified as an unmanaged collision. The old daemon is not stopped at this preflight, so no process-unavailability escalation applies.
- **EXPOSURE:** E3, authorized upgrade; E4, prior loose-package installation.
- **EPISTEMIC STATUS:** verified with extracted actual functions, disposable old/incoming plugin fixtures and absent historical manifest; inspected pinned-base builder/postinstall prove the manifest was never authored there.
- **PROVENANCE:** introduced. **POLICY FLOOR:** null. **Native/derived:** MEDIUM (I6, no raising exposure), nonblocking.

Original reproduction prints `LEGACY_UPGRADE_REJECTED` and the explicit unmanaged-collision error for `tar.dylib`. A root-protected exact package receipt may supply ownership for original installs; unknown/no-receipt plugins must remain unowned. **Disposition: OPEN pending receipt-adoption fix verification.** The existing receipt-free rejection is correct once a valid-receipt migration path exists, not itself a bypass to remove.

## Coverage and remaining work

Read critical packaging implementations, new checker, new lifecycle test, C++ diff, resource ledger, development runbook and relevant verifier/privilege contracts. Traced final-byte CMS through the existing agent verifier, not a new verifier; explicit single-target commands, terminal-success requirements, TLS/cookie handling and secret-safe errors; disabled-OTA startup and first-command guards; installer phase/recovery paths. No full live installation or code-signing exercise was performed.

The checker explicitly documents operator-selected identity rather than identity attestation; therefore an independently provided wrong target is not raised as a missing security guarantee. Root-process/FDA/SIP tests remain outside this review's authority.

Mandatory full-file coverage now includes the complete source, headers, both Meson files, scripts, Python/C++ tests, all modified documentation, resource ledger and both governance fragments. Every previously truncated region was separately retrieved, including the full Guardian design and upgrade manual. The C++ ownership proof covers the scoped `AgentRunner` stop/join lifetime, server-before-agent construction, test sidecar restoration, and existing verifier reuse; no production thread, fd, or heap ownership is newly transferred by the OTA guard/CLI path. Final changed fix hunks remain subject to reread as the implementer works.

SEC-2/3 are also release-deploy concerns but are the same reporter's findings, not independent corroboration. Existing plugin-directory trust hardening has been added before backup/promotion; no unproven privilege escalation is asserted. No live ES/FDA/root operation, server authentication, destructive cleanup of user data, build, or full C++ suite was run by this reviewer. Disposable fixtures clean themselves up; the root agent owns live/test-artifact acceptance evidence.

---

Source: `gate2-docs.md`

# Gate 2 — docs-writer

Scope: pinned `1972d3e2a` to HEAD `6eb78e12e` plus staged/working changes in `/private/tmp/yuzu-macos-foundation-pr`. The moving `origin/dev` was excluded after the coordinator corrected the base. No live services, repository files, or credentials were changed.

Input-integrity echo (`docs/macos-development-foundation.md`): “A previous package's live result is not evidence for freshly rebased source.” The supplied severity preamble and docs-writer brief were read intact.

## D1 — SHOULD: connect the operator upgrade manual to the new package lifecycle

- Location: `docs/user-manual/upgrading.md`; related new text `docs/user-manual/tar.md:156–167`.
- TRIGGER: an operator uses the upgrade manual to upgrade a macOS package, including the default loose-binary lane, after this change.
- IMPACT: I7, required documentation absent from the operator manual for changed upgrade workflow. Required-doc source is closed-list item 2 (changed operator workflow/upgrade step).
- EXPOSURE: E3.
- EPISTEMIC STATUS: likely; read the shared preinstall/postinstall/uninstall and package builder, and searched the relevant manual pages. No installation was performed.
- Derivation: I7 base MEDIUM, E3 unchanged → MEDIUM / SHOULD. No HIGH concealment claim: the detailed lifecycle/recovery material exists in the packaging README; the defect is that the operator upgrade surface neither covers nor routes to it.
- Provenance: introduced. Policy floor: none.
- Evidence: `build-pkg.sh` installs the rewritten preinstall/postinstall in both lanes. These introduce incoming payload staging, recovery journals and validation, preserved configuration, and bundle/loose transitions. The TAR manual's new paragraph describes entitlement/OTA/live-capture boundaries but does not link to the command/recovery reference. `upgrading.md` is unchanged in this pinned diff. The full lifecycle instructions exist in `deploy/packaging/macos/README.md`.
- Minimum fix: add a short macOS-package paragraph to `upgrading.md`, linking the authoritative packaging README and foundation runbook; mention retained data, recovery journals, bundle OTA-disabled behavior, and deliberate install/rollback lifecycle validation. Do not duplicate the command reference.

## Coverage and limits

Reviewed new runbook, packaging README, profile/staging helper, package builder, launchd generators, pre/postinstall and uninstall, registration and smoke helpers, changed agent/updater/build prose, TAR/manual additions, privilege/Darwin/Guardian references, changelog and resource ledger. Inspected relevant test coverage and historical ledger; this is a documentation review, not a fresh platform execution pass or complete C++ lifetime review.

The development-versus-production boundary, TAR ES-versus-Spark distinction, unchanged `prefer_spark`, private evidence, explicit target selection, FDA/SIP, transport limits and fresh-artifact evidence boundary are clearly stated. A changelog fragment exists and CHANGELOG.md is untouched. No new REST signature, plugin action or DSL feature needs documentation. The hidden verifier is packaging plumbing; no standalone operator-manual CLI finding is asserted.

Release-deploy handoffs, not independently asserted findings: verify how CMS-enabled users obtain final relocated/Apple-signed sidecars before the one-shot helper requires them; verify Python availability for the merge helper on every installed upgrade lane. The relevant one-shot workflow and code paths were sent to the coordinator. Ownership/resource truth and SDK/runtime guarantees remain with their domain reviewers.

Result: no docs BLOCKING finding; one SHOULD missing-manual entry. No wording-only nits.

## D1 closure recheck

Disposition: **fixed**. Re-read the working-tree addition at `docs/user-manual/upgrading.md:5`. Lines 7–14 describe the changed executable location, OTA-disabled sealed app, development-only unsigned package, retained data/enrollment configuration, recovery copies, and shared loose/bundle recovery paths. Lines 15 and 17 link to the authoritative packaging/recovery README and foundation runbook respectively; both relative targets resolve to the existing documents reviewed above. This adequately closes the required operator-manual coverage without duplicating the command reference. Exact input echo: “Loose-binary and app-bundle installations share these”. Verification is static documentation inspection, not a fresh lifecycle execution. No additional wording findings. Gate 2 docs result: **PASS**, zero unresolved docs findings; previously noted release-deploy handoffs remain domain questions.

---

Source: `gate3-a.md`

# Gate 3 wave A — four distinct roles, one reviewer

Scope: pinned `1972d3e2a8c0beec9c71a4aa0fc2492d2619b4e1` through HEAD `6eb78e12e989c735e8dad115836a17c64974f476` plus index/working-tree changes. Never substituted moving origin/dev. This is ONE actor applying four briefs, not four independent reporters. Initial Gate 3 review complete; later changed domains require Gate 8.

Read both C++ skills and all four role briefs; C++ conventions, native Objective-C++ conventions, C++23 troubleshooting, unit-test conventions/helper ownership comments, architecture, Darwin compatibility, power-health contract, gate1/resource ledger and shared severity contract. Gate 2's exhaustive modified-file reads were retained, with changed C++/test/build fix hunks reread. Integrity echo: `output.close(); // Detect buffered flush/close failures before claiming restoration.`

## cpp-expert

### CPP1 — unguarded jthread on older supported Apple libc++ (historical, fixed)

- File: original `tests/unit/test_agent_ota_disabled_lifecycle.cpp:305`; replacement `:173–186`.
- TRIGGER: compile the added POSIX test with a supported older Apple toolchain lacking `std::jthread`, unlike the current Xcode toolchain.
- IMPACT: I6 — agent test target cannot build on that supported toolchain. EXPOSURE: E3 authorized build, E4 toolchain selection. EPISTEMIC: likely, based on the repository's documented #2580 failure and existing feature-guard conventions, not a newly reproduced old-toolchain failure.
- PROVENANCE: introduced; POLICY FLOOR: null. Native SHOULD / derived MEDIUM, nonblocking.
- Disposition: FIXED. Scoped noncopyable `AgentRunner` borrows a longer-lived agent, calls stop then joins its owned `std::thread`; no detach or stop-token dependency. Local current-Xcode `std::jthread` syntax probe actually PASSES at min13.3, so that probe is explicitly NOT evidence for the historical incompatibility. This is a toolchain-library availability issue, not proof that macOS 13.3 itself forbids jthread.

Current production C++ changes are narrow: shared verifier CLI before daemon creation, guarded maintenance and marker paths. No ABI/proto changes, new borrowed-view escapes, or unsupported production C++ features. Objective-C++ compile/link floors align; native `.mm` linking consumes the new target-specific deployment argument. PASS.

## cpp-safety

### CPP-S1 — buffered restoration loses original bytes (HIGH, OPEN after partial fix)

- File: original/current `tests/unit/test_agent_ota_disabled_lifecycle.cpp:199–206`, used by `FileBackup::restore()`/destructor at `:223–239`.
- TRIGGER: small buffered sidecar restoration encounters a late write failure after opening/truncating the pre-existing file (reproduced using a child-local zero RLIMIT_FSIZE and ignored SIGXFSZ).
- IMPACT: I2, original bytes destroyed; I3, helper reports successful restoration because the destructor's flush error is discarded. EXPOSURE: E3 authorized test execution, E5 I/O failure. EPISTEMIC: verified. PROVENANCE: introduced. POLICY FLOOR: null. Native BLOCKING / derived HIGH/BLOCKING.
- Original proof: standalone exact helper printed `RESTORE_REPORTED_SUCCESS bytes=0` for a disposable pre-existing fixture. Source retained at `repro-buffered-sidecar.cpp` in this review directory.
- Disposition: OPEN, partial fix only. Implementer explicitly closes before testing stream state. Recompiled identical reproduction with that correction prints `RESTORE_REJECTED bytes=0`: I3 is corrected, but I2 remains. `FileBackup` retains originals only in RAM; on a failed destructor restoration the process terminates and loses the only remaining original bytes. Error visibility cannot lower I2. The earlier closure was incorrect and is superseded by this correction. Require a durable same-filesystem original backup before replacement and rename restoration; preserve the backup on failure outside auto-deleting temporary owners. Reject unsupported symlinks/nonregular originals instead of following them. Add a fault regression exercising the actual owner, not only its write helper.

Other ownership proof: gRPC server shuts down and waits before service destruction; runner destruction precedes agent, sidecar backups, lock and scratch directories; fd/flock ownership is noncopyable; assertion unwind restores originals after agent teardown; construction failure starts no owned thread; shared CMS verifier retains its pre-existing resource owners. No new production raw-resource transfer.

Resource Ledger: complete, including rebased integration coverage. Its phrase that a failed sentinel write throws "before state is changed" is false: truncation can already have occurred. Correct wording and the I2 ownership defect; do not treat attempted restoration as original-byte preservation. Sanitizer coverage needed: targeted TSan for the new loopback/runner teardown and ASan/UBSan for lifetime cleanup; not executed by this reviewer. Focused native reproductions provide platform validation, not sanitizer equivalence. FAIL pending CPP-S1 closure; sanitizer evidence remains an explicit validation limit.

## quality-engineer

No additional independent defect. Actual `Agent::run()` registration/Subscribe/reconnect path is exercised, not a shadow implementation. The missing-plugin command is intentionally REJECTED but proves first-frame receipt (the marker-writing location); it does not claim successful plugin execution. Sentinel bytes live beside the actual test executable and are checked byte-for-byte; the exceptional fixed path is serialized with flock and restored by noncopyable owners. Ephemeral loopback port and yuzu_test_ scratch paths avoid shared-runner collisions. POSIX guard intentionally excludes this lifecycle test on Windows, while updater maintenance unit tests retain Windows branches.

Python tests cover profile/device/identity negatives, final-byte policy, signature conditional behavior, nested/flat/empty/colliding layouts and receipt negatives. New smoke exercise tests cover success, missing events, PID restart, drop growth, changed bytes and cleanup; reviewer reran all 12 foundation cases successfully. Receipt-ownership focused test also passed. Installer JXA behavior and complete platform builds remain separate evidence owned by the implementer. The loopback test is an integration exception to no-network unit guidance, using only a private ephemeral local endpoint and bounded waits; no external dependency is hidden. PASS, with sanitizer limit above and live installation explicitly not certified.

## architect

PASS. The packaging lane is opt-in, keeps signed executable code apart from mutable agent data/plugins, and disables existing binary OTA mutation rather than replacing the update trust model. CLI verification delegates to the existing CMS authority; no duplicate cryptographic implementation or new public server endpoint is introduced. The smoke helper consumes existing targeted authenticated API routes (ADR-1005 public spine), not a parallel dispatch capability. It explicitly declines transport-attestation claims.

Spark/Guardian selection and ownership are unchanged; no `prefer_spark` flip, new ES authority, Network Extension support or prevention parity is claimed. Power-health's sole change adds the Darwin link floor; no action catalogue, permission, destructive classification or Windows mutation logic changes. Build graph remains downward/acyclic; no protobuf field, plugin ABI layout or server storage change. The new Foundation-only JXA merger was read completely: data-only plist parsing, existing argument-preservation policy, atomic serialization and argv invocation avoid Python as a customer runtime dependency. No new module-policy concern identified; final installer integration belongs in Gate 8 security/deployment reruns.

## Separate Gate 2 rerun — SEC-3 receipt adoption

SEC-3 FIXED by source review plus focused real-function fixture execution. `preinstall:122–142` uses exact `/usr/sbin/pkgutil --files com.yuzu.agent`, permits only immediate conservative `.dylib` names under the exact historical prefix, rejects unsafe matching entries, and adopts nothing if receipt lookup fails. Root-owned nonsymlink nonwritable plugin directory is checked before adoption/snapshot; synthesized manifest is created atomically and included in rollback snapshot. Unknown plugins remain unowned and collision refusal remains. No receipt install-location attack is asserted: the relevant original package explicitly installed at `/`, and changing the system receipt database requires root authority outside the alleged new boundary. This is ownership provenance, not plugin-byte authenticity; normal signature checks remain separate.

Later JXA/data-directory/installer modifications require their own full Gate 8 security and release-deploy integration check. No services, product edits, signing-key operations or privileged install were performed by this reviewer.

## Gate 8 follow-up — CPP-S1 durable backup correction

CPP-S1 is now FIXED for both I2 and I3, superseding the open disposition above without removing its initial/partial-fix history. Current FileBackup copies regular originals to a private unique sibling directory before truncating sentinel writes; symlinks/nonregular originals are rejected. Restore uses same-filesystem rename; a failure retains the on-disk original outside any auto-deleting TempDir owner. Successful restore is idempotent and removes the now-empty backup directory. Constructor copy failure leaves source bytes intact. No unsupported claim of power-loss/fsync durability is made. Actual-owner regression passed: 4 assertions / 1 case, forced rename failure → retained original bytes → remove obstruction → successful retry → backup-directory cleanup. Ledger wording now matches this contract. Current C++ ownership/quality assessment for this fix PASS; sanitizer/full-platform/live-lifecycle qualifications remain unchanged. See gate4-a.md for recovery-domain re-review of UP1.

---

Source: `gate3-b.md`

# Gate 3 wave B — build-ci / cross-platform / release-deploy / plugin-developer

One reviewer covered four roles; these are not four independent converging reviews. Scope: pinned `1972d3e2a` to `6eb78e12e` plus full working/index changes in `/private/tmp/yuzu-macos-foundation-pr`, including Gate 2 repairs as observed during review. Source-integrity echo from the installer: `# All validation occurs before changing active paths.` Shared severity preamble and Gate 1 scope apply unchanged.

Read the four role briefs, yuzu-build/yuzu-meson/yuzu-plugin-abi skills, build guide, Darwin pitfalls, UAT guide, native Objective-C++ conventions, packaging/readme/runbook, relevant ABI/loader declarations, changed Meson/native-triplet wiring and installer/scripts. No code edits, live services, installation, commits or new signing operations. Parent-reported all-plugin native build and five agent/TAR target passes are inherited evidence, not independent runs. No fresh package has been installed; old live results are not evidence for these bytes.

## build-ci

No additional finding. New test sources are in the agent target; Python tests are in the agent suite. Optional ES lookup now uses the SDK library and preserves the no-op fallback; bsm and Blocks flags remain conditional. All current Objective-C++ plugin targets (TAR, wifi, power_health), plus TAR tests, receive the 13.3 link floor. Repository overlay-triplet discovery is configured in vcpkg-configuration.json and release/CI use arm64-osx. Windows protobuf/CRT wiring and proto codegen are unchanged. No supported-platform build failure was independently reproduced. Linux, Windows, Intel Mac and oldest-OS runtime validation are limits, not claimed passes.

## cross-platform

No additional finding beyond the deployment defects below. Reviewed macOS path aliases and new POSIX test guards, scoped thread teardown replacing jthread, native linker flags and optional SDK behavior. Target metadata checks deliberately fail closed for mismatched architecture sets or non-13.3 load commands. Metadata is not runtime qualification. ES runtime privilege/FDA/grant requirements and polling fallback remain explicit; this does not add Network Extension, Spark mechanisms, or AUTH prevention.

## release-deploy

### RD1 — SHOULD / MEDIUM: fresh install omits launchd's working directory

- Location: `deploy/packaging/macos/postinstall:241–249`, `build-pkg.sh:146`, `com.yuzu.agent.plist:34–35` (line numbers before repair).
- TRIGGER: install either lane on a Mac where `/Library/Application Support/Yuzu` does not exist.
- IMPACT: I5, I6. EXPOSURE: E3. EPISTEMIC STATUS: likely.
- Derivation: MEDIUM base, no raise/cap → MEDIUM / SHOULD. Policy floor: none. Provenance: introduced.
- Evidence: previous postinstall created DATA_DIR; revised builder/pre/postinstall only create app-root/log/config/cert/plugin directories. The unchanged plist sets WorkingDirectory to DATA_DIR. Local Apple `launchd.plist(5)` says this chdir happens before running the job, so the daemon cannot create its own missing working directory. No live install was attempted.
- Fix: create an absent data directory before bootstrap while preserving existing ownership/modes/content. Coordinator notified; root implementing. Closure not yet re-read.

### RD2 — SHOULD / MEDIUM: default upgrades now require an unprovided Python runtime

- Location: `deploy/packaging/macos/postinstall:310–313`, `merge-launchd-plist.py:1`, `build-pkg.sh:39`.
- TRIGGER: ordinary loose-to-loose upgrade on an installed target without functional Python3 on Installer's PATH.
- IMPACT: I5, I6. EXPOSURE: E3. EPISTEMIC STATUS: likely.
- Derivation: MEDIUM base, no raise/cap → MEDIUM / SHOULD. Policy floor: none. Provenance: introduced.
- Evidence: merge runs through `#!/usr/bin/env python3` after require_stopped and code promotion whenever a prior plist exists. Package does not supply Python and preinstall does not check it. Published binary-install path (`docs/agent-bundle.md:140`) requires installer/plist/bootstrap; README's Python prerequisite is explicitly under Building. Read-only `/usr/bin/env PATH=/nonexistent python3 --version` returned 127, confirming interpreter lookup behavior, not simulating a full installation. Recovery should restore the previous package, but repeated upgrades cannot succeed on this host.
- Fix: use a supported native plist mechanism or supply the required runtime; a preflight alone avoids interruption but does not preserve formerly available no-Python upgrades.

### RD3 — SHOULD / MEDIUM: CMS-enabled first-time packaging lacks a final-byte handoff

- Location: `deploy/packaging/macos/build-app.py:447–478`; packaging README's one-shot command at lines 16–24.
- TRIGGER: first build from plugins carrying CMS sidecars; caller must produce signatures for the relocated and Apple-signed output.
- IMPACT: I6. EXPOSURE: E4. EPISTEMIC STATUS: likely.
- Derivation: MEDIUM base, no raise/cap → MEDIUM / SHOULD. Policy floor: none. Provenance: introduced.
- Evidence: helper privately stages, relocates and Apple-signs each plugin, then requires preexisting final sidecars and verifies them before publishing output. Failure deletes staging. No export/pause/finalize command or signing callback exposes the exact bytes first. The documented command therefore depends on independently reproducing an internal transformation; it does not supply the advertised complete CMS-enabled packaging workflow. No claim that cryptographic verification fails: stale/missing signatures are correctly rejected.
- Fix: provide a supported stage→CMS-sign→finalize path that verifies without rewriting signed bytes, or another explicit reproducible final-byte handoff. Preserve enforcement.

Reviewed transactional staging, recovery phases, archive reconstruction, legacy-app identity pinning, uninstall retention, profile/signature checks and sidecar policy. Gate 2 SEC1/SEC2 repairs and receipt-adoption code were inspected but are not duplicated as new findings. Receipt adoption limits itself to trusted Installer-receipt dylib paths before snapshot; unreceipted third-party collisions remain refused.

## plugin-developer

No additional ABI/action finding. Stable C descriptor/version/action surfaces are unchanged; no InstructionDefinition/proto updates are required. The new packaging-only verifier delegates to existing `verify_plugin_signature`, preserving shared CMS policy. External plugins remain external and Apple-signed; generated sidecar policy explicitly requires runtime signatures. The CMS workflow finding is operational accessibility, not a proposal to weaken the loader or forge new signature policy.

Overall: no new BLOCKING finding; three release-deploy SHOULD findings, with RD1 repair in progress. Required live install/upgrade/recovery/uninstall and cross-platform qualification remain unperformed in this review.

## Follow-up: RD1/RD2/RD3 closure and test portability

- **RD1 fixed:** `postinstall:105–116` now creates only an absent data root, mode 0750/root:wheel, and preserves an existing real directory without changing its contents, owner or mode. `:257` calls it before promotion/bootstrap. The extracted-function behavioral regression covers absent creation, existing sentinel/mode preservation and symlink refusal.
- **RD2 fixed:** installed merging now calls absolute `/usr/bin/osascript -l JavaScript` (`postinstall:327`); `build-pkg.sh:40` ships `merge-launchd-plist.js` and the Python helper is deleted. The JS uses Foundation plist parsing/atomic serialization, argv rather than shell construction, and no GUI `Application` calls. Reviewed option/environment policy against the former implementation. Native JXA tests exercise actual serialization, retained operator settings, forced signature policy/OTA behavior and malformed-input destination preservation. This closes the Python-runtime dependency; final security assessment of root-side JS input handling belongs to security-guardian, not this limited closure statement.
- **RD3 fixed:** `deploy/packaging/macos/README.md:108` documents a supported two-stage bootstrap: fresh no-sidecar inputs → published Apple-signed outputs → operator CMS signing of output dylibs plus explicit runtime policy → build-pkg final-byte verification. It forbids re-signing/editing after CMS and deleting existing enforced sidecars. No new signing callback or verifier fork was introduced. The positive/tampered package-orchestration fixture observes actual builder argv/policy/publication behavior; its verifier double is explicitly not cryptographic proof.

Independent targeted recheck: five relevant tests (data-directory behavior, native malformed-plist preservation, native hardened-policy merge, native disabled-OTA merge, two-stage CMS package orchestration) passed on the current Mac. No live installation occurred.

### CP1 — BLOCKING policy floor: native packaging tests registered on non-Darwin

- Location: `tests/test_macos_app_packaging.py:317`, `:646`, `:707`; unconditional registration in `tests/meson.build`.
- TRIGGER: run the agent suite on Linux or Windows after this change.
- IMPACT: I6 (supported validation lane unavailable). EXPOSURE: E0, E3. EPISTEMIC STATUS: likely.
- Derivation: I6 base MEDIUM, no modifier → MEDIUM/SHOULD operational band. **Policy floor overrides gate:** introduced broken test leg on a supported platform. `severity_native=BLOCKING` (policy); provenance introduced by the JXA repair.
- Evidence: these tests invoke absolute `/usr/bin/osascript` without a Darwin guard. Non-Darwin systems do not provide that macOS executable, so subprocess raises FileNotFoundError before assertions. Other package orchestration fixtures also depend on real `ditto`/absolute PlistBuddy and need the same portability audit; those are introduced versus the pinned base, not pre-existing project regressions. Only the legacy Bash test currently has a skip decorator. This was reported immediately, not treated as a reason to skip the whole test file.
- Minimum fix: gate genuinely native cases on Darwin, retaining portable profile/parser/byte-policy tests on every platform; on Darwin missing native tools must fail, not silently skip. Assert non-Darwin discovery/execution no longer reaches native-only tools. No Linux/Windows suite was run in this closure check.

Latest verdict: RD1–RD3 closed, **CP1 open** pending portability repair. Build-ci/cross-platform must recheck that repair; release-deploy and plugin-developer have no remaining finding from this actor.

CP1 affected-case inventory (pre-repair lines): native JXA tests `:317`, `:646`, `:707`; package orchestration `:265` (two-stage CMS), `:479` (mixed CMS), `:532` (source snapshot), `:734` (stale CMS) invoke real `ditto`/absolute PlistBuddy; operational-directory guard `:513` invokes BSD `stat -f` and symlinks. Bash/POSIX cases `:52` (classifier), `:105` (loose package/shebang stubs), `:144` (receipt), `:171` (DATA_DIR modes/symlinks), `:772` (argument parsing) additionally need explicit native-Windows handling; merely finding an MSYS Bash does not make native Python's Windows path arguments POSIX paths or make chmod/symlinks portable. Keep pure profile, Mach-O parser, structure, mocked verifier and mocked foundation contracts platform-neutral. Foundation's AWK subprocess case also needs tool/platform scrutiny. This inventory refines the single CP1 finding, not additional independent findings.

CP1 partial repair recheck: Darwin-native tests now use `sys.platform == 'darwin'` and shell/POSIX cases exclude `os.name == 'nt'`; appropriate pure tests stay active. Two Windows path assertions still require correction: packaging `test_final_plugin_sidecars_use_the_shared_agent_verifier` (`:783`) expects slash literals where the helper receives `str(Path(...))`, and foundation `test_cookie_only_passed_as_path_no_redirect_or_tls_bypass` (`:103`) similarly expects `/private/cookies` instead of the fixture path's native string. A read-only probe through the actual helpers with `PureWindowsPath` confirmed the emitted backslash-form argv, so these assertions cannot pass native Windows. Use `str(fixture_path)` expectations rather than suppressing either test. Same CP1 finding remains open until corrected; no full Windows run is claimed.

---

Source: `gate4-a.md`

# Gate 4 — happy-path and unhappy-path

One reviewer applying two role briefs; not independent convergence. Scope pinned `1972d3e2a8c0beec9c71a4aa0fc2492d2619b4e1` through `6eb78e12e989c735e8dad115836a17c64974f476` plus current index/working tree. No fetch, product edits, service operations, installer execution, or live faults. Shared severity contract and Gate1 apply; Gate2/3 findings are context, not new findings. Integrity echo: `remove_managed_plugins "$YUZU_LIB/package-files.list"`.

## Happy-path role

Read the role brief and traced profile/build/package preparation, preinstall snapshots, postinstall promotion, JXA configuration merge, recovery, uninstall, CLI CMS verification, immutable OTA and smoke evidence. Normal-input flow is coherent, subject to open findings below; this is source/fixture evidence, not live-host acceptance.

An explicit app/profile/device/identity preflight precedes signing; all staged Mach-O deployment floors and final app/profile/entitlement identity are checked. CMS is verified against final Apple-signed plugin bytes using the existing verifier, with the two-stage handoff documented. Nested and flat loose layouts produce manifests; duplicate basenames are rejected, including empty-plugin handling. Bundle packaging preserves the signed artifact rather than editing it after verification.

Preinstall rejects untrusted payload/state parents and existing plugin-directory ownership. Historical loose ownership can be established by the exact root Installer receipt, conservative immediate plugin names and atomic synthesized manifest; unknown plugins remain unowned. Snapshot includes manifest and managed plugins. The prepared phase distinguishes an unpromoted payload from a potentially changed installed generation. Postinstall validates incoming lane/files and refuses unmanaged collisions before promotion, confirms the service stopped, replaces the selected lane, preserves unrelated plugins, and generates a root service definition. Existing mutable data ownership is preserved; fresh data directories are created. JXA consumes argv, parses plist as data and atomically serializes preserved operator arguments and whitelisted environment values. Bundle mode forces disabled binary OTA.

Bootstrap requires consecutive observed running states; it is not proof of ES subscription, stable long-term health or a successful first remote command. Live FDA/root/ES gates remain separate. Normal synchronous error rollback removes current and incoming managed plugins before restoring the snapshot; the interrupted retry implementation differs and fails UP1 below.

The lifecycle regression runs the actual daemon loop against a private ephemeral gRPC service: registration, first delivered command, reconnect, absence of update RPCs and immutable sidecars are checked. Missing-plugin rejection proves command receipt, not successful feature execution. The smoke helper binds target identity, monitors event/drop/PID evidence and final-byte stability, and cleans its fixture; it does not claim transport attestation. Spark/Guardian selection and Network Extension functionality are unchanged.

Happy-path verdict: CONDITIONAL, not overall PASS. CPP-S1 original-byte loss and UP1 interrupted recovery remain open; CP1 cross-platform native-test gating belongs to its original reporter. No native install/uninstall/recovery, live ES or old-OS runtime acceptance is claimed.

## Unhappy-path role

### UP1 — interrupted promotion leaves a new plugin and wedges retries (HIGH, OPEN)

- Location: `deploy/packaging/macos/preinstall:173–193`; crash window in `postinstall:317–322` (plugin moves precede incoming-manifest promotion).
- TRIGGER: upgrade adds a previously absent plugin; interruption occurs after that plugin moves into the active directory but before the incoming manifest replaces the old current manifest; retry invokes interrupted-promotion recovery.
- IMPACT: I5 — recovery restores the old plugin set incompletely and the next attempt persistently fails unmanaged-collision preflight; state-machine wedge raises availability impact to HIGH. The active directory also contains mixed-generation package plugins. No specific crash or attacker code execution is asserted.
- EXPOSURE: E3 authorized upgrade, E5 interruption in a defined transition window. EPISTEMIC: verified. PROVENANCE: introduced. POLICY FLOOR: null. Native BLOCKING / derived HIGH / BLOCKING.
- Derivation/proof: `recover_interrupted_promotion` removes only the old current manifest's paths. Its synchronous sibling `restore_previous` also removes the incoming manifest's paths. Extracted actual functions, with all payload paths redirected to a disposable fixture and launchctl mocked, emitted `NEW_PLUGIN_SURVIVED_ROLLBACK`, `OLD_PLUGIN_RESTORED`, `RETRY_BLOCKED`, and the exact unmanaged-collision error for `new.dylib`. Reproducer: `repro-retry-manifest.py` in this review directory. The real service and filesystem payload roots were untouched.
- Required correction: remove validated transaction-owned incoming paths as well as current-manifest paths before snapshot restoration, or durably record each promoted new path. Preserve unknown third-party files. Add a regression for interruption after each new-plugin move and before manifest rename, then verify recovered old generation and successful retry.

### Existing open risk: CPP-S1 (not a duplicate finding)

Explicit stream close now detects late errors, but the actual `FileBackup` stores the sole original bytes only in RAM. A failed truncating restoration followed by destructor termination loses them. Corrected reproduction still prints `RESTORE_REJECTED bytes=0`; I2 remains HIGH. Gate3 raw report now explicitly reverses premature closure. Durable same-filesystem original backup must survive restoration failure and automatic scratch cleanup; reject unsupported symlinks/nonregular originals. Merely changing ledger wording cannot close I2.

### Remaining fault designs and limits (not newly proven findings)

| Transition/fault | Required observable result | Present evidence / remaining limit |
|---|---|---|
| Prepared payload fails validation or collides with unknown plugin | Old service/code retained; retry can discard unpromoted incoming payload | Source order and isolated packaging tests; no live launchd run |
| Promoting service stop/bootstrap fails | No success claim; recoverable old generation and actionable retained evidence | Forward path confirms stop; rollback/retry ignores bootout errors, so inject this only in a future disposable service harness and inspect whether code can be replaced while old PID remains |
| Invalid profile, identity, CMS or tampered signed bytes | Fail before install/trust claim | Negative validator/signature fixtures; no production identity changes |
| Malformed retained config or JXA write failure | No partially serialized live plist; old config recoverable | Foundation atomic write and ERR rollback source inspection; disk-fault execution pending |
| Persistent sidecar restore failure | Original bytes remain recoverable even when process exits | Fails current CPP-S1 design; durable-backup fix pending |
| Smoke missing events, restart, growing drops, byte changes or timeout | Failure, bounded cleanup, no parity claim | Existing twelve focused fixture cases passed previously; not live ES evidence |
| Uninstall cannot boot out loaded service | Explicitly demonstrate stopped service before claiming complete removal | Existing bootout error is ignored; retained as targeted lifecycle fault design, not evidence of an observed live failure |

Unhappy-path verdict: FAIL pending UP1 and CPP-S1. No chaos execution performed. These designs are next-gate inputs, not invented findings or completed acceptance evidence.

## Gate 8 bounded re-review — subsequent fixes

The initial verdict above is preserved as history. Current UP1 and CPP-S1 corrections were reread across security, C++ ownership, quality, happy/unhappy recovery and ledger-truth domains; these two findings are now FIXED for the reproduced triggers.

- UP1: preinstall now removes both current and trusted transaction incoming manifest paths before restoring the old snapshot. The promoting phase follows collision validation, so incoming names represent the accepted package generation, not arbitrary third-party discovery. Executed the actual-function product regression `python3 tests/test_macos_app_packaging.py -k interrupted_plugin_promotion`: 1 passed. It checks newly promoted plugin removal, old bytes restored, unrelated third-party bytes retained and the next attempt passing the same collision guard. No live service claim.
- CPP-S1: `FileBackup` rejects symlinks and other nonregular originals, creates a unique private directory beside the original, copies original bytes there before sentinel truncation, then restores via same-filesystem rename. Failed rename leaves the only original copy on disk; there is no TempDir auto-delete owner for real executable-adjacent backups. The restored flag makes explicit/destructor restoration idempotent. A failed constructor snapshot cannot authorize subsequent sentinel writes. The ledger no longer claims failure before any state change, and explicitly excludes power-loss durability. Executed `build-macos/tests/yuzu_agent_tests 'OTA sidecar backup retains originals when restoration fails'`: 4 assertions / 1 case passed. This uses the actual owner, forces rename failure with a destination directory, verifies retained original bytes, removes the obstruction, retries successfully and checks empty backup-directory removal. No process-wide resource limits or external artifacts are mutated.

Neither change grants an overall governance PASS: CP1 verification belongs to its originating role, remaining full-suite failures are under investigation, and live lifecycle/ES/old-OS compatibility remain unverified. Bootout-failure fault designs above remain pending, not automatically closed by these fixes.

---

Source: `gate4-b.md`

# Gate 4 — consistency-auditor

Scope: pinned `1972d3e2a` through the full current working/index tree at HEAD `6eb78e12e`; no live services or product edits. Read the consistency brief, shared severity contract, Gate 1 and Gate 2/3 reports; retained prior exhaustive packaging and relevant changed-source reads. Source-integrity echo: `remove_managed_plugins "$INCOMING_MANIFEST"` exists in postinstall recovery but is absent from preinstall replay recovery.

## C1 / shared cluster UP1 — interrupted promotion leaves a retry-blocking plugin

- Component/category: agent deployment / state.
- Location: `deploy/packaging/macos/preinstall:177–193`, compared with `postinstall:220–237` and promotion at `postinstall:317–323`.
- TRIGGER: an upgrade introduces `new.dylib`; installation is interrupted after that file moves into the live plugin directory but before `.package-files.incoming` is renamed to `package-files.list`. The next installation replays the persisted `promoting` recovery.
- Observed: replay removes only plugins named by the old/current manifest, restores the old plugin bytes and old manifest, and returns success. Newly moved `new.dylib` survives, no longer package-owned according to the restored manifest. Retry then rejects its own plugin as an unmanaged collision. Ordinary postinstall ERR recovery removes both current and incoming manifests; interruption replay does not.
- Expected: both recovery paths restore the same package-owned code state while preserving genuinely unmanaged plugins.
- EPISTEMIC STATUS: verified. PROVENANCE: introduced. EXPOSURE: E3 (authorized install), E5 (process interruption at the promotion window). Policy floor: none.
- Original independent derivation, preserved: I6 (upgrade capability unavailable) + I8 (residual code), MEDIUM/SHOULD, before comparing with the separate unhappy-path finding.
- Separate unhappy-path derivation reported by the coordinator: I5, persistent installer state-machine wedge, invokes I5(c) → **HIGH/BLOCKING**, E3/E5, verified. This is recorded separately from this actor's original native MEDIUM/SHOULD assessment; provisional shared-cluster gating uses the strongest report pending coordinator adjudication. No unsigned execution, privilege escalation or data-loss claim is made.
- Independent convergence: coordinator subsequently reported an independently produced unhappy-path reproduction of the same window. Shared defect cluster UP1, two independent reporters; one fix, not two separate defects.

Reproduction: `/private/tmp/yuzu-macos-foundation-review/repro-recovery-plugin-window.py` extracts the actual two recovery/removal functions and the actual subsequent collision classifier; rewrites fixed production deletion destinations into a disposable directory; stubs only platform copy/service calls. Output:

```text
RECOVERY_EXIT 0
RESTORED_MANIFEST plugins/old.dylib
RESTORED_OLD_BYTES b'original old plugin'
UNMANAGED_NEW_PLUGIN_REMAINS True
RETRY_PREFLIGHT_EXIT 1
ERROR: incoming plugin collides with an unmanaged third-party plugin: new.dylib
```

Fix: account for the trusted incoming manifest during interrupted-promotion cleanup before restoring the snapshot; regression-test interruption before/after manifest promotion and subsequent retry. Preserve receipt-only historical adoption and unmanaged-plugin collision protection.

## Other consistency coverage

Compared sibling legacy-app identity/profile/signature guards; Gate 2 SEC1 repair is present at all three sites. Receipt-derived historical ownership and existing manifest cleanup retain their boundaries. JXA preserves the intended selected argument/environment contract and forced bundle OTA/signature controls; CMS two-stage instructions match the existing final-byte builder/verifier boundary. No new REST/proto/store/ABI/action surface is introduced; the smoke consumes existing explicitly targeted command routes and disclaims identity/transport attestation. Guardian preference remains false by default; ES feeds TAR, not Spark, and docs do not claim a consumer cutover. Git and Docker exclusions agree on private `.agent-runs/` evidence.

CP1 remains the existing Gate 3 portability finding under repair, not a new independent consistency finding. Its repair needs separate Gate 3/8 closure. Fresh signed package/installer and oldest-OS lifecycle behavior are not certified by this read-only review. Verdict: **BLOCKING shared UP1**; no other new consistency findings.

## UP1/C1 fix recheck

**Fixed.** `preinstall:180` now removes trusted incoming-manifest entries as well as the current manifest before restoring saved files. Re-ran this actor's unchanged-window reproduction against the corrected actual function: `UNMANAGED_NEW_PLUGIN_REMAINS False`, `RETRY_PREFLIGHT_EXIT 0`, original old bytes/manifest restored. The added product real-function regression also passed and checks unrelated plugin retention. This closes the shared UP1/C1 defect; no live installation was used as evidence. Consistency verdict **PASS**; separate Gate 3 CP1 portability closure remains pending.

---

Source: `gate5-chaos.md`

# Gate 5 — controlled fault designs (not executed)

Read chaos-injector brief, shared severity contract, Gate1, happy/unhappy Gate4-a and consistency Gate4-b verbatim. Pinned scope remains `1972d3e2a..6eb78e12e` plus current index/working changes. Integrity echo: `remove_managed_plugins "$INCOMING_MANIFEST"`.

These are executable implementation recipes for quality-engineer, not newly observed defects or a claim that chaos/install acceptance ran. Root implemented UP1, CPP-S1 and CP1 fixes. Since that status message, bounded Gate8 re-review verified UP1 and CPP-S1 against actual-function/actual-owner regressions; CP1 closure remains with its originating reviewer. Historical severity remains attached to source findings. No code execution occurred during this design phase.

Common safety: phase A uses only unique `yuzu_test_` disposable fixture roots, extracted production functions with all absolute mutation paths rewritten, and deterministic launchctl/pkgutil doubles. Assert no unresolved production deletion path before execution. Record source hash, injected exit, code/manifests/config hashes and evidence without secrets. No signal, resource limit, firewall, disk-fill or service mutation may affect another process. Phase B requires separately authorized lifecycle qualification with restorable host snapshot/backup and explicit service/data scope; this report authorizes none.

## C5-01 — crash-window recovery symmetry

- Target: deployment; severity high; epistemic verified historical UP1/C1 (I5/E3/E5), now bounded fix verified.
- Hypothesis/setup: old manifest/plugin, new manifest adding one plugin, unrelated third-party plugin; construct prepared and promoting snapshots.
- Injection/trigger: terminate fixture subprocess after each plugin move, immediately before/after manifest rename; one transition per run, zero external delay.
- Success: prepared state never deletes active old code; promoting recovery restores exactly old package hashes, removes new-only code/signatures, preserves third-party bytes and allows next collision preflight/install attempt. Repeat recovery twice.
- Rollback/phase: stop fixture child; retain evidence then remove only its private root. A now; B later for actual launchd lifecycle.

## C5-02 — durable sidecar ownership

- Target: test resource ownership; severity high; epistemic verified historical CPP-S1 (I2/I3/E3/E5), now actual-owner fix verified.
- Hypothesis/setup: actual FileBackup on private regular file; record original bytes and backup path.
- Injection/trigger: child-only late buffered write failure after sentinel open; separately replace destination with directory before restore to force rename failure. Never apply RLIMIT to the runner process.
- Success: snapshot failure leaves source intact; failed sentinel write is reported; failed restore retains readable original on disk after child termination; remove obstruction and restore via rename, then repeat restore idempotently. Symlink/FIFO inputs must fail before writing. No requirement of power-loss durability.
- Rollback/phase: recover from retained backup before deleting fixture. A; baseline actual-owner rename regression already passed separately.

## C5-03 — conditional signature rejection

- Target: legacy ownership trust; severity high; epistemic verified historical SEC1 (I1), fixed.
- Hypothesis/setup: actual legacy predicate in all three installer scripts; valid identity/profile metadata doubles.
- Injection/trigger: codesign verification returns nonzero while metadata commands succeed; invoke predicate inside the same `if`/negation contexts that suppress shell errexit.
- Success: each rejects ownership; no legacy retirement/deletion/bootstrap call occurs. Run success control to rule out unconditional rejection.
- Rollback/phase: fixture-only audit log and paths. A; real tampered app-copy verification separately, never tamper installed code.

## C5-04 — receipt and unknown ownership

- Target: deployment migration; severity medium; epistemic verified historical SEC3 (I6), fixed.
- Setup/injection: absent manifest; pkgutil double yields valid immediate plugin, missing receipt, traversal/nested/leading-dot malformed matching name, or lookup failure, one per invocation.
- Trigger/success: only conservative receipt-owned names enter atomic manifest; malformed matching entries fail before snapshot/promotion; unknown existing plugin remains byte-identical and colliding incoming name is rejected. No receipt never authorizes directory-scan adoption.
- Rollback/phase: discard private receipt/manifest fixtures after hashes. A.

## C5-05 — native configuration merge failure

- Target: installer configuration; severity medium; epistemic likely risk from Gate4-a, not a finding.
- Setup/injection: macOS private plist files and actual Foundation JXA merger; malformed source/destination plist, missing required argv, then unwritable destination directory in an unprivileged child.
- Trigger/success: invoke exact absolute osascript argv; nonzero failure, destination bytes unchanged, no partial plist; valid control preserves operator args/environment and forces bundle OTA/signature policy. Include spaces/quotes in paths.
- Rollback/phase: restore fixture permissions and remove fixture only. A macOS-native; permission test must prove denial rather than pass vacuously as root.

## C5-06 — stopped/running transition failures

- Target: installer lifecycle; severity medium; epistemic likely unexecuted Gate4-a risk.
- Setup/injection: stateful launchctl double: loaded, bootout failure, bootstrap failure, absent PID, alternating PID and running/exited states. Fail one call at each phase boundary, maximum six polling observations.
- Trigger/success: forward mutation requires confirmed stop; failures never claim installed success, preserve recoverable snapshot and configuration, and retries recover. Explicitly inspect rollback/replay/uninstall when bootout fails: do not assume ignored failure means stopped.
- Rollback/phase: fixture state reset. A first; actual service behavior B only after authorization.

## C5-07 — lost ES and misleading smoke success

- Target: observability/transport; severity medium; epistemic verified negative-fixture coverage, not verified live ES behavior.
- Setup/injection: existing smoke fake session; omit event, grow drop counter, change PID/hash, stall command terminal response, or interrupt cleanup, one bounded fault per run.
- Trigger/success: each emits failure within configured timeout, preserves diagnostic reason, never claims parity, and removes its own marker where possible. Successful control requires target-bound command and stable counters/PID/bytes.
- Rollback/phase: fake transport termination and scoped marker cleanup. A; FDA revocation/process restart on real host belongs to B.

Recommendation: retain development-PR qualification separate from production deployment. A passing design/review is not executed evidence; production requires signed-distribution, actual lifecycle/recovery and supported-oldest-OS qualification with explicit authorization.

---

Source: `gate6-a.md`

# Gate 6 — compliance-officer and SRE

One actor, two explicitly separate roles; no independent-count inflation. Scope pinned `1972d3e2a` through current staged/working integration. Read both briefs, shared severity/Gate1 and Gate2–5 reports; enterprise-readiness framework §§1–3.5 and §§3.6–9, including Workstream D, were consulted. No new schema requires the inventory's unrelated store-specific histories. Reread smoke checker, foundation runbook, recovery/retention guidance, evidence exclusions and latest lifecycle-test fix. Integrity echo: `transport_security_verified': False`.

## Compliance Review

**Control impact:** access/privilege boundaries (CC6), monitoring and response evidence (CC7), change management (CC8), availability/recovery (A1), confidentiality and processing integrity. These are control-alignment observations, not an SOC 2 certification or a new control matrix.

The purpose and narrow boundary are traceable through the pinned change summary, changelog, resource ledger and foundation runbook. This is opt-in development packaging, not shipped Spark/Guardian/Reflex parity. Endpoint Security signing/grant, root execution and user-controlled FDA remain separate prerequisites; instructions preserve SIP and forbid TCC edits. The package does not confer a Network Extension entitlement or broader server authorization. A root ES daemon is an explicit platform requirement, not a silent exception claiming non-root execution.

The smoke uses existing authenticated, explicitly targeted command routes; it does not mint credentials, alter RBAC or bypass existing command/audit authority. Its marker's normal command/audit/event records remain under existing retention, disclosed in the runbook. No new store, retention policy, telemetry export, or independent audit stream is introduced.

**Evidence impact:** safe summaries contain hashes, PID, timing and aggregate outcome; raw cookie contents, command argv/stderr and server response bodies are not printed. Cookie inputs must be private regular files; symlinks are rejected. URL credentials/query/fragment and arbitrary plaintext hosts are refused. `.agent-runs/` is excluded from both git and Docker contexts; these exclusions are not access control or automatic credential deletion. Device UDID/profile/identity evidence remains private. Installer recovery snapshots are root-only, retained on failure and intentionally not erased with operational data during uninstall.

**Policy/risk impact:** no new policy exception identified. Keep source/toolchain/artifact hashes and updated review records together; historic live evidence must not be attributed to newly rebased bytes. Development signing does not satisfy distribution-signing/notarization or production TLS evidence. No new compliance finding. **PASS for scoped controls review only**, subject to unresolved validation below; not release approval.

## Operational Readiness Review

**Observability:** process-running observations are weaker than healthy ES capture. The optional smoke checks the installed root executable, stable PID, targeted terminal command success, ES capture method, native marker EXEC/EXIT, unchanged drop counters and signed-byte hashes. It deliberately disclaims per-agent heartbeat, target identity attestation and transport verification. No metrics/audit/lifecycle-event schema changes require new metric registration. Stable counters over a short window are not capacity/SLO evidence.

**Deployment/recovery:** code and mutable state remain separate; disabled binary OTA prevents sealed-app rewriting. Trusted incoming/current manifests and receipt migration preserve unknown plugins. UP1 recovery/retry and CPP-S1 durable sidecar corrections have bounded re-review evidence; live stop/restart, upgrade/downgrade, interrupted recovery and uninstall are still unqualified. Recovery must remain available on failure; do not automatically purge it. Existing local UAT must remain running: the runbook forbids rerunning destructive startup merely to inspect it. No reviewer service operation occurred.

**Capacity:** no new production queue/cache/store or fleet fanout. The smoke targets one agent with bounded command/HTTP timeouts and a 90–600-second configured observation window; this is not a fleet load test. No RTO/RPO measurement or enterprise-scale claim is available.

### QA1 — introduced shared-process test cancellation pollution

- TRIGGER: the new lifecycle test stops its real Agent before later subprocess cases execute in the same Catch2 process.
- IMPACT: I6 supported validation lane unavailable. EXPOSURE: E3 test execution, E5 order-dependent inter-test state. EPISTEMIC: verified by root-provided same-seed reproduction (`2353298010`, 44 failures versus isolated 73 passing); independently source-traced `Agent::stop()` setting global cancellation. PROVENANCE: introduced. POLICY FLOOR: broken supported test leg introduced by change. Operational MEDIUM; gate BLOCKING by floor.
- Repair snapshots cancellation and restores it after stop/join, with a post-scope assertion. Source matches intended ownership; same-seed full-suite rerun is pending. Do not call this baseline or close it using isolated tests.

**SRE verdict:** no additional operational finding beyond QA1; overall validation remains BLOCKING pending closure. Final package must be rebuilt after fixes and exact final bytes checked. No fresh installation, production TLS, notarization, Intel/oldest-OS runtime, live recovery, or long-duration ES reliability certification is claimed.

Artifact-specific limitation received after initial report: the current shared `/Users/nathan/Yuzu/vcpkg_installed/arm64-osx` dependency prefix emits `libxml2.a` archive-member minos26 warnings while linking a minos13.3 target. No fresh complete static-archive audit establishes the older floor for these bytes. Prior historical clean-dependency evidence cannot certify this artifact. Treat current output as current-host development only until a separate clean 13.3 dependency build/audit and oldest-OS execution qualify it; do not modify the user's shared dependency prefix as part of this review.

---

Source: `gate6-b.md`

# Gate 6 — enterprise readiness

PASS for the scoped **development-foundation review only**; no new enterprise-readiness finding. This is not customer deployment acceptance, a full-suite pass, or macOS 13.3 runtime qualification. Scope: pinned `1972d3e2a` through HEAD plus current index/working tree; one reviewer, no independent convergence claimed. Read enterprise-readiness brief, Workstream G and adjacent SDLC/first-customer requirements, A5 contract/exception ledger, shared severity contract, Gate1 and Gate2–5 reports, and current operator/development/package documentation. Integrity echo: `A previous package's live result is not evidence for freshly rebased source.`

## Documentation and assurance

- `docs/macos-development-foundation.md:3–6,25–29,39–44,137–144` explicitly limits the lane to development, distinguishes deployment metadata from oldest-OS execution, excludes Network Extension/profile support, and requires new-artifact acceptance. TAR's NOTIFY EXEC/EXIT observation is explicitly not synchronous AUTH prevention or Spark (`:121–127`). Guardian's `prefer_spark` is unchanged; DEX reuses existing Mac collectors; Reflex remains future architecture. No new parity or production-security claim is introduced.
- `docs/user-manual/upgrading.md:5–22` provides the required operator pointer, OTA/executable-location change, development-only unsigned package warning, retained state, receipt ownership, and shared loose/app recovery implications. D1 remains fixed. Packaging README supplies authoritative signing/CMS and noninteractive lifecycle commands; no duplicate CLI reference is required for the hidden packaging verifier.
- Workstream G's assurance outputs are not newly invalidated: no auth/RBAC/IdP, SIEM, DPA, or fleet data schema changes. A later customer assurance packet must distinguish ES observation, signing identity, privacy permission and transport security; the new runbook already does so. Existing assurance backlog is not closed by this change.

## Deployment and integrations

- `deploy/packaging/macos/README.md:57–106,108–143,145–191` documents root LaunchDaemon/FDA authorization, separate mutable data/config/trust, immutable code, operator-provisioned CMS trust anchors, final-byte signing order, receipt-limited ownership, recovery evidence and retained-data uninstall. Native JXA removes the newly introduced installed Python dependency (RD2); Python remains a development/build/smoke prerequisite, not an installer runtime assumption. RD1/RD3 and shared UP1 fixes retain their existing bounded proof; no new live lifecycle proof is inferred.
- The optional smoke tool consumes existing authorized command APIs for one explicit target; it does not add a remotely callable capability. ADR-1005/A5 therefore needs no new twin/schema or exception. A5 ledger audit: four closed entries retain their issue provenance; sole open #2990 has revisit-by **2026-10-31**, not stale on 2026-09-17. No undated active entry.
- Foundation runbook `:67–70,76–90,106–109` separates explicit loopback-only plaintext lab authorization from TLS/mTLS proof, keeps cookie/profile/device evidence private, and excludes `.agent-runs/` from git and Docker. Signing is not FDA, notarization, network entitlement or transport attestation.

## Evidence limits and release prerequisites

Current signed-app staging success is parent-reported; the package will be rebuilt after fixes and no fresh installation occurred. Historical live ES evidence cannot qualify this source/artifact. Parent reports shared `libxml2.a` objects with minOS 26 despite output metadata 13.3: **the current artifact is current-host development-only**. Clean 13.3-targeted dependencies and oldest-supported-OS execution remain required; no user dependency prefix was modified. Parent identified global-cancellation fixture pollution behind 44 full-suite failures and applied a fix; same-seed rerun is pending. Focused 73-case success does not substitute. CP1 final Windows-path closure also remains a Gate8 responsibility.

No new finding means no severity derivation/policy floor is asserted. Existing findings retain their originating IDs and evidence. Production/customer rollout still needs distribution signing/notarization, secure transport validation, native lifecycle/recovery, architecture/oldest-OS and remaining platform qualification plus independent review.

---

Source: `gate8-a.md`

# Gate 8 final wave A — rerouted fix-domain review

Scope: pinned `1972d3e2a..6eb78e12e` plus current staged/working changes; fix sweep uses `git diff HEAD`. Both routed-concern tables were reopened and read row by row, with truncated output recovered in smaller reads. Nine roles below are ONE reviewer, not nine independent reports. Relevant briefs and refs from the earlier gates remain applicable; C++ skills reread, full new JXA reread. No product edit, service/install operation, shared-dependency mutation or chaos execution.

Matched fixes/new foundation paths: packaging→shared CMS/security/release; C++→expert/safety/ledger; tests→quality/Darwin; smoke→dispatch targeting/public API authority/security/architecture; operator/manual/runbook→docs/domain truth; deployment/recovery/evidence→compliance/SRE. No new auth-store, server-schema, retention/reaper, protobuf, ABI, metrics/event-schema, approval primitive, engine-path or common-header trigger. Broader original power-health/TAR/build routes retain prior coverage and worker B's build/platform rerun. Integrity echo: `yuzu::agent::request_subprocess_cancel(previous_subprocess_cancel);`.

## security-guardian — PASS scoped review

All three legacy predicates explicitly return on failed codesign; metadata cannot mask signature failure under conditional shell contexts. Exact Installer-receipt adoption uses conservative immediate dylib names, a trusted root-owned nonsymlink plugin parent and atomic synthesized manifest before snapshot. No receipt grants no ownership. Both current and trusted incoming manifests participate in interrupted promotion cleanup, after the transaction's original collision preflight; no directory-scan adoption of unknown plugins.

Existing mutable data ownership is deliberately preserved; only absent data working directory is created, and symlink data roots are refused. This does not move sealed code into the mutable data root. JXA receives argv through absolute osascript, parses plist as data, requires string argument/environment structures, retains only whitelisted environment keys and atomically serializes the destination. No eval/shell/GUI automation or Python customer dependency. Existing trust-policy and forced bundle OTA arguments remain authoritative. Shared final-byte CMS verifier remains sole authority.

Smoke secrets/errors remain sanitized; explicit single target, terminal status, local process/executable identity, signature/hash and ES counters are checked. Cookie path validation and no redirects/TLS bypass remain. No new privilege or SIP/FDA bypass. No additional finding.

## cpp-expert — PASS source review

Scoped std::thread replaces unsupported-toolchain jthread use. Capture lifetime is bounded by owned join; no new ABI exposure, cast, narrowing or borrowed-view escape. Cancellation state is snapshotted before thread launch, restored after stop and join, and asserted after runner scope. QA1 test-gate closure still needs the exact broader run below.

## cpp-safety — PASS ownership fix; QA1 validation pending

CPP-S1 now preserves regular-file originals in a private unique same-filesystem sibling directory before sentinel writes; symlinks/nonregular files are rejected. Failed constructor copy leaves source intact. Explicit close detects late sentinel errors; unwinding then calls the actual owner. Restore is atomic rename, not buffered rewrite: failed rename leaves original bytes on disk outside an auto-deleting TempDir; success is idempotent and removes the empty backup directory. Previously observed I2 is closed, not discounted because an error is visible. No power-loss durability claim.

AgentRunner stop precedes joining run; run's cleanup drains owned workers, then prior process-global cancellation is restored. stop_completed_ makes later stop calls no-op. Sidecar restoration follows runner destruction and precedes flock release. Resource Ledger: complete, including cancellation state and disk backup. Platform-targeted regressions exist; TSan/ASan/UBSan were not run here. No new ownership finding.

## quality-engineer — source review clean; QA1 BLOCKING pending evidence

Actual-owner restore-failure regression had passed 4 assertions/1 case; it observes retained backup bytes and successful retry, not merely a helper error. Interrupted recovery fixture invokes actual production functions and checks old/new/third-party bytes and next collision preflight. Smoke exercise executes orchestration with explicit fake platform/transport boundaries; it does not pretend to be live ES.

This rerun independently passed 12 foundation tests, one native malformed-plist merge test, and six focused packaging tests: conditional bad signature, receipt ownership, data-directory preservation, interrupted recovery/retry, native hardened-policy merge and retained disabled OTA. No full suite rerun was duplicated.

QA1 history remains: same-seed full suite `2353298010` showed 44 subprocess failures from new lifecycle fixture cancellation leakage, while isolated 73 subprocess cases passed. Root-provided verified observation plus independent source trace; I6/E3/E5, introduced, broken-supported-test-leg policy floor BLOCKING. Current code repair looks correct but is NOT closed until root supplies exact same-seed broader passing evidence. CP1 platform-test closure is worker B's responsibility; no native Windows/Linux pass is asserted here.

## architect — PASS

No Spark preference flip or new Guardian/Reflex mechanism. Smoke consumes existing core-owned targeted API authority; no private API or new server capability requiring an MCP twin. Foundation JXA is local installer plumbing, not a new policy service. No trust-verifier fork, datastore, scheduler, approval gate or module cycle.

## happy-path — PASS reviewed corrections, not installed acceptance

Fresh data-root creation, operator argv preservation, signed immutable bundle promotion, receipt migration and verified final-byte handoff remain coherent. Normal/replayed rollback now agree on incoming plugins. Boot observation remains explicitly weaker than ES readiness. QA1 full-suite evidence and actual lifecycle execution are separate gates.

## unhappy-path — PASS UP1/CPP-S1 closure

UP1 new-plugin-before-manifest window is fixed with preserved old and third-party byte assertions and successful retry. CPP-S1 late-write/failed-rename ownership no longer depends on restoring from process-only RAM. Gate5 bootout/bootstrap/permission/disk and phase-boundary designs remain unexecuted, not claimed resolved through source inspection alone. No additional demonstrated defect.

## compliance-officer — PASS scoped controls

Development grant/root/FDA/SIP and private evidence boundaries remain honest. Exclusions prevent accidental git/Docker inclusion, not access control. Normal command/event/audit retention is unchanged; recovery evidence intentionally persists on failure. Final source/artifact hashes and approval records must supersede historical evidence. No new audit/privacy policy exception.

## sre — PASS review with explicit qualification limits

Do not restart or reinitialize retained UAT. No fresh package installed; rebuild final package after source fixes and check exact bytes. Root reports current shared vcpkg prefix `libxml2.a` objects with minos26 warnings despite emitted minos13.3; no current complete static-member audit or oldest-OS execution exists. Current artifact is current-host development evidence only. Historical clean dependencies do not certify it. Production TLS/mTLS, distribution signing/notarization, Intel/older-OS runtime, actual install/recovery/uninstall and sustained ES reliability remain unverified.

Overall: **review itself clean after fixes; validation gate remains BLOCKING pending QA1 same-seed full-suite evidence and worker B CP1 disposition.** No blanket governance/release PASS. Coordinator-authored final review records were not yet present and their eventual assertions require a bounded truth check.

## Final bounded closure — QA1 and draft truth check

QA1 **FIXED**. Independently inspected `agent-suite-seed-fixed.log`: command uses the normal agent target's `~[tsan-heavy]` filter and exact reproducing seed `2353298010`; duration 111.89s, result exit status 0; 3,157 cases, 3,152 passed, 5 skipped; all 165,801 assertions passed; Meson Ok 1 / Fail 0. This is broader same-seed evidence for the cancellation restoration, not the insufficient isolated subprocess pass. It is not sanitizer execution; ASAN/UBSAN environment variables printed by Meson do not themselves prove instrumented binaries. The earlier blocking disposition above remains historical. CP1 is reported closed by the separate platform reviewer, without claiming a native Linux/Windows run.

Read `docs/security-reviews/macos-development-foundation-20260917.md` draft in full. Its source range, same-actor role accounting, independently reproduced recovery finding, sidecar partial-fix history, QA1 failure and exact-seed closure, no-install/production/parity limitations and current libxml2 minos26 caveat match the reviewed evidence. Combined-five-target and extracted-app signature checks are explicitly pending, not represented as completed. Package/executable hashes, source-equal extracted scripts and current UAT/service status are implementer-provided operational evidence; this reviewer has not independently reproduced those checks. No contradiction found in the draft's scoped assertions. Final reports/ledger links are draft handoffs to be populated by the coordinator, not independently certified present by this check.

Current wave-A final outcome: **PASS scoped review, no remaining wave-A finding.** Overall validation must still respect combined-suite/artifact checks and all live/production/oldest-OS qualification limits. A normal agent-suite pass excludes `[tsan-heavy]` by its registered target definition; do not describe it as sanitizer coverage or every possible test mode.

---

Source: `gate8-b.md`

# Gate 8 — build/platform/release/plugin/docs/consistency/enterprise rerun

PASS for these scoped development-review domains; **CP1 FIXED** for the identified defects. No new finding. This is one actor applying seven role briefs, not seven independent reviewers. Comparison remains pinned `1972d3e2a` through current working/index tree; fix reroute additionally inspected `git diff HEAD`. Both routed-concern tables were reread completely, row by row. Integrity echo: `remove_managed_plugins "$YUZU_LIB/.package-files.incoming"`.

## Rerouting

Applicable rows: macOS/Darwin, packaging detached-CMS chokepoint, C++ ownership and tests, general docs, privilege model, platform/plugin coverage, agentic-first/ADR-1005 and enterprise parity. The C++/security/quality owners separately rerun their domains; this report does not substitute for them. No new auth store, request-admission gate, schema, proto, MCP tool, plugin action, Spark mechanism or Guardian consumer-selection change. Power-health change is Darwin linkage only: no new destructive action or securable. No cache workflow changed; the sentinel edit documents the target triplet, not cache policy.

## Distinct domain outcomes

- **build-ci — PASS (source and bounded validation).** New tests remain registered in Meson's `agent` suite with bounded timeout. Darwin Objective-C++ linkage covers all three `.mm` plugin consumers (TAR, Wi-Fi, power health); Linux/Windows linkage is unchanged. Full-Xcode ES resolves the SDK library and retains CLT fallback. Target triplet pins 13.3 without changing other target triplets. No compile/full-suite result is invented by this reviewer.
- **cross-platform — PASS; CP1 closure.** `tests/test_macos_app_packaging.py:314,367,530,565,585,700,762,790` gate actual JXA, ditto/PlistBuddy, native stat/archive integration to Darwin. `:51,105,145,173,268,829` gate POSIX Bash/permissions/receipt/recovery fixtures away from native Windows. Pure profile, load-command, signing-argv, generated-plist, smoke parser/client contracts stay active. `:687,718,745` uses `sys.executable`; `:786–788` and `tests/test_macos_foundation.py:109` compare platform-formatted `str(Path(...))`. Foundation AWK test independently checks tool availability. CP1's introduced-supported-test-failure floor is resolved for the demonstrated paths; **no native Windows/Linux execution claimed**.
- **release-deploy — PASS for reviewed transitions.** RD1 absent-only DATA_DIR creation preserves existing ownership/mode/contents and refuses symlinks. RD2 uses absolute native `osascript`, shipped JXA/Foundation data parsing and atomic serialization, not installed Python. Valid config preserves server/TLS/signing policy; generated signing policy takes precedence; malformed arguments/environment fail without replacing destination. Receipt adoption uses exact Installer ownership, not directory scanning. Both synchronous and interrupted recovery remove current plus incoming transaction-owned plugins; UP1 regression restores old bytes, removes new-only bytes, retains third-party bytes and permits retry. Uninstall removes new/historical merge helpers and retains operational data. These are fixture/source proofs, not installed service acceptance.
- **plugin-developer — PASS.** ABI, descriptors, actions and proto are unchanged. RD3's documented fresh-input two-stage process applies CMS to final Apple-signed output, then packages with policy/trust validation; it forbids deleting enforced sidecars or re-signing after CMS. The final-byte/tamper fixture explicitly uses a verifier double: orchestration evidence, not cryptographic proof or live plugin acceptance.
- **docs-writer — PASS.** D1 operator upgrade pointer, changelog fragment, authoritative packaging commands, runbook prerequisites/permissions/private evidence and unsupported boundaries remain aligned. Resource ledger now describes durable original sidecar backup, checked close, same-filesystem restoration and cancellation restoration after thread join; historical review range is explicitly not integrated-source certification. No claim of power-loss durability.
- **consistency-auditor — PASS.** Pre/post recovery symmetry and old/current incoming manifests remain coherent after fixes. Explicit-target smoke consumes existing APIs, reports transport verification false, and does not silently claim identity attestation, new capability or Spark/AUTH support. `prefer_spark` stays unchanged.
- **enterprise-readiness — PASS, development only.** Gate6-b A5 audit remains valid. Current shared libxml2 archive minOS-26 warnings mean the current artifact is **not 13.3 runtime-qualified**, regardless of final metadata. Clean dependencies, oldest-OS/Intel execution, distribution signing/notarization, actual lifecycle and secure transport remain release gates.

## Executed evidence and limits

Independently executed current `python3 tests/test_macos_app_packaging.py`: **35 passed**, including actual native JXA; `python3 tests/test_macos_foundation.py`: **12 passed**; `git diff --check 1972d3e2a`: clean. Only disposable fixtures; no installation/services/live operations. QA1 same-seed full-suite rerun remains with root/worker A; focused success is not full green. Signed staging is not a fresh install, and historical live evidence does not certify current bytes. Final orchestrator summary is not yet written or reviewed. No new derivation/policy floor; original finding history is preserved in prior reports.

## Final summary truth check (subsequent evidence)

Read `docs/security-reviews/macos-development-foundation-20260917.md` fully after creation. Its domain assertions and explicit limitations are consistent with this review; docs/consistency/enterprise PASS. The preceding pending-status paragraph is historical: root now reports same-seed full agent exit 0, 3,157 cases / 3,152 passed / 5 skipped and 165,801 assertions; SRE independently checks the log, not this reviewer. Summary correctly distinguishes that from still-pending final combined targets and extracted-app signature verification. The newly supplied package/executable hashes and byte-identical expanded installer scripts are root-reported artifact evidence, not independently recomputed here. Source/artifact/installed-host and metadata/runtime boundaries remain explicit, including libxml2 minOS-26 warnings. Companion raw-report link must be materialized by the orchestrator before commit, as planned; it was not yet present at this check. No new product finding.

<!-- End of verbatim review reports. -->
