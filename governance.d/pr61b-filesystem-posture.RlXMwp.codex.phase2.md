# codex — Phase 2 cross-examination — PR6.1-b filesystem_posture

## Peer finding cross-examination

| PEER-ID | label | evidence I checked (file:line / command) | my severity |
|---|---|---|---|
| K1 | agrees-with-mine ([CDX-P1-07]) | `filesystem_posture_macos.cpp:269-272`; reran `[filesystem_posture]` and observed nine false warnings during 238/238 passing assertions | HIGH |
| K2 | agrees-with-mine ([CDX-P1-03]) | `test_filesystem_posture_local_dispatcher.cpp:185-251` lacks status/completeness/provenance assertions; `:171-183` tests only the synthetic callback | MEDIUM |
| K3 | agrees-with-mine ([CDX-P1-08]) | `rg 'ctx\.write_output'` leaves the three wrappers plus `filesystem_posture_plugin.cpp:131`, contradicting `filesystem_posture_legs.hpp:14-15,132` | LOW |
| K4 | disagrees | `filesystem_posture_macos.cpp:190-216`, Linux `:164-220`, and Windows `:308-441`: the defect is broader than all-probes-denied macOS and violates the stated degraded-read contract even in mixed-success walks | HIGH |
| K5 | confirmed-independently | `filesystem_posture_macos.cpp:227-289`: successful empty probes set neither `any_row` nor `any_failure`, so one failed peer volume makes “failed on every volume” false | LOW |
| K6 | confirmed-independently | `tests/meson.build:440-448`: the three-line `license_scan` comment is split, with its latter two lines attached after the filesystem-posture entry | LOW |
| K7 | agrees-with-mine ([CDX-P1-09]) | `agent-plugins.md:589` and `filesystem_posture.yaml:7,29-30` duplicate `GetVolumeInformationW`; implementation uses `GetDiskFreeSpaceExW` at Windows `:209` | LOW |
| K8 | confirmed-independently | `os-capability-matrix.md:92,108` defines Full as builds/core actions work, but no Linux build exists; Windows prose also says “compile-verified” despite the stated and source-header evidence that no Windows compiler has seen the body | LOW |
| K9 | false-positive/unfair | The run capture directory exists at `/private/tmp/claude-501/-Users-alex-yuzu-dev/b5835e30-f14a-4d61-b0c5-3c0f9f6f4600/scratchpad/devteam-wave6-1b-fsposture/captures/`; `PROVENANCE.md` plus seven named files are readable. Kimi searched only the repository | INFO / no finding |

Severity adjudication: K1 is HIGH, not my Phase-1 LOW, because `result_status`, completeness, provenance, and nine WARNs are themselves authoritative output and all are false on an ordinary successful APFS walk (I3, E0/E3, verified). K2 is MEDIUM, not my Phase-1 policy-floor HIGH: the live tests are incomplete but do not assert a status property they cannot observe, so the governance policy-floor carve-out says this is ordinary missing coverage. K4 is HIGH, not Kimi's LOW: the target's explicit central contract says an acquisition failure must not read as clean success; the typed FULL/OK envelope is false even though a diligent consumer could reparse individual rows.

## Peer coverage adopted or rebutted

- macOS live parser/status probe: adopted K1 after reproducing the nine warnings. Kimi correctly separated the parser's clean live reply from the brace defect.
- Test-adequacy distinction: adopted K2's policy-floor rebuttal and reduced [CDX-P1-03] to MEDIUM.
- macOS mixed failure/empty prose: adopted as [CDX-P2-10] after tracing both booleans.
- Meson attribution comment: adopted as [CDX-P2-11] after reading the surrounding source-list entries.
- Linux/Windows documentation honesty: adopted K8 but expanded it: Kimi called the Windows disclaimer honest even though “compile-verified only” directly conflicts with the target's empirical state and `filesystem_posture_win.cpp` header.
- Fixture provenance: rebutted K9; the prompt said captures live in the run directory, and the external run path recorded during Phase 1 exists with the promised provenance and captures.
- Decoder safety: Kimi's “clean” conclusion is rebutted. Its outer-buffer proof prevents process-memory OOB, but it never proves accesses stay inside the record's declared boundary; the directed 30-byte record is accepted as a clean fabricated name.
- Windows and Linux legs: Kimi's static checks of RAII, HRESULTs, inner UTF-16 bounds, errno handling, and failure-vs-empty rows are adopted as no-finding areas, but they do not address outer FSCTL framing, mixed quota failures, or the 4 MiB mountinfo flag.

## Own-finding defence and revisions

- [CDX-P1-01] defended: reran the directed sanitizer-built harness; `record_length=30`, `attr_dataoffset=4`, `attr_length=2` still returns `"\x02"` with `malformed=false`. Kimi proved only outer-buffer bounds, not record-local bounds.
- [CDX-P1-02] defended: the range and all commit bodies still contain no Ledger. Kimi did not address the explicit C++-diff policy floor.
- [CDX-P1-03] severity changed HIGH → MEDIUM for the policy-floor reason above.
- [CDX-P1-04] defended at HIGH: Kimi confirmed the macOS site but under-scoped both the affected legs and the false summary outcome.
- [CDX-P1-05] defended: quotas and snapshots receive but never inspect `read_truncated`; a complete-line 4 MiB prefix below the parser's 4096-entry cap remains a concrete false-clean trigger.
- [CDX-P1-06] defended: Kimi verified only the inner multistring. The three outer `SRV_SNAPSHOT_ARRAY` ULONGs remain unread and uncorrelated with `returned` or decoded count.
- [CDX-P1-07] severity changed LOW → HIGH after accepting that the typed result envelope is output, not merely conservative noise.
- [CDX-P1-08] defended unchanged and independently matched by K3.
- [CDX-P1-09] defended and expanded with K7/K8's additional false verification wording.
- No Phase-1 finding is withdrawn.

## Revised full finding list

[CDX-P2-01]  HIGH · CONFIDENCE(hi) · PROVENANCE(test-run) · unchanged
The APFS decoder accepts a record whose declared length does not contain its header
- Location:  agents/plugins/filesystem_posture/src/filesystem_posture_parsers.hpp:530 (+ :538, :546-560)
- Claim:     A malformed record can make bytes inside `attrreference_t`/`attr_length` become a fabricated snapshot name while the parser reports a clean result.
- Evidence:  The parser proves 32 bytes exist in the outer buffer, but accepts any nonzero `record_length`; the sanitizer-built directed harness supplies length 30, data offset 4, attribute length 2 and receives one `0x02` name with `malformed=false`.
- Scenario:  A malformed `fs_snapshot_list` reply declares a record shorter than its already-read header -> header metadata is decoded as the name -> a nonexistent APFS snapshot is emitted under a clean result.
- Inference: TRIGGER = a short declared record with an attribute reference into header bytes; IMPACT = I3; EXPOSURE = E0 + E5; EPISTEMIC STATUS = verified.
- Anchor:    CLAUDE.md standing rule 2 + review severity I3.
- Precedent: tests/unit/test_filesystem_posture_parsers.cpp:335 rejects an attribute span beyond the record, but has no header-overlap case.
- Mitigations: Outer-buffer checks prevent process-memory OOB, and output escaping prevents delimiter injection; neither prevents the false row.
- Fix:       Reject `record_length < 32` and `name_start_in_record < 32`; add the directed regression.
- Falsifier: Apple defines an `attrreference_t` target inside the record's fixed header as valid name payload.

[CDX-P2-02]  HIGH · CONFIDENCE(hi) · PROVENANCE(static-read) · unchanged
The C++ change has no Resource Ledger
- Location:  range `243de5bc..f30dd3a5` (all seven new plugin C++ files; especially macOS :237 and Windows :153-175, :471-480)
- Claim:     The mandatory ownership proof for new fd, HANDLE, COM, mutex, and process-static buffer boundaries is absent.
- Evidence:  No changed path or commit body contains the required owner/acquire/release/transfer/failure-cleanup Ledger.
- Scenario:  The C++ range reaches governance without the mandatory Gate-1 artifact for every new owning resource boundary.
- Inference: Policy-floor violation; operational trigger/impact/exposure do not apply; EPISTEMIC STATUS = verified.
- Anchor:    `.claude/skills/governance/SKILL.md` “Policy floors” and “Resource Ledger”; docs/cpp-conventions.md §Resource ownership and lifetime.
- Precedent: docs/resource-ledgers/wave5-pr51-runner-convergence.md:1.
- Mitigations: The code largely uses RAII, but implementation quality does not waive the explicit floor.
- Fix:       Add a complete Gate-1 Resource Ledger for this range.
- Falsifier: A complete Ledger for this exact range exists in the review record outside the supplied local materials.

[CDX-P2-03]  MEDIUM · CONFIDENCE(hi) · PROVENANCE(test-run) · severity-changed
Real-action tests omit the result-status contract
- Location:  tests/unit/test_filesystem_posture_local_dispatcher.cpp:185-251
- Claim:     The three real-action tests assert rc and row shape but never status, completeness, or provenance, so the live macOS false-PARTIAL defect passes.
- Evidence:  The tagged suite passed 238 assertions while logging nine false malformed-buffer degradations; only the synthetic callback test at :171-183 asserts status fields.
- Scenario:  A leg regresses failure accounting -> CI's real-action test remains green -> result-envelope behavior has no end-to-end regression guard.
- Inference: TRIGGER = any status-accounting regression; IMPACT = I6 missing test reach over this behavior; EXPOSURE = E3; EPISTEMIC STATUS = verified.
- Anchor:    judgment; governance explicitly classifies ordinary missing coverage as non-floor SHOULD.
- Precedent: tests/unit/test_filesystem_posture_local_dispatcher.cpp:171-183 shows the required assertions.
- Mitigations: WARN inspection exposed the current bug manually; no assertion enforces it.
- Fix:       Assert status/completeness/provenance for deterministic real actions and add injectable clean, mixed, and all-failure decision tests.

[CDX-P2-04]  HIGH · CONFIDENCE(hi) · PROVENANCE(static-read) · unchanged
Quota acquisition failures can be masked by a clean status on every OS
- Location:  filesystem_posture_macos.cpp:190-216; filesystem_posture_linux.cpp:164-220; filesystem_posture_win.cpp:308-441
- Claim:     Per-volume failures emit unavailable/permission-denied rows without reliably marking the result partial, so mixed or unclassified failures retain FULL/OK.
- Evidence:  macOS never marks `rc != 0`; Linux marks only when every probed device is permission-denied; Windows marks only `any_ntfs && !any_success`, so one successful/disabled volume masks every failed peer volume.
- Scenario:  One volume succeeds and another returns EACCES/E_ACCESSDENIED or an unknown acquisition error -> both rows emit -> the typed summary reports a clean complete read.
- Inference: TRIGGER = mixed-success quota walk (or macOS any syscall failure); IMPACT = I3; EXPOSURE = E0 + E5; EPISTEMIC STATUS = likely.
- Anchor:    CLAUDE.md standing rule 2 + review severity I3; the target's explicit degraded-read contract.
- Precedent: filesystem_posture_win.cpp:527-540 marks snapshots partial on any failed/truncated volume.
- Mitigations: A consumer reparsing every row can see some failures; status-only consumers cannot.
- Fix:       Track `any_failure` separately on each leg and mark partial for every genuine acquisition failure.
- Falsifier: The result contract defines FULL/OK as correct when one or more requested volume probes failed but emitted typed failure rows.

[CDX-P2-05]  HIGH · CONFIDENCE(hi) · PROVENANCE(static-read) · unchanged
Linux quotas and snapshots ignore the 4 MiB mountinfo read cap
- Location:  agents/plugins/filesystem_posture/src/filesystem_posture_linux.cpp:141-149, :225-241 (contrast :96-105)
- Claim:     Both actions accept `read_truncated=true` without surfacing it, allowing omitted mounts to be reported as a complete read.
- Evidence:  `read_mountinfo_capped` sets the flag after a one-byte probe; only `emit_mounts` checks it before parsing.
- Scenario:  Mountinfo exceeds 4 MiB, and the retained prefix ends on a complete line below the 4096-entry cap -> later mounts disappear -> quotas/snapshots report FULL/OK.
- Inference: TRIGGER = the stated over-cap complete-line prefix; IMPACT = I3; EXPOSURE = E0 + E5; EPISTEMIC STATUS = likely.
- Anchor:    CLAUDE.md standing rule 2 + review severity I3.
- Precedent: filesystem_posture_linux.cpp:103-104 marks this exact condition partial for mounts.
- Mitigations: Parser malformed/entry caps catch some large-file shapes, not this one.
- Fix:       Mirror the `read_truncated` check in quotas and snapshots.
- Falsifier: A procfs guarantee makes the stated prefix shape impossible.

[CDX-P2-06]  HIGH · CONFIDENCE(med) · PROVENANCE(static-read) · unchanged
The Windows snapshot walker ignores its outer framing fields
- Location:  agents/plugins/filesystem_posture/src/filesystem_posture_win.cpp:495-520
- Claim:     It skips `NumberOfSnapShots`, `NumberOfSnapShotsReturned`, and `SnapShotArraySize`, so a count/size-inconsistent FSCTL reply can be accepted as clean inventory.
- Evidence:  After checking only `returned >= 12`, it parses every remaining returned byte as a multistring and never reads or compares any header ULONG.
- Scenario:  A filesystem/filter reply claims two returned snapshots but supplies one valid token and terminator -> inner parse succeeds -> the incomplete set is clean.
- Inference: TRIGGER = internally inconsistent successful FSCTL reply; IMPACT = I3; EXPOSURE = E0 + E5; EPISTEMIC STATUS = likely, Windows body uncompiled.
- Anchor:    CLAUDE.md standing rule 2 + review severity I3.
- Precedent: filesystem_posture_macos.cpp:193-199 validates a successful reply's declared size.
- Mitigations: Inner UTF-16 bounds checks prevent memory OOB but cannot detect ignored outer-count disagreement.
- Fix:       Decode and validate all three ULONGs against `returned`, payload size, and decoded count; add header-level synthetic tests.
- Falsifier: The API guarantees successful replies cannot contain inconsistent header values, including replies produced through filesystem/filter drivers.

[CDX-P2-07]  HIGH · CONFIDENCE(hi) · PROVENANCE(test-run) · severity-changed
An unbraced if falsely degrades every successful APFS snapshot probe
- Location:  agents/plugins/filesystem_posture/src/filesystem_posture_macos.cpp:269-272
- Claim:     `mark_result_partial` is unconditional, so clean APFS reads return false CONSTRAINED/PARTIAL status, provenance, and warnings.
- Evidence:  The tagged run passed but emitted nine “malformed reply buffer” warnings; the shipped parser returns `malformed=false` on a live reply, and compiler warning analysis identifies line 271 outside the if.
- Scenario:  Any ordinary macOS snapshots action succeeds -> the server receives authoritative but false degraded state -> real degradations become indistinguishable from routine false alarms.
- Inference: TRIGGER = any successfully parsed APFS mount; IMPACT = I3 and I4; EXPOSURE = E0 + E3; EPISTEMIC STATUS = verified.
- Anchor:    CLAUDE.md standing rule 2 + review severity I3/I4.
- Precedent: filesystem_posture_macos.cpp:256-261 correctly braces the failure branch.
- Mitigations: Snapshot rows remain accurate, but no layer corrects the typed status/provenance or warnings.
- Fix:       Brace both statements under `if (parsed.malformed)` and cover clean status end-to-end.
- Falsifier: A clean live macOS run returns COMPLETED/FULL with the current source.

[CDX-P2-08]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read) · unchanged
The pinned single-output seam has an extra unescaped writer
- Location:  filesystem_posture_plugin.cpp:131; filesystem_posture_legs.hpp:14-15,132-155
- Claim:     The unknown-action path directly writes raw action text, contradicting the “ONLY call sites” seam and bypassing the shared escaper.
- Evidence:  Source search finds the three wrappers plus `ctx.write_output` at plugin.cpp:131.
- Scenario:  A direct/local hostile unknown action includes delimiters -> captured error framing is forgeable.
- Inference: TRIGGER = direct invocation with hostile undeclared action; IMPACT = I3; EXPOSURE = E6 because production classification rejects it; EPISTEMIC STATUS = verified; cap LOW.
- Anchor:    CLAUDE.md standing rule 3 for comment truth; operational grade is judgment.
- Precedent: agents/plugins/rdp_control/src/rdp_control_plugin.cpp:321 sanitizes unknown action output.
- Mitigations: Production catalogue/classification rejects undeclared actions and execute returns nonzero.
- Fix:       Route sanitized error output through the seam or narrow the comment to row-emitting writers.

[CDX-P2-09]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read) · expanded-from-cross-exam
Bundled docs contradict mechanisms, quota behavior, and verification state
- Location:  content/definitions/filesystem_posture.yaml:7-8,29-30,111-117; docs/user-manual/agent-plugins.md:589-590; docs/os-capability-matrix.md:92,108; capability catalogue header:22-23
- Claim:     Docs duplicate the wrong mounts API, name an unused quota object/path, say macOS quota is unsupported, call Windows compile-verified when it was not compiled, and mark Linux Full despite no build evidence.
- Evidence:  Windows code uses `GetDiskFreeSpaceExW` and only `IDiskQuotaControl` getters; macOS emits configured/none states from `getattrlist`; the target and Windows file header say MSVC CI is the first real compiler; no Linux build exists.
- Scenario:  Operators/reviewers trust shipped descriptions -> audit the wrong API surface or overstate platform readiness and quota semantics.
- Inference: TRIGGER = reliance on bundled docs; IMPACT = I8/I9; EXPOSURE = E3; EPISTEMIC STATUS = verified for contradictions, likely for eventual Linux buildability.
- Anchor:    CLAUDE.md standing rule 3; severity otherwise judgment.
- Precedent: docs/os-capability-matrix.md:337-345 accurately names most implemented mechanisms and caveats.
- Mitigations: Runtime rows remain truthful; future CI would expose compilation failure before merge.
- Fix:       Correct the API/quota prose; say Windows “implemented, compilation pending first MSVC CI”; mark Linux verification pending until compiled or provide actual Linux build evidence.

[CDX-P2-10]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read) · new-from-cross-exam
macOS mixed empty/failure snapshots claim every volume failed
- Location:  agents/plugins/filesystem_posture/src/filesystem_posture_macos.cpp:227-289
- Claim:     `!any_row && any_failure` emits “failed on every volume” even when another volume succeeded with an empty snapshot set.
- Evidence:  Success-with-zero-names changes neither boolean; any single failed peer sets `any_failure`.
- Scenario:  One APFS volume fails and healthy peers are empty -> operator receives an overstated fleet-wide failure detail.
- Inference: TRIGGER = mixed failed and successful-empty APFS probes; IMPACT = I8; EXPOSURE = E5; EPISTEMIC STATUS = likely.
- Anchor:    judgment.
- Precedent: Windows :527-531 reports a failure without claiming every volume failed.
- Mitigations: PARTIAL status is correct; only detail prose is false.
- Fix:       Say “failed on at least one volume; no snapshots were enumerated” or report counts.

[CDX-P2-11]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read) · new-from-cross-exam
The test source-list edit misattributes the license-scan comment
- Location:  tests/meson.build:440-448
- Claim:     Two continuation lines describing `test_license_scan_actions.cpp` now follow and appear attached to the filesystem-posture test entry.
- Evidence:  `test_license_scan_actions.cpp` has no trailing explanation; filesystem-posture's final comment line contains the license-scan heading and the following two lines describe that earlier test.
- Scenario:  A maintainer reads the source list -> attributes license-scan end-to-end/runner coverage to the filesystem-posture test.
- Inference: TRIGGER = maintenance/review of the test list; IMPACT = I9; EXPOSURE = E0; EPISTEMIC STATUS = verified.
- Anchor:    CLAUDE.md standing rule 3; severity otherwise judgment.
- Precedent: Adjacent test entries keep continuation comments directly under their own source.
- Mitigations: Build membership itself is correct.
- Fix:       Move the three license-scan comment lines back under `test_license_scan_actions.cpp`.

## Areas checked with no revised finding

- No process-memory OOB or nontermination reproduced in either decoder across the sanitizer harness's million random inputs; [CDX-P2-01] is a record-boundary/semantic false-clean defect.
- All untrusted row fields pass through `safe_output_field`; nullopt renders `-`; fixed tokens remain caller-invariant; formatters add no newline.
- Windows HANDLE/COM and macOS fd ownership are RAII-managed; no ScopedFd same-identity-reset issue exists. This does not waive [CDX-P2-02].
- Capability rows are ReadOnly/None/Inventory/Read/Low/None and match the operations; all OS descriptor columns exist unconditionally; constrained legs retain real rung/mechanism plus fallback.
- Snapshot failure detail survives all three `kind=none` rows; Windows clean-empty and failure are distinct; Linux unreadable mountinfo retains its failure detail.
- The real capture labels match the external run captures; Windows tests are explicitly synthetic. K9 is rejected.
- Changelog fragment exists; no direct `CHANGELOG.md` edit. Matrix generation differs only on the two documented host-dependent wifi rows; all nine filesystem-posture rows match.

VERDICT:  BLOCK — the revised set retains five operational HIGH defects plus the mandatory missing-Resource-Ledger floor; the peer's macOS brace finding is also raised to HIGH in my grading.
COVERAGE: deep — both binary decoders and record/framing semantics; every acquisition/error path on all three legs; result-status and failure-vs-empty accounting; RAII/COM/HANDLE/fd ownership; seam/escaping/wire vocabularies; capability declarations and ABI leg shape; fixture provenance; tests, build registration, docs, packaging, changelog, and capability matrix. Static-only — Linux and Windows TUs because no Linux host/toolchain or Windows SDK/compiler/live host is available; no claim of either platform's compilation.
RAN:      Phase 2: `meson compile -C build-macos filesystem_posture` -> no work, success; `./build-macos/tests/yuzu_agent_tests '[filesystem_posture]'` -> 27 cases/238 assertions pass with nine false macOS malformed-buffer warnings; existing sanitizer-built `.cache/advrev-61b/codex_decoder_fuzz` -> rc 0 (directed short-record fabrication plus 1,000,000 random cases); `bash scripts/ci/check-plugin-spawn-lexical.sh` -> clean; `python3 tests/test_capability_gate_consistency.py` -> 9 tests OK; `bash scripts/ci/check-capability-matrix.sh build-macos` -> exit 1, diff limited to the two expected wifi rows. Phase-1 empirical evidence retained: Apple-Clang syntax warning at macOS :271; fixture byte comparison matched all captures. CI status: none, branch is local-only/unpushed; Linux and Windows were not compiled.
FILES:    both Phase-1 reviews; `.claude/{routed-concerns.md,routed-concerns-access-control.md,skills/governance/SKILL.md}`; `CLAUDE.md`; `docs/cpp-conventions.md`; `sdk/include/yuzu/plugin.h`; all seven filesystem_posture C++ files and its meson file; both filesystem-posture unit tests; `tests/meson.build`; capability declaration/catalogue tests; `content/definitions/filesystem_posture.yaml`; `docs/{os-capability-matrix.md,user-manual/agent-plugins.md}`; external run `captures/PROVENANCE.md` and seven capture/probe files; Phase-1 sanitizer harness/logs.

## Delta since Phase 1

- Raised the unbraced macOS false-PARTIAL defect LOW → HIGH after accepting Kimi's result-envelope argument.
- Reduced the real-action status-test gap HIGH policy floor → MEDIUM ordinary missing coverage.
- Added Kimi's macOS mixed-empty wording and Meson comment findings at LOW; expanded documentation honesty to uncompiled Linux/Windows claims.
- Rejected Kimi's missing-capture finding; defended the five blockers and Resource Ledger floor it missed.
- Final personal verdict remains BLOCK; main unresolved peer disagreements are decoder record semantics, false-clean quota/truncation/FSCTL severity, and the Ledger floor.
