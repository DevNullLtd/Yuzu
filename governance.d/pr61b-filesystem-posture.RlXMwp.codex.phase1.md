[CDX-P1-01]  HIGH · CONFIDENCE(hi) · PROVENANCE(test-run)
The APFS decoder accepts a record whose declared length does not contain its header
- Location:  agents/plugins/filesystem_posture/src/filesystem_posture_parsers.hpp:530 (+ :538, :546-560)
- Claim:     A malformed record can make bytes inside `attrreference_t`/`attr_length` become a fabricated snapshot name while the parser reports a clean result.
- Evidence:  The parser checks 32 bytes against the outer buffer before reading the header, but its record check is only `record_length == 0 || offset + record_length > buf.size()`; a sanitizer harness supplied `record_length=30`, `attr_dataoffset=4`, and `attr_length=2`, and the parser returned one name containing byte `0x02` with `malformed=false`.
- Scenario:  A malformed `fs_snapshot_list` reply declares a record shorter than the 32-byte header -> the decoder treats header bytes as name data -> the action emits a nonexistent APFS snapshot as a clean inventory row.
- Inference: TRIGGER = a reply with `record_length < 32` and an attribute reference into the header; IMPACT = I3 wrong result presented as correct; EXPOSURE = E0 + E5; EPISTEMIC STATUS = verified.
- Anchor:    judgment
- Precedent: tests/unit/test_filesystem_posture_parsers.cpp:335 bounds an attribute reference against the outer record, but does not cover a target inside the header.
- Mitigations: `safe_output_field` prevents delimiter injection only; it does not reject the fabricated name or mark the result partial.
- Fix:       Reject `record_length < 32` and reject `name_start_in_record < 32` before accepting the name span; add the directed 30-byte-record regression case.
- Falsifier: Apple’s `attrreference_t` contract permits its target to point into the fixed header and defines those header bytes as the attribute payload.

[CDX-P1-02]  HIGH · CONFIDENCE(hi) · PROVENANCE(static-read)
The C++ change has no Resource Ledger
- Location:  243de5bcd3c1c5157980b43c8229421fac6702dc..f30dd3a5a (all seven new plugin C++ files; especially filesystem_posture_macos.cpp:237 and filesystem_posture_win.cpp:153-175, :471-480)
- Claim:     The required ownership proof for the new fd, HANDLE, COM, mutex, and static-buffer boundaries is absent.
- Evidence:  The 24-path range contains no resource-ledger artifact, and none of the 11 commit bodies supplies the required owner/acquire/release/transfer/failure-cleanup table.
- Scenario:  This is a contract gate: the branch adds `open`, two kinds of Windows search/file HANDLE, COM, and a process-static `getmntinfo` buffer without the mandatory review artifact.
- Inference: TRIGGER/IMPACT/EXPOSURE = not applicable to a policy-floor contract violation; EPISTEMIC STATUS = verified by range inventory.
- Anchor:    CLAUDE.md standing rule 2; `.claude/skills/governance/SKILL.md` “Policy floors” and Gate 1 “Resource Ledger”; docs/cpp-conventions.md §Resource ownership and lifetime.
- Precedent: docs/resource-ledgers/wave5-pr51-runner-convergence.md:1.
- Mitigations: The implementation does use RAII (`ScopedFd`, `ScopedFileHandle`, `ScopedVolumeFindHandle`, `ComPtr`), but implementation quality does not waive the ledger floor.
- Fix:       Add the Gate-1 Resource Ledger covering every new resource boundary and all five required ownership fields.
- Falsifier: A complete Gate-1 Resource Ledger for this exact 11-commit range was supplied in the review record but omitted from the local materials I was given.

[CDX-P1-03]  HIGH · CONFIDENCE(hi) · PROVENANCE(test-run)
The advertised end-to-end test is false-green on result-status behavior
- Location:  tests/unit/test_filesystem_posture_local_dispatcher.cpp:230-250 (+ :185-227)
- Claim:     The three real-action tests assert row shape and `rc`, but never action `result_status`, `result_completeness`, or provenance, so they passed while the live snapshots action falsely marked every successful APFS probe partial.
- Evidence:  `./build-macos/tests/yuzu_agent_tests '[filesystem_posture]'` passed 238 assertions/27 cases while logging nine `macos:fs_snapshot_list: ... malformed reply buffer` warnings; the snapshots test checks only `rc`, nonempty rows, field count, discriminator, and kind.
- Scenario:  A status-accounting regression ships -> the closure test remains green -> callers receive incorrect CC-07 status despite the claimed end-to-end coverage.
- Inference: TRIGGER/IMPACT/EXPOSURE = policy-floor false-green test offered as closure evidence; EPISTEMIC STATUS = verified.
- Anchor:    CLAUDE.md standing rule 2 policy floors (“a FALSE-GREEN test offered as closure evidence”).
- Precedent: tests/unit/test_filesystem_posture_local_dispatcher.cpp:171-183 correctly asserts all three status fields for the synthetic callback.
- Mitigations: The emitted WARN exposed the defect during manual log inspection, but Catch2 did not fail and CI would remain green.
- Fix:       Assert expected status/completeness/provenance on every real action and add injectable leg-decision tests for clean, mixed-success, and all-failure paths.
- Falsifier: Re-running the current snapshots action test fails an assertion solely because its CC-07 result status is constrained/partial.

[CDX-P1-04]  HIGH · CONFIDENCE(hi) · PROVENANCE(static-read)
Quota probe failures can be masked by a clean command status on all three OS legs
- Location:  agents/plugins/filesystem_posture/src/filesystem_posture_macos.cpp:190-216; agents/plugins/filesystem_posture/src/filesystem_posture_linux.cpp:164-220; agents/plugins/filesystem_posture/src/filesystem_posture_win.cpp:308-441
- Claim:     Per-volume quota acquisition failures emit `unavailable`/`permission_denied` rows without reliably calling `mark_result_partial`, so `rc=0` derives an effective OK status for incomplete reads.
- Evidence:  macOS classifies every `getattrlist` `rc != 0` and writes the row without a status call; Linux marks only when *all* probed devices are permission-denied and never marks an unknown errno; Windows marks only `any_ntfs && !any_success`, so one disabled/configured NTFS volume suppresses failures on every other volume.
- Scenario:  One volume is readable and another returns EACCES/E_ACCESSDENIED (or an unknown acquisition error) -> both rows are emitted -> the command’s typed status remains undeclared and `derive_effective_result_status(..., 0)` reports OK -> automation treats an incomplete quota read as clean.
- Inference: TRIGGER = a mixed-success quota walk, or macOS/Windows metadata failure before a successful volume; IMPACT = I3 wrong completion result presented as correct; EXPOSURE = E0 + E5; EPISTEMIC STATUS = likely.
- Anchor:    judgment
- Precedent: agents/plugins/filesystem_posture/src/filesystem_posture_win.cpp:527-540 marks snapshots partial on *any* failed/truncated volume, even when other volumes produced tokens.
- Mitigations: Individual output rows retain `unavailable`/`permission_denied`, so a consumer that reparses every row can detect some failures; status-only consumers cannot.
- Fix:       Track `any_failure` independently of `any_success` on every quota leg and call `mark_result_partial` whenever any acquisition failed; keep expected states such as disabled/unsupported non-degraded.
- Falsifier: The command-result contract explicitly defines a result containing one or more failed volume probes as FULL/OK whenever at least one other volume succeeds.

[CDX-P1-05]  HIGH · CONFIDENCE(hi) · PROVENANCE(static-read)
Two Linux actions silently ignore the 4 MiB mountinfo read cap
- Location:  agents/plugins/filesystem_posture/src/filesystem_posture_linux.cpp:141-149, :225-241 (contrast :96-105)
- Claim:     `emit_quotas` and `emit_snapshots` receive `read_truncated=true` but never report it, allowing omitted mounts to be returned with an effective OK status.
- Evidence:  `read_mountinfo_capped` sets `truncated` after probing byte 4 MiB; only `emit_mounts` checks `read_truncated`, while quotas and snapshots pass the clipped text directly to `parse_proc_mountinfo`.
- Scenario:  `/proc/self/mountinfo` exceeds 4 MiB but the retained prefix has fewer than 4096 complete entries and ends at a line boundary -> parser caps do not fire -> later quota/snapshot-capable mounts disappear -> the command reports a clean complete result.
- Inference: TRIGGER = a mountinfo file over 4 MiB whose retained prefix does not trigger malformed-line or 4096-entry guards; IMPACT = I3 wrong incomplete result presented as correct; EXPOSURE = E0 + E5; EPISTEMIC STATUS = likely.
- Anchor:    judgment
- Precedent: agents/plugins/filesystem_posture/src/filesystem_posture_linux.cpp:103-104 correctly marks the mounts action partial on this exact flag.
- Mitigations: `parse.truncated` or a clipped partial final line catches common large-file shapes, but neither proves detection for the stated trigger.
- Fix:       Mirror the `read_truncated` status check in quotas and snapshots before parsing.
- Falsifier: It is impossible for a >4 MiB procfs mountinfo read to return a retained prefix below 4096 entries that ends on a complete line.

[CDX-P1-06]  HIGH · CONFIDENCE(med) · PROVENANCE(static-read)
The Windows snapshot walker ignores all three framing fields
- Location:  agents/plugins/filesystem_posture/src/filesystem_posture_win.cpp:495-520
- Claim:     The code skips the `NumberOfSnapShots`, `NumberOfSnapShotsReturned`, and `SnapShotArraySize` header without validating any of them, so a count/size-inconsistent FSCTL reply can be accepted as a clean inventory.
- Evidence:  After only `returned >= 3*sizeof(ULONG)`, the implementation passes every remaining returned byte to `parse_gmt_multistring`; no header field is read or compared with `returned`, decoded name count, or buffer size.
- Scenario:  A malformed reply says two snapshots were returned but supplies one token followed by a valid terminator -> the multistring parser succeeds with one name -> no `any_failure` bit is set -> the incomplete set is reported clean.
- Inference: TRIGGER = an internally inconsistent `FSCTL_SRV_ENUMERATE_SNAPSHOTS` reply; IMPACT = I3 wrong result presented as correct; EXPOSURE = E0 + E5; EPISTEMIC STATUS = likely (Windows body was not compiled or executed).
- Anchor:    judgment
- Precedent: agents/plugins/filesystem_posture/src/filesystem_posture_macos.cpp:193-199 rejects a successful syscall reply whose declared length does not match its requested structure.
- Mitigations: The inner UTF-16 decoder bounds-checks its payload and catches missing terminators, but it cannot detect disagreement with ignored outer counts/sizes.
- Fix:       Decode the three ULONGs with bounded reads, reject `returned > buf.size()`, validate array size against available bytes, and require decoded count to equal `NumberOfSnapShotsReturned`; add header-level synthetic tests.
- Falsifier: The Windows API contract guarantees these three returned header fields are unobservable or redundant and guarantees a successful reply can never be internally inconsistent, including through filesystem/filter drivers.

[CDX-P1-07]  LOW · CONFIDENCE(hi) · PROVENANCE(compiled)
An unbraced `if` falsely degrades every successful APFS snapshot probe
- Location:  agents/plugins/filesystem_posture/src/filesystem_posture_macos.cpp:269-272
- Claim:     `mark_result_partial` is outside `if (parsed.malformed)`, so every successful APFS parse reports `CONSTRAINED/PARTIAL` with a false malformed-buffer provenance.
- Evidence:  Apple Clang with `-Wmisleading-indentation` identifies line 271 as outside the `if`; the live tagged run logged the false warning for all nine APFS mounts.
- Scenario:  Any ordinary macOS snapshots action reaches a successful APFS parse -> valid rows are emitted -> the result is falsely labelled degraded and logs false acquisition failures.
- Inference: TRIGGER = any APFS mount whose `fs_snapshot_list` succeeds; IMPACT = I8 degraded but data rows remain correct; EXPOSURE = E0; EPISTEMIC STATUS = verified.
- Anchor:    judgment
- Precedent: agents/plugins/filesystem_posture/src/filesystem_posture_macos.cpp:193-199 braces the multi-statement malformed-reply branch correctly.
- Mitigations: Rows still contain the decoded names, and the false status is conservative rather than false-clean.
- Fix:       Brace the `if` so both `any_failure = true` and `mark_result_partial` are conditional; also handle `parsed.truncated` explicitly.

[CDX-P1-08]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read)
The pinned single-output seam has an extra unescaped writer
- Location:  agents/plugins/filesystem_posture/src/filesystem_posture_plugin.cpp:131 (+ filesystem_posture_legs.hpp:14-15, :132-155)
- Claim:     The unknown-action path calls `ctx.write_output` directly and interpolates raw action text, contradicting the stated “ONLY call sites” seam and bypassing `safe_output_field`.
- Evidence:  `rg 'ctx\.write_output' agents/plugins/filesystem_posture` returns the three wrappers plus plugin.cpp:131; an action containing CR/LF or `|` is copied verbatim.
- Scenario:  A caller reaches the plugin with an undeclared action containing row delimiters -> captured error output can contain forged row framing.
- Inference: TRIGGER = direct/local invocation with a hostile unknown action; IMPACT = I3 at that local seam; EXPOSURE = E6 because production server classification refuses undeclared `plugin.action`; EPISTEMIC STATUS = verified, capped LOW.
- Anchor:    judgment
- Precedent: agents/plugins/rdp_control/src/rdp_control_plugin.cpp:321 sanitizes an unknown action before output.
- Mitigations: server/core/src/agent_registry.hpp:198-203 rejects unclassified actions before production dispatch, and the plugin returns nonzero.
- Fix:       Emit no text for the unreachable unknown action, or route a `safe_output_field(action)` error through a sole writer declared in `legs.hpp` and correct the seam contract.

[CDX-P1-09]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read)
Bundled operator documentation still contradicts the implemented mechanisms and macOS quota result
- Location:  content/definitions/filesystem_posture.yaml:7-8, :29-30, :115-117; docs/user-manual/agent-plugins.md:589-590; server/core/src/capability_decls/plugin_action_catalogue_filesystem_posture.hpp:22-23
- Claim:     The docs say Windows capacity comes from `GetVolumeInformationW`, name a nonexistent `DISKQUOTA_USER_INFORMATION` control-object path, and say macOS reports `state=unsupported`, while the code uses `GetDiskFreeSpaceExW`, calls only `IDiskQuotaControl` getters, and emits configured/none from `getattrlist` on APFS.
- Evidence:  filesystem_posture_win.cpp:206-216 obtains capacity with `GetDiskFreeSpaceExW`; :353-435 never declares or uses `DISKQUOTA_USER_INFORMATION`; filesystem_posture_macos.cpp:183-215 probes APFS/HFS and emits classifier results including `Configured` and `None`.
- Scenario:  An operator reads the shipped definition/manual -> assumes APFS volume quotas are never reported or audits the wrong Windows API surface -> interprets valid rows and endpoint controls incorrectly.
- Inference: TRIGGER = reliance on bundled descriptions; IMPACT = I8 degraded but diagnosable documentation accuracy (no damaging named action); EXPOSURE = E3; EPISTEMIC STATUS = verified.
- Anchor:    CLAUDE.md standing rule 3 establishes domain truth ownership; severity is otherwise judgment.
- Precedent: docs/os-capability-matrix.md:337-345 accurately names `GetDiskFreeSpaceExW`, `IDiskQuotaControl`, and macOS `getattrlist` volume quotas.
- Mitigations: The generated capability matrix and descriptor fallback prose are correct, and runtime row states remain truthful.
- Fix:       Replace the stale mechanism names and describe macOS as volume-level configured/none/unsupported-by-filesystem; remove the snapshot-lineage caveat from the mounts action.

VERDICT:  BLOCK — two malformed-reply paths can return clean fabricated/incomplete inventories, three failure-accounting paths can return clean incomplete results, and two explicit policy floors are violated.
COVERAGE: deep on binary-decoder bounds/semantics, failure-versus-success/empty accounting, all Windows HRESULT/HANDLE/COM paths, POSIX fd/static-buffer lifetime and concurrency, escaping/pinned row schema, descriptors/capability classification, fixture provenance, build registration, documentation, and test honesty; Linux and Windows runtime behavior was necessarily static-only because no usable Linux host, Windows SDK/compiler, or live Windows host was available.
RAN:      `meson compile -C build-macos filesystem_posture` -> 0, current/no work; Apple Clang `-fsyntax-only -Wmisleading-indentation` on macOS TU -> compiled with the line-271 warning; `[filesystem_posture]` -> 27/27 cases, 238/238 assertions, with nine false malformed-buffer WARNs; ASan+UBSan directed decoder case plus 1,000,000 random inputs -> no memory violation/nontermination and directed short-record fabrication reproduced; `check-plugin-spawn-lexical.sh` -> clean; `test_capability_gate_consistency.py` -> 9/9; capability-matrix gate -> expected exit 1 with only the two documented host-dependent wifi rows differing and all nine filesystem_posture rows equal; fixture byte comparison -> both mountinfo captures and APFS hex MATCH, errno labels match PROVENANCE; full `meson test` rebuilt successfully after redirecting `CCACHE_TEMPDIR` but sandbox networking caused unrelated bind failures/cancelled gateway tests (34 OK, 6 failed including one manually interrupted after 270s, 2 skipped), so it does not contradict the supplied unsandboxed 40/0/2 result. Linux and Windows legs were not compiled. CI status was not queried because the target is LOCAL ONLY/unpushed.
FILES:    agents/plugins/filesystem_posture/{meson.build,src/filesystem_posture_legs.hpp,src/filesystem_posture_linux.cpp,src/filesystem_posture_macos.cpp,src/filesystem_posture_parsers.hpp,src/filesystem_posture_plugin.cpp,src/filesystem_posture_win.cpp}; changelog.d/wave6-pr61b-filesystem-posture.added.md; content/definitions/filesystem_posture.yaml; deploy/packaging/windows/yuzu-agent.iss; docs/{os-capability-matrix.md,user-manual/agent-plugins.md,cpp-conventions.md}; meson.build; server/core/src/{server.cpp,capability_decls/plugin_action_catalogue_filesystem_posture.hpp,agent_registry.hpp,authz_model.hpp}; sdk/include/yuzu/{plugin.h,string_utils.hpp}; tests/{meson.build,test_capability_catalogue_complete.py,test_capability_gate_consistency.py,unit/server/test_capability_catalogue.cpp,unit/server/test_dispatch_destructive_gate.cpp,unit/server/test_real_capability_registry.hpp,unit/test_filesystem_posture_local_dispatcher.cpp,unit/test_filesystem_posture_parsers.cpp,unit/test_new_plugins.cpp}; agents/{core/src/agent.cpp,shared/win_com.hpp}; CLAUDE.md; .claude/{routed-concerns.md,routed-concerns-access-control.md,skills/governance/SKILL.md}; scratchpad capture PROVENANCE plus six capture/probe files. No peer-review file was read.
