# kimi — Phase 1 independent review — PR6.1-b filesystem_posture

Range reviewed: `243de5bc..f30dd3a5` (11 commits, 24 files, +3362/-37). Working tree at HEAD.

## Findings

```
[K1]  HIGH · CONFIDENCE(hi) · PROVENANCE(test-run + compiled)
macOS snapshots leg: missing braces — mark_result_partial fires unconditionally on
every successfully-probed APFS mount, so every macOS `snapshots` run reports
CONSTRAINED/PARTIAL with a fabricated "malformed reply buffer" provenance
- Location:  agents/plugins/filesystem_posture/src/filesystem_posture_macos.cpp:269-272
- Claim:     `if (parsed.malformed) any_failure = true; mark_result_partial(...)` — the
             mark_result_partial call is NOT guarded by the if, so a clean, fully-parsed
             enumeration is reported to the server as a degraded partial result.
- Evidence:  the three lines as written:
               if (parsed.malformed)
                   any_failure = true;
                   mark_result_partial(ctx, "macos:fs_snapshot_list",
                                       std::string(s.f_mntonname) + ": malformed reply buffer");
             Live test log of `./build-macos/tests/yuzu_agent_tests '[filesystem_posture]'`:
             9x "degraded read (macos:fs_snapshot_list): <mount>: malformed reply buffer" —
             one per APFS mount on this host, during a PASSING run.
             Independent probe compiled against the shipped parser header + a live
             fs_snapshot_list("/", ...) on this host: rc=3, names=3, malformed=0 — the
             kernel reply parses clean; the warnings are purely the brace bug.
             `c++ -Wall -fsyntax-only` (same include flags as the real build) emits
             -Wmisleading-indentation pointing at exactly line 271; the project's real
             compile line carries -Wall -Wextra -Wpedantic (ninja -t commands), so the
             warning fired in every local build of this branch, unheeded (no -Werror).
- Scenario:  any operator/scheduled instruction runs `filesystem_posture.snapshots`
             against a macOS fleet -> every host returns result_status=CONSTRAINED,
             completeness=PARTIAL, provenance "macos:fs_snapshot_list" plus a WARN log
             line claiming a malformed kernel reply that never happened -> PARTIAL
             becomes background noise fleet-wide, so when a REAL acquisition failure
             occurs (the exact condition this PR's failure-vs-empty contract exists to
             surface), it is indistinguishable from the false alarm.
- Inference: severity rests on the result envelope being operator-visible truth, which
             is the design's own premise (legs.hpp:157-166, BR-001 comments). Rows
             themselves are correct; only status/completeness/provenance/logs are wrong.
- Anchor:    CLAUDE.md standing rule 2 severity table — I3 (wrong result presented as
             correct: the typed status asserts a degradation that did not occur) base
             HIGH; alternatively I4 (harmful operator guidance — trains the fleet to
             ignore PARTIAL) caps HIGH. Exposure E3 (authenticated, default config) —
             no change. Band HIGH. Epistemic: verified (reproduced live).
- Precedent: the guarded form exists two branches up in the same function
             (filesystem_posture_macos.cpp:256-261: `if (rc < 0) { any_failure = true;
             mark_result_partial(...); continue; }`).
- Mitigations: none. The LocalDispatcher shape tests never assert result_status for the
             real actions (see K2), so the suite is green while this fires; no other
             layer recomputes status. This is the only guard.
- Fix:       add the braces: `if (parsed.malformed) { any_failure = true;
             mark_result_partial(...); }`.
- Falsifier: a macOS `snapshots` run over clean-parsing APFS mounts yielding
             result_status != CONSTRAINED (i.e. status stays COMPLETED) — currently
             disproven by the live test-run log above.
```

```
[K2]  MEDIUM · CONFIDENCE(hi) · PROVENANCE(test-run)
Test-adequacy gap: the LocalDispatcher round-trip tests assert rc and row shape only —
never result_status/completeness — so the false-PARTIAL defect (K1) ships green
- Location:  tests/unit/test_filesystem_posture_local_dispatcher.cpp:185-251 (all three
             [posix_actions] cases); contrast the status assertions at :171-183 which use
             a FAKE descriptor, not the real plugin.
- Claim:     no test would fail if a real leg degraded the result status on the happy
             path; the "27 cases / 238 assertions pass" closure claim coexists with 9
             spurious degraded-read warnings in that very run's log.
- Evidence:  snapshots shape test (:238-251) checks `result.rc == 0` and row field
             counts/tokens only; the passing run's own log shows 9 "malformed reply
             buffer" WARNs.
- Scenario:  any future regression of the degradation contract on a POSIX leg (false
             PARTIAL, or a real failure failing to mark PARTIAL) is invisible to CI.
- Inference: MEDIUM not HIGH because the defect it permitted is itself graded in K1;
             this is the missing net, not the hole.
- Anchor:    judgment (test-adequacy axis). CLAUDE.md policy-floor "FALSE-GREEN test
             offered as closure evidence" was considered and NOT invoked: the tests are
             genuinely green for what they assert; they are incomplete, not false.
- Precedent: the same file demonstrates the seam assertion pattern at :171-183 — it
             just never applies it to the real plugin's actions.
- Mitigations: none, this is the only end-to-end exercise of the POSIX legs.
- Fix:       in the three [posix_actions] cases, CHECK(result.result_status ==
             YUZU_RESULT_STATUS_COMPLETED) (or the appropriate non-degraded constant) on
             hosts where no degradation is expected; K1 makes the snapshots one fail
             until fixed — which is the point.
```

```
[K3]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read)
legs.hpp's "ONLY call sites of ctx.write_output in this plugin" claim is false —
filesystem_posture_plugin.cpp:131 writes directly, with the raw action string unescaped
- Location:  agents/plugins/filesystem_posture/src/filesystem_posture_legs.hpp:14-15,132
             (the claim) vs agents/plugins/filesystem_posture/src/filesystem_posture_plugin.cpp:131
- Claim:     the pinned-seam documentation reviewers are told to trust (target area d)
             is contradicted by the plugin TU itself.
- Evidence:  legs.hpp: "It DEFINES ... the ctx::write_output wrapper functions (the ONLY
             call sites of ctx.write_output in this plugin)"; plugin.cpp:131:
             `ctx.write_output(std::string{"unknown action: "} + std::string{action});`
- Scenario:  a dispatch-layer bug or direct plugin invocation with an action outside the
             declared set echoes unescaped text (a '|' in it would break row grammar on
             that line). Unreachable via the capability-gated dispatch path.
- Inference: LOW via exposure (capability gate only routes declared actions → E6-shaped
             cap); the lasting harm is reviewer trust in the seam claim.
- Anchor:    CLAUDE.md standing rule 3 — a comment contradicting the code is a truth
             finding at native severity; native severity here is LOW.
- Precedent: every sibling plugin does the same bare unknown-action write
             (agent_actions_plugin.cpp:76, antivirus_plugin.cpp:565, ...) — an
             established (anti-)pattern, so only the doc claim is new and wrong.
- Mitigations: capability catalogue gates dispatch to declared actions.
- Fix:       either route the unknown-action write through a legs.hpp wrapper and keep
             the claim, or amend the claim to "the only ROW-EMITTING call sites".
```

```
[K4]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read)
macOS quotas leg never degrades result status on a getattrlist failure — cross-leg
inconsistency with Linux, which escalates all-probes-denied to PARTIAL
- Location:  agents/plugins/filesystem_posture/src/filesystem_posture_macos.cpp:190-216
             vs filesystem_posture_linux.cpp:217-220
- Claim:     a getattrlist(2) failure (EPERM/EIO/...) on an apfs/hfs mount yields a
             permission_denied/unavailable ROW but the action's status stays COMPLETE;
             on Linux the equivalent all-denied condition calls mark_result_partial.
- Evidence:  macos emit_quotas has no mark_result_partial on the rc != 0 path (only the
             reply-length-mismatch path at :193-200); linux:219-220:
             `if (any_dev_probed && all_dev_permission_denied) mark_result_partial(...)`.
- Scenario:  a fleet-wide permission regression on macOS quota probes reads as a
             COMPLETE result with all-unavailable rows; the same condition on Linux
             reads PARTIAL. Server-side alerting on completeness behaves differently per
             OS for the same fault.
- Inference: the per-row state token carries the truth, so nothing is presented as
             healthy that isn't — the inconsistency is in the summary signal only.
- Anchor:    judgment. I8 (degraded but correct) -> LOW.
- Precedent: linux leg's all-denied escalation (filesystem_posture_linux.cpp:219).
- Mitigations: the per-row `state` column still records permission_denied/unavailable.
- Fix:       mirror Linux: track rc != 0 across probed mounts and mark_result_partial
             when every probe failed.
```

```
[K5]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read)
macOS snapshots fallback detail overstates: "enumeration failed on every volume" also
fires when some volumes enumerated cleanly but simply had zero snapshots
- Location:  agents/plugins/filesystem_posture/src/filesystem_posture_macos.cpp:283-289
- Claim:     `!any_row && any_failure` is true in the mixed case (volume A open()/FSCTL
             failed, volume B succeeded with an empty snapshot set); the emitted detail
             then claims failure "on every volume", which is false for B.
- Evidence:  any_failure is set per-failure (:239-242, :256-261) while any_row requires
             a parsed name; a successful-but-empty enumeration sets neither.
- Scenario:  operator reads "failed on every volume" and chases a fleet-wide APFS fault
             that affected one volume of nine.
- Inference: corner case (needs ≥1 failure AND zero snapshots on every healthy volume),
             wrong-words-not-wrong-status; status is legitimately PARTIAL here anyway.
- Anchor:    judgment. I8 -> LOW.
- Precedent: Windows leg distinguishes cleanly via first_failure_err
             (filesystem_posture_win.cpp:527-531) but never claims "every volume".
- Mitigations: result status is PARTIAL regardless; only the prose is wrong.
- Fix:       "...failed on at least one volume; no snapshots were enumerated" or count
             failures and print "N of M volumes".
```

```
[K6]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read)
tests/meson.build edit clobbered the test_license_scan_actions.cpp comment — the
"Wave 4 PR4.3b: real license_scan.dylib..." text now dangles off the
filesystem_posture_local_dispatcher line, misattributing it
- Location:  tests/meson.build:440-448
- Evidence:  line 440 lost its trailing comment; line 446 ends with
             `# ... #ifndef _WIN32 guard)     # Wave 4 PR4.3b: real license_scan.dylib/.so driven`
             and lines 447-448 (the license_scan continuation) follow the
             filesystem_posture entry.
- Claim:     comment now describes the wrong test file; a reader trusts the attribution.
- Anchor:    CLAUDE.md standing rule 3 (comment contradicts code) — trivial native
             severity. judgment-LOW.
- Fix:       move the three license_scan comment lines back onto line 440's entry.
```

```
[K7]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read)
Doc wording: "FindFirstVolumeW/GetVolumeInformationW/GetVolumeInformationW" duplicated
API name (second should be GetDiskFreeSpaceExW) in two places
- Location:  docs/user-manual/agent-plugins.md (filesystem_posture `mounts` row);
             content/definitions/filesystem_posture.yaml:7 (header comment)
- Evidence:  both read "...GetVolumeInformationW/GetVolumeInformationW (mounts)"; the
             implementation's mounts leg uses GetDiskFreeSpaceExW for capacity
             (filesystem_posture_win.cpp:209) and the descriptor prose names it
             correctly (filesystem_posture_plugin.cpp:48).
- Anchor:    judgment (docs truth); I8/I9 -> LOW.
- Fix:       s/GetVolumeInformationW\/GetVolumeInformationW/GetVolumeInformationW\/GetDiskFreeSpaceExW/
             in both files.
```

```
[K8]  LOW · CONFIDENCE(med) · PROVENANCE(static-read)
os-capability-matrix summary row marks Linux ✅ while the Linux leg has never been
compiled anywhere; Windows (same never-compiled state this session) is honestly 🟡
with disclaimers — asymmetric verification claims
- Location:  docs/os-capability-matrix.md:108 (| filesystem_posture | 🟡 | ✅ | ✅ |,
             column order Windows|Linux|macOS per :44's table convention)
- Claim:     the table's own definition of ✅/"Full" is "the plugin builds and its core
             actions work on that OS" (:92); the Linux leg was never compiled this
             session (target's own empirical state), so ✅ asserts an unverified fact
             while Windows' identical verification state earns 🟡 + disclaimer prose.
- Evidence:  no Linux build exists in the diff's provenance; the generated per-action
             rows for Linux (verified identical to capmatrix-gen output, see RAN) carry
             no compile-verified caveat either.
- Inference: likely correct in the end (POSIX-standard code, Tier-2 CI compiles+tests
             it), but the branch is LOCAL ONLY — no CI leg has run, so no machine has
             checked the claim yet. Mitigation exists only after push.
- Anchor:    judgment (docs truth, rule 3 at native severity). I8 -> LOW.
- Mitigations: Tier-2 CI Linux leg compiles and runs [filesystem_posture] on push;
             would turn a false claim into a failed gate before merge.
- Fix:       mark Linux 🟡 with a "compile-verified pending first Linux CI leg" note, or
             bump to ✅ only after a Linux build+test run exists.
```

```
[K9]  INFO · CONFIDENCE(hi) · PROVENANCE(static-read)
Fixture provenance referenced but not committed: capture files live in
scratchpad/devteam-wave6-1b-fsposture/captures/ which is absent from the repo
- Location:  tests/unit/test_filesystem_posture_parsers.cpp:7 ("see
             captures/PROVENANCE.md"), filesystem_posture_parsers.hpp:325,505
- Evidence:  `find . -name PROVENANCE.md` and the scratchpad path return nothing in the
             tree; no capture files in the diff (`git diff --name-only ... | grep -i
             capture` empty).
- Claim:     the essential provenance (host/command/date/kind) IS inlined per fixture
             and the synthetic Windows round-trips are honestly labelled synthetic
             (verified, :400-444), so this is audit-trail hygiene, not dishonesty.
- Anchor:    judgment. INFO.
- Fix:       optional: commit the captures + PROVENANCE.md under tests/fixtures/, or
             drop the dangling pointer and keep the inline labels.
```

## Areas explicitly checked with NO finding

- (a) Binary decoder `parse_fs_snapshot_list_buffer`: every derived offset
  (record_length, attr_dataoffset, attr_length) is bounds-checked in 64-bit arithmetic
  before dereference; record_length==0 and attr_dataoffset<0 rejected; the NUL-final-byte
  check at :560 cannot exceed buf.size() because name_end ≤ record_length and
  offset+record_length ≤ buf.size() were proven earlier; offset strictly increases so no
  infinite loop. The 4GB-wrap construction is unreachable because offset+record_length
  must first fit the ≤1MB buffer. Tests cover truncation, wild dataoffset, zero
  attr_length, non-NUL final byte. My own probe against a live reply parses clean.
  `parse_gmt_multistring`: every 2-byte read bounds-checked; max_names cap has the
  exactly-full-then-terminator carve-out (tested). Clean.
- (d) Seam: formatters emit no trailing newline (tested, :459/:486/:502); nullopt → '-'
  (tested); flags/kind/state vocabularies are all fixed-literal at every call site
  (grepped all write_*_row sites); no leg calls ctx.write_output directly (only
  plugin.cpp:131 — K3). agent.cpp citations in legs.hpp verified true
  (append_output separator :305-313; set_result_status last-writer-wins :548-556).
- (e) Escaping: every untrusted text field (mount_point, device, fstype, options, name,
  detail) passes through yuzu::util::safe_output_field at the formatter; no leg
  hand-rolls escaping. Grepped all three legs.
- (g) Capability declaration: three rows ReadOnly/None/Inventory/Read/Low/None match the
  implementation (no write handle, no mutating ioctl/FSCTL, Initialize(FALSE) read-only
  COM). static_assert on execute_gate present. test_capability_gate_consistency (187
  rows) and catalogue-completeness gates pass.
- (h) Fixture honesty: real captures labelled with host/command/date; synthetic Windows
  round-trips labelled synthetic in both test names and comments. Only the missing
  committed provenance dir (K9).
- Windows leg static review (f): RAII for all three handle kinds (ScopedFileHandle,
  ScopedVolumeFindHandle, ComPtr/ComInit from win_com.hpp — APIs verified against
  agents/shared/win_com.hpp:33-84); include dir `../../shared` matches bitlocker/
  network_config precedent; win_str.hpp `yuzu::win::from_wide` signature matches all
  call sites; volume GUID trailing-backslash handling correct per API (kept for
  GetVolumeInformationW/GetDiskFreeSpaceExW, stripped for CreateFileW); read-only rights
  only (FILE_READ_ATTRIBUTES|FILE_READ_DATA|SYNCHRONIZE; Initialize FALSE); every
  HRESULT checked; failure-vs-empty contract honoured (first_failure_err, distinct
  "none"-row details); DRIVE_UNKNOWN degrades flags rather than fabricating ro/rw.
  Not compiled — no Windows toolchain here; body is preprocessed away on this host.
  Residual compile risk (MSVC-only surfaces: dskquota.h, FSCTL struct) is declared in
  the leg's own header and descriptor prose. Known limitation, honestly labelled: 64KB
  FSCTL buffer with no ERROR_INSUFFICIENT_BUFFER retry degrades honestly to a failure
  row, so no finding.
- Linux leg static review: quotactl errno save/classify correct (errno=0 before call,
  saved only on rc!=0); statvfs failure marks partial per mount; mountinfo read capped
  at 4MiB with truncation probe; network-fstype statvfs skip as documented. Not compiled
  — no Linux host; K8 records the doc asymmetry that results.
- ScopedFd use in the macOS leg is a plain open-and-hold; no reset() same-identity
  pattern — the routed-concerns CATASTROPHIC row is not engaged.
- Changelog floor: fragment changelog.d/wave6-pr61b-filesystem-posture.added.md present;
  `python3 scripts/assemble-changelog.py --check` passes (424 fragments); no direct
  CHANGELOG.md edit.
- Capability-matrix gate diff: verified to be exactly the two host-dependent wifi rows
  (YUZU_HAVE_LIBSYSTEMD); all nine filesystem_posture rows identical between committed
  and generated. Not a defect.
- Installer: yuzu-agent.iss row added with the same shape as siblings; macOS/Linux
  packaging needs no row (plugins install via meson `install: true`, consistent with
  siblings — no other packaging manifest lists plugins).

VERDICT:  BLOCK — K1 is a verified, reproducible-on-every-run wrong result envelope
(false CONSTRAINED/PARTIAL + fabricated "malformed reply buffer" provenance on every
macOS snapshots call), derived HIGH under I3/I4 with E3 and no mitigating layer.

COVERAGE: deep — memory safety of both binary decoders (analysis + live probe + the
shipped negative tests), failure-vs-success and failure-vs-empty contracts on all three
legs, seam/escaping/vocabulary pinning, capability declaration vs implementation, test
adequacy (found K2 by reading the passing run's own log), docs/packaging/changelog/
matrix-gate consistency, concurrency (getmntinfo mutex, thread-scoped error mode).
Skimmed — Windows/Linux legs are static-read only (no toolchain/host exists here; I
said so rather than claiming verification); server-side dispatch wiring beyond the
catalogue gates; the wifi matrix rows (out of scope by design, verified host-dependent).

RAN:
- `./build-macos/tests/yuzu_agent_tests '[filesystem_posture]'` → All tests passed
  (238 assertions / 27 cases); log contains 9 spurious "malformed reply buffer"
  degraded-read warnings — the K1 smoking gun.
- Custom probe (c++ -std=c++23 against the shipped parsers header + live
  fs_snapshot_list("/")) → rc=3, names=3, malformed=0: real replies parse clean.
- `c++ -std=c++23 -Wall -fsyntax-only` on filesystem_posture_macos.cpp with the real
  build's include flags → 1 warning: -Wmisleading-indentation at :271 (K1, machine-
  detectable in every local build; no -Werror so it did not break the build).
- `bash scripts/ci/check-capability-matrix.sh build-macos` → fails by design on the two
  wifi rows only; filesystem_posture rows match generated output.
- `bash scripts/ci/check-plugin-spawn-lexical.sh` → clean.
- `python3 tests/test_capability_gate_consistency.py` → 9 tests OK.
- `python3 tests/test_capability_catalogue_complete.py` → 6 tests OK.
- `python3 scripts/assemble-changelog.py --check` → OK (424 fragments).
- CI status on PR head: none — branch is LOCAL ONLY, never pushed; no CI has run.

FILES: agents/plugins/filesystem_posture/{meson.build, src/filesystem_posture_legs.hpp,
src/filesystem_posture_parsers.hpp, src/filesystem_posture_plugin.cpp,
src/filesystem_posture_linux.cpp, src/filesystem_posture_macos.cpp,
src/filesystem_posture_win.cpp}; server/core/src/capability_decls/
plugin_action_catalogue_filesystem_posture.hpp; server/core/src/server.cpp (diff);
content/definitions/filesystem_posture.yaml; tests/unit/test_filesystem_posture_parsers.cpp;
tests/unit/test_filesystem_posture_local_dispatcher.cpp; tests/meson.build;
tests/test_capability_gate_consistency.py, tests/test_capability_catalogue_complete.py,
tests/unit/server/{test_capability_catalogue.cpp, test_dispatch_destructive_gate.cpp,
test_real_capability_registry.hpp} (diffs); docs/os-capability-matrix.md;
docs/user-manual/agent-plugins.md; deploy/packaging/windows/yuzu-agent.iss;
changelog.d/wave6-pr61b-filesystem-posture.added.md; agents/shared/win_com.hpp,
agents/shared/win_str.hpp, sdk/include/yuzu/string_utils.hpp,
agents/core/include/yuzu/agent/scoped_fd.hpp (anchor cross-checks);
agents/core/src/agent.cpp:300-316,548-556 (seam doc claims).
