# kimi — Phase 2 cross-examination — PR6.1-b filesystem_posture

Peer file read: `codex.phase1.md` only. (`codex.phase2.md` exists in the shared dir but the
protocol scopes this phase to the peer's Phase-1 review; I did not open it.)

## 1. Cross-examination of codex's findings

| PEER-ID | label | evidence I checked | my severity |
|---|---|---|---|
| CDX-P1-01 | confirmed-independently | Built my own ASan+UBSan probe against the shipped header: `record_length=30, attr_dataoffset=4, attr_length=2` → `names=1 malformed=0`, name = byte `0x02` (the attr_length field's own bytes). parsers.hpp:538 checks only `record_length == 0 || offset + record_length > buf.size()` — no `record_length >= 32` / `name_start_in_record >= 32` check. No OOB (memory-safe); the defect is semantic: a fabricated name with a clean envelope. My Phase-1 clearance of this decoder covered memory safety only — this is a real miss on my part. | HIGH |
| CDX-P1-02 | confirmed-independently (with process caveat) | `git diff --name-only` over the range: 24 paths, no ledger artifact; `docs/resource-ledgers/` holds only 3 files, none wave6; all 11 commit bodies: 0 mentions of "resource ledger"; no ledger in the review dir. Floor text verified: `.claude/skills/governance/SKILL.md:293` and :456-460. Caveat: the ledger is a Gate-1 artifact of a `/governance` run, which this LOCAL-ONLY branch has not yet had; the floor is satisfied by producing it at Gate 1 — blocking-but-routine, not a code defect. | HIGH (policy floor) |
| CDX-P1-03 | agrees-with-mine (K2) — concede severity | Same test gap I filed as K2/MEDIUM. Re-adjudicated: the brief offers "27 cases / 238 assertions pass" as closure evidence while the real snapshots action — exercised end-to-end by that very suite — fabricated a degradation 9 times in the run log. A test that cannot fail on the contract in question, offered as closure for that contract, is false-green in the floor's sense (SKILL.md:297 area / CLAUDE.md floor list). My Phase-1 "incomplete ≠ false" reading was too narrow. | HIGH (severity-changed; confidence med — it's a floor-applicability judgment) |
| CDX-P1-04 | agrees-with-mine (K4) — extended and upgraded | Verified all three legs. macOS (macos.cpp:190-216): `rc != 0` writes an unavailable/permission_denied row with NO mark_result_partial — even an ALL-probes-fail fleet-wide quota outage reads COMPLETE (worse than my K4 graded). Linux (linux.cpp:167-169, 219-220): unknown errno → `QuotaState::Unavailable` (parsers.hpp:347) which clears `all_dev_permission_denied`, so all-fail-with-EIO also reads COMPLETE; mixed success likewise. Windows (win.cpp:439-441): `any_ntfs && !any_success` — one configured/disabled NTFS volume masks E_ACCESSDENIED on every other volume. This is exactly the brief's target question (b): yes, one succeeding volume masks failing ones, on all three legs. My K4 LOW was under-graded. | HIGH (severity-changed from LOW) |
| CDX-P1-05 | confirmed-independently | linux.cpp:143-147 (emit_quotas) and :227-241 (emit_snapshots) receive `read_truncated` and never test it; only emit_mounts does (:103-104). The 4096-entry `parse.truncated` guard (:214-215, :273-274) catches most >4MiB shapes (4MiB / ~150B per line ≈ 27k lines), so the live trigger needs a retained prefix <4096 entries ending on a line boundary — i.e. >1KiB average line length. Contrived but nameable, and the guard asymmetry is real. | HIGH (confidence med — trigger is environmental; derivation I3 + E5 = HIGH) |
| CDX-P1-06 | confirmed-independently | win.cpp:495-520: after `returned >= 3*sizeof(ULONG)` the three header ULONGs (NumberOfSnapShots, NumberOfSnapShotsReturned, SnapShotArraySize) are never read; all remaining bytes go to parse_gmt_multistring. No count/size cross-validation. No OOB (`returned` ≤ 64KB buffer by DeviceIoControl contract; inner parser bounds-checks) — semantic gap, same class as CDX-P1-01. Not compiled (no Windows toolchain); static-read only, hence confidence med. | HIGH (confidence med) |
| CDX-P1-07 | agrees-with-mine (K1) — DISAGREES on severity | Same defect (macos.cpp:269-272 unbraced if). Codex grades I8/LOW ("degraded but correct", conservative direction). Rebuttal in §3 below. | HIGH — defended |
| CDX-P1-08 | agrees-with-mine (K3) | Same defect, same grade. | LOW |
| CDX-P1-09 | agrees-with-mine (K7) — extended scope | Verified: yaml:7-8 duplicates `GetVolumeInformationW` AND names `DISKQUOTA_USER_INFORMATION` — grep confirms that struct appears nowhere in win.cpp (only GetQuotaState/GetDefaultQuotaLimit/GetDefaultQuotaThreshold); yaml:29-30 says capacity via GetVolumeInformationW but code uses GetDiskFreeSpaceExW (win.cpp:209); yaml:115-117 and user-manual:590 claim macOS reports `state=unsupported` while macos.cpp:173-216 probes apfs/hfs via getattrlist and can emit Configured/None. Broader than my K7 (which caught only the duplicated API name). | LOW |

## 2. Coverage adoption

Axes codex went deeper on than me:

- **Decoder semantic validation (beyond memory safety)** — I cleared both decoders on bounds/termination only. CDX-P1-01 and CDX-P1-06 are real semantic gaps; ADOPTED (verified independently).
- **Resource Ledger floor** — I never checked for the artifact. ADOPTED with the Gate-1-timing caveat above.
- **Failure-accounting breadth** — my K4 covered macOS quotas only; codex's three-leg analysis (incl. the Linux unknown-errno hole and the Windows `any_success` mask) is verified and ADOPTED; K4 upgraded.
- **mountinfo read-cap propagation** — I checked the 4MiB cap only where it was used (mounts). ADOPTED (CDX-P1-05).
- **Doc-truth sweep** — codex's CDX-P1-09 subsumes my K7; adopted as merged, LOW.

No codex axis rebutted. One codex claim I downgrade only in confidence, not substance: CDX-P1-05's trigger requires >1KiB-average mountinfo lines; the guard asymmetry is real but the reachable-without-it window is narrow (noted, severity kept HIGH per the shared derivation since E5 is "no change").

## 3. Defense of my findings under attack

**K1 vs CDX-P1-07 (severity dispute: my HIGH vs codex LOW).** Re-verified: the unbraced `if` at
macos.cpp:269-272 fires `mark_result_partial` on EVERY clean APFS parse — reproduced live in my
Phase 1 (9 spurious "malformed reply buffer" warnings in a passing run; independent probe showed
the kernel reply parses clean). Codex grades I8 "degraded but correct". That impact code requires
the result to be *correct*; here the typed envelope asserts a false fact — a degradation that did
not occur, with a fabricated provenance string attributing a malformed reply to the kernel. That is
I3 (wrong result presented as correct) on the status axis, and I4 (harmful operator guidance:
fleet-wide false PARTIAL trains operators to ignore the exact degradation signal this PR's
failure-vs-empty contract exists to surface, so a REAL future acquisition failure is
indistinguishable from background noise) — I4 caps HIGH; exposure E3, no change. Codex's
"conservative direction" observation is true but speaks to exploit likelihood, which the derivation
routes through exposure — and no exposure value downgrades here. **K1 defended at HIGH, confidence hi.**

**K2 vs CDX-P1-03** — codex's floor invocation convinced me; upgraded MEDIUM → HIGH (see table).

**K4 vs CDX-P1-04** — codex's wider read verified; upgraded LOW → HIGH (see table).

**K3, K5, K6, K8, K9** — untouched by the peer; re-verified in place, unchanged.

## 4. Revised full finding list

```
[K1]  HIGH · CONFIDENCE(hi) · PROVENANCE(test-run + compiled)  [unchanged]
macOS snapshots leg: unbraced if — mark_result_partial fires on every clean APFS parse;
every macOS snapshots run reports false CONSTRAINED/PARTIAL with fabricated "malformed
reply buffer" provenance
- Location:  agents/plugins/filesystem_posture/src/filesystem_posture_macos.cpp:269-272
- Claim/Evidence/Scenario: as Phase 1; live-run log (9 spurious warnings) + independent
  probe (rc=3, names=3, malformed=0) + -Wmisleading-indentation at :271.
- Anchor:    CLAUDE.md rule 2 derivation — I3 (wrong envelope presented as truth) / I4
             (harmful operator guidance, caps HIGH); E3 no change. Defended against
             CDX-P1-07's I8/LOW in §3.
- Fix:       brace the if: `if (parsed.malformed) { any_failure = true;
             mark_result_partial(...); }`
- Falsifier: a macOS snapshots run over clean-parsing APFS mounts yielding status
             COMPLETED — disproven by the live run.
```

```
[K2]  HIGH · CONFIDENCE(med) · PROVENANCE(test-run)  [severity-changed: MEDIUM→HIGH]
LocalDispatcher real-action tests never assert result_status/completeness — the suite
was offered as closure evidence while K1 fired 9 times inside the passing run
- Location:  tests/unit/test_filesystem_posture_local_dispatcher.cpp:185-251 (real-action
             cases assert rc + row shape only; the status assertions at :171-183 use a
             FAKE descriptor)
- Claim:     false-green offered as closure evidence: the green run cannot fail on the
             degradation contract it was cited as proving.
- Anchor:    CLAUDE.md standing rule 2 policy floor — "a FALSE-GREEN test offered as
             closure evidence" (conceded from codex CDX-P1-03; my Phase-1 "incomplete ≠
             false" reading withdrawn).
- Fix:       CHECK result_status/completeness on the three real-action cases; K1 makes the
             snapshots one fail until fixed — which is the point.
- Falsifier: the policy floor's text scopes "false-green" to tests asserting something
             untrue, excluding under-asserting tests.
```

```
[K3]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read)  [unchanged; = CDX-P1-08]
legs.hpp "ONLY call sites of ctx.write_output" claim is false — plugin.cpp:131 writes
directly with the raw action string unescaped
- Location:  filesystem_posture_legs.hpp:14-15,132 vs filesystem_posture_plugin.cpp:131
- Anchor:    CLAUDE.md rule 3 (comment contradicts code) at native LOW; capability gate
             makes the hostile-action path unreachable (E6-shaped cap).
- Fix:       route through a seam wrapper or amend the claim to "row-emitting call sites".
```

```
[K4]  HIGH · CONFIDENCE(hi) · PROVENANCE(static-read)  [severity-changed: LOW→HIGH; = CDX-P1-04]
Quota probe failures are masked by a clean result status on all three legs — macOS never
marks partial on getattrlist failure (even all-fail), Linux clears the partial condition
on any non-PermissionDenied errno (unknown errno all-fail reads COMPLETE; mixed reads
COMPLETE), Windows marks only when NO NTFS volume succeeded
- Location:  filesystem_posture_macos.cpp:190-216; filesystem_posture_linux.cpp:167-169,
             219-220 + parsers.hpp:347; filesystem_posture_win.cpp:439-441
- Evidence:  macOS rc!=0 path has no mark_result_partial (only the reply-length-mismatch
             path at :193-200 does); linux `if (state != QuotaState::PermissionDenied)
             all_dev_permission_denied = false;` — QuotaState::Unavailable (unknown errno)
             clears it; win `if (any_ntfs && !any_success)`.
- Scenario:  mixed-success quota walk (or macOS/unknown-errno all-fail) → rows say
             unavailable/permission_denied, envelope says COMPLETE → status-only consumers
             (server alerting on completeness) treat an incomplete read as clean — the
             exact failure the brief's target (b) asks about.
- Anchor:    derivation — I3 (incomplete result presented as complete), E3/E5 no change.
             Judgment-anchored; no policy floor.
- Mitigations: per-row state token remains truthful; consumers that reparse every row can
             detect it. Status-only consumers cannot. No other guard.
- Fix:       track any_failure independently of any_success on each quota leg and
             mark_result_partial whenever any acquisition failed; keep expected states
             (disabled/unsupported/no-block-device) non-degraded.
- Falsifier: the result contract defines a result with failed probes as FULL whenever at
             least one probe succeeded.
```

```
[K5]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read)  [unchanged]
macOS snapshots fallback detail "enumeration failed on every volume" also fires when one
volume failed and the rest enumerated cleanly-but-empty
- Location:  filesystem_posture_macos.cpp:283-289
- Fix:       "failed on at least one volume; no snapshots enumerated" or count N of M.
```

```
[K6]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read)  [unchanged]
tests/meson.build:440-448 — license_scan comment now dangles off the
filesystem_posture_local_dispatcher entry (misattribution)
- Fix:       move the three license_scan comment lines back to line 440's entry.
```

```
[K7]  LOW · CONFIDENCE(hi) · PROVENANCE(static-read)  [unchanged; subsumed by CDX-P1-09]
Doc truth: duplicated GetVolumeInformationW (yaml:7, user-manual:589); yaml:29-30 credits
capacity to GetVolumeInformationW (code: GetDiskFreeSpaceExW, win.cpp:209); yaml:7-8 names
DISKQUOTA_USER_INFORMATION (absent from code); yaml:115-117 + user-manual:590 claim macOS
reports state=unsupported (code probes getattrlist and can emit Configured/None)
- Fix:       correct mechanism names; describe macOS quotas as volume-level
             configured/none/unsupported-by-fs.
```

```
[K8]  LOW · CONFIDENCE(med) · PROVENANCE(static-read)  [unchanged]
os-capability-matrix.md:108 marks Linux ✅ ("builds and core actions work", :92) while the
Linux leg has never been compiled anywhere; Windows at the identical verification state is
honestly 🟡 — asymmetric claims on a branch with no CI run yet
- Mitigations: Tier-2 CI Linux leg would catch a false claim on push (branch is LOCAL
             ONLY, so none has run).
- Fix:       🟡 + "compile-verified pending first Linux CI leg", or bump after a real
             Linux build+test.
```

```
[K9]  INFO · CONFIDENCE(hi) · PROVENANCE(static-read)  [unchanged]
Fixture provenance pointer dangles: tests reference captures/PROVENANCE.md under
scratchpad/devteam-wave6-1b-fsposture/, absent from the repo; inline per-fixture labels
are honest and synthetic round-trips are labelled synthetic.
```

```
[K10]  HIGH · CONFIDENCE(med) · PROVENANCE(static-read)  [new-from-cross-exam]
macOS snapshots leg ignores parsed.truncated — an APFS volume with ≥1024 snapshots is
silently capped at 1024 rows with a clean envelope (Windows leg handles the identical
flag; the macOS leg's K1 brace bug currently masks this by marking every run PARTIAL —
once K1 is fixed the silent cap reads clean)
- Location:  filesystem_posture_macos.cpp:263-272 (only parsed.malformed is checked)
             vs parsers.hpp:524-527 (truncated set at the 1024 cap) and the correct
             handling in filesystem_posture_win.cpp:515-516, 534-541
- Claim:     same masked-incomplete class as CDX-P1-05: a known-incomplete set presented
             as a complete clean result.
- Evidence:  no reference to `.truncated` anywhere in filesystem_posture_macos.cpp
             (parse result field consumed only via .names/.malformed).
- Scenario:  backup software accumulates >1024 APFS snapshots on one volume → inventory
             truncated at 1024 → status COMPLETE → operator/automation believes the set
             is exhaustive.
- Anchor:    derivation — I3, E5 (no change). Judgment-anchored.
- Mitigations: none after K1 is fixed (today K1's unconditional PARTIAL accidentally
             covers it — not a control).
- Fix:       `if (parsed.truncated) mark_result_partial(ctx, "macos:fs_snapshot_list",
             mount + ": snapshot count cap reached");` mirroring the Windows leg.
- Falsifier: parse_fs_snapshot_list_buffer cannot set truncated, or the macOS leg checks
             it somewhere I could not find (grep says otherwise).
```

Adopted codex findings (verified independently; counted in my verdict):
- **CDX-P1-01** HIGH — APFS decoder accepts `record_length < 32` with name pointing into the
  header; fabricated name, `malformed=false`. Reproduced with my own ASan/UBSan probe.
  Fix: reject `record_length < 32` and `name_start_in_record < 32`; add the directed
  30-byte-record regression test.
- **CDX-P1-02** HIGH (policy floor) — no Resource Ledger for a C++ diff adding fds, HANDLEs,
  COM objects, a mutex-protected static getmntinfo buffer. Verified absent from the 24-path
  range, all 11 commit bodies, and the review dir. Caveat: satisfied by producing it at
  Gate 1 of the governance run; blocking-but-routine.
- **CDX-P1-05** HIGH (confidence med) — Linux quotas/snapshots never check the 4MiB
  `read_truncated` flag; only mounts does (linux.cpp:103). Fix: mirror the check.
- **CDX-P1-06** HIGH (confidence med, static-read — Windows body never compiled) — FSCTL
  snapshot walker never reads/validates the three header ULONGs. Fix: decode + cross-check
  counts/sizes against decoded names and buffer.

## Verdict, coverage, runs

VERDICT:  BLOCK — K1 (verified false CONSTRAINED/PARTIAL on every macOS snapshots run),
K2/K4 (upgraded), and adopted CDX-P1-01/02/05/06 are each independently blocking;
K1's fix must land before any other snapshots-leg grading is meaningful.

COVERAGE: deep — decoder memory safety AND (now) semantic validation, failure-vs-success
and failure-vs-empty accounting on all three legs, seam/escaping/vocabulary pinning,
capability declaration, test adequacy, docs/packaging/changelog/matrix consistency,
Windows leg static review (HRESULT/COM/handle rights/buffer walk), governance-floor
artifacts. Skimmed — Windows/Linux runtime behavior (no toolchain/host exists; static
only, said so plainly); server dispatch internals beyond the catalogue gates.

RAN (this phase):
- ASan+UBSan probe of parse_fs_snapshot_list_buffer with record_length=30/dataoffset=4/
  length=2 → `names=1 malformed=0`, name byte 0x02 — CDX-P1-01 reproduced independently.
- `git diff --name-only <range>`, `ls docs/resource-ledgers/`, `git log %b | grep -i ledger`
  → no ledger artifact anywhere — CDX-P1-02 confirmed.
- Targeted reads: parsers.hpp:490-600, linux.cpp:80-281, macos.cpp:150-296,
  win.cpp:300-544, yaml (full), user-manual:580-597, SKILL.md ledger sections —
  CDX-P1-04/05/06/09 confirmed line-by-line.
- grep `DISKQUOTA_USER_INFORMATION` in win.cpp → absent (doc-truth point confirmed).
- Did NOT open codex.phase2.md (protocol scopes cross-exam to the peer's Phase 1).

FILES (this phase, in addition to Phase-1 set): .claude/skills/governance/SKILL.md
(:161-168, :289-297, :452-495), docs/resource-ledgers/ (listing), full
content/definitions/filesystem_posture.yaml, docs/user-manual/agent-plugins.md:580-597.

## Delta since Phase 1 (3-5 lines)

Upgraded K2 MEDIUM→HIGH (conceded codex's false-green policy-floor reading) and K4
LOW→HIGH (quota-failure masking is all-three-legs and includes all-fail cases, verified).
Adopted four codex HIGHs after independent verification (APFS short-record decoder gap,
missing Resource Ledger floor, Linux read_truncated ignored in 2 of 3 actions, Windows
FSCTL header fields unvalidated). Added K10 (macOS ignores parsed.truncated; currently
masked by K1). Defended K1 at HIGH against codex's LOW (I8 requires a correct result;
this envelope asserts a fabricated fact). Still disagree with codex on: K1 severity
(HIGH vs LOW) and K10 (which codex mentioned only as a fix note, not a finding).
