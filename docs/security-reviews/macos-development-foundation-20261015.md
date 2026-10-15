# macOS development foundation: review fixes, installer rework and governance (2026-10-15)

Status: **PASS after Gate 8.** Every BLOCKING finding raised by Gates 1-8 and the two VM
chaos runs is fixed, or refuted with recorded evidence. Non-gating residue is tracked in
follow-up issues. This record supersedes the scope, verification and plugin-ownership
statements of [macos-development-foundation-20260917.md](macos-development-foundation-20260917.md);
that record still describes `6eb78e12e` and is not rewritten.

Ledger: `governance.d/4482-macos-installer-rework.aGwZqa.jsonl` (this run, 154 rows), plus three
supersession rows appended to `governance.d/macos-foundation-20260917.cdfcd1.jsonl` (CP1, RD1, SEC-3).

## Scope

- **Reviewed:** PR #4482 (`feat/macos-development-foundation`). Gates 1-6 ran against
  `origin/dev...992b50cc0`. The fixes are the first-parent commits `53fd57eaa`..`8691d6bf6`;
  `b9e218fe3` is a clean merge of `origin/dev` and is out of scope.
- **What the change now governs.** This is wider than the 2026-09-17 record and the original PR
  body claimed:
  - **Every macOS `.pkg`, including the release package.** The installer is transactional. It
    refuses before the payload on an untrusted `/usr/local` chain, on content another account
    could have written (mode bits or ACLs), on an untrusted data, log or config directory, on a
    plugin-name collision, and on retained signature enforcement. It does not start an
    unconfigured first install.
  - **The updater's `.old` rollback guard applies to every POSIX agent**, Linux included. It
    promotes only a regular, singly-linked file owned by the agent's own account or root, with
    no group or world write bit.
  - **`--no-auto-update` now disables startup rollback, `.old` cleanup and the verification
    marker on every platform.**
- **Not in scope.** No server, gateway, proto, REST, MCP or store change. ADR-1005 A1-A5 are not
  engaged.

## Owner decisions (2026-10-15, Tr3kkR, in the review session)

| # | Decision |
|---|---|
| D1 | An unconfigured first install is installed but **not started**, and is never rolled back for not running. |
| D2 | The data directory (and, by the same rule, the log directory) may be owned by **root or the `_yuzu` service account**, and must never be group- or world-writable. Otherwise the install refuses; it never adopts or re-owns the directory. **Withdrawn the same day** after the external review below: root only. |
| D3 | The recovery state-machine rework lands **in this PR**, not in a follow-up. |
| D4 | Chaos scenarios that need a real install run in a **disposable tart VM** ("Use tart"). |

## How the review ran

| Stage | Range or head | Result |
|---|---|---|
| Gates 1-6 | `992b50cc0` | FAIL: about 21 BLOCKING (policy floors bci-1/xp-1, qe-1, hp-1, sec-4/doc-1/doc-2; derived CRITICAL sec-2, ch-4). |
| Gate 7 | `53fd57eaa`..`2b0f971de` | Fixes, including the installer rework (`806eca71b`). |
| Gate 8 round 1 | `2b0f971de` (+`c92f63964`) | 12 re-reviews. BLOCKING: G8-S1, G8-S2, rd-n1/xp-14, rd-n2, rd-n3. |
| VM chaos run 1 | packages built at `b9e218fe3` | BLOCKING g8ch-B1 (every running-agent upgrade failed), B2, B3 (= rd-n2, verified). |
| Gate 8 round 2 | `3d329c44a` | BLOCKING: G8-S7 (ACLs), rd-r2-1, uh8-1/4/6/7. |
| Gate 8 round 3 | `3b028dde7`..`817abe9d8` | BLOCKING: con8-3, uh8r3-1 (a regression from the uh8-7 reorder), uh8r3-2..4. MEDIUM: S8-1. |
| VM chaos run 2 | scripts from the round-3 worktree | **13/13 scenarios pass**; every g8ch-* finding closed. |
| Gate 8 round 4 | `167b78a9c` | BLOCKING: S8r4-1, S8r4-2, U-1, uh8r4-1..3. Fixed in `167b78a9c` and `8691d6bf6`. |

The VM was a tart clone of `ghcr.io/cirruslabs/macos-sequoia-base` running **macOS 15.7.7**. Every
install, root action and power cut ran inside that VM, **never on the review host**. The
packages for VM run 2 were built from the round-3 scripts. Commits `167b78a9c`, `2c2a93306` and
`8691d6bf6` were verified by harness and kill matrices, not in the VM.

**Where Gate 8 stopped.** Each review round found less than the one before, and the round-4
findings were edge cases of transient `pkgutil` failures and one lane switch. The round-4 fixes
(`8691d6bf6`) were covered by behavioural tests, each mutation-checked, but **no further review
round re-read them**. The maintainer's standing guidance is to stop a governance loop once it no
longer moves the release. A later change to these scripts reopens Gate 8 for its own diff.

**External review after the record (FortitudeEtc, 2026-10-15, [review 5533419011](https://github.com/DevNullLtd/Yuzu/pull/4482#pullrequestreview-5533419011)).**
It confirmed the earlier blockers fixed and raised one new blocker and three should-fix items, all
fixed in `32acd46f2` and recorded in the ledger as `fr-1`..`fr-4` (pass 6):

| Id | Finding | Fix |
|---|---|---|
| fr-1 | The root daemon trusted `_yuzu`-owned data and log directories (D2), so that account could redirect a root write with a symlink. | D2 withdrawn by the owner: both directories must be root-owned, not group/world writable and free of write-granting ACLs. |
| fr-2 | `uninstall.sh` removed everything after a 30 s stop timeout. | It stops the agent first and refuses, with everything in place, if it does not stop. |
| fr-3 | Recovery state had no ACL check (`chmod 700` leaves ACLs). | The state root and every snapshot are refused on any ACL entry, checked and never stripped; a recovery restart also requires the package's own executable with a root-only definition and executable. |
| fr-4 | A loose package could build without `libyuzu_agent_core.dylib`. | The build fails, and postinstall requires the core's recorded hash. |

These fixes were tested (three new behavioural tests, 18 mutations killed) but not run through a
governance gate or the VM. The review's minor items (promoted-plist hardening, the bare `delete`
ACL right, the updater's lstat-then-rename, stale macOS rows in `docs/agent-privilege-model.md`)
are not addressed here.

## Evidence at the final head (`8691d6bf6`)

- **Packaging tests** (`tests/test_macos_app_packaging.py`):
  - **122 cases**, all passing on macOS (bash 3.2). In a `python:3.12-slim`
    container, the macOS-userland cases skip and there are 0 failures.
  - Every harness uses the production preamble (`set -euo pipefail`) and the real helpers;
    functions under test are called as plain statements.
- **Mutation testing:** seven test rounds, about 180 mutations of guarded lines, all caught.

  | Round | Commit | Cases | Mutations |
  |---|---|---|---|
  | 1 | `806eca71b` | 69 | 35 |
  | 2 | `7dd3b4886` | 81 | 35 |
  | 3 | `3b028dde7` | 86 | 22 |
  | 4-5 | `59599eeac` | 94 → 103 | 18 + 20 |
  | 6 | `4553ca96b` | 117 | 23 |
  | 7 | `8691d6bf6` | 122 | 12 |

  About 15 more mutations were checked directly during fixes; equivalent mutants are named in
  the round reports.
- **Updater:** `[updater]` passes at 41 cases. The new rollback-guard tests fail with the guard
  removed.
- **Meson `--suite agent --suite tar --suite docs`:** 0 failures, except two pre-existing timing
  flakes seen under host load. Both are green on re-run, and this PR touches neither:
  - `test_guardian_outbox_drain_worker.cpp:1836` (#5791);
  - `test_bounded_wait.cpp:289` (#5901).
- **Kill matrices (unhappy-path round 4):**
  - postinstall: 368 SIGKILL points and 173 SIGTERM points;
  - preinstall: 382 points;
  - preinstall recovery: 517 points;
  - stale-manifest re-derivation: 44 points;
  - uninstall: 133 points;
  - lane transitions: 143 points.

  Every point recovers or resolves on the next run. The only non-clean points were kills after
  the install had completed.
- **CI:** the Linux and Windows test legs passed at `b9e218fe3` (bci-1/xp-1 closed). The final
  head's CI is 24 checks passed, 0 failed and 3 still running when this record was written (2026-10-15).
- **Artifacts:** no package was hashed at the final head, so "packaged installer scripts match
  reviewed source" is **not** re-asserted. The release workflow builds the shipped package.

## Supersessions of the 2026-09-17 record and ledger

| Finding | 2026-09-17 state | Now |
|---|---|---|
| CP1 | fixed (pass 3) | Regressed as bci-1/xp-1 when the September review fixes added unguarded macOS-userland tests. Re-fixed by per-test guards (`53fd57eaa`). |
| RD1 | fixed: create the data directory, preserve the existing one | Replaced by **D2**: an existing directory must be owned by root or `_yuzu` and not group/world writable, or the install refuses (`806eca71b`, `7dd3b4886`). |
| SEC-3 | fixed: receipt-based legacy ownership | Superseded by **byte ownership**: a plugin is package-owned only while its bytes match a recorded package hash (`5897fb52a`). Removal keeps operator-modified plugins and accepts any package record (`806eca71b`, `59599eeac`). The receipt remains the source for pre-manifest packages and for re-derivation after a rollback (`806eca71b`, `59599eeac`). |

Statements in the 2026-09-17 record and the original PR body that no longer hold:

- **"35 tests passed".** The packaging suite now has 122 cases. The file had 49
  test methods at `992b50cc0`, not 50 (Gate 1 corrected).
- **"receipt-based legacy plugin ownership".** Ownership is now hash-based (see SEC-3).
- **"Packaged installer scripts match reviewed source".** Not re-established at the final head.
- **"No package was installed".** Packages were installed, upgraded, refused, interrupted and
  power-cut, **in a disposable VM only**.
- **"Recoverable installer transitions" and "opt-in development packaging".** These understate
  the scope; see Scope above.

## Corrections to commit messages

Commits are immutable, so the corrections are recorded here instead.

| Commit | Claim | Correction |
|---|---|---|
| `569c62c89` | Reproduced the deadlock via the ERR-trap rollback; "both recovery paths"; "three behaviour tests … each verified to fail when its fix is reverted". | Only preinstall's recovery and `retire_legacy_app` were tested; `restore_previous` was never executed (qe-1, the false-green floor). Behavioural tests now cover `restore_previous` (`806eca71b`). |
| `569c62c89`, `067c350bc` | Recovery "never blocks a later install". | False when the restored agent failed `require_started` (sec-1). True since `806eca71b`. |
| `19c914e22` | "both recovery paths … each verified to fail on its mutation". `/usr/local/lib` "already covered". | Postinstall was untested. `/usr/local` itself was never checked, which left the bundle lane open (sec-2). |
| `0d53e7191` | The unreadable-definition test "fails on the reverted guard" in both paths. | It covered preinstall only. |
| `8f3ed5d25` | The preinstall data-dir refusal was "verified to fail when the check is removed", and the error "says how to proceed". | The check was pinned by string order only (qe-3). The advice "remove it" would destroy agent identity (rd-1). |
| `d7842a0fe` | The copy is verified so the kept copy matches what was verified. | The kept copy was never read; it was dead state, removed in `7dd3b4886` (sec-8). |
| `5897fb52a` | "a plugin is package-owned only while its bytes match the hash". | It held for collision and hardening only; removal was name-only until `806eca71b` (sec-3). |
| `806eca71b` | "merge helper runs from the root-only snapshot"; "35 mutations". | The helper ships in the package's Scripts directory since `7dd3b4886` (G8-S3). The 35 mutations were round 1 only. |
| `3d329c44a` | CLI11 reads an empty value as off. | True for the environment variable only. `--plugin-require-signature=` (empty inline) is ON in CLI11 2.6; mirrored exactly in `59599eeac` (con8-1). |
| `3b028dde7` | A lost definition's default "cannot run unconfigured". | False when `/etc/yuzu/certs/default-ca.pem` exists. The merge now reports the loss explicitly (`59599eeac`, con8-2). |
| Gate 1 | Host macOS 26.6; `.mm` TUs compiled with Apple clang. | The host is macOS 26.5.2, and the TUs were built with Homebrew LLVM 23 (xp-10). |

## Signing-identity custody

| Identity | Kind | Custody | Authority in this code | Retirement |
|---|---|---|---|---|
| Developer ad-hoc / development certificate | Apple Development | Developer's login keychain on the build Mac | Signs development bundles only; never a release artifact | n/a (development only) |
| `Mac Developer: Nathan Dornbrook (YA95685L8R)`, team `7RLSYL2JM7` (`LEGACY_*` pins in postinstall and uninstall.sh) | Pinned legacy identity, a **temporary exception** | Personal | Delete-on-match of one pre-package development app under the data directory; anything else is quarantined | Removal tracked in #5900, **revisit by 2027-01-31** |
| Developer ID Application / Installer | Planned | HSM-held (SafeNet, on the BigMags runner) | None yet | Acceptance criteria belong in #239 (and #1455 for the ES entitlement) |

## Adjudications, waivers and refutations

- **G8-S7 / con8-3 (ACLs, derived CRITICAL).** These were **fixed, not adjudicated**. Write-granting
  ACLs are refused on the `/usr/local` chain, on agent binaries, on the whole plugin tree and on
  every trusted directory, including the bundle code root and its parents. Package-owned roots
  and promoted code are stripped with `chmod -N` (`3b028dde7`, `59599eeac`). Because nothing was
  waived, no human adjudication was needed.
- **Refuted, with evidence recorded in the ledger:**
  - ch-5: Installer does not re-own `/usr/local/bin`, and loose code is hash-verified (VM S6).
  - ch-6: installd serialises whole transactions (VM S8).
  - rd-n4: Installer does not re-own `/usr/local/bin` (VM S4).
  - rd-r2-2: the Scripts directory is extracted `root:wheel 755` (VM).
- **Waivers:** none. No BLOCKING finding is `open`.

## Dispositions

This is a summary; the ledger has every finding with its commit, issue or evidence.

| Disposition | Count |
|---|---|
| fixed | 114 |
| deferred to a follow-up issue (all non-gating) | 36 |
| refuted with evidence | 4 |

Every BLOCKING finding, with the commit that fixes it:

- **Policy floors:**
  - bci-1/xp-1 — `53fd57eaa`
  - qe-1 — `806eca71b`
  - hp-1 — `806eca71b`
  - sec-4/doc-1/doc-2 — `2cbd7fbbb`
  - rd-n1/xp-14 — `7dd3b4886`
  - rd-11 — `b3e4a5447`, `7dd3b4886`
- **CRITICAL:**
  - sec-2 — `806eca71b`, `7dd3b4886`
  - ch-4 — `316738701`, `806eca71b`, `7dd3b4886`, `c92f63964`
  - G8-S1/xp-13 — `7dd3b4886`
  - G8-S7 and con8-3 — `3b028dde7`, `59599eeac`
  - uh8r3-1 — `4553ca96b`, `167b78a9c`
  - S8r4-1 — `167b78a9c`
- **HIGH:**
  - sec-1, sec-3 and rd-4 — `806eca71b` (sec-3 and rd-4 also `59599eeac`)
  - S8-1 (native MEDIUM; its facts derive HIGH) — `d4e808fb6`, `4553ca96b`
  - rd-1 — `806eca71b`, `7dd3b4886`
  - rd-2 — `806eca71b`, `59599eeac`
  - uh-1..3 — `806eca71b`
  - ch-1 — `806eca71b`, `3b028dde7`, `59599eeac`
  - ch-2 — `806eca71b`
  - ch-3 — `806eca71b`, `59599eeac`
  - sre-2 — `806eca71b`, `3b028dde7`
  - er-2 — `806eca71b`
  - er-3 — `2cbd7fbbb`, `817abe9d8`
  - G8-S2 — `7dd3b4886`, `59599eeac`
  - rd-n2 and g8ch-B3 — `7dd3b4886`, `3b028dde7`, `4553ca96b`
  - rd-n3 — `7dd3b4886`
  - g8ch-B1 — `3b028dde7`
  - g8ch-B2 — `7dd3b4886`
  - rd-r2-1 and uh8-2 — `3b028dde7`, `4553ca96b`
  - uh8-1, uh8-4 — `59599eeac`
  - uh8-6, uh8-7 — `59599eeac`, `4553ca96b`
  - uh8r3-2 — `4553ca96b`
  - uh8r3-3, uh8r3-4 — `4553ca96b`, `167b78a9c`, `8691d6bf6`
  - S8r4-2 — `167b78a9c`
  - U-1 — `167b78a9c`, `8691d6bf6`
  - uh8r4-1..3 — `8691d6bf6`

## Follow-up issues (non-gating residue)

| # | Topic | Findings |
|---|---|---|
| #5896 | Stable installer outcome codes, a last-outcome file for MDM, quarantine metadata | sre8-1, er-6, co-4, sre-1, rd-7 |
| #5897 | Stage the incoming LaunchDaemon plist outside `/Library/LaunchDaemons` | r2-L1 |
| #5898 | Deployment-floor audit of static-archive members | xp-2 |
| #5899 | `hostArchitectures` in the distribution XML (Rosetta) | xp-12, rd-n7, g8ch-i1 |
| #5900 | Remove the pinned legacy identity; record signing custody | co-2, co-3 |
| #5901 | Flaky `bounded_call_ex` ceiling test under load | suite run |
| #5902 | Health-gate robustness | uh8-8, ch-8, sre-3 |
| #5903 | `lockf` descriptor form on macOS 13.3/14 (perl fallback in place) | uh8-6 residue |
| #5904 | Installer polish and INFO residue | rd-9, rd-n5..7, sre-5, sre8-4..5, sec-7/9, doc-11, cpx-3/5, cps-*, xp-5/8, qe-8..11, uh-7, con-1..3, I-1..3, uh8r3-5..8, uh8r4-6, rd-10, rd-r2-5 |
| #5905 | Enrolment token outside the world-readable plist | G8-S6, er N-3 |

## Links

- Endpoint Security entitlement: #1455.
- Developer ID via HSM: #239.
- Proper macOS bin/lib layout: #5889.
- Core library beside the binary: #5144.
- PR: #4482.
