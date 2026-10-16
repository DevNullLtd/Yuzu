> **2026-10-15:** this record describes `6eb78e12e` only; it is superseded in part by [macos-development-foundation-20261015.md](macos-development-foundation-20261015.md).

# macOS development foundation — governance and validation

Status: **PASS for the scoped development-foundation governance review**. All 12
findings are fixed, including three derived HIGH findings and two supported-test-leg
policy-floor blockers. This is not a release or installed-agent acceptance certificate.

## Scope and review

Reviewed base: `1972d3e2a8c0beec9c71a4aa0fc2492d2619b4e1`; initial integration HEAD:
`6eb78e12e989c735e8dad115836a17c64974f476`, plus the committed foundation/fix diff
accompanying this report. The later moving `origin/dev` was not used to fabricate
unrelated removals. Current governance policy and both routed tables were checked.

The change establishes an opt-in signed macOS development bundle, immutable
disabled-OTA behavior, recoverable package transitions, device-registration
discovery, and a targeted installed-agent smoke check. It does not implement
Spark mechanisms or Reflex, flip Guardian's `prefer_spark`, confer Network
Extension access, or certify prevention parity.

All mandatory review roles ran: security, docs, C++ language/safety, quality,
architecture, build, platform, deployment, plugin ABI, happy/unhappy paths,
consistency, chaos design, compliance, SRE and enterprise readiness. Two reviewer
workers covered explicit role groups because of concurrency limits; multiple
roles by one worker are not independent corroboration. No reviewer installed a
package, altered a live service, or ran destructive live fault injection.

Findings and supersessions are in
[`macos-foundation-20260917.cdfcd1.jsonl`](../../governance.d/macos-foundation-20260917.cdfcd1.jsonl).
Read each finding field-wise in timestamp order; attestation fields are row-local.
Raw reports are retained in the [companion record](macos-development-foundation-20260917-reports.md).
Absence of a finding is not evidence that a role ran; role coverage is explicit here.

Review found and drove fixes for ignored shell signature failures, original loose
package layout/ownership migration, fresh data-directory creation, installer
Python dependence, CMS final-byte handoff, old-library thread portability,
recoverable sidecar backups, interrupted plugin-promotion recovery, native-test
portability and process-global cancellation leaking between tests. The rollback
window was reproduced independently by two reviewers. Merely detecting a failed
sidecar restore was insufficient: the final repair retains original bytes on disk.

Severity-ordered synthesis follows. The UP1/C1 same-location, same-defect cluster
is **provisional**; it preserves both native assessments and gates at the stronger
derived severity. Other rows are separate defects. All are fixed; none were parked,
waived or deferred. CP1 and QA1 gate through the supported-test-leg policy floor,
not a fabricated HIGH operational impact.

| Finding | Reporting role (native label) | Derived severity / gate | Correction |
|---|---|---|---|
| SEC-1 | security (BLOCKING) | HIGH / BLOCKING | Explicit shell signature rejection |
| CPP-S1 | C++ safety (BLOCKING) | HIGH / BLOCKING | Retained on-disk original and atomic restoration |
| UP1/C1, provisional | unhappy-path (BLOCKING); consistency (SHOULD) | HIGH / BLOCKING; consistency native MEDIUM | Remove incoming-owned plugins on replay, preserve unrelated plugins |
| CP1 | cross-platform (BLOCKING) | MEDIUM / policy-floor BLOCKING | Native fixture guards and portable path/interpreter expectations |
| QA1 | SRE (BLOCKING) | MEDIUM / policy-floor BLOCKING | Restore global cancellation after joined teardown |
| SEC-2 | security (SHOULD) | MEDIUM / SHOULD | Nested loose-plugin discovery and complete manifests |
| SEC-3 | security (SHOULD) | MEDIUM / SHOULD | Strict Installer-receipt legacy ownership |
| RD1 | release-deploy (SHOULD) | MEDIUM / SHOULD | Create absent working directory without changing existing data |
| RD2 | release-deploy (SHOULD) | MEDIUM / SHOULD | Native Foundation plist merge |
| RD3 | release-deploy (SHOULD) | MEDIUM / SHOULD | Document final-byte two-stage CMS handoff |
| CPP1 | C++ expert (SHOULD) | MEDIUM / SHOULD | Scoped portable thread ownership |
| D1 | docs (SHOULD) | MEDIUM / SHOULD | Operator upgrade pointer and lifecycle explanation |

Only UP1/C1 has two independent reporters, both in Gate 4 before sharing their
results. Subsequent acknowledgements are not additional independent discoveries.
The fresh ledger passes `scripts/ci/check-governance-ledger.py`; the canonical
I1/I2/I3 park probe exits 4 (clean), and all 12 live dispositions are `fixed`.

## Validation record

Native macOS verification:

- `python3 tests/test_macos_app_packaging.py`: 35 passed.
- `python3 tests/test_macos_foundation.py`: 12 passed.
- `meson test -C build-macos --no-rebuild 'agent unit tests' --test-args
  '--rng-seed 2353298010' --print-errorlogs`: exit 0, 111.89 seconds;
  3,157 cases, 3,152 passed, 5 skipped; all 165,801 assertions passed.

An initial five-target success preceded the complete plugin build and is not the
final acceptance result. A later full agent run reproducibly failed 44 subprocess
cases at seed `2353298010`: the new lifecycle fixture left process-global
cancellation enabled. Isolated subprocess tests passing did not close that defect.
The repaired fixture restores the prior state after stopping and joining the agent;
the same-seed full rerun above passes. The final combined command,
`meson test -C build-macos --no-rebuild --suite agent --suite tar --print-errorlogs`,
also exits 0: all five targets passed, including the full agent target (103.74
seconds), TAR (1.93 seconds) and packaging (3.76 seconds).

The final development package was rebuilt after the recovery fixes. Its expanded
preinstall, postinstall and native JXA helper match current source byte-for-byte.

- Package SHA-256:
  `c16ed0f314c853cd8b0e00c5fdc2a40f18e8bb5e4d051428c46ef6095df61b5f`.
- Staged and extracted agent executable SHA-256:
  `4ff1748dcb1159d0622daf2ac91accc5686ab8174907c787820ea5a5a16681da`.

The package itself is intentionally unsigned; the app uses the validated Mac
Developer identity. `codesign --verify --deep --strict` on the extracted app exits 0.

## Explicit qualification limits

- Fresh source has been compiled and a signed development app staged; the final
  package was rebuilt after installer fixes. No newly built package has been
  installed in this run. Historical live ES evidence belongs to an older artifact.
- The local UAT server on port 8080 is down, so the live smoke was not run. The
  existing installed LaunchDaemon remains running and unchanged (final read-only
  observation: PID 810).
- The reused dependency prefix emits `libxml2.a` object minimum-OS 26.0 warnings
  while linking with target 13.3. The source triplet/runbook require a clean 13.3
  dependency rebuild; this artifact is current-host development evidence only,
  **not macOS 13.3 runtime qualification**. An older archive audit does not cover it.
- Distribution signing/notarization, agent/gateway TLS or mTLS, Intel/oldest-OS
  execution, fresh install/upgrade/downgrade/uninstall and privileged recovery,
  long-running ES/drop behavior and sanitizer qualification remain separate work.
- Portable mocked contracts, real native helper execution and actual cryptographic
  checks are distinct evidence; mocked verifier results are not cryptographic proof.

The [development runbook](../macos-development-foundation.md) defines how to obtain
fresh installed-agent evidence with explicit operator authorization. A scoped
governance pass does not waive any of the qualification limits above.
