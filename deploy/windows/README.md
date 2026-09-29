# Windows CI runner — provisioning spec

This directory is the **versioned source of truth for a native Windows CI build
host**, the Windows analog of `deploy/docker/Dockerfile.ci-linux`. Linux runners
get their toolchain from a Dockerfile; Windows needs native MSVC (no practical
container), so the equivalent is a declarative, idempotent PowerShell spec plus a
machine-readable manifest a self-test verifies.

The goal: a new Windows runner is reproducible from this directory, not a
multi-hour archaeology dig, and no script hardcodes one host's layout.

| File | Role |
|---|---|
| `Provision-Windows-Runner.ps1` | Installs the pinned toolchain, sets machine env (incl. the gateway + shared-cache contracts), emits `toolchain-manifest.json`. |
| `toolchain-contract.json` | Reviewable schema for host pins/probes and the separate job-scoped vcpkg baseline. Provisioning parameters must match it. |
| `Toolchain-Contract.psm1` | Fail-closed schema/pin/probe adapter shared by the assertion and its hermetic tests. |
| `Assert-Toolchain.ps1` | Runner self-test: verifies the manifest schema and live versions, contract env, and every per-agent PostgreSQL binary/service/health check. Run at provision time **and** as a registration/preflight gate. |
| `Update-ToolchainManifest.ps1` | Drained-host, manifest-only migration for an already-installed reviewed contract change. Preserves each host's recorded runner/PostgreSQL/telemetry topology, live-asserts a candidate, then atomically replaces the manifest with a backup. |
| `Assert-VcpkgCheckout.ps1` | Job self-test: after `lukka/run-vcpkg`, verifies the workspace checkout HEAD, clean tracked tree, and executable release against the checkout metadata before CI installs ports. |
| `Test-ToolchainContract.ps1` | Hermetic schema/version regression tests, also registered in Meson's `docs` suite when `pwsh` exists. Safe anywhere; reads no service or registry state. |
| `Test-ProvisionLogic.ps1` | Regression tests for the provisioning script's decision logic (maintenance gate, `-D` handling, `ImagePath` rewrite). Safe anywhere — no elevation, no machine state. Run after editing `Provision-Windows-Runner.ps1`. |
| `Start-PinnedRunner.ps1` | Supervises one runner, hard-pinned to one Threadripper CCD (L3 domain); shares the vcpkg binary cache and selects that runner's persistent telemetry DB. |

## Standing up a new box

1. **Provision** (elevated pwsh 7, over RDP/console — winget's source catalog
   doesn't work headless):
   ```powershell
   pwsh -File deploy\windows\Provision-Windows-Runner.ps1
   ```
   Re-runnable; pins live in the `param()` block (bump deliberately). Open a new
   shell afterwards so machine PATH/env take effect. The matching values in
   `toolchain-contract.json` are the reviewed contract; a command-line version
   override that differs from that file fails before the first provisioning
   step. Change both in the same review when deliberately bumping a pin.

   Host pin bumps use a two-phase compatibility window so review CI never
   depends on reprovisioning from unmerged code:

   1. Change the target in `pins` and list both old and new values in the
      matching `accepted_host_pins` entry. Merge while old and new hosts pass.
   2. Drain and reprovision the runners from the merged target, then remove the
      old accepted value in a follow-up review.

   Provisioning accepts only the target value; the compatibility list affects
   validation during the rollout, not what a newly provisioned host installs.

   Adding a newly required manifest item is stricter than widening an existing
   pin list: an older manifest cannot claim an artifact it never recorded.
   Keep the PR draft while every Windows host is drained and migrated from the
   reviewed branch, and do not enable its runners until `Assert-Toolchain.ps1`
   passes against that branch's contract. For an already-installed toolchain
   change, use the manifest-only migration rather than the Wee Tam provisioner:

   ```powershell
   pwsh -NoProfile -File deploy\windows\Update-ToolchainManifest.ps1
   ```

   It refuses to run while an Actions worker/job is live, preserves
   the prior manifest's one-runner or multi-runner topology, validates the
   candidate against live host state, and only then replaces the manifest
   atomically. It rechecks for a worker immediately before replacement. An idle
   listener may remain online because no service or toolchain state is mutated;
   a racing job sees either the old fail-closed manifest or the fully asserted
   candidate. The prior manifest is retained as a timestamped backup. Never
   hand-edit the JSON, and never run the four-runner Wee Tam provisioner on
   single-runner Shulgi merely to regenerate a manifest.

   The schema introduction's bounded compatibility bridge (a missing `schema`
   accepted through a deadline) has been retired: every Windows runner emits a
   schema-tagged manifest, verified live. A missing or unknown manifest schema
   now always fails.

   **On an existing shared box, stop all four runners first.** Provisioning
   restarts shared PostgreSQL services and rewrites machine PATH/env under
   whatever is running. A maintenance gate at the top of the script enforces
   this: it exits (code 2) before *any* step if a `Runner.Listener.exe` or
   `Runner.Worker.exe` is live. It gates on the **listener**, not just the
   worker — an idle listener can accept a job mid-run, so "no job right now" is
   not a safe state.

   That start-of-run check can be minutes stale by the time a service restart
   happens, so it is **re-asserted immediately before every `Restart-Service`**
   — the main PostgreSQL step's included — and on entry to the long per-agent
   binary step. The single exception is the rollback restart, marked
   `DRAIN-EXEMPT` in the source: it runs only after a liveness probe proves that
   cluster is *not* serving, where refusing would strand it broken — worse than
   the restart. It warns instead.

   Wherever it fires, the gate **exits the process directly** (code 2) rather
   than raising an error for something else to handle. That is deliberate:
   `Step()` catches and continues by design, so anything catchable can be — and
   twice was — swallowed or re-wrapped before reaching the top, letting the
   later Defender, vcpkg and machine PATH/env steps run under a live job. `exit`
   cannot be intercepted by any handler.

   It is a **check, not a lock**: an operator who starts a runner mid-run is
   detected at the next check, not prevented.

   `-AllowActiveRunners` **skips the check only** — it stops no runner and kills
   no job, so a live job may simply be interrupted. It exists for a box you know
   is yours.

   If you **edited** the provisioning script, run its regression tests first —
   they need no elevation and touch no machine state, so run them anywhere,
   including on a box that is busy:
   ```powershell
   pwsh -File deploy\windows\Test-ProvisionLogic.ps1
   ```

   If you edited the manifest, its assertion, or any pinned version, also run:
   ```powershell
   pwsh -NoProfile -File deploy\windows\Test-ToolchainContract.ps1
   ```

   For the Build Tools/SDK installation, Visual Studio Installer exits
   1641/3010 and WinGet's translated reboot results mean a reboot is required.
   Provisioning exits 3 immediately in those cases. On an already-registered
   host, disable the
   boot-triggered tasks that invoke `Start-PinnedRunner.ps1` (or preserve the
   site's runner-admission drain), then verify no `Runner.Listener.exe` or
   `Runner.Worker.exe` remains before rebooting. After reboot, verify the
   runners are still absent, rerun provisioning and `Assert-Toolchain.ps1`, and
   only then re-enable the tasks/admission.

   To roll this SDK target back, keep runner admission closed and revert the
   repository contract first. Verify the prior target's `Windows.h`,
   `kernel32.lib`, and `rc.exe` exist; if not, restore the known-good host image
   or reinstall the prior reviewed SDK target. Re-run provisioning from the
   reverted contract to regenerate the manifest, validate the prior native
   MSYS2 environment/build, and only then re-enable runners. Reverting Git alone
   does not restore host artifacts.

   Record each host reconciliation in the approved maintenance/change record
   before restoring runner admission. The retrievable record must identify the
   change ID, reviewed PR and exact commit, host, operator and approved window;
   link the provisioning transcript and capture the manifest hash,
   `Assert-Toolchain.ps1` result, native validation `/test` run ID, and any
   reboot or rollback outcome. Record installer/artifact hashes wherever the
   upstream distribution exposes stable immutable values. Link that record from
   the PR before taking it out of draft; a package-manager inventory entry or a
   host-local transcript alone is not approval evidence.

2. **Self-test** (must pass before registering):
   ```powershell
   pwsh -File deploy\windows\Assert-Toolchain.ps1
   ```

3. **Register the runners.** One runner per CCD. Configure each with its own root
   and a work dir on the fast data drive, labelled into the Windows pool
   (`.github/runner-inventory.json` declares the expected set):
   ```powershell
   # repeat for r0..r3 with a fresh --token each (gh api ... /registration-token)
   C:\actions-runner\r0\config.cmd --unattended --replace `
     --url https://github.com/DevNullLtd/Yuzu `
     --name yuzu-weetam-windows-0 `
     --labels self-hosted,Windows,X64,yuzu-weetam-windows `
     --work D:\ci\work-0 --token <TOKEN>
   ```

4. **Pin + supervise.** Run each runner under a **boot-triggered scheduled task**
   (NOT `svc.cmd install` — the service control manager starts it with full
   affinity, breaking the CCD pin), invoking the wrapper:
   ```
   pwsh.exe -NoProfile -File C:\actions-runner\Start-PinnedRunner.ps1 -Index 0
   ```
   Boot trigger ⇒ the runners auto-rejoin after a reboot / physical move.

## Contracts (why the env vars exist)

- **Gateway build (de-Shulgi-ified).** `scripts/build_gateway.py` resolves the
  Erlang toolchain from `YUZU_ESCRIPT` / `YUZU_REBAR3` (set by provisioning),
  then PATH/glob — it no longer assumes Shulgi's `C:\Erlang` junction or the
  Chocolatey rebar3 path. A box that sets those env vars builds the gateway with
  no filesystem fakery.
- **Per-agent PostgreSQL (#2094).** Provisioning creates **one cluster per
  runner agent**: agent 0's winget-installed service on `:5433`, plus an
  initdb'd cluster + service `postgresql-x64-18-yuzu-ci-<n>` on `:5433+<n>`
  (data under `D:\ci\pg\agent-<n>`, run as NETWORK SERVICE like agent 0) for
  each further agent. The machine-level `YUZU_TEST_POSTGRES_DSN` stays the
  **agent-0** DSN; `scripts/ci/ensure-postgres.sh` derives "base port + agent
  index" from the runner's `-<n>` name suffix at job time and probes before
  switching, falling back to the shared agent-0 cluster with a `::warning` if
  a per-agent cluster is missing. Rationale: 4 concurrent jobs sharing one
  cluster mutually DoS their `[pg]` server suites through the shared
  WAL/buffer pool (the 2026-07-12 server-suite timeouts). No runner `.env` or
  wrapper change is involved — re-running the provisioning script is the whole
  cutover.
- **Per-agent PostgreSQL binaries (#2354).** Each cluster also gets a **private
  copy of the whole PostgreSQL install tree** under `D:\ci\pgbin\agent-<n>`, and
  its Windows-service `ImagePath` is repointed at that copy's `pg_ctl.exe` (the
  `-D` datadir and every other argument left intact). Rationale: Postgres on
  Windows is `EXEC_BACKEND` — every connection `CreateProcess()`es a fresh
  `postgres.exe` — and when all four CCD-pinned agents shared one
  `C:\pgsql\bin\postgres.exe`, every backend spawn box-wide contended that single
  image file's FCB / image-section lock (~1000–1466 ms/spawn under concurrency;
  root-caused 2026-07-22, **not** Defender and **not** disk). A byte-identical
  copy at its own path has its own FCB and spawns in ~10–20 ms — validated ~50–70×
  under all-four-agent churn. The step is idempotent (`robocopy` refreshes the
  tree in place; an already-repointed `ImagePath` is accepted only after
  `pg_isready` plus authenticated `SELECT 1`) and per-agent catch-and-continue.
  A failed repoint restores the exact original `ImagePath`, restarts from the
  original bin directory, and verifies the same two health checks; a failed
  rollback is reported distinctly instead of claiming recovery. Both registry
  writes preserve the value's original kind, so a rollback restores the exact
  original bytes. Agent 0's live data exclusion comes from the service's actual
  `-D` argument (canonicalised before it is handed to `robocopy /XD`, which
  matches by path string), not an assumed install-root layout. `D:\ci\pgbin` and
  each copy's `postgres.exe` join the Defender exclusions below — and, unlike
  before, those two are verified fail-closed rather than added best-effort. The
  manifest self-test verifies all four private binary sets, registered service
  executables, `Running` states, and live authenticated probes, so drift fails
  before a build starts.
- **Shared vcpkg binary cache.** `RUNNER_TOOL_CACHE=D:\ci\tool_cache` points
  `${{ runner.tool_cache }}` (hence `VCPKG_DEFAULT_BINARY_CACHE` in `ci.yml`) at
  **one** machine-level dir, so the 4 CCD-pinned runners share one warm vcpkg
  binary cache instead of fragmenting it 4× (~1.9 GB each). Mirrors
  `CCACHE_DIR=D:\ci\ccache`. Set in each runner's `.env` (durable) and exported
  by the wrapper. The vcpkg binary cache is content-addressed → concurrent writes
  across runners are safe.
- **Build parallelism.** Provisioning sets machine-level
  `YUZU_BUILD_JOBS=16`; `Start-PinnedRunner.ps1` consumes that value and refuses
  to start if it is missing or differs from the fixed 16-thread CCD envelope.
  `Assert-Toolchain.ps1` also compares the live machine value with the manifest.
  CI passes it explicitly as `meson compile -j 16`; affinity controls placement
  but does not make Ninja ignore the host-wide 64-CPU count.
- **Persistent CI telemetry.** Each runner owns
  `D:\ci\test-runs\yuzu-weetam-windows-N\test-runs.db`. Provisioning initializes
  all four databases; the pin wrapper exports the matching path as
  `YUZU_TEST_DB`, and `ci.yml` records every Windows MSVC job, Meson suite
  duration/timeout and recovered known flake. The files sit outside the checkout
  and are never shared between agents, so history survives branch/build cleanup
  without adding SQLite writer contention between CCDs.
- **Defender CI exclusions.** Provisioning preserves Wee Tam's four exact runner
  work-root exclusions (`D:\ci\work-0` … `work-3`), which cover each runner's
  `_temp` directory and checkout/build outputs. PostgreSQL's executable and
  disposable data paths are also excluded, as are the Catch2 test binaries
  (`yuzu_{server,agent,tar}_tests.exe`) via process exclusions — a process
  exclusion skips scanning that binary's file I/O wherever it lands, which covers
  the SQLite temp churn even in the LOCAL SYSTEM `%TEMP%` the routing can't reach.
  Provisioning verifies every `_temp`
  path with Defender's own `MpCmdRun.exe -CheckExclusion`. It deliberately does
  not exempt the whole of user/system `%TEMP%` or `D:\ci` — only the scoped
  `C:\Windows\Temp\yuzu*` wildcard, for tests that run in a LOCAL SYSTEM context
  (`yuzu_test_kv_SYSTEM`, guardian, …) whose `TEMP` the per-runner `_temp`
  routing below cannot reach. The pin wrapper routes native `TEMP`/`TMP` and
  MSYS2 `TMPDIR` into that runner's own `_temp`; the CI telemetry start step
  repeats those exports so the fix applies before the next planned runner
  restart too. A daily `Yuzu-CI-Temp-Sweep` scheduled task purges
  `C:\Windows\Temp\yuzu*` entries older than 1 day so the SYSTEM-context leak
  cannot re-bloat the NTFS directory index.

## `toolchain-manifest.json`

Emitted by provisioning or the drained-host manifest-only migration (default
`C:\actions-runner\toolchain-manifest.json`),
verified by `Assert-Toolchain.ps1`:

```json
{
  "schema": "yuzu/windows-toolchain/v1",
  "generated": "2026-06-20T13:00:00Z",
  "host": "WEETAM",
  "runner_count": 4,
  "pins":  { "python": "3.14.6", "meson": "1.11.1", "erlang": "28.4.2",
             "rebar3": "3.24.0", "postgres": "18.4", "windows_sdk": "10.0.26100.0", "build_jobs": 16,
             "vcpkg_baseline": "4b77da7..." },
  "env":   { "VCPKG_ROOT": "C:\\vcpkg", "CCACHE_DIR": "D:\\ci\\ccache",
             "RUNNER_TOOL_CACHE": "D:\\ci\\tool_cache",
             "YUZU_BUILD_JOBS": "16",
             "YUZU_ESCRIPT": "...erts-*\\bin\\escript.exe",
             "YUZU_REBAR3": "C:\\tools\\rebar3\\rebar3",
             "YUZU_TEST_POSTGRES_DSN": "postgresql://yuzu:yuzu@127.0.0.1:5433/yuzu_test" },
  "telemetry": {
    "root": "D:\\ci\\test-runs",
    "databases": ["D:\\ci\\test-runs\\yuzu-weetam-windows-0\\test-runs.db", "..."]
  },
  "postgres_clusters": [
    { "agent": 0, "service": "postgresql-x64-18-yuzu-ci", "port": 5433,
      "bin": "D:\\ci\\pgbin\\agent-0\\bin",
      "pg_ctl": "D:\\ci\\pgbin\\agent-0\\bin\\pg_ctl.exe",
      "postgres": "D:\\ci\\pgbin\\agent-0\\bin\\postgres.exe",
      "psql": "D:\\ci\\pgbin\\agent-0\\bin\\psql.exe",
      "pg_isready": "D:\\ci\\pgbin\\agent-0\\bin\\pg_isready.exe" },
    "..."
  ],
  "tools": [
    { "name": "python", "path": "C:\\Python314\\python.exe", "version": "...", "required": true },
    { "name": "windows_sdk_header", "path": "C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.26100.0\\um\\Windows.h", "version": "10.0.26100.0", "required": true },
    { "name": "windows_sdk_lib", "path": "C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.26100.0\\um\\x64\\kernel32.lib", "version": "10.0.26100.0", "required": true },
    { "name": "windows_sdk_rc", "path": "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.26100.0\\x64\\rc.exe", "version": "10.0.26100.0", "required": true },
    "..."
  ]
}
```

The manifest is host-generated (like a lockfile) and not committed; this README
documents its shape so the self-test and any tooling agree on the contract.
The committed `toolchain-contract.json` is the version-policy source of truth.
The assertion is deliberately package-manager-agnostic: Chocolatey, WinGet,
and reviewed direct installs are all acceptable only when their effective
paths, versions, and live artifacts satisfy this contract. A package manager's
inventory entry is not validation evidence by itself.
`Assert-Toolchain.ps1` rejects a missing or unknown manifest schema outright,
rejects a host pin outside its committed `accepted_host_pins` list, then
executes version probes
for Python, Meson, Erlang OTP, rebar3, and PostgreSQL. The Windows SDK artifact
probes require the reviewed target in every recorded artifact version and path;
the live assertion then requires each recorded file to exist. It also proves the
effective `python`, `meson`, and `git` commands resolve to the recorded host
executables. Every executable probe has a 10-second deadline. A launch error,
timeout, unparseable output, or mismatch is a failure.

vcpkg has a different lifetime: Windows CI checks it out under
`$GITHUB_WORKSPACE\vcpkg`, so the host's `C:\vcpkg` clone is not evidence about
the tool a job executes. The effective baseline therefore lives under
`job_pins`. The retained `pins.vcpkg_baseline` in older and current host
manifests is informational and ignored for job validation. After `lukka/run-vcpkg`,
`Assert-VcpkgCheckout.ps1` checks the effective checkout HEAD, tracked-tree
cleanliness, and that `vcpkg.exe` reports the release tag in the checkout's
tracked `scripts/vcpkg-tool-metadata.txt`. (The executable's own commit is not
the ports repository baseline.) A
baseline PR can consequently validate itself without reprovisioning the host.

Ninja, CMake, Git, ccache, MSVC, and MSYS2 bash are currently observed but
unversioned: the host assertion checks their required paths (and Git's effective
command path), not a reviewed version. Add a pin plus executable probe before
claiming version enforcement for any of them.
