# Contract migration pilots

`tests/contracts/pilots.json` is an initial obligation registry. It names six
contracts, their authority, production/fixture inputs, native selection, oracle,
deliberate defects and coverage limits. It is not a complete ADR inventory.

The BaselineStore pilot cites accepted ADR-0055 by filename and section. Retention,
gateway and plugin cases cite implemented contracts; they do not invent accepted ADRs
for behavior whose precise requirement lives elsewhere. A passing case qualifies
only its recorded obligation, source state, binaries and environment.

## Run

Use an exclusively owned worktree and a dedicated per-OS contract build directory.
Follow `docs/build-guide.md` for dependency provisioning (and `docs/windows-build.md`
for the MSVC environment on Windows). Keep contract options out of the canonical
development build directory: changing them there can silently change later test
selection. Registrations are opt-in for local development; Linux debug CI enables
and captures all six pilots, then retains the portable bundle for 30 days.

```sh
./scripts/setup.sh --builddir build-linux-contracts --tests -- \
  -Dbuild_agent=true -Dserver=enabled -Dbuild_contract_tests=true
# Set YUZU_TEST_POSTGRES_DSN to an isolated disposable PostgreSQL service.
# Never put credentials into the command line or a committed registry.
python3 scripts/test/contract-evidence.py run \
  --build-dir build-linux-contracts --output /tmp/yuzu_test_contract_run_001
```

Running the complete six-contract plan requires Linux: the server and its PostgreSQL tests are
Linux-only under [ADR-0035](../adr/0035-server-is-linux-only-windows-is-agent-only.md).
`build_tests=true`, `build_agent=true`, `server=enabled` and the gateway toolchain
are required. Missing registration is an error, not a smaller successful plan.
`--only ID` (repeatable) selects a declared subset; the manifest records it.
`--jobs N` is the native build's parallelism (`meson compile -j`) and defaults to four; the
contracts themselves always run one at a time. `--build-timeout SECONDS` bounds the native build
step; it defaults to `YUZU_CONTRACT_BUILD_TIMEOUT_S`, else 1800 (CI sets 3600, because a runner's
first build of the contract build directory is cold). CI compiles the pilots' targets at the leg's
full width before it runs the collector, so the collector's own build finds nothing to do; see
`docs/ci-architecture.md` "Contract migration evidence".

On macOS or Windows (MSYS2 bash), select the four plugin/gateway contracts
explicitly and leave the server disabled:

```sh
contract_build=build-macos-contracts  # Use build-windows-contracts on Windows.
./scripts/setup.sh --builddir "$contract_build" --tests -- \
  -Dbuild_agent=true -Dserver=disabled -Dbuild_contract_tests=true
python3 scripts/test/contract-evidence.py run \
  --build-dir "$contract_build" --output /tmp/yuzu_test_contract_subset_001 \
  --only plugin.loader.reserved-name.reject \
  --only plugin.loader.duplicate-name.isolate \
  --only GW-HB-RETRY-001 \
  --only GW-REGISTRY-OWNER-DOWN-001
```

Use the provisioned native `python` interpreter in place of `python3` on Windows.
This subset supplies no PostgreSQL contract evidence.

The collector builds the listed native targets and runs their named Meson tests.
Meson invokes the Catch2 adapter or the gateway wrapper. The gateway compiles
into a fresh per-run `private/gateway-build`, then invokes the exact EUnit
generator in a fresh VM using the repository's pinned OTP resolver. This is
process-state isolation; deleting a shared `_build` is unnecessary.

The collector's build-directory lease excludes another collector, not arbitrary
`ninja`, Meson or rebar commands. Coordinate ownership before running. It does not
start PostgreSQL or other services. Live stack validation remains the separate
`scripts/integration-test.sh --tls --free-ports --gateway-ct` workflow described in
`integration-tests.md`; a mocked-RPC lifecycle case does not replace that test.

On POSIX, cancellation asks Meson to terminate all tests; the adapters translate
its termination signal into cleanup of their owned native children. The collector
allows five seconds for that shutdown before forcing the runner to stop, with a
bounded reap. If Meson cannot service termination, diagnostics mark descendant
cleanup unconfirmed: force-killing the runner alone cannot prove that separately
sessioned children are gone. Further interrupts do not bypass cleanup already
in progress.

Direct Meson use is also possible:

```sh
# REBAR_BASE_DIR must name a separate caller-owned gateway build directory.
meson test -C build-linux-contracts --suite contracts --print-errorlogs
```

The PostgreSQL contracts require their DSN, plugin contracts require their
compiled fixtures from the selected build, and the gateway wrapper requires an
isolated `REBAR_BASE_DIR`. Direct Meson results do not include the collector's
source/history bundle. For normal development without these prerequisites, leave
`build_contract_tests=false`.

Both gateway contract entries use `is_parallel: false`: direct Meson runs must
serialize their rebar compiles into the caller's shared isolated build directory.

## What qualifies as success

- The exact planned Meson entries must exist, execute once and report `OK`.
  Their command bindings must match the registry, not just their display names.
- Catch2 must report the registered case, matching filter, at least one successful
  assertion and no failures, expected failures or skips. Exit zero alone is
  insufficient. EUnit must complete exactly one case without cancellation.
- Native evidence must match the contract identity. Source and native binaries
  must remain unchanged during the capture. The gateway records and verifies its
  compiled BEAM hashes and actual loaded test-module path.
- Evidence and history writes must succeed. Build, setup, timeout, cancellation,
  missing report and source-drift errors cannot become a passing contract.

Counts are separate: Catch2's XML case summary and assertion summary measure
different things. Its JUnit `tests` attribute can count assertions. Polling and
randomized tests can change assertion totals without changing coverage. No
percentage of assertions passed is a percentage of architectural correctness.

## Evidence and history

Every invocation requires a **new output directory** and receives a unique run
ID. Reusing an output directory fails before overwriting anything. The manifest
contains the selected obligations, source commit and whole working-tree diff hash,
registered input snapshots/hashes, compiler/build configuration, binary hashes,
exact commands, native results, prerequisite presence and artifact hashes.
`source.patch` captures only the registered inputs; its separate hash and scope
are recorded explicitly. Unrelated tracked edits affect the whole-tree identity
but their contents are not copied. Untracked files are not represented by a Git
diff; registered inputs are independently copied and hashed. Per-case
Catch2 XML or EUnit logs remain alongside portable Meson JSON/text/JUnit reports.
Meson includes inherited environment values in its native reports: originals
stay under `private/meson-raw`, with hashes in the manifest. Portable copies omit
environment values and redact known credential values from output and commands;
the readable text report is rendered from that sanitized JSON.

The collector writes a `RUNNING` observation before work and terminal results to
the existing `scripts/test/test_db.py` schema. Missing planned executions become
`ABORTED`; a native pass does not override an aborted evidence qualification.
An interrupted process can leave a visible `RUNNING` capture. Each retry gets a
new run ID and output directory, preserving the first failure.

By default, `test-runs.db` lives in the capture. `--history-db PATH` appends to an
existing durable local/runner database. This is a manual contract run, not a
claim to have completed `/test --full`. Native timings and case counts retain
their units; unexecuted cases have no measured duration.

Create a portable bundle after either success or failure:

```sh
python3 scripts/test/contract-evidence.py bundle \
  /tmp/yuzu_test_contract_run_001 /tmp/yuzu_test_contract_run_001.zip
```

Bundling verifies every recorded artifact hash, refuses overwrite, and creates a
private archive containing only the sanitized Meson reports and result metadata.
The exported manifest lists hashes of the omitted artifacts and the original
manifest, so a portable projection cannot masquerade as a complete raw capture.
Raw native logs/reports, source snapshots/patches, command arguments, free-text
errors, build configuration and history databases remain in the private local
capture. They are excluded because they may contain credentials or application
data, even when the Meson reports have been sanitized. The bundle preserves
statuses, timings, selectors and source/binary hashes; use the retained local
capture for full reproduction and raw failure diagnostics.

Credential redaction in the portable Meson reports covers known sensitive
environment values, not arbitrary application secrets. Review even a portable
bundle before exporting. Retain raw captures separately in an access-controlled
durable artifact store when they are needed beyond CI's 30-day portable-bundle
retention. A temporary local path alone is not retention.

## Migrate the next test

1. Choose one actual obligation and record its full authority filename/section.
   Separate accepted ADRs, implemented contracts and proposals.
2. Drive a production entry point. Witness that the intended fault/branch was
   reached; observe exact durable effects and forbidden effects after completion.
   Include a valid positive control and recovery after the fault is removed.
3. Demonstrate sensitivity with an isolated faulty copy or a baseline failure.
   Keep exact mutations, source hashes, commands and raw failures. Do not mutate
   the shared production build, and do not count mutant failures as product bugs.
4. Register the native selector and required build targets. Run the owning suite
   as well as the contract. Retire the old case only after accounting for its
   useful observations; the six contracts replace weak cases in existing modules.

The second batch covers retention cutoff boundaries across midnight, registry
owner-death cleanup, and plugin duplicate-name isolation. The retention case uses
the helper's existing SQL clock-expression parameter; live-clock and consumer
wiring remain separate observations. The registry case reads actual ETS rows
because lookup independently filters dead PIDs; it preserves a live peer and
registers a replacement. Existing session-cap tests already cover slot release.
The duplicate-name case includes a distinct working plugin so rejecting every
candidate after the first cannot satisfy the contract.

On failure, start with `manifest.json`, then `build.log`, `meson.log` and the
per-contract native report. Distinguish prerequisites, assertion failure, timeout,
teardown and recording failure. Reproduce the recorded filter/generator and seed
against the recorded source and build. Preserve the first attempt before retrying.

Current limits: each native result qualifies only its recorded source and
platform. Linux runs the complete plan; macOS/Windows can qualify the four
plugin/gateway contracts, never the Linux-only server contracts. Historical
qualification does not qualify later commits. The registry does not yet cover
all ADRs, all stores, all gateway lifecycle boundaries or all plugin names. It
does not establish performance, coverage or flake-rate baselines, and Dialyzer's
production success typing is not runtime protocol proof.
