# CI architecture — runner topology, vcpkg cache, persistence

Reference for Yuzu's three-tier CI architecture (April 2026 overhaul).
CLAUDE.md keeps the headline tier breakdown + runner topology; this document
holds the cache-key contract, persistence rules, and operational knobs that
the `build-ci` agent loads on workflow / vcpkg / scripts/ci changes.

Plan of record: `/home/dornbrn/.claude/plans/our-ci-has-been-piped-castle.md`.
Failure-mode runbook: `docs/ci-troubleshooting.md`.

## Tier summary (mirrors CLAUDE.md)

- **Tier 1 — PR fast-path** (`ci.yml` on `pull_request`): one Linux variant
  (gcc-15 debug on the `yuzu-bigtam-linux` pool), one Windows variant (MSVC debug on
  the `yuzu-weetam-windows` pool), one macOS variant (appleclang debug on the
  `yuzu-bigmags-macos` pool), plus `proto-compat`. Wall target: <10 min per leg.
- **Tier 2 — push to dev/main** (`ci.yml` on push): full 4-way Linux matrix
  (gcc-15 / clang-21 × debug / release), 2-way Windows, 2-way macOS. **No
  sanitizers, no coverage** — those moved out (#410). **Since #3443 Phase 2**,
  the Linux matrix's `pg_mode` key (via `include:`, never a third axis) means
  only ONE leg (gcc-15/debug) runs the full 11-shard `server-pg` suite on a
  push; the other three legs run a small `[pg-smoke]`-tagged subset instead —
  see "PG push-leg policy" below. PR coverage is unaffected (the PR `exclude:`
  already trims the matrix to gcc-15/debug alone, which always resolves to
  `pg_mode: full`). **Since the Windows CI test-phase-split PR (#3443,
  2026-08-28)**, the Windows matrix carries the identical `pg_mode` key via
  the same `include:` mechanism (debug=full, release=smoke) — Windows and
  Linux now share one `pg_mode` concept, not two independently-invented ones.
- **Tier 3 — nightly cron** (`nightly.yml`, `0 6 * * *` UTC +
  `workflow_dispatch`): ASan+UBSan, TSan, coverage on the Big Tam pool
  (`yuzu-bigtam-linux`, gated on `bigtam_pool_healthy`), plus a Windows ASan
  leg (`windows-asan`, agent-only, Wee Tam pool, gated on
  `weetam_pool_healthy`) covering the Windows-only spark mechanisms that the
  Linux sanitizers can't reach (#1934a). On any leg failure, the `alert` job auto-opens or comments on a
  `nightly-broken` issue. **Discipline norm: no merge to main while a
  `nightly-broken` issue is open.**

  **Scheduled nightlies always run the DEFAULT branch's copy of the workflow**
  (currently `main`) — `dev` gets zero nightly ASan/TSan/coverage coverage
  outside a manual `workflow_dispatch` (#4018). `workflow_dispatch.inputs.jobs`
  (choice `all`/`windows-asan`, default `all`) exists so a `windows-asan`-only
  recurrence check can be dispatched against `dev` without paying for the full
  Big Tam matrix each time: it skips `sanitize-asan`/`sanitize-tsan`/`coverage`
  and — so a diagnostic dev-branch dispatch never touches the shared
  `nightly-broken` discipline gate — also skips `alert`/`close-on-green`. A
  plain `jobs=all` dispatch (or the omitted-input schedule trigger) is
  unaffected and runs exactly as before.

  The TSan leg preloads `$RUNNER_TEMP/libgai_sync_shim.so` to replace glibc's
  `getaddrinfo_a()` async DNS path with synchronous `getaddrinfo()` on the
  calling thread. Required because cpp-httplib enables
  `CPPHTTPLIB_USE_NON_BLOCKING_GETADDRINFO=ON` by default (vcpkg port), which
  makes glibc spawn an async-DNS helper thread via `clone3` directly —
  bypassing TSan's `pthread_create` interceptor — so the helper's per-thread
  allocator state is never initialised and the first `malloc()` from it
  segfaults inside `__tsan::SizeClassAllocator64LocalCache::Allocate
  (this=0x8)` (#438). Scoped to the TSan job via step-level `env: LD_PRELOAD`;
  production keeps the non-blocking-DNS behaviour. The shim is built by
  `scripts/ci/build-gai-sync-shim.sh` — a **single** script shared by both this
  workflow and `sanitizer-tests.yml` so the two can't drift (#1038 CS-03); it
  compiles with `gcc-15 -Werror` and `_Static_assert`s glibc's private
  `struct gaicb` layout (`ar_result`=24, `__return`=32, `sizeof`=56), so an ABI
  reshuffle fails the build loudly instead of silently corrupting adjacent
  memory. Built into `$RUNNER_TEMP`, not a fixed `/tmp` path, because Big Tam
  runs 4 runner agents under one OS identity and a fixed path is a cross-job
  collision class (#1038 R-15).

  libpq's own connect-time write-write race on its `static_std_strings`/
  `static_client_encoding` globals (`pqSaveParameterStatus`) is suppressed by
  a compiled-in `__tsan_default_suppressions` hook in
  `tests/unit/test_runner_main.cpp`, kept honest by the
  `tests/test_no_connless_pq_escape.py` tripwire (#1611).

  On Test **failure or job cancellation**, the TSan job's `Capture stack trace
  under gdb` diagnostic (`scripts/ci/tsan-gdb-capture.py`) derives **every**
  failing test binary from the meson junit, maps each to its binary+args via
  `meson introspect`, and replays each under `gdb -batch` with its own Catch2
  seed and shard filter, dumping `thread apply all bt full` + `info registers`
  into `build-linux-tsan/stack-capture.log`, which rides the `meson-testlog-tsan`
  artifact (uploaded on `failure() || cancelled()`). The cancelled path is the
  60-min-timeout **hang** case: it infers the unfinished entries and
  SIGINT-interrupts gdb for a live backtrace. Best-effort — it always exits 0
  and never changes pass/fail. **Guard note (#1038):** the step's `if:` must keep
  an explicit `failure() || cancelled()`; a bare `steps.test.outcome ==
  'failure'` gets an implicit `success()` ANDed on and is unreachable — that
  defect silently skipped this step on every red nightly from 2026-05-15 to
  2026-07-14.

`workflow_dispatch` only works once a workflow file exists on the **default
branch (`main`)**; the run then uses the workflow definition at whatever
`--ref` it is dispatched on, which must also carry the file. Cron schedules
likewise need `main`. New workflows added on `dev` are dormant until merged.

### Trusted fork pull-request CI

Automatic `pull_request` runs from forks are deliberately fail-closed. They
must never emit healthy self-hosted runner outputs, because fork code is not
trusted to execute on Big Tam or Wee Tam. The ordinary preflight fails red
when it detects a fork; it does not bypass runner control.

After static review, a maintainer may approve one immutable fork revision. Both
fork workflows execute fork code, and a `workflow_dispatch` run's GitHub
Actions cache scope is the ref it was dispatched on — so they are never
dispatched on `main` or `dev`. Cut a throwaway quarantine branch from the PR's
base (normally `origin/dev`), named for the PR; `ci.yml`'s `trusted_inputs`
step and the review workflow both refuse any other ref (#4471). First run the
hosted review workflow and wait for it to pass:

```bash
git push origin origin/dev:refs/heads/trusted-fork/pr-123
gh workflow run fork-dynamic-review.yml --ref trusted-fork/pr-123 \
  -f pr_number=123 -f head_sha=<40-character-head-sha>
gh run list --workflow=fork-dynamic-review.yml --limit 5
```

Then dispatch the trusted gate on the same branch using that exact SHA and
successful review run, and delete the branch once both runs have finished:

```bash
gh workflow run trusted-fork-ci.yml --ref trusted-fork/pr-123 \
  -f pr_number=123 \
  -f head_sha=<40-character-head-sha> \
  -f review_run_id=<successful-review-run-id>
git push origin --delete trusted-fork/pr-123   # housekeeping; the wrapper already purged the scope
```

The wrapper requires the PR to remain open, verifies that its current head is
the supplied SHA, requires the hosted review run to match the same PR and SHA,
and invokes the reusable `ci.yml` matrix. The reusable workflow also requires
the repository-only `TRUSTED_FORK_CI_GATE` secret, so a fork cannot call it
directly. The wrapper passes only that sentinel and `RUNNER_INVENTORY_TOKEN`;
the PAT is consumed by a hosted, base-workflow-revision runner-control step
before the approved fork revision is checked out. Trusted self-hosted jobs
start from a clean workspace, use run-private ccache/test state, disable vcpkg
binary sources, and purge the workspace afterwards. They never read or write
the normal `runner.tool_cache` caches.

The GitHub Actions cache is confined the same way. A run restores only from its
own ref, the default branch, and a PR's base, so nothing written in
`trusted-fork/pr-123`'s scope is reachable from `main`, `dev`, or any PR — and
because any code executing in a run can write that run's scope, no in-workflow
save gate could have closed this on its own (the canary's
`trusted_execution != 'true'` gates are defence in depth behind it). The
wrapper's final `purge-quarantine-cache` job then deletes every entry in that
scope; `fork-dynamic-review.yml` carries an identical job that purges its own
scope right after the hosted review finishes, so no window exists in which the
review run's (at that point unapproved) writes are restorable by the gate's
canary leg on the same ref. Deleting the branch does not purge caches by
itself — unread entries would otherwise linger for seven days. Cutting the
branch from the PR's base also means the run uses that
base's `ci.yml` rather than `main`'s. Two operational consequences: trusted
dispatches for DIFFERENT PRs no longer share `ci.yml`'s own concurrency group
(each resolves a distinct `github.ref`), so they run in parallel rather than
queuing behind an unrelated PR's build — `trusted-fork-ci.yml`'s own
`concurrency:` group still serialises two dispatches for the SAME PR, so a
re-approval waits for the run already in flight rather than racing it; and the
trusted canary reads only its own (empty) scope plus `main`, so it is a cold
build. This deliberate approval
therefore executes the full PR gate without turning a reviewed fork into a
cache-publisher or exposing the administration-scoped PAT to fork-controlled
code.

## Gates outside the tier ladder

### Plugin spawn lexical gate (`plugin-spawn-gate.yml`, ADR-3002 decision 10a)

A per-PR grep over `agents/plugins/*` and `agents/core` for a raw
process-spawn token (the `fork`/`exec` family, `system`, `popen`,
`CreateProcess` family, ...) outside the registered allowlist —
`scripts/ci/check-plugin-spawn-lexical.sh` carries the full
token/allowlist contract in its own header. It is tier (a) of a
two-tier enforcement scheme; a scheduled, call-identity-aware CodeQL
query is tier (b), the deep net for what a lexical scan can't see. See
`docs/adr/3002-acquisition-ladder.md:459-488` for why neither tier
alone is sufficient.

It runs as its **own workflow**, not folded into `ci.yml`: a source
grep needs no build, so it doesn't share `ci.yml`'s build-dependent
PR fast-path or `changes`-job path filtering — there is nothing
expensive to skip, so the workflow simply always runs on every PR and
push to `main`/`dev`. A failing lexical scan is a **merge-blocking**
required check; remediation is either moving the call into the
registered allowlist (if it is a legitimate, reviewed acquisition
path) or removing the raw spawn in favour of the sanctioned subprocess
runner.

### Plugin README gates (`docs` suite + `docs-lint.yml`, `docs/plugin-readme-standard.md`)

Two gates keep each plugin's `agents/plugins/<name>/README.md` honest. The
meson `docs` suite runs `tests/test_plugin_readmes.py` on every leg: the
README-existence ratchet (the count of plugin directories without a README
may only fall), the section contract, and a byte-diff of every generated
artefact — the README fences, the user-manual plugin index,
`site/src/nav.plugins.mjs` and the `content/plugin-docs/*.json` manifests —
against what `tools/plugin-doc-gen` produces from the committed sources
(the same contract `check-capability-matrix.sh` enforces for the
capability matrix, and it needs no build). A stale sample leg-hash fails
it too; regenerate with `python3 tools/plugin-doc-gen/plugin_doc_gen.py
--all`. The `plugin-readme-touch-rule` job in `docs-lint.yml` (pull
requests only, not a required check today) runs
`scripts/ci/check-plugin-readme-touch.sh`: a change under
`agents/plugins/<name>/src/**` must also touch that README, or the PR body
must carry a visible `docs-unchanged: <section> — <reason>` line, which
the job prints. Both scripts carry a fixture self-test that the `docs`
suite also runs.

### ClusterFuzzLite (`cflite-pr.yml` + `cflite-batch.yml`)

PR-scoped libFuzzer fuzzing of the untrusted-input parsers (target
inventory: `.clusterfuzzlite/README.md`). Not a required status check, and
deliberately path-gated to the fuzzed compile closure — six parser families
under `server/core/src/` plus `tests/fuzz/` and `.clusterfuzzlite/` — so
"why did the fuzz check not run on my PR" is almost always "the PR touches
nothing a harness compiles". The two workflows share one paths list;
KEEP-IN-SYNC banners in both plus `.clusterfuzzlite/build.sh` bind them.
One known hole, deliberately accepted: event-level `paths:` evaluation
inspects a bounded diff window (the #1978 limitation that moved `ci.yml`
onto `detect-code-change.sh`), so a very large PR touching a fuzzed file
can skip both legs; adopting the detect-code-change pattern here is
tracked on #3771.

`cflite-batch.yml` (push-to-dev on those paths; manual dispatch once the
file is on `main` — until then push-to-dev is its only live trigger) grows
the corpus and publishes the coverage report the PR job uses for
affected-target pruning. State is GHA artifacts on 90-day retention and
self-heals: if it expires or a download fails, PR runs degrade OPEN to
seed corpora + keep-all pruning (slower, never a false green skip on that
fully-expired path). Short of expiry, `cflite-pr.yml`'s "Check
coverage-artifact age" step (#3770) guards the remaining gap — a
stale-but-unexpired `cifuzz-coverage-latest` older than 30 days (3x the
~10-day measured refresh cadence) is treated as untrustworthy and the job
forces `keep-unaffected-fuzz-targets: true` instead of letting build_fuzzers
prune against it, logging which branch it took as a `::notice::`. A
fresh-timestamp, stale-content artifact (e.g. from a main-ref dispatch)
would still slip this age check, but `cflite-batch.yml`'s dev ref-guards
close the known producer of that case. The next healthy batch run regrows
both the corpus and a fresh coverage report.
Expiry-by-inactivity files no issue — only a RED run alerts, so a long
quiet period degrades silently. `prune` is dispatch-only — it replaces the
corpus wholesale, so it never runs unattended. A red batch run auto-files
a `cflite-batch-broken` issue (the `nightly-broken` pattern, minus the
merge discipline — it is a repair prompt, not a gate); while it is open,
coverage staleness silently degrades PR-time pruning **within** the 30-day
window the age gate above doesn't cover, so treat it as same-week work.

### Capability matrix drift gate (`check-capability-matrix.sh`, #2204)

Runs on every Linux CI leg immediately after `Build`, once
`capmatrix-gen` and every `agents/plugins/*/` shared object already
exist. The script discovers the full plugin set from the source tree
itself — not a hand-maintained subset — so a missing capability-matrix
artifact for **any** plugin is a hard failure, never a silent skip,
and a stale generated block in `docs/os-capability-matrix.md` fails
the same way. It currently runs in **ratchet mode only**: the
undeclared-plugin count must not grow PR-over-PR; it does not yet
hard-fail on any plugin being undeclared (that is a later PR). A
companion step, `tests/shell/test_capability_matrix_gate.sh` (#2204
finding F10), exercises both the "renders a DECLARED descriptor" path
and both ratchet-rejection branches against the real built binary and
the real gate script, using the `tests/fixtures/abi4/` declaring
fixture plugin inside throwaway git repos — it also runs right after
`Build` for the same reason (needs the built artifacts), not on the
preflight shell-gate step.

Both steps are **merge-blocking** required checks. A red
capability-matrix gate on a fork or source build is remediated by
running `capmatrix-gen` against the local build and committing the
refreshed generated block between the `<!-- BEGIN GENERATED -->` /
`<!-- END GENERATED -->` markers in `docs/os-capability-matrix.md`, or
by declaring the newly undeclared plugin(s) so the ratchet count stops
growing — `check-capability-matrix.sh`'s own header spells out the
three drifts it catches and the ratchet-baseline mechanics.

### Pin-displacement claim gate (`pin-displacement-claim-gate.yml`, #2740)

A per-PR check asserting that every surface stating what CAUSES an MCP replay-ring pin
displacement agrees on the cause set. `scripts/ci/check-pin-displacement-claim-set.sh`
carries the invariant and its derivation pointer; the surfaces are one array in that
script, and every check that iterates surfaces (all but the alert-expr check, which is
alert-specific by construction) derives from it.

It exists because that claim lives as an independent paraphrase in seven files, #2740
falsified it, and successive review passes each fixed a different subset — a convention
did not hold. It checks the machine-comparable part (which counters each surface names as
a cause) and deliberately NOT the derivation prose, which is where the parked lexical-gate
approach walls.

Three properties worth knowing before editing it:

- **It self-tests first.** The workflow runs `--selftest` (fixture cases proving each
  defect shape reddens) before the real check, on the `plugin-spawn-gate.yml` precedent —
  a gate nobody has watched fail is an assertion, not a check. Several of those cases exist
  because a review proved the gate was false-green for surfaces its own header claimed to
  protect, or false-green on a stale claim masked by a sibling occurrence; add a case
  whenever you add a surface. Its case count is not restated here - run it.
- **Add surfaces to `STATING_SURFACES`, not to a loop.** The two holes review found were
  both a divergence between two hand-maintained lists. There is now one.
- **The cause-set check is region-scoped, not whole-file (#2827).** On four surfaces a
  counter identifier legitimately occurs more than once (a metrics registration, a
  pre-seed, a sibling alert rule, a sibling table row), so a whole-file presence grep let a
  stale claim hide behind an unrelated sibling occurrence and stayed green on exactly the
  drift the gate exists to catch. `claim_region()` in the script extracts each surface's
  own bounded claim text and tests membership only there; a surface with no
  `claim_region()` arm, or whose anchor is missing or ambiguous, is reported as DRIFT
  rather than silently skipped. A narrower, best-effort fourth check catches a claim
  restated on an unregistered line elsewhere in a surface.
- **Two region-boundary shapes, chosen per surface, not one.** ALERTS/HELP/RUNBOOK/HOME_HDR
  scan multiple lines to a terminator anchored in syntax external to this gate (YAML
  alerting-rule structure, a C++ string literal, a markdown table's leading `|`, a Doxygen
  `///` prefix) — each fails DRIFT if the terminator is lost, or if the scan runs past
  `MAX_REGION_LINES` without ever confirming one. MANUAL/MCP_SERVER_DOC/ADR_DOC are
  single-line captures instead: their real claims have always been one physical line, and
  two rounds of governance review each defeated a broadened multi-line stop pattern with a
  different plausible reformat the prior round hadn't anticipated (a bare-emphasis-style
  sibling, then a lettered/decimal/em-dash sibling) — see the `claim_region()` ADR_DOC arm's
  comment for the fuller history. Single-line capture sidesteps guessing at prose format
  entirely rather than trying to broaden the pattern a third time.

A failing check is **merge-blocking** — the job exits non-zero and the workflow has no
`continue-on-error`. No build, no `paths:` filter (nothing expensive to skip, and no filter
means it always reports — see the trap noted for `docker-healthcheck-invariants.yml`
below).

### Docker healthcheck invariants (`docker-healthcheck-invariants.yml`, #751)

The five Yuzu **application** images' compose healthchecks depend on a tool baked
into the image, not on the application: **bash + `/dev/tcp` + `grep`** for
`yuzu-server`, **busybox `wget --spider`** for `yuzu-gateway`, and
**`/bin/busybox`** (by absolute path) for the three FROM-scratch chisel images.
Nothing else exercises those tools. A base-image swap, a dropped apt package, or a
chisel slice change that stops shipping the busybox symlink breaks nothing at
build time and nothing at boot — it breaks only the healthcheck, so Compose parks
every container `unhealthy` forever and anything with `depends_on: condition:
service_healthy` never starts, with no application failure to point at.

`yuzu-postgres` is published and healthchecked too (`pg_isready` + `psql`), but it
is `FROM postgres:*` — those tools are the image's whole purpose — so it has no
role in the gate and `docker-publish-postgres` has no pre-push check. `agent-chisel`
is gated **pre-emptively**: no compose healthchecks an agent image today.

The probes are a hard-coded copy of the healthcheck commands, so both the script
and the workflow's change-filter carry a **KEEP IN SYNC** list of every file that
defines one — including the two easy-to-miss ones,
`scripts/test/docker-compose.upgrade-test.yml` and the compose heredocs inlined in
`pre-release.yml`.

`scripts/ci/verify-healthcheck-invariants.sh` is the gate. It runs each image's
real healthcheck probe **against a live HTTP listener** in a shared network
namespace, so exit 0 is the only passing outcome. Probing a *closed* port cannot
distinguish a working bash from a bash built without net redirections — both
return 1 — which is why the naive "accept 0 or 1" check that #751 originally
proposed passes a broken image (verified against a bash compiled
`--disable-net-redirections`).

**Placement — it runs in two places, sharing one script:**

| Where | When | Why |
|---|---|---|
| `docker-healthcheck-invariants.yml` | PRs + pushes to `dev`/`main` | Catches a base-image swap in the PR that introduces it, not weeks later at release. |
| `release.yml` (`docker-publish`, `docker-publish-chisel`) | Between image build and registry push | A broken image is never published. Verifying after the push would leave a broken tag in GHCR. |

It is deliberately **not** in `ci.yml`: the Tier-1 fast path must stay under 10
min and these builds are far too heavy. It is equally deliberately **not**
`paths:`-filtered — per #1978, a path-filtered workflow that later becomes a
*required* check never reports on PRs it filters out, so the check sits at
"Expected — waiting for status" forever and a non-admin can never merge. Instead
the workflow always runs and a cheap `changes` job skips the build matrix.

That is necessary but **not sufficient for a matrix job**. Per `actions/runner#952`
a matrix job skipped at the job level is skipped *before* the matrix expands, so it
emits none of its inner check-run names — "skipped" never appears and the required
context hangs anyway. A `required-check-stubs` job (mirroring `ci.yml`'s
`docs-required-checks`) emits the five `Verify <role> healthcheck invariant` names
when the matrix is skipped, and fails red rather than hanging if the classifier
itself dies. **Only with that stub are the five contexts safe to add to branch
protection.**

The PR matrix reuses release.yml's local buildcache **read-only** (`cache-from`
with no `cache-to`), so it never evicts release layers and adds no cache directory
`cache-prune.yml` doesn't know about. Inside `release.yml` the verification build
likewise has no `cache-to`: it shares one buildkitd instance with the push build,
so the push hits BuildKit's own solver cache and rebuilds nothing.

## Self-hosted runner topology

| Runner | Host | Jobs |
|---|---|---|
| `yuzu-bigtam-linux-{0..3}` | Big Tam Threadripper 9970X, native Ubuntu **26.04** (gcc-15/clang-21) — 4 L3/CCD-pinned runners (`0-7,32-39`; `8-15,40-47`; `16-23,48-55`; `24-31,56-63`), Ninja capped at `-j16` | **all self-hosted Linux** (shared label `yuzu-bigtam-linux`): ci.yml `linux` matrix, `proto-compat`, sanitizer-tests (asan/tsan), nightly (asan/tsan/coverage), codeql Linux leg, **release.yml** (build-linux, build-gateway, docker-publish\*), cache-prune-linux. 4 runners on one host. Provisioned from [`deploy/linux/`](../deploy/linux/README.md). |
| `yuzu-weetam-windows-{0..3}` | Wee Tam 9970X native Windows 11 — 4 CCD-pinned runners, shared label `yuzu-weetam-windows` | **all self-hosted Windows**: ci.yml `windows`, nightly `windows-asan`, codeql Windows leg, release `build-windows`, instructions-windows-validate, cache-prune-windows. Provisioned from [`deploy/windows/`](../deploy/windows/README.md). |
| `yuzu-bigmags-macos-{0,1}` | BigMags Mac Mini (Apple M4 Pro, 24 GiB, macOS 26) — 2 runners as headless LaunchDaemons, shared label `yuzu-bigmags-macos` | **self-hosted macOS**: ci.yml `macos` matrix + `release.yml` build-macos. Only pre-release `install-macos` stays GitHub-hosted (`macos-14`, an install-to-root smoke test). Release **signing/notarization is deferred** — macOS releases currently ship UNSIGNED (Phase B = on-token `rcodesign`). Provisioned from [`deploy/macos/`](../deploy/macos/README.md). |

**Retired 2026-06-21:** `yuzu-wsl2-linux` (Shulgi WSL2 Ubuntu 24.04, label
`yuzu-shulgi`) and `yuzu-local-windows` (Shulgi native Windows) — superseded by
Big Tam and Wee Tam. Remove them from `.github/runner-inventory.json` to silence
the inventory sentinel. `proto-compat` and `cache-prune-linux` use the bare
`[self-hosted, Linux, X64]` label (no compiler), so they resolve to Big Tam.

### Ubuntu 26.04 migration (Big Tam) — COMPLETE

Big Tam is a native **Ubuntu 26.04 (Resolute)** box, default toolchain **GCC 15 /
Clang 21** (vs Shulgi's 24.04 GCC 13 / Clang 19). **Every self-hosted Linux job
runs on Big Tam**: ci.yml `linux` (#1609), then sanitizer-tests / nightly / codeql
Linux, then release.yml + the remaining Windows→Wee Tam stragglers (#1615). The
supporting scaffolding:

- Native files `meson/native/linux-gcc15.ini` + `linux-clang21.ini` are the live
  toolchain files (they also set `-fuse-ld=mold`; see Build speed below). The
  24.04 `linux-gcc13.ini`/`linux-clang19.ini` stay only for the GHA-hosted
  ubuntu-24.04 canary.
- The CI runner image (`Dockerfile.ci-linux`), the local `Dockerfile.ci`, and the
  four sanitizer images (`Dockerfile.{server,agent}-{asan,tsan}`) are on
  `ubuntu:26.04` + gcc-15/clang-21. `gcc-13`/`clang-19` stay installable from the
  archive but are not the defaults.
- `pre-release.yml`'s `install-deb` smoke matrix has an `ubuntu:26.04` leg.

`ImageOS` stays `ubuntu24` on every leg (setup-beam has no `ubuntu26` prebuilt
OTP; the 24.04 OTP runs fine on 26.04 — same `libcrypto.so.3` soname). Big Tam
runs 4 runners on one host, so every apt step is `flock`-serialized on
`/tmp/yuzu-ci-apt.lock`; each runner agent provisions its own persistent
`yuzu-ci-postgres-<n>` container (#2094, `scripts/ci/ensure-postgres.sh`) rather
than sharing one across agents, and meson is installed per-job via
`pip --user` (it is not a host default). Full history + per-file detail:
**`docs/ci-ubuntu-2604-cutover.md`**.

Each Big Tam runner is bounded to one kernel-reported L3 domain via a systemd
drop-in (`CPUAffinity` plus cgroup `AllowedCPUs`) and exports
`YUZU_BUILD_JOBS=16`. Linux's SMT numbering is split: L3 0 is
`0-7,32-39`, not the contiguous Windows `0-15`. CI passes that cap explicitly
to `meson compile -j`; a process affinity mask does not make Ninja's default
processor detection affinity-aware, while `-j16` alone is not an L3 pin. The
versioned source and verification commands are in
[`deploy/linux/`](../deploy/linux/README.md).

### Build speed (Big Tam)

The `runner` user (shared `HOME=/home/runner` across r0–r3) is provisioned once
for fast, download-free builds:

- **ccache** `max_size=50G`, compression on — the host default is 5 GiB, far too
  small for ~700 TUs × variants. ci.yml/nightly cap at 30G via the
  `CCACHE_MAXSIZE` env; release.yml now sets `CCACHE_MAXSIZE=30G` too (it had been
  inheriting the host default).
- **mold** linker (`apt install mold`), wired via `-fuse-ld=mold` in the gcc-15 /
  clang-21 native files — large cut in link time on the big `yuzu-server` /
  `yuzu-agent` binaries and the release LTO link.
- **meson** 1.12.0 + the rest of `requirements-ci.txt` persist in the runner
  user's `~/.local`, so the per-job `pip install --user --require-hashes` is a
  no-op (no re-download).
- **rpm** (rpmbuild) installed for release.yml's packaging step — absent on a
  fresh 26.04 (it was the first-Big-Tam-release blocker). Note: Big Tam ships RPM
  **6.0** vs Shulgi's 4.x — watch the first release.

The Windows toolchain is codified in [`deploy/windows/`](../deploy/windows/README.md)
(the native-Windows analog of `deploy/docker/Dockerfile.ci-linux`): a versioned
provisioning spec, a manifest, and a runner self-test. All four runners share one
vcpkg binary cache via `RUNNER_TOOL_CACHE=D:\ci\tool_cache` (mirroring
`CCACHE_DIR`), so the CCD split doesn't fragment the cache 4×. The provisioner
also enforces the four exact Defender work-root exclusions (`D:\ci\work-0` …
`work-3`), covering each runner's `_temp` and build outputs without excluding
user/system `%TEMP%` or the whole `D:\ci` tree. The pin wrapper routes native
`TEMP`/`TMP` and MSYS2 `TMPDIR` into the matching per-runner `_temp`; the CI
telemetry start step exports the same values for already-running listeners.

### Windows test-phase concurrency gate

Wee Tam's 4 runners are CCD-pinned, but affinity partitions only **cores** — not
DRAM bandwidth, the disk, or the Defender minifilter. So when several Windows jobs
run their **test** phase at the same time, the heavy unit-test suites
(`server ~[pg]`/`[pg]`, `agent`, `tar`) slow roughly linearly and hit their meson
timeouts: per-runner telemetry (`ci_test_suites`) measured `server ~[pg]` at
c0≈289 s → c2≈467 s → c4≈603 s — a **guaranteed** timeout once ≥4 test phases
overlap, and a 22–25 % timeout rate on the `server ~[pg]`/`tar` suites overall.
`fork()`/VFS/page-cache and no AV minifilter keep Big Tam's (Linux) per-op cost
lower than Wee Tam's — but a prior revision of this section claimed Big Tam
"scales flat" and needed no gate at all, which was never actually true; see
"Linux concurrency caps (within-job + cross-job)" below.

The `c0≈289 s → c2≈467 s → c4≈603 s` figures above predate the #3443 Windows
test-phase restructuring (2026-08-28, below) — they describe the box-wide
concurrency effect on the OLD single combined `Test` step and are not
re-measured here; the restructuring changed the step SHAPE first, at the
UNWIDENED starting values (slot count 2, pg-shards `--num-processes` 2),
before any measurement existed to widen against. The staged measurement
protocol below has since moved the pg-shards `--num-processes` value
through two real widening rounds (k=4, then k=6 — see the Push 2 and
Push 3 paragraphs below for the actual numbers); the slot count (2) has
not moved.

`ci.yml`'s Windows job now splits what used to be one combined `Test` step
into `Test (non-pg suites)`, `Test (pg shards, full)`, and (release/push
only) `Test (pg smoke)` — see "PG coverage by platform" below for the full
shape. Each gated step still wraps the run in
[`scripts/ci/with-test-slot.sh`](../scripts/ci/with-test-slot.sh) — a crash-safe
`flock` gate (a killed job releases its slot via OS fd-close, so a timeout never
leaks a slot) that caps concurrent heavy test phases to **2 per box** (the
**build** phase stays 4-wide). `Test (non-pg suites)` passes `--num-processes 4`
(one consolidated invocation now covers what used to be five separate
suites plus the four non-pg server shards).

`nightly.yml`'s `windows-asan` job now joins this same `with-test-slot.sh 2`
gate and carries `--timeout-multiplier 2` (#4018) — previously it ran
ungated, with no multiplier, on the shared 4-runner Wee Tam box. It shares
the script's default slot namespace with `ci.yml`'s Windows legs above (no
`YUZU_TEST_SLOT_NAME` override on either side), so a nightly run and a
concurrent PR/push genuinely compete for the same 2 slots.

**Staged widening — the decision rule (stated once here; each push's
paragraph below references it, doesn't restate it).** The pg-shards step
widens `2 → 4 → 6 → 8` in separate, individually-measured pushes, never
bundled with a topology change, so a wall-time delta stays attributable
to one axis at a time. At each width: take **≥2 same-SHA samples**
(one sample is noise, not a measurement) and use the median. **Continue**
widening only while (a) the median step wall improves ≥10% over the
previous width, AND (b) no shard's own duration inflates past **1.5x**
its value at the previous width, AND (c) no shard comes within 80% of
its 700s per-shard timeout (≥560s). **If either safety check (b) or (c)
fails, or the improvement check (a) comes back <10%, revert to the
previous width and stop** — a failed safety check is not "try one more
sample," it's "this width is unsafe, back off."

**Push 1** shipped `Test (pg shards, full)` at the unwidened starting
point, `--num-processes 2` — deliberately, rather than guessing ahead of
data. One sample (cold cache, first run of the branch on Wee Tam):
`Test (non-pg suites)` 4m30s, `Test (pg shards, full)` 10m02s (602s) —
the pg step alone was 61% of the 16m32s total job, confirming the plan's
own diagnosis that 11 shards through 2 workers leaves real serialization
on the table. (This baseline is itself only one sample — the huge margin
in every subsequent push's improvement makes that imprecision moot, but
it's not a second-sampled median the way k=4 and later are.)

**Push 2** widened to `--num-processes 4`, two same-SHA samples: 5m59s
(359s) and 5m57s (358s) — a strikingly stable pair (0.4% apart) despite
the *unrelated, untouched* non-pg step swinging 2m42s to 7m55s on the
exact same commit in the exact same two runs. That swing is real
box-contention noise on shared Wee Tam (already named as an unmeasured
risk in this branch's own chaos-injector pass) — it says the pg step's
own stability is real signal, not luck, precisely because the box was
demonstrably NOT quiet during at least one of the two runs. Median:
358.3s, a **40.5% improvement** over k=2 — clears rule (a). Worst-shard
inflation: shard F, 125s → 145s = **1.16x** — clears rule (b) (1.5x cap)
with margin. No shard within 500s of the 700s timeout — clears rule (c).
`Test (non-pg suites)`'s own width (4) had a working precedent for the
"N-wide fan-out inside the 2-slot box-wide gate" shape before push 2 ever
ran; push 2 confirmed the pg step tolerates it too, at least at k=4.

**Push 3** widens to `--num-processes 6` on that basis — genuinely novel
territory, though: unlike k=4, **no CI job anywhere in this repo has run
at `--num-processes 6` before**, so push 3 has no existing-precedent
shortcut the way push 2 did. Wee Tam's per-runner-agent CCD pinning is a
**fixed 16-thread envelope** (`deploy/windows/README.md`,
`YUZU_BUILD_JOBS=16`) — 6 meson-level worker processes is a modest
fraction of that on a raw process-count basis, but neither this doc nor
push 2's data quantifies how many threads or Postgres connections each
`yuzu_server_tests.exe` shard itself spawns, so "headroom" here is
bounded loosely, not measured precisely. The per-shard 1.5x/700s checks
above are the actual empirical safety net for that gap, not this
paragraph's arithmetic. The non-pg step's width (4) and the slot count
(2) are unchanged this round; only the pg-shards width moved. Full
diagnosis: the `tests/meson.build` server-shard comment.

**Push 3, measured:** two samples at k=6 (one on the push-3 commit
itself, one on the `dev`-merge commit that followed it — `git diff
--stat` between the two confirms no changes under `tests/`,
`scripts/ci/`, or `.github/workflows/`, so both samples are effectively
same-SHA for width purposes): 4m29s (269s) and 4m25s (265s). Median:
267s, a **~25.5% improvement** over the k=4 median (358.3s) — clears
rule (a). Worst-shard inflation:
shard I, **~1.11x** its k=4 duration — clears rule (b) with the widest
margin of any width so far (k=2→k=4's worst was shard F at 1.16x). No
shard came within 80% of its 700s timeout (the slowest shard at k=6,
C, runs ~184s median — about a quarter of the cap) — clears rule (c).
Total job wall both samples: 7m54s and 8m02s, down from push 2's
11m48s and 14m37s (push 2's own spread came entirely from the non-pg
step's box-contention noise on an otherwise-stable pg-shards step — see
push 2's paragraph above). This is the current head's width; no push 4
(k=8) has been made. `docs/ci-architecture.md`'s own worst-case job-budget arithmetic
(below, under "Worst-case job-budget arithmetic") and the round-count
math (11 shards over 6 workers is already 2 scheduling rounds —
identical to 11 over 8) are why k=6 is where the staged widening
stopped rather than continuing to k=8; going wider buys no
round-reduction here and only adds CCD-thread-contention risk on Wee
Tam's fixed 16-thread envelope.

### Linux concurrency caps (within-job + cross-job)

Big Tam's 4 runners are also CCD-pinned (16 logical CPUs each, "Self-hosted
runner topology" above), and each runner agent's `Ensure Postgres (server
tests)` step idempotently (re)uses one persistent `yuzu-ci-postgres-<n>`
container scoped to that agent. Two independent contention mechanisms turned
out to be stacked here, not one — fixed in two rounds.

**Within-job (fixed first):** `ci.yml`'s Linux `Test` step invoked
`scripts/ci/flake-retry.py` with no `--num-processes` cap. meson's own default
worker count is an uncapped, non-affinity-aware `cpu_count()` — the job's
execution is genuinely confined to 16 logical CPUs via cgroup, but meson's own
pool sizing ignores that confinement — so it fanned every `test()` entry out
at once: all ~8 server pg shards running concurrently inside a single job,
sharing that job's 16 logical CPUs and its one Postgres container. Proved via
back-computed shard start times (printed-timestamp minus reported elapsed)
landing within ~0.01 s of each other across every pg shard in a failing run —
sequential execution would spread those start times by each shard's own
duration, not cluster them. Solo/uncontended per-shard cost is much lower than
what full contention produces — `tests/meson.build`'s own recorded
measurements run ~50–180 s — the ~600 s figures below are a contention
artifact, not a shard's own baseline.

Each pg shard carries `timeout: 600` as a hard per-test meson kwarg (not the
job-level budget). Shard E hit it dead-on — 600.11–600.60 s, repeatedly —
under this same uncapped fan-out before the 2026-08-19 E→E+G split (#3322).
The fix: `--num-processes 2` on the Linux Test step, mirroring the
already-proven Windows value — chosen over a larger number specifically
because E/G had no measured headroom to spend on a guess.

**Cross-job (fixed second, #3443 AC4):** the within-job fix alone left
cross-job contention explicitly unmeasured at merge time, and it turned out
NOT to be a rare edge case: the post-split E/G pair was still measured at
86–96% of that ceiling across several runs the same week `--num-processes 2`
shipped, and a subsequent push to `dev` timed E out again at exactly 600.01s.
The mechanism: a single push to `dev` launches its own 4-way Linux matrix
(gcc-15/clang-21 × debug/release) **simultaneously**, saturating all 4 Big Tam
runners by itself — so Big Tam was never suffering primarily from OTHER
unrelated jobs the way Wee Tam does, but its OWN push-triggered matrix is
enough on its own. A concurrently-queued PR's Linux job was directly observed
waiting **35 minutes** for a free runner during exactly this window. The fix:
`ci.yml`'s Linux Test step now also wraps in `with-test-slot.sh 2`, the same
box-wide slot gate Wee Tam already used — capping concurrent heavy test
*phases* to 2 per box (the build phase stays 4-wide). Two Linux-specific
settings were required for `YUZU_TEST_SLOT_DIR`/`YUZU_TEST_SLOT_NAME`, where
Windows still uses the script's defaults:
`YUZU_TEST_SLOT_DIR` is set explicitly to a genuinely box-wide
path (`/tmp/yuzu-bigtam-test-slots`, following the same proven pattern as
`/tmp/yuzu-ci-apt.lock` above) because Big Tam's `RUNNER_TOOL_CACHE` is
per-agent, not box-wide like Wee Tam's shared `D:\ci\tool_cache` — the
script's own default would have silently no-op'd, each runner gating against
its own private lock dir and never actually contending with the others.
`YUZU_TEST_SLOT_NAME` is set to keep the two platforms' slot namespaces
distinct in logs. `YUZU_TEST_SLOT_TIMEOUT_MIN=30` is set short relative to
the 90-minute job budget to REDUCE (not guarantee-away) the chance a starved
job hits the ambiguous job-level timeout kill instead of the script's own
attributable error — the 90-minute budget also covers checkout/build time
before Test starts, so a slow build can still leave less than 30 minutes of
headroom when the wait begins. **Since the Windows CI test-phase-split PR
(#3443, 2026-08-28), Windows pins this same `YUZU_TEST_SLOT_TIMEOUT_MIN: "30"`
explicitly too** (on both of its two gated steps, "Test (non-pg suites)" and
"Test (pg shards, full)") — not for the Linux `SLOT_DIR`/`SLOT_NAME` reason
above (`RUNNER_TOOL_CACHE` IS box-wide on Wee Tam already), but because two
slot acquisitions per Windows job at the script's 115-minute default could
together exceed the job's own 120-minute budget — the identical
"ambiguous kill vs. attributable error" reasoning, applied to a different
constraint. This fix gates contention only *inside* a
job that already holds a runner — it does not address a job that cannot
start at all because no runner is free; see "Cross-job — runner
acquisition, a fourth layer" later in this section for that gap.

`nightly.yml`'s Linux ASan/TSan/coverage legs and `sanitizer-tests.yml`'s
ASan/TSan legs (the `/test --full` pre-push gate) invoke `meson test` directly
and carry NEITHER fix — tracked as the remaining open item on #3443. Full
diagnosis: the `tests/meson.build` server-shard comment (shard E/G split
history) + #3443.

**Suite isolation (fixed third, same day):** even with the cross-job gate live
and uncontested — a real run acquired its cross-job slot in 0s, no other job
competing — shards E and G still TIMEOUT'd at 600.51s/600.54s (SIGKILL'd). The
within-job `--num-processes` pool was shared by ALL ~32 registered tests, not
just the 8 pg shards: the Linux Test step ran one `meson test` invocation with
no `--suite`/name filter at all. Fix: split the Test step into 3
`flake-retry.py` invocations, cheap-first (fail-fast via `bash -e`) — 21 tests
across 5 cheap suites (`agent`/`docs`/`proto`/`tar`/`gateway`) run first, then
the 3 non-pg server tests, both uncapped (neither touches Postgres) — status as
of that day; see "Within-job cap extended to the non-pg step" at the end of
this section for what changed; the 8 pg
shards, isolated by exact name into their own `with-test-slot.sh`-gated call,
run last with the pool dedicated entirely to them. 21+3+8 = 32, verified as an
exact partition of the full registered test set before trusting it in CI.

**Root cause, corrected.** The original theory — a cheap test stealing one of
the 2 within-job slots — was superseded during governance re-review: back-
computed start times from the actual failing run show shard E's real
co-runners were shard D (~370s of overlap) then shard G (~230s), plain 2-wide
FIFO over `tests/meson.build`'s declaration order; cheap tests hadn't even
started by the time G timed out. The real mechanism is what this section's own
earlier paragraphs already say — shard cost is a function of concurrent
pg-shard count, and 8 shards at 2-wide inherently pairs some heavy ones for
extended stretches. Isolating cheap tests from the pool is still a real, if
smaller, improvement (it removes an incidental ~51s gap the same
reconstruction found between shards A and H starting), but doesn't by itself
explain or fix E/G's own margin. An earlier version of this fix also raised
`--num-processes` to 3, reasoning the now-pg-only pool had "no competition to
spend margin on" — reverted to 2 without a real run confirming it helped: at
3-wide, FIFO over A,H,B,D,E,G,F,C predicts D, E, and G (three of the heaviest)
running concurrently for a long stretch, plausibly worse than today's 2-wide
pairing. `tests/meson.build`'s own shard-history comment states the house
rule this broke: "raising the number is the last resort, not the first." The
cross-job slot count in `with-test-slot.sh` was ALSO held at 2 at the time
this paragraph was written, for the same reason (box-wide job saturation,
#3443 AC4) — SUPERSEDED 2026-08-25, see "Cross-job slot count: 2 -> 3"
below. `--num-processes` here is unaffected, still 2.

**Two more disclosed tradeoffs from the split, neither affecting job pass/fail
(each invocation gates on its own exit code via `bash -e`):** each invocation
overwrites meson's single `testlog.junit.xml`, so only the pg-gated call's
(last) per-suite telemetry survives the default import — and separately,
`flake-retry.py` writes `meson-logs/flake-retry.json` unconditionally on every
clean invocation, so a clean pg-shard pass can silently overwrite recovered-
flake evidence the cheap-suite calls found earlier. And groups 1/2 now run
entirely outside `with-test-slot.sh` — before this split, one gated invocation
covered all 32 tests; up to 4 concurrent Linux jobs' cheap-suite phases can now
overlap unrestrained. Judged low-risk (cheap suites measured ~1-2 min combined,
no Postgres/heavy-CPU contention), but a real narrowing of what #3443 AC4's
gate covers.

**Split again + timeout bump (2026-08-25, PR #3582).** The isolation fix above
removed cross-job and within-pool contention as variables, but E and G still
TIMEOUT'd — proof arrived via a direct solo diagnostic on Big Tam itself
(`--num-processes 1`, no other job on the box): A=227.86s H=214.19s B=90.35s
D=227.48s **E=353.32s** **G=317.04s** F=262.81s C=359.42s. E and G were each
already past half of the then-600s ceiling completely alone — 2-wide pairing
was never going to have real headroom, regardless of which other shard it
paired with. Both shards' own local-uncontended baselines had also roughly
doubled since their last (2026-08-19) split measurement (E: 180.45s ->
353.32s), only partly explained by case-count growth (E: 329->405 cases,
+23%; G: 278->351, +26%) — the rest is Big Tam's own per-op cost for this
fsync-heavy DDL workload drifting up over the same window, not further
diagnosed.

Fix: `tests/meson.build` split shard E into E+I and shard G into G+J (case-
count-balanced, ~half each; I defers to E and J defers to G the same way G
already deferred to E, to avoid double-counting a case that carries a tag
from both sides of a split — a first attempt without that deferral double-
counted 12 and 47 cases respectively, caught by `--list-tests` before
trusting it), and the four split shards' `timeout:` moved from 600 to 700.
The timeout bump is a **deliberate, temporary** exception to this file's own
"split, don't raise" house rule (`tests/meson.build`'s shard-history comment)
— corrected after Gate 2 governance review (2026-08-25) caught an earlier
draft's justification overclaiming a settled near-term timeline.
`docs/postgres-migration-ladder.md` explicitly disclaims one ("mutable state
that drains over time, not a contract"), and completing that ladder is
architecturally more likely to GROW the `[pg]` population than shrink it:
each store that migrates onto Postgres adds its own `[pg]`-tagged
CRUD/behaviour cases (exactly what shards E/I/G/J already carry), while each
store's narrow, already-thin `migrate_from_sqlite` backfill suite was only
ever prunable once — that pruning has since landed for all 19 already-migrated
stores (#3623, `AuditStore` the last to lose it), so it is no longer a
standing offset against future growth the way it was
when this section was written. The margin bought here is a plain safety
cushion on top of
what the split alone already earns (every new shard's real-diagnostic-scaled
estimate lands well under 700s even 2-wide paired).

**Extended to all ten shards, same day.** Merging PR #3582 required syncing
this branch to `dev`, and dev's own CI (run 32833097478, merging PR #3466 —
no PR-specific pg-shard changes) TIMEOUT'd shard E at 600.51s AND landed
shard G at 585-590/600s (97-98%) on all four Linux legs — live confirmation,
not a projection, that the 600s ceiling was already tight fleet-wide, not
just on the two shards #3582 happened to split. `tests/meson.build`'s
remaining six shards (A/B/D/F/H/C) moved from `timeout: 600` to `timeout:
700` the same way. Revisit on a fixed cadence, not an assumed completion date
— tighten back to 600, or drop, **per shard**, once that shard is comfortably
under budget: TWO reasons to revisit, not just budget hygiene — the
worst-case job-budget arithmetic below, and the #2093 duration watchdog's
80%-of-timeout warning threshold moving with it (480s->560s, now on all ten
shards, diluting the watchdog's lead time fleet-wide rather than on four).
This "revisit later" commitment is tracked at issue #3443 (adversarial
review, 2026-08-25 — a prose-only commitment with no dated/metric-based
trigger has this file's own track record of being forgotten until the next
stale-pin incident forces it; #3443 is the existing linked home for the
pg-shard-reliability lineage, not a fresh one-off). Full measurements,
partition verification, and per-shard local wall time: `tests/meson.build`'s
own comment at the shard E/I/G/J block.

**Worst-case job-budget arithmetic (Gate 6 SRE, 2026-08-25; corrected by
adversarial review, same day; re-derived 2026-08-25 after the timeout bump
extended to all ten shards; re-derived again 2026-08-28 after the Windows
CI test-phase-split PR (#3443) added an 11th pg shard, K, carved from C and
shared with Linux via `tests/meson.build`'s `suite: ['server', 'server-pg']`
mechanism), recorded so a future reviewer doesn't have to re-derive it.**
With all eleven pg shards now sharing one `timeout: 700`, the degenerate
case — every shard hitting its own timeout simultaneously — sums to
11*700s = 7700 test-seconds (up from 7000s at ten shards), and at
`--num-processes 2`, eleven being odd means 6 rounds rather than a clean 5
pairs (the sixth round runs a single shard alone, still bounded by the same
uniform 700s cap), so BEST and WORST achievable makespan are still the SAME
number: 4200s (up from 3500s). Uniform per-shard budgets still remove the
pairing-ORDER variable the earlier (six-at-600/four-at-700) version of this
paragraph had to reason about — there is no longer a lighter/heavier shard
to pair favourably or unfavourably — but they do not remove the ROUND-COUNT
effect of an odd shard total, which is what moved this time, not a pairing
choice. Add the up-to-30-min cross-job slot wait
(`YUZU_TEST_SLOT_TIMEOUT_MIN`) and this ceiling alone now reaches ~100 min
against the 90-min job ceiling, before checkout/build time — the arithmetic
ceiling BY ITSELF now exceeds the job timeout by about 10 minutes, where the
pre-K figure (~88.3 min) still cleared it with under 2 minutes to spare.
This is still the theoretical ceiling, not the expected case (it requires
the box already so unhealthy that all 11 shards hit their own 700s cap at
once, simultaneously, across all 6 sequential rounds — arguably indicating
the box itself needs attention, not a defect in this design), and the
realistic case, using the real measured numbers this PR's own staged
Windows protocol and the original E/I/G/J split were based on, stays
comfortably inside budget on both platforms. But a ceiling that used to
clear the job timeout with a thin positive margin and now formally exceeds
it is a materially different fact than "thin margin," not a rounding
difference — #3443 (already the tracked home for this bump's temporary
status) should treat the shard-K addition as a reason to revisit the 700s
per-shard budget or the Linux `--num-processes 2` cap sooner rather than
later. Neither number is adjusted here without the same measurement
discipline the rest of this PR applies to the Windows widths — this
paragraph exists to make the new fact visible to the next reviewer, not to
resolve it unilaterally.

**Drift risk — automated (#3443 Phase 1, 2026-08-26):** this used to hardcode
the 10 pg shard names and the 3 non-pg server test names directly in `ci.yml`,
hand-synced against `tests/meson.build`'s own tag filters and
`flake-retry.py`'s verbatim positional-filter pins — a 3-way triplication that
broke CI on 3 separate shard-layout changes in as many weeks, each silently,
because nothing proved the three copies still agreed. Replaced with a
structural contract: every pg shard's `test()` entry in `tests/meson.build`
now carries `suite: ['server', 'server-pg']`, so `ci.yml` selects the whole
group with `--suite server-pg` instead of enumerating names, and a new
`scripts/ci/check-pg-shard-partition.py` runs as its own meson test
(`'server pg shard partition invariant'`, `suite: ['server', 'server-checks']`
— the second label is what lets the Windows non-pg step's
`assert-suite-cover.py` select it) that discovers
every `server-pg`-suite entry via `meson introspect --tests` and proves, via
`--list-tests --reporter xml` against the real compiled binary, that every
`[pg]`-tagged Catch2 case lands in exactly one shard — none lost, none
duplicated. A shard add/split/rebalance needs no update to this check at all,
only a correct `suite:` kwarg on the changed `test()` entry.
`flake-retry.py`'s own selftest keeps a small, genuinely-static verbatim pin
for the non-pg server shards (four: the Windows restructuring split shard
B → B+C, #3443 2026-08-28, then a later measured-by-time follow-up carved
shard D's `[body_cap]` tests out of B) plus a count-based sanity check that
pg-shard extraction still finds a real population — a second, independent
hollow-discovery signal, not a rebuild of what the structural check above
already proves. The same structural check (`check_partition()`, parametrised
by `ref_spec`/`label`) also proves the non-pg shards partition `~[pg]`
exactly, reusing one chokepoint instead of a second hand-rolled copy. See
`scripts/ci/check-pg-shard-partition.py`'s module docstring and
`tests/meson.build`'s own shard-history comment block (search
"Sharded 2026-07-13") for the full incident history this replaces.

**PG push-leg policy — full on one leg, smoke elsewhere (#3443 Phase 2,
2026-08-26; extended to Windows 2026-08-28):** Phase 1's load asymmetry
diagnosis (a `dev`/`main` push originally ran the full pg-shard suite on
all 4 Linux legs, ~85% of each job's time, vs 2 Windows legs both running
the same full set on their own 4-runner box) is cut by narrowing what the
non-primary legs run on both platforms: Linux's 3 non-primary legs and
Windows' release leg (push-only; PRs are debug-only, so only one Windows
leg runs at all there) now run the `[pg-smoke]` subset instead. The Linux `matrix:` carries a
`pg_mode: full|smoke` key, added via `include:` on the existing
compiler/build_type combinations — never a third axis (would double the
matrix and break `max-parallel: 3`'s 4-runner arithmetic) and never in the
job `name:` (job names are the branch-protection ruleset's required-check
contexts; `docs-required-checks` mirrors them). `full` resolves on
gcc-15/debug only (every PR, plus that leg's push); the other three push
legs (clang-21/debug, gcc-15/release, clang-21/release) resolve to `smoke`.

The smoke set is 11 hand-picked `[pg-smoke]`-tagged existing cases (no new
test bodies) covering: libpq connection/RAII (`test_pg_raii.cpp`),
transaction rollback (same file), a migration runner run
(`test_pg_migration_runner.cpp`), TagStore migrate-and-reopen + CRUD +
NULL-vs-empty (`test_tag_store.cpp`), pool exhaustion and mid-use reconnect
(`test_pg_pool.cpp`), pool GUC hardening (`test_pg_hardening.cpp`), a real
BYTEA+bigint wire round-trip via the KEK-rotation regression case
(`test_secret_codec.cpp` — the originally-cited simpler case turned out not
to touch the BYTEA column at all; caught during implementation, not assumed),
and UTF-8 boundary-truncation (`test_software_inventory_store.cpp`). Run as
its own `tests/meson.build` entry, `'server pg smoke'`, in a dedicated suite
`server-pg-smoke` — NOT `server-pg`, which would make
`check-pg-shard-partition.py`'s partition invariant see these cases as
double-claimed by their real shard AND this entry.

Two hardening decisions worth knowing before touching this again:

- **The smoke entry CARRIES `--allow-running-no-tests`**, unlike an earlier
  draft's plan to omit it. Every `[pg-smoke]` case is all-DSN-gated (skips
  cleanly per `test_helpers.hpp`'s contract when `YUZU_TEST_POSTGRES_DSN` is
  unset); a flagless all-DSN-gated entry would exit 4
  (`AllTestsSkippedExitCode`) on every DSN-less UNFILTERED `meson test` —
  local dev without Postgres, and any future sanitizer/nightly leg that runs
  the whole suite — breaking that skip contract, the same reason shards
  D/G/H/I/J already carry the flag. Loud-fail duty for a genuinely broken or
  missing DSN moved to ci.yml's own `Resolve pg_mode + assert Postgres DSN`
  step (runs immediately after `Ensure Postgres`, before ANY test invocation,
  full or smoke) and to the checker's exact-count + flag-present assertions
  below — not to Catch2's zero-tests exit code.
- **`check-pg-shard-partition.py` was extended, not duplicated**, with a
  `check_smoke()` pass proving: exactly one `server-pg-smoke` entry, the
  expected exact name, the expected binary, the expected Catch2 spec, the
  `--allow-running-no-tests` flag present, an EXACT case count (not a
  MIN/MAX range — a range let a same-count drop-and-add, or a single
  stripped tag, pass silently; an exact count catches any single addition or
  removal), and every matched case also carrying `[pg]`. Documented residual:
  a same-count SUBSTITUTION (swap one intended case for a different `[pg]`
  case) is not statically caught — that is a reviewable diff on the tag
  itself, and pinning exact case identity here would recreate the
  hand-maintained-metadata problem Phase 1 exists to cure.

`ci.yml`'s by-name invocation (`"server pg smoke"`) fails loud on a rename
that doesn't update it — Meson's positional test-name matching is an EXACT
match (`fnmatch` against a literal with no glob characters, `mtest.py`'s
`tests_from_args`), not a substring one, so this is a hard failure
(`MesonException`), not a silent near-miss. A `--suite` typo, by contrast,
exits 0 silently **on a plain `meson test` run** — the invocation shape
ci.yml actually uses — (`mtest.py`'s `get_tests`/`doit` print "No suitable
tests defined." and return success); this is exactly why the smoke and
non-pg invocations select by explicit name/suite list rather than a broader
subtractive filter. Caveat found during adversarial review (both reviewers
independently probed this, one initially over-read it as a documentation
error): `meson test --list --suite <bad>` is a different code path and
exits 1 — the silent-0 behavior is specific to the real run, not `--list`.
Don't use `--list` locally to sanity-check whether a suite name would fail
loud in CI; it gives the opposite answer.

The smoke step is deliberately UNGATED by `with-test-slot.sh` (~11 cases,
280 assertions, ~2.8s measured locally — the up-to-30-minute slot wait the
gate exists to bound would dominate work this cheap). Item 4 of the original
Phase 2 proposal — a periodic full clang-release PG run to cover the
optimizer/NDEBUG-sensitive residual class smoke can't reach — is deferred:
it would need to join Phase 6A's nightly slot-gate narrowing, and Phase 6A
is shelved (`nightly.yml`'s cron only fires against `main`, which trails
`dev` by thousands of commits right now, so a `dev`-only fix would sit
inert). Tracked on #3443, not silently dropped.

**Nightly and sanitizer legs are unaffected and still run the full
population, redundantly**: both invoke `meson test` UNFILTERED (no `--suite`
at all), so every `test()` entry runs once regardless of suite — the 11 pg
shards AND the smoke entry both fire, meaning the 11 `[pg-smoke]` cases
execute twice there. Harmless (seconds of cost) but real, and not specific
to any one platform — the same is true of a plain local `meson test` in any
worktree. Not worth special-casing.

**Telemetry note**: on a smoke leg, `'server pg smoke'` is the LAST
PG-tagged invocation in the Test sequence, so (per the JUnit-overwrite
behavior the "Persistent runner-local test history" section below
documents for both platforms) it is what `ci-suite-stats` sees for that
leg's PG timing — a full leg's `ci-suite-stats` entry still reflects the
11-shard run, not the smoke entry, since `pg_mode` fully separates which
one actually executes per leg. The same overwrite silently drops the
non-pg step's own `flake-retry` recovery reporting from that job's
queryable history too, not just its per-suite timing rows — the non-pg
step's own job-summary "Suite durations" table is written on every
invocation and is where its numbers actually live, same as Linux.

**Cross-job — runner acquisition, a fourth layer (2026-08-25, same day as the
split/timeout extension above):** the "Cross-job (fixed second, #3443 AC4)"
fix earlier in this section (`with-test-slot.sh`) gates contention only
*inside* a job that already holds a runner — it does nothing for a job that
cannot START because no runner is free. That is a structurally lower-level
gap than any of the three fixes above address, and the 35-minute-wait
incident that paragraph cites is actually an instance of THIS gap, not one
`with-test-slot.sh` closes: a `dev`/`main` push's own 4-way Linux matrix
could claim all 4 Big Tam runners simultaneously, leaving nothing reserving
a runner for a concurrently-queued PR job. Fix: `ci.yml`'s Linux job's
`strategy.max-parallel: 3` caps how many legs of that SAME matrix run
concurrently, leaving at least one Big Tam runner unclaimed by it — a no-op
on `pull_request` events (already a single-leg matrix via the existing
`exclude`). This is a mitigation, not a guarantee: the freed runner is not
reserved for any specific job. `proto-compat` (this same workflow) targets
the bare `[self-hosted, Linux, X64]` label every Big Tam Linux runner also
carries and runs on the same push trigger — it can claim the freed runner
itself before a queued PR job does (its own `timeout-minutes: 5` means it
self-frees quickly, but it is a real same-push competitor, not just the
already-named nightly-overlap case). A stacked nightly run, another
concurrent PR/push, or a manual `workflow_dispatch` can do the same — none
of these are fixable from this diff's scope; a genuine guarantee needs
runner-pool partitioning (dedicating a runner label to PR-fast-path jobs),
which needs direct access to the Big Tam box and is tracked as a follow-up
on #3443, not done here.

**Cross-job slot count: 2 -> 3 (2026-08-25, same day as the max-parallel
fix above).** `max-parallel: 3` and the `with-test-slot.sh` slot gate are
different axes, not substitutes: max-parallel governs runner acquisition
for one push's own matrix; the slot gate governs box-wide heavy
test-phase concurrency across ALL jobs (any push, any PR, nightly, manual
dispatch) once a job already has a runner and has finished building.
Trigger: PR #3600's own Linux job waited the full 30-minute
`YUZU_TEST_SLOT_TIMEOUT_MIN` and gave up (`no 'yuzu-bigtam-heavy' slot free
after 30 min (2 slots busy)`, recovered via a manual rerun once the
contending jobs finished); PR #3530's Linux job waited 17m16s
(`acquired 'yuzu-bigtam-heavy' slot 1/2 after 1036s`) before running clean.
Both times the 2 slots were held by other jobs' own long pg-shard test
phases — ordinary concurrent CI activity, not an anomaly.

Why 3 is a reasonable experiment, not just a convenient number: each of the
4 Big Tam runner agents idempotently (re)uses its OWN persistent
`yuzu-ci-postgres-<n>` container, so 3 concurrent heavy phases don't
contend for one shared Postgres instance — unlike the WITHIN-job
`--num-processes` cap (which exists because one job's own pg shards fan
out onto that SAME job's one container). A same-day diagnostic (the
`tests/meson.build` shard-history comment) measured a shard's wall time
within ~3% whether the box was quiet or under 3 other PRs' full CI runs.
CAVEAT: that diagnostic was measured while the slot gate held at 2 — it
describes a load shape that never exceeded 2 SIMULTANEOUS heavy pg
phases, lighter than the 3-slot regime this change ships. It supports
trying 3; it is not proof the same low sensitivity holds at 3-wide.
Post-ship telemetry is the real confirmation, not this number alone.
Separate Postgres containers also remove DB-lock/connection contention
but not shared physical resources (page cache, DRAM bandwidth,
kernel/container overhead) — the cap stays below 4 specifically to keep
some protection against a full-box heavy-phase pileup. `--num-processes`
stays at 2, deliberately NOT bundled with this change: 2 slots x 2
shards/job = 4 concurrent pg shards today, 3 slots x 2 = 6, but 3 slots x
3 would jump to 9 with no diagnostic support at that load and no way to
attribute a regression to either knob — ship and measure one axis at a
time.

Not starvation-proof: `with-test-slot.sh` has no FIFO or PR-aware
admission — a freed slot goes to whichever waiter's 5s poll tick happens
to fire next, not to whichever waiter arrived first. If 3 dev-push legs
hold all 3 slots, a 4th job still waits the full 30 minutes, same as
before. Raising the count reduces how often that happens; it does not
eliminate it. Also unenforced: `nightly.yml`'s and `sanitizer-tests.yml`'s
Linux legs share this same box but invoke `meson test` directly,
bypassing this gate entirely (pre-existing gap, #3443) — an ungated heavy
job on the box's 4th runner can erode the margin above further, on top of
whatever the 3-slot regime itself costs.

Acceptance/rollback signal: the #2093 duration watchdog's 560s warning
(80% of the 700s per-shard ceiling) is an expected, accepted verification
signal on early 3-slot runs, not by itself a reason to revert (worst
shard measured 522.73s at 2-wide — PR #3530's Linux gcc-15 debug leg, run
32861777346/job 97847463421, 2026-08-25 — vs. the 700s ceiling needs
roughly a 34% slowdown before an actual failure). Two rollback triggers,
not one: repeated warnings on the SAME shard under confirmed 3-slot
occupancy, or warnings scattered across MULTIPLE DIFFERENT shards in the
same or overlapping runs (the box-wide-contention signature a
single-shard trigger would miss) — either is the signal this operating
point consumed too much margin. "Confirmed 3-slot occupancy" today means
manually correlating each job's own "acquired slot N/3" log line against
overlapping runs' timestamps — there is no automated cross-job
correlation yet; building that is a real #3443 follow-up, not assumed
done here. Response to either trigger is rebalancing/splitting the
affected shard(s) or reverting to slots=2, never another timeout
increase. Tracked: #3443.

**Within-job cap extended to the non-pg step (2026-09-18).** The "3 non-pg
server tests, both uncapped" status above (now 6 named entries, see the
count-drift note on `ci.yml`'s comment) turned out to matter even though those
tests don't touch Postgres: `--num-processes 2` was added to both
`flake-retry.py` invocations in the "Test (non-pg suites)" step, matching the
value already established for this box's pg-shard step. Evidence: on two
independently-diagnosed CI runs (PR #4532 run 35307458479, PR #4566 run
35361987460, no diff in common), that step's own `meson test` invocation
failed exactly one Catch2 case each time — both async/timing assertions in
the spark/guardian suite — consistent with the same within-job CPU-steal
mechanism this section already proved for the pg shards, just flipping a
timing assertion instead of hitting a hard per-shard timeout.

This is **not** a fix for the much larger ~20-case failure list CI actually
reported for those same two runs (`content_dist`/`script_exec`/`event_logs`/
`wifi`/`windows_updates`/`software_actions`/`license_scan`). A `build-ci`
review found that list is produced by `flake-retry.py`'s `catch2_failed_cases()`
classifier, which re-runs the whole failed binary a second time, solo, outside
meson's orchestrator entirely — untouched by `--num-processes` or by
`with-test-slot.sh`. Why that solo re-run reports a different failure set than
the original run (and drops the original run's own failing case from its own
list) is not diagnosed; tracked as #4580. Cross-job `with-test-slot.sh` gating
was deliberately not added to the non-pg step yet — this step's own duration
is still short, so the within-job cap ships first per this section's "one axis
at a time" practice; #4580's outcome may argue for cross-job gating here too,
once the actual mechanism is understood.

### Persistent runner-local test history

Every self-hosted runner agent owns a separate `test-runs.db` outside its
checkout. Big Tam stores it below that agent's registered tool cache at
`/srv/ci/work-N/_tool/yuzu-test-runs/yuzu-bigtam-linux-N/test-runs.db`;
Wee Tam stores it at
`D:\ci\test-runs\yuzu-weetam-windows-N\test-runs.db`. The files survive
`actions/checkout`, branch-switch build wipes and runner restarts. They are
deliberately per-agent rather than per-host: telemetry must not introduce a
shared SQLite writer lock between the four jobs whose contention it measures.

The Linux and Windows jobs in `ci.yml` call `scripts/ci/ci-telemetry.py` near
job start and from an `always()` finalizer. Schema v3 records GitHub run attempt,
job/platform/runner, commit/branch/event, conclusion and wall time, ccache ratio,
each Meson test entry's result/duration/timeout, and any listed flake recovered
by `flake-retry`. A cancelled job normally finalizes as `cancelled`; a hard kill
that prevents post-steps intentionally leaves an `in_progress` row, which is
itself evidence of runner/job termination rather than a fabricated result.

**Linux AND Windows gap, since the "Suite isolation" split above:** the
finalizer imports one `meson-logs/testlog.junit.xml`, and both platforms'
Test steps now run multiple separate `meson test` invocations against the
same builddir (Linux: 3; Windows: always 2 — the non-pg step plus
exactly one of pg-full/pg-smoke, `matrix.pg_mode` resolves to exactly
one or the job fails loud earlier), each overwriting that file. Only
the LAST invocation's per-suite `ci_test_suites` rows and any `flake-retry`
recovery it reports survive — the earlier, cheaper invocation(s) still gate
the job (their own exit code), but produce no queryable history via
`test-db-query.sh ci-suite-stats`/`ci-flakes` for this job. This was true
for Linux from the original #3443 restructuring and became true for
Windows too once this PR mirrored that shape — see the "Telemetry note"
above for the Windows-specific ordering detail (pg runs last on both
platforms, for the same reason). macOS remains genuinely unaffected — it
never runs a `[pg]`-tagged suite (ADR-0035) and still has one invocation.

Provisioning is versioned in
[`deploy/linux/Provision-BigTam-Runner-Telemetry.sh`](../deploy/linux/Provision-BigTam-Runner-Telemetry.sh)
and [`deploy/windows/Provision-Windows-Runner.ps1`](../deploy/windows/Provision-Windows-Runner.ps1).
Query a runner in place by setting `YUZU_TEST_DB` and using:

```bash
bash scripts/test/test-db-query.sh ci-stats --since 30d
bash scripts/test/test-db-query.sh ci-suite-stats --since 30d
bash scripts/test/test-db-query.sh ci-flakes --since 30d
```

macOS now runs on the self-hosted **BigMags** pool ([`deploy/macos/`](../deploy/macos/README.md)):
ccache persists in the runner user's HOME and the vcpkg binary cache in
`runner.tool_cache`, like Big Tam/Wee Tam. Per-agent `test-runs.db` telemetry is
NOT yet wired into the `macos` job (Phase 4 to-do), so the DB queries above have
no macOS data yet. `release.yml` build-macos is now self-hosted on BigMags too (unsigned —
signing/notarization deferred to Phase B). Only the `pre-release.yml`
`install-macos` smoke test stays GitHub-hosted (`macos-14`, ephemeral).

Inventory declared in `.github/runner-inventory.json`. The sentinel at
`runner-inventory-sentinel.yml` (every 30 min) compares actual to expected
and opens a `runner-inventory-drift` issue on mismatch. Both the sentinel
and the new ci.yml `preflight` job share `scripts/ci/runner-health-check.py`
(`--mode sentinel` vs `--mode preflight`). Preflight gates downstream
self-hosted jobs with explicit
`if: needs.preflight.outputs.<runner>_healthy == 'true'`. Each workflow also
declares its required pools with `--require-pool`. A wholly unavailable
required pool fails preflight red instead of silently turning its required
jobs into successful skips. The control interface distinguishes observed
runner drift from authentication, API/transport, and malformed-response
failures; missing evidence is a failure, never an inferred healthy state.
The query requires the `RUNNER_INVENTORY_TOKEN` PAT secret (fine-grained,
Administration:read on Tr3kkR/Yuzu). Expected failures publish a typed
`failure_kind` and `failure_report`; an unexpected crash before those outputs
still takes the sentinel's fallback issue path.

Automatic fork PRs are rejected before the runner query and cannot emit
healthy self-hosted outputs. Runner-control failures and required-pool outages
are red operational failures. In particular, an offline Big Tam or Wee Tam
pool causes nightly preflight to fail and the nightly alert opens
`nightly-broken`; the repository discipline remains **no merge to main while
that issue is open**. Follow `docs/ci-troubleshooting.md` before closing it.

As of #1978, preflight also emits a `code_changed` output (from
`scripts/ci/detect-code-change.sh`); the build jobs additionally gate on
`&& code_changed == 'true'`, so a docs-only PR skips the whole matrix. The
matrix-expanded required contexts (`Linux gcc-15 debug`, `Windows MSVC debug`,
`macOS debug`) would otherwise stay "Expected" forever on a docs-only PR
(a top-level-skipped matrix job emits none of its inner check names), so a
`docs-required-checks` stub emits those exact names as success when
`code_changed == 'false'`. `ci.yml` no longer path-filters `pull_request`;
the `push:` trigger keeps its docs `paths-ignore`.

## Postgres for server tests (`YUZU_TEST_POSTGRES_DSN`)

ADR-0006 decision 8: every tier that runs the server **`[pg]`** suite gets a
real PostgreSQL and exports `YUZU_TEST_POSTGRES_DSN`. The shipped substrate is
**PostgreSQL 18** (`deploy/docker/Dockerfile.postgres`), and the Linux/docker +
Windows legs test against it; the server SQL is version-agnostic (13+), so a
runner-native cluster on an older major still exercises the suites correctly.
One script implements it everywhere — `scripts/ci/ensure-postgres.sh`, inserted
as an `Ensure Postgres (server tests)` step between Build and Test in ci.yml
(linux / windows) and nightly.yml (asan / tsan / coverage).

**macOS does NOT run the server `[pg]` suite (ADR-0035; #2394).** The Yuzu
server is a Linux-only component (macOS/Windows are agent-only platforms), and
GHA-hosted macos-15 runs a *single* brew Postgres cluster. After the
auth→Postgres migration (ADR-0006) roughly doubled the `[pg]` population to
~660 clone-bound cases (`CREATE DATABASE … TEMPLATE` + `DROP … FORCE` per
case), one slow cluster cannot service that within the per-suite meson budget,
and sharding does not help — parallel shards contend on the one cluster (both
hit their timeout). So the macOS leg deliberately **does not provision Postgres
/ export the DSN**: every `[pg]` server test then SKIPS (env-unset → skip, the
same contract the Catch2 PG fixtures use), completing in milliseconds, while
the non-PG server suite (`~[pg]`), the agent suite, and the Apple-Clang compile
still run. Linux + Windows both run the full `[pg]` shard set (macOS runs
none) — Windows additionally skips 44 migration-in-substance fresh-DB
cases within that set (#2354, "PG coverage by platform" below); that is a
narrower, Windows-specific exclusion, not a return to macOS's all-or-nothing
skip. Re-enabling full macOS `[pg]` coverage requires first solving the
single-cluster capacity problem (per-shard clusters or a cheaper per-test
isolation model than database-per-test).
Resolution order inside the script:

1. **Pre-set `YUZU_TEST_POSTGRES_DSN`** (runner-level env) — the escape
   hatch for any bespoke runner setup. On a **multi-agent box** (runner
   name ending `-<n>`, i.e. the 4-runner pools) the pre-set DSN names the
   *agent-0* cluster and agent `<n>` uses **port + `<n>`** when that
   per-agent cluster answers a probe — one instance per agent, so
   concurrent jobs never share a WAL/buffer pool (#2094, the 2026-07-12
   Wee Tam server-suite timeouts). Until a box is provisioned with the
   extra clusters the script falls back to the shared pre-set DSN with a
   `::warning` — no flag day. Runners without a `-<n>` suffix use the DSN
   as-is. **The DSN must not set `options=`, and `PGOPTIONS` must be unset
   in the job environment** (checked unconditionally, before path
   selection) — either silently disables PgPool's `statement_timeout`/
   `lock_timeout` safety-bound GUCs (`pg_pool.cpp`'s `conninfo_has_options_`
   gate), caught by the `[pg][hardening]` test "PgPool injects
   statement_timeout and lock_timeout GUCs". Put durability tuning in
   `postgresql.conf` via `ALTER SYSTEM` instead (#2167).
2. **Docker** (self-hosted Linux) — idempotent persistent container
   (`docker start` || `docker run --restart unless-stopped`, image pinned
   to the same digest as `deploy/docker/Dockerfile.postgres`'s base;
   one-time cost per runner). On the multi-agent `yuzu-bigtam-linux` pool
   each agent gets **its own container** — `yuzu-ci-postgres-<n>` on
   `127.0.0.1:15440+<n>`, `max_connections=400` (#2094/#2096),
   self-created on the agent's first job. Single-agent boxes keep the
   shared `yuzu-ci-postgres` on `127.0.0.1:15432`. The 15440+ base and
   15432 avoid colliding with native clusters (5432), the dev pg-canary
   (5433), and the UAT sidecar (15433). Lifecycle is `flock`-serialized
   per container name.
3. **brew** (GHA-hosted macOS, no docker) — `postgresql@18` bottle +
   throwaway trust-auth cluster under `$RUNNER_TEMP` on
   `127.0.0.1:15432`.
4. **Native cluster on `127.0.0.1:5432`** — the generic self-hosted
   Windows precondition: a PostgreSQL 16+ Windows service with role
   `yuzu` / password `yuzu` / database `yuzu_test`, bootstrapped
   **once** per runner (installer or `choco install postgresql16`, then
   `createuser`/`createdb` as above). When `psql` is on PATH the script
   authenticates the conventional DSN with `SELECT 1` before exporting
   it — a TCP listener with the wrong credentials produces a `::warning`
   and no DSN rather than a false "ready". Without `psql` it falls back
   to the bare TCP probe with a loud unverified-credential warning.
   Prefer the runner-level env override (path 1) if the box already runs
   Postgres with different credentials.

   **Wee Tam (`yuzu-weetam-windows`) uses path 1, not path 4:** each runner
   provides native PostgreSQL **18** services — agent 0's winget-installed
   `postgresql-x64-18-yuzu-ci` on `:5433` plus one initdb'd cluster per
   further agent (`postgresql-x64-18-yuzu-ci-<n>` on `:5433+<n>`, #2094) —
   and a machine-level `YUZU_TEST_POSTGRES_DSN` (the agent-0 DSN; path 1
   derives the per-agent port) that wins before the docker probe, so the
   leg stays deterministic regardless of any Docker engine state.
   Provisioning specifics live in
   [`deploy/windows/`](../deploy/windows/README.md). (The retired
   `yuzu-local-windows` box ran a PG 16 binaries-zip service on 5433 — see
   git history if that bootstrap pattern is ever needed again.)

   Windows CI test-phase restructuring (#3443, 2026-08-28): `ci.yml`'s
   Windows job runs the `Test (pg shards, full)` / `Test (pg smoke)`
   split described in "PG coverage by platform" below, mirroring the
   Linux job's `pg_mode` shape. Neither the ensure-postgres.sh mechanism
   above nor the per-agent cluster topology changed — only which meson
   suites a given job invocation selects.
5. Nothing found → `::error`, exit 1.

**Fatal on every non-success path since #1320 PR 1 (`SOFT_EXIT=1`):**
the pg substrate suites (`[pg]`-tagged cases in the server suite)
consume the DSN and skip cleanly when it is unset — so a runner without
a database would silently skip that coverage. `exit "$SOFT_EXIT"`
(= exit 1) is reached on every failure path: Docker container not ready
in 60 s (path 2), brew cluster not ready (path 3), native-cluster
credential failure when `psql` is available (path 4), and nothing found
(path 5). The one non-fatal exception is path 4 without `psql`: a TCP
probe alone produces a `::warning` and still exports the conventional
DSN (credential **unverified** — wrong credentials then surface as
downstream `[pg]` test failures; install `psql` on the runner's PATH,
e.g. `C:\Program Files\PostgreSQL\18\bin` on the `yuzu-weetam-windows` runners, to
get the authenticated gate instead). Locally the tests still skip when
`YUZU_TEST_POSTGRES_DSN` is unset; when it is set but unreachable they
fail rather than skip.

On the Windows pool (path 1, #3443 restructuring): `ci.yml`'s `Resolve
pg_mode + assert Postgres DSN` step loud-fails (`::error`+`exit 1`,
checked before any test invocation runs, not just the PG-tagged ones) on
three separate conditions — `pg_mode` resolving to neither `full` nor
`smoke`, `YUZU_TEST_POSTGRES_DSN` being unset/empty after Ensure Postgres,
or the two symmetric matrix-include guards catching a broken mapping. It
does NOT check DSN *parseability* — a syntactically malformed but
non-empty DSN clears this step and only fails later, at the first actual
libpq connection attempt inside a PG-tagged test.

## PG coverage by platform

| Platform | pg shards | Migration-DDL tests | Notes |
|---|---|---|---|
| Linux (gcc-15/debug, every PR + primary push) | full (11 shards) | run | ADR-0006 reference platform |
| Linux (other push legs) | smoke (`[pg-smoke]`, 11 cases) | run | #3443 Phase 2 |
| Windows (debug, every PR + push) | full (11 shards) | **skipped** (`YUZU_REQUIRE_PG_MIGRATION_DB`) | #2354; behaviour covered on Linux |
| Windows (release, push only) | smoke | **skipped** (2 of the 11 smoke cases) | never runs on a PR |
| macOS | none (ADR-0035) | n/a | server is Linux-only |

**#3508 (moving pg shards off Windows PRs entirely) is deliberately NOT
adopted here** — Windows PR legs keep full `server-pg` coverage rather than
dropping to `[pg-smoke]`. The Windows server still ships (ADR-0035 is
`proposed`, not accepted, and `release.yml` signs `yuzu-server.exe` +
builds `YuzuServerSetup`), and there is no agent<->server integration step
in the Windows job that would make full pg coverage there redundant — the
#3508 premise for narrowing Windows PR coverage does not hold today. This
PR's non-pg/pg-shard split closes the time gap #3508 was trying to close
by a different, more targeted route instead.

44 migration-in-substance fresh-DB Postgres test sites (a real from-scratch
migration, `!is_open`-on-failure, backfill/upgrade, drift detection) SKIP
on Windows via `YUZU_REQUIRE_PG_MIGRATION_DB` in `tests/unit/test_helpers.hpp`
— each pays EXEC_BACKEND CreateProcess-per-connection plus the migration
DDL itself there (#2354), and none of them prove anything Windows-specific.
The predicate is fail-closed: set `YUZU_TEST_PG_MIGRATION_DDL=1` (exact
value) to force them back on locally. `--list-tests` still enumerates a
skipped case (Catch2 SKIP is a runtime throw, not a compile-time
exclusion), so the pg-shard partition checker and `SMOKE_EXACT_CASES` are
unaffected; the 28 pure pg-substrate tests (`test_pg_pool.cpp` etc. —
`test_secret_column_registration_tripwire.cpp` moved to the migration-skip
bucket above, governance 2026-08-28: it constructs a real `AuthDB` against a
fresh, non-templated DB, running actual migration DDL, not pure substrate)
and the 28 SQLite/pure `[migration]`-tagged tests (`test_offload_target_store.cpp`
no longer belongs in this count — it migrated to Postgres on 2026-08-25,
before this branch's own base commit, and was never SQLite or
`[migration]`-tagged to begin with) run everywhere unconditionally.

Local-dev note: to run the non-pg server tests on a machine with no
Docker and no Postgres, invoke the test binary directly
(`tests-build-server-*/yuzu_server_tests`) with `YUZU_TEST_POSTGRES_DSN`
unset — the `[pg]` cases skip cleanly. The `/test` skill and CI
deliberately hard-fail at the ensure-postgres step instead (that is the
gate working, not a skill bug).

Operational notes for shared instances: on a box where a Postgres
instance IS still shared across concurrent jobs (single-agent boxes, or
a multi-agent box before its per-agent instances are provisioned —
the fallback `::warning`), the migration runner's advisory locks are
**cluster-wide**, so same-named stores in different ephemeral test
databases briefly serialize on each other (transaction-scoped locks:
never deadlock, never cross-database corruption). The 4-agent pools run
**one instance per agent** (#2094) precisely so no job shares WAL/fsync
bandwidth — or advisory-lock space — with a concurrent job. After the
Big Tam cutover the legacy shared `yuzu-ci-postgres` container on
`:15432` is unused there and can be `docker rm -f`'d.

**Test-database lifecycle (PR #2091).** Ephemeral per-case databases
(`yuzu_test_<epoch>_<salt>_<n>`, created/dropped by `PostgresTestDb`) coexist
with run-lifetime shared clones (one clone and persistent pool for each
instantiated eligible high-volume test file) and per-process **template** databases
(`yuzu_test_tpl_<epoch>_<salt>_<key>`, built once by `PgTestTemplate` and
dropped at `testRunEnded`). At run end the listener invokes one ordered shared
cleanup primitive: it drains every persistent pool first, drops those clones,
then drops the templates, all before libpq/OpenSSL teardown. The active footprint
is therefore the per-case databases currently in flight, one clone per
instantiated shared-fixture file, and up to ~a dozen templates for each of the
box's 4 runner agents. A pile-up is NOT
automatically "teardown is failing": names embed their creation epoch, and
every suite start sweeps names older than 6 h (`kTestDbStaleAfterSeconds`),
so leaks from killed runs self-heal within that window; the sweep prints a
`sweep saw N ... dropped M` summary in the job log. A weekly out-of-band
janitor complements it (#1367): `cache-prune.yml` (Sundays 04:00 UTC +
`workflow_dispatch`) runs `scripts/ci/sweep-test-databases.sh` on both
self-hosted boxes, so leaks reclaim even on a box that stops running `[pg]`
legs. The janitor self-discovers the per-agent topology from #2094/#2114 —
every running `yuzu-ci-postgres(-<n>)` container on the docker boxes, and in
DSN mode the machine DSN's base port plus the next three per-agent ports
(dark higher ports are the normal pre-cutover state and skip silently); a
degraded sweep (psql missing, cluster dark, a pass query failing) exits
nonzero so the weekly run goes red rather than rotting silently.
Epoch-named databases age by the same >6 h/server-clock rule; names
the epoch sweeper can never parse (pre-epoch format `yuzu_test_<salt>_<n>`,
implausible clock stamps) are dropped only when the datdir's `PG_VERSION`
mtime exceeds 7 days AND the database has zero active backends
(superuser-only via `pg_stat_file`; dropped without FORCE so a racing
connection vetoes). Hand-cleaning a wedged instance: only ever touch
`yuzu_test_*`/`yuzu_test_tpl_*` names; prefer "name-epoch older than 6 h"
over "no current connections" (a live fixture is momentarily
connection-free between drop and re-create); pre-epoch-format names are
reclaimed by the weekly cron after 7 days — hand-clean only if one must go
sooner. The server suite's meson timeout was recalibrated 600 s → 900 s in
the same PR, then split into `[pg]`/`~[pg]` shards at 600 s each (#2092;
see the comment above the two `test('server ...', ...)` entries in
`tests/meson.build`).

## Universal vcpkg cache-key contract

`scripts/ci/vcpkg-triplet-sentinel.sh` is the single source of truth for
"have the inputs to vcpkg actually changed?". Key:

```
sha256(vcpkg.json + vcpkg-configuration.json + triplets/<triplet>.cmake + $VCPKG_COMMIT)
```

Stored at `vcpkg_installed/.<triplet>-cachekey.sha256`. On drift, wipes
`vcpkg_installed/<triplet>/` AND `vcpkg_installed/vcpkg/` (the
per-workspace registry — `info/`, `status`, `updates/`. Leaving the
registry behind after wiping the triplet tree leaves orphaned
`info/<port>_<triplet>.list` entries that make the next `vcpkg install`
short-circuit to "already installed" and then fail post-install
pkgconfig validation; this was #741.) Never touches `$WS/vcpkg/` (the
sibling vcpkg tool root, owned by lukka/run-vcpkg), never
`runner.tool_cache`, never ccache. Persistence: self-hosted in
`${runner.tool_cache}/yuzu-vcpkg-binary-cache-{linux,asan,windows,macos}`
(per-triplet, outside workspace). macOS joined this model with the BigMags
cutover; its former `actions/cache@v5` round-trip was removed.

The script must run cleanly under MSYS2 bash on Windows. **Do NOT use
`set -e` + `[[ test ]] && cmd` short-circuits** — they silently exit under
MSYS2 (cost us run #25051196135). Use `if/fi` blocks and explicit
per-command error checks.

## Persistence and recovery

Normal self-hosted checkouts use `clean: false`. Pre-checkout wipes
`build-<os>/` ONLY on branch change; vcpkg state is invalidated by the
sentinel above. A trusted fork execution is the intentional exception: it uses
`clean: true`, private temporary ccache/test paths, `VCPKG_BINARY_SOURCES=clear`,
and a final checkout-only purge. `meson setup --reconfigure` when
`meson-info/` exists. Manual recovery:
`bash scripts/ci/runner-reset.sh`
(`git clean -fdx -e vcpkg/ -e vcpkg_installed/ -e build-*/`) — **the only
sanctioned in-repo nuke path**; never `rm -rf` runner caches (memory
`feedback_vcpkg_cache.md`).

## Per-OS build directory names

Matrix: `build-{linux,windows,macos}`. Nightly variants:
`build-linux-{asan,tsan,coverage}`. `sanitizer-tests.yml` + `release.yml` +
`pre-release.yml` follow the same convention so the warm asan binary cache
is shared. Closes #406.

## Flaky-test retry (`flake-retry`)

`scripts/ci/flake-retry.py` wraps the `meson test` step on `ci.yml`'s three
test legs (PR fast-path + push matrix; **not** nightly/sanitizer, which stay
fail-loud so a real ASan/TSan race is never masked). Every run — green
included — first gets the #2093 duration watchdog: a per-suite
duration/budget table in the step summary, plus a `::warning` for any suite
past 80% of its meson timeout (reporting only; pass/fail semantics never
change). On a clean run it does nothing further. On failure it isolates the
failed **Catch2 case(s)** — it re-runs the
failed suite binary (located via `meson introspect --tests`) with Catch2's own
junit reporter, since meson's junit is only suite-level — then:

- any failed case **not** in `tests/known-flaky.json` (scoped to this OS) →
  the job **fails** (real regressions stay blocking);
- a failed suite that can't be classified per-case (non-Catch2, e.g. the
  gateway eunit/ct legs, or a crash/timeout with no junit) → **fails** (never
  mask);
- a **listed** case is retried in isolation up to 2× (`--retries`); the job
  passes only if it recovers, and a listed case that fails every retry still
  **fails** (a regression *inside* a flaky test is caught too).

`tests/known-flaky.json` is the static, in-repo, PR-curated source of truth —
one entry per case with `platforms` (OS-scoped; `["all"]` = cross-platform),
`reason`, tracking `issue`, accountable `owner`, and ISO-8601 `added` and
`expires` dates. Every field is required for every entry, including entries for
another OS. An entry expires at the end of its stated date; an expired or
malformed list fails before `meson test` starts, so stale exemptions cannot
silently mask a red build. Cross-platform flakes emit a loud `::warning` (they
signal a genuinely nondeterministic test, not an env quirk); OS-scoped ones a
`::notice`. Entries older than 90 days still get a soft `::warning` before their
hard expiry. Case names and platform values are unique, and `all` cannot be
combined with an OS. Expiry uses the UTC calendar date; the validator's clock is
injectable for hermetic tests.

The job summary + annotations remain the immediate signal. In addition,
`flake-retry.py` writes `meson-logs/flake-retry.json`; the job finalizer imports
recovered listed cases into the runner's `ci_flake_events` table alongside the
suite timings. `tests/known-flaky.json` remains the reviewed source of truth —
the database is observation history, never an implicit allowlist. This is
reversible test tooling — no ADR (rationale in the wrapper header).

**Triage note — shared-fixture files fail as a cluster on a PG blip.** The
shared-DB + TRUNCATE fixture files (#2362, #2603: `test_software_inventory_store`,
`test_software_licensing_*`, `test_product_registry_store`,
`test_rest_access_review`, `test_engine_principal_{lifecycle,integration}`, and
later conversions) hold one clone + one pool for the whole file. A Postgres
blip mid-file therefore reds out *several unrelated-looking CRUD cases in one
file* — and flake-retry's isolated re-run (fresh process, fresh clone) will
often recover them, so the incident can masquerade as N independent "recovered
known flakes". Before treating such a cluster as N regressions (or adding them
to `known-flaky.json`), grep the junit failure text for
`PGRES_COMMAND_OK`, `REQUIRE( lease )`, `is_open()`, or the bundle/reset tags
(`[ApiTokenStorePgShared]`, `[AuthDbPgShared]`, `[EpLcShared]`,
`[EpIntegShared]`, `[AccRevShared]`, `acc_rev_reset`) — a cluster of those in
one file is one PG-instance event, not a test bug.

## Workflow-PR canary

`ci.yml`'s `detect-ci-changes` + `canary` jobs run when a PR, or a push to
`main` or `dev`, touches `.github/workflows/`, `.github/actions/`, or
`scripts/ci/`. The named `ci-infrastructure` class in
`scripts/ci/detect-code-change.sh` owns both the path rules and `git diff`
error handling. If the diff cannot be established, it returns changed=true so
the canary runs fail-closed. Canary mirrors the linux build on a fresh-disk
GHA-hosted `ubuntu-24.04` with `actions/cache` for vcpkg + ccache — catches
workflow regressions before main.

**Diff semantics differ by event, deliberately.** A push asks "what did this
push move", so it diffs two-dot against `github.event.before`. A pull request
asks "what does this PR change", so it diffs from the merge base — its
`base.sha` is a live branch tip, and two-dot there additionally reports every
commit the base branch gained since the fork point, which misclassified any PR
that had merely fallen behind a CI-touching `dev` (#3232). The merge-base diff
must be given the **PR head**, never the checked-out `refs/pull/<N>/merge`
commit: `base.sha` is always an ancestor of that merge commit, so the merge
base *is* `base.sha` and three-dot silently collapses back to two-dot. That
no-op is pinned by cases in `tests/shell/test_detect_code_change.sh`, which
also assert the caller passes a resolved head.

**Cache keys must not be reachable by an earlier restore step.** (#3270's
original instance: a workspace-wide `hashFiles` glob picked up the vendored
headers the vcpkg restore had just materialised, so the key differed between a
cold and a warm run.) The canary's ccache key is now a **rolling 3-day bucket**
(`ccache-canary-x64-linux-<epoch/259200>`, computed from the runner clock —
trivially unreachable by any restore): the source-hash key it replaces never
exact-hit on a repo doing ~75 commits/day, so every run saved a fresh multi-GB
entry, the pool ran 7x over GitHub's 10 GB repo quota, and LRU eviction both
degraded the canary (8-20 min rebuilds from week-old entries) and starved every
other cache (measured 2026-09-01). One entry per 3-day bucket per scope now
(~2-3 live — bounded from growing WITHOUT limit by `restore-keys` naming
only the specific previous bucket, not bounded to a guaranteed total: an
open-ended prefix fallback would defeat even that, keeping any dead entry
alive forever since every fallback hit refreshes GitHub's last-accessed
clock, measured 2026-09-02 in `ci.yml`'s canary ccache restore step).

A job-level `CCACHE_MAXSIZE` caps each entry's own size (2G originally,
raised to 3G 2026-09-03 after the 2G estimate proved low against measured
2.2-2.6 GB working sets), but that is a per-entry cap, not a pool-wide
guarantee: the WORST-CASE aggregate — live-entry count x per-entry cap x
ccache's own measured overshoot past that cap, plus the separate
vcpkg-canary entry — can exceed the shared 10 GB repo quota outright, not
merely run close to it. See `ci.yml`'s "Compute ccache time bucket" step
comment for the current arithmetic and #3889 for the tracked observability
gap. ccache's own preprocessed-input hashing
absorbs intra-bucket source drift, so hit-rate decay is capped at ~3 days of dev
churn. The ccache save is gated on the Build step having run, pass or
fail — a cancelled run leaves no thin entry, at the accepted cost that an early
hard Build failure can occupy the bucket's key with a thin one (#3269,
documented at the restore step); the vcpkg save is gated more strictly, on its
install step succeeding, because a partial tree is a correctness problem rather
than a slow one.

**Pushes to `dev` are what keep the cache warm.** GHA cache scope lets a PR job
read its own ref, the default branch, and its base branch — never a sibling
PR's. The same rule is what confines a trusted-fork run: it is dispatched on a
throwaway `trusted-fork/pr-<N>` branch, so whatever fork code writes lands in a
scope no `dev`/`main`/PR run can restore from, and the wrapper purges it after
the run (#4471). Every PR bases on `dev`, so a dev-scoped entry serves all of them; main-only
warming left the scope empty for five weeks and each PR saved a private ~843 MB
duplicate (#3233). Note the canary key hashes `vcpkg.json` /
`vcpkg-configuration.json` / `triplets/x64-linux.cmake`, which the
`ci-infrastructure` class does not match, so a manifest bump on `dev` does not
itself re-warm the new key.

## Cache pruning + weekly maintenance

`cache-prune.yml` runs weekly (Sun 04:00 UTC) on each self-hosted runner.
Deletes `${RUNNER_TOOL_CACHE}/yuzu-vcpkg-binary-cache-*/<file>` >30 days
old. Does not touch ccache (own LRU at `CCACHE_MAXSIZE=30G`).
Also sweeps the buildx local cache the chisel images write
(`/mnt/d/docker-buildcache/*-chisel`, `mode=max` — several GB/arch, no
built-in eviction); whole-`*-chisel`-dir mtime sweep >30 days, Linux only.
Since #1367 the same run also executes `scripts/ci/sweep-test-databases.sh`
on both boxes — the weekly out-of-band janitor for leaked `yuzu_test_*`
databases (thresholds and semantics: "Test-database lifecycle" above).

## Chiselled demo images + agent bundle (release-time)

`docker-publish-chisel` (in `release.yml`) builds the server/gateway/agent
`*.chisel` images multi-arch — linux/amd64 native + linux/arm64 via **QEMU**
— on the self-hosted Linux runner. The emulated arm64 vcpkg-from-source
compile can hold that single runner slot up to its 360-min timeout, so the
job carries a `cancel-in-progress: true` concurrency group (a re-tagged
release supersedes a stale build instead of queueing behind it). It is
**not** in the `release` job's `needs:`, so a slow/failed demo-image build
never blocks the actual release. The sustainable fix for the QEMU cost is a
native arm64 runner — the open decision tracked in `docs/demo-environment.md`
("Publishing").

`docker-publish-agent-bundle` runs **after** `release` (it repackages the
release's own signed agent archives) on a GitHub-hosted runner — no
compilation, so no self-hosted dependency — and cosign-signs + SBOMs +
attests the pushed `yuzu-agent-bundle-chisel` image like the other publish
jobs.

## vcpkg state corruption — recovery path

If a Windows CI run repeatedly fails at `Install vcpkg packages` with a
missing `.pc` file under `vcpkg_installed/x64-windows/lib/pkgconfig/`, the
corruption is in `vcpkg/packages/` (which the cache-key sentinel does NOT
reach). Recovery procedure + full corruption-path inventory:
`docs/ci-troubleshooting.md` §7. Don't leave the recovery step in `ci.yml`
after an incident — it defeats the cache.
