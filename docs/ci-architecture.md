# CI architecture — runner topology, vcpkg cache, persistence

Reference for Yuzu's three-tier CI architecture (April 2026 overhaul).
CLAUDE.md keeps the headline tier breakdown + runner topology; this document
holds the cache-key contract, persistence rules, and operational knobs that
the `build-ci` agent loads on workflow / vcpkg / scripts/ci changes.

Plan of record: `/home/<user>/.claude/plans/our-ci-has-been-piped-castle.md`.
Failure-mode runbook: `docs/ci-troubleshooting.md`.

## Tier summary (mirrors CLAUDE.md)

- **Tier 1 — PR fast-path** (`ci.yml` on `pull_request`): one Linux variant
  (gcc-15 debug on the `yuzu-bigtam-linux` pool), one Windows variant (MSVC debug on
  the `yuzu-weetam-windows` pool), one macOS variant (appleclang debug on the
  `yuzu-bigmags-macos` pool), plus `proto-compat`. Wall target: <10 min per leg.
  Every `ci.yml` run starts with a two-job preflight (see the runner-inventory
  paragraph under "Persistent runner-local test history" below): a short `preflight-gate` job ("Preflight (gate)") that
  classifies docs-only changes and probes runner-pool health, which the build
  jobs `need`, and the `preflight` job ("Preflight (runner health)", the
  required-check name) that carries the source gates and runs alongside the
  builds.
- **Tier 2 — push to dev/main** (`ci.yml` on push): a push to `main` runs the
  full 4-way Linux matrix (gcc-15 / clang-21 × debug / release), 2-way Windows
  and 2-way macOS; a push to `dev` runs the **debug legs only** (Linux gcc-15 and
  clang-21 debug, Windows MSVC debug, macOS debug), and its release/LTO legs move
  to Tier 2b below. Either way a docs-only push runs the preflight jobs plus the
  required-check stubs instead (#5320).
  **No
  sanitizers, no coverage** — those moved out (#410). **Since #3443 Phase 2**,
  the Linux matrix's `pg_mode` key (via `include:`, never a third axis) means
  only ONE leg (gcc-15/debug) runs the full 14-shard `server-pg` suite on a
  push; the other three legs run a small `[pg-smoke]`-tagged subset instead —
  see "PG push-leg policy" below. PR coverage is unaffected (the PR `exclude:`
  already trims the matrix to gcc-15/debug alone, which always resolves to
  `pg_mode: full`). **Since ADR-0035 ladder step 1**, the Windows and macOS legs
  are agent-only (the `server` option is `auto`, off on any non-Linux target; step 1 passed `-Dbuild_server=false`): they build and test no server code and
  run no Postgres suite, so `pg_mode` exists on the Linux matrix only. (From the
  Windows test-phase split, #3443 on 2026-08-28, until then the Windows matrix
  carried the same `pg_mode` key: debug=full, release=smoke.)
  **Since #5320** the push trigger has no `paths` filter: a docs-only push
  (for example a changelog-only release commit) runs the preflight jobs and the
  `docs-required-checks` stubs instead of the matrix, so the required contexts
  still appear on the `main` commit a release tags. See "Docs-only changes
  (#1978, #5320)" below.
- **Tier 2b — daily release legs on dev** (`release-legs-daily.yml`, cron
  `30 2 * * *` UTC — nominal, GitHub starts scheduled runs late under load —
  plus `workflow_dispatch`): dispatches `ci.yml` against dev's tip with
  `legs=release`, which expands to the four release legs only (Linux gcc-15
  release LTO, Linux clang-21 release, Windows MSVC release LTO, macOS release
  LTO); the debug legs normally already ran on that commit's push. It skips
  when dev's tip already has a dispatch run that succeeded or is in flight; a
  failed or cancelled run does not count, so a red tip is retried the next day.
  While a bot-opened `release-legs-broken` issue is open, only an in-flight run
  counts, so the tip is re-checked daily until a green run closes the issue.
  No release leg is a required check, so moving them off the per-push path
  costs no gating; it saves 9–23 min of self-hosted runner time per leg per dev
  push. These legs are the only place the test suite runs in release/NDEBUG
  mode between promotions (`release.yml` builds with `-Dbuild_tests=false`), so
  a release-only defect now surfaces within about a day instead of on the push
  that caused it; `main` pushes still build release, so nothing tags untested
  in release mode. (Since ADR-0035 ladder step 2, `release.yml` builds no
  Windows or macOS server either, so nothing it ships goes untested by CI for
  that reason; `tests/test_release_agent_only.py` keeps it that way.)
  - **Failure signal.** A dispatched run is started by `github-actions[bot]`,
    which emails nobody. Whether to open, comment on or close a
    `release-legs-broken` issue is decided in one place,
    `scripts/ci/release-legs-issue.sh` (tested by
    `tests/shell/test_release_legs_issue.sh`), which two paths call:
    - **Listener (fast path).** `release-legs-alert.yml` is a `workflow_run`
      listener on CI runs, dev only, dispatch runs only. It fires as each run
      completes.
    - **Reconcile (backstop).** `release-legs-daily.yml`'s `reconcile` job
      re-judges the last completed, non-cancelled dispatch run every day,
      before that day's dispatch. It shares the listener's concurrency group,
      so the two never act on one run at once. A listener run that was
      dropped, failed or never fired is still reported within a day.

    What the script does:
    - **Opens or comments** on any failing conclusion. A late report is
      dropped when the newest completed, non-cancelled dispatch run is newer
      than it and has given a verdict: it failed, or it was fully green. A newer green run
      with a skipped leg never swallows it. This includes a run that
      never started (`startup_failure`), and words it by cause: a code
      failure, infrastructure (the preflight gate, or only preflight jobs,
      failed; proto-compat then fails closed too), or a run that started no
      job.
    - **Closes** only when the run is the newest completed dispatch run on
      dev, and every OS (Linux, Windows MSVC, macOS) had at least one
      `[dispatch]` build leg and all of them passed. Even then it closes only
      issues opened before that run finished. A green re-run of an older run
      never closes an issue while a newer run is red, and a green run answers
      nothing reported after it, such as a later reconcile or dispatch
      failure.
    - **Does nothing** on a cancelled or skipped run.
    - **Fails red** if listing the open issues fails, rather than reading that
      as "none open" and opening a duplicate.
    - **Matches** only open issues authored by `github-actions[bot]`, so a
      hand-added label is never commented on or closed.

    A failure of the daily workflow itself (its `reconcile` or `dispatch`
    job) opens the same issue from its `alert` job, worded by which job
    failed. All three writers (listener, reconcile, alert) share one
    concurrency group. There is no merge discipline attached, unlike
    `nightly-broken`, but the release skill checks the label before tagging.
  - **When `release-legs-broken` opens (triage).**
    1. Read the issue's cause line. A "dispatcher failed" or "daily
       reconcile failed" issue means `release-legs-daily.yml` itself failed:
       read that run's log and fix it. Re-dispatch (step 4) if the dispatch
       did not happen. If the preflight gate (or only preflight jobs) failed,
       it is infrastructure: a runner pool, a runner-health check or a source
       gate. Fix that, then re-run the failed jobs (GitHub re-runs the gate
       and everything that depends on it) or re-dispatch. Never re-run
       proto-compat alone: it would reuse the gate's earlier result. If the
       run started no job, dev's `ci.yml` failed to load, and every dev push
       is likely red too.
    2. Otherwise, open the failed leg. A timeout, a test-slot wait or a
       Postgres restart mid-run is a flake: re-run the failed jobs.
    3. A real test or link failure in release mode is a release-only
       regression. Take the commit from the leg's "Record built commit
       (dispatch)" step and bisect back to the last green dispatch (below).
    4. The issue closes itself on the next fully green dispatch that is the
       newest on dev. A re-run of the newest run counts, as does a fresh
       `gh workflow run ci.yml --ref dev -f legs=release`, so there is no need
       to wait a day. Three cases do not close it:
       - a green run in which a dispatch build leg was skipped;
       - a green run that finished before the issue was opened;
       - a re-run of an older run.

       A CANCELLED run neither opens nor closes one.
    Each dev push also shows a skipped "Release legs (alert)" run in the
    Actions tab; that is the listener filtering out non-dispatch runs.
  - **Required contexts.** A dispatch must never post a SKIPPED (= satisfied)
    required check on any SHA, including the dev tip that a dev → main
    promotion PR uses as its head. There are two mechanisms, because GitHub
    does not evaluate a skipped job's `name:` expression (it posts the raw
    template, [community #13261](https://github.com/orgs/community/discussions/13261)):
    - **Renamed.** On a direct dispatch, Preflight (runner health) and the
      Linux/Windows/macOS legs get a ` [dispatch]` suffix. Preflight always
      runs, and a skipped matrix leg already posts an unexpanded name, so the
      suffix is always rendered or harmless.
    - **Never skipped.** Proto backward-compat is routinely skipped (every
      docs-only PR, #1978), so it keeps its literal name. On a dispatch it
      always runs (`always()`, so a cancel does not skip it either, and a final
      step fails it red if the run was cancelled). It runs the real
      `buf breaking` on the branch it checks out (dev; main on a by-hand
      dispatch), the same thing
      every dev push already posts. If dev moved since the dispatch, its
      "Record built commit" step names the commit actually checked. If
      `preflight-gate` did not succeed (an infrastructure failure, or a
      dispatch cancelled during preflight), it fails red on a hosted runner
      instead of skipping. That red is a real, fail-closed "Proto
      backward-compat" on the dev tip. Before merging a promotion PR whose
      head is that commit, re-run that dispatch's failed jobs (not
      proto-compat alone), or re-run the PR's own CI.

    As defence in depth, `trusted_inputs` refuses a direct dispatch on any ref
    but `dev` or `main`.
  - **Mechanism.**
    - **Concurrency.** The dispatched run uses its own `-dispatch` concurrency
      group. GitHub keeps one pending run per group, so sharing the dev push
      group would let a dispatch evict a queued push run.
    - **Matrix.** The `include:` lists are conditional on a `legs=release`
      dispatch, because GitHub applies `include:` after `exclude:` and would
      re-add an excluded debug leg.
    - **Trusted-fork path.** A direct dispatch is told apart from the
      trusted-fork `workflow_call` path by `inputs.head_sha`, because a
      reusable workflow inherits its caller's `workflow_dispatch` event name.
      Trusted-fork runs keep the full matrix and their names.
    - **Permissions.** `ci.yml` requests no write permission. Its jobs are
      checked against the trusted-fork caller's read-only token when the
      workflow loads, so the alert's `issues: write` lives in the separate
      listener. `scripts/ci/test_runner_health_check.py` pins this, the
      matrix lockstep, the dispatch name suffix and proto-compat's literal
      name and never-skip rule;
      `tests/shell/test_trusted_inputs_validate.sh` pins the ref refusal.
    - **Telemetry.** Dispatch runs record `event_name=workflow_dispatch`, so
      release-leg history moves from `push` to `workflow_dispatch` events.
  - **Go-live and interim gap.** `schedule:` and `workflow_run:` both fire
    only from `main`, so the cron and the alert go live at the first dev →
    `main` promotion that carries them. Until then dev gets no automatic
    release coverage except the promotion push itself; dispatch by hand with
    `gh workflow run ci.yml --ref dev -f legs=release`. That works once the
    `workflow_dispatch:` trigger itself is on `main`, which is unverified
    before then. `gh workflow run release-legs-daily.yml` needs that file on
    `main`. `-f legs=all` runs the full matrix on `dev` or `main`.
  - **Dead-man.** Nothing detects a cron that never fires (the reconcile job
    runs inside it). If no `release-legs-daily` run appears in the Actions tab
    for two days, check that the workflow is enabled.
  - **Bisecting a red day.** A direct dispatch is accepted on `dev`/`main`
    only, and PR runs never build release, so CI cannot bisect it. Bisect
    locally instead: check out each candidate commit and build the release
    configuration (`./scripts/setup.sh --buildtype release --lto --tests`),
    then run the failing test.
- **Tier 3 — nightly cron** (`nightly.yml`, `0 6 * * *` UTC +
  `workflow_dispatch`): ASan+UBSan, TSan, coverage on the Big Tam pool
  (`yuzu-bigtam-linux`, gated on `bigtam_pool_healthy`), plus a Windows ASan
  leg (`windows-asan`, agent-only, Wee Tam pool, gated on
  `weetam_pool_healthy`) covering the Windows-only spark mechanisms that the
  Linux sanitizers can't reach (#1934a). On any leg failure, or a leg ending
  `cancelled` (a timeout) while the run itself was not cancelled, the `alert`
  job auto-opens or comments on a `nightly-broken` issue.
  **Discipline norm: no merge to main while a `nightly-broken` issue is
  open.**

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

### Browser smoke (`/test` Phase 5, `tests/puppeteer/ui-smoke.mjs`)

A gate in two parts. The live scenarios run from `/test` only: they need a running dashboard, so they
are not a required CI job. The selftest pair also runs in CI, in the path-filtered, non-required
`ui-smoke-selftest` workflow (`.github/workflows/ui-smoke-selftest.yml`, described below). In `/test`
the gate drives a headless browser against the running dashboard: it crawls every route the shell nav
links to (200, the `Content-Security-Policy` header, no page error, `console.error` or HTTP status of 400 or more), cross-checks the
discovered routes against `EXPECTED`, a hand-copied list of the nav in `app_shell.cpp`, in both
directions, checks that submit controls stay inside their form or dialog at two viewport sizes,
and runs nine scenarios (five that each force their own precondition, with writes answered by a
request stub in the browser so nothing reaches the server; the DEX Apps tab: a live keyboard half
plus a committed golden page served through a GET stub; a held Apps response superseded by Overview;
the DEX controls operated from the keyboard; and the Find software panel on `/software`: live
searches plus Load more served through a GET stub). The gate first runs
`ui-smoke.mjs --selftest`, which checks against a local fixture (no stack) that each crawl and
layout check fails when it should, and that the Apps expander check fails on the committed golden when
its `:has()` rules are removed; a selftest failure fails the gate.

The selftest half also runs in CI: the path-filtered `ui-smoke-selftest` workflow
(`.github/workflows/ui-smoke-selftest.yml`) runs `node tests/puppeteer/ui-smoke.mjs --selftest` on a
hosted `ubuntu-24.04` runner when `server/core/src/*_ui.cpp`, `server/core/src/dex_pane.hpp`,
`server/core/src/dex_routes.cpp`, `server/core/src/plural.hpp`, `server/core/static/**`, `tests/puppeteer/**`, the Apps goldens or the install script change. It is **not a required check**: it
is path-filtered, and the `dev` ruleset blocks a merge on a required check that was skipped. The live
half (the scenarios against a running dashboard) stays in `/test`, because it needs the UAT stack. A failure records FAIL (the
older `Puppeteer` gate is warn-only). `/test` Phase 0b runs `scripts/test/ensure-puppeteer.sh`,
which installs the Node dependencies and Chrome for Testing when absent and proves the browser
launches headless; if it cannot, the run aborts before the build. A missing
`tests/puppeteer/node_modules/puppeteer` at Phase 5 records FAIL, never SKIP.
`/test` Phase 0b also runs `scripts/test/ensure-gcovr.sh` (Linux only). A gcovr you already have at the
version pinned in `requirements-ci.in` that can produce the gate's reports is used as it is; otherwise it
installs that version from the hash-pinned `requirements-ci.txt` (the file CI uses) into a private
virtualenv. If neither works, default mode records WARN and Phase 7b measures nothing; `--full` stops in
Phase 0b.
Phase 7b re-checks gcovr before it measures (another worktree may have rebuilt the shared virtualenv since):
if it is no longer usable the Coverage gate is not run and is recorded as WARN in default mode and as FAIL
in `--full`.
Shared browser mechanics are in `tests/puppeteer/lib/harness.mjs`;
`tests/puppeteer/README.md` covers running it by hand.

### Release re-publish guard (`release-guard`, #5282)

The first job in `release.yml`. It refuses any run whose ref is not a tag
(a `workflow_dispatch` from a branch would otherwise pass, since a branch has
no release, and push `:latest` from branch content) or whose tag is not shaped
`vX.Y.Z` / `vX.Y.Z-{alpha,beta,rc}N` (the alphabet the prerelease classifier
and the `:latest` enable assume). It then reads
`gh api -i repos/<repo>/releases/tags/<tag>` and fails the run if the tag
already has a published GitHub release. Every image-publishing job
(`docker-publish`, `docker-publish-postgres`, `docker-publish-chisel`,
`docker-publish-agent-bundle`), the `release` job and the three build jobs list
it in `needs`, so a refused run stops before any build, provenance attestation
or image push. Before it, a run started against an already-released tag (by
mistake, or a superseded run) pushed new digests over `:X.Y.Z` (and
`:X.Y`/`:latest` on a stable tag) that no longer matched the release's signed
`SHA256SUMS` and SBOMs; the only existing-release check was in `Create GitHub
Release`, after every push, and it skipped with a notice and went green. That
step now fails instead, because a release appearing there means one arrived
after the guard ran.

It fails closed on the HTTP status line alone: `404` proceeds, `200` refuses,
and anything else (no status line, 401/403/429/5xx) fails the run. gh's exit
code and stderr prose are never interpreted. The step body is executed against
a stubbed `gh` by `tests/shell/test_release_guard.sh` (in preflight's shell
gate tests), which also checks that every job holding `packages: write` needs
the guard.

**Per-push tag re-check.** Two runs for one tag at different commits (a re-tag
while a run is in flight, or a moved tag whose push webhook never fired) both
pass the guard, because no release exists yet. So every image push and the
release creation run `scripts/ci/check-release-tag-sha.sh` immediately before
acting: it reads the tag from `origin` with `git ls-remote` and refuses unless
the tag (or its peeled commit) is still this run's `GITHUB_SHA`, failing closed
on any error. A run whose tag has moved away from its commit refuses at its
next publishing step, and a re-run of a failed job re-checks too. It cannot
see a tag moved away and back again while two runs are in flight (A -> B -> A):
cancel in-flight release runs for a tag before re-tagging it (#5478). The script is tested by
`tests/shell/test_release_tag_sha.sh`; `test_release_guard.sh` checks that
each publishing job runs it once, before its first push.

**There is no override.** A published release's assets and signatures describe
the images it shipped, so any re-push over it breaks verification. To ship
different images, cut a new version. To redo a release whose published content
is itself wrong, delete the GitHub release first (destructive; the release
skill requires operator confirmation), then start a fresh run, which recreates
the release with a `SHA256SUMS` that matches its images.

Limits: the guard's read-only token cannot see a **draft** release — one made
by hand, or one `gh release create` leaves behind when interrupted while
uploading assets (it creates a draft, uploads, then publishes). The `release`
job's own check sees drafts and fails. Deleting an unpublished draft is not
destructive (nothing was published): delete it, then re-run failed jobs on the
newest run.

Residual paths that can still leave `:X.Y.Z` digests and the signed
`SHA256SUMS` apart, none closed by this change: a draft release the guard
cannot see; a hand-run `gh release create`; the seconds between a publish
step's tag re-check and its push; a tag moved away and back again while two
runs are in flight (#5478); re-running an OLDER run of the tag (#5242: a re-run
does not repeat `release-guard`); and `:latest`/`:X.Y` landing on an older
version when runs for two tags finish out of order (#5462).

### Release artifact gate (`scripts/check-release-artifacts.sh`, release job)

Runs in `release.yml`'s `release` job after the artifacts are downloaded and
flattened, and before `SHA256SUMS`, signing, the `.intoto.jsonl` bundles and
`gh release create`. When it fails, no GitHub release, `SHA256SUMS` or
signature exists yet, but **the container images are already published**:
the `release` job needs `docker-publish`, `docker-publish-postgres` and
`docker-publish-chisel`, which have moved `:X.Y.Z` (and, on a stable tag, `:X.Y` and
`:latest`) to their verified, signed digests first (each of their publish journals
ends `tagged`; the agent-bundle image needs `release`, so it is not
published), and the build jobs' provenance attestations are already recorded.
An image is never published ahead of a failed build: every image-publish job (`docker-publish`,
`docker-publish-chisel`, `docker-publish-postgres`) also needs all four builds
(`build-linux`, `build-gateway`, `build-windows`, `build-macos`; ADR-0035 step 3,
a success gate, not an artifact dependency), so a failed build, including a failed
agent packaging step, pushes no versioned image.
`docker-publish-chisel` joined the release's needs in #5242, so the release
waits for the chisel builds (minutes with a warm cache, much longer cold) and
the three chisel images' SBOMs are always release assets, inside `SHA256SUMS`;
before that they were attached only when those jobs finished first, and rc2,
rc4 and rc6 shipped without some of them. On a stable tag `:latest` therefore points
at a release that does not exist until the release is fixed. It fails the
release when:

- an expected archive, installer glob or SBOM is missing or empty (#362/#408);
- an asset name contains a character GitHub rewrites on upload (anything but
  letters, digits, `.`, `_`, `-`, or a name not starting with a letter or
  digit), which would make `SHA256SUMS` and the provenance name an asset that
  does not exist (#5141);
- a `.deb`/`.rpm`/`.exe`/`.pkg` does not carry the tag's version in the form
  its builder writes; the error prints the expected pattern (#5141). The usual
  cause is a package left in a reused self-hosted workspace by an earlier
  build of another version.

Recovery: find the offending file in the error. For a stale file, clear the
runner workspace and start a fresh run of the same tag with
`gh workflow run release.yml --ref vX.Y.Z`, following the release skill's
Recovery steps (no release exists for the tag, no other run for it is queued
or running). "Re-run failed jobs" does not fix this case: it re-runs only the
`release` job, which downloads the same stale artifact again. The workflow
enforces the first of those steps itself: `release-guard` refuses a run when
the tag already has a published release (#5282, above). For any other failed
job, recovery is "Re-run failed jobs" on the NEWEST run for the tag (digests
kept; each push re-checks the tag), never on an older run (#5242); a fresh run
is the fallback (release skill, Recovery).
For a builder naming defect, a fresh run builds the tag's original commit
again, so fix the builder, then delete and re-push the tag at the fixed commit.
Either way the images are rebuilt and re-pushed under the same tags.

If the release cannot be fixed promptly on a stable tag, move `:latest` back
to the previous release's images. The gate has no override; the naming forms
it checks are a second copy of the builders' naming, and its header lists
where each lives.

### Linux ELF floor gate (`scripts/ci/check-elf-floor.sh`, ADR-2003 S0)

Every Linux native artifact carries the glibc / libstdc++ floor of the host
that built it by accident (#5143). The gate makes the floor an explicit,
committed promise and measures every build against it. It is specified by
ADR-2003 (Accepted, PR #5631). **In S0 it is
report-only: nothing it finds can fail a build or a release.** S2 turns it on.

- **The script** runs `objdump -T` and `readelf -d` over every ELF under a
  staging directory and compares the versioned symbols it imports
  (`GLIBC_x.y`, `GLIBCXX_x.y.z`, `CXXABI_x.y.z`, `LIBSYSTEMD_n`, `BLKID_n`,
  `OPENSSL_x.y.z`, anything else reported verbatim) with a floor file, by
  numeric version. It also flags any forbidden symbol (`EVP_sm4_*`) and any
  `RUNPATH`/`RPATH` entry not anchored at `$ORIGIN`. The header of
  `scripts/ci/check-elf-floor.sh` is the canonical reference for the flags,
  exit codes, floor-file schema and baseline schema. Four cases are never read
  as clean: a directory with no ELF in it, an ELF the tools cannot read (or a
  stub with the ELF magic and no room for a header), a directory that cannot be
  listed, and ELFs not reached before the aggregate deadline. Under
  `--enforce` each is an error; in report-only each is a warning and the exit
  stays 0.
- **Modes.** `--report-only` (the default) prints violations, emits
  `::warning::` annotations and a job-summary table on GitHub Actions, and
  exits 0. `--enforce` exits 1 on any violation. It is implemented and tested
  but wired nowhere yet. Usage and configuration errors exit 2 in both modes.
- **Floor files** are `deploy/packaging/linux-floor-agent.json` (glibc 2.28,
  `GLIBCXX_3.4.25`, `CXXABI_1.3.11`, `LIBSYSTEMD` 239 plus the Red Hat
  `LIBSYSTEMD_240` backport, `BLKID_1.0`) and
  `deploy/packaging/linux-floor-server.json` (glibc 2.34, `GLIBCXX_3.4.29`,
  `CXXABI_1.3.13`, `OPENSSL_3.0.0`, `LIBSYSTEMD_240`, `BLKID_1.0`, forbidden
  `EVP_sm4_*`; also the gateway's ERTS and OTP). They state the promise, not a
  measurement. Changing one is a floor decision (ADR-2003, accepted in PR #5631:
  "Floor review rule"), not a tuning edit. A typo in a family key would silently
  ungate that family (families absent from `max` are only reported), so the
  loader requires `GLIBC`, the script reports a measured family one edit away
  from a listed key, and the test pins the exact key set of both shipped
  files.
- **Baseline.** `deploy/packaging/linux-floor-baseline.json` is the measured
  gap of the v0.14.1 Linux x64 release artifacts (`agent`, `server` and
  `gateway` sets: per ELF the highest tag per family and the offending
  symbols). It is evidence, not an input: nothing reads it to decide pass or
  fail. To regenerate it from a release, download and extract the release
  tarballs into empty scratch directories (check each against the signed
  `SHA256SUMS`; the v0.14.1 values are `yuzu-linux-x64.tar.gz`
  `46e42df0026eb57460414c6c62bf7ab9ef9816e1f8c799286006fde61cc0385f` and
  `yuzu-gateway-linux-x64.tar.gz`
  `e4d45e0f256801af5fe28c188431221df87e0274dabaa48e768464706ecae1eb`), then
  run the script once per set against the same output file (each run replaces
  only its own set):

  ```bash
  B=deploy/packaging/linux-floor-baseline.json; rm -f "$B"
  scripts/ci/check-elf-floor.sh --floor deploy/packaging/linux-floor-agent.json \
    --dir <the yuzu-<VERSION>-linux-x64 directory inside the tarball> \
    --exclude bin/yuzu-server --set-name agent \
    --source "v0.14.1 yuzu-linux-x64.tar.gz (all ELFs except bin/yuzu-server)" --emit-baseline "$B"
  scripts/ci/check-elf-floor.sh --floor deploy/packaging/linux-floor-server.json \
    --dir <the yuzu-<VERSION>-linux-x64 directory inside the tarball> \
    --include bin/yuzu-server --set-name server \
    --source "v0.14.1 yuzu-linux-x64.tar.gz (bin/yuzu-server)" --emit-baseline "$B"
  scripts/ci/check-elf-floor.sh --floor deploy/packaging/linux-floor-server.json \
    --dir <the yuzu-gateway-<VERSION>-linux-x64 directory inside the tarball> \
    --set-name gateway \
    --source "v0.14.1 yuzu-gateway-linux-x64.tar.gz (ERTS, NIFs, crypto.so)" --emit-baseline "$B"
  ```

  Run with the real v0.14.1 tarballs this reproduces the committed file
  byte-for-byte; for another release change the version in the `--source`
  labels.

  Point `--dir` at the directory inside the tarball (the one that holds
  `bin/`), not at its parent, so artifact keys carry no version. Output is
  deterministic (sorted, no timestamps or paths): a refresh diffs cleanly. A
  set whose scan was incomplete (a PROBLEM, an unreadable or unscanned ELF)
  carries an `incomplete` list; the committed baseline has none. The
  floor-review rule in ADR-2003 (Accepted, PR #5631) says when to refresh it.
- **Release wiring.** `release.yml`'s `build-linux` job runs the script
  report-only on the staged tarball contents right after "Package archive"
  (agent set, then server set) in a `continue-on-error` step, and uploads the
  per-set text reports, the full per-ELF reports and a `baseline.json` as the
  `linux-elf-floor-report` artifact (14 days). The artifact deliberately has no
  `yuzu-` prefix: the `release` job downloads every `yuzu-*` artifact. The
  step is bounded (`timeout-minutes: 10`, and the script's own aggregate
  deadline of 240s per run), so a hung `objdump` cannot stall a release for
  long. The release step does **not** scan the gateway at all until S3; the
  `gateway` set in the committed baseline was measured by hand from the
  release tarball.
- **Pre-release QA.** `pre-release.yml`'s `install-rpm` matrix gained
  `rockylinux:8` and `amazonlinux:2023` as **non-gating** legs
  (`continue-on-error` via `matrix.experimental`). They are expected to fail
  on 0.14.x artifacts until S2. A failure there turns neither the job nor the
  Pre-release QA report red: a `continue-on-error` leg reports `success` to
  `needs.install-rpm.result`, so the gap is visible in the run graph and in a
  step summary the failed leg writes, **not** in the QA report table.
- **Tests.** `tests/shell/test_check_elf_floor.sh` (in preflight's "Shell gate
  tests") builds fixture ELFs with `gcc` and a linker version script, so the
  tags it checks are synthesized and the result does not depend on the host's
  glibc.
- **Notes for S2 (the slice that enforces).** (a) Only the agent promotes on
  `rockylinux:8`: the server and gateway promise glibc 2.34 and are not
  expected green there, so scope that leg to the agent package or keep it
  non-gating for the others. (b) The gate scans the `${STAGING}` tarball
  directory, but `build-deb.sh` and `build-rpm.sh` read `build-linux`
  directly: point the package builders at the gated directory, or re-run the
  gate on the extracted `.deb`/`.rpm` payload. (c) Flipping `--enforce` makes
  this a release gate; add its entry to "Gates outside the tier ladder" (and a
  routed-concern row) in that change. (d) Remove `continue-on-error: true`
  from the `release.yml` gate step when `--enforce` is wired: a swallowed exit
  1 would never gate. `tests/shell/test_check_elf_floor.sh` runs a tripwire
  (`tests/shell/elf_floor_workflow_tripwire.py`, PyYAML) over every workflow
  and local composite action. It flags a step that runs, or probably runs
  (mode chosen through a variable or env, a wrapper script, a composite
  action), `check-elf-floor.sh --enforce` when the step or its job has any
  `continue-on-error` other than a literal false, when the run text has
  `|| true`, `|| :`, `|| exit 0` or `set +e`, or when the gate's output is
  piped (`| tee`) without `pipefail` (the default `bash -e` would report
  `tee`'s status); report-only steps are never flagged. It is a guard, not a
  proof, and it assumes enforcement whenever it cannot tell. **Not caught:**
  a reusable workflow (`uses: ./.github/workflows/x.yml`) called from a job
  with `continue-on-error`; a command held in an env var and run through
  `bash -c "$CMD"` or `eval`; a wrapper outside `scripts/` and
  `.github/actions/`, or code the repo does not contain; shell-level swallows
  such as `|| echo`, `; true` or `trap`; and YAML nested so deeply that PyYAML
  recurses out, which is reported as its own error (exit 4) rather than
  analysed. It is vacuous today (only `--report-only` is wired); its detector
  is pinned on synthetic fixtures, one per bypass shape. The test needs PyYAML: `ci.yml`'s
  preflight installs it hash-pinned, and the test fails (rather than skips)
  under GitHub Actions if it is missing. (e) The report
  artifact is kept 14 days and the results are not in CI history: S2 should
  persist per-release results (commit the baseline diff, or extend the
  CI-history capture) and consider running the gate on the `ci.yml` Linux
  package artifact before tagging. (f) The pre-existing "Package archive" step
  runs `mkdir -p "$STAGING"` without clearing it, so a re-run of the same tag
  on a reused workspace scans stale ELFs: S2 should `rm -rf "$STAGING"` first.
  (g) The gateway is not scanned by the release step until S3.

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
meson `docs` suite runs `tests/test_plugin_readmes.py` on the Linux leg (the `docs` suite
is OS-independent and runs there only, see "Test suites by leg" below): the
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
suite also runs (the touch-rule one off Windows only, #5428).

A third `docs-lint.yml` gate, the personal-data guard
(`scripts/ci/check-personal-data.py`, run `--strict-baseline --ratchet`), keeps
real home paths, SIDs, tailnet IPs, MACs, private keys, consumer e-mail and
tracked session artifacts out of the public tree. The script header and rule 5
of `docs/plugin-readme-standard.md` give the detectors, scope and baseline rules.

### Docs drift gate (`docs` suite + `docs-lint.yml` + `doc-coupling.yml`, `docs/docs-drift-gate.md`)

`scripts/ci/check-docs-drift.py` extends the plugin README idea to the rest of the
product, in two layers. Fact parity (hermetic, in the required `changelog-order` job and
the `docs` suite) asserts every `/api/vN/` route, MCP tool and server/agent CLI flag is
named in the user manual, reusing `check-api-parity.py`'s extractors. It ratchets
against the by-name `scripts/ci/docs-drift-baseline.json` with the same only-shrinks rule
as the definition-description ratchet below. The `doc-coupling-touch-rule` job, in its
own `doc-coupling.yml` workflow so that editing the PR body re-runs it, applies
`scripts/ci/doc-coupling.json`: coupled code changed means a coupled doc changed, or the
body carries `doc-coupling-exempt: <rule-id> — <reason>`. It is advisory until the
repository owner adds it to the required checks. A Claude Code `PreToolUse` hook runs both
layers before `gh pr create`, always using the project tree's own copy of the gate.
Details, the runbook for a `dev` turned red by drift, and how to extend the fact
categories: `docs/docs-drift-gate.md`.

### Definition-description ratchet (`definition-descriptions` job + `docs` suite)

`scripts/ci/check-definition-descriptions.py` lints the description text of every shipped
`InstructionDefinition` (the text an agentic worker reads through `discover_instructions`): the
definition description, each parameter description, each result-column description, and
non-empty tags. It walks the files `server/core/scripts/embed_content.py` ships (every `*.yaml`
under `content/definitions` and `content/packs`, recursively) and lints only documents whose
`kind` is `InstructionDefinition`. It is a ratchet over
`scripts/ci/definition-descriptions-baseline.json`: a failure absent from the baseline is `NEW`
and fails the run, and a baselined failure that no longer fails is `STALE` and also fails it, so
the baseline only shrinks (delete the entry in the change that fixes it). `--update-baseline`
rewrites it from the tree; run it deliberately, never to hide a new failure, and never in CI.

Two places run the same test, `tests/test_definition_descriptions.py`. The `definition-descriptions`
job in `docs-lint.yml` (check name "Definition descriptions") is **advisory**: the workflow's own
header names only "CHANGELOG order" as its required check. It installs PyYAML from
`requirements-ci.txt` with `--require-hashes` (a `--user` install, skipped when PyYAML is already
importable), so it reaches PyPI and is its own job so that an outage reds only this check. The
same test is registered as the `definition descriptions` test in `tests/meson.build` (suite
`docs`), and the `linux` job of `ci.yml` lists `--suite docs` (the Linux leg is the only one that
runs that suite, "Test suites by leg" below), so the ratchet is enforced on the required
`Linux gcc-15 debug` leg without depending on the advisory job. A PR that changes only `docs/**` or root `*.md` builds nothing (see "Docs-only changes"),
but it cannot touch `content/` or the baseline, which are classified as code.

### Execution owner key tripwire and self-test (`docs` suite + `docs-lint.yml`, #5557)

`tests/test_execution_owner_key_tripwire.py` is a best-effort lexical check, not a control-flow
proof, that execution admission is keyed on the owner key and that neither list gate hands a
service-scoped session unrestricted authority; its self-test
(`tests/test_execution_owner_key_tripwire_selftest.py`) mutates the server sources in memory and
proves each mutation is caught. The tripwire runs as a step of the `changelog-order` job (check
name "CHANGELOG order", the required one). The self-test costs about half a minute of CPU, more on
a hosted runner, so it is its own job, `execution-owner-key-selftest` (check name "Execution owner
key tripwire self-test"), which keeps it out of the required check's five minute budget. That job
is **advisory**: the workflow's own header names only "CHANGELOG order" as required, and the
repository owner may add the job to branch protection. Both tests are also registered in
`tests/meson.build` (suite `docs`), and the `linux` job of `ci.yml` lists `--suite docs`, so the
self-test still gates on the required `Linux gcc-15 debug` leg without depending on the advisory
job. A red self-test job means a frozen set no longer matches or a mutation went undetected; it is
fixed by reviewing the edit, not by re-running the job.

### ClusterFuzzLite (`cflite-pr.yml` + `cflite-batch.yml`)

PR-scoped libFuzzer fuzzing of the untrusted-input parsers (target
inventory: `.clusterfuzzlite/README.md`). Not a required status check, and
deliberately path-gated to the fuzzed compile closure — seven parser families
(six under `server/core/src/`, the component_inventory ZIP reader under
`agents/plugins/component_inventory/src/`) plus `tests/fuzz/` and `.clusterfuzzlite/` — so
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

The `server` role also probes one non-healthcheck dependency of the same image:
the reference compose's one-shot `ca-export` service
(`deploy/docker/docker-compose.reference-gateway.yml`) runs the server image with
`/bin/sh -ec` and calls `install`, so the probe checks that `/bin/sh` runs and
`install` is on its path, and a base-image change that drops either fails the
gate instead of leaving the agent's `depends_on: ca-export` waiting forever. It
runs as the image's default user while `ca-export` runs as root, so it proves
presence and executability, not that user's write access.

`yuzu-postgres` is published and healthchecked too (`pg_isready` + `psql`), but it
is `FROM postgres:*` — those tools are the image's whole purpose — so it has no
role in the gate and `docker-publish-postgres` has no pre-push check. `agent-chisel`
is gated **pre-emptively**: no compose healthchecks an agent image today.

The probes are a hard-coded copy of the healthcheck commands, so both the script
and the workflow's change-filter carry a **KEEP IN SYNC** list of every file that
defines one — including the easy-to-miss
`scripts/test/docker-compose.upgrade-test.yml`. `pre-release.yml` no longer
inlines a compose stack: its integration, soak and upgrade jobs run the shipped
`deploy/docker/docker-compose.reference-gateway.yml` through
`scripts/ci/qa-stack.sh`, so that template's server healthcheck is the one they
exercise.

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

**`gateway-base-index` job (#6711).** The same workflow also runs one plain (non-matrix)
job, "Gateway builder index matches runtime Alpine", whenever the classifier says the
image surface changed. It runs `scripts/ci/check-gateway-base-index.py` on a hosted
runner with no Docker: it fetches the pinned `erlang:28-alpine` index from Docker Hub
(anonymous, retried, body hashed against the pinned digest) and fails when a platform
on `Dockerfile.gateway`'s `# yuzu:gateway-platforms` marker (today `linux/amd64`) is not
annotated as built on the runtime stage's Alpine release. That is the early check on a
Dependabot digest refresh; the build's abi-guard stays the build-time enforcement.
Exit 1 is a mismatch, 2 an unreadable registry or a body that is not the pinned digest (the
log says whether a re-run can help), 3 an input the script does not understand. A skipped
plain job satisfies a required check, so it needs no stub. To disable the networked
check, put `if: false` on the job (and take it out of branch protection first if it was
ever made required). Keep the script, `tests/test_gateway_base_index.py` and
the `docs-lint.yml` "Gateway base index lint" step: that test also holds the executed
arch-guard contract for `Dockerfile.gateway`.

The PR matrix reuses release.yml's local buildcache **read-only** (`cache-from`
with no `cache-to`), so it never evicts release layers and adds no cache directory
`cache-prune.yml` doesn't know about. Inside `release.yml` the verification build
likewise has no `cache-to`: it shares one buildkitd instance with the push build,
so the push hits BuildKit's own solver cache and rebuilds nothing.

### Release image vulnerability gate (`scripts/ci/image-vuln-gate.sh`, WP15/S9)

**What it checks.** Every image `release.yml` publishes (server, gateway, postgres, the three
chisel variants and the agent bundle) is scanned with a pinned Trivy **before it is pushed**.
The gate fails when an image has a CRITICAL vulnerability that has a fix available and is not
accepted in `.trivyignore.yaml`. HIGH findings and unfixed CRITICALs are printed for the record
and do not fail it. It also fails, rather than pass a scan that could not mean anything:

- a scan that cannot complete (Trivy error, DB download failure, wrong Trivy version, missing
  ignore file);
- the **DB**: downloaded once per run into a fresh, empty cache directory the script creates in
  its per-run work directory; an inherited `TRIVY_CACHE_DIR` is ignored (with a note), so a
  preseeded cache can never be scanned with. Each source's tag (`mirror.gcr.io/aquasec/trivy-db:2`,
  then `ghcr.io/aquasecurity/trivy-db:2`) is first resolved to its manifest digest and the download
  pinned to `repository@digest` (Trivy checks the manifest and layers against it); that
  `repository@digest` is recorded in every `.gate.txt` and the step summary. The gate fails when
  no source can be resolved and downloaded, or when the DB's `UpdatedAt` is older than 72 hours,
  more than an hour in the future, or unreadable, or its `DownloadedAt` is earlier than the run.
  Every scan then runs on that one DB (`--skip-db-update`). **The DB is not signed upstream:**
  `aquasecurity/trivy-db` is pushed with `oras` and carries no cosign signature, no OCI referrer
  and no GitHub attestation (checked 2026-11-18 with `cosign tree`, the referrers API and the
  attestations API), so the gate cannot verify it. A DB substituted at, or on the way from, the
  registry is detectable only by TLS to the registry and, after the fact, by the recorded digest;
  a tampered DB with a fresh `UpdatedAt` (one CVE's version range edited) passes the gate. Every
  long call has its own deadline and the gate has an overall budget ("Time budget" below), so a
  registry that trickles bytes ends the attempt instead of holding the job until its timeout;
- **no advisory data for the OS release**: Trivy marks the OS end of service life
  (`Metadata.OS.EOSL`), or its family is not one the gate has a canary for (Debian, Ubuntu, Alpine:
  every image the release publishes), or its version is a pre-release (`verdict=pre-release`, "no
  advisory data for a pre-release": `_alpha`, `_beta`, `_pre`, `_rc`, `_git`, `~`, `-rc`, `.rc`,
  `sid`, `testing`, `edge`, ...) or not a released version number (`N`, `N.N`, `N.N.N`), or the
  canary matches nothing. A pre-release is refused before the canary because Trivy reads it against
  the released version's advisories (Alpine `3.24.0_alpha...` as 3.24, Debian `13.0~rc1` as 13), so
  the canary would match and the image would read as covered. The canary is a tiny root
  filesystem of the image's exact OS release holding `openssl` and `zlib` at versions older than
  every fix, scanned against the run's DB once per OS release per run; it proves the DB holds
  advisories for that release. Trivy matches nothing for an OS release with no advisory bucket, so without this an
  image on Debian testing/sid (Trivy reports `forky/sid`), Alpine edge or an Ubuntu devel series
  (read as Debian sid) reads as scanned and clean (checked 2026-11-18: `debian:sid-slim` had 77
  packages, 0 findings and was `covered`). Trivy's "not on the EOL list" warning is not used: it
  also fires for Ubuntu 26.04, which has data;
- **no OS packages seen**: an image whose OS package scan found no package (no OS detected, or a
  0-package OS target) was not scanned for OS vulnerabilities, so the gate fails unless the image
  is listed, in force, in `scripts/ci/image-vuln-gate-not-covered.txt` (exact name match). Each
  listing carries the reason, `approved_by`, `approved_on`, `approval_ref` (the approving pull
  request) and an expiry at most 92 days out; an expired listing is not in force, and one whose
  `approval_ref` is `pending` is not in force in a release (`--release`). A listed image is
  printed as `NOT COVERED` (and a step warning) on every run. Today four images are listed: the
  three chisel images and the agent bundle. They are assembled FROM scratch from chisel slices,
  which leave no dpkg database (and no chisel manifest, because they do not cut
  `base-files_chisel`), so Trivy 0.70.0 reports "No OS package is detected". **Their libc6,
  libssl3t64, zlib1g and other slices ship unscanned.** The gate learns an image's name from
  `NAME=IMAGE` (release.yml) or the tag (pre-release.yml); a bare image ID can never match the list.
- an ignore file that `scripts/ci/image-vuln-gate-checks.py` does not accept (below).

The environment cannot steer the scan: the script clears every inherited `TRIVY_*` variable
(`TRIVY_CACHE_DIR` included), names the DB repositories explicitly, and gives Trivy an empty
config file so a `trivy.yaml` in the working directory is not read. `TRIVY_BIN` (use another trivy
binary) is for local runs and tests and is refused on GitHub Actions. `YUZU_TRIVYIGNORE` (another
ignore file) goes through the same parser, and Trivy never reads the named file at all: it reads
the checker's canonical YAML copy of the entries in force, so a plain-format file or an entry the
parser did not see cannot reach it. Trivy's temporary files go under the script's own work
directory.

**Time budget.** Every long call runs under `timeout`, bounded by its own deadline and by what is
left of the gate's overall budget: the DB digest lookup 60 s per source, the whole Trivy download
(all of curl's retries) 180 s, each DB download 420 s per source, each scan 600 s (with Trivy's own
`--timeout` 10 s inside it; Trivy's default is 5 minutes). The network calls alone are at most
2 x 60 + 180 + 2 x 420 = 1140 s (19 minutes) with both DB sources failing slowly. The budget is 1500 s
(25 minutes) by default (`GATE_BUDGET`; `--budget SECONDS` overrides it, 1 to 3600): when it runs
out the gate stops, writes `gate: FAIL: gate stopped before this image was judged: the gate ran out
of its <N>s budget` for every image not yet judged, and exits 1. So the gate ends by itself, with its
reports, within its budget plus a few seconds (the 2 s `--kill-after`, the cleanup).
`pre-release.yml`'s `security-scan` (timeout 30 minutes) passes `--budget 1200`, leaving 10 minutes
for checkout and the seven pulls before it; the `release.yml` jobs that run it have 60 to 120 minute
timeouts, but each builds its image first, so a slow build can still bring the job timeout before the
gate's budget, which is then a cancel (next paragraph). `tests/test_image_vuln_gate.py` checks that
every call names a deadline and that each call's budget (or the default), plus 10 minutes for the
job's other work before it, fits its job's `timeout-minutes`; mutants of the pre-release call (raised,
dropped, moved to a continuation line) must fail that check.

**Where.** `docker-publish` and `docker-publish-chisel` scan the image their healthcheck
verification build already loaded (step "Scan image for fixable CRITICAL vulnerabilities
(pre-push gate)", between the healthcheck probe and the tag re-check). `docker-publish-postgres`
gains its own no-push build for the scan. `docker-publish-agent-bundle` runs
`scripts/build-agent-bundle.sh` without `--push`, scans the local image, then pushes it.
`pre-release.yml` `security-scan` runs the same script on all seven published tags afterwards
with a fresher DB (detective: see "Pre-release QA"); it pulls each tag first.

**Evidence.** Each publish job runs the gate with `--release --attempt <run attempt> --report-dir`,
which writes, per image, `trivy-<image>.attempt-<N>.json` (the full Trivy report: image ID, layer
diff IDs, OS, every package, the HIGH/CRITICAL findings and the accepted ones),
`trivy-<image>.attempt-<N>.txt` (the table) and `trivy-<image>.attempt-<N>.gate.txt` (mode, run
attempt, Trivy version, the DB's `repository@digest`, `UpdatedAt` and `DownloadedAt`, image ID, OS,
OS package count, coverage, the advisory canary's result, the ignore-file hash with how many entries
were in force and pending, and the result). A `.gate.txt` is written for every image on every exit
the script reaches after reading its arguments: a refused image's says `gate: FAIL: <reason>`, when
the gate stops before judging an image (a refused ignore file, a stale DB) each image's says why, and
a SIGINT or SIGTERM (a cancelled run or a job timeout) writes `gate: FAIL: cancelled (SIGINT) before
this image was judged` (or `(SIGTERM)`). The step `exec`s the script so the runner's signal reaches
it, and the script runs each long child (Trivy, curl, the digest lookup) in the background and
`wait`s, so the trap runs at once rather than after the scan. The runner cancels with SIGINT, then
SIGTERM about 7.5 s later, then SIGKILL: on the first signal the trap ignores any further SIGINT or
SIGTERM, writes the reports at once, then stops the child (SIGTERM, SIGKILL after 3 s at most) and
exits 130 or 143, well inside the 7.5 s. A SIGKILL, or a usage error before the image list is read,
leaves no report. The `.gate.txt` is the gate script's alone: no other step writes to it. The
upload, as the `<image>-image-vuln-gate-attempt-<N>` artifact (for example
`yuzu-server-image-vuln-gate-attempt-1`) with
`retention-days: 90` (the repository's maximum) and no `overwrite`, runs whenever the gate step ran,
passed, failed or was cancelled (`if: always() && (steps.gate.outcome == 'success' ||
steps.gate.outcome == 'failure' || steps.gate.outcome == 'cancelled')`), so a refusal, the control
operating, is retained too, and **a re-run adds its attempt's reports beside the refused attempt's
instead of replacing them**. The same artifact carries the attempt's publish journal (next
paragraph) when its gate passed; the upload is the job's last publishing-related step, after the tags
move. The `release` job downloads every attempt's gate artifact of the run (`pattern:
'*-image-vuln-gate-attempt-*'` with `merge-multiple`; an artifact an earlier run attempt uploaded is
listed in a re-run, which "Re-run failed jobs" already relies on for the build artifacts) and
attaches every file to the GitHub Release, inside the signed `SHA256SUMS`, the same way it ships the
image SBOMs. `scripts/check-release-artifacts.sh` refuses a release in which a gate report or a
journal is not named per attempt, any journal is not a legal prefix (below) or sits beside a gate
report that does not record exactly `gate: pass`, or, for one of the six images, no attempt's journal
ends `tagged`, an attempt above the published one ends `tagging`, or the published attempt lacks
Trivy's three non-empty reports. Earlier and later attempts' reports may record a failure; they are
kept as the evidence. The agent bundle's job runs after the release exists, so its reports cannot be
inside `SHA256SUMS`; `attach-bundle-gate-report` attaches them to the GitHub Release afterwards. It
runs whenever the bundle job ran at all (`needs.docker-publish-agent-bundle.result != 'skipped'`),
downloads every attempt's bundle gate artifact the same way, fails when there is none, and attaches,
per attempt, its reports, its journal and a checksum list
`yuzu-agent-bundle-chisel-image-vuln-gate.attempt-<N>.SHA256SUMS` signed keyless by the same
`release.yml` identity and verified in-job. Each run of it converges: after the last one, every
attempt's files are on the release.

**The publish journal** (`scripts/ci/image-publish.sh`). A release tag (`:X.Y.Z`, and on a stable
tag `:X.Y` and `:latest`) is public the moment it moves, so it moves LAST, and every push of the
image and every tag move is announced before it runs. (The SBOMs, the provenance attestation and the
cosign signature are pushed as referrers of the digest before `signed-attested` records them: the
digest was announced at `push-started`, and no tag names it yet.) The contract:

- The journal is `publish-<image>.attempt-<N>.txt`, beside the gate's reports. Only
  `image-publish.sh` writes it, appending one line per completed step; it is never rewritten, and
  its LAST line is the state. The only legal contents are a prefix of exactly this sequence, with
  one digest throughout:
  1. `publish: none`, written when the gate passed (the script refuses unless every
     `<scanner>-<image>.attempt-<N>.gate.txt`, Trivy's and any future scanner's, records exactly
     `gate: pass`);
  2. `publish: push-started <candidate>`, appended BEFORE the push (`<candidate>` is the
     repository for a push by digest, or `<repository>:candidate-<run id>-<N>` for the agent
     bundle's `docker push`);
  3. `publish: verified <repository>@<digest>`, after `image-identity.sh verify-pushed` proves the
     digest has the scanned image's layers;
  4. `publish: signed-attested <repository>@<digest>`, after the SBOMs, the provenance attestation
     and the cosign signature are made BY DIGEST and the signature verifies for the workflow's
     identity;
  5. `publish: tagging <tags> <digest>`, appended BEFORE the first tag moves;
  6. `publish: tagged <tags> <digest>`, once every tag, applied with `docker buildx imagetools
     create --prefer-index=false -t <tag> <repository>@<digest>`, resolves to the digest.
- No journal for an attempt means one of three things: its gate refused the image (its `.gate.txt`
  is not `pass`), the job stopped before the journal was opened, or the journal never reached the
  artifact (the evidence upload and its one retry both failed, or the runner was lost: residuals
  below). The first two pushed nothing; the third is absence of evidence, not proof that nothing
  was pushed.
- A failure or a cancellation simply stops the journal. There is no failure label, and nothing is
  written on a cancel. So a journal's last label claims at least what the registry holds:
  `push-started` may have pushed an untagged digest (or the bundle's candidate tag), `tagging` may
  have moved some of the tags. A cancel reaches the script itself: every step runs it as `exec
  scripts/ci/image-publish.sh ...`, because the Actions runner signals only the step's PID (SIGINT,
  SIGTERM 7.5 s later, SIGKILL 2.5 s after that; `actions/runner` `ProcessInvoker`), never its
  process group. On SIGINT or SIGTERM the script stops at the next step boundary: it stops the
  registry call it is waiting on (each runs in the background, so the trap acts at once), appends
  nothing further and exits 130 or 143. No process of it outlives the step to append or move a tag
  after the evidence upload has read the journal (G8P6-chaos-injector-1), in this run or in a later
  run of the same tag (G8P6-chaos-injector-2: the chisel and bundle jobs' `cancel-in-progress`
  groups cancel an older run's leg the same way).
- The pushes carry no release tag: the buildx jobs push with `outputs:
  type=image,name=<repository>,push-by-digest=true,name-canonical=true,push=true` and no `tags:`,
  and the agent bundle pushes `:candidate-<run id>-<attempt>` and resolves its digest. The tags are
  applied only by `image-publish.sh tag`, which moves every one of them from the digest; a failed
  check that a tag resolves to the digest leaves the journal at `tagging`.
- The journal is uploaded with the gate reports under the same `if: always()` status function, and
  a retry step (`if: always() && steps.upload_gate.outcome == 'failure'`, no `overwrite`) uploads
  it again when that upload failed. Job outputs carry no publish state; consumers read the journal
  through `image-publish.sh state` (one attempt) or `published` (all attempts), and accept only a
  legal prefix.
- Across attempts, the published image is the HIGHEST attempt whose journal ends `tagged`. The
  release check and the attach job fail when any attempt above it ends `tagging`: a tag may then
  name either digest. A re-run that completes `tagged` heals it.

**Decision record (2026-11-18).** This contract and the "Future findings on this path" rule
below are the enterprise-architect contract, accepted by the project owner (fjarvis) on 2026-11-18.
After repeated Gate 8 governance passes kept finding orderings in which the publish state reported
by job outputs and the attach job disagreed with what the registry held, the enterprise-architect
review recommended replacing further point fixes with this write-ahead journal and a closed
definition of a defect on this path; the project owner accepted that ruling, and later passes
judge findings on this path by it. Review this decision if a publish job gains a registry write
the journal does not announce, or if a release tag starts moving anywhere other than
`image-publish.sh tag`.

Verified before this contract was frozen (2026-11-18): `docker buildx imagetools create
--prefer-index=false -t <tag> <repository>@<digest>` keeps a single-platform manifest's digest byte
for byte (a local `registry:2`, both a `docker push`ed Docker v2 manifest and a buildx push-by-digest
OCI manifest; without `--prefer-index=false` it wraps the manifest in a new index with another
digest), and a cosign signature made by digest before the tag existed verifies against the new tag;
`actions/download-artifact` v8 lists the run's artifacts through the runtime token's run scope, and
a release run whose attempt 3 re-ran only the Windows build created its release from attempt 1's
`yuzu-*` artifacts (v0.11.0-rc1).

**What the journal does not cover** (residuals, disclosed once here):

- **No evidence reaches the artifact** for an attempt when the runner is killed or lost before the
  upload, or when the evidence upload and its retry both fail (an artifact-service outage). That
  is absence, not disagreement: no journal claims less than the registry holds. Its cost: for one
  of the six images the release job does not run (it needs that job green, and a re-run tags a new
  digest the release then names). For the agent bundle, if that attempt had moved `:X.Y.Z`, the
  attach job reads only the other attempts, so it may name an older attempt as published (or none)
  while `:X.Y.Z` names the missing attempt's verified, signed digest (G8P6-architect-4); the bundle
  job is red. The release skill's terminal check (resolve `:X.Y.Z`, compare it with every journal)
  is how that is caught before the release is announced.
- **A SIGKILL of the script, or a lost runner process, mid-call.** The script stops its own
  registry call within about 3 s of the first signal, well before the runner's SIGKILL (10 s), so
  only a runner that kills or loses the script earlier can leave a registry call running. The
  journal already announced that call; the runner's orphan cleanup (at the end of the job) stops
  what remains unless the runner itself died, and such a call could then still move a tag after a
  later run's `tagged`.
- **A re-run moves the tag to a new digest.** Each attempt pushes and tags its own build; the
  release check requires the release's assets to name the published (highest `tagged`) attempt.
  That holds only until the release exists: re-running ONE publish job by hand ("Re-run job" on a
  green `docker-publish`, `-postgres` or `-chisel` leg) after the release is published reuses the
  earlier `release-guard` result, passes the tag re-check, and moves `:X.Y.Z` (and `:X.Y`,
  `:latest`) to a new verified, signed digest that the release's SBOMs, gate reports and journals
  do not name; its `Create Release` then fails (`already PUBLISHED`). Pre-existing (the old code
  pushed `:X.Y.Z` directly); the release skill forbids it and gives the repair
  (G8P6-unhappy-path-1).
- **Several tags do not move atomically.** That is what `tagging` records; the next attempt to end
  `tagged` moves all of them again.
- **Untagged candidate digests and the bundle's candidate tag stay in GHCR.** A digest that was
  pushed but never tagged (a verify failure, a cancel) and the `:candidate-<run id>-<attempt>` tag
  are not deleted: GHCR deletes a package VERSION, which is the digest itself, and every tag naming
  it goes with it. No journal can say which digests are safe (one ending `tagging` may have moved a
  release tag to its digest, and a `tagged` attempt whose upload failed has none), so the rule is
  the registry's, at delete time: resolve every live tag of the package and refuse any digest a tag
  other than a `candidate-*` tag names. `scripts/ci/image-candidate-delete.sh OWNER PACKAGE
  DIGEST...` does exactly that (it lists the tags with `gh api --paginate
  /orgs/<owner>/packages/container/<package>/versions`, resolves each with `docker buildx
  imagetools inspect`, refuses an index's children too, and refuses everything while a
  `release.yml` run is queued or in progress); it only checks unless given `--delete`, re-checks
  before each deletion, and deletes only when every named digest passes. A deleted digest's
  signature and attestation referrers (`sha256-<hex>.sig`/`.att`) stay behind, tagged, so the
  script refuses them; they are harmless. Confirm with the operator before any deletion.

**Future findings on this path.** A defect is a reachable row (a gate outcome, a point where the
job stops, a publish shape, and for attach an attempt order) in which the journal's last label
claims LESS than the registry holds, or in which the attach job or `check-release-artifacts.sh`
accepts an illegal sequence. Anything else on this path is non-blocking.
`tests/test_image_publish.py` is the table: gate pass, fail, SIGINT, SIGTERM and budget, times
stop points before the push, mid-push, a verify failure or cancel, an attest or sign failure,
before the tags, mid-tag with and without a tag applied, a cancel while `tag` is still loading the
journal, a tag move in flight that would complete later, another writer moving a tag, after the
tags before `tagged`, a failed evidence upload, and complete, for both the buildx and the bundle
shapes, run in `release.yml`'s own step order against a stub registry, with every cancel delivered
to the step's PID only (as the runner delivers it) and the evidence read as uploaded; cross-attempt
rows with the attach job interrupted at each attempt; a cross-run row (an older run cancelled
mid-tag while a newer run publishes); journal-reader rows; and mutants (adjacent step swaps, named
reorders, a dropped intent line, `tagged` recorded early, a writing step without `exec`, a script
that ignores the signal or waits on its registry call in the foreground, unchecked late journal
lines) that must be killed.

It never replaces a completed asset. For each name already on the release (the attach job re-run
for the same attempt) it reads GitHub's asset `state`, `size` and `digest`: an asset whose state is
not `uploaded` (`starter`, `open`: an upload that was interrupted, which GitHub never served), or
whose downloaded bytes do not match GitHub's own size or digest for it, is an incomplete upload, not
evidence, and is deleted and uploaded again; a completed asset is kept when identical to this run's
file (a `.sigstore` when it verifies this run's list) and fails the job when it differs. Every
refusal is decided before anything is deleted, and a failed download stops the job rather than
counting as incomplete. If the attach job fails, the Release run is red, so Pre-release QA does not
start (it runs only on a successful Release run), and the report exists only as the 90-day artifact,
which is shorter than a SOC 2 Type II observation window (except when the only failure is a higher
attempt stopped while tagging: the files are attached first, then the job fails):

- **A transient failure, or an interrupted upload** (a network error, a cosign or GitHub outage, a
  cancel during `gh release upload`): "Re-run failed jobs" re-runs the attach job (and any other job
  that failed); it replaces the incomplete assets and adds the rest. Dispatch `pre-release.yml` with
  the tag if QA still has not started once the run is green.
- **A refusal** (`already on the release with different content`, `does not verify`, or a publish
  journal that is not a legal prefix): a re-run fails the same way. A completed asset under
  this attempt's name with other content means something other than this job wrote it; do not
  delete it to make the job pass. Investigate it as a release-integrity incident with the owner.
- **A higher attempt stopped while tagging** (`stopped while moving the bundle's tag`): the record is
  attached, then the job fails, because `:X.Y.Z` may name either attempt's digest. "Re-run failed
  jobs" re-runs the bundle job; once an attempt ends `tagged`, this job passes. When the bundle
  job's re-run cannot pass (its gate refuses for a reason that needs a commit), this state is
  terminal for the release: do not keep re-running. Resolve `:X.Y.Z` (`docker buildx imagetools
  inspect ghcr.io/<owner>/yuzu-agent-bundle-chisel:X.Y.Z --format '{{.Manifest.Digest}}'`) and
  compare it with every attempt's journal: a digest on a `tagging` or `tagged` line was verified
  and signed before any tag moved (`cosign verify` it), so that is the bundle image this version
  ships, and the announcement says so. A digest on no uploaded journal's line is looked for in the
  bundle job's logs (the script prints every line it records; an attempt whose report never
  uploaded shows its tag move only there); found nowhere, or no tag at all, it is an incident to
  investigate with the owner. The same check applies whenever the run is red around the bundle,
  because an attempt whose evidence never uploaded can have moved the tag (residuals above).

Do not attach the report by hand: a hand upload has no signed checksum list. If the bundle job never
uploaded a report there is nothing to attach; its job log is the record. The report globs
in the release job, `SHA256SUMS`, the release upload, the pre-release upload and the bundle
attachment take every scanner's files (`trivy-*` and `grype-*`), while the coverage check reads
Trivy's JSON report only (it refuses any other). The script also writes a step summary table,
including the rows of a run that stopped early.

**Scanning the right image.** Four Big Tam runners share one Docker daemon, so a tag is not a
safe handle. Each verification build gets a tag salted with the commit, run id and run attempt
(under `yuzu-hc-verify/`, so `cache-prune.yml`'s sweep still reclaims a leaked one), and
`scripts/ci/image-identity.sh pin` resolves it to its image ID once, right after the build;
the healthcheck probe and the gate then use the ID. Every Trivy call passes
`--image-src docker`, so a missing local image fails the gate instead of a same-named image
being fetched from a registry and scanned. The push build is a second build that normally
reuses the scanned build's layers, but nothing forces it to: right after the push, before any
SBOM, attestation or signature, `image-identity.sh verify-pushed` reads the pushed digest's
layer diff IDs from the registry and fails the job unless they equal the scanned image's (the
image config, with its labels and timestamps, legitimately differs); `image-publish.sh verified`
runs it and records the result. The agent bundle is pushed from the scanned local image itself,
under its candidate tag, after checking its local tag still names the scanned ID. A mismatch leaves
an untagged digest (or the bundle's candidate tag) in GHCR, unsigned; no release tag names it, the
journal stays at `push-started`, and the release job does not run.

**Current packages.** The Debian and Alpine images upgrade their packages in the final stage
(`apt-get upgrade`, `apk upgrade`; `yuzu-postgres` holds the PGDG server packages so the
PostgreSQL minor stays the pinned one), and the chisel images cut their slices from the live
Ubuntu archive. A package index that cannot be fetched fails the build: the Debian runtime
stages run `apt-get update --error-on=any` (plain `apt-get update` exits 0 when, say, the
security pocket is unreachable, and the upgrade then ships without it; checked 2026-11-18 on
bookworm's apt 2.6 and trixie's apt 3.0, both exit 100 with the option), and Alpine's
`apk upgrade` already refuses an unavailable repository (exit 99). After the upgrade each Debian
build logs what apt still keeps back (`apt-get -s upgrade`). The Big Tam publish jobs build with
a persistent local cache, so each of those steps reads the `YUZU_PACKAGE_REFRESH` build argument,
which the workflow sets to `<run_id>-<run_attempt>`: every run attempt takes current packages,
and the scan build and the push build of one attempt share the layer. That writes new blobs into
the cache on every attempt; `cache-prune.yml` removes the ones no cache index references (see
"Cache pruning + weekly maintenance"). `tests/test_image_vuln_gate.py` (`docs` suite) is a
lexical tripwire over every workflow job: it flags a job whose steps match a push marker (the
`push:` input, `docker`/`podman`/`buildah`/`nerdctl` push or manifest push, one through a
variable named for the tool, `--push` or `--push=true`, an `--output`/`-o`/`outputs:` of
`type=registry` or `push=true`, a registry copy or retag with `imagetools create`, crane, skopeo,
oras, regctl or `cosign copy`), following local composite actions, local reusable workflows and
the repository scripts a job names, and counting a remote reusable workflow as a push; it fails
unless the job is a gated release job or listed as not a release image. It reads text, so it
cannot see a push assembled at run time (an `eval`, a command read from a file) or inside a remote
action. It also pins the gate-before-push order, `--release`, the evidence upload and its status
function, `--error-on=any` and the refresh argument.

**Trivy.** The script downloads Trivy `0.70.0` and checks it against a sha256 pinned in the
script (the release's checksums file and tarball were verified with `cosign verify-blob` when
pinned; re-verify on a bump). It installs into `RUNNER_TEMP` and keeps its DB there, never under
`$HOME`: the four Big Tam runners share one OS identity (#1871). No marketplace action is used.
Trivy (Apache-2.0) is a CI-time tool only; it ships in no image.

**Accepting a finding.** Add an entry to `.trivyignore.yaml` with a scope, a `statement` (why it
does not apply, with the evidence), an unquoted `expired_at` at most 92 days out, `approved_by`
(the GitHub login of the person who accepted it), and `approval_ref` (the pull request in which
they approved it, `"#N"` or its URL) with `approved_on` (the date). The scope is never a bare CVE
id: a `paths` item is one concrete relative path to a file in the image (it contains a `/`; no glob
character, no empty string, no leading `/`, no `.`/`..` component, and not a Trivy result target,
class or type name such as `Python`, `Node.js`, `Java`, `gobinary` or `os-pkgs`), because Trivy
matches `paths` as globs against a package's path AND its result's target, and an OS package's path
is empty: `**`, `*` or `""` would suppress the CVE in every package, and `Python` in every Python
package (verified with Trivy 0.70.0: an entry scoped `Python` hid CVE-2020-14343, a fixable CRITICAL
in PyYAML 5.3.1, from a `--release` run). A `purls` item is a full package URL with its version,
because Trivy matches a purl without one against every version. Until the approval is recorded,
`approval_ref: pending` (and no `approved_on`) records a proposed acceptance: the release gate
(`--release`) does not honour it, local runs and the post-release scan do and report it as pending.
`image-vuln-gate-checks.py` parses the file (a strict block-style subset of YAML: flow style,
anchors, a comment after a value, an unknown key or a second top-level section are refused, so a
decoy line cannot satisfy it), the gate refuses a file that breaks any rule, and Trivy reads only
the checker's canonical copy of the entries in force. It warns 21 days before an entry expires. An
expired entry is not in force, so the next release fails on that finding again. Today there is one
entry: the Go standard library CVE-2025-68121 in the upstream postgres image's `gosu` (gosu does not
link `crypto/tls`), with `approval_ref: pending`, as are the four not-covered listings: until an
approval is recorded in them, a release fails at the postgres and chisel legs. The entry is a
commit, so it is in the tag a release builds: it can only help a release cut after it.

**What the approval fields are, and what the control is.** `approved_by`, `approved_on` and
`approval_ref` are a RECORDED REFERENCE: the gate checks that they are present and well formed (a
GitHub login, a past date, `#N` or a pull-request URL) and nothing else. It does not ask GitHub
whether that pull request exists, was merged, or was approved by `approved_by`, so a typed `"#9999"`
with a date passes it exactly like a real approval. They are not a verified approval and no
document may present them as one. The control is human review of every change to
`.trivyignore.yaml`, `scripts/ci/image-vuln-gate-not-covered.txt`, the gate scripts
(`scripts/ci/image-vuln-gate.sh`, `scripts/ci/image-vuln-gate-checks.py`,
`scripts/ci/image-identity.sh`, `scripts/ci/image-publish.sh`, `scripts/check-release-artifacts.sh`) and the workflows that run them
(`release.yml`, `pre-release.yml`): the approval is the review of the pull request that adds or
changes the entry, and the fields record where to find it. That review is as strong as the branch
protection that requires it.

**The approver can be the change's author.** Nothing in the gate, the checker or the format stops
`approved_by` from naming the person who wrote the entry. GitHub does not let a pull request's
author approve it, but nothing ties `approved_by` to whoever did review it, and without branch
protection that requires a review the pull request can merge with none. Separation of duties
therefore rests entirely on that branch protection, and it is not enforced: the `.github/CODEOWNERS`
entries for these paths will request a review from either owner (`@fjarvis`, `@Tr3kkR`) once PR
#8243 is merged (until then nothing requests one), and they only REQUEST it: "Require review from
Code Owners" is off on the Protect Dev and Protect Main rulesets by owner decision (2026-11-18), and both owners can bypass the rulesets as organisation admins. So any one
approval merges a change to an acceptance, a not-covered listing or the gate, and an approver
recorded in `approved_by` may be the change's own author. By practice, when one of the two owners
writes an entry, the other approves it; a reviewer of these paths checks that the named approver
actually approved.

**Recording an approval.** For an acceptance or a not-covered listing:

1. Open a pull request that adds (or changes) the entry with `approved_by: <the approver's login>`
   and `approval_ref: pending` (no `approved_on`; in the not-covered list, `approved_on=-
   approval_ref=pending`), and the evidence in `statement` (or `reason=`). A pending entry is not
   honoured by a release, so merging it changes no release yet.
2. The approver reviews that pull request and approves it in GitHub's review UI. The approval is
   that review; it is not given anywhere else.
3. In the same pull request, after the approving review, set `approval_ref` to that pull request
   (`"#N"`, or its URL) and `approved_on` to the date of the review (in the not-covered list,
   `approved_on=<YYYY-MM-DD> approval_ref=#N`). A push after an approval may dismiss it under the
   branch rules; then the approver re-approves the final diff, and `approved_on` is that date.
4. Merge. Before tagging, the release skills run `python3 -I scripts/ci/image-vuln-gate-checks.py
   pending .trivyignore.yaml scripts/ci/image-vuln-gate-not-covered.txt`, which fails while any
   entry in force is still pending, and while any entry or listing has expired or expires today or
   tomorrow (each publish leg re-reads the date, so one that lapses during the release fails the legs
   that run after it); it warns for one expiring within 21 days.

Steps 1 and 3 are alternatives for when the reference is filled in: in the same pull request after
the approving review (step 3), or in a follow-up pull request after merging the pending entry (step
1). Either way, a tagged tree that still holds a pending entry fails the pre-tag check.

Whoever audits an acceptance later follows `approval_ref` to the pull request and checks the
approving review there; the gate does not.

**When it fails.** The leg whose gate failed pushed nothing (a failure in "Verify the pushed image
is the scanned one" pushed an untagged digest: see that paragraph and the release skill). Its sibling matrix
legs are `fail-fast: false`, so they may already have moved `:X.Y.Z` (and, on a stable tag,
`:X.Y` and `:latest`, leaving those tags on a mix of this release and the previous one), and the
release job does not run (same state as any other publish failure; the release skill's Recovery
covers it, including moving `:latest` back). Read the step log first. For every publish job
except the agent bundle:

- **A distro package with a fix**: the fix usually landed after the run started. "Re-run failed
  jobs" on the newest run takes current packages (the refresh argument changes per attempt).
- **A stale DB** (`more than 72` in the log): the published DB is rebuilt every few hours and
  the mirror normally lags by under a day, so wait and "Re-run failed jobs"; if it stays stale,
  check whether the mirror or Trivy's DB publishing is broken before anything else.
- **OS packages not scanned** (an image newly showing 0 OS packages): something removed the
  package database from an image that used to have one. Fix the image; listing it in
  `image-vuln-gate-not-covered.txt` is a reviewed decision that its OS packages ship unscanned.
  Either is a commit, so re-tag. On a listed image the log says why the listing is not in force:
  it expired (re-review it), or its `approval_ref` is `pending` (record the approval, above).
- **An acceptance `NOT IN FORCE`**: its `approval_ref` is `pending`. Record the approval as
  "Recording an approval" describes; a commit, so re-tag.
- **No advisory data** (`end of service life`, `no advisory data`, `no advisory data for a
  pre-release`): the image's base moved to an unreleased, pre-release, rolling or end-of-life OS
  release. Move it back to a released, supported one; a
  commit, so re-tag. An unknown OS family needs a canary added to `image-vuln-gate-checks.py`
  first.
- **An acceptance that expires mid-release, or a CRITICAL disclosed between legs**: the legs that
  ran before it have pushed and the rest fail, and "Re-run failed jobs" fails the same way. Renew
  the entry (a commit) and re-tag. The pre-tag `pending` check fails on an entry or listing that has
  expired or expires within two days, and warns 21 days ahead, as does every gate run's log; nothing
  warns between releases (a tracked gap).
- **The gate ran out of its budget** (`ran out of its <N>s budget`): a registry or the DB mirror
  was slow, or a scan hung. "Re-run failed jobs"; if it recurs, look at which call used the time
  in the step log before raising the budget.
- **A fix that is not in the distro yet, or in a binary the base image ships** (a Go tool, an
  upstream-built binary): refresh the base image digest if upstream has rebuilt it; otherwise
  accept it in `.trivyignore.yaml` with the evidence. Either is a commit, so re-tag.

**When the agent bundle's gate fails, never re-tag.** `docker-publish-agent-bundle` runs after
the `release` job has published the GitHub Release, so the tag is already a published release:
re-tagging it is forbidden (#5282), and `release-guard` refuses a fresh run of it. The gate runs
from the tag's own checkout, so a fix that needs a commit (a new `.trivyignore.yaml` entry, a new
base digest, a list entry) cannot reach this release's bundle at all. So:

- **A distro package with a fix, a stale DB, the gate's budget running out, or a cancel**: "Re-run
  failed jobs" on that run (the only recovery the release skill allows for this job); the chisel
  cut takes the current archive.
- **Anything that needs a commit**: this version ships without the agent-bundle image. The
  release itself is complete and its other images are signed; say so in the release notes or
  announcement, land the fix, and cut the next version (a patch release) to deliver the bundle.
  Confirm with the operator before publishing a bundle any other way.

A failed bundle job also leaves the Release run red, and Pre-release QA starts only on a
successful Release run, so that version gets no post-release scan or QA at all; a manual dispatch
of `pre-release.yml` stops at `docker pull` of the missing bundle tag before scanning the six
published images (a tracked gap).

**What it does not see.**

- **The chisel images' and the agent bundle's OS packages** (above): listed as not covered, so
  their CVEs in libc6, libssl3t64, zlib1g and the other slices never reach this gate.
- **PostgreSQL itself.** In `yuzu-postgres` Trivy lists `postgresql-18`, `libpq5` and
  `postgresql-common` as packages but matches no vulnerability to them: they come from the PGDG
  repository, and Trivy's Debian advisories cover Debian's own packages only. And the image holds
  the PGDG packages at the pinned minor on purpose, so no release build ever takes a PostgreSQL
  fix: only a deliberate `PG_BASE` bump in `Dockerfile.postgres` does. The build log names every
  held package with a newer version available (`kept back (held PGDG package)`), so a kept-back
  fix is visible in the publish job; reading it, and the PostgreSQL security announcements, is a
  release-time task for the release engineer.
- **The gateway's Erlang/OTP runtime.** Trivy does not identify the OTP runtime in the gateway's
  bundled ERTS, so OTP CVEs pass this gate (grype does report them).
- **Statically linked code.** Nothing in a statically linked C++ binary (the server and agent) is
  visible to either scanner.
- **A tampered DB.** The DB is unsigned upstream (above). The canary catches a DB with no
  advisories for the image's OS release, not one whose individual advisories were edited.

**Routed-concern invariants** (the `.claude/routed-concerns.md` row points here). Every publish
job gates its pinned image ID with `--release` BEFORE any push, and checks the pushed layers
BEFORE any SBOM, attestation or signature. The release tag moves only after verify, sign and
attest, and the publish journal is write-ahead ("The publish journal" above): only
`image-publish.sh` writes it, only `image-publish.sh tag` moves a release tag, every writing step
runs it with `exec` and it appends nothing after a SIGINT or SIGTERM, consumers read it only through
`image-publish.sh state` or `published` (one reader), and accept only a legal prefix; the published
image is the HIGHEST attempt ending `tagged`, and any higher attempt ending `tagging` fails both the
release check and the attach job. A GHCR version is deleted only when no tag other than a
`candidate-*` tag names it, decided from the registry at delete time
(`scripts/ci/image-candidate-delete.sh`). The gate fails closed: a scan, DB, coverage or
advisory-data failure is never a pass, and every exit it reaches after reading its arguments,
SIGTERM/SIGINT included, writes a report that the upload keeps, named per run attempt so a re-run
never replaces a refusal's. An acceptance is in force only when its scope is concrete (a path inside
the image, containing a `/` and naming no Trivy target, or a full purl with its version), it has not
expired, and, in a release, its approval fields are filled in and well formed (not `pending`); the
same holds for a not-covered listing. Those fields are a recorded reference, checked for format only;
the review of the change is the control. Trivy reads only the checker's canonical copy of the ignore
file, and the DB only from this run's fresh cache, pinned by digest. Widening any of these (a glob
or one-word scope, a bare id, an honoured pending approval, an inherited cache, a second coverage
reader that is not Trivy's report, an overwritten or clobbered report, a push that carries a
release tag, a second journal writer or reader, a consumer that accepts an illegal sequence, a
deletion decided from a journal instead of the registry) is a security decision, not a fix.

### Pre-release QA (`pre-release.yml`)

**Trigger.** `workflow_run` on a completed `Release` run whose head is a `v*` tag
and whose conclusion is `success`, or by hand: `gh workflow run pre-release.yml
-f tag=v0.14.0-rc3`. A `workflow_run` trigger always runs the copy of this
file on `main`, whatever branch the release was cut from.

**Detective, not preventive.** It starts after the release is already
published and never blocks one. A red run says the published release has a
defect to fix in the next one.

**Jobs.** `resolve` finds the tag, verifies `SHA256SUMS`, and picks the previous
stable release: the highest non-draft, non-prerelease `vX.Y.Z` strictly lower
than the tag under test (#5150). The other jobs check the following:

- **integration**: the reference stack starts, the dashboard answers over
  HTTPS against the install CA, the gateway is ready, the connected-agent
  gauges (server and gateway) are at least 1, an `os_info` command
  round-trips, and no service has restarted.
- **install-deb / install-rpm**: for each of server, agent and gateway, exactly
  one package is in the release. It installs, ships its systemd unit, and
  removes cleanly. It must also run: `--version` for server and agent. The
  gateway is started the way its systemd unit starts it: as the unit's
  `User=`, with its `Environment=` and its `EnvironmentFile=`
  (`/etc/yuzu/gateway.env`, the distribution cookie). The `yuzu_gw`
  application must be running within 30s, the node must still answer 10s
  later, and `stop` must succeed. A bare `ping` is not enough: it answers
  once Erlang distribution is up, even when the application refuses to
  start. The legs are ubuntu:22.04/24.04/26.04 and debian:12 for .deb, and
  fedora:42 and rockylinux:9 for .rpm (installed with `dnf`); rockylinux:8 and
  amazonlinux:2023 also run for .rpm but are non-gating (see "Linux ELF floor
  gate"). If a leg's libc or libstdc++ is older than the build's, the job fails
  and names the glibc floor (#5143). A gateway whose crypto NIF cannot load is
  named as #5171. A missing package fails; it is not skipped (#5151).
- **install-windows**: two install/uninstall passes. With `/NOTLS` the service
  must start and stay Running. With the default TLS posture the agent must
  fail closed because no CA is pinned. The uninstall wait is bounded (#5145).
- **install-macos**: the `.pkg` is present and installs, `--version` runs, the
  launchd plist is in place, and at least 5 plugins are installed.
- **artifact-verify**: checks the archive contents and ELF hardening (a
  missing NX fails; PIE, RELRO and stack canaries only warn), and that each
  `.deb` control `Version` equals the tag's Debian spelling (`0.14.0~rc3`); a
  mismatch fails. The RPM metadata step only prints. The ARM64 archive is checked only when the
  release ships one (#5135).
- **security-scan**: runs the release image vulnerability gate
  (`scripts/ci/image-vuln-gate.sh`) on all seven published images (server,
  gateway, postgres, the three chisel variants, the agent bundle). A CRITICAL
  with a fix that `.trivyignore.yaml` does not accept fails the job, as does an
  image that cannot be pulled or scanned; HIGH findings are informational.
  `release.yml` already ran the same gate before each push, so a failure here
  usually means a CVE disclosed after the release.
- **soak-test**: ten minutes on the stack. Every 30s it checks that all four
  services are running with 0 restarts, at least one agent is connected, and
  the gateway is ready. About once a minute it also round-trips a command. At
  the end the registration counters (`yuzu_agents_registered_total`,
  `yuzu_gw_agents_connected_total`, read once the gateway shows the agent's
  stream) must be unchanged: an agent that reconnected between samples, or a
  gateway that replayed registrations, fails the soak. A failed metric fetch
  fails its sample and is reported as a fetch failure, not as 0. Memory
  growth over 2x, measured from the first successful round-trip (after
  warm-up), is a warning only. Crash signatures in the server, agent and
  gateway logs fail the job. For the gateway that includes OTP process crashes
  (`crasher: initial call`) and supervisor restarts (`Supervisor: ...
  Context: child_terminated`), in the header-less format the reference
  `sys.config` logger writes. It also includes the VM dying outright: an ERTS
  abort (`<file>.c:<line>:<func>(): Internal error`), a failed boot
  (`Kernel pid terminated`) and a crash dump (`GW_CRASH_PAT` in
  `scripts/ci/qa-stack.sh`, locked by `tests/test_qa_stack_crash_pat.py`).
  Postgres logs are not checked.
- **upgrade-test**: brings up the previous stable release and upgrades every
  service in place, keeping the Postgres volume, CA and agent data dir. The
  same agent must reconnect running the new version. All services must be
  running with 0 restarts, and a command must round-trip.

**What the stack jobs run.** Integration, soak and upgrade use
`scripts/ci/qa-stack.sh` to run the **checkout's** reference template
(`deploy/docker/docker-compose.reference-gateway.yml`, #5134). The images are
the tag's own, pinned by `YUZU_VERSION`. The gateway `sys.config`, and the path
it is mounted at, come from the tag. Any difference between the tag's template
and the checkout's is printed as a warning and diffed in the job summary.

**Reporting.** In the `QA Report` job, a cell reads PASS only when that suite
ran and passed. The upgrade reads NOT TESTED when the previous release predates
the reference template, or when there is no previous stable release. A suite
that did not run reads NOT RUN, with the reason. With any such gap, the
headline is `PASSED WITH GAPS (<n> not tested)` and the run still exits 0. Any
failure or cancellation makes it `FAILED`. If no successful release triggered
the run, it reads `NOT RUN`. `has-stack` separates "predates" (exit 3) from
"could not reach GitHub" (exit 1), so an outage fails the upgrade job instead
of reading as NOT TESTED.

**Expected failures.** These reds are intended, not flakes.

- Artifacts from the v0.13.0 era fail the rpm install (#5142), the macOS
  install (#5144) and the Windows install (#5147, #1468). Those defects are
  fixed from 0.14.0-rc3 on.
- From 0.14.0-rc3 on, until the glibc/libstdc++ floor (#5143) is decided,
  these legs stay red: install-deb on ubuntu:22.04 and debian:12, the
  ubuntu:24.04 server (GLIBCXX_3.4.34), and install-rpm on rockylinux:9 (the
  gateway's bundled ERTS needs GLIBC_2.38 too).
- The gateway stays red on fedora:42 until #5171 is fixed: its bundled OTP
  crypto NIF needs OpenSSL SM4 symbols that Red Hat's OpenSSL lacks. The
  same defect is waiting behind #5143 on rockylinux:9.

**Gateway-upstream peer authorization and the rigs.** The server refuses to start with
`--gateway-upstream` unless gateway peer authorization is configured or acknowledged as disabled
(`--insecure-gateway-peer`, or `YUZU_INSECURE_GATEWAY_PEER=1`). The rigs that run the server from
the build under test pass the flag: `scripts/integration-test.sh` in its plaintext mode,
`scripts/start-UAT.sh`, `scripts/win-start-UAT.sh`, `scripts/start-stack.sh` and the locally built
full, sanitizer and viz UAT composes. None of those exercises a pinned gateway hop. One rig does:
`scripts/integration-test.sh --tls` runs the server on its generated default certificates with no
acknowledgement, so it enforces the automatic pin of its own `default-gateway.pem`, and the gateway
release dials it over `https` with `verify_peer` and that leaf as its client certificate; the
reverse hop (server to the gateway's management listener) is pinned there too. The `linux`
job runs it as the step "Gateway real-wire test (pinned TLS)" (below). The pre-release `integration`
job (`scripts/ci/qa-stack.sh`) starts no server itself: it runs this checkout's reference-gateway
template on the release's published images, so any acknowledgement or pin that rig needs belongs in
that template (an environment variable, which an image older than the flag ignores), not in the
script.

**Gateway real-wire gate (#5652, #5653).** The gateway's unit tests mock the upstream client
(`meck` on `yuzu_grpc_client`), so on their own they cannot show that a call site and the real client
still agree. The `linux` job's gcc-15/debug leg therefore runs `scripts/integration-test.sh --tls
--free-ports --gateway-ct`: the real `yuzu-server` under test, the gateway built as the prod
release (`rebar3 as prod release`, started with `foreground` on a generated `sys.config` that has
the production shape of `deploy/docker/reference-gateway-sys.config`) and one real `yuzu-agent`
(agent to gateway over one-way TLS), then `yuzu_gw_real_upstream_SUITE` (Common Test) against that
same server. The hop is pinned over TLS: the suite presents the gateway leaf the server auto-pins,
and a valid leaf of the same CA that is not pinned must be refused with `UNAUTHENTICATED` (counted as
`not_pinned`). The suite pairs every upstream call site (`ProxyRegister`, `BatchHeartbeat`,
`ProxyInventory`, `NotifyStreamStatus`, `ForwardGuardianMessage`) with the real client and reads the
effect back from the server (the decoded reply, or the server's `/metrics` for the two casts), checks
the error shapes (a server status as `{error, {Status, Message}}`, a non-200 HTTP response as the
`http_error` text, which needs an in-VM cowboy answering 502 because the real server never sends one),
and forces a registration replay: the server must adopt the agent's existing session (read back
through its answer to a heartbeat for that session), and a presented session it did not mint must
tear the agent down. A swapped request marshal function, a lost `x-yuzu-session-id` header or
`{error, _}` returned where `{http_error, _}` belongs each fails a named case (checked by mutating
the gateway source and rerunning the suite).

The same run covers the **management hop**, server to gateway (`:50063`, the privileged command
plane; the symptom of #5175 was every `SendCommand` reaching the server as `Socket closed`). The
gateway's management listener runs in the production posture, in the shipped mode by default: strict mutual TLS
(`verify_peer` + `fail_if_no_peer_cert`), `auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1`, and
`mgmt_peer_auth_mode = identity` with no `mgmt_peer_pins` (the shipped form since release N+1, #6016: the
gateway derives the identity from the single-certificate `default-ca.pem` and requires `serverAuth`);
`YUZU_GW_MGMT_AUTH_MODE=identity_or_pin` is the one setting that differs from the shipped
posture: it runs the transition mode, also pinning `<server default-server.pem>`. The shipped configurations (resolved and judged by the real boot-guard
functions) are also covered by the eunit module `yuzu_gw_config_posture_tests`; the server is pointed at it with `--gateway-command-addr` and
presents its own default leaf. Three layers check it. (1) The script dispatches `os_info.os_name` to
the real agent through the server's REST API (admin login, `POST /api/command`, poll
`/api/responses/{id}`): one round trip, then 300 commands, 16 at a time, whose streams all share the
server's single management connection; every one must return the agent's SUCCESS and the server's
`yuzu_server_gateway_forward_total` must count all 301 as `ok` and none under any failure status (the
REST per-IP limit is raised for this server with `--rate-limit 10000`; at the default 100 requests/s the
limiter answers 429 for most of the burst and the commands never overlap). (2)
`yuzu_gw_real_mgmt_SUITE` dials the listener itself: the pinned leaf is served, and the server identity cases (#6016, in the `identity_or_pin` mode the script configures) are covered too: the real server leaf is admitted by identity, a renewed-key leaf and a same-key re-issue carrying the identity are served, and a leaf carrying another install's identity is refused; the gateway's own
leaf and an enrolled agent's leaf, both valid certificates of the same CA, get `UNAUTHENTICATED` and
move `yuzu_gw_mgmt_auth_rejected_total` by `pin_mismatch` and `missing_server_auth_eku`; a peer with
no certificate gets no call; a command to the real agent returns its SUCCESS with output; 300
`SendCommand` streams (50 in flight) over ONE connection all complete; a command to an agent that
is not connected ends OK with a FAILURE frame; a fan-out whose 1 s deadline passes before the agent
(held 4 s by `delay_seconds`) answers ends OK without that answer and the connection still serves;
100 streams cancelled with `RST_STREAM` while the agent holds them leave the connection and gateway
serving. (3) After all of it the script greps the gateway log for `function_clause`, `CRASH REPORT`,
`=ERROR REPORT`, a supervisor termination or any `[error]` line, and the server log for `Socket
closed` or a failed `Gateway SendCommand`. Checked by mutation: pinning the gateway's leaf instead
of the server's fails the REST round trip and the burst, and listing the gateway's leaf as a second
pin fails `unpinned_leaf_is_refused`. It cannot skip: the script has no skip path, a missing
prerequisite exits non-zero, and `YUZU_REAL_UPSTREAM_STRICT=1` turns a check the suite cannot make
(server unreachable, `/metrics` unreadable) into a failure. The four runner agents share one OS
identity (#1871), so every named resource is per-run: all 8 ports come from the OS in one
allocation (`--free-ports`). A start-up that loses one to another process before binding it is retried, up to 3 attempts, on an unambiguous bind failure only, and a retry is a `::warning::` annotation and a step-summary line (#7538). The Postgres database is `yuzu_test_<epoch>_gwint_<random>` created on
the job's `YUZU_TEST_POSTGRES_DSN` and dropped on exit, the work directory is a `mktemp` name under
`runner.temp`, and the gateway's Erlang node name and cookie carry a random salt (the release's own
fixed `yuzu_gw` short name would contest the shared EPMD). A failed run keeps its work directory and
the step "Upload gateway real-wire logs on failure" uploads its logs, including each retried
attempt's `server.attemptN.log` / `gateway.attemptN.log` (`failure() &&` leads the
condition) and the Common Test logs, never the run's throwaway CA or agent keys. The burst's own log
(`mgmt_driver.log`) is among the uploaded `*.log` files.

**Gateway peer authorization gates.** Four pieces enforce it in CI. (1) The `linux` job in
`ci.yml` installs the `postgresql-client` apt package (it provides `psql`) and runs the step
"Gateway peer boot-decision CLI test" (`tests/shell/test_gateway_peer_boot_refusal.sh`) against the
built server with `YUZU_REQUIRE_PSQL=1`: the test creates one database per row through `psql`, so a
missing `psql` is a failure under that variable (and under `GITHUB_ACTIONS=true`), never a skip, and
a skipped step cannot be a green job that never ran. Besides the refusal and control rows (each
boot configuration against its expected exit and message), the test places real calls against the
listeners of the controls rows: anonymous calls (no client certificate) on the agent port, client-
certificate calls that present the default gateway leaf (admitted by the automatic pin, answered by
the real handler) and the default server leaf (a valid certificate of the same CA that is not the
pinned one: status 16 with `not_pinned`), and listener-port rows that repeat the certificate pair on
the dedicated gateway-upstream listener, where a call with no client certificate fails at the TLS
handshake instead of being answered with status 16. One further row group covers the second
deployment shape, operator-supplied certificates (`--cert/--key/--ca-cert` plus
`--gateway-peer-pin-file` naming the gateway leaf): it generates an operator CA and leaves, asserts
the enforce boot line carries the gateway leaf's SPKI prefix, and calls the gateway-upstream listener
presenting the pinned leaf (answered by the real handler), an unpinned serverAuth leaf (status 16,
`not_pinned`) and a clientAuth-only leaf (status 16, `no_server_auth_eku`). (2) The `docs` suite carries a lexical Python
gate, `tests/test_gateway_peer_registration_lexical.py` (Meson test "gateway-upstream guard
registration lexical gate", no build required), which fails if the gateway-upstream service is
registered other than through the guard. It reads `server.cpp` after removing comments, blanking
string and character literals (raw strings included, recognised only at an identifier boundary),
stripping a leading byte-order mark, joining backslash-newline splices and removing C++14 digit
separators, so none of those can hide a registration. Its rules: exactly three
`builder.RegisterService` calls with the expected arguments; no generic service; one `ServerBuilder`
that is never passed or copied; the unguarded handler used only in allow-listed contexts; the
member order of `agent_service_`, `gateway_service_`, `gateway_peer_guard_` and `agent_server_`, all
at the brace depth of the `ServerImpl` class body, with exactly two guard constructions; only header
includes (and imports); and a tree-wide scan so no other source file under `server/` names
`ServerBuilder` or a `Register*Service` API. It is lexical only, not a data-flow analysis. (3) The restart-advice lint
`tests/test_gateway_peer_restart_advice_lint.py` runs as the "Gateway peer restart-advice lint"
step of `docs-lint.yml` on every PR (docs-only PRs skip the Meson `docs` suite) and as the Meson
test "gateway peer restart-advice docs lint": every place that gives gateway-restart advice
after a peer-authorization refusal must carry the `5183` token (digit boundaries, so `15183`
does not count) anywhere in the same paragraph, table row, list item or alert annotation, and a
conditional marker (`only if` or `unless`) in the same sentence as the restart phrase or in the
next one. Text is matched after markdown marks are stripped, advice that is negated (`do not
restart the gateway`) is ignored, each file has a pinned minimum number of matching paragraphs so
a reworded runbook cannot silently drop out of the lint's reach, and the expiry runbook must say a
gateway redial is required. (4) The rigs
above, which carry the acknowledgement. The decision record,
[Gateway peer authorization (minimal), 2026-10-07](security-reviews/gateway-peer-authz-minimal-2026-10-07.md),
states what none of these cover.

### Local coverage gate: fast harness subset (#5803, #6116)

`scripts/test/coverage-gate.sh` is the local `/test` Phase 7b coverage gate: developer
tooling, not a CI gate (the CI coverage job is `nightly.yml`'s, with its own gcovr
invocation). Its behaviour (build-dir lock, inconclusive runs, DB-write handling, the
Linux-only refusal, option and baseline validation) is pinned by the mock-based harness
`tests/shell/test_pr2_gates.sh`. Preflight's "Shell gate tests" step runs the fast
scenarios only, `CH-6 CH-18 CH-20 CH-21 CH-22 CH-24 CH-25 CH-26` (bash, python3 with sqlite3, procps
and findutils, all on the hosted image). CH-6/CH-25 check performance parser,
requested-scale and evidence-write verdicts. CH-26 captures coverage at two real
Git revisions and again at the same revision, retaining distinct evidence identities.
The coverage fixtures stub disk space as well as `ps`, `find` and `ln`, so host capacity cannot change the expected result. The
slow scenarios (`CH-19`, the process-tree kill, about 2.5 minutes; `CH-23`, signal bursts,
about 35 s) and the rest of the harness are not in CI yet; wiring them into a nightly job,
and hardening them for the shared-identity runner pools, is #6116.

## Self-hosted runner topology

| Runner | Host | Jobs |
|---|---|---|
| `yuzu-bigtam-linux-{0..3}` | Big Tam Threadripper 9970X, native Ubuntu **26.04** (gcc-15/clang-21) — 4 L3/CCD-pinned runners (`0-7,32-39`; `8-15,40-47`; `16-23,48-55`; `24-31,56-63`), Ninja capped at `-j16` | **all self-hosted Linux** (shared label `yuzu-bigtam-linux`): ci.yml `linux` matrix, `proto-compat`, sanitizer-tests (asan/tsan), nightly (asan/tsan/coverage), codeql Linux leg, **release.yml** (build-linux, build-gateway, docker-publish\*), cache-prune-linux. 4 runners on one host. Provisioned from [`deploy/linux/`](../deploy/linux/README.md). |
| `yuzu-weetam-windows-{0..3}` | Wee Tam 9970X native Windows 11 — 4 CCD-pinned runners, shared label `yuzu-weetam-windows` | **all self-hosted Windows**: ci.yml `windows`, nightly `windows-asan`, codeql Windows leg (since ADR-0035 step 1 the Windows CodeQL row analyses the agent only; server code is CodeQL-scanned on Linux only), release `build-windows`, cache-prune-windows (the dispatch-only `instructions-windows-validate.yml` server smoke rig was deleted by ADR-0035 step 1). Provisioned from [`deploy/windows/`](../deploy/windows/README.md). |
| `yuzu-bigmags-macos-{0,1}` | BigMags Mac Mini (Apple M4 Pro, 24 GiB, macOS 26) — 2 runners as headless LaunchDaemons, shared label `yuzu-bigmags-macos` | **self-hosted macOS**: ci.yml `macos` matrix + `release.yml` build-macos. Only pre-release `install-macos` stays GitHub-hosted (`macos-14`, an install-to-root smoke test). Release **signing/notarization is deferred** — macOS releases currently ship UNSIGNED (Phase B = on-token `rcodesign`). Provisioned from [`deploy/macos/`](../deploy/macos/README.md). |

**Retired 2026-06-21** (removed from the inventory afterwards): `yuzu-wsl2-linux` (Shulgi WSL2 Ubuntu 24.04, label
`yuzu-shulgi`) and `yuzu-local-windows` (Shulgi native Windows) — superseded by
Big Tam and Wee Tam, and removed from `.github/runner-inventory.json`.
`proto-compat` and `cache-prune-linux` are pinned to `yuzu-bigtam-linux`; they
previously used the bare `[self-hosted, Linux, X64]` label, which Shulgi's WSL2
runner also carried, so they could land there instead of on Big Tam. The runners
were deregistered on the GitHub side on 2026-10-03 (per the repo admin). With the pin, `proto-compat` queues (it does not fail) while all four
Big Tam slots are busy. When no Big Tam runner is online, the `preflight-gate` job
fails (required pool `bigtam`) and `proto-compat` is skipped on a PR or push
(on a Tier 2b dispatch it instead fails red on a hosted runner, see Tier 2b).

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

All four runners run as the `runner` user, but each runner's `.env` sets its own
`HOME` (`/home/runner/rN/home`, checked 2026-11-17), so jobs see a per-runner
home directory. The user is provisioned once for fast, download-free builds:

- **ccache**: one cache per runner, at `/home/runner/rN/home/.cache/ccache`
  (with the per-runner `HOME` set, see
  [`deploy/linux/`](../deploy/linux/README.md)). Every self-hosted job that runs
  ccache sets `CCACHE_MAXSIZE=30G`, with compression on. ccache's built-in
  default of 5 GiB is far too small for ~700 TUs × variants, and the
  `max_size=50G` in `/home/runner/.config/ccache` is not read, because jobs
  don't run with that home directory. **Every job on a pool must use the same
  cap.** ccache trims the directory to the cap of whichever job is writing, so
  one job with a smaller cap empties the cache the other jobs rely on. Until
  2026-11-17, `codeql.yml` and `sanitizer-tests.yml` set 500M. Each daily CodeQL
  trace cut its runner's cache to 2.8-5.2 GB (the trace's own `ccache -s`), from
  the 18-30 GB the runner's previous CI job ended at, or 7.9 GB on a runner
  trimmed the day before. After four of the five traces from 2026-11-12 to -16,
  that runner's CI over the next 12 hours hit the cache 13-24 points less often
  than the other three runners did, depending on where the window starts; the
  fifth showed no gap. The windows hold 5-17 jobs and the comparison is
  observational, so treat the size of the gap as an estimate; the trim itself is
  not in doubt. `tests/test_ci_ccache_cap.py` now requires one cap per pool, and
  the CodeQL-traced build runs with `CCACHE_DISABLE` (see the comment on that
  step). At 30G a runner's cache sits at the cap and holds about two days of
  objects (r3's cache on 2026-11-17: 4.4 GB dated 11-15 or earlier, the rest
  11-16 and 11-17). Nothing measured shows that limit costing hits: r3, which no
  trim reached in that window, ended every job at the cap and its hit rate
  (79.1%) was close to the best of the others (73.8-79.8%). That does not show a
  larger cap would not help.
- **mold** linker (`apt install mold`), wired via `-fuse-ld=mold` in the gcc-15 /
  clang-21 native files — large cut in link time on the big `yuzu-server` /
  `yuzu-agent` binaries and the release LTO link.
- **meson** 1.12.0 + the rest of `requirements-ci.txt` persist in each runner's
  `~/.local`, so the per-job `pip install --user --require-hashes` is a
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

**Update (ADR-0035 ladder step 1).** The Windows leg is now agent-only: it
configures agent-only (step 1 passed `-Dbuild_server=false`; since step 3 it passes nothing and the `server` option's `auto` is off on Windows) into `build-windows-agent-{debug,release}`
and has one test step, `Test (non-pg suites)`, selecting `--suite agent --suite
platform --suite proto --suite echo --suite gateway`. The `Ensure Postgres`,
`Resolve pg_mode + assert Postgres DSN`, `Test (pg shards, full)` and `Test (pg
smoke)` steps and the `yuzu_pg_canary.exe` libpq import check are gone, and so
is the `pg_mode` key on the Windows matrix. The `with-test-slot.sh 2` gate, the
30-minute slot timeout and the `assert-suite-cover.py` guard stay. The server
`[pg]` measurements in this section (the c0/c2/c4 figures and Pushes 1–4) are
kept as historical evidence for the Wee Tam box; they describe steps that no
longer run. The build dirs were renamed so that a branch cut before this change
(which still configures the server) and one cut after it never share a stored
`build_server` value; the job deletes the old `build-windows-{debug,release}`
dirs on every run, so an unrebased branch rebuilds cold (ccache-warm) until it
is rebased onto `dev` (see `docs/ci-troubleshooting.md`).

**Measuring the saving.** Baseline: the Windows MSVC debug job on `dev`
pushes took 25.4–28.6 min wall time over 5 runs on 2026-11-10 (runs
42908124262, 42902526001, 42895515198, 42879744786, 42865414562), of
which `Test (pg shards, full)` was 14.3–17.0 min. Compare against the
median wall time of 5 post-cutover warm runs of the same job, excluding
each runner's first (cold) run after the cutover and any docs-only stub
run. Record the cold-run wall time and the ccache hit rate separately
(the MSVC `/Zi` hit rate is unverified). Leave the Windows job's
`timeout-minutes: 120` unchanged until at least 10 post-cutover samples
exist.

Wee Tam's 4 runners are CCD-pinned, but affinity partitions only **cores** — not
DRAM bandwidth, the disk, or the Defender minifilter. So when several Windows jobs
run their **test** phase at the same time, the heavy unit-test suites
(`server ~[pg]`/`[pg]`, `agent`, `echo`) slow roughly linearly and hit their meson
timeouts: per-runner telemetry (`ci_test_suites`) measured `server ~[pg]` at
c0≈289 s → c2≈467 s → c4≈603 s — a **guaranteed** timeout once ≥4 test phases
overlap, and a 22–25 % timeout rate on the `server ~[pg]`/`echo` suites overall.
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

From #3443 (2026-08-28) until ADR-0035 ladder step 1, `ci.yml`'s Windows job
split what used to be one combined `Test` step into `Test (non-pg suites)`,
`Test (pg shards, full)`, and (release/push only) `Test (pg smoke)`; only the
first remains. It wraps the run in
[`scripts/ci/with-test-slot.sh`](../scripts/ci/with-test-slot.sh) — a crash-safe
`flock` gate (a killed job releases its slot via OS fd-close, so a timeout never
leaks a slot) that caps concurrent heavy test phases to **2 per box** (the
**build** phase stays 4-wide). `Test (non-pg suites)` passes `--num-processes 4`
(one consolidated invocation covered what used to be five separate
suites plus the four non-pg server shards; since ADR-0035 step 1 it covers
the five agent-side suites only). Since 2026-10-21 that
invocation selects `--suite platform` instead of `--suite docs` (the
`docs` suite is Linux-only, "Test suites by leg" below) and its
`assert-suite-cover.py` guard names `--exclude-suite docs`, so a missed
label still fails loud.

`Test (non-pg suites)` also carries the registry plugin's real-registry cases (#6488). It sets
`YUZU_REQUIRE_WINDOWS_REGISTRY_TESTS=1`, so a case that would skip (no `registry.dll`, or a process that
cannot write `HKLM`) fails instead. The one exception is the Echo bam live case (#6898): a runner account can be refused
(error 5) creating its scratch keys under `HKLM\SYSTEM\CurrentControlSet\Services\bam` (measured on one test host as an elevated non-SYSTEM
user: a key directly under `bam` was allowed, `bam\State\UserSettings` was refused; LOCAL SYSTEM could write both on that host; the Windows CI leg's own account is not LOCAL SYSTEM and was refused at `bam\State\UserSettings` in CI run 43294719354, #7637), and then
the case SKIPs even with the flag set. The exclusion is proven live only where the account may write (e.g. a LOCAL SYSTEM
host), so while the Windows runner's account stays refused CI does not run it (#7637; the missing test of the skip
decision is #7638). Any other failure of that case still fails the job, including a refusal to open `bam\State` for reading, which has not been measured (#7637). The job-level
`YUZU_TEST_REGISTRY_SCOPE` (`<run id>-<attempt>-<build type>`) puts every scratch key under
`YuzuTest-<scope>-`, so two test phases sharing a box through the 2-slot gate judge only their own keys. The script
scans only the direct children named `YuzuTest-*` of `HKLM\SOFTWARE`, its `Wow6432Node`, `HKCU\Software` and (for the
#6898 Echo bam-exclusion live case) `HKLM\SYSTEM\CurrentControlSet\Services\bam` and its `State\UserSettings`; the
local dispatcher's `Software\YuzuTest\RegistryPr17Ld_<salt>` keys (`test_registry_local_dispatcher.cpp:228,248`) are
outside the scan.
Before the suite, `Self-test the registry leftover check` plants a probe key under each root the script scans (except a `bam` root the runner account is refused at, below) and proves both decisions of
`scripts/ci/check-registry-test-leftovers.ps1` (the probe's own scope: exit 1 with an `::error` naming it; any
other scope: exit 0 with a `::warning`). A probe under one of the two `bam` roots where the runner account is refused
is replaced by a check that the script still lists that root, with a `::warning` that also names the runner's identity
and says the bam live case is expected to skip; the three other roots always need a live probe. After the self-test,
`Assert this job left no YuzuTest-* registry keys behind` runs
the same script with the job's scope; a root it cannot list fails the step (a missing root is skipped). The
could-not-list arm has no self-test of its own (accepted residual): a persistent listing failure is caught pre-suite,
because the other-scope self-test arm expects exit 0 and a failed listing makes it exit 1. The check reports and never deletes (a leftover can be a registry link, and a
tree delete follows links), so a key orphaned by a cancelled job stays as a warning in later jobs until a human
removes it.

Removing a leftover is the job of whoever owns the runner. For each `YuzuTest-*` key whose run is no longer in
progress, open the key with `REG_OPTION_OPEN_LINK` and `DELETE` access, then call `NtDeleteKey` on that handle (a key
with subkeys: delete them first, leaf first, the same way). Never use `Remove-Item -Recurse` or `RegDeleteTreeW`:
both follow a registry link and can delete its target.

The Echo bam live case (#6898) sets a deny-read DACL for Everyone on its scratch key under `bam\State\UserSettings`,
so a leaf it left behind (a killed run) is expected to refuse `Get-Item`, `Remove-Item` and `reg delete`, which open the key for read
first. The recipe above still applies: the deny covers read only, so open the key with `DELETE` access and call
`NtDeleteKey`; its sibling directly under `bam` carries the default DACL.

**Spark Linux Service case (`YUZU_REQUIRE_SPARK_DBUS_TESTS`, #5719 item 5; a Linux-leg concern, not part of the Windows test phase above).** The Linux Service case in
`test_spark_mechanism.cpp` needs a `dbus-daemon` binary on `PATH` (it starts a private one on a per-process salted
socket and drives a child process against it). Where the daemon is missing, or the socket path is too long for
`sockaddr_un`, the case SKIPs; with `YUZU_REQUIRE_SPARK_DBUS_TESTS` set to anything non-empty other than `0` the same
condition FAILs instead (the same contract as `YUZU_REQUIRE_WINDOWS_REGISTRY_TESTS` above). No workflow sets it
today and no workflow installs `dbus-daemon`, so whether a leg runs the case depends on its runner image, and where
the daemon is missing the case skips silently; installing the daemon and setting the variable on a leg that is
meant to have it is tracked in #7901.

**Leaked ETW sessions (#7175).** The echo plugin's registry source starts a system-wide real-time ETW session named
`YuzuEchoRegistryEtw-<pid>` (`agents/plugins/echo/src/echo_registry_source.cpp`, the session-name function). A
real-time session outlives its process until something stops it, so a test process that is killed (a meson timeout),
crashes or is cancelled leaves its session running, and the four runner agents share one OS identity, so the leak is
shared state. On 2026-11-05 `logman query -ets` on Wee Tam showed one such session for a dead pid while `echo unit
tests` failed on every Windows run waiting for its own registry event (#7173, #7135); the leg passed in the two runs
after the session was stopped by hand. Whether the leak is the cause is not established (35 of the 64 system sessions
were in use, so the limit was not reached, and no mechanism by which a dead session starves a new one is known), so
the guard is preventive and the root-cause question stays on #7135.
The Windows job runs `scripts/ci/stop-dead-etw-sessions.ps1` three times, each step capped at 5 minutes: `Self-test
the ETW leaked-session cleanup` before the suite (canned `logman` output with injected liveness and stop functions,
plus one arm that runs the host `pwsh` as a short-lived child to prove the call timeout: it starts and stops no ETW
session and writes plain `selftest note:` lines, never an annotation), `Stop ETW sessions leaked by dead Yuzu test
processes (pre-test)` before `Test (non-pg suites)`, and a `(post-test)` run under `always()` after the registry
leftover assertion, so a session leaked by this job's own killed or cancelled test process is stopped and logged
against this job rather than the next one. Each real run logs the total session count (limit 64, `::warning` from 48)
and the Yuzu count. It stops a session by exact name only when the name matches `^Yuzu[A-Za-z]*Etw-[0-9]+$`
(case-sensitive) and its pid is not a running process, so a live job on another runner slot keeps its session and no
system or Defender session is ever matched; a liveness probe that fails for any reason other than "no such process"
counts as alive. The pid is checked a second time just before `logman stop`, which only guards against a flip between
the two checks; the window is not closed, which is safe because a live owner's session always has a live pid. It never
fails the job: a listing or stop error is a `::warning` and the script exits 0. Every `logman` call runs in a child
process that is killed after 45 s, inside a 180 s budget for the whole run, so a wedged ETW service costs a step at
most about three minutes and then warns; the 5-minute step cap is only a backstop. "Never fails" describes the
script's own logic: the step envelope can still fail the job (`pwsh` missing, or a failed self-test arm, which is
deliberate: a broken guard should be loud). A listing with fewer than 3 session rows (a healthy box lists its kernel
loggers) is treated as not understood and stops nothing. A stop that fails is checked against a fresh listing, and a
session that has gone (a concurrent job stopped it first) is logged as gone. A successful stop is also annotated as a
`::warning`, deliberately, so a leak shows on the job, and each run appends its counts to the job summary. `logman` is
run from the Windows system directory only: if it is not there, nothing is stopped. *Acceptance check, one-off:* in
the first three Windows runs after this change merges, read the `ETW sessions (pre-test):` line (`N total (system
limit 64), M Yuzu`). A green run whose log instead shows `could not list sessions`, `listing not understood`, `timed
out` or `could not stop leaked ETW session` means the guard is not working there; those are warnings, not failures,
and nothing pages anyone, so someone must look. Residuals: a pid reused by an unrelated live process keeps its session
until that process exits (and a leak whose pid was reused persists until a check happens to find that pid free); a
process killed after the post-test step leaves its session for the next job's pre-test step; output the parser does
not understand (a non-English Windows) stops nothing and warns; a session name of about 39 characters or more would be
undercounted in the total (the Yuzu names are about 30). A name outside `^Yuzu[A-Za-z]*Etw-[0-9]+$`, such as one with
a digit before `Etw`, is left alone. If the guard is itself broken, recover by hand on the runner host: `logman query
-ets`, then `logman stop <exact name> -ets` for a `Yuzu*Etw-<pid>` session whose pid is not running, with no job
running on any of the four slots. `nightly.yml`'s `windows-asan` job runs only the `agent` suite, whose tests do not
start the echo session, so it needs no such step.

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
own diagnosis that the then-11 pg shards (14 now) through 2 workers leave real serialization
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
math (at the then-11 shards, 11 over 6 workers is already 2 scheduling rounds,
identical to 11 over 8; at 14 shards k=6 is 3 rounds against 2 at k=8, see the
2026-10-11 paragraph) are why k=6 is where the staged widening
stopped rather than continuing to k=8; going wider buys no
round-reduction here and only adds CCD-thread-contention risk on Wee
Tam's fixed 16-thread envelope.

**Push 4 (staged 2026-10-21, never applied; its pg-shards half is moot since
ADR-0035 step 1 removed that step).** The CI test-phase tuning PR
(#4884) lands as a push ladder (the table in "Staged widening — Linux" below)
and its second push takes the Windows widths: `Test (pg shards, full)` 6 → 8
and `Test (non-pg suites)` 4 → 6, each judged by the decision rule above.
Baseline going in (2026-10-20, 14 pg shards): pg step 2,931 serial-s over
533 s wall at k=6; non-pg step 1,188 serial-s over 411 s wall at k=4. k=8 has
never run. Shard B (198 s) and the gateway eunit entry (167 s) are the
non-pg floor, so widening that step has a ceiling set by them. This paragraph
is rewritten with the two same-SHA samples when the width commit lands.

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
The mechanism: a single push to `dev` launched its own 4-way Linux matrix
(gcc-15/clang-21 × debug/release; since Tier 2b a `dev` push expands only the
2 debug legs, a `main` push is still 4-way) **simultaneously**, saturating all 4 Big Tam
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
explicitly too** (then on both of its two gated steps, "Test (non-pg suites)"
and "Test (pg shards, full)"; since ADR-0035 step 1 on the one remaining step,
"Test (non-pg suites)") — not for the Linux `SLOT_DIR`/`SLOT_NAME` reason
above (`RUNNER_TOOL_CACHE` IS box-wide on Wee Tam already), but because two
slot acquisitions per Windows job at the script's 115-minute default could
together exceed the job's own 120-minute budget — the identical
"ambiguous kill vs. attributable error" reasoning, applied to a different
constraint. With one acquisition left, a 115-minute wait would still leave
almost nothing of the 120-minute budget for checkout, build and the run, so
the explicit 30 minutes stays. This fix gates contention only *inside* a
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
across 5 cheap suites (`agent`/`docs`/`proto`/`echo`/`gateway`) run first, then
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
flake evidence the cheap-suite calls found earlier. (Both telemetry losses are
closed on Linux since 2026-11-10: each invocation has its own `--logbase` and
all three are imported; see "Linux test step: concurrent non-pg and pg
halves". Windows still has them.) And groups 1/2 now run
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
per-shard budget or the Linux `--num-processes 2` cap (the width then in
force; the pg step is now np=4, Push 2c) sooner rather than
later. Neither number is adjusted here without the same measurement
discipline the rest of this PR applies to the Windows widths — this
paragraph exists to make the new fact visible to the next reviewer, not to
resolve it unilaterally.

**Re-derived 2026-10-11 after shards M, N, O and P (pg-shard rebalance).** The
pg suite grew to 16 shards during this rebalance (12 on dev before it; 15 after
the first step, P added by the follow-up below) and was then merged back to 14
to meet the maintainer limit of 14 pg shards (J into I, P into M; see the last
paragraph of this section). The arithmetic below is for the final 14. Shards M
and N were carved from C (12
tags moved, C 886 to 542 cases) and shard O from F (its `[dex]` clause, F 532
to 418 cases; the 28 cases tagged both `[dex]` and `[mcp]` go to O). The
motivation was the weecolin Windows runner. The old figures of C 895s and F
765s came from re-running shards C and F alone with `--timeout-multiplier 3`
(so the 700s cap did not apply) on that box BEFORE its Postgres restart
(localhost DSN, 2s connects, 14 shards timed out). After the restart the old
12-shard layout (branch 32a37a5ac, 4-wide, full server suite, wall 1090s)
measured C TIMEOUT at 700s, F 585s, A 386s, E 343s, D 282s, L 267s, G 249s,
H 244s, K 192s, J 170s, I 162s, B 137s. Linux 4-wide on a loaded box measured
C 629s and F 470s (profiled on the pr2-sweep binary, which carries 28 more C
cases and 9 more F cases than the dev base: C 914 against 886, F 541 against
532).

The theoretical degenerate ceiling grows with the count, as the paragraph
above predicted for any addition. At the final 14 shards: 14 * 700 = 9800
test-seconds, and at the Linux `--num-processes 2` that is 7 rounds of two
shards, so 7 * 700 = 4900s = 81.7 minutes (np=2, as then in force; at the np=4 in
force since Push 2c it is 4 rounds, 2800s = 46.7 minutes, and the figures
below that quote 4900s are np=2 history). The np=2 figure ALONE (it excludes
checkout, build and the non-pg test step, so the real margin is smaller) was under the
Linux job's `timeout-minutes: 90` (`.github/workflows/ci.yml`, the `linux`
job), by 8.3 minutes (43.3 minutes at np=4); with the up-to-30-minute slot wait
(`YUZU_TEST_SLOT_TIMEOUT_MIN`) it is about 112 minutes at np=2, which still exceeded
the 90-minute limit, before checkout and build time (at np=4: 46.7 + 30 = 76.7
minutes, under it; the ceiling holds while nothing is retried, and `known-flaky.json`
is empty). For comparison, the 16- and 15-shard layouts (never on dev) were 8
rounds, 5600s = 93.3 minutes, over the limit on their own (about 123 minutes with
the slot wait), and the actual dev base of 12 shards was 6 rounds, 4200s = 70 minutes (about 100 minutes with
the slot wait). The ceiling is a figure that requires every shard to hit its
own cap, not an expected case: the degenerate figure applies only when every
shard runs to 700s, and the makespan is lower whenever any shard finishes
under its cap (the earlier "BEST and WORST makespan are the same number" holds
only in that all-at-cap case). The expected case moves the other way, see the
measured Windows run of the 16-shard layout below. On Windows the pg step ran
`--num-processes 6` (`ci.yml`, "Test (pg shards, full)" in the `windows`
job, until ADR-0035 step 1 removed it; the Windows arithmetic in the rest of
this paragraph is historical, and the Windows job now pays at most one
30-minute slot wait, for its single test step), so 14 shards were ceil(14/6) = 3 rounds, 3 * 700 = 2100s = 35 minutes,
65 minutes with a 30-minute slot wait for the pg step alone. The job also
acquires a slot for its non-pg step, so the worst case with both 30-minute
waits is 95 minutes plus that step's own run time, still under that job's
`timeout-minutes: 120`. Since #7135 a hung agent shard C holds the step for up to
480 s (was 240 s; shards A and B keep 240 s) and a hung echo entry up to 180 s (was
90 s). Where `flake-retry.py` can start its enumeration re-run of the failed suite,
an entry that hangs again on the re-run costs its limit twice before the job fails
(nothing is masked): about 16 minutes for shard C on Linux (480 s twice), and about
24 on macOS, where the first run uses `--timeout-multiplier 2` (960 s) and the re-run
does not. On Windows the re-run has not produced a classification in any of the four
logs read for this: in the one TIMEOUT log (run 41919798385 attempt 4) shard C's
verdict `not a classifiable Catch2 run` arrived 0.4 s after its TIMEOUT line (echo's
TIMEOUT line was two minutes earlier, and both verdicts print at the end of the
run), and three runs with a plain echo exit-42 failure (42040619981, 42049202343,
42056811785) gave the same verdict. That fits the open #6316 (flake-retry spawns the
DLL-linked test binary without meson's `extra_paths`), so a hung entry on Windows
costs its limit once: about 8 minutes for shard C, 3 for echo. It is an inference
from those logs, not a guarantee; fixing #6316 would make it twice (16 minutes for
shard C). The sanitizer and coverage legs call
`meson test --timeout-multiplier 2` directly, with no re-run, so a hung shard C
there costs 16 minutes. The 95 minutes above leaves 25 minutes inside
`timeout-minutes: 120` for checkout, build and that step's own run time, so several
hung entries are bounded by that job timeout, not by this arithmetic.
At np=2 the Linux slot-wait case was the one that needed attention: the "revisit the 700s per-shard budget or the Linux
`--num-processes 2` cap" follow-up tracked on #3443 (see the shard-K paragraph
above) had a less severe trigger than at 16 shards (the all-at-cap ceiling alone
fit the job limit, the ceiling plus a full slot wait did not). At np=4 (Push 2c)
both fit, about 77 minutes before checkout and build, so that trigger no longer
holds for the pg step once Push 2c lands; the 700s budget is unchanged. Neither
number is adjusted here. The tag assignment is the
tuning knob (move a tag between M and N, or O and F), documented in
`tests/meson.build` above shard M.

**Follow-up, same day: shard P carved from C.** A healthy-Postgres Windows
run of an intermediate 15-shard layout (4-wide, under heavier box load; this
layout was never on dev) measured C 542s (only 23% under the 700s
timeout), F 552s, A 615s, E 535s, D 450s, O 424s, K 269s, I 263s, J 260s,
B 175s and M 99s; Linux 4-wide on a loaded box ran C 254s and the others
113-258s, so C's Windows/Linux ratio was about 2.1. C's profile was flat (542
cases, 148s solo serial, mean 0.27s per case), so its cost is per-test
Postgres setup and the lever is case count. Shard P takes six C-resident tags
(`[rest]`, `[auth]`, `[dashboard]`, `[adversarial]`, `[authz_model]`,
`[app_perf]`): 202 cases and 46.9% of C's profiled seconds, leaving C 340
cases. Scaling C's 542s by the profiled share predicted P about 254s and C
about 288s. Measured on the 16-shard layout (weecolin Windows, restarted
Postgres, 4-wide, full server suite, 23/23 OK, wall 1064s; this is the
unmerged 16-shard layout, measured before the J and P merges below): A 393s, F 347s,
E 335s, D 287s, G 256s, O 247s, H 246s, L 236s, N 228s, C 185s, K 176s,
J 173s, I 169s, P 148s, B 140s, M 83s. So C and P came in under the
prediction (predicted 288/254, measured 185/148); the intermediate run above
was under heavier box load, so the two are not a like-for-like comparison.
The tightest shards are now A (393s, 43.9% under the cap), F and E; every
shard is at least 43% under 700s. P is a new shard rather than more M clauses
because the same C-based scaling (an estimate) would have put M near 350s
(M's 99s in the intermediate run plus P's predicted 254s); also an estimate:
M's `[readyz]` cases are likely dominated by waits that do not scale with
setup cost. Partition proof: the 16 shards' union equals the `[pg]`
population (4729), no case runs twice, the 202 cases leaving C are exactly
P's, and every other shard is set-identical. Rebalance by moving a TAG
(between P and C, or M and N, or O and F) before touching any timeout.

**Final step, same day: shards J and P merged into I and M (14 pg shards).**
The maintainer limit is at most 14 pg shards, so the 16-shard layout above
never shipped. Shards J and P were merged into I and M on 2026-10-11 to stay
at 14 pg shards; the names J and P no longer exist (the gaps are deliberate,
noted in `tests/meson.build`). Each merged entry's spec is the earlier shard's
clause list followed by the later shard's clause list verbatim (M then P;
I then J), every clause keeping its own exclusions, so no case moved between
any other shards. Partition proof (`--list-tests` on the built binary, by
name, file and line): the union of the 14 shards equals the `[pg]` population
(4729), zero duplicates, merged M = old M + old P (278 cases), merged I = old
I + old J (550 cases), and every other shard is set-identical. The measured
Windows times quoted in this section are from the 16-shard layout, not the
merged one. ESTIMATES for the merged shards are sums of those measured times
(startup is shared, so slightly less): M + P is 83 + 148 = 231s on Windows
(Linux 135 + 100 = 235s, from the 16-shard Linux run) and I + J is 169 + 173 =
342s (Linux 119 + 119 = 238s, same run); the estimate was
low for I. MEASURED on the merged 14-shard layout (Windows weecolin, 4-wide,
restarted Postgres, 21/21 OK): I 398s, A 393s, F 351s, E 340s, D 303s, G 282s,
H 257s, O 254s, M 239s, N 239s, L 238s, C 195s, K 160s, B 136s, so merged I is
the longest pole by 5s and every shard is at least 43% under 700s. Linux
4-wide, same layout, 23/23 OK: I 307s, A 284s, M 264s, F 263s, E 259s. These
runs were on a shared box, so treat the ordering among the top shards as
noise-level. Re-measure on the first CI run. Priorities are now merged M
185 and merged I 245 (all 14 distinct); see `tests/meson.build`.

**2026-10-22: test hot spots (#4882, #2600) — shard re-cuts after removing the
cost, not just moving it.** Two avoidable costs were found by measurement
(braga, macOS debug, one shard at a time) and removed before any rebalancing.
Non-pg shard D was 39.5 s, of which 34 s were two regular-expression passes
over every server source file (the route inventory); linear `find` scans now
do the same work (D 5.6 s, and 7.9 s once the dev merge had added dev's step-up inventory
cases, whose own pattern pass is linear too), and the three private copies of the `//`-comment
stripper are one helper. Several pg and non-pg cases slept through 1 s to 6 s
store deadlines; per-store `*_for_test` seams now age the local deadline
instead (about 99 s of sleeping removed; the two Postgres-authored deadlines,
lockout and break-glass, are rewound in SQL). With those gone: non-pg B moves
its four heaviest independent tags (`[oidc]`, `[retention]`, `[readyz]`,
`[tls]`) to C (B 77.5 s -> 38.4 s, C 4.8 s -> 37.9 s) and pg shard M's
`[pg][readyz]` clause (about 65 s of connect-deadline cases) moves to B (M 208
s -> 119.8 s, B 109 s -> 135.0 s). The pg move departs from the "move a TAG
between P and C, M and N, or O and F" rule above on purpose: B lost about 42 s of
sleeping, which the 2026-10-11 pairings could not foresee, so it became the
natural receiver for M's heaviest clause, a pairing that rule does not name.
No shard count changes (14 pg, 4 non-pg), the `[pg]` and non-pg populations
are exact partitions before and after (5792 and 6732 cases on the binary measured
before dev was merged; 5832 and 6867 after), and pg B's priority is now 186. Windows MSVC measurements of this
change (kingsley, one process per shard, one sample, not a like-for-like
comparison with the CI shard times): non-pg A 67.0 s, B 142.2 s, C 91.1 s,
D 0.55 s (D was 124-131 s on the Windows build host before the scan change, per #4882); `[oidc]` alone is 61.5 s
there, five times its macOS cost, and is most of C. pg B 120.7 s, M 386.1 s.
Candidate re-cuts were measured and not adopted, because each cuts the longest
shard by under the 25% bar (a re-cut must cut the longest shard by more than a quarter): moving `[rest]` from non-pg B to C gives B 121.2 s
and C 110.5 s (-15%), and moving `[pg][auth_db]` from pg M to B gives B 205.4 s
and M 319.0 s (-17%). The pre-move shards were not re-run on Windows, so the
pg move's own Windows effect is not measured; re-cut from the per-case
durations the CI job summary now carries. The echo writer and drain spin bounds were not
measured on Windows either, and nothing here claims it.

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
— the second label let the Windows non-pg step's
`assert-suite-cover.py` select it until ADR-0035 step 1 made that leg
agent-only; Linux selects it by name) that discovers
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
2026-08-26; extended to Windows 2026-08-28; Linux-only again since ADR-0035
ladder step 1, which removed the server suites from the Windows leg):** Phase 1's load asymmetry
diagnosis (a `dev`/`main` push originally ran the full pg-shard suite on
all 4 Linux legs, ~85% of each job's time, vs 2 Windows legs both running
the same full set on their own 4-runner box) is cut by narrowing what the
non-primary legs run on both platforms: Linux's 3 non-primary legs and
Windows' release leg (a `main` push or the Tier 2b daily dispatch only; PRs
and `dev` pushes are debug-only, so only one Windows leg runs there) now run
the `[pg-smoke]` subset instead. The Linux `matrix:` carries a
`pg_mode: full|smoke` key, added via `include:` on the existing
compiler/build_type combinations — never a third axis (would double the
matrix and break `max-parallel`'s 4-runner arithmetic) and never in the
job `name:` (job names are the branch-protection ruleset's required-check
contexts; `docs-required-checks` mirrors them). `full` resolves on
gcc-15/debug only (every PR, plus that leg's push); the other three push
legs (clang-21/debug, gcc-15/release, clang-21/release) resolve to `smoke`
(the release legs run only on a `main` push or the Tier 2b dispatch). The
`include:` list is conditional: on a `legs=release` dispatch it is the smoke
default alone, because GitHub applies `include:` after `exclude:` and a static
gcc-15/debug entry would re-add the excluded debug leg as a new combination.

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
  D/G/H/I already carry the flag (I now also covers J's former clauses). Loud-fail duty for a genuinely broken or
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
at all), so every `test()` entry runs once regardless of suite, so all the
`server-pg` shards AND the smoke entry both fire, meaning the 11 `[pg-smoke]` cases
execute twice there. Harmless (seconds of cost) but real, and not specific
to any one platform — the same is true of a plain local `meson test` in any
worktree. Not worth special-casing.

**Telemetry note**: on a smoke leg, `'server pg smoke'` is the LAST
PG-tagged invocation in the Test sequence, so (per the JUnit-overwrite
behavior the "Persistent runner-local test history" section below
documents for both platforms) it is what `ci-suite-stats` sees for that
leg's PG timing — a full leg's `ci-suite-stats` entry still reflects the
full-shard run, not the smoke entry, since `pg_mode` fully separates which
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
`with-test-slot.sh` closes: a `main` push's (and, before Tier 2b, a `dev`
push's) own 4-way Linux matrix could claim all 4 Big Tam runners simultaneously, leaving nothing reserving
a runner for a concurrently-queued PR job. Fix: `ci.yml`'s Linux job's
`strategy.max-parallel: 3` (3 at the time; 4 since 2026-10-21, see the update
below) caps how many legs of that SAME matrix run
concurrently, leaving at least one Big Tam runner unclaimed by it — a no-op
on `pull_request` events (already a single-leg matrix via the existing
`exclude`). This is a mitigation, not a guarantee: the freed runner is not
reserved for any specific job. `proto-compat` (this same workflow) is pinned
to the same `yuzu-bigtam-linux` label, so it draws on the same four runners,
and runs on the same push trigger — it can claim the freed runner
itself before a queued PR job does (its own `timeout-minutes: 5` means it
self-frees quickly, but it is a real same-push competitor, not just the
already-named nightly-overlap case). A stacked nightly run, another
concurrent PR/push, or a manual `workflow_dispatch` can do the same — none
of these are fixable from this diff's scope; a genuine guarantee needs
runner-pool partitioning (dedicating a runner label to PR-fast-path jobs),
which needs direct access to the Big Tam box and is tracked as a follow-up
on #3443, not done here.

**Update 2026-10-21 — `max-parallel` 3 → 4.** The cap is now 4 (all four Big
Tam runners): a `main` push's 2x2 matrix (a `dev` push's before Tier 2b) runs in one wave instead of two,
which shortens the push's wall. The trade is the one named above, accepted by
the owner: that push now claims every runner at once, so a concurrently-queued
PR's Linux leg waits for a runner. `with-test-slot.sh 3` still caps the heavy
test phases once a runner is held. Revert to 3 if PR runner-wait returns.

The revert rule's observable: queue wait never reaches `test-runs.db` (its
`started_at` is post-checkout), so it is read from GitHub. Metric: per-job
`started_at - created_at` of a PR's `Linux gcc-15 debug` job, from
`gh api repos/DevNullLtd/Yuzu/actions/runs/<id>/jobs`, sampled while a `dev`
push's matrix is running. Trip: either push-1 sample of the ladder below shows
that PR leg queued 5 minutes or more (against ~0 on the 2026-10-20 baseline and
35 minutes in the 2026-08-25 incident the cap was introduced for). Whoever fills
the push-1 row takes the sample.

**Cross-job slot count: 2 -> 3 (2026-08-25, same day as the max-parallel
fix above).** `max-parallel` (3 at the time, 4 since 2026-10-21) and the
`with-test-slot.sh` slot gate are different axes, not substitutes:
max-parallel governs runner acquisition
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
stayed at 2 (as of 2026-08-25), deliberately NOT bundled with this change: 2 slots x 2
shards/job = 4 concurrent pg shards today, 3 slots x 2 = 6, but 3 slots x
3 would jump to 9 with no diagnostic support at that load and no way to
attribute a regression to either knob — ship and measure one axis at a
time. (Push 2c later widened it to 4 on its own axis; box-wide that is
3 x 4 = 12.)

Not starvation-proof: `with-test-slot.sh` has no FIFO or PR-aware
admission — a freed slot goes to whichever waiter's 5s poll tick happens
to fire next, not to whichever waiter arrived first. If 3 push or dispatch legs
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

**Nightly Coverage runs after the sanitizer legs (#4019).** Within a
single nightly run, `coverage` `needs:` both `sanitize-asan` and
`sanitize-tsan`, so at most two of that run's three Linux legs share Big
Tam at once. Running all three together oversubscribed the box, which made
timing-sensitive sanitizer tests fail far more often; the tests that
assumed a scheduling order were fixed in the same change, so neither half
alone is the fix. The `needs:` is for ordering only: Coverage's `if:` leads
with `!cancelled()`, so it still runs when a sanitizer leg is red.

- Nightly wall time grows by roughly one sanitizer leg, and re-running a
  failed sanitizer leg also re-runs Coverage.
- This change does not close #3443. The legs still bypass the slot gate, other
  workflows can still land on the box alongside them, and a dispatch on
  another ref can overlap a scheduled run.
- Related alerting change: the `alert` job also opens `nightly-broken` when
  a leg ends `cancelled` while the run itself was not cancelled. That covers
  a leg hitting its
  `timeout-minutes`, which GitHub reports as cancelled rather than failed.
  It also fires if a runner goes away mid-job, which is a real
  infrastructure signal.

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

### Linux test step: concurrent non-pg and pg halves (2026-11-10)

The Linux job used to run three test steps one after another: `Test (non-pg
suites)` (two `flake-retry.py` invocations, about 6.6 to 7 min), then either
`Test (pg shards, full)` (about 10 min, `gcc-15`/`debug`) or `Test (pg smoke)`
(the other push legs). They share nothing but the build directory, so they are
now one step, `Test (non-pg + pg halves, concurrent)`, that starts two
background halves and waits on both:

| Half | What it runs | Slot gate |
|---|---|---|
| non-pg | `--num-processes 4` over `agent docs proto echo gateway platform`, then `--num-processes 2` over server shards A to D plus the four named checks (cheap first; the second does not start if the first fails) | none, as before |
| pg, `pg_mode=full` | `--num-processes 4 --suite server-pg` | `with-test-slot.sh 3`, as before |
| pg, `pg_mode=smoke` | `"server pg smoke"` by name | none, as before |

Selections, widths, the slot gate and the `Resolve pg_mode + assert Postgres DSN`
step are unchanged; the step also rejects a `pg_mode` other than `full` or
`smoke`. Both halves always run to the end. Each half's output is printed, in
one collapsed group, as soon as that half ends; a failing half gets an
`::error::` line naming it just before its group, so a red non-pg half is
visible while the pg half is still running. The step fails if either half exits
non-zero, and prints both exit codes with each half's wall seconds (also written
to the job summary as a "Linux test half" table).

Running two `meson test` processes in one build directory needs four kinds of
isolation, all in the step:

1. **Log names.** Every invocation passes its own meson `--logbase`
   (`testlog-nonpg-cheap`, `testlog-nonpg-server`, `testlog-pg`), so none
   overwrites another's `testlog.{txt,json,junit.xml}`. `flake-retry.py` reads
   the `--logbase` back from its passthrough arguments and uses it for the junit
   it classifies, its retry report (`<logbase>-flake-retry.json`) and its
   preserved enumeration junit and stale-file sweep
   (`<logbase>-flake-retry-enum-*`). Without `--logbase` (Windows, macOS) every
   path keeps its old name. `test-durations-summary.py` and the telemetry
   finalizer (`ci-telemetry.py finish`, one `--logbase` per base) take the same
   names. First thing in the step, before the `pg_mode` check and the
   `meson-test-prereq` build, it deletes all three bases' files left by an
   earlier run in the persistent build directory, and the legacy default
   `testlog.{txt,json,junit.xml}` from before the per-invocation names, so an
   invocation that never ran this time (or a step that failed before either half
   started) cannot upload or import a stale file.
2. **ninja.** `meson test` runs `ninja` before testing; two of those at once in
   one build directory race on `.ninja_log`. The step builds
   `meson-test-prereq` once, serially, and every invocation passes
   `--no-rebuild`.
3. **Job summary.** Each half writes its own summary file in `meson-logs/`;
   each is appended to the job summary when its half ends.
4. **Step log.** Each half's output goes to `meson-logs/ci-half-{nonpg,pg}.log`
   and is printed when that half ends. A heartbeat prints each running half's
   latest line every two minutes. Because the output is printed per half, the
   runner's per-line timestamps show when a line was printed, not when the test
   wrote it; use the times in the meson lines themselves. If the job times out or
   is cancelled the logs are not printed, but the `meson-logs` artifact upload
   (which runs on failure or cancel) carries them.

**Cancel and timeout.** Each half runs in its own process group, so the
runner's SIGINT/SIGTERM to the step's shell does not reach the halves on its
own. The step traps both: it sends SIGTERM to the process group of each half
that bash still tracks as a running job (`jobs -rp`; a PID already reaped is
never signalled, since it may belong to another process by then), waits up to
about 5 s for those groups to empty so `meson test` can stop its per-test
sessions and write its logs before the upload and telemetry steps read them,
then exits 1 whether or not they have. On a cancel the runner sends SIGINT and
waits 7.5 s before SIGTERM, so the wait fits inside that grace. If the step's
shell exits non-zero any other way while a half is running, an EXIT trap sends
the same SIGTERM (without the wait). When a half ends, its process group is
also sent SIGTERM, so children that outlive a half whose own shell was killed
do not keep running. The runner's final SIGKILL cannot be trapped; if it lands
first, the runner's end-of-job orphan sweep is what reaps the halves, and until
then a pg half can still hold its `with-test-slot.sh` slot. All of this is
exercised by `tests/shell/test_linux_concurrent_step.sh` against stubs.

**Windows has nothing to run side by side.** When this change landed, the
Windows job kept its separate `Test (non-pg suites)`, `Test (pg shards, full)`
and `Test (pg smoke)` steps, sequential, because its widths were measured that
way on a box (Wee Tam) this change had not measured. Since ADR-0035 ladder step
1 the Windows leg is agent-only and has a single `Test (non-pg suites)` step, so
there is no second half to overlap.

**Kill switch.** Setting the repository variable `YUZU_CI_SEQUENTIAL_HALVES`
to `1` makes the step run the non-pg half, then the pg half, and skip the pg
half if the non-pg half failed: the old back-to-back behaviour, with the same
log names and outputs. Set it under Settings, Secrets and variables, Actions,
Variables tab, as a repository variable (not a secret). Only the exact value
`1` enables it; any other non-empty value prints a `::warning::` and the halves
stay concurrent. It is read when a job starts, so it applies to runs that start
after it is set, not to runs already in progress. It needs no code change, so
use it first; a revert of the change is the fallback.

**Revert triggers.** Set `YUZU_CI_SEQUENTIAL_HALVES=1` on any of these on the
`gcc-15`/`debug` leg after the change: a spark or guardian `spin_until` (or
`ArmOutcomeKind`/`ReceiptStatus`) failure; a `blocked log sink SIGTERM
harness` failure; a pg-shard TIMEOUT or repeated 560 s watchdog warnings; a
non-pg entry passing 80% of its meson timeout. Each of these is a load
symptom the non-pg width history and Push 2c already treat as revert-grade. A
red that also occurs at a comparable rate with the switch set is recorded,
not a reason to keep the switch on.

**Slot-gate sizing.** `with-test-slot.sh 3` was sized for a slot holder that
runs only pg shards. A job holding a slot now also runs up to 4 non-pg
workers at the same time, so each slot carries more load than when the count
was chosen. Nothing changes the count here; watch the triggers above, which
are where the extra load would show.

**Expected effect and measurement plan.** The saving applies to the
`pg_mode=full` leg (`gcc-15`/`debug`) only: on the smoke legs the pg half takes
seconds, so the step lasts about as long as the non-pg half, as before. On the
full leg the step should last about as long as the longer half, the pg half.
Both halves share the job's 16 CPUs (up to 4 non-pg workers: 4 for the cheap
suites, 2 for the server-shard invocation; beside up to 4 pg shards), so the
saving is an estimate until measured:

- Baseline: the `gcc-15`/`debug` job wall time (`started_at` to
  `completed_at`, jobs API) of the last 12 or more successful dev-push runs
  before the change.
- Candidate: two or more same-SHA runs of the change (the PR run plus a re-run).
- Per entry: in each candidate, no entry of the non-pg half or pg shard
  reaches 80% of its meson timeout, and no entry of 5 s or more takes more
  than 1.5x its baseline mean. Each entry's baseline mean comes from the meson
  lines in the step logs of those same 12 or more baseline runs. Read the
  halves' wall seconds from the "Linux test half" summary table.
- Acceptance: keep the concurrency only if the median candidate
  `gcc-15`/`debug` job wall time is at least 10% below the baseline median (the
  same ≥10% bar as the widening rule) and the per-entry checks hold; otherwise
  set `YUZU_CI_SEQUENTIAL_HALVES=1`, record why here, and revisit.
- Record the samples, run and job ids, SHAs, runner names and slot waits here.

**Measured (2026-11-13), after the merge (#7460, merge commit `0f8a891fb2`, 2026-11-10).**
The per-entry 1.5x check failed in 2 of the 10 candidate runs, and the median job wall
time fell 35%, from 18.8 min to 12.2 min. The owner kept the concurrency (2026-11-13),
accepting the misses as the cost of sharing the CPUs, not as a revert trigger. Both
results are recorded below, so the next change to this step starts from them.

- Samples. The candidate is the first 10 successful `dev`-push runs of the job after the
  merge, not a same-SHA pair: the PR's own same-SHA samples are not recorded (not in the
  PR, its ledger fragment or this doc). One run in that window (42913101361, 2026-11-10
  22:17, 0.1 min) is excluded because its job skipped every step. The baseline is the 12
  successful `dev`-push runs before the merge. All 22 ran on Big Tam
  (`yuzu-bigtam-linux-0` to `-3`), and every `with-test-slot` acquisition in every run
  waited 0 s.
- Job wall time (jobs API, `started_at` to `completed_at`): baseline median 18.8 min
  (range 17.6 to 24.8), candidate median 12.2 min (range 10.6 to 16.6), so 35% below the
  baseline against the 10% bar.
- 80% of timeout: no entry of either half reached it. The closest was
  `gateway eunit shard A`, at 267 s of 600 s (45%); the slowest pg shard, A, reached
  187 s of 700 s (27%).
- 1.5x baseline mean (entries of 5 s or more): **failed in 2 of 10 runs**, by two pg
  shards on the same two adjacent runs (2026-11-10 21:11 and 21:45): shard O at 79.9 s
  and 82.9 s against a 48.0 s mean (1.73x worst), and shard E at 146.5 s and 147.9 s
  against a 93.9 s mean (1.57x worst). In the other 8 runs no entry exceeded 1.5x; the
  next-worst entries were pg shards G (1.49x) and D (1.47x).
- What the misses show: the halves share the job's CPUs, and the pg shards pay for it. The
  14 pg shards' serial time per run rose from a 1,482 s baseline mean to a 1,710 s
  candidate median (+15%; per-run sums, mean of the 12 baseline runs against median of the
  10 candidates), while the pg half still finishes in 448 s to 578 s. Not all of that rise
  is contention: the shard definitions are unchanged across the window, but they select by
  tag, and 117 files under `tests/unit/server/` changed between the first baseline and the
  last candidate SHA, so the shards also gained tests. Neither half dominates: the non-pg
  half took 471 s to 488 s in every run.
- None of the revert triggers above fired in the 10 candidate runs: no meson test
  failed (so nothing was retried as a flake), no entry raised the over-80%-of-timeout
  warning, and no pg shard timed out. The triggers still apply unchanged; setting
  `YUZU_CI_SEQUENTIAL_HALVES=1` on one of them is the way back, and the accepted 1.5x
  misses are not one of them.
- Per-entry values come from the meson summary lines in each job log (the `OK <secs>s`
  column). Runs:

Candidate (after the merge):

| Run | Job | SHA | Runner | Job wall | Slot wait | non-pg / pg half |
|---|---|---|---|---|---|---|
| 42895515198 | 130107665542 | `0f8a891fb2` | `yuzu-bigtam-linux-0` | 16.5 min | 0 s | 476 s / 513 s |
| 42902526001 | 130132146775 | `9d7ee88511` | `yuzu-bigtam-linux-3` | 14.9 min | 0 s | 484 s / 576 s |
| 42908124262 | 130151599835 | `f4c2c95aa7` | `yuzu-bigtam-linux-2` | 12.4 min | 0 s | 480 s / 578 s |
| 42991568006 | 130425661643 | `7e3e782456` | `yuzu-bigtam-linux-0` | 11.9 min | 0 s | 471 s / 449 s |
| 43005450029 | 130471818809 | `43e65ea5e1` | `yuzu-bigtam-linux-0` | 10.6 min | 0 s | 471 s / 461 s |
| 43008185580 | 130481028464 | `71519912c4` | `yuzu-bigtam-linux-1` | 11.2 min | 0 s | 483 s / 503 s |
| 43011603201 | 130492527502 | `b357fe186e` | `yuzu-bigtam-linux-3` | 16.6 min | 0 s | 488 s / 542 s |
| 43035122774 | 130572045791 | `dcd9a0a29e` | `yuzu-bigtam-linux-1` | 10.8 min | 0 s | 480 s / 448 s |
| 43038808720 | 130584994620 | `5814e80383` | `yuzu-bigtam-linux-1` | 11.6 min | 0 s | 482 s / 522 s |
| 43064481453 | 130675854942 | `7088f0cf2b` | `yuzu-bigtam-linux-0` | 13.4 min | 0 s | 481 s / 483 s |

Baseline (before the merge):

| Run | Job | SHA | Runner | Job wall | Slot wait |
|---|---|---|---|---|---|
| 42879744786 | 130052739576 | `cd163fe4dd` | `yuzu-bigtam-linux-3` | 18.6 min | 0 s |
| 42865414562 | 130002550762 | `8846f70cfc` | `yuzu-bigtam-linux-1` | 17.6 min | 0 s |
| 42832393723 | 129885791745 | `97122a2f26` | `yuzu-bigtam-linux-0` | 24.8 min | 0 s |
| 42822889919 | 129852765513 | `1f2698663b` | `yuzu-bigtam-linux-1` | 19.4 min | 0 s |
| 42816558875 | 129831141504 | `a7721dced7` | `yuzu-bigtam-linux-2` | 18.2 min | 0 s |
| 42674958480 | 129353923619 | `f362bc7bb0` | `yuzu-bigtam-linux-1` | 19.0 min | 0 s |
| 42658377286 | 129303139031 | `a11b1660d6` | `yuzu-bigtam-linux-3` | 17.7 min | 0 s |
| 42640706924 | 129240990338 | `4482311586` | `yuzu-bigtam-linux-1` | 18.5 min | 0 s |
| 42620776217 | 129172220558 | `dcadb36a85` | `yuzu-bigtam-linux-1` | 20.5 min | 0 s |
| 42614415550 | 129150732618 | `29df02ac0b` | `yuzu-bigtam-linux-3` | 18.9 min | 0 s |
| 42607751220 | 129128112839 | `6bb06db296` | `yuzu-bigtam-linux-1` | 19.3 min | 0 s |
| 42593254595 | 129079839035 | `bc4296f651` | `yuzu-bigtam-linux-0` | 18.3 min | 0 s |

This is a topology change; measure it on its own, as for the ladder below,
before bundling it with a width push.

### Staged widening — Linux (2026-10-21)

Until Push 2a (below), and for the pg-shards step until Push 2c, Linux ran
`--num-processes 2` on every test invocation since #3443; the server-shard
invocation stays at 2. The
2026-10-20 baseline at that width: the 14 pg shards were 1,778 serial-s over
907 s wall (sum/wall 1.96, so both workers were busy throughout); the non-pg
step was 678 serial-s over 5.4 min; the worst shard, M, took 244 s, 35% of its
700 s timeout. Widening follows the single rule in "Staged widening — the
decision rule" under "Windows test-phase concurrency gate" above (≥2 same-SHA
samples, median, stop on rule (b) or (c), keep only a ≥10% gain); it is not
restated here. At np=4 rule (c) is already cleared by the baseline (244 s is
far under 560 s).

The change lands as a **push ladder** (the pushes may be separate PRs; 2a is its
own), each push taking two same-SHA samples before the next, so a wall-time
delta is attributable to one axis ("never bundled with a topology change"):

| Push | Change | Axis | Run (id/attempt) | Samples (s) | Median pg step (s) | Median non-pg step (s) | Worst shard (s, % of timeout) | Verdict |
|---|---|---|---|---|---|---|---|---|
| 1 | Preflight split, `platform` suite + Linux-only `docs`, `max-parallel` 4, duration summary, PGDATA/RAM probe (np stays 2) | topology | | | | | | |
| 2a | Linux np 2 → 4 on the cheap-suites invocation only (see Push 2a below) | width | | | | | | |
| 2b | `gateway eunit` meson `priority: 120`, so it starts first in the cheap-suites invocation (see Push 2b below) | ordering | | | | | | |
| 2c | Linux np 2 → 4 on the pg-shards step only (see Push 2c below) | width | | | | | | |
| 2d | Gateway EUnit shards without cover, three shards, `gateway ct` `priority: 120` (see Push 2d below) | cost + ordering | | | | | | |
| 2 | Linux np 2 → 4 on the server-shard invocation (not planned: that invocation is about 66 s of wall time, Push 2a, so there is little to gain); Windows pg 6 → 8 (moot: the step was removed by ADR-0035 step 1), non-pg 4 → 6 (held) | width | | | | | | |
| 3 | tmpfs PGDATA, cap from the push-1 probe (see "Postgres for server tests") | storage | | | | | | |
| 4 | Linux np 4 → 6, then stop | width | | | | | | |

Push 1 is the comparison baseline for the rest: its two samples are the new
non-pg baselines (the docs suite left the Windows and macOS legs) and its probe
output fills the line below.

Probe (push 1, `Postgres container footprint (tmpfs sizing probe)` step):
host RAM: pending (filled by the tmpfs commit from the probe step log); post-run PGDATA per container (residual on-disk size after the pg step, not peak): pending.

**Push 2a (Linux cheap-suites invocation only, `--num-processes 2 → 4`).** The
second `Test (non-pg suites)` invocation (server shards) and the pg step stayed at
2 (at the time of 2a), so the delta is attributable to this one invocation.

*Baseline at np=2.* Step median over the 12 most recent `dev` push runs in which
the `gcc-15`/`debug` job succeeded (2026-10-22 to 2026-10-24): `Test (non-pg suites)` 6.7 min
(range 6.6 to 7.0). Two PR runs of #6425 on `gcc-15`/`debug` (job 120892371842
on commit `a264c1e59`, job 120898156494 on commit `2c6b3a120`) took 6.8 min in
both. In them the cheap-suites invocation took about 340 s of wall time for about
610 serial-s (agent about 240 s, gateway 158 s of which `gateway eunit` is 122 s
and `gateway ct` 36 s, docs 116 s, platform 96 s) and the second invocation about
66 s; per-entry times of 5 s or more differ by at most 1.09x between the two. The
older 678 serial-s figure above is for the same step before Push 1 added the
docs and platform suites. These are measurements from two runs, and "both
workers busy" is inferred from sum/wall.

*Expectation (an estimate, not a measurement).* About 454 serial-s of work other
than `gateway eunit` and `gateway ct` over four workers is about 113 s. Meson
starts entries in definition order (these suites set no `priority:` until Push 2b), and
`gateway eunit` and `gateway ct` are defined last, so they start after that work
drains and run side by side: wall time near 235 s, about 100 s saved on the
invocation and less on the job, where the pg step dominates. That makes rule (a)
near-certain, so the decision content is rules (b) and (c) and the revert
triggers. A `priority:` on `gateway eunit` is a separate, later axis (Push 2b below).

*How to measure* (read-only `gh`, no runner access):

- Find the job. After a re-run, `gh api repos/DevNullLtd/Yuzu/actions/runs/<run>/attempts/<n>/jobs`
  gives the new job id.
- Step duration: `gh api repos/DevNullLtd/Yuzu/actions/jobs/<id>`, the step named
  `Test (non-pg suites)` (`started_at`, `completed_at`). Since 2026-11-10 that step
  is the non-pg half of `Test (non-pg + pg halves, concurrent)` (section above),
  so the jobs API no longer times it: read the half's wall seconds from the
  step log line `non-pg half: exit N in Ss` or the job summary's "Linux test
  half" table.
- Per-entry times: `gh run view --repo DevNullLtd/Yuzu --job <id> --log`, then
  take the lines matching `[0-9]+/[0-9]+ .* - yuzu:` up to the first `Ok:` line
  (that is the first invocation, 105 entries today; the second prints `N/8`).
  Do not filter by step name (some logs show `UNKNOWN STEP`). The time is the
  last column, except on SKIP lines, which end in `exit status 77`. The counts are
  the `Ok:`, `Fail:` and `Skipped:` lines: Ok 100, Fail 0, Skipped 5 for the first
  invocation and Ok 8 for the second.
- Timeouts are not in the log: read `timeout:` in `tests/meson.build`. The ones
  that matter: agent shard C 480 s (shards A and B 240 s), `blocked log sink
  SIGTERM harness` 300 s, echo 180 s (`echo unit tests`; `echo fold sizing` and `echo v10 migration` are 300 s), `gateway eunit` and `gateway ct` 600 s. (Shard
  C was 240 s until #7135, a deliberate, temporary raise: see the sizing comment in
  `tests/meson.build`, and #7177 for the split that brings C back down. Echo was 90 s
  and is now 180 s, which keeps its measured passing runs under 50% of the limit.
  Every "of 240 s" sample below for shard C, every "of 90 s" sample for echo, and the
  192 s and 72 s 80% thresholds for them in the decision rule are against those old
  values; the current marks are 384 s for shard C and 144 s for echo, so while the
  raise stands neither warns as early as it did. Shards A and B are unchanged at
  240 s and a 192 s mark.)
- Not usable: the step summaries are not exposed by the jobs API, the meson-logs
  artifact uploads only on failure, and the runner telemetry database does not
  carry these entries (the junit import runs once at job end and reads the last
  invocation's file).
- Comparator: the two PR runs above. Push runs (6.7 min median) agree with them at
  np=2, so the comparison is not distorted for this step; the PR runs are still
  the better match for how the new samples run. Take two same-SHA samples: the
  first run of the PR plus a re-run of the same SHA. A PR run checks out the merge
  commit, which `gh run rerun` reuses; a fresh trigger after `dev` moved does not,
  and counts as a new sample.

*Decision rule.* The one under "Windows test-phase concurrency gate" above,
applied to this step (now the non-pg half, timed as above): (a) the `Test (non-pg suites)` median improves by 10% or
more (about 40 s); (b) no entry of 5 s or more at np=2 takes more than 1.5x the
mean of its two np=2 times (shorter entries have no stable ratio); (c) no entry
reaches 80% of its own meson timeout (480 s for `gateway eunit` and `gateway ct`,
240 s for the harness, 192 s for agent shards A and B, 192 s for shard C before #7135
and 384 s now, 72 s for echo before #7135 and 144 s now); and the entry
count (105) and skip count (5) are unchanged. Revert at once on any of: a spark or
guardian case failing (a `spin_until` that never resolves, an
`ArmOutcomeKind`/`ReceiptStatus` mismatch), even if a manual re-run is green
(`tests/known-flaky.json` is empty, so flake-retry retries nothing); the
`blocked log sink SIGTERM harness` failing (it asserts a fixed 8 s exit after
SIGTERM and is not scaled for load); a `gateway eunit` or `gateway ct` failure;
any red cheap-suites invocation. To revert, set `--num-processes` on the first
`flake-retry.py` call of the Linux job's `Test (non-pg suites)` step back to 2
(since 2026-11-10: the first call in `nonpg_half` of `Test (non-pg + pg halves,
concurrent)`).
Before the next rung, add a flake-rate check: two green samples cannot tell a 10%
flake rate from none, so require 10 or more push runs on the leg with no
non-timing red.

*Capacity.* Each Big Tam runner is confined to 16 logical CPUs (systemd
`AllowedCPUs`), so four workers get about four CPUs each, but a Catch2 shard and
the BEAM are multi-threaded, so load follows threads, not entries. With four
runner agents, Linux can now have 16 concurrent entries box-wide (up from 8). The
Linux non-pg step has no `with-test-slot.sh` gate, whereas the Windows non-pg
step runs the agent, platform, proto, echo and gateway suites (no server
entries since ADR-0035 ladder step 1; no docs) at 4 behind a slot of 2. Both boxes have 256 GB of RAM (owner-reported; the probe
measurement above is still pending) and no per-runner memory limit is documented.
This was measured on one leg (`gcc-15`/`debug`) but ships on all four: the
clang-21 and release legs never run on a PR (clang-21 debug on any push; release
on a `main` push or the Tier 2b dispatch), where up to four non-pg steps can
overlap at four wide on the box, so the 10-push-run check above is the only
coverage for them.

*Samples (measured, 2026-10-24).* Two same-SHA np=4 samples on the PR #6436
head `df7f2fd93` (run 40118483411, job 120944791805 attempt 1 and job 120949716811
attempt 2), each with the np=2 baseline above (jobs 120892371842 and 120898156494).

| | np=2 (two PR runs) | np=4 sample 1 | np=4 sample 2 |
|---|---|---|---|
| `Test (non-pg suites)` step | 406 s, 405 s | 291 s | 292 s |
| cheap-suites invocation wall | 340 s, 339 s | 224 s | 224 s |
| second invocation wall | 66 s | 66 s | 68 s |
| worst per-entry ratio (entries of 5 s or more) | | 1.12x | 1.12x |
| entries; Ok / Fail / Skipped | 105; 100 / 0 / 5 | same | same |

Rule (a): the step median fell from about 405 s to about 292 s (-28%), against
the 10% bar. Rule (b): the worst ratio of an entry of 5 s or more is 1.12x
(`docs drift gate self-test`, 7.8 s against 7.0 s; `personal data guard`), and
`gateway eunit`, `gateway ct`, the SIGTERM harness and the agent shards are
within 1.02x. Rule (c): the largest share of an entry's own timeout is agent
shard B at 83 s of 240 s (35%). Entry and skip counts are unchanged and no
revert trigger fired. The invocation saved about 116 s, a little more than the
estimate above.

One observation outside the rule: the pg-shards step, whose width is unchanged,
took 511 s and 545 s in these two samples, against 452 s and 453 s in the two
np=2 PR runs, and its 14 shards summed to 1005 s and 1079 s against 884 s and
880 s. Read against the `dev` push runs of the same day (np=2, pg-shard sums 885
s to 1028 s through 16:38, mean 942 s; 1335 s to 1437 s the evening before) the
np=2 baselines sit at the very bottom of the range and the np=4 samples inside
it (1005 s) or 5% above its top (1079 s). Later that day an np=2 push (19:12)
had the pg step at 586 s and the first np=4 push on `dev` (19:37, the #6436
merge) at 579 s, and its non-pg step took 288 s against 393 s to 405 s at np=2.
The step runs after the non-pg step and shares no code path with this change, so
this is most likely box state and an unusually fast baseline, not evidence of a
spillover; it is why the job total fell by only about 50 s. Day-to-day noise in
this step is large, so judge it only against runs taken in the same window.

Worst-case ceiling by width (14 pg shards, one shared 700 s timeout, every
shard at its cap; the degenerate figure, not an expected case): np=2 is 7
rounds, 4,900 s (81.7 min); np=4 is 4 rounds, 2,800 s (46.7 min); np=6 is 3
rounds, 2,100 s (35 min). The "7 rounds" and `--num-processes 2` restatements
in the arithmetic paragraphs above describe the width in force when they were
written and are brought forward by the width commit, not before.

**Push 2b (`gateway eunit` starts first, `priority: 120`).** A meson `priority:`
on the `gateway eunit` test in the root `meson.build` (about the entry's measured
seconds; the non-pg server shards use 10 to 50 and the pg shards a sparse rank
scale of 160 to 260). It only orders starts: the entry that ran last at np=4 now
starts first, so its 120 s overlaps the other entries instead of trailing them.
The 105 entries, the suites and the width are unchanged, and at
`--num-processes 1` the order changes but the wall time cannot. Meson sorts the
tests once, by descending priority and stably, so only the priority and the
definition order decide who starts first.

*Baseline.* The Push 2a np=4 samples: cheap-suites invocation 224 s and 224 s,
`Test (non-pg suites)` step 291 s and 292 s, `gateway eunit` about 120 s (about
111 s to 122 s over eleven runs). *Expectation (an estimate).* A replay of a
four-worker list scheduler in start order reproduces the two observed 223 s to
224 s walls to within 0.5 s. With eunit moved to the front it ends near 179 s,
not 165 s: the `blocked log sink SIGTERM harness` (59 s) then starts at about
120 s and ends at about 179 s, with `gateway ct` (37 s, last defined) ending near
168 s. So expect about 45 s saved on the invocation and the step near 247 s,
which still clears rule (a)'s bar of about 29 s. The harness and `gateway ct` are
the new tail; giving them priorities too (59 and 37) would take the replay to
about 160 s, and is the next ordering rung, not part of this push.
*Measurement and rule* are those of Push 2a above (job log, jobs API, two
same-SHA samples), with these changes. The comparator is the np=4 data, not np=2
runs (the np=2 step is far noisier): the Push 2a samples (invocation 223 s to 224
s, step 291 s to 292 s) and, as a drift control, np=4 `dev` pushes on other
commits (220.6 s and 221.4 s invocation wall, 288 s and 290 s step); np=4 walls
have a spread of about 1.5 s, so a 45 s effect is plainly visible. Read the log of
the right attempt: `gh run view <run> --attempt <n> --job <id> --log`, or
`gh api --allow-escape-sequences repos/DevNullLtd/Yuzu/actions/jobs/<id>/logs`.
Without `--attempt`, `gh run view --job <id> --log` returns the latest attempt's
log for every attempt's job id, so a re-run pair would be the same sample twice;
attempt-1 job ids come from the jobs API. Judge the non-pg step and the
invocation wall (first call to the first `Ok:` line), not the job total or the
pg step. (a) the step median improves by 10% or more; (b) no entry of 5 s or more takes more than 1.5x
its Push 2a time (eunit may stretch a little, and the harness now runs from about
120 s to 179 s beside eunit's tail and `gateway ct`); (c) no entry reaches 80% of
its own meson timeout; entry count and skip count unchanged against a contemporaneous `dev` push
(105 and 5 at the time of writing; a test added to `dev` meanwhile would move
them). The Push 2a revert triggers apply, the harness failing its fixed 8 s
bound being the one to watch: grep the log for `FAIL:` and `still alive`. A gain
below the bar with no rule (b) or (c) violation means the reorder buys little:
revert it rather than keep an unexplained change. To revert, delete the `priority: 120` line from the `gateway eunit` test.

*Other runs that see this (none measured by this push).* The Windows `gateway`
suite contains the test, so it starts first there too: in the #6436 Windows job
`gateway eunit` took 171.5 s and was the last of 29 entries, and a replay of that
job with eunit first gives about 275 s against the observed 337 s (about 62 s),
with `agent unit tests shard C` (148 s of its 240 s timeout) as the new tail; the
stretch of eunit when it runs beside the heavy shards is unverifiable. On macOS
(default width, no pg shards) eunit took 118.8 s and finished last of 47 entries
in about 138 s, so the gain is about 19 s if its duration holds. Unfiltered
nightly, sanitizer and coverage runs, which run every test at the default width,
start it right after the pg shards (priorities 160 to 260) instead of in the
quiet tail, which is the peak-contention wave: a false-red nightly opens
`nightly-broken` and blocks merges to main, so read eunit's duration on the first
nightlies after this merges (the wrapper's own deadline is a fixed 540 s, not
scaled by `--timeout-multiplier 2`, about 4.5 times its healthy 120 s).
*Samples (measured, 2026-10-24).* Two same-SHA samples on the PR #6458 head
`316123631` (run 40130611655, attempt 1 jobs 120981418470 Linux and 120981418546
Windows, attempt 2 jobs 121000195367 Linux and 121000195360 Windows), against
the Push 2a np=4 samples (jobs 120944791805 and 120949716811) and, as a drift
control, np=4 `dev` pushes without the priority.

| Linux gcc-15 debug | np=4, no priority | priority 120, attempt 1 | priority 120, attempt 2 |
|---|---|---|---|
| `Test (non-pg suites)` step | 291 s, 292 s | 249 s | 250 s |
| cheap-suites invocation wall | 224 s, 224 s | 181 s | 180 s |
| second invocation wall | 67 s | 67.5 s | 69 s |
| worst per-entry ratio (5 s or more) | | 1.03x | 1.04x |
| entries; Ok / Fail / Skipped | 105; 100 / 0 / 5 | same | same |

Rule (a): the step fell about 42 s (-14%) against the Push 2a samples; against
the np=4 `dev` pushes of the same evening (280 s, 282 s, 288 s, no priority) it is
about -12%, still above the 10% bar. Rule (b): the worst entry of 5 s or more is
1.04x; `gateway eunit` 119.0 s (against 120.0 s and 120.9 s), `gateway ct`
34.7 s, the SIGTERM harness 58.9 s with no `FAIL:` or `still alive`, agent
shards A, B, C unchanged. Rule (c): the largest share of an entry's own timeout
is still agent shard B at 35%. Entry and skip counts are unchanged; no revert
trigger fired. The replay predicted 179 s and a step near 247 s; the runs gave
181 s and 249 s to 250 s. The serial sums are 618 s against 619 s and 620 s: the
work is the same, only the order changed.

Windows MSVC debug (first measurement, one baseline job): the same step took 285
s and 284 s against 341 s in the #6436 job, and the invocation wall 283 s against
339 s, about 56 s saved (the replay predicted 275 s against 337 s). `gateway
eunit` took 180 s and 179 s against 171.5 s (1.05x), as the new tail the
replay expected was `agent unit tests shard C` (145 s of 240 s). The worst
per-entry ratio is 1.18x (`server unit tests shard A`), none exceeds 1.5x, and
all 29 entries passed. This was not part of the decision rule.

Outside the rule: the pg-shards step took 604 s and 695 s in these two attempts,
and 641 s and 662 s in the `dev` pushes at 20:03 and 21:07 without the
priority (474 s to 521 s that morning): the pg step drifted upward through the
evening on every run, with or without this change, so it says nothing about the
priority. Eunit's duration on the first nightlies after merge is still to be
read (see above).

**Push 2c (Linux pg-shards step only, `--num-processes 2 → 4`).** The width of the
`Test (pg shards, full)` step (since 2026-11-10 the `pg_mode=full` branch of the pg
half of `Test (non-pg + pg halves, concurrent)`); the slot count (3), the 14 shards, their priorities
and timeouts, and the other invocations are unchanged. The step runs only on the
`gcc-15`/`debug` leg (`pg_mode=full`), on PR runs and dev pushes; the other three
Linux legs do not run it. The 14 shards of one job share that job's single
Postgres container, so this doubles that container's concurrent clients.

*Baseline at np=2.* Fifteen runs whose `gcc-15`/`debug` job succeeded, from
2026-10-24 16:46Z to 2026-10-25 01:22Z (runs 40112522948 to 40149184808, dev
pushes and PR runs; run 40124557287 ended cancelled but its job succeeded, and it
is counted): the pg step took 474 s to 743 s (median 586 s), the 14 shards
summed 928 to 1,472 serial-s (sum/wall 1.96 to 1.99, so both workers were busy
throughout) and the longest shard took 99 to 158 s. All 15 acquired their slot
after 0 s, 11 at slot 1/3, 3 at 2/3 and 1 at 3/3 (run 40124557287, a PR run: 612 s,
shard sum 1,202 s, longest shard 132 s). Step and shard times drifted upward
through the window, not monotonically (474 s and 928 serial-s at the start, 743 s
and 1,472 at the end). Push 2a merged mid-window, at 19:37Z: the seven runs that
started before it have a pg-step median of 545 s and the eight from the merge push
on 649 s, but three of the seven earlier runs are Push 2a's own PR runs (545, 522
and 536 s), which excludes within-job spillover, so other jobs' now-wider non-pg
steps and time of day are the candidates, and the cause is not established. This
is the pg-step watch that Push 2a left open. The 2026-10-20 figure above (1,778
serial-s) is higher still, so a comparison across time is not evidence; that is
why the measurement below is interleaved, with both sides after Push 2a. The
Windows precedent went from 602 s at `--num-processes 2` to 358 s at 4 (Push 2
under "Windows test-phase concurrency gate" above: -40.5%, worst shard 1.16x); the
602 s is a single cold-cache sample, as that section says, and Windows is a
different OS.

*Expectation (an estimate, not a measurement).* The shard sum divided by four is
the floor, 232 s to 368 s for these runs. The Windows result suggests a cut of 30%
to 40% of the step, so a saving of roughly 140 s to 300 s on a step of 474 s to
743 s. The unknown is the shared Postgres container: four clients instead of two
may slow every shard, which rule (b) bounds.

*Capacity.* Box-wide, with the slot count held at 3, up to 3 jobs x 4 shards = 12
concurrent pg shards (up from 6) across up to three of the four per-agent
containers (`max_connections=400` each; a job owns its container, so connections
do not add across jobs). The `ci.yml` comment on the slot count refused a jump to
9 shards as having no diagnostic support at that load; this goes past 9, on the
strength of the measurement below and the post-merge watch. The containers have no
CPU or memory limit (`/dev/shm` is Docker's 64 MiB default), so their backends are
not covered by the runner's `AllowedCPUs` (16 logical CPUs per runner agent),
which pins only the test processes. Nightly and sanitizer jobs and every Linux
leg's non-pg step (np=4 since Push 2a) are not slot-gated and add to the load.
Connection use per shard has not been measured; the log checks below are the
tripwire, and they read nothing on a green run. A poll of `pg_stat_activity`
during one np=4 sample would turn that into a measurement; it is not done here
because it is a probe-step change on a width PR.

*Measurement.* Alternate np=4 and np=2 runs back to back so box drift cancels, one
job at a time, in the order np=4, np=2, np=4, np=2, each finishing before the next
starts. That samples a lightly loaded box, not the 12-shard regime; the post-merge
watch is the only check on that, and only for the slot numbers it reaches. The
np=4 side is this PR's `Linux gcc-15 debug` job (first run plus a re-run); a PR
run checks out its merge commit, which a re-run reuses. The np=2 side is a re-run
of the `Linux gcc-15 debug` job of a dev push (`gh run rerun <run> --job <id>`,
for example run 40182640011, job 121136792637, the dev push at a5054012d, whose
job succeeded while the run is red on another job). A push run does NOT reuse its
commit: it checks out the floating `refs/heads/dev` (`ci.yml`, `checkout_ref` for
non-PR events), so a re-run builds the current tip of dev, not the commit the run
was first made for (the earlier candidate, run 40132838208 at 62c3c806f, is stale
for this reason). Record the SHA each attempt actually checked out, from the
checkout lines of its log, and check that the two sides run the same tests: `git
diff --stat <np=2 sha> <np=4 merge sha> -- server/ agents/ common/ proto/ sdk/
scripts/ci/ tests/ meson.build vcpkg.json vcpkg-configuration.json triplets/
meson/ ':!tests/meson.build'` must show nothing, and `tests/meson.build`,
`.github/workflows/ci.yml` and `scripts/ci/with-test-slot.sh` may differ only by
this PR's own hunks (the comments in `tests/meson.build` and `with-test-slot.sh`,
the width and comments in `ci.yml`). The root `meson.build`, `vcpkg.json`,
`vcpkg-configuration.json`, `triplets/` and `meson/` are listed because their
compiler flags and dependency pins do reach the pg test binary, and `sdk/` because
the test targets link it; `gateway/` is not, because it cannot (#6458's `gateway
eunit` priority only orders the non-pg step). If the diff is not empty, take a
newer np=2 re-run. Attempt 1 of that same job is itself an np=2 sample at
a5054012d (pg step 437 s, 10:00Z), the original push attempt and not a re-run.
Meson's counts here are per shard (`Ok: 14`) and say nothing about the cases
inside, so they cannot show equal populations. Before each rerun check that
nothing is queued or running on `dev`, because a re-run joins its concurrency
group and a newer pending run cancels an older pending one. For each sample
record: run and job ids, the checked-out SHA, the runner name, the 14 per-shard
times (`gh run view <run> --attempt <n> --job <id> --log`, the `N/14 ... server pg
unit tests shard X` lines), the `with-test-slot: acquired '...' slot N/3 after Ns`
line, and the other Linux jobs in progress at its start, captured then from the
jobs API (`gh api repos/<repo>/actions/runs/<id>/jobs` for each in-progress run,
ignoring runs that have been queued for days), since it cannot be reconstructed
afterwards. The slot number is a weak proxy for load (the lowest free slot is
taken, and the ungated builds and non-pg steps never show in it), so re-take a
pair when the number of other Linux jobs running differs between its two sides.
The step duration from the jobs API includes the slot wait, which is queue time
and not width: take the step duration minus the wait, and re-take any sample with
a non-zero wait. At most 2 extra pairs may be taken; record every pair, and if the
box never settles record the result as inconclusive and ask the maintainer.
Adjacent runs in the np=2 baseline differ by up to 15% in step time and by up to
1.3x on a single shard, so a result between 10% and 15% on (a) is not a pass: take
one more pair, which is a precondition and not a retry after a failed rule.
Compare the np=4 median with the np=2 median taken in the same window, not with
earlier days.

*Decision rule.* The one under "Windows test-phase concurrency gate" above, with
three differences: (b) is measured per shard, the median of the np=4 samples
against the mean of the np=2 samples, (a) asks for 15% instead of 10%, and the
error checks are new. (a) the np=4 median is at least 15% below the interleaved
np=2 median (a result of 10% to 15% takes one more pair first, as above, and if
the result is still between 10% and 15% record it as inconclusive and ask the
maintainer); (b) no shard takes more than 1.5x its mean np=2 time; (c) no shard
reaches 560 s (80% of its 700 s timeout); all 14 shards pass in every sample; and
no shard output contains `sorry, too many clients already`, `remaining connection
slots are reserved`, `deadlock detected`, `could not resize shared memory segment`
or a connection or lease error. Meson prints only failing tests' output
(`--print-errorlogs`) and the meson-logs artifact, which holds every shard's full
output, uploads only on a red or cancelled job, so on an all-pass sample this
check reads nothing; with the DSN set a connection failure fails the test instead
of skipping it, so the all-14-pass requirement is the real test, and exhaustion
may also show first as slowness, which (b) catches. Precondition for (b): the two
np=2 samples must agree per shard within about 1.2x (adjacent baseline runs
differed by up to 1.3x, and across the window shards moved by 1.1x to 2.1x, most
by 1.6x or more); if they do not, take another np=4/np=2 pair within the cap above
before adjudicating, which is a precondition and not the forbidden retry after a
failed rule. If (b) or (c) fails, or (a) comes in under 10%, revert to 2 and stop;
a failed safety check is not "try one more sample".

*Merge condition and closure.* Merge only after the samples, run and job ids,
checked-out SHAs, runner names, slot waits and a rule-by-rule verdict are recorded
here (as Push 2a did) and (a) to (c) pass. After the merge 2c stays open until the
next 10 or more dev-push `gcc-15`/`debug` runs show no pg-shard TIMEOUT, no
repeated 560 s watchdog warning (two or more in the 10 runs, on one shard or
scattered across several) and no red of the `Test (pg shards, full)` step itself
(a red elsewhere in the run, such as the Windows legs, is not one). Since
2026-11-10 that step is the pg half of `Test (non-pg + pg halves, concurrent)`:
read "red of the step" as the line `::error::pg half (pg_mode=full) failed`, not
the step's own conclusion, which is also red when only the non-pg half fails. The np=2 red
rate of that step is the control: 0 of the 20 dev-push runs from 2026-10-23 11:05Z
to 2026-10-25 17:52Z (counted on 2026-10-25; the run before them had a cancelled
step) had a red pg step. A red of the step that also occurs at np=2 at a
comparable rate would be recorded and not a revert, but at 0 of 20 any red of the
step has no np=2 precedent, and is a revert. Two things are checked on the 10
runs. Occupancy: the ratio of the shard sum to the step duration minus the slot
wait was 1.96 to 1.99 at np=2 and cannot exceed 4 at np=4; a median at or below
2.5 (a judgement, not derived from data) means the extra workers are mostly idle.
It detects idle workers and not a slowdown: shards stretched by CPU or Postgres
contention keep the ratio high while the wall time gets no better. Gain: so the
median step minus slot wait must also stay below 649 s, the post-Push-2a np=2
median; at or above it no gain is demonstrated, and staying below it is necessary,
not sufficient, since a quiet-box np=2 run took 437 s. Failing either check
extends the watch by another 10 runs, recomputed over the 20; failing again is a
revert. Record each run's slot number: slot 3/3 occurred once in the 15 baseline
runs (a PR run, 0 s wait), and all 5 dev pushes among them held slot 1/3 (slots
2/3 and 3/3 occurred only in PR runs), so dev pushes alone will rarely reach it.
The watch therefore also counts np=4 `gcc-15`/`debug` PR runs toward the slot-3/3
observation, and needs at least one run that acquired slot 3/3 or waited before it
closes; if none does within 20 np=4 runs of either kind, the closure says plainly
that the 12-shard regime was never observed (slot 3/3 needs two other holders).
`tests/known-flaky.json` is `[]`, so nothing is retried and any np=4 flake turns
the run red; the #2093 watchdog is reporting-only and gates nothing. Repeated
warnings or a red with no np=2 precedent during the watch is a revert, not a
re-run; the PR author watches the dev pushes. That watch is also the flake-rate
check required before the Linux ladder's row 4 (np 4 → 6).

*Revert.* Set `--num-processes` on the pg-shards `flake-retry.py` call back to 2,
and in the same commit update the "Width history" comment and the "held at 2 ...
until Push 2c" sentence in that step, ladder row 2c, the "Until Push 2a" sentence,
this paragraph's status, and every sentence that says the pg step is np=4 or that
Push 2c widened it (grep both `Push 2c` and `np=4`; the job-budget paragraphs
above carry np=4 figures). Dated history paragraphs that still say np=2 were left
as history and need no edit. The revert PR runs the full leg and, being a workflow
edit, the canary job (about 6 minutes warm, much longer cold), so until it lands
every dev push and new PR still runs np=4; an in-flight PR's re-run reuses its
original merge commit and keeps np=4 until a new push or a sync.

*Samples* (taken 2026-10-25, all on `gcc-15`/`debug`, every one acquired its slot
after 0 s so the step minus the slot wait is the step; all 14 shards passed in
each):

| # | width | run / attempt / job | runner | checked-out SHA | pg step | shard sum, longest |
|---|---|---|---|---|---|---|
| 1 | np=4 | 40189715176 / 5 / 121215042603 | bigtam-linux-0, slot 1/3 | merge 889fba5f87 (PR 903d1cfdb into a5054012d) | 262 s | 941 s, 106 s (I) |
| 2 | np=2 | 40182640011 / 2 / 121240829606 | bigtam-linux-0, slot 1/3 | dev tip at its start, a5054012d (`git log -1 --format=%H` in its checkout step) | 484 s | 947 s, 105 s (I) |
| 3 | np=4 | 40189715176 / 7 / 121290474153 | bigtam-linux-3, slot 1/3 | merge 889fba5f87 | 260 s | 936 s, 106 s (I) |
| 4 | np=2 | 40182640011 / 1 / 121136792637 | bigtam-linux-2, slot 1/3 | dev push at a5054012d | 437 s | 862 s, 96 s (I) |

Per-shard seconds (shard J does not exist):

| shard | #1 np=4 | #3 np=4 | #2 np=2 | #4 np=2 |
|---|---|---|---|---|
| A | 78 | 78 | 78 | 68 |
| B | 92 | 92 | 92 | 90 |
| C | 63 | 63 | 69 | 60 |
| D | 57 | 57 | 56 | 50 |
| E | 63 | 63 | 63 | 56 |
| F | 74 | 74 | 73 | 65 |
| G | 58 | 57 | 59 | 53 |
| H | 90 | 89 | 90 | 82 |
| I | 106 | 106 | 105 | 96 |
| K | 31 | 30 | 33 | 30 |
| L | 53 | 53 | 54 | 49 |
| M | 93 | 94 | 93 | 87 |
| N | 48 | 47 | 49 | 44 |
| O | 35 | 35 | 35 | 31 |

Deviations from the procedure above, stated plainly. By time the samples are #4
(10:00Z), #1 (12:05Z), #2 (17:40Z) and #3 (21:08Z), so the widths alternate np=2,
np=4, np=2, np=4, but the procedure's order np=4, np=2, np=4, np=2 was not
followed: #4 is the original push attempt (not a re-run) and ran 2 hours before
any np=4 sample. A fourth interleaved np=2 re-run was not taken because dev had
moved off a5054012d, to 6954a193d (a `scripts/ci/` change, PR #6473) at 17:52Z and
to 360f998d0 (new server tests, PR #6475) at 21:21Z, and a re-run of a push job
builds the current tip, which would not have run the same tests as the np=4 merge
commit (which is also why sample 2 had to be taken before 17:52Z). Sample 4's
shard sum is 9% below the other np=2 sample's (862 s against 947 s). The other
Linux jobs in progress were not captured at the start of samples 1 to 4 as the
procedure asks; the only evidence is that all four took the lowest slot after 0 s,
that no run was in progress when sample 2 was re-run, and that only a
runner-inventory sentinel run was in progress when sample 3 was re-run. Attempt 6
of the np=4 job failed in the non-pg step (`agent unit tests shard C`, exit status
42) before the pg step ran and is not a sample; it was re-run as attempt 7.

*Verdict.* (a) The np=4 median step is 261 s (262, 260) against an np=2 median of
460.5 s (484, 437): 43.3% lower, and 46% against the interleaved np=2 sample
alone; the 15% bar is met with a wide margin. (b) The precondition holds: the two
np=2 samples agree per shard within 1.15x. The np=4 median over the np=2 mean is
between 0.97x and 1.08x for every shard (largest on D, 57 s against 53 s), under
the 1.5x limit. (c) The longest shard was 106 s, against the 560 s bar. All 14
shards passed in all four samples. Occupancy (shard sum over step) was 3.6 at np=4
and 1.96 to 1.97 at np=2. Shard times show no change from the width beyond the
1.15x spread between the two np=2 samples (the np=4 median over the np=2 mean is
0.97x to 1.08x per shard), so the shared Postgres container showed no slowdown at
4 clients; this samples a lightly loaded box with the slot at 1/3 and says nothing
about the 12-shard regime, which only the post-merge watch can reach. The
max_connections and `pg_stat_activity` peak were not measured.

**Push 2d (gateway EUnit shards without cover, three shards, `gateway ct` at
`priority: 120`).** Three changes to the gateway entries of the Linux cheap-suites
invocation, made together because each one alone leaves the gateway as that
invocation's tail. (1) The EUnit shards run with the `test` profile's
`cover_enabled` false (`gateway/eunit_shard.config.script`; a plain
`rebar3 eunit --dir` and `gateway ct` keep cover). meck preserves cover data on
every `meck:new`/`meck:unload` of a cover-compiled module, and the foreach
fixtures pay that per test: the whole suite took 459 s with cover and 268 s
without, the same 2807 tests passing, and nothing reads a shard's cover data.
(2) Three shards instead of two, balanced by weights measured without cover
(`scripts/gateway_eunit_shards.py`). (3) `gateway ct`, last to finish in all 22
sampled runs because it had no priority and is defined after every `tests/`
entry, gets the shards' `priority: 120`, so the four gateway entries start at t=0.

*Baseline.* The concurrent-halves runs (2026-11-10 to -13): shard A 234 s to
267 s, shard B 191 s to 214 s, `gateway ct` 124 s to 136 s, cheap-suites
invocation 362 s to 375 s where the log carries per-line timestamps.
*Expectation (an estimate).* A replay of a four-worker list scheduler in meson's
priority order, which reproduces two observed baseline walls to within 3 s, gives
269 s to 279 s with the shards at about 100 s and `gateway ct` at 130 s to 160 s,
and 290 s to 302 s with the shards at 130 s; the invocation only gets longer than
today if each shard runs past about 190 s. This takes the `gateway ct` half of the
rung Push 2b named, at the shards' 120 rather than its own duration: ct is no
longer the 37 s entry Push 2b measured but 124 s to 136 s under the concurrent
halves, so it needs to start with the shards. Local runs, all four entries at
once: 92 s to 100 s per shard on a quiet box, 131 s to 175 s under a load average
of 20 to 60. The new tail is `blocked log sink SIGTERM harness` (59 s, no
priority); a priority for it is the next rung. The non-pg half should fall from
about 480 s to about 390 s to 400 s, which leaves the pg half the longer one.
*Measurement and rule* are Push 2b's (two same-SHA samples, attempt-specific
logs), judged on the cheap-suites invocation wall and the non-pg half's wall:
(a) the invocation median improves by 10% or more; (b) no entry of 5 s or more
other than the gateway entries takes more than 1.5x its baseline; (c) no entry
reaches 80% of its own meson timeout, and the EUnit test count across the three
shards equals a contemporaneous `dev` push's (2807 at the time of writing; a test
module added to `dev` meanwhile would move it). Windows (Wee Tam) runs the same entries: its
`agent tsan-heavy checkpoints` barrier (`is_parallel: false`) now waits for C and
`gateway ct` as well as A and B, which should still be shorter than the two
covered shards were, but is not measured; read its first runs. Unfiltered nightly
runs now start `gateway ct` with the shards, after the pg shards. Faster code
without cover can move a race: watch about five runs per leg for a gateway flake
and name the module before any re-run. To revert, take the shards back to two in
the root `meson.build` table, `REQUIRED` in `scripts/ci/assert-gateway-tests.py`
and the names in `tests/test_gateway_test_summary.py` (and the shard count in
`docs/erlang-gateway-build.md`, `docs/testing/integration-tests.md` and
`docs/rhel9-build-setup.md`),
delete the `NoCover` wrapper from the config script, and delete `gateway ct`'s
priority; each of the three is separable.
*Samples (measured, 2026-11-13 to -14).* Three same-SHA samples per leg on the
PR #7703 head `f17fcc7c26`, run 43456524845 (Linux attempts 1, 2 and 4, jobs
131992161922, 132062790009, 132464908320; Windows attempts 1, 3 and 5, jobs
131992161930, 132075575242, 132467714240). Every gateway entry passed on its
first attempt in all six.

| Leg | Shard A (s) | Shard B (s) | Shard C (s) | `gateway ct` (s) | non-pg half (s) |
|---|---|---|---|---|---|
| Linux | 100, 98, 103 | 107, 103, 113 | 130, 127, 109 | 143, 145, 142 | 411, 401, 394 |
| Windows | 154, 155, 154 | 149, 152, 145 | 170, 170, 165 | 48, 49, 48 | — |

The cheap-suites invocation's wall is not printed on its own (the half's log is
written at its end); taking the non-pg half less the server-shard invocation
(about 95 s to 110 s at two workers, from its entries' durations) gives about
290 s to 300 s in each Linux sample, against the 362 s to 375 s baseline: rule
(a) holds (about 19%), and the non-pg half fell from about 480 s to 394 s to
411 s. Rule (c): the longest shard is 130 s on Linux (22% of its 600 s meson
timeout) and 170 s on Windows (31% of the wrapper's 540 s deadline). Not
checked from CI: rule (b) entry by entry, and the EUnit test count (a green run
uploads no test logs, and meson's summary shows each shard passing, not its
count); the 2807 is from the local cover-off run. The Windows job took 7.6 to
10.3 min; its barrier wait is not measured separately.

### Contract migration evidence

The Linux gcc-15 debug leg enables `build_contract_tests` in the dedicated
`build-linux-contracts-gcc15-debug` directory and runs all six registered
migration pilots after the regular suites, under the same three-slot
Big Tam admission limit. PostgreSQL contracts use
the job's test database; gateway and plugin contracts retain their native
reports. The collector's default portable bundle is uploaded after success or
failure with the GitHub run ID and attempt in its artifact name, retained for
30 days. Raw local inputs are excluded from that upload. A failed contract
fails the step; its evidence does not replace the regular suite verdicts.
See `docs/testing/contract-evidence.md` for the obligations and bundle format.

The step compiles the pilots' build targets (the union of `build_targets` in
`tests/contracts/pilots.json`) at the leg's full `YUZU_BUILD_JOBS` width
**before** it takes a slot, then runs the collector inside the slot; the
collector's own `meson compile -j 2` finds nothing to do. Before this, that
compile ran inside the slot at two jobs: across the 20 gcc-15 debug jobs of
2026-11-15 and -16 the step took 6 to 50 min (slot wait included), and in one
sampled run the build was 996 s and the six pilots ran in 26 s, all while
holding one of the three slots the Linux test step also needs. A compile error
in the precompile is a warning only: the collector repeats the build and
records the failure in its evidence. A precompile that runs past the job's
90-minute limit cancels the job, which uploads no bundle, as a slow collector
build could before. The Configure step sets `CCACHE_NOHASHDIR=1` for this leg
only: ccache otherwise hashes the working directory for a `-g` compile, so the
contract build directory never reused the standard build's objects (the two
directories' compile commands are identical). The cost is debug info only: an
object's recorded compile directory may name the other build directory (each
runner has its own cache, through its per-runner `HOME`, so never another
runner's workspace), and nothing in
this leg reads it. The step prints the precompile's wall time with its own
ccache hit and miss counts (from a per-step stats log, since the cache's
counters cover the whole job), and the collector's
time including its slot wait. The contract build's compiles, previously ccache
misses, now mostly hit, so the job's overall ccache hit rate is not comparable
with earlier runs. Each runner compiles each source cold once under the new
cache keys, in whichever directory compiles it first: the standard build is
incremental, so on a runner whose standard build directory survived, the
contract precompile pays it (on 2026-11-16, 393 s with 1% hits on linux-0's
first run, then 5 s with 100%). Most sources are compiled with include paths that name the
runner's own workspace, so the runners share few of these entries.

The collector's build-directory lease is an OS lock (`flock`, or
`msvcrt.locking` on Windows) on `.contract-evidence.lease` in the contract
build directory, so it ends with the collector however the collector ends. The
earlier lease was a directory, `.contract-evidence-lock`, which a cancelled job
could leave behind in this uncleaned workspace; every later contract run on
that runner then failed within seconds until a branch-switch wipe removed it
(#7986). A leftover directory of that name is inert and can be deleted. A
`BuildDirectoryBusy` now means a live collector holds the lease, and clears
once it exits. When a run ends in ERROR, the step log prints the exception
type, a fixed explanation for a known type, and which error fields the
manifest recorded, for example `contract-evidence: ERROR (BuildDirectoryBusy:
a live collector holds .contract-evidence.lease; retry after it exits);
recorded: error; error text stays in the private capture`. The portable
bundle carries the type and the field names, as `error_kind` and
`error_fields`. The error text
itself stays in the private capture on the runner, because it can carry
values derived from the environment.

### Persistent runner-local test history

The local `/test` recorder now uses schema v4. `test_gates` remains the latest
observation for each run/gate, while `test_gate_attempts` appends every recorded
write in the same transaction. An observation is not necessarily a fresh test
execution: repeated reporting also creates an entry. `--latest` shows repeated
gate history and JSON exports include `gate_attempts`. Migration preserves each
surviving v3 gate with an unknown recording time; it cannot reconstruct results
already overwritten by older clients.

**Compatibility and rollback:** schema v4 is a one-way local test-history
migration, not a product database migration. Older v3 recorders reject v4;
older `/test` preflight checks fail, and nonblocking CI telemetry may warn and
skip recording. Before the first upgrade, take a consistent SQLite backup
(using SQLite's backup API or `.backup`, not a lone copy of a live WAL-mode
file). When switching to an older checkout, set `YUZU_TEST_DB` to a separate
v3 database. To restore pre-upgrade history instead, stop its writers, retain
the v4 database and its logs separately, and restore the pre-upgrade backup;
there is no in-place downgrade or automatic merge of later v4 observations.
The newer recorder can still read and migrate the retained v3 history.

Finalization keeps earlier gate FAIL/ABORTED/WARN evidence, treats unfinished gates or
an empty run as ABORTED, and reports an all-skipped run as SKIP. An explicit
`run-finish --status` can worsen the result but cannot improve it; its floor
survives refinalization and late gate observations. A late observation reopens
the run until it is finalized again. Manual run IDs keep their original source
identity and start time; writes from another revision require a new run ID.
An ABORTED observation remains ABORTED after a later PASS; an ordinary
RUNNING → PASS transition completes the gate. For hand-run coverage captures,
`bash scripts/test/coverage-gate.sh --capture-baselines` generates a fresh
`manual-<UUID>` when `--run-id` is omitted. This preserves separate captures on
the same revision as well as across revisions.
The recorder still cannot detect a required gate that was never recorded: a
declared execution plan is future work. Metrics/timings still replace values,
and preserving a log path does not preserve overwritten log bytes.

The gateway's Meson, local, `/test` and release EUnit entrypoints share strict
summary grading: nonzero exits, cancellation, failed summaries and zero executed
tests fail. The old `cancel-tolerant` CLI spelling remains a strict compatibility
alias. The wrapper retains its deadline after output EOF and shares one budget
across retries/backoff, leaving separate bounded cleanup headroom. This does not
yet establish a complete per-case execution inventory.

The Instructions gate requires terminal SUCCESS from every agent counted in an
untargeted dispatch's `agents_reached`, reads response pages, validates command
and agent identities, and rejects any failure or malformed/incomplete evidence.
Earlier RUNNING chunks are allowed when that agent has terminal success. The
opt-in destructive/forensic path retains its separate stricter grading. These
checks establish reported execution success, not action-specific postconditions.

The performance gate remains measure-only: thresholds are not enforced. A failed
requested perf/scale process, missing metrics from either requested suite, or a
failed evidence write cannot produce PASS. Workflow shell tests select actual
YAML `jobs.*.steps` entries using the already-required PyYAML dependency; missing
or ambiguous selectors and step-shaped text inside script literals are refused.

Every self-hosted runner agent owns a separate `test-runs.db` outside its
checkout. Big Tam stores it below that agent's registered tool cache at
`/srv/ci/work-N/_tool/yuzu-test-runs/yuzu-bigtam-linux-N/test-runs.db`;
Wee Tam stores it at
`D:\ci\test-runs\yuzu-weetam-windows-N\test-runs.db`. The files survive
`actions/checkout`, branch-switch build wipes and runner restarts. They are
deliberately per-agent rather than per-host: telemetry must not introduce a
shared SQLite writer lock between the four jobs whose contention it measures.

The Linux and Windows jobs in `ci.yml` call `scripts/ci/ci-telemetry.py` near
job start and from an `always()` finalizer. Schema v4 retains the v3 GitHub run attempt,
job/platform/runner, commit/branch/event, conclusion and wall time, ccache ratio,
each Meson test entry's result/duration/timeout, and any listed flake recovered
by `flake-retry`. A cancelled job normally finalizes as `cancelled`; a hard kill
that prevents post-steps intentionally leaves an `in_progress` row, which is
itself evidence of runner/job termination rather than a fabricated result.

**Multi-invocation telemetry gap (Linux closed 2026-11-10; Windows closed by
ADR-0035 ladder step 1), since the "Suite isolation" split above:** on Linux
each invocation now has its own meson `--logbase` and the finalizer imports all
three (`ci-telemetry.py finish --logbase ...`); the Windows leg is now
agent-only with ONE test invocation, so its single `testlog.junit.xml` is the
whole record. The rest of this paragraph is history for both. Before
that, the finalizer imported one `meson-logs/testlog.junit.xml`, and both platforms'
Test steps ran multiple separate `meson test` invocations against the
same builddir (Linux: 3; Windows: then 2 — the non-pg step plus
exactly one of pg-full/pg-smoke, `matrix.pg_mode` resolves to exactly
one or the job failed loud earlier), each overwriting that file. Only
the LAST invocation's per-suite `ci_test_suites` rows and any `flake-retry`
recovery it reported survived — the earlier, cheaper invocation(s) still gated
the job (their own exit code), but produced no queryable history via
`test-db-query.sh ci-suite-stats`/`ci-flakes` for this job. This was true
for Linux from the original #3443 restructuring and became true for
Windows too once this PR mirrored that shape — see the "Telemetry note"
above for the Windows-specific ordering detail (pg then ran last on both
platforms, for the same reason). macOS was never affected — it never ran a
`[pg]`-tagged suite (ADR-0035) and has one invocation.

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

The macOS job installs Erlang/OTP 28 + rebar3 per run, on the same major/minor line as the
Linux leg (macOS pins the exact patch, the other legs float), so the gateway is built and
its eunit/ct suites run on macOS too. It downloads the prebuilt `erlef/otp_builds` OTP
tarball and the rebar3 escript into `$RUNNER_TEMP` (per agent, per job) and verifies pinned
SHA-256s, rather than using `erlef/setup-beam`: setup-beam re-copies one
`/opt/ci/tool_cache/otp/...` tree that both BigMags agents share, and a debug + release
pair starting together raced on it. Dependabot does not bump these pins; the bump and
hash-mismatch procedure is in `docs/darwin-compat.md` ("Erlang gateway in macOS CI").
Before #4841 it had no Erlang and Meson silently skipped the gateway.

Every CI leg that runs tests (ci.yml Linux/Windows/macOS, nightly asan/tsan/coverage/windows-asan, sanitizer-tests asan/tsan, and the dispatch-only
`fork-dynamic-review.yml` Linux leg, which installs Erlang via `erlef/setup-beam` like the other Linux legs) now runs
`scripts/ci/assert-gateway-tests.py <builddir>` straight after configure (`meson setup`, or `scripts/setup.sh` in the fork review leg), so a missing `rebar3` (gateway tests not registered)
fails the Configure step rather than skipping. It is deliberately a post-configure check, not the `-Drequire_gateway` project
option: a non-default project option stored in these persistent, branch-shared build dirs makes every older branch's
`meson setup --reconfigure` fail with `Unknown options` (measured, #4851). `tests/test_gateway_test_summary.py` pins that
every such `meson setup` is followed by the check, that none passes `-Drequire_gateway`, and (by globbing
every `.github/workflows/*.yml`, so a new or renamed workflow is covered) that every job running `meson test` or `flake-retry.py`
has the check at or before its first test step.

Inventory declared in `.github/runner-inventory.json`. The sentinel at
`runner-inventory-sentinel.yml` (every 30 min) compares actual to expected
and opens a `runner-inventory-drift` issue on mismatch. Both the sentinel
and the ci.yml `preflight-gate` job share `scripts/ci/runner-health-check.py`
(`--mode sentinel` vs `--mode preflight`). `ci.yml` splits its preflight in two
(2026-10-21) so the compile jobs start after a short gate instead of the whole
serial job: `preflight-gate` ("Preflight (gate)") holds the docs-only
classification, the pool probe and every output; `preflight` ("Preflight
(runner health)", the name the dev ruleset requires) holds the source
gates and runs alongside the builds. `preflight` runs under `!cancelled()` and
its first step fails unless `preflight-gate` succeeded, so a failed gate (or a
failed `trusted_inputs`, which skips the gate) reds the required check instead
of leaving it skipped. Only the gate's `health` step receives the
administration-scoped `RUNNER_INVENTORY_TOKEN`; `preflight` never does. Preflight
gates downstream self-hosted jobs with explicit
`if: needs.preflight-gate.outputs.<runner>_healthy == 'true'`. Each workflow also
declares its required pools with `--require-pool`. A wholly unavailable
required pool fails `preflight-gate` (and with it `preflight`) red instead of
silently turning its required jobs into successful skips. The control interface distinguishes observed
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

### Docs-only changes (#1978, #5320)

As of #1978, `preflight-gate` also emits a `code_changed` output (from
`scripts/ci/detect-code-change.sh`); the build jobs additionally gate on
`&& code_changed == 'true'`, so a docs-only PR skips the whole matrix. The
matrix-expanded required contexts (`Linux gcc-15 debug`, `Windows MSVC debug`,
`macOS debug`) would otherwise stay "Expected" forever on a docs-only PR
(a top-level-skipped matrix job emits none of its inner check names), so a
`docs-required-checks` stub emits those exact names as success when
`code_changed == 'false'`. `ci.yml` path-filters neither trigger.

Since #5320 the same applies to a push to `main`/`dev`. The push trigger used
to keep a docs `paths` allow-list, so a changelog-only push started no run and
the required contexts never appeared on the commit; the v0.14.0 release commit
(50a81af91) was tagged on an operator decision for that reason. Now every push
runs, and the codegate step's push arm sets `code_changed=false` only when:

1. the previous tip's newest `ci.yml` push run on the branch concluded
   `success` — a newer pending run cancels an older pending one in this
   workflow's concurrency group, so without this a docs push arriving behind a
   running build would cancel a code push's pending run and the code would
   never be built; it also stops a docs commit turning a red code commit
   green;
2. the compare API reports the push as a fast-forward (`ahead`) listing 1–299
   files (empty is missing evidence; 300 is the API cap, so the list may be
   truncated); and
3. every listed path, and every rename's previous path, is docs-only.

Any API error or other answer builds. The classification set is unchanged,
including the BR-010 carve-out: a push touching `docs/os-capability-matrix.md`
builds and runs its drift gate. A docs-only push therefore costs
`trusted_inputs`, `preflight-gate`, `preflight`, three stub jobs and `detect-ci-changes`, all
GitHub-hosted (plus the CI canary when the push touches a workflow file — the
CI-infrastructure classifier decides that separately). The required contexts on
such a commit read `success` (Preflight, the three stubs, CHANGELOG order) or
`skipped` (Proto backward-compat). `success` on those three names for a
docs-only commit means *inherited from the predecessor's build*, not *built*;
the run's summary says so. On a PR a skipped required context satisfies the
ruleset and an absent one does not; a push commit is never evaluated by the
ruleset, so on `main` the only consumer of these contexts is the release
skill's tag gate, which reads them the same way. The
push arm is executed against a stubbed `gh` by
`tests/shell/test_codegate_push.sh`.

Which contexts are required is a repository ruleset setting ("Protect Main",
"Protect Dev"), not part of `ci.yml`; #5320 did not change it.

### Test suites by leg (`docs` and `platform`, 2026-10-21)

The meson `docs` suite is OS-independent (lexical gates, selftests, lint
tests) and runs on the **Linux leg only**. Its "runs on every leg" premise was
false at the test-file level: platform entries pin OS-specific behaviour inside
the test file or script itself, not behind a meson guard. Twelve entries now carry the
`platform` suite instead, which every leg runs (except where an entry is not
registered: since ADR-0035 ladder step 1 the Windows and macOS legs configure
agent-only (the `server` option is off for a non-Linux target), so a `build_server`-gated entry runs on Linux only):

| Entry | Why it is OS-contract |
|---|---|
| `gateway build wrapper` | the Windows-only taskkill case and win32 branches in `tests/test_build_gateway.py`; its POSIX stdio and Ctrl-C behaviour must also keep running on Linux |
| `gateway OTP pin resolution` | pins the `erl.exe` resolution that `scripts/erlang_toolchain.py` branches on for win32 (`tests/test_erlang_toolchain_otp.py`) |
| `instructions runner hardening` | `WindowsConsoleBreak` (win32) next to about two thousand lines of POSIX tests |
| `gateway wrapper guard selftest` | exercises the real wrapper subprocess, native exit/status handling and diagnostic captures on each OS, including Windows pipe decoding |
| `contract evidence selftest` | exercises subprocess deadlines, child cleanup and native-path evidence handling; Windows task-tree termination and POSIX signals need separate observations |
| `local test runner platform selftest` | drives bash with native fixture paths (MSYS2 `cygpath` on Windows), UTF-8 output and the per-OS supported target selection |
| `windows sdk contract` | exercises the MSYS2 bash setup contract on win32 |
| `Windows toolchain contract` | registered only where `pwsh` is installed (not the Linux image) |
| `build_examples=false gating smoke test` | selects the per-OS vcpkg triplet with `uname -s` and configures a real build on each leg |
| `start-UAT.sh kill_stale scoping (#5333)` | sources `scripts/start-UAT.sh`, the macOS/Linux rig with Darwin branches; registered off Windows, so it runs on Linux and macOS |
| `capability matrix gate shell tests (#2204 F10)` | picks `.so`/`.dylib`/`.dll` and loads the real fixture plugins through `capmatrix-gen` on each leg |
| `healthcheck CLI contract (#5906)` | a bash test that drives the real native `yuzu-server` binary (`.exe` probe, `MSYS2_ARG_CONV_EXCL`, `cygpath`); labelled `['server', 'platform']` (Linux only since ADR-0035 step 1; not registered when `build_server=false`) |

Linux selects `--suite docs … --suite platform`; Windows selects `--suite agent
--suite platform --suite proto --suite echo --suite gateway` (not `docs`) with `--exclude-suite docs` on its coverage guard; macOS runs
everything but `--no-suite docs`. The five dual-labelled node tests
(`shell bell script behaviour`, `tokens page rotate behaviour`,
`echo timeline script behaviour`, `mcp http adapter behaviour` and
`swagger page behaviour`; `['server', 'docs']`)
therefore no longer run on Windows or macOS, by intent. Like its siblings, the
`mcp http adapter behaviour` test skips (exit 77) wherever `node` is absent.
Before moving an entry, grep the docs-suite tests, Python and shell, for a
Windows- or macOS-positive branch: `skipUnless(... win32`,
`if sys.platform == "win32":` guarding assertions, a Python ternary on
`sys.platform` (`"erl.exe" if sys.platform == "win32" else "erl"`), a shell
`uname -s` arm, `cygpath` or `MSYS2_*` handling, a `.exe` probe, a per-OS
triplet or extension select, an OS-tool `find_program` guard, or a test that
drives a real built binary or plugin on each leg. A `skipIf(win32)` is not one,
and neither is a fixture string that merely names an OS. `assert-suite-cover.py`
fails the Windows leg on any registered entry that is neither selected nor
excluded.

## Postgres for server tests (`YUZU_TEST_POSTGRES_DSN`)

ADR-0006 decision 8: every tier that runs the server **`[pg]`** suite gets a
real PostgreSQL and exports `YUZU_TEST_POSTGRES_DSN`. The shipped substrate is
**PostgreSQL 18** (`deploy/docker/Dockerfile.postgres`), and the Linux/docker
legs test against it; the server SQL is version-agnostic (13+), so a
runner-native cluster on an older major still exercises the suites correctly,
except where a step sets `YUZU_TEST_PG_CLONE_STRATEGY` (the Linux test step's
pg half does), which needs 15+.
One script implements it everywhere — `scripts/ci/ensure-postgres.sh`, inserted
as an `Ensure Postgres (server tests)` step between Build and Test in ci.yml
(linux) and nightly.yml (asan / tsan / coverage).

**Only Linux runs the server suites (ADR-0035 ladder step 1).** The Windows and
macOS legs of `ci.yml` configure agent-only (`server` option `auto`, off on any
non-Linux target), so they build no server code, register no server suite and need no Postgres; the Windows job no
longer runs `Ensure Postgres`. Wee Tam's per-agent PostgreSQL services stay
provisioned until ladder step 4 deprovisions them, and
`deploy/windows/Assert-Toolchain.ps1` still health-checks them in the Windows
job's `Assert toolchain manifest (self-hosted)` step, so a Wee Tam Postgres
outage still fails the Windows leg although no step uses the database. The
Windows-specific paragraphs below (path 1, the per-agent ports) describe that
still-provisioned setup and the pre-step-1 CI use of it.

**macOS does NOT run the server `[pg]` suite (ADR-0035; #2394).** Since ADR-0035
step 1 it builds no server at all; the history below explains why the `[pg]`
suite was dropped there first. The Yuzu
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
still ran. At the time Linux + Windows both ran the full `[pg]` shard set
(Windows additionally skipping 44 migration-in-substance fresh-DB cases,
#2354, "PG coverage by platform" below); since ADR-0035 step 1 only Linux does.
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

   **Footprint probe and the tmpfs PGDATA experiment (2026-10-21).** The
   Linux full-pg job ends with a `Postgres container footprint (tmpfs sizing
   probe)` step (`if: always()`, never fails the job) that prints `free -m`
   and `du -sm /var/lib/postgresql` for each `yuzu-ci-postgres*` container
   after the pg shards ran. Those numbers size a later, separately-measured
   push (the ladder in "Staged widening — Linux"): `ensure-postgres.sh`'s
   `docker run` gains `--tmpfs /var/lib/postgresql:rw,size=<cap>` (the image's
   PGDATA is `/var/lib/postgresql/18/docker` under its `VOLUME
   /var/lib/postgresql`), `PG_TUNE_LABEL` moves to `v2-tmpfs-pgdata` so the
   drift guard recreates existing per-agent containers, and the guard's
   `docker rm -f` becomes `-fv` so a retired container's anonymous volume is
   removed too. Cap rule: `size` = max(2g, 2x the measured post-run PGDATA, rounded
   up to 1g); four containers x cap must be at most 50% of the probed host RAM,
   otherwise tmpfs is not applied and the result is recorded here instead. A
   tmpfs cluster is empty after any container restart; the entrypoint then runs
   initdb and creates the database, the same path a brand-new container takes,
   and the script's 120 s `pg_isready` wait covers it. The change is kept only
   if the pg step's two samples show a gain; reverting is dropping the flag and
   bumping the label again. Docker Linux path only. Probe output and the
   decision: pending — filled by the push that applies or declines it.

   **Clone-strategy knob (2026-11-10; measured and wired 2026-11-14).** Every
   template-cloned `[pg]` case runs `CREATE DATABASE ... TEMPLATE ...`
   (`PostgresTestDb`, `tests/unit/test_helpers.hpp`). Setting
   `YUZU_TEST_PG_CLONE_STRATEGY` to `wal_log` or `file_copy` (any case) appends
   `STRATEGY WAL_LOG` or `STRATEGY FILE_COPY` to that statement; unset leaves the
   SQL unchanged (the server default, `WAL_LOG` on PostgreSQL 15+), and any other
   value fails the fixture with a message naming the variable. Measured on Big
   Tam in two runs of draft PR #7701, each running the `server-pg` suite four
   times in one job (default, file_copy, file_copy, default) so that load drift
   hits both strategies alike:

   | Run | default (wall / serial) | file_copy (wall / serial) | default (wall / serial) |
   |---|---|---|---|
   | 1 | 751 s / 2633 s | 739 s / 2625 s, 711 s / 2499 s | 807 s / 2850 s |
   | 2 | 927 s / 3303 s | 869 s / 3133 s, 870 s / 3136 s | not finished (step timeout) |

   Every default pass was slower than both file_copy passes of its run: about
   6-7% wall and 5-7% serial. Run 2 was on a busier box (all of its numbers
   about 20% higher), so compare within a run, not across. Result: the Linux
   test step's `pg_half` exports `YUZU_TEST_PG_CLONE_STRATEGY=file_copy` for
   both `pg_mode`s (a value leaking in from the runner is warned about and
   overridden; `tests/shell/test_linux_concurrent_step.sh` pins both). The
   checkpoint `FILE_COPY` forces stays inside the job's own per-runner
   Postgres container. No other workflow sets it. It needs PostgreSQL 15+ (every
   Big Tam agent runs the pinned 18 image), and it is only a gain with
   `fsync=off`, as `ensure-postgres.sh`'s Docker cluster runs: on that image a
   25 MB template cloned in 44 ms against 65 ms (`WAL_LOG`) with fsync off, but
   636 ms against 68 ms with fsync on. The pg half sets it whatever the
   cluster, so a Linux runner whose pre-set DSN or native fallback reaches a
   durable cluster would lose time instead (no Big Tam agent does). It moves the
   pg step's baseline: pg-step samples for a later push (the tmpfs push, Push 3)
   compare only against runs that include it, and samples taken before it (the
   concurrent-halves runs, and #7703's Push 2d samples) do not. Revert:
   `git revert -m 1` the merge commit of the PR that wired it. The
   concurrent-halves kill switch (`YUZU_CI_SEQUENTIAL_HALVES=1`) does not undo
   it: if a pg-half revert trigger persists with the switch set, revert this
   next. Contract:
   `docs/testing/unit-test-conventions.md`.
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

   **Wee Tam (`yuzu-weetam-windows`) uses path 1, not path 4 (unused by CI
   since ADR-0035 step 1):** each runner
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

   From the Windows CI test-phase restructuring (#3443, 2026-08-28)
   until ADR-0035 ladder step 1, `ci.yml`'s Windows job ran the
   `Test (pg shards, full)` / `Test (pg smoke)` split, mirroring the
   Linux job's `pg_mode` shape. Since step 1 no `ci.yml` job on Wee Tam
   uses these clusters; they stay provisioned (and health-checked by
   `Assert-Toolchain.ps1`) until ladder step 4.
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

On the Windows pool, until ADR-0035 step 1 removed it (path 1, #3443
restructuring), `ci.yml`'s `Resolve pg_mode + assert Postgres DSN` step
loud-failed (the Linux job's step of the same name still does) (`::error`+`exit 1`,
checked before any test invocation runs, not just the PG-tagged ones) on
three separate conditions — `pg_mode` resolving to neither `full` nor
`smoke`, `YUZU_TEST_POSTGRES_DSN` being unset/empty after Ensure Postgres,
or the two symmetric matrix-include guards catching a broken mapping. It
does NOT check DSN *parseability* — a syntactically malformed but
non-empty DSN clears this step and only fails later, at the first actual
libpq connection attempt inside a PG-tagged test.

**Connect cap on the Linux test legs.** The
`Resolve pg_mode + assert Postgres DSN` step in the Linux job appends
`PGCONNECT_TIMEOUT=30` to `$GITHUB_ENV` (the Windows job did the same until
ADR-0035 step 1 removed its Postgres steps), so every connect libpq makes in the
later steps has a bound, including a connect to a backend that accepts the TCP
connection and then never answers (libpq has no connect timeout by default).
30 s is deliberately looser than `PgPool`'s own 10 s default: the pool lets the
variable win over that default and over an Options-level `connect_timeout_s`, so
in these steps the pool's connect bound is 30 s unless the DSN itself carries a
`connect_timeout`, which wins over the variable. A test that needs a short bound
must therefore put it in the DSN.
A 10 s cap failed a fixture connect on a heavily loaded dev box, which is why
the value is not 10. `scripts/ci/sweep-test-databases.sh` exports its own 10 s
for itself. Windows and macOS are not given the variable: those legs build no
server and export no DSN, so no `[pg]` test connects. On POSIX the `[pg_reachability]` unit tests unset the
variable for the duration of each case (`test_pg_reachability_probe.cpp`),
because the probe lets it override the 3 s deadline those tests bound; the
timing-sensitive cases are compiled out on Windows. A case that needs another
value sets it itself.

## PG coverage by platform

| Platform | pg shards | Migration-DDL tests | Notes |
|---|---|---|---|
| Linux (gcc-15/debug, every PR + primary push) | full (14 shards) | run | ADR-0006 reference platform |
| Linux (other legs: clang-21 debug on a push; release legs on a `main` push or Tier 2b dispatch) | smoke (`[pg-smoke]`, 11 cases) | run | #3443 Phase 2 |
| Windows | none (ADR-0035: agent-only, `server` option off) | n/a | server is Linux-only |
| macOS | none (ADR-0035: agent-only, `server` option off) | n/a | server is Linux-only |

Until ADR-0035 ladder step 1, Windows debug (every PR and push) ran the full
14 shards and Windows release (a `main` push or a Tier 2b dispatch) the smoke
subset, both with the migration-DDL tests skipped (next paragraph).

**#3508 (moving pg shards off Windows PRs) is superseded.** It was
deliberately not adopted while the Windows server still shipped and ADR-0035
was `proposed`. ADR-0035 was accepted on 2026-11-10 (#7465) and step 1 goes
further than #3508 asked: the Windows leg runs no server suite at all, on any
event, so the `server-pg` shard set is Linux-only. (Since ladder step 2,
`release.yml` builds neither `yuzu-server.exe` nor `YuzuServerSetup`.)

**Historical (Windows, before ADR-0035 step 1):** 44 migration-in-substance fresh-DB Postgres test sites (a real from-scratch
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

**Install profile (ADR-0035 ladder step 3).** The key deliberately has no install-profile term. Every Windows and macOS workflow now installs an agent-only profile with no `server` feature (`--x-no-default-features`, plus `--x-feature=tests` where tests build; `release.yml` omits `tests`), so the persistent self-hosted tree (each Wee Tam runner keeps its own `vcpkg_installed/x64-windows` in its workspace, under its own work root, and the CI, nightly and CodeQL Windows jobs it picks up reuse it) is never reconciled between a full and an agent-only shape in steady state (when main and dev carry different `VCPKG_COMMIT` values the sentinel key changes and the tree is wiped and rebuilt instead). Linux legs install the full manifest; the Linux agent images use the agent-only profile in their own containers. A workflow that mixes profiles on one tree pays an incremental vcpkg reconcile on each switch (`docs/build-guide.md` "Dependency features"); do not add a second profile on Wee Tam without updating that section and the pins in `scripts/ci/test_runner_health_check.py`.

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

Matrix: `build-{linux,windows,macos}`. `ci.yml`'s Windows job uses
`build-windows-agent-{debug,release}` (agent-only since ADR-0035 step 1; the
earlier `build-windows-{debug,release}` dirs are deleted on every run so a
server-configured tree is never reused). Nightly variants:
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
`flake-retry.py` writes `meson-logs/flake-retry.json` (`<logbase>-flake-retry.json`
when its meson arguments carry `--logbase`, as on Linux); the job finalizer imports
recovered listed cases into the runner's `ci_flake_events` table alongside the
suite timings. `tests/known-flaky.json` remains the reviewed source of truth —
the database is observation history, never an implicit allowlist. This is
reversible test tooling — no ADR (rationale in the wrapper header).

**Per-case duration summary (#4884).** The suite-budget table above is
per meson entry. Next to it, `scripts/ci/test-durations-summary.py` appends a
"Test durations — <label>" block to the job summary after each
`flake-retry.py` invocation in the Linux (three), Windows (one, since ADR-0035
step 1) and macOS (one) Test steps: every entry's wall seconds, meson timeout and
share of it, then the 25 slowest Catch2 cases (entry, case, seconds, runs). The
non-PR pg smoke run (the Linux step's smoke branch; the Windows `Test (pg smoke)`
step went with ADR-0035 step 1) is deliberately not summarised: it runs one ~3 s entry. The case data is Catch2's
own `--durations=yes`, now on every Catch2 entry except the two pinned exemptions
(the non-PR pg smoke entry and the `[tsan-heavy]` checkpoints entry; the `=`
form is required: a space would add a positional
`yes` that `check-pg-shard-partition.py` rejects as a second spec). It is
parsed from `meson-logs/testlog.json` (on Linux `meson-logs/<logbase>.json`, via
`--logbase`, because its invocations run concurrently), which meson overwrites on every
invocation, hence one call per invocation rather than one at the end of the
job. The stale file is removed first, so a run that selects no tests warns and
skips instead of re-reporting the previous log: on Windows and macOS each
step removes `testlog.json` before its run; on Linux the step deletes every
base's files once, up front, before either half starts. On a red invocation
`bash -e` stops before the summary, and the uploaded `meson-logs` artifact
carries the log for running the script locally (`testlog.json`; on Linux
`<logbase>.json`).

Catch2 prints a duration line at the end of every *section*, with the test
case's own line last on each re-entry, so the script keeps a line only when its
name is a listed case of that entry (`--list-tests --verbosity quiet`, one
spawn per Catch2 entry, 30 s timeout) and sums per case across re-entries
(`runs` is the number of re-entries). Section lines whose name is not also a case
name of that entry are dropped, so a nested section does not rank beside its
parent; a section that shares its name with another case of the same entry is
summed into that case (a known limit, pinned by the selftest; Catch2's
structured reporter is the fix if it ever bites). A failed listing degrades that entry
to unfiltered lines and marks it `(unfiltered)`. The report is never a gate:
any failure becomes a `::warning` and exit 0; only `--selftest` (meson test
`test-durations-summary selftest`) can exit non-zero.

On macOS the used share is against the nominal meson timeout; that leg runs with
`--timeout-multiplier 2`, so the real budget is double (the same convention as
the budget table above).

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

## Agent unit-test shards (#5073)

The agent suite's single `agent unit tests` entry (one serial Catch2 process,
240 s budget) is three entries over the same `yuzu_agent_tests` binary:
`agent unit tests shard A`, `shard B`, `shard C`, each `suite: ['agent',
'agent-shard']`, one positional tag spec, a per-shard `timeout:` (A and B 240 s;
C 480 s, raised from the old single entry's 240 s by #7135 as a deliberate,
temporary exception to the 50% budget rule in `docs/testing/unit-test-conventions.md`,
to come back down with the split tracked as #7177). #7135 measured shard C at
185 s to 212 s as a pass on Windows MSVC debug (three of the 206 s to 212 s samples
are from jobs that failed on the echo ETW case, not from green jobs) and at the old
240 s limit once under load; the sizing comment beside the `timeout:` records the
runs. The contention figure for the server `~[pg]` suite, 289 s with no other test
phase running (c0) to 603 s with four overlapping (c4), about 2.1x, was measured on
the pre-#3443 combined step; see "Windows test-phase concurrency gate". The entries
also take
`--allow-running-no-tests`. That flag is what stops the zero-match shard C from
failing when `meson test --suite agent --test-args '[tag]'` appends a second
positional spec. It does not make that a targeted run: Catch2 binds the extra
spec to the LAST comma-separated OR term only, so it is exact only for shard C,
it widens shards A and B, and a mistyped tag is no longer loud. Run the binary
directly for a targeted run (`build-*/tests/yuzu_agent_tests '[tag]'`, see
`docs/build-guide.md` "Direct binary invocation"). Repro (2026-10-01, Linux
`build-linux/tests/yuzu_agent_tests`, `<shard spec> '[nonexistent_zzz]'
--list-tests --allow-running-no-tests`): shard A lists 319 cases, B 437, C 0 (B's count changed in
the 2026-10-04 re-balance; A's did not).
Every CI leg selects the shards by `--suite agent` (ci.yml Linux step and Windows step,
nightly.yml windows-asan) or runs `meson test` unfiltered (macOS, nightly and
sanitizer legs); none selects the old entry name. `agent tsan-heavy checkpoints`
is unsharded and unchanged.

Partition rule and measured balance live in the comment above the entries in
`tests/meson.build`: a case runs in the lowest-numbered shard holding any of its
tags, shard C is the AND-NOT complement so new tests land there, and every
inclusion term ends `~[.]~[tsan-heavy]~[flaky-4086]` because an inclusion term
does not drop hidden cases by itself. `'agent shard partition invariant'`
(`suite: ['agent', 'agent-checks']`, defined outside `if build_server`) runs
`scripts/ci/check-pg-shard-partition.py --family agent`, the same script and
`check_partition()` as the server shards: it proves against the real binary that
every case of `~[.]~[tsan-heavy]~[flaky-4086]` is in exactly one shard. It also
fails if a shard spec term does not end with that suffix (the meson
`agent_shard_suffix` and the script literal are hand-synced), if a spec is not a
shape flake-retry's isolated retry can strip, or if two shard entry names are
equal or one contains another. It proves exactness, not balance: it prints per-shard case counts as an informational
notice, and the drift signal is the 80%-of-budget table above (shard C's mark is 384 s while
the #7135 raise stands, so it is a late warning until #7177 lands). Per-entry history
in `test-runs.db` / `ci_test_suites` is keyed by entry name, so it restarts under
the new names.

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
(`$RUNNER_TOOL_CACHE/yuzu-docker-buildcache/*-chisel`, `mode=max` — several
GB/arch, no built-in eviction); whole-`*-chisel`-dir mtime sweep >30 days, Linux
only, each removal under an exclusive non-blocking `flock` on `<dir>.lock`, so a
directory a publish job holds is skipped with a notice, never removed under it.
Since #1367 the same run also executes `scripts/ci/sweep-test-databases.sh`
on both boxes — the weekly out-of-band janitor for leaked `yuzu_test_*`
databases (thresholds and semantics: "Test-database lifecycle" above). It runs
even when a prune step before it failed (`if: success() || failure()`).

**Release buildx caches (WP15/S9).** The Big Tam publish jobs export
`type=local,mode=max` caches to `$RUNNER_TOOL_CACHE/yuzu-docker-buildcache/<image>`
(`server`, `gateway`, `postgres`, `<image>-chisel`); an export never deletes
superseded blobs, so `scripts/ci/prune-buildcache.py` removes the blobs no cache
index references. Each Big Tam runner has its own tool cache
(`/srv/ci/work-N/_tool`) and all four run as one OS identity, so the weekly job,
which lands on one runner, prunes all four runners' caches every week. In use is
decided by a lock, not the clock: each publish job holds a shared `flock` on
`<dir>.lock` from before its first build until the job ends
(`scripts/ci/buildcache-lock.sh`), and the prune takes it exclusively without
waiting and skips a directory in use; a publish job waits up to 30 minutes for a
prune holding it. As defence in depth the prune also skips a directory written
in the last 3 hours, removes only unreferenced regular files older than 24
hours, removes a BROKEN directory (unparseable index, or an index naming a
missing blob, which would fail its next import) whole so the next build runs
cold, and refuses a symlinked directory or lock. A directory it cannot read is
an error: reported, left untouched, and the step exits 1 after the last
directory. So is a directory holding a file dated more than an hour in the
future (a clock or file time that would otherwise keep the 3-hour window open
for ever), and one holding a blob that starts like JSON but is over the 64 MiB
read cap (read as a layer, its references would be lost and blobs a manifest
needs removed). Its clock-guard disposition is in `docs/clock-guarded-retention.md`.

**A corrupted release cache** (a publish build failing to import its cache with
`NotFound content`, or a prune error naming a directory): on the runner that ran
the leg, delete `/srv/ci/work-N/_tool/yuzu-docker-buildcache/<image>` (leave
`<image>.lock`; check no publish job is running on that runner), then "Re-run
failed jobs": that build runs cold (the C++ images take the longest). The weekly
prune removes a broken directory itself the next Sunday.

## Chiselled demo images + agent bundle (release-time)

`docker-publish-chisel` (in `release.yml`) builds the server/gateway/agent
`*.chisel` images for linux/amd64 on the self-hosted Linux runner (the
QEMU-emulated arm64 leg was dropped; re-adding arm64 is the open decision in
`docs/demo-environment.md`, "Publishing"). It carries a
`cancel-in-progress: true` concurrency group, so a re-tagged release supersedes
a stale build instead of queueing behind it, and a 120-min timeout. Since
#5242 it **is** in the `release` job's `needs:`: the release waits for it
(1–16 min on rc1–rc6) so the chisel SBOMs are always in `SHA256SUMS`, and a
failed or cancelled chisel leg skips the release.

`docker-publish-agent-bundle` runs **after** `release` (it repackages the
release's own agent archives, after verifying the release `SHA256SUMS` cosign signature) on a GitHub-hosted runner — no
compilation, so no self-hosted dependency — builds the image without pushing,
runs the release image vulnerability gate on it, pushes it, and cosign-signs +
SBOMs + attests the pushed `yuzu-agent-bundle-chisel` image like the other
publish jobs.

## vcpkg state corruption — recovery path

If a Windows CI run repeatedly fails at `Install vcpkg packages` with a
missing `.pc` file under `vcpkg_installed/x64-windows/lib/pkgconfig/`, the
corruption is in `vcpkg/packages/` (which the cache-key sentinel does NOT
reach). Recovery procedure + full corruption-path inventory:
`docs/ci-troubleshooting.md` §7. Don't leave the recovery step in `ci.yml`
after an incident — it defeats the cache.
