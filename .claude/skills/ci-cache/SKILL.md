---
name: ci-cache
description: Canonical patterns for caching in Yuzu CI workflows. Two snippets — one for ephemeral GHA-hosted runners (split actions/cache/restore + actions/cache/save, never `save-always: true`) and one for self-hosted runners (local filesystem cache under `runner.tool_cache`, no GHA cache round-trip). Use when adding a new vcpkg/ccache/dependency cache step to any workflow under `.github/workflows/`, or when reviewing a PR that touches `actions/cache@`.
---

# ci-cache

Canonical caching patterns for Yuzu CI workflows. **CI eats more time than dev — get this right the first time.**

## TL;DR — two patterns

| Runner kind | Cache mechanism | Snippet |
|---|---|---|
| GHA-hosted (`ubuntu-24.04`, `macos-15`, `windows-latest`) | `actions/cache/restore` + paired `actions/cache/save` | [GHA-hosted](#gha-hosted-ephemeral-runners) |
| Self-hosted (`yuzu-wsl2-linux`, `yuzu-local-windows`, future macOS) | Local filesystem under `runner.tool_cache` | [Self-hosted](#self-hosted-runners) |

**Hard rule (enforced by `.github/workflows/zizmor.yml`):** never use `save-always: true` on `actions/cache@`. The input is deprecated by the actions/cache maintainers as "does not work as intended and will be removed in a future release." The `Guard — no save-always on actions/cache` step in zizmor.yml fails any workflow audit if `^[[:space:]]*save-always:` reappears as a YAML key. Don't try to silence the guard — rewrite the cache step using the snippets below.

Reference: <https://github.com/actions/cache/tree/main/save#always-save-cache>.

---

## GHA-hosted (ephemeral runners)

Each job starts on a fresh disk. The cache lives in GitHub's blob storage and is moved over the network on restore + save. Use the **split restore + always-save pattern**:

```yaml
- name: Restore <thing>
  id: cache-<thing>
  uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
  with:
    path: <path>
    key: <primary-key-with-strong-uniqueness>
    restore-keys: |
      <progressively-shorter-fallback-prefixes>

# ... build / test / install steps that produce the cache content ...

- name: Save <thing>
  # `if: always()` is the documented replacement for the deprecated
  # `save-always: true` input — runs even on Build/Test failure, which
  # is the only behaviour `save-always` was meant to deliver. NOTE: this
  # is right for an ADDITIVE cache only — see "Additive vs
  # coherent-artifact caches" below before copying it onto a tree. The
  # `cache-hit != 'true'` gate skips the upload when the primary key
  # already matched on restore (no new content to save, no point
  # paying the upload cost).
  if: always() && steps.cache-<thing>.outputs.cache-hit != 'true'
  uses: actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
  with:
    path: <path>
    key: ${{ steps.cache-<thing>.outputs.cache-primary-key }}
```

`<progressively-shorter-fallback-prefixes>` above is a CORRECTNESS-safe shape for a
content-hash key — an older prefix match is strictly worse (staler content) but never
*wrong* content, so restoring it can't corrupt the build **on its own**. That guarantee
is not free-standing, though: it holds only as long as something downstream actually
reconciles a stale restore against the current inputs (vcpkg's own sentinel does this —
see `scripts/ci/vcpkg-triplet-sentinel.sh` — wiping and rebuilding on drift rather than
trusting the restored tree as-is). Copy this shape onto a coherent-artifact cache with no
such reconciliation step and "correctness-safe" stops being true.

It also does NOT follow that an open-ended prefix is risk-free even where correctness does
hold: every fallback hit still refreshes GitHub's last-accessed clock, so if the key's
inputs ever change (a new manifest, a new pinned commit, a key-format migration), the
ENTRIES BEHIND that fallback stop being reachable by a fresh primary key but stay immortal
via the open prefix — the same quota-crowding failure mode as below, just gated on how
often the key's inputs change rather than guaranteed on every run. The vcpkg example
further down carries this risk today, tracked but not yet fixed (#3888).

It is a WRONG shape outright — correctness-safe or not — for a time-bucket key (see "For
ccache" below), where the key's inputs change on every run by construction: a bare
open-ended prefix there matches every entry the cache name has ever produced, including one
left by a since-changed key format. Name the specific previous bucket instead.

**Additive vs coherent-artifact caches — `always()` is not always right:**

The `if: always()` above is correct for an **additive** cache, where every object saved is
independently valid and a partial save is merely a smaller cache. `ccache` is the type case.

It is **wrong** for a **coherent-artifact** cache — `vcpkg_installed`, or any installed-prefix
tree — where the entry only means anything as a complete set. A run cancelled or failed
part-way saves a half-populated tree, and because the key inputs (manifest + baseline) still
claim it is complete, the next run restores it as an exact hit, rebuilds everything anyway, and
then **skips its own save** because `cache-hit == 'true'` — so the good tree is discarded and
the poison persists. GHA cache keys are immutable, so nothing can overwrite it; only
out-of-band deletion recovers (`gh cache delete <id>`, recipe under "For ccache" below —
the command is the same regardless of which failure mode put the entry there). This is not
hypothetical: it cost the canary ~65 min per run until #3229.

Note the split is about CONTENT VALIDITY, not about key occupancy. The
`cache-hit != 'true'` skip means ANY entry — additive or not — locks its key for
as long as it lives, so a thin entry saved by a cancelled run suppresses later
saves in both cases. For an additive cache that costs a colder cache; for a
coherent artifact it hands out a tree that reads as complete. Only the second is
a correctness problem, which is why only the second is gated here — but do not
read "additive" as "immune".

Two consequences follow, and they are different questions:

**Correctness** — only coherent artifacts need it. Gate the save on the **producing
step's** outcome, not the job's.

**Key occupancy** — both classes need thought. A thin entry written under an exact
key is hit by every later run with the same inputs, which then skips its own save,
and the key is immutable. For an additive cache that costs a permanently colder
cache rather than a wrong answer, so the gate is looser: save when the producing
step RAN (pass *or* fail — a failed build's objects are still worth keeping), skip
only when it was cancelled or never started. `ci.yml`'s canary ccache save is the
worked example.

**Key inputs must be stable.** `hashFiles` globs the whole workspace and does not
honour `.gitignore`, so a bare `**/*.cpp`-style glob also hashes anything an
earlier restore step materialised — dependency trees included. The key then differs
between a cold and a warm run and the namespace splits. Scope the glob to the
source roots you actually compile (#3270).

For coherent artifacts, additionally gate on the **producing step's** outcome, not the job's:

```yaml
- name: Install deps
  id: install-deps
  run: ...

- name: Save <tree>
  # always() is still required — see the invariant above; without it the
  # implicit success() would also skip the save when only a LATER step
  # (e.g. Build) failed, even though the tree is complete and worth keeping.
  if: always() && steps.install-deps.outcome == 'success' && steps.cache-<thing>.outputs.cache-hit != 'true'
```

**Key construction (D3 of the CI overhaul plan):**

For vcpkg: include manifest + every overlay triplet + the pinned baseline. Example:

```yaml
key: vcpkg-<triplet>-${{ env.VCPKG_COMMIT }}-${{ hashFiles('vcpkg.json', 'vcpkg-configuration.json', 'triplets/*.cmake') }}
restore-keys: |
  vcpkg-<triplet>-${{ env.VCPKG_COMMIT }}-
  vcpkg-<triplet>-
```

The bare `vcpkg-<triplet>-` second-tier fallback is correctness-safe here specifically
because `scripts/ci/vcpkg-triplet-sentinel.sh` wipes and rebuilds on any drift rather than
trusting a restored tree as-is (see the caveat above) — but it still carries the same
quota-crowding risk as an unfixed time-bucket key. That risk is gated on how often
`VCPKG_COMMIT` itself changes, not the manifest or triplet hash: a manifest-only change is
already absorbed by the first tier (`vcpkg-<triplet>-<COMMIT>-`, still matching since
`VCPKG_COMMIT` is unchanged), so the bare tier only gets reached when `VCPKG_COMMIT` moves
or every first-tier entry has aged out. The canary's live copy of this pattern has this
risk today, tracked as #3888.

For ccache: a TIME-BUCKET key, not a source hash. ccache hashes the real
preprocessed input per object, so the GHA cache key needs no source identity —
a stale entry can only lower the hit rate, never yield a wrong object. A
source-hash key (`hashFiles('**/*.cpp', ...)`) was the original recipe here and
is DISPROVEN for this repo: on ~75 commits/day it never exact-hits, so every
run falls to the prefix restore-key and then saves a fresh multi-GB entry —
the canary's copies alone ran the repo 7x over GitHub's 10 GB cache quota,
and the resulting LRU eviction degraded the canary itself and starved every
other cache (measured 2026-09-01; fixed in the same change that rewrote this
recipe). Bucket by TIME — one saved entry per bucket per scope; later
same-bucket runs exact-hit and skip the save. Pick the bucket width from the
trade: shorter = fresher cache (hit-rate decay is capped at the bucket width)
but more live entries against the 10 GB repo quota. The canary uses a rolling
3-day bucket (~2-3 live entries — but only because restore-keys below is
scoped to the previous bucket; an open-ended prefix defeats the bound, see
next paragraph. A weekly bucket risked heavy-week Thu/Fri decay, daily would
hold up to 7 entries):

```yaml
- name: Compute ccache time bucket
  run: |
    now="$(date -u +%s)"
    echo "CCACHE_BUCKET=$(( now / 259200 ))" >> "$GITHUB_ENV"
    echo "CCACHE_PREV_BUCKET=$(( now / 259200 - 1 ))" >> "$GITHUB_ENV"
# 259200 s = 3 days. (If you prefer a calendar week: date -u +%G-W%V —
# %G ISO year pairs with %V ISO week; %Y mispairs at year boundaries.)
# Read the clock ONCE — two independent `date` calls can straddle the
# bucket boundary and desync BUCKET from PREV_BUCKET.
...
key: ccache-<leg>-${{ env.CCACHE_BUCKET }}
restore-keys: |
  ccache-<leg>-${{ env.CCACHE_PREV_BUCKET }}
```

**Never leave a time-bucket key's restore-keys as a bare prefix** (`ccache-<leg>-`
with nothing after it). Unlike a content-hash key, a bare prefix here matches
every entry this cache name has EVER produced — including one left by a
since-abandoned key format — and every fallback hit refreshes GitHub's
last-accessed clock, the only thing that ever ages a cache out. That makes a
dead entry immortal instead of merely stale: one survived a full day past a
key-format migration, ~2.4 GB of dead weight pinning the pool back near the
10 GB quota a prior fix had just cleared (measured 2026-09-02). Name the
specific previous bucket, as above — anything else then ages out on GitHub's
own 7-day-unused clock instead of living forever. **Recovering from an
already-immortal entry:** `gh cache list --repo <owner>/<repo> --limit 100`
to find its numeric id (the first column), then `gh cache delete <id> --repo
<owner>/<repo>` to remove exactly that entry. Delete by id, not by key — a
time-bucket key like this one has no branch component, so `push` and
`pull_request` runs routinely produce several entries sharing the same key
on different refs, each with its own id; `gh cache list`'s columns are
id/key/size/created/last-accessed (no ref column), and the id is the one
value in that listing that names a single entry unambiguously.

Pair the bucket with a job-level `CCACHE_MAXSIZE` sized for ONE build of that
leg (the workflow-level value may be a self-hosted budget orders of magnitude
larger) — ccache only trims at MAXSIZE, so an uncapped entry grows
monotonically forever.

**Branch-scope gotcha (the canary cold-start lesson from PR #740):**

GHA cache scope is **branch-isolated** with PR runs scoped to `refs/pull/<N>/merge`. A PR job can read caches from (a) its own ref, (b) the repo's default branch, (c) the PR's base branch. **Sibling-PR caches are unreadable.** If a job only ever runs on `pull_request`, its cache never lands on `refs/heads/main` and every PR cold-starts.

Fix: also trigger the job on `push` to the branch PRs actually base on. The canary job in `ci.yml` does this via `detect-ci-changes` firing on `pull_request` plus `push` to `refs/heads/main` **and `refs/heads/dev`**. Warming only the default branch is not enough here and silently stopped working: this repo integrates on `dev`, `main` moves only at release time, and with no `main` push for five weeks the warm scope was simply empty — every PR then saved its own private ~843 MB copy of a byte-identical tree, six of them live at once against a 10 GB repo cap (#3233). Pick the branch by scope rule (c), not by convention, and check it is actually pushed to.

**Untrusted code never runs in a scope a trusted run reads (#4471).** The same rules are the security boundary. `fork-dynamic-review.yml` and `trusted-fork-ci.yml` → `ci.yml` execute fork code under `workflow_dispatch`, whose cache scope is the dispatch ref, and any code executing in a run can write that scope (the runtime token is in the runner process) — so a `save:` gate cannot close it. They refuse any ref but a throwaway `trusted-fork/pr-<N>` branch, unreadable from `main`, `dev`, or any PR by (a)–(c), and BOTH workflows carry their own `purge-quarantine-cache` job that deletes that scope right after they finish (branch deletion alone leaves entries for seven days) — the review workflow's own purge closes the window in which its pre-approval writes would otherwise be restorable by the later trusted gate on the same ref. The canary's `trusted_execution != 'true'` save gates are defence in depth behind that, not the primary control. CodeQL's `actions/cache-poisoning/poisonable-step` cannot see the confinement and is excluded in `.github/codeql/codeql-config.yml`; `scripts/ci/test_runner_health_check.py` sweeps for any new PR-derived checkout outside those two workflows.

---

## Self-hosted runners

Self-hosted runners (`yuzu-wsl2-linux`, `yuzu-local-windows`, and any future self-hosted macOS) keep state across jobs. **Skip GHA's blob-storage cache entirely** — round-tripping ~1 GB of vcpkg binaries through GHA storage when the same data already lives on the runner's local disk is an unforced loss. Pin caches to `runner.tool_cache` (a stable per-runner path that survives between jobs but is owned by the runner setup, not the workspace):

```yaml
# Self-hosted: no actions/cache step at all. Set the env var that
# the build tool consumes and let it manage its own on-disk cache.
- name: Configure local cache paths (self-hosted)
  if: ${{ !contains(runner.name, 'GitHub') && runner.environment == 'self-hosted' }}
  run: |
    echo "VCPKG_DEFAULT_BINARY_CACHE=${{ runner.tool_cache }}/yuzu-vcpkg-binary-cache-${{ matrix.os }}" >> "$GITHUB_ENV"
    echo "CCACHE_DIR=${{ runner.tool_cache }}/yuzu-ccache-${{ matrix.os }}" >> "$GITHUB_ENV"
    mkdir -p "${{ runner.tool_cache }}/yuzu-vcpkg-binary-cache-${{ matrix.os }}"
    mkdir -p "${{ runner.tool_cache }}/yuzu-ccache-${{ matrix.os }}"
```

(See `.github/workflows/codeql.yml` for the existing `VCPKG_DEFAULT_BINARY_CACHE → runner.tool_cache` wiring on the Windows self-hosted runner — that's the pattern.)

**Why `runner.tool_cache` and not `~/.cache/...`:**

- `runner.tool_cache` is a stable, runner-managed path. It survives `actions/checkout` workspace cleanup (which can wipe `vcpkg_installed/` if `clean: true` is set, see lesson from session 2026-04-28).
- It's per-runner (not per-job), so back-to-back jobs on the same runner share warm caches.
- It's outside `${{ github.workspace }}`, so concurrent jobs can't race on the same file.

**Per-triplet (not per-matrix-leg) scoping:**

If two matrix legs build the same triplet (e.g., `gcc-13 debug` and `gcc-13 release` both build `x64-linux`), share the cache directory keyed on the **triplet**, not the matrix axis. The CI overhaul commit on 2026-04-28b establishes this — cumulative first-warm cost dropped ~5 h → ~2 h 20 min by collapsing per-matrix scopes into per-triplet scopes.

**Sentinel-driven invalidation:**

Self-hosted caches stay until something invalidates them. `scripts/ci/vcpkg-triplet-sentinel.sh` is the canonical invalidator: it computes the cache key from `vcpkg.json` + `vcpkg-configuration.json` + overlay triplets + `VCPKG_COMMIT`, compares against the stored sentinel, and wipes the triplet tree (and the orphaned-registry `vcpkg/info/` directory — see #741) on drift. Always run the sentinel before `vcpkg install` on self-hosted.

**Future self-hosted macOS:**

When the self-hosted Mac lands (replacing or augmenting the `macos-15` GHA runner), it should follow the self-hosted pattern: drop the `actions/cache` step from the macOS leg, set `CCACHE_DIR=${{ runner.tool_cache }}/yuzu-ccache-macos-${{ matrix.build_type }}` and `VCPKG_DEFAULT_BINARY_CACHE=${{ runner.tool_cache }}/yuzu-vcpkg-binary-cache-arm64-osx`, and rely on the runner's local SSD. ccache deltas on macOS are the same shape as Linux (~30 G with `CCACHE_MAXSIZE=30G`); the GHA-hosted cap of 10 GB total per repo no longer applies.

---

## Reading the existing tree

When in doubt, read these as worked examples (all up-to-date as of v0.12.0-rc0):

| File | Pattern shown |
|---|---|
| `.github/workflows/ci.yml` macOS legs (lines 564–675) | GHA-hosted split restore + paired save |
| `.github/workflows/ci.yml` canary (job `canary:`; line numbers drift, grep the job name) | GHA-hosted split restore + paired save + push-to-main/dev warming |
| `.github/workflows/release.yml` (lines 703–751) | Restore-only (release builds consume cache, never produce — see comment block) |
| `.github/workflows/codeql.yml` | Self-hosted `VCPKG_DEFAULT_BINARY_CACHE → runner.tool_cache` |
| `scripts/ci/vcpkg-triplet-sentinel.sh` | Sentinel invalidation logic, including the orphaned-registry self-heal |

---

## When to add a new cache

Three questions to answer before you add `actions/cache/restore`:

1. **What's the cache key?** Must be uniquely determined by the inputs that change the cache content. Source-file hash for ccache; manifest + triplet + baseline for vcpkg; pip-tools requirements file hash for `~/.cache/pip`. If the key collapses two materially-different states into one entry, the cache is poisoned.
2. **Where does it save?** GHA-hosted → blob storage with branch-scope rules. Self-hosted → local `runner.tool_cache`. Pick one based on the runner kind, never both.
3. **Will it ever warm via a push to main or dev?** If only `pull_request` writes the cache, every PR cold-starts. Either accept that or add a push trigger on the branch PRs base on that produces the cache (see canary in ci.yml).

If any of those three feels wrong, the cache step is wrong. Re-read this skill before pushing.
