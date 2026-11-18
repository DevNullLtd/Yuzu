---
name: release
description: Cut a Yuzu release end-to-end. Runs preflight checks, validates compose-file version pins, pushes the tag, monitors the release workflow until artifacts publish, troubleshoots known failure modes (artifact download bugs, version mismatch, Windows signing, macOS notarization), verifies the GitHub Releases page has every expected asset including the Compose Wizard zip, and produces a release record. Use when the user says "/release vX.Y.Z" or asks to cut a release.
---

# release

Runbook for cutting a Yuzu release. Like `/test`, this skill is a **bash-first orchestrator** — each phase is one or more shell invocations the LLM executes via `Bash`. The LLM's job is to interpret failures, decide whether to continue or roll back, and produce the consolidated release report at the end.

Releases publish to two destinations from one tag push:
1. **GitHub Releases page** — platform tarballs/zips, .deb/.rpm packages, Windows/.macOS installers, SHA256SUMS + cosign signature, and the Compose Wizard zip
2. **GHCR** — `ghcr.io/<owner>/yuzu-server:X.Y.Z` and `:yuzu-gateway:X.Y.Z` Docker images. **NOTE: GHCR tags strip the leading `v`** — git tag is `v0.12.0-rc0`, GHCR image tag is `0.12.0-rc0`. The release workflow's `docker buildx push` step strips the prefix; verification commands must match.

Both go out from `.github/workflows/release.yml`, triggered by `git push origin vX.Y.Z`.

## Usage

```
/release vX.Y.Z              # stable release (e.g. v0.11.0)
/release vX.Y.Z-rcN          # release candidate (e.g. v0.11.0-rc1)
/release --watch vX.Y.Z      # only monitor an in-flight release
/release --verify vX.Y.Z     # only verify a published release
/release --resume vX.Y.Z     # tag exists and CI started — pick up where workflow stalled
```

Default mode (no flag): full pipeline from preflight → tag push → workflow monitor → verification.

## Pre-conditions the operator must confirm

Before invoking the skill, the operator should already have:
- All commits intended for this release merged to `main` (releases tag from main, not dev — confirm `git log origin/main..origin/dev` is empty or only contains intentional dev-only changes).
- CHANGELOG promoted: `python3 scripts/assemble-changelog.py promote X.Y.Z` run and committed — it assembles all `changelog.d/` fragments (plus any legacy `[Unreleased]` content) into `## [X.Y.Z] - YYYY-MM-DD` and deletes the fragment files. Never hand-move `[Unreleased]` content. Preflight check 4b fails while unpromoted fragments remain. **Later RCs and the final release:** the version was promoted at its first RC, so hotfix fragments added since then are folded in with `python3 scripts/assemble-changelog.py promote X.Y.Z --append` before each later RC tag, and with `--append --date <final-date>` before the final tag; run that even if no fragment landed since the last RC: with no fragments it only re-dates the header (#5221). Convention: `changelog.d/README.md`.
- `meson.build` `version: 'X.Y.Z'` updated.
- The six required checks green on the commit being tagged (`main`'s tip). **Skipped counts as passing; absent, failed or cancelled do not.** A docs/changelog-only push to `main` (the final `promote --append --date` commit is one only when it touches `CHANGELOG.md` alone; folding fragments also deletes `changelog.d/*.md`, which are nested markdown and so build) skips the build legs via preflight's `code_changed=false` (#5320): `Proto backward-compat` shows `skipped`, and the `Linux gcc-15 debug` / `Windows MSVC debug` / `macOS debug` names come from the `docs-required-checks` stub as `success`. That skip only happens when the previous commit's push run succeeded, so a green docs-only commit never hides a red or unbuilt code commit. `success` on those three names for a docs-only commit means *inherited from the predecessor's build*, not *built*; the run's summary says so. A context that is missing entirely is a stop: wait for the run, or find out why it did not start. Check it with:

  ```bash
  SHA=$(git rev-parse origin/main)
  gh api "repos/DevNullLtd/Yuzu/commits/$SHA/check-runs?per_page=100" --jq '
    if .total_count > 100 then "WARN: \(.total_count) check runs; only the first 100 were read" else empty end,
    ([.check_runs[] | select(.name | IN("Preflight (runner health)","Proto backward-compat","Linux gcc-15 debug","Windows MSVC debug","macOS debug","CHANGELOG order"))]
     | group_by(.name) | map(max_by(.id)) | .[] | "\(.name)\t\(.status)\t\(.conclusion)")'
  ```

  It must print all six names, each `completed` with `success` or `skipped`. The ruleset that lists them is the repo's "Protect Main" setting, not this file.
- The release/LTO legs green on `main`'s tip, and no open `release-legs-broken` issue. These legs are not required checks, but they are the only place the test suite runs in release/NDEBUG mode: `release.yml` builds with `-Dbuild_tests=false`. Since Tier 2b (`docs/ci-architecture.md`) they no longer run on dev pushes, only on `main` pushes and a daily dispatch on dev. An open issue means dev's release legs were red at the last dispatch, or the daily workflow itself failed (its reconcile or dispatch job; the issue says which). Find out whether that defect reached `main` before tagging:

  ```bash
  SHA=$(git rev-parse origin/main)
  gh issue list --repo DevNullLtd/Yuzu --label release-legs-broken --state open
  gh api "repos/DevNullLtd/Yuzu/commits/$SHA/check-runs?per_page=100" --jq '
    [.check_runs[] | select(.name | test("^(Linux (gcc-15|clang-21)|Windows MSVC|macOS) release$"))]
    | group_by(.name) | map(max_by(.id)) | .[] | "\(.name)\t\(.status)\t\(.conclusion)"'
  ```

  Expect four names, each `completed`/`success`. If the tip is a docs-only commit (the usual case for the final `promote --append --date` commit), it built nothing and the query prints nothing. In that case, set `SHA` to the most recent `main` commit whose push run built code (its run shows the build legs, not the `docs-required-checks` stubs) and re-run it there. No output on a code commit is a stop.
- All tracked compose files updated to `${YUZU_VERSION:-<BASE_VERSION>}` defaults — the **base** version with any `-rcN`/`-betaN` suffix stripped (e.g., for tag `v0.12.0-rc0` the default is `0.12.0`, NOT `0.12.0-rc0`). The workflow's `Validate docker-compose image versions` gate inside the `Create Release` job invokes `bash scripts/check-compose-versions.sh "$BASE_VERSION"` and will hard-fail the release after the full build matrix has run if the defaults don't match. Local dry-run **must use the same base version**: `bash scripts/check-compose-versions.sh 0.12.0` (NOT `0.12.0-rc0`) — the script accepts whatever you pass and is happy with consistent garbage, so passing the rc-suffixed version locally green-lights a doomed release. Preflight (`scripts/release-preflight.sh`) does the right thing automatically because it strips the suffix internally; the lesson from v0.12.0-rc0's first cut was that local one-off `check-compose-versions.sh` invocations are misleading on RC tags.

- No image-gate acceptance or not-covered listing still pending approval, expired, or expiring within two days (WP15/S9). The release gate (`--release`) does not honour an entry whose `approval_ref` is `pending` or that has expired, and each publish leg re-reads the date, so a tag cut with one fails at that image's publish leg, after the other legs that reached "Tag the release" have moved `:X.Y.Z` (and `:X.Y`/`:latest` on a stable tag) to their verified, signed digests. Check the tagged tree:

  ```bash
  python3 -I scripts/ci/image-vuln-gate-checks.py pending .trivyignore.yaml scripts/ci/image-vuln-gate-not-covered.txt
  ```

  It must exit 0 and print `no pending, expired or expiring acceptance or listing`. Exit 1 lists each problem: record a pending approval as `docs/ci-architecture.md` "Recording an approval" describes, and renew (a new review and approval) or remove an expired or expiring entry; each is a commit, reviewed like any change to those files; then re-check. A `warning:` line is an entry expiring within 21 days. The check reads the approval fields' format only; it cannot tell a real approval from a typed one, and the approver may be the entry's author: the control is the review (`CODEOWNERS`, "The approver can be the change's author" in that doc).

If any of these are missing, the skill prompts the operator to fix-and-commit-and-push before continuing. **It does NOT auto-bump versions** — bumping is a deliberate decision (which X, which Y, which Z) the operator owns.

## Phase 0 — Preflight (~30 sec)

Run from the repo root on `main` (or whatever branch is being tagged):

```bash
git fetch origin
git status -sb                                    # confirm branch + clean tree
bash scripts/release-preflight.sh vX.Y.Z          # CRLF, version, CHANGELOG, compose pins
bash scripts/check-compose-versions.sh X.Y.Z      # explicit compose check (preflight wraps this too)
```

Preflight checks:
1. No CRLF in scripts or gateway config
2. `meson.build` version matches the base version of the tag (rc/beta suffix stripped)
3. CHANGELOG has a `## [X.Y.Z]` section with non-empty content
4. Working tree is clean
5. `Dockerfile.server` includes `--data-dir`
6. All `actions/cache@v*` steps in release.yml have `save-always: true`
7. `docker-compose.full-uat.yml` includes `--data-dir`
8. `origin/dev` and `origin/main` are reconciled (no divergence either direction)

Optional `--full` adds a local C++ + Erlang compile (~2 min).

Windows and macOS releases are agent-only (ADR-0035 ladder step 2): `release.yml` builds no Windows or macOS server and no `YuzuServerSetup`, and the Windows and macOS archives are `yuzu-agent-windows-x64.zip` and `yuzu-agent-macos-arm64.tar.gz`. `tests/test_release_agent_only.py` (Docs Lint and `meson test`) fails if a server build or an old archive name comes back, or if the archive names in `release.yml`, `scripts/check-release-artifacts.sh` and `scripts/build-agent-bundle.sh` disagree, so there is no hand check left for this. The first release after step 2 is also the first real run of the changed Windows and macOS jobs: watch them, especially the Windows "Verify the agent runs from the packaged archive" step. Step 3 (`-Dserver`, agent-only vcpkg) adds a refusal of any server-port DLL (`libpq`, `libecpg`, `libpgtypes`, `drogon`, `trantor`, `jsoncpp`, `*xmlsec*`) in that step and makes every image-publish job wait for the builds; its first real run is the first release tag after it (an RC by plan), so watch that step and the six publish legs' start time on that run (the first-RC checks are tracked in #7597).

**Stop** if preflight fails. Surface the failures and ask the operator how to proceed (commit fixes? bump versions? abort?).

## Phase 0.5 — Branch reconciliation (only when preflight check #8 fails)

Releases tag from `main`, but ongoing development happens on `dev`. Every prior release has hit the same trap: `dev` accumulates dozens of merged commits, and the prior release's prep commits (CHANGELOG bump, version stamp) land directly on `main` without being cherry-picked back to `dev`. By the time the next release is cut, both branches are diverged in both directions and the operator has to remember to reconcile.

The preflight's check #8 surfaces this as a hard FAIL with the exact ahead/behind counts. Reconciliation flow:

```bash
# Diagnose what's where
git log --oneline origin/dev..origin/main    # commits on main, not on dev (usually 1-3 release-prep commits)
git log --oneline origin/main..origin/dev    # commits on dev, not on main (usually all the merged work)

# Step 1 — apply main's missing commits to dev (cherry-pick or merge).
# Cherry-pick is usually right when main only has a CHANGELOG bump from the prior release:
git checkout dev
git cherry-pick origin/dev..origin/main
# Resolve any CHANGELOG conflicts; commit; push:
git push origin dev

# Step 2 — fast-forward main to the new dev tip (now contains both halves).
# This is the safer path than `git checkout main && git merge dev` because it
# refuses if main ever diverges from dev again. After step 1, the FF should
# succeed cleanly:
git checkout main
git merge --ff-only origin/dev
git push origin main

# Step 3 — re-run preflight. Check #8 should now PASS.
bash scripts/release-preflight.sh vX.Y.Z
```

If step 2's `--ff-only` refuses, check #1 was incomplete — there are still commits on dev that aren't on main, OR the cherry-picks on dev didn't apply cleanly. Inspect with `git log --oneline origin/main..origin/dev` and resolve before continuing. Don't fall back to a non-FF merge; keeping `main` strictly fast-forward off `dev` is the invariant that keeps future releases honest.

After both branches are reconciled, the operator tags from `main` (which is now the same SHA as `dev` plus the prior release prep) and Phase 1 proceeds normally.

## Phase 1 — Tag and push (~5 sec)

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

This is the irreversible point. Once the tag is pushed, the release workflow starts. `git tag -d vX.Y.Z && git push --delete origin vX.Y.Z` can untag, but if any consumer has already pulled the GHCR image or downloaded an asset, untagging is socially expensive — confirm with the operator before doing it.

Capture the workflow run ID immediately:

```bash
sleep 10  # give GitHub a moment to start the workflow
RUN_ID=$(gh run list --workflow=release.yml --branch="vX.Y.Z" --limit=1 --json databaseId --jq '.[0].databaseId')
echo "Release workflow: https://github.com/DevNullLtd/Yuzu/actions/runs/$RUN_ID"
```

## Phase 2 — Monitor the workflow (~30-60 min)

The jobs run with a partial DAG (simplified; the full list follows):

```
release-guard ─┬─ build-linux ─── build-gateway ─┐
               ├─ build-windows ─────────────────┼─ docker-publish (2 legs) ───────┐
               └─ build-macos ───────────────────┤  docker-publish-chisel (3 legs) ┼─ release ─ docker-publish-agent-bundle
                                                 └─ docker-publish-postgres ───────┘
```
Every image-publish job before the release (`docker-publish`, `docker-publish-chisel`, `docker-publish-postgres`) needs ALL FOUR builds (`build-linux`, `build-gateway`, `build-windows`, `build-macos`), so the images start only after the slowest build (Windows, ~40 min); `release` needs every build and every publish job.

- **release-guard** (ubuntu-24.04, seconds) — fails the run if the tag already has a published release, or if the ref is not a `vX.Y.Z[-rcN]` tag (#5282); every other job waits for it
- **build-linux** (self-hosted Linux, ~25 min) — meson release + .deb + .rpm
- **build-gateway** (self-hosted Linux, ~10 min, needs build-linux) — rebar3 release + .deb + .rpm
- **build-windows** (self-hosted Windows, ~40 min) — MSVC + InnoSetup + signtool
- **build-macos** (self-hosted macOS, BigMags, ~30 min) — clang + codesign + notary
- **docker-publish** (matrix server+gateway, ~15 min each, needs all four builds) — buildx + GHCR push
- **docker-publish-postgres** (~1 min, needs all four builds as a success gate, not as an input: it holds no build artifact) — the `yuzu-postgres` image the composes pin
- **docker-publish-chisel** (matrix server/gateway/agent, 1–16 min warm, needs build-linux, build-gateway, build-windows + build-macos) — the `*-chisel` images and their SBOMs
- **release** (ubuntu-24.04, ~3 min, needs all of the above) — assemble artifacts, generate SHA256SUMS, cosign-sign, gh release create
- **docker-publish-agent-bundle** (needs release) — built from the published release; its SBOM is not a release asset

Since #5242 the release waits for `docker-publish-chisel`, so the chisel SBOMs are always in the signed `SHA256SUMS`. If any job the release needs fails or is cancelled (a build job, `docker-publish`, `docker-publish-postgres` or a `docker-publish-chisel` leg), the release job is skipped (fail-closed): no GitHub release is created, but an image leg may already have moved `:X.Y.Z` (and `:X.Y` and `:latest` on a stable tag). The push itself carries no release tag (an untagged digest; for the agent bundle, a `:candidate-<run id>-<attempt>` tag); the tags move only in that leg's "Tag the release" step, after the digest is verified, signed and attested. The leg's publish journal (`publish-<image>.attempt-N.txt` in its `<image>-image-vuln-gate-attempt-N` artifact) says how far it got: a last line `tagged` moved every tag, `tagging` may have moved some, anything earlier moved none. A failed build job is not such a case: all three image-publish jobs wait for all four builds, so a failed build, including a failed agent packaging step, pushes no versioned image (cost: the images start only after the slowest build, ~40 min, and a failed or cancelled Windows or macOS build blocks every image and the release; there is no sanctioned images-only publish path today, tracked in #7596). The chisel publish legs sit in a ref-and-image-keyed `cancel-in-progress: true` concurrency group with no SHA in the key, so a stale run's late chisel leg can cancel the newer run's leg for the same tag: another reason to cancel in-flight runs first. (A cancelled leg's `image-publish.sh` stops its own registry call before it exits, so it does not move a tag after the other run's leg has tagged, unless the runner itself dies mid-call: `docs/ci-architecture.md` "What the journal does not cover".) To recover, fix the cause and re-tag (cancel in-flight runs first), or "Re-run failed jobs" on the newest run.

**When `:latest` moves.** On a stable tag, `:latest` and `:X.Y` move as each image leg tags its image (`docker-publish`, `docker-publish-postgres`, each `docker-publish-chisel` leg: the push is by digest, and `scripts/ci/image-publish.sh tag` moves the tags only after that digest is verified, signed and attested), DURING the run and BEFORE the `release` job creates the GitHub Release, which needs every one of those legs to succeed. So for the minutes between a leg's tagging and the release (and indefinitely when a later leg or the `release` job fails), `:latest` names a version that has no GitHub Release, and may name this version for some images and the previous one for others. The agent bundle pushes only `:X.Y.Z`, after the release. The publishing order is deliberate and unchanged; `docs/user-manual/release-verification.md` tells users not to trust a tag without a Release. Moving them back by hand is not a release procedure (Release tag policy, below): while a stable release is unfinished, `:latest` and `:X.Y` keep naming its signed, unreleased digests until it is finished ("Re-run failed jobs" on the newest run), fixed and re-tagged, or superseded by the next patch release, each of which moves them only in "Tag the release".

**Recovery: "Re-run failed jobs" on the NEWEST run for the tag. A fresh run is the fallback, not the default.** Re-running the newest run keeps every image digest and artifact its succeeded jobs already produced; only the failed jobs and those skipped behind them execute again, and every publishing step re-checks that the tag still points at this run's commit before it pushes (#5282), so a run whose tag has moved away refuses. That re-check cannot see a tag moved away and back again while two runs are in flight (#5478): **cancel every in-flight release run for a tag before you re-tag it.** "Newest run" means the newest run that got past `release-guard`; a run the guard refused has nothing to re-run. Never re-run an OLDER run (#5242): a newer run may have pushed different images, and a re-run does not repeat `release-guard`. Two cases:
- **The `release` job did not run or failed** (a build, publish or Create Release failure): no release exists. "Re-run failed jobs" finishes the run in minutes. A fresh run also passes the guard but rebuilds and re-pushes everything with new digests (40+ min) — use it only when the newest run cannot be re-run. (Exception: when `Create Release`'s artifact gate rejects a stale package a self-hosted build job uploaded, re-running only the `release` job downloads the same file again; clear the runner workspace and start a fresh run — `docs/ci-architecture.md`, Release artifact gate.)
- **The `release` job published the release and the job then failed or was cancelled before it finished**: a re-run of `release` refuses because the release now exists, so `docker-publish-agent-bundle` cannot run behind it (#5479). The release itself is complete; verify its assets against its `SHA256SUMS`. No release procedure publishes the agent bundle for it (a hand push would bypass the gate and the journal: Release tag policy, Limit 1): say in the announcement that this version ships without the bundle image, and cut a patch release to ship one (Release tag policy).
- **The `release` job succeeded and `docker-publish-agent-bundle` failed**: a release exists, so the guard refuses a fresh run by design. "Re-run failed jobs" on that run is the only correct recovery; it is safe because the bundle builds from the published release's own assets.

**Once the GitHub Release exists, do not re-run a build or publish job** (a forbidden re-run, Release tag policy). When a job is re-run, GitHub also re-runs every job that depends on it, but not the jobs it depends on ("Re-running workflows and jobs" in GitHub's Actions docs), so `release-guard` is not repeated and each re-run publish job passes its tag re-check:

| Re-run, after the GitHub Release exists | What runs | |
|---|---|---|
| "Re-run all jobs", or `release-guard` alone | `release-guard`, which refuses the existing release; every other job is skipped | safe, does nothing |
| `build-linux`, `build-gateway`, `build-windows` or `build-macos` | that build, then every publish job (all of them need all four builds): all six images move `:X.Y.Z` (and `:X.Y`, `:latest`) to new digests the release's SBOMs, gate reports and journals do not name; `release` fails `already PUBLISHED` | **forbidden** |
| `docker-publish`, `docker-publish-postgres` or `docker-publish-chisel` | that job's images move the same way; `release` fails `already PUBLISHED` | **forbidden** |
| `release` | it refuses at `already PUBLISHED` before uploading; the bundle and attach jobs are skipped (#5479) | safe, does nothing |
| `docker-publish-agent-bundle` that FAILED ("Re-run failed jobs") | it and the attach job; it builds from the release's own assets and its attempt joins the attached record | safe: the recovery |
| `docker-publish-agent-bundle` that SUCCEEDED | moves the announced `yuzu-agent-bundle-chisel:X.Y.Z` to a new digest | **forbidden** |
| `attach-bundle-gate-report` | adds missing assets, replaces only an incomplete upload | safe |

"Re-run failed jobs" is safe only when every failed job is `release`, `docker-publish-agent-bundle` or `attach-bundle-gate-report`: look at the run's failed jobs before clicking. This also rules out re-running a build job to regenerate a missing or expired build artifact (Phase 4).

**Release tag policy (frozen 2026-11-18).**

**Controls (enforced by `release.yml`).** Within the release workflow, a release tag (`:X.Y.Z`, `:X.Y`, `:latest` of the six release images; the agent bundle's `:X.Y.Z`) is written only by the "Tag the release" step (`scripts/ci/image-publish.sh tag`), after the gate, verify, sign and attest steps and behind the publish journal. `release-guard` refuses a run for a tag that has a published release. The workflow deletes no image.

**Practices (not enforced).** A wrong or superseded published release is fixed by a new patch release. Deleting a published GitHub release, redoing a release under its tag, moving a release tag outside the workflow, and deleting a GHCR package version are not release procedures: each is an owner-decided incident, recorded in a tracking issue opened for it and announced. First step for a suspected-compromised digest: open that issue and announce the digest; delete or move nothing until the owner decides.

**Limits (disclosed).** (1) `scripts/docker-release.sh` and `scripts/build-agent-bundle.sh --push` predate the gate and can push release tags with maintainer credentials; they bypass the gate and the journal and are not used to publish a release. (2) Once a published release is deleted, `release-guard` passes a fresh run of its tag; that run destroys the release's signed `SHA256SUMS`, moves every tag including `:latest`, and leaves the earlier digests untagged with no signed record. (3) No signed record of "digests ever announced" exists. A journal records what each attempt published; it does not show which digest was first announced, nor whether a re-run was sanctioned, and releases up to v0.15.0 have no journals. (4) Nothing technical stops a package admin deleting a version or moving a tag.

What a patch release does and does not change:
- No later release moves the superseded release's own `:X.Y.Z`. After a forbidden re-run it names the re-run's digest, and for the bundle the re-attached records name it too (Limit 3).
- `release.yml` moves `:latest` on every stable tag, including a patch to an older `X.Y` line, so such a patch also moves `:latest` to that line until the next stable release on the newest line. On a pre-release the equivalent is the next `-rcN`, which moves only its own tag.
- `release-guard` passes a new version: it refuses only a ref that is not a `vX.Y.Z[-{alpha,beta,rc}N]` tag (1 to 4 digits per number) or a tag that already has a published release, and nothing checks that a version is higher than the last. The usual preflight applies (Phase 1; the compose defaults at the new version, `scripts/check-compose-versions.sh`).

A release existing means the `release` job of some run succeeded — not that the whole run did. Check `docker-publish-agent-bundle` and `attach-bundle-gate-report` on that run before calling the release done.

A re-run never replaces the image gate's evidence (WP15/S9): each attempt's gate reports are named `trivy-<image>.attempt-<N>.*` (artifact `<image>-image-vuln-gate-attempt-<N>`, for example `yuzu-server-image-vuln-gate-attempt-1`), so a refused attempt's report stays beside the passing one, the `release` job ships every attempt's reports inside `SHA256SUMS`, and `check-release-artifacts.sh` requires, for each image, an attempt whose journal ends `tagged` (the highest such attempt is the published image) and no higher attempt ending `tagging`; a higher attempt the gate refused (no journal) is kept as evidence and does not block it. A cancelled or timed-out gate writes `gate: FAIL: cancelled (SIGTERM|SIGINT) ...` and its report is uploaded too. "Re-run all jobs" on a released tag fails at `release-guard` (#5282).

```bash
TAG=v0.14.0
# The newest run for the tag, and its commit must be the tag's current target:
gh run list --workflow release.yml --repo DevNullLtd/Yuzu --branch "$TAG" --limit 1 --json databaseId,headSha,status,conclusion
git ls-remote origin "refs/tags/$TAG^{}" "refs/tags/$TAG"
gh run rerun <databaseId> --failed --repo DevNullLtd/Yuzu
```

If the newest run's commit is not the tag's current target, the tag moved: the run for the new commit is the one to finish. A fresh run of the tag (below) is for when no run can be re-run:

```bash
TAG=v0.14.0
# 1. No release run for the tag is queued, waiting or running (this must print nothing):
gh run list --workflow release.yml --repo DevNullLtd/Yuzu --branch "$TAG" --json databaseId,status --jq '.[] | select(.status != "completed")'
# 2. No release exists (read the output: it must say "release not found"):
gh release view "$TAG" --repo DevNullLtd/Yuzu
# 3. Start the fresh run, then capture ITS id (gh workflow run prints none; wait until a newer run appears):
PREV=$(gh run list --workflow release.yml --repo DevNullLtd/Yuzu --branch "$TAG" --limit 1 --json databaseId -q '.[0].databaseId')
gh workflow run release.yml --repo DevNullLtd/Yuzu --ref "$TAG"
for i in $(seq 1 24); do sleep 5; RUN_ID=$(gh run list --workflow release.yml --repo DevNullLtd/Yuzu --branch "$TAG" --limit 1 --json databaseId -q '.[0].databaseId'); [ -n "$RUN_ID" ] && [ "$RUN_ID" != "$PREV" ] && break; RUN_ID=; done
echo "fresh run: ${RUN_ID:-not seen after 2 min, check the Actions page}"
```

Start it only when step 1 prints nothing (a queued run counts as running: wait for it) and step 2 says `release not found` (any other error: stop and investigate). **The workflow enforces step 2 itself** (#5282): its first job, `release-guard`, refuses a ref that is not a `vX.Y.Z[-{alpha,beta,rc}N]` tag, then reads `GET /releases/tags/<tag>` and fails the run before any build or push when it answers HTTP 200; it proceeds only on HTTP 404, and any other answer fails the run too. Every image-publishing job and the release job need it. Step 2 is still worth running, because the guard refuses a mistaken run but cannot tell you which run to start. Limits: the guard's read-only token cannot see a **draft** release — one made by hand, or one `gh release create` leaves behind when interrupted while uploading assets (it creates a draft, uploads, then publishes). The `release` job's own check sees drafts and fails. Deleting an unpublished draft is not destructive (nothing was published): delete it, then re-run failed jobs on the newest run. A fresh run is for the newest release only: on an older stable tag, a fresh run would move `:latest` and `:X.Y` back to the older images. If the failure is deterministic, fix it and re-tag instead; a fresh run of the same tag fails the same way. If a stable release cannot be fixed promptly, `:latest` and `:X.Y` keep naming its unreleased digests meanwhile; moving them back by hand is not a release procedure (Release tag policy above). **There is no override input, by design.** To change what a published release ships, cut a new version. Deleting a published release, or redoing one under its tag, is not a recovery: see Release tag policy (owner incident; Limit 2). A fresh run rebuilds everything, about 40+ minutes.

The chisel timeout (120 min) is set in the workflow at the tagged commit, so a fresh run of the same tag cannot change it. Raising it means committing the bump and re-tagging.

Watch with `gh run watch` (interactive), or poll-until-done from the LLM:

```bash
gh run watch "$RUN_ID" --exit-status   # blocks until terminal state, exit 0 if all green
```

If `gh run watch` is unsuitable (long-running terminal session), poll every 60s:

```bash
while :; do
  STATUS=$(gh run view "$RUN_ID" --json status,conclusion --jq '.status + "/" + (.conclusion // "")')
  echo "$(date -u +%H:%M:%S) $STATUS"
  case "$STATUS" in
    completed/success) echo "RELEASE WORKFLOW PASSED"; break ;;
    completed/*)       echo "RELEASE WORKFLOW FAILED: $STATUS"; break ;;
  esac
  sleep 60
done
```

Phase 2 produces: workflow URL, terminal status, per-job timing, and (on failure) the failing job ID for Phase 3.

## Phase 3 — Troubleshoot known failure modes

Look up the failing job and pull the last 50 lines of its log:

```bash
gh run view "$RUN_ID" --log-failed | tail -100
```

Match the failure against this table. **All entries have happened in real Yuzu releases** — the `v0.10.0 manual release` documented in the v0.10.0 release notes is the canonical example.

| Symptom | Cause | Fix |
|---|---|---|
| `Validate docker-compose image versions` fails on the `Create Release` job | A tracked compose file's `${YUZU_VERSION:-...}` default doesn't equal the **base** version (rc/beta suffix stripped). E.g. for `v0.12.0-rc0` the default must be `0.12.0`, not `0.12.0-rc0`. | Bump the default in the offending file to BASE version, commit, retag with `git tag -fa vX.Y.Z` + `git push --force origin vX.Y.Z`. **Confirm with the operator before force-pushing the tag** — auto mode treats tag rewrites as destructive even mid-recovery. **All matrix jobs re-run** — costs ~30–60 min wall clock. Better: catch in preflight (it does the right thing because it strips the suffix internally). |
| `Artifact download failed after 5 retries` on the `release` job, complaining about a `*.dockerbuild` file | Docker buildx provenance/attestation artifacts have unstable names that download-artifact occasionally cannot resolve | Already filtered in workflow with `pattern: 'yuzu-*'` — if regression, re-add filter. v0.10.0 hit this and was assembled manually. |
| `ccache stats: 0 hits` on a re-run that should have been cached | ccache key changed (any C++ file edit invalidates) | Normal; subsequent build hits. If repeated 0% on identical input, check `~/.cache/ccache` writability on the runner. |
| `signtool sign /f` fails on Windows | `WINDOWS_SIGNING_CERT` secret missing or expired | The signing step is conditional on `env.HAS_SIGNING_CERT == 'true'` — release proceeds unsigned if absent. Confirm with operator whether unsigned is acceptable for this release; if not, refresh secret and retag. |
| `xcrun notarytool submit` times out (15 min) on macOS | Apple notary backlog | "Re-run failed jobs" on the newest run; see Recovery. If it keeps failing, fix the cause and re-tag: a notarize failure fails `build-macos`, which skips the release, so there is no release to upload a hand-notarized `.pkg` to, and it would sit outside the signed `SHA256SUMS`. |
| `Build and push` fails with `unauthorized` on GHCR | `GITHUB_TOKEN` `packages: write` scope missing | Verify `permissions: packages: write` at workflow root. |
| `vcpkg install` fails with version baseline mismatch | `VCPKG_COMMIT` env var in workflow drift from `vcpkg.json` baseline | Sync both — workflow env + manifest baseline must match. Tracked by `.github/workflows/vcpkg-baseline-update.yml`. |
| `Run EUnit tests` fails with a nonzero exit or cancellation, even when `Failed: 0` appears | Incomplete execution (including meck fixture cancellation, #336/#337/#1005) | `scripts/gateway_test_summary.py strict` preserves the native nonzero exit and rejects cancellation even with exit 0. Read `gateway/eunit.log` and the diagnostic excerpt; repair the fixture/process leak before release. The covered release suite runs once, without automatic retry; cancellation intentionally blocks the tag build. |
| `Run EUnit tests` reports `Test run printed no recognisable test summary` | rebar3 failed before any test ran (compile/dependency error), or its summary wording changed | Read the eunit.log head for the rebar3 error; if the wording changed, update `scripts/gateway_test_summary.py` and its parser tests. Strict mode emits plain diagnostics, not the old GitHub annotation strings. |
| `Run EUnit tests` reports `Test run executed ZERO tests` | Nothing was discovered, or every set was skipped/cancelled (`Failed: 0.  Skipped: 0.  Passed: 0.`) | Intentional failure: find the crashing setup or moved test directory in `gateway/eunit.log`. The strict parser requires at least one executed test and no failure or cancellation. |
| `Linking target agents/core/yuzu-agent` (or `yuzu_agent_core.dll`) fails with LNK2038 on Windows | vcpkg cache poisoned with mixed runtime-libraries (the option-D issue from #375 / PR #373) | Bust the Windows vcpkg cache, then "Re-run failed jobs" on the newest run; see Recovery. Long-form: see `.codex/agents/build-ci.md` "Windows MSVC static-link history and #375". |
| `Verify the agent runs from the packaged archive` fails on `build-windows` | The Windows agent archive lacks a DLL the agent or `yuzu_agent_core.dll` imports (exit `-1073741515`, STATUS_DLL_NOT_FOUND), lacks plugin DLLs, contains `yuzu-server.exe`, contains a server-port DLL (log line `server-only DLLs in the agent archive: <names>`: a manifest, install-profile or port change that pulled a server dependency in), or the agent hung (the step kills it after 60 s) | Read the step log. A server-port DLL refusal is deterministic: the release job installs from a clean checkout, so re-running the same tag refuses again. Fix the cause (the manifest, the install line or a port at the pinned baseline) and re-tag. "Re-run failed jobs" on the newest run is only for a transient failure such as a runner or network fault (a hang), as in Recovery above. A real packaging defect needs a commit, then re-tag as Recovery describes. No GitHub Release exists yet, and all three image-publish jobs wait for `build-windows`, so no versioned image was pushed |
| `Notarize binaries` fails with "notarization status is 'Invalid'" on `build-macos` | Apple rejected the agent binary or a dylib (only once `MACOS_SIGNING_CERT` is set; macOS signing is dormant until then) | `xcrun notarytool log <id>` with the id printed in the step log (the step prints the notarization result). Fix the signing with a commit, then re-tag as Recovery describes. No GitHub Release exists yet, and all three image-publish jobs wait for `build-macos`, so no versioned image was pushed |
| `docker-publish-agent-bundle` fails in `scripts/build-agent-bundle.sh` with `cosign verify-blob FAILED`, `no SHA256SUMS.sigstore`, `legacy SHA256SUMS.bundle`, `hash MISMATCH`, `malformed hash`, `no line for <file>`, `ambiguous`, `no <.deb/.rpm/.pkg/Windows> installer asset`, `no SHA256SUMS on`, `no Windows archive on` / `no macOS archive on`, `cannot determine the GitHub repo slug`, `cannot derive the signer repo`, `download missing or empty`, `need cosign`, `malformed --version`, `malformed --signer-repo`, `cannot create a staging dir` or `cannot read/hash/copy` (#7529) | The script authenticates the release's `SHA256SUMS` with cosign (exact identity `https://github.com/<signer>/.github/workflows/release.yml@refs/tags/<tag>`, issuer `https://token.actions.githubusercontent.com`) before reading it, then matches each download to ITS OWN `SHA256SUMS` line. In CI the signer is `--signer-repo ${{ github.repository }}`; by hand it comes from a fixed table (<= 0.13.x `Tr3kkR/Yuzu`, later `DevNullLtd/Yuzu`). The ONLY legitimate signers are `Tr3kkR/Yuzu` (<= 0.13.x) and `DevNullLtd/Yuzu` (after): a `cosign verify-blob FAILED` on the default path means a tampered release or the wrong download source, NOT a signer to override. Rule out first: cosign older than v2.6.2, a wrong clock, or a Sigstore/TUF network failure in cosign's output. There is no offline mode: check proxy/DNS and re-run; if it persists for about an hour, or cosign reports an expired or unverifiable trusted root, treat it as permanent and update cosign. `SHA256SUMS.sigstore` missing means a release before v0.11.0-rc1 (v0.8.0-rc0 to v0.10.0 carry neither signature file) or one assembled by hand (see Known limitations); `legacy SHA256SUMS.bundle` means a v0.7.x release (verify by hand with the exact tag-bound `--certificate-identity`); `hash MISMATCH`/`no line for` means a corrupt or tampered asset; an installer error means the release has none (or several) for the requested version (the script picks each installer by exact version-derived name, so a leftover earlier-rc installer on the same release is ignored, never bundled) | Reproduce without docker with `bash scripts/build-agent-bundle.sh --verify-only --version X.Y.Z` (needs `gh`, cosign v2.6.2 or later, `sha256sum` or `shasum`, and a git checkout; `--signer-repo owner/repo` overrides the table and prints a `[!!]` warning when it differs; **never set it to the subject cosign reports**). **Never skip the check or edit the script to get past it** and there is no skip flag by design; publishing a bundle outside `release.yml` for a release whose manifest does not verify bypasses the gate and the journal (Release tag policy, Limit 1); it is an owner-decided incident, recorded in a tracking issue opened for it and announced. A transient download failure: "Re-run failed jobs" on the newest run. |
| The `release` job's `Sign SHA256SUMS (keyless)` step fails at its own `cosign verify-blob` (#7529) | The just-made signature did not verify with the exact tag-bound `release.yml` identity. State left behind: the images are already pushed and signed (including `:latest` on a stable tag), the tag exists, NO GitHub Release was created and the agent-bundle job is skipped | "Re-run failed jobs" on the newest run (a deterministic SAN mismatch will fail again: find the cause, e.g. a changed workflow path or a moved tag). **Never widen the check to a `--certificate-identity-regexp`**; confirm with the operator before publishing a release whose manifest does not verify. |
| `Scan image for fixable CRITICAL vulnerabilities (pre-push gate)` fails on `docker-publish`, `docker-publish-postgres` or a `docker-publish-chisel` leg (WP15/S9) | The image vulnerability gate (`scripts/ci/image-vuln-gate.sh`) refused the image BEFORE its push: a fixable CRITICAL not accepted in `.trivyignore.yaml` (`has a fixable CRITICAL vulnerability`), a Trivy DB older than 72 h (`more than 72`), an image whose OS packages Trivy cannot see and that is not listed, in force, in `scripts/ci/image-vuln-gate-not-covered.txt` (`OS packages not scanned`; a listing whose `approval_ref` is `pending`, or that expired, is not in force), an OS release with no advisory data (`end of service life`, `no advisory data`), an ignore file the gate refuses (`not in the shape the gate accepts`), an acceptance whose `approval_ref` is still `pending` (`NOT IN FORCE`: the release gate runs with `--release`), an OS version that is a pre-release (`no advisory data for a pre-release`: `_alpha`, `_rc`, `~rc`, `-rc`, ...), a scan, DB-digest or download error (each call has its own deadline), or the gate's overall budget running out (`ran out of its 1500s budget`). State: that leg pushed nothing (no publish journal); `fail-fast: false` sibling legs may already have moved `:X.Y.Z` (and `:X.Y`/`:latest` on a stable tag) to their verified, signed digests; NO GitHub Release; the agent bundle is skipped | Read the step log, then follow `docs/ci-architecture.md` "Release image vulnerability gate", "When it fails": a distro fix or a stale DB is "Re-run failed jobs" on the newest run (each attempt takes current packages and a fresh DB); a base-image fix, a `.trivyignore.yaml` acceptance (a concrete path or full versioned purl, statement, expiry at most 92 days, `approved_by`, and `approved_on` + `approval_ref`, a recorded reference to the approving pull request that the gate checks for format only) or a not-covered listing is a commit, then re-tag as Recovery describes. A `pending` approval becomes in force only by recording the approval in a commit ("Recording an approval" in that doc); the control is the review of that commit, not the gate. The refused attempt's report stays in the run (and in the release) beside the re-run's. **Never edit the gate or the not-covered list just to get past a finding**; an acceptance needs the evidence and an approver. If a stable release cannot be finished promptly, `:latest` and `:X.Y` stay on its unreleased digests until it is finished or re-tagged; if it cannot be, cut the next patch release (Release tag policy). Moving a tag by hand is not a release procedure. |
| `Scan image for fixable CRITICAL vulnerabilities (pre-push gate)` fails on `docker-publish-agent-bundle` (WP15/S9) | Same gate, but this job runs AFTER the `release` job published the GitHub Release. State: the release and its six other images are complete and signed; THIS attempt pushed nothing (it has no journal), but an EARLIER attempt of the bundle job may already have moved `yuzu-agent-bundle-chisel:X.Y.Z` (its journal ends `tagging` or `tagged`) | **Never re-tag**: the tag is a published release (#5282) and `release-guard` refuses a fresh run. A distro fix, a stale DB, the gate's budget running out or a cancel: "Re-run failed jobs" on that run (the only recovery for this job, see Recovery). Anything that needs a commit (an acceptance, a new base digest) cannot reach this release, because the gate runs from the tag's checkout. Then read every earlier attempt's journal (`grep -H . publish-yuzu-agent-bundle-chisel.attempt-*.txt` in the bundle job's artifacts or on the release): if an earlier attempt ends `publish: tagged` and none above it ends `tagging`, the attach job records that attempt as the published bundle image and the announcement names its digest; if one ends `tagging`, or the run is red around the bundle, follow the terminal row below; only if no attempt has a journal does this version ship without the bundle image (say so in the announcement), then land the fix and cut the next version. No release procedure publishes the bundle image any other way (Release tag policy, Limit 1). |
| `Attach agent-bundle gate report to the release` fails (WP15/S9) | The bundle's gate report could not be signed or attached (a Sigstore or GitHub API error, an upload interrupted part-way), or it was refused: a completed asset of the same name is already on the release with different content (`refusing to replace it`), a `.sigstore` on the release `does not verify`, an attempt's publish journal is not a legal prefix (`not a legal publish journal`, `has a publish journal but its gate did not pass`), or a higher attempt stopped while moving the bundle's tag (`stopped while moving the bundle's tag`: the files are attached, then the job fails). It also fails when no attempt uploaded a gate report (`no gate report`). State: the release is complete; the bundle image is published by the highest attempt whose journal (`publish-yuzu-agent-bundle-chisel.attempt-N.txt`) ends `publish: tagged`, if any (the bundle job may itself have failed, e.g. on a refused gate); the bundle's reports are only in the 90-day workflow artifacts until this job attaches them (on `stopped while moving the bundle's tag` it attaches them first and then fails; on any other failure they are not attached); the Release run is red, so **Pre-release QA does not start** (it runs only on a successful Release run) | A transient error or an interrupted upload: "Re-run failed jobs" on that run. It re-runs this job (and any other job that failed, such as a refused bundle job, which then stays red until its own cause is fixed); the attach job deletes and re-uploads an asset GitHub reports as not `uploaded` (an interrupted upload, never served) or whose bytes do not match GitHub's size or digest for it, keeps a completed identical one, and adds the rest; it never replaces a completed asset. It downloads every attempt's bundle gate artifact, so each run adds whatever earlier attempts' files are still missing. A higher attempt stopped while tagging: "Re-run failed jobs" so the bundle job completes `tagged`, then this job passes. If the bundle job's re-run cannot pass (its gate refuses for a reason that needs a commit), stop re-running: this is terminal for the release, and the next row says what to record. When every re-run job succeeds the run concludes green. If QA has still not started, dispatch `pre-release.yml` with the tag (`gh workflow run pre-release.yml --repo DevNullLtd/Yuzu -f tag=vX.Y.Z`). A refusal fails the same way on every re-run: stop and investigate with the operator; never delete a completed release asset to get past it. Do not attach the report by hand: a hand upload has no signed checksum list. |
| `Hold the buildx cache lock` fails (`could not take the lock`), or a publish build fails importing its cache with `NotFound content` (WP15/S9) | The weekly `cache-prune.yml` held the cache directory's lock for longer than the 30-minute wait, or a cache directory is corrupted (an index naming a missing blob, e.g. after a prune by hand or a killed export). State: that leg pushed nothing; NO GitHub Release | Lock: "Re-run failed jobs" on the newest run once the prune job has finished. Corrupted cache: on the runner that ran the leg, delete `/srv/ci/work-N/_tool/yuzu-docker-buildcache/<image>` (`<image>` is `server`, `gateway`, `postgres` or `<image>-chisel`; leave `<image>.lock`), then "Re-run failed jobs": the build runs cold. The weekly prune also removes a broken directory itself. See `docs/ci-architecture.md` "Cache pruning + weekly maintenance". |
| `Verify the pushed image is the scanned one` fails (`is NOT the image that was scanned`, `could not read the pushed image's layers`, or for the bundle `names ..., not ...`) (WP15/S9) | The pushed digest's layers differ from the scanned build's (the push did not reuse the scanned layers), the registry read failed, or the bundle's candidate tag no longer names the pushed digest. State: the digest is in GHCR UNTAGGED (the buildx jobs push by digest; the bundle, as `:candidate-<run id>-<attempt>`), unsigned and unattested; NO release tag moved; the publish journal ends `publish: push-started`; the release job does not run (the bundle job: its release already exists) | "Re-run failed jobs" on the newest run (a registry blip clears; a real mismatch rebuilds, re-scans, pushes a new digest and tags it once it is verified, signed and attested). Nothing public changed, so nothing needs moving back. The untagged digest (the bundle's, under its candidate tag) stays, by decision: it is not a release tag, nothing pulls it by name, and it was gate-scanned before its push. **Do not delete it.** The release workflow deletes no image; deleting a GHCR package version is an owner-decided incident, recorded in a tracking issue opened for it and announced (Release tag policy). |
| `Generate image SBOM`, `Attest image provenance`, `Sign image (keyless)` or `Record signed and attested` fails on a publish job, or for the agent bundle `Generate bundle SBOM` or `Attest bundle provenance` (WP15/S9) | A Syft, attestation or Sigstore error, or (`Record signed and attested`) the signature on the verified digest does not verify for this workflow's identity (`has no signature from ... that verifies`). State: the publish journal ends `publish: verified` (the digest has the scanned layers; some SBOM, attestation or signature referrers may already be attached to it); the digest is in GHCR untagged (the bundle's, under its candidate tag); NO release tag moved; the release job does not run (the bundle job: its release already exists) | "Re-run failed jobs" on the newest run: the re-run pushes, verifies, signs and tags a new digest. Nothing public changed. The leftover digest stays (the row above). For the agent bundle a refused re-run follows the `docker-publish-agent-bundle` gate row. |
| `Upload image SBOM artifacts` (the bundle's: `Upload bundle SBOM artifacts`) or `Tag the release` fails on a publish job (WP15/S9) | `Upload image SBOM artifacts`: the artifact service failed after the digest was signed. `Tag the release`: a tag could not be moved, or does not resolve to the digest afterwards (a registry error, another writer, a cancel). State: the journal (`publish-<image>.attempt-N.txt` in the run's gate artifact) ends `signed-attested` (no tag moved) or `tagging` (SOME tags may name the new digest, the rest still the previous release's); the release job does not run | "Re-run failed jobs" on the newest run: the re-run pushes, verifies, signs and tags a new digest, moving every tag again. While a journal ends `tagging` and no later attempt has completed, `:X.Y.Z`, `:X.Y` and `:latest` may disagree; moving them by hand is not a release procedure: if the run cannot be finished, fix the cause and re-tag, or cut the next patch release (Release tag policy). `scripts/check-release-artifacts.sh` refuses a release whose published (highest `tagged`) attempt has a higher attempt ending `tagging`. For the agent bundle the release already exists: `Upload bundle SBOM artifacts` runs before signing, so its failure leaves the journal at `verified`, and the recovery is "Re-run failed jobs" on the bundle's run (the re-run table above). |
| The agent bundle's record and `:X.Y.Z` cannot be reconciled by a re-run: `attach-bundle-gate-report` keeps failing with `stopped while moving the bundle's tag` while the bundle job's re-run is refused for a reason that needs a commit, or the bundle job is red and the attach job names an older attempt (or `published=none`) (WP15/S9, G8P6-release-deploy-2, G8P6-architect-4) | An attempt moved (or began to move) `:X.Y.Z` and no later attempt can complete `tagged`; or an attempt that moved it lost its evidence (its report upload and the retry both failed), so the attach job cannot see it. State: the release and its six other images are complete; `:X.Y.Z` names a digest that the bundle's records may not show as published; the Release run stays red | **Terminal for this release: do not loop on re-runs.** Resolve the tag and compare it with every attempt's journal on the release (or in the 90-day artifacts): `docker buildx imagetools inspect ghcr.io/devnullltd/yuzu-agent-bundle-chisel:X.Y.Z --format '{{.Manifest.Digest}}'`, then `grep -H . publish-yuzu-agent-bundle-chisel.attempt-*.txt`. If the digest is on an attempt's `tagging` or `tagged` line, it was verified and signed before the tag moved: confirm with `cosign verify` for the release's tag, and announce that digest as the bundle image of this version (the record shows its tag move as interrupted or its evidence as missing; say which). If it is on no journal's line, look for it in the bundle job logs of every attempt (`gh run view <run id> --log --job <job id>`; `image-publish.sh` prints each line it records, e.g. `publish: tagged ...`): an attempt whose report never uploaded shows its tag move only there. Found there and `cosign verify` passes: announce it as above, saying its record is only the job log. Found nowhere, or the tag does not resolve: say the version ships without a verified bundle image and investigate with the operator before anything else. Dispatch `pre-release.yml` by hand once that is recorded (`gh workflow run pre-release.yml --repo DevNullLtd/Yuzu -f tag=vX.Y.Z`). |

For any failure not in the table: pull `gh run view "$RUN_ID" --log-failed` in full, summarize the error, and ask the operator how to proceed ("Re-run failed jobs" on the newest run; see Recovery — or a fix and re-tag, or abort).

## Phase 4 — Post-release verification (~2 min)

The workflow's `release` job creates the GitHub Release and uploads assets. Verify it actually did so:

```bash
gh release view "vX.Y.Z" --json assets,isDraft,isPrerelease,publishedAt --jq '{published: .publishedAt, draft: .isDraft, pre: .isPrerelease, asset_count: (.assets | length), assets: [.assets[].name]}'
```

Required assets (the `--verify` mode of this skill checks each):

```
yuzu-linux-x64.tar.gz
yuzu-gateway-linux-x64.tar.gz
yuzu-agent-windows-x64.zip
YuzuAgentSetup-X.Y.Z.exe
yuzu-agent-macos-arm64.tar.gz
YuzuAgent-X.Y.Z-macos-arm64.pkg
yuzu-server_X.Y.Z_amd64.deb
yuzu-server-X.Y.Z-1.x86_64.rpm
yuzu-gateway_X.Y.Z_amd64.deb
yuzu-gateway-X.Y.Z-1.x86_64.rpm
yuzu-agent_X.Y.Z_amd64.deb
yuzu-agent-X.Y.Z-1.x86_64.rpm
yuzu-compose-wizard-X.Y.Z.zip       ← Compose Wizard bundle (PR #405, fjarvis)
SHA256SUMS
SHA256SUMS.sigstore                   ← cosign keyless signature (v0.12.0+; legacy releases shipped this as SHA256SUMS.bundle)
<artifact>.intoto.jsonl × N           ← SLSA provenance, one per binary archive/installer (v0.12.0+)
```

On a pre-release tag (`vX.Y.Z-rcN`) the names differ: the `.deb` files are `…_X.Y.Z-rcN_amd64.deb` (the package's own `Version:` is `X.Y.Z~rcN`, so it sorts before the final release — the file name uses the tag's form because GitHub rewrites `~` in asset names, #5141), the RPMs are `…-X.Y.Z-0.1.rcN.x86_64.rpm`, and the Windows/macOS installers use `X.Y.Z_rcN`. Every name in `SHA256SUMS` must equal an asset name: `sha256sum -c SHA256SUMS` after downloading all assets is the check.

If any expected asset is missing, the workflow's `Create GitHub Release` step likely failed silently on a single asset (the `gh release create` call is one big command and a single missing asset returns non-zero). Re-upload the missing one:

```bash
gh release upload "vX.Y.Z" path/to/missing-asset.tar.gz
```

The artifacts are still in the workflow run — `gh run download "$RUN_ID"` retrieves them — until they expire. Do not re-run a build job to regenerate an expired one (Recovery, the re-run table: it moves every image's tags); a rebuilt file would not match the release's `SHA256SUMS` anyway. Ask the operator how to proceed (say so in the release notes, or cut the next version).

Verify the GHCR images:

```bash
# GHCR tags strip the leading `v` — git tag is vX.Y.Z, image tag is X.Y.Z.
# Post-transfer owner (repo moved to the DevNullLtd org 2026-09-28).
# Verifying a release at v0.13.0 or earlier? Those images stayed at
# ghcr.io/tr3kkr and carry a Tr3kkR/Yuzu signing identity -- use
# OWNER=tr3kkr and --repo DevNullLtd/Yuzu for those, per
# docs/user-manual/release-verification.md "Which owner applies".
OWNER=$(echo "DevNullLtd" | tr '[:upper:]' '[:lower:]')
docker pull "ghcr.io/$OWNER/yuzu-server:X.Y.Z"
docker pull "ghcr.io/$OWNER/yuzu-gateway:X.Y.Z"
docker image inspect "ghcr.io/$OWNER/yuzu-server:X.Y.Z" --format '{{.Config.Labels}}' | grep -E "version|revision"
```

Then check every release tag of the six images against the release's own signed journals (read-only; `:X.Y` and `:latest` too):

```bash
TAG=vX.Y.Z; V=${TAG#v}; D=$(mktemp -d)   # a fresh directory: gh refuses to overwrite an earlier download
gh release download "$TAG" --repo DevNullLtd/Yuzu --dir "$D" -p SHA256SUMS -p SHA256SUMS.sigstore -p 'publish-yuzu-*.attempt-*.txt'
cosign verify-blob --bundle "$D/SHA256SUMS.sigstore" \
  --certificate-identity "https://github.com/DevNullLtd/Yuzu/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$D/SHA256SUMS"
(cd "$D" && grep -E '[ *]publish-yuzu-' SHA256SUMS | sha256sum -c -)   # every journal the signed list names is here and unchanged
for img in yuzu-server yuzu-gateway yuzu-postgres yuzu-server-chisel yuzu-gateway-chisel yuzu-agent-chisel; do
  echo "== $img"
  grep -oE "publish-$img\.attempt-[0-9]+\.txt" "$D/SHA256SUMS" | sort -uV | while read -r f; do echo "$f: $(tail -n 1 "$D/$f")"; done
  for t in "$V" "${V%.*}" latest; do
    echo ":$t $(docker buildx imagetools inspect "ghcr.io/$OWNER/$img:$t" --format '{{.Manifest.Digest}}')"
  done
done
```

`Verified OK` and every `OK` must print. For each image, the highest attempt whose last line is `publish: tagged ...` names the digest that `:X.Y.Z` prints; on a stable release `:X.Y` and `:latest` print that digest too (a stable patch to an older line also moves `:latest`: Release tag policy). On a pre-release, `:X.Y` and `:latest` are the last stable release's and must not print this release's digest. The loop reads only journals the signed list names. Any other result: stop and move nothing (Release tag policy): it is an owner-decided incident, recorded in a tracking issue opened for it and announced. The agent bundle is checked from its own attached records (`docs/user-manual/release-verification.md`, the bundle commands).

Verify the cosign signature + GitHub attestation provenance. **Before running either command, gate on the client being installed** — first-time runs on a fresh dev box will hit one or both missing, and burning 30 min to discover "oh, I need cosign" post-release is exactly the gap v0.11.0-rc2 surfaced:

```bash
# Preflight: require cosign + gh 2.102.0+ for the pinned attestation verify
# (older gh matches --signer-workflow by prefix and --source-ref case-insensitively).
if ! command -v cosign >/dev/null 2>&1; then
  echo "WARN: cosign not installed — Sigstore signature round-trip skipped"
  echo "     install: curl -sSL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o ~/.local/bin/cosign && chmod +x ~/.local/bin/cosign"
fi
# Same version test as release-verification.md's script and build-agent-bundle.sh:
# plain X.Y.Z at or above 2.102.0, anything else (missing, a dev build) fails it.
GH_VERSION=$(gh --version 2>/dev/null | awk 'NR==1 {print $3}') || GH_VERSION=""
GH_PINNED_OK=0
if [[ "$GH_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
   && [[ "$(printf '%s\n' 2.102.0 "$GH_VERSION" | sort -V | head -1)" == 2.102.0 ]]; then
  GH_PINNED_OK=1
else
  echo "WARN: gh ${GH_VERSION:-<not found>} is missing, not a release version, or older than 2.102.0:"
  echo "     it cannot enforce --signer-workflow/--source-ref as written, so the attestation check below is SKIPPED"
  echo "     upgrade: curl -sSL https://github.com/cli/cli/releases/latest/download/gh_\$(gh api repos/cli/cli/releases/latest --jq .tag_name | sed s/v//)_linux_amd64.tar.gz -o /tmp/gh.tgz && tar xzf /tmp/gh.tgz -C /tmp && install -m755 /tmp/gh_*_linux_amd64/bin/gh ~/.local/bin/gh"
fi

gh release download "vX.Y.Z" --pattern 'SHA256SUMS*'
sha256sum -c SHA256SUMS

# cosign: verify the keyless signature on SHA256SUMS + both images, with the EXACT
# tag-bound identity (never a wildcard). Signer = the repo that ran release.yml.
# Tr3kkR/Yuzu only for releases <= 0.13.x
SIGNER_REPO=DevNullLtd/Yuzu
if command -v cosign >/dev/null 2>&1; then
  cosign verify-blob \
    --bundle SHA256SUMS.sigstore \
    --certificate-identity "https://github.com/$SIGNER_REPO/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    SHA256SUMS
  for img in yuzu-server yuzu-gateway; do
    cosign verify \
      --certificate-identity "https://github.com/$SIGNER_REPO/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      "ghcr.io/$OWNER/$img:X.Y.Z"
  done
fi

# gh attestation: verifies SLSA build provenance, pinned to release.yml at the tag
# (--repo alone accepts an attestation from any workflow in the repository)
# Best-effort, like build-agent-bundle.sh: on an unsuitable gh it says so, and
# provenance is then NOT verified (the customer page's script refuses instead).
if [[ "$GH_PINNED_OK" -eq 1 ]]; then
  gh attestation verify yuzu-linux-x64.tar.gz --repo "$SIGNER_REPO" \
    --signer-workflow "$SIGNER_REPO/.github/workflows/release.yml" --source-ref refs/tags/vX.Y.Z
  gh attestation verify "oci://ghcr.io/$OWNER/yuzu-server:X.Y.Z" --repo "$SIGNER_REPO" \
    --signer-workflow "$SIGNER_REPO/.github/workflows/release.yml" --source-ref refs/tags/vX.Y.Z
else
  echo "SKIPPED: SLSA provenance NOT verified (gh ${GH_VERSION:-<not found>} cannot enforce the pins; need 2.102.0+)"
fi
```

## Phase 5 — Compose Wizard verification

The release workflow includes a `Package Compose Wizard` step that zips `tools/compose-wizard/` into `yuzu-compose-wizard-X.Y.Z.zip` and includes it in the release assets + SHA256SUMS.

The wizard is a browser-based step-by-step generator for `docker-compose.yml` + `.env`, contributed by @fjarvis in PR #405. Zero dependencies — extract, open `index.html`, walk the wizard.

Smoke-check the bundle:

```bash
gh release download "vX.Y.Z" --pattern 'yuzu-compose-wizard-*.zip'
unzip -l "yuzu-compose-wizard-X.Y.Z.zip" | head -20
# Expect: index.html, css/style.css, js/wizard.js, js/generate.js, README.md
```

If the wizard zip is **missing**, two causes are likely:
1. The tag's commit doesn't have `tools/compose-wizard/` (wizard was on `main` only post-PR #405; if cutting from a stale branch, it won't be there). Fix: tag from a commit that includes the wizard.
2. The workflow's `Package Compose Wizard` step emitted a warning and skipped (check the run log). Same fix.

## Phase 6 — Cleanup and announce (~5 min)

After all verification passes:

1. **Bump dev branch to next dev version.** On `dev`:
   ```bash
   # Update meson.build version to X.Y.(Z+1) or (X+1).Y.0 (operator's call).
   # PLAIN version only — never a -dev/-rcN suffix. The suffix convention was
   # tried at 0.13.1-dev and rejected (operator ruling 2026-07-13): it
   # generated `int kVersionPatch = 1-dev;` via version.hpp.in and red-lined
   # the entire C++ matrix on dev + every open PR (fixed in fca69e34).
   # (No CHANGELOG step: the promote already left the ## [Unreleased] header +
   # do-not-edit note in place; new entries arrive as changelog.d/ fragments.)
   git commit -m "chore(post-release): bump dev to X.Y.Z+1"
   git push origin dev
   ```
2. **Reconcile main → dev** if the release tag was on a main commit not yet merged into dev (rare on this project — usually dev → main first).
3. **Close any release-blocker issues** in the milestone.
4. **Update the rollout doc** if relevant (`docs/dependency-rollout-*.md`, `docs/roadmap.md`).
5. **Announce.** Yuzu doesn't (currently) have an automated announcement channel. If applicable, post the release URL.

## Phase 7 — Produce the release report

End-of-skill output to the operator:

```
Release vX.Y.Z

Workflow:    https://github.com/DevNullLtd/Yuzu/actions/runs/<RUN_ID>
Release page: https://github.com/DevNullLtd/Yuzu/releases/tag/vX.Y.Z

Assets:      <N>/<expected> present
GHCR:        ghcr.io/<owner>/yuzu-server:vX.Y.Z + :yuzu-gateway:vX.Y.Z (linux/amd64)
Floating tags: :latest moved (or N/A for prerelease)
Signature:   cosign verified (or N/A if SIGNING absent)
SHA256SUMS:  verified

Compose Wizard: bundled (or absent — see Phase 5)

Next dev version: X.Y.(Z+1) (operator: bump on dev branch — plain version, no -dev suffix)
```

If anything failed, list the failures + the fix attempted + final status, and explicitly state whether the release is shippable as-is or requires a follow-up patch release.

## Resume / re-entry

Releases occasionally stall partway. The skill supports re-entry without redoing completed phases:

- `/release --resume vX.Y.Z` — assume tag exists and workflow ran (or is running). Skip preflight + tag push, jump to Phase 2 monitor with the existing run ID, then continue normally.
- `/release --watch vX.Y.Z` — only monitor (Phase 2). Useful when the operator pushed the tag manually and just wants the skill to babysit.
- `/release --verify vX.Y.Z` — only verify (Phases 4-5). Useful for an old release the operator wants to confirm.

In all resume modes, the skill discovers state via `gh release view` and `gh run list --workflow=release.yml`, so it works correctly even on a fresh shell with no in-skill memory.

## Cost / ROI

A successful release run is ~5 sec of operator work (push tag) + 30-60 min wall clock for the workflow + ~2 min of verification. The skill collapses the operator's work into one invocation and turns the 30-60 min wait into supervised waiting where every known failure mode has a documented response.

Releases that hit unfamiliar failure modes (the v0.10.0 download-artifact bug) have historically taken ~2 hours of manual artifact assembly + manual gh release create. The skill cannot prevent novel failures but documents them as they're solved so the runbook captures every known incident — see Phase 3 table.

## Known limitations

- **Self-hosted runner required for Linux + Windows + gateway.** The workflow assumes the self-hosted pools (`yuzu-bigtam-linux`, `yuzu-weetam-windows`, `yuzu-bigmags-macos`) are online; the runner-inventory-sentinel workflow gates this separately. If a runner is offline at tag-push time, the build matrix will queue indefinitely. Phase 2 monitor will surface this as `status=queued` for >5 min — escalate by waking the runner.
- **No rollback.** Once `gh release create` runs, the release is public. Untagging or moving a release tag by hand is not a release procedure (Release tag policy: an owner-decided incident); the remedy is a follow-up patch release (vX.Y.Z+1).
- **Compose Wizard requires the tag's commit to have `tools/compose-wizard/`.** PR #405 merged to `main` directly. If a future release is cut from a branch that hasn't reconciled with main, the wizard won't be in the source tree and the workflow step will skip it. Preflight does NOT currently check for this — consider adding.
- **Cosign keyless signing requires GitHub Actions OIDC.** Manual asset uploads via `gh release upload` are NOT signed. If a release was assembled manually (per Phase 3 table), `SHA256SUMS.sigstore` will be missing, `scripts/build-agent-bundle.sh` refuses such a release (it never trusts an unsigned `SHA256SUMS`), and operators must say so plainly: `sha256sum -c SHA256SUMS` alone shows the files match an UNAUTHENTICATED list, not that the release is genuine.

## Files this skill touches

The skill itself is read-only on the repo and write-only on:
- The git remote (`git push origin vX.Y.Z` — irreversible)
- GitHub Releases page (via `gh release create` triggered by workflow, or `gh release upload` for an asset missing from the release, Phase 4)
- GHCR (via the workflow's `docker buildx push`)

The local repo state is unchanged unless preflight failed and the operator chose to commit version bumps; those are explicit operator commits, not skill-driven.
