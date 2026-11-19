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
- All commits intended for this release merged to `main` (releases tag from main, not dev — confirm `git log origin/main..origin/dev` shows nothing you meant to ship; preflight check #9 reports divergence in either direction and, under the PR-only rulesets, will report at least the promotion merge commit — see Phase 0.5 for what it can and cannot resolve).
- CHANGELOG promoted: `python3 scripts/assemble-changelog.py promote X.Y.Z` run and committed — it assembles all `changelog.d/` fragments (plus any legacy `[Unreleased]` content) into `## [X.Y.Z] - YYYY-MM-DD` and deletes the fragment files. Never hand-move `[Unreleased]` content. Preflight check 4b fails while unpromoted fragments remain. **Later RCs and the final release:** the version was promoted at its first RC, so hotfix fragments added since then are folded in with `python3 scripts/assemble-changelog.py promote X.Y.Z --append` before each later RC tag, and with `--append --date <final-date>` before the final tag; run that even if no fragment landed since the last RC: with no fragments it only re-dates the header (#5221). Convention: `changelog.d/README.md`.
- `meson.build` `version: 'X.Y.Z'` updated.
- `README.md`'s Docker quickstart updated to the new release (the `/vX.Y.Z/` URL and `YUZU_VERSION=X.Y.Z`); `python3 -I tests/test_readme_quickstart.py` passes. CI runs it too (the `docs` suite of the required *Linux gcc-15 debug* check), but not on a docs-only change (PR or push), which gets that check's stub — run it locally before the release commit's PR rather than finding out from CI (#5540 is the precedent for the bump).
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

If any of these are missing, the skill prompts the operator to fix-and-commit-and-push before continuing. **It does NOT auto-bump versions** — bumping is a deliberate decision (which X, which Y, which Z) the operator owns.

## Phase 0 — Preflight (~30 sec)

Run from the repo root on `main` (or whatever branch is being tagged):

Phase 0 runs on `main`'s **merged** tip — after the promotion (or patch-prep) PR from Phase 0.5
has landed. If that PR does not exist yet, checks 2, 3, 4 and 4b will fail for the obvious reason
(and 9 is red either way — see Phase 0.5): do Phase 0.5 first, then come back here.

```bash
gh auth status                                    # every later `gh` call needs it; fail here, not mid-run
git fetch origin
git switch main && git merge --ff-only origin/main   # preflight checks 2-5 read the LOCAL tree
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" \
  || { echo "STOP: local main != origin/main - abort the release procedure and report to the operator"; return 1 2>/dev/null || exit 1; }
git status -sb                                    # confirm branch + clean tree
bash scripts/release-preflight.sh vX.Y.Z          # CRLF, version, CHANGELOG, compose pins
bash scripts/check-compose-versions.sh X.Y.Z      # explicit compose check (preflight wraps this too)
```

The command blocks in this skill are written to run as scripts, one block at a time — save the
block and run it with `bash`, or feed it whole to `bash <<'EOF' … EOF`. Each STOP then ends the
block (`return 1 2>/dev/null || exit 1` also ends a `source`d file without closing the shell).
**Never paste a block line by line into an interactive shell:** there a STOP's `return` ends
only its own line, the lines after it still run, and in Phase 1 those include `git tag` and
`git push`. A step you do by hand (an edit, a commit) always sits between two blocks, never
inside one. Because each block runs in its own shell, no block may rely on a variable an earlier
block set: every block derives what it reads (`RUN_ID`, `OWNER`) itself, and a block you add
must do the same. If anything prints `STOP`, do not run any
later step; report to the operator. (`--ff-only`
refuses when local `main` has a commit `origin/main` lacks — that is a STOP too. **Never
`git reset --hard` local `main`**: the stray commit is usually an un-pushed promote or version
bump, which belongs on a `release/*-prep` branch and in a PR, not in the bin.)

Preflight checks (numbered as `scripts/release-preflight.sh` numbers them):
1. No CRLF in scripts or gateway config
2. `meson.build` version matches the base version of the tag (rc/beta suffix stripped)
3. CHANGELOG has a `## [X.Y.Z]` section
4. Changelog extraction for that section produces non-empty content (same AWK as release.yml)
4b. No unpromoted `changelog.d/` fragments remain
5. Working tree is clean
6. `Dockerfile.server` includes `--data-dir`
7. release.yml uses `actions/cache/restore@` ONLY — never `actions/cache@` (save). Release
   builds consume cache and never produce it; a `save-always: true` here is the defect, not the
   requirement (see the CI-cache row in `.claude/routed-concerns.md`). Today release.yml has no
   cache step at all, so this passes vacuously
8. `docker-compose.full-uat.yml` includes `--data-dir`
9. `origin/dev` and `origin/main` have IDENTICAL tips (both `rev-list --count`s zero) — hard
   FAIL otherwise, except that it PASSes as "skipping" when either branch is missing on
   `origin`. **No PR-based step can make this check pass** — read Phase 0.5 before acting on
   it
10. (`--full` only) local C++ + Erlang compile (~2 min)

Windows and macOS releases are agent-only (ADR-0035 ladder step 2): `release.yml` builds no Windows or macOS server and no `YuzuServerSetup`, and the Windows and macOS archives are `yuzu-agent-windows-x64.zip` and `yuzu-agent-macos-arm64.tar.gz`. `tests/test_release_agent_only.py` (Docs Lint and `meson test`) fails if a server build or an old archive name comes back, or if the archive names in `release.yml`, `scripts/check-release-artifacts.sh` and `scripts/build-agent-bundle.sh` disagree, so there is no hand check left for this. The first release after step 2 is also the first real run of the changed Windows and macOS jobs: watch them, especially the Windows "Verify the agent runs from the packaged archive" step. Step 3 (`-Dserver`, agent-only vcpkg) adds a refusal of any server-port DLL (`libpq`, `libecpg`, `libpgtypes`, `drogon`, `trantor`, `jsoncpp`, `*xmlsec*`) in that step and makes every image-publish job wait for the builds; its first real run is the first release tag after it (an RC by plan), so watch that step and the six publish legs' start time on that run (the first-RC checks are tracked in #7597).

**Windows Visual C++ toolset and runtime (manual, every release; `release-preflight.sh` does not check it).** The Windows agent carries the Visual C++ runtime of the toolset in `deploy/packaging/windows/msvc-toolset.pin` app-local, and every DLL loaded into the agent, including vendor code such as the Configuration Manager client the `sccm` plugin loads, shares that copy (decision record: "Decision record: app-local Visual C++ runtime (2026-11-18)" in `docs/windows-build.md`). Before tagging, compare the pin with the newest MSVC toolset of the Visual Studio installed on Wee Tam, which builds the release (the version directories under `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\`, after checking the Visual Studio Installer for an update). This step can reach only that Visual Studio's toolsets: Visual Studio 2022 offers nothing past 14.44, so while Wee Tam has it the step finds nothing newer, and moving past 14.44 needs Wee Tam's Visual Studio upgraded first, a separate, reviewed change (`deploy/windows/README.md`) that weakens the decision record's mitigation until it is made. If a newer toolset exists, bump to it in a reviewed PR merged before the tag: install it on Wee Tam (`deploy/windows/README.md`), change `msvc-toolset.pin` and the cl.exe row of `docs/windows-build.md`'s toolchain table together (`tests/test_windows_payload_imports.py` fails when they disagree), and add the changelog fragment the pin file's comment asks for. The release fails when the runner's `VCToolsVersion` differs from the pin, so the runner and the pin move together. If you keep the older toolset, say why in the release report.

**Stop** if preflight fails. Surface the failures and ask the operator how to proceed (commit fixes? bump versions? abort?).

## Phase 0.5 — Branch reconciliation (what preflight check #9 is telling you)

Releases tag from `main`, but ongoing development happens on `dev`. Every prior release has hit the same trap: `dev` accumulates dozens of merged commits, and the prior release's prep commits (CHANGELOG promotion, version stamp) and any hotfixes land on `main` without being carried back to `dev`. By the time the next release is cut, both branches are diverged in both directions and the operator has to remember to reconcile.

The preflight's check #9 surfaces this as a hard FAIL with the exact ahead/behind counts.

**Check #9 cannot be made to PASS by any PR-based step, so do not loop on it.** It demands
identical tips. A PR merge — merge commit, squash or rebase — always creates a commit on the
target branch only, so after the promotion PR `main` is ahead by that commit and after the
back-merge PR `dev` is. The tips coincide only after a direct fast-forward push, which the
rulesets allow for bypass actors alone — that is how `v0.15.0` passed it (a direct push moved
`dev` onto the promotion merge before the tag; `docs/branch-strategy.md` §3.3). Do not rely on
that route: it needs a bypass actor and leaves no review trail. Every 0.14.x tag points at a PR merge commit on
`main`; at `v0.14.0` and `v0.14.1` the check would have read `main` a handful of commits ahead
and `dev` several hundred to a thousand ahead (`docs/branch-strategy.md` §6 has the measured
pairs) — the releases were cut with #9 red and the operator reading the counts rather than
waiting for zero. Do the same: after the two PRs below, re-run preflight, confirm that
`origin/dev..origin/main` is nothing but release prep, hotfixes and merge commits that the
back-merge will carry, and proceed. Making the check merge-aware is a tooling change tracked
separately (see `docs/branch-strategy.md` §3.3).

**Both directions go through a pull request.** The *Protect Main* and *Protect Dev* rulesets accept changes only by PR and require one approving review, so for an ordinary contributor a direct `git push` to either branch — including a fast-forward — is refused. (Which accounts may bypass is visible only to repository administrators; the history shows at least one can, since five `main` PRs and the #6271 back-merge merged without an approving review, and on 2026-10-30 `dev` was moved by a direct push. Use the PR path regardless — it is what leaves the review trail.) Reconciliation flow:

```bash
git fetch origin                             # every command below reads origin/*; a stale
                                             # remote-tracking ref cuts branches in the past
# Diagnose what's where
git log --oneline origin/dev..origin/main    # commits on main, not on dev (release prep, hotfixes)
git log --oneline origin/main..origin/dev    # commits on dev, not on main (usually all the merged work)

# Step 1 — carry main's missing commits back to dev, as a PR into dev.
if git merge-base --is-ancestor origin/main origin/dev; then
  echo "step 1: origin/main is already an ancestor of origin/dev - nothing to carry, skip to step 2"
else
  echo "step 1: $(git rev-list --count origin/dev..origin/main) commit(s) on main to carry back"
  # A merge is usually right (it keeps the hotfix history); cherry-pick only when main
  # holds nothing but a CHANGELOG/version commit that would conflict anyway.
  # Distinct from Phase 6's chore/post-release-back-merge-vX.Y.Z: a merged PR deletes only the
  # REMOTE branch, so a shared name would make the later `switch -c` refuse.
  git switch -c chore/pre-release-back-merge-vX.Y.Z origin/dev \
    || { echo "STOP: could not create chore/pre-release-back-merge-vX.Y.Z (a same-named local branch exists?) - do not merge or push"; return 1 2>/dev/null || exit 1; }
  git merge --no-edit origin/main \
    || { echo "STOP: merge conflict - report the conflicting paths (git diff --name-only --diff-filter=U) to the operator"; return 1 2>/dev/null || exit 1; }
                                   # Never `git merge --abort` silently and never resolve with
                                   # -X ours/theirs - a dropped CHANGELOG bullet passes every
                                   # later check. If a fix was cherry-picked dev->main, delete
                                   # its changelog.d fragment here (#6428): main's copy was
                                   # folded and removed, dev's copy survives the merge and
                                   # would be released twice.
  ! git grep -nE '^(<<<<<<< |>>>>>>> )' -- . \
    || { echo "STOP: conflict markers committed - fix the merge before pushing"; return 1 2>/dev/null || exit 1; }
  git push -u origin chore/pre-release-back-merge-vX.Y.Z \
    || { echo "STOP: push of chore/pre-release-back-merge-vX.Y.Z failed - do not open the PR"; return 1 2>/dev/null || exit 1; }
  gh pr create --base dev \
    --title "chore: back-merge main into dev after the <release> promotion" \
    --body "Carries the <release> promotion, folds and hotfixes back to dev. Merge as a MERGE COMMIT (not squash/rebase) so origin/main becomes an ancestor of origin/dev. Closes nothing."
fi
```

**STOP here if step 1 opened a PR.** Step 2 cuts from `origin/dev` and needs that PR merged — as
a merge commit, not squashed, or the ancestor test above never fires again. Poll
`gh pr view <n> --json state,mergeStateStatus` until `state` is `MERGED`; do not start step 2 on
`OPEN`, `CLOSED` or a dirty `mergeStateStatus`. The first line of the next block enforces this.

```bash
# Gate: refuse to continue unless the step-1 PR is MERGED into dev. Substitute its number;
# if step 1 was skipped, set it to the empty string (BM_PR=) - a literal <n> fails closed.
BM_PR=<n>
[ -z "$BM_PR" ] || gh pr view "$BM_PR" --json state,baseRefName -q '[.state,.baseRefName]|join(" ")' | grep -qx "MERGED dev" \
  || { echo "STOP: back-merge PR $BM_PR is not MERGED into dev - do not start step 2"; return 1 2>/dev/null || exit 1; }
# Step 2 — the PR into main that carries the release commit. THREE variants; pick by what you
# are releasing. Every variant's main-bound PR body carries the record below, and every
# variant passes the nightly-broken gate before that PR is merged.
#
# (a) PROMOTION via a prep branch (#5113): a release/vX.Y.Z-prep branch cut from the
#     RECONCILED dev (after step 1), carrying the release commit (CHANGELOG promotion,
#     meson.build bump, compose defaults — pre-conditions above), PR'd straight into main.
# (b) PATCH (vX.Y.(Z+1) carrying hotfixes already on main): cut the prep branch from
#     ORIGIN/MAIN and SKIP step 1 — a patch must not pick up unreleased dev work. #5540
#     (release/v0.14.1-prep) is the precedent. If the patch also needs a fix that exists only
#     on dev, cherry-pick it onto a hotfix branch off main FIRST (docs/branch-strategy.md §4);
#     never merge dev into a patch prep branch.
# (c) PROMOTION via dev (the 0.15.0 route: #6725 prep → dev, then #6773 dev → main): the same
#     prep branch as (a), PR'd into DEV with NO record in its body; once it is merged, a PINNED
#     candidate goes to main and THAT PR carries the record — see the variant (c) blocks below.
#     Never a bare `--head dev`: a branch ref keeps moving while the PR is open, so anything
#     merged to dev in the meantime rides into the release without release review.
#
# Set BASE once; the single `switch` below reads it. Never write two switch lines.
BASE=origin/dev        # (a) and (c) promotion
# BASE=origin/main     # (b) patch — uncomment this line and comment out the origin/dev line above
git fetch origin \
  || { echo "STOP: git fetch failed - $BASE may be stale; do not cut the prep branch"; return 1 2>/dev/null || exit 1; }
git switch -c release/vX.Y.Z-prep "$BASE" \
  || { echo "STOP: could not create release/vX.Y.Z-prep from $BASE"; return 1 2>/dev/null || exit 1; }
git config branch.release/vX.Y.Z-prep.yuzuReleaseBase "$BASE"   # the next block reads BASE from here
python3 scripts/assemble-changelog.py promote X.Y.Z \
  || { echo "STOP: promote failed - do not edit or commit"; return 1 2>/dev/null || exit 1; }
# plain promote for a new version. A LATER RC of an already-promoted version is none of (a)-(c):
# see "Later release candidates" below. The block ends here, on purpose.
```

**Now, by hand, on `release/vX.Y.Z-prep`:** set `version: 'X.Y.Z'` in `meson.build`, the
`${YUZU_VERSION:-X.Y.Z}` default in every compose file `scripts/check-compose-versions.sh` lists,
and the README quickstart (pre-conditions above); run `bash scripts/check-compose-versions.sh X.Y.Z`
and `python3 -I tests/test_readme_quickstart.py`; then `git add` those files and the promote's
`CHANGELOG.md`/`changelog.d/` changes and commit. A manual step never sits inside a block, because
a block runs whole. The next block refuses to push a branch with no commit of its own or a dirty
tree.

```bash
PR_BASE=main           # (a)/(b). (c): PR_BASE=dev, and a body that says the promotion PR follows - no record
BASE=$(git config --get branch.release/vX.Y.Z-prep.yuzuReleaseBase) \
  || { echo "STOP: no recorded base for release/vX.Y.Z-prep - run the block above first"; return 1 2>/dev/null || exit 1; }
test "$(git rev-parse --abbrev-ref HEAD)" = release/vX.Y.Z-prep \
  || { echo "STOP: not on release/vX.Y.Z-prep"; return 1 2>/dev/null || exit 1; }
[ -n "$(git rev-list "$BASE..HEAD")" ] \
  || { echo "STOP: release/vX.Y.Z-prep has no commit beyond $BASE - make the release commit first"; return 1 2>/dev/null || exit 1; }
[ -z "$(git status --porcelain --untracked-files=no)" ] \
  || { echo "STOP: uncommitted changes - commit or discard them before pushing"; return 1 2>/dev/null || exit 1; }
git push -u origin release/vX.Y.Z-prep \
  || { echo "STOP: push of release/vX.Y.Z-prep failed - do not open the PR"; return 1 2>/dev/null || exit 1; }
gh pr create --base "$PR_BASE" --head release/vX.Y.Z-prep \
  --title "release: vX.Y.Z — promote changelog, bump version" \
  --body "<promotion from dev | patch on main> for vX.Y.Z. Tag follows once merged. Preflight #9 record below.

Release: <tag: vX.Y.Z, or vX.Y.Z-rcN for a candidate>
Preflight #9: main ahead <n> (no-merges <k>) / dev ahead <m>
Expected + (named): <sha> <subject> [release-prep | hotfix #NNNN]; ...
git cherry -v output (verbatim): NOT YET RUN
Unexplained +: NOT YET RUN          Judged by: NOT YET RUN
Validated SHA: NOT YET RUN"
# `Release:` is the exact tag Phase 1 will push. The NOT YET RUN values are filled in step 3;
# Phase 1 refuses to tag while any remains. Get it approved; merge it only after the gate below
# (a merge commit; the ruleset forbids a force or direct push).
```

**Before merging ANY PR into `main`** — the step-2 PR, the variant (c) promotion PR, a later
candidate's `chore/release-*` fold, a hotfix — run this gate. There is no merge to `main` while a
`nightly-broken` issue is open (CLAUDE.md, CI architecture; `docs/ci-architecture.md`). The list
is read with your authenticated `gh`; an API error is a STOP, never an empty list, and so is a
missing label (a renamed label would otherwise list nothing and pass).

```bash
gh label list --repo DevNullLtd/Yuzu --search nightly-broken --json name -q '.[].name' | grep -qx nightly-broken \
  || { echo "STOP: cannot confirm the nightly-broken label exists - do not merge to main"; return 1 2>/dev/null || exit 1; }
NB=$(gh issue list --repo DevNullLtd/Yuzu --label nightly-broken --state open --json number -q 'map(.number)|join(" ")') \
  || { echo "STOP: cannot list nightly-broken issues - do not merge to main"; return 1 2>/dev/null || exit 1; }
[ -z "$NB" ] \
  || { echo "STOP: nightly-broken issue(s) open: $NB - no merge to main"; return 1 2>/dev/null || exit 1; }
```

**Variant (c) only — the pinned dev → `main` promotion.** Run after the prep PR is merged into
`dev`. The candidate is the `dev` commit you review; the PR's head is a branch created at it,
and the candidate is written into the PR body so every later check reads it from there rather
than from a fresh `origin/dev`. The block refuses a candidate that does not contain the merged
prep PR, and lists every `dev` merge that landed after it: those ride into the release, so the
promotion PR's reviewer must see them.

```bash
PREP_PR=<n>    # the variant (c) prep PR, merged into dev; a literal <n> fails closed
git fetch origin \
  || { echo "STOP: git fetch failed - origin/dev may be stale; do not pin a candidate"; return 1 2>/dev/null || exit 1; }
PREP_MERGE=$(gh pr view "$PREP_PR" --json state,baseRefName,mergeCommit -q 'select(.state=="MERGED" and .baseRefName=="dev") | .mergeCommit.oid') \
  && [ -n "$PREP_MERGE" ] \
  || { echo "STOP: prep PR $PREP_PR is not MERGED into dev - do not pin a candidate"; return 1 2>/dev/null || exit 1; }
CANDIDATE=$(git rev-parse origin/dev)
git merge-base --is-ancestor "$PREP_MERGE" "$CANDIDATE" \
  || { echo "STOP: candidate $CANDIDATE does not contain the prep merge $PREP_MERGE"; return 1 2>/dev/null || exit 1; }
RIDERS=$(git log --first-parent --oneline "$PREP_MERGE..$CANDIDATE")
echo "Merged to dev after the prep PR (they ride into the release): ${RIDERS:-none}"
PROMOTE_BRANCH=release/vX.Y.Z-promote   # a re-pin uses a fresh name: release/vX.Y.Z-promote-2, ...
# The branch must not exist yet: pushing onto an existing one would silently fast-forward it.
# (`${CANDIDATE}` is braced: in zsh, "$CANDIDATE:r…" is a modifier and eats the colon.)
git ls-remote --exit-code origin "refs/heads/${PROMOTE_BRANCH}" >/dev/null; LS_RC=$?
[ "$LS_RC" = 2 ] \
  || { echo "STOP: ${PROMOTE_BRANCH} already exists (or origin is unreadable, rc $LS_RC) - pin on a fresh name"; return 1 2>/dev/null || exit 1; }
git push origin "${CANDIDATE}:refs/heads/${PROMOTE_BRANCH}" \
  || { echo "STOP: could not create ${PROMOTE_BRANCH} at the candidate"; return 1 2>/dev/null || exit 1; }
gh pr create --base main --head "${PROMOTE_BRANCH}" \
  --title "release: dev → main promote for vX.Y.Z" \
  --body "Promotes candidate $CANDIDATE (dev, carrying the vX.Y.Z prep #$PREP_PR) to main. Tag follows once merged.

Merged to dev after the prep PR (riding into the release):
${RIDERS:-none}

Candidate: $CANDIDATE
<then the step-2 record lines, Release: through Validated SHA: NOT YET RUN>"
```

Merge it only this way, after the nightly-broken gate. `PROMO_PR` is this promotion PR, and
Phase 1 uses the same number. `--match-head-commit` makes GitHub refuse the merge if the head
has moved since it was pinned — nothing protects `release/*` branches, so this, not the branch
name, is the guard.

```bash
PROMO_PR=<n>
# The whole nightly-broken gate again, in the same block as the merge it guards.
gh label list --repo DevNullLtd/Yuzu --search nightly-broken --json name -q '.[].name' | grep -qx nightly-broken \
  || { echo "STOP: cannot confirm the nightly-broken label exists - do not merge to main"; return 1 2>/dev/null || exit 1; }
NB=$(gh issue list --repo DevNullLtd/Yuzu --label nightly-broken --state open --json number -q 'map(.number)|join(" ")') \
  && [ -z "$NB" ] \
  || { echo "STOP: nightly-broken open (${NB:-gh error}) - no merge to main"; return 1 2>/dev/null || exit 1; }
CANDIDATE=$(gh pr view "$PROMO_PR" --json body -q .body | tr -d '\r' | sed -n 's/^Candidate: \([0-9a-f]\{40\}\)[[:space:]]*$/\1/p')
[ -n "$CANDIDATE" ] && [ "$(printf '%s\n' "$CANDIDATE" | wc -l | tr -d ' ')" = 1 ] \
  || { echo "STOP: PR $PROMO_PR needs exactly one 'Candidate: <40-hex>' line"; return 1 2>/dev/null || exit 1; }
gh pr merge "$PROMO_PR" --merge --match-head-commit "$CANDIDATE" \
  || { echo "STOP: merge refused - if the head moved off $CANDIDATE, close the PR, pin a new candidate on a fresh branch and re-review"; return 1 2>/dev/null || exit 1; }
```

For every other PR into `main` there is no scripted merge: run the gate block above immediately
before you press merge, not when the PR is opened.

The head moves if anyone pushes to the branch, or if "Update branch" is used — both rulesets
require branches to be up to date, so a hotfix landing on `main` while the PR is open forces
one. In either case re-pin: close the PR; if `main` gained a commit `dev` lacks, carry it back
first (step 1's back-merge, merged), or every new candidate is refused the same way; then pin
the reviewed new candidate as `release/vX.Y.Z-promote-2` and re-review.

Phase 1 also checks that the tagged merge's second parent is the recorded candidate — when the
record is on this promotion PR. If a hotfix lands after it and the record moves to the hotfix
PR, that body has no `Candidate:` line and the check does not apply; the promotion merge was
already bound to the candidate by `--match-head-commit`.

```bash
# Step 3 — on the MERGED tip, re-run preflight and record what it validated. Expect check #9
# to report main ahead by the step-2 merge commit (and dev ahead by anything merged since).
# ACCEPTANCE TEST for the red #9 (docs/branch-strategy.md §3.3; tooling fix tracked in #6427).
# Write the expected `+` list into the PR body BEFORE running git cherry (pre-commitment).
git fetch origin \
  || { echo "STOP: git fetch failed - do not validate a stale origin/main"; return 1 2>/dev/null || exit 1; }
git switch main && git merge --ff-only origin/main \
  || { echo "STOP: cannot fast-forward local main to origin/main"; return 1 2>/dev/null || exit 1; }
VALIDATED=$(git rev-parse HEAD)
[ "$VALIDATED" = "$(git rev-parse origin/main)" ] \
  || { echo "STOP: local main != origin/main"; return 1 2>/dev/null || exit 1; }
bash scripts/release-preflight.sh vX.Y.Z; PF_RC=$?   # READ IT: every check except #9 must PASS (below)
[ "$PF_RC" -eq 0 ] || echo "
!!! PREFLIGHT EXITED $PF_RC. Read every FAIL line above. If any is not check #9
!!! (origin/dev and origin/main diverged), STOP: there is no SHA to record.
"
# The evidence reads $VALIDATED, not origin/main: preflight re-fetches, and origin/main may have moved.
git log --no-merges --oneline "origin/dev..$VALIDATED"   # must be ONLY release prep + hotfixes you can name
git cherry -v origin/dev "$VALIDATED"                     # every `+` must be in the expected list; an unexpected `+` STOPS the release
git log --merges -p --cc "origin/dev..$VALIDATED"         # cherry and --no-merges both skip merges; a non-empty --cc diff = a hand-resolved merge, READ it
git diff --stat "$VALIDATED^1" "$VALIDATED"               # the promotion merge vs its first parent = what the release added; must be the intended delta
echo "Validated SHA: $VALIDATED"
```

**Read the preflight output before recording anything.** If any check other than #9 reports
FAIL, STOP: fix it and re-run this step; there is no SHA to record. The skill does not parse
the script's output — a scripted "only #9 failed" check belongs in `release-preflight.sh`
(#6427), where it can be tested against the script's own wording.

Then fill the record (`gh pr edit <n> --body-file`; a merged PR's body stays editable) on the PR
whose merge commit is the `Validated SHA` printed above — normally the promotion PR; if a hotfix
merged after the promotion and before this step, the hotfix PR, with its `Expected +` line
written before you re-run `git cherry`. Phase 1 tags exactly that SHA and nothing else.

- `Preflight #9:` — the two counts preflight printed, and the `--no-merges` count.
- `git cherry -v output (verbatim):` — the first `+`/`-` line on the same line after the colon,
  the remaining lines below it, unedited. If it printed nothing, write `(empty)`.
- `Unexplained +:` — `none`. Anything else means the release stops here; Phase 1 tags only on
  `none`. `Judged by:` — your GitHub handle.
- `Validated SHA:` — the line printed above.

Phase 1 checks only what binds the tag to this record: exactly one well-formed `Validated SHA:`
line, no `NOT YET RUN` left, `Release:` exactly the tag, `Unexplained +: none`, the PR merged
into `main` at that SHA with local and remote `main` still there, and (variant (c)) that the
merge's second parent is the recorded `Candidate:`. The other fields are for the reviewer;
nothing parses them.

`origin/main^1` is the promotion merge's first parent only while that merge is still `main`'s
tip; if a hotfix landed after it, diff the merge commit itself: `git diff --stat <merge>^1 <merge>`.

**If anything lands on `main` after step 3**, the record no longer describes the tip and Phase 1
STOPs. Re-run step 3 on the new tip and write the record on the PR whose merge produced that tip
(for a hotfix, the hotfix PR — its body stays editable after the merge), writing its
`Expected +` line there before re-running `git cherry`.

**Later release candidates.** A later `-rcN` of an already-promoted version is folded by
`promote X.Y.Z --append` on a `chore/release-*` branch cut from `origin/main`
(`docs/branch-strategy.md` §3.4). That fold PR is the next tag's record PR: open it with the same
record lines (`Release: vX.Y.Z-rcN`), pass the nightly-broken gate, merge it, and run step 3 on
its merged tip.

`gh pr create` needs `--body` (or `--fill`) when run non-interactively — with `--title` alone it
exits with "must provide --title and --body". Recent instances:

- #6271 — back-merge, 2026-10-21.
- #6264 — a `--head dev` sync to `main` with no release commit, 2026-10-21.
- #5113 and #5540 — variants (a) and (b): promotions from `release/*` branches carrying the
  release commit.
- #6725 → #6773 — variant (c), v0.15.0, 2026-10-30. #6773 used `--head dev`; this skill replaces
  that with a pinned branch.

The operator then tags the validated SHA (Phase 1). The back-merge of the step-2 merge commit
itself happens after the release (Phase 6 step 1).

## Phase 1 — Tag and push (~5 sec)

```bash
# PROMO_PR = the PR whose merge commit is main's tip and whose body carries the Preflight #9
# record (Phase 0.5 step 3): the step-2 PR, the variant (c) promotion PR, a later candidate's
# chore/release-* fold PR, or a hotfix PR that landed after the promotion. TAG = the exact tag,
# -rcN included. Fail CLOSED: an unreadable PR (wrong number, gh error, literal <n>) is a STOP.
PROMO_PR=<n>
TAG=vX.Y.Z
git fetch origin \
  || { echo "STOP: git fetch failed - origin/main may be stale; do not tag"; return 1 2>/dev/null || exit 1; }
git switch main && git merge --ff-only origin/main \
  || { echo "STOP: cannot fast-forward local main to origin/main - do not tag"; return 1 2>/dev/null || exit 1; }
META=$(gh pr view "$PROMO_PR" --json state,baseRefName,mergeCommit -q '[.state, .baseRefName, (.mergeCommit.oid // "none")] | join(" ")') \
  && BODY=$(gh pr view "$PROMO_PR" --json body -q .body | tr -d '\r' | sed 's/[[:space:]]*$//') && test -n "$BODY" \
  || { echo "STOP: cannot read promotion PR $PROMO_PR - do not tag"; return 1 2>/dev/null || exit 1; }
# The verbatim git cherry lines (`+ `/`- `) and riders are free text, so they are not scanned.
printf '%s\n' "$BODY" | grep -vE '^(git cherry -v output \(verbatim\): )?[+-] ' | grep -qF 'NOT YET RUN' \
  && { echo "STOP: PR $PROMO_PR still carries an unfilled Preflight #9 record"; return 1 2>/dev/null || exit 1; }
[ "$(printf '%s\n' "$BODY" | grep -cE '^Validated SHA: [0-9a-f]{40}$')" = 1 ] \
  || { echo "STOP: PR $PROMO_PR needs exactly one 'Validated SHA: <40-hex>' line"; return 1 2>/dev/null || exit 1; }
VALIDATED_SHA=$(printf '%s\n' "$BODY" | sed -n 's/^Validated SHA: \([0-9a-f]\{40\}\)$/\1/p')
[ "$META" = "MERGED main $VALIDATED_SHA" ] \
  || { echo "STOP: PR $PROMO_PR is '$META', not MERGED into main at the validated SHA $VALIDATED_SHA - the record belongs on the PR whose merge commit that SHA is"; return 1 2>/dev/null || exit 1; }
[ "$(git rev-parse HEAD)" = "$VALIDATED_SHA" ] && [ "$(git rev-parse origin/main)" = "$VALIDATED_SHA" ] \
  || { echo "STOP: main is no longer the validated SHA $VALIDATED_SHA - re-run Phase 0.5 step 3 on the new tip and record it on the PR whose merge produced that tip"; return 1 2>/dev/null || exit 1; }
[ "$(printf '%s\n' "$BODY" | grep -c '^Release:')" = 1 ] && printf '%s\n' "$BODY" | grep -qxF "Release: $TAG" \
  && [ "$(printf '%s\n' "$BODY" | grep -c '^Unexplained +:')" = 1 ] \
  && printf '%s\n' "$BODY" | grep -qE '^Unexplained \+: none([[:space:]]+Judged by:.*)?$' \
  || { echo "STOP: PR $PROMO_PR needs exactly one 'Release: $TAG' line and exactly one 'Unexplained +: none' line"; return 1 2>/dev/null || exit 1; }
# Variant (c): the promotion merge must have merged the recorded candidate.
CANDIDATE=$(printf '%s\n' "$BODY" | sed -n 's/^Candidate: //p')
[ -z "$CANDIDATE" ] || [ "$(git rev-parse -q --verify "$VALIDATED_SHA^2")" = "$CANDIDATE" ] \
  || { echo "STOP: $VALIDATED_SHA did not merge the recorded candidate $CANDIDATE"; return 1 2>/dev/null || exit 1; }
git tag -a "$TAG" "$VALIDATED_SHA" -m "Release $TAG" \
  || { echo "STOP: git tag failed"; return 1 2>/dev/null || exit 1; }
git push origin "$TAG"
```

If that prints `STOP`, nothing has been tagged; do not run any later step.

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

Since #5242 the release waits for `docker-publish-chisel`, so the chisel SBOMs are always in the signed `SHA256SUMS`. If any job the release needs fails or is cancelled (a build job, `docker-publish`, `docker-publish-postgres` or a `docker-publish-chisel` leg), the release job is skipped (fail-closed): no GitHub release is created, but every image leg that reached its push step has already pushed `:X.Y.Z` (and `:X.Y` and `:latest` on a stable tag). A failed build job is not such a case: all three image-publish jobs wait for all four builds, so a failed build, including a failed agent packaging step, pushes no versioned image (cost: the images start only after the slowest build, ~40 min, and a failed or cancelled Windows or macOS build blocks every image and the release; there is no sanctioned images-only publish path today, tracked in #7596). The chisel publish legs sit in a ref-and-image-keyed `cancel-in-progress: true` concurrency group with no SHA in the key, so a stale run's late chisel leg can cancel the newer run's leg for the same tag: another reason to cancel in-flight runs first. To recover, fix the cause and re-tag (cancel in-flight runs first), or "Re-run failed jobs" on the newest run.

**Recovery: "Re-run failed jobs" on the NEWEST run for the tag. A fresh run is the fallback, not the default.** Re-running the newest run keeps every image digest and artifact its succeeded jobs already produced; only the failed jobs and those skipped behind them execute again, and every publishing step re-checks that the tag still points at this run's commit before it pushes (#5282), so a run whose tag has moved away refuses. That re-check cannot see a tag moved away and back again while two runs are in flight (#5478): **cancel every in-flight release run for a tag before you re-tag it.** "Newest run" means the newest run that got past `release-guard`; a run the guard refused has nothing to re-run. Never re-run an OLDER run (#5242): a newer run may have pushed different images, and a re-run does not repeat `release-guard`. Two cases:
- **The `release` job did not run or failed** (a build, publish or Create Release failure): no release exists. "Re-run failed jobs" finishes the run in minutes. A fresh run also passes the guard but rebuilds and re-pushes everything with new digests (40+ min) — use it only when the newest run cannot be re-run. (Exception: when `Create Release`'s artifact gate rejects a stale package a self-hosted build job uploaded, re-running only the `release` job downloads the same file again; clear the runner workspace and start a fresh run — `docs/ci-architecture.md`, Release artifact gate.)
- **The `release` job published the release and the job then failed or was cancelled before it finished**: a re-run of `release` refuses because the release now exists, so `docker-publish-agent-bundle` cannot run behind it (#5479). The release itself is complete; verify its assets against its `SHA256SUMS`, and confirm with the operator before publishing the agent bundle by another route.
- **The `release` job succeeded and `docker-publish-agent-bundle` failed**: a release exists, so the guard refuses a fresh run by design. "Re-run failed jobs" on that run is the only correct recovery; it is safe because the bundle builds from the published release's own assets.

A release existing means the `release` job of some run succeeded — not that the whole run did. Check `docker-publish-agent-bundle` on that run before calling the release done. "Re-run all jobs" on a released tag fails at `release-guard` (#5282).

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

Start it only when step 1 prints nothing (a queued run counts as running: wait for it) and step 2 says `release not found` (any other error: stop and investigate). **The workflow enforces step 2 itself** (#5282): its first job, `release-guard`, refuses a ref that is not a `vX.Y.Z[-{alpha,beta,rc}N]` tag, then reads `GET /releases/tags/<tag>` and fails the run before any build or push when it answers HTTP 200; it proceeds only on HTTP 404, and any other answer fails the run too. Every image-publishing job and the release job need it. Step 2 is still worth running, because the guard refuses a mistaken run but cannot tell you which run to start. Limits: the guard's read-only token cannot see a **draft** release — one made by hand, or one `gh release create` leaves behind when interrupted while uploading assets (it creates a draft, uploads, then publishes). The `release` job's own check sees drafts and fails. Deleting an unpublished draft is not destructive (nothing was published): delete it, then re-run failed jobs on the newest run. A fresh run is for the newest release only: on an older stable tag, a fresh run would move `:latest` and `:X.Y` back to the older images. If the failure is deterministic, fix it and re-tag instead; a fresh run of the same tag fails the same way. If a stable release cannot be fixed promptly, move `:latest` (and `:X.Y`) back to the previous release's images meanwhile ("Rolling `:latest` and `:X.Y` back", below: commands, and the `X.Y.0` case). **There is no override input, by design.** To change what a published release ships, cut a new version. Deleting a PUBLISHED release is never a recovery for a failed job; it is only for a release whose published content is itself wrong, and it is destructive and visible to anyone who downloaded it, so **confirm with the operator first**. The only way to redo a release under the same tag is to delete the GitHub release first (`gh release delete vX.Y.Z --repo DevNullLtd/Yuzu`, leaving the tag). The fresh run then rebuilds, pushes the images and recreates the release with a `SHA256SUMS` that matches them. A fresh run rebuilds everything, about 40+ minutes.

**Rolling `:latest` and `:X.Y` back** (a stable tag whose images were pushed but whose release failed, when the fix will not land promptly; a pre-release moves neither tag, so there is nothing to roll back). **Confirm with the operator first**: it changes what every `:latest` and `:X.Y` puller gets, and **it can downgrade a running server onto a database schema ahead of it** (see "A rollback can downgrade a running server" below: tell such users to pin the failed release's `:X.Y.Z` instead of following `:latest` back). Six images carry the two tags: `yuzu-server`, `yuzu-gateway`, `yuzu-postgres`, `yuzu-server-chisel`, `yuzu-gateway-chisel` and `yuzu-agent-chisel`. `docker buildx imagetools create --prefer-index=false` with one source copies the manifest byte for byte, so each moved tag keeps the digest, and so the cosign signature (attached by digest), of the image it is copied from. Without `--prefer-index=false` buildx wraps a single image manifest in a new index, which has a new, unsigned digest. It needs `docker login ghcr.io` with a token that can write the packages. The block stops at the first empty lookup, failed copy or digest mismatch; it is safe to run again (a tag already moved is copied to the same digest), so after a failure fix the cause and re-run it whole.

```bash
(
set -euo pipefail
TAG=v0.15.1                                   # the failed stable release
NEW=${TAG#v}; XY=${NEW%.*}; OWNER=devnullltd
# The failed run created no GitHub release, so the newest published stable release is the one :latest named before.
LATEST_PREV=$(gh release list --repo DevNullLtd/Yuzu --exclude-drafts --exclude-pre-releases --limit 1 --json tagName --jq '.[0].tagName // "" | ltrimstr("v")')
# The newest published X.Y.* release: empty when $NEW is X.Y.0 (or no earlier X.Y release was published).
XY_PREV=$(gh release list --repo DevNullLtd/Yuzu --exclude-drafts --exclude-pre-releases --limit 100 --json tagName --jq "[.[].tagName | ltrimstr(\"v\") | select(startswith(\"$XY.\"))][0] // \"\"")
if [ -z "$LATEST_PREV" ] || [ "$LATEST_PREV" = "$NEW" ] || [ "$XY_PREV" = "$NEW" ]; then
  echo "STOP: previous release lookup gave '$LATEST_PREV' / '$XY_PREV' (empty, or the failed release itself)" >&2; exit 1
fi
echo ":latest -> $LATEST_PREV   :$XY -> ${XY_PREV:-(no earlier $XY release: leave :$XY, see below)}"
digest() { docker buildx imagetools inspect "ghcr.io/$OWNER/$1" --format '{{.Manifest.Digest}}'; }
IMAGES="yuzu-server yuzu-gateway yuzu-postgres yuzu-server-chisel yuzu-gateway-chisel yuzu-agent-chisel"
for img in $IMAGES; do
  for pair in "latest $LATEST_PREV" ${XY_PREV:+"$XY $XY_PREV"}; do
    read -r to from <<< "$pair"
    want=$(digest "$img:$from")
    case "$want" in sha256:*) ;; *) echo "STOP: no digest for $img:$from" >&2; exit 1 ;; esac
    docker buildx imagetools create --prefer-index=false --tag "ghcr.io/$OWNER/$img:$to" "ghcr.io/$OWNER/$img:$from"
    got=$(digest "$img:$to")
    if [ "$got" != "$want" ]; then echo "STOP: $img:$to is $got, not $want ($img:$from)" >&2; exit 1; fi
    echo "OK $img:$to = $img:$from = $want"
  done
done
echo "rollback complete: every moved tag has the digest of the image it was copied from"
)
```

- **An `X.Y.0` release** has no earlier `:X.Y`: the failed run created that tag, and it names the failed release's images. Leave it there until the fix ships (only someone who asks for `:X.Y` by name gets them, the same images `:X.Y.0` names), and say so wherever you announce the rollback. **Do not delete the GHCR package version** to remove the tag: that deletes the digest with every tag on it, `:X.Y.0` and its signature included.
- **A rollback can downgrade a running server.** Anyone who pulled `:latest` while it named the failed release, and ran that server, may have a database it migrated. Following `:latest` back puts the older server on a schema ahead of it: it logs the schema-ahead warning and keeps running on a schema it was not written for (`docs/user-manual/upgrading.md`, "When a server build finds its database ahead of it (every Postgres store)"; returning to an earlier build is not a supported path). Say so in the announcement, and tell such users to stay on the image they run (pin `:X.Y.Z` of the failed release) until the fix ships rather than follow `:latest` back.
- Re-tagging or releasing the fix moves `:latest` and `:X.Y` forward again as usual.

The chisel timeout (120 min) is set in the workflow at the tagged commit, so a fresh run of the same tag cannot change it. Raising it means committing the bump and re-tagging.

Watch with `gh run watch` (interactive), or poll-until-done from the LLM:

```bash
RUN_ID=${RUN_ID:-$(gh run list --workflow=release.yml --branch="vX.Y.Z" --limit=1 --json databaseId --jq '.[0].databaseId')}
[ -n "$RUN_ID" ] || { echo "STOP: no release run found for vX.Y.Z"; return 1 2>/dev/null || exit 1; }
gh run watch "$RUN_ID" --exit-status   # blocks until terminal state, exit 0 if all green
```

If `gh run watch` is unsuitable (long-running terminal session), poll every 60s:

```bash
RUN_ID=${RUN_ID:-$(gh run list --workflow=release.yml --branch="vX.Y.Z" --limit=1 --json databaseId --jq '.[0].databaseId')}
[ -n "$RUN_ID" ] || { echo "STOP: no release run found for vX.Y.Z"; return 1 2>/dev/null || exit 1; }
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
RUN_ID=${RUN_ID:-$(gh run list --workflow=release.yml --branch="vX.Y.Z" --limit=1 --json databaseId --jq '.[0].databaseId')}
[ -n "$RUN_ID" ] || { echo "STOP: no release run found for vX.Y.Z"; return 1 2>/dev/null || exit 1; }
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
| `Linking target agents/core/yuzu-agent` (or `yuzu_agent_core.dll`) fails with LNK2038 on Windows | vcpkg cache poisoned with mixed runtime-libraries (the option-D issue from #375 / PR #373) | Bust the Windows vcpkg cache, then "Re-run failed jobs" on the newest run; see Recovery. Long-form: see `.claude/agents/build-ci.md` "Windows MSVC static-link history and #375". |
| `Verify the agent runs from the packaged archive` fails on `build-windows` | The Windows agent archive lacks a DLL the agent or `yuzu_agent_core.dll` imports (exit `-1073741515`, STATUS_DLL_NOT_FOUND), lacks plugin DLLs, contains `yuzu-server.exe`, contains a server-port DLL (log line `server-only DLLs in the agent archive: <names>`: a manifest, install-profile or port change that pulled a server dependency in), or the agent hung (the step kills it after 60 s) | Read the step log. A server-port DLL refusal is deterministic: the release job installs from a clean checkout, so re-running the same tag refuses again. Fix the cause (the manifest, the install line or a port at the pinned baseline) and re-tag. "Re-run failed jobs" on the newest run is only for a transient failure such as a runner or network fault (a hang), as in Recovery above. A real packaging defect needs a commit, then re-tag as Recovery describes. No GitHub Release exists yet, and all three image-publish jobs wait for `build-windows`, so no versioned image was pushed |
| `Notarize binaries` fails with "notarization status is 'Invalid'" on `build-macos` | Apple rejected the agent binary or a dylib (only once `MACOS_SIGNING_CERT` is set; macOS signing is dormant until then) | `xcrun notarytool log <id>` with the id printed in the step log (the step prints the notarization result). Fix the signing with a commit, then re-tag as Recovery describes. No GitHub Release exists yet, and all three image-publish jobs wait for `build-macos`, so no versioned image was pushed |
| `docker-publish-agent-bundle` fails in `scripts/build-agent-bundle.sh` with `cosign verify-blob FAILED`, `no SHA256SUMS.sigstore`, `legacy SHA256SUMS.bundle`, `hash MISMATCH`, `malformed hash`, `no line for <file>`, `ambiguous`, `no <.deb/.rpm/.pkg/Windows> installer asset`, `no SHA256SUMS on`, `no Windows archive on` / `no macOS archive on`, `cannot determine the GitHub repo slug`, `cannot derive the signer repo`, `download missing or empty`, `need cosign`, `malformed --version`, `malformed --signer-repo`, `cannot create a staging dir` or `cannot read/hash/copy` (#7529) | The script authenticates the release's `SHA256SUMS` with cosign (exact identity `https://github.com/<signer>/.github/workflows/release.yml@refs/tags/<tag>`, issuer `https://token.actions.githubusercontent.com`) before reading it, then matches each download to ITS OWN `SHA256SUMS` line. In CI the signer is `--signer-repo ${{ github.repository }}`; by hand it comes from a fixed table (<= 0.13.x `Tr3kkR/Yuzu`, later `DevNullLtd/Yuzu`). The ONLY legitimate signers are `Tr3kkR/Yuzu` (<= 0.13.x) and `DevNullLtd/Yuzu` (after): a `cosign verify-blob FAILED` on the default path means a tampered release or the wrong download source, NOT a signer to override. Rule out first: cosign older than v2.6.2, a wrong clock, or a Sigstore/TUF network failure in cosign's output. There is no offline mode: check proxy/DNS and re-run; if it persists for about an hour, or cosign reports an expired or unverifiable trusted root, treat it as permanent and update cosign. `SHA256SUMS.sigstore` missing means a release before v0.11.0-rc1 (v0.8.0-rc0 to v0.10.0 carry neither signature file) or one assembled by hand (see Known limitations); `legacy SHA256SUMS.bundle` means a v0.7.x release (verify by hand with the exact tag-bound `--certificate-identity`); `hash MISMATCH`/`no line for` means a corrupt or tampered asset; an installer error means the release has none (or several) for the requested version (the script picks each installer by exact version-derived name, so a leftover earlier-rc installer on the same release is ignored, never bundled) | Reproduce without docker with `bash scripts/build-agent-bundle.sh --verify-only --version X.Y.Z` (needs `gh`, cosign v2.6.2 or later, `sha256sum` or `shasum`, and a git checkout; `--signer-repo owner/repo` overrides the table and prints a `[!!]` warning when it differs; **never set it to the subject cosign reports**). **Never skip the check or edit the script to get past it** and there is no skip flag by design; confirm with the operator before publishing a bundle for a release whose manifest does not verify. A transient download failure: "Re-run failed jobs" on the newest run. |
| The `release` job's `Sign SHA256SUMS (keyless)` step fails at its own `cosign verify-blob` (#7529) | The just-made signature did not verify with the exact tag-bound `release.yml` identity. State left behind: the images are already pushed and signed (including `:latest` on a stable tag), the tag exists, NO GitHub Release was created and the agent-bundle job is skipped | "Re-run failed jobs" on the newest run (a deterministic SAN mismatch will fail again: find the cause, e.g. a changed workflow path or a moved tag). **Never widen the check to a `--certificate-identity-regexp`**; confirm with the operator before publishing a release whose manifest does not verify. |
| `Check artifact SBOM scope` fails on the `release` job, `Generate per-artifact SBOMs` fails on a build job, or `Mark the image SBOM incomplete where the scan cannot see` fails on an image-publish job (S8; not yet seen on a release) | `scripts/ci/artifact-sbom.py`: on the `release` job a file SBOM records another file's SHA-256 or name, is over its 400-entry bound, has no entries and no record of unpacked files, or lists a path under `vcpkg/`, `vcpkg_installed/`, `build-*/`, `_build/`, `_build_*/`, `site/`, `tests/`, `.git/` or `.github/`, or an image SBOM pair lacks its CycloneDX or SPDX half or the incomplete marker (`run artifact-sbom.py mark-image`), carries the marker `only in part`, or is named as a release image without that image's title label (`carries no title label`, `its title label is`); on a build job an unpacking tool or syft is missing (`not found on PATH`), syft fails (`syft exited N`) or something `did not finish within` its timeout, an archive member is refused (`escapes the extraction directory`, `is a device or FIFO`, `lies under a link member`), an `.rpm` does not unpack (`rpm2cpio|cpio failed`, either command's exit code), a file `unpacked to no files`, a `.pkg` or archive holds no Yuzu binary it recognises (`no Yuzu C++ binary found`), the installer's ISCC manifest (`YuzuAgentSetup-<version>.manifest.txt`, `docs/ci-architecture.md`, "The installer manifest contract") is refused: `not the encoding ISCC writes a manifest in`, `does not end in CR LF` or `a CR or LF that is not part of a CR LF`, `the header is not the one Inno Setup 6.7.3 writes` (the runner's Inno Setup writes another format: read it in that version's source and update the contract and its fixture in a commit), `no file rows`, `tab-separated columns`, `Index ... not`, `not 64 lowercase hex digits`, `not a drive-absolute Windows path`, `not strictly inside the build directory`, `holds a character Windows does not allow`, `listed again with another SHA-256`, `is missing from the build directory`, `is not a regular file`, `outside the build directory (a symlink or junction)`, or `not the file the installer holds` (a file in `build-windows` changed after ISCC packed it); or the `Build Windows installers` step says `ISCC wrote no manifest`; a vcpkg port the manifest needs is not installed, or an `unexpected <Error>`; on an image-publish job the two image SBOMs `describe different images`, or an image labelled as the release's server, agent, gateway or postgres image shows syft listing no such binary; and on a build job or an image-publish job a note value holds a line break (`a value with a line break`), or on the `release` job or an image-publish job a note `appears <n> times` (more than one copy of a `yuzu:sbom:` note) | Read the `::error::` line; each names the file and the rule. **Re-run first** ("Re-run failed jobs" on the newest run) when the cause can be transient: a `did not finish within` timeout, a runner or network fault, an `unexpected PermissionError` on Windows (an antivirus or indexer holding a freshly unpacked DLL), and, on the `release` job, a SHA-256 mismatch or a missing file or half-pair (a corrupt or failed artifact transfer: the re-run downloads again). Every other rule is about the SBOM or the input itself, and a re-run of the same commit fails the same way: fix the cause in a commit and re-tag as Recovery describes. When a build job fails, no GitHub Release exists and no versioned image was pushed (every image-publish job waits for all four builds). When an image-publish job's mark step fails, or `Check artifact SBOM scope` fails, the state is the one the `Sign SHA256SUMS` row describes: the images are pushed and signed, including `:X.Y` and `:latest` on a stable tag (a mark step runs after its image's push and signing, like the SBOM upload, and the other image legs may have pushed theirs), the tag exists and NO GitHub Release was created (a failed mark step skips the release job), so anyone pulling `:latest` meanwhile gets images no release, `SHA256SUMS` or release SBOM names. In either case, if the fix will not land promptly, move `:latest` and `:X.Y` back to the previous release's images (Recovery, "Rolling `:latest` and `:X.Y` back": the commands, an `X.Y.0` release with no earlier `:X.Y`, and the downgrade warning). The mark steps and the scope check first run for real on a release tag, so cut the first release that carries them as a pre-release (`-rcN`): a pre-release pushes only `:X.Y.Z-rcN` and moves neither `:latest` nor `:X.Y`. The same goes for the installer SBOM: no real ISCC manifest has been checked yet (the contract was built from Inno Setup's source and a fixture), so that `-rcN`'s Windows job is its first real verification; read its `Generate per-artifact SBOMs` output and keep the `windows-installer-manifest` artifact until the run is judged. Re-tagging the fix (a force-moved tag: confirm with the operator, and cancel every in-flight run for the tag first) pushes a second signed digest set under `:X.Y.Z`; the first stays in GHCR, signed, with no release naming it: leave it, and say so in the release notes if anyone may have pulled it. **Never raise `MAX_COMPONENTS` or drop a forbidden segment to get past it** without a measurement showing the SBOM is a correct artifact scan, and never delete the marker or the mark step to pass the image check. |

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
<stem>.cdx.json + <stem>.spdx.json   ← one SBOM pair per archive, .deb, .rpm, .exe and .pkg above (S8); <stem> is the
                                      file name without .tar.gz/.zip/.deb/.rpm/.exe/.pkg, e.g. yuzu-linux-x64.cdx.json,
                                      yuzu-agent_X.Y.Z_amd64.spdx.json, YuzuAgentSetup-X.Y.Z.cdx.json (none for the wizard zip)
yuzu-{server,gateway,postgres}-image.{cdx,spdx}.json, yuzu-{server,gateway,agent}-chisel-image.{cdx,spdx}.json   ← image SBOMs
SHA256SUMS
SHA256SUMS.sigstore                   ← cosign keyless signature (v0.12.0+; legacy releases shipped this as SHA256SUMS.bundle)
<artifact>.intoto.jsonl × N           ← SLSA provenance, one per binary archive/installer (v0.12.0+)
```

On a pre-release tag (`vX.Y.Z-rcN`) the names differ: the `.deb` files are `…_X.Y.Z-rcN_amd64.deb` (the package's own `Version:` is `X.Y.Z~rcN`, so it sorts before the final release — the file name uses the tag's form because GitHub rewrites `~` in asset names, #5141), the RPMs are `…-X.Y.Z-0.1.rcN.x86_64.rpm`, and the Windows/macOS installers use `X.Y.Z_rcN`. Every name in `SHA256SUMS` must equal an asset name: `sha256sum -c SHA256SUMS` after downloading all assets is the check. The per-artifact SBOMs follow the package names (`yuzu-agent_X.Y.Z-rcN_amd64.cdx.json`, `YuzuAgentSetup-X.Y.Z_rcN.cdx.json`); each records its file's SHA-256, and the release job's "Check artifact SBOM scope" step (`scripts/ci/artifact-sbom.py check`) refuses, before the GitHub Release is created (the images are already pushed by then), any file SBOM that does not match its file, is over its entry bound or lists a path under one of the checkout, build- or test-tree segments the script names (`vcpkg/`, `vcpkg_installed/`, `build-*/`, `_build/`, `_build_*/`, `site/`, `tests/`, `.git/`, `.github/`; a scan of some other wrong directory is caught, if at all, by the entry bound), and any image SBOM pair left without the incomplete marker its image calls for.

If any expected asset is missing, the workflow's `Create GitHub Release` step likely failed silently on a single asset (the `gh release create` call is one big command and a single missing asset returns non-zero). Re-upload the missing one:

```bash
gh release upload "vX.Y.Z" path/to/missing-asset.tar.gz
```

The artifacts are still in the workflow run — `gh run download "$RUN_ID"` retrieves them.

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

For non-prerelease tags, also verify the floating tags moved:

```bash
OWNER=$(echo "DevNullLtd" | tr '[:upper:]' '[:lower:]')   # tr3kkr for releases <= 0.13.0 (see the block above)
docker pull "ghcr.io/$OWNER/yuzu-server:latest"
docker image inspect "ghcr.io/$OWNER/yuzu-server:latest" --format '{{.RepoDigests}}'
# Expect the same digest as :X.Y.Z
```

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
OWNER=$(echo "DevNullLtd" | tr '[:upper:]' '[:lower:]')   # tr3kkr for releases <= 0.13.0 (see the image check above)
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

1. **Carry `main` back to `dev`, and bump `dev`'s version in the same PR.** The promotion
   merge commit, every hotfix and every `promote --append` fold exist only on `main` until this
   happens. The flow is Phase 0.5 step 1's on its own branch name: Phase 0.5 used
   `chore/pre-release-back-merge-vX.Y.Z`, and a merged PR deletes only the remote branch, so
   reusing that name would make `switch -c` refuse. When
   `git merge-base --is-ancestor origin/main origin/dev` already holds the merge below is a
   no-op, and the PR carries only the version bump.
   ```bash
   git fetch origin \
     || { echo "STOP: git fetch failed - origin/* may be stale"; return 1 2>/dev/null || exit 1; }
   git switch -c chore/post-release-back-merge-vX.Y.Z origin/dev \
     || { echo "STOP: could not create chore/post-release-back-merge-vX.Y.Z (a same-named local branch exists?) - do not merge or push"; return 1 2>/dev/null || exit 1; }
   git merge --no-edit origin/main \
     || { echo "STOP: merge conflict - report the conflicting paths (git diff --name-only --diff-filter=U) to the operator"; return 1 2>/dev/null || exit 1; }
                                   # Same rules as Phase 0.5 step 1: never abort or -X ours/theirs
                                   # silently; delete a cherry-picked fix's dev-side fragment (#6428).
   ! git grep -nE '^(<<<<<<< |>>>>>>> )' -- . \
     || { echo "STOP: conflict markers committed - fix the merge before pushing"; return 1 2>/dev/null || exit 1; }
   ```
   **Now, by hand:** set `meson.build`'s `version:` to X.Y.(Z+1) or (X+1).Y.0 (the operator's
   call). PLAIN version only — never a `-dev`/`-rcN` suffix: that convention was tried at
   0.13.1-dev and rejected (operator ruling 2026-07-13), because it generated
   `int kVersionPatch = 1-dev;` via `version.hpp.in` and red-lined the entire C++ matrix on `dev`
   and every open PR (fixed in fca69e34). There is no CHANGELOG step: the promote already left the
   `## [Unreleased]` header and its do-not-edit note in place. Then run:
   ```bash
   test "$(git rev-parse --abbrev-ref HEAD)" = chore/post-release-back-merge-vX.Y.Z \
     || { echo "STOP: not on chore/post-release-back-merge-vX.Y.Z"; return 1 2>/dev/null || exit 1; }
   git add meson.build            # never `commit -a`: a stray tracked change would ride along
   git commit -m "chore(post-release): bump dev to X.Y.Z+1" \
     || { echo "STOP: nothing committed - was meson.build's version edited?"; return 1 2>/dev/null || exit 1; }
   git push -u origin chore/post-release-back-merge-vX.Y.Z \
     || { echo "STOP: push of chore/post-release-back-merge-vX.Y.Z failed - do not open the PR"; return 1 2>/dev/null || exit 1; }
   gh pr create --base dev \
     --title "chore: back-merge main into dev after vX.Y.Z; bump dev to X.Y.Z+1" \
     --body "Carries the vX.Y.Z release commits back to dev and sets dev's next version. Merge as a MERGE COMMIT (not squash/rebase) so origin/main becomes an ancestor of origin/dev."
   ```
   One PR, not two: a separate bump branch cut from `origin/dev` before the back-merge has
   merged lacks `main`'s commits and conflicts with the promotion's version stamp. #6271 is the
   2026-10-21 back-merge; observed practice has lagged the bump half — after v0.14.1
   (2026-10-07) `dev` still read `0.14.1` on 2026-10-24, and after v0.15.0 (2026-10-30) the
   bump came three days later in a PR of its own (#6855, `chore/post-release-bump-0.16.0`)
   (`docs/branch-strategy.md` §3.5).
2. **Close any release-blocker issues** in the milestone.
3. **Update the rollout doc** if relevant (`docs/dependency-rollout-*.md`, `docs/roadmap.md`).
4. **Announce.** Yuzu doesn't (currently) have an automated announcement channel. If applicable, post the release URL.

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

Preflight #9:  main ahead <n> / dev ahead <m>; `git cherry` + lines: <list or none>; judged benign by <name> (promotion PR #<n> body)
Post-tag:      changelog.d/ at the tag = README.md only; no duplicate bullet across headers; compose defaults = X.Y.Z; origin/main is an ancestor of origin/dev after the back-merge

Next dev version: X.Y.(Z+1) (bumped in the back-merge PR #<n>, Phase 6 step 1)
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
- **No rollback.** Once `gh release create` runs, the release is public. Untagging is technically possible but discouraged once consumers exist. Prefer a follow-up patch release (vX.Y.Z+1) over rollback.
- **Compose Wizard requires the tag's commit to have `tools/compose-wizard/`.** PR #405 merged to `main` directly. If a future release is cut from a branch that hasn't reconciled with main, the wizard won't be in the source tree and the workflow step will skip it. Preflight does NOT currently check for this — consider adding.
- **Cosign keyless signing requires GitHub Actions OIDC.** Manual asset uploads via `gh release upload` are NOT signed. If a release was assembled manually (per Phase 3 table), `SHA256SUMS.sigstore` will be missing, `scripts/build-agent-bundle.sh` refuses such a release (it never trusts an unsigned `SHA256SUMS`), and operators must say so plainly: `sha256sum -c SHA256SUMS` alone shows the files match an UNAUTHENTICATED list, not that the release is genuine.

## Files this skill touches

The skill itself is read-only on the repo and write-only on:
- The git remote (`git push origin vX.Y.Z` — irreversible)
- GitHub Releases page (via `gh release create` triggered by workflow, or `gh release upload` for repairs)
- GHCR (via the workflow's `docker buildx push`)

The local repo state is unchanged unless preflight failed and the operator chose to commit version bumps; those are explicit operator commits, not skill-driven.
