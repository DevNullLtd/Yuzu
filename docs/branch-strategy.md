# Branches, releases and hotfixes

How work moves from a branch to a tagged release in this repository, as it is actually done
today. It describes practice, not a proposal: each section's claims were checked against the
tooling or the pull-request history on the date given in §6, and where the tooling's own
instructions and the observed practice differ, both are stated. Where the answer is "whoever
decides, decides", §5 names who that is rather than inventing a rule.

Companion documents: `CONTRIBUTING.md` (contributor onboarding, including branch naming),
`.claude/skills/release/SKILL.md` (the step-by-step release procedure the `/release` skill runs),
`changelog.d/README.md` (changelog fragments), `docs/ci-architecture.md` (the CI tiers and the
release gates), `docs/user-manual/release-verification.md` (verifying a published release).

## 1. The branches

| Branch | Role | Protected by |
|---|---|---|
| `main` | Released code only. Every release tag (`vX.Y.Z`, `vX.Y.Z-rcN`) points at a `main` commit. | ruleset *Protect Main* |
| `dev` | Integration branch. Every feature and fix merges here first; it is the PR base for all ordinary work. | ruleset *Protect Dev* |
| `feat/*`, `fix/*`, … | Short-lived work branches, cut from `dev`, deleted on merge. | — |
| `hotfix/*` | A fix to a released version, cut from `main`, merged to `main`, then carried back to `dev`. | — |
| `release/*`, `chore/release-*` | Release preparation: the version bump, the changelog promotion, the `dev`→`main` promotion. Cut from `dev` or `main` as the step requires. | — |

The two rulesets share the same core: changes arrive only by pull request; one approving
review is required; an approval is dismissed by any later push, and the last push must itself be
approved by someone other than its pusher; a change GitHub cannot attribute to a user needs an
extra approval; non-fast-forward pushes and branch deletion are refused; and six status
checks must pass on a branch that is up to date with its base — *Linux gcc-15 debug*, *Windows MSVC debug*, *macOS debug*, *Proto
backward-compat*, *Preflight (runner health)*, *CHANGELOG order*. *Protect Main* additionally
carries an `update` rule (ref updates restricted to bypass actors) that *Protect Dev* does not;
read together with the merge history below, its practical effect appears to be that merging
to `main` itself needs an administrator.

**Those rules are not absolute.** Which actors may bypass a ruleset is visible only to
repository administrators (the API omits `bypass_actors` for everyone else, so a non-admin
cannot confirm the list is empty), and the history shows that at least one account can: of the
28 pull requests merged to `main` between 29 September and 24 October 2026, five merged with no
approving review, and the 21 October back-merge into `dev` (#6271) merged with none, 61 seconds
after its last commit. On 30 October `dev` itself was moved by a direct push, with no pull
request at all: GitHub's repository activity log records a `push` by a release authority
fast-forwarding `dev` from `c262bc5e9` to `7937edebb` (the 0.15.0 promotion merge) at 13:01 UTC,
the only direct push to `dev` it shows after 13 July (read with a non-admin token; the log may
not be complete). Like the merges above, this is a structural gap, not a conduct finding (§5).
Read "one approving review is required" as the
rule that applies to an ordinary contributor, not as a guarantee about every change.

> The rulesets live in the repository settings, not in git. Nothing in this repository can detect
> a change to them, so the sentences above can drift silently. Re-check them against *Settings →
> Rules* when you rely on them; only an administrator can see the bypass list.

### Branch naming in practice

Prefixes used on the 680 pull requests merged between 24 August and 24 October 2026 inclusive
(re-measured on 6 November 2026 with the §6 query; the first count, 672, was taken during
24 October, before that day's last merges):

| Prefix | Count | Used for | Cut from | Merged to |
|---|---|---|---|---|
| `feat/` | 253 | new behaviour | `dev` | `dev` |
| `fix/` | 206 | bug fixes, including `fix/<issue>-<slug>` | `dev` | `dev` |
| `docs/` | 54 | documentation only | `dev` | `dev` |
| `chore/` | 39 | housekeeping; `chore/release-*` for release prep | `dev` or `main` | `dev` or `main` |
| `hotfix/` | 18 | fixes to a released version (§4) | `main` | `main` |
| `ci/` | 17 | workflow and runner changes | `dev` | `dev` |
| `refactor/`, `test/`, `perf/` | 24 | as named | `dev` | `dev` |
| `release/` | 2 | the version-bump and promotion PRs (§3) | `dev` or `main` | `main` (or `dev` in shape (c), §3.1) |
| other | 67 | `dependabot/` 42 (bot), `pg/` 13 and `po/` 4 (older workstream prefixes), 8 one-offs | `dev` | `dev` |

`CONTRIBUTING.md` lists the prefixes a contributor should choose from; this table records what
is actually used.

## 2. Pull-request and merge workflow

1. **Branch from `origin/dev`** after a `git fetch origin` — never from whatever branch you
   happen to be on (the repository's default branch is `main`). Three kinds of branch are cut
   from somewhere else: a hotfix, a `chore/release-*` fold branch and a *patch* release's
   `release/vX.Y.Z-prep` are cut from `main` (#5299, #5318, #5540); a *promotion*'s
   `release/vX.Y.Z-prep` is cut from the reconciled `dev` it promotes (#5113); a sub-PR of a
   long-lived `feat/*` branch is cut from that branch (below). Name it with a prefix from the
   table above and keep it to a single change.
2. **Open the PR against `dev`.** CI runs the Tier 1 fast path on `pull_request`; the full matrix
   runs on the push that lands on `dev` or `main` (`ci.yml`, `on:` block).
3. **Run `/governance <base>..HEAD` locally before asking for review** (`CLAUDE.md` → *Agent team
   & governance*). It reviews a commit range, so commit first. It writes one JSONL fragment per
   run under `governance.d/`, committed with the work it reviewed (`.claude/skills/governance/SKILL.md`,
   Gate 8 step 3). CI does not check for that fragment; its presence is the only durable
   evidence the review ran. Over 24 Aug – 24 Oct 2026, 436 of 556 code-changing PRs to `dev`
   (78%) carried one. A presence check is recommended and tracked in #6430.
4. **Add a `changelog.d/<PR#>-<slug>.<section>.md` fragment** for any operator-visible change;
   never edit `CHANGELOG.md` directly (`changelog.d/README.md`). Pure refactors, CI plumbing and
   test-only changes may skip it.
5. **Documentation gates run in CI** on every PR. The ones that can stop a merge are the steps
   inside the *CHANGELOG order* job, one of the six required checks: besides the changelog order
   itself, these include the docs-drift fact-parity check, the issue-lifecycle docs hygiene check
   (including the `CLAUDE.md` size cap), RBAC doc/seed parity and the governance-ledger linter
   self-test (`docs-lint.yml`, job `changelog-order`). The
   plugin README touch rule, the changelog-fragment lint and the doc-coupling touch rule are
   separate, non-required jobs, so their red results are advisory until the repository owner
   adds them to the rulesets (`docs/docs-drift-gate.md`, `docs/plugin-readme-standard.md`).
   `CLAUDE.md`'s claim that the `Changelog fragments` job "enforce[s]" this holds only in that
   advisory sense.
6. **One non-author approval, then merge.** All three merge methods are enabled on the
   repository; the practice is a merge commit, so a PR's own commits survive on `dev` beside the
   merge commit that lands them. The source branch is deleted automatically on merge.

### Long-lived feature branches

A large piece of work is sometimes built on a `feat/*` branch that stays open for days, with
smaller PRs merged *into it* and a single PR from it into `dev` at the end (`feat/docs-drift-gate`:
#6145 merged into it, then #6126 took it into `dev`). Keep such a branch current by merging `dev`
into it, never the reverse. The governance fragment and the changelog fragment travel with the
final PR into `dev`, not with the intermediate PRs; that is the observed practice, not a written
rule.

**Do not merge a sub-PR into a branch that has already gone to `dev`.** GitHub still accepts the
merge, but nothing then carries it further (#6143's description records that no CI except the
CLA check ever ran on the stranded code). It has happened twice: #6123 merged into `feat/crypto-asset-dashboard` two hours after #6056 had
taken that branch to `dev`, and had to be re-landed from its own branch (#6143); #6078 merged
into `feat/personal-data-commit-guard` six hours after #6042 had, and was re-landed through
`land/personal-data-commit-guard` (#6146). Check the parent's state
(`gh pr list --head <parent> --state merged`) before merging into it.

## 3. Release lifecycle

Releases are tagged from `main`. Development never stops on `dev` while a release is in
progress, so the lifecycle is a sequence of promotions from `dev` to `main` with release-only
commits in between. The 0.14.0 release (29 September – 3 October 2026) and the 0.14.1 patch
(7 October) are the worked example throughout.

### 3.1 Promote `dev` to `main`

A pull request into `main` that carries the release commit (§3.2). Because *Protect Main*
accepts changes only by pull request, this is the only route. Three shapes have been used:

- **(a) prep branch → `main`:** a `release/*` branch cut from `dev`, carrying the release
  commit (#5113 `release/v0.14.0-rc1-take2`).
- **(b) patch prep branch → `main`:** cut from `main`, not `dev` (#5540, 0.14.1; see
  *Recovering a bad release* below).
- **(c) prep branch → `dev`, then `dev` → `main`:** the 0.15.0 route — `release/v0.15.0-prep`
  merged into `dev` (#6725), then `dev` into `main` (#6773), and `v0.15.0` is that merge
  commit (`dev` was then fast-forwarded onto it by a direct push, §1). Before the second PR
  is opened, check that the candidate contains the merged prep PR
  (`git merge-base --is-ancestor <prep merge> <candidate>`): a candidate without it has no
  release commit, which preflight only notices after the merge into `main`. The risk in this
  shape is the second PR: opened with `--head dev`, it keeps moving while it is
  open, so anything merged to `dev` in the meantime rides into the release without release
  review. The guard is to pin the candidate: open the PR from a branch created at the reviewed
  `dev` commit, write that commit into the PR body, merge with
  `gh pr merge --merge --match-head-commit <candidate>` (GitHub refuses the merge if the head
  has moved — nothing protects `release/*` branches, so the branch alone is no guard), and
  check before tagging that the merge commit's second parent is the candidate. If the head
  moves — a push, or "Update branch" when a hotfix lands on `main` — close the PR, back-merge
  `main` into `dev` first if `main` gained a commit `dev` lacks (else every new candidate is
  refused the same way), pin the new candidate on a fresh branch and re-review. #6264 (`dev → main sync`, 21 October) was the same `--head dev` shape with no release
  commit.

**No merge to `main` while a `nightly-broken` issue is open** (CLAUDE.md → *CI architecture*).
Check it immediately before merging, with an authenticated
`gh issue list --label nightly-broken --state open`; an API error is a stop, not an empty list,
and so is a missing label (a renamed label would list nothing).

The step-by-step flow for all three, including the back-merge in the other direction, is
`.claude/skills/release/SKILL.md` Phase 0.5.

### 3.2 Prepare the release commit

One commit on the prep branch of §3.1 — merged into `main` by the same PR in shapes (a) and
(b), into `dev` first in shape (c) — that:

- runs `python3 scripts/assemble-changelog.py promote X.Y.Z`, which folds every `changelog.d/`
  fragment into a new `## [X.Y.Z]` section and deletes the fragment files;
- sets `version: 'X.Y.Z'` in `meson.build`;
- sets the `${YUZU_VERSION:-X.Y.Z}` default in every compose file listed in
  `scripts/check-compose-versions.sh` (ten files at the time of writing) to the **base** version,
  with no `-rcN` suffix. A new compose file must be added to that script's `FILES` array; discovery
  is deliberately not automatic (`CLAUDE.md` → *Release gates*);
- updates the README quickstart's release URL and `YUZU_VERSION=` line (`README.md`, the Docker
  quickstart block) — #5540 did this for 0.14.1. `tests/test_readme_quickstart.py` checks that
  the README's version equals the compose defaults; it runs in the `docs` suite of the required
  *Linux gcc-15 debug* check (`tests/meson.build`, `ci.yml`), so a release commit that bumps the
  compose files but not the README goes red. A docs-only change (PR or push) gets that check's
  stub instead and does not run it.

The version bump is a deliberate operator decision; nothing automates it
(`.claude/skills/release/SKILL.md`, pre-conditions).

### 3.3 Preflight, tag, publish

`bash scripts/release-preflight.sh vX.Y.Z` runs, in the script's own numbering: (1) no CRLF
line endings; (2) `meson.build` version equals the tag; (3) a matching `CHANGELOG.md` section
exists and (4) extracts to non-empty notes; (4b) no unpromoted `changelog.d/` fragments remain;
(5) a clean tree; (6) `Dockerfile.server` has `--data-dir`; (7) `release.yml` has no cache-*save*
step (today it has no cache step at all, so this passes vacuously); (8)
`docker-compose.full-uat.yml` has `--data-dir`; (9) `origin/dev` and `origin/main` have identical
tips; (10, `--full` only) a local compile.

**Preflight is the only enforcement of 4b and 9, and it runs only on the operator's machine.**
The tag push below triggers no preflight; `release.yml` checks neither fragments nor divergence.

**No pull-request step can make check 9 pass.** It requires both `rev-list` counts to be
zero, i.e. the two branches at the same commit. A pull-request merge always creates a commit on
the target branch only, so after a promotion `main` is ahead by that merge commit, and after a
back-merge `dev` is. The tips coincide only after a direct fast-forward push, which only a bypass
actor can perform (§1). Every 0.14.x tag — `v0.14.0-rc1`, `v0.14.0`,
`v0.14.1` — points at a PR merge commit on `main`, and at both `v0.14.0` and `v0.14.1` the
check would have reported `main` a handful of commits ahead and `dev` several hundred ahead
(measured pairs in §6): the releases were cut
with check 9 red and the operator proceeding past the script's stop. `v0.15.0` is the one
release where it would have passed: the direct push of §1 moved `dev` onto the promotion merge at
13:01 UTC, the tag followed at 14:50 with both branches at `7937edebb`, and check 9 would have
read 0/0 and passed — by bypass, not by any step a contributor can take. Until #6427 changes the
check (it must tolerate the release-prep commit, which in shapes (a) and (b) reaches `dev`
only through the back-merge, as well as merge commits), a red 9 is accepted only on this test,
and every other check must pass. The result is written into the promotion PR's body (counts, the `git cherry` output, who judged it) so the judgement is
reviewable afterwards:

- **`main` side:** `git log --no-merges --oneline origin/dev..origin/main` must list only
  release-prep commits (promote, version stamp, compose defaults) and hotfixes you can name.
  `git cherry -v origin/dev origin/main` shows each as `-` (already patch-equivalent on `dev`)
  or `+`; every `+` must be a release-prep commit or a hotfix the back-merge (§3.5) will carry.
  A `+` you cannot name stops the release. Both commands skip merge commits, so also run
  `git log --merges -p --cc origin/dev..origin/main`: a merge that shows a non-empty `--cc` diff
  was hand-resolved and may have dropped or altered a hunk — read it before accepting.
- **`dev` side:** `git log --no-merges --oneline origin/main..origin/dev` is expected to be
  long; what matters is that every commit you meant to ship is in the promotion. Run this on
  the merged tip, after the promotion PR has landed: `git diff --stat origin/main^1 origin/main`
  (the promotion merge against its first parent — what the release added) must be the intended
  delta and nothing else. Diffing against the prep *branch* after the merge is empty and proves
  nothing.

Write the **Expected +** list down when the promotion PR is opened, *before* `git cherry` runs,
so it is a pre-commitment, not a transcription. The remaining values are filled in on the
merged tip after the test, including **Validated SHA** — the `main` commit that preflight and
the test actually examined. The tag step (`.claude/skills/release/SKILL.md` Phase 1) checks
only what binds the tag to the record: it requires exactly one well-formed `Validated SHA:`
line; refuses while any field still reads `NOT YET RUN`; requires `Release:` to be exactly the
tag being pushed, `-rcN` included, and `Unexplained +:` to read `none`; requires the PR to be
merged into `main` at the Validated SHA and local and remote `main` to still be at it; in shape
(c), when the record is on the promotion PR, requires the merge's second parent to be the
recorded candidate (a record moved to a later hotfix PR has no candidate line; the promotion
merge was bound by `--match-head-commit`); and tags that SHA explicitly. The other fields, and the rule that every preflight check
except 9 passed, are for the reviewer and are not parsed by the skill; a scripted check belongs
in `release-preflight.sh` and is part of #6427. The record goes on the PR whose merge commit is
`main`'s tip when the test runs — normally the promotion PR; if a hotfix merged after it, or
anything lands on `main` after the test, re-run the test on that tip and write the record —
`Release:` through `Validated SHA:` — on the PR whose merge produced it (for a hotfix, the
hotfix PR; a merged PR's body stays editable). The promotion PR body carries:

```
Release: <tag: vX.Y.Z, or vX.Y.Z-rcN for a candidate>
Preflight #9: main ahead <n> (no-merges <k>) / dev ahead <m>
Expected + (named): <sha> <subject> [release-prep | hotfix #NNNN]; ...
git cherry -v output (verbatim): NOT YET RUN
Unexplained +: NOT YET RUN          Judged by: NOT YET RUN
Validated SHA: NOT YET RUN
```

`origin/main^1` is the promotion merge's first parent only while that merge is still `main`'s
tip; if a hotfix has landed since, diff the merge commit itself (`<merge>^1 <merge>`).

Preflight reads the *local* tree for checks 2–5, so before running it and again immediately
before tagging: `git switch main && git merge --ff-only origin/main` and confirm
`git rev-parse HEAD` equals `git rev-parse origin/main` — and, before tagging, the recorded
Validated SHA. Then tag that SHA, never "wherever `main` is now":

```bash
git tag -a vX.Y.Z "$VALIDATED_SHA" -m "Release vX.Y.Z" && git push origin vX.Y.Z
```

The tag push starts `release.yml` (`on: push: tags: ['v*']`). Its `release-guard` job refuses to
re-publish over an existing release; the `release:` job validates the compose defaults first;
a tag containing `-` (an `-rcN`) is published as a pre-release and does not move the `:latest`
or `:X.Y` image tags. When the run completes, `pre-release.yml` starts automatically
(`on: workflow_run`) and tests the published packages and images. Verification steps for the
published artefacts are in `docs/user-manual/release-verification.md`.

### 3.4 Release candidates

A version is promoted at its first candidate (`promote X.Y.Z` runs once, for `-rc1`). Fixes that
land on `main` for a later candidate of the *same* version leave new fragments in
`changelog.d/`; before each later tag run `promote X.Y.Z --append` to fold them into the
existing section, and at the final tag add `--date YYYY-MM-DD` to set the release date
(`changelog.d/README.md` → *Fixes that land after a version was promoted*; #5299 and #5318 are
the rc7 and final commits for 0.14.0). A fold is a commit on `main`, so like everything else it
arrives by a PR (`chore/release-*`), and that PR carries the next tag's §3.3 record
(`Release: vX.Y.Z-rcN`). `--append` is for candidates only: a fix that ships in the
*next* version — a patch such as 0.14.1, or the next minor — is folded by that version's own
plain `promote`. The assembler does **not** stop you appending onto a section that has
already shipped: it refuses `--append` only when the target is not the *newest* section
(unless `--allow-older-section`), and it never looks at tags or final dates. Straight after a
stable release, `promote X.Y.Z --append` onto that release's section succeeds, folds the
fragment into notes that are already published and deletes it — and the next version's plain
`promote` then has nothing to describe the fix. Avoiding that is the operator's job.

0.14.0 took seven candidates in five days (rc1 29 Sep → rc7 and final 3 Oct); most of the fixes between them were to the release tooling itself, and those fixes
are merged (#5283 SBOM race, #5284 `promote --append`, #5488 re-publish guard, all on `main` and
back-merged) — the next release does not start from the rc1 tooling.

### 3.5 After the release

1. **Carry `main` back to `dev`.** Everything that landed on `main` during the release — the
   promotion commit, every hotfix, every `--append` fold — must reach `dev`, or the next
   promotion re-opens the fixes. Current practice is a PR from a back-merge branch (#6271,
   21 October 2026, after the 0.15.0-development promotion); the release skill names them
   `chore/pre-release-back-merge-vX.Y.Z` (before a promotion) and
   `chore/post-release-back-merge-vX.Y.Z` (after the release), distinct so one left in a clone
   cannot block the other. After 0.15.0, `dev`'s tip moved onto the promotion merge itself
   (`7937edebb` is the first parent of `dev`'s next merge, #6772, on 30 October) with no
   back-merge PR: GitHub's activity log shows it was the direct bypass push of §1. For anyone
   without bypass the back-merge PR remains the route, and it is the one that leaves a review
   trail. When
   `git merge-base --is-ancestor origin/main origin/dev` already holds there is nothing to
   carry and the merge is a no-op, but the PR is still opened for step 2's version bump. A
   back-merge PR must land as a **merge commit**, never squashed or rebased, or that
   test never becomes true and every later release re-merges `main` for nothing.
   **One trap:** a fix that was cherry-picked from `dev` to `main` (§4) has its
   `changelog.d/` fragment on both branches; the fold deleted `main`'s copy, but the three-way
   merge sees `dev`'s copy as "added on one side" and keeps it, and the next plain `promote`
   releases the bullet a second time. `promote` dedupes only inside the section it is writing
   (#6428). Delete the fragment on `dev` when you cherry-pick, or in the back-merge PR.
2. **Set the next version on `dev`.** `.claude/skills/release/SKILL.md` Phase 6 says to bump
   `meson.build` to the next plain version straight after a release, as a second commit in the
   back-merge PR of step 1 (Phase 6 step 1). Practice has lagged: after 0.14.1 (7 October)
   `dev` still carried `0.14.1` on 24 October, and the bump happened at the next promotion;
   after 0.15.0 (30 October) it came three days later in a PR of its own (#6855,
   `chore/post-release-bump-0.16.0`, 2 November).
3. Patch releases follow the same path: `release/v0.14.1-prep` (#5540) promoted the changelog
   and bumped the version, then `v0.14.1` was tagged.
4. **Post-tag inspection.** Nothing after the tag push checks these (§3.3 covers what preflight
   checks beforehand), so look yourself once the release workflow is green, after
   `git fetch origin --tags`:
   - `git ls-tree --name-only vX.Y.Z changelog.d/` prints only `changelog.d/README.md`. A
     fragment left behind means a hotfix is missing from the notes — the one case nothing
     checks once the tag is pushed.
   - No bullet in the new section also appears under an earlier header (the step 1 trap). The
     file already carries older duplicates, so compare the new section against the rest, not
     the whole file against itself. `CHANGELOG.md` keeps `## [Unreleased]` as its first header
     and the newest release as its second, so the new section is header 2:
     `N=$(mktemp); git show vX.Y.Z:CHANGELOG.md | awk '/^## \[/{n++} n==2&&/^- /' > "$N";
     test -s "$N" || echo "STOP: new section empty - wrong header index";
     git show vX.Y.Z:CHANGELOG.md | awk '/^## \[/{n++} n>2&&/^- /' | grep -Fxf "$N"`
     — a non-empty `$N` and empty final output is a pass. The `test -s` matters: an empty
     pattern file matches nothing and would read as a pass.
   - The `${YUZU_VERSION:-…}` defaults in the compose files read `X.Y.Z`.
   - After the back-merge, `git merge-base --is-ancestor origin/main origin/dev` succeeds.

## 4. Hotfixes

A hotfix is a change that must reach the released line without waiting for the next promotion
from `dev`. Whether a given fix is one is the author's decision (§5). Between 29 September and
24 October 2026, 28 pull requests merged to `main`; 19 of
them changed only release tooling, CI or documentation, and about five changed shipped product
code (#5199 gateway `/metrics` 500s, #5326 and #5255 Windows installers, #5490 agent OTA
signature mode, #6245 nightly test fixes). None was a feature.

The sequence, as practised:

1. **Branch from `main`**, not `dev`: `git fetch origin && git switch -c hotfix/<issue>-<slug>
   origin/main` (the fetch matters — a stale `origin/main` cuts the branch behind other hotfixes
   and the PR then shows conflicts that are not yours). This is one of the three exceptions to
   "branch from `dev`" (§2 step 1). A branch cut from `dev` and pointed at `main` would carry
   every unreleased commit with it; a real hotfix PR has had between 2 and 11 commits (#5311,
   #6245, #5447, #5255), with one deliberate 29-commit stability bundle (#5493).
2. **Fix, with a `changelog.d/` fragment**, and open the PR against `main`. The same six checks
   and review rule apply as on `dev` (and the same bypass caveat, §1).
3. **Merge** — not while a `nightly-broken` issue is open (§3.1; check with an authenticated
   `gh issue list --label nightly-broken --state open`, and treat an API error as a stop) —
   then **fold the fragment** before the next tag (§3.4): `promote X.Y.Z --append`
   if the next tag is another candidate of the version already promoted, or the next version's
   own plain `promote` if it ships in a patch — 0.14.1 was the patch that carried the
   post-0.14.0 hotfixes, promoted by #5540. Only preflight 4b catches a fragment left behind, and
   only on the operator's machine (§3.3).
4. **Carry it back to `dev`** (§3.5 step 1). A hotfix that is only on `main` is lost at the next
   promotion.

Two variants also occur. A fix that was *first* merged to `dev` and then needed on `main` is
cherry-picked onto a branch off `main` (#5311 `hotfix/5298-line-cap-truncation-main`, #6245
`fix/nightly-flakes-main-backport` — both say so in their titles); its fragment then exists on
both branches — see §3.5 step 1 for what to do about that. And
fixes to the release machinery itself (`release.yml`, `pre-release.yml`, packaging) go straight
to `main`, because that is the only branch a release runs from; they are the majority of
hotfixes.

### Recovering a bad release

There is no rollback once `release.yml` has published: untagging is possible but the images and
packages may already be pulled, so the `/release` skill's advice is a patch. The recovery is the
two sequences above joined, and every step of it happens on `main` — do not wait for `dev`, and
do not promote it:

1. Hotfix PR to `main` (§4 steps 1–2).
2. A `release/vX.Y.(Z+1)-prep` branch **cut from `origin/main`** (not `dev` — a prep branch cut
   from `dev` would ship every unreleased commit in the patch; #5540 is the 0.14.1 precedent).
   If the patch also needs a fix that exists only on `dev`, cherry-pick it onto a hotfix branch
   off `main` first (the §4 variant); never merge `dev` into a patch prep branch.
   On it, run plain `promote X.Y.(Z+1)` (§3.4 — never `--append`: the assembler would accept it
   onto the released section and the fix would vanish from the patch's notes), stamp
   `meson.build` and the compose defaults with the higher version, open the PR to `main`. The
   fold touches `CHANGELOG.md`, so the *CHANGELOG order* required check applies.
3. Preflight on the merged tip with the red-9 test (§3.3), then a **new** tag — never a re-push
   of the bad one. Only a stable tag moves `:X.Y` and `:latest` off the bad release
   (`release.yml`'s `docker-publish` rules); an `-rcN` patch candidate leaves them where they
   are, so a recovery is not finished until the stable patch tag exists.
4. Back-merge into `dev`, deleting any `dev`-side fragment if the fix was a cherry-pick
   (§3.5 step 1).

## 5. Who decides

Three questions are settled by current practice rather than by a written policy. This is the
practice as confirmed on 2026-10-24 and recorded on the originating issue
([#119, comment by @mdornbrook, 2026-10-24](https://github.com/DevNullLtd/Yuzu/issues/119#issuecomment-6385608102));
the three bullets below restate that comment, so they stand if the link does not, and add
detail it does not carry — the release authorities' duties and the PR-history figures, taken
from §1 and §3. It
may change, and this section is where the change should be recorded.

- **Whether a change is a hotfix is the PR author's call.** The author decides whether a fix goes
  to `main` now (§4) or waits for the next promotion (§3). There is no qualifying list; the
  pattern to date — release-tooling breakage, installer and packaging defects, crashes or 500s in
  shipped binaries, never a feature — is what authors have chosen, not a rule they were applying.
- **Which released versions receive a hotfix is likewise the author's discretion.** In practice
  that has meant only the latest tagged line: every hotfix since 29 September 2026 targeted
  0.14.x, and nothing has been ported to an older tag.
- **Releases are cut by @fjarvis and @Tr3kkR.** They are the release authorities today: they
  decide the version, run the promotion and the tag, and own the `main`→`dev` back-merge. In
  the 0.14.0 and 0.14.1 cycles that was one person in practice: all 28 pull requests merged to
  `main` between 29 September and 24 October 2026 were authored and merged by the same release
  authority, with approving reviews from two other maintainers on 23 of them and no effective
  approval on five (four never approved, one approval dismissed by a later push; §1). That is a
  structural fact about the rulesets and staffing, not a conduct finding; the
  remedy is a compensating control (#6431), not a change of person.

### Open control gaps

Each of the four gaps below is true today, disclosed here on purpose, and has a tracking
issue. Until the issue is closed *as fixed* (a won't-fix close leaves the gap and should be
recorded here as a decision), the honest answer to "is every change to `main` independently
reviewed?" is *no*; to "is the process documented and followed?" it is *yes, with these gaps*.

| Gap | Where stated | Tracked in | Owner / target |
|---|---|---|---|
| The one-approval rule can be bypassed (inferred from PR review states and the activity log — the bypass list itself is admin-only); five of the 28 `main` PRs since 29 Sep 2026, the #6271 back-merge into `dev`, and the 30 Oct direct push to `dev` — seven changes — had no effective approval, and there is no written emergency-change policy saying when bypass is acceptable or what record it leaves | §1 | #6431 | Unassigned — owner to be named in the issue's decision record; no target date set |
| One role authors and merges every change to `main`, by bypass where no review was given; no compensating control (post-merge second review, bypass-use report, tag separated from merge) is in place | §5 | #6431 | as above |
| No PR step can make preflight check 9 pass: it was red at every 0.14.x release, and `v0.15.0` passed it only after a direct bypass push; the operator's judgement is now written into the promotion PR body (§3.3), but neither the check nor the record is machine-verified beyond the tag binding | §3.3 | #6427 | Unassigned |
| The governance review's only evidence is a committed `governance.d/` fragment that CI does not check for; a material share of code PRs lack one (figure, method and date in §2 step 3) | §2 step 3 | #6430 | Unassigned |

## 6. Verified against

Checked on 2026-10-24 at `dev` `21a489378`; re-checked on 2026-11-06 against `dev`
`b042ff63f` for review 5796750417. That re-check updated the §1 naming table, §3.1 shapes and §3.5
bump history, and a second, independent pass the same day corrected §1 (the review-dismissal
rule; the 30 October direct push to `dev`), §2 steps 5–6 and the long-lived-branch examples,
§3.2 (where the release commit is made; the README test runs in CI), §3.3 (check 9 at `v0.15.0`),
§4's hotfix commit range and the §5 gap table. The `release-process` rule in
`scripts/ci/doc-coupling.json` makes the *advisory* `Doc-coupling touch rule` job go red when a
PR changes any of the files in the first group without touching this document or stating
`doc-coupling-exempt: release-process — <reason>` in its body; it is not a required check and
does not stop a merge (`docs/docs-drift-gate.md`). **Not coupled, so they drift silently:** the
rulesets (not in git), `ci.yml`'s triggers (§2 step 2), the gate list in `docs-lint.yml` and
`doc-coupling.yml` (§2 step 5), `CONTRIBUTING.md`'s prefix list, the PR-history figures, and the
state of the tracking issues in §5.

| Section | Source |
|---|---|
| §1 roles, §3.3 trigger and gates | `.github/workflows/release.yml` (`on:`, `release-guard`, `docker-publish` tag rules), `.github/workflows/pre-release.yml` (`on: workflow_run`), `.github/workflows/ci.yml` (`on:`) |
| §3.2–3.3 preflight and version sites | `scripts/release-preflight.sh` (checks 1–10, including 4b; 10 is the optional `--full` build), `scripts/check-compose-versions.sh` (`FILES`), `meson.build` (`version:`) |
| §2 step 4, §3.2, §3.4 fragments | `scripts/assemble-changelog.py` (`promote`, `promote --append`, `--check`), `changelog.d/README.md` |
| §3 procedure | `.claude/skills/release/SKILL.md` (pre-conditions, Phases 0–6); Phase 0.5 was rewritten in the same change as this document to match the PR-only rulesets; its Phase 6 immediate version bump is the step §3.5 notes was not done after 0.14.1 and came late, in #6855, after 0.15.0 |
| §3.1, §4 step 3 nightly-broken stop | `CLAUDE.md` → *CI architecture* ("no merge to main while it is open"), `docs/ci-architecture.md` (the `nightly-broken` discipline norm) |
| §1 rulesets, §2 step 6 merge methods | Repository settings: rulesets *Protect Dev* (id 15845250) and *Protect Main* (id 13631572; `pull_request` rule: `dismiss_stale_reviews_on_push`, `require_last_push_approval`, `require_extra_approval_for_unattributed_changes`), `allow_merge_commit`/`allow_squash_merge`/`allow_rebase_merge`, `delete_branch_on_merge` — **not in git**. Checked with a non-admin token, which cannot see `bypass_actors`; the bypass statement rests on the review state of the 28 `main` PRs and of #6271, and on the repository activity log (`gh api 'repos/DevNullLtd/Yuzu/activity?ref=refs/heads/dev&activity_type=push'`: one direct push after 13 July, 2026-10-30T13:01:31Z, `c262bc5e9`→`7937edebb`). **Counting method for "no approving review":** a merged PR whose `reviewDecision` was not `APPROVED` (`gh pr list --base main --search "merged:>=2026-09-29" --json reviewDecision`); five of the 28 `main` PRs plus #6271 into `dev`, plus the direct push = seven changes |
| §1 naming table | head-branch names of the 680 PRs merged 2026-08-24 → 2026-10-24, re-run 2026-11-06 (`gh pr list --state merged --search "merged:2026-08-24..2026-10-24"`) |
| §2 step 3 governance fragment | `.claude/skills/governance/SKILL.md` Gate 8 step 3; `.github/workflows/docs-lint.yml` "Governance-ledger linter self-test" comment |
| §2 long-lived branches | #6145 → `feat/docs-drift-gate` → #6126; stranded sub-PRs: #6056 merged 2026-10-18T21:42Z then #6123 into the same branch at 23:49Z, re-landed by #6143; #6042 merged 14:02Z then #6078 at 20:06Z, re-landed by #6146 |
| §3 worked example | #5113, #5299, #5318, #5540, #6264, #6271; 0.15.0 shape (c): #6725, #6773 (`v0.15.0^{commit}` = `7937edebb`, second parent `c262bc5e9` = #6725's merge), #6772 (first parent `7937edebb`), #6855; tags `v0.14.0-rc1` (2026-09-29) … `v0.14.0` (2026-10-03), `v0.14.1` (2026-10-07) |
| §3.3 check 9 | `scripts/release-preflight.sh:132-137` (both counts must be 0); `git log --format='%h %p' -1 <tag>^{commit}` shows two parents for all three 0.14.x tags; `git rev-list --count` of `dev..main` / `main..dev` at the tag commits against `dev`'s tip at the time gave `main` 2–5 ahead and `dev` ~470–530 ahead at `v0.14.0` (the exact pair depends on which instant is taken for `dev`) and 5 / 1058 at `v0.14.1`; at `v0.15.0` (tagged 2026-10-30T14:50:59Z) both branches were at `7937edebb` after the 13:01Z direct push; `main`'s first-parent line since 2026-09-29 contains only PR merge commits |
| §4 hotfix sample | the 28 PRs merged to `main` 2026-09-29 → 2026-10-24; #5199, #5255, #5311, #5326, #5447, #5490, #5493, #6245 |
| §5 who decides | the 2026-10-24 comment on #119 linked from §5; the merger/approver figures from the 28 `main` PRs (`gh pr list --base main --search "merged:>=2026-09-29" --json author,mergedBy,reviewDecision`) |
