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
review is required; a review is dismissed when the author pushes again, and the last push must
itself be approved; non-fast-forward pushes and branch deletion are refused; and six status
checks must pass — *Linux gcc-15 debug*, *Windows MSVC debug*, *macOS debug*, *Proto
backward-compat*, *Preflight (runner health)*, *CHANGELOG order*. *Protect Main* additionally
carries an `update` rule (ref updates restricted to bypass actors) that *Protect Dev* does not;
read together with the merge history below, its practical effect appears to be that merging
to `main` itself needs an administrator.

**Those rules are not absolute.** Which actors may bypass a ruleset is visible only to
repository administrators (the API omits `bypass_actors` for everyone else, so a non-admin
cannot confirm the list is empty), and the history shows that at least one account can: of the
28 pull requests merged to `main` between 29 September and 24 October 2026, five merged with no
approving review, and the 21 October back-merge into `dev` (#6271) merged with none, 61 seconds
after its last commit. Read "one approving review is required" as the rule that applies to an
ordinary contributor, not as a guarantee about every merge.

> The rulesets live in the repository settings, not in git. Nothing in this repository can detect
> a change to them, so the sentences above can drift silently. Re-check them against *Settings →
> Rules* when you rely on them; only an administrator can see the bypass list.

### Branch naming in practice

Prefixes used on the 672 pull requests merged between 24 August and 24 October 2026:

| Prefix | Count | Used for | Cut from | Merged to |
|---|---|---|---|---|
| `feat/` | 252 | new behaviour | `dev` | `dev` |
| `fix/` | 204 | bug fixes, including `fix/<issue>-<slug>` | `dev` | `dev` |
| `docs/` | 54 | documentation only | `dev` | `dev` |
| `chore/` | 39 | housekeeping; `chore/release-*` for release prep | `dev` or `main` | `dev` or `main` |
| `hotfix/` | 18 | fixes to a released version (§4) | `main` | `main` |
| `ci/` | 16 | workflow and runner changes | `dev` | `dev` |
| `refactor/`, `test/`, `perf/` | 23 | as named | `dev` | `dev` |
| `release/` | 2 | the version-bump and promotion PRs (§3) | `dev` or `main` | `main` |
| other | 64 | `dependabot/` 39 (bot), `pg/` 13 and `po/` 4 (older workstream prefixes), 8 one-offs | `dev` | `dev` |

`CONTRIBUTING.md` lists the prefixes a contributor should choose from; this table records what
is actually used.

## 2. Pull-request and merge workflow

1. **Branch from `origin/dev`** after a `git fetch origin` — never from whatever branch you
   happen to be on (the repository's default branch is `main`). Three kinds of branch are cut
   from somewhere else: a hotfix and a `main`-side release-prep branch (`chore/release-*`,
   `release/*-prep` — #5299, #5318, #5540) are cut from `main`; a sub-PR of a long-lived
   `feat/*` branch is cut from that branch (below). Name it with a prefix from the table above
   and keep it to a single change.
2. **Open the PR against `dev`.** CI runs the Tier 1 fast path on `pull_request`; the full matrix
   runs on the push that lands on `dev` or `main` (`ci.yml`, `on:` block).
3. **Run `/governance <base>..HEAD` locally before asking for review** (`CLAUDE.md` → *Agent team
   & governance*). It reviews a commit range, so commit first. It writes one JSONL fragment per
   run under `governance.d/`, committed with the work it reviewed (`.claude/skills/governance/SKILL.md`,
   Gate 8 step 3). CI does not check for that fragment; its presence is the only durable
   evidence the review ran.
4. **Add a `changelog.d/<PR#>-<slug>.<section>.md` fragment** for any operator-visible change;
   never edit `CHANGELOG.md` directly (`changelog.d/README.md`). Pure refactors, CI plumbing and
   test-only changes may skip it.
5. **Documentation gates run in CI** on every PR: the docs-drift fact-parity check, the
   plugin README touch rule and the changelog-fragment lint block a merge when they fail; the
   doc-coupling touch rule runs too but is *advisory* — its `Doc-coupling touch rule` job is not
   among the six required checks, so a red result does not stop the merge
   (`docs/docs-drift-gate.md`, `docs/plugin-readme-standard.md`).
6. **One non-author approval, then merge.** All three merge methods are enabled on the
   repository; the practice is a merge commit, so a PR's own commits survive on `dev` (27 of the
   last 300 commits on `dev` are PR merge commits; the rest are the PRs' own commits). The source
   branch is deleted automatically on merge.

### Long-lived feature branches

A large piece of work is sometimes built on a `feat/*` branch that stays open for days, with
smaller PRs merged *into it* and a single PR from it into `dev` at the end (recent examples:
`feat/crypto-asset-dashboard` via #6123 → #6143; `feat/personal-data-commit-guard` via #6078 →
#6146; `feat/docs-drift-gate` via #6145 → #6126). Keep such a branch current by merging `dev`
into it, never the reverse. In both recent cases the governance fragment and the changelog
fragment travelled with the final PR into `dev`, not with the intermediate PRs; that is the
observed practice, not a written rule.

## 3. Release lifecycle

Releases are tagged from `main`. Development never stops on `dev` while a release is in
progress, so the lifecycle is a sequence of promotions from `dev` to `main` with release-only
commits in between. The 0.14.0 release (29 September – 3 October 2026) and the 0.14.1 patch
(7 October) are the worked example throughout.

### 3.1 Promote `dev` to `main`

A pull request from `dev` (or a `release/*` branch cut from it) into `main`
(#5113 `release/v0.14.0-rc1-take2`, #6264 `dev → main sync`). Because *Protect Main* accepts
changes only by pull request, this is the only route; the step-by-step flow, including the
back-merge in the other direction, is `.claude/skills/release/SKILL.md` Phase 0.5.

### 3.2 Prepare the release commit

On `main`, one commit (often in the same PR as the promotion) that:

- runs `python3 scripts/assemble-changelog.py promote X.Y.Z`, which folds every `changelog.d/`
  fragment into a new `## [X.Y.Z]` section and deletes the fragment files;
- sets `version: 'X.Y.Z'` in `meson.build`;
- sets the `${YUZU_VERSION:-X.Y.Z}` default in every compose file listed in
  `scripts/check-compose-versions.sh` (ten files at the time of writing) to the **base** version,
  with no `-rcN` suffix. A new compose file must be added to that script's `FILES` array; discovery
  is deliberately not automatic (`CLAUDE.md` → *Release gates*).

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

**Check 9 cannot pass under the current rulesets.** It requires both `rev-list` counts to be
zero, i.e. the two branches at the same commit. A pull-request merge always creates a commit on
the target branch only, so after a promotion `main` is ahead by that merge commit, and after a
back-merge `dev` is. The only way the tips have ever coincided is a direct fast-forward push,
which only a bypass actor can perform (§1). Every 0.14.x tag — `v0.14.0-rc1`, `v0.14.0`,
`v0.14.1` — points at a PR merge commit on `main`, and at both `v0.14.0` and `v0.14.1` the
check would have reported `main` 5 ahead and `dev` several hundred ahead: the releases were cut
with check 9 red and the operator proceeding past the script's stop. Treat 9 as a divergence
*report*, read its two counts, and confirm that what `main` has and `dev` lacks is release prep
and hotfixes that the back-merge (§3.5) will carry over. Making the check merge-aware
(compare trees, or ignore merge commits) is a tooling change outside this document's scope and
is tracked separately. Then:

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z" && git push origin vX.Y.Z
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
arrives by a PR (`chore/release-*`). `--append` is for candidates only: a fix that ships in the
*next* version — a patch such as 0.14.1, or the next minor — is folded by that version's own
plain `promote`, and `--append` onto an already-final section is refused as "not the newest
released section" unless forced. 0.14.0 took seven candidates in five days (rc1 29 Sep → rc7 and
final 3 Oct); most of the fixes between them were to the release tooling itself.

### 3.5 After the release

1. **Carry `main` back to `dev`.** Everything that landed on `main` during the release — the
   promotion commit, every hotfix, every `--append` fold — must reach `dev`, or the next
   promotion re-opens the fixes. Current practice is a PR from a `chore/back-merge-*` branch
   (#6271, 21 October 2026, after the 0.15.0-development promotion). Skip it only when
   `git merge-base --is-ancestor origin/main origin/dev` already holds (nothing to carry).
   **One trap:** a fix that was cherry-picked from `dev` to `main` (§4) has its
   `changelog.d/` fragment on both branches; the fold deleted `main`'s copy, but the three-way
   merge sees `dev`'s copy as "added on one side" and keeps it, and the next plain `promote`
   releases the bullet a second time. `promote` dedupes only inside the section it is writing.
   Delete the fragment on `dev` when you cherry-pick, or in the back-merge PR.
2. **Set the next version on `dev`.** `.claude/skills/release/SKILL.md` Phase 6 says to bump
   `meson.build` to the next plain version straight after a release. At the time of writing
   `dev` still carries `0.14.1`, the version released on 7 October, while the 21 October promotion
   PR calls the cycle "0.15.0 development" — so in practice the bump has been happening at the
   next promotion rather than straight after the release.
3. Patch releases follow the same path: `release/v0.14.1-prep` (#5540) promoted the changelog
   and bumped the version, then `v0.14.1` was tagged.

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
   every unreleased commit with it; a real hotfix PR has had between 2 and 8 commits (#5311,
   #6245, #5447), with one deliberate 29-commit stability bundle (#5493).
2. **Fix, with a `changelog.d/` fragment**, and open the PR against `main`. The same six checks
   and review rule apply as on `dev` (and the same bypass caveat, §1).
3. **Merge**, then **fold the fragment** before the next tag (§3.4): `promote X.Y.Z --append`
   if the next tag is another candidate of the version already promoted, or the next version's
   own plain `promote` if it ships in a patch — 0.14.1 was the patch that carried the
   post-0.14.0 hotfixes, promoted by #5540. Only preflight 4b catches a fragment left behind, and
   only on the operator's machine (§3.3).
4. **Carry it back to `dev`** (§3.5 step 1). A hotfix that is only on `main` is lost at the next
   promotion.

Two variants also occur. A fix that was *first* merged to `dev` and then needed on `main` is
cherry-picked onto a branch off `main` (#5311 `hotfix/5298-line-cap-truncation-main`, #6245
`fix/nightly-flakes-main-backport` — both say so in their titles); its fragment then exists on
both branches, so delete the `dev` copy or expect the duplicate-bullet trap in §3.5 step 1. And
fixes to the release machinery itself (`release.yml`, `pre-release.yml`, packaging) go straight
to `main`, because that is the only branch a release runs from; they are the majority of
hotfixes.

## 5. Who decides

Three questions are settled by current practice rather than by a written policy. This is the
practice as confirmed on 2026-10-24 and recorded on the originating issue
([#119, comment by @mdornbrook, 2026-10-24](https://github.com/DevNullLtd/Yuzu/issues/119#issuecomment-6385608102));
the three bullets below restate that comment in full, so they stand if the link does not. It
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
  `main` between 29 September and 24 October 2026 were authored and merged by @fjarvis, with
  approving reviews from two other maintainers on 23 of them and none on five (§1).

## 6. Verified against

Checked on 2026-10-24 at `dev` `21a489378`. The `release-process` rule in
`scripts/ci/doc-coupling.json` makes the *advisory* `Doc-coupling touch rule` job go red when a
PR changes any of the files in the first group without touching this document or stating
`doc-coupling-exempt: release-process — <reason>` in its body; it is not a required check and
does not stop a merge (`docs/docs-drift-gate.md`). **Not coupled, so they drift silently:** the
rulesets (not in git), `ci.yml`'s triggers (§2 step 2), the gate list in `docs-lint.yml` and
`doc-coupling.yml` (§2 step 5), `CONTRIBUTING.md`'s prefix list, and the PR-history figures.

| Section | Source |
|---|---|
| §1 roles, §3.3 trigger and gates | `.github/workflows/release.yml` (`on:`, `release-guard`, `docker-publish` tag rules), `.github/workflows/pre-release.yml` (`on: workflow_run`), `.github/workflows/ci.yml` (`on:`) |
| §3.2–3.3 preflight and version sites | `scripts/release-preflight.sh` (checks 1–10, including 4b; 10 is the optional `--full` build), `scripts/check-compose-versions.sh` (`FILES`), `meson.build` (`version:`) |
| §2 step 4, §3.2, §3.4 fragments | `scripts/assemble-changelog.py` (`promote`, `promote --append`, `--check`), `changelog.d/README.md` |
| §3 procedure | `.claude/skills/release/SKILL.md` (pre-conditions, Phases 0–6); Phase 0.5 was rewritten in the same change as this document to match the PR-only rulesets; its Phase 6 immediate version bump is the step §3.5 notes was not done after 0.14.1 |
| §1 rulesets, §2 step 6 merge methods | Repository settings: rulesets *Protect Dev* (id 15845250) and *Protect Main* (id 13631572), `allow_merge_commit`/`allow_squash_merge`/`allow_rebase_merge`, `delete_branch_on_merge` — **not in git**. Checked with a non-admin token, which cannot see `bypass_actors`; the bypass statement rests on the review state of the 28 `main` PRs and of #6271 |
| §1 naming table | head-branch names of the 672 PRs merged 2026-08-24 → 2026-10-24 (`gh pr list --state merged --search "merged:2026-08-24..2026-10-24"`) |
| §2 step 3 governance fragment | `.claude/skills/governance/SKILL.md` Gate 8 step 3; `.github/workflows/docs-lint.yml` "Governance-ledger linter self-test" comment |
| §2 long-lived branches | #6123→#6143, #6078→#6146, #6145→#6126 |
| §3 worked example | #5113, #5299, #5318, #5540, #6264, #6271; tags `v0.14.0-rc1` (2026-09-29) … `v0.14.0` (2026-10-03), `v0.14.1` (2026-10-07) |
| §3.3 check 9 | `scripts/release-preflight.sh:132-137` (both counts must be 0); `git log --format='%h %p' -1 <tag>^{commit}` shows two parents for all three 0.14.x tags; `git rev-list --count` of `dev..main` / `main..dev` at the tag commits against `dev`'s contemporaneous tip gave 5/529 (`v0.14.0`) and 5/1058 (`v0.14.1`); `main`'s first-parent line since 2026-09-29 contains only PR merge commits |
| §4 hotfix sample | the 28 PRs merged to `main` 2026-09-29 → 2026-10-24; #5199, #5255, #5311, #5326, #5447, #5490, #5493, #6245 |
| §5 who decides | the 2026-10-24 comment on #119 linked from §5; the merger/approver figures from the 28 `main` PRs (`gh pr list --base main --search "merged:>=2026-09-29" --json author,mergedBy,reviewDecision`) |
