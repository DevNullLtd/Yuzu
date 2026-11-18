# Dependency Updates

This doc is the strategy reference for keeping Yuzu's pinned third-party
dependencies current. It closes the acceptance criteria for #363: every
ecosystem has a clear update path, a staleness query, and a visible merge
latency. If you're adding a new pinned dependency, this is the file that
tells you where it belongs.

## What is pinned, where, and how it gets updated

| Ecosystem         | Source of truth                               | Update path                                                                                  |
|-------------------|-----------------------------------------------|----------------------------------------------------------------------------------------------|
| GitHub Actions    | `uses: ...@vX` in every `.github/workflows/*` | Dependabot (weekly) — `.github/dependabot.yml` `github-actions` entry                         |
| Windows SDK       | `10.0.26100.0` in the Windows build/provisioning contract | Deliberate reviewed PR; `tests/test_windows_sdk_contract.py` prevents drift (Dependabot tracks the MSVC action, not its `with.sdk` input) |
| Docker base images| `FROM` in `deploy/docker/*`                   | Dependabot (weekly) — `.github/dependabot.yml` `docker` entry. Digest refreshes flow; the `erlang` major, the `ubuntu` major/minor and the `alpine` major/minor are ignored there and moved by hand. The gateway's `alpine` runtime must stay on the `erlang:28-alpine` builder's Alpine release until the gateway is on OTP 29.1 or newer (#2150; `Dockerfile.gateway`'s abi-guard enforces it). A digest refresh of the erlang index is also checked by `scripts/ci/check-gateway-base-index.py`, and the gateway image is `linux/amd64` only (#6711) |
| Python tooling    | `requirements-ci.txt` (repo root)             | Dependabot (weekly) — `.github/dependabot.yml` `pip` entry                                    |
| npm tooling       | `package-lock.json` in `site/`, `tests/puppeteer/`, `deploy/docker/cedar-vale/app/` | Dependabot (weekly, grouped per directory) — `.github/dependabot.yml` `npm` entry; see "npm tooling" below |
| vcpkg baseline    | `vcpkg.json` `builtin-baseline`               | Scheduled workflow — `.github/workflows/vcpkg-baseline-update.yml` (monthly PR, hands-off)     |
| rebar3 deps       | `gateway/rebar.config`                        | **Manual quarterly review** — see "Rebar3 review checklist" below                              |
| Git submodules    | —                                             | No submodules; nothing to track                                                               |

## Update tiers — what carries a remediation SLA

Not everything Dependabot tracks ships to customers. Two tiers, and the
tier — not the tracking mechanism — decides the remediation posture:

- **Tier 1 — product.** Anything compiled into or shipped alongside the
  server, agent, or gateway: vcpkg deps, Docker base images, rebar3 deps,
  and the vendored JS assets embedded into the server binary. Security
  advisories here follow the vulnerability-management commitments in
  `docs/enterprise-readiness-soc2-first-customer.md` (Workstream C).
- **Tier 2 — repo tooling.** Build/test/docs/demo tooling that never
  ships in a product artifact: the three npm directories and the pip CI
  tooling. Advisories are tracked, surfaced, and auto-patched through the
  same Dependabot flow, but are triaged case-by-case and carry **no
  product SLA** — a DoS in the demo deck server is not a product CVE.

This tiering is the story SOC 2 evidence cites: Tier 2 surfaces are
in-scope for *tracking* (advisories cannot accumulate silently anywhere
in the repo) and explicitly out of scope for product remediation SLAs.
If a Tier 2 surface's output starts shipping in a product artifact, it
moves to Tier 1 with its whole ecosystem.

### Base branch

Every Dependabot entry sets `target-branch: dev`. Yuzu's release flow is
feature work → `dev` → reconcile PR → `main`, which means `main` lags
`dev` for hours-to-days at a time. Opening dependency PRs against
`main` races the reconcile cadence and repeatedly fails CI against a
stale base — the LNK2038 Windows fix lived on `dev` for ~24h before the
reconcile PR, during which every open Dependabot PR targeting `main`
kept failing Windows CI. Targeting `dev` eliminates the race.

## Python tooling (meson, etc.)

Yuzu's CI pipeline pins meson because subtle backend rewrites between
meson minor releases have bitten us on ninja dyndep ordering. The pin
is stored in two files at the repo root:

- **`requirements-ci.in`** — human-edited source-of-truth (one
  `package==version` per line).
- **`requirements-ci.txt`** — hash-pinned lock file auto-generated from
  `.in` via `pip-compile --generate-hashes`. Required by OpenSSF
  Scorecard's Pinned-Dependencies check.

These are consumed by:

- `.github/workflows/ci.yml` — the Linux and macOS jobs `pip3/pip/pipx install`
  from it (with `--require-hashes` so a tampered package breaks the install).
- `.github/workflows/release.yml` — the Linux and macOS release builds.

The Windows jobs in both workflows install nothing from it: they use the
runner's pre-provisioned toolchain, whose meson is pinned separately by
`deploy/windows/toolchain-contract.json` (see `docs/windows-build.md`). A
meson bump here therefore does not reach Windows until the contract and the
runner are updated to match.

`scripts/setup.sh` assumes a `meson` binary is already on PATH and does
not install one — local developers are responsible for matching the
pinned version themselves (`pip install --require-hashes -r requirements-ci.txt`
in a venv is the easiest path).

### Bumping meson

```bash
# 1. Edit requirements-ci.in
$EDITOR requirements-ci.in

# 2. Regenerate the hash-pinned lock file
pip install pip-tools      # if not already installed
pip-compile --generate-hashes --strip-extras requirements-ci.in \
            -o requirements-ci.txt

# 3. Commit both files together
git add requirements-ci.in requirements-ci.txt
```

Dependabot opens a PR bumping `requirements-ci.txt` whenever a newer
meson is released. Accepting a Dependabot bump: pull the branch locally,
re-run `pip-compile` to refresh the lock file hashes against the bumped
version in `.in`, amend-commit and push. (Dependabot doesn't know about
the `.in` file so it only updates the `.txt`; keep them in lockstep.)

### Known duplication — Dockerfile meson pins

`deploy/docker/Dockerfile.{agent,server,ci,ci-linux,runner-linux}` each
hardcode `meson==1.9.2` as part of the build-stage apt+pip RUN command.
These are **not** auto-tracked by Dependabot and will drift from
`requirements-ci.txt` if Dependabot bumps meson. This is a known
follow-up — centralizing them on `COPY requirements-ci.txt` is tracked
implicitly by #363 and can be done in a follow-up PR. Until then, when
merging a Dependabot meson bump, also bump the literal `meson==X.Y.Z`
string in those 5 Dockerfiles. Grep `meson==` under `deploy/docker/` to
find them:

```bash
grep -rn 'meson==' deploy/docker/
```

## npm tooling (docs site, UAT harness, demo app)

Three npm-managed directories, all Tier 2 (nothing here ships in a
product artifact):

| Directory | What it is | Exercised by |
|---|---|---|
| `site/` | Astro docs site (GitHub Pages) | `docs-site.yml` build job on every PR touching it |
| `tests/puppeteer/` | Puppeteer UAT harness | manual / UAT runs and the local `/test` pre-push gate (Phases 0b and 5) — **no CI coverage** |
| `deploy/docker/cedar-vale/app/` | Cedar & Vale demo deck server (Express + pg; built only by the viz-UAT rig) | local `docker-compose.viz-uat.yml` builds |

Each directory commits a `package-lock.json` and is listed in the
`npm` entry of `.github/dependabot.yml`. Minor+patch bumps ride one
grouped weekly PR per directory; **majors arrive as separate
single-dependency PRs** (the group filters on `update-types`) so a
breaking major — Astro N+1, express 5, a puppeteer line bump — never
dams the patch stream behind a red migration PR. Astro majors are
validated by the docs-site build job; **puppeteer majors get a manual
UAT-harness smoke before approval**, because nothing in CI exercises
that harness. The docs site pins its toolchain floor in
`site/package.json` `engines` (mirrors Astro's own floor — currently
Node ≥ 22.12.0, npm ≥ 9.6.5; the docs-site job runs Node 22).

**Standing convention — puppeteer launch args.** Every script in
`tests/puppeteer/` passes `--no-sandbox` in its `puppeteer.launch` args (all
seven do, as of the fix that closed this gap). On hosts where user-namespace/
AppArmor restrictions block Chromium's own sandbox, its absence is an
outright launch failure — not a puppeteer-version problem — which is exactly
what blocked the manual pre-approval smoke this doc mandates above for
puppeteer majors: four of the seven scripts silently diverged from the other
three and none of them could launch a browser at all until the flag was
added back. A new script in this directory must carry the flag from
creation.

**Standing convention — new npm directories.** A directory gaining a
`package.json` ships, in the same PR: a committed `package-lock.json`,
an entry in the `npm` block's `directories:` list in
`.github/dependabot.yml` (the list is explicit; there is no
auto-discovery), and `npm ci` — never `npm install` — in any Dockerfile
that consumes it, so images get exactly the committed, audited tree and
manifest/lockfile drift fails the build loudly. A lone `package.json`
has an unpinned transitive tree that is invisible to Dependabot,
`npm audit`, and OSV alike — exactly the hole PR #1877 closed for the
cedar-vale app, where the unpinned tree was carrying a live
high-severity ReDoS.

## vcpkg baseline

Dependabot does not understand vcpkg. We evaluated three options in #363:

1. **Renovate Bot with vcpkg regex managers** — more flexibility, but
   adds a second bot to the repo and the regex configuration is its own
   maintenance burden.
2. **Scheduled workflow that bumps the baseline and opens a PR** —
   simpler, uses GitHub Actions native tools, visible in the normal PR
   feed.
3. **Manual bump during release prep** — zero automation, relies on
   memory.

We chose **option 2**. `.github/workflows/vcpkg-baseline-update.yml`
runs at 10:00 UTC on the 1st of each month (and is
`workflow_dispatch`able). It:

1. Resolves `git ls-remote https://github.com/microsoft/vcpkg.git HEAD`
   to get the current master SHA.
2. Reads `vcpkg.json` `builtin-baseline` via `jq`.
3. If they match, exits silently.
4. Otherwise, `sed -i`s the new SHA into every **active** tracked reference.
   Historical `docs/reviews/` evidence is immutable and deliberately keeps the
   baseline that was reviewed at the time. The workflow file keeps the
   authoritative active list and fails loudly if a listed file still has the
   old SHA after the sed.
5. Opens a PR against `dev` via `peter-evans/create-pull-request` with labels
   `dependencies,ci`, from the fixed branch `deps/vcpkg-baseline-update`, so a
   month's bump updates the open bump PR rather than opening a second one. It
   is pushed and opened with the secret `VCPKG_BASELINE_PR_TOKEN`, stored in
   the `vcpkg-baseline` environment, never `GITHUB_TOKEN`: the bump rewrites files under `.github/workflows/`,
   and GitHub refuses a push that changes a workflow file unless the
   credential holds the `workflows` permission, which `GITHUB_TOKEN` can never
   hold. That refusal is why the scheduled runs from June to November 2026
   failed at "Create pull request" (`git` exited 1) and no PR was ever opened;
   the May run failed earlier, in job setup. A PR opened with the token also
   triggers CI; one opened by `GITHUB_TOKEN` would not. The token check is
   the run's first step, so an unset secret fails every month, also one with
   nothing to bump, with an error naming it. The bump commit names the
   token's owner as author and committer. A last step, "Check the bump PR can
   be approved", fails the run if `ci.yml`'s approval gate could not be
   satisfied on the PR. See "The PR token" below.
6. On any failure, opens (or comments on) a `vcpkg-baseline-broken` issue,
   the `nightly-broken` pattern. It is a repair prompt, not a merge gate. It
   is closed automatically only by a green run that proves the whole path
   works: a run of `main`'s copy (the scheduled one, or a dispatch from
   `main`) that moved the bump branch to a new head and created or updated
   the PR. A green run with nothing to bump, a run whose bump branch already
   held this month's bump (nothing new to push, even when the run opens a PR
   on that branch), or a dispatch from another branch (which the environment
   refuses), leaves it open.

**Schedule runs `main`'s copy.** A scheduled run uses the workflow file as it
is on the default branch, `main`. A change to
`.github/workflows/vcpkg-baseline-update.yml` therefore reaches the monthly
schedule only once `dev` is promoted to `main`; until then the schedule keeps
the old behaviour. A `workflow_dispatch` run from `dev` would use `dev`'s
copy, but the `vcpkg-baseline` environment admits only `main`, so it fails at
job start (see "Where the token is stored").

**Self-hosted CI is held until a maintainer approves the head.** The bump PR
builds an unreviewed `microsoft/vcpkg` HEAD, opened by automation at a known
time. The self-hosted runners are persistent and fill the caches that release
builds read ([CI architecture](ci-architecture.md#release-build-environment-and-provenance)),
so `ci.yml` does not run its self-hosted legs on a `deps/vcpkg-baseline*`
branch until a maintainer has approved the PR at exactly the head that CI run
builds. Until then `Preflight (runner health)` is red, so the PR cannot merge
(short of an administrator's ruleset bypass, after which the push CI on `dev`
runs the self-hosted legs), and only the GitHub-hosted jobs run. To approve, a
maintainer who is independent of the head (see the list below: not the PR's
author, not its pusher, not on any of its commits):

1. reviews the PR's diff and the upstream range linked in the PR body (the
   port changes between the old and new baseline), looking for anything
   unexpected in the ports Yuzu uses;
2. approves the PR (Files changed → Review changes → Approve) while it is at
   that head;
3. on the CI run for that head, chooses "Re-run failed jobs" ("Re-run all
   jobs" works too). Submitting a review starts no CI run; the gate reads the
   reviews live, so the re-run sees the approval. GitHub allows a re-run only
   for 30 days after a run's first attempt. After that, close and reopen the
   PR: that starts a new CI run for the same head, and the approval still
   covers it.

`ci.yml`'s `vcpkg_bump_approval` step counts an approval only if it is the
reviewer's latest approve, request-changes or dismissed review (a comment-only
review changes nothing), was submitted on the commit the run builds, and comes
from a person, not a bot, with write or admin access to the repository (the
repository is public, so anyone can leave an approving review), who is none
of these:

- the PR's author (the token's owner, see "The PR token");
- on a CI run started by a push, the account that pushed that head;
- an account GitHub links to any commit of the PR as its author or committer.
  That covers a maintainer who pushed a commit to the bump branch by hand and
  whoever pressed "Update branch". Each of those needs another maintainer to
  approve. The bump commit itself names the token's owner as author and
  committer (their `<id>+<login>@users.noreply.github.com` address, which
  GitHub always links to their account), so it adds no one beyond the PR's
  author. Until this change reaches `main`, the scheduled run's copy names the
  account that last edited the workflow's cron line instead, and a dispatched
  run's copy names the dispatcher.

A commit whose author or committer GitHub links to no account (an e-mail
address no GitHub account has verified, or a deleted account) fails the gate
outright: the gate cannot show that the approver is not that person. See "If
the bump PR cannot be approved" below for the recovery. The gate also fails if
the PR's commit list no longer contains the run's head (the PR has moved on)
or may be truncated (GitHub lists at most 250 commits).

These identities are the ones a pusher writes into their commits, so the check
keeps an honest maintainer from approving their own push; it is not a defence
against a maintainer who sets out to defeat it, who can run self-hosted CI
from any branch of this repository anyway. That is the limit of what the
gate guarantees: the self-hosted legs wait until an account other than the
ones GitHub records on the head approves it, and the gate cannot tell whether
that account belongs to an independent person.

Pushed with forged commit identities and then re-run from a reopened PR, a
maintainer's own approval would pass this gate. It would not count towards a
merge under the `dev` ruleset, which requires the most recent push to be
approved by someone other than its pusher, and GitHub does not let a PR's
author approve it. That merge rule is a review rule, not a backstop for the
gate. It holds against an ordinary write collaborator, but not against:

- an organisation admin, whom the rulesets let bypass it;
- anyone who can use a repository-wide token to push or approve as the
  token's owner, such as `CLA_REPO_ACCESS_TOKEN`: a classic `repo`-scope
  personal access token (see `cla.yml`) kept as a repository secret, which a
  workflow pushed to any branch can read. With such a token a maintainer could
  push a head as the token's owner and approve it themselves (this gate and
  the merge rule would both see the token's owner as the pusher), or approve
  their own pull request, any pull request and not only the bump PR, as the
  token's owner, and merge with no independent review.

The PR token would be another such token if it were a repository secret,
which is why it is stored in the `vcpkg-baseline` environment, which only
`main` may use (see "Where the token is stored"). That closes the PR token's
route only; the merge rule still does not hold against the two above.

**If the bump PR cannot be approved.** The bump workflow's last step, "Check
the bump PR can be approved", fails the run, and so opens or comments on the
`vcpkg-baseline-broken` issue, when the PR it just created or updated could
not pass the gate: a commit of the PR has an author or committer that GitHub
links to no account, the PR has 250 or more commits (more than GitHub lists),
the PR's author is not the token's owner, or the commit the run pushed is not
linked to the token's owner as both author and committer. The error names
which.

**The recovery**, the one every error message, the workflow's comments and
the alert issue point to: close the PR (do not reopen it), then run
vcpkg-baseline-update.yml from `main` (Actions → vcpkg baseline update → Run
workflow, branch `main`) or wait for the next scheduled run. The new PR is
opened by the token's owner and its commit names them. It applies to an
unlinked commit, a PR of 250 or more commits, and a PR opened by another
account (including after the token moved to a new owner: see "Rotating to a
different owner"). A fix pushed to the bump branch by hand is overwritten by
the next bump either way.

It does not apply when the commit the run pushed is not linked to the token's
owner: the token owner's account cannot be linked from its no-reply address
(check the account still exists and is the one the token belongs to), or the
step's identity inputs were changed. Fix that first; closing the PR alone does
not help.

Before this change reached `main`, the bump commit named the account that last
edited the cron line, so if that account was deleted every scheduled bump
carried an unlinked author and closing the PR did not help. Once this change
is on `main`, the recovery above works.

A later "Request changes" from that reviewer, or a dismissal, withdraws an
approval. Any push to the branch, including next month's bump, makes a new
head that carries no approval, so each new range needs its own review. If
the gate refuses with the PR already at a newer head, review and approve that
head and re-run its newest CI run. The next bump also rebuilds the branch from
`dev`, so a fix committed to the bump branch by hand is overwritten: merge or
close the PR before the 1st of the month. A direct `workflow_dispatch` of
`ci.yml` is not a way round the approval: it is accepted only on `dev` and
`main`.

**Where the approval is recorded.** GitHub keeps every review on the PR: the
reviewer, the time and the commit it was submitted on (the PR's
Conversation tab, or `gh api repos/DevNullLtd/Yuzu/pulls/<number>/reviews`).
That record, not the CI log, is the evidence of who approved which range: the
gate's run log, which names the approver it accepted, expires with the
repository's Actions log retention.

CI on the PR, once approved, re-resolves every downstream vcpkg port against
the new baseline — if anything breaks, the PR is left open for manual
investigation instead of silently merging a broken build.

When adding a new active file that pins the vcpkg baseline SHA (e.g., a new CI
workflow or Dockerfile), **add it to the `files` array in
`.github/workflows/vcpkg-baseline-update.yml`** and to the list in the PR body
there. Do not add immutable `docs/reviews/` evidence. The sed rewrites the
full SHA and its 12-character short form; write any short form at exactly 12
characters. The post-sed verifier checks listed files;
`tests/shell/test_vcpkg_baseline_bump.sh` (run in CI's preflight) fails if a
tracked file carries the current baseline SHA, in full or as a short prefix,
without being listed, if a short form has another length, or if the PR body
lists a different set. A bump record of the form "moved from `<old>` to
`<new>`", like the one below, is history and exempt.

### The PR token

On 2026-11-18 `VCPKG_BASELINE_PR_TOKEN` did not exist. Until a maintainer
creates it, every run fails at its first step and the `vcpkg-baseline-broken`
issue stays open.

- **Owner role:** the release manager (the maintainer who cuts releases with
  the `/release` skill), who creates the token, records its expiry date (a
  calendar reminder or a dated tracking issue) and rotates it.
- **Identity.** A GitHub App installation token, or a token from a dedicated
  bot account, is the preferred identity: the PR is then authored by the bot,
  not by a person. Choosing and setting one up is the repository owner's
  decision (Fraser); until then the token is a fine-grained personal access
  token of the release manager's own account. An App installation token
  cannot read `/user`, which the workflow's rotation guard ("Refuse to push
  onto a bump PR another account opened") uses to learn the token's owner, so
  switching to an App means changing that step in the same change.
- **Scope.** Fine-grained, resource owner `DevNullLtd`, repository access
  "Only select repositories" with this repository alone. Repository
  permissions: Contents, Pull requests and Workflows read and write; nothing
  else. If the organization requires approval of fine-grained tokens, the
  token works only once an organization owner approves it.
- **Expiry:** 90 days or less.
- **Attribution.** A PR opened with a personal token is authored by the
  token's owner, so that person is not an independent reviewer of it, and
  GitHub does not let an author approve their own PR. A different maintainer
  reviews the upstream range and approves the PR, which both releases the
  self-hosted legs for that head and counts towards the merge. The gate
  excludes the PR's author, so this holds only while the token's owner is the
  PR's author: the workflow refuses to push onto an open bump PR that another
  account opened (see "Rotating to a different owner"). The bump commit names
  the token's owner as author and committer too, so it excludes no one else.
- **CLA coverage.** `cla.yml` requires every commit author of a pull request
  to have signed the Contributor License Agreement unless the account is on
  its allowlist. The bump commit's author is the token's owner, so that
  account must have signed the CLA or be on `cla.yml`'s `allowlist`, or the
  CLA check fails on every bump PR. Adding an account to the allowlist is the
  repository owner's decision; a dedicated bot account or App needs the same.
  The bump workflow does not check this: with an uncovered token owner the
  bump run stays green and opens no `vcpkg-baseline-broken` issue, while the
  CLA check fails on every bump PR. Look on the bump PR itself: its checks
  list shows the `CLA Assistant` workflow's `cla-check` job failing, and the
  CLA bot comments on the PR asking the author to sign. Once the token's owner
  has signed or been added to the allowlist, comment `recheck` on the PR to
  re-run the check.
- **Where the token is stored.** In the `vcpkg-baseline` environment, never
  as a repository secret. A repository secret can be read by a workflow pushed
  to any branch, and with this token a maintainer could approve their own pull
  request as the token's owner and merge it with no independent review (the
  paragraph on the merge rule under "Self-hosted CI is held until a
  maintainer approves the head" above). The `propose-bump` job declares
  `environment: vcpkg-baseline`, and no other job or workflow names the
  environment or the secret (`tests/shell/test_vcpkg_baseline_bump.sh` checks both in this
  tree). The environment's settings are the repository owner's to make, once,
  under Settings → Environments:
  1. create the environment `vcpkg-baseline` (a run creates it on first use
     too, but then with no restrictions, so create it first);
  2. under "Deployment branches and tags" choose "Selected branches and tags"
     and add a rule of ref type Branch for `main` only (not a tag rule);
  3. add the secret `VCPKG_BASELINE_PR_TOKEN` under the environment's
     "Environment secrets", or `gh secret set VCPKG_BASELINE_PR_TOKEN --env
     vcpkg-baseline --repo DevNullLtd/Yuzu`;
  4. make sure there is no repository or organisation secret of that name.
     `gh secret list --repo DevNullLtd/Yuzu` must not list it (delete it with
     `gh secret delete VCPKG_BASELINE_PR_TOKEN --repo DevNullLtd/Yuzu` if it
     does), and `gh api repos/DevNullLtd/Yuzu/actions/organization-secrets
     --jq '.secrets[].name'`, the organisation secrets shared with this
     repository, must not list it either (an organisation owner removes it);
  5. required reviewers are optional. With them, every run, the monthly one
     included, waits until a reviewer approves the deployment and fails if
     nobody does within 30 days.

  The workflow does not check these settings, so an unrestricted environment,
  or a repository or organisation copy of the token, still runs green. The
  settings can be read through the API; check them after setting up or
  changing the environment: `gh api
  repos/DevNullLtd/Yuzu/environments/vcpkg-baseline` (its
  `deployment_branch_policy` must not be `null`), `gh api
  repos/DevNullLtd/Yuzu/environments/vcpkg-baseline/deployment-branch-policies`
  (exactly one policy, with `"name": "main"` and `"type": "branch"`; a policy
  of `"type": "tag"` named `main` would admit a tag of that name instead of
  the branch), and the two secret listings in step 4. Because only `main` may
  use the environment, a `workflow_dispatch` of the workflow from any other
  branch fails at job start and opens the `vcpkg-baseline-broken` issue.
- **Create or rotate.** Create the new token with the settings above, store it
  in the `vcpkg-baseline` environment as described in the previous bullet,
  run the workflow once with `workflow_dispatch` on `main` and confirm it
  ends green or opens/updates the bump PR, then revoke the old token. Rotate
  before the expiry date. The
  workflow's first step makes an authenticated read with the token, so an
  expired or revoked token fails every run there and opens a
  `vcpkg-baseline-broken` issue; a token GitHub accepts but whose permissions
  are short, or that still awaits an organization owner's approval, fails
  only at "Create pull request" (typically `git` exiting 1 or 128).
- **Rotating to a different owner.** If the new token belongs to another
  account than the old one and a bump PR is open, apply the recovery under "If
  the bump PR cannot be approved" first: close the PR (do not reopen it), then
  run vcpkg-baseline-update.yml from `main` or wait for the next scheduled
  run. The new PR is attributed to the new owner. (Unlike the 30-day re-run
  recovery above, which reopens a PR nobody else has pushed to, this PR is not
  reopened.) Otherwise the next run that has a bump to push refuses at
  "Refuse to push onto a bump PR another account opened" and opens a
  `vcpkg-baseline-broken` issue, rather than push a head onto the old owner's
  PR that the new owner, not being its author, could then approve. A rotation
  that keeps the same owner needs none of this. The guard runs only in the
  copy of the workflow that runs: a scheduled run uses `main`'s copy, so it
  protects the schedule only once it is on `main`.
- **If it leaks.** Revoke it at once (the owner's Settings → Developer
  settings → Personal access tokens, or an organization owner's token
  review), then create and store a replacement as above. A leaked token can
  push workflow files and tags to this repository; check the repository's
  recent pushes and tags.

### Baseline bump 2026.10.16

`builtin-baseline` moved from `4b77da7fed37` to `9eec002df1cd` (short SHAs; the full
new value is in `vcpkg.json`, the old one in git history; committed 2026-10-17 UTC, tagged
`2026.10.16` upstream). Versions and licenses are read from
`ports/<port>/vcpkg.json` at each commit; `pv` is `port-version`.

| Direct dependency | Old | New | `license` field |
|---|---|---|---|
| grpc | 1.76.0 pv1 | 1.81.1 | no change (Apache-2.0) |
| protobuf | 6.33.4 pv1 | 6.33.4 pv2 | no change (BSD-3-Clause) |
| abseil | 20260107.1 | 20260107.1 pv3 | no change (Apache-2.0) |
| spdlog | 1.17.0 | 1.17.0 pv1 | no change (MIT) |
| cli11 | 2.6.2 | 2.7.2 | no change (BSD-3-Clause) |
| cpp-httplib | 0.37.1 | 0.59.0 | no change (MIT) |
| sqlite3 | 3.52.0 | 3.53.4 pv2 | no change (blessing) |
| libpq | 16.9 pv3 | 18.4 pv1 | no change (PostgreSQL) |
| openssl | 3.6.1 pv2 | 3.6.5 pv2 | no change (Apache-2.0) |
| catch2 | 3.13.0 pv1 | 3.16.0 | no change (BSL-1.0) |
| libxml2 | 2.15.2 | 2.15.4 | no change (MIT) |
| xmlsec | 1.3.9 pv1 | 1.3.12 pv1 | no change (X11 AND MPL-1.1) |
| zlib | 1.3.1 | 1.3.2 pv2 | no change (Zlib) |
| drogon | 1.9.12 | 1.9.13 pv2 | **changed**: `MIT` to `MIT AND BSD-3-Clause` |

`nlohmann-json` (3.12.0 pv2) is unchanged. The license comparison covered the
direct dependencies in `vcpkg.json` only; transitive dependencies were not
checked.

The drogon change is a permissive one (MIT to MIT AND BSD-3-Clause), compatible with
AGPL-3.0-or-later. The `yuzu_drogon_canary` executable is not installed
(`server/core/meson.build`, `install: false`), but `.github/workflows/release.yml` copies every
`*.dll` from `vcpkg_installed/x64-windows/bin` into the Windows archive, so the drogon and
trantor libraries may be staged there. BSD-3-Clause requires its notice in binary
redistribution, so `NOTICE` now lists drogon and trantor with their copyright holders (taken
from the vcpkg port's `copyright` files). No release path ships `NOTICE` or the vcpkg `copyright` files (checked: `release.yml`, the Inno
Setup files, the rpm and debian packaging, and the `deploy/docker` Dockerfiles, whose shipped
images copy only the binaries, plugins and gateway release); staging them in the release
archives and images is a separate follow-up. Drogon's other bundled libraries were not checked.

A future cpp-httplib bump should follow the BUMP CHECKLIST comment in
`server/core/src/body_cap_httplib.hpp`.

**Resolver fix in the glibc branch of cpp-httplib 0.59.0.** The 0.59.0
header carries the fix for upstream issue 2431 (a use-after-free around
`getaddrinfo_a` cancellation); the 0.43.2 header already carries the same fix.
No CVE id is cited: none appears in the vcpkg tree.

**New behaviour.** On glibc builds a lookup against an unresponsive resolver now waits for the
resolver itself (about 30 seconds with default resolver settings; cpp-httplib's header says the
system resolver timeout, about 30 s by default, past the caller's timeout; read as
about 30 s from the start of the lookup, not measured) before the request fails, except the server's OIDC name lookups, which stop waiting at the per-operation timeout; see the upgrade note in `docs/user-manual/upgrading.md`.

**SBOMs.** Unchanged mechanism: `.github/workflows/release.yml` generates them
with Syft (`anchore/sbom-action`), scanning the build workspace and the pushed
release images by digest.

## Rebar3 deps review checklist

`rebar3` has no dependabot ecosystem. `rebar3 update` only refreshes the
package cache — it does not bump the pins in `rebar.config`. Automating
rebar3 bumps requires custom per-dep logic (hex.pm API for hex deps,
`git ls-remote --tags` for git deps) that isn't worth the complexity for
a project with 8 direct gateway dependencies that change a few times a year.

**We review `gateway/rebar.config` manually every quarter**, or whenever
a gateway change is blocked on an upstream fix. Checklist:

1. `cd gateway && source ../scripts/ensure-erlang.sh`
2. For each hex dep in `rebar.config`, check the latest stable release:
   - `cowboy` — https://hex.pm/packages/cowboy (the gateway's listeners: the
     `yuzu_grpc_*` layer is a `cowboy_stream` handler; `ranch` and `cowlib` come with it)
   - `gun` — https://hex.pm/packages/gun (the HTTP/2 client under the upstream gRPC
     client `yuzu_grpc_client`; it needs `cowlib` too)
   - `ctx` — https://hex.pm/packages/ctx (the request-context type of the gRPC layer)
   - `gpb` — https://hex.pm/packages/gpb
   - `telemetry` — https://hex.pm/packages/telemetry
   - `prometheus` — https://hex.pm/packages/prometheus
   - `prometheus_httpd` — https://hex.pm/packages/prometheus_httpd
   - `recon` — https://hex.pm/packages/recon
   - `meck` (test profile) — https://hex.pm/packages/meck
   - `proper` (test profile) — https://hex.pm/packages/proper
3. There are no git-pinned deps: the gateway used to vendor a patched grpcbox
   (`_checkouts/grpcbox`) and pin a `grpcbox_plugin` git tag, and both are gone, as is
   everything grpcbox brought (chatterbox, hpack, acceptor_pool, gproc). If a git-pinned dep
   is ever added, `git ls-remote --tags` it. Transitive deps (`ranch`, `cowlib`, `accept`,
   `quantile_estimator`) are pinned only by `rebar.lock`; they move when the dep that needs
   them is bumped, so read the lock diff.
4. Bump any dep whose latest stable is > 1 minor version ahead of the
   pin, or any dep with a known security advisory (check GitHub
   Security Advisories for the repo).
5. Run `/test --quick` (unit + eunit + dialyzer + synthetic UAT) after
   each bump — do not batch bumps without testing in between.
6. Commit the `rebar.config` change with a conventional
   `build(deps): bump <dep> to <version>` message.

**Pin policy.** `cowboy` and `gun` (the two HTTP/2 stacks the gateway's gRPC layer sits on)
are pinned to a release **at least a month old**, as the comments in `rebar.config` say; a
release newer than that waits. Apply the same rule to any bump. Pin an exact version (as every
dep there is), and refresh `rebar.lock` with `rebar3 upgrade <dep>` so its package hashes
cover the new tarball; commit both files together. After a `cowboy`, `gun`, `cowlib` or
`ranch` bump also run the wire suites that exercise them (`yuzu_grpc_wire_tests`,
`yuzu_grpc_origin_wire_tests`, `yuzu_grpc_client_tls_tests`) and `rebar3 dialyzer`
(`cowlib` and `gun` are in `plt_extra_apps`).

## Vendored JavaScript assets

Yuzu embeds third-party JavaScript at build time via `embed_js.py` (chunked raw-string-literal output to fit MSVC's 16,380-byte C2026 limit). These files are **not** tracked by Dependabot and must be refreshed manually. Each upstream version is pinned in `tests/unit/server/test_static_js_bundle.cpp` by exact byte count + canary substring; a silent CDN substitution fails the test loud.

| Asset | Vendor file | Symbol | Upstream | Current pin |
|---|---|---|---|---|
| HTMX runtime | `server/core/src/static_js_bundle.cpp` (chunked at hand) | `kHtmxJs` | https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js | 2.0.4, 50,918 bytes |
| HTMX SSE extension | same TU | `kSseJs` | https://unpkg.com/htmx-ext-sse@2.2.2/sse.js | 2.2.2, 8,897 bytes |
| Apache ECharts | `server/core/vendor/echarts.min.js` | `kEChartsJs` | unpkg.com/echarts/dist/echarts.min.js | 5.6.0, 1,034,102 bytes |
| IBM Plex Sans webfont (400, 500, 600) | `server/core/vendor/ibm-plex/ibm-plex-sans-latin-{400,500,600}-normal.woff2` | `kIbmPlexSans{400,500,600}Woff2` | https://www.npmjs.com/package/@ibm/plex-sans (IBM's own prebuilt `fonts/split/woff2/IBMPlexSans-{Regular,Medium,SemiBold}-Latin1.woff2`, vendored byte-identical; never re-subset: OFL Reserved Font Name "Plex") | 1.1.0, 20,984 / 21,960 / 22,260 bytes |
| IBM Plex Mono webfont (400, 500) | `server/core/vendor/ibm-plex/ibm-plex-mono-latin-{400,500}-normal.woff2` | `kIbmPlexMono{400,500}Woff2` | https://www.npmjs.com/package/@ibm/plex-mono (IBM's own prebuilt `fonts/split/woff2/IBMPlexMono-{Regular,Medium}-Latin1.woff2`, same rule) | 2.5.0, 17,544 / 17,868 bytes |
| Three.js (ES module) | `server/core/vendor/three.module.min.js` | `kThreeJs` | https://unpkg.com/three@0.168.0/build/three.module.min.js | r168, 685,408 bytes |
| Three.js OrbitControls | `server/core/vendor/three-orbit-controls.js` | `kThreeOrbitJs` | https://unpkg.com/three@0.168.0/examples/jsm/controls/OrbitControls.js | r168, 32,134 bytes |
| Yuzu chart adapter | `server/core/src/charts_js_bundle.cpp` (hand-written) | `kYuzuChartsJs` | first-party | n/a |
| Yuzu fleet renderer | `yuzu_viz_js_bundle.cpp` (generated at build time from `server/core/static/yuzu-viz.js`) | `kYuzuVizJs` | first-party | n/a |
| Yuzu access page glue | `yuzu_access_js_bundle.cpp` (generated at build time from `server/core/static/yuzu-access.js`) | `kYuzuAccessJs` | first-party | n/a |
| Yuzu tokens page glue | `yuzu_tokens_js_bundle.cpp` (generated at build time from `server/core/static/yuzu-tokens.js`) | `kYuzuTokensJs` | first-party | n/a |
| Yuzu groups page glue | `yuzu_groups_js_bundle.cpp` (generated at build time from `server/core/static/yuzu-groups.js`) | `kYuzuGroupsJs` | first-party | n/a |

### Refresh procedure (vendored vendor JS only)

For HTMX / ECharts / Three.js / OrbitControls — anything we did NOT author:

1. Download the new file from the upstream `unpkg.com/<pkg>@<version>/...` URL into the matching `server/core/vendor/` path. Keep the same filename.
2. Update the corresponding NOTICE file at `server/core/vendor/<pkg>-NOTICE.txt` if the upstream license header changed.
3. Update the top-level `NOTICE` row if the version naming changed.
4. Update `tests/unit/server/test_static_js_bundle.cpp`:
   - Bump the byte-count constant (`kExpectedFooBytes`).
   - Bump the version-token canary if upstream changed it (e.g. for Three.js, the bundle exposes `REVISION = "<n>"` once — pin the quoted form per gov R4 QA-B1).
5. Build with `meson compile -C build-{linux,macos,windows}`. The `embed_js.py` chunking + DELIM-collision check runs at build time; a refresh that smuggles in the close-delimiter token `)ECHARTSEMBED"` fails build cleanly.
6. Run `yuzu_server_tests "[static-js]"` to confirm pinned invariants pass.
7. Commit with a `chore(deps): bump <pkg> to <version>` message and reference the upstream changelog.

For Three.js specifically: r150+ is ES-module-only upstream. The OrbitControls module's top-level `import { ... } from 'three'` MUST resolve through the importmap declared in `viz_page_ui.cpp`. A refresh that splits OrbitControls into multiple files (e.g. PR-bundled with TransformControls) requires extending the importmap in lockstep. The `[viz][page]` test pins `from 'three'` and `class OrbitControls` substrings in the vendored file as a refresh canary.

For the IBM Plex fonts: a binary `.woff2` refresh follows the same pattern but uses `embed_binary.py`, not `embed_js.py`, and one custom target per file in `server/core/meson.build` (`plex_fonts`). Take IBM's own prebuilt files as-is from the `@ibm/plex-sans` and `@ibm/plex-mono` npm packages (`npm pack @ibm/plex-sans@<version> @ibm/plex-mono@<version>`, extract into a scratch directory, never run anything from it) — never subset, convert or otherwise modify them (the OFL Reserved Font Name "Plex" forbids a modified version under that name), and do not substitute Fontsource or Google Fonts builds. Each served face is the `Latin1` file of IBM's split build (`package/fonts/split/woff2/IBMPlex{Sans,Mono}-{Regular,Medium,SemiBold}-Latin1.woff2`) copied byte-for-byte to the served file name in the table above, so routes and `yuzu.css` do not change. IBM's other subsets (`Latin2`, `Latin3`, `Pi`, Greek, Cyrillic) are not vendored; a character outside the Latin1 file falls back to the next family in the stack, and the Latin1 file does not cover the arrows (`Pi`). Keep `server/core/vendor/ibm-plex/LICENSE.txt` equal to the packages' `LICENSE.txt` (line endings are normalised to LF by `.gitattributes`). On a refresh, update four things together: the per-weight byte counts in `test_static_js_bundle.cpp` (`kExpectedPlex`); the package versions, tarball integrity, package paths and SHA-256 lines in `server/core/vendor/ibm-plex/ibm-plex-NOTICE.txt` (`shasum -a 256 server/core/vendor/ibm-plex/*.woff2`); the version and byte-count columns in the two table rows above; and, if a refresh changes which characters the product's UI strings need, re-compare the files' `cmap` tables against the characters the UI uses.

### Why these aren't in Dependabot

These are flat vendored files embedded into the server binary at build time — there is no `package.json` describing them, so Dependabot's npm ecosystem has nothing to parse. (The repo's actual npm-managed directories — `site/`, `tests/puppeteer/`, `deploy/docker/cedar-vale/app/` — **are** Dependabot-tracked; see "npm tooling" above.) The cost of a manual quarterly review against the pinned byte counts is small relative to the cost of converting the embedded-JS flow to an npm toolchain just for staleness tracking. If the vendored JS surface grows past 8–10 packages, reconsider.

## Staleness query — "what's the oldest pinned dep?"

- **Dependabot-tracked** (`github-actions`, `docker`, `pip`, `npm`) — open the
  "Dependency updates" tab on the GitHub UI, or
  `gh pr list --label dependencies --state open`. An open Dependabot PR
  with an old `createdAt` is the staleness signal; merge latency is
  visible directly.
- **vcpkg** — the scheduled workflow either finds a new HEAD (PR opens)
  or it doesn't. If a PR from `.github/workflows/vcpkg-baseline-update.yml`
  is open and older than a week, that's the staleness signal. Additionally,
  the pinned SHA's age can be measured directly:
  `git -C /tmp/vcpkg show -s --format='%ci' <sha>` after a
  `git clone --bare https://github.com/microsoft/vcpkg.git /tmp/vcpkg`.
- **rebar3** — the manual quarterly review is the staleness check.
  If the last commit touching `gateway/rebar.config` is more than 90
  days old, the review is overdue.

## CODEOWNERS auto-assignment

Dependabot can auto-assign PR reviewers via CODEOWNERS. This requires
`.github/CODEOWNERS` to exist, which is tracked in #366 (currently
blocked). Once #366 lands, add `codeowners: true`-style routing to the
dependabot entries so dependency PRs automatically ping the right
reviewer group.
