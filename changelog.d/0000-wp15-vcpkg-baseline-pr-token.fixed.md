- **The monthly vcpkg baseline bump can open its PR again, and no longer fails
  silently.** `vcpkg-baseline-update.yml` opened no PR from May to November 2026:
  from June every scheduled run failed at "Create pull request", because the
  bump edits `.github/workflows/*.yml` and GitHub refuses a push that changes a
  workflow file from `GITHUB_TOKEN`, which cannot hold the `workflows`
  permission (May's run failed earlier, in job setup). The PR is now opened with
  an installation token of a GitHub App owned by the organisation and installed
  on this repository only, minted on each run and scoped to this repository
  with Contents, Pull requests and Workflows write, which also lets CI run on
  it. The App's client ID (variable `VCPKG_BASELINE_APP_CLIENT_ID`) and private
  key (secret `VCPKG_BASELINE_APP_PRIVATE_KEY`) are stored in the
  `vcpkg-baseline` environment, which the repository owner creates with `main`
  as its only deployment branch, so only `main` can use them; a dispatch of the
  workflow from any branch but `main` therefore fails at job start. The PR is
  authored by the App's bot account, and the bump commit names that bot as its
  author and committer, so the bot must be on `cla.yml`'s allowlist; otherwise
  the CLA check fails on every bump PR while the bump run stays green. The PR
  targets `dev`, and each month's bump updates the one open bump PR instead of
  opening another. Because the PR builds an unreviewed upstream vcpkg revision,
  `ci.yml` keeps its self-hosted legs off it, and `Preflight (runner health)`
  red, until a maintainer with write access who is not the PR's author, did
  not push its head and is not the author or committer of any of its commits
  has approved the PR at the exact head the CI run builds; a new push needs a
  new approval. A run refuses to push onto an open bump PR that another account
  than the App's bot opened. A run without the client ID or the key fails at
  its first step with an error naming what is missing, one whose App GitHub
  will not mint a token for fails at the next, and a run whose PR the approval
  gate could never pass (a commit linked to no account, 250 or more commits,
  or a PR or commit not the bot's) fails too; any failure opens or comments on
  a `vcpkg-baseline-broken` issue, which only a green run of `main`'s copy that
  pushed a new bump closes.
