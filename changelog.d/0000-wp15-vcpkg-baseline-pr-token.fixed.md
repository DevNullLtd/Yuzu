- **The monthly vcpkg baseline bump can open its PR again, and no longer fails
  silently.** `vcpkg-baseline-update.yml` opened no PR from May to November 2026:
  from June every scheduled run failed at "Create pull request", because the
  bump edits `.github/workflows/*.yml` and GitHub refuses a push that changes a
  workflow file from `GITHUB_TOKEN`, which cannot hold the `workflows`
  permission (May's run failed earlier, in job setup). The PR is now opened with
  the secret `VCPKG_BASELINE_PR_TOKEN` (Contents, Pull requests and Workflows
  read/write on this repository), which also lets CI run on it. The
  `vcpkg-baseline` environment is required: the job that uses the token runs
  in it, the repository owner creates it with `main` as its only deployment
  branch, and the secret is stored there, not as a repository secret, so only
  `main` can read it. A dispatch of the workflow from any branch but `main`
  therefore fails at job start. The bump commit names the token's owner as its
  author and committer, so that account must be covered by the CLA (signed,
  or on `cla.yml`'s allowlist); otherwise the CLA check fails on every bump PR
  while the bump run stays green. The PR
  targets `dev`, and each month's bump updates the one open bump PR instead of
  opening another. Because the PR builds an unreviewed upstream vcpkg revision,
  `ci.yml` keeps its self-hosted legs off it, and `Preflight (runner health)`
  red, until a maintainer with write access who is not the PR's author, did
  not push its head and is not the author or committer of any of its commits
  has approved the PR at the exact head the CI run builds; a new push needs a
  new approval. A run whose token now belongs to another account than the
  open bump PR's author refuses to push onto it. A run without the secret, or
  with a token GitHub rejects, fails at its first step with an error naming
  it, and a run whose PR the approval gate could never pass (a commit linked
  to no account, 250 or more commits, or a PR or commit not the token owner's)
  fails too; any
  failure opens or comments on a `vcpkg-baseline-broken` issue, which only a
  green run of `main`'s copy that pushed a new bump closes.
