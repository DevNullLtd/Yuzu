- **The monthly vcpkg baseline bump can open its PR again, and no longer fails
  silently.** `vcpkg-baseline-update.yml` opened no PR from May to November 2026:
  from June every scheduled run failed at "Create pull request", because the
  bump edits `.github/workflows/*.yml` and GitHub refuses a push that changes a
  workflow file from `GITHUB_TOKEN`, which cannot hold the `workflows`
  permission (May's run failed earlier, in job setup). The PR is now opened with
  the repository secret `VCPKG_BASELINE_PR_TOKEN` (Contents, Pull requests and
  Workflows read/write on this repository), which also lets CI run on it. It
  targets `dev`, and each month's bump updates the one open bump PR instead of
  opening another. Because the PR builds an unreviewed upstream vcpkg revision,
  `ci.yml` keeps its self-hosted legs off it, and `Preflight (runner health)`
  red, until a maintainer has reviewed the upstream range and added the
  `vcpkg-bump-reviewed` label. A run without the secret fails at its first step
  with an error naming it, any failure opens or comments on a
  `vcpkg-baseline-broken` issue, and the next green run closes it. The secret
  does not exist yet, and the scheduled run picks up these changes only once
  they reach `main`.
