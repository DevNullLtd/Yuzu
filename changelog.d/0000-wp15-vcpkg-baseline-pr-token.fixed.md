- **The monthly vcpkg baseline bump can open its PR again, and no longer fails
  silently.** `vcpkg-baseline-update.yml` failed at "Create pull request" on every
  scheduled run from May to November 2026 and never opened a PR: the bump edits
  `.github/workflows/*.yml`, and GitHub refuses a push that changes a workflow
  file from `GITHUB_TOKEN`, which cannot hold the `workflows` permission. The PR
  is now opened with the repository secret `VCPKG_BASELINE_PR_TOKEN` (Contents,
  Pull requests and Workflows read/write on this repository), which also lets CI
  run on the PR. A run without the secret fails before the bump with an error
  naming it, and any failure opens or comments on a `vcpkg-baseline-broken` issue
  (S10).
