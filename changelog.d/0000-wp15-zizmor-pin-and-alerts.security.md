- **The workflow audit runs a pinned zizmor, and its open alerts are resolved.**
  `zizmor.yml` now runs zizmor 1.32.0 instead of `latest`, so a bump of the
  zizmor action no longer silently changes the auditor. `docs-site.yml` no longer
  leaves the checkout token in `.git/config` (artipacked), and the agent-bundle
  publish job in `release.yml` passes step outputs to the shell through `env`
  (template-injection). The reviewed triggers (`pull_request_target` and
  `issue_comment` in `cla.yml`, `workflow_run` in `pre-release.yml`), the archived
  CLA action and the local reusable-workflow call in `trusted-fork-ci.yml` carry
  inline ignores that state why each is accepted. The audit is still not a
  required check; that is a branch-protection setting.
- **The documented `gh attestation verify` commands now pin the signing workflow
  and the release tag.** `docs/user-manual/release-verification.md` previously
  checked only `--repo`, which accepts a provenance attestation minted by any
  workflow run in the repository. Each command now also passes
  `--signer-workflow <repo>/.github/workflows/release.yml` and
  `--source-ref refs/tags/<tag>`; use these when verifying a release.
