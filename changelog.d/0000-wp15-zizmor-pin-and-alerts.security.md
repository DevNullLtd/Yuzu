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
  and the release tag.** `docs/user-manual/release-verification.md` and
  `docs/agent-bundle.md` previously checked only `--repo`, which accepts a
  provenance attestation minted by any workflow run in the repository. Every
  `gh attestation verify` command in them (the online, offline and image
  checks and the end-to-end script) now also passes
  `--signer-workflow <repo>/.github/workflows/release.yml` and
  `--source-ref refs/tags/<tag>`, and so does the best-effort check in
  `scripts/build-agent-bundle.sh`. These pins need GitHub CLI 2.102.0 or later:
  older versions match `--signer-workflow` by prefix and `--source-ref`
  case-insensitively, and before 2.68.0 have no `--source-ref`. The page now
  states that minimum and points Linux users at GitHub's own `gh` packages
  instead of the distribution's. The old offline example, which passed `-o`
  (an owner flag) as if it named an output file and omitted `--repo`, is
  replaced.
  **If you verify releases:** use GitHub CLI 2.102.0 or later. The page's
  end-to-end verification script now exits 1 on an older or unrecognised
  `gh` version instead of running the attestation check.
- **`CLA_REPO_ACCESS_TOKEN` now lives in the `cla` environment.** The CLA
  workflow's job declares that environment, which only the default branch may
  use.
