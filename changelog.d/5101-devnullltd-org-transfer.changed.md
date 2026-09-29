- **Repository moved to the `DevNullLtd` organisation.** `Tr3kkR/Yuzu` is now
  `DevNullLtd/Yuzu`; GitHub redirects the old paths, so existing clones, links
  and `git remote`s keep working. Two changes need action from operators:
  published container images move to **`ghcr.io/devnullltd/yuzu-*`** (every
  tracked compose file, the Compose Wizard output and the release-verification
  commands now use that path), and the CLA gate — which silently skipped every
  pull request between the transfer and this change, because its guard still
  named the old repository — is live again. Alert `runbook_url` annotations,
  the `.deb` `Homepage:` field and `vcpkg.json`'s homepage all point at the new
  path.
