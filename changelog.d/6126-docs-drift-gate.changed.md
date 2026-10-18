- **CI: docs drift gate.** A new REST route, MCP tool or CLI flag must now be documented in the user manual
  before merge (today's known gaps are frozen by name in
  `scripts/ci/docs-drift-baseline.json`, which only shrinks). A PR that changes code covered by
  `scripts/ci/doc-coupling.json` must also change one of its coupled docs, or state
  `doc-coupling-exempt: <rule-id> — <reason>` in the PR body; that check is advisory until it is made a
  required check. A Claude Code hook runs both checks before `gh pr create`. See
  `docs/docs-drift-gate.md`.
