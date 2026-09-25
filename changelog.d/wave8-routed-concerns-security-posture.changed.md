- Added a third routed-concerns table, `.claude/routed-concerns-security-posture.md`, for the read-only
  security-posture plugins, and registered it everywhere the tables are listed: the `CLAUDE.md`
  `@`-import, `AGENTS.md`, the instruction-file budget and dead-pointer lint (`tests/test_issue_docs.py`,
  `docs/instruction-file-standard.md`), the governance skill and the docs-writer agent. To pay for the
  added always-loaded text, the `execution_artifacts` row of `.claude/routed-concerns.md` is condensed to
  its four invariants and the full wording moved, unchanged, to `docs/execution-artifacts-invariants.md`.
