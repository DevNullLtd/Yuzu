# Adversarial review target

Range: cb69991f..3cc9f417 (11 commits incl. a merge of origin/dev reconciling a parallel Gate 7/8 evolution from the #2581 workstream, branch docs/governance-followups-2619-2620)
Repo (worktree): /home/fraser/Yuzu/.claude/worktrees/gov-followups-2619-2620
Doc-only change: closes #2619 (governance findings-ledger provenance: reporter/source/reporter_ref/reviewed_at_sha/recorded_at, refuted disposition, supersede-never-edit write contract, de-escalation guard, row-scoped attestations) and #2620 (prose-ownership split stated where agents read it; missing-required-doc is a truth finding; "required" is a closed six-item list).
Files: .claude/skills/governance/SKILL.md, CLAUDE.md, .claude/agents/docs-writer.md, governance.d/README.md, governance.d/2619-*.jsonl (the first ledger fragment, 62 rows), changelog.d/2619-*.md, docs/governance-skill-tuning-2026-07.md.
History note: the branch went through 9 internal Gate 8 rounds; rounds 2-8 each shipped a blocking defect of their own, all recorded in the ledger fragment and narrated in the tuning doc. The final round deliberately stopped at minimal fixes; structural follow-ups (single contract file, committed validator, Gate 8 convergence rule) are out of scope by operator decision.

## Anchors (authoritative ground truth)
- anchor-issue-2619.md and anchor-issue-2620.md in this dir (the acceptance criteria this change claims to close)
- CLAUDE.md as it stands ON origin/dev (git show origin/dev:CLAUDE.md) — standing-rules block, 40k-per-file ceiling, doc-layering heuristic ("stable reference material belongs in docs/ with a pointer")
- changelog.d/README.md (fragment convention; CHANGELOG.md is frozen)
- .claude/routed-concerns.md (unchanged by this diff; the prose rule routes normative-architecture truth to architect)
