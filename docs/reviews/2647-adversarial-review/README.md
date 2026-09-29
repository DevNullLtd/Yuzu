# Adversarial review record — PR #2647

The two-phase adversarial review (Claude subagent + Codex/gpt-5.6, disk-barrier protocol,
`.claude/skills/adversarial-review/`) run on `cb69991f..3cc9f417` before PR #2647 was opened.
`SYNTHESIS.md` is the orchestrator's merged verdict; the four `*.phaseN.md` files are each
reviewer's own output, verbatim. Committed so the ledger's `ADV-1`/`ADV-2` rows have a
`reporter_ref` that is retrievable and version-historied rather than pointing at the PR body,
which the author can edit in place.
