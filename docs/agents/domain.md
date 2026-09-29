# Domain Docs

Yuzu uses a single-context domain documentation layout.

## Read Before Work

- `CONTEXT.md` at the repo root for Yuzu glossary and domain boundaries.
- `docs/adr/` for architectural decisions relevant to the area being changed.
- Domain-specific docs referenced by `CODEX.md`, `CLAUDE.md`, or the local skill being used.

If a referenced context or ADR file is missing, proceed silently. The producer workflow `/grill-with-docs` creates domain docs lazily when terms or decisions are resolved.

## Layout

```text
/
+-- CONTEXT.md
+-- docs/
    +-- adr/
    +-- agents/
```

There is no `CONTEXT-MAP.md`; do not assume multiple contexts unless one is introduced later.

## Vocabulary Rule

Use the glossary terms from `CONTEXT.md` in issue titles, hypotheses, test names, plans, PR descriptions, and docs. If a term is missing, either choose an existing Yuzu term or flag it for `/grill-with-docs`.

## ADR Rule

ADRs live in `docs/adr/`. Create them only for decisions that are hard to reverse, surprising without context, and the result of a real trade-off.

## ADR Acceptance Convention

**Standing convention (@Tr3kkR, 2026-07-09):** an ADR merged to `dev` via a reviewed PR carries `status: accepted` — the merge itself is the acceptance event, not a separate post-merge sign-off step — unless the ADR's own frontmatter or Binding-status section records additional acceptance gates (e.g. ADR-1005's independent-review + tracking-issue requirement), which continue to govern regardless of when they were recorded. This supersedes any per-ADR named sign-off list recorded **before** this convention existed (e.g. platform-lead / security-architecture / data-licensing legs called for in ADR-0018/0023/0029's original text): the maintainer's review of the PR that lands (or flips) `status: accepted` stands as the recorded maintainer leg. It does **not** retroactively confirm any other named reviewer's sign-off — an ADR's Ratification section must flag honestly if a named leg besides the maintainer's is still open, and that open leg still governs until resolved. A named sign-off leg added to an ADR's Ratification section **after** 2026-07-09 is a deliberate choice to require more than the maintainer-merge leg, and is **not** waived by this convention — it governs until satisfied. The evidence artifact for the maintainer leg is GitHub's own PR-approval + merge metadata (branch-protection-enforced review, approver ≠ author) on the PR that lands the flip — not the ADR's prose alone; an ADR citing this convention should be verifiable against that PR's review history.
