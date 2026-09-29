# Architecture Decision Records

Accepted decisions live here as one file per decision. This README covers **how ADRs are numbered** — a convention that was previously unwritten and drifted as a result (issue #2736).

## Numbering is author-namespaced

Each regular author owns a thousand-block. Pick the next free number **inside your own block**.

| Block | Owner |
|---|---|
| `0xxx` | Nathan Dornbrook / platform |
| `1xxx` | Dave Rae |
| `2xxx` | Fraser Jarvis (@fjarvis) |
| `3xxx` | Alex Young (@Doomgoose) |
| `4xxx` | Andy Younie (@lesault) |

Not on the list? Use `0xxx` (platform) or ask for a block.

This is why ADR-0022 was renumbered to **ADR-1005** — it is Dave Rae's, and 0022 sat in the platform block.

### Picking your next number

```bash
ls docs/adr/ | grep -oE '^[0-9]{4}' | sort -n | tail -20   # what's taken
```

Take the next free number in your block. Filename is `<number>-<kebab-slug>.md`. **Record the author** in the frontmatter (`owner:`) or a `**Authors:**` line — without it nobody can tell which block an ADR belongs to. Older ADRs are inconsistent about which of the two forms they use; either is fine, but one of them is required.

## The convention binds prospectively

It was adopted **after** most `0xxx` ADRs were written, so the low block is mixed: roughly 21 ADRs sit in `0xxx` that belong to a namespaced author (10 @lesault, 7 Dave Rae, 4 Alex Young).

**Those are not errors and are deliberately not being renumbered.** They predate the rule, and renumbering them would churn thousands of inbound references across `CLAUDE.md`, `AGENTS.md`, `CONTEXT.md`, `docs/`, and code comments — several through routed-concern rows carrying catastrophic-if-violated invariants. Leave them where they are.

New ADRs follow the table above.

## Known number collisions

Two numbers currently host **two accepted ADRs each**. Renumbering is deferred for the reference-churn reason above, so until then a bare number is ambiguous — **cite these by filename, never by number alone**:

| Number | Files sharing it |
|---|---|
| `0016` | `0016-agent-daily-sync-framework.md` (Dave Rae) · `0016-live-only-demos.md` (Nathan) |
| `0031` | `0031-engine-principal-store.md` (platform) · `0031-presentation-core-engine-decomposition.md` (Dave Rae) |

Disambiguation for the two that appear in routed-concern rows:

- **"ADR-0016"** in `CLAUDE.md` / `AGENTS.md` routed concerns means the **agent daily-sync framework** (installed-software inventory).
- **"ADR-0031"** is used with *both* meanings — the engine-principal store in the auth/RBAC row, and the presentation/core/engine decomposition in the headless-platform row. Read the surrounding row to tell which.

Tracked in issue #2736.

## Related

- `docs/agents/domain.md` — how ADRs fit the wider domain-doc set
- `CONTEXT.md` — domain language and bounded contexts
