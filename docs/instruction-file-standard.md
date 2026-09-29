# Instruction-file standard

How to decide **where a rule belongs** — and why the answer is usually "not in CLAUDE.md".

## Why this exists

Six files load into every agent session before any work starts:

| File | Read by | Budget | Hard cap |
|---|---|---|---|
| `CLAUDE.md` | Claude | 40,000 | 48,000 |
| `AGENTS.md` | Codex, Kimi | 40,000 | 48,000 |
| `.claude/routed-concerns.md` | Claude (`@`-imported by CLAUDE.md) | 40,000 | 48,000 |
| `.claude/routed-concerns-access-control.md` | Claude (`@`-imported by CLAUDE.md) | 40,000 | 48,000 |
| `.claude/routed-concerns-security-posture.md` | Claude (`@`-imported by CLAUDE.md) | 40,000 | 48,000 |
| `.claude/routed-concerns-software-estate.md` | Claude (`@`-imported by CLAUDE.md) | 40,000 | 48,000 |

Every character in them is paid on every session, whether or not the work touches that subject. A
`docs/` file costs nothing until something reads it.

This ceiling has been hit four times. #2147 closed the first (44.6k → 23.1k, by moving the
routed-concerns table into an `@`-imported file). The second was found at **39,996 of 40,000 bytes —
four bytes free** — and split the table again. **Splitting is now exhausted: another file adds no
capacity, and the total context cost is unchanged by splitting anyway.** Two more splits landed
regardless, independently and around the same time: Wave 8 added `routed-concerns-security-posture.md`
(a third table file, so the security-posture plugin rows land there and `routed-concerns.md` gains
none) and Wave 10 P2a-3 added `routed-concerns-software-estate.md` (a fourth, for a Forensics/
per-user-software-data row that would not fit the remaining headroom either) — both stopgaps, not
new capacity. **A further split needs its own justification: each split buys headroom but leaves
the total context cost across all always-loaded files unchanged, so it is a deferral, not a fix,
and each new file is itself a fixed cost paid by every session.**

The failure was never a single bad commit. It was ~235 characters a day of individually reasonable
additions, each one cheaper to put in CLAUDE.md than to route properly.

## The default is no

Text enters an always-loaded file only if it fails every cheaper home below. These files are a
contents page; they are not where knowledge lives.

## The placement ladder

Take the **first** home that fits.

### 1. A hookify rule — if it is mechanically checkable at the moment of violation

`.claude/hookify.*.local.md`. Eight already exist: `vcvars64`, Windows Clang,
dropping `include_type: 'system'`, `rebar3 eunit --dir`, `sqlite3_changes()`, the CI
`save-always` guard, and both temp-path salt rules.

This is the **best** home for a "never do X" gotcha, because it fires when someone is about to do X
rather than hoping they read a file first. A rule with a hook needs at most one line elsewhere,
naming the hook.

### 2. A header comment or docstring at the site — if a reader only needs it once they open that file

`tests/unit/server/test_route_sink.hpp` and `tests/prometheus/run_promtool_tests.py` are the model:
both are **more precise** than the summaries that were kept of them, because the author was looking
at the code.

If the rule only matters to someone already editing that file, the file is the right place. An
always-loaded summary of a source header is pure cost — it is read by everyone and needed by almost
no one.

### 3. A `docs/` file plus a routed-concern row — if it is domain knowledge needed on some changes

The routed-concern row is the trigger ("when you touch these paths, read this doc"); the doc is the
content. This is the normal home for anything substantial.

### 4. A routed-concern row alone — only the catastrophic-if-violated invariant plus its pointer

A row states **what must never happen** and **where the detail is**. It is not the place for the
reasoning, the history, or the per-store comparison. The tables say this about themselves, and it is
the rule most often broken.

### 5. `CLAUDE.md` / `AGENTS.md` — last resort

Only if the rule is **cross-cutting**, **decision-grade**, and **needed before you know which files
you will touch.** That last clause is the actual test. If an agent only needs the rule once it has
opened a particular file, the rule belongs at that file (rung 2), not here.

## Rules that apply wherever the text lands

### One canonical home; every other mention is a pointer that loses on conflict

State it once. Everywhere else names the canonical location and defers. **A pointer must name its
target, and a target must not point back at its pointer** — a cycle means neither is canonical and
both will drift.

If you add a restatement anywhere, add it to the canonical file's enumerated list of copies in the
same change. A copy-currency rule only reaches the copies it enumerates: the two copies that drifted
in the governance rules were exactly the two the list had omitted.

### Pay-as-you-go

A PR that adds to an always-loaded file states the character delta in its body. **A net increase over
~500 characters needs an equivalent extraction in the same PR.** Trimming later never happens on its
own; the budget is only real if it is paid at the point of addition.

### Temporary sections carry a machine-readable expiry

```html
<!-- EXPIRES: 2026-10-01 owner:@username -->
```

CI fails once the date passes. Write the teardown step at the same time as the section.

The now-removed workstreams document (`docs/workstreams.md`, deleted in the same change that
wrote this standard) did the human half of this correctly — it declared a one-week
life *and* wrote its own teardown procedure naming the exact blocks to delete. It was still live four weeks past
expiry, and so were both pointer blocks, because nothing checked. Good intentions plus no check is
the same as no intention.

### No pointer to anything a collaborator cannot read

Never cite a personal memory file, a local-only path, or another machine's directory from a committed
file. Three such citations sat in CLAUDE.md pointing at a private memory directory; none of them
resolved even on the author's own machine.

## Anti-patterns, with the examples that produced this standard

| Anti-pattern | What it looked like here |
|---|---|
| An essay inside a table cell | One routed-concern cell reached **10,076 characters** — 26% of its file — holding seven numbered parts, per-store comparisons and reasoning history, in a table whose own rule says rows carry the invariant and a pointer |
| Restating a source header | ~88% of the test-conventions block duplicated `test_helpers.hpp`, `test_route_sink.hpp` and `run_promtool_tests.py` — all three more precise at the source |
| A temporary section with no enforced expiry | A workstreams block whose stated window had passed four weeks earlier, pointing at a `STREAM.md` that did not exist and a lock file that did not exist |
| A copy that outlives its subject | A skills paragraph describing an install command that no longer exists in the repo |
| Circular authority | A routed-concern row naming CLAUDE.md as its routed doc, duplicating the annotation it pointed at |

## Checks that enforce this

`tests/test_issue_docs.py`, run by `.github/workflows/docs-lint.yml` and the `docs` Meson suite:

1. **Budget** — each of the five files under 40,000 characters, and the 48,000 hard cap.
2. **Expiry** — no `EXPIRES:` date in the past.
3. **Dead pointers** — every backticked citation in the five files resolves: a path-shaped one
   (with a directory component) must exist exactly, and a bare filename must match some tracked
   file's name. `STREAM.md` was cited for months and existed nowhere.
4. **Routed-concern table structure** — every row has three populated columns, and no row's
   `Loaded by` column is a copy of its `Doc` column. A literal `|` inside a cell must be escaped as
   `\|`: an unescaped one shifts every column to its right, which is how one CATASTROPHIC row's
   agent list was silently overwritten while the table still looked well-formed. A row that names no
   review trigger defeats standing rule 1 — the matrix decides WHICH agents, never WHETHER.

Character counts are UTF-8-decoded in Python. `wc -c` reads high on these files (multi-byte
punctuation) and Windows `wc -m` disagrees again; the Python count is the one the budget means.
