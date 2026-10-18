# Docs drift gate

A change that alters what the product does should change the documentation that
describes it, before the change reaches a pull request. This gate enforces that in
two layers, both implemented by `scripts/ci/check-docs-drift.py`.

| Layer | What it checks | Failure is | Escape hatch |
|---|---|---|---|
| **Fact parity** | Named facts in the code appear in their owning doc | A hard block | None, apart from the by-name baseline of known gaps, which only shrinks |
| **Touch rule** | Coupled code changed → a coupled doc changed | A block | `doc-coupling-exempt: <rule-id> — <reason>` in the PR body |

A third, semantic layer already exists and stays advisory: the `docs-writer`
governance agent (Gate 2) reads the diff for meaning. Neither mechanical layer can
tell whether a paragraph is still *true*, so the two layers here are a floor, not a
replacement for that review.

## Layer 1: fact parity

| Category | Code side | Doc side |
|---|---|---|
| `rest_undocumented` | every `/api/vN/` route registration (not `OPTIONS`) | a heading `` #### `METHOD /api/vN/...` `` in `docs/user-manual/rest-api.md` |
| `rest_stale` | — | every such heading names a route that still exists |
| `mcp_undocumented` | every `kTools[]` entry in `mcp_server.cpp` | the backticked tool name in `docs/user-manual/mcp.md` |
| `flag_undocumented` | every `--flag` in a literal CLI11 `add_option`/`add_flag` name in `FLAG_SOURCES` | the flag anywhere under `docs/user-manual/` |

Route and tool extraction is shared with `scripts/ci/check-api-parity.py`, never
re-implemented, so the two gates can't disagree about the route or tool table.
Path parameters are keyed alike in every style (`{id}`, `<id>`, `:id`, a regex
capture group). A heading may name several methods: `` `GET`/`DELETE /api/v1/x` ``.

It is a **lexical tripwire, not a proof**: a route registered through a non-literal
path, or a flag whose name is not a string literal, is invisible to it, exactly as it
is to `check-api-parity.py`. A new options header must be added to `FLAG_SOURCES`, and
the self-test pins that tuple, so the change is a reviewed diff.

### The ratchet

`scripts/ci/docs-drift-baseline.json` lists today's known gaps **by name**:

- a gap not in the baseline fails: that's new drift;
- a baseline entry that is no longer a gap also fails, so you must delete it in the
  same change, and the file only ever shrinks;
- a named set, not a count, means fixing one old gap can't hide a new one.

`--write-baseline` regenerates the file but refuses to **add** entries unless passed
`--allow-growth`. Growing the baseline needs a reason in the PR description; the
expected answer to new drift is to write the docs.

## Layer 2: the touch rule

`scripts/ci/doc-coupling.json` maps code globs to the docs that describe them. When a
PR changes a file that a rule's `code` matches, at least one of the rule's `docs` must
change too, or the PR body must carry a line for that rule:

```
doc-coupling-exempt: devices — internal refactor, no behaviour change
```

- **One line per unmet rule.** An exemption satisfies only the rule it names.
- **The line must render.** It may be a bullet, but a line inside a fenced code block
  or an HTML comment doesn't count.
- **The keyword is deliberately not the plugin rule's `docs-unchanged:`.** That rule
  (`scripts/ci/check-plugin-readme-touch.sh`) treats any such line as a global
  override, so sharing the keyword would let one exemption silently pass both gates.
  `agents/plugins/*/src/**` belongs to the plugin rule, and the manifest self-check
  refuses any glob that reaches it.

This layer measures **co-change, not correctness**. It exists to make "the docs are
still right" a stated claim a reviewer can challenge, not a silent omission.

### Editing the manifest

Each rule has an `id` (kebab-case, used in exemption lines), a `why`, `code` globs and
`docs`. In a glob, `**` crosses `/`, `*` and `?` do not, and `{a,b}` alternates. The
fact-parity run self-checks the manifest on every PR: ids must be unique, every glob
must match a tracked file (no dead rules), and every listed doc must exist. Prefer
fewer, high-signal rules. A rule that fires on most internal refactors teaches people
to paste exemptions without thinking. That is why `gateway/**` is not in the seed set.

## Where it runs

| Where | What |
|---|---|
| `docs-lint.yml` → `changelog-order` job (required) | fact parity + self-test, every PR and every push to dev/main |
| `docs-lint.yml` → `doc-coupling-touch-rule` job | touch rule, pull requests only (the exemption lives in the body) |
| meson `docs` suite | `docs drift gate`, `docs drift gate self-test` |
| Claude Code `PreToolUse` hook (`scripts/hooks/docs-drift-pr-guard.py`) | both layers, before `gh pr create` runs; it reads `--base` and the body from `--body`/`--body-file`, and fails open on any error |

Local commands:

```bash
python3 -I scripts/ci/check-docs-drift.py              # fact parity + manifest self-check
python3 -I scripts/ci/check-docs-drift.py --list       # every current gap: the doc-fixing worklist
python3 -I scripts/ci/check-docs-drift.py --touch origin/dev HEAD pr-body.md
python3 -I tests/test_docs_drift_selftest.py
```

## Extending it

A new fact category belongs in this script, not in a sibling script. Add an
extractor, a `CATEGORIES` entry, a `FIX_HINT`, its baseline key and self-test cases.
Candidates not yet covered: Prometheus metric names against `docs/user-manual/metrics.md`,
audit verbs against `audit-log.md`, RBAC securables (partly covered by
`tests/test_rbac_doc_counts.py`), and the legacy unversioned `/api/` routes.
