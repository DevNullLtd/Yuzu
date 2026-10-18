# Docs drift gate

A change that alters what the product does should change the documentation that
describes it, before the change reaches a pull request. This gate enforces that in
two layers, both implemented by `scripts/ci/check-docs-drift.py`.

| Layer | What it checks | Failure is | Escape hatch |
|---|---|---|---|
| **Fact parity** | Named facts in the code appear in the user manual | A hard block | None, apart from the by-name baseline of known gaps, which only shrinks |
| **Touch rule** | Coupled code changed → a coupled doc changed | A failing check, advisory in CI until the repository owner adds `Doc-coupling touch rule` to the required checks; the PR hook enforces it for sessions that load the hook | `doc-coupling-exempt: <rule-id> — <reason>` in the PR body |

A third, semantic layer already exists and stays advisory: the `docs-writer`
governance agent reads the diff for meaning at governance Gate 2. Neither mechanical layer can
tell whether a paragraph is still *true*, so the two layers here are a floor, not a
replacement for that review.

## Layer 1: fact parity

| Category | Code side | Doc side |
|---|---|---|
| `rest_undocumented` | every `/api/vN/` route registration (not `OPTIONS`) | a heading `` #### `METHOD /api/vN/...` `` in `docs/user-manual/rest-api.md` |
| `rest_stale` | — | every such heading names a route that still exists |
| `mcp_undocumented` | every `kTools[]` entry in `mcp_server.cpp` | the backticked tool name in `docs/user-manual/mcp.md` |
| `flag_undocumented` | every `--flag` named in a CLI11 `add_option`/`add_flag` call in `FLAG_SOURCES`, as a literal or a `k*` string constant defined in a header under `server/core/src` or `agents/core/src` | the flag anywhere under `docs/user-manual/` |

Route and tool extraction is shared with `scripts/ci/check-api-parity.py`, never
re-implemented, so the two gates can't disagree about the route or tool table.
Path parameters are keyed alike in every style (`{id}`, `<id>`, `:id`, a regex
capture group). A heading may name several methods: `` `GET`/`DELETE /api/v1/x` ``.

It is a **lexical tripwire, not a proof**: a route registered through a non-literal
path, or a flag whose name is built at runtime, is invisible to it, exactly as it is to
`check-api-parity.py`. A new options header must be added to `FLAG_SOURCES`: the
self-test fails if any file under `server/core/src` or `agents/core/src` calls
`add_option`/`add_flag` and isn't listed, and the gate fails closed if a listed file
yields no flags.

A broken extractor would read as "nothing undocumented", so the gate **fails closed**
when it extracts fewer routes, tools or flags than `MIN_EXTRACTED` (about half of
today's counts). If that fires, fix the extractor; don't lower the floor.

### The ratchet

`scripts/ci/docs-drift-baseline.json` lists today's known gaps **by name**:

- a gap not in the baseline fails: that's new drift;
- a baseline entry that is no longer a gap also fails (reported as `stale`), so you
  must delete it in the same change, and the file only ever shrinks;
- a named set, not a count, means fixing one old gap can't hide a new one.

`--update-baseline` (alias `--write-baseline`) regenerates the file but refuses to
**add** entries unless passed `--allow-growth`. Growing the baseline needs a reason
in the PR description; the expected answer to new drift is to write the docs, and a growth PR should cite the
issue that tracks documenting the new entries.

**Known limit: two PRs can each pass and still break `dev` together.** The ratchet
requires an exact match, so two PRs that each pass against `dev` can, once both merge,
leave a stale entry or a heading for a deleted route. Git merges two identical line
deletions cleanly, so nothing conflicts. The fix is a one-line follow-up. Requiring
branches to be up to date before merge, or a merge queue, prevents it; both are
branch-protection settings. The other by-name ratchets (personal data, definition
descriptions) share this limit.

### When `dev` is red from drift

1. Run `python3 -I scripts/ci/check-docs-drift.py` on `dev` and read the names it
   prints.
2. A `rest_stale` heading for a deleted route: delete or correct that heading.
3. A `new` gap: document it (or, with an issue reference in the PR description,
   accept it into the baseline with `--update-baseline --allow-growth`).
4. A `stale` entry: run `python3 -I scripts/ci/check-docs-drift.py --update-baseline`.
   Removing entries needs no `--allow-growth`, but do steps 2 and 3 first:
   `--update-baseline` refuses to write anything while any `new` gap remains.
5. Open the fix as a small PR of its own.

If the gate itself misbehaves, for example an extraction floor trips after a
refactor, fix the extractor in the same way and don't lower the floor. There is
no switch to turn the check off: it runs inside the required job, and disabling it
means a reviewed change to `docs-lint.yml` like any other.

### Open PRs when this lands

CI checks a pull request's merge with its base branch, not the branch alone, so open PRs get
the gate on their next run without a rebase. A PR that adds an undocumented route,
tool or flag goes red until the docs are added. A PR that happens to document a
baseline gap must also delete that baseline line. The PR hook, by contrast, does
nothing on a branch that predates the gate until it is rebased.

## Layer 2: the touch rule

`scripts/ci/doc-coupling.json` maps code globs to the docs that describe them. When a
PR changes a file that a rule's `code` matches, at least one of the rule's `docs` must
change too, or the PR body must carry a line for that rule:

```
doc-coupling-exempt: devices — internal refactor, no behaviour change
```

- **One line per unmet rule.** An exemption satisfies only the rule it names. An
  exemption naming an unknown rule is ignored, with a note in the job log.
- **The separator** may be an em dash or ` - `, and the reason must be at least three
  characters.
- **The line must render as plain text.** It may be a bullet. A line inside a fenced
  code block, an HTML comment or raw HTML doesn't count; that includes anything from a
  line opening an HTML block to the next blank line, and a multi-line tag attribute.
- **The evidence record** of an exemption is the PR body at merge time and the job's
  log, which lists each exemption the job honoured. Actions logs
  expire (90 days by default), so the merged PR body is the durable copy.
- **Editing the body re-runs the check.** The job lives in its own workflow,
  `doc-coupling.yml`, which also triggers on `edited`, so adding an exemption doesn't
  need a new push.
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
| `doc-coupling.yml` → `doc-coupling-touch-rule` job | touch rule, pull requests only, re-run when the body is edited; advisory until made a required check |
| meson `docs` suite | `docs drift gate`, `docs drift gate self-test` |
| Claude Code `PreToolUse` hook (`scripts/hooks/docs-drift-pr-guard.py`) | both layers, when a Bash call runs `gh pr create` in command position; it reads `--base` and the body from `--body`/`--body-file`, and fails open on any error. PRs opened another way (the GitHub UI, the API, an MCP tool) rely on CI |

**The hook's trust boundary.** The hook always runs the gate from `$CLAUDE_PROJECT_DIR`,
the tree whose `.claude/settings.json` enabled it. The tree the command runs in, often a
worktree, is passed as `--root` and read as data only. The script also loads
`check-api-parity.py` from its own directory, never from `--root`. A session can sit in
a checkout of an untrusted branch, such as a fork PR under review, and executing that
tree's copy of the script would run its author's code with your credentials. If the
project tree predates the gate, the hook does nothing. Reading the tree as data is bounded too:
every file must be a regular file inside the tree and at most 16 MB (a symlink to a
device or outside the tree fails the run), every git call disables the tree's
`core.fsmonitor`, and names quoted back from the tree are cleaned, capped and labelled
as data in the hook's deny message.

Local commands:

```bash
python3 -I scripts/ci/check-docs-drift.py              # fact parity + manifest self-check
python3 -I scripts/ci/check-docs-drift.py --list       # every current gap: the doc-fixing worklist
python3 -I scripts/ci/check-docs-drift.py --touch origin/dev HEAD pr-body.md
python3 -I scripts/ci/check-docs-drift.py --root ../other-worktree   # check another tree, as data
python3 -I tests/test_docs_drift_selftest.py
```

## Extending it

A new fact category belongs in this script, not in a sibling script. Add an
extractor, a `CATEGORIES` entry, a `FIX_HINT`, its baseline key and self-test cases.
Candidates not yet covered: Prometheus metric names against `docs/user-manual/metrics.md`,
audit verbs against `audit-log.md`, RBAC securables (partly covered by
`tests/test_rbac_doc_counts.py`), and the legacy unversioned `/api/` routes.

Known gap in a sibling gate: the plugin README touch rule's bash parser
(`scripts/ci/check-plugin-readme-touch.sh`) still honours a `docs-unchanged:` line
inside raw HTML, its job still lives in `docs-lint.yml` without `edited`, and it diffs
the payload's `base.sha`, which goes stale once `dev` advances. This gate
closes all three for itself; the sibling is tracked separately.
