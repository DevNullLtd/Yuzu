# scripts/tracker/ — issue-tracker automation (ADR-3001)

Tooling for the issue-lifecycle guardrails programme
(`docs/adr/3001-issue-lifecycle-guardrails.md`, as amended by A1). Distinct
from `scripts/issues/`, which holds static issue *bodies* for the historical
one-shot `create_issues.sh` backfill.

| File | Owner PR | Purpose |
|---|---|---|
| `closing_refs.py` | PR 2 | **The** closing-keyword parser — the only implementation. Imported by the workflow, the backfill, the undo path, the leak scan, and the test corpus. Grammar: GitHub's closing keywords + chains (separators: comma, `and`, `&`, bare whitespace — `Closes #10 #11` closes both, where GitHub would close only #10), with code-fence/quote/comment stripping and negation suppression (`--selftest` runs the embedded cases). |
| `close_linked_issues.py` | PR 2 | The driver behind `.github/workflows/close-linked-issues.yml`: `--push` (workflow), `--backfill` (one-time #2139 sweep; the dry run writes a `--plan` snapshot, and `--execute` needs `--yes-i-reviewed` + the same `--plan` (aborts on drift — PR bodies are editable post-merge) + a verified `--approval-url` on #2139; security-labelled candidates are EXCLUDED — reviewed in the diff, never mutated), `--undo-push` (reopen an exact prior batch), `--leak-scan` (completeness backstop). Always dry-run unless `--execute`. **Fails closed** if `do-not-close.txt` is missing or unparseable. |
| `do-not-close.txt` | PR 1 (#2168) | The committed never-close list — issue numbers no automation may ever close (issue-standard.md §5.1). Number-keyed because labels have been wrong before. Only a reviewed PR changes it; the `do-not-close` *label* is the maintainer's instant, no-PR marker (union semantics). |
| `bootstrap-labels.sh` | PR 1 (#2168) | Idempotent creation of the six automation labels. Run at PR-1 merge, before the first agent filing. |

Never-close ladder, order load-bearing (see `close_linked_issues.py`):
cap → 404 → self-ref → not-an-issue(PR) → not-open → marker-idempotent →
`security` → `do-not-close` (label ∪ file) → assigned → open linked PR →
close as `completed` (state change first, then the evidence comment) with a
self-identifying evidence comment. The `do-not-close` **label** is the
zero-latency protection: apply it under incident pressure, PR the file after.

**Merge order (hard requirement):** #2168 (the never-close list) merges FIRST.
Merging this workflow early is loud, not silent — it runs on its own
introducing push, exits 3, and opens an `automation-broken` issue per push
until the list lands; recover skipped ranges by re-running those runs.

## Recovery

- **Find BEFORE/AFTER for a past run:** the close step's `env:` block in that
  run's log, or the alert issue's **Range** line.
- **Exit codes:** 1 = leaks found (leak scan) · 2 = backfill authorization
  missing (`--yes-i-reviewed`/`--plan`/`--approval-url`) · 3 = fail-closed
  (never-close list missing/unparseable, API error, truncated range) ·
  4 = safety assertion (security-labelled issue in a mutating action, or
  backfill plan drift) — always zero mutations.
- **Wrong close, single issue:** reopen + add `do-not-close` label (automation
  never touches it again). **Wrong batch:** `--undo-push BEFORE AFTER`
  (marker-verified, reopens only what this automation closed). Note undo can
  reopen an issue a human deliberately re-closed after an automation close —
  it is a manual, dry-run-default tool; read its dry-run first.

**Standing constraint:** no workflow may relay user-supplied text as a
`github-actions[bot]` comment — bot comments are marker-trusted for
idempotency, so a workflow that echoes user text would become a
marker-forgery oracle.

## Re-validating the grammar against GitHub's oracle

The parser was acceptance-tested against GitHub's own closing-reference
resolution over every merged main-base PR (where `closingIssuesReferences` IS
populated — it is empty for dev-base PRs, the whole reason this tooling
exists). Re-run after any grammar change; zero false negatives is the bar,
and the only acceptable supersets are keyword chains and already-closed refs:

```bash
gh api graphql --paginate -f query='
query($endCursor: String) {
  repository(owner: "Tr3kkR", name: "Yuzu") {
    pullRequests(baseRefName: "main", states: MERGED, first: 50, after: $endCursor) {
      pageInfo { hasNextPage endCursor }
      nodes { number body closingIssuesReferences(first: 20) { nodes { number } } }
    }
  }
}' --jq '.data.repository.pullRequests.nodes[] | {n: .number, body: .body, oracle: [.closingIssuesReferences.nodes[].number]}' > main_prs.jsonl

python - main_prs.jsonl <<'EOF'
import json, sys
sys.path.insert(0, 'scripts/tracker')
import closing_refs
fn = sup = 0
for line in open(sys.argv[1], encoding='utf-8'):
    d = json.loads(line)
    ours, oracle = set(closing_refs.closing_numbers(d['body'] or '')), set(d['oracle'])
    if oracle - ours: fn += 1; print(f"FALSE NEG PR #{d['n']}: {sorted(oracle-ours)}")
    if ours - oracle: sup += 1; print(f"superset PR #{d['n']}: {sorted(ours-oracle)}")
print(f"false-negatives={fn} (must be 0), supersets={sup} (inspect each)")
EOF
```

Run everything with `python` on Windows dev boxes (`python3` is the Store
stub); CI runners use `python3`.
