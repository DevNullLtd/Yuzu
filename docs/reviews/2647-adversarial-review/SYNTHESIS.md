# Adversarial review synthesis — cb69991f..3cc9f417 (#2619/#2620)

Reviewers: claude (isolated subagent) + codex (gpt-5.6 "Sol", `codex exec`, workspace-write sandbox).
Two phases, disk barrier, cross-examination. Both empirical: each independently parsed the 62-row
ledger fragment against the branch's own field table and re-ran the other's jq/recipe experiments.

## Verdict: BLOCK → fixed in round 10 (this branch), now PASS-equivalent pending re-read

Two HIGHs, both converged on and both empirically reproduced by BOTH reviewers:

1. **ADV-1 (claude F1 = codex C-P2-1, test-run ×2).** The Gate 8 step-4 jq park check is row-wise;
   the write model's own conforming sparse supersession (8-field minimum, `impact` inherited) parks an
   `I1` finding and the check exits 4 — the documented CLEAN result. Anchored to the false-green policy
   floor. FIX (applied): `roadmap-#N`/`linked-to-#N` rows must restate `impact` + `severity_mapped`;
   step 4 now names the gap and scopes "the check passed" to conforming rows.
2. **ADV-2 (codex C-P1-2, adopted by claude as F9 with git-log-L provenance).** The Gate 2 docs-writer
   preamble restated required-doc item 6 as "operator-facing reference", dropping the author-facing
   half the canonical item carries — a branch-authored narrowing (round 3) that survived the round-4
   canonical fix. Violates #2620 criterion (c). FIX (applied): preamble now says update obligation,
   operator- OR author-facing.

## Non-blocking, fixed

- COL-1's `reporter_ref` is free text, not third-party-retrievable (both, MEDIUM) → field rule gains an
  honest-`unresolved` carve-out; README names COL-1 as the wrong way.
- README wrong-row census undercounted (both, MEDIUM) → census now count-free and lists the bare
  off-enum `deferred-to-issue` row.
- Same-session attestations (claude F4; codex not-verified on same-session provenance) → README caveat:
  attestations here stand on recorded evidence, not actor independence.
- Legacy rows (dev's 2643 fragment) lack `recorded_at`; ordering was undefined (codex-led, LOW) →
  read rule: untimestamped rows sort first, file order among peers.
- Tuning-doc round-8 narration "closed … exactly those four fields" (claude F3 MEDIUM vs codex
  false-positive) — ADJUDICATED: codex is right that historical narration may record a false rule, but
  one parenthetical pointing at round 9's falsification costs nothing and prevents the misread. Applied.

## Adjudicated disagreements

- C-P1-1 severity: codex opened HIGH (policy floor), self-downgraded to MEDIUM in phase 2 after
  claude's cross-exam showed the README discloses the rows as deliberate wrong-as-written history and
  no anchor demands per-row validity of superseded rows. Concur: MEDIUM, fixed as above.
- claude F3: split (MEDIUM vs false-positive). Ruled: cosmetic-fix middle course (above).
- claude F4: codex could not verify same-session provenance from the repo alone. Ruled: true but only
  documentable, not fixable — README caveat is the proportionate action.

## Coverage gaps / open questions

- Gate 5 (chaos) does not receive the shared severity/ledger preamble (codex INFO). Left open — Gate 5
  transforms a risk register rather than raising ledger rows directly. Filed nowhere; noted here.
- "Closes #2620" auto-closes with the `.codex` runner copy still divergent — that divergence is
  deferred to open #2639 by design and both reviewers accepted the deferral as recorded; the criterion
  is met for the `.claude` runner after ADV-2's fix.
- Neither reviewer had network in-sandbox; GitHub issue states were taken from the pre-fetched anchors.

## What each reviewer ran

- claude: full 62-row JSONL validation vs field table (merge + row-scoped attestations + stronger-of);
  jq-1.8.1 park-check matrix (clean 4 / violation 0 / missing file 2 / scalar-impact 0 / sparse-park 4);
  mktemp+noclobber create, collision, `>>` append, 20-way concurrent append; changelog lint;
  40k ceilings; conflict-marker and stale-copy greps; `git log -L` provenance of the ADV-2 sentence.
- codex: independent 62-row validator (found the off-enum row); independent sparse-supersession jq
  repro; legacy-fragment scan (25/25 rows untimestamped); changelog lint; `git diff --check`;
  `wc -c`; attempted `gh issue view 2639` (no network — declared, not silently skipped).

Sandbox: workspace-write (no network). All reviewer artefacts: /tmp/yuzu-advrev-gov2619/.
