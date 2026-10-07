# #5459 option D: decision record and review provenance

This directory is the retrievable evidence behind the operator's 2026-10-06 decision to replace
the K=3 wedge waiver (the rung 9c PR-5e K-bound, PR #4529) with retry suppression at the retry
gate. It exists because the sources were local files that a change-management reviewer could not
retrieve (governance ledger finding `COMP-C1`). Nothing here changes behaviour. The decision's
consequences are in `docs/spark-flip-gate.md` (§3a, AC-1, AC-9 to AC-17) and
`docs/spark-stage2-guardian-consumer-design.md` (R5.3).

## What was decided, by whom, and how

- **Decision maker:** the operator (Dave Rae), in a terminal chat with the coordinating Claude Code
  session ("SPARK CHAOS") on 2026-10-06. The time of day is not recorded.
- **The words, verbatim:** "Go with D, have Astra review the suppress condition". It answered the
  question "Which do you want?", asked after the coordinating session wrote: "The ruling: replace
  the K-waiver with retry suppression at the retry gate. This reverses ruling 14 decision 1
  (PR-5e's K-bound) and accepts that recovery after a late failure depends on the next server push.
  If you can't accept that, it's C and the freeze moves about two weeks." The operator's stated
  criterion earlier the same day: "I need to understand better to make an informed decision on C vs
  D. I want the solution to be robust, but preferably not at the expense of weeks of development if
  we can reasonably avoid it." Also on the record, before and after: "I don't love the issues with C
  nor with D", "I'm leaning towards C", "I still don't like the gaps that D leaves".
- **Channel and record:** the ruling was made in a terminal session and was NOT posted as an issue
  comment at the time. This directory and `docs/spark-flip-gate.md` §3a are its in-repo record.
- **Numbering:** "ruling 21" and "ruling 14" are the coordinating session's own numbering, kept in
  an uncommitted local plan file. Only rulings 12, 13 and a few others were also posted as issue
  comments. The precise committed citation for what option D replaces is
  `docs/spark-stage2-guardian-consumer-design.md` R5.3 decision 1 (the K-bound), PR #4529. Earlier
  committed docs that cite ruling 14(a), 14(b), 14(c) or ruling 16 refer to that same local numbering.
- **Not ruled on by the operator at that time:** the safety-valve value of 10 suppressions and the
  compensation-aware extension came from the design-D review (below); the decision that a `Recovered`
  late success counts as outstanding work (the next identical push is suppressed) came from the
  Fable review of the implementation plan and was approved by the operator in the implementing
  session on 2026-10-06 (that session's transcript is the record; the coordinating session holds
  none). That no server back-off ships with the change was likewise agreed in the implementing
  session.

## Options considered

The letters below are the coordinating session's. A, B and C were presented first on 2026-10-06; D
was added by the coordinating session afterwards and was unvetted at the time, until the design-D
review and the Fable reframing below. The letters were later muddled by a second lettering used inside a forked mitigation analysis (A flag the waiver, B server
escalating interval, C agent-side suppression, D hold-for-T-then-waive), which is not the same A-D.

| Option | What | Disposition |
|---|---|---|
| A | accept the acknowledged-but-unarmed state, with a risk-register entry | not really available: governance treats a derived HIGH as fixed or the change withdrawn |
| B | repro first, then a small "re-open the generation" fix (a one-shot lowering of the reported generation so the server's existing reconcile re-pushes) | evaluated; the source-read opinion judged it not a safe decrement-and-retry patch without a recovery lifecycle |
| C | the issue's tick-driven recovery engine ("narrow C", the design-C opinion): about 620 to 1,100 production lines plus 1,000 to 2,000 test lines, one to two engineering weeks | sound, rejected for the freeze on size and risk; the design-C opinion recommended C, or holding the flip through the freeze |
| D | drop the K-waiver for wedged arms so the generation stays held; reframed in review as "move the waiver's predicate from `can_advance()` to `decide_retry()`" | chosen, on schedule grounds, knowing the C review's preference |
| (hybrid) | revocable acknowledgment | rejected: needs a server protocol change |
| (hold then waive) | bounded hold, then waive | rejected: reintroduces #5459 |

## Reviews behind the decision

- Source-read opinions (read-only, no code run, no governance run), model "Astra": the general
  accept-or-recover opinion, the narrow-C design opinion, and the D suppress-condition opinion.
  Files in this directory: `astra-accept-or-recover-opinion-2026-10-06.md` (recommended fixing
  before the freeze, not A, narrow C), `spark-5459-astra-c-design-opinion.md`,
  `spark-5459-astra-d-suppress-opinion.md`. Earlier Astra runs on #5401/#4472 are not retained.
- Fable consultations by the coordinating session (five, via an advisor tool on #5401/#4472 (twice),
  the #5459 accept-or-recover question, the C design, and "something better than C or D", which
  produced the reframing that option D is a predicate move): the text was not saved as files; the
  coordinating session's summaries are in its local plan file. **Not recorded here.**
- Fable review of the final plan, by the implementing session: `fable-review-2026-10-06.md`
  (GO WITH CHANGES, no blocking finding). It is the review that proposed counting `Recovered` as
  outstanding work.
- The kickoff and implementation brief the implementation followed:
  `spark-5459-optionD-retry-suppression-KICKOFF.md`, `spark-5459-optionD-IMPL-BRIEF.md`.
- Every review above was run by Claude Code sessions or their subagents: independence from the
  change author is asserted, not enforced. The governance ledger
  (`governance.d/5459-optionD-retry-suppression.*.jsonl`) records the implementation-side reviews.

## Reading these files

They are verbatim copies of working documents, kept as evidence. They quote line numbers that were
current at origin/dev `c9ffc9087` / `56ea4db8a`, use the session-local ruling numbers above, and
predate the final implementation (the kickoff's Step-0 citation corrections are in the brief). Where
they disagree with the code, the code and `docs/spark-flip-gate.md` win.
