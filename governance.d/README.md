# Governance findings ledger — fragments

One file per `/governance` run, mirroring `changelog.d/`. Each line is a JSON object
describing one finding.

```
governance.d/<PR-or-issue-number>-<short-slug>.<random>.jsonl
```

- `<PR-or-issue-number>` — the PR number if you have it, else the issue.
- `<short-slug>` — 2–5 words, kebab-case.
- `<random>` — a `mktemp` stem, with the final `.jsonl` path created under `noclobber`
  so the committed artifact itself is opened `O_EXCL`. A suffix collision therefore FAILS
  LOUDLY rather than overwriting an earlier run's findings; uniqueness is enforced by the
  filesystem rather than assumed from a timestamp. The recipe is in the skill — do not
  reimplement it with `mv`, which overwrites silently.

One file per **run**, not per PR. Gate 8 iterates, and `pass_ordinal` distinguishes rounds
*inside* a file; a fresh run gets a fresh fragment.

A fragment is not sealed when the run ends. Findings from a PR review, an
`/adversarial-review`, or another external pass are appended after the run finishes, and an
already-recorded finding's disposition may change later. Which field records the reviewer's
kind, and how an absent row must be read, are defined with the other fields in the Gate 8
table — deliberately not restated here.

Two rules govern those later writes, both defined in the Gate 8 recipe: writes after the
create are **appends**, and a row is **superseded, never edited**. An append to an
already-merged fragment goes through a pull request like any other change.

## Why these are committed

The ledger is evidence for whoever reviews the pull request: which findings were raised,
which were fixed, which were deferred and by whom. A per-machine path cannot be read by the
reviewer, and SOC 2 CC8.1 evidence has to be retrievable by someone other than the person
who generated it (#2618, decided on #2604).

Two costs, accepted deliberately. Fragments appear in diffs. And a fragment can be lost —
but **not** on the changelog fragment's terms, so do not reason from that analogy; the Gate
8 recipe has the detail. Commit the create with the work it reviews, and commit each append
on the same push that makes the claim it records.

## Limitations — read these before treating a fragment as evidence

- **Nothing writes these automatically.** Every row is hand-authored. There is no validator,
  so "required" and "required iff" in the field table are conventions, not enforcement.
- **Rows are author-writable and appendable after merge.** `recorded_at` and the
  supersede-never-edit rule are what make a later change legible; git history is the
  integrity substrate, and a squash-merge collapses it.
- **An absent row is uninformative.** It does not mean a reviewer passed, and an absent
  external-review row does not mean no external review happened.

## Retention

Indefinite, by default and not yet by decision. Nothing prunes these. Whether they are
pruned, assembled at release, or kept indefinitely as the access-review campaigns
deliberately are, has not been decided — unlike those campaigns, where indefinite retention
IS the recorded decision. The de facto posture is the conservative one; do not describe it
as a policy.

## Throwaway local runs

Set `YUZU_GOV_LOG_DIR` to a scratch directory outside the repo. Nothing is written here and
nothing needs cleaning up.

## Fields

**Defined in one place only:** the Gate 8 field table in
`.claude/skills/governance/SKILL.md`. Deliberately not restated here — an earlier draft of
this README listed the fields and had already dropped `classification`, which is exactly the
second-copy drift the governance rule itself forbids.

## Reading the first fragment as a template

`2619-ledger-provenance-prose-ownership.sW31cX.jsonl` is the first ledger written and will
be copied. Several things in it are worth not copying.

Few rows carry a `policy_floor`; compute which from the fragment — an earlier version of
this paragraph said "exactly one" and was falsified by a row added in the same PR, which is
the no-quoted-counts rule below demonstrating itself. `COL-1` is unusual (a process
violation rather than a code finding, and an averted one) — do not take it as the model for
an ordinary floored finding; `ADV-1` is the better model.

This README quotes no row counts, deliberately: it stated them three times and was wrong
three times, because a prose count of an append-only file goes stale the moment a row is
appended — often in the very commit that updated the count. Compute counts from the
fragment; never quote them from here.

Some rows are wrong as written and correct only after supersession (deliberately — no
count, counts here went stale): a bare `deferred-to-issue` with no `#N`; a human recorder
in `reporter` with `source: "governance-agent"` and missing `recorded_by`/`reviewed_at_sha`;
reporters joined into one string; a correction that described an error without restating
the field, which under field-wise merge changed nothing; and `COL-1`'s `reporter_ref`,
free-text prose where the field demands a third-party-retrievable reference (the honest
value was `unresolved`). They are left in place because superseding is the rule and
rewriting is not — but **the merged view is the artefact**. Read it through the merge,
never row by row.

One more caveat for evidence use: every adjudication and refutation in this fragment names
a governance agent of the SAME authoring session. The skill itself says a subagent of the
authoring session is not independent — these attestations stand on their recorded evidence
(the refutation is an executed measurement), not on actor independence.

Also not to copy: two rows withdrew an adjudication by nulling
`adjudicated_by`/`adjudication_rationale`. That was wrong twice over — the adjudications
were correct (an `I9` finding under a `SHOULD` label IS a genuine facts/label disagreement,
so lowering the label was a real de-escalation), and nulling an attestation is not how you
withdraw one. Attestation fields are row-scoped and exempt from the merge; you withdraw an
attestation by superseding the act it approved. Both withdrawals are themselves superseded
in the fragment.

Its `recorded_at` values were hand-written and are illustrative: nearly every row written
during the branch's own review rounds postdates the commit that introduced it, which is physically impossible and would make the commit-time
cross-check reject every row. Real runs should stamp real times. The cross-check bounds
`recorded_at` from above only, so it never catches the attack it is named for — an author
appending a later-stamped row and committing it promptly is always "consistent".
