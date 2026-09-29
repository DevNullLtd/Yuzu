# Issue Standard

The single canonical standard for filing, labelling, and closing GitHub issues in `Tr3kkR/Yuzu`.
Adopted by ADR-3001 (`docs/adr/3001-issue-lifecycle-guardrails.md`, as amended by A1). It binds
humans and agents equally, by this text and PR review; the `gh` CLI path will additionally carry
mechanical enforcement (a PreToolUse hook — ADR-3001 pillar 4, PR 3 of the stack; Claude sessions
only — other agents remain bound by this text alone). Command mechanics live in
[`issue-tracker.md`](issue-tracker.md); the full label taxonomy lives in
[`triage-labels.md`](triage-labels.md).

## 1. When an issue is warranted

File an issue when there is **one actionable outcome** that will not be delivered by the current
session or PR. Split multi-finding bundles — one outcome per issue. (A deliberate consolidation of
closely-related outcomes over one code neighbourhood is allowed — precedent #2148–#2156 — but it
must enumerate what it folds and the folded issues close with pointers to it.)

Type the work honestly:

- a code defect → `bug`
- new or improved behaviour → `enhancement`
- a concrete engineering chore → `task`
- a choice to be made, whose outcome is a recorded decision rather than code → `decision`
- proof-of-concept / plumbing exploration → `spike`
- docs-only work → `documentation`
- a question needing an answer → `question`
- infra / runners / CI plumbing → `operational`

**Never file an exploitable vulnerability as a public issue** — see section 6.

Parked or planned scope ("we should eventually…") is a `roadmap` issue: tracked on the roadmap
Project, excluded from the active backlog, carrying **no** priority and **no** triage state.

## 2. Duplicate search first (mandatory)

Dedupe is the only inflow filter — there is deliberately no volume cap. Before filing, run at
least the first two probes, and record what you ran and what it returned in the Origin section:

```bash
# probe 1 — by the file/symbol the issue cites
gh issue list --repo Tr3kkR/Yuzu --state open --search "<file-or-symbol>" --json number,title
# probe 2 — by title keywords (if all 20 results return, narrow the keywords and re-run)
gh search issues --repo Tr3kkR/Yuzu --state open "<two or three keywords>" --json number,title --limit 20
# probe 3 (when a type/facet is obvious) — label-scoped
gh issue list --repo Tr3kkR/Yuzu --state open --label <label> --search "<keywords>" --json number,title
```

| Probe result | Verdict |
|---|---|
| Same defect/outcome already open | **Do not file.** Comment the new evidence on the existing issue. |
| Same root cause, different symptom | Comment on the existing issue; widen its scope there. |
| Related but a distinct actionable outcome | File, with `Relates to #N` in the body. |
| Nothing relevant | File. |

## 3. Body format

Four sections, in this order. Mandatory on the `gh`/agent path. (The web issue forms — PR 5 of
the ADR-3001 stack — will require only a minimal subset, description plus reproduction, so a
drive-by human report is never lost to a schema; triage supplies the rest. The same grace applies
to web reports arriving via today's legacy templates.)

```markdown
## Context
<what and why — enough that a cold future session can pick this up>

## Evidence
<file:line citations against current origin/dev; logs; repro steps.
 file:line is mandatory wherever code is implicated>

## Acceptance criteria
<what closes this — machine-checkable where possible>

## Origin
<what produced this (governance run / test run / PR review / manual);
 the dedupe probes run and what they returned; related issues and PRs>
```

`file:line` citations keep issues verifiable — a future sweep greps current `origin/dev` to test
whether the defect is still present — and they feed duplicate detection.

## 4. Labels

Three mandatory axes; the full taxonomy with meanings is [`triage-labels.md`](triage-labels.md).

- **Every issue, any path:** exactly one **type** label (`bug`, `enhancement`, `task`, `decision`,
  `spike`, `documentation`, `question`, `operational`). Every **non-`roadmap`** issue additionally
  carries exactly one **triage state** (`needs-triage`, `needs-info`, `ready-for-agent`,
  `ready-for-human`, `wontfix`); `roadmap` issues carry a type only.
- **`gh` path (agents and maintainers), additionally:** either `roadmap` (parked scope — no
  priority, no triage state) **or** exactly one priority (`P0`/`P1`/`P2`) alongside the triage
  state. A drive-by web reporter cannot know the priority — priority is a triage decision; agents
  have the context, so the automated path carries the burden of proof.
- **Facet labels** (`security`, `performance`, `reliability`, `ci`, `auth`, `plugin`, …) —
  optional, any number that genuinely applies.
- **Automation-owned labels** (`fixed-on-dev`, `automation-broken`, `triage-sweep`,
  `do-not-close`, `nightly-broken`, `runner-inventory-drift`) are applied by automation or by the
  maintainer — never set them on a new filing. (Exception: a maintainer may add `do-not-close` to
  any issue at any time; that is the label's purpose.)

Invariants (measured by tracker telemetry once ADR-3001 PR 4 lands):

- every open non-`roadmap` issue carries a priority once triaged;
- `roadmap` never coexists with a priority or a triage state.

## 5. Closing

- Any PR that resolves an issue says `Closes #N` (or `Fixes #N` / `Resolves #N`) in its **body**.
  Partial work says `Relates to #N` or `Part of #N` and **must not** use a closing keyword
  (precedent: PR #1711 explicitly declines to close #1634 for exactly this reason).
- `completed` requires linked evidence: the closing PR, or — for work that is genuinely done but
  has no machine-checkable trail — a human attestation in the closing comment.
- `not_planned` covers wontfix / obsolete / duplicate / below-standard. Duplicates close with a
  pointer to the surviving issue.
- This taxonomy is forward-looking from ADR-3001's adoption: closures that predate it must not be
  re-read through it.

### 5.1 What automation must never close

No automated code path — the close-on-merge workflow, the backfill, a reconcile, or the triage
sweep — ever closes:

1. an issue carrying the `security` label;
2. an issue carrying the `do-not-close` label;
3. an issue whose number is listed in `scripts/tracker/do-not-close.txt`;
4. an assigned issue;
5. an issue with an open linked PR.

Union semantics: any one signal suffices. For these, automation posts an **advisory comment**
("merged PR #N claims to close this; a human must verify against current `origin/dev` before
closing") and stops. Labels are mutable and have been wrong before — #318 and #391 are
security-relevant issues that lacked the `security` label — so the committed, number-keyed file
is the authoritative backstop, and only a reviewed PR changes it.

## 6. The security exception

An **exploitable vulnerability** is never filed publicly. Report it via GitHub private
vulnerability reporting: <https://github.com/Tr3kkR/Yuzu/security/advisories/new> (see
[`SECURITY.md`](../../SECURITY.md)). Public issues carrying the `security` label are for
**hardening, defense-in-depth, and reliability** work only. If in doubt whether a finding is
exploitable, treat it as exploitable.

## 7. Canonical queries

- Active backlog: `is:open -label:roadmap` — the `roadmap` set is parked and deliberately excluded
- Agent work queue: `is:open label:ready-for-agent -label:roadmap`
- Untriaged: `is:open label:needs-triage -label:roadmap`
