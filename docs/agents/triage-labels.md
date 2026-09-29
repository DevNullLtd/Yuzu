# Triage Labels & the Label Contract

The engineering skills speak in five canonical triage roles; those map 1:1 to GitHub labels, as
they always have (first table below). This document now also records the **full label taxonomy**
those roles live in — the axes, who owns each label, and the invariants the tracker telemetry
measures. Which labels are mandatory when is defined by [`issue-standard.md`](issue-standard.md)
section 4; this file is the reference for what each label *means*.

## Triage states — exactly one per non-`roadmap` issue

| Canonical role | GitHub label | Meaning |
|---|---|---|
| `needs-triage` | `needs-triage` | Maintainer needs to evaluate this issue |
| `needs-info` | `needs-info` | Waiting on reporter for more information |
| `ready-for-agent` | `ready-for-agent` | Fully specified and ready for an AFK agent |
| `ready-for-human` | `ready-for-human` | Requires human implementation |
| `wontfix` | `wontfix` | Will not be actioned |

Use the right-hand label when applying or removing triage state in GitHub. "Fully specified" for
`ready-for-agent` means the body satisfies the issue standard: Context / Evidence with `file:line`
/ Acceptance criteria / Origin.

## Type — exactly one per issue

| Label | Meaning |
|---|---|
| `bug` | A code defect — current behaviour is wrong |
| `enhancement` | New or improved behaviour |
| `task` | Concrete engineering chore (rename, migration, wiring) |
| `decision` | A choice to be made; the outcome is a recorded decision, not code |
| `spike` | Proof-of-concept / plumbing exploration — not production-ready |
| `documentation` | Docs-only work |
| `question` | A question needing an answer |
| `operational` | Infra / runners / CI plumbing — not a code defect |

## Priority — exactly one per triaged non-`roadmap` issue

| Label | Meaning |
|---|---|
| `P0` | Critical — drop other work |
| `P1` | High — next in line |
| `P2` | Medium — scheduled, not urgent |

This is the **only** priority scheme. (A parallel `priority-p*` set existed until the 2026-07-14
consolidation deleted it; nothing may reintroduce it.) Priority is a *triage* decision: web
reporters leave it off; agents and maintainers set it at filing.

## Scope container

| Label | Meaning |
|---|---|
| `roadmap` | Parked/planned scope, tracked on the roadmap Project. **Excluded from the active backlog** (`is:open -label:roadmap`). Carries **no** priority and **no** triage state — a half-parked issue is a contract violation. |

## Facets — optional, any number that genuinely applies

`security` (public issues = hardening/defense-in-depth only — exploitable vulnerabilities go
through private reporting, see `SECURITY.md`), `performance`, `reliability`, `observability`,
`compliance`, `ci`, `auth`, `docker`, `plugin`, `TAR`, `tech-debt`, `test-infra`, `devops`,
`enterprise`, `enterprise-readiness`, `breaking-change`, `dependencies`, `github_actions`,
`codex`, `good first issue`, `help wanted`.

`governance-deferred` is a facet with a job: **every** issue filed from a `/governance` run
carries it, which makes agent inflow countable without any extra machinery.

## Automation-owned — never set these on a new filing

| Label | Owner | Meaning |
|---|---|---|
| `do-not-close` | maintainer | Automation must never close this issue (issue-standard §5.1). The committed list `scripts/tracker/do-not-close.txt` is the authoritative twin; the label is the instant, no-PR marker. |
| `fixed-on-dev` | close-on-merge workflow (ADR-3001 PR 2) | Closed by dev-merge automation; the fix is not yet in a `main` release. Stripped at release promotion (informational until that wiring lands). |
| `automation-broken` | close-on-merge alert job (PR 2) | The tracker automation itself failed; opened by the `if: failure()` alert job. |
| `triage-sweep` | tracker report (PR 4) | Marks the rolling tracking issue the weekly report posts to. |
| `nightly-broken` | nightly.yml | Nightly failed; no merge to `main` while open. |
| `runner-inventory-drift` | runner-inventory-sentinel.yml | Self-hosted runner drift detected. |

`duplicate` and `invalid` are GitHub defaults applied by humans at close time.

## Legacy — leave alone

`workstream-a-grc` … `workstream-g-assurance`, `phase-0-foundation` … `phase-16`. Two historical
series; open issues still carry them and nothing keys on them. Do not add them to new filings; do
not bulk-migrate them (ADR-3001 explicitly leaves `phase-*` untouched).

## Invariants (measured by tracker telemetry once ADR-3001 PR 4 lands)

- Exactly one type + one triage state on every open non-`roadmap` issue; a priority once triaged.
- `roadmap` never coexists with a priority or a triage state.
- Nothing but automation applies the automation-owned labels (except `do-not-close`, which the
  maintainer may apply at will). Removing an automation-owned label disarms a never-close signal —
  never do it without the maintainer's say-so; removals become telemetry-visible with PR 4.
