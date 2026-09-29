---
status: accepted
date: 2026-07-14
owner: "@Doomgoose (Alex Young)"
amended: 2026-07-14 (A1, post-merge audit) — close-on-merge trigger becomes `push: [dev]`; never-close goes programme-wide behind a committed never-close list; the sweep loses its autonomous tier and its reporting moves to a workflow; per-PR cap 6; CODEOWNERS artefact descoped; counts corrected against the post-consolidation tracker (see Amendment A1)
related: issue #2139 (auto-close gap, 29 leaked issues); docs/agents/issue-standard.md (the standard this ADR mandates); docs/agents/issue-tracker.md; docs/agents/triage-labels.md; .github/workflows/nightly.yml (issue-automation precedent)
---

# 3001 — Issue-lifecycle guardrails: closing the dev-branch tracker loop

> Records the remediation programme adopted after the July 2026 backlog audit. Over 2026-07-13/14 a
> full manual audit re-grouped the tracker and closed ~180 issues across two maintainer-run passes
> (28 closed as `completed` with linked evidence on 07-13; a 153-issue bulk reset closed as
> `not_planned` on 07-14), and filed #2139 quantifying the structural auto-close gap (29 issues
> left open despite merged PRs claiming to close them). Even after that effort, **over a thousand
> issues remain open in a four-month-old repository** (1,024 at the 2026-07-14 audit snapshot **[A1 §1]**),
> and nothing prevents regrowth: the audit treated
> symptoms. The backlog is a direct bottleneck on development speed — 683 issues are marked
> `ready-for-agent` but their freshness cannot be trusted, so picking up work starts with
> re-verification; governance runs re-file findings that already exist; maintainers burn sessions
> on manual batch-close sweeps because `Closes #N` never fires on dev merges; and release scoping
> cannot trust open counts. This ADR adopts five automated guardrails so the tracker stays
> truthful without recurring heroics.

## Context

### Where we are

The repository works on a `dev` integration branch; `main` is release-only and is GitHub's default
branch. Counts below are the 2026-07-14 audit snapshot — the tracker moves daily. Six structural
gaps let the backlog grow unchecked:

- **B1 — Fixed work stays open.** GitHub honours closing keywords only on default-branch merges,
  so every `Closes #N` in a dev PR is inert. Issue #2139 found 29 issues still open despite
  merged PRs explicitly claiming them; roughly one in four of the 50 most recently merged dev PRs
  (≈18% of the last 300, by strict closing-keyword grammar) carry closing keywords that do
  nothing. **[A1 §2]** The current substitute is periodic manual batch-close sweeps by maintainers.
- **B2 — Unbounded batch inflow.** Agent skills file issues in volume (the governance pipeline
  alone produces 8–15 deferred-finding issues per run) with a prose-only convention and no
  mandatory duplicate search. Issue *content* quality is high; the failure modes are duplicates,
  multi-finding bundles, and decisions typed as code tasks.
- **B3 — Silent fixes.** Issues resolved incidentally by feature/refactor PRs that never
  reference them leak past any keyword-based automation.
- **B4 — No recurring triage.** Nothing sweeps for obsolete, duplicate, or unclear issues; 160
  open issues still carry `needs-triage` and 24 are unlabelled. **[A1 §1]**
- **B5 — Taxonomy drift.** 66 labels with two parallel priority schemes (`P0/P1/P2` vs
  `priority-p*`) and two phase series make label-driven filtering and automation unreliable. **[A1 §1, §7]**
- **B6 — No telemetry.** Inflow/outflow and backlog age are invisible until the situation
  demands another multi-day audit.

### Why this is a dev-speed bottleneck

Every tracker-touching activity pays a tax. Selecting work requires re-verifying whether the
issue is still real; reviews and governance runs spend effort re-discovering known findings;
maintainer time goes to manual close sweeps; planning and release scoping work from inflated
numbers. The July audit itself — days of skilled effort — is the recurring cost of having no
guardrails, and without structural change it will need repeating within months.

## Decision

Adopt five guardrail pillars, delivered across five PRs (each subject to the standard review
gates) — the mapping is not one-to-one: pillars 2 and 3 share PR 2, and pillar 4 splits its
forms into PR 3 and its hook into PR 4 — plus a scripted label migration and a recurring
operational cadence: **[A1 §7, §13]**

1. **A written issue standard** (`docs/agents/issue-standard.md`) governing when an issue is warranted,
   required body sections (Context / Evidence / Acceptance criteria / Origin), mandatory labels
   (one type + one of `P0/P1/P2` + one triage state), one-actionable-outcome-per-issue,
   mandatory duplicate search before filing (no volume cap — dedupe is the filter), typing for
   decision/spike/hardening issues, and closing discipline (`Closes #N` required in any PR that
   resolves an issue; `completed` only with linked evidence; the security exception routing
   exploitable vulnerabilities to private advisories). Wired into every instruction surface:
   CLAUDE.md, AGENTS.md, CODEX.md, CONTRIBUTING.md, the governance and test skills, and the PR
   template.
2. **Close-on-dev-merge automation** (`close-linked-issues.yml`) **[A1 §3, §4]**: on every PR merged into `dev`,
   parse the PR body with GitHub's documented closing-keyword grammar (chain-aware:
   `Closes #1, #2, #3` / `Fixes` / `Resolves` and variants; the parser strips code fences and
   blockquotes and ignores negated context so quoted or discussed keywords don't fire) **[A1 §12]**, validate
   each reference via the REST API (same-repo, an issue not a PR, current state), and close the
   survivors as `completed` with an evidence comment and a `fixed-on-dev` label. The evidence
   comment self-identifies: it names the workflow and links the run, states the close was
   performed by automation, cites the PR + merge SHA, names the authorizing human (the PR's
   merger), and carries an idempotency marker. Residual accepted: REST validation proves a
   reference exists and is an issue, not that it is *related* — a typo'd `#N` can close the
   wrong issue, which the evidence comment makes visible and reversible. Revert PRs reopen what
   this automation closed **[A1 §11]**, deriving the reopen set from its own close markers on the reverted
   PR's issues (reopen drops `fixed-on-dev` and re-adds `needs-triage`). A daily reconcile pass
   covers fork merges, outages, and races **[A1 §3]**; the same parsing logic ships as a local script **[A1 §12]** —
   bound to the identical evidence-comment schema and caps, and required to print a dry-run
   diff before executing — that performs the one-time backfill of #2139's 29 leaked issues **[A1 §2]** and
   any pre-release reconciles (see Costs/risks: a dev-only workflow file accepts neither cron
   nor `workflow_dispatch` until it reaches `main`). A per-PR sanity cap bounds blast radius:
   if a single PR's body resolves more than 10 issues **[A1 §5]**, the workflow skips the batch and posts
   it to the automation-broken tracking issue so the skip is actionable, never just logged.
   **Failure is loud:** an `if: failure()` alert job opens or updates an `automation-broken`
   issue (the `nightly-broken` pattern from `nightly.yml`) — this, not the weekly sweep's
   leak count, is the primary liveness signal **[A1 §11]**; leak-count>0 is the correctness backstop.
   Alert and cap-skip issue bodies are public: they carry the workflow name, run URL, and a
   non-sensitive summary only — never raw logs, step outputs, or error stacks.
3. **A PR "issue radar"** (`linked-issues.yml`, advisory-only): one sticky comment per PR that
   (a) flags `#N` mentions lacking a closing keyword and (b) matches the PR's changed file paths
   against open-issue bodies — `file:line` citations are common in the agent-drafted bodies and
   the issue standard makes them mandatory going forward, so matching is best-effort where
   citations exist — so authors are told "these open issues cite files you touched" and add
   `Closes #N` before merge. Fork PRs run with a read-only token, so radar output surfaces in
   the workflow step summary rather than a PR comment.
4. **Mechanical enforcement at creation**: YAML issue forms (replacing the two legacy Markdown
   templates) + `blank_issues_enabled: false` + a private-advisory contact link for the web
   path — with a deliberate asymmetry: the human web forms require only a minimal subset
   (description plus reproduction/environment for bugs), keeping Acceptance-criteria/Origin as
   optional prompts so a drive-by report is never lost; the full four-section standard binds
   the agent-side `gh` path; a committed blocking PreToolUse hook (`issue-standard-guard.py`,
   reusing the changelog-fragment guard's proven fail-open JSON-deny pattern — the new hook
   needs its own `Bash`/`PowerShell` matcher and command-string parsing, since the changelog
   guard matches file-edit tools) that denies non-conformant `gh issue create` calls from agent
   sessions with a teaching message (fail-open, `YUZU_ISSUE_STANDARD_ACK=1` operator bypass). **[A1 §14]**
5. **A recurring evidence-based triage sweep** **[A1 §10]** (`/issue-triage` repo skill, run weekly from the
   maintainer's box; the `triage-sweep` label names its rolling tracking issue — the skill and
   the label are distinct identifiers): a five-category rubric — fixed-elsewhere / obsolete /
   too-trivial / unclear / duplicate — where every closure carries machine-parseable evidence
   (claiming PR **and** a grep of current `origin/dev` proving the defect gone). Both probes
   re-run against a freshly fetched `origin/dev` at execution time, never against the report
   snapshot. Machine-verifiable fixed-elsewhere closures execute autonomously from day one
   (capped 15/run; overflow carries to the next run); judgment categories produce a checkbox
   report for operator approval. Every closure comment records its authority tier —
   `sweep-auto` or `operator-approved` — and each executed sweep posts the approved per-issue
   decision list (or the report's hash plus summary) to the tracking issue, so batch
   authorization is durably reconstructable. Duplicate detection scales via a file-citation
   inverted index rather than pairwise comparison; index completeness (full pagination of the
   open set, never a truncated cap) is an acceptance criterion, since dedupe is the only
   inflow filter. The sweep also runs closure-integrity spot-checks (sampling recent
   `not_planned` closures against the current codebase so closure decisions stay durable as
   the architecture moves) and posts weekly telemetry to the rolling tracking issue. The
   `stateReason` taxonomy this programme adopts (`completed` = evidence-linked;
   `not_planned` = wontfix/obsolete/duplicate/below-standard) is **forward-looking**: closures
   predating this ADR must not be re-read through it. Work that is genuinely complete but has
   no machine-checkable trail still closes `completed`, with the human attestation recorded in
   the closing comment.

Both new workflows follow the repo's least-privilege convention: workflow-level
`permissions: contents: read`, with `issues: write` scoped per-job to the close job only and
`pull-requests: write` scoped per-job to the radar's comment job only (the `ci.yml`/`nightly.yml`
pattern — job-level permissions replace the workflow default). The advisory radar uses
per-PR `concurrency` with `cancel-in-progress: true` (newest run wins); the close job never
cancels mid-run; the sweep and the label migration throttle mutations with inter-call backoff
to stay clear of GitHub's secondary rate limits. The issue standard and the `config.yml`
contact link reference `SECURITY.md`'s private-advisory URL directly rather than paraphrasing
it, and state a hardening-only convention for public `security`-labelled issues (PR 1 adds the
one-line rule to `SECURITY.md` itself — an addition, not a restatement). `fixed-on-dev` has a
defined lifecycle: applied at dev-close, stripped when the fix ships to `main` (wired into the
release workflow as a follow-up; purely informational until then). The label migration must
complete before PR 2 merges — its `pull_request [closed]` trigger is live immediately — and
the workflow additionally tolerates a missing label so an early merge cannot fail a close.

Supporting decisions: merge `priority-p*` into `P0/P1/P2` and create the automation labels
(`fixed-on-dev`, `task`, `decision`, `triage-sweep`) via a one-time idempotent script **[A1 §7]**;
`phase-*` labels left untouched (open issues on both series; nothing keys on them); the ad-hoc
`github-issues/` staging directory is retired (its one draft gets filed per the standard, then the
directory is deleted) — the tracker is the sole source of truth; CODEOWNERS gains a
`/.github/` entry so automation changes always get owner review. **[A1 §9]**

## New artefacts

| # | Artefact (path) | PR | Value / output | Negates |
|---|---|---|---|---|
| 1 | `docs/agents/issue-standard.md` | PR 1 | Single canonical filing/labelling/closing standard for humans and agents; the document every other artefact cites | B2, B3, B5 |
| 2 | Pointer edits: `CLAUDE.md`, `AGENTS.md`, `CODEX.md`, `CONTRIBUTING.md`, `docs/agents/issue-tracker.md`, `docs/agents/triage-labels.md` | PR 1 | Every Claude/Codex session and human contributor is routed to the standard at the moment they touch the tracker | B2 |
| 3 | Governance + test skill rewrites (`.claude/skills/governance/SKILL.md`, `.claude/skills/test/SKILL.md`) | PR 1 | The largest inflow source dedupes against the open index before filing; run reports enumerate filed AND not-filed candidates, making inflow auditable | B2 |
| 4 | PR-template issue-linkage checklist line (`.github/pull_request_template.md`) | PR 1 | Authors declare `Closes #N` / `Relates to #N` on every PR as a matter of routine | B3 |
| 5 | `.github/workflows/close-linked-issues.yml` + local reconcile/backfill script | PR 2 | Linked issues close automatically on dev merge with an evidence trail; reverts reopen; the script backfills #2139's 29 leaked issues **[A1 §2]** and covers pre-release reconciles; manual batch-close sweeps end | B1 |
| 6 | `.github/workflows/linked-issues.yml` (issue radar) | PR 2 | Silent fixes surfaced pre-merge: "these open issues cite files you touched"; missing closing keywords flagged while the PR is still editable **[A1 §13]** | B3 |
| 7 | `scripts/issues/migrate-labels.sh` | PR 2 | One priority scheme; automation labels exist before anything references them; idempotent and dry-run-first **[A1 §7: superseded — `scripts/tracker/bootstrap-labels.sh`, PR 1]** | B5 |
| 8 | Issue forms + `config.yml` (`.github/ISSUE_TEMPLATE/`, legacy `.md` templates deleted) | PR 3 | Web-path issues arrive structured and `needs-triage`-labelled; blank issues off; vulnerability reports deflected to private advisories | B2, B5 |
| 9 | CODEOWNERS `/.github/` entry | PR 3 | Automation control plane always gets owner review — guards artefacts 5–8 themselves **[A1 §9: descoped]** | (protects all) |
| 10 | `scripts/hooks/issue-standard-guard.py` + `.claude/settings.json` wiring | PR 4 | Non-conformant `gh issue create` denied at source with a teaching message, in every Claude session sharing the repo settings | B2, B5 |
| 11 | `.claude/skills/issue-triage/` (SKILL.md + `dump-issues.sh`, `leak-scan.sh`, `build-citation-index.py`, comment templates) | PR 5 | Weekly evidence-based sweep: autonomous two-probe closures for claim-verified fixes, checkbox report for judgment calls, duplicate clustering, closure-integrity spot-checks **[A1 §10]** | B1, B3, B4 |
| 12 | `triage-sweep` rolling tracking issue + telemetry block | PR 5 (operational) | Weekly open/inflow/outflow/age/leak metrics plus operational gauges (telemetry staleness >10 days = dead-man's-switch, workflow failure-run count, issue-standard conformance count so hook-bypass drift is visible); threshold breaches (leak >0 post-PR-2, needs-triage >100, net inflow >+50/wk×2) open or update a P1 issue assigned to the maintainer rather than only commenting — drift visible in days, not months **[A1 §10]** | B6 |

> **[A1]** The PR assignments in this table (rows 5–12) and the row-7 script path are superseded
> by Amendment A1 — see §7 (label bootstrap) and §13 (corrected PR map).

## Consequences

**Positive.** The tracker becomes trustworthy without multi-day audit heroics: fixed work closes
itself with evidence, inflow is deduplicated and auditable at the source, silent fixes are
surfaced pre-merge, and drift triggers alerts instead of crises. `ready-for-agent` regains
meaning as a work queue, directly recovering the dev-speed lost to re-verification. Value
accrues per PR (see the Negates column) — but the end-state claims are staged: alert-driven
drift detection exists only once PR 5's telemetry lands, which is why PR 2 carries its own
fail-loud alert job in the same PR rather than depending on the sweep for liveness. Because
every automated closure carries an idempotency marker, the closures of any given run are
bulk-reversible by querying that run's markers — bad batches have a defined recovery path. **[A1 §10]**
Operator absence degrades gracefully: the merge-triggered close path runs unattended; only the
sweep, its telemetry, and leak detection pause until the next run.

**Costs / risks.**
- The close-on-dev-merge cron and the issue forms only activate once the files reach `main`
  (GitHub evaluates both from the default branch), and a dev-only workflow file accepts neither
  cron **nor** `workflow_dispatch` — new workflows on `dev` are fully dormant until the next
  release promotes them (the repo's documented CI invariant; verified empirically: a dev-only
  workflow is invisible to the Actions API). Accepted — the `pull_request [closed]` trigger (the
  main path) is live from the moment PR 2 merges to dev, and the bundled local script covers
  reconciles and the #2139 backfill from a maintainer checkout until the release. **[A1 §3]**
- `CLAUDE.md` is currently ~300 characters **over** its own self-imposed 40k cap **[A1 §8]**, so PR 1's
  pointer edit cannot be additive: it must rewrite the existing issue-tracker routing line
  net-negative (routing detail out to `docs/agents/`), with an explicit acceptance criterion
  that the committed file returns under 40,000 characters.
- The blocking hook adds friction to legitimate rapid filing; mitigated by fail-open behaviour,
  the `--web` escape, and the explicit `YUZU_ISSUE_STANDARD_ACK=1` bypass. Codex sessions do not run
  Claude hooks and rely on the AGENTS.md pointer + the sweep as backstop. Being fail-open and
  bypassable, the hook is an enforcement/teaching layer, never a security control — the
  vulnerability-routing guarantee rests on SECURITY.md, the `config.yml` contact link, and
  `blank_issues_enabled: false`, none of which sit on a fail-open path.
- Autonomous sweep closures could mis-fire; bounded by the two-probe evidence requirement,
  the 15-per-run cap, hard guardrails (never touch `security`-labelled / assigned / recently
  active / open-linked-PR issues), append-only comments with idempotency markers, and a standing
  rule that any wrongly-closed reopen freezes the autonomous tier until the operator re-enables
  it.
- The radar comment is heuristic and could annoy; it is advisory-only, single-sticky-comment,
  and per-PR opt-out (`<!-- radar:off -->`).

## Alternatives considered

- **Change the default branch to `dev`** so native auto-close works: rejected — touches release
  tooling, requires admin, and inverts the repo's release model for one feature we can replicate
  with a 10-permission-line workflow.
- **`pull_request_target` trigger** for fork coverage: rejected — adds a dangerous-trigger
  workflow to a zero-suppression zizmor repo; plain `pull_request` + daily reconcile covers the
  same ground. **[A1 §3]**
- **GraphQL `closingIssuesReferences` as the resolution source**: rejected on empirical grounds —
  GitHub only creates closing-issue references for PRs targeting the default branch, so the
  field returns an empty set for exactly the dev-based PRs this automation exists to handle
  (verified read-only on merged dev PRs #2125, #2126 and #1983, whose bodies carry explicit
  `Closes`/`Fixes` lines yet all return zero nodes). Body parsing with the documented
  closing-keyword grammar is therefore the only viable source — #2139's proposed fix already
  prescribes it — hardened by validating every parsed reference via the REST API (same-repo,
  issue-not-PR) before any close, and acceptance-tested against those known PRs before the
  backfill runs.
- **GitHub Actions-hosted LLM triage**: rejected — the sweep's core operation is grepping the
  current checkout, and an API-key secret would require admin provisioning; a repo skill run
  from the maintainer's box needs zero new credentials.
- **Volume caps on batch filing**: considered and dropped in favour of dedupe-only — a cap
  discards legitimate findings; deduplication plus enumeration-in-report achieves auditability
  without loss.

## Rollout

**[A1 §13]** PR 1 (policy) → PR 2 (workflows + label migration, then scratch-PR verification matrix, then
backfill + close #2139) → PR 3 (forms + CODEOWNERS) → PR 4 (hook) → PR 5 (sweep skill), followed
by a four-week operational burn-down: leaked-issue closure and closure-integrity spot-checks
first, then the 184 `needs-triage`/unlabelled **[A1 §1]** in tranches, then a full duplicate pass, then
bundling splits for P0/P1 — landing at a steady-state weekly sweep cadence. Each implementing
PR carries its own verification section with the acceptance tests for its artefacts.

**Ratification.** No acceptance gates beyond the standing convention (`docs/agents/domain.md`):
a reviewed-PR merge to `dev` confers acceptance; `status:` flips to `accepted` in the final
pre-merge commit of the PR that lands this document. **[A1 §0]**

---

## Amendment A1 (2026-07-14) — post-merge audit corrections

This ADR merged (PR #2143, approved by @fjarvis) hours after the 2026-07-14 backlog
consolidation finished moving the ground it was written on. Before implementation began, an
adversarial audit of its claims was run against the live repository; this amendment records what
the audit found and the corrected decisions. **Where A1 and the original text disagree, A1
governs.** Original prose is untouched — the `**[A1 §n]**` markers point here — and the five
pillars, the six gaps, and the parse-the-PR-body design all stand.

### §0 — Status

`status:` now reads `accepted`. Acceptance evidence per `docs/agents/domain.md`'s standing
convention: PR #2143's reviewed merge to `dev` (approver @fjarvis ≠ author @Doomgoose). The
Ratification clause said the flip would happen in the final pre-merge commit; it was missed, and
is recorded here by the PR that begins implementation.

### §1 — Corrected tracker snapshot

The "2026-07-14 audit snapshot" numbers predate the same-day consolidation. Post-consolidation:
**958** open issues (not 1,024), of which **334** carry `roadmap` (§6) — **624** active; **647**
`ready-for-agent` (not 683); **164** `needs-triage` (not 160), of which **82** active; **0**
unlabelled (not 24); **60** labels (not 66) with **one** priority scheme — the consolidation
deleted `priority-p*`, so gap B5's "two parallel priority schemes" is already resolved and the
label *migration* has nothing to migrate (§7).

### §2 — B1 rates re-derived; the backfill set is not what it was

Re-measured at implementation time: 20 of the last 80 merged dev PRs (25%) carry closing
keywords — consistent with "roughly one in four" — and across all 360 merged dev PRs the
strict-grammar rate is ~20% ("≈18% of the last 300" mislabelled its window). The "29 leaked
issues" of #2139 is stale: the maintainer hand-closed most of that set on 2026-07-13. The
residual still-open claimed set is **9–11 issues, dominated by the deliberately-held-open
security surface rather than by leaks** (§4). Genuine backfill closes: roughly three.

### §3 — Trigger: `push: branches: [dev]`, not `pull_request [closed]`

The specified trigger is structurally broken for exactly the merges it must not miss: a
`pull_request`-triggered run for a PR from a **fork** (or from Dependabot) receives a
**read-only** `GITHUB_TOKEN`, and `permissions:` can only reduce, never elevate — the close job
403s, **and the `if: failure()` alert job that exists to report the failure 403s in the same
breath**. Seven fork PRs have already merged into dev (#692, #795, #883, #1242, #1335, #1339,
#1361). Corrected: the workflow triggers on `push: branches: [dev]` — the trusted event issue
#2139 originally prescribed. Full token regardless of PR origin; live from the pushed ref (no
default-branch dormancy for the main path); merged PRs resolved per pushed merge commit via
`repos/{owner}/{repo}/commits/{sha}/pulls`; the PR body reaches the parser via an API fetch, so
no attacker-controlled event payload ever crosses a YAML interpolation. This deletes the **daily
reconcile cron** outright (it existed to patch the fork hole, and the Decision text and Costs
text contradicted each other about whether it was a workflow or a local script — moot now). The
`pull_request_target` alternative stays rejected; under `push:` the entire trigger-hazard class
is moot.

### §4 — Never-close is programme-wide, behind a committed never-close list

The original scopes the hard guardrails to pillar 5's sweep only, leaving pillar 2's close
workflow and its backfill unguarded — and the backfill's candidate set includes **#520** (P1,
verified still reachable on 2026-07-14, deliberately held open) and **#1634** (P0, whose claiming
PR #1711 says in bold that it does **not** close it). Corrected: **no automated code path ever
closes** an issue that is `security`-labelled, `do-not-close`-labelled, listed in
`scripts/tracker/do-not-close.txt`, assigned, or attached to an open PR — union semantics, any
one signal suffices; automation posts an advisory comment instead. The committed, number-keyed
file is authoritative because labels alone have already been wrong (#318 and #391 are
security-relevant issues that lacked the `security` label); it is seeded with the held-open
security surface and only a reviewed PR changes it. The backfill **hard-stops** (exit non-zero,
zero mutations) if any `security`-labelled issue survives into its candidate set, presents a
dry-run diff sorted security/P0/P1/assigned first, and its acceptance criterion is per-issue
maintainer approval posted to #2139 — never a count target. Full rules:
`docs/agents/issue-standard.md` §5.1.

### §5 — Per-PR cap: 6, not 10

The observed maximum of closing refs on any of 360 merged dev PRs is **6** (PR #1480; next
highest 4). A cap of >10 can never fire and bounds nothing. Corrected: **>6 refs → close nothing
for that PR**. A cap-skip is not a failure: it opens a `needs-triage`/`P2` cap-skip issue and
exits 0 — routing it to `automation-broken` would be wrong, since that issue self-clears on the
next green run and the notice would be erased.

### §6 — The `roadmap` label exists and changes every denominator

The same-day consolidation adopted `roadmap` as the active-backlog separator: **334** of 958
open issues, parked on the roadmap Project, excluded from triage via `is:open -label:roadmap`.
This ADR never mentions it. Consequences: the sweep's judgment categories (obsolete /
too-trivial / unclear) run on the **active** set only — 334 deliberately-parked issues must not
be churned; telemetry gauges key on the active set; and the mandatory-label rule becomes
three-tier — every issue carries one type; every non-`roadmap` issue carries one triage state;
the `gh` path additionally carries `roadmap` XOR (one of `P0/P1/P2` + the triage state);
`roadmap` never coexists with a priority or a triage state. Roadmap issues stay in the duplicate-detection snapshot (excluding them would
blind a third of the corpus) but are eligible for fixed-elsewhere advisory comments only.

### §7 — Label migration becomes a six-label bootstrap, owned by PR 1

With `priority-p*` gone (§1) there is nothing to migrate. `scripts/tracker/bootstrap-labels.sh`
(idempotent `gh label create --force`) creates what is genuinely missing: `task`, `decision`,
`do-not-close`, `fixed-on-dev`, `triage-sweep`, and `automation-broken` — the last omitted from
the original's own list yet required by its alert job. The home is `scripts/tracker/`, not
`scripts/issues/`, which is already occupied by the static issue bodies that
`scripts/create_issues.sh` consumes. Owned by PR 1 so every later artefact finds its labels in
place — the original's "label migration must complete before PR 2 merges" ordering gate
disappears.

### §8 — CLAUDE.md is over in bytes, not characters

CLAUDE.md measured **39,977 characters / 40,304 bytes** at amendment time: 23 characters *under*
its self-imposed 40k-character cap and 304 *bytes* over — "~300 characters over" read a byte
count as characters. The original acceptance criterion ("returns under 40,000 characters") was
already true and detects nothing. Corrected criterion: the pointer edit is **differential** —
the committed file is strictly smaller in characters than before the edit (UTF-8-decoded count;
`wc -m` under Git Bash on Windows degrades to bytes, which is the same trap), with the
replacement text ASCII-only so the edit is net-negative in bytes as well.

### §9 — CODEOWNERS artefact (#9) descoped

Deliberately dropped, not deferred. Both branch rulesets carry
`require_code_owner_review: false`, so a `/.github/` CODEOWNERS entry auto-requests review and
**gates nothing** — the original's "always gets owner review — guards artefacts 5–8" claimed a
control that would not exist. Making it real requires an admin ruleset flip that is repo-wide,
not path-scoped: it would hard-gate every PR touching the owned auth and guardian paths on two
specific reviewers' availability — a policy change outside this ADR's remit, and one the team's
current size and review-latency budget argue against. The automation control plane gets a real,
no-admin guard instead: a deterministic check in `zizmor.yml` (PR 2) that fails any PR deleting
`close-linked-issues.yml`, adding a `paths:` filter to it, or moving it off the `push:` trigger.
Revisit code-owner gating when the contributor base makes an unreviewed automation change a
plausible risk.

### §10 — The sweep: no autonomous closure tier, ever; reporting moves to a workflow

The autonomous tier is removed **structurally, not cautiously**: once close-on-merge is live, an
issue that satisfies the sweep's claiming-PR probe yet remains open is, by construction, an
issue the primary automation **failed on** — closing it autonomously would repair the symptom
and destroy the evidence. The code path is not built, rather than built-but-disabled. Every
closure is operator-approved and executes through a **fail-closed**
`scripts/tracker/apply_decisions.py` under the operator's credentials, with a per-run ledger
comment posted to the `triage-sweep` tracking issue *before* any close executes; `--revert
<run-id>` reverses an exact batch. (This replaces "bulk-reversible by querying that run's
markers", which is unimplementable as stated: comment search is eventually consistent and
returns issues, not comments.) The weekly *ritual* is replaced by machinery: a read-only, no-LLM
report workflow (`tracker-report.yml` — telemetry, leak scan, duplicate candidates,
closure-integrity sample; dormant as cron until it reaches `main` and runnable locally
meanwhile; it must check out `ref: dev` explicitly, since scheduled workflows default to the
default branch) plus an **on-demand** `/issue-triage` skill run when the report flags judgment
work — capped at 10 operator decisions per run with no carry-over, and security/P0/P1 decisions
require a typed `VERIFIED-GONE-AT: <sha>` line rather than a checkbox. Telemetry thresholds ship
green-on-day-one: `needs-triage > 100` keys on the **active** set (82 at amendment time, not the
raw 164), and the net-inflow alarm is deleted — measured inflow (83–173/week) breaches any such
threshold permanently, and a permanently-red alert buries `leak > 0`, the one signal that
matters; inflow becomes a reported gauge with a four-week trend.

### §11 — Liveness is three mechanisms; revert-reopen is cut

An `if: failure()` alert cannot be "the primary liveness signal": it cannot fire on a run that
never happens, nor on a green run whose parser silently regresses to matching nothing. Liveness
is three mechanisms: the `if: failure()` alert (execution failures), a **per-push leak scan
pulled forward from pillar 5 into PR 2** (completeness — merged-PR claims vs still-open issues,
same never-close and cap rules as the close job), and a frozen parser fixture corpus in `tests/`
(regression). Revert-reopen is cut: no GitHub-generated revert PR (body `Reverts …#N`) exists
among the ~2,150 merged PRs — the only "revert"-titled merge, PR #23, reverts a build flag, not
an issue-closing merge — and the marker-query mechanism it depended on is unreliable (§10). Its
replacement is
`--undo-push <before>...<after>`, which recomputes the closure set deterministically for an
exact push range and reverses it.

### §12 — One parser implementation, documented-superset grammar

"The same parsing logic ships as a local script", implemented literally, is two implementations
(workflow JavaScript + local Python) of one grammar, which will diverge. Corrected: there is
**one** implementation — `scripts/tracker/closing_refs.py` — invoked by the workflow step, the
backfill, the undo path, and the leak scan alike. Its grammar is a **documented superset of
GitHub's**: the documented closing keywords plus comma/`and` chains bound to a single keyword
(`Closes #1, #2, #3` — a form this repo genuinely uses; 9 of 105 closing refs in the dev corpus
are chain-only), with code fences, inline code, blockquotes, and negated contexts stripped.
Acceptance oracle: run it over all 72 merged main-base PRs — where GitHub's own
`closingIssuesReferences` is populated — requiring zero false negatives; PR #1711 ("does **not**
close #1634") is the canonical mandatory negative case in the frozen fixture corpus.

### §13 — Corrected PR map

| PR | Contents | Live on dev-merge |
|---|---|---|
| 1 | This amendment + `docs/agents/issue-standard.md` + the label contract (`triage-labels.md`) + `scripts/tracker/do-not-close.txt` + label bootstrap + `gh` allowlist entries + instruction-surface routing + governance/test skill filing rewrites | Everything |
| 2 | `close-linked-issues.yml` (`push:`) + `closing_refs.py` + backfill/undo + per-push leak scan + zizmor control-plane guard; its own merge closes #2139 | Everything |
| 3 | `issue-standard-guard.py` PreToolUse hook + the first tests for `scripts/hooks/` + dormant `issue-conformance.yml` server-side backstop | Hook yes; backstop dormant |
| 4 | `tracker-report.yml` + on-demand `/issue-triage` skill + fail-closed `apply_decisions.py` | Script + skill yes; cron dormant |
| 5 | Issue forms + `config.yml` (private-advisory contact link, blank issues off) — parallel, independent, must never gate PRs 1–4. Until the release promotes them, `SECURITY.md` is the only live web-path routing guard — unchanged from today | Dormant until release |

The issue radar (`linked-issues.yml`, artefact 6) is **deferred behind a measured trigger** — it
re-imports the `pull_request` token hazard §3 exists to escape, and it matches `file:line`
citations that only become mandatory going forward. Trigger: ≥10 duplicate-closures in any
four-week window, or ≥3 hand-rejected duplicate filings.

### §14 — Hook wiring must be interpreter-robust and locally verified

The committed hooks are invoked as `python3 …`; on Windows dev boxes `python3` can resolve to
the Microsoft Store app-execution-alias stub, which exits without emitting hook JSON — and a
fail-open hook that emits nothing **allows silently**. This is live today: the changelog-fragment
guard has never fired on the primary Windows dev box. Pillar 4's guard therefore ships with
interpreter-robust wiring and a local self-check that proves the hook actually denies on the
host it protects; Linux CI structurally cannot catch this failure class.
