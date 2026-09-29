---
status: accepted
date: 2026-07-01
owner: "@lesault (Andy Younie)"
depends-on: 0018 (server-authoritative matching — the engine that produces these findings); 0005 (two-matcher split)
related: docs/vuln-scan-engine-design.md §4.4; docs/vuln-scan-roadmap.md M2; docs/vuln-scan-capability-map.md V4; 0023 (correlation engine — first consumer, provisional number)
amended: 2026-07-05 (correlation-engine grill-with-docs session) — adds a fourth status `potential` and an orthogonal confidence axis (see Amendment); 2026-07-12 (vulnerability-management UCE module design) — retires `potential` in favour of a four-state assessment (OPEN/FIXED/NOT-APPLICABLE/UNKNOWN) and renames `confidence` to `provenance tier` (HIGH/MEDIUM/LOW) — see second Amendment (proposed, unratified — open legs: @FortitudeEtc review, `/governance` on the implementing PR)
---

# 0019 — Vulnerability findings carry a multi-value status; coverage is a dimension separate from vulnerability

> **Reading guide (added 2026-07-12) — this file now layers three things, read the right one for
> your purpose.** (1) The original Decision below plus (2) the 2026-07-05 Amendment describe the
> vocabulary **merged and schema-live in-server** via ADR-0023's implementation (PRs #1917/#1919/#1924:
> `VulnFindingStore` wired into `/readyz`'s `stores_ok` conjunction) — tri-state + a fourth `potential`
> status + a `confidence` axis. **The producing engine was never built**: the series stopped at PR
> 3/6, `VulnFindingStore::reconcile_agent` has no caller anywhere in the codebase, and the matching
> work was superseded by the Vulnerability Management UCE module decision (Amendment 2, below). The
> store therefore cannot be populated in production and **must not be cited as a customer
> questionnaire, support answer, or SOC 2 CC7.1 audit-sample target** — there is no live control to
> sample. Frontmatter `status: accepted` records this ADR's own acceptance, not a claim that a running
> production control exists. (3) The 2026-07-12 Amendment is a **proposed** four-state
> model (OPEN/FIXED/NOT-APPLICABLE/UNKNOWN) + provenance tier for the not-yet-built Vulnerability
> Management UCE module — **not yet ratified.** This docs PR itself has been through this project's
> `/governance` review process (docs-only; Gate 3 domain-triggered agents not applicable, no code
> touched; Gate 5 skipped, no injectable runtime fault), but that is not the same leg: the amendment
> has **not been shown to @FortitudeEtc**, and the code that implements it has **not been through
> `/governance` on its own implementing PR**, nor shipped anywhere. Do not cite (3) as current
> behavior.

> Crystallised in the 2026-07-01 grill-with-docs session. Records *what a scan result means* for a
> package the feeds do not cover — the difference between "we looked and it's clean" and "we never
> looked." Load-bearing for the floor's honesty bar and for the differentiator's integrity claim.

## Context

The server-authoritative matcher (ADR-0018) routes each installed-software identity to a feed —
distro packages to OVAL, the Windows/macOS-GUI and language-ecosystem tail to CPE/NVD. For a given
`(host, package)` the naive model has two outcomes: **matched an advisory → vulnerable**, or **no
match → clean**.

That two-state model is wrong, because it collapses two genuinely different situations into
"clean":

- **(a) The package is within a feed's coverage and no advisory matches.** "No known
  vulnerabilities" is a *true* assertion. Trusting the feed's silence is correct here — feed
  correctness is about accuracy *within scope*.
- **(b) No feed covers the package at all** — a side-loaded vendor `.deb`, a language package the
  feeds don't track, or an EOL distro whose OVAL stream stopped publishing. The feed's silence here
  does **not** mean "safe"; it means **we never looked.**

"Assume the vuln feed is correct" licenses only (a). It says nothing about packages *outside* the
feed's scope. Conflating "the feed is authoritative for what it covers" with "the feed covers
everything" is the classic scanner lie, and in security tooling the resulting failure is a false
**negative** — the more dangerous direction.

### The failure the two-state model produces

An **EOL Ubuntu 18.04** host. Canonical no longer publishes standard OVAL for it (moved to paid
ESM). The router sends every `deb` package to the Bionic OVAL stream; the stream has no current
rows; so **every package "matches no feed"** and the two-state model reports **"no vulnerabilities
found"** on a host that is a swiss-cheese of unpatched CVEs. That is not a coverage gap — it is
**false assurance**, which is *worse* than no scan, because a reader sees "clean" and moves on.

## Decision

**A vulnerability finding is tri-state, and coverage is tracked as a dimension separate from
vulnerability status.** *(This tri-state model is superseded below by two amendments — 2026-07-05
adds a fourth `potential` status, still the accepted/ratified vocabulary as opposed to the 2026-07-12
amendment (proposed, not yet ratified); "accepted" here is ratification status, not a production-
liveness claim — see the reading guide above for that distinction. This original text is left as the
decision history and is not the current shipped model on its own.)*

1. **Per-`(host, package)` status is one of three values:**
   - **Vulnerable** — matched an advisory in a covering feed.
   - **Assessed–clean** — within a covering feed's scope, no match. Reported as *"no known
     vulnerabilities, as of feed-sync timestamp T"* (the absence of a finding has a shelf life, so
     the assertion is timestamped to the feed version it was evaluated against).
   - **Not-assessed** — the package is identified but **no feed covers it**. Surfaced explicitly as
     *unknown / not assessed* — **never** rendered as clean, never silently dropped.

2. **Coverage is a first-class, separate dimension.** Each host scan carries a **coverage metric**:
   *assessed N of M installed packages; (M−N) not-assessed.* Coverage answers "how much of this box
   did we actually evaluate," which is orthogonal to "how many vulnerabilities did we find." The two
   dimensions are reported side by side and neither is inferable from the other.

## Consequences

**Gained:**
- **Honest reporting.** The EOL-18.04 host reports "0 vulnerabilities, but only 12 of 430 packages
  assessed" instead of a false all-clear. The gap becomes a *visible, actionable number* — operators
  can act on low coverage (upgrade the distro, buy ESM, add a feed) instead of being lied to.
- **Differentiator integrity.** The CAVM attack-path scoring (ADR-0018's differentiator, roadmap
  M5) cannot credibly rank a host's risk if some installed packages are dark and unaccounted-for.
  A per-host coverage number is the precondition for claiming scoring completeness.
- **False-negative containment.** The most dangerous failure mode in a scanner — silently missing
  real vulnerabilities — is surfaced as low coverage rather than hidden behind a clean verdict.

**Costs accepted:**
1. **More data model + UI surface.** Findings carry a status enum (not a boolean) and each host
   carries coverage counters; the dashboard/REST must present coverage as a first-class figure, not
   a footnote. Deliberate — the honesty is the point.
2. **"Not-assessed" can look like noise on messy fleets.** A fleet full of side-loaded software
   will show large not-assessed counts. This is truthful signal, not noise, but it needs good
   defaults (group/aggregate not-assessed by reason: no-OVAL-stream vs no-CPE-mapping vs
   side-loaded) so operators can triage rather than drown.
3. **Feed-freshness must be carried.** "Assessed–clean as of T" requires threading the feed-sync
   timestamp through to the finding, so a stale feed produces a *stale-clean* signal, not a
   confidently-clean one.

**Ownership.** Andy owns the finding-status taxonomy and the coverage-metric definition; Eng owns
carrying the feed-version timestamp and computing coverage counters at correlation time.

## Amendment — 2026-07-05: a fourth status `potential`, plus a confidence axis

> Added during the correlation-engine design (grill-with-docs). The original tri-state assumed the
> matching feed for a given package is *backport-correct* — true for OVAL (Lane 1's authoritative
> source, ADR-0018) but **not** for raw NVD-on-distro. M1a (`docs/vuln-scan-roadmap.md`) stands up the
> correlation engine on **NVD-only, before OVAL lands (M1b)**. Against NVD alone, a distro package's
> `release` backport suffix (`1.1.1f-1ubuntu2.16`) is invisible, so an in-range NVD hit on a
> distro package is *not* a confirmed vulnerability — it is the dominant false-positive source ADR-0018
> lines 67-73 warns about. Asserting such a hit as **Vulnerable** would reintroduce exactly the
> scanner-lie this ADR exists to prevent, in the false-**positive** direction.

**The finding status is extended from three values to four:**

- **Vulnerable** — matched an advisory in a **backport-correct** feed (OVAL, M1b), or a curated exact-CPE
  match where backport is not a confound. *An asserted, confirmed vulnerability.*
- **`potential`** *(new)* — matched an NVD version range, but the match is **not backport-confirmed** (no
  OVAL for this package yet). Surfaced as *"unconfirmed — pending OVAL backport check, as of feed-sync T"*,
  and **counted separately from Vulnerable** (never folded into the vulnerable headline). When OVAL lands
  (M1b) each `potential` resolves deterministically → **Vulnerable** (OVAL: not-backported) or →
  **Assessed–clean** (OVAL: backport-fixed) **only if the finding's identity confidence is `high`**; a
  `low`-confidence `potential` that OVAL marks backport-fixed resolves to **Not-assessed** instead — the
  confidence gate applies at every point a finding could become `assessed-clean`, not just at initial
  correlation. **This is not a final verdict**: like any other record, it is re-assessed on the next
  qualifying trigger (ingest content-change or a new-CVE feed delta) — a persistent NVD range match keeps
  resurfacing as `potential (low)` each cycle rather than being silently dropped.
- **Assessed–clean** — within a covering feed's scope, no match, **and the package identity was resolved
  at high confidence**. A low-confidence identity match that looks clean is never assessed-clean — see
  the confidence rule below.
- **Not-assessed** — no feed covers the package, or the package's identity could only be resolved at low
  confidence **and no advisory matched** (a low-confidence match against an in-range advisory is still
  `potential`, carrying `confidence: low` — see below; this carve-out only ever removes a clean verdict,
  never a positive one); identified but never evaluated.

**A second, orthogonal dimension: `confidence`.** Independent of status, each `potential`/Vulnerable
finding carries `confidence ∈ {high, low}` reflecting the **identity-mapping** certainty — `high` = a
curated or exact CPE identity; `low` = a best-effort normalized-name match. Confidence answers "did we map
this package to the right CPE product," which is orthogonal to status's "what did the feed say." (This is
the same separation-of-dimensions principle as coverage vs vulnerability, applied to identity.)

**Low-confidence identity can never produce a clean verdict.** Without this rule, a wrong best-effort
name-prefix match that happens to land on a safe NVD product would become a counted, timestamped
`assessed-clean` finding with no confidence field attached to ever flag it — reintroducing, in the
false-**negative** direction, exactly the false-assurance failure this ADR exists to prevent. So a
`low`-confidence match **that would otherwise read clean** (no advisory in range) is routed to
`not-assessed` (reason `identity-low-confidence`) instead; only a `high`-confidence identity can produce
`assessed-clean`. **This rule never demotes a positive match** — a low-confidence identity that DOES land
an in-range advisory still surfaces as `potential (confidence: low)`, per the confidence axis above; the
carve-out only ever removes a clean verdict. **Coverage consequence:** a low-confidence-identity record
that would have been clean now counts toward coverage as `not-assessed` — the coverage number may read
lower than a naive identity-match rate would suggest. That is deliberate honesty, not a regression.

**Feed-freshness threading (realises cost #3 above).** Every `potential` and Assessed–clean verdict is
stamped with the NVD catalog feed-sync timestamp, so a stale mirror yields a *stale* signal, not a
confidently-current one.

**Consequence — M1a acceptance reconciled.** The roadmap's M1a bar is *"no lower-bound false positives."*
The MVP hits it **because it never asserts Vulnerable on a distro package pre-OVAL** — such hits are
`potential`, explicitly unconfirmed. The confirmed-Vulnerable bucket is ~empty until M1b; that is the
honest state, not a gap.

**Ownership.** Andy owns the finding-status taxonomy, so this amendment is within the ADR owner's remit;
it is recorded here rather than as a new ADR because it refines this ADR's core taxonomy. Route through the
same `/governance` path on the implementing PR.

## Ratification

**Status: accepted** (2026-07-09). Authored by the vuln_scan domain owner. Less cross-cutting than
ADR-0018 (it does not redraw the agent↔server boundary), but it commits the finding data model and
the reporting surface. **Accepted per @Tr3kkR's standing convention (2026-07-09, `docs/agents/domain.md` "ADR Acceptance
Convention"): an ADR merged via reviewed PR carries `status: accepted` on `dev`.** Already merged
and standing on `dev` since 2026-07-01 without objection.

**Carve-out (2026-07-12) — open leg on the second Amendment below.** The 2026-07-12 Amendment (four-state
assessment / provenance tier, Vulnerability Management UCE module) is **not** covered by the acceptance
above. Per the same convention, this is a named sign-off leg recorded after 2026-07-09 and therefore
governs regardless of the document's overall `status: accepted`: the Amendment remains **proposed,
unratified** until it has been reviewed by @FortitudeEtc and its implementing PR has been through its
own `/governance` pass. Do not treat this document's frontmatter `status: accepted` as covering that
Amendment.

## Amendment — 2026-07-12: a four-state assessment (OPEN/FIXED/NOT-APPLICABLE/UNKNOWN) supersedes `potential`; `provenance tier` replaces `confidence`

> Written during the Vulnerability Management use-case-engine (UCE) module design
> (`VULN_UCE_MODULE_DESIGN.md`, itself an untracked working draft, not yet reviewed as a production
> artefact — ADR-1005 Decision 6 / `docs/adr-1005-execution-plan.md` Phase 2d), informed by the
> adversarially-reviewed CVE-matching research (`CVE_MATCHING_STRATEGY_ARBITRATED.md`, likewise an
> untracked working draft, 25 accept/5 partial/0 reject). `potential` (2026-07-05 amendment, above)
> was scaffolding for a specific in-server sequencing problem: ADR-0023's M1a shipped NVD-fallback-only, before OVAL
> (Lane 1's real backport-aware source) existed, so it needed a hedge state to avoid asserting
> `Vulnerable` on an NVD-on-distro hit that backporting could invalidate. The module carries no such
> constraint — it can build the regime-split, tracker-first architecture from day one instead of
> replaying the NVD-only-then-OVAL sequence, so there is no window where an unconfirmed NVD-on-distro
> hit needs its own status: the tracker gives a direct FIXED/OPEN/NOT-APPLICABLE answer, or its
> absence gives UNKNOWN. This is not a reversal of this ADR's core invariant — never assert a status
> you can't back up, never silently drop an unresolved case as clean — which is *fully* satisfied by
> UNKNOWN + provenance tier; `potential` was a symptom of staged in-server delivery, not a
> load-bearing part of the honesty model.

**The finding status is redefined to four values, replacing the three-plus-`potential` model above:**

- **OPEN** — affected and not fixed. Covers the prior **Vulnerable** case, plus the un-collapsed
  **`potential`** case: an OVAL-unconfirmed NVD hit is now `OPEN` at `LOW`/`MEDIUM` provenance tier,
  not a separate status — a strictly more informative signal, since it says *why* confidence is
  reduced rather than just *that* it is. **This explicitly supersedes the 2026-07-05 amendment's
  "never folded into the vulnerable headline" separate-counting rule for `potential`** — that rule
  existed only to protect a headline `Vulnerable` count from an unconfirmed hit; since OPEN now
  carries its own provenance tier, the correct replacement behavior is for any OPEN/coverage rollup
  to break out HIGH-tier (confirmed) vs. LOW/MEDIUM-tier (unconfirmed) counts rather than a single
  undifferentiated OPEN total — an implementer must not report one undifferentiated OPEN headline
  and silently lose the confirmed/unconfirmed distinction the old rule protected.
  `assessment_reason_code` is nullable/empty for the ordinary case (a plain, unqualified OPEN — no
  sub-mark, ordinarily HIGH provenance tier); it is populated only when one of the two named
  sub-cases below applies, or when the value duplicates a LOW/UNKNOWN reason code (see the
  provenance-tier paragraph below) — it is never a required, always-populated field. Two annotated
  sub-cases, carried on this same `assessment_reason_code` field (never a distinct status value):
  **`OPEN — permanently unfixed`** (`assessment_reason_code: eol-permanently-unfixed`; a positive
  EOL/terminal tracker marker, e.g. Ubuntu's `ignored (end of standard support)` — nothing will ever
  fix this) and **`OPEN — remediable only via <channel>`** (`assessment_reason_code: channel-gated`;
  a fix exists, but only in an unentitled channel, e.g. ESM or a disabled module). **Neither
  sub-mark may automatically change `disposition`** — they are facts about the evidence, not an
  operator decision, and auto-setting `disposition = accepted-risk` off either would silently pause
  SLA-breach tracking (measured from time-in-disposition-state) before anyone actually chose to
  accept the risk. The finding stays in its ordinary `triaged`/`new` disposition until an operator
  deliberately raises a risk record.
- **FIXED** — a fix is present and confirmed installed (backport ≥ tracker fixed version; installed
  build ≥ vendor's fixed build; the fixing/superseding KB present; installed version ≥ patched
  version).
- **NOT-APPLICABLE** — a *positive* not-affected marker exists (vendor CSAF `known_not_affected`,
  distro tracker not-affected/DNE). Only ever from a positive marker, never from feed absence. This
  is the other half of the retired **Assessed-clean**, split out because "the patch is installed"
  and "this was never affected" are different operator-facing claims a single status conflated.
- **UNKNOWN** — a first-class state, broader than the retired **Not-assessed**: no feed covers the
  package, the tracker hasn't triaged it yet (`needs-triage`/`under_investigation`), a source's
  snapshot is stale past its declared freshness SLA, an installed or advisory version string fails a
  strict parse, or a collection field couldn't be read. Always flagged `needs-review`, never silently
  cleared or dropped. `assessment_reason_code` records which.

**Second axis, renamed: `confidence` → `provenance tier`, `HIGH`/`MEDIUM`/`LOW` (was `high`/`low`).**
`HIGH`/`MEDIUM`/`LOW` describe **which source/anchor produced the match** — a structural prior, not a
measured probability. The rename itself is the correction: "confidence" implied a calibrated number
this axis never was. A committed calibration loop (periodic spot-check of sampled verdicts against
manual ground truth, publishing measured precision per tier) accompanies the rename. The 2026-07-05
amendment's core safety rule carries forward, restated against the new three-value labels — **the
clean-verdict eligibility rule is an explicit allowlist, not "everything except LOW":** only `HIGH`
and `MEDIUM` provenance-tier matches may produce `FIXED` or `NOT-APPLICABLE`. **Only `LOW` is
suppressed** — a `LOW`-provenance-tier match that would otherwise read `FIXED` or `NOT-APPLICABLE`
routes to `UNKNOWN` instead (reason `identity-low-confidence`); a `LOW`-provenance-tier match against
an in-range advisory still surfaces as `OPEN (provenance: LOW)` — this carve-out only ever removes a
clean verdict, never a positive one, exactly as before. `MEDIUM` is deliberately clean-verdict-eligible
— consistent with the arbitrated research's own `MEDIUM`-tier examples (a KB/supersedence-derived
FIXED with a freshness caveat, a tight-range NVD CPE match, a `github_reviewed` OSV/GHSA hit), which
already include genuine FIXED/NOT-APPLICABLE outcomes, not just OPEN ones — stating this explicitly
here rather than leaving "not LOW" to imply it by omission.

**Naming choice — deliberately not the literal OASIS CSAF/VEX vocabulary
(`affected`/`fixed`/`not_affected`/`under_investigation`), even though the four states map closely
onto it.** Two reasons: `UNKNOWN` is intentionally broader than VEX's `under_investigation` — it also
covers a stale feed snapshot and an unparseable version string, neither of which is "under
investigation" in the VEX sense, so reusing that word would undersell what it means here. And this
program already has a precedent for keeping internal vocabulary distinct from an external standard's
— ADR-0028 (agent-side component inventory collection; `status: accepted`, merged via PR #1958) names its
collection capability "component inventory," not "SBOM," reserving the standard's
name for the export/import document format rather than the internal model. Same logic here: keep
OPEN/FIXED/NOT-APPLICABLE/UNKNOWN as the internal vocabulary, map to real VEX terms only if/when a
VEX document is actually exported (plausible given roadmap Issue 18.5's SBOM-ingest direction) — the
mapping is cheap since the concepts already align.

**Disposition (triage) lifecycle is layered on top, orthogonal to this assessment axis, and is
out of this ADR's scope** — the module design doc proposed an 8-state disposition state machine
(`new`/`triaged`/`mitigated`/`accepted-risk`/`disputed`/`verification-failed`/`remediated`/`reopened`)
and its own risk-acceptance fields (`risk_acceptance_ref`, `accepted_risk_review_date`, required
together whenever disposition = `accepted-risk`). **Resolved by ADR-4004 (2026-07-16)** —
`docs/adr/4004-vulnerability-finding-disposition-lifecycle.md` reconciled this 8-state list against
`docs/adr-1005-execution-plan.md`'s M3 milestone (which had separately named 5 states) and CAVM v20's
gate model (ADR-4003), and ratifies a **9-state** list — this 8-state list plus `dismissed` (a
disputed finding confirmed as a genuine matcher/identity mistake, not a real finding) — as M3's
disposition-lifecycle spec. Read ADR-4004 for the authoritative state definitions, required fields,
and `gate_state` reconciliation; this amendment's 8-state list is superseded by it, not a still-open
reconciliation with Dave Rae. Coverage (this ADR's other contribution) is unaffected by this
amendment: UNKNOWN-fraction + LOW-provenance-tier-fraction per endpoint, stamped as-of-inventory.

**Row lifecycle on re-assessment: never delete, unlike ADR-0023's shipped in-server pattern.**
ADR-0023 Decision 5's in-server engine **deletes** a row when it resolves to a clean verdict
(`potential`→`assessed-clean` disposal), which is safe there because that engine carries no
disposition/triage state on the row — there is nothing to lose. **The module's row carries
disposition and risk-acceptance state on the same row as the assessment (§4.2 of the module design
doc), so this delete-on-clean pattern must NOT be ported** — deleting a row on a `FIXED`/
`NOT-APPLICABLE` re-assessment would silently destroy an attached `accepted-risk`/`disputed`
disposition, its `risk_acceptance_ref`, and its audit trail, with no record the finding or its
acceptance ever existed. The module's re-assessment must update the assessment fields in place and
leave the row (and its disposition state) intact; a genuine `FIXED` assessment overrides a stale
`accepted-risk`/`mitigated`/`disputed`/`verification-failed` disposition annotation, but "override"
means transitioning it (e.g. to `remediated`), never deleting the row out from under it.

**Reconstructability is split, unlike ADR-0023's single-property claim.** ADR-0023 states its
findings store is "fully reconstructable from `SoftwareInventoryStore` + `NvdDatabase`... a
lost/corrupted findings store rebuilds deterministically" — true there because every field on that
row derives from source data. On the module's combined findings+disposition row, this property now
**splits**: assessment fields (status, provenance tier, reason code) are reconstructable from the
CVE feeds + inventory API, exactly as before; disposition fields (`disposition`, `disposition_owner`,
`disposition_notes`, `risk_acceptance_ref`, `accepted_risk_review_date`) are **human-authored and
NOT reconstructable** — a "rebuild the findings store from scratch" recovery, reasoning by analogy
to ADR-0023's stated property, would silently lose every risk acceptance and triage decision ever
recorded. The module's disposition columns must be covered by ordinary Postgres backup/PITR, not
treated as rebuildable state.

**Observability — a metric family is owed, not yet named.** Mirroring ADR-0023's own precedent
(naming concrete metrics in its Consequences section before any code existed): the coverage
dimension this ADR claims as in-scope needs a metric surface for UNKNOWN-rate and provenance-tier
distribution per endpoint/fleet, and the SLA-breach fields (`sla_breached`, `sla_breach_days`) need
their own counters. Exact metric names are an implementing-PR decision, not fixed here — flagged so
it isn't silently skipped, the same discipline ADR-0023 followed.

**`/readyz` posture diverges from ADR-0023 by design.** ADR-0023's findings store is wired into the
server's `/readyz` `stores_ok` conjunction (its Decision 8). The module's findings+disposition store
is **its own Postgres, with no `/readyz` coupling to the server at all** — a deliberate consequence
of it being a separate deployable (ADR-1005 Decision 3 / `docs/adr-1005-execution-plan.md` Decision
11), not an oversight. Naming this explicitly so an operator reading only this ADR doesn't assume the
module follows the in-server health-check pattern; the module needs its own readiness/health surface,
not the server's.

**Scope note.** This amendment governs the assessment vocabulary as adopted by the Vulnerability
Management UCE module. It does **not** retroactively change ADR-0023's in-server implementation
(frozen, grandfathered under ADR-1005 surface #2, `docs/adr/0023-vulnerability-correlation-engine.md`)
— that document continues to accurately describe what was actually shipped in-server (`potential` +
`confidence`, as its own amendment defines), and is not being rewritten to match. See ADR-0023's own
pointer note.

**Ownership.** Same as the 2026-07-05 amendment: Andy owns the finding-status taxonomy, so this
amendment is again within the ADR owner's remit; recorded here rather than as a new ADR because it
refines this ADR's core taxonomy a second time. Route through the same `/governance` path on the
implementing PR. **Not yet ratified** — this amendment has not been through `/governance` or been
presented to @FortitudeEtc as of this writing; treat as proposed pending that review, notwithstanding
this document's overall `status: accepted`.
