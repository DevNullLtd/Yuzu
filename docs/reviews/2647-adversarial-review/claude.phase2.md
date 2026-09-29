# claude — Phase 2 cross-examination
Target cb69991f..3cc9f417 @ worktree /home/fraser/Yuzu/.claude/worktrees/gov-followups-2619-2620. Peer: codex.phase1.md (2 findings, both HIGH, verdict BLOCK).

## 1. Cross-examination of codex's findings

| PEER-ID | label | evidence I checked (file:line / command) | my severity |
|---|---|---|---|
| C-P1-1 | **disagrees** (facts confirmed, severity adjudicated HIGH→MEDIUM; line-6 half is not a defect at all) | Re-parsed the fragment myself: line 5 `"disposition":"deferred-to-issue"` (off-enum, no `#N`) and line 6 missing both `recorded_by` and `reviewed_at_sha` — both byte-confirmed. BUT governance.d/README.md:90–96 explicitly censuses line 6: "`C2` at `pass_ordinal 2` recorded a human recorder in `reporter` ... and omitted `recorded_by`/`reviewed_at_sha`", states "They are left in place because superseding is the rule and rewriting is not — but **the merged view is the artefact**. Read it through the merge, never row by row." | MEDIUM (line-5 half only, merged into my F5) |
| C-P1-2 | **confirmed-independently** (adopted as F9; strengthened with git archaeology codex didn't do) | SKILL.md:692–694 "item 6 is a routed-concern row that names a doc as the **operator-facing reference** for the changed surface" vs canonical SKILL.md:391–401 "**whether operator-facing** (a user-manual page...) **or author-facing** (a migration ladder, a capability registry, a per-surface invariants doc...)". `git log -L` shows the narrowing sentence is BRANCH-AUTHORED (round-3 commit 33ac7d50); `git show cb69991f:...SKILL.md \| grep "operator-facing reference"` → 0 hits at the range base. | HIGH |

**C-P1-1 adjudication detail.** Codex's HIGH rests on "a parser enforcing the field table must reject the repository's first fragment (or must special-case it) → it cannot serve as the conforming template". Three problems:
1. **Half the claim is documented-by-design.** Line 6 is one of the README's four censused wrong-as-written rows, preserved deliberately under the supersede-never-edit rule; the canonical read rule ("the merged view is the artefact ... never row by row", README:93–96) is precisely the sentence codex's falsifier asked for, minus the per-row-repair demand — which no anchor makes. #2619's acceptance criteria govern the SCHEMA (source enum, refuted+evidence, expected-sources statement, settled-before-writer); they say nothing about per-row validity of the exemplar fragment. Codex's anchor citation ("Schema carries…" + CLAUDE.md standing-rule-2 policy floor) does not reach this artifact.
2. **No validator exists to do the rejecting** — the committed validator is out of scope by recorded operator decision (TARGET.md history note), so the failure sequence has no present actor; the merged live view of C2 is conforming (line 6's `deferred-to-issue #2639` supersedes line 5's off-enum value).
3. **The genuinely defective half is line 5** — off-enum and NOT in the README's census — which is my F5. That is a real propagation vector (a template reader has no flag telling them the bare `deferred-to-issue` is invalid) and I raise F5 LOW→MEDIUM absorbing it. But it is I7-class doc/evidence drift at E3 → MEDIUM by the repo's own derivation, not merge-blocking.
Also minor: codex's "my check reported **exactly these** row-level defects" undercounts — lines 14, 17 (joined reporters) and 22 (no-op correction) are also wrong-as-written (README-censused); my validator flags all five.

**C-P1-2 adjudication detail.** The narrowing is real and reachable: an agent applying the Gate 2 paraphrase excludes author-facing routed update obligations (migration ladder, capability registry) → the missing-required-doc truth finding for exactly those docs is never filed. The canonical item 6 goes out of its way to name both subclasses, so naming only one is a disagreement on its face, inside an agent preamble that implements the prose-ownership/absence rule — the literal text of #2620 acceptance criterion 3 ("No remaining disagreement between the prose-ownership section and any agent preamble that implements it"). The branch's own precedent treats this shape as blocking (G8-35: local sentence read at face value against adjacent canonical text, BLOCKING, fixed). Mitigation (the same sentence defers to "the six-item list in the shared preamble", which arrives in the same prompt) lowers likelihood but does not satisfy a criterion whose test is textual consistency. HIGH confirmed. Fix is one phrase.

## 2. Coverage: adopt or rebut

- **Axis codex went deep on that I skimmed: paraphrase-vs-canonical consistency WITHIN the Gate 2 preamble.** My phase-1 stale-copy greps targeted known-bad phrases ("agent" field, four-attestation, blanket BLOCKING) and structural checks (check 6 present, mandate paragraph present, shared block fenced+pasted); they could not catch a semantic narrowing in a branch-authored paraphrase. **Adopted** as F9 with my own verification (text comparison + git -L provenance). My phase-1 acceptance-verdict line "#2620 criterion 3 met for `.claude`" is hereby **withdrawn** — criterion 3 fails in two places: F9 (in-repo, blocking) and F6 (.codex copy, deferred to #2639, LOW).
- **Axis codex claimed deep but wasn't: test adequacy of the step-4 check.** Codex ran the same four jq synthetics I did (clean/violation/scalar/missing) but never composed the check with the schema's own write model — the sparse-supersession case (my F1). Their RAN line confirms the omission. Rebutted as a coverage claim; nothing to adopt.
- Codex raised no finding on: F1's false negative, COL-1's reporter_ref (F2), the tuning-doc §10 contradiction (F3), same-session independence modelling (F4), mixed-generation ordering (F7), Gate 5 paste-list exclusion (F8). Codex's review neither contradicts nor undercuts any of these.

## 3. Defence of my findings under attack

Codex's review contradicts none of my findings directly; the only implicit pressure is on F1 (codex ran step-4 checks and reported no such gap — absence of the finding, not evidence against it).

**F1 re-verified and defended at HIGH.** Repro re-run this phase (jq-1.8.1): seed row `open`+`impact:["I1"]`, then a supersession carrying exactly the documented minimum set (`schema_version, run_id, finding_id, recorded_by, recorded_at, pass_ordinal, reviewed_at_sha, disposition:"roadmap-#99"`) → exit 4, the documented CLEAN result. On the live-view caveat the merge added (SKILL.md ~1783–1786: "The check is ROW-wise while the artefact is supersession-based: a row parked early and re-dispositioned by a later row still matches. Before calling a match a violation, read the finding's LIVE view..."): it points the WRONG DIRECTION. It instructs live-view reconstruction only when the check MATCHES (to avoid false positives on superseded parks); it gives no instruction on the clean path, where my failure lives. Worse, the adjacent blind-spot paragraph ("What this check cannot see...") enumerates four gaps — GitHub labels, linked-to target labels, constraint 2, author-thinned impact — and SKILL.md:1330 tells the reader step 4 "states its own blind spots". A reader is therefore affirmatively told the blind-spot list is the complete one, and this gap is not on it, while :1327 still claims "Constraint 1 is checkable against the ledger, and Gate 8 step 4 does it." A documented limitation in the false-positive direction does not downgrade a false NEGATIVE the check's own text denies having: this is exactly the repo's I3 ("clean result presented as constraint coverage the check cannot deliver") that this lineage itself graded BLOCKING twice (24bb819a hyphen gap; 2643 P8-02). **HIGH, unchanged.** Falsifier re-checked: no text in the range requires a park supersession to restate `impact` (SKILL.md:1583–1587 "Only the fields that CHANGE need restating ... plus [8-field minimum]"; "A supersession is not a re-derivation: the original row keeps the TRIGGER/IMPACT/EXPOSURE facts").

F2, F3, F4, F6, F7, F8: unchallenged; spot re-checks unchanged. F5: severity-changed (see §1).

## 4. Revised full finding list

```
[F1]  HIGH · hi · test-run — unchanged (re-verified this phase, incl. live-view caveat)
Gate 8 step-4 park check reads CLEAN on the schema's own blessed park path (sparse supersession) — false negative on the one constraint it exists to see
- Location:  .claude/skills/governance/SKILL.md:1740–1743 (jq check); :1327 (the claim it falsifies); :1583–1587 (minimum superseding set, no impact); :1783–1798 (live-view caveat is match-direction only; blind-spot list omits this gap)
- Claim:     A conforming sparse park supersession carries no `impact`; no single row then holds both park disposition and impact list; an I1/I2/I3 finding parked exactly as prescribed exits 4 (clean).
- Evidence:  Re-run (jq-1.8.1): two-row fragment (seed open+["I1"], conforming 8-field minimum supersession roadmap-#99) → exit 4. :1327 "Constraint 1 is checkable against the ledger, and Gate 8 step 4 does it"; :1330 "step 4 ... states its own blind spots"; blind-spot list enumerates four other gaps, not this one; the ROW-wise caveat instructs live-view reads only "before calling a match a violation".
- Scenario:  I1 finding recorded open at Gate 4 → parked at Gate 7 via conforming supersession → step 4 exits 4 → reviewer follows "Only 4 is clean" → gate passes with the machine check green. No gaming required.
- Inference: Repo's own derivation: I3 (false assurance to a caller who cannot tell), E3 → HIGH; same lineage graded its own narrower false negatives BLOCKING (24bb819a, 2643 P8-02).
- Anchor:    judgment (internal contract SKILL.md:1327 + applied precedent P8-02)
- Fix:       (a) merge-aware check (group by finding_id, field-wise merge, test disposition×impact on the LIVE view, ~6-line jq reduce) or (b) require `impact` restated on any roadmap-*/linked-to-* supersession, stated in the field table + step 4; either way add the gap to the blind-spot list until fixed.
- Falsifier: Any range text requiring a park supersession to restate `impact` or confining park dispositions to derivation-bearing rows. Re-searched: none (1583–1587, 1655).
```

```
[F9]  HIGH · hi · static-read — new-from-cross-exam (adopted from codex C-P1-2, independently verified + provenance added)
Gate 2 docs-writer preamble narrows canonical required-doc item 6 to "operator-facing reference", dropping the author-facing half — a branch-authored disagreement that leaves #2620 acceptance criterion 3 unmet
- Location:  .claude/skills/governance/SKILL.md:692–694 (narrowing paraphrase); :391–401 (canonical item 6: "whether operator-facing ... or author-facing (a migration ladder, a capability registry, a per-surface invariants doc ...)")
- Claim:     The Gate 2 restatement of item 6 names only operator-facing references; the canonical item expressly includes author-facing update obligations; the two disagree inside the very preamble #2620 criterion 3 governs.
- Evidence:  Both texts quoted at the cited lines. `git log -L` on the sentence: introduced by round-3 commit 33ac7d50 on this branch; `git show cb69991f:.claude/skills/governance/SKILL.md | grep "operator-facing reference"` → 0 hits (the disagreement did not exist at the range base).
- Scenario:  A change owes an entry to an author-facing routed doc (migration ladder / capability registry); docs-writer applies its local Gate 2 sentence, classes the doc as not-required, and the I7 missing-required-doc truth finding — the one #2620 exists to guarantee — is never filed.
- Inference: Branch precedent G8-35 graded exactly this shape (local sentence read at face value against adjacent canonical text) BLOCKING and fixed it. The same-prompt presence of the canonical list mitigates likelihood but not the criterion, whose test is textual consistency.
- Anchor:    anchor-issue-2620 acceptance criterion 3: "No remaining disagreement between the prose-ownership section and any agent preamble that implements it."
- Fix:       One phrase at :693: "...names a doc as an update obligation for the changed surface — operator- or author-facing — not merely as reading for the reviewer."
- Falsifier: A reading under which "operator-facing reference" includes migration ladders and capability registries. Foreclosed: the canonical text defines those as the author-facing contrast class.
```

```
[F2]  MEDIUM · hi · test-run — unchanged
COL-1 violates the reporter_ref third-party-retrievability requirement the same branch defines; schema has no honest value for an in-session collaborator finding; README spotlights COL-1 without flagging it
(Full text as phase 1: fragment line 48 vs SKILL.md:1639; fix = supersede with a retrievable ref or add an explicit carve-out + README not-to-copy bullet.)
```

```
[F3]  MEDIUM · hi · static-read — unchanged
Tuning doc §10 still asserts "this class is closed by the schema: the attestation set is exactly those four fields" in present voice — the sentence the canonical skill now calls false — corrected only by a later section with no marker at the site
(Full text as phase 1: docs/governance-skill-tuning-2026-07.md:587–589 vs :615–617 and SKILL.md:1439–1441/1468–1472.)
```

```
[F4]  MEDIUM · med · static-read — unchanged
Exemplar models same-session subagent adjudication/refutation as satisfying the independence bar the canonical text says such actors cannot satisfy; README not-to-copy list is silent on it
(Full text as phase 1: fragment lines 3, 40, 41, 49, 50 vs SKILL.md:1544–1546.)
```

```
[F5]  MEDIUM · hi · test-run — severity-changed (LOW→MEDIUM, absorbing codex C-P1-1's line-5 half)
Fragment line 5 is a fifth wrong-as-written row (bare off-enum `"deferred-to-issue"`, no `#N`) absent from the README's four-row census — an unflagged propagation vector in the artifact the README says will be copied
- Location:  governance.d/2619-...jsonl line 5; governance.d/README.md:90–96
- Claim:     The census that exists to tell template readers which rows not to copy omits one; a reader copying line 5's bare disposition has no flag telling them it is off-enum.
- Evidence:  Byte-confirmed `"disposition":"deferred-to-issue"` on line 5; README:90 "Four rows are wrong as written..." enumerates C2@pass2 (line 6), G8-1, G8-4, and the no-op correction — not line 5. Merged live view IS conforming (line 6 supersedes with `#2639`).
- Scenario:  Next run copies the bare disposition from the unflagged row; the same truncated-bare-word shape step 4's hyphen note documents as a measured gap for `roadmap` recurs for defer.
- Inference: I7-class evidence-doc drift, E3 → MEDIUM. Codex's parser-rejection escalation to HIGH fails: no validator exists (deferred by operator decision) and the canonical read rule is the merged view, not row-by-row.
- Anchor:    judgment (README's own census purpose; anchor #2619 makes no per-row-validity demand)
- Fix:       Add line 5 to the census (or restate the passage count-free) and name the bare `deferred-to-issue` as a not-to-copy shape.
```

```
[F6]  LOW · hi · compiled+static-read — unchanged
"Closes #2620" auto-closes with criterion 3 carrying the known .codex counterexample deferred to open #2639 (and now F9's in-repo counterexample; F9 is the blocking instance, this stays the close-hygiene residue)
(Full text as phase 1; fix = qualify the close or drop the keyword.)
```

```
[F7]  LOW · med · test-run — unchanged
Pre-#2619 rows carry no recorded_at, but recorded_at is the merge-precedence key; no absent-key ordering rule
(Full text as phase 1: 2643 fragment 25/25 rows vs SKILL.md:1424–1430.)
```

```
[F8]  INFO · med · static-read — unchanged
Shared-preamble paste list covers Gate 2/3/4/6; Gate 5 (chaos-injector) excluded despite authoring ledger rows and the fragment's only refutation
(Full text as phase 1.)
```

Withdrawn: none of F1–F8. Withdrawn CLAIM: my phase-1 acceptance-verdict line "#2620 criterion 3 met for `.claude`" (falsified by F9).

## VERDICT + COVERAGE

**VERDICT: BLOCK** — two HIGHs: F1 (Gate 8 step-4 park check provably reads clean on the schema's own prescribed sparse-supersession park path while :1327 claims constraint-1 coverage — re-verified test-run this phase; the merge's live-view caveat points only at the false-positive direction and does not cure it) and F9 (adopted from codex: branch-authored Gate 2 narrowing of required-doc item 6 leaves #2620 acceptance criterion 3 textually unmet). Both fixes are small and local.

**COVERAGE:** Phase-1 coverage stands (deep: cross-doc consistency, fragment machine-validation, jq/write-recipe empirics, CC8.1 evidence axes; moderate: portability; skimmed: merged-dev non-doc files, confirmed outside the branch delta). Phase 2 adds: paraphrase-vs-canonical semantic drift inside agent preambles (previously grep-only — the axis codex caught and I adopted), git -L provenance of the disputed sentences, and re-verification of the README wrong-row census against raw bytes. Residual known gap: no Darwin host for the BSD mktemp leg (both reviewers static-read it, agreeing).

## Delta since phase 1
- Adopted codex's C-P1-2 as **F9 (HIGH, new)** after independent verification; strengthened it with git -L provenance (the narrowing sentence is branch-authored, round 3, absent at the range base) — and withdrew my phase-1 claim that #2620 criterion 3 was met for `.claude`.
- Adjudicated codex's C-P1-1 **down HIGH→MEDIUM**: its line-6 half is README-censused deliberate history under the canonical merged-view read rule (no anchor demands per-row validity; no validator exists); its line-5 half is real and absorbed into **F5 (LOW→MEDIUM)**.
- **F1 defended at HIGH** under the stress-test: repro re-run clean-on-sparse-park (exit 4); the merge's ROW-wise/live-view caveat instructs live-view reads only on a MATCH (false-positive direction), while :1330 tells readers the blind-spot list is stated and that list omits this gap — the false assurance stands.
- All other findings unchanged; final verdict remains BLOCK, now on F1 + F9.
