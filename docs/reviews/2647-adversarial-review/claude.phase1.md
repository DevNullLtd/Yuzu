# claude — Phase 1 independent review
Target: cb69991f..3cc9f417, branch docs/governance-followups-2619-2620 (#2619 ledger provenance, #2620 prose ownership). Doc-only.
Reviewed at HEAD 3cc9f417 in /home/fraser/Yuzu/.claude/worktrees/gov-followups-2619-2620.

## Acceptance-criteria verdicts (anchors first)

**#2619 — all four criteria MET.**
- `source` (`governance-agent`/`collaborator`/`external-model`) in the field table (SKILL.md:1638); the rename from the issue's `agent`/`collaborator`/`external-model` to `governance-agent` is glossary-consistent (CLAUDE.md three-meanings) and is itself a recorded finding (C4 row).
- `refuted` distinct from `rejected`, with `refuted_by` (evidence) + `refuted_by_reporter` (independence) required-iff (SKILL.md:1655–1657); exercised by UP-2 in the shipped fragment.
- "Which sources a run is expected to record" stated, with the absent-row-is-uninformative reading (SKILL.md:1693–1703) and echoed honestly in governance.d/README.md:50–51.
- Settled before an automated writer exists.

**#2620 — criteria 1–2 MET; criterion 3 met for `.claude` but has a KNOWN, deferred counterexample** (`.codex` copy — see F6).
- Gate 2 docs-writer preamble now names in-code comments and log/error strings (check 6, SKILL.md:706–716) and the widened mandate paragraph (674–683); `.claude/agents/docs-writer.md` description + Documentation Domains updated to match.
- Absence classed as a truth finding (`I7`), never NICE, in the shared preamble (SKILL.md:374–380) — and the shared preamble block (fenced 164–434) is verifiably what every Gate 2/3/4/6 prompt receives, so "the others are told not to [file wording]" is structurally true, not aspirational.

## Findings

```
[F1]  HIGH · hi · test-run
Gate 8 step-4 park check reads CLEAN on the schema's own blessed park path (sparse supersession) — false negative on the one constraint it exists to see
- Location:  .claude/skills/governance/SKILL.md:1740–1743 (the jq check); :1327–1328 (the claim it falsifies); :1583–1587 (the minimum superseding-row set that creates the gap); adjacent: :1779–1790 (blind-spot list that omits this)
- Claim:     The check is row-wise (`select(disposition matches AND impact ∈ I1–I3)`), but on the documented write model a park arrives as a SUPERSEDING row whose required minimum set is schema_version, run_id, finding_id, recorded_by, recorded_at, pass_ordinal, reviewed_at_sha, disposition — no `impact`. No single row then carries both the park disposition and the impact list, so an I1/I2/I3 finding parked exactly as the schema prescribes is invisible to the check.
- Evidence:  Executed (jq-1.8.1): a two-row fragment — row 1 `{"finding_id":"F-1","disposition":"open","impact":["I1"],...}`, row 2 a conforming sparse supersession `{"finding_id":"F-1","disposition":"roadmap-#99","recorded_by":...,"reviewed_at_sha":...}` — gives exit 4, the documented CLEAN result. The write model makes this the canonical sequence: rows are "SUPERSEDED, never edited" (1420), `open` "exists so a finding can be recorded when it is RAISED" (1681–1685), and the #N park values are "fill[ed] in ... by SUPERSEDING ROW" (1655). SKILL.md:1327 claims "Constraint 1 is checkable against the ledger, and Gate 8 step 4 does it"; step 4's own blind-spot paragraph (1784–1790) enumerates GitHub labels, linked-to target labels, constraint 2, and author-thinned impact lists — not this.
- Scenario:  A run records a finding `open` with impact ["I1"] at Gate 4; Gate 7 parks it; the park is written as a conforming sparse supersession (`roadmap-#?`); Gate 8 step 4 exits 4; the reviewer, following the documented "only 4 is clean" rule, passes the gate. An I1 finding is parked with every rule followed and the machine check green — the precise outcome constraint 1 exists to prevent, with no gaming required.
- Inference: The same check's narrower false negatives were treated as blockers by this very lineage: the trailing-hyphen gap (24bb819a, "fix the check the last commit disarmed") and 2643's P8-02 ("A clean result presented as coverage the check cannot deliver is false assurance", severity BLOCKING, fixed). By the repo's own derivation this is I3 (clean result presented as constraint coverage; the caller cannot tell) → base HIGH, E3 → HIGH.
- Anchor:    judgment — no external anchor covers Gate 8 step 4 (it evolved in the merged #2581/#2643 workstream and was reconciled by this range's merge commit); graded against the branch's internal contract (SKILL.md:1327) and its own applied precedent (P8-02).
- Fix:       Either (a) make the check merge-aware — group rows by finding_id, field-wise merge (lists replace), then test disposition×impact on the LIVE view (a ~6-line jq reduce), or (b) add `impact` to the mandatory restatement set for any row whose disposition is `roadmap-*`/`linked-to-*`, and say so in the field table and step 4. Also add the current gap to step 4's blind-spot list until fixed.
- Falsifier: Any text in the range requiring a park/link supersession to restate `impact` (or requiring park dispositions to be recorded only on rows carrying the derivation facts). I searched SKILL.md, README, CLAUDE.md; the minimum-set sentence (1583–1587) and the disposition row (1655) contain no such requirement.
```

```
[F2]  MEDIUM · hi · test-run
The exemplar's only collaborator row (COL-1) violates the reporter_ref requirement the same branch defines — and exposes that the schema has no honest value for an in-session collaborator finding
- Location:  governance.d/2619-ledger-provenance-prose-ownership.sW31cX.jsonl line 48; contract at .claude/skills/governance/SKILL.md:1639; governance.d/README.md:78–83 (which spotlights COL-1 without flagging this)
- Claim:     COL-1 carries `reporter_ref: "in-session operator direction: do not skip the round-5 Gate 8 pass..."` — free text describing an unrecorded verbal direction, not "a THIRD-PARTY-RETRIEVABLE reference: a PR review URL or id, a comment permalink, a transcript path". It is exactly "a string the author types freely, which is precisely the self-declared claim this field exists to replace".
- Evidence:  Field table SKILL.md:1639 (quoted above). My validator confirms every other required/required-iff clause on COL-1 passes; this one fails on the field's stated semantics (it passes a mere presence check). README's "worth not copying" list (four wrong rows, the nulled attestations, the impossible timestamps) does not include it, and README:78–83 actively directs template-readers' attention to COL-1 as the sole policy_floor exerciser.
- Scenario:  The README says this fragment "will be copied". The next run's collaborator row copies the pattern: a prose description in reporter_ref. The one property the artefact "most needs to be checkable" (1639) — that external review actually happened — degrades back to a claim made by the reviewed, under a CC8.1 evidence framing.
- Inference: Deeper than a bad value: an in-session verbal operator direction HAS no third-party-retrievable artefact, so the schema's required-iff has no satisfiable honest value for this case — the same "required field with no honest value for one of its cases" defect class the fragment itself records fixing (A-1, line 9). Either the field needs an explicit `unresolved`-style sentinel for in-session directions (with its cost stated), or COL-1 should have been recorded differently.
- Anchor:    anchor-issue-2619 Context ("that is exactly the property a source field makes visible") + the review brief's test-adequacy axis (does the shipped fragment conform to the schema the same branch defines). Non-blocking by the repo's own derivation (I6/I8, E3 → MEDIUM).
- Fix:       Supersede COL-1 with a reporter_ref pointing at something retrievable (the committed tuning-doc §10 paragraph narrating the direction, or the PR discussion once open), or add an explicit carve-out to 1639 for in-session directions and list COL-1's reporter_ref in the README's not-to-copy section.
- Falsifier: A reading of 1639 under which a prose description of an unrecorded conversation is "third-party-retrievable". The field's own text forecloses it ("Not a bare name — a name is a string the author types freely").
```

```
[F3]  MEDIUM · hi · static-read
Tuning doc §10 still asserts "this class is closed by the schema: the attestation set is exactly those four fields" — the exact sentence the canonical skill now calls false — corrected only by a later section with no marker at the site
- Location:  docs/governance-skill-tuning-2026-07.md:587–589 (wrong, present-voice); :615–617 (the correction, under "Round 9 — stopping"); canonical: SKILL.md:1439–1441 ("The five are ..."), 1468–1472 ("The first version of this sentence said four and called the class closed; waiver_rationale was found one round later. So treat any NEW ... field as joining the exemption by default — settled per field, never assumed away")
- Claim:     A reader of §10's round-8 section takes away (a) four attestation fields and (b) a class closed by assumption — both false against the canonical rule; the doc contradicts its own next section, which is precisely the defect shape this branch's G8-35 was raised (BLOCKING, "a reader ... takes 'only broken by changing the KIND of fix' at face value against the following section") and fixed for, three paragraphs earlier in the same document.
- Evidence:  Line 588–589: "Unlike the routes above, this class is closed by the schema: the attestation set is exactly those four fields." — normative present voice inside a paragraph stating current rule semantics ("it is row-scoped and exempt from the merge — never inherited, never cleared"). Round 9 (615–617) then reports "a fifth attestation-class field (waiver_rationale) left inside the merge by the sentence that declared the class closed at four."
- Scenario:  A future schema change adds a rationale-like field; its author consults §10 (the history document SKILL.md:1553 explicitly routes readers to), reads "closed ... exactly those four", and leaves the new field in the merge — re-opening the G8-32 erasure route.
- Inference: Mitigated but not neutralised by the new CLAUDE.md pointer rule (the tuning doc "loses on conflict") — that rule exists because this class recurred, and this is a live instance #4 shipped by the branch that added the rule. By the repo's derivation: I7 doc drift, E3 → MEDIUM.
- Anchor:    judgment (internal: CLAUDE.md-on-branch pointer block; the doc-layering heuristic makes the doc authoritative-feeling reference material).
- Fix:       One clause at 588–589: "closed at four — a claim round 9 disproved (waiver_rationale was the fifth); the canonical rule now presumes a new rationale-like field joins the exemption" — or recast the sentence in past tense as round-8 belief.
- Falsifier: A reading in which 587–589 is unambiguously historical narration. The surrounding sentences state current rule semantics in the same voice, so the tense does not disambiguate.
```

```
[F4]  MEDIUM · med · static-read
The exemplar models same-session subagent adjudication and refutation as satisfying the independence bar the canonical text says such actors cannot satisfy — and the README's not-to-copy list omits it
- Location:  fragment lines 40, 41, 49, 50 (`adjudicated_by: "architect (reporter of the finding; not the change's author)"`), line 3 (`refuted_by_reporter: "chaos-injector (not the reporter of UP-2, and not the change's author)"`); contract at SKILL.md:1544–1546 ("A subagent of the authoring session is not independent — it is the same actor under another name"), CLAUDE.md governance para (same sentence)
- Claim:     Every adjudication and the sole refutation in the first-ever ledger are attributed to governance agents spawned by the authoring session. Under the canonical text those are "the same actor under another name"; the rows' parentheticals assert the separation anyway, and the README's template guidance does not warn against copying it.
- Evidence:  Quoted field values above; SKILL.md:1544–1546. The skill does frame the requirement as "an AUDIT TRAIL, not a verified control" and independence as "ASSERTED" (1538–1546), so the rows are not schema-invalid.
- Scenario:  Next run's author de-escalates their own BLOCKING finding, records `adjudicated_by: <some subagent> (not the change's author)` copied from the exemplar, and the artefact-level read is identical to a genuinely independent adjudication — the "small forgery" pattern, taught by the template.
- Inference: The letter/spirit gap is acknowledged in the abstract by the skill; the defect is that the EXEMPLAR resolves the gap in the permissive direction on every occurrence and the README (which exists to say what not to copy) is silent on it. I6, E3 → MEDIUM.
- Anchor:    judgment (SOC 2 CC8.1 evidence framing in governance.d/README.md:31–36 — independence assertions are the load-bearing content of that evidence).
- Fix:       One bullet in README's not-to-copy list: the adjudications/refutation here name same-session subagents; per the skill they record the assertion only — a human or out-of-session adjudicator is what the field wants for a contested de-escalation.
- Falsifier: Evidence that the Gate 8 architect/chaos passes ran outside the authoring session (e.g. a separate operator-driven session per pass). The tuning doc describes the rounds as this branch's own Gate 8 iterations, so I consider that unlikely.
```

```
[F5]  LOW · hi · test-run
README's "Four rows are wrong as written" undercounts: the fragment's line 5 is a fifth wrong-as-written row (bare off-enum `"deferred-to-issue"`), acknowledged in-fragment but absent from the README enumeration
- Location:  governance.d/README.md:90–96; fragment line 5 (C2 pass 1, `"disposition":"deferred-to-issue"` — no `#N`), corrected by line 6's supersession ("the earlier row named no issue, which the field table requires")
- Claim:     My validator flags exactly five nonconforming rows (lines 5, 6, 14, 17 + the described line-22 no-op correction); the README enumerates four and does not mention line 5's off-enum disposition — the same truncated-bare-word shape step 4's hyphen note warns about for `roadmap`.
- Evidence:  Validator output: `line 5 fid=C2: off-enum disposition 'deferred-to-issue'` plus the four documented cases, nothing else. README:90 says "Four rows are wrong as written and correct only after supersession".
- Scenario:  A reader auditing the fragment against the README finds a fifth wrong row the README's census missed and reasonably distrusts the rest of the census — in a section whose own punchline is that its counts kept going stale.
- Inference: Ironic rather than dangerous: the README banned row COUNTS after being wrong three times, then kept a wrong-row count. LOW.
- Anchor:    judgment.
- Fix:       Either add line 5 to the enumeration or restate the passage count-free ("the rows superseded for being wrong as written are identifiable by their correcting rows; read through the merge").
```

```
[F6]  LOW · hi · compiled (gh) + static-read
"Closes #2620" will auto-close with acceptance criterion 3 carrying a known live counterexample, deferred to open issue #2639
- Location:  .codex/skills/governance/SKILL.md (0 occurrences of `reporter_ref`/`refuted`; docs-writer prompt is the pre-#2620 narrower prose rule); fragment rows C2 (deferred-to-issue #2639); gh: #2639 OPEN, P2/governance-deferred/tech-debt/ready-for-agent
- Claim:     #2620's criterion 3 is "No remaining disagreement between the prose-ownership section and any agent preamble that implements it." The Codex runner's docs-writer prompt is such a preamble and still disagrees; the branch knows this, recorded it, and filed #2639 — but the close claim is unqualified.
- Evidence:  grep count 0 for the new schema/mandate terms in .codex/skills/governance/SKILL.md; issue #2639 title: "Codex /governance docs-writer prompt is a narrower copy of the prose rule; PR #2631's replacement does not close it".
- Scenario:  #2620 closes; six weeks later a Codex-driven pass files wording findings from every agent because its prompt never got the consolidation; nobody reopens #2620 because it is closed.
- Inference: Handled about as well as a deferral can be (ledger row + issue + CLAUDE.md now names the .codex copy as a pointer that loses on conflict); the residual defect is only the unqualified "Closes". LOW.
- Anchor:    anchor-issue-2620 acceptance criterion 3.
- Fix:       PR body: "Closes #2620 (the .codex copy is tracked separately in #2639)" — or drop the auto-close keyword for #2620.
```

```
[F7]  LOW · med · test-run
Mixed-generation fragments: pre-#2619 rows have no `recorded_at`, but `recorded_at` is the merge-precedence key; only `schema_version` absence is defined as the pre-#2619 marker
- Location:  governance.d/2643-governance-fix-defer-discriminator.Jn60vR.jsonl (all 25 rows lack schema_version, reporter, source, recorded_at, reviewed_at_sha; use the old `agent` field); contract at SKILL.md:1424–1430, 1633
- Claim:     The schema anticipates coexistence ("A row without [schema_version] predates #2619"; reporter "Named `agent` before #2619") but the read rules never say how to order or merge rows that carry no `recorded_at` — the precedence key. A future append to 2643's fragment (appends to old fragments are expressly normal) produces a merge with undefined ordering against the un-timestamped rows.
- Evidence:  Validator output on 2643 (25/25 rows missing the new required fields); SKILL.md:1424 ("ordered by `recorded_at`") with no absent-key rule.
- Scenario:  A collaborator refutation is appended to a pre-#2619 fragment; two conforming readers order the un-timestamped originals differently relative to it — the "unstated convention means no reader can be right" failure the branch itself keeps citing.
- Inference: No supersessions exist in 2643 today, so nothing misreads yet. LOW.
- Anchor:    judgment.
- Fix:       One sentence in the field table: rows without `recorded_at` sort before all timestamped rows, in file order.
```

```
[F8]  INFO · med · static-read
Shared-preamble paste list covers "every Gate 2/3/4/6 prompt" — Gate 5 (chaos-injector) is excluded, yet chaos-injector authors ledger rows and the fragment's only refutation
- Location:  SKILL.md:161–162; fragment lines 2 (CH-5) and 3 (UP-2 refuted_by chaos CH-1)
- Claim:     The agent that wrote a BLOCKING row and executed the refutation is the one gate actor whose prompt is not required to carry the severity-derivation/prose/ledger preamble.
- Evidence:  "Paste this block verbatim into every Gate 2/3/4/6 prompt" (161–162).
- Scenario:  A chaos finding arrives in un-derived vocabulary; the recorder back-fills the derivation — workable (the non-agent-row rule covers recorder derivation), just unstated for this in-pipeline case.
- Inference: Likely deliberate (Gate 5 consumes findings rather than raising them, usually). INFO.
- Anchor:    judgment.
- Fix:       Either add Gate 5 to the paste list or say chaos rows take the recorder-derives path.
```

## What I verified and found SOUND (negative results, for the cross-examination)

- **Ledger conformance:** all 62 rows parse; my field-table validator reports exactly the five known-wrong sites (F5) and nothing else; required-iff clauses (`reporter_ref`, `refuted_by` pair, `adjudication_rationale`-iff-`adjudicated_by`) hold everywhere else; zero live `open`; 48 distinct findings; field-wise merge with row-scoped attestations computes cleanly; COL-1 is the sole policy_floor row exactly as README claims; merged stronger-of reads are consistent (A-1/A-3 at NICE with I9=INFO ∈ {LOW,INFO}; G8-34/35 raised to BLOCKING matching I3→HIGH).
- **jq check semantics:** clean = exit 4, violation = exit 0, missing file = exit 2 — all reproduced on jq-1.8.1 (the exact version the doc cites); both shipped fragments exit 4; the scalar-impact normalisation claim is honest (`if type == "array"` branch present).
- **Write recipe:** mktemp -u + noclobber create works; a suffix collision refuses loudly with the file intact; the documented trap is real — reusing `: >` outside the subshell truncated to 0 bytes at exit 0 (measured); `>>` appends under 20-way parallelism gave 20/20 lines, 0 corrupt, 20 distinct ids (consistent with the fragment's CH-1 refutation evidence).
- **Changelog policy floor:** `python3 scripts/assemble-changelog.py --check` → "Changelog fragment lint OK — 132 fragment(s)"; no direct CHANGELOG.md edit in the range; fragment name `2619-...changed.md` conforms (`<PR-or-issue-number>`, issue number legal per changelog.d/README.md).
- **40k ceiling:** CLAUDE.md 31,163 bytes; .claude/routed-concerns.md 31,902 bytes — both under; routed-concerns.md untouched by the diff.
- **Conflict markers:** none in any changed doc file.
- **Stale-copy sweep:** no surviving `"agent"` field references, latest-row-wins phrasing, blanket docs-writer BLOCKING, or four-attestation claims anywhere in the changed set EXCEPT the F3 site; CLAUDE.md's rule-3 six-item summary matches the skill's list item-for-item; the changelog fragment's summary matches final (round-9) semantics — G8-31's fix held.
- **#2620 structural claim:** the prose rule (including "if you are any other agent, do not file it at all") sits INSIDE the fenced shared-preamble block (SKILL.md:164–434) that is pasted into every Gate 2/3/4/6 prompt — so the consolidation claim is enforced by construction where the pipeline runs, not just asserted.
- **Portability:** the two-step mktemp keeps the `XXXXXX` trailing in the template actually passed to `mktemp -u`, so the BSD/macOS constraint is respected by construction (BSD not testable on this host); `set -o noclobber` and `printf '%s\n' ... >>` are POSIX.

VERDICT:  BLOCK — F1: the Gate 8 step-4 park check, whose documented purpose is "the only part of the park contract a machine can see", provably (test-run) reads CLEAN when an I1/I2/I3 finding is parked via the schema's own prescribed sparse-supersession write path, and SKILL.md:1327's "Constraint 1 is checkable ... and Gate 8 step 4 does it" is therefore false as shipped; everything else found is MEDIUM or below.

COVERAGE: Deep — correctness/cross-document consistency (all seven changed files cross-checked pairwise + against the fragment), test adequacy (62-row fragment machine-validated against the field table; merge/stronger-of recomputed; both jq arms + exit codes exercised), concurrency (append model measured 20-way; noclobber create/collision/truncation measured), security-as-evidence (CC8.1 overclaim axis: F2, F4; README limitations section reviewed and found honest). Moderate — portability (GNU side of mktemp/noclobber/jq measured; BSD/macOS reasoned from the template shape, no Darwin host). Skimmed — the non-doc files in the range (scripts/test/*, ci.yml, detect-code-change.sh etc.): they arrived via the merged, already-reviewed #2581/#2616/#2642/#2643 dev PRs and are outside the declared scope; I read them only enough to confirm the merge brought them in unmodified relative to dev (git diff origin/dev...HEAD touches only CLAUDE.md + the seven scope files... verified via `git diff --stat origin/dev...HEAD`).

RAN:
- `git log --oneline cb69991f..3cc9f417` + `git diff --stat` (range = 11 branch commits + merged dev work)
- `git diff origin/dev HEAD -- CLAUDE.md` (branch's real CLAUDE.md delta: rules 3 rewrite + pointer block + ledger paragraph)
- `wc -c` CLAUDE.md=31163, routed-concerns=31902, SKILL.md=118410 — ceiling holds
- conflict-marker grep — none
- python validator over 62-row fragment (all required/required-iff/enums + field-wise merge + attestation row-scoping + live-open scan) — 5 hits, all documented-wrong rows; NONE live-open
- same validator over 2643 fragment — 25/25 rows pre-#2619 schema (F7)
- jq-1.8.1 park check: shipped fragment exit 4; 2643 exit 4; synthetic violation exit 0; missing file exit 2; **synthetic sparse-park false negative exit 4 (F1)**
- mktemp+noclobber create, loud collision, outside-subshell truncation (0 bytes, exit 0), 20-way parallel `>>` append: 20/20 clean
- `python3 scripts/assemble-changelog.py --check` → OK, 132 fragments
- `gh issue view 2639` → OPEN, P2 (F6)
- stale-copy greps ("agent" field, four-attestation, latest-row, blanket BLOCKING) across all changed files + .claude/agents/

FILES: .claude/skills/governance/SKILL.md (sections 138–434, 660–740, 1140–1360, 1370–1900); CLAUDE.md (worktree + origin/dev diff); .claude/agents/docs-writer.md (full diff); governance.d/README.md (full); governance.d/2619-ledger-provenance-prose-ownership.sW31cX.jsonl (all 62 rows); governance.d/2643-governance-fix-defer-discriminator.Jn60vR.jsonl (schema-level); changelog.d/2619-governance-ledger-provenance-and-prose-ownership.changed.md; changelog.d/README.md; docs/governance-skill-tuning-2026-07.md (§10 + structure); .codex/skills/governance/SKILL.md (grep-level); anchors in /tmp/yuzu-advrev-gov2619/.
