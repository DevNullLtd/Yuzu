# Codex Phase 2 — cross-examination and revised position

## Peer cross-examination

| PEER-ID | label | evidence I checked (file:line / command) | my severity |
|---|---|---|---|
| F1 | confirmed-independently | `.claude/skills/governance/SKILL.md:1420-1429,1583-1587,1732-1790`; independently built the two-row sparse supersession and reran the published jq filter on jq-1.8.1: exit 4 | HIGH |
| F2 | confirmed-independently | field contract at `.claude/skills/governance/SKILL.md:1638-1640`; decoded fragment line 48 and obtained the free-text `reporter_ref` quoted by the peer | MEDIUM |
| F3 | false-positive/unfair | `docs/governance-skill-tuning-2026-07.md:580-589,612-618`; the statement is inside the chronological Round 8 account and Round 9 explicitly records that the claim was disproved | none |
| F4 | not-verified | fragment lines 3, 40, 41, 49, 50 and `.claude/skills/governance/SKILL.md:1538-1546`; the row values and “subagent ... is not independent” rule are real, but neither the rows nor local git history proves those named actors ran in the authoring session | none |
| F5 | agrees-with-mine | same malformed C2 rows as my C-P1-1; my validator independently found line 5 off-enum and line 6 missing `recorded_by`/`reviewed_at_sha`; `governance.d/README.md:90-96` omits line 5 from its census | MEDIUM (severity changed from my Phase-1 HIGH) |
| F6 | agrees-with-mine | same acceptance-criterion-3 defect family as C-P1-2; `.codex/skills/governance/SKILL.md:55-72` is a narrower role prompt, while `.claude/skills/governance/SKILL.md:690-694` also independently narrows author-facing item 6; `gh issue view 2639` could not be rerun because this environment could not connect to api.github.com | HIGH, not peer's LOW |
| F7 | confirmed-independently | parsed `governance.d/2643-governance-fix-defer-discriminator.Jn60vR.jsonl`: 25/25 rows lack both `recorded_at` and `schema_version`; precedence is defined only by `recorded_at` at skill lines 1424-1430 | LOW |
| F8 | confirmed-independently | `.claude/skills/governance/SKILL.md:161-162,1035-1047`; shared block expressly names Gates 2/3/4/6 and the distinct Gate 5 prompt does not receive it | INFO |

Severity adjudication: F1 is HIGH because origin/dev `CLAUDE.md` standing rule 2 expressly floors “a false-green test offered as closure evidence for a blocking finding”; the recipe claims to machine-check the I1/I2/I3 park constraint and returns its documented clean code on the prescribed sparse write. F6/C-P1-2 is HIGH because #2620 acceptance criterion 3 is categorical (“No remaining disagreement”), and the `.claude` Gate 2 preamble itself still disagrees; filing a follow-up does not satisfy that closure criterion. Conversely, the malformed historical rows are real but the #2619 anchor requires the schema capabilities, not explicitly independent validity of every superseded historical row, so I withdraw the policy-floor rationale and grade the exemplar inconsistency MEDIUM.

## Coverage adoption and rebuttal

- Peer went deeper on the row-wise Gate 8 park check. I adopted F1 after recreating the sparse supersession from scratch and rerunning every claimed jq exit-code case.
- Peer went deeper on collaborator provenance and attestation examples. I adopted F2 after inspecting the decoded row. I did not adopt F4 because same-session provenance is the necessary fact and is not locally established; the schema itself warns that independence is asserted, not verified.
- Peer went deeper on the tuning-doc chronology. I rebut F3: a historical section may accurately record the false rule that existed in that round, and the immediately following round explains its failure.
- Peer went deeper on legacy-fragment coexistence and Gate 5 prompt coverage. I adopt F7 and F8 at LOW/INFO.
- Peer undercut my first finding's severity by treating the malformed C2 row as a README census defect. Reverification confirms the row defects but not my claimed anchor-level policy floor; I therefore downgrade it.
- Peer effectively ignored the narrower sentence inside the actual `.claude` Gate 2 prompt. Re-reading lines 381-399 against 690-694 confirms my original contradiction exactly, so C-P1-2 remains HIGH.

## Revised findings

[C-P1-1]  MEDIUM · CONFIDENCE(hi) · PROVENANCE(test-run) · severity-changed
The first ledger fragment contains schema-invalid historical rows and its README undercounts them
- Location:  `governance.d/2619-ledger-provenance-prose-ownership.sW31cX.jsonl:5-6`; `governance.d/README.md:90-96`
- Claim:     C2's first row has an off-enum disposition and its supersession omits two mandatory supersession fields, while the README's “Four rows” account omits the off-enum row.
- Evidence:  The field table requires `deferred-to-issue #N` and requires `recorded_by` plus `reviewed_at_sha` on supersessions; my 62-row validator reported line 5 off-enum and line 6 missing both fields.
- Scenario:  A template reader validates rows independently → the first exemplar fails its published schema and the README does not enumerate the failure → the reader must invent a compatibility exception.
- Inference: Supersession repairs the live finding view, but no text says it retroactively makes the earlier row schema-valid. The acceptance anchor nevertheless does not expressly require historical per-row validity, so this is not blocking.
- Anchor:    judgment; #2619 requires the schema capabilities but does not explicitly require every superseded exemplar row to validate independently.
- Fix:       Make the pre-publication exemplar conforming or document an explicit legacy/corrective-row validity rule, and make the README description count-free.

[C-P1-2]  HIGH · CONFIDENCE(hi) · PROVENANCE(static-read) · unchanged
Gate 2 narrows routed update obligations back to operator-facing docs
- Location:  `.claude/skills/governance/SKILL.md:690-694` (+ canonical definition at 381-399)
- Claim:     The delivered docs-writer preamble limits item 6 to an “operator-facing reference,” contradicting the canonical item that expressly includes author-facing migration ladders, registries, and invariants docs.
- Evidence:  Lines 392-395 say “whether operator-facing ... or author-facing”; lines 691-693 restate the same item as “the operator-facing reference.”
- Scenario:  A routed row imposes an author-facing update obligation → docs-writer applies its immediate Gate 2 restatement → it excludes that required doc → the missing-doc truth finding is not filed.
- Inference: Pointing generally to the shared list does not neutralise an explicit contradictory explanation in the prompt implementing that list.
- Anchor:    contract — anchor-issue-2620.md acceptance criterion 3: “No remaining disagreement between the prose-ownership section and any agent preamble that implements it.”
- Fix:       Say “update obligation ... whether operator- or author-facing,” matching item 6.
- Falsifier: The Gate 2 text is not delivered to docs-writer, or item 6 is canonically changed to exclude author-facing obligations.

[C-P2-1]  HIGH · CONFIDENCE(hi) · PROVENANCE(test-run) · new-from-cross-exam
The park-constraint check returns clean for the prescribed sparse supersession
- Location:  `.claude/skills/governance/SKILL.md:1327-1330,1420-1429,1583-1587,1732-1790`
- Claim:     The row-wise jq filter cannot see a live parked finding when the park disposition is written on a conforming sparse supersession that inherits `impact`.
- Evidence:  I created an `open` row with `impact:["I1"]` and a later `roadmap-#99` row containing the mandatory supersession minimum but no `impact`; the published jq filter returned exit 4, which lines 1755-1760 define as clean.
- Scenario:  An I1 finding is raised open → Gate 7 parks it with the documented sparse supersession → Gate 8 runs the mandated check → it reports clean and permits a forbidden park.
- Inference: The field-wise live view contains both `roadmap-#99` and `I1`; the row-wise test never constructs that view despite claiming constraint 1 is machine-checkable.
- Anchor:    contract — origin/dev `CLAUDE.md` standing rule 2 policy floor: “a false-green test offered as closure evidence for a blocking finding”; the checked impacts I1-I3 are blocking consequence classes.
- Fix:       Merge rows field-wise by `finding_id` before testing the live disposition and impact, or require park/link supersessions to restate impact.
- Falsifier: A canonical requirement that every park/link row itself restate `impact`, or the published command returns a non-clean result for the two-row fixture above.

[C-P2-2]  MEDIUM · CONFIDENCE(hi) · PROVENANCE(static-read) · new-from-cross-exam
The collaborator exemplar has no third-party-retrievable reporter reference
- Location:  fragment line 48 (`COL-1`); `.claude/skills/governance/SKILL.md:1638-1640`
- Claim:     `COL-1.reporter_ref` is a free-text description of an in-session direction, not the retrievable URL, id, permalink, or transcript path the field requires.
- Evidence:  The decoded value is `in-session operator direction: ...`; the field contract says “THIRD-PARTY-RETRIEVABLE” and rejects freely typed identity claims.
- Scenario:  A later run copies the only collaborator example → self-authored prose substitutes for retrievable external-review evidence → the source assertion cannot be checked.
- Inference: An unrecorded in-session direction has no honest value under the current required-iff rule.
- Anchor:    contract — anchor-issue-2619.md Context says working-copy independence is the property `source` makes visible; severity remains non-blocking because the acceptance list does not prescribe `reporter_ref`.
- Fix:       Point to a retrievable transcript/artifact or define an honest sentinel/carve-out and warn against copying this row.

[C-P2-3]  LOW · CONFIDENCE(med) · PROVENANCE(test-run) · new-from-cross-exam
Legacy rows have no ordering rule under the new precedence key
- Location:  `governance.d/2643-governance-fix-defer-discriminator.Jn60vR.jsonl`; `.claude/skills/governance/SKILL.md:1424-1430,1633`
- Claim:     The schema permits mixed-generation fragments but does not define ordering for pre-#2619 rows that lack `recorded_at`.
- Evidence:  All 25 legacy rows lack `recorded_at` and `schema_version`; the live-view rule orders only by `recorded_at`.
- Scenario:  A post-#2619 correction is appended to the legacy fragment → readers place untimestamped rows differently → they compute different live views.
- Inference: No current row in that fragment supersedes another, so the ambiguity is latent.
- Anchor:    judgment.
- Fix:       Define legacy rows as preceding timestamped rows, preserving file order among legacy rows.

[C-P2-4]  INFO · CONFIDENCE(med) · PROVENANCE(static-read) · new-from-cross-exam
Gate 5 does not receive the shared ledger/severity preamble
- Location:  `.claude/skills/governance/SKILL.md:161-162,1035-1047`
- Claim:     The shared preamble is mandated for Gates 2/3/4/6 but not the chaos-injector prompt even though chaos findings can become ledger rows.
- Evidence:  The paste instruction omits Gate 5 and Gate 5 has a separate preamble.
- Scenario:  Chaos-injector raises a finding without the shared derivation contract → the recorder must infer and backfill its ledger facts.
- Inference: Gate 5 usually transforms a risk register, so this is an ambiguity rather than a demonstrated failure.
- Anchor:    judgment.
- Fix:       Include Gate 5 or explicitly assign recorder-side derivation for chaos rows.

## Withdrawn

- Peer F3: withdrawn/not adopted — the four-field sentence is historical Round 8 narration and Round 9 explicitly records its falsification.
- Peer F4: withdrawn/not adopted — the necessary same-authoring-session fact could not be established from the repository; the row values alone only show the acknowledged, asserted-not-verified independence model.
- Peer F6's separate LOW finding is folded into C-P1-2; I could not independently verify the live GitHub issue state because `gh` had no network connection.

VERDICT:  BLOCK — the actual Gate 2 prompt still violates #2620's no-disagreement acceptance criterion, and the park check independently reproduces a false-green on the schema's prescribed sparse write path.
COVERAGE: Deep on correctness/logic, schema and cross-document consistency, test adequacy, evidence/provenance security, and shell/jq behavior; moderate on concurrency and portability (Linux execution, BSD/macOS static reasoning); resource/lifetime and executable privilege paths are inapplicable to the seven-file branch delta, with merged origin/dev implementation files checked only for branch attribution.
RAN:      jq-1.8.1 published filter on independently created sparse park (4), violation (0), clean (4), missing file (2), scalar impact violation (0); Python parse/validator over 62-row fragment (62 rows/48 findings; C2 line 5 off-enum, line 6 missing two minimum fields; decoded COL-1 and attestations); Python legacy check (25/25 lack `recorded_at` and `schema_version`); `python3 scripts/assemble-changelog.py --check` (PASS, 132); `git diff --check cb69991f..3cc9f417` (PASS); `wc -c` (CLAUDE.md 31,163; routed concerns 31,902); `gh issue view 2639` attempted and failed for unavailable network. Compile/unit/integration tests: N/A for doc-only branch delta. CI status: not independently queryable without network.
FILES:    both Phase-1 reports; both issue anchors; TARGET.md; origin/dev:CLAUDE.md; CLAUDE.md; `.claude/skills/governance/SKILL.md`; `.codex/skills/governance/SKILL.md`; `.claude/agents/docs-writer.md`; `.claude/routed-concerns.md`; both governance fragments; `governance.d/README.md`; tuning doc §10; changelog fragment and `changelog.d/README.md`.

## Delta since Phase 1

- C-P1-1 is downgraded HIGH→MEDIUM: the malformed rows are reproduced, but the cited acceptance anchor does not make independent historical-row validity a blocking requirement.
- C-P1-2 remains HIGH after re-reading the exact canonical and Gate 2 sentences; the peer missed this in-prompt operator/author narrowing.
- New HIGH C-P2-1 adopts the peer's sparse-supersession defect after independent jq reproduction.
- New MEDIUM/LOW/INFO findings adopt independently verified provenance, legacy-ordering, and Gate 5 gaps; two peer claims are not adopted.
