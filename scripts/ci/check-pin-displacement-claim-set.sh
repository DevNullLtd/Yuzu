#!/usr/bin/env bash
# check-pin-displacement-claim-set.sh — drift gate for the "what causes a replay-ring pin
# displacement" claim, which is stated independently on every surface in STATING_SURFACES
# (see the array below) plus changelog.d fragments.
#
# WHY THIS EXISTS. #2740 falsified the claim "a full pin-slot set means admission accounting
# has drifted". Correcting it across its surfaces took repeated review passes — the run
# ledger for that work is governance.d/2740-streamed-post-flip-set.csK3yu.jsonl, which is
# the one home for how many and what each found; this comment deliberately does not restate
# a count. The shape that mattered is what recurred: the claim lives as an independent
# paraphrase on every surface that mentions it, so each pass found and fixed a different
# subset. The pass that designated a single normative home and had every other site cite it
# STILL shipped two stale copies — one in a customer changelog, one in the `/metrics` HELP
# string — under four reviewers actively looking for exactly that. A convention did not
# hold. This does.
#
# WHAT IT CHECKS, AND WHY THAT AND NOT THE PROSE. It does NOT try to diff the derivation —
# the lexical-gate approach walls at exactly that boundary and is parked for that reason.
# What it checks is the part that is machine-comparable: the CAUSE SET, i.e. which counters
# each surface names as explaining a displacement. That set is enumerable, it is what an
# on-call engineer acts on, and every defect this gate exists to catch was a disagreement
# about its membership:
#
#   - the alert expression subtracting a counter that explains nothing
#   - `/metrics` HELP saying "rule all three out"
#   - a changelog telling operators to alert via a netted rule that no longer exists
#
# (Each is recorded in the ledger cited above, with the pass that found it. The --selftest
# below reproduces every shape in this list and the runbook/changelog shapes an adversarial
# review added, so the list is exercised rather than asserted. Its case count is not
# restated here - run it.)
#
# THE INVARIANT, in two halves:
#   (a) `yuzu_mcp_bridge_pin_displaced_for_admission_total` is NOT a cause. A successful
#       reclaim releases one pin and adds one charge, so the session stays AT cap and a slot
#       is always free. It must never appear in the alert expression - check (a) enforces
#       this structurally, by construction of the expression it parses. Prose telling the
#       reader to rule it out is a narrower, best-effort catch: check (c) scans for the two
#       specific phrasings that have actually shipped ("rule all three out", a netted-
#       expression description) and does not otherwise guarantee no such prose exists - a
#       new paraphrase of the same bad advice is not guaranteed to be caught.
#   (b) The two residual counters ARE the cause set. Every surface in STATING_SURFACES must
#       name BOTH, in its own CLAIM REGION — see #2827 below. changelog.d fragments are held
#       to both-or-neither instead: a release note need not enumerate counters, but naming
#       one while omitting the other is the drift shape.
#
# The runbook was NOT in (b) in the first version of this gate, while the workflow header
# claimed it was. Two external reviewers found that independently and blocked on it, each
# with a fixture: a runbook naming one residual passed green. That was the SECOND false-green
# this gate shipped; it is now covered and self-tested.
#
# #2827 — THE THIRD FALSE-GREEN, AND WHY (b) IS REGION-SCOPED, NOT WHOLE-FILE. The first
# region-less version of (b) tested each surface with a presence-only whole-file grep. On
# four surfaces a counter identifier occurs more than once (a metrics.describe() registration,
# a counter() pre-seed, a sibling alert rule, a sibling table row) — so rewriting ONLY the
# claim text to drop a cause left an unrelated sibling occurrence satisfying the grep, and the
# gate stayed green on exactly the drift it exists to catch. Found by an adversarial review of
# #2796 after merge, reproduced independently, filed as #2827. Root cause of why --selftest
# did not catch it: every fixture wrote exactly ONE occurrence per file, so masking was
# structurally unreachable in the fixtures regardless of what the checker did. (b) now
# extracts each surface's own CLAIM REGION (claim_region() below) and tests membership only
# inside it; the fixtures below carry realistic sibling occurrences so masking is reachable
# in --selftest too, and assert_realistic_fixture() guards against that property regressing.
# New check (d) is a narrower, best-effort tripwire for the sibling class this does not close:
# a claim restated on a surface/line that was never registered at all. See its own comment.
#
# Derivation and proof: `What a FULL PIN-SLOT SET means` in server/core/src/mcp_stream.hpp.
#
# Usage:  check-pin-displacement-claim-set.sh [REPO_ROOT]
# Exit:   0 = consistent, 1 = drift (message names the surface and the discrepancy)

set -euo pipefail

RECLAIM="yuzu_mcp_bridge_pin_displaced_for_admission_total"
RACED="yuzu_mcp_bridge_pin_release_raced_total"
FAILED="yuzu_mcp_bridge_pin_release_failed_total"
DISPLACED="yuzu_mcp_stream_pin_displaced_total"

ALERTS="docs/prometheus/yuzu-alerts.yml"
HELP="server/core/src/server.cpp"
MANUAL="docs/user-manual/metrics.md"
HOME_HDR="server/core/src/mcp_stream.hpp"
RUNBOOK="docs/ops-runbooks/mcp-stream-pin-displacement.md"
MCP_SERVER_DOC="docs/mcp-server.md"
ADR_DOC="docs/adr-1005-execution-plan.md"

# A multi-line claim_region() extractor's stop condition is a FORMAT ASSUMPTION about
# future edits (e.g. "the next table row starts with `|`"), not a syntactic guarantee -
# unlike an all-`grab`ped C++ describe() call bounded by a fixed string, prose/config
# formatting can drift without anyone intending to break the gate. If a future sibling
# item is reformatted so the stop pattern never matches, grab keeps consuming lines -
# which can absorb a sibling's unrelated mention of a residual counter into the CURRENT
# claim's region and silently re-open the #2827 masking class this gate exists to close.
#
# Two rounds of governance review on this same PR proved that for FREE-FORM PROSE (no
# syntax external to this file enforces a "next item" shape), no finite stop-pattern
# broadening closes this class - there is always another plausible reformat one step
# outside it (demonstrated against the ADR arm: `16) *Title*` defeated the first stop
# regex, and after broadening it to accept any numbered-list start, a lettered/decimal/
# em-dash sibling item still would have defeated the second). ADR_DOC and MCP_SERVER_DOC
# - the two arms with no syntax forcing a predictable sibling shape - are therefore
# single-line captures now (see their own arms), sidestepping the guessing game rather
# than continuing to chase it.
#
# The remaining multi-line arms (ALERTS, HELP, RUNBOOK, HOME_HDR) keep scanning multiple
# lines because their stop conditions are anchored to EXTERNAL SYNTAX a human can't
# casually reformat without also breaking something else that would be independently
# caught - YAML alerting-rule structure, a C++ string literal's closing paren, a markdown
# table's leading `|`, a Doxygen `///` comment prefix. Each still gets an explicit
# `terminated` flag (matching HELP's original design) so running off the end of the file
# without ever positively confirming the boundary fails closed rather than silently
# printing whatever was captured - "another pattern happened to match" and "we ran out of
# file" must not be indistinguishable outcomes. MAX_REGION_LINES bounds the same four arms
# against a terminator that matches nothing at all and runs on for many lines rather than
# EOF; it is sized well above every one of their real regions (the largest today, the hpp
# derivation block, is ~105 lines) - a first attempt at a tight shared cap (60) both
# false-DRIFTed on that legitimately-long block and did nothing against a 1-line
# absorption, which is why a size cap was never the right defense for the single-line
# arms' problem in the first place.
MAX_REGION_LINES=250

# THE STATING SURFACES - ONE list, and every check that iterates surfaces (checks b/c/d;
# the alert-expr check (a) is alert-specific by construction and operates on $ALERTS
# directly) derives from it.
#
# This is deliberately a single array because the two previous versions of this gate kept
# two hand-maintained lists, and BOTH holes found by review were a divergence between them:
# an external panel found the runbook missing from the cause-set check, and the next round
# found the derivation header missing from the phrase check. A list you have to remember to
# update twice is the defect, not the omissions it produces.
#
# Membership rule: a file belongs here if it STATES which counters explain a displacement.
# docs/mcp-server.md and the ADR were added after review proved they state it and were
# checked by nothing. If you add a surface that states the claim, add it HERE, give it a
# claim_region() arm below (its default arm is fail-closed - a surface with no extractor is
# reported as DRIFT, never silently unchecked), and every check picks it up.
STATING_SURFACES=(
    "$ALERTS"
    "$HELP"
    "$MANUAL"
    "$HOME_HDR"
    "$RUNBOOK"
    "$MCP_SERVER_DOC"
    "$ADR_DOC"
)

# ---------------------------------------------------------------------------
# claim_region() — extract the bounded region of a surface that actually states the cause
# set, so check (b) tests membership THERE rather than anywhere in the file (#2827).
#
# Protocol: on success, prints the region to stdout and returns 0. On failure, prints a
# single line "ERR <token>" and returns 1 - the caller maps the token to a DRIFT message.
# Every arm is fail-closed: an anchor that cannot be found (surface restructured), an anchor
# that matches more than once (ambiguous - would silently pick one and could pick the wrong
# one), or a terminator that goes missing (surface reformatted) is reported, never guessed
# past. Anchor/terminator matching uses index()/fixed strings, never a data-derived regex -
# several anchors below contain `|` and backticks, which are regex metacharacters.
#
# RESIDUAL LIMITATION (external review on #2838, reproduced and then extended). check (b)
# tests a returned region with a plain substring test, not "does the CLAIM SENTENCE name
# this counter" - and that gap is not confined to the multi-line arms. Reproduced on
# HOME_HDR: staling the raced mention in the derivation block while adding an in-region
# cross-reference comment naming it elsewhere in the same block passes (b) silently. Then
# reproduced again on MCP_SERVER_DOC, a SINGLE-line arm: the real claim there is one very
# long physical line, long enough to hold an unrelated same-line aside (e.g. a trailing
# `(cf. ...)` clause) after the true claim clause naming that counter is deleted - the
# region is one line, but "one line" does not mean "one clause". Single-line capture closes
# DIFFERENT-line masking (a sibling paragraph or table row) - that was its actual purpose,
# sidestepping the free-form-prose boundary-guessing problem documented above - but it was
# never a defense against a same-line decoy, and no arm here is immune to this class by
# construction. This FIX narrows the class #2827 reported - closing the four multi-line
# arms' most obvious sibling-row/comment shape - it does not close the class outright. Left
# as a follow-up (#2862) rather than folded into this fix because every prior attempt at
# tightening this mechanism (region-scoping itself, then single-line capture for free-form
# prose) shipped in its own governance round and each still left a gap the next review
# found - the fix earns its own review pass, not a rider on this one.
# ---------------------------------------------------------------------------
claim_region() {
    local f="$1"
    case "$f" in
        "$ALERTS")
            # Region = the YuzuMcpStreamPinDisplaced rule block, anchor line to the next
            # `- alert:` (commented or not - a commented-out sibling must not inflate the
            # region). Reuses check (a)'s proven anchor regex. Fail-closed like HELP below:
            # running off the end of the file without ever matching that stop line is
            # `terminated=0`, reported as ERR terminator-missing, never silently accepted as
            # an implicit EOF boundary.
            awk -v max="$MAX_REGION_LINES" '
                { line = $0; sub(/\r$/, "", line) }
                line ~ /^[[:space:]]*-[[:space:]]*alert:[[:space:]]*YuzuMcpStreamPinDisplaced([[:space:]]|#|$)/ {
                    n++
                    if (n == 1) { grab = 1; buf = line "\n"; cnt = 1; next }
                    grab = 0; next
                }
                grab && line ~ /^[[:space:]]*#?[[:space:]]*-[[:space:]]*alert:/ { grab = 0; terminated = 1 }
                grab {
                    cnt++
                    if (cnt > max) { overrun = 1; grab = 0; next }
                    buf = buf line "\n"
                }
                END {
                    if (n == 0) { print "ERR anchor-missing"; exit 1 }
                    if (n > 1)  { print "ERR anchor-ambiguous"; exit 1 }
                    if (overrun) { print "ERR region-overrun"; exit 1 }
                    if (!terminated) { print "ERR terminator-missing"; exit 1 }
                    printf "%s", buf
                }
            ' "$f"
            ;;
        "$HELP")
            # Region = the yuzu_mcp_stream_pin_displaced_total metrics_.describe() call,
            # anchor line through its closing `"counter");`/`"gauge");` line inclusive. A
            # lost terminator (reformatted, retyped) must not let the region run into the
            # next describe() call - that would silently re-open the #2827 mask inside this
            # very mechanism, so it is fail-closed rather than falling back to EOF.
            awk -v max="$MAX_REGION_LINES" '
                { line = $0; sub(/\r$/, "", line); stripped = line; sub(/^[[:space:]]+/, "", stripped) }
                index(stripped, "metrics_.describe(\"yuzu_mcp_stream_pin_displaced_total\",") == 1 {
                    n++
                    if (n == 1) { grab = 1; buf = line "\n"; cnt = 1; next }
                    grab = 0; next
                }
                grab {
                    cnt++
                    if (cnt > max) { overrun = 1; grab = 0; next }
                    buf = buf line "\n"
                    if (stripped == "\"counter\");" || stripped == "\"gauge\");") { grab = 0; terminated = 1; next }
                    if (index(stripped, "metrics_.") == 1) { grab = 0; next }
                }
                END {
                    if (n == 0) { print "ERR anchor-missing"; exit 1 }
                    if (n > 1)  { print "ERR anchor-ambiguous"; exit 1 }
                    if (overrun) { print "ERR region-overrun"; exit 1 }
                    if (!terminated) { print "ERR terminator-missing"; exit 1 }
                    printf "%s", buf
                }
            ' "$f"
            ;;
        "$MANUAL")
            # Region = the single markdown table row for yuzu_mcp_stream_pin_displaced_total.
            awk '
                { line = $0; sub(/\r$/, "", line); stripped = line; sub(/^[[:space:]]+/, "", stripped) }
                index(stripped, "| `yuzu_mcp_stream_pin_displaced_total` |") == 1 {
                    n++
                    if (n == 1) { buf = line "\n" }
                    next
                }
                END {
                    if (n == 0) { print "ERR anchor-missing"; exit 1 }
                    if (n > 1)  { print "ERR anchor-ambiguous"; exit 1 }
                    printf "%s", buf
                }
            ' "$f"
            ;;
        "$RUNBOOK")
            # Region = the cause table: header row through the last contiguous `|`-led line.
            awk -v max="$MAX_REGION_LINES" '
                { line = $0; sub(/\r$/, "", line); stripped = line; sub(/^[[:space:]]+/, "", stripped) }
                index(stripped, "| counter | what it means |") == 1 {
                    n++
                    if (n == 1) { grab = 1; buf = line "\n"; cnt = 1; next }
                    grab = 0; next
                }
                grab {
                    if (index(stripped, "|") != 1) { grab = 0; terminated = 1; next }
                    cnt++
                    if (cnt > max) { overrun = 1; grab = 0; next }
                    buf = buf line "\n"
                }
                END {
                    if (n == 0) { print "ERR anchor-missing"; exit 1 }
                    if (n > 1)  { print "ERR anchor-ambiguous"; exit 1 }
                    if (overrun) { print "ERR region-overrun"; exit 1 }
                    if (!terminated) { print "ERR terminator-missing"; exit 1 }
                    printf "%s", buf
                }
            ' "$f"
            ;;
        "$HOME_HDR")
            # Region = the "What a FULL PIN-SLOT SET means" ### block: anchor through the
            # last contiguous `///` line, stopping early at a later `/// ###` subheading.
            # Anchored on the `###`-prefixed heading, NOT the bare phrase - the phrase alone
            # also appears in a same-file cross-reference ("see ... above"), which would
            # make a bare-phrase anchor ambiguous today.
            awk -v max="$MAX_REGION_LINES" '
                { line = $0; sub(/\r$/, "", line); stripped = line; sub(/^[[:space:]]+/, "", stripped) }
                index(stripped, "/// ### What a FULL PIN-SLOT SET means") == 1 {
                    n++
                    if (n == 1) { grab = 1; buf = line "\n"; cnt = 1; next }
                    grab = 0; next
                }
                grab {
                    if (index(stripped, "/// ###") == 1) { grab = 0; terminated = 1; next }
                    if (index(stripped, "///") != 1) { grab = 0; terminated = 1; next }
                    cnt++
                    if (cnt > max) { overrun = 1; grab = 0; next }
                    buf = buf line "\n"
                }
                END {
                    if (n == 0) { print "ERR anchor-missing"; exit 1 }
                    if (n > 1)  { print "ERR anchor-ambiguous"; exit 1 }
                    if (overrun) { print "ERR region-overrun"; exit 1 }
                    if (!terminated) { print "ERR terminator-missing"; exit 1 }
                    printf "%s", buf
                }
            ' "$f"
            ;;
        "$MCP_SERVER_DOC")
            # Region = the anchor line ONLY - single-line capture, like MANUAL. NOT a
            # multi-line scan for "the next paragraph": an earlier version of this arm
            # scanned to a blank line or a bold-lead line, and governance review on this
            # same PR proved that a FINITE stop pattern for "what does the next paragraph
            # look like" can always be evaded by some plausible future reformat (the same
            # problem hit ADR_DOC below, worse - see its comment for the fuller account).
            # The real claim here has always been one physical line; single-line capture
            # cannot absorb a neighbor's content because it never looks past the anchor.
            # If this paragraph is ever legitimately rewrapped across multiple lines, this
            # extractor under-captures the wrapped portion - which fails CLOSED (the
            # region tests as "names one" or "names neither") and forces a claim_region()
            # update, rather than silently absorbing whatever text follows.
            awk '
                { line = $0; sub(/\r$/, "", line); stripped = line; sub(/^[[:space:]]+/, "", stripped) }
                index(stripped, "**A pin released to admit a new call") == 1 {
                    n++
                    if (n == 1) { buf = line "\n" }
                    next
                }
                END {
                    if (n == 0) { print "ERR anchor-missing"; exit 1 }
                    if (n > 1)  { print "ERR anchor-ambiguous"; exit 1 }
                    printf "%s", buf
                }
            ' "$f"
            ;;
        "$ADR_DOC")
            # Region = the anchor line ONLY - single-line capture, like MANUAL and (as of
            # this fix) MCP_SERVER_DOC above.
            #
            # This arm previously scanned multi-line, stopping at "the next numbered
            # decision item". Two rounds of governance review on this same PR proved that
            # approach cannot be made safe by broadening the stop pattern: the first
            # version (`^[0-9]+\.[[:space:]]+\*\*`, requiring bold emphasis) was defeated by
            # a sibling item written `16) *Title*` (paren delimiter, single-asterisk
            # emphasis) - neither the stop regex nor `^#` matched it, so the scan ran past
            # it into item 17, absorbing item 16's unrelated counter mention into decision
            # 15's claim region and masking a deliberately stale decision-15 claim. The
            # broadened second version (`^[0-9]+[.)][[:space:]]`, any ordered-list start)
            # closed THAT exploit but was then shown to still evade on other ordinary
            # reformats no maintainer would consider unusual - a lettered sub-item
            # ("15a."), a decimal sub-item ("15.1."), or an em-dash-led item ("— Decision
            # 16:"). A `MAX_REGION_LINES` backstop does not help either: a realistic
            # sibling-item absorption is 1-3 lines, far under any cap sized to tolerate
            # this block's own legitimate content.
            #
            # No finite "what does the next item look like" pattern closes this class -
            # there is always another plausible format one step outside it. Single-line
            # capture sidesteps the guessing game entirely: decision 15s real content,
            # including BOTH of its in-place amendments ("AMENDED 2026-08-05" and "FURTHER
            # AMENDED 2026-08-05"), has always been appended to the SAME physical line -
            # this file's own established editing convention is to lengthen a decision
            # in place, not to spawn a new paragraph - so single-line capture matches how
            # this file is actually edited, not merely how it happens to look today. A
            # future rewrap fails closed exactly as described in the MCP_SERVER_DOC arm
            # above and forces a claim_region() update rather than silently absorbing a
            # sibling item in whatever format it uses.
            awk '
                { line = $0; sub(/\r$/, "", line) }
                line ~ /^15\.[[:space:]]+\*\*MCP Streamable HTTP transport/ {
                    n++
                    if (n == 1) { buf = line "\n" }
                    next
                }
                END {
                    if (n == 0) { print "ERR anchor-missing"; exit 1 }
                    if (n > 1)  { print "ERR anchor-ambiguous"; exit 1 }
                    printf "%s", buf
                }
            ' "$f"
            ;;
        *)
            printf 'ERR no-extractor\n'
            return 1
            ;;
    esac
}

# (ROOT is re-read below for the normal path.)
# --selftest: prove the detector reddens on each defect shape it claims to catch, using
# fixtures in a scratch dir - never the real tree. Runs in CI BEFORE the real check, on the
# plugin-spawn-gate.yml precedent: a gate nobody has watched fail is an assertion, not a
# check (claim-discipline rule 5).
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    pass=0; failed=0

    # fixture() builds a minimal but REALISTIC tree: every maskable surface (alerts.yml,
    # server.cpp, metrics.md, the runbook) carries the SAME sibling-occurrence shape the
    # real files do - a registration/pre-seed pair, a sibling alert rule, a sibling table
    # row - so a mutation that stales ONLY the claim region while leaving siblings intact is
    # reachable here. The three surfaces that are protected today (exactly one occurrence
    # each in the real tree - mcp_stream.hpp, mcp-server.md, the ADR) still get an
    # anchor-uniqueness stress: mcp-server.md's anchor PHRASE occurs twice (a mid-line
    # cross-reference), and the ADR gets sibling numbered items naming one residual each, so
    # the region-scoping itself is exercised even where masking is not realistic today.
    fixture() {
        rm -rf "$tmp/t"; mkdir -p "$tmp/t/docs/prometheus" "$tmp/t/docs/user-manual" \
            "$tmp/t/docs/ops-runbooks" "$tmp/t/server/core/src" "$tmp/t/changelog.d"

        cat > "$tmp/t/$ALERTS" <<'YML'
groups:
  - name: mcp
    rules:
      - alert: YuzuMcpStreamPinDisplaced
        expr: |
          increase(yuzu_mcp_stream_pin_displaced_total[15m]) > 0
        labels:
          severity: warning
        annotations:
          description: >-
            causes are yuzu_mcp_bridge_pin_release_raced_total and
            yuzu_mcp_bridge_pin_release_failed_total.
      - alert: YuzuMcpBridgePinReleaseFailed
        expr: |
          yuzu_mcp_bridge_pin_release_failed_total > 0
        labels:
          severity: warning
        annotations:
          description: >-
            a release attempt threw and was contained; the other residual is
            yuzu_mcp_bridge_pin_release_raced_total.
YML

        cat > "$tmp/t/$HELP" <<'CPP'
metrics_.describe("yuzu_mcp_bridge_pin_release_raced_total",
                  "sibling registration, not the claim",
                  "counter");
metrics_.describe("yuzu_mcp_bridge_pin_release_failed_total",
                  "sibling registration, not the claim",
                  "counter");
metrics_.describe("yuzu_mcp_stream_pin_displaced_total",
                  "Rule THOSE TWO out: yuzu_mcp_bridge_pin_release_raced_total and "
                  "yuzu_mcp_bridge_pin_release_failed_total.",
                  "counter");
metrics_.counter("yuzu_mcp_bridge_pin_release_failed_total");
metrics_.counter("yuzu_mcp_bridge_pin_release_raced_total");
CPP

        cat > "$tmp/t/$MANUAL" <<'MD'
| `yuzu_mcp_bridge_pin_release_raced_total` | counter | the release lost a race. |
| `yuzu_mcp_bridge_pin_release_failed_total` | counter | the release threw. |
| `yuzu_mcp_stream_pin_displaced_total` | counter | Rule out yuzu_mcp_bridge_pin_release_raced_total and yuzu_mcp_bridge_pin_release_failed_total before treating this as drift. |
MD

        cat > "$tmp/t/$RUNBOOK" <<'MD'
Intro prose.

   | counter | what it means | explains how much? |
   |---|---|---|
   | `yuzu_mcp_bridge_pin_release_raced_total` | the release lost a race | at most one slot |
   | `yuzu_mcp_bridge_pin_release_failed_total` | the release threw | one slot |
   | `yuzu_mcp_bridge_pin_displaced_for_admission_total` | a successful reclaim | zero |

Trailing prose repeats yuzu_mcp_bridge_pin_release_raced_total for narrative reasons.
MD

        cat > "$tmp/t/$HOME_HDR" <<'HPP'
    /// ### What a FULL PIN-SLOT SET means
    ///
    /// Only two paths cause a displacement: yuzu_mcp_bridge_pin_release_raced_total and
    /// yuzu_mcp_bridge_pin_release_failed_total.
    std::uint64_t publish_final(std::string_view event_type, std::string_view data) noexcept;
HPP

        cat > "$tmp/t/$MCP_SERVER_DOC" <<'MD'
Some other text.

**A pin released to admit a new call.** Explains yuzu_mcp_bridge_pin_release_raced_total and yuzu_mcp_bridge_pin_release_failed_total as the two causes.

A cross-reference table row mentions "A pin released to admit a new call" again mid-line,
which must not count as a second anchor.
MD

        cat > "$tmp/t/$ADR_DOC" <<'MD'
14. **Earlier decision** unrelated, mentions yuzu_mcp_bridge_pin_release_raced_total in passing for context.
15. **MCP Streamable HTTP transport** reclaims (yuzu_mcp_bridge_pin_release_raced_total, #2795) and (yuzu_mcp_bridge_pin_release_failed_total, #2805).
16. **Later decision** mentions yuzu_mcp_bridge_pin_release_failed_total in passing for context.
MD

        : > "$tmp/t/changelog.d/x.md"
        assert_realistic_fixture
    }

    # The guard that guards the guard (#2827's root cause was fixtures that could not
    # exercise masking at all): fail the whole selftest run hard, not just one case, if a
    # future edit collapses fixture() back to one occurrence per file.
    assert_realistic_fixture() {
        local path count
        for path in "$ALERTS" "$MANUAL" "$ADR_DOC"; do
            count=$(grep -c -- "$RACED" "$tmp/t/$path" || true)
            [ "${count:-0}" -ge 2 ] || { printf 'FIXTURE BUG: %s has only %s raced occurrence(s), need >=2 to exercise masking\n' "$path" "${count:-0}" >&2; exit 2; }
            count=$(grep -c -- "$FAILED" "$tmp/t/$path" || true)
            [ "${count:-0}" -ge 2 ] || { printf 'FIXTURE BUG: %s has only %s failed occurrence(s), need >=2 to exercise masking\n' "$path" "${count:-0}" >&2; exit 2; }
        done
        count=$(grep -c -- "$RACED" "$tmp/t/$HELP" || true)
        [ "${count:-0}" -ge 3 ] || { printf 'FIXTURE BUG: server.cpp has only %s raced occurrence(s), need >=3\n' "${count:-0}" >&2; exit 2; }
        count=$(grep -c -- "$FAILED" "$tmp/t/$HELP" || true)
        [ "${count:-0}" -ge 3 ] || { printf 'FIXTURE BUG: server.cpp has only %s failed occurrence(s), need >=3\n' "${count:-0}" >&2; exit 2; }
        count=$(grep -c -- "$RACED" "$tmp/t/$RUNBOOK" || true)
        [ "${count:-0}" -ge 2 ] || { printf 'FIXTURE BUG: runbook has only %s raced occurrence(s), need >=2\n' "${count:-0}" >&2; exit 2; }
        count=$(grep -c -- "A pin released to admit a new call" "$tmp/t/$MCP_SERVER_DOC" || true)
        [ "${count:-0}" -ge 2 ] || { printf 'FIXTURE BUG: mcp-server.md anchor phrase occurs only %s time(s), need >=2\n' "${count:-0}" >&2; exit 2; }
    }

    # expect(): $1 = case name, $2 = expected exit (0 clean / 1 drift), $3 = optional
    # substring that MUST appear in the gate's output. Without $3 a case can pass for the
    # wrong reason (#2827 finding: several pre-region cases mutated a whole file, which
    # under region-scoping trips anchor-missing rather than the "one residual" arm their
    # name claims) - the token makes that a hard failure instead of a silent pass.
    expect() {
        local out rc
        if out="$(bash "$self" "$tmp/t" 2>&1)"; then rc=0; else rc=$?; fi
        if [ "$rc" = "$2" ]; then
            if [ -n "${3:-}" ] && ! printf '%s' "$out" | grep -qF -- "$3"; then
                failed=$((failed+1))
                printf '  FAIL  %s (exit %s matched, but output missing expected substring: %s)\n' "$1" "$2" "$3"
                printf '        output was:\n%s\n' "$out" | sed 's/^/        /'
            else
                pass=$((pass+1)); printf '  ok    %s\n' "$1"
            fi
        else
            failed=$((failed+1)); printf '  FAIL  %s (expected exit %s, got %s)\n' "$1" "$2" "$rc"
            printf '        output was:\n%s\n' "$out" | sed 's/^/        /'
        fi
    }

    fixture; expect "baseline consistent fixture is clean" 0

    # --- check (a): reclaim counter must not appear in the alert expr ---
    fixture
    perl -pi -e 's{increase\(yuzu_mcp_stream_pin_displaced_total\[15m\]\) > 0}{(increase(yuzu_mcp_stream_pin_displaced_total[15m]) - increase(yuzu_mcp_bridge_pin_displaced_for_admission_total[15m])) > 0}' \
        "$tmp/t/$ALERTS"
    expect "netted expr subtracting the reclaim counter" 1 "expr references"

    # --- check (b): MASK cases - stale ONLY the claim region, siblings stay intact. This
    # is the #2827 class; MASK-ALERTS below is its literal repro. ---
    fixture
    perl -0777 -pi -e 's/causes are yuzu_mcp_bridge_pin_release_raced_total and\n            yuzu_mcp_bridge_pin_release_failed_total\./causes are yuzu_mcp_bridge_pin_release_failed_total only - the raced case cannot happen here./' \
        "$tmp/t/$ALERTS"
    expect "MASK-ALERTS: claim region loses raced, sibling rule keeps both (#2827 repro)" 1 "names one residual"

    fixture
    perl -0777 -pi -e 's/Rule THOSE TWO out: yuzu_mcp_bridge_pin_release_raced_total and "\n\s*"yuzu_mcp_bridge_pin_release_failed_total\./Rule it out: yuzu_mcp_bridge_pin_release_failed_total only./' \
        "$tmp/t/$HELP"
    expect "MASK-HELP: HELP claim loses raced, registration+pre-seed keep both" 1 "names one residual"

    fixture
    perl -pi -e 's/Rule out yuzu_mcp_bridge_pin_release_raced_total and //' \
        "$tmp/t/$MANUAL"
    expect "MASK-MANUAL: displaced row loses raced, its own row keeps it" 1 "names one residual"

    fixture
    perl -pi -e 's/^   \| `yuzu_mcp_bridge_pin_release_raced_total`.*\n//m' \
        "$tmp/t/$RUNBOOK"
    expect "MASK-RUNBOOK: raced table row deleted, prose sibling keeps it" 1 "names one residual"

    fixture
    perl -0777 -pi -e 's/Only two paths cause a displacement: yuzu_mcp_bridge_pin_release_raced_total and\n    \/\/\/ yuzu_mcp_bridge_pin_release_failed_total\./Only one path is modelled here: yuzu_mcp_bridge_pin_release_failed_total./' \
        "$tmp/t/$HOME_HDR"
    expect "MASK-HPP: derivation block loses raced" 1 "names one residual"

    fixture
    perl -pi -e 's/Explains yuzu_mcp_bridge_pin_release_raced_total and yuzu_mcp_bridge_pin_release_failed_total as the two causes\./Explains yuzu_mcp_bridge_pin_release_failed_total as the cause./' \
        "$tmp/t/$MCP_SERVER_DOC"
    expect "MASK-MCP-SERVER: claim paragraph loses raced, cross-ref phrase intact" 1 "names one residual"

    fixture
    perl -pi -e 's/reclaims \(yuzu_mcp_bridge_pin_release_raced_total, #2795\) and //' \
        "$tmp/t/$ADR_DOC"
    expect "MASK-ADR: Decision-15 loses raced, sibling item 14 keeps it" 1 "names one residual"

    # --- Gate 4 regression: the exact shape governance review reproduced against this PR,
    # against ADR_DOC's OLD multi-line extractor - a sibling decision item in an alternate
    # numbering format ("16)" instead of "16.") got absorbed into decision 15's region,
    # masking a deliberately stale decision-15 claim. That extractor is now single-line
    # capture (see claim_region()'s ADR_DOC arm), which closes the class structurally: this
    # fixture proves decision 15's own stale claim is caught NO MATTER what any sibling item
    # looks like, because no sibling item is ever scanned at all.
    fixture
    printf '%s\n' \
        '14. **Earlier decision** unrelated.' \
        '15. **MCP Streamable HTTP transport** the release throw is counted as `yuzu_mcp_bridge_pin_release_failed_total` (#2805, the raced case cannot happen here).' \
        '16) *Later decision, alternate numbering format* mentions yuzu_mcp_bridge_pin_release_raced_total in passing for unrelated context.' \
        '17. **Final decision** wraps up.' \
        > "$tmp/t/$ADR_DOC"
    expect "ADR: single-line capture catches a stale claim regardless of sibling item format" 1 "names one residual"

    # --- Gate 4 regression: the same proof for MCP_SERVER_DOC, whose OLD extractor scanned
    # to a blank line or bold-lead paragraph and could analogously absorb an adjacent
    # paragraph. Single-line capture means the next paragraph's format - or its very
    # existence - is irrelevant: this fixture's stale claim is caught even with a sibling
    # paragraph immediately following, no blank line, mentioning the missing residual.
    fixture
    printf '%s\n' \
        '**A pin released to admit a new call.** Explains yuzu_mcp_bridge_pin_release_failed_total as the cause; the raced case cannot happen here.' \
        '**Terminal durability.** Unrelated paragraph mentioning yuzu_mcp_bridge_pin_release_raced_total' \
        'in passing, immediately following with no blank-line separator.' \
        > "$tmp/t/$MCP_SERVER_DOC"
    expect "MCP_SERVER_DOC: single-line capture ignores an immediately-following sibling paragraph" 1 "names one residual"

    # --- Gate 4 regression: MAX_REGION_LINES actually fires when a terminator truly never
    # matches, for one of the arms that still legitimately scans multiple lines (HOME_HDR -
    # ADR_DOC/MCP_SERVER_DOC no longer use this mechanism at all, see their arms above).
    fixture
    { printf '    /// ### What a FULL PIN-SLOT SET means\n'
      printf '    /// yuzu_mcp_bridge_pin_release_raced_total and yuzu_mcp_bridge_pin_release_failed_total.\n'
      for i in $(seq 1 260); do printf '    /// plain prose line %d, never a /// ### subheading.\n' "$i"; done
    } > "$tmp/t/$HOME_HDR"
    expect "REGION-OVERRUN: hpp terminator never matches, exceeds MAX_REGION_LINES" 1 "exceeded"

    # --- Gate 4 regression: a terminator that never matches AND never runs past
    # MAX_REGION_LINES either (the file simply ends first) must still fail closed. Every
    # remaining multi-line arm's `terminated` flag (added alongside MAX_REGION_LINES) is
    # what catches this - "another pattern happened to match" and "we ran out of file"
    # must not be indistinguishable outcomes. Truncates hpp right after a few /// lines
    # with nothing following at all: grab never turns off, cnt stays far under the cap,
    # but `terminated` was never set.
    fixture
    printf '%s\n' \
        '    /// ### What a FULL PIN-SLOT SET means' \
        '    /// yuzu_mcp_bridge_pin_release_raced_total and yuzu_mcp_bridge_pin_release_failed_total.' \
        > "$tmp/t/$HOME_HDR"
    expect "TERMINATOR-MISSING: hpp block runs to real EOF, under the line cap, never confirmed" 1 "terminator"

    # --- check (b): region names neither residual ---
    fixture
    perl -0777 -pi -e 's/   \| `yuzu_mcp_bridge_pin_release_raced_total`.*\n   \| `yuzu_mcp_bridge_pin_release_failed_total`.*\n//' \
        "$tmp/t/$RUNBOOK"
    expect "RUNBOOK region names neither residual (rows removed, header+reclaim row remain)" 1 "names neither"

    # --- check (b): anchor-loss, one per surface ---
    fixture; perl -pi -e 's/alert: YuzuMcpStreamPinDisplaced/alert: YuzuMcpStreamPinDisplacedRenamed/' "$tmp/t/$ALERTS"
    expect "ANCHOR-LOSS alerts.yml (alert renamed)" 1 "anchor not found"

    fixture; perl -pi -e 's/metrics_\.describe\("yuzu_mcp_stream_pin_displaced_total",/metrics_.describe("yuzu_mcp_stream_pin_displaced_total_v2",/' "$tmp/t/$HELP"
    expect "ANCHOR-LOSS server.cpp (describe() name reworded)" 1 "anchor not found"

    fixture; perl -pi -e 's/\| `yuzu_mcp_stream_pin_displaced_total` \|/| `yuzu_mcp_stream_pin_displaced_total_v2` |/' "$tmp/t/$MANUAL"
    expect "ANCHOR-LOSS metrics.md (row lead reworded)" 1 "anchor not found"

    fixture; perl -pi -e 's/\| counter \| what it means \|/| metric | what it means |/' "$tmp/t/$RUNBOOK"
    expect "ANCHOR-LOSS runbook (table header reworded)" 1 "anchor not found"

    fixture; perl -pi -e 's{/// ### What a FULL PIN-SLOT SET means}{/// What a FULL PIN-SLOT SET means}' "$tmp/t/$HOME_HDR"
    expect "ANCHOR-LOSS mcp_stream.hpp (### dropped from heading)" 1 "anchor not found"

    fixture; perl -pi -e 's/\*\*A pin released to admit a new call\./**A pin release admits a new call./' "$tmp/t/$MCP_SERVER_DOC"
    expect "ANCHOR-LOSS mcp-server.md (claim lead reworded)" 1 "anchor not found"

    fixture; perl -pi -e 's/^15\. \*\*MCP Streamable HTTP transport/17. **MCP Streamable HTTP transport/' "$tmp/t/$ADR_DOC"
    expect "ANCHOR-LOSS ADR (item renumbered)" 1 "anchor not found"

    # --- check (b): anchor-ambiguous ---
    fixture
    printf '\n      - alert: YuzuMcpStreamPinDisplaced\n        expr: |\n          0 > 0\n' >> "$tmp/t/$ALERTS"
    expect "ANCHOR-AMBIGUOUS alerts.yml (duplicate alert name)" 1 "ambiguous"

    fixture
    printf '| `yuzu_mcp_stream_pin_displaced_total` | counter | duplicate row |\n' >> "$tmp/t/$MANUAL"
    expect "ANCHOR-AMBIGUOUS metrics.md (duplicate row)" 1 "ambiguous"

    # --- check (b): terminator-missing ---
    fixture
    perl -pi -e 's/"counter"\);/"counter" );/' "$tmp/t/$HELP"
    expect "TERMINATOR-LOSS server.cpp (closing counter\\); line altered)" 1 "terminator"

    # --- check (b): no-extractor (a surface registered without a claim_region() arm) ---
    fixture
    cp "$self" "$tmp/no-extractor-gate.sh"
    perl -pi -e 's{("\$MCP_SERVER_DOC"\s*\n)}{$1}; ' "$tmp/no-extractor-gate.sh" >/dev/null # no-op, keep for clarity
    perl -pi -e 's/(STATING_SURFACES=\(\n)/$1    "docs\/unregistered-surface.md"\n/' "$tmp/no-extractor-gate.sh"
    printf 'yuzu_mcp_bridge_pin_release_raced_total yuzu_mcp_bridge_pin_release_failed_total\n' > "$tmp/t/docs/unregistered-surface.md"
    if out="$(bash "$tmp/no-extractor-gate.sh" "$tmp/t" 2>&1)"; then rc=0; else rc=1; fi
    if [ "$rc" = 1 ] && printf '%s' "$out" | grep -qF "no claim_region() extractor"; then
        pass=$((pass+1)); printf '  ok    %s\n' "NO-EXTRACTOR (surface registered with no claim_region() arm)"
    else
        failed=$((failed+1)); printf '  FAIL  %s (exit=%s)\n' "NO-EXTRACTOR (surface registered with no claim_region() arm)" "$rc"
        printf '        output was:\n%s\n' "$out" | sed 's/^/        /'
    fi

    # --- check (c): banned phrasing (kept from prior versions, now can live in-region) ---
    fixture
    printf '%s\n' 'Rule all three out against their counters.' >> "$tmp/t/$HELP"
    expect '"rule all three out" in the /metrics HELP' 1 "rule out three causes"

    fixture
    printf '%s\n' 'Rule all three out against their counters.' >> "$tmp/t/$HOME_HDR"
    expect "DERIVATION HEADER says to rule all three out" 1 "rule out three causes"

    fixture
    printf '%s\n' 'The shipped rule, which subtracts the explained paths.' >> "$tmp/t/$MCP_SERVER_DOC"
    expect "docs/mcp-server.md describes a netted rule" 1 "netted alert expression"

    # --- changelog.d: weaker both-or-neither rule ---
    fixture
    printf '%s\n' 'Alert via the shipped rule, which subtracts the explained paths.' \
        >> "$tmp/t/changelog.d/x.md"
    expect "changelog describing a netted rule" 1 "netted alert expression"

    fixture
    printf '%s\n' 'yuzu_mcp_stream_pin_displaced_total is explained by yuzu_mcp_bridge_pin_release_failed_total.' \
        > "$tmp/t/changelog.d/x.md"
    expect "CHANGELOG fragment names one residual without the other" 1 "names one residual"

    # --- check (d): unregistered-claim-restatement tripwire ---
    fixture
    printf '\nA new paragraph says yuzu_mcp_stream_pin_displaced_total is explained by yuzu_mcp_bridge_pin_release_raced_total alone.\n' \
        >> "$tmp/t/$MANUAL"
    expect "TRIPWIRE: displacement + one residual co-occur on an unregistered line" 1 "unregistered claim restatement"

    # --- CRLF robustness ---
    fixture
    perl -pi -e 's/\n/\r\n/' "$tmp/t/$ALERTS"
    expect "CRLF baseline stays clean" 0

    fixture
    perl -0777 -pi -e 's/causes are yuzu_mcp_bridge_pin_release_raced_total and\n            yuzu_mcp_bridge_pin_release_failed_total\./causes are yuzu_mcp_bridge_pin_release_failed_total only - the raced case cannot happen here./' \
        "$tmp/t/$ALERTS"
    perl -pi -e 's/\n/\r\n/' "$tmp/t/$ALERTS"
    expect "CRLF + MASK-ALERTS still catches the mask" 1 "names one residual"

    printf '\nselftest: %s passed, %s failed\n' "$pass" "$failed"
    [ "$failed" -eq 0 ] || exit 1
    exit 0
fi

ROOT="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
cd "$ROOT"

fail=0
note() { printf '  %s\n' "$*"; }
bad() { printf 'DRIFT: %s\n' "$*"; fail=1; }

for f in "$ALERTS" "$HELP" "$MANUAL" "$HOME_HDR"; do
    [ -f "$f" ] || { bad "missing surface: $f"; }
done
[ "$fail" -eq 0 ] || exit 1

# ---------------------------------------------------------------------------
# (a) The reclaim counter must not appear in the YuzuMcpStreamPinDisplaced expr.
#
# Extract the alert's expr block: from the alert name to the next `labels:` key.
# ---------------------------------------------------------------------------
expr_block="$(awk '
    # Tolerate a trailing comment on the alert line, and stop at ANY sibling key - an
    # earlier version stopped only at `labels:`, so a rule ordering `annotations:` first
    # (valid YAML) pulled annotation prose into the expr block and misdiagnosed it.
    /^[[:space:]]*-[[:space:]]*alert:[[:space:]]*YuzuMcpStreamPinDisplaced([[:space:]]|#|$)/ { grab=1; next }
    grab && /^[[:space:]]*(labels|annotations|for|keep_firing_for|-[[:space:]]*alert):/ { grab=0 }
    grab { print }
' "$ALERTS")"

if [ -z "$expr_block" ]; then
    bad "$ALERTS: alert YuzuMcpStreamPinDisplaced not found (renamed? then update this gate)"
elif printf '%s' "$expr_block" | grep -q "$RECLAIM"; then
    bad "$ALERTS: YuzuMcpStreamPinDisplaced's expr references $RECLAIM."
    note "A successful reclaim cannot cause a displacement, so subtracting it removes real"
    note "signal in proportion to ordinary client churn. It is also a process-wide total"
    note "while the displacement counter is per-session state, so the join cannot exist."
    note "See 'What a FULL PIN-SLOT SET means' in $HOME_HDR."
fi

# ---------------------------------------------------------------------------
# (b) Every surface's CLAIM REGION must name BOTH residual counters.
#
# Region-scoped, not whole-file (#2827): a counter identifier occurring elsewhere in the
# file - a metrics registration, a pre-seed, a sibling alert rule, a sibling table row -
# must not be able to satisfy this check on behalf of a stale claim. claim_region() extracts
# the bounded text that actually states the cause set; a registered surface with no
# extractor, whose anchor cannot be found or is ambiguous, whose terminator is lost, or
# whose region grows past MAX_REGION_LINES without ever finding its stop pattern (a sibling
# item reformatted so the multi-line scan never terminates - the same absorption shape as
# the original whole-file bug, reachable again through a broken terminator instead of a
# missing region), is reported as DRIFT rather than silently skipped or trusted past EOF.
# ---------------------------------------------------------------------------
for f in "${STATING_SURFACES[@]}"; do
    [ -f "$f" ] || { bad "missing surface: $f"; continue; }
    if ! region="$(claim_region "$f")"; then
        case "$region" in
            "ERR anchor-missing")
                bad "$f: claim-region anchor not found (surface restructured? update claim_region() in this script)."
                ;;
            "ERR anchor-ambiguous")
                bad "$f: claim-region anchor matches more than once (ambiguous) - narrow it in claim_region()."
                ;;
            "ERR terminator-missing")
                bad "$f: claim region has no terminator (surface reformatted? update claim_region())."
                ;;
            "ERR region-overrun")
                bad "$f: claim region exceeded $MAX_REGION_LINES lines without finding its stop pattern - a sibling item was likely reformatted and the extractor absorbed unrelated content. Update claim_region()."
                ;;
            *)
                bad "$f: registered stating surface has no claim_region() extractor - add one."
                ;;
        esac
        continue
    fi
    has_raced=0; has_failed=0
    [[ "$region" == *"$RACED"* ]] && has_raced=1
    [[ "$region" == *"$FAILED"* ]] && has_failed=1
    if [ "$has_raced" -ne "$has_failed" ]; then
        bad "$f names one residual counter but not the other in its claim region (raced=$has_raced failed=$has_failed)."
        note "Both are causes of a displacement; naming one implies the other has no signal,"
        note "which is exactly the defect $RACED was added to end."
    elif [ "$has_raced" -eq 0 ]; then
        bad "$f's claim region names neither residual counter."
        note "Either restate the cause set here, or remove it from STATING_SURFACES."
    fi
done

# changelog.d fragments get the weaker BOTH-OR-NEITHER rule, deliberately, and stay
# whole-file: a fragment is a small, self-contained bullet, not a surface where an unrelated
# sibling occurrence could plausibly mask a stale claim. A fragment may legitimately describe
# the fix without enumerating counter names at all - customer release notes are not a
# rule-out procedure - but naming ONE residual while omitting the other is the
# "#2795 is deliberately silent" shape that shipped once already, and that must fail.
for f in changelog.d/*.md; do
    [ -f "$f" ] || continue
    has_raced=0; has_failed=0
    grep -q "$RACED" "$f" && has_raced=1
    grep -q "$FAILED" "$f" && has_failed=1
    if [ "$has_raced" -ne "$has_failed" ]; then
        bad "$f names one residual counter but not the other (raced=$has_raced failed=$has_failed)."
        note "A fragment may name neither, but naming one implies the other has no signal."
    fi
done

# ---------------------------------------------------------------------------
# (c) No surface may instruct the reader to rule out against the reclaim counter.
#
# Phrase-based and deliberately narrow: it catches the exact wording that shipped twice
# ("rule all three out") without pretending to understand prose. Stays whole-file - broader
# than the claim region can only over-trigger, never mask.
# ---------------------------------------------------------------------------
for f in "${STATING_SURFACES[@]}" changelog.d/*.md; do
    [ -f "$f" ] || continue
    if grep -qiE 'rule[[:space:]]+(all[[:space:]]+)?three[[:space:]]+(of[[:space:]]+them[[:space:]]+)?out' "$f"; then
        bad "$f says to rule out three causes. There are two; the reclaim explains zero."
    fi
    if grep -qiE 'subtracts the explained paths|which subtracts|nets (them|all three) out' "$f"; then
        bad "$f describes a netted alert expression. The shipped rule is a plain threshold."
    fi
done

# ---------------------------------------------------------------------------
# (d) Unregistered-claim-restatement tripwire (#2827 follow-up, best-effort).
#
# (b) only checks surfaces already in STATING_SURFACES, in the region claim_region() already
# knows about. This catches a narrower but different gap: a NEW paraphrase appearing
# somewhere on a registered surface but outside any known region - naming the displacement
# counter and exactly one residual counter on the same physical line. It cannot see a claim
# split across lines or one that names no counters at all; it can only over-trigger (a real
# hit still needs a human to register or fix it), never mask, so it is safe to keep narrow.
# ---------------------------------------------------------------------------
for f in "${STATING_SURFACES[@]}"; do
    [ -f "$f" ] || continue
    hit="$(awk -v disp="$DISPLACED" -v raced="$RACED" -v failed="$FAILED" '
        {
            line = $0; sub(/\r$/, "", line)
            d = (index(line, disp) > 0)
            r = (index(line, raced) > 0)
            h = (index(line, failed) > 0)
            if (d && (r + h == 1)) { print NR; exit }
        }
    ' "$f")"
    if [ -n "$hit" ]; then
        bad "$f:$hit names the displacement counter and exactly one residual counter on the same line - looks like an unregistered claim restatement."
        note "If it is inside the surface's registered claim region, claim_region() is"
        note "mis-scoped - fix the extractor. If it is a NEW paraphrase, register it or"
        note "state both/neither."
    fi
done

if [ "$fail" -ne 0 ]; then
    printf '\n%s\n' "The cause set is: $RACED, $FAILED."
    printf '%s\n' "$RECLAIM is NOT a cause. Derivation: $HOME_HDR."
    exit 1
fi

printf 'pin-displacement claim set: consistent across %s surfaces (+ changelog.d):\n' "${#STATING_SURFACES[@]}"
printf '  %s\n' "${STATING_SURFACES[@]}"
