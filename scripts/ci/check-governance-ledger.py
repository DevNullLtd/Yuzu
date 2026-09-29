#!/usr/bin/env python3
"""check-governance-ledger.py - author-side self-consistency linter for a
governance.d run-ledger fragment.

WHAT THIS IS: a LINTER you run on YOUR OWN run's ledger fragment before you
push, to preview the self-consistency problems a strict reviewer will flag -
so a governance ledger stops taking multiple review rounds to converge. PR
#4337 took seven review rounds, every one a ledger-metadata self-consistency
defect while the code under review was byte-identical from round 1; each check
below is one of those rounds' lessons turned into a machine test.

WHAT THIS IS EXPLICITLY NOT: a blocking CI gate over the whole corpus.
Calibration against all ~330 historical fragments showed the strict rules here
are NOT project-wide invariants - most predate them. Wiring these as a required
check would break on the corpus. So this is an ADVISORY tool: the `/governance`
skill runs it on the current run's fragment as a pre-push step, and you can run
it by hand. The schema authority remains `.claude/skills/governance/SKILL.md`
(Gate 8 field table + the write/merge model at SKILL.md "the live view of a
finding is FIELD-WISE last-write-wins"); this script encodes a checkable subset
and loses to it on any conflict. It judges only mechanical field-consistency,
never whether a finding is true or a severity right.

THE LIVE VIEW IS A FIELD-WISE MERGE, NOT THE LAST ROW. SKILL.md is explicit: a
finding's live view is field-wise last-write-wins across every row sharing its
`finding_id`, ordered by `recorded_at` as a true instant (a row with no
`recorded_at` predates #2619 and sorts BEFORE timestamped rows, in file order;
ties break on higher `pass_ordinal`). List fields (`impact`/`exposure`) REPLACE
wholesale, and the five ATTESTATION fields (`adjudicated_by`,
`adjudication_rationale`, `refuted_by`, `refuted_by_reporter`,
`waiver_rationale`) are ROW-SCOPED and EXEMPT from the merge - they attach to
the row that performed the act, never inherited and never cleared forward.

A superseding row restates ONLY what changed - PLUS eight fields SKILL.md
requires on EVERY row regardless of whether they changed: `schema_version`,
`run_id`, `finding_id`, `recorded_by`, `recorded_at`, `pass_ordinal`,
`reviewed_at_sha`, `disposition`. That per-row minimum is checked on every row
that participates in the post-#2619 regime - identified by carrying ANY field
#2619 introduced (`_V2619_ONLY_FIELDS`: `schema_version`, `source`,
`reporter_ref`, `reviewed_at_sha`, `recorded_at`, `recorded_by`,
`adjudication_rationale`, the `refuted` pair, or `classification: "absence"`)
- a row with NONE of them is genuinely legacy and exempt. Checking only
`recorded_at`/`schema_version` (an earlier version of this checker) missed a
row that omitted BOTH while still carrying e.g. `recorded_by`/
`reviewed_at_sha`, letting a real escalation vanish undetected.
`pass_ordinal` and `run_id` are additionally validated PER ROW, not only on
the merged result: `pass_ordinal` determines MERGE ORDER itself (a bad value
maps to 0 for sorting), so a row that wins or loses a tie because of it must
be checked directly, not only via whichever value happens to survive into the
merge. Attestation pairing and the one frozen field (`severity_native`,
compared against the FINDING's first row, not merely the first row that
happens to mention the key - an omission-then-later-invention is the same
fabrication as a null-then-later-invention) are also checked PER ROW, so an
intermediate violation a later row incidentally restores is still caught.
`reviewed_at_sha` is deliberately NOT treated as immutable: correcting it
across a supersession is legitimate (its field definition is "the head the
reporter read", not a permanent record).

A `recorded_at` that is PRESENT but does not resolve to an UNAMBIGUOUS
instant - unparseable, OR parseable but carrying no timezone offset (a bare
date, a naive datetime) - is reported (`bad-recorded-at`) rather than
silently treated as legacy or coerced to UTC: precedence for that row becomes
genuinely indeterminate, and a malformed OR ambiguous timestamp on a
severity ESCALATION can silently vanish from the merged view with nothing
else in the format able to surface it - so the fragment must not read as
clean while one exists, even though this script still sorts it legacy-first
as the least-surprising deterministic placement.

USAGE
  check-governance-ledger.py --files governance.d/<frag>.jsonl   # lint one run
  check-governance-ledger.py                                     # diff-scoped: fragments changed vs --base
  check-governance-ledger.py --all                              # audit whole corpus (always report-only)

Exit is nonzero when a targeted fragment has any finding; `--all` always 0. A
git failure in the diff-scoped default FAILS CLOSED (nonzero), never a silent
empty scope.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import re
import subprocess
import sys
from pathlib import Path

LEDGER_DIR = "governance.d"

IMPACTS = frozenset(f"I{i}" for i in range(1, 10))
# E0-E7: E7 (advisory-artifact + author-controlled-input cap) added
# 2026-09-16 to SKILL.md's severity-derivation table after PR #4386's own
# 11-round review history showed the table had no way to discount a finding
# on author-controlled input to advisory tooling from one on reachable
# production input - range(0, 8) to include E7.
EXPOSURES = frozenset({f"E{i}" for i in range(0, 8)} | {"unresolved"})
MAPPED = frozenset({"BLOCKING", "SHOULD", "NICE"})
SOURCES = frozenset({"governance-agent", "collaborator", "external-model"})
ATTESTATION = frozenset({"adjudicated_by", "adjudication_rationale", "refuted_by",
                         "refuted_by_reporter", "waiver_rationale"})
LIST_FIELDS = frozenset({"impact", "exposure"})

# The eight fields SKILL.md requires on EVERY row, changed or not (the write
# model: "Only the fields that CHANGE need restating on a superseding row,
# plus schema_version, run_id, finding_id, recorded_by, recorded_at,
# pass_ordinal, reviewed_at_sha and disposition").
REQUIRED_ROW_FIELDS = ("schema_version", "run_id", "finding_id", "recorded_by",
                       "recorded_at", "pass_ordinal", "reviewed_at_sha", "disposition")

# Closed vocabularies from the Gate 8 field table.
EPISTEMIC_STATUSES = frozenset({"verified", "likely", "speculative"})
PROVENANCES = frozenset({"introduced", "newly-reachable", "pre-existing"})
CLASSIFICATIONS = frozenset({"wording", "truth-contradiction", "absence"})
DISPOSITIONS_CLOSED = frozenset({"open", "fixed", "split", "re-cut", "rejected", "refuted"})
# "deferred-to-issue #N" is a space before '#'; "roadmap-#N" / "linked-to-#N" are a dash.
DISPOSITION_PREFIXES = ("deferred-to-issue #", "roadmap-#", "linked-to-#")

# A policy_floor is a valid gate only if it cites one of the three CLOSED
# sources (a routed-concern catastrophic clause / a CLAUDE.md standing-rule
# sentence / an accepted ADR's normative requirement) - this is a necessary-
# marker check, not proof the citation is real, but it catches "floor sourced
# to nothing" / an invented label (the empty-impact gaming vector).
_FLOOR_MARKERS = ("CLAUDE.md", "ADR", "routed-concern", "routed concern")

# SKILL.md is explicit that missing-`schema_version` IS the legacy discriminator
# ("A validator treats missing-schema_version as the legacy discriminator") and
# that on a genuinely legacy row EVERY field #2619 introduced is "absent by
# construction" - it names these: source, reporter_ref, reviewed_at_sha,
# recorded_at, recorded_by, adjudication_rationale, the refuted pair, and
# classification's "absence" value. So a row (or a finding's merged view) that
# carries schema_version itself, OR ANY OTHER one of these markers, cannot be
# genuinely legacy - checking only schema_version/recorded_at (an earlier
# version of this checker) missed a row that omits BOTH of those two while
# still carrying e.g. recorded_by/reviewed_at_sha, which is unambiguously
# modern and can otherwise silently discard a real escalation.
_V2619_ONLY_FIELDS = frozenset({"schema_version", "source", "reporter_ref", "reviewed_at_sha",
                                "recorded_at", "recorded_by", "adjudication_rationale",
                                "refuted_by", "refuted_by_reporter"})


def _looks_versioned(d):
    """True if the dict (a single row, or a finding's merged view) carries any
    field #2619 introduced - meaning it cannot be genuinely legacy, per
    SKILL.md's own definition of what a legacy row looks like."""
    if any(k in d for k in _V2619_ONLY_FIELDS):
        return True
    return d.get("classification") == "absence"

# base band per impact code (SKILL.md "IMPACT - gives the base band")
_BASE = {"I1": "HIGH", "I2": "HIGH", "I3": "HIGH", "I4": "HIGH",
         "I5": "MEDIUM", "I6": "MEDIUM", "I7": "MEDIUM",
         "I8": "LOW", "I9": "INFO"}
_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
# impacts whose band is explicitly capped at HIGH regardless of exposure raises
_HIGH_CAPPED = frozenset({"I4", "I7"})
_UNSET = object()
_LABEL_CEILING = {"BLOCKING": "CRITICAL", "SHOULD": "MEDIUM", "NICE": "LOW"}


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _in(value, allowed):
    try:
        return value in allowed
    except TypeError:
        return False


def _is_int(v):
    """int, excluding bool (a bool IS an int in Python; a JSON true/false is
    never a legitimate schema_version/pass_ordinal/independent_reporters)."""
    return isinstance(v, int) and not isinstance(v, bool)


_FID_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+/,-]*")

# Named (not inline) so the self-test can pin the exact pattern - round-6
# shipped this as an inline `re.search(...)` call, which meant only specific
# behavioral instances were tested and a future one-character widening of the
# charset could reintroduce the blank-suffix defect while every existing
# assertion kept passing.
_DISPOSITION_SUFFIX_CONTENT_RE = re.compile(r"[A-Za-z0-9?]")


def _has_visible_id(v):
    """A genuine identifier string: an ANCHORED, whole-string match against a
    CLOSED ASCII token grammar (must START with an alphanumeric, then only
    alphanumerics and the small punctuation set the real corpus actually
    uses: `._+/,-`). This is the fourth attempt at this check, and the first
    that closes the WHOLE class rather than one more reported instance:
    - round 3: bare truthiness (`bool("   ")` is `True`)
    - round 5: `.strip()` (misses zero-width/format chars - ZWSP, BOM -
      Unicode category Cf - which `.strip()` doesn't remove)
    - round 6 attempt 1: `isprintable() and not isspace()` EXISTENTIAL check
      (still passes combining marks/variation selectors/blank-glyph symbols
      - category Mn/So/Lo - which report printable+non-whitespace despite
      rendering blank)
    - round 6 attempt 2 (existential "contains at least one alnum
      SOMEWHERE"): closed the BLANK-id collision, but said nothing about the
      REST of the string - "X" and "X\\u200b" both satisfy "contains an
      alnum" while being two DIFFERENT dict keys, silently SPLITTING one
      finding's history across two merge groups instead of colliding two
      unrelated ones (the opposite failure mode, same root cause).
    An ANCHORED full-match closes both directions of the same class at once:
    no leading/trailing/embedded invisible or non-ASCII character can hide
    anywhere in a value that still matches, and no separate `.strip()`
    comparison is needed (whitespace of any kind isn't in the charset, so it
    fails the match wherever it appears). Verified: 0 of 11,584 real corpus
    finding_id occurrences fail this grammar, and none starts with a
    non-alphanumeric character. finding_id is the MERGE JOIN KEY ITSELF, so
    any of these shapes silently either collides two unrelated findings or
    splits one finding's history in two."""
    return isinstance(v, str) and _FID_TOKEN.fullmatch(v) is not None


def floor_cites_closed_source(floor):
    return isinstance(floor, str) and any(m in floor for m in _FLOOR_MARKERS)


def min_derived_band(impact, exposure):
    """The FLOOR of the finding's band from the recorded facts alone.

    Only the mechanical parts of the derivation are modelled: base band per
    impact code, the E1/E2 single raise, the E6 LOW cap, the E7 MEDIUM cap
    (added 2026-09-16 for author-controlled input to advisory tooling - see
    SKILL.md's severity-derivation table), and the I4/I7 HIGH cap - applied
    PER IMPACT CODE before taking the max, so a mixed finding (e.g. I1+I4
    under E1) correctly floors at I1's escalated CRITICAL rather than being
    dragged down to I4's own HIGH ceiling. The CONDITIONAL raises SKILL.md
    defines (I5(a)-(c), I6 FALSE-ASSURANCE/DORMANT-AUTH, I7-conceals) can
    only push the true band HIGHER and cannot be evaluated from the fields
    alone, so this is a lower bound, not the exact band. Used only to catch
    UNDER-grading (a label whose ceiling cannot even reach this floor);
    over-labeling is left alone because it is indistinguishable from a
    legitimate conditional raise. E6 and E7 are independent `min()` caps, so
    applying both in either order gives the same result: E6's LOW dominates
    E7's MEDIUM whenever both are present, exactly as SKILL.md specifies.
    """
    codes = [i for i in impact if i in _BASE]
    if not codes:
        return "INFO"
    def _code_band(c):
        idx = _ORDER.index(_BASE[c])
        if any(e in ("E1", "E2") for e in exposure):
            idx = min(idx + 1, len(_ORDER) - 1)
        if c in _HIGH_CAPPED:
            idx = min(idx, _ORDER.index("HIGH"))
        return idx
    idx = max(_code_band(c) for c in codes)
    if "E6" in exposure:
        idx = min(idx, _ORDER.index("LOW"))
    if "E7" in exposure:
        idx = min(idx, _ORDER.index("MEDIUM"))
    return _ORDER[idx]


class Finding:
    __slots__ = ("path", "fid", "tier", "rule", "msg")

    def __init__(self, path, fid, tier, rule, msg):
        self.path, self.fid, self.tier, self.rule, self.msg = path, fid, tier, rule, msg


_MIN_INSTANT = datetime.min.replace(tzinfo=timezone.utc)


# recorded_at determines MERGE PRECEDENCE, so - exactly like finding_id, the
# merge JOIN KEY - it needs an anchored, whole-string grammar rather than a
# delegate-to-fromisoformat-and-hope approach: Python's fromisoformat (3.11+)
# is far more lenient than RFC 3339 in ways that matter for an order-critical
# field. Verified directly (all three accepted despite being invalid or
# self-contradictory under any RFC 3339 reading):
#   fromisoformat("2026-09-15T10:00:00z+14:00")  -> 2026-09-15 10:00:00+14:00
#     (a lowercase-z UTC marker AND an explicit numeric offset - the 'z' is
#     silently ignored and the offset wins, even though the two disagree)
#   fromisoformat("2026-09-15T10:00:00x+14:00")  -> the same result, with a
#     literal garbage character in place of the zone marker
#   fromisoformat("2026-09-15X10:00:00+00:00")   -> accepted with ANY single
#     character as the date/time separator, not just 'T'
# A self-contradictory or malformed-but-accepted string like the first two
# still parses to a DEFINITE instant, so it silently participates in merge
# ordering rather than being caught as unparseable - this can shift a row's
# effective UTC instant by hours and invert which of two rows is treated as
# the later, superseding one. The anchored grammar below is the closed set of
# shapes the real corpus actually uses (a mandatory 'T'/'t' separator, then
# EXACTLY ONE terminal zone designator: 'Z', 'z', or a colon-separated
# numeric offset - never a mix of the two, never an extra character):
#   verified: of the real corpus's non-null recorded_at values, only the
#   pre-existing bare-date shape (166 occurrences, 3 files) fails to resolve
#   to an instant under this grammar - by design (SKILL.md treats a bare date
#   as AMBIGUOUS, not malformed); every value that DOES carry a time
#   component matches (7 further distinct shapes seen, all covered)
#
# `[0-9]` deliberately, NOT `\d`: in a `str` pattern `\d` matches every
# Unicode Nd-category digit (e.g. Arabic-Indic, fullwidth), not just ASCII -
# `_FID_TOKEN` above spells its classes out for exactly this reason and this
# grammar must too, or a non-ASCII-digit date/time silently fullmatches here
# and only gets caught two lines later by fromisoformat raising.
#
# The offset alternative is `[01][0-9]|2[0-3]` hours / `[0-5][0-9]` minutes,
# NOT a bare `[0-9]{2}:[0-9]{2}`: round-8 review (Fable + Sol, independently
# converged) found that an unconstrained two-digit offset admits minute
# values 60-99, which fromisoformat NORMALIZES rather than rejecting
# ("+05:60" silently becomes "+06:00") - a malformed-but-accepted offset that
# still parses to a DEFINITE instant, the same escalation-loss mechanism as
# every prior finding in this field. Verified: 0 of 1,811 real corpus numeric
# offsets fall outside 00-23:00-59.
#
# The TIME-hour alternative is likewise `[01][0-9]|2[0-3]`, NOT a bare
# `[0-9]{2}`: round-9 review (Fable + Sol, independently converged) found
# that ISO-8601's hour-24 "end of day" spelling is legal ONLY when every
# smaller component - minute, second, AND every fractional digit - is zero,
# but fromisoformat's own hour-24 check runs against the SIX-DIGIT-TRUNCATED
# fractional value, not the real one: "...T24:00:00.0000001Z" (a nonzero
# 7th fractional digit) was wrongly ACCEPTED as midnight, while the round-8
# exact-precision _frac_key separately restored and ordered by that same
# nonzero remainder - the identical "validate the lossy value, order by the
# lossless value" seam that produced round 8's own blocker, one field over.
# Rejecting hour 24 entirely (0 real corpus values use ANY hour-24 spelling)
# sidesteps the whole interaction rather than special-casing the
# all-zeros-only legal form.
_INSTANT_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt](?:[01][0-9]|2[0-3]):[0-9]{2}:[0-9]{2}"
    r"(\.[0-9]+)?(Z|z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$")


def _instant(ra):
    """Parse an ISO-8601 recorded_at to a tz-aware instant, or None if absent,
    unparseable, AMBIGUOUS (no timezone offset - a bare date or a naive
    datetime), or malformed under the anchored grammar above (an extra/
    self-contradictory zone marker, a non-'T'/'t' separator, a non-colon
    offset, an out-of-range field). Compares actual instants, so fractional
    seconds and non-Z offsets order correctly (a plain string sort does not).

    The grammar validates SHAPE for every field, but only ENFORCES RANGE
    directly for the offset (hours 00-23, minutes 00-59, tightened in round
    8 after an unconstrained offset let fromisoformat silently NORMALIZE a
    malformed value like "+05:60" into "+06:00" rather than rejecting it)
    and the TIME-hour (00-23, tightened in round 9 - see the _INSTANT_RE
    comment for why hour 24 specifically needed grammar-level rejection
    rather than fromisoformat's own raise). Every OTHER field - month, day,
    minute, second - is shape-only in the regex and range-enforced by
    fromisoformat RAISING instead: e.g. "2026-13-01T00:00:00Z" (month 13),
    "2026-02-30T00:00:00Z" (day 30 in February), "2026-09-15T23:60:00Z"
    (minute 60) all fullmatch the grammar and only fail at fromisoformat.
    round-7 review (Fable + Sol, independently
    converged) caught that an earlier version of this function let that
    exception escape uncaught: a single out-of-range recorded_at - the single
    most realistic hand-typing mistake in this field, more likely than any
    invisible-character shape this whole review cycle has chased - would
    crash the entire check_fragment() call (raised again for the whole --all
    corpus, an exit-0 contract), silencing every OTHER finding in the run
    rather than reporting this one row as bad-recorded-at. A malformed value
    here means "unparseable", exactly like the absent/wrong-type/no-offset
    cases above - never an uncaught exception.

    Known, deliberate narrowing: a genuine RFC 3339 leap-second timestamp
    ("...T23:59:60Z") returns None - Python's datetime cannot represent leap
    seconds at all, so no parser change here could accept one. This is a
    loud, rare false rejection (reported as bad-recorded-at), never a silent
    escalation-loss path, and is treated as out of this function's profile.

    "-00:00" is rejected explicitly, even though it fullmatches the grammar
    and Python parses it without error: RFC 3339 section 4.3 reserves this
    EXACT spelling to mean "local offset unknown", as distinct from "+00:00"
    (genuinely UTC) - Python parses both identically to UTC, silently
    discarding that distinction. round-8 review (Sol) raised this: the
    resulting INSTANT is not ambiguous (RFC 3339 4.3 is explicit that the
    UTC time is known; only the writer's LOCAL offset is unknown), but ISO
    8601 forbids a negative-zero offset outright, and RFC 3339 reserves the
    spelling as a writer-declared data-quality flag - refusing to silently
    launder it into "+00:00" is the honest behavior, not a correctness fix
    for a wrong instant like every other malformed shape this field has
    chased. Verified: 0 real corpus recorded_at values use this spelling.
    """
    if not isinstance(ra, str) or not ra:
        return None
    if _INSTANT_RE.fullmatch(ra) is None:
        return None
    if ra.endswith("-00:00"):
        return None
    # RFC 3339 section 5.6 permits a lowercase 'z' spelling too; Python's
    # fromisoformat only recognizes uppercase 'Z' natively and raises on 'z'.
    # Safe to rewrite unconditionally here: the grammar above already proved
    # 'Z'/'z' is the sole terminal zone token when it appears at all.
    s = ra[:-1] + "+00:00" if ra.endswith(("Z", "z")) else ra
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


# fromisoformat truncates fractional seconds to 6 digits (microseconds), but
# _INSTANT_RE deliberately admits more (the real corpus has 34 rows with 7-9
# digits) - so two rows differing only PAST microsecond precision parse to
# the IDENTICAL `datetime`, a false tie that falls through to `pass_ordinal`
# (reserved by SKILL.md for GENUINE ties) and can invert the rows' real
# order. round-8 review (Fable + Sol, independently converged) reproduced
# this directly.
#
# The comparison must be correct for ARBITRARY digit counts: since
# `_INSTANT_RE`'s fractional group is unbounded (`[0-9]+`), any fixed-size
# assumption is an instance of exactly the class of bug this whole field's
# review cycle has chased (an unvalidated dimension of a merge-order value).
# This function has had two prior attempts, each closing one dimension while
# opening another - the current version (below the history) is the third.
# Fable and Sol's round-8
# confirmation pass both independently found the first version's fixed
# 32-char width was reachable: a 34-digit fraction and a 32-digit fraction
# that both truncate to the IDENTICAL microsecond value under `datetime`
# produced a wrong relative order once padded to unequal effective scales
# and compared as plain ints.
# round-9 review (Fable + Sol, independently converged) found this
# function's first shipped version - `Decimal("0." + digits)` - crashes for
# real, not just hypothetically, on any CPython built WITHOUT the C
# `_decimal` extension: the pure-Python `_pydecimal` fallback constructs a
# Decimal by internally converting the full digit string via `int()`, which
# hits the identical 4300-digit string-conversion cap this function exists
# to avoid. No documented support boundary excludes such an interpreter.
#
# The fix drops `Decimal` (and any digit-to-int conversion) entirely:
# stripping TRAILING zeros from the raw fractional-digit string, then
# comparing the results as plain strings, is EXACTLY equivalent to comparing
# the fractions as real numbers, at ANY digit count - a stripped string that
# is a strict prefix of another can only arise when the longer one has a
# nonzero digit past that point (trailing zeros are already gone), which
# makes it the larger value, and Python's own string-ordering convention
# ("a proper prefix sorts before the longer string it prefixes") already
# agrees. Verified empirically against `fractions.Fraction` over 300,000
# random digit-string pairs up to 45 digits each: zero disagreements. Pure
# string operations - no `int()`, no `Decimal`, no width limit, no
# interpreter-configuration dependence.
def _frac_key(ra):
    if not isinstance(ra, str):
        return ""
    m = re.search(r"\.([0-9]+)", ra)
    return m.group(1).rstrip("0") if m else ""


def _order_key(item):
    idx, r = item
    ra = r.get("recorded_at")
    inst = _instant(ra)
    po = r.get("pass_ordinal") if _is_int(r.get("pass_ordinal")) else 0
    if inst is not None:
        # timestamped: by instant, then EXACT sub-instant fractional
        # precision, then pass_ordinal, then file order
        return (1, inst, _frac_key(ra), po, idx)
    return (0, _MIN_INSTANT, "", 0, idx)   # no parseable recorded_at: sorts first, in file order


def merged_view(ordered_rows):
    """Field-wise last-write-wins over ordered rows; attestation fields excluded
    (row-scoped); list fields replace wholesale (plain dict assignment)."""
    m = {}
    for _, r in ordered_rows:
        for k, v in r.items():
            if k in ATTESTATION:
                continue
            m[k] = v
    return m


def _reject_duplicate_keys(pairs):
    """`json.loads`'s `object_pairs_hook`: raise ValueError on any object
    member name repeated within the SAME JSON object, at ANY nesting depth
    (this hook fires once per object as the parser closes it, bottom-up, so
    a duplicate inside a nested object is caught before the outer object's
    own pairs are even assembled).

    round-10 review (Fable + Sol, independently converged, then Kimi
    withdrew her own PASS after cross-examining Codex's finding and
    reproduced it independently) found this defect sits STRUCTURALLY BELOW
    every per-field grammar/range/precision fix the prior nine rounds
    shipped: Python's default JSON parser (matching jq and JavaScript's
    JSON.parse) silently keeps only the LAST value for a repeated key,
    discarding earlier ones with NO diagnostic - so a row whose raw JSON
    text states `recorded_at` (or `finding_id`, `pass_ordinal`,
    `severity_mapped`, or any other merge-governing field) TWICE has its
    first value vanish before any validator in this file ever runs. No
    field-level check can see a value that was discarded before parsing
    finished. Verified: a NICE row plus a BLOCKING row whose JSON states
    recorded_at twice (a later value, then an earlier one) merges to NICE
    with zero findings - the escalation silently gone.
    """
    result = {}
    dups = []
    for k, v in pairs:
        if k in result:
            dups.append(k)
        result[k] = v
    if dups:
        # `repr()`, NOT the raw name: a duplicate member name can itself be
        # a lone Unicode surrogate (`\ud800`, reachable via a JSON `\uXXXX`
        # escape with no matching low surrogate - `json.loads` decodes it
        # into a Python str without complaint). Printing that character to a
        # normal UTF-8 stdout raises UnicodeEncodeError uncaught - round-11
        # review (Fable + Sol) caught that this was the first place in the
        # file to interpolate a row-controlled string without the `!r`
        # discipline every other such site already uses, and the crash
        # lands mid-report: under --all, every fragment after the offending
        # one, and the summary line, never print.
        raise ValueError(f"duplicate object member(s): "
                          f"{', '.join(repr(d) for d in sorted(set(dups)))}")
    return result


def _reject_json_constant(token):
    """`json.loads`'s `parse_constant`: Python's json module accepts the
    non-standard literals `NaN`/`Infinity`/`-Infinity` (RFC 8259 section 6
    permits ONLY finite numbers) with no diagnostic by default. round-11
    review (Fable + Sol) found every merge/severity-governing field with a
    type check already fires a loud downstream finding on one of these
    (`_is_int` rejects a float; an enum membership check rejects `inf`), so
    this is format-hygiene rather than an escalation-loss path - but it is
    a one-line close, so close it rather than leave a documented gap."""
    raise ValueError(f"non-standard JSON constant {token!r} "
                      f"(NaN/Infinity/-Infinity are not valid JSON per RFC 8259 section 6)")


def check_fragment(path):
    out = []

    def add(fid, tier, rule, msg):
        out.append(Finding(path, fid, tier, rule, msg))

    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        # UnicodeDecodeError is a ValueError subclass, NOT an OSError - a
        # single non-UTF-8 byte anywhere in a fragment would otherwise raise
        # uncaught here, crashing check_fragment() (and, in --all, the whole
        # run) rather than reporting this one fragment as unreadable. round-8
        # review (Fable + Sol) caught this as the sibling of the same
        # uncaught-exception class round 7 fixed one function earlier in the
        # same call chain (the fromisoformat try/except).
        add("", "STRUCTURAL", "unreadable", str(e))
        return out

    rows = []  # (line_no, obj)
    # `.splitlines()` deliberately NOT used: it also splits on U+2028/U+2029/
    # U+0085 (and a few other Unicode line-boundary characters) - which are
    # LEGAL, unescaped inside a JSON string. round-9 review (Fable) caught
    # that a fragment with one of these characters raw inside a field value
    # (e.g. `adjudication_rationale`) still parses as ONE JSON object via
    # `json.loads` (and reads as one line via ordinary file iteration), but
    # got split into TWO here - reported as two spurious invalid-json
    # findings, the real row silently dropped from the merge, and every
    # later line number off by one. `.split("\n")` matches ordinary file
    # iteration exactly, since `read_text()` above already applies universal
    # newline translation (\r\n and bare \r both become \n before this line
    # ever runs).
    for n, line in enumerate(text.split("\n"), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line, object_pairs_hook=_reject_duplicate_keys,
                              parse_constant=_reject_json_constant)
        except (ValueError, RecursionError) as e:
            # `json.JSONDecodeError` is a `ValueError` subclass, so catching
            # `ValueError` covers it - but ALSO catches two siblings a
            # malformed line can raise that a narrower `except
            # json.JSONDecodeError` would miss: a JSON integer literal past
            # Python's 4300-digit int(str) conversion cap raises a plain
            # ValueError (not a JSONDecodeError), and ~100,000-deep array
            # nesting raises RecursionError. round-9 review (Fable + Sol,
            # independently converged) reproduced both crashing this call
            # uncaught - the same "narrower except than the input space
            # allows" class as round 8's UnicodeDecodeError gap one function
            # earlier.
            add("", "STRUCTURAL", "invalid-json", f"line {n}: {e}")
            continue
        if not isinstance(obj, dict):
            add("", "STRUCTURAL", "invalid-json", f"line {n}: not a JSON object")
            continue
        rows.append((n, obj))
    if not rows:
        return out

    # removesuffix strips exactly the literal ".jsonl" extension, unlike a
    # fixed [:-len(".jsonl")] chop (which mangled a non-.jsonl path into a
    # garbage stem) or Path.stem (which strips WHATEVER extension is present,
    # so an extension-less or wrong-extension --files misuse still gets a
    # silently-invented stem instead of an honest unchanged name).
    expected_run = Path(path).name.removesuffix(".jsonl")

    # group rows by finding_id, preserving file order for the ordering key.
    # finding_id is the MERGE JOIN KEY ITSELF - a bare truthiness check
    # (`not fid`) accepts a whitespace-only string, since bool("   ") is True
    # in Python. That's more fundamental than any value-shape gap fixed so
    # far: two otherwise-unrelated findings sharing a blank-looking id
    # silently collapse into ONE merge group, and a later NICE row can
    # overwrite an earlier BLOCKING row's facts with zero findings.
    by_fid = {}
    for i, (n, r) in enumerate(rows):
        fid = r.get("finding_id")
        if not _has_visible_id(fid):
            # a single anchored full-match check now covers every shape that
            # would otherwise either collide two unrelated findings (blank/
            # invisible ids, all equal to each other) or SPLIT one finding's
            # history in two (a stray leading/trailing/embedded whitespace or
            # invisible-character variant of an otherwise-legitimate id forms
            # a DIFFERENT dict key from the canonical one - no separate
            # `.strip()` comparison is needed, since whitespace of any kind
            # simply isn't in the allowed grammar wherever it appears).
            add("", "STRUCTURAL", "bad-finding-id",
                f"line {n}: finding_id {fid!r} is absent, not a string, or is not an anchored "
                f"token of ASCII alphanumerics/`._+/,-` starting with an alphanumeric - not a "
                f"valid merge key")
            continue
        by_fid.setdefault(fid, []).append((i, (n, r)))

    for fid, entries in by_fid.items():
        ordered = sorted(((idx, r) for idx, (n, r) in entries), key=_order_key)
        line_of = {id(r): n for _, (n, r) in entries}
        merged = merged_view(ordered)
        # Tested against each RAW row, not the merged view: merged_view()
        # strips the three attestation-only markers (adjudication_rationale,
        # refuted_by, refuted_by_reporter) since they're row-scoped and
        # excluded from the merge, so a finding whose ONLY #2619 marker is one
        # of those three would read as versioned per-row but legacy at the
        # merged level - never a live hole (such a row still lacks
        # schema_version, so missing-row-field already fires on it), but it
        # would wrongly exempt that finding from the merged-view checks below
        # (reporter/source/policy_floor presence, disposition's closed-enum
        # half) and make this comment false.
        legacy = not any(_looks_versioned(r) for _, r in ordered)

        # ---------- PER-ROW checks ----------
        # These run per ROW, not first-vs-live, so an intermediate violation a
        # later row incidentally restores is still caught (the append-only
        # ledger permanently contains the act it recorded).
        native_established = False
        native_seen = None
        # Precomputed ACROSS ALL ROWS before the per-row loop starts - not
        # updated progressively during iteration. Progressive updates meant a
        # row's OWN indeterminacy wasn't visible to checks running earlier in
        # that SAME row's iteration (e.g. native-mutated/bad-recorded-by,
        # which run before the recorded_at check later in the loop body), so
        # a genuinely indeterminate row could still emit an undisclosed
        # misattribution on itself. Gated the same way as the live
        # bad-recorded-at finding: only a VERSIONED row's unresolved
        # recorded_at counts (a genuinely legacy row lacking recorded_at is
        # normal, not indeterminate).
        seen_bad_recorded_at = any(
            _looks_versioned(r) and _instant(r.get("recorded_at")) is None
            for _, r in ordered)
        for row_pos, (_, r) in enumerate(ordered):
            ln = line_of[id(r)]

            # attestation pairing is a property of the ROW that performed the
            # act. A bare `bool(x)` truthiness check is the exact class Sol's
            # broader audit named: a whitespace string, a bare int, or `False`
            # itself all read as "set" under raw truthiness, so a garbage
            # non-null value on either field would silently satisfy pairing
            # with its genuine sibling. Presence is instead "a genuine
            # non-empty, non-whitespace string" - a value that is neither
            # None NOR a valid string is its OWN finding (regardless of
            # pairing), and pairing itself compares the two NORMALIZED
            # presence booleans, not the raw values.
            adj_by, adj_rat = r.get("adjudicated_by"), r.get("adjudication_rationale")
            adj_by_ok = adj_by is None or (isinstance(adj_by, str) and adj_by.strip())
            adj_rat_ok = adj_rat is None or (isinstance(adj_rat, str) and adj_rat.strip())
            if not adj_by_ok:
                add(fid, "STRUCTURAL", "bad-adjudicated-by",
                    f"line {ln}: adjudicated_by must be null or a non-empty, non-whitespace "
                    f"string, got {type(adj_by).__name__} {adj_by!r}")
            if not adj_rat_ok:
                add(fid, "STRUCTURAL", "bad-adjudication-rationale",
                    f"line {ln}: adjudication_rationale must be null or a non-empty, "
                    f"non-whitespace string, got {type(adj_rat).__name__} {adj_rat!r}")
            if adj_by_ok and adj_rat_ok and (adj_by is not None) != (adj_rat is not None):
                add(fid, "STRICT", "adjudication-pairing",
                    f"line {ln}: adjudicated_by and adjudication_rationale must be set together on the same row")

            # severity_native is the reporter's own word, frozen. Baseline is
            # the FIRST ROW's value (None if that row omits the key entirely -
            # the field's own documented default is null when "they gave
            # none"), not merely the first row that happens to mention it: a
            # later row that INTRODUCES a concrete value where the finding's
            # own first row never gave one is the same attribution fabrication
            # as an explicit null-to-value flip, just via omission.
            if row_pos == 0:
                native_seen = r.get("severity_native")
                native_established = True
            elif "severity_native" in r:
                val = r.get("severity_native")
                if val != native_seen:
                    qualifier = ("" if not seen_bad_recorded_at else
                                 " (NOTE: this finding also has a row whose recorded_at is absent or malformed, so merge order - "
                                 "and therefore which row is genuinely 'first' - is indeterminate; this "
                                 "message may be attributing the mutation to the wrong direction)")
                    add(fid, "STRICT", "native-mutated",
                        f"line {ln}: severity_native set to {val!r}, differs from the finding's "
                        f"first-row value {native_seen!r} (reporter's own word, immutable){qualifier}")

            # scalar impact/exposure - the shape the jq park probe's array check
            # exists to catch. `null` is explicitly EXCLUDED here, not merely
            # tolerated: SKILL.md states "impact: [] or a null fact set derives
            # INFO", treating null as an equally legitimate empty-fact-set
            # spelling - flagging it here would contradict the missing-field
            # check's own (deliberate) tolerance of it for the same two fields.
            for lf in LIST_FIELDS:
                if lf in r and r[lf] is not None and not isinstance(r[lf], list):
                    add(fid, "STRUCTURAL", "scalar-list-field",
                        f"line {ln}: {lf} must be a JSON array (or null for an empty fact set), "
                        f"got {r[lf]!r}")

            # pass_ordinal and run_id are validated PER ROW, not only on the
            # merged result: pass_ordinal determines MERGE ORDER itself (a bad
            # value silently maps to 0 for sorting in _order_key, so the row it
            # belongs to can WIN or LOSE a tie based on that bad value and then
            # vanish from the merge before anything downstream ever looks at
            # it - checking only merged["pass_ordinal"] inspects the winning
            # row's value, never the losing row's bad one that caused the
            # wrong outcome). run_id is checked per row for the same reason a
            # merged-only check missed it: a mid-history wrong run_id that a
            # later row incidentally restates correctly reads clean at the
            # merged level while the ledger permanently contains the bad row.
            if "pass_ordinal" in r and (not _is_int(r["pass_ordinal"]) or r["pass_ordinal"] < 0):
                add(fid, "STRUCTURAL", "bad-pass-ordinal",
                    f"line {ln}: pass_ordinal must be a non-negative integer, got {r['pass_ordinal']!r} "
                    f"(this row's own value, valid or not, determines its precedence in the merge)")
            if "run_id" in r and r["run_id"] != expected_run:
                add(fid, "STRUCTURAL", "run-id-mismatch",
                    f"line {ln}: run_id {r['run_id']!r} != filename stem {expected_run!r}")

            # Generalizing pass_ordinal/run_id's per-row treatment to the
            # REST of the eight mandatory fields (round-4 review's explicit
            # ask, after three straight rounds of fixing one field at a
            # time): a bad VALUE on an early row - not just an absent KEY -
            # is a permanently-recorded defect nothing else catches, since a
            # later valid row silently "corrects" it at the merged level
            # with no trace of the bad row ever having existed.
            if "schema_version" in r and not _is_int(r["schema_version"]):
                add(fid, "STRUCTURAL", "bad-schema-version",
                    f"line {ln}: schema_version must be an integer, got {r['schema_version']!r}")
            # A falsy/None check alone isn't enough here: 7, [], and "   " are
            # all truthy-or-empty-shaped in ways a bare `not x` check misses
            # or wrongly accepts - both fields need a genuine non-empty,
            # non-whitespace STRING (Sol's round-4 review caught this gap in
            # my own first draft of these two checks).
            if "reviewed_at_sha" in r:
                rsha = r["reviewed_at_sha"]
                if not (isinstance(rsha, str) and rsha.strip()):
                    add(fid, "STRUCTURAL", "bad-reviewed-at-sha",
                        f"line {ln}: reviewed_at_sha must be a non-empty, non-whitespace string, "
                        f"got {type(rsha).__name__} {rsha!r}")
            # recorded_by is the one field of the eight with a CONDITIONAL
            # value rule: "nullable on the row that first raises a finding,
            # required on a supersession" - null is fine at row_pos==0 (the
            # reporter and recorder are the same person) but not on any later
            # row (a supersession must name who wrote it). Any NON-null value,
            # at any row position, must still be a genuine non-empty string -
            # 7/[]/"" are never a legitimate recorder identity.
            if "recorded_by" in r:
                rby = r["recorded_by"]
                if rby is None:
                    if row_pos != 0:
                        # row_pos itself depends on sort order, which a prior
                        # bad-recorded-at row already made indeterminate - the
                        # row this fires on may not genuinely be "not the
                        # raising row" (Fable's round-4 review: misattribution,
                        # not an escalation loss, since the fragment already
                        # fails via bad-recorded-at either way).
                        qualifier = ("" if not seen_bad_recorded_at else
                                     " (NOTE: this finding also has a row whose recorded_at is absent or malformed, so which "
                                     "row genuinely raised the finding is indeterminate - this may be "
                                     "misattributing the raising row)")
                        add(fid, "STRUCTURAL", "bad-recorded-by",
                            f"line {ln}: recorded_by is nullable only on the row that first raises "
                            f"the finding; a supersession must name who wrote it{qualifier}")
                elif not (isinstance(rby, str) and rby.strip()):
                    add(fid, "STRUCTURAL", "bad-recorded-by",
                        f"line {ln}: recorded_by must be a non-empty, non-whitespace string (or null, "
                        f"only on the raising row), got {type(rby).__name__} {rby!r}")
            # disposition has TWO per-row checks now. (1) BEDROCK shape
            # (non-empty string) - true in every generation, not legacy-gated.
            # (2) CLOSED-ENUM membership - a #2643-era convention, so
            # legacy-gated like the rest of that convention. Checking (2) per
            # row (not just on the merged view) catches a permanently-recorded
            # invalid value even when a LATER row's valid disposition would
            # otherwise hide it with zero findings - and doing it per row does
            # NOT break the legitimate `open` -> `fixed` evolution, since both
            # values are individually valid and each row is checked on its own
            # merits, not against the other. A prefix match requires something
            # after the '#' ("roadmap-#" alone fails); a non-empty non-numeric
            # suffix ("linked-to-#garbage") is deliberately accepted - the real
            # corpus carries free-text notes trailing a placeholder
            # ("#TBD (draft: ...)"), so a strict numeric/placeholder
            # requirement would false-positive on legitimate entries.
            if "disposition" in r:
                dv = r["disposition"]
                if not (isinstance(dv, str) and dv.strip()):
                    add(fid, "STRUCTURAL", "bad-disposition",
                        f"line {ln}: disposition must be a non-empty string, got "
                        f"{type(dv).__name__} {dv!r}")
                # gated on THIS ROW's own versioned-ness (_looks_versioned),
                # not the finding-level `legacy` flag: a finding-wide flag is
                # true the moment ANY row is versioned, which would wrongly
                # retro-apply the #2643-era enum to a genuinely legacy FIRST
                # row that a later versioned row happens to supersede.
                elif _looks_versioned(r) and dv not in DISPOSITIONS_CLOSED:
                    prefix_match = next((p for p in DISPOSITION_PREFIXES if dv.startswith(p)), None)
                    # .strip() only strips category-Zs whitespace - a
                    # zero-width/format character (ZWSP, U+200B) or a
                    # blank-glyph symbol (braille blank, U+2800) survives
                    # .strip() and would pass as if it were real park-issue
                    # content. This is not a merge key (unlike finding_id),
                    # and the real corpus has legitimately free-form suffixes
                    # (prose, a bare `?` placeholder, parenthetical notes), so
                    # an anchored grammar would break ~400 real rows. Require
                    # only that SOME alphanumeric or the documented `?`
                    # placeholder appears in the suffix - existential, not
                    # anchored. Verified: 0 of the corpus's real suffix shapes
                    # fail this; only genuinely blank/invisible suffixes do.
                    if prefix_match is None or not _DISPOSITION_SUFFIX_CONTENT_RE.search(dv[len(prefix_match):]):
                        add(fid, "STRUCTURAL", "bad-disposition",
                            f"line {ln}: disposition {dv!r} is not in the closed enum "
                            f"{sorted(DISPOSITIONS_CLOSED)} or a valid non-empty '#<id>' prefix "
                            f"form ({DISPOSITION_PREFIXES})")

            # a row that participates in the post-#2619 append model (carries
            # ANY field #2619 introduced - a genuinely legacy row carries NONE
            # of them, per SKILL.md's own definition) must restate the eight
            # mandatory fields, even when otherwise sparse. A malformed
            # recorded_at is reported (precedence for THIS row is then
            # indeterminate) but still sorts legacy-first as the
            # least-surprising deterministic placement - the finding must not
            # read as clean while one exists, since a malformed timestamp on
            # an ESCALATION can silently lose the merge to an earlier,
            # lower-severity row with no other signal.
            # A VERSIONED row's sort position is indeterminate whenever
            # _instant() can't resolve it - whether recorded_at is malformed/
            # ambiguous OR simply ABSENT from a row that otherwise
            # participates in the modern regime (gated on _looks_versioned: an
            # ORDINARY legacy row also lacks recorded_at, and that is normal,
            # not an error). `seen_bad_recorded_at` is already precomputed
            # ABOVE the loop over every row in the finding (not updated here)
            # so the qualifier it feeds is visible to every row's checks
            # regardless of iteration order, including this row's own. Only
            # the present-but-bad case is its own finding here; an absent key
            # is separately, correctly caught by missing-row-field below.
            if _looks_versioned(r) and _instant(r.get("recorded_at")) is None and "recorded_at" in r:
                add(fid, "STRUCTURAL", "bad-recorded-at",
                    f"line {ln}: recorded_at {r.get('recorded_at')!r} is not an unambiguous "
                    f"ISO-8601 instant (unparseable, or parses but carries no timezone offset); "
                    f"this row's precedence relative to its peers is indeterminate")
            if _looks_versioned(r):
                for req in REQUIRED_ROW_FIELDS:
                    if req not in r:
                        add(fid, "STRUCTURAL", "missing-row-field",
                            f"line {ln}: row omits required field {req!r} "
                            f"(SKILL.md: every row restates it, changed or not - "
                            f"only OTHER fields may be omitted when unchanged)")
        assert native_established  # ordered is never empty (fid groups only nonempty entries)

        # ---------- STRUCTURAL: schema hygiene on the merged view ----------
        # schema_version/run_id/finding_id/disposition PRESENCE is now covered
        # by the per-row 8-field check above for every versioned finding; this
        # loop covers the fields that MAY legitimately be introduced only once
        # and then omitted forever after (they are not in the per-row eight).
        if not legacy:
            # impact/exposure are deliberately checked for PRESENCE only, not
            # non-null: SKILL.md is explicit that "impact: [] or a null fact
            # set derives INFO" - an explicit null is a legitimate empty fact
            # set, not a missing field.
            for req in ("source", "impact", "exposure", "severity_mapped"):
                if req not in merged:
                    add(fid, "STRUCTURAL", "missing-field",
                        f"live view lacks required field '{req}'")
            # SKILL.md's field table: "all required unless marked - on the row
            # that FIRST raises a finding". epistemic_status/provenance/
            # classification carry no nullable annotation there (unlike
            # recorded_by/reporter_ref/adjudicated_by/caused_by/
            # waiver_rationale, which do), so - UNLIKE impact/exposure above -
            # an explicit null does not satisfy them. A later supersession may
            # still legitimately correct an earlier omission (the same general
            # write model every other content field uses), so this is checked
            # on the MERGED view, not strictly the raising row itself.
            for req in ("epistemic_status", "provenance", "classification"):
                if req not in merged or merged.get(req) is None:
                    add(fid, "STRUCTURAL", "missing-field",
                        f"live view lacks required field '{req}' (or it is null) - "
                        f"SKILL.md marks it required, not nullable, unlike impact/exposure")
            if "policy_floor" not in merged:
                add(fid, "STRUCTURAL", "missing-field",
                    "live view lacks 'policy_floor' key (write null, do not omit)")
        if "source" in merged and not _in(merged.get("source"), SOURCES):
            add(fid, "STRUCTURAL", "bad-source",
                f"source {merged.get('source')!r} not one of {sorted(SOURCES)}")
        # a bare truthiness check on reporter_ref accepts a whitespace string
        # or an integer as "present" - it must be a genuine non-empty,
        # non-whitespace string (the literal "unresolved" satisfies this and
        # is the documented, legitimate value when no retrievable artefact exists).
        rref = merged.get("reporter_ref")
        if merged.get("source") and merged.get("source") != "governance-agent" \
                and not (isinstance(rref, str) and rref.strip()):
            add(fid, "STRUCTURAL", "missing-reporter-ref",
                "non-governance-agent finding needs reporter_ref (or the literal 'unresolved')")
        for i in _as_list(merged.get("impact")):
            if not _in(i, IMPACTS):
                add(fid, "STRUCTURAL", "bad-impact", f"impact {i!r}")
        for e in _as_list(merged.get("exposure")):
            if not _in(e, EXPOSURES):
                add(fid, "STRUCTURAL", "bad-exposure", f"exposure {e!r}")
        if "severity_mapped" in merged and not _in(merged.get("severity_mapped"), MAPPED):
            add(fid, "STRUCTURAL", "bad-severity-mapped",
                f"severity_mapped {merged.get('severity_mapped')!r}")

        # reporter: exactly one non-empty string value.
        if not legacy:
            rep = merged.get("reporter")
            if rep is None:
                add(fid, "STRUCTURAL", "missing-reporter", "reporter absent (needs exactly one value)")
            elif isinstance(rep, list):
                add(fid, "STRUCTURAL", "list-reporter", f"reporter must be one value, got a list {rep!r}")
            elif not isinstance(rep, str) or isinstance(rep, bool):
                add(fid, "STRUCTURAL", "bad-reporter-type",
                    f"reporter must be a string, got {type(rep).__name__} {rep!r}")
            elif not rep.strip():
                add(fid, "STRUCTURAL", "empty-reporter", "reporter is an empty string (needs exactly one value)")
            elif re.search(r"[+,]| and ", rep):
                add(fid, "STRUCTURAL", "joined-reporter", f"reporter must be one value, got {rep!r}")

        # independent_reporters: null is a legitimate "not yet counted" value in
        # real practice (the corpus carries it), so only a PRESENT-and-wrong-type
        # value fires - unlike schema_version/pass_ordinal below, which are two
        # of the eight per-row-mandatory fields and so are never legitimately
        # null once the key exists (a null there hides behind "key present",
        # passing the separate missing-row-field presence check for free).
        ir = merged.get("independent_reporters")
        if ir is not None and not _is_int(ir):
            add(fid, "STRUCTURAL", "bad-independent-reporters",
                f"independent_reporters must be an integer, got {ir!r}")
        # schema_version/pass_ordinal/reviewed_at_sha/recorded_by/disposition's
        # bedrock shape are NOT re-checked here: the per-row loop above already
        # validates every row's own value (including the merge's eventual
        # winner), which is the point of that fix - a second merged-only check
        # here would only ever double-report the same row. (Any non-bool
        # integer is accepted for schema_version, not just `1`: SKILL.md
        # states it is "currently 1" but ALSO that "one fragment can
        # legitimately hold rows written under two versions of this table" -
        # a deliberate forward-tolerance choice, not an oversight.)
        # epistemic_status/provenance/classification are FINDING-CONTENT enums,
        # not append-machinery fields the #2619 schema versioning introduced -
        # their valid values are a general contract, so these checks are NOT
        # legacy-gated (a genuinely ancient row can still carry an off-enum
        # value worth flagging). Only disposition's closed-enum HALF below is
        # legacy-gated, because THAT convention is #2643-era, later than #2619.
        es = merged.get("epistemic_status")
        if es is not None and not _in(es, EPISTEMIC_STATUSES):
            add(fid, "STRUCTURAL", "bad-epistemic-status",
                f"epistemic_status {es!r} not one of {sorted(EPISTEMIC_STATUSES)}")
        prov = merged.get("provenance")
        if prov is not None and not _in(prov, PROVENANCES):
            add(fid, "STRUCTURAL", "bad-provenance", f"provenance {prov!r} not one of {sorted(PROVENANCES)}")
        cls = merged.get("classification")
        if cls is not None and not _in(cls, CLASSIFICATIONS):
            add(fid, "STRUCTURAL", "bad-classification",
                f"classification {cls!r} not one of {sorted(CLASSIFICATIONS)} (or null)")
        # disposition's BOTH checks (bedrock shape + closed-enum membership)
        # are now done PER ROW above, not here - a merged-only check would
        # only double-report whichever row survives into the merge, and would
        # miss a permanently-recorded bad value a later valid row "corrects".
        disp_val = merged.get("disposition")

        # ---------- STRICT: reviewer-class self-consistency on the merged view ----------
        impact = [i for i in _as_list(merged.get("impact")) if _in(i, IMPACTS)]
        exposure = [e for e in _as_list(merged.get("exposure")) if _in(e, EXPOSURES)]
        mapped = merged.get("severity_mapped")
        raw_impact_present = bool(_as_list(merged.get("impact")))
        if _in(mapped, MAPPED):
            floor_band = min_derived_band(impact, exposure)
            ceiling = _LABEL_CEILING[mapped]
            # UNDER-grading only: a label whose ceiling cannot even reach the
            # facts' floor band is definitely too weak. Conditional raises can
            # only push the true band up, so over-labeling is left alone (F2).
            if _ORDER.index(ceiling) < _ORDER.index(floor_band):
                add(fid, "STRICT", "severity-under-derived",
                    f"severity_mapped {mapped!r} (ceiling {ceiling}) is below the facts' "
                    f"floor band {floor_band} (impact={impact} exposure={exposure}); "
                    f"a finding cannot be graded weaker than its own facts derive")
            # empty/absent impact derives INFO unconditionally (no conditional
            # raise applies to no facts). A non-NICE label is then excused ONLY
            # by a policy_floor that cites one of the three closed sources -
            # any other string (or none) is either a bare disagreement or a
            # fabricated floor used to dodge scrutiny, and both must fire.
            if not impact and not raw_impact_present and mapped != "NICE" \
                    and not floor_cites_closed_source(merged.get("policy_floor")):
                add(fid, "STRICT", "severity-empty-impact",
                    f"severity_mapped {mapped!r} with empty impact and a policy_floor that is either "
                    f"absent or does not cite a closed source (CLAUDE.md standing rule / accepted ADR / "
                    f"routed-concern clause) (empty facts derive INFO -> NICE; a genuine floor gates separately)")
        if merged.get("classification") == "wording" and "I7" in impact:
            add(fid, "STRICT", "wording-carries-i7",
                "classification 'wording' cannot carry I7 (standing rule 3 caps wording-only at NICE)")
        # Gate-7 park constraint (mirrors the SKILL.md jq probe): an I1/I2/I3
        # finding may not be parked. roadmap-* is a hard violation; linked-to-*
        # over-matches (a valid ending if the target issue is itself parked), so
        # it is a prompt to verify the target's labels, not an assertion. This
        # deliberately matches on the BARE prefix (no dash), broader than the
        # closed-enum check above, so a truncated off-enum value ("roadmap")
        # still trips the park constraint even though it also trips bad-disposition.
        top = {"I1", "I2", "I3"} & set(impact)
        if isinstance(disp_val, str) and top:
            if disp_val.startswith("roadmap"):
                add(fid, "STRICT", "parked-top-severity",
                    f"disposition {disp_val!r} parks an {sorted(top)} finding (Gate-7 constraint 1 bars this)")
            elif disp_val.startswith("linked-to"):
                add(fid, "STRICT", "linked-top-severity",
                    f"disposition {disp_val!r} links an {sorted(top)} finding to an existing issue - "
                    f"verify that issue is itself parked, else this is a park the constraint bars (prompt, not a verdict)")
    return out


def changed_fragments(base):
    """Diff-scoped discovery. Fails CLOSED: a git error raises, so the caller
    turns it into a nonzero exit rather than a silent empty scope (F4)."""
    mb = subprocess.run(["git", "merge-base", base, "HEAD"],
                        capture_output=True, text=True, check=True).stdout.strip()
    names = subprocess.run(["git", "diff", "--name-only", "--diff-filter=d", f"{mb}...HEAD"],
                           capture_output=True, text=True, check=True).stdout.splitlines()
    return [f for f in names if f.startswith(LEDGER_DIR + "/") and f.endswith(".jsonl")]


def main():
    # round-11 CONFIRMATION-pass finding (Fable): the round-11 fix for a
    # duplicate JSON member name that is a lone Unicode surrogate only
    # patched that ONE interpolation site (via `repr()`) - but this is an
    # instance fix, not a class fix. `f.path` is printed raw a few lines
    # below, and a FRAGMENT'S OWN FILENAME can carry the identical shape: a
    # non-UTF-8 byte in a filename decodes (via the OS's surrogateescape
    # handler) into a lone surrogate character Python can represent
    # in-memory but cannot ENCODE to a normal UTF-8 stream - reproduced
    # directly (a file named "4-bad\xff.X.jsonl" crashes `print()` at the
    # findings-report loop, uncaught, in both --files and --all). `repr()`
    # doesn't even fully close the CLASS on ORDINARY row content either: it
    # only escapes NON-PRINTABLE characters, so a duplicate key named
    # literally "e" with an acute accent - printable, valid Unicode - would
    # still crash under a non-UTF-8 stdout (e.g. PYTHONIOENCODING=ascii).
    # The actual invariant this tool needs is at the STREAM, not at each
    # interpolation site: reconfigure stdout/stderr to backslash-escape
    # anything they can't encode, rather than crashing on it. This closes
    # every current and future row/filename-controlled string in one place,
    # rather than requiring every future print site to remember `!r`.
    for _stream in (sys.stdout, sys.stderr):
        if hasattr(_stream, "reconfigure"):
            _stream.reconfigure(errors="backslashreplace")

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--all", action="store_true",
                   help="audit every governance.d fragment (always report-only, exit 0)")
    g.add_argument("--files", nargs="+", metavar="FILE", help="lint exactly these fragments")
    ap.add_argument("--base", default=os.environ.get("GOV_LEDGER_BASE", "origin/dev"),
                    help="base ref for the diff-scoped default (default: origin/dev)")
    ap.add_argument("--github", action="store_true",
                    help="emit ::error:: / ::warning:: GitHub-Actions annotations")
    args = ap.parse_args()

    if args.files:
        targets, audit = args.files, False
    elif args.all:
        targets, audit = sorted(str(p) for p in Path(LEDGER_DIR).glob("*.jsonl")), True
    else:
        try:
            targets = changed_fragments(args.base)
        except subprocess.CalledProcessError as e:
            print(f"::error::check-governance-ledger: git diff against base {args.base!r} failed "
                  f"({e}); refusing to report an empty scope (would under-lint). "
                  f"Pass --files explicitly or fix --base.", file=sys.stderr)
            return 2
        audit = False

    if not targets:
        print("check-governance-ledger: no fragments in scope — nothing to lint")
        return 0

    findings = []
    for t in targets:
        findings.extend(check_fragment(t))

    if not findings:
        print(f"check-governance-ledger: OK — {len(targets)} fragment(s) lint clean")
        return 0

    structural = [f for f in findings if f.tier == "STRUCTURAL"]
    strict = [f for f in findings if f.tier == "STRICT"]
    for group, items in (("STRUCTURAL (schema hygiene)", structural),
                         ("STRICT (reviewer-class self-consistency)", strict)):
        if not items:
            continue
        print(f"\n== {group}: {len(items)} ==")
        for f in items:
            loc = f"{f.path}" + (f" [{f.fid}]" if f.fid else "")
            if args.github:
                sev = "error" if f.tier == "STRUCTURAL" else "warning"
                print(f"::{sev}::check-governance-ledger: {loc}: {f.rule}: {f.msg}")
            else:
                print(f"  {loc}: {f.rule}: {f.msg}")

    print(f"\ncheck-governance-ledger: {len(findings)} finding(s) "
          f"({len(structural)} structural, {len(strict)} strict) "
          f"across {len({f.path for f in findings})} fragment(s)")
    return 0 if audit else 1


if __name__ == "__main__":
    sys.exit(main())
