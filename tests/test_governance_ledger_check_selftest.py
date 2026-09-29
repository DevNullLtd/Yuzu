#!/usr/bin/env python3
"""Self-test for scripts/ci/check-governance-ledger.py - the author-side
governance-ledger linter.

The linter is ADVISORY (a pre-push self-check the /governance skill runs on the
current run's fragment, not a corpus CI gate). This self-test does NOT lint the
real corpus; it (1) PINS the linter's policy constants against literals so a
silent edit to a band, an enum, or the eight per-row mandatory fields fails
here in reviewed test code (mirroring tests/test_seam_closure_selftest.py),
and (2) feeds the checker synthetic good/bad fragments and asserts it
DISCRIMINATES - a conforming ledger (including the prescribed SPARSE-
supersession shape, which restates ONLY changed fields plus the eight
per-row-mandatory ones) yields nothing, a NON-conforming sparse row that omits
one of the eight fires, an intermediate violation a later row restores is
still caught (the ledger is a FIELD-WISE MERGE, not last-row-wins), and a
malformed `recorded_at` is flagged rather than silently swallowed - including
the dangerous direction where it can hide a real severity escalation.
(3) exercises the CLI exit-code contract via subprocess, pinned to a scratch
git repo so the --base tests don't depend on this checkout's own state.

Imports the hyphenated script via importlib. Stdlib only. Exit 0 = pass.
"""
from __future__ import annotations

import ast
import importlib.util
import inspect
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ci" / "check-governance-ledger.py"
_REPO_ROOT = _SCRIPT.parents[2]


def _load():
    spec = importlib.util.spec_from_file_location("check_governance_ledger", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load()
_FAILURES: list[str] = []


def expect(cond, label):
    print(("  ok:   " if cond else "  FAIL: ") + label)
    if not cond:
        _FAILURES.append(label)


def _full(**kw):
    """A complete, conforming governance-agent row - carries all eight fields
    SKILL.md mandates on EVERY row (schema_version, run_id, finding_id,
    recorded_by, recorded_at, pass_ordinal, reviewed_at_sha, disposition),
    plus epistemic_status/provenance/classification at valid non-null values
    (SKILL.md marks these required, not nullable, unlike impact/exposure) and
    the usual finding-content fields."""
    base = {
        "schema_version": 1, "run_id": None, "finding_id": "f1",
        "reporter": "architect", "source": "governance-agent",
        "reviewed_at_sha": "abc123 (merge-base def456)", "recorded_by": "Claude",
        "recorded_at": "2026-09-15T10:00:00Z", "pass_ordinal": 0,
        "severity_native": "MEDIUM", "severity_mapped": "SHOULD",
        "impact": ["I6"], "exposure": ["E0"], "policy_floor": None,
        "classification": "truth-contradiction", "epistemic_status": "likely",
        "provenance": "introduced", "disposition": "open", "independent_reporters": 1,
        "adjudicated_by": None, "adjudication_rationale": None,
    }
    base.update(kw)
    return base


def _sparse(**kw):
    """A CONFORMING sparse supersession row: carries exactly the eight
    per-row-mandatory fields (defaults matching _full()'s finding_id/sha/etc)
    plus whatever else the caller wants to restate. Fields NOT in the eight
    (impact, severity_native, classification, ...) are legitimately omitted
    when unchanged - the whole point of the sparse shape."""
    base = {
        "schema_version": 1, "run_id": None, "finding_id": "f1",
        "recorded_by": "Claude", "reviewed_at_sha": "abc123 (merge-base def456)",
        "recorded_at": "2026-09-15T11:00:00Z", "pass_ordinal": 0,
        "disposition": "fixed",
    }
    base.update(kw)
    return base


def _write(dirpath, stem, rows, stamp_run_id=True):
    p = Path(dirpath) / f"{stem}.jsonl"
    if stamp_run_id:
        for r in rows:
            if "run_id" in r:  # only stamp rows that carry the key (keep sparse rows sparse)
                r["run_id"] = stem
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return str(p)


def _rules(findings):
    return sorted({f.rule for f in findings})


def _scratch_git_repo(tmp):
    """A throwaway one-commit git repo, isolated from this checkout's actual
    history/working tree, so the CLI --base tests are fully deterministic
    regardless of what's currently staged/changed in the real repository."""
    repo = Path(tmp) / "scratch-repo"
    repo.mkdir()
    for args in (["init", "-q"], ["config", "user.email", "t@t.example"],
                ["config", "user.name", "test"]):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
    (repo / "README.md").write_text("x")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo, check=True, capture_output=True)
    return repo


def run():
    # -------- (1) constant + derivation pinning (mutation-proofing) --------
    expect(M._BASE == {"I1": "HIGH", "I2": "HIGH", "I3": "HIGH", "I4": "HIGH",
                       "I5": "MEDIUM", "I6": "MEDIUM", "I7": "MEDIUM",
                       "I8": "LOW", "I9": "INFO"}, "pin _BASE band table")
    expect(set(M.IMPACTS) == {f"I{i}" for i in range(1, 10)}, "pin IMPACTS")
    expect(set(M.EXPOSURES) == {f"E{i}" for i in range(0, 8)} | {"unresolved"}, "pin EXPOSURES")
    expect(set(M.MAPPED) == {"BLOCKING", "SHOULD", "NICE"}, "pin MAPPED")
    expect(set(M.SOURCES) == {"governance-agent", "collaborator", "external-model"}, "pin SOURCES")
    expect(set(M.ATTESTATION) == {"adjudicated_by", "adjudication_rationale", "refuted_by",
                                  "refuted_by_reporter", "waiver_rationale"}, "pin ATTESTATION set")
    expect(set(M.LIST_FIELDS) == {"impact", "exposure"}, "pin LIST_FIELDS")
    expect(set(M._HIGH_CAPPED) == {"I4", "I7"}, "pin _HIGH_CAPPED")
    expect(M._LABEL_CEILING == {"BLOCKING": "CRITICAL", "SHOULD": "MEDIUM", "NICE": "LOW"},
           "pin _LABEL_CEILING")
    expect(M._ORDER == ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], "pin _ORDER")
    expect(tuple(M.REQUIRED_ROW_FIELDS) == ("schema_version", "run_id", "finding_id", "recorded_by",
                                            "recorded_at", "pass_ordinal", "reviewed_at_sha", "disposition"),
           "pin REQUIRED_ROW_FIELDS (the eight SKILL.md mandates on every row)")
    expect(set(M.EPISTEMIC_STATUSES) == {"verified", "likely", "speculative"}, "pin EPISTEMIC_STATUSES")
    expect(set(M.PROVENANCES) == {"introduced", "newly-reachable", "pre-existing"}, "pin PROVENANCES")
    expect(set(M.CLASSIFICATIONS) == {"wording", "truth-contradiction", "absence"}, "pin CLASSIFICATIONS")
    expect(set(M.DISPOSITIONS_CLOSED) == {"open", "fixed", "split", "re-cut", "rejected", "refuted"},
           "pin DISPOSITIONS_CLOSED")
    expect(tuple(M.DISPOSITION_PREFIXES) == ("deferred-to-issue #", "roadmap-#", "linked-to-#"),
           "pin DISPOSITION_PREFIXES")
    expect(tuple(M._FLOOR_MARKERS) == ("CLAUDE.md", "ADR", "routed-concern", "routed concern"),
           "pin _FLOOR_MARKERS")
    expect(set(M._V2619_ONLY_FIELDS) == {"schema_version", "source", "reporter_ref", "reviewed_at_sha",
                                         "recorded_at", "recorded_by", "adjudication_rationale",
                                         "refuted_by", "refuted_by_reporter"},
           "pin _V2619_ONLY_FIELDS (SKILL.md's own citation of what a legacy row lacks)")
    expect(M._looks_versioned({"recorded_by": "x"}) is True,
           "_looks_versioned: a single #2619-only field is sufficient (round-3 fix)")
    expect(M._looks_versioned({"classification": "absence"}) is True,
           "_looks_versioned: classification=='absence' counts too")
    expect(M._looks_versioned({"reporter": "architect", "impact": ["I6"]}) is False,
           "_looks_versioned: none of the markers present -> genuinely legacy")
    expect(M.min_derived_band(["I9"], ["E0"]) == "INFO", "derive I9/E0 -> INFO")
    expect(M.min_derived_band(["I3"], ["E0"]) == "HIGH", "derive I3/E0 -> HIGH")
    expect(M.min_derived_band(["I6"], ["E1"]) == "HIGH", "derive I6/E1 -> HIGH (E1 raises)")
    expect(M.min_derived_band(["I2"], ["E6"]) == "LOW", "derive I2/E6 -> LOW (E6 caps)")
    # E7 added 2026-09-16 (author-controlled input to advisory tooling caps
    # at MEDIUM - see SKILL.md's severity-derivation table for why).
    expect(M.min_derived_band(["I1"], ["E7"]) == "MEDIUM",
           "derive I1/E7 -> MEDIUM (E7 caps a would-be-CRITICAL finding)")
    expect(M.min_derived_band(["I9"], ["E7"]) == "INFO",
           "derive I9/E7 -> INFO (E7 never RAISES a genuinely low-impact finding)")
    expect(M.min_derived_band(["I1"], ["E6", "E7"]) == "LOW",
           "derive I1/E6+E7 -> LOW (E6's stronger cap dominates E7's, either order)")
    # Locks raise-before-cap ORDERING, not just the cap in isolation: I1's base
    # HIGH raises to CRITICAL under E1/E2, and only THEN does E7 cap it to
    # MEDIUM. A regression that capped before raising (HIGH->MEDIUM, then
    # MEDIUM->HIGH) would pass every assertion above and still be wrong.
    expect(M.min_derived_band(["I1"], ["E1", "E7"]) == "MEDIUM",
           "derive I1/E1+E7 -> MEDIUM (raise to CRITICAL applies before E7's cap)")
    expect(M.min_derived_band(["I1"], ["E2", "E7"]) == "MEDIUM",
           "derive I1/E2+E7 -> MEDIUM (raise to CRITICAL applies before E7's cap)")
    expect(M.min_derived_band(["I4"], ["E1"]) == "HIGH", "derive I4/E1 -> HIGH (I4 cap, F9)")
    expect(M.min_derived_band([], ["E0"]) == "INFO", "derive empty -> INFO")
    expect(M.min_derived_band(["I1", "I4"], ["E1"]) == "CRITICAL",
           "per-impact cap: I1 escalates to CRITICAL under E1 even alongside I4's own HIGH cap")
    expect(M.floor_cites_closed_source("CLAUDE.md standing rule 2") is True,
           "floor_cites_closed_source recognizes a real citation")
    expect(M.floor_cites_closed_source("just because") is False,
           "floor_cites_closed_source rejects a bare excuse string")
    # round-4 review blocker: a parsed-but-offset-less recorded_at must be
    # treated as AMBIGUOUS, not silently coerced to UTC (one parseability
    # tier away from the wholly-invalid-string case round 2 already fixed).
    expect(M._instant("2026-09-15") is None, "_instant rejects a bare date (no time, no offset)")
    expect(M._instant("2026-09-15T08:00:00") is None, "_instant rejects a naive datetime (no offset)")
    expect(M._instant("2026-09-15T08:00:00Z") is not None, "_instant still accepts a Z-suffixed instant")
    expect(M._instant("2026-09-15T08:00:00+05:00") is not None, "_instant still accepts an explicit offset")

    # round-7 review blocker (C2): Python's fromisoformat (3.11+) is far more
    # lenient than RFC 3339 - it accepts a lowercase-z UTC marker FOLLOWED BY
    # an explicit numeric offset (the two disagree and the offset silently
    # wins), a literal garbage character in the same position, and even an
    # arbitrary single character as the date/time separator. Each of these
    # still parses to a DEFINITE instant, so - unlike the wholly-unparseable
    # or offset-less cases above - it would silently participate in merge
    # ordering rather than being caught, which can invert which of two rows
    # supersedes the other. Pin the grammar's exact pattern (round-6's own
    # "should fix": a behavioral-instance-only self-test can't catch a future
    # one-character regex widening) and its rejections:
    expect(M._INSTANT_RE.pattern ==
           r"^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt](?:[01][0-9]|2[0-3]):[0-9]{2}:[0-9]{2}"
           r"(\.[0-9]+)?(Z|z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$",
           "pin _INSTANT_RE grammar")

    # round-7 review "should fix" (C1/K1): the round-6 finding_id grammar and
    # the disposition-suffix content check were verified correct against the
    # real corpus and an exhaustive Unicode sweep, but neither pattern was
    # PINNED - a future one-character widening of either (e.g. admitting
    # U+115F into _FID_TOKEN's tail charset) would silently reintroduce the
    # exact split-key/blank-suffix defect these rounds closed, while every
    # existing behavioral-instance assertion below kept passing (both
    # reviewers independently reproduced this exact mutation and confirmed
    # the shipped self-test, unmodified, still reports success against it).
    expect(M._FID_TOKEN.pattern == r"[A-Za-z0-9][A-Za-z0-9._+/,-]*",
           "pin _FID_TOKEN grammar (round-6 finding_id merge-key fix)")
    expect(M._DISPOSITION_SUFFIX_CONTENT_RE.pattern == r"[A-Za-z0-9?]",
           "pin the disposition '#<id>' suffix content grammar (round-6 fix)")
    expect(M._instant("2026-09-15T10:00:00z+14:00") is None,
           "_instant rejects a lowercase-z marker FOLLOWED BY an explicit offset (self-contradictory)")
    expect(M._instant("2026-09-15T10:00:00x+14:00") is None,
           "_instant rejects a literal garbage character in the zone-marker position")
    expect(M._instant("2026-09-15T10:00:00zz") is None,
           "_instant rejects a doubled lowercase-z (not a single terminal zone token)")
    expect(M._instant("2026-09-15X10:00:00+00:00") is None,
           "_instant rejects an arbitrary (non-T/t) date/time separator character")
    expect(M._instant("2026-09-15T10:00:00+1400") is None,
           "_instant rejects a colon-less numeric offset (not the corpus's canonical shape)")

    # round-7 review blocker, found independently by BOTH Fable and Sol on
    # THIS round's own fix: the anchored grammar validates SHAPE (digit count/
    # position) but not RANGE. An out-of-range field (month 13, day 30 in
    # February, minute 60, an offset past +/-24:00) fullmatches the grammar
    # and only fails at fromisoformat - which RAISES rather than returning a
    # bad value. An earlier version of this round's fix let that exception
    # escape UNCAUGHT: a single out-of-range recorded_at (the single most
    # realistic hand-typing mistake in this field) would crash the whole
    # check_fragment() call, silencing every other finding in the run, rather
    # than reporting the one bad row as bad-recorded-at. This must behave
    # exactly like every other malformed-timestamp case: None, never a raise.
    for bad in ("2026-13-01T00:00:00Z", "2026-02-30T00:00:00Z",
                "2026-09-15T23:60:00Z", "2026-09-15T10:00:00+24:00",
                "2026-09-15T10:00:00+99:99"):
        expect(M._instant(bad) is None,
               f"_instant treats an out-of-range field ({bad!r}) as unparseable, not a crash")
    # Sol's independent finding: `\d` in a str pattern matches every Unicode
    # Nd-category digit (Arabic-Indic, fullwidth, ...), not just ASCII -
    # _FID_TOKEN spells its classes out for exactly this reason and this
    # grammar must too, or a non-ASCII-digit timestamp fullmatches here and
    # is only caught two lines later by fromisoformat raising (the same
    # crash class as the range-validation gap above).
    expect(M._instant("２０２６-09-15T10:00:00Z") is None,
           "_instant rejects fullwidth-digit (non-ASCII \\d) date fields")
    expect(M._instant("2026-09-15T10:00:00.١Z") is None,
           "_instant rejects an Arabic-Indic digit in the fractional-seconds field")

    # round-8 review blocker #1 (Fable + Sol, independently converged then
    # cross-confirmed): the offset alternative was an unconstrained
    # `[0-9]{2}:[0-9]{2}`, admitting minute values 60-99 - which fromisoformat
    # NORMALIZES rather than rejecting ("+05:60" silently becomes "+06:00").
    # A malformed-but-accepted offset still parses to a DEFINITE instant, the
    # same escalation-loss mechanism as every prior finding in this field.
    expect(M._instant("2026-09-15T10:00:00+05:60") is None,
           "_instant rejects an offset with minutes >= 60 (silently normalized by fromisoformat, not raised)")
    expect(M._instant("2026-09-15T10:00:00-00:99") is None,
           "_instant rejects an offset with minutes >= 60 (negative sign variant)")
    expect(M._instant("2026-09-15T10:00:00+23:59") is not None,
           "_instant still accepts the maximum valid offset (+23:59)")
    expect(M._instant("2026-09-15T10:00:00+24:00") is None,
           "_instant rejects an offset with hours >= 24 (grammar-level now, not just fromisoformat)")

    # round-8 review blocker #2 (Fable + Sol, independently converged then
    # cross-confirmed): fromisoformat truncates fractional seconds to 6
    # digits, but _INSTANT_RE deliberately admits more (the real corpus has
    # 34 rows with 7-9 digits) - so two rows differing only PAST microsecond
    # precision parse to the IDENTICAL datetime, a false tie that falls
    # through to pass_ordinal (reserved for GENUINE ties) and can invert the
    # rows' real order. _frac_key compares the raw fractional-digit string
    # (trailing zeros stripped, then plain string comparison - see its own
    # docstring for why this is exact at any digit count) to break the tie
    # at the true precision before ever reaching pass_ordinal.
    expect(M._frac_key("2026-09-15T10:00:00.0000001Z") <
           M._frac_key("2026-09-15T10:00:00.0000002Z"),
           "_frac_key orders sub-microsecond fractions fromisoformat's own comparison would tie")
    expect(M._frac_key("2026-09-15T10:00:00.1Z") == M._frac_key("2026-09-15T10:00:00.10Z"),
           "_frac_key treats '.1' and '.10' as the equal decimals they denote (0.1 == 0.10)")
    expect(M._frac_key("2026-09-15T10:00:00.09Z") < M._frac_key("2026-09-15T10:00:00.1Z"),
           "_frac_key orders '.09' before '.1' (0.09 < 0.1), not by raw digit-string comparison")
    expect(M._frac_key("2026-09-15T10:00:00Z") == "", "_frac_key is empty for a fraction-less timestamp")

    # round-8 CONFIRMATION-pass finding (Fable + Sol, both independently
    # reproduced against THIS round's own fix, before push): the first
    # version of _frac_key right-padded the raw digit string to a FIXED
    # width (32 chars) and converted to int - a second instance of the
    # exact "validates one dimension, not the actual unbounded range" defect
    # this whole field's review cycle has chased, since _INSTANT_RE's
    # fractional group is unbounded (`[0-9]+`). Two consequences:
    # (a) OVERFLOW: a 34-digit fraction padded to 32 chars is UNCHANGED
    #     (ljust only pads shorter strings), so it compares as a LARGER int
    #     than a 32-digit fraction even when its true decimal value is
    #     SMALLER - inverting merge order silently, zero findings.
    long_a = "2026-09-15T10:00:00." + ("0" * 6) + "1" + ("0" * 27) + "Z"  # 34 digits: 0.0000001...
    long_b = "2026-09-15T10:00:00.0000002Z"                              # 32 digits: 0.0000002
    expect(M._frac_key(long_a) < M._frac_key(long_b),
           f"_frac_key orders a 34-digit fraction (0.0000001...) correctly below a 32-digit one "
           f"(0.0000002) - NOT by raw padded-string/int length (got {M._frac_key(long_a)!r} "
           f"vs {M._frac_key(long_b)!r})")
    # (b) CRASH: Python 3.11+ caps `int(str)` conversion at 4300 digits
    #     (sys.get_int_max_str_digits, CVE-2020-10735 mitigation);
    #     _INSTANT_RE's unbounded fractional group admits a longer digit
    #     string, so `int(...)` on it raises uncaught INSIDE sorted() - the
    #     same crash class round 7 fixed one function earlier in the call
    #     chain. The round-8 fix replaced the padded int with Decimal, which
    #     has no such limit ON THE STANDARD C-EXTENSION BUILD.
    #
    # round-9 review (Fable + Sol, independently converged) found that
    # Decimal ITSELF reopens the same crash on any CPython built WITHOUT the
    # C `_decimal` extension: the pure-Python `_pydecimal` fallback
    # constructs a Decimal via `int()` internally, hitting the identical
    # cap. The current fix drops Decimal entirely (see _frac_key's own
    # docstring) - a fraction of any length is handled by pure string
    # operations, with no int()/Decimal-based path to reopen on ANY
    # interpreter build.
    huge_frac = "2026-09-15T10:00:00." + ("1" * 5000) + "Z"
    expect(M._instant(huge_frac) is not None,
           "a 5000-digit fraction (past int()'s 4300-digit string-conversion cap) still parses")
    expect(isinstance(M._frac_key(huge_frac), type(M._frac_key("2026-09-15T10:00:00.1Z"))),
           "_frac_key doesn't crash on a 5000-digit fraction (past int()'s conversion cap)")
    with tempfile.TemporaryDirectory() as huge_d:
        huge_path = _write(huge_d, "9-hugefrac.X", [
            {"finding_id": "huge1", "run_id": "9-hugefrac.X", "pass_ordinal": 0,
             "recorded_at": huge_frac, "disposition": "open"}])
        cli_huge = subprocess.run([sys.executable, str(_SCRIPT), "--files", huge_path],
                                   capture_output=True, text=True)
        expect(cli_huge.returncode in (0, 1) and "Traceback" not in cli_huge.stderr,
               f"CLI on a 5000-digit fraction never crashes with a Python traceback "
               f"(got exit={cli_huge.returncode}, stderr={cli_huge.stderr[:200]!r})")

    # round-10 review should-fix (Fable + Sol): the round-9 fix that removed
    # Decimal from _frac_key (closing a real crash on Python's pure
    # `_pydecimal` fallback) is NOT locked against reintroduction, because
    # every self-test assertion above pins _frac_key's BEHAVIOR (the
    # ordering it produces) rather than its IMPLEMENTATION - a Decimal-based
    # reimplementation that happens to return byte-identical strings would
    # pass every behavioral assertion while still crashing on the pure-
    # Python fallback. This exact regression already occurred once in this
    # PR's own history (round 8 introduced Decimal; round 9's pre-push
    # review caught and removed it) - "ordinary missing coverage" language
    # doesn't cover a defect shape that has already recurred once.
    #
    # Fable's OWN confirmation pass on the first version of these two locks
    # (below) found they pinned the wrong boundary: leaving _frac_key
    # BYTE-IDENTICAL and instead wrapping ITS RESULT with
    # `Decimal("0." + _frac_key(ra))` one frame up, inside _order_key,
    # defeated BOTH locks - lock (a) only walked _frac_key's own source, and
    # lock (b) only called _frac_key directly, never the sort path that
    # actually wraps its result. That mutant crashes real usage identically
    # to round 8's shipped defect (verified: reintroducing it and blocking
    # `_decimal` reproduces the exact `int(str)` 4300-digit ValueError,
    # while the unwidened locks below both passed it clean). Two
    # independent locks, now scoped to the WHOLE numeric-conversion surface
    # rather than one function:
    #
    # (a) STRUCTURAL, MODULE-WIDE: an AST walk of the ENTIRE module - not
    #     just _frac_key - asserting no `import decimal`/`from decimal
    #     import ...`/`import fractions` and no call named
    #     Decimal/Fraction/int/float ANYWHERE. Scoping to the whole module
    #     (rather than one function) is what catches a Decimal-wrapping
    #     mutation introduced at any call site, not just inside _frac_key
    #     itself; nothing legitimate in this file needs any of these.
    forbidden_imports = {"decimal", "fractions"}
    forbidden_calls = {"Decimal", "Fraction", "int", "float"}
    found = set()
    module_tree = ast.parse(inspect.getsource(M))
    for node in ast.walk(module_tree):
        if isinstance(node, ast.Import):
            found |= {f"import {a.name}" for a in node.names if a.name in forbidden_imports}
        elif isinstance(node, ast.ImportFrom) and node.module in forbidden_imports:
            found.add(f"from {node.module}")
        elif isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", None)
            if name in forbidden_calls:
                found.add(f"call {name}")
    expect(not found,
           f"the WHOLE module contains no decimal/fractions import and no "
           f"Decimal/Fraction/int/float call anywhere - not just inside _frac_key - since a "
           f"digit-count-capped conversion wrapped around _frac_key's result at its call "
           f"site would reintroduce round 8's crash just as surely as inside the function "
           f"itself (found: {found or 'none'})")
    # (b) BEHAVIORAL, end-to-end, under the ACTUAL failure condition AND
    #     through the ACTUAL call path: a fresh subprocess with the C
    #     `_decimal` extension blocked BEFORE any import of `decimal`,
    #     which imports this module fresh and runs a full two-row
    #     SAME-finding_id fragment through `check_fragment()` (the real
    #     sort path, via `_order_key` - NOT calling `_frac_key` directly,
    #     which is exactly the frame Fable's mutant hid behind) with a
    #     5000-digit fraction on each row.
    decimal_block_probe = f"""
import sys
sys.modules['_decimal'] = None
import importlib.util
spec = importlib.util.spec_from_file_location('M', {str(_SCRIPT)!r})
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
huge_a = "2026-09-15T10:00:00." + ("1" * 5000) + "Z"
huge_b = "2026-09-15T10:00:00." + ("2" * 5000) + "Z"
rows = [
    {{"finding_id": "hf", "run_id": "hf", "pass_ordinal": 0,
      "recorded_at": huge_a, "disposition": "open"}},
    {{"finding_id": "hf", "run_id": "hf", "pass_ordinal": 0,
      "recorded_at": huge_b, "disposition": "fixed"}},
]
import json, tempfile, os
d = tempfile.mkdtemp()
p = os.path.join(d, "hf.jsonl")
with open(p, "w") as f:
    for r in rows:
        f.write(json.dumps(r) + chr(10))
findings = M.check_fragment(p)
print("OK", len(findings))
"""
    probe = subprocess.run([sys.executable, "-c", decimal_block_probe],
                            capture_output=True, text=True)
    expect(probe.returncode == 0 and probe.stdout.startswith("OK") and "Traceback" not in probe.stderr,
           f"a two-row 5000-digit-fraction fragment runs through the REAL sort path "
           f"(check_fragment -> _order_key) without crashing, with the C `_decimal` "
           f"extension blocked (forcing the pure-Python fallback) - the exact condition "
           f"round 8's shipped Decimal-based version crashed under, exercised through the "
           f"actual call path rather than calling _frac_key directly "
           f"(got exit={probe.returncode}, stdout={probe.stdout!r}, stderr={probe.stderr[:200]!r})")

    # round-11 review should-fix (Fable + Sol, independently converged then
    # cross-confirmed): the two round-10 locks above only ask "does it
    # crash", never "does it produce the RIGHT ordering". Both reviewers
    # independently constructed a plain, non-adversarial mutant that evades
    # both: aliasing `float` under an innocuous name (`coerce = float`) and
    # using `coerce(...)` in place of the real fractional key. The AST lock
    # finds nothing (the callee is named `coerce`, not `Decimal`/`int`/
    # `float`); the crash-safety probe PASSES (`float()` truncates silently
    # rather than raising like `Decimal`/`int()` do on a very long digit
    # string) - but it silently reintroduces a FALSE TIE for two fractions
    # differing only beyond float's ~15-17-significant-digit precision,
    # exactly the round-8 escalation-loss mechanism, one precision order
    # down. This is a correctness gap in the LOCK, not the shipped code
    # (verified: the real _frac_key is pure string comparison with no
    # precision limit) - a discriminating assertion through the real
    # _order_key/merged_view path, with pass_ordinal deliberately REVERSED
    # (mirroring the existing F1/sub-microsecond tests' own technique), so a
    # false-tie-driven fallback to pass_ordinal picks the WRONG row.
    prec_a = "3" * 20 + "1"  # 21 significant digits: any float-based key collapses this...
    prec_b = "3" * 20 + "2"  # ...and this to the IDENTICAL float, despite b > a as real numbers
    prec_rows = [
        {"finding_id": "pf", "run_id": "9-precfloat.X", "pass_ordinal": 9,
         "recorded_at": f"2026-09-15T10:00:00.{prec_a}Z", "disposition": "open"},
        {"finding_id": "pf", "run_id": "9-precfloat.X", "pass_ordinal": 1,
         "recorded_at": f"2026-09-15T10:00:00.{prec_b}Z", "disposition": "fixed"},
    ]
    # round-11 confirmation-pass minor (FortitudeEtc/Kimi+Sol synthesis): on
    # an interpreter where fromisoformat rejects a >6-digit fraction
    # outright, BOTH rows above would fall through _instant's None path to
    # the legacy (file-order) sort key - the assertion below would then pass
    # VACUOUSLY (by file order, never touching _frac_key's comparison at
    # all), silently un-exercising exactly the round-8 false-tie class this
    # test exists to catch, rather than failing loudly. Assert the
    # precondition explicitly so a too-old interpreter fails LOUDLY here
    # instead of silently skipping the real check.
    expect(M._instant(prec_rows[0]["recorded_at"]) is not None,
           "precondition: this interpreter parses a 21-digit fraction (required for the "
           "float-precision assertion below to actually exercise _frac_key, not file order)")
    prec_ordered = sorted(((i, r) for i, r in enumerate(prec_rows)), key=M._order_key)
    expect(M.merged_view(prec_ordered).get("disposition") == "fixed",
           "fractional precision beyond float's significant-digit limit still orders correctly "
           "(a float-based key would tie these and fall through to the deliberately-reversed "
           "pass_ordinal, picking the wrong row)")

    # round-11 CONFIRMATION-pass finding (Sol): the 21-digit assertion above
    # is specific to float's ~15-17-significant-digit precision and does NOT
    # close a sibling mutant - `coerce = int; coerce((_frac_key(ra) + "0"*64)
    # [:64])` - that pads/truncates to a FIXED 64-digit width before
    # converting, passing the AST lock (callee named `coerce`), the 5000-
    # digit crash-safety probe (only 64 digits are ever converted, so int()'s
    # cap is never approached), AND the 21-digit correctness assertion above
    # (64 digits is more than enough precision for a 21-digit difference) -
    # while still ties-and-inverts two fractions differing ONLY past digit
    # 64. This is the round-8 fixed-width-truncation defect again, at a
    # different (much larger) width. No single "big enough" width closes
    # this in principle - a mutant can always pick a width one digit larger
    # than whatever this test checks. Matching this file's own established
    # judgment call elsewhere (round-9/10 reviews explicitly treated
    # sufficiently-contrived dynamic-construction bypasses as unreasonable
    # adversarial stretches rather than open-ended obligations): a
    # correctness check at a width far beyond any plausible REAL fixed-width
    # constant a future edit might pick (64, 128, 256, 1024 are all
    # "reasonable-looking" numbers; 5000+ is not) makes the remaining gap a
    # bounded-but-absurd residual, not a realistic one - and it reuses the
    # exact width the crash-safety probe already established as the
    # profile's outer edge, so there is no new magic number to justify.
    huge_prec_a = "9" * 4999 + "1"
    huge_prec_b = "9" * 4999 + "2"
    huge_prec_rows = [
        {"finding_id": "hpf", "run_id": "9-hugeprecfloat.X", "pass_ordinal": 9,
         "recorded_at": f"2026-09-15T10:00:00.{huge_prec_a}Z", "disposition": "open"},
        {"finding_id": "hpf", "run_id": "9-hugeprecfloat.X", "pass_ordinal": 1,
         "recorded_at": f"2026-09-15T10:00:00.{huge_prec_b}Z", "disposition": "fixed"},
    ]
    # round-11 confirmation-pass minor: same precondition, for the same
    # reason, at the 5000-digit width.
    expect(M._instant(huge_prec_rows[0]["recorded_at"]) is not None,
           "precondition: this interpreter parses a 5000-digit fraction (required for the "
           "huge-precision assertion below to actually exercise _frac_key, not file order)")
    huge_prec_ordered = sorted(((i, r) for i, r in enumerate(huge_prec_rows)), key=M._order_key)
    expect(M.merged_view(huge_prec_ordered).get("disposition") == "fixed",
           "fractional precision at 5000 digits, differing only in the LAST digit, still orders "
           "correctly - closing any fixed-width numeric-conversion scheme up to that width "
           "(a bounded truncate-then-convert mutant would tie these and fall through to the "
           "deliberately-reversed pass_ordinal, picking the wrong row)")

    # round-8 CONFIRMATION-pass finding (Sol): "-00:00" is valid RFC 3339
    # syntax but its EXACT spelling is reserved (section 4.3) to mean "local
    # offset unknown", distinct from "+00:00" (genuinely UTC) - Python parses
    # both identically to UTC, silently discarding that distinction. Unlike
    # every other malformed shape in this field, this does NOT shift the
    # resulting instant (both are UTC either way) - but it contradicts this
    # function's own "unambiguous instant" contract, since the writer is
    # explicitly declaring they did not know their true offset.
    expect(M._instant("2026-09-15T10:00:00-00:00") is None,
           "_instant rejects '-00:00' (RFC 3339's reserved 'unknown local offset' spelling)")
    expect(M._instant("2026-09-15T10:00:00+00:00") is not None,
           "_instant still accepts '+00:00' (genuinely UTC, not the unknown-offset marker)")

    # round-9 review blocker (Fable + Sol, independently converged then
    # cross-confirmed): the TIME-hour field was shape-only (`[0-9]{2}`),
    # admitting hour 24. ISO-8601 permits hour 24 ONLY as "end of day"
    # notation, legal exclusively when minute/second/EVERY fractional digit
    # is zero - but fromisoformat's own hour-24 legality check runs against
    # the SIX-DIGIT-TRUNCATED fractional value, not the real one this
    # field's own exact-precision fix (_frac_key) separately preserves for
    # ordering. A nonzero 7th fractional digit is silently accepted as
    # midnight while still being ordered by its true nonzero value - the
    # identical "validate the lossy value, order by the lossless value" seam
    # that produced round 8's own blocker, one field over. Rejecting hour 24
    # entirely (0 real corpus values use ANY hour-24 spelling) closes it.
    expect(M._instant("2026-09-15T24:00:00.0000001Z") is None,
           "_instant rejects hour-24 with a nonzero 7th fractional digit (the exact escalation-loss repro)")
    expect(M._instant("2026-09-15T24:00:00.000001Z") is None,
           "_instant rejects hour-24 with a genuinely nonzero (6-digit) fractional value")
    expect(M._instant("2026-09-15T24:00:00Z") is None,
           "_instant rejects hour-24 entirely, including the ISO-legal all-zeros 'end of day' spelling "
           "(0 real corpus values use it; simpler than special-casing)")
    expect(M._instant("2026-09-15T23:59:59Z") is not None,
           "_instant still accepts the maximum valid hour (23)")

    with tempfile.TemporaryDirectory() as d:
        # -------- (2a) field-wise merge: a CONFORMING sparse supersession is clean --------
        # row1 is the full finding; row2 restates the eight per-row-mandatory
        # fields PLUS disposition (the only content field that changed) -
        # exactly the shape SKILL.md prescribes. Last-row-replace would
        # false-fire missing-field; the field-wise merge keeps row1's content.
        sparse = _write(d, "1234-sparse.AbCd", [
            _full(finding_id="a"),
            _sparse(finding_id="a"),
        ])
        expect(M.check_fragment(sparse) == [],
               f"conforming sparse supersession (all 8 mandatory fields + disposition) is clean "
               f"(got {_rules(M.check_fragment(sparse))})")

        # -------- (2a-neg) a NON-conforming sparse row (omits mandatory fields) fires --------
        nonconforming = _write(d, "1234-nonconf.AbCd", [
            _full(finding_id="a"),
            {"finding_id": "a", "recorded_at": "2026-09-15T11:00:00Z", "disposition": "fixed"},
        ])
        ncf = M.check_fragment(nonconforming)
        expect(_rules(ncf) == ["missing-row-field"],
               f"non-conforming sparse row (omits schema_version/run_id/recorded_by/pass_ordinal/"
               f"reviewed_at_sha) fires missing-row-field only (got {_rules(ncf)})")
        expect(sum(f.rule == "missing-row-field" for f in ncf) == 5,
               f"exactly the 5 omitted mandatory fields are each reported (got {len(ncf)})")

        # -------- (2b) a fully-conforming multi-finding fragment is clean --------
        good = _write(d, "1234-clean.AbCd", [
            _full(finding_id="a", impact=["I6"], exposure=["E0"], severity_mapped="SHOULD"),
            _full(finding_id="b", impact=["I9"], exposure=["E0"], severity_mapped="NICE",
                  severity_native="NICE", classification="wording"),
            _full(finding_id="c", impact=["I3"], exposure=["E0"], severity_mapped="BLOCKING",
                  severity_native="HIGH", disposition="fixed"),
            # valid floored row: derived band in severity_mapped, floor separate
            _full(finding_id="e", impact=["I9"], exposure=["E0"], severity_mapped="NICE",
                  severity_native="INFO",
                  policy_floor="severity-derived-not-chosen (CLAUDE.md standing rule 2)"),
            # legit over-label (could be a conditional raise): I6/E0 as BLOCKING - NOT flagged
            _full(finding_id="g", impact=["I6"], exposure=["E0"], severity_mapped="BLOCKING",
                  severity_native="HIGH"),
            # external-model row with reporter_ref and independent_reporters=2 (F3: not flagged)
            _full(finding_id="h", source="external-model", reporter="FortitudeEtc",
                  reporter_ref="https://x/pr#r1", impact=["I5"], exposure=["E0"],
                  severity_mapped="SHOULD", severity_native="MEDIUM", independent_reporters=2),
            # a genuine, valid empty-impact + closed-source-floor BLOCKING row - not flagged
            _full(finding_id="k", impact=[], exposure=["E0"], severity_mapped="BLOCKING",
                  severity_native="HIGH", policy_floor="CLAUDE.md standing rule 2"),
            # every closed-vocabulary field at a valid value
            _full(finding_id="m", epistemic_status="likely", provenance="introduced",
                  classification="truth-contradiction", disposition="deferred-to-issue #17"),
        ])
        gf = M.check_fragment(good)
        expect(gf == [], f"clean multi-finding fragment yields nothing (got {_rules(gf)})")

        def fires(stem, rows, rule, label):
            f = M.check_fragment(_write(d, stem, rows))
            expect(rule in _rules(f), label + f" (got {_rules(f)})")

        def clean_of(stem, rows, rule, label):
            f = M.check_fragment(_write(d, stem, rows))
            expect(rule not in _rules(f), label + f" (got {_rules(f)})")

        # -------- (3) STRICT rules --------
        fires("9-under.X", [_full(finding_id="s", impact=["I3"], exposure=["E0"],
                                  severity_mapped="SHOULD")],
              "severity-under-derived", "under-grading fires")
        clean_of("9-over.X", [_full(finding_id="s", impact=["I6"], exposure=["E0"],
                                    severity_mapped="BLOCKING", severity_native="HIGH")],
                 "severity-under-derived", "over-label (possible conditional raise) NOT flagged (F2)")
        fires("9-empty.X", [_full(finding_id="s", impact=[], exposure=["E0"],
                                  severity_mapped="BLOCKING")],
              "severity-empty-impact", "empty impact + BLOCKING + no floor fires (F2)")
        # policy_floor gaming vector: a bogus/fabricated floor string must NOT
        # excuse an empty-impact BLOCKING claim; only a closed-source citation does.
        fires("9-fakefloor.X", [_full(finding_id="s", impact=[], exposure=["E0"],
                                      severity_mapped="BLOCKING", policy_floor="just because")],
              "severity-empty-impact", "empty impact + BLOCKING + FABRICATED floor still fires")
        clean_of("9-realfloor.X", [_full(finding_id="s", impact=[], exposure=["E0"],
                                         severity_mapped="BLOCKING",
                                         policy_floor="CLAUDE.md standing rule 2")],
                 "severity-empty-impact", "empty impact + BLOCKING + REAL closed-source floor is excused")
        fires("9-word.X", [_full(finding_id="w", classification="wording", impact=["I7"],
                                 exposure=["E0"], severity_mapped="SHOULD")],
              "wording-carries-i7", "wording+I7 fires")

        # native mutated across a RESTORED middle row (F5): MEDIUM -> LOW -> MEDIUM
        fires("9-native.X", [
            _full(finding_id="n", recorded_at="2026-09-15T10:00:00Z", severity_native="MEDIUM",
                  impact=["I6"], severity_mapped="SHOULD"),
            _full(finding_id="n", recorded_at="2026-09-15T11:00:00Z", severity_native="LOW",
                  impact=["I6"], severity_mapped="SHOULD"),
            _full(finding_id="n", recorded_at="2026-09-15T12:00:00Z", severity_native="MEDIUM",
                  impact=["I6"], severity_mapped="SHOULD")],
            "native-mutated", "mutated-then-restored native still fires (F5)")

        # F5 null-escape: null -> HIGH invents a band the reporter did not give
        fires("9-nativenull.X", [
            _full(finding_id="nn", recorded_at="2026-09-15T10:00:00Z", severity_native=None,
                  impact=["I6"], severity_mapped="SHOULD"),
            _full(finding_id="nn", recorded_at="2026-09-15T11:00:00Z", severity_native="HIGH",
                  impact=["I6"], severity_mapped="SHOULD")],
            "native-mutated", "null -> HIGH native invention fires (F5 null-escape)")

        # omission-then-presence is the SAME fabrication as null-then-presence:
        # the finding's first row never mentions severity_native at all (not
        # even as null), and a later row introduces "HIGH" out of nowhere.
        omit_first = _full(finding_id="oo", recorded_at="2026-09-15T10:00:00Z",
                           impact=["I6"], severity_mapped="SHOULD")
        omit_first.pop("severity_native")
        fires("9-nativeomit.X", [
            omit_first,
            _full(finding_id="oo", recorded_at="2026-09-15T11:00:00Z", severity_native="HIGH",
                  impact=["I6"], severity_mapped="SHOULD")],
            "native-mutated", "absent-key-then-present-value invents native too (minor fix)")

        # F1 ordering: a fractional-second timestamp is LATER than a bare one but
        # sorts EARLIER as a plain string. Discriminating check: the EARLIER (bare)
        # row is disposition:open, the LATER (fractional) row is disposition:fixed;
        # correct instant-order merges to 'fixed', a string sort would pick 'open'.
        frac_rows = [
            _full(finding_id="fr", recorded_at="2026-09-15T10:00:00Z", disposition="open"),
            {"finding_id": "fr", "run_id": "9-frac.X",
             "recorded_at": "2026-09-15T10:00:00.500Z", "disposition": "fixed"}]
        frac_ordered = sorted(((i, r) for i, r in enumerate(frac_rows)), key=M._order_key)
        expect(M.merged_view(frac_ordered).get("disposition") == "fixed",
               "fractional-second timestamp orders by instant, not string (merged disposition=fixed)")

        # bad-recorded-at: a versioned row whose timestamp doesn't parse is
        # reported, not silently swallowed as legacy.
        fires("9-badra.X", [
            _full(finding_id="br"),
            _sparse(finding_id="br", recorded_at="NOT-A-TIMESTAMP")],
            "bad-recorded-at", "unparseable recorded_at on a versioned row fires")

        # THE dangerous direction (round-2 review): a malformed timestamp on a
        # genuine severity ESCALATION must not let the fragment read as clean -
        # the escalation can silently lose the merge to the earlier, lower row.
        esc = _write(d, "9-escalation.X", [
            _full(finding_id="e1", recorded_at="2026-09-15T10:00:00Z",
                  severity_native="INFO", severity_mapped="NICE", impact=["I9"], exposure=["E0"]),
            _full(finding_id="e1", recorded_at="NOT-A-TIMESTAMP",
                  severity_native="HIGH", severity_mapped="BLOCKING", impact=["I1"], exposure=["E3"]),
        ])
        ef = M.check_fragment(esc)
        expect(any(f.rule == "bad-recorded-at" for f in ef),
               f"malformed-timestamp escalation is NOT reported clean (got {_rules(ef)})")

        # round-4 review blocker: an AMBIGUOUS timestamp (parses, but no
        # timezone offset) on a genuine escalation is just as dangerous as a
        # wholly-invalid one - reproduced for both the bare-date and the
        # naive-datetime forms.
        for ambiguous_ra, label in (("2026-09-15", "bare date"), ("2026-09-15T08:00:00", "naive datetime")):
            esc2 = _write(d, f"9-ambig-{label.replace(' ', '')}.X", [
                _full(finding_id="e1", recorded_at="2026-09-15T10:00:00Z",
                      severity_native="INFO", severity_mapped="NICE", impact=["I9"], exposure=["E0"]),
                _full(finding_id="e1", recorded_at=ambiguous_ra,
                      severity_native="HIGH", severity_mapped="BLOCKING", impact=["I1"], exposure=["E3"]),
            ])
            ef2 = M.check_fragment(esc2)
            expect(any(f.rule == "bad-recorded-at" for f in ef2),
                   f"ambiguous recorded_at ({label}) on an escalation is NOT reported clean "
                   f"(got {_rules(ef2)})")

        # reviewed_at_sha is NOT immutable: correcting it across a supersession
        # (e.g. an early pre-rebase SHA that no longer resolves) is legitimate.
        clean_of("9-sha.X", [
            _full(finding_id="h", recorded_at="2026-09-15T10:00:00Z", reviewed_at_sha="aaa"),
            _full(finding_id="h", recorded_at="2026-09-15T11:00:00Z", reviewed_at_sha="bbb")],
            "reviewed-sha-mutated", "reviewed_at_sha correction NOT flagged")

        # attestation pairing PER ROW (F5): a middle row with adjudicated_by only
        fires("9-adj.X", [
            _full(finding_id="p", recorded_at="2026-09-15T10:00:00Z"),
            _full(finding_id="p", recorded_at="2026-09-15T11:00:00Z",
                  adjudicated_by="someone", adjudication_rationale=None),
            _full(finding_id="p", recorded_at="2026-09-15T12:00:00Z", disposition="fixed")],
            "adjudication-pairing", "per-row attestation pairing fires on middle row (F5)")

        # round-5 follow-up (Sol+Fable both independently found this in the
        # "broader truthiness audit" the round-5 process note requested): a
        # bare `bool(x)` check on adjudicated_by/adjudication_rationale lets a
        # whitespace string, a bare int, or `False` itself read as "set".
        fires("9-adjws.X", [_full(finding_id="j", adjudicated_by="   ", adjudication_rationale="real")],
              "bad-adjudicated-by", "a whitespace-only adjudicated_by (with a real rationale) fires its own finding")
        fires("9-adjint.X", [_full(finding_id="j", adjudicated_by=7, adjudication_rationale="real")],
              "bad-adjudicated-by", "a bare-integer adjudicated_by fires")
        fires("9-adjratws.X", [_full(finding_id="j", adjudicated_by="real", adjudication_rationale="   ")],
              "bad-adjudication-rationale", "a whitespace-only adjudication_rationale fires")
        clean_of("9-adjbothnull.X", [_full(finding_id="j")],
                 "adjudication-pairing", "both null is clean")
        clean_of("9-adjbothreal.X", [_full(finding_id="j", adjudicated_by="x", adjudication_rationale="y")],
                 "adjudication-pairing", "both genuinely set is clean")

        # park constraint (F8)
        fires("9-park.X", [_full(finding_id="k", impact=["I1"], exposure=["E0"],
                                 severity_mapped="BLOCKING", severity_native="HIGH",
                                 disposition="roadmap-#999")],
              "parked-top-severity", "parked top-severity fires")

        # -------- (4) STRUCTURAL rules --------
        fires("9-listrep.X", [_full(finding_id="j", reporter=["a", "b"])],
              "list-reporter", "list-valued reporter fires (F6)")
        fires("9-plusrep.X", [_full(finding_id="j", reporter="a+b")],
              "joined-reporter", "unspaced + reporter fires (F6)")
        norep = _full(finding_id="j"); norep.pop("reporter")
        fires("9-norep.X", [norep], "missing-reporter", "absent reporter fires (F6)")
        fires("9-emptyrep.X", [_full(finding_id="j", reporter="")],
              "empty-reporter", "empty-string reporter fires")
        fires("9-intrep.X", [_full(finding_id="j", reporter=7)],
              "bad-reporter-type", "bare-integer reporter fires")
        fires("9-boolrep.X", [_full(finding_id="j", reporter=True)],
              "bad-reporter-type", "boolean reporter fires (bool is not a valid reporter string)")
        fires("9-src.X", [_full(finding_id="j", source="robot")], "bad-source", "bad source fires")
        badref = _full(finding_id="j", source="external-model"); badref.pop("reporter_ref", None)
        badref["reporter_ref"] = None
        fires("9-ref.X", [badref], "missing-reporter-ref", "external-model without ref fires")
        fires("9-scalar.X", [_full(finding_id="j", impact="I5")],
              "scalar-list-field", "scalar impact fires (F8)")
        fires("9-scalarexp.X", [_full(finding_id="j", exposure="E0")],
              "scalar-list-field", "scalar exposure ALSO fires (not just impact)")
        nofloor = _full(finding_id="j"); nofloor.pop("policy_floor")
        fires("9-floorkey.X", [nofloor], "missing-field", "missing policy_floor key fires")
        fires("9-boolir.X", [_full(finding_id="j", independent_reporters=True)],
              "bad-independent-reporters", "boolean independent_reporters fires (bool is not an int here)")
        fires("9-boolsv.X", [_full(finding_id="j", schema_version=True)],
              "bad-schema-version", "boolean schema_version fires")
        fires("9-negpo.X", [_full(finding_id="j", pass_ordinal=-1)],
              "bad-pass-ordinal", "negative pass_ordinal fires")
        fires("9-epi.X", [_full(finding_id="j", epistemic_status="certain")],
              "bad-epistemic-status", "off-enum epistemic_status fires")
        fires("9-prov.X", [_full(finding_id="j", provenance="somewhere")],
              "bad-provenance", "off-enum provenance fires")
        fires("9-cls.X", [_full(finding_id="j", classification="invented")],
              "bad-classification", "off-enum classification fires")
        fires("9-disp.X", [_full(finding_id="j", disposition="no_change_needed")],
              "bad-disposition", "off-enum disposition fires")
        clean_of("9-dispok.X", [_full(finding_id="j", disposition="deferred-to-issue #4")],
                 "bad-disposition", "valid '#N'-suffixed disposition is NOT flagged")
        # disposition TYPE violations (bedrock, apply regardless of legacy status)
        for bad_disp in (7, True, None, [], {}):
            fires(f"9-disptype-{type(bad_disp).__name__}.X", [_full(finding_id="j", disposition=bad_disp)],
                  "bad-disposition", f"non-string disposition {bad_disp!r} fires")
        # an empty '#' suffix is genuinely malformed - nothing follows the prefix
        fires("9-dispempty.X", [_full(finding_id="j", disposition="roadmap-#")],
              "bad-disposition", "empty '#' suffix ('roadmap-#') fires")
        # a non-empty but non-numeric suffix is DELIBERATELY still accepted: the
        # real corpus carries free-text notes trailing a placeholder
        # ("#TBD (draft: ...)"), so requiring a strictly numeric/placeholder
        # suffix would false-positive on legitimate historical/future entries.
        clean_of("9-dispgarbage.X", [_full(finding_id="j", disposition="linked-to-#garbage")],
                 "bad-disposition", "non-empty non-numeric '#' suffix is accepted (documented leniency)")
        clean_of("9-dispplaceholder.X", [_full(finding_id="j", disposition="deferred-to-issue #?")],
                 "bad-disposition", "the schema's own '#?' unfilled-park placeholder is accepted")
        # schema_version/pass_ordinal are two of the eight per-row-mandatory
        # fields: an explicit null is never legitimate once the key exists (it
        # would otherwise hide behind "key present", passing missing-row-field
        # for free) - unlike independent_reporters, which legitimately carries
        # null in the real corpus as "not yet counted".
        fires("9-svnull.X", [_full(finding_id="j", schema_version=None)],
              "bad-schema-version", "explicit null schema_version fires (not silently 'absent')")
        fires("9-ponull.X", [_full(finding_id="j", pass_ordinal=None)],
              "bad-pass-ordinal", "explicit null pass_ordinal fires (not silently 'absent')")
        clean_of("9-irnull.X", [_full(finding_id="j", independent_reporters=None)],
                 "bad-independent-reporters", "explicit null independent_reporters is NOT flagged (legit 'uncounted')")

        # round-4 review should-fix: generalize the pass_ordinal/run_id
        # per-row-VALUE pattern to the rest of the eight mandatory fields - a
        # bad value on an EARLY row that a later valid row "corrects" must
        # still fire, since the merge would otherwise erase all trace of it.
        fires("9-svearly.X", [
            _full(finding_id="e", recorded_at="2026-09-15T10:00:00Z", schema_version="one"),
            _full(finding_id="e", recorded_at="2026-09-15T11:00:00Z", schema_version=1, disposition="fixed")],
            "bad-schema-version", "a bad schema_version on an EARLY row still fires even though a later row corrects it")
        fires("9-shaempty.X", [_full(finding_id="j", reviewed_at_sha="")],
              "bad-reviewed-at-sha", "empty-string reviewed_at_sha fires")
        fires("9-shanull.X", [_full(finding_id="j", reviewed_at_sha=None)],
              "bad-reviewed-at-sha", "null reviewed_at_sha fires")
        # Sol's round-4 review caught that a bare truthiness/None check on
        # these two fields lets wrong-typed and whitespace-only values slip
        # through (7 and "   " are both truthy; [] is falsy but not a SHA).
        fires("9-shawrongtype.X", [_full(finding_id="j", reviewed_at_sha=7)],
              "bad-reviewed-at-sha", "a non-string reviewed_at_sha (e.g. int) fires")
        fires("9-shawhitespace.X", [_full(finding_id="j", reviewed_at_sha="   ")],
              "bad-reviewed-at-sha", "a whitespace-only reviewed_at_sha fires")
        # recorded_by is the ONE conditional case: nullable on the row that
        # FIRST raises the finding, required (non-null, non-empty-string) on
        # any supersession.
        clean_of("9-rbfirstnull.X", [_full(finding_id="j", recorded_by=None)],
                 "bad-recorded-by", "null recorded_by on the FIRST (raising) row is legitimate")
        fires("9-rblatenull.X", [
            _full(finding_id="j", recorded_at="2026-09-15T10:00:00Z"),
            _full(finding_id="j", recorded_at="2026-09-15T11:00:00Z", recorded_by=None, disposition="fixed")],
            "bad-recorded-by", "null recorded_by on a SUPERSESSION fires (someone must be named as recorder)")
        fires("9-rbwrongtype.X", [
            _full(finding_id="j", recorded_at="2026-09-15T10:00:00Z"),
            _full(finding_id="j", recorded_at="2026-09-15T11:00:00Z", recorded_by=7, disposition="fixed")],
            "bad-recorded-by", "a non-string recorded_by (e.g. int) on a supersession fires")
        fires("9-rbempty.X", [
            _full(finding_id="j", recorded_at="2026-09-15T10:00:00Z"),
            _full(finding_id="j", recorded_at="2026-09-15T11:00:00Z", recorded_by="", disposition="fixed")],
            "bad-recorded-by", "an empty-string recorded_by on a supersession fires")
        # Fable's round-4 misattribution note: row_pos depends on sort order,
        # which a prior bad-recorded-at row already makes indeterminate - the
        # genuine raising row (legitimately null recorded_by) can get displaced
        # to row_pos!=0 and misfire bad-recorded-by. The fragment is already
        # non-clean via bad-recorded-at either way, but the message must own
        # the ambiguity rather than assert a wrong attribution as fact.
        misattr = M.check_fragment(_write(d, "9-rbmisattr.X", [
            _full(finding_id="m", recorded_at="NOT-A-TIMESTAMP"),
            _full(finding_id="m", recorded_at="2026-09-15T10:00:00Z", recorded_by=None)]))
        rb_msgs = [f.msg for f in misattr if f.rule == "bad-recorded-by"]
        expect(len(rb_msgs) == 1 and "indeterminate" in rb_msgs[0] and "misattributing" in rb_msgs[0],
               f"a bad-recorded-by fired alongside bad-recorded-at discloses the row-order ambiguity "
               f"rather than silently asserting a possibly-wrong attribution (got {rb_msgs})")
        fires("9-dispearly.X", [
            _full(finding_id="e2", recorded_at="2026-09-15T10:00:00Z", disposition=7),
            _full(finding_id="e2", recorded_at="2026-09-15T11:00:00Z", disposition="fixed")],
            "bad-disposition", "a non-string disposition on an EARLY row still fires per row")
        # positive control: a LEGITIMATE corrective supersession of an earlier
        # omission of epistemic_status/provenance/classification must stay
        # clean - the required-presence check resolves via the MERGE (like
        # every other content field), not strictly the raising row.
        missing_then_fixed = _full(finding_id="corr", recorded_at="2026-09-15T10:00:00Z")
        missing_then_fixed.pop("epistemic_status")
        epicorrected = M.check_fragment(_write(d, "9-epicorrected.X", [
            missing_then_fixed,
            _sparse(finding_id="corr", recorded_at="2026-09-15T11:00:00Z", epistemic_status="likely")]))
        expect(epicorrected == [],
               f"a later CONFORMING sparse row legitimately supplying an earlier-omitted "
               f"epistemic_status is fully clean, not merely missing-field-free (got {_rules(epicorrected)})")

        # bad-finding-id: previously zero self-test coverage (mutation-tested
        # by both round-4 reviewers - deleting the rule left the suite green).
        p_badfid = Path(d) / "9-badfid.X.jsonl"
        p_badfid.write_text(json.dumps({**_full(), "finding_id": None, "run_id": "9-badfid.X"}) + "\n",
                            encoding="utf-8")
        expect(any(f.rule == "bad-finding-id" for f in M.check_fragment(str(p_badfid))),
               "a row with a null/non-string finding_id fires bad-finding-id")

        # round-5 review BLOCKER: finding_id is the MERGE JOIN KEY ITSELF - a
        # bare truthiness check accepts a whitespace-only string (bool("   ")
        # is True in Python), so two unrelated findings sharing one can
        # silently collapse into ONE merge group. Both the positive-fire on
        # the guard AND the actual collision-collapse consequence are tested.
        p_wsfid = Path(d) / "9-wsfid.X.jsonl"
        p_wsfid.write_text(json.dumps({**_full(), "finding_id": "   ", "run_id": "9-wsfid.X"}) + "\n",
                           encoding="utf-8")
        expect(any(f.rule == "bad-finding-id" for f in M.check_fragment(str(p_wsfid))),
               "a whitespace-only finding_id fires bad-finding-id")
        collide1 = _full(finding_id="   ", severity_native="HIGH", severity_mapped="BLOCKING",
                         impact=["I1"], exposure=["E3"])
        collide2 = _full(finding_id="   ", recorded_at="2026-09-15T11:00:00Z",
                         severity_native="INFO", severity_mapped="NICE", impact=["I9"], exposure=["E0"])
        collision = M.check_fragment(_write(d, "9-fidcollide.X", [collide1, collide2]))
        expect(any(f.rule == "bad-finding-id" for f in collision) and
               not any(f.rule == "native-mutated" for f in collision),
               f"two UNRELATED findings sharing a whitespace-only finding_id are each individually "
               f"flagged, NOT silently merged into one group with a spurious cross-finding "
               f"native-mutated (got {_rules(collision)})")

        # Sol's round-5 follow-up: `.strip()` empties ordinary whitespace but
        # NOT zero-width/format characters (Unicode category Cf) - ZWSP
        # (U+200B), BOM (U+FEFF), soft hyphen (U+00AD), word joiner (U+2060)
        # are all still "non-empty after strip()" while being visually blank,
        # and a finding_id built solely from them is just as dangerous a
        # merge-key collision as plain whitespace.
        expect(M._has_visible_id("​") is False, "_has_visible_id rejects ZWSP-only")
        expect(M._has_visible_id("﻿") is False, "_has_visible_id rejects BOM-only")
        expect(M._has_visible_id("­") is False, "_has_visible_id rejects soft-hyphen-only")
        # round-6 review (2nd pass) BLOCKER: an EXISTENTIAL "contains an
        # alnum somewhere" check (the shape this fixture originally asserted)
        # closed the blank-id COLLISION but not the SPLIT direction of the
        # same class - "a" and "a<ZWSP>" both "contain an alnum" while being
        # two DIFFERENT dict keys, silently splitting one finding's history
        # instead of colliding two unrelated ones. The anchored full-match
        # grammar closes both directions: NO extra character - leading,
        # trailing, or embedded - may appear anywhere in the id.
        expect(M._has_visible_id("a​") is False,
               "_has_visible_id REJECTS a real char plus ZWSP (round-6 2nd-pass fix - "
               "an existential check would wrongly accept this as a valid, but DIFFERENT, id)")
        zwsp1 = _full(finding_id="​", severity_native="HIGH", severity_mapped="BLOCKING",
                     impact=["I1"], exposure=["E3"])
        zwsp2 = _full(finding_id="​", recorded_at="2026-09-15T11:00:00Z",
                     severity_native="INFO", severity_mapped="NICE", impact=["I9"], exposure=["E0"])
        zwsp_collision = M.check_fragment(_write(d, "9-fidzwsp.X", [zwsp1, zwsp2]))
        expect(any(f.rule == "bad-finding-id" for f in zwsp_collision) and
               not any(f.rule == "native-mutated" for f in zwsp_collision),
               f"a ZWSP-only finding_id collision is caught the same way as plain whitespace "
               f"(got {_rules(zwsp_collision)})")

        # round-6 review (2nd pass, both reviewers independently): the SPLIT
        # direction of the same class - a real, otherwise-legitimate id with
        # an invisible character appended/prepended/embedded forms a
        # DIFFERENT dict key from the canonical one, silently splitting one
        # finding's history into two "findings" with no findings on either
        # half (rather than colliding two unrelated ones - opposite failure
        # shape, same root cause: the id-validity check said nothing about
        # what ELSE was in the string).
        for variant, label in (("X​", "ZWSP-suffix"), ("﻿X", "BOM-prefix"),
                               ("wsa​4-seam", "interior ZWSP in an otherwise-real kebab id")):
            expect(M._has_visible_id(variant) is False,
                   f"_has_visible_id rejects the {label} variant (round-6 2nd-pass fix)")
        split1 = _full(finding_id="X", severity_native="HIGH", severity_mapped="BLOCKING",
                      impact=["I1"], exposure=["E3"])
        split2 = {**_full(recorded_at="2026-09-15T11:00:00Z", disposition="fixed"),
                 "finding_id": "X​"}  # trailing ZWSP - looks identical to "X"
        split_result = M.check_fragment(_write(d, "9-fidsplit.X", [split1, split2]))
        expect(any(f.rule == "bad-finding-id" for f in split_result),
               f"a real id plus an invisible-character variant (would silently SPLIT one "
               f"finding's history into two groups) is caught (got {_rules(split_result)})")

        # round-6 review BLOCKER: the round-5 fix (isprintable() and not
        # isspace()) was ITSELF a denylist and both reviewers independently
        # found it still passes combining marks, variation selectors, and
        # blank-glyph symbols (category Mn/So/Lo) - Python reports these as
        # printable and non-whitespace despite rendering blank. "Renders
        # blank" is a font property, not an enumerable Unicode category, so
        # no denylist is ever complete. FIX: switched to an ALLOWLIST -
        # require at least one ASCII alphanumeric character (verified: 0 of
        # 11,584 real corpus finding_id occurrences fail this).
        for bad_id, label in (("⠀", "U+2800 BRAILLE PATTERN BLANK"),
                              ("͏", "U+034F COMBINING GRAPHEME JOINER"),
                              ("️", "U+FE0F VARIATION SELECTOR-16"),
                              ("ᅠ", "U+3164 HANGUL FILLER")):
            expect(M._has_visible_id(bad_id) is False,
                   f"_has_visible_id rejects {label}-only (round-6 fix)")
        blank1 = _full(finding_id="⠀", severity_native="HIGH", severity_mapped="BLOCKING",
                      impact=["I1"], exposure=["E3"])
        blank2 = _full(finding_id="⠀", recorded_at="2026-09-15T11:00:00Z",
                      severity_native="INFO", severity_mapped="NICE", impact=["I9"], exposure=["E0"])
        blank_collision = M.check_fragment(_write(d, "9-fidblank.X", [blank1, blank2]))
        expect(any(f.rule == "bad-finding-id" for f in blank_collision) and
               not any(f.rule == "native-mutated" for f in blank_collision),
               f"a blank-glyph-only finding_id collision (Braille blank) is caught "
               f"(got {_rules(blank_collision)})")
        expect(M._has_visible_id("wsa4-compliance-seam") is True,
               "the real corpus's ASCII kebab-case convention still passes")

        # round-6 review minor: a leading/trailing-whitespace finding_id
        # variant ("X " vs "X") is a DIFFERENT merge-grouping key from the
        # canonical one - if the stray row fully restates every field, the
        # real finding's history silently splits into two with no findings.
        fires("9-fidtrailing.X", [_full(finding_id="X ", recorded_at="2026-09-15T10:00:00Z")],
              "bad-finding-id", "a trailing-whitespace finding_id fires (not silently split)")
        fires("9-fidleading.X", [_full(finding_id=" X", recorded_at="2026-09-15T10:00:00Z")],
              "bad-finding-id", "a leading-whitespace finding_id fires")

        # round-6 review minor: the '#<id>' disposition prefix check compared
        # LENGTH past the prefix, so a whitespace-only suffix ("roadmap-# ")
        # passed as non-empty-by-length while carrying no real id.
        fires("9-dispwssuffix.X", [_full(finding_id="e5", recorded_at="2026-09-15T10:00:00Z",
                                        disposition="roadmap-# ")],
              "bad-disposition", "a whitespace-only '#<id>' suffix fires")
        clean_of("9-dispgoodsuffix.X", [_full(finding_id="e5", recorded_at="2026-09-15T10:00:00Z",
                                             disposition="roadmap-#123")],
                 "bad-disposition", "a real '#<id>' suffix stays clean")

        # Fable's round-6 confirmation-pass finding: the whitespace-suffix
        # fix above still used .strip(), which only strips category-Zs
        # whitespace - a ZWSP (U+200B) or a blank-glyph symbol (braille
        # blank, U+2800) survives .strip() and would pass as if it carried
        # real park-issue content. Fixed via an existential
        # alnum-or-'?' content check.
        fires("9-dispzwspsuffix.X", [_full(finding_id="e6", recorded_at="2026-09-15T10:00:00Z",
                                           disposition="roadmap-#​")],
              "bad-disposition", "a ZWSP-only '#<id>' suffix fires")
        fires("9-dispbraillesuffix.X", [_full(finding_id="e7", recorded_at="2026-09-15T10:00:00Z",
                                              disposition="roadmap-#⠀")],
              "bad-disposition", "a braille-blank-only '#<id>' suffix fires")
        clean_of("9-dispbaresuffix.X", [_full(finding_id="e8", recorded_at="2026-09-15T10:00:00Z",
                                              disposition="roadmap-#?")],
                 "bad-disposition", "the documented bare '?' unfilled-park placeholder stays clean")

        # round-6 review minor: RFC 3339 permits a lowercase 'z' spelling too;
        # Python's fromisoformat only recognizes uppercase 'Z' natively.
        expect(M._instant("2026-09-15T10:00:00z") is not None,
               "_instant accepts a lowercase 'z' UTC suffix (RFC 3339 permits it)")
        clean_of("9-lowercasez.X", [_full(finding_id="j", recorded_at="2026-09-15T10:00:00z")],
                 "bad-recorded-at", "a lowercase-z recorded_at is NOT flagged")

        # round-7 review blocker (C2): FortitudeEtc's exact reproduction - a
        # self-contradictory recorded_at (a lowercase-z UTC marker followed by
        # an explicit numeric offset) parsed to a DEFINITE-but-wrong instant
        # under the OLD code, shifted hours into the past by the trailing
        # offset, sorting a later BLOCKING escalation BEFORE an earlier NICE
        # row - so the merge treated the NICE row as superseding and the
        # fragment reported ZERO findings with the escalation silently
        # discarded. The fix must surface this as a finding (bad-recorded-at
        # on the malformed row), never let it merge silently.
        c2_rows = [
            _full(finding_id="c2", recorded_at="2026-09-15T09:00:00Z",
                  severity_native="INFO", severity_mapped="NICE", impact=["I9"], exposure=["E0"]),
            _sparse(finding_id="c2", recorded_at="2026-09-15T10:00:00z+14:00",
                    severity_native="INFO", severity_mapped="BLOCKING", impact=["I1"], exposure=["E3"]),
        ]
        c2_findings = M.check_fragment(_write(d, "9-c2selfcontra.X", c2_rows))
        expect("bad-recorded-at" in _rules(c2_findings),
               f"a self-contradictory recorded_at (lowercase-z marker + explicit offset) is caught, "
               f"not silently merged as a definite-but-wrong instant (got {_rules(c2_findings)})")

        # the doubled-'z' variant Kimi raised, and the arbitrary-separator
        # variant Codex additionally probed - same escalation-loss mechanism.
        fires("9-c2doublez.X", [_full(finding_id="c3", recorded_at="2026-09-15T10:00:00zz")],
              "bad-recorded-at", "a doubled lowercase-z recorded_at is caught, not silently accepted")
        fires("9-c2badsep.X", [_full(finding_id="c4", recorded_at="2026-09-15X10:00:00+00:00")],
              "bad-recorded-at", "a non-T/t date/time separator is caught, not silently accepted")

        # Fable's round-7 confirmation-pass blocker: an out-of-range field
        # (here, month 13 - the single most realistic hand-typing mistake in
        # this entire field) fullmatches the anchored grammar and only fails
        # at fromisoformat, which RAISES. An earlier version of THIS round's
        # own fix let that exception escape uncaught, crashing the whole
        # check_fragment() call and silencing every other finding in the run
        # - worse than the escalation-LOSS defect this round set out to fix,
        # since a crash is a total run failure rather than a silent gap.
        # Mirrors the c2 shape exactly (NICE -> BLOCKING), but with an
        # out-of-range month instead of a self-contradictory zone marker.
        c2_month13_rows = [
            _full(finding_id="c5", recorded_at="2026-09-15T09:00:00Z",
                  severity_native="INFO", severity_mapped="NICE", impact=["I9"], exposure=["E0"]),
            _sparse(finding_id="c5", recorded_at="2026-13-01T00:00:00Z",
                    severity_native="INFO", severity_mapped="BLOCKING", impact=["I1"], exposure=["E3"]),
        ]
        c2_month13_path = _write(d, "9-c2month13.X", c2_month13_rows)
        c2_month13_findings = M.check_fragment(c2_month13_path)
        expect("bad-recorded-at" in _rules(c2_month13_findings),
               f"an out-of-range recorded_at field (month 13) is caught as bad-recorded-at, "
               f"not an uncaught crash (got {_rules(c2_month13_findings)})")
        # the crash class specifically: run the CLI end-to-end and assert no
        # Python traceback reaches stderr - `check_fragment` returning a
        # finding list only proves the FUNCTION doesn't raise; the CLI test
        # is what would have caught the round-7 regression's actual blast
        # radius (the /governance SKILL.md pre-push gate invokes the CLI,
        # not the function directly).
        cli = subprocess.run([sys.executable, str(_SCRIPT), "--files", c2_month13_path],
                              capture_output=True, text=True)
        expect(cli.returncode == 1 and "Traceback" not in cli.stderr,
               f"CLI on an out-of-range recorded_at exits 1 with a finding, never a Python "
               f"traceback (got exit={cli.returncode}, stderr={cli.stderr[:200]!r})")

        # round-8 review blocker #1 (Fable + Sol): an offset with minutes >= 60
        # ("+05:60") is silently NORMALIZED by fromisoformat to "+06:00" rather
        # than rejected - the exact same escalation-loss mechanism as c2, just
        # a different malformed shape. With the tightened grammar this now
        # fires bad-recorded-at exactly like every prior malformed-timestamp
        # case, rather than silently merging as a definite-but-wrong instant.
        c2_offsetmin_rows = [
            _full(finding_id="c6", recorded_at="2026-09-15T04:30:00Z",
                  severity_native="INFO", severity_mapped="NICE", impact=["I9"], exposure=["E0"]),
            _sparse(finding_id="c6", recorded_at="2026-09-15T10:00:00+05:60",
                    severity_native="INFO", severity_mapped="BLOCKING", impact=["I1"], exposure=["E3"]),
        ]
        c2_offsetmin_findings = M.check_fragment(_write(d, "9-c2offsetmin.X", c2_offsetmin_rows))
        expect("bad-recorded-at" in _rules(c2_offsetmin_findings),
               f"an offset with minutes >= 60 is caught as bad-recorded-at, not silently "
               f"normalized into a definite-but-wrong instant (got {_rules(c2_offsetmin_findings)})")

        # round-8 review blocker #2 (Fable + Sol): two rows differing only PAST
        # microsecond precision (fromisoformat's own truncation limit) parse to
        # the IDENTICAL datetime under the old code - a false tie that fell
        # through to pass_ordinal (reserved for GENUINE ties) and could invert
        # the rows' real order. Discriminating check, same style as the F1
        # fractional-ordering test above: the row with the SMALLER raw
        # sub-microsecond fraction is disposition:open (correctly earlier),
        # the LARGER is disposition:fixed (correctly later/superseding) -
        # `datetime`'s own truncated comparison would tie them and fall
        # through to pass_ordinal, which is deliberately set backwards here
        # (open's pass_ordinal > fixed's) so a tie-driven merge would pick the
        # WRONG (open) row instead.
        subfrac_rows = [
            {"finding_id": "sf", "run_id": "9-subfrac.X", "pass_ordinal": 5,
             "recorded_at": "2026-09-15T10:00:00.0000001Z", "disposition": "open"},
            {"finding_id": "sf", "run_id": "9-subfrac.X", "pass_ordinal": 1,
             "recorded_at": "2026-09-15T10:00:00.0000002Z", "disposition": "fixed"},
        ]
        # round-11 confirmation-pass finding (Fable): this is the ORIGINAL
        # round-8 lock the two round-11 precision assertions elsewhere in
        # this file exist to strengthen - it has the IDENTICAL vacuous-pass
        # exposure on an interpreter that rejects a >6-digit fraction
        # outright (both rows would fall to _order_key's file-order path and
        # 'fixed', at index 1, would win by accident rather than by the
        # precision comparison this test means to exercise). Guarding its
        # two descendants but not this one would leave the class only
        # partially closed.
        expect(M._instant(subfrac_rows[0]["recorded_at"]) is not None,
               "precondition: this interpreter parses a 7-digit fraction (required for the "
               "sub-microsecond assertion below to actually exercise _frac_key, not file order)")
        subfrac_ordered = sorted(((i, r) for i, r in enumerate(subfrac_rows)), key=M._order_key)
        expect(M.merged_view(subfrac_ordered).get("disposition") == "fixed",
               "sub-microsecond fractional precision orders correctly even though fromisoformat's "
               "own comparison would tie the two instants (merged disposition=fixed)")

        # round-9 review blocker (Fable + Sol): FortitudeEtc's exact
        # reproduction - an hour-24 timestamp with a nonzero 7th fractional
        # digit ("...T24:00:00.0000001Z") was wrongly accepted as valid
        # midnight (fromisoformat's own hour-24 check runs against the
        # truncated 6-digit fractional value, which IS all zeros), while the
        # round-8 exact-precision fix separately restores and orders by the
        # real nonzero remainder - producing the same "validate the lossy
        # value, order by the lossless value" seam as round 8's own blocker.
        c2_hour24_rows = [
            _full(finding_id="c7", recorded_at="2026-09-16T00:00:00.0000002Z",
                  severity_native="INFO", severity_mapped="NICE", impact=["I9"], exposure=["E0"]),
            _sparse(finding_id="c7", recorded_at="2026-09-15T24:00:00.0000001Z",
                    severity_native="INFO", severity_mapped="BLOCKING", impact=["I1"], exposure=["E3"]),
        ]
        c2_hour24_findings = M.check_fragment(_write(d, "9-c2hour24.X", c2_hour24_rows))
        expect("bad-recorded-at" in _rules(c2_hour24_findings),
               f"an hour-24 timestamp with a nonzero 7th fractional digit is caught as "
               f"bad-recorded-at, not silently accepted as valid midnight "
               f"(got {_rules(c2_hour24_findings)})")

        # round-10 review BLOCKER (Fable + Sol, then Kimi withdrew her own
        # PASS and independently reproduced it): this defect sits
        # STRUCTURALLY BELOW every per-field grammar/range/precision check
        # the prior nine rounds shipped. Python's `json.loads` (matching jq
        # and JavaScript's JSON.parse) silently keeps only the LAST value
        # for a repeated object member name, discarding earlier ones with NO
        # diagnostic - so a row whose raw JSON states a merge-governing
        # field TWICE has its first value vanish before any validator in
        # this file ever runs. FortitudeEtc's exact reproduction: a NICE row
        # at an earlier valid instant, and a BLOCKING row whose raw JSON
        # states recorded_at twice (a LATER value first, then an EARLIER
        # one) - the kept (earlier) value sorts before the NICE row, so the
        # merge treats NICE as superseding and the escalation vanishes with
        # zero findings. Built by hand (not via _full()/json.dumps, which
        # can't express a duplicate key) to exactly match a raw hand-typed
        # or externally-generated fragment.
        dup_key_line = (
            '{"schema_version": 1, "run_id": "9-dupkey.X", "finding_id": "dk1", '
            '"recorded_by": "Claude", "reviewed_at_sha": "abc123", "pass_ordinal": 0, '
            '"disposition": "open", "severity_native": "INFO", "severity_mapped": "BLOCKING", '
            '"impact": ["I1"], "exposure": ["E3"], '
            '"recorded_at": "2026-09-15T11:00:00Z", "recorded_at": "2026-09-15T09:00:00Z"}'
        )
        dup_key_path = Path(d) / "9-dupkey.X.jsonl"
        dup_key_path.write_text(
            json.dumps(_full(finding_id="dk1", recorded_at="2026-09-15T10:00:00Z",
                              severity_native="INFO", severity_mapped="NICE",
                              impact=["I9"], exposure=["E0"]))
            + "\n" + dup_key_line + "\n", encoding="utf-8")
        dup_key_findings = M.check_fragment(str(dup_key_path))
        expect("invalid-json" in _rules(dup_key_findings),
               f"a JSON line with a duplicate 'recorded_at' object member is caught as "
               f"invalid-json, not silently resolved to its last value with the BLOCKING "
               f"escalation discarded (got {_rules(dup_key_findings)})")

        # Codex's independent variant: a Unicode-escaped duplicate key
        # spelling ("recorded_at", which Python decodes identically to
        # the literal name "recorded_at") - proving the defect isn't merely
        # "don't hand-type the same key twice" but a genuine parser-level
        # gap reachable by any two spellings that decode to the same string.
        dup_key_unicode_line = (
            '{"schema_version": 1, "run_id": "9-dupkeyuni.X", "finding_id": "dk2", '
            '"recorded_by": "Claude", "reviewed_at_sha": "abc123", "pass_ordinal": 0, '
            '"disposition": "open", "recorded_at": "2026-09-15T11:00:00Z", '
            '"\\u0072ecorded_at": "2026-09-15T09:00:00Z"}'
        )
        dup_key_unicode_path = Path(d) / "9-dupkeyuni.X.jsonl"
        dup_key_unicode_path.write_text(dup_key_unicode_line + "\n", encoding="utf-8")
        dup_key_unicode_findings = M.check_fragment(str(dup_key_unicode_path))
        expect("invalid-json" in _rules(dup_key_unicode_findings),
               f"a Unicode-escaped duplicate key spelling that decodes to the same name is "
               f"also caught as invalid-json (got {_rules(dup_key_unicode_findings)})")

        # Kimi's independent variant: a duplicate finding_id silently
        # re-homes what was meant as a supersession row into the WRONG merge
        # group (the kept finding_id), leaving the intended group stale with
        # no trace the row ever existed.
        dup_fid_line = (
            '{"schema_version": 1, "run_id": "9-dupfid.X", '
            '"finding_id": "wrong-group", "finding_id": "dk3", '
            '"recorded_by": "Claude", "reviewed_at_sha": "abc123", "pass_ordinal": 0, '
            '"recorded_at": "2026-09-15T10:00:00Z", "disposition": "open"}'
        )
        dup_fid_path = Path(d) / "9-dupfid.X.jsonl"
        dup_fid_path.write_text(dup_fid_line + "\n", encoding="utf-8")
        dup_fid_findings = M.check_fragment(str(dup_fid_path))
        expect("invalid-json" in _rules(dup_fid_findings),
               f"a duplicate finding_id (silently re-homing a row to the wrong merge group) "
               f"is also caught as invalid-json (got {_rules(dup_fid_findings)})")

        # round-11 review should-fix (Fable + Sol): a duplicate JSON member
        # name spelled as a lone Unicode surrogate (\ud800, reachable via a
        # JSON \uXXXX escape with no matching low surrogate) is decoded fine
        # by json.loads, but printing it to a normal UTF-8 stdout raised
        # UnicodeEncodeError uncaught, mid-report - under --all, every
        # fragment after the offending one, and the summary line, never
        # printed. check_fragment() itself was always correct (it returned
        # the right invalid-json finding); the crash was purely in the CLI
        # report step. Verify BOTH: the in-process finding is produced, AND
        # the CLI (which actually prints it) doesn't crash.
        surrogate_line = '{"a": 1, "\\ud800": 2, "\\ud800": 3}'
        surrogate_path = Path(d) / "9-surrogate.X.jsonl"
        surrogate_path.write_text(surrogate_line + "\n", encoding="utf-8")
        surrogate_findings = M.check_fragment(str(surrogate_path))
        expect("invalid-json" in _rules(surrogate_findings),
               f"a duplicate lone-surrogate JSON member name is caught as invalid-json "
               f"(got {_rules(surrogate_findings)})")
        cli_surrogate = subprocess.run([sys.executable, str(_SCRIPT), "--files", str(surrogate_path)],
                                        capture_output=True, text=True)
        expect(cli_surrogate.returncode == 1 and "Traceback" not in cli_surrogate.stderr,
               f"CLI on a duplicate lone-surrogate key name exits 1 with a finding, never a "
               f"UnicodeEncodeError traceback (got exit={cli_surrogate.returncode}, "
               f"stderr={cli_surrogate.stderr[:200]!r})")

        # round-11 CONFIRMATION-pass finding (Fable): the surrogate-name fix
        # above only patched ONE interpolation site - the fragment's own
        # FILENAME can carry the identical shape. A non-UTF-8 byte in a
        # filename decodes (via the OS's surrogateescape handler) into a
        # lone surrogate character Python can hold in memory but cannot
        # ENCODE to a normal UTF-8 stream - `main()`'s findings-report loop
        # printed `f.path` raw and crashed on this exact input, uncaught.
        # Fixed at the STREAM (stdout/stderr reconfigured with
        # errors="backslashreplace" in main()), not by patching yet another
        # individual interpolation site - this closes the WHOLE class
        # (filenames, any future row-controlled string, everything) rather
        # than requiring every future print site to remember `!r`.
        # round-11 confirmation-pass minor (Fable/FortitudeEtc, both external
        # reviewers found-by-both): `os.fsdecode` on an arbitrary raw byte
        # string assumes the POSIX bytes-based path model - Windows paths
        # are natively UTF-16, so this raises UnicodeDecodeError itself on
        # Windows, before the fixture even runs. Not merge-blocking (the
        # Governance-ledger linter self-test step in docs-lint.yml is
        # ubuntu-24.04-only, confirmed by the reviewer's own check of the
        # workflow file), but guarding it costs one line and keeps this
        # fixture from becoming a landmine if a Windows leg is ever added.
        if os.name != "nt":
            bad_name = os.fsdecode(b"9-badname\xff.X.jsonl")
            bad_name_path = Path(d) / bad_name
            bad_name_path.write_bytes(b'{"a": 1}\n')
            cli_badname = subprocess.run([sys.executable, str(_SCRIPT), "--files", str(bad_name_path)],
                                          capture_output=True, text=True, errors="backslashreplace")
            expect(cli_badname.returncode == 1 and "Traceback" not in cli_badname.stderr,
                   f"CLI on a fragment whose FILENAME contains a non-UTF-8 byte exits 1 with a "
                   f"finding, never a UnicodeEncodeError traceback "
                   f"(got exit={cli_badname.returncode}, stderr={cli_badname.stderr[:200]!r})")

        # round-11 review minor (Fable + Sol): json.loads accepts Python's
        # non-standard NaN/Infinity/-Infinity literals (RFC 8259 section 6
        # permits ONLY finite numbers) with no diagnostic by default.
        # Format-hygiene rather than an escalation-loss path (every merge/
        # severity-governing field with a type check already fires a loud
        # downstream finding on one of these), but a one-line close.
        for const, label in (("NaN", "NaN"), ("Infinity", "Infinity"), ("-Infinity", "-Infinity")):
            const_path = Path(d) / f"9-const{label}.X.jsonl"
            const_path.write_text(f'{{"pass_ordinal": {const}}}\n', encoding="utf-8")
            const_findings = M.check_fragment(str(const_path))
            expect("invalid-json" in _rules(const_findings),
                   f"the non-standard JSON constant {label} is rejected as invalid-json, not "
                   f"silently accepted (got {_rules(const_findings)})")

        # round-9 review should-fix (Fable + Sol): json.loads()'s except
        # clause caught only json.JSONDecodeError - a JSON integer literal
        # past int()'s 4300-digit string-conversion cap raises a plain
        # ValueError (JSONDecodeError's own superclass, NOT covered by the
        # narrower except), and ~100,000-deep array nesting raises
        # RecursionError. Both crashed check_fragment() uncaught - the same
        # "narrower except than the input space allows" class as round 8's
        # UnicodeDecodeError gap one function earlier in the call chain.
        def _check_fragment_or_fail(path, label):
            # a regression that lets check_fragment() raise uncaught would
            # otherwise take down this WHOLE self-test process with an
            # unnamed traceback (no FAIL line, no partial results) - Fable's
            # round-9 mutation-test found exactly this shape for the EXC
            # mutant. Convert any exception into a normal, named failure.
            try:
                return M.check_fragment(path)
            except Exception as e:  # noqa: BLE001 - deliberately broad, see above
                expect(False, f"{label} (check_fragment raised uncaught: "
                               f"{type(e).__name__}: {e})")
                return []

        huge_int_path = Path(d) / "9-hugeint.X.jsonl"
        huge_int_path.write_text("9" * 5000 + "\n", encoding="utf-8")
        expect(any(f.rule == "invalid-json" for f in
                    _check_fragment_or_fail(str(huge_int_path), "huge-int fixture")),
               "a JSON integer literal past int()'s 4300-digit conversion cap is caught as "
               "invalid-json, not an uncaught crash")
        deepnest_path = Path(d) / "9-deepnest.X.jsonl"
        deepnest_path.write_text("[" * 100_000 + "]" * 100_000 + "\n", encoding="utf-8")
        expect(any(f.rule == "invalid-json" for f in
                    _check_fragment_or_fail(str(deepnest_path), "deep-nesting fixture")),
               "~100,000-deep JSON array nesting is caught as invalid-json, not an uncaught "
               "RecursionError crash")
        cli_deepnest = subprocess.run([sys.executable, str(_SCRIPT), "--files", str(deepnest_path)],
                                       capture_output=True, text=True)
        expect(cli_deepnest.returncode == 1 and "Traceback" not in cli_deepnest.stderr,
               f"CLI on ~100,000-deep JSON nesting exits 1 with a finding, never a Python "
               f"traceback (got exit={cli_deepnest.returncode}, stderr={cli_deepnest.stderr[:200]!r})")

        # Fable's round-5 follow-up: the per-row disposition CLOSED-ENUM check
        # must gate on THIS ROW's own versioned-ness, not the finding-level
        # `legacy` flag - a finding-wide flag is True the moment ANY row is
        # versioned, which would wrongly retro-apply the #2643-era enum to a
        # genuinely legacy FIRST row (e.g. the pre-#2643 bare "deferred-to-issue"
        # spelling) that a later versioned row happens to supersede.
        legacy_first = {"finding_id": "m3", "reporter": "architect", "impact": ["I6"],
                        "exposure": ["E0"], "severity_mapped": "SHOULD",
                        "disposition": "deferred-to-issue", "severity_native": "MEDIUM",
                        "run_id": "9-legacydisp.X"}
        versioned_second = _full(finding_id="m3", recorded_at="2026-09-15T10:00:00Z", disposition="fixed")
        legacydisp = M.check_fragment(_write(d, "9-legacydisp.X", [legacy_first, versioned_second]))
        expect(not any(f.rule == "bad-disposition" for f in legacydisp),
               f"a genuinely legacy first row's pre-#2643 disposition spelling is NOT retroactively "
               f"judged by the closed enum just because a later row in the same finding is versioned "
               f"(got {_rules(legacydisp)})")

        # round-5 review should-fix: disposition's CLOSED-ENUM half (not just
        # its bedrock string shape) is now checked per row too - a bad early
        # value a later valid row "corrects" must still fire, while the
        # legitimate open->fixed evolution stays clean (both values are
        # individually valid, so per-row checking doesn't break it).
        fires("9-dispenumeearly.X", [
            _full(finding_id="e3", recorded_at="2026-09-15T10:00:00Z", disposition="no_change_needed"),
            _full(finding_id="e3", recorded_at="2026-09-15T11:00:00Z", disposition="fixed")],
            "bad-disposition", "an off-enum disposition on an EARLY row still fires even though a later row is valid")
        clean_of("9-dispevolve.X", [
            _full(finding_id="e4", recorded_at="2026-09-15T10:00:00Z", disposition="open"),
            _full(finding_id="e4", recorded_at="2026-09-15T11:00:00Z", disposition="fixed")],
            "bad-disposition", "the legitimate open -> fixed evolution stays clean under per-row checking")

        # round-5 review minor: reporter_ref's bare truthiness check accepted
        # a whitespace string; must be a genuine non-empty, non-whitespace one.
        fires("9-refws.X", [_full(finding_id="j", source="external-model", reporter_ref="   ")],
              "missing-reporter-ref", "a whitespace-only reporter_ref fires")
        clean_of("9-refunresolved.X", [_full(finding_id="j", source="external-model", reporter_ref="unresolved")],
                 "missing-reporter-ref", "the literal 'unresolved' reporter_ref is NOT flagged")

        # round-5 review minor: a versioned row that OMITS recorded_at entirely
        # (rather than malforming it) makes order just as indeterminate as a
        # present-but-bad value, and must set the same disclosure qualifier -
        # a genuinely LEGACY finding (no #2619 markers at all) must NOT.
        omit_ra_row1 = {"schema_version": 1, "finding_id": "m2", "recorded_by": "x",
                        "reviewed_at_sha": "abc", "pass_ordinal": 0, "disposition": "open",
                        "severity_native": "MEDIUM", "run_id": "9-omitra.X"}
        omit_ra_row2 = _full(finding_id="m2", recorded_at="2026-09-15T10:00:00Z", severity_native="HIGH")
        omitra = M.check_fragment(_write(d, "9-omitra.X", [omit_ra_row1, omit_ra_row2]))
        nm = [f.msg for f in omitra if f.rule == "native-mutated"]
        expect(len(nm) == 1 and "indeterminate" in nm[0],
               f"an omitted (not malformed) recorded_at on a versioned row still discloses the "
               f"order-indeterminacy qualifier on a sibling native-mutated (got {nm})")
        legacy_sanity = {"finding_id": "L2", "reporter": "architect", "impact": ["I6"], "exposure": ["E0"],
                         "severity_mapped": "SHOULD", "disposition": "open", "run_id": "9-legacysanity.X"}
        expect(M.check_fragment(_write(d, "9-legacysanity.X", [legacy_sanity])) == [],
               "a genuinely legacy finding (no #2619 markers) never triggers the indeterminacy "
               "qualifier machinery - it has no bad-recorded-at row to disclose")

        # -------- (5) round-3 review: the two-discriminator legacy heuristic --------
        # A row is genuinely legacy ONLY if it carries NONE of the fields
        # #2619 introduced (SKILL.md's own citation: source, reporter_ref,
        # reviewed_at_sha, recorded_at, recorded_by, adjudication_rationale,
        # the refuted pair, classification=="absence") - checking only
        # schema_version/recorded_at missed a row that omits BOTH of those
        # two while still carrying e.g. recorded_by/reviewed_at_sha, letting a
        # real escalation vanish with zero findings.
        double_omit_row1 = _full(finding_id="e1", severity_native="INFO", severity_mapped="NICE",
                                 impact=["I9"], exposure=["E0"])
        double_omit_row2 = {"finding_id": "e1", "recorded_by": "x", "reviewed_at_sha": "def",
                            "pass_ordinal": 1, "severity_native": "HIGH", "severity_mapped": "BLOCKING",
                            "impact": ["I1"], "exposure": ["E3"], "disposition": "open"}
        do = M.check_fragment(_write(d, "9-doubleomit.X", [double_omit_row1, double_omit_row2]))
        expect(do != [],
               f"a row carrying recorded_by/reviewed_at_sha but omitting BOTH schema_version and "
               f"recorded_at is still recognized as modern, not silently legacy (got {_rules(do)})")
        expect("missing-row-field" in _rules(do),
               f"...specifically via missing-row-field for the omitted schema_version/recorded_at "
               f"(got {_rules(do)})")

        # round-3 review, blocker 2: pass_ordinal determines MERGE ORDER via
        # _order_key BEFORE anything validates its value - a bad value on the
        # LOSING row of a tie can silently determine the wrong outcome and then
        # vanish, since only merged["pass_ordinal"] (the WINNING row's own,
        # possibly-fine value) was ever checked. Two rows at an IDENTICAL
        # timestamp, one with a genuine escalation and a string pass_ordinal.
        tie_row1 = _full(finding_id="e2", recorded_at="2026-09-15T10:00:00Z", pass_ordinal=1,
                         severity_native="INFO", severity_mapped="NICE", impact=["I9"], exposure=["E0"])
        tie_row2 = _full(finding_id="e2", recorded_at="2026-09-15T10:00:00Z", pass_ordinal="2",
                         severity_native="HIGH", severity_mapped="BLOCKING", impact=["I1"], exposure=["E3"])
        tf = M.check_fragment(_write(d, "9-tiepo.X", [tie_row1, tie_row2]))
        expect(any(f.rule == "bad-pass-ordinal" for f in tf),
               f"a string pass_ordinal on a tied-timestamp row fires bad-pass-ordinal on ITS OWN row, "
               f"not only checked after it already determined (and lost) the merge (got {_rules(tf)})")

        # per-row run_id mismatch (minor, side effect of the pass_ordinal fix):
        # a MID-history wrong run_id that a later row incidentally restates
        # correctly must still fire, since the merged view alone would read
        # clean. NOTE: _write() normally stamps every row's run_id to match
        # the stem (so ordinary fixtures don't have to care) - these two
        # tests need stamp_run_id=False to deliberately keep a WRONG value.
        midrow1 = _full(finding_id="rid", recorded_at="2026-09-15T10:00:00Z", run_id="WRONG-STEM")
        midrow2 = _full(finding_id="rid", recorded_at="2026-09-15T11:00:00Z", disposition="fixed")
        midf = M.check_fragment(_write(d, "9-runidmid.X", [midrow1, midrow2], stamp_run_id=False))
        expect("run-id-mismatch" in _rules(midf),
               f"a mid-history wrong run_id still fires even though a later row restates it "
               f"correctly (got {_rules(midf)})")

        # -------- (6) the 5 previously-unfixtured rules (mutation-tested: stripping
        # any of these rule bodies from a copy of the checker left the suite green) --------
        ridtop = _full(finding_id="j", run_id="totally-different-stem")
        rtf = M.check_fragment(_write(d, "9-ridtop.X", [ridtop], stamp_run_id=False))
        expect("run-id-mismatch" in _rules(rtf),
               f"run_id not matching the filename stem fires (got {_rules(rtf)})")
        fires("9-impact.X", [_full(finding_id="j", impact=["I99"])],
              "bad-impact", "off-enum impact code fires")
        fires("9-exposure.X", [_full(finding_id="j", exposure=["E99"])],
              "bad-exposure", "off-enum exposure code fires")
        # E7 (advisory-artifact + author-controlled-input cap) added
        # 2026-09-16 - confirm it's accepted as a valid enum member, not
        # rejected as off-enum the way an unrecognized code like E99 is.
        clean_of("9-e7.X", [_full(finding_id="j", impact=["I3"], exposure=["E7"],
                                   severity_mapped="SHOULD")],
                 "bad-exposure", "the new E7 exposure code is a valid enum member, not off-enum")
        fires("9-sevmap.X", [_full(finding_id="j", severity_mapped="URGENT")],
              "bad-severity-mapped", "off-enum severity_mapped fires")
        fires("9-linktop.X", [_full(finding_id="j", impact=["I2"], exposure=["E0"],
                                    severity_mapped="BLOCKING", severity_native="HIGH",
                                    disposition="linked-to-#123")],
              "linked-top-severity", "linked-to- disposition on an I1/I2/I3 finding fires (a prompt, not a verdict)")

        # -------- (7) epistemic_status/provenance/classification are REQUIRED, --------
        # not nullable, per SKILL.md's field table (unlike impact/exposure,
        # which explicitly tolerate a null fact set) - on the FIRST-raising row,
        # resolved via the merge like any other content field (a later
        # supersession may correct an earlier omission).
        for req_field in ("epistemic_status", "provenance", "classification"):
            missing_row = _full(finding_id="j"); missing_row.pop(req_field)
            fires(f"9-missing-{req_field}.X", [missing_row], "missing-field",
                  f"omitted {req_field} on the raising row fires missing-field")
            null_row = _full(finding_id="j", **{req_field: None})
            fires(f"9-null-{req_field}.X", [null_row], "missing-field",
                  f"explicit null {req_field} fires missing-field too (unlike impact/exposure)")
        # severity_mapped is set to NICE here specifically so severity-empty-impact
        # (a SEPARATE, legitimate rule - empty impact + a non-NICE label + no
        # floor) doesn't also fire and confuse what this fixture is isolating.
        impactnull_findings = M.check_fragment(_write(d, "9-impactnull.X",
            [_full(finding_id="j", impact=None, severity_mapped="NICE", severity_native="INFO")]))
        expect(_rules(impactnull_findings) == [],
               f"explicit null impact fires NEITHER missing-field NOR scalar-list-field - a "
               f"legit empty fact set (got {_rules(impactnull_findings)})")

        # -------- (8) F11: legacy row (no ANY #2619-introduced field) is PARTIALLY exempt --------
        # Exempt: the eight per-row-mandatory fields, the NEW required-content
        # fields (epistemic_status/provenance/classification presence), and
        # disposition's CLOSED-ENUM half (a #2643-era convention, later than
        # #2619's schema_version). NOT exempt: disposition's own
        # must-be-a-string check, and the content enums' VALUE validity
        # (classification/epistemic_status/provenance still reject a garbage
        # value if present) - those are general contracts predating any
        # schema-versioning split, so a genuinely ancient row can still carry
        # a value worth flagging. Deliberately carries NO `source` key: source
        # is ITSELF one of the #2619-introduced markers (SKILL.md's own
        # citation), so a fixture that includes it is not actually legacy-shaped.
        legacy = {"finding_id": "L", "reporter": "architect",
                  "impact": ["I6"], "exposure": ["E0"], "severity_mapped": "SHOULD",
                  "disposition": "open", "run_id": "9-legacy.X"}
        lf = M.check_fragment(_write(d, "9-legacy.X", [legacy]))
        expect(not any(f.rule in ("missing-field", "missing-row-field", "bad-disposition")
                       for f in lf),
               f"legacy row (no #2619-introduced field at all) not flagged missing-*/bad-disposition-enum "
               f"(F11) (got {_rules(lf)})")
        legacy_bad_cls = dict(legacy, classification="invented")
        lbc = M.check_fragment(_write(d, "9-legacycls.X", [legacy_bad_cls]))
        expect("bad-classification" in _rules(lbc),
               f"legacy row with an off-enum classification STILL fires - content-value validity is not "
               f"legacy-exempt, only the per-row-mandatory-8/required-content-presence and disposition's "
               f"closed-enum half are (got {_rules(lbc)})")

        # Fable review (post-round-3): the finding-level `legacy` flag must be
        # computed from the RAW rows, not the merged view - merged_view()
        # strips the three attestation-only markers (adjudication_rationale,
        # refuted_by, refuted_by_reporter), so a finding whose ONLY #2619
        # marker is one of those three would read as versioned per-row but
        # legacy at the merged level, wrongly exempting it from the merged-view
        # checks below (source/policy_floor/required-content presence).
        att_only = {"finding_id": "att-only", "reporter": "architect", "impact": ["I6"],
                   "exposure": ["E0"], "severity_mapped": "SHOULD", "disposition": "refuted",
                   "refuted_by": "git show ... proves it false", "refuted_by_reporter": "not-the-author",
                   "run_id": "9-attonly.X"}
        af = M.check_fragment(_write(d, "9-attonly.X", [att_only]))
        expect(any(f.rule == "missing-field" and "'source'" in f.msg for f in af),
               f"a row whose ONLY #2619 marker is an attestation field (refuted_by) is still treated "
               f"as non-legacy at the FINDING level, so merged-view checks (e.g. missing 'source') "
               f"still apply (got {_rules(af)})")

        # -------- robustness: odd types / invalid json don't crash --------
        p = Path(d) / "9-weird.X.jsonl"
        p.write_text(json.dumps(_full(finding_id="z", run_id="9-weird.X")) + "\n{bad}\n",
                     encoding="utf-8")
        expect(any(f.rule == "invalid-json" for f in M.check_fragment(str(p))),
               "invalid-json flagged without crashing")

        # round-9 review should-fix (Fable): `.splitlines()` also splits on
        # U+2028/U+2029/U+0085 and a few other Unicode line-boundary
        # characters, which are LEGAL, unescaped inside a JSON string -
        # `json.loads` (and ordinary file iteration) reads a row containing
        # one of these raw as ONE object/line, but `.splitlines()` split it
        # into TWO here, reporting two spurious invalid-json findings,
        # silently dropping the real row from the merge, and shifting every
        # later line number by one.
        u2028_row = _full(finding_id="ls", run_id="9-u2028.X",
                           adjudication_rationale="a b", adjudicated_by="x")
        u2028_path = Path(d) / "9-u2028.X.jsonl"
        # ensure_ascii=False is REQUIRED here: json.dumps's default escapes
        # U+2028 as a six-character backslash-u escape sequence, which never
        # exercises the bug (the escaped form has no literal line-boundary
        # character in the file at all). Only a raw, unescaped U+2028 in the
        # file reproduces what a hand-written or non-Python producer could
        # legitimately emit.
        u2028_path.write_text(json.dumps(u2028_row, ensure_ascii=False) + "\n", encoding="utf-8")
        u2028_findings = M.check_fragment(str(u2028_path))
        expect(not any(f.rule == "invalid-json" for f in u2028_findings),
               f"a row containing a raw U+2028 inside a field value is read as ONE JSON object, "
               f"not silently split into two spurious invalid-json findings "
               f"(got {_rules(u2028_findings)})")

        # round-8 review should-fix (Fable + Sol): UnicodeDecodeError is a
        # ValueError subclass, NOT an OSError - a single non-UTF-8 byte
        # anywhere in a fragment would raise uncaught past a bare
        # `except OSError`, crashing check_fragment() (and, in --all, the
        # whole run) rather than reporting this one fragment as unreadable.
        # Caught only by mutation-testing: removing the UnicodeDecodeError
        # arm from the except clause left every OTHER self-test assertion
        # passing, since none of them exercised a non-UTF-8 fragment.
        badbytes = Path(d) / "9-badbytes.X.jsonl"
        badbytes.write_bytes(b"\xff\xfe not valid utf-8\n")
        bb_findings = M.check_fragment(str(badbytes))
        expect(bb_findings and bb_findings[0].rule == "unreadable",
               f"a non-UTF-8 fragment is reported as unreadable, not an uncaught "
               f"UnicodeDecodeError crash (got {_rules(bb_findings)})")

        # -------- (6) CLI exit-code contract (F10), via subprocess, pinned cwd --------
        scratch = _scratch_git_repo(d)

        def cli(*a, cwd=None):
            return subprocess.run([sys.executable, str(_SCRIPT), *a], capture_output=True,
                                  text=True, cwd=cwd or str(_REPO_ROOT)).returncode

        expect(cli("--files", good) == 0, "CLI: clean fragment exits 0")
        bad = _write(d, "9-badcli.X", [_full(finding_id="s", impact=["I3"], exposure=["E0"],
                                             severity_mapped="SHOULD")])
        expect(cli("--files", bad) == 1, "CLI: fragment with findings exits 1")
        expect(cli("--files", str(Path(d) / "nope.jsonl")) == 1, "CLI: nonexistent --files exits 1")
        # positive control: a scratch repo with no governance.d changes and a
        # genuinely resolvable --base (HEAD itself) must exit 0 - proves the
        # diff-scoped path works at all, not just that it fails on a bad ref.
        expect(cli("--base", "HEAD", cwd=str(scratch)) == 0,
               "CLI: good --base (HEAD, isolated scratch repo) exits 0 (positive control)")
        expect(cli("--base", "refs/heads/definitely-not-a-ref-xyz", cwd=str(scratch)) == 2,
               "CLI: bad --base fails CLOSED, exit 2 (F4), pinned cwd")

    if _FAILURES:
        print(f"\ngovernance-ledger-check self-test: FAILED ({len(_FAILURES)} case(s))")
        return 1
    print("\ngovernance-ledger-check self-test: OK - constants pinned; linter discriminates "
          "on every seeded defect incl. sparse-merge, per-row-mandatory-fields, and "
          "malformed-timestamp escalation-loss")
    return 0


if __name__ == "__main__":
    sys.exit(run())
