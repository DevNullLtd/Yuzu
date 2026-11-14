#!/usr/bin/env python3
"""Lexical pins for two quarantine facts that no behavioural test can fail on.

1. The apply claim is read and written on the DATABASE clock (#7613, UP-1).
   `apply_claimed_at` is stamped, and "no claim is live" is decided, in SQL against `now()`; the
   replica's own wall clock never enters. A [pg] case proves the SQL does the right thing, but it
   cannot fail on the old code while the test process and the database agree on the time, so the
   source text is pinned here: quarantine_store.cpp never sets or compares `apply_claimed_at`
   from a bind parameter (or a number spliced into the text), never subtracts
   `kApplyClaimTtlSecs` from `now_secs()` (or any `now`), and states "no live claim" exactly once
   (`no_live_claim_sql()`), which the claim, the token read and both fenced ends call.

2. server.cpp seeds the reconciler's metric families at boot (QE-1).
   Production calls `QuarantineContainmentReconciler::seed_metrics(metrics_)` exactly once and
   the only other caller is a unit case, so deleting the boot call would leave every test green
   and every `absent()` alert ambiguous with "never ran".

Source-text only (no build, no network). Comments are stripped with a literal-aware scanner, so
text mentioning a token cannot satisfy or break a check. Lexical: a statement moved into dead code
is review-enforced. The self-test classes below prove each rule fires on the pre-fix text and on a
mutation of the real file, so a stale pattern fails loudly instead of passing vacuously.

Usage: python3 -I tests/test_quarantine_wiring_lexical.py
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STORE_CPP = ROOT / "server" / "core" / "src" / "quarantine_store.cpp"
SERVER_CPP = ROOT / "server" / "core" / "src" / "server.cpp"

SEED_CALL = "QuarantineContainmentReconciler::seed_metrics(metrics_)"
SEED_RX = re.compile(r"QuarantineContainmentReconciler\s*::\s*seed_metrics\s*\(\s*metrics_\s*\)")


def strip_comments(src):
    """`src` without // and /* */ comments. String, character and raw-string literals are skipped
    over whole, so a `//` inside one does not open a comment."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        two = src[i:i + 2]
        if two == "//":
            while i < n and src[i] != "\n":
                i += 1
        elif two == "/*":
            end = src.find("*/", i + 2)
            i = n if end < 0 else end + 2
            out.append(" ")
        elif c == "R" and src[i + 1:i + 2] == '"' and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            m = re.match(r'R"([^()\\ \t\n]{0,16})\(', src[i:])
            if not m:
                out.append(c)
                i += 1
                continue
            close = ")" + m.group(1) + '"'
            end = src.find(close, i + m.end())
            end = n if end < 0 else end + len(close)
            out.append(src[i:end])
            i = end
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1])
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def code_text(src):
    """Comment-free text with whitespace collapsed and adjacent string literals joined, so line
    wrapping and implicit literal concatenation cannot hide or fake a statement."""
    text = re.sub(r"\s+", " ", strip_comments(src))
    return re.sub(r'"\s+"', "", text)


CMP = r"(?:=|<=|>=|<|>)"

# (pattern, what it means). Each is searched in `code_text`.
CLAIM_CLOCK_RULES = (
    (r"\bnow(?:_secs\(\))?\s*-\s*kApplyClaimTtlSecs",
     "the claim TTL is subtracted from a replica clock reading"),
    (r"apply_claimed_at\s*" + CMP + r"\s*\$\d",
     "apply_claimed_at is set or compared from a bind parameter"),
    (r'apply_claimed_at\s*' + CMP + r'\s*"\s*\)?\s*\+\s*std::to_string',
     "apply_claimed_at is set or compared from a number spliced into the SQL text"),
)


def claim_clock_problems(src):
    text = code_text(src)
    out = [msg for pat, msg in CLAIM_CLOCK_RULES if re.search(pat, text)]
    if text.count("apply_claimed_at = 0 OR") != 1:
        out.append("'no live claim' is not stated exactly once (it is the one statement of the rule)")
    uses = text.count("no_live_claim_sql()") - len(re.findall(r"std::string& no_live_claim_sql\(\)", text))
    if uses != 4:
        out.append("no_live_claim_sql() is used %d times; the claim, the token read and both fenced "
                   "ends must each use it (4)" % uses)
    if text.count("kClaimStampSql") != 3:
        out.append("kClaimStampSql (the database-clock stamp) is not defined once and used by the "
                   "fragment and the claim stamp (3 mentions)")
    if "EXTRACT(EPOCH FROM now())" not in text:
        out.append("the database-clock stamp EXTRACT(EPOCH FROM now()) is gone")
    return out


def seed_problems(src):
    n = len(SEED_RX.findall(code_text(src)))
    if n != 1:
        return ["server.cpp calls %s %d times; it must call it exactly once at boot" % (SEED_CALL, n)]
    return []


# Verbatim from the pre-fix quarantine_store.cpp: each statement the rules exist to catch.
PRE_FIX_SAMPLES = {
    "mark_released fence": (
        'constexpr const char* kFencedActiveWhere = "status = \'active\' AND apply_gen = $5::bigint AND "'
        '\n "(apply_claimed_at = 0 OR apply_claimed_at < $6::bigint)";\n'
        '{std::to_string(now), "0", std::to_string(*fence),\n std::to_string(now - kApplyClaimTtlSecs)},'),
    "clear_release_owed fence": (
        '{std::to_string(*fence), std::to_string(now_secs() - kApplyClaimTtlSecs)},'),
    "claim_apply": (
        '"UPDATE quarantine_store.quarantine_records SET apply_gen = apply_gen + 1, "\n'
        '"apply_claimed_at = $3::bigint WHERE agent_id = $1 AND id = $2::bigint AND status = "\n'
        '"\'active\' AND release_requested_at = 0 AND (apply_claimed_at = 0 OR apply_claimed_at < "\n'
        '"$4::bigint) RETURNING apply_gen",'),
    "apply_fence_token": (
        '"$2::bigint AND (apply_claimed_at = 0 OR apply_claimed_at < $3::bigint)",\n'
        'std::to_string(now_secs() - kApplyClaimTtlSecs)});'),
}


class QuarantineClaimUsesTheDatabaseClock(unittest.TestCase):
    def test_the_store_is_clean(self):
        self.assertEqual(claim_clock_problems(STORE_CPP.read_text(encoding="utf-8")), [])

    def test_server_cpp_seeds_the_reconciler_metrics_exactly_once(self):
        self.assertEqual(seed_problems(SERVER_CPP.read_text(encoding="utf-8")), [])


class ClaimClockSelfTest(unittest.TestCase):
    """Each rule fires on the pre-fix text, and on a mutation of the real file."""

    @classmethod
    def setUpClass(cls):
        cls.real = STORE_CPP.read_text(encoding="utf-8")

    def test_every_pre_fix_statement_is_caught_alone(self):
        for name, sample in PRE_FIX_SAMPLES.items():
            hits = [msg for pat, msg in CLAIM_CLOCK_RULES if re.search(pat, code_text(sample))]
            self.assertTrue(hits, "no rule fires on the pre-fix %s statement" % name)

    def test_the_pre_fix_file_fails(self):
        pre_fix = "\n".join(PRE_FIX_SAMPLES.values())
        self.assertNotEqual(claim_clock_problems(pre_fix), [])

    def test_a_replica_clock_cutoff_spliced_back_in_is_caught(self):
        mutated = self.real.replace('" + no_live_claim_sql();', '" + std::to_string(now_secs() - kApplyClaimTtlSecs);', 1)
        self.assertNotEqual(mutated, self.real)
        self.assertNotEqual(claim_clock_problems(mutated), [])

    def test_a_bound_claim_stamp_is_caught(self):
        mutated = self.real.replace("kClaimStampSql +", '"$3::bigint" +', 1)
        self.assertNotEqual(mutated, self.real)
        self.assertNotEqual(claim_clock_problems(mutated), [])

    def test_a_number_spliced_into_the_text_is_caught(self):
        mutated = self.real + '\nconst std::string x = "UPDATE t SET apply_claimed_at = " + std::to_string(now_secs());\n'
        self.assertNotEqual(claim_clock_problems(mutated), [])

    def test_a_second_statement_of_no_live_claim_is_caught(self):
        mutated = self.real + '\nconst char* y = "(apply_claimed_at = 0 OR apply_claimed_at < 5)";\n'
        self.assertNotEqual(claim_clock_problems(mutated), [])

    def test_a_site_that_stops_using_the_fragment_is_caught(self):
        mutated = self.real.replace("no_live_claim_sql() + \" RETURNING apply_gen\"", '" RETURNING apply_gen"', 1)
        self.assertNotEqual(mutated, self.real)
        self.assertNotEqual(claim_clock_problems(mutated), [])

    def test_comments_and_literals_are_handled(self):
        self.assertNotIn("kApplyClaimTtlSecs", code_text("// now - kApplyClaimTtlSecs\n/* now_secs() - kApplyClaimTtlSecs */"))
        self.assertIn("//", code_text('const char* u = "a//b"; // tail'))
        self.assertIn("now - kApplyClaimTtlSecs", code_text("auto v = now - kApplyClaimTtlSecs;"))
        self.assertIn("//x", code_text('auto r = R"d(//x)d"; // tail'))


class SeedMetricsSelfTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.real = SERVER_CPP.read_text(encoding="utf-8")

    def test_deleting_the_boot_call_is_caught(self):
        mutated = self.real.replace(SEED_CALL + ";", "", 1)
        self.assertNotEqual(mutated, self.real)
        self.assertNotEqual(seed_problems(mutated), [])

    def test_a_commented_out_call_is_caught(self):
        mutated = self.real.replace(SEED_CALL + ";", "// " + SEED_CALL + ";", 1)
        self.assertNotEqual(seed_problems(mutated), [])

    def test_a_second_call_is_caught(self):
        self.assertNotEqual(seed_problems(self.real + "\n" + SEED_CALL + ";\n"), [])

    def test_a_wrapped_call_still_counts(self):
        wrapped = self.real.replace(SEED_CALL, "QuarantineContainmentReconciler::seed_metrics(\n    metrics_)", 1)
        self.assertEqual(seed_problems(wrapped), [])


if __name__ == "__main__":
    unittest.main()
