#!/usr/bin/env python3
"""Table test for the Phase 2 API-token count helper (#2581).

Locks the empty-vs-unreadable distinction that `test-fixtures-verify.sh` relies
on. That script treats 0 as the PASS condition on an ADR-0030 cutover edge, so
any body it cannot read must return the -1 sentinel rather than collapsing to 0
— otherwise a 502, an auth failure or a truncated response scores as "tokens
correctly invalidated".

Governance Gate 3 F-C: before this existed there was no regression net for the
helper at all, and two defects shipped through it (a parse failure printing 0,
and an empty string satisfying `(( n == 0 ))` in the caller).

Run: python3 -m pytest tests/test_api_token_count.py
     or plain `python3 tests/test_api_token_count.py` with no pytest installed.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts" / "test"))

from api_token_count import count  # noqa: E402

CASES = [
    # (label, body, expected)
    ("empty list — the ADR-0030 cutover PASS case", '{"data":[],"meta":{}}', 0),
    ("one token", '{"data":[{"id":"a"}],"meta":{}}', 1),
    ("three tokens", '{"data":[1,2,3]}', 3),
    ("missing data key — unreadable, NOT empty", '{"meta":{}}', -1),
    ("data is null", '{"data":null}', -1),
    ("data is a string — len() would wrongly give 10", '{"data":"not-a-list"}', -1),
    ("top-level array", "[]", -1),
    ("bare scalar", "42", -1),
    ("HTML error page", "<html>502 Bad Gateway</html>", -1),
    ("truncated JSON", '{"data":[', -1),
    ("empty body", "", -1),
    ("whitespace only", "   \n", -1),
]


def test_table():
    failures = []
    for label, body, expected in CASES:
        got = count(body)
        if got != expected:
            failures.append(f"{label}: got {got}, want {expected}")
    assert not failures, "\n".join(failures)


def test_unreadable_never_collapses_to_zero():
    """The property the sentinel exists for, stated directly.

    Every unreadable shape must be distinguishable from a genuinely empty list,
    because the caller reads 0 as success.
    """
    unreadable = [b for _, b, e in CASES if e == -1]
    assert unreadable, "table has no unreadable cases — the property is untested"
    for body in unreadable:
        assert count(body) != 0, f"unreadable body scored as empty: {body!r}"


if __name__ == "__main__":
    test_table()
    test_unreadable_never_collapses_to_zero()
    print(f"api_token_count: {len(CASES)} cases OK")
