#!/usr/bin/env python3
"""Count API tokens in a REST v1 list body, distinguishing empty from unreadable.

Extracted from test-fixtures-verify.sh so the decision has a table test with no
docker, no server and no upgrade cycle (governance Gate 3, F-C). It was inline
shell-embedded python, which is exactly why the empty-string arithmetic defect
(F2) and the parse-failure-scores-as-zero defect both shipped unnoticed.

Reads the body on stdin, prints a single integer:

    >= 0   the number of entries in `data`
    -1     SENTINEL: the body could not be read as a v1 list envelope

The sentinel is load-bearing. `test-fixtures-verify.sh` treats 0 as the PASS
condition on an ADR-0030 cutover edge, so an unreadable response MUST NOT
collapse to 0 — that would score a 502, an auth failure or a truncated body as
"tokens correctly invalidated". Missing `data`, a non-list `data`, a top-level
array and a bare scalar are all unreadable, not empty.
"""

import json
import sys


def count(body: str) -> int:
    """Entries in a v1 `{"data": [...]}` envelope, or -1 if unreadable."""
    try:
        parsed = json.loads(body)
    except Exception:
        return -1
    if not isinstance(parsed, dict) or not isinstance(parsed.get("data"), list):
        return -1
    return len(parsed["data"])


if __name__ == "__main__":
    print(count(sys.stdin.read()))
