#!/usr/bin/env python3
"""WP04-X pin: in server/core/src/pg_reachability_probe.cpp the CONNECT-phase sites use the connect
classifier (`pq_error`, a fixed cause) and the QUERY-phase sites use `pq_query_error`, which must
delegate to `pg::query_failure_detail` and never to `connect_failure_cause` (a dropped connection or
"SSL SYSCALL error: EOF detected" in a failover must not read as a certificate problem).

Best-effort source-text gate. Self-tested by mutation: the checker must fail on the reverted shape."""
import pathlib
import re
import sys

SRC = pathlib.Path(__file__).resolve().parent.parent / "server/core/src/pg_reachability_probe.cpp"
QUERY_STEPS = ("could not set non-blocking mode", "could not send probe query",
               "could not flush probe query", "connection lost during probe")


def strip_comments(text):
    """Remove // and /* */ comments in SOURCE ORDER, leaving string and char literals intact (a "/*"
    inside a string is not a comment, and a comment-looking tail inside a string must not hide code)."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"' or c == "'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def strip_strings(text):
    """Blank string/char literal CONTENTS so a substring inside a literal cannot satisfy a pin."""
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', text)


def check(text):
    text = strip_comments(text)
    errs = []
    m = re.search(r"std::string pq_query_error\([^)]*\)\s*\{(.*?)\n\}", text, re.S)
    if not m:
        return ["pq_query_error not found"]
    body = m.group(1)
    body_code = strip_strings(body)
    if not re.search(r"return\s+pg::query_failure_detail\(", body_code) or "connect_failure_cause" in body_code:
        errs.append("pq_query_error must call pg::query_failure_detail and not connect_failure_cause")
    for step in QUERY_STEPS:
        if f'pq_query_error(c, "{step}")' not in text:
            errs.append(f"query-phase step {step!r} must use pq_query_error")
        if f'pq_error(c, "{step}")' in text:
            errs.append(f"query-phase step {step!r} must not use the connect classifier pq_error")
    if text.count('pq_error(c, "connection failed")') != 2:
        errs.append("the two connect-phase sites must use pq_error(c, \"connection failed\")")
    if 'query_failure_detail("probe query failed"' not in text:
        errs.append("the result_error path must use query_failure_detail")
    return errs


def main():
    good = SRC.read_text()
    # mutation self-test: reverting pq_query_error to the connect classifier, or a site to pq_error, must fail
    mut1 = good.replace("return pg::query_failure_detail(step,", "return pg::connect_failure_cause(", 1)
    mut2 = good.replace('pq_query_error(c, "connection lost during probe")', 'pq_error(c, "connection lost during probe")', 1)
    # a comment-only mention of query_failure_detail must NOT satisfy the pin
    mut3 = good.replace("return pg::query_failure_detail(step,", "return pg::connect_failure_cause(  // query_failure_detail(", 1)
    mut4 = re.sub(r"(std::string pq_query_error\([^)]*\)\s*\{)", r"\1 /* query_failure_detail( */", mut1, count=1)
    # the result_error path reverted to raw text
    mut5 = good.replace('pg::query_failure_detail("probe query failed", m)', 'std::string(m)', 1)
    # a query-phase step moved to the connect helper via a comment-hidden original
    mut6 = good.replace('pq_query_error(c, "could not send probe query")', 'pq_error(c, "could not send probe query") // pq_query_error(c, "could not send probe query")', 1)
    # a dropped call that keeps the substring only inside a string literal must be RED
    mut7 = good.replace("return pg::query_failure_detail(step,", 'return std::string("query_failure_detail(") + std::string(step', 1)
    assert all(check(m) for m in (mut1, mut2, mut3, mut4, mut5, mut6, mut7)), "selftest: mutations must be caught"
    # a benign "/*" inside a string literal before the pinned function must stay GREEN
    benign = good.replace("std::string pq_query_error(", 'static const char* kBenignGlob = "/*";\nstd::string pq_query_error(', 1)
    assert not check(benign), "selftest: a string containing /* must not false-RED"
    errs = check(good)
    for e in errs:
        print("FAIL:", e)
    if errs:
        return 1
    print("OK: probe connect/query phases use the right classifier")
    return 0


if __name__ == "__main__":
    sys.exit(main())
