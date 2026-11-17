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


def check(text):
    errs = []
    m = re.search(r"std::string pq_query_error\([^)]*\)\s*\{(.*?)\n\}", text, re.S)
    if not m:
        return ["pq_query_error not found"]
    body = m.group(1)
    if "query_failure_detail(" not in body or "connect_failure_cause" in body:
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
    assert check(mut1) and check(mut2), "selftest: mutations must be caught"
    errs = check(good)
    for e in errs:
        print("FAIL:", e)
    if errs:
        return 1
    print("OK: probe connect/query phases use the right classifier")
    return 0


if __name__ == "__main__":
    sys.exit(main())
