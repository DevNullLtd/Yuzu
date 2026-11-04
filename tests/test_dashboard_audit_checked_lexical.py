#!/usr/bin/env python3
"""Lexical gate for #3619: every audit row DashboardRoutes writes has its persist outcome checked.

`server/core/src/dashboard_routes.cpp` once called its audit sink as a bare statement at every
site (26 of them), and the sink's type returned `void`, so a row the audit store did not persist
was indistinguishable from one it did. ADR-0033 section 9 needs the outcome: a mutation whose
`attempted` row is not stored must not happen, and every other row that is not stored marks the
response `Sec-Audit-Failed: true`.

This gate pins the two properties that make that structural rather than per-site:

  1. `DashboardRoutes::AuditFn` returns `bool` (a `void` sink cannot report a failure at all);
  2. no code in dashboard_routes.cpp CALLS `audit_fn_(...)` or `persist_audit_fn_(...)`
     directly. Every row goes through the class's checked helpers, which hand the sink to the
     shared `detail::try_persist_audit` kernel (rest_audit.hpp) as an ARGUMENT.

A string-presence check, not a parser: it cannot prove a helper is called on the right path.
The behaviour is bound by the Catch2 cases tagged [3619]; this gate stops a new bare call from
reappearing silently. It runs a few in-memory self-checks first, so a detector that stopped
matching fails loudly instead of passing everything.

Usage: python3 -I tests/test_dashboard_audit_checked_lexical.py
"""
from __future__ import annotations

import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROUTES_CPP = os.path.join("server", "core", "src", "dashboard_routes.cpp")
ROUTES_HPP = os.path.join("server", "core", "src", "dashboard_routes.hpp")
TAG = "test_dashboard_audit_checked_lexical"

# A call through `this->` is still the class's own sink; any other `x.`/`x->` qualifier is a
# different object (#3619 review: `>` in the lookbehind once let `this->audit_fn_(...)` through).
BARE_CALL = re.compile(r"(?:\bthis\s*->\s*|(?<![\w.>]))(?:persist_)?audit_fn_\s*\(")
BOOL_TYPEDEF = re.compile(r"using\s+AuditFn\s*=\s*std::function<\s*bool\s*\(")


def strip_comments(text: str) -> str:
    """Drop // and /* */ comments and blank out string literals (a call inside a log string
    or a comment is not a call)."""
    out, i, n = [], 0, len(text)
    while i < n:
        two = text[i:i + 2]
        c = text[i]
        if two == "//":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif two == "/*":
            j = text.find("*/", i + 2)
            end = n if j < 0 else j + 2
            out.append(" " + "\n" * text.count("\n", i, end))  # keep line numbers true
            i = end
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            out.append(c + c)
            # Stop AT a newline (an unterminated literal, e.g. a digit separator), never past it.
            i = j if j < n and text[j] == "\n" else j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def bare_calls(cpp: str) -> list[int]:
    """1-based line numbers of each direct sink call."""
    code = strip_comments(cpp)
    return [code.count("\n", 0, m.start()) + 1 for m in BARE_CALL.finditer(code)]


def self_check() -> list[str]:
    errors = []
    cases = {
        "    audit_fn_(req, \"a\", \"denied\", \"t\", \"\", \"d\");\n": 1,
        "    persist_audit_fn_ (req, a, r, t, i, d);\n": 1,
        "    (void)audit_fn_(req, a, r, t, i, d);\n": 1,
        "    (void)detail::try_persist_audit(audit_fn_, req, a, r, t, i, d);\n": 0,
        "    // audit_fn_(req, ...) in a comment\n": 0,
        "    spdlog::warn(\"audit_fn_(x)\");\n": 0,
        "    audit_fn_ = std::move(audit_fn);\n": 0,
        "    other.audit_fn_(req);\n": 0,
        "    other->audit_fn_(req);\n": 0,
        "    this->audit_fn_(req, a, r, t, i, d);\n": 1,
        "    this->persist_audit_fn_(req, a, r, t, i, d);\n": 1,
        "    (void)this -> audit_fn_ (req, a, r, t, i, d);\n": 1,
        "    detail::try_persist_audit(this->audit_fn_, req, a, r, t, i, d);\n": 0,
    }
    for src, want in cases.items():
        got = len(bare_calls(src))
        if got != want:
            errors.append(f"self-check: {src.strip()!r} matched {got} call(s), expected {want}")
    if not BOOL_TYPEDEF.search("using AuditFn = std::function<bool(const httplib::Request&,"):
        errors.append("self-check: the bool AuditFn pattern no longer matches its own example")
    if BOOL_TYPEDEF.search("using AuditFn = std::function<void(const httplib::Request&,"):
        errors.append("self-check: the bool AuditFn pattern accepts a void sink")
    return errors


def main() -> int:
    errors = self_check()
    if not errors:
        with open(os.path.join(REPO_ROOT, ROUTES_HPP), encoding="utf-8") as f:
            hpp = strip_comments(f.read())
        if not BOOL_TYPEDEF.search(hpp):
            errors.append(f"{ROUTES_HPP}: DashboardRoutes::AuditFn must return bool, so a row the "
                          "audit store did not persist can be told from one it did (#3619)")
        with open(os.path.join(REPO_ROOT, ROUTES_CPP), encoding="utf-8") as f:
            for line in bare_calls(f.read()):
                errors.append(f"{ROUTES_CPP}:{line}: direct audit sink call; write the row through "
                              "audit_attempted / audit_or_flag so its persist outcome is checked "
                              "(#3619, ADR-0033 section 9)")
    for e in errors:
        print(f"{TAG}: FAIL: {e}")
    if errors:
        return 1
    print(f"{TAG}: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
