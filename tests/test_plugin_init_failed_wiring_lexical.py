#!/usr/bin/env python3
"""Static lexical gate over server/core/src/server.cpp: the yuzu_fleet_plugin_init_failed label
catalogue stays wired.

AgentHealthStore labels a `yuzu.plugins_failed` token only when it is in the set handed to
set_known_plugins(); an unwired store fails CLOSED, so every real plugin would be summed under
plugin="unknown" and YuzuPluginInitFailed would fire only on that one series. The unit tests build
their own store, so nothing but this gate notices the one production line being dropped, moved
after the first sweep, or duplicated.

Required (comments stripped, whitespace/line-wrap tolerant; the wiring, thread-start and
recompute tokens are matched with string, raw-string and character literal contents blanked, so a
statement spelt inside a literal cannot stand in for the call):
  * `health_store_.set_known_plugins(catalogue_plugin_names(capability_registry_))` exists EXACTLY
    once, and the registry it reads is composed (declared) in the same file;
  * that statement precedes the start of health_recompute_thread_ (which itself starts at exactly
    one site) and every health_store_.recompute_metrics( call;
  * both metrics_.describe registrations (yuzu_fleet_plugin_init_failed and
    kPluginInitFailedRejectedGauge) exist.

Lexical only: it cannot see a statement that is present but in a branch that never runs
(review-enforced). The companion tests/test_plugin_init_failed_wiring_lexical_selftest.py deletes
each required statement in memory and requires the gate to name it.

Usage: python3 -I tests/test_plugin_init_failed_wiring_lexical.py
"""
from __future__ import annotations

import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
SERVER_CPP = os.path.join("server", "core", "src", "server.cpp")
TAG = "test_plugin_init_failed_wiring_lexical"
HINT = (" (this gate pins the plugin-init-failed label catalogue wiring; if server.cpp was "
        "legitimately restructured, update tests/test_plugin_init_failed_wiring_lexical.py and its selftest)")

# The one comment-stripping, whitespace-collapsing scanner the other server.cpp wiring gates share.
_spec = importlib.util.spec_from_file_location(
    "forensics_tier_wiring_lexical", os.path.join(HERE, "test_forensics_tier_wiring_lexical.py"))
_forensics = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _forensics
_spec.loader.exec_module(_forensics)
canonical = _forensics.canonical
_RAW_OPEN = re.compile(r'R"([^()\\\s]{0,16})\(')


def blank_literals(text: str) -> str:
    """Empty the CONTENTS of string, raw-string and character literals in comment-free text.

    A statement spelt inside a literal is inert text, so the code-token patterns must never match
    it. The quotes stay, so `f("x")` keeps its shape.
    """
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == "R" and text[i + 1:i + 2] == '"' and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            m = _RAW_OPEN.match(text, i)
            if m:
                end = text.find(")" + m.group(1) + '"', m.end())
                j = n if end < 0 else end + len(m.group(1)) + 2
                out.append('R""')
                i = j
                continue
        if c == '"' or (c == "'" and not (i and text[i - 1].isalnum())):  # 1'000 is a digit separator
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            out.append(c + c)
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def code_canonical(src: str) -> str:
    """canonical() with literal contents blanked: only real code tokens remain."""
    t = re.sub(r"\s+", " ", blank_literals(_forensics.strip_comments(src)))
    return _forensics._PUNCT.sub(r"\1", t)

_WIRE = (r"health_store_\.set_known_plugins\((?:yuzu::server::)?catalogue_plugin_names\(capability_registry_\)\);")
_THREAD = r"health_recompute_thread_=std::thread\("
_RECOMPUTE = r"health_store_\.recompute_metrics\("

# Rows matched against the literal-preserving text: the two describe() name checks need the
# metric-name string. Every other row matches code only (literal contents blanked).
LITERAL_ROWS = frozenset({"describe-init-failed", "describe-rejected"})

# (id, pattern with a named group `k` = the statement the selftest deletes, why)
REQUIRED: list[tuple[str, str, str]] = [
    ("wire-known-plugins", r"(?P<k>" + _WIRE + r")",
     "the catalogue plugin names must reach the health store, or every real plugin is labelled unknown"),
    ("registry-composed", r"(?P<k>CommandCapabilityRegistry capability_registry_\{YUZU_ALL_CAPABILITY_FRAGMENTS\};)",
     "the catalogue the names are derived from must be composed from every capability fragment"),
    ("wire-before-thread", r"(?P<k>" + _WIRE + r").*?" + _THREAD,
     "the set must be wired before the health recompute thread starts (its first sweep must see it)"),
    ("describe-init-failed", r"(?P<k>metrics_\.describe\(\"yuzu_fleet_plugin_init_failed\",)",
     "yuzu_fleet_plugin_init_failed needs its HELP/TYPE registration"),
    ("describe-rejected",
     r"(?P<k>metrics_\.describe\(yuzu::server::kPluginInitFailedRejectedGauge,"
     r"yuzu::server::kPluginInitFailedRejectedHelp,\"gauge\"\);)",
     "the rejected gauge needs its HELP/TYPE registration from the shared constants"),
]

# (id, pattern, exact count, why)
COUNTED: list[tuple[str, str, int, str]] = [
    ("wire-once", r"(?P<k>" + _WIRE + r")", 1,
     "set_known_plugins is called at exactly one site, once, at boot (a second call would race the sweep)"),
    ("anchor-thread", r"(?P<k>" + _THREAD + r")", 1,
     "the health recompute thread starts at exactly one site (wire-before-thread measures against it)"),
]


def text_for(rid: str, code: str, lit: str) -> str:
    return lit if rid in LITERAL_ROWS else code


def problems_canonical(code: str, lit: str | None = None) -> list[tuple[str, str]]:
    """`code` is code_canonical(src); `lit` is canonical(src) (defaults to `code`)."""
    lit = code if lit is None else lit
    out: list[tuple[str, str]] = []
    for rid, pat, why in REQUIRED:
        if not re.search(pat, text_for(rid, code, lit), re.S):
            out.append((rid, f"{rid}: {why}"))
    t = code
    for rid, pat, want, why in COUNTED:
        got = len(re.findall(pat, t, re.S))
        if got != want:
            out.append((rid, f"{rid}: expected exactly {want} occurrences, found {got}: {why}"))
    wire = re.search(_WIRE, t)
    first_sweep = re.search(_RECOMPUTE, t)
    if wire and first_sweep and first_sweep.start() < wire.start():
        out.append(("wire-before-sweep", "wire-before-sweep: a recompute_metrics call precedes the set_known_plugins "
                    "statement; a sweep must never run on an unwired store"))
    return out


def problems(src: str) -> list[tuple[str, str]]:
    return problems_canonical(code_canonical(src), canonical(src))


def main() -> int:
    try:
        with open(os.path.join(REPO_ROOT, SERVER_CPP), encoding="utf-8") as fh:
            src = fh.read()
    except OSError as e:
        print(f"::error::{TAG}: cannot read {SERVER_CPP}: {e}", file=sys.stderr)
        return 1
    found = problems(src)
    for _rid, msg in found:
        print(f"::error::{TAG}: {SERVER_CPP}: {msg}{HINT}", file=sys.stderr)
    if found:
        return 1
    print(f"OK: {len(REQUIRED)} wiring statements, {len(COUNTED)} counted sites, 1 ordering pin")
    return 0


if __name__ == "__main__":
    sys.exit(main())
