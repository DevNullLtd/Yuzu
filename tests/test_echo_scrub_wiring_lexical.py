#!/usr/bin/env python3
"""WP07 lexical gate: every Echo diff source scrubs its identity strings at collection.

Echo baselines are dumped with nlohmann error_handler_t::replace (invalid byte -> U+FFFD). The next
enumeration holds the RAW bytes, so a name-keyed diff of (decoded baseline, raw current) emits a
phantom pair EVERY tick unless the freshly enumerated set is first passed through
yuzu::echo::scrub_wire_strings (echo_wire_scrub.hpp). The per-source behaviour is unit-tested on the
scrub helpers, but the CALL SITES live in echo_plugin.cpp's collect_fast_impl, behind anonymous
helpers a unit test cannot reach, so deleting one stays green. This gate pins each call site
lexically (best-effort: source text, not semantics). Run: python3 tests/test_echo_scrub_wiring_lexical.py
"""
import pathlib
import re
import sys

SRC = pathlib.Path(__file__).resolve().parents[1] / "agents/plugins/echo/src/echo_plugin.cpp"

S = r"yuzu::echo::scrub_wire_strings"
PROC = r"auto current = yuzu::agent::enumerate_processes\(\);\s*"

# (id, regex over the source with comments stripped). EVERY call site has its OWN pattern, anchored
# on a context unique to that site (never a prefix of another site's pattern), so deleting or
# commenting out any single call leaves exactly one pattern unmatched. Each must match exactly once.
REQUIRED = [
    ("pid_name_ map", r"std::string clean = name;\s*" + S + r"\(clean\);\s*pid_name_\[pid\]"),
    ("process stream pe.name", r"pe\.user = e\.user;\s*" + S + r"\(pe\.name\);\s*" + S + r"\(pe\.user\);"),
    ("process stream pe.user", S + r"\(pe\.name\);\s*" + S + r"\(pe\.user\);\s*pe\.exit_code"),
    ("process stream-fallback seed",
     r"stream_active_ = false;\s*" + PROC + S + r"\(current\);\s*note_pid_names\(current, ts\);\s*if \(!stab_excl"),
    ("process poll diff",
     r"\}\s*else\s*\{\s*" + PROC + S + r"\(current\);\s*note_pid_names\(current, ts\);\s*if \(!stab_excl"),
    ("network (after fill_process_names)",
     r"fill_process_names\(current, pid_name_, ts\);\s*" + S + r"\(current\);"),
    ("arp", S + r"\(\*current\);\s*auto previous = json_to_arp"),
    ("dns", r"enumerate_dns\(\);\s*" + S + r"\(current\);\s*auto previous = json_to_dns"),
    ("services", S + r"\(\*current\);\s*const std::string svc_key"),
    ("users", r"enumerate_users\(\);\s*" + S + r"\(current\);\s*auto prev_json = db_->get_state\(usr_key\)"),
    ("mapdrive", S + r"\(\*current\);\s*const std::string md_key"),
    # fleet_snapshot: four statements, each pinned together with its neighbours so deleting or
    # commenting out any one of them leaves at least one pattern unmatched.
    ("fleet_snapshot processes", r"\}\s*" + S + r"\(processes\);\s*" + S + r"\(connections\);"),
    ("fleet_snapshot connections", S + r"\(processes\);\s*" + S + r"\(connections\);\s*" + S + r"\(hostname\);"),
    ("fleet_snapshot hostname", S + r"\(connections\);\s*" + S + r"\(hostname\);\s*" + S + r"\(local_ips\);"),
    ("fleet_snapshot local_ips", S + r"\(hostname\);\s*" + S + r"\(local_ips\);\s*auto redaction"),
]
FLOOR = 15  # call sites in echo_plugin.cpp (the stream leg has two, fleet_snapshot four)


_TOKEN = re.compile(
    r'"(?:\\.|[^"\\\n])*"'      # string literal: kept verbatim
    r"|'(?:\\.|[^'\\\n])'"      # char literal: kept verbatim
    r"|//[^\n]*"                  # line comment: dropped
    r"|/\*.*?\*/",                # block comment: dropped
    re.S,
)


def strip_comments(text: str) -> str:
    """Drop // and /* */ comments in source order, so a `/*` inside a `//` comment (a glob like
    `echo_*.cpp`) cannot open a bogus block comment, and commenting a call out cannot satisfy a
    pattern. String and char literals are left intact."""
    return _TOKEN.sub(lambda m: m.group(0) if m.group(0)[0] in "\"'" else " ", text)


def main() -> int:
    text = strip_comments(SRC.read_text(encoding="utf-8"))
    bad = []
    for name, rx in REQUIRED:
        n = len(re.findall(rx, text))
        if n != 1:
            bad.append(f"{name} (matched {n}x, want exactly 1)")
    calls = len(re.findall(r"scrub_wire_strings\(", text))
    if calls < FLOOR:
        bad.append(f"live call-site count {calls} < {FLOOR}")
    for b in bad:
        print(f"FAIL: echo_plugin.cpp lost or changed a scrub_wire_strings call: {b}")
    if not bad:
        print(f"ok: {len(REQUIRED)} Echo scrub patterns and {calls} call sites present")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
