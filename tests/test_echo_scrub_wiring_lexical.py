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

# (id, regex over the source). Each must match exactly once or more.
REQUIRED = [
    ("process poll seed",
     r"auto current = yuzu::agent::enumerate_processes\(\);\s*yuzu::echo::scrub_wire_strings\(current\);"),
    ("process poll diff",
     r"auto current = yuzu::agent::enumerate_processes\(\);\s*yuzu::echo::scrub_wire_strings\(current\);"
     r"[^\n]*\n\s*// Before the exclusions"),
    ("network (after fill_process_names)",
     r"fill_process_names\(current, pid_name_, ts\);\s*yuzu::echo::scrub_wire_strings\(current\);"),
    ("dns", r"enumerate_dns\(\);\s*yuzu::echo::scrub_wire_strings\(current\);"),
    ("users", r"enumerate_users\(\);\s*yuzu::echo::scrub_wire_strings\(current\);"),
    ("arp", r"scrub_wire_strings\(\*current\);[^\n]*\n\s*auto previous = json_to_arp"),
    ("services", r"scrub_wire_strings\(\*current\);[^\n]*\n\s*const std::string svc_key"),
    ("mapdrive", r"scrub_wire_strings\(\*current\);[^\n]*\n\s*const std::string md_key"),
    ("process stream leg", r"pe\.user = e\.user;[^\n]*\n(?:\s*//[^\n]*\n)+\s*yuzu::echo::scrub_wire_strings\(pe\.name\);\s*yuzu::echo::scrub_wire_strings\(pe\.user\);"),
    ("pid_name_ map", r"scrub_wire_strings\(clean\);\s*pid_name_\[pid\]"),
]


def main() -> int:
    text = SRC.read_text(encoding="utf-8")
    bad = [name for name, rx in REQUIRED if not re.search(rx, text)]
    n = len(re.findall(r"scrub_wire_strings\(", text))
    if n < len(REQUIRED):
        bad.append(f"call-site count {n} < {len(REQUIRED)}")
    for b in bad:
        print(f"FAIL: echo_plugin.cpp lost its scrub_wire_strings call: {b}")
    if not bad:
        print(f"ok: {len(REQUIRED)} Echo scrub call sites present")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
