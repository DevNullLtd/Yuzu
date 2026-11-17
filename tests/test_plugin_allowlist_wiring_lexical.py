#!/usr/bin/env python3
"""WP13/F52 lexical tripwire: agent.cpp must run the allowlist startup decision before
PluginLoader::scan and tell scan that an allowlist was required. The std::exit path cannot be
exercised in-process, so pin the wiring (best-effort source text check)."""
import pathlib
import re
import sys

SRC = (pathlib.Path(__file__).resolve().parent.parent / "agents/core/src/agent.cpp").read_text()


def main() -> int:
    i_eval = SRC.find("evaluate_allowlist_startup(cfg_.plugin_allowlist")
    i_scan = SRC.find("PluginLoader::scan(cfg_.plugin_dir")
    errs = []
    if i_eval < 0:
        errs.append("agent.cpp no longer calls evaluate_allowlist_startup(cfg_.plugin_allowlist, ...)")
    if i_scan < 0:
        errs.append("agent.cpp PluginLoader::scan call not found")
    if i_eval >= 0 and i_scan >= 0 and i_eval > i_scan:
        errs.append("allowlist startup decision must precede PluginLoader::scan")
    if i_eval >= 0:
        window = SRC[i_eval:i_eval + 700]
        if "std::exit(EXIT_FAILURE)" not in window:
            errs.append("allowlist refusal must std::exit(EXIT_FAILURE)")
    if not re.search(r"PluginLoader::scan\(cfg_\.plugin_dir,[^;]*allowlist_required\)", SRC):
        errs.append("scan must receive allowlist_required")
    for e in errs:
        print("FAIL:", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
