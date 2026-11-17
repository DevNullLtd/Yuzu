#!/usr/bin/env python3
"""Best-effort lexical tripwire (WP11): endpoint-derived plugin result rows must be built by the
neutralising formatters, not by a raw std::format.

The unit tests drive the pure formatters directly, so a plugin leg reverted to a raw
`std::format("proc|...")` would leave them all green. This pins the call sites:

  * processes_plugin.cpp: exactly one call each of format_query_row (list + query = 2 sites),
    format_hashed_row and format_tree_row, and no raw `std::format("proc|`;
  * network_config_plugin.cpp: three format_bypass_row sites and no raw `std::format("bypass|`;
  * installed_apps_plugin.cpp: format_query_row once and format_user_app_row at the four
    list_per_user legs (Windows, Linux, macOS system, macOS brew), no raw `"user_app|` format.

A tripwire, not proof: it counts spellings in comment-stripped source. Self-checks run in
memory against deliberately broken copies.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def check(files: dict) -> list:
    errs = []
    proc = files["processes"]
    for name, want in (("format_query_row(", 2), ("format_hashed_row(", 1), ("format_tree_row(", 1)):
        if proc.count("yuzu::processes::" + name) != want:
            errs.append(f"processes_plugin.cpp: expected {want} x {name}, got "
                        f"{proc.count('yuzu::processes::' + name)}")
    if re.search(r'std::format\(\s*"proc\|', proc):
        errs.append('processes_plugin.cpp: raw std::format("proc|...") row')
    nc = files["network_config"]
    if nc.count("format_bypass_row(") != 3:
        errs.append(f"network_config_plugin.cpp: expected 3 x format_bypass_row, got {nc.count('format_bypass_row(')}")
    if re.search(r'std::format\(\s*"bypass\|', nc):
        errs.append('network_config_plugin.cpp: raw std::format("bypass|...") row')
    ia = files["installed_apps"]
    if ia.count("parsers::format_query_row(") != 1:
        errs.append("installed_apps_plugin.cpp: expected 1 x parsers::format_query_row")
    if ia.count("parsers::format_user_app_row(") != 4:
        errs.append(f"installed_apps_plugin.cpp: expected 4 x parsers::format_user_app_row, got "
                    f"{ia.count('parsers::format_user_app_row(')}")
    if re.search(r'"user_app\|', ia):
        errs.append('installed_apps_plugin.cpp: raw "user_app|..." row format')
    return errs


def load() -> dict:
    p = ROOT / "agents" / "plugins"
    return {
        "processes": strip_comments((p / "processes/src/processes_plugin.cpp").read_text()),
        "network_config": strip_comments((p / "network_config/src/network_config_plugin.cpp").read_text()),
        "installed_apps": strip_comments((p / "installed_apps/src/installed_apps_plugin.cpp").read_text()),
    }


def main() -> int:
    files = load()
    errs = check(files)
    # self-checks: a reverted site must be caught
    bad = dict(files)
    bad["processes"] = files["processes"].replace("yuzu::processes::format_tree_row(", "std::format(\"proc|{}\", ", 1)
    assert check(bad), "self-check: reverted processes site not caught"
    bad = dict(files)
    bad["network_config"] = files["network_config"].replace("yuzu::network_config::format_bypass_row(", "std::format(\"bypass|{}\", ", 1)
    assert check(bad), "self-check: reverted bypass site not caught"
    bad = dict(files)
    bad["installed_apps"] = files["installed_apps"].replace("parsers::format_user_app_row(", "std::format(\"user_app|{}\", ", 1)
    assert check(bad), "self-check: reverted user_app leg not caught"
    for e in errs:
        print("FAIL:", e)
    if not errs:
        print("ok")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
