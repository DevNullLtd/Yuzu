#!/usr/bin/env python3
"""Best-effort lexical tripwire (WP11): endpoint-derived plugin result rows must be built by the
neutralising formatters, not by a raw std::format.

The unit tests drive the pure formatters directly, so a plugin leg reverted to a raw
`std::format("proc|...")` would leave them all green. This pins the call sites:

  * processes_plugin.cpp: exactly one call each of format_query_row (list + query = 2 sites),
    format_hashed_row and format_tree_row, and no raw `std::format("proc|`;
  * network_config_plugin.cpp: three format_bypass_row sites and no raw `std::format("bypass|`;
  * installed_apps_plugin.cpp: format_query_row once and format_user_app_row at the four
    list_per_user legs (Windows, Linux, macOS system, macOS brew), no raw `"user_app|` format;
  * network_config_plugin.cpp: FOUR format_proxy_address_row sites (the credential chokepoint:
    a raw `std::format("proxy_address|` would leak proxy credentials) and no raw proxy_address row;
  * procfetch_plugin.cpp: three yuzu::procfetch::format_row sites, no raw `"{}|{}|{}|{}"` row;
  * wmi_plugin.cpp: format_row_line once and format_property_line once, no raw row/property row;
  * filesystem_plugin.cpp: row_field on list_dir's entry name, search_dir's path and the Windows
    version-info value.

A tripwire, not proof: it counts spellings in comment-stripped source. Self-checks run in
memory against deliberately broken copies.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"//[^\n]*", "", src)
    # a dead `#if 0 ... #endif` block must not count as a call site (non-nested: the first
    # #endif ends it, which can only UNDER-strip, i.e. fail toward a louder gate)
    return re.sub(r"^[ \t]*#[ \t]*if[ \t]+0\b.*?^[ \t]*#[ \t]*endif\b", "", src, flags=re.S | re.M)


def check(files: dict) -> list:
    errs = []
    proc = files["processes"]
    for name, want in (("format_query_row(", 2), ("format_hashed_row(", 1), ("format_tree_row(", 1)):
        if proc.count("yuzu::processes::" + name) != want:
            errs.append(f"processes_plugin.cpp: expected {want} x {name}, got "
                        f"{proc.count('yuzu::processes::' + name)}")
    if re.search(r'(?:std|fmt)::format\(\s*"proc\|', proc):
        errs.append('processes_plugin.cpp: raw std::format("proc|...") row')
    nc = files["network_config"]
    if nc.count("format_bypass_row(") != 3:
        errs.append(f"network_config_plugin.cpp: expected 3 x format_bypass_row, got {nc.count('format_bypass_row(')}")
    if re.search(r'(?:std|fmt)::format\(\s*"bypass\|', nc):
        errs.append('network_config_plugin.cpp: raw std::format("bypass|...") row')
    ia = files["installed_apps"]
    if ia.count("parsers::format_query_row(") != 1:
        errs.append("installed_apps_plugin.cpp: expected 1 x parsers::format_query_row")
    if ia.count("parsers::format_user_app_row(") != 4:
        errs.append(f"installed_apps_plugin.cpp: expected 4 x parsers::format_user_app_row, got "
                    f"{ia.count('parsers::format_user_app_row(')}")
    if re.search(r'"user_app\|', ia):
        errs.append('installed_apps_plugin.cpp: raw "user_app|..." row format')
    if nc.count("format_proxy_address_row(") != 4:
        errs.append(f"network_config_plugin.cpp: expected 4 x format_proxy_address_row, got "
                    f"{nc.count('format_proxy_address_row(')}")
    if re.search(r'(?:std|fmt)::format\(\s*"proxy_address\|', nc):
        errs.append('network_config_plugin.cpp: raw std::format("proxy_address|...") row (credential leak)')
    pf = files["procfetch"]
    if pf.count("yuzu::procfetch::format_row(") != 3:
        errs.append(f"procfetch_plugin.cpp: expected 3 x format_row, got {pf.count('yuzu::procfetch::format_row(')}")
    if re.search(r'(?:std|fmt)::format\(\s*"\{\}\|\{\}\|\{\}\|\{\}"', pf):
        errs.append("procfetch_plugin.cpp: raw pid|name|path|sha1 row format")
    wm = files["wmi"]
    if wm.count("yuzu::wmi::format_row_line(") != 1 or wm.count("yuzu::wmi::format_property_line(") != 1:
        errs.append("wmi_plugin.cpp: expected one format_row_line and one format_property_line")
    if re.search(r'(?:std|fmt)::format\(\s*"(row\{\}|property)\|', wm):
        errs.append("wmi_plugin.cpp: raw row/property format")
    fsx = files["filesystem"]
    for needle in ("row_field(entry_name)", "row_field(entry_path)", "row_field(val)"):
        if fsx.count("yuzu::filesystem::acl::" + needle) != 1:
            errs.append(f"filesystem_plugin.cpp: expected yuzu::filesystem::acl::{needle} once")
    return errs


def load() -> dict:
    p = ROOT / "agents" / "plugins"
    return {
        "processes": strip_comments((p / "processes/src/processes_plugin.cpp").read_text(encoding="utf-8")),
        "network_config": strip_comments((p / "network_config/src/network_config_plugin.cpp").read_text(encoding="utf-8")),
        "installed_apps": strip_comments((p / "installed_apps/src/installed_apps_plugin.cpp").read_text(encoding="utf-8")),
        "procfetch": strip_comments((p / "procfetch/src/procfetch_plugin.cpp").read_text(encoding="utf-8")),
        "wmi": strip_comments((p / "wmi/src/wmi_plugin.cpp").read_text(encoding="utf-8")),
        "filesystem": strip_comments((p / "filesystem/src/filesystem_plugin.cpp").read_text(encoding="utf-8")),
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
    bad = dict(files)
    bad["network_config"] = files["network_config"].replace("yuzu::network_config::format_proxy_address_row(", "std::format(\"proxy_address|{}\", ", 1)
    assert check(bad), "self-check: reverted proxy_address site not caught"
    bad = dict(files)
    bad["procfetch"] = files["procfetch"].replace("yuzu::procfetch::format_row(", "std::format(\"{}|{}|{}|{}\", ", 1)
    assert check(bad), "self-check: reverted procfetch site not caught"
    bad = dict(files)
    bad["wmi"] = files["wmi"].replace("yuzu::wmi::format_property_line(", "std::format(\"property|{}|{}\", ", 1)
    assert check(bad), "self-check: reverted wmi site not caught"
    bad = dict(files)
    bad["filesystem"] = files["filesystem"].replace("yuzu::filesystem::acl::row_field(entry_name)", "entry_name", 1)
    assert check(bad), "self-check: reverted filesystem site not caught"
    # dead code and the fmt:: spelling: a call site in `#if 0` does not count, and a raw
    # fmt::format("proxy_address|...") is as bad as the std:: one
    dead = strip_comments("#if 0\nyuzu::network_config::format_proxy_address_row(x);\n#endif\nint y;")
    assert "format_proxy_address_row" not in dead, "self-check: #if 0 block not stripped"
    bad = dict(files)
    bad["network_config"] = files["network_config"].replace("yuzu::network_config::format_proxy_address_row(", "fmt::format(\"proxy_address|{}\", ", 1)
    assert check(bad), "self-check: fmt::format proxy_address row not caught"
    for e in errs:
        print("FAIL:", e)
    if not errs:
        print("ok")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
