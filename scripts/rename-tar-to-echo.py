#!/usr/bin/env python3
"""Rename the TAR activity-record feature to Echo across the tracked tree.

One scripted, idempotent, hard-cut rename. Phase A renames every tracked path
that has a `tar` component (git mv, so history follows); phase B rewrites file
contents line by line with an ordered token map. Archive-tool uses of `tar`
(tar -xzf, .tar.gz, package lists) and the legacy on-disk SQLite names
(tar_events, idx_tar_events*) stay verbatim.

Usage (from anywhere inside the checkout):
    python3 scripts/rename-tar-to-echo.py --self-test   # fixture table + idempotence
    python3 scripts/rename-tar-to-echo.py --dry-run     # list renames and every edit
    python3 scripts/rename-tar-to-echo.py               # apply

Stdlib only. A second apply is a no-op ("0 edits, 0 renames").

Run it once, on the pre-rename tree. The hand-written upgrade-window shims that land after it
(agents/core/include/yuzu/agent/echo_db_legacy_rename.hpp, the registry wire shim, the Postgres
migrations, the audit both-spellings filter) deliberately spell the legacy names, and the map would
rewrite them.
Once that header exists the script reports "0 edits, 0 renames" and changes nothing.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

SELF = "scripts/rename-tar-to-echo.py"

# Only build trees and this script are skipped. The first apply (2026-10-28) kept governance.d/,
# changelog.d/, docs/reviews/, docs/plans/feat-tar-15f-* and CHANGELOG.md verbatim as evidence; the
# owner widened the rename to them on 2026-10-29 ("a new branding exercise"), so a run on the
# pre-rename tree now rewrites those too.
VERBATIM_PREFIXES = (
    "build-",
    "vcpkg_installed/",
)
VERBATIM_FILES = {SELF}

# --------------------------------------------------------------------------
# Phase A: path components
# --------------------------------------------------------------------------

_COMPONENT_HIT = re.compile(r"(^|[-_.])tar(?=[-_.]|$)")
_ARCHIVE_COMPONENT = re.compile(r"\.tar(\.|$)")


def rename_component(comp: str) -> str:
    """tar_db.cpp -> echo_db.cpp; test_tar_x.cpp -> test_echo_x.cpp; foo.tar.gz untouched."""
    if _ARCHIVE_COMPONENT.search(comp):
        return comp
    return _COMPONENT_HIT.sub(lambda m: m.group(1) + "echo", comp)


def rename_path(path: str) -> str:
    return "/".join(rename_component(c) for c in path.split("/"))


def is_verbatim(path: str) -> bool:
    return path in VERBATIM_FILES or path.startswith(VERBATIM_PREFIXES)


# --------------------------------------------------------------------------
# Phase B: content
# --------------------------------------------------------------------------

_SENTINEL = re.compile(r"\x01(\d+)\x02")

_ARCHIVE_LONG_OPTS = (
    "strip|exclude|create|extract|list|directory|file|gzip|xz|zstd|warning|no-|owner|group|"
    "sort|mtime|numeric|use-|transform|wildcards|totals|verbose|one-file|format|posix|"
    "preserve|same|keep|overwrite|to-stdout|files-from|null|absolute|dereference|hard|"
    "remove|index|label|checkpoint|blocking|record|sparse|ignore|anchored|auto-|bzip2|"
    "lzma|lzop|compress|show|backup|suffix|atime|touch|version|help"
)

# Spans (or single words, via lookarounds) that must survive the token map.
# Ordered: longer / more specific first, because a masked span is opaque to
# every later pattern.
PROTECT = [
    # the one sanctioned TAR mention (CONTEXT.md glossary, hand-written)
    r"Echo was named TAR before 2026-10",
    # (evidence-file references are NOT protected any more: the evidence files themselves are renamed)
    # branch names are history
    r"\b(?:feat|fix|chore)/[A-Za-z0-9._-]*(?<![A-Za-z])tar(?![A-Za-z])[A-Za-z0-9._-]*",
    # legacy on-disk SQLite objects inside pre-v3 database files
    r"(?:idx_)?tar_events\w*",
    # captured third-party data
    r"<tar@debian\.org>",
    r"(?<![\w])tar(?=\|\d)",
    # archive tool: files, commands, package lists, prose
    r"(?<=\.tar\.gz)\s+tar(?=\s*$)",
    r"(?<![\w])\.?tar\.(?:gz|xz|zst|bz2|lz|lzma|Z)(?![A-Za-z])",
    r"(?<=[\w}\)\"'])\.tar(?=[\"'\s`)\]]|$)",
    r"modern-tar",
    r"(?<![\w])tar\.exe",
    r"(?<![\w.-])tar(?=\) tar )",
    r"(?<![\w.-])tar(?=\s+(?:-[A-Za-z]|--(?:" + _ARCHIVE_LONG_OPTS + r")|[xctzvjJ]+f?\b))",
    r"(?<![\w.-])tar(?=\s*\|\s*(?:grep|head|wc|sed|awk|tee|gzip|zstd|xz|sha\w*)\b)",
    r"(?<=\bunzip )tar\b",
    r"(?<=\bzip )tar(?= )",
    r"(?<=\bcurl )tar(?= )",
    r"(?<![\w.-])tar(?= +(?:zip|unzip|git|python3-pip|ca-certificates|gzip)\b)",
    r"(?<=sh, cp, )tar(?=, ls)",
    r"(?<=sh ls cp )tar(?= cat)",
    r"(?<=Never )tar(?= the postgres)",
    r"(?<=# )tar(?= preserves)",
    r"(?<=--entrypoint )tar\b",
    r"(?<![\w.-])tar(?=/zstd)",
    r"(?<![\w.-])tar(?= (?:archive|stream)\b)",
    r"(?<![\w.-])tar(?= takes SIGPIPE)",
    r"(?<![\w.-])tar(?= unpacks)",
    r"(?<=filesystem-level `)tar(?=`)",
    r"(?<=by `)tar(?=`-ing)",
    r"(?<=and )tar(?= takes)",
]
PROTECT_RES = [re.compile(p) for p in PROTECT]

# Ordered token map. Applied to a masked line.
ARTICLE = re.compile(
    r"\b([Aa]) (?=[*_`\"'(\[]*(?:tar(?![A-Za-z])|TAR(?![A-Za-z])|Tar(?=[A-Z])|(?:Timeline|Telemetry) Activity))"
)
RULES: list[tuple[re.Pattern[str], str]] = [
    # display phrases
    (re.compile(r"(?:Timeline|Telemetry) Activity Record \(TAR\)"), "Echo"),
    (re.compile(r"\bTAR \((?:Timeline|Telemetry) Activity Record\)"), "Echo"),
    (re.compile(r"\btar \((?:Timeline|Telemetry) Activity Record\)"), "echo"),
    (re.compile(r"(?:Timeline|Telemetry) Activity Record"), "Echo activity record"),
    # CamelCase identifiers: TarDatabase, kTarQuery, YuzuTarProcEtw-, getTarProcessTree.
    # The uppercase lookahead keeps Target/Targeting out.
    (re.compile(r"(?<![A-Z])Tar(?=[A-Z])"), "Echo"),
    (re.compile(r"(?<![A-Za-z0-9_])kTar(?![A-Za-z])"), "kEcho"),
    (re.compile(r"(?<![A-Za-z])tar(?=[A-Z])"), "echo"),
    # snake_case: tar_config, list_tar_x, not_tar
    (re.compile(r"(?<![A-Za-z])tar_"), "echo_"),
    (re.compile(r"(?<=_)tar(?![A-Za-z0-9])"), "echo"),
    # SCREAMING: TAR_PRESENT
    (re.compile(r"(?<![A-Za-z0-9])TAR(?=_)"), "ECHO"),
    (re.compile(r"(?<=_)TAR(?![A-Za-z0-9])"), "ECHO"),
]
_BARE_TAR_UPPER = re.compile(r"(?<![A-Za-z0-9_])TAR(?![A-Za-z0-9_])")
_BARE_TAR_LOWER = re.compile(r"(?<![A-Za-z0-9_])tar(?![A-Za-z0-9_])")
_LOG_PREFIX = re.compile(r"(?<![A-Za-z0-9_])TAR:")
_CODE_EXT = {
    "cpp", "hpp", "h", "mm", "c", "cc", "py", "js", "mjs", "sh", "build", "erl", "hrl",
    "ps1", "cs", "iss", "cmake", "txt",
}


def _stash(spans: list[str]):
    def fn(m: re.Match[str]) -> str:
        spans.append(m.group(0))
        return f"\x01{len(spans) - 1}\x02"

    return fn


def transform_line(line: str, ext: str) -> str:
    """Apply the token map to one line. `ext` is the file extension, no dot."""
    low = line.lower()
    if "tar" not in low and "activity record" not in low and "echo" not in low:
        return line
    spans: list[str] = []
    out = line
    for rx in PROTECT_RES:
        out = rx.sub(_stash(spans), out)
    out = ARTICLE.sub(lambda m: m.group(1) + "n ", out)
    for rx, repl in RULES:
        out = rx.sub(repl, out)
    # `TAR:` is a log prefix in code, a display-name prefix ("TAR: SQL Query") elsewhere.
    if ext in _CODE_EXT:
        out = _LOG_PREFIX.sub("ECHO:", out)
    else:
        out = re.sub(r"(?<![A-Za-z0-9_])TAR:(?= [A-Z])", "Echo:", out)
        out = _LOG_PREFIX.sub("ECHO:", out)
    out = _BARE_TAR_UPPER.sub("Echo", out)
    out = _BARE_TAR_LOWER.sub("echo", out)
    while _SENTINEL.search(out):
        out = _SENTINEL.sub(lambda m: spans[int(m.group(1))], out)
    return out


def transform_text(text: str, ext: str) -> tuple[str, list[tuple[int, str, str]]]:
    lines = text.split("\n")
    edits: list[tuple[int, str, str]] = []
    for i, ln in enumerate(lines):
        new = transform_line(ln, ext)
        if new != ln:
            edits.append((i + 1, ln, new))
            lines[i] = new
    return "\n".join(lines), edits


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------


def repo_root() -> Path:
    return Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], encoding="utf-8").strip())


def tracked_files(root: Path) -> list[str]:
    raw = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"])
    return [p for p in raw.decode("utf-8", "surrogateescape").split("\0") if p]


APPLIED_MARKER = "agents/core/include/yuzu/agent/echo_db_legacy_rename.hpp"


def run(dry_run: bool) -> int:
    root = repo_root()
    if (root / APPLIED_MARKER).exists():
        print(f"{APPLIED_MARKER} exists: the rename is already applied and hand-edited; nothing to do")
        print("0 edits, 0 renames")
        return 0
    files = [f for f in tracked_files(root) if not is_verbatim(f)]

    # Phase A: path renames.
    renames = [(f, rename_path(f)) for f in files if rename_path(f) != f]
    for old, new in renames:
        print(f"RENAME {old} -> {new}")
    if not dry_run:
        for old, new in renames:
            dest = root / new
            dest.parent.mkdir(parents=True, exist_ok=True)
            subprocess.check_call(["git", "-C", str(root), "mv", old, new])
        for old, _ in renames:  # drop emptied directories
            d = (root / old).parent
            while d != root and d.is_dir() and not any(d.iterdir()):
                d.rmdir()
                d = d.parent

    # Phase B: content.
    edit_count = 0
    renamed = dict(renames)
    for f in files:
        cur = renamed.get(f, f)
        path = root / (f if dry_run else cur)
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if b"\0" in data[:8192]:
            continue
        text = data.decode("utf-8", "surrogateescape")
        new_text, edits = transform_text(text, f.rsplit(".", 1)[-1] if "." in f.rsplit("/", 1)[-1] else "")
        if not edits:
            continue
        for lineno, before, after in edits:
            print(f"{cur}:{lineno}: {before.strip()} -> {after.strip()}")
        edit_count += len(edits)
        if not dry_run:
            path.write_bytes(new_text.encode("utf-8", "surrogateescape"))
    print(f"{edit_count} edits, {len(renames)} renames")
    return 0


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

MUST_CHANGE = [
    ('plugin_name = "tar";', 'plugin_name = "echo";', "cpp"),
    ("tar.db", "echo.db", "txt"),
    ("tar.fast", "echo.fast", "txt"),
    ("TEST_CASE(\"x\", \"[tar_power]\")", "TEST_CASE(\"x\", \"[echo_power]\")", "cpp"),
    ("TarDatabase db;", "EchoDatabase db;", "cpp"),
    ("kTarQuery", "kEchoQuery", "cpp"),
    ("kMaxTarProcOutputBytes", "kMaxEchoProcOutputBytes", "cpp"),
    ("constexpr std::string_view kTar[] = {", "constexpr std::string_view kEcho[] = {", "cpp"),
    ("YuzuTarProcEtw-", "YuzuEchoProcEtw-", "cpp"),
    ("#include \"yuzu/tar_retention_tick.hpp\"", "#include \"yuzu/echo_retention_tick.hpp\"", "cpp"),
    ("list_tar_capture_sources", "list_echo_capture_sources", "cpp"),
    ("create_result_set_from_tar_query", "create_result_set_from_echo_query", "cpp"),
    ('spdlog::warn("TAR: failed");', 'spdlog::warn("ECHO: failed");', "cpp"),
    ('displayName: "TAR: SQL Query"', 'displayName: "Echo: SQL Query"', "yaml"),
    ("/fragments/tar/process-tree", "/fragments/echo/process-tree", "md"),
    ("see changelog.d/2026-10-21-tar-timeline-render.added.md", "see changelog.d/2026-10-21-echo-timeline-render.added.md", "md"),
    ("governance.d/tar-registry-live-source.KttYnZ.jsonl", "governance.d/echo-registry-live-source.KttYnZ.jsonl", "md"),
    ("docs/plans/feat-tar-15f-chrome-ir-e2e-2026-07-01.md", "docs/plans/feat-echo-15f-chrome-ir-e2e-2026-07-01.md", "md"),
    ("tar-timeline", "echo-timeline", "md"),
    (".tar-tree-node{margin:0}", ".echo-tree-node{margin:0}", "html"),
    ("/api/v1/result-sets/from-tar-query", "/api/v1/result-sets/from-echo-query", "md"),
    ("meson test --suite tar --suite proto", "meson test --suite echo --suite proto", "md"),
    ("plugin: tar", "plugin: echo", "yaml"),
    ("crossplatform.tar.query", "crossplatform.echo.query", "yaml"),
    ("yuzu_tar_tests", "yuzu_echo_tests", "build"),
    ("TAR_PRESENT", "ECHO_PRESENT", "py"),
    ("Dashboard TAR", "Dashboard Echo", "md"),
    ("com.yuzu.tar.removable.diskarb", "com.yuzu.echo.removable.diskarb", "mm"),
    ("yuzu.plugin.tar.db_corruption_total", "yuzu.plugin.echo.db_corruption_total", "cpp"),
    ("namespace yuzu::tar {", "namespace yuzu::echo {", "cpp"),
    ("applyTarTreeFilters(tarTreeState)", "applyEchoTreeFilters(echoTreeState)", "js"),
    ("a TAR capture source", "an Echo capture source", "md"),
    ("denied on a **TAR frame's picker**", "denied on an **Echo frame's picker**", "md"),
    ("TAR (Timeline Activity Record) plugin", "Echo plugin", "md"),
    ("Timeline Activity Record -- continuous", "Echo activity record -- continuous", "md"),
    ("[pg][server][tar][purge]", "[pg][server][echo][purge]", "cpp"),
    ("not_tar.dylib", "not_echo.dylib", "py"),
    ("pre-TAR this boot", "pre-Echo this boot", "md"),
    ("--plugin tar --action fleet_snapshot", "--plugin echo --action fleet_snapshot", "md"),
    ("--suite tar --suite proto", "--suite echo --suite proto", "yml"),
]

NEVER_CHANGE = [
    "yuzu-linux-x64.tar.gz",
    "tar -xzf archive.tar.gz",
    "tar xf foo",
    "tar czf out.tgz dir",
    "kTarget",
    "--target",
    "targeting",
    "restart",
    "startup",
    "StarTable",
    "modern-tar",
    "bsdtar",
    "tar.exe",
    "apt-get install -y curl zip unzip tar git",
    "tar | grep -q needle",
    "back up Postgres by `tar`-ing the postgres-data volume",
    'echo "x"',
    "icmp echo reply",
    "journal",
    "-journal",
    "idx_tar_events_ts",
    "tar_events",
    "tar_events_present",
    "feat/wave7-pr72a-forensics-tar-usage",
    "app|tar|1.35+dfsg-3.1|Janos Lenart <ocsi@debian.org>|-|-|-",
    "Alex Myczko <tar@debian.org>",
    "Echo was named TAR before 2026-10",
    "tarball",
    "node.tar.xz",
]


def self_test() -> int:
    bad = 0
    for before, want, ext in MUST_CHANGE:
        got = transform_line(before, ext)
        if got != want:
            print(f"FAIL must-change: {before!r} -> {got!r}, wanted {want!r}")
            bad += 1
        again = transform_line(got, ext)
        if again != got:
            print(f"FAIL second apply not a no-op: {got!r} -> {again!r}")
            bad += 1
    for line in NEVER_CHANGE:
        got = transform_line(line, "txt")
        if got != line:
            print(f"FAIL never-change: {line!r} -> {got!r}")
            bad += 1
    for comp, want in [
        ("tar", "echo"),
        ("tar_db.cpp", "echo_db.cpp"),
        ("test_tar_store.cpp", "test_echo_store.cpp"),
        ("yuzu-tar-timeline.js", "yuzu-echo-timeline.js"),
        ("0015-tar-arp-dns-capture-sources.md", "0015-echo-arp-dns-capture-sources.md"),
        ("win_tar_db_owner_probe.hpp", "win_echo_db_owner_probe.hpp"),
        ("yuzu-linux-x64.tar.gz", "yuzu-linux-x64.tar.gz"),
        ("restart.sh", "restart.sh"),
        ("Start-PinnedRunner.ps1", "Start-PinnedRunner.ps1"),
        ("target", "target"),
    ]:
        got = rename_component(comp)
        if got != want:
            print(f"FAIL rename_component: {comp!r} -> {got!r}, wanted {want!r}")
            bad += 1
    print("self-test: FAIL" if bad else "self-test: ok")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true", help="print every rename and edit; change nothing")
    ap.add_argument("--self-test", action="store_true", help="run the fixture table and exit")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    os.chdir(repo_root())
    return run(args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
