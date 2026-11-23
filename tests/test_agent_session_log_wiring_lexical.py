#!/usr/bin/env python3
"""Tripwire (#8159): the agent's "Registered with server" log line carries a session FINGERPRINT
(`session_fp=`, first 8 hex of SHA-256), never the session id, which is a bearer credential
readable through agent_logging.get_log.

Best-effort lexical gate, two checks:
  1. agents/core/src/agent.cpp logs `session_fp={}` via `session_log_fingerprint(` and never
     passes `session_id_` to that spdlog call; dex_linux_collector.cpp wraps subject/reason.
  2. No scanned text file parses `session=` out of that agent line (scanned: the whole checkout
     except the top-level SKIP_DIRS (including the `vcpkg` clone) and build* directories,
     rebar3's `gateway/_build*`, `node_modules` and `.git` at any depth, files over 2 MB, binary
     files (a NUL in the first 4 KiB), unreadable paths, and this file; directory symlinks are not
     followed). Backslash continuations are joined, and a `session=` extractor within WINDOW lines
     of a "Registered with server" mention
     (a separate-line extractor included) fails. A line that carries the marker
     `tripwire-allow: <reason>` is exempt, so each exemption is visible at its own line (only the
     upgrade note quoting the old line). There is NO other `session=` read of that line.
The server-side "ProxyRegister succeeded: ... session=" line is the id's source and is not flagged.
"""
import os
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SELF = pathlib.Path(__file__).resolve()
SKIP_DIRS = {".git", "node_modules", "vcpkg_installed", "vcpkg",
             "scratchpad", "governance.d", ".claude", "changelog.d", "site"}
# Also pruned: the untracked trees the CI runners keep in the checkout (the vcpkg clone at vcpkg/
# above, and rebar3's gateway/_build* output, gitignored there: ~110k of the ~120k files on a Big
# Tam workspace, #8637), so the walk stays far inside the meson timeout under load. The rebar3
# prune is anchored to gateway/ only, so a `_build*` directory anywhere else is still scanned.
SKIP_ANY_DEPTH = ("node_modules", ".git")
REBAR3_PARENT, REBAR3_PREFIX = "gateway", "_build"
# Every top-level build* directory is skipped, not only the three per-OS names: the self-hosted
# runners build several CI jobs into sibling dirs of one checkout (build-linux-coverage,
# build-linux-clang-21-debug, ...), whose test logs and coverage reports quote the agent's
# Registered line and would fail this gate on a PR that never touched it (#8637). Top-level FILES
# named build* are still scanned. Every skip here rests on one premise: no TRACKED file lies in a
# skipped directory, so only build output and third-party clones are skipped, never source.
# Nothing checks it yet (#8643); do not add tracked files under any of these names.
SKIP_PREFIX = "build"
WINDOW = 25  # extractors may sit well after the grep that fetches the line
MENTION = re.compile(r"Registered\s+with\s+server")
EXTRACT = re.compile(r"\bsession\\?=(?!fp)")
ALLOW = "tripwire-allow:"


def join_continuations(text):
    """Return (line_no, joined_line) pairs with backslash-newline continuations folded."""
    out, buf, start = [], "", 1
    for n, line in enumerate(text.splitlines(), 1):
        if not buf:
            start = n
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        out.append((start, buf + line))
        buf = ""
    if buf:
        out.append((start, buf))
    return out


def check_text(path, text):
    errs = []
    lines = join_continuations(text)
    mention_at = [i for i, (_, l) in enumerate(lines) if MENTION.search(l)]
    for i, (n, l) in enumerate(lines):
        if not EXTRACT.search(l) or ALLOW in l or ("ProxyRegister" in l and not MENTION.search(l)):
            continue
        if any(abs(i - m) <= WINDOW for m in mention_at):
            # Worded so the message does not itself match MENTION + EXTRACT: a log at the top of the
            # checkout that captured one failure (sanitizer-asan.log, a `meson test | tee`) would
            # otherwise keep this gate red on every later run in that workspace.
            errs.append(f"{path}:{n}: reads the session id near the agent's Registered line "
                        "(log and join on session_fp instead)")
    return errs


def check_agent_cpp(text):
    errs = []
    m = re.search(r'spdlog::info\(\s*"Registered with server[^;]*;', text)
    if not m:
        return ["agent.cpp: the 'Registered with server' spdlog call was not found"]
    call = m.group(0)
    if "session_fp={}" not in call or not re.search(r"session_log_fingerprint\(\s*session_id_\s*\)", call):
        errs.append("agent.cpp: the Registered line must log session_fp via session_log_fingerprint(session_id_) "
                    "(the argument IS the session id: a constant or another field would break every shell join)")
    if re.search(r"\bsession_id_\b", call.replace("session_log_fingerprint(session_id_)", "")):
        errs.append("agent.cpp: the Registered line must not pass session_id_ to the logger")
    return errs


def check_dex_emit(text):
    m = re.search(r'spdlog::info\("dex_observer\(linux\): observed[^;]*;', text)
    if not m:
        return ["dex_linux_collector.cpp: the observed spdlog call was not found"]
    c = m.group(0)
    if "log_key_token(obs.subject)" not in c or "log_key_token(obs.reason)" not in c:
        return ["dex_linux_collector.cpp: subject and reason must go through log_key_token"]
    return []


def skipped_dir(rel_parts):
    """True for a repo-relative DIRECTORY this gate does not descend into."""
    name = rel_parts[-1]
    if len(rel_parts) == 1 and (name in SKIP_DIRS or name.startswith(SKIP_PREFIX)):
        return True
    if len(rel_parts) == 2 and rel_parts[0] == REBAR3_PARENT and name.startswith(REBAR3_PREFIX):
        return True
    return name in SKIP_ANY_DEPTH


def skipped(rel_parts):
    """True when a repo-relative FILE lies in a skipped directory (or is a `.git` gitfile)."""
    return any(skipped_dir(rel_parts[:i]) for i in range(1, len(rel_parts))) or rel_parts[-1] == ".git"


def iter_files(root=ROOT, visited=None):
    # os.walk with pruning, not rglob: a skipped tree is never listed, so another job deleting or
    # writing its build output mid-scan cannot crash or slow this gate (#8637). Like rglob, it does
    # not follow directory symlinks, and a directory it cannot list is passed over. `visited`, when
    # given, collects every directory listed (the selftest uses it to pin the pruning).
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = pathlib.Path(dirpath).relative_to(root).parts
        if visited is not None:
            visited.append("/".join(rel_dir))
        dirnames[:] = [d for d in dirnames if not skipped_dir(rel_dir + (d,))]
        for name in filenames:
            rel = rel_dir + (name,)
            p = pathlib.Path(dirpath, name)
            if skipped(rel) or not p.is_file() or p.resolve() == SELF:
                continue
            try:
                if p.stat().st_size > 2_000_000:
                    continue
                raw = p.read_bytes()
            except OSError:
                continue
            if b"\0" in raw[:4096]:
                continue
            yield "/".join(rel), raw.decode("utf-8", errors="replace")


def selftest():
    good_call = 'spdlog::info("Registered with server (session_fp={}, enrollment={})", session_log_fingerprint(session_id_), e);'
    assert not check_agent_cpp(good_call), "selftest: the real call shape must pass"
    for mutant in (good_call.replace("session_id_)", '"constant")'),
                   good_call.replace("session_id_)", "agent_id_)"),
                   good_call.replace("session_log_fingerprint(session_id_)", "session_id_")):
        assert check_agent_cpp(mutant), ("selftest: must fire on", mutant)
    bad = [
        'sed -n "s/.*Registered with server (session=\\(.*\\),.*/\\1/p"',
        'grep "Registered with server" "$log" | \\\n    python3 -c "re.findall(r\'session=[^ ]+\')"',
        'grep "Registered with server" x > $t\nm=$(grep -oE "session=[^ ,)]+" $t)',
        'grep "Registered  with   server" x | sed "s/.*session=//"',
        'grep "Registered with server" x | sed s/session\\=//',
        'grep "Registered with server" x > $t\n' + "echo\n" * 15 + 'v=$(grep -oE "session=[^ ]+" $t)',
    ]
    # Assert messages name the case by index and never quote it, and no assert line carries a
    # matching literal: a failing selftest's traceback, teed to a top-level log, must not re-trip
    # this gate the way the old FAIL message did.
    for i, b in enumerate(bad):
        assert check_text("x.sh", b), f"selftest: must fire on bad[{i}]"
    # re-adding a session= read of the Registered line (a fallback) must be RED
    fallback = 'grep -a "Registered with server" "$1" | grep -aoE \'session=[^ ,)]+\''
    assert check_text("lib.sh", fallback), "selftest fallback"
    assert not check_text("x.sh", "Registered with server (session_fp=ab12cd34, "), "selftest ok-fp"
    assert not check_text("x.sh", 'grep "Registered with server" x | grep session=  # tripwire-allow: reviewed example'), "selftest allow"
    assert not check_text("x.sh", "ProxyRegister succeeded: agent=a, session=b"), "selftest server line"
    # Windows-style path separators must not matter
    assert check_text("scripts\\x.sh".replace("\\", "/"), bad[0]), "selftest path"
    # The gate's own FAIL line, captured in a top-level log, must not trip the gate on the next run.
    hit = check_text("x.sh", bad[0])
    assert hit and not check_text("x.log", "FAIL: " + hit[0]), "selftest: the FAIL message self-matches"
    selftest_walk(bad[0])


def selftest_walk(bad_line):
    """#8637: another CI job's output under any top-level build* dir is not scanned, while the
    same line in a source file still is. Runs the real walk over a throwaway tree."""
    log_line = "[info] Registered with server session=0123456789abcdef\n"
    with tempfile.TemporaryDirectory(prefix="yuzu_test_session_log_walk_") as tmp:
        root = pathlib.Path(tmp)
        skipped_trees = ("build-linux-clang-21-debug", "build-linux-coverage", "build-linux",
                         "builddir", "vcpkg", "gateway/_build", "gateway/_build_eunit_3")
        for rel in ("build-linux-clang-21-debug/meson-logs/ci-half-nonpg.log",
                    "build-linux-coverage/coverage-html/index.html",
                    "build-linux/meson-logs/testlog.txt",
                    "builddir/meson-logs/testlog.txt",
                    "vcpkg/ports/x/log.txt",
                    "gateway/_build/test/logs/ct.log",
                    "gateway/_build_eunit_3/x.log"):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(log_line)
        (root / "scripts").mkdir()
        (root / "scripts" / "x.sh").write_text(bad_line + "\n")
        # Still scanned: a build* name BELOW the top level, and top-level dirs the prefix must not
        # reach (a widened prefix such as "b", or a case-insensitive match, would skip these).
        # Every top-level name in this tree must stay distinct after case-folding (a bare `build/`
        # would merge with `Build/` on NTFS/APFS and break this assertion on Windows/macOS only).
        # The rebar3 prune is anchored to gateway/: a `_build*` directory anywhere else is source.
        still_scanned = ["Build/z.sh", "_build/z.sh", "bin/z.sh", "deploy/build-tools/y.sh",
                         "gateway/apps/_build_helpers/z.sh", "src/_build_helpers/z.sh"]
        for rel in still_scanned:
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(bad_line + "\n")
        visited = []
        flagged = sorted(rel for rel, text in iter_files(root, visited) if check_text(rel, text))
        assert flagged == sorted(still_scanned + ["scripts/x.sh"]), ("selftest walk", flagged)
        # Pruned, not just filtered: no skipped tree is ever listed (#8637: another job may be
        # deleting it mid-scan, and listing it costs time against the meson timeout).
        entered = [v for v in visited if any(v == t or v.startswith(t + "/") for t in skipped_trees)]
        assert not entered, ("selftest: walk entered skipped trees", entered)
    assert not skipped(("build-tools.sh",)), "selftest: a top-level FILE named build* is still scanned"


def main():
    selftest()
    errs = check_agent_cpp((ROOT / "agents/core/src/agent.cpp").read_text(errors="replace"))
    errs += check_dex_emit((ROOT / "agents/core/src/dex_linux_collector.cpp").read_text(errors="replace"))
    for rel, text in iter_files():
        errs += check_text(rel, text)
    if hasattr(sys.stdout, "reconfigure"):
        # A non-UTF-8 file name must not turn the FAIL listing into a traceback that hides the rest.
        sys.stdout.reconfigure(errors="backslashreplace")
    for e in errs:
        print("FAIL:", e)
    if errs:
        return 1
    print("OK: agent session id is not logged or parsed from the Registered line")
    return 0


if __name__ == "__main__":
    sys.exit(main())
