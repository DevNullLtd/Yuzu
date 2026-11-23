#!/usr/bin/env python3
"""Tripwire (#8159): the agent's "Registered with server" log line carries a session FINGERPRINT
(`session_fp=`, first 8 hex of SHA-256), never the session id, which is a bearer credential
readable through agent_logging.get_log.

Best-effort lexical gate, two checks:
  1. agents/core/src/agent.cpp logs `session_fp={}` via `session_log_fingerprint(` and never
     passes `session_id_` to that spdlog call; dex_linux_collector.cpp wraps subject/reason.
  2. No text file in the repo parses `session=` out of that agent line. Backslash continuations are
     joined, and a `session=` extractor within WINDOW lines of a "Registered with server" mention
     (a separate-line extractor included) fails. A line that carries the marker
     `tripwire-allow: <reason>` is exempt, so each exemption is visible at its own line (only the
     upgrade note quoting the old line). There is NO other `session=` read of that line.
The server-side "ProxyRegister succeeded: ... session=" line is the id's source and is not flagged.
"""
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SELF = pathlib.Path(__file__).resolve()
SKIP_DIRS = {".git", "node_modules", "vcpkg_installed",
             "scratchpad", "governance.d", ".claude", "changelog.d", "site"}
# Every top-level build* directory is skipped, not only the three per-OS names: the self-hosted
# runners build several CI jobs into sibling dirs of one checkout (build-linux-coverage,
# build-linux-clang-21-debug, ...), whose test logs and coverage reports quote the agent's
# Registered line and would fail this gate on a PR that never touched it (#8637).
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
            errs.append(f"{path}:{n}: parses/mentions session= near the agent 'Registered with server' line")
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


def skipped(rel_parts):
    """True when a repo-relative path lies in a directory this gate does not scan."""
    top = rel_parts[0] if len(rel_parts) > 1 else ""
    return (top in SKIP_DIRS or top.startswith(SKIP_PREFIX)
            or "node_modules" in rel_parts or ".git" in rel_parts)


def iter_files(root=ROOT):
    for p in root.rglob("*"):
        if not p.is_file() or p.resolve() == SELF:
            continue
        rel = p.relative_to(root)
        if skipped(rel.parts):
            continue
        try:
            if p.stat().st_size > 2_000_000:
                continue
            raw = p.read_bytes()
        except OSError:
            continue
        if b"\0" in raw[:4096]:
            continue
        yield rel.as_posix(), raw.decode("utf-8", errors="replace")


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
    for b in bad:
        assert check_text("x.sh", b), ("selftest: must fire on", b)
    # re-adding a session= read of the Registered line (a fallback) must be RED
    assert check_text("lib.sh", 'grep -a "Registered with server" "$1" | grep -aoE \'session=[^ ,)]+\''), "selftest fallback"
    assert not check_text("x.sh", "Registered with server (session_fp=ab12cd34, "), "selftest ok-fp"
    assert not check_text("x.sh", 'grep "Registered with server" x | grep session=  # tripwire-allow: reviewed example'), "selftest allow"
    assert not check_text("x.sh", "ProxyRegister succeeded: agent=a, session=b"), "selftest server line"
    # Windows-style path separators must not matter
    assert check_text("scripts\\x.sh".replace("\\", "/"), bad[0]), "selftest path"
    selftest_walk(bad[0])


def selftest_walk(bad_line):
    """#8637: another CI job's output under any top-level build* dir is not scanned, while the
    same line in a source file still is. Runs the real walk over a throwaway tree."""
    log_line = "[info] Registered with server session=0123456789abcdef\n"
    with tempfile.TemporaryDirectory(prefix="yuzu_test_session_log_walk_") as tmp:
        root = pathlib.Path(tmp)
        for rel in ("build-linux-clang-21-debug/meson-logs/ci-half-nonpg.log",
                    "build-linux-coverage/coverage-html/index.html",
                    "build-linux/meson-logs/testlog.txt",
                    "builddir/meson-logs/testlog.txt"):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(log_line)
        (root / "scripts").mkdir()
        (root / "scripts" / "x.sh").write_text(bad_line + "\n")
        # A build* name BELOW the top level is ordinary source and is still scanned.
        (root / "deploy" / "build-tools").mkdir(parents=True)
        (root / "deploy" / "build-tools" / "y.sh").write_text(bad_line + "\n")
        flagged = sorted(rel for rel, text in iter_files(root) if check_text(rel, text))
        assert flagged == ["deploy/build-tools/y.sh", "scripts/x.sh"], ("selftest walk", flagged)
    assert not skipped(("build-tools.sh",)), "selftest: a top-level FILE named build* is still scanned"


def main():
    selftest()
    errs = check_agent_cpp((ROOT / "agents/core/src/agent.cpp").read_text(errors="replace"))
    errs += check_dex_emit((ROOT / "agents/core/src/dex_linux_collector.cpp").read_text(errors="replace"))
    for rel, text in iter_files():
        errs += check_text(rel, text)
    for e in errs:
        print("FAIL:", e)
    if errs:
        return 1
    print("OK: agent session id is not logged or parsed from the Registered line")
    return 0


if __name__ == "__main__":
    sys.exit(main())
