#!/usr/bin/env python3
"""Tripwire (F50): the agent's "Registered with server" log line carries a session FINGERPRINT
(`session_fp=`, first 8 hex of SHA-256), never the session id, which is a bearer credential
readable through agent_logging.get_log.

Best-effort lexical gate, two checks:
  1. agents/core/src/agent.cpp logs `session_fp={}` with `session_log_fingerprint(` and never
     `session_id_` as an argument of that spdlog call.
  2. No script, test, tool, deploy file or workflow parses `session=` out of that agent line:
     a `Registered with server` line that also mentions `session=` (not `session_fp=`) fails.
     The server-side "ProxyRegister succeeded: ... session=" line is the id's source.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SELF = pathlib.Path(__file__).resolve()
# The upgrade note quotes the OLD line on purpose, to tell operators what changed.
EXEMPT = {"docs/user-manual/upgrading.md"}
SCAN_DIRS = ("agents", "server", "scripts", "tests", "tools", "deploy", ".github", "docs")
OLD_PARSE = re.compile(r"Registered with server[^\n]*\bsession=")


def check_agent_cpp(text):
    errs = []
    m = re.search(r'spdlog::info\(\s*"Registered with server[^;]*;', text)
    if not m:
        return ["agent.cpp: the 'Registered with server' spdlog call was not found"]
    call = m.group(0)
    if "session_fp={}" not in call or "session_log_fingerprint(" not in call:
        errs.append("agent.cpp: the Registered line must log session_fp via session_log_fingerprint(")
    if re.search(r"(?<!fingerprint\()\bsession_id_\b", call.replace("session_log_fingerprint(session_id_)", "")):
        errs.append("agent.cpp: the Registered line must not pass session_id_ to the logger")
    return errs


def check_dex_emit(text):
    """F59: the DEX observed-line wraps subject and reason (journal-sourced) in log_key_token."""
    m = re.search(r'spdlog::info\("dex_observer\(linux\): observed[^;]*;', text)
    if not m:
        return ["dex_linux_collector.cpp: the observed spdlog call was not found"]
    c = m.group(0)
    if "log_key_token(obs.subject)" not in c or "log_key_token(obs.reason)" not in c:
        return ["dex_linux_collector.cpp: subject and reason must go through log_key_token"]
    return []


def check_consumers(files):
    errs = []
    for path, text in files:
        for n, line in enumerate(text.splitlines(), 1):
            if OLD_PARSE.search(line):
                errs.append(f"{path}:{n}: parses session= from the agent 'Registered with server' line")
    return errs


def main():
    errs = check_agent_cpp((ROOT / "agents/core/src/agent.cpp").read_text(errors="replace"))
    errs += check_dex_emit((ROOT / "agents/core/src/dex_linux_collector.cpp").read_text(errors="replace"))
    files = []
    for d in SCAN_DIRS:
        base = ROOT / d
        if not base.is_dir():
            continue
        for p in base.rglob("*"):
            if p.is_file() and p.resolve() != SELF and str(p.relative_to(ROOT)) not in EXEMPT and p.suffix in {".sh", ".py", ".yml", ".yaml", ".md", ".ps1", ".js", ".mjs", ".cpp", ".hpp"}:
                files.append((p.relative_to(ROOT), p.read_text(errors="replace")))
    errs += check_consumers(files)
    # self-test: the detector must fire on the old shape
    assert check_consumers([("x", 'sed -n "s/.*Registered with server (session=\\(.*\\),.*/\\1/p"')]), "selftest"
    assert not check_consumers([("x", "Registered with server (session_fp=ab12cd34, ")]), "selftest"
    for e in errs:
        print("FAIL:", e)
    if errs:
        return 1
    print("OK: agent session id is not logged or parsed from the Registered line")
    return 0


if __name__ == "__main__":
    sys.exit(main())
