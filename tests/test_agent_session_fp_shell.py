#!/usr/bin/env python3
"""Runs scripts/lib/agent-session-fp.sh against synthetic agent and server logs (F50): the
fingerprint join must work on LF and CRLF logs (a native Windows server/agent writes CRLF), fall
back to a pre-F50 agent's session=<id>, tolerate a missing server log, and FAIL LOUDLY when no
SHA-256 tool exists. Skips when bash is unavailable."""
import hashlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASH = shutil.which("bash") or "bash"
LIB = (ROOT / "scripts/lib/agent-session-fp.sh").as_posix()
SID = "gw-session-0123456789abcdef0123456789abcdef"
OTHER = "gw-session-ffffffffffffffffffffffffffffffff"
FP = hashlib.sha256(SID.encode()).hexdigest()[:8]


def bash(script, env=None):
    return subprocess.run([BASH, "-c", f". '{LIB}'; {script}"], capture_output=True, text=True,
                          env=env, timeout=60)


def main():
    if shutil.which("bash") is None or not shutil.which("sha256sum") and not shutil.which("shasum"):
        print("SKIPPED: bash or a sha256 tool is not available on this runner; the join was NOT tested")
        return 77
    if sys.platform.startswith("win"):
        print("SKIPPED: Windows runner; the shell join was NOT tested here")
        return 77
    bad = []
    with tempfile.TemporaryDirectory(prefix="yuzu_test_fp_") as d:
        d = pathlib.Path(d)
        for eol in ("\n", "\r\n"):
            tag = "crlf" if eol == "\r\n" else "lf"
            agent = d / f"agent-{tag}.log"
            server = d / f"server-{tag}.log"
            agent.write_bytes((f"[info] Registered with server (session_fp={FP}, enrollment=enrolled){eol}").encode())
            server.write_bytes((f"[info] [gateway] ProxyRegister succeeded: agent=a1, session={OTHER}{eol}"
                                f"[info] [gateway] ProxyRegister succeeded: agent=a2, session={SID}{eol}").encode())
            r = bash(f"resolve_agent_session '{agent.as_posix()}' '{server.as_posix()}'")
            if r.stdout.strip() != SID:
                bad.append(f"{tag}: expected {SID}, got {r.stdout!r} {r.stderr!r}")
            if bash(f"agent_session_fp '{agent.as_posix()}'").stdout.strip() != FP:
                bad.append(f"{tag}: agent_session_fp wrong")
        # missing server log: unknown, rc 0 (no abort under set -e)
        r = bash(f"set -e; resolve_agent_session '{(d/'agent-lf.log').as_posix()}' '{(d/'nope.log').as_posix()}'")
        if r.returncode != 0 or r.stdout.strip() != "unknown":
            bad.append(f"missing server log: {r.returncode} {r.stdout!r}")
        # legacy agent
        legacy = d / "agent-old.log"
        legacy.write_bytes(f"Registered with server (session={SID}, enrollment=enrolled)\r\n".encode())  # tripwire-allow: legacy-agent fixture
        r = bash(f"resolve_agent_session '{legacy.as_posix()}' '{(d/'server-lf.log').as_posix()}'")
        if r.stdout.strip() != SID:
            bad.append(f"legacy: {r.stdout!r}")
        # no hash tool: loud failure. PATH holds only a dir with the few tools the lib needs.
        tools = d / "bin"
        tools.mkdir()
        for t in ("tr", "grep", "sed", "cut", "tail", "cat"):
            src = shutil.which(t)
            if src:
                os.symlink(src, tools / t)
        env = dict(os.environ, PATH=str(tools))
        r = bash(f"printf %s x | _sha256_hex8", env=env)
        if r.returncode == 0 or "cannot join" not in r.stderr:
            bad.append(f"no-hash-tool must fail loudly: rc={r.returncode} err={r.stderr!r}")
    for b in bad:
        print("FAIL:", b)
    if bad:
        return 1
    print("OK: session_fp join works on LF and CRLF logs, falls back, and fails loudly without a hash tool")
    return 0


if __name__ == "__main__":
    sys.exit(main())
