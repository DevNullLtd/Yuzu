#!/usr/bin/env python3
"""Runs scripts/lib/agent-session-fp.sh against synthetic agent and server logs (#8159): the
fingerprint join must work on LF and CRLF logs (a native Windows server/agent writes CRLF) and on
logs holding NUL bytes, stay fast on a 20k-line server log, exercise both hash-tool branches
(sha256sum, shasum -a 256), and FAIL LOUDLY (non-zero + message, never "unknown") when the Registered
line has no session_fp, the server log is missing, the fingerprint matches nothing, or no hash tool
exists. Skips (exit 77) when bash or a sha256 tool is unavailable."""
import hashlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASH = shutil.which("bash") or "bash"
LIB = pathlib.Path(os.environ.get("YUZU_FP_LIB") or (ROOT / "scripts/lib/agent-session-fp.sh")).as_posix()
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
        # NUL byte in a log: without grep -a the match is "binary file matches" and the join reads unknown
        nul_agent = d / "agent-nul.log"
        nul_server = d / "server-nul.log"
        nul_agent.write_bytes(b"garbage\x00\x00 bytes\n" + f"Registered with server (session_fp={FP}, enrollment=enrolled)\n".encode())
        nul_server.write_bytes(b"\x00junk\n" + f"ProxyRegister succeeded: agent=a2, session={SID}\n".encode())
        r = bash(f"resolve_agent_session '{nul_agent.as_posix()}' '{nul_server.as_posix()}'")
        if r.stdout.strip() != SID:
            bad.append(f"NUL-bearing logs: expected {SID}, got {r.stdout!r}")
        # missing server log: a loud, non-zero failure (never "unknown"), and no abort of a caller
        r = bash(f"resolve_agent_session '{(d/'agent-lf.log').as_posix()}' '{(d/'nope.log').as_posix()}'")
        if r.returncode != 2 or "not readable" not in r.stderr:
            bad.append(f"missing server log must fail loudly: {r.returncode} {r.stderr!r}")
        # no session_fp on the Registered line (an id-bearing line is NOT read): loud failure
        nofp = d / "agent-nofp.log"
        nofp.write_bytes(f"Registered with server (enrollment=enrolled) id={SID}\n".encode())
        r = bash(f"resolve_agent_session '{nofp.as_posix()}' '{(d/'server-lf.log').as_posix()}'")
        if r.returncode != 1 or "no session_fp" not in r.stderr or r.stdout.strip():
            bad.append(f"no session_fp must fail loudly: rc={r.returncode} out={r.stdout!r} err={r.stderr!r}")
        # a fingerprint that matches no server-side session: loud, rc 2
        nomatch = d / "agent-nomatch.log"
        nomatch.write_bytes(b"Registered with server (session_fp=00000000, enrollment=enrolled)\n")
        r = bash(f"resolve_agent_session '{nomatch.as_posix()}' '{(d/'server-lf.log').as_posix()}'")
        if r.returncode != 2 or r.stdout.strip():
            bad.append(f"unmatched fingerprint must fail: rc={r.returncode} out={r.stdout!r}")
        # hash-tool branches: force each with a PATH of symlinked basics plus ONE hash tool
        basics = ("tr", "grep", "sed", "cut", "tail", "cat", "awk", "head", "sort")
        real_sha = shutil.which("sha256sum")
        def path_with(name, tool_body):
            t = d / f"bin-{name}"
            t.mkdir()
            for b in basics:
                src = shutil.which(b)
                if src:
                    os.symlink(src, t / b)
            if tool_body is not None:
                shim = t / name
                shim.write_text("#!/bin/sh\n" + tool_body)
                shim.chmod(0o755)
            return dict(os.environ, PATH=str(t))
        if real_sha:
            # sha256sum-only
            env = path_with("sha256sum", f'exec {real_sha} "$@"\n')
            r = bash("printf %s x | _sha256_hex8", env=env)
            if r.returncode != 0 or len(r.stdout.strip()) != 8:
                bad.append(f"sha256sum branch: rc={r.returncode} out={r.stdout!r} err={r.stderr!r}")
            # shasum-only (the macOS branch): the shim must be called with -a 256
            env = path_with("shasum", f'[ "$1" = "-a" ] && [ "$2" = "256" ] || exit 9\nexec {real_sha}\n')
            r = bash("printf %s x | _sha256_hex8", env=env)
            want = hashlib.sha256(b"x").hexdigest()[:8]
            if r.returncode != 0 or r.stdout.strip() != want:
                bad.append(f"shasum branch: rc={r.returncode} out={r.stdout!r} want={want}")
        # many candidate lines: one pass, bounded (the agent registered recently; 20k lines must be fast)
        big = d / "server-big.log"
        with open(big, "w") as f:
            for n in range(20000):
                f.write(f"[info] [gateway] ProxyRegister succeeded: agent=a{n}, session=gw-session-{n:032x}\n")
            f.write(f"[info] [gateway] ProxyRegister succeeded: agent=last, session={SID}\n")
        t0 = time.monotonic()
        r = bash(f"resolve_agent_session '{(d/'agent-lf.log').as_posix()}' '{big.as_posix()}'")
        if r.stdout.strip() != SID or time.monotonic() - t0 > 30:
            bad.append(f"20k-line log: {r.stdout!r} in {time.monotonic() - t0:.1f}s")
        # no hash tool: loud failure. PATH holds only the basics.
        env = path_with("none", None)
        r = bash("printf %s x | _sha256_hex8", env=env)
        if r.returncode == 0 or "cannot join" not in r.stderr:
            bad.append(f"no-hash-tool must fail loudly: rc={r.returncode} err={r.stderr!r}")
    for b in bad:
        print("FAIL:", b)
    if bad:
        return 1
    print("OK: session_fp join works (LF, CRLF, NUL, 20k lines, both hash branches) and fails loudly otherwise")
    return 0


if __name__ == "__main__":
    sys.exit(main())
