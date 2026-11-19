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
        # the cap bounds the cost but must still reach a session that is NOT the very last one
        # (kills "cap 200 -> 5"): the target is followed by 50 other distinct sessions
        deep = d / "server-deep.log"
        with open(deep, "w") as f:
            f.write(f"ProxyRegister succeeded: agent=t, session={SID}\n")
            for n in range(50):
                f.write(f"ProxyRegister succeeded: agent=o{n}, session=gw-session-other-{n:04d}\n")
        r = bash(f"resolve_agent_session '{(d/'agent-lf.log').as_posix()}' '{deep.as_posix()}'")
        if r.stdout.strip() != SID:
            bad.append(f"target 50 sessions from the end must be found: {r.stdout!r} {r.stderr!r}")
        # the candidate list is DISTINCT sessions (kills "drop the awk filter"): the target once, then
        # 300 repeats of one other session; without de-duplication the cap window is all repeats
        dup = d / "server-dup.log"
        with open(dup, "w") as f:
            f.write(f"ProxyRegister succeeded: agent=t, session={SID}\n")
            for _ in range(300):
                f.write("ProxyRegister succeeded: agent=o, session=gw-session-repeat\n")
        r = bash(f"resolve_agent_session '{(d/'agent-lf.log').as_posix()}' '{dup.as_posix()}'")
        if r.stdout.strip() != SID:
            bad.append(f"repeats must not crowd out a distinct session: {r.stdout!r} {r.stderr!r}")
        # LAST match wins (kills "last -> first"): two different sessions sharing one 8-hex fingerprint
        seen = {}
        n = 0
        while True:
            cand = f"gw-session-collide-{n}"
            h = hashlib.sha256(cand.encode()).hexdigest()[:8]
            if h in seen:
                first, second, cfp = seen[h], cand, h
                break
            seen[h] = cand
            n += 1
        coll_agent = d / "agent-coll.log"
        coll_agent.write_bytes(f"Registered with server (session_fp={cfp}, enrollment=enrolled)\n".encode())
        coll_server = d / "server-coll.log"
        coll_server.write_text(f"ProxyRegister succeeded: agent=a, session={first}\n"
                               f"ProxyRegister succeeded: agent=b, session={second}\n")
        r = bash(f"resolve_agent_session '{coll_agent.as_posix()}' '{coll_server.as_posix()}'")
        if r.stdout.strip() != second:
            bad.append(f"the LAST matching session must win: want {second}, got {r.stdout!r}")
        # no hash tool, end to end through resolve_agent_session: rc 127 and the message, never a
        # silent rc 2 (kills "drop || return 127")
        env127 = path_with("none-e2e", None)
        r = bash(f"resolve_agent_session '{(d/'agent-lf.log').as_posix()}' '{(d/'server-lf.log').as_posix()}'", env=env127)
        if r.returncode != 127 or "cannot join" not in r.stderr:
            bad.append(f"no hash tool via resolve_agent_session: rc={r.returncode} err={r.stderr!r}")
        # no hash tool: loud failure. PATH holds only the basics.
        env = path_with("none", None)
        r = bash("printf %s x | _sha256_hex8", env=env)
        if r.returncode == 0 or "cannot join" not in r.stderr:
            bad.append(f"no-hash-tool must fail loudly: rc={r.returncode} err={r.stderr!r}")
        # last-occurrence recency (kills "awk '!seen[$0]++'" first-occurrence): the target registered
        # first and AGAIN last, with 250 other distinct sessions between; a first-occurrence filter
        # leaves it outside the 200-candidate window
        rec = d / "server-recent.log"
        with open(rec, "w") as f:
            f.write(f"ProxyRegister succeeded: agent=t, session={SID}\n")
            for n in range(250):
                f.write(f"ProxyRegister succeeded: agent=o{n}, session=gw-session-mid-{n:04d}\n")
            f.write(f"ProxyRegister succeeded: agent=t, session={SID}\n")
        r = bash(f"resolve_agent_session '{(d/'agent-lf.log').as_posix()}' '{rec.as_posix()}'")
        if r.stdout.strip() != SID:
            bad.append(f"a session that re-registered recently must stay in the recent window: {r.stdout!r}")
        # the HA scripts' route-table join (route_session_for_fp): exactly ONE non-empty row, else rc 1
        # with a message and NO stdout (zero rows, many rows, a failed query, a bad fingerprint)
        cases = [
            ("one", "psql_q() { printf '%s\\n' '" + SID + "'; }", 0, SID),
            ("one-crlf", "psql_q() { printf '%s\\r\\n' '" + SID + "'; }", 0, SID),
            ("zero", "psql_q() { :; }", 1, ""),
            ("blank", "psql_q() { printf '\\n  \\n'; }", 1, ""),
            ("many", "psql_q() { printf '%s\\n%s\\n' a b; }", 1, ""),
            ("failed", "psql_q() { return 2; }", 1, ""),
            ("failed-with-rows", "psql_q() { printf '%s\\n' x; return 2; }", 1, ""),
        ]
        for name, stub, rc, want in cases:
            r = bash(f"{stub}; route_session_for_fp '{FP}'")
            if r.returncode != rc or r.stdout.strip() != want or (rc and not r.stderr.strip()):
                bad.append(f"route_session_for_fp {name}: rc={r.returncode} out={r.stdout!r} err={r.stderr!r}")
        r = bash("psql_q() { printf '%s' \"$1\" >&2; return 2; }; route_session_for_fp '" + FP + "'")
        if "LIMIT" in r.stderr.upper() or "LIKE '" + FP + "%'" not in r.stderr:
            bad.append(f"the route query must not LIMIT (a collision must reach the count check): {r.stderr!r}")
        r = bash("psql_q() { echo x; }; route_session_for_fp \"ab'; DROP\"")
        if r.returncode != 1 or r.stdout.strip():
            bad.append(f"route_session_for_fp must refuse a non-8-hex fingerprint: rc={r.returncode} out={r.stdout!r}")
        # both HA scripts must resolve through it (no raw LIKE ... LIMIT 1, no '|| echo' success)
        for name in ("ha-gateway-failover-spike.sh", "ha-gateway-two-replica-probe.sh"):
            txt = (ROOT / "scripts/ha" / name).read_text()
            if ("route_session_for_fp" not in txt or "agent-session-fp.sh" not in txt
                    or "LIKE '$fp%' LIMIT 1" in txt):
                bad.append(f"{name} must resolve sessions through route_session_for_fp")
            if '|| { echo "agent_map: cannot resolve the session' not in txt or "return 1; }" not in txt:
                bad.append(f"{name}: a failed lookup must return 1")
        # BEHAVIOURAL: the REAL agent_map function and its REAL call line, extracted from each HA
        # script, with stubbed compose/docker/psql_q. A lookup that yields zero rows, many rows or a
        # failure for the SECOND agent must stop the caller (non-zero, never "CALLER CONTINUED") and
        # leave NO csv (not even a partial one); all-good must write both rows.
        import re as _re
        fp1, fp2 = "aaaaaaaa", "bbbbbbbb"
        for name in ("ha-gateway-failover-spike.sh", "ha-gateway-two-replica-probe.sh"):
            txt = (ROOT / "scripts/ha" / name).read_text()
            m = _re.search(r"^agent_map\(\) \{.*?^\}\n", txt, _re.S | _re.M)
            call = _re.search(r'^[ \t]*agent_map "\$run"(?=[ \t]|$).*$', txt, _re.M)
            if not m or not call:
                bad.append(f"{name}: agent_map or its guarded call line not found")
                continue
            for case, rows in (("good", "one"), ("zero", "zero"), ("many", "many"), ("failed", "failed")):
                rd = d / f"ha-{name}-{case}"
                rd.mkdir()
                stub = f"""
compose() {{ printf 'c1\\nc2\\n'; }}
cname() {{ echo "$1"; }}
docker() {{ case "$1" in
  inspect) echo "/n-$3" ;;
  logs) case "$2" in c1) echo "Registered with server (session_fp={fp1}, enrollment=e)";;
                     *) echo "Registered with server (session_fp={fp2}, enrollment=e)";; esac ;;
esac; }}
psql_q() {{ case "$1" in
  *"'{fp1}%'"*) echo s-one ;;
  *) case "{rows}" in one) echo s-two;; zero) :;; many) printf 'x\\ny\\n';; failed) return 2;; esac ;; esac; }}
die() {{ echo "DIE: $*" >&2; exit 2; }}
run='{rd.as_posix()}'
{m.group(0)}
{call.group(0).strip()}
echo "CALLER CONTINUED"
"""
                r = bash(stub)
                csv = rd / "agent_map.csv"
                tmpcsv = rd / "agent_map.csv.tmp"
                if case == "good":
                    if "CALLER CONTINUED" not in r.stdout or not csv.exists() or len(csv.read_text().splitlines()) != 2 \
                            or "s-one" not in csv.read_text() or "s-two" not in csv.read_text():
                        bad.append(f"{name}/good: rc={r.returncode} out={r.stdout!r} err={r.stderr!r}")
                else:
                    if r.returncode == 0 or "CALLER CONTINUED" in r.stdout or csv.exists() or tmpcsv.exists():
                        bad.append(f"{name}/{case}: must stop the caller with no csv: rc={r.returncode} "
                                   f"out={r.stdout!r} csv={csv.exists()} tmp={tmpcsv.exists()}")
    for b in bad:
        print("FAIL:", b)
    if bad:
        return 1
    print("OK: session_fp join works (LF, CRLF, NUL, 20k lines, both hash branches) and fails loudly otherwise")
    return 0


if __name__ == "__main__":
    sys.exit(main())
