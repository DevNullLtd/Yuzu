#!/usr/bin/env python3
"""WP13/F52 EXECUTED refusal test: run the real yuzu-agent binary.

usage: test_agent_allowlist_refusal_executed.py <path-to-yuzu-agent>

A configured --plugin-allowlist that is missing / empty / junk must make the agent log the
critical refusal (the async log hand-off must have flushed it) and exit non-zero WITHOUT loading
any plugin. Control: a valid allowlist must NOT produce the refusal (the agent is then killed
after a few seconds while it tries to reach the unreachable server).
"""
import os
import pathlib
import subprocess
import sys
import tempfile

REFUSAL = "Refusing to start"


def run(agent, allowlist, tmp, wait, extra=()):
    args = [agent, "--server", "127.0.0.1:1", "--no-tls", "--data-dir", str(tmp / "data"),
            "--plugin-dir", str(tmp / "plugins"), "--log-level", "info"]
    if allowlist is not None:
        args += ["--plugin-allowlist", str(allowlist)]
    args += list(extra)
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                         env={**os.environ, "YUZU_AGENT_LOG_FILE": ""})
    try:
        out, _ = p.communicate(timeout=wait)
        return p.returncode, out, False
    except subprocess.TimeoutExpired:
        p.kill()
        out, _ = p.communicate()
        return None, out, True


def main():
    agent = sys.argv[1]
    errs = []
    with tempfile.TemporaryDirectory(prefix="yuzu_test_allowlist_exec_") as d:
        tmp = pathlib.Path(d)
        (tmp / "data").mkdir()
        (tmp / "plugins").mkdir()
        empty = tmp / "empty.txt"
        empty.write_text("")
        junk = tmp / "junk.txt"
        junk.write_text("d41d8cd98f00b204e9800998ecf8427e  foo.so\n")
        for name, path in (("missing", tmp / "absent.txt"), ("empty", empty), ("junk", junk)):
            rc, out, timed_out = run(agent, path, tmp, 15)
            if timed_out:
                errs.append(f"{name}: agent kept running instead of refusing")
            elif rc == 0:
                errs.append(f"{name}: exit code 0")
            if REFUSAL not in out or "--plugin-allowlist" not in out:
                errs.append(f"{name}: refusal line not in output (lost log line?):\n{out[-600:]}")
        # --plugin-require-signature without a trust bundle (the sibling guard) uses the same
        # return-from-run mechanism: its line must reach the log and the exit must be non-zero.
        rc, out, timed_out = run(agent, None, tmp, 15, ["--plugin-require-signature"])
        if timed_out or rc == 0 or REFUSAL not in out or "--plugin-trust-bundle" not in out:
            errs.append(f"require-signature without a bundle: rc={rc} timed_out={timed_out}\n{out[-400:]}")
        good = tmp / "good.txt"
        good.write_text("a" * 64 + "  nothing.so\n")
        rc, out, timed_out = run(agent, good, tmp, 6)
        if REFUSAL in out:
            errs.append("control: a valid allowlist was refused")
    for e in errs:
        print("FAIL:", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
