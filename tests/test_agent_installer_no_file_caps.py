#!/usr/bin/env python3
"""WP13 (F21) pin for scripts/install-agent-user.sh: the installer sets NO file capability on the
agent binary and strips any it finds.

A file capability on a 0755 binary is a local privilege escalation (any local account that runs
it receives the capability, and the invoker chooses the plugin directory the agent loads). The
installer therefore never runs `setcap` other than `setcap -r`, treats a capability that may
still be live as an install failure (exit 5), and treats one in `--check` as drift.

  1. lexical: no `setcap` / `$SETCAP` token in code other than `setcap -r` or a presence probe
     (`command -v setcap`); message-only lines (warn/log/... "...") may name it;
  2. executed (`--dry-run`, tool stubs on PATH, nothing runs as root): caps found -> one
     `setcap -r` and no grant; no caps -> no setcap call; setcap missing while caps exist ->
     exit 5; `--no-cap-cleanup` -> exit 0 with a loud stderr warning and no setcap call;
     the removed `--no-setcap` flag -> exit 2 (unknown argument);
  3. mutations: the same checks run against in-memory mutants of the script (a restored
     `setcap ...+eip`, a dropped exit 5, a skipped strip, a restored `--no-setcap`) and each must
     fail.
"""
import os
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/install-agent-user.sh"

_MSG_CMD = re.compile(r"^\s*(?:warn|log|info|fail|echo|printf)\w*\b")
_TOKEN = re.compile(r"(?<![\w-])setcap\b|\$\{?SETCAP\}?(?!\w)")


def setcap_violations(code: str) -> list[str]:
    """Every `setcap` token in code (after `command`, `sudo`, `eval`, a pipe, `$SETCAP`) that is
    not `setcap -r` or a presence probe. A message-only line (warn/log/info/fail/echo/printf
    "...") may NAME setcap in its first quoted string; anything after that string is scanned."""
    bad = []
    for line in code.splitlines():
        if line.lstrip().startswith("#"):
            continue
        scan = line
        if _MSG_CMD.match(line):
            scan = re.sub(r'^\s*\w+\s+"(?:[^"\\]|\\.)*"', "", line, count=1)
        for m in _TOKEN.finditer(scan):
            before = scan[:m.start()].rstrip()
            after = scan[m.end():]
            if re.search(r"(?:command\s+-v|type|which)$", before):
                continue
            if re.match(r"\s+-r(?!\w)", after):
                continue
            bad.append(line.strip())
    return bad


def _stub(d: pathlib.Path, name: str, body: str) -> None:
    p = d / name
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(0o755)


def run_installer(script: pathlib.Path, args, *, caps: bool, setcap: bool, getcap: bool = True):
    with tempfile.TemporaryDirectory(prefix="yuzu_test_installer_caps_") as d:
        d = pathlib.Path(d)
        stubs = d / "stubs"
        stubs.mkdir()
        if getcap:
            _stub(stubs, "getcap", 'echo "$1 cap_net_admin+eip"' if caps else "exit 0")
        if setcap:
            _stub(stubs, "setcap", "exit 0")
        binary = d / "yuzu-agent"
        binary.write_text("x")
        env = {"PATH": f"{stubs}:/usr/bin:/bin", "HOME": str(d), "LC_ALL": "C"}
        r = subprocess.run(["/bin/bash", str(script), "--dry-run", "--account-name", "yuzu_t",
                            "--binary-path", str(binary), *args],
                           capture_output=True, text=True, env=env, timeout=120)
        return r


def check(script: pathlib.Path) -> list[str]:
    errs = []
    code = script.read_text()
    for v in setcap_violations(code):
        errs.append(f"installer invokes setcap other than `setcap -r`: {v!r}")
    if "setcap -r" not in code:
        errs.append("installer must strip file capabilities (`setcap -r`)")
    if re.search(r"\+eip|cap_net_admin,cap_net_raw", "\n".join(
            l for l in code.splitlines() if not l.lstrip().startswith("#") and not _MSG_CMD.match(l))):
        errs.append("installer still names a capability set in code")

    r = run_installer(script, [], caps=True, setcap=True)
    out = r.stdout + r.stderr
    if r.returncode != 0 or not re.search(r"\[dry-run\] setcap -r ", out):
        errs.append(f"caps found: expected exit 0 and one `setcap -r` (rc {r.returncode})")
    if re.search(r"\[dry-run\] setcap(?! -r)", out):
        errs.append("caps found: a setcap grant was printed")
    r = run_installer(script, [], caps=False, setcap=True)
    if r.returncode != 0 or re.search(r"\[dry-run\] setcap", r.stdout + r.stderr):
        errs.append(f"no caps: expected exit 0 and no setcap call (rc {r.returncode})")
    r = run_installer(script, [], caps=True, setcap=False)
    if r.returncode != 5:
        errs.append(f"setcap missing while caps exist: expected exit 5, got {r.returncode}")
    r = run_installer(script, ["--no-cap-cleanup"], caps=True, setcap=True)
    if r.returncode != 0 or "STILL LIVE" not in r.stderr or re.search(r"\[dry-run\] setcap", r.stdout + r.stderr):
        errs.append(f"--no-cap-cleanup with live caps: expected exit 0, a STILL LIVE warning, no setcap call "
                    f"(rc {r.returncode})")
    r = run_installer(script, ["--no-setcap"], caps=False, setcap=True)
    if r.returncode != 2 or "unknown arg" not in r.stderr:
        errs.append(f"--no-setcap must be an unknown argument (exit 2), got {r.returncode}")
    return errs


def selftest() -> list[str]:
    """Each mutant must be caught by check(); a pattern that no longer matches fails loudly."""
    src = SCRIPT.read_text()
    muts = {
        "setcap grant restored": (
            '    run setcap -r "$BINARY_PATH" ||',
            '    run setcap "cap_net_raw+eip" "$BINARY_PATH" ||'),
        "exit 5 dropped": (
            '        warn "  remove them by hand: setcap -r $BINARY_PATH   (apt: libcap2-bin, dnf: libcap)"\n        return 5',
            '        warn "  remove them by hand: setcap -r $BINARY_PATH   (apt: libcap2-bin, dnf: libcap)"\n        return 0'),
        "strip skipped": (
            "        strip_file_capabilities || cap_rc=$?", "        cap_rc=0"),
        "--no-setcap alias restored": (
            "        --no-cap-cleanup) SKIP_SETCAP=1; shift ;;",
            "        --no-cap-cleanup|--no-setcap) SKIP_SETCAP=1; shift ;;"),
        "warning silenced": (
            'warn "--no-cap-cleanup: file capabilities are STILL LIVE', 'log "--no-cap-cleanup: file capabilities are STILL LIVE'),
    }
    errs = []
    with tempfile.TemporaryDirectory(prefix="yuzu_test_installer_mut_") as d:
        for name, (a, b) in muts.items():
            if a not in src:
                errs.append(f"selftest '{name}': pattern no longer matches the installer (stale)")
                continue
            m = pathlib.Path(d) / "install-agent-user.sh"
            m.write_text(src.replace(a, b, 1))
            if not check(m):
                errs.append(f"selftest '{name}': mutation was NOT detected")
    for line, want in [('run setcap cap_net_raw+ep "$B"', True), ('command setcap cap_net_raw+ep "$B"', True),
                       ('"$SETCAP" cap_net_raw+ep "$B"', True), ('eval "setcap cap_net_raw+ep $B"', True),
                       ('log_warn "x"; setcap cap_net_raw+ep $B', True), ('run setcap -r "$B"', False),
                       ('command -v setcap >/dev/null', False), ('warn "setcap not installed"', False),
                       ('SKIP_SETCAP=1', False)]:
        if bool(setcap_violations(line)) != want:
            errs.append(f"setcap lint self-test: {line!r} expected flagged={want}")
    return errs


def main() -> int:
    errs = check(SCRIPT) + selftest()
    for e in errs:
        print("FAIL:", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
