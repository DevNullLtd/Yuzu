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


def run_installer(script: pathlib.Path, args, *, caps: bool, setcap: bool, getcap=True, dry_run=True,
                  binary_arg=True):
    """getcap: True/False (present/absent) or "stderr" (exit 0, error only on stderr) or "rc1"
    (exit 1, nothing on stderr)."""
    with tempfile.TemporaryDirectory(prefix="yuzu_test_installer_caps_") as d:
        d = pathlib.Path(d)
        stubs = d / "stubs"
        stubs.mkdir()
        if getcap == "stderr":
            _stub(stubs, "getcap", 'echo "Failed to get capabilities of file $1" >&2; exit 0')
        elif getcap == "rc1":
            _stub(stubs, "getcap", "exit 1")
        elif getcap:
            _stub(stubs, "getcap", 'echo "$1 cap_net_admin+eip"' if caps else "exit 0")
        if setcap:
            _stub(stubs, "setcap", "exit 0")
        binary = d / "yuzu-agent"
        binary.write_text("x")
        env = {"PATH": f"{stubs}:/usr/bin:/bin", "HOME": str(d), "LC_ALL": "C"}
        argv = ["/bin/bash", str(script)] + (["--dry-run"] if dry_run else []) + ["--account-name", "yuzu_t"]
        if binary_arg:
            argv += ["--binary-path", str(binary)]
        r = subprocess.run(argv + list(args),
                           capture_output=True, text=True, env=env, timeout=120)
        return r


def check(script: pathlib.Path, uat_text=None) -> list[str]:
    errs = []
    code = script.read_text()
    for v in setcap_violations(code):
        errs.append(f"installer invokes setcap other than `setcap -r`: {v!r}")
    if "setcap -r" not in code:
        errs.append("installer must strip file capabilities (`setcap -r`)")
    if re.search(r"\+eip|cap_net_admin,cap_net_raw", "\n".join(
            l for l in code.splitlines() if not l.lstrip().startswith("#") and not _MSG_CMD.match(l))):
        errs.append("installer still names a capability set in code")

    # start-UAT.sh step 4b (the binary actually launched) must read getcap the same way
    uat = uat_text if uat_text is not None else (ROOT / "scripts/start-UAT.sh").read_text()
    if '[ -s "$getcap_err" ]' not in uat or '"$getcap_rc" -ne 0' not in uat:
        errs.append("start-UAT.sh step 4b must treat a getcap failure or stderr as unverifiable")
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

    # getcap that exits 0 with its error only on stderr (or exits non-zero) is UNVERIFIABLE, never
    # "no file capabilities (good)": install (with setcap missing) exits 5.
    for mode in ("stderr", "rc1"):
        r = run_installer(script, [], caps=False, setcap=False, getcap=mode)
        if r.returncode != 5 or "(good)" in r.stdout + r.stderr:
            errs.append(f"getcap {mode}: install must not read it as clean; expected exit 5, got {r.returncode}")
    # an explicit --binary-path that is not a regular file is an argument error
    r = run_installer(script, ["--binary-path", "/nonexistent/yuzu-agent"], caps=False, setcap=True)
    if r.returncode != 2:
        errs.append(f"explicit --binary-path that is not a file: expected exit 2, got {r.returncode}")

    # --check: the exit status is the contract. The sandbox has other drift (no such account), so
    # the status is 1 on every run (a fall-through to `exit 0` would make it 0), and the capability
    # finding is read from the issue count: one more than the clean baseline.
    def issues(**kw):
        r = run_installer(script, ["--check"] + kw.pop("args", []), dry_run=False, **kw)
        m = re.search(r"check failed .{1,3} (\d+) issue", r.stdout + r.stderr)
        return r, (int(m.group(1)) if m else None)
    base_r, base_n = issues(caps=False, setcap=True)
    if base_r.returncode != 1 or base_n is None:
        errs.append(f"--check on a drifted host must exit 1 (got {base_r.returncode}) and report its issue count")
    elif "file capabilities present" in base_r.stdout + base_r.stderr:
        errs.append("--check reported a capability on a clean binary")
    else:
        for name, kw, needle in (("capability present", dict(caps=True, setcap=True), "file capabilities present"),
                                 ("getcap missing", dict(caps=False, setcap=True, getcap=False), "getcap not installed"),
                                 ("getcap stderr", dict(caps=False, setcap=True, getcap="stderr"), "getcap could not read"),
                                 ("getcap rc 1", dict(caps=False, setcap=True, getcap="rc1"), "getcap could not read")):
            r, n = issues(**kw)
            if r.returncode != 1 or n != (base_n or 0) + 1 or needle not in r.stdout + r.stderr:
                errs.append(f"--check {name}: expected exit 1, {base_n + 1} issues and {needle!r}; got rc {r.returncode}, "
                            f"issues {n}")
        r, n = issues(args=["--no-cap-cleanup"], caps=True, setcap=True)
        if r.returncode != 1 or n != base_n or "file-capability check skipped" not in r.stdout + r.stderr:
            errs.append(f"--check --no-cap-cleanup must skip the capability test and say so (rc {r.returncode}, issues {n})")
    return errs


def selftest() -> list[str]:
    """Each mutant must be caught by check(); a pattern that no longer matches fails loudly."""
    src = SCRIPT.read_text()
    muts = {
        "setcap grant restored": (
            '    run setcap -r "$BINARY_PATH" ||',
            '    run setcap "cap_net_raw+eip" "$BINARY_PATH" ||'),
        "exit 5 dropped": (
            '(needs libcap: apt libcap2-bin, dnf libcap)"\n        return 5',
            '(needs libcap: apt libcap2-bin, dnf libcap)"\n        return 0'),
        "strip skipped": (
            "        strip_file_capabilities || cap_rc=$?", "        cap_rc=0"),
        "--no-setcap alias restored": (
            "        --no-cap-cleanup) SKIP_SETCAP=1; shift ;;",
            "        --no-cap-cleanup|--no-setcap) SKIP_SETCAP=1; shift ;;"),
        "--check falls through to exit 0": (
            "        check_install\n        exit $?\n", "        check_install\n"),
        "getcap stderr ignored": (
            '[[ "$rc" -eq 0 && -z "$err" ]]', '[[ "$rc" -eq 0 ]]'),
        "getcap failure read as clean in --check": (
            "            if ! read_file_caps; then\n                warn \"getcap could not read $BINARY_PATH (exit status or stderr): cannot verify",
            "            if false; then\n                warn \"getcap could not read $BINARY_PATH (exit status or stderr): cannot verify"),
        "explicit missing --binary-path accepted": (
            "    echo \"--binary-path $BINARY_PATH is not a regular file\" >&2\n    exit 2\n", "    :\n"),
        "warning silenced": (
            'warn "--no-cap-cleanup: file capabilities are STILL LIVE', 'log "--no-cap-cleanup: file capabilities are STILL LIVE'),
    }
    errs = []
    uat_src = (ROOT / "scripts/start-UAT.sh").read_text()
    uat_mut = uat_src.replace('[ -s "$getcap_err" ]', "false", 1)
    if uat_mut == uat_src:
        errs.append("selftest 'start-UAT getcap stderr ignored': pattern no longer matches (stale)")
    elif not check(SCRIPT, uat_text=uat_mut):
        errs.append("selftest 'start-UAT getcap stderr ignored': mutation was NOT detected")
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
