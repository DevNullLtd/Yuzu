#!/usr/bin/env python3
"""WP13 (F21, F48) lint over scripts/install-agent-user.sh: what a fresh install GRANTS.

Runs the installer in --dry-run (no root, nothing executed) and inspects the output, plus the
generated systemctl wrapper itself with a stub systemctl. No attack code: refusals only.

  F21  the installer never sets a file capability (`setcap ...+e`); it strips them (`setcap -r`),
       and --check treats their presence, not absence, as drift.
  F48  no sudoers grant for `systemctl` ends in a glob; the only systemctl grant is the
       root-owned wrapper; the launchctl bootstrap/bootout grants are gone; the wrapper refuses
       every shape except `<verb> <unit>`.

iptables/ip6tables stay bare on purpose until #7634 (that issue owns narrowing them); the
allow-list below fails when #7634 lands so the doc and this test are updated together.
"""
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/install-agent-user.sh"
SRC = SCRIPT.read_text()
errs: list[str] = []


def fail(msg: str) -> None:
    errs.append(msg)


def dry_run(platform: str, binary: pathlib.Path):
    env = dict(os.environ)
    tmp = None
    if platform == "Darwin":
        # Stub uname so the macOS branch (dscl etc. are only PRINTED under --dry-run) renders.
        tmp = tempfile.mkdtemp(prefix="yuzu_test_uname_")
        stub = pathlib.Path(tmp) / "uname"
        stub.write_text("#!/bin/sh\necho Darwin\n")
        stub.chmod(0o755)
        env["PATH"] = tmp + os.pathsep + env["PATH"]
    r = subprocess.run(
        ["bash", str(SCRIPT), "--dry-run", "--account-name", "yuzu_lint", "--binary-path", str(binary)],
        capture_output=True, text=True, env=env, timeout=60)
    return r.stdout + r.stderr


def grants(out: str):
    """Non-comment sudoers lines from the dry-run dump."""
    lines = []
    marker = out.find("would write the following to /etc/sudoers.d/yuzu-agent")
    for l in (out[marker:] if marker >= 0 else "").splitlines():
        if l.startswith("[dry-run]   "):
            body = l[len("[dry-run]   "):]
            if body.strip() and not body.lstrip().startswith("#"):
                lines.append(body)
    return lines


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="yuzu_test_installer_lint_") as d:
        binary = pathlib.Path(d) / "yuzu-agent"
        binary.write_text("x")

        # ── F21: no setcap grant anywhere in the script ───────────────────────────────
        code = "\n".join(l for l in SRC.splitlines() if not l.lstrip().startswith("#"))
        for m in re.finditer(r"(?:^|\brun\s+)\s*setcap\s+(?!-r\b)[^\n]*", code, re.M):
            fail(f"installer invokes setcap other than `setcap -r`: {m.group(0)!r}")
        if "setcap -r" not in code:
            fail("installer must strip file capabilities (`setcap -r`)")
        if re.search(r"^apply_setcap\b", code, re.M):
            fail("apply_setcap is back")
        chk = code[code.index("check_install()"):code.index("case \"$ACTION\" in")]
        if re.search(r"no (file )?capabilities set on", chk):
            fail("--check must not warn when capabilities are ABSENT")
        if "file capabilities present" not in chk:
            fail("--check must warn when file capabilities are PRESENT")

        # ── governance R1/R2/D6: failure propagation and --check strictness ──────────
        if "requiretty" in "\n".join(l for l in code.splitlines()
                                       if "Defaults" in l and not l.lstrip().startswith("#")):
            fail("sudoers still carries a Defaults requiretty line (sudo-rs rejects the file)")
        # (Exit-status behaviour of install/--check is asserted by EXECUTION in
        # tests/test_agent_installer_exec.py; the text pins here would stay green under a neutered exit.)
        if "rm -f \"$target\"" not in code[code.index("install_sudoers()"):code.index("remove_sudoers()")]:
            fail("a failed sudoers validation must remove the existing (glob-carrying) file")
        if "cannot verify" not in chk:
            fail("--check must treat a missing getcap as drift")
        if "carries the systemctl enable|disable|mask|unmask glob grants" not in chk or \
           "lacks the $SYSTEMCTL_WRAPPER_PATH grant" not in chk:
            fail("--check must assert the wrapper grant AND the absence of the glob grants")
        if "--no-cap-cleanup" not in SRC:
            fail("--no-cap-cleanup is missing")

        if sys.platform.startswith("linux"):
            out = dry_run("Linux", binary)
            # The generated Linux sudoers must validate where visudo is available (classic sudo
            # or sudo-rs): a `!requiretty` line makes visudo reject the whole file.
            vis = subprocess.run(["bash", "-c", "command -v visudo"], capture_output=True, text=True).stdout.strip()
            if vis:
                content = subprocess.run(
                    ["bash", "-c",
                     "ACCOUNT_NAME=yuzu_lint PLATFORM=linux SYSTEMCTL_WRAPPER_PATH=/usr/libexec/yuzu/yuzu-systemctl;"
                     f" source <(sed -n '/^generate_sudoers_content()/,/^}}/p' {SCRIPT}); generate_sudoers_content"],
                    capture_output=True, text=True).stdout
                sf = pathlib.Path(d) / "sudoers.test"
                sf.write_text(content)
                r = subprocess.run([vis, "-cf", str(sf)], capture_output=True, text=True)
                if r.returncode != 0:
                    fail(f"generated Linux sudoers fails visudo -cf: {r.stdout}{r.stderr}")
            if re.search(r"\[dry-run\] setcap\s+\S*\+", out):
                fail("dry-run grants a file capability")
            g = grants(out)
            sysctl = [l for l in g if "systemctl" in l]
            wrapper = [l for l in g if "/usr/libexec/yuzu/yuzu-systemctl" in l]
            if len(wrapper) != 1 or sysctl != wrapper:
                fail(f"the only systemctl sudo grant must be the wrapper, got {sysctl!r}")
            for l in sysctl:
                if l.rstrip().endswith("*"):
                    fail(f"systemctl grant ends in a glob: {l!r}")
            # iptables is a RECORDED residual (#7634). This fails when it is narrowed.
            bare = [l for l in g if re.search(r"NOPASSWD: /usr/sbin/ip6?tables$", l)]
            if len(bare) != 2:
                fail("iptables/ip6tables bare grants changed: update this test and "
                     "docs/agent-privilege-model.md together (#7634)")

            # ── the wrapper itself ────────────────────────────────────────────────────
            fn = subprocess.run(
                ["bash", "-c",
                 f"source <(sed -n '/^generate_systemctl_wrapper_content()/,/^}}/p' {SCRIPT}); "
                 "generate_systemctl_wrapper_content"],
                capture_output=True, text=True, timeout=30).stdout
            if "SYSTEMCTL=/usr/bin/systemctl" not in fn:
                fail("could not extract the wrapper")
            else:
                log = pathlib.Path(d) / "calls.log"
                stub = pathlib.Path(d) / "systemctl"
                stub.write_text(f'#!/bin/sh\necho "$@" >> {log}\n')
                stub.chmod(0o755)
                w = pathlib.Path(d) / "yuzu-systemctl"
                w.write_text(fn.replace("SYSTEMCTL=/usr/bin/systemctl", f"SYSTEMCTL={stub}"))
                w.chmod(0o755)

                def run(*args):
                    return subprocess.run([str(w), *args], capture_output=True, text=True).returncode

                ok_cases = [("enable", "ssh.service"), ("disable", "a@b_c-d.service"),
                            ("mask", "x"), ("unmask", "-leading.service"), ("enable", "a" * 256)]
                for a in ok_cases:
                    if run(*a) != 0:
                        fail(f"wrapper refused a valid call {a[0]} {a[1][:20]}")
                calls = log.read_text().splitlines() if log.exists() else []
                if "enable -- ssh.service" not in calls or "unmask -- -leading.service" not in calls:
                    fail(f"wrapper must exec `systemctl <verb> -- <unit>`, got {calls[:5]!r}")
                before = len(calls)
                bad_cases = [
                    ("enable", "--now", "/tmp/x.service"),   # extra args
                    ("enable", "a", "b"),
                    ("enable",), (), ("start", "ssh.service"), ("--now", "ssh.service"),
                    ("enable", "/tmp/x.service"), ("enable", ""), ("enable", "a b"),
                    ("enable", "a;b"), ("enable", "a\nb"), ("enable", "a" * 257),
                    ("enable", "a/../b"), ("edit", "ssh.service"),
                ]
                for a in bad_cases:
                    if run(*a) != 2:
                        fail(f"wrapper must refuse (rc 2): {a!r}")
                after = log.read_text().splitlines() if log.exists() else []
                if len(after) != before:
                    fail("wrapper executed systemctl for a refused call")

        # ── F48 macOS: bootstrap/bootout are gone ──────────────────────────────────────
        out = dry_run("Darwin", binary)
        g = grants(out)
        if not g:
            fail("macOS dry-run produced no sudoers dump (stub failed?)")
        for l in g:
            if re.search(r"launchctl (bootstrap|bootout)", l):
                fail(f"macOS grant must not exist: {l!r}")
        if not any("launchctl enable system/*" in l for l in g):
            fail("macOS launchctl enable grant missing (the plugin uses it)")

    for e in errs:
        print("FAIL:", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
