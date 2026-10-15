#!/usr/bin/env python3
"""Hermetic integration test for flake-retry.py.

Drives the *real* flake-retry.py CLI as a subprocess against fake `meson` and
fake Catch2 stubs on PATH, exercising the orchestration the unit `--selftest`
can't reach: `meson test` -> meson suite-level junit -> `meson introspect` ->
re-run the suite binary with Catch2's junit reporter -> isolated case retries.

Scenarios: green pass (including an unavailable telemetry-report path), a
listed flake that recovers on retry, a listed flake that fails all retries
(blocks), an unlisted failure (blocks), and a non-classifiable (non-Catch2)
suite (blocks).

POSIX-only (the fakes are chmod +x shebang scripts); skipped on Windows, where
the real CI exercises the binary-execution mechanics anyway.

Run: python3 scripts/ci/test_flake_retry.py   (exit 0 = pass)
"""
import importlib.util
import json
import os
import platform
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.join(HERE, "flake-retry.py")

# Import detect_os from the wrapper so the test lists the flake for THIS OS.
_spec = importlib.util.spec_from_file_location("flake_retry", WRAPPER)
_fr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fr)
THIS_OS = _fr.detect_os()

FAKE_MESON = r"""#!/usr/bin/env python3
import os, sys, json
a = sys.argv[1:]
marker = os.environ.get("FAKE_MESON_CALLED")
if marker:
    open(marker, "w").write("called")
if a and a[0] == "introspect":
    builddir = a[1]
    if os.environ.get("FAKE_NONCATCH2") == "1":
        cmd = ["/bin/echo"]                 # basename not yuzu_*_tests -> unclassifiable
    else:
        cmd = [os.environ["FAKE_CATCH2_BIN"]]
        if os.environ.get("FAKE_SHARD_SPEC"):   # sharded entry (#2092): tag filter in cmd
            cmd.append(os.environ["FAKE_SHARD_SPEC"])
    print(json.dumps([{"name": "fake unit tests", "cmd": cmd, "env": {}, "workdir": None,
                       "suite": ["yuzu:fake"]}]))
    sys.exit(0)
if a and a[0] == "test":
    builddir = a[a.index("-C") + 1]
    logs = os.path.join(builddir, "meson-logs"); os.makedirs(logs, exist_ok=True)
    j = os.path.join(logs, "testlog.junit.xml")
    if os.environ.get("FAKE_MESON_TEST_PASS") == "1":
        open(j, "w").write('<testsuites><testsuite><testcase name="fake - yuzu:fake unit tests" time="1.0"/></testsuite></testsuites>')
        if os.environ.get("FAKE_REPORT_PATH_IS_FILE") == "1":
            os.remove(j)
            os.rmdir(logs)
            open(logs, "w").write("not a directory")
        sys.exit(0)
    open(j, "w").write('<testsuites><testsuite><testcase name="fake - yuzu:fake unit tests" time="1.0">'
                       '<failure>boom</failure></testcase></testsuite></testsuites>')
    sys.exit(1)
sys.exit(0)
"""

FAKE_CATCH2 = r"""#!/usr/bin/env python3
import os, re, sys
a = sys.argv[1:]
fail = [c for c in os.environ.get("FAKE_FAIL_CASES", "").split(";") if c]
always = [c for c in os.environ.get("FAKE_ALWAYS_FAIL", "").split(";") if c]
TAG_SPEC = re.compile(r"^~?(\[[^\[\]]+\])+$")
# #4580: every invocation (enumeration re-run AND isolated case retry) must
# replicate meson's own test-launch contract -- CWD at the build root,
# MESON_BUILD_ROOT/MESON_SOURCE_ROOT set -- or a real plugin-loading test
# fails its build-output-lookup fallback deterministically, masquerading as
# a genuine regression. Record what this invocation actually saw so the
# scenario can assert on it.
marker = os.environ.get("FAKE_ASSERT_MESON_CONTRACT")
if marker:
    with open(marker, "a") as f:
        f.write("%s\t%s\n" % (os.environ.get("MESON_BUILD_ROOT", ""), os.getcwd()))
if "--reporter" in a:                       # enumeration run -> emit Catch2 junit
    # A sharded entry's tag filter must SURVIVE into the enumeration run
    # (#2092: only the isolated retry strips it) — a missing spec means the
    # wrapper stripped too much, so emit nothing (-> unclassifiable -> block).
    spec = os.environ.get("FAKE_SHARD_SPEC")
    if spec and spec not in a:
        sys.exit(1)
    out = a[a.index("--out") + 1]
    tcs = "".join('<testcase classname="c" name="%s"><failure>boom</failure></testcase>' % c
                  for c in fail)
    open(out, "w").write('<testsuites><testsuite name="fake">%s</testsuite></testsuites>' % tcs)
    sys.exit(1 if fail else 0)
# Isolated retry of one case by name. A leftover tag spec means the wrapper
# failed to strip the shard filter (real Catch2 would OR it with the case and
# re-run the whole shard) -> hard fail so the recovery scenario can't pass.
if any(TAG_SPEC.match(x) for x in a):
    sys.exit(1)
case = a[0] if a else ""
sys.exit(1 if case in always else 0)
"""


def _write_exe(path, body):
    with open(path, "w") as f:
        f.write(body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def run_scenario(label, env_extra, known_flaky, expect_zero):
    with tempfile.TemporaryDirectory() as d:
        binroot = os.path.join(d, "bin"); os.makedirs(binroot)
        meson = os.path.join(binroot, "meson")
        catch2 = os.path.join(binroot, "yuzu_fake_tests")
        _write_exe(meson, FAKE_MESON)
        _write_exe(catch2, FAKE_CATCH2)
        builddir = os.path.join(d, "build"); os.makedirs(builddir)
        kf = os.path.join(d, "known-flaky.json")
        with open(kf, "w") as f:
            json.dump(known_flaky, f)
        env = dict(os.environ)
        # The wrapper's summary() writes bypass capture_output — never let a
        # fake scenario append to a real Actions job summary.
        env.pop("GITHUB_STEP_SUMMARY", None)
        env["PATH"] = binroot + os.pathsep + env["PATH"]
        env["FAKE_CATCH2_BIN"] = catch2
        env.update(env_extra)
        r = subprocess.run(
            [sys.executable, WRAPPER, "--builddir", builddir, "--known-flaky", kf],
            env=env, capture_output=True, text=True,
        )
        ok = (r.returncode == 0) == expect_zero
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {label}: exit={r.returncode} (expected {'0' if expect_zero else 'nonzero'})")
        if not ok:
            print("  stdout:", r.stdout.strip().replace("\n", "\n  "))
            print("  stderr:", r.stderr.strip().replace("\n", "\n  "))
        return ok


def run_meson_contract_scenario(label, known_flaky):
    """#4580: assert every re-invocation of the test binary (the enumeration
    re-run AND the isolated case retry) actually receives meson's own
    test-launch contract -- CWD at the build root, MESON_BUILD_ROOT set to
    it -- not just that the overall wrapper exit code looks right. A
    regression here (e.g. a future refactor that drops the builddir
    threading) would otherwise still pass every other scenario, because
    those only assert on the WRAPPER's exit code, and a real plugin-loading
    test failing on this exact contract gap is indistinguishable, from the
    exit code alone, from a genuine regression."""
    with tempfile.TemporaryDirectory() as d:
        binroot = os.path.join(d, "bin"); os.makedirs(binroot)
        meson = os.path.join(binroot, "meson")
        catch2 = os.path.join(binroot, "yuzu_fake_tests")
        _write_exe(meson, FAKE_MESON)
        _write_exe(catch2, FAKE_CATCH2)
        builddir = os.path.join(d, "build"); os.makedirs(builddir)
        kf = os.path.join(d, "known-flaky.json")
        with open(kf, "w") as f:
            json.dump(known_flaky, f)
        marker = os.path.join(d, "contract-marker.txt")
        env = dict(os.environ)
        env.pop("GITHUB_STEP_SUMMARY", None)
        env["PATH"] = binroot + os.pathsep + env["PATH"]
        env["FAKE_CATCH2_BIN"] = catch2
        # FlakeA fails then recovers on retry -> exercises BOTH the
        # enumeration re-run (catch2_failed_cases) and the isolated retry
        # (retry_case) in one pass, each appending its own marker line.
        env["FAKE_FAIL_CASES"] = "FlakeA"
        env["FAKE_ASSERT_MESON_CONTRACT"] = marker
        r = subprocess.run(
            [sys.executable, WRAPPER, "--builddir", builddir, "--known-flaky", kf],
            env=env, capture_output=True, text=True,
        )
        expected_root = os.path.abspath(builddir)
        # MESON_BUILD_ROOT is compared as an exact string: it's just an env
        # var set to expected_root and read back verbatim, exactly what the
        # real C++ test code does too (no resolution occurs either side in
        # production). cwd is compared via realpath: os.getcwd() inside the
        # child returns the kernel-resolved physical path, which differs
        # textually from expected_root whenever TMPDIR itself is a symlink
        # (macOS: /var -> /private/var, so tempfile.TemporaryDirectory()
        # paths are under /var/folders/... but getcwd() reports
        # /private/var/folders/...) -- same physical directory, different
        # string. A bare == here is a real CI-caught false failure (macOS
        # debug), not a production bug: build-macos under the actual
        # checkout is never under /tmp, so this symlink shape doesn't occur
        # in the real CI invocation this test exists to guard.
        expected_root_real = os.path.realpath(expected_root)
        lines = []
        if os.path.exists(marker):
            with open(marker) as f:
                lines = [ln.rstrip("\n").split("\t") for ln in f if ln.strip()]
        ok = (r.returncode == 0 and len(lines) >= 2
              and all(build_root == expected_root and os.path.realpath(cwd) == expected_root_real
                      for build_root, cwd in lines))
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {label}: exit={r.returncode}, {len(lines)} invocation(s) recorded")
        if not ok:
            print("  expected MESON_BUILD_ROOT/cwd:", expected_root)
            print("  recorded lines:", lines)
            print("  stdout:", r.stdout.strip().replace("\n", "\n  "))
            print("  stderr:", r.stderr.strip().replace("\n", "\n  "))
        return ok


def run_validation_failure(label, known_flaky):
    """An invalid registry must fail before it invokes the Meson executable."""
    with tempfile.TemporaryDirectory() as d:
        binroot = os.path.join(d, "bin"); os.makedirs(binroot)
        meson = os.path.join(binroot, "meson")
        catch2 = os.path.join(binroot, "yuzu_fake_tests")
        _write_exe(meson, FAKE_MESON)
        _write_exe(catch2, FAKE_CATCH2)
        builddir = os.path.join(d, "build"); os.makedirs(builddir)
        kf = os.path.join(d, "known-flaky.json")
        with open(kf, "w") as f:
            json.dump(known_flaky, f)
        marker = os.path.join(d, "meson-called")
        env = dict(os.environ)
        env.pop("GITHUB_STEP_SUMMARY", None)
        env["PATH"] = binroot + os.pathsep + env["PATH"]
        env["FAKE_CATCH2_BIN"] = catch2
        env["FAKE_MESON_CALLED"] = marker
        r = subprocess.run(
            [sys.executable, WRAPPER, "--builddir", builddir, "--known-flaky", kf],
            env=env, capture_output=True, text=True,
        )
        ok = r.returncode == 2 and not os.path.exists(marker) and "known-flaky list invalid" in r.stdout
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {label}: exit={r.returncode} (expected 2; meson not invoked)")
        if not ok:
            print("  stdout:", r.stdout.strip().replace("\n", "\n  "))
            print("  stderr:", r.stderr.strip().replace("\n", "\n  "))
        return ok


def main():
    if platform.system() == "Windows":
        print("test_flake_retry: skipped on Windows (POSIX fakes); real CI covers it")
        return 0

    listed = [{
        "case": "FlakeA",
        "platforms": [THIS_OS],
        "reason": "test flake",
        "issue": "#test",
        "owner": "ci",
        "added": "2026-06-23",
        "expires": "2099-12-31",
    }]
    results = [
        run_scenario("green pass", {"FAKE_MESON_TEST_PASS": "1"}, listed, True),
        run_scenario("green pass survives unavailable retry-report path",
                     {"FAKE_MESON_TEST_PASS": "1", "FAKE_REPORT_PATH_IS_FILE": "1"},
                     listed, True),
        run_scenario("listed flake recovers on retry", {"FAKE_FAIL_CASES": "FlakeA"}, listed, True),
        run_scenario("listed flake fails all retries -> block",
                     {"FAKE_FAIL_CASES": "FlakeA", "FAKE_ALWAYS_FAIL": "FlakeA"}, listed, False),
        run_scenario("unlisted failure -> block", {"FAKE_FAIL_CASES": "RealBug"}, listed, False),
        run_scenario("non-Catch2 suite -> block",
                     {"FAKE_FAIL_CASES": "FlakeA", "FAKE_NONCATCH2": "1"}, listed, False),
        run_scenario("sharded suite (#2092): retry replaces tag filter",
                     {"FAKE_FAIL_CASES": "FlakeA", "FAKE_SHARD_SPEC": "~[pg]"}, listed, True),
        run_meson_contract_scenario(
            "#4580: enumeration re-run and isolated retry both get meson's test-launch contract",
            listed),
        # Suite red under meson, but the solo enumeration re-run reproduces
        # ZERO failing cases (order/contention-dependent failure, or a stale
        # junit from a crashed run). Nothing is attributable to a listed
        # flake, so the wrapper must block — returning 0 here is the
        # masked-green hole governance UP-1 closed.
        run_scenario("suite fails, enumeration reproduces nothing -> block",
                     {"FAKE_FAIL_CASES": ""}, listed, False),
        run_validation_failure("expired registry entry blocks before Meson",
                               [{**listed[0], "added": "1999-01-01", "expires": "2000-01-01"}]),
    ]
    if all(results):
        print(f"\nflake-retry integration test: OK ({len(results)} scenarios)")
        return 0
    print(f"\nflake-retry integration test: {results.count(False)} FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
