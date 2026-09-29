#!/usr/bin/env python3
"""Regression tests for scripts/build_gateway.py and scripts/erlang_toolchain.py.

The wrapper runs `rebar3 compile` for Meson on every build; these tests drive
it with a fake Python child instead, so they need no Erlang. Each case pins a
failure found in governance review of the Windows stdio-isolation change:

  - a timeout while our own stdout is not being read must still exit 124
    promptly (the relay once wedged interpreter shutdown there);
  - Ctrl-C (even a second one mid-kill) and a broken stderr must still kill
    the whole child tree, grandchildren included;
  - the build log is never written through a planted link, and a previous
    run's log that cannot be removed is never passed off as this run's;
  - a broken stdout never turns a successful build into a failure;
  - a failing output sink never stops the drain, and a read failure closes
    the log and the pipe;
  - the shared env never gains -noinput (it breaks standard_io `peer` nodes
    in the gateway eunit suite) and never allows interactive git prompts.
"""

import io
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from unittest import mock

SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts")
sys.path.insert(0, SCRIPTS)

import build_gateway  # noqa: E402
import erlang_toolchain  # noqa: E402

PY = sys.executable


def _child(body):
    """argv for a fake rebar3 child running `body`."""
    return [PY, "-c", textwrap.dedent(body)]


class _TempDirCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="yuzu_test_build_gateway_")
        self.log_dir = os.path.join(self.tmp, "meson-logs")
        os.mkdir(self.log_dir)
        self.marker = os.path.join(self.tmp, "survived")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    SLEEP = 6

    def sleeper_code(self):
        """A child whose GRANDCHILD writes a marker unless the whole tree is
        killed first - killing only the direct child leaves the marker."""
        grandchild = (f"import time; time.sleep({self.SLEEP}); "
                      f"open({self.marker!r}, 'w').close()")
        return textwrap.dedent(f"""
            import subprocess, sys, time
            subprocess.Popen([sys.executable, "-c", {grandchild!r}])
            print("started", flush=True)
            time.sleep({self.SLEEP} + 2)
        """)

    def sleeper(self):
        return [PY, "-c", self.sleeper_code()]

    def assert_killed(self):
        time.sleep(self.SLEEP + 2)
        self.assertFalse(os.path.exists(self.marker), "child tree was not killed")


class TestHelpers(unittest.TestCase):
    def test_build_timeout(self):
        self.assertEqual(build_gateway.build_timeout({}), 900)
        self.assertEqual(build_gateway.build_timeout({"YUZU_GATEWAY_BUILD_TIMEOUT": "5"}), 5)
        self.assertEqual(build_gateway.build_timeout({"YUZU_GATEWAY_BUILD_TIMEOUT": "x"}), 900)

    def test_describe_exit(self):
        if sys.platform == "win32":
            self.assertEqual(build_gateway.describe_exit(3221225477),
                             "code 3221225477 (0xC0000005)")
        else:
            self.assertEqual(build_gateway.describe_exit(-9), "signal 9")
            self.assertEqual(build_gateway.describe_exit(3), "code 3")


class TestSharedEnv(unittest.TestCase):
    def test_no_noinput_and_no_prompts(self):
        with mock.patch.dict(os.environ, {"ERL_FLAGS": "+S 2"}):
            env = erlang_toolchain.base_env()
        # Unchanged: -noinput must never reach test_gateway.py's peer nodes.
        self.assertEqual(env["ERL_FLAGS"], "+S 2")
        if sys.platform == "win32":
            self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
            self.assertEqual(env["GCM_INTERACTIVE"], "never")

    def test_stdio_isolation(self):
        kw = erlang_toolchain.windows_stdio_isolation()
        if sys.platform == "win32":
            self.assertIs(kw["stdin"], subprocess.DEVNULL)
            self.assertTrue(kw["creationflags"] & subprocess.CREATE_NO_WINDOW)
        else:
            self.assertEqual(kw, {})


class TestBuildLog(_TempDirCase):
    def test_missing_dir_means_no_log(self):
        self.assertEqual(build_gateway.open_build_log(os.path.join(self.tmp, "nope")),
                         (None, None))

    def _canary(self):
        canary = os.path.join(self.tmp, "canary")
        with open(canary, "w") as f:
            f.write("PRECIOUS")
        return canary

    def _assert_canary_intact(self, canary):
        path, fd = build_gateway.open_build_log(self.log_dir)
        try:
            if fd is not None:
                os.write(fd, b"build output")
        finally:
            build_gateway._close_fd(fd)
        with open(canary) as f:
            self.assertEqual(f.read(), "PRECIOUS")

    def test_never_writes_through_a_hardlink(self):
        # Needs no symlink privilege, so this runs on every CI host; the guard
        # it pins (unlink the name, never write through it) is the same one.
        canary = self._canary()
        os.link(canary, os.path.join(self.log_dir, build_gateway.LOG_NAME))
        self._assert_canary_intact(canary)

    def test_never_writes_through_a_symlink(self):
        canary = self._canary()
        link = os.path.join(self.log_dir, build_gateway.LOG_NAME)
        try:
            os.symlink(canary, link)
        except (OSError, NotImplementedError):
            self.skipTest("cannot create symlinks here (the hardlink case still runs)")
        self._assert_canary_intact(canary)

    def test_stale_log_is_never_reused(self):
        stale = os.path.join(self.log_dir, build_gateway.LOG_NAME)
        with open(stale, "w") as f:
            f.write("OLD RUN")
        with mock.patch.object(build_gateway.os, "unlink",
                               side_effect=PermissionError("in use")):
            path, fd = build_gateway.open_build_log(self.log_dir)
        build_gateway._close_fd(fd)
        self.assertIsNotNone(fd)
        self.assertNotEqual(os.path.normcase(path), os.path.normcase(stale))


class _RaisingSrc:
    """A pipe stand-in whose read fails after two chunks."""

    def __init__(self):
        self.calls = 0
        self.closed = False

    def read1(self, n):
        self.calls += 1
        if self.calls > 2:
            raise OSError("read failed")
        return b"chunk\n"

    def close(self):
        self.closed = True


class TestRelay(_TempDirCase):
    def test_failing_sink_does_not_stop_the_drain(self):
        data = b"x" * (1 << 20)
        r, w = os.pipe()
        dead_r, dead_w = os.pipe()
        os.close(dead_r)  # writes to dead_w now fail
        path, log_fd = build_gateway.open_build_log(self.log_dir)
        src = os.fdopen(r, "rb")
        relay = build_gateway.Relay(src, dead_w, log_fd)
        relay.start()

        def feed():
            with os.fdopen(w, "wb") as out:
                out.write(data)

        threading.Thread(target=feed).start()
        self.assertTrue(relay.join(20))
        os.close(dead_w)
        self.assertTrue(relay.log_complete)
        with open(path, "rb") as f:
            self.assertEqual(f.read(), data)

    def test_read_failure_closes_log_and_pipe(self):
        path, log_fd = build_gateway.open_build_log(self.log_dir)
        src = _RaisingSrc()
        relay = build_gateway.Relay(src, None, log_fd)
        relay.start()
        self.assertTrue(relay.join(5))
        self.assertFalse(relay.log_complete)
        self.assertIsInstance(relay.read_error, OSError)
        self.assertTrue(src.closed)
        with self.assertRaises(OSError):
            os.fstat(log_fd)  # closed by the relay
        with open(path, "rb") as f:
            self.assertEqual(f.read(), b"chunk\nchunk\n")


class TestRunBuild(_TempDirCase):
    def run_build(self, cmd, timeout_s=60):
        return build_gateway.run_build(cmd, self.tmp, None, timeout_s, self.log_dir,
                                       relay_output=True)

    def test_exit_code_and_log(self):
        rc = self.run_build(_child("""
            import sys
            print("hello from rebar3", flush=True)
            sys.exit(3)
        """))
        self.assertEqual(rc, 3)
        with open(os.path.join(self.log_dir, build_gateway.LOG_NAME), "rb") as f:
            self.assertIn(b"hello from rebar3", f.read())

    def test_timeout_kills_tree(self):
        self.assertEqual(self.run_build(self.sleeper(), timeout_s=1),
                         build_gateway.EXIT_TIMEOUT)
        self.assert_killed()

    def test_second_ctrl_c_during_kill_still_kills_tree(self):
        # Interrupt the REAL kill primitive (taskkill's subprocess.run, or
        # os.killpg) on its first call, before it has signalled anything. The
        # retry must still reach the grandchildren - which it cannot if
        # anything killed the root first (taskkill /T walks from the root).
        if sys.platform == "win32":
            owner, name = erlang_toolchain.subprocess, "run"
        else:
            owner, name = erlang_toolchain.os, "killpg"
        real = getattr(owner, name)
        calls = {"n": 0}

        def interrupted_first(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise KeyboardInterrupt  # the impatient second press
            return real(*args, **kwargs)

        with mock.patch.object(owner, name, interrupted_first):
            with self.assertRaises(KeyboardInterrupt):
                self.run_build(self.sleeper(), timeout_s=1)
        self.assertGreaterEqual(calls["n"], 2)
        self.assert_killed()

    @unittest.skipUnless(sys.platform == "win32", "taskkill is Windows-only")
    def test_taskkill_is_isolated_and_bounded(self):
        # A console Ctrl-C must not be able to kill taskkill mid-walk (own
        # process group), a wedged taskkill must not hang us (timeout), and a
        # taskkill.exe planted in the cwd must never run (absolute path).
        with mock.patch.object(erlang_toolchain.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0)) as run:
            proc = mock.Mock(pid=4242)
            self.assertTrue(erlang_toolchain.kill_tree(proc, timeout=7))
        argv, kwargs = run.call_args.args[0], run.call_args.kwargs
        self.assertTrue(os.path.isabs(argv[0]))
        self.assertTrue(argv[0].lower().endswith(os.path.join("system32", "taskkill.exe")))
        self.assertTrue(kwargs["creationflags"] & subprocess.CREATE_NEW_PROCESS_GROUP)
        self.assertEqual(kwargs["timeout"], 7)
        proc.kill.assert_called_once()  # the root, after the walk

    def test_ctrl_c_kills_tree(self):
        real_wait = subprocess.Popen.wait
        calls = {"n": 0}

        def wait(proc, timeout=None):
            calls["n"] += 1
            if calls["n"] == 2:
                raise KeyboardInterrupt
            return real_wait(proc, timeout=timeout)

        with mock.patch.object(subprocess.Popen, "wait", wait):
            with self.assertRaises(KeyboardInterrupt):
                self.run_build(self.sleeper())
        self.assert_killed()

    def test_broken_stdout_still_builds(self):
        class Broken(io.StringIO):
            def write(self, s):
                raise OSError("handle is invalid")

        with mock.patch.object(sys, "stdout", Broken()):
            rc = self.run_build(_child("import sys; sys.exit(7)"))
        self.assertEqual(rc, 7)

    def test_relay_start_failure_kills_child(self):
        def fail_once_tree_exists(relay):
            # Wait for "started" (printed only after the grandchild is
            # spawned) before failing. Failing straight after Popen races
            # the grandchild's creation against taskkill /T's non-atomic
            # tree walk on Windows: a grandchild born mid-walk is orphaned
            # and the test flakes, without the start-failure path being
            # wrong.
            self.assertIn(b"started", relay._src.readline())
            raise RuntimeError("can't start new thread")

        with mock.patch.object(build_gateway.Relay, "start", autospec=True,
                               side_effect=fail_once_tree_exists):
            with self.assertRaises(RuntimeError):
                self.run_build(self.sleeper())
        self.assert_killed()


def _driver(tmp, log_dir, body, timeout_s, prelude=""):
    """argv running run_build in a separate interpreter, so the test controls
    that process's own stdio."""
    code = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {SCRIPTS!r})
        {prelude}
        import build_gateway
        sys.exit(build_gateway.run_build(
            [sys.executable, "-c", {body!r}], {tmp!r}, None, {timeout_s},
            {log_dir!r}, relay_output=True))
    """)
    return [PY, "-c", code]


class TestWrapperProcess(_TempDirCase):
    def test_timeout_with_unread_stdout_exits(self):
        # Our stdout is a pipe nobody reads, the child floods it: the relay
        # blocks writing, the pipe from the child fills, the timeout fires.
        # The wrapper must still exit 124 instead of wedging at shutdown.
        flood = "import sys\nwhile True: sys.stdout.write('x' * 65536)"
        r, w = os.pipe()
        try:
            start = time.monotonic()
            proc = subprocess.run(_driver(self.tmp, self.log_dir, flood, 2),
                                  stdout=w, stderr=subprocess.PIPE, timeout=60)
            self.assertEqual(proc.returncode, build_gateway.EXIT_TIMEOUT, proc.stderr)
            self.assertLess(time.monotonic() - start, 30)
            self.assertNotIn(b"Fatal Python error", proc.stderr)
        finally:
            os.close(r)
            os.close(w)

    def test_timeout_with_no_stderr_still_kills(self):
        proc = subprocess.run(
            _driver(self.tmp, self.log_dir, self.sleeper_code(), 1,
                    prelude="sys.stderr = None"),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60)
        self.assertEqual(proc.returncode, build_gateway.EXIT_TIMEOUT, proc.stderr)
        self.assert_killed()

    def test_broken_stdout_pipe_keeps_child_exit_code(self):
        # Our stdout's reader is gone before we start, so the banner write
        # fails; that must not turn a successful build into exit 120 when the
        # interpreter flushes stdout at shutdown.
        r, w = os.pipe()
        os.close(r)
        try:
            proc = subprocess.run(_driver(self.tmp, self.log_dir, "pass", 60),
                                  stdout=w, stderr=subprocess.PIPE, timeout=60)
        finally:
            os.close(w)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
