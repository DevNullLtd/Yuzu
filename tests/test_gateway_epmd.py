#!/usr/bin/env python3
"""Pin the gateway test wrapper's run-private epmd (#4853, scripts/gateway_epmd.py).

  1. the port pick and the isolate() decision (what it sets, what it leaves
     alone), against injected probes, and the real probe against real sockets;
  2. find_epmd() and stop(): where epmd is looked for, what is said when it is
     not stopped, and that cleanup can never raise;
  3. activate(): what a run says and registers for each of the three outcomes;
  4. scripts/test_gateway.py calls activate() on the env it hands to rebar3,
     right after base_env().

Hermetic: injected seams, plus a few wildcard-bound sockets on OS-chosen ports to
prove the real probe refuses a held port. No epmd, no rebar3, no subprocess.
"""
import errno
import fnmatch
import functools
import math
import os
import re
import socket
import subprocess
import sys
import types
import unittest
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

import gateway_epmd as ge  # noqa: E402

WRAPPER = os.path.join(ROOT, 'scripts', 'test_gateway.py')
SPAN = ge.PORT_RANGE[1] - ge.PORT_RANGE[0] + 1


def quiet(*args, **kwargs):
    """A `say`/`register` stand-in that records nothing."""


def free_port_number():
    """An OS-chosen port nothing holds right now. Skips where this host cannot
    bind (a sandbox), on IPv4 or, where it has the stack, IPv6: the real probe
    needs both, and a test of it cannot say anything there."""
    port = None
    for family, host in ((socket.AF_INET, ""), (socket.AF_INET6, "::")):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.bind((host, 0))
                port = port or s.getsockname()[1]
        except OSError as exc:
            if family == socket.AF_INET6 and exc.errno in ge._NO_IPV6:
                continue
            raise unittest.SkipTest("cannot bind a socket here: %s" % exc)
    return port


class PickPortTest(unittest.TestCase):
    LOW = ge.PORT_RANGE[0]

    def test_starts_at_the_port_the_pid_maps_to_and_scans_by_the_stride(self):
        seen = []

        def is_free(port):
            seen.append(port)
            return len(seen) == 3

        port = ge.pick_port(is_free, pid=lambda: 100)
        step = ge._SCAN_STRIDE
        self.assertEqual(seen, [self.LOW + 100, self.LOW + 100 + step, self.LOW + 100 + 2 * step])
        self.assertEqual(port, seen[-1])

    def test_with_everything_free_the_default_pid_picks_this_process_start_port(self):
        self.assertEqual(ge.pick_port(lambda p: True), self.LOW + os.getpid() % SPAN)

    def test_windows_pid_stride_reaches_every_start_port(self):
        # Windows pids are multiples of 4; a span divisible by 4 would reach a quarter of the
        # start ports and make two concurrent runs 4x likelier to share one.
        starts = {ge.pick_port(lambda p: True, pid=lambda pid=pid: pid) for pid in range(0, 4 * SPAN, 4)}
        self.assertEqual(len(starts), SPAN)

    def test_concurrent_runs_scan_disjoint_ports(self):
        # Adjacent pids (two jobs starting together) must not converge on one port when a start
        # port is busy: the stride keeps their scans apart for the whole bounded scan.
        def scanned(pid):
            seen = set()
            ge.pick_port(lambda p: seen.add(p) or False, pid=lambda: pid)
            return seen

        for other in range(101, 110):
            self.assertFalse(scanned(100) & scanned(other), other)

    def test_a_block_of_unusable_ports_is_stepped_over(self):
        # A Windows excluded-port block is a contiguous run; one stride clears a run this wide.
        start = self.LOW + 400
        blocked = range(start, start + 100)
        port = ge.pick_port(lambda p: p not in blocked, pid=lambda: 400)
        self.assertIsNotNone(port)
        self.assertNotIn(port, blocked)

    def test_the_scan_wraps_at_the_end_of_the_range(self):
        seen = []
        ge.pick_port(lambda p: seen.append(p) or False, pid=lambda: SPAN - 1)
        self.assertEqual(seen[:2], [ge.PORT_RANGE[1], self.LOW + ge._SCAN_STRIDE - 1])

    def test_gives_up_after_a_bounded_number_of_tries(self):
        calls = []
        self.assertIsNone(ge.pick_port(lambda p: calls.append(p) or False, pid=lambda: 5))
        self.assertEqual(len(calls), 20)
        self.assertEqual(len(set(calls)), 20)  # the stride never revisits a port within the scan

    def test_the_stride_is_coprime_with_the_span(self):
        self.assertEqual(math.gcd(ge._SCAN_STRIDE, SPAN), 1)

    def test_range_stays_below_every_ephemeral_range(self):
        # Linux ephemeral starts at 32768; Windows and macOS at 49152.
        self.assertLess(ge.PORT_RANGE[1], 32768)
        self.assertGreater(ge.PORT_RANGE[0], 1024)


class PortProbeTest(unittest.TestCase):
    def test_a_free_port_is_free(self):
        self.assertTrue(ge.port_is_free(free_port_number()))

    def test_a_held_port_is_not_free(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
            try:
                held.bind(("", 0))
            except OSError as exc:  # a sandbox that denies bind cannot run this probe test
                self.skipTest("cannot bind a socket here: %s" % exc)
            self.assertFalse(ge.port_is_free(held.getsockname()[1]))

    def test_a_port_held_only_on_ipv6_is_not_free(self):
        # epmd binds both stacks and fails to start, silently, when a foreign process
        # holds the port on either one; an IPv4-only probe would call the port free.
        try:
            held = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            held.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            held.bind(("::", 0))
        except OSError as exc:
            self.skipTest("no usable IPv6 here: %s" % exc)
        with held:
            self.assertFalse(ge.port_is_free(held.getsockname()[1]))

    def test_a_probe_that_cannot_open_a_socket_says_not_free_and_never_raises(self):
        # A restricted host must fall back to the shared epmd, not abort the run.
        with mock.patch.object(ge.socket, "socket", side_effect=PermissionError(errno.EPERM, "denied")):
            self.assertFalse(ge.port_is_free(24000))

    def test_a_host_without_ipv6_has_nothing_holding_the_port_there(self):
        real = socket.socket
        port = free_port_number()
        for code in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
            def no_v6(family, *args, code=code, **kwargs):
                if family == socket.AF_INET6:
                    raise OSError(code, "no IPv6")
                return real(family, *args, **kwargs)

            with self.subTest(errno=errno.errorcode[code]), \
                    mock.patch.object(ge.socket, "socket", side_effect=no_v6):
                self.assertTrue(ge.port_is_free(port))


class IsolateTest(unittest.TestCase):
    def test_sets_a_private_port_when_none_is_configured(self):
        env = {"PATH": "x"}
        got = ge.isolate(env, is_free=lambda p: True, pid=lambda: 3)
        self.assertEqual(env["ERL_EPMD_PORT"], got)
        self.assertEqual(got, str(ge.PORT_RANGE[0] + 3))
        self.assertEqual(env["PATH"], "x")

    def test_an_explicit_port_is_the_operators_isolation_and_wins(self):
        env = {"ERL_EPMD_PORT": "9999"}
        got = ge.isolate(env, is_free=lambda p: self.fail("must not probe"))
        self.assertIsNone(got)
        self.assertEqual(env["ERL_EPMD_PORT"], "9999")

    def test_an_empty_value_counts_as_unset(self):
        env = {"ERL_EPMD_PORT": ""}
        got = ge.isolate(env, is_free=lambda p: True, pid=lambda: 4)
        self.assertEqual(env["ERL_EPMD_PORT"], got)
        self.assertNotEqual(got, "")

    def test_no_free_port_leaves_the_environment_alone(self):
        env = {}
        self.assertIsNone(ge.isolate(env, is_free=lambda p: False, pid=lambda: 5))
        self.assertEqual(env, {})

    def test_the_kill_check_stays_strict_so_a_cleanup_cannot_take_down_a_registered_epmd(self):
        # epmd refuses `-kill` while any node is registered unless ERL_EPMD_RELAXED_COMMAND_CHECK
        # is set (measured). Setting it would let one run's exit kill an epmd another run
        # still has nodes on; leaving it unset only ever leaves this run's own epmd to the runner.
        env = {}
        ge.isolate(env, is_free=lambda p: True, pid=lambda: 6)
        self.assertNotIn("ERL_EPMD_RELAXED_COMMAND_CHECK", env)


class ActivateTest(unittest.TestCase):
    def run_activate(self, env, isolate_):
        said, registered = [], []
        port = ge.activate(env, register=lambda *a: registered.append(a),
                           say=lambda msg, **kw: said.append((msg, kw)), isolate_=isolate_)
        return port, said, registered

    def test_an_owned_port_is_announced_flushed_and_registered_for_cleanup(self):
        env = {"PATH": "p"}
        port, said, registered = self.run_activate(env, lambda e: "24242")
        self.assertEqual(port, "24242")
        self.assertEqual(said, [("[test_gateway.py] run-private epmd: ERL_EPMD_PORT=24242",
                                 {"flush": True})])
        self.assertEqual(registered, [(ge.stop, "24242", env)])
        self.assertIs(registered[0][2], env)  # the live env, not a copy a later edit would miss

    def test_an_operators_port_is_named_and_never_killed(self):
        env = {"ERL_EPMD_PORT": "9999"}
        port, said, registered = self.run_activate(env, lambda e: None)
        self.assertIsNone(port)
        self.assertIn("ERL_EPMD_PORT=9999 from the environment", said[0][0])
        self.assertEqual(registered, [])

    def test_falling_back_to_the_shared_epmd_is_said_not_silent(self):
        port, said, registered = self.run_activate({}, lambda e: None)
        self.assertIsNone(port)
        self.assertIn("using the shared epmd", said[0][0])
        self.assertIn("#4853", said[0][0])
        self.assertEqual(registered, [])

    def test_a_port_found_by_isolate_sets_the_env_and_registers_cleanup(self):
        env = {}
        port, said, registered = self.run_activate(
            env, functools.partial(ge.isolate, is_free=lambda p: True))
        self.assertEqual(registered[0][:2], (ge.stop, port))
        self.assertEqual(env["ERL_EPMD_PORT"], port)

    def test_the_defaults_compose_into_a_private_port_for_this_process(self):
        # The wrapper calls activate(env) on defaults only: the real probe, this pid, isolate.
        free_port_number()  # skips where sockets are denied; anywhere else the real probe works
        env = {}
        registered = []
        expected = ge.pick_port(ge.port_is_free)
        if expected is None:
            self.skipTest("no port in the range can be probed here")
        port = ge.activate(env, register=lambda *a: registered.append(a), say=quiet)
        self.assertEqual(port, str(expected))
        self.assertEqual(env["ERL_EPMD_PORT"], port)
        self.assertEqual(registered, [(ge.stop, port, env)])


class FindEpmdTest(unittest.TestCase):
    ROOT = os.path.realpath(os.path.join(os.sep, "otp"))

    def which_erl_only(self, root, on_path=None):
        """`which` that finds erl, and only erl, and only on the PATH it is given."""
        erl = os.path.join(root, "bin", "erl")
        return lambda name, path=None: erl if name == "erl" and path == on_path else None

    @staticmethod
    def listing(paths):
        def glob_(pattern):
            return [p for p in paths if fnmatch.fnmatchcase(p, pattern)]
        return glob_

    def test_prefers_the_epmd_on_the_runs_path(self):
        asked = []

        def which(name, path=None):
            asked.append((name, path))
            return "/otp/bin/epmd"

        self.assertEqual(ge.find_epmd({"PATH": "/otp/bin"}, which=which,
                                      glob_=lambda p: self.fail("no glob needed")),
                         "/otp/bin/epmd")
        self.assertEqual(asked, [("epmd", "/otp/bin")])

    def test_windows_layout_finds_epmd_exe_not_its_pdb(self):
        # Windows OTP: <root>/bin/erl.exe, but epmd.exe only in <root>/erts-<vsn>/bin, beside
        # epmd.pdb. An earlier revision globbed `epmd*` and made stop() try to run the symbols
        # file. The look-alikes are listed BEFORE the real file: with equal version keys max()
        # keeps the first, so a pattern that matches them would return one of them.
        bindir = os.path.join(self.ROOT, "erts-16.3.1", "bin")
        want = os.path.join(bindir, "epmd.exe")
        paths = [os.path.join(bindir, n) for n in
                 ("epmd.pdb", "epmdx.exe", "erl.exe", "erlexec.dll", "epmd.exe")]
        got = ge.find_epmd({"PATH": "x"}, which=self.which_erl_only(self.ROOT, on_path="x"),
                           glob_=self.listing(paths))
        self.assertEqual(got, want)

    def test_takes_the_newest_erts_by_numeric_version_not_by_string_or_first_component(self):
        # "erts-9.0" sorts after "erts-16.3.1" as a string; "16.10" beats "16.3.1" numerically
        # but not on the first component alone. A POSIX install is found by the bare name.
        dirs = ("erts-9.0", "erts-16.3.1", "erts-16.10", "erts-15.2")
        paths = [os.path.join(self.ROOT, d, "bin", "epmd") for d in dirs]
        got = ge.find_epmd({}, which=self.which_erl_only(self.ROOT), glob_=self.listing(paths))
        self.assertEqual(got, os.path.join(self.ROOT, "erts-16.10", "bin", "epmd"))

    def test_an_install_path_with_glob_characters_is_a_path_not_a_pattern(self):
        root = os.path.realpath(os.path.join(os.sep, "otp[28]"))
        sibling = os.path.realpath(os.path.join(os.sep, "otp2"))
        wanted = os.path.join(root, "erts-16.3.1", "bin", "epmd.exe")
        paths = [wanted, os.path.join(sibling, "erts-1.0", "bin", "epmd.exe")]
        got = ge.find_epmd({}, which=self.which_erl_only(root), glob_=self.listing(paths))
        self.assertEqual(got, wanted)

    def test_the_erl_that_names_the_install_is_the_one_behind_its_links(self):
        # A shim directory (a package manager's links) is not the OTP root.
        shim_erl = os.path.join(os.sep, "shims", "bin", "erl")
        real_root = os.path.join(self.ROOT, "erts-1.0")  # any directory the link resolves into
        real_erl = os.path.join(self.ROOT, "bin", "erl")
        wanted = os.path.join(self.ROOT, "erts-16.3.1", "bin", "epmd")
        with mock.patch.object(ge.os.path, "realpath", side_effect=lambda p: real_erl if p == shim_erl else p):
            got = ge.find_epmd({}, which=lambda n, path=None: shim_erl if n == "erl" else None,
                               glob_=self.listing([wanted, os.path.join(real_root, "bin", "epmd")]))
        self.assertEqual(got, wanted)

    def test_an_install_root_that_itself_contains_an_erts_name_does_not_tie_every_hit(self):
        root = os.path.realpath(os.path.join(os.sep, "erts-9", "otp"))
        paths = [os.path.join(root, d, "bin", "epmd") for d in ("erts-3.0", "erts-16.3.1")]
        got = ge.find_epmd({}, which=self.which_erl_only(root), glob_=self.listing(paths))
        self.assertEqual(got, paths[1])

    def test_no_erl_and_no_epmd_is_none(self):
        self.assertIsNone(ge.find_epmd({}, which=lambda n, path=None: None,
                                       glob_=lambda p: self.fail("no erl, no glob")))

    def test_an_erl_whose_install_has_no_epmd_is_none(self):
        self.assertIsNone(ge.find_epmd({}, which=self.which_erl_only(self.ROOT),
                                       glob_=lambda p: []))


class StopTest(unittest.TestCase):
    def stop(self, *, which=lambda name, path=None: "/otp/bin/epmd", run=None, env=None,
             listening=True):
        """Drive ge.stop with every seam faked; `listening` is whether anything holds the port."""
        said, calls = [], []

        def default_run(args, **kw):
            calls.append((args, kw))
            return types.SimpleNamespace(returncode=0)

        ok = ge.stop("24242", {"PATH": "p"} if env is None else env, which=which,
                     run=run or default_run, glob_=lambda pattern: [],
                     say=lambda msg, **kw: said.append(msg), is_free=lambda port: not listening)
        return ok, said, calls

    def test_kills_the_run_private_epmd_with_the_runs_env(self):
        env = {"PATH": "p", "ERL_EPMD_PORT": "24242"}
        ok, said, calls = self.stop(env=env)
        self.assertTrue(ok)
        self.assertEqual(said, [])
        self.assertEqual(calls[0][0], ["/otp/bin/epmd", "-port", "24242", "-kill"])
        self.assertIs(calls[0][1]["env"], env)
        self.assertEqual(calls[0][1]["timeout"], ge._KILL_TIMEOUT_SECS)
        self.assertLessEqual(ge._KILL_TIMEOUT_SECS, 10)  # the margin under meson's own timeout
        for stream in ("stdin", "stdout", "stderr"):
            self.assertIs(calls[0][1][stream], subprocess.DEVNULL, stream)

    def test_epmd_is_looked_up_on_the_runs_own_path(self):
        asked = []

        def which(name, path=None):
            asked.append((name, path))
            return "/otp/bin/epmd" if path == "/run/path" else None

        ok, _, _ = self.stop(which=which, env={"PATH": "/run/path"})
        self.assertTrue(ok)
        self.assertEqual(asked, [("epmd", "/run/path")])

    def test_nothing_listening_means_nothing_to_stop_and_nothing_to_say(self):
        # A `ct` run starts no distribution, so no epmd ever listened on the run's port; a
        # kill attempt would fail exactly like a refusal and a message would be false.
        ok, said, calls = self.stop(listening=False,
                                    run=lambda args, **kw: self.fail("must not kill"))
        self.assertTrue(ok)
        self.assertEqual(said, [])

    def test_the_real_probe_takes_the_string_port_the_wrapper_registers(self):
        # activate() registers the port as the string isolate() put in the env; the probe wants an int.
        port = free_port_number()
        said = []
        ok = ge.stop(str(port), {"PATH": "p"}, run=lambda *a, **k: self.fail("nothing listens"),
                     say=lambda *a, **k: said.append(a))
        self.assertTrue(ok)
        self.assertEqual(said, [])

    def test_no_epmd_anywhere_means_no_call_and_says_so(self):
        ok, said, calls = self.stop(which=lambda name, path=None: None)
        self.assertFalse(ok)
        self.assertEqual(calls, [])
        self.assertEqual(len(said), 1)
        self.assertIn("epmd -port 24242 -kill", said[0])

    def test_the_advised_command_names_the_epmd_that_was_found(self):
        # Windows keeps epmd.exe off PATH, so a bare `epmd` would not run there.
        found = "C:\\Program Files\\Erlang OTP\\erts-16.3.1\\bin\\epmd.exe"
        ok, said, _ = self.stop(which=lambda name, path=None: found,
                                run=lambda args, **kw: types.SimpleNamespace(returncode=1))
        self.assertFalse(ok)
        self.assertIn('"%s" -port 24242 -kill' % found, said[0])

    def test_a_refused_kill_says_the_epmd_is_still_running(self):
        # epmd answers `Killing not allowed - living nodes in database.` with rc 1.
        ok, said, _ = self.stop(run=lambda args, **kw: types.SimpleNamespace(returncode=1))
        self.assertFalse(ok)
        self.assertEqual(len(said), 1)
        self.assertIn("may still be running", said[0])
        self.assertIn("-port 24242 -kill", said[0])

    def test_never_raises(self):
        def boom(args, **kw):
            raise subprocess.TimeoutExpired(args, 5)

        def oserr(args, **kw):
            raise OSError("gone")

        for run in (boom, oserr):
            ok, said, _ = self.stop(run=run)
            self.assertFalse(ok)
            self.assertEqual(len(said), 1)

    def test_a_closed_stdout_at_exit_does_not_raise_either(self):
        def closed(msg, **kw):
            raise ValueError("I/O operation on closed file")

        ok = ge.stop("24242", {"PATH": "p"}, which=lambda name, path=None: None, say=closed,
                     is_free=lambda port: False)
        self.assertFalse(ok)


class WrapperWiringTest(unittest.TestCase):
    def setUp(self):
        with open(WRAPPER, encoding="utf-8") as f:
            self.src = f.read()

    def test_activates_the_env_it_hands_to_rebar3_right_after_base_env(self):
        # Blank lines and comments may sit between the two; any other statement may not.
        m = re.search(r"^env = base_env\(\)[ \t]*\n(?:[ \t]*(?:#.*)?\n)*gateway_epmd\.activate\(env\)",
                      self.src, re.M)
        self.assertIsNotNone(m, "test_gateway.py must call gateway_epmd.activate(env) on the "
                                "base_env() dict, before any suite-specific env is added")

    def test_the_wrapper_imports_the_helper_and_builds_the_env_once(self):
        self.assertRegex(self.src, r"(?m)^import gateway_epmd\b", "gateway_epmd must be imported")
        self.assertEqual(len(re.findall(r"^env = base_env\(\)", self.src, re.M)), 1,
                         "a second base_env() after activate() would drop the private port")

    def test_the_streamed_run_uses_that_env(self):
        self.assertRegex(self.src, r"popen_kwargs = dict\(\s*cwd=gateway_dir,\s*env=env\b",
                         "the rebar3 run must be started with the activated env")


if __name__ == "__main__":
    unittest.main()
