#!/usr/bin/env python3
"""Pin the gateway test wrapper's run-private epmd (#4853, scripts/gateway_epmd.py).

  1. the port pick and the isolate() decision (what it sets, what it leaves
     alone), against injected probes;
  2. find_epmd() and stop(): where epmd is looked for, and that cleanup can
     never raise;
  3. activate(): what a run says and registers for each of the three outcomes;
  4. scripts/test_gateway.py calls activate() on the env it hands to rebar3,
     right after base_env().

Hermetic: injected seams, plus one wildcard-bound listener to prove the real
probe refuses a held port. No epmd, no rebar3, no subprocess.
"""
import fnmatch
import functools
import os
import re
import socket
import subprocess
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

import gateway_epmd as ge  # noqa: E402

WRAPPER = os.path.join(ROOT, 'scripts', 'test_gateway.py')


class PickPortTest(unittest.TestCase):
    LOW = ge.PORT_RANGE[0]

    def test_starts_at_the_port_the_pid_maps_to_and_takes_the_first_free_one(self):
        seen = []

        def is_free(port):
            seen.append(port)
            return len(seen) == 3

        port = ge.pick_port(is_free, pid=lambda: 100)
        self.assertEqual(seen, [self.LOW + 100, self.LOW + 101, self.LOW + 102])
        self.assertEqual(port, self.LOW + 102)

    def test_concurrent_runs_start_at_distinct_ports(self):
        # Two wrapper processes alive together have different pids, so they cannot pick
        # one port before either epmd binds (a shared epmd would be killed by the first exit).
        first = [ge.pick_port(lambda p: True, pid=lambda pid=pid: pid) for pid in (4100, 4104, 4108)]
        self.assertEqual(len(set(first)), 3)

    def test_the_scan_wraps_at_the_end_of_the_range(self):
        span = ge.PORT_RANGE[1] - ge.PORT_RANGE[0] + 1
        seen = []
        ge.pick_port(lambda p: seen.append(p) or False, pid=lambda: span - 1)
        self.assertEqual(seen[:2], [ge.PORT_RANGE[1], self.LOW])

    def test_gives_up_after_a_bounded_number_of_tries(self):
        calls = []
        self.assertIsNone(ge.pick_port(lambda p: calls.append(p) or False, pid=lambda: 5))
        self.assertEqual(len(calls), 20)

    def test_range_stays_below_every_ephemeral_range(self):
        # Linux ephemeral starts at 32768; Windows and macOS at 49152.
        self.assertLess(ge.PORT_RANGE[1], 32768)
        self.assertGreater(ge.PORT_RANGE[0], 1024)


class PortProbeTest(unittest.TestCase):
    def test_a_held_port_is_not_free(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
            try:
                held.bind(("", 0))
            except OSError as exc:  # a sandbox that denies bind cannot run this probe test
                self.skipTest("cannot bind a socket here: %s" % exc)
            held.listen(1)
            self.assertFalse(ge.port_is_free(held.getsockname()[1]))


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

    def test_the_kill_check_stays_strict_so_a_cleanup_cannot_take_down_a_shared_epmd(self):
        # epmd refuses `-kill` while any node is registered unless ERL_EPMD_RELAXED_COMMAND_CHECK
        # is set (measured). Setting it would let one run's exit kill an epmd another run
        # still uses; leaving it unset only ever leaves this run's own epmd to the runner.
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
        self.assertEqual(registered, [])

    def test_the_default_isolation_is_isolate(self):
        env = {}
        port, said, registered = self.run_activate(
            env, functools.partial(ge.isolate, is_free=lambda p: True))
        self.assertEqual(registered[0][:2], (ge.stop, port))
        self.assertEqual(env["ERL_EPMD_PORT"], port)


class FindEpmdTest(unittest.TestCase):
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
        # Windows OTP: <root>/bin/erl.exe, but epmd.exe only in <root>/erts-<vsn>/bin,
        # beside epmd.pdb, which a bare `epmd*` glob sorts last (this shipped once and
        # made stop() try to run the symbols file, found on kingsley 2026-10-21).
        root = os.path.realpath(os.path.join(os.sep, "otp"))
        erl = os.path.join(root, "bin", "erl.exe")
        bindir = os.path.join(root, "erts-16.3.1", "bin")
        want = os.path.join(bindir, "epmd.exe")
        listing = [os.path.join(bindir, n) for n in
                   ("epmd.exe", "epmd.pdb", "erl.exe", "erlexec.dll", "epmdx.exe")]

        def glob_(pattern):
            return [p for p in listing if fnmatch.fnmatchcase(p, pattern)]

        def which(name, path=None):
            return erl if name == "erl" else None

        self.assertEqual(ge.find_epmd({"PATH": "x"}, which=which, glob_=glob_), want)

    def test_takes_the_newest_of_several_erts_dirs_by_version_not_by_string(self):
        # "erts-9.0" sorts after "erts-16.3.1" as a string; an OTP upgraded in place keeps both.
        hits = ["/otp/erts-9.0/bin/epmd", "/otp/erts-16.3.1/bin/epmd", "/otp/erts-15.2/bin/epmd"]
        got = ge.find_epmd({}, which=lambda n, path=None: "/otp/bin/erl" if n == "erl" else None,
                           glob_=lambda p: list(hits))
        self.assertEqual(got, "/otp/erts-16.3.1/bin/epmd")

    def test_no_erl_and_no_epmd_is_none(self):
        self.assertIsNone(ge.find_epmd({}, which=lambda n, path=None: None,
                                       glob_=lambda p: self.fail("no erl, no glob")))

    def test_an_erl_whose_install_has_no_epmd_is_none(self):
        self.assertIsNone(ge.find_epmd({}, which=lambda n, path=None: "/o/bin/erl" if n == "erl" else None,
                                       glob_=lambda p: []))


class StopTest(unittest.TestCase):
    def test_kills_the_run_private_epmd_with_the_runs_env(self):
        calls = []
        env = {"PATH": "p", "ERL_EPMD_PORT": "24242"}

        def run(args, **kw):
            calls.append((args, kw))

        ok = ge.stop("24242", env, which=lambda name, path=None: "/otp/bin/epmd", run=run)
        self.assertTrue(ok)
        self.assertEqual(calls[0][0], ["/otp/bin/epmd", "-port", "24242", "-kill"])
        self.assertIs(calls[0][1]["env"], env)
        self.assertEqual(calls[0][1]["timeout"], 10)

    def test_no_epmd_anywhere_means_no_call(self):
        self.assertFalse(ge.stop("24242", {"PATH": "/otp/bin"},
                                 which=lambda name, path=None: None,
                                 run=lambda *a, **k: self.fail("no epmd, no call"),
                                 glob_=lambda pattern: []))

    def test_never_raises(self):
        def boom(args, **kw):
            raise subprocess.TimeoutExpired(args, 10)

        self.assertFalse(ge.stop("1", {}, which=lambda n, path=None: "/e", run=boom))

        def oserr(args, **kw):
            raise OSError("gone")

        self.assertFalse(ge.stop("1", {}, which=lambda n, path=None: "/e", run=oserr))


class WrapperWiringTest(unittest.TestCase):
    def setUp(self):
        with open(WRAPPER, encoding="utf-8") as f:
            self.src = f.read()

    def test_activates_the_env_it_hands_to_rebar3_right_after_base_env(self):
        m = re.search(r"^env = base_env\(\)\n(?:#.*\n)*gateway_epmd\.activate\(env\)\n",
                      self.src, re.M)
        self.assertIsNotNone(m, "test_gateway.py must call gateway_epmd.activate(env) on the "
                                "base_env() dict, before any suite-specific env is added")

    def test_the_streamed_run_uses_that_env(self):
        self.assertRegex(self.src, r"popen_kwargs = dict\(\n\s+cwd=gateway_dir,\n\s+env=env,")


if __name__ == "__main__":
    unittest.main()
