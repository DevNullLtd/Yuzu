#!/usr/bin/env python3
"""Pin the gateway test wrapper's run-private epmd (#4853).

The multinode eunit modules boot Erlang distribution and `peer` nodes through
the host's one epmd. On the shared self-hosted Windows box the runner's
"Complete job" step kills that epmd as an orphan whenever ANY job on the box
completes, so a concurrent job's next `peer:start_link` times out (two PRs'
Windows legs on 2026-10-21, 28-50 s after another job on the box finished).
scripts/gateway_epmd.py gives each wrapper run its own ERL_EPMD_PORT; this file
pins:

  1. the port pick and the isolate() decision (what it sets, what it leaves
     alone), against injected probes;
  2. stop() as best-effort cleanup that can never raise;
  3. scripts/test_gateway.py really calls isolate() on the env it hands to
     rebar3, right after base_env(), and registers stop() for exit.

Hermetic: injected seams, plus one loopback listener to prove the real probe
refuses a held port. No epmd, no rebar3, no subprocess.
"""
import os
import random
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
    def test_returns_the_first_free_candidate_inside_the_range(self):
        seen = []

        def is_free(port):
            seen.append(port)
            return len(seen) == 3

        port = ge.pick_port(is_free, rng=random.Random(7))
        self.assertEqual(port, seen[2])
        self.assertEqual(len(seen), 3)
        for p in seen:
            self.assertTrue(ge.PORT_RANGE[0] <= p <= ge.PORT_RANGE[1])

    def test_gives_up_after_a_bounded_number_of_tries(self):
        calls = []
        self.assertIsNone(ge.pick_port(lambda p: calls.append(p) or False,
                                       rng=random.Random(1)))
        self.assertEqual(len(calls), 20)

    def test_range_stays_below_every_ephemeral_range(self):
        # Linux ephemeral starts at 32768; Windows and macOS at 49152.
        self.assertLess(ge.PORT_RANGE[1], 32768)
        self.assertGreater(ge.PORT_RANGE[0], 1024)


class PortProbeTest(unittest.TestCase):
    def test_a_held_port_is_not_free(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
            held.bind(("", 0))
            held.listen(1)
            self.assertFalse(ge.port_is_free(held.getsockname()[1]))


class IsolateTest(unittest.TestCase):
    def test_sets_a_private_port_when_none_is_configured(self):
        env = {"PATH": "x"}
        got = ge.isolate(env, is_free=lambda p: True, rng=random.Random(3))
        self.assertEqual(env["ERL_EPMD_PORT"], got)
        self.assertTrue(ge.PORT_RANGE[0] <= int(got) <= ge.PORT_RANGE[1])
        self.assertEqual(env["PATH"], "x")

    def test_an_explicit_port_is_the_operators_isolation_and_wins(self):
        env = {"ERL_EPMD_PORT": "9999"}
        got = ge.isolate(env, is_free=lambda p: self.fail("must not probe"))
        self.assertIsNone(got)
        self.assertEqual(env["ERL_EPMD_PORT"], "9999")

    def test_an_empty_value_counts_as_unset(self):
        env = {"ERL_EPMD_PORT": ""}
        got = ge.isolate(env, is_free=lambda p: True, rng=random.Random(4))
        self.assertEqual(env["ERL_EPMD_PORT"], got)
        self.assertNotEqual(got, "")

    def test_no_free_port_leaves_the_environment_alone(self):
        env = {}
        self.assertIsNone(ge.isolate(env, is_free=lambda p: False, rng=random.Random(5)))
        self.assertNotIn("ERL_EPMD_PORT", env)


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

    def test_windows_layout_finds_epmd_under_the_erts_dir_of_the_erl_on_path(self):
        # Windows OTP: <root>/bin/erl.exe, but epmd.exe only in <root>/erts-<vsn>/bin.
        root = os.path.join(os.sep, "otp")
        erl = os.path.join(root, "bin", "erl.exe")
        want = os.path.join(root, "erts-16.3.1", "bin", "epmd.exe")
        patterns = []

        def glob_(pattern):
            patterns.append(pattern)
            return [want]

        def which(name, path=None):
            return erl if name == "erl" else None

        self.assertEqual(ge.find_epmd({"PATH": "x"}, which=which, glob_=glob_), want)
        self.assertEqual(patterns, [os.path.join(os.path.realpath(root), "erts-*", "bin", "epmd*")])

    def test_takes_the_last_of_several_erts_dirs(self):
        hits = ["/otp/erts-15.0/bin/epmd", "/otp/erts-16.3.1/bin/epmd"]
        got = ge.find_epmd({}, which=lambda n, path=None: "/otp/bin/erl" if n == "erl" else None,
                           glob_=lambda p: list(reversed(hits)))
        self.assertEqual(got, hits[-1])

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

    def test_isolates_the_env_it_hands_to_rebar3_right_after_base_env(self):
        m = re.search(r"^env = base_env\(\)\n(?:#.*\n)*_epmd_port = gateway_epmd\.isolate\(env\)\n",
                      self.src, re.M)
        self.assertIsNotNone(m, "test_gateway.py must call gateway_epmd.isolate(env) on the "
                                "base_env() dict, before any suite-specific env is added")

    def test_registers_stop_for_exit_with_the_same_env(self):
        self.assertIn("atexit.register(gateway_epmd.stop, _epmd_port, env)", self.src)

    def test_the_streamed_run_uses_that_env(self):
        self.assertRegex(self.src, r"popen_kwargs = dict\(\n\s+cwd=gateway_dir,\n\s+env=env,")


if __name__ == "__main__":
    unittest.main()
