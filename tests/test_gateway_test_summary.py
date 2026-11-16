#!/usr/bin/env python3
"""Pin the Meson gateway test wrapper's #4800 guarantees.

#4800: the `gateway ct` Meson test ran `rebar3 ct` with no `--dir`, so it
discovered zero suites, printed "All 0 tests passed." and exited 0 on every
platform, hiding #4707 and #4708. This file pins three things so that
cannot silently come back:

  1. scripts/gateway_test_summary.py's summary parser and zero-executed
     guard, against every rebar3 ct/eunit summary shape it must handle;
  2. scripts/test_gateway.py still points ct at the directory the CT suites
     actually live in, and still routes every exit through the guard;
  3. each suite's wrapper deadline stays BELOW its meson timeout, so the
     wrapper's pre-kill process-tree dump is reachable.

Hermetic: parses sources, runs the parser CLI, and owns short-lived Python
children to check deadlines (no real rebar3, network, or shared paths).
"""
import ast
import glob
import io
import json
import os
import queue
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

import gateway_test_summary as gts  # noqa: E402

WRAPPER = os.path.join(ROOT, 'scripts', 'test_gateway.py')
MESON = os.path.join(ROOT, 'meson.build')
CT_DIR = os.path.join(ROOT, 'gateway', 'apps', 'yuzu_gw', 'test', 'ct')


def _read(path):
    with open(path, encoding='utf-8') as f:
        return f.read()


class ExecutedCount(unittest.TestCase):

    def test_summary_shapes(self):
        cases = {
            # ct. The three lines marked CAPTURED are verbatim output of
            # `rebar3 as test ct --dir apps/yuzu_gw/test/ct
            # --suite=yuzu_gw_e2e_SUITE` run locally with rebar3 3.27.0 on
            # OTP 28.4.2 (the failing and skipping ones with a scratch-only
            # broken assertion / init_per_testcase skip), including the
            # trailing space rebar3 prints. rebar3 CT never singularises
            # "test(s)": "Failed 1 tests." is the real wording. The other
            # lines come from the format strings in rebar3's CT provider
            # (extracted from the 3.24.0 binary, the CI pin, during the PR
            # review), not from a capture.
            'All 52 tests passed.': 52,
            'All 5 tests passed.': 5,                                    # CAPTURED
            'Failed 1 tests. Passed 4 tests. ': 5,                       # CAPTURED
            'Failed 1 tests. Skipped 1 (1, 0) tests. Passed 3 tests. ': 4,  # CAPTURED
            'Failed 6 tests. Skipped 2 (0, 2) tests. Passed 44 tests. ': 50,
            'Skipped 2 (2, 0) tests. Passed 44 tests.': 44,
            'Failed 5 tests. Passed 0 tests.': 5,
            # a CRLF-terminated variant of the captured line above
            'Failed 1 tests. Passed 4 tests. \r\n': 5,
            # eunit
            '  All 324 tests passed.': 324,
            '  Failed: 2.  Skipped: 0.  Passed: 309.': 311,
            '  Test passed.': 1,
            '  2 tests passed.': 2,
            'There were no tests to run.': 0,
            # the #4800 false green itself
            '\x1b[0mAll 0 tests passed.\r\n': 0,
            # ANSI colouring around the summary (rebar3 default)
            '\x1b[0;32mAll 52 tests passed.\x1b[0m\r\n': 52,
        }
        for text, want in cases.items():
            with self.subTest(text=text):
                self.assertEqual(gts.executed_count(text), want)

    def test_no_summary_is_none(self):
        self.assertIsNone(gts.executed_count('===> Compiling yuzu_gw\n'))
        self.assertIsNone(gts.executed_count(''))

    def test_truncated_capture_fails_closed(self):
        # #4800 Gate 5 CH-1: output cut before rebar3's summary must never
        # read as a pass, including when a test's own log text CONTAINS a
        # summary-shaped phrase (anchoring), a line is cut mid-way, or an
        # ANSI escape is split by the cut.
        real = ('%%% yuzu_gw_e2e_SUITE: ....\n'
                '*** log: All 5 tests passed. (fixture noise)\n'
                'agent said "Passed 3 tests." earlier\n'
                '\x1b[0mAll 52 tests passed.\n')
        cut = real.index('\x1b[0mAll 52')
        for n in range(0, cut + 1):
            with self.subTest(cut=n):
                self.assertEqual(gts.require_tests_executed(real[:n], 'ct', 0), 1)
        for partial in ('All 5', '\x1b[0mAll 52 tests pass', '\x1b[', '\x1b[0'):
            with self.subTest(partial=partial):
                self.assertEqual(
                    gts.require_tests_executed(real[:cut] + partial, 'ct', 0), 1)
        self.assertEqual(gts.require_tests_executed(real, 'ct', 0), 0)

    def test_last_summary_wins(self):
        self.assertEqual(
            gts.executed_count('All 3 tests passed.\n...\n  All 311 tests passed.\n'), 311)

    def test_several_genuine_summaries_last_one_decides(self):
        # Documents the limit of "last summary wins". Today `rebar3 ct` is
        # run once with a single --dir, so one genuine summary is printed.
        # A future `--spec` run (or any invocation that makes rebar3 print a
        # summary per group) could print several GENUINE summary lines; the
        # parser then judges only the last one, so an early failing run
        # followed by a passing one reads as a pass and the reverse reads as
        # a fail. This pins that outcome so changing the invocation shape
        # forces a decision here rather than going unnoticed.
        failed_then_passed = ('Failed 1 tests. Passed 4 tests. \n'
                              'All 5 tests passed.\n')
        passed_then_failed = ('All 5 tests passed.\n'
                              'Failed 1 tests. Passed 4 tests. \n')
        self.assertEqual(gts.last_summary(failed_then_passed), (5, 0, False))
        self.assertEqual(gts.last_summary(passed_then_failed), (5, 1, False))
        # A zero-executed LAST summary still fails the run.
        self.assertEqual(gts.require_tests_executed(
            'All 5 tests passed.\nAll 0 tests passed.\n', 'ct', 0), 1)


class RequireTestsExecuted(unittest.TestCase):

    def test_zero_executed_fails_a_green_run(self):
        self.assertEqual(gts.require_tests_executed('All 0 tests passed.', 'ct', 0), 1)
        self.assertEqual(gts.require_tests_executed('There were no tests to run.', 'eunit', 0), 1)

    def test_missing_summary_fails_a_green_run(self):
        self.assertEqual(gts.require_tests_executed('===> Running Common Test suites...', 'ct', 0), 1)

    def test_real_run_passes(self):
        self.assertEqual(gts.require_tests_executed('All 52 tests passed.', 'ct', 0), 0)

    def test_nonzero_rc_passes_through_unchanged(self):
        self.assertEqual(gts.require_tests_executed('Failed 6 tests. Passed 44 tests.', 'ct', 1), 1)
        self.assertEqual(gts.require_tests_executed('', 'ct', -1), -1)

    def test_failed_or_cancelled_output_cannot_pass_even_with_zero_status(self):
        for text in ('Failed 1 tests. Passed 4 tests.',
                     'Failed: 1.  Skipped: 0.  Passed: 4.',
                     'Failed: 0.  Skipped: 0.  Passed: 1.\n'
                     'One or more tests were cancelled.'):
            with self.subTest(text=text):
                self.assertEqual(gts.require_tests_executed(text, 'eunit', 0), 1)


class FailureDiagnostics(unittest.TestCase):

    def report(self, output, code, **kwargs):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = gts.require_tests_executed(output, 'eunit shard 1/2', code, **kwargs)
        return result, stderr.getvalue()

    def test_early_generator_error_survives_a_long_successful_tail(self):
        output = ('module fixture_tests\n'
                  '  *** test generator fixture_tests:validity_test_/0 failed ***\n'
                  '**in function crypto:sign/5\n'
                  '**error:signature_digest_rejected\n' + 'passing fixture noise\n' * 500 +
                  'Failed: 0.  Skipped: 0.  Passed: 711.\n'
                  'One or more tests were cancelled.\n')
        code, diagnostic = self.report(output, 1)
        self.assertEqual(code, 1)
        self.assertIn('fixture_tests:validity_test_/0', diagnostic)
        self.assertIn('signature_digest_rejected', diagnostic)
        self.assertIn('711', diagnostic)
        self.assertIn('cancelled', diagnostic)
        self.assertLess(len(diagnostic.splitlines()), 80)

    def test_child_status_is_preserved_without_inventing_cancellation(self):
        code, diagnostic = self.report('native process crashed\n', 42)
        self.assertEqual(code, 42)
        self.assertIn('42', diagnostic)
        self.assertIn('native process crashed', diagnostic)
        self.assertNotIn('cancellation', diagnostic)

    def test_ct_failure_and_ansi_generator_context_are_visible(self):
        for failure in ('%%% fixture_SUITE ==> failed_case: FAILED\nreason: expected_true\n',
                        '\x1b[31m*** context setup failed ***\x1b[0m\n'
                        '**error:expected_true\n'):
            with self.subTest(failure=failure):
                code, diagnostic = self.report(failure + 'noise\n' * 200, 7)
                self.assertEqual(code, 7)
                self.assertIn('expected_true', diagnostic)
                self.assertNotIn('\x1b[', diagnostic)

    def test_failure_logs_are_complete_and_never_overwrite_an_attempt(self):
        output = '*failed*\n**error:fixture_failure\n' + 'native output\n' * 500
        with tempfile.TemporaryDirectory(prefix='yuzu_test_gateway_logs_') as directory:
            for _ in range(2):
                code, diagnostic = self.report(output, 1, log_dir=directory)
                self.assertEqual(code, 1)
                self.assertIn('Full gateway output:', diagnostic)
            logs = glob.glob(os.path.join(directory, '*.log'))
            self.assertEqual(len(logs), 2)
            self.assertTrue(all(_read(path) == output for path in logs))

    def test_log_write_error_does_not_hide_native_failure(self):
        with tempfile.TemporaryDirectory(prefix='yuzu_test_gateway_logs_') as directory:
            blocked = os.path.join(directory, 'not_a_directory')
            with open(blocked, 'w') as stream:
                stream.write('occupied')
            code, diagnostic = self.report('*failed*\n**error:fixture_failure\n', 7,
                                           log_dir=blocked)
            self.assertEqual(code, 7)
            self.assertIn('fixture_failure', diagnostic)
            self.assertIn('could not save', diagnostic)

    def test_failed_close_does_not_advertise_a_complete_log(self):
        class FailedClose(io.StringIO):
            name = 'partial.log'

            def __exit__(self, *args):
                super().__exit__(*args)
                raise OSError('disk full during close')

        with tempfile.TemporaryDirectory(prefix='yuzu_test_gateway_logs_') as directory:
            with patch.object(gts.tempfile, 'NamedTemporaryFile', return_value=FailedClose()):
                code, diagnostic = self.report('*failed*\n', 7, log_dir=directory)
        self.assertEqual(code, 7)
        self.assertIn('could not save', diagnostic)
        self.assertNotIn('Full gateway output:', diagnostic)

    @unittest.skipUnless(shutil.which('meson'), 'Meson executable is required')
    def test_real_child_status_and_early_error_reach_mesons_console_tail(self):
        # Run the actual wrapper under Meson. Only the rebar/OTP dependency is
        # replaced: a real child emits both streams, then hundreds of later lines.
        with tempfile.TemporaryDirectory(prefix='yuzu_test_gateway_meson_') as directory:
            child = os.path.join(directory, 'child.py')
            driver = os.path.join(directory, 'invoke.py')
            gateway = os.path.join(directory, 'gateway')
            os.mkdir(gateway)
            with open(child, 'w', encoding='utf-8') as stream:
                stream.write(
                    'import sys\n'
                    'sys.stdout.buffer.write(b"native diagnostic: \\xe2\\x95\\x90\\xff\\n")\n'
                    'print("*** test generator fixture:broken_test_/0 failed ***", flush=True)\n'
                    'print("**in function crypto:sign/5\\n**error:original_otp_reason", '
                    'file=sys.stderr, flush=True)\n'
                    'print("later passing output\\n" * 400, flush=True)\n'
                    'print("Failed: 0.  Skipped: 0.  Passed: 711.\\n"\n'
                    '      "One or more tests were cancelled.", flush=True)\n'
                    'sys.exit(int(sys.argv[1]))\n')
            with open(driver, 'w', encoding='utf-8') as stream:
                stream.write(
                    'import os, runpy, subprocess, sys, types\n'
                    'status = sys.argv[1]\n'
                    'toolchain = types.ModuleType("erlang_toolchain")\n'
                    'toolchain.base_env = os.environ.copy\n'
                    f'toolchain.rebar3_prefix = lambda: [sys.executable, {child!r}, status]\n'
                    'toolchain.windows_stdio_isolation = lambda: {"stdin": subprocess.DEVNULL}\n'
                    'toolchain.kill_tree = lambda proc, timeout=10: proc.kill() is None\n'
                    'sys.modules["erlang_toolchain"] = toolchain\n'
                    'epmd = types.ModuleType("gateway_epmd")\n'
                    'epmd.activate = lambda env: None\n'
                    'sys.modules["gateway_epmd"] = epmd\n'
                    f'sys.argv = [{WRAPPER!r}, {gateway!r}, "eunit"]\n'
                    f'runpy.run_path({WRAPPER!r}, run_name="__main__")\n')
            python = sys.executable.replace('\\', '/').replace("'", "\\'")
            with open(os.path.join(directory, 'meson.build'), 'w', encoding='utf-8') as stream:
                stream.write(
                    "project('gateway-diagnostics')\n"
                    f"python = find_program('{python}')\n"
                    "foreach code : ['0', '42']\n"
                    "  test('gateway-' + code, python, args: ['invoke.py', code],\n"
                    "    workdir: meson.current_source_dir(), timeout: 10,\n"
                    "    env: {'YUZU_GATEWAY_TEST_LOG_DIR': meson.project_build_root() / 'meson-logs'})\n"
                    "endforeach\n")
            env = os.environ.copy()
            for name in ('MESON_BUILD_ROOT', 'REBAR_BASE_DIR', 'YUZU_GATEWAY_TEST_LOG_DIR'):
                env.pop(name, None)
            env['PYTHONIOENCODING'] = 'cp1252'
            build = os.path.join(directory, 'build')
            # This whole selftest has a 30 s Meson budget. Bound the two
            # nested children to at most half of it together; they compile no
            # targets and each fake test exits immediately.
            setup = subprocess.run(['meson', 'setup', build, directory], env=env,
                                   capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5)
            self.assertEqual(setup.returncode, 0, setup.stdout + setup.stderr)
            run = subprocess.run(['meson', 'test', '-C', build, '--no-rebuild',
                                  '--print-errorlogs', '--num-processes', '1'], env=env,
                                 capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
            self.assertNotEqual(run.returncode, 0)
            console = run.stdout + run.stderr
            self.assertIn('original_otp_reason', console)
            self.assertIn('native diagnostic:', console)
            self.assertIn('fixture:broken_test_/0', console)
            self.assertIn('Full gateway output:', console)
            with open(os.path.join(build, 'meson-logs', 'testlog.json'), encoding='utf-8') as stream:
                native = [json.loads(line) for line in stream if line.strip()]
            self.assertEqual(sorted(row['returncode'] for row in native), [1, 42])
            logs = glob.glob(os.path.join(build, 'meson-logs', 'yuzu_test_gateway_*.log'))
            self.assertEqual(len(logs), 2)
            self.assertTrue(all(_read(path).count('later passing output') == 400 for path in logs))
            self.assertTrue(all('native diagnostic: \u2550\ufffd' in _read(path) for path in logs))


class WrapperDeadline(unittest.TestCase):
    # The wrapper executes rebar3 at import time. Load its actual function
    # definitions without running its CLI setup; only the diagnostic listing
    # and tree kill are replaced, since these tests own a single Python child.
    def functions(self, **overrides):
        tree = ast.parse(_read(WRAPPER))
        definitions = ast.Module(body=[n for n in tree.body
                                       if isinstance(n, ast.FunctionDef)], type_ignores=[])
        namespace = dict(queue=queue, threading=threading, time=time, sys=sys,
                         subprocess=subprocess, os=os,
                         HEX_FAIL_PATTERN='Failed to fetch and copy dep:',
                         _RUN_DEADLINE_SECS=10)
        exec(compile(definitions, WRAPPER, 'exec'), namespace)
        namespace.update(_dump_process_tree=lambda: None,
                         _kill_process_tree=lambda proc: proc.kill())
        namespace.update(overrides)
        return namespace

    def test_stream_replaces_invalid_utf8_without_losing_the_summary(self):
        # rebar3's output can include bytes from native tools. One bad byte
        # must neither kill the reader nor discard the later terminal result.
        ns = self.functions(gateway_dir=ROOT, env=os.environ.copy(),
                            windows_stdio_isolation=lambda: {})
        child = [sys.executable, '-c',
                 'import os; os.write(1, b"diagnostic: \\xe2\\x95\\x90\\xff\\nAll 2 tests passed.\\n")']
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc, output = ns['_run_streamed'](child, 5)
        self.assertEqual(rc, 0)
        self.assertIn('diagnostic: \u2550\ufffd', output)
        self.assertIn('All 2 tests passed.', output)

    def test_output_eof_does_not_end_the_process_deadline(self):
        # Real EOF while the child stays alive: previously the timed reader
        # exited and proc.wait() then waited forever. The child has its own
        # finite backstop and is reaped even if the assertion fails.
        proc = subprocess.Popen(
            [sys.executable, '-c',
             'import os,time; print("before EOF",flush=True); '
             'os.close(1); os.close(2); time.sleep(5)'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
        try:
            started = time.monotonic()
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
                rc, output = self.functions()['_stream_until_exit'](proc, 0.5)
            self.assertNotEqual(rc, 0)
            self.assertLess(time.monotonic() - started, 4)
            self.assertIn('DEADLINE EXCEEDED', err.getvalue())
            self.assertIn('before EOF', output)
            self.assertIsNotNone(proc.poll())
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
            proc.stdout.close()

    def test_eof_from_a_successfully_exited_child_still_passes(self):
        with subprocess.Popen([sys.executable, '-c', 'print("All 2 tests passed.")'],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, encoding="utf-8", errors="replace") as proc:
            with redirect_stdout(io.StringIO()):
                rc, output = self.functions()['_stream_until_exit'](proc, 5)
            self.assertEqual(rc, 0)
            self.assertEqual(output.strip(), 'All 2 tests passed.')

    def test_exit_zero_during_deadline_cleanup_does_not_turn_green(self):
        proc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(0.3)'],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
        try:
            # Simulate the child naturally finishing while diagnostics run,
            # before the kill reaches it. Its final status is genuinely 0.
            ns = self.functions(_dump_process_tree=lambda: proc.wait(timeout=5),
                                _kill_process_tree=lambda proc: None)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                rc, _ = ns['_stream_until_exit'](proc, 0.01)
            self.assertEqual(proc.returncode, 0)
            self.assertNotEqual(rc, 0)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
            proc.stdout.close()

    def test_retries_share_one_deadline_including_backoff(self):
        now = [0]
        budgets, sleeps = [], []

        def run(args, budget):
            budgets.append(budget)
            now[0] += 4 if len(budgets) == 1 else 0.5
            return (1, 'Failed to fetch and copy dep: x') if len(budgets) == 1 else (0, 'pass')

        def sleep(delay):
            sleeps.append(delay)
            now[0] += delay

        ns = self.functions(time=SimpleNamespace(monotonic=lambda: now[0], sleep=sleep),
                            _run_streamed=run)
        with redirect_stderr(io.StringIO()):
            result = ns['run_with_retry']([], 'eunit')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(budgets, [10, 1])
        self.assertEqual(sleeps, [5])

    def test_retry_is_not_started_when_backoff_would_exhaust_budget(self):
        now = [0]
        budgets = []

        def run(args, budget):
            budgets.append(budget)
            now[0] += 6
            return 1, 'Failed to fetch and copy dep: x'

        def sleep(delay):
            self.fail('must not wait beyond the remaining suite budget')

        ns = self.functions(time=SimpleNamespace(monotonic=lambda: now[0], sleep=sleep),
                            _run_streamed=run)
        with redirect_stderr(io.StringIO()):
            result = ns['run_with_retry']([], 'eunit')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(budgets, [10])


class StrictEUnitVerdict(unittest.TestCase):
    # All EUnit gates are strict. The old cancel-tolerant API/CLI remains
    # compatible in shape but must no longer turn cancellations green.

    def test_matrix(self):
        cases = [
            # (log, rc, expected exit, why)
            ('  All 300 tests passed.', 0, 0, 'green'),
            ('  2 tests passed.', 0, 0, 'two tests'),
            ('  Test passed.', 0, 0, 'one test'),
            ('  Failed: 0.  Skipped: 0.  Passed: 309.\nOne or more tests were cancelled.', 1, 1,
             'some sets cancelled (former #1005 tolerance)'),
            ('  Failed: 0.  Skipped: 0.  Passed: 0.\nOne or more tests were cancelled.', 1, 1,
             'ALL cancelled (#4800 C-1)'),
            ('  Failed: 2.  Skipped: 0.  Passed: 307.', 1, 1, 'real failure'),
            ('  There were no tests to run.', 0, 1, 'nothing discovered'),
            ('===> Compilation failed', 1, 1, 'rebar3 failed before tests'),
            ('*** log: All 5 tests passed. (noise)\n', 0, 1, 'embedded noise only'),
            ('  All 300 tests passed.', 1, 1, 'rc!=0 without a Failed: line'),
        ]
        for log, rc, want, why in cases:
            with self.subTest(why=why):
                self.assertEqual(gts.cancel_tolerant_verdict(log, rc)[0], want)

    def test_cli(self):
        script = os.path.join(ROOT, 'scripts', 'gateway_test_summary.py')
        with tempfile.TemporaryDirectory(prefix='yuzu_test_') as d:
            log = os.path.join(d, 'eunit.log')
            for text, rc, want in [('  All 3 tests passed.\n', '0', 0),
                                   ('  Failed: 0.  Skipped: 0.  Passed: 0.\n', '1', 1),
                                   ('  Failed: 0.  Skipped: 0.  Passed: 1.\n'
                                    'One or more tests were cancelled.\n', '1', 1)]:
                with open(log, 'w', encoding='utf-8') as f:
                    f.write(text)
                p = subprocess.run([sys.executable, script, 'cancel-tolerant', rc, log, '--github'],
                                   capture_output=True, text=True, encoding="utf-8", errors="replace")
                self.assertEqual(p.returncode, want, p.stdout + p.stderr)
            p = subprocess.run([sys.executable, script], capture_output=True, text=True, encoding="utf-8", errors="replace")
            self.assertEqual(p.returncode, 2)

    def test_shell_gates_use_this_parser(self):
        # A hand-written regex copy in either gate is how the CH-1 anchoring
        # fix reached only one of three gates; keep them on the shared parser.
        for path in (os.path.join(ROOT, 'scripts', 'test', 'eunit-gate.sh'),
                     os.path.join(ROOT, '.github', 'workflows', 'release.yml')):
            with self.subTest(path=path):
                self.assertRegex(_read(path), r'gateway_test_summary\.py"?\s+strict\s+eunit')

    def test_local_runner_judges_by_the_summary(self):
        # gateway/test_runner.sh (the documented local runner) used to trust
        # rebar3's exit code, so the #4800 false green survived there. Every
        # rebar3 test invocation must go through its `gated` helper, which
        # hands the capture to the same strict parser for both suites.
        src = _read(os.path.join(ROOT, 'gateway', 'test_runner.sh'))
        self.assertRegex(src, r'SUMMARY_PARSER="\$SCRIPT_DIR/\.\./scripts/gateway_test_summary\.py"')
        self.assertRegex(src, r'python3 "\$SUMMARY_PARSER" strict ')
        self.assertRegex(src, r'python3 "\$SUMMARY_PARSER" "\$mode" ')
        calls = re.findall(r'^\s*(?!#)(.*\brebar3 as test\b.*)$', src, re.M)
        self.assertEqual(len(calls), 4, calls)   # eunit and ct, each with/without cover
        for line in calls:
            with self.subTest(call=line):
                want = 'strict ct' if ' ct ' in line else 'strict eunit'
                self.assertRegex(line, r'^gated %s rebar3 as test ' % want)

    def test_strict_cli(self):
        script = os.path.join(ROOT, 'scripts', 'gateway_test_summary.py')
        with tempfile.TemporaryDirectory(prefix='yuzu_test_') as d:
            log = os.path.join(d, 'ct.log')
            for text, rc, want in [('All 5 tests passed.\n', '0', 0),
                                   ('All 0 tests passed.\n', '0', 1),
                                   ('no summary\n', '0', 1),
                                   ('Failed 1 tests. Passed 4 tests. \n', '1', 1)]:
                with open(log, 'w', encoding='utf-8') as f:
                    f.write(text)
                p = subprocess.run([sys.executable, script, 'strict', 'ct', rc, log],
                                   capture_output=True, text=True, encoding="utf-8", errors="replace")
                self.assertEqual(p.returncode, want, text + p.stdout + p.stderr)
            p = subprocess.run([sys.executable, script, 'strict', 'ct', '0'],
                               capture_output=True, text=True, encoding="utf-8", errors="replace")
            self.assertEqual(p.returncode, 2)


@unittest.skipUnless(shutil.which('bash') and os.name != 'nt',
                     'needs bash and a POSIX host (gateway/test_runner.sh is never run on Windows)')
class LocalRunnerBehaviour(unittest.TestCase):
    # The source-text pin above cannot see `rebar_rc=${PIPESTATUS[0]}` become
    # `$?` or `verdict=$?` become `verdict=0`. This runs the real script
    # against a stub `rebar3` on PATH and asserts its exit code. The runner is
    # executed in place (it resolves the parser relative to itself and cd's
    # into gateway/); only rebar3 is faked, and TMPDIR is a private dir.

    RUNNER = os.path.join(ROOT, 'gateway', 'test_runner.sh')
    STUB = (
        '#!/usr/bin/env bash\n'
        'case "$1" in compile) exit 0;; esac\n'
        'for a in "$@"; do\n'
        '  if [ "$a" = ct ]; then printf \'%s\\n\' "$STUB_CT_OUT"; exit "$STUB_CT_RC"; fi\n'
        '  if [ "$a" = eunit ]; then printf \'%s\\n\' "$STUB_EUNIT_OUT"; exit "$STUB_EUNIT_RC"; fi\n'
        'done\n'
        'exit 99\n')

    CT_PASS = ('All 5 tests passed.', 0)
    EU_PASS = ('  All 300 tests passed.', 0)

    # Copies stdin like the real tee, then exits non-zero.
    FAILING_TEE = '#!/bin/sh\ncommand -p tee "$@"\nexit 1\n'

    def _run(self, args, ct=CT_PASS, eunit=EU_PASS, tee_fails=False):
        with tempfile.TemporaryDirectory(prefix='yuzu_test_') as d:
            stubs = [('rebar3', self.STUB)] + ([('tee', self.FAILING_TEE)] if tee_fails else [])
            for name, body in stubs:
                stub = os.path.join(d, name)
                with open(stub, 'w', encoding='utf-8') as f:
                    f.write(body)
                os.chmod(stub, os.stat(stub).st_mode | stat.S_IXUSR)
            env = dict(os.environ, PATH=d + os.pathsep + os.environ['PATH'], TMPDIR=d,
                       STUB_CT_OUT=ct[0], STUB_CT_RC=str(ct[1]),
                       STUB_EUNIT_OUT=eunit[0], STUB_EUNIT_RC=str(eunit[1]))
            p = subprocess.run(['bash', self.RUNNER] + args, env=env,
                               capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
            return p.returncode, p.stdout + p.stderr

    def test_ct_verdict_comes_from_the_summary(self):
        cases = [
            # (stub ct output, stub rebar3 rc, expected exit, why)
            ('All 0 tests passed.', 0, 1, 'zero-test ct (the #4800 false green)'),
            ('Failed 1 tests. Passed 4 tests. ', 1, 1, 'ct failed'),
            ('===> Compiling yuzu_gw', 0, 1, 'ct printed no summary'),
            ('All 5 tests passed.', 1, 1, 'strict: rebar3 non-zero stays a failure'),
            ('All 5 tests passed.', 0, 0, 'ct pass'),
        ]
        for out, rc, want, why in cases:
            with self.subTest(why=why):
                got, log = self._run(['ct'], ct=(out, rc))
                self.assertEqual(got, want, log)

    def test_eunit_verdict_comes_from_the_summary(self):
        cancelled = '\nOne or more tests were cancelled.'
        cases = [
            ('  Failed: 0.  Skipped: 0.  Passed: 0.' + cancelled, 1, 1, 'every set cancelled'),
            ('  Failed: 0.  Skipped: 0.  Passed: 309.' + cancelled, 1, 1, 'partial cancellation fails'),
            ('  Failed: 2.  Skipped: 0.  Passed: 307.', 1, 1, 'real failure'),
            ('  All 300 tests passed.', 1, 1, 'rc != 0 without a Failed: line'),
            ('  There were no tests to run.', 0, 1, 'nothing discovered'),
            ('  All 300 tests passed.', 0, 0, 'eunit pass'),
        ]
        for out, rc, want, why in cases:
            with self.subTest(why=why):
                got, log = self._run(['eunit'], eunit=(out, rc))
                self.assertEqual(got, want, log)

    def test_test_pipeline_eunit_gate_also_rejects_partial_cancellation(self):
        self.RUNNER = os.path.join(ROOT, 'scripts', 'test', 'eunit-gate.sh')
        cancelled = ('Failed: 0.  Skipped: 0.  Passed: 1.\n'
                     'One or more tests were cancelled.')
        for rc in (0, 1):
            with self.subTest(rebar_status=rc):
                got, log = self._run([], eunit=(cancelled, rc))
                self.assertNotEqual(got, 0, log)
        got, log = self._run([])
        self.assertEqual(got, 0, log)

    def test_verdict_uses_rebar3_status_not_the_pipeline_status(self):
        # Under `set -o pipefail` a bare `$?` equals PIPESTATUS[0] unless the
        # pipeline's other stage (tee) fails, so only a failing tee tells
        # `rebar_rc=${PIPESTATUS[0]}` from `rebar_rc=$?`: a green ct run whose
        # capture was copied intact must still pass, and a red one still fail.
        self.assertEqual(self._run(['ct'], tee_fails=True)[0], 0)
        self.assertEqual(self._run(['ct'], ct=('All 5 tests passed.', 1), tee_fails=True)[0], 1)

    def test_default_runs_both_and_counts_either_failure(self):
        zero = ('All 0 tests passed.', 0)
        bad_eunit = ('  Failed: 2.  Skipped: 0.  Passed: 307.', 1)
        self.assertEqual(self._run([])[0], 0)
        self.assertEqual(self._run([], ct=zero)[0], 1)
        self.assertEqual(self._run([], eunit=bad_eunit)[0], 1)
        self.assertEqual(self._run([], ct=zero, eunit=bad_eunit)[0], 2)


class WrapperWiring(unittest.TestCase):

    def test_ct_dir_points_at_the_suites(self):
        src = _read(WRAPPER)
        m = re.search(r'if suite == "ct":\s*\n(?:\s*#.*\n)*\s*cmd \+= \["--dir", "([^"]+)"\]', src)
        self.assertIsNotNone(m, 'test_gateway.py no longer passes --dir for ct (#4800)')
        ct_dir = os.path.join(ROOT, 'gateway', *m.group(1).split('/'))
        self.assertEqual(os.path.normpath(ct_dir), os.path.normpath(CT_DIR))
        suites = [f for f in os.listdir(CT_DIR) if f.endswith('_SUITE.erl')]
        self.assertTrue(suites, f'no *_SUITE.erl under {CT_DIR}')

    def test_every_exit_goes_through_the_guard(self):
        # An AST walk, not a line regex: a call split over several lines
        # (or written `exit(...)` / `os._exit(...)`) must still be judged.
        tree = ast.parse(_read(WRAPPER))

        def is_exit(node):
            f = node.func
            if isinstance(f, ast.Name):
                return f.id in ('exit', 'quit')
            return (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
                    and (f.value.id, f.attr) in (('sys', 'exit'), ('os', '_exit')))

        exits = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and is_exit(n)]
        self.assertTrue(exits)
        for node in exits:
            with self.subTest(line=node.lineno):
                guarded = any(
                    isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                    and c.func.id == '_require_tests_executed'
                    for arg in node.args for c in ast.walk(arg))
                self.assertTrue(guarded, f'exit at line {node.lineno} bypasses the guard')

    def test_deadline_is_below_meson_timeout(self):
        m = re.search(r'_SUITE_DEADLINE_SECS = \{(.*?)\}', _read(WRAPPER), re.S)
        self.assertIsNotNone(m)
        deadlines = {k: int(v) for k, v in re.findall(r'"(\w+)":\s*(\d+)', m.group(1))}
        meson = _read(MESON)
        # eunit is registered once per shard from a foreach, so its name is
        # built by concatenation; the one timeout there covers every shard.
        names = {'eunit': r"test\('gateway eunit shard ' \+", 'ct': r"test\('gateway ct',"}
        for suite in ('eunit', 'ct'):
            with self.subTest(suite=suite):
                t = re.search(names[suite] + r".*?timeout:\s*(\d+)", meson, re.S)
                self.assertIsNotNone(t, f"meson test 'gateway {suite}' not found")
                self.assertIn(suite, deadlines)
                # Leave room for the dump + kill + 15s wait in _run_streamed.
                self.assertLessEqual(deadlines[suite] + 30, int(t.group(1)))


class AssertGatewayTests(unittest.TestCase):
    # #4841: every CI leg asserts, right after `meson setup`, that the gateway
    # tests were registered (a missing rebar3 otherwise skips them silently).

    SCRIPT = os.path.join(ROOT, 'scripts', 'ci', 'assert-gateway-tests.py')
    WORKFLOWS = ('ci.yml', 'nightly.yml', 'sanitizer-tests.yml')
    # The workflow canary only compiles (it never runs `meson test`), so it
    # has no gateway tests to lose. Exempted by its STEP NAME, not its build
    # dir, so a future test-running leg that reuses the dir name is still checked.
    EXEMPT_STEPS = {('ci.yml', 'Configure (Meson, gcc-13 debug)')}

    def _run(self, tests):
        with tempfile.TemporaryDirectory(prefix='yuzu_test_') as d:
            if tests is not None:
                os.makedirs(os.path.join(d, 'meson-info'))
                with open(os.path.join(d, 'meson-info', 'intro-tests.json'), 'w', encoding='utf-8') as f:
                    json.dump(tests, f)
            return subprocess.run([sys.executable, self.SCRIPT, d],
                                  capture_output=True, text=True, encoding="utf-8", errors="replace").returncode

    def test_verdicts(self):
        names = ['gateway eunit shard A', 'gateway eunit shard B', 'gateway eunit shard C',
                 'gateway ct']
        every = [{'name': n} for n in names] + [{'name': 'x'}]
        self.assertEqual(self._run(every), 0)
        for missing in names:
            with self.subTest(missing=missing):
                self.assertEqual(self._run([t for t in every if t['name'] != missing]), 1)
        # The pre-shard single entry no longer satisfies the check.
        self.assertEqual(self._run([{'name': 'gateway eunit'}, {'name': 'gateway ct'}]), 1)
        self.assertEqual(self._run([]), 1)
        self.assertEqual(self._run(None), 1)   # not configured / unreadable

    def test_every_meson_setup_is_followed_by_the_assertion(self):
        # And never by -Drequire_gateway: a non-default project option stored
        # in a persistent, branch-shared build dir breaks every later
        # `--reconfigure` from a branch whose meson.options predates it.
        for wf in self.WORKFLOWS:
            text = _read(os.path.join(ROOT, '.github', 'workflows', wf))
            self.assertNotIn('-Drequire_gateway', text, wf)
            lines = text.split('\n')
            step = None
            for i, line in enumerate(lines):
                sm = re.match(r'\s*- name:\s*(.+?)\s*$', line)
                if sm:
                    step = sm.group(1)
                m = re.match(r'\s*meson setup (?:\$reconfig )?(\S+)', line)
                if not m or (wf, step) in self.EXEMPT_STEPS:
                    continue
                j = i
                while lines[j].rstrip().endswith('\\'):
                    j += 1
                with self.subTest(workflow=wf, line=i + 1):
                    a = re.match(r'\s*python3? scripts/ci/assert-gateway-tests\.py (\S+)\s*$', lines[j + 1])
                    self.assertIsNotNone(a, lines[j + 1])
                    # It must check the dir meson just configured, not a
                    # sibling whose intro-tests.json could be stale.
                    self.assertEqual(a.group(1).strip('"'), m.group(1).strip('"'))

    # `meson test` / `meson  test` / `meson \<newline> test`, or the flake-retry
    # wrapper that runs it.
    TEST_RE = re.compile(r'\bmeson(?:\s|\\\n)+test\b|flake-retry\.py')
    ASSERT_RE = re.compile(r'scripts/ci/assert-gateway-tests\.py')
    # `|| true`, `|| :` or `|| exit 0` on the assert's own command line.
    MASKED_RE = re.compile(r'\|\|\s*(?:true\b|:(?=\s|$|;)|exit\s+0\b)')

    @staticmethod
    def _truthy(value):
        v = str(value).strip().lower()
        if v.startswith('${{') and v.endswith('}}'):
            v = v[3:-2].strip()
        return v in ('true', '1')

    @staticmethod
    def _falsey(value):
        v = str(value).strip().lower()
        if v.startswith('${{') and v.endswith('}}'):
            v = v[3:-2].strip()
        return v in ('false', '0')

    @classmethod
    def _gateway_assert_problem(cls, steps):
        """None if `steps` (one job) either runs no tests or asserts the
        gateway tests registered STRICTLY before the first test invocation,
        by a step that can actually fail; else a one-line reason.

        Order is judged by source position: (step index, char offset in the
        comment-stripped `run:` text), so an assert placed after `meson test`
        inside one `run:` block is still late. An assert that cannot fail
        (`|| true`, `continue-on-error: true`, an `if:` that is literally
        false) does not count."""
        first_test = None
        asserts = []
        for i, step in enumerate(steps or []):
            run = '\n'.join(l for l in str(step.get('run') or '').split('\n')
                            if not l.lstrip().startswith('#'))
            m = cls.TEST_RE.search(run)
            if m and first_test is None:
                first_test = (i, m.start())
            neutral = None
            if cls._truthy(step.get('continue-on-error', False)):
                neutral = 'continue-on-error: true'
            elif 'if' in step and cls._falsey(step['if']):
                neutral = 'a false if:'
            for a in cls.ASSERT_RE.finditer(run):
                lo = max((k.end() for k in re.finditer(r'(?<!\\)\n', run[:a.start()])), default=0)
                nl = re.search(r'(?<!\\)\n', run[a.end():])
                line = run[lo:a.end() + nl.start()] if nl else run[lo:]
                why = neutral or ('|| true on the assert line' if cls.MASKED_RE.search(line) else None)
                asserts.append(((i, a.start()), why))
        if first_test is None:
            return None
        if not asserts:
            return 'runs tests but never asserts the gateway tests registered'
        live = [pos for pos, why in asserts if why is None]
        if not live:
            return 'the assertion cannot fail (%s)' % asserts[0][1]
        if min(live) >= first_test:
            return 'the assertion does not run strictly before the first test invocation'
        return None

    def test_assert_ordering_rule_rejects_each_weakening(self):
        # The rule itself, on synthetic jobs: each mutant of a good job must
        # be rejected, and the good shapes accepted.
        good = [{'run': 'python3 scripts/ci/assert-gateway-tests.py b'},
                {'run': 'meson test -C b'}]
        problem = self._gateway_assert_problem
        self.assertIsNone(problem(good))
        self.assertIsNone(problem([{'run': 'x'}]))   # no tests, nothing to assert
        self.assertIsNone(problem([{'run': 'python3 scripts/ci/assert-gateway-tests.py b\n'
                                           'meson test -C b'}]))
        self.assertIsNone(problem([{'run': 'python3 scripts/ci/assert-gateway-tests.py b'},
                                   {'run': 'python3 scripts/ci/flake-retry.py -- x'}]))
        bad = {
            'assert after the test step': [good[1], good[0]],
            'assert after meson test in one run': [{'run': 'meson test -C b\n'
                                                           'python3 scripts/ci/assert-gateway-tests.py b'}],
            'assert after meson<2 spaces>test in one run': [{'run': 'meson  test -C b\n'
                                                                    'python3 scripts/ci/assert-gateway-tests.py b'}],
            'assert after meson<tab>test in one run': [{'run': 'meson\ttest -C b\n'
                                                               'python3 scripts/ci/assert-gateway-tests.py b'}],
            'assert after a continued meson test': [{'run': 'meson \\\n  test -C b\n'
                                                            'python3 scripts/ci/assert-gateway-tests.py b'}],
            'assert after flake-retry in one run': [{'run': 'python3 scripts/ci/flake-retry.py -- x\n'
                                                            'python3 scripts/ci/assert-gateway-tests.py b'}],
            'assert on the test line itself, after': [{'run': 'meson test -C b; '
                                                              'python3 scripts/ci/assert-gateway-tests.py b'}],
            'no assert at all': [good[1]],
            'assert only in a comment': [{'run': '# python3 scripts/ci/assert-gateway-tests.py b'}, good[1]],
            '|| true': [{'run': 'python3 scripts/ci/assert-gateway-tests.py b || true'}, good[1]],
            '|| true after a continuation': [{'run': 'python3 scripts/ci/assert-gateway-tests.py \\\n b || true'},
                                             good[1]],
            '|| :': [{'run': 'python3 scripts/ci/assert-gateway-tests.py b || :'}, good[1]],
            'continue-on-error: true': [dict(good[0], **{'continue-on-error': True}), good[1]],
            "continue-on-error: 'true'": [dict(good[0], **{'continue-on-error': 'true'}), good[1]],
            "continue-on-error: ${{ true }}": [dict(good[0], **{'continue-on-error': '${{ true }}'}), good[1]],
            'if: false': [dict(good[0], **{'if': False}), good[1]],
            "if: ${{ false }}": [dict(good[0], **{'if': '${{ false }}'}), good[1]],
            "if: 'false'": [dict(good[0], **{'if': 'false'}), good[1]],
            'only a dead assert before, a live one after': [dict(good[0], **{'if': False}), good[1],
                                                            {'run': 'python3 scripts/ci/assert-gateway-tests.py b'}],
        }
        for why, steps in bad.items():
            with self.subTest(mutant=why):
                self.assertIsNotNone(problem(steps), why)

    def test_every_job_that_runs_tests_asserts_the_gateway(self):
        # The per-`meson setup` check above only sees the files it names and
        # only a literal `meson setup`. This one discovers EVERY workflow
        # (glob, so a new or renamed file is covered) and, for each job that
        # runs tests (`meson test`, or flake-retry.py which wraps it), requires
        # an assert-gateway-tests.py that runs strictly before the first test
        # invocation and can fail (see _gateway_assert_problem).
        # fork-dynamic-review.yml configures through scripts/setup.sh and
        # ran `meson test` with no Erlang and no assertion until this check
        # existed. Comment lines are ignored.
        import yaml
        found = set()
        for path in sorted(glob.glob(os.path.join(ROOT, '.github', 'workflows', '*.yml'))):
            wf = os.path.basename(path)
            with open(path, encoding='utf-8') as f:
                doc = yaml.safe_load(f)
            for job, body in (doc.get('jobs') or {}).items():
                steps = body.get('steps') or []
                if not any(self.TEST_RE.search('\n'.join(
                        l for l in str(st.get('run') or '').split('\n')
                        if not l.lstrip().startswith('#'))) for st in steps):
                    continue
                found.add((wf, job))
                with self.subTest(workflow=wf, job=job):
                    self.assertIsNone(self._gateway_assert_problem(steps))
        # Guard the discovery itself: it must still see the legs the doc names.
        for want in (('ci.yml', 'linux'), ('ci.yml', 'windows'), ('ci.yml', 'macos'),
                     ('fork-dynamic-review.yml', 'linux'), ('nightly.yml', 'coverage')):
            self.assertIn(want, found)

    def test_ci_setup_beam_isolates_the_tool_cache_for_trusted_forks(self):
        # setup-beam on a self-hosted pool installs erl into RUNNER_TOOL_CACHE,
        # which later normal jobs on the same agent execute. A trusted-fork run
        # must get a per-run temp dir instead (#4852). Every ci.yml leg that
        # installs Erlang with setup-beam must switch on trusted_execution. The
        # macOS leg no longer uses setup-beam: it downloads a hash-pinned OTP into
        # RUNNER_TEMP, which is per agent and per job. NOTE: this asserts the
        # declared YAML intent only; the actions runner applies its own RUNNER_*
        # values after a step's env (actions/runner NodeScriptActionHandler), so the
        # isolation it names is not established for the Linux leg.
        import yaml
        with open(os.path.join(ROOT, '.github', 'workflows', 'ci.yml'), encoding='utf-8') as f:
            doc = yaml.safe_load(f)
        legs = set()
        for job, body in doc['jobs'].items():
            for step in body.get('steps') or []:
                if str(step.get('uses', '')).startswith('erlef/setup-beam@'):
                    legs.add(job)
                    with self.subTest(job=job):
                        cache = str((step.get('env') or {}).get('RUNNER_TOOL_CACHE', ''))
                        self.assertIn('trusted_execution', cache)
                        self.assertIn('runner.temp', cache)
        self.assertEqual(legs, {'linux'})

    @staticmethod
    def _macos_erlang_step_problems(step):
        """Problems in the macOS 'Install Erlang/OTP and rebar3' step, [] when clean.

        The step installs a prebuilt OTP + rebar3 into RUNNER_TEMP instead of
        erlef/setup-beam, whose rmRF + re-copy of the tool cache both BigMags agents
        share raced. What makes that substitute safe, and so what is pinned here: no
        action, no tool cache, every download goes through fetch() and is verified
        against its own pinned SHA-256 BEFORE anything else reads it, and verify()
        really compares a digest of its argument and exits on a mismatch (rebar3 has
        no upstream attestation, so its hash IS its only integrity control).

        LEXICAL ONLY: it matches comment-stripped whole lines (the only comment form
        the step uses) and is not a shell parser; control flow that could skip a
        verify is rejected outright instead of being analysed.
        """
        problems = []
        for key in ('uses', 'if', 'continue-on-error', 'working-directory', 'shell'):
            if key in step:
                problems.append('step must not set %r' % key)
        env, run = step.get('env') or {}, str(step.get('run') or '')
        if not re.match(r'^\d+\.\d+', str(env.get('OTP_VERSION'))):
            problems.append('OTP_VERSION missing')
        for var in ('OTP_SHA256', 'REBAR3_SHA256'):
            if not re.fullmatch(r'[0-9a-f]{64}', str(env.get(var))):
                problems.append(var + ' is not a 64-hex pin')
        code = [ln for ln in run.splitlines() if ln.strip() and not ln.lstrip().startswith('#')]
        text = '\n'.join(code)
        if not any(re.fullmatch(r'\s*set -euo pipefail\s*', ln) for ln in code):
            problems.append('set -euo pipefail missing')
        if re.search(r'set \+e|exit 0\b|\|\|\s*true|:\s*;\s*\}|\bfalse\s*&&|^\s*(?:if|case|while|for|until)\b',
                     text, re.M):
            problems.append('step has a control-flow bypass')
        if '$RUNNER_TEMP' not in text:
            problems.append('install root is not under $RUNNER_TEMP')
        if 'tool_cache' in text.lower() or 'tool_cache' in str(env).lower():
            problems.append('step touches the tool cache')
        if 'http://' in text:
            problems.append('plain-http URL')
        if sorted(re.findall(r'^\s*(verify|fetch)\s*\(\)', text, re.M)) != ['fetch', 'verify']:
            problems.append('verify() and fetch() must each be defined exactly once')
        if len(re.findall(r'\bcurl\b', text)) != 1:
            problems.append('curl may only be run through fetch()')
        first_fetch = re.search(r'^\s*fetch "', text, re.M)
        vdef = text.find('verify() {')
        body = text[vdef:first_fetch.start()] if (first_fetch and vdef >= 0) else ''
        for needle in ('dgst -sha256 "$2"', 'test "$got" = "$1"'):
            if needle not in body:
                problems.append('verify() lost %r' % needle)
        if body.count('test "$got" =') != 1:
            problems.append('verify() must compare $got exactly once, against $1')
        if not re.search(r'test "\$got" = "\$1" \|\| \{.*\bexit 1\b', body, re.S):
            problems.append('verify() mismatch branch no longer exits 1')
        fetches = [(i, m.group(1)) for i, ln in enumerate(code)
                   for m in [re.fullmatch(r'\s*fetch "[^"]+" "([^"]+)" \d+\s*', ln)] if m]
        verifies = {m.group(2): (i, m.group(1)) for i, ln in enumerate(code)
                    for m in [re.fullmatch(r'\s*verify "\$(OTP_SHA256|REBAR3_SHA256)" "([^"]+)"\s*', ln)] if m}
        if sorted(v for _, v in verifies.values()) != ['OTP_SHA256', 'REBAR3_SHA256']:
            problems.append('each of OTP_SHA256 and REBAR3_SHA256 must be verified exactly once')
        for dest, (_, var) in verifies.items():
            if not dest.endswith({'OTP_SHA256': 'otp.tar.gz', 'REBAR3_SHA256': 'bin/rebar3'}[var]):
                problems.append('%s is verified against the wrong pin (%s)' % (dest, var))
        if len(fetches) != 2:
            problems.append('expected exactly two fetch calls, found %d' % len(fetches))
        for fi, dest in fetches:
            if dest not in verifies:
                problems.append('download %s is never verified' % dest)
                continue
            first_use = next((i for i in range(fi + 1, len(code)) if dest in code[i]), None)
            if verifies[dest][0] != first_use:
                problems.append('%s is used before it is verified' % dest)
        return problems

    def test_ci_macos_erlang_step_is_hash_pinned_and_not_setup_beam(self):
        import yaml
        with open(os.path.join(ROOT, '.github', 'workflows', 'ci.yml'), encoding='utf-8') as f:
            steps = yaml.safe_load(f)['jobs']['macos']['steps']
        self.assertFalse([s for s in steps if 'setup-beam' in str(s.get('uses', '')).lower()])
        step, = [s for s in steps if s.get('name') == 'Install Erlang/OTP and rebar3']
        self.assertEqual(self._macos_erlang_step_problems(step), [])

    def test_macos_erlang_step_gate_rejects_regressions(self):
        # In-memory mutations: each one must make the gate report a problem, so its
        # patterns cannot silently go stale (docs/testing/unit-test-conventions.md).
        import copy
        import yaml
        with open(os.path.join(ROOT, '.github', 'workflows', 'ci.yml'), encoding='utf-8') as f:
            steps = yaml.safe_load(f)['jobs']['macos']['steps']
        clean, = [s for s in steps if s.get('name') == 'Install Erlang/OTP and rebar3']
        run = clean['run']
        otp_v = 'verify "$OTP_SHA256" "$root/otp.tar.gz"'
        reb_v = 'verify "$REBAR3_SHA256" "$root/bin/rebar3"'
        self.assertIn(otp_v, run)
        self.assertIn(reb_v, run)
        mutations = {
            'otp verify removed': lambda r: r.replace(otp_v + '\n', ''),
            'rebar3 verify removed': lambda r: r.replace(reb_v + '\n', ''),
            'otp verify commented out': lambda r: r.replace(otp_v, '# ' + otp_v),
            'rebar3 verify commented out': lambda r: r.replace(reb_v, '# ' + reb_v),
            'verify pins swapped between files': lambda r: r.replace(
                otp_v, 'verify "$REBAR3_SHA256" "$root/otp.tar.gz"').replace(
                reb_v, 'verify "$OTP_SHA256" "$root/bin/rebar3"'),
            'third download without verify': lambda r: r.replace(
                reb_v + '\n', reb_v + '\nfetch "https://example.invalid/x" "$root/bin/x" 60\n'),
            'rebar3 verify after use': lambda r: r.replace(reb_v + '\n', '').replace(
                'chmod 755 "$root/bin/rebar3"\n', 'chmod 755 "$root/bin/rebar3"\n' + reb_v + '\n'),
            'install root moves to the tool cache': lambda r: r.replace(
                'root="$RUNNER_TEMP/erlang"', 'root="$RUNNER_TOOL_CACHE/erlang"; : $RUNNER_TEMP'),
            'verify no longer compares': lambda r: r.replace('test "$got" = "$1"', 'true'),
            'verify mismatch no longer exits': lambda r: r.replace(
                'CDN/proxy error page was saved)"\n    exit 1',
                'CDN/proxy error page was saved)"\n    :'),
            'verify hashes a fixed file': lambda r: r.replace('dgst -sha256 "$2"', 'dgst -sha256 /etc/hosts'),
            'verify redefined as a stub': lambda r: r.replace(
                otp_v, 'verify() { :; }\n' + otp_v),
            'second curl outside fetch': lambda r: r.replace(
                otp_v, 'curl -fsSL -o "$root/extra" https://example.invalid/x\n' + otp_v),
            'plain http url': lambda r: r.replace('https://github.com/erlang/rebar3', 'http://github.com/erlang/rebar3'),
            'verify under a conditional': lambda r: r.replace(otp_v, 'if false; then ' + otp_v + '; fi'),
            'exit 0 before the checks': lambda r: r.replace(otp_v, 'exit 0\n' + otp_v),
            'errexit switched off': lambda r: r.replace('mkdir -p "$root/otp"', 'set +e\n          mkdir -p "$root/otp"'),
            'pipefail dropped': lambda r: r.replace('set -euo pipefail', 'set -eu'),
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                bad = copy.deepcopy(clean)
                bad['run'] = mutate(run)
                self.assertNotEqual(bad['run'], run, 'mutation did not change the step')
                self.assertTrue(self._macos_erlang_step_problems(bad), name)
        for name, mutate in {
            'setup-beam action (any case)': lambda s: s.__setitem__('uses', 'ErLef/Setup-Beam@v1'),
            'continue-on-error': lambda s: s.__setitem__('continue-on-error', True),
            'conditional step': lambda s: s.__setitem__('if', 'false'),
            'hash pin emptied': lambda s: s['env'].__setitem__('REBAR3_SHA256', ''),
        }.items():
            with self.subTest(mutation=name):
                bad = copy.deepcopy(clean)
                mutate(bad)
                self.assertTrue(self._macos_erlang_step_problems(bad), name)


if __name__ == '__main__':
    unittest.main()
