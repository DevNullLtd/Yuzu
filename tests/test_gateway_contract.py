#!/usr/bin/env python3
"""Fail-closed selection/evidence and a real EOF deadline regression; no OTP needed."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'gateway_contract', ROOT / 'scripts/test/gateway-contract.py')
WRAPPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WRAPPER)


class VerdictTests(unittest.TestCase):
    @unittest.skipIf(os.name == 'nt', 'POSIX SIGTERM; Windows uses taskkill /T')
    def test_meson_sigterm_reaps_detached_child_despite_repeated_signals(self):
        with tempfile.TemporaryDirectory(prefix='yuzu_test_gateway_cancel_') as tmp:
            root = Path(tmp).resolve()
            pidfile = root / 'native.pid'
            native = ('import os,signal,time;from pathlib import Path;'
                      'signal.signal(signal.SIGTERM,signal.SIG_IGN);'
                      f'p=Path({str(pidfile)!r});t=p.with_suffix(".tmp");'
                      't.write_text(str(os.getpid()));t.replace(p);time.sleep(60)')
            driver = root / 'driver.py'
            driver.write_text(
                'import importlib.util,os,signal,sys,time\nfrom pathlib import Path\n'
                f's=importlib.util.spec_from_file_location("gw",{str(ROOT / "scripts/test/gateway-contract.py")!r})\n'
                'm=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n'
                'kill=m.kill_tree\ndef interrupted_kill(*a,**kw):\n'
                ' os.kill(os.getpid(),signal.SIGINT)\n os.kill(os.getpid(),signal.SIGTERM)\n'
                ' return kill(*a,**kw)\nm.kill_tree=interrupted_kill\n'
                'signal.signal(signal.SIGTERM,m.termination_interrupt)\ntry:\n'
                f' m.run([sys.executable,"-c",{native!r}],Path({str(root)!r}),os.environ.copy(),time.monotonic()+30)\n'
                'except RuntimeError as e:\n'
                f' Path({str(root / "outcome")!r}).write_text(str(e))\n')
            child = subprocess.Popen([sys.executable, str(driver)], stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, start_new_session=True)
            try:
                deadline = time.monotonic() + 4
                while not pidfile.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(pidfile.exists(), 'child must start before cancellation')
                native_pid = int(pidfile.read_text())
                self.assertEqual(os.getpgid(native_pid), native_pid)
                os.kill(child.pid, signal.SIGTERM)
                self.assertEqual(child.wait(timeout=8), 0)
                self.assertIn('KeyboardInterrupt', (root / 'outcome').read_text())
                with self.assertRaises(ProcessLookupError):
                    os.kill(native_pid, 0)
            finally:
                for pid in ([int(pidfile.read_text())] if pidfile.exists() else []) + [child.pid]:
                    try:
                        if os.getpgid(pid) == pid:
                            os.killpg(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                child.wait(timeout=5)

    def test_only_one_successful_uncancelled_case_passes(self):
        for output, code, expected in [
            ('Test passed.\n', 0, 0),
            ('All 1 tests passed.\n', 0, 0),
            ('All 2 tests passed.\n', 0, 1),
            ('There were no tests to run.\n', 0, 1),
            ('', 0, 1),
            ('Test passed.\n', 3, 1),
            ('Failed: 1.  Skipped: 0.  Passed: 0.\n', 0, 1),
            ('Test passed.\nOne or more tests were cancelled.\n', 0, 1),
        ]:
            with self.subTest(output=output, code=code):
                self.assertEqual(expected, WRAPPER.contract_verdict(output, code)[0])

    def test_evidence_identity_cannot_escape_parent(self):
        with tempfile.TemporaryDirectory(prefix='yuzu_test_contract_') as tmp:
            for identity in ('', '.', '..', '../outside', 'a/b', 'a\\b'):
                with self.subTest(identity=identity), self.assertRaises(ValueError):
                    WRAPPER.evidence_directory(tmp, identity)
            self.assertEqual([], list(Path(tmp).iterdir()))

    def test_existing_attempt_is_never_overwritten(self):
        with tempfile.TemporaryDirectory(prefix='yuzu_test_contract_') as tmp:
            first = WRAPPER.evidence_directory(tmp, 'GW-HB-RETRY-001')
            (first / 'result.json').write_text('prior evidence')
            with self.assertRaises(FileExistsError):
                WRAPPER.evidence_directory(tmp, 'GW-HB-RETRY-001')
            self.assertEqual('prior evidence', (first / 'result.json').read_text())

    def test_real_child_eof_does_not_disable_deadline(self):
        with tempfile.TemporaryDirectory(prefix='yuzu_test_contract_') as tmp:
            pidfile = Path(tmp) / 'pid'
            code = ('import os,time;'
                    f'open({str(pidfile)!r},"w").write(str(os.getpid()));'
                    'os.close(1);os.close(2);time.sleep(60)')
            started = time.monotonic()
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(
                    RuntimeError, 'deadline exceeded'):
                WRAPPER.run([sys.executable, '-c', code], Path(tmp),
                            os.environ.copy(), started + 1)
            self.assertLess(time.monotonic() - started, 8)
            self.assertTrue(pidfile.is_file(), 'child must reach output EOF')
            if os.name != 'nt':
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(pidfile.read_text()), 0)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='yuzu_test_contract_')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.gateway = self.root / 'gateway'
        self.gateway.mkdir()
        self.base = self.root / 'private-build'
        self.beam = self.base / 'test/lib/yuzu_gw/test/pilot.beam'
        self.beam.parent.mkdir(parents=True)
        self.beam.write_bytes(b'compiled test artifact')
        self.production = self.base / 'test/lib/yuzu_gw/ebin/owner.beam'
        self.production.parent.mkdir(parents=True)
        self.production.write_bytes(b'compiled production artifact')
        self.evidence = self.root / 'evidence'
        self.env = {'REBAR_BASE_DIR': str(self.base),
                    'YUZU_OTP_BIN': str(self.root / 'otp/bin'),
                    'YUZU_CONTRACT_EVIDENCE_DIR': str(self.evidence)}
        self.commands = []

    def invoke(self, *, compile_code=0, wrong_module=False, mutate=False, summary='Test passed.\n'):
        def run(command, _cwd, _env, _deadline, log=None):
            self.commands.append(command)
            if command[-1] == '--version':
                code, output = 0, 'rebar3 fixture-version\n'
            elif command[-1] == 'compile':
                code, output = compile_code, 'native compile output\n'
            else:
                self.assertIn('erlang:function_exported(pilot,only_test_,0)', command[-1])
                self.assertIn('eunit:test(pilot:only_test_(),[verbose])', command[-1])
                runtime = {'otp_release': '28', 'erts_version': '16.3',
                           'system_version': 'fixture runtime',
                           'test_module_path': str(self.root / 'wrong.beam' if wrong_module else self.beam)}
                code, output = 0, 'GATEWAY_CONTRACT_RUNTIME=' + json.dumps(runtime) + '\n' + summary
                if mutate:
                    self.production.write_bytes(b'changed while tests ran')
            if log is not None:
                log.write_text(output)
            return code, output

        argv = ['gateway-contract.py', str(self.gateway), 'pilot', 'only_test_', '--id', 'CONTRACT-1']
        with mock.patch.dict(os.environ, self.env, clear=True), \
             mock.patch.object(sys, 'argv', argv), \
             mock.patch.object(WRAPPER, 'base_env', return_value=self.env.copy()), \
             mock.patch.object(WRAPPER, 'otp_version', return_value='28.4'), \
             mock.patch.object(WRAPPER, 'rebar3_prefix', return_value=['rebar3']), \
             mock.patch.object(WRAPPER, 'run', side_effect=run), \
             contextlib.redirect_stdout(io.StringIO()):
            return WRAPPER.main()

    def result(self):
        return json.loads((self.evidence / 'CONTRACT-1/result.json').read_text())

    def test_success_binds_selector_runtime_and_actual_beam_bytes(self):
        self.assertEqual(0, self.invoke())
        result = self.result()
        self.assertEqual(('CONTRACT-1', 'pilot', 'only_test_', 1, 'PASS'),
                         tuple(result[k] for k in ('contract_id', 'module', 'generator', 'cases', 'status')))
        self.assertEqual('28.4', result['otp_version'])
        self.assertEqual('16.3', result['runtime']['erts_version'])
        for beam in (self.beam, self.production):
            self.assertEqual(hashlib.sha256(beam.read_bytes()).hexdigest(), result['beam_sha256'][str(beam)])
        for label in ('compile', 'test', 'rebar-version'):
            self.assertTrue((self.evidence / 'CONTRACT-1' / (label + '.log')).is_file())

    def test_compile_failure_never_starts_test_vm(self):
        with self.assertRaisesRegex(RuntimeError, 'compilation exited 17'):
            self.invoke(compile_code=17)
        self.assertEqual(2, len(self.commands))
        self.assertEqual('FAIL', self.result()['status'])
        self.assertEqual(0, self.result()['cases'])

    def test_missing_compiled_module_does_not_fall_back(self):
        self.beam.unlink()
        with self.assertRaisesRegex(RuntimeError, 'compiled test module missing'):
            self.invoke()
        self.assertEqual(2, len(self.commands))
        self.assertEqual('FAIL', self.result()['status'])

    def test_wrong_loaded_module_cannot_qualify_evidence(self):
        with self.assertRaisesRegex(RuntimeError, 'different test module'):
            self.invoke(wrong_module=True)
        self.assertEqual('FAIL', self.result()['status'])

    def test_mutated_beam_cannot_qualify_evidence(self):
        with self.assertRaisesRegex(RuntimeError, 'artifacts changed'):
            self.invoke(mutate=True)
        self.assertEqual('FAIL', self.result()['status'])

    def test_cancelled_run_has_failure_evidence(self):
        self.assertEqual(1, self.invoke(summary='Test passed.\nOne or more tests were cancelled.\n'))
        self.assertEqual('FAIL', self.result()['status'])


if __name__ == '__main__':
    unittest.main()
