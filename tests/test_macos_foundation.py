#!/usr/bin/env python3
"""Portable fail-closed contracts; no live services, credentials or root required."""
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('foundation', ROOT / 'scripts/macos-foundation-check.py')
foundation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(foundation)


def row(status, output='', target='test-agent'):
    return {'agent_id': target, 'status': status, 'output': output}


class FoundationTests(unittest.TestCase):
    def test_exercise_success_and_unhappy_paths_leave_no_marker(self):
        status = ('config|process_capture_method|endpoint_security\nconfig|process_enabled|true\n'
                  'config|process_stream_dropped|0\nconfig|process_stream_kernel_dropped|0')
        for scenario in ('pass', 'no-events', 'restart', 'drops', 'changed-bytes'):
            with self.subTest(scenario=scenario), contextlib.ExitStack() as stack:
                clock = [0]
                markers = []
                status_calls = [0]
                def sleep(seconds):
                    clock[0] += seconds
                def copy(source, destination):
                    destination.write_bytes(b'native marker fixture')
                    markers.append(destination)
                def command(plugin, action, params=None):
                    if action == 'status':
                        status_calls[0] += 1
                        return status.replace('dropped|0', 'dropped|1') if scenario == 'drops' and status_calls[0] > 1 else status
                    if action == 'os_name':
                        return 'os_name|Darwin'
                    self.assertEqual((plugin, action), ('tar', 'sql'))
                    self.assertIn(markers[0].name, params['sql'])
                    return '' if scenario == 'no-events' else 'started\nstopped'
                stack.enter_context(patch.object(foundation.time, 'monotonic', side_effect=lambda: clock[0]))
                stack.enter_context(patch.object(foundation.time, 'sleep', side_effect=sleep))
                stack.enter_context(patch.object(foundation.shutil, 'copyfile', side_effect=copy))
                stack.enter_context(patch.object(foundation, 'digest', return_value='fixture-sha256'))
                stack.enter_context(patch.object(foundation, 'run', return_value=''))
                stack.enter_context(patch.object(foundation, 'service_pid',
                                                side_effect=[42, 43] if scenario == 'restart' else None,
                                                return_value=42))
                stack.enter_context(patch.object(foundation, 'local_integrity', side_effect=[
                    {'executable_sha256': 'original'},
                    {'executable_sha256': 'changed' if scenario == 'changed-bytes' else 'original'}]))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                client = Mock()
                client.command.side_effect = command
                if scenario == 'pass':
                    result = foundation.exercise(client, 90)
                    self.assertEqual(result['result'], 'pass')
                    self.assertEqual(result['samples'], 6)
                    self.assertFalse(result['transport_security_verified'])
                else:
                    with self.assertRaises(foundation.CheckFailed):
                        foundation.exercise(client, 90)
                self.assertEqual(len(markers), 1)
                self.assertFalse(markers[0].parent.exists())

    def test_pid_check_rejects_nested_running_state_and_wrong_executable(self):
        for launchctl, ps in (('group = {\n\t\tstate = running\n}\n\tpid = 42\n', ''),
                              ('\tstate = running\n\tpid = 42\n', '0 /tmp/unrelated-agent')):
            with patch.object(foundation, 'run', side_effect=[launchctl, ps]), self.assertRaises(foundation.CheckFailed):
                foundation.service_pid()

    def test_requires_terminal_success_not_just_output(self):
        self.assertIsNone(foundation.terminal_output([row(0, 'os_name|Darwin')], 'test-agent'))
        self.assertEqual(foundation.terminal_output([row(0, 'os_name|Darwin'), row(1)], 'test-agent'),
                         'os_name|Darwin\n')

    def test_failure_wrong_target_and_malformed_responses_fail(self):
        for rows in ([row(2)], [row(3)], [row(1, target='other')], [row(1), row(2)],
                     [row(True)], [row('1')], [row(7)], {}, [None]):
            with self.subTest(rows=rows), self.assertRaises(foundation.CheckFailed):
                foundation.terminal_output(rows, 'test-agent')

    def test_explicit_target_on_every_dispatch(self):
        client = foundation.Client('https://localhost:8080', Path('/unused'), 'test-agent')
        with patch.object(client, 'request', side_effect=[{'command_id': 'test-123'}, [row(1, 'ok')]]) as request:
            self.assertEqual(client.command('os_info', 'os_name'), 'ok')
        self.assertEqual(request.call_args_list[0].args[1], {
            'plugin': 'os_info', 'action': 'os_name', 'params': {}, 'agent_ids': ['test-agent']})

    def test_polling_no_terminal_success_times_out(self):
        client = foundation.Client('https://localhost', Path('/unused'), 'test-agent')
        with patch.object(client, 'request', side_effect=[{'command_id': 'test'}, [row(0, 'started\nstopped')]]), \
             patch.object(foundation.time, 'monotonic', side_effect=[0, 1, 31]), \
             patch.object(foundation.time, 'sleep'), self.assertRaises(foundation.CheckFailed):
            client.command('tar', 'sql')

    def test_cookie_only_passed_as_path_no_redirect_or_tls_bypass(self):
        client = foundation.Client('https://localhost', Path('/private/cookies'), 'test-agent')
        with patch.object(foundation, 'run', return_value='{}\n200') as command:
            client.request('/api/command', {'agent_ids': ['test-agent']})
        argv, body = command.call_args.args
        self.assertEqual(argv[:2], ['/usr/bin/curl', '-q'])
        self.assertIn(str(Path('/private/cookies')), argv)
        self.assertEqual(json.loads(body), {'agent_ids': ['test-agent']})
        self.assertNotIn('-L', argv)
        self.assertNotIn('-k', argv)

    def test_http_failure_does_not_echo_response_secret(self):
        client = foundation.Client('https://localhost', Path('/unused'), 'test-agent')
        with patch.object(foundation, 'run', return_value='SECRET\n401'):
            with self.assertRaises(foundation.CheckFailed) as error:
                client.request('/api/command')
        self.assertNotIn('SECRET', str(error.exception))

    def test_plaintext_requires_loopback_and_opt_in(self):
        self.assertEqual(foundation.validate_url('http://127.0.0.1:8080/', True), 'http://127.0.0.1:8080')
        self.assertEqual(foundation.validate_url('https://example.com', False), 'https://example.com')
        for url, opt in [('http://localhost', False), ('http://example.com', True),
                         ('http://localhost.evil', True), ('https://u:p@localhost', False),
                         ('https://localhost/path', False), ('https://localhost?token=x', False)]:
            with self.subTest(url=url), self.assertRaises(foundation.CheckFailed):
                foundation.validate_url(url, opt)

    def test_es_requires_real_capture_and_counters(self):
        valid = ('config|process_capture_method|endpoint_security\nconfig|process_enabled|true\n'
                 'config|process_stream_dropped|2\nconfig|process_stream_kernel_dropped|3')
        self.assertEqual(foundation.es_status(valid), (2, 3))
        for output in (valid.replace('endpoint_security', 'poll'), valid.replace('|true', '|false'),
                       valid.replace('|2', '|-1'), valid + '\nconfig|process_enabled|true', ''):
            with self.subTest(output=output), self.assertRaises(foundation.CheckFailed):
                foundation.es_status(output)

    @unittest.skipUnless(shutil.which('awk'), 'awk is required for shell parser fixture')
    def test_device_discovery_uses_only_one_valid_provisioning_udid(self):
        script = (ROOT / 'scripts/macos-device-registration.zsh').read_text()
        awk = re.search(r"/usr/bin/awk '(.*?)'", script, re.S).group(1)
        fixtures = [
            ('Hardware UUID: AAAA-BBBB\n Provisioning UDID: 00006000-0012345678901234\n', 0),
            ('Hardware UUID: AAAA-BBBB\n', 1),
            ('Provisioning UDID: AAAA-BBBB\nProvisioning UDID: CCCC-DDDD\n', 1),
            ('Provisioning UDID: AAAA-BBBB\nProvisioning UDID: malformed\n', 1),
            ('Provisioning UDID: malformed\n', 1),
        ]
        for source, code in fixtures:
            result = subprocess.run(['awk', awk], input=source, text=True, capture_output=True)
            self.assertEqual(result.returncode, code)
            self.assertEqual(result.stdout, '00006000-0012345678901234\n' if code == 0 else '')

    def test_private_run_excluded_from_git_and_docker(self):
        for name in ('.gitignore', '.dockerignore'):
            self.assertIn('/.agent-runs/', (ROOT / name).read_text().splitlines())


if __name__ == '__main__':
    unittest.main()
