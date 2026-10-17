#!/usr/bin/env python3
"""Opt-in installed Mac smoke check. Never installs, restarts, enrolls or logs secrets.

Uses the existing operator session and normal targeted command routes. Creates
only a private temporary native marker; removes it on exit. See the runbook.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import stat
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
import uuid

APP = Path('/Library/Application Support/YuzuAgent/YuzuAgent.app')
EXE = APP / 'Contents/MacOS/yuzu-agent'
PLIST = Path('/Library/LaunchDaemons/com.yuzu.agent.plist')
PLUGINS = Path('/usr/local/lib/yuzu/plugins')


class CheckFailed(Exception):
    pass


def require(ok, message):
    if not ok:
        raise CheckFailed(message)


def run(argv, body=None):
    result = subprocess.run(argv, input=body, capture_output=True, text=True, timeout=20)
    # Neither raw stderr nor argv is safe evidence: curl can echo credentials.
    require(result.returncode == 0, 'Local command failed: ' + Path(argv[0]).name)
    return result.stdout


def digest(path):
    checksum = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            checksum.update(chunk)
    return checksum.hexdigest()


def validate_url(base, plaintext):
    url = urlsplit(base)
    require(url.scheme in ('https', 'http') and url.hostname
            and not url.username and not url.password and not url.query
            and not url.fragment and url.path in ('', '/'), 'Invalid server base URL')
    if url.scheme == 'http':
        require(plaintext and url.hostname in ('localhost', '127.0.0.1', '::1'),
                'Plaintext requires explicit opt-in and a literal loopback host')
    return base.rstrip('/')


def terminal_output(payload, target):
    rows = payload.get('responses') if isinstance(payload, dict) else payload
    require(isinstance(rows, list), 'Malformed command responses')
    require(all(isinstance(r, dict) and r.get('agent_id') == target for r in rows),
            'Response target mismatch')
    require(all(type(r.get('status')) is int and r['status'] in (0, 1, 2, 3)
                and isinstance(r.get('output', ''), str) for r in rows),
            'Malformed command status/output')
    require(not any(r['status'] in (2, 3) for r in rows), 'Target command failed or timed out')
    if not any(r['status'] == 1 for r in rows):
        return None
    return '\n'.join(r.get('output', '') for r in rows)


class Client:
    def __init__(self, base, cookie, target):
        self.base, self.cookie, self.target = base, cookie, target

    def request(self, path, data=None):
        argv = ['/usr/bin/curl', '-q', '--silent', '--show-error', '--noproxy', '*',
                '--max-time', '10', '--max-filesize', '2097152', '--cookie', str(self.cookie),
                '--write-out', '\n%{http_code}', self.base + path]
        if data is not None:
            argv += ['--header', 'Content-Type: application/json', '--data-binary', '@-']
        raw = run(argv, json.dumps(data) if data is not None else None)
        payload, code = raw.rsplit('\n', 1)
        require(code == '200', 'HTTP ' + code + ' (check session, permissions and gateway compatibility)')
        return json.loads(payload)

    def command(self, plugin, action, params=None):
        result = self.request('/api/command', {
            'plugin': plugin, 'action': action, 'params': params or {},
            'agent_ids': [self.target],
        })
        command_id = result.get('command_id', '')
        require(isinstance(command_id, str) and re.fullmatch(r'[A-Za-z0-9_-]+', command_id),
                'Missing or malformed command ID')
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            output = terminal_output(self.request('/api/responses/' + command_id), self.target)
            if output is not None:
                return output
            time.sleep(1)
        raise CheckFailed('No terminal SUCCESS within command deadline')


def es_status(output):
    config = {}
    for line in output.splitlines():
        parts = line.split('|', 2)
        if len(parts) == 3 and parts[0] == 'config':
            require(parts[1] not in config, 'Duplicate TAR status field')
            config[parts[1]] = parts[2]
    require(config.get('process_capture_method') == 'endpoint_security',
            'Live Endpoint Security is not active (polling is not ES)')
    require(config.get('process_enabled') == 'true', 'Process capture is disabled')
    keys = ('process_stream_dropped', 'process_stream_kernel_dropped')
    require(all(re.fullmatch(r'\d+', config.get(k, '')) for k in keys), 'Missing ES drop counters')
    return tuple(int(config[k]) for k in keys)


def service_pid():
    output = run(['/bin/launchctl', 'print', 'system/com.yuzu.agent'])
    # Only top-level launchctl fields; nested resource coalitions also have state.
    require(re.search(r'^\tstate = running$', output, re.M), 'Installed LaunchDaemon is not running')
    match = re.search(r'^\tpid = (\d+)$', output, re.M)
    require(match is not None, 'Installed LaunchDaemon has no PID')
    pid = int(match[1])
    process = run(['/bin/ps', '-p', str(pid), '-o', 'uid=', '-o', 'comm=']).strip().split(None, 1)
    require(process == ['0', str(EXE)], 'LaunchDaemon is not the installed root executable')
    return pid


def local_integrity():
    metadata = PLIST.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
            and metadata.st_mode & 0o022 == 0, 'Untrusted LaunchDaemon plist')
    with PLIST.open('rb') as source:
        config = plistlib.load(source)
    args = config.get('ProgramArguments', [])
    require(args and args[0] == str(EXE) and '--no-auto-update' in args,
            'Expected immutable installed bundle lane with OTA disabled')
    require(config.get('UserName', 'root') == 'root', 'Expected root LaunchDaemon')
    run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(APP)])
    plugins = sorted(PLUGINS.glob('*.dylib'))
    require(any(p.name == 'tar.dylib' for p in plugins), 'Installed TAR plugin is missing')
    for plugin in plugins:
        run(['/usr/bin/codesign', '--verify', '--strict', str(plugin)])
    require(not any((EXE.parent / name).exists() for name in
                    ('yuzu-agent.old', '.yuzu-update-verified')), 'Unexpected OTA mutation marker')
    return {'executable_sha256': digest(EXE),
            'profile_sha256': digest(APP / 'Contents/embedded.provisionprofile'),
            'plugin_sha256': {p.name: digest(p) for p in plugins}}


def exercise(client, seconds):
    original = local_integrity()
    pid = service_pid()
    started = time.monotonic()
    initial_drops = es_status(client.command('tar', 'status'))
    require(any(line.startswith('os_name|') for line in client.command('os_info', 'os_name').splitlines()),
            'Targeted OS command returned no OS name')
    # copyfile deliberately does NOT preserve Apple's restricted system flags.
    with tempfile.TemporaryDirectory(prefix='yuzu_test_es_') as directory:
        marker = Path(directory) / ('yuzu_es_' + uuid.uuid4().hex[:12])
        shutil.copyfile('/usr/bin/true', marker)
        marker.chmod(0o700)
        require(digest(marker) == digest(Path('/usr/bin/true')), 'Native marker copy differs')
        run([str(marker)])
        sql = "SELECT action FROM $Process_Live WHERE name='" + marker.name + "' ORDER BY ts LIMIT 10"
        deadline = time.monotonic() + seconds
        events = False
        samples = 0
        while time.monotonic() < deadline:
            require(service_pid() == pid, 'LaunchDaemon restarted during observation')
            # Each dispatch is a fresh snapshot: polling an old receipt cannot see a later TAR drain.
            lines = client.command('tar', 'sql', {'sql': sql}).splitlines()
            events = events or ('started' in lines and 'stopped' in lines)
            require(es_status(client.command('tar', 'status')) == initial_drops,
                    'ES counters changed (drop or reset) during observation')
            samples += 1
            print(json.dumps({'phase': 'observing', 'sample': samples,
                              'marker_events_received': events}), flush=True)
            time.sleep(min(15, max(0, deadline - time.monotonic())))
        require(events, 'No marker EXEC/EXIT through control plane before deadline')
    require(service_pid() == pid, 'LaunchDaemon changed at final check')
    require(local_integrity() == original, 'Installed signed bytes changed during observation')
    return {'result': 'pass', 'scope': 'development-smoke', 'pid': pid,
            'seconds': round(time.monotonic() - started, 1), 'samples': samples,
            'es_exec_exit': True, 'drop_counters_unchanged': True,
            'transport_security_verified': False, **original}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', required=True, help='Operator HTTP(S) base URL, not agent gRPC')
    parser.add_argument('--cookie-file', required=True, type=Path, help='Existing private operator cookie jar')
    parser.add_argument('--agent-id', required=True, help='Installed daemon ID; never a fleet selector')
    parser.add_argument('--allow-local-plaintext', action='store_true')
    parser.add_argument('--seconds', type=int, default=120, help='ES/command observation window, 90..600')
    args = parser.parse_args()
    try:
        require(platform.system() == 'Darwin', 'Run on the Mac under test')
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}', args.agent_id)
                and args.agent_id != '__all__', 'An explicit single agent ID is required')
        require(90 <= args.seconds <= 600, 'Observation window must be 90..600 seconds')
        base = validate_url(args.server, args.allow_local_plaintext)
        info = args.cookie_file.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_mode & 0o077 == 0,
                'Cookie file must be a private regular file (0600); symlinks refused')
        report = exercise(Client(base, args.cookie_file.resolve(), args.agent_id), args.seconds)
        print(json.dumps(report, sort_keys=True))
        return 0
    except CheckFailed as error:
        print(json.dumps({'result': 'fail', 'reason': str(error)}))
    except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.TimeoutExpired):
        print(json.dumps({'result': 'fail', 'reason': 'Local access, transport or response decoding failed'}))
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
