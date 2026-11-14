#!/usr/bin/env python3
"""Run the registered migration pilots through Meson; preserve each invocation.

This is an evidence collector around native tests, not an ADR correctness score.
`case` is Meson's Catch2 adapter: required pilots cannot pass by skipping.
"""
import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / 'tests/contracts/pilots.json'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def source_path(root, relative):
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError(f'Missing or outside-repository input: {relative}')
    return path


def load_registry(path=REGISTRY, root=ROOT):
    data = json.loads(path.read_text(encoding='utf-8'))
    if data.get('schema_version') != 1 or not data.get('contracts'):
        raise ValueError('Expected nonempty version-1 contract registry')
    seen = set()
    names = set()
    for row in data['contracts']:
        cid = row['id']
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', cid) or cid in seen:
            raise ValueError(f'Invalid or duplicate contract ID: {cid}')
        seen.add(cid)
        if row['meson_test'] != 'contract.' + cid or row['meson_test'] in names:
            raise ValueError(f'Invalid Meson binding: {cid}')
        names.add(row['meson_test'])
        if row['expected_cases'] != 1 or row['kind'] not in ('catch2', 'eunit'):
            raise ValueError(f'Pilot requires one exact native case: {cid}')
        for field in ('obligation', 'oracle', 'defects', 'limits', 'inputs'):
            if not row.get(field):
                raise ValueError(f'Missing {field}: {cid}')
        for field in ('build_targets', 'requires_env'):
            if not isinstance(row.get(field), list):
                raise ValueError(f'Expected list {field}: {cid}')
        authority = row['authority']
        if not isinstance(authority.get('section'), str) or not authority['section'].strip():
            raise ValueError(f'Authority section must be nonempty: {cid}')
        document = source_path(root, authority['path']).read_text(encoding='utf-8')
        if authority['section'] not in document:
            raise ValueError(f'Missing authority section: {cid}')
        if authority['kind'] == 'accepted_adr':
            if not re.search(r'(?im)^(?:- \*\*Status:\*\* Accepted\b|status:\s*accepted\b)', document):
                raise ValueError(f'ADR is not explicitly accepted: {cid}')
        elif authority['kind'] != 'production_contract':
            raise ValueError(f'Unknown authority kind: {cid}')
        for relative in row['inputs']:
            source_path(root, relative)
        if row['kind'] == 'catch2':
            if not re.fullmatch(r'\[[A-Za-z0-9_-]+\]', row['selector']) or not row['case_name']:
                raise ValueError(f'Expected exact single-tag selector: {cid}')
        else:
            for field in ('module', 'generator'):
                if not re.fullmatch(r'[a-z][a-zA-Z0-9_]*', row[field]):
                    raise ValueError(f'Invalid Erlang selector: {cid}')
    return data['contracts']


def catch_verdict(report, row, returncode):
    if returncode:
        raise ValueError(f'Catch2 exited {returncode}')
    tree = ET.fromstring(report)
    cases = tree.findall('TestCase')
    counts = tree.find('OverallResultsCases')
    assertions = tree.find('OverallResults')
    if tree.tag != 'Catch2TestRun' or tree.get('filters') != row['selector']:
        raise ValueError('Wrong Catch2 selection/report')
    if len(cases) != 1 or cases[0].get('name') != row['case_name']:
        raise ValueError('Expected exactly the registered case')
    case_result = cases[0].find('OverallResult')
    if case_result is None or case_result.get('success') != 'true' or case_result.get('skips') != '0':
        raise ValueError('The required case did not complete successfully')
    if any(node.get('success') not in (None, 'true') or node.tag in ('Failure', 'FatalErrorCondition', 'Exception', 'Skip') for node in tree.iter()):
        raise ValueError('Native report contains a failed or skipped observation')
    if counts is None or assertions is None:
        raise ValueError('Missing native completion summary')
    for count in (counts, assertions):
        if any(int(count.get(key, '-1')) != 0 for key in ('failures', 'expectedFailures', 'skips')):
            raise ValueError('Failure, expected failure or skip cannot satisfy a required contract')
    if int(counts.get('successes', '0')) != 1 or int(assertions.get('successes', '0')) < 1:
        raise ValueError('No completed case/assertions')
    return {'cases': 1, 'assertions': int(assertions.get('successes')), 'seed': tree.get('rng-seed')}


@contextlib.contextmanager
def uninterrupted_cleanup():
    """A repeated cancellation cannot bypass the bounded child kill/reap."""
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        yield
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


def termination_interrupt(_signum, _frame):
    # Meson cancels a test with SIGTERM. Enter the same owned-child cleanup as
    # Ctrl-C instead of letting the adapter die with its detached child alive.
    raise KeyboardInterrupt('SIGTERM')


def bounded(command, cwd, env, log, timeout, cancel_grace=0):
    """File-backed output; the deadline covers process exit even after output EOF."""
    start = time.monotonic()
    options = {'start_new_session': True} if os.name != 'nt' else {
        'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP}
    with log.open('wb') as output:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, **options)
        try:
            code = process.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            with uninterrupted_cleanup():
                if os.name == 'nt':
                    try:
                        subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                                       stdout=output, stderr=subprocess.STDOUT, timeout=10)
                    finally:
                        if process.poll() is None:
                            process.kill()
                        process.wait(timeout=10)
                else:
                    if cancel_grace:
                        # Meson gives each test a separate session. Let Meson's
                        # SIGTERM handler cancel ALL tests and let their adapters
                        # reap native children before forcing the Meson root down.
                        try:
                            os.killpg(process.pid, signal.SIGTERM)
                            process.wait(timeout=cancel_grace)
                        except ProcessLookupError:
                            pass
                        except (subprocess.TimeoutExpired, KeyboardInterrupt):
                            output.write(b'Graceful runner cancellation did not complete; descendant cleanup is unconfirmed.\n')
                            output.flush()
                    # A gracefully exited runner has already been reaped; do
                    # not signal its former group id after relinquishing it.
                    if not cancel_grace or process.poll() is None:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                process.wait(timeout=10)
            raise
    return {'command': command, 'exit_code': code, 'seconds': time.monotonic()-start,
            'log': log.name}


def run_case(args, rows):
    row = next(r for r in rows if r['id'] == args.id)
    if row['kind'] != 'catch2':
        raise ValueError('case adapter supports Catch2 only')
    for name in row['requires_env']:
        if not os.environ.get(name):
            raise ValueError(f'Required prerequisite unset: {name}')
    parent = os.environ.get('YUZU_CONTRACT_EVIDENCE_DIR')
    with tempfile.TemporaryDirectory(prefix='yuzu_test_contract_') as scratch:
        output = Path(parent)/row['id'] if parent else Path(scratch)
        if parent:
            output.mkdir()  # Refuse an existing attempt, never overwrite its reports.
        report = output/'catch.xml'
        command = [str(Path(args.binary).resolve()), row['selector'], '--rng-seed', str(args.seed),
                   '--reporter', 'xml', '--out', str(report), '--durations=yes']
        result = bounded(command, ROOT, os.environ.copy(), output/'native.log', 90)
        print((output/'native.log').read_text(errors='replace'))
        if report.exists():
            print(report.read_text(encoding='utf-8'))
        summary = catch_verdict(report.read_text(encoding='utf-8'), row, result['exit_code'])
        write_json(output/'result.json', dict(result, **summary, contract_id=row['id'], status='PASS', selector=row['selector']))
        print('CONTRACT_RESULT=' + json.dumps(summary))
    return 0


def snapshot(rows):
    inputs = {'tests/contracts/pilots.json', 'scripts/test/contract-evidence.py',
              'scripts/test/test_db.py', 'meson.build', 'meson.options', 'tests/meson.build'}
    for row in rows:
        inputs.update(row['inputs'])
        inputs.add(row['authority']['path'])
    diff = subprocess.check_output(['git', 'diff', 'HEAD', '--binary'], cwd=ROOT, timeout=15)
    return {'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True, timeout=15).strip(),
            'diff_sha256': hashlib.sha256(diff).hexdigest(),
            'inputs': {p: sha(source_path(ROOT, p)) for p in sorted(inputs)}}, diff


def qualify_meson(records, rows):
    by_name = {}
    for record in records:
        name = record['name'].rsplit(':', 1)[-1]
        if name in by_name:
            raise ValueError(f'Duplicate Meson result: {name}')
        by_name[name] = record
    if set(by_name) != {r['meson_test'] for r in rows}:
        raise ValueError('Executed Meson selection differs from the registered plan')
    return {r['id']: by_name[r['meson_test']]['result'] for r in rows}


def check_binding(row, entry, targets, build=ROOT):
    actual = entry['cmd'][1:].copy()
    if row['kind'] == 'catch2':
        executable = targets[row['build_targets'][0]]['filename'][0]
        expected = [str(ROOT/'scripts/test/contract-evidence.py'), 'case', '--id', row['id'], '--binary', executable]
        path_positions = (0, 5)
    else:
        expected = [str(ROOT/'scripts/test/gateway-contract.py'), str(ROOT/'gateway'), row['module'], row['generator'], '--id', row['id']]
        path_positions = (0, 1)
    if len(actual) == len(expected):
        for index in path_positions:
            actual[index] = str((build/actual[index]).resolve())
            expected[index] = str((build/expected[index]).resolve())
    if actual != expected:
        raise ValueError(f'Meson command does not implement registered selector: {row["id"]}')


def check_native_evidence(out, row):
    result = json.loads((out/row['id']/'result.json').read_text())
    if result.get('contract_id') != row['id'] or result.get('status') != 'PASS' or result.get('cases') != 1:
        raise ValueError('Missing or mismatched native contract result')
    if row['kind'] == 'catch2':
        if result.get('selector') != row['selector']:
            raise ValueError('Native selector changed')
        catch_verdict((out/row['id']/'catch.xml').read_text(), row, result['exit_code'])
    elif result.get('module') != row['module'] or result.get('generator') != row['generator']:
        raise ValueError('Native Erlang selector changed')


def preserve_meson_reports(build, out, run_id):
    """Meson logs inherited credentials; raw reports never enter the bundle."""
    raw = out/'private/meson-raw'
    raw.mkdir(parents=True)
    hashes = {}
    for suffix in ('.json', '.txt', '.junit.xml'):
        source = build/'meson-logs'/(run_id+suffix)
        if not source.exists():
            continue
        saved = raw/('meson-native'+suffix)
        shutil.copy2(source, saved)
        hashes[saved.name] = sha(saved)
    if len(hashes) != 3:
        raise ValueError('Incomplete Meson reports; available raw reports preserved privately')
    records = [json.loads(line) for line in (raw/'meson-native.json').read_text(encoding='utf-8').splitlines()]
    secrets = {value for record in records for key, value in record.get('env', {}).items()
               if value and re.search(r'PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|DSN|CREDENTIAL|AUTH', key, re.I)}
    # Preserve semantic result fields. Only free-text output/commands can echo
    # credentials; ordinary short environment values must not rewrite verdicts.
    def redact(value):
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, str):
            for secret in sorted(secrets, key=len, reverse=True):
                value = value.replace(secret, '<redacted>')
        return value
    for record in records:
        record['env'] = {key: '<redacted>' for key in record.get('env', {})}
        for key in ('stdout', 'stderr', 'command'):
            if key in record:
                record[key] = redact(record[key])
    (out/'meson-native.json').write_text(''.join(json.dumps(r) + '\n' for r in records), encoding='utf-8')
    # Render from the sanitized structured report: inherited values may contain
    # newlines, so deleting a single environment-header line is insufficient.
    readable = 'Portable Meson report; environment omitted. Raw report hashes are in manifest.json.\n'
    for record in records:
        readable += '\n' + json.dumps({k: record[k] for k in ('name', 'result', 'returncode', 'duration', 'command') if k in record}) + '\n'
        readable += record.get('stdout', '') + record.get('stderr', '') + '\n'
    (out/'meson-native.txt').write_text(readable, encoding='utf-8')
    xml = ET.parse(raw/'meson-native.junit.xml')
    for node in xml.iter():
        node.text = redact(node.text)
        node.tail = redact(node.tail)
        for key in ('message',):
            if key in node.attrib:
                node.set(key, redact(node.get(key)))
    xml.write(out/'meson-native.junit.xml', encoding='utf-8', xml_declaration=True)
    return records, hashes


def collect(args, rows):
    if args.only:
        wanted = set(args.only)
        if not wanted <= {r['id'] for r in rows}:
            raise ValueError('Unknown contract selection')
        rows = [r for r in rows if r['id'] in wanted]
    build = Path(args.build_dir).resolve()
    out = Path(args.output).resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    run_id = 'contracts-' + uuid.uuid4().hex
    manifest = {'schema_version': 1, 'run_id': run_id, 'status': 'RUNNING',
                'started_at': datetime.now(timezone.utc).isoformat(),
                'planned_contracts': rows, 'platform': sys.platform, 'steps': []}
    write_json(out/'manifest.json', manifest)
    started = time.monotonic()
    records = []
    history_env = dict(os.environ, YUZU_TEST_DB=str(Path(args.history_db).resolve() if args.history_db else out/'test-runs.db'))
    def history(*arguments):
        with (out/'history.log').open('a') as log:
            subprocess.run([sys.executable, str(ROOT/'scripts/test/test_db.py'), *arguments],
                           cwd=ROOT, env=history_env, check=True, stdout=log, stderr=subprocess.STDOUT, timeout=30)
    lock = build/'.contract-evidence-lock'
    locked = False
    try:
        history('gate', '--run-id', run_id, '--phase', '0', '--gate', 'collector',
                '--status', 'RUNNING', '--duration', '0', '--notes', f'Planned capture: {out}')
        lock.mkdir()  # Only our collectors honor this lease; caller owns the build directory.
        locked = True
        manifest['source'], diff = snapshot(rows)
        (out/'source.patch').write_bytes(diff)
        for path in manifest['source']['inputs']:
            destination = out/'source'/path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT/path, destination)
        env = os.environ.copy()
        env['YUZU_CONTRACT_EVIDENCE_DIR'] = str(out)
        env['MESON_BUILD_ROOT'] = str(build)
        env['REBAR_BASE_DIR'] = str(out/'private/gateway-build')
        manifest['prerequisites'] = {key: bool(env.get(key)) for row in rows for key in row['requires_env']}
        targets = sorted({t for row in rows for t in row['build_targets']})
        if targets:
            result = bounded(['meson', 'compile', '-C', str(build), '-j', str(args.jobs), *targets],
                             ROOT, env, out/'build.log', 1800)
            manifest['steps'].append(result)
            if result['exit_code']:
                raise ValueError('Native build failed; no contract verdict issued')
        # Check registered selection before invoking Meson: a disabled gateway/build target
        # cannot disappear from the plan and silently make a smaller run green.
        entries = json.loads(subprocess.check_output(['meson', 'introspect', '--tests', str(build)], text=True, timeout=30))
        all_targets = json.loads(subprocess.check_output(['meson', 'introspect', '--targets', str(build)], text=True, timeout=30))
        by_target = {t['name']: t for t in all_targets}
        available = {entry['name']: entry for entry in entries}
        if any(row['meson_test'] not in available for row in rows):
            raise ValueError('A planned contract is absent from this Meson configuration')
        for row in rows:
            check_binding(row, available[row['meson_test']], by_target, build)
        artifacts = {path for target in all_targets if target['name'] in targets for path in target['filename']}
        manifest['binary_sha256'] = {path: sha(Path(path)) for path in sorted(artifacts)}
        manifest['meson_selection'] = [available[row['meson_test']] for row in rows]
        write_json(out/'manifest.json', manifest)
        command = ['meson', 'test', '-C', str(build), '--no-rebuild', '--num-processes', '1',
                   '--logbase', run_id, '--print-errorlogs', *[r['meson_test'] for r in rows]]
        try:
            result = bounded(command, ROOT, env, out/'meson.log', 1200, cancel_grace=5)
        except (Exception, KeyboardInterrupt):
            try:
                records, manifest['raw_meson_sha256'] = preserve_meson_reports(build, out, run_id)
            except Exception as report_error:
                manifest['report_error'] = str(report_error)
            raise
        manifest['steps'].append(result)
        records, manifest['raw_meson_sha256'] = preserve_meson_reports(build, out, run_id)
        manifest['results'] = qualify_meson(records, rows)
        for row in rows:
            if manifest['results'][row['id']] == 'OK':
                check_native_evidence(out, row)
        if snapshot(rows)[0] != manifest['source']:
            raise ValueError('Source changed during execution; evidence cannot qualify the final tree')
        manifest['status'] = 'PASS' if result['exit_code'] == 0 and all(v == 'OK' for v in manifest['results'].values()) else 'FAIL'
        # Hash the exact tested native executables/fixtures and build configuration.
        if manifest['binary_sha256'] != {path: sha(Path(path)) for path in sorted(artifacts)}:
            raise ValueError('Native binaries changed during execution')
        for name in ('intro-buildoptions.json', 'intro-compilers.json'):
            shutil.copy2(build/'meson-info'/name, out/name)
    except (Exception, KeyboardInterrupt) as error:
        manifest['status'] = 'ERROR'
        manifest['error'] = f'{type(error).__name__}: {error}'
    finally:
        if locked:
            try:
                lock.rmdir()
            except OSError as error:
                manifest['status'] = 'ERROR'
                manifest['cleanup_error'] = str(error)
        try:
            for row in rows:
                record = next((r for r in records if r['name'].rsplit(':',1)[-1] == row['meson_test']), None)
                status = 'ABORTED' if record is None else ('PASS' if record['result'] == 'OK' else 'FAIL')
                history('gate', '--run-id', run_id, '--phase', '1', '--gate', row['id'], '--status', status,
                        '--duration', str(math.ceil(record['duration'])) if record else '0', '--notes',
                        f'Native execution only; qualification/status/source in {out}/manifest.json. Missing execution duration is zero.')
            status = 'ABORTED' if manifest['status'] == 'ERROR' else manifest['status']
            history('gate', '--run-id', run_id, '--phase', '0', '--gate', 'collector', '--status', status,
                    '--duration', str(math.ceil(time.monotonic()-started)), '--notes', manifest.get('error', str(out)))
            history('run-finish', '--run-id', run_id, '--status', status)
            manifest['history_db'] = history_env['YUZU_TEST_DB']
        except Exception as error:
            manifest['status'] = 'ERROR'
            manifest['history_error'] = str(error)
        manifest['finished_at'] = datetime.now(timezone.utc).isoformat()
        # Build caches are intentionally excluded; native logs/reports and source are
        # the bundle. The output directory is private because raw logs may be sensitive.
        manifest['artifact_sha256'] = {str(p.relative_to(out)): sha(p) for p in out.rglob('*')
                                      if p.is_file() and 'private' not in p.relative_to(out).parts and p.name != 'manifest.json'}
        write_json(out/'manifest.json', manifest)
    print(f"{manifest['status']}: {out/'manifest.json'}")
    return 0 if manifest['status'] == 'PASS' else 1


def bundle(directory, destination):
    manifest = json.loads((directory/'manifest.json').read_text())
    if manifest['status'] == 'RUNNING':
        raise ValueError('Cannot bundle a running capture')
    files = manifest['artifact_sha256']
    for relative, expected in files.items():
        path = source_path(directory, relative)
        if ('private' in Path(relative).parts or
                'private' in path.relative_to(directory.resolve()).parts or sha(path) != expected):
            raise ValueError(f'Artifact changed or private: {relative}')
    with os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as output:
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
            for relative in ['manifest.json', *files]:
                archive.write(directory/relative, relative)
    print(f'Bundle: {destination}')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('check')
    pack = sub.add_parser('bundle')
    pack.add_argument('directory', type=Path)
    pack.add_argument('destination', type=Path)
    case = sub.add_parser('case')
    case.add_argument('--id', required=True)
    case.add_argument('--binary', required=True)
    case.add_argument('--seed', type=int, default=16843009)
    run = sub.add_parser('run')
    run.add_argument('--build-dir', required=True)
    run.add_argument('--output', required=True)
    run.add_argument('--only', action='append')
    run.add_argument('--jobs', type=int, default=4)
    run.add_argument('--history-db')
    args = parser.parse_args()
    try:
        if args.command == 'bundle':
            return bundle(args.directory.resolve(), args.destination)
        rows = load_registry()
        if args.command == 'case':
            return run_case(args, rows)
        if args.command == 'run':
            return collect(args, rows)
        print(f'{len(rows)} contract definitions valid; no runtime conformance claimed')
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print(f'contract-evidence: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    if os.name != 'nt':
        signal.signal(signal.SIGTERM, termination_interrupt)
    sys.exit(main())
