#!/usr/bin/env python3
"""Pin how ci.yml's Linux "Contract migration evidence" step builds the pilots.

The step used to leave the build to the collector, which compiled the pilots'
targets at -j2 inside a heavy-test slot: 7-50 min of slot time for six tests
that run in under half a minute, while the Linux test step waited for the
same three slots. Three things keep that from coming back:

  1. the step compiles the pilots' targets at "$YUZU_BUILD_JOBS" BEFORE the
     with-test-slot call that runs the collector;
  2. the target list is read from tests/contracts/pilots.json, so a new pilot's
     targets are precompiled too rather than falling back to the slow path;
  3. the Configure step turns ccache's hash_dir off for the gcc-15 debug leg
     (the only leg with a contract build dir), so that second build dir reuses
     the standard build's objects.

Lexical and hermetic: reads ci.yml and pilots.json, runs nothing.
"""
import json
import os
import unittest

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))


def linux_steps():
    with open(os.path.join(ROOT, '.github', 'workflows', 'ci.yml'), encoding='utf-8') as f:
        return yaml.safe_load(f)['jobs']['linux']['steps']


def step(name):
    found = [s for s in linux_steps() if s.get('name') == name]
    if len(found) != 1:
        raise AssertionError(f'expected exactly one Linux step named {name!r}, found {len(found)}')
    return found[0]


def code_lines(script):
    return [line.strip() for line in script.splitlines()
            if line.strip() and not line.strip().startswith('#')]


class ContractStepPrecompile(unittest.TestCase):
    def setUp(self):
        self.contract = step('Contract migration evidence')
        self.lines = code_lines(self.contract['run'])

    def index_of(self, needle):
        hits = [i for i, line in enumerate(self.lines) if needle in line]
        self.assertTrue(hits, f'no code line in the contract step contains {needle!r}')
        return hits[0]

    def test_precompile_runs_full_width_before_the_slot(self):
        compile_at = self.index_of('meson compile -C "$CONTRACT_BUILD"')
        self.assertIn('-j "$YUZU_BUILD_JOBS"', self.lines[compile_at])
        self.assertIn('"${contract_targets[@]}"', self.lines[compile_at])
        slot_at = self.index_of('with-test-slot.sh')
        self.assertLess(compile_at, slot_at,
                        'the pilots must be compiled before a heavy-test slot is taken')

    def test_precompile_is_bounded_and_not_fatal(self):
        script = self.contract['run']
        self.assertIn('timeout "$YUZU_CONTRACT_BUILD_TIMEOUT_S"', script)
        self.assertIn('|| echo "::warning::contract pilot precompile failed', script)

    def test_targets_come_from_the_pilot_registry(self):
        at = self.index_of('mapfile -t contract_targets')
        self.assertIn('tests/contracts/pilots.json', self.lines[at])
        self.assertIn('build_targets', self.lines[at])
        with open(os.path.join(ROOT, 'tests', 'contracts', 'pilots.json'), encoding='utf-8') as f:
            targets = {t for r in json.load(f)['contracts'] for t in r['build_targets']}
        self.assertIn('yuzu_server_tests', targets,
                      'the precompile exists for the server test binary; update this test if '
                      'no pilot needs it any more')

    def test_hash_dir_off_for_the_contract_leg_only(self):
        script = step('Configure (Meson)')['run']
        self.assertIn('if [[ "$BUILDDIR" == build-linux-gcc-15-debug ]]; then', script)
        self.assertIn('echo "CCACHE_NOHASHDIR=1" >> "$GITHUB_ENV"', script)
        self.assertEqual(self.contract.get('if'),
                         "matrix.compiler == 'gcc-15' && matrix.build_type == 'debug'",
                         'the hash_dir leg and the contract leg must stay the same leg')


if __name__ == '__main__':
    unittest.main()
