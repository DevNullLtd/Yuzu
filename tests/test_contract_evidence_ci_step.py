#!/usr/bin/env python3
"""Pin how ci.yml's Linux "Contract migration evidence" step builds the pilots.

The step used to leave the build to the collector, which compiled the pilots'
targets at -j2 inside a heavy-test slot: the step took 6 to 50 min for six
tests that run in under half a minute, while the Linux test step waited for
the same three slots. Four things keep that from coming back:

  1. the step compiles the pilots' targets at "$YUZU_BUILD_JOBS" BEFORE the
     with-test-slot call that runs the collector;
  2. the target list is read from tests/contracts/pilots.json, so a new pilot's
     targets are precompiled too rather than falling back to the slow path;
  3. the Configure step turns ccache's hash_dir off for the gcc-15 debug leg
     (the only leg with a contract build dir), and only that leg, so that
     second build dir reuses the standard build's objects;
  4. a failed precompile stays a warning: the collector and the evidence
     bundle still run after it.

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
        # The only guard on the compile is "there are targets".
        self.assertRegex('\n'.join(self.lines),
                         r'if \(\( \$\{#contract_targets\[@\]\} \)\); then\n'
                         r'(?:[^\n]*\n){0,3}?[^\n]*meson compile -C "\$CONTRACT_BUILD"')

    def test_precompile_is_bounded_and_not_fatal(self):
        code = '\n'.join(self.lines)
        self.assertIn('timeout -k 30 "$YUZU_CONTRACT_BUILD_TIMEOUT_S"', code)
        # The warning is the whole fallback: no exit/return/false after it, and
        # the if-block closes on the next line.
        self.assertRegex(code, r'\|\| echo "::warning::contract pilot precompile failed[^"\n]*"\nfi\n')
        warn_at = self.index_of('::warning::contract pilot precompile failed')
        self.assertLess(warn_at, self.index_of('with-test-slot.sh'))
        self.assertLess(self.index_of('with-test-slot.sh'),
                        self.index_of('contract-evidence.py bundle'))

    def test_targets_come_from_the_pilot_registry(self):
        at = self.index_of('contract_targets_list=$(python3 -c')
        self.assertIn('tests/contracts/pilots.json', self.lines[at])
        self.assertIn('build_targets', self.lines[at])
        self.assertIn('read -r -a contract_targets <<< "$contract_targets_list"',
                      self.lines[at + 2])
        with open(os.path.join(ROOT, 'tests', 'contracts', 'pilots.json'), encoding='utf-8') as f:
            targets = {t for r in json.load(f)['contracts'] for t in r['build_targets']}
        self.assertIn('yuzu_server_tests', targets,
                      'the precompile exists for the server test binary; update this test if '
                      'no pilot needs it any more')

    def test_hash_dir_off_for_the_contract_leg_only(self):
        code = '\n'.join(code_lines(step('Configure (Meson)')['run']))
        self.assertIn('BUILDDIR=build-linux-${{ matrix.compiler }}-${{ matrix.build_type }}', code)
        self.assertRegex(code, r'if \[\[ "\$BUILDDIR" == build-linux-gcc-15-debug \]\]; then\n'
                               r'echo "CCACHE_NOHASHDIR=1" >> "\$GITHUB_ENV"\nfi\n')
        self.assertEqual(code.count('CCACHE_NOHASHDIR'), 1,
                         'CCACHE_NOHASHDIR must be set only inside the gcc-15 debug branch')
        self.assertEqual(self.contract.get('if'),
                         "matrix.compiler == 'gcc-15' && matrix.build_type == 'debug'",
                         'the hash_dir leg and the contract leg must stay the same leg')


if __name__ == '__main__':
    unittest.main()
