#!/usr/bin/env python3
"""Pin the gateway EUnit shard partition (scripts/gateway_eunit_shards.py).

Meson runs the gateway eunit suite as shards (`gateway eunit shard A`, `...
shard B`; root meson.build), each `scripts/test_gateway.py <gw> eunit
--shard K/N`. A shard split is only safe if the shards together run exactly
what the whole-suite `rebar3 eunit --dir apps/yuzu_gw/test` run did. This
file pins:

  1. the partition covers every eunit unit exactly once, for N in {1, 2, 3},
     over the real test directory and over a synthetic one;
  2. a newly added module lands in exactly one shard, with no edit to the
     weight table;
  3. the unit set mirrors eunit's own `--dir` rules (top level only; `M_tests`
     dropped when `M` is present; helper modules kept);
  4. the partition is deterministic (independent of listing order);
  5. the wrapper hands rebar3 that shard's list through
     gateway/eunit_shard.config.script (REBAR_CONFIG +
     YUZU_GW_EUNIT_SHARD_MODULES; each module `{spawn, {module, M}}`, one
     process per module as under `--dir`), keeps `--dir` for the whole-suite
     run, fails a shard whose output names a module outside it, and refuses
     a malformed shard before running anything;
  6. root meson.build's shard table, the CI registration check
     (scripts/ci/assert-gateway-tests.py) and the partition agree.

Hermetic: no rebar3, no network. The wrapper case (5) runs test_gateway.py
against a fake `rebar3` in a private temp dir (POSIX only: on Windows the
wrapper resolves escript.exe + the rebar3 escript, not a PATH `rebar3`).
"""
import os
import random
import re
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

import gateway_eunit_shards as ges  # noqa: E402

WRAPPER = os.path.join(ROOT, 'scripts', 'test_gateway.py')
MESON = os.path.join(ROOT, 'meson.build')
ASSERT_SCRIPT = os.path.join(ROOT, 'scripts', 'ci', 'assert-gateway-tests.py')
TEST_DIR = os.path.join(ROOT, 'gateway', 'apps', 'yuzu_gw', 'test')


def _read(path):
    with open(path, encoding='utf-8') as f:
        return f.read()


def _assert_exact_cover(tc, shards, units):
    seen = [m for s in shards for m in s]
    tc.assertEqual(len(seen), len(set(seen)), 'a module is in two shards')
    tc.assertEqual(sorted(seen), sorted(units), 'shards do not cover the unit set')
    for s in shards:
        tc.assertEqual(s, sorted(s), 'a shard is not in sorted run order')


class Partition(unittest.TestCase):

    def test_real_test_dir_is_covered_exactly_once(self):
        mods = ges.list_test_modules(TEST_DIR)
        units = ges.eunit_units(mods)
        self.assertTrue(any(m.endswith('_tests') for m in units))
        for n in (1, 2, 3):
            with self.subTest(n=n):
                shards = ges.partition(mods, n)
                self.assertEqual(len(shards), n)
                _assert_exact_cover(self, shards, units)
                for s in shards:
                    self.assertTrue(any(m.endswith('_tests') for m in s),
                                    f'shard {s} has no test module')
        self.assertEqual(ges.partition(mods, 1), [units])

    def test_real_test_dir_shards_are_balanced(self):
        # Balance is a property of the committed hints, not a correctness
        # rule; this only catches a gross regression (e.g. every heavy
        # module in one shard) before a CI leg discovers it as a timeout.
        mods = ges.list_test_modules(TEST_DIR)
        for n in (2, 3):
            with self.subTest(n=n):
                loads = [ges.shard_load(s) for s in ges.partition(mods, n)]
                self.assertLessEqual(max(loads) - min(loads),
                                     max(ges.WEIGHT_HINTS.values()), loads)

    def test_added_module_lands_in_exactly_one_shard(self):
        mods = ges.list_test_modules(TEST_DIR)
        for new in ('yuzu_gw_aaa_new_tests', 'yuzu_gw_zzz_new_tests', 'yuzu_gw_new_helper'):
            for n in (1, 2, 3):
                with self.subTest(new=new, n=n):
                    shards = ges.partition(mods + [new], n)
                    self.assertEqual(sum(s.count(new) for s in shards), 1)
                    _assert_exact_cover(self, shards, ges.eunit_units(mods + [new]))

    def test_synthetic_dirs_are_covered_exactly_once(self):
        rng = random.Random(4800)
        for size in (1, 2, 3, 7, 40):
            mods = [f'm{i:02d}_tests' for i in range(size)] + ['helper_a', 'helper_b']
            hints = {m: rng.uniform(0.5, 60.0) for m in mods[: size // 2]}
            for n in (1, 2, 3):
                with self.subTest(size=size, n=n):
                    _assert_exact_cover(self, ges.partition(mods, n, hints),
                                        ges.eunit_units(mods))

    def test_deterministic_regardless_of_listing_order(self):
        mods = ges.list_test_modules(TEST_DIR)
        want = ges.partition(mods, 2)
        rng = random.Random(2093)
        for _ in range(5):
            shuffled = list(mods)
            rng.shuffle(shuffled)
            self.assertEqual(ges.partition(shuffled, 2), want)

    def test_bad_shard_count_is_refused(self):
        with self.assertRaises(ValueError):
            ges.partition(['a_tests'], 0)


class EunitDirRules(unittest.TestCase):

    def test_tests_module_is_dropped_when_its_base_is_present(self):
        # eunit_data:get_directory_module_tests/1: running `m` already runs
        # `m_tests`, so `--dir` never hands eunit `m_tests` separately.
        self.assertEqual(ges.eunit_units(['m', 'm_tests', 'x_tests', 'helper']),
                         ['helper', 'm', 'x_tests'])

    def test_only_top_level_erl_files_are_listed(self):
        with tempfile.TemporaryDirectory(prefix='yuzu_test_') as d:
            os.makedirs(os.path.join(d, 'ct'))
            for f in ('a_tests.erl', 'helper.erl', 'notes.txt', 'b_tests.beam',
                      os.path.join('ct', 'x_SUITE.erl')):
                open(os.path.join(d, f), 'w').close()
            self.assertEqual(ges.list_test_modules(d), ['a_tests', 'helper'])

    def test_real_dir_excludes_ct_suites_and_keeps_helpers(self):
        mods = ges.list_test_modules(TEST_DIR)
        self.assertFalse([m for m in mods if m.endswith('_SUITE')])
        self.assertIn('yuzu_gw_test_listener', mods)

    def test_helpers_carry_no_hint_weight_by_default(self):
        self.assertEqual(ges.weight('some_helper', {}), ges.DEFAULT_HELPER_WEIGHT)
        self.assertEqual(ges.weight('some_tests', {}), ges.DEFAULT_TEST_WEIGHT)

    def test_every_weight_hint_names_a_real_module(self):
        # A stale hint cannot drop or duplicate anything; it only stops
        # steering balance. Fail so the table is kept honest.
        mods = set(ges.list_test_modules(TEST_DIR))
        self.assertEqual(sorted(set(ges.WEIGHT_HINTS) - mods), [])

    def test_parse_shard(self):
        self.assertEqual(ges.parse_shard('1/2'), (1, 2))
        self.assertEqual(ges.parse_shard('3/3'), (3, 3))
        for bad in ('0/2', '3/2', '1', '1/2/3', 'a/b', '', '-1/2'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ges.parse_shard(bad)


class MesonAndCiAgree(unittest.TestCase):

    def _meson_shards(self):
        m = re.search(r"_gw_eunit_shards = \{([^}]*)\}", _read(MESON))
        self.assertIsNotNone(m, 'root meson.build has no _gw_eunit_shards table')
        return re.findall(r"'([A-Z])':\s*'(\d+)/(\d+)'", m.group(1))

    def test_shard_table_is_a_complete_k_of_n_set(self):
        entries = self._meson_shards()
        n = len(entries)
        self.assertGreaterEqual(n, 2)
        self.assertEqual([e[0] for e in entries], [chr(ord('A') + i) for i in range(n)])
        self.assertEqual([(int(k), int(t)) for _, k, t in entries],
                         [(i + 1, n) for i in range(n)])

    def test_each_shard_has_its_own_rebar_base_dir(self):
        meson = _read(MESON)
        block = re.search(r"foreach _gw_shard_name, _gw_shard_spec : _gw_eunit_shards(.*?)endforeach",
                          meson, re.S)
        self.assertIsNotNone(block)
        body = block.group(1)
        self.assertIn("'--shard', _gw_shard_spec", body)
        self.assertRegex(body, r"'REBAR_BASE_DIR': _gw_src / \('_build_eunit_' \+ _gw_shard_spec\.split\('/'\)\[0\]\)")
        self.assertIn("suite: 'gateway'", body)

    def test_ci_registration_check_requires_every_shard(self):
        src = _read(ASSERT_SCRIPT)
        m = re.search(r'REQUIRED = \(([^)]*)\)', src)
        self.assertIsNotNone(m)
        required = re.findall(r'"([^"]+)"', m.group(1))
        want = ['gateway eunit shard ' + e[0] for e in self._meson_shards()] + ['gateway ct']
        self.assertEqual(sorted(required), sorted(want))


class ShardConfigScript(unittest.TestCase):
    # gateway/eunit_shard.config.script is what turns the wrapper's module
    # list into eunit tests; Erlang is not assumed here, so pin its text.

    def test_script_reads_the_wrapper_env_and_spawns_each_module(self):
        path = os.path.join(ROOT, 'gateway', ges.SHARD_CONFIG_SCRIPT)
        src = _read(path)
        self.assertIn('os:getenv("YUZU_GW_EUNIT_SHARD_MODULES"', src)
        self.assertIn('{eunit_tests, [{spawn, {module, M}} || M <- Mods]}', src)
        self.assertIn('"rebar.config"', src)
        wrapper = _read(WRAPPER)
        self.assertIn('env["YUZU_GW_EUNIT_SHARD_MODULES"]', wrapper)
        self.assertIn('env["REBAR_CONFIG"]', wrapper)

    def test_foreign_modules(self):
        out = ("module 'a_tests'\n  module 'base_tests'\n"
               "module 'base'\nmodule 'yuzu_gw_app'\n  module 'zz_tests'\n")
        self.assertEqual(ges.foreign_modules(out, ['a_tests', 'base']),
                         ['yuzu_gw_app', 'zz_tests'])
        self.assertEqual(ges.foreign_modules(out, ['a_tests', 'base', 'yuzu_gw_app', 'zz_tests']), [])


@unittest.skipIf(os.name == 'nt', 'the wrapper resolves escript.exe, not a PATH rebar3, on Windows')
class WrapperShardArgs(unittest.TestCase):
    # test_gateway.py against a fake rebar3 that prints its argv, the shard
    # env the wrapper set, any extra lines in FAKE_EXTRA, and a passing eunit
    # summary: what the wrapper asks rebar3 to run.

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='yuzu_test_')
        d = self._tmp.name
        self.gw = os.path.join(d, 'gateway')
        self.test_dir = os.path.join(self.gw, 'apps', 'yuzu_gw', 'test')
        os.makedirs(os.path.join(self.test_dir, 'ct'))
        self.mods = ['alpha_tests', 'beta_tests', 'gamma_tests', 'delta_tests',
                     'yuzu_gw_app_tests', 'helper', 'base', 'base_tests']
        for m in self.mods:
            open(os.path.join(self.test_dir, m + '.erl'), 'w').close()
        open(os.path.join(self.test_dir, 'ct', 'x_SUITE.erl'), 'w').close()
        open(os.path.join(self.gw, ges.SHARD_CONFIG_SCRIPT), 'w').close()
        bindir = os.path.join(d, 'bin')
        os.makedirs(bindir)
        fake = os.path.join(bindir, 'rebar3')
        with open(fake, 'w') as f:
            f.write('#!/bin/sh\n'
                    'echo "FAKE-ARGV: $*"\n'
                    'echo "FAKE-CONFIG: ${REBAR_CONFIG:-<unset>}"\n'
                    'echo "FAKE-MODS: ${YUZU_GW_EUNIT_SHARD_MODULES:-<unset>}"\n'
                    'printf "%b" "${FAKE_EXTRA:-}"\n'
                    'echo "  All 3 tests passed."\n')
        os.chmod(fake, os.stat(fake).st_mode | stat.S_IXUSR)
        # The wrapper prepends these to PATH when absent; listing them after
        # the fake keeps a real rebar3 there from shadowing it.
        extra = [os.path.expanduser('~/.cache/rebar3/bin'), '/usr/local/bin']
        self.env = dict(os.environ,
                        PATH=os.pathsep.join([bindir] + extra + [os.environ.get('PATH', '')]),
                        REBAR_BASE_DIR=os.path.join(d, '_build_x'))
        # An outer shard selection must never leak into a whole-suite run.
        self.env['REBAR_CONFIG'] = 'outer.config'
        self.env['YUZU_GW_EUNIT_SHARD_MODULES'] = 'outer_tests'

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, *args, extra=''):
        env = dict(self.env, FAKE_EXTRA=extra)
        p = subprocess.run([sys.executable, WRAPPER, self.gw, *args], env=env,
                           capture_output=True, text=True, timeout=60)

        def field(name):
            m = re.search(r'^FAKE-%s: (.*)$' % name, p.stdout, re.M)
            return m.group(1) if m else None

        argv = field('ARGV')
        return (p.returncode, argv.split() if argv is not None else None,
                field('CONFIG'), field('MODS'), p.stdout + p.stderr)

    def test_shards_select_their_modules_and_cover_the_dir(self):
        units = ges.eunit_units(self.mods)
        config = os.path.join(os.path.realpath(self.gw), ges.SHARD_CONFIG_SCRIPT)
        for n in (1, 2, 3):
            got = []
            for k in range(1, n + 1):
                rc, argv, cfg, mods, log = self._run('eunit', '--shard', f'{k}/{n}')
                self.assertEqual(rc, 0, log)
                # No test named on the command line: rebar3 must take the
                # config script's eunit_tests.
                self.assertEqual(argv, ['as', 'test', 'eunit'], log)
                self.assertEqual(os.path.realpath(cfg), config, log)
                shard = mods.split(',')
                self.assertEqual(shard, ges.partition(self.mods, n)[k - 1])
                got.append(shard)
            _assert_exact_cover(self, got, units)
            self.assertNotIn('base_tests', [m for s in got for m in s])

    def test_whole_suite_keeps_dir_and_drops_any_shard_env(self):
        rc, argv, cfg, mods, log = self._run('eunit')
        self.assertEqual(rc, 0, log)
        self.assertEqual(argv, ['as', 'test', 'eunit', '--dir', 'apps/yuzu_gw/test'], log)
        self.assertEqual((cfg, mods), ('<unset>', '<unset>'), log)
        rc, argv, cfg, mods, log = self._run('ct')
        self.assertEqual((cfg, mods), ('<unset>', '<unset>'), log)

    def test_a_shard_that_runs_a_foreign_module_fails(self):
        mine = ges.partition(self.mods, 2)[0]
        theirs = ges.partition(self.mods, 2)[1]
        ok = "module '%s'\\n" % mine[0]
        rc, *_, log = self._run('eunit', '--shard', '1/2', extra=ok)
        self.assertEqual(rc, 0, log)
        bad = ok + "module '%s'\\n" % theirs[0]
        rc, *_, log = self._run('eunit', '--shard', '1/2', extra=bad)
        self.assertEqual(rc, 1, log)
        self.assertIn('outside this shard', log)

    def test_malformed_shard_is_refused_before_rebar3(self):
        for args in (('eunit', '--shard', '3/2'), ('eunit', '--shard', 'x'),
                     ('eunit', '--shard'), ('eunit', '1/2'), ('ct', '--shard', '1/2')):
            with self.subTest(args=args):
                rc, argv, _, _, log = self._run(*args)
                self.assertEqual(rc, 2, log)
                self.assertIsNone(argv, log)

    def test_empty_shard_is_refused(self):
        # More shards than units (`base_tests` folds into `base`), so the
        # last one is empty: refused loudly rather than run as zero tests.
        n = len(ges.eunit_units(self.mods)) + 1
        rc, argv, _, _, log = self._run('eunit', '--shard', f'{n}/{n}')
        self.assertEqual(rc, 2, log)
        self.assertIsNone(argv, log)

    def test_missing_config_script_is_refused(self):
        os.remove(os.path.join(self.gw, ges.SHARD_CONFIG_SCRIPT))
        rc, argv, _, _, log = self._run('eunit', '--shard', '1/2')
        self.assertEqual(rc, 2, log)
        self.assertIsNone(argv, log)


if __name__ == '__main__':
    unittest.main()
