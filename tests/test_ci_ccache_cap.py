#!/usr/bin/env python3
"""Pin one CCACHE_MAXSIZE per self-hosted runner pool.

A self-hosted runner keeps one ccache directory for every job it picks up
(on Big Tam, /home/runner/rN/home/.cache/ccache per runner). ccache enforces
the cap of the job that is writing, so one job with a smaller cap trims the
cache every other job on that runner relies on. codeql.yml and
sanitizer-tests.yml carried 500M while ci.yml, nightly.yml and release.yml
carried 30G: the daily CodeQL trace cut a Big Tam runner's ~30 GB cache to
3-4 GB, and that runner's next 12 h of CI ran 13-20 points below the other
runners' hit rate (measured 2026-11-12 to -17).

Rules, over every workflow job that runs on a self-hosted pool and calls
ccache:
  1. its effective CCACHE_MAXSIZE (job env over workflow env) is set;
  2. every such job on the same pool has the same value;
  3. no step changes it, by step env or by writing to $GITHUB_ENV;
  4. the CodeQL-traced build disables ccache rather than recaching (see the
     comment on that step in codeql.yml).

Lexical and hermetic: reads .github/workflows/*.yml, runs nothing.
"""
import glob
import json
import os
import re
import unittest

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
WORKFLOWS = os.path.join(ROOT, '.github', 'workflows')
POOL_LABEL = re.compile(r'^yuzu-[a-z0-9]+-(linux|windows|macos)$')


def load(path):
    with open(path, encoding='utf-8') as f:
        return yaml.safe_load(f)


def runner_label_sets(job):
    """Every label set the job can run on; raises on a form it cannot resolve."""
    runs_on = job.get('runs-on')
    if isinstance(runs_on, str) and '${{' in runs_on:
        m = re.fullmatch(r'\$\{\{\s*matrix\.(\w+)\s*\}\}', runs_on.strip())
        if not m:
            raise AssertionError(f'unresolvable runs-on expression {runs_on!r}')
        key = m.group(1)
        matrix = (job.get('strategy') or {}).get('matrix') or {}
        values = list(matrix.get(key) or [])
        values += [inc[key] for inc in matrix.get('include') or [] if key in inc]
        if not values:
            raise AssertionError(f'runs-on uses matrix.{key} but the matrix has no {key}')
        return [v if isinstance(v, list) else [v] for v in values]
    if isinstance(runs_on, str):
        return [[runs_on]]
    if isinstance(runs_on, list):
        return [runs_on]
    raise AssertionError(f'unsupported runs-on {runs_on!r}')


def pool_of(labels):
    if 'self-hosted' not in labels:
        return None
    pools = [l for l in labels if isinstance(l, str) and POOL_LABEL.match(l)]
    if len(pools) != 1:
        raise AssertionError(f'self-hosted label set {labels!r} names no single yuzu-* pool')
    return pools[0]


def self_hosted_ccache_jobs():
    """Yield (workflow file, job id, job, pool, effective cap)."""
    for path in sorted(glob.glob(os.path.join(WORKFLOWS, '*.yml'))):
        doc = load(path)
        wf_env = doc.get('env') or {}
        for job_id, job in (doc.get('jobs') or {}).items():
            if 'ccache' not in json.dumps(job):
                continue
            if 'uses' in job and 'runs-on' not in job:
                continue  # reusable-workflow call; the callee is checked itself
            cap = (job.get('env') or {}).get('CCACHE_MAXSIZE', wf_env.get('CCACHE_MAXSIZE'))
            for labels in runner_label_sets(job):
                pool = pool_of(labels)
                if pool:
                    yield os.path.basename(path), job_id, job, pool, cap


class CcacheCapTests(unittest.TestCase):

    def test_some_self_hosted_ccache_jobs_found(self):
        pools = {pool for _, _, _, pool, _ in self_hosted_ccache_jobs()}
        self.assertIn('yuzu-bigtam-linux', pools)
        self.assertIn('yuzu-weetam-windows', pools)

    def test_every_job_sets_a_cap(self):
        for wf, job_id, _, pool, cap in self_hosted_ccache_jobs():
            with self.subTest(job=f'{wf}:{job_id}'):
                self.assertIsNotNone(
                    cap, f'{wf}:{job_id} runs ccache on {pool} with no CCACHE_MAXSIZE; '
                         f'ccache then uses its built-in cap and trims the shared cache to it')

    def test_one_cap_per_pool(self):
        caps = {}
        for wf, job_id, _, pool, cap in self_hosted_ccache_jobs():
            caps.setdefault(pool, {}).setdefault(str(cap), []).append(f'{wf}:{job_id}')
        for pool, by_cap in caps.items():
            with self.subTest(pool=pool):
                self.assertEqual(
                    len(by_cap), 1,
                    f'{pool} jobs disagree on CCACHE_MAXSIZE: {by_cap}. The smallest cap '
                    f'trims the cache every other job on that runner uses.')

    def test_no_step_changes_the_cap(self):
        for wf, job_id, job, _, _ in self_hosted_ccache_jobs():
            for step in job.get('steps') or []:
                with self.subTest(job=f'{wf}:{job_id}', step=step.get('name') or step.get('uses')):
                    self.assertNotIn('CCACHE_MAXSIZE', step.get('env') or {})
                    self.assertNotRegex(step.get('run') or '', r'CCACHE_MAXSIZE\s*=|ccache\s+(-M|--max-size)')

    def test_codeql_traced_build_disables_ccache(self):
        steps = load(os.path.join(WORKFLOWS, 'codeql.yml'))['jobs']['analyze']['steps']
        build = [s for s in steps if s.get('name') == 'Build (CodeQL-traced)']
        self.assertEqual(len(build), 1)
        env = build[0].get('env') or {}
        self.assertEqual(env.get('CCACHE_DISABLE'), 'true')
        self.assertNotIn('CCACHE_RECACHE', env)


if __name__ == '__main__':
    unittest.main()
