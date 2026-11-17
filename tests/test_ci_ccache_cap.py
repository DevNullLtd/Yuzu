#!/usr/bin/env python3
"""Pin one CCACHE_MAXSIZE per self-hosted runner pool.

A self-hosted runner keeps one ccache directory for every job it picks up (on
Big Tam, /home/runner/rN/home/.cache/ccache per runner). ccache enforces the
cap of the job that is writing, so one job with a smaller cap trims the cache
every other job on that runner relies on. codeql.yml and sanitizer-tests.yml
carried 500M while ci.yml, nightly.yml and release.yml carried 30G: each daily
CodeQL trace cut a Big Tam runner's cache to 2.8-5.2 GB (from as much as 30
GB), and in four of five such trims (2026-11-12 to -16) that runner's next 12 h
of CI hit the cache 13-24 points less often than the other runners did.

Rules, over every workflow job that runs on a self-hosted pool and mentions
ccache:
  1. its effective CCACHE_MAXSIZE (job env over workflow env) is set;
  2. every such job on the same pool has the same value;
  3. nothing else in the job sets or changes the cap or empties the cache:
     no CCACHE_MAXSIZE outside the job env (step env, container env,
     defaults, a $GITHUB_ENV write), no CCACHE_CONFIGPATH, and no
     `max_size`/`max-size`/`ccache.conf` or `ccache -M/-F/-o/-C/--set-config/
     --max-size/--max-files/--evict*/--clear/--cleanup` anywhere in the job.
     These are matched as text over the whole job, step names and paths
     included, so a step merely named "max-size report" also fails: rename it;
  4. no such job uses CCACHE_RECACHE (job, step or workflow env), and the
     CodeQL-traced build disables ccache (see the comment on that step in
     codeql.yml).

What it cannot see: it reads only the workflow files, so a cap change or a
wipe made inside a script under scripts/ or inside an action a job calls is
invisible, and so is a job that reaches ccache only that way and never names
it. None does today.

Lexical and hermetic: reads .github/workflows/*.yml and *.yaml, runs nothing.
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
CAP_CHANGE = re.compile(
    r'max[_-]size|ccache\.conf'
    r'|CCACHE_CONFIGPATH'
    r'|ccache\s+(-M|-F\b|-o\b|-C\b|--set-config|--max-size|--max-files|--evict|--clear|--cleanup)',
    re.IGNORECASE)


def load(path):
    with open(path, encoding='utf-8') as f:
        return yaml.safe_load(f)


def workflow_files():
    return sorted(glob.glob(os.path.join(WORKFLOWS, '*.yml'))
                  + glob.glob(os.path.join(WORKFLOWS, '*.yaml')))


def runner_label_sets(where, job):
    """Every label set the job can run on; raises, naming the job, on a form it cannot resolve."""
    runs_on = job.get('runs-on')
    hint = (f'{where}: add support for this runs-on form to tests/test_ci_ccache_cap.py, '
            f'so the job\'s CCACHE_MAXSIZE can be checked against its pool')
    if isinstance(runs_on, str) and '${{' in runs_on:
        m = re.fullmatch(r'\$\{\{\s*matrix\.(\w+)\s*\}\}', runs_on.strip())
        matrix = (job.get('strategy') or {}).get('matrix')
        if not m or not isinstance(matrix, dict):
            raise AssertionError(f'unresolvable runs-on {runs_on!r}. {hint}')
        key = m.group(1)
        values = list(matrix.get(key) or [])
        values += [inc[key] for inc in matrix.get('include') or []
                   if isinstance(inc, dict) and key in inc]
        if not values:
            raise AssertionError(f'runs-on uses matrix.{key} but the matrix has no {key}. {hint}')
        return [v if isinstance(v, list) else [v] for v in values]
    if isinstance(runs_on, str):
        return [[runs_on]]
    if isinstance(runs_on, list):
        return [runs_on]
    raise AssertionError(f'unsupported runs-on {runs_on!r}. {hint}')


def pool_of(where, labels):
    if 'self-hosted' not in labels:
        return None
    pools = [l for l in labels if isinstance(l, str) and POOL_LABEL.match(l)]
    if len(pools) != 1:
        raise AssertionError(f'{where}: self-hosted label set {labels!r} names no single yuzu-* pool')
    return pools[0]


def self_hosted_ccache_jobs():
    """Yield (workflow file, job id, job, pool, effective cap)."""
    for path in workflow_files():
        doc = load(path)
        wf = os.path.basename(path)
        wf_env = doc.get('env') or {}
        for job_id, job in (doc.get('jobs') or {}).items():
            if 'ccache' not in json.dumps(job).lower():
                continue
            if 'uses' in job and 'runs-on' not in job:
                continue  # reusable-workflow call; the callee is checked itself
            where = f'{wf}:{job_id}'
            cap = (job.get('env') or {}).get('CCACHE_MAXSIZE', wf_env.get('CCACHE_MAXSIZE'))
            for labels in runner_label_sets(where, job):
                pool = pool_of(where, labels)
                if pool:
                    yield wf, job_id, job, pool, cap


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

    def test_nothing_else_changes_the_cap(self):
        for wf, job_id, job, _, _ in self_hosted_ccache_jobs():
            rest = json.dumps({k: v for k, v in job.items() if k != 'env'})
            with self.subTest(job=f'{wf}:{job_id}'):
                self.assertFalse('CCACHE_MAXSIZE' in rest,
                                 f'{wf}:{job_id} sets CCACHE_MAXSIZE outside its job env')
                m = CAP_CHANGE.search(rest)
                self.assertIsNone(m, f'{wf}:{job_id} changes the ccache cap or empties the '
                                     f'cache ({m.group(0) if m else ""!r})')
                self.assertFalse('CCACHE_RECACHE' in json.dumps(job),
                                 f'{wf}:{job_id} uses CCACHE_RECACHE; use CCACHE_DISABLE')
        for path in workflow_files():
            doc = load(path)
            rest = json.dumps({k: v for k, v in doc.items() if k not in ('env', 'jobs')})
            with self.subTest(workflow=os.path.basename(path)):
                self.assertFalse('CCACHE_RECACHE' in json.dumps(doc.get('env') or {}),
                                 f'{os.path.basename(path)} sets CCACHE_RECACHE in its '
                                 f'workflow env; use CCACHE_DISABLE on the step that needs it')
                self.assertFalse('CCACHE_MAXSIZE' in rest,
                                 f'{os.path.basename(path)} sets CCACHE_MAXSIZE outside '
                                 f'its workflow env')

    def test_codeql_traced_build_disables_ccache(self):
        steps = load(os.path.join(WORKFLOWS, 'codeql.yml'))['jobs']['analyze']['steps']
        build = [s for s in steps if s.get('name') == 'Build (CodeQL-traced)']
        self.assertEqual(len(build), 1,
                         'codeql.yml job "analyze" needs exactly one step named '
                         '"Build (CodeQL-traced)"; if it was renamed, update this test')
        env = build[0].get('env') or {}
        self.assertEqual(env.get('CCACHE_DISABLE'), 'true',
                         'the CodeQL-traced build must run with CCACHE_DISABLE=true')


if __name__ == '__main__':
    unittest.main()
