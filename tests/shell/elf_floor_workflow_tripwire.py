#!/usr/bin/env python3
"""Tripwire for tests/shell/test_check_elf_floor.sh (ADR-2003 S0).

The ELF floor gate is report-only in S0, and its release.yml step is
`continue-on-error: true` ON PURPOSE. The day S2 wires `--enforce`, that same
`continue-on-error` would swallow the gate's exit 1 and the gate would never
gate. This script fails if any workflow or local composite action contains a
step that (probably) runs `check-elf-floor.sh --enforce` and can swallow its
exit status.

It is a GUARD, not a proof. It parses the YAML (PyYAML) and reasons about the
text of `run:` blocks; it cannot follow a script it cannot see, so it is
deliberately conservative in one direction only: whenever it cannot tell
whether a step enforces, it assumes it does. Report-only steps (where
continue-on-error is required) are never flagged. VACUOUS TODAY: no step
enforces. Known blind spots: a gate reached through code outside .github/ and
scripts/, `uses:` of a remote or reusable workflow, and a swallowing wrapper
the text heuristics do not recognise.

A step is a GATE STEP if its run text mentions `check-elf-floor`, or it runs a
wrapper script under scripts/ or .github/actions/ that does, or it `uses:` a
local composite action whose file does. A gate step is ENFORCING if (after
joining continuation lines, dropping comment lines and removing shell quotes)
any logical line contains `--enforce`; or a line mentioning the gate has no
`--report-only` and contains `$` or a backtick (mode chosen through a variable,
an env var or a command substitution: undecidable); or the step's env/with
values mention `enforce`; or it calls a wrapper / composite action (undecidable).
An enforcing step is flagged when its step or its job has any
`continue-on-error` value other than a literal false, or its run text contains
`|| true`, `|| :`, `|| exit 0` or `set +e`, or a gate line is piped (`| tee`)
in a step that has neither `set -o pipefail` nor `shell: bash` (GitHub's default
`bash -e` has no pipefail, so the pipeline's status is tee's and the gate's exit
1 is swallowed).

NOT CAUGHT (known blind spots; this is a guard, not a proof):
  * `uses: ./.github/workflows/x.yml` (a reusable workflow) from a job that has
    `continue-on-error`: the caller's job-level setting is not followed into the
    called workflow;
  * the command held in an env var and run through `bash -c "$CMD"` or `eval`;
  * a wrapper script outside scripts/ and .github/actions/, or code the repo
    does not contain (a downloaded script, a remote action);
  * shell-level swallows other than the ones listed: `|| echo ...`, `; true`,
    `trap ... EXIT`, `if ...; then`, a subshell that discards the status;
  * YAML so deeply nested that PyYAML hits the recursion limit: reported as a
    distinct error (exit 4), not analysed.

Usage: elf_floor_workflow_tripwire.py ROOT   (ROOT = repository root)
Exit: 0 clean, 1 offenders found, 2 usage, 3 PyYAML missing, 4 a file could not
be analysed (unparseable or too deeply nested): the guard did NOT run on it.
"""
import glob
import os
import re
import sys

try:
    import yaml
except ImportError:
    sys.stderr.write('elf_floor_workflow_tripwire: PyYAML is not installed\n')
    sys.exit(3)

GATE = 'check-elf-floor'
PIPE = re.compile(r'(?<!\|)\|(?!\|)')
PIPEFAIL = re.compile(r'\bpipefail\b')
SWALLOW = re.compile(r'\|\|\s*(true\b|:|exit\s+0)|\bset\s+\+e\b')


class Unanalysable(Exception):
    pass


def falsey(v):
    return v is None or v is False or (isinstance(v, str) and v.strip().lower() == 'false')


def logical_lines(run_text):
    out, buf = [], ''
    for raw in run_text.splitlines():
        if raw.lstrip().startswith('#'):
            continue
        raw = raw.rstrip()
        if raw.endswith('\\'):
            buf += raw[:-1] + ' '
            continue
        out.append(re.sub(r'["\'\\]', '', buf + raw))
        buf = ''
    if buf:
        out.append(re.sub(r'["\'\\]', '', buf))
    return out


def wrappers(root):
    names = set()
    for pat in ('scripts/**/*', '.github/actions/**/*'):
        for path in glob.glob(os.path.join(root, pat), recursive=True):
            if not os.path.isfile(path) or os.path.basename(path).startswith('check-elf-floor'):
                continue
            try:
                with open(path, encoding='utf-8') as fh:
                    if GATE in fh.read():
                        names.add(os.path.basename(path))
            except (OSError, UnicodeDecodeError):
                continue
    return names


def step_blob(step, key):
    vals = step.get(key)
    if isinstance(vals, dict):
        return ' '.join(str(v) for v in vals.values())
    return ''


def action_text(root, uses):
    if not isinstance(uses, str) or not uses.startswith('./'):
        return ''
    d = os.path.join(root, uses[2:])
    for name in ('action.yml', 'action.yaml'):
        try:
            with open(os.path.join(d, name), encoding='utf-8') as fh:
                return fh.read()
        except OSError:
            continue
    return ''


def classify(step, root, wrap):
    """-> (is_gate_step, enforcing)"""
    run = step.get('run') if isinstance(step.get('run'), str) else ''
    lines = logical_lines(run)
    joined = '\n'.join(lines)
    uses_text = action_text(root, step.get('uses'))
    via_wrapper = any(w in joined for w in wrap)
    via_action = GATE in uses_text
    gate = GATE in joined or via_wrapper or via_action
    if not gate:
        return False, False
    if '--enforce' in joined:
        return True, True
    if 'enforce' in (step_blob(step, 'env') + ' ' + step_blob(step, 'with')).lower():
        return True, True
    if via_wrapper or via_action:
        return True, True                       # cannot see inside: assume it enforces
    for ln in lines:
        if GATE in ln and '--report-only' not in ln and ('$' in ln or '`' in ln):
            return True, True
    return True, False


def steps_of(doc):
    out = []
    if not isinstance(doc, dict):
        return out
    jobs = doc.get('jobs')
    if isinstance(jobs, dict):
        for jname, job in jobs.items():
            if isinstance(job, dict):
                for st in job.get('steps') or []:
                    if isinstance(st, dict):
                        out.append((jname, job, st))
    runs = doc.get('runs')
    if isinstance(runs, dict):
        for st in runs.get('steps') or []:
            if isinstance(st, dict):
                out.append(('<composite action>', {}, st))
    return out


def offenders(path, root):
    try:
        with open(path, encoding='utf-8') as fh:
            doc = yaml.safe_load(fh)
    except RecursionError:
        raise Unanalysable('%s: YAML nested too deeply for PyYAML (RecursionError); '
                           'the tripwire did NOT analyse this file' % path)
    except (OSError, yaml.YAMLError) as exc:
        raise Unanalysable('%s: unparseable (%s)'
                           % (path, str(exc).splitlines()[0] if str(exc) else exc))
    wrap = wrappers(root)
    bad = []
    for jname, job, st in steps_of(doc):
        gate, enforcing = classify(st, root, wrap)
        if not (gate and enforcing):
            continue
        why = []
        if not falsey(st.get('continue-on-error')):
            why.append('step continue-on-error=%r' % (st.get('continue-on-error'),))
        if not falsey(job.get('continue-on-error')):
            why.append('job continue-on-error=%r' % (job.get('continue-on-error'),))
        run = st.get('run') if isinstance(st.get('run'), str) else ''
        lines = logical_lines(run)
        if SWALLOW.search('\n'.join(lines)):
            why.append('run text swallows the exit status (|| true / set +e)')
        if (any(GATE in ln and PIPE.search(ln) for ln in lines)
                and not PIPEFAIL.search('\n'.join(lines))
                and str(st.get('shell', '')).strip() != 'bash'):
            why.append('gate output is piped without pipefail (default `bash -e`: '
                       "the pipeline's status is the last command's)")
        if why:
            bad.append('%s: job %s, step %r: %s'
                       % (path, jname, st.get('name') or st.get('uses') or '?', '; '.join(why)))
    return bad


def main(argv):
    if len(argv) != 2 or not os.path.isdir(argv[1]):
        sys.stderr.write(__doc__.split('Usage:')[1].split('\n')[0].strip() + '\n')
        return 2
    root = argv[1]
    files = sorted(glob.glob(os.path.join(root, '.github/workflows/*.y*ml'))
                   + glob.glob(os.path.join(root, '.github/actions/**/action.y*ml'), recursive=True))
    n = unanalysed = 0
    for f in files:
        try:
            found = offenders(f, root)
        except Unanalysable as exc:
            print('TRIPWIRE ERROR: %s' % exc)
            unanalysed += 1
            continue
        for line in found:
            print(line)
            n += 1
    if unanalysed:
        return 4
    return 1 if n else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
