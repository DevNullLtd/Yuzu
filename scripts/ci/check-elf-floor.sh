#!/usr/bin/env bash
# check-elf-floor.sh -- the Linux native-build floor gate (ADR-2003, slice S0).
#
# Walks a staging directory, runs `objdump -T` and `readelf -d` over every ELF
# in it (binaries, plugins, ERTS, crypto.so ...) and compares what each one
# IMPORTS against a committed floor file: the oldest glibc / libstdc++ /
# libgcc / systemd / OpenSSL ... the artefact promises to run on. It gates the
# PROMISE (the floor file), never a measured value.
#
# S0 IS REPORT-ONLY. The default mode prints violations, emits GitHub Actions
# `::warning::` annotations plus a job-summary table, and exits 0. `--enforce`
# is implemented and tested but is NOT wired anywhere yet (S2 turns it on).
#
# USAGE
#   check-elf-floor.sh --floor FILE --dir STAGING [options]
#     --floor FILE          floor file (see FLOOR FILE); required
#     --dir DIR             staging directory to scan (recursively); required
#     --report-only         print + annotate violations, exit 0 (the default)
#     --enforce             exit 1 on any violation; an empty scan is an error
#     --include GLOB        only scan ELFs whose path RELATIVE to --dir matches
#                           GLOB (fnmatch; '*' crosses '/'); repeatable
#     --exclude GLOB        skip ELFs whose relative path matches; repeatable
#                           (applied after --include)
#     --set-name NAME       name of this scan in a baseline (default: the floor
#                           file's "name")
#     --source LABEL        free-text provenance recorded in the baseline
#                           (e.g. "v0.14.1 linux-x64"); never a path or a time
#     --emit-baseline FILE  write/merge the machine-readable baseline (below)
#     --full-report FILE    write the full per-ELF, per-tag symbol report (JSON;
#                           large -- a CI artefact, never committed)
#   Tools are looked up on PATH; override with OBJDUMP=... READELF=... .
#   Needs python3 (3.8+) for parsing and JSON; there is no other dependency.
#
# EXIT STATUS
#   0  report-only mode (whatever was found), or enforce mode and clean
#   1  enforce mode and at least one violation / unreadable ELF / empty scan
#   2  usage or configuration error, missing tool, unreadable floor file:
#      always, in either mode -- a broken invocation must never look clean
#
# WHAT COUNTS
#   * An import is an UNDEFINED dynamic symbol carrying a version tag
#     (`GLIBC_2.38`, `GLIBCXX_3.4.34`, `CXXABI_1.3.15`, `LIBSYSTEMD_240`,
#     `BLKID_1.0`, `OPENSSL_3.0.0`, `GCC_4.3.0` ...). The tag is split into
#     FAMILY (`GLIBC`) and a dotted numeric VERSION (`2.38`), compared as an
#     integer tuple (so 2.9 < 2.28). The same tag required from several
#     libraries (libc and libm both give GLIBC_2.x) is one tag: the gate
#     compares tags, not provenance. Tags with no numeric suffix
#     (`GLIBC_PRIVATE`) are their own family and are reported verbatim.
#   * Defined symbols and unversioned imports (`Base`) never count toward the
#     version comparison; unversioned imports still feed forbidden_symbols.
#   * Non-ELF files are skipped (counted, never an error). Symlinks are not
#     followed. A static or no-dynamic-section ELF is scanned, has no imports,
#     and is marked "static". A stripped ELF is fine (the dynamic table
#     survives stripping). An ELF the tools cannot read is a violation of kind
#     `unreadable` -- an artefact that cannot be checked is not a clean one.
#   * ZERO ELFs under --dir (after --include/--exclude) is a problem: an
#     error in --enforce, a warning in report-only. An empty scan must never
#     read as "clean".
#   * RUNPATH / RPATH: every colon-separated entry must be anchored at
#     $ORIGIN (or ${ORIGIN}). An absolute path, a bare relative path or an
#     empty entry (= the current directory) is a violation of kind `runpath`.
#
# FLOOR FILE (JSON; deploy/packaging/linux-floor-{agent,server}.json)
#   {
#     "schema": 1,
#     "name": "agent",                  # default --set-name
#     "description": "free text",
#     "max": { "GLIBC": "2.28", ... },  # family -> highest version allowed
#     "allow": [ "LIBSYSTEMD_240" ],    # exact tags exempt from "max" (a
#                                       # measured vendor backport, say)
#     "forbidden_symbols": [ "EVP_sm4_*" ],   # fnmatch over undefined names
#     "unlisted_families": "report"     # or "fail": a versioned family absent
#                                       # from "max" is only listed, or is a
#                                       # violation. Default "report".
#   }
#
# BASELINE FILE (--emit-baseline; deploy/packaging/linux-floor-baseline.json)
#   Deterministic (sorted, no timestamps, no paths) so a refresh diffs cleanly.
#   One file holds several scans ("sets"); emitting to an existing file
#   replaces only the set being emitted and keeps the others.
#   {
#     "schema": 1,
#     "sets": {
#       "<set-name>": {
#         "floor": "linux-floor-agent.json",
#         "source": "<--source label>",            # omitted if not given
#         "elf_count": 68,
#         "maxima": { "GLIBC": "2.38", ... },      # highest tag per family,
#                                                  # across the whole set
#         "artifacts": {
#           "<path relative to --dir>": {
#             "maxima": { ... },                   # this ELF's own highest
#             "offending": { "GLIBC_2.38": ["strlcpy", ...] },  # above floor
#             "forbidden": ["EVP_sm4_cbc"],        # forbidden names imported
#             "runpath": ["/opt/x"],               # non-$ORIGIN entries
#             "status": "static" | "error: ..."    # omitted when ordinary
#           }
#         }
#       }
#     }
#   }
#   Regenerate: see docs/ci-architecture.md "Linux ELF floor gate (ADR-2003)".
#
# Contract tests: tests/shell/test_check_elf_floor.sh.
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "check-elf-floor: python3 is required but not on PATH" >&2
  exit 2
fi

exec python3 -I - "$@" <<'PYEOF'
import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys

TAG_RE = re.compile(r'^(?P<fam>.+)_(?P<ver>[0-9]+(?:\.[0-9]+)*)$')
ELF_MAGIC = b'\x7fELF'
TOOL_TIMEOUT = 300
SUMMARY_ROWS = 20
ANNOTATION_CAP = 50
SYMS_SHOWN = 6


def die(msg):
    sys.stderr.write('check-elf-floor: %s\n' % msg)
    sys.exit(2)


def safe(text):
    """Printable-ASCII rendering of attacker-influenced text (file names,
    symbol names, RUNPATH entries): a newline in a file name must not be able
    to start a fake `::error::` workflow command on its own log line."""
    return re.sub(r'[^\x20-\x7e]', lambda m: '\\x%02x' % ord(m.group(0)), text)


def vtuple(ver):
    return tuple(int(p) for p in ver.split('.'))


def split_tag(tag):
    m = TAG_RE.match(tag)
    if not m:
        return tag, None
    return m.group('fam'), m.group('ver')


# --------------------------------------------------------------- floor file
def load_floor(path):
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            floor = json.load(fh)
    except (OSError, ValueError) as exc:
        die('cannot read floor file %s: %s' % (path, exc))
    if not isinstance(floor, dict) or floor.get('schema') != 1:
        die('floor file %s: "schema" must be 1' % path)
    name = floor.get('name')
    if not isinstance(name, str) or not name:
        die('floor file %s: "name" must be a non-empty string' % path)
    mx = floor.get('max')
    if not isinstance(mx, dict) or not mx:
        die('floor file %s: "max" must be a non-empty object' % path)
    for fam, ver in mx.items():
        if not isinstance(ver, str) or not re.match(r'^[0-9]+(\.[0-9]+)*$', ver):
            die('floor file %s: max[%s] must be a dotted numeric version' % (path, fam))
    allow = floor.get('allow', [])
    forb = floor.get('forbidden_symbols', [])
    for key, val in (('allow', allow), ('forbidden_symbols', forb)):
        if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
            die('floor file %s: "%s" must be a list of strings' % (path, key))
    unl = floor.get('unlisted_families', 'report')
    if unl not in ('report', 'fail'):
        die('floor file %s: "unlisted_families" must be "report" or "fail"' % path)
    return {'name': name, 'max': mx, 'allow': set(allow),
            'forbidden': list(forb), 'unlisted': unl}


# --------------------------------------------------------------- discovery
def discover(root, includes, excludes):
    found, non_elf = [], 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            rel = os.path.relpath(full, root).replace(os.sep, '/')
            try:
                with open(full, 'rb') as fh:
                    magic = fh.read(4)
            except OSError:
                # Cannot even read the header: surface it, do not skip it.
                magic = ELF_MAGIC
            if magic != ELF_MAGIC:
                non_elf += 1
                continue
            if includes and not any(fnmatch.fnmatchcase(rel, g) for g in includes):
                continue
            if any(fnmatch.fnmatchcase(rel, g) for g in excludes):
                continue
            found.append((rel, full))
    found.sort()
    return found, non_elf


# ---------------------------------------------------------------- tool runs
def run(cmd):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=TOOL_TIMEOUT, env=dict(os.environ, LC_ALL='C'))
    except subprocess.TimeoutExpired:
        return None, '', 'timed out after %ds' % TOOL_TIMEOUT
    except OSError as exc:
        return None, '', str(exc)
    return (p.returncode, p.stdout.decode('utf-8', 'replace'),
            p.stderr.decode('utf-8', 'replace'))


def first_line(text):
    for ln in text.splitlines():
        if ln.strip():
            return ln.strip()[:200]
    return ''


def parse_imports(text):
    """-> {tag: set(symbols)}, set(all undefined names)"""
    tags, names = {}, set()
    for ln in text.splitlines():
        toks = ln.split()
        if '*UND*' not in toks:
            continue
        i = toks.index('*UND*')
        # Columns after the section: size, version, name. A symbol with no
        # version prints either `Base` or an empty column (then the name is
        # the second token), so count from the END for the name.
        rest = toks[i + 1:]
        if len(rest) < 2:
            continue          # nameless undefined entry
        name = rest[-1]
        ver = rest[1].strip('()') if len(rest) >= 3 else ''
        names.add(name)
        if ver and ver != 'Base':
            tags.setdefault(ver, set()).add(name)
    return tags, names


def parse_runpath(text):
    out = []
    for ln in text.splitlines():
        if '(RUNPATH)' in ln or '(RPATH)' in ln:
            m = re.search(r'\[(.*)\]', ln)
            if m:
                out.extend(m.group(1).split(':'))
    return out


def scan_elf(rel, full, objdump, readelf):
    rec = {'tags': {}, 'names': set(), 'runpath': [], 'status': None}
    rc, out, err = run([readelf, '-d', '--wide', full])
    if rc is None or rc != 0 or 'Error:' in err:
        rec['status'] = 'error: readelf -d: ' + (first_line(err) or 'failed')
        return rec
    rec['runpath'] = parse_runpath(out)
    rc, out, err = run([objdump, '-T', full])
    if rc is None or rc != 0:
        # A well-formed ELF with no dynamic symbol table (static executable,
        # relocatable object). A truncated or corrupt one is NOT this: objdump
        # then says "file format not recognized", which stays an error, so a
        # damaged file can never pass as a static one.
        if rc is not None and 'not a dynamic object' in err:
            rec['status'] = 'static'
            return rec
        rec['status'] = 'error: objdump -T: ' + (first_line(err) or 'failed')
        return rec
    rec['tags'], rec['names'] = parse_imports(out)
    return rec


# --------------------------------------------------------------- evaluation
def evaluate(floor, rec):
    """-> (maxima {fam: verstr}, violations [dict])"""
    maxima, viol = {}, []
    for tag in sorted(rec['tags']):
        fam, ver = split_tag(tag)
        if ver is not None:
            if fam not in maxima or vtuple(ver) > vtuple(maxima[fam]):
                maxima[fam] = ver
        syms = sorted(rec['tags'][tag])
        if fam in floor['max'] and ver is not None:
            if vtuple(ver) > vtuple(floor['max'][fam]) and tag not in floor['allow']:
                viol.append({'kind': 'above-floor', 'tag': tag, 'fam': fam,
                             'floor': floor['max'][fam], 'symbols': syms})
        elif tag not in floor['allow']:
            rec.setdefault('unlisted', {})[tag] = syms
            if floor['unlisted'] == 'fail':
                viol.append({'kind': 'unlisted-family', 'tag': tag, 'fam': fam,
                             'floor': None, 'symbols': syms})
    hits = sorted(n for n in rec['names']
                  if any(fnmatch.fnmatchcase(n, p) for p in floor['forbidden']))
    if hits:
        viol.append({'kind': 'forbidden-symbol', 'symbols': hits})
    bad = [e for e in rec['runpath']
           if not (e in ('$ORIGIN', '${ORIGIN}') or e.startswith('$ORIGIN/')
                   or e.startswith('${ORIGIN}/'))]
    if bad:
        viol.append({'kind': 'runpath', 'entries': bad})
    st = rec['status']
    if st and st.startswith('error'):
        viol.append({'kind': 'unreadable', 'detail': st})
    return maxima, viol


def describe(v, brief=False):
    k = v['kind']
    if brief and k in ('above-floor', 'unlisted-family', 'forbidden-symbol'):
        # Annotations stay short; the log and the full report carry the names.
        if k == 'above-floor':
            head = 'above-floor %s (floor %s_%s)' % (safe(v['tag']), safe(v['fam']), v['floor'])
        elif k == 'unlisted-family':
            head = 'unlisted-family ' + safe(v['tag'])
        else:
            head = 'forbidden-symbol'
        return '%s: %d symbol(s)' % (head, len(v['symbols']))
    if k in ('above-floor', 'unlisted-family', 'forbidden-symbol'):
        syms = [safe(x) for x in v['symbols']]
        shown = ', '.join(syms[:SYMS_SHOWN]) + (
            ', ... (+%d more)' % (len(syms) - SYMS_SHOWN) if len(syms) > SYMS_SHOWN else '')
        if k == 'above-floor':
            return 'above-floor %s (floor %s_%s): %s' % (
                safe(v['tag']), safe(v['fam']), v['floor'], shown)
        if k == 'unlisted-family':
            return 'unlisted-family %s: %s' % (safe(v['tag']), shown)
        return 'forbidden-symbol: ' + shown
    if k == 'runpath':
        ents = [safe(e) for e in v['entries']]
        return 'runpath not $ORIGIN-anchored: ' + ', '.join(repr(e) for e in ents[:3]) + (
            ', ... (+%d more)' % (len(ents) - 3) if len(ents) > 3 else '')
    return 'unreadable: ' + safe(v['detail'])


# ------------------------------------------------------------------- output
def gh_escape(s):
    return s.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')


def gh_prop(s):
    return gh_escape(s).replace(':', '%3A').replace(',', '%2C')


def compact(o):
    return json.dumps(o, sort_keys=True, separators=(', ', ': '))


def dump(o, level=0):
    pad = '  ' * level
    if isinstance(o, dict) and o:
        flat = not any(isinstance(v, dict) for v in o.values())
        if flat or level >= 4:
            return compact(o)
        items = ['%s  %s: %s' % (pad, json.dumps(k), dump(o[k], level + 1))
                 for k in sorted(o)]
        return '{\n' + ',\n'.join(items) + '\n' + pad + '}'
    return compact(o)


def write_atomic(path, text):
    d = os.path.dirname(os.path.abspath(path))
    tmp = os.path.join(d, '.%s.tmp.%d' % (os.path.basename(path), os.getpid()))
    try:
        with open(tmp, 'w', encoding='utf-8') as fh:
            fh.write(text)
        os.replace(tmp, path)
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        die('cannot write %s: %s' % (path, exc))


def main():
    ap = argparse.ArgumentParser(prog='check-elf-floor.sh', add_help=True)
    ap.add_argument('--floor', required=True)
    ap.add_argument('--dir', required=True, dest='root')
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument('--report-only', action='store_true')
    mode.add_argument('--enforce', action='store_true')
    ap.add_argument('--include', action='append', default=[])
    ap.add_argument('--exclude', action='append', default=[])
    ap.add_argument('--set-name')
    ap.add_argument('--source')
    ap.add_argument('--emit-baseline')
    ap.add_argument('--full-report')
    args = ap.parse_args()

    enforce = args.enforce
    floor = load_floor(args.floor)
    set_name = args.set_name or floor['name']
    if not os.path.isdir(args.root):
        die('--dir %s is not a directory' % args.root)
    objdump = os.environ.get('OBJDUMP', 'objdump')
    readelf = os.environ.get('READELF', 'readelf')
    for tool in (objdump, readelf):
        if shutil.which(tool) is None:
            die('%s not found on PATH (binutils is required)' % tool)

    elfs, non_elf = discover(args.root, args.include, args.exclude)

    arts, full = {}, {}
    overall, over_count = {}, {}
    all_viol = []                       # (rel, violation)
    static_n = 0
    for rel, path in elfs:
        rec = scan_elf(rel, path, objdump, readelf)
        maxima, viol = evaluate(floor, rec)
        for fam, ver in maxima.items():
            if fam not in overall or vtuple(ver) > vtuple(overall[fam]):
                overall[fam] = ver
        for fam in {v['fam'] for v in viol if v['kind'] == 'above-floor'}:
            over_count[fam] = over_count.get(fam, 0) + 1
        if rec['status'] == 'static':
            static_n += 1
        entry = {'maxima': maxima}
        off = {v['tag']: v['symbols'] for v in viol if v['kind'] == 'above-floor'}
        if off:
            entry['offending'] = off
        if rec.get('unlisted'):
            entry['unlisted'] = rec['unlisted']
        for v in viol:
            if v['kind'] == 'forbidden-symbol':
                entry['forbidden'] = v['symbols']
            elif v['kind'] == 'runpath':
                entry['runpath'] = v['entries']
        if rec['status']:
            entry['status'] = rec['status']
        arts[rel] = entry
        full[rel] = dict(entry, imports={t: sorted(s) for t, s in sorted(rec['tags'].items())},
                         runpath_all=rec['runpath'])
        for v in viol:
            all_viol.append((rel, v))

    problems = []
    if not elfs:
        problems.append('no ELF files found under the scanned directory '
                        '(an empty scan is not a clean scan)')

    # ---------------------------------------------------------------- stdout
    out = []
    out.append('check-elf-floor: floor=%s (%s) set=%s mode=%s'
               % (os.path.basename(args.floor), floor['name'], set_name,
                  'enforce' if enforce else 'report-only'))
    out.append('ELF files scanned: %d (static/no dynamic section: %d); non-ELF skipped: %d'
               % (len(elfs), static_n, non_elf))
    fams = sorted(set(overall) | set(floor['max']))
    if elfs:
        out.append('')
        out.append('%-14s %-10s %-10s %s' % ('family', 'floor', 'measured', 'ELFs over floor'))
        for fam in fams:
            out.append('%-14s %-10s %-10s %d' % (
                safe(fam), floor['max'].get(fam, '(unlisted)'), overall.get(fam, '-'),
                over_count.get(fam, 0)))
    if all_viol:
        out.append('')
        out.append('Violations (%d across %d ELF(s)):'
                   % (len(all_viol), len({r for r, _ in all_viol})))
        for rel, v in sorted(all_viol, key=lambda rv: (rv[0], describe(rv[1]))):
            out.append('  %s: %s' % (safe(rel), describe(v)))
    for p in problems:
        out.append('PROBLEM: ' + p)
    failing = bool(all_viol or problems)
    if enforce:
        out.append('RESULT: %s' % ('FAIL' if failing else 'OK'))
    else:
        out.append('RESULT: report-only, %d violation(s), %d problem(s); exit 0'
                   % (len(all_viol), len(problems)))
    sys.stdout.write('\n'.join(out) + '\n')

    # ------------------------------------------------- GitHub Actions output
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        level = 'error' if enforce else 'warning'
        title = gh_prop('Linux ELF floor (%s)' % set_name)
        by_art = {}
        for rel, v in all_viol:
            by_art.setdefault(rel, []).append(describe(v, brief=True))
        n = 0
        for rel in sorted(by_art):
            if n >= ANNOTATION_CAP:
                print('::%s title=%s::%s' % (level, title, gh_escape(
                    '%d more ELF(s) with violations not annotated; see the log and the report artifact'
                    % (len(by_art) - n))))
                break
            print('::%s title=%s::%s' % (level, title, gh_escape(
                '%s: %s' % (safe(rel), '; '.join(by_art[rel])))))
            n += 1
        for p in problems:
            print('::%s title=%s::%s' % (level, title, gh_escape(p)))
    summ = os.environ.get('GITHUB_STEP_SUMMARY')
    if summ:
        md = ['### Linux ELF floor: %s (%s)' % (set_name, 'enforce' if enforce else 'report-only'),
              '', '%d ELF(s) scanned, %d violation(s) in %d ELF(s). Floor file `%s`.'
              % (len(elfs), len(all_viol), len({r for r, _ in all_viol}),
                 os.path.basename(args.floor)), '']
        for p in problems:
            md += ['**Problem:** ' + p, '']
        if elfs:
            md += ['| Family | Floor | Measured max | ELFs over floor |', '|---|---|---|---|']
            for fam in fams:
                md.append('| %s | %s | %s | %d |' % (
                    safe(fam), floor['max'].get(fam, '(unlisted)'), overall.get(fam, '-'),
                    over_count.get(fam, 0)))
            md.append('')
        if all_viol:
            counts = {}
            for rel, _ in all_viol:
                counts[rel] = counts.get(rel, 0) + 1
            worst = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:SUMMARY_ROWS]
            md += ['| ELF (top %d by violations) | Violations |' % SUMMARY_ROWS, '|---|---|']
            md += ['| `%s` | %d |' % (safe(rel), c) for rel, c in worst]
            md.append('')
        try:
            with open(summ, 'a', encoding='utf-8') as fh:
                fh.write('\n'.join(md) + '\n')
        except OSError:
            pass                       # the summary is best-effort, never a failure

    # -------------------------------------------------------------- baseline
    if args.emit_baseline:
        data = {'schema': 1, 'sets': {}}
        if os.path.exists(args.emit_baseline):
            try:
                with open(args.emit_baseline, 'r', encoding='utf-8') as fh:
                    data = json.load(fh)
            except (OSError, ValueError) as exc:
                die('existing baseline %s is unreadable: %s' % (args.emit_baseline, exc))
            if (not isinstance(data, dict) or data.get('schema') != 1
                    or not isinstance(data.get('sets'), dict)):
                die('existing baseline %s is not a schema-1 baseline' % args.emit_baseline)
        entry = {'floor': os.path.basename(args.floor), 'elf_count': len(elfs),
                 'maxima': overall, 'artifacts': arts}
        if args.source:
            entry['source'] = args.source
        data['sets'][set_name] = entry
        write_atomic(args.emit_baseline, dump(data) + '\n')
    if args.full_report:
        write_atomic(args.full_report, json.dumps(
            {'schema': 1, 'set': set_name, 'floor': os.path.basename(args.floor),
             'elf_count': len(elfs), 'maxima': overall, 'artifacts': full},
            sort_keys=True, indent=1) + '\n')

    sys.exit(1 if (enforce and failing) else 0)


main()
PYEOF
