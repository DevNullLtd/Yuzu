#!/usr/bin/env bash
# check-elf-floor.sh -- the Linux native-build floor gate (ADR-2003 (Accepted, PR #5631), slice S0).
#
# Walks a staging directory, runs `objdump -T` and `readelf -d` over every ELF
# in it (binaries, plugins, ERTS, crypto.so ...) and compares what each one
# IMPORTS against a committed floor file: the oldest glibc / libstdc++ /
# libgcc / systemd / OpenSSL ... the artefact promises to run on. It gates the
# PROMISE (the floor file), never a measured value.
#
# S0 IS REPORT-ONLY. The default mode prints violations, emits GitHub Actions
# `::warning::` annotations plus a job-summary table, and exits 0 (except for a
# usage/configuration error, exit 2). `--enforce` is implemented and tested but
# is NOT wired anywhere yet (S2 turns it on).
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
#   Time bound: each tool call is limited to 300s and the whole scan to
#   YUZU_ELF_FLOOR_DEADLINE seconds (default 240; a test hook; set-but-empty
#   counts as unset). ELFs not reached
#   by then are reported as `unreadable` ("not scanned") plus one PROBLEM line,
#   never skipped silently. A normal scan of ~70 ELFs takes well under a second.
#
# EXIT STATUS
#   0  report-only mode (whatever was found), or enforce mode and clean
#   1  enforce mode and at least one violation / unreadable ELF or directory /
#      empty scan
#   2  usage or configuration error, missing tool, unreadable floor file, or an
#      unexpected internal error: always, in either mode -- a broken invocation
#      must never look clean
#   In report-only mode an empty scan, an unreadable ELF or an unreadable
#   directory is only a warning (PROBLEM / violation line, exit 0); under
#   --enforce each one is an error.
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
#   * A parse that could silently read as clean is an error instead. An ELF is
#     `unreadable` when (a) readelf/objdump wrote an error/warning/"not
#     recognized"-style message on stderr, even with exit 0 (a damaged ELF must
#     not read as a clean partial parse), or (b) readelf shows NEEDED libraries
#     yet no undefined symbol row could be parsed from `objdump -T` (a changed
#     objdump output format would otherwise make every ELF "import nothing").
#     (b) is deliberately narrow: a dynamic object with no NEEDED entry, or a
#     static one, legitimately imports nothing and is not flagged.
#     Residuals of rule (b) and of the libc rule below: `gcc -shared -nostdlib
#     -Wl,--no-as-needed -lc` with no imports at all is flagged (a NEEDED
#     library with nothing parsed); an ELF NEEDing libc.so.* must yield at least
#     one GLIBC_* tag or it is `unreadable`. Likewise an ELF that NEEDs
#     libstdc++.so.* and imports at least one std:: symbol (`_ZSt`, `_ZNSt`,
#     `_ZNKSt` prefixes) must carry a GLIBCXX_* tag. (libm and a bare
#     libstdc++ NEEDED are NOT checked: linked-but-unused is common, and a
#     broad CXXABI/__cxa_* rule false-positives because __cxa_atexit is GLIBC.) Detached debug files (`*.debug`, the
#     `-dbg` payload) make objdump say "invalid operation" and are flagged: do
#     not scan a debug-symbol payload. A symbol name shaped like `GLIBC_2.38`
#     (or another known version family) is taken as a moved column.
#   * Defined symbols and unversioned imports (`Base`) never count toward the
#     version comparison; unversioned imports still feed forbidden_symbols.
#   * Non-ELF files are skipped (counted, never an error). Symlinks are not
#     followed. A static or no-dynamic-section ELF is scanned, has no imports,
#     and is marked "static". A stripped ELF is fine (the dynamic table
#     survives stripping). An ELF the tools cannot read -- or a file with the
#     ELF magic but fewer than 64 bytes (no room for an ELF header) -- is a
#     violation of kind `unreadable`: an artefact that cannot be checked is not
#     a clean one. Likewise a DIRECTORY that cannot be listed, or a file that
#     cannot be examined (stat fails with anything but "vanished"), is a
#     PROBLEM.
#   * ZERO ELFs under --dir (after --include/--exclude) is a problem: an
#     error in --enforce, a warning in report-only. An empty scan must never
#     read as "clean".
#   * The floor file must list GLIBC in "max" (exit 2 otherwise): a typo in a
#     family name would silently ungate it, because other families absent from
#     "max" are only reported. A measured family that is exactly ONE edit away
#     from a listed key (GLIBCCXX vs GLIBCXX) is a PROBLEM line. A "listed
#     family never measured" warning was considered and NOT added: the server
#     set legitimately lacks several families (LIBSYSTEMD, BLKID, OPENSSL), so it
#     would cry wolf. The test suite pins the exact key set of each shipped floor.
#   * Known limits: tool stderr is read up to 1 MiB (a longer one is itself an
#     error); stdout/stderr closed by the caller are discarded, not an error;
#     a stdout that is open but failing (/dev/full) exits 2.
#   * Output hygiene: file names, symbol names, families and RUNPATH entries
#     come from the artefact under test. Every line printed is rendered as
#     printable ASCII, and any line that would begin (after whitespace) with
#     `::` -- which the Actions runner would execute as a workflow command --
#     is prefixed with `| `. Only the script's own annotations start with `::`.
#     The legacy `##[error]`/`##[add-mask]` syntax (recognised anywhere in a
#     line) is broken by rewriting `##[` to `#\x23[`. argparse usage errors and
#     the internal-error handler go through the same rendering.
#   * Annotation order: PROBLEM annotations first (GitHub shows only about ten
#     per step), then per-ELF violations.
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
#             "unlisted": { "GCC_4.3.0": [...] },  # tags of families absent
#                                                  # from the floor's "max"
#             "status": "static" | "error: ..."    # omitted when ordinary
#           }
#         },
#         "incomplete": ["directory x cannot be read (...)", ...]
#                                                  # ONLY present when the scan
#                                                  # had PROBLEMs or unreadable /
#                                                  # unscanned ELFs: the numbers
#                                                  # above are then a lower bound
#       }
#     }
#   }
#   Regenerate: see docs/ci-architecture.md, "Linux ELF floor gate
#   (`scripts/ci/check-elf-floor.sh`, ADR-2003 S0)".
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
import stat
import subprocess
import sys
import tempfile
import time

# Digit runs are capped (9) so a hostile 5000-digit tag cannot reach int()
# (Python refuses 4300+ digits); such a tag is simply a family with no version.
TAG_RE = re.compile(r'^(?P<fam>.+)_(?P<ver>[0-9]{1,9}(?:\.[0-9]{1,9})*)$')
VER_RE = re.compile(r'^[0-9]{1,9}(?:\.[0-9]{1,9})*$')
ELF_MAGIC = b'\x7fELF'
TOOL_TIMEOUT = 300
BAD_STDERR = re.compile(r"(?i)\b(error|warning|can't|cannot|not recognized|truncated|"
                        r"corrupt|unable|invalid|bad )")
DEFAULT_DEADLINE = 240
MIN_ELF_BYTES = 64
MAX_STDERR = 1 << 20
STD_SYMBOL = re.compile(r'^_Z(NK?)?St')
# Families whose tags are expected to look like `NAME_1.2.3`; a symbol NAME shaped
# like one means the objdump column layout moved (see scan_elf).
KNOWN_VERSION_FAMILIES = ('GLIBC', 'GLIBCXX', 'CXXABI', 'GCC', 'LIBSYSTEMD',
                          'OPENSSL', 'BLKID')
SUMMARY_ROWS = 20
ANNOTATION_CAP = 50
SYMS_SHOWN = 6


def die(msg):
    try:
        sys.stderr.write(neutralize('check-elf-floor: %s' % safe(msg)) + '\n')
    except Exception:
        pass                                  # stderr closed/full
    sys.exit(2)


def safe(text):
    """Printable-ASCII rendering of attacker-influenced text (file names,
    symbol names, RUNPATH entries): a newline in a file name must not be able
    to start a fake `::error::` workflow command on its own log line."""
    text = re.sub(r'[^\x20-\x7e]', lambda m: '\\x%02x' % ord(m.group(0)), text)
    # The legacy `##[error]` / `##[add-mask]` syntax matches anywhere in a line.
    return text.replace('##[', '#\\x23[')


def neutralize(line):
    """Defuse a log line: the Actions runner trims leading whitespace and runs
    a line starting with `::` as a workflow command, so such a line gets a
    visible marker in front. Applied to EVERY line this script prints that is
    not one of its own annotations."""
    return '\n'.join('| ' + ln if ln.lstrip().startswith('::') else ln
                     for ln in line.split('\n'))


def mdsafe(text):
    """safe() plus what would break out of a markdown table cell/code span."""
    return (safe(text).replace('|', '\\|').replace('`', "'")
            .replace('<', '&lt;').replace('>', '&gt;'))


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
        if not isinstance(ver, str) or not VER_RE.match(ver):
            die('floor file %s: max[%s] must be a dotted numeric version' % (path, fam))
    if 'GLIBC' not in mx:
        die('floor file %s: "max" must list GLIBC (a typo in a family name would '
            'silently ungate it)' % path)
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
    """-> (found [(rel, full)], non_elf_count, walk_errors [str])"""
    found, non_elf, errs = [], 0, []

    def onerror(exc):
        # os.walk drops an unlistable directory silently unless told not to.
        where = os.path.relpath(exc.filename, root) if exc.filename else '.'
        errs.append('directory %s cannot be read (%s)'
                    % (safe(where.replace(os.sep, '/')), safe(exc.strerror or 'error')))

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=onerror):
        dirnames.sort()
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            relname = safe(os.path.relpath(full, root).replace(os.sep, '/'))
            try:
                mode = os.lstat(full).st_mode
            except FileNotFoundError:
                continue              # vanished between listing and stat
            except OSError as exc:
                # e.g. EACCES in a listable-but-not-searchable directory:
                # isfile() would say False and the ELF would vanish silently.
                errs.append('file %s cannot be examined (%s)'
                            % (relname, safe(exc.strerror or 'error')))
                continue
            if stat.S_ISLNK(mode):
                continue
            if not stat.S_ISREG(mode):
                non_elf += 1          # FIFO, socket, device: never opened
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
    return found, non_elf, sorted(errs)


# ---------------------------------------------------------------- tool runs
def run(cmd, deadline):
    limit = max(1.0, min(float(TOOL_TIMEOUT), deadline - time.monotonic()))
    try:
        # stderr goes to a temp file and only its first MAX_STDERR bytes are read:
        # a tool that complains at length cannot balloon this process's memory.
        with tempfile.TemporaryFile() as errf:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=errf,
                               timeout=limit, env=dict(os.environ, LC_ALL='C'))
            errf.seek(0)
            err = errf.read(MAX_STDERR)
            if errf.read(1):
                # Truncated: whatever came after the cap was never examined.
                err = b'Error: tool stderr exceeded %d bytes\n' % MAX_STDERR + err
    except subprocess.TimeoutExpired:
        return None, '', 'timed out after %ds' % limit
    except OSError as exc:
        return None, '', str(exc)
    # surrogateescape: a non-UTF-8 staging path round-trips, so err.replace(full, rel)
    # still finds it and the path cannot leak into results.
    return (p.returncode, p.stdout.decode('utf-8', 'surrogateescape'),
            err.decode('utf-8', 'surrogateescape'))


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


def needed_libs(readelf_out):
    return re.findall(r'\(NEEDED\)\s+Shared library: \[([^\]]*)\]', readelf_out)


def scan_elf(rel, full, objdump, readelf, deadline, vfams):
    rec = {'tags': {}, 'names': set(), 'runpath': [], 'status': None}
    try:
        size = os.path.getsize(full)
    except OSError as exc:
        rec['status'] = 'error: stat: ' + (exc.strerror or 'failed')
        return rec
    if size < MIN_ELF_BYTES:
        rec['status'] = ('error: ELF magic but only %d byte(s), too small for an ELF header'
                         % size)
        return rec
    # `--` ends option parsing: a path can never be read as a tool option.
    rc, out, err = run([readelf, '-d', '--wide', '--', full], deadline)
    err = err.replace(full, rel)          # keep the staging path out of results
    if rc is None or rc != 0 or BAD_STDERR.search(err):
        rec['status'] = 'error: readelf -d: ' + (first_line(err) or 'failed')
        return rec
    rec['runpath'] = parse_runpath(out)
    needed = needed_libs(out)
    rc, out, err = run([objdump, '-T', '--', full], deadline)
    err = err.replace(full, rel)
    if rc == 0 and BAD_STDERR.search(err):
        rec['status'] = 'error: objdump -T: ' + first_line(err)
        return rec
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
    fmt = 'error: objdump -T: '
    shaped = re.compile(r'^\(?(?:%s)_[0-9]+(?:\.[0-9]+)*\)?$'
                        % '|'.join(map(re.escape, sorted(vfams))))
    if any(shaped.match(n) for n in rec['names']):
        # The version tag landed in the NAME column: the layout moved.
        rec['status'] = fmt + 'a symbol name is shaped like a version tag (unrecognised output format?)'
    elif needed and not rec['names']:
        # NEEDED libraries but not one undefined symbol parsed: far more likely
        # an objdump output format this parser does not know than an object
        # that links libraries and uses nothing from them.
        rec['status'] = (fmt + 'NEEDED libraries but no undefined '
                         'symbol row could be parsed (unrecognised output format?)')
    else:
        # A real build that links libc imports at least one GLIBC versioned symbol
        # (__libc_start_main, ...). Rows parsed but not one such tag means the
        # VERSION column was not understood. Only libc is checked: measured on
        # ~7,000 system ELFs, an ELF that NEEDs libstdc++ or libm without a
        # GLIBCXX/CXXABI/GLIBC tag of that family is common (linked but unused),
        # so checking those would be a false-positive source.
        have = {split_tag(t)[0] for t in rec['tags'] if split_tag(t)[1] is not None}
        hit = [n for n in needed if n == 'libc.so' or n.startswith('libc.so.')]
        if hit and 'GLIBC' not in have:
            rec['status'] = (fmt + 'expected GLIBC versioned imports (NEEDED %s), parsed none '
                             '(unrecognised output format?)' % safe(hit[0]))
        elif (any(n == 'libstdc++.so' or n.startswith('libstdc++.so.') for n in needed)
              and any(STD_SYMBOL.match(n) for n in rec['names']) and 'GLIBCXX' not in have):
            # Narrow on purpose: an ELF that links libstdc++ AND imports a std::
            # symbol (_ZSt..., _ZNSt..., _ZNKSt...) always carries a GLIBCXX tag.
            # No broad __cxa_* / CXXABI rule: __cxa_atexit is a GLIBC symbol.
            rec['status'] = (fmt + 'expected GLIBCXX versioned imports (NEEDED libstdc++, std:: '
                             'symbols imported), parsed none (unrecognised output format?)')
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


def edit_distance(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def typo_problems(floor, unlisted_fams):
    """A measured family absent from the floor's "max" but within edit distance 2
    of a key that IS there is probably a typo in the floor file, which would
    silently ungate the family. Distance 1 only and names under 5 characters
    exempt: distance 2 flagged real families (OPENCL~OPENSSL, BLKID_2~BLKID)
    on a system corpus, and GLIBC~GLIBCXX is exactly 2 apart."""
    out = []
    for u in sorted(unlisted_fams):
        for k in sorted(floor['max']):
            if len(u) >= 5 and len(k) >= 5 and u != k and edit_distance(u, k) == 1:
                out.append('family %s is measured but not in the floor\'s "max", and is '
                           'one edit away from the listed %s: typo in the floor file?'
                           % (safe(u), safe(k)))
    return out


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


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse echoes argv text; render it like every other untrusted string.
        try:
            sys.stderr.write(neutralize('check-elf-floor.sh: error: %s' % safe(message)) + '\n')
        except Exception:
            pass
        sys.exit(2)


def main():
    # allow_abbrev=False: `--enf` must not silently mean `--enforce` (a workflow
    # tripwire greps for the literal flag).
    ap = Parser(prog='check-elf-floor.sh', add_help=True, allow_abbrev=False)
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
    args.root = os.path.abspath(args.root)   # never option-shaped (`-w`)
    try:
        limit = float(os.environ.get('YUZU_ELF_FLOOR_DEADLINE') or DEFAULT_DEADLINE)
        if not 0 <= limit < 1e7:
            raise ValueError
    except ValueError:
        die('YUZU_ELF_FLOOR_DEADLINE must be a number of seconds >= 0')
    objdump = os.environ.get('OBJDUMP', 'objdump')
    readelf = os.environ.get('READELF', 'readelf')
    for tool in (objdump, readelf):
        if shutil.which(tool) is None:
            die('%s not found on PATH (binutils is required)' % tool)

    elfs, non_elf, walk_errors = discover(args.root, args.include, args.exclude)
    deadline = time.monotonic() + limit
    unscanned = 0

    arts, full = {}, {}
    overall, over_count = {}, {}
    all_viol = []                       # (rel, violation)
    static_n = 0
    for rel, path in elfs:
        if time.monotonic() >= deadline:
            unscanned += 1
            rec = {'tags': {}, 'names': set(), 'runpath': [],
                   'status': 'error: not scanned (aggregate deadline exceeded)'}
        else:
            rec = scan_elf(rel, path, objdump, readelf, deadline,
                           set(KNOWN_VERSION_FAMILIES) | set(floor['max']))
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

    problems = list(walk_errors)
    unlisted_fams = {split_tag(t)[0] for _, e in arts.items() for t in e.get('unlisted', {})
                     if split_tag(t)[1] is not None}
    problems += typo_problems(floor, unlisted_fams)
    if unscanned:
        problems.append('aggregate deadline of %gs exceeded: %d of %d ELF(s) not scanned'
                        % (limit, unscanned, len(elfs)))
    if not elfs:
        problems.append('no ELF files found under the scanned directory '
                        '(an empty scan is not a clean scan)')

    # ---------------------------------------------------------------- stdout
    out = []
    out.append('check-elf-floor: floor=%s (%s) set=%s mode=%s'
               % (safe(os.path.basename(args.floor)), safe(floor['name']), safe(set_name),
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
    sys.stdout.write(neutralize('\n'.join(out)) + '\n')
    sys.stdout.flush()      # a failed write must surface here, as exit 2

    # ------------------------------------------------- GitHub Actions output
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        level = 'error' if enforce else 'warning'
        title = gh_prop('Linux ELF floor (%s)' % safe(set_name))
        # GitHub shows only ~10 annotations per step: say what is wrong with
        # the SCAN first, then the per-ELF findings.
        for p in problems:
            print('::%s title=%s::%s' % (level, title, gh_escape(p)))
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
    summ = os.environ.get('GITHUB_STEP_SUMMARY')
    if summ:
        md = ['### Linux ELF floor: %s (%s)' % (mdsafe(set_name), 'enforce' if enforce else 'report-only'),
              '', '%d ELF(s) scanned, %d violation(s) in %d ELF(s). Floor file `%s`.'
              % (len(elfs), len(all_viol), len({r for r, _ in all_viol}),
                 mdsafe(os.path.basename(args.floor))), '']
        for p in problems:
            md += ['**Problem:** ' + mdsafe(p), '']
        if elfs:
            md += ['| Family | Floor | Measured max | ELFs over floor |', '|---|---|---|---|']
            for fam in fams:
                md.append('| %s | %s | %s | %d |' % (
                    mdsafe(fam), floor['max'].get(fam, '(unlisted)'), overall.get(fam, '-'),
                    over_count.get(fam, 0)))
            md.append('')
        if all_viol:
            counts = {}
            for rel, _ in all_viol:
                counts[rel] = counts.get(rel, 0) + 1
            worst = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:SUMMARY_ROWS]
            md += ['| ELF (top %d by violations) | Violations |' % SUMMARY_ROWS, '|---|---|']
            md += ['| `%s` | %d |' % (mdsafe(rel), c) for rel, c in worst]
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
        bad_elfs = sum(1 for v in arts.values() if str(v.get('status', '')).startswith('error'))
        if problems or bad_elfs:
            # An understated baseline must say so, but a clean one stays byte-identical.
            entry['incomplete'] = list(problems) + (
                ['%d ELF(s) unreadable or not scanned' % bad_elfs] if bad_elfs else [])
        data['sets'][set_name] = entry
        write_atomic(args.emit_baseline, dump(data) + '\n')
    if args.full_report:
        write_atomic(args.full_report, json.dumps(
            {'schema': 1, 'set': set_name, 'floor': os.path.basename(args.floor),
             'elf_count': len(elfs), 'maxima': overall, 'artifacts': full},
            sort_keys=True, indent=1) + '\n')

    sys.stdout.flush()
    sys.exit(1 if (enforce and failing) else 0)


# A std stream closed by the caller (`>&-`) is None in Python: discard instead of
# crashing, so a report-only run still exits 0. A stream that is OPEN but failing
# (/dev/full) is a real error and exits 2.
for _name in ('stdout', 'stderr'):
    if getattr(sys, _name) is None:
        setattr(sys, _name, open(os.devnull, 'w'))

try:
    main()
except Exception as exc:       # SystemExit is not an Exception: exit codes pass through
    try:
        sys.stdout = open(os.devnull, 'w')   # a broken stdout must not re-fail at exit (120)
    except OSError:
        pass
    try:
        sys.stderr.write(neutralize('check-elf-floor: internal error: %s: %s'
                                    % (type(exc).__name__, safe(str(exc))[:200])) + '\n')
    except Exception:
        pass                                  # stderr closed/full: exit 2 is all we can say
    sys.exit(2)
PYEOF
