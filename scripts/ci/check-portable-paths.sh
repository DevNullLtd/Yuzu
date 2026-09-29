#!/usr/bin/env bash
# check-portable-paths.sh -- portable tracked-path gate (ws91 P91-7 respec,
# Architect ruling 2026-09-08)
#
# A zero-cost, no-build text scan (same shape as check-metrics-help-ascii.sh /
# check-api-parity.py) that fails a PR reintroducing a tracked path Windows
# cannot represent. NTFS rejects ':' outright (ERROR_INVALID_NAME) and treats
# `* ? " < > |` and a trailing '.'/' ' on any path COMPONENT as illegal too;
# a `git checkout` of such a branch fails completely on any Windows host --
# the-rig and the required self-hosted "Windows MSVC" CI checkout job alike.
#
# History: P91-5 (wave 2) committed a Linux sysfs fixture tree using literal
# sysfs device-address colons ("0000:00:01.0", "1-0:1.0", "0-0:1.1") --
# `git ls-files | grep -c ':'` went from 0 to 35 on that commit
# (68324501e) and broke the Windows checkout for every branch built on top
# of it. Fixed in the same package (P91-7) that added this gate: the tree
# is now materialized at runtime from a portable-named manifest instead of
# tracked path-for-path (see tests/unit/fixtures/wave9/peripherals/linux/
# provenance.txt). This gate exists so the NEXT sysfs-shaped or
# `dev:addr`-shaped fixture tree fails fast in CI instead of reaching
# the-rig.
#
# Usage:
#   scripts/ci/check-portable-paths.sh              # scan the real tree (git ls-files)
#   scripts/ci/check-portable-paths.sh --selftest    # fixture self-test (no git needed)
#
# Exit status: 0 = clean (or selftest passed), 1 = an illegal path was found
# (or selftest failed), 2 = usage error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

SELFTEST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --selftest) SELFTEST=1 ;;
    *)
      echo "usage: $0 [--selftest]" >&2
      exit 2
      ;;
  esac
  shift
done

# Resolve a WORKING interpreter, not merely one whose name is on PATH (the
# Windows python3.exe App Execution Alias stub reports success on
# `command -v` but is not a real interpreter) -- same guard as the sibling
# gates.
PYTHON_BIN=""
for _candidate in python3 python; do
  if command -v "$_candidate" >/dev/null 2>&1 && "$_candidate" -c "" >/dev/null 2>&1; then
    PYTHON_BIN="$_candidate"
    break
  fi
done
if [ -z "$PYTHON_BIN" ]; then
  echo "check-portable-paths: no working python interpreter found (tried python3, python)." >&2
  exit 2
fi

"$PYTHON_BIN" - "$REPO_ROOT" "$SELFTEST" <<'PYEOF'
import subprocess
import sys

repo_root = sys.argv[1]
selftest_flag = sys.argv[2] == "1"

# Characters NTFS/Win32 reject outright in a path component, plus control
# characters (0x00-0x1F, also illegal). ':' is listed explicitly even though
# it is also < 0x20-adjacent territory, so the error message can name it by
# itself -- it is by far the most common offender (sysfs/PCI/MAC-address-
# shaped fixture data).
ILLEGAL_CHARS = set(':*?"<>|') | {chr(c) for c in range(0x20)}

# Win32/NTFS reserved device basenames -- illegal as a path component
# REGARDLESS of extension ("NUL", "nul.txt", "Com1.log" are all rejected by
# CreateFile/git-checkout the same way a literal ':' is). Case-insensitive;
# compared against the component with any extension stripped.
RESERVED_BASENAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{d}" for d in range(1, 10)),
    *(f"LPT{d}" for d in range(1, 10)),
}


def illegal_reason(path):
    """None if every component of `path` is representable on Windows, else a
    short human-readable reason. Pure -- no filesystem/git access, so the
    selftest below exercises the exact logic the real scan uses."""
    if not path:
        return None
    for component in path.split("/"):
        if component in ("", ".", ".."):
            continue
        bad_chars = sorted(set(component) & ILLEGAL_CHARS)
        if bad_chars:
            shown = ", ".join(repr(c) for c in bad_chars)
            return f"path component {component!r} contains character(s) illegal on Windows: {shown}"
        if component[-1] in (".", " "):
            return f"path component {component!r} ends with a trailing '.' or ' ' (illegal on Windows)"
        basename = component.split(".", 1)[0].upper()
        if basename in RESERVED_BASENAMES:
            return (f"path component {component!r} uses the Win32 reserved device name "
                    f"{basename!r} (illegal on Windows regardless of extension)")
    return None


def run_full_scan(paths):
    findings = []
    for path in paths:
        reason = illegal_reason(path)
        if reason is not None:
            findings.append((path, reason))
    if findings:
        for path, reason in findings:
            print(
                f"::error file={path}::tracked path is not representable on Windows: {reason}. "
                f"A plain `git checkout` of this branch fails on NTFS. Materialize the real name "
                f"at test/build run time instead of tracking it verbatim -- see "
                f"tests/unit/fixtures/wave9/peripherals/linux/provenance.txt for the pattern "
                f"this gate was added alongside (ws91 P91-7, Architect ruling 2026-09-08)."
            )
        print(f"\n{len(findings)} tracked path(s) are not representable on Windows.", file=sys.stderr)
        return 1
    print(f"check-portable-paths: clean ({len(paths)} tracked path(s) scanned, all Windows-representable).")
    return 0


def run_selftest():
    # Clean: ordinary paths, including one with a trailing-dot DIRECTORY
    # component check boundary (a dot as part of an extension, not at the
    # end of the component) and a dash-hyphenated bus-address-looking name
    # that does NOT use a colon.
    clean = [
        "agents/plugins/peripherals/src/peripherals_win.cpp",
        "tests/unit/fixtures/wave9/peripherals/linux/sysfs_tree.manifest",
        "tests/unit/fixtures/wave9/peripherals/windows/0000-00-01.0.txt",
    ]
    for p in clean:
        reason = illegal_reason(p)
        if reason is not None:
            print(f"SELFTEST FAILED: clean path {p!r} was flagged: {reason}")
            return 1

    # Seeded: the exact defect class this gate exists for -- a literal ':'
    # in a path component (sysfs PCI/USB/thunderbolt device-address shape).
    seeded_colon = "tests/unit/fixtures/wave9/peripherals/linux/sysfs_tree/sys/bus/pci/devices/0000:00:01.0/class"
    reason = illegal_reason(seeded_colon)
    if reason is None or ":" not in reason:
        print(f"SELFTEST FAILED: colon-bearing path was NOT flagged: {reason!r}")
        return 1

    # Seeded: every other Win32-illegal character, one path each.
    for ch in '*?"<>|':
        p = f"tests/unit/fixtures/bad{ch}name/file.txt"
        reason = illegal_reason(p)
        if reason is None:
            print(f"SELFTEST FAILED: {ch!r}-bearing path was NOT flagged")
            return 1

    # Seeded: trailing dot and trailing space on a path component.
    for bad in ["tests/unit/fixtures/trailing_dot./file.txt",
                "tests/unit/fixtures/trailing_space /file.txt"]:
        reason = illegal_reason(bad)
        if reason is None:
            print(f"SELFTEST FAILED: trailing dot/space path was NOT flagged: {bad!r}")
            return 1

    # Seeded: Win32 reserved device basenames, bare and with an extension,
    # case-insensitively -- the class this gate was missing (adversarial
    # review, wave9 PR9.1a).
    for bad in ["tests/unit/fixtures/NUL", "tests/unit/fixtures/nul",
                "tests/unit/fixtures/COM1.log", "tests/unit/fixtures/com1.log"]:
        reason = illegal_reason(bad)
        if reason is None:
            print(f"SELFTEST FAILED: reserved-basename path was NOT flagged: {bad!r}")
            return 1

    # Clean: a component that merely STARTS WITH a reserved name, or carries
    # one mid-string, must NOT be flagged -- only an exact (extension-
    # stripped) basename match is reserved.
    for ok in ["tests/unit/fixtures/NULodata/file.txt",
               "tests/unit/fixtures/console/file.txt"]:
        reason = illegal_reason(ok)
        if reason is not None:
            print(f"SELFTEST FAILED: clean path {ok!r} was flagged: {reason}")
            return 1

    # Full-scan wiring: a clean list must exit 0, a seeded list must exit 1
    # -- proves run_full_scan's own exit-code contract, not just the pure
    # predicate above.
    if run_full_scan(clean) != 0:
        print("SELFTEST FAILED: run_full_scan flagged an all-clean list")
        return 1
    if run_full_scan(clean + [seeded_colon]) != 1:
        print("SELFTEST FAILED: run_full_scan did not fail a list containing the colon path")
        return 1

    print("check-portable-paths --selftest: all fixtures behaved as expected.")
    return 0


def real_tracked_paths(root):
    """The exact set of paths `git checkout` would try to materialize.
    -z / NUL-terminated so a path containing a newline (legal on POSIX,
    itself something this gate would flag) can't desync the list."""
    out = subprocess.run(
        ["git", "-C", root, "ls-files", "-z"],
        check=True, capture_output=True,
    ).stdout
    return [p for p in out.decode("utf-8", errors="surrogateescape").split("\0") if p]


if selftest_flag:
    sys.exit(run_selftest())
else:
    sys.exit(run_full_scan(real_tracked_paths(repo_root)))
PYEOF
