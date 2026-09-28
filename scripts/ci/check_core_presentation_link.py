#!/usr/bin/env python3
"""check_core_presentation_link.py - per-family LINK-CLOSURE seam-enforcement
gate (ADR-0031 WS-A4, PR-1 F1 fix).

`check-seam-closure.py` (docs-lint.yml, no build dependency) enforces INCLUDE
closure only: it walks a family's TUs and fails if any of them can reach a
store-layer header. It is explicitly blind to a LINK dependency - a CORE
translation unit can call a function that is only DECLARED in a pure,
store-free header but DEFINED in a PRESENTATION translation unit's own
`.cpp`, and the include-closure walk never sees that, because the
presentation TU's `.cpp` file is never `#include`d by anyone (only its
sibling `.hpp` is, and the `.hpp` carries just the declaration). That gap is
exactly how the `dex` family's `dex_read_model.cpp`/`dex_api.cpp` (core)
ended up calling seven functions - `dex_signal_groups`, `dex_catalogued_type_
count`, `dex_obs_platforms`, `dex_family_rollup`, `dex_family_health_
deduction`, `dex_compute_health`, `dex_family_index` - all DECLARED in the
pure `dex_types.hpp` but DEFINED in the presentation TU `dex_routes.cpp`
(plus `dex_window_to_days`/`dex_iso_since`/`dex_normalize_os_filter` in
`dex_window.hpp`/`dex_routes.cpp`, and `dex_device_score`/`dex_score_from_
signals` in the core-only `dex_read_builders.hpp`/`dex_routes.cpp` - the
WS-B2 "LINK RESIDUAL" #4579 that header's own doc comment had flagged but
nothing enforced) - invisible to check-seam-closure.py, caught only by a
Fable plan-review pass (2026-09-28) reading dex_routes.cpp by hand.

WHAT THIS CHECKS: for each enrolled family, the union of UNDEFINED symbols
referenced by its declared CORE object files must not intersect the union of
DEFINED symbols exported by its declared PRESENTATION object files. A
non-empty intersection means a core TU has a real, unresolved link-time
dependency on a symbol only the presentation TU supplies - core linking
against presentation, exactly the shape this family split exists to prevent.

WHY THIS RUNS AFTER A BUILD, UNLIKE check-seam-closure.py: this check needs
the compiled `.o` files to run `nm` over - it cannot run as a pure
source-tree walk. It is wired as a meson `test()` in `suite:server`
(tests/meson.build's `dex_link_no_presentation_symbols`), not a
docs-lint.yml step, so it gates every build-and-test CI job rather than the
build-free docs-lint job check-seam-closure.py runs in.

SOUNDNESS, matching check-seam-closure.py's own stated posture: this is a
sound-for-its-stated-claim link-symbol check, not a full static analysis.
- A symbol that is DEFINED WEAK in every TU that uses it (an ordinary inline
  function, most template instantiations under the standard GCC/Clang model)
  never shows up as UNDEFINED in the referencing TU at all - the compiler
  emits the referencing TU its own weak copy - so this check cannot see, and
  does not need to see, that class of symbol; it only fires on a symbol a
  core object could NOT resolve locally.
- Symbol NAMES are mangled C++ link names, matched byte-for-byte (never
  demangled for matching, only for the failure message) - two genuinely
  different functions cannot coincidentally collide under the Itanium C++
  ABI's name mangling.
- Like check-seam-closure.py, this is a PROXY, not a substitute for review: a
  core TU that hand-redeclares a presentation-only symbol with an
  INCOMPATIBLE local shadow, or reaches presentation only via a function
  pointer resolved at runtime, is out of scope. Neither shape exists in the
  family this script covers today.

Data-driven (FAMILIES below) so a new family enrols by adding one entry -
same posture as check-seam-closure.py's own FAMILIES dict.

USAGE
  check_core_presentation_link.py [--build-dir DIR] [--verbose]
    DIR defaults to $MESON_BUILD_ROOT (set by `meson test`), then to the
    first of ../build-linux, ../build-macos, ../build-windows under the repo
    root that exists (local dev convenience only - CI always sets
    MESON_BUILD_ROOT via `meson test`).
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# One entry per enrolled family. `core`/`presentation` are OBJECT-FILE STEMS
# (the source file's name under server/core/src, without the `.cpp`
# extension) - the script locates each stem's compiled object under the
# build directory itself (find_object below), so it does not hard-code a
# build-system path shape.
FAMILIES: dict[str, dict[str, list[str]]] = {
    "dex": {
        "core": [
            "dex_api",         # ADR-0031 WS-A4 fifth family API seam impl
            "dex_read_model",  # store-reaching builders + the MCP-only-gap builder
            "dex_types",       # PURE catalogue/health computation (PR-1 F1 fix)
            "dex_window",      # PURE window/OS-filter resolvers (PR-1 F1 fix)
        ],
        "presentation": [
            "dex_routes",      # the httplib-coupled /dex dashboard TU
        ],
    },
}


class Violation:
    def __init__(self, family: str, symbol: str, core_obj: str, presentation_obj: str) -> None:
        self.family = family
        self.symbol = symbol
        self.core_obj = core_obj
        self.presentation_obj = presentation_obj


def find_build_dir(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).resolve()
    env = os.environ.get("MESON_BUILD_ROOT")
    if env:
        return Path(env).resolve()
    for candidate in ("build-linux", "build-macos", "build-windows"):
        p = ROOT / candidate
        if p.is_dir():
            return p
    raise SystemExit(
        "check_core_presentation_link: no build directory - pass --build-dir, "
        "set MESON_BUILD_ROOT, or run under one of build-linux/build-macos/"
        "build-windows"
    )


def find_object(build_dir: Path, stem: str) -> Path:
    """Locate the single compiled object for a source stem under build_dir.

    Meson names an object `src_<stem>.cpp.o` (or `.obj` on the MSVC backend)
    inside its target's `*.p`/`.p` directory - match on the exact basename
    rather than a substring, so a stem that is a suffix of another source
    file's name (there is none today, but a future one should not silently
    match the wrong object).
    """
    wanted = {f"src_{stem}.cpp.o", f"src_{stem}.cpp.obj"}
    matches = [p for p in build_dir.rglob("*.o*") if p.name in wanted]
    if not matches:
        raise SystemExit(
            f"check_core_presentation_link: no compiled object for '{stem}' under "
            f"{build_dir} (matched none of {sorted(wanted)}) - build "
            f"yuzu_server_core first (`meson compile -C <builddir> yuzu_server_core`)"
        )
    if len(matches) > 1:
        raise SystemExit(
            f"check_core_presentation_link: ambiguous object for '{stem}' under "
            f"{build_dir}: {sorted(str(m) for m in matches)}"
        )
    return matches[0]


def object_symbols(nm_path: str, obj_path: Path, undefined_only: bool) -> set[str]:
    flag = "--undefined-only" if undefined_only else "--defined-only"
    proc = subprocess.run(
        [nm_path, flag, str(obj_path)], capture_output=True, text=True, check=True
    )
    syms: set[str] = set()
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # Undefined lines are "U <sym>"; defined lines are "<addr> <type> <sym>".
        # The mangled symbol is always the last whitespace-separated field -
        # mangled C++ names never contain a space, so this is exact.
        syms.add(line.split()[-1])
    return syms


def demangle(nm_path: str, symbol: str) -> str:
    cppfilt = shutil.which("c++filt")
    if not cppfilt:
        return symbol
    try:
        proc = subprocess.run([cppfilt, symbol], capture_output=True, text=True, check=True)
        return proc.stdout.strip() or symbol
    except (OSError, subprocess.SubprocessError):
        return symbol


def check_family(build_dir: Path, nm_path: str, family: str, spec: dict[str, list[str]]) -> list[Violation]:
    core_objs = {stem: find_object(build_dir, stem) for stem in spec["core"]}
    presentation_objs = {stem: find_object(build_dir, stem) for stem in spec["presentation"]}

    presentation_defined: dict[str, str] = {}  # symbol -> defining object stem
    for stem, obj in presentation_objs.items():
        for sym in object_symbols(nm_path, obj, undefined_only=False):
            presentation_defined.setdefault(sym, stem)

    violations: list[Violation] = []
    for stem, obj in core_objs.items():
        for sym in object_symbols(nm_path, obj, undefined_only=True):
            hit = presentation_defined.get(sym)
            if hit is not None:
                violations.append(Violation(family, sym, stem, hit))
    return violations


def run_check(build_dir: Path, verbose: bool = False) -> int:
    nm_path = shutil.which("nm")
    if not nm_path:
        raise SystemExit("check_core_presentation_link: 'nm' not found on PATH")

    all_violations: list[Violation] = []
    for family, spec in FAMILIES.items():
        violations = check_family(build_dir, nm_path, family, spec)
        all_violations.extend(violations)
        if verbose and not violations:
            print(
                f"check_core_presentation_link: family '{family}' OK "
                f"({len(spec['core'])} core objects checked against "
                f"{len(spec['presentation'])} presentation objects)"
            )

    if all_violations:
        for v in all_violations:
            print(
                f"::error::check_core_presentation_link: family '{v.family}': "
                f"core object '{v.core_obj}.cpp.o' has an unresolved reference to "
                f"'{demangle(nm_path, v.symbol)}' ({v.symbol}), which is DEFINED in "
                f"presentation object '{v.presentation_obj}.cpp.o' - core links "
                f"against presentation, invisible to check-seam-closure.py's "
                f"include-closure walk. Move the definition into a core TU.",
                file=sys.stderr,
            )
        print(
            f"check_core_presentation_link: FAILED - {len(all_violations)} "
            f"core-links-against-presentation symbol(s) across "
            f"{len({v.family for v in all_violations})} family(ies)",
            file=sys.stderr,
        )
        return 1

    print(
        f"check_core_presentation_link: OK ({len(FAMILIES)} family(ies) checked; "
        f"no enrolled core object references a symbol defined in its family's "
        f"presentation object(s))"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", default=None, help="meson build directory (defaults to $MESON_BUILD_ROOT)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    build_dir = find_build_dir(args.build_dir)
    return run_check(build_dir, verbose=args.verbose)


if __name__ == "__main__":
    sys.exit(main())
