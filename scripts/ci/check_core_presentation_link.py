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
source-tree walk. It is wired as a meson `test()`, name `'dex link no
presentation symbols'` (tests/meson.build, `suite: ['server',
'server-checks']`), not a docs-lint.yml step. MSVC has no `nm` and emits
`.obj` not `.cpp.o`, so the test() entry itself does not exist on that
toolchain (`if cxx.get_id() != 'msvc'` in tests/meson.build) - it gates
every build-and-test CI job where the toolchain is GCC/Clang (Linux, macOS)
rather than the build-free docs-lint job check-seam-closure.py runs in.
CI-2 (2026-09-28): the Linux leg's non-pg Test step selected its
`server-checks`-suite tests by an explicit NAME list, which had never named
this test, so it silently never ran there despite existing in the build -
fixed by adding it to that list (ci.yml); the macOS leg already ran it
(no by-name filter, full `meson test`).

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
import json
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
            "rest_api_v1",     # WS-A4 PR-1 Gate 7 fix round: the three REST DEX
                                # aggregate handlers call the seam directly (dex_api),
                                # never dex_routes.cpp - enrolled so a future revert
                                # to a store-backed/dex_routes.cpp-linked call here is
                                # itself caught, not just the seam's own core TUs.
            "mcp_server",      # same rationale as rest_api_v1 above, for the MCP twins.
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


#: The core library target's own object directory (UP-10) - restricting the
#: object lookup to here, rather than an `rglob` over the whole build tree,
#: avoids ever picking up a stale or duplicate object compiled into a
#: DIFFERENT target's `.p` directory (e.g. a future test binary that also
#: compiles one of these same source files) - `find_object` below now
#: errors clearly if the wanted object is missing or duplicated even within
#: this single, narrower directory, rather than silently matching whichever
#: copy `rglob` happened to find first across the whole tree.
CORE_TARGET_OBJ_DIR = Path("server") / "core" / "libyuzu_server_core.a.p"


def find_object(build_dir: Path, stem: str) -> Path:
    """Locate the single compiled object for a source stem under the core
    library target's own object directory (see CORE_TARGET_OBJ_DIR).

    Meson names an object `src_<stem>.cpp.o` (or `.obj` on the MSVC backend)
    inside its target's `*.p`/`.p` directory - match on the exact basename
    rather than a substring, so a stem that is a suffix of another source
    file's name (there is none today, but a future one should not silently
    match the wrong object).
    """
    obj_dir = build_dir / CORE_TARGET_OBJ_DIR
    if not obj_dir.is_dir():
        raise SystemExit(
            f"check_core_presentation_link: core target object directory "
            f"{obj_dir} does not exist - build yuzu_server_core first "
            f"(`meson compile -C <builddir> yuzu_server_core`)"
        )
    wanted = {f"src_{stem}.cpp.o", f"src_{stem}.cpp.obj"}
    matches = [p for p in obj_dir.iterdir() if p.name in wanted]
    if not matches:
        raise SystemExit(
            f"check_core_presentation_link: no compiled object for '{stem}' under "
            f"{obj_dir} (matched none of {sorted(wanted)}) - build "
            f"yuzu_server_core first (`meson compile -C <builddir> yuzu_server_core`)"
        )
    if len(matches) > 1:
        raise SystemExit(
            f"check_core_presentation_link: ambiguous object for '{stem}' under "
            f"{obj_dir}: {sorted(str(m) for m in matches)}"
        )
    return matches[0]


#: An LTO "slim" object (produced under `-flto` when the toolchain defers
#: real codegen to the link step) carries essentially no real symbol table -
#: `nm` on one, WITHOUT the LTO plugin loaded, sees only this GCC-internal
#: marker symbol (ci8-1/UP-9). Reading such an object with a plain `nm`
#: lacking `/usr/lib/bfd-plugins/liblto_plugin.so` would otherwise present
#: as "defines/references nothing", which the vacuous-pass guards below
#: already catch generically - but a bare "ZERO symbols" message gives no
#: hint that the FIX is "use gcc-nm/pass --plugin", not "the object is
#: broken". This name is checked for explicitly so that failure mode gets
#: its own, actionable diagnostic instead.
LTO_SLIM_MARKER = "__gnu_lto_slim"


def object_symbols(nm_path: str, obj_path: Path, undefined_only: bool) -> set[str]:
    flag = "--undefined-only" if undefined_only else "--defined-only"
    args = [nm_path, flag]
    if not undefined_only:
        # xp8-1: `--extern-only` (`-g`) on the DEFINED-only read only - an
        # undefined reference is external by construction, but a defined-
        # symbol read without it can surface a TU-local symbol (e.g. an
        # empty translation unit's Mach-O local `ltmp0`) that this check
        # has no business comparing against another object's undefined set.
        args.append("--extern-only")
    args.append(str(obj_path))
    proc = subprocess.run(args, capture_output=True, text=True, check=True)
    syms: set[str] = set()
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # Undefined lines are "U <sym>"; defined lines are "<addr> <type> <sym>".
        # The mangled symbol is always the last whitespace-separated field -
        # mangled C++ names never contain a space, so this is exact.
        syms.add(line.split()[-1])
    if syms and syms <= {LTO_SLIM_MARKER}:
        raise VacuousPassError(
            f"LTO slim object unreadable: '{obj_path}' carries only the "
            f"'{LTO_SLIM_MARKER}' marker symbol - `nm` cannot read a real "
            f"symbol table from an LTO-slim object without the LTO plugin "
            f"loaded. Use gcc-nm (or pass --plugin=<path to liblto_plugin.so> "
            f"to nm) instead of a plain `nm`."
        )
    return syms


def select_nm(build_dir: Path) -> str:
    """Prefer a compiler-matched `nm` (ci8-1/UP-9): a plain `nm` cannot read
    an LTO-slim object's real symbol table without the LTO plugin loaded,
    which `gcc-nm`/`llvm-nm` load automatically. Falls back to plain `nm`
    when the compiler-matched variant is not installed - LTO-slim inputs
    then surface via the dedicated LTO_SLIM_MARKER diagnostic above rather
    than a silent vacuous pass.
    """
    compiler_id = None
    try:
        proc = subprocess.run(
            ["meson", "introspect", "--compilers", str(build_dir)],
            capture_output=True,
            text=True,
            check=True,
        )
        info = json.loads(proc.stdout)
        compiler_id = info.get("host", {}).get("cpp", {}).get("id")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, KeyError):
        pass  # fall through to plain nm below - not fatal, just less precise
    preferred = {"gcc": "gcc-nm", "clang": "llvm-nm"}.get(compiler_id or "")
    if preferred:
        found = shutil.which(preferred)
        if found:
            return found
    found = shutil.which("nm")
    if not found:
        raise SystemExit("check_core_presentation_link: 'nm' not found on PATH")
    return found


def demangle(nm_path: str, symbol: str) -> str:
    cppfilt = shutil.which("c++filt")
    if not cppfilt:
        return symbol
    try:
        proc = subprocess.run([cppfilt, symbol], capture_output=True, text=True, check=True)
        return proc.stdout.strip() or symbol
    except (OSError, subprocess.SubprocessError):
        return symbol


class VacuousPassError(Exception):
    """Raised when the check's own inputs could produce a false-green PASS
    regardless of what the checked objects actually contain - governance
    finding arch-4/xp-2 (WS-A4 PR-1 Gate 7 fix round): an empty `nm` read on
    EITHER side (a mis-stemmed object, a stripped binary, a build-system
    change that stops emitting the symbol table this check depends on) would
    otherwise silently pass with zero violations found, indistinguishable
    from a genuinely clean family. Both guards below fire BEFORE the
    intersection is computed, so a vacuous input is reported as its own
    failure, never folded into "0 violations."
    """


def check_family(build_dir: Path, nm_path: str, family: str, spec: dict[str, list[str]]) -> list[Violation]:
    core_objs = {stem: find_object(build_dir, stem) for stem in spec["core"]}
    presentation_objs = {stem: find_object(build_dir, stem) for stem in spec["presentation"]}

    presentation_defined: dict[str, str] = {}  # symbol -> defining object stem
    for stem, obj in presentation_objs.items():
        for sym in object_symbols(nm_path, obj, undefined_only=False):
            presentation_defined.setdefault(sym, stem)

    # Vacuous-pass guard 1: the presentation side defines NOTHING. Every
    # violation this check can find requires a presentation object to
    # DEFINE the colliding symbol - an empty `presentation_defined` set
    # makes every core object's undefined-symbol set trivially "clean"
    # regardless of its real content, exactly the false-green shape a
    # stripped/mis-stemmed/empty presentation object would produce.
    if not presentation_defined:
        raise VacuousPassError(
            f"family '{family}': its presentation object(s) "
            f"({', '.join(sorted(presentation_objs))}) define ZERO symbols between "
            f"them - this check cannot distinguish 'genuinely clean' from 'read "
            f"nothing' and refuses to report a pass either way"
        )

    violations: list[Violation] = []
    for stem, obj in core_objs.items():
        undefined = object_symbols(nm_path, obj, undefined_only=True)
        # Vacuous-pass guard 2: a core object with ZERO undefined symbols is
        # not a normal, tightly-self-contained TU in this codebase (every
        # enrolled core object calls at minimum libstdc++/libc symbols) - it
        # is the signature of `nm` reading the wrong/empty object, and it
        # would otherwise pass this family's check by definition (nothing to
        # intersect against presentation_defined).
        if not undefined:
            raise VacuousPassError(
                f"family '{family}': core object '{stem}.cpp.o' has ZERO "
                f"undefined symbols - this is not a normal TU shape (every "
                f"enrolled core object calls at least libc/libstdc++) and would "
                f"trivially 'pass' this check with nothing to compare; likely a "
                f"mis-stemmed or empty object"
            )
        for sym in undefined:
            hit = presentation_defined.get(sym)
            if hit is not None:
                violations.append(Violation(family, sym, stem, hit))
    return violations


def run_check(build_dir: Path, verbose: bool = False) -> int:
    nm_path = select_nm(build_dir)

    all_violations: list[Violation] = []
    for family, spec in FAMILIES.items():
        try:
            violations = check_family(build_dir, nm_path, family, spec)
        except VacuousPassError as exc:
            print(f"::error::check_core_presentation_link: {exc}", file=sys.stderr)
            print(
                "check_core_presentation_link: FAILED - vacuous-pass guard tripped "
                "(see error above); refusing to report a pass on an empty read",
                file=sys.stderr,
            )
            return 1
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
