#!/usr/bin/env python3
"""Self-test that locks scripts/ci/check_core_presentation_link.py against
silent neutering (ADR-0031 WS-A4 PR-1 F1 fix's link-level twin of
check-seam-closure.py; see that script's own module docstring for what it
checks and why it needs a build).

Mirrors tests/test_seam_closure_selftest.py's shape for its sibling
include-closure gate:

1. Pins the checker's FAMILIES module-level constant against a frozen value
   HERE, in test code, so widening/narrowing the real policy (dropping a
   stem from `dex`'s `core` list, or the whole family) means also editing
   this file in the same reviewed change - a loud, auditable path, not a
   silent edit.

2. Runs a POSITIVE-FIRE PROBE: compiles two tiny, synthetic `.cpp` files into
   objects named the way meson names them (`src_<stem>.cpp.o`) in a fake
   build directory, one ("core") calling an external function only the
   other ("presentation") defines, and asserts the checker's own
   `check_family()` reports exactly that violation - proving the gate
   actually fires on the link shape it claims to catch, not merely that it
   returns clean on the real (already-fixed) tree, which a checker that
   always returned no violations would also do.

3. Pairs the positive probe with a NEGATIVE CONTROL: the same two-object
   shape, but where the "core" object calls nothing the "presentation"
   object defines - asserts `check_family()` reports zero violations, so a
   "fires" result on probe 2 is evidence of discrimination, not of a checker
   that always fails.

4. Exercises `find_object`'s missing/ambiguous-object error paths, since a
   silently wrong object-lookup (matching zero, or the wrong, `.o`) would
   make the gate either always pass (false negative) or crash uninformatively
   on real families.

Imports the checker module directly (`importlib.util.spec_from_file_
location`, matching test_seam_closure_selftest.py's own established pattern
for a script whose name is not a valid Python identifier as written on
disk - this one uses underscores so a plain `import` would also work, but
importlib keeps the two selftests' shape identical for a future reader
diffing them). Needs a working C++ compiler and `nm` on PATH - both are
already load-bearing for the surrounding `meson test` run this selftest
itself gates (docs-lint.yml runs a plain `python3` invocation with no build,
same as test_seam_closure_selftest.py, so this file does NOT depend on
build-linux/build-macos/build-windows existing; it compiles its own
throwaway fixtures under a temp directory instead).
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECKER_PATH = REPO_ROOT / "scripts" / "ci" / "check_core_presentation_link.py"

# --- FROZEN CONSTANT (the lock). Editing check_core_presentation_link.py's
# --- FAMILIES to enrol/change a family must also edit this value in the
# --- same reviewed change - a loud, auditable path, not a silent narrowing
# --- or widening. Dict equality, so a re-ordered `core`/`presentation` list
# --- also trips it (`assertEqual` prints both sides).
EXPECTED_FAMILIES = {
    "dex": {
        "core": ["dex_api", "dex_read_model", "dex_types", "dex_window", "rest_api_v1",
                 "mcp_server"],
        "presentation": ["dex_routes"],
    },
}

SEAM_CLOSURE_PATH = REPO_ROOT / "scripts" / "ci" / "check-seam-closure.py"


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_core_presentation_link", CHECKER_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _load_seam_closure():
    spec = importlib.util.spec_from_file_location("check_seam_closure", SEAM_CLOSURE_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _require_toolchain() -> bool:
    # qa-4 (WS-A4 PR-1 Gate 7 fix round): a bare SkipTest on a missing
    # compiler/`nm` exits 0 from unittest's own perspective, and this
    # selftest runs under docs-lint.yml (suite: 'docs'), which has no build
    # dependency and so has no reason to guarantee either tool is present -
    # a runner image drifting to lack a C++ compiler would silently stop
    # exercising these probes forever, reading as a clean pass. Set
    # YUZU_REQUIRE_TOOLCHAIN=1 (docs-lint.yml does) to convert that into a
    # real, loud test FAILURE instead of a silent skip.
    return os.environ.get("YUZU_REQUIRE_TOOLCHAIN") == "1"


def _find_cxx() -> str:
    for candidate in (os.environ.get("CXX"), "c++", "g++", "clang++"):
        if candidate and shutil.which(candidate):
            return candidate
    if _require_toolchain():
        raise AssertionError(
            "no C++ compiler found on PATH and YUZU_REQUIRE_TOOLCHAIN=1 - "
            "this must be a real failure, not a silent skip"
        )
    raise unittest.SkipTest("no C++ compiler found on PATH")


def _find_nm() -> str:
    nm = shutil.which("nm")
    if not nm:
        if _require_toolchain():
            raise AssertionError(
                "no 'nm' found on PATH and YUZU_REQUIRE_TOOLCHAIN=1 - this must be "
                "a real failure, not a silent skip"
            )
        raise unittest.SkipTest("no 'nm' found on PATH")
    return nm


def _core_obj_dir(mod, build_dir: Path) -> Path:
    """UP-10: find_object() now looks ONLY inside the core library target's
    own object directory, not the whole build tree - mirror that here so
    every fixture this file compiles is actually where find_object() will
    look for it."""
    d = build_dir / mod.CORE_TARGET_OBJ_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d


def _compile_stem(cxx: str, build_dir: Path, stem: str, source: str, mod=None) -> None:
    """Compile `source` (a tiny synthetic .cpp body) into
    build_dir/<CORE_TARGET_OBJ_DIR>/src_<stem>.cpp.o, matching both the
    object naming AND the object LOCATION this script's find_object() looks
    for (UP-10). `mod` defaults to a fresh `_load_checker()` call when the
    caller doesn't already have one handy."""
    if mod is None:
        mod = _load_checker()
    out_dir = _core_obj_dir(mod, build_dir)
    src_path = out_dir / f"{stem}.cpp"
    src_path.write_text(source)
    obj_path = out_dir / f"src_{stem}.cpp.o"
    subprocess.run(
        [cxx, "-c", "-std=c++17", "-o", str(obj_path), str(src_path)],
        check=True,
        capture_output=True,
        text=True,
    )


class TestFamiliesFrozen(unittest.TestCase):
    def test_families_match_frozen_expectation(self) -> None:
        mod = _load_checker()
        self.assertEqual(
            EXPECTED_FAMILIES,
            mod.FAMILIES,
            "check_core_presentation_link.py's FAMILIES changed - update "
            "EXPECTED_FAMILIES here in the SAME reviewed change if the "
            "widening/narrowing is intentional",
        )

    def test_every_link_check_family_is_also_a_seam_closure_family(self) -> None:
        # arch-4 (WS-A4 PR-1 Gate 7 fix round): this link-level tripwire is
        # the LINK-closure twin of check-seam-closure.py's INCLUDE-closure
        # walk (see this checker's own module docstring) - a family enrolled
        # here with no matching entry over there would be checking link
        # cleanliness for a family whose include closure nobody enforces,
        # which is backwards (the link check exists to close a gap the
        # include check left, not to run standalone). Every key in THIS
        # module's FAMILIES must also be a key in check-seam-closure.py's own
        # FAMILIES dict - a superset relationship, not equality, since
        # check-seam-closure.py enrols families (e.g. `guardian`, `workflow`)
        # this link-level check has no reason to duplicate until they hit
        # the same defect class `dex` did.
        link_mod = _load_checker()
        seam_mod = _load_seam_closure()
        missing = set(link_mod.FAMILIES) - set(seam_mod.FAMILIES)
        self.assertEqual(
            set(),
            missing,
            f"check_core_presentation_link.py enrols {sorted(missing)}, which "
            f"check-seam-closure.py's own FAMILIES dict does not know about - "
            f"every link-check family must also be a seam-closure family",
        )


class TestPositiveFireProbe(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_checker()
        self.cxx = _find_cxx()
        self.nm = _find_nm()
        self._tmp = tempfile.TemporaryDirectory(prefix="core_pres_link_selftest_")
        self.build_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_core_calling_presentation_defined_symbol_fires(self) -> None:
        # "core" references an external function it never defines locally;
        # "presentation" is the ONLY object that defines it - the exact shape
        # of the dex_family_index/dex_signal_groups/... defect this gate
        # exists to catch.
        _compile_stem(
            self.cxx,
            self.build_dir,
            "probe_core",
            "extern void presentation_only_fn();\n"
            "void core_fn() { presentation_only_fn(); }\n",
        )
        _compile_stem(
            self.cxx,
            self.build_dir,
            "probe_pres",
            "void presentation_only_fn() {}\n",
        )
        violations = self.mod.check_family(
            self.build_dir,
            self.nm,
            "probe",
            {"core": ["probe_core"], "presentation": ["probe_pres"]},
        )
        self.assertEqual(1, len(violations), "expected exactly one violation")
        v = violations[0]
        self.assertEqual("probe", v.family)
        self.assertEqual("probe_core", v.core_obj)
        self.assertEqual("probe_pres", v.presentation_obj)
        self.assertIn("presentation_only_fn", v.symbol)

    def test_core_not_calling_presentation_defined_symbol_is_clean(self) -> None:
        # Negative control for the probe above: same two-object shape, but
        # "core" calls nothing "presentation" defines - proves a clean run
        # is discrimination, not a checker that always returns no violations.
        # Calls a THIRD, unrelated extern (never defined by either object in
        # this test) so "core" has a normal, non-vacuous undefined-symbol
        # shape - a totally self-contained core function would instead trip
        # the vacuous-pass guard 2 (TestVacuousPassGuards), which is a
        # correct, separate outcome this negative control must not collide
        # with.
        _compile_stem(
            self.cxx,
            self.build_dir,
            "clean_core",
            "extern void some_other_unrelated_extern();\n"
            "void clean_core_fn() { some_other_unrelated_extern(); }\n",
        )
        _compile_stem(
            self.cxx,
            self.build_dir,
            "clean_pres",
            "void unrelated_presentation_fn() {}\n",
        )
        violations = self.mod.check_family(
            self.build_dir,
            self.nm,
            "clean_probe",
            {"core": ["clean_core"], "presentation": ["clean_pres"]},
        )
        self.assertEqual([], violations)

    def test_run_check_reports_nonzero_exit_on_a_violation(self) -> None:
        # End-to-end: run_check() (the function main() calls) over a FAMILIES
        # override containing only the positive-fire probe, proving the
        # process-level contract (nonzero exit on a real violation), not just
        # check_family()'s return value.
        _compile_stem(
            self.cxx,
            self.build_dir,
            "e2e_core",
            "extern void e2e_presentation_only_fn();\n"
            "void e2e_core_fn() { e2e_presentation_only_fn(); }\n",
        )
        _compile_stem(
            self.cxx,
            self.build_dir,
            "e2e_pres",
            "void e2e_presentation_only_fn() {}\n",
        )
        original_families = self.mod.FAMILIES
        try:
            self.mod.FAMILIES = {
                "e2e": {"core": ["e2e_core"], "presentation": ["e2e_pres"]}
            }
            rc = self.mod.run_check(self.build_dir, verbose=False)
        finally:
            self.mod.FAMILIES = original_families
        self.assertEqual(1, rc)


class TestVacuousPassGuards(unittest.TestCase):
    # arch-4/xp-2 (WS-A4 PR-1 Gate 7 fix round): both guards must fire BEFORE
    # `check_family` reports "0 violations" on an input that could never have
    # produced a real violation in the first place (an empty `nm` read on
    # either side of the comparison).
    def setUp(self) -> None:
        self.mod = _load_checker()
        self.cxx = _find_cxx()
        self.nm = _find_nm()
        self._tmp = tempfile.TemporaryDirectory(prefix="core_pres_link_selftest_")
        self.build_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_presentation_defining_zero_symbols_raises_vacuous_pass_error(self) -> None:
        # "presentation" is an empty TU (no functions at all) - `nm
        # --defined-only` reports nothing for it, so `presentation_defined`
        # would be empty and EVERY core object would trivially "pass"
        # regardless of what it actually calls.
        _compile_stem(
            self.cxx,
            self.build_dir,
            "vacuous_core",
            "extern void something_external();\n"
            "void vacuous_core_fn() { something_external(); }\n",
        )
        _compile_stem(
            self.cxx,
            self.build_dir,
            "vacuous_pres_empty",
            "// deliberately empty - no functions, no symbols\n",
        )
        with self.assertRaises(self.mod.VacuousPassError) as ctx:
            self.mod.check_family(
                self.build_dir,
                self.nm,
                "vacuous_probe_1",
                {"core": ["vacuous_core"], "presentation": ["vacuous_pres_empty"]},
            )
        self.assertIn("ZERO symbols", str(ctx.exception))

    def test_core_object_with_zero_undefined_symbols_raises_vacuous_pass_error(self) -> None:
        # "core" is a self-contained TU that calls nothing external at all -
        # `nm --undefined-only` reports nothing for it, so it would trivially
        # "pass" (nothing to intersect against presentation_defined) even if
        # this were the WRONG object (mis-stemmed, stripped, empty).
        _compile_stem(
            self.cxx,
            self.build_dir,
            "vacuous_core_empty",
            "void vacuous_core_empty_fn() {}\n",
        )
        _compile_stem(
            self.cxx,
            self.build_dir,
            "vacuous_pres_normal",
            "void vacuous_pres_normal_fn() {}\n",
        )
        with self.assertRaises(self.mod.VacuousPassError) as ctx:
            self.mod.check_family(
                self.build_dir,
                self.nm,
                "vacuous_probe_2",
                {"core": ["vacuous_core_empty"], "presentation": ["vacuous_pres_normal"]},
            )
        self.assertIn("ZERO undefined symbols", str(ctx.exception))

    def test_run_check_reports_nonzero_exit_on_a_vacuous_family(self) -> None:
        # End-to-end: run_check() must propagate the guard as a failure
        # (nonzero exit), never let it escape as an uncaught exception or a
        # silent pass.
        _compile_stem(
            self.cxx,
            self.build_dir,
            "vacuous_e2e_core",
            "void vacuous_e2e_core_fn() {}\n",
        )
        _compile_stem(
            self.cxx,
            self.build_dir,
            "vacuous_e2e_pres",
            "void vacuous_e2e_pres_fn() {}\n",
        )
        original_families = self.mod.FAMILIES
        try:
            self.mod.FAMILIES = {
                "vacuous_e2e": {"core": ["vacuous_e2e_core"], "presentation": ["vacuous_e2e_pres"]}
            }
            rc = self.mod.run_check(self.build_dir, verbose=False)
        finally:
            self.mod.FAMILIES = original_families
        self.assertEqual(1, rc)


class TestLtoSlimDetection(unittest.TestCase):
    # ci8-1/UP-9: a real `-flto` build produces objects `nm` cannot read a
    # real symbol table from without the LTO plugin, surfacing as an
    # object whose only symbol is GCC's `__gnu_lto_slim` marker. Building a
    # genuine LTO-slim object here would tie this selftest to a specific
    # compiler/flag combination succeeding in whatever environment runs it
    # (docs-lint.yml has no build dependency) - mocking `subprocess.run`'s
    # `nm` output tests the DETECTION logic directly and portably, the same
    # boundary `object_symbols` itself draws (it doesn't care how the `nm`
    # output was produced, only what it says).
    def setUp(self) -> None:
        self.mod = _load_checker()

    def test_lto_slim_marker_only_raises_vacuous_pass_error(self) -> None:
        fake_proc = subprocess.CompletedProcess(
            args=["nm"], returncode=0, stdout="0000000000000000 t __gnu_lto_slim\n", stderr=""
        )
        with mock.patch.object(subprocess, "run", return_value=fake_proc):
            with self.assertRaises(self.mod.VacuousPassError) as ctx:
                self.mod.object_symbols("nm", Path("/fake/obj.cpp.o"), undefined_only=False)
        self.assertIn("LTO slim", str(ctx.exception))
        self.assertIn("gcc-nm", str(ctx.exception))

    def test_lto_slim_marker_alongside_real_symbols_does_not_raise(self) -> None:
        # The marker CAN legitimately appear alongside genuine symbols on
        # some toolchain versions - only a symbol set that is ENTIRELY the
        # marker (nothing else readable) is the unreadable-object signal.
        fake_proc = subprocess.CompletedProcess(
            args=["nm"],
            returncode=0,
            stdout=(
                "0000000000000000 t __gnu_lto_slim\n"
                "0000000000000010 T _Z7real_fnv\n"
            ),
            stderr="",
        )
        with mock.patch.object(subprocess, "run", return_value=fake_proc):
            syms = self.mod.object_symbols("nm", Path("/fake/obj.cpp.o"), undefined_only=False)
        self.assertIn("_Z7real_fnv", syms)

    def test_ordinary_symbols_do_not_raise(self) -> None:
        fake_proc = subprocess.CompletedProcess(
            args=["nm"], returncode=0, stdout="0000000000000000 T _Z7real_fnv\n", stderr=""
        )
        with mock.patch.object(subprocess, "run", return_value=fake_proc):
            syms = self.mod.object_symbols("nm", Path("/fake/obj.cpp.o"), undefined_only=False)
        self.assertEqual({"_Z7real_fnv"}, syms)


class TestFindObject(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_checker()
        self._tmp = tempfile.TemporaryDirectory(prefix="core_pres_link_selftest_")
        self.build_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_core_target_dir_missing_raises(self) -> None:
        # UP-10: find_object() looks ONLY inside CORE_TARGET_OBJ_DIR - if
        # that directory itself was never built, it must say so clearly
        # rather than reporting a generic "no compiled object" (which reads
        # as "you forgot the file", not "you forgot the whole build").
        with self.assertRaises(SystemExit) as ctx:
            self.mod.find_object(self.build_dir, "does_not_exist")
        self.assertIn("does not exist", str(ctx.exception))

    def test_missing_object_raises(self) -> None:
        (self.build_dir / self.mod.CORE_TARGET_OBJ_DIR).mkdir(parents=True)
        with self.assertRaises(SystemExit) as ctx:
            self.mod.find_object(self.build_dir, "does_not_exist")
        self.assertIn("no compiled object", str(ctx.exception))

    def test_duplicate_stem_outside_target_dir_is_ignored(self) -> None:
        # UP-10's whole point: restricting the lookup to ONE directory means
        # a same-named object compiled into some OTHER target's `.p`
        # directory (a future test binary that also compiles this source
        # file, say) can never be mistaken for the real one - a scenario
        # the OLD whole-tree `rglob` genuinely could not disambiguate.
        core_dir = self.build_dir / self.mod.CORE_TARGET_OBJ_DIR
        core_dir.mkdir(parents=True)
        (core_dir / "src_found_stem.cpp.o").write_bytes(b"real")
        other_dir = self.build_dir / "tests" / "some_other_target.p"
        other_dir.mkdir(parents=True)
        (other_dir / "src_found_stem.cpp.o").write_bytes(b"decoy")
        found = self.mod.find_object(self.build_dir, "found_stem")
        self.assertEqual(core_dir / "src_found_stem.cpp.o", found)
        self.assertEqual(b"real", found.read_bytes())

    def test_exact_match_found(self) -> None:
        core_dir = self.build_dir / self.mod.CORE_TARGET_OBJ_DIR
        core_dir.mkdir(parents=True)
        (core_dir / "src_found_stem.cpp.o").write_bytes(b"")
        found = self.mod.find_object(self.build_dir, "found_stem")
        self.assertEqual(core_dir / "src_found_stem.cpp.o", found)


if __name__ == "__main__":
    sys.exit(unittest.main())
