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

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECKER_PATH = REPO_ROOT / "scripts" / "ci" / "check_core_presentation_link.py"

# --- FROZEN CONSTANT (the lock). Editing check_core_presentation_link.py's
# --- FAMILIES to enrol/change a family must also edit this value in the
# --- same reviewed change - a loud, auditable path, not a silent narrowing
# --- or widening. Dict equality, so a re-ordered `core`/`presentation` list
# --- also trips it (`assertEqual` prints both sides).
EXPECTED_FAMILIES = {
    "dex": {
        "core": ["dex_api", "dex_read_model", "dex_types", "dex_window"],
        "presentation": ["dex_routes"],
    },
}


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_core_presentation_link", CHECKER_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _find_cxx() -> str:
    for candidate in (os.environ.get("CXX"), "c++", "g++", "clang++"):
        if candidate and shutil.which(candidate):
            return candidate
    raise unittest.SkipTest("no C++ compiler found on PATH")


def _find_nm() -> str:
    nm = shutil.which("nm")
    if not nm:
        raise unittest.SkipTest("no 'nm' found on PATH")
    return nm


def _compile_stem(cxx: str, build_dir: Path, stem: str, source: str) -> None:
    """Compile `source` (a tiny synthetic .cpp body) into build_dir/src_<stem>.cpp.o,
    matching the object naming this script's find_object() looks for."""
    src_path = build_dir / f"{stem}.cpp"
    src_path.write_text(source)
    obj_path = build_dir / f"src_{stem}.cpp.o"
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
        _compile_stem(
            self.cxx,
            self.build_dir,
            "clean_core",
            "void clean_core_fn() {}\n",
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


class TestFindObject(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_checker()
        self._tmp = tempfile.TemporaryDirectory(prefix="core_pres_link_selftest_")
        self.build_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_missing_object_raises(self) -> None:
        with self.assertRaises(SystemExit):
            self.mod.find_object(self.build_dir, "does_not_exist")

    def test_ambiguous_object_raises(self) -> None:
        # Two DIFFERENT subdirectories each containing an object matching the
        # same stem - find_object must refuse rather than silently pick one.
        (self.build_dir / "a").mkdir()
        (self.build_dir / "b").mkdir()
        (self.build_dir / "a" / "src_dup_stem.cpp.o").write_bytes(b"")
        (self.build_dir / "b" / "src_dup_stem.cpp.o").write_bytes(b"")
        with self.assertRaises(SystemExit):
            self.mod.find_object(self.build_dir, "dup_stem")

    def test_exact_match_found(self) -> None:
        (self.build_dir / "src_found_stem.cpp.o").write_bytes(b"")
        found = self.mod.find_object(self.build_dir, "found_stem")
        self.assertEqual(self.build_dir / "src_found_stem.cpp.o", found)


if __name__ == "__main__":
    sys.exit(unittest.main())
