#!/usr/bin/env python3
"""Self-test that locks scripts/ci/check-seam-closure.py against silent
neutering (WS-A4 item 1's per-family seam-enforcement scaffold, ADR-0031
migration step 3).

check-seam-closure.py's own FAMILIES/FORBIDDEN_HEADER_PATTERNS module-level
constants are the entire policy the gate enforces - a PR could quietly widen
the gate (drop a TU from the `network` family's list, narrow a forbidden
pattern so a real store header stops matching) with nothing else in the tree
noticing. This test pins those constants against frozen values HERE, in test
code, so changing the real policy means also editing this file in the same
reviewed change - a loud, auditable path, not a silent JSON/constant edit.
Mirrors tests/test_split_interlock_tripwire_selftest.py's shape for the
sibling WS-0 gate.

It also runs a POSITIVE-FIRE PROBE: builds a synthetic root/src/include tree
containing a TU that includes a real forbidden-pattern header, and asserts
the checker's own `check_family()` flags it (returns False) via the SAME
FORBIDDEN_HEADER_PATTERNS the shipped gate uses - proving the gate actually
fires on the policy it claims to enforce, not merely that it returns green on
the current tree (which a checker that always returns True would also do).
Each positive probe is paired with a negative control so a "fires" result is
evidence the gate DISCRIMINATES, not that it fails everything: probes 4/5 for
the store patterns, probe 6 for the angle-bracket internal-header escape, and
probes 7/8 for #4249's abstract-vs-local seam boundary (a presentation TU
reaching a core-only `*_api_local.hpp` must fire and name the chain; the
abstract `*_api.hpp` half it is meant to include must pass).

Not wired through subprocess against an alternate ledger file (unlike the
interlock selftest) because check-seam-closure.py's policy is in-module
constants, not an external file the CI job could point elsewhere; instead
this imports the checker module directly (`importlib.util.spec_from_file_
location`, matching scripts/ci/test_check_pg_shard_partition.py's own
established pattern for a hyphenated script) and calls its functions with
explicit `Roots` overrides, so the real repo tree is never touched by the probes.
The one exception is check 19, which temporarily swaps the module's three check
functions for recorders (restored in a `finally`) to observe how `run_check()`
consumes its lists - the module is a private instance, never put in `sys.modules`.

Wired into .github/workflows/docs-lint.yml alongside check-seam-closure.py
itself. Stdlib only.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECKER_PATH = REPO_ROOT / "scripts" / "ci" / "check-seam-closure.py"

# --- FROZEN CONSTANTS (the lock). Editing check-seam-closure.py's FAMILIES or
# --- FORBIDDEN_HEADER_PATTERNS to change any of these must also edit the
# --- matching value here - a loud, reviewed change, never a silent narrowing.
# --- The comparison is LIST EQUALITY, so it is ORDER-SENSITIVE by design: a
# --- pure re-order also trips it (both lists are printed side by side).
EXPECTED_FAMILIES = {
    "device": {
        "tus": [
            "server/core/src/device_routes.cpp",
            "server/core/src/device_ui.cpp",
            "server/core/src/device_api.hpp",
            "server/core/src/device_api_local.hpp",
            "server/core/src/device_lens_routes.cpp",
            "server/core/src/device_lens_routes.hpp",
        ],
    },
    "network": {
        "tus": [
            "server/core/src/network_routes.cpp",
            "server/core/src/network_ui.cpp",
            "server/core/src/network_perf_model.cpp",
            "server/core/src/discovered_devices_model.hpp",
            "server/core/src/discovered_devices_model.cpp",
            "server/core/src/network_api.hpp",
            "server/core/src/network_api_local.hpp",
        ],
    },
    "verify": {
        "tus": [
            "server/core/src/verify_routes.cpp",
            "server/core/src/verify_ui.cpp",
            "server/core/src/verify_api.hpp",
            "server/core/src/verify_api_local.hpp",
        ],
    },
    "compliance": {
        "tus": [
            "server/core/src/compliance_routes.cpp",
            "server/core/src/compliance_ui.cpp",
            "server/core/src/compliance_model.cpp",
            "server/core/src/compliance_api.hpp",
            "server/core/src/compliance_api_local.hpp",
        ],
    },
    "dex": {
        "tus": [
            "server/core/src/dex_types.hpp",
            "server/core/src/dex_read_model.hpp",
            "server/core/src/dex_api.hpp",
            "server/core/src/dex_api_local.hpp",
        ],
    },
    "dex_perf": {
        "tus": [
            "server/core/src/app_perf_types.hpp",
            "server/core/src/dex_app_perf_pure.hpp",
            "server/core/src/dex_perf_model.hpp",
            "server/core/src/dex_perf_api.hpp",
            "server/core/src/dex_perf_api_local.hpp",
            "server/core/src/dex_perf_ui.cpp",
            "server/core/src/dex_app_perf_ui.hpp",
            "server/core/src/dex_app_perf_ui.cpp",
        ],
    },
    "schedule": {
        "tus": [
            "server/core/src/schedule_types.hpp",
            "server/core/src/schedule_model.hpp",
            "server/core/src/schedule_model.cpp",
            "server/core/src/schedule_api.hpp",
            "server/core/src/schedule_api_local.hpp",
        ],
    },
    "workflow": {
        "tus": [
            "server/core/src/workflow_types.hpp",
            "server/core/src/workflow_model.hpp",
            "server/core/src/workflow_model.cpp",
            "server/core/src/workflow_execution_list_model.hpp",
            "server/core/src/workflow_execution_list_model.cpp",
            "server/core/src/list_keyset.hpp",
            "server/core/src/list_keyset.cpp",
            "server/core/src/workflow_api.hpp",
            "server/core/src/workflow_api_local.hpp",
        ],
    },
    "guardian": {
        "tus": [
            "server/core/src/guardian_types.hpp",
            "server/core/src/guardian_api.hpp",
            "server/core/src/guardian_api_local.hpp",
        ],
    },
    "crypto": {
        "tus": [
            "server/core/src/crypto_types.hpp",
            "server/core/src/crypto_library_model.hpp",
            "server/core/src/crypto_library_model.cpp",
            "server/core/src/crypto_widget_catalogue.hpp",
            "server/core/src/crypto_widget_catalogue.cpp",
            "server/core/src/crypto_api.hpp",
            "server/core/src/crypto_api_local.hpp",
            "server/core/src/crypto_routes.hpp",
            "server/core/src/crypto_routes.cpp",
            "server/core/src/crypto_ui.hpp",
            "server/core/src/crypto_ui.cpp",
        ],
    },
}
EXPECTED_FORBIDDEN_HEADER_PATTERNS = [
    "*_store.hpp",
    "agent_registry.hpp",
    "pg/*.hpp",
    # #4249's abstract-vs-local seam boundary. Pinned here for the same
    # reason as the three store patterns: the local header carries no store
    # includes of its own, so dropping this pattern would leave a
    # presentation TU free to reach the store-backed factory with a closure
    # the other three patterns read as perfectly clean - a silent, invisible
    # widening. Probe 7 below proves it actually fires.
    "*_api_local.hpp",
    # `schedule` (seventh family) / a future `workflow` seam, Fable review:
    # ScheduleEngine/WorkflowEngine are Postgres-backed stores named
    # `*_engine.hpp`, not `*_store.hpp` - see check-seam-closure.py's own
    # comment on this pair for the full rationale.
    "schedule_engine.hpp",
    "workflow_engine.hpp",
    # WS-A4 S0: Postgres-backed / store-fronting headers the `*_store.hpp` and
    # `pg/*.hpp` patterns are blind to - see check-seam-closure.py's own comment
    # for the rationale and for the in-memory engines deliberately NOT listed.
    "execution_tracker.hpp",
    "auth_db.hpp",
    "approval_manager.hpp",
    "directory_sync.hpp",
    "update_registry.hpp",
    "patch_manager.hpp",
    "deployment_engine.hpp",
    "nvd_db.hpp",
]
# WS-A4 S0: the new patterns, named separately so probe 17 can prove each one fires.
S0_NEW_HEADER_COUNT = 8   # execution_tracker .. nvd_db: asserted in check 2e, so a shrink is loud
S0_NEW_FORBIDDEN_HEADERS = EXPECTED_FORBIDDEN_HEADER_PATTERNS[-S0_NEW_HEADER_COUNT:]
# WS-A4 S0: store-definition-free presentation TUs - clean-by-gate, not by convention.
EXPECTED_STORE_DEFINITION_FREE_TUS = [
    "server/core/src/access_audit_ui.cpp",
    "server/core/src/access_tokens_ui.cpp",
    "server/core/src/access_ui.cpp",
    "server/core/src/approvals_ui.cpp",
    "server/core/src/developer_ui.cpp",
    "server/core/src/device_data_routes.cpp",
    "server/core/src/executions_ui.cpp",
    "server/core/src/groups_routes.cpp",
    "server/core/src/groups_ui.cpp",
    "server/core/src/guardian_page_ui.cpp",
    "server/core/src/guardian_ui.cpp",
    "server/core/src/help_ui.cpp",
    "server/core/src/home_ui.cpp",
    "server/core/src/instruction_ui.cpp",
    "server/core/src/integrations_routes.cpp",
    "server/core/src/integrations_ui.cpp",
    "server/core/src/kek_routes.cpp",
    "server/core/src/legacy_events_routes.cpp",
    "server/core/src/login_ui.cpp",
    "server/core/src/mcp_disabled_routes.cpp",
    "server/core/src/pki_routes.cpp",
    "server/core/src/preflight_ui.cpp",
    "server/core/src/settings_data_ui.cpp",
    "server/core/src/settings_general_ui.cpp",
    "server/core/src/settings_pki_ui.cpp",
    "server/core/src/settings_plugins_ui.cpp",
    "server/core/src/settings_security_ui.cpp",
    "server/core/src/settings_ui.cpp",
    "server/core/src/tar_page_ui.cpp",
    "server/core/src/tar_timeline_page_ui.cpp",
    "server/core/src/tar_tree_routes.cpp",
    "server/core/src/viz_host_page_ui.cpp",
    "server/core/src/viz_page_ui.cpp",
    "server/core/src/workflows_ui.cpp",
]
# TUs that were clean only under the pre-S0 patterns: must not be enrolled while their
# closure still reaches the header named (approval_manager/auth_db, directory_sync, nvd_db).
S0_DELIBERATELY_NOT_STORE_DEFINITION_FREE = [
    "server/core/src/approval_routes.cpp",
    "server/core/src/enrollment_directory_routes.cpp",
    "server/core/src/nvd_routes.cpp",
]
# --- Impl-purity rule constants (ADR-0031 WS-A4, Fable review). Pinned so a
# --- narrowing (dropping an impl TU, weakening the presentation-header set, or
# --- silently widening the httplib allowlist) is a loud, reviewed change.
EXPECTED_IMPL_FORBIDDEN_HEADER_PATTERNS = [
    "*_routes.hpp",
    "*_view_types.hpp",
    "*_ui.hpp",
]
EXPECTED_IMPL_TUS = [
    "server/core/src/network_api.cpp",
    "server/core/src/verify_api.cpp",
    "server/core/src/compliance_api.cpp",
    "server/core/src/device_api.cpp",
    "server/core/src/dex_api.cpp",
    "server/core/src/dex_perf_api.cpp",
    "server/core/src/schedule_api.cpp",
    "server/core/src/workflow_api.cpp",
    "server/core/src/dex_read_model.cpp",
    "server/core/src/dex_app_perf_model.cpp",
    "server/core/src/guardian_api.cpp",
    "server/core/src/guardian_model.cpp",
    "server/core/src/crypto_api.cpp",
]
EXPECTED_IMPL_HTTPLIB_ALLOWED = {"server/core/src/event_bus.hpp"}
# Abstract-header store-type probe (PR #4582 FIX 3).
EXPECTED_ABSTRACT_API_HEADERS = [
    "server/core/src/network_api.hpp",
    "server/core/src/verify_api.hpp",
    "server/core/src/compliance_api.hpp",
    "server/core/src/device_api.hpp",
    "server/core/src/dex_api.hpp",
    "server/core/src/dex_perf_api.hpp",
    "server/core/src/schedule_api.hpp",
    "server/core/src/workflow_api.hpp",
    "server/core/src/guardian_api.hpp",
    "server/core/src/crypto_api.hpp",
]
EXPECTED_EXTRA_STORE_TYPE_TOKENS = ["AppPerfDailyRow", "AppPerfFleetRow", "AuthDB",
                                    "AgentRegistry", "ExecutionTracker", "PgPool",
                                    "ScheduleEngine", "WorkflowEngine",
                                    "ApprovalManager", "DirectorySync", "UpdateRegistry",
                                    "PatchManager", "NvdDatabase"]
# WS-A4 S0: the five tokens added by S0 are the tail of the pin (derived, so probe 18 cannot drift).
S0_NEW_TOKEN_COUNT = 5   # ApprovalManager .. NvdDatabase: asserted in check 2e
S0_NEW_STORE_TYPE_TOKENS = EXPECTED_EXTRA_STORE_TYPE_TOKENS[-S0_NEW_TOKEN_COUNT:]
# Each S0 token must be DEFINED (not merely forward-declared or mentioned) in the one header
# that its paired forbidden pattern names.
S0_TOKEN_HOME_HEADER = {
    "ApprovalManager": "approval_manager.hpp", "DirectorySync": "directory_sync.hpp",
    "UpdateRegistry": "update_registry.hpp", "PatchManager": "patch_manager.hpp",
    "NvdDatabase": "nvd_db.hpp",
}


def _gnu_gxx():
    """A GNU g++ to use as the include oracle, or None. `g++` on macOS is Apple clang, whose
    preprocessor differs on the shapes this selftest pins (`udl_suffix_R_is_not_a_raw_string`), so
    the compiler must identify itself as GCC and not as clang."""
    gxx = shutil.which("g++")
    if not gxx:
        return None
    try:
        r = subprocess.run([gxx, "-dM", "-E", "-x", "c++", os.devnull], capture_output=True,
                           text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode == 0 and "#define __GNUC__" in r.stdout and "#define __clang__" not in r.stdout:
        return gxx
    return None


def _oracle_lists(gxx, tu, include_dir):
    """True/False: does the compiler's preprocessor list hid_store.hpp for `tu`? None when it
    exits non-zero (an unterminated comment, say) - then its dependency output is not evidence."""
    dep = subprocess.run([gxx, "-std=gnu++23", "-MM", "-MG", "-I", str(include_dir), str(tu)],
                         capture_output=True, text=True, errors="replace")
    if dep.returncode != 0:
        return None
    return "hid_store.hpp" in dep.stdout


def _diff(got, want) -> str:
    """added/removed between a module list and its frozen pin (the full lists run to ~35 paths)."""
    got, want = list(got), list(want)
    return (f"added={[x for x in got if x not in want]!r} "
            f"removed={[x for x in want if x not in got]!r} "
            f"(order-only difference if both are empty) - edit the matching EXPECTED_* constant "
            f"in this file in the same change")


def _fail(msg: str, failures: list) -> None:
    failures.append(msg)
    print(f"FAIL: {msg}", file=sys.stderr)


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_seam_closure", CHECKER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    if os.environ.get("YUZU_REQUIRE_TOOLCHAIN") == "1" and _gnu_gxx() is None:
        print("::error::seam closure self-test: YUZU_REQUIRE_TOOLCHAIN=1 but no GNU g++ is on PATH "
              "(Apple clang does not count) - the include-parser oracle cannot run", file=sys.stderr)
        return 1
    mod = _load_checker()
    failures: list[str] = []

    # 1. FAMILIES pinned - a dropped TU (e.g. quietly removing network_ui.cpp
    #    from the list) would silently shrink what the gate covers.
    if mod.FAMILIES != EXPECTED_FAMILIES:
        _fail(f"FAMILIES {mod.FAMILIES!r} != frozen {EXPECTED_FAMILIES!r}", failures)

    # 1b. The docstring's family count matches FAMILIES (#6056 review: it read
    #     "nine" with ten families). Both coverage sentences name the count.
    words = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven",
             8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen",
             14: "fourteen", 15: "fifteen"}
    want_word = words.get(len(mod.FAMILIES), str(len(mod.FAMILIES)))
    doc = mod.__doc__ or ""
    for phrase in (f"covers {want_word} families", f"checks {want_word} families"):
        if phrase not in doc:
            _fail(f"check-seam-closure.py docstring does not say {phrase!r} "
                  f"(len(FAMILIES) == {len(mod.FAMILIES)})", failures)
    for fam in mod.FAMILIES:
        if f"`{fam}`" not in doc:
            _fail(f"check-seam-closure.py docstring does not name family `{fam}`", failures)

    # 2. FORBIDDEN_HEADER_PATTERNS pinned - narrowing a pattern (or dropping
    #    one) would silently stop the gate blocking a real store-layer header.
    if mod.FORBIDDEN_HEADER_PATTERNS != EXPECTED_FORBIDDEN_HEADER_PATTERNS:
        _fail("FORBIDDEN_HEADER_PATTERNS differs from its frozen pin: "
              + _diff(mod.FORBIDDEN_HEADER_PATTERNS, EXPECTED_FORBIDDEN_HEADER_PATTERNS), failures)

    # 2b. Impl-purity constants pinned (ADR-0031 WS-A4). A dropped impl TU, a
    #     weakened presentation-header set, or a silently-widened httplib
    #     allowlist would let a core *_api.cpp re-acquire a presentation/httplib
    #     dependency with nothing else noticing.
    if mod.IMPL_FORBIDDEN_HEADER_PATTERNS != EXPECTED_IMPL_FORBIDDEN_HEADER_PATTERNS:
        _fail(f"IMPL_FORBIDDEN_HEADER_PATTERNS {mod.IMPL_FORBIDDEN_HEADER_PATTERNS!r} != "
              f"frozen {EXPECTED_IMPL_FORBIDDEN_HEADER_PATTERNS!r}", failures)
    if mod.IMPL_TUS != EXPECTED_IMPL_TUS:
        _fail("IMPL_TUS differs from its frozen pin: " + _diff(mod.IMPL_TUS, EXPECTED_IMPL_TUS),
              failures)
    if mod.IMPL_HTTPLIB_ALLOWED != EXPECTED_IMPL_HTTPLIB_ALLOWED:
        _fail(f"IMPL_HTTPLIB_ALLOWED {mod.IMPL_HTTPLIB_ALLOWED!r} != "
              f"frozen {EXPECTED_IMPL_HTTPLIB_ALLOWED!r}", failures)

    # 2c. Abstract-header store-type probe constants pinned (PR #4582 FIX 3).
    if mod.ABSTRACT_API_HEADERS != EXPECTED_ABSTRACT_API_HEADERS:
        _fail(f"ABSTRACT_API_HEADERS {mod.ABSTRACT_API_HEADERS!r} != "
              f"frozen {EXPECTED_ABSTRACT_API_HEADERS!r}", failures)
    if mod.EXTRA_STORE_TYPE_TOKENS != EXPECTED_EXTRA_STORE_TYPE_TOKENS:
        _fail(f"EXTRA_STORE_TYPE_TOKENS {mod.EXTRA_STORE_TYPE_TOKENS!r} != "
              f"frozen {EXPECTED_EXTRA_STORE_TYPE_TOKENS!r}", failures)

    # 2c2. The generated-header allowlist is pinned: widening it (e.g. to `.h`) would silently
    #      re-open the "unresolved include truncates the closure" hole (UP-4).
    if mod.GENERATED_HEADER_SUFFIXES != (".pb.h",):
        _fail(f"GENERATED_HEADER_SUFFIXES {mod.GENERATED_HEADER_SUFFIXES!r} != frozen ('.pb.h',)",
              failures)

    # 2d. WS-A4 S0: the store-definition-free presentation list is pinned, is disjoint from every
    #     FAMILIES set (a TU enforced twice is a silent ownership ambiguity), and never
    #     contains the two TUs that were clean only under the pre-S0 patterns.
    if mod.STORE_DEFINITION_FREE_TUS != EXPECTED_STORE_DEFINITION_FREE_TUS:
        _fail("STORE_DEFINITION_FREE_TUS differs from its frozen pin: "
              + _diff(mod.STORE_DEFINITION_FREE_TUS, EXPECTED_STORE_DEFINITION_FREE_TUS),
              failures)
    family_tus = {t for spec in mod.FAMILIES.values() for t in spec["tus"]}
    overlap = sorted(set(mod.STORE_DEFINITION_FREE_TUS) & family_tus)
    if overlap:
        _fail(f"STORE_DEFINITION_FREE_TUS overlaps a FAMILIES set: {overlap!r}. A TU whose "
              f"family seam has landed MOVES: remove it from STORE_DEFINITION_FREE_TUS and "
              f"EXPECTED_STORE_DEFINITION_FREE_TUS, then add it to FAMILIES and EXPECTED_FAMILIES",
              failures)
    for rel in S0_DELIBERATELY_NOT_STORE_DEFINITION_FREE:
        if rel in mod.STORE_DEFINITION_FREE_TUS:
            _fail(f"{rel} was clean only under the pre-S0 patterns and must not be in "
                  f"STORE_DEFINITION_FREE_TUS while its closure reaches a store-backed header",
                  failures)
    if len(set(mod.STORE_DEFINITION_FREE_TUS)) != len(mod.STORE_DEFINITION_FREE_TUS):
        _fail("STORE_DEFINITION_FREE_TUS contains a duplicate entry", failures)

    # 2e. The probe lists are DERIVED from the pins, never an independent copy (a
    #     probe list that can drift from the pin silently shrinks coverage), and every
    #     name the probes synthesise is a REAL header / type in the tree (probes 17/18
    #     only prove "a pattern with this spelling fires"; a spelling that matches no
    #     real file would pass them and protect nothing).
    # Literal endpoints, NOT the slice constants above (comparing a slice to the constant that
    # defines it is a tautology): the S0 tails must start and end where S0 put them.
    if (len(S0_NEW_FORBIDDEN_HEADERS), S0_NEW_FORBIDDEN_HEADERS[0], S0_NEW_FORBIDDEN_HEADERS[-1]) != \
            (8, "execution_tracker.hpp", "nvd_db.hpp") or \
            (len(S0_NEW_STORE_TYPE_TOKENS), S0_NEW_STORE_TYPE_TOKENS[0],
             S0_NEW_STORE_TYPE_TOKENS[-1]) != (5, "ApprovalManager", "NvdDatabase"):
        _fail("the S0 probe lists are not the 8 headers (execution_tracker .. nvd_db) / 5 tokens "
              "(ApprovalManager .. NvdDatabase) S0 added. The tails are POSITIONAL: if you "
              "legitimately added a pattern/token, edit S0_NEW_HEADER_COUNT / S0_NEW_TOKEN_COUNT "
              "and this literal endpoint check (and decide whether the new entry is an 'S0' one); "
              "otherwise a pin shrank", failures)
    if set(S0_TOKEN_HOME_HEADER) != set(S0_NEW_STORE_TYPE_TOKENS) or \
            not set(S0_TOKEN_HOME_HEADER.values()) <= set(S0_NEW_FORBIDDEN_HEADERS):
        _fail("S0_TOKEN_HOME_HEADER does not cover exactly the S0 tokens, each in an S0 header",
              failures)
    for hdr in S0_NEW_FORBIDDEN_HEADERS:
        real = list(mod.SERVER_SRC.rglob(hdr)) + list(mod.SERVER_INCLUDE.rglob(hdr))
        if not real:
            _fail(f"S0 forbidden header {hdr!r} names no real header under server/core - a "
                  f"misspelt pattern would pass probe 17 and protect nothing", failures)
    for tok, home in S0_TOKEN_HOME_HEADER.items():
        homes = list(mod.SERVER_SRC.rglob(home)) + list(mod.SERVER_INCLUDE.rglob(home))
        code = "\n".join(mod._strip_comments(h.read_text(encoding="utf-8", errors="replace"))
                         for h in homes)
        # A DEFINITION: `class|struct Tok [final] {` or `... : base {` - a `;`-terminated
        # forward declaration, `friend class Tok;`, `enum class Tok` and comments do not count.
        if not re.search(r"^\s*(?:class|struct)\s+" + re.escape(tok) + r"\b(?:\s+final)?\s*[{:]",
                         code, re.M):
            _fail(f"S0 store-type token {tok!r} is not DEFINED in {home}: a renamed class (stale "
                  f"forward declaration elsewhere) would make the token inert. Note the check is "
                  f"deliberately strict - a definition written with an attribute or macro between "
                  f"the keyword and the name (`class [[nodiscard]] X`, `class YUZU_API X`) also "
                  f"fails it; extend the regex in check 2e if you introduce that form", failures)

    # 3. Missing-family-member HARD ERROR: a declared TU that does not exist
    #    on disk must fail the family check, never be silently skipped.
    with tempfile.TemporaryDirectory() as td:
        root = Path(td).resolve()   # macOS: /var -> /private/var, else relative_to() breaks
        src = root / "server" / "core" / "src"
        inc = root / "server" / "core" / "include"
        common = root / "common" / "include"
        src.mkdir(parents=True)
        inc.mkdir(parents=True)
        common.mkdir(parents=True)
        roots = mod.Roots(root, src, inc, common)

        ok = mod.check_family("missing-probe",
                               ["server/core/src/does_not_exist.cpp"],
                               roots=roots)
        if ok:
            _fail("check_family did not fail on a declared-but-missing family TU", failures)

        # 4. POSITIVE-FIRE PROBE: a synthetic TU that includes a header
        #    matching a REAL shipped forbidden pattern (`*_store.hpp`) must be
        #    flagged, via the checker's own FORBIDDEN_HEADER_PATTERNS - proves
        #    the gate fires on its stated policy, not just that it stays green.
        (src / "evil_store.hpp").write_text("#pragma once\nclass EvilStore {};\n",
                                             encoding="utf-8")
        (src / "probe_routes.cpp").write_text('#include "evil_store.hpp"\nint main() {}\n',
                                               encoding="utf-8")
        ok = mod.check_family("positive-fire-probe",
                               ["server/core/src/probe_routes.cpp"],
                               roots=roots,
                               patterns=mod.FORBIDDEN_HEADER_PATTERNS)
        if ok:
            _fail("check_family did not fire on a synthetic TU including a "
                  "*_store.hpp header - the gate is inert", failures)

        # 5. Negative control: a synthetic TU including only a clean header
        #    (no forbidden pattern anywhere in its closure) must PASS - so the
        #    positive probe above is proof the gate discriminates, not that it
        #    fails everything indiscriminately.
        (src / "clean.hpp").write_text("#pragma once\nclass Clean {};\n", encoding="utf-8")
        (src / "clean_routes.cpp").write_text('#include "clean.hpp"\nint main() {}\n',
                                               encoding="utf-8")
        ok = mod.check_family("negative-control",
                               ["server/core/src/clean_routes.cpp"],
                               roots=roots,
                               patterns=mod.FORBIDDEN_HEADER_PATTERNS)
        if not ok:
            _fail("check_family flagged a synthetic TU with a clean closure "
                  "(false positive) - the gate over-fires", failures)

        # 6. Angle-bracket internal-header escape: a store header reachable
        #    ONLY via `<...>` against the internal include root (mirrors the
        #    real `<yuzu/server/scim_store.hpp>` shape the module docstring
        #    documents) must still be caught - proves the gate does not treat
        #    angle brackets as an automatic "not a store" signal.
        (inc / "hidden_store.hpp").write_text("#pragma once\nclass HiddenStore {};\n",
                                               encoding="utf-8")
        (src / "angle_routes.cpp").write_text("#include <hidden_store.hpp>\nint main() {}\n",
                                               encoding="utf-8")
        ok = mod.check_family("angle-bracket-probe",
                               ["server/core/src/angle_routes.cpp"],
                               roots=roots,
                               patterns=mod.FORBIDDEN_HEADER_PATTERNS)
        if ok:
            _fail("check_family did not follow an angle-bracket include into "
                  "the internal include root and catch its store header - "
                  "the angle-bracket escape is unguarded", failures)

        # 7. ABSTRACT-VS-LOCAL SEAM POSITIVE PROBE (#4249): a synthetic
        #    PRESENTATION TU that includes a core-only `*_api_local.hpp` must
        #    be flagged. The fake local header holds only a forward
        #    declaration and a factory signature - exactly the real
        #    `network_api_local.hpp` shape - so NONE of the three store
        #    patterns can see it; only `*_api_local.hpp` itself can. stderr is
        #    captured so this asserts the checker NAMES THE CHAIN, not merely
        #    that it returned False (`run_check()` maps any False family to
        #    exit code 1).
        (src / "fake_api_local.hpp").write_text(
            "#pragma once\n"
            "namespace detail { class FakeStore; }\n"
            "int make_local_fake_api(detail::FakeStore&);\n",
            encoding="utf-8")
        (src / "seam_probe_routes.cpp").write_text(
            '#include "fake_api_local.hpp"\nint main() {}\n', encoding="utf-8")
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            ok = mod.check_family("api-local-seam-probe",
                                   ["server/core/src/seam_probe_routes.cpp"],
                                   roots=roots,
                                   patterns=mod.FORBIDDEN_HEADER_PATTERNS)
        diag = captured.getvalue()
        if ok:
            _fail("check_family did not fire on a synthetic presentation TU "
                  "including a *_api_local.hpp header - the abstract-vs-local "
                  "seam boundary (#4249) is convention only, not enforced",
                  failures)
        elif "*_api_local.hpp" not in diag:
            _fail("check_family fired on the *_api_local.hpp probe but did "
                  f"not name the matched pattern; stderr was: {diag!r}", failures)
        elif ("server/core/src/seam_probe_routes.cpp -> "
              "server/core/src/fake_api_local.hpp") not in diag:
            _fail("check_family fired on the *_api_local.hpp probe but did "
                  f"not name the include chain; stderr was: {diag!r}", failures)

        # 8. Negative control for probe 7: the ABSTRACT half of the same seam
        #    (`fake_api.hpp`, no `_local`) is exactly what a presentation TU
        #    IS meant to include, and must PASS - proving the new pattern
        #    discriminates between the two halves rather than banning a
        #    family's in-process API header outright.
        (src / "fake_api.hpp").write_text(
            "#pragma once\nclass FakeApi { public: virtual ~FakeApi() = default; };\n",
            encoding="utf-8")
        (src / "seam_control_routes.cpp").write_text(
            '#include "fake_api.hpp"\nint main() {}\n', encoding="utf-8")
        ok = mod.check_family("api-abstract-negative-control",
                               ["server/core/src/seam_control_routes.cpp"],
                               roots=roots,
                               patterns=mod.FORBIDDEN_HEADER_PATTERNS)
        if not ok:
            _fail("check_family flagged a synthetic TU including only the "
                  "ABSTRACT fake_api.hpp - the *_api_local.hpp pattern is "
                  "over-firing onto the abstract half of the seam", failures)

        # 9. IMPL-PURITY POSITIVE PROBE (presentation header): a synthetic core
        #    `*_api.cpp` whose closure reaches a `*_routes.hpp` presentation
        #    header must be flagged by check_impl_purity - this is the exact
        #    dex_api.cpp -> dex_routes.hpp inversion the rule exists to catch.
        (src / "probe_routes.hpp").write_text("#pragma once\nint route();\n", encoding="utf-8")
        (src / "impl_probe_api.cpp").write_text(
            '#include "probe_routes.hpp"\nint main() {}\n', encoding="utf-8")
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            ok = mod.check_impl_purity(["server/core/src/impl_probe_api.cpp"], roots=roots)
        diag = captured.getvalue()
        if ok:
            _fail("check_impl_purity did not fire on a synthetic *_api.cpp reaching a "
                  "*_routes.hpp presentation header - the core->presentation inversion "
                  "rule is inert", failures)
        elif "*_routes.hpp" not in diag:
            _fail(f"check_impl_purity fired but did not name the presentation pattern; "
                  f"stderr was: {diag!r}", failures)

        # 10. IMPL-PURITY POSITIVE PROBE (direct httplib): a synthetic core
        #     `*_api.cpp` that directly includes <httplib.h> must be flagged (it
        #     is NOT event_bus.hpp, so the allowlist does not exempt it).
        (src / "impl_httplib_api.cpp").write_text(
            "#include <httplib.h>\nint main() {}\n", encoding="utf-8")
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            ok = mod.check_impl_purity(["server/core/src/impl_httplib_api.cpp"], roots=roots)
        if ok:
            _fail("check_impl_purity did not fire on a synthetic *_api.cpp that directly "
                  "includes <httplib.h> - the transport-layer ban is inert", failures)

        # 11. IMPL-PURITY NEGATIVE CONTROL (store is ALLOWED for an impl): a
        #     synthetic `*_api.cpp` reaching ONLY a `*_store.hpp` must PASS -
        #     the impl is the store-backed side of the seam, so this proves
        #     impl-purity discriminates (bans presentation, permits stores)
        #     rather than banning everything a family header rule bans.
        ok = mod.check_impl_purity(["server/core/src/probe_routes.cpp"], roots=roots)
        if not ok:
            _fail("check_impl_purity flagged a synthetic *_api.cpp reaching only a "
                  "*_store.hpp header - it must PERMIT stores (the impl is the "
                  "store-backed side of the seam)", failures)

        # 12. IMPL-PURITY ALLOWLIST CONTROL: a synthetic core header named
        #     event_bus.hpp that pulls <httplib.h>, reached by an *_api.cpp,
        #     must PASS - proving the documented pre-existing core-SSE exemption
        #     works (and only for that name; probe 10 proves any other httplib
        #     path still fires).
        (src / "event_bus.hpp").write_text("#pragma once\n#include <httplib.h>\n",
                                            encoding="utf-8")
        (src / "impl_eventbus_api.cpp").write_text(
            '#include "event_bus.hpp"\nint main() {}\n', encoding="utf-8")
        ok = mod.check_impl_purity(["server/core/src/impl_eventbus_api.cpp"], roots=roots)
        if not ok:
            _fail("check_impl_purity flagged a synthetic *_api.cpp reaching httplib ONLY "
                  "via the allowlisted event_bus.hpp - the documented core-SSE exemption "
                  "is not honoured", failures)

        # 13. ABSTRACT-HEADER STORE-TYPE POSITIVE PROBE (PR #4582 FIX 3): a
        #     synthetic abstract `*_api.hpp` whose closure includes a header that
        #     NAMES a store type (a forward-declared `class FooStore;` + a
        #     store-pointer signature) must fire — this is the exact class of bug
        #     dex_api.hpp shipped (it named GuaranteedStateStore via the bundled
        #     builders). The store-HEADER patterns can't see it: there is no
        #     `*_store.hpp` in the closure, only the NAME.
        # A forward-declared store class + a store-pointer signature, and NO
        # `*_store.hpp` in the closure — exactly the dex_api.hpp/PR #4582 shape.
        (src / "abs_model.hpp").write_text(
            "#pragma once\n"
            "namespace yuzu::server {\n"
            "class FooStore;\n"
            "int build_it(FooStore* s);\n"
            "}\n",
            encoding="utf-8")
        (src / "abs_probe_api.hpp").write_text(
            '#pragma once\n#include "abs_model.hpp"\n', encoding="utf-8")
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            ok = mod.check_abstract_headers_store_type_free(
                ["server/core/src/abs_probe_api.hpp"], roots=roots)
        diag = captured.getvalue()
        if ok:
            _fail("check_abstract_headers_store_type_free did not fire on a synthetic abstract "
                  "header whose closure forward-declares a `*Store` type - the store-type gap "
                  "(the dex_api.hpp/PR #4582 bug) is unguarded", failures)
        elif "FooStore" not in diag:
            _fail(f"abstract-header probe fired but did not name the store token; stderr: {diag!r}",
                  failures)

        # 14. ABSTRACT-HEADER EXTRA-TOKEN POSITIVE PROBE: a store ROW type that
        #     does NOT end in "Store" (the EXTRA_STORE_TYPE_TOKENS list, e.g.
        #     AppPerfDailyRow) named in code must also fire.
        (src / "abs_row_api.hpp").write_text(
            "#pragma once\n"
            "namespace yuzu::server {\n"
            "struct AppPerfDailyRow;\n"
            "int use_row(const AppPerfDailyRow& r);\n"
            "}\n",
            encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()):
            ok = mod.check_abstract_headers_store_type_free(
                ["server/core/src/abs_row_api.hpp"], roots=roots)
        if ok:
            _fail("check_abstract_headers_store_type_free did not fire on a synthetic abstract "
                  "header naming an EXTRA store-row token (AppPerfDailyRow)", failures)

        # 15. ABSTRACT-HEADER NEGATIVE CONTROL + COMMENT-STRIP: a header that
        #     mentions a store type ONLY in a comment (never in code) must PASS.
        #     This is load-bearing: the real dex_api.hpp banner names
        #     `GuaranteedStateStore` in prose, and MUST NOT false-fire. Proves the
        #     probe scans code, not comments, and discriminates (does not just
        #     fail everything).
        (src / "abs_clean_api.hpp").write_text(
            "#pragma once\n"
            "/// This seam names NO store type in code, though this doc comment\n"
            "/// mentions GuaranteedStateStore and AppPerfDailyRow by name.\n"
            "namespace yuzu::server { class CleanApi { public: virtual ~CleanApi() = default; }; }\n",
            encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()):
            ok = mod.check_abstract_headers_store_type_free(
                ["server/core/src/abs_clean_api.hpp"], roots=roots)
        if not ok:
            _fail("check_abstract_headers_store_type_free fired on a header that names store "
                  "types ONLY in comments - it is not comment-stripping, so the real dex_api.hpp "
                  "banner would false-fire (over-firing / not discriminating)", failures)

        # 16. STRING-LITERAL OVER-STRIP GUARD (#4582 Fable review): a store token
        #     in CODE that follows a string literal containing `//` on the SAME
        #     line must still FIRE. Before literals were blanked ahead of comment
        #     stripping, the `//` inside the literal was treated as a line comment
        #     and over-stripped the real store token after it - a silent bypass of
        #     the exact class this probe guards. Must fire and name the token.
        (src / "abs_litbypass_api.hpp").write_text(
            "#pragma once\n"
            "namespace yuzu::server {\n"
            'const char* kUrl = "http://h"; class BazStore;\n'
            "int build_baz(BazStore* s);\n"
            "}\n",
            encoding="utf-8")
        captured16 = io.StringIO()
        with contextlib.redirect_stderr(captured16):
            ok = mod.check_abstract_headers_store_type_free(
                ["server/core/src/abs_litbypass_api.hpp"], roots=roots)
        if ok:
            _fail("check_abstract_headers_store_type_free did not fire on a store token following "
                  "a `//`-bearing string literal - _strip_comments over-strips the literal as a "
                  "comment, reopening the store-type bypass (#4582)", failures)
        elif "BazStore" not in captured16.getvalue():
            _fail(f"literal-over-strip probe fired but did not name the token; stderr: "
                  f"{captured16.getvalue()!r}", failures)

        # 17. WS-A4 S0 POSITIVE PROBE, one per new pattern: a synthetic route TU that
        #     includes a header named exactly like each new forbidden header must be
        #     flagged with the REAL shipped pattern list. Proves every added entry is
        #     live (not a typo that matches nothing) - a dead pattern is the "gate
        #     quietly covers less than it claims" defect this checker exists to prevent.
        for hdr in S0_NEW_FORBIDDEN_HEADERS:
            stem = hdr[:-4]
            (src / hdr).write_text("#pragma once\nclass S0Probe {};\n", encoding="utf-8")
            (src / f"s0_{stem}_routes.cpp").write_text(f'#include "{hdr}"\nint main() {{}}\n',
                                                       encoding="utf-8")
            captured17 = io.StringIO()
            with contextlib.redirect_stderr(captured17):
                ok = mod.check_family(f"s0-probe-{stem}",
                                      [f"server/core/src/s0_{stem}_routes.cpp"],
                                      roots=roots, patterns=mod.FORBIDDEN_HEADER_PATTERNS)
            if ok:
                _fail(f"check_family did not fire on a synthetic TU including {hdr} - the "
                      f"WS-A4 S0 pattern is inert", failures)
            elif f"forbidden pattern '{hdr}'" not in captured17.getvalue():
                _fail(f"S0 probe for {hdr} fired but did not name it; stderr: "
                      f"{captured17.getvalue()!r}", failures)

        # 17b. The directory-qualified `pg/*.hpp` pattern fires through its path-qualified
        #      branch (a pre-existing gap found in the S0 review: nothing proved that branch
        #      live, so disabling it left both scripts green).
        (src / "pg").mkdir(exist_ok=True)
        (src / "pg" / "pool_probe.hpp").write_text("#pragma once\nclass PoolProbe {};\n",
                                                    encoding="utf-8")
        (src / "pg_probe_routes.cpp").write_text('#include "pg/pool_probe.hpp"\nint main() {}\n',
                                                 encoding="utf-8")
        captured17b = io.StringIO()
        with contextlib.redirect_stderr(captured17b):
            ok = mod.check_family("pg-probe", ["server/core/src/pg_probe_routes.cpp"],
                                  roots=roots, patterns=mod.FORBIDDEN_HEADER_PATTERNS)
        if ok or "forbidden pattern 'pg/*.hpp'" not in captured17b.getvalue():
            _fail("check_family did not fire on a TU including a pg/*.hpp header via the "
                  "'pg/*.hpp' pattern - the directory-qualified branch is inert", failures)

        # 18. WS-A4 S0 TOKEN PROBE: each new type-name token must fire in an abstract header,
        #     be NAMED by the message, and a longer identifier that merely starts with it
        #     (`<Tok>Foo`) must NOT fire (the trailing word boundary).
        for tok in S0_NEW_STORE_TYPE_TOKENS:
            (src / f"abs_s0_{tok}_api.hpp").write_text(
                f"#pragma once\nclass {tok};\nint use_it({tok}* p);\n", encoding="utf-8")
            captured18 = io.StringIO()
            with contextlib.redirect_stderr(captured18):
                ok = mod.check_abstract_headers_store_type_free(
                    [f"server/core/src/abs_s0_{tok}_api.hpp"], roots=roots)
            if ok or f"store type '{tok}'" not in captured18.getvalue():
                _fail(f"abstract-header probe did not fire / name the WS-A4 S0 token {tok!r}",
                      failures)
            (src / f"abs_s0_{tok}_neg_api.hpp").write_text(
                f"#pragma once\nclass {tok}Foo;\nint use_it({tok}Foo* p);\n", encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                ok = mod.check_abstract_headers_store_type_free(
                    [f"server/core/src/abs_s0_{tok}_neg_api.hpp"], roots=roots)
            if not ok:
                _fail(f"abstract-header probe over-fired on `{tok}Foo` - the token's word "
                      f"boundary is gone", failures)

        # 20. PARSER (UP-1, UP-3): every form below hides a real store include from a
        #     line-anchored regex unless handled, and is a real include to GCC/Clang -
        #     each form is re-checked against GNU `g++ -MM -MG` below when one is installed
        #     (and the CI step REQUIRES one). Every `fire` form must fire via check_family; every `hide` form
        #     (a comment, a splice into a comment, an unterminated comment) must NOT.
        (src / "hid_store.hpp").write_text("#pragma once\nclass HidStore {};\n", encoding="utf-8")
        parser_forms = {
            # name: (body, fires)
            "plain": ('#include "hid_store.hpp"\nint x;\n', True),
            "continuation": ('#include \\\n"hid_store.hpp"\nint x;\n', True),
            "continuation_crlf": ('#  include \\\r\n  "hid_store.hpp"\r\nint x;\r\n', True),
            "continuation_trailing_blank": ('#include \\ \n"hid_store.hpp"\nint x;\n', True),
            "continuation_in_name": ('#inc\\\nlude "hid_store.hpp"\nint x;\n', True),
            "same_line_block_comment": ('/* generated */ #include "hid_store.hpp"\nint x;\n', True),
            "block_comment_no_space": ('/**/#include "hid_store.hpp"\nint x;\n', True),
            "two_block_comments": ('/* a */ /* b */   #  include "hid_store.hpp"\nint x;\n', True),
            "multiline_comment_closing_before_hash": ('/* a\n b */ #include "hid_store.hpp"\nint x;\n', True),
            "comment_between_hash_and_include": ('# /* c */ include "hid_store.hpp"\nint x;\n', True),
            "comment_between_hash_and_include_tight": ('#/*c*/include "hid_store.hpp"\nint x;\n', True),
            "comment_between_include_and_name": ('#include /* c */ "hid_store.hpp"\nint x;\n', True),
            "comment_between_include_and_name_tight": ('#include/*c*/"hid_store.hpp"\nint x;\n', True),
            "include_next": ('#include_next "hid_store.hpp"\nint x;\n', True),
            "digraph": ('%:include "hid_store.hpp"\nint x;\n', True),
            "form_feed_prefix": ('\f#include "hid_store.hpp"\nint x;\n', True),
            "after_string_containing_comment_open": ('const char* s = "/* ";\n#include "hid_store.hpp"\nconst char* e = " */";\n', True),
            "after_string_containing_slashes": ('const char* u = "http://h";\n#include "hid_store.hpp"\n', True),
            "after_raw_string_containing_comment_open": ('const char* r = R"x(/* )x";\n#include "hid_store.hpp"\n', True),
            "after_char_literal_quote": ("char q = '\"';\n#include \"hid_store.hpp\"\n", True),
            "after_digit_separator": ("int n = 1'000'000; /* c\n*/\n#include \"hid_store.hpp\"\n", True),
            "after_escaped_quote_string": ('const char* s = "a\\"/*";\n#include "hid_store.hpp"\n', True),
            # Discriminating literal cases (a naive scanner passes the ones above by luck):
            "raw_string_with_inner_quote_and_comment_open": ('const char* r = R"x(a" /* b)x";\n#include "hid_store.hpp"\n', True),
            "u8_raw_string_with_inner_quote": ('const char* r = u8R"x(a" /* b)x";\n#include "hid_store.hpp"\n', True),
            "wide_raw_string_with_inner_quote": ('const wchar_t* r = LR"x(a" /* b)x";\n#include "hid_store.hpp"\n', True),
            "raw_string_custom_delim_with_paren": ('const char* r = R"d(a)" /* b)d";\n#include "hid_store.hpp"\n', True),
            # Shapes found by an independent randomized differential fuzz against g++ (round 6):
            "char_literal_after_return": ("char f() { return'/*'; }\n#include \"hid_store.hpp\"\n/* x */\n", True),
            "char_literal_after_L_prefix": ("auto c = L'/*';\n#include \"hid_store.hpp\"\n/* x */\n", True),
            "char_literal_after_u8_prefix": ("auto c = u8'/*';\n#include \"hid_store.hpp\"\n/* x */\n", True),
            "quote_after_digit_is_a_char_literal": ("int k = 1'/*';\n#include \"hid_store.hpp\"\n/* x */\n", True),
            "udl_suffix_R_is_not_a_raw_string": ('auto s = "a"R"(";\n#include/**/"hid_store.hpp"\n', True),
            "nul_byte_is_whitespace": ('\0#include "hid_store.hpp"\n', True),
            "nul_byte_inside_directive": ('#\0include "hid_store.hpp"\n', True),
            "form_feed_splice_before_comment": ('/\\\f\n/* x\n#include "hid_store.hpp"\n', True),
            "vertical_tab_splice": ('#include \\\v\n"hid_store.hpp"\n', True),
            "import_directive": ('#import "hid_store.hpp"\n', True),
            "digraph_import": ('%:import "hid_store.hpp"\n', True),
            # separators that must STILL be recognised (a comment opens after them and hides the include)
            "hex_digit_separator_then_comment_hides_include": ("int n = 0xAB'CD; /* hides\n#include \"hid_store.hpp\"\n*/ int z;\n", False),
            "float_digit_separator_then_comment_hides_include": ("double d = 1'000.5'5; /* hides\n#include \"hid_store.hpp\"\n*/ int z;\n", False),
            # a char literal whose body is alphanumeric must not be mistaken for a digit separator
            # (the swallowed `'; /* hides` would then un-hide the include): comment opens, include HIDDEN
            "alnum_char_literal_after_prefix_then_comment_hides_include": ("char16_t c = u'a'; /* hides\n#include \"hid_store.hpp\"\n*/ int z;\n", False),
            "alnum_char_literal_after_return_then_comment_hides_include": ("char f() { return'a'; } /* hides\n#include \"hid_store.hpp\"\n*/ int z;\n", False),
            # a hex separator chain whose later segment starts with a LETTER is still one pp-number
            "hex_separator_chain_then_comment_hides_include": ("int n = 0xAB'CD'EF; /* hides\n#include \"hid_store.hpp\"\n*/ int z;\n", False),
            # backslash-newline INSIDE a raw string is kept by the compiler (shape B of the fuzz)
            "raw_string_keeps_its_backslash_newline": ('const char* r = R"()\\\n"/*)";\n#include "hid_store.hpp"\n/* x */\n', True),
            # S0 review (round 7): the splice inside the raw-string OPENER, the leading-dot
            # pp-number separator, and `R` as the tail of an identifier / pp-number / UDL suffix.
            "spliced_raw_string_opener": ('R\\\n"()\\\n"/*)";\n#include "hid_store.hpp"\n', True),
            "leading_dot_digit_separator": ("double d = .5'0; int c = '/*';\n#include \"hid_store.hpp\"\n", True),
            "string_udl_suffix_LR_is_not_a_raw_string": ('auto s = "a"LR"(";\n#include/**/"hid_store.hpp"\n', True),
            "identifier_ending_LR_then_string_hides_include": ('int aLR = 0; const char* p = aLR"()x"; /* hides\n#include "hid_store.hpp"\n*/ int z;\n', False),
            "dollar_identifier_ending_R_then_string_hides_include": ('int $R = 0; const char* p = $R"()x"; /* hides\n#include "hid_store.hpp"\n*/ int z;\n', False),
            "pp_number_ending_LR_then_string_hides_include": ('auto n = 0LR"()x"; /* hides\n#include "hid_store.hpp"\n*/ int z;\n', False),
            # hide: NOT includes to the compiler
            "line_comment": ('// #include "hid_store.hpp"\nint x;\n', False),
            "line_comment_continued_over_include": ('// c \\\n#include "hid_store.hpp"\nint x;\n', False),
            "inside_multiline_block_comment": ('/*\n#include "hid_store.hpp"\n*/\nint x;\n', False),
            "inside_one_line_block_comment": ('/* #include "hid_store.hpp" */\nint x;\n', False),
            "after_code_same_line": ('int x; /* c */ #include "hid_store.hpp"\n', False),
            "multiline_comment_after_code": ('int x; /* a\n */ #include "hid_store.hpp"\n', False),
            "unterminated_comment_opens_before_include": ('/* #include "hid_store.hpp"\nint x;\n', False),
            # a REAL comment must open after a digit separator / escaped backslash, hiding the include
            "digit_separator_then_comment_hides_include": ("int n = 1'000; /* hides\n#include \"hid_store.hpp\"\n*/ int z;\n", False),
            "escaped_backslash_then_comment_hides_include": ('const char* s = "a\\\\"; /* hides\n#include "hid_store.hpp"\n*/ int z;\n', False),
            # U+2028 / VT are not line terminators to the compiler: no directive starts after them
            "unicode_line_separator_is_not_a_newline": ('int x;\u2028#include "hid_store.hpp"\n', False),
            "vertical_tab_mid_line_is_not_a_newline": ('int x;\x0b#include "hid_store.hpp"\n', False),
        }
        gxx = _gnu_gxx()   # oracle: GNU g++ only; the CI step sets YUZU_REQUIRE_TOOLCHAIN=1
        for form, (body, fires) in parser_forms.items():
            (src / f"hid_{form}_routes.cpp").write_text(body, encoding="utf-8", newline="")
            with contextlib.redirect_stderr(io.StringIO()):
                ok = mod.check_family(f"hid-{form}", [f"server/core/src/hid_{form}_routes.cpp"],
                                      roots=roots, patterns=mod.FORBIDDEN_HEADER_PATTERNS)
            if gxx:
                # The oracle: the real compiler's preprocessor must agree with the expectation.
                listed = _oracle_lists(gxx, src / f"hid_{form}_routes.cpp", src)
                if listed is not None and listed != fires:
                    _fail(f"the compiler ({gxx}) disagrees with this selftest's expectation for {form!r}: "
                          f"it {'lists' if listed else 'does not list'} hid_store.hpp "
                          f"but the probe expects fires={fires}", failures)
            if fires and ok:
                _fail(f"the include parser missed a real store include written as {form!r} - the "
                      f"closure walk is blind to it (UP-1/UP-3)", failures)
            if not fires and not ok:
                _fail(f"the include parser over-fired on {form!r}: a comment is not an include", failures)
        # 20b. S0 review round 7: a `//` or `/*` INSIDE an include's `<header-name>` is not a comment
        #      (the compiler lexes the header-name as one token), and the type-token lane must see
        #      the same raw-string-with-splice shape the include lane does. The directory `sub`
        #      lets `<sub//hid_store.hpp>` resolve on every platform; the `/*` spelling is judged
        #      on the parser's output directly because `*` cannot be a file name on Windows.
        (inc / "sub").mkdir()
        (inc / "sub" / "hid_store.hpp").write_text("#pragma once\nclass HidStore {};\n", encoding="utf-8")
        angle_forms = {
            "angle_double_slash": ("#include <sub//hid_store.hpp>\nint x;\n", True),
            "angle_double_slash_trailing_comment": ("#include <sub//hid_store.hpp> // c\n", True),
            "angle_after_closed_comment": ("/* a\n*/ # include <sub//hid_store.hpp>\n", True),
            "angle_spliced_inside_name": ("#include <su\\\nb//hid_store.hpp>\n", True),
            "angle_quote_inside_comment_hides": ("// #include <sub//hid_store.hpp>\nint x;\n", False),
        }
        for form, (body, fires) in angle_forms.items():
            tu = src / f"{form}_routes.cpp"
            tu.write_text(body, encoding="utf-8", newline="")
            with contextlib.redirect_stderr(io.StringIO()):
                ok = mod.check_family(f"hid-{form}", [f"server/core/src/{form}_routes.cpp"],
                                      roots=roots, patterns=mod.FORBIDDEN_HEADER_PATTERNS)
            if fires and ok:
                _fail(f"the include parser missed `{body.strip()!r}`: a `//` inside <header-name> is "
                      f"not a comment", failures)
            if not fires and not ok:
                _fail(f"the include parser over-fired on {form!r}", failures)
            if gxx:
                listed = _oracle_lists(gxx, tu, inc)
                if listed is not None and listed != fires:
                    _fail(f"the compiler disagrees with the expectation for {form!r} "
                          f"(lists={listed}, expected fires={fires})", failures)
        tu = src / "angle_block_comment_routes.cpp"
        tu.write_text("#include <a/*b*/c.hpp>\nint x;\n", encoding="utf-8")
        if mod.parse_includes(tu) != [(True, "a/*b*/c.hpp")]:
            _fail(f"parse_includes mangled `#include <a/*b*/c.hpp>`: {mod.parse_includes(tu)!r} - a "
                  f"`/*` inside <header-name> is not a comment", failures)
        for form, body, want in (
                ("raw_splice_opener_type_token", 'R\\\n"()\\\n"/*)";\nclass HiddenStore;\n', "HiddenStore"),
                ("raw_splice_content_type_token", 'const char* r = R"()\\\n"/*)";\nclass HiddenStore;\n', "HiddenStore"),
                ("leading_dot_separator_type_token", "double d = .5'0; int c = '/*';\nclass HiddenStore;\n", "HiddenStore"),
                ("comment_hides_type_token", "/* class HiddenStore; */\nint x;\n", None)):
            tu = src / f"{form}.hpp"
            tu.write_text(body, encoding="utf-8")
            if mod.names_store_type(tu) != want:
                _fail(f"names_store_type({form}) -> {mod.names_store_type(tu)!r}, want {want!r}: the "
                      f"type-token lane must lex the shape the include lane does", failures)

        # 20c. The SPLICE-JOINED lex alone must be right: `parse_includes` also unions an unjoined
        #      lex for files with a raw-string opener, which would mask a broken offset mapping
        #      between the original and the joined text, so assert on `strip_comments` directly.
        # An earlier `)"` inside the window a WRONG offset mapping would search closes the raw string
        # early; vary the padding so some pad puts it in range.
        shifted = tuple((f"shifted_{nsplice}_{pad}",
                         '\\\n' * nsplice + ' ' * pad + '")";R"()\\\n"/*)";\n#include "hid_store.hpp"\n')
                        for nsplice in range(1, 7) for pad in range(0, 4))
        for form, body in shifted + (
                ("opener", 'R\\\n"()\\\n"/*)";\n#include "hid_store.hpp"\n'),
                ("content", 'const char* r = R"()\\\n"/*)";\n#include "hid_store.hpp"\n'),
                ("splice_before_literal", '\\\n\\\nconst char* r = R"()\\\n"/*)";\n#include "hid_store.hpp"\n'),
                ("two_raw_strings", 'auto a = R"x(\\\n)x"; auto b = R"()\\\n"/*)";\n#include "hid_store.hpp"\n')):
            for blank in (False, True):
                want_ = '#include ""' if blank else '#include "hid_store.hpp"'   # blanking empties the literal
                if want_ not in mod.strip_comments(body, blank_strings=blank):
                    _fail(f"strip_comments({form!r}, blank_strings={blank}) lost the include after a "
                          f"raw string holding a backslash-newline - the splice offset mapping is wrong",
                          failures)
        # BOM / UTF-16 (bytes written explicitly: Windows editors and MSVC produce both).
        for form, raw in (("bom", b'\xef\xbb\xbf#include "hid_store.hpp"\nint x;\n'),
                          ("utf16_le", b'\xff\xfe' + '#include "hid_store.hpp"\nint x;\n'.encode("utf-16-le")),
                          ("utf16_be", b'\xfe\xff' + '#include "hid_store.hpp"\nint x;\n'.encode("utf-16-be"))):
            (src / f"hid_{form}_routes.cpp").write_bytes(raw)
            with contextlib.redirect_stderr(io.StringIO()):
                ok = mod.check_family(f"hid-{form}", [f"server/core/src/hid_{form}_routes.cpp"],
                                      roots=roots, patterns=mod.FORBIDDEN_HEADER_PATTERNS)
            if ok:
                _fail(f"the include parser missed a store include in a {form} file (UP-1/UP-4)", failures)
        # Parser return values, not just check_family outcomes: (is_angle, name) pairs.
        (src / "ret_routes.cpp").write_text('#include <a.h>\n#include "b.h"\n#include_next <c.h>\n',
                                            encoding="utf-8")
        if mod.parse_includes(src / "ret_routes.cpp") != [(True, "a.h"), (False, "b.h"), (True, "c.h")]:
            _fail("parse_includes did not return (is_angle, name) pairs in file order", failures)

        # 21. UNRESOLVED QUOTE INCLUDE (UP-4): hard error on EVERY lane; a generated *.pb.h is
        #     the one allowed exception; an unresolved ANGLE include (external header) is fine.
        (src / "unres_routes.cpp").write_text('#include "no_such_header.hpp"\nint x;\n',
                                              encoding="utf-8")
        (src / "unres_api.cpp").write_text('#include "no_such_header.hpp"\nint x;\n', encoding="utf-8")
        (src / "unres_api.hpp").write_text('#pragma once\n#include "no_such_header.hpp"\n',
                                           encoding="utf-8")
        lanes = (
            ("family", lambda: mod.check_family("unres", ["server/core/src/unres_routes.cpp"],
                                                roots=roots)),
            ("impl-purity", lambda: mod.check_impl_purity(["server/core/src/unres_api.cpp"],
                                                          roots=roots)),
            ("abstract-header", lambda: mod.check_abstract_headers_store_type_free(
                ["server/core/src/unres_api.hpp"], roots=roots)),
        )
        for lane, fn in lanes:
            cap = io.StringIO()
            with contextlib.redirect_stderr(cap):
                ok = fn()
            if ok or "could not resolve quote-include" not in cap.getvalue():
                _fail(f"an unresolved quote include did not hard-fail the {lane} lane - its "
                      f"closure would be silently truncated (UP-4)", failures)
        # The allowlist matches only the SUFFIX of a quote include: these must still hard-fail.
        for nm in ("x.pb.hpp", "pbkdf_store.hpp", "x.pb.h.hpp", "pb.h/x.hpp"):
            (src / "sfx_routes.cpp").write_text(f'#include "{nm}"\n', encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                ok = mod.check_family("sfx", ["server/core/src/sfx_routes.cpp"], roots=roots)
            if ok:
                _fail(f"an unresolved quote include {nm!r} passed - the generated-header allowlist "
                      f"must match only a true *.pb.h suffix", failures)
        # One shared header reached by several TUs reports ONCE (not once per TU).
        (src / "shared_bad.hpp").write_text('#pragma once\n#include "no_such_shared.hpp"\n', encoding="utf-8")
        for k in range(3):
            (src / f"fan{k}_routes.cpp").write_text('#include "shared_bad.hpp"\n', encoding="utf-8")
        cap_fan = io.StringIO()
        with contextlib.redirect_stderr(cap_fan):
            mod.check_family("fan", [f"server/core/src/fan{k}_routes.cpp" for k in range(3)], roots=roots)
        if cap_fan.getvalue().count("could not resolve quote-include") != 1:
            _fail("the same unresolved include reached by 3 TUs was not reported exactly once "
                  f"(got {cap_fan.getvalue().count('could not resolve quote-include')})", failures)
        # extra_include roots mirror the build's -I directories: a quote include that resolves
        # ONLY there is resolved (not an error), and angle includes resolve there too.
        extra_dir = root / "sdk" / "include" / "yuzu"
        extra_dir.mkdir(parents=True)
        (extra_dir / "metrics.hpp").write_text("#pragma once\n", encoding="utf-8")
        (src / "extra_routes.cpp").write_text('#include "yuzu/metrics.hpp"\n#include <yuzu/metrics.hpp>\n',
                                              encoding="utf-8")
        # an ANGLE include that resolves only in an extra root must be WALKED (its own includes
        # reach a store here), not silently dropped.
        (extra_dir / "metrics2.hpp").write_text('#pragma once\n#include "evil_store.hpp"\n', encoding="utf-8")
        (src / "angwalk_routes.cpp").write_text("#include <yuzu/metrics2.hpp>\n", encoding="utf-8")
        roots_extra = mod.Roots(root, src, inc, common, (root / "sdk" / "include",))
        with contextlib.redirect_stderr(io.StringIO()):
            ok_ang = mod.check_family("angwalk", ["server/core/src/angwalk_routes.cpp"], roots=roots_extra,
                                      patterns=mod.FORBIDDEN_HEADER_PATTERNS)
        if ok_ang:
            _fail("an angle include resolving only via Roots.extra_include was not walked", failures)
        with contextlib.redirect_stderr(io.StringIO()):
            ok_extra = mod.check_family("extra", ["server/core/src/extra_routes.cpp"], roots=roots_extra)
        with contextlib.redirect_stderr(io.StringIO()):
            ok_noextra = mod.check_family("noextra", ["server/core/src/extra_routes.cpp"], roots=roots)
        if not ok_extra or ok_noextra:
            _fail("Roots.extra_include is not consulted for quote/angle resolution (or an include that "
                  "resolves only there is treated as unresolved)", failures)
        (src / "gen_routes.cpp").write_text('#include "agent.grpc.pb.h"\n#include <external/x.h>\n',
                                            encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()):
            ok = mod.check_family("gen", ["server/core/src/gen_routes.cpp"], roots=roots)
        if not ok:
            _fail("a generated *.pb.h (or an unresolved ANGLE include) hard-failed - the "
                  "allowlist/angle exemption is gone", failures)


        # ===== QE gate-8 round-6 KILL FIXTURES =====
        INC_ = b'#include "hid_store.hpp"\n'
        qe_forms = {
            # name: (bytes, fires)
            "qe_empty_line_comment_then_include": (b'//\n' + INC_, True),
            "qe_slash_star_slash_hides": (b'/*/\n' + INC_ + b'*/\nint z;\n', False),
            "qe_block_then_stray_star_slash": (b'/*a*/*/\n' + INC_, True),
            "qe_adjacent_block_comments": (b'/* a *//* b */' + INC_, True),
            "qe_unterminated_comment_include_on_next_line": (b'/* x\n' + INC_, False),
            "qe_slash_before_charlit_hides": (b"int c = n/'\"'; /* open\n" + INC_ + b"*/ int z;\n", False),
            "qe_empty_string_then_comment_hides": (b'const char* e = ""; /* open\n' + INC_ + b'*/ int z;\n', False),
            "qe_uR_raw": (b'const char16_t* r = uR"x(a" /* b)x";\n' + INC_, True),
            "qe_UR_raw": (b'const char32_t* r = UR"x(a" /* b)x";\n' + INC_, True),
            "qe_raw_delim16": (b'const char* r = R"0123456789abcdef(a" /* b)0123456789abcdef";\n' + INC_, True),
            "qe_raw_at_file_start": (b'R"x(a" /* b)x"\n' + INC_ + b'int z', True),
            "qe_ident_R_then_string_hides": (b'const char* s = FOOR"x(a"; /* open\n' + INC_ + b'*/ int z;\n', False),
            "qe_char_at_file_start": (b"'a /* c\n" + INC_ + b"*/ x", True),
            "qe_utf8_ident_digit_separator_hides": ("int n = 1\u00e9'0; /* hides\n".encode() + INC_ + b"*/ int z;\n", False),
            "qe_string_at_file_start_hides": (b'"x(" /* hides\n' + INC_ + b'*/ R', False),
            "qe_unterminated_str_in_if0_then_comment_hides": (b'#if 0\nsay "hi\n#endif\n/* open\n' + INC_ + b'*/\n', False),
            "qe_unterminated_chr_in_if0_then_comment_hides": (b"#if 0\nsay 'hi\n#endif\n/* open\n" + INC_ + b"*/\n", False),
            "qe_chr_escaped_quote_hides": (b"char q = '\\''; /* hides\n" + INC_ + b"*/ int z;\n", False),
            "qe_chr_escaped_backslash_hides": (b"char q = '\\\\'; /* hides\n" + INC_ + b"*/ int z;\n", False),
            "qe_hex_digit_separator_hides": (b"int n = 0xFF'FF; /* hides\n" + INC_ + b"*/ int z;\n", False),
            "qe_underscore_digit_separator_hides": (b"int n = 1_'0; /* hides\n" + INC_ + b"*/ int z;\n", False),
            "qe_tab_trailing_continuation": (b'#include \\\t\n"hid_store.hpp"\n', True),
            "qe_lone_cr_newline": (b'int x;\r' + INC_, True),
            "qe_lone_cr_after_comment": (b'// c\r' + INC_, True),
            "qe_utf16le_lone_cr": (b'\xff\xfe' + ('int x;\r' + INC_.decode()).encode('utf-16-le'), True),
            "qe_latin1_byte_in_comment": (b'// caf\xe9\n' + INC_, True),
            "qe_utf16_odd_tail": (b'\xff\xfe' + INC_.decode().encode('utf-16-le') + b'\x00', True),
            "qe_utf16_lone_surrogate": (b'\xff\xfe' + INC_.decode().encode('utf-16-le') + b'\x00\xd8', True),
            "qe_include_then_eof_comment_no_newline": (b'#include "hid_store.hpp" // c', True),
            "qe_ws_tab_before_hash": (b'\t' + INC_, True),
            "qe_ws_vt_before_hash": (b'\x0b' + INC_, True),
            "qe_ws_tab_hash_include": (b'#\tinclude "hid_store.hpp"\n', True),
            "qe_ws_vt_hash_include": (b'#\x0binclude "hid_store.hpp"\n', True),
            "qe_ws_ff_hash_include": (b'#\x0cinclude "hid_store.hpp"\n', True),
            "qe_ws_tab_include_name": (b'#include\t"hid_store.hpp"\n', True),
            "qe_ws_vt_include_name": (b'#include\x0b"hid_store.hpp"\n', True),
            "qe_ws_ff_include_name": (b'#include\x0c"hid_store.hpp"\n', True),
        }
        for form, (raw_, fires_) in qe_forms.items():
            (src / f"{form}_routes.cpp").write_bytes(raw_)
            # GCC does not decode UTF-16 source (MSVC does); the checker does, deliberately, so the
            # UTF-16 forms are the only ones the GCC oracle cannot judge.
            if gxx and "utf16" not in form:
                listed_ = _oracle_lists(gxx, src / f"{form}_routes.cpp", src)
                if listed_ is not None and listed_ != fires_:
                    _fail(f"QE: the compiler disagrees with the expectation for {form!r} "
                          f"(g++ {'lists' if listed_ else 'does not list'} it, "
                          f"expected fires={fires_})", failures)
            with contextlib.redirect_stderr(io.StringIO()):
                ok_ = mod.check_family(f"qe-{form}", [f"server/core/src/{form}_routes.cpp"],
                                       roots=roots, patterns=mod.FORBIDDEN_HEADER_PATTERNS)
            if fires_ and ok_:
                _fail(f"QE: parser missed {form!r}", failures)
            if not fires_ and not ok_:
                _fail(f"QE: parser over-fired on {form!r}", failures)
        # return-value controls: blank-mode newline/EOF behaviour, CRLF handed straight in, raw EOF
        for text_, want_ in (("char c = 'a\nint x;", "char c = ''\nint x;"),
                             ('s = "abc\nint x;', 's = ""\nint x;'),
                             ('s = "abc', 's = ""'), ("c = 'a", "c = ''"),
                             ("int a; // c", "int a;  "),
                             ("#define X \\\r\n 1", "#define X  1"),
                             ('R"x(a\n/* c\nint z;', 'R""')):
            if mod._strip_comments(text_) != want_:
                _fail(f"QE: _strip_comments({text_!r}) -> {mod._strip_comments(text_)!r}, want {want_!r}", failures)
        # resolution-order / reach controls
        (src / "sub").mkdir(exist_ok=True)
        (src / "sub" / "dup.hpp").write_text("#pragma once\n", encoding="utf-8")
        (inc / "dup.hpp").write_text('#pragma once\n#include "evil_store.hpp"\n', encoding="utf-8")
        (src / "sub" / "sibling_user.hpp").write_text('#pragma once\n#include "dup.hpp"\n', encoding="utf-8")
        (src / "res_order_routes.cpp").write_text('#include "sub/sibling_user.hpp"\n', encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()):
            ok_ = mod.check_family("qe-order", ["server/core/src/res_order_routes.cpp"], roots=roots,
                                   patterns=mod.FORBIDDEN_HEADER_PATTERNS)
        if not ok_:
            _fail("QE: includer-directory-first resolution lost (sibling dup.hpp shadowed by include root)", failures)
        (src / "sub" / "clean_peer.hpp").write_text("#pragma once\n", encoding="utf-8")
        (src / "sub" / "uses_peer.hpp").write_text('#pragma once\n#include "clean_peer.hpp"\n', encoding="utf-8")
        (src / "sub" / "uses_src_rel.hpp").write_text('#pragma once\n#include "evil_store.hpp"\n', encoding="utf-8")
        (src / "sibling_routes.cpp").write_text('#include "sub/uses_peer.hpp"\n', encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()):
            ok_ = mod.check_family("qe-sib", ["server/core/src/sibling_routes.cpp"], roots=roots)
        if not ok_:
            _fail("QE: a sibling include (same directory as the includer) hard-failed", failures)
        (src / "srcrel_routes.cpp").write_text('#include "sub/clean_peer.hpp"\n', encoding="utf-8")
        (src / "sub" / "uses_srcrel.hpp").write_text('#pragma once\n#include "sub/clean_peer.hpp"\n', encoding="utf-8")
        (src / "srcrel2_routes.cpp").write_text('#include "sub/uses_srcrel.hpp"\n', encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()):
            ok_ = mod.check_family("qe-srcrel", ["server/core/src/srcrel2_routes.cpp"], roots=roots)
        if not ok_:
            _fail("QE: a src-relative quote include (resolved only via server_src) hard-failed", failures)
        (common / "cm_store.hpp").write_text("#pragma once\n", encoding="utf-8")
        (src / "angle_common_routes.cpp").write_text("#include <cm_store.hpp>\n", encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()):
            ok_ = mod.check_family("qe-angcommon", ["server/core/src/angle_common_routes.cpp"], roots=roots,
                                   patterns=mod.FORBIDDEN_HEADER_PATTERNS)
        if ok_:
            _fail("QE: an angle include resolving only in common/include was not walked", failures)
        # unresolved-error content and dedupe granularity
        (src / "bad1.hpp").write_text('#pragma once\n#include "nosuch_a.hpp"\n#include "nosuch_b.hpp"\n', encoding="utf-8")
        (src / "bad2.hpp").write_text('#pragma once\n#include "nosuch_a.hpp"\n', encoding="utf-8")
        (src / "dd_routes.cpp").write_text('#include "bad1.hpp"\n#include "bad2.hpp"\n', encoding="utf-8")
        cap_ = io.StringIO()
        with contextlib.redirect_stderr(cap_):
            mod.check_family("qe-dd", ["server/core/src/dd_routes.cpp"], roots=roots)
        if cap_.getvalue().count("could not resolve quote-include") != 3:
            _fail("QE: expected 3 distinct (includer,spelling) unresolved errors, got "
                  f"{cap_.getvalue().count('could not resolve quote-include')}", failures)
        if '"nosuch_a.hpp"' not in cap_.getvalue() or "server/core/src/bad1.hpp" not in cap_.getvalue().replace("\\", "/"):
            _fail("QE: the unresolved-include error no longer names the spelling and the includer", failures)
        seen_ = set()
        with contextlib.redirect_stderr(io.StringIO()):
            r1_ = mod.report_unresolved("l", "t", [(src / "bad2.hpp", "nosuch_a.hpp")], roots, seen_)
            r2_ = mod.report_unresolved("l", "t", [(src / "bad2.hpp", "nosuch_a.hpp")], roots, seen_)
        if r1_ or r2_:
            _fail("QE: report_unresolved must return False for a repeated (deduped) unresolved include too", failures)
        for lane_, fn_ in (("impl-purity", lambda: mod.check_impl_purity(
                                [f"server/core/src/dfan{k}_api.cpp" for k in range(3)], roots=roots)),
                           ("abstract-header", lambda: mod.check_abstract_headers_store_type_free(
                                [f"server/core/src/dfan{k}_api.hpp" for k in range(3)], roots=roots))):
            ext_ = "cpp" if lane_ == "impl-purity" else "hpp"
            for k in range(3):
                (src / f"dfan{k}_api.{ext_}").write_text('#pragma once\n#include "bad2.hpp"\n', encoding="utf-8")
            cap2_ = io.StringIO()
            with contextlib.redirect_stderr(cap2_):
                fn_()
            if cap2_.getvalue().count("could not resolve quote-include") != 1:
                _fail(f"QE: {lane_} lane did not dedupe a shared unresolved include "
                      f"(got {cap2_.getvalue().count('could not resolve quote-include')})", failures)
        # ===== end QE kill fixtures =====

        # 22. PARSER + COMMENT-STRIPPER COST. The gate runs in CI over repo files: a pathological
        #     header must never hang it. Earlier drafts were superlinear in two places: a nested
        #     quantifier in the include regex (hung >120 s on 20000 closed comments) and
        #     `_strip_comments`' `"(?:\\.|[^"\\\n])*"` / `/\*.*?\*/` (5.7 s at 64 KB, 30 s at 240 KB).
        #     `re` holds the GIL while backtracking, so a thread cannot be timed out - run the
        #     work in a SUBPROCESS with a hard timeout, so a regression FAILS instead of wedging CI.
        pathological = {
            "closed_comments": "/* x */ " * 20000 + "int x;\n",
            "unterminated_comment_starts": "/* " * 100000 + "\n",
            "escaped_quotes": '"\\"' * 100000 + "\n",
            "string_openers": '"' * 200000 + "\n",
            "line_continuations": "\\\n" * 200000 + "int x;\n",
            "comment_then_include": "/* x */ " * 20000 + '#include "a.hpp"\n',
            "raw_openers": 'LR"' * 100000 + "\n",  # every LR" is a valid opener; the delimiter cap bounds each scan
        }
        probe_code = (
            "import importlib.util, pathlib, sys\n"
            "spec = importlib.util.spec_from_file_location('c', sys.argv[1])\n"
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
            "f = pathlib.Path(sys.argv[2])\n"
            "print(len(m.parse_includes(f)), len(m._strip_comments(f.read_text())))\n")
        for label, body in pathological.items():
            (src / "slow_input.cpp").write_text(body, encoding="utf-8")
            try:
                done = subprocess.run([sys.executable, "-B", "-I", "-c", probe_code, str(CHECKER_PATH),
                                       str(src / "slow_input.cpp")], capture_output=True, text=True,
                                      timeout=20)
                want_inc = "1" if label == "comment_then_include" else "0"
                if done.returncode != 0 or done.stdout.split()[:1] != [want_inc]:
                    _fail(f"pathological input {label!r}: rc={done.returncode} out={done.stdout.strip()!r} "
                          f"err={done.stderr.strip()[:200]!r} (expected {want_inc} includes)", failures)
            except subprocess.TimeoutExpired:
                _fail(f"pathological input {label!r} did not finish within 20 s - a comment/include "
                      f"regex is superlinear again (ReDoS) and would hang CI", failures)
        # return-value controls for the comment stripper (what the type-token probe reads)
        for text, want in (('const char* u = "http://h"; class FooStore;', 'const char* u = ""; class FooStore;'),
                           ("int a; // class HidStore;\nint b;", "int a;  \nint b;"),
                           ("int a; /* class HidStore; */ int b;", "int a;   int b;"),
                           ("char c = '\"'; class FooStore;", "char c = ''; class FooStore;"),
                           ('const char* r = R"x(/* class HidStore; )x"; int z;', 'const char* r = R""; int z;'),
                           ('const char* r = R"x(a" /* b)x"; class FooStore;', 'const char* r = R""; class FooStore;'),
                           ("int n = 1'000; /* gone */ class FooStore;", "int n = 1'000;   class FooStore;")):
            if mod._strip_comments(text) != want:
                _fail(f"_strip_comments({text!r}) -> {mod._strip_comments(text)!r}, expected {want!r}", failures)
        # failure-message hints are pinned (the store-definition-free lane tells the author what to do)
        (src / "kh_routes.cpp").write_text('#include "evil_store.hpp"\n', encoding="utf-8")
        cap_h = io.StringIO()
        with contextlib.redirect_stderr(cap_h):
            mod.check_family("store_definition_free", ["server/core/src/kh_routes.cpp"], roots=roots,
                             patterns=mod.FORBIDDEN_HEADER_PATTERNS)
        cap_o = io.StringIO()
        with contextlib.redirect_stderr(cap_o):
            mod.check_family("network", ["server/core/src/kh_routes.cpp"], roots=roots,
                             patterns=mod.FORBIDDEN_HEADER_PATTERNS)
        if "enrolled as store-definition-free" not in cap_h.getvalue() or \
                "enrolled as store-definition-free" in cap_o.getvalue():
            _fail("the store-definition-free remediation hint is missing for that lane or leaked into "
                  "another family's message", failures)
        if "ADR-0031" not in cap_h.getvalue() or "ADR-0031" not in cap_o.getvalue():
            _fail("a forbidden-header failure no longer points at ADR-0031 / the matrix", failures)
        cap_nf = io.StringIO()
        with contextlib.redirect_stderr(cap_nf):
            mod.check_family("store_definition_free", ["server/core/src/nope_routes.cpp"], roots=roots)
        if "STORE_DEFINITION_FREE_TUS" not in cap_nf.getvalue():
            _fail("the missing-TU message does not name STORE_DEFINITION_FREE_TUS for that lane", failures)

    # 18b. The LANE DEFAULTS are pinned. Check 19 forces run_check() onto them, so a mutated default
    #      (`patterns=()`, `extra_include=()`, a repointed root) left both scripts green.
    import inspect
    for fn in (mod.check_family, mod.is_forbidden_header):
        if inspect.signature(fn).parameters["patterns"].default is not mod.FORBIDDEN_HEADER_PATTERNS:
            _fail(f"{fn.__name__}'s `patterns=` default is no longer FORBIDDEN_HEADER_PATTERNS - "
                  f"run_check() would enforce a different policy than the one pinned above", failures)
    for fn in (mod.check_family, mod.check_impl_purity, mod.check_abstract_headers_store_type_free,
               mod.closure, mod.resolve_include):
        if inspect.signature(fn).parameters["roots"].default is not mod.DEFAULT_ROOTS:
            _fail(f"{fn.__name__}'s `roots=` default is not DEFAULT_ROOTS", failures)
    dr = mod.DEFAULT_ROOTS
    rel = lambda path: Path(path).relative_to(mod.ROOT).as_posix()
    got_roots = (dr.root == mod.ROOT, rel(dr.server_src), rel(dr.server_include),
                 rel(dr.common_include), [rel(x) for x in dr.extra_include])
    want_roots = (True, "server/core/src", "server/core/include", "common/include",
                  ["sdk/include", "server/core/vendor/qrcodegen", "server/core", "proto"])
    if got_roots != want_roots:
        _fail(f"DEFAULT_ROOTS drifted from the frozen pin:{_diff(got_roots, want_roots)}", failures)
    for r in (dr.server_src, dr.server_include, dr.common_include, *dr.extra_include):
        if not Path(r).is_dir():
            _fail(f"DEFAULT_ROOTS names a directory that does not exist: {r}", failures)

    # 19. run_check() WIRING: every check above exercises a helper or a constant in
    #     isolation, so nothing observed how run_check() CONSUMES them - deleting a lane's
    #     call, passing it `[]`, overriding its patterns/roots, ignoring its result, or turning
    #     a FAMILIES loop body into `pass` all left both scripts green. Swap the three check
    #     functions for recorders and assert run_check() calls each lane exactly once with the
    #     module's own list and no override, and that ANY failing lane fails the run.
    real_fns = (mod.check_family, mod.check_impl_purity, mod.check_abstract_headers_store_type_free)
    first_family = next(iter(mod.FAMILIES))
    try:
        for failing in (None, "store_definition_free", first_family, "impl", "abstract"):
            fam_calls: list = []
            other_calls: dict = {"impl": [], "abstract": []}

            def fake_family(name, tus, *a, _failing=failing, **kw):
                fam_calls.append((name, list(tus), a, dict(kw)))
                return name != _failing

            def fake_impl(tus, *a, _failing=failing, **kw):
                other_calls["impl"].append((list(tus), a, dict(kw)))
                return _failing != "impl"

            def fake_abstract(headers, *a, _failing=failing, **kw):
                other_calls["abstract"].append((list(headers), a, dict(kw)))
                return _failing != "abstract"

            mod.check_family = fake_family
            mod.check_impl_purity = fake_impl
            mod.check_abstract_headers_store_type_free = fake_abstract
            captured19 = io.StringIO()
            with contextlib.redirect_stdout(captured19), contextlib.redirect_stderr(io.StringIO()):
                rc = mod.run_check()
            want = {name: spec["tus"] for name, spec in mod.FAMILIES.items()}
            want["store_definition_free"] = mod.STORE_DEFINITION_FREE_TUS
            names = [c[0] for c in fam_calls]
            if sorted(names) != sorted(want):
                _fail(f"run_check() called check_family for {sorted(names)!r}, expected exactly "
                      f"once each for {sorted(want)!r} (failing={failing!r})", failures)
            for name, tus, a, kw in fam_calls:
                if name in want and (tus != list(want[name]) or a or kw):
                    _fail(f"run_check() called check_family({name!r}) with {(tus, a, kw)!r}, "
                          f"expected exactly the module list and NO extra args/overrides", failures)
            for lane, want_list in (("impl", mod.IMPL_TUS), ("abstract", mod.ABSTRACT_API_HEADERS)):
                calls = other_calls[lane]
                if len(calls) != 1 or calls[0][0] != list(want_list) or calls[0][1] or calls[0][2]:
                    _fail(f"run_check() must call the {lane} lane exactly once with the module "
                          f"list and no override; got {calls!r} (failing={failing!r})", failures)
            if (rc == 0) != (failing is None):
                _fail(f"run_check() returned {rc} with the {failing!r} lane failing - any failing "
                      f"lane must fail the run, and a clean run must return 0", failures)
            if failing is None and f"{len(mod.STORE_DEFINITION_FREE_TUS)} store-definition-free" \
                    not in captured19.getvalue():
                _fail("run_check() OK line does not report the store-definition-free TU count", failures)
    finally:
        (mod.check_family, mod.check_impl_purity,
         mod.check_abstract_headers_store_type_free) = real_fns

    if failures:
        print(f"\n{len(failures)} seam-closure self-test failure(s).", file=sys.stderr)
        return 1
    print("seam closure self-test: OK - policy constants pinned; gate fires on "
          "its stated patterns (including the angle-bracket internal-header "
          "shape and #4249's core-only *_api_local.hpp seam half) and does "
          "not over-fire.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
