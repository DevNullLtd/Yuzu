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
explicit `Roots` overrides, so no monkeypatching of the real module globals
is needed and the real repo tree is never touched by the probe.

Wired into .github/workflows/docs-lint.yml alongside check-seam-closure.py
itself. Stdlib only.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
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
]
EXPECTED_EXTRA_STORE_TYPE_TOKENS = ["AppPerfDailyRow", "AppPerfFleetRow", "AuthDB",
                                    "AgentRegistry", "ExecutionTracker", "PgPool",
                                    "ScheduleEngine", "WorkflowEngine"]


def _fail(msg: str, failures: list) -> None:
    failures.append(msg)
    print(f"FAIL: {msg}", file=sys.stderr)


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_seam_closure", CHECKER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    mod = _load_checker()
    failures: list[str] = []

    # 1. FAMILIES pinned - a dropped TU (e.g. quietly removing network_ui.cpp
    #    from the list) would silently shrink what the gate covers.
    if mod.FAMILIES != EXPECTED_FAMILIES:
        _fail(f"FAMILIES {mod.FAMILIES!r} != frozen {EXPECTED_FAMILIES!r}", failures)

    # 2. FORBIDDEN_HEADER_PATTERNS pinned - narrowing a pattern (or dropping
    #    one) would silently stop the gate blocking a real store-layer header.
    if mod.FORBIDDEN_HEADER_PATTERNS != EXPECTED_FORBIDDEN_HEADER_PATTERNS:
        _fail(f"FORBIDDEN_HEADER_PATTERNS {mod.FORBIDDEN_HEADER_PATTERNS!r} != "
              f"frozen {EXPECTED_FORBIDDEN_HEADER_PATTERNS!r}", failures)

    # 2b. Impl-purity constants pinned (ADR-0031 WS-A4). A dropped impl TU, a
    #     weakened presentation-header set, or a silently-widened httplib
    #     allowlist would let a core *_api.cpp re-acquire a presentation/httplib
    #     dependency with nothing else noticing.
    if mod.IMPL_FORBIDDEN_HEADER_PATTERNS != EXPECTED_IMPL_FORBIDDEN_HEADER_PATTERNS:
        _fail(f"IMPL_FORBIDDEN_HEADER_PATTERNS {mod.IMPL_FORBIDDEN_HEADER_PATTERNS!r} != "
              f"frozen {EXPECTED_IMPL_FORBIDDEN_HEADER_PATTERNS!r}", failures)
    if mod.IMPL_TUS != EXPECTED_IMPL_TUS:
        _fail(f"IMPL_TUS {mod.IMPL_TUS!r} != frozen {EXPECTED_IMPL_TUS!r}", failures)
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

    # 3. Missing-family-member HARD ERROR: a declared TU that does not exist
    #    on disk must fail the family check, never be silently skipped.
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
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
