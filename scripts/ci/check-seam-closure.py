#!/usr/bin/env python3
"""check-seam-closure.py - per-family INCLUDE-CLOSURE seam-enforcement gate
(ADR-0031 migration step 3, WS-A4 item 1).

ADR-0031's migration step 3 requires that a family's presentation/handler
translation units do NOT reach a data store directly - they call the
in-process API instead. This script is the first per-family scaffold for that
rule (issue tracked under the /split control plane's WS-A4 item 1); today it
covers ten families — `network`, `verify`, `compliance`, `device`, `dex`,
`dex_perf`, `schedule`, `workflow`, `guardian`, `crypto` (see FAMILIES below;
this docstring previously read "five", already stale by `dex_perf` before the
`schedule` family was added, then stale again at "seven" once `workflow`
landed, again at "eight" once `guardian` landed, and again at "nine" once
`crypto` landed — corrected here each time, not merely for the family that
caught it; the self-test pins the count to len(FAMILIES)).

WHAT THIS IS: a sound-for-its-stated-claim INCLUDE-CLOSURE check, NOT a full
static analysis and NOT a substitute for review. The enforceable proxy for
"this translation unit does not touch a store" is: the TRANSITIVE `#include`
closure of the TU contains no store header. To call `store->method()` the
class definition has to be VISIBLE via some include, so if no header in the
closure defines a store class, the TU cannot be calling into one directly.
That implication breaks in the ways below, all ACKNOWLEDGED and NOT caught here (the two
numbered shapes, plus the "ALSO NOT CAUGHT" list after them):

  1. A COMPUTED / macro-built include (`#include SOME_MACRO`, X-macro headers,
     `#define STORE_HEADER "foo_store.hpp"` + `#include STORE_HEADER`) - the
     literal filename this script's regex extracts would not be the real
     target, or there would be no filename to extract at all.
  2. A translation unit that hand-re-declares a store class's body (or a
     subset of its member signatures) locally instead of including its real
     header - the closure walk never sees the real header because the code
     never asked for it, yet the call still resolves at link time.

Neither shape exists in any family this script covers today; if one is ever
introduced, this check will pass while the seam is actually broken. That is a
known, stated gap - not a silent one.

HOTFIX REVERT: this file and tests/test_seam_closure_selftest.py are pinned in lockstep,
so reverting one alone turns the selftest red - revert BOTH in one change.

ALSO NOT CAUGHT (found in the WS-A4 S0 review, each reproduced on a scratch tree):
  3. THE INCLUDE PARSER SEES DIRECTIVES, NOT THE PREPROCESSOR. It strips comments in one
     linear lexer pass (`strip_comments`: `//`, `/* */` across lines, string/char/raw-string
     aware), joins backslash-newline (trailing blanks / FF / VT allowed), drops a UTF-8 BOM,
     decodes UTF-16, treats NUL as whitespace and accepts `%:include`, `include_next` and
     `import` - cross-checked against `g++ -MM -MG` (a fuzz of ~100k files found hiding shapes in
     earlier drafts, and two independent reviewers' own grammars found more in this one; each
     reported shape is fixed and pinned in the selftest, but this is a hand-written lexer and
     "no miss in the fuzz grammars tried" is the strongest claim available). It still extracts NOTHING from a
     macro-built include (`#include SOME_MACRO`) or a `##`-spliced one, cannot see an include
     guarded away by `__has_include`. A backslash-newline INSIDE a raw string (the compiler
     reverts the splice there) and an include's `<header-name>` containing `//` or `/*` are lexed
     as the compiler does (see `strip_comments`). Conversely an `#include` line inside `#if 0`
     or alone on a line inside a raw string IS extracted and can false-FAIL (conservative).
     THREAT MODEL: this is a regression lock against honest mistakes and refactors, not a proof
     against an author deliberately contorting source to hide a store include (a macro include
     already can); it is merge-gating, so it is held to "no MISS in the fuzz grammar", not to
     "cannot be defeated".
  4. THE DENYLIST IS HAND-MAINTAINED. A store-owning header that no pattern names is
     invisible to the walk - `nvd_db.hpp` (a raw `sqlite3*`) was exactly this until S0.
     Others unlisted today: `*_owner.hpp`, `app_perf_{cohort,group}_reader.hpp`,
     `app_perf_rollup.hpp`, `sqlite_raii.hpp`. See `STORE_DEFINITION_FREE_TUS`.
  5. EXTERNAL ANGLE HEADERS ARE OPAQUE: `<sqlite3.h>` / `<libpq-fe.h>` give raw database
     access with no project class. The "cannot define a project store class" argument in
     INCLUDE RESOLUTION below is about project classes only.
  6. AN UNRESOLVED QUOTE INCLUDE IS A HARD ERROR on every lane (family, impl-purity,
     abstract-header) unless it names a generated protobuf header
     (`GENERATED_HEADER_SUFFIXES`, e.g. `agent.grpc.pb.h`) - because a header outside
     the resolution roots truncates the closure under it, and the closure under a
     generated header is not checked at all (they live only in the build directory). The
     roots mirror the build's -I directories that can hold a checked-in header
     (`Roots.extra_include`: `sdk/include`, `server/core/vendor/qrcodegen`, and meson's implicit
     `-I server/core` and `-I proto`); a NEW build include directory must be added there, and
     `DEFAULT_ROOTS` is frozen in the selftest so removing one is a loud change.
     Unresolved ANGLE includes stay silent (they are external by default; item 5).
  7. A FORWARD DECLARATION OF A STORE IS ALLOWED in a non-abstract closure (only the
     abstract `*_api.hpp` headers get the type-name probe); calling through it needs the
     full definition, which the walk would catch.

ABSTRACT-VS-LOCAL SEAM (#4249): the fourth forbidden pattern,
`*_api_local.hpp`, is NOT a store-layer header - it is the CORE-ONLY half of
a family's in-process API. #4249 splits `network_api.hpp` into the ABSTRACT
interface (what a presentation TU is allowed to call) and a new
`network_api_local.hpp` holding the store-backed FACTORY
(`make_local_network_api`) that wires that interface up to real stores. The
local header deliberately carries NO store `#include`s of its own - only
forward declarations - so the three store patterns above CANNOT see a
presentation TU that wrongly includes it, and the abstract/local boundary
would be convention only. Naming the local header itself is what makes the
boundary enforced rather than advisory. WHAT IT CATCHES: any enforced family
TU (route / renderer / model / the abstract API header) that reaches a
`*_api_local.hpp` anywhere in its include closure - i.e. a presentation TU
helping itself to the store-backed factory instead of receiving the abstract
interface. It is NOT a ban on the header existing or being used: `server.cpp`
(core wiring), the family's own `*_api.cpp` implementation, and the tests all
include it legitimately, and none of those is in any family's enforced TU
set. The local header ITSELF, however, IS in the family's enforced TU set:
a TU is excluded from its own include closure (closure() seeds `seen` with
the TU), so it never self-matches this pattern, and enforcing it makes its
own purity (forward declarations only, zero store `#include`s) lint-checked
rather than review-only. Being an include-closure check, this pattern
carries exactly the SAME acknowledged escape as shape 2 above, in the same
class and for the same reason: a presentation TU that hand-re-declares the
factory's signature locally instead of including the header still links,
and this script will never see it. Two further NAME-LEVEL escapes are
inherent to a basename glob and are stated here so the whole escape list
lives in one place: a core-only factory header that is not literally named
`*_api_local.hpp` (the template prescribes that name for every family), and
the `.hpp`-only / case-sensitive match (a `.h`/`.hxx` or differently-cased
spelling is not caught; the tree has neither). Known and stated, not silent.

INCLUDE RESOLUTION: this project spells project-internal, cross-component
headers `<yuzu/...>` (server/core/meson.build's own
`include_directories(['include', '../../common/include'])`), so ANGLE
BRACKETS ARE NOT A RELIABLE "this is third-party, never a store" SIGNAL here -
`server/core/include/yuzu/server/scim_store.hpp` is a real store header
reachable via `#include <yuzu/server/scim_store.hpp>`. A checker that only
followed quote-includes would treat that as an unwatched escape hatch, on top
of the two above. This script therefore follows BOTH quote and angle
includes, resolving each one against the project's actual include roots
(mirroring the compiler's own quote-then-search-path / angle-search-path
distinction - see `resolve_include()`); an angle-bracket spelling that does
not resolve inside `server/core/include` or `common/include` is treated as a
genuine external/system/vendored header (the C++ stdlib, httplib, spdlog,
libpq-fe, ...), which by construction cannot define one of this project's own
store classes, so treating it as opaque there is sound.

FAMILY COVERAGE: today this checks ten families — `network`, `verify`, `compliance`,
`device`, `dex`, `dex_perf`, `schedule`, `workflow`, `guardian` and `crypto` — each contributing its dashboard/UI, REST-route (or seamed routes)
and model translation units, plus the abstract in-process API header and (since
#4249) the core-only `*_api_local.hpp` factory header. The exact per-family TU
set is the FAMILIES dict below. Separately, `STORE_DEFINITION_FREE_TUS` (WS-A4 S0,
NOT a family and not counted above) enrols route/renderer TUs whose closure reaches no
store DEFINITION (not "touches no store": see that list's KNOWN LIMITS), so they stay so; and S0 widened `FORBIDDEN_HEADER_PATTERNS` to the store-backed headers the
`*_store.hpp` glob missed. Also separately (#6558, again a LANE and not a family),
the MCP REGISTRY LANE include-closure-checks every `mcp_tools_<domain>.cpp` (globbed, with a pinned
count and an accessor cross-check) plus the three headers a registry file may include
(`mcp_tool_deps.hpp`, `mcp_tool_helpers.hpp`, `mcp_tool_registry.hpp`) and the seven
store-free `*_types.hpp` headers they use: a registry file reaches data only through
`ToolDeps` provider closures, so its closure must reach no header matching a store pattern
(see the lane's KNOWN LIMITS: patterns only, include closure only, not linkage). Each family's REST-handler TWIN
registrations live inside `rest_api_v1.cpp` (or the family's own routes TU), and its MCP-tool
twin inside `mcp_server.cpp` (or, once carved, a registry file under the lane above) -
`rest_api_v1.cpp` and `mcp_server.cpp` are
multi-family translation units that legitimately hold real store access for
~20 OTHER families each. An include-closure check applied to either whole
file would trivially fail (or be gamed by scoping) and would say nothing
meaningful about a given family specifically. Those two files' per-family
sections are therefore INSPECTED-NOT-ENFORCED - reviewed by hand today, not
gated by this script - until each family is carved out into its own enforced file
(the "WS-A4 per-family carve-out sub-tasks (#6558)" table in docs/presentation-core-split-delivery-matrix.md)
or a block-scoped or symbol-scoped successor exists. Do not read a clean run of this
script as covering them: the registry lane covers only the tools ALREADY carved into
`mcp_tools_*.cpp`, not the inline branches still in `mcp_server.cpp`.

USAGE
  check-seam-closure.py          # run the gate (CI mode); 0 pass / 1 fail
"""
from __future__ import annotations

import bisect
import fnmatch
import re
import sys
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[2]
SERVER_CORE = ROOT / "server" / "core"
SERVER_SRC = SERVER_CORE / "src"
SERVER_INCLUDE = SERVER_CORE / "include"
COMMON_INCLUDE = ROOT / "common" / "include"


class Roots(NamedTuple):
    """The resolution roots an include closure walk is parameterized over -
    threaded explicitly (never read off module globals mid-walk) so the
    selftest can point a walk at a synthetic tree without monkeypatching."""
    root: Path
    server_src: Path
    server_include: Path
    common_include: Path
    # Further directories the BUILD adds with -I (mirrored, not guessed): `sdk/include`
    # (`"yuzu/metrics.hpp"`, reached through the yuzu_sdk dependency),
    # `server/core/vendor/qrcodegen` (`"qrcodegen.hpp"`, the MFA-QR target,
    # server/core/meson.build), and meson's implicit per-subdir `-I` for the two directories whose
    # meson.build declares targets and that can hold a checked-in header: `server/core`
    # (`<src/x_store.hpp>` resolves) and `proto`. Without them a legitimate quote include of a checked-in header
    # would read as unresolved and - now that unresolved is a hard error - false-fail any
    # future enrolment of a TU that reaches on_behalf_guard.hpp / mfa_qr.cpp.
    extra_include: tuple = ()


DEFAULT_ROOTS = Roots(ROOT, SERVER_SRC, SERVER_INCLUDE, COMMON_INCLUDE,
                      (ROOT / "sdk" / "include", SERVER_CORE / "vendor" / "qrcodegen",
                       SERVER_CORE, ROOT / "proto"))

# ── Forbidden header patterns (store layer + the core-only API half) ─────
# Evidence (see the PR description / junior report for the exact commands):
#   - `ls server/core/src/*_store.hpp` -> 43 files, every server store header
#     in the tree (device_store.hpp, quarantine_store.hpp, ... including
#     `server/core/include/yuzu/server/scim_store.hpp` by BASENAME match -
#     `*_store.hpp` matches regardless of which directory the header lives
#     under, which is what closes the angle-bracket `<yuzu/server/
#     scim_store.hpp>` escape noted in the module docstring above).
#   - `agent_registry.hpp` (server/core/src/agent_registry.hpp) is the
#     in-process agent/device registry - not named `*_store.hpp` but is the
#     same class of direct-data-access surface a presentation TU must not
#     reach past the seam.
#   - `server/core/src/pg/*.hpp` (pg_pool.hpp, pg_exec.hpp, pg_raii.hpp,
#     pg_migration_runner.hpp, pg_retention_guard.hpp, pg_array.hpp,
#     pg_session_advisory_lock.hpp, secret_codec.hpp) is the shared
#     Postgres-connection/raw-SQL layer EVERY store is built on
#     (`PgPool`, `PQexecParams`-wrapping `exec_param`/`exec_params`,
#     `PgResult`/`PgConn` RAII) - a TU that includes one of these can issue
#     raw SQL against the pool directly, bypassing any store class entirely,
#     which the `*_store.hpp` pattern alone would not catch.
#   - `*_api_local.hpp` (#4249) is the ONLY non-store pattern here: it
#     enforces the ABSTRACT-vs-LOCAL seam boundary within a family's own
#     in-process API. The local header declares the store-backed factory
#     (`make_local_network_api`) but holds only FORWARD DECLARATIONS of the
#     stores it wires, so the three patterns above are blind to it - a
#     presentation TU including it would reach the factory with a clean
#     store closure. It is legitimately included by `server.cpp` (core
#     wiring), by the family's own `*_api.cpp` implementation, and by tests
#     - none of which is in any family's enforced TU set - but NEVER by a
#     route / renderer / model TU, which is exactly what this pattern gates.
#     See the module docstring's "ABSTRACT-VS-LOCAL SEAM" section for the
#     acknowledged hand-re-declaration escape it shares with shape 2.
FORBIDDEN_HEADER_PATTERNS = [
    "*_store.hpp",
    "agent_registry.hpp",
    "pg/*.hpp",
    "*_api_local.hpp",
    # `schedule` (seventh family) / a future `workflow` seam, Fable review:
    # `ScheduleEngine`/`WorkflowEngine` are Postgres-backed stores
    # (`pg::PgPool&` constructor dependency) but are named `*_engine.hpp`,
    # not `*_store.hpp` — the first pattern above does not catch them, and
    # neither is named `agent_registry.hpp`. Without this pair, an abstract
    # seam header could `#include`/forward-declare either and CI would stay
    # green — the same blindness class `agent_registry.hpp` above was added
    # to close, just for a different store header naming convention.
    "schedule_engine.hpp",
    "workflow_engine.hpp",
    # WS-A4 S0: store-layer headers the `*_store.hpp` / `pg/*.hpp` /
    # `agent_registry.hpp` patterns above are blind to - each is Postgres-backed
    # (`PgPool`) or fronts a store, yet is named neither `*_store.hpp` nor
    # `pg/*.hpp`. Before this, two unenforced-but-"clean" route TUs
    # (`approval_routes.cpp` -> `approval_manager.hpp` + `auth_db.hpp`,
    # `enrollment_directory_routes.cpp` -> `directory_sync.hpp`) read as clean only
    # BECAUSE of this gap, and the auth / executions / approvals families could not
    # be gated at all. Deliberately NOT listed: `scope_engine.hpp`,
    # `oidc_provider.hpp`, `saml_provider.hpp`, `response_templates_engine.hpp`,
    # `auto_approve.hpp`, `visualization_engine.hpp` — in-memory/pure engines with no
    # store dependency (`visualization_engine.hpp` already reaches
    # `response_store.hpp`, so it is caught transitively); listing them would make
    # this a "server-state class" ban, which is not what the gate claims.
    "execution_tracker.hpp",
    "auth_db.hpp",
    "approval_manager.hpp",
    "directory_sync.hpp",
    "update_registry.hpp",
    "patch_manager.hpp",
    "deployment_engine.hpp",
    # `NvdDatabase` wraps a raw `sqlite3*` (the NVD CVE database) but is named
    # `*_db.hpp`, so no pattern above saw it; `nvd_routes.cpp` calls it directly
    # (`deps.nvd_db->match_inventory(...)`).
    "nvd_db.hpp",
]

# ── Impl-purity rule (ADR-0031 WS-A4, Fable review) ──────────────────────────
# A CORE `*_api.cpp` implementation is the store-backed side of the seam, so it
# legitimately reaches stores (network/verify/compliance/device/dex `_api.cpp`
# all include their family's stores). What it MUST NOT reach is the
# PRESENTATION / transport layer: a route header (`*_routes.hpp`), a view-type
# header (`*_view_types.hpp`), a renderer (`*_ui.hpp`), or `<httplib.h>`. The
# core→presentation include inversion this rule prevents shipped once (dex_api.cpp
# `#include "dex_routes.hpp"` for the window resolvers, which transitively pulled
# httplib) and the store-only FORBIDDEN_HEADER_PATTERNS above could not catch it
# — a route header is not a store header. `httplib.h` is EXTERNAL (resolves to
# no in-tree path, so the closure walk never visits it as a Path); it is caught
# by an include-SPELLING scan across the closure instead of the resolved-path
# match the other patterns use.
IMPL_FORBIDDEN_HEADER_PATTERNS = [
    "*_routes.hpp",
    "*_view_types.hpp",
    "*_ui.hpp",
]
IMPL_TUS = [
    "server/core/src/network_api.cpp",
    "server/core/src/verify_api.cpp",
    "server/core/src/compliance_api.cpp",
    "server/core/src/device_api.cpp",
    "server/core/src/dex_api.cpp",
    "server/core/src/dex_perf_api.cpp",
    "server/core/src/schedule_api.cpp",
    "server/core/src/workflow_api.cpp",
    # dex_read_model.cpp backs the same LocalDexApi (it defines the builders +
    # serializers) — PR #4582 FIX 4 dropped its dex_routes.hpp (httplib) include,
    # hoisting the last symbols it needed (dex_signal_groups → dex_types.hpp,
    # dex_device_score → dex_read_builders.hpp). NOTE: this check is INCLUDE-purity
    # (no presentation/httplib header in the TU's include closure), NOT link-purity
    # — dex_read_model.cpp used to still CALL symbols whose definitions lived in
    # the presentation dex_routes.cpp, a core→presentation LINK residual tracked
    # in #4579. That residual is now CLOSED (ADR-0031 WS-A4 PR-1 F1 fix,
    # 2026-09-28: the definitions moved into dex_types.cpp/dex_window.cpp/
    # dex_read_model.cpp) and enforced by the LINK-level twin this include-purity
    # check cannot be — scripts/ci/check_core_presentation_link.py, wired as the
    # meson test() `dex link no presentation symbols` (suite:server) since it
    # needs compiled objects, unlike this pure source-tree walk.
    "server/core/src/dex_read_model.cpp",
    # dex_app_perf_model.cpp backs the same LocalDexPerfApi (it defines
    # app_perf_fleet_trend/app_perf_group_trend/app_perf_device_summaries +
    # dex_device_app_perf_json, ADR-0031 WS-A4 DexPerfApi seam) and was already
    # httplib/routes-free from its first commit (unlike dex_read_model.cpp, it
    # never had the DEX-signals-seam's presentation include to drop).
    "server/core/src/dex_app_perf_model.cpp",
    "server/core/src/guardian_api.cpp",
    # guardian_model.cpp backs the same LocalGuardianApi (it defines
    # guardian_status_rollup/guardian_agent_status_rollup/
    # guardian_rule_agent_status_rows/guardian_device_all_guards/
    # guardian_device_compliance_rollup, ADR-0031 WS-A4 GuardianApi seam,
    # ninth family) and was already httplib/routes-free — the dashboard
    # fragments that also call it (`guardian_routes.cpp`) reach it as a
    # SIBLING include, not the other way around.
    "server/core/src/guardian_model.cpp",
    "server/core/src/crypto_api.cpp",
]
# ── Abstract-header store-type probe (ADR-0031 WS-A4, FortitudeEtc / PR #4582) ─
# The store-HEADER patterns above do NOT catch an abstract seam header that
# NAMES a store type without INCLUDING its header — e.g. a forward-declared
# `class GuaranteedStateStore;` plus a `build_dex_*(GuaranteedStateStore*,…)`
# signature. dex_api.hpp shipped exactly that (10 GuaranteedStateStore mentions;
# the four sibling abstract headers: 0), because dex_read_model.hpp bundled the
# store-reaching builders with the pure model structs. This probe closes that
# gap: for each family's ABSTRACT `*_api.hpp`, no file in its transitive include
# closure may name a store type token in CODE (comments are stripped first).
# A store-pointer-taking signature is caught for free — the type name appears.
ABSTRACT_API_HEADERS = [
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
# Most store class names end in "Store" (GuaranteedStateStore, RbacStore, …); the
# regex catches any of them used as a type. Store/infra type names that do NOT end
# in "Store" are listed EXPLICITLY. Three kinds belong here:
#   - store ROW/data types (defined in a `*_store.hpp`): `AppPerfDailyRow` (from
#     app_perf_daily_store.hpp) — reachable from dex_api.hpp via the gap-#2
#     serializer before PR #4582.
#   - store/infra CLASS names the "Store" suffix misses: `AuthDB`, `AgentRegistry`,
#     `ExecutionTracker`, `PgPool` — data/identity/registry/pool types that must
#     never surface in an abstract seam header. (auth_db.hpp / execution_tracker.hpp
#     were once absent from FORBIDDEN_HEADER_PATTERNS, making this probe their only
#     guard; WS-A4 S0 added both there. The name probe stays load-bearing: a bare
#     forward declaration names the type WITHOUT including its header, which the
#     header patterns cannot see.) Added per the #4582 Fable review; verified
#     absent from all abstract-header closures today (no false-fire).
#   - `AppPerfFleetRow` (from app_perf_fleet_store.hpp) — the DexPerfApi seam's own
#     raw B2 store row. It carries per-`(version,day)` histogram arrays the
#     `kDexCohortFloor` suppression must apply to BEFORE anything crosses the
#     seam, so `dex_perf_api.hpp` exposes only the floor-applied `AppPerfTrendPoint`
#     (a pure type, see `dex_app_perf_model.hpp`), never this raw type. Two SIBLING row types
#     — `AppPerfVersionDeviceRow` (app_perf_daily_store.hpp) and `AppPerfAppSummary`
#     (app_perf_fleet_store.hpp) — were RELOCATED into the pure `app_perf_types.hpp`
#     instead of denylisted, because the version-devices drill and the app picker
#     are floor-FREE / no-suppression-needed resources that legitimately return
#     those rows verbatim across the seam (see their own doc comments). Only
#     `AppPerfDailyRow` and `AppPerfFleetRow` — the two row types a floor/audit
#     gate must interpose on BEFORE crossing — stay store-side and denylisted.
# This is a hand-maintained denylist (a new such type is a manual add) — the
# `*_store.hpp` include check remains the backstop for any full-definition leak.
# NOT listed: `AppPerfCohortRow`, a PURE comparison type in `app_perf_compare.hpp`
# (the verify seam's own pure model) that legitimately appears in verify_api.hpp's
# closure — it is NOT a store type, so listing it would be a false positive.
STORE_TYPE_TOKEN_RE = re.compile(r"\b[A-Z][A-Za-z0-9_]*Store\b")
# `ScheduleEngine`/`WorkflowEngine`: `schedule` (seventh family) / a future
# `workflow` seam, Fable review — the same naming-convention gap
# `FORBIDDEN_HEADER_PATTERNS`' `schedule_engine.hpp`/`workflow_engine.hpp`
# entries close for the HEADER-include probe, closed here for the
# TYPE-NAME-in-code probe (a forward-declared `class ScheduleEngine;` plus a
# `list_schedules(ScheduleEngine*, …)` signature names the type without
# including its header).
#
# WS-A4 S0: `ApprovalManager`, `DirectorySync`, `UpdateRegistry`, `PatchManager`,
# `NvdDatabase` — the type-name twins of the new `FORBIDDEN_HEADER_PATTERNS` entries
# above (same store-backed, not-`*Store`-named class gap).
EXTRA_STORE_TYPE_TOKENS = ["AppPerfDailyRow", "AppPerfFleetRow", "AuthDB",
                           "AgentRegistry", "ExecutionTracker", "PgPool",
                           "ScheduleEngine", "WorkflowEngine",
                           "ApprovalManager", "DirectorySync", "UpdateRegistry",
                           "PatchManager", "NvdDatabase"]

# `<httplib.h>` allowlist for the impl-purity scan: one PRE-EXISTING core coupling.
# `event_bus.hpp` is a CORE SSE primitive (the legacy `GET /events` content-provider
# bus + `StreamBudget`) that includes `<httplib.h>` for `httplib::DataSink&`.
# `network_api.cpp` and `device_api.cpp` reach it TRANSITIVELY through their own
# stores (not through any presentation header) — a core→core dependency that
# predates this seam and is NOT the presentation-inversion this rule targets.
# Exempting it by name keeps the transitive-httplib ban meaningful for any NEW
# path while not forcing an out-of-scope network/device refactor; the broader
# "should a core *_api.cpp transitively touch httplib via a core SSE primitive"
# question is a WS-B2 physical-split concern (core owns no httplib once extracted),
# out of scope for this seam and tracked as #4579, not this round.
# `dex_api.cpp` reaches NEITHER event_bus.hpp NOR httplib — its fix is fully clean.
IMPL_HTTPLIB_ALLOWED = {"server/core/src/event_bus.hpp"}  # root-relative, exact file only

# ── Family definitions ────────────────────────────────────────────────────
# Ten families so far: `network` (WS-A4 item 1's pilot), `verify` (WS-A4
# #4250, the SECOND family), `compliance` (the THIRD, #4337), `device`
# (the FOURTH, #4484), `dex` (the FIFTH — the DEX signals seam), `dex_perf`
# (the SIXTH — the DEX app-perf-over-time seam), `schedule` (the SEVENTH),
# `workflow` (the EIGHTH), `guardian` (the NINTH) and `crypto` (the TENTH). Each set covers the
# presentation-side TUs plus BOTH halves of the seam header pair: the
# abstract `*_api.hpp` and the core-only `*_api_local.hpp` (#4249). Enforcing
# the local header pins its own purity (forward decls only); it cannot
# self-match `*_api_local.hpp` because a TU is excluded from its own closure.
# A declared-but-missing TU is a hard error - see `check_family()`.
#
# `verify`'s closure was NOT clean before #4250's rewire: `verify_routes.hpp`
# used to include `dex_app_perf_model.hpp` (for the retired `AppPerfCohortFn`)
# AND `dex_routes.hpp` (for `DexRoutes::AuditFn`) - the latter transitively
# reaches `dex_app_perf_ui.hpp` -> `dex_app_perf_model.hpp` regardless, which
# itself `#include`s `app_perf_daily_store.hpp` + `app_perf_fleet_store.hpp`
# (both `*_store.hpp`). The rewire (1) replaced the cohort provider with the
# `VerifyApi` seam, (2) relocated the pure `app_perf_param_valid`/
# `kAppPerfParamCap` validator out of `dex_app_perf_model.hpp` into the
# already-pure `app_perf_compare.hpp`, and (3) defined `VerifyRoutes::AuditFn`
# LOCALLY (same shape as `DexRoutes::AuditFn`/`NetworkRoutes::AuditFn`)
# instead of borrowing `dex_routes.hpp` for one type alias - which is what
# actually makes this family's closure clean, not merely dropping one include.
FAMILIES = {
    "device": {
        "tus": [
            "server/core/src/device_routes.cpp",
            "server/core/src/device_ui.cpp",
            "server/core/src/device_api.hpp",
            "server/core/src/device_api_local.hpp",
            # device_lens_routes.{cpp,hpp} — the DEX/Guardian device-page lens
            # fragments, split out of device_routes.cpp in the SAME wave but
            # left outside this enforced set until their own rewire (issue
            # #4576 + the guardian-lens deferral). Now onto the DexApi/
            # GuardianApi abstract seams (see device_lens_routes.hpp's own
            # banner) — enrolled here alongside device_routes.cpp/device_ui.cpp
            # rather than as a standalone family, since it is this family's
            # own presentation surface, just a second TU.
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
    # `compliance` (ADR-0031 WS-A4, the THIRD family through the seam). The
    # read/presentation surface (`compliance_routes.cpp` + dashboard fragments,
    # `compliance_ui.cpp`) consumes the store-free `ComplianceApi` seam; the
    # policy/fragment MUTATORS (no public REST/MCP twin — INV-31-4) live in
    # `policy_admin_routes.*`, deliberately OUTSIDE this enforced set (see that
    # file's banner). `compliance_model.cpp` is the family's pure model TU.
    "compliance": {
        "tus": [
            "server/core/src/compliance_routes.cpp",
            "server/core/src/compliance_ui.cpp",
            "server/core/src/compliance_model.cpp",
            "server/core/src/compliance_api.hpp",
            "server/core/src/compliance_api_local.hpp",
        ],
    },
    # `dex` (ADR-0031 WS-A4, the FIFTH family through the seam) — the DEX
    # signals / experience-score surface (GuaranteedStateStore-backed
    # `/api/v1/dex/*` reads). The enforced set is the four PURE seam headers:
    # `dex_types.hpp` (the relocated DEX leaf PODs), `dex_read_model.hpp` (the
    # pure model structs + model-only JSON serializers), and the abstract/local
    # api pair. Their closures must contain NO store header AND name no store
    # TYPE (the abstract-header probe below enforces the latter). `dex_types.hpp`
    # was relocated out of the CATASTROPHIC `guaranteed_state_store.hpp` in slice
    # 1a; the store-reaching `build_dex_*_model(GuaranteedStateStore*,…)` builders
    # (and `dex_device_app_perf_json`, which names `AppPerfDailyRow`) were then
    # split out of `dex_read_model.hpp` into the core-only `dex_read_builders.hpp`
    # (PR #4582, FortitudeEtc review) — before that split `dex_api.hpp`
    # transitively NAMED `GuaranteedStateStore` and was not store-type-free like
    # its siblings. The IMPL TUs `dex_read_model.cpp`, `dex_api.cpp` and
    # `dex_read_builders.hpp`'s other includers are OUTSIDE this set: they
    # legitimately reach the store (core side of the seam), like every other
    # family's `*_api.cpp`. The CONSUMERS `rest_api_v1.cpp` / `mcp_server.cpp` /
    # `dex_routes.cpp` are multi-family / mixed TUs and stay
    # INSPECTED-NOT-ENFORCED (reviewed by hand), same posture as the other
    # families' twin-registration files. REST and MCP both route through
    # `DexApi`; `device_lens_routes.cpp`'s `/fragments/device/dex` lens is ALSO
    # now rewired onto `DexApi` (issue #4576) and is enforced too — but via the
    # `device` family's TU set above (it is that family's own second
    # presentation TU), not this one, since `dex`'s enforced set here is
    # header-only.
    "dex": {
        "tus": [
            "server/core/src/dex_types.hpp",
            "server/core/src/dex_read_model.hpp",
            "server/core/src/dex_api.hpp",
            "server/core/src/dex_api_local.hpp",
        ],
    },
    # dex_perf: the SIXTH family — DexPerfApi, the DEX app-perf-over-time
    # sequel to `dex` (DEX signals). REST and MCP ARE rewired through this
    # seam (zero remaining direct AppPerfProviders/DexPerfFn calls in
    # rest_api_v1.cpp/mcp_server.cpp). #4626 additionally rewired and ENROLLED
    # the dashboard consumer TUs (`dex_perf_ui.cpp`, `dex_app_perf_ui.hpp`,
    # `dex_app_perf_ui.cpp`) — the retired `AppPerfProviders` bundle's last
    # production consumer — so this family now enforces its UI TUs too,
    # narrowing the gap to `network`'s five-consumer-enforced posture.
    # `dex_routes.cpp`/`.hpp` (the ROUTE-registration half) stay OUTSIDE this
    # set, same as `dex`'s own `dex_routes.cpp` — that TU also registers the
    # still-store-coupled DEX-SIGNALS fragments (GuaranteedStateStore-backed,
    # out of scope for both `dex` and `dex_perf`'s own seam builds), so
    # enforcing it would require splitting the DEX-signals dashboard rewire
    # (tracked #4576) into this family's scope, which it is not.
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
    # `schedule` (ADR-0031 WS-A4, the SEVENTH family through the seam) — the
    # recurring-schedule READ surface (GET /fragments/schedules, GET
    # /api/v1/schedules, MCP list_schedules — all three share ONE
    # ScheduleApi::list_schedules call). Header-only posture, same reason as
    # `dex`/`dex_perf`: the consumer TU (`workflow_routes.cpp`) is
    # multi-family (it also holds the unseamed `workflow` family's routes),
    # so it stays INSPECTED-NOT-ENFORCED like every other family's
    # multi-family consumer, not because a rewire is outstanding — both REST
    # v1 and the dashboard fragment ARE rewired (server.cpp / mcp_server.cpp
    # both call the seam). `schedule_types.hpp` was relocated out of
    # `schedule_engine.hpp`; `schedule_model.hpp`/`.cpp` (schedule_row_json)
    # was split out of the entangled `workflow_model.hpp`, which previously
    # bundled it with the (unseamed) workflow builders and `#include`d BOTH
    # `schedule_engine.hpp` AND `workflow_engine.hpp` despite claiming
    # "pure, I/O-free" — the exact anti-pattern the `dex_perf` seam's own
    # design note (PR #4582) warns against. The unversioned legacy
    # `/api/schedules` POST/DELETE/enable mutators (`schedule_routes.cpp`)
    # are a SEPARATE, deliberately untouched capability with no public
    # REST v1/MCP twin — nothing to carve out of this family's enforced set,
    # unlike `compliance`'s WS-A3 mutator gap.
    "schedule": {
        "tus": [
            "server/core/src/schedule_types.hpp",
            "server/core/src/schedule_model.hpp",
            "server/core/src/schedule_model.cpp",
            "server/core/src/schedule_api.hpp",
            "server/core/src/schedule_api_local.hpp",
        ],
    },
    # `workflow` (ADR-0031 WS-A4, the EIGHTH family through the seam) — the
    # multi-step-workflow READ surface (GET /api/v1/workflows[/{id}], GET
    # /api/v1/workflow-executions[/{id}], MCP list_workflows/get_workflow/
    # list_workflow_executions/get_workflow_execution). Header-only
    # posture, same reason as
    # `dex`/`dex_perf`/`schedule`: the consumer TU (`workflow_routes.cpp`) is
    # multi-family (it also holds the legacy unversioned GET routes and
    # every mutator, plus `schedule`'s own legacy `/api/schedules` routes),
    # so it stays INSPECTED-NOT-ENFORCED like every other family's
    # multi-family consumer, not because a rewire is outstanding — both REST
    # v1 and MCP ARE rewired (server.cpp / mcp_server.cpp both call the
    # seam). `workflow_types.hpp` was relocated out of `workflow_engine.hpp`;
    # `workflow_model.hpp` was made genuinely pure by pointing it at
    # `workflow_types.hpp` instead of the store-coupled `workflow_engine.
    # hpp` (it needed no FURTHER split by this eighth family — it DID
    # originally bundle another family's builder, `schedule_row_json`, but
    # the seventh family's own PR already split that out into
    # `schedule_model.hpp`, so by the time `workflow` landed there was
    # nothing left to carve out). The legacy unversioned GET
    # routes and every `POST`/`DELETE`/`.../execute` mutator
    # (`workflow_routes.cpp`) are a SEPARATE, deliberately untouched
    # capability with no public REST v1/MCP twin of their own (the
    # mutators) or sharing the SAME store call as their v1 twin without
    # themselves being the versioned resource (the legacy GETs) — nothing
    # to carve out of this family's enforced set, unlike `compliance`'s
    # WS-A3 mutator gap.
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
    # `guardian` (ADR-0031 WS-A4, the NINTH family) — the Guardian /
    # Guaranteed State READ surface: `GuaranteedStateStore`-backed
    # `GET /api/v1/guaranteed-state/{rules,rules/{id},status,
    # status/{agent_id},rules/{id}/status,agents/{id}/rules,events}` +
    # `BaselineStore`-backed `device-compliance` — eight of the family's
    # nine public resources, each with a live MCP twin. The ninth,
    # `schemas`/MCP `get_guardian_schemas`, is deliberately outside the
    # seam (a compiled-in, store-free catalog — see guardian_api.hpp).
    # Enforced at the HEADER level only, same posture as
    # `dex`/`dex_perf`/`schedule`/`workflow` and for the SAME reason:
    # `rest_api_v1.cpp`/`mcp_server.cpp` are multi-family TUs, and
    # `guardian_routes.cpp` — UNLIKE those four siblings — has no
    # single-family enforced TU of its own to add here either, because it
    # interleaves the seamed READ fragments with the rule/baseline
    # MUTATORS (no public REST/MCP twin — `compliance`'s own WS-A3 gap
    # shape, #4334) in one translation unit; carving the mutators out into
    # a `policy_admin_routes.hpp`-style sibling file is a disclosed,
    # separate follow-up, not done by this seam. `guardian_types.hpp` holds
    # both the relocated `GuaranteedState*` row/query/error types (out of
    # `guaranteed_state_store.hpp`) AND the five pre-existing pure result
    # structs relocated out of `guardian_model.hpp` (that header itself
    # forward-declares `GuaranteedStateStore`/`BaselineStore` and so cannot
    # sit in this family's enforced set — see its own file banner).
    # `device_lens_routes.cpp`'s `/fragments/device/guardian` fragment IS now
    # rewired onto this seam (`GuardianApi::device_guards`, mirroring the
    # `dex` family's own ISSUE #4576 rewire) and enforced — but via the
    # `device` family's TU set, not this one, since `guardian`'s own enforced
    # set here is header-only (see the `device` family entry above).
    "guardian": {
        "tus": [
            "server/core/src/guardian_types.hpp",
            "server/core/src/guardian_api.hpp",
            "server/core/src/guardian_api_local.hpp",
        ],
    },
    # `crypto` (ADR-0031 WS-A4, the TENTH family through the seam) - the /crypto
    # crypto-library-presence READ surface (REST /api/v1/crypto/libraries[/devices], the
    # /fragments/crypto/* fragments and MCP get_crypto_libraries /
    # list_crypto_library_devices share ONE CryptoApi). Header-level plus the pure model:
    # `crypto_library_model.{hpp,cpp}` names no store type (the store-facing mapping lives in
    # the core-only crypto_api.cpp, an IMPL_TUS member). The route owner `crypto_routes.{hpp,cpp}`
    # and the renderers `crypto_ui.{hpp,cpp}` are single-family TUs, so they ARE enforced: their
    # closure reaches the seam, never a store.
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

# ── Store-DEFINITION-free presentation TUs (WS-A4 S0, Fable review of the WS-A4 plan) ───
# NOT a seam family: no `*Api` is involved and the count in FAMILIES (which the
# docstring and the selftest pin) is unchanged. These are route/renderer TUs whose
# include closure was ALREADY free of every forbidden header when this list was
# written — they are fed by injected `std::function` providers (the
# `docs/api-twin-recipe.md` style) or render from plain view types. Until now they
# were clean by CONVENTION only; enrolling them turns that into a gate, so a future
# edit that adds a store include to any of them fails CI instead of passing
# silently. Zero refactor cost — it only locks in what is already true.
#
# "STORE-DEFINITION-FREE" means exactly this and no more: walking the TU's `#include` closure
# reaches no header matching `FORBIDDEN_HEADER_PATTERNS` - i.e. no store/engine/DB class
# DEFINITION. It does NOT mean "touches no store" (see KNOWN LIMITS below).
#
# Membership rule: a `*_routes.cpp` / `*_ui.cpp` whose closure is clean under the
# CURRENT `FORBIDDEN_HEADER_PATTERNS` and which no FAMILIES entry already enforces.
# `approval_routes.cpp`, `enrollment_directory_routes.cpp` and `nvd_routes.cpp` are
# deliberately NOT here: they were clean only under the pre-S0 patterns (they reach
# `approval_manager.hpp`/`auth_db.hpp`, `directory_sync.hpp` and `nvd_db.hpp`
# respectively - the last a raw `sqlite3*` the first draft of this list missed). New unenforced
# clean TUs are NOT auto-enrolled — add them here when they are written.
# Being clean says nothing about being SEAMED: a TU here may still reach its data
# through a provider closure that wraps a raw store in `server.cpp`; that is the
# per-family seam work this list does not claim to have done. Enrolment is a
# REGRESSION LOCK, not seam progress.
#
# KNOWN LIMITS of "store-definition-free" here (include-closure only, same as every family):
#   - a header that merely FORWARD-DECLARES a store (`auth.hpp`, `authz_gates.hpp`,
#     `dex_routes.hpp`, `preflight_routes.hpp`) is allowed; calling through it needs
#     the full definition, which the closure walk would catch.
#   - external angle headers (`<sqlite3.h>`, `<libpq-fe.h>`) are opaque to the walk;
#     no enrolled closure includes either today.
#   - a store-owning header that no pattern names stays invisible. Before enrolling
#     MORE TUs, scan the union of their closures for headers owning a `PgPool` or a
#     `sqlite3*` (today's unlisted owners include `*_owner.hpp`,
#     `app_perf_{cohort_reader,group_reader,rollup}.hpp`, `sqlite_raii.hpp`) and add
#     patterns first - the `nvd_db.hpp` miss was exactly this.
STORE_DEFINITION_FREE_TUS = [
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
    "server/core/src/echo_page_ui.cpp",
    "server/core/src/echo_timeline_page_ui.cpp",
    "server/core/src/echo_tree_routes.cpp",
    "server/core/src/viz_host_page_ui.cpp",
    "server/core/src/viz_page_ui.cpp",
    "server/core/src/workflows_ui.cpp",
]


# MCP REGISTRY LANE (#6558, WS-A4) - a LANE, not a family. Every `mcp_tools_<domain>.cpp`
# is a store-free registry file: a tool handler reaches data only through the provider
# closures on `ToolDeps` (`mcp_tool_deps.hpp`), never a store, so its include closure must
# reach no store DEFINITION. The TU set is GLOBBED (a new `mcp_tools_*.cpp` is enrolled the
# moment it exists - nobody has to remember to add it here), and the file count is PINNED so
# adding one is still a loud, reviewed edit rather than a silent widening. A count alone
# cannot see a RENAME paired with an ADD (the count stays right while one file leaves the
# glob), so the glob is also cross-checked against the one-accessor-per-domain contract in
# `mcp_tool_registry.hpp` (`<domain>_tool_records()` <-> `mcp_tools_<domain>.cpp`, both
# directions). The three shared headers are listed explicitly: they are the headers a
# registry file may include (`mcp_server.hpp` includes `mcp_tool_deps.hpp`), so a store
# header reached through any of them leaks into every registry file that includes it.
#
# The row/view types these files need live in store-free `*_types.hpp` headers
# (MCP_REGISTRY_TYPES_HEADERS below); a store header re-includes its types header, never the
# reverse. A registry file that wants a type still defined in a store header moves that
# type out first - it does not get an exemption here. The types headers are enrolled
# DIRECTLY, not merely reached through a registry TU: a header nothing includes any more
# would otherwise leave the lane unguarded, and a store include added to it unseen.
#
# KNOWN LIMITS - read before quoting this lane as "store-free":
#   - "store-free" means: no header matching FORBIDDEN_HEADER_PATTERNS is reachable. A
#     store OWNER that no pattern names (`*_owner.hpp`, `*_sql_helpers.hpp`, the `app_perf_*`
#     readers, `sqlite_raii.hpp`, `migration_runner.hpp`) passes the lane. Widening the
#     patterns changes every family's policy and is a separate, not-yet-filed decision.
#   - it proves an INCLUDE closure only, not linkage: a registry object can still link a store
#     through a .cpp it does not include (`hardware_list_model.cpp` calls
#     `TagStore::validate_key`; `build_routes_catalog`, declared in `discover_catalog_types.hpp`,
#     is defined in `discover_routes.cpp`, whose TU includes `agent_registry.hpp`). Linkage is not
#     checked here; the `nm` tripwire
#     (check_core_presentation_link.py) covers only its own enrolled families (today `dex`), not
#     registry objects.
#   - the same include-closure-only limits as STORE_DEFINITION_FREE_TUS: a header that merely
#     forward-declares a store is allowed, and a macro-built `#include` is invisible.
#   - a registry TU outside the glob (another name, a subdirectory) is invisible to the
#     glob; only the accessor cross-check notices one whose accessor is declared in
#     `mcp_tool_registry.hpp` (a declaration elsewhere is caught only by the compiled
#     dispatch test, tests/unit/server/test_mcp_dispatch_coverage.cpp). That cross-check is a
#     lowercase `[a-z0-9_]` name scan of the comment-stripped header and is preprocessor-blind:
#     an upper/camel-case accessor or a macro-pasted one is invisible, and an accessor kept in
#     `#if 0` still counts as declared.
# The `mcp_server.cpp` inline tool branches and the `rest_api_v1.cpp` route registrations are
# NOT covered by this lane - they are still INSPECTED-NOT-ENFORCED, and carving each family
# out of them into its own enforced file is the "WS-A4 per-family carve-out sub-tasks
# (#6558)" table in docs/presentation-core-split-delivery-matrix.md.
MCP_REGISTRY_TU_GLOB = "mcp_tools_*.cpp"
MCP_REGISTRY_EXPECTED_TU_COUNT = 4
MCP_REGISTRY_REGISTRY_HEADER = "server/core/src/mcp_tool_registry.hpp"
MCP_REGISTRY_HEADERS = [
    "server/core/src/mcp_tool_deps.hpp",
    "server/core/src/mcp_tool_helpers.hpp",
    MCP_REGISTRY_REGISTRY_HEADER,
]
MCP_REGISTRY_TYPES_HEADERS = [
    "server/core/src/device_inventory_types.hpp",
    "server/core/src/discover_catalog_types.hpp",
    "server/core/src/inventory_types.hpp",
    "server/core/src/offline_endpoint_types.hpp",
    "server/core/src/quarantine_types.hpp",
    "server/core/src/software_inventory_types.hpp",
    "server/core/src/tag_types.hpp",
]
# One accessor per domain file, declared in mcp_tool_registry.hpp (see its own comment). The scan
# is deliberately LOOSE - any `<name>_tool_records(` in the comment-stripped header - not the one
# spelling the header uses today: a strict form-match would FAIL OPEN for a declaration written
# another way (`noexcept`, a qualified or `const`-after `ToolRecord`, a trailing return type),
# letting a registry file rename out of the glob unseen. `registered_tool_records` is the
# aggregator (defined in mcp_server.cpp), not a domain accessor.
_MCP_ACCESSOR_RE = re.compile(r'\b([a-z0-9_]+)_tool_records\s*\(')
_MCP_ACCESSOR_NOT_DOMAINS = frozenset({"registered"})

# The directive itself. By the time this runs every comment is already gone (see
# `strip_comments`), backslash-newline is already joined, and string literals are intact, so
# `#include/*c*/"x"`, `# /* c */ include "x"` and a multi-line comment closing before the `#`
# all reach it as plain `#include "x"`. `include_next` is a GCC/Clang spelling of the same
# thing. Horizontal whitespace only: the text is split on `\n` first.
_INCLUDE_RE = re.compile(r'^[ \t\f\v]*(?:#|%:)[ \t\f\v]*(?:include(?:_next)?|import)[ \t\f\v]*'
                         r'(<[^>\n]+>|"[^"\n]+")')
# Translation phase 2: backslash-newline is deleted BEFORE comments and directives exist
# (GCC/Clang also accept trailing blanks between the backslash and the newline, with a
# warning, and MSVC does too).
_LINE_CONTINUATION_RE = re.compile(r'\\[ \t\f\v]*\r?\n')
# Per-logical-line directive tracking (see `_LineState`): the code on a line so far is
# `#` / `%:` then `include` / `include_next` / `import` followed by a non-identifier character.
_DIRECTIVE_PREFIX_RE = re.compile(r'[ \t\f\v]*(?:#|%:)[ \t\f\v]*(?:include_next|include|import)'
                                  r'(?=[^A-Za-z0-9_$\x80-\U0010ffff])')
_LT_OR_NL_RE = re.compile(r"[<\n]")
_DIRECTIVE_PREFIX_CAP = 64   # `#   include_next` plus blanks fits; a longer prefix is not a directive
_SPECIAL_RE = re.compile(r"[/\"']")
_STR_END_RE = re.compile(r'["\\\n]')
_CHR_END_RE = re.compile(r"['\\\n]")
_RAW_OPEN_RE = re.compile(r'"([^()\\ \t\n]{0,16})\(')

# Quote includes that legitimately resolve nowhere in the tree: generated protobuf/gRPC
# headers (`agent.grpc.pb.h`, `common.pb.h`) exist only in the build directory. ANY other
# unresolved quote include is a hard error (WS-A4 S0 governance, UP-4).
GENERATED_HEADER_SUFFIXES = (".pb.h",)


def gh(kind, msg):
    # stderr, matching check-api-parity.py's convention.
    print(f"::{kind}::{msg}", file=sys.stderr, flush=True)


def _is_ident_char(ch: str) -> bool:
    # `$` is an identifier character to GCC, Clang and MSVC (`$R"x(` is an identifier then a string),
    # and so is any non-ASCII character (extended identifier characters).
    return ch.isalnum() or ch == "_" or ch == "$" or ord(ch) > 127


def _is_pp_run_char(ch: str) -> bool:
    """A character that can be part of a run holding a pp-number or an identifier before a quote."""
    return _is_ident_char(ch) or ch in ".+-"


class _LineState:
    """Tracks, for the CURRENT logical line (backslash-newline already joined; a multi-line block
    comment is one blank and does not end it), whether the code so far is an include directive and
    whether the lexer is inside a `<header-name>`.

    The compiler lexes a header-name as ONE token, so `//` and `/*` inside it are not comments, and
    in an include directive EVERY `<` after the keyword opens one (`#include<a.h></*>` has a second
    header-name). The tracker is fed only plain code segments (comments contribute a blank, literals
    are skipped via `literal()`), so a comment between `#`, `include` and `<` does not hide the
    directive. Linear: each segment is scanned once, and the pre-keyword prefix is capped."""
    __slots__ = ("prefix", "dead", "in_include", "in_name")

    def __init__(self):
        self.reset()

    def reset(self):
        self.prefix = ""
        self.dead = False
        self.in_include = False
        self.in_name = False

    def literal(self):
        # A string/char literal before the directive keyword makes this line not a directive; the
        # `"` of `#include "x"` arrives before the keyword's follower, so look ahead with a blank.
        if self.in_include or self.dead:
            return
        m = _DIRECTIVE_PREFIX_RE.match(self.prefix + " ")
        if m:
            self.in_include = True
            self.prefix = ""
        else:
            self.dead = True

    def feed(self, seg: str):
        pos, n = 0, len(seg)
        while pos < n:
            if self.in_include:
                if self.in_name:
                    gt = seg.find(">", pos)
                    nl = seg.find("\n", pos)
                    if nl >= 0 and (gt < 0 or nl < gt):
                        self.reset()
                        pos = nl + 1
                        continue
                    if gt < 0:
                        return
                    self.in_name = False
                    pos = gt + 1
                else:
                    m = _LT_OR_NL_RE.search(seg, pos)
                    if m is None:
                        return
                    if m.group() == "\n":
                        self.reset()
                    else:
                        self.in_name = True
                    pos = m.end()
            else:
                nl = seg.find("\n", pos)
                end = n if nl < 0 else nl
                if not self.dead:
                    self.prefix += seg[pos:end]
                    m = _DIRECTIVE_PREFIX_RE.match(self.prefix)
                    if m:
                        rest = self.prefix[m.end():]
                        self.in_include = True
                        self.prefix = ""
                        self.feed(rest)
                    elif len(self.prefix) > _DIRECTIVE_PREFIX_CAP:
                        self.dead = True
                if nl < 0:
                    return
                self.reset()
                pos = nl + 1


def _quoted_end(text: str, k: int, end_re) -> int:
    """Offset just past the string/char literal whose body starts at `k` (`end_re` finds the
    closing quote, a backslash or a newline). Backslash skips the next character; an unterminated
    literal ends AT the newline, which is not consumed; EOF ends it at len(text)."""
    while True:
        sm = end_re.search(text, k)
        if sm is None:
            return len(text)
        ch = text[sm.start()]
        if ch == "\\":
            if text[sm.start() + 1:sm.start() + 2] == "\n":
                return sm.start() + 1   # a surviving backslash-newline is not a splice: the literal ends
            k = sm.start() + 2
            continue
        return sm.start() if ch == "\n" else sm.end()


def _ends_in_pp_number(run: str) -> bool:
    """`run` is a maximal run of identifier characters, `.`, `+` and `-`. True when its LAST token,
    lexed from the left the way the compiler does, is a pp-number: it starts with an ASCII digit or
    `.digit`, then takes letters, digits, `_`, `.`, `$`, non-ASCII characters, and a sign directly
    after `e`/`E`/`p`/`P`. An identifier swallows its digits (`a$1`, `x1`); a `.`, `+` or `-` that
    does not continue a number is punctuation (`x.5` is the identifier `x` then `.5`)."""
    i, n = 0, len(run)
    is_num = False
    while i < n:
        c = run[i]
        if "0" <= c <= "9" or (c == "." and i + 1 < n and "0" <= run[i + 1] <= "9"):
            i += 1
            while i < n:
                d = run[i]
                if _is_ident_char(d) or d == ".":
                    i += 1
                elif d in "+-" and run[i - 1] in "eEpP":
                    i += 1
                else:
                    break
            is_num = True
        elif _is_ident_char(c):
            i += 1
            while i < n and _is_ident_char(run[i]):
                i += 1
            is_num = False
        else:
            i += 1
            is_num = False
    return is_num


def _raw_prefix_ok(text: str, r: int) -> bool:
    """`text[r]` is an `R` directly before a `"`. True when `R`, `LR`, `uR`, `UR` or `u8R` starting
    at `r` (or just before it) is a whole raw-string encoding prefix: NOT the tail of a longer
    identifier or pp-number (`aLR"`, `1R"`, `0LR"`) and NOT a user-defined-literal suffix on a
    preceding literal (`"s"R"`, `'c'LR"`)."""
    k = r
    while k >= 0 and _is_pp_run_char(text[k]):
        k -= 1
    if _ends_in_pp_number(text[k + 1:r + 1]):   # `1.R"`, `0x1R"`: the R belongs to a number
        return False
    start = r
    if r >= 2 and text[r - 2:r] == "u8":
        start = r - 2
    elif r >= 1 and text[r - 1] in "LuU":
        start = r - 1
    return start == 0 or not (_is_ident_char(text[start - 1]) or text[start - 1] in "\"'")


def strip_comments(text: str, blank_strings: bool, join_splices: bool = True) -> str:
    """ONE LINEAR PASS over `text`: every `//` and `/* ... */` comment becomes a single space;
    string, char and raw-string literals are skipped, so a `//` or `/*` INSIDE one is never
    read as a comment; with `blank_strings` their contents are replaced by `""` / `''`.
    Backslash-newline is deleted first (translation phase 2), so a `//` comment ending in a
    backslash correctly swallows the next line, exactly as the compiler does.

    Linear by construction: `_SPECIAL_RE` jumps to the next `/`, `"` or `'`, and each
    terminator is found with `str.find` / a forward regex search from where the scan already
    is (the header-name look-back is bounded by the previous comment's end). Do NOT replace this with `re.sub` over nested/lazy quantifiers: the previous versions
    of this function were quadratic (a header of `"\\"\\"...` or of repeated unterminated
    `/*` took 5-30 s per 64-240 KB) and this script gates CI.

    Differentially tested against `g++ -MM -MG` as the oracle: the hand-written fixtures pinned in
    the selftest (which re-checks them against GNU g++ when one is installed) and, in review,
    ~100k randomly generated files from a grammar of comments / literals / raw strings / splices /
    digraphs / NULs / prefixes / `<header-name>`s. That fuzz FOUND hiding shapes in earlier
    drafts - a char literal after `return`/`L`/`u8`/a digit, `R` used as a user-defined-literal
    suffix or as the tail of an identifier / pp-number (`aLR"`, `0LR"`), a NUL byte, a splice with
    FF/VT before the newline, `#import`, a splice inside a raw string or inside the raw-string
    OPENER, a `//` or `/*` inside `#include <a//b.hpp>`, and a leading-dot pp-number separator
    (`.5'0`) - all fixed and pinned.

    RAW-STRING SPLICES: phase-2 splices are removed before raw strings are lexed, but the compiler
    REVERTS a backslash-newline INSIDE a raw string. So the raw string's closing `)delim"` is
    searched in the ORIGINAL text (the offset is mapped back through the deleted splices), while
    its opener is recognised on the joined text. (An earlier draft also lexed such files a second
    time WITHOUT the join and unioned the results; with the mapping exact that was dead weight that
    only added false FAILs, and no fixture needed it, so it was removed.)

    HEADER-NAMES: `_LineState` follows each logical line (a multi-line block comment is one blank
    and does not end it). Once the line is `#` / `%:` then `include` / `include_next` / `import`
    - comments and blanks between the pieces are fine - EVERY `<` opens a header-name that runs to
    `>` or the end of the line, and inside it no `//`, `/*`, `"` or `'` starts anything
    (`#include<a.h></*>` has two header-names). Outside a directive a `<` means nothing.

    An include on its own line inside `#if 0` or a raw string is still extracted (the
    conservative direction: a possible false FAIL, never a hidden include). An unterminated
    `/*` consumes the rest of the file (the compiler rejects such a file)."""
    orig = text
    cut_orig: list[int] = []   # original offset of each deleted splice
    cut_join: list[int] = []   # joined offset at which each splice was deleted
    cut_cum: list[int] = []    # cumulative deleted length up to and including that splice
    if join_splices:
        parts: list[str] = []
        last_cut = 0
        removed = 0
        for sm in _LINE_CONTINUATION_RE.finditer(orig):
            parts.append(orig[last_cut:sm.start()])
            cut_orig.append(sm.start())
            cut_join.append(sm.start() - removed)
            removed += sm.end() - sm.start()
            cut_cum.append(removed)
            last_cut = sm.end()
        parts.append(orig[last_cut:])
        text = "".join(parts)
    def to_orig(p: int) -> int:
        # joined offset of a retained character -> its offset in the original text
        k = bisect.bisect_right(cut_join, p)
        return p + (cut_cum[k - 1] if k else 0)

    def to_joined(e: int) -> int:
        # original offset at a retained-character boundary -> joined offset
        k = bisect.bisect_left(cut_orig, e)
        return e - (cut_cum[k - 1] if k else 0)

    n = len(text)
    out: list[str] = []
    last = 0
    i = 0
    ls = _LineState()
    fed = 0         # text[:fed] has been fed to `ls`
    last_sep = -1   # position of the previous digit-separator quote (a chain 1'0'0'0 is one token)
    while True:
        m = _SPECIAL_RE.search(text, i)
        if m is None:
            break
        j = m.start()
        c = text[j]
        ls.feed(text[fed:j])
        fed = j
        if ls.in_name:
            i = j + 1   # inside a `<header-name>`: no comment, string or char literal can start
            continue
        if c == "/":
            nxt = text[j + 1:j + 2]
            if nxt == "/":
                end = text.find("\n", j + 2)
                end = n if end < 0 else end
                out.append(text[last:j])
                out.append(" ")
                last = i = fed = end
                ls.feed(" ")
            elif nxt == "*":
                end = text.find("*/", j + 2)
                out.append(text[last:j])
                out.append(" ")
                if end < 0:
                    last = i = n
                    break
                last = i = fed = end + 2
                ls.feed(" ")
            else:
                i = j + 1
        elif c == '"':
            end = None
            # Raw string: R"delim( ... )delim" (also LR / uR / UR / u8R prefixes).
            if j > 0 and text[j - 1] == "R" and _raw_prefix_ok(text, j - 1):
                rm = _RAW_OPEN_RE.match(text, j)
                if rm:
                    # The compiler REVERTS phase-2 splices inside a raw string, so the closing
                    # `)delim"` is searched in the ORIGINAL text, from just after the `(`.
                    tail = ")" + rm.group(1) + '"'
                    oclose = orig.find(tail, to_orig(rm.end() - 1) + 1)
                    # max(): forward progress is guaranteed even if the offset mapping were wrong
                    end = n if oclose < 0 else max(to_joined(oclose + len(tail)), rm.end())
            if end is None:
                end = _quoted_end(text, j + 1, _STR_END_RE)
            ls.literal()
            fed = end
            if blank_strings:
                out.append(text[last:j])
                out.append('""')
                last = end
            i = end
        else:  # a single quote
            nx = text[j + 1:j + 2]
            if j > 0 and nx and nx.isascii() and (nx.isalnum() or nx == "_"):
                # C++14 digit separator (1'000'000) - but ONLY inside a pp-number: tokenise the run of
                # identifier/number characters that ends here; the token touching the quote must be
                # a pp-number (an earlier separator in the same chain counts). `return'/*'`,
                # `L'x'`, `u8'x'`, `1'/*'`, `a$1'x'` are char literals; `x.5'0`, `.5'0`, `1.'5` and
                # `5e+'1` are separators. The character after the quote must be ASCII [A-Za-z0-9_].
                k = j - 1
                while k >= 0 and _is_pp_run_char(text[k]):
                    k -= 1
                if (k >= 0 and k == last_sep) or _ends_in_pp_number(text[k + 1:j]):
                    last_sep = j
                    i = j + 1
                    continue
            end = _quoted_end(text, j + 1, _CHR_END_RE)
            ls.literal()
            fed = end
            if blank_strings:
                out.append(text[last:j])
                out.append("''")
                last = end
            i = end
    out.append(text[last:])
    return "".join(out)


def _read_source(path: Path) -> str:
    """Decode a source file: UTF-16 when it starts with a UTF-16 BOM (MSVC accepts such files),
    else UTF-8 with a leading BOM dropped. Never raises on bad bytes (`replace`)."""
    raw = path.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16", errors="replace")
    else:
        text = raw.decode("utf-8-sig", errors="replace")
    # GCC treats a NUL byte as whitespace (with a warning), so `\0#include "x"` is a directive.
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\0", " ")


def parse_includes(path: Path):
    """Yields (is_angle, spelling) for every `#include` / `#include_next` directive in `path`,
    in file order. Comments are removed first by the linear `strip_comments`, backslash-newline
    is joined, a BOM is dropped and UTF-16 is decoded, so the forms a line-anchored regex
    missed - `#include/*c*/"x"`, `# /* c */ include "x"`, a multi-line comment closing before the
    `#`, `#include \\` + blank + newline, `%:include`, `include_next` - ARE found (each probed
    in the selftest and cross-checked against `g++ -MM`).

    Still NOT seen: a macro-built include (`#include SOME_MACRO`) or a `##`-spliced one.
    Over-extracted (the conservative direction, a possible false FAIL): an `#include` line
    inside `#if 0` or inside a raw string literal."""
    out = []
    for line in strip_comments(_read_source(path), blank_strings=False).split("\n"):
        m = _INCLUDE_RE.match(line)
        if not m:
            continue
        item = (m.group(1).startswith("<"), m.group(1)[1:-1])
        if item not in out:
            out.append(item)
    return out


def resolve_include(includer: Path, is_angle: bool, name: str, roots: Roots = DEFAULT_ROOTS):
    """Resolve one `#include` spelling to an absolute in-tree Path, or None if
    it is a genuine external/system/vendored header this checker cannot (and
    need not) see inside. See the module docstring's "INCLUDE RESOLUTION"
    section for why angle vs quote is not itself the external/internal
    signal in this codebase."""
    def inside(candidate: Path):
        # A header that resolves OUTSIDE the repository root (`"../../../x.h"`) is treated as not
        # found: every error message and the chain printer assume root-relative paths.
        resolved = candidate.resolve()
        return resolved if roots.root.resolve() in resolved.parents else None

    if is_angle:
        for r in (roots.server_include, roots.common_include, *roots.extra_include):
            candidate = r / name
            if candidate.is_file():
                return inside(candidate)
        return None
    # Quote form: directory of the includer first (ordinary compiler
    # behaviour), then the same internal roots plus server/core/src itself
    # (a fallback for a quote-include reaching a sibling file by a path
    # relative to src/ rather than to the includer's own subdirectory).
    for d in (includer.parent, roots.server_include, roots.common_include,
              *roots.extra_include, roots.server_src):
        candidate = d / name
        if candidate.is_file():
            return inside(candidate)
    return None


def closure(tu_path: Path, roots: Roots = DEFAULT_ROOTS):
    """BFS the `#include` closure of `tu_path`.

    Returns (visited, parent, unresolved):
      visited    - set of resolved absolute Paths reached (excludes tu_path
                   itself).
      parent     - {child_path: includer_path} for chain reconstruction.
      unresolved - [(includer_path, spelling)] for a QUOTE include that could
                   not be resolved anywhere in the tree. Quote includes in
                   this codebase are in-tree by construction, so an unresolved
                   one TRUNCATES the closure under it and is a HARD ERROR on
                   every lane (`report_unresolved`) unless it names a generated
                   `*.pb.h`. An unresolved ANGLE include is the expected,
                   common case (a real external header) and is not reported
                   at all.
    """
    tu_path = tu_path.resolve()
    visited: set[Path] = set()
    parent: dict[Path, Path] = {}
    unresolved: list[tuple[Path, str]] = []
    seen = {tu_path}
    queue = [tu_path]
    while queue:
        cur = queue.pop(0)
        for is_angle, name in parse_includes(cur):
            resolved = resolve_include(cur, is_angle, name, roots)
            if resolved is None:
                if not is_angle:
                    unresolved.append((cur, name))
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            visited.add(resolved)
            parent[resolved] = cur
            queue.append(resolved)
    return visited, parent, unresolved


def chain_to(target: Path, parent: dict[Path, Path], tu_path: Path):
    """Reconstructs the include chain from `tu_path` to `target` (inclusive
    of both ends) by walking `parent` backward."""
    chain = [target]
    cur = target
    while cur in parent:
        cur = parent[cur]
        chain.append(cur)
    chain.reverse()
    return chain


def is_forbidden_header(abspath: Path, root: Path = ROOT,
                         patterns=FORBIDDEN_HEADER_PATTERNS):
    """Returns (True, matched_pattern) if `abspath` matches any forbidden
    pattern (store-layer, or the core-only `*_api_local.hpp` seam half) -
    checked against BOTH the bare basename (so
    `*_store.hpp` fires regardless of which directory the header lives
    under, closing the angle-bracket `<yuzu/server/scim_store.hpp>` escape)
    and the root-relative path (so a directory-qualified pattern like
    `pg/*.hpp` only fires on a real `pg/` subdirectory, not on a file that
    merely happens to end the right way)."""
    rel = str(abspath.relative_to(root)).replace("\\", "/")
    base = abspath.name
    for pat in patterns:
        if fnmatch.fnmatch(base, pat):
            return True, pat
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, "*/" + pat):
            return True, pat
    return False, None


def report_unresolved(label: str, tu_rel, unresolved, roots: Roots = DEFAULT_ROOTS,
                      seen: set | None = None) -> bool:
    """False (and a `::error::` per include) if the closure holds a QUOTE include that
    resolves nowhere and is not a generated header. Such an include TRUNCATES the closure
    under it - a store header moved outside the resolution roots would otherwise
    keep every TU that reaches it green on a warning nobody reads in a passing job."""
    ok = True
    for includer, spelling in unresolved:
        if spelling.endswith(GENERATED_HEADER_SUFFIXES):
            continue
        ok = False
        # One shared header reached by N enrolled TUs would otherwise print N identical errors
        # and bury the finding: report each (includer, spelling) once per lane.
        key = (str(includer), spelling)
        if seen is not None:
            if key in seen:
                continue
            seen.add(key)
        gh("error",
           f"check-seam-closure: {label}: {tu_rel}: could not resolve quote-include "
           f"\"{spelling}\" from {includer.relative_to(roots.root)} - the closure under it "
           f"is NOT checked. Prefer fixing the include path; if the header lives in a "
           f"directory the build adds with -I, add that directory to Roots.extra_include. "
           f"Widening GENERATED_HEADER_SUFFIXES re-opens the hole this error closes and needs "
           f"security-guardian sign-off")
    return ok


def check_family(name: str, tus: list[str], roots: Roots = DEFAULT_ROOTS,
                  patterns=FORBIDDEN_HEADER_PATTERNS) -> bool:
    """Runs the seam-closure check for one family. `tus` is a list of
    root-relative path strings; a declared member that does not exist on
    disk is a HARD ERROR (never silently skipped - a missing family member
    is exactly the kind of "the check quietly covers less than it claims"
    defect this gate exists to prevent), reported and then EXCLUDED from the
    closure walk so the remaining members are still checked."""
    ok = True
    kind = "lane" if name == "mcp_registry" else "family"
    seen_unresolved: set = set()
    existing: list[Path] = []
    for rel in tus:
        p = (roots.root / rel).resolve()
        if not p.is_file():
            gh("error", f"check-seam-closure: expected family TU not found: "
                        f"{rel} ({kind} {name!r}) - if it was renamed or deleted, "
                        f"update "
                        + ("STORE_DEFINITION_FREE_TUS" if name == "store_definition_free"
                           else "MCP_REGISTRY_HEADERS / MCP_REGISTRY_TYPES_HEADERS" if name == "mcp_registry"
                           else f"FAMILIES[{name!r}]")
                        + " AND the frozen pin in tests/test_seam_closure_selftest.py")
            ok = False
            continue
        existing.append(p)

    for tu in existing:
        rel_tu = tu.relative_to(roots.root)
        visited, parent, unresolved = closure(tu, roots)
        if not report_unresolved(f"{kind} {name!r}", rel_tu, unresolved, roots, seen_unresolved):
            ok = False
        for f in sorted(visited, key=str):
            hit, pat = is_forbidden_header(f, roots.root, patterns)
            if not hit:
                continue
            chain = chain_to(f, parent, tu)
            chain_str = " -> ".join(str(c.relative_to(roots.root)) for c in chain)
            gh("error",
               f"check-seam-closure: {kind} {name!r}: {rel_tu} reaches "
               f"forbidden header {f.relative_to(roots.root)} (matches "
               f"forbidden pattern {pat!r}) via include chain: {chain_str}"
               + (" - this TU is enrolled as store-definition-free: route the data through an "
                  "injected provider or a `*Api` seam instead of including the store "
                  "(see STORE_DEFINITION_FREE_TUS)"
                  if name == "store_definition_free"
                  else " - this TU is in the MCP registry lane, which must stay store-free: reach "
                       "data through a provider closure on `ToolDeps`, and move any row type it "
                       "needs out of the store header into a `*_types.hpp` (see "
                       "MCP_REGISTRY_HEADERS / MCP_REGISTRY_TYPES_HEADERS)"
                  if name == "mcp_registry" else "")
               + " [ADR-0031 migration step 3; docs/presentation-core-split-delivery-matrix.md, "
                 "WS-A4]")
            ok = False
    return ok


def _includes_httplib(path: Path) -> bool:
    """True if `path` has a `#include` of httplib.h (angle or quote). Used to
    detect the EXTERNAL header the closure walk never visits as a resolved
    Path (see check_impl_purity)."""
    for _is_angle, name in parse_includes(path):
        if Path(name).name == "httplib.h":
            return True
    return False


def check_impl_purity(tus: list[str], roots: Roots = DEFAULT_ROOTS) -> bool:
    """Every family's `*_api.cpp` impl TU must NOT reach a presentation /
    transport header — `*_routes.hpp`, `*_view_types.hpp`, `*_ui.hpp`, or
    `<httplib.h>` — anywhere in its transitive include closure. The impl is the
    store-backed side of the seam (it legitimately reaches stores), so this is a
    DIFFERENT forbidden set from the family rule; a route/view/ui header is not a
    store header, which is exactly why the store-only patterns missed the
    dex_api.cpp -> dex_routes.hpp -> httplib inversion. A missing declared TU is
    a HARD ERROR (same posture as check_family)."""
    ok = True
    seen_unresolved: set = set()
    for rel in tus:
        tu = (roots.root / rel).resolve()
        if not tu.is_file():
            gh("error", f"check-seam-closure: impl-purity: expected impl TU not found: {rel} - if it "
                        f"was renamed or deleted, update IMPL_TUS AND the frozen pin in "
                        f"tests/test_seam_closure_selftest.py")
            ok = False
            continue
        visited, parent, unresolved = closure(tu, roots)
        if not report_unresolved("impl-purity", rel, unresolved, roots, seen_unresolved):
            ok = False
        # (a) presentation in-tree headers via resolved-path basename match.
        for f in sorted(visited, key=str):
            hit, pat = is_forbidden_header(f, roots.root, patterns=IMPL_FORBIDDEN_HEADER_PATTERNS)
            if not hit:
                continue
            chain = chain_to(f, parent, tu)
            chain_str = " -> ".join(str(c.relative_to(roots.root)) for c in chain)
            gh("error",
               f"check-seam-closure: impl-purity: {rel} reaches presentation header "
               f"{f.relative_to(roots.root)} (matches {pat!r}) via include chain: {chain_str}")
            ok = False
        # (b) <httplib.h> via include-SPELLING scan (external -> never a visited Path),
        #     minus the IMPL_HTTPLIB_ALLOWED pre-existing core-SSE coupling.
        for f in sorted({tu} | visited, key=str):
            if str(f.relative_to(roots.root)).replace("\\", "/") in IMPL_HTTPLIB_ALLOWED:
                continue
            if _includes_httplib(f):
                gh("error",
                   f"check-seam-closure: impl-purity: {rel} reaches <httplib.h> via "
                   f"{f.relative_to(roots.root)} — a core *_api.cpp must not depend on "
                   f"the httplib transport layer")
                ok = False
    return ok


def _strip_comments(text: str) -> str:
    """Comments removed and string/char literal CONTENTS blanked, in ONE LINEAR PASS
    (`strip_comments`). Blanking literals is load-bearing for the type-token probe: a `//` or
    `/*` inside a string literal (`const char* u = "http://h";`) must not be read as a comment
    start, or a real store-type token after it is over-stripped - the bypass #4582 found.
    Raw strings are lexed too (this used to be a documented residual)."""
    return strip_comments(text, blank_strings=True)


def names_store_type(path: Path):
    """Returns the first store-type token this file NAMES in code (comments
    stripped), or None. Catches both `*Store` class names (regex) and the
    non-`Store` store row/data types (EXTRA_STORE_TYPE_TOKENS)."""
    code = strip_comments(_read_source(path), blank_strings=True)
    m = STORE_TYPE_TOKEN_RE.search(code)
    if m:
        return m.group(0)
    for tok in EXTRA_STORE_TYPE_TOKENS:
        if re.search(r"\b" + re.escape(tok) + r"\b", code):
            return tok
    return None


def check_abstract_headers_store_type_free(headers: list[str],
                                           roots: Roots = DEFAULT_ROOTS) -> bool:
    """Each family's ABSTRACT `*_api.hpp` — and every header in its transitive
    include closure — must NAME no store type in code (see the probe's block
    comment above). A missing declared header is a HARD ERROR."""
    ok = True
    seen_unresolved: set = set()
    for rel in headers:
        tu = (roots.root / rel).resolve()
        if not tu.is_file():
            gh("error", f"check-seam-closure: abstract-header probe: header not found: {rel} - if it "
                        f"was renamed or deleted, update ABSTRACT_API_HEADERS AND the frozen pin "
                        f"in tests/test_seam_closure_selftest.py")
            ok = False
            continue
        visited, parent, unresolved = closure(tu, roots)
        if not report_unresolved("abstract-header probe", rel, unresolved, roots, seen_unresolved):
            ok = False
        for f in sorted({tu} | visited, key=str):
            tok = names_store_type(f)
            if tok is None:
                continue
            if f == tu:
                chain_str = str(f.relative_to(roots.root))
            else:
                chain = chain_to(f, parent, tu)
                chain_str = " -> ".join(str(c.relative_to(roots.root)) for c in chain)
            gh("error",
               f"check-seam-closure: abstract-header {rel} reaches a header that NAMES store "
               f"type {tok!r}: {f.relative_to(roots.root)} — an abstract seam header's closure "
               f"must be store-type-free (forward-decl / store-pointer signature included) via: "
               f"{chain_str}")
            ok = False
    return ok


def mcp_registry_cpps(roots: Roots = DEFAULT_ROOTS) -> list[str]:
    """Root-relative paths of every regular `mcp_tools_*.cpp` under `roots.server_src`, sorted so
    the order is stable. A symlink is NOT returned (see mcp_registry_symlinks)."""
    return sorted(
        p.relative_to(roots.root).as_posix()
        for p in roots.server_src.glob(MCP_REGISTRY_TU_GLOB)
        if p.is_file() and not p.is_symlink())


def mcp_registry_symlinks(roots: Roots = DEFAULT_ROOTS) -> list[str]:
    """Root-relative paths of glob matches that are symlinks. A registry file is a real file in
    the tree; a link can point outside the repo and would crash the closure walk, so it is
    reported and refused rather than followed."""
    return sorted(
        p.relative_to(roots.root).as_posix()
        for p in roots.server_src.glob(MCP_REGISTRY_TU_GLOB) if p.is_symlink())


def mcp_registry_tus(roots: Roots = DEFAULT_ROOTS) -> list[str]:
    """Root-relative TU list for the MCP registry lane: the globbed registry files, the shared
    headers (MCP_REGISTRY_HEADERS) and the store-free types headers (MCP_REGISTRY_TYPES_HEADERS)."""
    return (mcp_registry_cpps(roots) + list(MCP_REGISTRY_HEADERS)
            + list(MCP_REGISTRY_TYPES_HEADERS))


def mcp_registry_accessor_errors(roots: Roots = DEFAULT_ROOTS) -> list[str]:
    """Cross-check the globbed registry files against the one-accessor-per-domain contract in
    mcp_tool_registry.hpp: every declared `<d>_tool_records()` must have a globbed
    `mcp_tools_<d>.cpp`, and every globbed file must have its accessor. This is what notices a
    RENAME paired with an ADD, which leaves the count pin satisfied while a registry file has
    left the glob (and so left the lane). Returns human-readable error strings."""
    hdr = roots.root / MCP_REGISTRY_REGISTRY_HEADER
    if not hdr.is_file():
        return [f"cannot cross-check registry accessors: {MCP_REGISTRY_REGISTRY_HEADER} not found"]
    text = hdr.read_text(encoding="utf-8", errors="replace")
    declared = set(_MCP_ACCESSOR_RE.findall(_strip_comments(text))) - _MCP_ACCESSOR_NOT_DOMAINS
    globbed = {Path(c).name[len("mcp_tools_"):-len(".cpp")] for c in mcp_registry_cpps(roots)}
    errs = []
    for d in sorted(declared - globbed):
        errs.append(f"{d}_tool_records() is declared in {MCP_REGISTRY_REGISTRY_HEADER} but "
                    f"mcp_tools_{d}.cpp is not among the globbed registry files - a registry "
                    f"file renamed (or moved) out of `{MCP_REGISTRY_TU_GLOB}` leaves this lane "
                    f"unchecked while the count pin still passes (rename the file back to "
                    f"mcp_tools_{d}.cpp, or rename the accessor to match; if the one-accessor-per-domain "
                    f"contract itself is being changed, update _MCP_ACCESSOR_RE and "
                    f"docs/api-twin-recipe.md in the same PR)")
    for d in sorted(globbed - declared):
        errs.append(f"mcp_tools_{d}.cpp is globbed as a registry file but "
                    f"{MCP_REGISTRY_REGISTRY_HEADER} declares no {d}_tool_records() accessor "
                    f"- a registry file serves nothing until its accessor is declared there and "
                    f"listed in mcp_server.cpp's registered_tool_records() (if the "
                    f"one-accessor-per-domain contract itself is being changed, update "
                    f"_MCP_ACCESSOR_RE and docs/api-twin-recipe.md in the same PR)")
    return errs


def check_mcp_registry_lane(roots: Roots = DEFAULT_ROOTS,
                            expected_count: int = MCP_REGISTRY_EXPECTED_TU_COUNT,
                            patterns=FORBIDDEN_HEADER_PATTERNS) -> bool:
    """The MCP registry lane (#6558): pin the globbed file count, cross-check the glob against
    the accessor contract, refuse symlinks, then run the same closure check every family gets.
    A count mismatch is a hard error in BOTH directions - fewer means a registry file was
    renamed or deleted (the lane would quietly cover less than it claims); more means a new
    registry file arrived and its enrolment was never reviewed. Either way the fix is one
    reviewed edit across ALL of these pins, which must agree: MCP_REGISTRY_EXPECTED_TU_COUNT and
    EXPECTED_MCP_REGISTRY_TU_COUNT / EXPECTED_MCP_REGISTRY_CPPS in
    tests/test_seam_closure_selftest.py, MIN_REGISTRY_FILES in scripts/ci/check-api-parity.py,
    and kRegistryDomainFiles in tests/unit/server/test_mcp_dispatch_coverage.cpp."""
    ok = True
    for link in mcp_registry_symlinks(roots):
        gh("error",
           f"check-seam-closure: MCP registry lane: {link} is a symlink - a registry file must "
           f"be a regular file in the tree (a link can point outside the repo); refusing to "
           f"follow it [ADR-0031 WS-A4, #6558]")
        ok = False
    # A symlinked shared/types header gets the same refusal as a symlinked registry file (an
    # out-of-repo link would otherwise crash the closure walk), and is left out of the walk.
    tus = []
    for rel in mcp_registry_tus(roots):
        if (roots.root / rel).is_symlink():
            gh("error",
               f"check-seam-closure: MCP registry lane: {rel} is a symlink - a lane header must "
               f"be a regular file in the tree; refusing to follow it [ADR-0031 WS-A4, #6558]")
            ok = False
        else:
            tus.append(rel)
    n_cpp = len(mcp_registry_cpps(roots))
    if n_cpp != expected_count:
        gh("error",
           f"check-seam-closure: MCP registry lane: found {n_cpp} `{MCP_REGISTRY_TU_GLOB}` "
           f"file(s) under {roots.server_src.relative_to(roots.root).as_posix()}, expected "
           f"{expected_count} - enrol a new registry file (or retire a removed one) by updating "
           f"ALL of: MCP_REGISTRY_EXPECTED_TU_COUNT here; EXPECTED_MCP_REGISTRY_TU_COUNT and "
           f"EXPECTED_MCP_REGISTRY_CPPS in tests/test_seam_closure_selftest.py; MIN_REGISTRY_FILES "
           f"in scripts/ci/check-api-parity.py; kRegistryDomainFiles in "
           f"tests/unit/server/test_mcp_dispatch_coverage.cpp [ADR-0031 WS-A4, #6558]")
        ok = False
    for msg in mcp_registry_accessor_errors(roots):
        gh("error", f"check-seam-closure: MCP registry lane: {msg} [ADR-0031 WS-A4, #6558]")
        ok = False
    if not check_family("mcp_registry", tus, roots, patterns):
        ok = False
    return ok


def run_check() -> int:
    ok = True
    checked = 0
    for name, spec in FAMILIES.items():
        checked += 1
        if not check_family(name, spec["tus"]):
            ok = False
    if not check_family("store_definition_free", STORE_DEFINITION_FREE_TUS):
        ok = False
    if not check_mcp_registry_lane():
        ok = False
    impl_ok = check_impl_purity(IMPL_TUS)
    if not impl_ok:
        ok = False
    abstract_ok = check_abstract_headers_store_type_free(ABSTRACT_API_HEADERS)
    if not abstract_ok:
        ok = False
    if ok:
        print(f"check-seam-closure: OK ({checked} famil"
              f"{'y' if checked == 1 else 'ies'} header-closure checked + "
              f"{len(STORE_DEFINITION_FREE_TUS)} store-definition-free presentation TUs checked + "
              f"{len(mcp_registry_tus())} MCP registry lane TUs checked + "
              f"{len(IMPL_TUS)} impl TUs impl-purity checked + "
              f"{len(ABSTRACT_API_HEADERS)} abstract headers store-type-free checked; "
              f"all closures free of store-layer / core-only `*_api_local.hpp` headers, "
              f"impls free of presentation/httplib headers, and abstract headers name no "
              f"store type)")
    return 0 if ok else 1


def main() -> int:
    return run_check()


if __name__ == "__main__":
    sys.exit(main())
