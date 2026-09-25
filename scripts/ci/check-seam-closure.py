#!/usr/bin/env python3
"""check-seam-closure.py - per-family INCLUDE-CLOSURE seam-enforcement gate
(ADR-0031 migration step 3, WS-A4 item 1).

ADR-0031's migration step 3 requires that a family's presentation/handler
translation units do NOT reach a data store directly - they call the
in-process API instead. This script is the first per-family scaffold for that
rule (issue tracked under the /split control plane's WS-A4 item 1); today it
covers nine families — `network`, `verify`, `compliance`, `device`, `dex`,
`dex_perf`, `schedule`, `workflow`, `guardian` (see FAMILIES below; this
docstring previously read "five", already stale by `dex_perf` before the
`schedule` family was added, then stale again at "seven" once `workflow`
landed, then again at "eight" once `guardian` landed — corrected here each
time, not merely for the family that caught it).

WHAT THIS IS: a sound-for-its-stated-claim INCLUDE-CLOSURE check, NOT a full
static analysis and NOT a substitute for review. The enforceable proxy for
"this translation unit does not touch a store" is: the TRANSITIVE `#include`
closure of the TU contains no store header. To call `store->method()` the
class definition has to be VISIBLE via some include, so if no header in the
closure defines a store class, the TU cannot be calling into one directly.
That implication only breaks two ways, both ACKNOWLEDGED and NOT caught here:

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

FAMILY COVERAGE: today this checks nine families — `network`, `verify`, `compliance`,
`device`, `dex`, `dex_perf`, `schedule`, `workflow` and `guardian` — each contributing its dashboard/UI, REST-route (or seamed routes)
and model translation units, plus the abstract in-process API header and (since
#4249) the core-only `*_api_local.hpp` factory header. The exact per-family TU
set is the FAMILIES dict below. Each family's REST-handler TWIN registrations
live inside `rest_api_v1.cpp` (or the family's own routes TU), and its MCP-tool
twin inside `mcp_server.cpp` - BOTH are
multi-family translation units that legitimately hold real store access for
~20 OTHER families each. An include-closure check applied to either whole
file would trivially fail (or be gamed by scoping) and would say nothing
meaningful about a given family specifically. Those two files' per-family
sections are therefore INSPECTED-NOT-ENFORCED - reviewed by hand today, not
gated by this script - until a block-scoped or symbol-scoped successor
exists. Do not read a clean run of this script as covering them.

USAGE
  check-seam-closure.py          # run the gate (CI mode); 0 pass / 1 fail
"""
from __future__ import annotations

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


DEFAULT_ROOTS = Roots(ROOT, SERVER_SRC, SERVER_INCLUDE, COMMON_INCLUDE)

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
    # — dex_read_model.cpp still CALLS symbols whose definitions live in the
    # presentation dex_routes.cpp, a core→presentation LINK residual tracked in
    # #4579 (only meaningful at the WS-B2 physical split; inert in today's monolith).
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
]
# Most store class names end in "Store" (GuaranteedStateStore, RbacStore, …); the
# regex catches any of them used as a type. Store/infra type names that do NOT end
# in "Store" are listed EXPLICITLY. Three kinds belong here:
#   - store ROW/data types (defined in a `*_store.hpp`): `AppPerfDailyRow` (from
#     app_perf_daily_store.hpp) — reachable from dex_api.hpp via the gap-#2
#     serializer before PR #4582.
#   - store/infra CLASS names the "Store" suffix misses: `AuthDB`, `AgentRegistry`,
#     `ExecutionTracker`, `PgPool` — data/identity/registry/pool types that must
#     never surface in an abstract seam header (some, e.g. auth_db.hpp /
#     execution_tracker.hpp, are not even in FORBIDDEN_HEADER_PATTERNS, so this
#     name probe is their only guard). Added per the #4582 Fable review; verified
#     absent from all five abstract-header closures today (no false-fire).
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
EXTRA_STORE_TYPE_TOKENS = ["AppPerfDailyRow", "AppPerfFleetRow", "AuthDB",
                           "AgentRegistry", "ExecutionTracker", "PgPool",
                           "ScheduleEngine", "WorkflowEngine"]

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
# Nine families so far: `network` (WS-A4 item 1's pilot), `verify` (WS-A4
# #4250, the SECOND family), `compliance` (the THIRD, #4337), `device`
# (the FOURTH, #4484), `dex` (the FIFTH — the DEX signals seam), `dex_perf`
# (the SIXTH — the DEX app-perf-over-time seam), `schedule` (the SEVENTH),
# `workflow` (the EIGHTH) and `guardian` (the NINTH). Each set covers the
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
    # /api/v1/workflow-executions/{id}, MCP list_workflows/get_workflow/
    # get_workflow_execution). Header-only posture, same reason as
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
}

_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*(<[^>]+>|"[^"]+")')


def gh(kind, msg):
    # stderr, matching check-api-parity.py's convention.
    print(f"::{kind}::{msg}", file=sys.stderr, flush=True)


def parse_includes(path: Path):
    """Yields (is_angle, spelling) for every `#include` line in `path`, in
    file order. Line-anchored regex, not a real preprocessor - a `#include`
    reached only through an `#if 0`/macro-guarded block is still extracted as
    if unconditional. That is conservative in the direction that matters for
    this gate (it can only make the walk see MORE of the tree, never hide a
    real include), so it is not a soundness gap for the "no store in the
    closure" claim, only a possible source of a false-positive edge the
    escapes section above does not need to cover."""
    out = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        m = _INCLUDE_RE.match(line)
        if not m:
            continue
        spelling = m.group(1)
        is_angle = spelling.startswith("<")
        out.append((is_angle, spelling[1:-1]))
    return out


def resolve_include(includer: Path, is_angle: bool, name: str, roots: Roots = DEFAULT_ROOTS):
    """Resolve one `#include` spelling to an absolute in-tree Path, or None if
    it is a genuine external/system/vendored header this checker cannot (and
    need not) see inside. See the module docstring's "INCLUDE RESOLUTION"
    section for why angle vs quote is not itself the external/internal
    signal in this codebase."""
    if is_angle:
        for r in (roots.server_include, roots.common_include):
            candidate = r / name
            if candidate.is_file():
                return candidate.resolve()
        return None
    # Quote form: directory of the includer first (ordinary compiler
    # behaviour), then the same internal roots plus server/core/src itself
    # (a fallback for a quote-include reaching a sibling file by a path
    # relative to src/ rather than to the includer's own subdirectory).
    for d in (includer.parent, roots.server_include, roots.common_include, roots.server_src):
        candidate = d / name
        if candidate.is_file():
            return candidate.resolve()
    return None


def closure(tu_path: Path, roots: Roots = DEFAULT_ROOTS):
    """BFS the `#include` closure of `tu_path`.

    Returns (visited, parent, unresolved):
      visited    - set of resolved absolute Paths reached (excludes tu_path
                   itself).
      parent     - {child_path: includer_path} for chain reconstruction.
      unresolved - [(includer_path, spelling)] for a QUOTE include that could
                   not be resolved anywhere in the tree. Quote includes in
                   this codebase are always in-tree by construction, so an
                   unresolved one is reported as a warning (an extraction
                   gap to fix, not itself evidence of a store reach) rather
                   than silently ignored. An unresolved ANGLE include is the
                   expected, common case (a real external header) and is not
                   reported at all.
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


def check_family(name: str, tus: list[str], roots: Roots = DEFAULT_ROOTS,
                  patterns=FORBIDDEN_HEADER_PATTERNS) -> bool:
    """Runs the seam-closure check for one family. `tus` is a list of
    root-relative path strings; a declared member that does not exist on
    disk is a HARD ERROR (never silently skipped - a missing family member
    is exactly the kind of "the check quietly covers less than it claims"
    defect this gate exists to prevent), reported and then EXCLUDED from the
    closure walk so the remaining members are still checked."""
    ok = True
    existing: list[Path] = []
    for rel in tus:
        p = (roots.root / rel).resolve()
        if not p.is_file():
            gh("error", f"check-seam-closure: expected family TU not found: "
                        f"{rel} (family {name!r})")
            ok = False
            continue
        existing.append(p)

    for tu in existing:
        rel_tu = tu.relative_to(roots.root)
        visited, parent, unresolved = closure(tu, roots)
        for includer, spelling in unresolved:
            gh("warning",
               f"check-seam-closure: {rel_tu}: could not resolve quote-"
               f"include \"{spelling}\" from "
               f"{includer.relative_to(roots.root)} (extraction gap, not "
               f"itself a store-header finding)")
        for f in sorted(visited, key=str):
            hit, pat = is_forbidden_header(f, roots.root, patterns)
            if not hit:
                continue
            chain = chain_to(f, parent, tu)
            chain_str = " -> ".join(str(c.relative_to(roots.root)) for c in chain)
            gh("error",
               f"check-seam-closure: family {name!r}: {rel_tu} reaches "
               f"forbidden header {f.relative_to(roots.root)} (matches "
               f"forbidden pattern {pat!r}) via include chain: {chain_str}")
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
    for rel in tus:
        tu = (roots.root / rel).resolve()
        if not tu.is_file():
            gh("error", f"check-seam-closure: impl-purity: expected impl TU not found: {rel}")
            ok = False
            continue
        visited, parent, _unresolved = closure(tu, roots)
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
    """Blank ordinary string/char literal CONTENTS first, then remove /* */
    block comments and // line comments (covers /// doc comments too). Not a
    full C++ lexer. Blanking literals before comment-stripping is load-bearing:
    a `//` or `/*` INSIDE a string literal (e.g. `const char* u = "http://h";`)
    would otherwise be treated as a comment and over-strip a real store-type
    token that follows the literal on the same line — the exact bypass this
    probe exists to prevent (#4582 review). After the literal-blank the pass is
    sound in the direction that matters: it can under-strip (a leftover token
    just produces an author-resolved false positive), and can no longer
    over-strip via an ordinary literal. RESIDUAL: raw string literals
    (`R"(...)"`) are not lexed, so a `//` inside one could still over-strip;
    accepted because no abstract `*_api.hpp` closure contains a raw string (a
    selftest case pins the ordinary-literal fix)."""
    text = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', text)  # blank string literals
    text = re.sub(r"'(?:\\.|[^'\\\n])*'", "''", text)  # blank char literals
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", " ", text)
    return text


def names_store_type(path: Path):
    """Returns the first store-type token this file NAMES in code (comments
    stripped), or None. Catches both `*Store` class names (regex) and the
    non-`Store` store row/data types (EXTRA_STORE_TYPE_TOKENS)."""
    code = _strip_comments(path.read_text(encoding="utf-8", errors="replace"))
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
    for rel in headers:
        tu = (roots.root / rel).resolve()
        if not tu.is_file():
            gh("error", f"check-seam-closure: abstract-header probe: header not found: {rel}")
            ok = False
            continue
        visited, parent, _unresolved = closure(tu, roots)
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


def run_check() -> int:
    ok = True
    checked = 0
    for name, spec in FAMILIES.items():
        checked += 1
        if not check_family(name, spec["tus"]):
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
