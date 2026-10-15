#pragma once

/// @file device_lens_routes.hpp
/// The DEX + Guardian LENS fragments for the shared device page
/// (`/fragments/device/dex`, `/fragments/device/guardian`) — split out of
/// `device_routes.cpp` by ADR-0031 WS-A4 (family=`device`, wave 2) so the
/// device family's enforced TUs (`device_routes.cpp`/`device_ui.cpp`) can
/// drop `GuaranteedStateStore*` and become store-free.
///
/// **REWIRED onto the `DexApi`/`GuardianApi` seams** (issue #4576 + the
/// deferred guardian-lens rewire disclosed alongside the `guardian` family's
/// own landing) — this file no longer touches `GuaranteedStateStore*`
/// directly. The DEX lens calls `DexApi::device_score` (the SAME
/// `build_dex_device_score_model` builder `GET /api/v1/dex/devices/{id}`
/// already uses, fixed to the lens's pre-existing 7-day window); the
/// Guardian lens calls `GuardianApi::device_guards` (the SAME
/// `guardian_device_all_guards` model function `GET
/// /api/v1/guaranteed-state/agents/{id}/rules` already uses — a single
/// per-agent-scoped SQL read + rule-name resolution, replacing this file's
/// former fleet-wide `list_rules()` + `agent_rule_statuses()` C++
/// post-filter). Both are now ENROLLED in the `device` family's
/// seam-closure enforcement (`scripts/ci/check-seam-closure.py`) — this
/// file's transitive include closure is checked to contain no store header.
///
/// A null `DexApiPtr`/`GuardianApiPtr` renders the SAME "store unavailable"
/// placeholder the old `!store_` guard did (server.cpp passes `nullptr` for
/// either seam exactly when its backing store is absent — see
/// `ServerImpl`'s lens-registration wiring). One BEHAVIOUR DELTA from the
/// pre-rewire code, both accepted and narrow: a device with genuinely zero
/// reported guards now renders "No guards evaluated" even when the fleet-wide
/// rule catalogue read would itself have been degraded — because
/// `GuaranteedStateStore::rule_names_for` short-circuits to a trivial success
/// on an EMPTY rule_id list (no store round-trip at all), so a
/// zero-statuses device's `device_guards` call never depends on the
/// catalogue read's own health, unlike the old code's unconditional
/// `list_rules()` call. Judged more accurate: a device that has reported no
/// guards is honestly "no guards evaluated", not "the store is degraded".
///
/// See the "Device pages" routed-concern row (`.claude/routed-concerns.md`)
/// for the shared invariants this file must preserve verbatim: the per-lens
/// `GuaranteedState:Read` SCOPED gate (tier + management group, ancestor-
/// aware), and the `dex.device.view`/`guardian.device.view`
/// `emit_behavioral_audit` calls (behavioural-PII access audit, dashboard
/// set-and-proceed posture — a dropped/throwing audit_fn flags
/// `Sec-Audit-Failed` but still renders the fragment).

#include "device_routes.hpp" // DeviceGuardRow, render_device_dex_lens/render_device_guardian_lens/
                              // render_device_lens_placeholder, DeviceRoutes::ScopedPermFn
#include "dex_api.hpp"       // abstract DexApi seam (store-type-free)
#include "guardian_api.hpp"  // abstract GuardianApi seam (store-type-free)

#include <httplib.h>

#include <functional>
#include <memory>
#include <string>

namespace yuzu::server {

class HttpRouteSink;

/// `/fragments/device/dex` + `/fragments/device/guardian` — the DEX/Guardian
/// lens fragments for the shared device page. See the file banner above for
/// the seam rewire this file went through.
class DeviceLensRoutes {
public:
    using ScopedPermFn = DeviceRoutes::ScopedPermFn;
    using AuditFn = DeviceRoutes::AuditFn;
    /// SHARED ownership, matching every other seam consumer (DexRoutes'
    /// DexPerfApiPtr, RestApiV1, McpServer): the route lambdas outlive the
    /// ServerImpl init scope that constructs the seams, so the lens co-owns
    /// them rather than borrowing a pointer another consumer happens to keep
    /// alive.
    using DexApiPtr = std::shared_ptr<const DexApi>;
    using GuardianApiPtr = std::shared_ptr<const GuardianApi>;

    /// `dex_api`/`guardian_api` back the DEX/Guardian lens respectively
    /// (either nullptr → an honest "store unavailable" placeholder, matching
    /// device_routes.cpp's pre-split posture exactly — the caller passes
    /// nullptr precisely when the backing store is absent, mirroring every
    /// other seam's null-means-unavailable convention);
    /// `scoped_perm_fn`/`audit_fn` are the same per-device gate + behavioural-
    /// PII audit chokepoints every other per-device device-page route uses.
    void register_routes(httplib::Server& svr, ScopedPermFn scoped_perm_fn, DexApiPtr dex_api,
                         GuardianApiPtr guardian_api, AuditFn audit_fn = {});

    /// HttpRouteSink overload — testable in-process via TestRouteSink (no
    /// httplib acceptor, the #438 TSan trap). The httplib::Server& overload
    /// wraps + delegates.
    void register_routes(HttpRouteSink& sink, ScopedPermFn scoped_perm_fn, DexApiPtr dex_api,
                         GuardianApiPtr guardian_api, AuditFn audit_fn = {});

private:
    ScopedPermFn scoped_perm_fn_;
    DexApiPtr dex_api_;
    GuardianApiPtr guardian_api_;
    AuditFn audit_fn_;
};

} // namespace yuzu::server
