#pragma once

/// @file guardian_api_local.hpp
/// CORE-ONLY. The store-backed factory for the Guardian-read seam (ADR-0031
/// WS-A4, ninth family, mirroring `dex_perf_api_local.hpp`'s
/// nullable-per-dependency shape — NOT `workflow_api_local.hpp`'s
/// single-required-reference one, see below for why). Included by server.cpp
/// (wiring), the impl (guardian_api.cpp) and the tests — NEVER by a
/// presentation/renderer/route TU; the seam-closure lint forbids
/// `*_api_local.hpp` in the family's enforced presentation TUs so the
/// abstract/local boundary is enforced, not conventional.
///
/// Store types stay FORWARD-DECLARED here (zero store `#include`s) — this
/// header is the core side of the seam, not the store layer. That purity is
/// lint-enforced: this header is itself in the family's enforced closure set,
/// so a store `#include` added here fails CI.

#include <memory>

#include "guardian_api.hpp"

namespace yuzu::server {

class GuaranteedStateStore;
class BaselineStore;

/// Factory for the store-backed implementation (`LocalGuardianApi`,
/// guardian_api.cpp — kept out of the abstract header so that header stays
/// free of store references entirely).
///
/// BOTH pointers are NULLABLE — mirrors `dex_perf_api_local.hpp`'s own
/// multi-dependency shape, not `workflow_api_local.hpp`'s single-required-
/// reference one: seven of `GuardianApi`'s eight methods need ONLY `store`
/// (`BaselineStore` never enters them at all), and only `device_compliance`
/// needs both. A single "both-or-neither" gate at construction time (this
/// factory's FIRST-draft shape, reverted) would make baseline_store's mere
/// absence 503 every OTHER method too — a real behaviour regression this
/// factory's nullable-pointer shape avoids, matching the resource's existing
/// per-route store-unavailable 503 today: a null `store` degrades every
/// method (`std::unexpected`/`nullopt`/empty-vector, per each method's own
/// return shape); `device_compliance` ADDITIONALLY degrades
/// (`*store_degraded = true`) when `baseline_store` alone is null, even with
/// `store` present. `make_local_guardian_api` is therefore called
/// UNCONDITIONALLY (server.cpp constructs the seam whether or not either
/// store is present) — same posture as `make_local_dex_perf_api`, and unlike
/// `make_local_workflow_api`/`make_local_schedule_api`'s store-gated
/// construction.
///
/// LIFETIME CONTRACT (load-bearing, mirrors `dex_perf_api_local.hpp`): each
/// pointer is BORROWED, NOT owned — it MUST outlive every call to the
/// returned API. `ServerImpl::stop()` joins the web thread
/// (`web_server_->stop()` + `web_thread_.join()`) before either store is
/// destroyed — explicitly for `guaranteed_state_store_` (`stop()`'s own
/// `.reset()` call), implicitly via member-declaration order for
/// `baseline_store_` (torn down after `stop()` returns, in `~ServerImpl`).
/// Either way, no in-flight REST/MCP handler can be mid-call into a store
/// by the time it is destroyed.
[[nodiscard]] std::shared_ptr<GuardianApi>
make_local_guardian_api(GuaranteedStateStore* store, BaselineStore* baseline_store);

} // namespace yuzu::server
