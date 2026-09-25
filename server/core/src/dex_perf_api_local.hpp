#pragma once

/// @file dex_perf_api_local.hpp
/// CORE-ONLY. The store-backed factory for the DEX app-perf-over-time seam
/// (ADR-0031 WS-A4, mirroring `dex_api_local.hpp` / `verify_api_local.hpp`).
/// Included by server.cpp (the REST + MCP consumer wiring is already live —
/// see `dex_perf_api.hpp`'s "Consumer rewire status" note; the dashboard
/// rewire completed too, #4626), the impl (dex_perf_api.cpp), and the parity
/// test — NEVER by a presentation/renderer/route TU; the
/// seam-closure lint forbids `*_api_local.hpp` in a family's enforced
/// presentation TUs so the abstract/local boundary is enforced, not
/// conventional.
///
/// Store/reader types stay FORWARD-DECLARED here (zero store `#include`s) —
/// this header is the core side of the seam, not the store layer.
///
/// `AppPerfProviders` (the pre-seam callback-bundle interface) is DELIBERATELY
/// NOT reused here — this factory takes the store/reader references directly
/// (the same pattern `dex_api_local.hpp` uses), so the seam's own construction
/// never touches `AppPerfProviders::cohort`/`CohortRead` (VerifyApi's dead-in-
/// production input shape). See `dex_app_perf_builders.hpp`'s banner.

#include "dex_perf_api.hpp"
#include "dex_perf_model.hpp" // DexPerfFn (already a pure provider seam pre-seam)

#include <memory>

namespace yuzu::server {

class AppPerfDailyStore;
class AppPerfFleetStore;
class AppPerfGroupReader;
class ManagementGroupStore;
class TagStore;

/// Factory for the store-backed implementation (`LocalDexPerfApi`,
/// dex_perf_api.cpp — kept out of the abstract header so that header stays
/// free of store references entirely).
///
/// All FIVE store/reader pointers are NULLABLE — each mirrors the pre-seam
/// `AppPerfProviders` lambdas' own tolerance (a null store/reader degrades the
/// corresponding method to `nullopt`, matching the resource's existing
/// store-unavailable 503 today). `dex_perf_fn` may be empty (degrades
/// `fleet_snapshot` to a default-constructed, all-empty `DexPerfSnapshot`,
/// matching the handlers' own `dex_perf_fn ? dex_perf_fn(key) :
/// DexPerfSnapshot{}` tolerance).
///
/// LIFETIME CONTRACT (load-bearing, mirrors `dex_api_local.hpp`): every
/// pointer is BORROWED, NOT owned — each MUST outlive every call to the
/// returned API. `ServerImpl` guarantees this by joining the web thread
/// (`web_server_->stop()`) before destroying the stores, so no handler can
/// reach the API after any of them die. `dex_perf_fn`'s captures are subject
/// to the same ordering.
[[nodiscard]] std::shared_ptr<DexPerfApi>
make_local_dex_perf_api(DexPerfFn dex_perf_fn, AppPerfFleetStore* fleet_store,
                        AppPerfDailyStore* daily_store, AppPerfGroupReader* group_reader,
                        ManagementGroupStore* mgmt_group_store, TagStore* tag_store);

} // namespace yuzu::server
