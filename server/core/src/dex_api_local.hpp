#pragma once

/// @file dex_api_local.hpp
/// CORE-ONLY. The store-backed factory for the DEX signals seam (ADR-0031
/// WS-A4, mirroring `verify_api_local.hpp` / `network_api_local.hpp`).
/// Included by server.cpp (wiring), the impl (dex_api.cpp) and the tests —
/// NEVER by a presentation/renderer/route TU; the seam-closure lint forbids
/// `*_api_local.hpp` in the family's enforced presentation TUs so the
/// abstract/local boundary is enforced, not conventional.
///
/// Store types stay FORWARD-DECLARED here (zero store `#include`s) — this
/// header is the core side of the seam, not the store layer. That purity is
/// lint-enforced: this header is itself in the family's enforced closure set,
/// so a store `#include` added here fails CI.

#include <functional>
#include <memory>

#include "dex_api.hpp"
#include "dex_score_policy_provider.hpp" // DexScorePolicyProvider::ReadFn - pure, no store type
#include "dex_types.hpp" // DexFleet — a pure POD (the FleetFn return), not a store type

namespace yuzu::server {

class GuaranteedStateStore;
class RuntimeConfigStore;

/// Supplies the cross-store `DexFleet` denominator (agent registry + health
/// snapshot), assembled in server.cpp — the SAME `dex_fleet_fn` closure
/// DexRoutes / RestApiV1 / mcp_server already share (see server.cpp). Kept as
/// a callback so this core-only header needs no AgentRegistry/health includes.
using FleetFn = std::function<DexFleet()>;

/// Factory for the store-backed implementation (`LocalDexApi`, dex_api.cpp —
/// kept out of the abstract header so that header stays free of store
/// references entirely).
///
/// `store` is NULLABLE — it mirrors the handlers' own tolerance
/// (`guaranteed_state_store_` may be unset in some configs, and every
/// `build_dex_*_model` already degrades to an empty/`-1` model on a null
/// store). A caller still guards with its own store-unavailable 503 before
/// calling the API (unchanged), so the API is reached only once the store is
/// live; the null tolerance is defense-in-depth, matching the builders.
///
/// `fleet_fn` may be empty — the impl then uses `DexFleet{}` (the honest
/// "no data" denominator), exactly as the handlers' `fleet_fn_ ? fleet_fn_()
/// : DexFleet{}` guard does today; `apps()` treats an empty `fleet_fn` as an
/// unknown population (nullopt).
///
/// LIFETIME CONTRACT (load-bearing, mirrors verify_api_local.hpp): `store` is
/// borrowed, NOT owned — it MUST outlive every call to the returned API.
/// `ServerImpl` guarantees this by joining the web thread (`web_server_->
/// stop()`) before destroying `guaranteed_state_store_`, so no handler can
/// reach the API after it dies. `fleet_fn`'s and `policy_fn`'s captures are
/// subject to the same ordering.
///
/// `policy_fn` may be empty - the impl then scores under the shipped defaults
/// (`dex_default_score_policy()`, source "default"). A `policy_fn` that returns
/// an error makes `apps()` degrade with `degraded_reason`
/// "score_policy_unavailable"; see `DexScorePolicyFn` for the contract.
[[nodiscard]] std::shared_ptr<DexApi> make_local_dex_api(GuaranteedStateStore* store,
                                                         FleetFn fleet_fn,
                                                         DexScorePolicyFn policy_fn = {});

/// The production `DexScorePolicyProvider::ReadFn`: reads the stored score policy
/// document (`kDexScorePolicyKey`) from the runtime config store. A stored value is
/// the document text, nothing stored is `nullopt`, and a failed read is an error.
/// Named here, not inline in server.cpp, so a test can run the production mapping.
/// `store` is borrowed by reference and MUST outlive the returned function.
[[nodiscard]] DexScorePolicyProvider::ReadFn
dex_score_policy_store_reader(RuntimeConfigStore& store);

} // namespace yuzu::server
