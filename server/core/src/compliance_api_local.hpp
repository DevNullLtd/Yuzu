#pragma once

/// @file compliance_api_local.hpp
/// CORE-ONLY. The store-backed factory for the compliance seam (ADR-0031
/// WS-A4, mirroring `network_api_local.hpp`/`verify_api_local.hpp`). Included
/// by server.cpp (wiring) and the impl/tests — NEVER by a
/// presentation/renderer/route TU; the seam-closure lint forbids
/// `*_api_local.hpp` in the family's presentation TUs so the abstract/local
/// boundary is enforced, not conventional.
///
/// Store types stay FORWARD-DECLARED here (zero store `#include`s) — this
/// header is the core side of the ADR-0031 WS-A4 seam, not the store layer.
/// That purity is lint-enforced: this header is itself in the family's
/// enforced closure set, so a store `#include` added here fails CI.

#include <memory>

#include "compliance_api.hpp"

namespace yuzu::server {

class PolicyStore;

/// Factory for the store-backed implementation (`LocalComplianceApi`,
/// compliance_api.cpp — kept out of the abstract header so that header stays
/// free of store references entirely).
///
/// LIFETIME CONTRACT (load-bearing for the per-family seam pattern this
/// mirrors from `network_api_local.hpp`/`verify_api_local.hpp`): `store` is
/// borrowed, NOT owned — it MUST outlive every call to the returned API.
/// Today `ServerImpl` guarantees this by joining the web thread
/// (`web_server_->stop()`) before it destroys the stores, so no handler can
/// reach the API after they die. A future family copying this shape MUST
/// preserve that ordering (or hold the API with a lifetime <= its stores) —
/// this snapshot-at-construction idiom UAFs if the store is torn down first.
[[nodiscard]] std::shared_ptr<ComplianceApi> make_local_compliance_api(PolicyStore& store);

} // namespace yuzu::server
