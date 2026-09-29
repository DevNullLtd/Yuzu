#pragma once

/// @file verify_api_local.hpp
/// CORE-ONLY. The store-backed factory for the verify seam (ADR-0031 WS-A4
/// #4250, mirroring `network_api_local.hpp`). Included by server.cpp
/// (wiring) and the impl/tests — NEVER by a presentation/renderer/route TU;
/// the seam-closure lint forbids `*_api_local.hpp` in the family's
/// presentation TUs so the abstract/local boundary is enforced, not
/// conventional.
///
/// Store types stay FORWARD-DECLARED here (zero store `#include`s) — this
/// header is the core side of the ADR-0031 WS-A4 seam, not the store layer.
/// That purity is lint-enforced: this header is itself in the family's
/// enforced closure set, so a store `#include` added here fails CI.

#include <memory>

#include "verify_api.hpp"

namespace yuzu::server {

class ManagementGroupStore;
class AppPerfCohortReader;

/// Factory for the store-backed implementation (`LocalVerifyApi`,
/// verify_api.cpp — kept out of the abstract header so that header stays
/// free of store references entirely).
///
/// `cohort_reader` is nullable — server.cpp constructs `AppPerfCohortReader`
/// with "no fail-closed gate — it degrades to nullopt" (its own header
/// comment), a Postgres-dependent startup path distinct from
/// `ManagementGroupStore`'s OWN fail-closed open gate. A null reader makes
/// every `compare()` call return the AUTHORITATIVE-degrade `nullopt`, the
/// same posture as the prior server.cpp provider closure's
/// `!app_perf_cohort_reader_` arm.
///
/// `groups` is NOT nullable — `ManagementGroupStore` fails startup CLOSED on
/// an open failure (ADR-0012 §1), so by the time routes are serving requests
/// it is always live.
///
/// LIFETIME CONTRACT (load-bearing for the per-family seam pattern this
/// mirrors from `network_api_local.hpp`): `groups` and `*cohort_reader` are
/// borrowed, NOT owned — they MUST outlive every call to the returned API.
/// Today `ServerImpl` guarantees this by joining the web thread
/// (`web_server_->stop()`) before it destroys these stores, so no handler can
/// reach the API after they die. A future family copying this shape MUST
/// preserve that ordering (or hold the API with a lifetime <= its stores) —
/// this snapshot-at-construction idiom UAFs if the stores are torn down
/// first.
[[nodiscard]] std::shared_ptr<VerifyApi>
make_local_verify_api(ManagementGroupStore& groups, AppPerfCohortReader* cohort_reader);

} // namespace yuzu::server
