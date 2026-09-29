#pragma once

/// @file network_api_local.hpp
/// CORE-ONLY. The store-backed factory for the network seam. Included by
/// server.cpp (wiring) and the impl/tests — NEVER by a presentation/renderer/
/// route TU; the seam-closure lint forbids `*_api_local.hpp` in the family's
/// presentation TUs so the abstract/local boundary is enforced, not
/// conventional.
///
/// Store types stay FORWARD-DECLARED here (zero store `#include`s) — this
/// header is the core side of the ADR-0031 WS-A4 seam, not the store layer.
/// That purity is lint-enforced: this header is itself in the family's
/// enforced closure set, so a store `#include` added here fails CI.

#include <memory>

#include "network_api.hpp"

namespace yuzu::server {

class TagStore;
namespace detail {
class AgentHealthStore;
class AgentRegistry;
} // namespace detail

/// Factory for the store-backed implementation (`LocalNetworkApi`,
/// network_api.cpp — kept out of the abstract header so that header stays
/// free of store references entirely). `tags` is nullable — a null TagStore
/// degrades to no cohort resolution / empty `available_keys`, same posture as
/// the prior server.cpp assembly. The returned object is non-copyable (holds
/// a mutex for its internal 5s TTL memo) — held by shared_ptr so it composes
/// with the existing `std::function`-based route-provider wiring.
///
/// LIFETIME CONTRACT (load-bearing for the per-family seam pattern this pilots):
/// `health`, `registry` and `*tags` are borrowed, NOT owned — they MUST outlive
/// every call to the returned API. Today `ServerImpl` guarantees this by joining
/// the web thread (`web_server_->stop()`) before it destroys these stores, so no
/// handler can reach the API after they die. A future family copying this shape
/// MUST preserve that ordering (or hold the API with a lifetime <= its stores) —
/// this snapshot-at-construction idiom UAFs if the stores are torn down first.
[[nodiscard]] std::shared_ptr<NetworkApi>
make_local_network_api(detail::AgentHealthStore& health, detail::AgentRegistry& registry,
                       TagStore* tags);

} // namespace yuzu::server
