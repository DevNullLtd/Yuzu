#pragma once

/// @file device_api_local.hpp
/// CORE-ONLY. The store-backed factory for the device seam. Included by
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

#include "device_api.hpp"

namespace yuzu::server {

class TagStore;
namespace detail {
class AgentRegistry;
} // namespace detail

/// Factory for the store-backed implementation (`LocalDeviceApi`,
/// device_api.cpp — kept out of the abstract header so that header stays
/// free of store references entirely). `tags` is nullable — a null TagStore
/// degrades `lookup_device`'s `tags` field to an empty vector (same posture
/// as `device_agent_detail_json`'s null-store degrade, except this seam
/// always returns an (empty) `tags` vector rather than omitting the key —
/// there is no JSON key to omit at this layer). The returned object is held
/// by shared_ptr so it composes with the existing `std::function`-based
/// route-provider wiring.
///
/// LIFETIME CONTRACT (load-bearing for the per-family seam pattern this
/// mirrors — see `network_api_local.hpp`'s identical paragraph): `registry`
/// and `*tags` are borrowed, NOT owned — they MUST outlive every call to the
/// returned API. Today `ServerImpl` guarantees this by joining the web
/// thread (`web_server_->stop()`) before it destroys these stores, so no
/// handler can reach the API after they die. A future family copying this
/// shape MUST preserve that ordering (or hold the API with a lifetime <= its
/// stores) — this snapshot-at-construction idiom UAFs if the stores are torn
/// down first.
[[nodiscard]] std::shared_ptr<DeviceApi>
make_local_device_api(detail::AgentRegistry& registry, TagStore* tags);

} // namespace yuzu::server
