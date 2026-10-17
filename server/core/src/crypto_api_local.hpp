#pragma once

/// @file crypto_api_local.hpp
/// CORE-ONLY. The store-backed factory for the crypto-library seam (ADR-0031 WS-A4, tenth
/// family, mirroring `schedule_api_local.hpp`). Included by server.cpp (wiring), the impl
/// (crypto_api.cpp) and the tests - NEVER by a presentation/renderer/route TU; the
/// seam-closure lint enforces that. Store types stay FORWARD-DECLARED here.

#include "crypto_api.hpp"

#include <memory>

namespace yuzu::server {

class SoftwareInventoryStore;
class DeviceApi;

/// Factory for the store-backed implementation. `store` is required (a reference: callers
/// guard their own store-unavailable 503 before wiring, as the schedule seam does); a store
/// that is not open degrades every read (kDegraded), never an empty answer. `device_api` is
/// NULLABLE - it only supplies hostnames for the drill; null leaves them empty.
///
/// LIFETIME CONTRACT: both are BORROWED, NOT owned, and must outlive every call to the
/// returned API. `ServerImpl` joins the web thread before destroying either.
[[nodiscard]] std::shared_ptr<CryptoApi> make_local_crypto_api(SoftwareInventoryStore& store,
                                                               const DeviceApi* device_api);

} // namespace yuzu::server
