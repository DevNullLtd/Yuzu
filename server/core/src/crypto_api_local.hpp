#pragma once

/// @file crypto_api_local.hpp
/// CORE-ONLY. The store-backed factory for the crypto-library seam (ADR-0031 WS-A4, tenth
/// family, mirroring `schedule_api_local.hpp`). Included by server.cpp (wiring), the impl
/// (crypto_api.cpp) and the tests - NEVER by a presentation/renderer/route TU; the
/// seam-closure lint enforces that. Store types stay FORWARD-DECLARED here.

#include "crypto_api.hpp"
#include "crypto_read_gate.hpp"

#include <memory>

namespace yuzu::server {

class SoftwareInventoryStore;
class DeviceApi;
class CaStore;
class CryptoDashboardLayoutStore;

/// What the store-backed implementation reads. EVERY store is NULLABLE: a null store degrades
/// the methods that read it (kDegraded, "unavailable"), never answers them empty, and leaves
/// the other methods working - so a server without the software-inventory store still serves
/// the Yuzu-issued widgets and the layout. `devices` only supplies hostnames for the library
/// drill; null leaves them empty.
/// `max_concurrent_reads` bounds the store calls this instance (one per process) holds in flight
/// across ALL its methods (library, Yuzu-issued and layout, the layout write included); a call
/// over the bound is refused at once as kDegraded ("crypto read capacity in use; retry") with no
/// store call. 0 refuses every call (tests).
///
/// LIFETIME CONTRACT: every pointer is BORROWED, NOT owned, and must outlive every call to the
/// returned API. `ServerImpl` joins the web thread before destroying any of them.
struct LocalCryptoApiDeps {
    SoftwareInventoryStore* software = nullptr;
    const DeviceApi* devices = nullptr;
    CaStore* ca = nullptr;
    CryptoDashboardLayoutStore* layouts = nullptr;
    int max_concurrent_reads = kMaxConcurrentCryptoReads;
};

[[nodiscard]] std::shared_ptr<CryptoApi> make_local_crypto_api(const LocalCryptoApiDeps& deps);

/// The library-only shorthand (the slice-1 tests): `store` required, no CA, no layout store.
[[nodiscard]] std::shared_ptr<CryptoApi>
make_local_crypto_api(SoftwareInventoryStore& store, const DeviceApi* device_api,
                      int max_concurrent_reads = kMaxConcurrentCryptoReads);

} // namespace yuzu::server
