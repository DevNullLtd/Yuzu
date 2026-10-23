#pragma once

/// @file crypto_api_local.hpp
/// CORE-ONLY. The store-backed factory for the crypto-library seam (ADR-0031 WS-A4, tenth
/// family, mirroring `schedule_api_local.hpp`). Included by server.cpp (wiring), the impl
/// (crypto_api.cpp) and the tests - NEVER by a presentation/renderer/route TU; the
/// seam-closure lint enforces that. Store types stay FORWARD-DECLARED here.

#include "crypto_api.hpp"
#include "crypto_read_gate.hpp"

#include <chrono>
#include <functional>
#include <memory>
#include <string_view>

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
///
/// Admission: the library and Yuzu-issued reads share ONE per-process bound on in-flight store
/// calls; a call over it is refused at once as kDegraded/kCapacity ("busy") with no store call.
/// The bound is `max_concurrent_reads`, narrowed to max(1, pool_size / 4) when `pool_size` is
/// known (> 0), so /crypto never holds more than a quarter of the shared PgPool; with
/// `pool_size` 1..3 the Yuzu-issued reads are refused outright (busy), leaving the small pool to
/// RBAC, audit and ingest, and with `pool_size` 1 the library reads are refused too (M3), so the
/// mTLS-accept `is_revoked` check always keeps the one connection. `max_concurrent_reads` 0
/// refuses every admission-bounded call (tests); `pool_size` 0 means "unknown" and narrows
/// nothing. The layout read and save are NOT admission-bounded: one short keyed statement each,
/// bounded by the pool's own lease timeout.
///
/// `shared_read_ttl` > 0 shares the unfiltered, unconfined library summary (slice 1) across
/// callers for that long: one store read per window per process, concurrent callers waiting on
/// the read in flight (single flight). 0 (the tests' default) reads every time. The Yuzu-issued
/// stats read is NEVER shared: every call reads at request time through the admission gate
/// (ADR-0070 "The CaStore count method": bounded by admission limits, not a cached count).
///
/// `note_degrade(source, reason)` is told of every shed and degraded read on the Yuzu-issued and
/// layout paths, with closed label values only: source `ca_issued` | `crypto_layout`, reason
/// `admission_full` | `store_not_open` | `pool_acquire_timeout` | `query_error`. The library
/// path keeps `SoftwareInventoryStore::note_read_shed`. Never a username or widget id.
///
/// LIFETIME CONTRACT: every pointer is BORROWED, NOT owned, and must outlive every call to the
/// returned API. `ServerImpl` joins the web thread before destroying any of them.
struct LocalCryptoApiDeps {
    SoftwareInventoryStore* software = nullptr;
    const DeviceApi* devices = nullptr;
    CaStore* ca = nullptr;
    CryptoDashboardLayoutStore* layouts = nullptr;
    int max_concurrent_reads = kMaxConcurrentCryptoReads;
    int pool_size = 0;
    std::chrono::seconds shared_read_ttl{0};
    std::function<void(std::string_view source, std::string_view reason)> note_degrade;
    /// M2: bound a pinned as_of to [db_now - 7 days, db_now + 300 s] on the database clock.
    /// false ONLY in tests that pin a fixed calendar instant; production never sets it.
    bool bound_pinned_as_of = true;
};

/// The admission bound `make_local_crypto_api` derives (see LocalCryptoApiDeps).
[[nodiscard]] constexpr int crypto_admission_bound(int max_concurrent_reads, int pool_size) {
    if (pool_size <= 0)
        return max_concurrent_reads;
    const int quarter = pool_size / 4 > 1 ? pool_size / 4 : 1;
    return max_concurrent_reads < quarter ? max_concurrent_reads : quarter;
}

/// Pools this small refuse the Yuzu-issued reads outright (see LocalCryptoApiDeps).
inline constexpr int kCryptoCaMinPoolSize = 4;
/// Pools this small refuse the library reads outright too (M3): a pool of one connection must
/// stay free for the mTLS-accept revocation check.
inline constexpr int kCryptoLibraryMinPoolSize = 2;

[[nodiscard]] std::shared_ptr<CryptoApi> make_local_crypto_api(const LocalCryptoApiDeps& deps);

/// The library-only shorthand (the slice-1 tests): `store` required, no CA, no layout store.
[[nodiscard]] std::shared_ptr<CryptoApi>
make_local_crypto_api(SoftwareInventoryStore& store, const DeviceApi* device_api,
                      int max_concurrent_reads = kMaxConcurrentCryptoReads);

} // namespace yuzu::server
