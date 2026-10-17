#pragma once

/// @file crypto_api.hpp
/// The TENTH per-family in-process API seam for the presentation/core/engine split (ADR-0031,
/// WS-A4), covering the `/crypto` crypto-library-presence READ surface (REST `GET
/// /api/v1/crypto/libraries[/devices]`, the dashboard fragments and the MCP twins
/// `get_crypto_libraries` / `list_crypto_library_devices`). Abstract, ZERO store-shaped
/// dependencies - it includes only the pure `crypto_types.hpp`, `authz_model.hpp` and std
/// headers. The store-backed factory lives in the core-only `crypto_api_local.hpp`.
///
/// One method per public resource: a presentation/MCP caller consumes only what the public,
/// versioned core API serves (INV-31-4). Both methods take the caller's `authz::VisibleSet`
/// and push it into the read (ADR-0017 / ADR-0033): nullopt = unfiltered, present-empty =
/// deny-all.

#include "authz_model.hpp"
#include "crypto_types.hpp"

#include <expected>
#include <string>

namespace yuzu::server {

/// Why a read failed. kDegraded = the backing read could not be answered (surface as 503 +
/// retry, NEVER as an empty result); kInvalid = the request was refused (a bad cursor) and
/// `message` is the 400 text.
struct CryptoReadError {
    enum class Kind { kDegraded, kInvalid };
    Kind kind{Kind::kDegraded};
    std::string message;
};

class CryptoApi {
public:
    virtual ~CryptoApi() = default;

    /// The family summary behind `GET /api/v1/crypto/libraries` and its twins.
    [[nodiscard]] virtual std::expected<CryptoSummary, CryptoReadError>
    library_summary(const CryptoSummaryQuery& q, const authz::VisibleSet& scope) const = 0;

    /// One family's device drill behind `GET /api/v1/crypto/libraries/devices` and its twins.
    [[nodiscard]] virtual std::expected<CryptoDevicesPage, CryptoReadError>
    library_devices(const CryptoDevicesQuery& q, const authz::VisibleSet& scope) const = 0;
};

} // namespace yuzu::server
