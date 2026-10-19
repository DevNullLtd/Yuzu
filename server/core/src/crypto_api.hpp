#pragma once

/// @file crypto_api.hpp
/// The TENTH per-family in-process API seam for the presentation/core/engine split (ADR-0031,
/// WS-A4), covering the `/crypto` surface: the crypto-library-presence reads (REST `GET
/// /api/v1/crypto/libraries[/devices]`, the dashboard fragments and the MCP twins
/// `get_crypto_libraries` / `list_crypto_library_devices`), the Yuzu-issued certificate widget
/// reads (`GET /api/v1/crypto/ca/{stats,certificates}` and twins) and the per-operator widget
/// layout (`GET/PUT /api/v1/crypto/dashboard/layout` and twins). Abstract, ZERO store-shaped
/// dependencies - it includes only the pure `crypto_types.hpp`, `authz_model.hpp` and std
/// headers. The store-backed factory lives in the core-only `crypto_api_local.hpp`.
///
/// One method per public resource: a presentation/MCP caller consumes only what the public,
/// versioned core API serves (INV-31-4). The two library methods take the caller's
/// `authz::VisibleSet` and push it into the read (ADR-0017 / ADR-0033): nullopt = unfiltered,
/// present-empty = deny-all.

#include "authz_model.hpp"
#include "crypto_types.hpp"

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace yuzu::server {

/// Why a read failed. kDegraded = the backing read could not be answered (surface as 503 +
/// retry, NEVER as an empty result; `cause` says which); kInvalid = the request was refused (a
/// bad cursor) and `message` is the 400 text.
struct CryptoReadError {
    enum class Kind { kDegraded, kInvalid };
    Kind kind{Kind::kDegraded};
    std::string message;
    CryptoReadCause cause{CryptoReadCause::kNone}; ///< set on kDegraded only
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

    // ── Dashboard widgets (ADR-0070 D13) ────────────────────────────────────────────
    // The Yuzu-issued reads take no VisibleSet: Yuzu's own PKI inventory has no per-device
    // scope, and the routes gate them on Security:Read (the same gate as GET /api/v1/ca/issued)
    // before calling. `as_of` is the server clock the caller read once for the request; every
    // window is computed against it and echoed back (D13 conditions 2 and 3).

    /// Every Yuzu-issued count behind `GET /api/v1/crypto/ca/stats` and `get_crypto_ca_stats`.
    [[nodiscard]] virtual std::expected<CaCertStats, CryptoReadError>
    ca_stats(std::int64_t as_of) const = 0;

    /// The Yuzu-issued certificates behind one count (`GET /api/v1/crypto/ca/certificates`,
    /// `list_crypto_ca_certificates`). kInvalid = a window outside the closed set, a week start
    /// that is not a Monday 00:00 UTC, or an offset out of range; `limit` is clamped to
    /// [1, crypto_widgets::kCertPageMax].
    [[nodiscard]] virtual std::expected<CaCertPage, CryptoReadError>
    ca_certificates(const CaCertQuery& q, std::int64_t as_of) const = 0;

    /// `username`'s OWN dashboard layout: the stored ids still in the catalogue, or the catalogue
    /// default (`is_default`) when none is stored. A degraded read is kDegraded - never the
    /// default served as if nothing were stored.
    [[nodiscard]] virtual std::expected<CryptoDashboardLayout, CryptoReadError>
    dashboard_layout(const std::string& username) const = 0;

    /// Replace `username`'s layout and return it as stored. kInvalid = more than
    /// crypto_widgets::kMaxLayoutWidgets ids, an id outside the catalogue, or a repeat (the
    /// message is the 400 text).
    [[nodiscard]] virtual std::expected<CryptoDashboardLayout, CryptoReadError>
    set_dashboard_layout(const std::string& username, const std::vector<std::string>& widgets) const = 0;
};

} // namespace yuzu::server
