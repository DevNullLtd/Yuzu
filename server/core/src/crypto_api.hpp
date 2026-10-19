#pragma once

/// @file crypto_api.hpp
/// The TENTH per-family in-process API seam for the presentation/core/engine split (ADR-0031,
/// WS-A4), covering the `/crypto` surface: the crypto-library-presence reads (REST `GET
/// /api/v1/crypto/libraries[/devices]`, the dashboard fragments and the MCP twins
/// `get_crypto_libraries` / `list_crypto_library_devices`), the Yuzu-issued certificate widget
/// reads (`GET /api/v1/crypto/ca/stats` and its twin; the filtered `GET /api/v1/ca/issued` and
/// its twin) and the per-operator widget layout (`GET/PUT /api/v1/crypto/dashboard/layout` and
/// twins). Abstract, ZERO store-shaped
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
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// Why a read failed.
///   kDegraded       the backing read could not be answered (503 + retry, NEVER an empty result;
///                   `cause` says which: a store fault, or the admission bound - "busy");
///   kInvalid        the request was refused (a bad parameter or cursor); `message` is the 400;
///   kConflict       a layout save named an `expected_version` that is no longer the stored
///                   one (another tab or client saved first): reload, then save again (409);
///   kCorrupt        the stored layout cannot be read as a layout (an element is not a string):
///                   not retryable; a save with `expected_version = version` replaces it (Reset);
///   kOutcomeUnknown a layout save was sent but its commit outcome is unknown (the connection
///                   was lost after sending): 503, "reload to check" - never reported as a
///                   failure that did not happen, nor as a success.
struct CryptoReadError {
    enum class Kind { kDegraded, kInvalid, kConflict, kCorrupt, kOutcomeUnknown };
    Kind kind{Kind::kDegraded};
    std::string message;
    CryptoReadCause cause{CryptoReadCause::kNone}; ///< set on kDegraded only
    /// kCorrupt: the corrupt row's version (pass it as expected_version to replace it);
    /// kConflict: the stored version now (0 = nothing stored).
    std::int64_t version{0};
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
    // scope. The CALLER gates them before calling: the counts on Inventory:Read and withheld
    // from a confined caller (ADR-0070 R2), the certificate rows on Security:Read (the filtered
    // GET /api/v1/ca/issued and the dashboard drill). Every window is computed against one
    // `as_of` - Postgres now() when the caller passes none (R4) - echoed back (D13 conditions
    // 2 and 3).

    /// Every Yuzu-issued count behind `GET /api/v1/crypto/ca/stats` and `get_crypto_ca_stats`.
    /// `as_of` nullopt = the database's now(); such reads are shared: one store read per
    /// process per cache window, concurrent callers waiting on the one in flight.
    [[nodiscard]] virtual std::expected<CaCertStats, CryptoReadError>
    ca_stats(std::optional<std::int64_t> as_of) const = 0;

    /// The Yuzu-issued certificates behind one count (the filtered `GET /api/v1/ca/issued`,
    /// `list_issued_certs` with filters, and the dashboard drill). kInvalid = a window outside
    /// the closed set, a week start that is not a Monday 00:00 UTC, a bucket on a kind that is
    /// not revoked, or a limit/offset out of range.
    [[nodiscard]] virtual std::expected<CaCertPage, CryptoReadError>
    ca_certificates(const CaCertQuery& q) const = 0;

    /// `username`'s OWN dashboard layout: the stored ids this build knows (unknown ones are
    /// counted in `preserved_unknown`, not drawn), or the catalogue default (`is_default`,
    /// version 0) when none is stored. A degraded read is kDegraded and a corrupt row kCorrupt -
    /// never the default served as if nothing were stored. Not admission-bounded (the pool's
    /// own lease bound applies).
    [[nodiscard]] virtual std::expected<CryptoDashboardLayout, CryptoReadError>
    dashboard_layout(const std::string& username) const = 0;

    /// Replace `username`'s layout and return it as stored. `expected_version`: nullopt =
    /// replace whatever is stored; 0 = only if nothing is stored; n = only if the stored version
    /// is n (else kConflict). Stored ids this build does not know are kept, after the caller's,
    /// capped at the catalogue's layout bound. kInvalid = more than
    /// crypto_widgets::kMaxLayoutWidgets ids, an id outside the catalogue, a repeat, or a
    /// username the store cannot key (the message is the 400 text).
    [[nodiscard]] virtual std::expected<CryptoDashboardLayout, CryptoReadError>
    set_dashboard_layout(const std::string& username, const std::vector<std::string>& widgets,
                         std::optional<std::int64_t> expected_version) const = 0;
};

} // namespace yuzu::server
