#pragma once

/// @file ca_panel_render.hpp
///
/// Pure renderer for the System > Certificates and secrets CA panels (Certificate
/// authority | Revocation | Issued certificates). Selected by `?view=pki` on
/// `GET /fragments/settings/ca`; the default Settings shape (`render_ca_fragment`
/// in ca_routes.cpp) is untouched. A view model goes in, HTML comes out: no store,
/// no clock, no crypto, so every state is a unit-test fixture.
///
/// Every operator- or agent-influenced string goes through html_escape.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::ca_panel {

enum class Availability {
    Ready,       ///< a root exists
    Unavailable, ///< ca_store null or closed
    StoreError,  ///< get_root() failed
    NoRoot,      ///< no internal CA on this install
};

struct Root {
    std::string algo;
    std::string fingerprint_sha256; ///< colon-hex, as stored
    std::int64_t not_after{0};
    bool subordinate{false};
};

/// What the revocation list status pill says. Derived by the caller from
/// `latest_crl()` and `has_unpublished_revocations()`.
enum class CrlState {
    Current,      ///< a CRL exists and covers every revocation
    OutOfDate,    ///< a CRL exists but a revocation is not on it
    NotPublished, ///< no CRL exists yet (or the store could not be read)
    Unconfirmed,  ///< a CRL exists but cannot be compared with the revoked set
    Expired,      ///< the latest CRL's next_update has passed (counts may still match)
};

struct Crl {
    bool present{false};
    std::int64_t version{0};
    std::int64_t published_at{0};
    std::int64_t next_update{0};
    std::optional<std::int64_t> revoked_count; ///< nullopt on pre-v3 rows: "Not recorded", never 0
    CrlState state{CrlState::NotPublished};
};

struct IssuedRow {
    std::string serial_hex;
    std::string subject;
    std::string purpose;
    std::int64_t not_after{0};
    bool revoked{false};
};

struct Model {
    Availability availability{Availability::Unavailable};
    Root root;
    Crl crl;
    bool inventory_error{false}; ///< list_issued() failed
    /// Non-empty = the caller may not list the issued certificates (confined view, or the
    /// access check is degraded or unwired): `issued` is left empty and this note renders in
    /// place of the table. The CA metadata, CRL figures and import form still render.
    std::string inventory_note;
    std::vector<IssuedRow> issued;
    std::size_t panel_limit{500}; ///< rows requested; hitting it shows the cap banner
    std::int64_t now{0};          ///< epoch seconds, for the Expired rule
};

/// "Agent identity", "Code signing", the raw string for any other purpose (the
/// caller escapes). Never empty for a non-empty purpose.
std::string purpose_label(std::string_view purpose);

/// Purpose-aware revoke confirmation (plain text; the renderer escapes it into the
/// attribute). Does not promise a runtime effect the server has not verified.
std::string revoke_confirm_text(std::string_view purpose, std::string_view subject);

/// Expired = not_after is set and has passed (an unrevoked certificate only).
bool is_expired(std::int64_t not_after, std::int64_t now) noexcept;

/// "YYYY-MM-DD" and "YYYY-MM-DD HH:MM" in UTC; "—" for a zero epoch.
std::string format_utc_date(std::int64_t epoch);
std::string format_utc_minute(std::int64_t epoch);

/// The whole fragment body.
std::string render(const Model& m);

} // namespace yuzu::server::ca_panel
