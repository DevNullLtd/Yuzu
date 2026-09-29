#include "config_secret_keys.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <string>

namespace yuzu::server {

// Constant-initialised, so there is no static-initialisation-order question at all:
// `AuditStore::query()` reaches this from another TU, and a dynamically-initialised
// namespace-scope vector would have been safe only by audit (no static-duration
// caller exists today) rather than by construction.
//
// Adding a secret-valued key to RuntimeConfigStore's allow-list without adding it
// here is the mistake this list exists to make hard: the value would go straight to
// the startup log, GET /api/config, the PUT audit detail and the PUT response echo.
// The name-shaped TRIPWIRE in test_runtime_config_secret_redaction.cpp catches the
// common spellings. Before adding one, also grep the `get(`/`get_value(` call sites
// for it -- redaction changes what an existing FUNCTIONAL consumer receives, and
// that failure is silent.
inline constexpr std::array<std::string_view, 1> kSecretKeys{
    "oidc_client_secret",
};

namespace {
/// Shared trim: strip bytes at or below 0x20 from both ends. The `unsigned char` cast
/// is load-bearing - `char` is signed on x86-64 and unsigned on aarch64, so a byte
/// >= 0x80 (any UTF-8 lead or continuation) would otherwise compare negative on one
/// and positive on the other.
std::string_view trim_ctrl(std::string_view v) {
    const auto keep = [](unsigned char c) { return c > 0x20; };
    std::size_t b = 0, e = v.size();
    while (b < e && !keep(static_cast<unsigned char>(v[b])))
        ++b;
    while (e > b && !keep(static_cast<unsigned char>(v[e - 1])))
        --e;
    return v.substr(b, e - b);
}
} // namespace

bool is_redaction_placeholder(std::string_view value) {
    // Two rules, both failing CLOSED, because the costs are asymmetric: refusing an
    // implausible secret costs an error message, accepting a padded placeholder
    // destroys a live credential.
    //   1. ignore surrounding bytes at or below 0x20;
    //   2. then refuse EQUALS or CONTAINS.
    // Rule 2 currently subsumes rule 1 (every byte of "<redacted>" is above 0x20, so
    // trimming the ends can neither create nor destroy an occurrence). Rule 1 is kept
    // so a later narrowing of rule 2 cannot silently re-open the whitespace hole; it
    // is not load-bearing today and NO TEST protects it, because none can while rule 2
    // stands.
    const std::string_view trimmed = trim_ctrl(value);
    if (trimmed.empty())
        return false;
    return trimmed.find(kRedactedPlaceholder) != std::string_view::npos;
}

bool is_exactly_redaction_placeholder(std::string_view value) {
    return trim_ctrl(value) == kRedactedPlaceholder;
}

bool is_secret_config_key(std::string_view key) {
    return std::ranges::find(kSecretKeys, key) != kSecretKeys.end();
}

} // namespace yuzu::server
