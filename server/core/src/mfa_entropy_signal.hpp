#pragma once

/// @file mfa_entropy_signal.hpp
///
/// The ONE place the MFA CSPRNG-failure signal (#6995, follow-up to #4763) is
/// named and counted. `AuthDB` reports a CSPRNG fault while minting a TOTP
/// secret or a recovery code as `AuthDBError::EntropyUnavailable`; every route
/// that surfaces it (login enrol-init / confirm, Settings init / verify /
/// regenerate) counts it here, NOT in the store-outage counters
/// (`yuzu_auth_secret_unavailable_total`, `yuzu_auth_read_degrade_total`) —
/// no query failed, so those would send an on-call engineer after the database.
///
/// The counter is the existing `yuzu_secure_random_failure_total{reason,site}`,
/// so the label-agnostic paging recipe
///   rate(yuzu_secure_random_failure_total[5m]) > 0
/// covers MFA with no rule change. `site` is a closed set (`kAllSites` below); this
/// header's `count()` is the path for the two MFA sites:
///   mfa_enroll   — the TOTP secret draw        (mfa_init_enrollment)
///   mfa_recovery — a recovery-code or recovery-code-salt draw
///                  (mfa_verify_enrollment, mfa_regenerate_recovery_codes)
/// Add a site to `kAllSites`, never only as a literal at a call site, so `server.cpp`'s
/// boot-time pre-seeding stays in step.

#include <array>
#include <string>
#include <string_view>

#include <yuzu/metrics.hpp>

namespace yuzu::server::mfa_entropy {

inline constexpr std::string_view kMetric = "yuzu_secure_random_failure_total";
inline constexpr std::string_view kReason = "prng_failure";
inline constexpr std::string_view kSiteEnroll = "mfa_enroll";
inline constexpr std::string_view kSiteRecovery = "mfa_recovery";

/// The four token-issuance sites that already count this metric inline at their own
/// call sites (rest_api_v1.cpp, mcp_server.cpp, settings_routes.cpp). They are named
/// here ONLY so the boot-time pre-seed covers them: a series first created at the
/// moment of its first fault starts at 1 with no earlier sample, so a lone first fault
/// would not trip `rate(yuzu_secure_random_failure_total[5m]) > 0` (#6995, SRE-1).
/// A wiring test pins that each literal still appears at its call site.
inline constexpr std::string_view kSiteApiToken = "api_token";
inline constexpr std::string_view kSiteApiTokenHtmx = "api_token_htmx";
inline constexpr std::string_view kSiteDeviceToken = "device_token";
inline constexpr std::string_view kSiteEnginePrincipal = "engine_principal";

/// EVERY `site` value this metric carries. `server.cpp` pre-seeds one series per entry.
/// Adding a site means adding it here, so the pre-seed and the docs row stay in step.
inline constexpr auto kAllSites = std::to_array<std::string_view>(
    {kSiteApiToken, kSiteApiTokenHtmx, kSiteDeviceToken, kSiteEnginePrincipal, kSiteEnroll,
     kSiteRecovery});

/// Count one MFA CSPRNG fault at `site` (one of the constants above). Null
/// registry is a no-op (unit-test harnesses without metrics).
inline void count(yuzu::MetricsRegistry* m, std::string_view site) {
    if (m == nullptr)
        return;
    m->counter(std::string{kMetric},
               {{"reason", std::string{kReason}}, {"site", std::string{site}}})
        .increment();
}

} // namespace yuzu::server::mfa_entropy
