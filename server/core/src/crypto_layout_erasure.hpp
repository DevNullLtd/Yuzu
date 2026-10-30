#pragma once

/// @file crypto_layout_erasure.hpp
/// The closed reason set of `yuzu_server_crypto_layout_erase_failures_total{reason}` (ADR-0071
/// deprovision erasure of `/crypto` dashboard layouts) and the mapping from a layout-store
/// failure to its reason. One copy, shared by the boot pre-seed and the emitter in `server.cpp`
/// and unit-tested in `test_crypto_dashboard_layout_store.cpp`, so the reason set the alert
/// (`YuzuCryptoLayoutEraseFailed`, any reason) and the docs list cannot drift from what is
/// counted. Pure decision code: no I/O.

#include "crypto_dashboard_layout_store.hpp"
#include "deprovision_erasure.hpp"

#include <array>
#include <optional>
#include <string_view>

namespace yuzu::server::crypto_layout_erasure {

/// The counter's name, as the alert expression in docs/prometheus/yuzu-alerts.yml spells it.
inline constexpr std::string_view kMetric = "yuzu_server_crypto_layout_erase_failures_total";

inline constexpr std::string_view kStoreNotOpen = "store_not_open";
inline constexpr std::string_view kPoolAcquireTimeout = "pool_acquire_timeout";
inline constexpr std::string_view kOutcomeUnknown = "outcome_unknown";
inline constexpr std::string_view kQueryError = "query_error";
/// The erasure ran on the slug alone: the linked identities could not be read (R2-1).
inline constexpr std::string_view kLinkReadFailed = kErasureLinkReadFailed;

/// Every reason, each pre-seeded to 0 at boot.
inline constexpr std::array<std::string_view, 5> kReasons{
    kStoreNotOpen, kPoolAcquireTimeout, kOutcomeUnknown, kQueryError, kLinkReadFailed};

/// The reason an `erase` failure is counted under; nullopt = not a failure (a principal the
/// store cannot key - oversized or non-UTF-8 - owns no row, so there is nothing to erase).
[[nodiscard]] constexpr std::optional<std::string_view>
reason_for(CryptoLayoutStoreError::Kind kind) noexcept {
    using Kind = CryptoLayoutStoreError::Kind;
    switch (kind) {
    case Kind::kInvalidInput:
        return std::nullopt;
    case Kind::kNotOpen:
        return kStoreNotOpen;
    case Kind::kPoolAcquireTimeout:
        return kPoolAcquireTimeout;
    case Kind::kOutcomeUnknown:
        return kOutcomeUnknown;
    case Kind::kQueryError:
    case Kind::kConflict:
    case Kind::kCorrupt:
        break;
    }
    return kQueryError;
}

} // namespace yuzu::server::crypto_layout_erasure
