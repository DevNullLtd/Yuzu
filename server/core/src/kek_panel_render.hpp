#pragma once

/// @file kek_panel_render.hpp
///
/// Pure renderer for the System > Certificates and secrets "Key-encryption key" panel
/// (status only). Built from `KekOpResult` fields by `GET /fragments/settings/kek`;
/// no store, codec or clock in here, so every state is a unit-test fixture.
///
/// Fixed sentences only for the failure states: a codec or driver string is never
/// interpolated (kek_routes.hpp rule B).

#include <cstdint>
#include <optional>
#include <string>

namespace yuzu::server::kek_panel {

enum class Availability {
    Ready,
    Unavailable,   ///< ops.status unset, or Failure::Unavailable
    QueryCanceled, ///< Failure::QueryCanceled
    Internal,      ///< anything else
};

struct Model {
    Availability availability{Availability::Unavailable};
    std::uint32_t active_version{0};
    std::optional<std::uint32_t> oldest_in_use; ///< nullopt: no stored secrets
    bool rotation_complete{false};
    std::optional<std::uint32_t> live_versions;  ///< nullopt: unknown, never 0
    std::optional<bool> lock_held;               ///< nullopt: unknown, never "Free"
    std::optional<int> lock_holder_pid;
    std::string lock_captured_at;                ///< preformatted "HH:MM:SS UTC", or empty
};

std::string render(const Model& m);

} // namespace yuzu::server::kek_panel
