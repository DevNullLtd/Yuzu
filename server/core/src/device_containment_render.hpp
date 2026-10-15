#pragma once

/// @file device_containment_render.hpp
/// PURE renderers for device containment (quarantine) on /hardware: the Quarantined
/// devices panel, the record's Containment lens and the record-header banner. No I/O,
/// no gate: the routes (device_containment_routes.cpp) decide what the caller may see
/// and hand these views in. Every user/agent string goes through `html_escape`; the
/// copy never claims more than the record proves (record != applied != confirmed, and a
/// released record says nothing about the device's firewall).

#include "quarantine_store.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// Every quarantine/containment surface on /hardware (row pill + link, degrade banner, Quarantined
/// devices panel, record banner, Containment tab and lens) is gated on this. The renderers, the
/// /fragments/hardware/{quarantine,ci/containment} routes, REST and MCP are untouched.
// ponytail: UI hidden until the approval workflow lands; flip to true to restore
inline constexpr bool kContainmentUi = false;

/// How far containment has been shown to reach the device — the record alone proves
/// only `Recorded`. `Applied` = a re-dispatch of the stored whitelist was accepted (NOT
/// proof); `Confirmed` = a follow-up `quarantine.status` read reported `state|active`.
enum class ContainmentState { Recorded, Applied, Confirmed };

[[nodiscard]] ContainmentState containment_state(const QuarantineRecord& r);

struct QuarantinePanelRow {
    QuarantineRecord record;
    std::string hostname; ///< "" when the device is not in the roster window
};

struct QuarantinePanelView {
    /// StoreDegraded = the store read failed; ProbeDegraded = the caller's authority could not
    /// be derived (the list gate was unwired or unavailable).
    enum class Read { Ok, StoreDegraded, ProbeDegraded } read{Read::Ok};
    std::vector<QuarantinePanelRow> rows; ///< visible, newest first, already capped
    bool more{false};                     ///< the cap stopped the walk
    std::size_t cap{200};
    std::int64_t now_secs{0};
};

/// The `#hw-quarantine` panel body (self-contained root element). A degraded read is a
/// banner, never "no device is quarantined".
[[nodiscard]] std::string render_quarantine_panel(const QuarantinePanelView& v);

struct ContainmentLensView {
    enum class Read { Ok, Degraded, Denied } read{Read::Ok};
    std::optional<QuarantineRecord> record; ///< the ACTIVE record, if any
    std::string agent_id;
    std::string hostname; ///< "" -> agent id shown
    std::string os;       ///< roster os token ("windows"/"linux"/"darwin"/...)
    bool online{false};
    bool identity_known{false}; ///< false: hostname/OS/online could not be read
    bool can_execute{false}; ///< Security:Execute probe for this device
    std::int64_t now_secs{0};
};

/// The `#hw-containment` lens body (self-contained root element).
[[nodiscard]] std::string render_containment_lens(const ContainmentLensView& v);

/// The record-header banner `#hw-quarantine-banner`: non-empty only for an active record
/// (or a degraded read); always the same root element so it can be re-fetched in place.
[[nodiscard]] std::string render_containment_banner(const ContainmentLensView& v);

/// The unloaded placeholders the record and list fragments embed.
[[nodiscard]] std::string containment_banner_placeholder(const std::string& agent_id);
[[nodiscard]] std::string containment_lens_placeholder(const std::string& agent_id);
[[nodiscard]] std::string quarantine_panel_placeholder();

} // namespace yuzu::server
