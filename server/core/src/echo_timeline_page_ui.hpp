#pragma once

/// @file echo_timeline_page_ui.hpp
/// The Echo timeline page shell: GET /echo/timeline?id=<agent_id>[&at=<epoch>]. The shell
/// holds the slots (run, moment, selected) and the controls; the fragments it loads draw
/// the record and static/yuzu-echo-timeline.js moves the moment line. Design:
/// docs/echo-dashboard.md section 5.8.

#include <string>
#include <string_view>

namespace yuzu::server {

/// The page and its script are registered only when this is true. This is the DEFAULT of
/// page::Deps::echo_timeline_ui, so a test can drive both states. While false the routes
/// do not exist at all (an unregistered path, not a disabled page) and nothing links to them.
inline constexpr bool kEchoTimelineUi = false;

/// The page for one device. `agent_id` is percent-encoded then HTML-escaped wherever it
/// lands; `at` is the opening moment and is used only when it is 1 to 19 ASCII digits.
[[nodiscard]] std::string render_echo_timeline_page(std::string_view agent_id, std::string_view at);

} // namespace yuzu::server
