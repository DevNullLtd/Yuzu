/**
 * app_control_legs.hpp -- the Windows leg entry points, declared once for the portable TU
 * (app_control_plugin.cpp, which calls them under _WIN32) and their definitions in
 * app_control_win.cpp, so the two TUs cannot silently disagree: a signature drift surfaces as a
 * compile error (return type) or a link error (parameters).
 */
#pragma once

#include <yuzu/plugin.hpp>

namespace yuzu::app_control {

int collect_wdac(yuzu::CommandContext& ctx);
int collect_applocker(yuzu::CommandContext& ctx);

} // namespace yuzu::app_control
