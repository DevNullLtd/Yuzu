// guardian_runbook_pointer.hpp - the one sentence every "ordering uncertain" marker ends with,
// so the dashboard fragments (guardian_routes.cpp, device_ui.cpp) cannot drift apart. Header-only.
#pragma once

namespace yuzu::server {

// Where an operator reads what to do about a flagged pair (docs/user-manual/guaranteed-state.md,
// section "When a verdict is flagged or does not move"). Single quotes only, so it is safe inside
// a double-quoted title attribute; it carries no caller data.
inline constexpr const char* kUncertainRunbookPointer =
    "See the Guaranteed State guide, section 'When a verdict is flagged or does not move'.";

} // namespace yuzu::server
