#pragma once

// Interval of the agent's `tar.rollup` trigger, in seconds. It is also the
// `tick_seconds` the data-retention API publishes: rows may outlive their
// retention limit by up to one tick. Pure constant; shared so the two cannot drift.

namespace yuzu {

inline constexpr int kTarRollupTickSeconds = 900;

} // namespace yuzu
