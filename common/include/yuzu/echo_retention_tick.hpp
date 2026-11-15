#pragma once

#include <cstdint>

// Interval of the agent's `echo.rollup` trigger, in seconds. The data-retention
// API publishes it as `tick_seconds`: it is how often the agent runs its
// retention and byte-budget pass, so a row can outlive its limit by ordinary
// scheduling lag (the interval is a cadence, not a bound), and by more when the
// retention clock guard declines a pass. Pure constants; shared so the figures
// the server publishes cannot drift from the agent's trigger.

#include <cstdint>

namespace yuzu {

inline constexpr int kEchoRollupTickSeconds = 900;

// Default and minimum of the agent's `db_budget_bytes` (250 MiB and 32 MiB): the byte budget
// echo.db is held to. Pure constants, shared so the agent's enforcement and the server's
// data-retention surface cannot drift.
inline constexpr int64_t kEchoDbBudgetBytesDefault = 262144000;
inline constexpr int64_t kEchoDbBudgetBytesMin = 33554432;

} // namespace yuzu
