#pragma once

#include <cstdint>

// Interval of the agent's `echo.rollup` trigger, in seconds. The data-retention
// API publishes it as `tick_seconds`: it is how often the agent runs its
// retention and byte-budget pass, so a row can outlive its limit by ordinary
// scheduling lag (the interval is a cadence, not a bound), and by more when the
// retention clock guard declines a pass. Pure constants; shared so the figures
// the server publishes cannot drift from the agent's trigger.

namespace yuzu {

inline constexpr int kEchoRollupTickSeconds = 900;

// Default and minimum `db_budget_bytes` (250 MiB and 32 MiB): the cap on what
// echo.db holds, used pages plus the write-ahead log. The agent applies the
// default when no value is stored; the data-retention API publishes it.
inline constexpr std::int64_t kEchoDbBudgetBytesDefault = 262144000;
inline constexpr std::int64_t kEchoDbBudgetBytesMin = 33554432;

} // namespace yuzu
