#pragma once

// Interval of the agent's `echo.rollup` trigger, in seconds. It is also the
// `tick_seconds` the data-retention API publishes: rows may outlive their
// retention limit by up to one tick. Pure constant; shared so the two cannot drift.

#include <cstdint>

namespace yuzu {

inline constexpr int kEchoRollupTickSeconds = 900;

// Default and minimum of the agent's `db_budget_bytes` (250 MiB and 32 MiB): the byte budget
// echo.db is held to. Pure constants, shared so the agent's enforcement and the server's
// data-retention surface cannot drift.
inline constexpr int64_t kEchoDbBudgetBytesDefault = 262144000;
inline constexpr int64_t kEchoDbBudgetBytesMin = 33554432;

} // namespace yuzu
