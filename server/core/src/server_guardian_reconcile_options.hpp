#pragma once

/// @file server_guardian_reconcile_options.hpp
///
/// CLI/env registration for the Guardian heartbeat-reconcile admission budget knobs (#5513),
/// split out of `main.cpp` for the same reason and in the same shape as
/// `server_ota_options.hpp`: the flag names, defaults and env spellings are contract (they
/// appear in `docs/user-manual/server-admin.md`), and a header is reachable by a test.
///
/// The three values feed `GuardianReconcileBudget` (guardian_reconcile_budget.hpp). That class
/// CLAMPS an out-of-range value rather than refusing it, so the refusal of a non-positive or
/// non-finite value lives here, at the operator-facing edge. The budget's clamp is a backstop
/// for what gets through: a value above its documented maximum, and also a positive value below
/// the documented minimum (a budget or burst in (0, 1) ms is raised to 1.0, see
/// `kMinBudgetMsPerS` / `kMinBurstMs`; `max_per_s` is capped at 1,000,000). The server logs a
/// warning naming each flag that was clamped.

#include <CLI/CLI.hpp>

#include <cmath>
#include <string>

#include <yuzu/server/server.hpp>

namespace yuzu::server {

/// Register the three Guardian reconcile admission options onto `app`, bound to `cfg`.
///
/// Each is `CLI::PositiveNumber`-validated: zero or a negative value does not "disable" the
/// budget, it configures a server that sheds every heartbeat reconcile (nothing converges)
/// with no clear signal why, so the parse is refused at startup instead.
inline void register_guardian_reconcile_options(CLI::App& app, Config& cfg) {
    app.add_option("--guardian-reconcile-budget-ms-per-s", cfg.guardian_reconcile_budget_ms_per_s,
                   "Guardian heartbeat-reconcile admission budget: milliseconds of reconcile wall "
                   "time replenished per wall second, per server replica (default: 500). Each "
                   "admitted re-push is charged its measured wall time; when the balance is "
                   "exhausted further reconciles are shed (agents retry on their next "
                   "heartbeat). Must be greater than 0.")
        ->default_val(500.0)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_GUARDIAN_RECONCILE_BUDGET_MS_PER_S");
    app.add_option("--guardian-reconcile-burst-ms", cfg.guardian_reconcile_burst_ms,
                   "Guardian heartbeat-reconcile admission bucket capacity in milliseconds of "
                   "reconcile wall time (default: 1000). The bucket starts full. Must be greater "
                   "than 0.")
        ->default_val(1000.0)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_GUARDIAN_RECONCILE_BURST_MS");
    app.add_option("--guardian-reconcile-max-per-s", cfg.guardian_reconcile_max_per_s,
                   "Guardian heartbeat-reconcile admissions allowed per one-second window, per "
                   "server replica (default: 1000). Bounds the burst a still-full time budget "
                   "would otherwise allow before any push has finished. Must be greater than 0.")
        ->default_val(1000)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_GUARDIAN_RECONCILE_MAX_PER_S");
}

/// Refusal text for a configuration the server must not start with, or empty when the three
/// values are acceptable. `CLI::PositiveNumber` already rejects <= 0 at parse time; this adds the
/// case it lets through (NaN, measured; the parser itself refuses infinity). The `isfinite`
/// checks stay as defence in depth, so a directly assigned `Config` with an infinity is refused
/// too. This is the single place a test pins the rule. Call once after parsing.
[[nodiscard]] inline std::string guardian_reconcile_options_error(const Config& cfg) {
    if (!std::isfinite(cfg.guardian_reconcile_budget_ms_per_s) ||
        cfg.guardian_reconcile_budget_ms_per_s <= 0.0)
        return "--guardian-reconcile-budget-ms-per-s must be a finite number greater than 0";
    if (!std::isfinite(cfg.guardian_reconcile_burst_ms) || cfg.guardian_reconcile_burst_ms <= 0.0)
        return "--guardian-reconcile-burst-ms must be a finite number greater than 0";
    if (cfg.guardian_reconcile_max_per_s == 0)
        return "--guardian-reconcile-max-per-s must be greater than 0";
    return {};
}

} // namespace yuzu::server
