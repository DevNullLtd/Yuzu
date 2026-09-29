#pragma once

/// @file schedule_engine.hpp
/// Postgres-backed recurring-schedule store (ADR-0009/0065). Schema
/// `schedule_engine`, one table (`schedules`).
///
/// Posture (ADR-0012 §1): AUTHORITATIVE/fail-hard construction — a
/// reachable database whose schema can't migrate/open is a fatal startup
/// error (`startup_failed_`), a posture UPGRADE from the SQLite era, where
/// migration failure was log-only and no caller ever checked an
/// availability flag (there wasn't one). Runtime reads/writes keep their
/// pre-migration plain-container/`std::expected<std::string,std::string>`
/// shapes — this store's consumers (`ScheduleRoutes`, `mcp_server.cpp`,
/// `ScheduleRunner`) are unaffected by this migration by design.
///
/// Backfill: NONE (ADR-0009's 2026-08-25 fresh-start-by-default amendment —
/// no production fleet has ever run a pre-Postgres build of any Yuzu
/// store). The legacy `instructions.db` (shared with the ExecutionTracker/
/// ApprovalManager siblings, ADR-0065) is never read for data; construction
/// logs a one-time "fresh start, no legacy backfill" line, and the caller
/// (`server.cpp`) runs `legacy_sqlite_probe::warn_if_legacy_rows()` over
/// the legacy file so an environment where "no production fleet" turns out
/// to be locally wrong gets a loud signal instead of silent loss.

#include <expected>
#include <string>
#include <vector>

#include "schedule_types.hpp" // InstructionSchedule / ScheduleQuery / ScheduleListResult (ADR-0031
                              // WS-A4 seventh family) — relocated here, PODs only, see that file's
                              // own banner. Re-included so every pre-existing includer of THIS
                              // header keeps seeing the types transitively (ODR-safe relocation,
                              // not a duplication).

namespace yuzu::server::pg {
class PgPool;
} // namespace yuzu::server::pg

namespace yuzu::server {

class ScheduleEngine {
public:
    explicit ScheduleEngine(pg::PgPool& pool);
    ~ScheduleEngine() = default;

    ScheduleEngine(const ScheduleEngine&) = delete;
    ScheduleEngine& operator=(const ScheduleEngine&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Idempotent no-op kept for call-site compatibility — migration now
    /// runs unconditionally inside the constructor (PgMigrationRunner),
    /// unlike the SQLite era where callers invoked this explicitly.
    void create_tables() {}
    void stop();

    /// ADR-0031 WS-A4 (seventh family): after the `ScheduleApi` seam rewired
    /// the dashboard fragment onto `query_schedules_checked()` below, this
    /// unchecked method's ONE remaining caller is the legacy, deliberately
    /// untouched, unversioned `GET /api/schedules` route
    /// (`schedule_routes.cpp` — a distinct capability from the seamed
    /// `GET /api/v1/schedules`/MCP `list_schedules`/fragment triad, see
    /// `schedule_api.hpp`). Do not add a new caller of this method — route it
    /// through `ScheduleApi::list_schedules` instead.
    std::vector<InstructionSchedule> query_schedules(const ScheduleQuery& q = {}) const;

    /// #4030 review finding (blocking): the machine-facing REST v1/MCP
    /// twins need to distinguish "the store failed" from "there are no
    /// schedules" — `query_schedules()` above cannot, by design, for its
    /// then-existing HTML-fragment caller (a human viewing "No schedules
    /// configured" tolerates the ambiguity a machine consumer cannot).
    /// ADR-0031 WS-A4 (seventh family): now the sole backing method for the
    /// `ScheduleApi` seam (`schedule_api.cpp`), which fronts ALL THREE of the
    /// dashboard fragment, REST v1, and MCP — the fragment's own pre-seam use
    /// of the unchecked method above is retired.
    std::expected<ScheduleListResult, std::string>
    query_schedules_checked(const ScheduleQuery& q = {}) const;

    std::expected<std::string, std::string> create_schedule(const InstructionSchedule& sched);

    /// Owner-scoped delete (M-01, #1806): `created_by` is REQUIRED (no
    /// default) so a caller cannot accidentally pass an empty principal and
    /// have it silently match every legacy row with an empty created_by —
    /// that would reopen the exact cross-tenant mutation gap this closes.
    /// Returns false for a wrong-owner id exactly like a nonexistent one, so
    /// this cannot be used to probe id existence across owners.
    bool delete_schedule(const std::string& id, const std::string& created_by);

    /// Owner-scoped enable/disable (M-01, #1806) — same required-`created_by`
    /// contract as delete_schedule. Returns true iff a row matched (id AND
    /// created_by), so the route can audit only on an actual change.
    bool set_enabled(const std::string& id, bool enabled, const std::string& created_by);

    std::vector<InstructionSchedule> evaluate_due() const;
    void advance_schedule(const std::string& id);

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
