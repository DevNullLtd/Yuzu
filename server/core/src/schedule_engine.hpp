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

/// Upper bound of `interval_minutes`: floor(INT32_MAX / 60), about 68 years. The one value the
/// REST route (`schedule_routes.cpp`) and `ScheduleEngine::create_schedule` both enforce, so a
/// non-route caller cannot store a larger interval than the route would have accepted.
inline constexpr long long kMaxScheduleIntervalMinutes = 35791394;

/// The four `create_schedule` error texts that come from the store write rather than from the
/// engine's own request validation. The first two mean the store could not take the write and
/// nothing was written (a route answers 503 and a retry is safe); the third means the store
/// refused a field value as invalid text or as violating a constraint (SQLSTATE class 22 or 23):
/// that is a client error, a route answers 400, and nothing is wrong with the store. The fourth
/// means the INSERT ran and the transaction then did not report success: the write may or may not
/// have landed, so a route answers 503 WITHOUT a retry hint. Every other error text
/// `create_schedule` returns is a request-validation text (also 400).
inline constexpr const char* kScheduleCreateNotOpenError = "database not open";
inline constexpr const char* kScheduleCreateInsertFailedError =
    "insert failed (pool degraded or transaction failed)";
inline constexpr const char* kScheduleCreateValueRefusedError =
    "a field value is not valid text for the schedule store";
inline constexpr const char* kScheduleCreateOutcomeUnknownError =
    "the write ran but the transaction did not report success (outcome unknown)";

/// Answer of `ScheduleEngine::owned_schedule_exists_checked`.
enum class OwnedScheduleLookup {
    Exists,     ///< the read succeeded and `created_by` owns a schedule with this id
    Absent,     ///< the read succeeded and no such owned schedule exists
    Unreadable, ///< the store could not answer (not open, pool timeout, query error)
};

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

    /// On a failed insert the error is `kScheduleCreateValueRefusedError` when Postgres reported a
    /// data exception or integrity violation (SQLSTATE class 22 or 23, for example a NUL byte or
    /// invalid UTF-8 in a text field), `kScheduleCreateInsertFailedError` for any other failure of
    /// the INSERT or of the connection before it, and `kScheduleCreateOutcomeUnknownError` when the
    /// INSERT succeeded but the transaction did not (a failed or unanswered COMMIT).
    std::expected<std::string, std::string> create_schedule(const InstructionSchedule& sched);

    /// Point read: does `created_by` own a schedule with this id? One owner-filtered
    /// `SELECT 1`, independent of the listing cap. Used by the routes to tell a write that matched
    /// no row because the schedule is absent from a write that did not apply to an existing one.
    [[nodiscard]] OwnedScheduleLookup owned_schedule_exists_checked(const std::string& id,
                                                                    const std::string& created_by) const;

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
