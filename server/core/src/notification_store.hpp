#pragma once

/// @file notification_store.hpp
/// Postgres-backed operator notification feed (ADR-0006 Wave 2 migration,
/// schema `notification_store`). Persists the small toast/badge feed the
/// dashboard renders ("Agent Enrolled", "Execution Failed", …) — one flat
/// table, no foreign keys, no secret-bearing columns.
///
/// Substrate contract (ADR-0008): the store holds a `PgPool&` (not a
/// `sqlite3*`), runs its schema migration at construction on a pinned lease,
/// and schema-qualifies every runtime statement
/// (`notification_store.notifications`) — pooled connections carry no
/// per-store search_path. Mutate-and-return uses `RETURNING` (the
/// #1033-banning idiom), never `sqlite3_changes()`.
///
/// Posture (ADR-0012 §1): construction is AUTHORITATIVE/fail-closed — a
/// Postgres store that cannot open is a fatal startup error. The plain runtime
/// reads/writes below stay container/bool returns for callers that only draw a badge (the
/// `_checked` variants add the failure channel the operator-facing bell routes use; ADR-0046
/// Update 2026-10-15) because NONE of them feed an authorization, targeting,
/// enforcement, or skip decision — `list_unread`/`list_all`/`count_unread`
/// back a display list and a count, and `mark_read`/`dismiss`
/// affect only what is shown, never what runs. A transient DB error on any
/// of these degrades the display (empty list, stale badge); it never
/// silently grants, targets, or suppresses anything (the playbook's own
/// reviewer test in docs/postgres-store-playbook.md § "Authoritative reads
/// must be type-distinguishable").
///
/// `migrate_from_sqlite()` retired (chore/retire-migrate-from-sqlite-batch-b,
/// #3623): no production fleet ever ran a pre-Postgres build of this store.
/// `server.cpp` now runs a detect-and-warn probe over the legacy file
/// instead; `set_metrics()` went with it — this store's `metrics_` pointer
/// had no other consumer.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

struct Notification {
    int64_t id{0};
    int64_t timestamp{0}; // epoch MILLISECONDS (matches create()'s duration_cast<milliseconds>)
    std::string level;    // "info", "warn", "error", "success"
    std::string title;
    std::string message;
    bool read{false};
    bool dismissed{false};
};

class NotificationStore {
public:
    /// Borrows the shared pool and runs the `notification_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed (the server fails closed before
    /// reaching here, so in production the migration runs against a
    /// proven-reachable database).
    explicit NotificationStore(pg::PgPool& pool);

    NotificationStore(const NotificationStore&) = delete;
    NotificationStore& operator=(const NotificationStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Create a new notification. Returns the assigned id, or -1 on a
    /// closed store / query error (display-only: a failed persist means one
    /// fewer toast shown, never a suppressed enforcement action).
    int64_t create(const std::string& level, const std::string& title, const std::string& message);

    /// List all unread, non-dismissed notifications (newest first). Empty
    /// on a closed store or query error — the dashboard badge/list degrade
    /// to "nothing to show", which is the display-only failure mode this
    /// store's posture note above documents.
    std::vector<Notification> list_unread(int limit = 50);

    /// List all notifications (newest first).
    std::vector<Notification> list_all(int limit = 100, int offset = 0);

    /// Mark a notification as read. Returns true only if the write is
    /// confirmed to have affected exactly one row (`PQcmdTuples()`, never a
    /// bare `PGRES_COMMAND_OK` on the UPDATE — that status is identical
    /// whether the id matched or not). False on a closed store, a query
    /// error, or a nonexistent id — the caller must not treat this call as
    /// having succeeded, e.g. for an audit row asserting the mutation
    /// landed (adversarial-review, fjarvis: an audit entry is compliance
    /// evidence and must not assert success for a write that may never
    /// have reached Postgres).
    [[nodiscard]] bool mark_read(int64_t id);

    /// Dismiss a notification (soft-delete). Same confirmed-affected-row
    /// contract as `mark_read` — see its doc comment.
    [[nodiscard]] bool dismiss(int64_t id);

    /// Count unread, non-dismissed notifications. 0 on a closed store or
    /// query error (same display-only degrade as list_unread).
    std::size_t count_unread();

    /// Failure-distinguishing readers and mutators (PR #5859 review). The plain methods above
    /// keep the display-only degrade for callers that only draw a badge; the operator-facing
    /// bell route uses these so that a lease timeout or a query error is an error the page can
    /// show, not "No unread notifications." A closed store is also an error here.
    /// `mark_read_checked` / `dismiss_checked`: `true` = exactly one row changed, `false` = no
    /// such id, error = the write may not have reached Postgres.
    [[nodiscard]] std::expected<std::vector<Notification>, std::string>
    list_unread_checked(int limit = 50);
    [[nodiscard]] std::expected<std::vector<Notification>, std::string>
    list_all_checked(int limit = 100, int offset = 0);
    [[nodiscard]] std::expected<std::size_t, std::string> count_unread_checked();
    [[nodiscard]] std::expected<bool, std::string> mark_read_checked(int64_t id);
    [[nodiscard]] std::expected<bool, std::string> dismiss_checked(int64_t id);

    /// Test seam: shorten the bounded lease wait so a held-lease failure test does not sit out
    /// the 2 s production timeout. Not for production use.
    void set_acquire_timeout_for_test(std::chrono::milliseconds t) noexcept {
        read_timeout_ = t;
        write_timeout_ = t;
    }

private:
    /// Bounded wait for a pooled connection; a display path must not pin an HTTP worker.
    static constexpr std::chrono::milliseconds kDefaultAcquireTimeout{2000};
    std::chrono::milliseconds read_timeout_{kDefaultAcquireTimeout};
    std::chrono::milliseconds write_timeout_{kDefaultAcquireTimeout};
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
