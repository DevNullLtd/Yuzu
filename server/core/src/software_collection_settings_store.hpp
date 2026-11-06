#pragma once

/// @file software_collection_settings_store.hpp
/// Born-on-Postgres store (ADR-0006/0008/0012; schema `software_collection_settings_store`) for
/// the per-management-group software collection settings document (SAM-34, roadmap 3.7a): one
/// row per group (`settings`) plus a count-bounded change trail (`settings_history`). The pure
/// types, validator and version hash live in `collection_settings_resolve.hpp`; resolution across
/// groups is the caller's (the routes hand this store's rows to `collection_settings::resolve`).
///
/// Substrate contract (ADR-0008): holds a `PgPool&`, migrates at construction on a pinned lease
/// and schema-qualifies every runtime statement. Construction is fail-closed (ADR-0012 s1): the
/// server refuses to start when the store cannot open, because the documents are authoritative
/// configuration.
///
/// Concurrency: a write names the version it expects to replace (`nullopt` = "no row may exist").
/// Create is `INSERT ... ON CONFLICT DO NOTHING RETURNING` (no row back = a concurrent create
/// won = Conflict carrying the winner). Replace is `SELECT ... FOR UPDATE`, a version compare, then
/// `UPDATE ... WHERE version = $n RETURNING`. `ON CONFLICT DO UPDATE` is never used: a row lock on
/// a row that does not exist locks nothing, so DO UPDATE would silently overwrite the winner of a
/// concurrent create. A stale version is a Conflict, never last-writer-wins.
///
/// Time: `updated_at` and history `at` are authored from the database clock in-SQL
/// (`EXTRACT(EPOCH FROM now())`), never the replica's clock.
///
/// History is count-bounded, not time-bounded: the newest `kHistoryKeep` rows per group by id,
/// trimmed inside the write transaction (no wall-clock cutoff; see docs/clock-guarded-retention.md).
///
/// Group ids carry no foreign key (cross-schema foreign keys are banned, ADR-0024 D4): a deleted
/// group's row is orphaned. `list_all` returns it and it counts toward `kListRowCap`; the resolver
/// and the list route ignore a document whose group is not in the tree.
///
/// Read rule (the stored row is configuration, never silently defaulted): a row whose
/// `plugins_json` does not parse, holds a non-boolean or an UNKNOWN key, or whose scalar fields fail
/// `validate()` is `Error::Kind::Corrupt`. A MISSING known plugin key reads as that plugin's fleet
/// default (on), and the registered apps collector reads as on. The stored `version` is returned
/// as written (it hashes the written document, not the widened read).

#include "collection_settings_resolve.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

class SoftwareCollectionSettingsStore {
public:
    struct Error {
        enum class Kind {
            Unavailable,     ///< store closed, no connection in time, or a read failed
            InvalidInput,    ///< the document or group id cannot be stored; nothing ran
            InvalidTimezone, ///< the zone is not in the database's zone table
            Conflict,        ///< expected_version did not match; `current` carries the stored row
            WriteFailed,     ///< a statement failed with a definite rollback
            OutcomeUnknown,  ///< the COMMIT did not confirm: the write may be live
            Corrupt,         ///< a stored row failed the read rule
            TooMany,         ///< more than kListRowCap rows: never a truncated answer
        };
        Kind kind{Kind::Unavailable};
        std::string message;
        /// Conflict only: the stored document (nullopt = no row exists).
        std::optional<collection_settings::StoredDocument> current;
    };

    struct PutResult {
        collection_settings::StoredDocument stored;
        /// The row this write replaced (nullopt on create), read inside the same transaction.
        std::optional<collection_settings::StoredDocument> previous;
    };

    struct HistoryRow {
        std::int64_t id{0};
        std::string group_id;
        std::optional<std::string> before_json; ///< nullopt on the first save
        std::string after_json;
        std::string actor;
        std::int64_t at{0};
    };

    static constexpr int kHistoryKeep = 200;
    static constexpr int kListRowCap = 20000;
    static constexpr std::size_t kMaxGroupIdBytes = 64;

    explicit SoftwareCollectionSettingsStore(pg::PgPool& pool);

    SoftwareCollectionSettingsStore(const SoftwareCollectionSettingsStore&) = delete;
    SoftwareCollectionSettingsStore& operator=(const SoftwareCollectionSettingsStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// nullopt value = a successful read finding no document for the group.
    [[nodiscard]] std::expected<std::optional<collection_settings::StoredDocument>, Error>
    get(const std::string& group_id);

    /// Every stored document, ordered by group id.
    [[nodiscard]] std::expected<std::vector<collection_settings::StoredDocument>, Error>
    list_all();

    /// Validate, then write `settings` for `group_id` if the stored row is at
    /// `expected_version` (nullopt = create only). The zone, when set, must exist in the
    /// database's zone table.
    [[nodiscard]] std::expected<PutResult, Error>
    put(const std::string& group_id, const collection_settings::CollectionSettings& settings,
        const std::optional<std::string>& expected_version, std::string_view actor);

    /// Newest first, at most `limit` (capped at kHistoryKeep).
    [[nodiscard]] std::expected<std::vector<HistoryRow>, Error>
    list_history(const std::string& group_id, int limit);

    /// Test seam: shorten the bounded lease wait. Not for production use.
    void set_acquire_timeout_for_test(std::chrono::milliseconds t) noexcept { timeout_ = t; }

private:
    static constexpr std::chrono::milliseconds kAcquireTimeout{3000};
    std::chrono::milliseconds timeout_{kAcquireTimeout};
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
