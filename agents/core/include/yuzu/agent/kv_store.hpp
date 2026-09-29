#pragma once

/**
 * kv_store.hpp -- Persistent key-value storage for Yuzu agent plugins
 *
 * SQLite-backed, file at {data_dir}/kv_store.db. Each plugin's keys are
 * namespaced by plugin name so plugins cannot access each other's state.
 *
 * Thread-safe: a std::mutex protects all sqlite3* operations (required
 * for macOS where SQLite's built-in threading may not suffice).
 */

#include <yuzu/plugin.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

struct sqlite3; // Forward declaration — avoids exposing sqlite3.h in the header

namespace yuzu::agent {

struct KvStoreError {
    std::string message;
};

/// A key/value pair from list_entries(). The value is byte-exact - embedded NULs
/// survive - unlike get()/list(), which read via sqlite3_column_text and truncate
/// at the first NUL.
struct KvRow {
    std::string key;
    std::string value;
};

/// Aggregate size of a (plugin, key-prefix) row set from namespace_size().
/// `bytes` counts raw value BYTES, matching KvRow::value.size().
struct KvNamespaceSize {
    std::uint64_t count = 0;
    std::uint64_t bytes = 0;
};

/// A key with its value's BYTE length from list_keys_sized() - the row shape for a
/// scan that must size and order a namespace without paying to materialize it.
/// `bytes` matches KvRow::value.size() (see namespace_size()'s octet_length note).
struct KvKeySize {
    std::string key;
    std::uint64_t bytes = 0;
};

/// Result of insert_if_absent(): row created, already present, or op failed.
enum class KvInsert { Inserted, Exists, Error };

/// Result of rename_key(): moved, from-key absent, to-key already existed (PK
/// conflict), or op failed.
enum class KvRename { Renamed, NotFound, Conflict, Error };

/// The storage contract GuardianLifecycleJournal requires: the 8 KvStore methods it
/// calls, with signatures identical to KvStore's own. This is a NARROW seam (#4153),
/// not a general KvStore abstraction - it exists solely so the journal's concurrency
/// checkpoints can run against an in-memory test double instead of real SQLite I/O.
/// Production always constructs the journal with a real KvStore.
///
/// Contract every implementation MUST keep - the journal's multi-caller safety
/// argument (see guardian_lifecycle_journal.hpp's CONCURRENCY block) rests on it:
///   * each call serialises itself (one lock covers the whole call, exactly like
///     KvStore's single std::mutex mu_);
///   * each call returns an OWNING snapshot (a copy), never a reference into
///     internal state, and releases its lock before returning;
///   * a call never invokes a callback, blocks on another participant, or calls
///     back into the journal while holding its lock.
/// A future second consumer of this interface must not weaken any of the three.
class YUZU_EXPORT IJournalStore {
public:
    virtual ~IJournalStore() = default;

    [[nodiscard]] virtual int pragma_synchronous() = 0;

    [[nodiscard]] virtual std::expected<KvNamespaceSize, KvStoreError>
    namespace_size(std::string_view plugin, std::string_view prefix) = 0;

    [[nodiscard]] virtual std::expected<std::vector<KvKeySize>, KvStoreError>
    list_keys_sized(std::string_view plugin, std::string_view prefix) = 0;

    [[nodiscard]] virtual std::expected<std::optional<std::string>, KvStoreError>
    get_entry(std::string_view plugin, std::string_view key) = 0;

    [[nodiscard]] virtual KvInsert insert_if_absent(std::string_view plugin, std::string_view key,
                                                    std::string_view value) = 0;

    [[nodiscard]] virtual KvRename rename_key(std::string_view plugin, std::string_view from_key,
                                              std::string_view to_key) = 0;

    [[nodiscard]] virtual int del_keys(std::string_view plugin,
                                       const std::vector<std::string>& keys) = 0;

    virtual bool set(std::string_view plugin, std::string_view key, std::string_view value) = 0;
};

class YUZU_EXPORT KvStore final : public IJournalStore {
public:
    /**
     * Open (or create) the KV store database at the given path.
     * Sets WAL mode and busy_timeout=5000.
     */
    static std::expected<KvStore, KvStoreError> open(const std::filesystem::path& db_path);

    ~KvStore();

    KvStore(KvStore&& other) noexcept;
    KvStore& operator=(KvStore&& other) noexcept;

    KvStore(const KvStore&) = delete;
    KvStore& operator=(const KvStore&) = delete;

    /** Store a key-value pair for the given plugin. Returns true on success. */
    bool set(std::string_view plugin, std::string_view key, std::string_view value) override;

    /** Retrieve a value. Returns std::nullopt if the key does not exist. */
    std::optional<std::string> get(std::string_view plugin, std::string_view key);

    /** Delete a key. Returns true on success (even if key did not exist). */
    bool del(std::string_view plugin, std::string_view key);

    /** Check if a key exists. Returns true if present. */
    bool exists(std::string_view plugin, std::string_view key);

    /** List all keys for a plugin matching the given prefix. */
    std::vector<std::string> list(std::string_view plugin, std::string_view prefix);

    /** Delete all keys for a plugin. Returns the number of deleted rows. */
    int clear(std::string_view plugin);

    /**
     * Fallible, byte-exact, terminal-error-aware sibling of list(). Returns each
     * matching key WITH its value; distinguishes an empty result (empty vector)
     * from a DB error (unexpected) - which list()'s fail-open cannot. Values are
     * read as blobs so embedded NULs survive.
     */
    [[nodiscard]] std::expected<std::vector<KvRow>, KvStoreError>
    list_entries(std::string_view plugin, std::string_view prefix);

    /**
     * Count and total value-bytes of the (plugin, prefix) rows WITHOUT
     * materializing any value - the aggregate sibling of list_entries(), for
     * callers that only need the size of a namespace. list_entries() on a
     * journal at its hard ceiling would pull tens of MiB into RAM to learn a
     * number. Same fallible contract: an empty namespace is {0, 0} while a DB
     * error is unexpected, so a caller can tell "nothing there" from "cannot
     * tell" and fail closed on the latter.
     *
     * `bytes` sums each value's raw BYTE length, matching what list_entries()
     * reports as KvRow::value.size(). It uses octet_length(value) (byte length
     * of the UTF-8 encoding) rather than bare LENGTH(), which on a TEXT column
     * counts CHARACTERS and would silently under-count every multibyte value.
     */
    [[nodiscard]] std::expected<KvNamespaceSize, KvStoreError>
    namespace_size(std::string_view plugin, std::string_view prefix) override;

    /**
     * Per-row keys and value BYTE lengths for a (plugin, prefix) scan, WITHOUT
     * materializing any value - the per-row sibling of namespace_size() and the
     * O(work) alternative to list_entries() for a caller that selects rows by key
     * and reads only the few values it actually needs. Rows come back ORDER BY
     * key, so a key whose ordering field is a fixed-width prefix scans in that
     * field's order for free.
     *
     * Same fallible contract as list_entries(): an empty result is an empty
     * vector while a DB error is unexpected. `bytes` uses octet_length(value) for
     * byte parity with KvRow::value.size() (see namespace_size()).
     */
    [[nodiscard]] std::expected<std::vector<KvKeySize>, KvStoreError>
    list_keys_sized(std::string_view plugin, std::string_view prefix) override;

    /**
     * Fallible, byte-exact point read: the single-key sibling of list_entries().
     * nullopt means the key is ABSENT; unexpected means the read FAILED - a
     * distinction get() cannot make (it returns nullopt for both) and which a
     * caller that must not treat "cannot tell" as "not there" depends on. Reads
     * the value as a blob, so embedded NULs survive get()'s column_text
     * truncation and a corrupt value reaches the parser intact.
     */
    [[nodiscard]] std::expected<std::optional<std::string>, KvStoreError>
    get_entry(std::string_view plugin, std::string_view key) override;

    /**
     * Insert only if (plugin, key) is absent. Uses INSERT ... ON CONFLICT DO
     * NOTHING RETURNING, so it reports Inserted vs Exists WITHOUT the
     * sqlite3_changes()-after-step race (#1033) - letting a collision counter be
     * truthful.
     */
    [[nodiscard]] KvInsert insert_if_absent(std::string_view plugin, std::string_view key,
                                            std::string_view value) override;

    /**
     * Atomically rename (plugin, from_key) → (plugin, to_key) via a single UPDATE
     * of the key column, preserving the value. Conflict if to_key already exists.
     * Used for the quarantine move - never a non-atomic copy+delete.
     */
    [[nodiscard]] KvRename rename_key(std::string_view plugin, std::string_view from_key,
                                      std::string_view to_key) override;

    /**
     * Delete a set of keys for a plugin in ONE transaction. Returns the number
     * actually removed (via RETURNING, not sqlite3_changes()). All-or-nothing: on
     * error the transaction rolls back and 0 is returned.
     */
    [[nodiscard]] int del_keys(std::string_view plugin,
                               const std::vector<std::string>& keys) override;

    /**
     * The effective `PRAGMA synchronous` level (0=OFF, 1=NORMAL, 2=FULL,
     * 3=EXTRA), or -1 on error. The journal's power-loss-durability claim wants
     * FULL; the caller SOFT-warns on anything less (never a hard abort - config
     * drift must not kill an agent).
     */
    [[nodiscard]] int pragma_synchronous() override;

    /**
     * TEST-ONLY: turn on SQLite extended result codes for this connection.
     * Production code never enables them here, so rename_key's PK-conflict
     * classification uses `rc & 0xFF`; this seam lets a test exercise that
     * masking by making step() actually return the extended code
     * SQLITE_CONSTRAINT_PRIMARYKEY (1555) instead of the primary 19. Without
     * the mask that test would see Error, not Conflict.
     */
    void enable_extended_result_codes_for_test();

private:
    explicit KvStore(sqlite3* db);

    sqlite3* db_{nullptr};
    std::mutex mu_;
};

} // namespace yuzu::agent
