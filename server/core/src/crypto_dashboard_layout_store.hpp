#pragma once

/// @file crypto_dashboard_layout_store.hpp
/// Born-on-Postgres store (ADR-0006/0008/0012, ADR-0071; schema `crypto_dashboard_layout_store`)
/// for each operator's `/crypto` dashboard layout: an ordered list of catalogue widget ids,
/// keyed by username. One flat table, no foreign keys, no secret-bearing columns, no legacy
/// SQLite predecessor (nothing to detect or warn about).
///
/// Substrate contract (ADR-0008): the store holds a `PgPool&`, runs its schema migration at
/// construction on a pinned lease, and schema-qualifies every runtime statement
/// (`crypto_dashboard_layout_store.layouts`).
///
/// Optimistic concurrency: every row carries a `version` (1 on first write, +1 on every
/// replace). `get` returns it; `put` names the version it expects to replace (nullopt = "I
/// expect no row") and is ONE conditional statement — an `INSERT ... ON CONFLICT DO NOTHING`
/// for a first write, an `UPDATE ... WHERE version = $n` for a replace — so of two writers
/// racing from the same version (two tabs, or two first writes) exactly one wins and the other
/// gets kConflict; nothing is silently overwritten.
///
/// Posture (ADR-0012 §1, as amended for this store by the owner decision of 2026-10-19 —
/// ADR-0071): a store that cannot open at boot DEGRADES — the server boots without layouts
/// (the routes answer "layouts unavailable", the dashboard draws the default) rather than
/// refusing to start, because a lost layout is an inconvenience, never a security or
/// correctness fault. Runtime reads and writes return `std::expected` with a typed error, so
/// a lease timeout or query error is TYPE-DISTINGUISHABLE from "no layout stored" (ADR-0036):
/// the routes answer a degraded read with 503 + retry, never by silently serving the default
/// as if nothing were stored. No read here feeds an authorization, targeting or enforcement
/// decision - a layout only chooses which widgets are DRAWN, and every widget's data read keeps
/// its own gate.
///
/// The store does not judge ids: it stores and returns them VERBATIM, including ids this build's
/// catalogue does not know (a widget added by a newer build, or retired by this one). Keeping
/// those across a save is the caller's job (the seam), as is validating new ids against the
/// pure catalogue (`crypto_widgets::layout_error`) BEFORE `put`. The store only bounds what it
/// will hold (`kMaxIds` ids of at most `kMaxIdBytes` bytes) as defence in depth.
///
/// Privacy: the key is the operator's username (personal data, ADR-0071); `erase` removes it on
/// deprovision. No log line here ever carries a username or a widget id.
///
/// Degrade log level (playbook "Degrade log level"): `warn`. Each failure is an operator's own
/// page load or save reported to them as a 503, but a run of them is an outage an SRE must be
/// able to see in the log without a debug build.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// Why a layout call failed. The seam maps each kind to its own answer:
///   kNotOpen            the store did not open at boot — layouts unavailable until restart;
///   kInvalidInput       the caller's argument cannot be stored (empty / oversized / non-UTF-8
///                       username, too many or malformed ids, expected_version < 1) — no SQL ran;
///   kPoolAcquireTimeout no pooled connection within the acquire bound (retryable);
///   kQueryError         a statement failed with a definite outcome (nothing was written);
///   kConflict           `put`'s expected_version did not match the stored row (another
///                       writer saved first, or the row was erased) — reload, then retry;
///   kOutcomeUnknown     the connection was lost after a write was sent: it may or may not
///                       have committed — reload to check, never assume either way;
///   kCorrupt            the stored row is not a JSON array of strings; `version` carries the
///                       row's version, so a `put` naming it (the dashboard's Reset) overwrites it.
/// `message` is for logs and never carries a username.
struct CryptoLayoutStoreError {
    enum class Kind {
        kNotOpen,
        kInvalidInput,
        kPoolAcquireTimeout,
        kQueryError,
        kConflict,
        kOutcomeUnknown,
        kCorrupt,
    };
    Kind kind{Kind::kQueryError};
    std::string message;
    std::int64_t version{0}; ///< kCorrupt only: the corrupt row's version
};

/// One stored layout: the ids verbatim in display order, and the row's version.
struct StoredCryptoLayout {
    std::vector<std::string> widget_ids;
    std::int64_t version{0};
};

class CryptoDashboardLayoutStore {
public:
    /// Defence-in-depth bounds; the catalogue's own (64 ids, 64-byte ids) are equal or tighter
    /// (pinned by a static_assert in crypto_api.cpp, where both headers are visible).
    static constexpr std::size_t kMaxIds = 64;
    static constexpr std::size_t kMaxIdBytes = 64;
    /// Usernames longer than this are refused as kInvalidInput (no auth surface mints one this
    /// long).
    static constexpr std::size_t kMaxUsernameBytes = 1024;
    // The longest principal name an identity source can produce: a 5-byte source prefix, a
    // 255-byte qualifier, a separator and a 255-byte name.
    static_assert(kMaxUsernameBytes >= 5 + 255 + 1 + 255,
                  "a username the auth layer can mint must fit the layout key");

    /// Borrows the shared pool and runs the schema migration on a pinned lease. `is_open()` is
    /// false if the lease was empty or the migration failed.
    explicit CryptoDashboardLayoutStore(pg::PgPool& pool);

    CryptoDashboardLayoutStore(const CryptoDashboardLayoutStore&) = delete;
    CryptoDashboardLayoutStore& operator=(const CryptoDashboardLayoutStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// The operator's stored layout and its version. `nullopt` = a successful read finding none
    /// (the caller serves the catalogue default; a first `put` then passes no expected
    /// version); an empty id list = a stored, deliberately empty layout. Errors: kNotOpen,
    /// kInvalidInput, kPoolAcquireTimeout, kQueryError, kCorrupt.
    [[nodiscard]] std::expected<std::optional<StoredCryptoLayout>, CryptoLayoutStoreError>
    get(const std::string& username);

    /// Write the operator's layout (ids in display order) if the stored row is still at
    /// `expected_version` (nullopt = no row may exist yet), and return the new version. Errors:
    /// kNotOpen, kInvalidInput, kPoolAcquireTimeout, kQueryError, kConflict, kOutcomeUnknown.
    [[nodiscard]] std::expected<std::int64_t, CryptoLayoutStoreError>
    put(const std::string& username, const std::vector<std::string>& widget_ids,
        std::optional<std::int64_t> expected_version);

    /// Delete the operator's row (deprovision erasure, ADR-0071). `true` = a row was deleted,
    /// `false` = there was none. Unconditional: no version check. Errors: kNotOpen,
    /// kInvalidInput, kPoolAcquireTimeout, kQueryError, kOutcomeUnknown.
    [[nodiscard]] std::expected<bool, CryptoLayoutStoreError> erase(const std::string& username);

    /// Test seam: shorten the bounded lease wait so a held-lease test does not sit out the
    /// production timeout. Not for production use.
    void set_acquire_timeout_for_test(std::chrono::milliseconds t) noexcept { timeout_ = t; }

private:
    /// Bounded wait for a pooled connection: an operator page load must not pin an HTTP worker.
    static constexpr std::chrono::milliseconds kDefaultAcquireTimeout{2000};
    std::chrono::milliseconds timeout_{kDefaultAcquireTimeout};
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
