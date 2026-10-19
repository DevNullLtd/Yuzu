#pragma once

/// @file crypto_dashboard_layout_store.hpp
/// Born-on-Postgres store (ADR-0006/0008/0012, ADR-0071; schema `crypto_dashboard_layout_store`)
/// for each operator's `/crypto` dashboard layout: an ordered list of catalogue widget ids,
/// keyed by username. One flat table, no foreign keys, no secret-bearing columns, no legacy
/// SQLite predecessor (nothing to detect or warn about).
///
/// Substrate contract (ADR-0008): the store holds a `PgPool&`, runs its schema migration at
/// construction on a pinned lease, and schema-qualifies every runtime statement
/// (`crypto_dashboard_layout_store.layouts`). The write is a single-statement upsert
/// (`ON CONFLICT (username) DO UPDATE`), so concurrent saves by one operator are
/// last-writer-wins and never a duplicate-key error.
///
/// Posture (ADR-0012 §1): AUTHORITATIVE / fail-closed construction - a store that cannot open is
/// a fatal startup error. Runtime reads and writes return `std::expected`, so a lease timeout or
/// query error is TYPE-DISTINGUISHABLE from "no layout stored" (ADR-0036): the routes answer a
/// degraded read with 503 + retry, never by silently serving the default as if nothing were
/// stored. No read here feeds an authorization, targeting or enforcement decision - a layout
/// only chooses which widgets are DRAWN, and every widget's data read keeps its own gate.
///
/// The store does not judge ids: the caller validates a layout against the pure catalogue
/// (`crypto_widgets::layout_error`) BEFORE `put`. The store only bounds what it will hold
/// (`kMaxIds` ids of at most `kMaxIdBytes` bytes) as defence in depth.
///
/// Degrade log level (playbook "Degrade log level"): `debug`. Every caller is an operator's own
/// page load or save that reports the failure to that operator as a 503; nothing retries in the
/// background.

#include <chrono>
#include <cstddef>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

class CryptoDashboardLayoutStore {
public:
    /// Defence-in-depth bounds; the catalogue's own (64 ids, 64-byte ids) are equal or tighter.
    static constexpr std::size_t kMaxIds = 64;
    static constexpr std::size_t kMaxIdBytes = 64;
    /// Usernames longer than this are refused (no auth surface mints one this long).
    static constexpr std::size_t kMaxUsernameBytes = 512;

    /// Borrows the shared pool and runs the schema migration on a pinned lease. `is_open()` is
    /// false if the lease was empty or the migration failed.
    explicit CryptoDashboardLayoutStore(pg::PgPool& pool);

    CryptoDashboardLayoutStore(const CryptoDashboardLayoutStore&) = delete;
    CryptoDashboardLayoutStore& operator=(const CryptoDashboardLayoutStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// The operator's stored layout. `nullopt` = a successful read finding none (the caller
    /// serves the catalogue default); an empty vector = a stored, deliberately empty layout.
    /// `unexpected(msg)` = the store is closed, no connection in time, the query failed or the
    /// stored row is not a JSON array of strings.
    [[nodiscard]] std::expected<std::optional<std::vector<std::string>>, std::string>
    get(const std::string& username);

    /// Insert or replace the operator's layout (ids in display order). `unexpected(msg)` = the
    /// store is closed, an argument is out of bounds, no connection in time, or the write may
    /// not have reached Postgres.
    [[nodiscard]] std::expected<void, std::string> put(const std::string& username,
                                                       const std::vector<std::string>& widget_ids);

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
