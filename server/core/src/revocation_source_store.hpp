#pragma once

/// @file revocation_source_store.hpp
/// Born-on-Postgres store (ADR-0006/0008/0012, ADR-0070 D12; schema `revocation_source_store`) for
/// the CRL sources an administrator registers: one source is one CA (its certificate keys, one
/// subject Name) and the CRL URLs the server may fetch for it. See
/// `docs/crypto-slice2-certificate-design.md`, "R1: registered-CRL revocation".
///
/// Never touches `ca_store` (ADR-0070 D6): a registered CA certificate here is data the server
/// CHECKS a CRL against; it is never a trust anchor, an issuer, or a TLS root for any Yuzu
/// decision path.
///
/// 2b-1a WRITES only `source`, `source_ca_key` and `source_url`. v1 creates the tables the
/// fetcher (2b-1b) reads and writes; `cert_signature_check` (2b-2) is not created here. v2 lands
/// the three #6590 rulings (owner, 2026-11-18) before 2b-1b accepts any CRL:
///   - ONE encoded `scope_key`, used identically in `crl` and `rollback_high_water`: `full` or
///     `idp:<64 lowercase hex of the IDP DER SHA-256>`, then `:base` or `:delta`, pinned by a
///     CHECK on both tables. The CA is the table's own column (`crl.source_id`,
///     `rollback_high_water.ca_subject_name_sha256`), never part of the key. Only
///     `rollback_high_water`'s CHECK also admits `'*'`, the CA-level row whose permanent
///     `reset_at` scopes first seen later inherit. `crl.is_delta` is GENERATED from the suffix,
///     so the two cannot disagree, and `UNIQUE (source_id, scope_key, is_delta)` stays: the
///     fetcher replaces a scope's held CRL by delete-then-insert inside its acceptance
///     transaction, so a reader sees the old CRL or the new one, never both and never none;
///   - every stored URL is in the canonical form of `revocation_url_canonical.hpp`, which
///     `UNIQUE (source_id, url)` and `replace` compare. The store refuses to write any other
///     form, and on every open it rewrites a stored URL that is not canonical (a v1 row), refusing
///     to open, with the source named in the error log, when two URLs of one source collapse
///     into one;
///   - the high-water reset names the keys that survive (`keep_key_sha256`, values of
///     `source_ca_key.cert_sha256`, each already registered) and the `config_version` it was
///     read from: every other key and every held CRL of the CA are removed in its transaction.
/// `config_version` stays a PER-ROW counter (kept by the same ruling): 1 at register, raised by
/// one in the transaction of a `replace` that changes the source and of every reset. Source ids
/// come from an identity column that is never reset, so a remove and re-register can never
/// reproduce an earlier (source id, config_version) pair; there is no global sequence.
///
/// `fetch_status`, `crl`, `crl_entry` and `rollback_high_water` are READ here (a source's fetch
/// status, its held-CRL count) and are deleted with their source / URL / key, but nothing in
/// this store inserts into `crl` or `crl_entry` yet. The one exception is
/// `rollback_high_water`, which `reset_high_water` upserts: that mark is keyed by the CA, never by
/// the source, so it survives `remove` (a remove and re-register cannot accept an older CRL).
///
/// Posture (ADR-0012 §1): construction is fail-CLOSED. A store that cannot migrate/open sets
/// the server's `startup_failed_`, and the store is in the `/readyz` conjunction: it holds the
/// registered egress targets and the revocation sources every later revocation statement is
/// judged against, so a node without it must not serve. Runtime reads and writes return
/// `std::expected` with a typed error, so a lease timeout or query error is TYPE-DISTINGUISHABLE
/// from "no such source" (ADR-0036): the routes answer a degraded read 503 + retry, never an
/// empty list.
///
/// Concurrency: every multi-statement write is ONE transaction. `create` serialises on a
/// transaction-scoped advisory lock so the 64-source ceiling and the one-source-per-CA rule hold
/// across replicas; `replace`, `remove` and `reset_high_water` lock the source row first. An
/// ambiguous commit (connection lost after COMMIT was sent) is `kOutcomeUnknown`, never a guess.
///
/// Personal data: `created_by` is the registering operator's username. URLs are operator-supplied
/// free text that can embed internal host names; no log line here carries a URL, a name or a
/// username (the SQLSTATE and a count only).
///
/// Degrade log level (playbook "Degrade log level"): `warn`, sampled.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
struct PgMigration;
} // namespace yuzu::server::pg

namespace yuzu::server {

/// Why a store call failed. The seam maps each kind to its own answer:
///   kNotOpen            the store did not open (only reachable in a test: boot is fail-closed);
///   kInvalidInput       the argument cannot be stored (empty / oversized / non-UTF-8 text, a
///                       count over a ceiling) - no SQL ran;
///   kPoolAcquireTimeout no pooled connection within the acquire bound (retryable);
///   kQueryError         a statement failed with a definite outcome (nothing was written);
///   kNotFound           no source has that id;
///   kConflict           `create`: a source for this CA already exists; `existing_id` names it;
///   kLimitReached       `create`: kMaxSources sources are already registered;
///   kSubjectChanged     `replace`: the new CA certificates name a different subject than the
///                       source holds (a source is one CA);
///   kVersionConflict    `replace` / `reset_high_water`: the caller's expected_config_version is
///                       not the stored one;
///                       `existing_id` carries the stored config_version;
///   kBadResetTime       `reset_high_water`: the supplied `reset_at` is later than Postgres now();
///   kUnknownKey         `reset_high_water`: a `keep_key_sha256` entry names no key registered on
///                       the source; `existing_id` carries the entry's index;
///   kOutcomeUnknown     the connection was lost after a write was sent: it may or may not have
///                       committed - re-read to check, never assume either way.
/// `message` is for logs and never carries a URL, a name or a username.
struct RevocationSourceStoreError {
    enum class Kind {
        kNotOpen,
        kInvalidInput,
        kPoolAcquireTimeout,
        kQueryError,
        kNotFound,
        kConflict,
        kLimitReached,
        kSubjectChanged,
        kBadResetTime,
        kVersionConflict,
        kUnknownKey,
        kOutcomeUnknown,
    };
    Kind kind{Kind::kQueryError};
    std::string message;
    /// kConflict: the existing source id; kVersionConflict: the stored config_version;
    /// kUnknownKey: the index of the first `keep_key_sha256` entry that is not registered.
    std::int64_t existing_id{0};
};

/// One CA certificate (key) of a source. `cert_der` is the raw DER on write and EMPTY on read
/// (the fetcher reads it by its own statement; nothing a route serves needs it).
struct RevocationSourceKey {
    std::string cert_sha256; ///< lowercase hex SHA-256 of the DER
    std::string cert_der;
    std::optional<std::string> ski; ///< lowercase hex subject key identifier, absent if none
    std::string spki_sha256;        ///< lowercase hex SHA-256 of the DER SubjectPublicKeyInfo
};

/// The fetcher's per-URL status (`fetch_status`). All empty/absent until 2b-1b writes it.
struct RevocationFetchStatus {
    bool present{false}; ///< a `fetch_status` row exists
    std::optional<std::int64_t> last_attempt_at;  ///< epoch seconds, Postgres clock
    std::optional<std::int64_t> last_success_at;  ///< epoch seconds, Postgres clock
    std::optional<std::string> last_failure_cause; ///< closed cause token
    std::int64_t consecutive_failures{0};
    std::optional<std::int64_t> next_attempt_at; ///< epoch seconds, Postgres clock
};

/// One registered CRL URL. `confirmed_address_classes` are the class names the administrator
/// confirmed at registration (sorted); the fetcher refuses an address outside them.
struct RevocationSourceUrl {
    std::int64_t id{0};
    std::string url;  ///< canonical form (`revocation_url_canonical.hpp`)
    std::string host; ///< the canonical URL's host, without brackets
    std::vector<std::string> confirmed_address_classes;
    RevocationFetchStatus fetch;
};

struct RevocationSourceRecord {
    std::int64_t id{0};
    std::string name;
    std::string ca_subject_name_sha256; ///< lowercase hex SHA-256 of the subject Name DER
    std::int64_t config_version{1};
    std::string created_by;
    std::int64_t created_at{0}; ///< epoch seconds, Postgres clock
    std::int64_t updated_at{0}; ///< epoch seconds, Postgres clock
    std::int64_t held_crl_count{0}; ///< 0 until the fetcher (2b-1b) stores a CRL
    /// The CA's anti-rollback floor (the CA-level `rollback_high_water` row): set by a reset,
    /// never cleared. nullopt = never reset. Lets a caller verify a reset whose outcome was unknown.
    std::optional<std::int64_t> reset_at;
    std::optional<std::string> pinned_crl_sha256; ///< the first CRL the administrator pinned, if any
    std::vector<RevocationSourceKey> keys;
    std::vector<RevocationSourceUrl> urls;
};

/// What `create` / `replace` write. Already validated by the service: the store re-checks only
/// what it must to stay consistent (ceilings, UTF-8, NUL).
struct NewRevocationSource {
    std::string name;
    std::string ca_subject_name_sha256;
    std::vector<RevocationSourceKey> keys;
    struct Url {
        std::string url;  ///< MUST be canonical (`canonical_crl_url`); the store refuses any other form
        std::string host; ///< MUST be the canonical URL's host
        std::vector<std::string> confirmed_address_classes;
    };
    std::vector<Url> urls;
    /// `replace` only: a body that would change the stored configuration is refused
    /// (kVersionConflict) unless this is set and equals the stored config_version.
    std::optional<std::int64_t> expected_config_version;
};

struct RevocationSourceUpdate {
    RevocationSourceRecord source; ///< the source after the call (config_version bumped iff changed)
    bool changed{false};
    std::int64_t dropped_urls{0};
    std::int64_t dropped_keys{0};
    std::int64_t crls_deleted{0};
};

/// What `reset_high_water` is asked to do (already validated by the service; the store re-checks
/// only its own invariants).
struct HighWaterResetRequest {
    /// The keys that survive the reset: `source_ca_key.cert_sha256` values (64 lowercase hex), each
    /// already registered on the source, 1..kMaxCaKeys of them, no duplicates. Every other key of
    /// the source is removed in the reset's transaction.
    std::vector<std::string> keep_key_sha256;
    /// The source's config_version as the caller read it; a reset against any other version is
    /// kVersionConflict and changes nothing.
    std::int64_t expected_config_version{0};
    /// RFC 3339 UTC (already shape-checked), no later than Postgres now(); empty = now().
    std::string reset_at_rfc3339;
    /// Optional, 64 lowercase hex: the only first CRL to accept afterwards.
    std::string pin_crl_sha256;
};

struct HighWaterReset {
    std::int64_t reset_at{0};       ///< epoch seconds: the floor now in force for the CA
    std::int64_t crls_deleted{0};   ///< held CRLs the reset discarded
    std::int64_t dropped_keys{0};   ///< registered keys the reset removed (not in keep_key_sha256)
    /// Their cert_sha256 values, sorted: the audit evidence of WHICH keys stopped being trusted.
    std::vector<std::string> dropped_key_sha256;
    std::int64_t config_version{0}; ///< the source's config_version after the reset
    bool pinned{false};             ///< a first-CRL pin was recorded
};

/// The store's numbered migrations (v1, v2), exactly as the constructor runs them. Exposed so a
/// test can stage a database at an earlier version (run a prefix through `PgMigrationRunner`)
/// and prove the upgrade; not for production use.
[[nodiscard]] const std::vector<pg::PgMigration>& revocation_source_store_migrations();

class RevocationSourceStore {
public:
    /// At most this many sources, which also bounds every per-source and per-URL metric label.
    static constexpr std::size_t kMaxSources = 64;
    static constexpr std::size_t kMaxCaKeys = 8;
    static constexpr std::size_t kMaxUrls = 8;
    static constexpr std::size_t kMaxNameBytes = 128;
    static constexpr std::size_t kMaxUrlBytes = 2048;
    static constexpr std::size_t kMaxUsernameBytes = 1024;
    static constexpr std::size_t kMaxCertDerBytes = 64 * 1024;

    /// Borrows the shared pool, runs the schema migration on a pinned lease, then the canonical-URL
    /// pass (every stored URL rewritten to the canonical form). `is_open()` is false if the lease
    /// was empty, the migration failed, or the pass refused: a stored URL that cannot be
    /// canonicalised, or two URLs of one source that collapse into one (the error log names the
    /// source id and the URL ids, never the URL text).
    explicit RevocationSourceStore(pg::PgPool& pool);

    RevocationSourceStore(const RevocationSourceStore&) = delete;
    RevocationSourceStore& operator=(const RevocationSourceStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Every source, ordered by id (at most kMaxSources), read in one snapshot.
    [[nodiscard]] std::expected<std::vector<RevocationSourceRecord>, RevocationSourceStoreError>
    list();

    /// One source. Errors: kNotFound plus the read errors.
    [[nodiscard]] std::expected<RevocationSourceRecord, RevocationSourceStoreError>
    get(std::int64_t id);

    /// Registered CRL scopes (source, scope key, base or delta) whose held CRL is past its
    /// `nextUpdate` (the list's `crl_past_next_update`; design D13, ADR-0070 R12). A CRL with no
    /// `nextUpdate` is never past. Always 0 until the fetcher stores a CRL.
    [[nodiscard]] std::expected<std::int64_t, RevocationSourceStoreError>
    crl_past_next_update_count();

    /// Register a source; returns it as stored, read back inside the same transaction (so a
    /// committed registration is never reported as a failure). Errors: kConflict (one source per
    /// CA), kLimitReached, kInvalidInput, kPoolAcquireTimeout, kQueryError, kOutcomeUnknown.
    [[nodiscard]] std::expected<RevocationSourceRecord, RevocationSourceStoreError>
    create(const NewRevocationSource& src, const std::string& created_by);

    /// Replace the source's name, keys and URLs (a full replace). A body equal to the stored
    /// configuration changes nothing and does not bump `config_version`. A URL absent from `src`
    /// is deleted with its `fetch_status` and held CRLs; a key absent from `src` deletes every
    /// held CRL that verified only under it. The CA's high-water marks are never touched.
    /// Errors: kNotFound, kSubjectChanged, plus the write errors.
    [[nodiscard]] std::expected<RevocationSourceUpdate, RevocationSourceStoreError>
    replace(std::int64_t id, const NewRevocationSource& src);

    /// Remove the source with its URLs, keys, fetch status and held CRLs. The CA's high-water
    /// marks SURVIVE. Errors: kNotFound plus the write errors.
    [[nodiscard]] std::expected<void, RevocationSourceStoreError> remove(std::int64_t id);

    /// Reset the CA's anti-rollback marks, in ONE transaction under the source row lock: refuses a
    /// stale `expected_config_version` (kVersionConflict) and a `keep_key_sha256` entry that is not
    /// a registered key (kUnknownKey), then removes every key NOT named in `keep_key_sha256`, sets
    /// `reset_at` on every scope of the source's CA (creating the CA-level `'*'` row if none),
    /// clears each scope's CRL number and thisUpdate, records the optional pin on the CA-level row,
    /// deletes every held CRL of the CA and bumps config_version. `reset_at` must not be later
    /// than Postgres now() (kBadResetTime) and is kept permanently on every row. NOT idempotent:
    /// each call sets a new `reset_at` (and a retry after an unknown outcome is kVersionConflict,
    /// because the first call moved config_version). Errors: kNotFound, kVersionConflict,
    /// kUnknownKey, kBadResetTime, kInvalidInput plus the write errors.
    [[nodiscard]] std::expected<HighWaterReset, RevocationSourceStoreError>
    reset_high_water(std::int64_t id, const HighWaterResetRequest& req);

    /// The open-time canonical-URL pass on its own (the constructor runs it once, on its pinned
    /// lease): the number of stored URLs it rewrote, or nullopt when it refused (see the
    /// constructor) or found no connection. Public so a test can stage a v1 row and run the pass
    /// again; idempotent.
    [[nodiscard]] std::optional<std::int64_t> canonicalise_stored_urls_for_test();

    /// Test seam (empty in production): called with the operation name at the start of every write
    /// (`create`, `replace`, `remove`, `reset_high_water`); a returned kind makes the call fail with
    /// it BEFORE any SQL runs. Lets a test drive `kOutcomeUnknown` (a connection lost mid-COMMIT),
    /// which a unit test cannot stage for real, through the REST and MCP transports.
    void set_write_fault_for_test(std::function<std::optional<RevocationSourceStoreError::Kind>(
                                      std::string_view op)> f) {
        write_fault_ = std::move(f);
    }

    /// Test seam (empty in production): the read-side twin of `set_write_fault_for_test`, called
    /// with the operation name (`list`, `get`, `crl_past_next_update_count`) at the start of every
    /// read, where a returned kind fails the read with it before any lease is taken; and with
    /// `create.reread` just before `create` reads its new row back inside its open transaction,
    /// where a returned kind fails the create and the transaction rolls back. Lets a test prove a
    /// write path does not depend on a separate read after its commit, and that a failed read-back
    /// leaves nothing committed.
    void set_read_fault_for_test(std::function<std::optional<RevocationSourceStoreError::Kind>(
                                     std::string_view op)> f) {
        read_fault_ = std::move(f);
    }

    /// Test seam: shorten the bounded lease wait so a held-lease test does not sit out the
    /// production timeout. Not for production use.
    void set_acquire_timeout_for_test(std::chrono::milliseconds t) noexcept { timeout_ = t; }

private:
    /// Bounded wait for a pooled connection: an operator request must not pin an HTTP worker.
    static constexpr std::chrono::milliseconds kDefaultAcquireTimeout{2000};
    std::chrono::milliseconds timeout_{kDefaultAcquireTimeout};
    pg::PgPool& pool_;
    bool open_{false};
    std::function<std::optional<RevocationSourceStoreError::Kind>(std::string_view)> write_fault_;
    std::function<std::optional<RevocationSourceStoreError::Kind>(std::string_view)> read_fault_;
};

} // namespace yuzu::server
