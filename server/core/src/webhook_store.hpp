#pragma once

/// @file webhook_store.hpp
/// Postgres-backed webhook config + delivery-log store (ADR-0057, Wave 3 —
/// first `SecretCodec`-migrating store past `AuthDB`, the ADR-0010
/// precedent). Schema `webhook_store`, two tables (`webhooks` FK-cascaded by
/// `webhook_deliveries`).
///
/// Posture (ADR-0012 §1): construction and every `webhooks`
/// create/list/delete mutator are AUTHORITATIVE/fail-hard — this is
/// operator-authored integration config, a silent empty/false on a DB error
/// reads as "no webhooks configured" (list()) or "nothing happened"
/// (create/delete), neither of which is true. `fire_event`'s internal
/// enabled-webhook scan and `record_delivery`'s write are DELIBERATELY
/// fail-soft: they run off the gRPC hot path / a worker-pool thread, a
/// degraded read there just means "this tick's events are not delivered",
/// and there is no in-memory authoritative layer to fall back on — dropping
/// benignly (skip + warn + counter) is correct, never a caller-visible
/// error, exactly as it was before this migration.
///
/// `webhooks.secret` (ADR-0010 headline of this migration): a SecretCodec
/// envelope blob, never plaintext. `has_secret` is an INDEPENDENT boolean
/// column (ADR-0010 §Decision-1 anti-downgrade rule — "no secret configured"
/// must never be represented by column emptiness). Decrypt happens at the
/// HMAC signing site inside `deliver_single`, on the worker-pool thread that
/// performs the delivery — never batched/cached at `fire_event` gather time
/// (ADR-0010 §Consequences names batch-caching as an allowed option; this
/// store deliberately declines it, see ADR-0057). `Webhook`/the internal
/// delivery-carrying struct therefore never hold plaintext — only the
/// encrypted blob and `has_secret`.
///
/// `migrate_from_sqlite()` retired (#3623, ADR-0057 Update): no production fleet ever ran a
/// pre-Postgres build of this store, so the mandatory, both-tables, fingerprint-verified
/// backfill it implemented never had real legacy data to protect. `server.cpp` now runs
/// `legacy_sqlite_probe::harden_legacy_file_0600` (this store's legacy file may hold a
/// plaintext signing secret, ADR-0010 §Consequences (a)) then `warn_if_legacy_rows` over
/// `webhooks`/`webhook_deliveries` instead — silent unless real rows are found, never blocks
/// boot. No move-aside: with nothing migrated, a `.migrated-<epoch>` rename would misdescribe
/// what happened to the file, so the legacy file is left in place at its original path.

#include "store_worker_pool.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
class SecretCodec;
} // namespace yuzu::server::pg

namespace yuzu::server {

/// Public webhook view — deliberately carries no secret material at all
/// (not even the encrypted blob): `list()` is a display/audit surface, and
/// the internal encrypted-blob-carrying type used for delivery stays
/// private to the .cpp.
struct Webhook {
    int64_t id{0};
    std::string url;
    std::string event_types; // comma-separated: "agent.registered,execution.completed"
    bool has_secret{false};  // true iff a signing secret is configured (ADR-0010 anti-downgrade)
    bool enabled{true};
    int64_t created_at{0};
};

struct WebhookDelivery {
    int64_t id{0};
    int64_t webhook_id{0};
    std::string event_type;
    std::string payload; // JSON
    int status_code{0};
    int64_t delivered_at{0};
    std::string error;
};

/// Typed mutator failure (#3097 lesson — 400 vs 503 classification at the
/// REST seam, `docs/postgres-migration-ladder.md` DeploymentStore/
/// SoftwareDeploymentStore precedent). `invalid_url` is a CALLER error
/// (400); the other two are store/infra degradation (503).
enum class WebhookWriteError {
    invalid_url,        ///< url is empty or not http(s):// — caller error, 400
    store_unavailable,  ///< not open / pool exhausted / codec unavailable — 503
    db_error,           ///< a query against an open store failed — 503
};

class WebhookStore {
public:
    /// Borrows the shared pool and its OWN `SecretCodec` instance (ADR-0010
    /// "Instance model" — one codec per secret-bearing store, not shared;
    /// the codec may itself be backed by a `KeyProvider` shared with other
    /// stores' codecs, that sharing is the caller's concern). Runs the
    /// `webhook_store` schema migration on a pinned lease and registers
    /// `{"webhook_store","webhooks","secret","id"}` as a secret column.
    /// `is_open()` is false if the lease was empty, the migration failed, or
    /// the column registration failed (duplicate/invalid identifier).
    /// The caller MUST run `secret_codec.init(conn)` AFTER this constructor
    /// returns and BEFORE any encrypt/decrypt call reaches this store —
    /// mirrors `AuthDB`'s construction contract exactly (`server.cpp`'s
    /// AuthDB block is the reference wiring site).
    explicit WebhookStore(pg::PgPool& pool, pg::SecretCodec& secret_codec);
    ~WebhookStore();

    WebhookStore(const WebhookStore&) = delete;
    WebhookStore& operator=(const WebhookStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics sink for delivery outcome counters. Set-before-traffic
    /// contract, same as DexAlertRouter::set_metrics - call once, before
    /// the store is wired into agent_service_.
    void set_metrics(yuzu::MetricsRegistry* metrics);

    /// Stop accepting new deliveries and wait up to `timeout` for every
    /// queued/in-flight delivery to finish. Returns true if fully drained.
    /// The caller (ServerImpl::stop()) MUST NOT destroy this store — or the
    /// `SecretCodec`/`KeyProvider` it borrows — if this returns false; a
    /// still-draining delivery decrypts the signing secret on its worker
    /// thread right up until it finishes (see the file header).
    bool quiesce(std::chrono::milliseconds timeout);

    /// Create a new webhook. `secret` may be empty (no signing secret —
    /// deliveries fire unsigned, `has_secret=false`); a non-empty secret is
    /// envelope-encrypted before it ever reaches Postgres. Returns the
    /// assigned id, or a typed `WebhookWriteError` (400 vs 503 — see the
    /// enum doc).
    [[nodiscard]] std::expected<int64_t, WebhookWriteError>
    create_webhook(const std::string& url, const std::string& event_types,
                   const std::string& secret, bool enabled = true);

    /// List all webhooks (no secret material — not even the encrypted blob).
    /// AUTHORITATIVE (ADR-0036/postgres-store-playbook policy): this is
    /// operator-facing integration-config visibility, so a degraded read
    /// returns `nullopt`, never a silently-empty vector that reads as "no
    /// webhooks configured". The REST route surfaces `nullopt` as 503.
    [[nodiscard]] std::optional<std::vector<Webhook>> list(int limit = 100, int offset = 0) const;

    /// Delete a webhook by id. `true` = deleted, `false` = no such id,
    /// `unexpected` = a query against an open store failed (503; distinct
    /// from the plain-`false` not-found case, #3097 classification).
    [[nodiscard]] std::expected<bool, WebhookWriteError> delete_webhook(int64_t id);

    /// Fetch a single webhook by id (no secret material). `nullopt` covers
    /// both "no such id" and a degraded read — this is a pre-delete-snapshot
    /// convenience for the REST layer's audit trail (`offload_target_store`
    /// precedent), not itself a decision surface, so it doesn't need the
    /// finer 404-vs-503 split `delete_webhook` has.
    [[nodiscard]] std::optional<Webhook> get(int64_t id) const;

    /// Recent deliveries for a webhook, newest first. Deliberately stays a
    /// plain container (empty on error) — delivery HISTORY is an audit
    /// convenience, not itself a decision surface (mirrors
    /// `ResultSetStore::lineage`'s deny-or-benign carve-out, ADR-0057).
    [[nodiscard]] std::vector<WebhookDelivery> get_deliveries(int64_t webhook_id,
                                                               int limit = 50) const;

    /// Fire an event to all matching, enabled webhooks asynchronously. Each
    /// delivery runs on the bounded worker pool (see `delivery_pool_` below)
    /// - never a raw thread - so concurrency and thread creation are both
    /// capped. The matching scan is a short bounded-acquire read off the
    /// gRPC/dispatch caller's thread; a degraded pool skips this tick's
    /// firing entirely (logged + counted), never blocks the caller.
    void fire_event(const std::string& event_type, const std::string& payload_json);

    /// Compute HMAC-SHA256 signature for webhook payload verification.
    /// `secret` is a view, never `std::string` (ADR-0010 zeroization rule —
    /// a decrypted `SecureBuffer`'s bytes must not be copied into an
    /// unzeroized `std::string` on the way here).
    [[nodiscard]] static std::string hmac_sha256(std::string_view secret, std::string_view data);

private:
    pg::PgPool& pool_;
    pg::SecretCodec& secret_codec_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};

    /// Delivery-time view of one webhook: carries the still-ENCRYPTED
    /// secret blob (or none), never plaintext — decrypt happens in
    /// `deliver_single`, right before the HMAC call (see file header).
    struct WebhookDeliveryTarget {
        int64_t id{0};
        std::string url;
        std::string event_types;
        std::vector<std::uint8_t> secret_blob; // empty iff !has_secret
        bool has_secret{false};
    };

    void deliver_single(const WebhookDeliveryTarget& wh, const std::string& event_type,
                        const std::string& payload_json);
    /// Returns false (logged + counted) on a store-not-open/query failure —
    /// the caller (deliver_single, a worker-pool thread) has no 503 to
    /// return to; this surfaces via the metric + log rather than silently
    /// discarding the failure (kickoff lesson 3).
    bool record_delivery(int64_t webhook_id, const std::string& event_type,
                         const std::string& payload, int status_code, const std::string& error);

    // LAST-DECLARED MEMBER (#3261 governance hardening, ported from the
    // SQLite era) - see the identical comment history on
    // OffloadTargetStore::pool_. The destructor still drains this
    // explicitly before touching pool_/secret_codec_ (a destructor's body
    // runs before its members' destructors), so this ordering is defense in
    // depth, not the sole guarantee.
    StoreWorkerPool delivery_pool_{/*num_threads=*/4, /*max_queue=*/256};
};

} // namespace yuzu::server
