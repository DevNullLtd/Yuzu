#pragma once

/// @file offload_target_store.hpp
/// Postgres-backed offload-target config + delivery-log store (ADR-0059,
/// Wave 3 — SecretCodec-migrating store; mirrors WebhookStore's ADR-0057 (in
/// flight at the time of writing) conventions verbatim for the secrets seam,
/// since the two stores are near-twins — targets + deliveries tables,
/// wildcard `event_types`, an `enabled` flag). Schema `offload_target_store`,
/// two tables (`offload_targets` FK-cascaded by `offload_deliveries`).
///
/// Posture (ADR-0012 §1): construction and every `offload_targets`
/// create/list/get/get_by_name/delete mutator are AUTHORITATIVE/fail-hard —
/// this is operator-authored integration config (also referenced by name
/// from `spec.offload.targets` in InstructionDefinition YAML), so a silent
/// empty/false/nullopt-without-distinction on a DB error would read as "no
/// targets configured" or "nothing happened", neither of which is true.
/// `fire_event`'s internal enabled-target scan and `record_delivery`'s write
/// are DELIBERATELY fail-soft: they run off the gRPC hot path / a
/// worker-pool thread, a degraded read there just means "this tick's events
/// are not delivered", and there is no in-memory authoritative layer to fall
/// back on — dropping benignly (skip + warn + counter) is correct, never a
/// caller-visible error, exactly as it was before this migration.
///
/// `auth_credential` (ADR-0010 headline of this migration): a SecretCodec
/// envelope blob, never plaintext. `has_credential` is an INDEPENDENT
/// boolean column (ADR-0010 §Decision-1 anti-downgrade rule — "no credential
/// configured" must never be represented by column emptiness alone).
/// Decrypt happens at the dispatch site inside `deliver_single`, per
/// delivery — never batched/cached across a `batch_size > 1` flush (ADR-0010
/// §Consequences names batch-caching as an allowed option; this store
/// declines it, same as webhook). `OffloadTarget` (the public view) and the
/// buffering/dispatch path therefore never hold plaintext credential bytes
/// outside the one delivery attempt that needs them.
///
/// Backfill: NONE (ADR-0009's 2026-08-25 fresh-start-by-default amendment —
/// no production fleet has ever run a pre-Postgres build of any Yuzu store,
/// so there is no real legacy data to protect). Skipped unconditionally, no
/// flag, same as `ResponseStore`'s pre-existing precedent: the legacy
/// `offload_targets.db` is never read, and construction logs a one-time
/// "fresh start, no legacy backfill" line.
///
/// Reuses the WebhookStore delivery pattern (bounded-worker-pool dispatch
/// per delivery, async record - see store_worker_pool.hpp), and adds:
///   - typed auth (none / bearer / basic / hmac)
///   - server-side batching (`batch_size > 1` accumulates events into a
///     per-target buffer and flushes on threshold or on `flush_all()`)
///   - per-target name → callers can name a target and reference it from
///     `spec.offload.targets` in InstructionDefinition YAML
///
/// The `fire_event` call path is fire-and-forget and dispatches onto the
/// bounded worker pool so a slow endpoint can't drown the server.

#include "store_worker_pool.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
class SecretCodec;
} // namespace yuzu::server::pg

namespace yuzu::server {

enum class OffloadAuthType {
    None,
    Bearer,
    Basic,
    Hmac,
};

/// Convert auth-type enum ↔ wire string. Wire strings are lowercase.
std::string offload_auth_type_to_string(OffloadAuthType t);
OffloadAuthType offload_auth_type_from_string(const std::string& s);

/// Public target view — deliberately carries no credential material at all
/// (not even the encrypted blob): `list()`/`get()` are display/audit
/// surfaces, and the internal encrypted-blob-carrying type used for delivery
/// stays private to the .cpp.
struct OffloadTarget {
    int64_t id{0};
    std::string name;
    std::string url;
    OffloadAuthType auth_type{OffloadAuthType::None};
    /// True iff a credential is configured (ADR-0010 anti-downgrade rule —
    /// never inferred from column emptiness). Bearer: token. Basic:
    /// "user:pass". Hmac: shared secret.
    bool has_credential{false};
    /// Comma-separated event types or "*". Same semantics as WebhookStore.
    std::string event_types;
    /// 1 = no batching (deliver each event immediately).
    /// >1 = accumulate up to N events before POST.
    int batch_size{1};
    bool enabled{true};
    int64_t created_at{0};
};

struct OffloadDelivery {
    int64_t id{0};
    int64_t target_id{0};
    std::string event_type;
    /// Number of events in this delivery (>=1 when batching).
    int event_count{1};
    /// JSON payload. For batches this is a JSON array.
    std::string payload;
    int status_code{0};
    int64_t delivered_at{0};
    std::string error;
};

/// Typed mutator failure (#3097 lesson — 400 vs 503 classification at the
/// REST seam, mirrors `WebhookWriteError`). `invalid_input` is a CALLER
/// error (400); the other two are store/infra degradation (503).
enum class OffloadWriteError {
    invalid_input,     ///< empty name/url, bad url scheme, batch_size < 1, duplicate name,
                       ///< or a control byte in a free-text field — caller error, 400
    store_unavailable, ///< not open / pool exhausted / codec unavailable — 503
    db_error,          ///< a query against an open store failed — 503
};

class OffloadTargetStore {
public:
    /// Borrows the shared pool and its OWN `SecretCodec` instance (ADR-0010
    /// "Instance model" — one codec per secret-bearing store, not shared;
    /// the codec may itself be backed by a `KeyProvider` shared with other
    /// stores' codecs — that sharing is the caller's concern). Runs the
    /// `offload_target_store` schema migration on a pinned lease and
    /// registers `{"offload_target_store","offload_targets","auth_credential","id"}`
    /// as a secret column. `is_open()` is false if the lease was empty, the
    /// migration failed, or the column registration failed
    /// (duplicate/invalid identifier). The caller MUST run
    /// `secret_codec.init(conn)` AFTER this constructor returns and BEFORE
    /// any encrypt/decrypt call reaches this store — mirrors `AuthDB`'s and
    /// `WebhookStore`'s construction contract exactly.
    explicit OffloadTargetStore(pg::PgPool& pool, pg::SecretCodec& secret_codec);

    /// Destruction does NOT flush pending batched events - call
    /// `flush_all()` on a graceful-shutdown path first if at-least-once
    /// delivery for batched (`batch_size > 1`) targets matters; anything
    /// still buffered when this destructs is dropped.
    ///
    /// #3261 governance hardening (ported from the SQLite era): a delivery
    /// still in flight at destruction time would otherwise race a decrypt
    /// through `secret_codec_` against the codec/`KeyProvider` going away
    /// (`record_delivery` also locks a store member as its first
    /// statement). Deliveries run on `delivery_pool_`, a bounded worker pool
    /// this destructor drains BEFORE returning, so a delivery in flight at
    /// destruction time now blocks the destructor until it finishes rather
    /// than racing it. The caller (`ServerImpl::stop()`) MUST NOT reset the
    /// `SecretCodec`/`KeyProvider` this store borrows until `quiesce()` (or
    /// this destructor) has returned true/completed — see `quiesce()`'s doc
    /// comment.
    ~OffloadTargetStore();

    OffloadTargetStore(const OffloadTargetStore&) = delete;
    OffloadTargetStore& operator=(const OffloadTargetStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics sink for delivery outcome counters. Set-before-traffic
    /// contract, same as DexAlertRouter::set_metrics.
    void set_metrics(yuzu::MetricsRegistry* metrics);

    /// Stop accepting new deliveries and wait up to `timeout` for every
    /// queued/in-flight delivery to finish. Returns true if fully drained.
    /// The caller (ServerImpl::stop()) MUST NOT destroy this store, or the
    /// `SecretCodec`/`KeyProvider` it borrows, if this returns false — a
    /// still-draining delivery decrypts the credential on its worker thread
    /// right up until it finishes (see the file header).
    bool quiesce(std::chrono::milliseconds timeout);

    /// Create a new offload target. `auth_credential` may be empty (no
    /// credential — `has_credential=false`, dispatch sends no auth header
    /// regardless of `auth_type`); a non-empty credential is
    /// envelope-encrypted before it ever reaches Postgres. Returns the
    /// assigned id, or a typed `OffloadWriteError` (400 vs 503 — see the
    /// enum doc).
    [[nodiscard]] std::expected<int64_t, OffloadWriteError>
    create_target(const std::string& name, const std::string& url, OffloadAuthType auth_type,
                 const std::string& auth_credential, const std::string& event_types,
                 int batch_size = 1, bool enabled = true);

    /// List all targets (no credential material — not even the encrypted
    /// blob). AUTHORITATIVE: this is operator-facing config visibility, so a
    /// degraded read returns `nullopt`, never a silently-empty vector that
    /// reads as "no targets configured". The REST route surfaces `nullopt`
    /// as 503. Newest first.
    [[nodiscard]] std::optional<std::vector<OffloadTarget>> list(int limit = 100,
                                                                 int offset = 0) const;

    /// Get a single target by id (no credential material). `store_ok`, if
    /// non-null, is set to false on a degraded read (lease timeout/query
    /// failure) and left true otherwise — including the genuine "no such
    /// id" case, which is a legitimate business answer, not a degradation
    /// (BaselineStore::get_baseline precedent). `nullopt` with `store_ok`
    /// left true means "not found"; `nullopt` with `store_ok` set false
    /// means "degraded — do not treat as not-found".
    [[nodiscard]] std::optional<OffloadTarget> get(int64_t id, bool* store_ok = nullptr) const;

    /// Look up a target by name (no credential material). Same
    /// found/not-found/degraded contract as `get()`.
    [[nodiscard]] std::optional<OffloadTarget> get_by_name(const std::string& name,
                                                           bool* store_ok = nullptr) const;

    /// Delete a target. Cascades on offload_deliveries. `true` = deleted,
    /// `false` = no such id (business fact, not an error), `unexpected` = a
    /// query against an open store failed (503; distinct from the plain
    /// `false` not-found case, #3097 classification).
    [[nodiscard]] std::expected<bool, OffloadWriteError> delete_target(int64_t id);

    /// Recent deliveries for a target, newest first. Deliberately stays a
    /// plain container (empty on error) — delivery HISTORY is an audit
    /// convenience, not itself a decision surface.
    [[nodiscard]] std::vector<OffloadDelivery> get_deliveries(int64_t target_id,
                                                              int limit = 50) const;

    /// Fire an event to all enabled, matching targets. Honours batching:
    /// when a target has `batch_size > 1`, the event is appended to an
    /// in-memory buffer keyed on `target_id`. When the buffer reaches
    /// `batch_size`, it is flushed asynchronously. `target_filter`
    /// (optional non-empty) limits dispatch to targets named in the
    /// vector — `spec.offload.targets` in InstructionDefinition YAML.
    ///
    /// The matching scan is a short bounded-acquire read off the
    /// gRPC/dispatch caller's thread (this store sits on a hot path — see
    /// the load-bearing partial index on `enabled` in the .cpp); a degraded
    /// pool/lease skips this tick's firing entirely (logged + counted),
    /// never blocks the caller. Deliveries run on the bounded
    /// `delivery_pool_` (#3261 governance hardening), not a raw detached
    /// thread.
    void fire_event(const std::string& event_type, const std::string& payload_json,
                    const std::vector<std::string>& target_filter = {});

    /// Flush any non-empty per-target buffers regardless of batch_size.
    /// Useful for graceful shutdown and tests.
    void flush_all();

    /// Compute HMAC-SHA256 signature for HMAC auth. `secret` is a view,
    /// never `std::string` (ADR-0010 zeroization rule — a decrypted
    /// credential's bytes must not be copied into an unzeroized
    /// `std::string` on the way here). Same primitive as
    /// WebhookStore::hmac_sha256. Returns `nullopt` on a crypto-provider
    /// failure (OpenSSL `HMAC()` / a BCrypt step) rather than a
    /// zero-filled hash — a caller must fail the delivery closed, never
    /// send a predictable all-zero signature as if it were real.
    [[nodiscard]] static std::optional<std::string> hmac_sha256(std::string_view secret,
                                                                 std::string_view data);

    /// Base64-encode bytes for the Basic auth header. `data` is a view for
    /// the same zeroization reason as `hmac_sha256`.
    [[nodiscard]] static std::string base64_encode(std::string_view data);

private:
    pg::PgPool& pool_;
    pg::SecretCodec& secret_codec_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};

    /// Delivery-time view of one target: carries the still-ENCRYPTED
    /// credential blob (or none), never plaintext — decrypt happens in
    /// `deliver_single`, right before the auth header/signature is built
    /// (see file header).
    struct OffloadDeliveryTarget {
        int64_t id{0};
        std::string name;
        std::string url;
        OffloadAuthType auth_type{OffloadAuthType::None};
        /// The raw `auth_type` column value `auth_type` was parsed from —
        /// carried alongside the enum so `deliver_single` can defend against
        /// a stored value that doesn't round-trip (a tampered row, or a
        /// value from a since-retired enum member), which the lenient
        /// from-string parser would otherwise silently fold to `None`.
        std::string auth_type_raw;
        std::vector<std::uint8_t> credential_blob; // empty iff !has_credential
        bool has_credential{false};
        int batch_size{1};
    };

    /// Per-target accumulator for `batch_size > 1`. Guarded by buf_mu_;
    /// kept separate from the store's PG lease discipline so a flush in
    /// flight does not block the REST list/get paths.
    struct BufferedEvent {
        std::string event_type;
        std::string payload_json;
    };
    mutable std::mutex buf_mu_;
    std::unordered_map<int64_t, std::vector<BufferedEvent>> buffers_;

    void deliver_single(const OffloadDeliveryTarget& tgt, const std::string& event_type,
                        int event_count, const std::string& payload_body);
    /// Returns false (logged + counted) on a store-not-open/query failure —
    /// the caller (deliver_single, a worker-pool thread) has no 503 to
    /// return to; this surfaces via the metric + log rather than silently
    /// discarding the failure.
    bool record_delivery(int64_t target_id, const std::string& event_type, int event_count,
                         const std::string& payload, int status_code, const std::string& error);

    /// Log + count a delivery dropped because delivery_pool_.submit()
    /// returned false (queue full or the store is quiescing/shutting down).
    void log_dropped_delivery(const std::string& target_url);

    /// Build the JSON body to POST. For a single event this is the raw
    /// payload_json. For a batched flush, the events are wrapped in a
    /// JSON array under `{"events":[…]}`.
    ///
    /// #2437-class guard: each event's raw `payload_json` is depth-checked
    /// BEFORE `nlohmann::json::parse` ever sees it (see mcp_jsonrpc.hpp's
    /// `json_exceeds_depth`): a too-deep event is preserved as a raw string
    /// element, the same fallback already used for a genuinely unparseable
    /// event, rather than being parsed into a tree whose `.dump()` below
    /// would be unboundedly recursive. `target_id` is for the log line only
    /// (identifiers, never the payload).
    static std::string build_batch_body(const std::vector<BufferedEvent>& events,
                                        int64_t target_id);

    // LAST-DECLARED MEMBER (#3261 governance hardening, ported from the
    // SQLite era) - see the identical comment history on
    // WebhookStore::delivery_pool_. The destructor still drains this
    // explicitly before returning (a destructor's body runs before its
    // members' destructors), so this ordering is defense in depth, not the
    // sole guarantee.
    StoreWorkerPool delivery_pool_{/*num_threads=*/4, /*max_queue=*/256};
};

} // namespace yuzu::server
