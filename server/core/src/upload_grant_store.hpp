#pragma once

/// @file upload_grant_store.hpp
/// Born-on-Postgres store (ADR-0006, schema `upload_grant_store`) for the
/// PR1.6a one-time upload grant + authenticated chunked receive protocol
/// (CC-06 server-side fix, docs/adr/3004-artifact-blob-storage.md). Holds
/// three row kinds:
///   * grants     — operator-minted, single-use redemption credentials
///                  (`grant_secret_hash` only; the raw secret is returned
///                  once, at mint, and never stored).
///   * sessions   — the credential a grant redeems into. Authenticates every
///                  chunk/status/commit/cancel call for one upload
///                  (`session_secret_hash` only; the raw secret is returned
///                  once, at session-open, and never stored).
///   * completed_uploads — durable metadata for a successfully committed
///                  upload (destination key, actual size, verified hash,
///                  retention class, received-at), independent of the
///                  session row's own lifecycle so a later session prune
///                  never loses the completion record.
///
/// Posture (ADR-0012 §1): CONSTRUCTION is fail-CLOSED (a reachable database
/// whose schema can't migrate/open sets `startup_failed_` in server.cpp,
/// same pattern as every other born-on-PG store). RUNTIME is AUTHORITATIVE
/// for every mutator (mint/open_session/advance_offset/commit_session/
/// cancel_session/revoke): a lease timeout or query error returns
/// `std::unexpected`/an outcome that is NEVER confusable with a normal
/// negative result (see each method's own contract below) — this store
/// backs an authentication decision (grant/session redemption), and a
/// silently-swallowed write here is a silently-granted or silently-denied
/// upload, never an acceptable failure mode. `list_for_agent` (an
/// authoritative READ, ADR-0012 §1) returns `std::expected` for the same
/// reason.
///
/// Substrate contract (ADR-0008/0012): holds a `pg::PgPool&`, runs its
/// migration at construction on a pinned lease, schema-qualifies every
/// runtime statement (`upload_grant_store.grants` etc.), `RETURNING` is the
/// mutate-and-return idiom (never `sqlite3_changes()`). Bounded acquires
/// everywhere at runtime; unbounded `acquire()` is construction-only.
///
/// EVERY decision (credential grammar, offset/cap/hash checks, expiry,
/// destination-key derivation, the reason-string mapping) lives in the pure
/// `upload_grant_parsers.hpp` header — this store's job is state (Postgres
/// rows) and the one thing the pure layer cannot do: hash a secret /
/// atomically transition a row. `open_session`'s single-redemption
/// guarantee is a Postgres `UPDATE ... WHERE grant_id=$1 AND state='minted'
/// ... RETURNING` — a concurrent second caller's UPDATE deterministically
/// sees 0 rows once the first commits (MVCC row-level serialization, not a
/// read-then-write race in this store's own code).

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// Parameters for `mint`. `expected_sha256` / `retention_class` /
/// `requested_ttl_secs` are optional per the frozen protocol; `retention_class`
/// defaults to "standard" when empty (see `upload_grant::is_valid_retention_class`
/// for the closed set `mint` validates against before this ever reaches SQL).
struct UploadGrantMintParams {
    std::string agent_id;
    std::string source_path; ///< declared by the operator — informational only,
                             ///< NEVER used to derive the destination key.
    std::int64_t declared_max_size{0};
    std::string expected_sha256; ///< empty = grant carries no expected hash
    std::string retention_class; ///< "standard" | "extended" | "transient"
    std::string minted_by;       ///< operator principal (auth::Session::username)
    std::optional<std::int64_t> requested_ttl_secs;
};

/// One-time mint result. `grant_secret` is the RAW secret — the caller
/// (`file_retrieval_routes.cpp`) must return it in the mint response body
/// and MUST NOT log it or persist it anywhere itself; the store already
/// persisted only its digest.
struct UploadGrantMinted {
    std::string grant_id;
    std::string grant_secret;
    std::int64_t expires_at{0};
    std::string destination_key;
};

/// Classifies a `mint` failure so the route layer can map it to the right
/// HTTP status: a validation failure is the OPERATOR's mistake (400), an
/// entropy/database failure is the SERVER's (503) — collapsing both onto one
/// status, as the initial cut did, makes a transient "database unavailable"
/// look exactly like a non-retryable bad request.
enum class MintError {
    kInvalidInput, ///< empty agent_id, non-positive declared_max_size, unrecognized retention_class
    kUnavailable,  ///< store not open, CSPRNG/digest failure, lease/query failure
};

struct MintFailure {
    MintError kind{MintError::kUnavailable};
    std::string message;
};

/// Operator-facing grant metadata (list/get). Never carries the secret or
/// its hash.
struct UploadGrantRow {
    std::string grant_id;
    std::string agent_id;
    std::string source_path;
    std::int64_t declared_max_size{0};
    std::string expected_sha256;
    std::string retention_class;
    std::string destination_key;
    std::string state; ///< "minted" | "redeemed" | "revoked"
    std::string minted_by;
    std::int64_t created_at{0};
    std::int64_t expires_at{0};
};

enum class OpenSessionOutcome {
    kOpened,
    kGrantUnknown,        ///< no such grant_id, OR the secret didn't match, OR the grant was revoked
                           ///< (collapsed — see upload_grant_parsers.hpp file header)
    kAlreadyRedeemed,
    kExpired,
    kUnavailable, ///< store/lease error — caller must 503, never treat as any of the above
};

struct UploadGrantSession {
    std::string upload_id;
    std::string session_secret; ///< RAW, one-time — same handling contract as grant_secret above
    std::int64_t chunk_max_bytes{0};
    std::int64_t offset{0}; ///< always 0 at open
    std::int64_t expires_at{0};
};

struct OpenSessionResult {
    OpenSessionOutcome outcome{OpenSessionOutcome::kUnavailable};
    UploadGrantSession session; ///< engaged only when outcome == kOpened
};

enum class SessionAuthOutcome {
    kOk,
    kSessionUnknown, ///< no such upload_id, OR the secret didn't match (collapsed)
    kSessionTerminal,
    kExpired,
    kUnavailable,
};

/// Server-side facts about an authenticated session — everything the chunk/
/// status/commit/cancel handlers need, resolved ONCE per request by
/// `authenticate_session` so no handler re-derives agent_id/destination_key
/// from anything client-supplied.
struct UploadSessionInfo {
    std::string upload_id;
    std::string grant_id;
    std::string agent_id;
    std::string destination_key;
    std::int64_t declared_max_size{0};
    std::string expected_sha256;
    std::string retention_class;
    std::string state; ///< "open" | "committed" | "cancelled" | "expired"
    std::int64_t recorded_offset{0};
    std::int64_t created_at{0};
    std::int64_t expires_at{0};
};

struct SessionAuthResult {
    SessionAuthOutcome outcome{SessionAuthOutcome::kUnavailable};
    UploadSessionInfo info; ///< engaged only when outcome == kOk
};

class UploadGrantStore {
public:
    /// Borrows the shared pool and runs the `upload_grant_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed.
    explicit UploadGrantStore(pg::PgPool& pool);

    UploadGrantStore(const UploadGrantStore&) = delete;
    UploadGrantStore& operator=(const UploadGrantStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Mint a new grant. Generates `grant_id` (16 random bytes, hex) and
    /// `grant_secret` (32 random bytes, hex) via `auth::AuthManager::random_bytes`,
    /// persists only `sha256(grant_secret)`, and derives the destination key
    /// from `retention_class` + the freshly-minted `grant_id` alone (see
    /// `upload_grant::derive_destination_key` — `params.source_path` is
    /// stored verbatim as informational metadata but never touches the key).
    /// `unexpected` on invalid input (empty agent_id, non-positive
    /// declared_max_size, an unrecognized retention_class) or a store/CSPRNG/
    /// digest failure — `MintFailure::kind` tells the caller which, so a
    /// transient infrastructure failure never reports as a non-retryable bad
    /// request. Never a silent partial mint.
    [[nodiscard]] std::expected<UploadGrantMinted, MintFailure>
    mint(const UploadGrantMintParams& params, std::int64_t now);

    /// Authoritative list (ADR-0012 §1): `unexpected` on a runtime DB error,
    /// a value (possibly empty) on success. `agent_id` empty = every grant
    /// (the caller — `file_retrieval_routes.cpp`'s list handler — applies
    /// the `ListReadFn` visibility filter over the returned rows for
    /// `AdmitScoped`, rather than pushing a per-agent-set SQL filter into
    /// this store; the visible-agent set size is small and bounded by the
    /// caller's own management-group membership, not by this table).
    [[nodiscard]] std::expected<std::vector<UploadGrantRow>, std::string>
    list_for_agent(const std::string& agent_id = {}) const;

    /// Revoke a grant. `true` — the grant existed, was still `minted`, and
    /// is now `revoked` (never redeemable again). `false` — no such grant,
    /// or it was already redeemed/revoked (nothing to do; a redeemed
    /// grant's session is unaffected — revoke only closes the mint-time
    /// redemption window). `unexpected` on a store/lease error — the caller
    /// MUST surface this (503), never read it as `false`/"already gone"
    /// (same ADR-0030 §Posture contract `ApiTokenStore::revoke_token` uses).
    [[nodiscard]] std::expected<bool, std::string> revoke(const std::string& grant_id);

    /// Redeem a grant credential into a fresh session — the ONE atomic
    /// single-redemption operation the frozen protocol requires. `grant_id`/
    /// `presented_secret` come straight from the decoded
    /// `X-Yuzu-Upload-Grant` header (see `upload_grant::parse_credential`).
    /// Secret verification (constant-time, against the stored digest) runs
    /// BEFORE the atomic UPDATE, as a plain lookup-by-id + compare — the
    /// UPDATE's own WHERE clause conditions only on `grant_id`/`state`/
    /// `expires_at`, matching the frozen protocol's text verbatim. The
    /// redemption UPDATE and the session INSERT run in ONE transaction: an
    /// insert failure (entropy, constraint, connection loss mid-statement)
    /// rolls back the redemption too, so a transient fault never permanently
    /// burns a grant with no session to show for it.
    [[nodiscard]] OpenSessionResult
    open_session(const std::string& grant_id, const std::string& presented_secret, std::int64_t now);

    /// Authenticate `X-Yuzu-Upload-Session: <upload_id>.<secret>` and return
    /// the session's server-side facts. Every chunk/status/commit/cancel
    /// handler calls this FIRST and derives everything else (destination
    /// key, caps, offset) from the returned `UploadSessionInfo` — never from
    /// anything the request itself claims.
    [[nodiscard]] SessionAuthResult
    authenticate_session(const std::string& upload_id, const std::string& presented_secret,
                         std::int64_t now);

    /// Atomically advance the recorded offset after a chunk has been
    /// durably written to disk (the route layer writes the bytes BEFORE
    /// calling this — see file_retrieval_routes.cpp's "write once" comment).
    /// CAS on `recorded_offset = expected_prev_offset AND state = 'open'`:
    /// `true` — advanced; `false` — the CAS missed (a concurrent chunk for
    /// the same session already moved the offset, or the session left
    /// `open` — a benign, expected outcome under a well-behaved single-
    /// writer-per-session client, never surfaced as an error). `unexpected`
    /// only on a genuine store/lease failure.
    [[nodiscard]] std::expected<bool, std::string>
    advance_offset(const std::string& upload_id, std::int64_t expected_prev_offset,
                  std::int64_t new_offset);

    /// Terminal success: sets state -> `committed`, writes the
    /// `completed_uploads` row, in ONE transaction. `true` — committed (the
    /// session was `open`); `false` — the CAS missed (already terminal,
    /// concurrent commit/cancel) — the caller re-reads via
    /// `authenticate_session` to report `session_terminal`. `unexpected`
    /// only on a genuine store/lease failure.
    [[nodiscard]] std::expected<bool, std::string>
    commit_session(const std::string& upload_id, std::int64_t actual_size,
                  const std::string& verified_hash, std::int64_t now);

    /// Terminal, non-success: sets state -> `cancelled`. Used for BOTH the
    /// explicit `DELETE /api/v1/uploads/{id}` cancel and the `size_exceeded`
    /// forced termination (frozen protocol: "the session terminates" — same
    /// wire state, partial blob discarded either way). Same true/false/
    /// unexpected contract as `commit_session`.
    [[nodiscard]] std::expected<bool, std::string> cancel_session(const std::string& upload_id);

    /// Terminal, non-success: sets state -> `expired`. Called (in addition
    /// to the background `expire_stale_sessions` sweep) whenever a request
    /// against an already-expired-but-still-`open` session is TOUCHED
    /// (frozen protocol: "any request after it -> 410 expired, partial
    /// discarded") — distinct from `cancel_session` so the operator-visible
    /// terminal state accurately records WHY the session ended. Same true/
    /// false/unexpected contract as `cancel_session`.
    [[nodiscard]] std::expected<bool, std::string> expire_now(const std::string& upload_id);

    /// Best-effort maintenance sweep: marks every `open` session whose
    /// `expires_at <= now` as `expired`. NOT required for correctness — every
    /// per-request path already evaluates expiry itself via the injected
    /// clock — this exists purely so a long-idle abandoned session doesn't
    /// sit `open` forever in `list`/operator views. Returns the count swept;
    /// 0 (never negative) on a store error, logged at debug (mirrors
    /// `OfflineEndpointStore::upsert`'s durability-on-top posture for this
    /// one housekeeping path only — every OTHER method above stays
    /// authoritative).
    std::size_t expire_stale_sessions(std::int64_t now);

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
