#pragma once

/// @file upload_grant_parsers.hpp
/// PURE decision layer for the one-time upload grant + authenticated
/// chunked receive protocol (PR1.6a, CC-06 server-side fix). Every branch a
/// reviewer needs to audit for the credential/offset/cap/hash/expiry state
/// machine lives HERE, as free functions over plain values — no store, no
/// httplib, no libpq, and (deliberately) no `now()`: every time-dependent
/// decision takes the instant to compare against as an explicit parameter,
/// injected by the caller (`upload_grant_store.cpp` / `file_retrieval_routes.cpp`),
/// so this header is trivially unit-testable without a clock or a database.
///
/// FROZEN PROTOCOL v1 (Architect-frozen; p7 implements the agent half
/// against this identical text — do not drift):
///
///  * Mint (operator, POST /api/v1/upload-grants, securable UploadGrant,
///    operation Write): body names agent_id, source path, declared max
///    size, optional expected sha256, retention class. Server derives
///    destination key, expiry (default <= 15 min), grant_id, and a 32-byte
///    random grant_secret. Response returns grant_id + grant_secret EXACTLY
///    ONCE. The store persists only a SHA-256 digest of the secret, never
///    plaintext.
///  * Operator list/revoke: GET /api/v1/upload-grants (UploadGrant:Read,
///    routed through RbacStore::authorize_list_read), DELETE
///    /api/v1/upload-grants/{grant_id} (UploadGrant:Delete).
///  * Session open (agent, POST /api/v1/uploads, header
///    `X-Yuzu-Upload-Grant: <grant_id>.<grant_secret>`, TLS required):
///    atomic single redemption. A second open with the same grant
///    credential fails 409 grant_already_redeemed. Success returns
///    upload_id, a fresh 32-byte session_secret (returned once), chunk_max_bytes,
///    offset 0.
///  * Chunk (agent, PUT /api/v1/uploads/{upload_id}/chunk, header
///    `X-Yuzu-Upload-Session: <upload_id>.<session_secret>`,
///    `Content-Range: bytes <start>-<end>/<total>`, body = raw bytes):
///    accept only start == recorded_offset; mismatch -> 409 offset_mismatch
///    with the authoritative offset in the body. Over chunk_max_bytes ->
///    413 chunk_too_large. Exceeding the grant's declared size -> 413
///    size_exceeded and the session terminates.
///  * Status/resume (agent, GET /api/v1/uploads/{upload_id}, session
///    header) -> {state, offset, expires_at}.
///  * Commit (agent, POST /api/v1/uploads/{upload_id}/commit, session
///    header, body {"sha256":"..."}): verify total bytes == declared size
///    and the streaming digest == the supplied sha256 AND, if the grant
///    carried one, the grant's expected sha256; ANY of those three checks
///    failing -> 422 hash_mismatch (single collapsed reason — see
///    `verify_commit` below) and the blob is discarded. Success -> state
///    committed (terminal), session secret invalidated.
///  * Cancel (agent, DELETE /api/v1/uploads/{upload_id}, session header):
///    partial blob discarded, state cancelled (terminal).
///  * Expiry: the session inherits the grant's expiry; any request strictly
///    after it -> 410 expired, partial discarded. `now == expires_at` is
///    still valid (not expired); `now > expires_at` is expired.
///  * Error envelope: `{"error":{"code":<http>,"message":"...","reason":"..."},
///    "meta":{"api_version":"v1"}}`, `reason` from the closed 10-value set
///    below.
///  * No endpoint on this surface accepts an agent_id, destination path or
///    server URL from the client, on any path, ever — the destination key
///    is derived ONLY from server-side facts (`derive_destination_key`
///    below takes a retention class and a grant_id, nothing client-typed).
///
/// HTTP status mapping (the Architect's frozen text pins 409/410/413/422 for
/// six of the ten reasons explicitly; the remaining four — grant_unknown,
/// session_unknown, session_terminal, tls_required — are this package's own
/// call, restated here so p7 codes against the exact numbers):
///   grant_unknown          -> 401  (collapsed with "wrong secret" — never
///                                   distinguish "no such grant" from "bad
///                                   secret" on the wire; device_token_rejection.hpp
///                                   precedent)
///   grant_already_redeemed -> 409
///   expired                -> 410
///   offset_mismatch        -> 409
///   chunk_too_large        -> 413
///   size_exceeded           -> 413
///   hash_mismatch           -> 422
///   session_unknown         -> 401  (same collapse as grant_unknown)
///   session_terminal        -> 409
///   tls_required            -> 400

#include <nlohmann/json.hpp>

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server::upload_grant {

// ── Credential grammar (`<id>.<secret>`) ────────────────────────────────────

/// Byte lengths the frozen protocol mints (`auth::AuthManager::random_bytes`
/// output, hex-encoded by the store/route layer — see
/// `upload_grant_store.cpp`): a 16-byte id (32 hex chars) and a 32-byte
/// secret (64 hex chars), for BOTH the grant credential and the session
/// credential — one grammar, two call sites.
inline constexpr std::size_t kCredentialIdHexLen = 32;
inline constexpr std::size_t kCredentialSecretHexLen = 64;

/// A decoded `<id>.<secret>` credential header value.
struct Credential {
    std::string id;
    std::string secret;
};

/// True iff `s` is exactly `len` lowercase hex characters (`[0-9a-f]{len}`).
/// Uppercase is rejected outright (not normalized) — the store hex-encodes
/// with `AuthManager::bytes_to_hex`, which is always lowercase, so an
/// uppercase credential can never be a genuine one; accepting it would only
/// widen the parse surface for no legitimate caller.
[[nodiscard]] inline bool is_lowercase_hex(std::string_view s, std::size_t len) noexcept {
    if (s.size() != len)
        return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

/// Parse `X-Yuzu-Upload-Grant` / `X-Yuzu-Upload-Session` header values:
/// exactly one `.` separating an `id_len`-hex id from a `secret_len`-hex
/// secret. Returns nullopt on ANY grammar violation (missing/extra dots,
/// wrong length, non-hex, empty) — the caller maps a parse failure to the
/// same collapsed reason (`grant_unknown`/`session_unknown`) a valid-grammar-
/// but-wrong-value credential gets, so a malformed header is never
/// distinguishable on the wire from an unknown one.
[[nodiscard]] inline std::optional<Credential>
parse_credential(std::string_view header_value, std::size_t id_len = kCredentialIdHexLen,
                 std::size_t secret_len = kCredentialSecretHexLen) {
    const auto dot = header_value.find('.');
    if (dot == std::string_view::npos)
        return std::nullopt;
    // Exactly one dot: a second one anywhere in the remainder is a grammar
    // violation, not a longer secret.
    const auto id_part = header_value.substr(0, dot);
    const auto secret_part = header_value.substr(dot + 1);
    if (secret_part.find('.') != std::string_view::npos)
        return std::nullopt;
    if (!is_lowercase_hex(id_part, id_len) || !is_lowercase_hex(secret_part, secret_len))
        return std::nullopt;
    return Credential{std::string(id_part), std::string(secret_part)};
}

/// Encode a credential back to wire form. Used by the store/routes layer
/// when composing the one-time mint/session-open response bodies — kept
/// here so the wire format has exactly one producer and one consumer.
[[nodiscard]] inline std::string encode_credential(std::string_view id, std::string_view secret) {
    std::string out;
    out.reserve(id.size() + 1 + secret.size());
    out.append(id).append(".").append(secret);
    return out;
}

/// Constant-time byte comparison. Used to compare a presented secret's
/// digest against the stored digest AFTER a plain (non-secret-gated) lookup
/// by id — the frozen protocol's atomic redemption UPDATE conditions only on
/// `grant_id`/`state`, never the secret, so the secret check is this
/// separate, explicit step (see `upload_grant_store.cpp::open_session`).
/// Mirrors `auth::AuthManager::constant_time_compare` (auth.cpp) — duplicated
/// rather than depending on `auth.hpp` here, to keep this header free of the
/// store/httplib/pg include graph auth.hpp pulls in transitively.
[[nodiscard]] inline bool constant_time_equals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size())
        return false;
    volatile unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    return diff == 0;
}

// ── Content-Range parsing (`bytes <start>-<end>/<total>`) ──────────────────

struct ContentRange {
    std::int64_t start{0};
    std::int64_t end{0};   ///< inclusive last byte offset of this chunk
    std::int64_t total{0}; ///< client-declared total upload size (NOT authoritative — see note below)
};

/// Parse a `Content-Range: bytes <start>-<end>/<total>` header value.
/// Returns nullopt on any malformed input: wrong unit, non-numeric fields,
/// `start < 0`, `end < start`, `total <= 0`, or `end >= total`. Deliberately
/// strict — this is a chunk-upload control header, not the HTTP Range spec's
/// full grammar (`*` total, multiple ranges, suffix-ranges are all rejected).
///
/// NOTE ON AUTHORITY: `total` is client-asserted metadata carried for the
/// agent's own bookkeeping. It is NEVER treated as authoritative by the
/// server — the only cumulative-size gate is `cumulative_exceeds_declared`
/// below, evaluated against the grant's server-recorded `declared_max_size`.
[[nodiscard]] inline std::optional<ContentRange> parse_content_range(std::string_view header_value) {
    constexpr std::string_view kPrefix = "bytes ";
    if (header_value.size() <= kPrefix.size() || !header_value.starts_with(kPrefix))
        return std::nullopt;
    std::string_view rest = header_value.substr(kPrefix.size());

    const auto dash = rest.find('-');
    const auto slash = rest.find('/');
    if (dash == std::string_view::npos || slash == std::string_view::npos || slash < dash)
        return std::nullopt;

    std::string_view start_sv = rest.substr(0, dash);
    std::string_view end_sv = rest.substr(dash + 1, slash - dash - 1);
    std::string_view total_sv = rest.substr(slash + 1);
    if (start_sv.empty() || end_sv.empty() || total_sv.empty())
        return std::nullopt;

    auto parse_nonneg = [](std::string_view sv, std::int64_t& out) {
        if (sv.empty())
            return false;
        std::int64_t v = 0;
        for (char c : sv) {
            if (c < '0' || c > '9')
                return false;
            // Overflow guard: this header is bytes-scale, never anywhere near
            // INT64_MAX; refuse rather than wrap.
            if (v > (std::numeric_limits<std::int64_t>::max() - (c - '0')) / 10)
                return false;
            v = v * 10 + (c - '0');
        }
        out = v;
        return true;
    };

    ContentRange cr;
    if (!parse_nonneg(start_sv, cr.start) || !parse_nonneg(end_sv, cr.end) ||
        !parse_nonneg(total_sv, cr.total))
        return std::nullopt;
    if (cr.total <= 0 || cr.end < cr.start || cr.end >= cr.total)
        return std::nullopt;
    return cr;
}

/// Chunk length implied by a parsed Content-Range (inclusive end).
[[nodiscard]] inline std::int64_t content_range_length(const ContentRange& cr) noexcept {
    return cr.end - cr.start + 1;
}

// ── Offset discipline ───────────────────────────────────────────────────────

struct OffsetCheck {
    bool ok{false};
    /// The server's recorded offset — echoed back on a mismatch so the agent
    /// can resume from the authoritative point (frozen protocol: "409
    /// offset_mismatch with the authoritative offset in the body").
    std::int64_t authoritative_offset{0};
};

[[nodiscard]] inline OffsetCheck check_offset(std::int64_t recorded_offset,
                                              std::int64_t start) noexcept {
    return OffsetCheck{start == recorded_offset, recorded_offset};
}

// ── Caps ─────────────────────────────────────────────────────────────────

/// Default per-chunk cap (8 MiB). Single source of truth for both
/// `UploadGrantStore::open_session` (echoed to the agent in the session-open
/// response) and `file_retrieval_routes.cpp` (the actual enforcement site) —
/// defined here, in the pure layer, so the two can never drift.
inline constexpr std::int64_t kDefaultChunkMaxBytes = 8 * 1024 * 1024;

[[nodiscard]] inline bool chunk_exceeds_max(std::int64_t chunk_len,
                                            std::int64_t chunk_max_bytes) noexcept {
    return chunk_len > chunk_max_bytes;
}

/// True when accepting this chunk would push the session's cumulative
/// received bytes past the grant's declared size. Evaluated BEFORE the
/// chunk is written — the caller must terminate the session on `true`
/// (frozen protocol: "the session terminates"), never merely reject the
/// one request and stay open.
[[nodiscard]] inline bool cumulative_exceeds_declared(std::int64_t recorded_offset,
                                                      std::int64_t chunk_len,
                                                      std::int64_t declared_max_size) noexcept {
    // recorded_offset/chunk_len are both caller-validated non-negative and
    // bounded well under INT64_MAX (chunk_len <= chunk_max_bytes, itself a
    // small server-configured cap) by the time this runs, so the add cannot
    // overflow in practice — still written as a saturating comparison rather
    // than a bare `+` so a future caller that skips that validation fails
    // safe (rejects) instead of wrapping.
    if (chunk_len > declared_max_size - recorded_offset)
        return true;
    return false;
}

/// True when a chunk's client-asserted Content-Range `total` claims a bigger
/// entity than the grant actually admits. `total` is still never
/// authoritative for the cumulative-bytes gate (`cumulative_exceeds_declared`
/// above is the real enforcement) — this is a CAP, not an equality
/// requirement (a client is free to assert a smaller honest total for a
/// smaller-than-the-cap upload), so a well-behaved chunk whose own length
/// merely exceeds `chunk_max_bytes` while its total stays within the grant's
/// cap is unaffected — only a total that oversells past what the grant ever
/// admitted is rejected here.
[[nodiscard]] inline bool total_exceeds_declared(std::int64_t total,
                                                 std::int64_t declared_max_size) noexcept {
    return total > declared_max_size;
}

// ── Commit verification ─────────────────────────────────────────────────────

enum class CommitCheck {
    kOk,
    kMismatch, ///< any of size/client-hash/grant-hash failed -> hash_mismatch (collapsed, see below)
};

/// Case-insensitive hex-string equality (sha256 hex may arrive upper- or
/// lower-case from a client; the server always compares logically, not
/// byte-for-byte on case).
[[nodiscard]] inline bool hex_equal_ci(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size())
        return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        auto lower = [](char c) { return (c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c; };
        if (lower(a[i]) != lower(b[i]))
            return false;
    }
    return true;
}

/// The commit-time verification state machine. The frozen protocol names
/// three independent checks (total size, client-supplied hash, grant's
/// expected hash) but ONE collapsed outcome — the acceptance criteria are
/// explicit: "Commit verifies size and both hashes; a mismatch returns 422
/// hash_mismatch" — so this never tries to distinguish which of the three
/// failed on the wire (defense-in-depth against a hash-oracle: revealing
/// "size was fine but hash was wrong" leaks more than the agent needs to
/// retry-from-scratch). `grant_expected_sha256_hex` empty means the grant
/// carried no expected hash (that leg is skipped, not treated as a match).
///
/// The size leg is a CAP, not an equality requirement — the same reading
/// `total_exceeds_declared` above states and the only one the grant's own
/// field name (`declared_max_size`) supports. It used to test `!=`, which
/// 422'd every honest upload smaller than the grant's maximum: the session
/// is cancelled and the blob deleted on a mismatch, and the grant is
/// already redeemed by then, so the agent had no retry. Callers pass the
/// grant's `declared_max_size` here, so an equality test was only ever
/// satisfiable by a client that happened to send exactly the cap.
[[nodiscard]] inline CommitCheck verify_commit(std::int64_t actual_size,
                                               std::int64_t declared_max_size,
                                               std::string_view computed_sha256_hex,
                                               std::string_view client_sha256_hex,
                                               std::string_view grant_expected_sha256_hex) {
    if (actual_size > declared_max_size)
        return CommitCheck::kMismatch;
    if (!hex_equal_ci(computed_sha256_hex, client_sha256_hex))
        return CommitCheck::kMismatch;
    if (!grant_expected_sha256_hex.empty() &&
        !hex_equal_ci(computed_sha256_hex, grant_expected_sha256_hex))
        return CommitCheck::kMismatch;
    return CommitCheck::kOk;
}

// ── Destination-key derivation (server-side facts ONLY) ─────────────────────

/// Small allowlist — the mint request's `retention_class` field is validated
/// against this BEFORE it is ever interpolated into a destination key, so an
/// operator-supplied string can never smuggle a path-traversal segment into
/// the blob layout. Extend deliberately, not by widening the grammar.
[[nodiscard]] inline bool is_valid_retention_class(std::string_view rc) noexcept {
    return rc == "standard" || rc == "extended" || rc == "transient";
}

/// A mint request's OPTIONAL `expected_sha256`: absent (empty) or exactly 64
/// lowercase hex characters — the same grammar the MCP `mint_upload_grant`
/// tool's input schema enforces via `"pattern": "^[0-9a-f]{64}$"`.
///
/// The REST twin accepted anything and persisted it verbatim, which is not a
/// cosmetic gap: a stored non-hash value is non-empty, so `verify_commit`'s
/// grant-expected leg runs and can never match a real digest. Every commit
/// against that grant 422s, and a commit mismatch cancels the session and
/// deletes the blob while the grant is already redeemed — so a typo at mint
/// time silently converts the grant into one that can never be used, with no
/// retry. Rejecting at mint is the only point where the operator can still
/// fix it. Validated here (not in the store) so both surfaces share one
/// grammar and it is unit-testable without a database.
/// Reuses `is_lowercase_hex` rather than re-spelling the character class:
/// the digest and the credential secret are both 64 lowercase hex chars, so
/// one grammar covers both and cannot drift.
[[nodiscard]] inline bool is_valid_expected_sha256(std::string_view hex) noexcept {
    if (hex.empty())
        return true; // absent — the grant simply carries no expected hash.
    return is_lowercase_hex(hex, kCredentialSecretHexLen);
}

/// The ONLY inputs are server-minted identifiers: the (pre-validated)
/// retention class and the grant_id this store itself generated
/// (`kCredentialIdHexLen` lowercase hex chars — see `parse_credential`).
/// Neither the client-declared `source path` nor any client-declared
/// server URL ever reaches this function or anything it returns — the
/// frozen protocol's "no endpoint accepts a destination... from the
/// client" invariant is structural here, not a runtime check: there is no
/// parameter through which a caller COULD pass one.
[[nodiscard]] inline std::string derive_destination_key(std::string_view retention_class,
                                                        std::string_view grant_id) {
    std::string key;
    key.reserve(retention_class.size() + 1 + grant_id.size());
    key.append(retention_class).append("/").append(grant_id);
    return key;
}

// ── Expiry (injected clock — no now() in this header) ───────────────────────

/// `now == expires_at` is still valid; `now > expires_at` is expired
/// (frozen protocol: "any request after it -> 410 expired").
[[nodiscard]] inline bool is_expired(std::int64_t expires_at, std::int64_t now) noexcept {
    return now > expires_at;
}

/// Resolve a mint request's grant TTL: `requested` (seconds, nullopt = use
/// the default) clamped to `(0, max_ttl_secs]`. A non-positive requested
/// value is rejected outright (treated as absent -> default), never
/// silently floored to 1 — an operator typo should not mint a
/// near-instantly-expired grant that reads as a confusing "expired"
/// response a heartbeat later.
[[nodiscard]] inline std::int64_t resolve_grant_ttl_secs(std::optional<std::int64_t> requested,
                                                         std::int64_t default_ttl_secs = 900,
                                                         std::int64_t max_ttl_secs = 900) noexcept {
    if (!requested.has_value() || *requested <= 0)
        return default_ttl_secs;
    return *requested > max_ttl_secs ? max_ttl_secs : *requested;
}

// ── Reason set + error envelope ─────────────────────────────────────────────

/// The closed 10-value machine `reason` set. Exhaustive — every rejection
/// path in `upload_grant_store.cpp` / `file_retrieval_routes.cpp` maps to
/// exactly one of these; there is no "other"/"unknown" catch-all member by
/// design, so an un-mapped C++ error is a compile-time-visible bug (a
/// missing switch arm), not a silently-invented eleventh reason.
enum class Reason {
    kGrantUnknown,
    kGrantAlreadyRedeemed,
    kExpired,
    kOffsetMismatch,
    kChunkTooLarge,
    kSizeExceeded,
    kHashMismatch,
    kSessionUnknown,
    kSessionTerminal,
    kTlsRequired,
};

[[nodiscard]] inline std::string_view reason_string(Reason r) noexcept {
    switch (r) {
    case Reason::kGrantUnknown: return "grant_unknown";
    case Reason::kGrantAlreadyRedeemed: return "grant_already_redeemed";
    case Reason::kExpired: return "expired";
    case Reason::kOffsetMismatch: return "offset_mismatch";
    case Reason::kChunkTooLarge: return "chunk_too_large";
    case Reason::kSizeExceeded: return "size_exceeded";
    case Reason::kHashMismatch: return "hash_mismatch";
    case Reason::kSessionUnknown: return "session_unknown";
    case Reason::kSessionTerminal: return "session_terminal";
    case Reason::kTlsRequired: return "tls_required";
    }
    return "grant_unknown"; // unreachable — every enumerator handled above
}

/// HTTP status for each reason — see the file-header doc comment for the
/// rationale on the four this package chose itself.
[[nodiscard]] inline int reason_http_status(Reason r) noexcept {
    switch (r) {
    case Reason::kGrantUnknown: return 401;
    case Reason::kGrantAlreadyRedeemed: return 409;
    case Reason::kExpired: return 410;
    case Reason::kOffsetMismatch: return 409;
    case Reason::kChunkTooLarge: return 413;
    case Reason::kSizeExceeded: return 413;
    case Reason::kHashMismatch: return 422;
    case Reason::kSessionUnknown: return 401;
    case Reason::kSessionTerminal: return 409;
    case Reason::kTlsRequired: return 400;
    }
    return 401; // unreachable
}

/// The frozen envelope: `{"error":{"code":<http>,"message":"...",
/// "reason":"..."},"meta":{"api_version":"v1"}}`. `extra` merges additional
/// fields into the `error` object (e.g. `offset_mismatch`'s authoritative
/// offset) — empty by default. Pure string building, no httplib dependency,
/// so `file_retrieval_routes.cpp` is the only place that ever touches
/// `httplib::Response`.
[[nodiscard]] inline std::string error_envelope(Reason r, std::string_view message,
                                                const nlohmann::json& extra = nlohmann::json::object()) {
    nlohmann::json error = {{"code", reason_http_status(r)},
                            {"message", std::string(message)},
                            {"reason", std::string(reason_string(r))}};
    for (auto& [k, v] : extra.items())
        error[k] = v;
    nlohmann::json envelope = {{"error", error}, {"meta", {{"api_version", "v1"}}}};
    return envelope.dump();
}

} // namespace yuzu::server::upload_grant
