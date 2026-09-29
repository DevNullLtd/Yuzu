#pragma once

/// @file content_dist_upload_parsers.hpp
/// PURE decision layer for `content_dist`'s `upload_file` action — the AGENT
/// half of the one-time upload grant + authenticated chunked receive
/// protocol (PR1.6, CC-06). Every branch a reviewer needs to audit for
/// chunk planning, resume, retry/backoff and the ten-reason wire
/// classification lives HERE, as free functions over plain values — no
/// httplib, no filesystem, no sleeping, no clock read. `content_dist_plugin.cpp`
/// is the thin OS/network shell around this header.
///
/// FROZEN PROTOCOL (Architect-frozen; implemented verbatim against the
/// identical text `server/core/src/upload_grant_parsers.hpp` implements —
/// this header deliberately DUPLICATES that header's ten-value reason
/// enum/strings rather than including it: an `agents/plugins/*` source must
/// never depend on a `server/core/src/*` header, the same layering split
/// every other agent plugin already observes):
///
///  * Session open (agent, POST /api/v1/uploads, header
///    `X-Yuzu-Upload-Grant: <grant_id>.<grant_secret>`, TLS required) ->
///    `{"upload_id","session_secret","chunk_max_bytes","offset","expires_at"}`,
///    HTTP 201.
///  * Chunk (agent, PUT /api/v1/uploads/{upload_id}/chunk, header
///    `X-Yuzu-Upload-Session: <upload_id>.<session_secret>`,
///    `Content-Range: bytes <start>-<end>/<total>`, body = raw bytes) ->
///    `{"offset":<new_offset>}`, HTTP 200 on success.
///  * Status (agent, GET /api/v1/uploads/{upload_id}, session header) ->
///    `{"state","offset","expires_at"}`.
///  * Commit (agent, POST /api/v1/uploads/{upload_id}/commit, session
///    header, body `{"sha256":"..."}`) -> `{"state":"committed","actual_size","sha256"}`,
///    HTTP 200.
///  * Cancel (agent, DELETE /api/v1/uploads/{upload_id}, session header).
///  * Error envelope: `{"error":{"code":<http>,"message":"...","reason":"..."},
///    "meta":{"api_version":"v1"}}` — `offset_mismatch` merges an extra
///    `"offset"` key into the SAME `error` object (never top-level).
///    `reason` is one of the closed 10-value set below.

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::content_dist::upload {

// ── Credential grammar ────────────────────────────────────────────────────
//
// #3136 minor: the frozen `<id>.<secret>` grammar `X-Yuzu-Upload-Grant`/
// `X-Yuzu-Upload-Session` both use — duplicated from
// server/core/src/upload_grant_parsers.hpp's `kCredentialIdHexLen`/
// `kCredentialSecretHexLen`/`is_lowercase_hex` (never included: the
// agents/plugins/* <-> server/core/* layering split this file's header
// already documents). The server already fails closed on a malformed
// credential (grant_unknown/session_unknown), so this is a LOCAL,
// clarity-of-error precheck only — a malformed grant_id/grant_secret
// parameter is caught before a doomed network round-trip, with a message
// naming the actual problem instead of a generic 401.

inline constexpr std::size_t kCredentialIdHexLen = 32;
inline constexpr std::size_t kCredentialSecretHexLen = 64;

[[nodiscard]] inline bool is_lowercase_hex(std::string_view s, std::size_t len) noexcept {
    if (s.size() != len)
        return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

/// True iff `id` is exactly `kCredentialIdHexLen` lowercase hex chars and
/// `secret` is exactly `kCredentialSecretHexLen` lowercase hex chars — the
/// shape both `grant_id`/`grant_secret` (mint-time) and the server-returned
/// `upload_id`/`session_secret` (session-open time) must satisfy.
[[nodiscard]] inline bool is_valid_credential_parts(std::string_view id,
                                                    std::string_view secret) noexcept {
    return is_lowercase_hex(id, kCredentialIdHexLen) &&
          is_lowercase_hex(secret, kCredentialSecretHexLen);
}

// ── Chunk planning ──────────────────────────────────────────────────────

/// One planned chunk: `[start, end]` inclusive, `total` echoing the whole
/// upload's declared size (the `Content-Range` header's three numbers).
struct ChunkSpec {
    std::int64_t start{0};
    std::int64_t end{0}; ///< inclusive
    std::int64_t total{0};
};

/// The next chunk to send from `offset`, honouring the server-supplied
/// `chunk_max_bytes` (never buffering — or planning — the whole file at
/// once). `nullopt` when there is nothing left to send (`offset >=
/// file_size`) or the inputs are structurally invalid.
[[nodiscard]] inline std::optional<ChunkSpec>
plan_next_chunk(std::int64_t offset, std::int64_t file_size, std::int64_t chunk_max_bytes) noexcept {
    if (file_size <= 0 || chunk_max_bytes <= 0 || offset < 0 || offset >= file_size)
        return std::nullopt;
    const auto remaining = file_size - offset;
    const auto len = remaining < chunk_max_bytes ? remaining : chunk_max_bytes;
    return ChunkSpec{offset, offset + len - 1, file_size};
}

/// Total number of chunks `plan_next_chunk` will walk through for a fresh
/// (offset-0) upload — used only for progress reporting, never for
/// planning a request body.
[[nodiscard]] inline std::int64_t chunk_count(std::int64_t file_size,
                                              std::int64_t chunk_max_bytes) noexcept {
    if (file_size <= 0 || chunk_max_bytes <= 0)
        return 0;
    return (file_size + chunk_max_bytes - 1) / chunk_max_bytes;
}

// ── Resume-offset reconciliation ────────────────────────────────────────

/// Validate a server-asserted "authoritative offset" (the `offset` field a
/// 409 `offset_mismatch` body carries) before trusting it as the new resume
/// point: it must land within `[0, file_size]`. `nullopt` on anything else
/// — a server claiming an offset past the end of the very file it is
/// receiving is a protocol violation, not something to resume from.
[[nodiscard]] inline std::optional<std::int64_t>
reconcile_resume_offset(std::int64_t authoritative_offset, std::int64_t file_size) noexcept {
    if (authoritative_offset < 0 || authoritative_offset > file_size)
        return std::nullopt;
    return authoritative_offset;
}

/// A byte range `[start, end)` this process's running commit-digest hasher
/// has not yet covered but must, before adopting `resynced_offset` as the
/// new resume point.
struct RehashRange {
    std::int64_t start;
    std::int64_t end; ///< exclusive
};

/// The commit digest is built incrementally as bytes are ACKNOWLEDGED, so
/// its coverage (`hashed_to`) normally tracks `offset` exactly. A FORWARD
/// resync breaks that: it means the server accepted a chunk whose success
/// response this process never saw, so `hasher` was never fed that range —
/// the bytes exist on disk and on the server, but not in the digest. This
/// is the fix for the defect where a lost chunk-ack response, followed by a
/// resync, produced a commit hash silently missing the acknowledged bytes
/// (the eventual commit then 422s with `hash_mismatch`, the session is
/// terminal, and the already-redeemed grant has no retry).
///
/// Returns the range to hash before advancing, or `nullopt` when
/// `resynced_offset` does not exceed `hashed_to` — the ordinary case where
/// nothing is missing (a resync that repeats or retreats, or one that
/// exactly matches what has already been hashed). Never returns a range
/// with `start < 0`: `hashed_to` is caller-tracked and only ever advances
/// forward from 0, and `reconcile_resume_offset` has already bounded
/// `resynced_offset` to `[0, file_size]` before this is called.
[[nodiscard]] inline std::optional<RehashRange>
plan_resync_rehash(std::int64_t hashed_to, std::int64_t resynced_offset) noexcept {
    if (resynced_offset <= hashed_to)
        return std::nullopt;
    return RehashRange{hashed_to, resynced_offset};
}

/// Validates a SUCCESSFUL chunk PUT's acknowledged offset. Unlike
/// `offset_mismatch` reconciliation (where the server's number is the only
/// source of truth), a 200 ack is checked against what the agent already
/// knows: the request it just sent covered exactly `[spec.start, spec.end]`,
/// so the only valid acknowledged offset is `spec.end + 1`
/// (`expected_next_offset`). A missing field, a value that disagrees, or one
/// outside `[0, file_size]` is a malformed or inconsistent response — not
/// new state to trust — so the caller must treat it as a failure rather
/// than silently adopting an arbitrary offset.
[[nodiscard]] inline std::optional<std::int64_t>
validate_chunk_ack(std::optional<std::int64_t> acked_offset, std::int64_t expected_next_offset,
                   std::int64_t file_size) noexcept {
    if (!acked_offset || *acked_offset != expected_next_offset || *acked_offset < 0 ||
        *acked_offset > file_size)
        return std::nullopt;
    return *acked_offset;
}

// ── The closed 10-value reason set ──────────────────────────────────────

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

[[nodiscard]] inline std::optional<Reason> parse_reason(std::string_view s) noexcept {
    if (s == "grant_unknown") return Reason::kGrantUnknown;
    if (s == "grant_already_redeemed") return Reason::kGrantAlreadyRedeemed;
    if (s == "expired") return Reason::kExpired;
    if (s == "offset_mismatch") return Reason::kOffsetMismatch;
    if (s == "chunk_too_large") return Reason::kChunkTooLarge;
    if (s == "size_exceeded") return Reason::kSizeExceeded;
    if (s == "hash_mismatch") return Reason::kHashMismatch;
    if (s == "session_unknown") return Reason::kSessionUnknown;
    if (s == "session_terminal") return Reason::kSessionTerminal;
    if (s == "tls_required") return Reason::kTlsRequired;
    return std::nullopt;
}

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

/// What the shell should do next. `kRetry` — same request, no new
/// server-supplied state needed. `kResync` — re-derive local state (the
/// send offset) from the response, then continue immediately. `kAbort` —
/// unrecoverable; the shell surfaces the failure and, if a session is open,
/// sends the cancel (DELETE).
enum class UploadDecision {
    kRetry,
    kResync,
    kAbort,
};

/// Classifies each of the ten frozen reasons. Only one is recoverable
/// in-band:
///   * `offset_mismatch` -> Resync — the response body carries the
///     authoritative offset (`reconcile_resume_offset` above); the agent's
///     local send position was wrong, the server's is truth.
/// Every other reason names a terminal, non-retryable outcome per the
/// frozen protocol text (`expired`/`size_exceeded`/`hash_mismatch` all
/// explicitly terminate the session server-side; `grant_unknown`/
/// `grant_already_redeemed`/`session_unknown`/`session_terminal`/
/// `tls_required` are all "this credential or transport can never succeed",
/// not "try again") -> Abort. `chunk_too_large` is ALSO Abort, not Retry: the
/// agent already learned `chunk_max_bytes` at session-open and every
/// `plan_next_chunk` call honours it deterministically, so this can only
/// legitimately fire from a local planning bug or a cap that changed
/// mid-session — either way a retry resends the IDENTICAL range with the
/// SAME already-known cap and cannot converge on its own (the frozen
/// protocol gives the agent no new cap to reconcile from, unlike
/// `offset_mismatch`'s authoritative offset), so retrying only burns the
/// attempt budget on a structurally guaranteed repeat failure.
[[nodiscard]] inline UploadDecision classify_reason(Reason r) noexcept {
    switch (r) {
    case Reason::kOffsetMismatch:
        return UploadDecision::kResync;
    case Reason::kChunkTooLarge:
    case Reason::kGrantUnknown:
    case Reason::kGrantAlreadyRedeemed:
    case Reason::kExpired:
    case Reason::kSizeExceeded:
    case Reason::kHashMismatch:
    case Reason::kSessionUnknown:
    case Reason::kSessionTerminal:
    case Reason::kTlsRequired:
        return UploadDecision::kAbort;
    }
    return UploadDecision::kAbort; // unreachable — every enumerator handled above
}

// ── Retry/backoff (pure function of status + reason + attempt; no sleep) ──

/// Attempt numbers start at 1. Deliberately small and fixed — this is a
/// per-chunk retry budget, not a long-lived reconnect policy; the caller
/// resets the attempt counter whenever real forward progress is made (a
/// higher offset than previously seen), so a flaky link that eventually
/// makes progress never exhausts this budget, only a genuinely stuck one
/// does.
inline constexpr int kMaxAttempts = 5;

[[nodiscard]] inline bool attempts_exhausted(int attempt) noexcept { return attempt >= kMaxAttempts; }

inline constexpr std::int64_t kBackoffBaseMs = 250;
inline constexpr std::int64_t kBackoffCapMs = 30000;

/// Deterministic exponential backoff, capped. Pure — returns a delay for
/// the CALLER to sleep on; this function never sleeps itself.
[[nodiscard]] inline std::int64_t backoff_delay_ms(int attempt) noexcept {
    if (attempt < 1)
        attempt = 1;
    std::int64_t delay = kBackoffBaseMs;
    for (int i = 1; i < attempt && delay < kBackoffCapMs; ++i)
        delay *= 2;
    return delay < kBackoffCapMs ? delay : kBackoffCapMs;
}

struct RetryDecision {
    UploadDecision action{UploadDecision::kAbort};
    std::int64_t backoff_ms{0}; ///< engaged only when action == kRetry
};

/// Whether a non-2xx response carrying NO recognized `reason` (a generic
/// envelope, or no envelope at all) is the "connection-level or unreasoned
/// server error" case that `decide_next_action` treats as retryable: a 5xx,
/// or `http_status == 0` (the shell's spelling for a connection failure —
/// no response reached it at all). Exposed separately from
/// `decide_next_action` so a caller can also use it OUTSIDE the retry
/// decision itself — e.g. to recognize an outcome-AMBIGUOUS commit failure
/// (a lost response can mean the server already committed) once the retry
/// budget is exhausted and worth resolving with a status check before
/// declaring failure.
[[nodiscard]] inline bool is_transient_no_reason(int http_status,
                                                 std::optional<Reason> reason) noexcept {
    return !reason.has_value() && (http_status == 0 || (http_status >= 500 && http_status < 600));
}

/// The single entry point the shell calls after every non-2xx response
/// (chunk, session-open, or commit). `reason` is the parsed `error.reason`
/// field when the body carried one of the ten frozen strings — `nullopt`
/// for a generic envelope (no `reason` field at all: an operator-route-style
/// 400/503) or a connection-level failure the shell reports as
/// `http_status == 0`.
///
///   * A recognized `reason` always drives the outcome via `classify_reason`
///     above — a `kRetry` result would additionally check the attempt
///     budget, though no reason classifies as Retry today (see
///     `classify_reason`'s doc comment) — this stays defensive against a
///     future reclassification rather than assuming the branch is dead.
///   * No `reason` at all: `is_transient_no_reason` above is the ONLY other
///     retryable case — any other unreasoned status (e.g. a 400 from a
///     locally malformed Content-Range) is a structural bug, not a
///     transient condition, so it aborts.
[[nodiscard]] inline RetryDecision decide_next_action(int http_status, std::optional<Reason> reason,
                                                      int attempt) noexcept {
    if (reason.has_value()) {
        const auto action = classify_reason(*reason);
        if (action != UploadDecision::kRetry)
            return {action, 0};
        if (attempts_exhausted(attempt))
            return {UploadDecision::kAbort, 0};
        return {UploadDecision::kRetry, backoff_delay_ms(attempt)};
    }
    if (!is_transient_no_reason(http_status, reason))
        return {UploadDecision::kAbort, 0};
    if (attempts_exhausted(attempt))
        return {UploadDecision::kAbort, 0};
    return {UploadDecision::kRetry, backoff_delay_ms(attempt)};
}

// ── Minimal compact-JSON field extraction ───────────────────────────────
//
// `content_dist`'s meson.build carries no `nlohmann_dep` (unlike every
// plugin that already uses `<nlohmann/json.hpp>`) and this package's
// `owned_files` does not include that build file — widening it is out of
// scope (see this package's spec boundaries). Every response this header
// parses is a small, FLAT, compact-dumped (`nlohmann::json::dump()`'s
// default: no inserted whitespace) object produced by
// `file_retrieval_routes.cpp` on the other end, so a plain `"key":` token
// scan is sufficient and exact for this closed set of shapes — this is
// intentionally NOT a general JSON parser.
namespace detail {

[[nodiscard]] inline std::optional<std::string> extract_string(std::string_view json,
                                                                std::string_view key) {
    const std::string needle = "\"" + std::string(key) + "\":\"";
    const auto pos = json.find(needle);
    if (pos == std::string_view::npos)
        return std::nullopt;
    std::size_t i = pos + needle.size();
    std::string out;
    while (i < json.size() && json[i] != '"') {
        if (json[i] == '\\' && i + 1 < json.size()) {
            out.push_back(json[i + 1]);
            i += 2;
            continue;
        }
        out.push_back(json[i]);
        ++i;
    }
    if (i >= json.size()) // unterminated string — malformed, refuse to guess
        return std::nullopt;
    return out;
}

[[nodiscard]] inline std::optional<std::int64_t> extract_int(std::string_view json,
                                                              std::string_view key) {
    const std::string needle = "\"" + std::string(key) + "\":";
    const auto pos = json.find(needle);
    if (pos == std::string_view::npos)
        return std::nullopt;
    std::size_t i = pos + needle.size();
    bool neg = false;
    if (i < json.size() && json[i] == '-') {
        neg = true;
        ++i;
    }
    if (i >= json.size() || json[i] < '0' || json[i] > '9')
        return std::nullopt;
    constexpr std::int64_t kMax = std::numeric_limits<std::int64_t>::max();
    std::int64_t v = 0;
    while (i < json.size() && json[i] >= '0' && json[i] <= '9') {
        const int digit = json[i] - '0';
        // Reject BEFORE the multiply/add would overflow — computing past
        // INT64_MAX and only checking afterward is undefined behavior for a
        // signed type, not a value this parser could reliably detect once
        // it has already happened.
        if (v > (kMax - digit) / 10)
            return std::nullopt;
        v = v * 10 + digit;
        ++i;
    }
    return neg ? -v : v;
}

} // namespace detail

// ── Session-open / chunk-ack / commit response parsing ──────────────────

struct SessionOpenResponse {
    std::string upload_id;
    std::string session_secret;
    std::int64_t chunk_max_bytes{0};
    std::int64_t offset{0};
    std::int64_t expires_at{0};
};

/// Parses `{"upload_id","session_secret","chunk_max_bytes","offset","expires_at"}`
/// (session-open success body). `nullopt` on any missing/malformed field, or
/// a structurally impossible value (`chunk_max_bytes <= 0`, `offset != 0`) —
/// never a partially-populated result. `offset` must be EXACTLY 0: this is
/// the fresh-session response, and server/core/src/upload_grant_parsers.hpp's
/// frozen protocol text states a successful session open always returns
/// `offset 0` (never merely non-negative) — the resume-poll case where a
/// non-zero offset is legitimate is `StatusResponse`/`parse_status_response`
/// below, a separate type used at the one distinct call site that polls an
/// already-open session (#3136 review: this parser's own file header claims
/// to implement the frozen text "verbatim", so it must actually reject what
/// that text calls impossible, not merely non-negative).
[[nodiscard]] inline std::optional<SessionOpenResponse>
parse_session_open_response(std::string_view body) {
    auto upload_id = detail::extract_string(body, "upload_id");
    auto secret = detail::extract_string(body, "session_secret");
    auto chunk_max = detail::extract_int(body, "chunk_max_bytes");
    auto offset = detail::extract_int(body, "offset");
    auto expires = detail::extract_int(body, "expires_at");
    if (!upload_id || upload_id->empty() || !secret || secret->empty() || !chunk_max ||
        *chunk_max <= 0 || !offset || *offset != 0 || !expires)
        return std::nullopt;
    return SessionOpenResponse{*upload_id, *secret, *chunk_max, *offset, *expires};
}

/// Parses a successful chunk PUT's `{"offset":<new_offset>}` body.
[[nodiscard]] inline std::optional<std::int64_t> parse_chunk_ack_offset(std::string_view body) {
    return detail::extract_int(body, "offset");
}

struct CommitResponse {
    std::string state;
    std::int64_t actual_size{0};
    std::string sha256;
};

/// Parses `{"state":"committed","actual_size","sha256"}`. `nullopt` unless
/// `state` is EXACTLY `"committed"` — any other value on a 200 would be a
/// server-contract violation this header refuses to paper over.
[[nodiscard]] inline std::optional<CommitResponse> parse_commit_response(std::string_view body) {
    auto state = detail::extract_string(body, "state");
    auto size = detail::extract_int(body, "actual_size");
    auto sha = detail::extract_string(body, "sha256");
    if (!state || *state != "committed" || !size || !sha || sha->empty())
        return std::nullopt;
    return CommitResponse{*state, *size, *sha};
}

/// Whether a parsed commit response's reported size/hash agree with what
/// THIS run actually computed and transmitted. A 200 response naming a
/// different artifact's size or digest is a server-contract violation this
/// header refuses to paper over — same posture as `parse_commit_response`
/// rejecting a non-`"committed"` state.
[[nodiscard]] inline bool commit_matches(const CommitResponse& resp, std::int64_t expected_size,
                                         std::string_view expected_sha256) noexcept {
    return resp.actual_size == expected_size && resp.sha256 == expected_sha256;
}

struct StatusResponse {
    std::string state; ///< "open" | "committed" | "cancelled" | "expired"
    std::int64_t offset{0};
    std::int64_t expires_at{0};
};

/// Parses `{"state","offset","expires_at"}` (the status GET response).
/// Used to resolve an outcome-AMBIGUOUS commit failure: the frozen
/// protocol's status route answers 200 with the CURRENT state even once a
/// session has gone terminal (`file_retrieval_routes.cpp`'s
/// `register_status` handles `kOk` and `kSessionTerminal` identically), so
/// this is the one call that can distinguish "already committed by an
/// earlier attempt whose response was lost" from "genuinely failed or
/// cancelled".
[[nodiscard]] inline std::optional<StatusResponse> parse_status_response(std::string_view body) {
    auto state = detail::extract_string(body, "state");
    auto offset = detail::extract_int(body, "offset");
    auto expires = detail::extract_int(body, "expires_at");
    if (!state || state->empty() || !offset || *offset < 0 || !expires)
        return std::nullopt;
    return StatusResponse{*state, *offset, *expires};
}

struct ErrorInfo {
    std::optional<Reason> reason;       ///< nullopt if absent or not one of the ten
    std::optional<std::int64_t> offset; ///< present only for offset_mismatch
    std::string message;
};

/// Parses the frozen error envelope's `error` object fields. Tolerant by
/// design (never itself an error): an envelope missing `reason`/`offset`
/// simply leaves those fields `nullopt` — the caller (`decide_next_action`)
/// already treats a missing reason as "generic, classify by HTTP status
/// alone".
[[nodiscard]] inline ErrorInfo parse_error_envelope(std::string_view body) {
    ErrorInfo info;
    if (auto r = detail::extract_string(body, "reason"))
        info.reason = parse_reason(*r);
    info.offset = detail::extract_int(body, "offset");
    if (auto m = detail::extract_string(body, "message"))
        info.message = *m;
    return info;
}

} // namespace yuzu::content_dist::upload
