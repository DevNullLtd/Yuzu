#pragma once

/// @file kek_routes.hpp
/// KEK (key-encryption-key) rotation REST surface (#2395): `/api/v1/secrets/kek/*`.
///
/// - `POST /api/v1/secrets/kek/rotate` — `Security:Write`. Mint a new KEK
///   version and re-wrap every registered secret row under it.
/// - `POST /api/v1/secrets/kek/rewrap` — `Security:Write`. Idempotent RESUME
///   of a rotation that advanced the active version but did not finish
///   re-wrapping every row (see `KekOpResult::Failure::HalfCommitted` below).
/// - `GET  /api/v1/secrets/kek/status` — `Security:Read`. Current active
///   version + oldest version still referenced by a live secret row + whether
///   rotation is complete (every row is on the active version).
///
/// NO RETIRE ROUTE — deliberate. `SecretCodec::retire_kek` exists and is
/// tested, but it is NOT exposed here and must not be, and `KekOpResult`
/// carries no `retirable` field advertising which versions could be retired.
///
/// Retiring a KEK deletes key material, and #2525 documents a write race that
/// makes that unsafe: `SecretCodec::encrypt()` snapshots the active version,
/// releases its mutex, and the CALLER persists the blob afterwards — so a
/// retirement can pass its "no rows reference this version" check and delete
/// the key while an in-flight write is still about to commit a blob wrapped
/// under it. That blob is then permanently undecryptable. This happens on a
/// single server; it is not an HA-only hazard, and no lock this module could
/// take would close it, because ordinary secret writers do not participate.
///
/// Advertising a version as retirable while providing no safe way to retire it
/// would be worse than silence. Do not add a retire route, a `retirable` list,
/// or any "safe to delete" hint without closing #2525 first.
///
/// The crypto + Postgres access (`pg::SecretCodec`, `pg::PgPool`) is injected
/// as the `KekOps` seam so this module links neither — it only maps an
/// already-sanitised `KekOpResult` to HTTP. The seam implementation (server.cpp)
/// is responsible for classifying failures into `KekOpResult::Failure`; in
/// particular it MUST NOT let a codec-internal error string (which can carry
/// `PQerrorMessage` text) reach this struct — see rule B below.

#include <yuzu/server/auth.hpp>

#include "http_route_sink.hpp"

#include <httplib.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server {

/// Outcome of one KEK lifecycle operation, ALREADY SANITISED for external
/// consumption. The seam implementation classifies failures; the route only
/// maps them to HTTP. Codec-internal error strings (which carry
/// PQerrorMessage text) MUST NEVER reach this struct — see #2395 rule B.
struct KekOpResult {
    enum class Failure {
        None,
        Unavailable,     ///< codec or pool not available -> 503
        Conflict,        ///< another KEK operation is in flight -> 409
        Cooldown,        ///< too soon after the last rotate attempt -> 429
        // ── #2530 hardening: three new failure classes ─────────────────────
        VersionCeiling,  ///< live KEK versions at the configured maximum -> 409, NO retry_after_ms
        QueryCanceled,   ///< a KEK query was canceled or hit statement_timeout -> 503, NO retry_after_ms
        ClockAnomaly,    ///< newest kek_meta row is future-dated -> 503, NO retry_after_ms
        HalfCommitted,   ///< rotate advanced the version then failed -> 500 + the resume instruction
        Internal,        ///< anything else -> 500, generic message only
    };
    Failure failure{Failure::None};
    std::uint32_t new_version{0};                 ///< rotate
    std::size_t   rows_rewrapped{0};              ///< rewrap only (rotate deliberately never sets this)
    std::uint32_t active_version{0};              ///< status
    std::optional<std::uint32_t> oldest_in_use{}; ///< status; nullopt = no secret rows exist
    bool rotation_complete{false};                ///< status

    /// Only meaningful when `failure == Cooldown`. The honest number of
    /// milliseconds remaining on the DURABLE rate limit
    /// (`--kek-min-rotate-interval`), computed by the seam from
    /// `SecretCodec::rotate_clock()`'s single-statement Postgres timestamps
    /// (#2530 B3/D — "waiting genuinely resolves it" is only true if this
    /// number is accurate). Zero means the seam did not populate it (an older seam,
    /// or a stub in tests); `write_failure` falls back to a conservative
    /// default in that case rather than emitting a false `0`. NEVER set this
    /// for VersionCeiling / QueryCanceled / ClockAnomaly — those three
    /// deliberately carry no retry hint at all (see the D mapping table in
    /// the #2530 contract: waiting does not fix any of them).
    std::uint32_t cooldown_retry_after_ms{0};

    /// #2530 G7-B6: only meaningful when `failure == ClockAnomaly`. How many
    /// seconds the newest `kek_meta.created_at` row is dated INTO THE
    /// FUTURE relative to the database server's own clock — a forward skew
    /// is NOT self-clearing the way a backward skew is (it stays `> now()`
    /// until real time catches up), so this is the one number that lets an
    /// operator tell "a few seconds of NTP jitter" from "this row is dated
    /// next year", which demand completely different responses. Zero means
    /// the seam did not populate it.
    std::uint64_t clock_skew_secs{0};

    // ── #2530 B2: diagnostic snapshots (status only) ───────────────────────
    // The three fields below are read LOCK-FREE, each by its own SELECT, at
    // POSSIBLY DIFFERENT INSTANTS — `live_versions` and `lock_held`/
    // `lock_holder_pid` are not read inside one transaction and are not
    // read under the `secrets_kek_op` advisory lock (GET /status
    // deliberately never takes it, see the status route below). Treat every
    // one of them as a snapshot that can already be stale by the time the
    // caller reads the response body — never poll them in a loop expecting
    // monotonic or atomic behaviour, and never derive a "safe to retire"
    // conclusion from any combination of them. #2525 documents in detail why
    // this module still has no retire route; these three fields are pure
    // observability and add no safety guarantee toward that problem.
    //
    // #2530 T5 — `live_versions` and `lock_held` are `nullopt` when the
    // underlying query FAILED, never a fabricated `0`/`false`. Yuzu's
    // standing rule (already honoured by the 15s metrics sampler in
    // server.cpp) is that a value nobody could determine is ABSENT, never a
    // confident negative. This matters most for `lock_held`: this field
    // exists so an operator can diagnose a backend wedged holding
    // `secrets_kek_op` — the failure mode where every KEK operation 409s
    // forever. During exactly that incident a `false` fabricated from a
    // failed query would tell the operator "there is no wedge", which is
    // the one answer this field must never give when it does not actually
    // know. A `nullopt` `lock_held` MUST NEVER be read as "no lock is
    // held" — it means the lock state is UNKNOWN; corroborate via
    // `pg_stat_activity` before concluding anything.
    std::optional<std::uint32_t> live_versions{}; ///< status; live (non-retired) KEK version count; nullopt = could not be determined
    std::optional<bool> lock_held{};      ///< status; true iff `secrets_kek_op` has a granted holder IN THIS DATABASE; nullopt = could not be determined (NEVER read as "not held")
    // #2530 G8-F3: THREE states, not two — `nullopt` alone is ambiguous
    // between "unheld" and "undetermined", and even a non-null `lock_held`
    // does not imply a pid: (1) lock_held=false -> pid is always nullopt
    // (nothing to report); (2) lock_held=true with pid SET -> a normal held
    // lock, corroborate via `pg_stat_activity WHERE pid = <lock_holder_pid>`;
    // (3) lock_held=true with pid nullopt -> HELD but the holder's backend
    // pid could not be read from `pg_locks` (#2530 G7-S1) — there is no pid
    // to corroborate with; fall back to inspecting `pg_locks`/
    // `pg_stat_activity` for ANY backend holding classid 2037545589 in this
    // database, since no single pid identifies it. Always check `lock_held`
    // first to disambiguate which of the three states a null `pid` means.
    std::optional<int> lock_holder_pid{};

    /// #2530 H1 (Hermes round 2) — wall-clock instant the `lock_held`/
    /// `lock_holder_pid` snapshot above was TAKEN (`KekOpLockHolder::captured_at`,
    /// kek_op_lock.hpp), so a caller can see how stale the pid it is
    /// looking at already is instead of implicitly trusting it as current.
    /// `nullopt` in lockstep with `lock_held`/`lock_holder_pid` being
    /// undetermined (the holder query itself failed) — never fabricated.
    /// This does NOT make the snapshot any less stale by the time a caller
    /// (or a DBA acting on it) reads it; it just makes the staleness
    /// visible. See the runbook's termination step
    /// (docs/user-manual/server-admin.md) for why a pid must still be
    /// RE-CONFIRMED in `pg_locks` at the moment of any consequential action
    /// — pids are reused.
    std::optional<std::chrono::system_clock::time_point> lock_holder_captured_at{};
};

/// The three operations. Any may be empty (unset) -> route answers 503.
struct KekOps {
    std::function<KekOpResult()> rotate;
    std::function<KekOpResult()> rewrap;
    std::function<KekOpResult()> status;
};

namespace detail {
/// #2530 G8-F2 — test-only, externally-linked twin of this file's file-local
/// audit-detail switch (kek_routes.cpp's `failure_tag()`). Exposed purely so
/// a table-driven test can assert the REST, MCP (`mcp_server.cpp`'s
/// `kek_failure_tag()`), and metrics (`kek_rotate_control.hpp`'s
/// `kek_op_outcome_label()`) failure vocabularies agree for all nine
/// `Failure` values — the mapping-lock #2284 says must exist. The three
/// switches stay independent by design (see the #2530 hardening contract's
/// "do not collapse into one shared table" scope note); this function only
/// forwards to the existing production one so it is callable from a test
/// binary that does not link kek_routes.cpp's whole route-registration path.
[[nodiscard]] std::string_view kek_route_failure_tag(KekOpResult::Failure failure);
} // namespace detail

class KekRoutes {
public:
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type, const std::string& operation)>;
    // Returns false if the audit row could not be persisted (caller surfaces the
    // evidence-chain gap via `Sec-Audit-Failed`). Matches the canonical
    // bool-returning audit contract used across the other route modules
    // (ca_routes.hpp) so a privileged KEK rotate/rewrap can observe an
    // audit-persistence failure (#1240).
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    /// Production overload — wraps `svr` in an HttplibRouteSink and delegates.
    void register_routes(httplib::Server& svr, PermFn perm_fn, AuditFn audit_fn, KekOps ops);

    /// Testable overload — register against an in-process sink (no socket).
    void register_routes(HttpRouteSink& sink, PermFn perm_fn, AuditFn audit_fn, KekOps ops);
};

} // namespace yuzu::server
