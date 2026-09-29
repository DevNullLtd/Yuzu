#include "api_token_store.hpp"
#include "engine_principal_store.hpp"
#include "mcp_policy.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/pg_session_advisory_lock.hpp"
#include "rotation_confirm_state.hpp"
#include "secure_random.hpp"

#include <yuzu/secure_zero.hpp>

#include <libpq-fe.h>
#include <openssl/crypto.h> // CRYPTO_memcmp — constant-time PoP secret compare (#3015)
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <mutex>
#include <optional>
#include <span>
#include <string_view>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// clang-format off
#include <windows.h>  // must precede bcrypt.h (defines NTSTATUS)
// clang-format on
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <openssl/sha.h>
#endif

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "api_token_store";

// Bounded acquires (ADR-0012 §2). Token validation sits on the request hot
// path (every Bearer-authed call falls through here on a cache miss) so it
// gets the shorter budget; mutations (create/revoke/delete) are user-facing
// but rarer, so they get a little more room. Neither is unbounded.
constexpr std::chrono::milliseconds kReadTimeout{1500};
constexpr std::chrono::milliseconds kWriteTimeout{2000};

// Raw token layout: "yuzu_" prefix + 32 random chars = 37 bytes total
// (generate_raw_token below). The move-based secret-scrub discipline
// elsewhere in this file (rotate_token's `scrub_secrets` ScopeExit, and
// every other `std::move`-then-secure_zero site on a raw token) depends on
// every generated token staying above libstdc++'s small-string-optimisation
// threshold (15 bytes), libc++'s (22), and MSVC's (15) — a std::string at or
// below its stdlib's threshold is stored INLINE in the string object itself,
// so moving it copies the bytes rather than stealing a heap pointer, and the
// plaintext is left sitting in the (still non-empty, inline-storage) moved-
// from object — which `secure_zero`, called on THAT object afterward, never
// reaches because the caller already treats the moved-from string as empty/
// irrelevant. Below is a static, compile-time pin of that dependency: shrink
// the token layout and this fails loudly instead of quietly reopening the
// residual-plaintext gap.
constexpr std::size_t kRawTokenPrefixLen = 5;  // "yuzu_"
constexpr std::size_t kRawTokenRandomLen = 32;
constexpr std::size_t kRawTokenTotalLen = kRawTokenPrefixLen + kRawTokenRandomLen;
static_assert(kRawTokenTotalLen > 22,
             "raw API token length must stay above every stdlib's SSO threshold "
             "(libstdc++ 15 / libc++ 22 / MSVC 15) - the move-based secret scrub "
             "in this file silently stops zeroing residual plaintext otherwise");

// UP-6 (clock-guarded-retention routed concern, part 5: "cap every accepted
// pass UNCONDITIONALLY - the cap is the half that always applies, the
// detectors are best-effort"). `sweep_expired_rotations` is a bulk
// wall-clock mutation (`overlap_expires_at <=` PostgreSQL's own clock).
// Since #2964 it carries the FULL seven-part clock-guarded-retention shape
// (persisted anchor, sanitised reading, fact-set dedup anomaly detection —
// see the function's own doc comment) — this cap remains unchanged and
// still applies UNCONDITIONALLY regardless of what the detectors above it
// decide: even an accepted, undeclined pass never processes more than this
// many predecessors in one tick. Without it, a single forward NTP step that
// slips past every detector still cuts over every in-flight rotation
// fleet-wide in one 60s tick. This number is a defensible choice for THIS
// sweep, not copied from another store's constant (the routed concern is
// explicit those are substrate-tuned): the sweep runs every 60s and does one
// advisory-locked write transaction PER predecessor, so at this cap a
// worst-case tick still drains in well under a second, and 200/tick still
// clears 12,000/hour of legitimate churn — rotations are individual
// admin/self-service actions, not a bulk workload, so that headroom is
// generous. A clock jump degrades to a several-tick drain (visible via the
// cap-hit log line + counter below) rather than a single fleet-wide event.
constexpr std::size_t kMaxAutoRevokesPerTick = 200;

// Shared implausible-reading UPPER bound for both the caller's clock and
// PostgreSQL's own, checked before either reading is trusted for anything —
// mirrors `audit_store.cpp`'s `kMaxPlausibleNow` in shape (same bound, same
// role as the routed clock-guarded-retention concern's part-1 "excluding
// rows stamped implausibly far ahead" probe applied to the reading itself
// rather than a row), though this file has no `now + window + slack`
// overflow-prone add for it to protect the way `audit_store.cpp`'s does
// today — `moved_at_least` (`audit_retention_rules.hpp`) is overflow-free by
// construction for every representable pair. UPPER bound only — a deeply
// negative reading is the legitimate dead-CMOS case this guard exists for.
//
// Parenthesised `(std::numeric_limits<std::int64_t>::max)()`: this TU
// includes <windows.h> DIRECTLY (above, under `#ifdef _WIN32`) with
// WIN32_LEAN_AND_MEAN but no NOMINMAX — bcrypt.h is the REASON that include
// is here (it requires NTSTATUS from windows.h to already be defined), not
// the vehicle that pulls windows.h in transitively. Either way, the
// unparenthesised bare `max()` call is swallowed by <windows.h>'s
// function-like `max(a,b)` macro — a
// 2-argument macro invoked with 1 argument is a preprocessor arity error on
// MSVC, not a silent misparse. The extra parens around the callee suppress
// macro expansion (the preprocessor only expands `max` when immediately
// followed by `(`, and `(std::numeric_limits<std::int64_t>::max)` is not).
// `kMaxAutoRevokesPerTick + 1`'s own `(std::min)` call downstream in this
// file uses the identical idiom, with the identical justification, already.
constexpr std::int64_t kMaxPlausibleNow = (std::numeric_limits<std::int64_t>::max)() / 4;

// Strict integer parse for a durable meta-table TEXT value — mirrors
// `audit_store.cpp`'s `parse_meta_i64` (not shared across TUs: each
// clock-guarded store's meta read is a few lines around one call site, and
// duplicating this one is cheaper than a new shared-utility header for a
// three-line function). No trailing junk, no partial parse — a hand-edited
// or corrupted row is `prev_unusable`, never silently truncated to
// whatever prefix happens to parse.
[[nodiscard]] std::optional<std::int64_t> parse_meta_i64(const std::string& val) {
    errno = 0;
    char* end = nullptr;
    const long long v = std::strtoll(val.c_str(), &end, 10);
    if (val.empty() || errno != 0 || end == val.c_str() || *end != '\0')
        return std::nullopt;
    return static_cast<std::int64_t>(v);
}

// Serialize the rotation sweep's five guard facts to a stable string — the
// durable dedup key, comparing the whole FACT SET rather than the
// classified enum (routed concern part 4: a `Wipe` arriving underneath an
// already-reported `BadState` classifies as `BadState` both times and would
// be invisible to an enum comparison). Mirrors `audit_store.cpp`'s
// `serialize_facts` byte-for-byte in shape; not shared, since each
// clock-guarded store owns its own meta table and there is no third
// consumer yet to justify extracting one.
std::string serialize_rotation_facts(const audit_retention::Facts& f) {
    return std::string(f.has_expired ? "e" : "-") + (f.would_wipe ? "w" : "-") +
           (f.big_step ? "s" : "-") + (f.prev_unusable ? "u" : "-") + (f.no_anchor ? "b" : "-");
}

// The rotation-sweep clock guard's ELIGIBILITY predicate. This store's own
// application of routed-concern part 1's "probe by OUTCOME (would this
// expire EVERY datable row?)" — the ELIGIBLE set below is what "datable row"
// means for THIS store, not a routed-concern quotation itself. ONE
// definition, shared by the probe query AND the real candidate SELECT
// inside the same classification transaction,
// so the two can never drift apart the way a hand-copied WHERE clause
// would (the exact risk `kAuditRetentionProbeSql`'s own comment in
// `audit_store.hpp` calls out for its sibling). Column-qualification-free
// (no table alias) so it composes into either query unchanged; both
// queries run it against the SAME (sole) table.
//
//   * `revoked = FALSE AND overlap_expires_at > 0 AND supersedes_token_id
//     = ''` — a predecessor row (a successor always carries a non-empty
//     `supersedes_token_id`), not yet revoked, actually in an overlap pair.
//   * `EXISTS (... s.revoked = FALSE ...)` — the successor to cut over to
//     is still LIVE. If it was manually revoked/deleted, this predecessor
//     is now the ONLY credential for THIS ROTATION GROUP; auto-revoking it
//     would leave zero usable credentials for the group (not necessarily
//     zero for the principal as a whole, who may hold other unrelated
//     active tokens).
//   * `s.last_used_at <> 0` (UP-5) — that live successor must have been
//     PRESENTED at least once. A successor that has NEVER been used is the
//     "dropped/lost secret" case (the operator's own copy may not exist);
//     revoking the predecessor would reach the same zero-usable-credential
//     outcome as the EXISTS clause above already guards against, just by a
//     different route. This makes such a pair PERMANENTLY ineligible until
//     an operator resolves it — never merely "not yet due" — which is
//     exactly why the probes above must use this same predicate rather
//     than a bare `overlap_expires_at <= now`.
constexpr std::string_view kRotationEligiblePredicate =
    "revoked = FALSE AND overlap_expires_at > 0 AND supersedes_token_id = '' "
    "AND EXISTS (SELECT 1 FROM api_token_store.api_tokens s "
    "WHERE s.rotation_group = api_token_store.api_tokens.rotation_group "
    "AND s.supersedes_token_id = api_token_store.api_tokens.token_id "
    "AND s.revoked = FALSE AND s.last_used_at <> 0)";

// DELIBERATE NON-ADOPTION of the clock-guarded-retention routed concern's
// part 1 ("probe by OUTCOME — would this pass expire EVERY datable row?")
// for THIS store — recorded here per that same routed concern's part 6
// ("what makes any of these correct is the RECORDED reasoning, not the
// answer") and `ResultSetStore::gc_sweep`'s precedent for declining to adopt
// a part outright rather than re-tuning it.
//
// A first attempt (#2964 fix round, finding 3) tried gating the would-wipe
// verdict on a minimum eligible population (`kMinWipeProbePopulation`, since
// removed) — measured (#2964 round 3 review) to move the swallow ABOVE the
// population floor rather than close it: at population 6, a routine batch
// expiry declines and plants fact set `ew---`; the next tick's genuine 12h
// forward clock step produces the byte-identical fact set, is suppressed as
// a repeat (part 4), and revokes predecessors whose windows had NOT elapsed
// before the step — with `outcome=Ok`, no decline, no counter, no log. The
// population gate cannot close this: the defect is that a ROUTINE verdict
// spends the single un-namespaced dedup slot, and every population this
// store can have reaches an all-expired terminal state as a matter of
// course — a drain queue is SUPPOSED to reach 100% expiry, repeatedly, by
// design, unlike `audit_store`'s long-lived time series where 100% expiry
// can only mean the retention cutoff moved. A would-wipe predicate whose
// true positive (a genuine clock jump) and its single most common false
// positive (an ordinary drain tick) are the SAME observable outcome is
// mis-fitted to this store at the type level, not the size level — no
// population threshold fixes a predicate that cannot distinguish its own
// true and false positives.
//
// The harm from accepting that mis-fit is also bounded, unlike
// `audit_store`'s: the per-pair revoke UPDATE re-asserts
// `s.last_used_at <> 0` under the row lock (UP-5) before touching anything,
// so every predecessor this sweep can ever revoke has a successor PROVEN in
// use — never non-regenerable evidence, which is what `audit_store`'s
// would-wipe half exists to protect.
//
// So: `would_wipe` is hardcoded `false` below and the probe that used to
// compute it (the survivor-existence + population-count sub-queries) is
// removed outright — a disarmed detector that still runs the query is a
// second thing to keep in sync with a decision that no longer uses its
// output. `kRotationSweepBigStepSecs` (tuned to this store's 60s re-anchor
// cadence — see that constant's own doc comment) is this store's actual
// clock-jump detector; nothing else in the fact set is weakened by this
// non-adoption.

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE api_tokens ("
         "  token_id      TEXT PRIMARY KEY,"
         "  token_hash    TEXT NOT NULL UNIQUE,"
         "  name          TEXT NOT NULL,"
         "  principal_id  TEXT NOT NULL DEFAULT '',"
         "  scope_service TEXT NOT NULL DEFAULT '',"
         "  mcp_tier      TEXT NOT NULL DEFAULT '',"
         "  principal_kind TEXT NOT NULL DEFAULT 'human' "
         "    CHECK (principal_kind IN ('human','engine')),"
         "  created_at    BIGINT NOT NULL DEFAULT 0,"
         "  expires_at    BIGINT NOT NULL DEFAULT 0,"
         "  last_used_at  BIGINT NOT NULL DEFAULT 0,"
         "  revoked       BOOLEAN NOT NULL DEFAULT FALSE);"
         "CREATE INDEX api_tokens_principal_idx ON api_tokens (principal_id);"},
        // v2 (design doc §7, plan PR 4.3): overlap-pair credential rotation.
        // Additive only — every existing row defaults cleanly to "not
        // rotating" (empty group/predecessor, 0 overlap/confirm instants).
        {2,
         "ALTER TABLE api_tokens ADD COLUMN rotation_group TEXT NOT NULL DEFAULT '';"
         "ALTER TABLE api_tokens ADD COLUMN supersedes_token_id TEXT NOT NULL DEFAULT '';"
         "ALTER TABLE api_tokens ADD COLUMN overlap_expires_at BIGINT NOT NULL DEFAULT 0;"
         "ALTER TABLE api_tokens ADD COLUMN confirmed_at BIGINT NOT NULL DEFAULT 0;"},
        // v3 (#2961): durable twin of the RAM-only grace cache's
        // `requesting_user`, so the confirm-identity binding (Hermes F5)
        // survives a server restart mid-rotation. Additive only — every
        // existing row (including an in-flight v2 pair) defaults to '',
        // which the confirm-identity resolver treats as "not stamped", NEVER
        // as a wildcard. Stamped ONLY on a fresh successor's own INSERT
        // (`rotate_engine_credential`/`rotate_token`'s mint arms) — never
        // backfilled onto a predecessor or onto a pre-existing pair.
        //
        // NUMBERING NOTE (reconciled with the sibling PR on
        // feat/auth-rotation-clock-guard, `rotation_retention_meta` — a new
        // TABLE, unrelated to this ALTER): that sibling ALSO allocates v3,
        // on architect direction — neither PR pre-allocates ahead of the
        // other. `PgMigrationRunner::run` skips any migration whose id is
        // `<= current` against a SCALAR high-water mark
        // (`public.schema_meta`), with no applied-SET table behind it (fixed
        // to fail closed on a duplicate/non-monotonic vector, #3013 — but
        // that only catches the collision, it doesn't resolve it). Landing a
        // HIGHER-numbered migration first would silently and permanently
        // skip a LOWER-numbered one on any database that migrated through
        // the higher version first. Whichever of this migration and the
        // sibling's lands on `dev` SECOND must renumber to the next free id
        // at that point, never by pre-allocation ahead of time.
        // SETTLED: this migration landed first and keeps v3; the sibling
        // (`rotation_retention_meta`, #2964) renumbered to v4 below.
        {3,
         "ALTER TABLE api_tokens ADD COLUMN rotation_initiator TEXT NOT NULL DEFAULT '';"},
        // v4: durable state for the T12 rotation sweep's clock guard (#2964,
        // clock-guarded-retention routed concern) — mirrors `audit_store`'s
        // `audit_retention_meta` (`audit_store.cpp`): one SHARED k/v table,
        // not process-local, because N server replicas each attempt the
        // sweep and the persisted reading + anomaly-dedup fact set must be
        // one shared truth under the sweep's own store-wide session
        // advisory lock.
        //
        // NUMBERING NOTE — RECONCILED, no longer pending. #2961's
        // `rotation_initiator` ALTER landed on `dev` FIRST and holds v3
        // (immediately above); this migration was renumbered 3 -> 4 at that
        // merge, which is the rule both PRs committed to: whichever lands
        // SECOND renumbers, never by pre-allocation ahead of time.
        //
        // Why pre-allocation was refused, recorded because the reasoning is
        // what makes the rule correct rather than arbitrary:
        // `PgMigrationRunner::run` skips any migration whose id is
        // `<= current` against a SCALAR high-water mark
        // (`public.schema_meta`), with no applied-SET table behind it. Had
        // this migration pre-taken v4 and landed first, any database
        // migrating through v4 would then skip #2961's v3 SILENTLY and
        // permanently — strictly worse than a collision, which at least
        // fails loudly. #2961 additionally shipped a duplicate/
        // non-monotonic guard in the runner (#3013), so a future collision
        // now refuses the boot rather than skipping; that guard catches a
        // collision inside one binary's own vector, it does not resolve
        // one, and it cannot see a version another binary already recorded.
        //
        // FAIL-CLOSED SCOPE (governance chaos-injection finding, #2964 fix
        // round): if the #3013 reconciliation above is ever botched — this
        // migration's id collides with an unrelated one that already
        // claimed it — `rotation_retention_meta` never gets created, yet
        // `PgMigrationRunner::run` reports overall success (a scalar
        // high-water mark has no way to know "id 3 applied" doesn't mean
        // "THIS store's migration 3 applied").
        //
        // #2964 round 3 review (finding 4): an EARLIER version of this
        // comment claimed whole-store fail-closed construction on that
        // table's absence was "considered and rejected" as a categorically
        // worse outage than the scoped alternative. That claim is FALSE
        // against this file's own code and always was, in the same commit
        // that added it: the constructor's post-migration smoke-read (see
        // `ApiTokenStore::ApiTokenStore` — `SELECT 1 FROM
        // api_token_store.rotation_retention_meta LIMIT 0`) leaves `open_`
        // false when that table is missing, `is_open()` then returns false,
        // and `server.cpp` treats that identically to every other
        // born-on-PG store's migration/open failure: `startup_failed_ =
        // true`, and the WHOLE SERVER refuses to boot (ADR-0012 §1) — never
        // "the auth hot path keeps serving while only the rotation subsystem
        // degrades", the outcome the rejected paragraph described choosing
        // instead. Retracted rather than reverted: #3013 is two migrations
        // inside THIS store's own `kMigrations` list both claiming the same
        // id — a genuinely WRONG schema, not a merely-missing optional
        // table — and `server.cpp` (around its `ApiTokenStore` construction
        // block) already treats a reachable-but-wrong schema as a deploy
        // error for all of this store's 18 sibling born-on-PG stores. Failing
        // the deploy loudly beats a subsystem silently dead forever, so the
        // CODE here (the smoke-read, and the whole-store fail-closed
        // construction it drives) is correct and stays; only the comment
        // claiming the opposite choice was made is wrong and is retracted.
        // `sweep_expired_rotations`'s own `fail()` helper still matters —
        // it is what surfaces the EXACT libpq error for a table that goes
        // missing AFTER a successful boot (e.g. an out-of-band `DROP TABLE`),
        // a RUNTIME case this construction-time smoke-read cannot see —
        // but it is no longer this store's ONLY fail-closed posture for a
        // missing `rotation_retention_meta`, only its posture for losing the
        // table after the server already started serving.
        {4,
         "CREATE TABLE rotation_retention_meta ("
         "  key   TEXT PRIMARY KEY,"
         "  value TEXT NOT NULL);"},
    };
    return kMigrations;
}

// Epoch SECONDS (unchanged from the SQLite store — do not drift to ms).
int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<int64_t>(std::strtoll(s, nullptr, 10));
}

bool to_bool(const char* s) {
    return s != nullptr && (s[0] == 't' || s[0] == 'T' || s[0] == '1');
}

// Null-safe column read: every column in the v1 projection is NOT NULL, so
// PQgetvalue never returns a NULL cell today. This gate keeps read_token
// robust if a future migration relaxes a NOT NULL constraint or the
// projection drifts from kTokenColsTail — a NULL cell degrades to "" rather
// than dereferencing a nullptr into std::string.
const char* col(PGresult* res, int row, int c) {
    return PQgetisnull(res, row, c) ? "" : PQgetvalue(res, row, c);
}

// `token_hash` (column 1) is always present in the projection — either the
// real hash (validate_token) or a literal '' mask (list_tokens/get_token,
// which never expose the hash — see kTokenColsTail's callers).
ApiToken read_token(PGresult* res, int row) {
    ApiToken t;
    int c = 0;
    t.token_id = col(res, row, c++);
    t.token_hash = col(res, row, c++);
    t.name = col(res, row, c++);
    t.principal_id = col(res, row, c++);
    t.scope_service = col(res, row, c++);
    t.created_at = to_i64(col(res, row, c++));
    t.expires_at = to_i64(col(res, row, c++));
    t.last_used_at = to_i64(col(res, row, c++));
    t.revoked = to_bool(col(res, row, c++));
    t.mcp_tier = col(res, row, c++);
    t.principal_kind = col(res, row, c++);
    t.rotation_group = col(res, row, c++);
    t.supersedes_token_id = col(res, row, c++);
    t.overlap_expires_at = to_i64(col(res, row, c++));
    t.confirmed_at = to_i64(col(res, row, c++));
    t.rotation_initiator = col(res, row, c++);
    return t;
}

// Column order shared by validate_token / get_token / list_tokens /
// list_active_for_principal; the token_hash slot is either the real column
// (validate_token) or a literal '' (the others mask it — never expose the
// hash outside a validate).
constexpr const char* kTokenColsTail =
    "name, principal_id, scope_service, created_at, expires_at, last_used_at, revoked, "
    "mcp_tier, principal_kind, rotation_group, supersedes_token_id, overlap_expires_at, "
    "confirmed_at, rotation_initiator";

// Same query `list_active_for_principal` runs, but against a caller-supplied
// `conn` (no lease acquisition) and a caller-supplied `now` — used by
// `rotate_engine_credential`/`confirm_rotation` to re-read the active set
// INSIDE their advisory-locked transaction (Hermes F1/F5): the count/rows
// this returns are what the ≤2-active branch decision and the pairing
// checks are based on, never a pre-lock snapshot.
std::vector<ApiToken> read_active_for_principal_on_conn(PGconn* conn, const std::string& principal_id,
                                                         int64_t now) {
    std::vector<ApiToken> result;
    const std::string sql = std::string("SELECT token_id, '' AS token_hash, ") + kTokenColsTail +
                            " FROM api_token_store.api_tokens "
                            "WHERE principal_id = $1 AND revoked = FALSE "
                            "AND (expires_at = 0 OR expires_at > $2::bigint) "
                            "ORDER BY created_at ASC";
    pg::PgResult res = pg::exec_params(
        conn, sql.c_str(), std::vector<std::string>{principal_id, std::to_string(now)});
    if (res.status() != PGRES_TUPLES_OK)
        return result;
    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        result.push_back(read_token(res.get(), i));
    return result;
}

// Fresh single-row lookup by token_id, on any caller-supplied PGconn* — a
// pool lease outside a transaction, or the connection inside one. Shared by
// rotate_token/confirm_token_rotation's pre-txn principal_id resolution and
// their in-txn fresh re-read (invariant: state re-derived under the advisory
// lock, never the pre-lock snapshot). `ok` distinguishes a genuine zero-row
// match (positive: this token_id definitively does not exist) from a query
// failure (retryable) — unlike read_active_for_principal_on_conn's
// empty-vector contract, a single WHERE token_id=$1 lookup can tell the two
// apart cheaply, so callers here get MORE precision than the count-based
// principal-wide read the engine arm relies on.
struct TokenLookup {
    bool ok = false;                 // the SELECT itself succeeded
    std::optional<ApiToken> token;   // engaged iff ok && a row matched
};
TokenLookup read_token_by_id_on_conn(PGconn* conn, const std::string& token_id) {
    TokenLookup result;
    const std::string sql = std::string("SELECT token_id, '' AS token_hash, ") + kTokenColsTail +
                            " FROM api_token_store.api_tokens WHERE token_id = $1";
    pg::PgResult res = pg::exec_params(conn, sql.c_str(), std::vector<std::string>{token_id});
    result.ok = (res.status() == PGRES_TUPLES_OK);
    if (result.ok && PQntuples(res.get()) > 0)
        result.token = read_token(res.get(), 0);
    return result;
}

// #3015 proof-of-possession: fresh single-column read of the REAL
// `token_hash` for one token_id, on the caller-supplied `conn` — inside the
// confirm functions' own already-advisory-locked transaction, never a
// pre-lock snapshot. Every OTHER reader in this file (including
// `read_token_by_id_on_conn`/`read_active_for_principal_on_conn` above) masks
// `token_hash` behind a literal `''` — see `kTokenColsTail`'s own comment —
// so PoP verification needs this dedicated authoritative read rather than
// reusing either list projection. `nullopt` on a query failure or a
// zero-row match (the row vanished — should not happen under the lock the
// callers already hold, but fails closed rather than assuming a match).
std::optional<std::string> read_token_hash_by_id_on_conn(PGconn* conn, const std::string& token_id) {
    pg::PgResult res = pg::exec_params(
        conn, "SELECT token_hash FROM api_token_store.api_tokens WHERE token_id = $1",
        std::vector<std::string>{token_id});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;
    return std::string(PQgetvalue(res.get(), 0, 0));
}

// #3015 proof-of-possession: constant-time comparison of two SHA-256 hex
// digests. Mirrors `saml_provider.cpp`'s own `constant_time_hex_equal` —
// duplicated (same rationale `upload_grant_parsers.hpp::constant_time_equals`
// records for its own duplicate of `AuthManager::constant_time_compare`)
// rather than exporting a symbol from an unrelated auth surface, and the
// `<openssl/crypto.h>` include here is unconditional (mirrors
// `scim_store.cpp`'s own cross-platform CRYPTO_memcmp use, NOT
// saml_provider.cpp's Windows-stubbed one) since OpenSSL is a hard
// dependency on every platform including Windows regardless of this file's
// own Windows-vs-OpenSSL branch in `sha256_hex` above. Length is compared
// first (not secret — both operands are always fixed-length 64-char hex
// digests here), then CRYPTO_memcmp compares the equal-length byte ranges
// without early-exit-on-mismatch, so branch timing does not leak how many
// leading bytes matched.
bool constant_time_hex_equal(const std::string& a, const std::string& b) {
    if (a.size() != b.size())
        return false;
    if (a.empty())
        return true; // both empty. Unreachable here (operands are always fixed
                     // 64-char SHA-256 hex); do NOT reuse this helper with
                     // attacker-controllable empty operands without revisiting
                     // this shortcut (#3015 UP-8).
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

// Runs `fn` unconditionally in its destructor — covers EVERY exit from the
// enclosing scope, including a thrown exception, which a manual
// call-before-every-`return` pair cannot (a prior round of this file's own
// diff used exactly that shape and missed the throw path). Local to this
// file: every use here guards `yuzu::secure_zero` calls, which are noexcept,
// so — unlike agents/core's `GuardianRollback` — no swallow-on-throwing-
// cleanup complexity is needed.
//
// TEMPLATE, not `std::function`-erased (round 6 review): the closures this
// guards capture 3+ references, which exceeds libstdc++'s small-object
// buffer, so a `std::function`-typed member would make CONSTRUCTING the
// guard itself capable of allocating — a `bad_alloc` there would skip past
// the guard's own construction and leave `candidate_raw` (already generated
// moments earlier) unscrubbed, the one exit path a heap-allocating guard
// cannot cover. This template shape is allocation-free (the closure is
// stored by value, inline, no type erasure) — mirrors
// `agents/core/src/agent.cpp`'s own `ScopeExit`.
// COPY/MOVE (governance Gate 8, considered and left alone): this is an
// AGGREGATE, so it has the implicit copy/move constructors, and a copy
// would run `fn()` TWICE. Deliberately NOT `= delete`d. A reviewer verified
// that deleting copy/move would NOT in fact break the existing call sites —
// an explicit converting constructor (`explicit ScopeExit(F f) :
// fn(std::move(f)) {}`) compiles fine alongside deleted copy/move against
// every `ScopeExit scrub_secrets{lambda}` construction here, so "no
// converting constructor could take its place" is not the reason to leave
// this aggregate and copyable. The actual reason: every use in this file is
// a single local RAII variable, never copied or moved out of its declaring
// scope, and a double-fire here is idempotent (`yuzu::secure_zero` on an
// already-scrubbed/empty string is a no-op) — so the theoretical
// double-fire hazard has no live path, and there is no defect this
// guard needs deleted copy/move to close. Same reasoning applies to the
// byte-identical siblings in `agents/core/src/agent.cpp` and
// `agents/core/src/spark_engine.cpp` (#2050) — keep all three
// aggregate, not just this one.
template <typename F> struct ScopeExit {
    F fn;
    ~ScopeExit() { fn(); }
};
template <typename F> ScopeExit(F) -> ScopeExit<F>;

// #2963: the authority-inheritance guard used by rotate_token/
// confirm_token_rotation (three call sites — the pre-txn mirror and the
// authoritative check in rotate_token, plus confirm_token_rotation's own
// defense-in-depth copy) originally required caller_mcp_tier/
// caller_scope_service to match the token's OWN tier/scope exactly, which
// makes a full-authority interactive session (a plain cookie session,
// tier="" scope="") structurally unable to rotate/confirm its OWN
// MCP-tiered or service-scoped token — backwards precisely when the
// reason to rotate is that the secret may be compromised.
//
// The fix is a SINGLE special case, not a tier lattice: a caller holding
// NO standing tier/scope authority at all already holds a strict superset
// of what ANY tiered/scoped token can do, so admitting it here grants
// nothing new — the successor still inherits the TOKEN's own (narrower)
// tier/scope verbatim, copied from the predecessor, never from the
// caller. A caller that itself holds SOME non-empty tier/scope must still
// match the token's exactly (no ordering/"no-broader-than" comparison —
// that requires a lattice assumption this guard deliberately does not
// make, per its original design).
[[nodiscard]] bool caller_may_act_on_tiered_token(std::string_view token_mcp_tier,
                                                   std::string_view token_scope_service,
                                                   std::string_view caller_mcp_tier,
                                                   std::string_view caller_scope_service) {
    if (caller_mcp_tier.empty() && caller_scope_service.empty())
        return true; // full-authority caller — the #2963 exception
    return token_mcp_tier == caller_mcp_tier && token_scope_service == caller_scope_service;
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

ApiTokenStore::ApiTokenStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("ApiTokenStore: no database connection at construction ({}) — API token "
                      "store disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("ApiTokenStore: schema migration failed — API token store disabled");
        return;
    }
    // #3013/#2964 fix-round: a SECOND, independent line of defence behind
    // the migration runner's own duplicate/non-monotonic-version guard
    // above. That guard catches a collision baked into THIS binary's own
    // `migrations()` vector; it cannot see a version already recorded in
    // `public.schema_meta` by a DIFFERENT binary that shipped before the
    // guard existed, or any other way this store's schema could have ended
    // up short a column `run()` itself believes it already applied. A
    // `LIMIT 0` projection read against every column this store's own
    // runtime queries actually select — including `token_hash`, which
    // `kTokenColsTail` deliberately omits (validate_token selects it as a
    // real column; every other reader masks it behind a literal `''`) —
    // touches zero rows (cheap even on a large table) and fails the exact
    // same way a live `validate_token`/`list_tokens` call would on an
    // `undefined column` — except here, at construction, fail-CLOSED
    // (ADR-0012 §1) rather than in production traffic on whichever request
    // happens to run first.
    {
        const std::string smoke_sql =
            std::string("SELECT token_id, token_hash, ") + kTokenColsTail +
            " FROM api_token_store.api_tokens LIMIT 0";
        pg::PgResult smoke = pg::exec_params(lease.get(), smoke_sql.c_str(), std::vector<std::string>{});
        if (smoke.status() != PGRES_TUPLES_OK) {
            spdlog::error("ApiTokenStore: post-migration schema projection check failed — "
                          "api_tokens is missing an expected column (hypothesis: a skipped or "
                          "partial migration; could also be a dropped connection or other "
                          "transient failure) — API token store disabled: {}",
                          PQresultErrorMessage(smoke.get()));
            return;
        }
    }

    // Post-migration smoke-read (#2964 fix round, chaos-injection finding):
    // `PgMigrationRunner::run` treats "this migration's id <= the stored
    // scalar high-water mark" as already-applied and SKIPS it — there is no
    // applied-set table behind that mark, only a single integer per store.
    // #3013 is exactly the shape that defeats it: two independently-authored
    // migrations claim the same version id, and whichever the numbering
    // reconciliation left SECOND is silently skipped forever on any database
    // that reaches the shared id via the OTHER migration first — `run()`
    // still reports success (nothing failed; there was, from its point of
    // view, nothing left to do). Construction is documented fail-CLOSED
    // (ADR-0012 §1, this file's own header) for exactly this shape —
    // reachable-but-wrong schema, not merely unreachable — so verify the v3
    // table this store's clock guard depends on is ACTUALLY present rather
    // than trusting a reported-successful run. Deliberately scoped to
    // `rotation_retention_meta` only (the concrete hole this round
    // reproduced against a real collision) rather than a general per-column
    // smoke-read of every migration this store has ever shipped — a broader
    // schema-completeness probe is a real idea (raised in review) but a
    // larger, separately-reviewable change; this closes the one hole that is
    // measured to exist today.
    pg::PgResult smoke = pg::exec_params(
        lease.get(), "SELECT 1 FROM api_token_store.rotation_retention_meta LIMIT 0",
        std::vector<std::string>{});
    if (smoke.status() != PGRES_TUPLES_OK) {
        spdlog::error(
            "ApiTokenStore: post-migration smoke-read of rotation_retention_meta failed ({}) "
            "— the migration runner reported success but the schema this code expects is not "
            "actually present (see #3013: a migration-numbering collision can make it skip a "
            "migration whose id is already <= the stored high-water mark) — refusing to open "
            "(ADR-0012 §1 fail-closed)",
            PQerrorMessage(lease.get()));
        return;
    }
    open_ = true;
    spdlog::info("ApiTokenStore: opened (schema {})", kStoreName);
}

bool ApiTokenStore::is_open() const {
    return open_;
}

// ── Token generation and hashing ─────────────────────────────────────────────

std::expected<std::string, std::string> ApiTokenStore::generate_raw_token() const {
    // Cryptographic PRNG required — pre-#801 this swallowed CSPRNG failures
    // and produced a token derived from zero-initialised bytes (all 'A'
    // chars). secure_random surfaces entropy exhaustion as a hard error so
    // the request becomes a 503 instead of issuing a known-weak token.
    std::uint8_t buf[kRawTokenRandomLen]{};
    auto rc = fill_random(std::span{buf, sizeof(buf)});
    if (!rc.has_value())
        return std::unexpected(std::string{"CSPRNG unavailable (entropy exhausted)"});

    static constexpr char chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::string token = "yuzu_";
    token.reserve(kRawTokenTotalLen);
    for (std::uint8_t b : buf)
        token += chars[b % 62];
    return token;
}

std::string ApiTokenStore::sha256_hex(const std::string& input) const {
    unsigned char hash[32]{};

#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (alg) {
        BCRYPT_HASH_HANDLE h = nullptr;
        BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0);
        if (h) {
            BCryptHashData(h, reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
                           static_cast<ULONG>(input.size()), 0);
            BCryptFinishHash(h, hash, 32, 0);
            BCryptDestroyHash(h);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
#else
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);
#endif

    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (unsigned char c : hash) {
        result += hex[c >> 4];
        result += hex[c & 0x0f];
    }
    return result;
}

// ── CRUD ─────────────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
ApiTokenStore::create_token(const std::string& name, const std::string& principal_id,
                            int64_t expires_at, const std::string& scope_service,
                            const std::string& mcp_tier, std::string principal_kind) {
    if (!open_)
        return std::unexpected("database not open");

    // Common human-mint checks (name/scope/tier/TTL), unconditional for both
    // principal_kind values — factored out so rotate_token's candidate-
    // successor prep shares the exact same policy gate (anti-drift, mirrors
    // validate_engine_mint's role for the engine arm).
    auto human_validation = validate_human_mint(name, scope_service, mcp_tier, expires_at,
                                                now_epoch());
    if (!human_validation.has_value())
        return std::unexpected(human_validation.error());

    // ── Engine principal block (design doc §6/§7/§8) ───────────────────────
    // C++-side allowlist ahead of the DB CHECK (principal_kind IN
    // ('human','engine')) — defense-in-depth per governance PR-4.2 prereq:
    // never let an unrecognized value reach Postgres and rely solely on the
    // constraint to reject it.
    if (principal_kind != "human" && principal_kind != "engine")
        return std::unexpected("invalid principal_kind");

    // G2 (governance hardening, security LOW / UP-1): symmetric namespace
    // guard. Without this, the `engine:`-namespace guarantee is only as
    // strong as every call site remembering to pass principal_kind=="engine"
    // whenever principal_id starts with "engine:" — a human-kind token could
    // otherwise carry an engine: id that RbacStore's engine-resolution arm
    // would happily match at role-resolution time. Make the guarantee
    // structural here, ahead of PR 4.3's engine-minting routes.
    if (principal_id.starts_with("engine:") && principal_kind != "engine")
        return std::unexpected("engine:-namespaced principal_id requires principal_kind=engine");

    if (principal_kind == "engine") {
        // §6/§7/§8: scope/tier/TTL + referential-integrity validation,
        // shared verbatim with `rotate_engine_credential`'s candidate-
        // successor prep (Hermes F2) so the two mint paths can never drift.
        auto validation = validate_engine_mint(principal_id, scope_service, mcp_tier, expires_at,
                                               now_epoch());
        if (!validation.has_value())
            return std::unexpected(validation.error());
    }

    auto raw_result = generate_raw_token();
    if (!raw_result.has_value())
        return std::unexpected(raw_result.error());
    auto raw = std::move(*raw_result);
    auto hash = sha256_hex(raw);
    auto token_id = hash.substr(0, 24); // Display ID — 24 hex chars (96 bits, collision-resistant)
    auto now = now_epoch();

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    // principal_kind is bound as a parameter ($7): "human" by default, or
    // "engine" once the engine block above has validated the mint (design doc
    // §§6-8). The DB CHECK (principal_kind IN ('human','engine')) is the
    // schema-level backstop behind the C++-side allowlist checked earlier.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO api_token_store.api_tokens "
        "(token_id, token_hash, name, principal_id, scope_service, mcp_tier, principal_kind, "
        " created_at, expires_at) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8::bigint,$9::bigint) RETURNING token_id",
        std::vector<std::string>{token_id, hash, name, principal_id, scope_service, mcp_tier,
                                 principal_kind, std::to_string(now), std::to_string(expires_at)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::unexpected(std::string("failed to create token: ") +
                               PQerrorMessage(lease.get()));
    return raw; // Return the raw token (shown once to user)
}

std::optional<ApiToken> ApiTokenStore::validate_token(const std::string& raw_token) {
    if (!open_ || raw_token.empty())
        return std::nullopt;

    auto hash = sha256_hex(raw_token);

    // Snapshot the revoke generation BEFORE the cache lookup so that any
    // revoke that races with our DB read is observable at the cache-write
    // step below, where we skip caching a stale entry. This guards cache
    // POISONING only — it does NOT serialize this validate against a
    // concurrent revoke the way sqlite's db_mtx_ used to. A token revoked
    // during this call's own execution may still be returned once (bounded;
    // the next uncached validate SELECTs revoked=true). See the
    // revoke_generation_ field comment in the hpp for the two residual
    // windows and the tracked follow-up for a proper close.
    const auto gen_before = revoke_generation_.load(std::memory_order_acquire);

    // Check cache first (avoids the Postgres round-trip on a hit).
    {
        std::lock_guard cache_lock(cache_mtx_);
        auto it = token_cache_.find(hash);
        if (it != token_cache_.end()) {
            auto age = std::chrono::steady_clock::now() - it->second.cached_at;
            if (age < kTokenCacheTtl) {
                const auto& cached = it->second.token;
                auto now = now_epoch();
                if (cached.revoked || (cached.expires_at > 0 && now > cached.expires_at)) {
                    token_cache_.erase(it);
                    cache_misses_.fetch_add(1, std::memory_order_relaxed);
                    return std::nullopt;
                }
                cache_hits_.fetch_add(1, std::memory_order_relaxed);
                return cached;
            }
            // Expired cache entry — remove and fall through to DB lookup
            token_cache_.erase(it);
        }
    }

    cache_misses_.fetch_add(1, std::memory_order_relaxed);

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;

    const std::string sql = std::string("SELECT token_id, token_hash, ") + kTokenColsTail +
                            " FROM api_token_store.api_tokens WHERE token_hash = $1";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{hash});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;

    ApiToken t = read_token(res.get(), 0);

    if (t.revoked)
        return std::nullopt;
    auto now = now_epoch();
    if (t.expires_at > 0 && now > t.expires_at)
        return std::nullopt;

    // Update last_used_at (best-effort — do not fail validation on this).
    pg::exec_params(lease.get(),
                    "UPDATE api_token_store.api_tokens SET last_used_at = $1::bigint "
                    "WHERE token_hash = $2",
                    std::vector<std::string>{std::to_string(now), hash});

    // Store in cache, but skip the write if a revoke raced our SELECT — this
    // prevents a stale revoked=false entry surviving the cache TTL. It does
    // NOT retract the value already being returned below; that bounded
    // single-request window is documented on revoke_generation_ in the hpp.
    //
    // The generation re-check MUST be taken UNDER cache_mtx_, not before it.
    // invalidate_cache() acquires the same mutex, and revoke_token bumps the
    // generation BEFORE it locks, so a check-then-lock ordering left a real
    // window: a revoke's erase could run between our check and our insert
    // (erasing nothing, since we hadn't inserted yet), after which we inserted a
    // revoked=false entry that re-authenticated the token for up to
    // kTokenCacheTtl. Holding the lock across the re-check AND the insert makes
    // the two operations serialize against the erase: either we observe the
    // bumped generation and skip, or the revoke's erase runs strictly after our
    // insert and removes it. Neither leaves a stale entry.
    if (test_hook_after_validate_select_)
        test_hook_after_validate_select_();

    {
        std::lock_guard cache_lock(cache_mtx_);
        if (revoke_generation_.load(std::memory_order_acquire) == gen_before) {
            token_cache_[hash] = CachedToken{t, std::chrono::steady_clock::now()};
        }
    }

    return t;
}

ApiTokenStore::CheckedToken ApiTokenStore::validate_token_checked(const std::string& raw_token) {
    if (raw_token.empty())
        return {TokenCheck::kInvalid, std::nullopt};  // definitive: no credential is no credential
    if (!open_)
        return {TokenCheck::kUnavailable, std::nullopt};  // store closed → we cannot know

    // This does its OWN status-aware lookup rather than calling validate_token and
    // inferring from its nullopt. An earlier version did exactly that, then probed
    // the store with a *different* trivial statement to decide whether the negative
    // answer was real — and that is wrong in the precise case this function exists
    // for: `validate_token` folds "could not acquire a connection" and "the query
    // errored" into the same nullopt as "no such row", while the probe statement can
    // still succeed on a merely-contended store. The result was a healthy stream
    // being killed as `credential_revoked` because the backend was busy — the 60 s
    // grace window (Decision 15(i)) unreachable for the most likely auth-store fault.
    // Only the status of the actual lookup can distinguish the two. (The reasoning
    // was written against SQLite's BUSY/IOERR rc and survives the Postgres port
    // unchanged: a failed lease and a non-TUPLES_OK result are the same class of
    // "we asked and did not get an answer", and zero rows is the same definitive no.)
    const auto hash = sha256_hex(raw_token);
    const auto gen_before = revoke_generation_.load(std::memory_order_acquire);

    {
        std::lock_guard cache_lock(cache_mtx_);
        auto it = token_cache_.find(hash);
        if (it != token_cache_.end()) {
            if (std::chrono::steady_clock::now() - it->second.cached_at < kTokenCacheTtl) {
                const auto& cached = it->second.token;
                const auto now = now_epoch();
                if (cached.revoked || (cached.expires_at > 0 && now > cached.expires_at)) {
                    token_cache_.erase(it);
                    cache_misses_.fetch_add(1, std::memory_order_relaxed);
                    return {TokenCheck::kInvalid, std::nullopt}; // definitive
                }
                cache_hits_.fetch_add(1, std::memory_order_relaxed);
                return {TokenCheck::kValid, cached};
            }
            token_cache_.erase(it);
        }
    }
    cache_misses_.fetch_add(1, std::memory_order_relaxed);

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        // No connection inside the timeout: we could not even ask. NOT evidence of
        // revocation — the caller rides out its bounded grace window instead.
        return {TokenCheck::kUnavailable, std::nullopt};
    }

    const std::string sql = std::string("SELECT token_id, token_hash, ") + kTokenColsTail +
                            " FROM api_token_store.api_tokens WHERE token_hash = $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{hash});
    if (res.status() != PGRES_TUPLES_OK) {
        // We asked and did not get an answer (backend error, connection dropped
        // mid-query, ...). Fail-safe: indeterminate never GRANTS access, it only
        // defers the decision to cut an already-authenticated stream.
        return {TokenCheck::kUnavailable, std::nullopt};
    }
    if (PQntuples(res.get()) == 0)
        return {TokenCheck::kInvalid, std::nullopt}; // the row genuinely is not there

    ApiToken t = read_token(res.get(), 0);

    if (t.revoked || (t.expires_at > 0 && now_epoch() > t.expires_at))
        return {TokenCheck::kInvalid, std::nullopt}; // definitive

    // Deliberately NO `UPDATE last_used_at` here. This runs on every heartbeat tick of
    // every live stream: writing would (a) make last_used_at track heartbeats rather
    // than actual calls, and (b) put a write on a pooled connection every time a
    // stream's cache entry expires — with streams' TTLs aligned by attach time, that is
    // a thundering herd of writes that every token-authenticated request on the server
    // then queues behind. Re-validation is a READ.
    //
    // The generation re-check is taken UNDER cache_mtx_, matching validate_token: a
    // check-then-lock ordering leaves a window where a racing revoke's erase runs
    // between the check and the insert, leaving a revoked=false entry alive for a full
    // kTokenCacheTtl — which on this path would keep a revoked credential's stream up.
    {
        std::lock_guard cache_lock(cache_mtx_);
        if (revoke_generation_.load(std::memory_order_acquire) == gen_before) {
            token_cache_[hash] = CachedToken{t, std::chrono::steady_clock::now()};
        }
    }
    return {TokenCheck::kValid, std::move(t)};
}

void ApiTokenStore::invalidate_cache(const std::string& token_hash) {
    std::lock_guard cache_lock(cache_mtx_);
    token_cache_.erase(token_hash);
}

std::size_t ApiTokenStore::cache_size() const {
    std::lock_guard cache_lock(cache_mtx_);
    return token_cache_.size();
}

std::size_t ApiTokenStore::rotation_grace_cache_size() const {
    std::lock_guard cache_lock(rotation_cache_mtx_);
    return rotation_grace_cache_.size();
}

void ApiTokenStore::set_engine_referent_check(
    std::function<EngineLookupStatus(const std::string&)> fn) {
    engine_referent_check_ = std::move(fn);
}

std::expected<std::vector<ApiToken>, std::string>
ApiTokenStore::list_tokens(const std::string& principal_id) const {
    // Authoritative store (ADR-0012 §1): a runtime read error is SURFACED, never
    // papered over as an empty result — a silent empty read here would show an
    // operator "no tokens" during a Postgres outage and could hide a live
    // credential. Only a genuine zero-row read returns an empty vector.
    if (!open_)
        return std::unexpected("database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    std::string sql = std::string("SELECT token_id, '' AS token_hash, ") + kTokenColsTail +
                      " FROM api_token_store.api_tokens";
    std::vector<std::string> params;
    if (!principal_id.empty()) {
        sql += " WHERE principal_id = $1";
        params.push_back(principal_id);
    }
    sql += " ORDER BY created_at DESC";

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("list_tokens read failed: ") +
                               PQerrorMessage(lease.get()));

    std::vector<ApiToken> result;
    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        result.push_back(read_token(res.get(), i)); // token_hash is the literal '' column above
    }
    return result;
}

std::expected<std::optional<ApiToken>, std::string>
ApiTokenStore::get_token(const std::string& token_id) const {
    // Authoritative store (ADR-0012 §1): distinguish a runtime read error
    // (surfaced → caller 503s) from a genuine no-such-row (value == nullopt →
    // caller 404s). The old nullopt-on-DB-error made an ownership pre-check 404
    // during an outage while the token stayed live (#2188 review).
    if (!open_)
        return std::unexpected("database not open");
    if (token_id.empty())
        return std::optional<ApiToken>{std::nullopt}; // argument guard, not a DB error

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    const std::string sql = std::string("SELECT token_id, '' AS token_hash, ") + kTokenColsTail +
                            " FROM api_token_store.api_tokens WHERE token_id = $1";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{token_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("get_token read failed: ") + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::optional<ApiToken>{std::nullopt}; // genuine not-found

    return std::optional<ApiToken>{read_token(res.get(), 0)};
}

std::vector<ApiToken>
ApiTokenStore::list_active_for_principal(const std::string& principal_id) const {
    std::vector<ApiToken> result;
    if (!open_ || principal_id.empty())
        return result;

    // Both early returns below share rotation_confirm_state.hpp's positive-read
    // contract: an empty vector here is indistinguishable from a genuine
    // zero-active-credentials read by ANY caller of this public accessor. That
    // is fine for a destructive in-transaction consumer (stays retryable), but
    // #2443's precondition caller has no other signal to notice a persistent
    // fault here — the warn line is that signal for on-call, since the caller
    // itself denies-without-consuming either way and cannot distinguish the
    // causes from the return value alone.
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::warn("ApiTokenStore::list_active_for_principal: pool lease timed out for "
                     "principal_id={}",
                     principal_id);
        return result;
    }

    const auto now = now_epoch();
    const std::string sql = std::string("SELECT token_id, '' AS token_hash, ") + kTokenColsTail +
                            " FROM api_token_store.api_tokens "
                            "WHERE principal_id = $1 AND revoked = FALSE "
                            "AND (expires_at = 0 OR expires_at > $2::bigint) "
                            "ORDER BY created_at ASC";
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(), std::vector<std::string>{principal_id, std::to_string(now)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("ApiTokenStore::list_active_for_principal: query failed for "
                     "principal_id={}: {}",
                     principal_id, PQerrorMessage(lease.get()));
        return result;
    }

    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        result.push_back(read_token(res.get(), i)); // token_hash is the literal '' column above
    return result;
}

// ── Overlap-pair rotation (design doc §7) ───────────────────────────────────

std::expected<void, std::string>
ApiTokenStore::validate_engine_mint(const std::string& principal_id,
                                    const std::string& scope_service, const std::string& mcp_tier,
                                    int64_t expires_at, int64_t now) const {
    // F6 (Hermes pass-2 MEDIUM M3): engine principals are fleet-wide only
    // (§4.3) — a service-scoped engine token is not a valid combination.
    if (!scope_service.empty())
        return std::unexpected("engine principal tokens cannot be service-scoped");

    // §8: mcp_tier readonly hard-lock. Unlike the human path (which permits
    // an empty mcp_tier for a non-MCP token), an engine token MUST be
    // readonly — empty or any other tier is rejected outright.
    if (mcp_tier != "readonly")
        return std::unexpected("engine principal tokens must use mcp_tier=readonly");

    // §7: non-perpetual / 90-day ceiling.
    if (expires_at == 0)
        return std::unexpected("engine principal tokens cannot be perpetual (90-day max)");
    constexpr int64_t k90Days = 90 * 24 * 3600;
    if (expires_at - now > k90Days)
        return std::unexpected("engine principal token TTL cannot exceed 90 days");

    // §6: creation-time referential integrity. Fail-closed if the resolver
    // isn't wired yet — never mint an engine token without this check.
    if (!engine_referent_check_)
        return std::unexpected("engine referent check unavailable");
    switch (engine_referent_check_(principal_id)) {
    case EngineLookupStatus::Active:
        return {};
    case EngineLookupStatus::MissingOrRevoked:
        // Terminal (401-class) per engine_principal_store.hpp's three-state
        // contract — the referenced principal doesn't exist or was revoked.
        return std::unexpected("engine principal not found or revoked");
    case EngineLookupStatus::StoreUnreachable:
        // Retryable (503-class), distinct from the terminal case above — see
        // the EngineLookupStatus doc comment / design doc §3.1.
        return std::unexpected("engine principal store unavailable — try again");
    }
    return std::unexpected("engine referent check returned an unrecognized status");
}

std::expected<void, std::string>
ApiTokenStore::validate_human_mint(const std::string& name, const std::string& scope_service,
                                   const std::string& mcp_tier, int64_t expires_at,
                                   int64_t now) const {
    // Verbatim `create_token`'s pre-refactor common checks — kept byte-for-
    // byte so factoring this out changes nothing about the wire-visible
    // error strings (engine_store_error_class.hpp keys on these exact
    // substrings).
    if (name.empty())
        return std::unexpected("token name cannot be empty");
    if (!scope_service.empty() && expires_at <= 0)
        return std::unexpected("service-scoped tokens must have an expiration time");
    if (!mcp_tier.empty() && !mcp::is_valid_tier(mcp_tier))
        return std::unexpected(
            "invalid MCP tier — must be 'readonly', 'operator', or 'supervised'");
    if (!mcp_tier.empty() && expires_at <= 0)
        return std::unexpected("MCP tokens must have an expiration time (max 90 days)");
    if (!mcp_tier.empty() && expires_at > 0) {
        constexpr int64_t k90Days = 90 * 24 * 3600;
        if (expires_at - now > k90Days)
            return std::unexpected("MCP token TTL cannot exceed 90 days");
    }
    return {};
}

bool ApiTokenStore::try_reserve(const std::string& rotation_group, std::string& out_raw,
                                std::string& out_requesting_user) const {
    std::lock_guard cache_lock(rotation_cache_mtx_);
    auto it = rotation_grace_cache_.find(rotation_group);
    if (it == rotation_grace_cache_.end())
        return false;
    out_requesting_user = it->second.requesting_user;
    if (std::chrono::steady_clock::now() - it->second.minted > kRotationGraceSecs) {
        // Raw-secret reveal is time-bounded (§7) — the entry itself stays
        // resident so `confirm_rotation`/`grace_entry_owner` can still
        // resolve `requesting_user` for the rest of the (much longer)
        // overlap window. See the RotationGraceEntry doc comment.
        return false;
    }
    out_raw = it->second.raw;
    return true;
}

bool ApiTokenStore::grace_entry_owner(const std::string& rotation_group,
                                      std::string& out_requesting_user) const {
    std::lock_guard cache_lock(rotation_cache_mtx_);
    auto it = rotation_grace_cache_.find(rotation_group);
    if (it == rotation_grace_cache_.end())
        return false;
    out_requesting_user = it->second.requesting_user;
    return true;
}

std::optional<std::string>
ApiTokenStore::resolve_rotation_initiator(const ApiToken& successor) const {
    std::string ram_initiator;
    const bool ram_present = grace_entry_owner(successor.rotation_group, ram_initiator);
    const bool durable_present = !successor.rotation_initiator.empty();

    std::optional<std::string> resolved;
    if (ram_present && durable_present) {
        if (ram_initiator != successor.rotation_initiator) {
            // Not reachable through any live code path in this store: both
            // sources are written from the SAME requesting_user in the SAME
            // mint call (the durable column is stamped inside the mint's
            // own locked transaction; store_rotation_raw only ever runs
            // AFTER that same transaction commits — see its call sites'
            // #2961 fix-round comments). A disagreement can only arise from
            // an out-of-band write to api_tokens.rotation_initiator (direct
            // SQL, a restored/edited backup) or a future bug — i.e. this is
            // a tamper/corruption signal on an authorization input, not an
            // operational condition. Counted and logged (rotation_group
            // only, never either disputed username — same disclosure
            // posture as resolve_rotation_pair_after_revoke's own defensive
            // log line) so it is actually alertable rather than silently
            // folded into the benign "rotation confirmation unavailable"
            // conflict class this returns into.
            rotation_initiator_disagreements_.fetch_add(1, std::memory_order_relaxed);
            spdlog::error(
                "[{}] resolve_rotation_initiator: RAM and durable rotation_initiator DISAGREE "
                "for rotation_group='{}' — refusing to resolve either (fail closed). This "
                "cannot happen through any live code path; treat as a tamper/corruption "
                "signal and inspect the row's history manually.",
                kStoreName, successor.rotation_group);
            return std::nullopt; // fail closed, never prefer either
        }
        resolved = ram_initiator;
    } else if (ram_present) {
        resolved = ram_initiator;
    } else if (durable_present) {
        // The RAM-absent recovery path #2961 exists for: a restart forfeited
        // the grace-cache entry, but the successor's own row still carries
        // the operator who minted it.
        resolved = successor.rotation_initiator;
    }
    // Neither present falls through with `resolved` unset — empty is NOT a
    // wildcard (pre-v3 pair, or a restart before v3 ever stamped this row).
    //
    // The empty guard below applies to WHICHEVER branch produced `resolved`
    // — not just the durable one. `grace_entry_owner` only ever returns an
    // empty `requesting_user` if it were ever stored empty, which no current
    // caller does, but the guard lives HERE precisely so a future caller
    // (e.g. #2946's read-only accessor) can't reintroduce that gap.
    if (resolved && resolved->empty())
        return std::nullopt;
    return resolved;
}

void ApiTokenStore::evict_rotation_raw(const std::string& rotation_group) {
    std::lock_guard cache_lock(rotation_cache_mtx_);
    auto it = rotation_grace_cache_.find(rotation_group);
    if (it != rotation_grace_cache_.end())
        yuzu::secure_zero(it->second.raw); // scrub before the erase frees it
    rotation_grace_cache_.erase(rotation_group);
}

void ApiTokenStore::resolve_rotation_pair_after_revoke(const std::string& principal_id,
                                                      const std::string& rotation_group,
                                                      const std::string& revoked_token_id) {
    if (!open_ || principal_id.empty() || rotation_group.empty())
        return; // the common non-rotation revoke — nothing to resolve

    // Clear the surviving partner's rotation state under the same principal
    // advisory lock rotate/confirm/sweep take, so this can't race them. The
    // partner is simply the OTHER live row sharing this rotation_group — the
    // clear is identical whether it is the predecessor or the successor: it
    // becomes a plain standalone credential and (crucially) drops out of the
    // sweep's predecessor scan (overlap_expires_at -> 0).
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult lock_res =
            pg::exec_params(conn, "SELECT pg_advisory_xact_lock(hashtext($1))",
                            std::vector<std::string>{principal_id});
        if (lock_res.status() != PGRES_TUPLES_OK)
            return false;
        pg::PgResult r = pg::exec_params(
            conn,
            "UPDATE api_token_store.api_tokens "
            "SET rotation_group = '', supersedes_token_id = '', overlap_expires_at = 0, "
            "    rotation_initiator = '' "
            "WHERE rotation_group = $1 AND token_id <> $2 AND revoked = FALSE",
            std::vector<std::string>{rotation_group, revoked_token_id});
        // Zero rows is fine (partner already resolved/gone); no RETURNING, so a
        // successful zero-row match is PGRES_COMMAND_OK. Only a genuine
        // execution failure rolls back.
        return r.status() == PGRES_COMMAND_OK;
    });
    // Fail-visibility (governance Gate 7; consequence CORRECTED by PR #2974
    // review, K7). A swallowed failure here leaves the surviving partner
    // still stamped with its `rotation_group`/`overlap_expires_at`, which is
    // untidy and worth alerting on.
    //
    // An earlier revision of this comment claimed the sweep could then
    // auto-revoke that partner and leave the principal with ZERO active
    // credentials. **That chain is not reachable** and the claim was wrong.
    // A reviewer traced the sweep SQL and I confirmed it: the predecessor
    // scan requires `supersedes_token_id = ''`, which structurally excludes a
    // stranded SUCCESSOR row whatever it is stamped with; and its `EXISTS`
    // clause requires a LIVE (`revoked = FALSE`), used partner whose
    // `supersedes_token_id` equals the scanned row's `token_id` — but in this
    // failure path that partner is precisely the row that was just revoked.
    // No stranded row can satisfy both predicates, in either revoke-half.
    //
    // The correction matters because the overstated consequence is what a
    // future reader would prioritise off. This is an operability defect —
    // a swallowed failure with no metric — not a lockout risk.
    //
    // Logged only, never surfaced to the caller: the revoke that triggered
    // this call has already committed and there is no compensating action
    // left to take. Now also counted, so a swallowed failure is alertable
    // rather than log-only.
    if (!ok) {
        rotation_pair_resolve_failures_.fetch_add(1, std::memory_order_relaxed);
        spdlog::error(
            "[{}] resolve_rotation_pair_after_revoke: failed to clear rotation state on the "
            "surviving partner of rotation_group='{}' after revoking token_id='{}' "
            "(principal_id='{}') — the partner may still be stamped as an unresolved "
            "predecessor; the sweep cannot auto-revoke it (see the comment above), so this "
            "is stale metadata rather than a lockout risk, but inspect manually",
            kStoreName, rotation_group, revoked_token_id, principal_id);
    }
    evict_rotation_raw(rotation_group);
}

void ApiTokenStore::store_rotation_raw(const std::string& rotation_group, const std::string& raw,
                                       const std::string& requesting_user) {
    std::lock_guard cache_lock(rotation_cache_mtx_);
    auto it = rotation_grace_cache_.find(rotation_group);
    if (it != rotation_grace_cache_.end())
        yuzu::secure_zero(it->second.raw); // scrub the entry being overwritten
    rotation_grace_cache_[rotation_group] =
        RotationGraceEntry{raw, requesting_user, std::chrono::steady_clock::now()};
}

bool ApiTokenStore::successor_rotation_still_pending(const std::string& successor_token_id) const {
    // See the .hpp doc comment for the race this closes and why it fails
    // OPEN (returns true) on any ambiguous outcome below.
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return true;
    auto lookup = read_token_by_id_on_conn(lease.get(), successor_token_id);
    if (!lookup.ok || !lookup.token)
        return true;
    // `rotation_group` is cleared to '' by resolve_rotation_pair_after_revoke
    // ON THE SURVIVING PARTNER (`token_id <> $2`) whenever EITHER side of a
    // pair is revoked — but never on the revoked row itself, whose own
    // `rotation_group` (stamped to the successor's OWN token_id at mint time)
    // survives unchanged. So a non-empty `rotation_group` alone does NOT mean
    // "nothing has resolved this pair since the mint committed" — it also
    // matches a successor that was itself revoked in the window, which IS a
    // resolution (measured: this happens whenever the successor is revoked
    // before being confirmed). Check `revoked` explicitly rather than
    // inferring resolution from `rotation_group` alone: a revoked successor
    // is resolved and must not have its raw secret re-cached.
    return !lookup.token->revoked && !lookup.token->rotation_group.empty();
}

void ApiTokenStore::scrub_elapsed_grace_secrets() {
    std::lock_guard cache_lock(rotation_cache_mtx_);
    const auto now = std::chrono::steady_clock::now();
    for (auto& [group, entry] : rotation_grace_cache_) {
        // Mirrors try_reserve's own staleness check — once the raw-reveal
        // grace window has elapsed, no caller can read `raw` back out
        // anyway, so its plaintext no longer needs to sit in RAM. The
        // entry itself (notably `requesting_user`) stays resident; only
        // scrub once, so an already-empty `raw` is a cheap no-op.
        if (!entry.raw.empty() && now - entry.minted > kRotationGraceSecs)
            yuzu::secure_zero(entry.raw);
    }
}

std::expected<std::string, std::string>
ApiTokenStore::rotate_engine_credential(const std::string& principal_id, int64_t overlap_secs,
                                        int64_t now, const std::string& requesting_user) {
    if (!open_)
        return std::unexpected("database not open");
    if (principal_id.empty())
        return std::unexpected("principal_id required");
    if (requesting_user.empty())
        return std::unexpected("requesting_user required");

    // §7: reject an under-floor window outright rather than truncating it —
    // a window the module never gets a chance to act within is a worse
    // failure than a rejected rotate call. Pure-math check; no DB round trip
    // needed to evaluate it.
    if (overlap_secs < kOverlapFloorSecs)
        return std::unexpected("overlap window below 24h floor");

    // Reject an absurdly large window outright too — `overlap_secs` is
    // floored above but was never ceilinged, so an unbounded caller value
    // fed into the `now + overlap_secs` adds below would be an unchecked
    // signed int64 overflow (UB), and a wrapped-negative `window_end` could
    // slip past the expiry guards those adds feed. Evaluated here, before
    // any arithmetic touches `overlap_secs`.
    if (overlap_secs > kOverlapCeilSecs)
        return std::unexpected("overlap window exceeds the maximum (10 years)");

    // Every local plaintext-secret slot the scrub guard below reaches is
    // declared HERE, empty, and the guard is ARMED before any of them is
    // populated — same declare-then-arm-then-generate discipline as
    // `rotate_token`'s own guard (this file), closing the gap an earlier
    // round of this diff left open here (see that guard's comment, which
    // used to note this function as future work).
    std::string candidate_raw, candidate_hash, candidate_token_id, candidate_error;
    std::string error_msg;
    std::string raw_out;
    // Populated only by the 1-active mint branch, applied to the RAM grace
    // cache AFTER the transaction below commits successfully.
    std::string grace_group_out, grace_raw_out;
    // Re-serve arm's local secret + owner, hoisted to FUNCTION scope (rather
    // than declared inside the lambda below) so the scope-exit scrub guard
    // immediately below can reach `cached_raw` regardless of how the
    // transaction exits — a lambda-local variable is destroyed the moment
    // the lambda returns, before any function-scope guard could run. Same
    // rationale as `rotate_token`'s identical hoist.
    std::string cached_raw, cached_user;

    // Scrub every local plaintext secret copy, unconditionally, on EVERY
    // exit from this function from this point on — including a thrown
    // exception. Same four slots, same reasoning, as `rotate_token`'s own
    // guard (this file) — see that guard's comment for the full rationale
    // per slot; `raw_out` is included unconditionally there too, since the
    // success path already moves it out via `return raw_out;` before this
    // guard fires.
    ScopeExit scrub_secrets{[&] {
        yuzu::secure_zero(candidate_raw);
        yuzu::secure_zero(grace_raw_out);
        yuzu::secure_zero(cached_raw);
        yuzu::secure_zero(raw_out);
    }};

    // Candidate successor, prepared BEFORE the locked transaction below
    // (Hermes F2 — see this function's .hpp doc comment for why: both
    // `validate_engine_mint`'s referential-integrity call and CSPRNG
    // generation must not run from inside `with_txn_for`'s callback). Used
    // only if the lock-held re-read below actually lands on the 1-active
    // mint branch; discarded otherwise.
    constexpr int64_t k90Days = 90 * 24 * 3600;
    const int64_t candidate_expires_at = now + k90Days;
    auto candidate_validation =
        validate_engine_mint(principal_id, /*scope_service=*/{}, "readonly", candidate_expires_at,
                             now);
    if (candidate_validation.has_value()) {
        auto raw_result = generate_raw_token();
        if (raw_result.has_value()) {
            candidate_raw = std::move(*raw_result);
            candidate_hash = sha256_hex(candidate_raw);
            candidate_token_id = candidate_hash.substr(0, 24);
        } else {
            candidate_error = raw_result.error();
        }
    } else {
        candidate_error = candidate_validation.error();
    }

    // Hermes F1: the ENTIRE check -> mint -> stamp sequence commits inside
    // ONE transaction, opened with a principal-scoped Postgres advisory
    // lock — a concurrent rotate_engine_credential/confirm_rotation call
    // for the SAME principal_id blocks on the lock until this transaction
    // resolves, so its own re-read always observes this call's committed
    // effect (or its absence), never an interleaved half-state. The ≤2
    // ceiling therefore holds under concurrency.
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult lock_res =
            pg::exec_params(conn, "SELECT pg_advisory_xact_lock(hashtext($1))",
                            std::vector<std::string>{principal_id});
        if (lock_res.status() != PGRES_TUPLES_OK) {
            error_msg = "failed to acquire rotation lock";
            return false;
        }

        auto active = read_active_for_principal_on_conn(conn, principal_id, now);

        // Belt-and-braces (mirrors the G2 namespace guard in create_token):
        // rotate_engine_credential only ever operates on engine credentials
        // — never silently mix a human-kind row into the rotation state
        // machine.
        for (const auto& t : active) {
            if (t.principal_kind != "engine") {
                error_msg = "principal has a non-engine active credential";
                return false;
            }
        }

        if (active.empty()) {
            error_msg = "no active credential to rotate — mint one first";
            return false;
        }

        if (active.size() == 1) {
            const ApiToken& predecessor = active.front();
            const int64_t window_end = now + overlap_secs;

            // Reject, never truncate, if the requested overlap would
            // outlive either credential's own expiry.
            if (predecessor.expires_at != 0 && window_end > predecessor.expires_at) {
                error_msg = "overlap window would exceed the predecessor credential's expiry";
                return false;
            }
            if (window_end > candidate_expires_at) {
                error_msg = "overlap window would exceed the successor credential's expiry";
                return false;
            }
            if (!candidate_error.empty()) {
                error_msg = candidate_error;
                return false;
            }

            // Hermes F2: mint (INSERT) and pair-stamp (both UPDATEs) commit
            // in this SAME transaction — a crash here rolls back the whole
            // thing, so a successful rotate always leaves both rows linked;
            // there is no window where an orphan successor (empty
            // rotation_group) can exist.
            pg::PgResult ins = pg::exec_params(
                conn,
                "INSERT INTO api_token_store.api_tokens "
                "(token_id, token_hash, name, principal_id, scope_service, mcp_tier, "
                " principal_kind, created_at, expires_at, rotation_group, supersedes_token_id, "
                " rotation_initiator) "
                "VALUES ($1,$2,$3,$4,'', 'readonly', 'engine', $5::bigint, $6::bigint, $7, $8, $9) "
                "RETURNING token_id",
                std::vector<std::string>{candidate_token_id, candidate_hash, predecessor.name,
                                         principal_id, std::to_string(now),
                                         std::to_string(candidate_expires_at), candidate_token_id,
                                         predecessor.token_id, requesting_user});
            if (ins.status() != PGRES_TUPLES_OK || PQntuples(ins.get()) == 0) {
                error_msg = "failed to mint successor credential";
                return false;
            }

            pg::PgResult r2 = pg::exec_params(
                conn,
                "UPDATE api_token_store.api_tokens "
                "SET rotation_group = $1, overlap_expires_at = $2::bigint "
                "WHERE token_id = $3 AND revoked = FALSE RETURNING token_id",
                std::vector<std::string>{candidate_token_id, std::to_string(now + overlap_secs),
                                         predecessor.token_id});
            if (r2.status() != PGRES_TUPLES_OK || PQntuples(r2.get()) == 0) {
                error_msg = "failed to stamp predecessor overlap window";
                return false;
            }

            raw_out = candidate_raw;
            grace_group_out = candidate_token_id;
            grace_raw_out = candidate_raw;
            return true;
        }

        if (active.size() == 2) {
            const ApiToken* predecessor = nullptr;
            const ApiToken* successor = nullptr;
            for (const auto& t : active) {
                if (!t.supersedes_token_id.empty())
                    successor = &t;
                else
                    predecessor = &t;
            }
            if (predecessor == nullptr || successor == nullptr ||
                successor->rotation_group.empty() ||
                successor->rotation_group != predecessor->rotation_group ||
                successor->supersedes_token_id != predecessor->token_id) {
                error_msg = "two active credentials not in a recognized rotation pair — "
                           "resolve via revoke, not rotate";
                return false;
            }

            // Idempotency window, epoch side: a retry more than
            // kRotationGraceSecs after the successor's own mint is out of
            // bounds regardless of whether the in-memory cache entry
            // happens to still be present.
            if (now - successor->created_at > kRotationGraceSecs.count()) {
                error_msg = "rotation grace window elapsed; confirm or revoke";
                return false;
            }

            // Idempotency window, cache side: the raw secret itself must
            // still be resident and unexpired. `cached_raw`/`cached_user`
            // are the FUNCTION-scope variables declared above (not
            // lambda-local) so the scope-exit scrub guard above can reach
            // `cached_raw` on every exit from this function, not just this
            // lambda's return.
            if (!try_reserve(successor->rotation_group, cached_raw, cached_user)) {
                error_msg = "rotation grace window elapsed; confirm or revoke";
                return false;
            }

            // Hermes F4: only the SAME operator who initiated this rotation
            // may re-serve its raw secret — never a different admin, even
            // within the grace window.
            if (cached_user != requesting_user) {
                error_msg = "rotation in progress by a different operator";
                return false;
            }

            // Re-serve the SAME raw value. The per-reveal audit and the
            // step-up re-validation this replay still owes (§7) are the
            // route layer's responsibility, not this store's.
            raw_out = cached_raw;
            return true;
        }

        // Defensive: this function's own 1-active arm is the only mint path
        // it drives, so >2 active means a credential was minted outside
        // rotate_engine_credential (e.g. a direct create_token call) — never
        // silently arbitrate which one to treat as authoritative.
        error_msg = "more than two active credentials for this principal — "
                    "resolve manually before rotating";
        return false;
    });

    if (!ok)
        return std::unexpected(error_msg.empty() ? "rotation failed" : error_msg);

    // Cache the raw secret + initiating operator for the grace window AFTER
    // the mint committed — the one-time-reveal contract's "once" means once
    // per grace-bounded rotation attempt (§7), so a bounded retry BY THE
    // SAME OPERATOR can re-serve this exact value.
    //
    // #2961 fix-round finding 2: the mint's advisory lock is already RELEASED
    // by this point (with_txn_for committed above), so a confirm/sweep/
    // revoke-partner-clear for this SAME rotation group can slip in here and
    // fully resolve the pair — via the durable rotation_initiator column
    // this same commit just wrote — before this cache write runs. Re-check
    // freshly rather than caching unconditionally: see
    // successor_rotation_still_pending's doc comment for why an insert here
    // for an already-resolved group would be permanently unevictable.
    if (!grace_group_out.empty()) {
        if (test_hook_before_store_rotation_raw_)
            test_hook_before_store_rotation_raw_();
        if (successor_rotation_still_pending(grace_group_out))
            store_rotation_raw(grace_group_out, grace_raw_out, requesting_user);
    }

    return raw_out;
}

std::expected<void, std::string>
ApiTokenStore::confirm_rotation(const std::string& principal_id, const std::string& token_id,
                                const std::string& presented_secret,
                                const std::string& requesting_user) {
    if (!open_)
        return std::unexpected("database not open");
    if (principal_id.empty())
        return std::unexpected("principal_id required");
    if (token_id.empty())
        return std::unexpected("token_id required");
    if (presented_secret.empty())
        return std::unexpected("secret required");
    if (requesting_user.empty())
        return std::unexpected("requesting_user required");

    const int64_t now = now_epoch();
    std::string error_msg;
    std::string revoked_hash;
    std::string confirmed_group;

    // Advisory-locked exactly like rotate_engine_credential (Hermes F5) —
    // the confirm + predecessor-revoke + successor-clear triple commits
    // atomically in this same transaction, and can't race a concurrent
    // rotate/confirm/sweep for the same principal.
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult lock_res =
            pg::exec_params(conn, "SELECT pg_advisory_xact_lock(hashtext($1))",
                            std::vector<std::string>{principal_id});
        if (lock_res.status() != PGRES_TUPLES_OK) {
            error_msg = "failed to acquire rotation lock";
            return false;
        }

        auto active = read_active_for_principal_on_conn(conn, principal_id, now);
        for (const auto& t : active) {
            if (t.principal_kind != "engine") {
                error_msg = "principal has a non-engine active credential";
                return false;
            }
        }

        // #2404: discriminate the states a confirm can find so a replay after
        // the rotation already resolved gets a TERMINAL answer (the caller's
        // classifier maps these strings to a 409/kInvalidParams conflict),
        // instead of the old blanket "no in-flight rotation" that classified
        // 503-retryable and made an idempotent-hint-honouring agent retry a
        // permanently-failing call forever. The state machine is factored into
        // a pure classifier (rotation_confirm_state.hpp) so a future
        // pre-consume recheck seam (#2443) can reuse the same taxonomy; the
        // recheck HERE, under the advisory lock, stays authoritative.
        //
        // Each error string below embeds the substring engine_store_error_class.hpp
        // keys on to choose the HTTP/JSON-RPC class ("more than two active
        // credentials"->400; "sole active credential"/"the rotation was
        // resolved"/"unresolved rotation metadata"->409; "no in-flight rotation
        // to confirm"->retryable 503). A reword that drops the keyed substring
        // silently reclassifies to the Transient default, so keep these strings
        // and the classifier in lockstep (arch review, #2404).
        switch (detail::classify_confirm_state(active, token_id)) {
        case detail::RotationConfirmState::kNoneActive:
            // Ambiguous with a swallowed read failure (empty-on-error read
            // contract) -> stays retryable, never a terminal client error.
            error_msg = "no in-flight rotation to confirm";
            return false;
        case detail::RotationConfirmState::kOverfull:
            error_msg = "more than two active credentials for this principal - "
                        "resolve manually before confirming";
            return false;
        case detail::RotationConfirmState::kUnresolvedSole:
            // A best-effort pair-resolve failed (or the partner expired before
            // cleanup while the sweep was down), leaving one row still stamped
            // mid-rotation. Rotating from here would strand a malformed pair.
            // Remediation LEADS WITH inspect, not revoke: in the sweep-outage
            // variant (UP-2) this sole row is the GOOD surviving credential, so
            // a reflexive revoke would drop the principal to zero credentials.
            error_msg = "one active credential with unresolved rotation metadata - "
                        "inspect the credential state and do not rotate; revoke only "
                        "if it is confirmed stale";
            return false;
        case detail::RotationConfirmState::kSoleConfirmed:
            error_msg = "rotation already confirmed - the supplied token_id is the "
                        "sole active credential; nothing to confirm";
            return false;
        case detail::RotationConfirmState::kSoleResolved:
            error_msg = "no rotation in flight - the supplied token_id is already the "
                        "sole active credential; nothing to confirm";
            return false;
        case detail::RotationConfirmState::kSoleOtherToken:
            error_msg = "no rotation in flight for the supplied token_id - the rotation "
                        "was resolved (confirmed, revoked, or cut over); rotate again if "
                        "a new rotation is needed";
            return false;
        case detail::RotationConfirmState::kPair:
            break; // exactly two active -> fall through to pair processing below
        }

        // This linkage check is intentionally NOT expressed via
        // rotation_confirm_state.hpp::pair_matches_pin, even though the two
        // are checking the same shape (#2443 added that helper for the same
        // linkage question, unlocked). pair_matches_pin collapses "not
        // linked" and "linked but wrong pin" into one bool; here those are
        // two DIFFERENT client-visible error classes (this block: retryable
        // "no in-flight rotation to confirm"; the pin check below: terminal
        // "token_id does not match" - see engine_store_error_class.hpp).
        // Swapping in the bool would silently merge them. A shared helper
        // needs a reason enum, not a bool - tracked as #2953, not done here
        // to avoid changing this authoritative path's error taxonomy late in
        // an unrelated governance round.
        const ApiToken* predecessor = nullptr;
        const ApiToken* successor = nullptr;
        for (const auto& t : active) {
            if (!t.supersedes_token_id.empty())
                successor = &t;
            else
                predecessor = &t;
        }
        if (predecessor == nullptr || successor == nullptr || successor->rotation_group.empty() ||
            successor->rotation_group != predecessor->rotation_group ||
            successor->supersedes_token_id != predecessor->token_id) {
            error_msg = "no in-flight rotation to confirm";
            return false;
        }

        // #2384: the caller must pin the exact rotation being confirmed by
        // supplying the successor's token_id (the value rotate returned).
        // A stale id from an earlier rotation — the blind-retry hazard —
        // mismatches here and rejects before any write. Checked before the
        // initiator binding: structural mismatch is the harder failure.
        if (token_id != successor->token_id) {
            error_msg = "token_id does not match the pending rotation successor; "
                        "pass the token_id returned by rotate";
            return false;
        }

        // Hermes F4/F5: only the operator who initiated the rotation may
        // confirm it — same binding as the grace-window re-serve, but NOT
        // time-bounded to kRotationGraceSecs (see grace_entry_owner's doc
        // comment). #2961: resolve_rotation_initiator adds the durable
        // fallback so this survives a restart — see its own doc comment.
        std::optional<std::string> initiator = resolve_rotation_initiator(*successor);
        if (!initiator) {
            // #2961 fix-round finding 6: "retry via rotate" was an
            // unreachable remedy — every state that reaches this branch is
            // a live two-row pair, and a rotate call against a 2-active
            // rotation lands on the idempotent re-serve arm (grace window
            // permitting) or errors, never a fresh attempt; only revoke
            // actually resolves this. The leading substring
            // "rotation confirmation unavailable" is unchanged, so this
            // still matches engine_store_error_class.hpp's existing
            // `has("rotation confirmation unavailable")` key — no new key
            // needed.
            error_msg = "rotation confirmation unavailable — fall back to revoke";
            return false;
        }
        if (*initiator != requesting_user) {
            error_msg = "rotation in progress by a different operator";
            return false;
        }

        // #3015 PROOF OF POSSESSION — checked LAST, strictly after ownership/
        // principal-kind, pair-state, the token_id pin, and the initiator
        // binding above have all passed (see the .hpp doc comment for the
        // full rationale and the cross-admin-oracle reasoning this ordering
        // closes). Reads the AUTHORITATIVE successor row's real token_hash —
        // never the masked `''` `read_active_for_principal_on_conn`
        // populated `successor` from above — fresh, inside this same locked
        // transaction.
        std::optional<std::string> successor_hash =
            read_token_hash_by_id_on_conn(conn, successor->token_id);
        if (!successor_hash) {
            error_msg = "failed to verify rotation secret";
            return false;
        }
        if (!constant_time_hex_equal(sha256_hex(presented_secret), *successor_hash)) {
            error_msg = "rotation secret mismatch — the presented secret does not verify "
                        "against the pending successor";
            return false;
        }

        confirmed_group = successor->rotation_group;

        pg::PgResult confirm_res = pg::exec_params(
            conn,
            "UPDATE api_token_store.api_tokens SET confirmed_at = $1::bigint "
            "WHERE token_id = $2 AND revoked = FALSE RETURNING token_id",
            std::vector<std::string>{std::to_string(now), successor->token_id});
        if (confirm_res.status() != PGRES_TUPLES_OK || PQntuples(confirm_res.get()) == 0) {
            error_msg = "failed to confirm rotation";
            return false;
        }

        // Bump the revoke generation BEFORE the predecessor's revoke UPDATE
        // — same TOCTOU contract revoke_token/sweep_expired_rotations use.
        revoke_generation_.fetch_add(1, std::memory_order_release);

        pg::PgResult revoke_res = pg::exec_params(
            conn,
            "UPDATE api_token_store.api_tokens SET revoked = TRUE "
            "WHERE token_id = $1 AND revoked = FALSE RETURNING token_hash",
            std::vector<std::string>{predecessor->token_id});
        if (revoke_res.status() != PGRES_TUPLES_OK || PQntuples(revoke_res.get()) == 0) {
            error_msg = "failed to revoke predecessor on confirm";
            return false;
        }
        revoked_hash = PQgetvalue(revoke_res.get(), 0, 0);

        // #2961: also clear rotation_initiator — a resolved successor row has
        // no further use for the initiator binding (confirm is over), and on
        // the ENGINE arm that value is a third-party admin's username, so
        // this is data minimisation as well as lifecycle hygiene.
        pg::PgResult clear_res = pg::exec_params(
            conn,
            "UPDATE api_token_store.api_tokens "
            "SET rotation_group = '', supersedes_token_id = '', overlap_expires_at = 0, "
            "    rotation_initiator = '' "
            "WHERE token_id = $1 AND revoked = FALSE RETURNING token_id",
            std::vector<std::string>{successor->token_id});
        if (clear_res.status() != PGRES_TUPLES_OK || PQntuples(clear_res.get()) == 0) {
            error_msg = "failed to clear successor rotation state on confirm";
            return false;
        }

        return true;
    });

    if (!ok)
        return std::unexpected(error_msg.empty() ? "confirm failed" : error_msg);

    // Second generation bump AFTER the txn commits, before invalidating the
    // cache — the double-bump TOCTOU contract revoke_token/revoke_for_principal
    // use (#2188). Without it, a validate_token whose SELECT read the
    // pre-commit revoked=FALSE predecessor could re-populate the cache with the
    // stale row AFTER invalidate_cache ran, letting the revoked predecessor
    // validate from cache for up to kTokenCacheTtl (60s) past confirm — exactly
    // the immediate-cutover guarantee this call exists to provide.
    revoke_generation_.fetch_add(1, std::memory_order_release);
    invalidate_cache(revoked_hash);
    evict_rotation_raw(confirmed_group);
    return {};
}

// ── Human arm: token-keyed overlap-pair rotation (P2 #11, SOC 2 CC6.3) ─────
//
// See the .hpp doc comments for the full state-machine description. The
// short version: `rotate_engine_credential`/`confirm_rotation` above key on
// principal_id and arbitrate on a per-PRINCIPAL <=2-active ceiling, which is
// wrong for a human (one username, many unrelated tokens). These two
// key on the TOKEN being rotated instead, and enforce <=2 PER ROTATION
// GROUP. The advisory lock is still `hashtext(principal_id)` — the SAME key
// the engine arm and the sweep use — so all rotation activity for a shared
// principal still serializes, even across the human/engine seam.

std::expected<std::string, std::string>
ApiTokenStore::rotate_token(const std::string& predecessor_token_id, int64_t overlap_secs,
                            int64_t now, const std::string& requesting_user,
                            const std::string& caller_mcp_tier,
                            const std::string& caller_scope_service,
                            std::optional<int64_t> successor_expires_at) {
    if (!open_)
        return std::unexpected("database not open");
    if (predecessor_token_id.empty())
        return std::unexpected("token_id required");
    if (requesting_user.empty())
        return std::unexpected("requesting_user required");
    if (overlap_secs < kOverlapFloorSecs)
        return std::unexpected("overlap window below 24h floor");
    if (overlap_secs > kOverlapCeilSecs)
        return std::unexpected("overlap window exceeds the maximum (10 years)");

    // Pre-txn prep (mirrors Hermes F2 for the human arm): resolve the
    // predecessor row here, BEFORE the locked transaction opens — both to
    // derive the advisory-lock key (principal_id, taken from the row, never
    // a caller-supplied value) and to seed the speculative candidate
    // successor below. Never nested inside with_txn_for's own connection.
    std::string principal_id, predecessor_name, predecessor_scope_service, predecessor_mcp_tier;
    int64_t predecessor_expires_at = 0;
    {
        auto lease = pool_.try_acquire_for(kReadTimeout);
        if (!lease)
            return std::unexpected("database unavailable — try again");
        auto lookup = read_token_by_id_on_conn(lease.get(), predecessor_token_id);
        if (!lookup.ok)
            return std::unexpected("database unavailable — try again");
        // Self-service ONLY (deliberate asymmetry with the engine arm, where
        // requesting_user is a third-party admin by design): a human token's
        // raw successor secret authenticates AS that user, so a mismatch is
        // identity takeover, not a permission gap an admin override could
        // legitimately cross — admins already have revoke_token for that.
        // Folded into the SAME "no such token" wording the genuine-absent
        // case uses (never a distinguishable "not yours" message) so this
        // is not an ownership-enumeration oracle — same posture the human
        // DELETE route takes for a non-owner (rest_api_v1.cpp).
        if (!lookup.token || lookup.token->principal_id != requesting_user)
            return std::unexpected("no such token to rotate");
        // Authority-inheritance guard (governance Gate 7 CRITICAL fix) —
        // early-rejection MIRROR only, against this pre-lock snapshot; the
        // fresh re-read under the advisory lock below is authoritative. See
        // the header doc comment for the full rationale, and
        // caller_may_act_on_tiered_token's doc comment for the #2963
        // full-authority-caller exception. Folded into the SAME "no such
        // token to rotate" wording so this is not an authority-probing
        // oracle.
        if (!caller_may_act_on_tiered_token(lookup.token->mcp_tier, lookup.token->scope_service,
                                            caller_mcp_tier, caller_scope_service))
            return std::unexpected("no such token to rotate");
        if (lookup.token->principal_kind != "human")
            return std::unexpected("token is not a human-owned credential");
        if (lookup.token->revoked ||
            (lookup.token->expires_at != 0 && now > lookup.token->expires_at))
            return std::unexpected("credential is not currently active — nothing to rotate");
        principal_id = lookup.token->principal_id;
        predecessor_name = lookup.token->name;
        predecessor_scope_service = lookup.token->scope_service;
        predecessor_mcp_tier = lookup.token->mcp_tier;
        predecessor_expires_at = lookup.token->expires_at;
    }

    // Every local plaintext-secret slot the scrub guard below reaches is
    // declared HERE, empty, and the guard is ARMED before any of them is
    // populated — including `candidate_raw`/`candidate_hash`/
    // `candidate_token_id` below, which used to be generated first and only
    // THEN handed to the guard. `sha256_hex()`/`.substr(0,24)` allocate; a
    // `bad_alloc` in that pre-guard window would free `candidate_raw`
    // (already holding the 37-byte plaintext) unscrubbed — precisely the
    // class of hole this guard's own reasoning below argues against for
    // every OTHER exit path. Declare-then-arm-then-generate closes it.
    std::string candidate_raw, candidate_hash, candidate_token_id, candidate_error;
    std::string error_msg;
    std::string raw_out;
    std::string grace_group_out, grace_raw_out;
    // Re-serve arm's local secret + owner, hoisted to FUNCTION scope (rather
    // than declared inside the lambda below) so the scope-exit scrub guard
    // immediately below can reach `cached_raw` regardless of how the
    // transaction exits — a lambda-local variable is destroyed the moment
    // the lambda returns, before any function-scope guard could run.
    std::string cached_raw, cached_user;

    // Scrub every local plaintext secret copy, unconditionally, on EVERY
    // exit from this function from this point on — including a thrown
    // exception, which a manual call-before-every-`return` pair (a prior
    // round of this diff used exactly that shape) cannot cover.
    //   `candidate_raw`  — always speculatively generated before the txn
    //                      opens (Hermes F2); dead/unreturned on the
    //                      re-serve arm or any rejection, and redundant
    //                      (raw_out/grace_raw_out already hold their OWN
    //                      copies) even on the mint-success path.
    //   `grace_raw_out`  — a redundant duplicate of raw_out once
    //                      store_rotation_raw (below, success-only) has
    //                      copied it into the grace cache.
    //   `cached_raw`     — the re-serve arm's local copy of the SAME secret
    //                      already assigned into raw_out — redundant from
    //                      that point on.
    //   `raw_out`        — SAFE to scrub unconditionally too (round 6
    //                      review), not excluded: on the success path
    //                      `return raw_out;` below moves its contents into
    //                      the return slot before any local — including
    //                      this guard — is destroyed, so by the time this
    //                      fires raw_out is already empty (moved-from) and
    //                      the scrub is a harmless no-op (secure_zero
    //                      short-circuits on an empty string). On a
    //                      FAILURE path it can still hold a live secret —
    //                      concretely the re-serve arm's cached raw,
    //                      assigned into raw_out before `with_txn_for`'s
    //                      OWN commit can still fail on a read-only
    //                      transaction (the re-serve arm writes nothing) —
    //                      and that copy must not sit unscrubbed in this
    //                      frame just because the function is about to
    //                      discard it (the underlying cache entry / minted
    //                      row, if any, is untouched either way).
    // `rotate_engine_credential` (this file, engine arm) carries the
    // byte-identical guard, closing the gap this note used to describe as
    // future work.
    ScopeExit scrub_secrets{[&] {
        yuzu::secure_zero(candidate_raw);
        yuzu::secure_zero(grace_raw_out);
        yuzu::secure_zero(cached_raw);
        yuzu::secure_zero(raw_out);
    }};

    // Successor TTL: inherit the predecessor's absolute expires_at VERBATIM
    // (perpetual, 0, stays perpetual) unless the caller overrides it — never
    // recomputed as now+90d, which would silently extend authorization
    // lifetime. The (possibly-overridden) value is validated through the
    // same policy gate a fresh human mint uses.
    const int64_t candidate_expires_at = successor_expires_at.value_or(predecessor_expires_at);
    auto candidate_validation = validate_human_mint(predecessor_name, predecessor_scope_service,
                                                     predecessor_mcp_tier, candidate_expires_at,
                                                     now);
    if (candidate_validation.has_value()) {
        auto raw_result = generate_raw_token();
        if (raw_result.has_value()) {
            candidate_raw = std::move(*raw_result);
            candidate_hash = sha256_hex(candidate_raw);
            candidate_token_id = candidate_hash.substr(0, 24);
        } else {
            candidate_error = raw_result.error();
        }
    } else {
        candidate_error = candidate_validation.error();
    }

    // The entire check -> mint -> stamp sequence runs inside ONE transaction
    // opened with the SAME principal-scoped advisory lock
    // rotate_engine_credential/confirm_rotation/sweep take — never a
    // token-scoped lock, or a concurrent rotate for a DIFFERENT token owned
    // by the same principal could race this one.
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult lock_res =
            pg::exec_params(conn, "SELECT pg_advisory_xact_lock(hashtext($1))",
                            std::vector<std::string>{principal_id});
        if (lock_res.status() != PGRES_TUPLES_OK) {
            error_msg = "failed to acquire rotation lock";
            return false;
        }

        // Fresh re-read of the pinned predecessor row, under the lock —
        // never the pre-txn snapshot above.
        auto lookup = read_token_by_id_on_conn(conn, predecessor_token_id);
        if (!lookup.ok) {
            // Ambiguous with a swallowed read failure — mirrors the engine
            // arm's 0-active rejection wording, which classifies Transient
            // for exactly this reason.
            error_msg = "no active credential to rotate — mint one first";
            return false;
        }
        // Self-service ONLY — same rationale + same indistinguishable-from-
        // absent wording as the pre-txn check above; re-asserted here
        // because this is the AUTHORITATIVE read (never trust the pre-lock
        // snapshot for the write decision).
        if (!lookup.token || lookup.token->principal_id != requesting_user) {
            error_msg = "no such token to rotate";
            return false;
        }
        // Authority-inheritance guard (governance Gate 7 CRITICAL fix,
        // AUTHORITATIVE — see the header doc comment): rotation must never
        // mint authority the caller does not already hold. mcp_tier/
        // scope_service are copied VERBATIM into the successor, and the
        // predecessor is caller-chosen, so without this an operator-tier
        // caller could rotate their own untiered sibling token into a
        // fresh untiered/perpetual credential. Equality against the FRESH
        // under-lock read, never a "no-broader-than" ordering (deliberate
        // — needs no tier-lattice assumption), EXCEPT the single #2963
        // full-authority-caller case caller_may_act_on_tiered_token
        // carves out (a caller with NO standing tier/scope authority
        // already holds a superset of any tiered/scoped token, so it may
        // rotate one it owns — the successor still inherits the token's
        // OWN narrower tier/scope, never the caller's). Folded into the
        // SAME "no such token to rotate" wording as the absence/ownership
        // checks above so this is not an authority-probing oracle.
        if (!caller_may_act_on_tiered_token(lookup.token->mcp_tier, lookup.token->scope_service,
                                            caller_mcp_tier, caller_scope_service)) {
            error_msg = "no such token to rotate";
            return false;
        }
        const ApiToken& predecessor = *lookup.token;
        if (predecessor.principal_kind != "human") {
            error_msg = "token is not a human-owned credential";
            return false;
        }
        if (predecessor.revoked || (predecessor.expires_at != 0 && now > predecessor.expires_at)) {
            error_msg = "credential is not currently active — nothing to rotate";
            return false;
        }

        if (predecessor.rotation_group.empty()) {
            // ── Mint arm: no rotation in flight for THIS token yet ────────
            const int64_t window_end = now + overlap_secs;
            if (predecessor.expires_at != 0 && window_end > predecessor.expires_at) {
                error_msg = "overlap window would exceed the predecessor credential's expiry";
                return false;
            }
            if (candidate_expires_at != 0 && window_end > candidate_expires_at) {
                error_msg = "overlap window would exceed the successor credential's expiry";
                return false;
            }
            if (!candidate_error.empty()) {
                error_msg = candidate_error;
                return false;
            }

            pg::PgResult ins = pg::exec_params(
                conn,
                "INSERT INTO api_token_store.api_tokens "
                "(token_id, token_hash, name, principal_id, scope_service, mcp_tier, "
                " principal_kind, created_at, expires_at, rotation_group, supersedes_token_id, "
                " rotation_initiator) "
                "VALUES ($1,$2,$3,$4,$5,$6,'human',$7::bigint,$8::bigint,$9,$10,$11) "
                "RETURNING token_id",
                std::vector<std::string>{candidate_token_id, candidate_hash, predecessor.name,
                                         principal_id, predecessor.scope_service,
                                         predecessor.mcp_tier, std::to_string(now),
                                         std::to_string(candidate_expires_at), candidate_token_id,
                                         predecessor.token_id, requesting_user});
            if (ins.status() != PGRES_TUPLES_OK || PQntuples(ins.get()) == 0) {
                error_msg = "failed to mint successor credential";
                return false;
            }

            pg::PgResult r2 = pg::exec_params(
                conn,
                "UPDATE api_token_store.api_tokens "
                "SET rotation_group = $1, overlap_expires_at = $2::bigint "
                "WHERE token_id = $3 AND revoked = FALSE RETURNING token_id",
                std::vector<std::string>{candidate_token_id, std::to_string(now + overlap_secs),
                                         predecessor.token_id});
            if (r2.status() != PGRES_TUPLES_OK || PQntuples(r2.get()) == 0) {
                error_msg = "failed to stamp predecessor overlap window";
                return false;
            }

            raw_out = candidate_raw;
            grace_group_out = candidate_token_id;
            grace_raw_out = candidate_raw;
            // Test-only seam (round 4 regression): let a test force the
            // COMMIT that follows this `return true` to fail, and assert
            // store_rotation_raw below never ran for this attempt.
            if (test_hook_before_mint_commit_)
                test_hook_before_mint_commit_(conn);
            return true;
        }

        // ── Re-serve / conflict arm: predecessor already stamped ─────────
        // <=2 enforced PER ROTATION GROUP, never per principal (invariant
        // #3 — a human's other, unrelated active tokens must never count
        // against this ceiling). Reuses the PRINCIPAL-WIDE read + in-memory
        // filter — the SAME pattern confirm_token_rotation uses via
        // classify_confirm_state_in_group, and the SAME reason: a
        // group-scoped SQL query's own zero-row result is indistinguishable
        // from a swallowed SELECT failure, which is exactly the trap the
        // "GROUP-FILTERING NOTE" in rotation_confirm_state.hpp warns against
        // reintroducing. Filtering an already-fetched, non-empty
        // principal-wide read is positive evidence the query itself
        // succeeded; a group-scoped-only read has no such evidence to lean
        // on.
        if (test_hook_before_rotate_group_read_)
            test_hook_before_rotate_group_read_(conn);
        auto principal_active = read_active_for_principal_on_conn(conn, principal_id, now);
        if (principal_active.empty()) {
            // Ambiguous with a swallowed read failure — predecessor is
            // known-active (checked above, under this same advisory lock,
            // moments ago), so a genuinely empty read here can only mean
            // the SELECT failed. Reuses the SAME wording — and Transient
            // classification — the pre-mint lookup-failure branch above
            // uses for the identical ambiguity; never the terminal
            // "not a recognized rotation pair" conflict below.
            error_msg = "no active credential to rotate — mint one first";
            return false;
        }
        for (const auto& t : principal_active) {
            if (t.principal_kind != "human") {
                error_msg = "principal has a non-human active credential";
                return false;
            }
        }
        std::vector<ApiToken> in_group;
        for (const auto& t : principal_active)
            if (t.rotation_group == predecessor.rotation_group)
                in_group.push_back(t);
        if (in_group.size() > 2) {
            error_msg = "more than two active credentials for this principal — "
                       "resolve manually before rotating";
            return false;
        }
        const ApiToken* pred_row = nullptr;
        const ApiToken* succ_row = nullptr;
        for (const auto& t : in_group) {
            if (!t.supersedes_token_id.empty())
                succ_row = &t;
            else
                pred_row = &t;
        }
        if (in_group.size() != 2 || pred_row == nullptr || succ_row == nullptr ||
            succ_row->rotation_group != pred_row->rotation_group ||
            succ_row->supersedes_token_id != pred_row->token_id) {
            error_msg = "two active credentials not in a recognized rotation pair — "
                       "resolve via revoke, not rotate";
            return false;
        }

        if (now - succ_row->created_at > kRotationGraceSecs.count()) {
            error_msg = "rotation grace window elapsed; confirm or revoke";
            return false;
        }

        // `cached_raw`/`cached_user` are the FUNCTION-scope variables
        // declared above (captured by reference) — never lambda-local, so
        // the scope-exit scrub guard above can reach `cached_raw` on every
        // exit from `rotate_token`, not just this lambda's return.
        if (!try_reserve(succ_row->rotation_group, cached_raw, cached_user)) {
            error_msg = "rotation grace window elapsed; confirm or revoke";
            return false;
        }
        if (cached_user != requesting_user) {
            error_msg = "rotation in progress by a different operator";
            return false;
        }

        raw_out = cached_raw;
        return true;
    });

    if (!ok)
        return std::unexpected(error_msg.empty() ? "rotation failed" : error_msg);

    // Cache the raw secret + initiating operator for the grace window AFTER
    // the mint committed — mirrors rotate_engine_credential's ordering
    // exactly (this file, engine arm) and for the SAME reason: `with_txn_for`
    // (`pool_.with_txn_for` -> `PgPool::run_in_txn`, pg/pg_pool.cpp) can still
    // return false AFTER this callback returned true — a COMMIT failure
    // (`PgTxn::commit()`, pg/pg_raii.hpp, false when COMMIT != PGRES_COMMAND_OK)
    // or the aborted-transaction refusal ahead of it. Caching BEFORE checking
    // `ok` would insert a grace-cache entry keyed to a `candidate_token_id`
    // with NO committed row — permanently unevictable, since
    // `evict_rotation_raw` fires only on confirm-success or the sweep
    // resolving a pair, both of which require a committed row to exist at
    // all; `scrub_elapsed_grace_secrets` zeroes the entry's `raw` past the
    // grace window but deliberately never erases the entry itself. The
    // one-time-reveal contract's "once" means once per grace-bounded
    // rotation ATTEMPT that actually committed (§7), so a bounded retry BY
    // THE SAME OPERATOR can re-serve this exact value.
    //
    // #2961 fix-round finding 2: same re-check as rotate_engine_credential's
    // mirror-image call site — the mint's advisory lock is already released
    // here, so a confirm/sweep/revoke-partner-clear for this rotation group
    // can resolve the pair, via the durable rotation_initiator column this
    // same commit just wrote, before this cache write runs. See
    // successor_rotation_still_pending's doc comment.
    if (!grace_group_out.empty()) {
        if (test_hook_before_store_rotation_raw_)
            test_hook_before_store_rotation_raw_();
        if (successor_rotation_still_pending(grace_group_out))
            store_rotation_raw(grace_group_out, grace_raw_out, requesting_user);
    }

    return raw_out;
}

std::expected<void, std::string>
ApiTokenStore::confirm_token_rotation(const std::string& successor_token_id,
                                      const std::string& presented_secret,
                                      const std::string& requesting_user,
                                      const std::string& caller_mcp_tier,
                                      const std::string& caller_scope_service) {
    if (!open_)
        return std::unexpected("database not open");
    if (successor_token_id.empty())
        return std::unexpected("token_id required");
    if (presented_secret.empty())
        return std::unexpected("secret required");
    if (requesting_user.empty())
        return std::unexpected("requesting_user required");

    // Pre-txn prep: resolve principal_id from the pinned row — the advisory
    // lock key — before opening the locked transaction. Never nested inside
    // with_txn_for's own connection.
    std::string principal_id;
    {
        auto lease = pool_.try_acquire_for(kReadTimeout);
        if (!lease)
            return std::unexpected("database unavailable — try again");
        auto lookup = read_token_by_id_on_conn(lease.get(), successor_token_id);
        if (!lookup.ok)
            return std::unexpected("database unavailable — try again");
        // Self-service ONLY — same rationale as rotate_token: confirming
        // someone else's rotation would let a non-owner complete a cutover
        // of a credential that authenticates AS that user. Folded into the
        // SAME "no such token" wording the genuine-absent case uses.
        if (!lookup.token || lookup.token->principal_id != requesting_user)
            return std::unexpected("no such token to confirm");
        if (lookup.token->principal_kind != "human")
            return std::unexpected("token is not a human-owned credential");
        principal_id = lookup.token->principal_id;
    }

    const int64_t now = now_epoch();
    std::string error_msg;
    std::string revoked_hash;
    std::string confirmed_group;

    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult lock_res =
            pg::exec_params(conn, "SELECT pg_advisory_xact_lock(hashtext($1))",
                            std::vector<std::string>{principal_id});
        if (lock_res.status() != PGRES_TUPLES_OK) {
            error_msg = "failed to acquire rotation lock";
            return false;
        }

        // Fresh re-read of the pinned row, under the lock — never the
        // pre-txn snapshot above.
        auto lookup = read_token_by_id_on_conn(conn, successor_token_id);
        if (!lookup.ok) {
            error_msg = "no in-flight rotation to confirm";
            return false;
        }
        // Self-service ONLY, re-asserted here as the AUTHORITATIVE read —
        // same rationale + same indistinguishable-from-absent wording as
        // the pre-txn check above.
        if (!lookup.token || lookup.token->principal_id != requesting_user) {
            error_msg = "no such token to confirm";
            return false;
        }
        // DEFENCE IN DEPTH ONLY (governance Gate 7 fix) — mirrors
        // rotate_token's authority-inheritance guard, but the successor's
        // tier/scope are fixed at mint time and cannot legitimately
        // diverge from what the caller who initiated the rotation already
        // held, so rotate_token's own guard is the load-bearing one; this
        // catches only a hypothetical future bypass of it, never a live
        // path today. Uses the SAME caller_may_act_on_tiered_token
        // exception as rotate_token (#2963) — a full-authority caller that
        // successfully rotated a tiered token must also be able to
        // confirm it, or the two calls would disagree on the identical
        // caller/token pair. Same "no such token" wording for the same
        // reason.
        if (!caller_may_act_on_tiered_token(lookup.token->mcp_tier, lookup.token->scope_service,
                                            caller_mcp_tier, caller_scope_service)) {
            error_msg = "no such token to confirm";
            return false;
        }
        const ApiToken& pinned = *lookup.token;
        if (pinned.principal_kind != "human") {
            error_msg = "token is not a human-owned credential";
            return false;
        }
        if (pinned.rotation_group.empty()) {
            // Deliberately NOT the engine arm's verbatim kSoleOtherToken
            // wording ("...the rotation was resolved (confirmed, revoked, or
            // cut over)..." — see confirm_rotation above): that IS the
            // correct fact pattern to describe here too (this row was
            // resolved — confirmed, revoked, or cut over — or never rotated
            // at all), but reusing that string byte-for-byte would make this
            // site's classification a silent, parasitic side effect of the
            // engine arm's entry rather than an explicit decision of its own
            // (round-4 review). Own wording, own classifier entry — same
            // Conflict class as the engine arm reaches for the analogous
            // state (see engine_store_error_class.hpp's dedicated rationale;
            // round 5 corrected an earlier, refuted Transient
            // classification of this exact string).
            error_msg = "no rotation currently pending for the supplied token_id — nothing "
                        "to confirm; call rotate again if a new rotation is needed";
            return false;
        }
        const std::string rotation_group = pinned.rotation_group;

        // UP-6, group-aware sibling (rotation_confirm_state.hpp): reuses the
        // SAME principal-wide read (never a group-scoped SQL query, which
        // would reintroduce the read-vs-failure ambiguity in a new place),
        // filtering it in memory.
        auto principal_active = read_active_for_principal_on_conn(conn, principal_id, now);
        for (const auto& t : principal_active) {
            if (t.principal_kind != "human") {
                error_msg = "principal has a non-human active credential";
                return false;
            }
        }

        switch (detail::classify_confirm_state_in_group(principal_active, rotation_group)) {
        case detail::GroupRotationConfirmState::kAmbiguousEmpty:
            error_msg = "no in-flight rotation to confirm";
            return false;
        case detail::GroupRotationConfirmState::kOverfullGroup:
            error_msg = "more than two active credentials for this principal - "
                        "resolve manually before confirming";
            return false;
        case detail::GroupRotationConfirmState::kGroupEmpty:
            // Same state, same wording, and same rationale as the
            // `pinned.rotation_group.empty()` short-circuit above — this is
            // the fresh-under-lock re-confirmation of that same fact (the
            // group had nothing active left) reached via the classifier
            // instead. A POSITIVE fact (see classify_confirm_state_in_group's
            // own doc comment), so Conflict, never Transient — same
            // classifier entry as the short-circuit above; see that
            // comment's fuller rationale.
            error_msg = "no rotation currently pending for the supplied token_id — nothing "
                        "to confirm; call rotate again if a new rotation is needed";
            return false;
        case detail::GroupRotationConfirmState::kUnresolvedSoleInGroup:
            error_msg = "one active credential with unresolved rotation metadata - "
                        "inspect the credential state and do not rotate; revoke only "
                        "if it is confirmed stale";
            return false;
        case detail::GroupRotationConfirmState::kPairInGroup:
            break; // exactly two in-group -> fall through to pair processing below
        }

        const ApiToken* predecessor = nullptr;
        const ApiToken* successor = nullptr;
        for (const auto& t : principal_active) {
            if (t.rotation_group != rotation_group)
                continue;
            if (!t.supersedes_token_id.empty())
                successor = &t;
            else
                predecessor = &t;
        }
        if (predecessor == nullptr || successor == nullptr ||
            successor->supersedes_token_id != predecessor->token_id) {
            // #2943: TERMINAL, not retryable. We only reach here after
            // `classify_confirm_state_in_group` returned `kPairInGroup` — a
            // POSITIVE read of exactly two active rows in this group, never
            // the ambiguous 0-active case. So the #2404 positive-read
            // exemption applies exactly as it does to `kGroupEmpty`,
            // `kUnresolvedSoleInGroup` and the pin mismatch: the read
            // succeeded, the state is simply unresolvable without an
            // operator.
            //
            // Do NOT reuse "no in-flight rotation to confirm" here. That
            // string is deliberately keyed Transient in
            // `engine_store_error_class.hpp` for the AMBIGUOUS read, where a
            // swallowed query failure and a genuinely empty set are
            // indistinguishable — retrying is right there and wrong here. An
            // agentic client retries a malformed pair forever; it cannot fix
            // itself.
            error_msg = "rotation pair is malformed — confirm cannot proceed; "
                        "revoke one side explicitly";
            return false;
        }

        // #2384-equivalent pin: the caller must supply the exact successor
        // token_id rotate returned.
        if (successor->token_id != successor_token_id) {
            error_msg = "token_id does not match the pending rotation successor; "
                        "pass the token_id returned by rotate";
            return false;
        }

        // Same operator-initiator binding as confirm_rotation (Hermes F4/F5),
        // including the #2961 durable fallback (resolve_rotation_initiator).
        std::optional<std::string> initiator = resolve_rotation_initiator(*successor);
        if (!initiator) {
            // #2961 fix-round finding 6: "retry via rotate" was an
            // unreachable remedy — every state that reaches this branch is
            // a live two-row pair, and a rotate call against a 2-active
            // rotation lands on the idempotent re-serve arm (grace window
            // permitting) or errors, never a fresh attempt; only revoke
            // actually resolves this. The leading substring
            // "rotation confirmation unavailable" is unchanged, so this
            // still matches engine_store_error_class.hpp's existing
            // `has("rotation confirmation unavailable")` key — no new key
            // needed.
            error_msg = "rotation confirmation unavailable — fall back to revoke";
            return false;
        }
        if (*initiator != requesting_user) {
            error_msg = "rotation in progress by a different operator";
            return false;
        }

        // #3015 PROOF OF POSSESSION — same ordering/oracle-freedom rationale
        // as confirm_rotation above: checked LAST, strictly after ownership,
        // pair-state, the token_id pin, tier/scope, and the initiator
        // binding have all passed. Reads the AUTHORITATIVE successor row's
        // real token_hash — never the masked `''` `principal_active`
        // populated `successor` from above — fresh, inside this same locked
        // transaction.
        std::optional<std::string> successor_hash =
            read_token_hash_by_id_on_conn(conn, successor->token_id);
        if (!successor_hash) {
            error_msg = "failed to verify rotation secret";
            return false;
        }
        if (!constant_time_hex_equal(sha256_hex(presented_secret), *successor_hash)) {
            error_msg = "rotation secret mismatch — the presented secret does not verify "
                        "against the pending successor";
            return false;
        }

        confirmed_group = rotation_group;

        pg::PgResult confirm_res = pg::exec_params(
            conn,
            "UPDATE api_token_store.api_tokens SET confirmed_at = $1::bigint "
            "WHERE token_id = $2 AND revoked = FALSE RETURNING token_id",
            std::vector<std::string>{std::to_string(now), successor->token_id});
        if (confirm_res.status() != PGRES_TUPLES_OK || PQntuples(confirm_res.get()) == 0) {
            error_msg = "failed to confirm rotation";
            return false;
        }

        // Bump the revoke generation BEFORE the predecessor's revoke UPDATE
        // — same TOCTOU contract confirm_rotation/revoke_token use.
        revoke_generation_.fetch_add(1, std::memory_order_release);

        pg::PgResult revoke_res = pg::exec_params(
            conn,
            "UPDATE api_token_store.api_tokens SET revoked = TRUE "
            "WHERE token_id = $1 AND revoked = FALSE RETURNING token_hash",
            std::vector<std::string>{predecessor->token_id});
        if (revoke_res.status() != PGRES_TUPLES_OK || PQntuples(revoke_res.get()) == 0) {
            error_msg = "failed to revoke predecessor on confirm";
            return false;
        }
        revoked_hash = PQgetvalue(revoke_res.get(), 0, 0);

        // #2961: also clear rotation_initiator — see confirm_rotation's
        // matching comment.
        pg::PgResult clear_res = pg::exec_params(
            conn,
            "UPDATE api_token_store.api_tokens "
            "SET rotation_group = '', supersedes_token_id = '', overlap_expires_at = 0, "
            "    rotation_initiator = '' "
            "WHERE token_id = $1 AND revoked = FALSE RETURNING token_id",
            std::vector<std::string>{successor->token_id});
        if (clear_res.status() != PGRES_TUPLES_OK || PQntuples(clear_res.get()) == 0) {
            error_msg = "failed to clear successor rotation state on confirm";
            return false;
        }

        return true;
    });

    if (!ok)
        return std::unexpected(error_msg.empty() ? "confirm failed" : error_msg);

    // Second generation bump AFTER the txn commits, before invalidating the
    // cache — same double-bump TOCTOU contract confirm_rotation uses.
    revoke_generation_.fetch_add(1, std::memory_order_release);
    invalidate_cache(revoked_hash);
    evict_rotation_raw(confirmed_group);
    return {};
}

// ── T12: rotation maintenance sweep (design doc §7) ─────────────────────────

ApiTokenStore::SweepResult ApiTokenStore::sweep_expired_rotations(int64_t now) {
    SweepResult result;
    // `fail` is the ONE place every post-connection `Failed` outcome is
    // produced from here down, so every site logs the actual libpq error
    // text and carries it in `SweepResult::fail_reason` for the caller —
    // mirrors `decline_reason`'s role for the `Declined` outcome. This
    // distinguishes a permanent schema defect (e.g. a missing
    // `rotation_retention_meta` table from a botched migration-number
    // reconciliation, #3013 — this branch's own NUMBERING NOTE above warns
    // of the collision that produces it) from a one-off transient pool
    // blip, which a shared generic "pool contention / query failure" log
    // text would not.
    auto fail = [&](const char* stage, PGconn* conn) {
        const std::string detail = PQerrorMessage(conn);
        spdlog::error("[{}] sweep_expired_rotations: {} failed: {}", kStoreName, stage, detail);
        result.outcome = SweepOutcome::Failed;
        result.fail_reason = std::string(stage) + ": " + detail;
    };
    if (!open_) {
        result.outcome = SweepOutcome::Failed;
        result.fail_reason = "store not open";
        spdlog::error("[{}] sweep_expired_rotations: store not open — declining the tick",
                      kStoreName);
        return result;
    }

    // Secret-hygiene half, RAM-only (no DB round trip): scrub any
    // grace-cache `raw` past its raw-reveal window before the DB-side
    // auto-revoke half below. Runs every tick regardless of whether this
    // tick finds any expired predecessors.
    scrub_elapsed_grace_secrets();

    // Sanitise the CALLER's clock the same way every other clock-guarded
    // store in this codebase does (`AuditStore::cleanup_once`,
    // `ResultSetStore::gc_sweep`) — UPPER bound only, a negative reading is
    // the legitimate dead-CMOS case this whole guard exists for. `now` does
    // NOT drive the eligibility decision (part 2 below reads PostgreSQL's
    // own clock instead) and, honestly, does nothing else either — it
    // reaches no arithmetic beyond this comparison and stamps no liveness
    // signal (the sweep's actual liveness signal,
    // `rotation_sweep_last_pass_now()`, reads the durable `rotation_
    // retention_meta.last_pass_now` PostgreSQL itself last wrote — see that
    // accessor). This check is kept anyway because it is cheap and catches
    // a plainly malformed caller argument before it can reach a log line.
    if (now > kMaxPlausibleNow) {
        spdlog::warn("[{}] sweep_expired_rotations: called with an implausible clock reading "
                    "({}) — declining the tick",
                    kStoreName, now);
        result.outcome = SweepOutcome::Failed;
        result.fail_reason = "implausible caller clock reading";
        return result;
    }

    // ── Global sweep lock: a NEW store-wide SESSION advisory lock, its own
    // key namespace — never `hashtext(principal_id)`, the per-PRINCIPAL key
    // every rotate/confirm/per-row-revoke call below takes. SESSION, not
    // TRANSACTION-scoped: it must survive across the classification
    // transaction below AND the up-to-200 separate per-pair transactions
    // that follow it, on OTHER connections, for the whole call. Acquired
    // with a bounded TRY on one leased connection.
    //
    // POOL-SIZE FLOOR: `lease` below is held for the ENTIRE function body,
    // including the up-to-200 per-pair
    // `pool_.with_txn_for` calls further down — each of THOSE acquires its
    // own, SECOND connection from this same pool while `lease` is still
    // held. A pool configured with fewer than 2 connections can therefore
    // never make forward progress here: every per-pair `with_txn_for` would
    // time out acquiring against the one connection already pinned by this
    // session lock. This is a deliberate consequence of the LOCKING SHAPE
    // documented on this method in the header (the lock must be session-,
    // not transaction-scoped, and held across the per-pair revokes — not an
    // oversight to "fix" by releasing `lease` earlier), not a hazard in
    // practice today (production pool 16, test fixtures 4, and the only
    // size-1 pool in this codebase never runs this sweep).
    // ONE definition of this lock's key, generating matching try-lock/unlock
    // SQL (`pg::PgAdvisoryLockKey`) — a hand-written pair of string
    // constants could drift (a drift unlocks a
    // key never locked; Postgres reports `false`, and the release guard
    // treats `false` as "released" — a silent leak of the key actually
    // held).
    static const pg::PgAdvisoryLockKey kRotationSweepLockKey =
        pg::PgAdvisoryLockKey::single("hashtextextended('api_token_store:rotation_sweep', 0)");
    const std::string lock_label = std::string(kStoreName) + " rotation sweep";

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        result.outcome = SweepOutcome::Failed;
        result.fail_reason = "connection pool exhausted: " + pool_.last_error();
        spdlog::error("[{}] sweep_expired_rotations: could not acquire a connection for the "
                      "store-wide sweep lock (pool exhausted): {}",
                      kStoreName, pool_.last_error());
        return result;
    }
    const std::string rotation_sweep_try_lock_sql = kRotationSweepLockKey.try_lock_sql();
    pg::PgResult lock_probe =
        pg::exec_params(lease.get(), rotation_sweep_try_lock_sql.c_str(), std::vector<std::string>{});
    // Defence-in-depth row-shape guard (mirrors `kek_op_lock.hpp`'s
    // `try_lock_kek_op`): `PQgetvalue` returns nullptr out-of-range, and
    // `to_bool` quietly treats that as `false` rather than surfacing a
    // malformed result shape as the fault it actually is.
    if (lock_probe.status() != PGRES_TUPLES_OK || PQntuples(lock_probe.get()) != 1 ||
        PQgetisnull(lock_probe.get(), 0, 0)) {
        // We could not read whether the try-lock was granted, so we do NOT
        // know if the server actually gave us the lock. Unlocking a lock we
        // never held is a harmless no-op; skipping the release when it WAS
        // granted leaves a lock-holding connection to return to the pool
        // and wedges every future sweep on this key permanently — same
        // defensive-release rationale as `try_lock_kek_op`'s `kError` caller.
        pg::PgSessionAdvisoryLockGuard release_if_held{lease.get(), kRotationSweepLockKey,
                                                       lock_label};
        fail("sweep-lock try-lock probe", lease.get());
        return result;
    }
    if (!to_bool(PQgetvalue(lock_probe.get(), 0, 0))) {
        result.outcome = SweepOutcome::SkippedLock; // another replica is sweeping — routine
        return result;
    }

    // Exception-safe RAII release, BEFORE the connection returns to the
    // pool: a leaked SESSION advisory lock — unlike the per-PRINCIPAL
    // `pg_advisory_xact_lock` this same file's rotate/confirm/per-row-revoke
    // paths use, which is transaction-scoped and self-releases at
    // COMMIT/ROLLBACK — persists on the connection until explicitly
    // unlocked or the connection closes, so a leak here wedges every future
    // sweep on this key permanently. `pg::PgSessionAdvisoryLockGuard`
    // (`pg/pg_session_advisory_lock.hpp`) is the same reusable release
    // protocol `KekOpLockGuard` uses.
    //
    // `unlock_guard` is declared before `pg::PgTxn txn` below, so
    // reverse-destruction-order guarantees `~PgTxn`'s ROLLBACK always runs
    // before the unlock attempt, leaving the connection clean every time —
    // an aborted-transaction unlock failure is therefore not reachable at
    // THIS call site. That ordering is UNPINNED (nothing enforces it, and a
    // future edit could silently break it), which is why this uses the
    // shared guard rather than a hand-rolled release tied to declaration
    // order. See `pg_session_advisory_lock.hpp`'s own file header for the
    // full account of the guard's release protocol.
    pg::PgSessionAdvisoryLockGuard unlock_guard{lease.get(), kRotationSweepLockKey, lock_label};

    // ── Classification transaction: PG-authoritative clock, durable meta
    // read/write, the clock-guard's five-fact decision, and — if accepted —
    // the candidate SELECT. All ONE transaction, on the SAME connection
    // that holds the session lock above (never `pool_.with_txn_for`, which
    // would acquire a SECOND connection and self-deadlock a size-1 pool).
    PGconn* conn = lease.get();
    pg::PgResult begin = pg::exec_params(conn, "BEGIN", std::vector<std::string>{});
    if (begin.status() != PGRES_COMMAND_OK) {
        fail("BEGIN classification transaction", conn);
        return result;
    }
    pg::PgTxn txn(conn);

    // Part 2 (routed concern): PostgreSQL's OWN clock drives every decision
    // below, not the caller's `now` — the same reasoning
    // `AuditStore::cleanup_once` documents (N replicas comparing against N
    // independently-drifting process clocks can alternate distinct
    // verdicts forever; PG is the one authority every sweeper already
    // serialises through, via the session lock above).
    pg::PgResult clk =
        pg::exec_params(conn, "SELECT EXTRACT(EPOCH FROM now())::bigint", std::vector<std::string>{});
    // Defence-in-depth row-shape guard (mirrors `kek_op_lock.hpp:50`): a
    // scalar single-row read that trusted `status() == PGRES_TUPLES_OK`
    // alone would still call `PQgetvalue` on a zero-row/NULL result if the
    // query's shape ever drifted, and `to_i64` quietly treats an
    // out-of-range/NULL `PQgetvalue` as `0` rather than surfacing it.
    if (clk.status() != PGRES_TUPLES_OK || PQntuples(clk.get()) != 1 || PQgetisnull(clk.get(), 0, 0)) {
        fail("PostgreSQL clock read", conn);
        return result;
    }
    const std::int64_t pg_now = to_i64(PQgetvalue(clk.get(), 0, 0));
    if (pg_now > kMaxPlausibleNow) {
        spdlog::error("[{}] sweep_expired_rotations: PostgreSQL's own clock reading ({}) is "
                      "implausible — declining the tick",
                      kStoreName, pg_now);
        result.outcome = SweepOutcome::Failed;
        result.fail_reason = "implausible PostgreSQL clock reading";
        return result;
    }

    // Durable dedup state (shared across replicas + restarts) — mirrors
    // `audit_store.audit_retention_meta`.
    pg::PgResult meta = pg::exec_params(
        conn,
        "SELECT key, value FROM api_token_store.rotation_retention_meta WHERE key IN "
        "('last_pass_now','last_anomaly_facts','bootstrap_settled')",
        std::vector<std::string>{});
    if (meta.status() != PGRES_TUPLES_OK) {
        // This is the site that fails with libpq's `relation
        // "api_token_store.rotation_retention_meta" does not exist` when
        // the table is missing (e.g. a botched migration-number
        // reconciliation, #3013) — a permanent schema defect, not a
        // transient fault; `fail()` carries that specific text to the
        // caller rather than a generic "pool contention / query failure"
        // label.
        fail("durable meta read", conn);
        return result;
    }
    std::optional<std::int64_t> prev;
    bool prev_unusable = false;
    std::string last_facts;
    bool bootstrap_settled = false;
    for (int i = 0; i < PQntuples(meta.get()); ++i) {
        const std::string key = col(meta.get(), i, 0);
        const std::string val = col(meta.get(), i, 1);
        if (key == "last_pass_now") {
            if (const auto parsed = parse_meta_i64(val)) // part 3: sanitise the persisted reading
                prev = *parsed;
            else
                prev_unusable = true; // unparseable — an anomaly, never a quiet reset
        } else if (key == "last_anomaly_facts") {
            last_facts = val;
        } else if (key == "bootstrap_settled") {
            bootstrap_settled = true;
        }
    }
    // Part 3: ahead-of-now or negative cannot be reasoned about — decline.
    if (prev && (*prev < 0 || *prev > pg_now)) {
        prev_unusable = true;
        prev.reset();
    }

    // Re-anchor BEFORE any early return — a decline still updates the
    // comparison point, so a poisoned value self-heals on the next pass.
    pg::PgResult stamp = pg::exec_params(
        conn,
        "INSERT INTO api_token_store.rotation_retention_meta (key, value) VALUES "
        "('last_pass_now', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        std::vector<std::string>{std::to_string(pg_now)});
    if (stamp.status() != PGRES_COMMAND_OK) {
        fail("durable meta re-anchor stamp", conn);
        return result;
    }

    // Eligibility probe, over the ELIGIBLE set only (never every
    // syntactically-elapsed predecessor — a UP-5 never-used-successor pair
    // is PERMANENTLY ineligible and plays no part in this decision).
    // `kRotationEligiblePredicate` is the SAME predicate the candidate
    // SELECT below uses — one definition, so the two can never drift apart.
    // NO would-wipe half here — see the DELIBERATE NON-ADOPTION comment
    // above `kRotationSweepBigStepSecs`'s definition for why this store does
    // not adopt routed-concern part 1's would-wipe probe; `has_expired`
    // alone is all this store's eligibility probe computes.
    const std::string probe_sql = "SELECT EXISTS(SELECT 1 FROM api_token_store.api_tokens WHERE " +
                                  std::string(kRotationEligiblePredicate) +
                                  " AND overlap_expires_at <= $1::bigint)";
    pg::PgResult probe =
        pg::exec_params(conn, probe_sql.c_str(), std::vector<std::string>{std::to_string(pg_now)});
    // Defence-in-depth row-shape guard (mirrors `kek_op_lock.hpp:50`) —
    // `to_bool` quietly treats an out-of-range `PQgetvalue` as `false`
    // rather than surfacing a malformed result shape as a fault.
    if (probe.status() != PGRES_TUPLES_OK || PQntuples(probe.get()) != 1 ||
        PQgetisnull(probe.get(), 0, 0)) {
        fail("eligibility probe", conn);
        return result;
    }
    const bool has_expired = to_bool(PQgetvalue(probe.get(), 0, 0));
    // Deliberately hardcoded `false` — see the DELIBERATE NON-ADOPTION
    // comment above (where `kMinWipeProbePopulation` used to live) for why
    // this store does not adopt routed-concern part 1's would-wipe half.
    constexpr bool would_wipe = false;
    // Part 7: ABSOLUTE threshold, never scaled to any window — this store
    // has no retention window to scale against in the first place, only a
    // tick cadence (60s, `server.cpp`). A gap this large since the last
    // pass to reach a verdict is itself remarkable at that cadence, whether
    // the cause is a genuine multi-hour outage or a clock jump; either way
    // it warrants a decline+report rather than a silent drain.
    const bool big_step = prev.has_value() && has_expired &&
                          audit_retention::moved_at_least(*prev, pg_now, kRotationSweepBigStepSecs) &&
                          pg_now > *prev;

    const audit_retention::Facts facts{.has_expired = has_expired,
                                       .would_wipe = would_wipe,
                                       .big_step = big_step,
                                       .prev_unusable = prev_unusable,
                                       .no_anchor = !bootstrap_settled};
    const audit_retention::Anomaly anomaly = audit_retention::classify(facts);
    const std::string facts_ser = serialize_rotation_facts(facts);

    // The pass has now reached a VERDICT — settle the bootstrap marker HERE
    // (not at the re-anchor above), so a pass whose probes fail leaves the
    // trigger armed rather than spending it without ever classifying
    // anything (mirrors `AuditStore::cleanup_once`'s #2579 fix).
    if (!bootstrap_settled) {
        pg::PgResult settle = pg::exec_params(
            conn,
            "INSERT INTO api_token_store.rotation_retention_meta (key, value) VALUES "
            "('bootstrap_settled', '1') ON CONFLICT (key) DO NOTHING",
            std::vector<std::string>{});
        if (settle.status() != PGRES_COMMAND_OK) {
            fail("bootstrap-settled marker write", conn);
            return result;
        }
    }

    if (anomaly != audit_retention::Anomaly::None) {
        // Part 4: decline-once per DISTINCT fact SET (never a latch bool,
        // never the classified enum) — a new anomaly declines and records;
        // an identical repeat is suppressed and drains, paced by the cap,
        // so a legitimately all-expired backlog still ages out.
        if (facts_ser != last_facts) {
            pg::PgResult rec = pg::exec_params(
                conn,
                "INSERT INTO api_token_store.rotation_retention_meta (key, value) VALUES "
                "('last_anomaly_facts', $1) ON CONFLICT (key) DO UPDATE SET value = "
                "EXCLUDED.value",
                std::vector<std::string>{facts_ser});
            if (rec.status() != PGRES_COMMAND_OK) {
                fail("anomaly fact-set record", conn);
                return result;
            }
            if (!txn.commit()) {
                fail("decline-path commit", conn);
                return result;
            }
            result.outcome = SweepOutcome::Declined;
            result.decline_anomaly = anomaly;
            // The raw fact, not the classified precedence winner — see
            // `SweepResult::no_anchor`'s own doc comment for why the caller
            // must route its bootstrap-vs-clock-anomaly metric split on
            // this, never on `decline_anomaly == NoAnchor`.
            result.no_anchor = facts.no_anchor;
            // Part 6: a missing anchor declines (the `AuditStore` answer).
            // Both credentials in an affected pair stay active — the
            // already-supported, already-warned-about UP-5 state, so this
            // never locks anyone out — but the cost is real, not free: a
            // pair whose successor HAS been used stays valid past its
            // promised overlap window for at least one more 60s tick,
            // extending exposure to a possibly-compromised credential.
            // Accepted because clock-driven revocation on an unverified
            // reading is worse, and fact-set dedup means this is not
            // permanent — an identical repeat next tick drains, capped.
            // NoAnchor is the only anomaly this store's own text can claim is
            // definitely about the clock reading; `Step`/`BadState` can also
            // be a genuinely correlated, non-clock-related event (an outage
            // for `Step`) or a durable reading corrupted by something other
            // than a clock fault (`BadState`) — so the generic branch below
            // names the GUARD's verdict, not a diagnosis of the clock
            // itself, on a server whose clock may be perfectly correct.
            // `Wipe` cannot reach here at all — this store's `would_wipe`
            // fact is hardcoded `false` (see the DELIBERATE NON-ADOPTION
            // comment near `kRotationSweepBigStepSecs`'s definition).
            // Triage payload for the non-bootstrap branch below: `prev`,
            // `pg_now` and their delta — an operator staring at "facts=e-s--"
            // alone cannot tell a genuine clock jump from a several-tick
            // outage without them (ops runbook, "The retention clock guard"
            // — do not drop these once added, that gap is what this exists
            // to close). `prev` may be unset here (e.g. an unparseable
            // durable reading, or one reset by the part-3 ahead-of-now/
            // negative sanitiser above) — reported honestly as "none" rather
            // than a fabricated 0.
            const std::string prev_str = prev.has_value() ? std::to_string(*prev) : "none";
            const std::string delta_str =
                prev.has_value() ? std::to_string(pg_now - *prev) : "n/a";
            result.decline_reason =
                anomaly == audit_retention::Anomaly::NoAnchor
                    ? "no usable previous rotation-sweep clock reading and predecessors are "
                      "already eligible for auto-revoke — declining this tick and anchoring; "
                      "both credentials in each affected pair stay active until the next tick, "
                      "which has a comparison point and proceeds"
                    : "rotation-sweep clock guard declined this tick (facts=" + facts_ser +
                          ", prev=" + prev_str + ", pg_now=" + std::to_string(pg_now) +
                          ", delta=" + delta_str +
                          ") — both credentials in each affected pair stay active; an identical "
                          "next tick will drain, capped";
            return result; // committed the stamp + anomaly record above
        }
        // Suppressed repeat of the same fact set — fall through to drain.
    } else if (!last_facts.empty()) {
        pg::PgResult clr = pg::exec_params(
            conn, "DELETE FROM api_token_store.rotation_retention_meta WHERE key = 'last_anomaly_facts'",
            std::vector<std::string>{});
        if (clr.status() != PGRES_COMMAND_OK) {
            fail("anomaly fact-set clear", conn);
            return result;
        }
    }

    // Accepted pass: select at most 201 eligible candidates — one more than
    // the cap (part 5), purely to tell "more than the cap" from "exactly
    // the cap"; trimmed back to `kMaxAutoRevokesPerTick` below before
    // anything is touched. `ORDER BY overlap_expires_at ASC` drains the
    // longest-overdue rows first when a tick is capped.
    std::vector<ApiToken> expired_predecessors;
    if (has_expired) {
        const std::string select_sql = std::string("SELECT token_id, '' AS token_hash, ") +
                                       kTokenColsTail +
                                       " FROM api_token_store.api_tokens WHERE " +
                                       std::string(kRotationEligiblePredicate) +
                                       " AND overlap_expires_at <= $1::bigint "
                                       "ORDER BY overlap_expires_at ASC LIMIT $2::bigint";
        pg::PgResult sel = pg::exec_params(
            conn, select_sql.c_str(),
            std::vector<std::string>{std::to_string(pg_now),
                                     std::to_string(kMaxAutoRevokesPerTick + 1)});
        if (sel.status() != PGRES_TUPLES_OK) {
            fail("eligible-candidate select", conn);
            return result;
        }
        const int rows = PQntuples(sel.get());
        const auto row_count = static_cast<std::size_t>(rows);
        // `(std::min)` parenthesised — see kMaxAutoRevokesPerTick's own
        // history: <windows.h>'s min/max function-like macros make a bare
        // `std::min` a MSVC C2589 on this TU.
        const std::size_t take = (std::min)(row_count, kMaxAutoRevokesPerTick);
        if (row_count > kMaxAutoRevokesPerTick) {
            result.capped = true;
            spdlog::warn("[{}] sweep_expired_rotations: tick hit the "
                        "auto-revoke cap ({} eligible, processing {}) — draining over "
                        "subsequent ticks",
                        kStoreName, row_count, take);
        }
        expired_predecessors.reserve(take);
        for (std::size_t i = 0; i < take; ++i)
            expired_predecessors.push_back(read_token(sel.get(), static_cast<int>(i)));
    }

    if (!txn.commit()) {
        fail("accepted-pass commit", conn);
        return result;
    }
    result.outcome = SweepOutcome::Ok;

    // A bare `bool` return from the per-pair lambda below would conflate
    // three DIFFERENT reasons for "false" — couldn't acquire the
    // per-principal lock (genuine fault), the predecessor was already
    // resolved out from under this sweep (benign, expected idempotent
    // no-op), or the clear UPDATE's own execution genuinely failed (fault)
    // — leaving a tick where every candidate resolved as a no-op
    // indistinguishable from one where every candidate hit a hard fault
    // (both would leave `result.revoked` empty and `result.outcome ==
    // Ok`). This typed outcome is what `result.failed_pairs` below is
    // derived from.
    enum class PairRevokeOutcome { kFailed, kNoOp, kRevoked };

    // Up to 200 SEPARATE per-pair transactions, each on its OWN connection
    // (never folded into the classification transaction above — ~600
    // statements holding locks against a 2s pool-acquire budget and a 30s
    // statement timeout would block interactive rotation for the whole
    // batch, for the sake of one commit fate shared by 200 unrelated
    // rotations). The session sweep lock above is STILL held throughout —
    // lock order stays global-sweep -> per-principal -> mutation; the
    // global lock is never (re-)acquired from inside one of these.
    for (const auto& predecessor : expired_predecessors) {
        // Bump revoke generation BEFORE the UPDATE — same TOCTOU contract as
        // revoke_token/revoke_for_principal (a concurrent validate_token's
        // SELECT racing this UPDATE observes the generation move at its
        // cache-write step and skips the stale write).
        revoke_generation_.fetch_add(1, std::memory_order_release);

        std::string revoked_hash;
        PairRevokeOutcome pair_outcome = PairRevokeOutcome::kFailed;

        // Atomic pair-resolve: revoke the predecessor AND clear the
        // surviving successor's rotation state together, or neither —
        // never leave a revoked predecessor with a successor still stamped
        // mid-rotation (design doc §7: "revocation during overlap ...
        // resolves the rotation state"). Hermes F3: the clear UPDATE's
        // result is checked (a genuine execution failure — not merely
        // "matched zero rows", the expected idempotent case when the
        // successor is already gone/resolved — rolls back the WHOLE
        // transaction, including the predecessor's revoke, so "or neither"
        // is a real guarantee). Also advisory-locked on the same
        // principal_id key rotate_engine_credential/confirm_rotation use,
        // so this sweep can't race a concurrent manual rotate/confirm for
        // the same principal.
        const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) {
            pg::PgResult lock_res =
                pg::exec_params(conn, "SELECT pg_advisory_xact_lock(hashtext($1))",
                                std::vector<std::string>{predecessor.principal_id});
            if (lock_res.status() != PGRES_TUPLES_OK) {
                pair_outcome = PairRevokeOutcome::kFailed;
                return false;
            }

            // Re-assert the scan's preconditions UNDER THE LOCK (the scan at the
            // top of this function is unlocked, so a manual successor-revoke
            // could have run between it and this locked revoke): only revoke if
            // the predecessor still has a live overlap window AND a live
            // successor to cut over to. Without this, a successor manually
            // revoked in that window — whose resolve_rotation_pair_after_revoke
            // cleared this predecessor's overlap_expires_at — would still be
            // revoked here, dropping THIS ROTATION GROUP to zero usable
            // credentials (the exact §7 invariant — not necessarily zero for
            // the principal as a whole, who may hold other unrelated active
            // tokens). The `overlap_expires_at > 0` check makes
            // resolve's clear authoritative under the lock; the EXISTS is the
            // belt to its suspenders.
            //
            // UP-5: `s.last_used_at <> 0` is re-asserted HERE too, under the
            // lock, against a FRESH read — never trusted from the unlocked
            // scan above. A successor could have been used for the first
            // time in the gap between the scan and this transaction; this is
            // the authoritative check, the scan's copy is only a
            // cheap pre-filter. Never auto-revoke a predecessor whose
            // successor has never been presented — the operator's only copy
            // of that secret may be the one that was lost, and revoking here
            // would leave zero usable credentials for this rotation group,
            // the exact failure this whole guard exists to prevent (not
            // necessarily zero for the principal as a whole, who may hold
            // other unrelated active tokens). The pair
            // stays live past its window; `list_rotations_nearing_expiry_
            // unused` keeps surfacing it until an operator resolves it
            // explicitly. Cadence is owned by `rotation_warn_dedup.hpp`:
            // the log line repeats per tick, the audit row and metric fire
            // once per pair per state.
            pg::PgResult r1 = pg::exec_params(
                conn,
                "UPDATE api_token_store.api_tokens SET revoked = TRUE "
                "WHERE token_id = $1 AND revoked = FALSE AND overlap_expires_at > 0 "
                "AND EXISTS (SELECT 1 FROM api_token_store.api_tokens s "
                "WHERE s.rotation_group = api_token_store.api_tokens.rotation_group "
                "AND s.supersedes_token_id = api_token_store.api_tokens.token_id "
                "AND s.revoked = FALSE AND s.last_used_at <> 0) "
                "RETURNING token_hash",
                std::vector<std::string>{predecessor.token_id});
            if (r1.status() != PGRES_TUPLES_OK) {
                pair_outcome = PairRevokeOutcome::kFailed;
                return false;
            }
            if (PQntuples(r1.get()) == 0) {
                // Already revoked, or resolved under the lock — idempotent
                // no-op, NOT a failure.
                pair_outcome = PairRevokeOutcome::kNoOp;
                return false;
            }
            revoked_hash = PQgetvalue(r1.get(), 0, 0);

            // A successor already revoked/gone simply matches zero rows,
            // which is fine (nothing survives to clear) — but a genuine
            // execution failure (status != PGRES_TUPLES_OK) must roll back
            // the predecessor's revoke above too, never commit half the
            // pair-resolve.
            pg::PgResult r2 = pg::exec_params(
                conn,
                "UPDATE api_token_store.api_tokens "
                "SET rotation_group = '', supersedes_token_id = '', overlap_expires_at = 0, "
                "rotation_initiator = '' "
                "WHERE rotation_group = $1 AND supersedes_token_id = $2 AND revoked = FALSE",
                std::vector<std::string>{predecessor.rotation_group, predecessor.token_id});
            // Zero rows is the expected idempotent case (successor already
            // gone/resolved) and still reports PGRES_COMMAND_OK — this
            // UPDATE has no RETURNING clause, so a successful zero-row match
            // is PGRES_COMMAND_OK, never PGRES_TUPLES_OK; only a genuine
            // execution failure returns anything else.
            if (r2.status() != PGRES_COMMAND_OK) {
                pair_outcome = PairRevokeOutcome::kFailed;
                return false;
            }
            pair_outcome = PairRevokeOutcome::kRevoked;
            return true;
        });
        // `with_txn_for` itself can fail OUTSIDE the lambda (acquire/BEGIN/
        // COMMIT) without ever running it, leaving `pair_outcome` at its
        // default `kFailed` — correctly counted as a genuine fault, not a
        // no-op, since the lambda never got to decide.
        //
        // Testing `pair_outcome == kFailed` alone would miss the COMMIT
        // path: `with_txn_for` can return `false` AFTER the lambda already
        // set `pair_outcome = kRevoked` and returned `true` (the
        // `PQTRANS_INTRANS` guard, or `commit()` itself failing); that pair
        // would then enter neither `result.revoked` (guarded by `if (ok)`
        // below) NOR `result.failed_pairs`, silently vanishing from both.
        // The correct condition is "the transaction did not actually
        // succeed, and this was not the benign idempotent no-op" — `kNoOp`
        // is excluded because the lambda deliberately returns `false` there
        // too (already resolved under the lock), and that path must stay
        // uncounted.
        if (!ok && pair_outcome != PairRevokeOutcome::kNoOp)
            ++result.failed_pairs;

        if (ok) {
            // Second generation bump AFTER the txn commits, before invalidating
            // — the double-bump TOCTOU contract revoke_token/confirm_rotation
            // use (#2188): closes the window where a validate_token that read
            // the pre-commit predecessor could re-populate the cache after
            // invalidate_cache, re-serving the revoked credential for the 60s TTL.
            revoke_generation_.fetch_add(1, std::memory_order_release);
            invalidate_cache(revoked_hash);
            evict_rotation_raw(predecessor.rotation_group);
            result.revoked.push_back(predecessor);
        }
    }
    return result;
}

ApiTokenStore::NearingExpiryResult
ApiTokenStore::list_rotations_nearing_expiry_unused(int64_t warn_within_secs) const {
    NearingExpiryResult result;
    if (!open_)
        return result;

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;

    // PostgreSQL's OWN clock, read once here, drives both this scan's
    // window AND (via `result.pg_now`) the caller's own "has this pair's
    // overlap window already elapsed" derivation — never the caller's
    // process clock. The two halves of the T12 sweep must compare against
    // the SAME clock: under exactly the skew the whole clock-guarded-
    // retention shape exists to survive, comparing this scan's window
    // against the caller's `std::chrono::system_clock::now()` in
    // server.cpp instead could log/audit an "overlap window elapsed" state
    // for a pair that `sweep_expired_rotations` — reading the SAME PG
    // clock via its own, separate query — does not (yet) consider elapsed
    // at all.
    pg::PgResult clk =
        pg::exec_params(lease.get(), "SELECT EXTRACT(EPOCH FROM now())::bigint",
                        std::vector<std::string>{});
    if (clk.status() != PGRES_TUPLES_OK || PQntuples(clk.get()) != 1 ||
        PQgetisnull(clk.get(), 0, 0)) {
        spdlog::warn("[{}] list_rotations_nearing_expiry_unused: clock read failed", kStoreName);
        return result;
    }
    result.pg_now = to_i64(PQgetvalue(clk.get(), 0, 0));

    // Predecessors whose overlap window ends within the warn lead time —
    // INCLUDING one that has already elapsed (UP-5). Before the
    // never-used-successor carve-out in sweep_expired_rotations, an
    // already-elapsed window was exclusively that function's job and this
    // query excluded it (`> $1::bigint`, strictly future) to keep the two
    // halves from double-handling the same row. Now that
    // sweep_expired_rotations deliberately leaves a never-used-successor
    // pair alone past its window, THIS half is the only thing left that
    // keeps surfacing it — dropping the lower bound is what makes that
    // happen; no double-handling results because the two queries' successor
    // conditions are now complementary (this one requires `last_used_at = 0`
    // below, sweep_expired_rotations requires `<> 0`), never the same row.
    const std::string sql = std::string("SELECT token_id, '' AS token_hash, ") + kTokenColsTail +
                            " FROM api_token_store.api_tokens "
                            "WHERE revoked = FALSE AND overlap_expires_at > 0 "
                            "AND overlap_expires_at <= $1::bigint AND supersedes_token_id = ''";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(),
                        std::vector<std::string>{std::to_string(result.pg_now + warn_within_secs)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("[{}] list_rotations_nearing_expiry_unused: predecessor scan failed",
                    kStoreName);
        return result;
    }

    const int rows = PQntuples(res.get());
    for (int i = 0; i < rows; ++i) {
        ApiToken predecessor = read_token(res.get(), i);

        const std::string succ_sql = std::string("SELECT token_id, '' AS token_hash, ") +
                                     kTokenColsTail +
                                     " FROM api_token_store.api_tokens "
                                     "WHERE revoked = FALSE AND rotation_group = $1 "
                                     "AND supersedes_token_id = $2 AND last_used_at = 0 LIMIT 1";
        pg::PgResult sres = pg::exec_params(
            lease.get(), succ_sql.c_str(),
            std::vector<std::string>{predecessor.rotation_group, predecessor.token_id});
        if (sres.status() != PGRES_TUPLES_OK || PQntuples(sres.get()) == 0)
            continue; // successor gone, already used, or already revoked — nothing to warn about

        ApiToken successor = read_token(sres.get(), 0);
        result.pairs.push_back(RotationPair{std::move(predecessor), std::move(successor)});
    }
    return result;
}

std::optional<int64_t> ApiTokenStore::rotation_sweep_last_pass_now() const {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT value FROM api_token_store.rotation_retention_meta WHERE key = 'last_pass_now'",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1 || PQgetisnull(res.get(), 0, 0))
        return std::nullopt; // unreachable, or no pass has ever reached a verdict yet
    return parse_meta_i64(col(res.get(), 0, 0)); // same sanitiser the sweep itself uses
}

std::expected<bool, std::string> ApiTokenStore::revoke_token(const std::string& token_id) {
    if (!open_)
        return std::unexpected("database not open");

    // Bump the revoke generation BEFORE the UPDATE so any concurrent
    // validate_token whose SELECT outraces this UPDATE will observe the
    // generation move at its cache-write step and skip the stale write.
    revoke_generation_.fetch_add(1, std::memory_order_release);

    if (test_hook_after_first_revoke_bump_)
        test_hook_after_first_revoke_bump_();

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        // authoritative: a lease timeout is a WRITE FAILURE — never a silent
        // success and never a false "not found". The caller must 503/retry.
        return std::unexpected("database unavailable — try again");

    // RETURNING token_hash — never sqlite3_changes()-style mutate-then-count
    // (#1033). PQntuples > 0 IS the changed check, and the returned hash is
    // exactly what we need to invalidate the cache (no pre-SELECT needed).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE api_token_store.api_tokens SET revoked = TRUE WHERE token_id = $1 "
        "RETURNING token_hash, principal_id, rotation_group",
        std::vector<std::string>{token_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("revoke did not persist: ") +
                               PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    if (rows == 0)
        return false; // DB write succeeded; no such token (already gone / unknown id)
    const std::string revoked_principal_id = PQgetvalue(res.get(), 0, 1);
    const std::string revoked_rotation_group = PQgetvalue(res.get(), 0, 2);

    // Second generation bump — AFTER the UPDATE has committed, BEFORE we
    // invalidate. The pre-UPDATE bump alone only catches a validate_token that
    // snapshotted revoke_generation_ *before* it. A validate that started AFTER
    // that first bump captured the already-incremented value as its baseline,
    // and under Postgres READ COMMITTED its SELECT can still read this row's
    // pre-commit revoked=false; its post-SELECT re-check would then match its
    // own snapshot and cache the stale row for the full TTL (PR #2188 round-3
    // review). This second transition moves the generation past that snapshot,
    // so the racing validate skips its cache write; invalidate_cache below then
    // clears any entry that still beat us (both serialize on cache_mtx_).
    revoke_generation_.fetch_add(1, std::memory_order_release);
    invalidate_cache(PQgetvalue(res.get(), 0, 0));
    // Design §7: if this credential was part of an in-flight rotation pair,
    // resolve the surviving partner. Release our write lease FIRST — the helper
    // opens its own advisory-locked txn, and holding two leases would
    // self-starve a size-1 pool.
    lease.reset();
    resolve_rotation_pair_after_revoke(revoked_principal_id, revoked_rotation_group, token_id);
    return true;
}

std::expected<std::size_t, std::string>
ApiTokenStore::revoke_for_principal(const std::string& principal_id) {
    if (!open_)
        return std::unexpected("database not open");
    if (principal_id.empty())
        return std::size_t{0}; // argument guard: nothing to revoke, DB untouched

    // Bump revoke generation BEFORE the UPDATE — same contract as
    // `revoke_token`.
    revoke_generation_.fetch_add(1, std::memory_order_release);

    std::vector<std::string> hashes;
    std::vector<std::string> rotation_groups;
    std::string error_msg;

    // #2961 residual A: wrapped in the SAME per-principal advisory lock
    // (hashtext(principal_id)) rotate_engine_credential/rotate_token/
    // confirm_rotation/confirm_token_rotation all take — this deactivation
    // necessarily includes both sides of any in-flight rotation pair, so it
    // follows the same per-principal serialization discipline every other
    // rotation-touching write in this store already does. ONE statement
    // yields the count (PQntuples), every hash to invalidate, and every
    // rotation_group to scrub (RETURNING) — no separate pre-SELECT snapshot
    // needed; the UPDATE's own WHERE clause is the authoritative "what
    // changed" answer (#1033).
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult lock_res =
            pg::exec_params(conn, "SELECT pg_advisory_xact_lock(hashtext($1))",
                            std::vector<std::string>{principal_id});
        if (lock_res.status() != PGRES_TUPLES_OK) {
            error_msg = "failed to acquire rotation lock";
            return false;
        }
        pg::PgResult res = pg::exec_params(
            conn,
            "UPDATE api_token_store.api_tokens SET revoked = TRUE "
            "WHERE principal_id = $1 AND revoked = FALSE "
            "RETURNING token_hash, rotation_group",
            std::vector<std::string>{principal_id});
        if (res.status() != PGRES_TUPLES_OK) {
            error_msg =
                std::string("revoke_for_principal did not persist: ") + PQerrorMessage(conn);
            return false;
        }
        const int rows = PQntuples(res.get());
        hashes.reserve(static_cast<std::size_t>(rows));
        for (int i = 0; i < rows; ++i) {
            hashes.emplace_back(PQgetvalue(res.get(), i, 0));
            std::string group = PQgetvalue(res.get(), i, 1);
            if (!group.empty())
                rotation_groups.push_back(std::move(group));
        }
        return true;
    });

    if (!ok)
        // authoritative: never report a count (even 0) when we could not reach
        // the DB — that is indistinguishable from "the principal had no tokens"
        // and would let "Sign out everywhere" lie during an outage.
        return std::unexpected(error_msg.empty() ? "revoke_for_principal did not persist"
                                                  : error_msg);

    // Second generation bump after the UPDATE commits, before invalidating —
    // see revoke_token for the full rationale (closes the post-first-bump /
    // pre-commit READ COMMITTED cache-poisoning window).
    if (!hashes.empty())
        revoke_generation_.fetch_add(1, std::memory_order_release);
    for (const auto& hash : hashes)
        invalidate_cache(hash);

    // #2961 residual A: scrub every affected rotation_group's RAM-only grace
    // cache entry (keyed by rotation_group, NOT principal — mapped via the
    // RETURNING rows above) so "sign out everywhere"/deactivate cannot leave
    // an already-cached raw successor secret from a recent rotate
    // re-servable via a grace-window replay after every credential for this
    // principal was just revoked. `evict_rotation_raw` scrubs
    // (`yuzu::secure_zero`) the raw value before erasing — never a bare
    // erase. See this function's own .hpp doc comment for what this does
    // NOT close (a genuinely concurrent in-flight mint's own post-commit
    // cache write — bounded by `successor_rotation_still_pending` instead,
    // #2961 residual B, out of scope here).
    std::sort(rotation_groups.begin(), rotation_groups.end());
    rotation_groups.erase(std::unique(rotation_groups.begin(), rotation_groups.end()),
                          rotation_groups.end());
    for (const auto& group : rotation_groups)
        evict_rotation_raw(group);

    return hashes.size();
}

std::expected<bool, std::string> ApiTokenStore::delete_token(const std::string& token_id) {
    if (!open_)
        return std::unexpected("database not open");

    // Bump revoke generation BEFORE the DELETE — a delete is a stronger
    // form of revoke from the cache's perspective, so the same TOCTOU
    // applies.
    revoke_generation_.fetch_add(1, std::memory_order_release);

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        // authoritative (ADR-0030 §Posture names delete_token alongside
        // revoke_*): a lease timeout is a WRITE FAILURE, never a silent success
        // and never a false "not found".
        return std::unexpected("database unavailable — try again");

    // RETURNING token_hash — same #1033 idiom as revoke_token: PQntuples is
    // the changed-check, the returned hash is the cache-invalidation key.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM api_token_store.api_tokens WHERE token_id = $1 "
        "RETURNING token_hash, principal_id, rotation_group",
        std::vector<std::string>{token_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("delete did not persist: ") + PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    if (rows == 0)
        return false; // DB write succeeded; no such token (already gone / unknown id)
    const std::string deleted_principal_id = PQgetvalue(res.get(), 0, 1);
    const std::string deleted_rotation_group = PQgetvalue(res.get(), 0, 2);

    // Second generation bump after the DELETE commits, before invalidating —
    // see revoke_token for the full rationale.
    revoke_generation_.fetch_add(1, std::memory_order_release);
    invalidate_cache(PQgetvalue(res.get(), 0, 0));
    // Design §7: resolve the rotation pair if this credential was part of one
    // (release our lease first — see revoke_token).
    lease.reset();
    resolve_rotation_pair_after_revoke(deleted_principal_id, deleted_rotation_group, token_id);
    return true;
}

} // namespace yuzu::server
