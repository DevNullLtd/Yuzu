#include "approval_manager.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "refusal_log_throttle.hpp"
#include "secure_random.hpp"
#include "sha256_hex.hpp"

#include <libpq-fe.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <yuzu/metrics.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <random>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "approval_manager";

// Declared in server.cpp (describe + per-origin pre-seed) and documented in
// docs/user-manual/metrics.md; the name is spelled once here.
constexpr const char* kPreconditionDeniedMetric = "yuzu_approval_precondition_denied_total";

// query()/query_checked() row cap. No creation-side check enforces this on
// submit() — a legitimately busy queue can exceed it — query_checked()
// detects and reports the overflow via ApprovalListResult::truncated. Both
// query() and query_checked() build their SQL from this constant (review
// finding, PR #4656) — see ApprovalListResult's doc comment.
constexpr int kApprovalListCap = 100;

// Bounded acquires (ADR-0012 §2). No hot-path caller here — every runtime
// acquire uses the ordinary CRUD budget (matches PatchManager/
// ScheduleEngine).
constexpr std::chrono::milliseconds kReadTimeout{1500};
constexpr std::chrono::milliseconds kWriteTimeout{2000};

// Approval ids are BEARER CAPABILITIES: an MCP approval-ticket recall (#289) is
// authorized by presenting the id, and the bound args are not secret. A
// predictable id — e.g. mt19937 state recovered from prior outputs — would let
// an attacker ride another operator's approved-but-unconsumed ticket
// (governance UP-4). Draw from the CSPRNG (RAND_bytes / BCryptGenRandom) instead;
// 16 bytes = 128-bit unguessable. Entropy failure fails the mint closed.
std::expected<std::string, std::string> generate_id() {
    auto hex = yuzu::server::random_hex(16);
    if (!hex)
        return std::unexpected(std::string("secure approval-id generation failed"));
    return *hex;
}

// An approval id is a BEARER CAPABILITY (see generate_id above): presenting it
// is what authorizes an MCP recall. Logs are read by more people than may
// redeem a ticket, so log a prefix that is enough to correlate two lines about
// the same ticket and not enough to redeem it. 8 hex chars of a 128-bit id.
std::string redact_id(const std::string& id) {
    constexpr std::size_t kKeep = 8;
    return id.size() <= kKeep ? id : id.substr(0, kKeep) + "...";
}

// reviewed_at, consumed_at and every expiry cutoff are authored by the DATABASE,
// in-SQL, and compared against the same database's clock (#6061, governance
// UP-3/UP-4). With a per-replica clock, a forward-skewed replica's sweep cutoff
// expired every live ticket fleet-wide, a replica running days behind stamped an
// approval already past its TTL, and a far-future `reviewed_at` was never swept and
// stayed consumable. Postgres `now()` is the one authority all replicas share (the
// same direction as SessionStore, ADR-2002 s4 / #3715). `now()` is fixed for a
// transaction, so a statement or sweep sees one reading.
//
// `submitted_at` is database time too (#6096): submit() authors it in-SQL from the same
// expression, so every stamp this store writes and every comparison it makes (the
// pending-expiry cutoff, the ticket lifetime) is on the one clock. It used to be the
// one process-clock stamp, kept so ScheduleRunner could compare it with ScheduleEngine's
// process-clock `last_executed_at`; that comparison is gone. One approval == one
// scheduled run is now a guarded STATE transition (retire_schedule_tickets), not a clock
// comparison, so no reader needs the two clocks to agree.
constexpr const char* kDbNowEpochSql = "EXTRACT(EPOCH FROM now())::bigint";

// THE ticket-liveness predicate, as a SQL boolean over `reviewed_at`. ONE definition,
// used by the consume CAS, its diagnostic read, submit()'s approved-ticket sweep and
// `ticket_is_live()` (which ScheduleRunner calls), so those four can never disagree
// about when an approved ticket may still be redeemed or fired.
//   lower bound: reviewed_at >= now - kApprovalTicketTtlSeconds   (the 7-day lifetime)
//   upper bound: reviewed_at <= now + kApprovalReviewedAtSlackSeconds
// The upper bound is what makes the lower one safe: a `reviewed_at` far in the future
// (a writer with a wild clock, a hand-edited row) would otherwise pass the lower bound
// for as long as the skew lasts and never be swept. Clock-guarded-retention (the
// routed concern for any wall-clock cutoff): the guard reasoning is that the cutoff
// does not come from any replica's clock at all, so there is no per-replica reading to
// distrust or persist (parts 1-4 have nothing to guard), and the sweep is a status
// transition to 'expired', never a DELETE (ADR-0065 "Expiry-sweep clock-guard
// adjudication"), so a wrong cutoff is recoverable by resubmitting. What remains is the
// database's own clock, the shared authority every replica already trusts for sessions.
// Literals are interpolated from the constants (integers, no caller text).
std::string ticket_live_sql() {
    const std::string now = kDbNowEpochSql;
    return "(reviewed_at >= (" + now + " - " + std::to_string(kApprovalTicketTtlSeconds) +
           ") AND reviewed_at <= (" + now + " + " +
           std::to_string(kApprovalReviewedAtSlackSeconds) + "))";
}

const char* col(PGresult* res, int row, int c) {
    return PQgetisnull(res, row, c) ? "" : PQgetvalue(res, row, c);
}
std::string col_str(PGresult* res, int row, int c) { return std::string(col(res, row, c)); }
std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

// Best-effort SQLSTATE extraction (mirrors engine_principal_store.cpp's
// file-local helper of the same shape, #2456). Never throws, never
// null-derefs — `PQresultErrorField` returns nullptr both for "no such
// field" and "PGresult itself is null". Empty string, not "<none>" — this
// is a data field (StoreReadError::sqlstate/ConsumeError::sqlstate), not a
// log-line rendering.
std::string result_sqlstate(const pg::PgResult& res) {
    const char* p = res.get() ? PQresultErrorField(res.get(), PG_DIAG_SQLSTATE) : nullptr;
    return p ? std::string(p) : std::string();
}

} // namespace

// Guarded the same way as `consume_denial_reason`. A missing arm here falls
// through to `return ""`, which `approval_origin_from_string` decodes as
// kUnspecified — refused at redemption since #2442's closing half
// (origin_redeemable_as). That makes an unhandled enumerator fail CLOSED
// today, which was not always true: before the MCP mint declared kMcp,
// kUnspecified was the value that granted, and a missing arm here was
// fail-open. Kept guarded regardless — this function's return value is a
// stored column, not just a redemption input, and a silently-wrong write is
// its own defect independent of which way redemption currently reads it. See
// that function's header comment for why the MSVC arm is ordered as it is and
// why it is best-effort.
const char* to_string(ApprovalOrigin origin) {
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(1 : 4062) // off by default; `error:` alone does NOT enable it
#pragma warning(error : 4062)
#endif
    switch (origin) {
    case ApprovalOrigin::kInstruction:
        return "instruction";
    case ApprovalOrigin::kSchedule:
        return "schedule";
    case ApprovalOrigin::kMcp:
        return "mcp";
    case ApprovalOrigin::kGuardianDeploy:
        return "guardian_deploy";
    case ApprovalOrigin::kUnspecified:
    case ApprovalOrigin::kUnrecognised:
        // Neither is written as a surface. kUnrecognised only ever comes OUT of
        // a decode; storing it would round-trip to kUnspecified, collapsing
        // "this build cannot attribute it to any surface" into "declared
        // nothing" — different facts even though both refuse today.
        break;
    }
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif
    return "";
}

ApprovalOrigin approval_origin_from_string(std::string_view text) {
    if (text == "instruction")
        return ApprovalOrigin::kInstruction;
    if (text == "schedule")
        return ApprovalOrigin::kSchedule;
    if (text == "mcp")
        return ApprovalOrigin::kMcp;
    if (text == "guardian_deploy")
        return ApprovalOrigin::kGuardianDeploy;
    // Empty is an UNDECLARED MINT. Since #2442's closing half, no production
    // caller writes it any more — the MCP mint now declares kMcp, and
    // `submit()`'s `origin` parameter is no longer defaulted — so this arm now
    // exists for two things only: a row minted before this change, and a
    // caller that regresses the non-default (which the compiler stops, but a
    // stored row predating the fix is real data, not a hypothetical). Both are
    // REFUSED at redemption, same as kUnrecognised (origin_redeemable_as).
    // It is NOT the pre-column row: migration v7 rewrote every '' it found to
    // the sentinel, so a row that predates the column decodes below as
    // kUnrecognised, not kUnspecified — kept apart so the two refusal causes
    // ("declared nothing" vs. "predates the column entirely") stay
    // distinguishable in code even though redemption treats them alike today.
    // Anything ELSE is a value this build does not know, and it must NOT fold
    // into either declared case — decode it as its own value (kUnrecognised)
    // and let the predicate refuse it on that basis, not by accident of
    // string-matching.
    if (text.empty())
        return ApprovalOrigin::kUnspecified;
    return ApprovalOrigin::kUnrecognised;
}

// Guarded like the other closed-set switch over this enum, `to_string` above.
// (`consume_denial_reason` in the header carries the same guard, but over
// `ConsumeFailure` — a different enum, so it is not part of this set.)
//
// The trailing `return false` (not a concrete surface) already fails closed, so
// a missing arm cannot grant — but it would silently pick the REFUSE side for a
// surface that may have been added precisely to be redeemable, and the author
// would never be told. Guarding one of the two was an inconsistency, not a
// judgement.
//
// DO NOT ADD A `default:` LABEL TO THE SWITCH BELOW. `-Wswitch` only fires while
// the switch has none, so a defensive `default: return false;` — which looks like
// belt-and-braces, and does exactly what the statement below already does —
// silently deletes this guard, with no warning and no failing test. MEASURED
// on GCC 15.2: with a default label added, a missing enumerator stops erroring
// here while still erroring in `to_string`. The trailing return living OUTSIDE
// the switch is what keeps the guard armed, and that is the whole reason it is
// out there rather than in a default arm.
//
// kUnspecified moved from the grant side to the refuse side (#2442, closing half):
// the MCP mint declares ApprovalOrigin::kMcp explicitly (mcp_server.cpp), so
// kUnspecified is no longer "the MCP gate, undeclared" - it is indistinguishable
// from a row this build cannot attribute to any surface, which is exactly the
// kUnrecognised case. Grouping them is deliberate, not an oversight.
//
// #6062 split the old one-surface predicate in two: THIS function only says whether
// a value names a concrete surface (the half the -Wswitch guard protects: a new
// surface must be classified here or the build fails), and `origin_redeemable_as`
// below compares two of them. A surface that is not listed as concrete can never
// redeem or be redeemed, so a missing arm refuses rather than grants.
static bool names_concrete_surface(ApprovalOrigin origin) {
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(1 : 4062) // off by default; `error:` alone does NOT enable it
#pragma warning(error : 4062)
#endif
    switch (origin) {
    case ApprovalOrigin::kInstruction:
    case ApprovalOrigin::kSchedule:
    case ApprovalOrigin::kMcp:
    case ApprovalOrigin::kGuardianDeploy:
        return true;
    case ApprovalOrigin::kUnrecognised:
    case ApprovalOrigin::kUnspecified:
        return false;
    }
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif
    return false; // unreachable; fail closed if the enum grows
}

bool origin_redeemable_as(ApprovalOrigin stored, ApprovalOrigin expected) {
    return names_concrete_surface(stored) && names_concrete_surface(expected) &&
           stored == expected;
}

// Same -Wswitch guard as `names_concrete_surface`: a surface added later must state
// whether its tickets bind a request, or the build fails. The trailing return is the
// SAFE answer (true: must bind) and lives outside the switch so the guard stays armed.
bool requires_bound_request(ApprovalOrigin origin) {
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(1 : 4062) // off by default; `error:` alone does NOT enable it
#pragma warning(error : 4062)
#endif
    switch (origin) {
    case ApprovalOrigin::kGuardianDeploy:
        return true;
    case ApprovalOrigin::kInstruction:
    case ApprovalOrigin::kSchedule:
    case ApprovalOrigin::kMcp:
    case ApprovalOrigin::kUnspecified:
    case ApprovalOrigin::kUnrecognised:
        return false;
    }
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif
    return true; // unreachable; fail toward "must bind" if the enum grows
}

namespace {

// `excluded_roots` is stored as a JSON array of strings; '' (the column default, and
// every row minted before migration v3) means "none". nullopt == the column holds
// something else: callers that ENFORCE the list refuse on it, they never read it as
// empty.
std::optional<std::vector<std::string>> decode_excluded_roots(const std::string& text) {
    std::vector<std::string> out;
    if (text.empty())
        return out;
    const auto doc = nlohmann::json::parse(text, nullptr, /*allow_exceptions=*/false);
    if (!doc.is_array())
        return std::nullopt;
    for (const auto& e : doc) {
        if (!e.is_string())
            return std::nullopt;
        out.push_back(e.get<std::string>());
    }
    return out;
}

// The stored form of an excluded-roots list: '' for none, else a compact JSON array of
// strings. ONE definition, used by submit_bound (to store it) and by redemption (to pin the
// consuming CAS to the list the integrity check read), so the two cannot drift. STRICT: an
// invalid-UTF-8 root throws rather than being "replaced" - a replaced root would no longer
// equal the name it was meant to exclude, and a silently weakened exclusion is the one outcome
// this must not have. nullopt == not encodable.
std::optional<std::string> encode_excluded_roots(const std::vector<std::string>& roots) {
    if (roots.empty())
        return std::string{};
    try {
        return nlohmann::json(roots).dump(-1, ' ', false, nlohmann::json::error_handler_t::strict);
    } catch (const nlohmann::json::exception&) {
        return std::nullopt;
    }
}

// True when `j` nests containers deeper than `limit` (a scalar is depth 0). Bounded by
// the limit itself, so the recursion is at most `limit + 1` frames whatever the input.
bool nests_deeper_than(const nlohmann::json& j, std::size_t limit) {
    if (!j.is_structured())
        return false;
    if (limit == 0)
        return true;
    for (const auto& child : j) {
        if (nests_deeper_than(child, limit - 1))
            return true;
    }
    return false;
}

} // namespace

bool bound_request_is_readable(std::string_view text) {
    if (text.empty() || text.size() > kMaxRequestJsonBytes)
        return false;
    // Lexical container-depth scan BEFORE parsing: a document nested past the limit is
    // refused without ever being built, whatever the parser would have done with it.
    // Brackets inside string literals do not count.
    // Written as a hex escape: test_approval_manager.cpp's comment-stripping scan of this
    // file cannot tolerate a double-quote character literal.
    constexpr char kQuote = '\x22';
    std::size_t depth = 0;
    bool in_string = false;
    bool escaped = false;
    for (const char c : text) {
        if (in_string) {
            if (escaped)
                escaped = false;
            else if (c == '\\')
                escaped = true;
            else if (c == kQuote)
                in_string = false;
            continue;
        }
        if (c == kQuote) {
            in_string = true;
        } else if (c == '{' || c == '[') {
            if (++depth > kMaxRequestJsonDepth)
                return false;
        } else if ((c == '}' || c == ']') && depth > 0) {
            --depth;
        }
    }
    const auto doc = nlohmann::json::parse(text, nullptr, /*allow_exceptions=*/false);
    return doc.is_object() && !nests_deeper_than(doc, kMaxRequestJsonDepth);
}

namespace {

// THE four-eyes root comparison (#6062): the submitter check and the excluded-root
// check in set_review_status both go through here, so "is this reviewer the same human
// as that principal" has one definition. At this layer a root IS the principal name -
// the approve routes admit only interactive human sessions (approver_assurance.hpp),
// for which the session username is the human, and ADR-0033 section 7's resolution
// table (token -> owner, engine -> owner, run -> admitting operator) is applied by the
// CALLER that builds `excluded_roots` and picks the reviewer, not guessed at here.
// Byte-for-byte: account names are case-sensitive keys in the auth store, and folding
// case here would equate two distinct accounts. Deliberately NOT a normalising
// compare - a fold that is wrong in the permissive direction would let a designer
// approve their own effect.
bool same_human_root(const std::string& a, const std::string& b) { return a == b; }

// Why an APPROVED ticket must not be redeemed even though its row says "approved"
// (#6062): the approval is only worth what produced it. approve() refuses the
// submitter and every excluded root and mints the digest at mint, but a row written or
// edited by anything else (a replica running an older build whose approve() ignores
// excluded_roots, a hand edit, a restored backup) can say "approved" without any of
// that having held. Redemption therefore re-derives the facts from the stored row
// instead of trusting the status word. nullopt == the row is sound; otherwise a short
// cause for the SERVER log only (never sent to a client: for a fault the refusal message is
// the uniform one, so the redeemer is no oracle for which check fired; the one exception is
// the digest that could not be COMPUTED, which decided nothing and is reported to the caller
// as a store error, see integrity_refusal).
//
// A legacy row (no request_json, no digest, no excluded roots) passes the digest and
// roots checks by construction, so every pre-v3 and unbound ticket redeems as before.
struct IntegrityFault {
    std::string cause;
    bool unevaluated{false}; ///< the digest could not be computed: nothing was decided
};
// The request half of the integrity check, shared by redemption (digest only) and
// approve() (digest AND readability, so a reviewer is never asked to approve a request
// they could not have read). An empty request with an empty digest is an unbound
// (legacy) ticket and is sound; a digest with no request, or a request that does not
// hash to its digest, is not.
std::optional<IntegrityFault> request_binding_fault(const std::string& request_json,
                                                    const std::string& request_digest,
                                                    bool require_readable) {
    if (request_json.empty()) {
        if (request_digest.empty())
            return std::nullopt;
        return IntegrityFault{"digest stored without a request"};
    }
    if (require_readable && !bound_request_is_readable(request_json))
        return IntegrityFault{"stored request is not a readable bounded JSON object"};
    const auto digest = sha256_hex(request_json);
    if (!digest)
        return IntegrityFault{"request digest could not be computed", /*unevaluated=*/true};
    if (*digest != request_digest)
        return IntegrityFault{"request digest does not match the stored request"};
    return std::nullopt;
}

std::optional<IntegrityFault> approval_integrity_fault(const Approval& a) {
    // approve() always records its reviewer (it refuses an empty one), so an approved
    // ticket with none was not produced by it: set by hand, an old build, or a restore.
    if (a.reviewed_by.empty())
        return IntegrityFault{"approved with no recorded reviewer"};
    if (a.excluded_roots_unreadable)
        return IntegrityFault{"excluded_roots column unreadable"};
    if (same_human_root(a.reviewed_by, a.submitted_by))
        return IntegrityFault{"reviewer is the submitter"};
    if (reviewer_is_excluded(a.reviewed_by, a.excluded_roots))
        return IntegrityFault{"reviewer is an excluded root"};
    return request_binding_fault(a.request_json, a.request_digest, /*require_readable=*/false);
}

Approval row_to_approval(PGresult* r, int i) {
    Approval a;
    a.id = col_str(r, i, 0);
    a.definition_id = col_str(r, i, 1);
    a.status = col_str(r, i, 2);
    a.submitted_by = col_str(r, i, 3);
    a.submitted_at = to_i64(col(r, i, 4));
    a.reviewed_by = col_str(r, i, 5);
    a.reviewed_at = to_i64(col(r, i, 6));
    a.review_comment = col_str(r, i, 7);
    a.scope_expression = col_str(r, i, 8);
    a.consumed_at = to_i64(col(r, i, 9));
    a.consumed_by = col_str(r, i, 10);
    a.schedule_id = col_str(r, i, 11);
    a.origin = approval_origin_from_string(col_str(r, i, 12));
    a.target_plugin = col_str(r, i, 13);
    a.target_action = col_str(r, i, 14);
    a.request_json = col_str(r, i, 15);
    a.request_digest = col_str(r, i, 16);
    a.row_version = col_str(r, i, 18);
    a.row_position = col_str(r, i, 19);
    if (auto roots = decode_excluded_roots(col_str(r, i, 17)))
        a.excluded_roots = std::move(*roots);
    else
        a.excluded_roots_unreadable = true;
    return a;
}

// THE canonical column list — every SELECT that feeds row_to_approval uses
// this constant so the column order can never drift between call sites.
constexpr const char* kSelectAllCols =
    "id, definition_id, status, submitted_by, submitted_at, "
    "reviewed_by, reviewed_at, review_comment, scope_expression, "
    "consumed_at, consumed_by, schedule_id, origin, target_plugin, target_action, "
    "request_json, request_digest, excluded_roots, xmin::text, ctid::text";

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    //
    // Folds the SQLite-era v1..v8 ladder into a single v1 DDL — every column
    // the ladder added (consumed_at/consumed_by/schedule_id/origin/
    // target_plugin/target_action) and all six indexes are present from
    // creation on a fresh Postgres schema (ADR-0009 fresh-start-by-default);
    // there is no pre-existing population to back-fill, so v7's
    // `origin = 'legacy'` rewrite (the SQLite ladder's only DML migration)
    // has nothing to run against and is dropped — see approval_manager.hpp's
    // `to_string()` comment for why the DECODE side of that distinction (an
    // unrecognised stored value still refuses) stays live regardless. v8
    // (#1398 dispatch-approval-gate hardening) adds target_plugin/
    // target_action, both '' by default — a mint that leaves either empty
    // (every non-schedule submit path) simply never matches
    // `fire_with_approval`'s equality check, the correct fail-closed outcome
    // (ADR-0033 §1), not a state requiring back-fill.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE approvals ("
         "  id                TEXT    PRIMARY KEY,"
         "  definition_id     TEXT    NOT NULL,"
         "  status            TEXT    NOT NULL DEFAULT 'pending',"
         "  submitted_by      TEXT    NOT NULL DEFAULT '',"
         "  submitted_at      BIGINT  NOT NULL DEFAULT 0,"
         "  reviewed_by       TEXT    NOT NULL DEFAULT '',"
         "  reviewed_at       BIGINT  NOT NULL DEFAULT 0,"
         "  review_comment    TEXT    NOT NULL DEFAULT '',"
         "  scope_expression  TEXT    NOT NULL DEFAULT '',"
         "  consumed_at       BIGINT  NOT NULL DEFAULT 0,"
         "  consumed_by       TEXT    NOT NULL DEFAULT '',"
         "  schedule_id       TEXT    NOT NULL DEFAULT '',"
         "  origin            TEXT    NOT NULL DEFAULT '',"
         "  target_plugin     TEXT    NOT NULL DEFAULT '',"
         "  target_action     TEXT    NOT NULL DEFAULT ''"
         ");"
         "CREATE INDEX idx_approvals_status ON approvals(status);"
         "CREATE INDEX idx_approvals_submitted_at ON approvals(submitted_at);"
         "CREATE INDEX idx_approvals_definition ON approvals(definition_id);"
         "CREATE INDEX idx_approvals_schedule_id ON approvals(schedule_id);"
         // v6 (SQLite era): make the two status-scoped access patterns
         // index-covered. MEASURED on a synthetic SQLite table at 1M rows:
         // query() 112ms -> 0.34ms, the approved-unconsumed sweep 100ms ->
         // 0.01ms. Postgres's own planner benefits identically from these.
         "CREATE INDEX idx_approvals_status_submitted ON approvals(status, submitted_at);"
         "CREATE INDEX idx_approvals_status_consumed_reviewed "
         "  ON approvals(status, consumed_at, reviewed_at);"},
        // v2 (#6096): LEGACY MIGRATION, data only. Before #6096 a scheduled ticket was never
        // marked used; ScheduleRunner recognised a spent one by comparing its process-clock
        // submitted_at with the schedule's last_executed_at. That comparison is gone and a
        // ticket is now eligible only while consumed_at = 0, so every pre-upgrade ticket
        // the old rule would have called spent looks unspent. This retires ALL unsettled
        // approved/rejected tickets of every schedule, once per database, with no clock
        // comparison: the deny direction (a legitimate approved-but-unfired ticket at upgrade
        // time just gets a fresh ask). Idempotent; a fresh database matches no row.
        // The runner sends the step as one message inside the step's transaction, and SET
        // LOCAL was verified to take effect in that shape (also over a shorter session-level
        // timeout), so this one statement is bounded at 300 s without leaking onto the pooled
        // connection. It touches EVERY unsettled approved or rejected scheduled ticket,
        // including old rejected ones (rejected tickets never expire and are never swept);
        // normally small, and bounded by that timeout.
        {2,
         std::string("SET LOCAL statement_timeout = '300s';"
                     "UPDATE approvals SET consumed_at = ") + kDbNowEpochSql +
             ", consumed_by = 'schedule:legacy-6096' WHERE schedule_id <> '' AND "
             "consumed_at = 0 AND status IN ('approved','rejected');"},
        // v3 (#6062, four-eyes MVP PR2): the bound-approval columns. Ordered AFTER #6096's
        // v2 (a data-only legacy-ticket retire) because that step claimed v2 first; the two
        // are independent. Additive, with constant defaults (instant on PG11+, no table
        // rewrite), so every existing row reads as "binds no request, excludes nobody" and keeps working
        // unchanged. '' rather than NULL, matching every other column in this table
        // and the store-wide convention: the three are text the reader can always
        // fetch without a null branch. They are written once, at INSERT, by
        // submit_bound(); no UPDATE in this file touches them, which is what
        // "frozen at mint" means here.
        // IF NOT EXISTS makes the step idempotent on purpose: a development or UAT database
        // that ran an earlier build of this branch recorded these same columns as version 2,
        // so it reaches this step already holding them. Nothing else changes for it, and a
        // database without them gets them exactly as before.
        {3,
         "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS request_json   TEXT NOT NULL DEFAULT '';"
         "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS request_digest TEXT NOT NULL DEFAULT '';"
         "ALTER TABLE approvals ADD COLUMN IF NOT EXISTS excluded_roots TEXT NOT NULL DEFAULT '';"},
    };
    return kMigrations;
}

} // namespace

bool reviewer_is_excluded(const std::string& reviewer,
                          const std::vector<std::string>& excluded_roots) {
    return std::any_of(excluded_roots.begin(), excluded_roots.end(),
                       [&](const std::string& root) { return same_human_root(reviewer, root); });
}

bool approval_state_is_approvable(const Approval& a) {
    return !a.excluded_roots_unreadable &&
           !request_binding_fault(a.request_json, a.request_digest, /*require_readable=*/true)
                .has_value();
}

ApprovalManager::ApprovalManager(pg::PgPool& pool) : pool_(pool) {
    // Construction-only unbounded acquire (ADR-0012 §2) — every runtime
    // acquire elsewhere in this file is bounded.
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error(
            "ApprovalManager: no database connection at construction ({}) — approval "
            "manager disabled",
            pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("ApprovalManager: schema migration failed — approval manager disabled");
        return;
    }
    open_ = true;
    // ADR-0009's 2026-08-25 fresh-start-by-default amendment: no
    // migrate_from_sqlite here, unconditionally, no flag. The caller
    // (server.cpp) separately runs legacy_sqlite_probe::warn_if_legacy_rows()
    // over the legacy instructions.db so a locally-wrong "no production
    // fleet" premise still gets a loud signal.
    spdlog::info("ApprovalManager initialized (schema {}) — fresh start, no legacy backfill",
                 kStoreName);
}

// ---------------------------------------------------------------------------
// Submit
// ---------------------------------------------------------------------------

std::expected<std::string, std::string>
ApprovalManager::submit(const std::string& definition_id, const std::string& submitted_by,
                        const std::string& scope_expression, const std::string& schedule_id,
                        ApprovalOrigin origin, std::string target_plugin,
                        std::string target_action) {
    // A surface whose tickets bind a request cannot be minted unbound: the redeemer
    // would find an empty request_json and nothing for the reviewer to have seen.
    if (requires_bound_request(origin))
        return std::unexpected(std::string{kBoundRequestRequiredMessage});
    auto r = submit_impl(definition_id, submitted_by, scope_expression, schedule_id, origin,
                         /*bound=*/nullptr, std::move(target_plugin), std::move(target_action));
    if (!r)
        return std::unexpected(std::move(r.error().message));
    return std::move(*r);
}

std::expected<std::string, SubmitError>
ApprovalManager::submit_bound(const std::string& definition_id, const std::string& submitted_by,
                              const std::string& scope_expression, ApprovalOrigin origin,
                              const BoundRequest& bound, std::string target_plugin,
                              std::string target_action) {
    // The schedule id is fixed empty here, not taken from the caller: see the header.
    return submit_impl(definition_id, submitted_by, scope_expression, std::string{}, origin, &bound,
                       std::move(target_plugin), std::move(target_action));
}

std::expected<std::string, SubmitError>
ApprovalManager::submit_impl(const std::string& definition_id, const std::string& submitted_by,
                             const std::string& scope_expression, const std::string& schedule_id,
                             ApprovalOrigin origin, const BoundRequest* bound,
                             std::string target_plugin, std::string target_action) {
    const auto fail = [](SubmitFailure kind, std::string message) {
        return std::unexpected(SubmitError{kind, std::move(message)});
    };
    if (!open_)
        return fail(SubmitFailure::kStoreError, "database not open");
    if (definition_id.empty())
        return fail(SubmitFailure::kInvalidRequest, "definition_id is required");
    if (submitted_by.empty())
        return fail(SubmitFailure::kInvalidRequest, "submitted_by is required");

    // Everything that can be decided from the arguments alone is decided BEFORE the
    // lock, the id draw and the transaction: a refused mint costs nothing and writes
    // nothing. `request_digest` and `excluded_roots_text` stay empty for an unbound
    // mint (the column defaults), which is what "binds nothing" means.
    std::string request_json;
    std::string request_digest;
    std::string excluded_roots_text;
    if (bound != nullptr) {
        // A gated effect needs a human requester root (ADR-0033 section 7): an
        // engine principal's root is its owner, and letting it submit would let a
        // machine identity raise the approval a human then rubber-stamps.
        if (submitted_by.starts_with("engine:"))
            return fail(SubmitFailure::kEnginePrincipal, kEnginePrincipalSubmitMessage);
        if (!names_concrete_surface(origin))
            return fail(SubmitFailure::kInvalidRequest,
                        "a bound approval must declare a concrete origin");
        if (bound->request_json.empty() || bound->request_json.size() > kMaxRequestJsonBytes)
            return fail(SubmitFailure::kInvalidRequest,
                        "request_json is required and at most " +
                            std::to_string(kMaxRequestJsonBytes) + " bytes");
        // A NUL byte anywhere is refused BEFORE parsing. nlohmann accepts one after a
        // complete value (it reads as end of input), the digest below covers every
        // byte, and pg::exec_params binds the column as a C string - so the row would
        // keep the prefix while the digest named the full buffer, and a reviewer would
        // see a request whose digest matches neither it nor any recompute.
        if (bound->request_json.find('\0') != std::string::npos)
            return fail(SubmitFailure::kInvalidRequest,
                        "request_json must not contain a NUL byte");
        const auto parsed =
            nlohmann::json::parse(bound->request_json, nullptr, /*allow_exceptions=*/false);
        if (!parsed.is_object())
            return fail(SubmitFailure::kInvalidRequest, "request_json must be a JSON object");
        if (nests_deeper_than(parsed, kMaxRequestJsonDepth))
            return fail(SubmitFailure::kInvalidRequest,
                        "request_json is nested more than " +
                            std::to_string(kMaxRequestJsonDepth) + " levels deep");
        if (bound->excluded_roots.size() > kMaxExcludedRoots)
            return fail(SubmitFailure::kInvalidRequest,
                        "at most " + std::to_string(kMaxExcludedRoots) + " excluded roots");
        for (const auto& root : bound->excluded_roots) {
            if (root.empty() || root.size() > kMaxExcludedRootBytes)
                return fail(SubmitFailure::kInvalidRequest,
                            "each excluded root must be 1-" +
                                std::to_string(kMaxExcludedRootBytes) + " bytes");
            // A principal name carries no control character; one that did could never
            // equal a reviewer name, so it would be an exclusion that excludes nobody.
            if (std::any_of(root.begin(), root.end(), [](char c) {
                    const auto u = static_cast<unsigned char>(c);
                    return u < 0x20 || u == 0x7F;
                }))
                return fail(SubmitFailure::kInvalidRequest,
                            "an excluded root must not contain a control character");
        }
        if (!bound->excluded_roots.empty()) {
            // STRICT encode: see encode_excluded_roots.
            auto encoded = encode_excluded_roots(bound->excluded_roots);
            if (!encoded)
                return fail(SubmitFailure::kInvalidRequest,
                            "excluded roots must be valid UTF-8");
            excluded_roots_text = std::move(*encoded);
        }
        auto digest = sha256_hex(bound->request_json);
        if (!digest)
            return fail(SubmitFailure::kStoreError, "request digest could not be computed");
        request_json = bound->request_json;
        request_digest = std::move(*digest);
    }
    // NO mint-time refusal for the reserved namespace. #2442 is defended at
    // REDEMPTION (see consume_ticket) instead, deliberately:
    //
    //  - Refusing here strands pre-existing operator content. A definition
    //    already under `mcp.` with a schedule submits via kSchedule on every
    //    fire; refused at mint, that schedule can never run again, and moving a
    //    schedule between definitions is not supported (#2742).
    //  - The redemption guard covers more: a ticket minted before the GUARD
    //    existed, or by a surface that declares itself later, is refused at the
    //    point of use rather than only at the point of mint. NOT "strictly
    //    more" — that claim was false and is why migration v7 back-fills a
    //    sentinel. A row minted before the COLUMN existed carries no surface at
    //    all, and '' is the granting case; only the back-fill closes it. A
    //    future caller that omits the defaulted `origin` argument is in the
    //    same class.
    //  - Authoring is still refused where authoring happens —
    //    `instruction_yaml.cpp` and `instruction_store.cpp` both call
    //    `is_reserved_definition_id`, and `reserved_definition_id.hpp` warns
    //    that a further call site is "another chance to diverge". This was it.

    std::lock_guard lock(mtx_);

    auto id_r = generate_id();
    if (!id_r)
        return fail(SubmitFailure::kStoreError, id_r.error());
    auto id = *id_r;
    // Cutoffs and every stamp, submitted_at included, come from the database clock (see
    // kDbNowEpochSql above), never from this process.
    const std::string ttl = std::to_string(kApprovalTicketTtlSeconds);
    const std::string db_now = kDbNowEpochSql;
    const std::string live_sql = ticket_live_sql();

    // Queue cap + lazy expiry sweep + insert as one bounded transaction
    // (runs on every mint, still serialized process-locally by mtx_ above —
    // multi-replica coordination of this check-then-act is an ADR-2002 (HA)
    // concern, not addressed here). One shared 7-day expiry window,
    // deliberately simple:
    //   * PENDING tickets nobody reviewed within 7 days of submission expire.
    //   * APPROVED-but-unconsumed tickets expire 7 days after their review
    //     (PR #1796 review N3): an approved ticket is a live one-time
    //     capability — the recall executes the gated tool with no further
    //     human step — so without a TTL a forgotten approval leaks a
    //     forever-valid capability token into backups/log dumps. The recall
    //     path treats an expired ticket exactly like a rejected one (submit a
    //     fresh request); consumed tickets (consumed_at != 0) are history, not
    //     capabilities, and are never touched.
    // Counts come from PQntuples on the RETURNING result — never a bare
    // affected-row count (#1033's SQLite shared-connection race has no
    // Postgres analogue on a per-lease connection, but RETURNING is kept as
    // the uniform idiom across every store in this ladder).
    std::string queue_full_error;
    // Sweep counts, logged AFTER the transaction commits (governance PR
    // review, 2026-08-31, Doomgoose) — logging inside the lambda claims an
    // action happened before it is known to have survived; a later
    // statement in the SAME transaction (the cap check, the insert) can
    // still roll the whole thing back, which would make an "expired N"
    // info line false.
    int expired_pending_committed = 0;
    int expired_approved_committed = 0;
    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // Expiry sweep runs BEFORE the pending-count cap check, not after: the
        // cap is exactly the state the sweep exists to relieve, and a stale
        // queue full of 1000 unreviewed tickets must not be able to wedge
        // itself past its own recovery path (governance adversarial review,
        // 2026-08-31 — the sweep-after-cap ordering made a full stale queue
        // permanently unrecoverable without manual database intervention).
        const std::string sweep_pending_sql =
            "UPDATE approval_manager.approvals SET status = 'expired' "
            "WHERE status = 'pending' AND submitted_at < (" + db_now + " - $1::bigint) "
            "RETURNING 1";
        pg::PgResult exp = pg::exec_params(conn, sweep_pending_sql.c_str(),
                                           std::vector<std::string>{ttl});
        if (exp.status() != PGRES_TUPLES_OK)
            return false;
        int expired_pending = PQntuples(exp.get());

        const std::string sweep_approved_sql =
            "UPDATE approval_manager.approvals SET status = 'expired' "
            "WHERE status = 'approved' AND consumed_at = 0 AND NOT " + live_sql +
            " RETURNING 1";
        pg::PgResult expa = pg::exec_params(conn, sweep_approved_sql.c_str(),
                                            std::vector<std::string>{});
        if (expa.status() != PGRES_TUPLES_OK)
            return false;
        int expired_approved = PQntuples(expa.get());

        pg::PgResult cnt = pg::exec_params(
            conn, "SELECT COUNT(*) FROM approval_manager.approvals WHERE status = 'pending'",
            std::vector<std::string>{});
        if (cnt.status() != PGRES_TUPLES_OK)
            return false;
        int pending = static_cast<int>(to_i64(col(cnt.get(), 0, 0)));
        if (pending >= kMaxPendingApprovals) {
            // Clock-guard signal (governance cpp-safety, 2026-08-31): a
            // backward clock skew of the DATABASE host (NTP correction, VM
            // snapshot restore) moves the cutoff into the past, so the sweep
            // above matches nothing even though it should have — this WARN is
            // the only thing that distinguishes that anomaly from an ordinary,
            // healthy full queue, both of which otherwise look identical
            // ("queue is full" with zero rows just expired). Not a full clock-guard apparatus
            // (ADR-0065's "Expiry-sweep clock-guard adjudication": this sweep
            // is a state-transition UPDATE, never a DELETE, so the
            // irreversible-loss trigger the full 7-part apparatus exists for
            // is not met) — a log line an operator can alert on is
            // proportionate to the risk.
            if (expired_pending == 0) {
                spdlog::warn(
                    "ApprovalManager: pending queue at cap ({}) and the stale-pending sweep "
                    "expired nothing — if this persists, check the database host's clock (ttl={}s)",
                    kMaxPendingApprovals, kApprovalTicketTtlSeconds);
            }
            queue_full_error = "approval queue is full (" +
                               std::to_string(kMaxPendingApprovals) + " pending)";
            return false;
        }

        const std::string insert_sql =
            "INSERT INTO approval_manager.approvals "
            "(id, definition_id, status, submitted_by, submitted_at, "
            " reviewed_by, reviewed_at, review_comment, scope_expression, schedule_id, origin, "
            " target_plugin, target_action, request_json, request_digest, excluded_roots) "
            "VALUES ($1,$2,'pending',$3," + db_now + ",'',0,'',$4,$5,$6,$7,$8,$9,$10,$11)";
        pg::PgResult ins = pg::exec_params(
            conn, insert_sql.c_str(),
            std::vector<std::string>{id, definition_id, submitted_by, scope_expression,
                                     schedule_id, to_string(origin), target_plugin,
                                     target_action, request_json, request_digest,
                                     excluded_roots_text});
        if (ins.status() != PGRES_COMMAND_OK)
            return false;
        expired_pending_committed = expired_pending;
        expired_approved_committed = expired_approved;
        return true;
    });

    if (!ok) {
        if (!queue_full_error.empty())
            return fail(SubmitFailure::kQueueFull, queue_full_error);
        return fail(SubmitFailure::kStoreError, "insert failed (pool degraded or transaction failed)");
    }
    if (expired_pending_committed > 0)
        spdlog::info("ApprovalManager: expired {} stale pending approvals",
                     expired_pending_committed);
    if (expired_approved_committed > 0)
        spdlog::info("ApprovalManager: expired {} approved-but-unconsumed approval tickets",
                     expired_approved_committed);

    spdlog::info("ApprovalManager: submitted approval {} for definition {} by {}", redact_id(id),
                 definition_id, submitted_by);
    return id;
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

const std::vector<std::string>& ApprovalManager::allowed_status() {
    static const std::vector<std::string> v = {"pending", "approved", "rejected", "expired"};
    return v;
}

std::vector<Approval> ApprovalManager::query(const ApprovalQuery& q) const {
    std::vector<Approval> results;
    if (!open_)
        return results;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return results;

    std::string sql =
        std::string("SELECT ") + kSelectAllCols + " FROM approval_manager.approvals WHERE 1=1";
    std::vector<std::string> params;
    int idx = 1;

    if (!q.status.empty()) {
        sql += " AND status = $" + std::to_string(idx++);
        params.push_back(q.status);
    }
    if (!q.submitted_by.empty()) {
        sql += " AND submitted_by = $" + std::to_string(idx++);
        params.push_back(q.submitted_by);
    }
    // `id DESC` tiebreaker (unhappy-path governance finding, #2146 A2-R4):
    // submitted_at has no uniqueness constraint, so a tie straddling the
    // LIMIT boundary was non-deterministic across identical calls -- id is
    // TEXT PRIMARY KEY, always unique, so appending it makes the result
    // order fully deterministic.
    sql += " ORDER BY submitted_at DESC, id DESC LIMIT " + std::to_string(kApprovalListCap);

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK)
        return results;

    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        results.push_back(row_to_approval(res.get(), i));
    return results;
}

// Checked twin of query() above (#2146 A2-R4): the same three degraded
// conditions that method silently folds into an empty vector -- store not
// open, pool-lease timeout, and a failed SQL query -- are reported as
// std::unexpected here instead, mirroring get_checked's shape (this class's
// own established checked-read convention) so REST v1 `GET /api/v1/approvals`
// and MCP `list_pending_approvals` can emit an honest 503/retry_after_ms
// rather than serializing a false empty-list response.
//
// Resource Ledger (gov cpp-safety, #2146 A2-R4 fix round): this function and
// pending_count_checked() below each acquire one pg::PgPool::Lease (owner
// move-only/non-copyable, `pool_.try_acquire_for`) and one pg::PgResult
// (owner RAII, PQclear on scope exit, via pg::exec_params). Both are
// stack-local and released by destructor on every path, including every
// early std::unexpected return -- no manual cleanup, no borrow escapes past
// either object's scope (row_to_approval copies every column into owned
// std::string/int64_t fields before the PgResult goes out of scope).
std::expected<ApprovalListResult, StoreReadError>
ApprovalManager::query_checked(const ApprovalQuery& q) const {
    if (!open_) {
        spdlog::warn("ApprovalManager::query_checked degraded: store not open");
        return std::unexpected(StoreReadError{"database not open"});
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::warn("ApprovalManager::query_checked degraded: pool exhausted");
        return std::unexpected(
            StoreReadError{"approval store temporarily unavailable (pool exhausted)"});
    }

    std::string sql =
        std::string("SELECT ") + kSelectAllCols + " FROM approval_manager.approvals WHERE 1=1";
    std::vector<std::string> params;
    int idx = 1;

    if (!q.status.empty()) {
        sql += " AND status = $" + std::to_string(idx++);
        params.push_back(q.status);
    }
    if (!q.submitted_by.empty()) {
        sql += " AND submitted_by = $" + std::to_string(idx++);
        params.push_back(q.submitted_by);
    }
    // Query one row PAST the cap so a match count of EXACTLY kApprovalListCap
    // is never misreported as truncated -- the simpler "returned == limit"
    // heuristic false-positives on that boundary (matches
    // ScheduleEngine::query_schedules_checked's identical technique,
    // schedule_engine.cpp). The sentinel row is trimmed back off below, never
    // returned to the caller. `id DESC` tiebreaker: see query() above.
    sql += " ORDER BY submitted_at DESC, id DESC LIMIT " + std::to_string(kApprovalListCap + 1);

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("ApprovalManager::query_checked degraded: query failed: {}",
                     PQresultErrorMessage(res.get()));
        return std::unexpected(StoreReadError{
            std::string("read failed: ") + PQresultErrorMessage(res.get()), result_sqlstate(res)});
    }

    ApprovalListResult out;
    const int rows = PQntuples(res.get());
    out.truncated = rows > kApprovalListCap;
    const int take = out.truncated ? kApprovalListCap : rows;
    out.approvals.reserve(static_cast<std::size_t>(take));
    for (int i = 0; i < take; ++i)
        out.approvals.push_back(row_to_approval(res.get(), i));
    return out;
}

// ---------------------------------------------------------------------------
// Pending count
// ---------------------------------------------------------------------------

int ApprovalManager::pending_count() const {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return 0;

    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT COUNT(*) FROM approval_manager.approvals WHERE status = 'pending'",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return 0;
    return static_cast<int>(to_i64(col(res.get(), 0, 0)));
}

// Checked twin of pending_count() above (#2146 A2-R4): the same three
// degraded conditions that method silently folds into 0 -- store not open,
// pool-lease timeout, and a failed SQL query -- are reported as
// std::unexpected here instead, identical to a real "zero pending approvals"
// count otherwise. Feeds REST v1 `GET /api/v1/approvals/pending/count` and
// MCP `get_pending_approval_count`.
std::expected<int, StoreReadError> ApprovalManager::pending_count_checked() const {
    if (!open_) {
        spdlog::warn("ApprovalManager::pending_count_checked degraded: store not open");
        return std::unexpected(StoreReadError{"database not open"});
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::warn("ApprovalManager::pending_count_checked degraded: pool exhausted");
        return std::unexpected(
            StoreReadError{"approval store temporarily unavailable (pool exhausted)"});
    }

    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT COUNT(*) FROM approval_manager.approvals WHERE status = 'pending'",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("ApprovalManager::pending_count_checked degraded: query failed: {}",
                     PQresultErrorMessage(res.get()));
        return std::unexpected(StoreReadError{
            std::string("read failed: ") + PQresultErrorMessage(res.get()), result_sqlstate(res)});
    }
    return static_cast<int>(to_i64(col(res.get(), 0, 0)));
}

int ApprovalManager::pending_count_for(const std::string& submitted_by) const {
    if (!open_ || submitted_by.empty())
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return 0;

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT COUNT(*) FROM approval_manager.approvals "
        "WHERE status = 'pending' AND submitted_by = $1",
        std::vector<std::string>{submitted_by});
    if (res.status() != PGRES_TUPLES_OK)
        return 0;
    return static_cast<int>(to_i64(col(res.get(), 0, 0)));
}

// ---------------------------------------------------------------------------
// Get by id (#289 — MCP approval-ticket recall)
// ---------------------------------------------------------------------------

std::optional<Approval> ApprovalManager::get(const std::string& id) const {
    auto r = get_checked(id);
    return r ? std::move(*r) : std::nullopt;
}

std::expected<std::optional<Approval>, StoreReadError>
ApprovalManager::get_checked(const std::string& id) const {
    if (!open_)
        return std::unexpected(StoreReadError{"database not open"});
    if (id.empty())
        return std::unexpected(StoreReadError{"approval id is required"});

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(StoreReadError{"approval store temporarily unavailable "
                                              "(pool exhausted)"});
    return read_row(lease.get(), id, /*for_update=*/false);
}

std::expected<std::optional<Approval>, StoreReadError>
ApprovalManager::read_row(PGconn* conn, const std::string& id, bool for_update) const {
    std::string sql = std::string("SELECT ") + kSelectAllCols +
                      " FROM approval_manager.approvals WHERE id = $1";
    if (for_update)
        sql += " FOR UPDATE";
    pg::PgResult res = pg::exec_params(conn, sql.c_str(), std::vector<std::string>{id});

    // A read that FAILED is not a read that found nothing. Collapsing the two is what
    // let a store error be reported to the operator as "this one-time capability is
    // spent" - see the pre-consume path in consume_core.
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(StoreReadError{
            std::string("read failed: ") + PQresultErrorMessage(res.get()), result_sqlstate(res)});

    std::optional<Approval> out;
    if (PQntuples(res.get()) > 0)
        out = row_to_approval(res.get(), 0);
    return out;
}

// ---------------------------------------------------------------------------
// Find an existing PENDING approval matching (definition_id, submitted_by,
// scope_expression) — the MCP approval-ticket mint dedup key (#289 / governance
// UP-1). Returning the extant ticket instead of minting a new one makes the mint
// idempotent and bounds a single principal's junk to distinct (tool,args) tuples,
// so a supervised token can no longer flood the GLOBAL pending-approval cap
// shared with the REST instruction-approval workflow. Newest match wins.
// ---------------------------------------------------------------------------

std::optional<Approval> ApprovalManager::find_pending(const std::string& definition_id,
                                                      const std::string& submitted_by,
                                                      const std::string& scope_expression) const {
    if (!open_ || definition_id.empty() || submitted_by.empty())
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;

    // NO `LIMIT 1`. The newest match is not necessarily a usable one: since the
    // mint-time namespace refusal was removed, a ticket carrying a declared
    // non-MCP surface can sit in this dedup key. Handing one back would return a
    // ticket THIS CALLER'S OWN RECALL WILL REFUSE (`kForeignOrigin`) — so an
    // administrator reviews and approves a request that can never complete, and
    // a human approval is spent on a flow with no successful outcome.
    //
    // Filtered in C++ through the SHARED predicate (`origin_redeemable_as`, the
    // one consume_ticket applies) rather than a second, hand-written SQL copy of
    // the rule. A copy in a WHERE clause is a second home for it, and the two
    // would drift the first time the enum grows.
    //
    // Walk newest-first and take the first REDEEMABLE candidate, rather than
    // taking the newest and rejecting it — an older undeclared ticket under the
    // same key is a perfectly good dedup hit, and skipping it would mint a
    // duplicate.
    std::string sql = std::string("SELECT ") + kSelectAllCols +
                      " FROM approval_manager.approvals WHERE definition_id = $1 "
                      "AND submitted_by = $2 AND scope_expression = $3 AND status = 'pending' "
                      "ORDER BY submitted_at DESC";
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(),
        std::vector<std::string>{definition_id, submitted_by, scope_expression});
    if (res.status() != PGRES_TUPLES_OK)
        return std::nullopt;

    const int rows = PQntuples(res.get());
    for (int i = 0; i < rows; ++i) {
        Approval a = row_to_approval(res.get(), i);
        if (origin_redeemable_as(a.origin, ApprovalOrigin::kMcp))
            return a;
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Consume (#289 — one-time MCP approval ticket)
// ---------------------------------------------------------------------------

std::expected<void, ConsumeError>
ApprovalManager::consume_ticket(const std::string& id, const std::string& consumed_by,
                                ApprovalOrigin expected, const ConsumePrecondition& precondition) {
    return consume_core(/*held=*/nullptr, id, consumed_by, expected, precondition);
}

std::expected<void, ConsumeError>
ApprovalManager::consume_ticket(PGconn* conn, const std::string& id, const std::string& consumed_by,
                                ApprovalOrigin expected, const ConsumePrecondition& precondition) {
    // A null connection must NOT fall through to consume_core's `held == nullptr`
    // meaning ("take your own leases"): that would silently turn a caller's
    // transaction-joined consume into an autocommit one, the exact thing this
    // overload exists to rule out.
    if (conn == nullptr)
        return std::unexpected(
            ConsumeError{ConsumeFailure::kStoreError, "a transaction connection is required"});
    return consume_core(conn, id, consumed_by, expected, precondition);
}

std::expected<void, ConsumeError>
ApprovalManager::consume_core(PGconn* held, const std::string& id, const std::string& consumed_by,
                              ApprovalOrigin expected, const ConsumePrecondition& precondition) {
    // These three guards are NOT store faults — `sqlstate` stays at its
    // default empty. For `!open_`, that default is harmless: `!mgr.is_open()`
    // independently forces `approval_store_error_body`'s PERMANENT arm
    // regardless of `sqlstate`, so this guard never reaches the TRANSIENT
    // wording. For the other two (empty id/consumed_by), the store IS
    // open, so an empty `sqlstate` alone (not one of the permanent classes)
    // DOES take the transient arm ("retry this call unchanged") if this
    // `kStoreError` ever reaches `approval_store_error_body` — and that's
    // misleading, since these are caller/argument errors, not conditions
    // that clear on their own. Harmless today: the MCP recall (the sole
    // production caller) pre-validates a non-empty `supplied_id` before
    // calling, and `consumed_by` is the session's own username, never empty
    // for an authenticated caller. A future caller that reaches this
    // function without that pre-validation should not trust the transient
    // wording for these two cases.
    if (!open_)
        return std::unexpected(ConsumeError{ConsumeFailure::kStoreError, "database not open"});
    if (id.empty())
        return std::unexpected(
            ConsumeError{ConsumeFailure::kStoreError, "approval id is required"});
    // SOC-2 CC7.2 (PR #1796 H3/N2): a consumption with no attributable principal
    // would be an evidence-chain hole — fail the recall closed instead.
    if (consumed_by.empty())
        return std::unexpected(
            ConsumeError{ConsumeFailure::kStoreError, "consumed_by is required"});
    // #6062: the caller must name a concrete surface. kUnspecified / kUnrecognised as
    // `expected` ALWAYS refuse - checked here, before any read, so a caller that
    // declared nothing learns nothing about the row and the row is never touched.
    // Reported as kForeignOrigin (uniform message) so it lands in the same audit
    // class as every other origin refusal.
    if (!origin_redeemable_as(expected, expected)) {
        spdlog::warn("ApprovalManager: consume of ticket {} refused: the caller declared no "
                     "concrete surface",
                     redact_id(id));
        return std::unexpected(ConsumeError{ConsumeFailure::kForeignOrigin, kNotConsumableMessage});
    }

    // #2442 CROSS-SURFACE + CROSS-SUBMITTER BINDING. Approvals are one shared
    // store with three mint paths, and this recall matches a ticket on its
    // definition id and scope expression — neither of which names the
    // minting surface, and neither of which is bound to who redeems it. So an
    // approval raised through the REST instruction gate, where both fields are
    // caller-influenced, could line up with an MCP tool's canonical arguments
    // and be redeemed against it; and separately, an id disclosed to any
    // `Approval:Read` holder (e.g. `GET /api/approvals`) could be redeemed by
    // a principal other than the one it was granted to. What both buy is the
    // HUMAN APPROVAL itself: the reviewer sees a ticket id, a submitter and a
    // scope expression, and nothing that names the SURFACE it was raised on
    // or BINDS who may present it. (The tool is named: `definition_id` is on
    // the row, and must be exactly `mcp.<tool>` for the surface confusion to
    // work at all — that is the premise of the reserved prefix.)
    //
    // get_checked, not get: a FAILED read must not decode as an absent row —
    // `get` collapsed the two, and a transient store fault reading as "no
    // such row" is exactly the burn class the guard clause below (masked
    // denial) exists to close. There is no submitter-side equivalent of
    // kUnspecified's old grant: an empty `submitted_by` never equals a
    // non-empty `consumed_by` (the empty-argument guard above already
    // refused an empty `consumed_by`), so a missing submitter simply
    // mismatches and refuses like any other wrong value.
    //
    // Runs BEFORE the precondition block because that block is conditional —
    // a caller supplying no precondition must not skip this.
    //
    // `read_row(held, ..., for_update)` on the caller's own connection, or
    // `get_checked` (its own bounded lease) on the pooled path. On the held path the
    // row is locked FOR UPDATE here and stays locked to the end of the caller's
    // transaction, so the origin/submitter/status facts read below cannot move before
    // the CAS.
    //
    // TEST DEPENDENCY: this read has TWO implementations and each has its own fault
    // test. Pooled (`get_checked`, its own bounded lease): test_approval_manager.cpp
    // asserts `binding_check_unevaluated=true` + a non-empty `sqlstate` when it fails.
    // Held (`read_row` on the caller's connection, FOR UPDATE): test_approval_manager_bound.cpp
    // fails it with an aborted caller transaction and asserts the same. (ADR-0065: the
    // SQLite-era countdown-authorizer test that isolated this one read has no Postgres
    // analogue and was not ported.) A read added before this one, or a change to either
    // implementation, must keep both tests pointing at THIS read. The submitter and
    // integrity checks below extend this SAME read rather than adding another, for
    // exactly that reason.
    //
    // The redemption integrity re-check (#6062) as a function of one examined row, so it runs
    // on EVERY read this call makes and not just the first. nullopt == sound. See the comment
    // at its first use below for the kind it returns and why.
    const auto integrity_refusal = [&](const Approval& a) -> std::optional<ConsumeError> {
        if (a.status != "approved" || a.consumed_at != 0)
            return std::nullopt;
        const auto fault = approval_integrity_fault(a);
        if (!fault)
            return std::nullopt;
        // A caller retries a refused ticket, so the line is throttled per ticket (one error per
        // id prefix per minute, repeats at debug) like the other repeated refusal lines. The
        // refusal itself, and the caller's own audit row, are never throttled.
        static RefusalLogThrottle integrity_throttle;
        if (integrity_throttle.should_warn(redact_id(id)))
            spdlog::error("ApprovalManager: ticket {} failed its redemption integrity "
                          "check ({}); refusing",
                          redact_id(id), fault->cause);
        else
            spdlog::debug("ApprovalManager: ticket {} still fails its redemption integrity check",
                          redact_id(id));
        if (fault->unevaluated)
            return ConsumeError{ConsumeFailure::kStoreError,
                                "approval integrity check could not run",
                                /*sqlstate=*/{}, /*binding_check_unevaluated=*/true};
        return ConsumeError{ConsumeFailure::kForeignOrigin, kNotConsumableMessage};
    };
    // Everything that decides whether THIS row may be redeemed by THIS caller on THIS surface,
    // as one function of one examined row, applied to EVERY read the call makes (the first,
    // and the precondition's fresher one). Running only part of it on a later read is how a
    // row changed between the reads got consumed on the strength of a state never checked
    // (Gate 8 round 3). nullopt == sound.
    //
    //  - #2442 origin: the ticket's recorded surface must be the one the caller declared.
    //  - #2442 submitter: an approval id disclosed to a third party (e.g. via
    //    `GET /api/approvals`, gated on `Approval:Read`, seeded to Viewer) must not be
    //    redeemable by anyone but the principal it was granted to. Same posture as the origin
    //    check: the uniform message, a distinct KIND for the audit trail only, so the recall
    //    is no probe for whether a ticket exists versus who owns it. Checked after origin, so
    //    a foreign-origin ticket reads as that (the more specific fact).
    //  - #6062 integrity (integrity_refusal above): only for an approved, unconsumed row. A
    //    replay of a consumed ticket, and a pending, rejected or expired one, keep reading as
    //    the ordinary refusal they are; a ticket legitimately rejected by an excluded root
    //    must not look like a forgery.
    //
    // Refused as kForeignOrigin (integrity) with the uniform message: the closest EXISTING
    // kind, so it is counted and audited by every caller like the others, adds no new label
    // value and is indistinguishable from a replay to the redeemer (a digest that could not be
    // computed is the exception: a store error, see integrity_refusal). The cause goes to the
    // server log. A digest that could not be COMPUTED decided nothing, so it is a store
    // error flagged `binding_check_unevaluated`, like a failed read.
    const auto check_examined = [&](const Approval& a) -> std::optional<ConsumeError> {
        if (!origin_redeemable_as(a.origin, expected))
            return ConsumeError{ConsumeFailure::kForeignOrigin, kNotConsumableMessage};
        if (a.submitted_by != consumed_by)
            return ConsumeError{ConsumeFailure::kForeignSubmitter, kNotConsumableMessage};
        return integrity_refusal(a);
    };
    // The row the checks (and, if supplied, the precondition) LAST examined. The consuming CAS
    // below is pinned to the row's version (and to the columns the checks read), so a decision made on
    // one state of the row can only be spent against that same state (Gate 8 g8-sg-1).
    std::optional<Approval> examined;
    // The window between a caller's own earlier read of this ticket and the read below: a
    // caller that matched the ticket to its request BEFORE calling here must re-check the row
    // this function examines (the precondition receives it), not rely on its earlier read.
    if (consume_test_hook_)
        consume_test_hook_(ConsumeTestStage::kBeforeFirstRead);
    {
        auto row = held ? read_row(held, id, /*for_update=*/true)
                        : get_checked(id); // pooled: takes its own bounded lease
        if (!row) {
            // #2786 arm 1: this read failing means neither the origin nor the
            // submitter comparison below runs, so a foreign-origin OR
            // foreign-submitter ticket is exactly as likely to be sitting
            // behind this refusal as an innocent one — the forgery signal is
            // masked for the duration of the fault. Flag it and log it here,
            // at the store, so every consume_ticket caller (today only the
            // MCP recall) gets the signal without duplicating this check.
            spdlog::warn("ApprovalManager: binding check for ticket {} could not be evaluated "
                        "(store fault: {}); refusing closed",
                        redact_id(id), row.error().message);
            return std::unexpected(ConsumeError{ConsumeFailure::kStoreError, row.error().message,
                                                row.error().sqlstate,
                                                /*binding_check_unevaluated=*/true});
        }
        // The binding, submitter and integrity checks, ONE function applied to this read.
        if (*row)
            if (auto refusal = check_examined(**row))
                return std::unexpected(std::move(*refusal));
        examined = *row;
    }

    if (precondition && consume_test_hook_)
        consume_test_hook_(ConsumeTestStage::kBetweenReads);

    // Pre-consume recheck (#2443). Skipped entirely when no precondition was
    // supplied, so a consume without one issues no second read of the row.
    if (precondition) {
        // get_checked, not get: a FAILED read must not be reported as a row that
        // is not there. Telling the operator a live human-approved ticket is
        // spent, because SQLite was busy for a moment, is the burn class #2443
        // exists to close, re-entered through the taxonomy.
        auto row = held ? read_row(held, id, /*for_update=*/true)
                        : get_checked(id); // pooled: takes its own bounded lease
        if (!row)
            return std::unexpected(ConsumeError{ConsumeFailure::kStoreError, row.error().message,
                                                row.error().sqlstate});
        // This read is FRESHER than the first: it is what the callback is handed and what the
        // CAS is pinned to, so every check runs on it too, not just the integrity one. A row
        // that went bad (or foreign) between the two reads is refused here.
        if (*row)
            if (auto refusal = check_examined(**row))
                return std::unexpected(std::move(*refusal));
        // A row that cannot transition is reported WITHOUT running the
        // precondition: the callback may be costly or emit audit, and the CAS
        // below would decline this row anyway. Same message as the CAS decline,
        // so the two paths are indistinguishable to the caller (they mean the
        // same thing).
        if (!*row || (*row)->status != "approved" || (*row)->consumed_at != 0)
            return std::unexpected(ConsumeError{
                ConsumeFailure::kNotConsumable,
                kNotConsumableMessage});
        examined = *row;
        // The callback is caller code. If it throws, that must not escape a
        // store method as an unhandled exception on an httplib worker: the
        // ticket is untouched either way, so report it as a store error and let
        // the caller answer with its own envelope. Deliberately NOT
        // kPrecondition — a callback that threw did not decide anything.
        std::expected<void, std::string> ok;
        try {
            ok = precondition(**row);
        } catch (const std::exception& e) {
            spdlog::warn("ApprovalManager: pre-consume recheck threw for ticket {}: {}",
                         redact_id(id), e.what());
            // e.what() goes to the LOG, not into the returned message: this
            // string reaches the MCP error envelope, and e.what() is unvetted
            // text from caller code. A precondition's OWN error message does
            // ride along, deliberately — it is authored under the constraints
            // on ConsumePrecondition. Unvetted is the distinction, not origin.
            return std::unexpected(
                ConsumeError{ConsumeFailure::kStoreError, "pre-consume recheck failed"});
        } catch (...) {
            spdlog::warn("ApprovalManager: pre-consume recheck threw a non-std exception for "
                         "ticket {}",
                         redact_id(id));
            return std::unexpected(
                ConsumeError{ConsumeFailure::kStoreError, "pre-consume recheck failed"});
        }
        if (!ok) {
            spdlog::info("ApprovalManager: pre-consume recheck declined ticket {} for {}: {}",
                         redact_id(id), consumed_by, ok.error());
            // #6062: a precondition denial is counted and audited AT THE STORE, whichever
            // surface redeems. Only a redeemer that SUPPLIES a precondition can reach
            // this, and today that is the MCP recall alone (every approval-gated tool, for
            // the request match; confirm_engine_rotation adds its rotation-state check);
            // instruction and schedule tickets are never redeemed and the Guardian
            // surface mints nothing yet, so those labels stay at zero until a redeemer
            // exists. The label is the ticket's own origin, already known to be
            // concrete and equal to `expected` by the binding check above, so it is a
            // closed set.
            if (metrics_)
                metrics_
                    ->counter(kPreconditionDeniedMetric,
                              {{"origin", to_string((*row)->origin)}})
                    .increment();
            if (denial_observer_) {
                try {
                    denial_observer_(
                        PreconditionDenial{id, (*row)->origin, consumed_by, ok.error()});
                } catch (const std::exception& e) {
                    spdlog::warn("ApprovalManager: precondition-denial observer threw for "
                                 "ticket {}: {}",
                                 redact_id(id), e.what());
                } catch (...) {
                    spdlog::warn("ApprovalManager: precondition-denial observer threw for "
                                 "ticket {}",
                                 redact_id(id));
                }
            }
            return std::unexpected(ConsumeError{ConsumeFailure::kPrecondition, ok.error()});
        }
    }

    // Atomic CAS: only an approved, not-yet-consumed ticket transitions. A
    // single Postgres statement is already atomic under the target row's
    // own lock — no app-level mutex needed (mtx_ is scoped to submit()'s
    // compound cap-check + sweep + insert only; see the header). RETURNING
    // carries the "row matched" signal in the result's row count, the same
    // uniform idiom every store in this ladder uses instead of a bare
    // affected-row count. consumed_by rides the same UPDATE so who/when can
    // never disagree.
    if (consume_test_hook_)
        consume_test_hook_(ConsumeTestStage::kBeforeCas);

    // No row was found to examine: there is nothing to pin the CAS to, and nothing it
    // could legitimately consume. (The CAS would match no row anyway; stopping here keeps
    // an UNPINNED consuming statement out of this function altogether.)
    if (!examined)
        return std::unexpected(ConsumeError{ConsumeFailure::kNotConsumable, kNotConsumableMessage});
    // The consuming CAS is PINNED to the row it examined. Two layers:
    //
    //  1. The ROW VERSION: `xmin::text` AND `ctid::text`, both taken from the last read. For DML
    //     (INSERT/UPDATE/DELETE), a statement pinned to the examined pair can only consume the
    //     tuple the checks saw. `xmin` names the (sub)transaction that wrote the version, so an
    //     UPDATE by ANOTHER transaction (any column, any values, a no-op rewrite included) moves
    //     it. A second write at the SAME (sub)transaction level keeps it (every version written
    //     at one level carries that level's xid), which is the held overload's case when the
    //     caller's own transaction already wrote the row, or when its precondition or the test
    //     hook writes it through the held connection; each such write puts the row in a new
    //     tuple, so `ctid` moves where `xmin` cannot. A write after a SAVEPOINT carries the
    //     subtransaction's xid and moves `xmin` too, which only refuses more. Neither value
    //     alone is a version: a plain VACUUM between two other transactions' writes can put the
    //     new tuple back in the examined slot, and only `xmin` then tells them apart. Together
    //     they close the classes the per-column pins below cannot enumerate (consumed_at,
    //     reviewed_at, definition_id, scope_expression, target_*, schedule_id, and any column
    //     added later).
    //  2. The explicit columns the checks read - status, reviewer, frozen request, digest,
    //     excluded roots, origin, submitter - as bound parameters. Implied by (1) for a row that
    //     is the same tuple, and kept as defence in depth, so a regression in the version pin
    //     does not silently reopen the classes they cover.
    //
    // The pooled overload reads on one lease and updates on another, and a precondition runs
    // arbitrary caller code between the two, so without a pin a row rewritten after the check
    // (an old-build replica, a hand edit, a precondition that writes) would be consumed on the
    // strength of a state it no longer has. The status pin matters as much as the rest: a row
    // examined as pending, rejected or expired never had its integrity checked, and must not
    // become spendable by a status-only flip. A pin mismatch matches no row and reads as the
    // uniform kNotConsumable below, never as a store error.
    //
    // WHAT THIS IS NOT. The check and the CAS are still two statements; the pin makes the CAS
    // refuse a row that moved, it does not make them atomic. It is accident and skew detection
    // for a row that changed between statements - an old-build replica, a stray UPDATE, a
    // restore - not a boundary against a principal with database write access: a plain UPDATE
    // cannot choose the version it writes, but a writer who can replace the row wholesale
    // (a restore) or work below SQL is outside what it can tell. `xmin` is the raw 32-bit xid
    // with no epoch, so even the pair is bounded by it: a different writer that received the
    // very same xid after a wraparound and reused the same slot would match.
    //
    // NOT DETECTED, for the HELD overload only: a table-rewriting statement issued by the
    // holding transaction itself between the read and the CAS - CLUSTER, an ALTER TABLE that
    // rewrites the table, TRUNCATE followed by a re-insert - can leave a changed row at the
    // examined (xmin, ctid). A held-overload caller must therefore never run DDL on its
    // connection inside the redeeming transaction (ADR-1009, PR3 entry conditions). The only
    // production caller today is the pooled overload, which cannot reach this.
    //
    // It also fails CLOSED in two more directions, each a refusal that is wrong about the
    // ticket: a no-op rewrite (`SET reviewed_by = reviewed_by`) is a new version, and VACUUM FULL
    // or CLUSTER can move `ctid` of an unchanged row. After either, a retry reads the new
    // version and succeeds. (When the other writer is a concurrent consume or a real edit, the
    // refusal is correct and a retry is refused again.) VACUUM FREEZE changes neither
    // `xmin::text` nor `ctid`, so it refuses nothing.
    //
    // Under the held overload's FOR UPDATE inside a real transaction no OTHER transaction can
    // move the row, but the caller's own transaction can (see layer 1); on an AUTOCOMMIT
    // connection the lock drops after each statement and the pin is what holds (cs-3: refusing
    // an autocommit connection outright, via PQTRANS_INTRANS, is deferred to PR3 - see the
    // ADR-1009 entry conditions).
    const auto pinned_roots = encode_excluded_roots(examined->excluded_roots);
    if (!pinned_roots) // cannot happen for a list decoded from JSON; fail closed regardless
        return std::unexpected(ConsumeError{ConsumeFailure::kNotConsumable, kNotConsumableMessage});

    // Held path: the caller's connection, no lease. Pooled path: one bounded write
    // lease for the CAS and the diagnostic read below.
    pg::PgPool::Lease lease;
    PGconn* conn = held;
    if (conn == nullptr) {
        lease = pool_.try_acquire_for(kWriteTimeout);
        if (!lease)
            return std::unexpected(
                ConsumeError{ConsumeFailure::kStoreError, "approval store temporarily unavailable "
                                                           "(pool exhausted)"});
        conn = lease.get();
    }

    //
    // EXPIRY AT CONSUME (#6061): the 7-day TTL used to be enforced only by
    // submit()'s lazy sweep, so an approved ticket past its TTL stayed
    // redeemable until some unrelated submit() happened to run. The predicate
    // lives in the CAS itself so there is no window between "expired" and
    // "swept". It is the shared `ticket_live_sql()` predicate, on DATABASE time
    // (see kDbNowEpochSql): the lower bound stops a leaked capability outliving
    // its lifetime, the upper bound refuses a `reviewed_at` stamped in the
    // future (UP-3), which the lower bound alone would honour indefinitely.
    const std::string consume_sql =
        std::string("UPDATE approval_manager.approvals SET consumed_at = ") + kDbNowEpochSql +
        ", consumed_by = $1 "
        "WHERE id = $2 AND status = 'approved' AND consumed_at = 0 AND " + ticket_live_sql() +
        " AND reviewed_by = $3 AND request_json = $4 AND request_digest = $5"
        " AND excluded_roots = $6 AND origin = $7 AND submitted_by = $8 AND status = $9"
        " AND xmin::text = $10 AND ctid::text = $11"
        " RETURNING 1";
    pg::PgResult res = pg::exec_params(
        conn, consume_sql.c_str(),
        std::vector<std::string>{consumed_by, id, examined->reviewed_by, examined->request_json,
                                 examined->request_digest, *pinned_roots,
                                 to_string(examined->origin), examined->submitted_by,
                                 examined->status, examined->row_version,
                                 examined->row_position});

    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(ConsumeError{
            ConsumeFailure::kStoreError,
            std::string("consume failed: ") + PQresultErrorMessage(res.get()),
            result_sqlstate(res)});

    if (PQntuples(res.get()) > 0) {
        // On the held path this is a statement inside the CALLER's transaction: the
        // consume takes effect only if that commits, so the line says so rather than
        // claim a durable spend that a rollback may still undo.
        spdlog::info("ApprovalManager: consumed approval ticket {} by {}{}", redact_id(id),
                     consumed_by, held ? " (inside the caller's transaction)" : "");
        return {};
    }
    // Zero rows matched — already used / not approved / absent / EXPIRED
    // (replay-safe: a second concurrent recall loses here). Classify the
    // expired case apart so the caller can say "submit a fresh request" rather
    // than "already used". This read is DIAGNOSTIC ONLY: the CAS above already
    // refused, so a failed or odd classification read degrades to the generic
    // kNotConsumable and can never turn a refusal into a grant. The binding
    // check (origin + submitter) ran before the CAS, so naming expiry here
    // discloses nothing to a caller who could not already see the ticket.
    // The pinned columns ride the same read, so a pin mismatch can be named (column NAMES
    // only, never values) at no extra round trip.
    const std::string why_sql =
        "SELECT status, consumed_at, NOT " + ticket_live_sql() +
        ", reviewed_by, request_json, request_digest, excluded_roots, origin, submitted_by, xmin::text, ctid::text"
        " FROM approval_manager.approvals WHERE id = $1";
    pg::PgResult why =
        pg::exec_params(conn, why_sql.c_str(), std::vector<std::string>{id});
    if (why.status() == PGRES_TUPLES_OK && PQntuples(why.get()) == 1) {
        const std::string status = col_str(why.get(), 0, 0);
        const bool unconsumed = to_i64(col(why.get(), 0, 1)) == 0;
        const bool past_ttl = col_str(why.get(), 0, 2) == "t";
        if (status == "expired" || (status == "approved" && unconsumed && past_ttl)) {
            spdlog::info("ApprovalManager: refused expired approval ticket {} for {}",
                         redact_id(id), consumed_by);
            return std::unexpected(ConsumeError{ConsumeFailure::kExpired, kTicketExpiredMessage});
        }
        // Still approved, unconsumed and in date, yet the pinned CAS matched nothing: the row
        // differs from the one examined. Refused uniformly; the server log is where it shows,
        // throttled per ticket like every other repeated refusal line (a stuck ticket is
        // retried by its caller).
        if (status == "approved" && unconsumed && !past_ttl) {
            std::string changed;
            const auto note = [&](const char* column, bool differs) {
                if (!differs)
                    return;
                if (!changed.empty())
                    changed += ",";
                changed += column;
            };
            note("status", status != examined->status);
            note("reviewed_by", col_str(why.get(), 0, 3) != examined->reviewed_by);
            note("request_json", col_str(why.get(), 0, 4) != examined->request_json);
            note("request_digest", col_str(why.get(), 0, 5) != examined->request_digest);
            note("excluded_roots", col_str(why.get(), 0, 6) != *pinned_roots);
            note("origin", col_str(why.get(), 0, 7) != to_string(examined->origin));
            note("submitted_by", col_str(why.get(), 0, 8) != examined->submitted_by);
            // The row version (xmin and tuple position) also moves for a change in a column none
            // of the checks read (consumed_at, reviewed_at, definition_id, scope, target,
            // schedule), which is the point of pinning it.
            note("row version", col_str(why.get(), 0, 9) != examined->row_version ||
                                    col_str(why.get(), 0, 10) != examined->row_position);
            static RefusalLogThrottle throttle;
            const std::string key = redact_id(id);
            if (throttle.should_warn(key))
                spdlog::warn("ApprovalManager: ticket {} no longer matches the state examined "
                             "for it (changed: {}); refusing",
                             key, changed.empty() ? "none of the pinned columns" : changed);
            else
                spdlog::debug("ApprovalManager: ticket {} still does not match its examined "
                              "state",
                              key);
        }
    }
    return std::unexpected(ConsumeError{ConsumeFailure::kNotConsumable, kNotConsumableMessage});
}

std::expected<bool, std::string> ApprovalManager::ticket_is_live(const std::string& id) const {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("approval store temporarily unavailable (pool exhausted)");
    const std::string sql = "SELECT 1 FROM approval_manager.approvals WHERE id = $1 AND "
                            "status = 'approved' AND consumed_at = 0 AND " + ticket_live_sql();
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ApprovalManager::ticket_is_live: read failed for id={}: {}", redact_id(id),
                      PQresultErrorMessage(res.get()));
        return std::unexpected("approval store temporarily unavailable (read failed)");
    }
    return PQntuples(res.get()) > 0;
}

// ---------------------------------------------------------------------------
// Approve / Reject
// ---------------------------------------------------------------------------

std::expected<void, std::string> ApprovalManager::approve(const std::string& id,
                                                          const std::string& reviewer,
                                                          const std::string& comment) {
    return set_review_status(id, "approved", reviewer, comment);
}

std::expected<void, std::string> ApprovalManager::reject(const std::string& id,
                                                         const std::string& reviewer,
                                                         const std::string& comment) {
    return set_review_status(id, "rejected", reviewer, comment);
}

std::expected<void, std::string> ApprovalManager::set_review_status(const std::string& id,
                                                                    const std::string& status,
                                                                    const std::string& reviewer,
                                                                    const std::string& comment) {
    if (!open_)
        return std::unexpected("database not open");
    if (id.empty())
        return std::unexpected("approval id is required");
    if (reviewer.empty())
        return std::unexpected("reviewer is required");
    if (comment.size() > kMaxReviewCommentBytes)
        return std::unexpected(std::string{kReviewCommentTooLong});

    // Fetch the current approval to validate state (a friendly error
    // message only — the real TOCTOU guard is the UPDATE's own
    // WHERE status='pending' below, not this read).
    {
        auto lease = pool_.try_acquire_for(kReadTimeout);
        if (!lease)
            return std::unexpected("approval store temporarily unavailable (pool exhausted)");
        pg::PgResult sel = pg::exec_params(
            lease.get(),
            "SELECT status, submitted_by, excluded_roots, request_json, request_digest "
            "FROM approval_manager.approvals "
            "WHERE id = $1",
            std::vector<std::string>{id});
        if (sel.status() != PGRES_TUPLES_OK) {
            // Scrubbed generic string reaching the REST/MCP caller (this
            // reaches the HX-Trigger toast and the MCP error body) — matches
            // the shape create_execution/submit already use in this ladder
            // (governance PR review, 2026-08-31, Doomgoose: this site leaked
            // the raw Postgres diagnostic while the same-PR fix scrubbed the
            // identical shape elsewhere). Diagnostic logged server-side only.
            spdlog::error("ApprovalManager::set_review_status: read failed for id={}: {}", id,
                          PQresultErrorMessage(sel.get()));
            return std::unexpected("approval store temporarily unavailable (read failed)");
        }
        if (PQntuples(sel.get()) == 0)
            return std::unexpected("approval not found: " + id);

        auto current_status = col_str(sel.get(), 0, 0);
        auto submitted_by = col_str(sel.get(), 0, 1);

        // Cannot review an already-reviewed approval
        if (current_status != "pending")
            return std::unexpected("approval already reviewed (status: " + current_status + ")");

        // Ownership rule: reviewer must not be the submitter
        if (same_human_root(reviewer, submitted_by))
            return std::unexpected("reviewer cannot be the same as the submitter");

        // Excluded roots (#6062): the people who designed the effect cannot approve it.
        // APPROVE only. A non-submitter excluded root may still REJECT: rejecting
        // grants nothing, so there is nothing to bar, and it is the way a designer
        // withdraws a request they no longer want (the dashboard offers it too). The
        // SUBMITTER is barred from both verbs by the check above, so a submitter cannot
        // withdraw through this store at all - this exemption does not reach them.
        // Fail CLOSED on an unreadable column: an unparseable list must not read as
        // "nobody is excluded".
        if (status == "approved") {
            const auto roots = decode_excluded_roots(col_str(sel.get(), 0, 2));
            if (!roots) {
                spdlog::error("ApprovalManager::set_review_status: excluded_roots of {} is "
                              "unreadable; refusing the approval",
                              redact_id(id));
                return std::unexpected(std::string{kExcludedRootsUnreadableMessage});
            }
            if (reviewer_is_excluded(reviewer, *roots))
                return std::unexpected(std::string{kExcludedReviewerMessage});
            // A bound request the reviewer could not have read, or that no longer
            // hashes to its digest, cannot be approved - "approve exactly what you saw"
            // is only true if what is stored is what can be shown. Reject stays open: it
            // grants nothing, and it is the only way to clear such a row from the queue.
            if (const auto fault = request_binding_fault(col_str(sel.get(), 0, 3),
                                                         col_str(sel.get(), 0, 4),
                                                         /*require_readable=*/true)) {
                spdlog::error("ApprovalManager::set_review_status: the bound request of {} "
                              "failed its check ({}); refusing the approval",
                              redact_id(id), fault->cause);
                return std::unexpected(std::string{kBoundRequestUnreadableMessage});
            }
        }
    }

    // Atomic update; WHERE status = 'pending' prevents TOCTOU double-approve
    // (G4-UHP-MCP-005). RETURNING carries the "row matched" signal in the
    // result's row count — approve/reject is reachable via MCP, and a security
    // decision must not be mis-reported by a racy affected-row count
    // (#1033 / governance UP-2 — the Postgres port keeps the same idiom
    // every store in this ladder uses, though the SQLite-era shared-
    // connection race this specifically defended against has no direct
    // Postgres analogue on a per-lease connection).
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("approval store temporarily unavailable (pool exhausted)");

    // reviewed_at is stamped by the database (kDbNowEpochSql), the clock the consume
    // CAS and the sweep compare it against: stamping it from this process made a
    // replica running days behind produce an approval that was already expired.
    const std::string review_sql =
        std::string("UPDATE approval_manager.approvals SET status = $1, reviewed_by = $2, "
                    "reviewed_at = ") + kDbNowEpochSql +
        ", review_comment = $3 WHERE id = $4 AND status = 'pending' RETURNING 1";
    pg::PgResult res = pg::exec_params(lease.get(), review_sql.c_str(),
                                       std::vector<std::string>{status, reviewer, comment, id});

    if (res.status() != PGRES_TUPLES_OK) {
        // Scrubbed generic string (governance PR review, 2026-08-31,
        // Doomgoose + scoped re-review, consistency-auditor: this branch
        // was missed when the SELECT failure four lines above it was fixed
        // to the same shape — both reach the HX-Trigger toast and the MCP
        // error body via mcp_server.cpp's approve_request/reject_request
        // and server.cpp's /api/approvals/{id}/approve|reject).
        spdlog::error("ApprovalManager::set_review_status: update failed for id={}: {}", id,
                      PQresultErrorMessage(res.get()));
        return std::unexpected("approval store temporarily unavailable (update failed)");
    }

    if (PQntuples(res.get()) > 0) {
        spdlog::info("ApprovalManager: {} approval {} by {}", status, redact_id(id), reviewer);
        return {};
    }
    return std::unexpected("approval already reviewed by another user");
}

// ---------------------------------------------------------------------------
// Schedule-origin retire (#6096)
// ---------------------------------------------------------------------------

// Resource ledger: one bounded write lease (kWriteTimeout, `try_acquire_for`) released by the
// RAII lease on every return path; one parameterised statement (the id array is a bound
// parameter, never spliced into the SQL text); the PgResult is RAII; no thread, callback or
// retained state, so nothing can leak on the error or exception path.
std::expected<int, std::string>
ApprovalManager::retire_schedule_tickets(const std::string& schedule_id,
                                         const std::string& occurrence_id,
                                         const std::vector<std::string>& ids) {
    if (!open_)
        return std::unexpected("database not open");
    // consumed_by is the evidence chain (submitted_by -> reviewed_by -> consumed_by), so it
    // must never be written empty: both halves of 'schedule:<occurrence>' are required.
    if (schedule_id.empty() || occurrence_id.empty())
        return std::unexpected("schedule id and occurrence id are required");
    // Nothing observed, nothing to settle: no statement, no lease.
    if (ids.empty())
        return 0;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("approval store temporarily unavailable (pool exhausted)");

    // pg::to_text_array double-quotes and escapes every element, so ids are bound as data.
    const std::string array = pg::to_text_array(
        std::vector<std::string_view>(ids.begin(), ids.end()));

    // One guarded UPDATE keyed on `consumed_at = 0`, so each ticket is retired by exactly one
    // caller and a repeat matches nothing. Scoped to the ids the caller OBSERVED (`id = ANY`),
    // so a ticket approved after the caller's snapshot, or a successor occurrence's ticket, is
    // never touched. Pending tickets are never touched (the status list). consumed_at is
    // database time, the clock every other stamp here uses.
    const std::string retire_sql =
        std::string("UPDATE approval_manager.approvals SET consumed_at = ") + kDbNowEpochSql +
        ", consumed_by = 'schedule:' || $2::text WHERE schedule_id = $1 AND consumed_at = 0 "
        "AND status IN ('approved','rejected') AND id = ANY($3::text[]) RETURNING 1";
    pg::PgResult res = pg::exec_params(lease.get(), retire_sql.c_str(),
                                       std::vector<std::string>{schedule_id, occurrence_id, array});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ApprovalManager::retire_schedule_tickets: update failed for schedule={}: {}",
                      schedule_id, PQresultErrorMessage(res.get()));
        return std::unexpected("approval store temporarily unavailable (retire failed)");
    }
    return PQntuples(res.get());
}

} // namespace yuzu::server
