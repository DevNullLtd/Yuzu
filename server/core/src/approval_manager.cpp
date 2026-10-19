#include "approval_manager.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "secure_random.hpp"
#include "sha256_hex.hpp"

#include <libpq-fe.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <yuzu/metrics.hpp>

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
// `submitted_at` is the ONE deliberate exception, stamped by submit_stamp_epoch()
// below: ScheduleRunner's occurrence anchor (`ticket_is_current`) compares it with
// ScheduleEngine's `last_executed_at`/`created_at`, which are process-clock stamps.
// Moving only one side to database time would make that comparison cross-clock, and
// a database clock running ahead of the runner would make a spent, approved ticket
// look newer than its occurrence again -- one approval firing more than once, which
// is worse than anything this change closes. Follow-up: move ScheduleEngine's stamps
// to database time, then this one.
int64_t submit_stamp_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

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
// (declares_non_mcp_surface). That makes an unhandled enumerator fail CLOSED
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
    // REFUSED at redemption, same as kUnrecognised (declares_non_mcp_surface).
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

bool declares_non_mcp_surface(ApprovalOrigin origin) {
    return !origin_redeemable_as(origin, ApprovalOrigin::kMcp);
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
// every row minted before migration v2) means "none". nullopt == the column holds
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
    "request_json, request_digest, excluded_roots";

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
        // v2 (#6062, four-eyes MVP PR2): the bound-approval columns. Additive, with
        // constant defaults (instant on PG11+, no table rewrite), so every existing
        // row reads as "binds no request, excludes nobody" and keeps working
        // unchanged. '' rather than NULL, matching every other column in this table
        // and the store-wide convention: the three are text the reader can always
        // fetch without a null branch. They are written once, at INSERT, by
        // submit_bound(); no UPDATE in this file touches them, which is what
        // "frozen at mint" means here.
        {2,
         "ALTER TABLE approvals ADD COLUMN request_json   TEXT NOT NULL DEFAULT '';"
         "ALTER TABLE approvals ADD COLUMN request_digest TEXT NOT NULL DEFAULT '';"
         "ALTER TABLE approvals ADD COLUMN excluded_roots TEXT NOT NULL DEFAULT '';"},
    };
    return kMigrations;
}

} // namespace

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
                              const std::string& scope_expression, const std::string& schedule_id,
                              ApprovalOrigin origin, BoundRequest bound, std::string target_plugin,
                              std::string target_action) {
    return submit_impl(definition_id, submitted_by, scope_expression, schedule_id, origin, &bound,
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
        }
        if (!bound->excluded_roots.empty()) {
            // STRICT dump: invalid UTF-8 throws rather than being "replaced". A
            // replaced root would no longer equal the name it was meant to exclude,
            // and a silently weakened exclusion is the one outcome this must not have.
            try {
                excluded_roots_text =
                    nlohmann::json(bound->excluded_roots)
                        .dump(-1, ' ', false, nlohmann::json::error_handler_t::strict);
            } catch (const nlohmann::json::exception&) {
                return fail(SubmitFailure::kInvalidRequest,
                            "excluded roots must be valid UTF-8");
            }
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
    //    that a further call site is "a fourth chance to diverge". This was it.

    std::lock_guard lock(mtx_);

    auto id_r = generate_id();
    if (!id_r)
        return fail(SubmitFailure::kStoreError, id_r.error());
    auto id = *id_r;
    // Cutoffs come from the database clock (see kDbNowEpochSql above), never from this
    // process; only submitted_at is process-stamped, for the reason given there.
    const std::string submitted_at = std::to_string(submit_stamp_epoch());
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
            "VALUES ($1,$2,'pending',$3,$4,'',0,'',$5,$6,$7,$8,$9,$10,$11,$12)";
        pg::PgResult ins = pg::exec_params(
            conn, insert_sql.c_str(),
            std::vector<std::string>{id, definition_id, submitted_by, submitted_at,
                                     scope_expression, schedule_id, to_string(origin),
                                     target_plugin, target_action, request_json,
                                     request_digest, excluded_roots_text});
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
    // Filtered in C++ through the SHARED predicate rather than a second,
    // hand-written SQL copy of the rule. A copy in a WHERE clause is a second
    // home for `declares_non_mcp_surface`, and the two would drift the first
    // time the enum grows.
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
    // TEST DEPENDENCY: with no precondition supplied (today's only production
    // caller, the MCP recall), this is the 2nd top-level SELECT this call
    // issues against the store — the 1st is the caller's own pre-consume
    // lookup (e.g. mcp_server.cpp's rung-1 get_checked). ADR-0065 (governance
    // adversarial review, 2026-08-31): the SQLite-era MCP integration test
    // that isolated a fault to THIS read specifically via a countdown
    // `sqlite3_set_authorizer` has no Postgres analogue and was deleted, not
    // ported — the equivalent coverage now lives at the store level
    // (`test_approval_manager.cpp`, asserts `binding_check_unevaluated=true`
    // + a non-empty `sqlstate` when this read fails), since consume_ticket's
    // own logic here is unchanged by the migration. A future read added
    // between the caller's lookup and this one would still need that
    // store-level test updated to target the right read. The submitter check
    // below extends this SAME read rather than adding a 3rd SELECT, for
    // exactly that reason.
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
        if (*row && !origin_redeemable_as((*row)->origin, expected))
            return std::unexpected(
                ConsumeError{ConsumeFailure::kForeignOrigin, kNotConsumableMessage});
        // #2442 submitter binding: an approval id disclosed to a third party
        // (e.g. via `GET /api/approvals`, gated on `Approval:Read` — seeded to
        // Viewer) must not be redeemable by anyone but the principal it was
        // granted to. Same posture as the origin check: refused with the
        // uniform message, distinct KIND for the audit trail only, so the
        // recall cannot be used to probe whether a ticket exists versus who
        // owns it. Checked in the SAME block, after the origin check, so a
        // foreign-origin ticket is always reported as that (the more specific
        // fact) rather than as foreign-submitter when both are true.
        if (*row && (*row)->submitted_by != consumed_by)
            return std::unexpected(
                ConsumeError{ConsumeFailure::kForeignSubmitter, kNotConsumableMessage});
    }

    // Pre-consume recheck (#2443). Skipped entirely when no precondition was
    // supplied, so the two-argument path issues the exact same single statement
    // it always has.
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
        // A row that cannot transition is reported WITHOUT running the
        // precondition: the callback may be costly or emit audit, and the CAS
        // below would decline this row anyway. Same message as the CAS decline,
        // so the two paths are indistinguishable to the caller (they mean the
        // same thing).
        if (!*row || (*row)->status != "approved" || (*row)->consumed_at != 0)
            return std::unexpected(ConsumeError{
                ConsumeFailure::kNotConsumable,
                kNotConsumableMessage});
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
            // #6062: every precondition denial is counted and audited AT THE STORE, for
            // every origin. The label is the ticket's own origin, already known to be
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
        " RETURNING 1";
    pg::PgResult res = pg::exec_params(conn, consume_sql.c_str(),
                                       std::vector<std::string>{consumed_by, id});

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
    const std::string why_sql = "SELECT status, consumed_at, NOT " + ticket_live_sql() +
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
            "SELECT status, submitted_by, excluded_roots FROM approval_manager.approvals "
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
        // Approve only - a designer rejecting their own request is harmless, and
        // refusing it would strand a request its authors want withdrawn.
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
            for (const auto& root : *roots) {
                if (same_human_root(reviewer, root))
                    return std::unexpected(std::string{kExcludedReviewerMessage});
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

} // namespace yuzu::server
