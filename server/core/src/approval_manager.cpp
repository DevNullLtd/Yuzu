#include "approval_manager.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "secure_random.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdlib>
#include <random>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "approval_manager";

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

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
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
// The trailing `return true` already fails closed, so a missing arm cannot
// grant — but it would silently pick the REFUSE side for a surface that may
// have been added precisely to be redeemable, and the author would never be
// told. Guarding one of the two was an inconsistency, not a judgement.
//
// DO NOT ADD A `default:` LABEL HERE. `-Wswitch` only fires while the switch
// has none, so a defensive `default: return true;` — which looks like
// belt-and-braces, and does exactly what the statement below already does —
// silently deletes this guard, with no warning and no failing test. MEASURED
// on GCC 15.2: with a default label added, a missing enumerator stops erroring
// here while still erroring in `to_string`. The trailing return living OUTSIDE
// the switch is what keeps the guard armed, and that is the whole reason it is
// out there rather than in a default arm.
//
// kUnspecified moved from the grant side to the refuse side here (#2442,
// closing half): the MCP mint now declares ApprovalOrigin::kMcp explicitly
// (mcp_server.cpp), so kUnspecified is no longer "the MCP gate, undeclared" —
// it is now indistinguishable from a row this build cannot attribute to any
// surface, which is exactly the kUnrecognised case one arm below. Grouping
// them is deliberate, not an oversight.
bool declares_non_mcp_surface(ApprovalOrigin origin) {
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
    case ApprovalOrigin::kUnrecognised:
    case ApprovalOrigin::kUnspecified:
        return true;
    case ApprovalOrigin::kMcp:
        return false;
    }
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif
    return true; // unreachable; fail closed if the enum grows
}

namespace {

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
    return a;
}

// THE canonical column list — every SELECT that feeds row_to_approval uses
// this constant so the column order can never drift between call sites.
constexpr const char* kSelectAllCols =
    "id, definition_id, status, submitted_by, submitted_at, "
    "reviewed_by, reviewed_at, review_comment, scope_expression, "
    "consumed_at, consumed_by, schedule_id, origin, target_plugin, target_action";

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
    if (!open_)
        return std::unexpected("database not open");
    if (definition_id.empty())
        return std::unexpected("definition_id is required");
    if (submitted_by.empty())
        return std::unexpected("submitted_by is required");
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
        return std::unexpected(id_r.error());
    auto id = *id_r;
    auto ts = now_epoch();
    constexpr int64_t k7Days = 7 * 24 * 3600;
    auto cutoff = std::to_string(ts - k7Days);

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
        pg::PgResult exp = pg::exec_params(
            conn,
            "UPDATE approval_manager.approvals SET status = 'expired' "
            "WHERE status = 'pending' AND submitted_at < $1 RETURNING 1",
            std::vector<std::string>{cutoff});
        if (exp.status() != PGRES_TUPLES_OK)
            return false;
        int expired_pending = PQntuples(exp.get());

        pg::PgResult expa = pg::exec_params(
            conn,
            "UPDATE approval_manager.approvals SET status = 'expired' "
            "WHERE status = 'approved' AND consumed_at = 0 AND reviewed_at < $1 RETURNING 1",
            std::vector<std::string>{cutoff});
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
            // backward clock skew (NTP correction, VM snapshot restore) moves
            // `cutoff` into the past, so the sweep above matches nothing even
            // though it should have — this WARN is the only thing that
            // distinguishes that anomaly from an ordinary, healthy full
            // queue, both of which otherwise look identical ("queue is full"
            // with zero rows just expired). Not a full clock-guard apparatus
            // (ADR-0065's "Expiry-sweep clock-guard adjudication": this sweep
            // is a state-transition UPDATE, never a DELETE, so the
            // irreversible-loss trigger the full 7-part apparatus exists for
            // is not met) — a log line an operator can alert on is
            // proportionate to the risk.
            if (expired_pending == 0) {
                spdlog::warn(
                    "ApprovalManager: pending queue at cap ({}) and the stale-pending sweep "
                    "expired nothing — if this persists, check for clock skew (cutoff={})",
                    kMaxPendingApprovals, cutoff);
            }
            queue_full_error = "approval queue is full (" +
                               std::to_string(kMaxPendingApprovals) + " pending)";
            return false;
        }

        pg::PgResult ins = pg::exec_params(
            conn,
            "INSERT INTO approval_manager.approvals "
            "(id, definition_id, status, submitted_by, submitted_at, "
            " reviewed_by, reviewed_at, review_comment, scope_expression, schedule_id, origin, "
            " target_plugin, target_action) "
            "VALUES ($1,$2,'pending',$3,$4,'',0,'',$5,$6,$7,$8,$9)",
            std::vector<std::string>{id, definition_id, submitted_by, std::to_string(ts),
                                     scope_expression, schedule_id, to_string(origin),
                                     target_plugin, target_action});
        if (ins.status() != PGRES_COMMAND_OK)
            return false;
        expired_pending_committed = expired_pending;
        expired_approved_committed = expired_approved;
        return true;
    });

    if (!ok) {
        if (!queue_full_error.empty())
            return std::unexpected(queue_full_error);
        return std::unexpected("insert failed (pool degraded or transaction failed)");
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

    std::string sql = std::string("SELECT ") + kSelectAllCols +
                      " FROM approval_manager.approvals WHERE id = $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{id});

    // A read that FAILED is not a read that found nothing. Collapsing the two
    // is what let a store error be reported to the operator as "this one-time
    // capability is spent" — see the pre-consume path in consume_ticket.
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
        if (!declares_non_mcp_surface(a.origin))
            return a;
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Consume (#289 — one-time MCP approval ticket)
// ---------------------------------------------------------------------------

std::expected<void, ConsumeError>
ApprovalManager::consume_ticket(const std::string& id, const std::string& consumed_by,
                                const ConsumePrecondition& precondition) {
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
        auto row = get_checked(id); // takes its own bounded lease
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
        if (*row && declares_non_mcp_surface((*row)->origin))
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
        auto row = get_checked(id); // takes its own bounded lease
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
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(
            ConsumeError{ConsumeFailure::kStoreError, "approval store temporarily unavailable "
                                                       "(pool exhausted)"});

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE approval_manager.approvals SET consumed_at = $1, consumed_by = $2 "
        "WHERE id = $3 AND status = 'approved' AND consumed_at = 0 RETURNING 1",
        std::vector<std::string>{std::to_string(now_epoch()), consumed_by, id});

    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(ConsumeError{
            ConsumeFailure::kStoreError,
            std::string("consume failed: ") + PQresultErrorMessage(res.get()),
            result_sqlstate(res)});

    if (PQntuples(res.get()) > 0) {
        spdlog::info("ApprovalManager: consumed approval ticket {} by {}", redact_id(id), consumed_by);
        return {};
    }
    // Zero rows matched — already used / not approved / absent (replay-safe:
    // a second concurrent recall loses here).
    return std::unexpected(ConsumeError{ConsumeFailure::kNotConsumable, kNotConsumableMessage});
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

    // Fetch the current approval to validate state (a friendly error
    // message only — the real TOCTOU guard is the UPDATE's own
    // WHERE status='pending' below, not this read).
    {
        auto lease = pool_.try_acquire_for(kReadTimeout);
        if (!lease)
            return std::unexpected("approval store temporarily unavailable (pool exhausted)");
        pg::PgResult sel = pg::exec_params(
            lease.get(),
            "SELECT status, submitted_by FROM approval_manager.approvals WHERE id = $1",
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
        if (reviewer == submitted_by)
            return std::unexpected("reviewer cannot be the same as the submitter");
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

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE approval_manager.approvals SET status = $1, reviewed_by = $2, "
        "reviewed_at = $3, review_comment = $4 WHERE id = $5 AND status = 'pending' "
        "RETURNING 1",
        std::vector<std::string>{status, reviewer, std::to_string(now_epoch()), comment, id});

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
