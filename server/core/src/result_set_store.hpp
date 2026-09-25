#pragma once

/// @file result_set_store.hpp
/// Migrated Postgres store (ADR-0006, ADR-0036, schema `result_set_store`) for
/// the scope-walking result-set primitive (design: docs/scope-walking-design.md).
/// Was `result_sets.db` (SQLite). `migrate_from_sqlite()` retired
/// (chore/retire-migrate-from-sqlite-batch-b, #3623) — see ADR-0036's Update;
/// `server.cpp` now runs a detect-and-warn probe over the legacy file instead.
///
/// Posture (ADR-0012 §1): AUTHORITATIVE / fail-hard, both construction and
/// runtime. The database IS the source of truth for scope-walking lineage —
/// there is no in-memory fallback. Construction failure (`!is_open()`) is
/// fatal (server.cpp sets `startup_failed_`), same as every other
/// Postgres-backed store.
///
/// **Every authorization/targeting-relevant read is type-distinguishable
/// (2026-07-25, program policy — see `docs/postgres-store-playbook.md`
/// "Authoritative reads must be type-distinguishable").** `get`, `contains`,
/// `resolve_alias`, `member_set_owned`, `count_for_owner_checked`,
/// `members_checked`, `list_by_owner_checked`, and `lineage_checked` return
/// `std::expected<T, ResultSetError>` — a runtime DB error is
/// `std::unexpected(DbError)`, NEVER an empty/false/nullopt value
/// indistinguishable from a genuine "not found" or "not a member". This is
/// load-bearing: `member_set_owned` backs `AgentRegistry::evaluate_scope`'s
/// `from_result_set:` membership check, and under a `NOT from_result_set:<id>`
/// scope a silently-empty membership (the pre-2026-07-25 behavior) INVERTS to
/// "matches every device" — a concrete command-dispatch fleet-wide fail-open,
/// not a theoretical one. `count_for_owner_checked` backs the pre-dispatch
/// per-owner quota check on the three async result-set producers (#4306
/// finding 1): a silently-empty/zero count there would let an over-quota
/// dispatch fire for real before the authoritative in-txn recheck ever runs.
/// `members_checked`/`list_by_owner_checked`/`lineage_checked` back every
/// REST/MCP consumer that materialises or reports membership (#4306 finding 3
/// / #4307 finding 2): a silently-truncated page there is indistinguishable
/// from a genuine last page or an empty fleet. Every caller of these eight
/// methods MUST apply the reviewer test: "if this value were silently
/// empty/false, could any downstream branch grant/target/enforce/skip/
/// invert(NOT)/report success? If yes, fail closed (abort/503) on `DbError`
/// — never treat it as empty-container."
///
/// `list_by_owner`, `members`, `lineage`, and `count_for_owner` are thin
/// `.value_or(...)` wrappers over their `_checked` twins above, kept for API
/// continuity. `list_by_owner` and `lineage` still have real production
/// callers — the render-only dashboard fragments in `result_set_routes.cpp`
/// (`docs/postgres-store-playbook.md` rule 4's render-only carve-out: no
/// decision downstream of a dashboard render, so a degraded read just
/// re-renders an empty fragment rather than needing a 503). `members` and
/// `count_for_owner` have NO production caller left after this widening —
/// every call site that could grant/target/dispatch on their result now goes
/// through the `_checked` twin; the plain forms exist only for
/// `test_result_set_store.cpp`'s own healthy-path assertions. **`lineage`'s
/// wrapper is NOT behaviourally identical to the pre-#4306 plain
/// implementation**: the old `lineage()` returned a PARTIAL chain on a
/// mid-walk query failure (whatever had been accumulated before the failing
/// hop); `lineage_checked` treats a mid-walk failure as `DbError` for the
/// whole call, so the wrapper now returns EMPTY instead — more honest (no
/// silent partial breadcrumb), but a real behavior change for the dashboard's
/// still-plain `lineage()` callers. `counts`, `count_pinned_for_owner`, and
/// `list_pending` remain plain-container reads too (deny-or-benign failure
/// modes; not yet widened — tracked as a follow-up, see ADR-0036).
///
/// Substrate contract (ADR-0008): the store holds a `PgPool&` (not a
/// `sqlite3*`), runs its schema migration at construction on a pinned lease,
/// and schema-qualifies every runtime statement (`result_set_store.result_sets`)
/// — pooled connections carry no per-store search_path. Mutate-and-return uses
/// `RETURNING` (the #1033-banning idiom), never `sqlite3_changes()`. No
/// secrets — plain columns, no `SecretCodec`.
//
// A result set is a named, TTL-bounded, lineage-tracked set of device IDs
// produced by a query, action result, or operator-curated list. Each narrowing
// step in an investigation produces a new result set whose `parent_id` points
// at the set it refined, so a SELECT walking `parent_id` reconstructs the
// operator's full reasoning chain (design: docs/scope-walking-design.md).
//
// Producers come in two flavours:
//   • synchronous  (inventory query, manual curation) — members known at create
//     time → row lands in status `materialized`.
//   • asynchronous (TAR SQL, instruction-result) — a command is dispatched and
//     responses trickle in over seconds–minutes; the row lands `pending` with a
//     `source_execution_id`, and the server's maintenance thread materialises it
//     once the execution reaches a terminal state.
// ─────────────────────────────────────────────────────────────────────────────

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// Lifecycle state of a result set's membership list.
enum class ResultSetStatus { Pending, Materialized, Failed };

const char* to_string(ResultSetStatus s);
ResultSetStatus result_set_status_from(std::string_view s);

/// Source that produced a result set. Mirrors design §3.2 `source_kind`.
/// Carried as a plain string in the row so future kinds need no schema change.
namespace source_kind {
inline constexpr std::string_view kInventoryQuery = "inventory_query";
inline constexpr std::string_view kTarQuery = "tar_query";
inline constexpr std::string_view kInstructionResult = "instruction_result";
inline constexpr std::string_view kManualCurate = "manual_curate";
} // namespace source_kind

/// Row metadata for a result set (members live in a separate table).
struct ResultSet {
    std::string id;              // "rs_<time-hex><rand-hex>", lexically sortable
    std::string name;            // operator alias, unique per owner; may be empty
    std::string owner_principal; // result sets are per-operator
    int64_t created_at{0};       // epoch seconds
    int64_t ttl_at{0};           // epoch seconds; GC'd when now > ttl_at AND !pinned
    int64_t last_used_at{0};     // epoch seconds; bumped by touch()
    bool pinned{false};
    std::optional<std::string> parent_id; // lineage edge; empty for ground sets
    std::string source_kind;              // see source_kind:: constants
    std::string source_payload;           // JSON; enough to re-evaluate (design §3.2)
    ResultSetStatus status{ResultSetStatus::Materialized};
    std::string source_execution_id;      // set for async producers; else empty
    std::string matcher;                  // JSON matcher for instruction-result; else empty
    int64_t device_count{0};
};

/// One step in a lineage chain (design §6 `/lineage`).
struct LineageNode {
    std::string id;
    std::string name;
    std::string source_kind;
    int64_t device_count{0};
};

/// A pending set awaiting async materialisation, surfaced to the server's
/// maintenance thread. The thread owns the response→matcher→members logic.
struct PendingSet {
    std::string id;
    std::string owner_principal;
    std::string source_kind;
    std::string source_execution_id;
    std::string matcher;
    int64_t created_at{0};
};

/// Typed failure surface; the REST layer maps these to the error taxonomy
/// (RESULT_SET_NOT_FOUND, RESULT_SET_NOT_OWNER, RESULT_SET_QUOTA, PIN_LIMIT,
/// RESULT_SET_EXPIRED) and the corresponding HTTP status.
enum class ResultSetError { NotFound, NotOwner, QuotaExceeded, PinLimit, Pinned, TooManyMembers, DbError };

const char* to_string(ResultSetError e);

/// Parameters for creating a result set. `members` (for sync create) and
/// `execution_id` (for async create) are supplied to the respective methods.
struct CreateRequest {
    std::string name;            // optional alias
    std::string owner_principal; // required
    std::optional<std::string> parent_id;
    std::string source_kind;
    std::string source_payload; // JSON
    std::string matcher;        // JSON; only meaningful for async instruction-result
};

class ResultSetStore {
public:
    // Lifecycle / sizing knobs (design §3.3, §3.4).
    static constexpr int64_t kDefaultTtlSeconds = 3600;  // 1 hour
    static constexpr int kMaxPerOwner = 10000;           // hard create cap
    static constexpr int kMaxMembersPerSet = 100000;     // per-set member cap (DoS guard)
    static constexpr int kMaxPinsPerOwner = 50;          // pin-storm guard
    static constexpr int kLineageDepthCap = 10;          // breadcrumb truncation

    /// Borrows the shared pool and runs the `result_set_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed.
    explicit ResultSetStore(pg::PgPool& pool);

    ResultSetStore(const ResultSetStore&) = delete;
    ResultSetStore& operator=(const ResultSetStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    // ── Create ───────────────────────────────────────────────────────────────
    /// Synchronous create: members are known now; lands `materialized`.
    std::expected<ResultSet, ResultSetError> create_materialized(
        const CreateRequest& req, const std::vector<std::string>& members);

    /// Asynchronous create: a command has been dispatched under `execution_id`;
    /// lands `pending`. The maintenance thread later calls materialize().
    std::expected<ResultSet, ResultSetError> create_pending(const CreateRequest& req,
                                                            const std::string& execution_id);

    // ── Read ─────────────────────────────────────────────────────────────────
    /// `std::unexpected(DbError)` on a runtime Postgres error — type-
    /// distinguishable from a genuine absent row (`std::optional` holding
    /// `nullopt`). Backs the owner gate at `scope_yaml.cpp` / the dashboard
    /// and REST result-set routes; a caller MUST treat `DbError` as "cannot
    /// verify ownership" (fail closed / 503), never as "not found" (404) —
    /// collapsing the two would let a transient DB blip read as a clean
    /// not-found on an authorization-relevant lookup.
    std::expected<std::optional<ResultSet>, ResultSetError> get(const std::string& id);

    /// One page of an owner-scoped list, sorted last_used_at then created_at
    /// DESC. `std::unexpected(DbError)` on a runtime error — see the type-
    /// distinguishable-reads note above; NEVER an empty page indistinguishable
    /// from a genuine last/only page. `list_by_owner()` below is the deny-or-
    /// benign plain wrapper (dashboard-only).
    struct ListPage {
        std::vector<ResultSet> sets;
        std::string next_cursor; // empty once the last page is reached
    };
    std::expected<ListPage, ResultSetError> list_by_owner_checked(const std::string& owner,
                                                                   const std::string& cursor,
                                                                   int limit);
    /// Deny-or-benign plain wrapper over `list_by_owner_checked` — see the
    /// file-header posture note. `out_next_cursor` is set empty on a `DbError`
    /// (same shape as a genuine last page), matching this method's pre-#4306
    /// behavior exactly.
    std::vector<ResultSet> list_by_owner(const std::string& owner, const std::string& cursor,
                                         int limit, std::string& out_next_cursor);

    /// One page of `id`'s member device ids. `std::unexpected(DbError)` on a
    /// runtime error — see the type-distinguishable-reads note above; NEVER an
    /// empty page indistinguishable from a genuine last page. THE read this
    /// producer/report chain materialises or displays as membership (#4306
    /// finding 3 / #4307 finding 2) — a caller that lets `DbError` fall
    /// through as an empty page silently truncates or empties the result.
    /// `members()` below is the deny-or-benign plain wrapper (dashboard-only).
    struct MembersPage {
        std::vector<std::string> device_ids;
        std::string next_cursor; // empty once the last page is reached
    };
    std::expected<MembersPage, ResultSetError> members_checked(const std::string& id,
                                                                const std::string& cursor,
                                                                int limit);
    /// Deny-or-benign plain wrapper over `members_checked` — see the
    /// file-header posture note. `out_next_cursor` is cleared on a `DbError`
    /// (same shape as a genuine last page), matching this method's pre-#4306
    /// behavior exactly.
    std::vector<std::string> members(const std::string& id, const std::string& cursor, int limit,
                                     std::string& out_next_cursor);

    /// Lineage chain root→leaf, walking parent_id. Owner-filtered: the walk
    /// stops at the first ancestor not owned by `owner`, so a child parented
    /// onto another operator's set cannot leak that set's metadata (review B2)
    /// — stopping there is NORMAL termination, not a `DbError`, same as the
    /// cycle guard. `std::unexpected(DbError)` is reserved for a genuine
    /// store/query failure encountered mid-walk — see the type-
    /// distinguishable-reads note above. `lineage()` below is the deny-or-
    /// benign plain wrapper (dashboard-only) and is NOT behaviourally
    /// identical to the pre-#4306 plain implementation on a mid-walk failure
    /// — see the file-header posture note.
    std::expected<std::vector<LineageNode>, ResultSetError>
    lineage_checked(const std::string& id, const std::string& owner);
    std::vector<LineageNode> lineage(const std::string& id, const std::string& owner);
    /// `std::unexpected(DbError)` on a runtime error — see the type-
    /// distinguishable-reads note above the `get()` declaration. (No current
    /// production caller — `AgentRegistry`'s membership check uses
    /// `member_set_owned` instead; widened for API consistency and the
    /// authorization-primitive contract this store advertises.)
    ///
    /// CAUTION: `!contains(...)` tests the ERROR state (`std::expected`'s
    /// `operator!`/`operator bool`), NOT "device is not a member" — a bare
    /// `!contains(...)` silently treats a DB error the same as "not a
    /// member" and a successful `false` the same as "degraded", both wrong.
    /// Check `.has_value()` first, then dereference (`**result` or
    /// `result.value()`) for the actual boolean membership answer.
    std::expected<bool, ResultSetError> contains(const std::string& id,
                                                 const std::string& device_id);
    /// All members of `id` iff owned by `owner`; empty set otherwise (absent id
    /// and "not owned" are intentionally indistinguishable — design's
    /// documented "stale/not-yours members drop silently" contract, review
    /// findings B1 + F). `std::unexpected(DbError)` on a runtime error is
    /// DISTINCT from both — see the type-distinguishable-reads note above.
    /// THE authorization gate for `AgentRegistry::evaluate_scope`'s
    /// `from_result_set:` scope kind: a caller that lets `DbError` fall
    /// through as an empty set converts a transient DB blip into "no
    /// members", which under a `NOT from_result_set:<id>` scope inverts to
    /// "every device matches" — the fleet-wide fail-open this contract exists
    /// to prevent. Callers MUST abort (not dispatch) on `DbError`.
    std::expected<std::unordered_set<std::string>, ResultSetError>
    member_set_owned(const std::string& id, const std::string& owner);
    /// Resolve an owner-scoped alias to a canonical id; `nullopt` if not
    /// found. `std::unexpected(DbError)` on a runtime error — see the
    /// type-distinguishable-reads note above the `get()` declaration. Feeds
    /// `resolve_scope_aliases()` (scope_yaml.cpp), which must PROPAGATE a
    /// `DbError` (abort resolution) rather than leaving the alias atom
    /// unresolved — an unresolved atom no-matches downstream and, under NOT,
    /// inverts to match-all, same class of fail-open as `member_set_owned`.
    std::expected<std::optional<std::string>, ResultSetError>
    resolve_alias(const std::string& owner, const std::string& name);
    /// `std::unexpected(DbError)` on a runtime error — NEVER `0`,
    /// indistinguishable from a genuinely-empty owner. See the type-
    /// distinguishable-reads note above. THE pre-dispatch per-owner quota
    /// check on the three async result-set producers (#4306 finding 1): a
    /// caller that lets `DbError` fall through as `0` reads a degraded
    /// backend as "well under quota" and dispatches a real command before
    /// `create_pending`'s atomic in-txn recheck ever runs — by which point
    /// the command has already reached agents. Callers MUST refuse to
    /// dispatch (not substitute 0) on `DbError`. `count_for_owner()` below is
    /// the deny-or-benign plain wrapper, kept for the one caller
    /// (`test_result_set_store.cpp`) that doesn't need the distinction.
    std::expected<int, ResultSetError> count_for_owner_checked(const std::string& owner);
    int count_for_owner(const std::string& owner);
    int count_pinned_for_owner(const std::string& owner);

    /// Fleet-wide aggregate counts for observability gauges.
    struct Counts {
        int total{0};
        int pinned{0};
        int pending{0};
    };
    Counts counts();

    // ── Mutate ───────────────────────────────────────────────────────────────
    std::expected<ResultSet, ResultSetError> pin(const std::string& id);
    std::expected<ResultSet, ResultSetError> unpin(const std::string& id);
    /// Extend ttl_at to max(ttl_at, now + kDefaultTtlSeconds) and bump
    /// last_used_at. Called when a set is used as the scope of a new operation.
    void touch(const std::string& id);
    std::expected<void, ResultSetError> delete_set(const std::string& id);

    // ── Async materialisation (server maintenance thread) ────────────────────
    std::vector<PendingSet> list_pending();
    /// Populate members, flip status → materialized, set device_count.
    std::expected<void, ResultSetError> materialize(const std::string& id,
                                                    const std::vector<std::string>& members);
    void mark_failed(const std::string& id, const std::string& reason);

    /// #4493 heal path for a row `mark_failed` cannot reach: `mark_failed`'s
    /// SELECT/UPDATE are both gated on `status = 'pending'`, so a
    /// `materialized` (or `failed`) row whose `source_payload` nests past
    /// `kMcpMaxJsonDepth` had no way back to a safe, dumpable payload. This
    /// method is status-agnostic on purpose: unlike `mark_failed`, whose job
    /// IS the pending -> failed transition, this NEVER writes `status`, since
    /// a `materialized` row's members are real and still scope-walkable
    /// (`member_set_owned` never filters on status), so forcing it to
    /// `failed` would misrepresent a working set as having produced nothing
    /// to every status-reading consumer (REST/MCP response body, the
    /// dashboard badge). Re-checks the raw text itself (never trusts a
    /// caller's prior check) and is a no-op (returns false, writes nothing)
    /// when the payload is not actually poisoned, so it can never silently
    /// overwrite a healthy row's provenance. Returns true only when the
    /// UPDATE below actually affected exactly one row -- a poisoned payload
    /// was found and replaced with the same fixed `note` text `mark_failed`
    /// writes for its own poisoned-pending case (not the same full object --
    /// `mark_failed`'s also carries a caller-supplied `failure` reason this
    /// method has no equivalent argument for).
    ///
    /// `false` is overloaded across seven distinct causes: the store is not
    /// open, no connection lease was available, the initial SELECT failed
    /// (a genuine read error, connection already held), the row was already
    /// gone at that SELECT, the payload was never actually poisoned (the
    /// no-op case), the UPDATE itself failed (a genuine write error,
    /// connection already held), or the row was deleted between the SELECT
    /// and the UPDATE (#4540 -- a concurrent `delete_set`/GC sweep on an
    /// independent connection lease with no shared lock, caught via
    /// `RETURNING id` + an affected-row check, same idiom as `materialize`'s
    /// own UPDATE) -- a caller needing to distinguish a genuine write failure
    /// from a harmless no-op cannot do so from the return value alone
    /// (#4524).
    ///
    /// Deliberately has NO owner check of its own -- same shape as
    /// `mark_failed`. Both of this method's only two production callers
    /// (REST `/re-eval`, MCP `reevaluate_result_set`) call it only after
    /// their own `load_owned`/`rs_load_owned` has already confirmed the
    /// caller owns `id`; a future caller must do the same before invoking
    /// this method directly.
    ///
    /// Invariant this method's safety depends on and that is NOT enforced by
    /// any type or assertion: today, REST's `/re-eval` and MCP
    /// `reevaluate_result_set` are the ONLY code paths that ever parse
    /// `source_payload` back into JSON, and both already depth-check it
    /// first. A future consumer of `source_payload` (a dashboard/lineage
    /// view, a list endpoint) that parses it WITHOUT its own depth check
    /// would reopen the #2437 SIGSEGV class this guard exists to close --
    /// healing on read here does not protect a consumer that never calls it.
    bool heal_poisoned_payload(const std::string& id);

    // ── GC ───────────────────────────────────────────────────────────────────
    /// Delete unpinned rows past TTL; cascades to members. Returns count removed.
    int gc_sweep();

private:
    pg::PgPool& pool_;
    bool open_{false};

    static std::string generate_id();
    // Shared body for create_materialized/create_pending: dedups members,
    // enforces the per-set cap client-side, then inserts the row + member
    // batch inside ONE transaction (quota check + insert + members atomic).
    std::expected<ResultSet, ResultSetError> insert_row_impl(
        const CreateRequest& req, ResultSetStatus status, const std::string& execution_id,
        const std::vector<std::string>& members);
};

} // namespace yuzu::server
