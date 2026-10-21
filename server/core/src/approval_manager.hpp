#pragma once

/// @file approval_manager.hpp
/// Postgres-backed one-time approval-ticket store (ADR-0009/0065). Schema
/// `approval_manager`, one table (`approvals`).
///
/// Posture (ADR-0012 §1): AUTHORITATIVE/fail-hard construction — a
/// reachable database whose schema can't migrate/open is a fatal startup
/// error (`startup_failed_`). This store was ALREADY fail-closed in the
/// SQLite era (a failed migration nulled `db_`), so this is a shape
/// preservation, not a posture upgrade like its ScheduleEngine sibling.
/// Runtime method signatures are unchanged — `submit`/`approve`/`reject`
/// keep their `std::expected<T, std::string>` shapes, `consume_ticket`
/// keeps `std::expected<void, ConsumeError>` — this store's consumers
/// (`mcp_server.cpp`, REST v1, `ScheduleRunner`, `workflow_routes.cpp`) are
/// unaffected by this migration, with ONE exception: `StoreReadError`/
/// `ConsumeError::extended_errcode` (a raw `sqlite3_extended_errcode()`)
/// becomes `sqlstate` (a Postgres SQLSTATE string) — see the field's own
/// doc comment and `pg_error_class.hpp`.
///
/// Backfill: NONE (ADR-0009's 2026-08-25 fresh-start-by-default amendment).
/// The legacy `instructions.db` (shared with the ExecutionTracker/
/// ScheduleEngine siblings, ADR-0065 — ScheduleEngine already migrated,
/// ExecutionTracker still to come) is never read for data; construction
/// logs a one-time "fresh start, no legacy backfill" line, and the caller
/// (`server.cpp`) runs `legacy_sqlite_probe::warn_if_legacy_rows()` over
/// the legacy file so an environment where "no production fleet" turns out
/// to be locally wrong gets a loud signal instead of silent loss.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// PGconn (`consume_ticket`'s caller-held connection): included directly rather than
// forward-declaring libpq's private `pg_conn` tag, per api_token_store.hpp's and
// audit_store.hpp's rationale (#5342) - a re-declaration pins a third party's internal
// name and breaks last and least legibly if libpq renames it.
#include <libpq-fe.h>

namespace yuzu {
class MetricsRegistry;
} // namespace yuzu

namespace yuzu::server::pg {
class PgPool;
} // namespace yuzu::server::pg

namespace yuzu::server {

/// WHICH surface minted a ticket (#2442). `ApprovalManager` is one shared store
/// with three mint paths, and a ticket was previously matched on
/// (definition_id, scope_expression) alone — so an instruction definition named
/// `mcp.<tool>` whose approval scope equalled a tool's canonical argument JSON
/// was consumable through the MCP recall, and vice versa. Recording the minting
/// surface makes the namespaces separable, and gives audit a clean per-surface
/// split.
enum class ApprovalOrigin {
    /// A mint that has not declared its surface, or a row minted before
    /// `submit()`'s `origin` parameter existed or before it was made
    /// non-defaulted. REFUSED at redemption (origin_redeemable_as),
    /// same as kUnrecognised — since #2442's closing half, the MCP gate
    /// (the one surface that historically relied on this value granting)
    /// declares `kMcp` explicitly, so nothing in the tree writes
    /// `kUnspecified` any more and there is no longer a correct reason for a
    /// new caller to produce it. Kept as a distinct decode target from
    /// kUnrecognised (see `to_string`'s comment) rather than merged into it,
    /// so "declared nothing" and "predates the column" stay separable causes
    /// even though both refuse today.
    kUnspecified,
    /// The interactive REST/dashboard instruction-approval gate
    /// (workflow_routes.cpp).
    kInstruction,
    /// A scheduled-fire submission (schedule_runner.cpp).
    kSchedule,
    /// The MCP approval-ticket gate (mcp_server.cpp).
    kMcp,
    /// The Guardian rule-deploy approval (#6062, four-eyes MVP PR3). Always a
    /// BOUND ticket (`submit_bound`): the reviewed rule set is frozen on the row,
    /// and the deploy redeems it through the caller-held-connection `consume_ticket`
    /// so the consume commits or rolls back with the deploy itself. Its definition
    /// ids live under the reserved `guardian.` prefix (reserved_definition_id.hpp).
    kGuardianDeploy,
    /// A stored value this build does not know — a row written by a newer
    /// binary, or a corrupted column. DISTINCT from kUnspecified because they
    /// are different FACTS ("declared nothing" vs. "this build cannot
    /// attribute it to any surface") even though both refuse at redemption
    /// today (#2442's closing half retired the era where kUnspecified
    /// granted): folding an unknown string into kUnspecified would erase that
    /// distinction in the stored evidence, which matters for audit even
    /// though it would not currently change whether the ticket redeems.
    /// Never written, only decoded.
    kUnrecognised,
};

/// THE redemption-time origin predicate (#2442, generalised by #6062): may a ticket
/// recorded as `stored` be redeemed by a caller that declared `expected`?
///
/// True ONLY when BOTH are a concrete surface (neither kUnspecified nor
/// kUnrecognised) and they are equal. kUnspecified and kUnrecognised therefore
/// ALWAYS refuse - as the stored value ("declared nothing" / "this build cannot
/// attribute it") and as the expected one (a caller that names no surface has no
/// claim on any ticket, however the row reads). One definition, used by
/// `consume_ticket` and by `find_pending`'s dedup filter: a second copy of this
/// rule is how the two would drift the first time the enum grows.
[[nodiscard]] bool origin_redeemable_as(ApprovalOrigin stored, ApprovalOrigin expected);

/// Column text for `origin`. `kUnspecified` stores the empty string.
///
/// History (SQLite era, ADR-0065 port): `origin` was an additive column
/// (migration v5) on a store that predated it, so a v7 migration rewrote
/// every pre-existing `''` row to a sentinel decoding as `kUnrecognised`,
/// keeping "no declared origin" (a caller that stays silent) distinct from
/// "declared nothing because the column did not exist yet" (a stored row
/// from before it did) — collapsing them would make a future, more
/// permissive treatment of one silently apply to the other. The Postgres
/// schema (ADR-0065) creates `origin` from row one, fresh-start, so no
/// stored row can predate it any more and the v7 back-fill has nothing
/// left to run against — but the DECODE side of this distinction stays
/// live defense-in-depth: any future stored value `approval_origin_from_
/// string` does not recognize (a newer binary's row, or corruption) still
/// decodes to `kUnrecognised`, not folded into the granting-adjacent
/// `kUnspecified`.
const char* to_string(ApprovalOrigin origin);
ApprovalOrigin approval_origin_from_string(std::string_view text);

struct Approval {
    std::string id;
    std::string definition_id;
    std::string status;
    std::string submitted_by;
    int64_t submitted_at{0};
    std::string reviewed_by;
    int64_t reviewed_at{0};
    std::string review_comment;
    std::string scope_expression;
    // One-time-consumption stamp for the MCP approval-ticket flow (#289 / Issue
    // 13.5): epoch-seconds when an approved ticket was recalled-and-executed,
    // 0 while unconsumed. SQLite-era additive column (v2); part of the
    // Postgres v1 DDL from creation (ADR-0065).
    int64_t consumed_at{0};
    // WHO consumed the ticket (PR #1796 review H3/N2, SOC-2 CC7.2): the
    // principal whose recall executed the gated tool. Empty while unconsumed.
    // SQLite-era additive column (v3). Completes the ticket's evidence chain:
    // submitted_by → reviewed_by → consumed_by.
    std::string consumed_by;
    /// Empty for an interactively-submitted ticket (workflow_routes.cpp) or an
    /// MCP-minted one (mcp_server.cpp); set to the owning schedule's id for a
    /// scheduled-fire submission (M-02, #1806) so
    /// ScheduleRunner::fire_with_approval can match a ticket to the ONE
    /// schedule occurrence that asked for it, instead of to every schedule
    /// sharing the same (submitted_by, definition_id, scope_expression)
    /// tuple. SQLite-era additive column (v4).
    std::string schedule_id;
    /// Which surface minted this ticket (#2442). SQLite-era additive column
    /// (v5); see `to_string`'s comment for the pre-Postgres back-fill
    /// history and why the decode side of that distinction still matters.
    ApprovalOrigin origin{ApprovalOrigin::kUnspecified};
    /// `target_plugin`/`target_action`, snapshotted at `submit()` time
    /// (#1398 hardening, governance Gate 4 unhappy-path CRITICAL finding).
    /// `Approval` binds a human review to `definition_id` only — but
    /// `InstructionDefinition::plugin`/`.action` are MUTABLE
    /// (`PUT /api/instructions/{id}`, gated on nothing stronger than
    /// `InstructionDefinition:Write`, and NEITHER field is charset-restricted
    /// — `InstructionStore::validate_and_prepare` only checks `plugin` is
    /// non-empty), so a ticket approved while a definition pointed at one
    /// action remains matchable by `definition_id` alone after the
    /// definition is repointed at a DIFFERENT one — no human ever reviewed
    /// the content that actually dispatches. `ScheduleRunner::
    /// fire_with_approval` is the one redemption path this binds: it
    /// re-fetches the definition fresh every tick and must refuse a ticket
    /// whose `target_plugin`/`target_action` no longer match what is about
    /// to dispatch, exactly as ADR-0033 §1 requires for any filter that
    /// applies ("unresolvable/missing/unparseable denies") — a plain string
    /// mismatch (including empty, for a pre-migration row) already falls out
    /// of a strict `==` with no special-casing needed.
    ///
    /// TWO SEPARATE FIELDS, deliberately — NOT ONE `plugin + "." + action"`
    /// string (governance Gate 4 security-guardian re-review, folded in
    /// 2026-08-29). A single concatenated string is collision-prone: 28
    /// shipped actions already contain a literal `.` as an internal
    /// namespace separator (`workflow.list`, `policy.list`,
    /// `product_pack.install`, all under `plugin: server`) — no ACTUAL
    /// collision exists today (verified empirically: 226 distinct
    /// `(plugin, action)` pairs across `capability_decls/*.hpp` +
    /// `content/definitions/*.yaml` produce 226 distinct concatenations),
    /// but nothing enforces that invariant, `action` isn't charset-validated
    /// AT ALL, and `CommandCapabilityRegistry::classify` itself compares
    /// `plugin`/`action` as independent fields — matching that shape here
    /// eliminates the collision class structurally rather than relying on
    /// it staying empirically true forever.
    ///
    /// EMPTY for an MCP-minted ticket only (`mcp_server.cpp`'s generic
    /// multi-tool `submit()` call site has no single plugin/action in
    /// scope) — MCP does not need these fields: it already binds redemption
    /// to `definition_id = "mcp."+tool_name` (a code constant, not an
    /// editable row) plus a canonical hash of the full call arguments, an
    /// orthogonal and already-sufficient binding. Populated for BOTH
    /// `ScheduleRunner` (the exploitable path this fixes) AND the
    /// interactive `workflow_routes.cpp` mint, even though the latter has no
    /// redemption flow at all today (a separate, pre-existing,
    /// already-tracked gap — see the design doc's follow-up list) —
    /// populated there anyway so a FUTURE interactive-redemption
    /// implementation inherits this protection for free rather than needing
    /// its own hardening round.
    /// Additive columns (migration v8).
    std::string target_plugin;
    std::string target_action;
    /// The exact effect a reviewer is shown, frozen at mint (#6062, four-eyes MVP
    /// PR2). EMPTY for every ticket minted through the unbound `submit()` (all MCP,
    /// interactive-instruction and scheduled-fire tickets today, and every row that
    /// predates migration v2): an empty value means "this ticket binds no request",
    /// never "an empty request was reviewed". Only `submit_bound()` writes it, and
    /// nothing updates it afterwards. The store treats it as an opaque UTF-8 JSON
    /// document; the Approvals page renders a bounded summary of it (see
    /// `approvals_page_render.hpp`): every key is listed, but a long value, a long
    /// list or a long document is CUT, and the summary then says so and names the digest
    /// as the identity of the whole request. The reviewer therefore reads a summary of
    /// what is stored, not necessarily all of it.
    std::string request_json;
    /// Lowercase hex SHA-256 of `request_json`, computed by the store at mint (so
    /// the two can never disagree) and frozen with it. Empty exactly when
    /// `request_json` is. A redeemer that re-derives the effect it is about to
    /// perform compares its own digest to this one.
    std::string request_digest;
    /// Human roots that may NOT approve this ticket, frozen at mint (#6062):
    /// the people who designed the effect (ADR-0033 section 7 - the approver must
    /// sit outside the set of humans who authored it), over and above the
    /// submitter, who is always excluded. Empty for every unbound ticket.
    std::vector<std::string> excluded_roots;
    /// True when the stored `excluded_roots` column is not a JSON array of strings
    /// (a hand-edited or corrupted row). `excluded_roots` then reads empty, which
    /// must NOT be taken as "nobody is excluded": `approve()` reads the column
    /// itself and refuses the ticket in this state, and any other reader that
    /// acts on `excluded_roots` must refuse on this flag too.
    bool excluded_roots_unreadable{false};
};

/// Bounds on a bound ticket's frozen request (#6062). `request_json` is returned by
/// every list/read of the table and rendered on the Approvals page, so it is capped;
/// a request that does not fit is refused at mint, never truncated (a truncated
/// request is a different request than the one that will be redeemed).
inline constexpr std::size_t kMaxRequestJsonBytes = 16 * 1024;
inline constexpr std::size_t kMaxRequestJsonDepth = 16; ///< nesting limit of the frozen request
inline constexpr std::size_t kMaxExcludedRoots = 32;
inline constexpr std::size_t kMaxExcludedRootBytes = 256;

/// Whether `a`'s STORED state is sound enough for `approve()` to accept (#6062): a stored
/// request that is readable and bounded and hashes to its digest (or no request and no digest
/// at all, an unbound ticket), and an excluded-roots list that could be read. The request half is
/// the very function `approve()` calls (`request_binding_fault`); `approve()` checks the
/// excluded-roots half itself in `set_review_status`, so the two halves agree because tests pin
/// them together (see `approval_state_is_approvable` in test_approval_manager_bound.cpp), not by
/// construction. The dashboard uses this to offer Approve only when the store would not refuse it
/// for these reasons. A reviewer who is themselves excluded or the submitter is a separate,
/// per-viewer question (`reviewer_is_excluded`).
[[nodiscard]] bool approval_state_is_approvable(const Approval& a);

/// THE excluded-reviewer predicate (#6062): is `reviewer` one of the human roots barred
/// from approving? Byte-for-byte, the same comparison as the submitter check (a root IS
/// the principal name at this layer; ADR-0033 section 7's resolution table is applied by
/// whoever builds `excluded_roots` and picks the reviewer). `approve()`, the redemption
/// integrity re-check and the dashboard (which hides Approve, never Reject, from an
/// excluded viewer) all decide through this one function, so the page cannot offer a
/// button the store refuses or hide one it allows. A caller that holds an `Approval` must
/// ALSO refuse on `excluded_roots_unreadable`: an unreadable list is not an empty one.
[[nodiscard]] bool reviewer_is_excluded(const std::string& reviewer,
                                        const std::vector<std::string>& excluded_roots);

/// Whether a stored bound request can be shown to a reviewer and verified (#6062): at
/// most `kMaxRequestJsonBytes`, nested no deeper than `kMaxRequestJsonDepth`, and a JSON
/// object. THE definition of "readable", shared by `approve()` (which refuses a request
/// the reviewer could not have read) and the Approvals renderer (which takes its
/// "unreadable" path instead of parsing or dumping it). The size and depth are checked
/// lexically BEFORE any parse, so a hostile row is rejected without being expanded.
/// An EMPTY string is not readable; callers treat an empty `request_json` as "unbound"
/// before asking.
[[nodiscard]] bool bound_request_is_readable(std::string_view request_json);

/// True for a surface whose tickets MUST bind a request: `submit()` (unbound) refuses
/// to mint one, and only `submit_bound()` does. Exhaustive over `ApprovalOrigin` in
/// the .cpp (a new surface fails the build until it is classified).
[[nodiscard]] bool requires_bound_request(ApprovalOrigin origin);

/// What a bound ticket freezes at mint (#6062). Both parts are written once, at
/// INSERT, and never updated.
struct BoundRequest {
    /// The exact effect the reviewer is shown, as one JSON OBJECT, at most
    /// `kMaxRequestJsonBytes`. The store records it opaquely and derives
    /// `request_digest` from these exact bytes; the Approvals page renders the
    /// subset documented in `approvals_page_render.hpp`.
    std::string request_json;
    /// Human roots barred from approving, in addition to the submitter (who is
    /// always barred). At most `kMaxExcludedRoots` non-empty entries of at most
    /// `kMaxExcludedRootBytes` valid UTF-8 bytes each. Compared byte-for-byte with
    /// the reviewer name, the same comparison the submitter check uses.
    std::vector<std::string> excluded_roots;
};

/// Why `submit_bound` refused. A closed set so a caller can answer each cause
/// distinctly without parsing `message`.
enum class SubmitFailure {
    kInvalidRequest,  ///< an argument or the frozen request failed validation
    kEnginePrincipal, ///< the submitter is an engine principal (`engine:` namespace)
    kQueueFull,       ///< the global pending cap is reached
    kStoreError,      ///< store unavailable or a Postgres failure
};

struct SubmitError {
    SubmitFailure kind{SubmitFailure::kStoreError};
    std::string message;
};

/// Stable messages for the two refusals a route must be able to answer by name.
inline constexpr const char* kEnginePrincipalSubmitMessage =
    "engine principals cannot submit an approval for a gated effect";
inline constexpr const char* kExcludedReviewerMessage =
    "reviewer is excluded from approving this request";
inline constexpr const char* kExcludedRootsUnreadableMessage =
    "this request's excluded reviewers could not be read; it cannot be approved";
inline constexpr const char* kBoundRequestUnreadableMessage =
    "this request's frozen content could not be read or verified; it cannot be approved";
inline constexpr const char* kBoundRequestRequiredMessage =
    "this approval origin requires a bound request; use submit_bound";

struct ApprovalQuery {
    std::string status;
    std::string submitted_by;
};

/// `query_checked()`'s result: the matched rows plus whether the fixed LIST
/// cap (approval_manager.cpp's `kApprovalListCap`, currently 100 — MUST stay
/// equal to `query()`'s own hardcoded `LIMIT 100`, kept unmodified per this
/// method's introducing PR's scope) actually dropped rows. Mirrors
/// `ScheduleEngine::ScheduleListResult` (schedule_engine.hpp) — same #4030-
/// programme rationale: a fleet with more matching approvals than the cap
/// must not have its truncated response mistaken for the complete set.
struct ApprovalListResult {
    std::vector<Approval> approvals;
    bool truncated{false};
};

/// Why a precondition-guarded consume did not consume (#2443). The caller needs
/// these apart: a precondition denial must be reported to the operator as
/// "state moved, mint a fresh ticket" with the ticket still recallable, whereas
/// kNotConsumable means the one-time capability is spent. Distinguishing them by
/// parsing the message string would be a fragile seam, so the kind is typed.
///
/// DISCHARGED (#2443, confirm_engine_rotation): the MCP recall's shared consume
/// failure handling in mcp_server.cpp gives kPrecondition its own client
/// message instead of falling through to "approval already used" - the
/// fallthrough would have told the operator to discard a ticket this code
/// deliberately left recallable, re-entering the very burn class #2443 exists
/// to close. That message is deliberately GENERIC and kind-independent, not
/// this error's own `.message` string: the precondition runs before the
/// tool's own per-handler RBAC check, so echoing the specific fact (which
/// RotationConfirmState fired) would be a credential-state oracle for a
/// tier-eligible, RBAC-less caller. The specific fact still reaches the
/// audit row - server-side, ahead of RBAC concerns - via mcp_server.cpp's
/// `mcp_audit("denied", ...)`, which already fires generically for every
/// ConsumeFailure kind, so kPrecondition needed no new audit/metric plumbing
/// there, only the message split. This store method's own `spdlog::info` on
/// a precondition decline (see the impl) stays a log line by design; the
/// caller's audit row is the durable record.
///
/// A FUTURE second caller of `consume_ticket` with a precondition inherits this same
/// obligation for its own kind of drift: (1) do not let its kPrecondition
/// message fall through to the shared "already used" wording, and (2) if its
/// `.message` carries anything the caller shouldn't learn before their own
/// RBAC gate runs, keep it out of the client-facing text the way this one
/// does - do not assume this comment's DISCHARGED note still covers it.
enum class ConsumeFailure {
    kPrecondition,  ///< precondition denied — ticket UNTOUCHED, still recallable
    kNotConsumable, ///< absent / not approved / already consumed (the CAS lost)
    kStoreError,    ///< store unavailable, missing argument, or a Postgres failure —
                    ///< see ConsumeError::sqlstate/binding_check_unevaluated
    kForeignOrigin, ///< minted on a surface other than the MCP recall (#2442); ALSO the kind for a
                    ///< ticket that fails the redemption integrity re-check (#6062): its stored
                    ///< reviewer is the submitter or an excluded root, or its stored
                    ///< request_json no longer hashes to request_digest. Same forgery class,
                    ///< same uniform message, no new audit/metric label value.
    kForeignSubmitter, ///< recalled by a principal other than the ticket's submitter (#2442)
    kExpired,       ///< approved but unconsumed past kApprovalTicketTtlSeconds since its review
                    ///< (#6061) — refused at consume by DATABASE time, no submit() sweep needed
};

/// The one refusal message this STORE returns for every "this ticket cannot
/// be redeemed" outcome. kForeignOrigin and kForeignSubmitter deliberately
/// share it with kNotConsumable: the KIND separates a forgery attempt (wrong
/// surface, or wrong principal) from a replay for the log, but the MESSAGE
/// must not, or the recall becomes an oracle for which SURFACE minted a
/// ticket or WHO submitted it. (Not for which definition ids exist: a
/// mismatched id is refused earlier, and with a different message, before
/// this is reached.)
///
/// NOT one home end-to-end: the MCP recall (`mcp_server.cpp`) does not
/// consume this constant — it independently hardcodes its own client-facing
/// string ("approval already used (one-time ticket)"), worded differently
/// but semantically the same refusal. The two are kept in sync by test
/// assertions at each layer, not by sharing a symbol. If a future consumer
/// of `ConsumeError` wants the store's own wording, this is it.
/// Stable audit token, one per failure kind. The AUDIT trail is server-side and
/// is never returned to the caller, so the anti-oracle reasoning below does NOT
/// reach it: suppressing the distinction there would destroy the only evidence
/// a cross-surface or cross-submitter redemption attempt was refused, which is
/// the thing #2442 exists to produce.
///
/// Closed set. Adding a `ConsumeFailure` without a token here fails the build on
/// GCC and Clang — `-Wswitch` is promoted to an error locally because
/// `meson.build` sets `werror=false`, so the warning alone would not stop it,
/// and a new kind would otherwise inherit whatever the caller happens to say.
///
/// The ORDER of the MSVC pragmas is load-bearing. C4062 is off by default, and
/// `#pragma warning(error : N)` does NOT enable an off-by-default warning —
/// Microsoft documents that behaviour only for the `1|2|3|4` and `default`
/// specifiers — so promoting it alone sets an as-error flag on a diagnostic
/// that is never emitted. The explicit level enable has to come first.
///
/// Unverified on MSVC: no Windows leg has built this. That is the only reason
/// the claim is hedged. (An earlier version of this comment blamed the
/// whole-function pragma rule instead; that rule is scoped to warnings
/// 4700-4999, and C4062 is parse-time, so it does not reach the `pop` below.)
[[nodiscard]] constexpr const char* consume_denial_reason(ConsumeFailure kind) {
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(1 : 4062) // off by default; `error:` alone does NOT enable it
#pragma warning(error : 4062)
#endif
    switch (kind) {
    case ConsumeFailure::kPrecondition:
        return "precondition";
    case ConsumeFailure::kNotConsumable:
        return "not_consumable";
    case ConsumeFailure::kStoreError:
        return "store_error";
    case ConsumeFailure::kForeignOrigin:
        return "foreign_origin";
    case ConsumeFailure::kForeignSubmitter:
        return "foreign_submitter";
    case ConsumeFailure::kExpired:
        return "expired";
    }
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif
    // Not reachable today: the switch above has an arm per ConsumeFailure
    // value, and the pragma makes a missing arm a compile ERROR rather than a
    // warning. Present so the function still returns on a compiler that does
    // not honour the pragma.
    return "unknown";
}

/// How long a ticket stays live: a PENDING ticket 7 days from submission, an
/// APPROVED-but-unconsumed one 7 days from its review. One constant shared by
/// `submit()`'s lazy sweep and `consume_ticket()`'s expiry predicate (#6061) so
/// the two can never disagree about when a ticket dies.
inline constexpr std::int64_t kApprovalTicketTtlSeconds = 7 * 24 * 3600;

/// How far into the FUTURE (database time) an approved ticket's `reviewed_at` may sit and
/// still count as live. `reviewed_at` is stamped by the database now, so a healthy row is
/// never ahead of `now()`; the slack only absorbs a row written by another path and the
/// boundary of a statement racing the clock. A ticket beyond it is NOT live (consume refuses
/// it, ScheduleRunner will not fire it, the sweep expires it): the lifetime check is a
/// lower bound on `reviewed_at`, and without this upper bound a far-future value satisfies
/// it for as long as the skew lasts (#6061, governance UP-3). 5 minutes.
inline constexpr std::int64_t kApprovalReviewedAtSlackSeconds = 300;

/// Longest reviewer comment `approve`/`reject` accept, in bytes. The guard lives in
/// set_review_status, where REST and MCP meet. The dialogs cap input at 1000 UTF-16
/// units, at most 4000 UTF-8 bytes, so the two limits never disagree.
inline constexpr std::size_t kMaxReviewCommentBytes = 4000;
inline constexpr const char* kReviewCommentTooLong = "comment too long (max 4000 bytes)";

inline constexpr const char* kTicketExpiredMessage =
    "approval ticket expired (past its 7-day lifetime); submit a new request";

inline constexpr const char* kNotConsumableMessage =
    "approval not consumable (already used, not approved, or absent)";

/// A store read's failure, kept apart from the row simply not being there.
/// `sqlstate` is the Postgres SQLSTATE (`PQresultErrorField(...,
/// PG_DIAG_SQLSTATE)`) at the failing query, or empty when the failure has
/// no Postgres origin (store not open, missing argument) — see
/// `pg_error_class.hpp::is_permanent_pg_error` (ADR-0065 port of #2786
/// "PR 1c", which this field replaces: was `int extended_errcode`, a raw
/// `sqlite3_extended_errcode()`).
struct StoreReadError {
    std::string message;
    std::string sqlstate;
};

struct ConsumeError {
    ConsumeFailure kind{ConsumeFailure::kStoreError};
    std::string message;
    /// The Postgres SQLSTATE for a `kStoreError` produced by a Postgres
    /// read/write failure; empty otherwise (store not open, missing
    /// argument, a throwing precondition). See
    /// `pg_error_class.hpp::is_permanent_pg_error` (ADR-0065 port of #2786).
    /// The empty default is safe for the store-not-open producer
    /// specifically because `approval_store_error_body`'s permanent-arm
    /// check is `!is_open() || is_permanent_pg_error(sqlstate)` — the
    /// `is_open()` disjunct alone correctly forces the permanent arm there
    /// regardless of `sqlstate`. The missing-argument/throwing-precondition
    /// producers are NOT similarly protected: the store IS open in those
    /// cases, so an empty `sqlstate` DOES take the transient arm if that
    /// `kStoreError` ever reaches `approval_store_error_body` (see
    /// `consume_ticket`'s guard-clause comment for why this is harmless
    /// today — the sole production caller never triggers them).
    std::string sqlstate;
    /// True ONLY when the #2442 cross-surface/cross-submitter binding check's
    /// own read (`get_checked` inside `consume_ticket`) is the thing that
    /// faulted — so NEITHER the origin nor the submitter comparison ran, and
    /// a foreign-origin or foreign-submitter ticket could be hiding behind
    /// this refusal exactly as easily as an innocent one. #2786 arm 1:
    /// without this, a store fault at that specific read reports as a plain
    /// `kStoreError` and the forgery-detection signal is lost for the
    /// duration of the fault. False for every other `kStoreError` producer
    /// (the store-not-open guard, the missing-id/missing-principal guards,
    /// the CAS itself, the precondition recheck read, a throwing
    /// precondition) — those never reached the binding check, so there is
    /// nothing masked to flag.
    bool binding_check_unevaluated = false;
};

/// One `kPrecondition` denial, handed to the observer installed with
/// `ApprovalManager::set_precondition_denial_observer` (#6062). Plain data, no
/// `Approval` row: the observer writes an audit record, and the row's
/// `definition_id` / `scope_expression` are caller-supplied text the audit detail
/// must not carry (see ConsumePrecondition).
struct PreconditionDenial {
    std::string approval_id;
    ApprovalOrigin origin{ApprovalOrigin::kUnspecified}; ///< the ticket's (concrete) origin
    std::string consumed_by;                             ///< who tried to redeem it
    std::string reason; ///< the precondition's own message (server-authored, see ConsumePrecondition)
};
using PreconditionDenialObserver = std::function<void(const PreconditionDenial&)>;

/// A cheap, read-only recheck of the state a ticket's effect depends on,
/// evaluated between the ticket match and the consuming CAS (#2443). Returning
/// an error denies the recall WITHOUT consuming; the string is operator-facing
/// (it reaches the MCP error envelope's remediation), so say what drifted.
///
/// Two constraints on what you may write there. The message must not echo any
/// field of the `Approval` it is handed: `definition_id` and `scope_expression`
/// are caller-supplied, and the MCP envelope and audit detail are documented as
/// carrying no caller-derived text. And the callback must not decide AUTHORITY —
/// that stays in the core approval gate, which can audit it. This seam is for
/// state the effect depends on (a rotation already resolved, a device gone),
/// not for re-deciding who may act.
using ConsumePrecondition = std::function<std::expected<void, std::string>(const Approval&)>;

class ApprovalManager {
public:
    /// Global cap on `status='pending'` rows `submit()` enforces (queue-cap +
    /// lazy-expiry-sweep, see `submit()`'s body). Exposed so tests exercising
    /// the boundary reference this constant instead of duplicating the
    /// literal (governance quality-engineer finding, 2026-08-31).
    static constexpr int kMaxPendingApprovals = 1000;

    explicit ApprovalManager(pg::PgPool& pool);
    ~ApprovalManager() = default;

    ApprovalManager(const ApprovalManager&) = delete;
    ApprovalManager& operator=(const ApprovalManager&) = delete;

    /// Wire the metrics registry for `yuzu_approval_precondition_denied_total{origin}`.
    /// Set ONCE during single-threaded startup, before any consume; null (the default)
    /// disables emission.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// Install the observer that records a `kPrecondition` denial in the audit trail
    /// (#6062: "a precondition denial gets an audit row plus a counter" - at the
    /// STORE, so every present and future redeemer gets both, not just the one that
    /// remembers). Set ONCE during single-threaded startup. The store increments the
    /// counter itself and then calls the observer; an exception from the observer is
    /// caught and logged, never propagated out of `consume_ticket`.
    ///
    /// The observer runs on the consuming thread, BEFORE `consume_ticket` returns,
    /// and for the `PGconn*` overload while the caller's transaction is open. It must
    /// therefore write its record on its OWN connection (AuditStore::log, never
    /// log_in_txn on the caller's): a denial is evidence about the attempt, not part
    /// of the caller's mutation, and must survive the caller rolling back.
    void set_precondition_denial_observer(PreconditionDenialObserver obs) {
        denial_observer_ = std::move(obs);
    }

    /// TEST SEAM (same precedent as `ApiTokenStore`'s `test_hook_before_*`): called by
    /// `consume_ticket` at the two points where a concurrent writer could change the row and
    /// where an interleaving test cannot otherwise stand - between the first read and the
    /// precondition's fresher read (only when a precondition is supplied), and after every
    /// check has passed, immediately before the consuming CAS. Never set in production; set
    /// once before any consume, so it is read without a lock. A hook must not call back into
    /// this manager's consume path.
    enum class ConsumeTestStage { kBetweenReads, kBeforeCas };
    void set_consume_test_hook_for_test(std::function<void(ConsumeTestStage)> hook) {
        consume_test_hook_ = std::move(hook);
    }

    /// Idempotent no-op kept for call-site compatibility — migration now
    /// runs unconditionally inside the constructor (PgMigrationRunner),
    /// unlike the SQLite era where callers invoked this explicitly.
    void create_tables() {}

    /// `schedule_id` (M-02, #1806): empty for the interactive submit path;
    /// the owning schedule's id for a scheduled-fire submission — see the
    /// `Approval::schedule_id` doc comment for why this matters.
    ///
    /// `origin` (#2442) RECORDS the minting surface. It is not enforced here:
    /// this store does not refuse a `mcp.`-prefixed definition_id from any
    /// surface. The binding is applied at REDEMPTION, in `consume_ticket`,
    /// which refuses a ticket whose recorded surface is not the one the redeemer
    /// declares (`origin_redeemable_as`) - see the rationale in `submit()`'s body
    /// for why the check moved.
    ///
    /// No default (#2442's closing half — was `= ApprovalOrigin::kUnspecified`
    /// until the MCP mint could declare `kMcp`; it does now). Every caller
    /// states its surface explicitly, so a future caller cannot silently
    /// regain the pre-fix behaviour by forgetting the argument — and forgetting
    /// it is now a compile error rather than a silent `kUnspecified`, which
    /// itself refuses at redemption today, not grants (see `origin_redeemable_as`).
    ///
    /// `target_plugin`/`target_action` (#1398 hardening): see
    /// `Approval::target_plugin`'s doc comment. Both DEFAULTED (unlike
    /// `origin`) because they have no meaning at the generic MCP mint call
    /// site (one shared helper across several tools, no single
    /// plugin/action in scope) — callers that DO have one (`ScheduleRunner`,
    /// the interactive workflow route) must pass both.
    std::expected<std::string, std::string>
    submit(const std::string& definition_id, const std::string& submitted_by,
           const std::string& scope_expression, const std::string& schedule_id,
           ApprovalOrigin origin, std::string target_plugin = {},
           std::string target_action = {});

    /// Mint a ticket that BINDS the exact reviewed effect (#6062, four-eyes MVP PR2).
    /// `bound.request_json` and its SHA-256 digest (computed here, so the two cannot
    /// disagree) and `bound.excluded_roots` are frozen on the row at INSERT; no later
    /// statement in this store updates them, and `approve()` refuses a reviewer named
    /// in `excluded_roots`. Everything else (the pending cap, the lazy expiry sweep,
    /// the id, `origin` having no default) is exactly `submit()`'s, in the same
    /// transaction - there is one mint body, not two.
    ///
    /// Refused with a TYPED error (`SubmitFailure`), nothing written, when:
    ///   - the submitter is an engine principal (`engine:` is a reserved namespace
    ///     no human account can hold - the boot-time collision scan fails closed on
    ///     one - so the prefix is the engine discriminator here; a caller that
    ///     holds the session should also test `Session::is_engine()` first). A
    ///     gated effect needs a human requester root (ADR-0033 section 7);
    ///   - `origin` names no concrete surface (kUnspecified / kUnrecognised);
    ///   - `request_json` is empty, over `kMaxRequestJsonBytes`, nested deeper than
    ///     `kMaxRequestJsonDepth`, not a JSON object, or contains a NUL byte anywhere
    ///     (the JSON parser accepts a NUL after a complete value, but the column is bound
    ///     as a C string: the digest, taken over every byte, would then disagree with
    ///     the stored prefix);
    ///   - an excluded root is empty, over-long, not valid UTF-8, contains a control
    ///     character (below 0x20, or 0x7F; a principal name has none), or the list is
    ///     over `kMaxExcludedRoots`.
    [[nodiscard]] std::expected<std::string, SubmitError>
    submit_bound(const std::string& definition_id, const std::string& submitted_by,
                 const std::string& scope_expression, const std::string& schedule_id,
                 ApprovalOrigin origin, const BoundRequest& bound, std::string target_plugin = {},
                 std::string target_action = {});

    std::vector<Approval> query(const ApprovalQuery& q = {}) const;

    /// unhappy-path governance finding (#2146 A2-R4): neither GET
    /// /api/v1/approvals nor MCP list_pending_approvals validated `status`
    /// against this closed set before this fix -- an unrecognized value
    /// (a typo, a case mismatch, or MCP's explicit `""`) flowed straight
    /// into a SQL equality filter and silently produced a false-empty (or,
    /// for `""`, a false-ALL-statuses) result instead of rejecting the
    /// caller's malformed input. Mirrors ResponseStore::allowed_op_column()
    /// and ScheduleEngine's group_by allow-list convention.
    static const std::vector<std::string>& allowed_status();

    /// query() with the store failure kept apart from a genuinely empty
    /// result — the same rationale as get_checked (see its doc comment):
    /// query() collapses "not open" / "pool exhausted" / "query failed"
    /// into the SAME empty vector a real zero-match result returns, so a
    /// caller polling "are there any approvals needing attention" (REST v1
    /// `GET /api/v1/approvals`, MCP `list_pending_approvals`) cannot tell
    /// "all clear" from "blind to a backlog because the store is down" — a
    /// silent false-negative on exactly the signal a maker-checker workflow
    /// depends on. Returns `StoreReadError` (not a bare optional/string) so
    /// the caller can classify permanent-vs-transient via `sqlstate`, the
    /// same shape `get_checked` already established in this class.
    ///
    /// `ApprovalListResult::truncated` is detected by querying one row PAST
    /// the fixed cap (matches `ScheduleEngine::query_schedules_checked`'s
    /// technique, schedule_engine.cpp) so a match count of EXACTLY the cap
    /// is never misreported as truncated — the simpler "returned == limit"
    /// heuristic false-positives at that boundary.
    std::expected<ApprovalListResult, StoreReadError> query_checked(const ApprovalQuery& q = {}) const;

    /// Single-approval lookup by id (read-only). Two callers: the versioned
    /// GET /api/v1/approvals/{id} status_url target (query()'s LIMIT 100 would
    /// false-404 an id that has aged past the top window), and the MCP
    /// approval-ticket recall path (#289), which reads
    /// status/definition_id/scope_expression/consumed_at to validate a ticket
    /// before consuming it. Returns std::nullopt when no row matches; does NOT
    /// touch the lifecycle (submit/approve/reject/consume are elsewhere).
    /// True iff the store is usable (schema migrated). False after a failed
    /// migration — feeds the /readyz + /healthz conjunction so a broken approval
    /// schema fails the probe instead of serving errors behind a green light
    /// (governance sre-BLOCKING-1).
    [[nodiscard]] bool is_open() const noexcept { return open_; }

    std::optional<Approval> get(const std::string& id) const;

    /// get() with the store failure kept apart from the row simply not being
    /// there. Both read back as nullopt through get(), which is fine for a
    /// caller that 404s either way, and NOT fine for one deciding whether a
    /// one-time capability is spent — see consume_ticket's pre-consume recheck,
    /// which uses this.
    std::expected<std::optional<Approval>, StoreReadError> get_checked(const std::string& id) const;

    /// Newest PENDING approval matching (definition_id, submitted_by,
    /// scope_expression), or nullopt. The MCP approval-ticket mint dedup key
    /// (#289 / governance UP-1): reusing an extant pending ticket makes the mint
    /// idempotent and stops a supervised token flooding the global pending cap.
    std::optional<Approval> find_pending(const std::string& definition_id,
                                         const std::string& submitted_by,
                                         const std::string& scope_expression) const;

    int pending_count() const;

    /// pending_count() with the same store-failure/genuinely-empty
    /// distinction as query_checked (see its doc comment) — pending_count()
    /// returns 0 for "not open" / "pool exhausted" / "query failed",
    /// identical to a real "zero pending approvals" state.
    std::expected<int, StoreReadError> pending_count_checked() const;

    /// Count of PENDING approvals submitted by one principal. Backs the MCP
    /// mint's per-submitter sub-cap (governance sec8-MEDIUM-1): dedup alone does
    /// not stop an adaptive flood (a nonce key defeats the args-hash), so the
    /// mint bounds any single supervised token's share of the GLOBAL cap.
    int pending_count_for(const std::string& submitted_by) const;

    std::expected<void, std::string> approve(const std::string& id, const std::string& reviewer,
                                             const std::string& comment);

    std::expected<void, std::string> reject(const std::string& id, const std::string& reviewer,
                                            const std::string& comment);

    /// Atomically consume an APPROVED, not-yet-consumed approval as a one-time
    /// ticket (#289). Returns ok() iff THIS call transitioned consumed_at
    /// 0→now — the CAS (`WHERE status='approved' AND consumed_at=0 RETURNING 1`)
    /// carries the match signal in the step return code, so there is no
    /// `sqlite3_changes()` race on the shared FULLMUTEX connection (#1033). A
    /// replay of an already-consumed ticket, or an absent/non-approved id,
    /// returns unexpected. The caller validates definition_id + args BEFORE
    /// calling; this method guards the double-consume (concurrent-recall) race so
    /// a mutating tool executes at most once per ticket.
    ///
    /// `consumed_by` records WHO recalled the ticket (PR #1796 H3/N2, SOC-2
    /// CC7.2) — the caller passes the authenticated principal; it is stored in
    /// the same CAS UPDATE so the who and the when can never disagree.
    ///
    /// EXPIRY (#6061): the CAS also requires `reviewed_at` to be within
    /// kApprovalTicketTtlSeconds of DATABASE time, so an approved ticket past
    /// its lifetime is refused (ConsumeFailure::kExpired) even if no submit()
    /// has swept it yet. The refusal leaves the row untouched.

    /// Is `id` an approved, unconsumed ticket still inside its lifetime, by DATABASE time?
    /// This is the one liveness predicate (`ticket_live_sql()` in the .cpp): the same text
    /// gates the consume CAS and submit()'s approved-ticket sweep, so an approved ticket
    /// that consume would refuse as expired is never fired by ScheduleRunner either
    /// (#6061, governance SG-2). A store failure is an error, not `false`: the caller
    /// (the scheduler) holds the occurrence rather than treating an unreadable ticket as
    /// a dead one. Read-only; consumes nothing.
    [[nodiscard]] std::expected<bool, std::string> ticket_is_live(const std::string& id) const;

    /// ORIGIN-DECLARED consume with a pre-consume recheck (#2443, #6062). A ticket can sit
    /// approved-but-unconsumed for up to the 7-day TTL, so the state its effect
    /// assumes may have moved on (the canonical case: an engine-key rotation the
    /// ticket confirms has already resolved). Without a recheck the recall
    /// matches, CONSUMES, and only then does the handler fail — burning a
    /// human-approved one-time capability on a no-op and forcing a fresh
    /// approval round.
    ///
    /// `expected` is the surface the CALLER is, and it has no default on purpose
    /// (#6062): a caller that does not say which surface it redeems for cannot
    /// redeem. The ticket's recorded origin must equal it (`origin_redeemable_as`);
    /// kUnspecified and kUnrecognised as `expected` ALWAYS refuse
    /// (ConsumeFailure::kForeignOrigin, uniform message), whatever the row says.
    ///
    /// Order: argument guards → `expected` is a concrete surface → #2442
    /// origin+submitter binding check → redemption integrity re-check (#6062: an
    /// approved, unconsumed row whose stored reviewer is the submitter or an excluded
    /// root, whose excluded_roots cannot be read, or whose non-empty request_json no
    /// longer hashes to request_digest is refused as kForeignOrigin with the uniform
    /// message; a legacy row with no request and no roots is unaffected) → match the
    /// row → reject a non-consumable one → evaluate `precondition` → CAS.
    /// A precondition denial returns ConsumeFailure::kPrecondition and leaves
    /// the row untouched, so the same ticket is still recallable once the
    /// operator resolves the drift; the binding check has the same
    /// untouched-on-refusal property.
    ///
    /// `precondition` runs WITHOUT `mtx_` held, deliberately: it inspects state
    /// OUTSIDE this store (rotation status, device state — never authority; see
    /// ConsumePrecondition), which no lock
    /// here can freeze, so holding the store mutex across an arbitrary caller
    /// callback would buy no atomicity while adding a lock-order hazard and
    /// serialising the store behind caller I/O. The consequence is honest rather
    /// than hidden: this NARROWS the drift window, it does not close it — state
    /// can still move between a passing recheck and the CAS, and a handler must
    /// stay correct when it does. The CAS remains the sole one-time-consumption
    /// guard, so a concurrent recall still loses exactly as before.
    ///
    /// An empty `precondition` runs no recheck.
    ///
    /// A `kPrecondition` denial is observable at the store for EVERY origin
    /// (#6062): `yuzu_approval_precondition_denied_total{origin}` counts it and the
    /// installed denial observer (`set_precondition_denial_observer`) writes the
    /// audit row. MCP's own per-tool counter and `mcp_audit` row are unchanged and
    /// additional.
    [[nodiscard]] std::expected<void, ConsumeError> consume_ticket(const std::string& id,
                                                     const std::string& consumed_by,
                                                     ApprovalOrigin expected,
                                                     const ConsumePrecondition& precondition);

    /// The same consume, joined to the CALLER's transaction (#6062): every read, the
    /// precondition and the consuming CAS run on `conn`, which the caller has already
    /// begun a transaction on, and this method neither begins, commits nor rolls
    /// anything back. Rolling the caller's transaction back therefore rolls the
    /// consume back with it, and committing it commits the consume atomically with
    /// whatever else the caller wrote - the point of the overload: a deploy that
    /// redeems its approval and records itself in one transaction cannot spend the
    /// ticket without the deploy, nor deploy without spending it.
    ///
    /// The row is read `FOR UPDATE`, so it stays locked from the binding check
    /// through the CAS until the caller ends the transaction - the precondition and
    /// the CAS are one critical section here, unlike the pooled overload's two
    /// leases. `precondition` therefore runs INSIDE the caller's transaction on
    /// `conn`'s lock: keep it cheap and never have it touch `conn` or take another
    /// store's lease it could wait on while the caller's pool is exhausted.
    ///
    /// Postgres aborts a transaction on any failed statement, so a kStoreError from
    /// this overload leaves the caller's transaction unusable until it rolls back;
    /// the caller must roll back on ANY error. A refusal that is not a store error
    /// (kForeignOrigin, kNotConsumable, kPrecondition, ...) leaves the transaction
    /// healthy and the row untouched. `conn` must be non-null; null is a
    /// kStoreError. The caller keeps `conn` and its lease alive for the call.
    [[nodiscard]] std::expected<void, ConsumeError> consume_ticket(PGconn* conn, const std::string& id,
                                                     const std::string& consumed_by,
                                                     ApprovalOrigin expected,
                                                     const ConsumePrecondition& precondition);

private:
    /// The ONE consume body behind both public overloads. `held` is the caller's
    /// transaction connection, or nullptr for the pooled path (own bounded leases,
    /// exactly the pre-#6062 behaviour).
    std::expected<void, ConsumeError> consume_core(PGconn* held, const std::string& id,
                                                   const std::string& consumed_by,
                                                   ApprovalOrigin expected,
                                                   const ConsumePrecondition& precondition);

    /// `get_checked`'s read on an already-held connection (no lease taken).
    /// `for_update` adds `FOR UPDATE` - only meaningful inside a transaction.
    std::expected<std::optional<Approval>, StoreReadError>
    read_row(PGconn* conn, const std::string& id, bool for_update) const;

    /// The ONE mint body behind `submit` (`bound == nullptr`) and `submit_bound`.
    std::expected<std::string, SubmitError>
    submit_impl(const std::string& definition_id, const std::string& submitted_by,
                const std::string& scope_expression, const std::string& schedule_id,
                ApprovalOrigin origin, const BoundRequest* bound, std::string target_plugin,
                std::string target_action);

    std::expected<void, std::string> set_review_status(const std::string& id,
                                                       const std::string& status,
                                                       const std::string& reviewer,
                                                       const std::string& comment);

    pg::PgPool& pool_;
    bool open_{false};
    // Protects ONLY submit()'s compound cap-check + expiry-sweep + insert
    // (G4-UHP-MCP-005) — narrowed from the SQLite era's "all db_ access"
    // scope now that Postgres's own per-row/per-statement concurrency
    // replaces the rest (consume_ticket's CAS is a single atomic
    // UPDATE...RETURNING; every other method issues one statement per
    // call). This mutex still only serializes THIS PROCESS's callers —
    // multi-replica coordination of the pending-cap/expiry-sweep
    // check-then-act is an ADR-2002 (HA) concern, not addressed here.
    mutable std::mutex mtx_;
    yuzu::MetricsRegistry* metrics_{nullptr};     // borrowed; set_metrics, startup only
    PreconditionDenialObserver denial_observer_;  // set_..._observer, startup only
    std::function<void(ConsumeTestStage)> consume_test_hook_; // tests only, see the setter
};

} // namespace yuzu::server
