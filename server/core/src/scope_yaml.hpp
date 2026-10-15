#pragma once

#include "result_set_store.hpp" // ResultSetError, used by value in the widened
                                // resolve_scope_aliases/scope_refs_failing_owner_check
                                // return types below (ADR-0036) — a forward
                                // declaration of the enum is not worth the risk
                                // against std::expected's instantiation needs.

#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

// Scope-walking YAML DSL surface (PR-E, design docs/scope-walking-design.md §7).
//
// A `spec.scope:` block may carry a `fromResultSet:` reference (a result-set id
// or per-operator alias) and/or a `selector:` (platform + tags), composed with
// AND. This module parses that block, validates the design's rules, and lowers
// it to a scope-engine expression string the existing parser/resolver already
// consume (scope_engine.cpp `from_result_set:` / `ostype` / `EXISTS tag:`).
//
// Resolution is lazy: lowering produces a string only; result-set membership is
// resolved at dispatch by AgentRegistry::evaluate_scope. A definition carrying a
// `fromResultSet:` that has since expired is still valid YAML.

/// Parsed `spec.scope` block. All fields default to "absent".
struct ScopeBlock {
    bool has_from_result_set{false};
    std::string from_result_set; // raw value: a canonical `rs_<...>` id or an alias
    bool has_selector{false};
    std::string selector_platform;          // selector.platform (e.g. "windows")
    std::vector<std::string> selector_tags; // selector.tags (presence-checked)
};

/// Parse the `spec.scope` block out of a full definition/policy `yaml_source`.
/// A scalar `scope:` (a raw scope-engine expression) yields an empty ScopeBlock
/// — callers handle the scalar form separately for backward compatibility.
ScopeBlock parse_scope_block(const std::string& yaml_source);

/// Enforce the design §7 rules when `fromResultSet` is present:
///   1. `fromResultSet` + `assignment.managementGroups` is forbidden.
///   2. `fromResultSet` requires `assignment.mode` to be `static` (reject
///      `dynamic`; an omitted mode defaults to static and is accepted).
/// Also rejects an empty / over-long `fromResultSet` value. `assignment_mode`
/// and `assignment_has_mgmt_groups` are passed in so the caller controls
/// section isolation (these fields live under `spec.assignment`, not `scope`).
/// Returns an error message, or std::nullopt when the block is valid.
std::optional<std::string> validate_scope_block(const ScopeBlock& sb,
                                                const std::string& assignment_mode,
                                                bool assignment_has_mgmt_groups);

/// Lower a (validated) ScopeBlock to a scope-engine expression string, AND-ing
/// the parts: `from_result_set:<ref>`, `ostype == "<platform>"` (platform
/// lower-cased), and `EXISTS tag:<name>` per selector tag. Returns "" for an
/// empty block.
std::string lower_scope_block(const ScopeBlock& sb);

// ── Dispatch-time result-set reference resolution ────────────────────────────
//
// The scope resolver (agent_registry.cpp) owner-checks result-set ids but does
// NOT resolve per-operator aliases — callers must pre-resolve at the dispatch
// layer where the owner is known. These free functions do that, sharing the
// from_result_set:<ref> token grammar of scope_engine.cpp's tokenizer (idents:
// alnum / _ . : - *) and skipping quoted string literals.

/// Rewrite each `from_result_set:<alias>` atom (a ref not already a canonical
/// `rs_` id) to its canonical id via store->resolve_alias(owner, alias).
/// Canonical ids and unresolved (genuinely-not-found) aliases are left as-is
/// (they no-match downstream — stale drops silently, design §4.3). No-op
/// (returns `expr` unchanged) when `owner` is empty or `store` is null,
/// mirroring the resolver's empty-principal contract.
///
/// Returns `std::unexpected(DbError)` — ADR-0036 fail-closed contract — when
/// `resolve_alias` hits a Postgres error mid-rewrite. The caller MUST treat
/// this as "abort dispatch" (503/internal-error), never fall back to the
/// unresolved expression: an unresolved `from_result_set:<alias>` atom
/// no-matches downstream and, under a `NOT` combinator, INVERTS to
/// match-every-agent — the same class of fleet-wide fail-open
/// `member_set_owned`'s contract guards against.
std::expected<std::string, ResultSetError> resolve_scope_aliases(std::string_view expr,
                                                                 const std::string& owner,
                                                                 ResultSetStore* store);

/// Return the `from_result_set:<ref>` atoms in an (already alias-resolved)
/// expression that fail the owner check: the set is absent/expired
/// (store->get == nullopt) or owned by another principal. A set that exists, is
/// owned, and is legitimately empty is NOT reported. Empty when `owner` is empty
/// or `store` is null (no owner context to check against). Drives the
/// invocation-time INSTRUCTION_SCOPE_RESOLUTION_FAILED audit row (design §7).
///
/// **#4981 PR-1 (Finding A/A2): this is an EARLY, per-ref FORENSIC pass —
/// NOT the binding authorization check.** It runs once, before parsing, using
/// `store->get()` (a plain existence+ownership read). The BINDING check is
/// `AgentRegistry::evaluate_scope`'s own `member_set_owned` preload, which
/// runs later (after parsing, at actual registry evaluation) against the
/// SAME store in a single snapshot-consistent statement (A1) — so a set that
/// passes THIS check can still be deleted/expired in the window between here
/// and that later read (a real TOCTOU race: `delete_set`/`gc_sweep` both
/// cascade via an FK), and `evaluate_scope` aborts fail-closed
/// (`ScopeEvalError::Kind::OwnerCheckFailed`) when that happens — this
/// function's job is only to produce the early per-ref forensic audit row
/// BEFORE that later abort, not to be the sole gate against it. The
/// redundancy between the two checks (an owner-valid ref here can still fail
/// at evaluate_scope moments later) is a harmless, deliberate two-layer
/// check, not a bug — do not "simplify" it away.
///
/// Returns `std::unexpected(DbError)` when `store->get` hits a Postgres error
/// mid-scan (ADR-0036 fail-closed contract) — the caller MUST abort dispatch
/// rather than proceed with a partial/no audit-row view (this function is a
/// forensic side-channel, but a degraded scan could also mask a
/// genuinely-failing owner check, which the audit row exists to surface).
std::expected<std::vector<std::string>, ResultSetError>
scope_refs_failing_owner_check(std::string_view expr, const std::string& owner,
                               ResultSetStore* store);

/// The single dispatch-gate decision for a resolved scope expression
/// (governance M1, 2026-07-29). Consumes scope_refs_failing_owner_check and
/// classifies the outcome:
///   - AbortDbDegraded  — the owner-check scan itself failed (store degraded);
///   - AbortOwnerCheck  — one or more referenced sets are absent, expired, or
///                        not owned by `principal` (`failing_out` carries them
///                        for per-ref forensic audit rows);
///   - Proceed          — every from_result_set: reference is owner-valid (or
///                        the expression has none) AT THIS EARLY CHECK — see
///                        `scope_refs_failing_owner_check`'s doc comment
///                        above: `evaluate_scope`'s own later preload is the
///                        binding check and can still abort after this
///                        returns Proceed (#4981 PR-1 Finding A TOCTOU case).
/// Extracted from the three dispatch sites (REST raw / tracked closure / MCP)
/// so the abort-vs-proceed rule is ONE testable function: the pre-M1 bug was
/// exactly a caller auditing the failing refs and then dispatching anyway,
/// which a NOT combinator inverts into a fleet-wide match. Callers MUST NOT
/// parse/evaluate/dispatch unless this returns Proceed — but a Proceed here
/// is a necessary, not sufficient, condition for the dispatch to actually go
/// through; the later evaluate_scope call can still abort.
enum class ScopeDispatchGate { Proceed, AbortDbDegraded, AbortOwnerCheck };
ScopeDispatchGate gate_scope_dispatch(std::string_view resolved_scope,
                                      const std::string& principal, ResultSetStore* store,
                                      std::vector<std::string>& failing_out);

} // namespace yuzu::server
