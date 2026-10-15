#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

/// @file authz_model.hpp
/// The registry-INDEPENDENT authz MODEL on the ADR-0033 §2 spine
/// (`docs/adr/0033-access-control-spine.md:141-159`): the
/// securable×operation×risk_tier×mcp_tier_class classification a future
/// runtime capability-declaration registry (PR1.9) will consume when a
/// Module registers a tool or REST route.
///
/// WHAT THIS IS NOT: it does not create that registry, it does not read or
/// write `rbac.db`, and it enforces nothing on the wire — it is a header-only
/// vocabulary + a handful of pure classification rules, seeded with the SAME
/// securable/operation catalogue `RbacStore::seed_defaults()` hardcodes today
/// (`rbac_store.cpp:291-327`+ops, 23 seeded types, read-only reference) so PR1.9 has real data
/// to migrate rather than a speculative schema. `mcp_policy.hpp` is the other
/// read-only reference for the existing (securable, operation) vocabulary in
/// live use.
///
/// It also carries the shared #1788 fix primitive (`VisibleSet` /
/// `in_scope` / `filter_to_scope`): the one place that composes with — and
/// never re-decides — the frozen #1715/INV-7 lattice `RbacStore` already
/// resolves. See the header-bottom section for that half.
namespace yuzu::server::authz {

// ── §2 vocabulary ────────────────────────────────────────────────────────

/// The RBAC operation vocabulary. ADR-0033 §2 names "the existing six" as
/// Read/Write/Execute/Delete/Approve/Push; `Attest` is a SEVENTH, narrower
/// operation added since for Periodic Access Reviews (SOC 2 CC6.2,
/// `rbac_store.cpp` seed comment) — deliberately excluded from the CRUD
/// loops there, and included here for the same reason: a Module capability
/// can genuinely declare it (the seed catalogue below has an example).
/// `Rotate` is an EIGHTH (P2 #11, SOC 2 CC6.3, `rbac_store.cpp` seed
/// comment), same treatment, and DELIBERATELY DISTINCT from `Write` on its
/// own securable (`ApiToken`) — why is mcp_policy.hpp's `tier_allows()`
/// operator-tier comment, the single narrative home for that finding.
enum class Operation : uint8_t {
    Read,
    Write,
    Execute,
    Delete,
    Approve,
    Push,
    Attest,
    Rotate,
};

[[nodiscard]] constexpr std::string_view to_string(Operation op) {
    switch (op) {
        case Operation::Read: return "Read";
        case Operation::Write: return "Write";
        case Operation::Execute: return "Execute";
        case Operation::Delete: return "Delete";
        case Operation::Approve: return "Approve";
        case Operation::Push: return "Push";
        case Operation::Attest: return "Attest";
        case Operation::Rotate: return "Rotate";
    }
    return "";
}

/// ADR-0033 §2's `mcp_tier_class` (read / write / execute) — the routing
/// input the shipped tier-before-RBAC ordering (`docs/mcp-server.md`,
/// `mcp_policy.hpp::tier_allows`) evaluates every built-in AND declared tool
/// through, per the ADR's "one chokepoint, never a parallel one" rule.
///
/// This is deliberately NOT derived purely from `Operation` in general — §1
/// of the ADR is explicit that read-vs-effect ("the one typing that must not
/// be self-certified") is core's RATIFIED mutability class, decided when a
/// Module's capability manifest is approved, never inferred from the
/// operation name alone. `default_mcp_tier_class` below is a convenience for
/// classifying THIS header's own seed catalogue, not a rule PR1.9's
/// registration path is bound to follow for an arbitrary future declaration.
enum class McpTierClass : uint8_t {
    Read,
    Write,
    Execute,
};

[[nodiscard]] constexpr std::string_view to_string(McpTierClass cls) {
    switch (cls) {
        case McpTierClass::Read: return "read";
        case McpTierClass::Write: return "write";
        case McpTierClass::Execute: return "execute";
    }
    return "";
}

/// The routing input ADR-0033 §5 (D5)'s future auto-approval policy layer
/// consumes ("auto-approve if risk tier is low *and* blast radius < N
/// devices..."), captured from day one per §2. The ADR does not fix concrete
/// thresholds — D5 is explicitly future work — so this is a deliberately
/// small, ordered scale: enough for PR1.9 to carry a real value per
/// declaration without this header pre-committing to a policy it does not
/// own. `min_risk_tier_for` below is the one rule this header DOES commit
/// to: a floor per operation, so a Module cannot under-declare risk for an
/// inherently sensitive operation class.
enum class RiskTier : uint8_t {
    Low,
    Medium,
    High,
    Critical,
};

[[nodiscard]] constexpr std::string_view to_string(RiskTier tier) {
    switch (tier) {
        case RiskTier::Low: return "low";
        case RiskTier::Medium: return "medium";
        case RiskTier::High: return "high";
        case RiskTier::Critical: return "critical";
    }
    return "";
}

/// The default `mcp_tier_class` for the seed catalogue below. `Read` maps to
/// the read tier; every mutating or irreversible operation maps to `Write`
/// except `Execute` itself, which maps to `Execute` — matching
/// `mcp_policy.hpp`'s existing special-case (`Execution:Execute` is the one
/// combination the `operator` MCP tier auto-approves without also allowing
/// arbitrary writes). NOT a substitute for per-capability ratification (see
/// the `McpTierClass` doc comment above).
[[nodiscard]] constexpr McpTierClass default_mcp_tier_class(Operation op) {
    if (op == Operation::Read)
        return McpTierClass::Read;
    if (op == Operation::Execute)
        return McpTierClass::Execute;
    return McpTierClass::Write; // Write/Delete/Approve/Push/Attest/Rotate: all mutating effects
}

/// The rule for sensitive definitions: a floor `risk_tier` per operation, so
/// a capability declaration can never UNDER-state the risk of an inherently
/// sensitive operation class. A declaration below its floor is invalid (see
/// `is_valid` on `CapabilityDeclaration`) — PR1.9's registration path rejects
/// it rather than silently accepting a self-certified "low risk" delete.
/// Declaring ABOVE the floor is always fine; this is a minimum, not a fixed
/// value.
[[nodiscard]] constexpr RiskTier min_risk_tier_for(Operation op) {
    switch (op) {
        case Operation::Read: return RiskTier::Low;
        case Operation::Write: return RiskTier::Medium;
        case Operation::Execute: return RiskTier::Medium;
        case Operation::Attest: return RiskTier::Medium;
        // Same floor as Write — Rotate is a self-service mutating operation
        // on its own securable (ApiToken), not a fleet-wide or irreversible
        // one like Delete/Approve/Push.
        case Operation::Rotate: return RiskTier::Medium;
        case Operation::Delete: return RiskTier::High;
        case Operation::Approve: return RiskTier::High;
        case Operation::Push: return RiskTier::High;
    }
    return RiskTier::Critical; // unreachable for a valid enumerator; fail loud, not low
}

// ── PR1.9-facing declaration schema ──────────────────────────────────────

/// One capability's registration record — what PR1.9 will bind at
/// registration time. Carries the securable×operation×risk_tier×
/// mcp_tier_class quadruple this PR defines, PLUS the fields ADR-1005/0032
/// require of EVERY capability (the versioned REST twin, the MCP twin, the
/// discovery entry, the A4 error envelope, agentic-context annotations,
/// `data_class` + `audit_verb`) — this schema REFERENCES those platform-wide
/// obligations as fields PR1.9 populates at registration; it does not
/// redefine the mechanisms themselves (those stay governed by ADR-1005/0032
/// and the A4 envelope in `rest_a4_envelope.hpp`).
///
/// Deliberately carries NO `execute_roles` (or any other role-shaped) field
/// — which principals get `operation` on `securable` stays entirely in
/// `RbacStore`'s role_permissions table; this schema classifies a
/// capability, it never grants one.
struct CapabilityDeclaration {
    /// Reuses an existing `RbacStore::list_securable_types()` entry wherever
    /// one accurately describes the protected resource (ADR-0033 §2); a
    /// Module mints a new one only when nothing fits — that runtime mint
    /// path is NOT built yet (ADR-0033 §2's own stated precondition), so
    /// today every value here must name an already-seeded securable.
    std::string securable;
    Operation operation{Operation::Read};
    RiskTier risk_tier{RiskTier::Low};
    McpTierClass mcp_tier_class{McpTierClass::Read};

    /// ADR-1005: every capability ships a versioned REST twin AND an MCP
    /// twin, or carries a recorded exception in the ADR-1005 ledger — never
    /// silently missing one. Exactly one of `has_*_twin` being false without
    /// `twin_exception_ref` set is what `is_valid` rejects below.
    bool has_rest_twin{false};
    bool has_mcp_twin{false};
    /// Non-empty iff a twin is deliberately absent per a recorded ADR-1005
    /// ledger exception (e.g. an issue/ADR-decision id).
    std::string twin_exception_ref;

    /// Must enumerate in BOTH `/api/v1/openapi.json` and MCP `tools/list`
    /// (ADR-1005; ADR-0032 interlock (j) is what makes that possible) — the
    /// stable name/operationId a discovery consumer resolves this capability
    /// by.
    std::string discovery_entry;

    /// ADR-0032 Decision 11: so a device-attributable read is countable by
    /// construction, emitted with the release-log write.
    std::string data_class;
    std::string audit_verb;

    /// Track 2g (agentic-first A5): decision-grade description, bounded
    /// input schema, typed output schema, honest `retry_after_ms`, and a
    /// truthful `destructiveHint` all live in the MCP tool registration
    /// itself (`mcp_server.cpp`) — this is only the flag PR1.9 checks before
    /// registering a tool that skipped them.
    bool agentic_context_annotated{false};

    /// CDX-P2-004/K-23 presence sentinels — ADR-0033 §2: "a missing or
    /// unparseable mcp_tier_class, securable or operation means the capability
    /// does not exist. Never defaults to read." Because `operation`/
    /// `mcp_tier_class` are plain enums whose zero value IS `Read`, a future
    /// decoder (PR1.9) that fails to parse them would silently leave `Read`.
    /// `classification_explicit` is set true ONLY after a decoder positively
    /// parses securable + operation + mcp_tier_class; `a4_envelope_declared`
    /// records the mandatory A4 error-envelope obligation (ADR-1005/ADR-0032 §8)
    /// as an explicit field. Both default false, so a default-constructed or
    /// partially-decoded declaration fails `is_valid` (fail closed).
    bool a4_envelope_declared{false};
    bool classification_explicit{false};

    /// Fail-closed validation: a missing/inconsistent field means the
    /// capability DOES NOT REGISTER on any surface (ADR-0033 §2 — "never
    /// defaults to read"), not that it silently narrows or widens. Checks:
    ///   - classification (securable+operation+mcp_tier_class) POSITIVELY
    ///     supplied, the A4 envelope declared, the agentic context annotated
    ///   - `operation`/`mcp_tier_class` in range (reject a bad-decode cast)
    ///   - `securable`/`discovery_entry`/`data_class`/`audit_verb` non-empty
    ///   - `risk_tier` at or above `min_risk_tier_for(operation)`
    ///   - BOTH REST and MCP twins present, unless an exception is recorded
    [[nodiscard]] bool is_valid() const {
        // ADR-0033 §2 never-defaults-to-read: the classification, the A4
        // envelope, and the agentic annotation must be POSITIVELY supplied.
        if (!classification_explicit || !a4_envelope_declared || !agentic_context_annotated)
            return false;
        // Reject an out-of-range enum (e.g. a bad decode casting arbitrary bits).
        // risk_tier needs a CEILING as well as the floor check below: a decoder
        // casting an unparseable value (CDX-R2-005) must not slip through just
        // because a high bit pattern sits above every operation's floor.
        if (static_cast<uint8_t>(operation) > static_cast<uint8_t>(Operation::Rotate) ||
            static_cast<uint8_t>(mcp_tier_class) > static_cast<uint8_t>(McpTierClass::Execute) ||
            static_cast<uint8_t>(risk_tier) > static_cast<uint8_t>(RiskTier::Critical))
            return false;
        if (securable.empty() || discovery_entry.empty() || data_class.empty() ||
            audit_verb.empty())
            return false;
        if (static_cast<uint8_t>(risk_tier) < static_cast<uint8_t>(min_risk_tier_for(operation)))
            return false;
        // ADR-1005 twin contract: a capability must be discoverable on BOTH the
        // REST and MCP surfaces. EITHER twin missing without a recorded
        // exception is invalid -- not just both missing. (BR-005)
        if ((!has_rest_twin || !has_mcp_twin) && twin_exception_ref.empty())
            return false;
        return true;
    }
};

/// A lightweight, string_view-only seed row — `CapabilityDeclaration` owns
/// strings (for PR1.9's future runtime registry rows); the catalogue below
/// stays a plain compile-time array of views over string literals so this
/// header remains free of any static-init-order or heap-allocation concern.
struct CapabilitySeed {
    std::string_view securable;
    Operation operation;
    RiskTier risk_tier;
    std::string_view discovery_entry;
    std::string_view data_class;
    std::string_view audit_verb;
};

/// Materialize a full `CapabilityDeclaration` from a seed row, filling
/// `mcp_tier_class` via `default_mcp_tier_class` and marking both twins
/// present (every seeded row here already ships as a REST route today; PR1.9
/// is what will populate real per-Module rows with a genuine twin/exception
/// split).
[[nodiscard]] inline CapabilityDeclaration from_seed(const CapabilitySeed& seed) {
    CapabilityDeclaration decl;
    decl.securable = std::string(seed.securable);
    decl.operation = seed.operation;
    decl.risk_tier = seed.risk_tier;
    decl.mcp_tier_class = default_mcp_tier_class(seed.operation);
    decl.has_rest_twin = true;
    decl.has_mcp_twin = true;
    decl.discovery_entry = std::string(seed.discovery_entry);
    decl.data_class = std::string(seed.data_class);
    decl.audit_verb = std::string(seed.audit_verb);
    decl.agentic_context_annotated = true;
    // Seed rows are hand-authored, complete capabilities: their classification
    // is explicit and they ship the A4 envelope (CDX-P2-004 presence sentinels).
    decl.a4_envelope_declared = true;
    decl.classification_explicit = true;
    return decl;
}

/// A small, representative seed catalogue — NOT a full mirror of
/// `RbacStore`'s 38 securables × 8 operations catalogue. It exists so PR1.9 has real
/// rows to migrate and so this header's own tests exercise `is_valid`, not
/// to be the registry itself (that is explicitly out of scope here). Covers
/// an ordinary CRUD securable (`Response:Read`), a Tag write (mirrors
/// `mcp_policy.hpp`'s own Tag special-case), the `Execution:Execute`
/// combination the #1788 fix below cares about, the Guardian-only `Push`
/// narrow op, and — required by this PR's spec — the `AccessReview`
/// securable with its `Attest` narrow op (Periodic Access Reviews, SOC 2
/// CC6.2), deliberately outside every CRUD loop, exactly as seeded in
/// `rbac_store.cpp`.
///
/// PR1.9a (peer finding PLAN-001) adds three more rows for the three
/// securables that same PR appends to `rbac_store.cpp`'s `seed_defaults()`
/// `types[]` — `PluginConfig`, `PluginSecret`, `UploadGrant` — reusing only
/// EXISTING `Operation` enumerators, per that PR's explicit "no new
/// Operation" constraint: `PluginConfig:Write` (a plugin kill-switch flip),
/// `PluginSecret:Write` (setting/rotating a plugin secret value — `Delete`
/// removes it, `Read` reveals whether one is set, both role-gated the same
/// way in `rbac_store.cpp`, only `Write` illustrated here), and
/// `UploadGrant:Write` (minting an upload grant; `Delete` revokes one). None
/// of the three needs a `FileRetrieval`-shaped op of its own — actual file
/// retrieval after a grant is minted stays under the existing
/// `FileRetrieval` securable, so `UploadGrant` only ever governs the
/// grant's own lifecycle.
inline constexpr std::array<CapabilitySeed, 8> kSeedCatalogue{{
    {"Response", Operation::Read, RiskTier::Low, "listResponses", "device_operational",
     "response.list"},
    {"Tag", Operation::Write, RiskTier::Medium, "setTag", "device_operational", "tag.set"},
    {"Execution", Operation::Execute, RiskTier::Medium, "dispatchCommand", "device_operational",
     "command.dispatch"},
    {"GuaranteedState", Operation::Push, RiskTier::High, "pushGuardianRuleSet",
     "device_operational", "guardian.push"},
    {"AccessReview", Operation::Attest, RiskTier::Medium, "attestAccessReview",
     "grant_evidence", "access_review.attested"},
    {"PluginConfig", Operation::Write, RiskTier::Medium, "setPluginConfig",
     "device_operational", "plugin_config.write"},
    {"PluginSecret", Operation::Write, RiskTier::High, "setPluginSecret", "secret_material",
     "plugin_secret.write"},
    {"UploadGrant", Operation::Write, RiskTier::Medium, "mintUploadGrant", "device_operational",
     "upload_grant.mint"},
}};

// ── #1788: the shared per-device visibility primitive ───────────────────

/// The operator-scoped visible set for one securable×operation pair.
/// `std::nullopt` means UNFILTERED — a global ALLOW (or an equivalent
/// full-access bypass `require_permission` already granted, e.g. JIT
/// elevation) admits every target, matching #1715(b): a global allow
/// overrides any group deny. A present (possibly empty) set means every id
/// absent from it is out of scope — the ADR-0017 per-agent visible set from
/// `RbacStore::visible_agents_for_permission`. Callers derive this ONCE from
/// `RbacStore`'s public API (never re-implemented here — this header holds
/// no store, no lock, no SQL) and pass it to `in_scope`/`filter_to_scope`
/// for every dispatch arm.
using VisibleSet = std::optional<std::unordered_set<std::string>>;

/// The deny-all set: PRESENT but empty, admitting nothing.
///
/// Spell the fail-closed fallback with this, never by hand. `VisibleSet{}`
/// looks like it means "empty set" and in fact default-constructs the optional
/// to `nullopt` — UNFILTERED, the exact inverse — and that one-character class
/// of slip is not hypothetical: the REST bundle route shipped it, so its
/// defense-in-depth confinement silently became permissive on any deployment
/// that had not wired the derivation, while a green test asserted the
/// behaviour was intended. Thirteen hand-spelled copies of the correct literal
/// existed across the dispatch surfaces when that one was found wrong; a named
/// constructor makes the wrong spelling something you have to go out of your
/// way to write, which is the same argument `RestApiV1::CommandDispatchFn`
/// makes for requiring its `VisibleSet` parameter rather than defaulting it.
[[nodiscard]] inline VisibleSet deny_all() { return VisibleSet{std::unordered_set<std::string>{}}; }

/// Whether `agent_id` is admitted by `visible` — the ONE predicate every
/// `/api/command` dispatch arm applies before `send_to` (#1788: explicit
/// `agent_ids`, broadcast, Group, Scope all call this same function so a
/// fifth arm can never forget it, the same reasoning
/// `dispatch_target_shape.hpp` gives for `classify_dispatch_arm`).
[[nodiscard]] inline bool in_scope(const VisibleSet& visible, const std::string& agent_id) {
    return !visible || visible->contains(agent_id);
}

/// Filter an already-resolved dispatch-arm target list against `visible`.
/// Pure and total — no I/O, no partial results. `Ids` is any range of
/// `std::string`-like ids (an explicit `agent_ids` list, a management
/// group's resolved members, a scope's matched ids, or the full known-agent
/// set for a broadcast).
template <class Ids>
[[nodiscard]] inline std::vector<std::string> filter_to_scope(const Ids& ids,
                                                              const VisibleSet& visible) {
    if (!visible)
        return std::vector<std::string>(ids.begin(), ids.end());
    std::vector<std::string> out;
    out.reserve(ids.size());
    for (const auto& id : ids)
        if (visible->contains(id))
            out.push_back(id);
    return out;
}

/// Lattice intersection of two `VisibleSet`s: `std::nullopt` is TOP
/// (unfiltered), so it is the identity — `meet(nullopt, b) == b` and
/// `meet(a, nullopt) == a`. A present set is a filter; the meet of two
/// present sets is their set intersection, always present (never collapsed
/// back to `nullopt`, even when the result is empty — `deny_all()` above is
/// exactly that present-but-empty case, and it must survive a meet with
/// TOP unchanged: `meet(deny_all(), b) == deny_all()`, the lattice bottom
/// absorbing). Commutative and associative — composing more than two axes
/// in any order is safe.
///
/// This is the primitive the new list-read gate uses to combine the
/// management-group axis (`RbacStore::authorize_list_read`) with the
/// service-scope axis: never a reuse of, and never a rewrite of,
/// `compose_exec_visible` below — that function's *supersede* semantics for
/// dispatch are a deliberately separate, unchanged decision.
[[nodiscard]] inline VisibleSet meet(const VisibleSet& a, const VisibleSet& b) {
    if (!a)
        return b;
    if (!b)
        return a;
    std::unordered_set<std::string> out;
    for (const auto& id : *a)
        if (b->contains(id))
            out.insert(id);
    return out;
}

/// The already-resolved facts `compose_exec_visible` decides from. Each is
/// looked up by the caller (which owns the RbacStore/TagStore handles this
/// registry-independent header deliberately does not depend on) so the DECISION
/// itself stays pure and directly testable.
struct ExecVisibleFacts {
    /// The caller presented a service-scoped token (`token_scope_service`
    /// non-empty).
    bool service_scoped = false;
    /// Agents tagged with that service. `nullopt` == the tag store was
    /// unavailable, which must fail CLOSED, not open.
    std::optional<std::unordered_set<std::string>> service_tagged;
    /// RBAC is loaded-but-disabled (legacy-open). A null or load-failed store
    /// is NOT legacy-open — that stays fail-closed (BR-002).
    bool legacy_open = false;
    /// The session reached the route via JIT admin elevation.
    bool elevated = false;
    /// The username holds a GLOBAL `Execution:Execute` grant.
    bool global_grant = false;
    /// The ADR-0017 per-agent visible set. `nullopt` == store error, fail closed.
    std::optional<std::unordered_set<std::string>> scoped_visible;
};

/// Decide a caller's `Execution:Execute` visible set (#1788).
///
/// ORDER IS THE CONTRACT, and it is the whole of CDX-001: a service-scoped
/// token is resolved FIRST and is NEVER unfiltered, so its confinement takes
/// PRECEDENCE over any global grant the minting username holds. BR-001 confined
/// service tokens only INSIDE the `!unfiltered` branch, so an administrator
/// minting a service-A token still matched the global grant, came out
/// unfiltered, and reached the whole fleet. Checking the global grant first —
/// or composing the two branches independently — reintroduces exactly that.
///
/// This is a free function rather than a method for one reason: the previous
/// arrangement, where the decision lived only inside `ServerImpl`, could not be
/// tested without an `RbacStore`, so its tests re-implemented it. Two
/// independent copies then diverged and the PRECEDENCE was composed by neither,
/// leaving CDX-001 reopenable under green tests. Keep the decision here.
[[nodiscard]] inline VisibleSet compose_exec_visible(const ExecVisibleFacts& f) {
    if (f.service_scoped) {
        // Never unfiltered. Absent tag store -> empty == deny-all.
        return f.service_tagged.value_or(std::unordered_set<std::string>{});
    }
    if (f.legacy_open || f.elevated || f.global_grant)
        return std::nullopt; // genuinely unfiltered authority
    // Store error -> empty == deny-all, never nullopt.
    return f.scoped_visible.value_or(std::unordered_set<std::string>{});
}

} // namespace yuzu::server::authz
