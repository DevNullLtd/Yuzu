#pragma once

/// @file guardian_api.hpp
/// The NINTH per-family in-process API seam for the presentation/core/engine
/// split (ADR-0031, WS-A4), covering the Guardian / Guaranteed State READ
/// surface — the Postgres-backed `GuaranteedStateStore`'s (+ one
/// `BaselineStore` read) `GET /api/v1/guaranteed-state/{rules,rules/{id},
/// status,status/{agent_id},rules/{id}/status,agents/{id}/rules,
/// device-compliance,events}` resources (and their MCP twins
/// `list_guardian_rules`/`get_guardian_rule`/`get_guardian_status`/
/// `get_guardian_agent_status`/`get_guardian_rule_status`/
/// `get_guardian_device_guards`/`get_guardian_device_compliance`/
/// `list_guardian_events`). Abstract, ZERO store-shaped dependencies — it
/// includes only the pure `guardian_types.hpp` + std headers, so this header
/// can be included by a future presentation-side client without dragging the
/// server's `GuaranteedStateStore`/`BaselineStore` (Postgres-backed stores)
/// along.
///
/// The eight methods == eight of the nine public REST v1 resources above
/// (plus their MCP twins) — see the DELIBERATELY-NOT-in-this-seam list below
/// for the ninth (`schemas`) — so a presentation/MCP caller consumes only
/// what the public, versioned core API serves (ADR-0031 B3, INV-31-4 "no
/// private core API") — a local in-process implementation today
/// (`LocalGuardianApi`, `guardian_api.cpp`), a core HTTP client after the
/// WS-B2 cutover. Adding a method here without a corresponding public
/// REST/MCP resource would reintroduce a private core API and defeat the
/// point of the seam.
///
/// The store-backed factory (`make_local_guardian_api`) lives in the
/// core-only `guardian_api_local.hpp` — this header names no store type at
/// all, not even by forward declaration, so a presentation TU including it
/// cannot reach one.
///
/// Method-to-function mapping (each wraps the SAME shared pure function
/// `guardian_model.hpp` already exposed to REST/MCP, so this seam changes
/// WHO calls them, never WHAT they compute):
///   - `list_rules`/`get_rule` wrap `GuaranteedStateStore::list_rules`/
///     `get_rule` directly (no separate model function existed for these —
///     REST/MCP/dashboard each called the store method inline).
///   - `status`/`agent_status`/`rule_status`/`device_guards`/
///     `device_compliance` wrap `guardian_status_rollup`/
///     `guardian_agent_status_rollup`/`guardian_rule_agent_status_rows`/
///     `guardian_device_all_guards`/`guardian_device_compliance_rollup`
///     (`guardian_model.hpp`) verbatim, including their exact
///     nullopt-on-degrade / out-param contracts.
///   - `list_events` wraps `GuaranteedStateStore::query_events` directly —
///     this is the ADR-0038 "deferred widening" (#2659) class: a plain
///     `std::vector`, empty-on-degrade, NOT `std::optional` like the other
///     seven methods. This is a deliberate, PRE-EXISTING asymmetry in the
///     store's own read posture (see `guaranteed_state_store.hpp`'s header
///     comment) — the seam preserves it byte-identically rather than
///     "fixing" it, which would be an unreviewed behavior change smuggled
///     into a refactor.
///
/// Deliberately NOT in this seam (see `docs/presentation-core-split-delivery-matrix.md`'s
/// WS-A4 row for the full disclosure):
///   - The four RULE MUTATORS (`POST`/`PUT`/`DELETE /guaranteed-state/rules[/{id}]`,
///     `POST /guaranteed-state/push`) and the four BASELINE-mutator dashboard
///     actions — no public REST/MCP twin (mutators) or dashboard-only
///     (Baselines have ZERO public REST/MCP twin at all today — a WS-A3 gap,
///     larger in scope than any prior family's, tracked separately). They
///     keep direct `GuaranteedStateStore*`/`BaselineStore*` access in
///     `guardian_routes.cpp`, unaffected by this seam.
///   - `GET /api/v1/guaranteed-state/alerts` — a permanently-empty stub
///     (`res.set_content(list_json("[]", 0), ...)`), no MCP twin, no data
///     source to route through a seam. Left untouched.
///   - `GET /api/v1/guaranteed-state/schemas` / MCP `get_guardian_schemas` —
///     the compiled-in, store-free Guard authoring schema catalog
///     (`guardian::guardian_schema_catalog()`, `guardian_schema_registry.hpp`).
///     Deliberately NOT wrapped by this seam even though it has a public
///     REST+MCP twin: it touches no store at all, so wrapping it would add a
///     method that ignores every constructor dependency and can never
///     itself degrade — no consistency benefit `list_rules`/`status`/etc.
///     get from sharing ONE seam instance across REST/MCP applies here,
///     since there is no store call for the two transports to drift on. It
///     keeps calling `guardian::guardian_schema_catalog()` directly,
///     unchanged, exactly like the unrelated `GET /discover/scope`
///     compiled-in catalog route.
///   - `guardian_routes.cpp`'s dashboard fragments stay OUTSIDE the
///     seam-closure ENFORCED set (same posture as `dex`/`dex_perf`/
///     `schedule`/`workflow`'s own multi-purpose consumer files) — the file
///     interleaves read fragments with the rule/baseline mutators listed
///     above in ONE translation unit, so a `policy_admin_routes.hpp`-style
///     carve-out would be needed before it could be fully enforced; that
///     carve-out is a separate, disclosed follow-up, not done here.
///
/// `device_lens_routes.cpp`'s `/fragments/device/guardian` fragment IS
/// wrapped by this seam (`device_guards`, mirroring the `dex` family's own
/// ISSUE #4576 rewire) and is enforced via the `device` family's TU set in
/// `check-seam-closure.py` (that fragment's OWN file, not this seam's).

#include "guardian_types.hpp"

#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// The in-process public Guardian-read API. Each method == one public
/// REST v1 / MCP resource, so presentation/MCP consume only what the public,
/// versioned core API serves (ADR-0031 B3, INV-31-4) — a local in-process
/// client today, a core HTTP client after the WS-B2 cutover.
class GuardianApi {
public:
    virtual ~GuardianApi() = default;

    /// The rule catalogue behind `GET /api/v1/guaranteed-state/rules` / MCP
    /// `list_guardian_rules`. AUTHORITATIVE (ADR-0038 catastrophic-read set):
    /// `std::unexpected` on a store/pool/query degrade, NEVER a silent empty
    /// vector a push/reconcile/baseline-deploy consumer could mistake for
    /// "no rules configured". The error string is INTERNAL — a caller
    /// rendering it to an operator or returning it over REST/MCP runs it
    /// through the caller's own sanitisation first, exactly as REST/MCP
    /// already do (this method is a thin wrap of
    /// `GuaranteedStateStore::list_rules`, whose own contract this mirrors).
    [[nodiscard]] virtual std::expected<std::vector<GuaranteedStateRuleRow>, std::string>
    list_rules() const = 0;

    /// The single-rule detail behind
    /// `GET /api/v1/guaranteed-state/rules/{rule_id}` / MCP
    /// `get_guardian_rule`, and the existence check inside
    /// `rule_status`'s own REST/MCP handlers. Three-state (ADR-0038
    /// catastrophic-read set): `std::nullopt` = a successful read finding
    /// none (genuinely no such rule); `std::unexpected` = a store/pool/query
    /// degrade — the caller MUST 503, never collapse a degrade into 404.
    [[nodiscard]] virtual std::expected<std::optional<GuaranteedStateRuleRow>,
                                        GuaranteedStateReadError>
    get_rule(const std::string& rule_id) const = 0;

    /// The fleet status rollup behind `GET /api/v1/guaranteed-state/status` /
    /// MCP `get_guardian_status`. `agent_scope`: `nullopt` = whole fleet;
    /// engaged (including empty, ADR-0017 INV-2) = confine `errored_rules`
    /// to exactly these agents (applied in SQL, INV-3 — never a C++
    /// post-filter). Returns `nullopt` on a degraded read (ADR-0038
    /// catastrophic-read set) — the caller MUST refuse to render (503),
    /// never a silent 0 that would misreport the fleet as compliant.
    [[nodiscard]] virtual std::optional<GuardianStatusRollup>
    status(const std::optional<std::vector<std::string>>& agent_scope) const = 0;

    /// The per-agent status rollup behind
    /// `GET /api/v1/guaranteed-state/status/{agent_id}` / MCP
    /// `get_guardian_agent_status`. `total_rules` here is "rules with ANY
    /// census entry for THIS agent, intersected against the live rule
    /// catalogue" — a DIFFERENT algorithm from `status` above, never a
    /// scoped call to it. Returns `nullopt` on a degraded read — the caller
    /// MUST refuse to render (503).
    [[nodiscard]] virtual std::optional<GuardianAgentStatusRollup>
    agent_status(const std::string& agent_id) const = 0;

    /// The per-guard fleet-wide agent-status drilldown behind
    /// `GET /api/v1/guaranteed-state/rules/{rule_id}/status` / MCP
    /// `get_guardian_rule_status` — one row per agent that has reported THIS
    /// rule's state, fleet-wide. Raw census — does NOT apply the dashboard
    /// fragment's own offline-agent-folds-to-unknown rollup. Does NOT itself
    /// distinguish "rule not found" from "rule exists, no agent has reported
    /// yet" (both return an empty, non-nullopt vector) — a caller needing
    /// that distinction calls `get_rule` first, exactly as the REST/MCP
    /// handlers already do. Returns `nullopt` on a degraded read.
    [[nodiscard]] virtual std::optional<std::vector<GuardianRuleAgentStatusRow>>
    rule_status(const std::string& rule_id) const = 0;

    /// The per-device all-guards view behind
    /// `GET /api/v1/guaranteed-state/agents/{agent_id}/rules` / MCP
    /// `get_guardian_device_guards` — every guard's state for ONE device,
    /// unscoped to any Baseline (genuinely distinct from `device_compliance`
    /// below, which is scoped to one named Baseline). A device with no
    /// reported guards returns an empty, non-nullopt vector — not an error.
    /// Returns `nullopt` on a degraded read.
    [[nodiscard]] virtual std::optional<std::vector<GuardianDeviceGuardRow>>
    device_guards(const std::string& agent_id) const = 0;

    /// The name-anchored, device-applicable Baseline compliance rollup
    /// behind `GET /api/v1/guaranteed-state/device-compliance` / MCP
    /// `get_guardian_device_compliance`. `store_degraded`/`pii_access_began`
    /// are REQUIRED out-params with the EXACT contract
    /// `guardian_device_compliance_rollup` (`guardian_model.hpp`)
    /// documents: `store_degraded` distinguishes a store FAULT (retryable
    /// 503) from a genuine "no such baseline" miss (`nullopt` with
    /// `*store_degraded == false`); `pii_access_began` tells the caller
    /// whether the degrade happened before or after this agent's
    /// per-baseline PII was first touched, so it knows whether it owes an
    /// audit row for the failure. See that function's own doc comment for
    /// the full audit-obligation table this method preserves verbatim.
    [[nodiscard]] virtual std::optional<GuardianDeviceComplianceRollup>
    device_compliance(const std::string& baseline_name, const std::string& agent_id,
                       bool* store_degraded, bool* pii_access_began) const = 0;

    /// The event query behind `GET /api/v1/guaranteed-state/events` / MCP
    /// `list_guardian_events`. UNLIKE every other method on this interface,
    /// this is a plain vector, empty-on-degrade — NOT `std::optional`. This
    /// mirrors `GuaranteedStateStore::query_events`'s own ADR-0038
    /// "deferred widening" (#2659) posture verbatim: events/DEX-analytic
    /// reads keep their pre-existing empty-on-degrade contract, unlike the
    /// rules/status/compliance reads above which are all type-distinguishable.
    /// This is a documented PRE-EXISTING asymmetry in the store, not
    /// something this seam introduces or should paper over.
    [[nodiscard]] virtual std::vector<GuaranteedStateEventRow>
    list_events(const GuaranteedStateEventQuery& q) const = 0;
};

} // namespace yuzu::server
