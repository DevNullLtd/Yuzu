#pragma once

/// @file rotation_sweep_naming.hpp
/// P2 #11 (SOC 2 CC6.3): single chokepoint deciding which telemetry family
/// (Prometheus metric + audit action) an overlap-pair rotation sweep event
/// routes to, given the row's `ApiToken::principal_kind` ("human" | "engine").
///
/// The T12 maintenance sweep (`ApiTokenStore::sweep_expired_rotations` /
/// `list_rotations_nearing_expiry_unused`, driven from server.cpp) scans
/// BOTH kinds with no `principal_kind` filter in the SQL — that stays
/// correct and unchanged. What was wrong: the sweep DRIVER unconditionally
/// emitted `yuzu_engine_principal_rotation_*` metrics and
/// `engine_principal.rotation.*` audit rows for every swept row, so the
/// first human-owned rotation pair would be misreported as an engine
/// credential in both Prometheus and the audit trail — exactly the evidence
/// this telemetry exists to produce for CC6.3. This header is the ONE
/// decision point the driver calls per row/pair; EXTEND it, never fork it
/// (matches the `dispatch_target_shape.hpp` / `authz_topology_floor.hpp` /
/// `body_cap_policy.hpp` single-chokepoint precedent in this codebase).
///
/// Deliberately a SEPARATE, parallel family for the human side
/// (`yuzu_api_token_rotation_*` / `api_token.rotation.*`) rather than a
/// `kind` label bolted onto the existing `yuzu_engine_principal_rotation_*`
/// names — a label under a name that says `engine_principal` would still be
/// dishonest naming, and it would silently expand the deliberately
/// pre-seeded bounded cross-product those series already carry. The engine
/// arm's names/labels/semantics are UNCHANGED by this file.

#include <string_view>

namespace yuzu::server {

/// The four names the T12 sweep driver needs for one `principal_kind`: the
/// two Prometheus counter families it increments (`auto_revoked` has no
/// labels; `events` carries the bounded `reason` label, e.g.
/// `successor_unused`) and the two audit `action` strings. `target_type`
/// stays `"ApiToken"` for BOTH kinds (matches the human-token audit
/// convention at `rest_api_v1.cpp`'s `api_token.create`/`api_token.revoke`
/// sites) — no per-kind target-type split.
struct RotationSweepNames {
    const char* metric_auto_revoked;
    const char* metric_events;
    const char* audit_auto_revoke;
    const char* audit_successor_unused;
};

inline constexpr RotationSweepNames kEngineRotationSweepNames{
    .metric_auto_revoked = "yuzu_engine_principal_rotation_auto_revoked_total",
    .metric_events = "yuzu_engine_principal_rotation_events_total",
    .audit_auto_revoke = "engine_principal.rotation.auto_revoke",
    .audit_successor_unused = "engine_principal.rotation.successor_unused",
};

inline constexpr RotationSweepNames kHumanRotationSweepNames{
    .metric_auto_revoked = "yuzu_api_token_rotation_auto_revoked_total",
    .metric_events = "yuzu_api_token_rotation_events_total",
    .audit_auto_revoke = "api_token.rotation.auto_revoke",
    .audit_successor_unused = "api_token.rotation.successor_unused",
};

/// Resolve the names for one sweep row/pair from its `principal_kind`.
/// Binary split, not an allowlist that needs a third arm: `ApiToken::
/// principal_kind` defaults to `"human"` and the DB `CHECK (principal_kind
/// IN ('human','engine'))` bounds the column to exactly those two values —
/// so anything that isn't literally `"engine"` is safely routed to the
/// human family, never a silent third bucket.
[[nodiscard]] constexpr const RotationSweepNames&
rotation_sweep_names_for_kind(std::string_view principal_kind) {
    return principal_kind == "engine" ? kEngineRotationSweepNames : kHumanRotationSweepNames;
}

/// Human-owned twin of `yuzu_engine_principal_confirm_total` (#2404) —
/// registered + pre-seeded alongside the four names above, but NOT one of
/// them: it is not per-swept-row telemetry (the T12 sweep never confirms
/// anything), it is incremented by the human confirm-rotation REST/MCP
/// handlers (a sibling piece, not wired here). Exported as a symbol rather
/// than left as a string literal at each call site so a typo on either side
/// (registration here vs. the increment call the sibling piece adds) is a
/// compile error instead of a silently-diverging shadow series sitting next
/// to a pre-seeded family that looks perfectly healthy at 0.
inline constexpr const char* kApiTokenConfirmTotalMetric = "yuzu_api_token_confirm_total";

} // namespace yuzu::server
