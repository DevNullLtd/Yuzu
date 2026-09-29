/**
 * test_rotation_sweep_naming.cpp — coverage for P2 #11's single chokepoint
 * (`rotation_sweep_naming.hpp`'s `rotation_sweep_names_for_kind`) that
 * decides which Prometheus metric family + audit `action` string the T12
 * overlap-pair rotation sweep driver (server.cpp) emits for one swept
 * row/pair, keyed on `ApiToken::principal_kind`.
 *
 * This header is a PURE lookup — no store, no server, no PG. It exists so
 * the sweep driver's kind-discrimination can be pinned WITHOUT standing up
 * ServerImpl's private background thread. The whole point of this file:
 * a human `principal_kind` must NEVER resolve to an `engine_principal`-named
 * metric or `engine_principal.rotation.*` audit action, and vice versa —
 * that misrouting is exactly the CC6.3 evidence-corruption bug this piece
 * fixes. Expected values below are an INDEPENDENT copy, not derived from the
 * header (mirrors test_body_cap_policy.cpp / test_authz_topology_floor.cpp),
 * so an accidental edit to the header's literals is caught here rather than
 * only in server.cpp's actual emission sites.
 */

#include "rotation_sweep_naming.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

using yuzu::server::kApiTokenConfirmTotalMetric;
using yuzu::server::kEngineRotationSweepNames;
using yuzu::server::kHumanRotationSweepNames;
using yuzu::server::rotation_sweep_names_for_kind;
using yuzu::server::RotationSweepNames;

namespace {

void check_names(const RotationSweepNames& names, std::string_view metric_auto_revoked,
                  std::string_view metric_events, std::string_view audit_auto_revoke,
                  std::string_view audit_successor_unused) {
    CHECK(std::string(names.metric_auto_revoked) == metric_auto_revoked);
    CHECK(std::string(names.metric_events) == metric_events);
    CHECK(std::string(names.audit_auto_revoke) == audit_auto_revoke);
    CHECK(std::string(names.audit_successor_unused) == audit_successor_unused);
}

} // namespace

TEST_CASE("rotation_sweep_names_for_kind: 'engine' resolves to the UNCHANGED "
          "yuzu_engine_principal_rotation_* family and engine_principal.rotation.* actions",
          "[server][rotation][telemetry][principal_kind]") {
    check_names(rotation_sweep_names_for_kind("engine"),
                "yuzu_engine_principal_rotation_auto_revoked_total",
                "yuzu_engine_principal_rotation_events_total", "engine_principal.rotation.auto_revoke",
                "engine_principal.rotation.successor_unused");
    // Referential identity, not just value equality — the driver must reuse
    // the SAME literal table the engine block registered in the ctor.
    CHECK(&rotation_sweep_names_for_kind("engine") == &kEngineRotationSweepNames);
}

TEST_CASE("rotation_sweep_names_for_kind: 'human' resolves to the parallel "
          "yuzu_api_token_rotation_* family and api_token.rotation.* actions — NEVER "
          "the engine-named series (P2 #11)",
          "[server][rotation][telemetry][principal_kind]") {
    check_names(rotation_sweep_names_for_kind("human"),
                "yuzu_api_token_rotation_auto_revoked_total", "yuzu_api_token_rotation_events_total",
                "api_token.rotation.auto_revoke", "api_token.rotation.successor_unused");
    CHECK(&rotation_sweep_names_for_kind("human") == &kHumanRotationSweepNames);

    // The direct assertion the task exists to pin: a human row's resolved
    // names must not collide with ANY engine-named series/action.
    const auto& human = rotation_sweep_names_for_kind("human");
    const auto& engine = rotation_sweep_names_for_kind("engine");
    CHECK(std::string(human.metric_auto_revoked) != engine.metric_auto_revoked);
    CHECK(std::string(human.metric_events) != engine.metric_events);
    CHECK(std::string(human.audit_auto_revoke) != engine.audit_auto_revoke);
    CHECK(std::string(human.audit_successor_unused) != engine.audit_successor_unused);
}

TEST_CASE("rotation_sweep_names_for_kind: anything other than the literal 'engine' "
          "kind is a SAFE binary split to human, never a silent third bucket",
          "[server][rotation][telemetry][principal_kind]") {
    // ApiToken::principal_kind defaults to "human" and the DB CHECK bounds
    // the column to exactly {'human','engine'} — but the lookup itself must
    // not rely on that DB-level guarantee to stay safe against a
    // not-yet-migrated row / a future default change.
    CHECK(&rotation_sweep_names_for_kind("") == &kHumanRotationSweepNames);
    CHECK(&rotation_sweep_names_for_kind("bogus") == &kHumanRotationSweepNames);
    CHECK(&rotation_sweep_names_for_kind("Engine") == &kHumanRotationSweepNames); // case-sensitive
}

TEST_CASE("kApiTokenConfirmTotalMetric: exported symbol matches the registered/pre-seeded "
          "name — the compile-time seam a REST-side increment call site now shares "
          "instead of a hand-copied string literal",
          "[server][rotation][telemetry][principal_kind]") {
    CHECK(std::string(kApiTokenConfirmTotalMetric) == "yuzu_api_token_confirm_total");
}
