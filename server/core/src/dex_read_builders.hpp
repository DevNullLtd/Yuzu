#pragma once

/// @file dex_read_builders.hpp
/// CORE-ONLY. The store-reaching half of the DEX read-model layer: the nine
/// `build_dex_*_model(GuaranteedStateStore* store, ...)` builders that read a
/// store into a pure model struct. Split out of `dex_read_model.hpp` (ADR-0031
/// WS-A4, FortitudeEtc review on PR #4582) so the PURE half —
/// `dex_read_model.hpp` (the model structs + the model-only JSON serializers) —
/// carries NO store-type token and can sit behind the ABSTRACT `dex_api.hpp`
/// seam with a genuinely store-type-free include closure, exactly like the four
/// sibling abstract headers (network/verify/compliance/device).
///
/// This header forward-declares the store types it needs (never includes a
/// store header) and is included ONLY by store-reaching TUs: the seam impl
/// (`dex_api.cpp`), the definitions TU (`dex_read_model.cpp`), and the parity
/// test (`test_dex_api.cpp`). It is NEVER included by `dex_api.hpp` or any
/// presentation TU — that is what keeps the abstract seam header store-type-free
/// (enforced by check-seam-closure.py's abstract-header probe).
///
/// LINK RESIDUAL (WS-B2, #4579's DEX HALF — the issue's OTHER half, the
/// `event_bus.hpp`→`<httplib.h>` SSE-sink inversion, stays OPEN and is
/// untouched here) — CLOSED (ADR-0031 WS-A4 PR-1 F1 fix, Fable
/// review 2026-09-28): "CORE-ONLY" here now means link-clean too — all nine
/// builders AND `dex_device_score`/`dex_score_from_signals` below are DEFINED
/// in `dex_read_model.cpp` (core); the presentation TU `dex_routes.cpp` no
/// longer defines either. A core-only link target resolves cleanly. Enforced
/// going forward by the `dex` family entry in the link-level symbol tripwire
/// (`scripts/ci/check_core_presentation_link.py`, meson test `'dex link no
/// presentation symbols'`, suites `server`+`server-checks`).

#include <optional>
#include <set>
#include <string>
#include <vector>

#include "dex_read_model.hpp" // the pure model structs the builders return

namespace yuzu::server {

class GuaranteedStateStore;

// ── Store-reaching builders (each reads `store` into a pure model struct) ──
// `store` may be null in every builder (degrades to an empty/`-1` model, never
// a throw); `visible` (where present) is the ADR-0017 admit-then-filter set.

/// Per-device DEX experience score (0–100) — the canonical severity-weighted
/// composite; -1 when `store` is null. A store-reaching read helper the
/// builders (device score / overview) and several route/lens TUs share.
/// Declaration relocated from dex_routes.hpp (PR #4582 FIX 4); the DEFINITION
/// relocated from `dex_routes.cpp` to `dex_read_model.cpp` (ADR-0031 WS-A4
/// PR-1 F1 fix, closing the LINK RESIDUAL noted above) — `dex_routes.hpp`
/// re-includes this header, so its own callers (the Overview renderer) are
/// unaffected.
int dex_device_score(const GuaranteedStateStore* store, const std::string& agent_id,
                     const std::string& since);

/// Pure scoring formula (#4855 extraction) — `dex_device_score`'s body once it
/// has a device's signal summary in hand. Store-free; lets
/// `build_dex_device_score_model` derive score + signals from the SAME
/// checked read (closing the #4855 torn-read window) instead of a second,
/// independent store call. DEFINED in `dex_read_model.cpp` alongside
/// `dex_device_score` (LINK RESIDUAL above, now closed).
int dex_score_from_signals(const std::vector<DexSignalCount>& device_signals);

DexDeviceScoreModel build_dex_device_score_model(GuaranteedStateStore* store,
                                                 const std::string& agent_id,
                                                 const std::string& window, const std::string& since);

DexAppModel build_dex_app_model(GuaranteedStateStore* store, const std::string& process_name,
                                const std::string& window, const std::string& since,
                                const std::set<std::string>* visible);

DexAppsModel build_dex_apps_model(GuaranteedStateStore* store, const std::string& window,
                                  const std::string& since);

std::optional<DexCatalogueGroupModel> build_dex_catalogue_group_model(
    GuaranteedStateStore* store, const std::string& group_name, const std::string& os_filter,
    const DexFleet& fleet, const std::string& window, const std::string& since);

DexDeviceHistoryModel build_dex_device_history_model(GuaranteedStateStore* store,
                                                     const std::string& agent_id,
                                                     const std::string& window,
                                                     const std::string& since);

/// Lookup + ownership check in ONE call — `nullopt` both when the event is
/// absent AND when it belongs to a DIFFERENT device than `agent_id` (the caller
/// turns either into the SAME 404, so a guessed/foreign event_id reveals
/// nothing beyond what the scope gate already allowed).
std::optional<GuardianObservationRow> build_dex_observation_model(GuaranteedStateStore* store,
                                                                  const std::string& agent_id,
                                                                  const std::string& event_id);

DexHealthModel build_dex_health_model(GuaranteedStateStore* store, const DexFleet& fleet,
                                      const std::string& weighting, const std::string& window,
                                      const std::string& since);

DexTrendsModel build_dex_trends_model(GuaranteedStateStore* store, const DexFleet& fleet,
                                      const std::string& window, const std::string& since);

DexOverviewModel build_dex_overview_model(GuaranteedStateStore* store, const DexFleet& fleet,
                                          const std::string& window, int window_days,
                                          const std::string& since,
                                          const std::set<std::string>* visible);

/// ADR-0031 WS-A4 PR-1 (Fraser decision 1) — the Catalogue View 1 read model
/// (per-family cards + fleet coverage + the "Other (uncatalogued)" list), the
/// first public resource the /dex Catalogue grid's own fragment computation
/// has ever had (previously fragment-only: no REST/MCP twin served the
/// per-family health score / online-denominator coverage this builds).
/// `since` is derived from `window` internally (`dex_iso_since(
/// dex_window_to_days(window))`), matching every other builder here.
DexCatalogueModel build_dex_catalogue_model(GuaranteedStateStore* store, const DexFleet& fleet,
                                            const std::string& os_filter,
                                            const std::string& window);

} // namespace yuzu::server
