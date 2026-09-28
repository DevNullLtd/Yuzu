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
/// LINK RESIDUAL (WS-B2, tracked #4579): "CORE-ONLY" here means include-only —
/// the nine builders are DEFINED in `dex_read_model.cpp` (core), but the
/// `dex_device_score` declaration below is still DEFINED in the presentation
/// `dex_routes.cpp`. So a core-only link target does not yet resolve cleanly;
/// #4579 enumerates the symbols to re-home. Inert in today's single-binary build.

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
/// Relocated from dex_routes.hpp (PR #4582 FIX 4) so dex_read_model.cpp can call
/// it without that httplib-coupled header; dex_routes.hpp re-includes this
/// header, so its own callers are unaffected.
int dex_device_score(const GuaranteedStateStore* store, const std::string& agent_id,
                     const std::string& since);

/// Pure scoring formula (#4855 extraction) — `dex_device_score`'s body once it
/// has a device's signal summary in hand. Store-free; lets
/// `build_dex_device_score_model` derive score + signals from the SAME
/// checked read (closing the #4855 torn-read window) instead of a second,
/// independent store call. Also DEFINED in `dex_routes.cpp` (LINK RESIDUAL
/// above applies here too).
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

} // namespace yuzu::server
