#pragma once

/// @file dex_app_perf_model.hpp
/// Slice-2 READ model for DEX app-perf-over-time — the ONE pure transform that
/// turns stored B2 (`AppPerfFleetStore`) rows into the fleet-trend shape the
/// REST endpoint, the MCP tool, and (later) the dashboard all render. Putting
/// the mean + percentile derivation here, not in each handler, is what keeps the
/// three surfaces from disagreeing (the same reason `dex_perf_model.hpp` exists
/// for the heartbeat-now surface).
///
/// This realises the "F2b retained series" the heartbeat-now model deferred
/// until the Postgres store landed (see `dex_perf_model.hpp` header) — it reads
/// the retained B1/B2 substrate rather than render-time heartbeat state.
///
/// Honesty rules carried from the rest of DEX:
///   - a percentile that falls in the OPEN top histogram bucket is a FLOOR, not
///     an exact value (`HistPctile::lower_bound`) — render "≥ value", never the
///     boundary as if exact;
///   - a row stamped under a different histogram scheme than the running
///     `kAppPerfHistVersion` has its percentiles WITHHELD (`hist_stale`), never
///     reinterpreted under the current buckets;
///   - the exact fleet mean (`cpu_sum/device_count`) and exact maxima are always
///     carried alongside the bucket-resolution percentiles for callers that need
///     a precise number.

// PURE half (ADR-0031 WS-A4 DexPerfApi split, PR #4582-review pattern): the
// abstract dex_perf_api.hpp includes ONLY this.
#include "dex_app_perf_pure.hpp"
// CORE-ONLY half: the store-reaching builders (the retired `AppPerfProviders`
// bundle used to live here too, #4626). Kept as a SEPARATE #include (not
// inlined here) so a TU can pull the pure half alone;
// this umbrella header re-exports both for every EXISTING caller (ODR-safe
// relocation, not a duplication — ADD NOTHING NEW to this file, see the two
// headers above for where new content belongs).
#include "dex_app_perf_builders.hpp"
