#pragma once

/**
 * echo_netqual_boot.hpp — the netqual RETROSPECTIVE boot baseline (ADR-0020).
 *
 * One NetQualBootRow per boot, collected at EchoPlugin::init() from
 * cumulative-since-boot OS counters, so an operator can ask "what was network
 * quality like this boot, BEFORE Echo was running?" with zero provisioning and
 * no elevation. Windows: GetTcpStatisticsEx2 (IPv4+IPv6 TCP MIB; falls back to
 * the 32-bit GetTcpStatisticsEx on pre-1709 hosts) + GetIfTable2 non-loopback
 * interface totals. Returns nullopt off Windows (Linux/macOS baselines are a
 * follow-up) and on any API failure — the caller treats that as "no baseline
 * this boot", never an error.
 *
 * Dedup is the CALLER's job (config key `netqual_boot_backfill_ts` keyed on
 * boot_time_unix(), set only after a successful insert — mirrors the proc
 * ETL backfill's `last_backfill_boot_ts`).
 */

#include "echo_db.hpp" // NetQualBootRow

#include <cstdint>
#include <optional>

namespace yuzu::echo {

/// Collect the since-boot baseline. `now_ts` becomes the row's `ts` (= t_live,
/// the start of Echo's own observation) and bounds `window_s = ts - boot_ts`.
/// snapshot_id is left 0 for the caller to fill.
std::optional<NetQualBootRow> collect_netqual_boot(std::int64_t now_ts);

} // namespace yuzu::echo
