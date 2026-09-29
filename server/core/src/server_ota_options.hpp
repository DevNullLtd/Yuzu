#pragma once

/// @file server_ota_options.hpp
///
/// CLI/env registration for the OTA and gRPC bound knobs (#913, #911), split out
/// of `main.cpp` so it is reachable by a test.
///
/// WHY. These options are the ONLY way an operator tunes the OTA bounds, and
/// while the registration lived inline in `main.cpp` nothing exercised it: a
/// misspelled `envname()`, a default that drifted from the documented one, a
/// binding pointed at the wrong `Config` field, or a lost `CLI::PositiveNumber`
/// validator would all ship silently, with every service-level test still green
/// because those drive the setters directly. A gate-1 review flagged that gap.
///
/// The flag names, defaults and env spellings here are contract — they appear in
/// `docs/user-manual/server-admin.md` and the changelog. `test_server_ota_options.cpp`
/// pins them.

#include <CLI/CLI.hpp>

#include <yuzu/server/server.hpp>

#include "principal_quota.hpp" // kMinPeersTracked

namespace yuzu::server {

/// Register the OTA + gRPC bound options onto `app`, bound to `cfg`.
///
/// Every knob except `--ota-cert-reserve-pct` (which is `CLI::Range(0, 100)`,
/// where zero is a legitimate "no reserve") is `CLI::PositiveNumber`-validated
/// for the same reason the
/// per-principal quota options are: a zero or negative value does not "disable"
/// these bounds, it configures a server that refuses every OTA pull (or accepts
/// no streams at all) with no clear signal why. Rejecting at parse time turns a
/// silent self-inflicted outage into a startup error.
inline void register_ota_options(CLI::App& app, Config& cfg) {
    app.add_option("--ota-max-concurrent-per-peer", cfg.ota_max_concurrent_per_peer,
                   "Max parallel DownloadUpdate streams per peer (default: 2)")
        ->default_val(2)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_OTA_MAX_CONCURRENT_PER_PEER");
    app.add_option("--ota-rate-capacity", cfg.ota_rate_capacity,
                   "Per-peer OTA token-bucket burst (default: 20)")
        ->default_val(20.0)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_OTA_RATE_CAPACITY");
    app.add_option("--ota-rate-refill-per-min", cfg.ota_rate_refill_per_min,
                   "Per-peer OTA tokens restored per minute (default: 1)")
        ->default_val(1.0)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_OTA_RATE_REFILL_PER_MIN");
    app.add_option("--ota-transfer-deadline-secs", cfg.ota_transfer_deadline_secs,
                   "Whole-transfer bound for one OTA download (default: 900)")
        ->default_val(900)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_OTA_TRANSFER_DEADLINE_SECS");
    app.add_option("--ota-chunk-write-deadline-secs", cfg.ota_chunk_write_deadline_secs,
                   "Single-chunk stall bound for an OTA download (default: 30). Raise "
                   "on fleets with genuinely slow links (satellite, congested WAN) — a "
                   "deadline-tripped transfer refunds its rate token, so raising this "
                   "trades a longer held thread for fewer aborted updates.")
        ->default_val(30)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_OTA_CHUNK_WRITE_DEADLINE_SECS");
    app.add_option("--ota-max-peers-tracked", cfg.ota_max_peers_tracked,
                   "Cardinality ceiling on the per-peer OTA admission map (default: 50000)")
        ->default_val(50000)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_OTA_MAX_PEERS_TRACKED");

    app.add_option("--ota-max-concurrent-total", cfg.ota_max_concurrent_total,
                   "Server-wide cap on concurrent OTA transfers across all peers "
                   "(default: 64). The per-peer cap bounds one identity; where the "
                   "identity gate is inert the admission key falls back to source IP, "
                   "so only this bound does not scale with a caller's address space.")
        ->default_val(64)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_OTA_MAX_CONCURRENT_TOTAL");
    app.add_option("--ota-cert-reserve-pct", cfg.ota_cert_reserve_pct,
                   "Percent of --ota-max-concurrent-total reserved for peers admitted "
                   "on a certificate identity (default: 50). IP-keyed peers may use at "
                   "most the remainder, so a flood of unenrolled peers cannot starve an "
                   "enrolled fleet out of the shared ceiling. The remainder is floored "
                   "at one slot for any non-zero ceiling, so a small ceiling or a high "
                   "reserve cannot round IP-keyed peers down to no capacity at all; a "
                   "ceiling of 0 still admits nobody. Set 0 for no reserve.")
        ->default_val(50)
        ->check(CLI::Range(0, 100))
        ->envname("YUZU_OTA_CERT_RESERVE_PCT");
    app.add_option("--grpc-max-threads", cfg.grpc_max_threads,
                   "Thread ceiling for the gRPC sync server (default: 8192). THIS IS A "
                   "FLEET-SIZE CEILING: AgentService is synchronous and Subscribe holds "
                   "one thread per connected agent for the life of its command stream, "
                   "so this MUST exceed your concurrently-connected agent count. Below "
                   "it, gRPC answers ResourceExhausted to every RPC on every service "
                   "sharing the quota — a fleet-wide outage, not back-pressure.")
        ->default_val(8192)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_GRPC_MAX_THREADS");
    app.add_option("--grpc-max-concurrent-streams", cfg.grpc_max_concurrent_streams,
                   "Max concurrent HTTP/2 streams per gRPC connection (default: 128)")
        ->default_val(128)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_GRPC_MAX_CONCURRENT_STREAMS");
    app.add_option("--grpc-max-resource-memory-mb", cfg.grpc_max_resource_memory_mb,
                   "gRPC ResourceQuota memory ceiling in MiB (default: 512)")
        ->default_val(512)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_GRPC_MAX_RESOURCE_MEMORY_MB");
}

/// Apply the floors that the consumers enforce, so every operator-facing surface
/// reports the value the server will ACTUALLY use.
///
/// Without this the floor lives at one call site and the capacity gauge, the
/// settings page and the alert that divides by that gauge all publish the raw
/// configured number — so an operator who sets `--ota-max-peers-tracked=500` is
/// paged at 400 tracked keys against a real ceiling of 1024, and the runbook's
/// remedy does nothing until they cross a threshold no surface mentions. Call this
/// immediately after parsing, before anything reads `cfg`.
inline void normalize_ota_options(Config& cfg) {
    const auto floored = static_cast<int>(kMinPeersTracked);
    if (cfg.ota_max_peers_tracked < floored)
        cfg.ota_max_peers_tracked = floored;
}

} // namespace yuzu::server
