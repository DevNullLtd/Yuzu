/**
 * echo_plugin.cpp -- Echo plugin for Yuzu
 *
 * Continuously captures system state snapshots (processes, network connections,
 * services, user sessions) and records changes as timestamped events in a local
 * SQLite database. Enables retrospective "what happened on this machine" queries
 * without requiring pre-configured logging.
 *
 * Actions:
 *   collect_fast  -- Snapshot processes + network, diff, record events (60s interval)
 *   collect_slow  -- Snapshot services + users, diff, record events (300s interval)
 *   status        -- Return db stats (count, oldest, newest, disk size, config)
 *   query         -- Query events by time range with optional type filter
 *   export        -- Export events as JSON array
 *   snapshot      -- Force an immediate full snapshot (all 4 collectors)
 *   configure     -- Update retention_days, intervals, redaction patterns
 *
 * Data flow:
 *   trigger fires -> enumerate current state -> load previous state from echo_state
 *   -> compute diff -> insert events -> save current state
 */

#include "echo_capture_status.hpp" // yuzu::echo::collect_or_retain
#include "echo_collectors.hpp"
#include "echo_cursor.hpp" // yuzu::echo::CursorSource, make_cursor_sources
#include "echo_netqual_nstat.hpp"
#include "echo_proc_etw.hpp"
#include "echo_proc_es.hpp"
#include "echo_proc_stream.hpp"
#include "echo_module_etw.hpp"
#include "echo_db.hpp"
#include "echo_fold.hpp" // EchoFold::gc_dictionary
#include "echo_fold_schema.hpp"
#include "echo_usage.hpp"
#include "echo_fleet_snapshot.hpp"
#include "echo_source_health.hpp"
#include "echo_status_format.hpp"
#include "echo_netconn.hpp"
#include "echo_netqual_boot.hpp"
#include "echo_perf.hpp"
#include "echo_proc_perf.hpp"
#include "echo_schema_registry.hpp"
#include "echo_aggregator.hpp"
#include "echo_hour_dedup.hpp" // HourlySeenSet
#include "echo_software_core.hpp"
#include "echo_sql_executor.hpp"

#include <yuzu/agent/network_interfaces.hpp>
#include <yuzu/agent/process_enum.hpp>
#include <yuzu/plugin.hpp>
#include <yuzu/echo_retention_tick.hpp> // kEchoRollupTickSeconds (shared with the data-retention API)

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <charconv>
#include <chrono>
#include <filesystem>
#include <format>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <string_view>
#include <system_error>
#include <vector>

namespace {

using json = nlohmann::json;

int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

int64_t next_snapshot_id() {
    static std::atomic<int64_t> counter{0};
    return now_epoch_seconds() * 1000 + counter.fetch_add(1, std::memory_order_relaxed) % 1000;
}

// Operator-configurable retroactive reach for the netconn backfill, in seconds
// (ADR-0020 privacy note). Defaults to kNetConnLookbackS (7 days); 0 means "no
// retrospective read" — the backfill window collapses to empty and the source
// records only forward connectivity from enablement, for jurisdictions where
// pre-notice collection is not permitted. Clamped to [0, 90 days] so a bad
// config value cannot request an unbounded window.
int64_t netconn_lookback_seconds(yuzu::echo::EchoDatabase& db) {
    try {
        return yuzu::echo::nq_clamp_lookback(std::stoll(db.get_config(
            "netconn_lookback_seconds", std::to_string(yuzu::echo::kNetConnLookbackS))));
    } catch (...) {
        // Non-numeric stored value (should be impossible — do_configure rejects
        // it) → fall back to the default rather than throw across a collect leg.
        return yuzu::echo::kNetConnLookbackS;
    }
}

// ── State serialization helpers ──────────────────────────────────────────────

json processes_to_json(const std::vector<yuzu::agent::ProcessInfo>& procs) {
    json arr = json::array();
    for (const auto& p : procs) {
        arr.push_back({{"pid", p.pid},
                       {"ppid", p.ppid},
                       {"name", p.name},
                       {"cmdline", p.cmdline},
                       {"user", p.user}});
    }
    return arr;
}

std::vector<yuzu::agent::ProcessInfo> json_to_processes(const std::string& s) {
    std::vector<yuzu::agent::ProcessInfo> result;
    if (s.empty())
        return result;
    try {
        auto arr = json::parse(s);
        for (const auto& j : arr) {
            yuzu::agent::ProcessInfo p;
            p.pid = j.value("pid", 0u);
            p.ppid = j.value("ppid", 0u);
            p.name = j.value("name", "");
            p.cmdline = j.value("cmdline", "");
            p.user = j.value("user", "");
            result.push_back(std::move(p));
        }
    } catch (...) {}
    return result;
}

json connections_to_json(const std::vector<yuzu::echo::NetConnection>& conns) {
    json arr = json::array();
    for (const auto& c : conns) {
        arr.push_back({{"proto", c.proto},
                       {"local_addr", c.local_addr},
                       {"local_port", c.local_port},
                       {"remote_addr", c.remote_addr},
                       {"remote_port", c.remote_port},
                       {"state", c.state},
                       {"pid", c.pid},
                       {"process_name", c.process_name}});
    }
    return arr;
}

std::vector<yuzu::echo::NetConnection> json_to_connections(const std::string& s) {
    std::vector<yuzu::echo::NetConnection> result;
    if (s.empty())
        return result;
    try {
        auto arr = json::parse(s);
        for (const auto& j : arr) {
            yuzu::echo::NetConnection c;
            c.proto = j.value("proto", "");
            c.local_addr = j.value("local_addr", "");
            c.local_port = j.value("local_port", 0);
            c.remote_addr = j.value("remote_addr", "");
            c.remote_port = j.value("remote_port", 0);
            c.state = j.value("state", "");
            c.pid = j.value("pid", 0u);
            c.process_name = j.value("process_name", "");
            result.push_back(std::move(c));
        }
    } catch (...) {}
    return result;
}

json arp_to_json(const std::vector<yuzu::echo::ArpEntry>& entries) {
    json arr = json::array();
    for (const auto& e : entries) {
        arr.push_back({{"interface", e.iface},
                       {"ip_address", e.ip_address},
                       {"mac_address", e.mac_address},
                       {"entry_type", e.entry_type}});
    }
    return arr;
}

std::vector<yuzu::echo::ArpEntry> json_to_arp(const std::string& s) {
    std::vector<yuzu::echo::ArpEntry> result;
    if (s.empty())
        return result;
    try {
        auto arr = json::parse(s);
        for (const auto& j : arr) {
            yuzu::echo::ArpEntry e;
            e.iface = j.value("interface", "");
            e.ip_address = j.value("ip_address", "");
            e.mac_address = j.value("mac_address", "");
            e.entry_type = j.value("entry_type", "");
            result.push_back(std::move(e));
        }
    } catch (...) {}
    return result;
}

json dns_to_json(const std::vector<yuzu::echo::DnsEntry>& entries) {
    json arr = json::array();
    for (const auto& e : entries) {
        arr.push_back({{"name", e.name},
                       {"record_type", e.record_type},
                       {"data", e.data},
                       {"ttl_remaining_s", e.ttl_remaining_s},
                       {"source", e.source}});
    }
    return arr;
}

std::vector<yuzu::echo::DnsEntry> json_to_dns(const std::string& s) {
    std::vector<yuzu::echo::DnsEntry> result;
    if (s.empty())
        return result;
    try {
        auto arr = json::parse(s);
        for (const auto& j : arr) {
            yuzu::echo::DnsEntry e;
            e.name = j.value("name", "");
            e.record_type = j.value("record_type", "");
            e.data = j.value("data", "");
            e.ttl_remaining_s = j.value("ttl_remaining_s", int64_t{0});
            e.source = j.value("source", "");
            result.push_back(std::move(e));
        }
    } catch (...) {}
    return result;
}

// mapdrive snapshot baseline (capability-map §3.8): serializes the MapDriveEntry
// fields only (no ts/action/origin — those are event, not baseline, data). The
// baseline is implicitly `origin=live`; historical rows never touch it.
json mapdrive_to_json(const std::vector<yuzu::echo::MapDriveEntry>& entries) {
    json arr = json::array();
    for (const auto& e : entries) {
        arr.push_back({{"direction", e.direction},
                       {"local_mount", e.local_mount},
                       {"remote_path", e.remote_path},
                       {"remote_host", e.remote_host},
                       {"username", e.username},
                       {"provider", e.provider}});
    }
    return arr;
}

std::vector<yuzu::echo::MapDriveEntry> json_to_mapdrive(const std::string& s) {
    std::vector<yuzu::echo::MapDriveEntry> result;
    if (s.empty())
        return result;
    try {
        auto arr = json::parse(s);
        for (const auto& j : arr) {
            yuzu::echo::MapDriveEntry e;
            e.direction = j.value("direction", "");
            e.local_mount = j.value("local_mount", "");
            e.remote_path = j.value("remote_path", "");
            e.remote_host = j.value("remote_host", "");
            e.username = j.value("username", "");
            e.provider = j.value("provider", "");
            result.push_back(std::move(e));
        }
    } catch (...) {}
    return result;
}

json services_to_json(const std::vector<yuzu::echo::ServiceInfo>& svcs) {
    json arr = json::array();
    for (const auto& s : svcs) {
        arr.push_back({{"name", s.name},
                       {"display_name", s.display_name},
                       {"status", s.status},
                       {"startup_type", s.startup_type},
                       // Finding 3: persisted across ticks so a Windows
                       // per-service query-failure row loaded back as
                       // "previous" next tick still suppresses the
                       // startup_type comparison symmetrically (see
                       // ServiceInfo::startup_type_query_failed's comment).
                       {"startup_type_query_failed", s.startup_type_query_failed}});
    }
    return arr;
}

std::vector<yuzu::echo::ServiceInfo> json_to_services(const std::string& s) {
    std::vector<yuzu::echo::ServiceInfo> result;
    if (s.empty())
        return result;
    try {
        auto arr = json::parse(s);
        for (const auto& j : arr) {
            yuzu::echo::ServiceInfo si;
            si.name = j.value("name", "");
            si.display_name = j.value("display_name", "");
            si.status = j.value("status", "");
            si.startup_type = j.value("startup_type", "");
            si.startup_type_query_failed = j.value("startup_type_query_failed", false);
            result.push_back(std::move(si));
        }
    } catch (...) {}
    return result;
}

json users_to_json(const std::vector<yuzu::echo::UserSession>& users) {
    json arr = json::array();
    for (const auto& u : users) {
        json j = {{"user", u.user},
                  {"domain", u.domain},
                  {"logon_type", u.logon_type},
                  {"session_id", u.session_id}};
        if (u.disconnected)
            j["disconnected"] = true; // absent = attached: an older baseline reads as attached
        arr.push_back(std::move(j));
    }
    return arr;
}

std::vector<yuzu::echo::UserSession> json_to_users(const std::string& s) {
    std::vector<yuzu::echo::UserSession> result;
    if (s.empty())
        return result;
    try {
        auto arr = json::parse(s);
        for (const auto& j : arr) {
            yuzu::echo::UserSession u;
            u.user = j.value("user", "");
            u.domain = j.value("domain", "");
            u.logon_type = j.value("logon_type", "");
            u.session_id = j.value("session_id", "");
            u.disconnected = j.value("disconnected", false);
            result.push_back(std::move(u));
        }
    } catch (...) {}
    return result;
}

// Installed-software state (de)serialisation lives in echo_software_core.cpp
// (software_state_to_json / software_state_from_json) so the orchestration that
// uses it — software_collect_core — is unit-testable off-Windows.

// ── Redaction pattern loading ────────────────────────────────────────────────

std::vector<std::string> load_redaction_patterns(yuzu::echo::EchoDatabase& db) {
    // The built-in patterns (`kDefaultRedactionPatterns` — password/secret/token/
    // api_key/credential) are the baseline content-protection layer for
    // process_live, and they MUST always apply: an operator can ADD patterns via
    // configure but can never fully DISABLE redaction. So union the defaults into
    // whatever is stored — fail-closed (fjarvis HIGH). A bare `parse_pattern_config`
    // fallback was fail-OPEN: it returns the safe built-in set only for an empty or
    // non-array value, but a *valid array whose elements all get dropped* (`[]`,
    // `[1,2,3]`, all-over-long, or `["*"]` whose stripped core is empty) returns an
    // EMPTY vector — silently disabling redaction so `password`/`token`/`secret`
    // land in process_live in plaintext. collect_fast and procperf called this
    // without the union do_fleet_snapshot already applied; centralising it here
    // closes all three paths at once and removes the divergent local default list.
    // #541 — parse_pattern_config still bounds + sanitises at load (drops
    // non-string/empty/over-long, truncates to the element cap), because this runs
    // every fast-collect cycle on whatever is stored. ensure_redaction_defaults
    // then unions the built-ins — the single, unit-tested home of the fail-closed
    // guarantee, shared with do_fleet_snapshot.
    std::vector<std::string> result;
    if (auto v = yuzu::echo::parse_pattern_config(db.get_config("redaction_patterns")))
        result = std::move(*v);
    return yuzu::echo::ensure_redaction_defaults(std::move(result));
}

// Per-source enable/disable (issue #59). The collect-time / purge-time gate
// `source_enabled` now lives in echo_aggregator (beside canonical_source_enabled,
// the #560 tri-state authority it wraps) so the guard predicate — including the
// Phase 15.A destructive-purge guard — is directly unit-testable. Pull it into
// this TU's unqualified lookup so the many bare `source_enabled(*db_, ...)` call
// sites below are unchanged.
using yuzu::echo::source_enabled;

// Health token for a collect leg skipped at its enable gate. A confirmed false is
// a disable (not a failure); an unreadable flag is a skipped tick and must COUNT
// (state_unreadable), otherwise source_disabled resets the failure streak and a
// source that silently never collects raises no failure surface.
constexpr std::string_view skip_token(std::optional<bool> state) noexcept {
    return state.has_value() ? "source_disabled" : "state_unreadable";
}
// §3.8 mapped-drive backfill retry (related issue #5291) — same unqualified-lookup convenience as
// source_enabled above, for the bare calls in retry_pending_mapdrive_backfill() below.
using yuzu::echo::apply_outcomes;
using yuzu::echo::commit_first_pass;
using yuzu::echo::initial_pending;
using yuzu::echo::kMapDriveBackfillMaxAttempts;
using yuzu::echo::kMapDriveBackfillRetryIntervalS;
using yuzu::echo::MapDriveHistory;
using yuzu::echo::MapDriveEvent;
using yuzu::echo::PendingState;
using yuzu::echo::format_pending_state;
using yuzu::echo::parse_pending_state;
using yuzu::echo::retry_due;
using yuzu::echo::retry_sids;

// Process stabilization exclusion patterns (issue #59). Empty = no exclusions.
std::vector<std::string> load_stabilization_exclusions(yuzu::echo::EchoDatabase& db) {
    auto stored = db.get_config("process_stabilization_exclusions");
    if (stored.empty())
        return {};
    // #541 — bound + sanitise at load (see load_redaction_patterns), AND enforce
    // the ≥3-char effective-core floor here (require_min_core_len=true): unlike
    // redaction, a sub-floor exclusion like ["a"] or ["*a*"] silently drops every
    // process whose name contains that core, so a value persisted before the
    // floor existed (no-tamper upgrade) or tampered out of band must be filtered
    // on this hot path, not just rejected at configure. A non-array stored value
    // yields no exclusions (the safe default — nothing dropped).
    if (auto v = yuzu::echo::parse_pattern_config(stored, /*require_min_core_len=*/true))
        return std::move(*v);
    return {};
}

// ── ABI4 capability declarations (#2204) ─────────────────────────────────
//
// One row per entry in actions() below, same names/order. Legs are grounded
// in two places: reading each collector's own #ifdef structure directly, and
// cross-checking against the pre-existing per-capture-source support table
// this plugin already ships (echo_schema_registry.cpp build_sources(),
// consumed by the `compatibility` action) — its OsSupportStatus enumerators
// alias the SAME YuzuSupportLevel values (echo_schema_registry.hpp:66-70), so
// its judgments are reused directly rather than re-derived from scratch.
//
//   - status/query/export/configure/rollup/sql/compatibility/purge_source:
//     pure in-process SQLite reads/writes against echo.db (EchoDatabase) — no
//     OS acquisition at all, native in-process on every OS (rung 1).
//   - collect_fast: process (ETW/Endpoint-Security/procfs) + network
//     (iphlpapi/procfs/libproc, always the poll — see
//     effective_network_capture_method) + netqual are each native
//     (rung 1) on every OS. macOS's process/tcp legs self-heal to a poll
//     without the ES entitlement / nstat root privilege
//     (echo_schema_registry.cpp process/tcp rows: kSupportedConstrained); the
//     arp sub-source is now wired natively on both non-Windows legs
//     too (echo_arp_collector.cpp: /proc/net/arp on Linux, the shared
//     route_sysctl_arp.hpp sysctl dump on macOS — constrained there,
//     entry_type always 'unknown'), while dns remains kPlanned
//     (echo_dns_collector.cpp) on both — CONSTRAINED, not a bare SUPPORTED,
//     on those two legs.
//   - collect_slow: service (SCM native / systemctl+launchctl, rung-2 argv
//     via the shared subprocess runner) + user (native WTS/utmp/utmpx) +
//     netconn/mapdrive. Windows is all native (scm/wts/wnet/wevtapi,
//     rung 1). Linux/macOS service enumeration runs bounded argv
//     (echo_service_collector.cpp, rung 2 — the worst rung actually
//     exercised on that OS); mapdrive is native getfsstat (rung 1,
//     outbound-live-only, constrained) on macOS and a rung-1/rung-2 mix on
//     Linux (native /proc/mounts + /etc/fstab reads, rung-2 argv for
//     smbstatus/journalctl), and netconn is kPlanned (no-op) on both non-
//     Windows OSes (echo_netconn_win.cpp #else).
//   - collect_perf: device counters (echo_perf.cpp) native on Windows/Linux,
//     kPlanned (host_statistics) on macOS — the target rung is still 1
//     (native syscalls once wired).
//   - collect_software: HKLM Uninstall registry walk on Windows (native,
//     rung 1); kPlanned (dpkg_rpm / pkgutil, echo_software_collector.cpp
//     #else) on Linux/macOS — an argv subprocess once wired (target rung 2).
//   - fleet_snapshot: enumerate_processes()/enumerate_connections() only —
//     ALWAYS the poll, never nstat (echo_schema_registry.cpp:1093-1105
//     effective_network_capture_method). Native on every OS; macOS's poll
//     (proc_pidfdinfo) carries the same TOCTOU caveat the schema table
//     records for that leg (echo "tcp" row 2) — CONSTRAINED there.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        "status",
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
    },
    {
        "query",
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
    },
    {
        "snapshot",
        {YUZU_SUPPORT_CONSTRAINED, 2, "procfs+systemctl+dpkg_rpm(planned)",
         "software inventory collection is PLANNED (dpkg/rpm not yet wired) on Linux; "
         "service enumeration runs bounded argv (rung 2) via the shared subprocess runner"},
        {YUZU_SUPPORT_CONSTRAINED, 2, "endpoint_security+nstat+launchctl+getfsstat+pkgutil(planned)",
         "software collection is PLANNED on macOS; mapdrive is wired but outbound-live-only "
         "(getfsstat, no username, no inbound, no history); service enumeration runs bounded "
         "argv (rung 2) via the shared subprocess runner; process/tcp fall back to a poll "
         "without the Endpoint Security entitlement or nstat root privilege"},
        {YUZU_SUPPORT_SUPPORTED, 1, "etw+iphlpapi+scm+wts+wnet+wevtapi+registry", nullptr},
    },
    {
        "export",
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
    },
    {
        "configure",
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
    },
    {
        "collect_fast",
        {YUZU_SUPPORT_CONSTRAINED, 1, "procfs",
         "dns sub-source is PLANNED (no-op) on Linux; arp sub-source is "
         "native (procfs, /proc/net/arp); core process/network/netqual collection is "
         "native"},
        {YUZU_SUPPORT_CONSTRAINED, 1, "endpoint_security+nstat+route_sysctl",
         "process/tcp fall back to a KERN_PROC_ALL/proc_pidfdinfo poll without the "
         "Endpoint Security entitlement or nstat root privilege; dns sub-source "
         "is PLANNED (no-op) on macOS; arp sub-source is native but constrained "
         "(route_sysctl, entry_type always 'unknown')"},
        {YUZU_SUPPORT_SUPPORTED, 1, "etw+iphlpapi", nullptr},
    },
    {
        "collect_slow",
        {YUZU_SUPPORT_CONSTRAINED, 2, "systemctl+utmp",
         "service enumeration runs bounded argv (rung 2) via the shared subprocess "
         "runner; startup_type reads 'unknown'; netconn source is PLANNED "
         "(no-op) on Linux"},
        {YUZU_SUPPORT_CONSTRAINED, 2, "launchctl+utmpx+getfsstat",
         "service enumeration runs bounded argv (rung 2) via the shared subprocess "
         "runner; no startup_type; mapdrive source is wired but "
         "outbound-live-only (getfsstat, no username, no inbound, no history); "
         "netconn source is PLANNED (no-op) on macOS"},
        {YUZU_SUPPORT_SUPPORTED, 1, "scm+wts+wnet+wevtapi", nullptr},
    },
    {
        "collect_perf",
        {YUZU_SUPPORT_SUPPORTED, 1, "procfs", nullptr},
        {YUZU_SUPPORT_PLANNED, 1, "host_statistics", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "ntcounters", nullptr},
    },
    {
        "collect_software",
        {YUZU_SUPPORT_PLANNED, 2, "dpkg_rpm", nullptr},
        {YUZU_SUPPORT_PLANNED, 2, "pkgutil", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "registry", nullptr},
    },
    {
        "rollup",
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
    },
    {
        "sql",
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
    },
    {
        "compatibility",
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
    },
    {
        "fleet_snapshot",
        {YUZU_SUPPORT_SUPPORTED, 1, "procfs", nullptr},
        {YUZU_SUPPORT_CONSTRAINED, 1, "libproc(proc_pidfdinfo)",
         "inherent TOCTOU between pid enumeration and per-fd query; short-lived "
         "sockets may be missed"},
        {YUZU_SUPPORT_SUPPORTED, 1, "iphlpapi+win32_process_enum", nullptr},
    },
    {
        "purge_source",
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "sqlite", nullptr},
    },
};

} // namespace

class EchoPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "echo"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Echo activity record -- continuous system state change tracking";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"status",         "query",         "snapshot",
                                     "export",         "configure",     "collect_fast",
                                     "collect_slow",   "collect_perf",  "collect_software",
                                     "rollup",         "sql",           "compatibility",
                                     "fleet_snapshot", "purge_source",  nullptr};
        return acts;
    }

    [[nodiscard]] const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }

    [[nodiscard]] size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        plugin_ctx_ = ctx.raw();

        // Determine data directory
        auto data_dir = ctx.get_config("agent.data_dir");
        std::string db_dir;
        if (data_dir.empty()) {
#ifdef _WIN32
            db_dir = "C:\\ProgramData\\yuzu\\agent";
#else
            db_dir = "/var/lib/yuzu/agent";
#endif
        } else {
            db_dir = std::string{data_dir};
        }

        auto db_path = std::filesystem::path{db_dir} / "echo.db";
        db_path_ = db_path;
        auto result = yuzu::echo::EchoDatabase::open(db_path);
        if (!result) {
            // The ABI carries only the code, so this line is where the cause (a refused planted
            // file, its owner and the remedy; a corrupt-and-unmovable db) reaches the log.
            spdlog::error("ECHO: failed to open db: {}", result.error());
            if (yuzu::echo::is_free_space_refusal(result.error())) {
                // The v10 roll-up migration needs twice the file's size free and the volume has
                // less. Nothing was changed. The plugin LOADS, offline, so `echo.status` can say why
                // (`storage_state|offline|free_space`); no trigger is registered and nothing
                // collects until the agent restarts with the space freed.
                offline_reason_ = "free_space";
                offline_detail_ = result.error();
                return {};
            }
            return std::unexpected(
                yuzu::PluginError{1, std::format("ECHO: failed to open db: {}", result.error())});
        }
        db_ = std::make_unique<yuzu::echo::EchoDatabase>(std::move(*result));
        reconcile_db_health_publish(ctx); // #1567: replay any unpublished quarantine fact

        // Load config
        int fast_interval = 60;
        int slow_interval = 300;
        auto fast_str = db_->get_config("fast_interval_seconds", "60");
        auto slow_str = db_->get_config("slow_interval_seconds", "300");
        try {
            fast_interval = std::stoi(fast_str);
        } catch (...) {}
        try {
            slow_interval = std::stoi(slow_str);
        } catch (...) {}

        // Register triggers
        auto fast_config = std::format(
            R"({{"interval_seconds":{},"plugin":"echo","action":"collect_fast","parameters":{{}}}})",
            fast_interval);
        ctx.register_trigger("echo.fast", "interval", fast_config);

        auto slow_config = std::format(
            R"({{"interval_seconds":{},"plugin":"echo","action":"collect_slow","parameters":{{}}}})",
            slow_interval);
        ctx.register_trigger("echo.slow", "interval", slow_config);

        // Perf sampler (BRD A1): 30 s default. perf_interval_seconds = 0
        // disables registration entirely; the per-source perf_enabled config
        // gates collection at run time (both honoured — the trigger seam is
        // the cheap off-switch, the source gate is the operator-facing one).
        int perf_interval = 30;
        try {
            perf_interval = std::stoi(db_->get_config("perf_interval_seconds", "30"));
        } catch (...) {}
        if (perf_interval > 0) {
            auto perf_config = std::format(
                R"({{"interval_seconds":{},"plugin":"echo","action":"collect_perf","parameters":{{}}}})",
                perf_interval);
            ctx.register_trigger("echo.perf", "interval", perf_config);
        }

        // Software install/uninstall sampler: hourly default. Installs are rare,
        // so this runs on its own slower trigger rather than the 60s/300s collectors.
        // software_interval_seconds = 0 disables registration entirely; the
        // per-source software_enabled config gates collection at run time.
        int software_interval = 3600;
        try {
            software_interval = std::stoi(db_->get_config("software_interval_seconds", "3600"));
        } catch (...) {}
        if (software_interval > 0) {
            auto software_config = std::format(
                R"({{"interval_seconds":{},"plugin":"echo","action":"collect_software","parameters":{{}}}})",
                software_interval);
            ctx.register_trigger("echo.software", "interval", software_config);
        }

        // Register rollup trigger (15-minute aggregation cycle)
        auto rollup_config = std::format(
            R"({{"interval_seconds":{},"plugin":"echo","action":"rollup","parameters":{{}}}})",
            yuzu::kEchoRollupTickSeconds);
        ctx.register_trigger("echo.rollup", "interval", rollup_config);

        // Gap-free process events: ETW on Windows, Endpoint Security on macOS. On
        // success, collect_fast drains the stream instead of polling; on failure
        // (wrong platform, missing entitlement/privilege, no session) it stays
        // inactive and the poll handles processes (no silent loss). On platforms
        // with no stream the pointer is null and we go straight to the poll.
#ifdef _WIN32
        proc_stream_ = std::make_unique<yuzu::echo::ProcEtwCollector>();
#elif defined(__APPLE__)
        proc_stream_ = std::make_unique<yuzu::echo::ProcEsCollector>();
#endif
        // Boundary for boot backfill: events before this instant came from the
        // pre-session boot window; the live session owns everything from here on.
        const auto t_live = now_epoch_seconds();
        stream_active_ = proc_stream_ && proc_stream_->start();
        if (stream_active_) {
            spdlog::info("ECHO: {} process stream active (process poll superseded)",
                         proc_stream_->method_name());
            // The stream reports only processes that start from now on; seed the pid -> name
            // map with the ones already running so their sockets and loads can be labelled.
            // Best effort: init() is not contained at the plugin seam, and the map also fills
            // from the stream and the next poll, so a failed seed must not fail the plugin.
            try {
                note_pid_names(yuzu::agent::enumerate_processes(), now_epoch_seconds());
            } catch (const std::exception& e) {
                spdlog::warn("ECHO: process-name seed failed: {}", e.what());
            } catch (...) {
                spdlog::warn("ECHO: process-name seed failed");
            }
        }

        // roadmap 2.2: construct + start the nstat client alongside the ES
        // process stream above (same lifetime/teardown ordering discipline —
        // both are torn down together in shutdown() under collect_mu_).
        // Unconditional/no #ifdef: start() is a documented no-op off-macOS,
        // so this line is inert everywhere except macOS. Registered so the
        // netqual free functions in echo_network_collector.cpp (a different
        // TU, platform-dispatched) can reach it without a second,
        // independently-owned client (echo_collectors.hpp,
        // netqual_nstat_register_client).
        nstat_client_ = std::make_unique<yuzu::echo::NstatClient>();
        if (nstat_client_->start()) {
            spdlog::info("ECHO: nstat client active (netqual + tcp lifecycle)");
        }
        yuzu::echo::netqual_nstat_register_client(nstat_client_.get());

        if (stream_active_) {

            // Boot-window backfill: replay the AutoLogger .etl (configured at
            // install time WITH a FlushTimer so it's continuously written to
            // disk, and started by the kernel early at boot) for process events
            // with ts < t_live — the window before our live session existed.
            // Read directly from the live file; no session stop / no elevation
            // (the narrow agent account only needs read access).
            //
            // Gated on the `process` source toggle: an operator who disables
            // process collection must not have boot events inserted on the next
            // restart (the AutoLogger is a system-level config the agent can't
            // turn off, but the agent will not STORE what the toggle forbids).
            //
            // Per-boot dedup keyed on the BOOT INSTANT (boot_time_unix), not the
            // earliest event in the .etl: the AutoLogger file is circular, so its
            // earliest event shifts as the buffer wraps — a min-ts key would
            // drift and a late restart would re-insert already-captured events as
            // user-empty rows. The boot instant is stable across same-boot
            // restarts and distinct between boots, so dedup is wrap-immune.
            //
            // Boot events are names-only with NO user: the processes are dead by
            // replay time (no token to query), and the Kernel-Process start event
            // itself carries only SessionID + integrity label, not the owning
            // user. Precise boot-window user attribution would require adding the
            // Security-Auditing 4688 provider to the AutoLogger — deferred.
            if (source_enabled(*db_, "process")) {
                const auto boot_key = std::to_string(yuzu::echo::boot_time_unix());
                if (db_->get_config("last_backfill_boot_ts", "") == boot_key) {
                    spdlog::info(
                        "ECHO: boot-backfill already done this boot (agent restart) — skipped");
                } else {
                    const auto etl = (std::filesystem::path{db_dir} / "procboot.etl").string();
                    std::error_code ec;
                    if (!std::filesystem::exists(etl, ec)) {
                        // Normal on any install without the boot AutoLogger — e.g.
                        // a minimal install that omits the `advanced` component, or
                        // a fresh install not yet rebooted. Logged, never silent.
                        spdlog::info("ECHO: no boot AutoLogger trace at {} — boot-window "
                                     "backfill skipped",
                                     etl);
                    } else {
                        auto boot_evs = yuzu::echo::backfill_proc_events_from_etl(etl, t_live);
                        const auto snap = next_snapshot_id();
                        std::vector<yuzu::echo::ProcessEvent> typed;
                        typed.reserve(boot_evs.size());
                        for (auto& e : boot_evs) {
                            yuzu::echo::ProcessEvent pe;
                            pe.ts = e.ts_unix;
                            pe.snapshot_id = snap;
                            pe.action = e.is_start ? "started" : "stopped";
                            pe.pid = e.pid;
                            pe.ppid = e.ppid;
                            pe.name = e.image_name;
                            pe.user = e.user; // empty for boot-backfill (see above)
                            typed.push_back(std::move(pe));
                        }
                        if (typed.empty()) {
                            spdlog::info(
                                "ECHO: boot AutoLogger trace had no pre-session process events");
                            db_->set_config("last_backfill_boot_ts", boot_key);
                        } else if (db_->fold_process_events(typed)) {
                            db_->set_config("last_backfill_boot_ts", boot_key);
                            spdlog::info(
                                "ECHO: boot-backfilled {} process events from the ETW AutoLogger",
                                typed.size());
                        } else {
                            // Leave the key unset so the next restart retries.
                            spdlog::warn("ECHO: boot-backfill insert failed (continuing; "
                                         "will retry on restart)");
                        }
                    }
                }
            } else {
                spdlog::info("ECHO: process source disabled — boot-backfill skipped");
            }
        } else {
            spdlog::info("ECHO: no gap-free process stream active — using snapshot-diff poll");
        }

        // Wave 7 PR7.2b: boot is one of the THREE call sites (boot, configure,
        // fast-tick) that must all reconcile the `usage` fold's lifecycle
        // through this SAME function -- see echo_usage.hpp's file banner for
        // why a boot-time path that instead wrote its own marker directly
        // (the original PR7.2 shape) could stamp coverage while the source
        // was disabled, or race a later enable-edge rebaseline into
        // retrospectively over-collecting the disabled window. A best-effort
        // attempt here is a latency optimisation only -- run_usage_fold()
        // itself calls the identical function on every fast tick, so a
        // failure here is never fatal, only slower to notice.
        if (auto baseline = yuzu::echo::usage::usage_ensure_baselined(*db_, now_epoch_seconds());
            !baseline.has_value()) {
            spdlog::warn("ECHO: boot-time usage baseline attempt failed ({}); the fast-tick fold "
                        "will retry it",
                        baseline.error());
        }
#ifdef _WIN32
        // Construct the Windows ETW image-load collector; the session is STARTED
        // LAZILY by collect_fast on the first tick where module_enabled is true (so
        // enabling takes effect on the next tick — no restart — matching
        // procperf/netqual, and a transient session death auto-re-arms). Null on
        // non-Windows (M4/M5 add macOS Endpoint Security, M6 adds Linux auditd).
        module_stream_ = std::make_unique<yuzu::echo::ModuleEtwCollector>();
#endif

        // ── netqual boot baseline + netconn history backfill (ADR-0020) ──────
        // Both are RETROSPECTIVE one-shot reads of state the OS accumulated
        // BEFORE Echo ran this boot, taken at init with t_live as the boundary.
        // Cross-platform no-ops where unimplemented (the collectors return
        // nullopt/{} off Windows); failures are warn-and-continue — a
        // diagnostics plugin never fails init over retrospective data.
        if (source_enabled(*db_, "netqual")) {
            // One row per boot (the counters are per-boot state); keyed on the
            // boot instant exactly like the proc ETL backfill above, and set
            // ONLY on insert success so a failure retries on the next restart.
            const auto nq_boot_key = std::to_string(yuzu::echo::boot_time_unix());
            if (db_->get_config("netqual_boot_backfill_ts", "") != nq_boot_key) {
                if (auto row = yuzu::echo::collect_netqual_boot(t_live)) {
                    row->snapshot_id = next_snapshot_id();
                    if (db_->insert_netqual_boot_row(*row)) {
                        db_->set_config("netqual_boot_backfill_ts", nq_boot_key);
                        spdlog::info(
                            "ECHO: netqual boot baseline recorded ({}s pre-Echo window)",
                            row->window_s);
                    } else {
                        spdlog::warn("ECHO: netqual boot baseline insert failed "
                                     "(will retry on restart)");
                    }
                }
            }
        }
        if (source_enabled(*db_, "netconn") &&
            db_->get_config("netconn_backfill_hwm", "").empty()) {
            // First-ever read: pull the OS-retained connectivity history from
            // before Echo existed on this box ([t_live - lookback, t_live)).
            // The hwm then hands incremental reads to the collect_slow leg; it
            // is set ONLY on success, so a failed backfill retries on the next
            // slow tick (which sees the still-empty hwm and re-runs the deep
            // read — same window, EvtQuery is cheap at this event rate).
            //
            // The retroactive REACH is operator-configurable (ADR-0020 privacy
            // note): netconn_lookback_seconds bounds how far before enablement
            // the backfill reads. nq_netconn_plan turns lookback==0 into a
            // FORWARD-ONLY plan (read nothing, seed the hwm to t_live) so no
            // pre-enablement history is read; a positive lookback reads
            // [t_live - lookback, t_live).
            const auto plan = yuzu::echo::nq_netconn_plan(/*have_hwm=*/false, 0,
                                                         netconn_lookback_seconds(*db_), t_live);
            if (!plan.read) {
                // Forward-only: seed the hwm so the slow leg reads forward from here.
                db_->set_config("netconn_backfill_hwm", std::to_string(plan.hwm));
            } else {
                auto nc_rows = yuzu::echo::backfill_netconn_events(plan.from, plan.to);
                const auto nc_snap = next_snapshot_id();
                for (auto& r : nc_rows)
                    r.snapshot_id = nc_snap;
                if (nc_rows.empty()) {
                    db_->set_config("netconn_backfill_hwm", std::to_string(plan.hwm));
                } else if (db_->fold_netconn_events(nc_rows)) {
                    db_->set_config("netconn_backfill_hwm", std::to_string(plan.hwm));
                    spdlog::info("ECHO: netconn backfilled {} pre-Echo connectivity events",
                                 nc_rows.size());
                } else {
                    spdlog::warn(
                        "ECHO: netconn history backfill insert failed (slow tick retries)");
                }
            }
        }

        // §3.8: one-time historical mapped-drive backfill. Seeds PAST mappings from
        // persistent OS artifacts (Windows registry Network/MRU/MountPoints2 +
        // Security event log; Linux fstab + Samba logs) as origin='historical' rows
        // that bypass the live diff. Gated on the source toggle AND a one-shot
        // dedup key so it runs at most once per data dir — the key stays UNSET on
        // insert failure so the next restart retries (mirrors last_backfill_boot_ts).
        // Init-time so it materializes on the first (re)start after an operator
        // enables the source, matching the ETW boot-backfill precedent above.
        if (source_enabled(*db_, "mapdrive")) {
            if (!db_->get_config("mapdrive_backfill_done", "").empty()) {
                spdlog::info("ECHO: mapdrive historical backfill already done — skipped");
                // §3.8 bounded per-profile retry (related issue #5291): the first pass already
                // ran -- give its pending list a chance before this tick's own work. Cheap when
                // nothing is due (phase A's own short lock-and-check).
                retry_pending_mapdrive_backfill();
            } else {
                // enumerate_mapdrive_history touches the registry / offline hives /
                // subprocesses and does substantial allocation; a std::bad_alloc (or
                // any future throwing edit) must not cross the plugin C-ABI boundary
                // out of init(). Catch here; a throw is NOT the same as "no history"
                // — enumerated_ok gates the done-key so a throw leaves it unset and
                // the next restart retries (only a clean empty result records done).
                MapDriveHistory hist;
                bool enumerated_ok = false;
                try {
                    hist = yuzu::echo::enumerate_mapdrive_history();
                    enumerated_ok = true;
                } catch (const std::exception& e) {
                    spdlog::warn("ECHO: mapdrive historical backfill enumeration threw ({}) — "
                                 "will retry on restart",
                                 e.what());
                } catch (...) {
                    spdlog::warn("ECHO: mapdrive historical backfill enumeration threw — "
                                 "will retry on restart");
                }
                const auto snap = next_snapshot_id();
                std::vector<MapDriveEvent> typed;
                typed.reserve(hist.rows.size());
                for (auto& h : hist.rows) {
                    MapDriveEvent ev;
                    ev.ts = h.ts;
                    ev.snapshot_id = snap;
                    ev.action = "historical";
                    ev.direction = h.entry.direction;
                    ev.local_mount = h.entry.local_mount;
                    ev.remote_path = h.entry.remote_path;
                    ev.remote_host = h.entry.remote_host;
                    ev.username = h.entry.username;
                    ev.provider = h.entry.provider;
                    ev.origin = "historical";
                    typed.push_back(std::move(ev));
                }
                if (!enumerated_ok) {
                    // Enumeration threw (already logged) — leave the key unset so the
                    // next restart retries rather than permanently skipping history.
                } else if (typed.empty() ||
                           // skip_known_historical: a restart after the commit below failed
                           // re-walks every profile, and the rows the failed pass already wrote
                           // must not be written a second time (the retry path's own insert).
                           db_->fold_mapdrive_events(typed, std::nullopt,
                                                       /*skip_known_historical=*/true)) {
                    // §3.8 bounded per-profile retry (related issue #5291): every profile this
                    // pass could not fully resolve (not_found, privilege_missing, mount_failed, a
                    // refused hive file, a failed inner read, or a cap-cut walk) starts at attempt
                    // 1/kMapDriveBackfillMaxAttempts -- the first pass itself is attempt 1 -- and
                    // a profile it did not try at all (a mount before it timed out, or no mount
                    // was possible) starts at 0.
                    PendingState pending{now_epoch_seconds(), initial_pending(hist.profiles)};
                    if (typed.empty() && pending.profiles.empty()) {
                        spdlog::info("ECHO: no historical mapped drives found to backfill");
                    } else if (typed.empty()) {
                        spdlog::info("ECHO: no historical mapped drives recovered this pass; {} "
                                     "profile(s) are pending a retry",
                                     pending.profiles.size());
                    } else {
                        spdlog::info("ECHO: backfilled up to {} historical mapped-drive rows "
                                     "(rows already recorded are skipped)",
                                     typed.size());
                    }
                    for (const auto& p : pending.profiles) {
                        if (p.attempts == 0) {
                            spdlog::info("Echo mapdrive backfill: profile {} not yet tried, pending "
                                         "(0/{} attempts)",
                                         p.sid, kMapDriveBackfillMaxAttempts);
                        } else {
                            spdlog::info("Echo mapdrive backfill: profile {} attempt {}/{} pending",
                                         p.sid, p.attempts, kMapDriveBackfillMaxAttempts);
                        }
                    }
                    if (!commit_first_pass(
                            [&](std::string_view k, std::string_view v) {
                                return db_->set_config(std::string{k}, std::string{v});
                            },
                            pending.profiles.empty() ? std::string{} : format_pending_state(pending),
                            std::to_string(now_epoch_seconds()))) {
                        spdlog::error("ECHO: mapdrive historical backfill commit failed — "
                                      "backfill left undone, retried on restart");
                    }
                    if (!hist.complete) {
                        // Pre-existing one-shot contract: the first pass's own ProfileList walk
                        // was itself cut short. Logged, not retried separately here -- a
                        // profile this missed is simply never in `pending` either, so it is
                        // never picked up again until the NEXT full restart's first pass.
                        // Tracked as a follow-up (plan risk, not fixed in this change).
                        spdlog::warn("ECHO: mapdrive historical backfill's profile list walk was "
                                     "incomplete this pass");
                    }
                } else {
                    // Leave the key unset so the next restart retries.
                    spdlog::warn("ECHO: mapdrive historical backfill insert failed (continuing; "
                                 "will retry on restart)");
                }
            }
        }

        // ── Cursor-model sources (echo_cursor.hpp: power, removable — wave 2) ──
        // Built once here as EchoPlugin-owned members (P-002 — never a
        // function-local static); make_cursor_sources() returns an empty
        // vector this wave, so this loop is a no-op until wave 2's
        // integrator adds the two push_backs. start()ed unconditionally
        // (like proc_stream_/nstat_client_ above) so an operator flipping
        // `<name>_enabled` later has a live subscription to resume against —
        // the `<name>_enabled` gate itself is applied in collect_slow_impl's
        // per-source region, not here.
        cursor_sources_ = yuzu::echo::make_cursor_sources();
        // A consumer's factory returning a null entry would be dereferenced
        // unguarded at four sites; drop them once, here, rather than checking
        // at each. (cpp-safety, Gate 3.)
        std::erase_if(cursor_sources_, [](const auto& s) { return s == nullptr; });
        // start() is not noexcept in the CursorSource contract, and this runs
        // inside init(): an escaping exception would cross the plugin C-ABI.
        // One source failing to arm its subscription must not take the whole
        // Echo plugin down with it -- the mapdrive block above guards the same
        // hazard for the same reason.
        for (auto& src : cursor_sources_) {
            try {
                // An UNREADABLE flag is not a disable: nothing later re-routes
                // on_enabled_changed(true) (do_configure routes only a canonical
                // edge, the collect loop only skips), so latching the source off
                // would leave it reporting Advanced/0 forever while `status`
                // says enabled. Throw instead -- the catch below drops the source
                // loudly, the same outcome as any other start failure. Read BEFORE
                // start() so this path arms nothing that a drop would have to unarm.
                const auto enabled_state = yuzu::echo::source_enabled_state(*db_, src->name());
                if (!enabled_state)
                    throw std::runtime_error(
                        std::format("{}_enabled unreadable at init", src->name()));
                src->start(*db_);
                // A source is constructed CAPTURING. start() arms the OS
                // subscription regardless of the configured enable state --
                // deliberately, so a later enable does not have to pay a cold
                // arm -- so a source whose persisted state is DISABLED must be
                // told so immediately, before the first callback can arrive.
                // Without this, an agent restarted while the source is disabled
                // buffers the forbidden window (macOS queues callbacks, Linux's
                // netlink socket fills) and commits it on the first later
                // enable: on_enabled_changed(true) is a no-op because the fresh
                // process never saw a disable. echo_cursor.hpp's lifecycle rule
                // is absolute -- NOTHING from a paused window is ever stored --
                // and the disabled-collect path only skips the tick, it does
                // not discard what the OS already handed the source.
                if (!*enabled_state)
                    src->on_enabled_changed(false);
            } catch (const std::exception& e) {
                spdlog::error("ECHO: cursor source '{}' failed to start: {} -- dropping it",
                              src->name(), e.what());
                src.reset();
            } catch (...) {
                spdlog::error("ECHO: cursor source '{}' failed to start (unknown exception) -- "
                              "dropping it",
                              src->name());
                src.reset();
            }
        }
        // A source whose start() threw has NO armed subscription, so leaving it
        // in the vector meant collect() ran against it every tick and returned
        // an ordinary Advanced/0-events result -- a dead source reporting
        // health, which is worse than an absent one. It also never received the
        // on_enabled_changed(false) that the block above argues must land
        // before the first callback can arrive, because that call is inside the
        // same try. Found by both the architect and cpp-safety. A source dropped
        // AFTER a successful start() (a throwing on_enabled_changed) is unarmed by its
        // destructor: R-007 (`~...CursorSource() { stop(); }`) on the power and removable
        // legs, RAII session and fd members elsewhere, so the reset is safe.
        std::erase_if(cursor_sources_, [](const auto& s) { return s == nullptr; });

        spdlog::info("Echo plugin initialized (fast={}s, slow={}s, db={})", fast_interval,
                     slow_interval, db_path.string());
        return {};
    }

    void shutdown(yuzu::PluginContext& ctx) noexcept override {
        ctx.unregister_trigger("echo.fast");
        ctx.unregister_trigger("echo.slow");
        ctx.unregister_trigger("echo.perf");
        ctx.unregister_trigger("echo.software");
        ctx.unregister_trigger("echo.rollup");
        // Unregister the nstat client BEFORE tearing it down: collect_tcp_quality()
        // / netqual_effective_capture_method() (echo_network_collector.cpp) both run
        // OUTSIDE collect_mu_ (do_collect_fast's pre-collection stage), so a call
        // in flight right now could otherwise race nstat_client_->stop() below.
        // This narrows, but does not by itself eliminate, that window — the same
        // level of care the ES process stream already accepts (see the collect_mu_
        // comment right below).
        yuzu::echo::netqual_nstat_register_client(nullptr);
        // Take collect_mu_ around the collector teardown: a collect_fast tick may
        // still be draining proc_stream_ (reads impl_ via drain()/running()), and
        // stop() resets impl_. The host quiesces the trigger engine before
        // shutdown, but the lock makes the ordering safe regardless. The stream's
        // worker (ETW consumer thread / ES handler queue) never takes collect_mu_,
        // so joining it here cannot deadlock.
        {
            std::lock_guard lock(collect_mu_);
            if (proc_stream_) {
                // Windows: closes the ETW session + joins the consumer thread.
                // macOS: es_unsubscribe_all + es_delete_client (blocks until any
                // in-flight handler returns, so no handler touches the ring after).
                proc_stream_->stop();
            }
            if (module_stream_) {
                // Windows: closes the module-load ETW session + joins its
                // consumer thread (idempotent; safe if never started).
                module_stream_->stop();
            }
            if (nstat_client_) {
                // Closes the kctl socket (unblocks the reader's recv) and joins
                // the reader + query threads. Same teardown-ordering discipline
                // as proc_stream_/module_stream_ above — the tcp leg only drains
                // nstat_client_ under collect_mu_ (collect_fast_impl).
                nstat_client_->stop();
            }
            // Cursor-model sources (echo_cursor.hpp): every source's stop() is
            // a bounded unregister/drain/join of everything it owns — called
            // here, under collect_mu_, BEFORE db_.reset() below, exactly the
            // proc_stream_/module_stream_/nstat_client_ ordering above. A
            // source's stop() contract forbids it from touching db_ (or
            // taking collect_mu_ itself) once this returns.
            for (auto& src : cursor_sources_)
                src->stop();
        }
        {
            // A pool command (a manual `rollup`, or a `status` released from a VACUUM wait) can
            // still be inside enforce_budget. Wait for that pass to finish rather than reset the
            // database under it. collect_mu_ is already released, so the lock order
            // rollup_mu_ -> collect_mu_ -> mu_ holds.
            std::lock_guard rollup_lock(rollup_mu_);
            set_budget_catch_up({}); // a collect_fast past the db_ check must not arm a slice
            db_.reset();
        }
        spdlog::info("Echo plugin shut down");
    }

    // Frozen plugin-ABI seam: no C++ exception may unwind out of an action. One containment
    // point for all of them -- before this, a throw from any of the dispatch chain (a
    // std::ios_base::failure from a /proc read, a bad_alloc, a std::length_error) terminated the
    // agent. The catch also rolls back a transaction the unwind left open on the shared write
    // connection (purge_source and the other raw-BEGIN paths allocate between BEGIN and COMMIT).
    // What it does: fail_internal asks for a ROLLBACK before this action returns and logs the
    // result (a warning with the SQLite return code when the ROLLBACK itself fails); it does
    // not promise the connection is back in autocommit. What it cannot cover: the unwind
    // releases mu_ before the catch re-takes it, so another thread can write in between. A
    // transactional writer fails its own BEGIN; the two standalone writers (set_config,
    // set_state) refuse while a transaction is open and report failure instead of a success
    // the rollback would discard. The one per-call-locked writer left,
    // the roll-up's execute_sql_range, can still join and be discarded. Its mark is written by
    // set_config, which refuses while the transaction is open, so that window is rolled up
    // again at the next pass; if the rollback lands first the mark is written and the window
    // is not re-run (a missing hourly summary, never a lost raw capture row). A throw between
    // BEGIN and COMMIT plus a writer in the unwind-to-catch gap is the whole exposure.
    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        try {
            return execute_dispatch(ctx, action, params);
        } catch (const std::exception& e) {
            return fail_internal(ctx, e.what());
        } catch (...) {
            return fail_internal(ctx, "unknown exception");
        }
    }

    int fail_internal(yuzu::CommandContext& ctx, const char* what) noexcept {
        // Ask for the rollback FIRST (it is noexcept and logs its own result): the logger and
        // the output sink can throw, and a swallowed throw must not skip the rollback request
        // for a transaction the unwind left open on the shared connection.
        if (db_)
            db_->rollback_open_transaction();
        try {
            // what() stays in the log only; the wire line is a fixed token because the text can
            // carry paths and JSON fragments.
            spdlog::error("ECHO: action aborted by an exception: {}", what);
            ctx.write_output("error|internal");
        } catch (...) {
            // Containment of the containment: nothing may escape the catch handler.
        }
        return 1;
    }

    int execute_dispatch(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) {
        if (!db_) {
            if (!offline_reason_.empty()) {
                // Loaded but offline (the migration was refused): `status` explains, every other
                // action refuses with the same error. `error|` leads, as format_storage_*_lines
                // pins.
                const auto lines =
                    yuzu::echo::format_storage_refused_lines(offline_reason_, offline_detail_);
                for (std::size_t i = 0; i < lines.size(); ++i)
                    if (i == 0 || action == "status")
                        ctx.write_output(lines[i]);
                return 1;
            }
            ctx.write_output("error|Echo database not initialized");
            return 1;
        }

        if (action == "collect_fast")
            return do_collect_fast(ctx);
        if (action == "collect_slow")
            return do_collect_slow(ctx);
        if (action == "collect_perf")
            return do_collect_perf(ctx);
        if (action == "collect_software")
            return do_collect_software(ctx);
        if (action == "status")
            return do_status(ctx);
        if (action == "query")
            return do_query(ctx, params);
        if (action == "export")
            return do_export(ctx, params);
        if (action == "snapshot")
            return do_snapshot(ctx);
        if (action == "configure")
            return do_configure(ctx, params);
        if (action == "purge_source")
            return do_purge_source(ctx, params);
        if (action == "rollup")
            return do_rollup(ctx);
        if (action == "sql")
            return do_sql(ctx, params);
        if (action == "compatibility")
            return do_compatibility(ctx);
        if (action == "fleet_snapshot")
            return do_fleet_snapshot(ctx);

        ctx.write_output(std::format("error|unknown action: {}", action));
        return 1;
    }

    // Record a source's terminal outcome for this tick in the health ledger.
    // `registry_name` is a capture_sources() name (NOT an echo_state key).
    void note_health(std::string_view registry_name, std::string_view token) {
        const auto now = static_cast<int64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
        std::lock_guard lock(health_mu_);
        health_.record(registry_name, token, now);
    }

    // ── pid -> name map (pid_name_) ───────────────────────────────────────────
    // Callers hold collect_mu_ (init runs before any trigger can fire).
    // `ts` (the event or tick time, epoch seconds) only ages out exited pids at the cap.
    void note_pid_start(std::uint32_t pid, const std::string& name, std::int64_t ts) {
        if (pid == 0 || name.empty())
            return;
        if (pid_name_.size() >= kPidNameCap && !pid_name_.contains(pid)) {
            // The stream leg never erases a stopped pid, so a busy host fills the map with dead
            // ones. Entries past their grace window already resolve to "" and cost nothing to
            // drop; flush wholesale (which forgets running pids too) only if that left no room.
            std::erase_if(pid_name_, [ts](const auto& kv) {
                return kv.second.exited_at != 0 &&
                       ts - kv.second.exited_at > yuzu::echo::kPidNameGraceSec;
            });
            if (pid_name_.size() >= kPidNameCap)
                pid_name_.clear(); // wholesale flush, as the ETW consumer's cache does
        }
        pid_name_[pid] = yuzu::echo::PidName{name, 0};
    }
    // A stop never erases: loads and sockets of a just-exited process still resolve inside
    // kPidNameGraceSec, while a reused pid whose start was missed resolves to "" after it.
    void note_pid_names(const std::vector<yuzu::echo::ProcEvent>& evs) {
        for (const auto& e : evs) {
            if (e.is_start) {
                note_pid_start(e.pid, e.image_name, e.ts_unix);
            } else if (auto it = pid_name_.find(e.pid); it != pid_name_.end()) {
                it->second.exited_at = e.ts_unix;
            }
        }
    }
    // Poll leg: a snapshot has no stop events, so a pid missing from the UNFILTERED enumeration
    // is stamped exited at `ts` (same epoch-seconds clock as the stream's ts_unix), which is what
    // makes the grace window hold on a platform with no process stream. Starts first, so a pid
    // observed again after a stamp is reset to running by note_pid_start.
    void note_pid_names(const std::vector<yuzu::agent::ProcessInfo>& procs, std::int64_t ts) {
        for (const auto& p : procs)
            note_pid_start(p.pid, p.name, ts);
        yuzu::echo::note_pid_exits(pid_name_, procs, ts);
    }

    // #1567: idempotent reconcile of the persisted quarantine fact (echo_config)
    // into the plugin's heartbeat KV keys. The agent bridges `heartbeat.*` keys
    // into `yuzu.plugin.echo.*` heartbeat tags. Runs at init and at the top of
    // every collect_slow tick, so a crash between the quarantine and the publish,
    // or a failed storage_set, is replayed rather than lost. The ledger is never
    // overwritten when it exists but is unreadable (storage_get returns "" for
    // absent AND read-failure). Known host-layer gap: storage_exists reports a
    // READ FAILURE as absent (KvStore::exists folds closed-handle/prepare/step
    // failures into false and agent.cpp maps that to not-found, against
    // plugin.h's negative-on-error contract), so a read fault on the ledger
    // probe followed by a successful write in the same tick restarts the count
    // at 1 — the count is monotonic per agent except for that fault; tracked as
    // a follow-up, #5037 (KvStore::exists tri-state). The two windows where the fact is
    // lost are a crash between the quarantine rename and the fresh DB's config
    // write inside EchoDatabase::open(), and that config write failing (logged by
    // open(); db_health|quarantined still shows for this process).
    void reconcile_db_health_publish(yuzu::PluginContext& pctx) {
        if (!db_ || !db_->is_open())
            return;
        int64_t epoch = 0;
        try {
            epoch = std::stoll(db_->get_config("db_health_last_quarantine_epoch", "0"));
        } catch (...) {
            return;
        }
        const auto file = db_->get_config("db_health_last_quarantine_file", "");
        if (epoch <= 0 || file.empty())
            return;
        const std::string want = std::format("{}:{}", epoch, file);
        constexpr std::string_view kLastKey = "heartbeat.db_quarantine_last";
        constexpr std::string_view kTotalKey = "heartbeat.db_corruption_total";
        // One atomic ledger record `<count>:<epoch>:<basename>` in a private,
        // non-bridged key holds the truth; the two published keys are derived
        // from it by idempotent sets. A failed publish therefore replays the
        // same computation on the next tick instead of re-counting. The
        // identity key is withheld until the matching total is durable, so a
        // torn publish never pairs a stale total with a newer identity.
        constexpr std::string_view kLedgerKey = "db_health.ledger";
        int64_t count = 0;
        std::string ledger_identity;
        if (pctx.storage_exists(kLedgerKey)) {
            const auto raw = pctx.storage_get(kLedgerKey);
            const auto colon = raw.find(':');
            bool ok = colon != std::string::npos && colon > 0;
            if (ok) {
                const auto [p, ec] = std::from_chars(raw.data(), raw.data() + colon, count);
                ok = ec == std::errc{} && p == raw.data() + colon && count >= 0;
            }
            if (!ok) {
                spdlog::warn("ECHO: db_health.ledger unreadable; not overwriting");
                return;
            }
            ledger_identity = raw.substr(colon + 1);
        }
        if (ledger_identity != want) {
            ++count;
            if (!pctx.storage_set(kLedgerKey, std::format("{}:{}", count, want))) {
                spdlog::warn("ECHO: failed to record db quarantine ledger; will retry");
                return;
            }
        }
        const auto publish = [&](std::string_view key, const std::string& value) {
            if (pctx.storage_exists(key) && pctx.storage_get(key) == value)
                return true;
            return pctx.storage_set(key, value);
        };
        // The identity is published only once the matching total is durable:
        // publishing kLastKey after a failed kTotalKey write would let the KV
        // hold a stale total paired with a newer identity.
        if (!publish(kTotalKey, std::to_string(count))) {
            spdlog::warn("ECHO: failed to publish db quarantine total; will retry "
                        "(identity withheld)");
            return;
        }
        if (!publish(kLastKey, want))
            spdlog::warn("ECHO: failed to publish db quarantine identity; will retry");
    }

private:
    YuzuPluginContext* plugin_ctx_{nullptr};
    std::mutex health_mu_;
    yuzu::echo::SourceHealthLedger health_;
    std::atomic<int64_t> procperf_procs_seen_{0};
    // Set when the stream-fallback baseline seed failed: the poll must re-seed
    // (no diff) on the next tick instead of diffing against a stale baseline.
    // Guarded by collect_mu_.
    bool proc_poll_seed_pending_{false};
    std::unique_ptr<yuzu::echo::EchoDatabase> db_;
    // Set when the database could not be opened because the v10 migration needs more free disk
    // space than the volume has (the plugin loads, offline): the token `status` reports and the
    // open error's text. Empty on every other path. Written once in init(), before any action runs.
    std::string offline_reason_;
    std::string offline_detail_;
    std::mutex collect_mu_; // Protects the state read-diff-write sequence in collect methods
    // Separate mutex for the software source: its state read-diff-write touches
    // only the "software" KV state (never prev_perf_/prev_proc_/proc_stream_), and
    // the registry walk + JSON (de)serialise can be slow on many-profile hosts —
    // putting it on collect_mu_ would stall collect_fast/slow/fleet_snapshot. A
    // dedicated mutex serialises concurrent collect_software (manual vs trigger)
    // without that cross-collector coupling.
    std::mutex software_collect_mu_;
    // Serialises whole rollup passes (#2361). do_rollup is reachable from two
    // places at once: the 900s `echo.rollup` trigger and an operator-issued manual
    // `echo rollup` instruction. run_retention's clock-guard state is plain
    // in-memory maps that it reads and writes WITHOUT holding db_->mu_ (the
    // database mutex only serialises individual statements), so two concurrent
    // passes would race the latch and the decline counters -- exactly what TSan
    // catches in CI. Serialising the pass is cleaner than making each map entry
    // atomic, and rollup is a background maintenance tick where a rare wait costs
    // nothing. Also makes the aggregate-then-retain ordering below atomic.
    std::mutex rollup_mu_;
    // Per-table retention clock-guard state. rollup_mu_ serialises whole PASSES;
    // the state carries its own mutex for the brief map touches, so do_status can
    // read the counters without waiting for a pass to finish.
    yuzu::echo::RetentionGuardState retention_guard_;
    yuzu::echo::PerfCounters prev_perf_; // previous perf reading (guarded by collect_mu_)
    yuzu::echo::ProcSnapshot prev_proc_; // previous per-process snapshot (guarded by collect_mu_)
    // Per-app version cache, keyed by (pid, create_time): resolves each top-N
    // process once while it stays in the set (read-once-near-launch). Touched
    // only by resolve_proc_versions OUTSIDE collect_mu_ — so it has its own
    // mutex; never hold collect_mu_ across the OpenProcess/file-read it drives.
    std::mutex proc_ver_mu_;
    std::unordered_map<std::uint64_t, std::string> version_cache_;

    // Gap-free process start/stop stream: ETW on Windows, Endpoint Security on
    // macOS (one concrete collector per platform behind the ProcStreamCollector
    // interface; null where no stream exists). When it starts, stream_active_ is
    // true and collect_fast DRAINS this instead of polling; if it fails to start
    // (wrong platform, missing entitlement/privilege, session-open failure),
    // stream_active_ stays false and collect_fast falls back to the snapshot-diff
    // poll — so a process source is always present. Drained only under collect_mu_.
    std::unique_ptr<yuzu::echo::ProcStreamCollector> proc_stream_;
    // Atomic: written under collect_mu_ (init + self-heal in collect_fast) but
    // also read WITHOUT the lock by the `status` action (do_status), which runs
    // on a different command thread — a plain bool there would be a data race.
    std::atomic<bool> stream_active_{false};
    // Events drained from the stream ring but not yet persisted because a prior
    // insert failed (DB locked/full); retried on the next collect_fast tick so a
    // transient failure does not lose the batch (UP-2). Guarded by collect_mu_;
    // bounded so a persistently failing DB cannot grow memory without limit.
    std::vector<yuzu::echo::ProcEvent> pending_stream_evs_;
    static constexpr std::size_t kPendingStreamCap = 100000;
    // High-water mark of ProcEventRing::dropped() already logged, so the overflow
    // warning fires on each new drop rather than every tick. Guarded by collect_mu_.
    std::uint64_t last_logged_dropped_{0};
    // Epoch seconds of the last `usage` fold failure warning -- rate-limits
    // run_usage_fold() failure logging to once per minute (Wave 7 PR7.2b) so
    // a persistently wedged fold does not spam every fast tick. Guarded by
    // collect_mu_ (only read/written from collect_fast_impl).
    int64_t usage_last_fold_warn_ts_{0};

    // ── M2: gap-free module/image-load stream (Windows ETW; null elsewhere) ───
    // Unlike the process stream, this is high-volume, so the session is started
    // LAZILY by collect_fast on the first enabled tick (enabling takes effect on
    // the next tick — no restart — and a transient session death auto-re-arms).
    // When active, collect_fast drains it; there is NO poll fallback (no
    // snapshot-diff equivalent for image loads). Drained only under collect_mu_.
    std::unique_ptr<yuzu::echo::ImageStreamCollector> module_stream_;
    std::atomic<bool> module_stream_active_{false};
    std::vector<yuzu::echo::ModuleEvent> pending_module_evs_;
    std::uint64_t last_module_dropped_{0};
    // Latches a failed start() so collect_fast does not retry every tick (start
    // storm) when the ETW session is genuinely unavailable; reset when the source
    // is disabled, so a later re-enable retries. Guarded by collect_mu_.
    bool module_start_failed_{false};

    // ── roadmap 2.2: nstat (macOS netqual + tcp lifecycle; echo_netqual_nstat.hpp)
    // ONE client feeds both the netqual leg (collect_tcp_quality(), reached via
    // netqual_nstat_register_client() below — see echo_collectors.hpp) and the
    // tcp lifecycle leg (drained directly here, see the "tcp" block in
    // collect_fast_impl). Constructed + started UNCONDITIONALLY on every
    // platform: off-macOS every NstatClient method is a documented no-op and
    // start() returns false, so this never needs an #ifdef — same "inert
    // elsewhere" contract the ES/ETW streams get via platform-specific
    // construction, just without needing platform selection since there is
    // only ever one concrete NstatClient type. Single-owner (this plugin);
    // NOT an EsClientBroker — nstat has exactly one consumer surface (memo
    // ~/.claude/plans/nstat-spike-2.1-memo.md §4.3).
    std::unique_ptr<yuzu::echo::NstatClient> nstat_client_;
    // High-water mark of NstatClient::dropped() already logged (same pattern
    // as last_logged_dropped_/last_module_dropped_). Guarded by collect_mu_.
    std::uint64_t last_nstat_dropped_{0};
    // HIGH-3: events mapped from the nstat lifecycle ring but not yet
    // persisted because a prior insert failed (DB locked/full) — mirrors
    // pending_stream_evs_/pending_module_evs_ above so a transient DB failure
    // never permanently loses tcp lifecycle events. Guarded by collect_mu_;
    // bounded by kPendingStreamCap. HIGH-4 clears this when the tcp source is
    // disabled (the buffered-but-undelivered batch belongs to the paused
    // window and must never be persisted on re-enable); HIGH-5 also feeds it
    // from the stream-death/stall drain-before-fallback path.
    std::vector<yuzu::echo::NetworkEvent> pending_nstat_evs_;
    // Whether nstat was the tcp lifecycle PRIMARY source on the previous
    // collect_fast tick — lets the "tcp" leg detect a nstat→poll fallback
    // transition and reseed the poll's diff baseline instead of misreporting
    // every already-open tcp connection as newly "connected" (see the tcp
    // block's self-heal comment). Guarded by collect_mu_.
    bool nstat_tcp_primary_prev_{false};

    // ── Storage budget and hourly de-duplication state ────────────────────────
    // Path of echo.db, for the free-disk check that gates the one-off VACUUM.
    std::filesystem::path db_path_;
    // pid -> process name, so tcp sockets and module loads (which carry a pid but not always a
    // name) can be labelled. Fed by the process source (stream events or poll snapshots), so
    // a paused process source leaves it empty. Guarded by collect_mu_; flushed wholesale at
    // kPidNameCap, cleared when the process source is confirmed disabled.
    std::unordered_map<std::uint32_t, yuzu::echo::PidName> pid_name_;
    static constexpr std::size_t kPidNameCap = 65536;
    // Hourly de-duplication sets (echo_hour_dedup.hpp). Each tick filters against a COPY and
    // keeps it only once the rows are committed, so a rolled-back tick re-derives the same
    // rows. Guarded by collect_mu_. The overflow counters mirror the committed sets for status.
    yuzu::echo::HourlySeenSet tcp_closing_seen_;
    yuzu::echo::HourlySeenSet module_seen_;
    std::atomic<std::uint64_t> tcp_closing_overflows_{0};
    std::atomic<std::uint64_t> module_overflows_{0};
    // Set when a pass ran out of time with evictable rows left and data still over target:
    // each fast tick then runs one more bounded slice (do_collect_fast) until it clears.
    std::atomic<bool> budget_catch_up_{false};
    // The clock reading the pass that armed the catch-up was admitted with (the retention clock
    // guard had a verdict on it). Every slice of that drain runs with it, never a fresh reading:
    // a slice has no guard contact of its own. A separate field, not a sentinel in one int64,
    // because a reading <= 0 is the legitimate dead-CMOS case. Only meaningful while the flag is
    // set; written and read under rollup_mu_ (the flag alone is also peeked lock-free).
    std::atomic<std::int64_t> budget_catch_up_now_{0};
    // The conversion-VACUUM deferral time when the persisted marker could not be written: it
    // keeps the retry at most daily for this process. 0 = none. Written under rollup_mu_, read
    // lock-free by status.
    std::atomic<std::int64_t> vacuum_marker_fallback_{0};
    // steady_clock tick count of this process's last conversion attempt, 0 = none (see
    // vacuum_attempted_recently).
    std::atomic<std::int64_t> vacuum_last_attempt_{0};

    // Cursor-model sources (echo_cursor.hpp: power, removable — wave 2). Built
    // once in init() from make_cursor_sources() (empty this wave); NOT a
    // function-local static (P-002) — these are EchoPlugin-owned members with
    // the same lifetime discipline as proc_stream_/module_stream_/
    // nstat_client_ above: start()ed at init, stop()ped under collect_mu_
    // in shutdown() BEFORE db_.reset() (see shutdown()).
    std::vector<std::unique_ptr<yuzu::echo::CursorSource>> cursor_sources_;

    // ── collect_fast: processes + network ─────────────────────────────────────
    // Unlocked implementation -- caller must hold collect_mu_
    // arp_pre/dns_pre: optionally pre-enumerated snapshots collected by the caller
    // BEFORE collect_mu_ was taken (the arp/dns collectors are syscall-heavy — see
    // do_collect_fast). When null, the leg enumerates inline (legacy/no-op path).
    // arp_pre is an optional<vector> (not a bare vector) so a precollection
    // failure (enumerate_arp() threw -- incomplete capture, echo_capture_status.hpp's
    // collect_or_retain contract) is preserved as nullopt through this layer
    // instead of collapsing to an empty vector indistinguishable from a
    // genuinely empty ARP table (BR-001, round 2) -- do_collect_fast sets it.
    // skipped_sources: when non-null, the name of every enabled
    // collect_or_retain-backed source this call skipped (arp) is appended --
    // do_snapshot (round 3, B3-002) aggregates these across both
    // collect_fast_impl and collect_slow_impl to decide whether the forced
    // `snapshot` action can honestly report "complete". Null for the regular
    // collect_fast trigger tick (do_collect_fast), which already logs the
    // same skip via spdlog and has no separate completeness response to give.
    int collect_fast_impl(yuzu::CommandContext& ctx,
                          std::optional<std::vector<yuzu::echo::ArpEntry>>* arp_pre = nullptr,
                          std::vector<yuzu::echo::DnsEntry>* dns_pre = nullptr,
                          std::vector<yuzu::echo::TcpQualitySample>* netqual_pre = nullptr,
                          std::vector<std::string>* skipped_sources = nullptr) {
        auto ts = now_epoch_seconds();
        auto snap_id = next_snapshot_id();
        auto redaction = load_redaction_patterns(*db_);
        auto stab_excl = load_stabilization_exclusions(*db_);
        int total_events = 0;

        // Process diff (C6: check insert return, abort state save on failure)
        // Per-source enable gate (issue #59): if disabled, skip both the
        // diff and the state save so that re-enabling later starts from a
        // clean baseline rather than diffing against a frozen snapshot.
        const auto process_state = yuzu::echo::source_enabled_state(*db_, "process");
        const bool process_enabled = process_state.value_or(false);
        // Forensic-pause contract: the ETW collector owns a live session and keeps
        // filling its ring even while the `process` source is disabled. Unlike the
        // poll (which simply doesn't enumerate), the buffered events SURVIVE — so on
        // the first drain after re-enable they would be persisted into process_live,
        // capturing exactly the paused window the toggle forbids ("the agent will not
        // STORE what the toggle forbids", as already enforced for boot-backfill).
        // Drain-and-DISCARD each disabled tick so nothing from the paused window is
        // ever stored. (Keeps the session warm — no stop/re-arm gap; the kernel
        // session keeps running, events are captured-then-dropped, never inserted.)
        // Discard only on a CONFIRMED disable: an unreadable flag skips this tick
        // (process_enabled is false) but leaves the ring buffering, so a transient
        // read failure never destroys events for a source that is actually enabled.
        if (stream_active_ && process_state.has_value() && !*process_state) {
            proc_stream_->drain();       // flush + discard; never inserted
            pending_stream_evs_.clear(); // and drop any pre-disable insert-retry backlog
        }
        if (process_state.has_value() && !*process_state)
            pid_name_.clear(); // a paused process source feeds nothing; forget what it knew
        if (process_enabled) {
            // #538: single source of truth for the diff-baseline state key (see
            // diff_state_key) — the same key apply_source_enabled_transition
            // clears on disable, so the two can't drift.
            const std::string proc_key{yuzu::echo::diff_state_key("process")};
            if (stream_active_) {
                // Gap-free stream (ETW/Windows or Endpoint Security/macOS)
                // supersedes the snapshot-diff poll. Same process_live schema +
                // 'started'/'stopped' so rollups and the $Process_* query surface
                // are unchanged. Names-only (no cmdline — matches the works-council
                // posture); user resolved at drain (SID on Windows, audit-token uid
                // on macOS).
                auto evs = proc_stream_->drain();
                // Prepend events held over from a prior failed insert. The stream
                // has no re-diff self-heal like the poll, so a transient insert
                // failure (DB locked/full) must not silently drop the drained batch
                // (UP-2). Bounded below by kPendingStreamCap.
                if (!pending_stream_evs_.empty()) {
                    evs.insert(evs.begin(), std::make_move_iterator(pending_stream_evs_.begin()),
                               std::make_move_iterator(pending_stream_evs_.end()));
                    pending_stream_evs_.clear();
                }
                note_pid_names(evs); // all events, including stabilization-excluded ones
                std::vector<yuzu::echo::ProcessEvent> typed;
                typed.reserve(evs.size());
                for (auto& e : evs) {
                    // Stabilization exclusions apply here too (parity with the poll).
                    if (!stab_excl.empty() && yuzu::echo::should_redact(e.image_name, stab_excl)) {
                        continue;
                    }
                    yuzu::echo::ProcessEvent pe;
                    pe.ts = e.ts_unix;
                    pe.snapshot_id = snap_id;
                    pe.action = e.is_start ? "started" : "stopped";
                    pe.pid = e.pid;
                    pe.ppid = e.ppid;
                    pe.name = e.image_name;
                    pe.user = e.user;
                    pe.exit_code = e.exit_code;
                    pe.parent_name = yuzu::echo::pid_name_lookup(pid_name_, e.ppid, e.ts_unix);
                    typed.push_back(std::move(pe));
                }
                if (!typed.empty()) {
                    if (!db_->fold_process_events(typed, std::nullopt, ts)) {
                        note_health("process", "insert_failed");
                        spdlog::error("ECHO: process stream insert failed — re-queuing {} events "
                                      "for the next tick",
                                      evs.size());
                        // Retain the drained events (pre-redaction source) and
                        // retry next tick; bound the backlog so a persistently
                        // failing DB cannot grow memory without limit (drops the
                        // oldest, mirroring the ring's overflow posture).
                        pending_stream_evs_ = std::move(evs);
                        if (pending_stream_evs_.size() > kPendingStreamCap) {
                            const auto excess = pending_stream_evs_.size() - kPendingStreamCap;
                            pending_stream_evs_.erase(pending_stream_evs_.begin(),
                                                      pending_stream_evs_.begin() +
                                                          static_cast<std::ptrdiff_t>(excess));
                        }
                        ctx.write_output("error|process insert failed");
                        return 1;
                    }
                    total_events += static_cast<int>(typed.size());
                }
                note_health("process", "events_recorded");
                // No state save — the stream is continuous, not a snapshot.

                // Ring-overflow visibility: dropped() is cumulative, so warn only
                // on the delta since the last drain (else it spams every tick for
                // the agent's lifetime after a single burst). Also surfaced via
                // the `status` action (process_stream_dropped).
                if (auto d = proc_stream_->dropped(); d > last_logged_dropped_) {
                    spdlog::warn(
                        "ECHO: process stream ring overflow — {} dropped (+{} since last drain)", d,
                        d - last_logged_dropped_);
                    last_logged_dropped_ = d;
                }

                // Self-heal: fall back to the snapshot-diff poll if the stream is no
                // longer delivering, so the process source does not go silently blind
                // (UP-1). Two triggers: running()==false (Windows ETW ProcessTrace
                // returned — another tool stopped it, buffer loss, quota), or
                // stalled()==true (macOS Endpoint Security exposes no liveness API, so
                // a prolonged TOTAL silence is treated as presumed-dead — see
                // ProcEsCollector::stalled and its quiet-host caveat). The batch above
                // is already persisted; `status` then reports
                // process_capture_method=polling.
                if (!proc_stream_->running() || proc_stream_->stalled()) {
                    spdlog::warn("ECHO: process stream ended/stalled — falling back to "
                                 "snapshot-diff poll");
                    proc_stream_->stop();
                    stream_active_ = false;
                    // Prime the poll's process baseline with the CURRENT process
                    // set, WITHOUT emitting events. Otherwise the first poll tick
                    // would diff every running process against an empty snapshot
                    // and emit a spurious 'started' for each — double-counting the
                    // processes ETW already recorded as started. Seeding the
                    // baseline here makes the first real diff capture only changes
                    // since the fallback. (Mirrors the poll branch's enumerate +
                    // stabilization-exclusion filter, minus the diff/insert.)
                    auto current = yuzu::agent::enumerate_processes();
                    note_pid_names(current, ts);
                    if (!stab_excl.empty()) {
                        std::erase_if(current, [&](const auto& p) {
                            return yuzu::echo::should_redact(p.name, stab_excl);
                        });
                    }
                    // Checked (#1654): a failed seed must not be followed by a diff
                    // against a stale/empty baseline (ghost `started` storm), so the
                    // poll re-seeds WITHOUT diffing on the next tick.
                    if (!db_->set_state(proc_key, processes_to_json(current).dump())) {
                        spdlog::error("ECHO: process poll-baseline seed failed after stream "
                                      "fallback; will re-seed next tick");
                        ctx.write_output("error|process state_save_failed");
                        note_health("process", "state_save_failed");
                        proc_poll_seed_pending_ = true;
                    }
                }
            } else {
                // No active stream (poll-only platform, or stream unavailable):
                // snapshot-diff poll.
                auto current = yuzu::agent::enumerate_processes();
                // Before the exclusions: a noisy process still names its sockets.
                note_pid_names(current, ts);

                // Stabilization exclusions: drop processes whose name matches any
                // exclusion pattern. The patterns reuse the same matching as
                // redaction (case-insensitive substring with optional '*' on
                // either side stripped — NOT real glob). Excluded processes never enter the
                // diff, so their birth/death events are silently dropped — the
                // documented forensic-completeness trade-off.
                if (!stab_excl.empty()) {
                    std::erase_if(current, [&](const auto& p) {
                        return yuzu::echo::should_redact(p.name, stab_excl);
                    });
                }

                if (proc_poll_seed_pending_) {
                    // A previous stream-fallback seed failed: re-seed the baseline
                    // without diffing (no ghost `started` for every process).
                    if (!db_->set_state(proc_key, processes_to_json(current).dump())) {
                        spdlog::error("ECHO: process poll-baseline re-seed failed");
                        ctx.write_output("error|process state_save_failed");
                        note_health("process", "state_save_failed");
                        return 1;
                    }
                    proc_poll_seed_pending_ = false;
                    note_health("process", "baseline");
                } else {
                    auto prev_json = db_->get_state(proc_key);
                    auto previous = json_to_processes(prev_json);

                    auto typed = yuzu::echo::compute_process_events(previous, current, ts, snap_id,
                                                                   redaction);
                    // The parent's image name, from the pid -> name map filled just above.
                    for (auto& pe : typed)
                        pe.parent_name = yuzu::echo::pid_name_lookup(pid_name_, pe.ppid, ts);
                    // Events + baseline commit in ONE transaction (#1654): a failed
                    // baseline save can no longer leave events durable with a stale
                    // baseline that the next tick would re-diff and double-emit.
                    const std::string state_json = processes_to_json(current).dump();
                    const bool ok =
                        typed.empty()
                            ? db_->set_state(proc_key, state_json)
                            : db_->fold_process_events(
                                  typed, yuzu::echo::StateWrite{proc_key, state_json}, ts);
                    if (!ok) {
                        const char* tok = typed.empty() ? "state_save_failed" : "insert_failed";
                        spdlog::error("ECHO: process poll {} — nothing persisted, next tick "
                                      "re-diffs",
                                      tok);
                        ctx.write_output(typed.empty() ? "error|process state_save_failed"
                                                       : "error|process insert failed");
                        note_health("process", tok);
                        return 1;
                    }
                    total_events += static_cast<int>(typed.size());
                    note_health("process", "events_recorded");
                }
            }
        } else {
            note_health("process", skip_token(process_state));
        }

        // `usage` derived fold (Wave 7 PR7.2b): the events themselves were folded into the usage
        // tables INSIDE the process fold's transaction above (EchoDatabase::fold_process_events
        // passes usage_fold_in as the fold's `extra`, so the two commit or roll back together).
        // What is left here is the per-tick sweep with no events: expire and cap the open runs and
        // advance the anchor, so a run ages out even on a tick with no process event. Still under
        // collect_mu_. Gates itself on usage_enabled AND process_enabled, and on the lifecycle
        // state internally -- a disabled or not-yet-baselined source is not a failure.
        if (auto fold = yuzu::echo::usage::usage_sweep(*db_, ts); !fold.ok) {
            note_health("usage", "insert_failed");
            if (ts - usage_last_fold_warn_ts_ >= 60) {
                spdlog::warn("ECHO: usage sweep failed this tick ({}) -- retrying next tick",
                            fold.error);
                usage_last_fold_warn_ts_ = ts;
            }
        } else {
            const auto usage_state = yuzu::echo::source_enabled_state(*db_, "usage");
            note_health("usage", usage_state.value_or(false) ? "events_recorded"
                                                             : skip_token(usage_state));
        }

        // Network diff
        const auto tcp_state = yuzu::echo::source_enabled_state(*db_, "tcp");
        if (tcp_state.value_or(false)) {
            // #538: tcp's diff baseline lives under "network" (see diff_state_key).
            const std::string net_key{yuzu::echo::diff_state_key("tcp")};
            auto current = yuzu::echo::enumerate_connections();
            // Label sockets the collector could not name (TIME_WAIT sockets have pid 0 and stay
            // unnamed; the rest resolve through the process source's pid -> name map).
            yuzu::echo::fill_process_names(current, pid_name_, ts);

            // macOS (roadmap 2.2): nstat is the PRIMARY tcp lifecycle source
            // when the plugin's NstatClient is live and system-wide — its
            // SRC_ADDED/SRC_REMOVED stream drains straight into network_live
            // below, gap-free, mirroring the ES process-stream discipline
            // above. enumerate_connections() (the proc_pidfdinfo poll, called
            // unconditionally above regardless of platform) stays the
            // FALLBACK + SEED: a not-running/stalled client self-heals onto
            // the ordinary poll diff below with no silent loss. UDP has no
            // nstat provider, so it is ALWAYS diffed via the poll, never
            // routed through nstat.
            bool nstat_primary = nstat_client_ && nstat_client_->running() &&
                                 nstat_client_->system_wide() && !nstat_client_->stalled();

            // #1846 M2: a failed nstat lifecycle insert this tick must win over
            // a later successful poll-leg write when the tcp source's single
            // terminal health token is recorded below (tcp_tick_status).
            bool nstat_insert_failed = false;

            // HIGH-3: maps a batch of drained lifecycle events into
            // NetworkEvent rows, prepends anything held over from a prior
            // failed insert (mirrors pending_stream_evs_/pending_module_evs_
            // above), and inserts. On success the pending queue is cleared;
            // on FAILURE the whole (already-typed) batch is retained,
            // bounded, for a retry next tick — the previous behavior only
            // logged "dropped this tick" and lost the batch for good.
            auto persist_nstat_flow_events =
                [&](std::vector<yuzu::echo::NstatFlowEvent> flow_events) {
                    std::vector<yuzu::echo::NetworkEvent> typed;
                    typed.reserve(flow_events.size());
                    // remote_host stays empty: nstat is a lifecycle event stream, not the
                    // DNS-resolving poll (resolve_hostnames), the same simplification the ES
                    // process stream makes for cmdline.
                    for (const auto& e : flow_events)
                        typed.push_back(yuzu::echo::network_event_from_nstat_flow(e, snap_id));
                    if (!pending_nstat_evs_.empty()) {
                        typed.insert(typed.begin(),
                                     std::make_move_iterator(pending_nstat_evs_.begin()),
                                     std::make_move_iterator(pending_nstat_evs_.end()));
                        pending_nstat_evs_.clear();
                    }
                    if (typed.empty())
                        return;
                    if (!db_->fold_network_events(typed)) {
                        spdlog::error("ECHO: nstat tcp lifecycle insert failed — re-queuing "
                                      "{} events for the next tick",
                                      typed.size());
                        nstat_insert_failed = true;
                        pending_nstat_evs_ = std::move(typed);
                        if (pending_nstat_evs_.size() > kPendingStreamCap) {
                            const auto excess = pending_nstat_evs_.size() - kPendingStreamCap;
                            pending_nstat_evs_.erase(pending_nstat_evs_.begin(),
                                                     pending_nstat_evs_.begin() +
                                                         static_cast<std::ptrdiff_t>(excess));
                        }
                    } else {
                        total_events += static_cast<int>(typed.size());
                    }
                };

            if (nstat_primary) {
                persist_nstat_flow_events(nstat_client_->drain());
                if (auto d = nstat_client_->dropped(); d > last_nstat_dropped_) {
                    spdlog::warn("ECHO: nstat lifecycle ring overflow — {} dropped (+{} since "
                                 "last drain)",
                                 d, d - last_nstat_dropped_);
                    last_nstat_dropped_ = d;
                }
            } else if (nstat_tcp_primary_prev_ && nstat_client_) {
                // HIGH-5: a stream-death/stall transition — nstat owned the
                // tcp lifecycle LAST tick but is not primary THIS tick
                // (running() self-detected the reader thread's death,
                // system_wide() dropped, or stalled() tripped). drain() only
                // needs the ring, not running(), so it can still hold events
                // the reader buffered before it died; draining BEFORE
                // seeding the poll's diff baseline below mirrors the process
                // stream precedent of draining the ring before checking
                // running() (see the "process" leg above) rather than
                // abandoning a still-populated ring. A layout_mismatch()
                // means our transcribed wire layout disagreed with this
                // kernel, so the buffered bytes are untrustworthy and must
                // be discarded, never persisted; the self-heal
                // baseline-priming below (nstat_tcp_primary_prev_) applies
                // either way.
                if (!nstat_client_->layout_mismatch()) {
                    persist_nstat_flow_events(nstat_client_->drain());
                } else {
                    // Discard, never persist: a layout mismatch is permanent
                    // for this client's remaining session (running() stays
                    // false — no future tick can ever become nstat_primary
                    // again to retry a queued batch), so also drop any
                    // already-typed pending_nstat_evs_ from an earlier failed
                    // insert rather than let it sit stuck-forever bounded.
                    nstat_client_->drain(); // discard — untrustworthy bytes
                    pending_nstat_evs_.clear();
                    spdlog::warn("ECHO: nstat layout mismatch on stream death — discarding "
                                 "the buffered tcp lifecycle ring");
                }
            } else if (!pending_nstat_evs_.empty() && nstat_client_) {
                // R2-2: a poll-only steady-state tick (nstat never became
                // primary again after a fallback) must still retry a stranded
                // insert-retry backlog — a batch requeued on the one transition
                // tick would otherwise sit in memory until disable/shutdown,
                // since neither branch above runs once nstat_tcp_primary_prev_
                // has flipped false. Mirrors pending_stream_evs_ being retried
                // on every process tick.
                persist_nstat_flow_events({});
            }

            auto prev_json = db_->get_state(net_key);
            auto previous = json_to_connections(prev_json);

            const std::vector<yuzu::echo::NetConnection>* diff_current = &current;
            const std::vector<yuzu::echo::NetConnection>* diff_previous = &previous;
            std::vector<yuzu::echo::NetConnection> udp_current;
            std::vector<yuzu::echo::NetConnection> udp_previous;
            auto is_tcp = [](const yuzu::echo::NetConnection& c) {
                return c.proto == "tcp" || c.proto == "tcp6";
            };
            if (nstat_primary) {
                // TCP already handled above via the nstat drain — diff the
                // poll for UDP only so the same open/close is never recorded
                // twice.
                udp_current = current;
                udp_previous = previous;
                std::erase_if(udp_current, is_tcp);
                std::erase_if(udp_previous, is_tcp);
                diff_current = &udp_current;
                diff_previous = &udp_previous;
            } else if (nstat_tcp_primary_prev_) {
                // Falling back from nstat to the poll THIS tick: `previous`
                // only carries udp (nstat owned tcp lifecycle last tick), so
                // diffing it against the full current snapshot would
                // misreport every already-open tcp connection as a fresh
                // "connected" — a self-heal artifact, not a real event.
                // Prime the baseline with the full current snapshot instead
                // (zero diff this tick), mirroring the process stream's
                // self-heal seeding above.
                diff_previous = &current;
            }
            // `nstat_tcp_primary_prev_` shadows the stored baseline's shape, so it
            // advances only after the events + baseline commit (below): a rolled
            // back fallback tick must re-prime next tick, not diff a udp-only
            // baseline against the full snapshot (#1654).

            // Filter against a COPY of the closing-socket seen set and keep it only once the rows
            // commit below, so a rolled-back tick re-derives the same rows.
            yuzu::echo::HourlySeenSet closing_seen = tcp_closing_seen_;
            auto typed = yuzu::echo::compute_network_events(*diff_previous, *diff_current, ts,
                                                            snap_id, closing_seen);

            // While nstat is primary, persist the udp-only view so the next
            // tick's poll diff stays apples-to-apples (never mistakes
            // nstat-owned tcp state for a poll-observed disconnect);
            // otherwise persist the full snapshot as before (the poll owns
            // both protocols). Events + baseline commit in ONE transaction.
            const std::string state_json =
                connections_to_json(nstat_primary ? *diff_current : current).dump();
            const bool ok = typed.empty()
                                ? db_->set_state(net_key, state_json)
                                : db_->fold_network_events(
                                      typed, yuzu::echo::StateWrite{net_key, state_json});
            if (!ok) {
                const char* tok = typed.empty() ? "state_save_failed" : "insert_failed";
                spdlog::error("ECHO: network {} — nothing persisted, next tick re-diffs", tok);
                ctx.write_output(typed.empty() ? "error|network state_save_failed"
                                               : "error|network insert failed");
                // A failed nstat lifecycle insert earlier this tick takes
                // precedence over this leg's own outcome, so it is never
                // silently overwritten (#1846 M2).
                note_health("tcp", yuzu::echo::tcp_tick_status(nstat_insert_failed, tok));
                return 1;
            }
            nstat_tcp_primary_prev_ = nstat_primary;
            tcp_closing_seen_ = std::move(closing_seen);
            tcp_closing_overflows_.store(tcp_closing_seen_.overflows(), std::memory_order_relaxed);
            total_events += static_cast<int>(typed.size());
            note_health("tcp", yuzu::echo::tcp_tick_status(nstat_insert_failed, "events_recorded"));
        } else if (nstat_client_ && tcp_state.has_value()) {
            note_health("tcp", "source_disabled");
            // HIGH-4: forensic-pause contract for tcp lifecycle — the nstat
            // client keeps its reader thread running and filling its ring
            // even while the `tcp` source is disabled (the whole block above
            // is skipped, so nothing here would otherwise touch it), unlike
            // the poll which simply stops enumerating. Drain-and-DISCARD
            // each disabled tick so the paused window is never inserted on
            // re-enable — mirrors the process/module stream drain-and-discard
            // contract above (echo_plugin.cpp process/module leg comments).
            // Drop any pre-disable insert-retry backlog too. The client
            // itself stays running (it also feeds netqual, which has its own
            // independent enable gate below) — only the lifecycle ring is
            // discarded here. Only on a CONFIRMED disable (tcp_state.has_value()):
            // an unreadable flag skips the tick via the plain branch below and
            // leaves the ring buffering rather than discarding live lifecycle events.
            nstat_client_->drain();
            pending_nstat_evs_.clear();
        } else {
            note_health("tcp", skip_token(tcp_state));
        }

        // netqual: per-connection TCP quality (BRD Workstream E). Co-sampled with
        // the tcp leg above: same snap_id + ts so netqual rows join the connection
        // events on snapshot_id. Only the privacy bucket leaves select_netqual_rows;
        // the raw remote address is dropped there and never persisted. Empty off
        // Linux (collector stub).
        const auto netqual_state = yuzu::echo::source_enabled_state(*db_, "netqual");
        if (netqual_state.value_or(false)) {
            // netqual_pre: pre-collected by the caller OUTSIDE collect_mu_ (the
            // Windows ESTATS pass is one enable+read syscall pair per tracked
            // connection — same rationale as arp_pre/dns_pre). Inline when null.
            auto samples =
                netqual_pre ? std::move(*netqual_pre) : yuzu::echo::collect_tcp_quality();
            auto rows =
                yuzu::echo::select_netqual_rows(samples, ts, snap_id, yuzu::echo::kNetQualTopN);
            if (!rows.empty()) {
                // A netqual insert failure must NOT fail the whole
                // collect_fast tick — the tcp/process legs already
                // committed, so returning 1 here would misreport a healthy cycle
                // as failed (and suppress the events_recorded line the server
                // reads for retention-pause detection). Log and skip instead.
                if (db_->fold_netqual_samples(rows)) {
                    total_events += static_cast<int>(rows.size());
                    note_health("netqual", "sample_recorded");
                } else {
                    spdlog::error("ECHO: netqual insert failed this tick (skipped)");
                    note_health("netqual", "insert_failed");
                }
            } else {
                note_health("netqual", "sample_recorded");
            }
        } else {
            note_health("netqual", skip_token(netqual_state));
        }

        // ARP diff (ADR-0015). Implemented on Windows, Linux, and macOS -- see the
        // registry (echo_schema_registry.cpp) for the platform-specific field
        // constraints. Non-fatal on insert failure — the core legs above
        // already committed, so a failure here must not misreport a healthy tick;
        // the diff baseline is advanced ONLY on success so a failed insert retries
        // the same deltas next tick.
        //
        // enumerate_arp() throws when the platform capture didn't genuinely
        // complete (sysctl/procfs/GetIpNetTable2 read failure, a kernel-
        // truncated parse, or the kArpEntryCap reached before the whole table
        // was consumed -- echo_arp_collector.cpp / echo_capture_status.hpp). A
        // partial ARP table must never be diffed against the last COMPLETE
        // snapshot (it would manufacture false appeared/removed forensic
        // events) or replace it as the new baseline -- same
        // collect-or-retain contract as the service/mapdrive legs below.
        // arp_pre, when supplied, carries the OUTCOME of a precollection
        // attempt (nullopt if that threw -- do_collect_fast), not just the
        // entries.
        const auto arp_state = yuzu::echo::source_enabled_state(*db_, "arp");
        if (arp_state.value_or(false)) {
            std::optional<std::vector<yuzu::echo::ArpEntry>> current;
            if (arp_pre) {
                current = std::move(*arp_pre);
            } else {
                auto res = yuzu::echo::collect_or_retain(
                    [] { return yuzu::echo::enumerate_arp(); });
                current = std::move(res.current);
                if (!current) {
                    spdlog::warn("ECHO: arp snapshot incomplete ({}) -- retaining baseline",
                                 res.skip_reason);
                    if (skipped_sources)
                        skipped_sources->push_back("arp");
                }
            }
            if (current) {
                auto previous = json_to_arp(db_->get_state("arp"));
                auto typed = yuzu::echo::compute_arp_events(previous, *current, ts, snap_id);
                // Events + baseline in one transaction (#1654); non-fatal, so a
                // failure emits no `error|` line (the tick's events_recorded
                // contract holds) and the ledger records the token.
                const std::string state_json = arp_to_json(*current).dump();
                const bool ok = typed.empty()
                                    ? db_->set_state("arp", state_json)
                                    : db_->fold_arp_events(
                                          typed, yuzu::echo::StateWrite{"arp", state_json});
                if (ok) {
                    total_events += static_cast<int>(typed.size());
                    note_health("arp", "events_recorded");
                } else {
                    const char* tok = typed.empty() ? "state_save_failed" : "insert_failed";
                    spdlog::error("ECHO: arp {} this tick (nothing persisted)", tok);
                    note_health("arp", tok);
                }
            } else {
                note_health("arp", "capture_incomplete");
            }
        } else {
            note_health("arp", skip_token(arp_state));
        }

        // DNS-cache diff (ADR-0015). Device-level resolver-cache state; NOT
        // per-process (no pid). Same non-fatal / advance-on-success discipline as
        // the arp leg.
        const auto dns_state = yuzu::echo::source_enabled_state(*db_, "dns");
        if (dns_state.value_or(false)) {
            auto current = dns_pre ? std::move(*dns_pre) : yuzu::echo::enumerate_dns();
            auto previous = json_to_dns(db_->get_state("dns"));
            auto typed = yuzu::echo::compute_dns_events(previous, current, ts, snap_id);
            const std::string state_json = dns_to_json(current).dump();
            const bool ok = typed.empty()
                                ? db_->set_state("dns", state_json)
                                : db_->fold_dns_events(
                                      typed, yuzu::echo::StateWrite{"dns", state_json});
            if (ok) {
                total_events += static_cast<int>(typed.size());
                note_health("dns", "events_recorded");
            } else {
                const char* tok = typed.empty() ? "state_save_failed" : "insert_failed";
                spdlog::error("ECHO: dns {} this tick (nothing persisted)", tok);
                note_health("dns", tok);
            }
        } else {
            note_health("dns", skip_token(dns_state));
        }

        // M2: module/image loads (Windows ETW). The session starts lazily below.
        const auto module_state = yuzu::echo::source_enabled_state(*db_, "module");
        const bool module_enabled = module_state.value_or(false);
        // Lazy start / re-arm: start the session on the first enabled tick (so
        // enabling takes effect next tick — like procperf/netqual, no restart) and
        // re-arm after a transient session death. module_start_failed_ prevents a
        // start-storm when the session is genuinely unavailable; it is reset on
        // disable so a later re-enable retries.
        if (module_stream_ && module_enabled && !module_stream_active_ && !module_start_failed_) {
            module_stream_active_ = module_stream_->start();
            if (module_stream_active_) {
                spdlog::info("ECHO: module stream active ({})", module_stream_->method_name());
            } else {
                module_start_failed_ = true;
                spdlog::warn("ECHO: module ETW session failed to start — module capture "
                             "unavailable (retries if module_enabled is toggled off then on)");
            }
        }
        if (!module_enabled) {
            module_start_failed_ = false; // re-enable should retry a previously-failed start
        }
        std::string_view module_tok; // ledger token for this tick (see below); empty = unset
        if (module_stream_active_ && module_state.has_value() && !*module_state) {
            // Disabled mid-run (a true→false toggle): drain-and-discard so the
            // paused window is never stored, keeping the session warm. Mirrors
            // the process forensic-pause contract. Only on a CONFIRMED disable --
            // an unreadable flag skips the tick and leaves the ring buffering.
            module_stream_->drain();
            pending_module_evs_.clear();
        } else if (module_stream_active_ && module_enabled) {
            module_tok = "events_recorded";
            // drain() resolves signing (cached) and redacts module_dir off the
            // ETW thread, so events arrive fully populated + privacy-scrubbed.
            auto mevs = module_stream_->drain();
            if (!pending_module_evs_.empty()) {
                mevs.insert(mevs.begin(), std::make_move_iterator(pending_module_evs_.begin()),
                            std::make_move_iterator(pending_module_evs_.end()));
                pending_module_evs_.clear();
            }
            // Label loads whose loader the ETW consumer could not name (an exited or protected
            // process), from the process source's pid -> name map. Kernel loads have no user
            // process to name. Before the filter: the loader name is part of its key.
            for (auto& e : mevs) {
                if (e.process_name.empty() && !e.is_kernel)
                    e.process_name = yuzu::echo::pid_name_lookup(pid_name_, e.pid, e.ts_unix);
            }
            // §5 edge filter: unloads dropped, every risky load kept, other loads once per hour
            // per (action, loader, module, folder). Filter against a COPY of the seen set and
            // keep it only once the rows commit, so a failed insert re-filters identically.
            yuzu::echo::HourlySeenSet module_seen = module_seen_;
            mevs = yuzu::echo::apply_module_risk_filter(std::move(mevs), module_seen);
            std::vector<yuzu::echo::ModuleRow> mrows;
            mrows.reserve(mevs.size());
            for (const auto& e : mevs) {
                yuzu::echo::ModuleRow r;
                r.ts = e.ts_unix;
                r.snapshot_id = snap_id;
                r.action = std::string{yuzu::echo::module_action_token(e.action)};
                r.pid = e.pid;
                r.process_name = e.process_name;
                r.module_name = e.module_name;
                r.module_dir = e.module_dir; // already redacted by the collector
                r.signed_state = std::string{yuzu::echo::module_signed_token(e.signed_state)};
                r.signer = e.signer;
                r.is_kernel = e.is_kernel;
                mrows.push_back(std::move(r));
            }
            if (!mrows.empty()) {
                if (!db_->fold_module_events(mrows)) {
                    // Like netqual, do NOT fail the whole tick (the
                    // other legs already committed). Re-queue the filtered
                    // batch for the next tick, bounded, and log.
                    module_tok = "insert_failed";
                    spdlog::error("ECHO: module stream insert failed — re-queuing {} events",
                                  mevs.size());
                    pending_module_evs_ = std::move(mevs);
                    if (pending_module_evs_.size() > kPendingStreamCap) {
                        const auto excess = pending_module_evs_.size() - kPendingStreamCap;
                        pending_module_evs_.erase(pending_module_evs_.begin(),
                                                  pending_module_evs_.begin() +
                                                      static_cast<std::ptrdiff_t>(excess));
                    }
                } else {
                    total_events += static_cast<int>(mrows.size());
                    module_seen_ = std::move(module_seen);
                }
            }
            module_overflows_.store(module_seen_.overflows(), std::memory_order_relaxed);
            if (auto d = module_stream_->dropped(); d > last_module_dropped_) {
                spdlog::warn("ECHO: module stream ring overflow — {} dropped (+{} since last drain)",
                             d, d - last_module_dropped_);
                last_module_dropped_ = d;
            }
            // Self-heal: no poll fallback for modules — if the session ended, stop
            // and report module_capture_method=none (vs going silently blind).
            if (!module_stream_->running()) {
                spdlog::warn(
                    "ECHO: module stream ended — module capture stopped (no poll fallback)");
                module_stream_->stop();
                module_stream_active_ = false;
            }
        }

        if (!module_enabled) {
            module_tok = skip_token(module_state);
        } else if (module_tok.empty()) {
            const auto st = yuzu::echo::os_support_status("module", yuzu::echo::current_platform_os());
            module_tok = (st == yuzu::echo::OsSupportStatus::kSupported ||
                          st == yuzu::echo::OsSupportStatus::kSupportedConstrained)
                             ? "capture_incomplete"
                             : "unsupported_platform";
        }
        note_health("module", module_tok);

        ctx.write_output(std::format("echo|collect_fast|{}|events_recorded", total_events));
        return 0;
    }

    int do_collect_fast(yuzu::CommandContext& ctx) {
        // SRE/UP-1: enumerate the syscall-heavy network sources (arp via
        // GetIpNetTable2; dns via DnsGetCacheDataTable + up to kDnsEntryCap cache-only
        // DnsQuery_W calls) BEFORE taking collect_mu_, so a large host cache cannot
        // stall the core process/tcp legs or the fleet-snapshot pump (mirrors
        // do_collect_perf's lock-free counter read). The diff/insert/state-save still
        // run under collect_mu_ inside collect_fast_impl.
        const bool arp_on = source_enabled(*db_, "arp");
        const bool dns_on = source_enabled(*db_, "dns");
        // netqual's Windows ESTATS pass is a per-connection enable+read syscall sweep, so
        // it pre-collects lock-free with arp/dns.
        const bool netqual_on = source_enabled(*db_, "netqual");
        // arp: precollected through collect_or_retain into an OPTIONAL (not a
        // bare vector) so enumerate_arp()'s incomplete-capture throw (read
        // failure / kernel-truncated parse / entry-cap reached --
        // echo_arp_collector.cpp) is preserved as nullopt through this layer,
        // rather than collapsing to an empty vector collect_fast_impl could
        // not tell apart from a genuinely empty ARP table (BR-001, round 2).
        // Isolated in its own try (via collect_or_retain) so an ARP failure
        // does not also discard the independent dns/netqual precollection
        // below.
        std::optional<std::vector<yuzu::echo::ArpEntry>> arp_pre;
        if (arp_on) {
            auto res = yuzu::echo::collect_or_retain([] { return yuzu::echo::enumerate_arp(); });
            arp_pre = std::move(res.current);
            if (!arp_pre)
                spdlog::warn("ECHO: arp snapshot incomplete ({}) -- retaining baseline",
                             res.skip_reason);
        }
        std::vector<yuzu::echo::DnsEntry> dns_pre;
        std::vector<yuzu::echo::TcpQualitySample> netqual_pre;
        // Belt-and-suspenders (SRE): the dns collector calls an undocumented dnsapi
        // export over an opaque heap list; isolate any throw so a bad list degrades
        // this tick to empty rather than crossing the plugin ABI boundary.
        try {
            if (dns_on)
                dns_pre = yuzu::echo::enumerate_dns();
            if (netqual_on)
                netqual_pre = yuzu::echo::collect_tcp_quality();
        } catch (...) {
            spdlog::error("ECHO: dns/netqual enumeration threw; skipping this tick");
            dns_pre.clear();
            netqual_pre.clear();
        }
        int rc = 0;
        {
            std::lock_guard lock(collect_mu_);
            rc = collect_fast_impl(ctx, arp_on ? &arp_pre : nullptr, dns_on ? &dns_pre : nullptr,
                                   netqual_on ? &netqual_pre : nullptr);
        }
        run_budget_catch_up(); // outside collect_mu_; no-op unless a pass left data over target
        return rc;
    }

    // ── collect_perf: device performance sample (BRD A1) ─────────────────────
    // Reads raw kernel counters, derives one perf_live row from the delta vs
    // the previous reading (held in memory — first tick after start is the
    // baseline and records nothing).
    //
    // The counter read (32 PhysicalDrive opens + GetIfTable2) runs OUTSIDE
    // collect_mu_ (gov UP-6): that mutex also serialises collect_fast/slow and
    // fleet_snapshot, so a slow/hung disk IOCTL under the lock would stall them
    // and the /viz hot path. Only the prev_perf_ read-modify-write needs the
    // lock; next_snapshot_id is atomic and fold_perf_sample takes its own.
    //
    // A2: the per-app top-N sampler (echo_proc_perf) rides the SAME tick under
    // its OWN `procperf` source toggle — disabling device perf does not kill
    // per-app sampling or vice versa (both die when the echo.perf trigger is
    // unregistered via perf_interval_seconds=0).
    int do_collect_perf(yuzu::CommandContext& ctx) {
        int rc = 0;
        const auto perf_state = yuzu::echo::source_enabled_state(*db_, "perf");
        if (!perf_state.value_or(false)) {
            note_health("perf", skip_token(perf_state));
            ctx.write_output(std::format("echo|collect_perf|0|{}", skip_token(perf_state)));
        } else {
            const auto cur = yuzu::echo::read_perf_counters(); // syscalls, no lock held
            if (!cur.valid) {
                // counters_unavailable on an OS whose registry row says a perf
                // collector exists; unsupported_platform where none does (#1846).
                const auto tok = yuzu::echo::read_failure_token(
                    yuzu::echo::os_support_status("perf", yuzu::echo::current_platform_os()));
                note_health("perf", tok);
                ctx.write_output(std::format("echo|collect_perf|0|{}", tok));
            } else {
                std::optional<bool> perf_now = true;
                yuzu::echo::PerfSample sample;
                {
                    std::lock_guard lock(collect_mu_); // prev_perf_ RMW + disable re-check
                    // The enabled gate above ran WITHOUT the lock; a disable could
                    // have landed (and reset prev_perf_) since. Re-check here so a
                    // disable racing a mid-flight sample never commits a post-disable
                    // row, and leave prev_perf_ untouched when disabled so the reset
                    // in the disable branch stands. (#538)
                    perf_now = yuzu::echo::source_enabled_state(*db_, "perf");
                    if (perf_now.value_or(false)) {
                        sample = yuzu::echo::derive_sample(prev_perf_, cur);
                        prev_perf_ = cur;
                    }
                }
                if (!perf_now.value_or(false)) {
                    note_health("perf", skip_token(perf_now));
                    ctx.write_output(std::format("echo|collect_perf|0|{}", skip_token(perf_now)));
                } else if (!sample.valid) {
                    note_health("perf", yuzu::echo::kCollectStatusBaseline);
                    ctx.write_output(std::format("echo|collect_perf|0|{}",
                                                 yuzu::echo::kCollectStatusBaseline));
                } else {
                    yuzu::echo::PerfRow row;
                    row.ts = cur.ts_epoch;
                    row.snapshot_id = next_snapshot_id();
                    row.cpu_pct = sample.cpu_pct;
                    row.mem_used_pct = sample.mem_used_pct;
                    row.commit_pct = sample.commit_pct;
                    row.disk_read_bps = sample.disk_read_bps;
                    row.disk_write_bps = sample.disk_write_bps;
                    row.disk_read_lat_us = sample.disk_read_lat_us;
                    row.disk_write_lat_us = sample.disk_write_lat_us;
                    row.net_rx_bps = sample.net_rx_bps;
                    row.net_tx_bps = sample.net_tx_bps;
                    if (!db_->fold_perf_sample(row)) {
                        note_health("perf", "insert_failed");
                        ctx.write_output("error|perf insert failed");
                        rc = 1;
                    } else {
                        note_health("perf", yuzu::echo::kCollectStatusSampleRecorded);
                        ctx.write_output(std::format("echo|collect_perf|1|{}",
                                                     yuzu::echo::kCollectStatusSampleRecorded));
                    }
                }
            }
        }

        // A2 per-app leg (independent of the device leg's outcome).
        // `procperf_enabled=false` switches off per-app sampling while
        // device-level perf stays on.
        const auto procperf_state = yuzu::echo::source_enabled_state(*db_, "procperf");
        if (!procperf_state.value_or(false)) {
            note_health("procperf", skip_token(procperf_state));
            ctx.write_output(
                std::format("echo|collect_procperf|0|{}", skip_token(procperf_state)));
            return rc;
        }
        auto proc_cur = yuzu::echo::read_proc_counters(); // one snapshot, no lock held
        if (!proc_cur.valid) {
            const auto tok = yuzu::echo::read_failure_token(
                yuzu::echo::os_support_status("procperf", yuzu::echo::current_platform_os()));
            note_health("procperf", tok);
            ctx.write_output(std::format("echo|collect_procperf|0|{}", tok));
            return rc;
        }
        procperf_procs_seen_.store(static_cast<int64_t>(proc_cur.procs.size()),
                                   std::memory_order_relaxed);
        const auto ts = proc_cur.ts_epoch; // before the move; never read prev_proc_ unlocked
        const auto redaction = load_redaction_patterns(*db_);
        std::optional<bool> procperf_now = true;
        std::vector<yuzu::echo::ProcPerfSample> samples;
        {
            std::lock_guard lock(collect_mu_); // prev_proc_ RMW + disable re-check
            // The procperf gate above ran WITHOUT the lock; re-check here so a
            // disable that raced this tick (and already reset prev_proc_) cannot
            // commit a post-disable row. Leave prev_proc_ as the disable branch
            // reset it so a later re-enable re-baselines instead of diffing across
            // the opt-out window. (#538)
            procperf_now = yuzu::echo::source_enabled_state(*db_, "procperf");
            if (procperf_now.value_or(false)) {
                samples = yuzu::echo::derive_proc_samples(prev_proc_, proc_cur, redaction);
                prev_proc_ = std::move(proc_cur);
            }
        }
        if (!procperf_now.value_or(false)) {
            note_health("procperf", skip_token(procperf_now));
            ctx.write_output(
                std::format("echo|collect_procperf|0|{}", skip_token(procperf_now)));
            return rc;
        }
        if (samples.empty()) {
            note_health("procperf", yuzu::echo::kCollectStatusBaseline);
            ctx.write_output(std::format("echo|collect_procperf|0|{}",
                                         yuzu::echo::kCollectStatusBaseline));
            return rc;
        }
        // Resolve each app's on-disk file version OUTSIDE collect_mu_ — the
        // OpenProcess + version-resource read must never block other collectors.
        // No-op off Windows (versions stay ""). (#DEX app-perf-over-time slice 1)
        {
            std::lock_guard vlock(proc_ver_mu_);
            yuzu::echo::resolve_proc_versions(samples, version_cache_);
        }
        const auto snap_id = next_snapshot_id();
        std::vector<yuzu::echo::ProcPerfRow> rows;
        rows.reserve(samples.size());
        for (auto& s : samples) {
            yuzu::echo::ProcPerfRow r;
            r.ts = ts;
            r.snapshot_id = snap_id;
            r.name = std::move(s.name);
            r.version = std::move(s.version);
            r.instances = s.instances;
            r.cpu_pct = s.cpu_pct;
            r.ws_bytes = s.ws_bytes;
            r.is_kthread = s.is_kthread;
            rows.push_back(std::move(r));
        }
        if (!db_->fold_proc_perf_samples(rows)) {
            note_health("procperf", "insert_failed");
            ctx.write_output("error|procperf insert failed");
            return 1;
        }
        note_health("procperf", yuzu::echo::kCollectStatusAppsRecorded);
        ctx.write_output(std::format("echo|collect_procperf|{}|{}", rows.size(),
                                     yuzu::echo::kCollectStatusAppsRecorded));
        return rc;
    }

    // ── collect_slow: services + users ────────────────────────────────────────
    // Unlocked implementation -- caller must hold collect_mu_
    // skipped_sources: see collect_fast_impl's parameter doc above -- service
    // and mapdrive are BOTH collected entirely inside this function (no
    // outer precollection stage like arp/dns/netqual has), so this is the
    // only place their collect_or_retain skip can be recorded for do_snapshot.
    int collect_slow_impl(yuzu::CommandContext& ctx,
                          std::vector<std::string>* skipped_sources = nullptr) {
        auto ts = now_epoch_seconds();
        auto snap_id = next_snapshot_id();
        int total_events = 0;

        // Service diff (C6: check insert return)
        const auto service_state = yuzu::echo::source_enabled_state(*db_, "service");
        if (service_state.value_or(false)) {
            // enumerate_services() throws when the underlying capture (systemctl/
            // launchctl via run_bounded_subprocess) didn't genuinely complete --
            // spawn failure, deadline, output-cap truncation, or non-zero exit
            // (echo_service_collector.cpp, echo_capture_status.hpp). A partial
            // service list must never be diffed against the last COMPLETE
            // snapshot (it would manufacture false stopped/started events) or
            // replace it as the new baseline -- so on a throw, skip this tick's
            // diff and state-advance entirely and retry next tick, exactly the
            // same "leave state untouched, retry" contract already used for the
            // mapdrive historical backfill (init(), enumerate_mapdrive_history).
            auto res = yuzu::echo::collect_or_retain([] { return yuzu::echo::enumerate_services(); });
            auto current = std::move(res.current);
            if (!current) {
                spdlog::warn("ECHO: service snapshot incomplete ({}) -- retaining baseline",
                             res.skip_reason);
                if (skipped_sources)
                    skipped_sources->push_back("service");
                note_health("service", "capture_incomplete");
            }
            if (current) {
                const std::string svc_key{yuzu::echo::diff_state_key("service")}; // #538
                auto prev_json = db_->get_state(svc_key);
                auto previous = json_to_services(prev_json);

                auto typed = yuzu::echo::compute_service_events(previous, *current, ts, snap_id);
                // Events + baseline in ONE transaction (#1654).
                const std::string state_json = services_to_json(*current).dump();
                const bool ok = typed.empty()
                                    ? db_->set_state(svc_key, state_json)
                                    : db_->fold_service_events(
                                          typed, yuzu::echo::StateWrite{svc_key, state_json});
                if (!ok) {
                    const char* tok = typed.empty() ? "state_save_failed" : "insert_failed";
                    spdlog::error("ECHO: service {} — nothing persisted, next tick re-diffs", tok);
                    ctx.write_output(typed.empty() ? "error|service state_save_failed"
                                                   : "error|service insert failed");
                    note_health("service", tok);
                    return 1;
                }
                total_events += static_cast<int>(typed.size());
                note_health("service", "events_recorded");
            }
        } else {
            note_health("service", skip_token(service_state));
        }

        // User diff
        const auto user_state = yuzu::echo::source_enabled_state(*db_, "user");
        if (user_state.value_or(false)) {
            const std::string usr_key{yuzu::echo::diff_state_key("user")}; // #538
            auto current = yuzu::echo::enumerate_users();
            auto prev_json = db_->get_state(usr_key);
            auto previous = json_to_users(prev_json);

            auto typed = yuzu::echo::compute_user_events(previous, current, ts, snap_id);
            // Events + baseline in ONE transaction (#1654).
            const std::string state_json = users_to_json(current).dump();
            const bool ok = typed.empty()
                                ? db_->set_state(usr_key, state_json)
                                : db_->fold_user_events(
                                      typed, yuzu::echo::StateWrite{usr_key, state_json});
            if (!ok) {
                const char* tok = typed.empty() ? "state_save_failed" : "insert_failed";
                spdlog::error("ECHO: user {} — nothing persisted, next tick re-diffs", tok);
                ctx.write_output(typed.empty() ? "error|user state_save_failed"
                                               : "error|user insert failed");
                note_health("user", tok);
                return 1;
            }
            total_events += static_cast<int>(typed.size());
            note_health("user", "events_recorded");
        } else {
            note_health("user", skip_token(user_state));
        }

        // netconn: OS-logged connectivity transitions (ADR-0020). Incremental read
        // from the high-water mark; an EMPTY hwm means "never read" (fresh enable,
        // or the init backfill failed) and triggers the deep lookback — so an
        // operator who enables the source LATER still recovers the OS-retained
        // history. The hwm advances ONLY on success, so a failed tick re-reads the
        // same window; rows carry the EVENT's own ts. Non-fatal like the netqual leg.
        const auto netconn_state = yuzu::echo::source_enabled_state(*db_, "netconn");
        if (netconn_state.value_or(false)) {
            // Empty hwm (fresh enable / init backfill failed) -> deep read bounded
            // by the operator-configurable retroactive reach; a set hwm -> forward
            // incremental read [hwm, ts). nq_netconn_plan centralises this AND the
            // forward-only case: with netconn_lookback_seconds=0 and no hwm the
            // window is empty, so the plan reads nothing but STILL seeds the hwm
            // to ts — otherwise the leg would recompute from==ts every tick and
            // never advance (a late enable with lookback=0 would wedge). rows
            // carry the EVENT's own ts. Non-fatal like the netqual leg.
            const auto hwm_str = db_->get_config("netconn_backfill_hwm", "");
            bool have_hwm = !hwm_str.empty();
            int64_t hwm = 0;
            if (have_hwm) {
                try {
                    hwm = std::stoll(hwm_str);
                } catch (...) {
                    have_hwm = false; // corrupt hwm -> treat as fresh (deep read)
                }
            }
            const auto plan =
                yuzu::echo::nq_netconn_plan(have_hwm, hwm, netconn_lookback_seconds(*db_), ts);
            if (!plan.read) {
                // Empty/backward window (lookback 0 forward-only, or clock skew):
                // read nothing, but advance the hwm so forward reads begin.
                db_->set_config("netconn_backfill_hwm", std::to_string(plan.hwm));
                note_health("netconn", "baseline");
            } else {
                auto rows = yuzu::echo::backfill_netconn_events(plan.from, plan.to);
                for (auto& r : rows)
                    r.snapshot_id = snap_id;
                if (rows.empty()) {
                    // Nothing in the window (or channels missing) — still advance
                    // so the next tick doesn't re-scan the same empty window.
                    db_->set_config("netconn_backfill_hwm", std::to_string(plan.hwm));
                    note_health("netconn", "events_recorded");
                } else if (db_->fold_netconn_events(rows)) {
                    db_->set_config("netconn_backfill_hwm", std::to_string(plan.hwm));
                    total_events += static_cast<int>(rows.size());
                    note_health("netconn", "events_recorded");
                } else {
                    spdlog::error("ECHO: netconn insert failed this tick (skipped)");
                    note_health("netconn", "insert_failed");
                }
            }
        } else {
            note_health("netconn", skip_token(netconn_state));
        }

        // §3.8 — mapped-drive diff (both directions). NON-FATAL on
        // insert failure — the service/user legs above may have already
        // committed, so a failure here must not misreport the tick (do NOT `return
        // 1`); the diff baseline advances ONLY on insert success so a failed insert
        // retries the same deltas next tick. The one-time historical backfill is
        // separate (init, mapdrive_backfill_done) and does not touch this baseline.
        const auto mapdrive_state = yuzu::echo::source_enabled_state(*db_, "mapdrive");
        if (mapdrive_state.value_or(false)) {
            // enumerate_mapdrive() throws when its underlying LIVE capture
            // didn't genuinely complete -- WNet/NetSessionEnum on Windows,
            // /proc/mounts/smbstatus on Linux, or on macOS a getfsstat(2)
            // failure/over-cap snapshot (echo_mapdrive_collector.cpp, BR-002
            // round 2) -- same contract as enumerate_services() above.
            // (wevtutil/journalctl are used only by the SEPARATE one-time
            // enumerate_mapdrive_history() backfill, not this live path --
            // BR4-007, round 4: an earlier version of this comment named
            // them here and could mislead a reader auditing live
            // completeness into thinking the live WNet/procfs legs were
            // history-tool-guarded too.) Skip the whole tick's
            // diff/state-advance on a throw rather than diff a partial snapshot
            // against the last COMPLETE one.
            auto res = yuzu::echo::collect_or_retain([] { return yuzu::echo::enumerate_mapdrive(); });
            auto current = std::move(res.current);
            if (!current) {
                spdlog::warn("ECHO: mapdrive snapshot incomplete ({}) -- retaining baseline",
                             res.skip_reason);
                if (skipped_sources)
                    skipped_sources->push_back("mapdrive");
                note_health("mapdrive", "capture_incomplete");
            }
            if (current) {
                const std::string md_key{yuzu::echo::diff_state_key("mapdrive")}; // #538
                auto previous = json_to_mapdrive(db_->get_state(md_key));
                auto typed = yuzu::echo::compute_mapdrive_events(previous, *current, ts, snap_id);
                const std::string state_json = mapdrive_to_json(*current).dump();
                const bool ok = typed.empty()
                                    ? db_->set_state(md_key, state_json)
                                    : db_->fold_mapdrive_events(
                                          typed, yuzu::echo::StateWrite{md_key, state_json});
                if (ok) {
                    total_events += static_cast<int>(typed.size());
                    note_health("mapdrive", "events_recorded");
                } else {
                    const char* tok = typed.empty() ? "state_save_failed" : "insert_failed";
                    spdlog::error("ECHO: mapdrive {} this tick (nothing persisted)", tok);
                    note_health("mapdrive", tok);
                }
            }
        } else {
            note_health("mapdrive", skip_token(mapdrive_state));
        }

        // ── Cursor-model sources (echo_cursor.hpp: power, removable — wave 2) ──
        // Generic driver over every constructed cursor source -- empty this
        // wave (make_cursor_sources() returns {}), so this loop is a no-op
        // until the wave-2 integrator adds the two push_backs; nothing else
        // in echo_plugin.cpp needs to change when it does. Honours
        // `<name>_enabled` the same way every other source above does
        // (registry default via source_enabled -- power/removable default
        // TRUE per the Alex ruling, echo_schema_registry.cpp).
        for (auto& src : cursor_sources_) {
            const std::string src_name = src->name();
            const auto src_state = yuzu::echo::source_enabled_state(*db_, src_name);
            if (!src_state.value_or(false)) {
                note_health(src_name, skip_token(src_state));
                ctx.write_output(
                    std::format("echo|collect_{}|0|{}", src_name, skip_token(src_state)));
                continue;
            }
            auto cursor_read = db_->get_cursor(src_name);
            if (!cursor_read) {
                // The cursor could not be READ. That is a transient failure of
                // the store, not evidence about this source, so rule 1 applies:
                // retain the cursor exactly as last written and skip the tick.
                // Passing nullopt through would tell the source it had never
                // run, and it would re-baseline forward -- skipping everything
                // between the durable cursor and now, with no capture_gap.
                spdlog::warn("ECHO: {} cursor read failed ({}) -- retaining cursor, skipping tick",
                            src_name, cursor_read.error());
                note_health(src_name, yuzu::echo::kCollectStatusCaptureIncomplete);
                if (skipped_sources)
                    skipped_sources->push_back(src_name);
                // Say so on the collect stream too. do_collect_slow passes
                // nullptr for skipped_sources, so without this line the source
                // is simply ABSENT from the output -- indistinguishable from a
                // healthy source with nothing to report, while status still
                // shows it enabled with a frozen row count.
                ctx.write_output(std::format("echo|collect_{}|0|{}", src_name,
                                             yuzu::echo::kCollectStatusCaptureIncomplete));
                continue;
            }
            const auto& cursor = *cursor_read;
            try {
                // The source persists its own events+cursor atomically via
                // insert_power_events_and_cursor / insert_removable_events_
                // and_cursor (echo_db.hpp) from inside collect() -- this
                // driver only orchestrates the enable gate, cursor load, the
                // transient-failure skip (rule 1), and the status line.
                auto result = src->collect(*db_, cursor);
                total_events += static_cast<int>(result.events_emitted);
                std::string_view token;
                switch (result.outcome) {
                case yuzu::echo::CursorOutcome::Baseline:
                    token = yuzu::echo::kCollectStatusBaseline;
                    break;
                case yuzu::echo::CursorOutcome::Advanced:
                    token = yuzu::echo::kCollectStatusCursorAdvanced;
                    break;
                case yuzu::echo::CursorOutcome::CursorLost:
                    token = yuzu::echo::kCollectStatusCursorLost;
                    break;
                }
                // S1: a heartbeat an operator can alert on. `live_rows == 0` is
                // ambiguous -- a healthy quiet source and a wedged one look the
                // same -- so record WHEN this source last completed a tick.
                // Staleness relative to slow_interval is then an expressible
                // alert, which absence never was.
                note_health(src_name, token);
                db_->set_config(std::string(src_name) + "_last_collect_ts",
                                std::to_string(now_epoch_seconds()));
                ctx.write_output(std::format("echo|collect_{}|{}|{}", src_name,
                                             result.events_emitted, token));
            } catch (const yuzu::echo::IncompleteCaptureError& e) {
                // Rule 1: a transient read failure. The source must not have
                // persisted anything on this path, so the cursor stays
                // exactly as last written -- skip this tick's status/persist
                // entirely, same collect_or_retain skip-and-retain contract
                // as service/mapdrive above (echo_capture_status.hpp:187).
                spdlog::warn("ECHO: {} cursor collect incomplete ({}) -- retaining cursor",
                            src_name, e.what());
                note_health(src_name, yuzu::echo::kCollectStatusCaptureIncomplete);
                if (skipped_sources)
                    skipped_sources->push_back(src_name);
                // Say so on the collect stream too. do_collect_slow passes
                // nullptr for skipped_sources, so without this line the source
                // is simply ABSENT from the output -- indistinguishable from a
                // healthy source with nothing to report, while status still
                // shows it enabled with a frozen row count.
                ctx.write_output(std::format("echo|collect_{}|0|{}", src_name,
                                             yuzu::echo::kCollectStatusCaptureIncomplete));
            } catch (const std::exception& e) {
                // A source's events+cursor write opens a raw BEGIN IMMEDIATE; an unwind between
                // it and COMMIT would leave the shared connection mid-transaction and every
                // later write would refuse. noexcept, and a no-op in autocommit.
                db_->rollback_open_transaction();
                // ABI containment. The SDK's execute trampoline
                // (sdk/include/yuzu/plugin.hpp) is an extern "C" boundary with
                // no try/catch of its own, so ANY exception that escapes here
                // crosses it and std::terminate()s the whole agent -- and Echo
                // is in-process and default-on, so that is the agent, not just
                // this plugin. A collector is REQUIRED to map its failures to
                // IncompleteCaptureError or CursorLost (echo_cursor.hpp rules 1
                // and 2), but rule 2 names "the cursor JSON fails to parse" as
                // a first-class outcome and nlohmann::json throws by default,
                // so the single most likely consumer mistake is exactly the one
                // that would take the process down. Contain it and lose the
                // tick instead. Same reasoning as start()'s guard above and the
                // dns/netqual pre-collection stage's catch (...).
                spdlog::error("ECHO: {} cursor collect threw ({}) -- source skipped this tick; "
                              "a CursorSource must map failures to IncompleteCaptureError or "
                              "CursorOutcome::CursorLost, never throw",
                              src_name, e.what());
                note_health(src_name, yuzu::echo::kCollectStatusCaptureIncomplete);
                if (skipped_sources)
                    skipped_sources->push_back(src_name);
                // Say so on the collect stream too. do_collect_slow passes
                // nullptr for skipped_sources, so without this line the source
                // is simply ABSENT from the output -- indistinguishable from a
                // healthy source with nothing to report, while status still
                // shows it enabled with a frozen row count.
                ctx.write_output(std::format("echo|collect_{}|0|{}", src_name,
                                             yuzu::echo::kCollectStatusCaptureIncomplete));
            } catch (...) {
                db_->rollback_open_transaction(); // same reason as the std::exception arm above
                spdlog::error("ECHO: {} cursor collect threw a non-std exception -- source "
                              "skipped this tick", src_name);
                note_health(src_name, yuzu::echo::kCollectStatusCaptureIncomplete);
                if (skipped_sources)
                    skipped_sources->push_back(src_name);
                // Say so on the collect stream too. do_collect_slow passes
                // nullptr for skipped_sources, so without this line the source
                // is simply ABSENT from the output -- indistinguishable from a
                // healthy source with nothing to report, while status still
                // shows it enabled with a frozen row count.
                ctx.write_output(std::format("echo|collect_{}|0|{}", src_name,
                                             yuzu::echo::kCollectStatusCaptureIncomplete));
            }
        }

        // Legacy purge removed — retention is now handled by run_retention() in rollup action

        ctx.write_output(std::format("echo|collect_slow|{}|events_recorded", total_events));
        return 0;
    }

    // §3.8 bounded per-profile retry for the mapped-drive HISTORICAL backfill (related issue
    // #5291). The first pass (init()) can leave a profile unread; this retries each one
    // individually, kMapDriveBackfillRetryIntervalS apart, up to kMapDriveBackfillMaxAttempts
    // attempts in total (first pass included), until it resolves or is abandoned.
    //
    // Three phases, mirroring do_collect_software's enumeration-outside-the-lock split (gov
    // UP-6): PHASE A claims the slot under collect_mu_ (so a concurrent tick reads not-due and a
    // crash mid-retry costs a day, never an attempt); PHASE B enumerates UNLOCKED (hive I/O, via
    // with_user_hive/ScopedOfflineHiveLock, never runs under the shared lock); PHASE C commits
    // under collect_mu_ again, taken a second time, never nested. Called from two sites, both
    // BEFORE they take their own collect_mu_ lock_guard: init()'s already-done branch and
    // do_collect_slow below — never from collect_slow_impl or fleet_snapshot, so a snapshot
    // dispatch never carries hive I/O.
    void retry_pending_mapdrive_backfill() {
        constexpr int kMax = kMapDriveBackfillMaxAttempts;
        const auto now = now_epoch_seconds();

        // PHASE A: claim. A concurrent tick that reads `mapdrive_backfill_pending` after this
        // write sees `now` and skips (not due); a crash or throw before PHASE C's commit leaves
        // the SID list unchanged, so the cost of this claim going nowhere is one day, never an
        // acquisition attempt.
        PendingState state;
        std::string claimed_pending; // the exact value this claim persisted; re-checked in PHASE C
        {
            std::lock_guard lock(collect_mu_);
            if (!source_enabled(*db_, "mapdrive"))
                return;
            state = parse_pending_state(db_->get_config("mapdrive_backfill_pending", ""), kMax);
            if (state.profiles.empty() ||
                !retry_due(now, state.last_ts, kMapDriveBackfillRetryIntervalS))
                return;
            state.last_ts = now;
            claimed_pending = format_pending_state(state);
            if (!db_->set_config("mapdrive_backfill_pending", claimed_pending))
                return; // claim write failed; the next due tick tries again
        }

        // PHASE B: enumerate unlocked. retry_sids excludes any already-exhausted entry (review
        // P5); an empty result still falls through to PHASE C so a hand-edited/clamped exhausted
        // entry is abandoned even when nothing was walked.
        const auto sids = retry_sids(state, kMax);
        MapDriveHistory hist; // default {rows={}, profiles={}, complete=true} when sids is empty
        if (!sids.empty()) {
            try {
                hist = yuzu::echo::enumerate_mapdrive_history_for_profiles(sids);
            } catch (const std::exception& e) {
                spdlog::warn("ECHO: mapdrive backfill retry enumeration threw ({}) — will retry "
                             "at the next due tick",
                             e.what());
                return; // the claimed state stands unchanged; costs a day, not an attempt
            } catch (...) {
                spdlog::warn("ECHO: mapdrive backfill retry enumeration threw — will retry at "
                             "the next due tick");
                return;
            }
        }

        const auto snap = next_snapshot_id();
        std::vector<MapDriveEvent> typed;
        typed.reserve(hist.rows.size());
        for (auto& h : hist.rows) {
            MapDriveEvent ev;
            ev.ts = h.ts;
            ev.snapshot_id = snap;
            ev.action = "historical";
            ev.direction = h.entry.direction;
            ev.local_mount = h.entry.local_mount;
            ev.remote_path = h.entry.remote_path;
            ev.remote_host = h.entry.remote_host;
            ev.username = h.entry.username;
            ev.provider = h.entry.provider;
            ev.origin = "historical";
            typed.push_back(std::move(ev));
        }

        // PHASE C: commit. Re-check source_enabled: a plain disable that is STILL in effect here
        // raced the enumeration above, so this result is stale -- drop it and leave the claimed
        // state exactly as PHASE A left it (the next enable's first pass starts fresh).
        std::lock_guard lock(collect_mu_);
        if (!source_enabled(*db_, "mapdrive")) {
            spdlog::info("ECHO: mapdrive backfill retry result dropped — source disabled mid-retry");
            return;
        }
        // A disable+purge+re-enable fully inside PHASE B's unlocked window defeats the check
        // above: `mapdrive` reads enabled again by the time we get here, but do_purge_source
        // also clears this exact key (adversarial review: a stale commit otherwise resurrects
        // rows the purge just deleted). Nothing else writes `mapdrive_backfill_pending` except
        // this function's own two phases and the first pass's commit_first_pass, so a value that
        // no longer matches what PHASE A itself persisted means something else touched it in
        // between -- drop the stale result rather than overwrite that newer state.
        if (db_->get_config("mapdrive_backfill_pending", "") != claimed_pending) {
            spdlog::info("ECHO: mapdrive backfill retry result dropped — claim superseded "
                         "mid-retry (reconfigured or purged)");
            return;
        }
        // skip_known_historical=true: the NOT EXISTS insert makes a repeated attempt over the
        // same identity idempotent, so a retry that re-observes an already-recorded mapping never
        // duplicates it.
        if (!db_->fold_mapdrive_events(typed, std::nullopt, /*skip_known_historical=*/true)) {
            spdlog::warn("ECHO: mapdrive backfill retry insert failed — will retry at the next "
                         "due tick");
            return; // claimed state untouched; the retry is idempotent next time
        }
        // Runs even when sids was empty, so an exhausted-but-still-persisted entry (a clamped or
        // hand-edited attempt count) is abandoned here rather than retried forever.
        const auto r = apply_outcomes(state, hist.profiles, hist.complete, kMax);
        for (const auto& f : r.failed) {
            spdlog::info("Echo mapdrive backfill: profile {} attempt {}/{} {}", f.sid, f.attempts,
                         kMax, f.token);
        }
        for (const auto& a : r.abandoned) {
            spdlog::warn("Echo mapdrive backfill: profile {} abandoned after {} attempts ({})",
                         a.sid, kMax, a.token);
        }
        for (const auto& ret : r.retained) {
            spdlog::info("Echo mapdrive backfill: profile {} retained ({})", ret.sid, ret.cause);
        }
        for (const auto& sid : r.vanished) {
            spdlog::info("Echo mapdrive backfill: profile {} is no longer in the profile list; "
                         "dropped from the pending set",
                         sid);
        }
        if (!db_->set_config("mapdrive_backfill_pending", r.next.profiles.empty()
                                                               ? std::string{}
                                                               : format_pending_state(r.next)))
            spdlog::warn("ECHO: mapdrive backfill retry committed its rows but failed to persist "
                         "the updated pending state — the stale claim stands, costing one extra "
                         "retry interval (quality-engineer)");
    }

    int do_collect_slow(yuzu::CommandContext& ctx) {
        {
            yuzu::PluginContext pctx{plugin_ctx_};
            reconcile_db_health_publish(pctx);
        }
        // §3.8 bounded mapdrive-backfill retry (related issue #5291): above collect_mu_, same as
        // init()'s call site, so hive I/O never runs under the shared lock. Cheap when nothing is
        // due (phase A's own short lock-and-check) — see retry_pending_mapdrive_backfill's banner.
        retry_pending_mapdrive_backfill();
        std::lock_guard lock(collect_mu_);
        return collect_slow_impl(ctx);
    }

    // ── collect_software: installed-software inventory diff ───────────────────
    // Diffs the installed-software inventory and records install/remove/upgrade
    // events. Runs on the dedicated echo.software trigger (hourly default).
    //
    // Scope: MACHINE-WIDE inventory only (HKLM Uninstall). The source carries no
    // user identity — an event is the host's software, never a Windows profile's —
    // so there is no per-user / NTUSER.DAT / hive-mount path (#1620). On by
    // default; an operator can turn it off per host.
    //
    // The enumeration — which on Windows walks the registry — runs OUTSIDE
    // collect_mu_ so a slow registry pass cannot stall collect_fast/slow/
    // fleet_snapshot under that shared lock (gov UP-6, mirrors collect_perf). Only
    // the state read-diff-write is locked.
    //
    // Cold start: the FIRST run on a host (no prior "software" state) seeds the
    // baseline WITHOUT emitting events — an 'installed' event must mean "installed
    // now", not "already present when the agent started watching". This is a
    // deliberate divergence from the service/user cold-start burst and mirrors the
    // process-stream fallback baseline seed.
    int do_collect_software(yuzu::CommandContext& ctx) {
        const auto ts = now_epoch_seconds();
        // Heartbeat: record that the tick fired regardless of outcome, so an
        // operator reading echo.status can tell "healthy but quiet" from "trigger
        // never ran" / "every tick errors" (the agent has no /metrics endpoint).
        db_->set_config("software_last_run_ts", std::to_string(ts));

        const auto software_state = yuzu::echo::source_enabled_state(*db_, "software");
        if (!software_state.value_or(false)) {
            note_health("software", skip_token(software_state));
            ctx.write_output(std::format("echo|collect_software|0|{}", skip_token(software_state)));
            return 0;
        }

        std::lock_guard lock(software_collect_mu_); // serialises concurrent collect_software only
        // #538/#1620: the source_enabled gate above ran WITHOUT this lock; a
        // `echo.configure software_enabled=false` (do_configure) takes this SAME
        // lock to clear the baseline + flip the flag. Re-check under the lock so a
        // disable racing a mid-flight tick can neither insert events from the
        // paused window nor re-seed a baseline after the disable cleared it
        // (mirrors the perf/procperf post-lock re-check).
        const auto software_locked = yuzu::echo::source_enabled_state(*db_, "software");
        if (!software_locked.value_or(false)) {
            note_health("software", skip_token(software_locked));
            ctx.write_output(std::format("echo|collect_software|0|{}", skip_token(software_locked)));
            return 0;
        }

        auto prev_json = db_->get_state("software");

        // Enumerate THIS tick's machine-scope inventory (HKLM Uninstall, 64-bit +
        // WOW6432Node). The enumeration runs OUTSIDE collect_mu_ (we hold only
        // software_collect_mu_), so a slow registry pass cannot stall
        // collect_fast/slow/fleet_snapshot.
        std::vector<yuzu::echo::SoftwareInfo> enumerated;
        yuzu::echo::enumerate_machine_software(enumerated);

        // Pure classify + diff (cold-start seed / corrupt-skip / steady), unit-tested
        // off-Windows in test_echo_software.cpp.
        const auto snap_id = next_snapshot_id();
        auto result = yuzu::echo::software_collect_core(prev_json, std::move(enumerated), ts, snap_id);
        using Kind = yuzu::echo::SoftwareCollectResult::Kind;
        switch (result.kind) {
        case Kind::kCorruptSkip:
            spdlog::error("ECHO: software state is not a JSON array — skipping tick "
                          "(baseline preserved, not re-seeded)");
            note_health("software", "state_unreadable");
            ctx.write_output("echo|collect_software|0|state_unreadable");
            return 0;
        case Kind::kColdStartSeed:
            // Checked (#1654): on failure the next run re-detects the empty
            // baseline and re-seeds, so nothing is emitted against a stale one.
            if (!db_->set_state("software", result.new_state_json)) {
                spdlog::error("ECHO: software baseline seed failed");
                note_health("software", "state_save_failed");
                ctx.write_output("echo|collect_software|0|state_save_failed");
                return 1;
            }
            note_health("software", "baseline_seeded");
            ctx.write_output("echo|collect_software|0|baseline_seeded");
            return 0;
        case Kind::kSteady: {
            // Events + baseline in ONE transaction (#1654).
            const bool ok = result.events.empty()
                                ? db_->set_state("software", result.new_state_json)
                                : db_->fold_software_events(
                                      result.events,
                                      yuzu::echo::StateWrite{"software", result.new_state_json});
            if (!ok) {
                const char* tok = result.events.empty() ? "state_save_failed" : "insert_failed";
                spdlog::error("ECHO: software {} — nothing persisted, next run re-diffs", tok);
                ctx.write_output(result.events.empty() ? "error|software state_save_failed"
                                                       : "error|software insert failed");
                note_health("software", tok);
                return 1;
            }
            note_health("software", "events_recorded");
            ctx.write_output(
                std::format("echo|collect_software|{}|events_recorded", result.events.size()));
            return 0;
        }
        }
        return 0; // unreachable — switch is exhaustive over Kind
    }

    // ── status action ─────────────────────────────────────────────────────────

    int do_status(yuzu::CommandContext& ctx) {
        // ALWAYS emitted, and first. With a closed store every getter below
        // returns its default -- record_count 0, live_rows 0, and each source
        // reporting its DEFAULT enabled state -- which reads as a healthy, empty
        // database rather than a dead one. This action is the only operator- and
        // agentic-readable surface the agent has (no /metrics), so that
        // false-healthy report would be the whole signal (#2361 Gate 8).
        const bool storage_ok = db_->is_open();
        if (!storage_ok) {
            // `error|` FIRST, before storage_state. The server-side consumers gate
            // on `output.starts_with("error|")` (echo_tree_routes.cpp), and
            // poll_command treats any non-empty output as success -- so leading
            // with `storage_state|` made the dashboard fall through to the
            // capture-sources renderer, which parses only `config|` lines. With
            // none present it drew all ten sources blank: the one frame an
            // operator opens to ask "why is this device's data missing" rendered
            // identically to a healthy device (#2361 Gate 6, enterprise-readiness).
            //
            // Built by a free function in echo_status_format.hpp rather than
            // inline, because the ORDER above is a contract with the server and
            // EchoPlugin is TU-local -- nothing could assert it here. See that
            // header, and the test that pins `lines[0]` starting with `error|`.
            for (const auto& line :
                 yuzu::echo::format_storage_offline_lines(db_->query_engine_available()))
                ctx.write_output(line);
            return 1;
        }
        ctx.write_output("storage_state|ok");
        {
            // #1567: db_health|<ok|quarantined>|<epoch>. The epoch survives restarts
            // (echo_config); "quarantined" is true only for the open that did it.
            int64_t last_q = 0;
            try {
                last_q = std::stoll(db_->get_config("db_health_last_quarantine_epoch", "0"));
            } catch (...) {}
            const auto q = db_->quarantined_this_open();
            ctx.write_output(yuzu::echo::format_db_health_line(q.has_value(), q ? *q : last_q));
        }
        auto s = db_->stats();
        ctx.write_output(std::format("record_count|{}", s.record_count));
        ctx.write_output(std::format("oldest_timestamp|{}", s.oldest_timestamp));
        ctx.write_output(std::format("newest_timestamp|{}", s.newest_timestamp));
        ctx.write_output(std::format("db_size_bytes|{}", s.db_size_bytes));
        ctx.write_output(std::format("retention_days|{}", s.retention_days));
        // Byte budget (db_budget_bytes): db_size_bytes above is used pages + WAL, the figure the
        // budget is enforced against. budget_over_bytes is how far data + WAL sit above it right
        // now (measured here, not cached, so it is true before the first pass too); it can be
        // non-zero while an echo.sql read pins the WAL (the budget is hard for data pages, soft
        // for the WAL). Either figure is `unknown` when its input could not be read: an
        // unreadable setting or size is not "within budget".
        {
            const auto budget = yuzu::echo::budget_from_config(
                db_->try_get_config(std::string{yuzu::echo::kDbBudgetKey}));
            const auto sb = db_->storage_bytes();
            if (budget)
                ctx.write_output(std::format("db_budget_bytes|{}", *budget));
            else
                ctx.write_output("db_budget_bytes|unknown");
            if (budget && sb.ok) {
                ctx.write_output(std::format(
                    "budget_over_bytes|{}",
                    yuzu::echo::budget_over_bytes(sb.data_bytes(), sb.wal_bytes, *budget)));
            } else {
                ctx.write_output("budget_over_bytes|unknown");
            }
            ctx.write_output(std::format(
                "budget_evicted_raw_rows_total|{}",
                db_->get_config(std::string{yuzu::echo::kBudgetEvictedRawKey}, "0")));
            ctx.write_output(std::format(
                "budget_evicted_hourly_rows_total|{}",
                db_->get_config(std::string{yuzu::echo::kBudgetEvictedHourlyKey}, "0")));
            // incremental: auto_vacuum is on. deferred: a conversion VACUUM was wanted but the
            // volume lacked the free space (or it failed); retried at most daily. none: a file
            // created before auto_vacuum existed that has not needed the conversion yet.
            const bool deferred = deferred_marker() > 0;
            ctx.write_output(std::format("db_auto_vacuum|{}",
                                         sb.auto_vacuum == 2 ? "incremental"
                                                             : (deferred ? "deferred" : "none")));
            ctx.write_output(std::format("module_dedup_overflow_total|{}",
                                         module_overflows_.load(std::memory_order_relaxed)));
            ctx.write_output(std::format("tcp_closing_dedup_overflow_total|{}",
                                         tcp_closing_overflows_.load(std::memory_order_relaxed)));
        }

        // Per-source enable/disable state (issue #59) plus the operational
        // surface PR-A (#547) needs: paused_at, rows, oldest_ts. Default
        // = enabled, paused_at = 0, so operators that never call `configure`
        // see the steady-state behavior. rows / oldest_ts are queried from the source's
        // FINEST physical tier (the roll-up has no raw table to count): `<src>_hourly_r`, or
        // `usage_daily` for usage. A bucket is its hour's (day's) start, not an event's own time.
        // `<src>_live_rows` is the same figure under its old name for ONE release, so the server
        // readers (dashboard_routes, device_routes, echo_process_tree) keep working until they
        // move to `<src>_rows`; an empty table reports 0 / 0.
        for (const auto& src : yuzu::echo::capture_sources()) {
            std::string enabled_key = std::format("{}_enabled", src.name);
            // Default to the source's declared default so a fresh agent
            // reports the registry's value rather than a hard-coded one.
            auto stored = db_->get_config(enabled_key, src.default_enabled ? "true" : "false");
            // #560 — emit a strict tri-state (true/false/errored). do_configure
            // only ever persists "true"/"false"; any other stored value was
            // written outside the plugin (corruption, disk tampering, a
            // downgrade/upgrade) and is surfaced as the explicit "errored"
            // sentinel so the dashboard renders a value-error badge instead of
            // silently omitting the source. Never coerced/guessed.
            auto enabled_val = yuzu::echo::canonical_source_enabled(stored);
            ctx.write_output(std::format("config|{}|{}", enabled_key, enabled_val));

            std::string paused_at_key = std::format("{}_paused_at", src.name);
            auto paused_at_val = db_->get_config(paused_at_key, "0");
            ctx.write_output(std::format("config|{}|{}", paused_at_key, paused_at_val));

            // The source's finest physical tier and its bucket column.
            std::string tier_table;
            std::string_view bucket_col = "hour_ts";
            if (src.name == "usage") {
                tier_table = "usage_daily";
                bucket_col = "day_ts";
            } else if (const auto* fold = yuzu::echo::fold_source(src.name); fold && !fold->tiers.empty()) {
                tier_table = yuzu::echo::physical_table_name(src.name, fold->tiers.front());
                bucket_col = yuzu::echo::ts_column_for_suffix(fold->tiers.front());
            }
            int64_t rows = 0;
            int64_t oldest_ts = 0;
            if (!tier_table.empty()) {
                auto count_q =
                    db_->execute_query(std::format("SELECT COUNT(*), IFNULL(MIN({}), 0) FROM {}",
                                                   bucket_col, tier_table),
                                       /*max_rows=*/1);
                if (count_q.has_value() && !count_q->rows.empty() && count_q->rows[0].size() == 2) {
                    try {
                        rows = std::stoll(count_q->rows[0][0]);
                        oldest_ts = std::stoll(count_q->rows[0][1]);
                    } catch (...) {}
                }
            }
            ctx.write_output(std::format("config|{}_rows|{}", src.name, rows));
            ctx.write_output(std::format("config|{}_live_rows|{}", src.name, rows)); // one-release alias
            ctx.write_output(std::format("config|{}_oldest_ts|{}", src.name, oldest_ts));
            if (src.name == "netqual") {
                // The per-boot baseline is a plain table beside the roll-up tiers.
                auto boot_q = db_->execute_query("SELECT COUNT(*) FROM netqual_boot", /*max_rows=*/1);
                int64_t boot_rows = 0;
                if (boot_q.has_value() && !boot_q->rows.empty()) {
                    try {
                        boot_rows = std::stoll(boot_q->rows[0][0]);
                    } catch (...) {}
                }
                ctx.write_output(std::format("config|netqual_boot_rows|{}", boot_rows));
            }
        }
        // Retention clock-guard declines, per warehouse table (#2361). The agent
        // has no /metrics endpoint, so this action is the ONLY fleet-readable
        // signal that an endpoint's clock moved in a way that would have wiped
        // its forensic window - a `spdlog::warn` on an unattended endpoint is not
        // an operator surface. Only tables with a non-zero count are emitted, so
        // a healthy fleet pays two lines; both totals are always present.
        // Per-table state is in-memory and resets on agent restart, deliberately,
        // since a reboot re-declines anyway.
        //
        // Reads the guard's OWN mutex (inside format_retention_guard_lines), NOT
        // rollup_mu_. Taking rollup_mu_ here would make the diagnostic an
        // operator runs WHEN Echo IS MISBEHAVING block for a full rollup pass.
        for (const auto& line : yuzu::echo::format_retention_guard_lines(retention_guard_))
            ctx.write_output(line);

        // Usage-fold health (run_usage_fold, echo_usage.cpp) — the derived
        // process-pairing fold behind the app_usage plugin has no channel of
        // its own out of echo.db: it is not a CursorSource and has no
        // collector, so unlike every capture source above it was previously
        // readable ONLY by the (not yet landed) single-target Forensics-
        // gated `app_usage` plugin's own `summary` action. Emitted
        // UNCONDITIONALLY, same key-always-present NFR-visibility contract
        // as process/module/nstat above (no agent /metrics endpoint; `echo
        // status` is the operator/agentic surface). `usage_lifecycle_state`
        // is the one status line worth reading FIRST: "collecting" is the
        // only state under which any of the counters below are currently
        // advancing.
        {
            const char* lifecycle = "disabled";
            switch (yuzu::echo::usage::usage_lifecycle_state(*db_)) {
                case yuzu::echo::usage::LifecycleState::Disabled: lifecycle = "disabled"; break;
                case yuzu::echo::usage::LifecycleState::PendingBaseline:
                    lifecycle = "baseline_pending"; break;
                case yuzu::echo::usage::LifecycleState::Active: lifecycle = "collecting"; break;
            }
            ctx.write_output(std::format("config|usage_lifecycle_state|{}", lifecycle));
        }
        ctx.write_output(
            std::format("config|usage_gap_count|{}", db_->get_config("usage_gap_count", "0")));
        ctx.write_output(std::format("config|usage_gap_lost_events|{}",
                                     db_->get_config("usage_gap_lost_events", "0")));
        ctx.write_output(
            std::format("config|usage_gap_last_ts|{}", db_->get_config("usage_gap_last_ts", "-")));
        ctx.write_output(std::format("config|usage_expiry_declined_count|{}",
                                     db_->get_config("usage_expiry_declined_count", "0")));
        ctx.write_output(std::format("config|usage_coverage_since|{}",
                                     db_->get_config("usage_coverage_since", "-")));
        ctx.write_output(
            std::format("config|usage_lag_events|{}", db_->get_config("usage_lag_events", "0")));

        // Currently-configured network capture method (defaults to "polling").
        auto net_method = db_->get_config("network_capture_method", "polling");
        ctx.write_output(std::format("config|network_capture_method|{}", net_method));

        // Software source pacing + heartbeat. software_last_run_ts is the wall-clock
        // of the last collect_software tick (0 if it has never run) — the operator's
        // signal that the hourly trigger is alive even on a host with no software
        // changes (where software_live_rows stays 0).
        ctx.write_output(std::format("config|software_interval_seconds|{}",
                                     db_->get_config("software_interval_seconds", "3600")));
        ctx.write_output(std::format("config|software_last_run_ts|{}",
                                     db_->get_config("software_last_run_ts", "0")));

        // Mechanism actually in force. Only polling is wired today regardless of
        // the configured method (kPlanned methods like etw / endpoint_security are
        // accepted for pre-staging but not collected), so status can never
        // misrepresent the active capture mechanism to a forensic analyst (#1528).
        ctx.write_output(std::format("config|network_capture_method_effective|{}",
                                     yuzu::echo::effective_network_capture_method(net_method)));

        // Process stream health. capture_method reflects the LIVE path: the
        // stream's method_name() ("etw" on Windows, "endpoint_security" on macOS)
        // while the stream runs, "polling" if it never started or self-healed to
        // the poll after a session death. dropped is the cumulative ring-overflow
        // count (NFR visibility — there is no agent /metrics endpoint; this action
        // is the operator/agentic surface).
        ctx.write_output(std::format("config|process_capture_method|{}",
                                     (stream_active_ && proc_stream_) ? proc_stream_->method_name()
                                                                      : "polling"));
        // dropped() reads the ring's own atomic (independent of the session
        // lifecycle) so it is safe without collect_mu_. Emit unconditionally — 0 on
        // a poll-only platform (null proc_stream_) — so the key is always present and
        // agentic consumers can read it without a presence check.
        //
        // process_stream_dropped is the USERSPACE ring-overflow count (events the
        // drain tick could not keep up with). process_stream_kernel_dropped is the
        // distinct kernel/provider-side drop count (Endpoint Security seq_num gaps;
        // 0 on ETW, which exposes no per-message sequence to inspect here).
        ctx.write_output(std::format("config|process_stream_dropped|{}",
                                     proc_stream_ ? proc_stream_->dropped() : 0));
        ctx.write_output(std::format("config|process_stream_kernel_dropped|{}",
                                     proc_stream_ ? proc_stream_->kernel_dropped() : 0));

        // M2 module-stream health — emitted UNCONDITIONALLY (same contract as the
        // process keys) so agentic consumers read by key presence without a
        // presence check. "none" when there is no live session: off-Windows, or
        // when module_enabled was false at start so the session never started.
        ctx.write_output(std::format(
            "config|module_capture_method|{}",
            (module_stream_active_ && module_stream_) ? module_stream_->method_name() : "none"));
        ctx.write_output(std::format("config|module_stream_dropped|{}",
                                     module_stream_ ? module_stream_->dropped() : 0));

        // nstat (macOS tcp lifecycle) stream health — emitted UNCONDITIONALLY,
        // same key-always-present NFR-visibility contract as the process/module
        // streams above (there is no agent /metrics endpoint; echo.status is the
        // operator/agentic surface, so ring-overflow / kernel-desync / flow-table
        // growth must never be silent). All 0/false/"none" off-macOS or when no
        // client. nstat_flow_table_size + nstat_flow_reaped are the observable
        // signals of the bounded kernel-flow table (a lost SRC_REMOVED shows up
        // as reaped, never as unbounded growth).
        ctx.write_output(std::format("config|nstat_capture_method|{}",
                                     nstat_client_ ? nstat_client_->method_name() : "none"));
        ctx.write_output(std::format("config|nstat_stream_dropped|{}",
                                     nstat_client_ ? nstat_client_->dropped() : 0));
        ctx.write_output(std::format("config|nstat_stream_kernel_dropped|{}",
                                     nstat_client_ ? nstat_client_->kernel_dropped() : 0));
        ctx.write_output(std::format("config|nstat_flow_table_size|{}",
                                     nstat_client_ ? nstat_client_->flow_table_size() : 0));
        ctx.write_output(std::format("config|nstat_flow_reaped|{}",
                                     nstat_client_ ? nstat_client_->flow_reaped() : 0));
        ctx.write_output(std::format("config|nstat_stalled|{}",
                                     (nstat_client_ && nstat_client_->stalled()) ? "true" : "false"));
        ctx.write_output(
            std::format("config|nstat_layout_mismatch|{}",
                        (nstat_client_ && nstat_client_->layout_mismatch()) ? "true" : "false"));

        // registry source (PR11.8) health — emitted UNCONDITIONALLY (key-always-present
        // contract) from the values the source wrote on its last committed tick. The
        // defaults read as "not running": capture_method none, every counter 0.
        {
            static constexpr std::pair<std::string_view, std::string_view> kRegistryKeys[] = {
                {"registry_capture_method", "none"},   {"registry_watch_roots", "0"},
                {"registry_watch_roots_unarmed", "0"}, {"registry_roots_unreadable", "0"},
                {"registry_roots_capped", "0"},        {"registry_etw_events", "0"},
                {"registry_etw_dropped", "0"},         {"registry_etw_lost", "0"},
                {"registry_attr_attributed", "0"},     {"registry_attr_ambiguous", "0"},
                {"registry_attr_none", "0"},
            };
            for (const auto& [key, def] : kRegistryKeys)
                ctx.write_output(std::format("config|{}|{}", key,
                                             db_->get_config(std::string(key), std::string(def))));
        }

        // netqual capture method (ADR-0020) — the method actually in effect:
        // "inetdiag" (Linux), "estats" (Windows once the elevation gate latches
        // active), "estats_pending" (Windows, gate not yet tested — or netqual
        // off), "nstat" (macOS when the kctl client is live and system-wide),
        // "none" (Windows after the ACCESS_DENIED latch; macOS unprivileged,
        // layout-mismatch, or client down). Emitted
        // UNCONDITIONALLY (key-always-present contract, same as the process/
        // module keys above) so an operator can tell "netqual is on but the
        // agent can't collect" apart from "netqual is off".
        ctx.write_output(std::format("config|netqual_capture_method|{}",
                                     yuzu::echo::netqual_effective_capture_method()));

        // §3.8 mapdrive — the capture mechanism is fixed per-OS (no runtime/health-
        // dependent path like process/module), so this reports the platform method
        // for parity with the other *_capture_method keys; the full per-OS matrix is
        // in the `compatibility` action. macOS reports "getfsstat" (outbound-live-only,
        // constrained — see the mapdrive os_support row).
#if defined(_WIN32)
        ctx.write_output("config|mapdrive_capture_method|wnet");
#elif defined(__linux__)
        ctx.write_output("config|mapdrive_capture_method|procfs");
#else
        ctx.write_output("config|mapdrive_capture_method|getfsstat");
#endif

        // #1846(4): registry-derived perf capture method for the running OS
        // ("none" when the OS has no perf collector), and (3) the process count of
        // the last valid per-process counter snapshot.
        {
            const auto os = yuzu::echo::current_platform_os();
            const auto st = yuzu::echo::os_support_status("perf", os);
            const bool supported = st == yuzu::echo::OsSupportStatus::kSupported ||
                                   st == yuzu::echo::OsSupportStatus::kSupportedConstrained;
            ctx.write_output(std::format("config|perf_capture_method|{}",
                                         supported ? yuzu::echo::supported_capture_method("perf", os)
                                                   : std::string_view{"none"}));
        }
        ctx.write_output(std::format("config|procperf_procs_seen|{}",
                                     procperf_procs_seen_.load(std::memory_order_relaxed)));

        // #1846(2): per-source health ledger (process memory only; an agent
        // restart resets every source to never_ran/0).
        {
            std::lock_guard hlock(health_mu_);
            for (const auto& line :
                 yuzu::echo::format_source_health_lines(health_, yuzu::echo::capture_sources()))
                ctx.write_output(line);
        }
        return 0;
    }

    // ── compatibility action (issue #59) ──────────────────────────────────────
    //
    // Emits one row per (source, OS) describing how the source captures data
    // on that platform and any known constraint. Pipe-delimited so the
    // existing dashboard renderer can show it as a table without a JSON
    // codec change.
    // #2204: derived entirely from yuzu::echo::support_level_name(), the one
    // place that maps the unified support-level enum to its operator-facing
    // name — this function no longer keeps its own copy of that mapping.
    int do_compatibility(yuzu::CommandContext& ctx) {
        ctx.write_output("header|source|os|status|capture_method|notes");
        for (const auto& src : yuzu::echo::capture_sources()) {
            for (const auto& os : src.os_support) {
                std::string_view status_str = yuzu::echo::support_level_name(os.status);
                ctx.write_output(std::format("row|{}|{}|{}|{}|{}", src.name, os.os, status_str,
                                             os.capture_method, os.notes));
            }
        }
        return 0;
    }

    // ── query action ──────────────────────────────────────────────────────────

    int do_query(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto from_str = params.get("from", "0");
        auto to_str = params.get("to");
        auto type_filter = std::string{params.get("type")};
        auto limit_str = params.get("limit", "1000");

        int64_t from = 0;
        int64_t to = now_epoch_seconds();
        int limit = 1000;

        try {
            from = std::stoll(std::string{from_str});
        } catch (...) {
            ctx.write_output("error|invalid 'from' parameter (must be epoch seconds)");
            return 1;
        }
        if (!to_str.empty()) {
            try {
                to = std::stoll(std::string{to_str});
            } catch (...) {
                ctx.write_output("error|invalid 'to' parameter (must be epoch seconds)");
                return 1;
            }
        }
        try {
            limit = std::stoi(std::string{limit_str});
        } catch (...) {}

        if (from < 0 || to < 0) {
            ctx.write_output("error|timestamps must be non-negative");
            return 1;
        }
        if (from > to) {
            ctx.write_output("error|'from' must be <= 'to'");
            return 1;
        }
        if (limit <= 0 || limit > 10000)
            limit = 1000;

        // Query the hourly roll-up views. The raw capture rows these queries once read are not
        // kept: every row is an hour BUCKET, reported as ts = the bucket's start, action =
        // 'bucket' and snapshot_id = 0, so the columns keep their old shape. A bucket is in range
        // when it STARTS at or before `to` and ends after `from`.
        auto from_s = std::to_string(from - from % 3600);
        auto to_s = std::to_string(to);
        auto lim_s = std::to_string(limit);
        std::string where = " WHERE hour_ts >= " + from_s + " AND hour_ts <= " + to_s;
        std::string tail = " ORDER BY ts ASC LIMIT " + lim_s;
        const auto select = [&](std::string_view type, std::string_view view,
                                std::string_view detail) {
            return std::format("SELECT hour_ts AS ts, '{}' AS event_type, 'bucket' AS action, "
                               "0 AS snapshot_id, {} AS detail_json FROM {}",
                               type, detail, view);
        };

        std::string sql;
        if (type_filter == "process") {
            sql = select("process", "process_hourly",
                         "(name || ' start=' || start_count || ' stop=' || stop_count)") +
                  where + tail;
        } else if (type_filter == "network") {
            sql = select("network", "tcp_hourly",
                         "(proto || ' ' || remote_addr || ':' || remote_port)") +
                  where + tail;
        } else if (type_filter == "service") {
            sql = select("service", "service_hourly", "name") + where + tail;
        } else if (type_filter == "user") {
            sql = select("user", "user_hourly", "(user || '@' || domain)") + where + tail;
        } else if (type_filter == "software") {
            sql = select("software", "software_hourly", "name") + where + tail;
        } else if (type_filter == "arp") {
            // ADR-0015. detail_json carries a human summary (ip @ mac [iface]); the
            // full row is available via echo.sql over $ARP_Hourly.
            sql = select("arp", "arp_hourly",
                         "(ip_address || ' @ ' || mac_address || ' [' || interface || ']')") +
                  where + tail;
        } else if (type_filter == "dns") {
            sql = select("dns", "dns_hourly", "(name || ' ' || record_type || ' ' || data)") +
                  where + tail;
        } else if (type_filter == "mapdrive") {
            // §3.8. detail_json is a human summary (direction mount remote [host]); the full
            // row (incl. the historical count) is via echo.sql over $MapDrive_Hourly.
            sql = select("mapdrive", "mapdrive_hourly",
                         "(direction || ' ' || local_mount || ' ' || remote_path || ' [' || "
                         "remote_host || ']')") +
                  where + tail;
        } else {
            // No-filter union stays the core event timeline. arp/dns/mapdrive are
            // device-state sources — reachable only via an explicit
            // type filter above or echo.sql, never the default feed.
            sql = "SELECT * FROM (" + select("process", "process_hourly", "''") + where +
                  " UNION ALL " + select("network", "tcp_hourly", "''") + where +
                  " UNION ALL " + select("service", "service_hourly", "''") + where +
                  " UNION ALL " + select("user", "user_hourly", "''") + where +
                  " UNION ALL " + select("software", "software_hourly", "''") + where + ")" + tail;
        }

        auto query_result = db_->execute_query(sql);
        if (!query_result) {
            ctx.write_output(std::format("error|{}", query_result.error()));
            return 1;
        }
        for (const auto& row : query_result->rows) {
            std::string line;
            for (size_t i = 0; i < row.size(); ++i) {
                if (i > 0)
                    line += '|';
                line += row[i];
            }
            ctx.write_output(line);
        }
        ctx.write_output(std::format("total|{}", query_result->rows.size()));
        return 0;
    }

    // ── export action (JSON array output) ─────────────────────────────────────

    int do_export(yuzu::CommandContext& ctx, yuzu::Params params) {
        // Export delegates to the sql action with a JSON wrapper
        auto type_filter = std::string{params.get("type")};
        auto from_str = params.get("from", "0");
        auto to_str = params.get("to");
        auto limit_str = params.get("limit", "1000");

        int64_t from = 0;
        int64_t to = now_epoch_seconds();
        int limit = 1000;

        try {
            from = std::stoll(std::string{from_str});
        } catch (...) {}
        if (!to_str.empty()) {
            try {
                to = std::stoll(std::string{to_str});
            } catch (...) {}
        }
        try {
            limit = std::stoi(std::string{limit_str});
        } catch (...) {}
        if (limit <= 0 || limit > 10000)
            limit = 1000;

        // Pick the right hourly view (HP-5: handle empty filter and unknown types). Rows are hour
        // BUCKETS (ts = the bucket's start, action = 'bucket', snapshot_id = 0): the raw capture
        // rows this once exported are not kept.
        //
        // For the "no filter" case we have to UNION ALL five views that do
        // not share a column count or schema. Project each branch to a
        // uniform shape (source, ts, snapshot_id, action, summary) so the
        // UNION is well-typed and the JSON envelope stays consistent for
        // SIEM ingest. Callers that want per-table fields should pass a
        // type filter.
        const int64_t from_hour = from - from % 3600;
        std::string sql;
        if (type_filter.empty()) {
            sql = std::format("SELECT * FROM ("
                              "SELECT 'process' AS source, hour_ts AS ts, 0 AS snapshot_id, "
                              "       'bucket' AS action, "
                              "       (name || ' start=' || start_count || ' stop=' || stop_count) "
                              "       AS summary "
                              "  FROM process_hourly WHERE hour_ts >= {0} AND hour_ts <= {1} "
                              "UNION ALL "
                              "SELECT 'network', hour_ts, 0, 'bucket', "
                              "       (proto || ' ' || remote_addr || ':' || remote_port) "
                              "  FROM tcp_hourly WHERE hour_ts >= {0} AND hour_ts <= {1} "
                              "UNION ALL "
                              "SELECT 'service', hour_ts, 0, 'bucket', "
                              "       (name || ' (' || last_status || ')') "
                              "  FROM service_hourly WHERE hour_ts >= {0} AND hour_ts <= {1} "
                              "UNION ALL "
                              "SELECT 'user', hour_ts, 0, 'bucket', (user || '@' || domain) "
                              "  FROM user_hourly WHERE hour_ts >= {0} AND hour_ts <= {1} "
                              "UNION ALL "
                              "SELECT 'software', hour_ts, 0, 'bucket', (name || ' ' || version) "
                              "  FROM software_hourly WHERE hour_ts >= {0} AND hour_ts <= {1}"
                              ") ORDER BY ts ASC LIMIT {2}",
                              from_hour, to, limit);
        } else {
            std::string view;
            if (type_filter == "process")
                view = "process_hourly";
            else if (type_filter == "network")
                view = "tcp_hourly";
            else if (type_filter == "service")
                view = "service_hourly";
            else if (type_filter == "user")
                view = "user_hourly";
            else if (type_filter == "software")
                view = "software_hourly";
            else if (type_filter == "arp") // ADR-0015
                view = "arp_hourly";
            else if (type_filter == "dns") // ADR-0015
                view = "dns_hourly";
            else if (type_filter == "mapdrive") // §3.8
                view = "mapdrive_hourly";
            else {
                ctx.write_output(std::format("error|unknown type filter: {}", type_filter));
                return 1;
            }
            sql = std::format("SELECT hour_ts AS ts, 0 AS snapshot_id, 'bucket' AS action, v.* "
                              "FROM {} v WHERE hour_ts >= {} AND hour_ts <= {} "
                              "ORDER BY hour_ts ASC LIMIT {}",
                              view, from_hour, to, limit);
        }

        auto query_result = db_->execute_query(sql);
        if (!query_result) {
            ctx.write_output(std::format("error|{}", query_result.error()));
            return 1;
        }

        json arr = json::array();
        for (const auto& row : query_result->rows) {
            json obj;
            for (size_t i = 0; i < query_result->columns.size() && i < row.size(); ++i) {
                obj[query_result->columns[i]] = row[i];
            }
            arr.push_back(std::move(obj));
        }

        ctx.write_output(arr.dump());
        return 0;
    }

    // ── snapshot action (force immediate full collection) ─────────────────────

    int do_snapshot(yuzu::CommandContext& ctx) {
        // Pre-enumerate arp/dns/netqual lock-free (same rationale as do_collect_fast).
        const bool arp_on = source_enabled(*db_, "arp");
        const bool dns_on = source_enabled(*db_, "dns");
        const bool netqual_on = source_enabled(*db_, "netqual");
        // round 3 (B3-002): names of every enabled source classified
        // incomplete this pass (arp/service/mapdrive) -- accumulated across
        // the arp precollection below AND collect_slow_impl's service/
        // mapdrive legs (collect_fast_impl's arp leg never adds to this: arp
        // is always precollected here, so its own internal else-branch is
        // unreachable for this caller). snapshot_result_line
        // (echo_capture_status.hpp) turns this into the action's honest
        // response -- the whole point being that a forced `snapshot` must
        // never report "complete" while it silently skipped a source and
        // left its baseline stale, which is exactly what happened before
        // this round: the collect_*_impl return values were ignored and the
        // action wrote "echo|snapshot|complete" unconditionally.
        //
        // round 4 (BR4-001): that fix covered only the collect_or_retain /
        // IncompleteCaptureError skip path (arp/service/mapdrive). An
        // ordinary persistence failure inside collect_fast_impl,
        // collect_slow_impl, or do_collect_software (each already writes
        // its own "error|... insert failed" line and returns 1) was still
        // invisible here -- the three calls below were bare expression
        // statements with their return values discarded, so the action
        // still finished "echo|snapshot|complete" / rc 0 despite a failed
        // write. fast_rc/slow_rc/software_rc capture those return codes;
        // snapshot_phase_outcome (echo_capture_status.hpp) is the pure
        // function deciding which phase names to add here and the action's
        // own exit code, unit-tested directly since EchoPlugin is
        // translation-unit-local and cannot be exercised from
        // tests/unit/*.cpp.
        std::vector<std::string> skipped_sources;
        // arp: same optional-through-collect_or_retain precollection as
        // do_collect_fast, and for the identical reason (BR-001, round 2) --
        // see that function's comment.
        std::optional<std::vector<yuzu::echo::ArpEntry>> arp_pre;
        if (arp_on) {
            auto res = yuzu::echo::collect_or_retain([] { return yuzu::echo::enumerate_arp(); });
            arp_pre = std::move(res.current);
            if (!arp_pre) {
                spdlog::warn("ECHO: arp snapshot incomplete ({}) -- retaining baseline",
                             res.skip_reason);
                skipped_sources.push_back("arp");
            }
        }
        std::vector<yuzu::echo::DnsEntry> dns_pre;
        std::vector<yuzu::echo::TcpQualitySample> netqual_pre;
        // Belt-and-suspenders (SRE): the dns collector calls an undocumented dnsapi
        // export over an opaque heap list; isolate any throw so a bad list degrades
        // this tick to empty rather than crossing the plugin ABI boundary.
        try {
            if (dns_on)
                dns_pre = yuzu::echo::enumerate_dns();
            if (netqual_on)
                netqual_pre = yuzu::echo::collect_tcp_quality();
        } catch (...) {
            spdlog::error("ECHO: dns/netqual enumeration threw; skipping this tick");
            dns_pre.clear();
            netqual_pre.clear();
        }
        int fast_rc = 0;
        int slow_rc = 0;
        {
            std::lock_guard lock(collect_mu_);
            fast_rc = collect_fast_impl(ctx, arp_on ? &arp_pre : nullptr,
                                        dns_on ? &dns_pre : nullptr,
                                        netqual_on ? &netqual_pre : nullptr, &skipped_sources);
            slow_rc = collect_slow_impl(ctx, &skipped_sources);
        }
        // Software lives on its own dedicated software_collect_mu_ (NOT collect_mu_),
        // so collect it as a SEPARATE step after the collect_mu_ scope closes —
        // preserving the collect_mu_ ≺ software_collect_mu_ lock order. It self-gates
        // on source_enabled("software"), so a disabled source is a no-op. The manual
        // promises `snapshot` collects all enabled capture sources (#1620).
        const int software_rc = do_collect_software(ctx);
        // BR4-001 (round 4): fold each phase's own return code into the
        // honesty response -- see the comment above skipped_sources.
        //
        // round 5 (adversarial-review finding): by this point skipped_sources
        // already holds every arp/service/mapdrive name collect_fast_impl /
        // collect_slow_impl pushed for a collect_or_retain skip (each phase
        // rc above stays 0 for that kind of skip -- it's not a persistence
        // failure). Fold that into the honesty decision too, so a snapshot
        // that silently retained a source's stale baseline returns nonzero
        // at the action level, not just in the "echo|snapshot|partial|..."
        // text line a generic/MCP/automation consumer may not parse.
        // An unreadable enable flag skips its source's leg through skip_token() and never raises
        // IncompleteCaptureError, so no leg above names it: a snapshot that skipped it is partial.
        for (const auto& src : yuzu::echo::capture_sources())
            if (!yuzu::echo::source_enabled_state(*db_, src.name))
                skipped_sources.emplace_back(src.name);
        const bool had_earlier_skips = !skipped_sources.empty();
        const auto phase_outcome =
            yuzu::echo::snapshot_phase_outcome(fast_rc, slow_rc, software_rc, had_earlier_skips);
        skipped_sources.insert(skipped_sources.end(), phase_outcome.failed_phases.begin(),
                               phase_outcome.failed_phases.end());
        if (!skipped_sources.empty()) {
            // Structured ABI4 result seam (runner_status.hpp's pattern) --
            // a partial/skipped-sources snapshot is CONSTRAINED/PARTIAL for
            // any consumer reading the typed status, not only the text line.
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "echo:snapshot_skipped_sources");
        }
        ctx.write_output(yuzu::echo::snapshot_result_line(skipped_sources));
        return phase_outcome.return_code;
    }

    // ── fleet_snapshot action (single JSON document for fleet-topology viz) ──
    //
    // Re-enumerates processes + connections + local IPs on demand and emits a
    // single JSON line conforming to fleet_snapshot.v1. Used by the server-side
    // FleetTopologyStore on cache miss to assemble the /viz/fleet topology.
    //
    // Locking: takes collect_mu_ to serialise OS-resource enumeration with the
    // collect_fast / collect_slow paths. The action does not write to echo.db,
    // but enumerate_processes() / enumerate_connections() open many fds and a
    // concurrent collect_fast cycle would double the OS pressure (governance
    // round 1, plugin-B2 + UP-1).
    //
    // Source gating: if the operator paused process or tcp capture (forensic
    // hold, PII compliance regime), fleet_snapshot must respect that decision
    // -- otherwise a paused source silently leaks data through the new path
    // (governance round 1, plugin-B1 + compliance-F1). When a source is
    // disabled, the corresponding list is emitted empty with truncated_*=false
    // and the snapshot carries `source_paused.process` / `.tcp` markers.
    //
    // Redaction: load_redaction_patterns now unions kDefaultRedactionPatterns
    // (via ensure_redaction_defaults) internally, so an empty/all-dropped config
    // does NOT disable redaction on ANY collect path — this snapshot included
    // (governance round 1, sec-M1 + compliance-F3; #1532 fail-closed).
    int do_fleet_snapshot(yuzu::CommandContext& ctx) {
        std::lock_guard lock(collect_mu_);
        auto ts = now_epoch_seconds();
        auto hostname = yuzu::agent::get_hostname();
        auto local_ips = yuzu::agent::enumerate_local_ips();

        const bool process_on = source_enabled(*db_, "process");
        const bool tcp_on = source_enabled(*db_, "tcp");

        std::vector<yuzu::agent::ProcessInfo> processes;
        if (process_on) {
            processes = yuzu::agent::enumerate_processes();
        }
        std::vector<yuzu::echo::NetConnection> connections;
        if (tcp_on) {
            auto live = yuzu::echo::enumerate_connections();
            // The snapshot is the connections ESTABLISHED right now. It once widened this to
            // "established within a rolling window" from the raw tcp rows (each 5-tuple, last seen);
            // the roll-up keeps hourly counts per remote and process, not per socket, so there is
            // nothing to widen it with and `fleet_snapshot_window_seconds` no longer has an effect.
            connections = std::move(live);
        }

        // Redaction defaults are now unioned inside load_redaction_patterns (so
        // every collect path — collect_fast, procperf, and this snapshot — is
        // uniformly fail-closed; no stored value can disable *password*/*secret*/
        // *token*/*api_key*/*credential*). The previously-separate union here is
        // therefore redundant; keep the single source of truth in the loader.
        auto redaction = load_redaction_patterns(*db_);

        spdlog::info("echo.fleet_snapshot host={} procs={} conns={} ips={} "
                     "process_on={} tcp_on={}",
                     hostname, processes.size(), connections.size(), local_ips.size(), process_on,
                     tcp_on);

        auto payload = yuzu::echo::build_fleet_snapshot_json(
            processes, connections, local_ips, hostname, ts, redaction, process_on, tcp_on);

        ctx.write_output(payload);
        return 0;
    }

    // ── configure action ──────────────────────────────────────────────────────

    // Phase 15.A retention-paused purge: drop ALL warehouse rows for a source
    // the operator deliberately paused, WITHOUT re-enabling collection. Refuses
    // unless the source is currently disabled — this is the authoritative safety
    // guard (closes the scan→purge TOCTOU: the server frame lists paused sources,
    // but one could have been re-enabled between the operator's scan and purge).
    // No baseline (echo_state) reset is needed: purge touches only the warehouse
    // event tables, not the diff snapshot, and the disable transition already
    // cleared the baseline when the source was paused — so a later re-enable
    // starts fresh regardless.
    int do_purge_source(yuzu::CommandContext& ctx, yuzu::Params params) {
        const std::string source{params.get("source")};
        if (source.empty()) {
            ctx.write_output("error|source is required");
            return 1;
        }
        bool known = false;
        for (const auto& s : yuzu::echo::capture_sources()) {
            if (s.name == source) {
                known = true;
                break;
            }
        }
        if (!known) {
            ctx.write_output(std::format("error|unknown source: {}", source));
            return 1;
        }
        // Hold the collect-side lock(s) across BOTH the enabled-check AND the purge
        // so the guard is atomic w.r.t. do_configure's enable transition (which also
        // holds collect_mu_ [+software_collect_mu_] around apply_source_enabled_
        // transition). Without this the check and the delete are two separate mu_
        // critical sections and a concurrent `<src>_enabled=true` could commit
        // between them — purging an actively-collecting source (the scan→purge TOCTOU
        // the guard exists to close). Lock order matches do_configure exactly
        // (collect_mu_ ≺ software_collect_mu_ ≺ EchoDatabase::mu_); source_enabled_state and
        // purge_source take only mu_, which is not held here, so no deadlock/recursion.
        std::lock_guard collect_lock(collect_mu_);
        std::unique_lock<std::mutex> sw_lock;
        if (source == "software")
            sw_lock = std::unique_lock<std::mutex>(software_collect_mu_);

        // ONE read, three outcomes: source_enabled() would read an unreadable config
        // row as DISABLED (collect gates fail closed), which for this destructive
        // guard would be fail-open -- so refuse unless the flag is confirmed, and
        // take the confirmation from the same read that decides it.
        const auto enabled_state = yuzu::echo::source_enabled_state(*db_, source);
        if (!enabled_state) {
            ctx.write_output(std::format(
                "error|config_unreadable: cannot confirm {} is disabled; not purging", source));
            return 1;
        }
        if (*enabled_state) {
            ctx.write_output(std::format(
                "error|source_not_paused: {} is enabled; disable it before purging", source));
            return 1;
        }
        auto res = db_->purge_source(source);
        if (!res) {
            ctx.write_output(std::format("error|{}", res.error()));
            return 1;
        }
        // The per-profile mapdrive backfill retry (§3.8, related issue #5291) persists its own
        // pending list in a key this purge does not otherwise touch -- left alone, a still-
        // pending profile's next retry can re-enumerate and re-insert exactly the rows this
        // purge just deleted (adversarial review). Never clear mapdrive_backfill_done here: that
        // would re-run the full first pass and resurrect everything, not just the pending subset.
        // This write's own failure must not report a silent success: the warehouse rows are
        // already gone (checked above), so a retry only re-attempts this one idempotent write,
        // never a second deletion -- but reporting "purged" while the pending list still names
        // the deleted rows reopens the exact resurrection this fix exists to close (governance,
        // unhappy-path).
        if (source == "mapdrive" && !db_->set_config("mapdrive_backfill_pending", "")) {
            ctx.write_output(
                "error|purge removed the rows but failed to clear the pending backfill retry "
                "list; retry the purge (the deletion itself is idempotent and will not repeat)");
            return 1;
        }
        ctx.write_output(
            std::format(R"({{"source":"{}","rows_deleted":{},"status":"purged"}})", source, *res));
        return 0;
    }

    int do_configure(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto retention = params.get("retention_days");
        auto fast_interval = params.get("fast_interval");
        auto slow_interval = params.get("slow_interval");
        auto software_interval = params.get("software_interval");
        auto netconn_lookback = params.get("netconn_lookback_seconds");
        auto power_lookback = params.get("power_lookback_seconds");
        auto removable_lookback = params.get("removable_lookback_seconds");
        auto redaction = params.get("redaction_patterns");
        auto db_budget = params.get("db_budget_bytes");

        bool changed = false;
        // db_budget_bytes: set only when provided AND valid (parse_budget_bytes).
        std::optional<int64_t> budget_bytes;
        int fast_secs = 0;
        int slow_secs = 0;
        int days = 0;
        // Software interval accepts 0 (disable the trigger) or 300–86400, so it
        // needs a "was it provided" flag distinct from the 0 sentinel.
        int software_secs = 0;
        bool software_provided = false;
        // netconn_lookback_seconds: the documented forward-only privacy control
        // (ADR-0020). A numeric value is CLAMPED to [0, 90 days] (0 = no
        // pre-enablement read) so a privacy-tightening request never fails on a
        // fat-fingered bound; a non-numeric value is rejected.
        int64_t netconn_lookback_secs = 0;
        bool netconn_lookback_provided = false;
        // The same forward-only privacy control for the two cursor sources. The
        // manual and the SOC 2 data inventory both present `0` as the works-council
        // lawfulness lever, so the key has to be REACHABLE: do_configure enumerates
        // a fixed key set and silently ignores anything outside it, which would have
        // made a documented control inert.
        int64_t power_lookback_secs = 0;
        bool power_lookback_provided = false;
        int64_t removable_lookback_secs = 0;
        bool removable_lookback_provided = false;

        // M13 contract: validate EVERY parameter in the request in PHASE 1 and
        // only persist them in PHASE 2 once all pass. A request that mixes a
        // valid change with a later invalid one is therefore rejected atomically
        // — nothing is written. (Previously the writes were interleaved with the
        // validators, so e.g. a request carrying a valid `process_enabled=false`
        // followed by an invalid exclusion list would persist the disable —
        // silently turning off capture — yet return an error to the caller.)
        // No db_->set_config / apply_source_enabled_transition call happens until
        // the "Phase 2" block below; every path before it only reads + validates.

        // ── Phase 1: validate everything (no writes) ─────────────────────────
        if (!retention.empty()) {
            try {
                days = std::stoi(std::string{retention});
            } catch (...) {}
            if (days < 1 || days > 365) {
                ctx.write_output("error|retention_days must be 1-365");
                return 1;
            }
        }

        if (!db_budget.empty()) {
            budget_bytes = yuzu::echo::parse_budget_bytes(db_budget);
            if (!budget_bytes) {
                ctx.write_output(std::format(
                    "error|db_budget_bytes must be a whole number of bytes >= {}",
                    yuzu::echo::kEchoDbBudgetBytesMin));
                return 1;
            }
        }

        if (!fast_interval.empty()) {
            try {
                fast_secs = std::stoi(std::string{fast_interval});
            } catch (...) {}
            if (fast_secs < 10 || fast_secs > 3600) {
                ctx.write_output("error|fast_interval must be 10-3600 seconds");
                return 1;
            }
        }

        if (!slow_interval.empty()) {
            try {
                slow_secs = std::stoi(std::string{slow_interval});
            } catch (...) {}
            if (slow_secs < 30 || slow_secs > 7200) {
                ctx.write_output("error|slow_interval must be 30-7200 seconds");
                return 1;
            }
        }

        if (!software_interval.empty()) {
            software_provided = true;
            bool parsed = false;
            try {
                software_secs = std::stoi(std::string{software_interval});
                parsed = true;
            } catch (...) {}
            // 0 disables the trigger; otherwise 300–86400 (5 min – 1 day). A
            // non-numeric value is rejected rather than silently treated as 0.
            if (!parsed || software_secs < 0 ||
                (software_secs > 0 && (software_secs < 300 || software_secs > 86400))) {
                ctx.write_output("error|software_interval must be 0 (disable) or 300-86400 seconds");
                return 1;
            }
        }

        if (!netconn_lookback.empty()) {
            netconn_lookback_provided = true;
            bool parsed = false;
            try {
                netconn_lookback_secs = std::stoll(std::string{netconn_lookback});
                parsed = true;
            } catch (...) {}
            if (!parsed) {
                ctx.write_output("error|netconn_lookback_seconds must be an integer 0-7776000 "
                                 "(0 = forward-only, no pre-enablement read)");
                return 1;
            }
            // Clamp rather than reject an out-of-range bound (see the field decl).
            netconn_lookback_secs = yuzu::echo::nq_clamp_lookback(netconn_lookback_secs);
        }

        struct LookbackSpec {
            const char* key;
            std::string_view raw;
            int64_t* out;
            bool* provided;
        };
        LookbackSpec power_lookback_spec{"power_lookback_seconds", power_lookback,
                                         &power_lookback_secs, &power_lookback_provided};
        LookbackSpec removable_lookback_spec{"removable_lookback_seconds", removable_lookback,
                                             &removable_lookback_secs,
                                             &removable_lookback_provided};
        for (auto* spec : {&power_lookback_spec, &removable_lookback_spec}) {
            if (spec->raw.empty())
                continue;
            *spec->provided = true;
            bool parsed = false;
            try {
                *spec->out = std::stoll(std::string{spec->raw});
                parsed = true;
            } catch (...) {}
            if (!parsed) {
                ctx.write_output(std::format("error|{} must be an integer 0-7776000 "
                                             "(0 = forward-only, no pre-enablement read)",
                                             spec->key));
                return 1;
            }
            *spec->out = yuzu::echo::nq_clamp_lookback(*spec->out);
        }

        // Cross-field validation BEFORE any writes
        if (fast_secs > 0 && slow_secs > 0 && fast_secs >= slow_secs) {
            ctx.write_output("error|fast_interval must be less than slow_interval");
            return 1;
        }

        // redaction_patterns — validate a JSON array of non-empty strings.
        const bool have_redaction = !redaction.empty();
        if (have_redaction) {
            try {
                auto arr = json::parse(std::string{redaction});
                if (!arr.is_array()) {
                    ctx.write_output("error|redaction_patterns must be a JSON array of strings");
                    return 1;
                }
                if (arr.size() > yuzu::echo::kMaxPatternArrayElements) {
                    ctx.write_output(std::format("error|redaction_patterns exceeds the {}-element "
                                                 "limit",
                                                 yuzu::echo::kMaxPatternArrayElements));
                    return 1;
                }
                for (const auto& elem : arr) {
                    if (!elem.is_string() || elem.get<std::string>().empty()) {
                        ctx.write_output(
                            "error|redaction_patterns must contain only non-empty strings");
                        return 1;
                    }
                    if (auto err = yuzu::echo::validate_config_pattern(
                            elem.get<std::string>(), /*require_min_core_len=*/false)) {
                        ctx.write_output(std::format("error|redaction_patterns: {}", *err));
                        return 1;
                    }
                }
            } catch (...) {
                ctx.write_output("error|redaction_patterns must be valid JSON array");
                return 1;
            }
        }

        // ── Per-source enable/disable (issue #59) ─────────────────────────────
        // Operators can disable any collector on a host without editing source.
        // Disabled collectors short-circuit in collect_fast/slow but still permit
        // `query` against existing rows. Collect the validated (source, value)
        // toggles here; the transition is applied in Phase 2. PR-A: enable→disable
        // records `<source>_paused_at` (wall-clock) for the retention-paused
        // dashboard list (#547); the reverse clears it to "0".
        std::vector<std::pair<std::string, std::string>> source_toggles;
        for (const auto& src : yuzu::echo::capture_sources()) {
            std::string key = std::format("{}_enabled", src.name);
            auto val = params.get(key);
            if (val.empty())
                continue;
            std::string v{val};
            if (v != "true" && v != "false") {
                ctx.write_output(std::format("error|{} must be 'true' or 'false'", key));
                return 1;
            }
            // M13 two-phase contract (#1532): collect the validated toggle now;
            // the actual transition (and its #538 collect_mu_ serialisation +
            // baseline reset) is applied in Phase 2, so a later invalid parameter
            // in the same request writes nothing.
            source_toggles.emplace_back(std::string{src.name}, std::move(v));
        }

        // ── Network capture method surface (issue #59) ───────────────────────
        // Today only "polling" is wired. ETW (Windows) and Endpoint Security
        // (macOS) are accepted-and-stored values per the schema registry's
        // OsSupport metadata so an operator can pre-stage the configuration, but
        // the collector continues to use polling until the implementation lands.
        const auto net_param = params.get("network_capture_method");
        const bool have_net = !net_param.empty();
        std::string net_method{net_param};
        if (have_net && net_method != "polling") {
            // "polling" is a sentinel meaning "use the platform default" — the
            // only mechanism wired today — and is accepted unconditionally even
            // though no os_support row carries it as a capture_method (governance
            // C-1 / QA Finding 2 round-trip). #540 — validate any other value
            // against THIS host's OS accept-list, not the OS-blind union, so a
            // Linux agent cannot store 'iphlpapi' nor a Windows agent 'procfs'.
            auto accepted =
                yuzu::echo::accepted_capture_methods_for_os("tcp", yuzu::echo::current_platform_os());
            if (std::find(accepted.begin(), accepted.end(), net_method) == accepted.end()) {
                std::string list = "polling";
                for (const auto& m2 : accepted) {
                    list += ",";
                    list += m2;
                }
                ctx.write_output(
                    std::format("error|network_capture_method '{}' is not accepted on this OS "
                                "(must be one of: {})",
                                net_method, list));
                return 1;
            }
        }

        // ── Process stabilization exclusions (issue #59) ─────────────────────
        // Case-insensitive substring patterns whose churn is excluded from
        // process events (noisy short-lived helpers). Validate here; persist in
        // Phase 2. Trade-off: anything matching is invisible to Echo, hence the
        // require_min_core_len floor that rejects over-broad 1–2 char patterns.
        const auto excl_param = params.get("process_stabilization_exclusions");
        const bool have_excl = !excl_param.empty();
        if (have_excl) {
            try {
                auto arr = json::parse(std::string{excl_param});
                if (!arr.is_array()) {
                    ctx.write_output("error|process_stabilization_exclusions must be a JSON array");
                    return 1;
                }
                if (arr.size() > yuzu::echo::kMaxPatternArrayElements) {
                    ctx.write_output(
                        std::format("error|process_stabilization_exclusions exceeds the {}-element "
                                    "limit",
                                    yuzu::echo::kMaxPatternArrayElements));
                    return 1;
                }
                for (const auto& elem : arr) {
                    if (!elem.is_string() || elem.get<std::string>().empty()) {
                        ctx.write_output("error|process_stabilization_exclusions must contain only "
                                         "non-empty strings");
                        return 1;
                    }
                    if (auto err = yuzu::echo::validate_config_pattern(
                            elem.get<std::string>(), /*require_min_core_len=*/true)) {
                        ctx.write_output(
                            std::format("error|process_stabilization_exclusions: {}", *err));
                        return 1;
                    }
                }
            } catch (...) {
                ctx.write_output("error|process_stabilization_exclusions must be valid JSON array");
                return 1;
            }
        }

        // ── Phase 2: persist (every parameter above is already validated) ────
        if (budget_bytes) {
            // The only checked write, so it goes FIRST: this control gates deletes, a value that
            // did not persist must not be reported as applied, and its failure must leave nothing
            // else half-applied (retention_days below is unchecked and cannot fail the call).
            if (!db_->set_config(std::string{yuzu::echo::kDbBudgetKey},
                                 std::to_string(*budget_bytes))) {
                ctx.write_output("error|db_budget_bytes could not be saved");
                return 1;
            }
            ctx.write_output(std::format("config|db_budget_bytes|{}", *budget_bytes));
            changed = true;
        }
        if (days > 0) {
            db_->set_config("retention_days", std::string{retention});
            ctx.write_output(std::format("config|retention_days|{}", retention));
            changed = true;
        }
        if (fast_secs > 0) {
            db_->set_config("fast_interval_seconds", std::string{fast_interval});
            ctx.write_output(std::format("config|fast_interval_seconds|{}", fast_interval));
            changed = true;
        }
        if (slow_secs > 0) {
            db_->set_config("slow_interval_seconds", std::string{slow_interval});
            ctx.write_output(std::format("config|slow_interval_seconds|{}", slow_interval));
            changed = true;
        }
        if (software_provided) {
            db_->set_config("software_interval_seconds", std::to_string(software_secs));
            ctx.write_output(std::format("config|software_interval_seconds|{}", software_secs));
            changed = true;
        }
        if (netconn_lookback_provided) {
            // Persist the CLAMPED value so the stored config and the echo agree
            // with what the collect legs will actually read (nq_clamp_lookback is
            // applied again on read, defensively). 0 => forward-only.
            db_->set_config("netconn_lookback_seconds", std::to_string(netconn_lookback_secs));
            ctx.write_output(
                std::format("config|netconn_lookback_seconds|{}", netconn_lookback_secs));
            changed = true;
        }
        if (power_lookback_provided) {
            db_->set_config("power_lookback_seconds", std::to_string(power_lookback_secs));
            ctx.write_output(std::format("config|power_lookback_seconds|{}", power_lookback_secs));
            changed = true;
        }
        if (removable_lookback_provided) {
            db_->set_config("removable_lookback_seconds", std::to_string(removable_lookback_secs));
            ctx.write_output(
                std::format("config|removable_lookback_seconds|{}", removable_lookback_secs));
            changed = true;
        }
        if (have_redaction) {
            db_->set_config("redaction_patterns", std::string{redaction});
            ctx.write_output(std::format("config|redaction_patterns|{}", redaction));
            changed = true;
        }
        for (const auto& [src_name, v] : source_toggles) {
            bool transition_ok;
            {
                // #2361 Gate 8 (Sol): serialise against a whole RETENTION pass,
                // outermost. run_retention decides which sources are enabled in a
                // read phase and executes the queued deletes afterwards, so
                // without this a pause landing between the two still deletes the
                // rows the operator just asked to preserve -- and reports success
                // to both sides. The pre-change code raced too (it read the flag
                // one statement before deleting); the read/write split widened the
                // window to the whole sweep, so the fix belongs here rather than
                // in a narrower re-check.
                //
                // Lock order is rollup_mu_ ≺ collect_mu_ ≺ software_collect_mu_.
                // do_rollup takes ONLY rollup_mu_ (then db_->mu_ -- per statement
                // for the probes, and for the whole batch during the retention
                // deletes) and never collect_mu_, so no cycle exists. Cost: a configure
                // waits out an in-flight rollup, which is the correct trade for a
                // mutation whose whole purpose is to stop data being deleted.
                std::lock_guard rollup_lock(rollup_mu_);
                // #538: collect_fast/slow hold collect_mu_ for their whole
                // enumerate→diff→set_state cycle. Taking it here makes the
                // enabled-flag write + baseline clear atomic w.r.t. a collection
                // tick: the tick either fully precedes the disable (its set_state
                // is then wiped by the baseline clear) or sees enabled=false and
                // skips. No interleaving ⇒ no post-disable snapshot, no ghost
                // "stopped" events on re-enable. No deadlock: do_configure runs
                // without collect_mu_ held and the helper re-acquires nothing.
                std::lock_guard lock(collect_mu_);
                // `software` keeps its baseline read-diff-write under the dedicated
                // software_collect_mu_, NOT collect_mu_ (its slow registry walk must
                // not stall collect_fast under the shared lock — gov UP-6). So for the
                // software transition also hold THAT lock, or the baseline clear +
                // flag flip is not atomic w.r.t. an in-flight collect_software tick and
                // the #538 ghost-event race reopens on the default-on software source
                // (#1620). Lock order is always collect_mu_ ≺ software_collect_mu_
                // (collect_software takes only the latter), so there is no inversion.
                std::unique_lock<std::mutex> sw_lock;
                if (src_name == "software")
                    sw_lock = std::unique_lock<std::mutex>(software_collect_mu_);
                // Capture the prior state BEFORE applying, while it is still prior --
                // for the tcp nstat drain below (C1 fix) and for the cursor-source
                // routing block further down.
                //
                // Canonicalised the way apply_source_enabled_transition itself
                // does it, NOT via source_enabled(). The two disagree on a
                // corrupt value: source_enabled() fails closed, so "errored"
                // reads as NOT enabled, while the transition's disable leg fires
                // on any non-"false" prev -- errored included. Deriving the edge
                // from the collect-time gate therefore made
                // `<name>_enabled=false` over a tampered value write paused_at
                // while routing NO on_enabled_changed(false), so the source
                // never drained and discarded the paused window and committed it
                // on the next enable. The forensic-pause contract is exactly
                // what that breaks, so the edge must be the transition's own.
                const std::string_view cursor_prev_canon = yuzu::echo::canonical_source_enabled(
                   db_->get_config(std::string(src_name) + "_enabled",
                                   yuzu::echo::source_default_enabled(src_name) ? "true" : "false"));
                // C1 fix: the R2-3 nstat-ring drain below fires only on an actual
                // enable<->disable EDGE. An idempotent tcp_enabled=true re-assert
                // (common from desired-state reconciliation) returns transition_ok==true
                // but is NOT a pause boundary and must never discard live buffered
                // lifecycle events (nstat stays primary and the poll is filtered to
                // UDP, so the loss would be unobservable). Derived from the single
                // read above, not a second source_enabled() read: a failed read
                // there would report prev=false and turn that re-assert into an edge.
                const bool tcp_prev_enabled = (src_name == "tcp") && cursor_prev_canon == "true";
                transition_ok = yuzu::echo::apply_source_enabled_transition(*db_, src_name, v,
                                                                           now_epoch_seconds());
                if (transition_ok && v == "false") {
                    // The interval samplers (perf / procperf) keep their previous
                    // reading in memory, not in a diff-state row, so the
                    // diff_state_key clear inside apply_source_enabled_transition
                    // does not reach them (diff_state_key is empty for both). Reset
                    // the in-memory baseline under the SAME lock the collect legs
                    // take so a later re-enable diffs against a fresh reading instead
                    // of one from before the pause — otherwise the first
                    // post-re-enable row would cover the entire disabled window (a
                    // privacy leak on procperf, and contradicts the
                    // "re-enabling starts from a clean baseline" promise in
                    // docs/user-manual/echo.md). default-constructed → valid=false,
                    // which derive_sample/derive_proc_samples treat as "no baseline"
                    // (records nothing on the next tick).
                    if (src_name == "perf")
                        prev_perf_ = yuzu::echo::PerfCounters{};
                    else if (src_name == "procperf")
                        prev_proc_ = yuzu::echo::ProcSnapshot{};
                }
                // R2-3 (edge-gated per C1): drain-and-discard the nstat ring and
                // insert-retry backlog on a real tcp enable<->disable EDGE, under
                // collect_mu_ so it is atomic w.r.t. a collection tick. The disable
                // edge clears everything buffered up to the pause; the enable edge
                // clears whatever accumulated DURING a pause too short to have fired
                // the per-tick disabled discard in collect_fast. The client keeps
                // running (it also feeds netqual) — only the lifecycle ring is
                // discarded. Gated on an actual state change so an idempotent
                // re-assert never discards live events (C1).
                if (transition_ok && src_name == "tcp" && nstat_client_ &&
                    (v == "true") != tcp_prev_enabled) {
                    nstat_client_->drain();
                    pending_nstat_evs_.clear();
                }
                // Cursor-model sources (echo_cursor.hpp, P-002): forward the
                // toggle to the matching source's on_enabled_changed(), under
                // the same collect_mu_ a collection tick holds, so the
                // transition is atomic w.r.t. an in-flight collect() -- same
                // rationale as the #538 baseline-clear atomicity above. The
                // source itself owns the disable-drain-discard /
                // re-enable-rebaseline-and-gap contract (echo_cursor.hpp); this
                // call site only routes the edge.
                // Routed on an EDGE only. `cursor_prev_enabled` is captured before
                // apply_source_enabled_transition() above, for the same reason the
                // tcp/nstat drain is edge-gated (C1): an idempotent
                // `<name>_enabled=true` re-assert is routine from desired-state
                // reconciliation and is NOT a pause boundary. Routing it as one
                // makes the source re-baseline forward and emit a capture_gap,
                // silently discarding history it had not yet replayed -- the
                // consumer cannot defend against this, because it cannot tell an
                // edge from a re-assert.
                // An EDGE is exactly what the transition treated as one.
                const bool cursor_edge = (v == "false" && cursor_prev_canon != "false") ||
                                         (v == "true" && cursor_prev_canon != "true");
                if (transition_ok && cursor_edge) {
                    for (auto& cs : cursor_sources_) {
                        if (cs->name() == src_name) {
                            // ABI containment, same reason as the collect loop:
                            // on_enabled_changed() is declared noexcept-free and
                            // the SDK execute trampoline is an extern "C"
                            // boundary with no catch, so an escaping exception
                            // here terminates the agent from a plain
                            // configuration write. Losing the pause/resume
                            // bookkeeping for one toggle is the strictly better
                            // outcome, and it is logged loudly because a source
                            // that throws here has an un-honoured P-002 contract.
                            try {
                                cs->on_enabled_changed(v == "true");
                            } catch (const std::exception& e) {
                                spdlog::error("ECHO: {} on_enabled_changed threw ({}) -- the "
                                              "source's pause/resume bookkeeping for this "
                                              "toggle is not applied", src_name, e.what());
                            } catch (...) {
                                spdlog::error("ECHO: {} on_enabled_changed threw a non-std "
                                              "exception -- the source's pause/resume "
                                              "bookkeeping for this toggle is not applied",
                                              src_name);
                            }
                            break;
                        }
                    }
                }
            }
            if (!transition_ok) {
                // #538/UP-1 + #1654: the transition (baseline clear, flag, paused_at)
                // is one transaction, so a failure leaves the source in its previous
                // state. This is an apply-time I/O failure (a busy DB), not a
                // validation failure -- Phase 1 already validated every parameter.
                ctx.write_output(std::format(
                    "error|{}_enabled transition failed: could not persist (database busy); "
                    "source left in its previous state",
                    src_name));
                return 1;
            }
            ctx.write_output(std::format("config|{}_enabled|{}", src_name, v));
            // Consent clarity (#1831 review): enabling procperf does more than
            // collect on-device — the top-N per-app names + versions feed the
            // daily app_perf sync to the central server (B1/B2). An operator
            // opting in for local triage must see that the app identity leaves
            // the device. Surfaced here, in the manual, and in the CHANGELOG.
            if (src_name == "procperf" && v == "true")
                ctx.write_output(
                    "notice|procperf: per-app names + versions are now sampled AND "
                    "synced off-device to the central app_perf store (daily); disable "
                    "with procperf_enabled=false or --inventory-disable to keep the "
                    "device fully local");
            // Echo the resulting paused_at so the dashboard sees the transition
            // timestamp without an extra status round-trip — single source of
            // truth (re-read, not re-derived).
            std::string paused_at_key = std::format("{}_paused_at", src_name);
            ctx.write_output(
                std::format("config|{}|{}", paused_at_key, db_->get_config(paused_at_key, "0")));
            changed = true;
        }
        if (have_net) {
            if (net_method != "polling") {
                // Surface that no kernel-event collector is wired yet so an
                // operator pre-staging 'etw' / 'endpoint_security' isn't
                // surprised the collector keeps polling under the hood.
                ctx.write_output(
                    std::format("warn|network_capture_method '{}' accepted but not yet "
                                "implemented; collector will continue polling",
                                net_method));
            }
            db_->set_config("network_capture_method", net_method);
            ctx.write_output(std::format("config|network_capture_method|{}", net_method));
            changed = true;
        }
        if (have_excl) {
            db_->set_config("process_stabilization_exclusions", std::string{excl_param});
            ctx.write_output(std::format("config|process_stabilization_exclusions|{}", excl_param));
            changed = true;
        }

        // Phase 1 returns early on any invalid parameter, so reaching here with
        // nothing changed means the request carried no recognised parameter.
        if (!changed) {
            ctx.write_output("error|no valid configuration parameters provided");
            return 1;
        }

        // Re-register triggers with new intervals if changed
        if (fast_secs > 0 || slow_secs > 0 || software_provided) {
            yuzu::PluginContext pctx{plugin_ctx_};
            if (fast_secs > 0) {
                pctx.unregister_trigger("echo.fast");
                auto cfg = std::format(
                    R"({{"interval_seconds":{},"plugin":"echo","action":"collect_fast"}})",
                    fast_secs);
                pctx.register_trigger("echo.fast", "interval", cfg);
                ctx.write_output(std::format("trigger|echo.fast|re-registered|{}s", fast_secs));
            }
            if (slow_secs > 0) {
                pctx.unregister_trigger("echo.slow");
                auto cfg = std::format(
                    R"({{"interval_seconds":{},"plugin":"echo","action":"collect_slow"}})",
                    slow_secs);
                pctx.register_trigger("echo.slow", "interval", cfg);
                ctx.write_output(std::format("trigger|echo.slow|re-registered|{}s", slow_secs));
            }
            if (software_provided) {
                // Always unregister first; re-register only when non-zero. An
                // interval of 0 leaves the trigger absent (collection disabled
                // until re-registered with a positive interval or agent restart).
                pctx.unregister_trigger("echo.software");
                if (software_secs > 0) {
                    auto cfg = std::format(
                        R"({{"interval_seconds":{},"plugin":"echo","action":"collect_software"}})",
                        software_secs);
                    pctx.register_trigger("echo.software", "interval", cfg);
                    ctx.write_output(
                        std::format("trigger|echo.software|re-registered|{}s", software_secs));
                } else {
                    ctx.write_output("trigger|echo.software|unregistered|0s");
                }
            }
        }

        ctx.write_output("status|ok");
        return 0;
    }

    // ── rollup action (retention, byte budget, dictionary sweep) ─────────────

    int do_rollup(yuzu::CommandContext& ctx) {
        // No collect_mu_ needed — rollup operates on the roll-up tiers, not live-state diffs.
        // The SQLite-level mutex (db_->mu_) provides thread safety for individual
        // statements. It does NOT cover run_retention's in-memory clock-guard
        // state, which spans many statements - rollup_mu_ does (#2361), and it
        // keeps the trigger tick and a manual `echo rollup` from interleaving.
        std::lock_guard rollup_lock(rollup_mu_);
        auto ts = now_epoch_seconds();

        // There is no aggregation pass: the fold writes every tier as events arrive. What this
        // action does is prune by age, prune by size, and sweep the string dictionary.
        //
        // Retention's clock guard has a verdict on `ts`: a fresh decline (a big wall-clock step,
        // an implausible or ahead-of-clock anchor) or a failed read means this pass's clock
        // cannot be trusted to delete anything. Every budget floor derives from the same `ts`,
        // so a clock the guard refused must not drive eviction either. Same semantics as
        // retention: a FRESH anomaly declines the pass; a suppressed repeat is paced and drains
        // on a later pass.
        const std::int64_t guard_before = yuzu::echo::retention_clock_events(retention_guard_);
        yuzu::echo::run_retention(*db_, ts, retention_guard_);
        if (yuzu::echo::retention_clock_events(retention_guard_) > guard_before) {
            {
                // Surfaced as `retention_guard|__budget__|N`; counted in neither status total,
                // because the decline or failure that caused it is already counted.
                std::lock_guard guard_lock(retention_guard_.mu);
                ++retention_guard_.budget_skips;
            }
            // A pending catch-up slice is cleared: the guard has just refused the clock, so the
            // reading that slice was admitted with is no longer a basis to keep deleting on.
            set_budget_catch_up({});
            spdlog::warn("ECHO: byte budget pass skipped: the retention clock guard refused this "
                         "pass's clock reading");
        } else {
            // Then the byte budget, the one-off VACUUM gate and file hygiene.
            enforce_budget(ts, /*maintenance_pass=*/true);
        }
        // After the budget: eviction and retention are what create orphaned strings.
        run_dictionary_gc(ts);
        // `rows_aggregated` is kept for the reply shape (a stored client parses it): the roll-up
        // has no aggregation pass, so it is always 0.
        ctx.write_output("echo|rollup|0|rows_aggregated");
        return 0;
    }

    // The dictionary sweep: weekly, 2 s of steady clock (the PR 2 measurement: the live-set scan
    // alone took about 1.6 s of the 2 s at 3.92 M roll-up rows). A pass whose scan outruns the
    // deadline deletes nothing and is counted in `dict_gc_starved_total`; it is retried at the next
    // maintenance pass, not in a week. The caller holds rollup_mu_.
    void run_dictionary_gc(std::int64_t now_ts) {
        constexpr std::int64_t kDictGcIntervalSec = 7 * 86400;
        constexpr auto kDictGcDeadline = std::chrono::seconds(2);
        std::int64_t last = 0;
        {
            const auto text = db_->get_config("dict_gc_last_ts", "0");
            const auto [p, ec] = std::from_chars(text.data(), text.data() + text.size(), last);
            if (ec != std::errc{} || p != text.data() + text.size())
                last = 0;
        }
        // A marker ahead of the clock was written during a forward excursion: stale, never a reason
        // to wait.
        if (last > 0 && last <= now_ts && now_ts - last < kDictGcIntervalSec)
            return;
        const auto swept = db_->fold().gc_dictionary(*db_, yuzu::echo::EchoFold::Clock::now() + kDictGcDeadline);
        if (!swept) {
            spdlog::warn("ECHO: dictionary sweep failed: {}", swept.error());
            return;
        }
        if (!swept->live_set_built) {
            const auto total = std::to_string(
                std::atoll(db_->get_config("dict_gc_starved_total", "0").c_str()) + 1);
            db_->set_config("dict_gc_starved_total", total);
            spdlog::warn("ECHO: the dictionary sweep's scan did not finish inside its {} s deadline "
                         "(starved {} time(s)); retrying at the next maintenance pass",
                         kDictGcDeadline.count(), total);
            return;
        }
        if (swept->deleted > 0)
            spdlog::info("ECHO: dictionary sweep removed {} unreferenced strings", swept->deleted);
        // Done for the week only when nothing is left to delete; a deadline hit mid-delete leaves
        // orphans, so the next pass continues.
        if (!swept->deadline_hit && now_ts > 0)
            db_->set_config("dict_gc_last_ts", std::to_string(now_ts));
    }

    // ── byte budget: eviction, VACUUM gate, file hygiene ─────────────────────

    // Store both halves of the catch-up latch: the clock first, then the flag the reader checks.
    // The caller holds rollup_mu_, which orders the pair for run_budget_catch_up.
    void set_budget_catch_up(const yuzu::echo::BudgetCatchUp& c) {
        budget_catch_up_now_.store(c.admitted_now, std::memory_order_relaxed);
        budget_catch_up_.store(c.armed, std::memory_order_relaxed);
    }

    // One bounded eviction pass plus the post-pass hygiene. Runs in the 15-minute maintenance
    // pass (`maintenance_pass`, which also gates the one-off conversion VACUUM) and as the
    // catch-up slice of a fast tick. `now_ts` is the clock the retention guard admitted for a
    // maintenance pass, and the ARMING pass's admitted reading for a catch-up slice (never a
    // fresh one). The caller holds rollup_mu_.
    void enforce_budget(std::int64_t now_ts, bool maintenance_pass) {
        // Tri-state: an unreadable budget is NOT the default. Falling back to 250 MiB would
        // delete down to a smaller target than the operator configured.
        const auto stored = db_->try_get_config(std::string{yuzu::echo::kDbBudgetKey});
        const auto configured = yuzu::echo::budget_from_config(stored);
        if (!configured) {
            set_budget_catch_up({});
            // A PRESENT value that is not a usable budget (damaged or edited outside the plugin)
            // is unknown too, never the default: deleting down to 250 MiB would undo a budget the
            // operator raised (#6900). Say which it is.
            if (yuzu::echo::budget_setting_invalid(stored))
                spdlog::warn("ECHO: the stored db_budget_bytes is not a valid budget; the byte "
                             "budget pass was skipped. Re-set it with `echo.configure "
                             "db_budget_bytes=<bytes>`");
            else
                spdlog::warn("ECHO: db_budget_bytes could not be read; the byte budget pass was "
                             "skipped and is retried at the next pass");
            return;
        }
        const std::int64_t budget = *configured;
        const std::int64_t target = budget - yuzu::echo::kEchoWalAllowanceBytes;
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(yuzu::echo::kBudgetPassDeadlineMs);
        const auto time_left = [&] { return std::chrono::steady_clock::now() < deadline; };
        const auto res = yuzu::echo::run_budget(*db_, now_ts, target, time_left);

        // Another slice on the next fast tick only when this one ran out of time with rows left
        // to evict, carrying the clock reading this pass ran with (a slice re-arms with the same
        // one). A failed pass is retried by the next maintenance pass, not hammered.
        set_budget_catch_up(yuzu::echo::budget_catch_up_after(res, target, now_ts));
        const std::int64_t evicted = res.evicted_hourly;
        if (evicted > 0) {
            spdlog::info("ECHO: byte budget evicted {} hourly rows (data {} bytes, target {})",
                         res.evicted_hourly, res.data_bytes_after, target);
        }
        if (maintenance_pass && res.exhausted) {
            spdlog::warn("ECHO: echo.db data ({} bytes) is above its {} byte target and nothing "
                         "more is eligible to evict (hourly rows under 48 h (5 d for procperf), "
                         "daily and monthly rows, the usage tables, netqual_boot and paused or "
                         "errored sources are never evicted)",
                         res.data_bytes_after, target);
        }

        if (maintenance_pass)
            maybe_vacuum_to_incremental(now_ts, target, res.exhausted);

        // Hygiene: hand free pages back to the OS while the pass deadline allows (at least one
        // call, as before; only an incremental-auto_vacuum file has any to hand back, and the
        // guard stops the loop burning the deadline on a file where the call is a no-op), then
        // checkpoint. TRUNCATE (reclaims the WAL file) when rows were evicted or the WAL outgrew
        // its allowance -- the recovery from a pinned reader, retried every pass and slice;
        // PASSIVE otherwise. The checkpoint never waits: a busy result means a reader pins the
        // WAL and is retried.
        const auto has_free_pages = [this] {
            const auto sb = db_->storage_bytes();
            return sb.ok && sb.auto_vacuum == 2 && sb.freelist_count > 0;
        };
        // A failing PRAGMA (disk full, I/O error, read-only) ends the loop: re-issuing it would
        // only spin to the deadline with a warning per call.
        while (db_->incremental_vacuum(256) && time_left() && has_free_pages()) {
        }
        const auto wal = db_->storage_bytes();
        const bool truncate = evicted > 0 || (wal.ok && wal.wal_bytes >
                                                            yuzu::echo::kEchoWalAllowanceBytes);
        if (db_->checkpoint(truncate ? yuzu::echo::CheckpointMode::kTruncate
                                     : yuzu::echo::CheckpointMode::kPassive) ==
            yuzu::echo::CheckpointResult::kBusy) {
            spdlog::debug("ECHO: WAL checkpoint busy (a reader pins the WAL); retrying next pass");
        }
    }

    // The conversion-deferral time: the in-memory copy kept while the last marker write failed,
    // else the persisted marker (0 when absent, unreadable or not a whole non-negative number);
    // precedence in yuzu::echo::deferred_marker_reading. The one reader behind both the VACUUM
    // decision and the status line.
    std::int64_t deferred_marker() {
        const auto text = db_->get_config(std::string{yuzu::echo::kAutoVacuumDeferredKey}, "0");
        std::int64_t at = 0;
        const auto [p, ec] = std::from_chars(text.data(), text.data() + text.size(), at);
        if (ec != std::errc{} || p != text.data() + text.size() || at < 0)
            at = 0;
        return yuzu::echo::deferred_marker_reading(
            at, vacuum_marker_fallback_.load(std::memory_order_relaxed));
    }

    // Persist the deferral time. A write that fails keeps an in-memory copy so a database that
    // cannot store the marker still retries at most daily within this process.
    //
    // A reading at or below zero (a dead-CMOS clock, #6889 B6) cannot be stored as a marker: the
    // reader treats a non-positive marker as "absent". Storing it would silently lift the daily
    // bound, so it is not stored; the in-process attempt limiter below holds the bound instead.
    void set_deferred_marker(std::int64_t value) {
        if (value <= 0)
            return;
        const bool stored = db_->set_config(std::string{yuzu::echo::kAutoVacuumDeferredKey},
                                            std::to_string(value));
        vacuum_marker_fallback_.store(stored ? 0 : value, std::memory_order_relaxed);
    }

    // A conversion succeeded: the marker reads 0 ("none") again, and the in-memory copy goes with it.
    void clear_deferred_marker() {
        db_->set_config(std::string{yuzu::echo::kAutoVacuumDeferredKey}, "0");
        vacuum_marker_fallback_.store(0, std::memory_order_relaxed);
    }

    // True when a conversion attempt was made less than a day ago BY THIS PROCESS, on the steady
    // clock. The persisted marker bounds attempts across restarts but only works while the wall
    // clock is positive; this bounds them within a process whatever the wall clock says.
    bool vacuum_attempted_recently() {
        const auto last = vacuum_last_attempt_.load(std::memory_order_relaxed);
        if (last == 0)
            return false;
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        return std::chrono::nanoseconds(now - last) < std::chrono::hours(24);
    }
    void note_vacuum_attempt() {
        vacuum_last_attempt_.store(std::chrono::steady_clock::now().time_since_epoch().count(),
                                   std::memory_order_relaxed);
    }

    // The one-off conversion of a pre-existing database to incremental auto_vacuum. Never at
    // boot; only here, once eviction has brought data under target (or has nothing left to
    // evict) and the file holds many free pages. Too little free disk (or a failed VACUUM)
    // records the time and retries at most daily; status shows db_auto_vacuum|deferred until a
    // conversion succeeds (the marker is not cleared when a later pass finds the freelist too
    // small to warrant one). The VACUUM runs on the single interval-trigger thread with the
    // database lock held, so it stalls the agent's triggers for its duration. It copies used
    // pages only, so its duration (and the free disk it needs, twice that size) follows the used
    // data at the time of the conversion: at or under the target, or, when eviction is exhausted,
    // whatever exempt data remains, which can sit above the target. It happens once per database.
    void maybe_vacuum_to_incremental(std::int64_t now_ts, std::int64_t target,
                                     bool eviction_exhausted) {
        const auto sb = db_->storage_bytes();
        if (!sb.ok)
            return; // cannot size the decision; the next pass retries
        const std::int64_t deferred_at = deferred_marker();
        // An unreadable volume counts as no free space: defer rather than risk a full disk.
        std::error_code ec;
        const auto space = std::filesystem::space(db_path_.parent_path(), ec);
        const auto free_disk =
            ec ? std::int64_t{0}
               : static_cast<std::int64_t>(std::min<std::uintmax_t>(
                     space.available, static_cast<std::uintmax_t>(INT64_MAX)));

        if (vacuum_attempted_recently())
            return;
        switch (yuzu::echo::vacuum_decision(yuzu::echo::VacuumInputs{
            .auto_vacuum = sb.auto_vacuum,
            .data_bytes = sb.data_bytes(),
            .target_bytes = target,
            .freelist_bytes = sb.freelist_bytes(),
            .file_bytes = sb.file_bytes(),
            .free_disk_bytes = free_disk,
            .deferred_at = deferred_at,
            .now = now_ts,
            .eviction_exhausted = eviction_exhausted})) {
        case yuzu::echo::VacuumAction::kSkip:
            break;
        case yuzu::echo::VacuumAction::kDefer:
            spdlog::warn("ECHO: not converting echo.db to incremental auto_vacuum yet: {} bytes "
                         "free on its volume, {} needed; retrying within a day",
                         free_disk, 2 * sb.data_bytes());
            set_deferred_marker(now_ts);
            note_vacuum_attempt();
            break;
        case yuzu::echo::VacuumAction::kRun: {
            spdlog::info("ECHO: converting echo.db to incremental auto_vacuum (one-off VACUUM; "
                         "collectors pause while it runs)");
            // The attempt is recorded BEFORE the VACUUM and cleared on success, so a crash or a
            // watchdog kill mid-VACUUM bounds the repeat to daily instead of every boot.
            set_deferred_marker(now_ts);
            note_vacuum_attempt();
            const auto started = std::chrono::steady_clock::now();
            const bool converted = db_->vacuum_to_incremental();
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - started)
                                .count();
            const auto after = db_->storage_bytes();
            if (converted) {
                clear_deferred_marker();
                spdlog::info("ECHO: auto_vacuum conversion finished in {} ms (used {} -> {} "
                             "bytes, file {} -> {} bytes)",
                             ms, sb.data_bytes(), after.data_bytes(), sb.file_bytes(),
                             after.file_bytes());
            } else {
                spdlog::warn("ECHO: the auto_vacuum conversion VACUUM failed after {} ms; "
                             "retrying within a day",
                             ms);
            }
            break;
        }
        }
    }

    // One more bounded eviction slice per fast tick while a pass has left the database over
    // target. try_lock only: it never waits on a maintenance pass, and a pass that is running
    // already does the same work. Called with collect_mu_ RELEASED, so rollup_mu_ is never
    // taken inside it. The slice runs with the clock reading the arming pass was admitted with:
    // it has no retention-guard contact of its own, so a clock that stepped forward since would
    // widen every floor unchecked. It also reads a FRESH clock, but only to refuse: a wall clock
    // that has stepped BACKWARD below the admitted reading puts that reading's floors above rows
    // written since the step, so the drain is disarmed (budget_slice_clock, #6889 review B1). The
    // next maintenance pass admits (or refuses, and clears the latch) a new reading.
    void run_budget_catch_up() {
        if (!budget_catch_up_.load(std::memory_order_relaxed))
            return;
        std::unique_lock lock(rollup_mu_, std::try_to_lock);
        // db_ is reset under rollup_mu_ in shutdown(), so it is checked under the lock.
        if (!lock.owns_lock() || !db_ || !budget_catch_up_.load(std::memory_order_relaxed))
            return;
        const yuzu::echo::BudgetCatchUp armed{true, budget_catch_up_now_.load(std::memory_order_relaxed)};
        const auto clock = yuzu::echo::budget_slice_clock(armed, now_epoch_seconds());
        if (!clock) {
            set_budget_catch_up({});
            spdlog::warn("ECHO: byte budget catch-up disarmed: the wall clock stepped back below the "
                         "reading the drain was admitted with; the next maintenance pass decides");
            return;
        }
        enforce_budget(*clock, /*maintenance_pass=*/false);
    }

    // ── sql action (warehouse query engine) ──────────────────────────────────

    int do_sql(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto sql_param = std::string{params.get("sql")};
        if (sql_param.empty()) {
            ctx.write_output("error|missing required 'sql' parameter");
            return 1;
        }

        auto validated = yuzu::echo::validate_and_translate_sql(sql_param);
        if (!validated) {
            ctx.write_output(std::format("error|{}", validated.error()));
            return 1;
        }

        auto query_result = db_->execute_user_query(*validated);
        if (!query_result) {
            ctx.write_output(std::format("error|{}", query_result.error()));
            return 1;
        }
        auto& result = *query_result;

        // Output schema line
        std::string schema_line = "__schema__";
        for (const auto& col : result.columns)
            schema_line += "|" + col;
        ctx.write_output(schema_line);

        // Output data rows
        for (const auto& row : result.rows) {
            std::string line;
            for (size_t i = 0; i < row.size(); ++i) {
                if (i > 0)
                    line += '|';
                line += row[i];
            }
            ctx.write_output(line);
        }

        ctx.write_output(std::format("__total__|{}", result.rows.size()));
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(EchoPlugin)
