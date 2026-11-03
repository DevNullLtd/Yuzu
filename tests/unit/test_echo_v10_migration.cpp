/**
 * test_echo_v10_migration.cpp -- schema v10: the one-transaction move from the retired raw
 * tables and summary tiers to the roll-up tiers.
 *
 * A "v9" database is seeded with raw sqlite3 calls (the retired DDL lives HERE, as a fixture of
 * what shipped; the production registry no longer declares it): every raw `<src>_live` table
 * with 2+ rows, the old summary tiers, rollup marks, usage_live. EchoDatabase::open() then
 * migrates it. The correctness oracle is a DIFFERENTIAL: the same events folded through the
 * production `<src>_delta` + the fold writer on a fresh database must give the same tier views
 * as the migration of the raw rows (and the same replay ring for the cursor sources).
 *
 * Nothing here polls, sleeps or asserts a duration; the free-space and fault seams are injected
 * through OpenSeams.
 */

#include "echo_db.hpp"
#include "echo_fold.hpp"
#include "echo_fold_schema.hpp"
#include "echo_schema_registry.hpp"
#include "echo_sql_executor.hpp"
#include "echo_status_format.hpp"
#include "test_helpers.hpp"

#include <sqlite3.h>

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <format>
#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <variant>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::echo;

namespace {

constexpr int64_t kH0 = 1793613600; // 2026-11-02T10:00:00Z
constexpr int64_t kT0 = kH0 + 1800;
constexpr int64_t kNextHour = kH0 + 3600;
constexpr int64_t kNextDay = kH0 + 86400;
constexpr std::uintmax_t kRoomy = std::uintmax_t{1} << 40; // a volume with room to spare

// ── raw sqlite helpers ───────────────────────────────────────────────────────

using Db = yuzu::test::SqliteHandleOwner<sqlite3>;

struct StmtFinalizer {
    void operator()(sqlite3_stmt* s) const { sqlite3_finalize(s); }
};
using Stmt = std::unique_ptr<sqlite3_stmt, StmtFinalizer>;

void open_raw(Db& d, const fs::path& path) {
    REQUIRE(sqlite3_open(path.string().c_str(), &d.db) == SQLITE_OK);
}

void exec(sqlite3* db, const std::string& sql) {
    char* raw = nullptr;
    const int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &raw);
    const std::unique_ptr<char, decltype(&sqlite3_free)> err{raw, &sqlite3_free};
    INFO("sql: " << sql << "\nsqlite: " << (err ? err.get() : ""));
    REQUIRE(rc == SQLITE_OK);
}

std::vector<std::vector<std::string>> rows_of(sqlite3* db, const std::string& sql) {
    sqlite3_stmt* raw = nullptr;
    REQUIRE(sqlite3_prepare_v2(db, sql.c_str(), -1, &raw, nullptr) == SQLITE_OK);
    const Stmt st{raw};
    std::vector<std::vector<std::string>> out;
    while (sqlite3_step(st.get()) == SQLITE_ROW) {
        std::vector<std::string> r;
        for (int i = 0; i < sqlite3_column_count(st.get()); ++i) {
            const auto* t = reinterpret_cast<const char*>(sqlite3_column_text(st.get(), i));
            r.emplace_back(t ? t : "NULL");
        }
        out.push_back(std::move(r));
    }
    return out;
}

int64_t count_of(sqlite3* db, const std::string& sql) {
    const auto r = rows_of(db, sql);
    REQUIRE(r.size() == 1);
    return std::stoll(r[0][0]);
}

// Rows of a query on an EchoDatabase's trusted connection.
std::vector<QueryRow> q(EchoDatabase& db, const std::string& sql) {
    const auto r = db.execute_query(sql, 100000);
    INFO(sql);
    REQUIRE(r.has_value());
    return r->rows;
}

int64_t n(EchoDatabase& db, const std::string& sql) {
    const auto r = q(db, sql);
    REQUIRE(r.size() == 1);
    return std::stoll(r[0][0]);
}

// ── the retired schema (a fixture of what v9 shipped) ────────────────────────

const char* kBaseTables = R"(
CREATE TABLE echo_state (collector TEXT PRIMARY KEY, state_json TEXT NOT NULL DEFAULT '{}', updated_at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE echo_config (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');
CREATE TABLE echo_cursor (source TEXT PRIMARY KEY, cursor_json TEXT NOT NULL, updated_at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE usage_live (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL DEFAULT 0, snapshot_id INTEGER NOT NULL DEFAULT 0, action TEXT NOT NULL DEFAULT '', pid INTEGER NOT NULL DEFAULT 0, exe_key TEXT NOT NULL DEFAULT '', user TEXT NOT NULL DEFAULT '', start_ts INTEGER NOT NULL DEFAULT 0);
CREATE TABLE usage_daily (id INTEGER PRIMARY KEY AUTOINCREMENT, day_ts INTEGER NOT NULL DEFAULT 0, exe_key TEXT NOT NULL DEFAULT '', run_count INTEGER NOT NULL DEFAULT 0, total_seconds INTEGER NOT NULL DEFAULT 0, first_seen INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL DEFAULT 0, distinct_users INTEGER NOT NULL DEFAULT 0, superseded_runs INTEGER NOT NULL DEFAULT 0, expired_runs INTEGER NOT NULL DEFAULT 0);
CREATE TABLE netqual_boot (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL DEFAULT 0, snapshot_id INTEGER NOT NULL DEFAULT 0, boot_ts INTEGER NOT NULL DEFAULT 0, window_s INTEGER NOT NULL DEFAULT 0, retrans_segs INTEGER NOT NULL DEFAULT 0, segs_out INTEGER NOT NULL DEFAULT 0, estab_resets INTEGER NOT NULL DEFAULT 0, if_in_errors INTEGER NOT NULL DEFAULT 0, if_in_discards INTEGER NOT NULL DEFAULT 0, if_out_errors INTEGER NOT NULL DEFAULT 0, if_out_discards INTEGER NOT NULL DEFAULT 0, if_in_octets INTEGER NOT NULL DEFAULT 0, if_out_octets INTEGER NOT NULL DEFAULT 0);
)";

// The old summary tiers: (table, columns). Every column is NOT NULL DEFAULT 0 / ''.
struct OldTier {
    const char* table;
    const char* columns; // "name TYPE, ..."
};
const OldTier kOldTiers[] = {
    {"process_hourly", "hour_ts INTEGER, name TEXT, user TEXT, start_count INTEGER, stop_count INTEGER"},
    {"process_daily", "day_ts INTEGER, name TEXT, user TEXT, start_count INTEGER, stop_count INTEGER"},
    {"process_monthly", "month_ts INTEGER, name TEXT, user TEXT, start_count INTEGER, stop_count INTEGER"},
    {"tcp_hourly", "hour_ts INTEGER, remote_addr TEXT, remote_port INTEGER, proto TEXT, process_name TEXT, connect_count INTEGER, disconnect_count INTEGER"},
    {"tcp_daily", "day_ts INTEGER, remote_addr TEXT, remote_port INTEGER, proto TEXT, process_name TEXT, connect_count INTEGER, disconnect_count INTEGER"},
    {"tcp_monthly", "month_ts INTEGER, remote_addr TEXT, remote_port INTEGER, proto TEXT, process_name TEXT, connect_count INTEGER, disconnect_count INTEGER"},
    {"service_hourly", "hour_ts INTEGER, name TEXT, status_changes INTEGER, last_status TEXT"},
    {"user_daily", "day_ts INTEGER, user TEXT, domain TEXT, login_count INTEGER, logout_count INTEGER"},
    {"perf_hourly", "hour_ts INTEGER, samples INTEGER, cpu_avg REAL, cpu_max REAL, mem_avg REAL, mem_max REAL, commit_avg REAL, read_bps_avg INTEGER, write_bps_avg INTEGER, read_lat_us_avg INTEGER, write_lat_us_avg INTEGER, read_lat_us_max INTEGER, write_lat_us_max INTEGER, rx_bps_avg INTEGER, tx_bps_avg INTEGER"},
    {"procperf_hourly", "hour_ts INTEGER, name TEXT, version TEXT, is_kthread INTEGER, samples INTEGER, instances_max INTEGER, cpu_avg REAL, cpu_max REAL, ws_avg_bytes INTEGER, ws_max_bytes INTEGER"},
    {"module_hourly", "hour_ts INTEGER, module_name TEXT, signer TEXT, signed_state TEXT, is_kernel INTEGER, load_count INTEGER"},
    {"module_daily", "day_ts INTEGER, module_name TEXT, signer TEXT, signed_state TEXT, is_kernel INTEGER, load_count INTEGER"},
    {"module_monthly", "month_ts INTEGER, module_name TEXT, signer TEXT, signed_state TEXT, is_kernel INTEGER, load_count INTEGER"},
    {"software_daily", "day_ts INTEGER, name TEXT, install_count INTEGER, remove_count INTEGER, upgrade_count INTEGER"},
    {"software_monthly", "month_ts INTEGER, name TEXT, install_count INTEGER, remove_count INTEGER, upgrade_count INTEGER"},
    {"arp_hourly", "hour_ts INTEGER, interface TEXT, ip_address TEXT, mac_address TEXT, appear_count INTEGER, remove_count INTEGER"},
    {"dns_hourly", "hour_ts INTEGER, name TEXT, record_type TEXT, appear_count INTEGER, remove_count INTEGER"},
    {"mapdrive_hourly", "hour_ts INTEGER, direction TEXT, local_mount TEXT, remote_path TEXT, remote_host TEXT, appear_count INTEGER, remove_count INTEGER"},
};

std::string create_table(const std::string& name, const std::string& columns) {
    std::string out = "CREATE TABLE " + name + " (id INTEGER PRIMARY KEY AUTOINCREMENT";
    size_t pos = 0;
    while (pos < columns.size()) {
        auto comma = columns.find(',', pos);
        if (comma == std::string::npos)
            comma = columns.size();
        std::string col = columns.substr(pos, comma - pos);
        const auto first = col.find_first_not_of(' ');
        col = col.substr(first);
        const bool text = col.ends_with("TEXT");
        out += ", " + col + (text ? " NOT NULL DEFAULT ''" : " NOT NULL DEFAULT 0");
        pos = comma + 1;
    }
    return out + ");\n";
}

// The raw table of a source, declared from the same column list the migration decodes.
std::string create_raw_table(const std::string& source) {
    std::string cols;
    for (const auto& c : legacy_live_columns(source))
        cols += (cols.empty() ? "" : ", ") + std::string{c.name} + " " + std::string{c.sql_type};
    return create_table(source + "_live", cols);
}

void seed_schema(sqlite3* db) {
    exec(db, kBaseTables);
    for (const auto& def : fold_sources())
        if (!def.own_tables)
            exec(db, create_raw_table(std::string{def.name}));
    for (const auto& t : kOldTiers)
        exec(db, create_table(t.table, t.columns));
    exec(db, "INSERT INTO echo_config VALUES ('schema_version', '9'), ('retention_days', '7')");
}

using Cell = std::variant<int64_t, double, std::string>;

void insert_raw(sqlite3* db, std::string_view source, const std::vector<Cell>& values) {
    const auto cols = legacy_live_columns(source);
    REQUIRE(cols.size() == values.size());
    std::string names, marks;
    for (size_t i = 0; i < cols.size(); ++i) {
        names += (i ? ", " : "") + std::string{cols[i].name};
        marks += i ? ", ?" : "?";
    }
    sqlite3_stmt* raw = nullptr;
    const auto sql = std::format("INSERT INTO {}_live ({}) VALUES ({})", source, names, marks);
    REQUIRE(sqlite3_prepare_v2(db, sql.c_str(), -1, &raw, nullptr) == SQLITE_OK);
    const Stmt st{raw};
    for (size_t i = 0; i < values.size(); ++i) {
        const int idx = static_cast<int>(i) + 1;
        if (const auto* v = std::get_if<int64_t>(&values[i]))
            sqlite3_bind_int64(st.get(), idx, *v);
        else if (const auto* d = std::get_if<double>(&values[i]))
            sqlite3_bind_double(st.get(), idx, *d);
        else
            sqlite3_bind_text(st.get(), idx, std::get<std::string>(values[i]).c_str(), -1,
                              SQLITE_TRANSIENT);
    }
    REQUIRE(sqlite3_step(st.get()) == SQLITE_DONE);
}

// ── the fixtures: events, their raw-row encoding, and the fresh-database fold ─

struct Case {
    std::string source;
    std::function<void(sqlite3*)> seed_raw;      // write the events as raw rows
    std::function<void(EchoDatabase&)> fold_fresh; // fold the same events the production way
};

Cell I(int64_t v) { return v; }
Cell R(double v) { return v; }
Cell T(std::string v) { return std::move(v); }

template <class E, class Enc, class Fold>
Case make_case(const char* source, std::vector<E> events, Enc enc, Fold fold) {
    return Case{source,
                [source, events, enc](sqlite3* db) {
                    for (const auto& e : events)
                        insert_raw(db, source, enc(e));
                },
                [events, fold](EchoDatabase& db) { fold(db, events); }};
}

ProcessEvent proc(int64_t ts, int64_t snap, const char* action, uint32_t pid, uint32_t ppid,
                  const char* name, const char* cmdline, const char* user) {
    ProcessEvent e;
    e.ts = ts;
    e.snapshot_id = snap;
    e.action = action;
    e.pid = pid;
    e.ppid = ppid;
    e.name = name;
    e.cmdline = cmdline;
    e.user = user;
    return e;
}

RemovableEvent removable(int64_t ts, int64_t snap, const char* action, const char* bus_volume_serial,
                         int64_t size, const char* image, int64_t pid, const char* evidence,
                         const char* key) {
    RemovableEvent e;
    e.ts = ts;
    e.snapshot_id = snap;
    e.action = action;
    e.device_key = "usb:1";
    e.vendor = "SanDisk";
    e.product = "Cruzer";
    e.serial = bus_volume_serial;
    e.bus = "usb";
    e.volume = "E:";
    e.size_bytes = size;
    e.image_path = image;
    e.pid = pid;
    e.evidence = evidence;
    e.record_key = key;
    return e;
}

std::vector<Case> all_cases() {
    std::vector<Case> out;

    out.push_back(make_case(
        "process",
        std::vector<ProcessEvent>{
            proc(kT0, 1, "started", 100, 1, "alpha.exe", "alpha --x", "jsmith"),
            proc(kT0 + 60, 1, "stopped", 100, 1, "alpha.exe", "", "jsmith"),
            proc(kNextHour + 5, 2, "started", 200, 100, "beta.exe", "", "SYSTEM")},
        [](const ProcessEvent& e) -> std::vector<Cell> {
            return {I(e.ts), I(e.snapshot_id), T(e.action), I(e.pid), I(e.ppid), T(e.name),
                    T(e.cmdline), T(e.user)};
        },
        [](EchoDatabase& db, const std::vector<ProcessEvent>& ev) {
            REQUIRE(db.fold_process_events(ev, std::nullopt, kT0));
        }));

    out.push_back(make_case(
        "tcp",
        std::vector<NetworkEvent>{
            {kT0, 1, "connected", "tcp", "10.0.0.5", 51000, "93.184.216.34", "example.org", 443,
             "ESTABLISHED", 100, "chrome"},
            {kT0 + 30, 1, "disconnected", "tcp", "10.0.0.5", 51000, "93.184.216.34", "example.org",
             443, "CLOSE", 100, "chrome"},
            {kNextHour, 2, "connected", "tcp", "10.0.0.5", 51001, "93.184.216.34", "", 443,
             "ESTABLISHED", 100, "chrome"}},
        [](const NetworkEvent& e) -> std::vector<Cell> {
            return {I(e.ts), I(e.snapshot_id), T(e.action), T(e.proto), T(e.local_addr),
                    I(e.local_port), T(e.remote_addr), T(e.remote_host), I(e.remote_port),
                    T(e.state), I(e.pid), T(e.process_name)};
        },
        [](EchoDatabase& db, const std::vector<NetworkEvent>& ev) {
            REQUIRE(db.fold_network_events(ev));
        }));

    out.push_back(make_case(
        "service",
        std::vector<ServiceEvent>{
            {kT0, 1, "started", "Spooler", "Print Spooler", "running", "", "auto", ""},
            {kT0 + 120, 1, "state_changed", "Spooler", "Print Spooler", "stopped", "running", "auto", "auto"},
            {kNextHour, 2, "stopped", "Spooler", "Print Spooler", "stopped", "running", "auto", "auto"}},
        [](const ServiceEvent& e) -> std::vector<Cell> {
            return {I(e.ts), I(e.snapshot_id), T(e.action), T(e.name), T(e.display_name),
                    T(e.status), T(e.prev_status), T(e.startup_type), T(e.prev_startup_type)};
        },
        [](EchoDatabase& db, const std::vector<ServiceEvent>& ev) {
            REQUIRE(db.fold_service_events(ev));
        }));

    out.push_back(make_case(
        "user",
        std::vector<UserEvent>{{kT0, 1, "login", "jsmith", "CORP", "interactive", "1"},
                               {kT0 + 600, 1, "disconnect", "jsmith", "CORP", "interactive", "1"},
                               {kNextDay, 2, "logout", "jsmith", "CORP", "interactive", "1"}},
        [](const UserEvent& e) -> std::vector<Cell> {
            return {I(e.ts), I(e.snapshot_id), T(e.action), T(e.user), T(e.domain),
                    T(e.logon_type), T(e.session_id)};
        },
        [](EchoDatabase& db, const std::vector<UserEvent>& ev) {
            REQUIRE(db.fold_user_events(ev));
        }));

    // Doubles are exactly representable so a sum is the same however it is grouped.
    out.push_back(make_case(
        "perf",
        std::vector<PerfRow>{{kT0, 1, 12.5, 37.5, 50.0, 100, 200, 3, 4, 500, 600},
                             {kT0 + 30, 1, 25.0, 40.0, 50.0, 300, 400, 5, 6, 700, 800},
                             {kNextHour, 2, 50.0, 45.0, 55.0, 10, 20, 1, 2, 30, 40}},
        [](const PerfRow& e) -> std::vector<Cell> {
            return {I(e.ts), I(e.snapshot_id), R(e.cpu_pct), R(e.mem_used_pct), R(e.commit_pct),
                    I(e.disk_read_bps), I(e.disk_write_bps), I(e.disk_read_lat_us),
                    I(e.disk_write_lat_us), I(e.net_rx_bps), I(e.net_tx_bps)};
        },
        [](EchoDatabase& db, const std::vector<PerfRow>& ev) {
            for (const auto& r : ev)
                REQUIRE(db.fold_perf_sample(r));
        }));

    out.push_back(make_case(
        "procperf",
        std::vector<ProcPerfRow>{{kT0, 1, "chrome.exe", "120.0", 4, 12.5, 4096, false},
                                 {kT0 + 30, 1, "chrome.exe", "120.0", 5, 25.0, 8192, false},
                                 {kNextHour, 2, "kworker", "", 1, 0.5, 0, true}},
        [](const ProcPerfRow& e) -> std::vector<Cell> {
            return {I(e.ts), I(e.snapshot_id), T(e.name), T(e.version), I(e.instances),
                    R(e.cpu_pct), I(e.ws_bytes), I(e.is_kthread ? 1 : 0)};
        },
        [](EchoDatabase& db, const std::vector<ProcPerfRow>& ev) {
            REQUIRE(db.fold_proc_perf_samples(ev));
        }));

    out.push_back(make_case(
        "netqual",
        std::vector<NetQualRow>{{kT0, 1, "tcp", "public", "chrome", 1000, 50, 0, 10, 100, 0},
                                {kT0 + 30, 1, "tcp", "public", "chrome", 3000, 70, 2, 12, 150, 3},
                                {kNextHour, 2, "tcp6", "private", "ssh", 200, 5, 0, 0, 5, 0}},
        [](const NetQualRow& e) -> std::vector<Cell> {
            return {I(e.ts), I(e.snapshot_id), T(e.proto), T(e.remote_bucket), T(e.process_name),
                    I(e.rtt_us), I(e.rtt_var_us), I(e.lost), I(e.retrans), I(e.segs_out),
                    I(e.ca_state)};
        },
        [](EchoDatabase& db, const std::vector<NetQualRow>& ev) {
            REQUIRE(db.fold_netqual_samples(ev));
        }));

    out.push_back(make_case(
        "module",
        std::vector<ModuleRow>{
            {kT0, 1, "loaded", 100, "alpha.exe", "ntdll.dll", "C:\\Windows\\System32", "signed",
             "Microsoft", true},
            {kT0 + 5, 1, "loaded", 100, "alpha.exe", "ntdll.dll", "C:\\Windows\\System32", "signed",
             "Microsoft", true},
            {kNextHour, 2, "blocked", 200, "beta.exe", "evil.dll", "C:\\Temp", "unsigned", "", false}},
        [](const ModuleRow& e) -> std::vector<Cell> {
            return {I(e.ts), I(e.snapshot_id), T(e.action), I(e.pid), T(e.process_name),
                    T(e.module_name), T(e.module_dir), T(e.signed_state), T(e.signer),
                    I(e.is_kernel ? 1 : 0)};
        },
        [](EchoDatabase& db, const std::vector<ModuleRow>& ev) {
            REQUIRE(db.fold_module_events(ev));
        }));

    out.push_back(make_case(
        "software",
        std::vector<SoftwareEvent>{{kT0, 1, "installed", "7-Zip", "23.01", "", "Igor Pavlov", "20260101"},
                                   {kT0 + 60, 1, "upgraded", "7-Zip", "24.00", "23.01", "Igor Pavlov", ""},
                                   {kNextDay, 2, "removed", "7-Zip", "24.00", "", "Igor Pavlov", ""}},
        [](const SoftwareEvent& e) -> std::vector<Cell> {
            return {I(e.ts), I(e.snapshot_id), T(e.action), T(e.name), T(e.version),
                    T(e.prev_version), T(e.publisher), T(e.install_date)};
        },
        [](EchoDatabase& db, const std::vector<SoftwareEvent>& ev) {
            REQUIRE(db.fold_software_events(ev));
        }));

    out.push_back(make_case(
        "arp",
        std::vector<ArpEvent>{{kT0, 1, "appeared", "en0", "10.0.0.1", "aa:bb:cc:dd:ee:ff", "dynamic"},
                              {kT0 + 90, 1, "removed", "en0", "10.0.0.1", "aa:bb:cc:dd:ee:ff", "dynamic"}},
        [](const ArpEvent& e) -> std::vector<Cell> {
            return {I(e.ts), I(e.snapshot_id), T(e.action), T(e.iface), T(e.ip_address),
                    T(e.mac_address), T(e.entry_type)};
        },
        [](EchoDatabase& db, const std::vector<ArpEvent>& ev) {
            REQUIRE(db.fold_arp_events(ev));
        }));

    out.push_back(make_case(
        "dns",
        std::vector<DnsEvent>{{kT0, 1, "appeared", "example.org", "A", "93.184.216.34", 300, "cache"},
                              {kT0 + 90, 1, "removed", "example.org", "A", "93.184.216.34", 0, "cache"}},
        [](const DnsEvent& e) -> std::vector<Cell> {
            return {I(e.ts), I(e.snapshot_id), T(e.action), T(e.name), T(e.record_type),
                    T(e.data), I(e.ttl_remaining_s), T(e.source)};
        },
        [](EchoDatabase& db, const std::vector<DnsEvent>& ev) {
            REQUIRE(db.fold_dns_events(ev));
        }));

    out.push_back(make_case(
        "netconn",
        std::vector<NetConnRow>{{kT0, 1, "wifi_connected", "wlan", "", "internet", "wifi", 0},
                                {kT0 + 60, 1, "wifi_disconnected", "wlan", "", "", "wifi", 5},
                                {kNextHour, 2, "wifi_connected", "wlan", "", "internet", "wifi", 0}},
        [](const NetConnRow& e) -> std::vector<Cell> {
            return {I(e.ts), I(e.snapshot_id), T(e.action), T(e.channel), T(e.category),
                    T(e.capability), T(e.iface_kind), I(e.reason_code)};
        },
        [](EchoDatabase& db, const std::vector<NetConnRow>& ev) {
            REQUIRE(db.fold_netconn_events(ev));
        }));

    out.push_back(make_case(
        "mapdrive",
        std::vector<MapDriveEvent>{
            {kT0, 1, "appeared", "outbound", "Z:", "\\\\srv\\share", "srv", "jsmith", "smb", "live"},
            {kT0 + 60, 1, "removed", "outbound", "Z:", "\\\\srv\\share", "srv", "jsmith", "smb", "live"},
            {kNextHour, 2, "historical", "outbound", "Y:", "\\\\old\\data", "old", "jsmith", "smb",
             "historical"}},
        [](const MapDriveEvent& e) -> std::vector<Cell> {
            return {I(e.ts), I(e.snapshot_id), T(e.action), T(e.direction), T(e.local_mount),
                    T(e.remote_path), T(e.remote_host), T(e.username), T(e.provider), T(e.origin)};
        },
        [](EchoDatabase& db, const std::vector<MapDriveEvent>& ev) {
            REQUIRE(db.fold_mapdrive_events(ev));
        }));

    // The cursor sources carry a record_key; the fresh side folds them through the replay ring.
    out.push_back(make_case(
        "power",
        std::vector<PowerEvent>{{kT0, 1, "sleep", "lid closed", "power:1"},
                                {kT0 + 600, 1, "wake", "lid opened", "power:2"},
                                {kNextHour, 2, "sleep", "idle", "power:3"}},
        [](const PowerEvent& e) -> std::vector<Cell> {
            return {I(e.ts), I(e.snapshot_id), T(e.action), T(e.detail), T(e.record_key)};
        },
        [](EchoDatabase& db, const std::vector<PowerEvent>& ev) {
            REQUIRE(db.insert_power_events_and_cursor(ev, "{}").has_value());
        }));

    out.push_back(make_case(
        "removable",
        std::vector<RemovableEvent>{
            removable(kT0, 1, "attached", "SER1", 1000000, "", 0, "e1", "rm:1"),
            removable(kT0 + 120, 1, "detached", "SER1", 1000000, "", 0, "e2", "rm:2"),
            removable(kNextHour, 2, "exec_from_removable", "SER1", 0, "E:\\a.exe", 77, "e3", "rm:3")},
        [](const RemovableEvent& e) -> std::vector<Cell> {
            return {I(e.ts), I(e.snapshot_id), T(e.action), T(e.device_key), T(e.vendor),
                    T(e.product), T(e.serial), T(e.bus), T(e.volume), I(e.size_bytes),
                    T(e.image_path), I(e.pid), T(e.evidence), T(e.record_key)};
        },
        [](EchoDatabase& db, const std::vector<RemovableEvent>& ev) {
            REQUIRE(db.insert_removable_events_and_cursor(ev, "{}").has_value());
        }));

    out.push_back(make_case(
        "registry",
        std::vector<RegistryEvent>{
            {kT0, 1, "HKLM", "SOFTWARE\\Run", "Updater", "added", "REG_SZ", "C:\\u.exe", 9, 0, "", "", 0, 0, 55, "u.exe", "notify", kT0 * 1000, "attr:ok", "reg:1"},
            {kT0 + 60, 1, "HKLM", "SOFTWARE\\Run", "Updater", "changed", "REG_SZ", "C:\\v.exe", 9, 0, "REG_SZ", "", 9, 0, 55, "u.exe", "notify", kT0 * 1000 + 60000, "attr:ok", "reg:2"},
            {kNextHour, 2, "HKLM", "SOFTWARE\\Run", "Updater", "removed", "", "", 0, 0, "REG_SZ", "", 9, 0, 0, "", "reconcile", 0, "attr:none", "reg:3"}},
        [](const RegistryEvent& e) -> std::vector<Cell> {
            return {I(e.ts), I(e.snapshot_id), T(e.hive), T(e.key_path), T(e.value_name),
                    T(e.action), T(e.data_type), T(e.data), I(e.data_size), I(e.data_truncated),
                    T(e.prev_data_type), T(e.prev_data), I(e.prev_data_size),
                    I(e.prev_data_truncated), I(e.actor_pid), T(e.actor_image), T(e.source),
                    I(e.observed_at), T(e.detail), T(e.record_key)};
        },
        [](EchoDatabase& db, const std::vector<RegistryEvent>& ev) {
            REQUIRE(db.insert_registry_events_and_cursor(ev, "{}", {}).has_value());
        }));

    return out;
}

// Every column a tier view exposes except `id` (the surrogate), in view order.
std::string view_columns(const FoldSourceDef& def, std::string_view tier) {
    std::string cols{ts_column_for_suffix(tier)};
    for (const auto& c : def.columns)
        cols += ", " + std::string{c.name};
    return cols;
}

// A source's tier view, ordered by every column so two databases compare row for row.
std::vector<QueryRow> tier_rows(EchoDatabase& db, const FoldSourceDef& def, std::string_view tier) {
    const auto cols = view_columns(def, tier);
    return q(db, std::format("SELECT {0} FROM {1} ORDER BY {0}", cols, fold_view_name(def.name, tier)));
}

std::vector<QueryRow> ring_rows(EchoDatabase& db, std::string_view source) {
    return q(db, std::format("SELECT record_key, digest, seq FROM {} WHERE source = '{}' "
                             "ORDER BY seq",
                             kSeenTable, source));
}

struct Seeded {
    yuzu::test::TempDbFile tmp{"yuzu_test_echo_v10_"};
};

fs::path seed(Seeded& s, const std::function<void(sqlite3*)>& fill) {
    Db raw;
    open_raw(raw, s.tmp.path);
    seed_schema(raw.db);
    fill(raw.db);
    return s.tmp.path;
}

EchoDatabase open_ok(const fs::path& p, const OpenSeams& seams = {}) {
    auto r = EchoDatabase::open(p, seams);
    INFO(std::string{r.has_value() ? "" : r.error()});
    REQUIRE(r.has_value());
    return std::move(*r);
}

bool has_table(sqlite3* db, const std::string& name, const char* type = "table") {
    return count_of(db, std::format("SELECT COUNT(*) FROM sqlite_master WHERE type='{}' AND name='{}'",
                                    type, name)) == 1;
}

} // namespace

TEST_CASE("v10 migration: every source converts exactly (differential against a fresh fold)",
          "[echo][v10][migration]") {
    Seeded seeded;
    const auto cases = all_cases();
    REQUIRE(cases.size() == 16); // every roll-up source
    seed(seeded, [&](sqlite3* db) {
        for (const auto& c : cases)
            c.seed_raw(db);
        // usage keeps its own tables: the migration must leave them alone
        exec(db, "INSERT INTO usage_live (ts, snapshot_id, action, pid, exe_key, user, start_ts) "
                 "VALUES (1793613600, 0, 'open', 7, 'alpha.exe', 'jsmith', 1793613600)");
        exec(db, "INSERT INTO echo_config VALUES ('usage_hwm_id', '42'), ('usage_lag_events', '3'), "
                 "('usage_gap_count', '1')");
    });

    auto migrated = open_ok(seeded.tmp.path);

    // the fresh side: the same events through the production deltas and the fold writer
    yuzu::test::TempDbFile fresh_tmp{"yuzu_test_echo_v10_fresh_"};
    auto fresh = open_ok(fresh_tmp.path);
    for (const auto& c : cases)
        c.fold_fresh(fresh);

    for (const auto& def : fold_sources()) {
        if (def.own_tables)
            continue;
        for (const auto tier : def.tiers) {
            INFO(def.name << " " << tier);
            const auto got = tier_rows(migrated, def, tier);
            const auto want = tier_rows(fresh, def, tier);
            CHECK(!want.empty());
            CHECK(got == want);
        }
        if (def.cursor_source) {
            INFO(def.name << " replay ring");
            // the migration seeds the ring with each source's migrated keys and digests
            CHECK(ring_rows(migrated, def.name) == ring_rows(fresh, def.name));
        }
    }

    // one dictionary row per distinct key text, exactly what the fresh fold interned
    CHECK(n(migrated, "SELECT COUNT(*) FROM echo_dict") == n(fresh, "SELECT COUNT(*) FROM echo_dict"));

    // the retired tables are gone, the shims and the tables the roll-up does not own remain
    Db check;
    migrated.checkpoint(CheckpointMode::kTruncate);
    open_raw(check, seeded.tmp.path);
    for (const auto& def : fold_sources()) {
        if (def.own_tables)
            continue;
        CHECK(!has_table(check.db, std::format("{}_live", def.name)));
        CHECK(has_table(check.db, std::format("{}_live", def.name), "view"));
        for (const auto tier : def.tiers) {
            CHECK(!has_table(check.db, fold_view_name(def.name, tier)));
            CHECK(has_table(check.db, fold_view_name(def.name, tier), "view"));
            CHECK(!has_table(check.db, fold_view_name(def.name, tier) + "_legacy"));
        }
    }
    CHECK(has_table(check.db, "usage_live"));
    CHECK(count_of(check.db, "SELECT COUNT(*) FROM usage_live") == 1);

    // marks, the usage cursor and the lag counter are gone; the version is stamped
    CHECK(migrated.get_config("schema_version") == "10");
    CHECK(migrated.get_config("usage_hwm_id", "absent") == "absent");
    CHECK(migrated.get_config("usage_lag_events", "absent") == "absent");
    CHECK(migrated.get_config("usage_gap_count") == "1"); // history the app_usage plugin still reads
}

TEST_CASE("v10 migration: raw rows below the rollup mark are not counted twice",
          "[echo][v10][migration]") {
    Seeded seeded;
    // Hour H0 was rolled up (mark = H0 + 1 h): its two raw rows are already in process_hourly. The
    // row at exactly the mark second and the one after it were NOT.
    seed(seeded, [&](sqlite3* db) {
        for (const auto ts : {kH0 + 10, kH0 + 20, kNextHour, kNextHour + 7})
            insert_raw(db, "process",
                       {I(ts), I(1), T("started"), I(1), I(0), T("alpha.exe"), T(""), T("jsmith")});
        exec(db, std::format("INSERT INTO process_hourly (hour_ts, name, user, start_count, stop_count) "
                             "VALUES ({}, 'alpha.exe', 'jsmith', 2, 0)",
                             kH0));
        exec(db, std::format("INSERT INTO echo_config VALUES ('rollup_process_hourly_at', '{}')",
                             kNextHour));
    });
    auto db = open_ok(seeded.tmp.path);
    // 2 (legacy hourly) + nothing from below the mark, in hour H0
    CHECK(n(db, std::format("SELECT start_count FROM process_hourly WHERE hour_ts = {}", kH0)) == 2);
    // the row AT the mark second and the one after it are folded (a mark is the first unrolled second)
    CHECK(n(db, std::format("SELECT start_count FROM process_hourly WHERE hour_ts = {}", kNextHour)) == 2);
    CHECK(n(db, "SELECT SUM(start_count) FROM process_hourly") == 4);
    // the daily tier holds the same total: the rolled hour came from the hourly->daily finish, the
    // unrolled rows from the fold (the daily mark was absent, so the hourly history folds in full)
    CHECK(n(db, "SELECT SUM(start_count) FROM process_daily") == 4);
}

TEST_CASE("v10 migration: a raw row with an unrepresentable stamp is counted as rejected, the rest fold",
          "[echo][v10][migration]") {
    Seeded seeded;
    seed(seeded, [&](sqlite3* db) {
        for (const auto ts : {kT0, kFoldMaxStamp + 1})
            insert_raw(db, "process",
                       {I(ts), I(1), T("started"), I(1), I(0), T("alpha.exe"), T(""), T("jsmith")});
    });
    auto db = open_ok(seeded.tmp.path);
    CHECK(db.get_config(std::string{kFoldRejectedCounterKey}) == "1");
    CHECK(n(db, "SELECT SUM(start_count) FROM process_hourly") == 1);
}

TEST_CASE("v10 migration: the roll-ups the aggregator had not performed are finished once",
          "[echo][v10][migration]") {
    Seeded seeded;
    const int64_t d0 = kH0 - kH0 % 86400;      // day of kH0
    const int64_t m0 = 1793491200;             // 2026-11-01
    seed(seeded, [&](sqlite3* db) {
        // hourly rows for day d0 (not yet in daily: daily mark = d0), a daily row in the month
        // (monthly mark = month end, so already in monthly), plus one daily row past the mark
        exec(db, std::format("INSERT INTO process_hourly VALUES (NULL, {}, 'a', 'u', 3, 1), (NULL, {}, 'a', 'u', 4, 2)",
                             d0 + 3600, d0 + 7200));
        exec(db, std::format("INSERT INTO process_daily VALUES (NULL, {}, 'a', 'u', 10, 5)", d0 - 86400));
        exec(db, std::format("INSERT INTO process_monthly VALUES (NULL, {}, 'a', 'u', 10, 5)", m0));
        exec(db, std::format("INSERT INTO echo_config VALUES ('rollup_process_hourly_at', '{0}'), "
                             "('rollup_process_daily_at', '{1}'), ('rollup_process_monthly_at', '{2}')",
                             d0 + 86400, d0, m0 + 86400 * 31));
    });
    auto db = open_ok(seeded.tmp.path);
    // daily: the old row (10, 5) plus the two hours folded in (7, 3) on day d0
    CHECK(n(db, std::format("SELECT start_count FROM process_daily WHERE day_ts = {}", d0)) == 7);
    CHECK(n(db, std::format("SELECT stop_count FROM process_daily WHERE day_ts = {}", d0)) == 3);
    CHECK(n(db, std::format("SELECT start_count FROM process_daily WHERE day_ts = {}", d0 - 86400)) == 10);
    // monthly: the old row (already containing d0 - 1 day's 10) plus the new day d0 (7): the
    // daily rows at or above the monthly mark... the mark is past both, so monthly is unchanged
    CHECK(n(db, std::format("SELECT start_count FROM process_monthly WHERE month_ts = {}", m0)) == 10);
}

TEST_CASE("v10 migration: a retired average comes back as a sum",
          "[echo][v10][migration]") {
    Seeded seeded;
    seed(seeded, [&](sqlite3* db) {
        exec(db, std::format("INSERT INTO perf_hourly (hour_ts, samples, cpu_avg, cpu_max, read_bps_avg, "
                             "read_lat_us_max) VALUES ({}, 4, 12.5, 40.0, 100, 9)",
                             kH0));
        exec(db, std::format("INSERT INTO procperf_hourly (hour_ts, name, version, is_kthread, samples, "
                             "instances_max, cpu_avg, cpu_max, ws_avg_bytes, ws_max_bytes) "
                             "VALUES ({}, 'chrome', '1.0', 0, 2, 3, 20.0, 30.0, 1000, 1500)",
                             kH0));
    });
    auto db = open_ok(seeded.tmp.path);
    CHECK(n(db, "SELECT cpu_sum FROM perf_hourly_r") == 50);          // 12.5 * 4
    CHECK(n(db, "SELECT read_bps_sum FROM perf_hourly_r") == 400);    // 100 * 4
    CHECK(n(db, "SELECT samples FROM perf_hourly_r") == 4);
    // the view's own average is the original again
    CHECK(q(db, "SELECT cpu_avg FROM perf_hourly")[0][0] == "12.5");
    CHECK(n(db, "SELECT read_bps_avg FROM perf_hourly") == 100);
    CHECK(n(db, "SELECT ws_sum FROM procperf_hourly_r") == 2000);     // 1000 * 2
    CHECK(n(db, "SELECT ws_avg_bytes FROM procperf_hourly") == 1000);
    CHECK(n(db, "SELECT cpu_max FROM perf_hourly") == 40);
    // no duplicate: perf had no daily tier before, so it is built from the hourly history
    CHECK(n(db, "SELECT samples FROM perf_daily") == 4);
}

TEST_CASE("v10 migration: shim views answer a retired $X_Live query with no rows and no error",
          "[echo][v10][migration][shim]") {
    Seeded seeded;
    seed(seeded, [&](sqlite3* db) {
        insert_raw(db, "process", {I(kT0), I(1), T("started"), I(1), I(0), T("a.exe"), T(""), T("u")});
    });
    auto db = open_ok(seeded.tmp.path);

    const auto sql = validate_and_translate_sql("SELECT * FROM $Process_Live");
    REQUIRE(sql.has_value());
    const auto r = db.execute_user_query(*sql);
    REQUIRE(r.has_value()); // not an error
    CHECK(r->rows.empty());
    // the legacy columns, `id` first, in the order the raw table declared them
    std::vector<std::string> want{"id"};
    for (const auto& c : legacy_live_columns("process"))
        want.emplace_back(c.name);
    CHECK(r->columns == want);
    CHECK(columns_for_table("process_live") == want);

    // every one of the 16 names, a COUNT(*) as well
    for (const auto& name : legacy_live_shim_names()) {
        const auto r2 = db.execute_user_query(std::format("SELECT COUNT(*) FROM {}", name));
        INFO(name);
        REQUIRE(r2.has_value());
        CHECK(r2->rows[0][0] == "0");
    }
    // usage_live is still a table, and still denied to operator SQL (#4260)
    Db check;
    db.checkpoint(CheckpointMode::kTruncate);
    open_raw(check, seeded.tmp.path);
    CHECK(has_table(check.db, "usage_live"));
    CHECK(!db.execute_user_query("SELECT * FROM usage_live").has_value());
}

TEST_CASE("v10 migration: a migrated database opens again and creates its warehouse tables",
          "[echo][v10][migration]") {
    Seeded seeded;
    seed(seeded, [&](sqlite3* db) {
        insert_raw(db, "process", {I(kT0), I(1), T("started"), I(1), I(0), T("a.exe"), T(""), T("u")});
    });
    {
        auto first = open_ok(seeded.tmp.path);
        CHECK(first.get_config("schema_version") == "10");
    }
    auto second = open_ok(seeded.tmp.path);
    // create_warehouse_tables() runs on every open: it must not attempt an index on a view
    CHECK(second.create_warehouse_tables());
    CHECK(second.get_config("schema_version") == "10");
    CHECK(n(second, "SELECT SUM(start_count) FROM process_hourly") == 1);
}

TEST_CASE("v10 migration: a fault after the drops rolls everything back and the retry succeeds",
          "[echo][v10][migration][rollback]") {
    Seeded seeded;
    const auto cases = all_cases();
    seed(seeded, [&](sqlite3* db) {
        for (const auto& c : cases)
            c.seed_raw(db);
        exec(db, std::format("INSERT INTO process_hourly VALUES (NULL, {}, 'a', 'u', 3, 1)", kH0));
    });

    {
        OpenSeams seams;
        bool faulted = false;
        seams.v10_after_drop = [&]() -> std::expected<void, std::string> {
            faulted = true;
            return std::unexpected("injected fault after the DROP TABLE statements");
        };
        const auto failed = EchoDatabase::open(seeded.tmp.path, seams);
        REQUIRE(faulted);
        REQUIRE(!failed.has_value());
        CHECK(failed.error().find("injected fault") != std::string::npos);
    }

    // The file is exactly the v9 database: version, every retired table and its rows, no roll-up.
    {
        Db check;
        open_raw(check, seeded.tmp.path);
        CHECK(count_of(check.db, "SELECT value FROM echo_config WHERE key = 'schema_version'") == 9);
        for (const auto& def : fold_sources()) {
            if (def.own_tables)
                continue;
            INFO(def.name);
            CHECK(has_table(check.db, std::format("{}_live", def.name)));
            CHECK(count_of(check.db, std::format("SELECT COUNT(*) FROM {}_live", def.name)) >= 2);
        }
        CHECK(has_table(check.db, "process_hourly"));
        CHECK(count_of(check.db, "SELECT COUNT(*) FROM process_hourly") == 1);
        CHECK(!has_table(check.db, "echo_dict"));
        CHECK(!has_table(check.db, "process_hourly_r"));
        CHECK(!has_table(check.db, "process_live", "view"));
    }

    // the next open redoes the whole step
    auto db = open_ok(seeded.tmp.path);
    CHECK(db.get_config("schema_version") == "10");
    CHECK(n(db, "SELECT SUM(start_count) FROM process_hourly") == 3 + 2); // 3 in the old tier + 2 started raw rows
}

TEST_CASE("v10 migration: a volume with less than twice the file free refuses and changes nothing",
          "[echo][v10][migration][free_space]") {
    Seeded seeded;
    seed(seeded, [&](sqlite3* db) {
        insert_raw(db, "process", {I(kT0), I(1), T("started"), I(1), I(0), T("a.exe"), T(""), T("u")});
    });
    const auto size_before = fs::file_size(seeded.tmp.path);

    OpenSeams tight;
    tight.free_bytes = [](const fs::path&) -> std::optional<std::uintmax_t> { return 1000; };
    const auto refused = EchoDatabase::open(seeded.tmp.path, tight);
    REQUIRE(!refused.has_value());
    CHECK(is_free_space_refusal(refused.error()));
    CHECK(refused.error().find("1000 bytes are free") != std::string::npos); // both figures named
    CHECK(refused.error().find("are needed") != std::string::npos);
    // untouched: the same size, version 9, the raw table with its row
    Db check;
    open_raw(check, seeded.tmp.path);
    CHECK(count_of(check.db, "SELECT value FROM echo_config WHERE key = 'schema_version'") == 9);
    CHECK(count_of(check.db, "SELECT COUNT(*) FROM process_live") == 1);
    CHECK(!has_table(check.db, "echo_dict"));
    CHECK(fs::file_size(seeded.tmp.path) >= size_before); // WAL mode may append to nothing, never shrink

    // and it succeeds once the space is there
    OpenSeams roomy;
    roomy.free_bytes = [](const fs::path&) -> std::optional<std::uintmax_t> {
        return std::uintmax_t{1} << 40;
    };
    auto db = open_ok(seeded.tmp.path, roomy);
    CHECK(db.get_config("schema_version") == "10");
}

TEST_CASE("v10 migration: the VACUUM runs when there is room and is deferred when there is not",
          "[echo][v10][migration][free_space]") {
    const auto seed_it = [](Seeded& s) {
        seed(s, [&](sqlite3* db) {
            insert_raw(db, "process", {I(kT0), I(1), T("started"), I(1), I(0), T("a.exe"), T(""), T("u")});
        });
    };
    {
        Seeded s;
        seed_it(s);
        OpenSeams seams;
        seams.free_bytes = [](const fs::path&) -> std::optional<std::uintmax_t> { return kRoomy; };
        auto db = open_ok(s.tmp.path, seams);
        CHECK(db.storage_bytes().auto_vacuum == 2); // converted to incremental
        CHECK(db.get_config("auto_vacuum_deferred_at", "absent") == "absent");
    }
    {
        // room for the migration (first check), none for the VACUUM copy (second check)
        Seeded s;
        seed_it(s);
        OpenSeams seams;
        int calls = 0;
        seams.free_bytes = [&calls](const fs::path&) -> std::optional<std::uintmax_t> {
            return ++calls == 1 ? kRoomy : std::uintmax_t{10};
        };
        auto db = open_ok(s.tmp.path, seams);
        CHECK(calls == 2);
        CHECK(db.get_config("schema_version") == "10");
        CHECK(db.storage_bytes().auto_vacuum != 2);          // not converted
        CHECK(db.get_config("auto_vacuum_deferred_at", "absent") != "absent"); // retried daily
    }
}

TEST_CASE("v10 migration: a cursor source's recent keys are replays, a reused key is a collision",
          "[echo][v10][migration][cursor]") {
    Seeded seeded;
    const std::vector<PowerEvent> ev{{kT0, 1, "sleep", "lid closed", "power:1"},
                                     {kT0 + 600, 1, "wake", "lid opened", "power:2"}};
    seed(seeded, [&](sqlite3* db) {
        for (const auto& e : ev)
            insert_raw(db, "power", {I(e.ts), I(e.snapshot_id), T(e.action), T(e.detail), T(e.record_key)});
    });
    auto db = open_ok(seeded.tmp.path);
    CHECK(n(db, "SELECT SUM(event_count) FROM power_hourly") == 2);

    // the same record re-offered after the upgrade: a replay, folded once
    REQUIRE(db.insert_power_events_and_cursor({ev[0]}, "{}").has_value());
    CHECK(n(db, "SELECT SUM(event_count) FROM power_hourly") == 2);

    // the same key with different content: the permanent collision error
    PowerEvent clash = ev[0];
    clash.detail = "something else";
    const auto bad = db.insert_power_events_and_cursor({clash}, "{}");
    REQUIRE(!bad.has_value());
    CHECK(bad.error() == EchoDatabase::CursorInsertError::KeyCollision);

    // purge_source clears the ring: the key is a first sighting again
    REQUIRE(db.purge_source("power").has_value());
    CHECK(n(db, "SELECT COUNT(*) FROM echo_fold_seen WHERE source = 'power'") == 0);
    REQUIRE(db.insert_power_events_and_cursor({ev[0]}, "{}").has_value());
    CHECK(n(db, "SELECT SUM(event_count) FROM power_hourly") == 1);
}

TEST_CASE("v10 migration: a fresh database gets the roll-up schema directly",
          "[echo][v10][migration]") {
    yuzu::test::TempDbFile tmp{"yuzu_test_echo_v10_fresh_"};
    auto db = open_ok(tmp.path);
    CHECK(db.get_config("schema_version") == "10");
    Db check;
    open_raw(check, tmp.path);
    CHECK(has_table(check.db, "process_hourly", "view"));
    CHECK(has_table(check.db, "process_hourly_r"));
    CHECK(has_table(check.db, "process_live", "view"));
    CHECK(!has_table(check.db, "process_live"));
    CHECK(has_table(check.db, "usage_live"));
    CHECK(has_table(check.db, "netqual_boot"));
}

TEST_CASE("v10 migration: the free-space refusal is told apart from every other open failure",
          "[echo][v10][migration][status]") {
    CHECK(is_free_space_refusal(
        "v10 roll-up migration failed (the schema stays at v9; the retired tables are intact): "
        "not enough free disk space to migrate the Echo database to its roll-up tables: 10 bytes are free"));
    CHECK(!is_free_space_refusal("failed to open echo.db: unable to open database file"));
    const auto lines = format_storage_refused_lines("not enough free disk space to migrate x");
    REQUIRE(lines.size() == 2);
    CHECK(lines[0].starts_with("error|")); // the server gates on a leading error|
    CHECK(lines[1] == "storage_state|offline|free_space");
}
