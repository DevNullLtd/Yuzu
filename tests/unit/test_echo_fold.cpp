/**
 * test_echo_fold.cpp -- the roll-up substrate: bucket math, the tier accumulator,
 * the 17 deltas, the generated schema, the transactional fold writer, the replay
 * ring, dictionary GC and the operator-SQL boundary.
 *
 * Roll-up is the only storage model; none of this is wired into open(). Fixtures
 * are in-process: a raw :memory: handle for DDL-only cases, a temp-file
 * EchoDatabase (yuzu_test_ prefix, shared helper) wherever the fold writer or the
 * read-only query connection is involved. Nothing polls; the one bounded negative wait
 * (150 ms) can only false-pass. The GC deadline is driven by an injected clock.
 */

#include "echo_collectors.hpp"
#include "echo_db.hpp"
#include "echo_fold.hpp"
#include "echo_fold_schema.hpp"
#include "echo_schema_registry.hpp"
#include "echo_sql_executor.hpp"
#include "test_helpers.hpp"

#include <sqlite3.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <future>
#include <latch>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::echo;

namespace {

constexpr int64_t kT0 = 1793615400;     // 2026-11-02T10:30:00Z
constexpr int64_t kHour0 = 1793613600;  // 2026-11-02T10:00:00Z
constexpr int64_t kDay0 = 1793577600;   // 2026-11-02T00:00:00Z
constexpr int64_t kMonth0 = 1793491200; // 2026-11-01T00:00:00Z
constexpr int64_t kLo = -62135596800LL;
constexpr int64_t kHi = 253402300799LL;

// ── Fixtures ────────────────────────────────────────────────────────────────

// A raw :memory: handle for DDL-only cases. The owner closes it on scope exit, so a fatal
// REQUIRE after the open cannot leak it.
using Mem = yuzu::test::SqliteHandleOwner<sqlite3>;

void open_mem(Mem& m) {
    REQUIRE(sqlite3_open(":memory:", &m.db) == SQLITE_OK);
}

// A prepared statement that is finalised on every exit, including a fatal REQUIRE.
struct StmtFinalizer {
    void operator()(sqlite3_stmt* s) const { sqlite3_finalize(s); }
};
using Stmt = std::unique_ptr<sqlite3_stmt, StmtFinalizer>;

Stmt prepare(sqlite3* db, const std::string& sql) {
    sqlite3_stmt* raw = nullptr;
    const int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &raw, nullptr);
    Stmt st{raw};
    REQUIRE(rc == SQLITE_OK);
    return st;
}

bool exec(sqlite3* db, const std::string& sql) {
    char* raw = nullptr;
    const int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &raw);
    const std::unique_ptr<char, decltype(&sqlite3_free)> err{raw, &sqlite3_free};
    UNSCOPED_INFO("sqlite: " << (err ? err.get() : "")); // INFO would pop before the caller asserts
    return rc == SQLITE_OK;
}

// All rows of `sql`, each cell as text ("NULL" for NULL).
std::vector<std::vector<std::string>> rows(sqlite3* db, const std::string& sql) {
    std::vector<std::vector<std::string>> out;
    const Stmt st = prepare(db, sql);
    while (sqlite3_step(st.get()) == SQLITE_ROW) {
        std::vector<std::string> r;
        for (int i = 0; i < sqlite3_column_count(st.get()); ++i) {
            const auto* t = reinterpret_cast<const char*>(sqlite3_column_text(st.get(), i));
            r.emplace_back(t ? std::string(t, static_cast<size_t>(sqlite3_column_bytes(st.get(), i)))
                             : "NULL");
        }
        out.push_back(std::move(r));
    }
    return out;
}

int64_t count(sqlite3* db, const std::string& sql) {
    const auto r = rows(db, sql);
    REQUIRE(r.size() == 1);
    return std::stoll(r[0][0]);
}

// A temp-file EchoDatabase with the roll-up schema installed.
struct FoldDb {
    yuzu::test::TempDbFile tmp; // first member: destroyed last, after the database has closed
    EchoDatabase db;
    EchoFold fold;
    explicit FoldDb(EchoDatabase d, fs::path p, EchoFold::NowFn now = nullptr)
        : tmp(std::move(p)), db(std::move(d)), fold(std::move(now)) {}
    int64_t n(const std::string& sql) {
        const auto r = db.execute_query(sql);
        REQUIRE(r.has_value());
        REQUIRE(r->rows.size() == 1);
        return std::stoll(r->rows[0][0]);
    }
    std::vector<QueryRow> q(const std::string& sql) {
        const auto r = db.execute_query(sql);
        REQUIRE(r.has_value());
        return r->rows;
    }
};

std::unique_ptr<FoldDb> make_fold_db(bool install = true, EchoFold::NowFn now = nullptr) {
    const auto path = yuzu::test::unique_temp_path("yuzu_test_echo_fold_");
    auto opened = EchoDatabase::open(path);
    REQUIRE(opened.has_value());
    auto f = std::make_unique<FoldDb>(std::move(*opened), path, std::move(now));
    if (install)
        REQUIRE(f->fold.install_fold_schema(f->db).has_value());
    return f;
}

// Every interned `<key>_id` of every `_r` table joins to a dictionary row, and every
// view exposes exactly its table's rows. Returns the number of violations.
int64_t integrity_violations(FoldDb& f) {
    int64_t bad = 0;
    for (const auto& def : fold_sources()) {
        if (def.own_tables)
            continue;
        for (auto tier : def.tiers) {
            const auto table = physical_table_name(def.name, tier);
            for (const auto& c : def.columns)
                if (c.interned)
                    bad += f.n("SELECT COUNT(*) FROM " + table + " r LEFT JOIN echo_dict d ON d.id = r." +
                               physical_column_name(c) + " WHERE d.id IS NULL");
            const auto tr = f.n("SELECT COUNT(*) FROM " + table);
            const auto vr = f.n("SELECT COUNT(*) FROM " + fold_view_name(def.name, tier));
            if (tr != vr)
                ++bad;
        }
    }
    return bad;
}

ProcessEvent pev(int64_t ts, const char* action, const char* name, const char* user = "u") {
    ProcessEvent e;
    e.ts = ts;
    e.action = action;
    e.name = name;
    e.user = user;
    return e;
}

TierAccumulator make_acc(std::string_view src) {
    const FoldSourceDef* def = fold_source(src);
    REQUIRE(def != nullptr);
    return TierAccumulator(*def);
}

std::string to_str(const Value& v) {
    if (const auto* s = std::get_if<std::string>(&v))
        return *s;
    if (const auto* i = std::get_if<int64_t>(&v))
        return std::to_string(*i);
    return std::to_string(std::get<double>(v));
}

// The row of `tier` whose named keys equal the given text values.
TierRow row_for(const TierAccumulator& acc, std::string_view tier,
                std::initializer_list<std::pair<std::string_view, std::string>> keys) {
    for (const auto& r : acc.rows(tier)) {
        bool match = true;
        for (const auto& [name, want] : keys) {
            const Value* v = acc.key(r, name);
            if (!v || to_str(*v) != want)
                match = false;
        }
        if (match)
            return r;
    }
    FAIL("no row for the requested keys in tier " << tier);
    return {};
}

int64_t mi(const TierAccumulator& a, const TierRow& r, std::string_view n) {
    const Value* v = a.measure(r, n);
    REQUIRE(v != nullptr);
    return std::get<int64_t>(*v);
}
double md(const TierAccumulator& a, const TierRow& r, std::string_view n) {
    const Value* v = a.measure(r, n);
    REQUIRE(v != nullptr);
    return std::get<double>(*v);
}
std::string ms(const TierAccumulator& a, const TierRow& r, std::string_view n) {
    const Value* v = a.measure(r, n);
    REQUIRE(v != nullptr);
    return std::get<std::string>(*v);
}
std::string ks(const TierAccumulator& a, const TierRow& r, std::string_view n) {
    const Value* v = a.key(r, n);
    REQUIRE(v != nullptr);
    return to_str(*v);
}

// Every named measure of `r` is zero / empty (the enrichment columns).
void check_zero(const TierAccumulator& a, const TierRow& r, std::initializer_list<std::string_view> names) {
    for (auto n : names) {
        INFO("column " << n);
        const Value* v = a.measure(r, n);
        if (!v)
            v = a.key(r, n);
        REQUIRE(v != nullptr);
        CHECK((to_str(*v) == "0" || to_str(*v).empty() || to_str(*v) == "0.000000"));
    }
}

} // namespace

// ═════════════════════════════════════════════════════════════════════════════
// Bucket math
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("bucket_start: hour and day floor division, negative stamps included",
          "[echo][fold][bucket]") {
    struct Row { int64_t ts, hour, day; };
    for (const Row& r : {Row{-1, -3600, -86400}, Row{0, 0, 0}, Row{3599, 0, 0}, Row{3600, 3600, 0}}) {
        INFO("ts " << r.ts);
        CHECK(bucket_start(r.ts, "hourly").value() == r.hour);
        CHECK(bucket_start(r.ts, "daily").value() == r.day);
    }
}

TEST_CASE("bucket_start: calendar month, including a stamp before 1970", "[echo][fold][bucket]") {
    CHECK(bucket_start(1775001599, "monthly").value() == 1772323200);  // 2026-03-31T23:59:59Z -> 2026-03-01
    CHECK(bucket_start(1793491200, "monthly").value() == 1793491200);  // a month start is its own bucket
    CHECK(bucket_start(-1, "monthly").value() == -2678400);            // 1969-12-31 -> 1969-12-01
}

TEST_CASE("bucket_start: the representable domain edges bucket exactly", "[echo][fold][bucket]") {
    CHECK(bucket_start(kLo, "hourly").value() == kLo);
    CHECK(bucket_start(kLo, "daily").value() == kLo);
    CHECK(bucket_start(kLo, "monthly").value() == kLo);
    CHECK(bucket_start(kHi, "hourly").value() == 253402297200);
    CHECK(bucket_start(kHi, "daily").value() == 253402214400);
    CHECK(bucket_start(kHi, "monthly").value() == 253399622400);
}

TEST_CASE("bucket_start: a stamp outside the domain is refused and named", "[echo][fold][bucket]") {
    for (int64_t ts : {kLo - 1, kHi + 1, std::numeric_limits<int64_t>::min(),
                       std::numeric_limits<int64_t>::max()}) {
        for (const char* tier : {"hourly", "daily", "monthly"}) {
            INFO("ts " << ts << " tier " << tier);
            const auto r = bucket_start(ts, tier);
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error().find(std::to_string(ts)) != std::string::npos);
        }
    }
    CHECK_FALSE(bucket_start(0, "weekly").has_value());
}

TEST_CASE("TierAccumulator: an unrepresentable stamp rejects that event only",
          "[echo][fold][bucket]") {
    auto acc = make_acc("process");
    process_delta({pev(kT0, "started", "a.exe"), pev(std::numeric_limits<int64_t>::max(), "started", "b.exe"),
                   pev(kLo - 1, "started", "c.exe"), pev(kT0 + 5, "started", "d.exe")},
                  acc);
    CHECK(acc.rejected() == 2);
    CHECK(acc.first_rejected_stamp() == std::numeric_limits<int64_t>::max());
    CHECK(acc.rows("hourly").size() == 2); // a.exe and d.exe folded; b and c did not
    CHECK(acc.rows("monthly").size() == 2);
}

TEST_CASE("TierAccumulator: a sum saturates; a non-finite measure rejects that event only",
          "[echo][fold][merge]") {
    constexpr auto kMax = std::numeric_limits<int64_t>::max();
    constexpr auto kMin = std::numeric_limits<int64_t>::min();
    auto acc = make_acc("process");
    using P = std::pair<const char*, int64_t>;
    for (const auto& [name, n] : {P{"hi", kMax}, P{"hi", 1}, P{"lo", kMin}, P{"lo", -1}})
        acc.add(kT0, {{"name", vt(name)}, {"user", vt("u")}}, {{"start_count", vi(n)}});
    CHECK(mi(acc, row_for(acc, "hourly", {{"name", "hi"}}), "start_count") == kMax);
    CHECK(mi(acc, row_for(acc, "hourly", {{"name", "lo"}}), "start_count") == kMin);

    auto perf = make_acc("perf");
    const auto cpu = [&](int64_t ts, double v) { return perf.add(ts, {}, {{"cpu_sum", vr(v)}}); };
    CHECK(cpu(kT0, 0.5));
    CHECK_FALSE(cpu(kT0 + 1, std::nan("")));
    CHECK_FALSE(cpu(kT0 + 2, std::numeric_limits<double>::infinity()));
    CHECK(cpu(kT0 + 3, 0.25));
    CHECK(perf.rejected() == 2);
    CHECK(perf.first_rejected_stamp() == kT0 + 1);
    CHECK(md(perf, perf.rows("hourly")[0], "cpu_sum") == 0.75);
}

// ═════════════════════════════════════════════════════════════════════════════
// Registry types and the per-source declarations
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("ColumnDef: a plain {name, type} initialiser keeps its old meaning", "[echo][fold][schema]") {
    constexpr ColumnDef c{"ts", "INTEGER"};
    static_assert(c.role == ColumnRole::kMeasure);
    static_assert(c.merge == MergeOp::kNone);
    static_assert(!c.interned);
    CHECK(c.generated_expr.empty());
    CHECK(c.guard.empty());
}

TEST_CASE("fold_sources: 1:1 with the registry, internally consistent", "[echo][fold][schema]") {
    const auto& reg = capture_sources();
    const auto& fold = fold_sources();
    REQUIRE(fold.size() == 17);
    REQUIRE(fold.size() == reg.size());
    const std::set<std::string_view> tiers_ok{"hourly", "daily", "monthly"};
    for (std::size_t i = 0; i < fold.size(); ++i) {
        const auto& d = fold[i];
        INFO("source " << d.name);
        CHECK(d.name == reg[i].name);
        CHECK(fold_source(d.name) == &d);
        REQUIRE_FALSE(d.tiers.empty());
        for (auto t : d.tiers)
            CHECK(tiers_ok.contains(t));
        CHECK(d.cursor_source == (d.name == "power" || d.name == "removable" || d.name == "registry"));
        CHECK(d.own_tables == (d.name == "usage"));

        std::set<std::string_view> names;
        for (const auto& c : d.columns)
            CHECK(names.insert(c.name).second); // no duplicate column
        for (const auto& c : d.columns) {
            INFO("column " << c.name);
            if (c.interned) {
                CHECK(c.role == ColumnRole::kKey);
                CHECK(c.sql_type == "TEXT");
            }
            if (c.role == ColumnRole::kKey && c.sql_type == "TEXT" && !d.own_tables)
                CHECK(c.interned);
            if (c.merge == MergeOp::kLast) {
                const auto g = std::find_if(d.columns.begin(), d.columns.end(),
                                            [&](const ColumnDef& x) { return x.name == c.guard; });
                REQUIRE(g != d.columns.end());
                CHECK(g->sql_type == "INTEGER");
                CHECK(g->role == ColumnRole::kMeasure);
                CHECK(g->merge == MergeOp::kMax); // the guard itself only ever moves forward
            }
            if (c.role == ColumnRole::kGenerated) {
                const std::string expr{c.generated_expr};
                CHECK(expr.find("samples") != std::string::npos);
                CHECK(names.contains("samples"));
                bool sum_found = false;
                for (const auto& s : d.columns)
                    if (s.name.ends_with("_sum") && expr.find(s.name) != std::string::npos)
                        sum_found = true;
                CHECK(sum_found);
            }
        }
    }
    CHECK(fold_source("usage")->own_tables);
    CHECK(fold_source("nope") == nullptr);
}

TEST_CASE("fold_sources: key and measure lists are the pinned contract", "[echo][fold][schema]") {
    struct Pin {
        std::string_view name;
        std::vector<std::string_view> keys, measures;
    };
    // The contract. Keys keep the registry's existing order where the registry already
    // declares the tier (so process keys read name, user, parent_name); measures list the
    // generated *_avg columns where the existing view order interleaves them.
    const std::vector<Pin> pins = {
        {"process", {"name", "user", "parent_name"},
         {"start_count", "stop_count", "abnormal_exit_count", "elevated_count", "spoofed_parent_count"}},
        {"tcp", {"remote_addr", "remote_port", "proto", "process_name"},
         {"connect_count", "disconnect_count", "failed_count", "duration_s_sum", "listen_open_count",
          "listen_close_count"}},
        {"service", {"name"},
         {"status_changes", "last_status", "install_count", "remove_count", "last_ts", "last_exit_code",
          "last_start_account", "last_binary_path", "failed_count"}},
        {"user", {"user", "domain", "logon_type"},
         {"login_count", "logout_count", "disconnect_count", "session_s_sum"}},
        {"perf", {},
         {"samples", "cpu_avg", "cpu_max", "mem_avg", "mem_max", "commit_avg", "read_bps_avg",
          "write_bps_avg", "read_lat_us_avg", "write_lat_us_avg", "read_lat_us_max", "write_lat_us_max",
          "rx_bps_avg", "tx_bps_avg", "cpu_sum", "mem_sum", "commit_sum", "read_bps_sum", "write_bps_sum",
          "read_lat_us_sum", "write_lat_us_sum", "rx_bps_sum", "tx_bps_sum", "cpu_kernel_sum",
          "rx_bps_max", "tx_bps_max", "procs_sum", "threads_sum", "handles_sum"}},
        {"procperf", {"name", "version", "is_kthread"},
         {"samples", "instances_max", "cpu_avg", "cpu_max", "ws_avg_bytes", "ws_max_bytes", "cpu_sum",
          "ws_sum", "private_bytes_max", "handles_max", "threads_max", "io_read_bytes_sum",
          "io_write_bytes_sum"}},
        {"netqual", {"proto", "remote_bucket", "process_name"},
         {"samples", "rtt_us_sum", "rtt_us_max", "rtt_us_min", "rtt_var_us_sum", "lost_sum", "lost_max",
          "degraded_samples", "bytes_in_sum", "bytes_out_sum"}},
        {"module", {"module_name", "signer", "signed_state", "is_kernel", "module_dir", "process_name"},
         {"load_count", "blocked_count", "rebased_count"}},
        {"software", {"name", "version", "publisher", "arch"},
         {"install_count", "remove_count", "upgrade_count", "downgrade_count"}},
        {"arp", {"interface", "ip_address", "mac_address", "is_router"},
         {"appear_count", "remove_count", "rebind_count"}},
        {"dns", {"name", "record_type", "data"}, {"appear_count", "remove_count", "negative_count"}},
        {"netconn",
         {"action", "channel", "category", "capability", "iface_kind", "reason_code", "phy_type", "auth_alg",
          "cipher_alg"},
         {"event_count", "last_ts"}},
        {"mapdrive", {"direction", "local_mount", "remote_path", "remote_host"},
         {"appear_count", "remove_count", "historical_count", "first_ts", "last_ts", "last_dialect",
          "guest_count"}},
        {"power", {"action", "resume_kind", "source"}, {"event_count", "last_ts", "last_detail"}},
        {"removable", {"action", "device_key", "vendor", "product", "serial", "bus", "volume", "image_path"},
         {"event_count", "first_ts", "last_ts", "size_bytes", "disk_id", "partition_count"}},
        {"registry", {"hive", "key_path", "value_name", "action"},
         {"change_count", "last_data", "last_data_type", "last_actor_image", "last_ts"}},
        {"usage", {"exe_key"},
         {"run_count", "total_seconds", "first_seen", "last_seen", "distinct_users", "superseded_runs",
          "expired_runs", "max_run_s", "min_run_s", "short_run_count", "peak_instances",
          "launched_by_exe_key"}},
    };
    REQUIRE(pins.size() == 17);
    for (const auto& p : pins) {
        INFO("source " << p.name);
        const FoldSourceDef* d = fold_source(p.name);
        REQUIRE(d != nullptr);
        std::vector<std::string_view> keys, measures;
        for (const auto& c : d->columns)
            (c.role == ColumnRole::kKey ? keys : measures).push_back(c.name);
        CHECK(keys == p.keys);
        CHECK(measures == p.measures);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Generated DDL
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("generate_fold_ddl: tables, indexes and views are exactly what the declarations say",
          "[echo][fold][schema]") {
    Mem m;
    open_mem(m);
    REQUIRE(exec(m.db, generate_fold_ddl()));
    REQUIRE(exec(m.db, generate_fold_ddl())); // idempotent

    int64_t tiers = 0;
    for (const auto& d : fold_sources())
        if (!d.own_tables)
            tiers += static_cast<int64_t>(d.tiers.size());
    CHECK(tiers == 34); // pinned: a tier added or dropped is a deliberate edit
    // + the dictionary, the replay ring and sqlite_sequence (the dictionary id never reuses a value).
    CHECK(count(m.db, "SELECT COUNT(*) FROM sqlite_master WHERE type='table'") == tiers + 3);
    CHECK(count(m.db, "SELECT COUNT(*) FROM sqlite_master WHERE sql LIKE '%AUTOINCREMENT%'") == 1);
    CHECK(count(m.db, "SELECT COUNT(*) FROM sqlite_master WHERE type='view'") == tiers);
    CHECK(count(m.db, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'usage%'") == 0);

    for (const auto& d : fold_sources()) {
        if (d.own_tables)
            continue;
        for (auto tier : d.tiers) {
            const auto table = physical_table_name(d.name, tier);
            INFO("table " << table);
            // Exactly one UNIQUE index, bucket column first.
            const auto idx = rows(m.db, "SELECT name FROM pragma_index_list('" + table + "') WHERE \"unique\"=1");
            REQUIRE(idx.size() == 1);
            CHECK(idx[0][0] == table + "_uq");
            const auto first = rows(m.db, "SELECT name FROM pragma_index_info('" + idx[0][0] + "') WHERE seqno=0");
            REQUIRE(first.size() == 1);
            CHECK(first[0][0] == std::string{ts_column_for_suffix(tier)});
        }
    }
    const auto digest = rows(m.db, "SELECT \"notnull\" FROM pragma_table_info('echo_fold_seen') WHERE name='digest'");
    REQUIRE(digest.size() == 1);
    CHECK(digest[0][0] == "1");

    // Every view is a WHERE-less single-table projection: no JOIN, no row filter, and
    // the only WHERE is the one inside each correlated dictionary lookup. The authorizer
    // lets a column-less read of a `_r` table through because its row count is exactly
    // the view's; a filter or a JOIN in a view would turn that count into an oracle.
    for (const auto& d : fold_sources()) {
        if (d.own_tables)
            continue;
        std::size_t interned = 0;
        for (const auto& c : d.columns)
            interned += c.interned ? 1 : 0;
        for (auto tier : d.tiers) {
            const auto view = fold_view_name(d.name, tier);
            INFO("view " << view);
            const auto sql = rows(m.db, "SELECT sql FROM sqlite_master WHERE type='view' AND name='" + view + "'");
            REQUIRE(sql.size() == 1);
            const std::string& v = sql[0][0];
            CHECK(v.find(" JOIN ") == std::string::npos);
            CHECK(v.ends_with(" FROM " + physical_table_name(d.name, tier) + " r"));
            std::size_t wheres = 0;
            for (auto pos = v.find(" WHERE "); pos != std::string::npos; pos = v.find(" WHERE ", pos + 1))
                ++wheres;
            CHECK(wheres == interned);
        }
    }
}

TEST_CASE("generate_fold_ddl: every view keeps the registry's columns first, in order, with the same types",
          "[echo][fold][schema]") {
    Mem m;
    open_mem(m);
    REQUIRE(exec(m.db, generate_fold_ddl()));
    int checked = 0;
    for (const auto& src : capture_sources()) {
        const FoldSourceDef* d = fold_source(src.name);
        REQUIRE(d != nullptr);
        for (const auto& g : src.granularities) {
            if (g.suffix == "live" || g.suffix == "boot" || d->own_tables)
                continue;
            REQUIRE(std::find(d->tiers.begin(), d->tiers.end(), g.suffix) != d->tiers.end());
            const auto view = fold_view_name(src.name, g.suffix);
            INFO("view " << view);
            const auto info = rows(m.db, "SELECT name, type FROM pragma_table_info('" + view + "') ORDER BY cid");
            const auto today = columns_for_table(view);
            REQUIRE(today.size() == g.columns.size() + 1);
            REQUIRE(info.size() >= today.size());
            CHECK(info[0][0] == "id");
            for (std::size_t i = 0; i < g.columns.size(); ++i) {
                INFO("column " << g.columns[i].name);
                CHECK(info[i + 1][0] == std::string{g.columns[i].name});
                CHECK(info[i + 1][1] == std::string{g.columns[i].sql_type});
            }
            ++checked;
        }
    }
    // Every tier the roll-up declarations carry is a tier of the registry, and the other way round.
    std::size_t declared = 0;
    for (const auto& d : fold_sources())
        if (!d.own_tables)
            declared += d.tiers.size();
    CHECK(checked == static_cast<int>(declared));
    CHECK(checked == 34);
}

TEST_CASE("is_fold_view, is_fold_internal_table and legacy_live_shim_names", "[echo][fold][schema]") {
    const auto shims = legacy_live_shim_names();
    CHECK(shims.size() == 16);
    CHECK(std::find(shims.begin(), shims.end(), "usage_live") == shims.end());
    CHECK(std::find(shims.begin(), shims.end(), "process_live") != shims.end());
    CHECK(std::find(shims.begin(), shims.end(), "netqual_live") != shims.end());

    CHECK(is_fold_internal_table("echo_dict"));
    CHECK(is_fold_internal_table("echo_fold_seen"));
    CHECK(is_fold_internal_table("process_hourly_r"));
    CHECK_FALSE(is_fold_internal_table("process_hourly"));
    for (const auto& v : fold_view_names()) {
        INFO("view " << v);
        CHECK(is_fold_view(v));
        CHECK_FALSE(is_fold_internal_table(v));
        CHECK(is_fold_internal_table(v + "_r"));
        CHECK_FALSE(is_fold_view(v + "_r"));
    }
    CHECK_FALSE(is_fold_view("usage_daily"));
    CHECK_FALSE(is_fold_internal_table("usage_daily"));
    CHECK_FALSE(is_fold_view("process_live"));
    CHECK_FALSE(is_fold_view(""));
}

// ═════════════════════════════════════════════════════════════════════════════
// Merge operations and the UPSERT builder
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("TierAccumulator: merge ops, and kLast never lets an older event win", "[echo][fold][merge]") {
    const FoldSourceDef def{"synthetic",
                            {"hourly"},
                            {ColumnDef{"k", "TEXT", ColumnRole::kKey, MergeOp::kNone, true},
                             ColumnDef{"n", "INTEGER", ColumnRole::kMeasure, MergeOp::kSum},
                             ColumnDef{"r", "REAL", ColumnRole::kMeasure, MergeOp::kSum},
                             ColumnDef{"hi", "INTEGER", ColumnRole::kMeasure, MergeOp::kMax},
                             ColumnDef{"lo", "INTEGER", ColumnRole::kMeasure, MergeOp::kMin},
                             ColumnDef{"seen", "INTEGER", ColumnRole::kMeasure, MergeOp::kMax},
                             ColumnDef{"status", "TEXT", ColumnRole::kMeasure, MergeOp::kLast, false, {}, "seen"}}};
    const auto fold_one = [&](TierAccumulator& a, int64_t ts, double r, int64_t hi, int64_t lo,
                              const char* status) {
        a.add(kT0, {{"k", vt("x")}},
              {{"n", vi(1)}, {"r", vr(r)}, {"hi", vi(hi)}, {"lo", vi(lo)}, {"seen", vi(ts)},
               {"status", vt(status)}});
    };
    TierAccumulator a(def);
    fold_one(a, 10, 0.5, 4, 7, "newer");
    fold_one(a, 5, 0.25, 9, 3, "older"); // lower guard: must not overwrite
    fold_one(a, 5, 1.0, 1, 9, "older2");
    const auto rs = a.rows("hourly");
    REQUIRE(rs.size() == 1);
    CHECK(mi(a, rs[0], "n") == 3);
    CHECK(md(a, rs[0], "r") == 1.75);
    CHECK(mi(a, rs[0], "hi") == 9);
    CHECK(mi(a, rs[0], "lo") == 3); // the first event's value, not a zero default
    CHECK(mi(a, rs[0], "seen") == 10);
    CHECK(ms(a, rs[0], "status") == "newer");

    fold_one(a, 10, 0, 0, 9, "tie"); // equal guard takes the incoming
    CHECK(ms(a, a.rows("hourly")[0], "status") == "tie");

    // Order of arrival does not matter when the guards differ.
    TierAccumulator b(def);
    fold_one(b, 5, 0, 0, 0, "older");
    fold_one(b, 10, 0, 0, 0, "newer");
    CHECK(ms(b, b.rows("hourly")[0], "status") == "newer");

    CHECK_THROWS_AS(a.add(kT0, {{"nope", vt("x")}}, {}), std::invalid_argument);
    CHECK_THROWS_AS(a.add(kT0, {{"k", vi(1)}}, {}), std::invalid_argument);
    // Numeric typing is strict in both directions: no int <-> real conversion.
    CHECK_THROWS_AS(a.add(kT0, {{"k", vt("x")}}, {{"n", vr(1.5)}}), std::invalid_argument); // INTEGER given a real
    CHECK_THROWS_AS(a.add(kT0, {{"k", vt("x")}}, {{"r", vi(1)}}), std::invalid_argument);   // REAL given an int
}

TEST_CASE("tier_upsert_sql: pinned text, and it prepares against the generated schema",
          "[echo][fold][merge]") {
    CHECK(tier_upsert_sql(*fold_source("process"), "hourly") ==
          "INSERT INTO process_hourly_r(hour_ts,name_id,user_id,parent_name_id,start_count,stop_count,"
          "abnormal_exit_count,elevated_count,spoofed_parent_count) VALUES(?,?,?,?,?,?,?,?,?) "
          "ON CONFLICT(hour_ts,name_id,user_id,parent_name_id) DO UPDATE SET "
          "start_count=start_count+excluded.start_count,stop_count=stop_count+excluded.stop_count,"
          "abnormal_exit_count=abnormal_exit_count+excluded.abnormal_exit_count,"
          "elevated_count=elevated_count+excluded.elevated_count,"
          "spoofed_parent_count=spoofed_parent_count+excluded.spoofed_parent_count RETURNING id");
    CHECK(tier_upsert_sql(*fold_source("service"), "daily") ==
          "INSERT INTO service_daily_r(day_ts,name_id,status_changes,last_status,install_count,"
          "remove_count,last_ts,last_exit_code,last_start_account,last_binary_path,failed_count) "
          "VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(day_ts,name_id) DO UPDATE SET "
          "status_changes=status_changes+excluded.status_changes,"
          "last_status=CASE WHEN excluded.last_ts>=last_ts THEN excluded.last_status ELSE last_status END,"
          "install_count=install_count+excluded.install_count,remove_count=remove_count+excluded.remove_count,"
          "last_ts=MAX(last_ts,excluded.last_ts),"
          "last_exit_code=CASE WHEN excluded.last_ts>=last_ts THEN excluded.last_exit_code ELSE last_exit_code END,"
          "last_start_account=CASE WHEN excluded.last_ts>=last_ts THEN excluded.last_start_account ELSE last_start_account END,"
          "last_binary_path=CASE WHEN excluded.last_ts>=last_ts THEN excluded.last_binary_path ELSE last_binary_path END,"
          "failed_count=failed_count+excluded.failed_count RETURNING id");
    CHECK(tier_upsert_sql(*fold_source("netqual"), "hourly").find("rtt_us_min=MIN(rtt_us_min,excluded.rtt_us_min)") !=
          std::string::npos);

    Mem m;
    open_mem(m);
    REQUIRE(exec(m.db, generate_fold_ddl()));
    for (const auto& d : fold_sources()) {
        if (d.own_tables)
            continue;
        for (auto tier : d.tiers) {
            INFO("upsert " << d.name << " " << tier);
            CHECK(prepare(m.db, tier_upsert_sql(d, tier)) != nullptr);
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// The 17 deltas (enrichment columns stay zero)
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("process_delta", "[echo][fold][delta]") {
    auto acc = make_acc("process");
    process_delta({pev(kT0, "started", "a.exe"), pev(kT0 + 1, "started", "a.exe"),
                   pev(kT0 + 2, "stopped", "a.exe"), pev(kT0 + 3, "started", "b.exe"),
                   pev(kT0 + 4, "paused", "z.exe")},
                  acc);
    for (auto tier : {"hourly", "daily", "monthly"}) {
        REQUIRE(acc.rows(tier).size() == 2); // the unknown token made no row
    }
    const auto a = row_for(acc, "hourly", {{"name", "a.exe"}});
    CHECK(a.bucket == kHour0);
    CHECK(mi(acc, a, "start_count") == 2);
    CHECK(mi(acc, a, "stop_count") == 1);
    check_zero(acc, a, {"parent_name", "abnormal_exit_count", "elevated_count", "spoofed_parent_count"});
    CHECK(row_for(acc, "daily", {{"name", "b.exe"}}).bucket == kDay0);
    CHECK(row_for(acc, "monthly", {{"name", "b.exe"}}).bucket == kMonth0);
}

TEST_CASE("tcp_delta: connect, disconnect, failed, listen, unknown", "[echo][fold][delta]") {
    const auto ev = [](const char* action, int local_port = 0) {
        NetworkEvent e;
        e.ts = kT0;
        e.action = action;
        e.proto = "tcp";
        e.local_addr = "0.0.0.0";
        e.local_port = local_port;
        e.remote_addr = "10.0.0.1";
        e.remote_port = 443;
        e.process_name = "chrome";
        return e;
    };
    auto acc = make_acc("tcp");
    tcp_delta({ev("connected"), ev("connected"), ev("disconnected"), ev("failed"),
               ev("listen_open", 8080), ev("listen_close", 8080), ev("frobnicated")},
              acc);
    REQUIRE(acc.rows("hourly").size() == 2);
    const auto c = row_for(acc, "hourly", {{"remote_addr", "10.0.0.1"}, {"remote_port", "443"}});
    CHECK(mi(acc, c, "connect_count") == 2);
    CHECK(mi(acc, c, "disconnect_count") == 1);
    CHECK(mi(acc, c, "failed_count") == 1);
    check_zero(acc, c, {"duration_s_sum", "listen_open_count", "listen_close_count"});
    const auto l = row_for(acc, "hourly", {{"remote_addr", "*"}, {"remote_port", "8080"}});
    CHECK(ks(acc, l, "process_name") == "chrome");
    CHECK(mi(acc, l, "listen_open_count") == 1);
    CHECK(mi(acc, l, "listen_close_count") == 1);
    CHECK(mi(acc, l, "connect_count") == 0);
}

TEST_CASE("module_delta: loaded counts; seed and unloaded contribute nothing; blocked is counted",
          "[echo][fold][delta]") {
    const auto row = [](const char* action, const char* module) {
        ModuleRow r;
        r.ts = kT0;
        r.action = action;
        r.process_name = "p.exe";
        r.module_name = module;
        r.module_dir = "C:\\Windows";
        r.signed_state = "signed";
        r.signer = "Vendor";
        r.is_kernel = true;
        return r;
    };
    auto acc = make_acc("module");
    module_delta({row("loaded", "m.dll"), row("seed", "m.dll"), row("blocked", "m.dll"),
                  row("unloaded", "gone.dll")},
                 acc);
    REQUIRE(acc.rows("hourly").size() == 1);
    const auto m = acc.rows("hourly")[0];
    CHECK(mi(acc, m, "load_count") == 1);
    CHECK(mi(acc, m, "blocked_count") == 1);
    CHECK(ks(acc, m, "is_kernel") == "1");
    CHECK(ks(acc, m, "module_dir") == "C:\\Windows");
    check_zero(acc, m, {"rebased_count"});
}

TEST_CASE("service_delta: the real tokens from compute_service_events", "[echo][fold][delta]") {
    const std::vector<ServiceInfo> prev{{"a", "A", "running", "automatic"}, {"b", "B", "running", "automatic"}};
    const std::vector<ServiceInfo> cur{{"a", "A", "stopped", "automatic"}, {"c", "C", "running", "manual"}};
    const auto events = compute_service_events(prev, cur, kT0, 1);
    REQUIRE(events.size() == 3);

    auto acc = make_acc("service");
    service_delta(events, acc);
    const auto a = row_for(acc, "hourly", {{"name", "a"}});
    CHECK(mi(acc, a, "status_changes") == 1);
    CHECK(mi(acc, a, "install_count") == 0);
    CHECK(ms(acc, a, "last_status") == "stopped");
    const auto b = row_for(acc, "hourly", {{"name", "b"}});
    CHECK(mi(acc, b, "remove_count") == 1);
    CHECK(mi(acc, b, "status_changes") == 0); // a vanish is not a state_changed
    const auto c = row_for(acc, "hourly", {{"name", "c"}});
    CHECK(mi(acc, c, "install_count") == 1);
    CHECK(mi(acc, c, "last_ts") == kT0);
    check_zero(acc, c, {"last_exit_code", "last_start_account", "last_binary_path", "failed_count"});

    // last_status follows the newest ts whatever the arrival order.
    ServiceEvent newer, older;
    newer.ts = kT0 + 100;
    newer.action = "state_changed";
    newer.name = "a";
    newer.status = "paused";
    older = newer;
    older.ts = kT0 - 100;
    older.status = "ancient";
    service_delta({newer, older}, acc);
    CHECK(ms(acc, row_for(acc, "hourly", {{"name", "a"}}), "last_status") == "paused");
}

TEST_CASE("user, software, arp and dns deltas", "[echo][fold][delta]") {
    {
        UserEvent li, lo;
        li.ts = lo.ts = kT0;
        li.action = "login";
        lo.action = "logout";
        li.user = lo.user = "alice";
        li.domain = lo.domain = "D";
        li.logon_type = lo.logon_type = "interactive";
        auto acc = make_acc("user");
        user_delta({li, li, lo}, acc);
        const auto r = row_for(acc, "daily", {{"user", "alice"}});
        CHECK(mi(acc, r, "login_count") == 2);
        CHECK(mi(acc, r, "logout_count") == 1);
        CHECK(ks(acc, r, "logon_type") == "interactive");
        check_zero(acc, r, {"disconnect_count", "session_s_sum"});
    }
    {
        SoftwareEvent e;
        e.ts = kT0;
        e.name = "app";
        e.version = "2.0";
        e.publisher = "P";
        auto acc = make_acc("software");
        e.action = "installed";
        software_delta({e}, acc);
        e.action = "removed";
        software_delta({e}, acc);
        e.action = "upgraded";
        software_delta({e, e}, acc);
        const auto r = row_for(acc, "daily", {{"name", "app"}});
        CHECK(mi(acc, r, "install_count") == 1);
        CHECK(mi(acc, r, "remove_count") == 1);
        CHECK(mi(acc, r, "upgrade_count") == 2);
        check_zero(acc, r, {"arch", "downgrade_count"});
        CHECK(acc.rows("hourly").size() == 1);
    }
    {
        ArpEvent e;
        e.ts = kT0;
        e.iface = "en0";
        e.ip_address = "10.0.0.2";
        e.mac_address = "aa:bb";
        auto acc = make_acc("arp");
        e.action = "appeared";
        arp_delta({e, e}, acc);
        e.action = "removed";
        arp_delta({e}, acc);
        const auto r = row_for(acc, "hourly", {{"interface", "en0"}});
        CHECK(mi(acc, r, "appear_count") == 2);
        CHECK(mi(acc, r, "remove_count") == 1);
        check_zero(acc, r, {"is_router", "rebind_count"});
    }
    {
        DnsEvent e;
        e.ts = kT0;
        e.name = "example.org";
        e.record_type = "A";
        e.data = "1.2.3.4";
        auto acc = make_acc("dns");
        e.action = "appeared";
        dns_delta({e}, acc);
        e.action = "removed";
        dns_delta({e}, acc);
        const auto r = row_for(acc, "hourly", {{"name", "example.org"}});
        CHECK(ks(acc, r, "data") == "1.2.3.4");
        CHECK(mi(acc, r, "appear_count") == 1);
        CHECK(mi(acc, r, "remove_count") == 1);
        check_zero(acc, r, {"negative_count"});
    }
}

TEST_CASE("netconn, mapdrive, perf, procperf and netqual deltas", "[echo][fold][delta]") {
    {
        NetConnRow a;
        a.ts = kT0;
        a.action = "connected";
        a.channel = "ncsi";
        a.capability = "internet";
        a.reason_code = 7;
        NetConnRow b = a;
        b.ts = kT0 + 60;
        auto acc = make_acc("netconn");
        netconn_delta({a, b}, acc);
        const auto r = row_for(acc, "hourly", {{"action", "connected"}, {"reason_code", "7"}});
        CHECK(mi(acc, r, "event_count") == 2);
        CHECK(mi(acc, r, "last_ts") == kT0 + 60);
        check_zero(acc, r, {"phy_type", "auth_alg", "cipher_alg"});
    }
    {
        MapDriveEvent e;
        e.direction = "outbound";
        e.local_mount = "Z:";
        e.remote_path = "\\\\srv\\share";
        e.remote_host = "srv";
        auto acc = make_acc("mapdrive");
        e.ts = kT0 + 30;
        e.action = "appeared";
        mapdrive_delta({e}, acc);
        e.ts = kT0 + 10;
        e.action = "removed";
        mapdrive_delta({e}, acc);
        e.ts = kT0 + 20;
        e.action = "historical";
        mapdrive_delta({e}, acc);
        const auto r = row_for(acc, "hourly", {{"local_mount", "Z:"}});
        CHECK(mi(acc, r, "appear_count") == 1);
        CHECK(mi(acc, r, "remove_count") == 1);
        CHECK(mi(acc, r, "historical_count") == 1);
        CHECK(mi(acc, r, "first_ts") == kT0 + 10);
        CHECK(mi(acc, r, "last_ts") == kT0 + 30);
        check_zero(acc, r, {"last_dialect", "guest_count"});
    }
    {
        PerfRow p;
        p.ts = kT0;
        p.cpu_pct = 10;
        p.mem_used_pct = 50;
        p.commit_pct = 30;
        p.disk_read_bps = 100;
        p.disk_write_bps = 200;
        p.disk_read_lat_us = 7;
        p.disk_write_lat_us = 9;
        p.net_rx_bps = 1000;
        p.net_tx_bps = 2000;
        PerfRow q = p;
        q.cpu_pct = 30;
        q.disk_read_lat_us = 11;
        auto acc = make_acc("perf");
        perf_delta({p, q}, acc);
        const auto r = acc.rows("hourly")[0];
        CHECK(mi(acc, r, "samples") == 2);
        CHECK(md(acc, r, "cpu_sum") == 40);
        CHECK(md(acc, r, "cpu_max") == 30);
        CHECK(mi(acc, r, "read_lat_us_sum") == 18);
        CHECK(mi(acc, r, "read_lat_us_max") == 11);
        CHECK(mi(acc, r, "rx_bps_sum") == 2000);
        CHECK(md(acc, r, "mem_sum") == 100);
        CHECK(md(acc, r, "mem_max") == 50);
        CHECK(md(acc, r, "commit_sum") == 60);
        CHECK(mi(acc, r, "read_bps_sum") == 200);
        CHECK(mi(acc, r, "write_bps_sum") == 400);
        CHECK(mi(acc, r, "write_lat_us_sum") == 18);
        CHECK(mi(acc, r, "write_lat_us_max") == 9);
        CHECK(mi(acc, r, "tx_bps_sum") == 4000);
        check_zero(acc, r, {"cpu_kernel_sum", "rx_bps_max", "tx_bps_max", "procs_sum", "threads_sum", "handles_sum"});
    }
    {
        ProcPerfRow p;
        p.ts = kT0;
        p.name = "app";
        p.version = "1.0";
        p.instances = 3;
        p.cpu_pct = 12.5;
        p.ws_bytes = 4096;
        p.is_kthread = true;
        ProcPerfRow q = p;
        q.instances = 5;
        q.ws_bytes = 8192;
        auto acc = make_acc("procperf");
        procperf_delta({p, q}, acc);
        const auto r = row_for(acc, "hourly", {{"name", "app"}, {"is_kthread", "1"}});
        CHECK(mi(acc, r, "samples") == 2);
        CHECK(mi(acc, r, "instances_max") == 5);
        CHECK(md(acc, r, "cpu_sum") == 25);
        CHECK(md(acc, r, "cpu_max") == 12.5);
        CHECK(mi(acc, r, "ws_sum") == 12288);
        CHECK(mi(acc, r, "ws_max_bytes") == 8192);
        check_zero(acc, r, {"private_bytes_max", "handles_max", "threads_max", "io_read_bytes_sum", "io_write_bytes_sum"});
    }
    {
        NetQualRow n;
        n.ts = kT0;
        n.proto = "tcp";
        n.remote_bucket = "public";
        n.process_name = "p";
        n.rtt_us = 1000;
        n.rtt_var_us = 50;
        n.lost = 0;
        NetQualRow d = n;
        d.rtt_us = 3000;
        d.lost = 4;
        auto acc = make_acc("netqual");
        netqual_delta({n, d}, acc);
        const auto r = acc.rows("hourly")[0];
        CHECK(mi(acc, r, "samples") == 2);
        CHECK(mi(acc, r, "rtt_us_sum") == 4000);
        CHECK(mi(acc, r, "rtt_us_max") == 3000);
        CHECK(mi(acc, r, "rtt_var_us_sum") == 100);
        CHECK(mi(acc, r, "lost_sum") == 4);
        CHECK(mi(acc, r, "lost_max") == 4);
        CHECK(mi(acc, r, "degraded_samples") == 1);
        check_zero(acc, r, {"rtt_us_min", "bytes_in_sum", "bytes_out_sum"});
    }
}

TEST_CASE("cursor deltas: power, removable and registry clipping and digests", "[echo][fold][delta]") {
    PowerEvent pw;
    pw.ts = kT0;
    pw.snapshot_id = 1;
    pw.action = "sleep";
    pw.detail = std::string(300, 'd');
    pw.record_key = "pk1";
    const auto pc = power_delta({pw});
    REQUIRE(pc.size() == 1);
    CHECK(pc[0].record_key == "pk1");
    auto pacc = make_acc("power");
    for (const auto& c : pc)
        pacc.add(c.ts, c.keys, c.measures);
    const auto pr = pacc.rows("hourly")[0];
    CHECK(ms(pacc, pr, "last_detail").size() == 256);
    CHECK(mi(pacc, pr, "event_count") == 1);
    check_zero(pacc, pr, {"resume_kind", "source"});

    RemovableEvent rm;
    rm.ts = kT0;
    rm.action = "attached";
    rm.device_key = "usb1";
    rm.vendor = "V";
    rm.size_bytes = 4096;
    rm.record_key = "rk1";
    auto racc = make_acc("removable");
    for (const auto& c : removable_delta({rm}))
        racc.add(c.ts, c.keys, c.measures);
    const auto rr = racc.rows("daily")[0];
    CHECK(mi(racc, rr, "size_bytes") == 4096);
    CHECK(mi(racc, rr, "first_ts") == kT0);
    check_zero(racc, rr, {"disk_id", "partition_count"});

    RegistryEvent rg;
    rg.ts = kT0;
    rg.hive = "HKLM";
    rg.key_path = "SOFTWARE\\X";
    rg.value_name = "v";
    rg.action = "changed";
    rg.data = std::string(600, 'x');
    rg.data_type = "REG_SZ";
    rg.actor_image = "a.exe";
    rg.record_key = "gk1";
    auto gacc = make_acc("registry");
    for (const auto& c : registry_delta({rg}))
        gacc.add(c.ts, c.keys, c.measures);
    const auto gr = gacc.rows("hourly")[0];
    CHECK(ms(gacc, gr, "last_data").size() == 512);
    CHECK(ms(gacc, gr, "last_actor_image") == "a.exe");
    CHECK(mi(gacc, gr, "change_count") == 1);
}

TEST_CASE("usage_delta: a pure adapter over fold_daily", "[echo][fold][delta]") {
    using usage::ClosedRun;
    const std::vector<ClosedRun> runs = {
        {1, "a.exe", "u", kDay0 + 100, kDay0 + 160, ClosedRun::Kind::normal},
        {2, "a.exe", "u", kDay0 + 500, kDay0 + 600, ClosedRun::Kind::superseded},
        {3, "b.exe", "u", kDay0 + 900, kDay0 + 910, ClosedRun::Kind::expired},
    };
    auto acc = make_acc("usage");
    usage_delta(runs, acc);
    const auto expected = usage::fold_daily(runs);
    REQUIRE(expected.size() == 2);
    REQUIRE(acc.rows("daily").size() == expected.size());
    for (const auto& d : expected) {
        const auto r = row_for(acc, "daily", {{"exe_key", d.exe_key}});
        CHECK(r.bucket == d.day_ts);
        CHECK(mi(acc, r, "run_count") == d.run_count);
        CHECK(mi(acc, r, "total_seconds") == d.total_seconds);
        CHECK(mi(acc, r, "first_seen") == d.first_seen);
        CHECK(mi(acc, r, "last_seen") == d.last_seen);
        CHECK(mi(acc, r, "superseded_runs") == d.superseded_runs);
        CHECK(mi(acc, r, "expired_runs") == d.expired_runs);
        check_zero(acc, r, {"max_run_s", "min_run_s", "short_run_count", "peak_instances", "launched_by_exe_key"});
    }
}

TEST_CASE("identity_digest: deterministic, and covers exactly the fields the raw store compared",
          "[echo][fold][delta]") {
    CHECK(identity_digest({"a", "b"}) == identity_digest({"a", "b"}));
    CHECK(identity_digest({"a", "b"}) != identity_digest({"b", "a"}));
    CHECK(identity_digest({"ab", ""}) != identity_digest({"a", "b"})); // no separator forgery

    PowerEvent a;
    a.ts = kT0;
    a.snapshot_id = 1;
    a.action = "sleep";
    a.detail = "lid";
    a.record_key = "k";
    PowerEvent b = a;
    b.snapshot_id = 99; // collection metadata: not identity
    CHECK(power_delta({a})[0].identity_digest == power_delta({b})[0].identity_digest);
    b.detail = "other";
    CHECK(power_delta({a})[0].identity_digest != power_delta({b})[0].identity_digest);
    b = a;
    b.ts = kT0 + 1;
    CHECK(power_delta({a})[0].identity_digest != power_delta({b})[0].identity_digest);
    a.action = b.action = "capture_gap"; // for a gap `ts` is when we noticed, not identity
    CHECK(power_delta({a})[0].identity_digest == power_delta({b})[0].identity_digest);

    RegistryEvent r;
    r.ts = kT0;
    r.action = "changed";
    r.hive = "HKLM";
    r.key_path = "k";
    r.data = "d";
    r.record_key = "rk";
    RegistryEvent s = r;
    s.actor_pid = 7; // attribution: not identity
    s.actor_image = "x.exe";
    s.detail = "attr:late";
    s.snapshot_id = 5;
    CHECK(registry_delta({r})[0].identity_digest == registry_delta({s})[0].identity_digest);
    s.ts = kT0 + 1; // the stamp is not identity either
    const auto reg = [](const RegistryEvent& e) { return registry_delta({e})[0].identity_digest; };
    CHECK(reg(r) == reg(s));
    // Every field the raw store compared is identity: a record differing in one is a collision.
    const std::vector<std::function<void(RegistryEvent&)>> identity = {
        [](RegistryEvent& e) { e.action = "added"; },     [](RegistryEvent& e) { e.hive = "HKU"; },
        [](RegistryEvent& e) { e.key_path = "k2"; },      [](RegistryEvent& e) { e.value_name = "v"; },
        [](RegistryEvent& e) { e.data_type = "REG_SZ"; }, [](RegistryEvent& e) { e.data = "changed"; },
        [](RegistryEvent& e) { e.data_size = 9; },        [](RegistryEvent& e) { e.prev_data_type = "REG_DWORD"; },
        [](RegistryEvent& e) { e.prev_data = "p"; },      [](RegistryEvent& e) { e.prev_data_size = 5; },
        [](RegistryEvent& e) { e.observed_at = 3; },
    };
    for (std::size_t i = 0; i < identity.size(); ++i) {
        INFO("registry edit " << i);
        s = r;
        identity[i](s);
        CHECK(reg(r) != reg(s));
    }
    for (const auto& edit : identity)
        edit(s); // every identity field of `s` now differs from `r` ...
    r.action = s.action = "capture_gap"; // ... yet a gap carries nothing but its action
    CHECK(reg(r) == reg(s));

    // removable: every stored field is identity; `ts` is too, except for capture_gap and
    // present_at_baseline, where it is only when we noticed; snapshot_id never is.
    RemovableEvent m;
    m.ts = kT0;
    m.snapshot_id = 1;
    m.action = "attached";
    m.device_key = "usb1";
    m.vendor = "V";
    m.serial = "S";
    m.record_key = "mk";
    const auto digest_of = [](const RemovableEvent& e) { return removable_delta({e})[0].identity_digest; };
    RemovableEvent n = m;
    n.snapshot_id = 99;
    CHECK(digest_of(m) == digest_of(n));
    n = m;
    n.ts = kT0 + 1;
    CHECK(digest_of(m) != digest_of(n)); // a real attach: ts is identity
    for (const char* special : {"capture_gap", "present_at_baseline"}) {
        INFO("action " << special);
        m.action = n.action = special;
        n.ts = kT0 + 1;
        CHECK(digest_of(m) == digest_of(n));
    }
    m.action = "attached";
    const std::vector<std::function<void(RemovableEvent&)>> edits = {
        [](RemovableEvent& e) { e.action = "detached"; },  [](RemovableEvent& e) { e.device_key = "usb2"; },
        [](RemovableEvent& e) { e.vendor = "W"; },         [](RemovableEvent& e) { e.product = "P"; },
        [](RemovableEvent& e) { e.serial = "T"; },         [](RemovableEvent& e) { e.bus = "usb"; },
        [](RemovableEvent& e) { e.volume = "E:"; },        [](RemovableEvent& e) { e.size_bytes = 5; },
        [](RemovableEvent& e) { e.image_path = "x.exe"; }, [](RemovableEvent& e) { e.pid = 4; },
        [](RemovableEvent& e) { e.evidence = "ev"; },
    };
    for (std::size_t i = 0; i < edits.size(); ++i) {
        INFO("edit " << i);
        n = m;
        edits[i](n);
        CHECK(digest_of(m) != digest_of(n));
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// The fold writer
// ═════════════════════════════════════════════════════════════════════════════

TEST_CASE("install_fold_schema: replaces a legacy tier table with its view, idempotently",
          "[echo][fold][writer]") {
    // open() has installed the schema already; put a legacy tier TABLE back where the view is, as a
    // file written before roll-up looked, and re-install.
    const auto legacy_in_place = [](FoldDb& d) {
        REQUIRE(d.db.execute_sql("DROP VIEW process_hourly"));
        REQUIRE(d.db.execute_sql("CREATE TABLE process_hourly (id INTEGER PRIMARY KEY, hour_ts INTEGER, "
                                 "name TEXT, user TEXT)"));
    };
    auto f = make_fold_db(/*install=*/false);
    legacy_in_place(*f);
    CHECK(f->n("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='process_hourly'") == 1);
    REQUIRE(f->fold.install_fold_schema(f->db).has_value());
    CHECK(f->n("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='process_hourly'") == 0);
    CHECK(f->n("SELECT COUNT(*) FROM sqlite_master WHERE type='view' AND name='process_hourly'") == 1);
    CHECK(f->n("SELECT COUNT(*) FROM sqlite_master WHERE type='view' AND name='netqual_hourly'") == 1);
    REQUIRE(f->fold.install_fold_schema(f->db).has_value());

    // A legacy table that holds rows refuses the install and keeps them; the refusal rolls the
    // whole install back, so a view the install would have recreated stays absent.
    auto g = make_fold_db(/*install=*/false);
    legacy_in_place(*g);
    REQUIRE(g->db.execute_sql("DROP VIEW tcp_hourly"));
    REQUIRE(g->db.execute_sql("INSERT INTO process_hourly(hour_ts, name, user) VALUES (1, 'a', 'u')"));
    const auto refused = g->fold.install_fold_schema(g->db);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().find("process_hourly holds 1 rows; move them aside") != std::string::npos);
    CHECK(g->n("SELECT COUNT(*) FROM process_hourly") == 1);
    CHECK(g->n("SELECT COUNT(*) FROM sqlite_master WHERE type='view' AND name='tcp_hourly'") == 0);
}

TEST_CASE("fold_rows: counts, text round-trip, and refusals", "[echo][fold][writer]") {
    auto f = make_fold_db();
    auto acc = make_acc("process");
    process_delta({pev(kT0, "started", "a.exe"), pev(kT0, "started", "a.exe"), pev(kT0, "stopped", "a.exe"),
                   pev(kT0, "started", "b.exe")},
                  acc);
    const auto r = f->fold.fold_rows(f->db, "process", acc);
    REQUIRE(r.has_value());
    CHECK(r->rows_touched == 6); // 2 keys x 3 tiers, counted from RETURNING
    CHECK(r->rejected_events == 0);
    const auto got = f->q("SELECT name, user, start_count, stop_count FROM process_hourly ORDER BY name");
    REQUIRE(got.size() == 2);
    CHECK(got[0] == QueryRow{"a.exe", "u", "2", "1"});
    CHECK(got[1] == QueryRow{"b.exe", "u", "1", "0"});
    CHECK(f->n("SELECT COUNT(*) FROM echo_dict") == 4); // a.exe, b.exe, u, and '' (parent_name)
    CHECK(integrity_violations(*f) == 0);

    // The same fold again merges into the same rows.
    REQUIRE(f->fold.fold_rows(f->db, "process", acc).has_value());
    CHECK(f->n("SELECT COUNT(*) FROM process_hourly_r") == 2);
    CHECK(f->n("SELECT start_count FROM process_hourly WHERE name='a.exe'") == 4);

    CHECK_FALSE(f->fold.fold_rows(f->db, "usage", make_acc("usage")).has_value());
    CHECK_FALSE(f->fold.fold_rows(f->db, "nope", acc).has_value());
    CHECK_FALSE(f->fold.fold_rows(f->db, "power", make_acc("power")).has_value()); // cursor source
    CHECK_FALSE(f->fold.fold_rows(f->db, "tcp", acc).has_value());                  // wrong accumulator
}

TEST_CASE("fold_rows: a cold id cache re-folding known strings writes no more WAL frames than a warm one",
          "[echo][fold][writer]") {
    auto f = make_fold_db();
    auto acc = make_acc("process");
    std::vector<ProcessEvent> evs;
    for (int i = 0; i < 1500; ++i)
        evs.push_back(pev(kT0, "started", ("proc_" + std::to_string(i) + std::string(40, 'x')).c_str()));
    process_delta(evs, acc);
    REQUIRE(f->fold.fold_rows(f->db, "process", acc).has_value()); // interns the strings
    const auto frames = [&](EchoFold& fold) { // WAL frames one fold of `acc` writes
        f->q("PRAGMA wal_checkpoint(TRUNCATE)");
        REQUIRE(fold.fold_rows(f->db, "process", acc).has_value());
        return std::stoll(f->q("PRAGMA wal_checkpoint(PASSIVE)")[0][1]);
    };
    const auto warm = frames(f->fold); // every id is cached
    EchoFold cold;                     // an empty cache: every string is a dictionary hit
    const auto cold_frames = frames(cold);
    INFO("warm " << warm << " cold " << cold_frames);
    CHECK(warm > 0);
    CHECK(cold_frames <= warm);
}

TEST_CASE("fold_rows: perf averages are weighted means across separate folds; an INTEGER one truncates",
          "[echo][fold][writer]") {
    auto f = make_fold_db();
    const auto sample = [](double cpu, int64_t bps = 1000) {
        PerfRow p;
        p.ts = kT0;
        p.cpu_pct = cpu;
        p.disk_read_bps = bps;
        return p;
    };
    auto a1 = make_acc("perf");
    perf_delta({sample(10), sample(20)}, a1);
    const auto first = f->fold.fold_rows(f->db, "perf", a1);
    REQUIRE(first.has_value());
    CHECK(first->rows_touched == 2); // hourly + daily, one row each
    auto a2 = make_acc("perf");
    perf_delta({sample(60, 1001)}, a2);
    REQUIRE(f->fold.fold_rows(f->db, "perf", a2).has_value());
    const auto r = f->q("SELECT samples, cpu_avg, cpu_max, read_bps_avg FROM perf_hourly");
    REQUIRE(r.size() == 1);
    CHECK(r[0][0] == "3");
    CHECK(std::stod(r[0][1]) == 30.0); // (10 + 20 + 60) / 3
    CHECK(std::stod(r[0][2]) == 60.0);
    CHECK(r[0][3] == "1000"); // 3001 / 3 truncated, as CAST(AVG(..) AS INTEGER) is
    CHECK(f->n("SELECT COUNT(*) FROM perf_daily_r") == 1);
}

TEST_CASE("fold_rows: a failing statement rolls rows, dictionary, state and counter back together",
          "[echo][fold][writer]") {
    auto f = make_fold_db();
    // The daily upsert fails after the hourly one succeeded and its strings were interned.
    REQUIRE(f->db.execute_sql("CREATE TRIGGER fold_fail BEFORE INSERT ON process_daily_r "
                              "BEGIN SELECT RAISE(ABORT, 'forced'); END"));
    auto acc = make_acc("process");
    process_delta({pev(kT0, "started", "a.exe"), pev(std::numeric_limits<int64_t>::max(), "started", "x.exe")}, acc);
    REQUIRE(acc.rejected() == 1);
    const auto r = f->fold.fold_rows(f->db, "process", acc, StateWrite{"process", "{\"v\":1}"});
    CHECK_FALSE(r.has_value());
    CHECK(f->n("SELECT COUNT(*) FROM process_hourly_r") == 0);
    CHECK(f->n("SELECT COUNT(*) FROM echo_dict") == 0);
    CHECK_FALSE(f->db.try_get_state("process").value().has_value());
    CHECK_FALSE(f->db.try_get_config(std::string{kFoldRejectedCounterKey}).value().has_value()); // unchanged

    // Clear the cause and fold again through the SAME EchoFold: no reinstall, so nothing but the
    // rollback itself keeps the id cache clean. A cache that learned the rolled-back ids would
    // bind them here and leave dangling references.
    REQUIRE(f->db.execute_sql("DROP TRIGGER fold_fail"));
    const auto ok = f->fold.fold_rows(f->db, "process", acc, StateWrite{"process", "{\"v\":1}"});
    REQUIRE(ok.has_value());
    CHECK(integrity_violations(*f) == 0);
    CHECK(f->n("SELECT COUNT(*) FROM process_hourly WHERE name = 'a.exe' AND user = 'u' AND start_count = 1") == 1);
    CHECK(f->db.try_get_state("process").value() == "{\"v\":1}");
    CHECK(f->db.try_get_config(std::string{kFoldRejectedCounterKey}).value() == std::optional<std::string>{"1"});
}

TEST_CASE("fold_rows: an unrepresentable stamp rejects that event, counts it, keeps the batch",
          "[echo][fold][writer]") {
    auto f = make_fold_db();
    const auto counter = [&] { return f->db.try_get_config(std::string{kFoldRejectedCounterKey}).value(); };
    auto acc = make_acc("process");
    process_delta({pev(kT0, "started", "a.exe"), pev(std::numeric_limits<int64_t>::min(), "started", "b.exe"),
                   pev(kT0 + 1, "started", "c.exe")},
                  acc);
    const auto r = f->fold.fold_rows(f->db, "process", acc);
    REQUIRE(r.has_value()); // never a batch refusal
    CHECK(r->rejected_events == 1);
    CHECK(f->n("SELECT COUNT(*) FROM process_hourly WHERE name IN ('a.exe','c.exe')") == 2);
    CHECK(f->n("SELECT COUNT(*) FROM process_hourly WHERE name='b.exe'") == 0);
    CHECK(counter() == std::optional<std::string>{"1"});

    // Adds up across batches, and a batch with only a bad stamp still counts.
    auto only_bad = make_acc("process");
    process_delta({pev(kHi + 1, "stopped", "d.exe")}, only_bad);
    REQUIRE(f->fold.fold_rows(f->db, "process", only_bad).has_value());
    CHECK(counter() == std::optional<std::string>{"2"});

    // A forced rollback leaves the counter where it was.
    REQUIRE(f->db.execute_sql("DROP TABLE process_monthly_r"));
    CHECK_FALSE(f->fold.fold_rows(f->db, "process", acc).has_value());
    CHECK(counter() == std::optional<std::string>{"2"});
}

TEST_CASE("fold_cursor_rows: events, ring, baseline and cursor commit together; replays fold nothing",
          "[echo][fold][cursor]") {
    auto f = make_fold_db();
    const auto contrib = [](const char* key, const char* detail, int64_t ts = kT0) {
        PowerEvent e;
        e.ts = ts;
        e.action = "sleep";
        e.detail = detail;
        e.record_key = key;
        return power_delta({e})[0];
    };
    const auto cursor = [&] { return f->db.get_cursor("power").value(); };

    const auto r1 = f->fold.fold_cursor_rows(f->db, "power", {contrib("k1", "a"), contrib("k2", "b")},
                                             "{\"v\":1,\"n\":1}", {StateWrite{"power:base", "S1"}});
    REQUIRE(r1.has_value());
    CHECK(r1->folded == 2);
    CHECK(r1->replayed == 0);
    CHECK(f->n("SELECT SUM(event_count) FROM power_hourly") == 2);
    CHECK(f->n("SELECT COUNT(*) FROM echo_fold_seen WHERE source='power'") == 2);
    CHECK(cursor() == std::optional<std::string>{"{\"v\":1,\"n\":1}"});
    CHECK(f->db.try_get_state("power:base").value() == "S1");

    // The same records re-offered (same digests): nothing folds, the cursor still advances.
    const auto r2 = f->fold.fold_cursor_rows(f->db, "power", {contrib("k1", "a"), contrib("k2", "b")},
                                             "{\"v\":1,\"n\":2}", {});
    REQUIRE(r2.has_value());
    CHECK(r2->folded == 0);
    CHECK(r2->replayed == 2);
    CHECK(f->n("SELECT SUM(event_count) FROM power_hourly") == 2);
    CHECK(cursor() == std::optional<std::string>{"{\"v\":1,\"n\":2}"});

    // A key already in the ring with a DIFFERENT digest is a collision: everything rolls back.
    const auto r3 = f->fold.fold_cursor_rows(f->db, "power", {contrib("k3", "c"), contrib("k1", "DIFFERENT")},
                                             "{\"v\":1,\"n\":3}", {StateWrite{"power:late", "S2"}});
    REQUIRE_FALSE(r3.has_value());
    CHECK(r3.error().kind == CursorFoldError::Kind::KeyCollision);
    CHECK(r3.error().text.find("contribution 1 of source 'power'") != std::string::npos);
    CHECK(f->n("SELECT SUM(event_count) FROM power_hourly") == 2);
    CHECK(f->n("SELECT COUNT(*) FROM echo_fold_seen WHERE source='power'") == 2); // k3 not entered
    CHECK_FALSE(f->db.try_get_state("power:late").value().has_value());
    CHECK(cursor() == std::optional<std::string>{"{\"v\":1,\"n\":2}"});

    // The refusal did not poison the connection: a good batch folds afterwards.
    const auto r4 = f->fold.fold_cursor_rows(f->db, "power", {contrib("k3", "c")}, "{\"v\":1,\"n\":4}", {});
    REQUIRE(r4.has_value());
    CHECK(r4->folded == 1);
    CHECK(f->n("SELECT SUM(event_count) FROM power_hourly") == 3);
}

TEST_CASE("fold_cursor_rows: a registry replay that differs only in attribution is a replay, not a collision",
          "[echo][fold][cursor]") {
    auto f = make_fold_db();
    RegistryEvent e;
    e.ts = kT0;
    e.hive = "HKLM";
    e.key_path = "K";
    e.value_name = "v";
    e.action = "changed";
    e.data = "d";
    e.record_key = "rk";
    e.actor_image = "first.exe";
    auto again = e;
    again.actor_image = "second.exe";
    again.actor_pid = 9;
    again.detail = "attr:other";
    REQUIRE(f->fold.fold_cursor_rows(f->db, "registry", registry_delta({e}), "c1", {}).has_value());
    const auto r = f->fold.fold_cursor_rows(f->db, "registry", registry_delta({again}), "c2", {});
    REQUIRE(r.has_value());
    CHECK(r->replayed == 1);
    CHECK(f->n("SELECT change_count FROM registry_hourly") == 1);
}

TEST_CASE("fold_cursor_rows: an empty or NUL record_key refuses the batch with no writes",
          "[echo][fold][cursor]") {
    auto f = make_fold_db();
    PowerEvent e;
    e.ts = kT0;
    e.action = "sleep";
    for (const std::string& key : {std::string{}, std::string("a\0b", 3)}) {
        e.record_key = key;
        const auto r = f->fold.fold_cursor_rows(f->db, "power", power_delta({e}), "c", {StateWrite{"s", "x"}});
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == CursorFoldError::Kind::KeyCollision);
    }
    CHECK_FALSE(f->db.get_cursor("power").value().has_value());
    CHECK_FALSE(f->db.try_get_state("s").value().has_value());
    CHECK(f->n("SELECT COUNT(*) FROM power_hourly_r") == 0);
    // Not a cursor source, or not a source at all: a programming error, never a retryable failure.
    for (const char* source : {"process", "usage", "nope"}) {
        INFO("source " << source);
        const auto misuse = f->fold.fold_cursor_rows(f->db, source, {}, "c", {});
        REQUIRE_FALSE(misuse.has_value());
        CHECK(misuse.error().kind == CursorFoldError::Kind::Misuse);
    }
}

TEST_CASE("fold_cursor_rows: a bad stamp drops only that contribution, the cursor still advances",
          "[echo][fold][cursor]") {
    auto f = make_fold_db();
    PowerEvent good, bad, good2;
    good.ts = kT0;
    good.action = "sleep";
    good.record_key = "g1";
    bad = good;
    bad.ts = std::numeric_limits<int64_t>::min();
    bad.record_key = "bad";
    good2 = good;
    good2.ts = kT0 + 5;
    good2.record_key = "g2";
    const auto r = f->fold.fold_cursor_rows(f->db, "power", power_delta({good, bad, good2}), "cur",
                                            {StateWrite{"power:b", "B"}});
    REQUIRE(r.has_value()); // never a KeyCollision for a stamp
    CHECK(r->folded == 2);
    CHECK(r->rejected == 1);
    CHECK(f->n("SELECT SUM(event_count) FROM power_hourly") == 2);
    CHECK(f->n("SELECT COUNT(*) FROM echo_fold_seen WHERE record_key='bad'") == 0); // not in the ring
    CHECK(f->db.get_cursor("power").value() == std::optional<std::string>{"cur"});
    CHECK(f->db.try_get_state("power:b").value() == std::optional<std::string>{"B"});
    CHECK(f->db.try_get_config(std::string{kFoldRejectedCounterKey}).value() == std::optional<std::string>{"1"});
}

TEST_CASE("fold_cursor_rows: a batch whose every stamp is unrepresentable still advances the cursor",
          "[echo][fold][cursor]") {
    auto f = make_fold_db();
    PowerEvent a;
    a.ts = std::numeric_limits<int64_t>::min();
    a.action = "sleep";
    a.record_key = "x1";
    PowerEvent b = a;
    b.record_key = "x2";
    const auto r = f->fold.fold_cursor_rows(f->db, "power", power_delta({a, b}), "cur", {StateWrite{"s", "B"}});
    REQUIRE(r.has_value());
    CHECK(r->rejected == 2);
    CHECK(r->folded == 0);
    CHECK(f->db.get_cursor("power").value() == std::optional<std::string>{"cur"});
    CHECK(f->n("SELECT COUNT(*) FROM echo_fold_seen") == 0); // a dropped contribution is never in the ring
    CHECK(f->db.try_get_config(std::string{kFoldRejectedCounterKey}).value() == std::optional<std::string>{"2"});
    CHECK(f->db.try_get_state("s").value() == std::optional<std::string>{"B"});
}

TEST_CASE("fold_cursor_rows: a removable replay follows the digest's field set",
          "[echo][fold][cursor]") {
    auto f = make_fold_db();
    // A capture_gap re-noticed later has a different ts, which is not identity for a gap: a replay.
    RemovableEvent gap;
    gap.ts = kT0;
    gap.action = "capture_gap";
    gap.record_key = "gap-1";
    auto later = gap;
    later.ts = kT0 + 60;
    REQUIRE(f->fold.fold_cursor_rows(f->db, "removable", removable_delta({gap}), "c1", {}).has_value());
    const auto replay = f->fold.fold_cursor_rows(f->db, "removable", removable_delta({later}), "c2", {});
    REQUIRE(replay.has_value());
    CHECK(replay->replayed == 1);
    CHECK(replay->folded == 0);

    // The same key with a different stored field is a different record: a collision.
    RemovableEvent att;
    att.ts = kT0;
    att.action = "attached";
    att.device_key = "usb1";
    att.vendor = "V";
    att.record_key = "att-1";
    REQUIRE(f->fold.fold_cursor_rows(f->db, "removable", removable_delta({att}), "c3", {}).has_value());
    auto other = att;
    other.vendor = "W";
    const auto collision = f->fold.fold_cursor_rows(f->db, "removable", removable_delta({other}), "c4", {});
    REQUIRE_FALSE(collision.has_value());
    CHECK(collision.error().kind == CursorFoldError::Kind::KeyCollision);
    CHECK(f->n("SELECT SUM(event_count) FROM removable_hourly") == 2); // the gap and the attach only
    CHECK(f->db.get_cursor("removable").value() == std::optional<std::string>{"c3"});
}

TEST_CASE("fold_cursor_rows: a failing statement rolls the cursor and the ring back together",
          "[echo][fold][cursor]") {
    auto f = make_fold_db();
    REQUIRE(f->db.execute_sql("DROP TABLE power_daily_r"));
    PowerEvent e;
    e.ts = kT0;
    e.action = "sleep";
    e.record_key = "k";
    const auto r = f->fold.fold_cursor_rows(f->db, "power", power_delta({e}), "cur", {StateWrite{"s", "x"}});
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().kind == CursorFoldError::Kind::Transient);
    CHECK(f->n("SELECT COUNT(*) FROM echo_fold_seen") == 0);
    CHECK(f->n("SELECT COUNT(*) FROM power_hourly_r") == 0);
    CHECK_FALSE(f->db.get_cursor("power").value().has_value());
    CHECK_FALSE(f->db.try_get_state("s").value().has_value());
}

TEST_CASE("fold_cursor_rows: a rolled-back fold publishes nothing to the id cache", "[echo][fold][cursor]") {
    auto f = make_fold_db();
    REQUIRE(f->db.execute_sql("CREATE TRIGGER fold_fail BEFORE INSERT ON power_daily_r "
                              "BEGIN SELECT RAISE(ABORT, 'forced'); END"));
    PowerEvent e;
    e.ts = kT0;
    e.action = "sleep";
    e.record_key = "k1";
    const auto contrib = power_delta({e});
    const auto failed = f->fold.fold_cursor_rows(f->db, "power", contrib, "cur", {StateWrite{"s", "x"}});
    CHECK_FALSE(failed.has_value());
    CHECK(f->n("SELECT COUNT(*) FROM echo_dict") == 0);
    CHECK(f->n("SELECT COUNT(*) FROM echo_fold_seen") == 0);

    // Same EchoFold, same cache, no reinstall and no GC in between: the retry must intern afresh.
    REQUIRE(f->db.execute_sql("DROP TRIGGER fold_fail"));
    const auto ok = f->fold.fold_cursor_rows(f->db, "power", contrib, "cur", {StateWrite{"s", "x"}});
    REQUIRE(ok.has_value());
    CHECK(ok->folded == 1);
    CHECK(integrity_violations(*f) == 0);
    CHECK(f->n("SELECT COUNT(*) FROM power_hourly WHERE action = 'sleep' AND event_count = 1") == 1);
}

TEST_CASE("fold_cursor_rows: the replay ring prunes to its depth, per source", "[echo][fold][cursor]") {
    auto f = make_fold_db();
    std::vector<KeyedContribution> batch;
    for (int i = 0; i < 4200; ++i) {
        PowerEvent e;
        e.ts = kT0;
        e.action = "wake";
        e.record_key = "key-" + std::to_string(i);
        batch.push_back(power_delta({e})[0]);
    }
    RemovableEvent other;
    other.ts = kT0;
    other.action = "attached";
    other.record_key = "other-1";
    REQUIRE(f->fold.fold_cursor_rows(f->db, "removable", removable_delta({other}), "c", {}).has_value());
    REQUIRE(f->fold.fold_cursor_rows(f->db, "power", batch, "c", {}).has_value());
    CHECK(f->n("SELECT COUNT(*) FROM echo_fold_seen WHERE source='power'") == 4096);
    CHECK(f->n("SELECT COUNT(*) FROM echo_fold_seen WHERE source='power' AND record_key='key-4199'") == 1);
    CHECK(f->n("SELECT COUNT(*) FROM echo_fold_seen WHERE source='power' AND record_key='key-0'") == 0);
    CHECK(f->n("SELECT COUNT(*) FROM echo_fold_seen WHERE source='removable'") == 1);
    CHECK(f->n("SELECT SUM(event_count) FROM power_hourly") == 4200); // pruning never un-folds
    // The ring is first-sighting FIFO: a record re-offered after 4096 newer keys folds again.
    const auto again = f->fold.fold_cursor_rows(f->db, "power", batch, "c", {});
    REQUIRE(again.has_value());
    CHECK(again->replayed == 4096);
    CHECK(f->n("SELECT SUM(event_count) FROM power_hourly") == 4304);
}

// ═════════════════════════════════════════════════════════════════════════════
// Dictionary GC
// ═════════════════════════════════════════════════════════════════════════════

namespace {
constexpr auto kHour = std::chrono::hours(1);

// Fold one process event for each name; names are interned in the given order.
void fold_names(FoldDb& f, std::initializer_list<const char*> names) {
    auto acc = make_acc("process");
    std::vector<ProcessEvent> evs;
    for (const char* n : names)
        evs.push_back(pev(kT0, "started", n));
    process_delta(evs, acc);
    REQUIRE(f.fold.fold_rows(f.db, "process", acc).has_value());
}

void drop_rows_of(FoldDb& f, const char* name) {
    for (const char* t : {"process_hourly_r", "process_daily_r", "process_monthly_r"})
        REQUIRE(f.db.execute_sql(std::string("DELETE FROM ") + t +
                                 " WHERE name_id = (SELECT id FROM echo_dict WHERE text = '" + name + "')"));
}
} // namespace

TEST_CASE("gc_dictionary: orphans go, referenced strings stay, a stale cache id never comes back",
          "[echo][fold][gc]") {
    auto f = make_fold_db();
    fold_names(*f, {"b.exe", "keep.exe", "z.exe"}); // b.exe gets a LOW id: not the table's max
    const int64_t old_id = f->n("SELECT id FROM echo_dict WHERE text='b.exe'");
    drop_rows_of(*f, "b.exe");

    const auto g = f->fold.gc_dictionary(f->db, std::chrono::steady_clock::now() + kHour);
    REQUIRE(g.has_value());
    CHECK(g->deleted == 1);
    CHECK_FALSE(g->deadline_hit);
    CHECK(f->n("SELECT COUNT(*) FROM echo_dict WHERE text='b.exe'") == 0);
    CHECK(f->n("SELECT COUNT(*) FROM echo_dict WHERE text IN ('keep.exe','z.exe','u','')") == 4);

    // Fold b.exe again: the cache must not hand back the deleted id.
    fold_names(*f, {"b.exe"});
    CHECK(f->n("SELECT id FROM echo_dict WHERE text='b.exe'") != old_id);
    CHECK(integrity_violations(*f) == 0);
}

TEST_CASE("gc_dictionary: a deadline already past deletes nothing and is not an error", "[echo][fold][gc]") {
    auto f = make_fold_db();
    fold_names(*f, {"a.exe"});
    drop_rows_of(*f, "a.exe");
    const auto g = f->fold.gc_dictionary(f->db, std::chrono::steady_clock::now() - kHour);
    REQUIRE(g.has_value());
    CHECK(g->deadline_hit);
    CHECK(g->deleted == 0);
    CHECK(f->n("SELECT COUNT(*) FROM echo_dict WHERE text='a.exe'") == 1);
}

TEST_CASE("gc_dictionary: a deadline that passes mid-statement rolls the batch back, then GC resumes",
          "[echo][fold][gc]") {
    // Injected clock: the pre-batch check sees time before the deadline, every later reading
    // (the progress handler's) sees it after. No wall-clock dependence.
    const auto t0 = std::chrono::steady_clock::time_point{} + std::chrono::hours(100);
    auto calls = std::make_shared<std::atomic<int>>(0);
    auto f = make_fold_db(true, [t0, calls] { return calls->fetch_add(1) == 0 ? t0 : t0 + kHour; });
    REQUIRE(f->db.execute_sql("WITH RECURSIVE s(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM s WHERE n < 3000) "
                              "INSERT INTO echo_dict(text) SELECT 'orphan-' || n FROM s"));
    // A VACUUM resets the schema, so the pass's first prepare re-loads it under the progress
    // handler: the deadline can interrupt that prepare, and it must still read as a deadline hit.
    REQUIRE(f->db.execute_sql("VACUUM"));
    const auto g = f->fold.gc_dictionary(f->db, t0 + std::chrono::seconds(1));
    REQUIRE(g.has_value());
    CHECK(g->deadline_hit);
    CHECK_FALSE(g->live_set_built); // the scan did not fit: "nothing orphaned" would be a lie
    CHECK(g->deleted == 0);
    CHECK(f->n("SELECT COUNT(*) FROM echo_dict") == 3000); // the interrupted scan rolled back
    // The progress handler is cleared on every exit: a long statement on the trusted
    // connection must not call into the destroyed GcProgress.
    const char* long_stmt = "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM c WHERE n < 200000) "
                            "SELECT COUNT(*) FROM c";
    CHECK(f->n(long_stmt) == 200000);
    CHECK(f->n("SELECT COUNT(*) FROM sqlite_temp_master") == 0); // the orphan table is dropped on every exit

    // The connection is healthy and a generous deadline now finishes the job: one scan,
    // then two batches by id.
    calls->store(1);
    const auto done = f->fold.gc_dictionary(f->db, t0 + 2 * kHour);
    REQUIRE(done.has_value());
    CHECK_FALSE(done->deadline_hit);
    CHECK(done->live_set_built);
    CHECK(done->deleted == 3000);
    CHECK(f->n("SELECT COUNT(*) FROM echo_dict") == 0);
    CHECK(f->n(long_stmt) == 200000);
    CHECK(f->n("SELECT COUNT(*) FROM sqlite_temp_master") == 0);
}

TEST_CASE("gc_dictionary: a real failure is an error, never an empty success", "[echo][fold][gc]") {
    auto f = make_fold_db();
    REQUIRE(f->db.execute_sql("DROP TABLE echo_dict"));
    const auto g = f->fold.gc_dictionary(f->db, std::chrono::steady_clock::now() + kHour);
    CHECK_FALSE(g.has_value());
}

TEST_CASE("dictionary_orphans_sql: one EXCEPT term per interned key column; the chain fits SQLite's compound limit",
          "[echo][fold][gc]") {
    std::size_t terms = 0;
    for (const auto& d : fold_sources())
        if (!d.own_tables)
            for (std::size_t t = 0; t < d.tiers.size(); ++t)
                for (const auto& c : d.columns)
                    terms += c.interned ? 1 : 0;
    const auto sql = dictionary_orphans_sql();
    std::size_t found = 0;
    for (auto pos = sql.find(" EXCEPT "); pos != std::string::npos; pos = sql.find(" EXCEPT ", pos + 1))
        ++found;
    CHECK(found == terms);
    CHECK(terms < 500); // SQLITE_MAX_COMPOUND_SELECT
    Mem m;
    open_mem(m);
    REQUIRE(exec(m.db, generate_fold_ddl()));
    REQUIRE(exec(m.db, "CREATE TEMP TABLE echo_dict_orphan (id INTEGER PRIMARY KEY)"));
    CHECK(prepare(m.db, sql) != nullptr);
}

TEST_CASE("fold_rows waits while a GC pass holds op_mu_", "[echo][fold][gc][concurrency]") {
    // The injected clock runs under op_mu_ (the first reading is the GC pass's own): park
    // it there, then a fold started meanwhile must not complete until the pass is released.
    std::promise<void> parked, release;
    auto release_f = release.get_future().share();
    std::atomic<bool> first{true};
    auto f = make_fold_db(true, [&] {
        if (first.exchange(false)) {
            parked.set_value();
            release_f.wait();
        }
        return std::chrono::steady_clock::now();
    });
    auto acc = make_acc("process"); // built here: no Catch2 assertions off the main thread
    process_delta({pev(kT0, "started", "a.exe")}, acc);
    std::atomic<bool> fold_ok{false};
    std::promise<void> folded;
    std::thread gc([&] { (void)f->fold.gc_dictionary(f->db, std::chrono::steady_clock::now() + kHour); });
    parked.get_future().wait();
    std::thread fold([&] {
        fold_ok = f->fold.fold_rows(f->db, "process", acc).has_value();
        folded.set_value();
    });
    auto folded_f = folded.get_future();
    const auto blocked = folded_f.wait_for(std::chrono::milliseconds(150));
    release.set_value();
    gc.join();
    fold.join();
    CHECK(blocked == std::future_status::timeout);
    CHECK(fold_ok);
    CHECK(integrity_violations(*f) == 0);
}

TEST_CASE("fold and GC serialise: no dangling dictionary id after concurrent use",
          "[echo][fold][gc][concurrency]") {
    auto f = make_fold_db();
    REQUIRE(f->db.execute_sql("PRAGMA synchronous=OFF"));
    // One batch folds BEFORE the threads start, so the dictionary already holds strings
    // (seed_proc, seed_user) that nothing re-references: the maintainer's first pass orphans
    // them and GC deletes them on every schedule.
    {
        auto seed = make_acc("process");
        process_delta({pev(kT0, "started", "seed_proc", "seed_user")}, seed);
        REQUIRE(f->fold.fold_rows(f->db, "process", seed).has_value());
    }
    constexpr int kMinPasses = 20;
    std::latch start{2}; // both threads begin together
    std::atomic<bool> folding{true};
    std::atomic<int> fold_errors{0}, gc_errors{0};
    std::atomic<int64_t> gc_deleted{0};

    std::thread folder([&] {
        start.arrive_and_wait();
        for (int i = 0; i < 200; ++i) {
            TierAccumulator acc(*fold_source("process")); // no Catch2 assertions off the main thread
            process_delta({pev(kT0 + i, "started", ("proc_" + std::to_string(i % 16)).c_str(),
                               ("user_" + std::to_string(i)).c_str())},
                          acc);
            if (!f->fold.fold_rows(f->db, "process", acc).has_value())
                ++fold_errors;
        }
        folding = false;
    });
    std::thread maintainer([&] {
        start.arrive_and_wait();
        // A work loop, not a poll: every pass is a real retention-style DELETE then a real GC.
        // At least kMinPasses passes run whatever the schedule, then it continues until the
        // folder is done.
        for (int pass = 0; pass < kMinPasses || folding; ++pass) {
            // Simulated retention (drops references), then GC (drops the orphans).
            for (const char* t : {"process_hourly_r", "process_daily_r", "process_monthly_r"})
                if (!f->db.execute_sql(std::string("DELETE FROM ") + t))
                    ++gc_errors;
            const auto g = f->fold.gc_dictionary(f->db, std::chrono::steady_clock::now() + kHour);
            if (g.has_value())
                gc_deleted += g->deleted;
            else
                ++gc_errors;
        }
    });
    folder.join();
    maintainer.join();

    CHECK(fold_errors == 0);
    CHECK(gc_errors == 0);
    CHECK(gc_deleted > 0); // GC really ran: at least the seed strings went
    CHECK(integrity_violations(*f) == 0);

    // Positive control: the same check does see a dangling id.
    REQUIRE(f->db.execute_sql("INSERT INTO process_hourly_r(hour_ts, name_id, user_id, parent_name_id) "
                              "VALUES (1, 999999, 999999, 999999)"));
    CHECK(integrity_violations(*f) > 0);

    // Equivalence pin: the view never hides a row. A dangling id reads as a NULL text key,
    // and the view's row count stays the row table's: that is what makes the authorizer's
    // column-less read of a `_r` table expose nothing the view does not.
    CHECK(f->n("SELECT COUNT(*) FROM process_hourly") == f->n("SELECT COUNT(*) FROM process_hourly_r"));
    CHECK(f->n("SELECT COUNT(*) FROM process_hourly WHERE name IS NULL AND user IS NULL") == 1);
}

// ═════════════════════════════════════════════════════════════════════════════
// The operator-SQL boundary
// ═════════════════════════════════════════════════════════════════════════════

namespace {
// Exactly the plugin's path: validate and translate, then the read-only connection.
std::expected<QueryResult, std::string> plugin_sql(EchoDatabase& db, const std::string& sql) {
    auto v = validate_and_translate_sql(sql);
    if (!v)
        return std::unexpected(v.error());
    return db.execute_user_query(*v);
}
} // namespace

TEST_CASE("operator SQL reads the roll-up views, never the tables behind them", "[echo][fold][authorizer]") {
    auto f = make_fold_db();
    fold_names(*f, {"a.exe"});

    const auto ok = plugin_sql(f->db, "SELECT name, user, start_count FROM process_hourly");
    INFO("error: " << (ok.has_value() ? std::string{} : ok.error()));
    REQUIRE(ok.has_value());
    REQUIRE(ok->rows.size() == 1);
    CHECK(ok->rows[0] == QueryRow{"a.exe", "u", "1"});
    CHECK(plugin_sql(f->db, "SELECT * FROM $Process_Daily").has_value()); // the $-name path
    // A tier the registry does not declare is still allowed (a view, by name).
    CHECK(plugin_sql(f->db, "SELECT * FROM netqual_hourly").has_value());
    CHECK(plugin_sql(f->db, "SELECT 'with' AS w FROM process_hourly").has_value());
    // A partial projection and a COUNT(*) must work: they are the common queries.
    CHECK(plugin_sql(f->db, "SELECT name FROM process_hourly WHERE start_count > 0").has_value());
    const auto cnt = plugin_sql(f->db, "SELECT COUNT(*) FROM process_hourly");
    REQUIRE(cnt.has_value());
    CHECK(cnt->rows[0][0] == "1");
    // A column-less read of a row table exposes only a count the view already exposes:
    // bare COUNT(*), SELECT 1 and EXISTS are the allowed shapes, pinned here. Every
    // column, id, rowid and oid read of a `_r` table stays denied, as does a count that
    // a column narrows (WHERE, ORDER BY, GROUP BY): those read the column.
    for (const char* sql : {
             "SELECT COUNT(*) FROM process_hourly_r",
             "SELECT 1 FROM process_hourly_r",
             "SELECT EXISTS(SELECT 1 FROM process_hourly_r)",
         }) {
        INFO(sql);
        CHECK(plugin_sql(f->db, sql).has_value());
    }

    for (const char* sql : {
             "SELECT * FROM echo_dict",
             "SELECT * FROM process_hourly_r",
             "SELECT * FROM echo_fold_seen",
             "SELECT p.name FROM process_hourly p JOIN echo_dict d ON d.id = p.id",
             "SELECT (SELECT COUNT(*) FROM echo_dict)",
             "SELECT * FROM echo_dict AS process_hourly",
             "SELECT * FROM (SELECT * FROM echo_dict) AS process_hourly",
             "SELECT * FROM usage_daily", // #4260 stays denied
             "SELECT COUNT(*) FROM echo_dict",
             "SELECT 1 FROM echo_dict",
             "SELECT COUNT(*) FROM echo_fold_seen",
             "SELECT 1 FROM echo_fold_seen",
             "SELECT hour_ts FROM process_hourly_r",
             "SELECT id FROM process_hourly_r",
             "SELECT oid FROM process_hourly_r",
             "SELECT _rowid_ FROM process_hourly_r",
             "SELECT rowid FROM process_hourly_r",
             "SELECT name_id FROM process_hourly_r",
             "SELECT 1 FROM process_hourly_r WHERE rowid = 1",
             "SELECT 1 FROM process_hourly_r ORDER BY name_id",
             "SELECT COUNT(*) FROM process_hourly_r GROUP BY user_id",
             "SELECT COUNT(*) FROM perf_hourly_r WHERE cpu_avg > 0",
         }) {
        INFO(sql);
        CHECK_FALSE(plugin_sql(f->db, sql).has_value());
    }
}

TEST_CASE("operator SQL: NATURAL and USING joins never reach the dictionary or the usage tables",
          "[echo][fold][authorizer]") {
    // SQLite resolves a NATURAL / USING join's shared columns before name resolution, so
    // those column reads never reach the authorizer, and a table whose only reads are
    // USING terms is never reported column-less either. The probes below drive the
    // read-only connection DIRECTLY (validator bypassed) and pin what the authorizer alone
    // does; the plugin path (validator first) must refuse every one of them.
    auto f = make_fold_db();
    fold_names(*f, {"a.exe"});
    {
        UserEvent li;
        li.ts = kT0;
        li.action = "login";
        li.user = "u";
        li.domain = "d";
        li.logon_type = "2";
        auto acc = make_acc("user");
        user_delta({li}, acc);
        REQUIRE(f->fold.fold_rows(f->db, "user", acc).has_value());
    }
    // A usage row for the same user on the same day (the usage tables stay denied, #4260).
    REQUIRE(f->db.execute_sql("INSERT INTO usage_daily_user(day_ts, exe_key, user) VALUES (" +
                              std::to_string(kDay0) + ", 'x.exe', 'u')"));

    struct Probe {
        const char* sql;
        bool authorizer_admits; // observed on the shipped SQLite, pinned
    };
    // Observed: the authorizer alone ADMITS a NATURAL join and a USING join over real columns (the
    // dictionary or a usage table), because those column reads never reach it. USING over the rowid
    // alias `id` is the one shape it still catches: a rowid-alias read leaves the table
    // column-less, which is reported, and the dictionary is denied column-less. That is why the
    // validator, not the authorizer, is the closure for NATURAL / USING; these pins say so.
    const Probe probes[] = {
        {"SELECT COUNT(*) FROM echo_dict a NATURAL JOIN echo_dict b", true},
        {"SELECT COUNT(*) FROM echo_dict a JOIN echo_dict b USING (text)", true},
        {"SELECT COUNT(*) FROM echo_dict a JOIN echo_dict b USING (id)", false},
        {"SELECT COUNT(*) FROM user_daily NATURAL JOIN usage_daily_user WHERE user_daily.user = 'u'", true},
        {"SELECT COUNT(*) FROM user_daily JOIN usage_daily_user USING (day_ts, user) "
         "WHERE user_daily.user = 'u'",
         true},
    };
    for (const auto& p : probes) {
        INFO(p.sql);
        const auto direct = f->db.execute_user_query(p.sql);
        CHECK(direct.has_value() == p.authorizer_admits);
        if (direct.has_value()) {
            REQUIRE(direct->rows.size() == 1);
            CHECK(direct->rows[0][0] != "0"); // it really reached the data
        }
    }
    for (const auto& p : probes) {
        INFO(p.sql);
        const auto v = validate_and_translate_sql(p.sql);
        REQUIRE_FALSE(v.has_value());
        CHECK(v.error().find("forbidden keyword") != std::string::npos);
    }
    // ON joins keep working, and identifiers or literals that merely contain the words
    // are not the keywords.
    CHECK(plugin_sql(f->db, "SELECT COUNT(*) FROM process_hourly p JOIN process_daily d ON d.name = p.name")
              .has_value());
    CHECK(plugin_sql(f->db, "SELECT name AS using_it, 'natural' AS n FROM process_hourly").has_value());
    // Positive control: a quoted identifier that is exactly a keyword is a name, not the keyword.
    for (const char* sql : {"SELECT name AS \"natural\" FROM process_hourly",
                            "SELECT name AS [natural] FROM process_hourly",
                            "SELECT name AS `using` FROM process_hourly"}) {
        INFO(sql);
        CHECK(plugin_sql(f->db, sql).has_value());
    }
}

TEST_CASE("operator SQL: a CTE can never shadow a roll-up view name", "[echo][fold][authorizer]") {
    // SQLite reports a CTE's reads under the CTE's name, so the authorizer's "reached through a
    // roll-up view" rule would admit `WITH process_hourly AS (SELECT * FROM echo_dict)` -- exactly
    // why the validator (layer 1, the only entry to the plugin's echo.sql) refuses WITH outright.
    // The authorizer rule is defence in depth behind that refusal, not the closure.
    auto f = make_fold_db();
    fold_names(*f, {"a.exe"});
    for (const char* sql : {
             "SELECT * FROM (WITH process_hourly AS (SELECT * FROM echo_dict) SELECT * FROM process_hourly)",
             "SELECT * FROM (with process_hourly AS (SELECT * FROM echo_dict) SELECT * FROM process_hourly)",
             "SELECT * FROM (WITH \"process_hourly\" AS (SELECT * FROM echo_dict) SELECT * FROM \"process_hourly\")",
             "SELECT * FROM (WITH process_hourly_r AS (SELECT * FROM echo_dict) SELECT * FROM process_hourly_r)",
             "SELECT * FROM (SELECT * FROM (WITH process_hourly AS (SELECT * FROM echo_dict) "
             "SELECT * FROM process_hourly))",
         }) {
        INFO(sql);
        const auto v = validate_and_translate_sql(sql);
        REQUIRE_FALSE(v.has_value());
        CHECK(v.error().find("forbidden keyword") != std::string::npos);
    }
    CHECK_FALSE(validate_and_translate_sql("WITH x AS (SELECT 1) SELECT * FROM x").has_value());
    // An unterminated quoting runs to the end of the input, as SQLite reads it, and SQLite then
    // refuses to tokenise it: nothing executes.
    CHECK_FALSE(plugin_sql(f->db, "SELECT 1 AS \"x, (WITH process_hourly AS (SELECT * FROM echo_dict) "
                                  "SELECT * FROM process_hourly)")
                    .has_value());
    // Identifiers that merely contain the word are not the keyword.
    CHECK(validate_and_translate_sql("SELECT name AS without_it FROM process_hourly").has_value());
    // Positive control: a quoted identifier that is exactly the keyword is a name.
    for (const char* sql : {"SELECT name AS \"with\" FROM process_hourly", "SELECT name AS [with] FROM process_hourly",
                            "SELECT name AS `with` FROM process_hourly"}) {
        INFO(sql);
        CHECK(plugin_sql(f->db, sql).has_value());
    }
}

TEST_CASE("validate_and_translate_sql: a quoted identifier is one token and $ names translate in it",
          "[echo][fold][authorizer][sql]") {
    // Quoted identifiers that merely contain a keyword or a comment or quote marker validate.
    for (const char* sql : {"SELECT 1 AS \"with\"", "SELECT 1 AS `natural`", "SELECT 1 AS [using]",
                            "SELECT 1 AS \"a--b\"", "SELECT 1 AS [a/*b]", "SELECT 1 AS \"it's\"",
                            "SELECT 1 AS \"a\"\"--\""}) {
        INFO(sql);
        CHECK(validate_and_translate_sql(sql).has_value());
    }
    // A $name in a quoted identifier is translated like one in code; in a literal it is data (#631).
    const auto q = validate_and_translate_sql(
        "SELECT 1 AS \"$Process_Hourly\", 2 AS [$Process_Daily], 3 AS `$Process_Hourly`, '$Process_Hourly' "
        "FROM \"$Process_Hourly\"");
    REQUIRE(q.has_value());
    CHECK(*q == "SELECT 1 AS \"process_hourly\", 2 AS [process_daily], 3 AS `process_hourly`, '$Process_Hourly' "
                "FROM \"process_hourly\"");
    // Every bound-parameter marker is refused, named or not.
    for (const char* sql : {"SELECT ?", "SELECT ?1", "SELECT $a", "SELECT :a", "SELECT @a", "SELECT #1"}) {
        INFO(sql);
        const auto r = validate_and_translate_sql(sql);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("bound-parameter marker") != std::string::npos);
    }
}

TEST_CASE("operator SQL: no validator-accepted string runs a refused payload", "[echo][fold][authorizer][sql]") {
    // A differential corpus: the tokens that swallow text in SQLite (the three identifier quotings,
    // both comments, and the variable token with its "(...)" body) placed before a payload only the
    // validator guards. Whatever the validator accepts must not run it.
    auto f = make_fold_db();
    fold_names(*f, {"zz_sentinel"});
    const std::string payloads[] = {
        "(SELECT count(*)+7777777 FROM echo_dict a NATURAL JOIN echo_dict b)",
        // The CTE shadows a view name, so the authorizer alone would admit it.
        "(WITH process_hourly AS (SELECT text AS name FROM echo_dict) SELECT group_concat(name) FROM process_hourly)"};
    const auto leaks = [](const std::expected<QueryResult, std::string>& r) {
        if (!r)
            return false;
        for (const auto& row : r->rows)
            for (const auto& cell : row)
                if (cell.find("zz_sentinel") != std::string::npos ||
                    (cell.size() >= 7 && cell.find_first_not_of("0123456789") == std::string::npos &&
                     std::stoll(cell) >= 7777777))
                    return true;
        return false;
    };
    for (const auto& p : payloads) // positive control: the detector sees each payload when it runs
        REQUIRE(leaks(f->db.execute_user_query("SELECT 1, " + p)));

    int accepted = 0, parameter_refusals = 0;
    const auto probe = [&](const std::string& sql) { // refused, or it runs without leaking a payload
        INFO(sql);
        const auto v = validate_and_translate_sql(sql);
        parameter_refusals += !v && v.error().find("bound-parameter marker") != std::string::npos;
        accepted += v.has_value();
        if (v)
            CHECK_FALSE(leaks(f->db.execute_user_query(*v)));
    };
    // The known swallowing shapes, each in front of each payload: a quoted identifier holding a
    // comment opener, and a variable token whose "(...)" body holds one.
    for (const char* unit : {"1 AS \"--\"", "1 AS `--`", "1 AS [--]", "1 AS \"/*\"", "@x(--)", "$x(--)",
                             ":x(--)", "#x(--)", "@x(/*)"})
        for (const auto& p : payloads)
            probe(std::string("SELECT ") + unit + ", " + p);
    // Then every pair of swallowing tokens in front of each payload, as an alias or a select item.
    const char* const tokens[] = {"'", "\"", "`", "[", "]", "--", "/*", "*/", "@x(", "$x(", ":x(", "#x(", ")", "\n", " "};
    for (const char* a : tokens)
        for (const char* b : tokens)
            for (const auto& p : payloads)
                for (const char* lead : {"SELECT 1 AS ", "SELECT 1, "})
                    probe(std::string(lead) + a + b + ", " + p);
    CHECK(accepted > 0);           // not vacuous: the validator does accept some of the corpus
    CHECK(parameter_refusals > 0); // and the corpus does reach the variable-token shapes
}

// ═════════════════════════════════════════════════════════════════════════════
// Three-day synthetic run
// ═════════════════════════════════════════════════════════════════════════════

namespace {

constexpr int64_t kStart = 1793361600; // 2026-10-30T12:00:00Z
constexpr int64_t kOct1 = 1790812800;  // 2026-10-01T00:00:00Z
constexpr int64_t kNov1 = 1793491200;  // 2026-11-01T00:00:00Z
// The shared tick, seconds. 300 s (864 ticks over 72 h) rather than 60 s (4,320): five times
// fewer transactions on a suite that already runs long, with the same hour, day and month
// boundaries and the same late event exercised.
constexpr int64_t kStep = 300;
constexpr int64_t kTicks = 72 * 3600 / kStep;

// The independent reducer's calendar: no bucket_start. The window starts after the epoch and
// sits inside October/November 2026, so truncation is floor and the month is one of two constants.
int64_t ref_bucket(int64_t ts, std::string_view tier) {
    if (tier == "hourly")
        return ts / 3600 * 3600;
    if (tier == "daily")
        return ts / 86400 * 86400;
    return ts >= kNov1 ? kNov1 : kOct1;
}

struct Reducer {
    std::map<std::string, int64_t> sums;                           // src|tier|bucket|key|measure
    std::map<std::string, std::pair<double, int64_t>> perf;        // tier|bucket -> cpu sum, samples
    std::map<std::string, std::pair<int64_t, std::string>> svc;    // tier|bucket|name -> ts, status

    void add(const char* src, int64_t ts, const std::string& key, const char* measure) {
        for (auto tier : fold_source(src)->tiers)
            sums[std::format("{}|{}|{}|{}|{}", src, tier, ref_bucket(ts, tier), key, measure)] += 1;
    }
};

struct Headline {
    const char* src;
    std::vector<const char*> keys;
    const char* measure;
};

std::string first_diffs(const std::map<std::string, int64_t>& want, const std::map<std::string, int64_t>& got) {
    std::string out;
    int shown = 0;
    for (const auto& [k, v] : want) {
        const auto it = got.find(k);
        if ((it == got.end() || it->second != v) && shown++ < 5)
            out += std::format("want {}={} got {}\n", k, v, it == got.end() ? "(none)" : std::to_string(it->second));
    }
    for (const auto& [k, v] : got)
        if (!want.contains(k) && shown++ < 5)
            out += std::format("unexpected {}={}\n", k, v);
    return out;
}

} // namespace

TEST_CASE("synthetic three-day run: every source, every tier equals the independent reducer",
          "[echo][fold][synthetic]") {
    auto f = make_fold_db();
    REQUIRE(f->db.execute_sql("PRAGMA synchronous=OFF"));
    Reducer red;
    const auto snap = [&](const char* src, TierAccumulator& acc) {
        REQUIRE(f->fold.fold_rows(f->db, src, acc).has_value());
    };
    const auto cursor = [&](const char* src, std::vector<KeyedContribution> c, int64_t n) {
        REQUIRE(f->fold.fold_cursor_rows(f->db, src, c, "{\"v\":1,\"n\":" + std::to_string(n) + "}", {}).has_value());
    };
    const auto tag = [](const char* p, int64_t i) { return std::string{p} + std::to_string(i); };
    const auto perf_sample = [&](int64_t ts, double cpu) {
        PerfRow p;
        p.ts = ts;
        p.cpu_pct = cpu;
        TierAccumulator acc(*fold_source("perf"));
        perf_delta({p}, acc);
        snap("perf", acc);
        red.add("perf", ts, "", "samples");
        for (auto tier : fold_source("perf")->tiers) {
            auto& slot = red.perf[std::format("{}|{}", tier, ref_bucket(ts, tier))];
            slot.first += cpu;
            slot.second += 1;
        }
    };

    for (int64_t n = 0; n < kTicks; ++n) {
        const int64_t ts = kStart + n * kStep;
        const int64_t i = n;
        if (n % 2 == 0) { // process
            const auto name = tag("p", (n / 2) % 4), user = tag("u", (n / 2) % 2);
            TierAccumulator acc(*fold_source("process"));
            process_delta({pev(ts, "started", name.c_str(), user.c_str())}, acc);
            snap("process", acc);
            red.add("process", ts, name + "|" + user, "start_count");
        }
        { // tcp
            NetworkEvent e;
            e.ts = ts;
            e.action = "connected";
            e.proto = "tcp";
            e.remote_addr = "10.0.0." + std::to_string(i % 5);
            e.remote_port = 443;
            e.process_name = "chrome";
            TierAccumulator acc(*fold_source("tcp"));
            tcp_delta({e}, acc);
            snap("tcp", acc);
            red.add("tcp", ts, e.remote_addr + "|tcp", "connect_count");
        }
        if (n % 3 == 0) { // service
            ServiceEvent e;
            e.ts = ts;
            e.action = "state_changed";
            e.name = tag("svc", (n / 3) % 3);
            e.status = ((n / 3) % 2) ? "running" : "stopped";
            TierAccumulator acc(*fold_source("service"));
            service_delta({e}, acc);
            snap("service", acc);
            red.add("service", ts, e.name, "status_changes");
            for (auto tier : fold_source("service")->tiers) {
                auto& slot = red.svc[std::format("{}|{}|{}", tier, ref_bucket(ts, tier), e.name)];
                if (ts >= slot.first)
                    slot = {ts, e.status};
            }
        }
        if (n % 6 == 0) { // user
            UserEvent e;
            e.ts = ts;
            e.action = "login";
            e.user = tag("u", (n / 6) % 3);
            e.domain = "D";
            TierAccumulator acc(*fold_source("user"));
            user_delta({e}, acc);
            snap("user", acc);
            red.add("user", ts, e.user + "|D", "login_count");
        }
        perf_sample(ts, static_cast<double>(n % 100));
        if (n % 3 == 0) { // procperf
            ProcPerfRow p;
            p.ts = ts;
            p.name = tag("app", (n / 3) % 3);
            p.version = "1.0";
            TierAccumulator acc(*fold_source("procperf"));
            procperf_delta({p}, acc);
            snap("procperf", acc);
            red.add("procperf", ts, p.name, "samples");
        }
        if (n % 2 == 0) { // netqual
            NetQualRow q;
            q.ts = ts;
            q.proto = "tcp";
            q.remote_bucket = ((n / 2) % 2) ? "public" : "private";
            q.process_name = "x";
            q.rtt_us = 500;
            TierAccumulator acc(*fold_source("netqual"));
            netqual_delta({q}, acc);
            snap("netqual", acc);
            red.add("netqual", ts, q.remote_bucket, "samples");
        }
        if (n % 2 == 0) { // module
            ModuleRow m;
            m.ts = ts;
            m.action = "loaded";
            m.module_name = tag("m", (n / 2) % 5) + ".dll";
            m.process_name = "p";
            TierAccumulator acc(*fold_source("module"));
            module_delta({m}, acc);
            snap("module", acc);
            red.add("module", ts, m.module_name, "load_count");
        }
        if (n % 24 == 0) { // software
            SoftwareEvent e;
            e.ts = ts;
            e.action = "installed";
            e.name = tag("sw", (n / 24) % 2);
            TierAccumulator acc(*fold_source("software"));
            software_delta({e}, acc);
            snap("software", acc);
            red.add("software", ts, e.name, "install_count");
        }
        if (n % 6 == 0) { // arp
            ArpEvent e;
            e.ts = ts;
            e.action = "appeared";
            e.iface = "en0";
            e.ip_address = "10.0.0." + std::to_string((n / 6) % 4);
            TierAccumulator acc(*fold_source("arp"));
            arp_delta({e}, acc);
            snap("arp", acc);
            red.add("arp", ts, e.ip_address, "appear_count");
        }
        if (n % 3 == 0) { // dns
            DnsEvent e;
            e.ts = ts;
            e.action = "appeared";
            e.name = tag("n", (n / 3) % 6);
            e.record_type = "A";
            TierAccumulator acc(*fold_source("dns"));
            dns_delta({e}, acc);
            snap("dns", acc);
            red.add("dns", ts, e.name, "appear_count");
        }
        if (n % 6 == 0) { // netconn
            NetConnRow e;
            e.ts = ts;
            e.action = ((n / 6) % 2) ? "connected" : "disconnected";
            e.channel = "ncsi";
            TierAccumulator acc(*fold_source("netconn"));
            netconn_delta({e}, acc);
            snap("netconn", acc);
            red.add("netconn", ts, e.action, "event_count");
        }
        if (n % 12 == 0) { // mapdrive
            MapDriveEvent e;
            e.ts = ts;
            e.action = "appeared";
            e.direction = "outbound";
            e.remote_path = tag("\\\\srv\\share", (n / 12) % 2);
            TierAccumulator acc(*fold_source("mapdrive"));
            mapdrive_delta({e}, acc);
            snap("mapdrive", acc);
            red.add("mapdrive", ts, e.remote_path, "appear_count");
        }
        if (n % 12 == 0) { // power (cursor)
            PowerEvent e;
            e.ts = ts;
            e.action = ((n / 12) % 2) ? "wake" : "sleep";
            e.record_key = tag("pk", n);
            cursor("power", power_delta({e}), n);
            red.add("power", ts, e.action, "event_count");
        }
        if (n % 24 == 0) { // removable (cursor)
            RemovableEvent e;
            e.ts = ts;
            e.action = "attached";
            e.device_key = tag("d", (n / 24) % 2);
            e.record_key = tag("rk", n);
            cursor("removable", removable_delta({e}), n);
            red.add("removable", ts, e.device_key, "event_count");
        }
        if (n % 3 == 0) { // registry (cursor)
            RegistryEvent e;
            e.ts = ts;
            e.hive = "HKLM";
            e.key_path = tag("k", (n / 3) % 3);
            e.value_name = "v";
            e.action = "changed";
            e.record_key = tag("gk", n);
            cursor("registry", registry_delta({e}), n);
            red.add("registry", ts, e.key_path, "change_count");
        }
    }

    // A late event lands in its own (old) buckets: a distinct process, a perf sample that
    // merges into an existing hour, and a new cursor record.
    const int64_t late = kStart + 3600 + 5;
    {
        TierAccumulator acc(*fold_source("process"));
        process_delta({pev(late, "started", "late.exe", "u9")}, acc);
        snap("process", acc);
        red.add("process", late, "late.exe|u9", "start_count");
    }
    perf_sample(late, 40.0);
    {
        PowerEvent e;
        e.ts = late;
        e.action = "sleep";
        e.record_key = "pk-late";
        cursor("power", power_delta({e}), kTicks);
        red.add("power", late, "sleep", "event_count");
    }

    const std::vector<Headline> headlines = {
        {"process", {"name", "user"}, "start_count"}, {"tcp", {"remote_addr", "proto"}, "connect_count"},
        {"service", {"name"}, "status_changes"},      {"user", {"user", "domain"}, "login_count"},
        {"perf", {}, "samples"},                      {"procperf", {"name"}, "samples"},
        {"netqual", {"remote_bucket"}, "samples"},    {"module", {"module_name"}, "load_count"},
        {"software", {"name"}, "install_count"},      {"arp", {"ip_address"}, "appear_count"},
        {"dns", {"name"}, "appear_count"},            {"netconn", {"action"}, "event_count"},
        {"mapdrive", {"remote_path"}, "appear_count"}, {"power", {"action"}, "event_count"},
        {"removable", {"device_key"}, "event_count"}, {"registry", {"key_path"}, "change_count"},
    };
    REQUIRE(headlines.size() == 16); // every fold source but usage

    std::map<std::string, int64_t> actual;
    for (const auto& h : headlines) {
        std::string key = "''";
        for (std::size_t k = 0; k < h.keys.size(); ++k)
            key = (k == 0 ? std::string{} : key + " || '|' || ") + h.keys[k];
        for (auto tier : fold_source(h.src)->tiers) {
            const auto sql = std::format("SELECT {}, {}, SUM({}) FROM {} GROUP BY 1, 2", ts_column_for_suffix(tier),
                                         key, h.measure, fold_view_name(h.src, tier));
            for (const auto& r : f->q(sql))
                actual[std::format("{}|{}|{}|{}|{}", h.src, tier, r[0], r[1], h.measure)] = std::stoll(r[2]);
        }
    }
    const auto diffs = first_diffs(red.sums, actual);
    INFO(diffs);
    CHECK(diffs.empty());

    // hourly -> daily -> monthly totals agree for every source and key.
    for (const auto& h : headlines) {
        std::map<std::string, int64_t> total; // tier -> sum
        for (auto tier : fold_source(h.src)->tiers) {
            const std::string prefix = std::format("{}|{}|", h.src, tier);
            for (const auto& [k, v] : actual)
                if (k.starts_with(prefix))
                    total[std::string{tier}] += v;
        }
        INFO("source " << h.src);
        for (const auto& [tier, v] : total)
            CHECK(v == total.begin()->second);
    }

    // perf: exact sums, exact weighted means, in every tier.
    for (auto tier : fold_source("perf")->tiers) {
        const auto r = f->q(std::format("SELECT {}, samples, cpu_sum, cpu_avg FROM perf_{}", ts_column_for_suffix(tier), tier));
        REQUIRE_FALSE(r.empty());
        for (const auto& row : r) {
            const auto& want = red.perf.at(std::format("{}|{}", tier, row[0]));
            CHECK(std::stoll(row[1]) == want.second);
            CHECK(std::stod(row[2]) == want.first);
            CHECK(std::abs(std::stod(row[3]) - want.first / static_cast<double>(want.second)) < 1e-9);
        }
        CHECK(r.size() == (tier == std::string_view{"hourly"} ? 72u : 4u)); // 72 hours, 4 calendar days
    }

    // service: last_status is the newest event's status in every tier.
    for (auto tier : fold_source("service")->tiers) {
        for (const auto& row : f->q(std::format("SELECT {}, name, last_status FROM service_{}", ts_column_for_suffix(tier), tier)))
            CHECK(row[2] == red.svc.at(std::format("{}|{}|{}", tier, row[0], row[1])).second);
    }

    // The late event owns its own rows.
    CHECK(f->n("SELECT COUNT(*) FROM process_hourly WHERE name='late.exe'") == 1);
    CHECK(f->n("SELECT hour_ts FROM process_hourly WHERE name='late.exe'") == ref_bucket(late, "hourly"));
    CHECK(integrity_violations(*f) == 0);
    CHECK(f->db.try_get_config(std::string{kFoldRejectedCounterKey}).value() == std::nullopt);
}
