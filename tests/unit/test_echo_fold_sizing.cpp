/**
 * test_echo_fold_sizing.cpp -- bytes-per-row ceilings for the roll-up substrate.
 *
 * Every fold source folds 20,000 distinct-key events in ONE transaction; the
 * test then reports how many bytes the roll-up tables and their unique index cost
 * per row. The dictionary and the replay ring grow in the same file, so each is
 * measured by a control (an in-memory copy of the same schema that receives the
 * identical strings / ring rows in the identical order) and subtracted. SQLite's
 * dbstat is not compiled into every build, so this uses page counts only.
 *
 * Tagged [fold_sizing], excluded from the main echo run and registered as its own
 * test() with a longer timeout (tests/meson.build).
 */

#include "echo_db.hpp"
#include "echo_fold.hpp"
#include "echo_fold_schema.hpp"
#include "test_helpers.hpp"

#include <sqlite3.h>

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <format>
#include <map>
#include <memory>
#include <string>
#include <vector>

using namespace yuzu::echo;

namespace {

constexpr int kEvents = 20'000;
constexpr int64_t kBase = 1793615400; // 2026-11-02T10:30:00Z: every event shares one hour/day/month

// A raw handle, closed on scope exit even when a REQUIRE fails after the open.
using Conn = yuzu::test::SqliteHandleOwner<sqlite3>;

void open_conn(Conn& c, const char* path, int flags) {
    REQUIRE(sqlite3_open_v2(path, &c.db, flags, nullptr) == SQLITE_OK);
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

int64_t pragma(sqlite3* db, const char* name) {
    const Stmt st = prepare(db, std::string("PRAGMA ") + name);
    REQUIRE(sqlite3_step(st.get()) == SQLITE_ROW);
    return sqlite3_column_int64(st.get(), 0);
}

int64_t used_bytes(sqlite3* db) {
    return (pragma(db, "page_count") - pragma(db, "freelist_count")) * pragma(db, "page_size");
}

void exec(sqlite3* db, const std::string& sql) {
    char* raw = nullptr;
    const int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &raw);
    const std::unique_ptr<char, decltype(&sqlite3_free)> err{raw, &sqlite3_free};
    INFO("sqlite: " << (err ? err.get() : ""));
    REQUIRE(rc == SQLITE_OK);
}

std::string padded(int n, int width) {
    std::string s = std::to_string(n);
    return std::string(static_cast<std::size_t>(width) - s.size(), '0') + s;
}

// A realistic value for the distinct column of a source. Lengths follow what the collectors emit.
std::string distinct_text(std::string_view src, std::string_view col, int n) {
    if (src == "tcp" && col == "remote_addr")
        return std::format("10.{}.{}.{}", (n >> 16) & 255, (n >> 8) & 255, n & 255);
    if (src == "registry" && col == "key_path")
        return "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" + padded(n, 6);
    return std::string{col} + "_" + padded(n, 6);
}

struct Built {
    TierAccumulator acc;
    std::vector<KeyedContribution> contributions; // cursor sources only
    std::string distinct_col;
};

// Realistic length of a TEXT measure: the registry value is the one large one (clipped to 512 B by
// the delta); a data type token, an image path and the rest are short.
std::size_t text_measure_len(std::string_view col) {
    if (col == "last_data")
        return 512;
    if (col == "last_actor_image")
        return 24;
    if (col == "last_data_type")
        return 6;
    return 16;
}

// kEvents events whose distinct column (the first interned key; the bucket for a keyless source)
// differs, every measure carrying a small but non-zero value.
Built build(const FoldSourceDef& def) {
    Built b{TierAccumulator(def), {}, {}};
    for (const auto& c : def.columns)
        if (c.interned) {
            b.distinct_col = std::string{c.name};
            break;
        }
    NamedValues measures; // identical for every event
    for (const auto& m : b.acc.measure_columns()) {
        if (m.sql_type == "TEXT")
            measures.emplace_back(m.name, vt(std::string(text_measure_len(m.name), 'x')));
        else if (m.sql_type == "REAL")
            measures.emplace_back(m.name, vr(12.5));
        else
            measures.emplace_back(m.name, vi(3));
    }
    for (int n = 0; n < kEvents; ++n) {
        NamedValues keys;
        int64_t ts = kBase;
        if (b.distinct_col.empty())
            ts = kBase + static_cast<int64_t>(n) * 3600; // perf: one hourly bucket per event
        else
            keys.emplace_back(b.distinct_col, vt(distinct_text(def.name, b.distinct_col, n)));
        if (def.cursor_source)
            b.contributions.push_back({"rk-" + padded(n, 6), n, ts, std::move(keys), measures});
        else
            b.acc.add(ts, keys, measures);
    }
    return b;
}

struct Sizes {
    double row_bytes{0};  // roll-up table + unique index bytes per row, all tiers
    double dict_bytes{0}; // dictionary bytes per distinct string
    double dict_text{0};  // mean length of those strings
    int64_t rows{0};
};

Sizes measure(const FoldSourceDef& def) {
    // Declared first so it is destroyed last, after the reader, the control copies and the database.
    yuzu::test::TempDbFile tmp{"yuzu_test_echo_fold_size_"};
    const auto& path = tmp.path;
    auto opened = EchoDatabase::open(path);
    REQUIRE(opened.has_value());
    EchoDatabase db = std::move(*opened);
    EchoFold fold;
    REQUIRE(fold.install_fold_schema(db).has_value());
    REQUIRE(db.execute_sql("PRAGMA synchronous=OFF"));

    Conn reader;
    open_conn(reader, path.string().c_str(), SQLITE_OPEN_READONLY);
    const int64_t before = used_bytes(reader.db);

    Built b = build(def);
    if (def.cursor_source)
        REQUIRE(fold.fold_cursor_rows(db, def.name, b.contributions, "{}", {}).has_value());
    else
        REQUIRE(fold.fold_rows(db, def.name, b.acc).has_value());
    const int64_t grown = used_bytes(reader.db) - before;

    Sizes s;
    for (auto tier : def.tiers) {
        const auto r = db.execute_query("SELECT COUNT(*) FROM " + physical_table_name(def.name, tier));
        REQUIRE(r.has_value());
        s.rows += std::stoll(r->rows[0][0]);
    }

    // Controls: identical strings / ring rows, identical order, in an in-memory copy of the schema.
    int64_t dict_total = 0, ring_total = 0;
    const auto strings = db.execute_query("SELECT text FROM echo_dict ORDER BY id", kEvents * 8);
    REQUIRE(strings.has_value());
    if (!strings->rows.empty()) {
        Conn mem;
        open_conn(mem, ":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
        exec(mem.db, generate_fold_ddl());
        const int64_t base = used_bytes(mem.db);
        exec(mem.db, "BEGIN");
        const Stmt ins = prepare(mem.db, "INSERT INTO echo_dict(text) VALUES(?)");
        double text_len = 0;
        for (const auto& row : strings->rows) {
            sqlite3_reset(ins.get());
            sqlite3_bind_text(ins.get(), 1, row[0].data(), static_cast<int>(row[0].size()), SQLITE_STATIC);
            REQUIRE(sqlite3_step(ins.get()) == SQLITE_DONE);
            text_len += static_cast<double>(row[0].size());
        }
        exec(mem.db, "COMMIT");
        dict_total = used_bytes(mem.db) - base;
        s.dict_bytes = static_cast<double>(dict_total) / static_cast<double>(strings->rows.size());
        s.dict_text = text_len / static_cast<double>(strings->rows.size());
    }
    if (def.cursor_source) {
        const auto ring = db.execute_query("SELECT source, record_key, digest, seq FROM echo_fold_seen ORDER BY source, record_key", kEvents);
        REQUIRE(ring.has_value());
        Conn mem;
        open_conn(mem, ":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
        exec(mem.db, generate_fold_ddl());
        const int64_t base = used_bytes(mem.db);
        exec(mem.db, "BEGIN");
        for (const auto& row : ring->rows)
            exec(mem.db, "INSERT INTO echo_fold_seen VALUES ('" + row[0] + "','" + row[1] + "'," + row[2] + "," + row[3] + ")");
        exec(mem.db, "COMMIT");
        ring_total = used_bytes(mem.db) - base;
    }
    s.row_bytes = static_cast<double>(grown - dict_total - ring_total) / static_cast<double>(s.rows);
    return s;
}

} // namespace

TEST_CASE("roll-up size: bytes per row stay under the pinned ceilings, for every fold source",
          "[echo][fold][fold_sizing]") {
    // Ceilings, bytes per row (table + unique index, all tiers). process, tcp, module, registry and
    // perf have round ceilings fixed up front. The rest are the figure measured at 100,000 keys x 1.25 rounded
    // up to a multiple of 8. Both measurements sit beside each ceiling (at 100,000 keys, then at
    // the 20,000 this test folds; the per-row cost barely moves with the key count). All of them
    // depend on this fixture's small non-zero measures and its TEXT measure lengths
    // (text_measure_len), not on production data.
    const std::map<std::string, double> ceiling = {
        {"process", 56},    // measured 54.2 @100k, 51.0 @20k
        {"tcp", 64},        // measured 58.3 @100k, 55.3 @20k
        {"module", 80},     // measured 60.8 @100k, 57.8 @20k
        {"registry", 640},  // measured 612.3 @100k, 610.8 @20k (a 512 B last_data: 7 rows to a 4 KiB page)
        {"perf", 192},      // measured 109.1 @100k, 108.3 @20k
        {"service", 128},   // measured 99.1 @100k, 96.3 @20k
        {"user", 72},       // measured 52.1 @100k, 48.9 @20k
        {"procperf", 104},  // measured 78.0 @100k, 75.4 @20k
        {"netqual", 88},    // measured 64.3 @100k, 61.0 @20k
        {"software", 72},   // measured 56.6 @100k, 53.5 @20k
        {"arp", 72},        // measured 52.2 @100k, 49.2 @20k
        {"dns", 64},        // measured 50.1 @100k, 46.9 @20k
        {"netconn", 96},    // measured 71.8 @100k, 69.0 @20k
        {"mapdrive", 104},  // measured 77.8 @100k, 74.8 @20k
        {"power", 88},      // measured 65.3 @100k, 62.1 @20k
        {"removable", 120}, // measured 93.1 @100k, 90.0 @20k
    };
    Sizes tcp, registry;
    for (const auto& def : fold_sources()) {
        if (def.own_tables)
            continue;
        const auto s = measure(def);
        WARN(def.name << ": " << s.row_bytes << " B/row over " << s.rows << " rows; dictionary "
                      << s.dict_bytes << " B/string (mean text " << s.dict_text << ")");
        INFO("source " << def.name << " measured " << s.row_bytes << " B/row");
        REQUIRE(ceiling.contains(std::string{def.name}));
        CHECK(s.row_bytes <= ceiling.at(std::string{def.name}));
        if (def.name == "tcp")
            tcp = s;
        if (def.name == "registry")
            registry = s;
    }

    // Dictionary: bytes per distinct string, measured on the tcp remote_addr and registry key_path sets.
    CHECK(tcp.dict_bytes <= tcp.dict_text + 48);
    CHECK(registry.dict_bytes <= registry.dict_text + 48);
}

TEST_CASE("roll-up size: a replay-ring row costs its key plus a small fixed overhead",
          "[echo][fold][fold_sizing]") {
    Conn mem;
    open_conn(mem, ":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    exec(mem.db, generate_fold_ddl());
    const int64_t base = used_bytes(mem.db);
    exec(mem.db, "BEGIN");
    const Stmt ins = prepare(mem.db, "INSERT INTO echo_fold_seen(source, record_key, digest, seq) VALUES ('registry', ?, ?, ?)");
    double key_len = 0;
    for (int i = 0; i < static_cast<int>(kReplayRingDepth); ++i) {
        const std::string key = "HKLM|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|value" + padded(i, 6) + "|changed";
        sqlite3_reset(ins.get());
        sqlite3_bind_text(ins.get(), 1, key.data(), static_cast<int>(key.size()), SQLITE_TRANSIENT);
        sqlite3_bind_int64(ins.get(), 2, 0x5a5a5a5a5a5a5a5aLL + i);
        sqlite3_bind_int64(ins.get(), 3, i + 1);
        REQUIRE(sqlite3_step(ins.get()) == SQLITE_DONE);
        key_len += static_cast<double>(key.size());
    }
    exec(mem.db, "COMMIT");
    const double per_row = static_cast<double>(used_bytes(mem.db) - base) / static_cast<double>(kReplayRingDepth);
    WARN("ring: " << per_row << " B/row, mean key " << key_len / static_cast<double>(kReplayRingDepth));
    // The primary key stores the source name, the key, the 8-byte digest and the sequence in every
    // cell, plus the record and cell headers: measured 41 B of overhead on the final shape.
    CHECK(per_row <= key_len / static_cast<double>(kReplayRingDepth) + 48);
}
