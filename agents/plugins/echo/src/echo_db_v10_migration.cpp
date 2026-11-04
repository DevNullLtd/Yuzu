/**
 * echo_db_v10_migration.cpp -- schema v10: the roll-up flip, in ONE transaction.
 *
 * Before v10 a source kept raw event rows in `<src>_live` and an aggregator rolled them up into
 * `<src>_hourly` / `_daily` / `_monthly` tables on a schedule (rollup marks in echo_config).
 * v10 keeps only the roll-up tiers (echo_fold_schema.hpp): the fold writes every event into every
 * tier at once, and the old tables are gone. This file moves an existing database across.
 *
 * ONE ATOMIC TRANSACTION for the whole database (a ruling, not a convenience): either every
 * source is migrated and the retired tables dropped, or NOTHING changed and the retired tables
 * are intact. A failure, a fault, a crash or a power cut at any point leaves the database at
 * schema v9 exactly as found (SQLite's WAL recovery discards the unfinished transaction); the next
 * open redoes the whole step. There is no per-source or resumable state to reason about.
 *
 *   inside the transaction, in this order
 *     1. rename each old summary table `<src>_<tier>` to `<src>_<tier>_legacy`, then create the
 *        roll-up schema (generate_fold_ddl: the dictionary, the replay ring, the `_r` tables and
 *        the views that take the old tables' names);
 *     2. convert each `_legacy` table into its `_r` table: text keys interned through the
 *        dictionary, a retired average turned back into a sum (`avg * samples`); a bucket outside
 *        years 0001-9999 or an average that is not a finite sum refuses the migration with the
 *        table, column and row named, before any write to that tier;
 *     3. finish the roll-ups the aggregator had not yet performed (hourly -> daily for buckets at or
 *        above `rollup_<src>_daily_at`, daily -> monthly above `rollup_<src>_monthly_at`;
 *        an absent mark means the upper tier is empty, so everything folds). This runs BEFORE any
 *        raw row is folded, because a raw row folds into every tier at once. The marks are read
 *        once and validated first: an unparseable mark, a populated old tier with no mark, or a
 *        coarser tier's mark ahead of its finer tier's fails the migration with the key and value
 *        named (never read as "fold everything", which would double count); a mark ahead of the
 *        clock is untrusted and replaced by the end of the converted tier's newest bucket, logged
 *        with the figures (the old pass returned early on such a mark, so nothing after it was
 *        summarised);
 *     4. fold each source's raw rows the aggregator had NOT yet summarised (ts at or above the
 *        mark of the source's first old summary tier; every row when there is none) through the
 *        production `<src>_delta` and EchoFold::fold_in, in id order and chunks of 10,000; the
 *        process rows past `usage_hwm_id` (the usage fold's own cursor, deleted in step 5) are
 *        also fed to the usage fold in this transaction when usage is enabled and Active (the
 *        fold's own predicate, whether or not the process source is enabled), so a lagging
 *        usage fold loses nothing it would have credited (the rows below the mark reach usage
 *        only, through a second pass: the tiers already hold them); a usage source that is
 *        disabled or awaiting its baseline would not have credited them either, and gets nothing;
 *     5. drop the 16 raw tables and every `_legacy` table, create the `$X_Live` shim views (empty,
 *        with the old columns), delete the rollup marks and the usage cursor from echo_config, and
 *        stamp schema_version 10.
 *
 * AFTER the commit: the connection must be in autocommit (B3), the WAL is checkpointed to zero
 * (secure_delete=ON zeroes every dropped raw page into the WAL, so the WAL after COMMIT is as
 * large as the file or larger: 325.7 MB on a 241.8 MB file, 1.35 times, in the one measurement
 * taken), and the one VACUUM that returns the freed pages runs if the volume still
 * has twice the file's size free; otherwise `auto_vacuum_deferred_at` is set and the maintenance
 * pass retries daily.
 *
 * BOUNDS. Before it starts the migration refuses a volume with less than twice the database file
 * plus its write-ahead log already on disk free (so Echo stays offline until the space is freed and the agent restarts, rather than risking
 * the host's disk). The transaction's WAL (the converted summary bytes plus the zeroed raw pages)
 * is NOT bounded by the file's size: it measured 1.35 times the file. The twice-the-file check
 * covers the measured case (WAL 325.7 MB plus the new file about 79 MB is about 404 MB, under the
 * 483 MB demanded for a 241.8 MB file); no general bound is proven. The WAL is checkpointed to
 * zero before the VACUUM, whose temporary copy and journal are at most twice the post-drop file,
 * and the second free-space check bounds that phase. The write lock is held for the whole run (tens of seconds on a 250 MiB file): no
 * collector writes meanwhile, and a collector call that finds the database busy retries on its
 * next tick.
 *
 * CURSOR SOURCES (power, removable, registry) change their idempotence: the raw store kept every
 * record_key forever and refused a reuse; the replay ring keeps the newest 4096 keys of a source.
 * The migration seeds the ring with each source's newest 4096 migrated keys and their identity
 * digests, so a record re-offered right after the upgrade is still a replay.
 *
 * Roll-up is the only storage model: nothing here selects between it and raw rows.
 */

#include "echo_aggregator.hpp" // kAutoVacuumDeferredKey
#include "echo_db.hpp"
#include "echo_fold.hpp"
#include "echo_fold_schema.hpp"
#include "echo_schema_registry.hpp" // source_default_enabled: the usage feed decision
#include "echo_status_format.hpp"   // kFreeSpaceRefusalPrefix
#include "echo_usage.hpp"           // usage_active_in, usage_fold_in: the lagged rows reach usage

#include <sqlite3.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <format>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::echo {

namespace {

struct StmtDeleter {
    void operator()(sqlite3_stmt* s) const { sqlite3_finalize(s); }
};
using StmtPtr = std::unique_ptr<sqlite3_stmt, StmtDeleter>;

constexpr int64_t kChunkRows = 10'000;
constexpr std::string_view kTiers[] = {"hourly", "daily", "monthly"};

int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// ── Small statement helpers (all failures poison the handle, like the fold's) ──

StmtPtr prep(TransactionHandle& h, const std::string& sql) {
    if (h.poisoned())
        return nullptr;
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(h.raw(), sql.c_str(), static_cast<int>(sql.size()), &raw, nullptr) !=
        SQLITE_OK) {
        h.fail(std::string("prepare failed: ") + sqlite3_errmsg(h.raw()));
        return nullptr;
    }
    return StmtPtr{raw};
}

// Step a statement that returns no rows to completion.
bool step_done(TransactionHandle& h, sqlite3_stmt* s) {
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW) {
    }
    if (rc != SQLITE_DONE) {
        h.fail(std::string("step failed: ") + sqlite3_errmsg(h.raw()));
        return false;
    }
    return true;
}

// One text column of every row of `sql`.
std::optional<std::vector<std::string>> read_texts(TransactionHandle& h, const std::string& sql) {
    auto st = prep(h, sql);
    if (!st)
        return std::nullopt;
    std::vector<std::string> out;
    int rc = SQLITE_OK;
    while ((rc = sqlite3_step(st.get())) == SQLITE_ROW) {
        const auto* t = reinterpret_cast<const char*>(sqlite3_column_text(st.get(), 0));
        out.emplace_back(t ? t : "");
    }
    if (rc != SQLITE_DONE) {
        h.fail(std::string("step failed: ") + sqlite3_errmsg(h.raw()));
        return std::nullopt;
    }
    return out;
}

// A column's text for an error message: "NULL" when it is NULL.
std::string column_text_or_null(sqlite3_stmt* st, int col) {
    const auto* t = reinterpret_cast<const char*>(sqlite3_column_text(st, col));
    return t ? std::string{t} : std::string{"NULL"};
}

// The column names of `table`.
std::optional<std::set<std::string>> column_names(TransactionHandle& h, std::string_view table) {
    const auto names = read_texts(h, std::format("SELECT name FROM pragma_table_info('{}')", table));
    if (!names)
        return std::nullopt;
    return std::set<std::string>(names->begin(), names->end());
}

// An integer `echo_config` value: nullopt when the row is absent (a state: "never written"), an
// error when it is present but not an integer. The two are never collapsed: an absent roll-up mark
// means the tier was never filled and everything folds, so a damaged mark read as absent would
// add every row on top of a tier that already holds it (cpp-1). The error names the table, the
// key and the value, so the operator knows what to repair.
std::expected<std::optional<int64_t>, std::string> read_mark(TransactionHandle& h,
                                                             const std::string& key) {
    auto st = prep(h, "SELECT value FROM echo_config WHERE key = ?");
    if (!st)
        return std::unexpected(h.error());
    sqlite3_bind_text(st.get(), 1, key.c_str(), static_cast<int>(key.size()), SQLITE_STATIC);
    const int rc = sqlite3_step(st.get());
    if (rc == SQLITE_DONE)
        return std::optional<int64_t>{};
    if (rc != SQLITE_ROW) {
        h.fail(std::string("step failed: ") + sqlite3_errmsg(h.raw()));
        return std::unexpected(h.error());
    }
    const auto* t = reinterpret_cast<const char*>(sqlite3_column_text(st.get(), 0));
    const std::string_view text = t ? t : "";
    int64_t v = 0;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), v);
    if (ec != std::errc{} || end != text.data() + text.size())
        return std::unexpected(std::format("echo_config key '{}' holds '{}', which is not an integer; "
                                           "repair or delete the row before the agent starts",
                                           key, text));
    return std::optional<int64_t>{v};
}

// Years 0001-9999 as unix seconds: the range SQLite's date functions accept. A bucket outside it
// (a millisecond stamp written by a past defect) makes `date(..., 'start of month')` NULL and the
// NOT NULL insert aborts the whole transaction with a message naming no row (UP-1), so it is
// refused up front with the table, column and value.
constexpr int64_t kMinBucket = -62135596800;
constexpr int64_t kMaxBucket = 253402300799;
// A sum beyond this is not a count or a byte total any tier can hold; NULL, NaN (stored as NULL)
// and an infinite product are refused by the same predicate.
constexpr double kMaxSum = 9.2e18;

// ── Raw row decoding ──────────────────────────────────────────────────────

// The SELECT list of a raw table, by name. A column the table lacks (a database that went
// through an older release) reads as its type's zero value, never as a failure: the roll-up of
// what the table does hold is still correct.
struct Columns {
    std::vector<LegacyColumn> cols;
    std::vector<bool> present;
    std::unordered_map<std::string_view, std::size_t> index;
};

class RawRow {
public:
    RawRow(const Columns& c, int64_t id, std::vector<Value> v) : c_(&c), id_(id), v_(std::move(v)) {}
    [[nodiscard]] int64_t id() const noexcept { return id_; }
    [[nodiscard]] int64_t i(std::string_view n) const { return std::get<int64_t>(at(n)); }
    [[nodiscard]] double d(std::string_view n) const { return std::get<double>(at(n)); }
    [[nodiscard]] const std::string& t(std::string_view n) const { return std::get<std::string>(at(n)); }
    [[nodiscard]] uint32_t u32(std::string_view n) const { return static_cast<uint32_t>(i(n)); }

private:
    const Value& at(std::string_view n) const { return v_.at(c_->index.at(n)); }
    const Columns* c_;
    int64_t id_;
    std::vector<Value> v_;
};

std::optional<Columns> raw_columns(TransactionHandle& h, std::string_view source) {
    Columns c;
    c.cols = legacy_live_columns(source);
    const auto names = column_names(h, std::format("{}_live", source));
    if (!names)
        return std::nullopt;
    for (std::size_t i = 0; i < c.cols.size(); ++i) {
        c.present.push_back(names->contains(std::string{c.cols[i].name}));
        c.index.emplace(c.cols[i].name, i);
    }
    return c;
}

// Streams `<source>_live` rows with ts >= min_ts in id order, kChunkRows at a time, to `on_chunk`.
// `below_ts` flips that to ts < min_ts, and `after_id` starts the id walk past that id: together
// they select the rows under the roll-up mark that are still past a cursor.
// Id order, not (ts, id): every merge the fold applies (sum, max, min, last-by-guard with ties to
// the later arrival) gives the same result for either order, and the id walk needs no sort.
// Returns the number of rows read. The SELECT is finalised before this returns, so a later DROP
// TABLE finds the table unlocked.
std::optional<int64_t> for_each_chunk(
    TransactionHandle& h, std::string_view source, const Columns& c, int64_t min_ts,
    const std::function<bool(const std::vector<RawRow>&)>& on_chunk, bool below_ts = false,
    int64_t after_id = std::numeric_limits<int64_t>::min()) {
    std::string select = "SELECT id";
    for (std::size_t i = 0; i < c.cols.size(); ++i)
        select += c.present[i] ? std::format(", {}", c.cols[i].name)
                               : std::format(", {} AS {}", c.cols[i].sql_type == "TEXT" ? "''" : "0",
                                             c.cols[i].name);
    select += std::format(" FROM {}_live WHERE id > ?1 AND ts {} ?2 ORDER BY id LIMIT {}", source,
                          below_ts ? "<" : ">=", kChunkRows);
    auto st = prep(h, select);
    if (!st)
        return std::nullopt;

    int64_t total = 0;
    int64_t last_id = after_id;
    for (;;) {
        sqlite3_reset(st.get());
        sqlite3_clear_bindings(st.get());
        sqlite3_bind_int64(st.get(), 1, last_id);
        sqlite3_bind_int64(st.get(), 2, min_ts);
        std::vector<RawRow> rows;
        int rc = SQLITE_OK;
        while ((rc = sqlite3_step(st.get())) == SQLITE_ROW) {
            const int64_t id = sqlite3_column_int64(st.get(), 0);
            std::vector<Value> v;
            v.reserve(c.cols.size());
            for (std::size_t i = 0; i < c.cols.size(); ++i) {
                const int col = static_cast<int>(i) + 1;
                if (c.cols[i].sql_type == "TEXT") {
                    const auto* t = reinterpret_cast<const char*>(sqlite3_column_text(st.get(), col));
                    v.emplace_back(std::string(t ? t : "", static_cast<std::size_t>(
                                                               sqlite3_column_bytes(st.get(), col))));
                } else if (c.cols[i].sql_type == "REAL") {
                    v.emplace_back(sqlite3_column_double(st.get(), col));
                } else {
                    v.emplace_back(sqlite3_column_int64(st.get(), col));
                }
            }
            rows.emplace_back(c, id, std::move(v));
            last_id = id;
        }
        if (rc != SQLITE_DONE) {
            h.fail(std::string("step failed: ") + sqlite3_errmsg(h.raw()));
            return std::nullopt;
        }
        if (rows.empty())
            break;
        total += static_cast<int64_t>(rows.size());
        const bool more = static_cast<int64_t>(rows.size()) == kChunkRows;
        if (!on_chunk(rows) || h.poisoned())
            return std::nullopt;
        if (!more)
            break;
    }
    return total;
}

// The decoders: the inverse of the retired insert_* bind lists, one raw row to one event.

ProcessEvent decode_process(const RawRow& r) {
    ProcessEvent e;
    e.ts = r.i("ts");
    e.snapshot_id = r.i("snapshot_id");
    e.action = r.t("action");
    e.pid = r.u32("pid");
    e.ppid = r.u32("ppid");
    e.name = r.t("name");
    e.cmdline = r.t("cmdline");
    e.user = r.t("user");
    return e;
}

NetworkEvent decode_tcp(const RawRow& r) {
    NetworkEvent e;
    e.ts = r.i("ts");
    e.snapshot_id = r.i("snapshot_id");
    e.action = r.t("action");
    e.proto = r.t("proto");
    e.local_addr = r.t("local_addr");
    e.local_port = static_cast<int>(r.i("local_port"));
    e.remote_addr = r.t("remote_addr");
    e.remote_host = r.t("remote_host");
    e.remote_port = static_cast<int>(r.i("remote_port"));
    e.state = r.t("state");
    e.pid = r.u32("pid");
    e.process_name = r.t("process_name");
    return e;
}

ServiceEvent decode_service(const RawRow& r) {
    ServiceEvent e;
    e.ts = r.i("ts");
    e.snapshot_id = r.i("snapshot_id");
    e.action = r.t("action");
    e.name = r.t("name");
    e.display_name = r.t("display_name");
    e.status = r.t("status");
    e.prev_status = r.t("prev_status");
    e.startup_type = r.t("startup_type");
    e.prev_startup_type = r.t("prev_startup_type");
    return e;
}

UserEvent decode_user(const RawRow& r) {
    UserEvent e;
    e.ts = r.i("ts");
    e.snapshot_id = r.i("snapshot_id");
    e.action = r.t("action");
    e.user = r.t("user");
    e.domain = r.t("domain");
    e.logon_type = r.t("logon_type");
    e.session_id = r.t("session_id");
    return e;
}

PerfRow decode_perf(const RawRow& r) {
    PerfRow e;
    e.ts = r.i("ts");
    e.snapshot_id = r.i("snapshot_id");
    e.cpu_pct = r.d("cpu_pct");
    e.mem_used_pct = r.d("mem_used_pct");
    e.commit_pct = r.d("commit_pct");
    e.disk_read_bps = r.i("disk_read_bps");
    e.disk_write_bps = r.i("disk_write_bps");
    e.disk_read_lat_us = r.i("disk_read_lat_us");
    e.disk_write_lat_us = r.i("disk_write_lat_us");
    e.net_rx_bps = r.i("net_rx_bps");
    e.net_tx_bps = r.i("net_tx_bps");
    return e;
}

ProcPerfRow decode_procperf(const RawRow& r) {
    ProcPerfRow e;
    e.ts = r.i("ts");
    e.snapshot_id = r.i("snapshot_id");
    e.name = r.t("name");
    e.version = r.t("version");
    e.instances = static_cast<int>(r.i("instances"));
    e.cpu_pct = r.d("cpu_pct");
    e.ws_bytes = r.i("ws_bytes");
    e.is_kthread = r.i("is_kthread") != 0;
    return e;
}

NetQualRow decode_netqual(const RawRow& r) {
    NetQualRow e;
    e.ts = r.i("ts");
    e.snapshot_id = r.i("snapshot_id");
    e.proto = r.t("proto");
    e.remote_bucket = r.t("remote_bucket");
    e.process_name = r.t("process_name");
    e.rtt_us = r.i("rtt_us");
    e.rtt_var_us = r.i("rtt_var_us");
    e.lost = r.i("lost");
    e.retrans = r.i("retrans");
    e.segs_out = r.i("segs_out");
    e.ca_state = r.i("ca_state");
    return e;
}

ModuleRow decode_module(const RawRow& r) {
    ModuleRow e;
    e.ts = r.i("ts");
    e.snapshot_id = r.i("snapshot_id");
    e.action = r.t("action");
    e.pid = r.u32("pid");
    e.process_name = r.t("process_name");
    e.module_name = r.t("module_name");
    e.module_dir = r.t("module_dir");
    e.signed_state = r.t("signed_state");
    e.signer = r.t("signer");
    e.is_kernel = r.i("is_kernel") != 0;
    return e;
}

SoftwareEvent decode_software(const RawRow& r) {
    SoftwareEvent e;
    e.ts = r.i("ts");
    e.snapshot_id = r.i("snapshot_id");
    e.action = r.t("action");
    e.name = r.t("name");
    e.version = r.t("version");
    e.prev_version = r.t("prev_version");
    e.publisher = r.t("publisher");
    e.install_date = r.t("install_date");
    return e;
}

ArpEvent decode_arp(const RawRow& r) {
    ArpEvent e;
    e.ts = r.i("ts");
    e.snapshot_id = r.i("snapshot_id");
    e.action = r.t("action");
    e.iface = r.t("interface");
    e.ip_address = r.t("ip_address");
    e.mac_address = r.t("mac_address");
    e.entry_type = r.t("entry_type");
    return e;
}

DnsEvent decode_dns(const RawRow& r) {
    DnsEvent e;
    e.ts = r.i("ts");
    e.snapshot_id = r.i("snapshot_id");
    e.action = r.t("action");
    e.name = r.t("name");
    e.record_type = r.t("record_type");
    e.data = r.t("data");
    e.ttl_remaining_s = r.i("ttl_remaining_s");
    e.source = r.t("source");
    return e;
}

NetConnRow decode_netconn(const RawRow& r) {
    NetConnRow e;
    e.ts = r.i("ts");
    e.snapshot_id = r.i("snapshot_id");
    e.action = r.t("action");
    e.channel = r.t("channel");
    e.category = r.t("category");
    e.capability = r.t("capability");
    e.iface_kind = r.t("iface_kind");
    e.reason_code = r.i("reason_code");
    return e;
}

MapDriveEvent decode_mapdrive(const RawRow& r) {
    MapDriveEvent e;
    e.ts = r.i("ts");
    e.snapshot_id = r.i("snapshot_id");
    e.action = r.t("action");
    e.direction = r.t("direction");
    e.local_mount = r.t("local_mount");
    e.remote_path = r.t("remote_path");
    e.remote_host = r.t("remote_host");
    e.username = r.t("username");
    e.provider = r.t("provider");
    e.origin = r.t("origin");
    return e;
}

PowerEvent decode_power(const RawRow& r) {
    PowerEvent e;
    e.ts = r.i("ts");
    e.snapshot_id = r.i("snapshot_id");
    e.action = r.t("action");
    e.detail = r.t("detail");
    e.record_key = r.t("record_key");
    return e;
}

RemovableEvent decode_removable(const RawRow& r) {
    RemovableEvent e;
    e.ts = r.i("ts");
    e.snapshot_id = r.i("snapshot_id");
    e.action = r.t("action");
    e.device_key = r.t("device_key");
    e.vendor = r.t("vendor");
    e.product = r.t("product");
    e.serial = r.t("serial");
    e.bus = r.t("bus");
    e.volume = r.t("volume");
    e.size_bytes = r.i("size_bytes");
    e.image_path = r.t("image_path");
    e.pid = r.i("pid");
    e.evidence = r.t("evidence");
    e.record_key = r.t("record_key");
    return e;
}

RegistryEvent decode_registry(const RawRow& r) {
    RegistryEvent e;
    e.ts = r.i("ts");
    e.snapshot_id = r.i("snapshot_id");
    e.hive = r.t("hive");
    e.key_path = r.t("key_path");
    e.value_name = r.t("value_name");
    e.action = r.t("action");
    e.data_type = r.t("data_type");
    e.data = r.t("data");
    e.data_size = r.i("data_size");
    e.data_truncated = static_cast<int>(r.i("data_truncated"));
    e.prev_data_type = r.t("prev_data_type");
    e.prev_data = r.t("prev_data");
    e.prev_data_size = r.i("prev_data_size");
    e.prev_data_truncated = static_cast<int>(r.i("prev_data_truncated"));
    e.actor_pid = r.i("actor_pid");
    e.actor_image = r.t("actor_image");
    e.source = r.t("source");
    e.observed_at = r.i("observed_at");
    e.detail = r.t("detail");
    e.record_key = r.t("record_key");
    return e;
}

// ── The migration proper ──────────────────────────────────────────────────

struct Report {
    int64_t legacy_tier_rows{0};
    int64_t raw_rows{0};
    int64_t below_mark{0}; // raw rows older than the old roll-up mark (or floor): not folded, counted
    int64_t rejected{0};
    int64_t ring_keys{0};
    int64_t untrusted_marks{0};   // marks ahead of the clock, replaced by the converted tier's edge
    int64_t usage_lag_rows{0};    // raw process rows past usage_hwm_id (the stored lag)
    int64_t usage_lag_folded{0};  // of those, the ones fed to usage (usage Active), above or below the floor
    int64_t usage_lag_events{0};  // the counter the old fold kept, read before it is deleted
};

// One old roll-up mark after validation. A mark the old aggregator wrote ahead of the clock (a
// forward excursion that later healed; the old pass returned early on `last_mark >= boundary`, so
// nothing after it was ever summarised) proves nothing about what was summarised: it is replaced
// by the edge of what the converted tier actually holds (cmp-1).
struct Mark {
    std::optional<int64_t> value; // absent: the tier was never filled
    bool untrusted{false};        // ahead of the clock: `value` is the stored figure, not the floor
};

class Migration {
public:
    Migration(TransactionHandle& h, EchoFold& fold, std::set<std::string> legacy_tiers,
              std::set<std::string> raw_tables, int64_t now)
        : h_(h), fold_(fold), legacy_tiers_(std::move(legacy_tiers)),
          raw_tables_(std::move(raw_tables)), now_(now) {}

    std::expected<void, std::string> run() {
        // 1. the roll-up schema, beside the renamed old tables
        for (const auto& name : legacy_tiers_)
            if (!h_.exec(std::format("ALTER TABLE {} RENAME TO {}_legacy", name, name)))
                return std::unexpected(h_.error());
        if (!h_.exec(generate_fold_ddl()))
            return std::unexpected(h_.error());
        // the empty string is a key too: a missing legacy column reads '' and must intern
        if (!h_.exec(std::format("INSERT OR IGNORE INTO {}(text) VALUES ('')", kDictTable)))
            return std::unexpected(h_.error());
        if (auto r = load_marks(); !r)
            return r;

        // 2. old summary tables -> `_r`
        for (const auto& def : fold_sources()) {
            if (def.own_tables)
                continue;
            for (const auto tier : def.tiers)
                if (legacy_tiers_.contains(fold_view_name(def.name, tier)))
                    if (auto r = convert_tier(def, tier); !r)
                        return r;
        }
        // 3. finish the roll-ups the aggregator had not yet performed
        for (const auto& def : fold_sources()) {
            if (def.own_tables)
                continue;
            for (std::size_t i = 1; i < def.tiers.size(); ++i)
                if (auto r = finish_rollup(def, def.tiers[i - 1], def.tiers[i]); !r)
                    return r;
        }
        // 4. raw rows not yet summarised
        for (const auto& def : fold_sources()) {
            if (def.own_tables || !raw_tables_.contains(std::format("{}_live", def.name)))
                continue;
            if (auto r = fold_raw(def); !r)
                return r;
        }
        return {};
    }

    // The tables of step 5, in the order they are dropped.
    [[nodiscard]] std::vector<std::string> retired_tables() const {
        std::vector<std::string> out;
        for (const auto& name : raw_tables_)
            out.push_back(name);
        for (const auto& name : legacy_tiers_)
            out.push_back(name + "_legacy");
        return out;
    }

    [[nodiscard]] const Report& report() const noexcept { return report_; }

private:
    std::expected<void, std::string> convert_tier(const FoldSourceDef& def, std::string_view tier) {
        const std::string legacy = fold_view_name(def.name, tier) + "_legacy";
        const std::string bucket{ts_column_for_suffix(tier)};
        const auto have = column_names(h_, legacy);
        if (!have)
            return std::unexpected(h_.error());
        if (!have->contains(bucket))
            return std::unexpected(std::format("{} has no {} column; cannot convert it", legacy, bucket));

        // A retired average comes back as a sum: avg * samples (the fold keeps sums, so tiers merge).
        std::map<std::string_view, const ColumnDef*> avg_of;
        for (const auto& c : def.columns)
            if (c.role == ColumnRole::kGenerated)
                avg_of.emplace(avg_sum_column(c), &c);

        // Refuse, with the row named, what the insert below would abort on without naming it: a
        // bucket outside the years SQLite's date functions accept, and an average that does not
        // come back as a finite sum (UP-1). Checked before any write to this tier.
        if (auto st = prep(h_, std::format("SELECT id, {0} FROM {1} WHERE {0} IS NULL OR {0} < {2} "
                                           "OR {0} > {3} LIMIT 1",
                                           bucket, legacy, kMinBucket, kMaxBucket))) {
            const int rc = sqlite3_step(st.get());
            if (rc == SQLITE_ROW)
                return std::unexpected(std::format(
                    "{}.{} = {} (row id {}) is outside years 0001-9999; repair that row before the "
                    "agent starts",
                    legacy, bucket, column_text_or_null(st.get(), 1), sqlite3_column_int64(st.get(), 0)));
            if (rc != SQLITE_DONE)
                return std::unexpected(std::string("step failed: ") + sqlite3_errmsg(h_.raw()));
        } else {
            return std::unexpected(h_.error());
        }
        for (const auto& [sum_col, avg_col] : avg_of) {
            if (!have->contains(std::string{avg_col->name}) || !have->contains("samples"))
                continue;
            auto st = prep(h_, std::format("SELECT id, {0}, samples FROM {1} WHERE {0} IS NULL OR "
                                           "samples IS NULL OR ({0} * samples) IS NULL OR "
                                           "NOT (({0} * samples) BETWEEN -{2} AND {2}) LIMIT 1",
                                           avg_col->name, legacy, kMaxSum));
            if (!st)
                return std::unexpected(h_.error());
            const int rc = sqlite3_step(st.get());
            if (rc == SQLITE_ROW)
                return std::unexpected(std::format(
                    "{}.{} = {} with samples = {} (row id {}) does not convert to a finite sum; "
                    "repair that row before the agent starts",
                    legacy, avg_col->name, column_text_or_null(st.get(), 1),
                    column_text_or_null(st.get(), 2), sqlite3_column_int64(st.get(), 0)));
            if (rc != SQLITE_DONE)
                return std::unexpected(std::string("step failed: ") + sqlite3_errmsg(h_.raw()));
        }

        // Every distinct text of every interned key column enters the dictionary first.
        for (const auto& c : def.columns)
            if (c.interned && have->contains(std::string{c.name}))
                if (!h_.exec(std::format("INSERT OR IGNORE INTO {}(text) SELECT DISTINCT {} FROM {}",
                                         kDictTable, c.name, legacy)))
                    return std::unexpected(h_.error());

        std::string cols = bucket, vals = "l." + bucket, conflict = bucket;
        for (const auto& c : def.columns) {
            if (c.role == ColumnRole::kGenerated)
                continue;
            const std::string phys = physical_column_name(c);
            const bool in_legacy = have->contains(std::string{c.name});
            std::string expr;
            if (c.interned) {
                expr = std::format("(SELECT id FROM {} WHERE text = {})", kDictTable,
                                   in_legacy ? "l." + std::string{c.name} : std::string{"''"});
            } else if (in_legacy) {
                expr = "l." + std::string{c.name};
            } else if (const auto avg = avg_of.find(c.name);
                       avg != avg_of.end() && have->contains(std::string{avg->second->name}) &&
                       have->contains("samples")) {
                expr = c.sql_type == "INTEGER"
                           ? std::format("CAST(ROUND(l.{} * l.samples) AS INTEGER)", avg->second->name)
                           : std::format("l.{} * l.samples", avg->second->name);
            } else {
                expr = c.sql_type == "TEXT" ? "''" : "0";
            }
            cols += "," + phys;
            vals += "," + expr;
            if (c.role == ColumnRole::kKey)
                conflict += "," + phys;
        }
        // An old summary table could hold two rows for one (bucket, keys) (nothing enforced it): merge.
        auto st = prep(h_, std::format("INSERT INTO {0}({1}) SELECT {2} FROM {3} l WHERE 1 ORDER BY l.id "
                                       "ON CONFLICT({4}) DO UPDATE SET {5} RETURNING id",
                                       physical_table_name(def.name, tier), cols, vals, legacy, conflict,
                                       fold_upsert_assignments(def)));
        if (!st)
            return std::unexpected(std::string("converting ") + legacy + ": " + h_.error());
        int rc = SQLITE_OK;
        while ((rc = sqlite3_step(st.get())) == SQLITE_ROW)
            ++report_.legacy_tier_rows;
        if (rc != SQLITE_DONE)
            return std::unexpected(std::string("converting ") + legacy + ": " + sqlite3_errmsg(h_.raw()));
        return {};
    }

    std::expected<void, std::string> finish_rollup(const FoldSourceDef& def, std::string_view from,
                                                   std::string_view to) {
        // Only a tier the old aggregator had filled can hold rows its upper tier is missing.
        if (!legacy_tiers_.contains(fold_view_name(def.name, from)))
            return {};
        const std::string sql = fold_tier_from_tier_sql(def.name, from, to);
        if (sql.empty())
            return {};
        const auto floor = floor_for(def, to);
        if (!floor)
            return std::unexpected(floor.error());
        auto st = prep(h_, sql);
        if (!st)
            return std::unexpected(std::format("rolling {} {} up into {}: {}", def.name, from, to, h_.error()));
        sqlite3_bind_int64(st.get(), 1, *floor);
        if (!step_done(h_, st.get()))
            return std::unexpected(std::format("rolling {} {} up into {}: {}", def.name, from, to, h_.error()));
        return {};
    }

    // Every mark of every old summary table present, read ONCE and validated against the tables
    // (cpp-1, UP-8, cmp-1): an unparseable mark fails (read_mark); a populated old tier whose own
    // mark is absent fails, because "absent" means "fold everything into it" and would double
    // count what it already holds; a coarser tier's mark above its finer tier's fails, because the
    // old pass filled the coarser tier FROM the finer one and could never be ahead of it; a mark
    // ahead of the clock is kept but marked untrusted (floor_for resolves it from the converted
    // tier). Sane marks are used exactly as stored.
    std::expected<void, std::string> load_marks() {
        for (const auto& def : fold_sources()) {
            if (def.own_tables)
                continue;
            std::optional<int64_t> finer; // the nearest finer tier's trusted mark
            for (const auto tier : kTiers) {
                const std::string legacy = fold_view_name(def.name, tier) + "_legacy";
                if (!legacy_tiers_.contains(fold_view_name(def.name, tier)))
                    continue;
                const std::string key = std::format("rollup_{}_{}_at", def.name, tier);
                auto mark = read_mark(h_, key);
                if (!mark)
                    return std::unexpected(mark.error());
                Mark m{*mark, false};
                if (!m.value) {
                    auto st = prep(h_, std::format("SELECT COUNT(*) FROM {}", legacy));
                    if (!st || sqlite3_step(st.get()) != SQLITE_ROW)
                        return std::unexpected(std::string("step failed: ") + sqlite3_errmsg(h_.raw()));
                    if (const int64_t rows = sqlite3_column_int64(st.get(), 0); rows > 0)
                        return std::unexpected(std::format(
                            "{} holds {} rows but echo_config has no '{}' mark, so what was "
                            "summarised into it cannot be told; restore the mark or empty the "
                            "table before the agent starts",
                            fold_view_name(def.name, tier), rows, key));
                } else if (*m.value > now_ || *m.value > kEchoMaxPlausibleNow) {
                    m.untrusted = true;
                    ++report_.untrusted_marks;
                } else if (finer && *m.value > *finer) {
                    return std::unexpected(std::format(
                        "echo_config '{}' = {} is ahead of the finer tier's mark ({}); the old "
                        "roll-up filled the {} tier from the finer one and could not be ahead of "
                        "it; repair the marks before the agent starts",
                        key, *m.value, *finer, tier));
                }
                if (m.value && !m.untrusted)
                    finer = m.value;
                marks_.emplace(std::format("{}/{}", def.name, tier), m);
            }
        }
        return {};
    }

    // The ts at or above which `tier` of `def` was NOT yet filled: the stored mark when it is sane;
    // the beginning of time when there is none (the tier is empty, load_marks proved it); and, for
    // a mark ahead of the clock, the end of the newest bucket AT OR BEFORE THE CLOCK that the
    // converted tier holds (what the old pass had provably summarised), clamped to the clock. A
    // bucket the old pass wrote during the excursion sits ahead of the clock too and must not be
    // the floor: every raw row written since the clock healed is below it and would be dropped as
    // summarised (g8-2). A converted tier with no such bucket cannot bound the fold: folding
    // everything would add every raw row on top of the upper tiers that already hold them (g8-1),
    // so the migration refuses with the figures named instead of guessing. The trust rule is the
    // old budget pass's own bare `mark > now` (acd22e776 echo_aggregator.cpp, no tolerance), so a
    // migration clock behind the stored marks makes them untrusted and lands here: a source whose
    // converted tier holds a bucket is bounded by it, one with no bucket refuses until the clock
    // or the mark is repaired. Logged once per mark with the figures. A source with nothing to
    // fold (no raw row, every converted tier empty) is not refused: its mark bounds nothing.
    // ponytail: two triggers fold rows a second time on top of the converted buckets that hold
    // them, and neither is closed here. (1) A raw row the excursion itself stamped (ts ahead of
    // the clock) folds again on top of the converted future bucket; an upper bound on the raw
    // read would close that. (2) A migration clock set back from a SANE mark (a restored
    // snapshot, an NTP step) makes the mark untrusted by the same rule, and the clamp to the
    // clock re-folds every raw row between the clock and the mark on top of the buckets that
    // hold them. Add the bound if a healed excursion with surviving raw rows, or a migration
    // under a stepped-back clock, is ever seen in the field.
    std::expected<int64_t, std::string> floor_for(const FoldSourceDef& def, std::string_view tier) {
        const auto it = marks_.find(std::format("{}/{}", def.name, tier));
        if (it == marks_.end() || !it->second.value)
            return std::numeric_limits<int64_t>::min();
        if (!it->second.untrusted)
            return *it->second.value;
        const auto edge = newest_bucket_end(def, tier);
        if (!edge)
            return std::unexpected(edge.error());
        if (!edge->has_value()) {
            const auto idle = nothing_to_fold(def);
            if (!idle)
                return std::unexpected(idle.error());
            if (*idle) {
                spdlog::info("EchoDatabase v10: rollup mark rollup_{}_{}_at = {} is ahead of the clock "
                             "({}) but the {} source holds no raw row and no converted bucket, so "
                             "there is nothing it could bound; the mark is ignored",
                             def.name, tier, *it->second.value, now_, def.name);
                return std::numeric_limits<int64_t>::min();
            }
            return std::unexpected(std::format(
                "echo_config 'rollup_{0}_{1}_at' = {2} is ahead of the clock ({3}) and the converted "
                "{0} {1} tier holds no bucket at or before the clock to bound the fold, so what the "
                "old roll-up summarised cannot be told; fix the clock or repair the mark before the "
                "agent starts",
                def.name, tier, *it->second.value, now_));
        }
        const int64_t floor = std::min(**edge, now_);
        spdlog::warn("EchoDatabase v10: rollup mark rollup_{}_{}_at = {} is ahead of the clock ({}); "
                     "it proves nothing about what was summarised, so the fold floor is the end of "
                     "the converted {} tier's newest bucket at or before the clock instead ({}); rows "
                     "below it are counted as older than the mark",
                     def.name, tier, *it->second.value, now_, tier, floor);
        return floor;
    }

    // The end of the newest bucket at or before the clock of `def`'s converted `tier`, or nullopt
    // when it holds no such row. A bucket starting after the clock is ignored, never the edge.
    std::expected<std::optional<int64_t>, std::string> newest_bucket_end(const FoldSourceDef& def,
                                                                        std::string_view tier) {
        const std::string table = physical_table_name(def.name, tier);
        const std::string bucket{ts_column_for_suffix(tier)};
        std::string expr;
        if (tier == "hourly")
            expr = std::format("MAX({}) + 3600", bucket);
        else if (tier == "daily")
            expr = std::format("MAX({}) + 86400", bucket);
        else
            expr = std::format("CAST(strftime('%s', datetime(MAX({}), 'unixepoch', 'start of month', "
                               "'+1 month')) AS INTEGER)",
                               bucket);
        auto st = prep(h_, std::format("SELECT {} FROM {} WHERE {} <= ?1", expr, table, bucket));
        if (!st)
            return std::unexpected(h_.error());
        sqlite3_bind_int64(st.get(), 1, now_);
        if (sqlite3_step(st.get()) != SQLITE_ROW)
            return std::unexpected(std::string("step failed: ") + sqlite3_errmsg(h_.raw()));
        if (sqlite3_column_type(st.get(), 0) == SQLITE_NULL)
            return std::optional<int64_t>{};
        return std::optional<int64_t>{sqlite3_column_int64(st.get(), 0)};
    }

    // The ts at or above which a source's raw rows were NOT yet summarised: the floor of its first
    // old summary tier (the tier that read the raw table), or the beginning of time when it had none.
    std::expected<int64_t, std::string> unsummarised_from(const FoldSourceDef& def) {
        for (const auto tier : kTiers)
            if (legacy_tiers_.contains(fold_view_name(def.name, tier)))
                return floor_for(def, tier);
        return std::numeric_limits<int64_t>::min();
    }

    std::expected<void, std::string> fold_raw(const FoldSourceDef& def) {
        const auto cols = raw_columns(h_, def.name);
        if (!cols)
            return std::unexpected(h_.error());
        const auto from = unsummarised_from(def);
        if (!from)
            return std::unexpected(from.error());
        const int64_t min_ts = *from;

        // Rows older than the mark are not folded: the old roll-up already summarised them, except
        // those a process-event backfill wrote or the clock-gap clamp skipped, and the old GROUP BY
        // destroyed the identity that would tell the two apart. They are counted so the drop is
        // visible. With no mark nothing is below it.
        if (min_ts != std::numeric_limits<int64_t>::min()) {
            auto st = prep(h_, std::format("SELECT COUNT(*) FROM {}_live WHERE ts < ?1", def.name));
            if (!st)
                return std::unexpected(h_.error());
            sqlite3_bind_int64(st.get(), 1, min_ts);
            if (sqlite3_step(st.get()) != SQLITE_ROW)
                return std::unexpected(std::string("step failed: ") + sqlite3_errmsg(h_.raw()));
            report_.below_mark += sqlite3_column_int64(st.get(), 0);
        }

        // The usage fold read the raw process rows through its own cursor (`usage_hwm_id`): rows
        // past it never reached usage, and the migration deletes the cursor (hp-2). They are fed to
        // the usage fold here, in this transaction, exactly as the fold itself would have, and
        // only when it would have credited them: usage enabled and the lifecycle Active, the
        // fold's own predicate (usage_active_in). The process source's own flag is NOT part of
        // it (g8b-1): the pre-v10 fold left the cursor where it was while process was disabled
        // and credited the rows once process was re-enabled, and the raw rows fold into the
        // process tiers here regardless, so a disabled process source must not make them vanish
        // from usage while the cursor is deleted. Decided ONCE, before the chunk loop (g8-5): a
        // PendingBaseline tick stamps a baseline and folds nothing, so nothing is fed and nothing
        // is stamped here; decided per chunk, the first chunk's stamp would turn the next chunk
        // into a retrospective fold of the rows the baseline excluded. An Active lifecycle with
        // no cursor is the fault the
        // pre-v10 fold refused on (its cursor and its active generation were written together), so
        // it refuses here too (g8-4). The stored lag counter is informational: it is read for the
        // log line, and an unreadable one is logged, never a refusal (g8-s3).
        int64_t usage_hwm = std::numeric_limits<int64_t>::max(); // nothing past it: nothing fed
        if (def.name == "process") {
            const auto hwm = read_mark(h_, "usage_hwm_id");
            if (!hwm)
                return std::unexpected(hwm.error());
            if (const auto lag = read_mark(h_, "usage_lag_events"); lag)
                report_.usage_lag_events = lag->value_or(0);
            else if (h_.poisoned())
                return std::unexpected(lag.error());
            else
                spdlog::warn("EchoDatabase v10: {}; the counter is informational and the migration "
                             "deletes it",
                             lag.error());
            const auto feed = usage_fold_active();
            if (!feed)
                return std::unexpected(feed.error());
            if (*feed && !hwm->has_value())
                return std::unexpected(
                    "usage is active (usage_active_generation equals usage_generation) but "
                    "echo_config has no 'usage_hwm_id' cursor, so which raw process rows the usage "
                    "fold had read cannot be told; restore the cursor, or delete the "
                    "'usage_active_generation' row so usage re-baselines, before the agent starts");
            // No cursor: the usage fold never ran on this file, so nothing lagged behind it.
            if (hwm->has_value()) {
                auto st = prep(h_, "SELECT COUNT(*) FROM process_live WHERE id > ?1");
                if (!st)
                    return std::unexpected(h_.error());
                sqlite3_bind_int64(st.get(), 1, **hwm);
                if (sqlite3_step(st.get()) != SQLITE_ROW)
                    return std::unexpected(std::string("step failed: ") + sqlite3_errmsg(h_.raw()));
                report_.usage_lag_rows = sqlite3_column_int64(st.get(), 0);
                if (*feed)
                    usage_hwm = **hwm;
            }
        }

        // The newest kReplayRingDepth rows of a cursor source seed its replay ring.
        int64_t seed_from_id = 0;
        if (def.cursor_source) {
            auto st = prep(h_, std::format("SELECT id FROM {}_live WHERE ts >= ?1 ORDER BY id DESC "
                                           "LIMIT 1 OFFSET {}",
                                           def.name, kReplayRingDepth - 1));
            if (!st)
                return std::unexpected(h_.error());
            sqlite3_bind_int64(st.get(), 1, min_ts);
            const int rc = sqlite3_step(st.get());
            if (rc == SQLITE_ROW)
                seed_from_id = sqlite3_column_int64(st.get(), 0);
            else if (rc != SQLITE_DONE)
                return std::unexpected(std::string("step failed: ") + sqlite3_errmsg(h_.raw()));
        }

        int64_t seq = 0;
        std::optional<std::string> failure;
        const auto chunk = [&](const std::vector<RawRow>& rows) -> bool {
            TierAccumulator acc(def);
            std::vector<ProcessEvent> lagged; // process rows the usage fold had not yet read
            try {
                if (def.name == "process") {
                    const auto events = decode<ProcessEvent>(rows, decode_process);
                    process_delta(events, acc);
                    for (std::size_t i = 0; i < rows.size(); ++i)
                        if (rows[i].id() > usage_hwm)
                            lagged.push_back(events[i]);
                } else if (def.name == "tcp")
                    tcp_delta(decode<NetworkEvent>(rows, decode_tcp), acc);
                else if (def.name == "service")
                    service_delta(decode<ServiceEvent>(rows, decode_service), acc);
                else if (def.name == "user")
                    user_delta(decode<UserEvent>(rows, decode_user), acc);
                else if (def.name == "perf")
                    perf_delta(decode<PerfRow>(rows, decode_perf), acc);
                else if (def.name == "procperf")
                    procperf_delta(decode<ProcPerfRow>(rows, decode_procperf), acc);
                else if (def.name == "netqual")
                    netqual_delta(decode<NetQualRow>(rows, decode_netqual), acc);
                else if (def.name == "module")
                    module_delta(decode<ModuleRow>(rows, decode_module), acc);
                else if (def.name == "software")
                    software_delta(decode<SoftwareEvent>(rows, decode_software), acc);
                else if (def.name == "arp")
                    arp_delta(decode<ArpEvent>(rows, decode_arp), acc);
                else if (def.name == "dns")
                    dns_delta(decode<DnsEvent>(rows, decode_dns), acc);
                else if (def.name == "netconn")
                    netconn_delta(decode<NetConnRow>(rows, decode_netconn), acc);
                else if (def.name == "mapdrive") {
                    const auto events = decode<MapDriveEvent>(rows, decode_mapdrive);
                    mapdrive_delta(events, acc);
                    remember_historical(events);
                }
                else if (def.name == "power")
                    contribute(rows, power_delta(decode<PowerEvent>(rows, decode_power)), def, acc,
                               seed_from_id, seq);
                else if (def.name == "removable")
                    contribute(rows, removable_delta(decode<RemovableEvent>(rows, decode_removable)),
                               def, acc, seed_from_id, seq);
                else if (def.name == "registry")
                    contribute(rows, registry_delta(decode<RegistryEvent>(rows, decode_registry)), def,
                               acc, seed_from_id, seq);
                else
                    failure = std::format("no decoder for source '{}'", def.name);
            } catch (const std::exception& e) {
                failure = std::format("{}: {}", def.name, e.what());
            }
            if (failure)
                return false;
            report_.rejected += static_cast<int64_t>(acc.rejected());
            const auto n = fold_.fold_in(h_, def.name, acc);
            if (!n) {
                failure = n.error();
                return false;
            }
            if (!lagged.empty()) {
                if (const auto u = usage::usage_fold_in(h_, now_, lagged); !u) {
                    failure = "usage fold of the lagged process rows: " + u.error();
                    return false;
                }
                report_.usage_lag_folded += static_cast<int64_t>(lagged.size());
            }
            return true;
        };
        const auto read = for_each_chunk(h_, def.name, *cols, min_ts, chunk);
        if (failure)
            return std::unexpected(*failure);
        if (!read)
            return std::unexpected(h_.error());
        report_.raw_rows += *read;

        // The chunk walk above reads only rows at or past the mark, so a process row past the
        // usage cursor but below the mark (the old roll-up summarised it into the tiers, but the
        // usage fold never read it) reached neither. Feed those to usage only, never to the tiers
        // (the mark means the tiers already hold them), and count them with the other lagged rows.
        if (def.name == "process" && usage_hwm != std::numeric_limits<int64_t>::max() &&
            min_ts != std::numeric_limits<int64_t>::min()) {
            const auto below = for_each_chunk(
                h_, def.name, *cols, min_ts,
                [&](const std::vector<RawRow>& rows) -> bool {
                    std::vector<ProcessEvent> lagged;
                    try {
                        lagged = decode<ProcessEvent>(rows, decode_process);
                    } catch (const std::exception& e) {
                        failure = std::format("{}: {}", def.name, e.what());
                        return false;
                    }
                    if (const auto u = usage::usage_fold_in(h_, now_, lagged); !u) {
                        failure = "usage fold of the lagged process rows below the mark: " + u.error();
                        return false;
                    }
                    report_.usage_lag_folded += static_cast<int64_t>(lagged.size());
                    return true;
                },
                /*below_ts=*/true, /*after_id=*/usage_hwm);
            if (failure)
                return std::unexpected(*failure);
            if (!below)
                return std::unexpected(h_.error());
        }
        return {};
    }

    // Whether the usage fold would credit process rows: usage enabled (the canonical tri-state,
    // the registry default for a missing row, as usage_fold_in reads it) and the lifecycle Active
    // through the fold's own predicate (usage_active_in: `usage_generation` strict, the active
    // generation parsed as usage_lifecycle_state parses it, so an empty or malformed value is 0
    // and reads Active against an absent or 0 generation exactly as the fold reads it). The
    // process flag is deliberately absent (see fold_raw).
    std::expected<bool, std::string> usage_fold_active() {
        auto st = prep(h_, "SELECT value FROM echo_config WHERE key = 'usage_enabled'");
        if (!st)
            return std::unexpected(h_.error());
        const int rc = sqlite3_step(st.get());
        if (rc != SQLITE_ROW && rc != SQLITE_DONE)
            return std::unexpected(std::string("step failed: ") + sqlite3_errmsg(h_.raw()));
        const auto* t = rc == SQLITE_ROW ? reinterpret_cast<const char*>(sqlite3_column_text(st.get(), 0))
                                         : nullptr;
        const std::string stored = t ? t : (source_default_enabled("usage") ? "true" : "false");
        if (canonical_source_enabled(stored) != "true")
            return false;
        return usage::usage_active_in(h_);
    }

    // Whether `def` has nothing the migration could fold: no raw row and no row in any of its
    // converted tiers. A never-used source's untrusted mark then bounds nothing and must not
    // refuse the migration (g8b-2: the pre-v10 pass wrote a mark for every source and tier
    // whether or not it had rows, so after a forward excursion every idle source carries one).
    std::expected<bool, std::string> nothing_to_fold(const FoldSourceDef& def) {
        std::vector<std::string> tables;
        if (raw_tables_.contains(std::format("{}_live", def.name)))
            tables.push_back(std::format("{}_live", def.name));
        for (const auto tier : def.tiers)
            tables.push_back(physical_table_name(def.name, tier));
        for (const auto& table : tables) {
            auto st = prep(h_, std::format("SELECT EXISTS (SELECT 1 FROM {})", table));
            if (!st || sqlite3_step(st.get()) != SQLITE_ROW)
                return std::unexpected(std::string("step failed: ") + sqlite3_errmsg(h_.raw()));
            if (sqlite3_column_int64(st.get(), 0) != 0)
                return false;
        }
        return true;
    }

    template <class Event, class Decode>
    static std::vector<Event> decode(const std::vector<RawRow>& rows, Decode d) {
        std::vector<Event> out;
        out.reserve(rows.size());
        for (const auto& r : rows)
            out.push_back(d(r));
        return out;
    }

    // A historical mapdrive event is a one-time backfill whose count is additive, so the identity of
    // every one folded is remembered in the replay ring's table, in this same transaction: the
    // bounded per-profile retry (fold_mapdrive_events under skip_known_historical) then skips it
    // instead of counting the mapping a second time after the upgrade. The same hash as that
    // wrapper's, so its lookup finds these.
    void remember_historical(const std::vector<MapDriveEvent>& events) {
        auto st = prep(h_, std::format("INSERT INTO {} (source, record_key, digest, seq) "
                                       "VALUES ('{}', ?, 0, 0) ON CONFLICT DO NOTHING "
                                       "RETURNING record_key",
                                       kSeenTable, kMapdriveHistoricalSource));
        if (!st)
            return;
        for (const auto& e : events) {
            if (e.origin != "historical")
                continue;
            const std::string key =
                identity_hex({e.direction, e.local_mount, e.remote_path, e.remote_host, e.username});
            sqlite3_reset(st.get());
            sqlite3_bind_text(st.get(), 1, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);
            const int rc = sqlite3_step(st.get());
            if (rc == SQLITE_ROW) {
                ++report_.ring_keys;
            } else if (rc != SQLITE_DONE) {
                h_.fail(std::string("step failed: ") + sqlite3_errmsg(h_.raw()));
                return;
            }
        }
    }

    // A cursor source's chunk: each contribution joins the accumulator directly (a raw row is already
    // unique by record_key, so the ring is not consulted), and the newest ones seed the ring.
    void contribute(const std::vector<RawRow>& rows, const std::vector<KeyedContribution>& cs,
                    const FoldSourceDef& def, TierAccumulator& acc, int64_t seed_from_id,
                    int64_t& seq) {
        for (std::size_t i = 0; i < cs.size(); ++i) {
            const auto& c = cs[i];
            acc.add(c.ts, c.keys, c.measures);
            if (rows[i].id() < seed_from_id || c.record_key.empty() ||
                c.record_key.find('\0') != std::string::npos)
                continue;
            auto st = prep(h_, std::format("INSERT OR IGNORE INTO {} (source, record_key, digest, seq) "
                                           "VALUES (?, ?, ?, ?)",
                                           kSeenTable));
            if (!st)
                return;
            sqlite3_bind_text(st.get(), 1, def.name.data(), static_cast<int>(def.name.size()), SQLITE_STATIC);
            sqlite3_bind_text(st.get(), 2, c.record_key.c_str(), static_cast<int>(c.record_key.size()),
                              SQLITE_STATIC);
            sqlite3_bind_int64(st.get(), 3, c.identity_digest);
            sqlite3_bind_int64(st.get(), 4, ++seq);
            if (!step_done(h_, st.get()))
                return;
            ++report_.ring_keys;
        }
    }

    TransactionHandle& h_;
    EchoFold& fold_;
    std::set<std::string> legacy_tiers_; // old summary tables present: "process_hourly", ...
    std::set<std::string> raw_tables_;   // raw tables present: "process_live", ...
    int64_t now_;                        // the wall clock at the start, for the mark sanity check
    std::map<std::string, Mark> marks_;  // "<source>/<tier>" -> its validated mark
    Report report_;
};

// The names of the old tables a database still holds: `<src>_live` and `<src>_<tier>` for every
// roll-up source. A lookup failure is an error, never "no tables".
std::expected<std::pair<std::set<std::string>, std::set<std::string>>, std::string>
find_retired_tables(EchoDatabase& db) {
    std::set<std::string> tiers, raw, wanted_tiers, wanted_raw;
    for (const auto& def : fold_sources()) {
        if (def.own_tables)
            continue;
        wanted_raw.insert(std::format("{}_live", def.name));
        for (const auto tier : kTiers)
            wanted_tiers.insert(fold_view_name(def.name, tier));
    }
    const auto rows = db.execute_query("SELECT name FROM sqlite_master WHERE type = 'table'", 100000);
    if (!rows)
        return std::unexpected("listing tables: " + rows.error());
    for (const auto& r : rows->rows) {
        if (wanted_raw.contains(r.at(0)))
            raw.insert(r.at(0));
        else if (wanted_tiers.contains(r.at(0)))
            tiers.insert(r.at(0));
    }
    return std::pair{std::move(tiers), std::move(raw)};
}

std::optional<std::uintmax_t> free_bytes_of(const OpenSeams& seams, const std::filesystem::path& path) {
    if (seams.free_bytes)
        return seams.free_bytes(path);
    std::error_code ec;
    const auto parent = path.parent_path().empty() ? std::filesystem::path{"."} : path.parent_path();
    const auto info = std::filesystem::space(parent, ec);
    if (ec)
        return std::nullopt;
    return info.available;
}

} // namespace

std::expected<void, std::string> EchoDatabase::migrate_to_v10(EchoDatabase& db,
                                                              const std::filesystem::path& path,
                                                              const OpenSeams& seams) {
    using Clock = std::chrono::steady_clock;
    const auto started = Clock::now();

    const auto retired = find_retired_tables(db);
    if (!retired)
        return std::unexpected(retired.error());
    const std::set<std::string> legacy_tiers = retired->first;
    const std::set<std::string> raw_tables = retired->second;
    const bool has_retired = !legacy_tiers.empty() || !raw_tables.empty();

    // 0. BEFORE any transaction: refuse a volume that cannot hold the migration. Echo stays offline
    // until the space is freed and the agent restarted -- the alternative is a full disk under
    // the host. A database with nothing to migrate needs no room.
    const StorageBytes before = db.storage_bytes();
    if (has_retired) {
        if (!before.ok)
            return std::unexpected("the database size could not be read");
        const auto free_now = free_bytes_of(seams, path);
        // Twice the file, plus the write-ahead log already on disk: the migration's own writes
        // land in the log before the checkpoint, and the log's current size is known up front.
        const auto need = 2 * before.file_bytes() + before.wal_bytes;
        // An unreadable volume is a refusal too: the 2x check is mandatory, never skipped.
        if (!free_now) {
            return std::unexpected(
                std::string{kFreeSpaceRefusalPrefix} +
                std::format(" the Echo database to its roll-up tables: the free space on the volume "
                            "could not be read and {} bytes are needed (twice the {}-byte database "
                            "file plus its {}-byte log)",
                            need, before.file_bytes(), before.wal_bytes));
        }
        if (*free_now < static_cast<std::uintmax_t>(need)) {
            return std::unexpected(
                std::string{kFreeSpaceRefusalPrefix} +
                std::format(" the Echo database to its roll-up tables: {} bytes are free and {} are "
                            "needed (twice the {}-byte database file plus its {}-byte log)",
                            *free_now, need, before.file_bytes(), before.wal_bytes));
        }
    }

    // 1. ONE transaction.
    Report report;
    std::size_t dropped = 0;
    const auto result = db.checked_transaction([&](TransactionHandle& h) -> std::expected<void, std::string> {
        if (has_retired) {
            Migration m(h, *db.fold_, legacy_tiers, raw_tables, now_epoch_seconds());
            if (auto r = m.run(); !r)
                return r;
            for (const auto& table : m.retired_tables()) {
                if (!h.exec("DROP TABLE " + table))
                    return std::unexpected(h.error());
                ++dropped;
            }
            report = m.report();
            if (seams.v10_after_drop) {
                if (auto fault = seams.v10_after_drop(); !fault)
                    return std::unexpected(std::move(fault.error()));
            }
        } else if (!h.exec(generate_fold_ddl())) {
            return std::unexpected(h.error()); // a fresh database: just the roll-up schema
        }
        if (!h.exec(legacy_live_shim_ddl()))
            return std::unexpected(h.error());
        if (!h.exec(R"(DELETE FROM echo_config WHERE key LIKE 'rollup\_%\_at' ESCAPE '\' OR key IN ('usage_hwm_id', 'usage_lag_events'))"))
            return std::unexpected(h.error());
        if (!h.exec("INSERT INTO echo_config (key, value) VALUES ('schema_version', '10') "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value"))
            return std::unexpected(h.error());
        return {};
    });
    if (!result) {
        spdlog::error("EchoDatabase v10: migration rolled back, the retired tables are intact: {}",
                      result.error());
        return std::unexpected(result.error());
    }

    // 2. After COMMIT: never carry on from a connection that is still inside a transaction.
    if (sqlite3_get_autocommit(db.db_) == 0)
        return std::unexpected("the connection is still inside a transaction after the v10 commit");
    if (!has_retired) {
        spdlog::info("EchoDatabase: migrated to schema version 10 (roll-up tiers installed)");
        return {};
    }

    // secure_delete=ON zeroed every dropped raw page into the WAL: bring the WAL back to zero before
    // the VACUUM, whose own copy and journal are then the only transient space.
    const StorageBytes after_commit = db.storage_bytes();
    if (const auto cp = db.checkpoint(CheckpointMode::kTruncate); cp != CheckpointResult::kOk)
        spdlog::warn("EchoDatabase v10: the WAL checkpoint after the migration did not complete; the "
                     "next maintenance pass truncates it");

    const StorageBytes now_sb = db.storage_bytes();
    std::string vacuum_note = "not needed (already incremental)";
    if (now_sb.ok && now_sb.auto_vacuum != 2) {
        const auto free_now = free_bytes_of(seams, path);
        const std::uintmax_t need = 2 * static_cast<std::uintmax_t>(now_sb.file_bytes());
        if (!free_now || *free_now < need) {
            if (const int64_t t = now_epoch_seconds(); t > 0)
                (void)db.set_config(std::string{kAutoVacuumDeferredKey}, std::to_string(t));
            vacuum_note = "deferred (not enough free disk space for the copy)";
            spdlog::warn("EchoDatabase v10: the VACUUM that returns the freed pages is deferred: the "
                         "volume has less than twice the database free. The daily maintenance pass "
                         "retries it.");
        } else if (!db.vacuum_to_incremental()) {
            if (const int64_t t = now_epoch_seconds(); t > 0)
                (void)db.set_config(std::string{kAutoVacuumDeferredKey}, std::to_string(t));
            vacuum_note = "failed (retried by the daily maintenance pass)";
        } else {
            vacuum_note = "done";
        }
        if (sqlite3_get_autocommit(db.db_) == 0)
            return std::unexpected("the connection is inside a transaction after the VACUUM");
    }
    if (const auto cp = db.checkpoint(CheckpointMode::kTruncate); cp != CheckpointResult::kOk)
        spdlog::debug("EchoDatabase v10: WAL checkpoint after the VACUUM: not completed");

    const StorageBytes end = db.storage_bytes();
    spdlog::info("EchoDatabase: migrated to schema version 10 (roll-up tiers) in {} s: {} old summary "
                 "rows converted, {} raw rows folded, {} raw rows older than the old roll-up mark (or "
                 "the converted tier's edge that replaced an untrusted one) were not folded (under a "
                 "sane mark the old roll-up had summarised them, except rows written by a "
                 "process-event backfill or skipped by the clock-gap clamp, and the two cannot be told "
                 "apart; under a replaced floor they are the rows the converted tier's edge does not "
                 "reach), {} rejected, {} replay keys seeded, {} marks ahead of the clock replaced by "
                 "the converted tier's edge, usage lag: {} raw process rows past usage_hwm_id "
                 "(usage_lag_events was {}), {} of them folded into usage, {} tables dropped; file {} "
                 "-> {} bytes, WAL {} bytes at commit; VACUUM {}",
                 std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - started).count(),
                 report.legacy_tier_rows, report.raw_rows, report.below_mark, report.rejected,
                 report.ring_keys, report.untrusted_marks, report.usage_lag_rows,
                 report.usage_lag_events, report.usage_lag_folded, dropped, before.file_bytes(),
                 end.ok ? end.file_bytes() : 0, after_commit.wal_bytes, vacuum_note);
    return {};
}

} // namespace yuzu::echo
