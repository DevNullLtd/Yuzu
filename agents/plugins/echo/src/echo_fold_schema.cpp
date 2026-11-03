/**
 * echo_fold_schema.cpp -- the 17 per-source roll-up declarations, the DDL
 * generator and the read-surface allowlists. See echo_fold_schema.hpp.
 *
 * Roll-up is the ONLY storage model: raw capture rows are not kept, and no
 * setting, flag or mode selects between the two. Nothing outside the fold writer
 * and its tests opens, writes or reads these tables.
 *
 * Enrichment columns are the ones a source's *_delta leaves unnamed: they are
 * written as 0 / '' and are declared with the tier so a tier is declared once.
 */

#include "echo_fold_schema.hpp"

#include <algorithm>
#include <cctype>
#include <format>
#include <sstream>
#include <unordered_set>

namespace yuzu::echo {

namespace {

using R = ColumnRole;
using M = MergeOp;

// ── Column constructors ─────────────────────────────────────────────────────

constexpr ColumnDef k_txt(std::string_view n) { return {n, "TEXT", R::kKey, M::kNone, true}; }
constexpr ColumnDef k_int(std::string_view n) { return {n, "INTEGER", R::kKey}; }
constexpr ColumnDef m_sum(std::string_view n) { return {n, "INTEGER", R::kMeasure, M::kSum}; }
constexpr ColumnDef m_rsum(std::string_view n) { return {n, "REAL", R::kMeasure, M::kSum}; }
constexpr ColumnDef m_max(std::string_view n) { return {n, "INTEGER", R::kMeasure, M::kMax}; }
constexpr ColumnDef m_rmax(std::string_view n) { return {n, "REAL", R::kMeasure, M::kMax}; }
constexpr ColumnDef m_min(std::string_view n) { return {n, "INTEGER", R::kMeasure, M::kMin}; }
constexpr ColumnDef m_last_t(std::string_view n, std::string_view guard) {
    return {n, "TEXT", R::kMeasure, M::kLast, false, {}, guard};
}
constexpr ColumnDef m_last_i(std::string_view n, std::string_view guard) {
    return {n, "INTEGER", R::kMeasure, M::kLast, false, {}, guard};
}
constexpr ColumnDef g_avg(std::string_view n, std::string_view type, std::string_view expr) {
    return {n, type, R::kGenerated, M::kNone, false, expr};
}

// Average = sum / samples; 0 for an empty bucket. An INTEGER-declared average truncates, as
// the legacy rollup's CAST(AVG(..) AS INTEGER) does; a REAL one is the exact mean.
#define YUZU_FOLD_AVG(sum_col) "CASE WHEN samples>0 THEN " sum_col "*1.0/samples ELSE 0 END"
#define YUZU_FOLD_IAVG(sum_col) "CASE WHEN samples>0 THEN " sum_col "/samples ELSE 0 END"

constexpr std::string_view kH = "hourly";
constexpr std::string_view kD = "daily";
constexpr std::string_view kM = "monthly";

// ── The 17 declarations ─────────────────────────────────────────────────────
//
// Order inside `columns` is the VIEW order: the registry's existing columns first
// (where the registry already declares the tier), new columns after.

std::vector<FoldSourceDef> build_fold_sources() {
    std::vector<FoldSourceDef> s;

    s.push_back({"process", {kH, kD, kM},
                 {k_txt("name"), k_txt("user"), m_sum("start_count"), m_sum("stop_count"),
                  k_txt("parent_name"), m_sum("abnormal_exit_count"), m_sum("elevated_count"),
                  m_sum("spoofed_parent_count")}});

    // Listening sockets fold into tcp with remote_addr='*' and remote_port=local_port.
    s.push_back({"tcp", {kH, kD, kM},
                 {k_txt("remote_addr"), k_int("remote_port"), k_txt("proto"),
                  k_txt("process_name"), m_sum("connect_count"), m_sum("disconnect_count"),
                  m_sum("failed_count"), m_sum("duration_s_sum"), m_sum("listen_open_count"),
                  m_sum("listen_close_count")}});

    s.push_back({"service", {kH, kD},
                 {k_txt("name"), m_sum("status_changes"), m_last_t("last_status", "last_ts"),
                  m_sum("install_count"), m_sum("remove_count"), m_max("last_ts"),
                  m_last_i("last_exit_code", "last_ts"), m_last_t("last_start_account", "last_ts"),
                  m_last_t("last_binary_path", "last_ts"), m_sum("failed_count")}});

    s.push_back({"user", {kH, kD},
                 {k_txt("user"), k_txt("domain"), m_sum("login_count"), m_sum("logout_count"),
                  k_txt("logon_type"), m_sum("disconnect_count"), m_sum("session_s_sum")}});

    s.push_back({"perf", {kH, kD},
                 {m_sum("samples"), g_avg("cpu_avg", "REAL", YUZU_FOLD_AVG("cpu_sum")),
                  m_rmax("cpu_max"), g_avg("mem_avg", "REAL", YUZU_FOLD_AVG("mem_sum")),
                  m_rmax("mem_max"), g_avg("commit_avg", "REAL", YUZU_FOLD_AVG("commit_sum")),
                  g_avg("read_bps_avg", "INTEGER", YUZU_FOLD_IAVG("read_bps_sum")),
                  g_avg("write_bps_avg", "INTEGER", YUZU_FOLD_IAVG("write_bps_sum")),
                  g_avg("read_lat_us_avg", "INTEGER", YUZU_FOLD_IAVG("read_lat_us_sum")),
                  g_avg("write_lat_us_avg", "INTEGER", YUZU_FOLD_IAVG("write_lat_us_sum")),
                  m_max("read_lat_us_max"), m_max("write_lat_us_max"),
                  g_avg("rx_bps_avg", "INTEGER", YUZU_FOLD_IAVG("rx_bps_sum")),
                  g_avg("tx_bps_avg", "INTEGER", YUZU_FOLD_IAVG("tx_bps_sum")),
                  m_rsum("cpu_sum"), m_rsum("mem_sum"), m_rsum("commit_sum"),
                  m_sum("read_bps_sum"), m_sum("write_bps_sum"), m_sum("read_lat_us_sum"),
                  m_sum("write_lat_us_sum"), m_sum("rx_bps_sum"), m_sum("tx_bps_sum"),
                  m_rsum("cpu_kernel_sum"), m_max("rx_bps_max"), m_max("tx_bps_max"),
                  m_sum("procs_sum"), m_sum("threads_sum"), m_sum("handles_sum")}});

    s.push_back({"procperf", {kH, kD},
                 {k_txt("name"), k_txt("version"), k_int("is_kthread"), m_sum("samples"),
                  m_max("instances_max"), g_avg("cpu_avg", "REAL", YUZU_FOLD_AVG("cpu_sum")),
                  m_rmax("cpu_max"),
                  g_avg("ws_avg_bytes", "INTEGER", YUZU_FOLD_IAVG("ws_sum")),
                  m_max("ws_max_bytes"), m_rsum("cpu_sum"), m_sum("ws_sum"),
                  m_max("private_bytes_max"), m_max("handles_max"), m_max("threads_max"),
                  m_sum("io_read_bytes_sum"), m_sum("io_write_bytes_sum")}});

    // netqual_boot stays a plain table; only the live sample stream folds.
    s.push_back({"netqual", {kH, kD},
                 {k_txt("proto"), k_txt("remote_bucket"), k_txt("process_name"),
                  m_sum("samples"), m_sum("rtt_us_sum"), m_max("rtt_us_max"), m_min("rtt_us_min"),
                  m_sum("rtt_var_us_sum"), m_sum("lost_sum"), m_max("lost_max"),
                  m_sum("degraded_samples"), m_sum("bytes_in_sum"), m_sum("bytes_out_sum")}});

    s.push_back({"module", {kH, kD, kM},
                 {k_txt("module_name"), k_txt("signer"), k_txt("signed_state"),
                  k_int("is_kernel"), m_sum("load_count"), k_txt("module_dir"),
                  k_txt("process_name"), m_sum("blocked_count"), m_sum("rebased_count")}});

    s.push_back({"software", {kH, kD, kM},
                 {k_txt("name"), m_sum("install_count"), m_sum("remove_count"),
                  m_sum("upgrade_count"), k_txt("version"), k_txt("publisher"), k_txt("arch"),
                  m_sum("downgrade_count")}});

    s.push_back({"arp", {kH},
                 {k_txt("interface"), k_txt("ip_address"), k_txt("mac_address"),
                  m_sum("appear_count"), m_sum("remove_count"), k_int("is_router"),
                  m_sum("rebind_count")}});

    s.push_back({"dns", {kH},
                 {k_txt("name"), k_txt("record_type"), m_sum("appear_count"),
                  m_sum("remove_count"), k_txt("data"), m_sum("negative_count")}});

    s.push_back({"netconn", {kH, kD},
                 {k_txt("action"), k_txt("channel"), k_txt("category"), k_txt("capability"),
                  k_txt("iface_kind"), k_int("reason_code"), k_txt("phy_type"),
                  k_txt("auth_alg"), k_txt("cipher_alg"), m_sum("event_count"),
                  m_max("last_ts")}});

    // last_ts exists only to order last_dialect (a kLast column needs a guard).
    s.push_back({"mapdrive", {kH, kD},
                 {k_txt("direction"), k_txt("local_mount"), k_txt("remote_path"),
                  k_txt("remote_host"), m_sum("appear_count"), m_sum("remove_count"),
                  m_sum("historical_count"), m_min("first_ts"), m_max("last_ts"),
                  m_last_t("last_dialect", "last_ts"), m_sum("guest_count")}});

    s.push_back({"power", {kH, kD},
                 {k_txt("action"), k_txt("resume_kind"), k_txt("source"), m_sum("event_count"),
                  m_max("last_ts"), m_last_t("last_detail", "last_ts")},
                 /*cursor_source=*/true});

    s.push_back({"removable", {kH, kD},
                 {k_txt("action"), k_txt("device_key"), k_txt("vendor"), k_txt("product"),
                  k_txt("serial"), k_txt("bus"), k_txt("volume"), k_txt("image_path"),
                  m_sum("event_count"), m_min("first_ts"), m_max("last_ts"), m_max("size_bytes"),
                  m_last_t("disk_id", "last_ts"), m_max("partition_count")},
                 /*cursor_source=*/true});

    s.push_back({"registry", {kH, kD},
                 {k_txt("hive"), k_txt("key_path"), k_txt("value_name"), k_txt("action"),
                  m_sum("change_count"), m_last_t("last_data", "last_ts"),
                  m_last_t("last_data_type", "last_ts"), m_last_t("last_actor_image", "last_ts"),
                  m_max("last_ts")},
                 /*cursor_source=*/true});

    // usage keeps usage_daily / usage_daily_user as its own tables (read directly
    // by app_usage): declared here for its column set only. No DDL, no dictionary,
    // so exe_key is a plain key and the launcher is a plain guarded measure.
    s.push_back({"usage", {kD},
                 {{"exe_key", "TEXT", R::kKey}, m_sum("run_count"), m_sum("total_seconds"),
                  m_min("first_seen"), m_max("last_seen"), m_max("distinct_users"),
                  m_sum("superseded_runs"), m_sum("expired_runs"), m_max("max_run_s"),
                  m_min("min_run_s"), m_sum("short_run_count"), m_max("peak_instances"),
                  m_last_t("launched_by_exe_key", "last_seen")},
                 /*cursor_source=*/false, /*own_tables=*/true});

    return s;
}

#undef YUZU_FOLD_AVG
#undef YUZU_FOLD_IAVG

const std::unordered_set<std::string>& view_set() {
    static const std::unordered_set<std::string> s = [] {
        std::unordered_set<std::string> out;
        for (const auto& n : fold_view_names())
            out.insert(n);
        return out;
    }();
    return s;
}

} // namespace

const std::vector<FoldSourceDef>& fold_sources() {
    static const std::vector<FoldSourceDef> s = build_fold_sources();
    return s;
}

const FoldSourceDef* fold_source(std::string_view name) {
    for (const auto& d : fold_sources())
        if (d.name == name)
            return &d;
    return nullptr;
}

std::string fold_view_name(std::string_view source, std::string_view tier) {
    return std::format("{}_{}", source, tier);
}

std::string physical_table_name(std::string_view source, std::string_view tier) {
    return std::format("{}_{}_r", source, tier);
}

std::string physical_column_name(const ColumnDef& col) {
    return col.interned ? std::format("{}_id", col.name) : std::string{col.name};
}

std::vector<std::string> fold_view_names() {
    std::vector<std::string> out;
    for (const auto& def : fold_sources()) {
        if (def.own_tables)
            continue;
        for (auto tier : def.tiers)
            out.push_back(fold_view_name(def.name, tier));
    }
    return out;
}

std::string generate_fold_ddl() {
    std::ostringstream d;
    d << "CREATE TABLE IF NOT EXISTS " << kDictTable
      << " (id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT NOT NULL UNIQUE);\n";
    // The replay ring of the cursor sources. `digest` is the identity check the raw
    // store did by payload comparison; `seq` orders the ring for pruning.
    d << "CREATE TABLE IF NOT EXISTS " << kSeenTable
      << " (source TEXT NOT NULL, record_key TEXT NOT NULL, digest INTEGER NOT NULL,"
         " seq INTEGER NOT NULL, PRIMARY KEY (source, record_key)) WITHOUT ROWID;\n";

    for (const auto& def : fold_sources()) {
        if (def.own_tables)
            continue;
        for (auto tier : def.tiers) {
            const std::string bucket{ts_column_for_suffix(tier)};
            const std::string table = physical_table_name(def.name, tier);
            const std::string view = fold_view_name(def.name, tier);

            d << "CREATE TABLE IF NOT EXISTS " << table << " (\n    id INTEGER PRIMARY KEY,\n    "
              << bucket << " INTEGER NOT NULL DEFAULT 0";
            for (const auto& c : def.columns) {
                // An interned key is stored as its dictionary id, whatever its logical type.
                d << ",\n    " << physical_column_name(c) << ' ' << (c.interned ? "INTEGER" : c.sql_type);
                if (c.role == ColumnRole::kGenerated) {
                    d << " GENERATED ALWAYS AS (" << c.generated_expr << ") VIRTUAL";
                } else if (c.interned) {
                    d << " NOT NULL"; // an id; there is no meaningful default
                } else {
                    d << " NOT NULL DEFAULT " << (c.sql_type == "TEXT" ? "''" : "0");
                }
            }
            d << "\n);\n";

            // ONE unique index: the UPSERT target and the retention bucket
            // index (bucket first, so a bucket-ordered scan needs no second index).
            d << "CREATE UNIQUE INDEX IF NOT EXISTS " << table << "_uq ON " << table << "(" << bucket;
            for (const auto& c : def.columns)
                if (c.role == ColumnRole::kKey)
                    d << ", " << physical_column_name(c);
            d << ");\n";

            // The view: the names every consumer already queries. A text key resolves
            // through a correlated dictionary lookup, NOT a JOIN: SQLite reports a join
            // table that a query does not select from as a column-less read of that table
            // at the top level, which the operator-SQL authorizer cannot tell from a direct
            // read of the dictionary. A lookup is only present for the columns a query
            // selects, and its reads are reported under the view's name.
            d << "CREATE VIEW IF NOT EXISTS " << view << " AS SELECT r.id AS id, r." << bucket << " AS "
              << bucket;
            for (const auto& c : def.columns) {
                if (c.interned)
                    d << ", (SELECT text FROM " << kDictTable << " WHERE id = r." << physical_column_name(c)
                      << ") AS " << c.name;
                else
                    d << ", r." << c.name << " AS " << c.name;
            }
            d << " FROM " << table << " r;\n";
        }
    }
    return d.str();
}

bool is_fold_view(std::string_view name) {
    return view_set().contains(std::string(name));
}

// A row table is `<view>_r` for a roll-up view: derived from the view set, not a second set.
bool is_fold_row_table(std::string_view name) {
    return name.ends_with("_r") && is_fold_view(name.substr(0, name.size() - 2));
}

bool is_fold_internal_table(std::string_view name) {
    return name == kDictTable || name == kSeenTable || is_fold_row_table(name);
}

std::vector<std::string> legacy_live_shim_names() {
    std::vector<std::string> out;
    for (const auto& def : fold_sources())
        if (!def.own_tables)
            out.push_back(std::format("{}_live", def.name));
    return out;
}

bool is_legacy_live_shim(std::string_view name) {
    static const std::unordered_set<std::string> names = [] {
        const auto v = legacy_live_shim_names();
        return std::unordered_set<std::string>(v.begin(), v.end());
    }();
    return names.contains(std::string(name));
}

std::vector<std::string> referenced_legacy_live_shims(std::string_view sql) {
    const auto ident = [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
    };
    std::vector<std::string> out;
    for (const auto& name : legacy_live_shim_names()) {
        for (auto pos = sql.find(name); pos != std::string_view::npos; pos = sql.find(name, pos + 1)) {
            const bool starts = pos == 0 || !ident(sql[pos - 1]);
            const bool ends = pos + name.size() == sql.size() || !ident(sql[pos + name.size()]);
            if (starts && ends) {
                out.push_back(name);
                break;
            }
        }
    }
    return out;
}

// ── The retired raw tables' columns ─────────────────────────────────────────

namespace {

constexpr std::string_view kI = "INTEGER";
constexpr std::string_view kR = "REAL";
constexpr std::string_view kT = "TEXT";

// The raw store's column declarations, moved here verbatim from the registry's `live`
// granularities (name, type, in declaration order; `id` is implicit and leads every table).
// A raw-row decoder reads them positionally, so a column is never reordered or renamed.
const std::vector<std::pair<std::string_view, std::vector<LegacyColumn>>>& legacy_tables() {
    static const std::vector<std::pair<std::string_view, std::vector<LegacyColumn>>> t = {
        {"process", {{"ts", kI}, {"snapshot_id", kI}, {"action", kT}, {"pid", kI}, {"ppid", kI},
                     {"name", kT}, {"cmdline", kT}, {"user", kT}}},
        {"tcp", {{"ts", kI}, {"snapshot_id", kI}, {"action", kT}, {"proto", kT}, {"local_addr", kT},
                 {"local_port", kI}, {"remote_addr", kT}, {"remote_host", kT},
                 {"remote_port", kI}, {"state", kT}, {"pid", kI}, {"process_name", kT}}},
        {"service", {{"ts", kI}, {"snapshot_id", kI}, {"action", kT}, {"name", kT},
                     {"display_name", kT}, {"status", kT}, {"prev_status", kT},
                     {"startup_type", kT}, {"prev_startup_type", kT}}},
        {"user", {{"ts", kI}, {"snapshot_id", kI}, {"action", kT}, {"user", kT}, {"domain", kT},
                  {"logon_type", kT}, {"session_id", kT}}},
        {"perf", {{"ts", kI}, {"snapshot_id", kI}, {"cpu_pct", kR}, {"mem_used_pct", kR},
                  {"commit_pct", kR}, {"disk_read_bps", kI}, {"disk_write_bps", kI},
                  {"disk_read_lat_us", kI}, {"disk_write_lat_us", kI}, {"net_rx_bps", kI},
                  {"net_tx_bps", kI}}},
        {"procperf", {{"ts", kI}, {"snapshot_id", kI}, {"name", kT}, {"version", kT},
                      {"instances", kI}, {"cpu_pct", kR}, {"ws_bytes", kI}, {"is_kthread", kI}}},
        {"netqual", {{"ts", kI}, {"snapshot_id", kI}, {"proto", kT}, {"remote_bucket", kT},
                     {"process_name", kT}, {"rtt_us", kI}, {"rtt_var_us", kI}, {"lost", kI},
                     {"retrans", kI}, {"segs_out", kI}, {"ca_state", kI}}},
        {"module", {{"ts", kI}, {"snapshot_id", kI}, {"action", kT}, {"pid", kI},
                    {"process_name", kT}, {"module_name", kT}, {"module_dir", kT},
                    {"signed_state", kT}, {"signer", kT}, {"is_kernel", kI}}},
        {"software", {{"ts", kI}, {"snapshot_id", kI}, {"action", kT}, {"name", kT},
                      {"version", kT}, {"prev_version", kT}, {"publisher", kT},
                      {"install_date", kT}}},
        {"arp", {{"ts", kI}, {"snapshot_id", kI}, {"action", kT}, {"interface", kT},
                 {"ip_address", kT}, {"mac_address", kT}, {"entry_type", kT}}},
        {"dns", {{"ts", kI}, {"snapshot_id", kI}, {"action", kT}, {"name", kT},
                 {"record_type", kT}, {"data", kT}, {"ttl_remaining_s", kI}, {"source", kT}}},
        {"netconn", {{"ts", kI}, {"snapshot_id", kI}, {"action", kT}, {"channel", kT},
                     {"category", kT}, {"capability", kT}, {"iface_kind", kT},
                     {"reason_code", kI}}},
        {"mapdrive", {{"ts", kI}, {"snapshot_id", kI}, {"action", kT}, {"direction", kT},
                      {"local_mount", kT}, {"remote_path", kT}, {"remote_host", kT},
                      {"username", kT}, {"provider", kT}, {"origin", kT}}},
        {"power", {{"ts", kI}, {"snapshot_id", kI}, {"action", kT}, {"detail", kT},
                   {"record_key", kT}}},
        {"removable", {{"ts", kI}, {"snapshot_id", kI}, {"action", kT}, {"device_key", kT},
                       {"vendor", kT}, {"product", kT}, {"serial", kT}, {"bus", kT},
                       {"volume", kT}, {"size_bytes", kI}, {"image_path", kT}, {"pid", kI},
                       {"evidence", kT}, {"record_key", kT}}},
        {"registry", {{"ts", kI}, {"snapshot_id", kI}, {"hive", kT}, {"key_path", kT},
                      {"value_name", kT}, {"action", kT}, {"data_type", kT}, {"data", kT},
                      {"data_size", kI}, {"data_truncated", kI}, {"prev_data_type", kT},
                      {"prev_data", kT}, {"prev_data_size", kI}, {"prev_data_truncated", kI},
                      {"actor_pid", kI}, {"actor_image", kT}, {"source", kT},
                      {"observed_at", kI}, {"detail", kT}, {"record_key", kT}}},
    };
    return t;
}

} // namespace

std::vector<LegacyColumn> legacy_live_columns(std::string_view source) {
    for (const auto& [name, cols] : legacy_tables())
        if (name == source)
            return cols;
    return {};
}

std::string legacy_live_shim_ddl() {
    std::string ddl;
    for (const auto& [name, cols] : legacy_tables()) {
        ddl += std::format("CREATE VIEW IF NOT EXISTS {}_live AS SELECT CAST(NULL AS INTEGER) AS id", name);
        for (const auto& c : cols)
            ddl += std::format(", CAST(NULL AS {}) AS {}", c.sql_type, c.name);
        ddl += " WHERE 0;\n";
    }
    return ddl;
}

// ── The shared merge clause, the tier-to-tier roll-up, the average conversion ──

std::string fold_upsert_assignments(const FoldSourceDef& def) {
    std::string out;
    const auto add = [&](std::string s) {
        out += out.empty() ? "" : ",";
        out += s;
    };
    for (const auto& c : def.columns) {
        if (c.role != ColumnRole::kMeasure)
            continue;
        const std::string name = physical_column_name(c);
        switch (c.merge) {
        case MergeOp::kSum:
            add(std::format("{0}={0}+excluded.{0}", name));
            break;
        case MergeOp::kMax:
            add(std::format("{0}=MAX({0},excluded.{0})", name));
            break;
        case MergeOp::kMin:
            add(std::format("{0}=MIN({0},excluded.{0})", name));
            break;
        case MergeOp::kLast:
            add(std::format("{0}=CASE WHEN excluded.{1}>={1} THEN excluded.{0} ELSE {0} END", name,
                            c.guard));
            break;
        case MergeOp::kNone:
            break;
        }
    }
    return out;
}

std::string_view avg_sum_column(const ColumnDef& generated) {
    // The expression is `CASE WHEN samples>0 THEN <sum>*1.0/samples ELSE 0 END` (REAL) or
    // `... THEN <sum>/samples ELSE 0 END` (INTEGER): the identifier right after THEN.
    if (generated.role != ColumnRole::kGenerated)
        return {};
    constexpr std::string_view kThen = "THEN ";
    const auto pos = generated.generated_expr.find(kThen);
    if (pos == std::string_view::npos)
        return {};
    auto rest = generated.generated_expr.substr(pos + kThen.size());
    std::size_t n = 0;
    while (n < rest.size() && (std::isalnum(static_cast<unsigned char>(rest[n])) || rest[n] == '_'))
        ++n;
    return rest.substr(0, n);
}

std::string fold_tier_from_tier_sql(std::string_view source, std::string_view from,
                                    std::string_view to) {
    const FoldSourceDef* def = fold_source(source);
    if (!def || def->own_tables)
        return {};
    const auto has = [&](std::string_view t) {
        return std::find(def->tiers.begin(), def->tiers.end(), t) != def->tiers.end();
    };
    if (!has(from) || !has(to))
        return {};
    const std::string from_bucket{ts_column_for_suffix(from)};
    const std::string to_bucket{ts_column_for_suffix(to)};
    // Floor to the coarser bucket in SQL (SQLite's % truncates toward zero, hence the double mod).
    std::string bucket_expr;
    if (from == "hourly" && to == "daily")
        bucket_expr = std::format("({0} - (({0} % 86400) + 86400) % 86400)", from_bucket);
    else if (from == "daily" && to == "monthly")
        bucket_expr = std::format(
            "CAST(strftime('%s', date({}, 'unixepoch', 'start of month')) AS INTEGER)", from_bucket);
    else
        return {};

    std::string cols = to_bucket, vals = bucket_expr, conflict = to_bucket;
    for (const auto& c : def->columns) {
        if (c.role == ColumnRole::kGenerated)
            continue;
        const std::string name = physical_column_name(c);
        cols += "," + name;
        vals += ",r." + name;
        if (c.role == ColumnRole::kKey)
            conflict += "," + name;
    }
    // WHERE is required: without it SQLite reads `ON CONFLICT` after a bare SELECT as a join clause.
    return std::format("INSERT INTO {0}({1}) SELECT {2} FROM {3} r WHERE r.{4} >= ?1 "
                       "ORDER BY r.{4}, r.id ON CONFLICT({5}) DO UPDATE SET {6}",
                       physical_table_name(source, to), cols, vals,
                       physical_table_name(source, from), from_bucket, conflict,
                       fold_upsert_assignments(*def));
}

} // namespace yuzu::echo
