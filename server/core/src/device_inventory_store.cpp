#include "device_inventory_store.hpp"

#include "device_ci_kinds.hpp"
#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sha256_hex.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <iterator>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "device_inventory_store";

// Bounded acquires (ADR-0012 lease discipline). Ingest runs on the gRPC thread
// (direct ReportInventory / gateway ProxyInventory) so it gives up fast on a
// saturated pool — best-effort, the agent retries next cycle + weekly floor. The
// reads are user-facing dashboard requests and can wait a little longer.
constexpr std::chrono::milliseconds kIngestAcquireTimeout{500};
constexpr std::chrono::milliseconds kQueryAcquireTimeout{3000};
// Hard cap on roster rows materialised regardless of the caller's `limit`, so the
// store can never allocate an unbounded result set.
constexpr int kListRowCap = 100000;

// Read-degrade reason labels (mirror SoftwareInventoryStore / the alert taxonomy).
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
// Sample the per-site degrade WARN (leading edge of an episode, then every Nth)
// so a sustained PG outage during a roster poll cannot flood the log — the counter
// is the continuous signal, the log a sampled breadcrumb. Values match the
// SoftwareInventoryStore sibling (consistency S1; a 4th copy is the convention).
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Per-site degrade-WARN state (one static instance per call site).
struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};
struct DegradeLog {
    bool should_log;
    std::uint64_t occurrence;
};

// Always increment the SHARED read-degrade counter with a source label (so the
// existing YuzuInventoryReadDegraded alert — which sums yuzu_inventory_read_degrade_total
// — covers device_ci too, while the label keeps it distinguishable from
// installed_software; sre BLOCKING reconciled with consistency N1). Decide whether
// this degrade emits a sampled WARN. Mirrors SoftwareInventoryStore::note_read_degrade.
DegradeLog note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason,
                             DegradeSampler& s) {
    if (metrics)
        metrics->counter("yuzu_inventory_read_degrade_total",
                         {{"reason", reason}, {"source", "device_ci"}})
            .increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return {new_episode || (n % kReadDegradeLogSample) == 0, n};
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

// Normalise a wire decimal string to a canonical bigint literal for the typed
// columns. A malformed/empty value becomes "0" (never an invalid SQL literal).
// from_chars is locale-independent and leaves `v` at 0 on a parse miss.
std::string bigint_param(const std::string& s) {
    long long v = 0;
    std::from_chars(s.data(), s.data() + s.size(), v);
    return std::to_string(v);
}

// The 11 scalars appended to device_ci at wire positions 22-32 (device_ci_kinds.hpp).
constexpr const char* kV2ScalarCols[] = {
    "chassis_type",   "chassis_serial", "chassis_asset_tag", "chassis_source",
    "board_vendor",   "board_product",  "board_serial",      "board_source",
    "machine_id_hash", "machine_id_algorithm", "machine_id_source",
};
// Ties the migration DDL to the wire: positions 0-21 are the frozen v1 fields, the rest are
// the appended scalars named here.
static_assert(std::size(kV2ScalarCols) == kDeviceCiScalarFields - 22,
              "kV2ScalarCols must name every appended scalar position (22..kDeviceCiScalarFields-1)");

// Split a kDeviceCiSections column list ("a,b,c") into names.
std::vector<std::string> split_columns(std::string_view columns) {
    std::vector<std::string> out;
    for (const auto part : std::views::split(columns, ','))
        out.emplace_back(part.begin(), part.end());
    return out;
}

// Migration v2 (additive, online-safe: constant defaults make the ALTER metadata-only,
// ADR-0008): the v2 blob's identity scalars on device_ci, a per-section status table, and
// one child table per list kind (typed TEXT columns, driven by kDeviceCiSections so a kind
// costs one registry entry). Children cascade from device_ci so delete_agent stays one
// statement. Unqualified DDL — the runner sets search_path to the store schema.
std::string migration_v2_sql() {
    std::string sql =
        "ALTER TABLE device_ci ADD COLUMN blob_version SMALLINT NOT NULL DEFAULT 1";
    for (const char* c : kV2ScalarCols)
        sql += std::string(", ADD COLUMN ") + c + " TEXT NOT NULL DEFAULT ''";
    sql += ";";
    sql += "CREATE TABLE device_ci_section ("
           "  agent_id TEXT NOT NULL REFERENCES device_ci (agent_id) ON DELETE CASCADE,"
           "  kind     TEXT NOT NULL,"
           "  level    TEXT NOT NULL DEFAULT '',"
           "  reason   TEXT NOT NULL DEFAULT '',"
           "  PRIMARY KEY (agent_id, kind));";
    for (const auto& d : kDeviceCiSections) {
        if (d.table == nullptr)
            continue;
        sql += std::string("CREATE TABLE ") + d.table +
               " (agent_id TEXT NOT NULL REFERENCES device_ci (agent_id) ON DELETE CASCADE,"
               " ord INTEGER NOT NULL";
        for (const auto& col : split_columns(d.columns))
            sql += ", " + col + " TEXT NOT NULL DEFAULT ''";
        sql += ", PRIMARY KEY (agent_id, ord));";
    }
    return sql;
}

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for the
    // migration transaction, so `device_ci` lands in `device_inventory_store`.
    // Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         // One row per agent (device-CI is 1:1). content_hash is the
         // server-recomputed canonical hash (drives hash-skip). first_seen/last_seen
         // are the SERVER receipt time (#1685). Numeric facts are typed BIGINT for
         // future range queries; the strings they came from are hashed, not these.
         "CREATE TABLE device_ci ("
         "  agent_id      TEXT PRIMARY KEY,"
         "  content_hash  TEXT NOT NULL DEFAULT '',"
         "  manufacturer  TEXT NOT NULL DEFAULT '',"
         "  model         TEXT NOT NULL DEFAULT '',"
         "  serial        TEXT NOT NULL DEFAULT '',"
         "  system_uuid   TEXT NOT NULL DEFAULT '',"
         "  hostname      TEXT NOT NULL DEFAULT '',"
         "  domain        TEXT NOT NULL DEFAULT '',"
         "  ou            TEXT NOT NULL DEFAULT '',"
         "  bios_vendor   TEXT NOT NULL DEFAULT '',"
         "  bios_version  TEXT NOT NULL DEFAULT '',"
         "  bios_date     TEXT NOT NULL DEFAULT '',"
         "  cpu_model     TEXT NOT NULL DEFAULT '',"
         "  cpu_cores     BIGINT NOT NULL DEFAULT 0,"
         "  cpu_threads   BIGINT NOT NULL DEFAULT 0,"
         "  ram_bytes     BIGINT NOT NULL DEFAULT 0,"
         "  disks_summary TEXT NOT NULL DEFAULT '',"
         "  primary_mac   TEXT NOT NULL DEFAULT '',"
         "  macs_summary  TEXT NOT NULL DEFAULT '',"
         "  nic_count     BIGINT NOT NULL DEFAULT 0,"
         "  os_name       TEXT NOT NULL DEFAULT '',"
         "  os_version    TEXT NOT NULL DEFAULT '',"
         "  os_build      TEXT NOT NULL DEFAULT '',"
         "  arch          TEXT NOT NULL DEFAULT '',"
         "  first_seen    BIGINT NOT NULL,"
         "  last_seen     BIGINT NOT NULL);"
         // Roster reads order by hostname; the index keeps the LIMIT scan ordered.
         "CREATE INDEX device_ci_hostname_idx ON device_ci (hostname);"},
        {2, migration_v2_sql()},
    };
    return kMigrations;
}

// SELECT column list shared by get + list, in a fixed order matched by fill_record.
constexpr const char* kSelectCols =
    "agent_id, manufacturer, model, serial, system_uuid, hostname, domain, ou, "
    "bios_vendor, bios_version, bios_date, cpu_model, cpu_cores, cpu_threads, ram_bytes, "
    "disks_summary, primary_mac, macs_summary, nic_count, os_name, os_version, os_build, "
    "arch, first_seen, last_seen, blob_version, chassis_type, chassis_serial, "
    "chassis_asset_tag, chassis_source, board_vendor, board_product, board_serial, "
    "board_source, machine_id_hash, machine_id_algorithm, machine_id_source";

void fill_record(PGresult* res, int row, DeviceCiRecord& out) {
    int c = 0;
    const auto col = [&]() { return PQgetvalue(res, row, c++); };
    out.agent_id = col();
    out.manufacturer = col();
    out.model = col();
    out.serial = col();
    out.system_uuid = col();
    out.hostname = col();
    out.domain = col();
    out.ou = col();
    out.bios_vendor = col();
    out.bios_version = col();
    out.bios_date = col();
    out.cpu_model = col();
    out.cpu_cores = col();
    out.cpu_threads = col();
    out.ram_bytes = col();
    out.disks_summary = col();
    out.primary_mac = col();
    out.macs_summary = col();
    out.nic_count = col();
    out.os_name = col();
    out.os_version = col();
    out.os_build = col();
    out.arch = col();
    out.first_seen = to_i64(col());
    out.last_seen = to_i64(col());
    out.blob_version = static_cast<int>(to_i64(col()));
    out.chassis_type = col();
    out.chassis_serial = col();
    out.chassis_asset_tag = col();
    out.chassis_source = col();
    out.board_vendor = col();
    out.board_product = col();
    out.board_serial = col();
    out.board_source = col();
    out.machine_id_hash = col();
    out.machine_id_algorithm = col();
    out.machine_id_source = col();
}

} // namespace

std::string DeviceInventoryStore::canonical_hash(const DeviceCiRecord& rec) {
    // v2: the agent's canonical bytes ARE the blob; the parser pinned its sha256 into
    // content_hash (empty on a digest failure -> the store nacks). v1 keeps the positional
    // 22-field join below, byte-identical, so old agents never loop on need_full.
    if (rec.blob_version >= 2)
        return rec.content_hash;
    // POSITIONAL — field order is the contract; MUST match the agent's
    // device_ci_canonical_blob (sync_source_device_ci.cpp) byte-for-byte. The
    // fields are already scrub+clamp'd by the ingest seam's parse (like
    // SoftwareInventoryStore::canonical_hash, which trusts the seam clamp), so this
    // joins positionally + hashes; it does NOT re-clamp.
    const std::string fields[] = {
        rec.manufacturer, rec.model,       rec.serial,        rec.system_uuid,
        rec.hostname,     rec.domain,      rec.ou,            rec.bios_vendor,
        rec.bios_version, rec.bios_date,   rec.cpu_model,     rec.cpu_cores,
        rec.cpu_threads,  rec.ram_bytes,   rec.disks_summary, rec.primary_mac,
        rec.macs_summary, rec.nic_count,   rec.os_name,       rec.os_version,
        rec.os_build,     rec.arch,
    };
    std::string canon;
    bool first = true;
    for (const auto& f : fields) {
        if (!first)
            canon += '\x1f';
        canon += f;
        first = false;
    }
    canon += '\x1e';
    return sha256_hex(canon).value_or("");
}

DeviceInventoryStore::DeviceInventoryStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("DeviceInventoryStore: no database connection at construction ({}) — "
                      "device-CI persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("DeviceInventoryStore: schema migration failed — device-CI persistence "
                      "disabled");
        return;
    }
    open_ = true;
}

InventoryIngestOutcome DeviceInventoryStore::apply_device_ci(std::string_view agent_id,
                                                            std::string_view claimed_hash,
                                                            std::optional<DeviceCiRecord> rec,
                                                            [[maybe_unused]] std::int64_t collected_at) {
    if (!open_ || agent_id.empty())
        return InventoryIngestOutcome::kError;

    // last_seen / first_seen are the SERVER receipt time, never the agent-supplied
    // collected_at (#1685): the freshness comparison must stay on one clock.
    const std::int64_t ts = now_secs();

    // ── Hash-only report: compare against the stored (server-recomputed) hash ──
    if (!rec.has_value()) {
        auto lease = pool_.try_acquire_for(kIngestAcquireTimeout);
        if (!lease) {
            spdlog::warn("DeviceInventoryStore: hash-only ingest skipped for agent={}, no "
                         "connection ({})",
                         agent_id, pool_.last_error());
            return InventoryIngestOutcome::kError;
        }
        pg::PgResult res =
            pg::exec_params(lease.get(),
                            "SELECT content_hash FROM device_inventory_store.device_ci "
                            "WHERE agent_id = $1",
                            std::vector<std::string>{std::string(agent_id)});
        if (res.status() != PGRES_TUPLES_OK) {
            spdlog::warn("DeviceInventoryStore: hash lookup failed for agent={}: {}", agent_id,
                         PQerrorMessage(lease.get()));
            return InventoryIngestOutcome::kError;
        }
        if (PQntuples(res.get()) == 0)
            return InventoryIngestOutcome::kNeedFull; // cold cache
        const std::string stored = PQgetvalue(res.get(), 0, 0);
        if (stored != std::string(claimed_hash))
            return InventoryIngestOutcome::kNeedFull; // drifted
        pg::PgResult upd =
            pg::exec_params(lease.get(),
                            "UPDATE device_inventory_store.device_ci SET last_seen = $2::bigint "
                            "WHERE agent_id = $1 RETURNING agent_id",
                            std::vector<std::string>{std::string(agent_id), std::to_string(ts)});
        if (upd.status() != PGRES_TUPLES_OK) {
            spdlog::warn("DeviceInventoryStore: last_seen bump failed for agent={}: {}", agent_id,
                         PQerrorMessage(lease.get()));
            return InventoryIngestOutcome::kError;
        }
        return InventoryIngestOutcome::kTouched;
    }

    // ── Full payload: recompute the hash, replace the parent row AND every child row ──
    const DeviceCiRecord r = std::move(*rec);
    const std::string server_hash = canonical_hash(r);
    if (server_hash.empty()) {
        // v2 record without a pinned hash (digest failure): never store it under a
        // placeholder hash — nack so the agent resends rather than loop on a bad compare.
        spdlog::warn("DeviceInventoryStore: no canonical hash for agent={} (blob_version={}) — "
                     "not stored",
                     agent_id, r.blob_version);
        return InventoryIngestOutcome::kError;
    }
    const std::string agent_id_s{agent_id};
    const std::string ts_s = std::to_string(ts);

    const bool ok = pool_.with_txn_for(kIngestAcquireTimeout, [&](PGconn* c) -> bool {
        // Serialise concurrent full replaces for THIS agent (two fulls under READ COMMITTED
        // would interleave their child DELETE+INSERT and leave a mixed set under a hash that
        // matches neither). Transaction-scoped and blocking on purpose — same rationale as
        // SoftwareInventoryStore. The key is PREFIXED so it never collides with that store's
        // unprefixed per-agent key on the same report thread.
        pg::PgResult lk = pg::exec_params(
            c, "SELECT pg_advisory_xact_lock(hashtextextended('device_ci:' || $1::text, 0))",
            std::vector<std::string>{agent_id_s});
        if (lk.status() != PGRES_TUPLES_OK)
            return false;

        // Parent upsert. first_seen is preserved on conflict; last_seen is the server
        // receipt time. blob_version + the 11 appended scalars are replaced wholesale, so a
        // v2 -> v1 downgrade blanks them.
        pg::PgResult up = pg::exec_params(
            c,
            "INSERT INTO device_inventory_store.device_ci ("
            "agent_id, content_hash, manufacturer, model, serial, system_uuid, hostname, domain, "
            "ou, bios_vendor, bios_version, bios_date, cpu_model, cpu_cores, cpu_threads, "
            "ram_bytes, disks_summary, primary_mac, macs_summary, nic_count, os_name, os_version, "
            "os_build, arch, first_seen, last_seen, blob_version, chassis_type, chassis_serial, "
            "chassis_asset_tag, chassis_source, board_vendor, board_product, board_serial, "
            "board_source, machine_id_hash, machine_id_algorithm, machine_id_source) VALUES ("
            "$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::bigint, $15::bigint, "
            "$16::bigint, $17, $18, $19, $20::bigint, $21, $22, $23, $24, $25::bigint, "
            "$26::bigint, $27::smallint, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38) "
            "ON CONFLICT (agent_id) DO UPDATE SET "
            "content_hash = EXCLUDED.content_hash, manufacturer = EXCLUDED.manufacturer, "
            "model = EXCLUDED.model, serial = EXCLUDED.serial, system_uuid = EXCLUDED.system_uuid, "
            "hostname = EXCLUDED.hostname, domain = EXCLUDED.domain, ou = EXCLUDED.ou, "
            "bios_vendor = EXCLUDED.bios_vendor, bios_version = EXCLUDED.bios_version, "
            "bios_date = EXCLUDED.bios_date, cpu_model = EXCLUDED.cpu_model, "
            "cpu_cores = EXCLUDED.cpu_cores, cpu_threads = EXCLUDED.cpu_threads, "
            "ram_bytes = EXCLUDED.ram_bytes, disks_summary = EXCLUDED.disks_summary, "
            "primary_mac = EXCLUDED.primary_mac, macs_summary = EXCLUDED.macs_summary, "
            "nic_count = EXCLUDED.nic_count, os_name = EXCLUDED.os_name, "
            "os_version = EXCLUDED.os_version, os_build = EXCLUDED.os_build, arch = EXCLUDED.arch, "
            "last_seen = EXCLUDED.last_seen, blob_version = EXCLUDED.blob_version, "
            "chassis_type = EXCLUDED.chassis_type, chassis_serial = EXCLUDED.chassis_serial, "
            "chassis_asset_tag = EXCLUDED.chassis_asset_tag, "
            "chassis_source = EXCLUDED.chassis_source, board_vendor = EXCLUDED.board_vendor, "
            "board_product = EXCLUDED.board_product, board_serial = EXCLUDED.board_serial, "
            "board_source = EXCLUDED.board_source, machine_id_hash = EXCLUDED.machine_id_hash, "
            "machine_id_algorithm = EXCLUDED.machine_id_algorithm, "
            "machine_id_source = EXCLUDED.machine_id_source "
            "RETURNING agent_id",
            std::vector<std::string>{
                agent_id_s, server_hash, r.manufacturer, r.model, r.serial, r.system_uuid,
                r.hostname, r.domain, r.ou, r.bios_vendor, r.bios_version, r.bios_date,
                r.cpu_model, bigint_param(r.cpu_cores), bigint_param(r.cpu_threads),
                bigint_param(r.ram_bytes), r.disks_summary, r.primary_mac, r.macs_summary,
                bigint_param(r.nic_count), r.os_name, r.os_version, r.os_build, r.arch, ts_s, ts_s,
                std::to_string(r.blob_version), r.chassis_type, r.chassis_serial,
                r.chassis_asset_tag, r.chassis_source, r.board_vendor, r.board_product,
                r.board_serial, r.board_source, r.machine_id_hash, r.machine_id_algorithm,
                r.machine_id_source});
        if (up.status() != PGRES_TUPLES_OK)
            return false;

        // Child replace: the full payload IS the new set, so a v1 full (no sections) or a
        // shrunk v2 leaves no stale rows. Driven by the registry so a kind costs no code.
        for (const auto& d : kDeviceCiSections) {
            if (d.table == nullptr)
                continue;
            const std::string del =
                std::string("DELETE FROM device_inventory_store.") + d.table + " WHERE agent_id = $1";
            pg::PgResult dr = pg::exec_params(c, del.c_str(), std::vector<std::string>{agent_id_s});
            if (dr.status() != PGRES_COMMAND_OK)
                return false;
        }
        pg::PgResult ds = pg::exec_params(
            c, "DELETE FROM device_inventory_store.device_ci_section WHERE agent_id = $1",
            std::vector<std::string>{agent_id_s});
        if (ds.status() != PGRES_COMMAND_OK)
            return false;

        // Only registered kinds persist (a hand-built record cannot smuggle a stray kind).
        // One pass: each kept section's row INSERT runs inline while its status columns are
        // collected for the single device_ci_section INSERT after the loop.
        std::vector<std::string_view> kinds, levels, reasons;
        for (const auto& sec : r.sections) {
            const auto si = device_ci_section_index(sec.kind);
            if (!si)
                continue;
            const auto& def = kDeviceCiSections[*si];
            kinds.emplace_back(sec.kind);
            levels.emplace_back(sec.level);
            reasons.emplace_back(sec.reason);
            if (def.table == nullptr || sec.rows.empty())
                continue;
            const auto cols = split_columns(def.columns);
            const std::size_t ncol = cols.size();
            std::vector<std::string> ords;
            ords.reserve(sec.rows.size());
            std::vector<std::vector<std::string_view>> arrays(ncol);
            for (auto& a : arrays)
                a.reserve(sec.rows.size());
            const std::string blank;
            for (std::size_t i = 0; i < sec.rows.size(); ++i) {
                ords.push_back(std::to_string(i));
                for (std::size_t k = 0; k < ncol; ++k)
                    arrays[k].emplace_back(k < sec.rows[i].size() ? sec.rows[i][k] : blank);
            }
            std::vector<std::string_view> ord_views(ords.begin(), ords.end());
            std::string sql = std::string("INSERT INTO device_inventory_store.") + def.table +
                              " (agent_id, ord";
            for (const auto& col : cols)
                sql += ", " + col;
            sql += ") SELECT $1, o";
            for (std::size_t k = 0; k < ncol; ++k)
                sql += ", c" + std::to_string(k);
            sql += " FROM unnest($2::int[]";
            for (std::size_t k = 0; k < ncol; ++k)
                sql += ", $" + std::to_string(k + 3) + "::text[]";
            sql += ") AS t(o";
            for (std::size_t k = 0; k < ncol; ++k)
                sql += ", c" + std::to_string(k);
            sql += ")";
            std::vector<std::string> params;
            params.reserve(ncol + 2);
            params.push_back(agent_id_s);
            params.push_back(pg::to_text_array(ord_views));
            for (const auto& a : arrays)
                params.push_back(pg::to_text_array(a));
            pg::PgResult ins = pg::exec_params(c, sql.c_str(), params);
            if (ins.status() != PGRES_COMMAND_OK)
                return false;
        }
        if (!kinds.empty()) {
            pg::PgResult si = pg::exec_params(
                c,
                "INSERT INTO device_inventory_store.device_ci_section (agent_id, kind, level, "
                "reason) SELECT $1, k, l, r FROM unnest($2::text[], $3::text[], $4::text[]) "
                "AS t(k, l, r)",
                std::vector<std::string>{agent_id_s, pg::to_text_array(kinds),
                                         pg::to_text_array(levels), pg::to_text_array(reasons)});
            if (si.status() != PGRES_COMMAND_OK)
                return false;
        }
        return true;
    });
    if (!ok) {
        // Rolled back (or never began): the previous set survives intact; the caller nacks
        // need_full and the agent resends. Never a half-replaced set.
        spdlog::warn("DeviceInventoryStore: full ingest failed for agent={} ({})", agent_id,
                     pool_.last_error());
        return InventoryIngestOutcome::kError;
    }
    return InventoryIngestOutcome::kStored;
}

std::expected<std::optional<DeviceCiRecord>, CiReadError>
DeviceInventoryStore::get_device_ci(std::string_view agent_id) {
    if (!open_) {
        static DegradeSampler s;
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, s).should_log)
            spdlog::warn("DeviceInventoryStore: get on a closed store");
        return std::unexpected(CiReadError::kDegraded);
    }
    if (agent_id.empty())
        return std::optional<DeviceCiRecord>{}; // precondition miss → absent, not a degrade
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler s;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, s).should_log)
            spdlog::warn("DeviceInventoryStore: get skipped, no connection in time ({})",
                         pool_.last_error());
        return std::unexpected(CiReadError::kDegraded);
    }
    const std::string sql = std::string("SELECT ") + kSelectCols +
                            " FROM device_inventory_store.device_ci WHERE agent_id = $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                       std::vector<std::string>{std::string(agent_id)});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler s;
        if (note_read_degrade(metrics_, kReasonQueryError, s).should_log)
            spdlog::warn("DeviceInventoryStore: get failed for agent={}: {}", agent_id,
                         PQerrorMessage(lease.get()));
        return std::unexpected(CiReadError::kDegraded);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<DeviceCiRecord>{}; // read succeeded, no CI row yet → absent
    DeviceCiRecord out;
    fill_record(res.get(), 0, out);
    return std::optional<DeviceCiRecord>{std::move(out)};
}

std::optional<std::vector<DeviceCiRecord>> DeviceInventoryStore::list_device_ci(int limit) {
    if (!open_) {
        static DegradeSampler s;
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, s).should_log)
            spdlog::warn("DeviceInventoryStore: list on a closed store");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler s;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, s).should_log)
            spdlog::warn("DeviceInventoryStore: list skipped, no connection in time ({})",
                         pool_.last_error());
        return std::nullopt;
    }
    int eff = limit > 0 && limit < kListRowCap ? limit : kListRowCap;
    const std::string sql =
        std::string("SELECT ") + kSelectCols +
        " FROM device_inventory_store.device_ci ORDER BY hostname ASC, agent_id ASC LIMIT $1::bigint";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                       std::vector<std::string>{std::to_string(eff)});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler s;
        if (note_read_degrade(metrics_, kReasonQueryError, s).should_log)
            spdlog::warn("DeviceInventoryStore: list failed: {}", PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    const int rows = PQntuples(res.get());
    std::vector<DeviceCiRecord> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        DeviceCiRecord r;
        fill_record(res.get(), i, r);
        out.push_back(std::move(r));
    }
    return out;
}

std::expected<std::vector<DeviceCiSection>, CiReadError>
DeviceInventoryStore::get_device_ci_sections(std::string_view agent_id) {
    if (!open_) {
        static DegradeSampler s;
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, s).should_log)
            spdlog::warn("DeviceInventoryStore: sections get on a closed store");
        return std::unexpected(CiReadError::kDegraded);
    }
    if (agent_id.empty())
        return std::vector<DeviceCiSection>{}; // precondition miss -> empty, not a degrade
    const std::string agent_id_s{agent_id};

    // One REPEATABLE READ transaction so the section SELECT and every per-kind SELECT share
    // ONE snapshot: a concurrent full replace committing between them can never mix
    // generations (a plain with_txn_for is READ COMMITTED — each statement re-snapshots).
    // `sections` is indexed by registry position; a non-empty `kind` marks a section seen
    // (a status row, or rows without one). with_txn_for runs the lambda exactly once, so the
    // registry-order result is assembled inside it.
    std::array<DeviceCiSection, kDeviceCiSectionCount> sections;
    std::vector<DeviceCiSection> out;
    bool began = false;
    const bool ok = pool_.with_txn_for(kQueryAcquireTimeout, [&](PGconn* c) -> bool {
        began = true;
        pg::PgResult iso{PQexec(c, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")};
        if (iso.status() != PGRES_COMMAND_OK)
            return false;
        pg::PgResult sres = pg::exec_params(
            c,
            "SELECT kind, level, reason FROM device_inventory_store.device_ci_section "
            "WHERE agent_id = $1",
            std::vector<std::string>{agent_id_s});
        if (sres.status() != PGRES_TUPLES_OK)
            return false;
        for (int i = 0; i < PQntuples(sres.get()); ++i) {
            const auto si = device_ci_section_index(PQgetvalue(sres.get(), i, 0));
            if (!si)
                continue; // unregistered kind: never surfaced
            sections[*si].kind = kDeviceCiSections[*si].section;
            sections[*si].level = PQgetvalue(sres.get(), i, 1);
            sections[*si].reason = PQgetvalue(sres.get(), i, 2);
        }
        // Registry order (deterministic). A kind with rows but no status row still surfaces,
        // with a blank level.
        for (std::size_t si = 0; si < kDeviceCiSectionCount; ++si) {
            const auto& d = kDeviceCiSections[si];
            auto& sec = sections[si];
            if (d.table != nullptr) {
                const std::string sql = std::string("SELECT ") + d.columns +
                                        " FROM device_inventory_store." + d.table +
                                        " WHERE agent_id = $1 ORDER BY ord";
                pg::PgResult rres =
                    pg::exec_params(c, sql.c_str(), std::vector<std::string>{agent_id_s});
                if (rres.status() != PGRES_TUPLES_OK)
                    return false;
                const int nrow = PQntuples(rres.get());
                const int ncol = PQnfields(rres.get());
                sec.rows.reserve(static_cast<std::size_t>(nrow));
                for (int i = 0; i < nrow; ++i) {
                    std::vector<std::string> row;
                    row.reserve(static_cast<std::size_t>(ncol));
                    for (int k = 0; k < ncol; ++k)
                        row.emplace_back(PQgetvalue(rres.get(), i, k));
                    sec.rows.push_back(std::move(row));
                }
            }
            if (sec.kind.empty() && sec.rows.empty())
                continue;
            sec.kind = d.section;
            out.push_back(std::move(sec));
        }
        return true;
    });
    if (!ok) {
        // Never an empty success on a failed read: a degrade the caller can surface.
        static DegradeSampler s_timeout;
        static DegradeSampler s_query;
        const bool timeout = !began;
        if (note_read_degrade(metrics_, timeout ? kReasonPoolTimeout : kReasonQueryError,
                              timeout ? s_timeout : s_query)
                .should_log)
            spdlog::warn("DeviceInventoryStore: sections get failed for agent={} ({})", agent_id,
                         pool_.last_error());
        return std::unexpected(CiReadError::kDegraded);
    }
    return out;
}

bool DeviceInventoryStore::delete_agent(std::string_view agent_id) {
    if (!open_ || agent_id.empty())
        return false;
    auto lease = pool_.try_acquire_for(kIngestAcquireTimeout);
    if (!lease) {
        spdlog::debug("DeviceInventoryStore: delete skipped for agent={}, no connection ({})",
                      agent_id, pool_.last_error());
        return false;
    }
    pg::PgResult res =
        pg::exec_params(lease.get(), "DELETE FROM device_inventory_store.device_ci WHERE agent_id = $1",
                        std::vector<std::string>{std::string(agent_id)});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::debug("DeviceInventoryStore: delete failed for agent={}: {}", agent_id,
                      PQerrorMessage(lease.get()));
        return false;
    }
    return true;
}

} // namespace yuzu::server
