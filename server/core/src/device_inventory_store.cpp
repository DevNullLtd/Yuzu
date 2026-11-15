#include "device_inventory_store.hpp"

#include "device_ci_kinds.hpp"
#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "device_ci_section_digest.hpp"
#include "sha256_hex.hpp"

#include <yuzu/log_token.hpp>
#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
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

// Read-degrade reason labels (mirror SoftwareInventoryStore / the alert taxonomy).
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
// The keyed list read (`list_device_ci_for`) ran out of its overall budget between chunks (#7549): the
// whole read is reported degraded rather than returned partial.
constexpr const char* kReasonKeyedBudget = "keyed_read_budget";
// A failed read of the v2 per-section statements (the section status SELECT or a per-kind row
// SELECT) after - or, for the standalone `get_device_ci_sections`, instead of - the record read:
// kept apart from `query_error` (the record read failed) because the two are answered differently
// (REST 503 / MCP retryable error versus `ci: null`, HTTP 200) and fixed differently.
constexpr const char* kReasonSectionsQueryError = "sections_query_error";
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

// Split a kDeviceCiSections column list ("a,b,c") into names.
std::vector<std::string> split_columns(std::string_view columns) {
    std::vector<std::string> out;
    for (const auto part : std::views::split(columns, ','))
        out.emplace_back(part.begin(), part.end());
    return out;
}

// Migration v2 (additive, online-safe: constant defaults make the ALTER metadata-only,
// ADR-0008): the v2 blob's identity scalars on device_ci (wire positions 22-32 of
// device_ci_kinds.hpp), a per-section status table, and one child table per list kind
// (typed TEXT columns). Children cascade from device_ci so delete_agent stays one statement.
// Unqualified DDL - the runner sets search_path to the store schema.
//
// FROZEN (#7164): this is a checked-in literal, NOT generated from kDeviceCiSections. The
// runner skips a migration whose version is already recorded, so a generated v2 changes what a
// FRESH database gets and nothing about a deployed one. Never edit it: a new table-backed kind,
// or a changed column list, ships its own migration (v4 or later) - see "Registry-backed tables"
// in docs/postgres-store-playbook.md. What ties the registry to the schema is now (a) the
// projection check in the constructor (a registry table or column the database lacks refuses
// at boot) and (b) the schema test in test_device_inventory_store.cpp. The compile-time tie
// between kDeviceCiScalarFields and the scalar DDL that the old generator carried is replaced
// by those two. It is byte-identical (3311 bytes, sha256
// 1e6e39f4f195e20b1d0253ab1fc7bc6d48401162e78371df3ebecaaabaf41f6c) to what the generator emitted
// when it was frozen, so a database that already ran v2 on today's registry needs nothing.
constexpr const char* kMigrationV2Sql =
    "ALTER TABLE device_ci ADD COLUMN blob_version SMALLINT NOT NULL DEFAULT 1,"
    " ADD COLUMN chassis_type TEXT NOT NULL DEFAULT '',"
    " ADD COLUMN chassis_serial TEXT NOT NULL DEFAULT '',"
    " ADD COLUMN chassis_asset_tag TEXT NOT NULL DEFAULT '',"
    " ADD COLUMN chassis_source TEXT NOT NULL DEFAULT '',"
    " ADD COLUMN board_vendor TEXT NOT NULL DEFAULT '',"
    " ADD COLUMN board_product TEXT NOT NULL DEFAULT '',"
    " ADD COLUMN board_serial TEXT NOT NULL DEFAULT '',"
    " ADD COLUMN board_source TEXT NOT NULL DEFAULT '',"
    " ADD COLUMN machine_id_hash TEXT NOT NULL DEFAULT '',"
    " ADD COLUMN machine_id_algorithm TEXT NOT NULL DEFAULT '',"
    " ADD COLUMN machine_id_source TEXT NOT NULL DEFAULT '';"
    "CREATE TABLE device_ci_section (  agent_id TEXT NOT NULL REFERENCES device_ci (agent_id) ON DELETE CASCADE,"
    "  kind     TEXT NOT NULL,  level    TEXT NOT NULL DEFAULT '',"
    "  reason   TEXT NOT NULL DEFAULT '',  PRIMARY KEY (agent_id, kind));"
    "CREATE TABLE device_ci_cpu (agent_id TEXT NOT NULL REFERENCES device_ci (agent_id) ON DELETE CASCADE,"
    " ord INTEGER NOT NULL, idx TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '',"
    " cores TEXT NOT NULL DEFAULT '', threads TEXT NOT NULL DEFAULT '',"
    " clock_mhz TEXT NOT NULL DEFAULT '', socket_designation TEXT NOT NULL DEFAULT '',"
    " stepping TEXT NOT NULL DEFAULT '', PRIMARY KEY (agent_id, ord));"
    "CREATE TABLE device_ci_dimm (agent_id TEXT NOT NULL REFERENCES device_ci (agent_id) ON DELETE CASCADE,"
    " ord INTEGER NOT NULL, slot TEXT NOT NULL DEFAULT '',"
    " size_mb TEXT NOT NULL DEFAULT '', type TEXT NOT NULL DEFAULT '',"
    " speed_mhz TEXT NOT NULL DEFAULT '', manufacturer TEXT NOT NULL DEFAULT '',"
    " part_number TEXT NOT NULL DEFAULT '', serial TEXT NOT NULL DEFAULT '',"
    " PRIMARY KEY (agent_id, ord));"
    "CREATE TABLE device_ci_disk (agent_id TEXT NOT NULL REFERENCES device_ci (agent_id) ON DELETE CASCADE,"
    " ord INTEGER NOT NULL, idx TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '',"
    " size_gb TEXT NOT NULL DEFAULT '', media_type TEXT NOT NULL DEFAULT '',"
    " interface TEXT NOT NULL DEFAULT '', PRIMARY KEY (agent_id, ord));"
    "CREATE TABLE device_ci_swap (agent_id TEXT NOT NULL REFERENCES device_ci (agent_id) ON DELETE CASCADE,"
    " ord INTEGER NOT NULL, device TEXT NOT NULL DEFAULT '',"
    " total_mb TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '',"
    " PRIMARY KEY (agent_id, ord));"
    "CREATE TABLE device_ci_volume (agent_id TEXT NOT NULL REFERENCES device_ci (agent_id) ON DELETE CASCADE,"
    " ord INTEGER NOT NULL, volume TEXT NOT NULL DEFAULT '',"
    " mount_points TEXT NOT NULL DEFAULT '', device TEXT NOT NULL DEFAULT '',"
    " fstype TEXT NOT NULL DEFAULT '', total_bytes TEXT NOT NULL DEFAULT '',"
    " detail TEXT NOT NULL DEFAULT '', PRIMARY KEY (agent_id, ord));"
    "CREATE TABLE device_ci_partition (agent_id TEXT NOT NULL REFERENCES device_ci (agent_id) ON DELETE CASCADE,"
    " ord INTEGER NOT NULL, disk TEXT NOT NULL DEFAULT '',"
    " partition TEXT NOT NULL DEFAULT '', size_bytes TEXT NOT NULL DEFAULT '',"
    " type TEXT NOT NULL DEFAULT '', mount_points TEXT NOT NULL DEFAULT '',"
    " detail TEXT NOT NULL DEFAULT '', PRIMARY KEY (agent_id, ord));"
    "CREATE TABLE device_ci_topology (agent_id TEXT NOT NULL REFERENCES device_ci (agent_id) ON DELETE CASCADE,"
    " ord INTEGER NOT NULL, topo_kind TEXT NOT NULL DEFAULT '',"
    " name TEXT NOT NULL DEFAULT '', uuid TEXT NOT NULL DEFAULT '',"
    " members TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '',"
    " PRIMARY KEY (agent_id, ord));";

// Migration v3 (additive, online-safe, ADR-0008): the number of child rows stored for the
// section (`row_count`) and the SHA-256 of their canonical serialization (`content_digest`),
// both written in the same transaction as the rows. NULL = status-only kind (no child rows) or a
// row written before v3 (unknown) - both read exactly as before (never verified). Nullable with
// no default and no CHECK: the ALTERs are metadata-only and cannot fail on existing rows.
// v3 is unreleased, so the digest column is folded into it rather than adding a v4. The ADDs are
// IF NOT EXISTS so a re-run is harmless, BUT the runner will not run an applied version again: a
// database that already recorded the earlier row_count-only v3 lacks content_digest. Since #7158
// the runner's recorded-hash check refuses first when that database recorded the old text AFTER
// public.yuzu_schema_migrations existed (the log line names the store and v3); a database that
// applied the old v3 BEFORE the table existed was recorded as first seen with this build's text,
// so the constructor's projection check refuses it instead, with a log line naming
// device_ci_section. Either way server.cpp refuses to start the server. The reset for such a
// dev/UAT database is in docs/user-manual/upgrading.md ("the server refuses to start on a device
// inventory schema it cannot read"): UPDATE public.schema_meta SET version = 2 WHERE store =
// 'device_inventory_store', then restart (the re-applied v3 overwrites its recorded hash).
// Unqualified DDL - the runner sets search_path to the store schema.
constexpr const char* kMigrationV3Sql =
    "ALTER TABLE device_ci_section ADD COLUMN IF NOT EXISTS row_count INTEGER NULL, "
    "ADD COLUMN IF NOT EXISTS content_digest TEXT NULL;";

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
         // Historical: built for an ordered roster read that no longer exists (the Hardware list
         // joins CI by agent_id, #7549). No read relies on this index.
         "CREATE INDEX device_ci_hostname_idx ON device_ci (hostname);"},
        {2, kMigrationV2Sql},
        {3, kMigrationV3Sql},
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
    // Post-migration projection check (postgres-store-playbook "Runner guards"; the same shape as
    // ApiTokenStore and SoftwareInventoryStore). The runner skips any version at or below the
    // stored high-water mark, so a database that ran an earlier revision of v2 or v3 (or one
    // stamped by a different binary) can lack a table or column this binary reads while run()
    // still reports success - and every sections read then fails with 42P01/42703 on the first
    // request. One LIMIT 0 SELECT per table, over every column the runtime uses, touches no rows
    // and refuses here instead (server.cpp then refuses to start). The child tables are driven by
    // the registry, so a registry kind with no table fails at boot. Column PRESENCE only: an extra
    // column is tolerated (#3894's ahead-database stance); names, types, nullability, order and
    // the key shape are pinned for the shipped literals by the schema test in
    // test_device_inventory_store.cpp, column defaults are not pinned by anything.
    {
        struct Probe {
            std::string table;
            std::string columns;
        };
        std::vector<Probe> probes;
        probes.push_back({"device_ci", std::string("content_hash, ") + kSelectCols});
        probes.push_back(
            {"device_ci_section", "agent_id, kind, level, reason, row_count, content_digest"});
        for (const auto& d : kDeviceCiSections) {
            if (d.table == nullptr)
                continue;
            probes.push_back({d.table, std::string("agent_id, ord, ") + d.columns});
        }
        for (const auto& p : probes) {
            const std::string sql =
                "SELECT " + p.columns + " FROM device_inventory_store." + p.table + " LIMIT 0";
            pg::PgResult probe =
                pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
            if (probe.status() != PGRES_TUPLES_OK) {
                // SQLSTATE 42P01 (undefined table) / 42703 (undefined column) is a schema defect;
                // anything else (a dropped connection, a statement timeout, a permission error)
                // is not evidence of one, and a restart is the retry. The message names no
                // destructive step: the supported reset for a development or UAT database is in
                // the upgrade notes, and it is not advice for any other database.
                const char* state = PQresultErrorField(probe.get(), PG_DIAG_SQLSTATE);
                const std::string sqlstate = state != nullptr ? state : "";
                const bool schema_defect = sqlstate == "42P01" || sqlstate == "42703";
                const bool permission = sqlstate == "42501";
                spdlog::error(
                    "DeviceInventoryStore: post-migration schema projection check failed on {} "
                    "(SQLSTATE {}) - {} The server will not start; see docs/user-manual/"
                    "upgrading.md, \"the server refuses to start on a device inventory schema it "
                    "cannot read\". Database said: {}",
                    p.table, sqlstate.empty() ? "none" : sqlstate,
                    schema_defect
                        ? "the database lacks a table or column this build reads (an earlier "
                          "revision of the unreleased migration v2/v3, a skipped or partial "
                          "migration, or a database from a different build)."
                        : permission
                              ? "the server's database role cannot read it (grant SELECT on the "
                                "store's schema; a restart will not fix a permission error)."
                              : "this is not a missing-object error (a dropped connection or a "
                                "timeout); restart once before treating the schema as damaged.",
                    PQresultErrorMessage(probe.get()));
                return;
            }
        }
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

    // Which statement failed and Postgres's primary error line, for the warn below.
    const char* fail_stage = "";
    std::string fail_err;
    const bool ok = pool_.with_txn_for(kIngestAcquireTimeout, [&](PGconn* c) -> bool {
        // First line only: later lines (DETAIL) can echo row values.
        const auto fail = [&](const char* stage) {
            fail_stage = stage;
            fail_err = PQerrorMessage(c);
            fail_err.resize(std::min(fail_err.find('\n'), fail_err.size()));
            return false;
        };
        // Serialise concurrent full replaces for THIS agent (two fulls under READ COMMITTED
        // would interleave their child DELETE+INSERT and leave a mixed set under a hash that
        // matches neither). Transaction-scoped and blocking on purpose — same rationale as
        // SoftwareInventoryStore. The key is PREFIXED so it never collides with that store's
        // unprefixed per-agent key on the same report thread.
        pg::PgResult lk = pg::exec_params(
            c, "SELECT pg_advisory_xact_lock(hashtextextended('device_ci:' || $1::text, 0))",
            std::vector<std::string>{agent_id_s});
        if (lk.status() != PGRES_TUPLES_OK)
            return fail("lock");

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
            return fail("upsert");

        // Child replace: the full payload IS the new set, so a v1 full (no sections) or a
        // shrunk v2 leaves no stale rows. Driven by the registry so a kind costs no code.
        for (const auto& d : kDeviceCiSections) {
            if (d.table == nullptr)
                continue;
            const std::string del =
                std::string("DELETE FROM device_inventory_store.") + d.table + " WHERE agent_id = $1";
            pg::PgResult dr = pg::exec_params(c, del.c_str(), std::vector<std::string>{agent_id_s});
            if (dr.status() != PGRES_COMMAND_OK)
                return fail("child_delete");
        }
        pg::PgResult ds = pg::exec_params(
            c, "DELETE FROM device_inventory_store.device_ci_section WHERE agent_id = $1",
            std::vector<std::string>{agent_id_s});
        if (ds.status() != PGRES_COMMAND_OK)
            return fail("section_delete");

        // Only registered kinds persist (a hand-built record cannot smuggle a stray kind).
        // One pass: each kept section's row INSERT runs inline while its status columns are
        // collected for the single device_ci_section INSERT after the loop.
        std::vector<std::string_view> kinds, levels, reasons;
        // Per kept section: the child-row count the INSERT below ACTUALLY stored (read from its
        // command tag, never from the agent; it is expected to equal the parser-capped
        // `sec.rows.size()`, and the tag is authoritative if a trigger ever diverges), or "" for
        // a status-only kind (-> NULL: nothing to verify). The read side compares this to the
        // rows it reads.
        std::vector<std::string> row_counts;
        // Per kept section: the content digest of the rows inserted (server-computed from the same
        // padded rows the INSERT stores, via the one shared serialization), or "" -> NULL for a
        // status-only kind. Written in the same transaction as the rows and the status row.
        std::vector<std::string> digests;
        for (const auto& sec : r.sections) {
            const auto si = device_ci_section_index(sec.kind);
            if (!si)
                continue;
            const auto& def = kDeviceCiSections[*si];
            kinds.emplace_back(sec.kind);
            levels.emplace_back(sec.level);
            reasons.emplace_back(sec.reason);
            if (def.table == nullptr) {
                row_counts.emplace_back(); // status-only kind: NULL
                digests.emplace_back();
                continue;
            }
            const auto cols = split_columns(def.columns);
            const std::size_t ncol = cols.size();
            // Computed from exactly what is about to be stored (short rows pad, long rows
            // truncate to the registry's columns - the same rule the INSERT applies below).
            const auto digest =
                section_content_digest(def, sec.rows, digest_fn_ ? digest_fn_ : &sha256_hex);
            if (!digest) {
                const bool failed = fail("digest");
                fail_err = "digest_provider_failed"; // no libpq statement failed: name the cause
                return failed;
            }
            digests.push_back(*digest);
            if (sec.rows.empty()) {
                row_counts.emplace_back("0"); // table-backed, nothing inserted
                continue;
            }
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
                return fail("row_insert");
            // The tag's row count is what Postgres stored under this transaction. A successful
            // INSERT always carries one; an empty tag would silently store NULL (= unverified),
            // so refuse it rather than fail open.
            const char* const tag = PQcmdTuples(ins.get());
            if (tag == nullptr || *tag == '\0')
                return fail("row_insert");
            row_counts.emplace_back(tag);
        }
        if (!kinds.empty()) {
            pg::PgResult si = pg::exec_params(
                c,
                "INSERT INTO device_inventory_store.device_ci_section (agent_id, kind, level, "
                "reason, row_count, content_digest) SELECT $1, k, l, r, NULLIF(n, '')::integer, "
                "NULLIF(d, '') FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], "
                "$6::text[]) AS t(k, l, r, n, d)",
                std::vector<std::string>{
                    agent_id_s, pg::to_text_array(kinds), pg::to_text_array(levels),
                    pg::to_text_array(reasons),
                    pg::to_text_array(std::vector<std::string_view>(row_counts.begin(),
                                                                    row_counts.end())),
                    pg::to_text_array(std::vector<std::string_view>(digests.begin(),
                                                                    digests.end()))});
            if (si.status() != PGRES_COMMAND_OK)
                return fail("section_insert");
        }
        return true;
    });
    if (!ok) {
        // Rolled back (or never began): the previous set survives intact; the caller nacks
        // need_full and the agent resends. Never a half-replaced set. An empty stage means
        // no statement ran (no connection in time, or BEGIN failed): the pool error says why.
        spdlog::warn("DeviceInventoryStore: full ingest failed for agent={} stage={} err='{}' "
                     "pool='{}'",
                     agent_id, *fail_stage != '\0' ? fail_stage : "acquire_or_begin", ::yuzu::log_key_token(fail_err),
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

std::optional<std::vector<DeviceCiRecord>>
DeviceInventoryStore::list_device_ci_for(const std::vector<std::string>& agent_ids,
                                         DeviceCiKeyedReadLimits limits) {
    if (!open_) {
        static DegradeSampler s;
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, s).should_log)
            spdlog::warn("DeviceInventoryStore: keyed list on a closed store");
        return std::nullopt;
    }
    std::vector<DeviceCiRecord> out;
    if (agent_ids.empty())
        return out; // nothing asked, nothing to read: an empty success, no lease taken
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler s;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, s).should_log)
            spdlog::warn("DeviceInventoryStore: keyed list skipped, no connection in time ({})",
                         pool_.last_error());
        return std::nullopt;
    }
    const std::size_t chunk = limits.chunk > 0 ? limits.chunk : 1;
    // Clamped both ways so neither an "unlimited" sentinel (milliseconds::max()) nor a hugely
    // negative value can overflow the time_point arithmetic (signed overflow is UB). A day is far
    // past any real read, and a negative budget behaves like zero: the first chunk runs, then the
    // read degrades.
    const auto budget = std::clamp(limits.budget, std::chrono::milliseconds{0},
                                   std::chrono::milliseconds{std::chrono::hours{24}});
    const auto deadline = std::chrono::steady_clock::now() + budget;
    const std::string sql =
        std::string("SELECT ") + kSelectCols +
        " FROM device_inventory_store.device_ci WHERE agent_id = ANY($1::text[])";
    std::vector<std::string_view> views;
    views.reserve(std::min(chunk, agent_ids.size()));
    for (std::size_t off = 0; off < agent_ids.size(); off += chunk) {
        if (off > 0 && std::chrono::steady_clock::now() >= deadline) {
            static DegradeSampler s;
            if (note_read_degrade(metrics_, kReasonKeyedBudget, s).should_log)
                spdlog::warn("DeviceInventoryStore: keyed list abandoned after {} of {} ids, "
                             "budget {} ms spent",
                             off, agent_ids.size(), limits.budget.count());
            return std::nullopt; // never a partial map: an absent row must mean "no CI", not "not read"
        }
        const std::size_t end = std::min(off + chunk, agent_ids.size());
        views.assign(agent_ids.begin() + static_cast<std::ptrdiff_t>(off),
                     agent_ids.begin() + static_cast<std::ptrdiff_t>(end));
        pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                           std::vector<std::string>{pg::to_text_array(views)});
        if (res.status() != PGRES_TUPLES_OK) {
            static DegradeSampler s;
            if (note_read_degrade(metrics_, kReasonQueryError, s).should_log)
                spdlog::warn("DeviceInventoryStore: keyed list failed: {}", PQerrorMessage(lease.get()));
            return std::nullopt;
        }
        const int rows = PQntuples(res.get());
        // No per-chunk reserve: reserve(n) allocates exactly n, which defeats the vector's geometric
        // growth and reallocates the whole result once per chunk.
        for (int i = 0; i < rows; ++i) {
            DeviceCiRecord r;
            fill_record(res.get(), i, r);
            out.push_back(std::move(r));
        }
    }
    return out;
}

namespace {

/// The section reads of one device, run on a connection that is ALREADY inside a REPEATABLE READ
/// transaction (the caller owns BEGIN/isolation/COMMIT), so the section SELECT and every
/// per-kind SELECT share the caller's snapshot. Appends to `out` in registry order (a status row
/// or rows make a kind present; a kind with rows but no status row still surfaces, with a blank
/// level). False on any statement failure - `out` is then partial and must be discarded.
bool read_sections_in_txn(PGconn* c, const std::string& agent_id_s, std::vector<DeviceCiSection>& out) {
    // `sections` is indexed by registry position; a non-empty `kind` marks a section seen.
    std::array<DeviceCiSection, kDeviceCiSectionCount> sections;
    pg::PgResult sres = pg::exec_params(
        c,
        "SELECT kind, level, reason, row_count, content_digest "
        "FROM device_inventory_store.device_ci_section "
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
        // NULL = status-only kind, or a row written before migration v3: never verified.
        if (!PQgetisnull(sres.get(), i, 3))
            sections[*si].row_count = static_cast<int>(to_i64(PQgetvalue(sres.get(), i, 3)));
        if (!PQgetisnull(sres.get(), i, 4))
            sections[*si].content_digest = PQgetvalue(sres.get(), i, 4);
    }
    // Registry order (deterministic).
    for (std::size_t si = 0; si < kDeviceCiSectionCount; ++si) {
        const auto& d = kDeviceCiSections[si];
        auto& sec = sections[si];
        if (d.table != nullptr) {
            const std::string sql = std::string("SELECT ") + d.columns +
                                    " FROM device_inventory_store." + d.table +
                                    " WHERE agent_id = $1 ORDER BY ord";
            pg::PgResult rres = pg::exec_params(c, sql.c_str(), std::vector<std::string>{agent_id_s});
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
}

} // namespace

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

    // One REPEATABLE READ READ ONLY transaction so the section SELECT and every per-kind SELECT
    // share ONE snapshot: a concurrent full replace committing between them can never mix
    // generations (a plain with_txn_for is READ COMMITTED - each statement re-snapshots).
    // with_txn_on runs the lambda exactly once, so the registry-order result is assembled
    // inside it.
    //
    // The lease is acquired here (bounded, nothing in between) rather than inside
    // with_txn_for so "no connection in time" and "the transaction failed" are told apart:
    // with_txn_for answers both with one false. A read has no compensating step, so the
    // lost-COMMIT ambiguity documented on with_txn_on does not apply.
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler s;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, s).should_log)
            spdlog::warn("DeviceInventoryStore: sections get skipped for agent={}, no connection "
                         "in time ({})",
                         agent_id, pool_.last_error());
        return std::unexpected(CiReadError::kDegraded);
    }
    std::vector<DeviceCiSection> out;
    const bool ok = pool_.with_txn_on(std::move(lease), [&](PGconn* c) -> bool {
        pg::PgResult iso{PQexec(c, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")};
        if (iso.status() != PGRES_COMMAND_OK)
            return false;
        return read_sections_in_txn(c, agent_id_s, out);
    });
    if (!ok) {
        // Never an empty success on a failed read: a degrade the caller can surface.
        static DegradeSampler s;
        if (note_read_degrade(metrics_, kReasonSectionsQueryError, s).should_log)
            spdlog::warn("DeviceInventoryStore: sections get failed for agent={} ({})", agent_id,
                         pool_.last_error());
        return std::unexpected(CiReadError::kDegraded);
    }
    return out;
}

std::expected<DeviceCiWithSections, CiReadError>
DeviceInventoryStore::get_device_ci_with_sections(std::string_view agent_id) {
    if (!open_) {
        static DegradeSampler s;
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, s).should_log)
            spdlog::warn("DeviceInventoryStore: record+sections get on a closed store");
        return std::unexpected(CiReadError::kDegraded);
    }
    if (agent_id.empty())
        return DeviceCiWithSections{}; // precondition miss -> absent, not a degrade
    const std::string agent_id_s{agent_id};

    // ONE lease and ONE REPEATABLE READ READ ONLY transaction for the record AND its sections:
    // the scalars and the rows are always the same replace generation (two separate reads could
    // pair gen N scalars with gen N+1 rows, undetectably). Acquired here, with nothing between
    // the acquire and with_txn_on (that call's contract); see get_device_ci_sections.
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler s;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, s).should_log)
            spdlog::warn("DeviceInventoryStore: record+sections get skipped for agent={}, no "
                         "connection in time ({})",
                         agent_id, pool_.last_error());
        return std::unexpected(CiReadError::kDegraded);
    }
    // Held OUTSIDE the lambda so the record survives the rollback a failed section statement
    // forces (an aborted Postgres transaction cannot run further statements).
    enum class Stage { kNone, kRecordRead, kSectionsFailed, kDone };
    Stage stage = Stage::kNone;
    DeviceCiWithSections result;
    const bool ok = pool_.with_txn_on(std::move(lease), [&](PGconn* c) -> bool {
        pg::PgResult iso{PQexec(c, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")};
        if (iso.status() != PGRES_COMMAND_OK)
            return false;
        const std::string sql = std::string("SELECT ") + kSelectCols +
                                " FROM device_inventory_store.device_ci WHERE agent_id = $1";
        pg::PgResult res = pg::exec_params(c, sql.c_str(), std::vector<std::string>{agent_id_s});
        if (res.status() != PGRES_TUPLES_OK)
            return false;
        stage = Stage::kRecordRead;
        if (PQntuples(res.get()) == 0) {
            stage = Stage::kDone; // no CI row yet -> absent
            return true;
        }
        DeviceCiRecord rec;
        fill_record(res.get(), 0, rec);
        const bool v2 = rec.blob_version >= 2;
        result.record = std::move(rec);
        if (v2) {
            std::vector<DeviceCiSection> sections;
            if (!read_sections_in_txn(c, agent_id_s, sections)) {
                stage = Stage::kSectionsFailed;
                return false;
            }
            result.record->sections = std::move(sections);
        }
        stage = Stage::kDone;
        return true;
    });
    if (ok)
        return result;
    if (stage == Stage::kSectionsFailed) {
        // The record read answered; only a section statement failed. Say so - never an
        // empty-sections success - and keep the record the caller may still need.
        static DegradeSampler s;
        if (note_read_degrade(metrics_, kReasonSectionsQueryError, s).should_log)
            spdlog::warn("DeviceInventoryStore: sections get failed for agent={} ({})", agent_id,
                         pool_.last_error());
        result.record->sections.clear();
        result.sections_failed = true;
        return result;
    }
    // Isolation, the record SELECT, or COMMIT failed (a COMMIT failure after a complete read is
    // treated as a degrade, never a possibly-torn success).
    static DegradeSampler s;
    if (note_read_degrade(metrics_, kReasonQueryError, s).should_log)
        spdlog::warn("DeviceInventoryStore: record+sections get failed for agent={} ({})", agent_id,
                     pool_.last_error());
    return std::unexpected(CiReadError::kDegraded);
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
