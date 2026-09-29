#include "device_inventory_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <openssl/evp.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <optional>
#include <string>
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

std::string sha256_hex(const std::string& in) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(in.data(), in.size(), md, &len, EVP_sha256(), nullptr) != 1)
        return {};
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<std::size_t>(len) * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(kHex[md[i] >> 4]);
        out.push_back(kHex[md[i] & 0x0f]);
    }
    return out;
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
    };
    return kMigrations;
}

// SELECT column list shared by get + list, in a fixed order matched by fill_record.
constexpr const char* kSelectCols =
    "agent_id, manufacturer, model, serial, system_uuid, hostname, domain, ou, "
    "bios_vendor, bios_version, bios_date, cpu_model, cpu_cores, cpu_threads, ram_bytes, "
    "disks_summary, primary_mac, macs_summary, nic_count, os_name, os_version, os_build, "
    "arch, first_seen, last_seen";

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
}

} // namespace

std::string DeviceInventoryStore::canonical_hash(const DeviceCiRecord& rec) {
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
    return sha256_hex(canon);
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

    // ── Full payload: recompute the hash from the record, upsert the single row ──
    const DeviceCiRecord r = std::move(*rec);
    const std::string server_hash = canonical_hash(r);
    auto lease = pool_.try_acquire_for(kIngestAcquireTimeout);
    if (!lease) {
        spdlog::warn("DeviceInventoryStore: full ingest skipped for agent={}, no connection ({})",
                     agent_id, pool_.last_error());
        return InventoryIngestOutcome::kError;
    }
    // Single-row ON CONFLICT upsert is atomic — no advisory lock needed (unlike the
    // multi-row software replace). first_seen is preserved on conflict; last_seen is
    // the server receipt time. RETURNING carries the result (no sqlite3_changes race).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO device_inventory_store.device_ci ("
        "agent_id, content_hash, manufacturer, model, serial, system_uuid, hostname, domain, ou, "
        "bios_vendor, bios_version, bios_date, cpu_model, cpu_cores, cpu_threads, ram_bytes, "
        "disks_summary, primary_mac, macs_summary, nic_count, os_name, os_version, os_build, arch, "
        "first_seen, last_seen) VALUES ("
        "$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::bigint, $15::bigint, "
        "$16::bigint, $17, $18, $19, $20::bigint, $21, $22, $23, $24, $25::bigint, $26::bigint) "
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
        "last_seen = EXCLUDED.last_seen "
        "RETURNING agent_id",
        std::vector<std::string>{std::string(agent_id), server_hash, r.manufacturer, r.model,
                                 r.serial, r.system_uuid, r.hostname, r.domain, r.ou, r.bios_vendor,
                                 r.bios_version, r.bios_date, r.cpu_model, bigint_param(r.cpu_cores),
                                 bigint_param(r.cpu_threads), bigint_param(r.ram_bytes),
                                 r.disks_summary, r.primary_mac, r.macs_summary,
                                 bigint_param(r.nic_count), r.os_name, r.os_version, r.os_build,
                                 r.arch, std::to_string(ts), std::to_string(ts)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("DeviceInventoryStore: upsert failed for agent={}: {}", agent_id,
                     PQerrorMessage(lease.get()));
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
