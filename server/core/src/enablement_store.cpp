#include "enablement_store.hpp"

#include "leader_elector.hpp"
#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "plugin_config_parsers.hpp"

#include <yuzu/log_token.hpp>
#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <numeric>
#include <random>
#include <system_error>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace yuzu::server {

namespace fs = std::filesystem;
namespace en = enablement;

namespace {

constexpr std::chrono::milliseconds kReadTimeout{1500};
constexpr std::chrono::milliseconds kWriteTimeout{2000};
constexpr std::chrono::milliseconds kRegistrationTimeout{1500};
// One batch: acquire <= 5 s, then SET LOCAL statement_timeout bounds each of the
// three statements at 5 s, so a batch is never unbounded (about 20 s worst case).
constexpr std::chrono::milliseconds kBatchTimeout{5000};
constexpr const char* kBatchStatementTimeout = "5s";

constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr const char* kReasonOverCap = "over_cap";

constexpr const char* kMeta = "plugin_config_store.enablement_meta";
constexpr const char* kRules = "plugin_config_store.enablement_rules";
constexpr const char* kEndpoints = "plugin_config_store.enablement_endpoints";
// The SELECT lists, spelled once: each reader decodes its columns by position, and the
// construction smoke read projects the same lists, so what the runtime selects and what
// open_ proves present cannot drift apart.
constexpr const char* kRuleCols =
    "id, array_to_json(units)::text, selector, provenance, actor, audit_ref, active, "
    "(EXTRACT(EPOCH FROM updated_at) * 1000)::bigint";
constexpr const char* kMetaCols =
    "store_id, epoch, counter, rules_version, overlay_hash, job_cursor, "
    "regressed_at IS NOT NULL, regressed_reason, issuer_epoch";
constexpr const char* kEndpointCols =
    "agent_id, hostname, os, arch, agent_version, reg_boot_id, reg_seq, input_gen, "
    "resolved_version, array_to_json(desired_units)::text, desired_hash, desired_epoch, "
    "desired_counter, reported_epoch, reported_counter, reported_hash, report_ahead, "
    "pending_since IS NOT NULL, "
    "COALESCE(EXTRACT(EPOCH FROM (now() - pending_since))::bigint, -1), "
    "has_held_state, retired_at IS NOT NULL";

constexpr std::size_t kMaxAgentIdBytes = 256;
// One batch holds the enablement_meta row lock for its whole transaction; 20,000 rows were
// measured to hit the 5 s statement timeout and roll back whole, so the boundary refuses far
// less than that.
constexpr std::size_t kMaxBatchRows = 2000;

const char* col(PGresult* res, int row, int c) {
    return PQgetisnull(res, row, c) ? "" : PQgetvalue(res, row, c);
}
std::string col_str(PGresult* res, int row, int c) { return std::string(col(res, row, c)); }
std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
bool to_bool(const char* s) { return s != nullptr && (s[0] == 't' || s[0] == 'T' || s[0] == '1'); }

/// A text[] column read through array_to_json(...)::text, so an element holding any
/// byte is parsed by a real parser rather than split on a delimiter.
std::vector<std::string> json_strings(const char* json) {
    std::vector<std::string> out;
    if (json == nullptr || json[0] == '\0')
        return out;
    auto v = nlohmann::json::parse(json, nullptr, /*allow_exceptions=*/false);
    if (!v.is_array())
        return out;
    for (const auto& e : v)
        if (e.is_string())
            out.push_back(e.get<std::string>());
    return out;
}

std::string join_lines(const std::vector<std::string>& v) {
    std::string out;
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i != 0)
            out.push_back('\n');
        out += v[i];
    }
    return out;
}

std::string text_array(const std::vector<std::string>& v) {
    std::vector<std::string_view> views(v.begin(), v.end());
    return pg::to_text_array(views);
}

en::RuleRow rule_row(PGresult* r, int i) {
    en::RuleRow row;
    row.id = col_str(r, i, 0);
    row.units = json_strings(col(r, i, 1));
    row.selector = col_str(r, i, 2);
    row.provenance = col_str(r, i, 3);
    row.actor = col_str(r, i, 4);
    row.audit_ref = col_str(r, i, 5);
    row.active = to_bool(col(r, i, 6));
    row.updated_at_ms = to_i64(col(r, i, 7));
    return row;
}

bool valid_agent_id(std::string_view id) {
    if (id.empty() || id.size() > kMaxAgentIdBytes)
        return false;
    for (const unsigned char c : id)
        if (c < 0x20 || c == 0x7f)
            return false;
    return true;
}

std::string random_suffix() {
    std::random_device rd;
    std::uniform_int_distribution<int> hex(0, 15);
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < 16; ++i)
        s += kHex[hex(rd)];
    return s;
}

// -- The anchor file ----------------------------------------------------------

enum class FileState { Missing, Unreadable, Ok };
struct AnchorFile {
    FileState state{FileState::Missing};
    std::string bytes;
};

AnchorFile read_anchor_file(const fs::path& p) {
    std::error_code ec;
    const auto st = fs::status(p, ec);
    if (ec == std::errc::no_such_file_or_directory || ec == std::errc::not_a_directory ||
        (!ec && st.type() == fs::file_type::not_found))
        return {FileState::Missing, {}};
    if (ec || st.type() != fs::file_type::regular)
        return {FileState::Unreadable, {}};
    std::ifstream in(p, std::ios::binary);
    if (!in)
        return {FileState::Unreadable, {}};
    // One byte past the cap is enough to tell "too big" without reading a hostile file.
    std::string buf(en::kMaxAnchorBytes + 1, '\0');
    in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
    if (in.bad())
        return {FileState::Unreadable, {}};
    buf.resize(static_cast<std::size_t>(in.gcount()));
    return {FileState::Ok, std::move(buf)};
}

/// Owns the one OS handle (POSIX descriptor, Win32 HANDLE) of a durable write. The destructor
/// closes whatever is still owned, so an early return or a throwing log call cannot leak it;
/// close_checked() is the explicit close whose result feeds the durability verdict.
class ScopedHandle {
public:
#ifdef _WIN32
    using Raw = HANDLE;
    [[nodiscard]] static bool usable(Raw h) noexcept { return h != INVALID_HANDLE_VALUE; }
    [[nodiscard]] static bool close_raw(Raw h) noexcept { return ::CloseHandle(h) != 0; }
#else
    using Raw = int;
    [[nodiscard]] static bool usable(Raw h) noexcept { return h >= 0; }
    [[nodiscard]] static bool close_raw(Raw h) noexcept { return ::close(h) == 0; }
#endif
    explicit ScopedHandle(Raw h) noexcept : h_(h), owned_(usable(h)) {}
    ~ScopedHandle() {
        if (owned_)
            (void)close_raw(h_);
    }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    [[nodiscard]] bool valid() const noexcept { return owned_; }
    [[nodiscard]] Raw get() const noexcept { return h_; }
    /// Close now and report whether the OS accepted it. The guard owns nothing afterwards.
    [[nodiscard]] bool close_checked() noexcept {
        if (!owned_)
            return true;
        owned_ = false;
        return close_raw(h_);
    }

private:
    Raw h_;
    bool owned_;
};

/// Write `bytes` to `dest` so a crash never leaves a torn file: temp file in the
/// same directory (O_EXCL), contents fsynced BEFORE the rename, checked close,
/// atomic replace, then a best-effort directory fsync (warn only). The shape of
/// key_provider.cpp's write_file_atomic, written locally: that one is private and
/// specific to key material.
bool durable_write_file(const fs::path& dest, const std::string& bytes) {
    std::error_code ec;
    if (dest.has_parent_path())
        fs::create_directories(dest.parent_path(), ec);
    fs::path tmp = dest;
    tmp += ".tmp." + random_suffix();
#ifndef _WIN32
    ScopedHandle fd(::open(tmp.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600));
    if (!fd.valid()) {
        spdlog::error("EnablementStore: anchor temp open failed: {}", std::strerror(errno));
        return false;
    }
    const char* p = bytes.data();
    std::size_t remaining = bytes.size();
    bool ok = true;
    while (remaining > 0) {
        const ssize_t n = ::write(fd.get(), p, remaining);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            ok = false;
            break;
        }
        p += n;
        remaining -= static_cast<std::size_t>(n);
    }
#ifdef __APPLE__
    // fsync on Darwin only reaches the drive cache; F_FULLFSYNC is the durable form.
    if (ok && ::fcntl(fd.get(), F_FULLFSYNC) != 0 && ::fsync(fd.get()) != 0)
        ok = false;
#else
    if (ok && ::fsync(fd.get()) != 0)
        ok = false;
#endif
    if (!fd.close_checked())
        ok = false;
    if (!ok) {
        spdlog::error("EnablementStore: anchor temp write failed");
        fs::remove(tmp, ec);
        return false;
    }
    fs::rename(tmp, dest, ec);
    if (ec) {
        spdlog::error("EnablementStore: anchor rename failed: {}", ec.message());
        fs::remove(tmp, ec);
        return false;
    }
    // Best-effort: a lost directory entry leaves the PREVIOUS anchor (<= the store).
    const fs::path dir = dest.has_parent_path() ? dest.parent_path() : fs::path(".");
    ScopedHandle dfd(::open(dir.c_str(), O_RDONLY | O_CLOEXEC));
    if (dfd.valid() && ::fsync(dfd.get()) != 0)
        spdlog::warn("EnablementStore: anchor directory fsync failed: {}", std::strerror(errno));
    return true;
#else
    ScopedHandle h(::CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                 FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!h.valid()) {
        spdlog::error("EnablementStore: anchor temp open failed (err {})", ::GetLastError());
        return false;
    }
    bool ok = true;
    const char* p = bytes.data();
    std::size_t remaining = bytes.size();
    while (remaining > 0) {
        DWORD written = 0;
        if (!::WriteFile(h.get(), p, static_cast<DWORD>(remaining), &written, nullptr) ||
            written == 0) {
            ok = false;
            break;
        }
        p += written;
        remaining -= written;
    }
    if (ok && !::FlushFileBuffers(h.get()))
        ok = false;
    if (!h.close_checked())
        ok = false;
    if (!ok) {
        spdlog::error("EnablementStore: anchor temp write failed");
        fs::remove(tmp, ec);
        return false;
    }
    if (!::MoveFileExW(tmp.c_str(), dest.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        spdlog::error("EnablementStore: anchor rename failed (err {})", ::GetLastError());
        fs::remove(tmp, ec);
        return false;
    }
    return true;
#endif
}

} // namespace

std::string_view EnablementStore::to_string(Error err) {
    switch (err) {
    case Error::Unavailable: return "unavailable";
    case Error::NotFound: return "not_found";
    case Error::InvalidInput: return "invalid_input";
    case Error::WriteFailed: return "write_failed";
    case Error::Regressed: return "regressed";
    case Error::Fenced: return "fenced";
    }
    return "unknown";
}

EnablementStore::EnablementStore(pg::PgPool& pool, en::UnitOverlay overlay,
                                 std::vector<std::string_view> kinds)
    : pool_(pool), overlay_(std::move(overlay)), kinds_(std::move(kinds)) {
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("EnablementStore: no database connection at construction ({}) — "
                      "enablement store disabled",
                      pool_.last_error());
        return;
    }
    // Fail closed unless every column the runtime selects is present (postgres-store-playbook
    // "post-migration projection smoke read"): the singleton read proves enablement_meta is
    // seeded; the two LIMIT 0 projections touch no rows. last_report_at is the one column
    // record_report uses without selecting it.
    const auto projects = [&](const std::string& cols, const char* table, const char* tail,
                              int rows) {
        pg::PgResult r = pg::exec_params(
            lease.get(), (std::string("SELECT ") + cols + " FROM " + table + tail).c_str(),
            std::vector<std::string>{});
        return r.status() == PGRES_TUPLES_OK && PQntuples(r.get()) == rows;
    };
    if (!projects(kMetaCols, kMeta, " WHERE id = 1", 1) ||
        !projects(kRuleCols, kRules, " LIMIT 0", 0) ||
        !projects(std::string(kEndpointCols) + ", last_report_at", kEndpoints, " LIMIT 0", 0)) {
        spdlog::error("EnablementStore: the enablement schema is missing or incomplete "
                      "(plugin_config_store schema v3 not applied) — enablement store disabled");
        return;
    }
    open_ = true;
}

std::expected<std::unique_ptr<EnablementStore>, std::string>
EnablementStore::boot(pg::PgPool& pool, en::UnitOverlay overlay, std::string_view overlay_digest,
                      std::vector<std::string_view> kinds, const fs::path& anchor_path,
                      yuzu::MetricsRegistry* metrics) {
    auto store = std::make_unique<EnablementStore>(pool, std::move(overlay), std::move(kinds));
    if (!store->is_open())
        return std::unexpected("enablement store open failed");
    store->set_metrics(metrics);
    // A release that adds/removes a unit OR a requirement edge makes every endpoint row
    // stale (rules_version bump in the same statement).
    const auto synced = store->sync_overlay_hash(overlay_digest);
    if (!synced)
        return std::unexpected("enablement overlay hash could not be recorded");
    if (*synced)
        spdlog::info("EnablementStore: the unit overlay changed in this release; every endpoint "
                     "will be re-resolved");
    // A present anchor that disagrees with the store declares it regressed (issuing desired
    // state freezes); a missing one is only reported. Either way the server still boots.
    if (!store->check_continuity_at_boot(anchor_path))
        return std::unexpected(
            "enablement continuity check could not complete (store or anchor unreadable)");
    return store;
}

void EnablementStore::set_metrics(yuzu::MetricsRegistry* m) {
    metrics_ = m;
    if (!m)
        return;
    // Pre-seed every closed label set so the families exist on a healthy server and
    // absent() alerts stay meaningful (docs/observability-conventions.md).
    const auto seed = [m](const char* name, const char* help, const char* label,
                          std::initializer_list<const char*> values) {
        m->describe(name, help, "counter");
        for (const char* v : values)
            m->counter(name, {{label, v}});
    };
    seed("yuzu_server_enablement_rules_rejected_total",
         "Persisted enablement rules refused at load and quarantined, by reason", "reason",
         {"refused", "provenance", "caps"});
    seed("yuzu_server_enablement_registration_skipped_total",
         "Registrations whose enablement row was not written, by reason", "reason",
         {"invalid_identity", "retired", "stale"});
    seed("yuzu_server_enablement_write_degrade_total",
         "Best-effort enablement writes that did not land, by reason", "reason",
         {kReasonStoreNotOpen, kReasonPoolTimeout, kReasonQueryError});
    seed("yuzu_server_enablement_read_degrade_total",
         "Enablement reads that could not be served, by reason", "reason",
         {kReasonStoreNotOpen, kReasonPoolTimeout, kReasonQueryError, kReasonOverCap});
    seed("yuzu_server_enablement_anchor_write_refused_total",
         "Continuity anchor writes refused (the anchor is never lowered), by reason", "reason",
         {"regressed", "file_ahead"});
    m->describe("yuzu_server_enablement_report_ahead_total",
                "Agent reports above the store's highest (epoch, counter)", "counter");
    m->counter("yuzu_server_enablement_report_ahead_total");
    m->describe("yuzu_server_enablement_anchor_unwitnessed_total",
                "Boots where the continuity anchor was missing", "counter");
    m->counter("yuzu_server_enablement_anchor_unwitnessed_total");
    m->describe("yuzu_server_enablement_anchor_write_failed_total",
                "Continuity anchor writes that failed (crash-lag is safe: store >= file)",
                "counter");
    m->counter("yuzu_server_enablement_anchor_write_failed_total");
    m->describe("yuzu_server_enablement_unresolved_units",
                "Unit names persisted rules reference that this release does not know", "gauge");
    m->gauge("yuzu_server_enablement_unresolved_units").set(0);
    m->describe("yuzu_server_enablement_rules_quarantined",
                "Persisted enablement rules refused at the last load (a standing condition: the "
                "rule is not applied)",
                "gauge");
    m->gauge("yuzu_server_enablement_rules_quarantined").set(0);
    m->describe("yuzu_server_enablement_regressed",
                "1 while the enablement store is declared regressed (issuing desired state is "
                "frozen)",
                "gauge");
    m->gauge("yuzu_server_enablement_regressed").set(0);
    m->describe("yuzu_server_enablement_report_ahead_endpoints",
                "Distinct endpoints that reported above the store's highest (epoch, counter)",
                "gauge");
    m->gauge("yuzu_server_enablement_report_ahead_endpoints").set(0);
}

void EnablementStore::count(const char* name, const char* label_key,
                            const char* label_value) const {
    if (metrics_)
        metrics_->counter(name, {{label_key, label_value}}).increment();
}
void EnablementStore::count_write_degrade(const char* reason) const {
    count("yuzu_server_enablement_write_degrade_total", "reason", reason);
}
void EnablementStore::count_read_degrade(const char* reason) const {
    count("yuzu_server_enablement_read_degrade_total", "reason", reason);
}

pg::PgPool::Lease EnablementStore::read_lease() const {
    if (!open_) {
        count_read_degrade(kReasonStoreNotOpen);
        return {};
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        count_read_degrade(kReasonPoolTimeout);
    return lease;
}

// Not counted: a failed write acquire is reported to the caller as Unavailable, and
// write_degrade_total means "best-effort writes that did not land".
pg::PgPool::Lease EnablementStore::write_lease() const {
    if (!open_)
        return {};
    return pool_.try_acquire_for(kWriteTimeout);
}

// -- Rules --------------------------------------------------------------------

namespace {
// The bump-first prologue shared by put_rule and deactivate_rule: row-locks
// enablement_meta, so concurrent authors serialise here.
bool bump_rules_version(PGconn* c) {
    pg::PgResult r = pg::exec_params(
        c,
        (std::string("UPDATE ") + kMeta +
         " SET rules_version = rules_version + 1 WHERE id = 1 RETURNING rules_version")
            .c_str(),
        std::vector<std::string>{});
    return r.status() == PGRES_TUPLES_OK && PQntuples(r.get()) == 1;
}
} // namespace

std::expected<void, EnablementStore::Error> EnablementStore::put_rule(const RuleRow& row) {
    if (!open_)
        return std::unexpected(Error::Unavailable);
    if (!en::check_rule_caps(row.id, row.units, row.selector, row.audit_ref))
        return std::unexpected(Error::InvalidInput);
    if (!row.actor.empty() && !plugin_config::is_valid_actor(row.actor))
        return std::unexpected(Error::InvalidInput);
    const auto prov = en::parse_provenance(row.provenance);
    if (!prov)
        return std::unexpected(Error::InvalidInput);
    // Authoring: every named unit must exist today; a rule naming any unit absent from
    // this release's overlay is refused before any write.
    if (!en::make_rule(row.id, row.units, row.selector, *prov, overlay_, kinds_))
        return std::unexpected(Error::InvalidInput);

    bool ran = false;
    Error err = Error::WriteFailed;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        ran = true;
        if (!bump_rules_version(c))
            return false;
        // The cap bounds the ACTIVE count this write would produce: editing an
        // already-active rule at the cap passes; a new id or a re-activation does not.
        pg::PgResult cnt = pg::exec_params(
            c,
            (std::string("SELECT count(*) FROM ") + kRules + " WHERE active AND id <> $1").c_str(),
            std::vector<std::string>{row.id});
        if (cnt.status() != PGRES_TUPLES_OK || PQntuples(cnt.get()) != 1)
            return false;
        if (to_i64(col(cnt.get(), 0, 0)) >= static_cast<std::int64_t>(en::kMaxRules)) {
            err = Error::InvalidInput;
            return false; // rolls the bump back with it
        }
        pg::PgResult ins = pg::exec_params(
            c,
            (std::string("INSERT INTO ") + kRules +
             " (id, units, selector, provenance, actor, audit_ref, active) "
             "VALUES ($1, $2::text[], $3, $4, $5, $6, TRUE) "
             "ON CONFLICT (id) DO UPDATE SET units = EXCLUDED.units, "
             "selector = EXCLUDED.selector, provenance = EXCLUDED.provenance, "
             "actor = EXCLUDED.actor, audit_ref = EXCLUDED.audit_ref, active = TRUE, "
             "updated_at = now()")
                .c_str(),
            std::vector<std::string>{row.id, text_array(row.units), row.selector,
                                     std::string(en::to_wire(*prov)), row.actor, row.audit_ref});
        return ins.status() == PGRES_COMMAND_OK;
    });
    if (!ok)
        return std::unexpected(!ran ? Error::Unavailable : err);
    return {};
}

std::expected<void, EnablementStore::Error> EnablementStore::deactivate_rule(std::string_view id) {
    if (!open_)
        return std::unexpected(Error::Unavailable);
    if (!plugin_config::is_valid_identifier(id))
        return std::unexpected(Error::InvalidInput);
    bool ran = false;
    Error err = Error::WriteFailed;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        ran = true;
        if (!bump_rules_version(c))
            return false;
        pg::PgResult r = pg::exec_params(
            c,
            (std::string("UPDATE ") + kRules +
             " SET active = FALSE, updated_at = now() WHERE id = $1 RETURNING id")
                .c_str(),
            std::vector<std::string>{std::string(id)});
        if (r.status() != PGRES_TUPLES_OK)
            return false;
        if (PQntuples(r.get()) == 0) {
            err = Error::NotFound;
            return false;
        }
        return true;
    });
    if (!ok)
        return std::unexpected(!ran ? Error::Unavailable : err);
    return {};
}

std::expected<std::vector<en::RuleRow>, EnablementStore::Error>
EnablementStore::list_rules(bool active_only) const {
    auto lease = read_lease();
    if (!lease)
        return std::unexpected(Error::Unavailable);
    const std::string sql = std::string("SELECT ") + kRuleCols + " FROM " + kRules +
                            (active_only ? " WHERE active" : "") + " ORDER BY id";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        count_read_degrade(kReasonQueryError);
        return std::unexpected(Error::Unavailable);
    }
    std::vector<en::RuleRow> out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i)
        out.push_back(rule_row(res.get(), i));
    return out;
}

std::expected<EnablementStore::LoadedRules, EnablementStore::Error>
EnablementStore::load_rules() const {
    if (!open_) {
        count_read_degrade(kReasonStoreNotOpen);
        return std::unexpected(Error::Unavailable);
    }
    std::vector<en::RuleRow> rows;
    std::int64_t version = 0;
    bool over_cap = false;
    const bool ok = pool_.with_txn_for(kReadTimeout, [&](PGconn* c) -> bool {
        // ONE snapshot for the version and the rows: the SET must be the first
        // statement of the transaction.
        pg::PgResult iso = pg::exec_params(c, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ",
                                           std::vector<std::string>{});
        if (iso.status() != PGRES_COMMAND_OK)
            return false;
        pg::PgResult v = pg::exec_params(
            c, (std::string("SELECT rules_version FROM ") + kMeta + " WHERE id = 1").c_str(),
            std::vector<std::string>{});
        if (v.status() != PGRES_TUPLES_OK || PQntuples(v.get()) != 1)
            return false;
        version = to_i64(col(v.get(), 0, 0));
        pg::PgResult r = pg::exec_params(
            c,
            (std::string("SELECT ") + kRuleCols + " FROM " + kRules +
             " WHERE active ORDER BY id LIMIT $1::bigint")
                .c_str(),
            std::vector<std::string>{std::to_string(en::kMaxRules + 1)});
        if (r.status() != PGRES_TUPLES_OK)
            return false;
        const int n = PQntuples(r.get());
        if (static_cast<std::size_t>(n) > en::kMaxRules) {
            over_cap = true;
            return true;
        }
        for (int i = 0; i < n; ++i)
            rows.push_back(rule_row(r.get(), i));
        return true;
    });
    if (!ok) {
        count_read_degrade(kReasonQueryError);
        return std::unexpected(Error::Unavailable);
    }
    if (over_cap) {
        // Truncating would turn units back on; refuse the load instead.
        spdlog::error("EnablementStore: more than {} active rules stored — load refused",
                      en::kMaxRules);
        count_read_degrade(kReasonOverCap);
        return std::unexpected(Error::Unavailable);
    }

    LoadedRules out;
    out.rules_version = version;
    for (const auto& row : rows) {
        auto rule = en::load_rule_row(row, kinds_);
        if (rule) {
            out.rules.push_back(std::move(*rule));
            continue;
        }
        // Loader duty 1: never skip silently. The label only — make_persisted_rule's
        // text can carry RE2 output, and under `caps` the id is the very field that
        // failed validation, so it goes through the closed-set fold.
        const std::string_view label = en::to_label(rule.error());
        count("yuzu_server_enablement_rules_rejected_total", "reason",
              std::string(label).c_str());
        spdlog::warn("EnablementStore: rule {} refused at load: {}; quarantined, not applied",
                     ::yuzu::log_id_token(row.id), label);
        out.quarantined.push_back(row.id);
    }
    // Loader duty 2: unresolved names are surfaced (gauge + one warn naming a few). The
    // quarantined count is a gauge too: a refused rule is a standing condition (its unit
    // stays on), and the counter above only says it happened.
    out.unresolved_units = en::unresolved_units(out.rules, overlay_);
    if (metrics_) {
        metrics_->gauge("yuzu_server_enablement_unresolved_units")
            .set(static_cast<double>(out.unresolved_units.size()));
        metrics_->gauge("yuzu_server_enablement_rules_quarantined")
            .set(static_cast<double>(out.quarantined.size()));
    }
    if (!out.unresolved_units.empty()) {
        std::string names;
        for (std::size_t i = 0; i < out.unresolved_units.size() && i < 20; ++i) {
            if (i != 0)
                names += ",";
            names += ::yuzu::log_id_token(out.unresolved_units[i]);
        }
        spdlog::warn("EnablementStore: {} rule unit name(s) unknown to this release (switch "
                     "nothing off): {}",
                     out.unresolved_units.size(), names);
    }
    return out;
}

// -- Endpoints ----------------------------------------------------------------

void EnablementStore::upsert_on_registration(const std::string& agent_id, const Identity& id,
                                             const Registration& reg) {
    if (!open_) {
        count_write_degrade(kReasonStoreNotOpen);
        return;
    }
    if (!valid_agent_id(agent_id) ||
        !en::check_identity(id.hostname, id.os, id.arch, id.agent_version) ||
        !en::check_boot_id(reg.boot_id)) {
        count("yuzu_server_enablement_registration_skipped_total", "reason", "invalid_identity");
        spdlog::debug("EnablementStore: registration identity refused for {}",
                      ::yuzu::log_id_token(agent_id));
        return;
    }
    const std::string seq = std::to_string(reg.seq);

    auto lease = pool_.try_acquire_for(kRegistrationTimeout);
    if (!lease) {
        count_write_degrade(kReasonPoolTimeout);
        return;
    }
    // Conditioned on the registration-order guard: within one process a lower seq
    // never overwrites a higher one; a different boot id always wins. input_gen marks a
    // changed resolution INPUT, so it moves (and resolved_version clears) only when the
    // identity differs: a reconnect that re-registers the same identity leaves both alone,
    // while the order columns still advance so the guard holds.
    pg::PgResult up = pg::exec_params(
        lease.get(),
        (std::string("INSERT INTO ") + kEndpoints +
         " (agent_id, hostname, os, arch, agent_version, reg_boot_id, reg_seq, input_gen, "
         "resolved_version) VALUES ($1, $2, $3, $4, $5, $6, $7::bigint, 1, 0) "
         "ON CONFLICT (agent_id) DO UPDATE SET hostname = EXCLUDED.hostname, "
         "os = EXCLUDED.os, arch = EXCLUDED.arch, agent_version = EXCLUDED.agent_version, "
         "reg_boot_id = EXCLUDED.reg_boot_id, reg_seq = EXCLUDED.reg_seq, "
         "input_gen = CASE WHEN (enablement_endpoints.hostname, enablement_endpoints.os, "
         "enablement_endpoints.arch, enablement_endpoints.agent_version) IS DISTINCT FROM "
         "(EXCLUDED.hostname, EXCLUDED.os, EXCLUDED.arch, EXCLUDED.agent_version) "
         "THEN enablement_endpoints.input_gen + 1 ELSE enablement_endpoints.input_gen END, "
         "resolved_version = CASE WHEN (enablement_endpoints.hostname, enablement_endpoints.os, "
         "enablement_endpoints.arch, enablement_endpoints.agent_version) IS DISTINCT FROM "
         "(EXCLUDED.hostname, EXCLUDED.os, EXCLUDED.arch, EXCLUDED.agent_version) "
         "THEN 0 ELSE enablement_endpoints.resolved_version END "
         "WHERE enablement_endpoints.retired_at IS NULL AND "
         "(enablement_endpoints.reg_boot_id <> EXCLUDED.reg_boot_id OR "
         " enablement_endpoints.reg_seq < EXCLUDED.reg_seq) "
         "RETURNING agent_id")
            .c_str(),
        std::vector<std::string>{agent_id, id.hostname, id.os, id.arch, id.agent_version,
                                 reg.boot_id, seq});
    if (up.status() != PGRES_TUPLES_OK) {
        count_write_degrade(kReasonQueryError);
        return;
    }
    if (PQntuples(up.get()) == 0) {
        // Zero rows: either the row is retired or a newer registration already won.
        pg::PgResult why = pg::exec_params(
            lease.get(),
            (std::string("SELECT retired_at IS NOT NULL FROM ") + kEndpoints +
             " WHERE agent_id = $1")
                .c_str(),
            std::vector<std::string>{agent_id});
        const bool retired = why.status() == PGRES_TUPLES_OK && PQntuples(why.get()) == 1 &&
                             to_bool(col(why.get(), 0, 0));
        count("yuzu_server_enablement_registration_skipped_total", "reason",
              retired ? "retired" : "stale");
    }
}

std::expected<EnablementStore::EndpointRow, EnablementStore::Error>
EnablementStore::get_endpoint(std::string_view agent_id) const {
    if (!valid_agent_id(agent_id))
        return std::unexpected(Error::InvalidInput);
    auto lease = read_lease();
    if (!lease)
        return std::unexpected(Error::Unavailable);
    pg::PgResult r = pg::exec_params(
        lease.get(),
        (std::string("SELECT ") + kEndpointCols + " FROM " + kEndpoints + " WHERE agent_id = $1")
            .c_str(),
        std::vector<std::string>{std::string(agent_id)});
    if (r.status() != PGRES_TUPLES_OK) {
        count_read_degrade(kReasonQueryError);
        return std::unexpected(Error::Unavailable);
    }
    if (PQntuples(r.get()) == 0)
        return std::unexpected(Error::NotFound);
    PGresult* p = r.get();
    EndpointRow e;
    e.agent_id = col_str(p, 0, 0);
    e.identity = {col_str(p, 0, 1), col_str(p, 0, 2), col_str(p, 0, 3), col_str(p, 0, 4)};
    e.reg_boot_id = col_str(p, 0, 5);
    e.reg_seq = to_i64(col(p, 0, 6));
    e.input_gen = to_i64(col(p, 0, 7));
    e.resolved_version = to_i64(col(p, 0, 8));
    e.desired_units = json_strings(col(p, 0, 9));
    e.desired_hash = col_str(p, 0, 10);
    e.desired_epoch = to_i64(col(p, 0, 11));
    e.desired_counter = to_i64(col(p, 0, 12));
    e.reported_epoch = to_i64(col(p, 0, 13));
    e.reported_counter = to_i64(col(p, 0, 14));
    e.reported_hash = col_str(p, 0, 15);
    e.report_ahead = to_bool(col(p, 0, 16));
    e.pending = to_bool(col(p, 0, 17));
    if (const auto age = to_i64(col(p, 0, 18)); e.pending && age >= 0)
        e.pending_age_seconds = age;
    e.has_held_state = to_bool(col(p, 0, 19));
    e.retired = to_bool(col(p, 0, 20));
    return e;
}

std::expected<EnablementStore::ReportOutcome, EnablementStore::Error>
EnablementStore::record_report(std::string_view agent_id, std::int64_t epoch, std::int64_t counter,
                               std::string_view hash) {
    if (!open_)
        return std::unexpected(Error::Unavailable);
    if (!valid_agent_id(agent_id) || !en::check_report(epoch, counter, hash))
        return std::unexpected(Error::InvalidInput);
    auto lease = write_lease();
    if (!lease)
        return std::unexpected(Error::Unavailable);
    // See the banner: ONE conditional UPDATE, evaluated under the row lock.
    pg::PgResult r = pg::exec_params(
        lease.get(),
        (std::string("UPDATE ") + kEndpoints +
         " e SET reported_epoch = $2::bigint, reported_counter = $3::bigint, "
         "reported_hash = $4::text, last_report_at = now(), "
         "has_held_state = e.has_held_state OR $3::bigint > 0, "
         "pending_since = CASE "
         "WHEN e.desired_epoch = $2::bigint AND e.desired_counter = $3::bigint AND "
         "e.desired_hash = $4::text THEN NULL "
         "WHEN ($2::bigint, $3::bigint) < (e.desired_epoch, e.desired_counter) "
         "THEN COALESCE(e.pending_since, now()) "
         "ELSE e.pending_since END, "
         "report_ahead = (($2::bigint, $3::bigint) > "
         "(SELECT m.epoch, m.counter FROM " +
         kMeta +
         " m WHERE m.id = 1)) "
         "WHERE e.agent_id = $1 AND e.retired_at IS NULL AND "
         "(e.reported_epoch <> $2::bigint OR e.reported_counter <> $3::bigint OR "
         " e.reported_hash <> $4::text OR e.last_report_at IS NULL OR "
         " e.last_report_at < now() - interval '1 hour') "
         "RETURNING report_ahead")
            .c_str(),
        std::vector<std::string>{std::string(agent_id), std::to_string(epoch),
                                 std::to_string(counter), std::string(hash)});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(Error::WriteFailed);
    if (PQntuples(r.get()) == 1) {
        if (to_bool(col(r.get(), 0, 0))) {
            if (metrics_)
                metrics_->counter("yuzu_server_enablement_report_ahead_total").increment();
            return ReportOutcome::Ahead;
        }
        return ReportOutcome::Written;
    }
    pg::PgResult exists = pg::exec_params(
        lease.get(),
        (std::string("SELECT 1 FROM ") + kEndpoints + " WHERE agent_id = $1").c_str(),
        std::vector<std::string>{std::string(agent_id)});
    if (exists.status() != PGRES_TUPLES_OK)
        return std::unexpected(Error::WriteFailed);
    if (PQntuples(exists.get()) == 0)
        return std::unexpected(Error::NotFound);
    return ReportOutcome::Skipped;
}

// -- Desired state ------------------------------------------------------------

std::expected<EnablementStore::BatchResult, EnablementStore::Error>
EnablementStore::set_desired_batch(const BatchWrite& batch) {
    if (!open_)
        return std::unexpected(Error::Unavailable);
    // The batch holds the meta-row lock for its whole transaction, so its size is bounded here.
    if (batch.changed.size() + batch.unchanged.size() > kMaxBatchRows)
        return std::unexpected(Error::InvalidInput);
    for (const auto& d : batch.changed)
        if (!valid_agent_id(d.agent_id) || d.hash.empty() || !en::check_report(0, 0, d.hash))
            return std::unexpected(Error::InvalidInput);
    for (const auto& s : batch.unchanged)
        if (!valid_agent_id(s.agent_id) || !en::check_report(0, 0, s.hash))
            return std::unexpected(Error::InvalidInput);

    // Counters are assigned in agent_id order from the reserved range.
    std::vector<std::size_t> order(batch.changed.size());
    std::iota(order.begin(), order.end(), std::size_t{0});
    std::sort(order.begin(), order.end(), [&](std::size_t a, std::size_t b) {
        return batch.changed[a].agent_id < batch.changed[b].agent_id;
    });
    // `changed` agent_ids must be unique: a duplicate would reserve a counter it never writes.
    if (std::adjacent_find(order.begin(), order.end(), [&](std::size_t a, std::size_t b) {
            return batch.changed[a].agent_id == batch.changed[b].agent_id;
        }) != order.end())
        return std::unexpected(Error::InvalidInput);

    BatchResult result;
    bool ran = false;
    Error err = Error::WriteFailed;
    const std::int64_t n = static_cast<std::int64_t>(batch.changed.size());
    const bool ok = pool_.with_txn_for(kBatchTimeout, [&](PGconn* c) -> bool {
        ran = true;
        pg::PgResult st = pg::exec_params(
            c,
            (std::string("SET LOCAL statement_timeout = '") + kBatchStatementTimeout + "'")
                .c_str(),
            std::vector<std::string>{});
        if (st.status() != PGRES_COMMAND_OK)
            return false;

        // FIRST DATA STATEMENT: reserve the counter range, require not-regressed and
        // embed the epoch fence — one indivisible UPDATE of the single meta row. The fence's
        // leader_state subquery is read under the statement snapshot and is NOT re-run when
        // this UPDATE waited on the row lock, so the columns of the row itself carry the
        // second check (they ARE re-evaluated against the newest row version after a wait):
        // issuer_epoch rejects a leader older than one that already issued, and rules_version
        // rejects a batch planned before a rule or overlay write moved it.
        const std::string fence =
            LeaderElector::epoch_fence_sql(batch.leader_lock_name, batch.leader_epoch);
        pg::PgResult res = pg::exec_params(
            c,
            (std::string("UPDATE ") + kMeta +
             " SET counter = counter + $1::bigint, job_cursor = $2, "
             "issuer_epoch = $3::bigint "
             "WHERE id = 1 AND regressed_at IS NULL AND rules_version = $4::bigint AND "
             "issuer_epoch <= $3::bigint AND " +
             fence + " RETURNING epoch, counter")
                .c_str(),
            std::vector<std::string>{std::to_string(n), batch.cursor,
                                     std::to_string(batch.leader_epoch),
                                     std::to_string(batch.rules_version)});
        if (res.status() != PGRES_TUPLES_OK)
            return false;
        if (PQntuples(res.get()) == 0) {
            pg::PgResult why = pg::exec_params(
                c, (std::string("SELECT regressed_at IS NOT NULL FROM ") + kMeta + " WHERE id = 1")
                       .c_str(),
                std::vector<std::string>{});
            const bool regressed = why.status() == PGRES_TUPLES_OK && PQntuples(why.get()) == 1 &&
                                   to_bool(col(why.get(), 0, 0));
            err = regressed ? Error::Regressed : Error::Fenced;
            return false; // roll back: nothing of this batch commits
        }
        const std::int64_t epoch = to_i64(col(res.get(), 0, 0));
        const std::int64_t last = to_i64(col(res.get(), 0, 1));
        const std::int64_t first = last - n + 1;
        result.issued = n;

        if (n > 0) {
            std::vector<std::string> ids, gens, units, hashes, counters;
            for (std::size_t i = 0; i < order.size(); ++i) {
                const auto& d = batch.changed[order[i]];
                ids.push_back(d.agent_id);
                gens.push_back(std::to_string(d.input_gen));
                units.push_back(join_lines(d.units));
                hashes.push_back(d.hash);
                counters.push_back(std::to_string(first + static_cast<std::int64_t>(i)));
            }
            pg::PgResult w = pg::exec_params(
                c,
                (std::string("UPDATE ") + kEndpoints +
                 " e SET desired_units = string_to_array(v.units, E'\\n'), "
                 "desired_hash = v.hash, desired_epoch = $6::bigint, "
                 "desired_counter = v.counter, "
                 "pending_since = COALESCE(e.pending_since, now()), "
                 "resolved_version = $7::bigint "
                 "FROM unnest($1::text[], $2::bigint[], $3::text[], $4::text[], $5::bigint[]) "
                 "AS v(agent_id, input_gen, units, hash, counter) "
                 "WHERE e.agent_id = v.agent_id AND e.retired_at IS NULL "
                 "AND e.input_gen = v.input_gen")
                    .c_str(),
                std::vector<std::string>{text_array(ids), text_array(gens), text_array(units),
                                         text_array(hashes), text_array(counters),
                                         std::to_string(epoch),
                                         std::to_string(batch.rules_version)});
            if (w.status() != PGRES_COMMAND_OK)
                return false;
            result.written = to_i64(PQcmdTuples(w.get()));
        }
        if (!batch.unchanged.empty()) {
            std::vector<std::string> ids, gens, hashes;
            for (const auto& s : batch.unchanged) {
                ids.push_back(s.agent_id);
                gens.push_back(std::to_string(s.input_gen));
                hashes.push_back(s.hash);
            }
            // A stamp says "this row's desired state is current": it holds only while the row
            // still carries the hash the planner observed, so a row rewritten in between is
            // not stamped and is re-resolved next pass.
            pg::PgResult s = pg::exec_params(
                c,
                (std::string("UPDATE ") + kEndpoints +
                 " e SET resolved_version = $3::bigint "
                 "FROM unnest($1::text[], $2::bigint[], $4::text[]) "
                 "AS v(agent_id, input_gen, hash) "
                 "WHERE e.agent_id = v.agent_id AND e.retired_at IS NULL "
                 "AND e.input_gen = v.input_gen AND e.desired_hash = v.hash")
                    .c_str(),
                std::vector<std::string>{text_array(ids), text_array(gens),
                                         std::to_string(batch.rules_version),
                                         text_array(hashes)});
            if (s.status() != PGRES_COMMAND_OK)
                return false;
            result.stamped = to_i64(PQcmdTuples(s.get()));
        }
        return true;
    });
    if (!ok)
        return std::unexpected(!ran ? Error::Unavailable : err);
    return result;
}

// -- Meta, continuity, regression ---------------------------------------------

std::expected<EnablementStore::MetaRow, EnablementStore::Error> EnablementStore::get_meta() const {
    auto lease = read_lease();
    if (!lease)
        return std::unexpected(Error::Unavailable);
    pg::PgResult r = pg::exec_params(
        lease.get(),
        (std::string("SELECT ") + kMetaCols + " FROM " + kMeta + " WHERE id = 1").c_str(),
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1) {
        count_read_degrade(kReasonQueryError);
        return std::unexpected(Error::Unavailable);
    }
    PGresult* p = r.get();
    MetaRow m;
    m.store_id = col_str(p, 0, 0);
    m.epoch = to_i64(col(p, 0, 1));
    m.counter = to_i64(col(p, 0, 2));
    m.rules_version = to_i64(col(p, 0, 3));
    m.overlay_hash = col_str(p, 0, 4);
    m.job_cursor = col_str(p, 0, 5);
    m.regressed = to_bool(col(p, 0, 6));
    m.regressed_reason = col_str(p, 0, 7);
    m.issuer_epoch = to_i64(col(p, 0, 8));
    return m;
}

std::expected<bool, EnablementStore::Error>
EnablementStore::sync_overlay_hash(std::string_view hash) {
    auto lease = write_lease();
    if (!lease)
        return std::unexpected(Error::Unavailable);
    // One conditional statement: atomic across replicas booting together.
    pg::PgResult r = pg::exec_params(
        lease.get(),
        (std::string("UPDATE ") + kMeta +
         " SET overlay_hash = $1, rules_version = rules_version + 1 "
         "WHERE id = 1 AND overlay_hash <> $1 RETURNING rules_version")
            .c_str(),
        std::vector<std::string>{std::string(hash)});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(Error::WriteFailed);
    return PQntuples(r.get()) == 1;
}

void EnablementStore::apply_regression_cache(bool regressed, std::string reason,
                                             std::int64_t since_ms) {
    regressed_.store(regressed, std::memory_order_release);
    regressed_since_ms_.store(since_ms, std::memory_order_relaxed);
    {
        std::lock_guard lock(reason_mu_);
        regressed_reason_ = std::move(reason);
    }
    if (metrics_)
        metrics_->gauge("yuzu_server_enablement_regressed").set(regressed ? 1.0 : 0.0);
}

// Idempotent: only the first declaration records its time and reason.
std::expected<void, EnablementStore::Error> EnablementStore::set_regressed(std::string_view reason) {
    auto lease = write_lease();
    if (!lease)
        return std::unexpected(Error::Unavailable);
    pg::PgResult r = pg::exec_params(
        lease.get(),
        (std::string("UPDATE ") + kMeta +
         " SET regressed_at = now(), regressed_reason = $1 WHERE id = 1 AND regressed_at IS NULL")
            .c_str(),
        std::vector<std::string>{::yuzu::log_token(reason.substr(0, 64))});
    if (r.status() != PGRES_COMMAND_OK)
        return std::unexpected(Error::WriteFailed);
    lease.reset();
    refresh_regression();
    return {};
}

void EnablementStore::refresh_regression() {
    if (!open_)
        return;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        count_read_degrade(kReasonPoolTimeout);
        return; // keep the last known picture
    }
    pg::PgResult r = pg::exec_params(
        lease.get(),
        (std::string("SELECT regressed_at IS NOT NULL, regressed_reason, "
                     "COALESCE((EXTRACT(EPOCH FROM regressed_at) * 1000)::bigint, 0), "
                     "(SELECT count(*) FROM ") +
         kEndpoints + " WHERE report_ahead) FROM " + kMeta + " WHERE id = 1")
            .c_str(),
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1) {
        count_read_degrade(kReasonQueryError);
        return;
    }
    const bool regressed = to_bool(col(r.get(), 0, 0));
    if (regressed && !regressed_.load(std::memory_order_acquire))
        spdlog::error("EnablementStore: store is declared REGRESSED ({}) — issuing desired "
                      "state is frozen",
                      ::yuzu::log_token(col(r.get(), 0, 1)));
    apply_regression_cache(regressed, col_str(r.get(), 0, 1), to_i64(col(r.get(), 0, 2)));
    const auto ahead = to_i64(col(r.get(), 0, 3));
    report_ahead_endpoints_.store(ahead, std::memory_order_relaxed);
    if (metrics_)
        metrics_->gauge("yuzu_server_enablement_report_ahead_endpoints")
            .set(static_cast<double>(ahead));
}

EnablementStore::RegressionState EnablementStore::regression() const {
    RegressionState s;
    s.regressed = regressed_.load(std::memory_order_acquire);
    s.since_ms = regressed_since_ms_.load(std::memory_order_relaxed);
    s.anchor_unwitnessed = anchor_unwitnessed_.load(std::memory_order_relaxed);
    s.report_ahead_endpoints = report_ahead_endpoints_.load(std::memory_order_relaxed);
    std::lock_guard lock(reason_mu_);
    s.reason = regressed_reason_;
    return s;
}

void EnablementStore::set_regression_state_for_test(const RegressionState& state) {
    apply_regression_cache(state.regressed, state.reason, state.since_ms);
    anchor_unwitnessed_.store(state.anchor_unwitnessed, std::memory_order_relaxed);
    report_ahead_endpoints_.store(state.report_ahead_endpoints, std::memory_order_relaxed);
}

std::expected<en::Continuity, EnablementStore::Error>
EnablementStore::check_continuity_at_boot(const fs::path& anchor_path) {
    const AnchorFile file = read_anchor_file(anchor_path);
    if (file.state == FileState::Unreadable) {
        // A file that EXISTS but cannot be read (permissions, descriptors, a directory in its
        // place) is an I/O fault, not evidence about the store. A persisted declaration has no
        // way back in the product, so nothing is declared: the server refuses to start, the
        // operator fixes the file or its permissions, and the next boot is clean.
        spdlog::error("EnablementStore: the continuity anchor exists but cannot be read — fix "
                      "the file or its permissions and restart; nothing was declared");
        return std::unexpected(Error::Unavailable);
    }
    auto meta = get_meta();
    if (!meta)
        return std::unexpected(meta.error());
    const en::Anchor store{meta->store_id, meta->epoch, meta->counter};

    en::ContinuityVerdict verdict;
    if (file.state == FileState::Missing) {
        verdict = en::classify_continuity(std::nullopt, store);
    } else if (auto parsed = en::parse_anchor(file.bytes)) {
        verdict = en::classify_continuity(parsed, store);
    } else {
        // Readable bytes that are not an anchor (hand-edited, truncated, over the cap).
        verdict = {en::Continuity::Regressed, "anchor_unparseable"};
    }

    switch (verdict.kind) {
    case en::Continuity::Regressed:
        spdlog::error("EnablementStore: continuity anchor disagrees with the store ({}) — "
                      "declaring the enablement store regressed",
                      verdict.reason);
        if (auto r = set_regressed(verdict.reason); !r)
            return std::unexpected(r.error());
        break;
    case en::Continuity::Unwitnessed:
        spdlog::warn("EnablementStore: no continuity anchor at boot — this restore or first "
                     "boot is unwitnessed; the anchor is written from the store's current "
                     "highest");
        if (metrics_)
            metrics_->counter("yuzu_server_enablement_anchor_unwitnessed_total").increment();
        anchor_unwitnessed_.store(true, std::memory_order_relaxed);
        // The outcome is logged so the boot log tells a first boot from a data directory
        // that cannot be written (every boot of which would read as unwitnessed).
        if (write_anchor(anchor_path) == AnchorWrite::Failed)
            spdlog::error("EnablementStore: the continuity anchor could not be written at boot — "
                          "this host stays unwitnessed until its data directory is writable");
        break;
    case en::Continuity::Ok: break;
    }
    refresh_regression();
    return verdict.kind;
}

EnablementStore::AnchorWrite EnablementStore::write_anchor(const fs::path& anchor_path) {
    // Two in-process callers must not interleave their read-compare-replace. The section is
    // bounded (one leased DB read plus local file I/O), so no unbounded wait is introduced.
    static std::mutex write_mu;
    const std::lock_guard<std::mutex> serialise(write_mu);

    const auto count_failed = [this] {
        if (metrics_)
            metrics_->counter("yuzu_server_enablement_anchor_write_failed_total").increment();
        return AnchorWrite::Failed;
    };
    const auto refuse = [this](const char* reason) {
        if (metrics_)
            metrics_
                ->counter("yuzu_server_enablement_anchor_write_refused_total", {{"reason", reason}})
                .increment();
        return AnchorWrite::Refused;
    };

    // The FILE is read BEFORE the meta row: a file read first can only reflect a store state
    // older than the snapshot taken after it, so a concurrent advance can never read as a
    // file ahead of the store (a false, permanent regression).
    const AnchorFile file = read_anchor_file(anchor_path);
    if (file.state == FileState::Unreadable) {
        // An I/O fault is not evidence about the store (see check_continuity_at_boot): the
        // write fails and is counted; nothing is declared.
        spdlog::error("EnablementStore: the continuity anchor exists but cannot be read — the "
                      "anchor was not written");
        return count_failed();
    }
    // Authoritative: another instance's committed declaration is seen HERE, not from
    // a periodically refreshed cache.
    auto meta = get_meta();
    if (!meta)
        return AnchorWrite::Failed;
    if (meta->regressed) {
        spdlog::debug("EnablementStore: anchor write refused: the store is regressed");
        return refuse("regressed");
    }
    const en::Anchor store{meta->store_id, meta->epoch, meta->counter};

    // The file-local monotonic guard: a store that fell behind THIS host's file while
    // the server was running (a dump restored under a live server) is declared, never
    // silently lowered.
    if (file.state == FileState::Ok) {
        const auto parsed = en::parse_anchor(file.bytes);
        const en::ContinuityVerdict v =
            parsed ? en::classify_continuity(parsed, store)
                   : en::ContinuityVerdict{en::Continuity::Regressed, "anchor_unparseable"};
        if (v.kind == en::Continuity::Regressed) {
            spdlog::error("EnablementStore: the anchor file is ahead of or foreign to the store "
                          "({}) — declaring regression instead of lowering it",
                          v.reason);
            (void)set_regressed(v.reason);
            return refuse("file_ahead");
        }
        if (parsed && *parsed == store)
            return AnchorWrite::Written; // already current: no rewrite
    }
    if (!durable_write_file(anchor_path, en::render_anchor(store)))
        return count_failed();
    return AnchorWrite::Written;
}

} // namespace yuzu::server
