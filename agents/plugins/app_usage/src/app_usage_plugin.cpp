/**
 * app_usage_plugin.cpp — read-only Forensics-gated view over TAR's
 * usage_daily / usage_daily_user / usage_live tables inside tar.db.
 *
 * Actions:
 *   "summary"    — one `usage|` row per exe_key over a window (params:
 *                  days [1-365, default 30], top [1-500, default 25], by
 *                  [run_time|run_count, default run_time]), preceded by one
 *                  `meta|` row carrying the fold's health counters.
 *   "last_used"  — per-exe_key last/first-seen (within TAR's retained usage
 *                  window) plus a 30-day run_count/total_seconds window.
 *                  Optional `exe=<key>` param narrows to one executable
 *                  (normalised the same way tar_usage.hpp normalises
 *                  exe_key on write); the unfiltered form is capped at
 *                  kMaxLastUsedRows exe_keys (app_usage_parsers.hpp) and
 *                  reports a trailing `constrained|last_used_truncated|<cap>`
 *                  row if the cap was reached. Refuses to run at all
 *                  (`constrained|usage_feeder_disabled`/`usage_feeder_errored`)
 *                  when TAR's own fold is not actually advancing — see
 *                  do_last_used_on's usage_feeder_enabled check.
 *   "foreground" — always CONSTRAINED, rc 0: per-session focus-time
 *                  attribution is not captured by this source (see
 *                  app_usage_parsers.hpp and app_usage.yaml).
 *
 * SEAM DECISION (see this package's spec): CommandContext (the type
 * execute() receives) has no get_config — only PluginContext (init()'s
 * argument) does, and most tests drive execute() directly without ever
 * calling init() (test_app_usage_local_dispatcher.cpp's real-plugin case is
 * the exception — it does call init() through StandalonePluginContext). So
 * init() caches `agent.data_dir` (same platform fallback as tar_plugin.cpp's
 * init() applies when it is empty), and every execute() call re-resolves
 * `<dir>/tar.db` through resolve_db_dir(), which reapplies the identical
 * fallback when the cached value is still empty — i.e. when a caller drives
 * execute() directly without ever calling init(), this plugin still finds
 * the platform-default tar.db, not a null path.
 *
 * ALL SQL lives in app_usage_parsers.hpp, which takes an already-open
 * `sqlite3*` — this file only opens the connection (read-only, WAL-aware —
 * tar.db is always WAL, tar_db.cpp) and formats the typed outcome into the
 * CC-07 result status + exit code contract.
 *
 * Reads ONLY usage_daily, usage_daily_user (COUNT(DISTINCT user) only),
 * `SELECT COUNT(*) FROM usage_live` (count only — never a pid/exe column),
 * and the named tar_config keys. NEVER TAR's raw process-event table or
 * any command-line column — see app_usage_parsers.hpp's file header and
 * the grep-based test that enforces this.
 */

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <optional>
#include <sqlite3.h>
#include <string>
#include <string_view>

#include "app_usage_parsers.hpp"

namespace {

namespace fs = std::filesystem;

// Same platform fallback tar_plugin.cpp's init() applies when
// `agent.data_dir` is empty (tar_plugin.cpp:565-580) — kept in sync by
// inspection, not by shared code, since app_usage cannot depend on tar's
// internal sources.
std::string platform_default_data_dir() {
#ifdef _WIN32
    return "C:\\ProgramData\\yuzu\\agent";
#else
    return "/var/lib/yuzu/agent";
#endif
}

// Non-copyable RAII owner for the connection handle, mirroring
// app_usage_parsers.hpp's detail::Stmt — guarantees sqlite3_close() runs on
// every path out of a do_summary_on()/do_last_used_on() call, including
// exception unwinding between open and the (formerly bare) close two
// statements later.
class DbHandle {
public:
    DbHandle() noexcept = default;
    explicit DbHandle(sqlite3* db) noexcept : db_(db) {}
    ~DbHandle() {
        if (db_)
            sqlite3_close(db_);
    }
    DbHandle(const DbHandle&) = delete;
    DbHandle& operator=(const DbHandle&) = delete;
    DbHandle(DbHandle&& other) noexcept : db_(other.db_) { other.db_ = nullptr; }
    DbHandle& operator=(DbHandle&& other) noexcept {
        if (this != &other) {
            if (db_)
                sqlite3_close(db_);
            db_ = other.db_;
            other.db_ = nullptr;
        }
        return *this;
    }
    [[nodiscard]] sqlite3* get() const noexcept { return db_; }
    [[nodiscard]] explicit operator bool() const noexcept { return db_ != nullptr; }

private:
    sqlite3* db_{nullptr};
};

// Opens tar.db read-only (SQLITE_OPEN_READONLY|SQLITE_OPEN_NOMUTEX per this
// package's spec), sets a 2s busy timeout, and forces query_only — tar.db
// is always WAL (tar_db.cpp:430); same process/user, so the -shm sidecar is
// usable read-only. Returns an empty DbHandle and fills `out_err` on
// failure; the returned handle owns the connection on success.
//
// Round-3 review finding (HIGH): sqlite3_open_v2 alone never proves tar.db's
// integrity. TarDatabase::open (tar_db.cpp) runs a full PRAGMA
// integrity_check and quarantines/fails closed on a corrupt file, but that
// guarantee is scoped to TAR's own long-lived connection at ITS open time —
// this plugin opens a fresh connection per dispatch and would otherwise
// silently serve/sync rows from a file TAR itself has already rejected.
// yuzu::app_usage::quick_check_ok (app_usage_parsers.hpp) trades the full
// cross-index consistency pass for speed (appropriate here — this runs on
// every dispatch, not once at process start) and stops at the first error
// rather than enumerating every one; on a genuinely large/corrupt tar.db
// this still costs a scan, same as any integrity check.
//
// `out_token` is set to the distinct wire token the caller should emit --
// "tar_db_unavailable" (missing file, permission denied, lock contention) or
// "tar_db_corrupt" (opened fine, failed the integrity gate) -- governance
// Gate 6 sre finding: both used to collapse into the same token, leaving an
// operator unable to distinguish "benign, often transient" from "possible
// disk corruption, worth investigating" without parsing free-text detail.
DbHandle open_readonly(const fs::path& path, std::string& out_err, std::string_view& out_token) {
    out_token = "tar_db_unavailable";
    sqlite3* raw = nullptr;
    const int rc = sqlite3_open_v2(path.string().c_str(), &raw,
                                   SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nullptr);
    // Round-3 review Blocker (policy floor, round 2): owns `raw` from this
    // point forward, even when `rc != SQLITE_OK` -- sqlite3_open_v2 can
    // still allocate a handle on failure precisely so sqlite3_errmsg() has
    // something to report, and the two branches below used to close it by
    // hand instead of going through this file's own DbHandle RAII owner.
    // Every path out of this function, including both failure returns, is
    // now RAII-safe; no manual sqlite3_close() left in this function.
    DbHandle db{raw};
    if (rc != SQLITE_OK) {
        out_err = db ? sqlite3_errmsg(db.get()) : "sqlite3_open_v2 failed";
        return DbHandle{};
    }
    sqlite3_busy_timeout(db.get(), 2000);
    sqlite3_exec(db.get(), "PRAGMA query_only=1", nullptr, nullptr, nullptr);
    if (!yuzu::app_usage::quick_check_ok(db.get())) {
        out_err = "tar.db failed integrity quick_check";
        out_token = "tar_db_corrupt";
        return DbHandle{};
    }
    return db;
}

// Aligns a unix timestamp down to the start of its UTC day — usage_daily's
// day_ts column is day-aligned (tar_usage.hpp, P21).
constexpr int64_t kSecondsPerDay = 86400;
int64_t align_to_day(int64_t ts) {
    return ts - (ts % kSecondsPerDay);
}

// Distinguishes "the key is genuinely absent" (a well-formed query that
// simply returned zero rows) from "the query itself failed to prepare/step"
// (busy/locked/I-O error) — the two are NOT interchangeable: absence falls
// through to TAR's own default (source_state_from_config(nullopt) ==
// Enabled), while a read failure must map to SourceState::Errored and never
// silently to Enabled (this plugin's routed concern, `.claude/routed-concerns.md`
// row "`app_usage` agent plugin..." clause 3 — a `tar_config` read failure is
// fail-closed, the opposite of fail-open).
enum class ConfigReadOutcome { kPresent, kMissing, kReadError };

struct ConfigReadResult {
    ConfigReadOutcome outcome{ConfigReadOutcome::kMissing};
    std::string value; // meaningful only when outcome == kPresent
};

ConfigReadResult get_tar_config(sqlite3* db, std::string_view key) {
    static constexpr std::string_view kSql = "SELECT value FROM tar_config WHERE key = ?";
    // RAII via app_usage_parsers.hpp's detail::Stmt (governance Gate 7,
    // #app_usage-policy-floor) — a hand-rolled sqlite3_stmt* with a manual
    // sqlite3_finalize() here was leak-free by inspection (single path,
    // no early return between prepare and finalize) but was still a policy
    // floor: new C++ manual cleanup with no documented-impossible exception,
    // trivially wrappable since this file already transitively includes the
    // wrapper. Mirrors read_meta()'s get_config lambda in app_usage_parsers.hpp.
    yuzu::app_usage::detail::Stmt stmt{db, kSql};
    if (!stmt)
        return {ConfigReadOutcome::kReadError, {}};
    sqlite3_bind_text(stmt.get(), 1, key.data(), static_cast<int>(key.size()), SQLITE_TRANSIENT);
    ConfigReadResult out;
    const int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        out.outcome = ConfigReadOutcome::kPresent;
        out.value = text ? std::string{text} : std::string{};
    } else if (rc == SQLITE_DONE) {
        out.outcome = ConfigReadOutcome::kMissing;
    } else {
        out.outcome = ConfigReadOutcome::kReadError;
    }
    return out;
}

// Resolves the tri-state for a named tar_config `<x>_enabled` key (shared by
// the `usage_enabled` checks in both do_summary_on/do_last_used_on, and the
// `usage_feeder_enabled` check added to do_last_used_on below) — a genuine
// read failure is mapped to SourceState::Errored HERE, directly, before
// source_state_from_config ever sees it, so its nullopt->Enabled default
// (reserved for a genuinely absent key) can never be reached by a failed
// prepare/step.
struct UsageSourceCheck {
    yuzu::app_usage::SourceState state;
    std::string reason; // populated only when state == Errored
};

// `missing_means_enabled` (default true) controls what an ABSENT key maps
// to -- true reuses source_state_from_config's nullopt->Enabled default,
// correct for `usage_enabled` (TAR's own genuine default when that key has
// never been written). Round-3 review should-fix: `usage_feeder_enabled`
// has no such "safe missing" semantics -- TAR's fold (tar_usage.cpp) writes
// this key unconditionally before it ever writes a usage_daily row, so a
// genuinely absent key on a reachable host is itself an anomaly (a
// hand-edited/restored tar.db, or a tar_config write fault) rather than
// "the fold simply hasn't run yet". Passing false at that call site treats
// a missing key the same as an explicit "false", keeping the round-1 fix's
// own stated "false/missing -> constrained" contract for the feeder key
// specifically, without changing source_state_from_config's default for
// every other caller.
UsageSourceCheck check_source_state(sqlite3* db, std::string_view config_key,
                                    bool missing_means_enabled = true) {
    const auto cfg = get_tar_config(db, config_key);
    if (cfg.outcome == ConfigReadOutcome::kReadError)
        return {yuzu::app_usage::SourceState::Errored, std::string{config_key} + "=<read_error>"};

    if (cfg.outcome == ConfigReadOutcome::kMissing && !missing_means_enabled)
        return {yuzu::app_usage::SourceState::Disabled, {}};

    const std::optional<std::string_view> stored =
        cfg.outcome == ConfigReadOutcome::kPresent ? std::optional<std::string_view>(cfg.value)
                                                    : std::nullopt;
    const auto state = yuzu::app_usage::source_state_from_config(stored);
    UsageSourceCheck check{state, {}};
    if (state == yuzu::app_usage::SourceState::Errored)
        check.reason = std::string{config_key} + "=" + yuzu::util::safe_output_field(cfg.value);
    return check;
}

// Writes the CONSTRAINED response for a gated (Disabled/Errored)
// check_source_state result and returns true; returns false without writing
// anything when state == Enabled, so the caller proceeds. Shared by all
// three check_source_state call sites (do_summary_on's usage_enabled check,
// do_last_used_on's usage_enabled check, do_last_used_on's usage_feeder_enabled
// check) so the three can never drift out of the same Disabled/Errored shape
// by hand-editing one and not the others — exactly the class of bug the
// stale-comment fix earlier in this same round caught. Exactly one token per
// path (#560 tri-state, adjudication P3 respec §3) — a single failure mode,
// so no ConstraintAccumulator here (that composes genuinely multi-source
// failures; see read_meta). Errored covers both a corrupted stored value AND
// a failed tar_config prepare/step (check_source_state maps the latter to
// Errored directly, fail-closed — never silently Enabled).
bool report_if_gated(yuzu::CommandContext& ctx, const UsageSourceCheck& check,
                     std::string_view disabled_reason, std::string_view disabled_token,
                     std::string_view errored_token) {
    if (check.state == yuzu::app_usage::SourceState::Disabled) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              disabled_reason);
        ctx.write_output("constrained|" + std::string{disabled_token});
        return true;
    }
    if (check.state == yuzu::app_usage::SourceState::Errored) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              check.reason);
        ctx.write_output("constrained|" + std::string{errored_token} + "|" + check.reason);
        return true;
    }
    return false;
}

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "summary",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "tar.db usage_daily (derived from TAR process/procfs)",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "tar.db usage_daily (derived from TAR process/endpoint_security or sysctl poll)",
         "inherits the process source's names-only constraint; ES entitlement absent -> poll "
         "granularity"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "tar.db usage_daily (derived from TAR process/etw)", nullptr},
    },
    {
        /* .action      = */ "last_used",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "tar.db usage_daily (derived from TAR process/procfs)",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "tar.db usage_daily (derived from TAR process/endpoint_security or sysctl poll)",
         "inherits the process source's names-only constraint; ES entitlement absent -> poll "
         "granularity"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "tar.db usage_daily (derived from TAR process/etw)", nullptr},
    },
    {
        /* .action      = */ "foreground",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "not captured",
         "foreground/focus time and per-session attribution are not captured; promoted by the "
         "user-context-bridge roadmap without a schema change"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "not captured",
         "foreground/focus time and per-session attribution are not captured; promoted by the "
         "user-context-bridge roadmap without a schema change"},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "not captured",
         "foreground/focus time and per-session attribution are not captured; promoted by the "
         "user-context-bridge roadmap without a schema change"},
    },
};

} // namespace

class AppUsagePlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "app_usage"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Read-only machine-scope app usage inventory derived from TAR's usage fold "
               "(no pid, command line, or user names in output)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"summary", "last_used", "foreground", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        const auto configured = ctx.get_config("agent.data_dir");
        data_dir_ = configured.empty() ? platform_default_data_dir() : std::string{configured};
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "summary")
            return do_summary(ctx, params);
        if (action == "last_used")
            return do_last_used(ctx, params);
        if (action == "foreground")
            return do_foreground(ctx);

        ctx.write_output(std::string{"unknown action: "} + std::string{action});
        return 1;
    }

private:
    // No env-var/param override of the db path — an operator-supplied path
    // would be an arbitrary-file read (this package's spec, "boundaries").
    // When init() never ran (most dispatcher tests drive execute()
    // directly — see this file's header), data_dir_ is still empty here,
    // so the platform fallback is reapplied on every call.
    fs::path resolve_db_path() const {
        const std::string dir = data_dir_.empty() ? platform_default_data_dir() : data_dir_;
        return fs::path{dir} / "tar.db";
    }

    int do_summary(yuzu::CommandContext& ctx, yuzu::Params& params) {
        const auto path = resolve_db_path();
        std::string err;
        std::string_view token;
        DbHandle db = open_readonly(path, err, token);
        if (!db) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL, err);
            ctx.write_output("constrained|" + std::string{token} + "|" + path.string() + "|" + err);
            return 1;
        }

        return do_summary_on(ctx, params, db.get());
    }

    int do_summary_on(yuzu::CommandContext& ctx, yuzu::Params& params, sqlite3* db) {
        const auto check = check_source_state(db, yuzu::app_usage::kConfigUsageEnabled);
        if (report_if_gated(ctx, check, "usage_enabled=false", "usage_source_disabled",
                            "usage_source_errored"))
            return 0;
        // Governance Gate 7 round 2 (UP-1): usage_daily_table_exists now
        // distinguishes a genuine read failure (busy/corrupt) from the
        // legitimate "no such table" case -- a failure must not be
        // misreported as "older TAR schema" (same fail-closed shape as the
        // tar_config Errored branch just above).
        const auto table_exists = yuzu::app_usage::usage_daily_table_exists(db);
        if (!table_exists) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL, table_exists.error().detail);
            ctx.write_output("unavailable|query_failed|" + table_exists.error().detail);
            return 1;
        }
        if (!*table_exists) {
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "usage_daily table absent (older TAR schema)");
            ctx.write_output("constrained|usage_schema_missing");
            return 0;
        }

        const auto window = yuzu::app_usage::parse_window_params(
            params.get("days"), params.get("top"), params.get("by"));
        if (window.by == yuzu::app_usage::WindowParams::By::unmodelled) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "unrecognised 'by' param");
            ctx.write_output("error|bad_param|by");
            return 1;
        }

        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        const int64_t since_day_ts = align_to_day(now) - static_cast<int64_t>(window.days - 1) * kSecondsPerDay;

        const auto meta = yuzu::app_usage::read_meta(db, since_day_ts);
        if (!meta) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL, meta.error().detail);
            ctx.write_output("unavailable|query_failed|" + meta.error().detail);
            return 1;
        }
        const auto summary = yuzu::app_usage::run_summary(db, window, since_day_ts);
        if (!summary) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL, summary.error().detail);
            ctx.write_output("unavailable|query_failed|" + summary.error().detail);
            return 1;
        }

        ctx.write_output(yuzu::app_usage::format_meta_line(window, *meta));
        for (const auto& row : summary->rows)
            ctx.write_output(yuzu::app_usage::format_usage_row(row));

        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
        return 0;
    }

    int do_last_used(yuzu::CommandContext& ctx, yuzu::Params& params) {
        const auto path = resolve_db_path();
        std::string err;
        std::string_view token;
        DbHandle db = open_readonly(path, err, token);
        if (!db) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL, err);
            ctx.write_output("constrained|" + std::string{token} + "|" + path.string() + "|" + err);
            return 1;
        }

        return do_last_used_on(ctx, params, db.get());
    }

    int do_last_used_on(yuzu::CommandContext& ctx, yuzu::Params& params, sqlite3* db) {
        const auto check = check_source_state(db, yuzu::app_usage::kConfigUsageEnabled);
        if (report_if_gated(ctx, check, "usage_enabled=false", "usage_source_disabled",
                            "usage_source_errored"))
            return 0;
        // Round-3 review blocker: `usage_feeder_enabled` gates the FOLD's
        // freshness, not merely the table's presence. TAR's own aggregator
        // (tar_usage.cpp) computes usage_feeder_enabled = (usage_on &&
        // process_on) and early-returns from the fold when either is off —
        // i.e. TAR already knows and records "unable to observe" for this
        // state, and this action was the only one that threw that signal
        // away (do_summary_on surfaces it via format_meta_line's
        // feeder_enabled field; this action has no meta row). Left
        // unchecked, a feeder-dead source republishes a daily-changing slice
        // of a FROZEN 30-day window (kLastUsedSqlAll) as OK/FULL forever,
        // defeating the sync layer's hash-skip and eventually driving a real
        // replace_agent_last_used wipe-to-empty
        // (server/core/src/app_usage_ingestion.cpp) once the window drains
        // past the last real data.
        const auto feeder_check = check_source_state(db, yuzu::app_usage::kConfigFeederEnabled,
                                                     /*missing_means_enabled=*/false);
        if (report_if_gated(ctx, feeder_check, "usage_feeder_enabled=false",
                            "usage_feeder_disabled", "usage_feeder_errored"))
            return 0;
        // Governance Gate 7 round 2 (UP-1): usage_daily_table_exists now
        // distinguishes a genuine read failure (busy/corrupt) from the
        // legitimate "no such table" case -- a failure must not be
        // misreported as "older TAR schema" (same fail-closed shape as the
        // tar_config Errored branch just above).
        const auto table_exists = yuzu::app_usage::usage_daily_table_exists(db);
        if (!table_exists) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL, table_exists.error().detail);
            ctx.write_output("unavailable|query_failed|" + table_exists.error().detail);
            return 1;
        }
        if (!*table_exists) {
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "usage_daily table absent (older TAR schema)");
            ctx.write_output("constrained|usage_schema_missing");
            return 0;
        }

        std::optional<std::string_view> exe;
        if (params.has("exe")) {
            const auto raw_exe = params.get("exe");
            // Governance Gate 7 round 2 (consistency-auditor F1): a present
            // but blank `exe` (exe= or whitespace-only) is treated as
            // OMITTED, matching this action's own documented contract
            // (content/definitions/app_usage.yaml: "omit to return every
            // executable"). Without this, an empty string normalises via
            // normalise_exe_key to the "(unknown)" sentinel and filters on
            // that literal key -- silently returning near-zero rows instead
            // of everything, which a caller could misread as "no data"
            // rather than "I passed an empty filter".
            const bool blank = std::all_of(raw_exe.begin(), raw_exe.end(),
                                           [](unsigned char c) { return std::isspace(c) != 0; });
            if (!blank)
                exe = raw_exe;
        }

        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        const int64_t since_30d_ts = align_to_day(now) - 29 * kSecondsPerDay;

        auto rows = yuzu::app_usage::run_last_used(db, exe, since_30d_ts);
        if (!rows) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL, rows.error().detail);
            ctx.write_output("unavailable|query_failed|" + rows.error().detail);
            return 1;
        }

        // run_last_used requests kMaxLastUsedRows+1 rows on the unfiltered
        // (no `exe` param) path only, so the extra row is the truncation
        // signal — round-3 review MEDIUM finding, see kMaxLastUsedRows.
        const bool truncated =
            !exe && rows->size() > static_cast<std::size_t>(yuzu::app_usage::kMaxLastUsedRows);
        if (truncated)
            rows->resize(static_cast<std::size_t>(yuzu::app_usage::kMaxLastUsedRows));

        for (const auto& row : *rows)
            ctx.write_output(yuzu::app_usage::format_last_used_row(row));

        if (truncated) {
            ctx.write_output("constrained|last_used_truncated|" +
                             std::to_string(yuzu::app_usage::kMaxLastUsedRows));
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "row cap reached, see last_used_truncated");
        } else {
            ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
        }
        return 0;
    }

    int do_foreground(yuzu::CommandContext& ctx) {
        // Permanent, by-design degraded outcome — never a hard failure. Matches
        // this file's own Disabled/Errored branches and repo convention
        // (autoruns_plugin.cpp, power_health_plugin.cpp's do_battery): CONSTRAINED
        // status + rc 0, so a dispatch of this action records as the documented
        // "always constrained" outcome (content/definitions/app_usage.yaml) in the
        // executions history, never a FAILURE (agent.cpp derives the wire status
        // from rc alone, independent of this typed status).
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "foreground/focus attribution not captured by this source");
        ctx.write_output(
            "constrained|foreground_not_captured|user-context-bridge roadmap (session-scope "
            "attribution)");
        return 0;
    }

    std::string data_dir_;
};

YUZU_PLUGIN_EXPORT(AppUsagePlugin)
