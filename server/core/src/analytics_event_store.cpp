#include "analytics_event_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdlib>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "analytics_event_store";

// emit() is on hot request paths (auth/SCIM routes, agent/gateway service
// handlers) — a short deadline keeps it truly best-effort so a saturated
// pool never stalls the caller. Reads back a diagnostics endpoint, can wait
// a little longer. The drain claim/revert are background-thread work, not
// request-path, so they get the most slack.
constexpr std::chrono::milliseconds kEmitAcquireTimeout{250};
constexpr std::chrono::milliseconds kReadAcquireTimeout{2000};
constexpr std::chrono::milliseconds kDrainClaimTimeout{5000};
constexpr std::chrono::milliseconds kDrainRevertTimeout{2000};

constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr const char* kReasonSerializeError = "serialize_error";

void note_emit_dropped(yuzu::MetricsRegistry* metrics, const char* reason) {
    if (metrics)
        metrics->counter("yuzu_server_analytics_emit_dropped_total", {{"reason", reason}})
            .increment();
}

void note_read_degrade(yuzu::MetricsRegistry* metrics, const char* method, const char* reason) {
    if (metrics)
        metrics
            ->counter("yuzu_server_analytics_read_degrade_total",
                      {{"method", method}, {"reason", reason}})
            .increment();
}

// Unqualified DDL: the migration runner sets search_path to the store schema
// for the migration transaction. Runtime statements below schema-qualify
// explicitly. Partial index (not the SQLite original's plain (drained, id)):
// hazard 2 (kickoff doc) keeps drained rows forever — no retention pass — so
// the working set the drain claim + pending_count actually scan is only the
// undrained rows; indexing the whole ever-growing table would waste space on
// entries neither query ever touches.
const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE analytics_buffer ("
         "  id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
         "  event_json TEXT   NOT NULL,"
         "  created_at BIGINT NOT NULL,"
         "  drained    BOOLEAN NOT NULL DEFAULT FALSE);"
         "CREATE INDEX analytics_buffer_pending_idx ON analytics_buffer (id) WHERE NOT drained;"},
    };
    return kMigrations;
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

bool to_bool(const char* s) { return s != nullptr && s[0] == 't'; }

std::optional<AnalyticsEvent> parse_event(const char* json_text, std::int64_t id) {
    try {
        auto j = nlohmann::json::parse(json_text);
        return j.get<AnalyticsEvent>();
    } catch (const std::exception& e) {
        spdlog::error("AnalyticsEventStore: failed to parse event JSON (id={}): {}", id, e.what());
    } catch (...) {
        spdlog::error("AnalyticsEventStore: unexpected non-std exception parsing event JSON "
                      "(id={})",
                      id);
    }
    return std::nullopt;
}

} // namespace

AnalyticsEventStore::AnalyticsEventStore(pg::PgPool& pool, int drain_interval_seconds,
                                         int batch_size)
    : pool_(pool), drain_interval_seconds_(drain_interval_seconds), batch_size_(batch_size) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("AnalyticsEventStore: no database connection at construction ({}) — "
                      "analytics persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("AnalyticsEventStore: schema migration failed — analytics persistence "
                      "disabled");
        return;
    }
    open_ = true;
    spdlog::info("AnalyticsEventStore initialized (schema {})", kStoreName);
}

AnalyticsEventStore::~AnalyticsEventStore() { stop_drain(); }

void AnalyticsEventStore::emit(AnalyticsEvent event) {
    // shutting_down_ (set by stop_drain(), acquire-paired with its release)
    // refuses NEW entrants once stop_drain() has run — it is a latch, not a
    // rundown/quiesce guard: a caller that already read it as false an
    // instant earlier is not blocked from reaching pool_ below. What makes
    // that acceptable in practice: stop_drain() runs at server.cpp's
    // stop_drain() call site, a multi-second span (several joins/quiesce
    // waits) before pg_pool_.reset() — see the comment there. This does
    // not make the window provably zero, only practically small (cpp-expert
    // review, PR #3350, 2026-08-20 — a prior version of this comment
    // overclaimed the guarantee as absolute).
    if (!open_ || shutting_down_.load(std::memory_order_acquire)) {
        note_emit_dropped(metrics_, kReasonStoreNotOpen);
        return;
    }

    event.ingest_time = now_ms();
    if (event.event_time == 0) {
        event.event_time = event.ingest_time;
    }

    std::string json_str;
    try {
        nlohmann::json j = event;
        // error_handler_t::replace substitutes U+FFFD for invalid UTF-8
        // instead of throwing — an agent-supplied field (hostname,
        // agent_version, error text, ...) must never turn a fail-soft emit
        // into an exception in the caller's request path (auth/SCIM routes).
        // dump() always escapes control chars (incl. NUL) as \u00XX, so the
        // emitted text carries no raw NUL byte for exec_params' C-string
        // bind — no separate NUL guard is needed here.
        json_str = j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    } catch (const std::exception& e) {
        spdlog::debug("AnalyticsEventStore: emit dropped, serialize failed: {}", e.what());
        note_emit_dropped(metrics_, kReasonSerializeError);
        return;
    } catch (...) {
        // Belt-and-braces parity with parse_event() (governance Gate 2,
        // 2026-08-16): the fail-soft contract is "never throws into the
        // caller's request path" — that guarantee shouldn't rest on every
        // possible thrower deriving from std::exception.
        spdlog::debug("AnalyticsEventStore: emit dropped, unexpected non-std exception "
                      "during serialize");
        note_emit_dropped(metrics_, kReasonSerializeError);
        return;
    }

    auto lease = pool_.try_acquire_for(kEmitAcquireTimeout);
    if (!lease) {
        spdlog::debug("AnalyticsEventStore: emit dropped, no connection in time ({})",
                      pool_.last_error());
        note_emit_dropped(metrics_, kReasonPoolTimeout);
        return;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO analytics_event_store.analytics_buffer (event_json, created_at) "
        "VALUES ($1, $2::bigint)",
        std::vector<std::string>{json_str, std::to_string(event.ingest_time)});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::debug("AnalyticsEventStore: emit dropped, insert failed: {}",
                      PQerrorMessage(lease.get()));
        note_emit_dropped(metrics_, kReasonQueryError);
        return;
    }
    total_emitted_.fetch_add(1, std::memory_order_relaxed);
}

std::optional<std::vector<AnalyticsEvent>> AnalyticsEventStore::query_recent(int limit) const {
    // Deliberately NOT gated on shutting_down_ (PR #3350 review, fjarvis,
    // 2026-08-20): reads must stay answerable between stop_drain() and the
    // pool's actual teardown — this store's own drain tests read
    // pending_count()/query_recent() right after stop_drain() to observe
    // final state, which is the intended, documented usage. Safety against
    // pg_pool_.reset() comes from a different, already-verified mechanism
    // for THIS path specifically: the sole production callers are
    // web_server_->Get(...) handlers, and server.cpp's web_thread_ join
    // (with its own bounded wait/_Exit escalation) completes strictly
    // before pg_pool_.reset() runs — every httplib worker thread,
    // including any in-flight analytics handler, is already joined by
    // then. That's a join ordering, not a timing margin (cpp-safety
    // review, PR #3350, 2026-08-20 — traced into vendored httplib.h's
    // ThreadPool::shutdown() to confirm).
    // emit() and start_drain() stay gated: they're reachable from the
    // untracked forward_gateway_pending() detached thread / can spin up a
    // fresh pool-touching thread, neither of which this argument covers.
    if (!open_) {
        note_read_degrade(metrics_, "query_recent", kReasonStoreNotOpen);
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadAcquireTimeout);
    if (!lease) {
        note_read_degrade(metrics_, "query_recent", kReasonPoolTimeout);
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id, event_json FROM analytics_event_store.analytics_buffer "
        "ORDER BY id DESC LIMIT $1",
        std::vector<std::string>{std::to_string(limit)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("AnalyticsEventStore::query_recent: query failed: {}",
                      PQerrorMessage(lease.get()));
        note_read_degrade(metrics_, "query_recent", kReasonQueryError);
        return std::nullopt;
    }
    std::vector<AnalyticsEvent> results;
    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        auto id = to_i64(PQgetvalue(res.get(), i, 0));
        if (auto ev = parse_event(PQgetvalue(res.get(), i, 1), id))
            results.push_back(std::move(*ev));
    }
    return results;
}

std::optional<std::size_t> AnalyticsEventStore::pending_count() const {
    // See query_recent()'s comment above — same reasoning, same
    // deliberate omission of the shutting_down_ check.
    if (!open_) {
        note_read_degrade(metrics_, "pending_count", kReasonStoreNotOpen);
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadAcquireTimeout);
    if (!lease) {
        note_read_degrade(metrics_, "pending_count", kReasonPoolTimeout);
        return std::nullopt;
    }
    // The partial index (WHERE NOT drained) makes this an index-only scan of
    // the pending working set, not the whole ever-growing table.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT count(*) FROM analytics_event_store.analytics_buffer WHERE NOT drained",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("AnalyticsEventStore::pending_count: query failed: {}",
                      PQerrorMessage(lease.get()));
        note_read_degrade(metrics_, "pending_count", kReasonQueryError);
        return std::nullopt;
    }
    return static_cast<std::size_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

std::size_t AnalyticsEventStore::total_emitted() const noexcept {
    return static_cast<std::size_t>(total_emitted_.load(std::memory_order_relaxed));
}

void AnalyticsEventStore::add_sink(std::unique_ptr<AnalyticsEventSink> sink) {
    spdlog::info("AnalyticsEventStore: registered sink '{}'", sink->name());
    sinks_.push_back(std::move(sink));
}

void AnalyticsEventStore::start_drain() {
    if (!open_ || drain_interval_seconds_ <= 0 || sinks_.empty())
        return;
    // Sticky-stop (matches the Spark prefer_spark_/start_local() convention):
    // once stop_drain() has run, never re-arm — a caller after shutdown would
    // otherwise spin up a fresh drain thread walking straight into a pool_
    // that stop() may already be tearing down.
    if (shutting_down_.load(std::memory_order_acquire))
        return;
    // Defensive (governance Gate 3 cpp-safety, 2026-08-16): assigning over a
    // still-joinable jthread/thread calls std::terminate(). No production
    // call site invokes start_drain() twice today, but a future caller or a
    // test doing so should get a silent no-op, not a crashed process.
    if (drain_thread_.joinable())
        return;
#ifdef __cpp_lib_jthread
    drain_thread_ = std::jthread([this](std::stop_token stop) { run_drain(stop); });
#else
    stop_requested_ = false;
    drain_thread_ = std::thread([this] { run_drain(); });
#endif
}

void AnalyticsEventStore::stop_drain() {
    // Set first, before anything else below, so emit() sees it as early as
    // possible: this is a latch, not a rundown/quiesce guard, on the same
    // terms as emit()'s comment above (which is the full statement) —
    // refusing NEW entrants doesn't block a caller that already read it as
    // false an instant earlier, so this alone does not make it provably
    // safe for server.cpp's stop() to free pg_pool_ without waiting on or
    // joining the untracked forward_gateway_pending() detached thread. What
    // makes that acceptable in practice is the same multi-second span
    // before pg_pool_.reset() described in emit()'s comment, not this
    // store alone.
    shutting_down_.store(true, std::memory_order_release);
#ifdef __cpp_lib_jthread
    if (drain_thread_.joinable()) {
        drain_thread_.request_stop();
        drain_thread_.join();
    }
#else
    if (drain_thread_.joinable()) {
        stop_requested_ = true;
        drain_thread_.join();
    }
#endif
}

#ifdef __cpp_lib_jthread
void AnalyticsEventStore::run_drain(std::stop_token stop) {
    while (!stop.stop_requested()) {
        for (int i = 0; i < drain_interval_seconds_ && !stop.stop_requested(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (stop.stop_requested())
            break;
#else
void AnalyticsEventStore::run_drain() {
    while (!stop_requested_.load()) {
        for (int i = 0; i < drain_interval_seconds_ && !stop_requested_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (stop_requested_.load())
            break;
#endif
        // NOTHING may escape a thread function: an exception here is
        // std::terminate on the WHOLE SERVER PROCESS, not a contained
        // analytics outage (governance Gate 3 sre finding, 2026-08-16 — the
        // #2037-class hazard AuditStore::run_cleanup already guards against;
        // this drain loop was missing the identical guard). drain_batch()
        // allocates, formats, and calls into an operator-supplied
        // AnalyticsEventSink::send() this store does not control, so the
        // surface is real.
        if (metrics_)
            metrics_->gauge("yuzu_server_analytics_drain_last_pass_unixtime")
                .set(static_cast<double>(
                    std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count()));
        try {
            drain_batch();
        } catch (...) {
            if (metrics_)
                metrics_->counter("yuzu_server_analytics_drain_pass_failed_total").increment();
            try {
                try {
                    throw;
                } catch (const std::exception& e) {
                    spdlog::error("AnalyticsEventStore: drain pass threw ({}); abandoned, "
                                  "retried at the next interval",
                                  e.what());
                } catch (...) {
                    spdlog::error("AnalyticsEventStore: drain pass threw a non-std exception; "
                                  "abandoned, retried at the next interval");
                }
            } catch (...) {
                // Nothing escapes a thread function, not even a failure to report.
            }
        }
    }
}

// Three phases, deliberately never overlapping a lease with sink I/O
// (ADR-0012: never hold a lease across network/external work):
//
//  A. CLAIM  — single-sweeper advisory lease (pg_try_advisory_xact_lock,
//     fleet-wide: exactly one replica drains per tick) + one transaction
//     that both claims and marks the batch `drained = true` via
//     UPDATE ... RETURNING. Committing releases the advisory lock.
//  B. SEND   — sink->send() with NO lease held. All sinks must succeed for
//     the batch to count delivered (matches the SQLite predecessor's
//     all_ok gate).
//  C. REVERT — only on a partial/total sink failure: a separate, later
//     transaction sets `drained = false` back on the claimed ids so the
//     next tick retries them.
//
// Delivery semantics this yields, recorded here because they differ subtly
// from a plain reap: at-most-once if the process crashes between A and B
// (rows are already committed `drained = true` but never sent — accepted,
// expendable telemetry); at-least-once on a sink that fails then recovers
// (phase C un-claims for retry); a batch row whose JSON fails to parse is
// claimed in phase A but never added to the send/revert sets, so it drains
// exactly once and is dropped — an improvement on the SQLite version, which
// re-selected (and re-failed to parse) a poison-pill row every tick forever.
void AnalyticsEventStore::drain_batch() {
    if (!open_)
        return;

    std::vector<std::string> id_strs;
    std::vector<AnalyticsEvent> events;
    bool locked = false;
    const bool claim_ok = pool_.with_txn_for(kDrainClaimTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult lk = pg::exec_params(
            conn,
            "SELECT pg_try_advisory_xact_lock("
            "hashtextextended('analytics_event_store:drain', 0))",
            std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK) {
            spdlog::error("AnalyticsEventStore: drain lock probe failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        if (!to_bool(PQgetvalue(lk.get(), 0, 0))) {
            return true; // another replica is draining this tick — not a failure
        }
        locked = true;

        pg::PgResult res = pg::exec_params(
            conn,
            "UPDATE analytics_event_store.analytics_buffer SET drained = true "
            "WHERE id IN (SELECT id FROM analytics_event_store.analytics_buffer "
            "WHERE NOT drained ORDER BY id LIMIT $1) "
            "RETURNING id, event_json",
            std::vector<std::string>{std::to_string(batch_size_)});
        if (res.status() != PGRES_TUPLES_OK) {
            spdlog::error("AnalyticsEventStore: drain claim failed: {}", PQerrorMessage(conn));
            return false;
        }
        const int rows = PQntuples(res.get());
        id_strs.reserve(static_cast<std::size_t>(rows));
        events.reserve(static_cast<std::size_t>(rows));
        for (int i = 0; i < rows; ++i) {
            const auto* id_text = PQgetvalue(res.get(), i, 0);
            if (auto ev = parse_event(PQgetvalue(res.get(), i, 1), to_i64(id_text))) {
                events.push_back(std::move(*ev));
                id_strs.emplace_back(id_text);
            }
        }
        return true;
    });
    if (!claim_ok || !locked || events.empty())
        return;

    bool all_ok = true;
    for (auto& sink : sinks_) {
        if (!sink->send(events)) {
            spdlog::warn("AnalyticsEventStore: sink '{}' failed for batch of {}", sink->name(),
                         events.size());
            all_ok = false;
        }
    }
    if (all_ok)
        return;

    std::vector<std::string_view> id_views(id_strs.begin(), id_strs.end());
    auto lease = pool_.try_acquire_for(kDrainRevertTimeout);
    if (!lease) {
        spdlog::error("AnalyticsEventStore: drain revert skipped, no connection in time ({}) — "
                      "{} claimed events left drained without confirmed delivery",
                      pool_.last_error(), id_strs.size());
        return;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE analytics_event_store.analytics_buffer SET drained = false "
        "WHERE id = ANY($1::bigint[])",
        std::vector<std::string>{pg::to_text_array(id_views)});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::error("AnalyticsEventStore: drain revert failed: {} — {} events left drained "
                      "without confirmed delivery",
                      PQerrorMessage(lease.get()), id_strs.size());
    }
}

} // namespace yuzu::server
