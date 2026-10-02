#include "guardian_ingest.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <spdlog/async_logger.h>
#include <spdlog/details/thread_pool.h>
#include <spdlog/sinks/sink.h>
#include <spdlog/spdlog.h>
#include <yuzu/log_token.hpp>
#include <yuzu/metrics.hpp>

#include "dex_alert_router.hpp"
#include "dex_blast_radius.hpp"
#include "guaranteed_state.pb.h"
#include "guaranteed_state_store.hpp"

namespace yuzu::server::detail {

namespace {
// Strip control bytes from an agent-supplied label before it reaches an alert
// sink (webhook HTTP, notification row) or a server log line (gov review
// MEDIUM #2). obs_type and agent_id flow to on_alert_/on_incident_ and the
// spdlog warns; a raw \r\n is a latent CRLF/header-injection and a log-forging
// vector. subject is already stripped in blast_subject_from_detail; this gives
// obs_type and agent_id the same treatment at the one chokepoint that feeds
// both observers. Bounded at 256 bytes (the projection field clamp) so a
// forged multi-KB label can't bloat a notification/log either.
std::string sanitize_label(const std::string& s) {
    std::string out = s.size() > 256 ? s.substr(0, 256) : s;
    for (char& c : out)
        if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) == 0x7F)
            c = '?';
    return out;
}

// google.protobuf.Timestamp seconds → ISO-8601 UTC; falls back to "now" when
// unset (an agent that didn't stamp the event, or a 0 default). Mirrors
// iso_now() in rest_api_v1.cpp. Moved here from agent_service_impl.cpp when the
// Guardian ingest was factored out (Half B) — it had no other caller there.
std::string ts_to_iso8601(std::int64_t epoch_seconds) {
    std::time_t t = epoch_seconds > 0
                        ? static_cast<std::time_t>(epoch_seconds)
                        : std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}

// The `status` label value for a store outcome (bounded set = the four enum values). Kept in
// sync with the warm-create loop below and the EventInsertOutcome enum.
[[nodiscard]] std::string_view event_insert_status_label(EventInsertOutcome outcome) noexcept {
    switch (outcome) {
    case EventInsertOutcome::Inserted:
        return "inserted";
    case EventInsertOutcome::Redelivered:
        return "redelivered";
    case EventInsertOutcome::Conflict:
        return "conflict";
    case EventInsertOutcome::Error:
        return "error";
    }
    return "unknown";
}
} // namespace

std::vector<double> guardian_event_store_buckets() {
    // 0.1ms .. 10s: sub-ms resolution for a healthy SQLite single-row insert, plus the
    // seconds tail for Postgres / lock contention (and the pending SQLite->Postgres move).
    return {0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025,
            0.05,   0.1,     0.25,   0.5,   1.0,    2.5,   5.0,  10.0};
}

// Guard the hand-written warm-create list against enum drift (unhappy-path UP-2). This pins the
// four current values, so a REORDER / RENUMBER / REMOVAL trips the build. It does NOT catch an
// APPEND (a 5th value leaves 0..3 intact) - that case is caught instead by the non-`default`
// -Wswitch in event_insert_status_label (a build WARNING; werror is off, so non-fatal). An
// appended outcome that slipped past the warning would get a lazily-created default-bucket
// "unknown" series - wrong buckets on that one series, never a crash. A hard append-catch would
// need a Count sentinel on EventInsertOutcome, which would ripple -Wswitch into the store's own
// ingest switch - out of scope for a metric. If this fires (or -Wswitch warns), add the new
// outcome to BOTH event_insert_status_label and the warm-create loop.
static_assert(static_cast<int>(EventInsertOutcome::Inserted) == 0 &&
                  static_cast<int>(EventInsertOutcome::Redelivered) == 1 &&
                  static_cast<int>(EventInsertOutcome::Conflict) == 2 &&
                  static_cast<int>(EventInsertOutcome::Error) == 3,
              "EventInsertOutcome reordered/renumbered; update event_insert_status_label + warm-create");

void warm_create_guardian_event_store_metric(yuzu::MetricsRegistry& metrics) {
    const auto buckets = guardian_event_store_buckets();
    for (const EventInsertOutcome status :
         {EventInsertOutcome::Inserted, EventInsertOutcome::Redelivered,
          EventInsertOutcome::Conflict, EventInsertOutcome::Error})
        metrics.histogram(kGuardianEventStoreDurationMetric,
                          {{"status", std::string(event_insert_status_label(status))}}, buckets);
}

// ── #4666 PR-4: dedicated bounded async logger for the T_server diagnostic line ─────────────
// See the full design rationale on the declarations in guardian_ingest.hpp. This is
// deliberately much lighter than agents/core/src/log_handoff.hpp's LogHandoff: one 1024-slot
// queue, one worker thread, no teardown watchdog. This is an ACCEPTED exposure, not an
// eliminated one (see guardian_ingest.hpp's full rationale, corrected 2026-09-28 by adversarial
// review): the server's hard-exit machinery is signal-driven, not self-armed -- the first
// SIGTERM takes the graceful stop() path, so a wedged pool join at exit is bounded only by a
// SECOND signal or the deployment's external stop deadline (210s in both shipped
// systemd/Compose configs), not "a plain SIGTERM" alone -- plus no heartbeat/metrics surfacing
// (out of scope for this PR).
namespace {

// Message-count bound (mirrors log_handoff.hpp's kLogQueueCapacity, sized down: this backs
// exactly one diagnostic line, not the whole process's logging). (1024 + 1) *
// sizeof(spdlog::details::async_msg) fixed RSS at construction - see
// docs/resource-ledgers/4666-t-server-async-logger.md for the exact figure.
constexpr std::size_t kTServerLogQueueCapacity = 1024;

// Mutex-guarded count + truncated last message, no I/O of any kind in the handler itself. This
// is a deliberately server-local, MUCH smaller equivalent of LogHandoff::ErrorState -- it does
// NOT reproduce that class's rate-limited stderr fallback (#5023): this logger backs one
// diagnostic line, not the process's default logger, so there is no pre-existing
// operator-visible stderr signal to preserve here, and adding one would mean a second detached
// emit-thread/Permit apparatus for a single benchmark-diagnostic line. No accessor exists today
// (quality-engineer finding, governance Gate 3): the struct is reachable only from inside the
// `set_error_handler` lambda's capture, so "a future consumer reads the count" is not yet true as
// written -- a future consumer needs an accessor added first, matching LogHandoff's own
// log_errors_total()/stderr_emits_dropped() precedent for the shape such an accessor would take.
struct TServerErrorState {
    std::mutex mu;
    std::uint64_t count{0};
    std::string last_message; // truncated to 256 bytes
};

std::mutex g_t_server_logger_mu;
std::shared_ptr<spdlog::logger> g_t_server_logger; // guarded by g_t_server_logger_mu
std::atomic<std::uint64_t> g_t_server_log_skipped_total{0};
std::atomic<bool> g_t_server_construction_fault_for_test{false};

// Snapshot under the lock, then use the returned shared_ptr lock-free: cheap (one refcount
// bump), and keeps the logger alive for the whole ->info() call even if set_t_server_logger()
// swaps or clears the seam concurrently (production: only at boot, before any ingest traffic;
// tests: serialized by Catch2's default single-threaded run).
std::shared_ptr<spdlog::logger> t_server_logger_snapshot() {
    std::lock_guard<std::mutex> lock(g_t_server_logger_mu);
    return g_t_server_logger;
}

} // namespace

std::shared_ptr<spdlog::logger> create_t_server_logger(std::vector<spdlog::sink_ptr> sinks,
                                                       spdlog::level::level_enum level) {
    // Best-effort by construction (MUST #7 of the #4666 PR-4 spec): a thread-creation refusal
    // (thread_pool's ctor can throw std::system_error) is caught here, logged via the default
    // logger, and returns nullptr -- NEVER EXIT_FAILURE. Nothing before this point mutates any
    // global state; the seam stays unset until set_t_server_logger() is called with the result.
    //
    // Consume the test-fault flag FIRST, unconditionally -- mirrors LogHandoff's own governance
    // hardening fix (log_handoff.cpp): consuming it AFTER some other early-return path would let
    // a fault flag set ahead of that path go unconsumed and leak into the next, unrelated call.
    // This function has no such early-return before the try block today, but the ordering is
    // kept first-thing regardless, so it stays correct if one is ever added.
    if (g_t_server_construction_fault_for_test.exchange(false, std::memory_order_relaxed)) {
        spdlog::warn("Guardian T_server: failed to construct dedicated async logger (injected "
                     "test fault); the T_server diagnostic line will be skipped until the next "
                     "restart");
        return nullptr;
    }
    try {
        auto pool = std::make_shared<spdlog::details::thread_pool>(kTServerLogQueueCapacity, 1);
        auto logger = std::make_shared<spdlog::async_logger>(
            std::string("guardian.t_server"), sinks.begin(), sinks.end(),
            std::weak_ptr<spdlog::details::thread_pool>(pool),
            spdlog::async_overflow_policy::overrun_oldest);

        auto error_state = std::make_shared<TServerErrorState>();
        logger->set_error_handler([error_state](const std::string& msg) {
            // No I/O in this handler (MUST #2) -- see the class comment above for why this
            // deliberately does not mirror LogHandoff::ErrorState's stderr fallback.
            std::lock_guard<std::mutex> lock(error_state->mu);
            ++error_state->count;
            error_state->last_message = msg.size() > 256 ? msg.substr(0, 256) : msg;
        });
        // Explicit level set (MUST #4): spdlog::set_level()'s registry-wide reach only applies
        // to already-registered loggers, and register_logger() alone does not retroactively
        // apply the process's current level (only registry::initialize_logger() does) -- so
        // this must be set here, at construction, or --log-level would silently fail to
        // suppress T_server.
        logger->set_level(level);

        // spdlog::async_logger holds only a WEAK back-reference to its thread_pool (verified
        // against async_logger-inl.h: sink_it_()/flush_() both do
        // `if (auto pool_ptr = thread_pool_.lock()) pool_ptr->post_log(...)`), so something must
        // keep `pool` alive for as long as the returned logger is used -- otherwise the pool
        // (and its worker thread) would be destroyed the moment this function returns and the
        // local `pool` shared_ptr above drops, and every future ->info() call would silently
        // no-op (thread_pool_.lock() returning nullptr, per the same guard). This function is
        // contracted (MUST #8) to return a plain `shared_ptr<spdlog::logger>`, not a dedicated
        // owning class the way LogHandoff is, so the two lifetimes are bundled into that one
        // returned handle instead: a second control block sharing `logger`'s pointer, whose
        // deleter captures both `pool` and `logger` and does nothing else. Dropping the last
        // copy of the returned handle releases both captures, and each is then destroyed
        // through its OWN original shared_ptr machinery -- this deleter never calls delete
        // itself, so there is no double-free. Capture order has no correctness dependency
        // either way: ~async_logger() never touches the pool, and ~thread_pool()'s worker join
        // never touches the logger.
        return std::shared_ptr<spdlog::logger>(logger.get(),
                                                [pool, logger](spdlog::logger*) {});
    } catch (const std::exception& e) {
        spdlog::warn("Guardian T_server: failed to construct dedicated async logger ({}); the "
                     "T_server diagnostic line will be skipped until the next restart",
                     e.what());
        return nullptr;
    } catch (...) {
        spdlog::warn("Guardian T_server: failed to construct dedicated async logger (unknown "
                     "exception); the T_server diagnostic line will be skipped until the next "
                     "restart");
        return nullptr;
    }
}

void set_t_server_logger(std::shared_ptr<spdlog::logger> logger) {
    std::lock_guard<std::mutex> lock(g_t_server_logger_mu);
    g_t_server_logger = std::move(logger);
}

std::uint64_t t_server_log_skipped_total_for_test() {
    return g_t_server_log_skipped_total.load(std::memory_order_relaxed);
}

void set_t_server_construction_fault_for_test(bool fail) noexcept {
    g_t_server_construction_fault_for_test.store(fail, std::memory_order_relaxed);
}

void ingest_guardian_response(GuaranteedStateStore& store, const std::string& agent_id,
                              const pb::CommandResponse& resp, BlastRadiusDetector* blast_radius,
                              DexAlertRouter* alert_router, yuzu::MetricsRegistry* metrics) {
    if (resp.action() == "event") {
        ::yuzu::guardian::v1::GuaranteedStateEvent ev;
        if (!ev.ParseFromString(resp.payload())) {
            spdlog::warn("Guardian: failed to parse GuaranteedStateEvent from agent {}",
                         log_id_token(agent_id));
            return; // a malformed frame never reaches the store - not a timed ingest
        }
        // #4606 criterion-10 T_server waypoint: server receipt, captured before
        // store.insert_event_classified so store latency is not folded in.
        const std::int64_t recv_wall_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                               std::chrono::system_clock::now().time_since_epoch())
                                               .count();
        GuaranteedStateEventRow ev_row;
        ev_row.event_id = ev.event_id();
        ev_row.rule_id = ev.rule_id();
        ev_row.agent_id = agent_id; // caller-supplied (cert-bound or gateway-asserted)
        ev_row.event_type = ev.event_type();
        ev_row.severity = ev.severity();
        ev_row.guard_type = ev.guard_type();
        ev_row.guard_category = ev.guard_category();
        ev_row.detected_value = ev.detected_value();
        ev_row.expected_value = ev.expected_value();
        ev_row.detail_json = ev.detail_json(); // structured companion (route a'); "" for plain drift
        // Ingest-boundary size cap (governance/adversarial-review F6): a legit
        // detail_json is well under 1 KiB; a compromised enrolled agent could ship
        // a multi-MB blob to bloat the events column and burn JSON-parse cost on the
        // ingest thread in-txn. Drop an over-cap blob (the event is still recorded;
        // the DEX projection degrades to empty fields — degrade-don't-destroy). 16
        // KiB is generous headroom over any real signal payload.
        constexpr std::size_t kMaxDetailJson = 16 * 1024;
        if (ev_row.detail_json.size() > kMaxDetailJson) {
            // Sanitize the agent-controlled identifiers here too (sec-M1 sibling) — this
            // WARN predates the classify switch and reaches a log line with the same
            // CRLF-forging exposure.
            spdlog::warn("Guardian: dropping oversized detail_json ({} bytes) from agent {} "
                         "event {} (cap {})",
                         ev_row.detail_json.size(), log_id_token(agent_id),
                         log_id_token(ev_row.event_id), kMaxDetailJson);
            ev_row.detail_json.clear();
        }

        ev_row.remediation_action = ev.remediation_action();
        ev_row.remediation_success = ev.remediation_success();
        ev_row.detection_latency_us = static_cast<int64_t>(ev.detection_latency_us());
        ev_row.remediation_latency_us = static_cast<int64_t>(ev.remediation_latency_us());
        ev_row.timestamp = ts_to_iso8601(ev.timestamp().seconds());
        // Enrich severity from the rule store (contract decision 4) — the agent
        // isn't pushed severity. Fall back to the event's own value, then
        // "unknown" for an already-deleted rule.
        // get_rule is now three-state (found / genuinely-absent / degraded — ADR-0038).
        // Ingest is fail-soft: both "deleted rule" and "degraded read" fall through to
        // the "unknown" default below, matching this comment's pre-existing intent.
        if (auto rule = store.get_rule(ev_row.rule_id); rule && *rule)
            ev_row.severity = (*rule)->severity;
        if (ev_row.severity.empty())
            ev_row.severity = "unknown";
        // Tri-state ingest (item-7 PR-Sv): the durable agent journal re-sends on every
        // reconnect, so a matching-fields redelivery is EXPECTED. The DEX blast-radius
        // + alert observers below run ONLY on a genuine first insert (`Inserted`) — a
        // redelivery must NOT re-fire them (false blast-radius sightings / duplicate
        // routed alerts), and a mismatched collision stays on the loud CC7.3 metric.
        // Time the store operation (insert_event_classified: the classify+store SQLite txn -
        // the redelivery byte-compare on redelivered/conflict, projection+commit on insert),
        // split by outcome `status`. This is the store-latency signal the off-write-path compare
        // (#2298) is VALIDATED against, NOT the go/no-go itself: an aggregate histogram can't
        // attribute compare-CPU vs lock-wait vs txn, so the decision needs a concurrent
        // benchmark. Series are warm-created at startup, so this is a cheap name+label lookup
        // (no per-event bucket-vector alloc). Inert when `metrics` is null (tests / gateway
        // without a registry).
        const auto store_t0 = std::chrono::steady_clock::now();
        const EventInsertResult res = store.insert_event_classified(ev_row);
        if (metrics) {
            // This runs on the gRPC ingest thread, whose Subscribe / ForwardGuardianMessage loops
            // have NO catch-all above them (same reason the observer block below is guarded). The
            // series are warm-created, so in steady state only the transient Labels/key alloc can
            // throw (OOM) - swallow it: a best-effort metric observation must never tear down the
            // agent's stream. Uniform no-escape posture (cpp-safety Gate-3).
            try {
                const double secs =
                    std::chrono::duration<double>(std::chrono::steady_clock::now() - store_t0)
                        .count();
                metrics->histogram(kGuardianEventStoreDurationMetric,
                                   {{"status", std::string(event_insert_status_label(res.outcome))}})
                    .observe(secs);
            } catch (...) { // best-effort metric; never propagate onto the ingest thread
            }
        }
        switch (res.outcome) {
        case EventInsertOutcome::Inserted:
            break; // fall through to the observers below
        case EventInsertOutcome::Redelivered:
            // Agent-controlled identifiers are neutralised before they reach any key=value
            // log line: the NUL guard strips \0 but not CR/LF, a space or '=' forges extra
            // tokens, and the tightened YuzuGuardianEventsDropped alert directs operators to
            // trust these logs (sec-M1). log_id_token is the neutraliser and length rule that
            // the T_server line and the agent's T_wire/T_detect lines use, so an id reads
            // identically on every line an operator joins across. (sanitize_label above stays
            // for the observer path: the alert-sink labels and the observer-threw warns below,
            // which are not key=value lines.) res.error is dropped on Conflict: it only
            // repeats the (now-neutralised) event_id.
            spdlog::debug("Guardian: idempotent event redelivery (no re-observe) "
                          "event_id={} agent={} rule={}",
                          log_id_token(ev_row.event_id), log_id_token(agent_id),
                          log_id_token(ev_row.rule_id));
            return;
        case EventInsertOutcome::Conflict:
            spdlog::warn("Guardian: event_id collision with MISMATCHED fields (possible "
                         "forged-id pre-claim / seq-reset) event_id={} agent={} rule={}",
                         log_id_token(ev_row.event_id), log_id_token(agent_id),
                         log_id_token(ev_row.rule_id));
            return;
        case EventInsertOutcome::Error:
            // res.error is server-constructed (SQLite errmsg / fixed strings) — no agent
            // input — but the identifiers still get neutralised.
            spdlog::warn("Guardian: event ingest error (agent={}, rule={}): {}",
                         log_id_token(agent_id), log_id_token(ev_row.rule_id), res.error);
            return;
        }
        if (ev_row.rule_id != kObservationRuleId) {
            // #4606 criterion-10 T_server: benchmark-diagnostic latency waypoint, always-on at
            // info level (the shipped default is what the benchmark must measure). Best-effort —
            // formatting/logging must never escape onto the gRPC ingest thread (same posture as
            // the metrics try/catch above and the blast-radius try/catch below).
            try {
                const std::int64_t store_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                   std::chrono::steady_clock::now() - store_t0)
                                                   .count();
                // Agent-supplied wire timestamp, checked before use (untrusted protobuf input):
                // the field must be present, nanos must be in [0, 1e9) and seconds must not
                // overflow an int64 once scaled. An ABSENT timestamp reads as seconds()==0, which
                // must not be reported as a real epoch-0 instant, so it takes the sentinel too.
                std::int64_t agent_ns = -1; // sentinel: invalid/unavailable
                const std::int64_t secs = ev.timestamp().seconds();
                const std::int32_t nanos = ev.timestamp().nanos();
                constexpr std::int64_t kNsPerSec = 1'000'000'000;
                if (ev.has_timestamp() && nanos >= 0 && nanos < kNsPerSec && secs >= 0 &&
                    secs <= (std::numeric_limits<std::int64_t>::max() / kNsPerSec) - 1)
                    agent_ns = secs * kNsPerSec + nanos;
                // The three ids are agent- or operator-supplied text embedded in a space-delimited
                // key=value line, so each goes through the SAME neutraliser and shortening the
                // agent's T_wire/T_detect lines use (yuzu/log_token.hpp, log_id_token): a space or
                // '=' would otherwise forge extra tokens, and a per-side rule would break the
                // event_id join.
                //
                // #4666 PR-4: resolved through the dedicated seam logger (never the bare
                // spdlog:: free functions) so a stalled sink can never block this thread. Null
                // (construction/registration never succeeded, or main.cpp hasn't wired it yet)
                // is a silent, counted skip, not a fallback onto the synchronous default logger
                // -- falling back would reintroduce the exact hazard this seam exists to close.
                if (auto logger = t_server_logger_snapshot()) {
                    logger->info("Guardian T_server event_id={} agent={} rule={} recv_ns={} "
                                 "committed_ns={} agent_ns={} store_ms={}",
                                 log_id_token(ev_row.event_id), log_id_token(agent_id),
                                 log_id_token(ev_row.rule_id), recv_wall_ns, res.committed_wall_ns,
                                 agent_ns, store_ms);
                } else {
                    g_t_server_log_skipped_total.fetch_add(1, std::memory_order_relaxed);
                }
            } catch (...) { // best-effort diagnostic; never propagate onto the ingest thread
            }
        }
        // Fleet-wide incident detection — RULELESS observations only, and only
        // AFTER the event committed (a rolled-back duplicate must never count a
        // device twice). Uses the SHARED kObservationRuleId constant, same one
        // is_reserved_rule_id keys on, so the feed gate and the projection guard
        // can't desync (gov architect/consistency). The window uses server
        // receipt time, not the agent's clock — "blast radius" is about
        // simultaneity as the FLEET experiences it, and a skewed agent clock
        // must not smear the window.
        if ((blast_radius || alert_router) && ev_row.rule_id == kObservationRuleId) {
            const std::int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                                         std::chrono::system_clock::now().time_since_epoch())
                                         .count();
            // Sanitize every agent-influenced label that reaches an alert sink
            // or a log line: subject (via blast_subject_from_detail), plus
            // obs_type and agent_id here (gov review MEDIUM #2). The stored
            // projection above keeps the raw values (escaped at render); this is
            // the alert/log path only.
            const auto subject = blast_subject_from_detail(ev_row.detail_json);
            const auto obs_type = sanitize_label(ev_row.event_type);
            const auto safe_agent = sanitize_label(agent_id);
            // Belt-and-braces (gov SRE): this runs on the gRPC ingest thread
            // inside a sync handler with NO catch-all above it — an escape tears
            // down the agent's Subscribe stream. Each observer also guards its
            // own sink, but this catch-all protects EVERY current and future
            // observer regardless of whether each remembers to.
            try {
                if (blast_radius)
                    blast_radius->observe(obs_type, subject, safe_agent, now);
                // F1: operator-routed per-signal alerts — same chokepoint, same
                // both-paths coverage, same sanitized labels.
                if (alert_router)
                    alert_router->observe(obs_type, subject, safe_agent, now);
            } catch (const std::exception& e) {
                spdlog::warn("Guardian ingest: observer threw for {} from agent {}: {}", obs_type,
                             safe_agent, e.what());
            } catch (...) {
                spdlog::warn("Guardian ingest: observer threw (non-std) for {} from agent {}",
                             obs_type, safe_agent);
            }
        }
        return;
    }
    // action "status" ingest lands with the status slice; any other action is
    // logged and dropped — the "__guard__" channel is generic, so a future
    // status message (or a malformed one) must not crash this path. Never
    // enters the response store / executions drawer.
    spdlog::debug("Guardian: ignoring __guard__ action '{}' from agent {} (only 'event' ingested "
                  "in A1)",
                  resp.action(), agent_id);
}

} // namespace yuzu::server::detail
