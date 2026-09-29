#include "nvd_sync.hpp"

#include "background_jobs.hpp" // WS-10 YUZU_ASSERT_BACKGROUND_JOB gate

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <exception>
#include <format>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

// NVD 2.0 accepts ISO-8601 date/times with millisecond precision and implicit
// UTC (no suffix), e.g. "2024-01-01T00:00:00.000".
std::string iso_of(std::chrono::system_clock::time_point tp) {
    return std::format("{:%Y-%m-%dT%H:%M:%S}.000", std::chrono::floor<std::chrono::seconds>(tp));
}

long long epoch_secs(std::chrono::system_clock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
}

// NVD's published-date catalog effectively starts 1999-01-01T00:00:00Z; no
// legitimate CVE predates it. This fixed epoch is used two ways:
//   1. the floor for a full-history (`--nvd-backfill-years 0`) backfill, and the
//      lower clamp for any bounded floor (see backfill_floor), so a floor is never
//      a pre-epoch NEGATIVE value; and
//   2. the fixed lower sanity bound passed to parse_cursor — anything below it is
//      pre-catalog garbage, never a real resume position.
// Anchoring to this FIXED positive bound (not a rolling `now - N years`) is
// load-bearing: `now - years(100)` is ~1926, a negative epoch, which as a
// parse_cursor bound would accept pre-catalog garbage like "-5" (→1969) and let
// the backfill walk 1969→1926 and false-complete, skipping 1969→present
// (#1889 review r2 / governance UP-3/UP-4).
constexpr long long kNvdCatalogStartEpoch = 915148800; // 1999-01-01T00:00:00Z

// Cap on consecutive empty-catalog recovery resets (see do_backfill). Bounds a
// full-range re-walk to at most this many passes when NVD returns well-formed-but-
// empty windows for an extended outage, instead of re-walking every ~60s tick.
constexpr int kMaxEmptyCatalogResets = 5;

// A window that returns ok+empty AFTER real data has landed is re-confirmed this many
// times (holding the cursor) before it's accepted as genuinely empty and skipped —
// guards against a stale cache/proxy serving an empty page for a populated range while
// still terminating at a truly-empty boundary window (see do_backfill, #1889 review r5).
constexpr int kSuspiciousEmptyConfirmations = 3;

// Cursors are stored in sync_meta as epoch-seconds strings (no ISO parsing —
// avoids std::chrono::parse portability differences). A cursor is rejected →
// nullopt (caller restarts from a safe idempotent default) when it is empty,
// unparseable, or older than `min_epoch_secs` (callers pass the FIXED
// kNvdCatalogStartEpoch — see above). Whether the walk has reached the *configured*
// floor is decided separately by the caller comparing the parsed cursor to
// backfill_floor(now); parse_cursor only screens out pre-catalog garbage.
std::optional<std::chrono::system_clock::time_point> parse_cursor(const std::string& s,
                                                                  long long min_epoch_secs) {
    if (s.empty())
        return std::nullopt;
    try {
        const long long v = std::stoll(s);
        if (v < min_epoch_secs)
            return std::nullopt;
        return std::chrono::system_clock::time_point{std::chrono::seconds{v}};
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace

NvdSyncManager::NvdSyncManager(std::shared_ptr<NvdDatabase> db, std::string api_key,
                               std::string proxy_url, std::chrono::seconds sync_interval,
                               int backfill_years)
    : db_{std::move(db)}, interval_{sync_interval}, backfill_years_{backfill_years} {
    // Build the concrete client in the body so we can wire the cancel flag before
    // erasing to INvdFetcher (#1879). &stopping_ is a stable member address; the
    // client only dereferences it during a fetch, long after construction.
    auto client = std::make_unique<NvdClient>(std::move(api_key), std::move(proxy_url));
    client->set_cancel_flag(&stopping_);
    fetcher_ = std::move(client);
}

NvdSyncManager::NvdSyncManager(std::shared_ptr<NvdDatabase> db,
                               std::unique_ptr<INvdFetcher> fetcher,
                               std::chrono::seconds sync_interval, int backfill_years)
    : db_{std::move(db)}, fetcher_{std::move(fetcher)}, interval_{sync_interval},
      backfill_years_{backfill_years} {}

NvdSyncManager::~NvdSyncManager() {
    // On the detach path stop() returns false; the owner (ServerImpl::stop())
    // releases the unique_ptr so the dtor normally doesn't run there. Discard.
    (void)stop();
}

void NvdSyncManager::start() {
    if (sync_thread_.joinable()) {
        return; // already running
    }
    // Note: restarting after a stop() that DETACHED (returned false) would reset
    // stopping_/finished_ while the abandoned thread still runs — but ServerImpl
    // release()es the manager on that path and never restarts it, so this is
    // unreachable in production.
    stopping_.store(false);
    finished_.store(false);
#ifdef __cpp_lib_jthread
    sync_thread_ = std::jthread([this](std::stop_token stop) { sync_loop(stop); });
#else
    stop_requested_ = false;
    sync_thread_ = std::thread([this] { sync_loop(); });
#endif
    spdlog::info("NVD sync manager started (interval={}s, backfill={}y)", interval_.count(),
                 backfill_years_);
}

bool NvdSyncManager::stop() {
    if (!sync_thread_.joinable()) {
        return true; // never started or already cleanly stopped — safe to destroy
    }
    stopping_.store(true); // cooperative: abort a long backfill/freshness pass between windows
#ifdef __cpp_lib_jthread
    sync_thread_.request_stop();
#else
    stop_requested_ = true;
#endif
    {
        std::lock_guard<std::mutex> lock{mu_};
        cv_.notify_all();
    }

    // #1867 bounded join. Cooperative cancellation (stopping_) aborts between
    // windows, but a fetch wedged mid-page (see #1879) can still take a while;
    // wait a short grace for a clean exit, then detach + signal the owner to LEAK
    // this manager (ServerImpl::stop()) rather than hang shutdown or UAF freed
    // members from the abandoned thread.
    constexpr auto kGrace = std::chrono::seconds(5);
    const auto deadline = std::chrono::steady_clock::now() + kGrace;
    while (!finished_.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (finished_.load()) {
        sync_thread_.join();
        spdlog::info("NVD sync manager stopped");
        return true;
    }
    spdlog::warn("NVD sync thread did not exit within {}s (stuck in a fetch?); detaching + leaking "
                 "the manager to avoid wedging shutdown / a teardown UAF (see #1867)",
                 kGrace.count());
    sync_thread_.detach();
    return false;
}

void NvdSyncManager::sync_now() {
    do_sync();
}

void NvdSyncManager::request_sync() {
    {
        std::lock_guard<std::mutex> lock{mu_};
        sync_requested_ = true;
    }
    cv_.notify_all(); // wake the loop; it owns the sync so nothing outlives us
}

NvdSyncManager::SyncStatus NvdSyncManager::status() const {
    std::lock_guard<std::mutex> lock{mu_};
    SyncStatus st = status_;
    // Snapshot the per-reason failure tallies for the /metrics scrape (pull model,
    // #1909). Relaxed loads: each is an independent monotonic counter and the scrape
    // only needs a recent value, not cross-counter ordering.
    for (std::size_t i = 0; i < failure_counts_.size(); ++i)
        st.failure_counts[i] = failure_counts_[i].load(std::memory_order_relaxed);
    // Surface backfill progress (cpp/consistency S1 + sre): the store is the
    // source of truth for completion + the newest-first cursor.
    // Completion is DERIVED (cursor vs current floor), not read from a sticky flag —
    // the same source of truth as do_sync's branch, so status can't report "complete"
    // while the loop is still backfilling a newly-deepened range (#1889 review r2).
    st.backfill_complete = backfill_complete();
    // Display the stored cursor whenever it clears the fixed catalog-start bound
    // (pre-1999 = garbage → blank). This does NOT blank a legitimately-completed
    // cursor: the walk floor is >= the catalog start in every config, so a completed
    // cursor is always >= 1999 and survives (#1889 review, S1). Clamp to `now`: a
    // corrupt far-future cursor must never reach iso_of()/std::format (which can throw
    // on an extreme year and 500 the status endpoint), and "oldest published" is never
    // legitimately in the future (governance Gate 4 UP-6).
    const auto now = std::chrono::system_clock::now();
    if (auto cur = parse_cursor(db_->get_meta("backfill_oldest_published"), kNvdCatalogStartEpoch))
        st.backfill_oldest_published = iso_of(std::min(*cur, now));
    // Survive restart: last_sync_time lives in meta, not just memory (S1).
    if (st.last_sync_time.empty())
        st.last_sync_time = db_->get_meta("last_sync_time");
    return st;
}

bool NvdSyncManager::backfill_complete() const {
    // Completion is DERIVED from the persisted cursor vs the CURRENTLY-configured
    // floor, never a sticky flag: a flag written under a past --nvd-backfill-years
    // would wrongly report "complete" after an operator deepens the config, leaving
    // the newly-requested older range unfetched forever (#1889 review r2). The cursor
    // is parsed against the FIXED catalog-start bound (not backfill_floor(now)) so a
    // legitimately-completed cursor pinned at an older, now-drifted bounded floor is
    // NOT rejected — only pre-catalog garbage is. Defensive try/catch: this runs in
    // the sync_loop header outside do_sync's guard, so a throwing SQLite read must not
    // escape the thread and std::terminate (unreadable → "not complete", safe: keeps
    // backfilling).
    try {
        const auto cursor =
            parse_cursor(db_->get_meta("backfill_oldest_published"), kNvdCatalogStartEpoch);
        // Position AND content: the cursor must have reached the floor AND the catalog
        // must actually hold real NVD CVEs. Without the content check, a corrupt
        // at/below-floor cursor — or an NVD outage that returns empty windows — would
        // report the mirror "complete" over an empty catalog, making every vuln scan
        // silently return clean (a false-negative). Uses nvd_cve_count() (source='nvd'),
        // NOT total_cve_count(), so the built-in fallback rules seeded at startup can't
        // masquerade as a populated mirror (#1889 review r4). Short-circuited so the
        // COUNT only runs once the cheap floor test already passed.
        return cursor.has_value() && *cursor <= backfill_floor(std::chrono::system_clock::now()) &&
               db_->nvd_cve_count() > 0;
    } catch (const std::exception& e) {
        spdlog::warn("NVD backfill_complete() meta read failed: {} (assuming not complete)",
                     e.what());
        return false;
    }
}

#ifdef __cpp_lib_jthread
void NvdSyncManager::sync_loop(std::stop_token stop) {
#else
void NvdSyncManager::sync_loop() {
#endif
    // Seed built-in rules on first run (offline fallback).
    try {
        db_->seed_builtin_rules();
        spdlog::info("NVD built-in rules seeded");
    } catch (const std::exception& e) {
        spdlog::error("Failed to seed built-in rules: {}", e.what());
    }

    // Immediate first sync (runs the backfill until the floor, or freshness).
    YUZU_ASSERT_BACKGROUND_JOB("nvd_sync.do_sync"); // WS-10 DisabledUntilFixed (engine-tier pending)
    do_sync();

    while (true) {
        // While the catalog is still backfilling, retry soon (a failed window
        // shouldn't wait the full freshness interval); once complete, settle to
        // the periodic freshness cadence.
        std::chrono::seconds wait = interval_;
        if (!backfill_complete() && interval_ > std::chrono::seconds{60}) {
            wait = std::chrono::seconds{60};
        }

        std::unique_lock<std::mutex> lock{mu_};
#ifdef __cpp_lib_jthread
        cv_.wait_for(lock, wait, [&] { return stop.stop_requested() || sync_requested_; });
        if (stop.stop_requested())
            break;
#else
        cv_.wait_for(lock, wait,
                     [this] { return stop_requested_.load() || sync_requested_; });
        if (stop_requested_.load())
            break;
#endif
        sync_requested_ = false; // consume an on-demand request (request_sync)
        lock.unlock();
        do_sync();
    }

    // Signal a clean exit so stop() can join() within its grace instead of
    // detaching (#1867).
    finished_.store(true);
}

void NvdSyncManager::do_sync() {
    // Reject a concurrent sync (periodic loop vs. detached "Sync now"): running
    // two on the same fetcher races the client's rate-limit state and doubles
    // NVD load (#1867 governance).
    bool expected = false;
    if (!sync_active_.compare_exchange_strong(expected, true)) {
        spdlog::info("NVD sync already in progress — skipping this trigger");
        return;
    }
    struct ActiveGuard {
        std::atomic<bool>& flag;
        ~ActiveGuard() { flag.store(false); }
    } active_guard{sync_active_};

    {
        std::lock_guard<std::mutex> lock{mu_};
        status_.syncing = true;
        status_.last_error.clear();
    }

    try {
        if (backfill_complete()) {
            do_freshness();
        } else {
            do_backfill();
        }
        const auto count = db_->total_cve_count(); // off the status lock (cpp-safety)
        std::lock_guard<std::mutex> lock{mu_};
        status_.total_cves = count;
        status_.syncing = false;
    } catch (const std::exception& e) {
        spdlog::error("NVD sync failed: {}", e.what());
        std::lock_guard<std::mutex> lock{mu_};
        status_.last_error = e.what();
        status_.syncing = false;
    }
}

std::chrono::system_clock::time_point
NvdSyncManager::backfill_floor(std::chrono::system_clock::time_point now) const {
    const auto nvd_start =
        std::chrono::system_clock::time_point{std::chrono::seconds{kNvdCatalogStartEpoch}};
    // Full history (backfill_years <= 0) walks back to NVD's catalog start. A bounded
    // config is clamped to that same start: no CVEs predate it, and a sub-1999 floor
    // (backfill_years > ~56 gives a pre-1970 negative-epoch floor) would reintroduce
    // the pre-catalog-garbage accept bug (#1889 review r2). Clamping keeps
    // epoch_secs(floor) a sane positive bound in every configuration.
    if (backfill_years_ <= 0)
        return nvd_start;
    // Clamp the year count before the subtraction: --nvd-backfill-years is unbounded
    // at config parse, and an absurd value would overflow the years->system_clock
    // conversion (UB). 200y is far past NVD's ~27y catalog — the max() below pins any
    // real deep config to nvd_start regardless — and stays well inside int64 range.
    constexpr int kMaxSaneBackfillYears = 200;
    const int years = std::min(backfill_years_, kMaxSaneBackfillYears);
    return std::max(now - std::chrono::years(years), nvd_start);
}

void NvdSyncManager::report_failure(NvdFailureReason reason, const char* phase) {
    // A shutdown cancel is not a failure — don't log it as one and don't count it.
    // kNone can't reach here (only set on ok==true) but is guarded so it can never
    // land in the countable index range.
    if (stopping_.load() || reason == NvdFailureReason::kCancelled ||
        reason == NvdFailureReason::kNone)
        return;
    // Pull model (#1909): tally the failure on the manager itself. The /metrics scrape
    // reads failure_counts_ via status() and emits yuzu_nvd_sync_failures_total. There
    // is NO cross-object callback, so the sync thread never touches ServerImpl::metrics_
    // — the teardown-UAF window the callback had is gone (the manager, even leaked on
    // the detach path, owns this atomic for its whole lifetime).
    const int idx = nvd_reason_index(reason);
    if (idx >= 0)
        failure_counts_[idx].fetch_add(1, std::memory_order_relaxed);
    spdlog::warn("NVD {} window failed (reason={}) — will retry next tick (cursor unchanged)", phase,
                 nvd_reason_label(reason));
}

void NvdSyncManager::do_backfill() {
    const auto now = std::chrono::system_clock::now();
    const auto floor = backfill_floor(now);
    const auto max_window = std::chrono::days(120); // NVD caps a pub/lastMod range at 120 days

    // Resume from the oldest published date reached so far (newest-first walk).
    // Clamp to `now`: a future cursor (clock skew) would otherwise ask NVD for a
    // future window forever (livelock, UP-4). The parse bound is the FIXED catalog
    // start — a pre-1999 garbage cursor is rejected and restarts from `now` (idempotent
    // re-fetch); a valid cursor already at/below the configured floor simply makes the
    // while-loop below exit immediately (no re-fetch). Floor gating lives in the loop,
    // not in the parse bound (#1889 review r2).
    auto cursor =
        std::min(parse_cursor(db_->get_meta("backfill_oldest_published"), kNvdCatalogStartEpoch)
                     .value_or(now),
                 now);

    // Recovery: if the walk would be a no-op (cursor already at/below the floor) but the
    // catalog holds no real NVD CVEs, the mirror was emptied out-of-band (corruption /
    // manual truncate / disk loss) without a matching cursor reset. Restart from `now` so
    // we actually re-fetch, rather than sitting "incomplete" (per the content guard in
    // backfill_complete()) forever while the loop does nothing (governance Gate 6 SRE).
    // Bounded: if NVD keeps returning well-formed-but-empty windows (an outage where
    // result.ok stays true), stop re-walking after kMaxEmptyCatalogResets to avoid a
    // full-range re-walk every ~60s tick. The counter clears the moment real data lands
    // (see the successful-upsert path below), so a genuine NVD recovery resumes cleanly.
    if (cursor <= floor && db_->nvd_cve_count() == 0) {
        if (empty_catalog_resets_ >= kMaxEmptyCatalogResets) {
            // Capped: stop re-walking the full range every tick. Instead probe ONLY the
            // newest window so a genuine NVD recovery is detected without a server restart.
            // If it's still empty/erroring, stay capped (a cheap one-window no-op). If data
            // returns, clear the cap and fall through to a full re-walk — the probe result
            // is deliberately NOT upserted here, so a partial (newest-window-only) catalog
            // can't falsely satisfy the content guard (grill-with-docs self-review).
            if (stopping_.load())
                return;
            auto probe = fetcher_->fetch_by_published_window(iso_of(now - max_window), iso_of(now));
            if (!probe.ok || probe.records.empty()) {
                // Still empty — re-assert the starved state each tick. do_sync clears
                // status_.last_error at the top of every tick, so a one-shot set on the
                // cap-transition would vanish for the rest of the outage (re-review SHOULD).
                std::lock_guard<std::mutex> lock{mu_};
                status_.last_error = "NVD returning empty responses — mirror not populated";
                return;
            }
            // Data is back — full re-walk this tick. Do NOT clear the cap here: the in-loop
            // reset below clears it only once a window actually PERSISTS, so a flapping NVD
            // (probe returns data, deeper windows keep failing) can't re-enter uncapped
            // full re-walks (cpp-safety r4). The probe result is deliberately not upserted,
            // so a newest-window-only catalog can't falsely satisfy the content guard.
            spdlog::info("NVD backfill: data returned after an empty-catalog outage — resuming "
                         "full recovery");
            cursor = now;
        } else {
            if (++empty_catalog_resets_ == kMaxEmptyCatalogResets) {
                spdlog::error("NVD backfill: catalog still empty after {} recovery resets — NVD "
                              "appears to be returning empty responses; pausing full re-walks and "
                              "probing the newest window each tick until data returns or restart",
                              kMaxEmptyCatalogResets);
                // Surface the starved state on /api/nvd/status so a prolonged empty-NVD
                // outage is operator-alertable, not just a one-shot log line (Gate 4 UP-5).
                std::lock_guard<std::mutex> lock{mu_};
                status_.last_error = "NVD returning empty responses — mirror not populated";
            } else {
                spdlog::warn("NVD backfill: cursor at/below the floor but the catalog is empty — "
                             "resetting the cursor to `now` to re-fetch (recovery {} of {})",
                             empty_catalog_resets_, kMaxEmptyCatalogResets);
            }
            cursor = now;
        }
    }

    // On a fresh backfill start, pin the freshness cursor to now so that after a
    // multi-day backfill the first freshness pass re-checks everything modified
    // *during* the build, not just the last 2 days (UP-6).
    if (db_->get_meta("last_freshness_check").empty())
        db_->set_meta("last_freshness_check", std::to_string(epoch_secs(now)));

    std::size_t total = 0;

    while (cursor > floor && !stopping_.load()) {
        const auto window_start = (cursor - floor > max_window) ? cursor - max_window : floor;
        spdlog::info("NVD backfill: published {} .. {}", iso_of(window_start), iso_of(cursor));

        auto result = fetcher_->fetch_by_published_window(iso_of(window_start), iso_of(cursor));
        if (!result.ok) {
            // Transient error — leave the cursor so the next tick retries this window rather
            // than skipping unfetched CVEs (#1875). report_failure() warns with the reason and
            // increments yuzu_nvd_sync_failures_total (no-op on a shutdown cancel, #1880); also
            // surface it on /api/nvd/status so a PERSISTENT fetch failure (connection, HTTP
            // error, or a self-contradictory totalResults>0-but-empty page forced to ok=false in
            // parse_response) isn't silent (#1889 r5) — but not on a clean cancel.
            report_failure(result.reason, "backfill");
            if (!stopping_.load() && result.reason != NvdFailureReason::kCancelled) {
                std::lock_guard<std::mutex> lock{mu_};
                status_.last_error = std::string("NVD backfill fetch failed (") +
                                     nvd_reason_label(result.reason) +
                                     ") — retrying (mirror incomplete)";
            }
            return;
        }
        if (!result.records.empty()) {
            // Backfill passes nullptr: historical CVEs MUST NOT drive the freshness/feed
            // delta trigger — backfill has its own trigger (ADR-0023 Decision 6d).
            if (!db_->upsert_cves(result.records, nullptr)) {
                // Persist failed (BEGIN/COMMIT/rollback) — HOLD the cursor and retry next tick;
                // never advance past unpersisted CVEs (#1889 review r4). We deliberately do NOT
                // advance-and-drop after N tries: for a vuln mirror, silently dropping a window
                // is a PERMANENT false-negative (freshness only re-fetches by lastMod, so a
                // historical CVE is never recovered), whereas holding keeps backfill_complete()
                // false so the catalog correctly reports incomplete. A transient failure clears
                // on retry; a persistent one (catastrophic disk/corruption) fails SAFE — the
                // mirror stays incomplete and the error is surfaced on /api/nvd/status.
                spdlog::error("NVD backfill window persist failed — holding the cursor and "
                              "retrying; the mirror stays INCOMPLETE until it succeeds");
                {
                    std::lock_guard<std::mutex> lock{mu_};
                    status_.last_error = "NVD backfill window persist failed — mirror incomplete";
                }
                return;
            }
            total += result.records.size();
            empty_catalog_resets_ = 0;      // real NVD data landed — clear the recovery backstop
            empty_window_confirmations_ = 0; // ...and the suspicious-empty streak
        } else if (db_->nvd_cve_count() > 0) {
            // Empty window while the catalog ALREADY holds real NVD CVEs (nvd_cve_count is
            // all-time, so this also covers a resumed build across restarts) — SUSPICIOUS. A
            // stale cache/proxy can serve a well-formed empty page for a populated historical
            // range, and blindly advancing would skip those CVEs and could report the mirror
            // complete over a hole (#1889 review r5). Hold + re-confirm across a few ticks: a
            // transient anomaly returns data on retry (the hole is filled), while a genuinely-
            // empty window (e.g. near the 1999 floor, before NVD's earliest published CVE) is
            // accepted after kSuspiciousEmptyConfirmations so it never wedges. Advancing only on
            // a STABLY confirmed empty means no CVEs are dropped. Note the only empty shape that
            // reaches here is NVD's own totalResults==0 — parse_response forces a totalResults>0-
            // but-empty page to ok=false upstream, so we never "accept" a self-contradictory page.
            if (++empty_window_confirmations_ < kSuspiciousEmptyConfirmations) {
                spdlog::warn("NVD backfill: empty window ending {} after real data — re-confirming "
                             "({}/{}) before trusting it (holding cursor)",
                             iso_of(cursor), empty_window_confirmations_,
                             kSuspiciousEmptyConfirmations);
                {
                    std::lock_guard<std::mutex> lock{mu_};
                    status_.last_error = "re-confirming a suspicious empty NVD window (" +
                                         std::to_string(empty_window_confirmations_) + "/" +
                                         std::to_string(kSuspiciousEmptyConfirmations) + ")";
                }
                return; // hold — do not advance past a possibly-populated window
            }
            spdlog::info("NVD backfill: window ending {} confirmed empty after {} checks — "
                         "accepting as genuinely empty and advancing",
                         iso_of(cursor), empty_window_confirmations_);
            empty_window_confirmations_ = 0;
        }
        // (empty && nvd_cve_count()==0 → no data yet; nothing to skip past — the all-empty
        // recovery block above owns that case. Fall through and advance.)
        cursor = window_start;
        // Re-capture the wall clock per window so last_sync_time actually advances
        // during a multi-hour backfill (#1889 review r2). `now` is deliberately NOT
        // reassigned — the floor and cursor clamp stay pinned to the pass start; only
        // the "last progress" timestamp tracks real time.
        const auto window_now_iso = iso_of(std::chrono::system_clock::now());
        db_->set_meta("backfill_oldest_published", std::to_string(epoch_secs(cursor)));
        db_->set_meta("last_sync_time", window_now_iso); // persist so status survives restart (S1)
        // Compute the count OUTSIDE the status lock so a concurrent status()
        // reader never blocks on a SQLite query (cpp-safety SHOULD).
        const auto count = db_->total_cve_count();
        {
            std::lock_guard<std::mutex> lock{mu_};
            status_.total_cves = count;
            status_.last_sync_time = window_now_iso;
        }
    }

    if (cursor <= floor) {
        // No sticky "backfill_complete" flag is written: completion is DERIVED from the
        // persisted cursor vs the current floor (see backfill_complete()), so a later
        // config deepening correctly re-opens the backfill instead of trusting a flag
        // written under the old, shallower config (#1889 review r2). Gate the "complete"
        // log on the SAME content check backfill_complete() uses, so the log can never
        // claim "complete" while the status API / gauge correctly report incomplete over
        // an empty catalog (governance Gate 6 compliance).
        if (db_->nvd_cve_count() > 0) {
            spdlog::info("NVD backfill complete — floor reached ({} CVEs upserted this pass)",
                         total);
        } else {
            spdlog::warn("NVD backfill reached the floor but the catalog is EMPTY "
                         "(NVD returned no data?) — not reporting complete");
        }
    }
}

void NvdSyncManager::do_freshness() {
    const auto now = std::chrono::system_clock::now();
    const auto max_window = std::chrono::days(120);

    // Re-check everything modified since the last freshness pass, split into
    // <=120-day windows (fixes the >120-day incremental-range error). A future
    // last_freshness_check (backward clock skew or a manual DB edit) is treated as
    // missing and reset to the 2-day default, so the next window actually fetches
    // and re-advances the cursor to `now` — self-healing parity with the backfill
    // cursor's clamp (#1889). A bare std::min(cursor, now) would NOT self-heal here:
    // nvd_split_windows returns empty for start >= end, so a future cursor clamped
    // to `now` still yields no window and the stale future cursor would persist.
    const auto parsed =
        parse_cursor(db_->get_meta("last_freshness_check"), kNvdCatalogStartEpoch);
    if (parsed && *parsed > now)
        spdlog::warn("NVD freshness cursor is in the future (backward clock skew / manual edit) "
                     "— resetting to the 2-day default to self-heal");
    const auto start = (parsed && *parsed <= now) ? *parsed : (now - std::chrono::days(2));
    std::size_t total = 0;

    // The freshness/feed delta: the cve_ids persisted on this pass. Collected now so a
    // future feed trigger can consume it (ADR-0023 Decision 6d); no consumer wired yet.
    std::vector<std::string> changed;

    for (const auto& [ws, we] : nvd_split_windows(start, now, max_window)) {
        if (stopping_.load())
            return;
        auto result = fetcher_->fetch_modified_between(iso_of(ws), iso_of(we));
        if (!result.ok) {
            // report_failure() warns with the reason + increments the failure metric (no-op on
            // a shutdown cancel); also surface it on /api/nvd/status unless it's a clean cancel.
            report_failure(result.reason, "freshness");
            if (!stopping_.load() && result.reason != NvdFailureReason::kCancelled) {
                std::lock_guard<std::mutex> lock{mu_};
                status_.last_error =
                    std::string("NVD freshness fetch failed (") + nvd_reason_label(result.reason) +
                    ") — retrying";
            }
            return;
        }
        if (!result.records.empty()) {
            // Freshness passes &changed: these ARE the feed delta (ADR-0023 Decision 6d).
            if (!db_->upsert_cves(result.records, &changed)) {
                // Persist failed — HOLD last_freshness_check and retry; never advance past
                // unpersisted CVEs (dropping a modified CVE is a silent, permanent miss —
                // #1889 review r4). Fails SAFE: freshness stays behind and the error surfaces.
                spdlog::error("NVD freshness window persist failed — holding the cursor and "
                              "retrying; freshness stays behind until it succeeds");
                {
                    std::lock_guard<std::mutex> lock{mu_};
                    status_.last_error = "NVD freshness window persist failed";
                }
                return;
            }
            total += result.records.size();
        }
        // Advance only after a successful (fetched AND persisted) window. An ok+empty
        // freshness window is TRUSTED as verified-empty and advances — unlike do_backfill's
        // suspicious-empty hold, we do NOT re-confirm here: empty modified-since windows are
        // normal and common (quiet periods), so holding on them would stall freshness for
        // hours. parse_response still forces a self-contradictory totalResults>0-but-empty
        // page to ok=false (handled above), so only NVD's own totalResults==0 advances. The
        // residual — a stale cache serving totalResults==0 for a window that DID have lastMod
        // changes — is an inherent trust-NVD limitation (a missed update, not a missed CVE;
        // re-fetched if the CVE is modified again); see docs/vuln-scan-roadmap.md fast-follow.
        db_->set_meta("last_freshness_check", std::to_string(epoch_secs(we)));
    }

    db_->set_meta("last_sync_time", iso_of(now)); // persist for restart (S1)
    const auto count = db_->total_cve_count();     // off the status lock (cpp-safety)
    {
        std::lock_guard<std::mutex> lock{mu_};
        status_.total_cves = count;
        status_.last_sync_time = iso_of(now);
    }
    spdlog::info("NVD freshness re-check complete — {} CVEs updated", total);
}

} // namespace yuzu::server
