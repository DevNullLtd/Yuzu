/**
 * tar_power_collector.cpp -- make_power_cursor_source() (tar_cursor.hpp):
 * the "power" cursor-model TAR source (sleep/wake + AC-source transitions).
 *
 * Three OS legs, all pure-string/decision logic factored out to
 * tar_power_parsers.hpp so it unit-tests without a live subprocess/OS
 * subscription (tests/unit/test_tar_power.cpp):
 *
 *   macOS   -- flagship. `pmset -g log` polled once per collect() tick
 *              through run_bounded_subprocess (RunFn-injectable, same shape
 *              as tar_service_collector.cpp's launchctl/systemctl legs), and
 *              replayed via the P-007 EXACT-TAIL cursor model
 *              (tar_power_parsers.hpp). A pure-replay source: start()/stop()/
 *              on_enabled_changed() are no-ops per the CursorSource contract
 *              (tar_cursor.hpp).
 *   Windows -- live subscription only (no OS history API for sleep/wake or
 *              AC source). PowerRegisterSuspendResumeNotification +
 *              PowerSettingRegisterNotification callbacks push into the
 *              seam's BoundedPendingQueue and do nothing else; collect()
 *              snapshots, builds events, and acks ONLY after the
 *              insert_power_events_and_cursor transaction commits (P-003).
 *   Linux   -- live subscription for sleep/wake (sd-bus match on
 *              org.freedesktop.login1's PrepareForSleep, compile-gated
 *              YUZU_HAVE_LIBSYSTEMD) + a polled AC read
 *              (/sys/class/power_supply, per-supply "online" file) each
 *              tick, diffed against the persisted last_ac. Without libsystemd, sleep/wake is
 *              honestly unavailable (queue never populated) while AC diff
 *              still works.
 *
 * Every leg's cursor_json is produced by tar_power_parsers.hpp's codecs;
 * every leg calls TarDatabase::insert_power_events_and_cursor() itself from
 * inside collect() (tar_plugin.cpp's driver only orchestrates the enable
 * gate / cursor load / rule-1 retry, per tar_cursor.hpp's collect() doc).
 */

#include "tar_aggregator.hpp"     // yuzu::tar::source_enabled -- R-002 disabled-window guard on start()
#include "tar_capture_status.hpp" // yuzu::tar::{classify_subprocess_capture,IncompleteCaptureError}
#include "tar_cursor.hpp"         // yuzu::tar::{CursorSource,BoundedPendingQueue,make_power_cursor_source}
#include "tar_db.hpp"             // yuzu::tar::{TarDatabase,PowerEvent}
#include "tar_power_parsers.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <powrprof.h> // PowerRegisterSuspendResumeNotification / PowerSettingRegisterNotification
                      // (links `-lPowrProf`, wired in agents/plugins/tar/meson.build
                      // alongside this source file, both added by this PR)
#else
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess / probe_tool_path (ADR-3002 rung 2)

#include <chrono>
#include <functional>

#ifdef __linux__
#include <cerrno> // EINTR (sd_bus_wait error handling, R-015)
#include <filesystem>
#include <fstream>
#include <thread>
#ifdef YUZU_HAVE_LIBSYSTEMD
#include <systemd/sd-bus.h>
#endif
#endif
#endif

namespace yuzu::tar {

namespace {

std::int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

[[maybe_unused]] std::int64_t now_epoch_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Same shape as tar_plugin.cpp's own next_snapshot_id() (translation-unit
// local there, not reachable from this file) -- "groups events from same
// collection cycle" is a value field for every OTHER purpose (PowerEvent's
// doc, tar_db.hpp), so a locally-scoped equivalent formula is correct: it
// only needs to be distinct across ticks of THIS source, never coordinated
// with any other collector's snapshot_id sequence.
std::int64_t next_power_snapshot_id() {
    static std::atomic<std::int64_t> counter{0};
    return now_epoch_seconds() * 1000 + counter.fetch_add(1, std::memory_order_relaxed) % 1000;
}

std::int64_t power_lookback_seconds(TarDatabase& db) {
    // tar_cursor.hpp rule 5: a source that cannot READ its lookback treats it
    // as 0 (forward-only), never as the default -- db.get_config() returns
    // the caller's default on ANY read failure, so calling it directly here
    // turns a transient SQLite failure into a 7-day retrospective read on a
    // host where the operator set 0 precisely because that is not lawful
    // (PR #4017 review, blocker #1). lookback_seconds_or_forward_only()
    // floors at 0 on any read failure or malformed value; clamp still applies
    // the 90-day ceiling on top.
    return power_clamp_lookback(
        lookback_seconds_or_forward_only(db, "power", kPowerLookbackDefaultS));
}

} // namespace

// ============================================================================
// macOS -- pmset -g log (flagship cursor leg, rung 2, the run's ONLY spawn)
// ============================================================================
#if defined(__APPLE__)

// Finding-3-shaped seam (tar_service_collector.cpp's enumerate_services_impl
// precedent): production calls go through the real
// yuzu::agent::run_bounded_subprocess (the default argument on the factory
// below); a test injects a fixture double and calls mac_power_collect_impl
// directly so the REAL collect() body (probe_tool_path, argv,
// classify_subprocess_capture, IncompleteCaptureError, the exact-tail
// decision) is exercised, never a hand-simulated stand-in. Declared here
// (not in a header -- neither tar_cursor.hpp, which is frozen, nor a new
// header this package isn't scoped to add) purely as a same-translation-unit
// test seam: test_tar_power.cpp forward-declares this exact signature
// itself, the same way it would from a header.
using RunSubprocessFn = std::function<yuzu::agent::SubprocessResult(
    const std::vector<std::string>& argv, const yuzu::agent::SubprocessOptions& opts)>;

CursorCollectResult mac_power_collect_impl(TarDatabase& db,
                                           const std::optional<std::string>& cursor_json,
                                           const RunSubprocessFn& run,
                                           std::optional<std::string> forced_gap_reason = std::nullopt) {
    // tar/power_pmset#1 (docs/agent-spawn-sink-manifest.md): sleep/wake
    // history has no rung-1 public API on macOS -- `pmset -g log` is the
    // only source, read via the bounded runner (never popen).
    auto pmset_path = yuzu::agent::probe_tool_path({"/usr/bin/pmset"});
    if (pmset_path.empty()) {
        spdlog::error("TAR: power snapshot incomplete (pmset not found) -- retrying next tick");
        throw IncompleteCaptureError("TAR: pmset not found");
    }

    auto res = run({pmset_path, "-g", "log"},
                   yuzu::agent::SubprocessOptions{
                       .deadline = std::chrono::seconds{20},
                       .output_cap_bytes = 8 * 1024 * 1024,
                   });
    // zero_exit_required=true: `pmset -g log` exits 0 for a normal,
    // possibly-empty log read on this host (verified live, braga 26.5.1
    // arm64, 2026-09-04 -- the same run that produced
    // fixtures/power-macos-pmset.txt).
    auto status = yuzu::tar::classify_subprocess_capture(res.tool_ran, res.timed_out,
                                                          res.output_truncated, res.exit_code);
    // TRUNCATION IS NOT TRANSIENT, and rule 1 is the wrong response to it.
    //
    // Every other incomplete reason here -- the tool missing, a deadline, a
    // non-zero exit -- is a genuine transient: throwing retains the cursor and
    // the next tick may well succeed. Truncation is not. `pmset -g log` is
    // read from the start, so once the log exceeds the cap EVERY tick reads
    // the same first N bytes, classifies incomplete, and throws again: the
    // cursor never moves, no capture_gap is ever written, and the source is
    // permanently dead with a repeating log line as the only symptom. The log
    // grows monotonically with assertion churn, so this is a matter of time on
    // a long-lived host rather than a hypothetical.
    //
    // Rule 2 is the honest classification: the read cannot be trusted relative
    // to our stored position, so say so with a capture_gap and re-baseline
    // forward on what we did manage to read. The key is stable for the
    // condition, so a host that stays truncated shows ONE standing row rather
    // than one per tick.
    const bool truncated = res.output_truncated;
    if (!status.complete && !truncated) {
        spdlog::error("TAR: power snapshot incomplete (pmset {}) -- retrying next tick",
                      status.reason);
        throw IncompleteCaptureError("TAR: pmset capture incomplete: " + status.reason);
    }
    if (truncated) {
        spdlog::error("TAR: power pmset output exceeded the read cap -- reporting a capture gap "
                      "and re-baselining; sleep/wake history beyond the cap is not recoverable");
    }

    auto entries = parse_pmset_log(res.lines);

    bool had_prior_cursor = cursor_json.has_value();
    std::optional<MacPowerCursor> cursor;
    if (had_prior_cursor)
        cursor = decode_mac_power_cursor(*cursor_json);

    // A truncated read forces the gap-and-re-baseline path even when no
    // re-enable did. If BOTH apply, the re-enable reason wins -- it is the more
    // specific statement and the operator needs the pause named.
    //
    // truncation_owns_gap tracks whether THIS branch is the one that set
    // forced_gap_reason: truncation is a PERSISTENT condition (a host past the
    // cap stays past it every tick until the log is trimmed), so its gap key
    // must be time-independent -- see mac_power_gap_record_key_stable()
    // (PR #4017 review, should-fix #5). A re-enable-owned reason is a one-shot
    // event and keeps the existing now-keyed form.
    bool truncation_owns_gap = false;
    if (truncated && !forced_gap_reason.has_value()) {
        truncation_owns_gap = true;
        forced_gap_reason =
           "pmset -g log exceeded the agent's read cap, so this read could not be trusted "
           "relative to the stored position -- re-baselined forward; sleep/wake history beyond "
           "the cap was not captured";
    }

    auto decision = decide_mac_power_collect(entries, had_prior_cursor, cursor,
                                             power_lookback_seconds(db), now_epoch_seconds(),
                                             std::move(forced_gap_reason), truncation_owns_gap);

    // R-014: one snapshot_id per collection CYCLE (this tick), not per
    // event -- snapshot_id's documented purpose (PowerEvent, tar_db.hpp) is
    // to group every row this tick produced, which a per-event counter
    // defeats.
    const auto snapshot_id = next_power_snapshot_id();
    std::vector<PowerEvent> events;
    events.reserve(decision.events.size());
    for (auto& draft : decision.events) {
        PowerEvent ev;
        ev.ts = draft.ts;
        ev.snapshot_id = snapshot_id;
        ev.action = std::move(draft.action);
        ev.detail = std::move(draft.detail);
        ev.record_key = std::move(draft.record_key);
        events.push_back(std::move(ev));
    }
    auto new_cursor_json = encode_mac_power_cursor(decision.new_cursor);

    if (auto ins = db.insert_power_events_and_cursor(events, new_cursor_json); !ins) {
        // A KeyCollision is PERMANENT (tar_db.hpp): the source re-derives the
        // same batch every tick and the store refuses it every tick, so
        // retrying is not recovery -- it is a silent wedge with a repeating log
        // line. It means this source has violated rule 3(a) by persisting a
        // field that is not deterministically re-derivable, which is a bug
        // here, not a condition to wait out. Say so distinctly and loudly
        // rather than dressing it up as a transient.
        if (ins.error() == TarDatabase::CursorInsertError::KeyCollision) {
            spdlog::critical("TAR: power record_key COLLISION -- this source persisted a field "
                             "that is not deterministically re-derivable (rule 3a). Capture is "
                             "STUCK and retrying cannot clear it.");
            throw IncompleteCaptureError("TAR: power insert refused: record_key collision");
        }
        // Nothing committed -- the persisted cursor is unchanged, so a retry
        // next tick re-reads from the same position (rule 1).
        spdlog::error("TAR: power snapshot incomplete (insert_power_events_and_cursor failed) -- "
                      "retrying next tick");
        throw IncompleteCaptureError("TAR: power insert failed");
    }

    CursorCollectResult result;
    result.new_cursor_json = std::move(new_cursor_json);
    result.events_emitted = events.size();
    result.outcome = decision.cursor_lost ? CursorOutcome::CursorLost
                    : decision.is_baseline ? CursorOutcome::Baseline
                                            : CursorOutcome::Advanced;
    result.detail = decision.detail;
    return result;
}

namespace {

class MacPowerCursorSource : public CursorSource {
public:
    explicit MacPowerCursorSource(RunSubprocessFn run) : run_(std::move(run)) {}

    [[nodiscard]] std::string name() const noexcept override { return "power"; }

    // Pure-replay source (tar_cursor.hpp: "A no-op for a pure-replay source
    // that only reads a log on collect()") -- there is no live subscription
    // to arm/release/pause here, only a poll-and-parse on every tick.
    void start(TarDatabase&) override {}
    void stop() noexcept override {}

    // R-001: disable itself needs no action here -- the driver's
    // source_enabled gate (tar_plugin.cpp) already skips collect() entirely
    // while disabled, so no pmset line is ever read during the paused
    // window. But re-enable is NOT a no-op: tar_cursor.hpp's contract
    // requires the FIRST collect() after re-enable to re-baseline forward
    // and emit exactly one capture_gap, NEVER replay the disabled window's
    // real Sleep/Wake/Using-AC lines from the still-persisted cursor. Record
    // that one gap is owed; collect() clears it only once the tick that
    // reports it actually commits (mac_power_collect_impl throws
    // IncompleteCaptureError on a failed commit, so a failed attempt leaves
    // this flag set and retries next tick -- same rule-1 retry shape as
    // every other transient failure here).
    void on_enabled_changed(bool enabled) override {
        if (enabled) {
            owed_reenable_gap_.store(true, std::memory_order_release);
        } else {
            // Record the disable instant so the owed gap can name the window's
            // bounds, matching the Windows/Linux legs (PR #4017 review,
            // should-fix #6) -- previously this leg reported non-replay with
            // no since/until at all.
            disabled_at_ms_.store(now_epoch_ms(), std::memory_order_release);
        }
    }

    CursorCollectResult collect(TarDatabase& db,
                                const std::optional<std::string>& cursor_json) override {
        std::optional<std::string> forced_gap_reason;
        if (owed_reenable_gap_.load(std::memory_order_acquire)) {
            const auto since_ms = disabled_at_ms_.load(std::memory_order_acquire);
            forced_gap_reason =
                since_ms > 0
                    ? ("power source re-enabled -- the disabled window (" +
                       std::to_string(since_ms) +
                       "ms until now, epoch ms) is never replayed (forensic-pause contract)")
                    : "power source re-enabled -- the disabled window's pmset history is never "
                      "replayed (forensic-pause contract)";
        }
        auto result = mac_power_collect_impl(db, cursor_json, run_, forced_gap_reason);
        if (forced_gap_reason.has_value()) {
            owed_reenable_gap_.store(false, std::memory_order_release);
            disabled_at_ms_.store(0, std::memory_order_release);
        }
        return result;
    }

private:
    RunSubprocessFn run_;
    std::atomic<bool> owed_reenable_gap_{false};
    // 0 = no disable instant recorded (either never disabled, or already
    // consumed by a successful re-enable gap report above).
    std::atomic<std::int64_t> disabled_at_ms_{0};
};

} // namespace

std::unique_ptr<CursorSource> make_power_cursor_source() {
    return std::make_unique<MacPowerCursorSource>(yuzu::agent::run_bounded_subprocess);
}

// ============================================================================
// Windows -- live subscription only (no history API)
// ============================================================================
#elif defined(_WIN32)

namespace {

// One item pushed by an OS callback -- callbacks do NOTHING else (no DB, no
// allocation-heavy work, no shared locks beyond the queue's own), per the
// seam's rule 6 / P-003.
struct RawPowerItem {
    std::uint64_t seq{0};   // assigned at push time -- unique regardless of clock resolution
    std::int64_t ts{0};     // epoch seconds
    std::string kind;       // "sleep" | "wake" | "ac" | "batt"
};

class WindowsPowerCursorSource : public CursorSource {
public:
    // R-007: RAII -- if a later cursor source throws during plugin init (or
    // any other exceptional teardown), destruction must not leave a live
    // callback targeting a freed `this`.
    ~WindowsPowerCursorSource() override { stop(); }

    [[nodiscard]] std::string name() const noexcept override { return "power"; }

    void start(TarDatabase& db) override {
        // R-002: seed the disabled-window guard from the PERSISTED config on
        // every start() (including the very first one, at plugin init,
        // before any on_enabled_changed edge has ever fired) -- a process
        // that restarts with power_enabled=false must never buffer events
        // from callbacks the OS still delivers to this (kept-warm,
        // per tar_cursor.hpp) subscription while the app-level source is
        // disabled.
        enabled_.store(source_enabled(db, name()), std::memory_order_release);

        // RAII-owned before any early-exit check (P-002 handle-ownership
        // rule): both handles are member-owned from construction. Per-handle
        // null-guard (R-008) makes this safe to call repeatedly (retry) --
        // an already-armed handle is never re-registered, and a still-null
        // one is retried.
        std::lock_guard<std::mutex> lock(handle_mu_);
        if (!suspend_handle_) {
            DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS params{};
            params.Callback = &WindowsPowerCursorSource::suspend_resume_callback;
            params.Context = this;
            if (PowerRegisterSuspendResumeNotification(DEVICE_NOTIFY_CALLBACK, &params,
                                                        &suspend_handle_) != ERROR_SUCCESS) {
                spdlog::error("TAR: power PowerRegisterSuspendResumeNotification failed -- "
                              "will retry next tick");
                suspend_handle_ = nullptr;
            }
        }
        if (!acdc_handle_) {
            DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS acdc_params{};
            acdc_params.Callback = &WindowsPowerCursorSource::power_setting_callback;
            acdc_params.Context = this;
            if (PowerSettingRegisterNotification(&GUID_ACDC_POWER_SOURCE, DEVICE_NOTIFY_CALLBACK,
                                                 &acdc_params, &acdc_handle_) != ERROR_SUCCESS) {
                spdlog::error("TAR: power PowerSettingRegisterNotification failed -- "
                              "will retry next tick");
                acdc_handle_ = nullptr;
            }
        }
        // R-008: a partial/failed registration is not a permanent
        // false-success state -- retry on the very next collect() tick
        // until both handles are armed.
        needs_rearm_.store(suspend_handle_ == nullptr || acdc_handle_ == nullptr,
                           std::memory_order_release);
        // PR #4017 review, should-fix #4: stamp the ACTUAL arm instant, not
        // the instant some later collect() tick happens to notice it armed --
        // a restart's first tick can land tens of seconds after this, and a
        // future restart-gap calculation reading the tick-time stamp back
        // would overstate the outage by that much. Only stamp on the
        // false->true transition so a still-armed retry doesn't move it.
        if (suspend_handle_ && acdc_handle_ && !armed_at_ms_.has_value())
            armed_at_ms_ = now_epoch_ms();
    }

    void stop() noexcept override {
        std::lock_guard<std::mutex> lock(handle_mu_);
        if (suspend_handle_) {
            PowerUnregisterSuspendResumeNotification(suspend_handle_);
            suspend_handle_ = nullptr;
        }
        if (acdc_handle_) {
            PowerSettingUnregisterNotification(acdc_handle_);
            acdc_handle_ = nullptr;
        }
    }

    void on_enabled_changed(bool enabled) override {
        enabled_.store(enabled, std::memory_order_release); // R-002 callback gate
        if (!enabled) {
            // Disable: unregister so the paused window is never stored, and
            // drain-and-DISCARD anything already buffered (forensic-pause
            // parity, tar_cursor.hpp).
            stop();
            queue_.discard_all();
            disabled_at_ms_ = now_epoch_ms();
            armed_at_ms_.reset(); // re-arm on the next enable gets a fresh stamp
            return;
        }
        // Re-enable: re-arm the live subscription and record that exactly
        // one capture_gap is owed on the NEXT collect() tick (this method
        // has no `db` parameter to persist one directly -- see tar_cursor.hpp).
        // start() takes no db either, so re-registration happens lazily on
        // the next collect() if not already armed.
        //
        // Only the window's START is stamped here. The END is stamped in
        // collect(), and ONLY once is_armed() actually confirms the
        // subscription is live again -- stamping `until` at this instant (as
        // this used to) closes the gap before start() has even run, so the
        // table asserted continuous coverage for exactly the window it did
        // NOT have (PR #4017 review, blocker #3).
        if (disabled_at_ms_.has_value()) {
            // WIDEN, never replace. Two disable->enable cycles inside one
            // collect interval would otherwise overwrite the first window
            // (T1..T2) with the second (T3..T4), and T1..T2 -- a window during
            // which capture really was paused -- would never be reported at
            // all. The contract owes exactly one gap per disabled window; where
            // two windows fall inside one tick the honest single report is the
            // span that covers both.
            const std::int64_t since = *disabled_at_ms_;
            pending_gap_since_ms_ =
               pending_gap_since_ms_ ? std::min(*pending_gap_since_ms_, since) : since;
            disabled_at_ms_.reset();
        }
        std::lock_guard<std::mutex> lock(handle_mu_);
        needs_rearm_.store(suspend_handle_ == nullptr || acdc_handle_ == nullptr,
                           std::memory_order_release);
    }

    CursorCollectResult collect(TarDatabase& db,
                                const std::optional<std::string>& cursor_json) override {
        if (needs_rearm_.exchange(false, std::memory_order_acq_rel))
            start(db);

        // Close a pending re-enable gap only once the subscription is
        // ACTUALLY re-armed (PR #4017 review, blocker #3) -- see
        // on_enabled_changed()'s comment. A tick where start() just failed
        // (still not armed) leaves pending_gap_until_ms_ unset, so no gap row
        // is emitted yet and the next tick's rearm attempt gets another
        // chance; the ever-present unarmed_gap_reason below covers "no
        // coverage right now" in the meantime.
        if (pending_gap_since_ms_.has_value() && !pending_gap_until_ms_.has_value() &&
            is_armed())
            pending_gap_until_ms_ = armed_at_ms_.value_or(now_epoch_ms());

        bool had_prior_cursor = cursor_json.has_value();
        auto decoded = decode_subscription_ac_cursor("subscribed_since_ms",
                                                      cursor_json.value_or("{}"));

        // R-004: a PRESENT-but-malformed subscription key is data
        // corruption -- report an input-specific gap and re-baseline,
        // rather than silently re-seeding as if nothing had ever been
        // subscribed. R-003: a PRESENT-and-valid key from BEFORE this
        // process's own life means the live subscription cannot have
        // survived the restart (no OS history API backfills it) -- report
        // the elapsed window as a gap, and only close it out (advance the
        // persisted since-time to now) once actually (re-)armed, so a
        // start() that is still retrying keeps re-reporting the same
        // window instead of understating it.
        std::optional<std::string> subscription_gap_reason;
        std::optional<std::int64_t> restart_gap_since_ms;
        std::int64_t subscribed_since_ms;
        if (decoded.subscription_present && !decoded.subscription_valid) {
            subscription_gap_reason =
                "power subscription cursor corrupt -- re-armed at current time";
            subscribed_since_ms = now_epoch_ms();
        } else if (decoded.subscription_present && decoded.subscription_valid &&
                   decoded.subscribed_since_ms > 0 &&
                   decoded.subscribed_since_ms < this_run_start_ms_) {
            // PR #4017 review, should-fix #4: name the window from whichever
            // lower bound is LATER (tighter/more honest) -- the persisted
            // subscription-start can be days old, but power_last_collect_ts
            // (tar_plugin.cpp, written by the driver after every committed
            // tick) is a positive "we know this source was working AT LEAST
            // until here" heartbeat. Taking the max never understates the
            // gap, only avoids overstating it. A read failure/absent key
            // yields 0 and falls back to the old bound unchanged.
            std::int64_t last_collect_ms = 0;
            try {
                last_collect_ms = std::stoll(db.get_config("power_last_collect_ts", "0")) * 1000;
            } catch (...) {
            }
            restart_gap_since_ms = std::max(decoded.subscribed_since_ms, last_collect_ms);
            subscribed_since_ms =
                is_armed() ? armed_at_ms_.value_or(now_epoch_ms()) : decoded.subscribed_since_ms;
        } else if (decoded.subscription_present && decoded.subscription_valid &&
                   decoded.subscribed_since_ms > 0) {
            subscribed_since_ms = decoded.subscribed_since_ms; // continuous, healthy
        } else {
            subscribed_since_ms = now_epoch_ms(); // never subscribed before -- fresh, no gap
        }

        // One row, not one per tick: the key encodes the window start, so the
        // store's record_key dedupe collapses every later tick onto it while
        // the source stays unarmed.
        std::optional<std::string> unarmed_gap_reason;
        if (!is_armed()) {
            unarmed_gap_reason =
               "power sleep/wake subscription is NOT armed "
               "(PowerRegisterSuspendResumeNotification / PowerSettingRegisterNotification did "
               "not register) -- sleep and wake transitions cannot be captured on this host and "
               "no row will appear for them; AC attach/detach is unaffected";
        }


        std::optional<std::string> ac_gap_reason;
        std::string last_ac;
        if (decoded.ac_present && !decoded.ac_valid) {
            ac_gap_reason = "power AC-state cursor corrupt -- state re-seeded";
            last_ac = "unknown";
        } else if (decoded.ac_present && decoded.ac_valid) {
            last_ac = decoded.last_ac;
        } else {
            last_ac = "unknown";
        }

        auto batch = queue_.snapshot_batch();

        SubscriptionTickInputs tick_in;
        tick_in.leg_tag = "winpower";
        tick_in.run_nonce_ms = this_run_start_ms_;
        tick_in.items.reserve(batch.items.size());
        for (const auto& item : batch.items)
            tick_in.items.push_back(SubscriptionRawItem{item.seq, item.ts, item.kind});
        tick_in.last_ac = last_ac;
        tick_in.pending_gap_since_ms = pending_gap_since_ms_;
        tick_in.pending_gap_until_ms = pending_gap_until_ms_;
        // Captured BEFORE the post-commit reset below: a pending gap whose
        // `until` is still unset (not yet re-armed) must survive this tick --
        // resetting pending_gap_since_ms_ unconditionally here would silently
        // drop the gap's start marker before it was ever reported, on any
        // tick that commits successfully for OTHER reasons while still
        // unarmed (PR #4017 review, blocker #3 follow-through).
        const bool gap_reported_this_tick = pending_gap_until_ms_.has_value();
        tick_in.subscription_gap_reason = subscription_gap_reason;
        tick_in.unarmed_gap_reason = unarmed_gap_reason;
        tick_in.unarmed_since_ms = subscribed_since_ms;
        tick_in.restart_gap_since_ms = restart_gap_since_ms;
        tick_in.ac_gap_reason = ac_gap_reason;
        tick_in.dropped_total = queue_.dropped();
        tick_in.last_reported_dropped = last_reported_dropped_;
        tick_in.now = now_epoch_seconds();
        tick_in.sleep_wake_detail =
            "OS suspend/resume notification (PowerRegisterSuspendResumeNotification)";
        tick_in.ac_detail = "GUID_ACDC_POWER_SOURCE setting-change notification";
        auto tick = build_subscription_tick_events(tick_in);
        last_ac = tick.new_last_ac;

        // R-014: one snapshot_id per collection CYCLE (this tick), not per
        // event.
        const auto snapshot_id = next_power_snapshot_id();
        std::vector<PowerEvent> events;
        events.reserve(tick.events.size());
        for (auto& draft : tick.events) {
            PowerEvent ev;
            ev.ts = draft.ts;
            ev.snapshot_id = snapshot_id;
            ev.action = std::move(draft.action);
            ev.detail = std::move(draft.detail);
            ev.record_key = std::move(draft.record_key);
            events.push_back(std::move(ev));
        }
        auto dropped_now = tick_in.dropped_total;

        auto new_cursor_json =
            encode_subscription_ac_cursor("subscribed_since_ms", subscribed_since_ms, last_ac);

        if (auto ins = db.insert_power_events_and_cursor(events, new_cursor_json); !ins) {
        // A KeyCollision is PERMANENT (tar_db.hpp): the source re-derives the
        // same batch every tick and the store refuses it every tick, so
        // retrying is not recovery -- it is a silent wedge with a repeating log
        // line. It means this source has violated rule 3(a) by persisting a
        // field that is not deterministically re-derivable, which is a bug
        // here, not a condition to wait out. Say so distinctly and loudly
        // rather than dressing it up as a transient.
            if (ins.error() == TarDatabase::CursorInsertError::KeyCollision) {
                spdlog::critical("TAR: power record_key COLLISION -- this source persisted a "
                                 "field that is not deterministically re-derivable (rule 3a). "
                                 "Capture is STUCK and retrying cannot clear it.");
                throw IncompleteCaptureError("TAR: power insert refused: record_key collision");
            }
            spdlog::error("TAR: power snapshot incomplete (insert_power_events_and_cursor failed) "
                          "-- retrying next tick");
            throw IncompleteCaptureError("TAR: power insert failed");
        }
        // P-003: ack (and clear the gap owed / advance the dropped baseline)
        // ONLY after the commit above succeeded. subscription_gap_reason /
        // restart_gap_since_ms / ac_gap_reason need no equivalent reset:
        // they are recomputed from the persisted cursor_json every tick, so
        // a failed commit naturally retries the identical gap next tick,
        // and a successful one persists the fixed-up cursor that stops
        // reproducing it.
        //
        // ack_through() is identity-based (R-005, tar_cursor.hpp): an entry
        // a callback pushes into the queue after this tick's snapshot_batch()
        // has a larger internal sequence number than `batch.last_seq` and so
        // can never be removed here, regardless of any overflow eviction in
        // between.
        queue_.ack_through(batch.last_seq);
        if (gap_reported_this_tick) {
            pending_gap_since_ms_.reset();
            pending_gap_until_ms_.reset();
        }
        last_reported_dropped_ = dropped_now;

        CursorCollectResult result;
        result.new_cursor_json = std::move(new_cursor_json);
        result.events_emitted = events.size();
        result.outcome = !had_prior_cursor        ? CursorOutcome::Baseline
                        : !events.empty() && events.front().action == "capture_gap"
                              ? CursorOutcome::CursorLost
                              : CursorOutcome::Advanced;
        result.detail = "windows live subscription";
        return result;
    }

private:
    static ULONG CALLBACK suspend_resume_callback(PVOID context, ULONG type, PVOID /*setting*/) {
        auto* self = static_cast<WindowsPowerCursorSource*>(context);
        try {
            // R-002: never buffer an event the OS delivers while the
            // app-level source is disabled -- callbacks do NOTHING but
            // push, so this check (a relaxed atomic read, no lock beyond
            // the queue's own) is the only gate available here.
            if (!self->enabled_.load(std::memory_order_acquire))
                return ERROR_SUCCESS;
            if (type == PBT_APMSUSPEND) {
                self->queue_.push(RawPowerItem{self->next_seq(), now_epoch_seconds(), "sleep"});
                self->wake_pending_.store(true, std::memory_order_release);
            } else if (type == PBT_APMRESUMESUSPEND || type == PBT_APMRESUMEAUTOMATIC) {
                // Windows can broadcast BOTH resume types for one real wake
                // (PR #4017 review, minor #8) -- only the first resume
                // notification after a suspend produces a row; a second one
                // for the same wake is suppressed rather than double-counted.
                if (self->wake_pending_.exchange(false, std::memory_order_acq_rel))
                    self->queue_.push(RawPowerItem{self->next_seq(), now_epoch_seconds(), "wake"});
            }
        } catch (...) {
            // R-006: an OS C callback boundary must never let an exception
            // (e.g. std::bad_alloc from the queue's internal allocation)
            // unwind across it -- best-effort swallow.
        }
        return ERROR_SUCCESS;
    }

    static ULONG CALLBACK power_setting_callback(PVOID context, ULONG /*type*/, PVOID setting) {
        auto* self = static_cast<WindowsPowerCursorSource*>(context);
        try {
            if (!self->enabled_.load(std::memory_order_acquire))
                return ERROR_SUCCESS;
            auto* pbs = static_cast<POWERBROADCAST_SETTING*>(setting);
            if (!pbs || pbs->PowerSetting != GUID_ACDC_POWER_SOURCE || pbs->DataLength < 1)
                return ERROR_SUCCESS;
            // Data[0]: 0 = AC, 1 = battery, 2 = short-term (treated as
            // battery -- it is still "not on AC" for this source's
            // purposes).
            const char* kind = pbs->Data[0] == 0 ? "ac" : "batt";
            self->queue_.push(RawPowerItem{self->next_seq(), now_epoch_seconds(), kind});
        } catch (...) { // R-006, see above
        }
        return ERROR_SUCCESS;
    }

    std::uint64_t next_seq() { return seq_.fetch_add(1, std::memory_order_relaxed); }

    bool is_armed() {
        std::lock_guard<std::mutex> lock(handle_mu_);
        return suspend_handle_ != nullptr && acdc_handle_ != nullptr;
    }

    std::atomic<std::uint64_t> seq_{0};
    BoundedPendingQueue<RawPowerItem> queue_;
    std::mutex handle_mu_;
    HPOWERNOTIFY suspend_handle_{nullptr};
    HPOWERNOTIFY acdc_handle_{nullptr};
    std::atomic<bool> needs_rearm_{false};
    // Suppresses a second "wake" row when Windows broadcasts both
    // PBT_APMRESUMESUSPEND and PBT_APMRESUMEAUTOMATIC for one real resume
    // (minor #8) -- set on suspend, consumed by the first resume after it.
    std::atomic<bool> wake_pending_{false};
    std::atomic<bool> enabled_{true}; // seeded from persisted config in start()
    std::optional<std::int64_t> disabled_at_ms_;
    // Set by start() only on the false->true arm transition; cleared on
    // disable. The honest "actually armed at" instant (should-fix #4).
    std::optional<std::int64_t> armed_at_ms_;
    std::optional<std::int64_t> pending_gap_since_ms_;
    std::optional<std::int64_t> pending_gap_until_ms_;
    std::size_t last_reported_dropped_{0};
    // R-003: this process life's own start time, captured once at
    // construction -- a persisted subscribed_since_ms strictly older than
    // this can only be a carry-over from a PREVIOUS run, which is what
    // identifies a restart (see collect() above). Deliberately a
    // constructor-time constant, not re-derived in start(), so a start()
    // retry (R-008) does not move the goalposts.
    const std::int64_t this_run_start_ms_{now_epoch_ms()};
};

} // namespace

std::unique_ptr<CursorSource> make_power_cursor_source() {
    return std::make_unique<WindowsPowerCursorSource>();
}

// ============================================================================
// Linux -- sd-bus PrepareForSleep (compile-gated YUZU_HAVE_LIBSYSTEMD) + a
// polled AC read every tick.
// ============================================================================
#elif defined(__linux__)

namespace {

struct RawPowerItem {
    std::uint64_t seq{0};
    std::int64_t ts{0};
    std::string kind; // "sleep" | "wake"
};

// Pure-ish helper (kept here rather than tar_power_parsers.hpp because it
// touches /sys, unlike everything in that header): read the host's current
// AC-source state from /sys/class/power_supply/*/online. Returns "unknown"
// if no AC-type supply is found or none is readable -- an absent/unreadable
// sysfs tree is not an error for this source (AC diff simply stays silent
// until a reading is available), consistent with removable-media's USBSTOR
// absence-tolerance precedent.
std::string linux_read_ac_state() {
    namespace fs = std::filesystem;
    std::error_code ec;
    const fs::path base{"/sys/class/power_supply"};
    if (!fs::exists(base, ec))
        return "unknown";
    // R-013: aggregate across EVERY readable Mains/USB supply rather than
    // returning the first one's state -- a multi-supply host (e.g. a
    // Mains adapter plus a USB-PD dock) with one offline supply and another
    // genuinely online must report "ac", not mask it behind whichever
    // directory iteration happened to visit first.
    bool any_readable = false;
    for (const auto& entry : fs::directory_iterator(base, ec)) {
        if (ec)
            break;
        auto type_path = entry.path() / "type";
        std::ifstream type_file(type_path);
        std::string type;
        if (!type_file || !std::getline(type_file, type))
            continue;
        if (type != "Mains" && type != "USB")
            continue; // only AC-ish supplies answer "are we on mains power"
        auto online_path = entry.path() / "online";
        std::ifstream online_file(online_path);
        std::string online;
        if (!online_file || !std::getline(online_file, online))
            continue;
        any_readable = true;
        if (online == "1")
            return "ac"; // any AC-ish supply online -> on mains, full stop
    }
    return any_readable ? "batt" : "unknown";
}

class LinuxPowerCursorSource : public CursorSource {
public:
    ~LinuxPowerCursorSource() override { stop(); } // R-007

    [[nodiscard]] std::string name() const noexcept override { return "power"; }

    void start(TarDatabase& db) override {
        enabled_.store(source_enabled(db, name()), std::memory_order_release); // R-002
#ifdef YUZU_HAVE_LIBSYSTEMD
        std::lock_guard<std::mutex> lock(thread_mu_);
        if (arm_failed_.exchange(false, std::memory_order_acq_rel) && bus_thread_.joinable()) {
            // R-008: the previous attempt's worker already returned (a
            // finished std::thread is still joinable() until joined) --
            // reap it before retrying so a transient arming failure is not
            // permanent.
            bus_thread_.join();
        }
        if (bus_thread_.joinable())
            return;
        stop_requested_.store(false, std::memory_order_release);
        // tar_cursor.hpp: "start() ... throw[s] nothing at all" -- std::thread's
        // constructor can throw std::system_error (resource_unavailable_try_again)
        // if the OS refuses to create the thread. The driver's generic catch
        // backstops it either way, but start() should honor its own contract
        // rather than rely on that (PR #4017 review, minor #11): treat a failed
        // spawn exactly like a failed sd_bus_open_system -- arm_failed_ so
        // collect() retries next tick, no exception escapes.
        try {
            bus_thread_ = std::thread(&LinuxPowerCursorSource::bus_loop, this);
        } catch (const std::exception& e) {
            spdlog::error("TAR: power std::thread spawn failed ({}) -- will retry next tick",
                          e.what());
            arm_failed_.store(true, std::memory_order_release);
        }
#endif
    }

    void stop() noexcept override {
#ifdef YUZU_HAVE_LIBSYSTEMD
        std::lock_guard<std::mutex> lock(thread_mu_);
        stop_requested_.store(true, std::memory_order_release);
        if (bus_thread_.joinable())
            bus_thread_.join();
#endif
    }

    void on_enabled_changed(bool enabled) override {
        enabled_.store(enabled, std::memory_order_release); // R-002 callback gate
        if (!enabled) {
            stop();
            queue_.discard_all();
            disabled_at_ms_ = now_epoch_ms();
            armed_at_ms_.store(0, std::memory_order_release); // fresh stamp on next arm
            return;
        }
        // Only the window's START is stamped here. The END is stamped in
        // collect(), and ONLY once is_armed() confirms sd_bus_match_signal
        // actually re-registered -- stamping `until` at this instant (as this
        // used to) closes the gap before the bus thread has even respawned
        // (PR #4017 review, blocker #3, same defect as the Windows leg).
        if (disabled_at_ms_.has_value()) {
            // WIDEN, never replace. Two disable->enable cycles inside one
            // collect interval would otherwise overwrite the first window
            // (T1..T2) with the second (T3..T4), and T1..T2 -- a window during
            // which capture really was paused -- would never be reported at
            // all. The contract owes exactly one gap per disabled window; where
            // two windows fall inside one tick the honest single report is the
            // span that covers both.
            const std::int64_t since = *disabled_at_ms_;
            pending_gap_since_ms_ =
               pending_gap_since_ms_ ? std::min(*pending_gap_since_ms_, since) : since;
            disabled_at_ms_.reset();
        }
        needs_rearm_.store(true, std::memory_order_release);
    }

    CursorCollectResult collect(TarDatabase& db,
                                const std::optional<std::string>& cursor_json) override {
        // R-008/R-015: retry a failed/dead worker every tick, same as the
        // toggle-driven re-arm path.
        if (arm_failed_.load(std::memory_order_acquire))
            needs_rearm_.store(true, std::memory_order_release);
        if (needs_rearm_.exchange(false, std::memory_order_acq_rel))
            start(db);

        // Close a pending re-enable gap only once actually re-armed
        // (PR #4017 review, blocker #3) -- see on_enabled_changed()'s comment.
        if (pending_gap_since_ms_.has_value() && !pending_gap_until_ms_.has_value() &&
            is_armed()) {
            const auto a = armed_at_ms_.load(std::memory_order_acquire);
            pending_gap_until_ms_ = a != 0 ? a : now_epoch_ms();
        }

        bool had_prior_cursor = cursor_json.has_value();
        auto decoded =
            decode_subscription_ac_cursor("armed_since_ms", cursor_json.value_or("{}"));

        // Same shape as the Windows leg (R-003/R-004) -- see its collect()
        // for the full rationale.
        //
        // An UNARMED source never advances armed_since_ms. On a build without
        // libsystemd, or before sd_bus_match_signal has registered, or after a
        // mid-run bus loss, sleep/wake cannot be captured at all -- so the
        // window of missed coverage keeps growing and is reported as such. It
        // used to close the gap here and then fall silent, which made
        // $Power_Live read as continuous sleep/wake coverage on a host that
        // could never produce a single sleep or wake row. The AC leg is
        // unaffected: it is a polled sysfs read and keeps working.
        std::optional<std::string> subscription_gap_reason;
        std::optional<std::int64_t> restart_gap_since_ms;
        std::int64_t armed_since_ms;
        if (decoded.subscription_present && !decoded.subscription_valid) {
            subscription_gap_reason =
                "power subscription cursor corrupt -- re-armed at current time";
            armed_since_ms = now_epoch_ms();
        } else if (decoded.subscription_present && decoded.subscription_valid &&
                   decoded.subscribed_since_ms > 0 &&
                   decoded.subscribed_since_ms < this_run_start_ms_) {
            // PR #4017 review, should-fix #4: same fix as the Windows leg --
            // name the window from whichever lower bound is LATER (tighter),
            // using power_last_collect_ts as a positive "known working until
            // here" heartbeat instead of trusting only the possibly-stale
            // persisted subscription-start.
            std::int64_t last_collect_ms = 0;
            try {
                last_collect_ms = std::stoll(db.get_config("power_last_collect_ts", "0")) * 1000;
            } catch (...) {
            }
            restart_gap_since_ms = std::max(decoded.subscribed_since_ms, last_collect_ms);
            {
                const auto a = armed_at_ms_.load(std::memory_order_acquire);
                armed_since_ms = is_armed() ? (a != 0 ? a : now_epoch_ms())
                                            : decoded.subscribed_since_ms;
            }
        } else if (decoded.subscription_present && decoded.subscription_valid &&
                   decoded.subscribed_since_ms > 0) {
            armed_since_ms = decoded.subscribed_since_ms;
        } else {
            armed_since_ms = now_epoch_ms();
        }

        std::optional<std::string> ac_gap_reason;
        std::string last_ac;
        if (decoded.ac_present && !decoded.ac_valid) {
            ac_gap_reason = "power AC-state cursor corrupt -- state re-seeded";
            last_ac = "unknown";
        } else if (decoded.ac_present && decoded.ac_valid) {
            last_ac = decoded.last_ac;
        } else {
            last_ac = "unknown";
        }

        auto batch = queue_.snapshot_batch();
        auto now = now_epoch_seconds();

        // AC has no push source on Linux: fold the current poll reading in
        // as one more synthetic queue item (seq 0 -- ac/batt items never use
        // seq for uniqueness beyond "this tick's one reading", unlike
        // sleep/wake) so it goes through the exact same state-change-driven
        // decision as every other leg's AC handling.
        auto current_ac = linux_read_ac_state();

        // Same statement as the Windows leg: a source that is NOT armed says
        // so, once, rather than falling silent and reading as continuous
        // coverage. Keyed on the window start (unarmed_since_ms below) so the
        // store's record_key dedupe collapses every later tick onto one row.
        std::optional<std::string> unarmed_gap_reason;
        if (!is_armed()) {
            unarmed_gap_reason =
               "power sleep/wake subscription is NOT armed (no libsystemd in this build, or "
               "logind unreachable) -- sleep and wake transitions cannot be captured on this "
               "host and no row will appear for them; AC attach/detach is unaffected";
        }

        SubscriptionTickInputs tick_in;
        tick_in.leg_tag = "linuxpower";
        tick_in.run_nonce_ms = this_run_start_ms_;
        tick_in.items.reserve(batch.items.size() + 1);
        for (const auto& item : batch.items)
            tick_in.items.push_back(SubscriptionRawItem{item.seq, item.ts, item.kind});
        if (current_ac != "unknown")
            tick_in.items.push_back(SubscriptionRawItem{static_cast<std::uint64_t>(now), now, current_ac});
        tick_in.last_ac = last_ac;
        tick_in.pending_gap_since_ms = pending_gap_since_ms_;
        tick_in.pending_gap_until_ms = pending_gap_until_ms_;
        // Captured BEFORE the post-commit reset below -- see the Windows
        // leg's identical guard for the full rationale (PR #4017 review,
        // blocker #3 follow-through).
        const bool gap_reported_this_tick = pending_gap_until_ms_.has_value();
        tick_in.subscription_gap_reason = subscription_gap_reason;
        tick_in.unarmed_gap_reason = unarmed_gap_reason;
        tick_in.unarmed_since_ms = armed_since_ms;
        tick_in.restart_gap_since_ms = restart_gap_since_ms;
        tick_in.ac_gap_reason = ac_gap_reason;
        tick_in.dropped_total = queue_.dropped();
        tick_in.last_reported_dropped = last_reported_dropped_;
        tick_in.now = now;
        tick_in.sleep_wake_detail = "logind PrepareForSleep sd-bus signal";
        tick_in.ac_detail = "/sys/class/power_supply AC-source poll";
        auto tick = build_subscription_tick_events(tick_in);
        last_ac = tick.new_last_ac;

        // R-014: one snapshot_id per collection CYCLE (this tick), not per
        // event.
        const auto snapshot_id = next_power_snapshot_id();
        std::vector<PowerEvent> events;
        events.reserve(tick.events.size());
        for (auto& draft : tick.events) {
            PowerEvent ev;
            ev.ts = draft.ts;
            ev.snapshot_id = snapshot_id;
            ev.action = std::move(draft.action);
            ev.detail = std::move(draft.detail);
            ev.record_key = std::move(draft.record_key);
            events.push_back(std::move(ev));
        }
        auto dropped_now = tick_in.dropped_total;

        auto new_cursor_json =
            encode_subscription_ac_cursor("armed_since_ms", armed_since_ms, last_ac);

        if (auto ins = db.insert_power_events_and_cursor(events, new_cursor_json); !ins) {
        // A KeyCollision is PERMANENT (tar_db.hpp): the source re-derives the
        // same batch every tick and the store refuses it every tick, so
        // retrying is not recovery -- it is a silent wedge with a repeating log
        // line. It means this source has violated rule 3(a) by persisting a
        // field that is not deterministically re-derivable, which is a bug
        // here, not a condition to wait out. Say so distinctly and loudly
        // rather than dressing it up as a transient.
            if (ins.error() == TarDatabase::CursorInsertError::KeyCollision) {
                spdlog::critical("TAR: power record_key COLLISION -- this source persisted a "
                                 "field that is not deterministically re-derivable (rule 3a). "
                                 "Capture is STUCK and retrying cannot clear it.");
                throw IncompleteCaptureError("TAR: power insert refused: record_key collision");
            }
            spdlog::error("TAR: power snapshot incomplete (insert_power_events_and_cursor failed) "
                          "-- retrying next tick");
            throw IncompleteCaptureError("TAR: power insert failed");
        }
        // P-003 ack-after-commit; see the Windows leg's identical call site
        // for the identity-based ack_through() rationale (R-005).
        queue_.ack_through(batch.last_seq);
        if (gap_reported_this_tick) {
            pending_gap_since_ms_.reset();
            pending_gap_until_ms_.reset();
        }
        last_reported_dropped_ = dropped_now;

        CursorCollectResult result;
        result.new_cursor_json = std::move(new_cursor_json);
        result.events_emitted = events.size();
        result.outcome = !had_prior_cursor        ? CursorOutcome::Baseline
                        : !events.empty() && events.front().action == "capture_gap"
                              ? CursorOutcome::CursorLost
                              : CursorOutcome::Advanced;
#ifdef YUZU_HAVE_LIBSYSTEMD
        result.detail = "linux live subscription (libsystemd)";
#else
        result.detail = "linux: sleep/wake unavailable (built without libsystemd) -- AC diff only";
#endif
        return result;
    }

private:
#ifdef YUZU_HAVE_LIBSYSTEMD
    static int prepare_for_sleep_handler(sd_bus_message* m, void* userdata, sd_bus_error*) {
        auto* self = static_cast<LinuxPowerCursorSource*>(userdata);
        try {
            if (!self->enabled_.load(std::memory_order_acquire)) // R-002
                return 0;
            int starting = 0;
            if (sd_bus_message_read(m, "b", &starting) < 0)
                return 0;
            self->queue_.push(RawPowerItem{self->next_seq(), now_epoch_seconds(),
                                           starting ? "sleep" : "wake"});
        } catch (...) { // R-006, see the Windows leg's callback for rationale
        }
        return 0;
    }

    void bus_loop() {
        sd_bus* bus = nullptr;
        if (sd_bus_open_system(&bus) < 0) {
            spdlog::error("TAR: power sd_bus_open_system failed -- sleep/wake unavailable this run");
            arm_failed_.store(true, std::memory_order_release); // R-008: retry, not permanent
            return;
        }
        sd_bus_slot* slot = nullptr;
        int rc = sd_bus_match_signal(bus, &slot, "org.freedesktop.login1",
                                     "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
                                     "PrepareForSleep", &LinuxPowerCursorSource::prepare_for_sleep_handler,
                                     this);
        if (rc < 0) {
            spdlog::error("TAR: power sd_bus_match_signal(PrepareForSleep) failed -- sleep/wake "
                          "unavailable this run");
            sd_bus_unref(bus);
            arm_failed_.store(true, std::memory_order_release); // R-008
            return;
        }
        // The match is registered: from here a PrepareForSleep signal can
        // actually reach us, and only now is this source honestly "armed".
        arm_confirmed_.store(true, std::memory_order_release);
        armed_at_ms_.store(now_epoch_ms(), std::memory_order_release); // should-fix #4
        while (!stop_requested_.load(std::memory_order_acquire)) {
            // R-015: a negative return is a real bus error (e.g. logind/
            // dbus-daemon disconnected mid-run), not a transient "nothing
            // to do" -- treat it exactly like a failed initial arm so
            // collect() retries (join + respawn) rather than spinning this
            // thread forever against a dead connection.
            int process_rc = sd_bus_process(bus, nullptr);
            if (process_rc < 0) {
                spdlog::error("TAR: power sd_bus_process failed (rc={}) -- bus disconnected, "
                              "sleep/wake unavailable until re-arm",
                              process_rc);
                arm_failed_.store(true, std::memory_order_release);
                arm_confirmed_.store(false, std::memory_order_release);
                armed_at_ms_.store(0, std::memory_order_release);
                break;
            }
            if (process_rc > 0)
                continue; // more messages may be immediately pending
            // Bounded wait so stop_requested_ is re-checked promptly --
            // stop() must return quickly (it is called under tar_plugin.cpp's
            // shutdown() collect_mu_, which must never stall on this thread).
            int wait_rc = sd_bus_wait(bus, 200'000); // 200ms, microseconds
            if (wait_rc < 0 && wait_rc != -EINTR) {
                spdlog::error("TAR: power sd_bus_wait failed (rc={}) -- bus disconnected, "
                              "sleep/wake unavailable until re-arm",
                              wait_rc);
                arm_failed_.store(true, std::memory_order_release);
                arm_confirmed_.store(false, std::memory_order_release);
                armed_at_ms_.store(0, std::memory_order_release);
                break;
            }
        }
        sd_bus_slot_unref(slot);
        sd_bus_unref(bus);
    }
#endif

    std::uint64_t next_seq() { return seq_.fetch_add(1, std::memory_order_relaxed); }

    // A POSITIVE acknowledgement, not an inference from thread liveness.
    //
    // This used to return true on a build without libsystemd -- reasoning that
    // there is no subscription to wait on, so a carried-over restart gap should
    // close rather than repeat forever. The consequence was the opposite of
    // honest: armed_since_ms advanced to now, the restart gap closed, and no
    // capture_gap was ever emitted again. $Power_Live then read as CONTINUOUS
    // sleep/wake coverage on a build that can never capture a sleep or a wake.
    //
    // With libsystemd it also used to infer arming from `bus_thread_.joinable()`,
    // which is true the instant the thread is spawned and long before
    // sd_bus_match_signal has succeeded -- so a tick landing in that window saw
    // "armed" and closed the gap on a subscription that had not been established.
    // arm_confirmed_ is set by bus_loop() only after the match actually
    // registers.
    bool is_armed() {
#ifdef YUZU_HAVE_LIBSYSTEMD
        std::lock_guard<std::mutex> lock(thread_mu_);
        return bus_thread_.joinable() && arm_confirmed_.load(std::memory_order_acquire) &&
               !arm_failed_.load(std::memory_order_acquire);
#else
        return false; // no sd-bus in this build: sleep/wake is genuinely uncapturable
#endif
    }

    std::atomic<std::uint64_t> seq_{0};
    BoundedPendingQueue<RawPowerItem> queue_;
    std::mutex thread_mu_;
#ifdef YUZU_HAVE_LIBSYSTEMD
    std::thread bus_thread_;
#endif
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> needs_rearm_{false};
    std::atomic<bool> arm_failed_{false};
    // Set by bus_loop() ONLY after sd_bus_match_signal succeeds.
    std::atomic<bool> arm_confirmed_{false};
    // The honest "actually armed at" instant, stamped by bus_loop() alongside
    // arm_confirmed_; 0 = not currently armed (should-fix #4).
    std::atomic<std::int64_t> armed_at_ms_{0};
    std::atomic<bool> enabled_{true}; // seeded from persisted config in start() -- R-002
    std::optional<std::int64_t> disabled_at_ms_;
    std::optional<std::int64_t> pending_gap_since_ms_;
    std::optional<std::int64_t> pending_gap_until_ms_;
    std::size_t last_reported_dropped_{0};
    // R-003: see the Windows leg's identical member for the full rationale.
    const std::int64_t this_run_start_ms_{now_epoch_ms()};
};

} // namespace

std::unique_ptr<CursorSource> make_power_cursor_source() {
    return std::make_unique<LinuxPowerCursorSource>();
}

// ============================================================================
// Unsupported platform
// ============================================================================
#else

namespace {

class NullPowerCursorSource : public CursorSource {
public:
    [[nodiscard]] std::string name() const noexcept override { return "power"; }
    void start(TarDatabase&) override {}
    void stop() noexcept override {}
    void on_enabled_changed(bool) override {}
    CursorCollectResult collect(TarDatabase&, const std::optional<std::string>&) override {
        throw IncompleteCaptureError("TAR: power not supported on this platform");
    }
};

} // namespace

std::unique_ptr<CursorSource> make_power_cursor_source() {
    return std::make_unique<NullPowerCursorSource>();
}

#endif

} // namespace yuzu::tar
