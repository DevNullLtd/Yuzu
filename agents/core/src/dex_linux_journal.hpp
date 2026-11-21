#pragma once

/**
 * dex_linux_journal.hpp — pure journald-record classification for Linux DEX.
 *
 * The Linux DEX collector (dex_linux_collector.cpp) reads the systemd journal via
 * a slow-cadence `journalctl --after-cursor … -o json` shell-out (the macOS
 * `log show` playbook — the DEX family reads logs via the OS log CLI), and feeds
 * each line through the PURE classifier here. journald reliability events map onto
 * EXISTING obs_types, so a Linux server lights up the same `/dex` buckets as
 * Windows/macOS with ZERO server change:
 *   - systemd unit failed     (MESSAGE_ID "Failed with result", live carrier;     → service.crashed
 *                              SD_MESSAGE_UNIT_FAILED also matched, defensive)
 *   - systemd-coredump entry  (MESSAGE_ID SD_MESSAGE_COREDUMP)                     → process.crashed
 *   - kernel OOM-killer       (_TRANSPORT=kernel + the OOM text)                   → memory.exhausted
 *
 * A unit failure is service.crashed whether it died at runtime or failed to start —
 * the two are indistinguishable by MESSAGE_ID (see parse_journal_line for why the
 * service.start_failed split is not done).
 *
 * journalctl shell-out, not sd-journal, deliberately: no libsystemd build dep (the
 * collector stays buildable on musl/Alpine like the PR3 /proc source), no coupling
 * to the systemd_guard feature-gate, and `journalctl -o json` → a pure classifier
 * keeps the off-Linux-tested pattern (this file). MESSAGE_ID matching gives one
 * canonical entry per failure (so no multi-line de-dup needed); a flapping unit is
 * bounded by the collector's per-(type,subject) debounce, not here.
 *
 * PRIVACY (works-council / co-determination): only safe fields leave the device —
 * the killed/failed process comm, the unit name, and the signal/result code. The
 * raw MESSAGE is never shipped (the kernel OOM line is read only to extract the
 * killed comm). Never throws (the JSON parse is exception-free).
 */

#include <yuzu/plugin.h>                     // YUZU_EXPORT
#include <yuzu/agent/dex_signal_catalog.hpp> // SignalObservation

#include <cstddef>
#include <cstdint>
#include <cstdio> // std::FILE — read_pipe_line / drain_journal_pipe operate on the popen() stream
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu::agent::lnx {

// Stable systemd journal MESSAGE_IDs (from <systemd/sd-messages.h>) the collector
// filters the journal on and the classifier keys off.
inline constexpr std::string_view kMsgIdCoredump = "fc2e22bc6ee647b6b90729ab34a250b1"; // SD_MESSAGE_COREDUMP
// SD_MESSAGE_UNIT_FAILED. Matched DEFENSIVELY: it did not fire in any tested
// crash/start-fail case on systemd 259 (kMsgIdUnitResult carried them all), but it
// is kept for paths not exercised (oneshot, start-limit-hit, dependency failure).
inline constexpr std::string_view kMsgIdUnitFailed = "be02cf6855d2428ba40df7e9d022f03d";
// The "<unit>: Failed with result 'X'." message — the LIVE carrier: what a unit
// failure actually logs (carries UNIT + UNIT_RESULT), for both a runtime death and a
// start failure. Both ids are matched for service.crashed.
inline constexpr std::string_view kMsgIdUnitResult = "d9b373ed55a64feb8242e02dbe79a49c";

/// One classified `journalctl -o json` line: its `__CURSOR` (the poll checkpoint —
/// always extracted, even when the line is not a catalogued signal, so the cursor
/// advances past noise) and the DEX observation it maps to (nullopt = not a
/// reliability signal we record).
struct JournalLine {
    std::string cursor;                   ///< __CURSOR, "" if absent/unparsable
    std::optional<SignalObservation> obs; ///< the mapped signal, or nullopt
    /// True when the entry carried a reliability MESSAGE_ID (or the chronyd comm) but failed
    /// the journald-stamped sender check (WP13/F58). Counted by the collector so a trusted-field
    /// mismatch on a real host (e.g. a different coredump identity) is visible, not silent.
    bool untrusted_dropped{false};
};

/// PURE: parse + classify one `journalctl -o json` line. Extracts ONLY safe fields
/// (process comm / unit name / signal / result code); never ships the raw MESSAGE.
/// Never throws. Tested off-Linux against captured journalctl fixtures.
YUZU_EXPORT JournalLine parse_journal_line(std::string_view json_line);

/// PURE: best-effort signal name for a `COREDUMP_SIGNAL` number ("11" → "SIGSEGV");
/// "signal N" when unmapped. Exposed for tests.
YUZU_EXPORT std::string crash_signal_name(int signo);

// ── journald pipe orchestration (pure / tmpfile-testable on every platform) ──────
// These move the journald read loop out of the Linux-only collector so the cursor
// advance, command construction, and debounce are unit-tested directly rather than
// only via the live pipeline. The collector keeps just the popen() + poll thread.

/// PURE: read one newline-terminated line from `f` into `out` (trailing `\n` and a
/// preceding `\r` stripped). false at clean EOF; a final line with no trailing
/// newline still returns true. Accumulates across `fgets` chunks so a long JSON line
/// is not split. Operates on any `FILE*` → tmpfile-testable without journalctl.
YUZU_EXPORT bool read_pipe_line(std::FILE* f, std::string& out);

/// PURE: the journalctl command for the FIRST (baseline) poll — tail one entry so
/// the cursor can be seeded at the journal head without replaying history. Wrapped in
/// `timeout` so a wedged journalctl cannot hang the baseline read.
YUZU_EXPORT std::string journald_baseline_query();

/// PURE: the steady-state journalctl command reading strictly AFTER `cursor`
/// (`--after-cursor` is exclusive), filtered to the reliability MESSAGE_IDs plus the
/// kernel transport (the OOM line has no stable id). Wrapped in `timeout`. Returns
/// nullopt when `cursor` contains a single quote — a real `__CURSOR` never does, so
/// this is the injection guard AND the "re-baseline" signal; the caller MUST clear
/// the cursor on nullopt. `cursor` is the only external input and sits only inside
/// the single-quoted shell slot.
YUZU_EXPORT std::optional<std::string> build_journald_after_cursor_query(std::string_view cursor);

/// PURE: read every line from an open journalctl pipe, classify each, advance
/// `cursor` to the newest `__CURSOR` seen (journalctl is chronological → last
/// non-empty wins), and return the observations to emit (classification ONLY — the
/// caller applies the debounce). A line with no `__CURSOR` (malformed tail) does not
/// advance the cursor, so the same window is re-read next poll. Pure over the `FILE*`
/// → tmpfile-testable.
YUZU_EXPORT std::vector<SignalObservation> drain_journal_pipe(std::FILE* pipe, std::string& cursor,
                                                              std::size_t* untrusted_dropped = nullptr);

/// Per-(obs_type, subject) debounce with age eviction, so a flapping unit / crash
/// loop collapses to one observation per window instead of flooding the wire.
/// Timestamps are MONOTONIC (the caller passes steady_now()): the window is a timer,
/// immune to wall-clock steps. The map is bounded by the trailing-window event count,
/// not daemon uptime, because evict_stale() drops entries older than the window.
class YUZU_EXPORT JournalDebounce {
public:
    explicit JournalDebounce(std::int64_t window_seconds) : window_(window_seconds) {}

    /// true (and records the stamp) when (obs_type, subject) is outside the window;
    /// false (collapse) when a prior emit is still within it.
    bool should_emit(const std::string& obs_type, const std::string& subject, std::int64_t now_mono);

    /// Drop entries whose last emit is >= window old — they can no longer suppress.
    void evict_stale(std::int64_t now_mono);

    std::size_t size() const { return seen_.size(); } ///< for tests / bound assertions

private:
    std::int64_t window_;
    std::unordered_map<std::string, std::int64_t> seen_;
};

} // namespace yuzu::agent::lnx
