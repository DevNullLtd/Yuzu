#pragma once

// event_logs_journal.hpp -- bounded sd_journal read core for the event_logs
// plugin's Linux native leg (Wave-4 PR4.2, ADR-3002 rung 1).
//
// Compiled ONLY under __linux__ && YUZU_HAVE_LIBSYSTEMD (the tri-state
// `systemd_guard` meson feature the device_identity and firewall plugins
// already consume -- the SAME knob, never a second option). The plugin shell
// includes this header behind that guard and falls back to a bounded
// `journalctl` argv invocation (rung 2) when the leg is compiled out OR the
// journal is unreachable at runtime -- an sd_journal failure must never be
// reported as "no events" (the device_identity sd-bus fallback contract).
//
// Bounding (ADR-3002 "bounded call modes" -- sd-journal has no
// sd_bus_set_method_call_timeout analogue, so the bound is explicit here):
//   1. a hard entry cap (the old `journalctl -n N` bound);
//   2. a wall-clock budget checked every iteration (steady_clock, the
//      firewall remaining-budget shape);
//   3. sd_journal_wait() is NEVER called -- it blocks indefinitely, the
//      exact hang-forever mode ADR-3002 exists to remove. Reads iterate
//      backwards from sd_journal_seek_tail, so the walk is inherently
//      finite.
//
// This header does journal I/O (it is not pure) but touches nothing else --
// no subprocesses, no plugin SDK types -- so a small standalone harness can
// drive it against a real journal for verification, and the row FORMATTING
// stays in the pure event_logs_parsers.hpp.

#include <chrono>
#include <cstdint>
#include <ctime>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <systemd/sd-journal.h>

#include "event_logs_parsers.hpp" // journal_message_matches (filter matching)

namespace yuzu::event_logs_journal {

// ── RAII owner ──────────────────────────────────────────────────────────────

// sd_journal* must be closed with sd_journal_close. Copies are deleted per
// the review-hardened guard convention (device_identity BR-012): an
// accidental copy would double-close the handle.
class JournalGuard {
public:
    explicit JournalGuard(sd_journal* j) noexcept : j_{j} {}
    ~JournalGuard() {
        if (j_)
            ::sd_journal_close(j_);
    }
    JournalGuard(const JournalGuard&) = delete;
    JournalGuard& operator=(const JournalGuard&) = delete;
    sd_journal* get() const noexcept { return j_; }

private:
    sd_journal* j_;
};

// ── entry model ─────────────────────────────────────────────────────────────

struct Entry {
    std::uint64_t realtime_usec = 0;
    std::string identifier;   // SYSLOG_IDENTIFIER
    std::string pid;          // _PID
    std::string systemd_unit; // _SYSTEMD_UNIT
    std::string message;      // MESSAGE
};

enum class ReadStatus {
    kOk,        // read completed (out may legitimately be empty)
    kOpenFailed // journal could not be opened/positioned -- caller MUST fall
                // through to the argv fallback, never report "no events"
};

struct ReadResult {
    ReadStatus status = ReadStatus::kOpenFailed;
    bool truncated = false; // budget/scan-cap stop or mid-read error: `out`
                            // is honest but possibly incomplete -- caller
                            // surfaces a typed CONSTRAINED status
};

// ── field access ────────────────────────────────────────────────────────────

// One field of the CURRENT entry, with the "FIELD=" prefix stripped. Absent
// field (-ENOENT) or any read error yields "" -- the row composers render
// missing fields as "-".
inline std::string field_value(sd_journal* j, const char* field) {
    const void* data = nullptr;
    std::size_t length = 0;
    if (::sd_journal_get_data(j, field, &data, &length) < 0)
        return {};
    std::string_view raw{static_cast<const char*>(data), length};
    if (const auto eq = raw.find('='); eq != std::string_view::npos)
        raw = raw.substr(eq + 1);
    return std::string(raw);
}

// `journalctl -o short-iso`-compatible local-time timestamp for one journal
// realtime value ("2026-08-24T09:15:02+0100").
inline std::string format_short_iso(std::uint64_t realtime_usec) {
    const std::time_t secs = static_cast<std::time_t>(realtime_usec / 1'000'000);
    std::tm tmv{};
    if (::localtime_r(&secs, &tmv) == nullptr)
        return {};
    char buf[40]{};
    if (::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%S%z", &tmv) == 0)
        return {};
    return buf;
}

namespace detail {

// sd_journal_open SUCCEEDS for a process that can read no journal files at all
// -- it opens whichever files the caller's UID is permitted to see. The agent
// runs as a dedicated `yuzu`/`_yuzu` account (docs/agent-privilege-model.md);
// if that account is outside the `systemd-journal` group and the system journal
// is not world-readable, the walk simply finds nothing and the leg would report
// a clean, confident "no events" for a host it could not actually read -- the
// exact failure-reads-as-empty-log mode this migration exists to remove, on the
// leg the migration promotes to rung 1.
//
// sd_journal_get_cutoff_realtime_usec answers "are ANY entries visible to me?":
// 1 when the journal has readable entries, 0 when it has none. Treat "none
// visible" as unreachable rather than empty and let the caller fall through to
// the journalctl fallback, which reports honestly (and which, on a genuinely
// empty journal, simply also finds nothing -- costing one extra bounded spawn
// in the rare empty case, in exchange for never lying about a denied one).
inline bool journal_has_visible_entries(sd_journal* j) {
    std::uint64_t from_usec = 0;
    std::uint64_t to_usec = 0;
    return ::sd_journal_get_cutoff_realtime_usec(j, &from_usec, &to_usec) > 0;
}

inline Entry read_current_entry(sd_journal* j, std::uint64_t realtime_usec) {
    Entry e;
    e.realtime_usec = realtime_usec;
    e.message = field_value(j, "MESSAGE");
    e.identifier = field_value(j, "SYSLOG_IDENTIFIER");
    e.pid = field_value(j, "_PID");
    e.systemd_unit = field_value(j, "_SYSTEMD_UNIT");
    return e;
}

} // namespace detail

// ── bounded reads ───────────────────────────────────────────────────────────

// Newest-first collection of err-or-worse entries (PRIORITY 0..3, the
// `journalctl -p err` set) from the last `hours` hours, up to `cap` entries.
// The CALLER reverses `out` before emitting so rows appear oldest-first,
// matching the old `journalctl --since ... -n 100` output order.
inline ReadResult read_errors(int hours, std::size_t cap, std::chrono::milliseconds budget,
                              std::vector<Entry>& out) {
    sd_journal* raw = nullptr;
    if (::sd_journal_open(&raw, SD_JOURNAL_LOCAL_ONLY) < 0)
        return {ReadStatus::kOpenFailed, false};
    JournalGuard j{raw};

    // Multiple matches on the SAME field are OR'd by sd-journal, giving the
    // exact `-p err` semantics (emerg..err).
    for (const char* match : {"PRIORITY=0", "PRIORITY=1", "PRIORITY=2", "PRIORITY=3"})
        if (::sd_journal_add_match(j.get(), match, 0) < 0)
            return {ReadStatus::kOpenFailed, false};
    if (::sd_journal_seek_tail(j.get()) < 0)
        return {ReadStatus::kOpenFailed, false};
    // An open that can see no entries at all is a denied read, not an empty
    // log -- see detail::journal_has_visible_entries.
    if (!detail::journal_has_visible_entries(j.get()))
        return {ReadStatus::kOpenFailed, false};

    const auto deadline = std::chrono::steady_clock::now() + budget;
    const auto now_usec = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    const std::uint64_t window_usec =
        static_cast<std::uint64_t>(hours) * 3'600ULL * 1'000'000ULL;
    const std::uint64_t cutoff = (window_usec < now_usec) ? now_usec - window_usec : 0;

    while (out.size() < cap) {
        if (std::chrono::steady_clock::now() >= deadline)
            return {ReadStatus::kOk, true}; // budget exhausted: honest partial
        const int r = ::sd_journal_previous(j.get());
        if (r < 0) {
            // Mid-read error with nothing collected is indistinguishable
            // from "couldn't read the journal at all" -- fall back; with a
            // partial batch, return it honestly as truncated.
            if (out.empty())
                return {ReadStatus::kOpenFailed, false};
            return {ReadStatus::kOk, true};
        }
        if (r == 0)
            break; // reached the head: legitimately exhausted
        std::uint64_t usec = 0;
        if (::sd_journal_get_realtime_usec(j.get(), &usec) < 0)
            continue;
        if (usec < cutoff)
            break; // walked past the time window
        out.push_back(detail::read_current_entry(j.get(), usec));
    }
    return {ReadStatus::kOk, false};
}

// Newest-first collection of entries whose MESSAGE contains `filter`
// (case-insensitive substring -- the native equivalent of the old
// `journalctl --grep` leg), up to `count` matches. `scan_cap` bounds the
// total entries examined so a rare filter cannot walk an entire large
// journal; with the wall-clock budget it forms the ADR-3002 bound.
inline ReadResult read_matches(std::string_view filter, std::size_t count, std::size_t scan_cap,
                               std::chrono::milliseconds budget, std::vector<Entry>& out) {
    sd_journal* raw = nullptr;
    if (::sd_journal_open(&raw, SD_JOURNAL_LOCAL_ONLY) < 0)
        return {ReadStatus::kOpenFailed, false};
    JournalGuard j{raw};
    if (::sd_journal_seek_tail(j.get()) < 0)
        return {ReadStatus::kOpenFailed, false};
    // An open that can see no entries at all is a denied read, not an empty
    // log -- see detail::journal_has_visible_entries.
    if (!detail::journal_has_visible_entries(j.get()))
        return {ReadStatus::kOpenFailed, false};

    const auto deadline = std::chrono::steady_clock::now() + budget;
    std::size_t scanned = 0;
    while (out.size() < count) {
        if (std::chrono::steady_clock::now() >= deadline)
            return {ReadStatus::kOk, true};
        if (scanned >= scan_cap)
            return {ReadStatus::kOk, true}; // scan bound hit: honest partial
        const int r = ::sd_journal_previous(j.get());
        if (r < 0) {
            if (out.empty())
                return {ReadStatus::kOpenFailed, false};
            return {ReadStatus::kOk, true};
        }
        if (r == 0)
            break;
        ++scanned;
        std::uint64_t usec = 0;
        if (::sd_journal_get_realtime_usec(j.get(), &usec) < 0)
            continue;
        // Non-const so the move below is a real move, and read ONCE here —
        // read_current_entry would otherwise fetch MESSAGE a second time only
        // for it to be overwritten.
        std::string message = field_value(j.get(), "MESSAGE");
        if (!yuzu::event_logs_parsers::journal_message_matches(message, filter))
            continue;
        Entry e = detail::read_current_entry(j.get(), usec);
        e.message = std::move(message);
        out.push_back(std::move(e));
    }
    return {ReadStatus::kOk, false};
}

} // namespace yuzu::event_logs_journal
