#pragma once

/**
 * tar_power_parsers.hpp -- pure core for the `power` cursor-model TAR source
 * (tar_cursor.hpp). Everything here is free functions over strings/structs --
 * no platform headers, no subprocess spawning, no OS callbacks -- so the
 * whole derivation unit-tests on every host (tests/unit/test_tar_power.cpp)
 * independent of which OS leg (tar_power_collector.cpp) drives it.
 *
 * Three independent pieces live here:
 *
 *  1. The macOS `pmset -g log` line parser + the P-007 EXACT-TAIL cursor
 *     model. P-007: a naive "skip lines with ts <= cursor.last_ts" replay
 *     model is REFUTED by a live probe (fixtures/power-macos-pmset.txt,
 *     braga 26.5.1, 2026-09-04) showing two DISTINCT 'Using AC' summary
 *     lines in the SAME second (2026-09-03 14:44:18) -- a timestamp alone
 *     cannot tell "already replayed" from "a second real line arrived the
 *     same second". The exact-tail model instead identifies the cursor's
 *     own line by (timestamp, line CRC32, occurrence-within-that-second),
 *     locates it in the freshly-read log, and replays every line strictly
 *     after it, in order, equal timestamps included.
 *
 *  2. The AC-state-change decision shared by every OS leg (macOS's
 *     Using-AC/Using-Batt summary lines, Windows'/Linux's live AC polls):
 *     'Using AC'/'Using Batt' (and their OS equivalents) are STATUS
 *     SUMMARIES, not edge-triggered transitions -- an ac_attached/
 *     ac_detached PowerEvent is emitted only when the parsed state differs
 *     from the persisted `last_ac`, and an `unknown` prior state seeds
 *     silently (no event) rather than firing a spurious first transition.
 *
 *  3. Cursor JSON encode/decode/validate for all three OS legs. macOS's is
 *     a single flat document (rule 4: one row per source, not per input --
 *     there is only one input here). Windows'/Linux's pack an independent
 *     subscription-side key and an independent ac-side key into the same
 *     document so a malformed/missing one never invalidates the other (the
 *     spec's per-input isolation rule for those two legs).
 */

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu::tar {

// ── CRC32 (IEEE 802.3), pure/bitwise -- no static table, so no init-order or
// thread-safety concerns; called at most a few thousand times per collect
// tick, well within budget. ──────────────────────────────────────────────
inline std::uint32_t power_crc32(std::string_view data) {
    std::uint32_t crc = 0xFFFFFFFFu;
    for (unsigned char byte : data) {
        crc ^= byte;
        for (int i = 0; i < 8; ++i) {
            const std::uint32_t mask = static_cast<std::uint32_t>(-(static_cast<std::int32_t>(crc & 1u)));
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

inline std::string power_hex8(std::uint32_t v) {
    char buf[9];
    std::snprintf(buf, sizeof(buf), "%08x", v);
    return std::string(buf, 8);
}

// ── macOS pmset log-line parsing ────────────────────────────────────────────

/// One recognised line from `pmset -g log`: a Sleep/Wake/DarkWake transition
/// or a 'Using AC'/'Using Batt' assertions-summary line. Every other line the
/// log emits (the vast majority -- process-level power assertions, etc.) is
/// not of interest and parse_pmset_line() returns nullopt for it.
struct PmsetLogEntry {
    std::int64_t ts{0};        // epoch seconds, UTC (normalised from the line's local "+HHMM" offset)
    std::uint32_t line_crc{0}; // power_crc32() of the FULL raw line, exactly as read
    std::string kind;          // "sleep" | "wake" | "darkwake" | "using_ac" | "using_batt"
    std::string detail;        // trimmed reason/summary text after the domain column
};

/// Fixed-width `pmset -g log` line prefix: "YYYY-MM-DD HH:MM:SS +HHMM ",
/// exactly 26 bytes, verified against every line in the REAL CAPTURE fixture
/// (fixtures/power-macos-pmset.txt -- the 26-byte prefix and the padded Domain
/// column are a real capture; see that file's header for what it does NOT
/// prove). Returns the parsed UTC epoch seconds and
/// the byte offset of the first character after the prefix, or nullopt for
/// any line that does not match this shape (section headers, blank lines,
/// `=== ... ===` fixture markers, `pmset -g batt`/`-g ps` trailer lines).
inline std::optional<std::pair<std::int64_t, std::size_t>>
parse_pmset_timestamp_prefix(std::string_view line) {
    if (line.size() < 26)
        return std::nullopt;
    auto digits = [&](std::size_t off, std::size_t n) -> std::optional<int> {
        int v = 0;
        for (std::size_t i = 0; i < n; ++i) {
            char c = line[off + i];
            if (c < '0' || c > '9')
                return std::nullopt;
            v = v * 10 + (c - '0');
        }
        return v;
    };
    if (line[4] != '-' || line[7] != '-' || line[10] != ' ' || line[13] != ':' ||
        line[16] != ':' || line[19] != ' ' || line[25] != ' ')
        return std::nullopt;
    if (line[20] != '+' && line[20] != '-')
        return std::nullopt;

    auto y = digits(0, 4);
    auto mo = digits(5, 2);
    auto d = digits(8, 2);
    auto h = digits(11, 2);
    auto mi = digits(14, 2);
    auto s = digits(17, 2);
    auto off_h = digits(21, 2);
    auto off_m = digits(23, 2);
    if (!y || !mo || !d || !h || !mi || !s || !off_h || !off_m)
        return std::nullopt;
    if (*mo < 1 || *mo > 12 || *d < 1 || *h > 23 || *mi > 59 || *s > 60)
        return std::nullopt;
    // Reject impossible calendar dates (R-016): 31 April, 30 February, and
    // non-leap-year 29 February must not silently normalise into March.
    auto is_leap = [](int yy) { return (yy % 4 == 0 && yy % 100 != 0) || yy % 400 == 0; };
    static constexpr int kDaysInMonth[13] = {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int max_day = kDaysInMonth[*mo];
    if (*mo == 2 && is_leap(*y))
        max_day = 29;
    if (*d > max_day)
        return std::nullopt;
    // Reject unchecked UTC offsets outside the real-world range: no zone is
    // ever more than 14 hours ahead or 12 behind, and offset minutes are a
    // clock field (0-59), not just "2 digits" (which digits() alone allows
    // up to 99).
    if (*off_h > 14 || *off_m > 59)
        return std::nullopt;

    // Howard Hinnant's days_from_civil, UTC calendar math -- no timezone
    // database lookup, so this is pure and portable.
    int yy = *y;
    unsigned mm = static_cast<unsigned>(*mo);
    unsigned dd = static_cast<unsigned>(*d);
    yy -= (mm <= 2) ? 1 : 0;
    const std::int64_t era = (yy >= 0 ? yy : yy - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(yy - era * 400);
    const unsigned doy = (153 * (mm + (mm > 2 ? static_cast<unsigned>(-3) : 9)) + 2) / 5 + dd - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const std::int64_t days = era * 146097 + static_cast<std::int64_t>(doe) - 719468;

    std::int64_t local_epoch = days * 86400 + *h * 3600 + *mi * 60 + *s;
    std::int64_t offset_seconds = (*off_h * 3600 + *off_m * 60) * (line[20] == '+' ? 1 : -1);
    std::int64_t utc_epoch = local_epoch - offset_seconds;
    return std::make_pair(utc_epoch, std::size_t{26});
}

/// Parse one `pmset -g log` line. Domain column shape: after the 26-byte
/// timestamp prefix, a single whitespace-delimited domain token ("Sleep",
/// "Wake", "DarkWake", "Assertions", ...), then the rest of the line
/// (trimmed) as the message. Verified against the REAL CAPTURE fixture's
/// `Assertions`-domain lines (tab-separated after the domain's trailing
/// padding); Sleep/Wake/DarkWake use the identical fixed-width layout per
/// pmset(1) -- see test_tar_power.cpp's RECONSTRUCTION block for why no
/// REAL Sleep/Wake line exists in this host's capture window.
inline std::optional<PmsetLogEntry> parse_pmset_line(std::string_view line) {
    auto prefix = parse_pmset_timestamp_prefix(line);
    if (!prefix)
        return std::nullopt;
    auto [ts, off] = *prefix;
    std::string_view rest = line.substr(off);

    std::size_t p = 0;
    while (p < rest.size() && rest[p] != ' ' && rest[p] != '\t')
        ++p;
    std::string_view domain = rest.substr(0, p);
    while (p < rest.size() && (rest[p] == ' ' || rest[p] == '\t'))
        ++p;
    std::string_view message = rest.substr(p);
    while (!message.empty() &&
           (message.back() == ' ' || message.back() == '\t' || message.back() == '\r'))
        message.remove_suffix(1);

    std::string kind;
    if (domain == "Sleep")
        kind = "sleep";
    else if (domain == "Wake")
        kind = "wake";
    else if (domain == "DarkWake")
        kind = "darkwake";
    else if (domain == "Assertions") {
        bool has_ac = message.find("Using AC") != std::string_view::npos;
        bool has_batt = message.find("Using Batt") != std::string_view::npos;
        if (has_ac && !has_batt)
            kind = "using_ac";
        else if (has_batt && !has_ac)
            kind = "using_batt";
        else
            return std::nullopt;
    } else {
        return std::nullopt;
    }

    PmsetLogEntry e;
    e.ts = ts;
    e.line_crc = power_crc32(line);
    e.kind = std::move(kind);
    e.detail = std::string(message);
    return e;
}

/// Parse a whole `pmset -g log` capture (already split into lines by the
/// subprocess runner) into every recognised entry, in file order (which is
/// also chronological -- pmset never reorders its own log).
inline std::vector<PmsetLogEntry> parse_pmset_log(const std::vector<std::string>& lines) {
    std::vector<PmsetLogEntry> out;
    out.reserve(lines.size());
    for (const auto& line : lines) {
        if (auto e = parse_pmset_line(line))
            out.push_back(std::move(*e));
    }
    return out;
}

/// Occurrence-within-timestamp-group, 1-based, parallel to `entries`: for
/// each maximal run of consecutive entries sharing the same `ts` (a "ts
/// group" -- pmset lines are chronological so same-second lines are always
/// adjacent), the k-th time a given `line_crc` appears within that group.
/// This is what disambiguates the P-007 same-second duplicate pair (and any
/// duplicate identical line within one second) into distinct, replay-stable
/// identities -- see mac_power_record_key() and locate_exact_tail() below.
inline std::vector<std::int64_t> compute_pmset_occurrences(const std::vector<PmsetLogEntry>& entries) {
    std::vector<std::int64_t> result(entries.size(), 0);
    std::size_t i = 0;
    while (i < entries.size()) {
        std::size_t j = i;
        while (j < entries.size() && entries[j].ts == entries[i].ts)
            ++j;
        std::unordered_map<std::uint32_t, std::int64_t> counts;
        for (std::size_t k = i; k < j; ++k)
            result[k] = ++counts[entries[k].line_crc];
        i = j;
    }
    return result;
}

/// The UNIQUE replay-idempotence key (tar_cursor.hpp rule 3) for one pmset
/// log line's derived event.
inline std::string mac_power_record_key(std::int64_t ts, std::uint32_t crc, std::int64_t occurrence) {
    return "pmset:" + std::to_string(ts) + ":" + power_hex8(crc) + ":" + std::to_string(occurrence);
}

/// Record key for a synthetic `capture_gap` event (not derived from any one
/// log line): keyed on the gap's own timestamp + a CRC of its reason text, so
/// two gaps in the same second with different reasons still get distinct
/// keys, and a retried identical gap report is idempotent.
inline std::string mac_power_gap_record_key(std::int64_t ts, const std::string& reason) {
    return "pmset:gap:" + std::to_string(ts) + ":" + power_hex8(power_crc32(reason));
}

/// Record key for a PERSISTENT-CONDITION gap (currently: pmset output stuck
/// truncated) -- deliberately time-INDEPENDENT, unlike mac_power_gap_record_key
/// above. A host whose pmset log stays past the read cap re-derives the exact
/// same forced_gap_reason on every tick; keying on `now` (as every other gap
/// does) makes each tick's row distinct and the table fills with one row per
/// tick forever. Keying on the condition alone means the FIRST tick's row
/// wins and the store's record_key dedupe collapses every later tick onto it
/// -- one standing row, matching the intent already stated in
/// tar_power_collector.cpp's truncation comment.
inline std::string mac_power_gap_record_key_stable(const std::string& reason) {
    return "pmset:gap:stable:" + power_hex8(power_crc32(reason));
}

// ── macOS cursor: {"v":1,"last_ts":...,"last_line_crc":...,"occurrence":...,
// "last_ac":"ac|batt|unknown"} (P-007 exact-tail model). ────────────────────

struct MacPowerCursor {
    int v{1};
    std::int64_t last_ts{0};
    std::uint32_t last_line_crc{0};
    std::int64_t occurrence{1};
    // How many entries shared `last_ts` when this cursor was written.
    //
    // `occurrence` alone is NOT a stable identity across a wrapping log.
    // Occurrences are recomputed per read, so if the log front-evicts the
    // EARLIER of two byte-identical same-second lines, the survivor renumbers
    // from 2 to 1 -- straight into the cursor's stored occurrence. The tail
    // then binds to a record we had NOT yet reported, replay resumes past it,
    // and that record is lost with no gap. Recording the group's size makes the
    // change detectable: a group that is no longer the size it was is not the
    // group this cursor points into, so the honest answer is rule 2 rather than
    // a confident mis-bind. 0 means "written before this field existed" and is
    // accepted without the check, so an upgrade does not force a re-baseline.
    std::int64_t ts_group_size{0};
    std::string last_ac{"unknown"};
};

inline std::string encode_mac_power_cursor(const MacPowerCursor& c) {
    // Hand-rolled (not nlohmann::json::dump): last_ac is always one of three
    // fixed ASCII tokens we control, so no escaping is ever needed, and this
    // keeps the header free of a JSON library #include for the common case --
    // decode still goes through nlohmann::json for robustness against a
    // hand-edited or corrupted stored value.
    std::string ac = c.last_ac;
    if (ac != "ac" && ac != "batt" && ac != "unknown")
        ac = "unknown";
    return "{\"v\":1,\"last_ts\":" + std::to_string(c.last_ts) +
           ",\"last_line_crc\":" + std::to_string(c.last_line_crc) +
           ",\"occurrence\":" + std::to_string(c.occurrence) +
           ",\"ts_group_size\":" + std::to_string(c.ts_group_size) + ",\"last_ac\":\"" + ac +
           "\"}";
}

/// Decode + validate. Returns nullopt for ANYTHING short of a well-formed
/// `{"v":1,...}` document with every field present and in range -- the
/// caller (tar_power_collector.cpp) treats a decode failure identically to a
/// rule-2 lost cursor (capture_gap + forward re-baseline), never as a parse
/// error to propagate.
inline std::optional<MacPowerCursor> decode_mac_power_cursor(const std::string& json_text) {
    try {
        auto j = nlohmann::json::parse(json_text);
        if (!j.is_object() || !j.contains("v") || !j.at("v").is_number_integer() ||
            j.at("v").get<int>() != 1)
            return std::nullopt;
        if (!j.contains("last_ts") || !j.contains("last_line_crc") || !j.contains("occurrence") ||
            !j.contains("last_ac"))
            return std::nullopt;

        MacPowerCursor c;
        c.v = 1;
        c.last_ts = j.at("last_ts").get<std::int64_t>();
        auto crc = j.at("last_line_crc").get<std::int64_t>();
        if (crc < 0 || crc > 0xFFFFFFFFLL)
            return std::nullopt;
        c.last_line_crc = static_cast<std::uint32_t>(crc);
        c.occurrence = j.at("occurrence").get<std::int64_t>();
        if (c.occurrence < 1)
            return std::nullopt;
        // Optional: absent on a cursor written before the field existed.
        if (j.contains("ts_group_size") && j.at("ts_group_size").is_number_integer()) {
            c.ts_group_size = j.at("ts_group_size").get<std::int64_t>();
            if (c.ts_group_size < 0)
                return std::nullopt;
        }
        c.last_ac = j.at("last_ac").get<std::string>();
        if (c.last_ac != "ac" && c.last_ac != "batt" && c.last_ac != "unknown")
            return std::nullopt;
        return c;
    } catch (...) {
        return std::nullopt;
    }
}

enum class MacTailOutcome {
    kFound,
    kNotFound,
    kWallClockRegression,
    // The cursor's timestamp group is no longer the size it was, so an
    // eviction has renumbered the occurrences and the stored occurrence can no
    // longer be trusted to name the same line. Treated exactly like kNotFound
    // by policy (capture_gap + forward re-baseline); reported separately so the
    // log says WHY, since a confident mis-bind here loses a record silently.
    kTailGroupGone
};

struct MacTailSearch {
    MacTailOutcome outcome{MacTailOutcome::kNotFound};
    std::size_t index{0}; // valid iff outcome == kFound
};

/// Locate the EXACT tail the cursor points at within a freshly-read log:
/// the entry whose (ts, line_crc, occurrence-within-ts-group) matches the
/// cursor exactly. `occurrences` must be compute_pmset_occurrences(entries).
/// A wall-clock regression (the log's newest entry is now OLDER than the
/// cursor's last_ts -- the log was rewritten/rotated under the cursor) is
/// reported distinctly from a plain not-found (the tail's ts group is
/// simply gone, e.g. evicted by a circular-buffer wrap) for logging, but
/// both drive the identical capture_gap + re-baseline policy.
inline MacTailSearch locate_exact_tail(const std::vector<PmsetLogEntry>& entries,
                                       const std::vector<std::int64_t>& occurrences,
                                       const MacPowerCursor& cursor) {
    if (!entries.empty() && entries.back().ts < cursor.last_ts)
        return MacTailSearch{MacTailOutcome::kWallClockRegression, 0};
    // How many entries currently share the cursor's timestamp.
    std::int64_t current_group = 0;
    for (const auto& e : entries)
        if (e.ts == cursor.last_ts)
            ++current_group;
    // Only a SHRUNK group is dangerous, and the distinction is the whole point.
    // Occurrences are assigned in order within a timestamp group, so appending a
    // new same-second line leaves every existing member's occurrence untouched
    // -- a group that GREW is the ordinary case where the log gained an entry
    // between reads, and refusing to bind there would turn every same-second
    // append into a spurious gap. Losing an EARLIER member is what renumbers the
    // survivors into somebody else's occurrence, and that is what this catches.
    // (0 = a cursor written before this field existed; accept it rather than
    // force a re-baseline on upgrade.)
    if (cursor.ts_group_size != 0 && current_group != 0 &&
        current_group < cursor.ts_group_size)
        return MacTailSearch{MacTailOutcome::kTailGroupGone, 0};

    for (std::size_t i = 0; i < entries.size(); ++i) {
        if (entries[i].ts == cursor.last_ts && entries[i].line_crc == cursor.last_line_crc &&
            occurrences[i] == cursor.occurrence)
            return MacTailSearch{MacTailOutcome::kFound, i};
    }
    return MacTailSearch{MacTailOutcome::kNotFound, 0};
}

// ── AC-state-change decision, shared by every OS leg ────────────────────────

/// `last_ac`/`current_ac` in {"ac","batt","unknown"}. Returns "ac_attached",
/// "ac_detached", or "" (no event -- either unchanged, or seeding silently
/// from an unknown prior state). `current_ac` outside {"ac","batt"} (should
/// not happen -- callers only pass a resolved reading) also yields "".
inline std::string ac_transition_action(const std::string& last_ac, const std::string& current_ac) {
    if (current_ac != "ac" && current_ac != "batt")
        return {};
    if (last_ac == current_ac)
        return {};
    if (last_ac == "unknown")
        return {}; // seed silently -- not a real transition
    return current_ac == "ac" ? "ac_attached" : "ac_detached";
}

// ── Lookback (rule 5 -- same shape as netconn_lookback_seconds) ────────────

inline constexpr std::int64_t kPowerLookbackDefaultS = 604800; // 7 days
inline constexpr std::int64_t kPowerLookbackMaxS = 90LL * 24 * 3600;

inline std::int64_t power_clamp_lookback(std::int64_t seconds) {
    if (seconds < 0)
        return 0;
    if (seconds > kPowerLookbackMaxS)
        return kPowerLookbackMaxS;
    return seconds;
}

// ── One drafted PowerEvent (ts/action/detail/record_key) -- snapshot_id is
// filled in by the caller, which owns the collection-cycle counter. ────────

struct PowerEventDraft {
    std::int64_t ts{0};
    std::string action;
    std::string detail;
    std::string record_key;
};

/// Result of one macOS collect() tick's pure decision, mirroring
/// CursorCollectResult (tar_cursor.hpp) minus the DB-facing bits
/// (snapshot_id assignment, cursor_json serialisation) the collector adds.
struct MacPowerCollectDecision {
    std::vector<PowerEventDraft> events;
    MacPowerCursor new_cursor;
    bool cursor_lost{false}; // -> CursorOutcome::CursorLost
    bool is_baseline{false}; // -> CursorOutcome::Baseline
    std::string detail;      // logged only
};

/// The full macOS collect-tick decision, pure over an already-parsed log.
///
///  - `had_prior_cursor` false: first-ever read. `lookback_seconds` bounds
///    how far back into the ALREADY-RETAINED log history events are
///    actually emitted (0 = forward-only, nothing emitted, cursor still
///    baselines at the current log end); AC state is tracked across the
///    FULL log regardless of the window so an in-window 'Using AC' that is
///    not actually a change does not fire spuriously, but forward-only mode
///    (lookback_seconds == 0) skips the log entirely, including for AC
///    seeding, per the "no pre-enablement history is ever read" contract.
///  - `had_prior_cursor` true, `cursor` empty: the persisted cursor_json
///    failed to decode/validate -- treated exactly like a rule-2 lost
///    cursor (no tail search is even attempted), but `last_ac` cannot be
///    trusted from a corrupt blob and is re-seeded to "unknown".
///  - `had_prior_cursor` true, `cursor` set: normal replay -- locate the
///    exact tail and emit every entry strictly after it, in order, equal
///    timestamps included; not-found/regression -> capture_gap + re-baseline
///    at the current log end (never replay-from-zero).
///  - `forced_gap_reason`: set only by the collector's on_enabled_changed(true)
///    path (tar_cursor.hpp's re-enable contract: "RE-BASELINE forward ... and
///    emit a capture_gap event recording the disabled window -- NEVER emit
///    the disabled window's own events"). When set (and a valid prior cursor
///    exists), the normal exact-tail replay is skipped entirely -- the
///    disabled window's real log lines must never be emitted -- and this
///    tick instead behaves exactly like a rule-2 lost cursor: one
///    capture_gap using this reason, re-baselined at the current log end,
///    CursorOutcome::CursorLost.
///  - `forced_gap_stable_key`: true only for a PERSISTENT condition (pmset
///    output stuck truncated) whose forced_gap_reason text is re-derived
///    identically every tick -- see mac_power_gap_record_key_stable() above.
///    False (the default) covers the one-shot re-enable gap, which legitimately
///    keys on `now` since it fires (and clears) at most once per disable window.
inline MacPowerCollectDecision decide_mac_power_collect(const std::vector<PmsetLogEntry>& entries,
                                                         bool had_prior_cursor,
                                                         const std::optional<MacPowerCursor>& cursor,
                                                         std::int64_t lookback_seconds,
                                                         std::int64_t now,
                                                         std::optional<std::string> forced_gap_reason = std::nullopt,
                                                         bool forced_gap_stable_key = false) {
    MacPowerCollectDecision out;
    auto occurrences = compute_pmset_occurrences(entries);

    auto emit_for = [&](std::size_t i, std::string& last_ac, bool allow_emit) {
        const auto& e = entries[i];
        if (e.kind == "sleep" || e.kind == "wake" || e.kind == "darkwake") {
            // R-011: the schema/spec only permits action in
            // {sleep,wake,ac_attached,ac_detached,capture_gap} -- "darkwake"
            // is not one of them. A DarkWake is a wake (the system left a
            // sleep state), so it maps to "wake"; the parser's own `kind`
            // stays "darkwake" (PmsetLogEntry, above) so parse-level tests
            // can still tell the two apart.
            if (allow_emit)
                out.events.push_back(PowerEventDraft{
                    e.ts, e.kind == "darkwake" ? "wake" : e.kind, e.detail,
                    mac_power_record_key(e.ts, e.line_crc, occurrences[i])});
            return;
        }
        // using_ac / using_batt
        std::string cur = (e.kind == "using_ac") ? "ac" : "batt";
        auto action = ac_transition_action(last_ac, cur);
        if (allow_emit && !action.empty())
            out.events.push_back(PowerEventDraft{
                e.ts, action, e.detail, mac_power_record_key(e.ts, e.line_crc, occurrences[i])});
        last_ac = cur;
    };

    // Size of the timestamp group a given entry belongs to -- stored on the
    // cursor so a later read can tell that an eviction has renumbered it.
    auto group_size_at = [&](std::size_t i) -> std::int64_t {
        std::int64_t n = 0;
        for (const auto& e : entries)
            if (e.ts == entries[i].ts)
                ++n;
        return n;
    };

    auto rebaseline_at_log_end = [&](std::string last_ac) {
        if (entries.empty()) {
            out.new_cursor = MacPowerCursor{1, now, 0, 1, 0, last_ac};
        } else {
            out.new_cursor = MacPowerCursor{1,
                                            entries.back().ts,
                                            entries.back().line_crc,
                                            occurrences.back(),
                                            group_size_at(entries.size() - 1),
                                            last_ac};
        }
    };

    // A FORCED GAP OUTRANKS EVERYTHING, INCLUDING "no cursor yet".
    //
    // This check used to sit below the !had_prior_cursor branch, which returns.
    // So a source disabled BEFORE its first-ever collect -- a staged rollout, or
    // a tar.db quarantine -- came back with cursor_json == nullopt, took the
    // baseline path, and replayed up to power_lookback_seconds (7 days by
    // default) of the paused window's real Sleep/Wake/AC lines straight into
    // $Power_Live, while the capture_gap it owed was dropped on the floor.
    // tar_cursor.hpp is absolute about this: NOTHING from a paused window is
    // ever stored. A forced gap always means gap plus forward re-baseline,
    // whether or not a cursor exists.
    if (forced_gap_reason.has_value()) {
        out.cursor_lost = true;
        const std::string key = forced_gap_stable_key
                                     ? mac_power_gap_record_key_stable(*forced_gap_reason)
                                     : mac_power_gap_record_key(now, *forced_gap_reason);
        out.events.push_back(PowerEventDraft{now, "capture_gap", *forced_gap_reason, key});
        rebaseline_at_log_end(cursor.has_value() ? cursor->last_ac : std::string("unknown"));
        out.detail = *forced_gap_reason;
        return out;
    }

    if (!had_prior_cursor) {
        out.is_baseline = true;
        std::string last_ac = "unknown";
        if (lookback_seconds > 0) {
            std::int64_t window_start = now - lookback_seconds;
            for (std::size_t i = 0; i < entries.size(); ++i)
                emit_for(i, last_ac, entries[i].ts >= window_start);
        }
        // lookback_seconds == 0 (forward-only): entries are never scanned at
        // all -- last_ac stays "unknown" and seeds silently on the next tick.
        rebaseline_at_log_end(last_ac);
        out.detail = "baseline";
        return out;
    }

    if (!cursor.has_value()) {
        out.cursor_lost = true;
        std::string reason = "cursor unparsable / corrupt";
        out.events.push_back(PowerEventDraft{now, "capture_gap", reason,
                                             mac_power_gap_record_key(now, reason)});
        rebaseline_at_log_end("unknown");
        out.detail = reason;
        return out;
    }


    if (entries.empty() && cursor->last_line_crc == 0 && cursor->occurrence == 1) {
        // R-012: `rebaseline_at_log_end` on an empty log persists the
        // sentinel {last_line_crc:0, occurrence:1} (there being no real line
        // to point at). That sentinel can never satisfy locate_exact_tail
        // (an empty `entries` has nothing to search), so without this
        // special case a log that is STILL empty on the next tick would be
        // reported as a lost cursor -- and re-baseline to the same sentinel
        // -- on every single tick. This is the expected "nothing new"
        // outcome, not a lost cursor: carry the sentinel and last_ac forward
        // unchanged, no gap. (A real line_crc landing on exactly 0 is a
        // ~1-in-4-billion CRC32 collision, not a realistic false positive.)
        out.new_cursor = *cursor;
        out.detail = "advanced (log still empty)";
        return out;
    }

    auto tail = locate_exact_tail(entries, occurrences, *cursor);
    if (tail.outcome != MacTailOutcome::kFound) {
        out.cursor_lost = true;
        std::string reason = (tail.outcome == MacTailOutcome::kWallClockRegression)
                                  ? "wall-clock regression (log rewritten under the cursor)"
                                  : "cursor tail not found (log wrapped)";
        out.events.push_back(PowerEventDraft{now, "capture_gap", reason,
                                             mac_power_gap_record_key(now, reason)});
        rebaseline_at_log_end(cursor->last_ac);
        out.detail = reason;
        return out;
    }

    std::string last_ac = cursor->last_ac;
    for (std::size_t i = tail.index + 1; i < entries.size(); ++i)
        emit_for(i, last_ac, /*allow_emit=*/true);

    if (tail.index == entries.size() - 1) {
        out.new_cursor = *cursor;
        out.new_cursor.last_ac = last_ac;
    } else {
        rebaseline_at_log_end(last_ac); // "rebaseline" here just means "cursor = new log end"
    }
    out.detail = "advanced";
    return out;
}

// ── Windows / Linux cursor: subscription-side and ac-side packed under
// SEPARATE JSON keys so a malformed/absent one never invalidates the other
// (per-input isolation rule). ───────────────────────────────────────────────

/// Decoded view of one OS's power cursor_json. `subscription_present`/
/// `ac_present` are false when that top-level key was absent (a normal,
/// expected state -- e.g. never subscribed yet, or AC unknown); `*_valid` is
/// false only when the key WAS present but malformed, in which case that
/// side alone is treated as lost (re-armed / last_ac reseeded to "unknown")
/// while the other side's value is still honoured.
struct SubscriptionAcCursor {
    bool subscription_present{false};
    bool subscription_valid{true};
    std::int64_t subscribed_since_ms{0}; // meaning is leg-specific (Windows: subscription start;
                                         // Linux: sd-bus match armed-since)
    bool ac_present{false};
    bool ac_valid{true};
    std::string last_ac{"unknown"};
};

/// `subscription_key` is "subscribed_since_ms" (Windows) or "armed_since_ms"
/// (Linux) -- the two legs' subscription concepts are named differently on
/// purpose (they track different things) even though the codec is shared.
inline std::string encode_subscription_ac_cursor(const char* subscription_key,
                                                  std::optional<std::int64_t> subscribed_since_ms,
                                                  const std::string& last_ac) {
    nlohmann::json j;
    j["v"] = 1;
    if (subscribed_since_ms.has_value())
        j[subscription_key] = *subscribed_since_ms;
    std::string ac = last_ac;
    if (ac != "ac" && ac != "batt" && ac != "unknown")
        ac = "unknown";
    j["last_ac"] = ac;
    return j.dump();
}

// ── Windows / Linux tick decision (queue-drain + gap/overflow reporting) ────
//
// Both legs' collect() bodies reduce to the SAME shape: drain a
// BoundedPendingQueue<...> snapshot, report an owed re-enable gap (at most
// once) and any NEW queue-overflow drops as capture_gap events, turn
// sleep/wake items into events 1:1, and turn ac/batt items into
// state-change-driven events via ac_transition_action -- differing only in
// the record_key namespace and the human-readable detail text. Factored out
// here (pure, no OS/queue types) so this decision unit-tests on every
// platform (P-014) even though the OS-specific queue/subscription machinery
// around it only compiles on its own OS.

/// One item drained from a leg's BoundedPendingQueue, decoupled from
/// whatever OS-callback struct actually produced it. `kind` is
/// "sleep" | "wake" | "ac" | "batt".
struct SubscriptionRawItem {
    std::uint64_t seq{0}; // assigned at push time -- unique regardless of clock resolution
    std::int64_t ts{0};   // epoch seconds
    std::string kind;
};

struct SubscriptionTickInputs {
    std::string leg_tag;                    // "winpower" | "linuxpower" -- record_key namespace
    // Per-process-life nonce (the collector's start time, epoch ms), mixed into
    // the record_keys derived from PROCESS-LOCAL COUNTERS -- `seq` and
    // `dropped_total`. Both reset to 0 when the agent restarts, so without this
    // the second process life re-emits "winpower:sw:0" and the store's
    // INSERT OR IGNORE on record_key discards a genuinely new event while
    // reporting success. The timestamp-derived keys below (gap, restart,
    // subcorrupt, accorrupt) are content-addressed and already idempotent
    // across restarts, so they deliberately do NOT take the nonce -- mixing it
    // in would make a re-reported restart gap duplicate instead of dedupe.
    std::int64_t run_nonce_ms{0};
    std::vector<SubscriptionRawItem> items; // queue snapshot, oldest first
    std::string last_ac{"unknown"};
    std::optional<std::int64_t> pending_gap_since_ms; // set together, or neither
    std::optional<std::int64_t> pending_gap_until_ms;
    std::size_t dropped_total{0};
    std::size_t last_reported_dropped{0};
    std::int64_t now{0}; // epoch seconds -- ts for the overflow/corrupt/restart event, if any
    std::string sleep_wake_detail;
    std::string ac_detail;
    // R-004: the subscription-side cursor key was PRESENT but malformed --
    // an input-specific gap distinct from the pending re-enable gap above
    // (that one is a policy pause; this one is data corruption). Set only
    // when `subscription_present && !subscription_valid`.
    std::optional<std::string> subscription_gap_reason;
    // R-003: this is the first tick of a fresh process life and a prior,
    // valid subscription cursor was found -- the live subscription cannot
    // have survived the restart, so the window between the persisted
    // `subscribed_since_ms` and now is an unrecoverable, honestly-reported
    // gap. Mutually exclusive with `subscription_gap_reason` (a cursor is
    // either corrupt or a stale-but-valid restart marker, never both).
    std::optional<std::int64_t> restart_gap_since_ms;
    // The source is NOT armed: sleep/wake cannot be captured on this host at
    // all (no libsystemd in the build, a failed registration, a lost bus).
    // Keyed on the window START so the store's record_key dedupe collapses
    // every subsequent tick onto one row -- an operator gets one honest
    // statement rather than silence or a per-tick flood.
    std::optional<std::string> unarmed_gap_reason;
    std::int64_t unarmed_since_ms{0};

    // R-004: same shape as `subscription_gap_reason` for the AC-side key.
    std::optional<std::string> ac_gap_reason;
};

struct SubscriptionTickResult {
    std::vector<PowerEventDraft> events;
    std::string new_last_ac;
};

inline SubscriptionTickResult build_subscription_tick_events(const SubscriptionTickInputs& in) {
    SubscriptionTickResult out;
    out.new_last_ac = in.last_ac;

    if (in.pending_gap_until_ms.has_value() && in.pending_gap_since_ms.has_value()) {
        std::string detail = "power subscription paused " +
                             std::to_string(*in.pending_gap_since_ms) + "ms..." +
                             std::to_string(*in.pending_gap_until_ms) +
                             "ms (epoch ms) -- events during this window are unrecoverable";
        out.events.push_back(PowerEventDraft{
            *in.pending_gap_until_ms / 1000, "capture_gap", detail,
            in.leg_tag + ":gap:" + std::to_string(*in.pending_gap_since_ms) + ":" +
                std::to_string(*in.pending_gap_until_ms)});
    }

    if (in.unarmed_gap_reason.has_value()) {
        out.events.push_back(PowerEventDraft{
            in.now, "capture_gap", *in.unarmed_gap_reason,
            in.leg_tag + ":unarmed:" + std::to_string(in.unarmed_since_ms)});
    }

    if (in.subscription_gap_reason.has_value()) {
        out.events.push_back(PowerEventDraft{
            in.now, "capture_gap", *in.subscription_gap_reason,
            in.leg_tag + ":subcorrupt:" + std::to_string(in.now)});
    }

    if (in.restart_gap_since_ms.has_value()) {
        std::string detail = "power subscription restarted (process/agent restart) -- "
                             "live subscription was not running from " +
                             std::to_string(*in.restart_gap_since_ms) +
                             "ms (epoch ms) until now; events during this window are unrecoverable";
        out.events.push_back(PowerEventDraft{
            in.now, "capture_gap", detail,
            in.leg_tag + ":restart:" + std::to_string(*in.restart_gap_since_ms)});
    }

    if (in.ac_gap_reason.has_value()) {
        out.events.push_back(PowerEventDraft{
            in.now, "capture_gap", *in.ac_gap_reason,
            in.leg_tag + ":accorrupt:" + std::to_string(in.now)});
    }

    if (in.dropped_total > in.last_reported_dropped) {
        out.events.push_back(PowerEventDraft{
            in.now, "capture_gap",
            "power queue overflow: " + std::to_string(in.dropped_total - in.last_reported_dropped) +
                " event(s) dropped (bounded queue at capacity)",
            in.leg_tag + ":" + std::to_string(in.run_nonce_ms) + ":overflow:" +
                std::to_string(in.dropped_total)});
    }

    for (const auto& item : in.items) {
        if (item.kind == "sleep" || item.kind == "wake") {
            out.events.push_back(PowerEventDraft{
                item.ts, item.kind, in.sleep_wake_detail,
                in.leg_tag + ":" + std::to_string(in.run_nonce_ms) + ":sw:" +
                    std::to_string(item.seq)});
        } else if (item.kind == "ac" || item.kind == "batt") {
            auto action = ac_transition_action(out.new_last_ac, item.kind);
            if (!action.empty())
                out.events.push_back(PowerEventDraft{
                    item.ts, action, in.ac_detail,
                    in.leg_tag + ":" + std::to_string(in.run_nonce_ms) + ":ac:" +
                        std::to_string(item.seq)});
            out.new_last_ac = item.kind;
        }
    }
    return out;
}

/// Decode with PER-KEY isolation (see SubscriptionAcCursor doc above): a
/// completely unparsable document (not JSON, not an object, wrong/missing
/// "v") invalidates both sides equally -- there is nothing to salvage. Once
/// the document itself parses, `subscription_key` and "last_ac" are decoded
/// independently, so a malformed value under one key never disturbs the
/// other's reading.
inline SubscriptionAcCursor decode_subscription_ac_cursor(const char* subscription_key,
                                                           const std::string& json_text) {
    SubscriptionAcCursor out;
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(json_text);
    } catch (...) {
        out.subscription_valid = false;
        out.ac_valid = false;
        return out;
    }
    if (!j.is_object() || !j.contains("v") || !j.at("v").is_number_integer() ||
        j.at("v").get<int>() != 1) {
        out.subscription_valid = false;
        out.ac_valid = false;
        return out;
    }

    if (j.contains(subscription_key)) {
        out.subscription_present = true;
        try {
            if (!j.at(subscription_key).is_number_integer())
                throw std::runtime_error("not an integer");
            out.subscribed_since_ms = j.at(subscription_key).get<std::int64_t>();
        } catch (...) {
            out.subscription_valid = false;
        }
    }

    if (j.contains("last_ac")) {
        out.ac_present = true;
        try {
            auto ac = j.at("last_ac").get<std::string>();
            if (ac != "ac" && ac != "batt" && ac != "unknown")
                throw std::runtime_error("bad enum");
            out.last_ac = ac;
        } catch (...) {
            out.ac_valid = false;
        }
    }
    return out;
}

} // namespace yuzu::tar
