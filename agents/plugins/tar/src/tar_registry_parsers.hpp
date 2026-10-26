#pragma once

// tar_registry_parsers.hpp -- pure core for the `registry` cursor-model TAR
// source (tar_registry_source.{hpp,cpp}). Everything here is a free function
// over strings/structs: no OS handle, no file I/O -- so it compiles and
// unit-tests identically on every platform (tests/unit/test_tar_registry_source.cpp).
//
// THE MECHANISM, IN TWO LAYERS
//   Layer 1 (WHAT changed): a RegNotifyChangeKeyValue subtree watch marks a root
//     dirty; a budgeted subtree read is diffed against the root's persisted
//     BASELINE (tar_state `registry:<root>`), giving added/changed/removed values
//     with old and new data (diff_registry_snapshot).
//   Layer 2 (WHO): a write-only Kernel-Registry ETW session (SetValueKey |
//     DeleteValueKey | DeleteKey, mask 0x4300). Those events carry the writer's
//     pid and the VALUE NAME, but the key-name field is empty on most of them, so
//     the key can never be read off an event. The actor is therefore CORRELATED to
//     a Layer-1 change on value name + type + size + time window
//     (attribute_candidate), never read off an event that named the key.
//
// A change becomes a row only after its attribution is final: a candidate is HELD
// (persisted in the cursor) until kEtwSettle100ns after its window closed, since an
// event for a write just before the read can still arrive that long after it
// (stitch_registry_tick). The row is stamped with the end of the read that saw it.
//
// WHAT CORRELATION ESTABLISHES. For a candidate change C, E(C) is the set of write
// events whose signature matches C inside C's window and P(C) their distinct
// pids. While the session ran and NO loss was observed over the window, every
// successful in-scope value write produced an event, so the true writer's pid is in
// P(C); when |P(C)| == 1 that pid is the writer. The residual: a change produced
// WITHOUT a value-write event (hive load, RegRestoreKey, a transacted commit
// outside the window) has no true event in E(C), so one unrelated same-signature
// writer inside the window is correlated to it. actor_pid is an investigative lead
// to verify against $Process_Live, NOT proof. Every DETECTABLE break of the
// invariant is marked rather than guessed: loss -> attr:degraded, session down ->
// attr:off, buffer lost across a restart/pause -> attr:lost-restart, two or more
// pids -> attr:ambiguous:<n>, none -> attr:none.

#include "tar_db.hpp" // RegistryEvent

#include <nlohmann/json.hpp>
#include <sha256.hpp>
#include <user_profile_model.hpp> // yuzu::profiles::reg_type_name

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <format>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace yuzu::tar {

// ── Constants ───────────────────────────────────────────────────────────────

inline constexpr std::size_t kRegistryDataCap = 4096;       // rendered new value, bytes of text
inline constexpr std::size_t kBaselineRenderCap = 512;      // rendered prefix kept in the baseline
inline constexpr std::size_t kBaselineValueCap = 50000;     // values per root read
inline constexpr std::size_t kBaselineKeyCap = 20000;       // keys per root read
inline constexpr std::size_t kBaselineDepthCap = 16;
inline constexpr std::size_t kBaselineValueReadCap = 4u * 1024u * 1024u; // bytes read per value
inline constexpr std::size_t kBaselineBytesCap = 64u * 1024u * 1024u;    // bytes read per root
inline constexpr std::size_t kSkippedCap = 32; // access-denied child keys recorded per root read
inline constexpr std::int64_t kSnapshotBudget100ns = 10LL * 10'000'000;  // 10 s
inline constexpr std::int64_t kReconcileEveryTicks = 12;     // 12 x 300 s = hourly full re-read
inline constexpr std::size_t kRegistryEtwBufferCap = 65536;  // buffered write events; oldest evicted past it
inline constexpr std::int64_t kEtwWindowSlack100ns = 10'000'000; // 1 s either side of a notify burst
inline constexpr std::int64_t kEtwSettle100ns = 50'000'000;      // 5 s: how long a late event may trail its write
inline constexpr std::size_t kLossEpochCap = 64; // loss epochs kept before they collapse into one
inline constexpr std::size_t kWatchHandleCap = 62; // + HKEY_USERS name watch + stop event = 64

inline constexpr std::uint64_t kEtwKeywordMask = 0x4300; // SetValueKey 0x100 | DeleteValueKey 0x200 | DeleteKey 0x4000

static_assert(kWatchHandleCap + 2 <= 64, "WaitForMultipleObjects takes at most 64 handles");

inline constexpr std::int64_t kFiletimeUnixDelta100ns = 116444736000000000LL; // 1601 -> 1970

[[nodiscard]] inline std::int64_t filetime_to_unix_ms(std::int64_t ft) {
    return ft < kFiletimeUnixDelta100ns ? 0 : (ft - kFiletimeUnixDelta100ns) / 10000;
}

// ── Scope ────────────────────────────────────────────────────────────────────

/// The curated watch list: HKLM roots, plus suffixes applied to every loaded
/// per-user hive. A root is a normalised path with a leading hive token:
/// `HKLM\<path>` or `HKU\<sid>\<path>`.
struct RegistryScope {
    std::vector<std::string> hklm;       // HKLM-relative paths
    std::vector<std::string> hku_suffix; // appended after the HKU sid component

    /// Concrete roots for the loaded hive names under HKEY_USERS. Only SID-named hives
    /// are user profiles (see is_user_hive_name); every other name is skipped.
    [[nodiscard]] std::vector<std::string>
    roots_for(const std::vector<std::string>& hku_subkeys) const;
};

/// A loaded user profile's HKEY_USERS key is its SID: "S-1-" and then digits and dashes.
/// Anything else is not watched -- `.DEFAULT`, `<sid>_Classes`, and the temporary
/// `YUZU_HIVE_<sid>_<hex>_<n>` mounts sibling plugins load for a logged-out profile and
/// unload without force: a watch handle held open on one would fail that unload and leave
/// the user's NTUSER.DAT locked.
[[nodiscard]] inline bool is_user_hive_name(std::string_view n) {
    constexpr std::string_view kSidPrefix = "S-1-";
    if (!n.starts_with(kSidPrefix) || n.size() == kSidPrefix.size())
        return false;
    return std::all_of(n.begin() + kSidPrefix.size(), n.end(),
                       [](char c) { return (c >= '0' && c <= '9') || c == '-'; });
}

inline std::vector<std::string>
RegistryScope::roots_for(const std::vector<std::string>& hku_subkeys) const {
    std::vector<std::string> out;
    for (const auto& p : hklm)
        out.push_back("HKLM\\" + p);
    for (const auto& sid : hku_subkeys) {
        if (!is_user_hive_name(sid))
            continue;
        for (const auto& s : hku_suffix)
            out.push_back("HKU\\" + sid + "\\" + s);
    }
    return out;
}

[[nodiscard]] inline RegistryScope default_registry_scope() {
    RegistryScope s;
    s.hklm = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SYSTEM\\CurrentControlSet\\Services",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "SYSTEM\\CurrentControlSet\\Control\\Lsa",
        "SOFTWARE\\Policies",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
        "SOFTWARE\\Microsoft\\Windows Defender",
    };
    s.hku_suffix = {
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Software\\Policies",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies",
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    };
    return s;
}

/// Maps `...\SYSTEM\ControlSetNNN\...` to `...\SYSTEM\CurrentControlSet\...` when
/// NNN is the control set the machine booted from (HKLM\SYSTEM\Select\Current),
/// so a path given as the numbered set and the same keys addressed as the
/// current one are one baseline. Any other numbered set is left alone. Case is
/// preserved; the comparison is case-insensitive.
[[nodiscard]] inline std::string normalise_registry_path(std::string_view path,
                                                         int current_control_set) {
    const std::string want = std::format("controlset{:03}", current_control_set);
    std::string out;
    std::size_t pos = 0;
    while (pos <= path.size()) {
        const auto next = path.find('\\', pos);
        const auto seg =
           path.substr(pos, next == std::string_view::npos ? std::string_view::npos : next - pos);
        std::string lower(seg);
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (pos != 0)
            out += '\\';
        out += (lower == want) ? std::string_view{"CurrentControlSet"} : seg;
        if (next == std::string_view::npos)
            break;
        pos = next + 1;
    }
    return out;
}

/// Splits a root or key path into the hive token and the remainder.
[[nodiscard]] inline std::pair<std::string, std::string> split_hive(std::string_view full) {
    const auto b = full.find('\\');
    if (b == std::string_view::npos)
        return {std::string(full), {}};
    return {std::string(full.substr(0, b)), std::string(full.substr(b + 1))};
}

// ── Value rendering ─────────────────────────────────────────────────────────

struct RenderedData {
    std::string text;
    bool truncated{false};
};

namespace registry_detail {

inline void append_utf8(std::string& out, std::uint32_t cp) {
    if (cp < 0x80) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800) {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

/// UTF-16LE -> UTF-8. A trailing odd byte is dropped; a lone surrogate becomes
/// U+FFFD. Stops once `limit` output bytes are produced (sets `cut`).
inline std::string utf16le_to_utf8(std::string_view bytes, std::size_t limit, bool& cut) {
    std::string out;
    cut = false;
    const std::size_t units = bytes.size() / 2;
    auto unit = [&](std::size_t i) {
        return static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[2 * i])) |
               (static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[2 * i + 1])) << 8);
    };
    for (std::size_t i = 0; i < units; ++i) {
        if (out.size() >= limit) {
            cut = true;
            break;
        }
        std::uint32_t u = unit(i);
        if (u >= 0xD800 && u <= 0xDBFF && i + 1 < units && unit(i + 1) >= 0xDC00 &&
            unit(i + 1) <= 0xDFFF) {
            u = 0x10000 + ((u - 0xD800) << 10) + (unit(i + 1) - 0xDC00);
            ++i;
        } else if (u >= 0xD800 && u <= 0xDFFF) {
            u = 0xFFFD;
        }
        append_utf8(out, u);
    }
    return out;
}

/// Trim to `cap` bytes without splitting a UTF-8 sequence. Returns true if cut.
inline bool clip_utf8(std::string& s, std::size_t cap) {
    if (s.size() <= cap)
        return false;
    std::size_t n = cap;
    while (n > 0 && (static_cast<unsigned char>(s[n]) & 0xC0) == 0x80)
        --n;
    s.resize(n);
    return true;
}

} // namespace registry_detail

/// Text for a registry value, in the shape registry_plugin.cpp renders: SZ /
/// EXPAND_SZ / LINK -> UTF-8 up to the first NUL, MULTI_SZ -> '\n'-joined,
/// DWORD / QWORD decimal, everything else lowercase hex. `cap` bounds the TEXT.
[[nodiscard]] inline RenderedData render_reg_data(std::uint32_t type, std::string_view bytes,
                                                  std::size_t cap) {
    namespace P = yuzu::profiles;
    RenderedData r;
    if (type == P::kRegSz || type == P::kRegExpandSz || type == P::kRegLink) {
        bool cut = false;
        r.text = registry_detail::utf16le_to_utf8(bytes, cap + 4, cut);
        if (const auto nul = r.text.find('\0'); nul != std::string::npos) {
            r.text.resize(nul);
            cut = false;
        }
        r.truncated = registry_detail::clip_utf8(r.text, cap) || cut;
        return r;
    }
    if (type == P::kRegMultiSz) {
        bool cut = false;
        std::string all = registry_detail::utf16le_to_utf8(bytes, cap + 4, cut);
        // Records are NUL-separated; the list ends at the first EMPTY record.
        std::string joined;
        std::size_t pos = 0;
        while (pos < all.size()) {
            auto nul = all.find('\0', pos);
            const bool last = nul == std::string::npos;
            if (last)
                nul = all.size();
            if (nul == pos)
                break;
            if (!joined.empty())
                joined += '\n';
            joined.append(all, pos, nul - pos);
            if (last)
                break;
            pos = nul + 1;
        }
        r.text = std::move(joined);
        r.truncated = registry_detail::clip_utf8(r.text, cap) || cut;
        return r;
    }
    if (type == P::kRegDword && bytes.size() == 4) {
        std::uint32_t v = 0;
        for (int i = 3; i >= 0; --i)
            v = (v << 8) | static_cast<unsigned char>(bytes[static_cast<std::size_t>(i)]);
        r.text = std::to_string(v);
        return r;
    }
    if (type == P::kRegQword && bytes.size() == 8) {
        std::uint64_t v = 0;
        for (int i = 7; i >= 0; --i)
            v = (v << 8) | static_cast<unsigned char>(bytes[static_cast<std::size_t>(i)]);
        r.text = std::to_string(v);
        return r;
    }
    static constexpr char kHex[] = "0123456789abcdef";
    const std::size_t take = std::min(bytes.size(), cap / 2);
    r.text.reserve(take * 2);
    for (std::size_t i = 0; i < take; ++i) {
        const auto b = static_cast<unsigned char>(bytes[i]);
        r.text += kHex[b >> 4];
        r.text += kHex[b & 0xF];
    }
    r.truncated = bytes.size() > take;
    return r;
}

// ── Reads and baselines ─────────────────────────────────────────────────────

enum class RegistryReadStatus { Complete, Absent, Unreadable, Capped };

[[nodiscard]] inline std::string_view to_string(RegistryReadStatus s) {
    switch (s) {
    case RegistryReadStatus::Complete: return "complete";
    case RegistryReadStatus::Absent: return "absent";
    case RegistryReadStatus::Unreadable: return "unreadable";
    case RegistryReadStatus::Capped: return "capped";
    }
    return "unreadable";
}

/// One value as the reader returned it. `bytes` is at most kBaselineValueReadCap;
/// `truncated` means the value was larger than that and `bytes` is a prefix (or
/// empty when the registry API cannot return a partial read).
struct RegistryValueRead {
    std::uint32_t type{0};
    std::uint64_t full_size{0};
    std::string bytes;
    bool truncated{false};
};

/// One bounded subtree read: key path (full, `HKLM\...`) -> value name -> value.
/// Every visited key is present, with an empty map when it holds no values, so a
/// vanished key is distinguishable from a key that never had values.
///
/// `skipped` names the child keys the reader was denied access to (full paths, at
/// most kSkippedCap; one more makes the read Capped). They are absent from `keys`,
/// and the diff keeps whatever the baseline holds at or under them rather than
/// reading their absence as a deletion. A denied child therefore never blinds the
/// rest of its root. `Unreadable` means the root, or any key beneath it other than an
/// access-denied child, could not be read.
struct SubtreeRead {
    RegistryReadStatus status{RegistryReadStatus::Unreadable};
    std::map<std::string, std::map<std::string, RegistryValueRead>> keys;
    std::vector<std::string> skipped;
};

/// True when `key` is `prefix` itself or a descendant of it (on a path-separator
/// boundary, so `...\Run2` is not under `...\Run`).
[[nodiscard]] inline bool registry_key_under(std::string_view key, std::string_view prefix) {
    return key.starts_with(prefix) && (key.size() == prefix.size() || key[prefix.size()] == '\\');
}

/// Pure budget accounting for the production reader (R9): one place decides when
/// a read has visited as much as a root may cost.
class RegistryReadBudget {
public:
    [[nodiscard]] bool admit_key() { return ++keys_ <= kBaselineKeyCap; }
    [[nodiscard]] bool admit_value(std::size_t bytes) {
        bytes_ += bytes;
        return ++values_ <= kBaselineValueCap && bytes_ <= kBaselineBytesCap;
    }
    [[nodiscard]] static bool depth_ok(std::size_t depth) { return depth <= kBaselineDepthCap; }

private:
    std::size_t keys_{0}, values_{0}, bytes_{0};
};

/// What the baseline remembers about a value: type, full stored size, a hash of
/// every byte read (R8: a change anywhere in the value shows), a rendered prefix
/// for the old-value column, and `dt` = the value exceeded kBaselineValueReadCap, so
/// `h` covers only what the reader returned (nothing, from the Windows API, which has
/// no partial read) and a change that keeps the type and size is not detected.
struct BaselineEntry {
    std::uint32_t t{0};
    std::uint64_t s{0};
    std::string h;
    std::string d;
    bool dt{false};
    bool operator==(const BaselineEntry&) const = default;
};

[[nodiscard]] inline BaselineEntry baseline_entry_from_bytes(std::uint32_t type,
                                                             std::uint64_t full_size,
                                                             std::string_view bytes,
                                                             bool truncated) {
    BaselineEntry e;
    e.t = type;
    e.s = full_size;
    yuzu::shared::Sha256 sha;
    sha.update(bytes.data(), bytes.size());
    e.h = sha.hex_digest().substr(0, 32); // 128 bits
    e.d = render_reg_data(type, bytes, kBaselineRenderCap).text;
    e.dt = truncated;
    return e;
}

struct RegistryBaseline {
    std::map<std::string, std::map<std::string, BaselineEntry>> keys;
    bool operator==(const RegistryBaseline&) const = default;
};

[[nodiscard]] inline std::string fold_value_name(std::string_view n) {
    std::string out(n);
    for (auto& c : out)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    return out;
}

struct RegistryWindow {
    std::int64_t lo{0}, hi{0};
};

/// The time window (lo, hi] (FILETIME 100 ns) in which a change observed by a read
/// ending at `read_end` must have been written. `window_base` is the root's last
/// COMPLETE read start (R5: a Capped/Unreadable read does not advance it, so a
/// change in the unvisited part cannot fall outside the next window). A
/// notify-triggered read (first_dirty != 0) is tightened to the notify burst
/// +/- slack; a reconcile read keeps the whole interval.
[[nodiscard]] inline RegistryWindow candidate_window(std::int64_t window_base, std::int64_t read_end,
                                                     std::int64_t first_dirty,
                                                     std::int64_t last_dirty, std::int64_t slack) {
    RegistryWindow wide{window_base, read_end};
    if (wide.hi < wide.lo)
        wide.lo = wide.hi;
    if (first_dirty == 0)
        return wide;
    RegistryWindow w;
    w.lo = std::max(window_base, first_dirty - slack);
    w.hi = std::min(read_end, last_dirty + slack);
    if (w.lo > w.hi)
        return wide; // inconsistent stamps: never narrow on them
    return w;
}

/// A change the key watch observed, awaiting its attribution (held for the settle
/// interval) and then written as one registry_live row.
struct RegistryCandidate {
    std::string root;
    std::string key; // full, HKLM\... / HKU\<sid>\...
    std::string value;
    std::string action; // added | changed | removed | key_removed
    std::uint32_t type{0};
    std::uint64_t size{0};
    std::string data;
    bool data_truncated{false};
    bool has_prev{false};
    std::uint32_t prev_type{0};
    std::uint64_t prev_size{0};
    std::string prev_data;
    bool prev_truncated{false};
    std::int64_t observed_at{0}; // FILETIME of the read that saw it
    std::int64_t window_lo{0}, window_hi{0}; // (lo, hi]: when the write must have happened
    std::string source;                      // notify | reconcile
};

struct DiffResult {
    std::vector<RegistryCandidate> candidates;
    RegistryBaseline baseline;
    bool changed{false}; // the baseline differs from the one passed in
};

[[nodiscard]] inline RegistryBaseline baseline_from_read(const SubtreeRead& read) {
    RegistryBaseline b;
    for (const auto& [key, values] : read.keys) {
        auto& m = b.keys[key];
        for (const auto& [name, v] : values)
            m[name] = baseline_entry_from_bytes(v.type, v.full_size, v.bytes, v.truncated);
    }
    return b;
}

/// Diffs a read against a root's baseline. Removals are derived ONLY from a
/// Complete or Absent read (a partial read cannot prove anything is gone) and
/// never for a key at or under one of `read.skipped`, whose baseline is kept as
/// it was; Unreadable changes nothing; Capped adds/updates what it visited and
/// retains the rest. `suppress` returns the new baseline with no candidates (the
/// first read of a root). Every candidate carries its `root` and `window`.
[[nodiscard]] inline DiffResult diff_registry_snapshot(const RegistryBaseline& base,
                                                       const SubtreeRead& read,
                                                       std::string_view root,
                                                       std::string_view source,
                                                       const RegistryWindow& window,
                                                       std::int64_t observed_at,
                                                       bool suppress = false) {
    DiffResult r;
    if (read.status == RegistryReadStatus::Unreadable) {
        r.baseline = base;
        return r;
    }
    const bool authoritative =
       read.status == RegistryReadStatus::Complete || read.status == RegistryReadStatus::Absent;
    r.baseline = authoritative ? RegistryBaseline{} : base;

    auto make = [&](const std::string& key, const std::string& value, const char* action) {
        RegistryCandidate c;
        c.root = std::string(root);
        c.key = key;
        c.value = value;
        c.action = action;
        c.observed_at = observed_at;
        c.window_lo = window.lo;
        c.window_hi = window.hi;
        c.source = std::string(source);
        return c;
    };
    auto set_prev = [](RegistryCandidate& c, const BaselineEntry& e) {
        c.has_prev = true;
        c.prev_type = e.t;
        c.prev_size = e.s;
        c.prev_data = e.d;
        c.prev_truncated = e.dt || e.d.size() >= kBaselineRenderCap;
    };

    for (const auto& [key, values] : read.keys) {
        auto& out_vals = r.baseline.keys[key];
        const auto bk = base.keys.find(key);
        for (const auto& [name, v] : values) {
            BaselineEntry now = baseline_entry_from_bytes(v.type, v.full_size, v.bytes, v.truncated);
            const BaselineEntry* before = nullptr;
            if (bk != base.keys.end())
                if (auto it = bk->second.find(name); it != bk->second.end())
                    before = &it->second;
            const bool differs = before == nullptr || before->t != now.t || before->s != now.s ||
                                 before->h != now.h;
            if (differs && !suppress) {
                RegistryCandidate c = make(key, name, before ? "changed" : "added");
                c.type = v.type;
                c.size = v.full_size;
                auto rd = render_reg_data(v.type, v.bytes, kRegistryDataCap);
                c.data = std::move(rd.text);
                c.data_truncated = rd.truncated || v.truncated;
                if (before)
                    set_prev(c, *before);
                r.candidates.push_back(std::move(c));
            }
            out_vals[name] = std::move(now);
        }
    }

    if (authoritative) {
        const auto under_skipped = [&](const std::string& key) {
            return std::any_of(read.skipped.begin(), read.skipped.end(), [&](const std::string& p) {
                return registry_key_under(key, p);
            });
        };
        for (const auto& [key, values] : base.keys) {
            if (read.keys.contains(key))
                continue;
            if (under_skipped(key)) {
                r.baseline.keys[key] = values; // not readable now: nothing proves it is gone
                continue;
            }
            // A whole key vanished: each of its values, then the key itself.
            for (const auto& [name, e] : values) {
                if (suppress)
                    break;
                RegistryCandidate c = make(key, name, "removed");
                set_prev(c, e);
                r.candidates.push_back(std::move(c));
            }
            if (!suppress)
                r.candidates.push_back(make(key, {}, "key_removed"));
        }
        // Values removed from a key that survived.
        for (const auto& [key, values] : read.keys) {
            const auto bk = base.keys.find(key);
            if (bk == base.keys.end() || suppress)
                continue;
            for (const auto& [name, e] : bk->second) {
                if (values.contains(name))
                    continue;
                RegistryCandidate c = make(key, name, "removed");
                set_prev(c, e);
                r.candidates.push_back(std::move(c));
            }
        }
    }
    // A Capped read started from a copy of the baseline: what it did not return
    // (it may simply be past the cap) stays, and only what it visited is updated.
    r.changed = !(r.baseline == base);
    return r;
}

// ── ETW events and attribution ──────────────────────────────────────────────

enum class RegistryEtwOp { Set, DeleteValue, DeleteKey };

struct RegistryEtwEvent {
    std::uint64_t seq{0}; // assigned by the buffer
    std::int64_t ts100ns{0};
    std::uint32_t pid{0};
    std::uint32_t tid{0};
    std::string image;
    std::uint64_t key_object{0}; // dedupe only -- no inference is drawn from it
    RegistryEtwOp op{RegistryEtwOp::Set};
    std::string value;
    std::uint32_t type{0};
    std::uint32_t size{0};
};

struct LossEpoch {
    std::int64_t lo{0}, hi{0}; // closed [lo, hi]
    bool operator==(const LossEpoch&) const = default;
};

[[nodiscard]] inline bool window_intersects(const RegistryWindow& w, const LossEpoch& e) {
    return e.lo <= w.hi && e.hi > w.lo;
}

[[nodiscard]] inline bool intersects_loss(const RegistryCandidate& c,
                                          const std::vector<LossEpoch>& epochs) {
    const RegistryWindow w{c.window_lo, c.window_hi};
    return std::any_of(epochs.begin(), epochs.end(),
                       [&](const LossEpoch& e) { return window_intersects(w, e); });
}

/// Appends an epoch; past kLossEpochCap everything collapses into one covering
/// interval (conservative: it can only degrade more candidates, never fewer).
inline void append_loss_epoch(std::vector<LossEpoch>& epochs, LossEpoch e) {
    if (e.hi < e.lo)
        e.hi = e.lo;
    epochs.push_back(e);
    if (epochs.size() <= kLossEpochCap)
        return;
    LossEpoch all = epochs.front();
    for (const auto& x : epochs) {
        all.lo = std::min(all.lo, x.lo);
        all.hi = std::max(all.hi, x.hi);
    }
    epochs.assign(1, all);
}

/// Drops epochs no future window can reach (hi < `floor`).
inline void age_loss_epochs(std::vector<LossEpoch>& epochs, std::int64_t floor) {
    std::erase_if(epochs, [&](const LossEpoch& e) { return e.hi < floor; });
}

enum class AttributionKind { Corr, Ambiguous, None };

struct Attribution {
    AttributionKind kind{AttributionKind::None};
    std::uint32_t pid{0};
    std::string image;
    std::size_t n_pids{0};
    std::size_t n_events{0};
};

/// Drops repeated deliveries of one event (same ts, pid, tid, key object, op, value).
[[nodiscard]] inline std::vector<RegistryEtwEvent>
dedupe_registry_events(std::vector<RegistryEtwEvent> events) {
    std::set<std::tuple<std::int64_t, std::uint32_t, std::uint32_t, std::uint64_t, int,
                        std::string>>
       seen;
    std::vector<RegistryEtwEvent> out;
    out.reserve(events.size());
    for (auto& e : events) {
        if (seen.emplace(e.ts100ns, e.pid, e.tid, e.key_object, static_cast<int>(e.op), e.value)
               .second)
            out.push_back(std::move(e));
    }
    return out;
}

/// Matches write events to a candidate on signature and window (see the header
/// comment for what this establishes). `key_removed` is never attributed: a
/// DeleteKey event carries no name, and no sibling inference is drawn. A writer is
/// named ONLY when exactly one pid matches.
[[nodiscard]] inline Attribution attribute_candidate(const RegistryCandidate& c,
                                                     const std::vector<RegistryEtwEvent>& events) {
    Attribution a;
    if (c.action == "key_removed")
        return a;
    const bool is_set = c.action == "added" || c.action == "changed";
    const std::string name = fold_value_name(c.value);
    const RegistryEtwEvent* last = nullptr;
    std::set<std::uint32_t> pids;
    for (const auto& e : events) {
        if (!(c.window_lo < e.ts100ns && e.ts100ns <= c.window_hi))
            continue;
        if (is_set) {
            if (e.op != RegistryEtwOp::Set || e.type != c.type || e.size != c.size)
                continue;
        } else if (e.op != RegistryEtwOp::DeleteValue) {
            continue;
        }
        if (fold_value_name(e.value) != name)
            continue;
        pids.insert(e.pid);
        ++a.n_events;
        if (last == nullptr || e.ts100ns >= last->ts100ns)
            last = &e;
    }
    a.n_pids = pids.size();
    if (pids.size() == 1 && last != nullptr) {
        a.kind = AttributionKind::Corr;
        a.pid = last->pid;
        a.image = last->image;
    } else if (pids.size() >= 2) {
        a.kind = AttributionKind::Ambiguous;
    }
    return a;
}

struct StitchFlags {
    bool etw_running{true};
    bool restarted{false};        // the event buffer was discarded since the candidates were read
    std::int64_t events_since{0}; // the buffer holds nothing from before this instant (0 = n/a)
};

struct StitchCounters {
    std::uint64_t attributed{0}, ambiguous{0}, none{0};
};

struct StitchResult {
    std::vector<RegistryEvent> rows;
    std::vector<RegistryCandidate> held_next;
    StitchCounters counters;
};

// ── Rows ────────────────────────────────────────────────────────────────────

namespace registry_detail {

inline std::string rk_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\\')
            out += "\\\\";
        else if (c == '\0')
            out += "\\0";
        else
            out += c;
    }
    return out;
}

} // namespace registry_detail

/// Diff-row key: independent of attribution (so a retry after a restart re-derives
/// the same key whatever the buffer then holds) and length-framed so key/value
/// cannot be re-split into another pair. NUL (legal in a registry name) and '\' are escaped, as the store refuses
/// a NUL-bearing key.
[[nodiscard]] inline std::string registry_diff_record_key(std::string_view source,
                                                          std::int64_t read_end,
                                                          std::string_view action,
                                                          std::string_view key,
                                                          std::string_view value) {
    const std::string k = registry_detail::rk_escape(key);
    return std::format("{}:{}:{}:{}:{}{}", source, read_end, action, k.size(), k,
                       registry_detail::rk_escape(value));
}

/// kind in restart | disabled | cursorlost | loss | baselinelost | unreadable; `ident`
/// is a timestamp or the root.
[[nodiscard]] inline std::string registry_gap_record_key(std::string_view kind,
                                                         std::string_view ident) {
    return std::format("gap:{}:{}", kind, registry_detail::rk_escape(ident));
}

[[nodiscard]] inline RegistryEvent registry_gap_row(std::string_view kind, std::string_view ident,
                                                    std::string detail, std::int64_t now100ns,
                                                    std::int64_t snapshot_id) {
    RegistryEvent ev;
    const auto ms = filetime_to_unix_ms(now100ns);
    ev.ts = ms / 1000;
    ev.snapshot_id = snapshot_id;
    ev.action = "capture_gap";
    ev.observed_at = ms;
    ev.detail = std::move(detail);
    ev.record_key = registry_gap_record_key(kind, ident);
    return ev;
}

[[nodiscard]] inline RegistryEvent
registry_row_from_candidate(const RegistryCandidate& c, std::uint32_t actor_pid,
                            const std::string& actor_image, std::string detail,
                            std::int64_t snapshot_id) {
    RegistryEvent ev;
    const auto ms = filetime_to_unix_ms(c.observed_at);
    ev.ts = ms / 1000;
    ev.snapshot_id = snapshot_id;
    auto [hive, rest] = split_hive(c.key);
    ev.hive = std::move(hive);
    ev.key_path = std::move(rest);
    ev.value_name = c.value;
    ev.action = c.action;
    if (c.action == "added" || c.action == "changed") {
        ev.data_type = std::string(yuzu::profiles::reg_type_name(c.type));
        ev.data = c.data;
        ev.data_size = static_cast<std::int64_t>(c.size);
        ev.data_truncated = c.data_truncated ? 1 : 0;
    }
    if (c.has_prev) {
        ev.prev_data_type = std::string(yuzu::profiles::reg_type_name(c.prev_type));
        ev.prev_data = c.prev_data;
        ev.prev_data_size = static_cast<std::int64_t>(c.prev_size);
        ev.prev_data_truncated = c.prev_truncated ? 1 : 0;
    }
    ev.actor_pid = actor_pid;
    ev.actor_image = actor_image;
    ev.source = c.source;
    ev.observed_at = ms;
    ev.detail = std::move(detail);
    ev.record_key =
       registry_diff_record_key(c.source, c.observed_at, c.action, c.key, c.value);
    return ev;
}

/// Finalises every held candidate whose window closed at least kEtwSettle100ns
/// before `now` (a late event for a write just before the read can still arrive
/// that long after it); the rest stay held. Order of precedence for the marker:
/// buffer discarded (lost-restart) > session down (off) > loss over the window
/// (degraded) > the correlation outcome.
[[nodiscard]] inline StitchResult
stitch_registry_tick(const std::vector<RegistryCandidate>& candidates,
                     const std::vector<RegistryEtwEvent>& raw_events,
                     const std::vector<LossEpoch>& epochs, const StitchFlags& flags,
                     std::int64_t now, std::int64_t snapshot_id) {
    StitchResult out;
    const auto events = dedupe_registry_events(raw_events);
    for (const auto& c : candidates) {
        if (now - c.window_hi < kEtwSettle100ns) {
            out.held_next.push_back(c);
            continue;
        }
        std::uint32_t pid = 0;
        std::string image;
        std::string detail;
        if (flags.restarted || c.window_lo < flags.events_since) {
            detail = "attr:lost-restart";
            ++out.counters.none;
        } else if (!flags.etw_running) {
            detail = "attr:off";
            ++out.counters.none;
        } else if (intersects_loss(c, epochs)) {
            detail = "attr:degraded";
            ++out.counters.none;
        } else {
            const Attribution a = attribute_candidate(c, events);
            switch (a.kind) {
            case AttributionKind::Corr:
                pid = a.pid;
                image = a.image;
                detail = a.n_events > 1 ? std::format("attr:corr;events:{}", a.n_events)
                                        : std::string{"attr:corr"};
                ++out.counters.attributed;
                break;
            case AttributionKind::Ambiguous:
                detail = std::format("attr:ambiguous:{}", a.n_pids);
                ++out.counters.ambiguous;
                break;
            case AttributionKind::None:
                detail = "attr:none";
                ++out.counters.none;
                break;
            }
        }
        out.rows.push_back(registry_row_from_candidate(c, pid, image, std::move(detail), snapshot_id));
    }
    return out;
}

// ── Retention ───────────────────────────────────────────────────────────────

struct RegistryRootState {
    bool baselined{false};
    std::int64_t window_base{0}; // last COMPLETE (or Absent) read_start; 0 = never
    std::int64_t read_start{0};
    std::int64_t read_end{0};
    std::string status; // complete | absent | unreadable | capped | due
    bool armed{true};
    std::vector<std::string> skipped; // denied child keys (sorted; a Capped read only adds): a new member is a gap
    bool operator==(const RegistryRootState&) const = default;
};

/// Every future candidate's window starts at or after its root's window_base, so
/// an event at or before the minimum of them can never be matched again. A root
/// never completely read contributes 0 (retain everything until the cap).
[[nodiscard]] inline std::int64_t
retention_watermark(const std::map<std::string, RegistryRootState>& roots) {
    if (roots.empty())
        return std::numeric_limits<std::int64_t>::max();
    std::int64_t m = std::numeric_limits<std::int64_t>::max();
    for (const auto& [_, st] : roots)
        m = std::min(m, st.window_base);
    return m;
}

/// May `e` be erased? Only if no future window can need it AND no held
/// candidate's window still covers it.
[[nodiscard]] inline bool release_event(const RegistryEtwEvent& e, std::int64_t watermark,
                                        const std::vector<RegistryCandidate>& held) {
    if (e.ts100ns > watermark)
        return false;
    return std::none_of(held.begin(), held.end(), [&](const RegistryCandidate& h) {
        return h.window_lo < e.ts100ns && e.ts100ns <= h.window_hi;
    });
}

// ── Cursor state and codecs ─────────────────────────────────────────────────

/// The cursor row is a content store (v1): besides positions it holds the HELD
/// candidates -- changes the key watch saw whose attribution is not final yet --
/// with their rendered old and new values, for up to one settle interval.
struct RegistryCursor {
    bool present{false};   // a cursor was supplied at all
    bool malformed{false}; // supplied but unusable (CursorLost, never a Baseline)
    std::int64_t tick{0};
    std::map<std::string, RegistryRootState> roots;
    std::vector<RegistryCandidate> held;
    std::vector<LossEpoch> loss;
    std::vector<std::string> hku;
    std::string ccs; // ControlSetNNN the machine was on when the baselines were taken
};

namespace registry_detail {

inline nlohmann::json candidate_to_json(const RegistryCandidate& c) {
    return {{"r", c.root},         {"k", c.key},          {"v", c.value},
            {"a", c.action},       {"t", c.type},         {"s", c.size},
            {"d", c.data},         {"dtr", c.data_truncated}, {"hp", c.has_prev},
            {"pt", c.prev_type},   {"ps", c.prev_size},   {"pd", c.prev_data},
            {"ptr", c.prev_truncated}, {"o", c.observed_at}, {"lo", c.window_lo},
            {"hi", c.window_hi},   {"src", c.source}};
}

inline RegistryCandidate candidate_from_json(const nlohmann::json& j) {
    RegistryCandidate c;
    c.root = j.at("r").get<std::string>();
    c.key = j.at("k").get<std::string>();
    c.value = j.at("v").get<std::string>();
    c.action = j.at("a").get<std::string>();
    c.type = j.at("t").get<std::uint32_t>();
    c.size = j.at("s").get<std::uint64_t>();
    c.data = j.at("d").get<std::string>();
    c.data_truncated = j.at("dtr").get<bool>();
    c.has_prev = j.at("hp").get<bool>();
    c.prev_type = j.at("pt").get<std::uint32_t>();
    c.prev_size = j.at("ps").get<std::uint64_t>();
    c.prev_data = j.at("pd").get<std::string>();
    c.prev_truncated = j.at("ptr").get<bool>();
    c.observed_at = j.at("o").get<std::int64_t>();
    c.window_lo = j.at("lo").get<std::int64_t>();
    c.window_hi = j.at("hi").get<std::int64_t>();
    c.source = j.at("src").get<std::string>();
    return c;
}

} // namespace registry_detail

[[nodiscard]] inline RegistryCursor decode_registry_cursor(const std::optional<std::string>& json) {
    RegistryCursor cur;
    if (!json)
        return cur; // absent: a first-ever tick, not a lost cursor
    cur.present = true;
    try {
        const auto j = nlohmann::json::parse(*json);
        if (!j.is_object() || j.at("v").get<int>() != 1) {
            cur.malformed = true; // empty, wrong shape or a version this build cannot read
            return cur;
        }
        cur.tick = j.at("tick").get<std::int64_t>();
        cur.ccs = j.value("ccs", std::string{});
        for (const auto& [name, r] : j.at("roots").items()) {
            RegistryRootState st;
            st.baselined = r.at("baselined").get<bool>();
            // Optional: a cursor written before window_base existed decodes with 0 (a wide
            // first window, which the first complete read narrows).
            st.window_base = r.value("window_base", std::int64_t{0});
            st.read_start = r.at("read_start").get<std::int64_t>();
            st.read_end = r.at("read_end").get<std::int64_t>();
            st.status = r.at("status").get<std::string>();
            st.armed = r.at("armed").get<bool>();
            st.skipped = r.value("skipped", std::vector<std::string>{});
            cur.roots.emplace(name, std::move(st));
        }
        // Optional: a cursor written before held/loss existed has neither, and holds no
        // candidate. A present-but-malformed element still throws into CursorLost below.
        if (const auto it = j.find("held"); it != j.end())
            for (const auto& h : it->get<std::vector<nlohmann::json>>())
                cur.held.push_back(registry_detail::candidate_from_json(h));
        if (const auto it = j.find("loss"); it != j.end())
            for (const auto& e : it->get<std::vector<nlohmann::json>>())
                cur.loss.push_back({e.at(0).get<std::int64_t>(), e.at(1).get<std::int64_t>()});
        for (const auto& s : j.at("hku"))
            cur.hku.push_back(s.get<std::string>());
        // An unknown field is ignored, so a later build can add state to this v1 cursor.
    } catch (const nlohmann::json::exception&) {
        RegistryCursor lost;
        lost.present = true;
        lost.malformed = true;
        return lost;
    }
    return cur;
}

[[nodiscard]] inline std::string encode_registry_cursor(const RegistryCursor& cur) {
    nlohmann::json j;
    j["v"] = 1;
    j["tick"] = cur.tick;
    j["ccs"] = cur.ccs;
    auto roots = nlohmann::json::object();
    for (const auto& [name, st] : cur.roots)
        roots[name] = {{"baselined", st.baselined},   {"window_base", st.window_base},
                       {"read_start", st.read_start}, {"read_end", st.read_end},
                       {"status", st.status},         {"armed", st.armed},
                       {"skipped", st.skipped}};
    j["roots"] = std::move(roots);
    auto held = nlohmann::json::array();
    for (const auto& c : cur.held)
        held.push_back(registry_detail::candidate_to_json(c));
    j["held"] = std::move(held);
    auto loss = nlohmann::json::array();
    for (const auto& e : cur.loss)
        loss.push_back(nlohmann::json::array({e.lo, e.hi}));
    j["loss"] = std::move(loss);
    j["hku"] = cur.hku;
    // A registry value can hold bytes that are not valid UTF-8 after rendering;
    // never let that decide whether the cursor can be written.
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

struct DecodedBaseline {
    bool malformed{false};
    RegistryBaseline baseline;
};

[[nodiscard]] inline std::string encode_registry_baseline(const RegistryBaseline& b) {
    nlohmann::json keys = nlohmann::json::object();
    for (const auto& [k, values] : b.keys) {
        auto vj = nlohmann::json::object();
        for (const auto& [n, e] : values)
            vj[n] = {{"t", e.t}, {"s", e.s}, {"h", e.h}, {"d", e.d}, {"dt", e.dt}};
        keys[k] = std::move(vj);
    }
    nlohmann::json j;
    j["v"] = 1;
    j["keys"] = std::move(keys);
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

/// nullopt input is "no baseline stored" (not malformed); anything unusable sets
/// `malformed` rather than throwing.
[[nodiscard]] inline DecodedBaseline decode_registry_baseline(const std::optional<std::string>& json) {
    DecodedBaseline out;
    if (!json)
        return out;
    try {
        const auto j = nlohmann::json::parse(*json);
        if (!j.is_object() || j.at("v").get<int>() != 1) {
            out.malformed = true;
            return out;
        }
        for (const auto& [k, values] : j.at("keys").items()) {
            auto& m = out.baseline.keys[k];
            for (const auto& [n, e] : values.items()) {
                BaselineEntry b;
                b.t = e.at("t").get<std::uint32_t>();
                b.s = e.at("s").get<std::uint64_t>();
                b.h = e.at("h").get<std::string>();
                b.d = e.at("d").get<std::string>();
                b.dt = e.at("dt").get<bool>();
                m.emplace(n, std::move(b));
            }
        }
    } catch (const nlohmann::json::exception&) {
        out = DecodedBaseline{};
        out.malformed = true;
    }
    return out;
}

} // namespace yuzu::tar
