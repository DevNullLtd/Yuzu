#pragma once

// tar_registry_parsers.hpp -- pure core for the `registry` cursor-model TAR
// source (tar_registry_source.{hpp,cpp}). Everything here is a free function
// over strings/structs: no OS handle, no file I/O -- so it compiles and
// unit-tests identically on every platform (tests/unit/test_tar_registry_source.cpp).
//
// THE MECHANISM. A RegNotifyChangeKeyValue subtree watch marks a root dirty; a
// budgeted subtree read is diffed against the root's persisted BASELINE (tar_state
// `registry:<root>`), giving added/changed/removed values with old and new data
// (diff_registry_snapshot). A change becomes a row in the tick that observes it,
// stamped with that read's end time. Actor attribution follows in a later PR: rows
// carry actor_pid 0 and an empty actor_image until then.

#include "tar_db.hpp" // RegistryEvent

#include <nlohmann/json.hpp>
#include <sha256.hpp>
#include <user_profile_model.hpp> // yuzu::profiles::reg_type_name

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <format>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::tar {

// ── Constants ───────────────────────────────────────────────────────────────

inline constexpr std::int64_t kRegistryLiveRowCap = 500000; // registry_live retention (pinned by the schema test)
inline constexpr std::size_t kRegistryDataCap = 4096;       // rendered new value, bytes of text
inline constexpr std::size_t kBaselineRenderCap = 512;      // rendered prefix kept in the baseline
inline constexpr std::size_t kBaselineValueCap = 50000;     // values per root read
inline constexpr std::size_t kBaselineKeyCap = 20000;       // keys per root read
inline constexpr std::size_t kBaselineDepthCap = 16;
inline constexpr std::size_t kBaselineValueReadCap = 4u * 1024u * 1024u; // bytes read per value
inline constexpr std::size_t kBaselineBytesCap = 64u * 1024u * 1024u;    // bytes read per root
inline constexpr std::int64_t kSnapshotBudget100ns = 10LL * 10'000'000;  // 10 s
inline constexpr std::int64_t kReconcileEveryTicks = 12;     // 12 x 300 s = hourly full re-read
inline constexpr std::size_t kWatchHandleCap = 62; // + HKEY_USERS name watch + stop event = 64

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

    /// Concrete roots for the loaded hive names under HKEY_USERS. `.DEFAULT` and
    /// `<sid>_Classes` are not user profiles and are skipped.
    [[nodiscard]] std::vector<std::string>
    roots_for(const std::vector<std::string>& hku_subkeys) const;
};

[[nodiscard]] inline bool is_user_hive_name(std::string_view n) {
    if (n.empty() || n.front() == '.')
        return false;
    constexpr std::string_view kClasses = "_classes";
    if (n.size() >= kClasses.size()) {
        const auto tail = n.substr(n.size() - kClasses.size());
        bool eq = true;
        for (std::size_t i = 0; i < kClasses.size(); ++i)
            eq = eq && static_cast<char>(std::tolower(static_cast<unsigned char>(tail[i]))) ==
                          kClasses[i];
        if (eq)
            return false;
    }
    return true;
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
struct SubtreeRead {
    RegistryReadStatus status{RegistryReadStatus::Unreadable};
    std::map<std::string, std::map<std::string, RegistryValueRead>> keys;
};

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
/// for the old-value column, and `dt` = the hash covers a prefix only because the
/// value exceeded kBaselineValueReadCap.
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

/// A change the baseline diff observed, written as one registry_live row.
struct RegistryCandidate {
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
    std::string source;          // notify | reconcile
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
/// Complete or Absent read (a partial read cannot prove anything is gone);
/// Unreadable changes nothing; Capped adds/updates what it visited and retains
/// the rest. `suppress` returns the new baseline with no candidates (the first
/// read of a root).
[[nodiscard]] inline DiffResult diff_registry_snapshot(const RegistryBaseline& base,
                                                       const SubtreeRead& read,
                                                       std::string_view source,
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
        c.key = key;
        c.value = value;
        c.action = action;
        c.observed_at = observed_at;
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
        for (const auto& [key, values] : base.keys) {
            if (read.keys.contains(key))
                continue;
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

/// Diff-row key: independent of the actor columns (so filling them later never
/// changes a key) and length-framed so key/value cannot be re-split into another
/// pair. NUL (legal in a registry name) and '\' are escaped, as the store refuses
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

/// kind in restart | disabled | cursorlost | baselinelost; `ident` is a timestamp
/// or the root.
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

// ── Cursor state and codecs ─────────────────────────────────────────────────

struct RegistryRootState {
    bool baselined{false};
    std::int64_t read_start{0};
    std::int64_t read_end{0};
    std::string status; // complete | absent | unreadable | capped | due
    bool armed{true};
    bool operator==(const RegistryRootState&) const = default;
};

struct RegistryCursor {
    bool present{false};   // a cursor was supplied at all
    bool malformed{false}; // supplied but unusable (CursorLost, never a Baseline)
    std::int64_t tick{0};
    std::map<std::string, RegistryRootState> roots;
    std::vector<std::string> hku;
    std::string ccs; // ControlSetNNN the machine was on when the baselines were taken
};

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
            st.read_start = r.at("read_start").get<std::int64_t>();
            st.read_end = r.at("read_end").get<std::int64_t>();
            st.status = r.at("status").get<std::string>();
            st.armed = r.at("armed").get<bool>();
            cur.roots.emplace(name, std::move(st));
        }
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
        roots[name] = {{"baselined", st.baselined}, {"read_start", st.read_start},
                       {"read_end", st.read_end},   {"status", st.status},
                       {"armed", st.armed}};
    j["roots"] = std::move(roots);
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
