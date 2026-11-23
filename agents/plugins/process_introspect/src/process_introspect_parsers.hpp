/**
 * process_introspect_parsers.hpp -- the pure core of the process_introspect plugin.
 *
 * No OS call and no SDK include. Every function takes text (or a number) and returns a value;
 * nothing throws on malformed input, every failure is an empty optional or an `invalid` /
 * `absent` field state. The wire rows are built here too, so the "no free text on the wire"
 * contract is one place: every emitted field is a validated number, a validated 16-digit hex
 * mask, a validated cpu list or a token from a closed table. `comm` (the process name) is parsed
 * past and never stored.
 *
 * Row contract (the `status` row is written by the seam, legs.hpp):
 *   target|<pid>|<start_time token>|<facet>
 *   limit|<name>|<soft>|<hard>|<unit>
 *   sigmask|<pending|shared_pending|blocked|ignored|caught>|<hex16>
 *   cap|<inheritable|permitted|effective|bounding|ambient>|<hex16>
 *   seccomp|<disabled|strict|filter|->|<filters|->|<no_new_privs 0|1|->
 *   oom|<score|->|<score_adj|->
 *   sched|<policy token>|<nice>|<rt_priority>|<cpus list|->
 */
#pragma once

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::process_introspect {

// ---------------------------------------------------------------------------
// Request grammar
// ---------------------------------------------------------------------------

enum class Facet { resource_limits, sigmasks, caps, seccomp, oom, sched };

inline constexpr std::array<std::string_view, 6> kFacetNames{
    "resource_limits", "sigmasks", "caps", "seccomp", "oom", "sched"};

[[nodiscard]] inline std::string_view facet_name(Facet f) noexcept {
    return kFacetNames[static_cast<std::size_t>(f)];
}

/// Exact lower-case match; no `all`, no list.
[[nodiscard]] inline std::optional<Facet> parse_facet(std::string_view s) noexcept {
    for (std::size_t i = 0; i < kFacetNames.size(); ++i)
        if (s == kFacetNames[i])
            return static_cast<Facet>(i);
    return std::nullopt;
}

/// `^[1-9][0-9]{0,9}$`, at most INT32_MAX.
[[nodiscard]] inline std::optional<std::uint32_t> parse_pid(std::string_view s) noexcept {
    if (s.empty() || s.size() > 10 || s.front() < '1' || s.front() > '9')
        return std::nullopt;
    std::uint64_t v = 0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || p != s.data() + s.size() || v > 2147483647ULL)
        return std::nullopt;
    return static_cast<std::uint32_t>(v);
}

[[nodiscard]] inline bool is_lower_hex(char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

/// `^[0-9a-f]{8}\.[0-9]{1,20}$`
[[nodiscard]] inline bool valid_start_time_token(std::string_view s) noexcept {
    if (s.size() < 10 || s.size() > 29 || s[8] != '.')
        return false;
    for (std::size_t i = 0; i < 8; ++i)
        if (!is_lower_hex(s[i]))
            return false;
    for (std::size_t i = 9; i < s.size(); ++i)
        if (s[i] < '0' || s[i] > '9')
            return false;
    return true;
}

/// First 8 bytes of /proc/sys/kernel/random/boot_id; each must be lower-case hex.
[[nodiscard]] inline std::optional<std::string> boot_prefix(std::string_view boot_id) {
    if (boot_id.size() < 8)
        return std::nullopt;
    for (std::size_t i = 0; i < 8; ++i)
        if (!is_lower_hex(boot_id[i]))
            return std::nullopt;
    return std::string{boot_id.substr(0, 8)};
}

[[nodiscard]] inline std::string start_time_token(std::string_view boot8, std::uint64_t starttime) {
    std::string t{boot8};
    t += '.';
    t += std::to_string(starttime);
    return t;
}

// ---------------------------------------------------------------------------
// Small text helpers
// ---------------------------------------------------------------------------

namespace detail {

[[nodiscard]] inline bool is_space(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

[[nodiscard]] inline std::string_view trim(std::string_view s) noexcept {
    while (!s.empty() && is_space(s.front()))
        s.remove_prefix(1);
    while (!s.empty() && is_space(s.back()))
        s.remove_suffix(1);
    return s;
}

/// Next whitespace-delimited token; advances `s` past it. Empty when none is left.
[[nodiscard]] inline std::string_view next_token(std::string_view& s) noexcept {
    while (!s.empty() && is_space(s.front()))
        s.remove_prefix(1);
    std::size_t n = 0;
    while (n < s.size() && !is_space(s[n]))
        ++n;
    const std::string_view t = s.substr(0, n);
    s.remove_prefix(n);
    return t;
}

template <typename T>
[[nodiscard]] inline std::optional<T> to_number(std::string_view s) noexcept {
    if (s.empty())
        return std::nullopt;
    T v{};
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || p != s.data() + s.size())
        return std::nullopt;
    return v;
}

/// Calls `fn(line)` for each '\n'-separated line.
template <typename Fn> inline void for_each_line(std::string_view text, Fn&& fn) {
    while (!text.empty()) {
        const std::size_t nl = text.find('\n');
        fn(text.substr(0, nl));
        if (nl == std::string_view::npos)
            break;
        text.remove_prefix(nl + 1);
    }
}

} // namespace detail

// ---------------------------------------------------------------------------
// /proc/<pid>/stat
// ---------------------------------------------------------------------------

struct StatFields {
    std::uint64_t starttime = 0;
    int nice = 0;
    unsigned rt_priority = 0;
    unsigned policy = 0;
};

/// First '(' / LAST ')' rule (comm may hold spaces and parentheses), then whitespace tokens:
/// token index = proc(5) field number - 3 (nice 16, starttime 19, rt_priority 37, policy 38).
/// comm is parsed past and never stored. Any malformation is nullopt.
[[nodiscard]] inline std::optional<StatFields> parse_stat(std::string_view s) {
    const std::size_t open = s.find('(');
    const std::size_t close = s.rfind(')');
    if (open == std::string_view::npos || close == std::string_view::npos || close < open)
        return std::nullopt;
    std::string_view rest = s.substr(close + 1);
    std::array<std::string_view, 39> tok{};
    for (auto& t : tok) {
        t = detail::next_token(rest);
        if (t.empty())
            return std::nullopt;
    }
    const auto start = detail::to_number<std::uint64_t>(tok[19]);
    const auto nice = detail::to_number<int>(tok[16]);
    const auto rt = detail::to_number<unsigned>(tok[37]);
    const auto pol = detail::to_number<unsigned>(tok[38]);
    if (!start || !nice || !rt || !pol || *nice < -20 || *nice > 19 || *rt > 99)
        return std::nullopt;
    return StatFields{*start, *nice, *rt, *pol};
}

/// 0 other, 1 fifo, 2 rr, 3 batch, 5 idle, 6 deadline, 7 ext; anything else unknown.
[[nodiscard]] inline std::string_view policy_token(unsigned p) noexcept {
    switch (p) {
    case 0:
        return "other";
    case 1:
        return "fifo";
    case 2:
        return "rr";
    case 3:
        return "batch";
    case 5:
        return "idle";
    case 6:
        return "deadline";
    case 7:
        return "ext";
    default:
        return "unknown";
    }
}

// ---------------------------------------------------------------------------
// /proc/self/mountinfo: is /proc mounted so that other accounts' processes are hidden?
// ---------------------------------------------------------------------------

enum class ProcVisibility { visible, hidden, unknown };

/// A line counts when its mount point (field 5) is exactly `/proc` and the filesystem type
/// after the ` - ` separator is `proc`. The LAST counting line decides (a later mount covers an
/// earlier one). In its super-options, `hidepid=<v>`: absent, 0, off, 1 or noaccess -> visible
/// (under hidepid=1 the open is refused with EPERM, not ENOENT; measured as permission_denied for
/// uid 65534 on a WSL2 6.18 kernel, README Privileges); any other value
/// (2, invisible, 4, ptraceable, or one this code does not know) -> hidden. Kernels before 5.8
/// print the number, later ones the name, so both are accepted. No counting line -> unknown.
[[nodiscard]] inline ProcVisibility proc_visibility(std::string_view mountinfo) {
    std::optional<ProcVisibility> verdict;
    detail::for_each_line(mountinfo, [&](std::string_view line) {
        const std::size_t sep = line.find(" - ");
        if (sep == std::string_view::npos)
            return;
        std::string_view pre = line.substr(0, sep);
        std::string_view post = line.substr(sep + 3);
        // field 5 of the pre-separator part is the mount point.
        std::string_view point;
        for (int i = 0; i < 5; ++i) {
            point = detail::next_token(pre);
            if (point.empty())
                return;
        }
        if (point != "/proc")
            return;
        const std::size_t t1 = post.find(' ');
        if (post.substr(0, t1) != "proc" || t1 == std::string_view::npos)
            return;
        post.remove_prefix(t1 + 1);
        const std::size_t t2 = post.find(' '); // skip the mount source
        if (t2 == std::string_view::npos)
            return;
        std::string_view opts = post.substr(t2 + 1);
        opts = opts.substr(0, opts.find(' '));
        ProcVisibility v = ProcVisibility::visible;
        while (!opts.empty()) {
            const std::size_t c = opts.find(',');
            const std::string_view o = opts.substr(0, c);
            if (o.starts_with("hidepid=")) {
                const std::string_view val = o.substr(8);
                if (!(val == "0" || val == "off" || val == "1" || val == "noaccess"))
                    v = ProcVisibility::hidden;
            }
            if (c == std::string_view::npos)
                break;
            opts.remove_prefix(c + 1);
        }
        verdict = v;
    });
    return verdict.value_or(ProcVisibility::unknown);
}

// ---------------------------------------------------------------------------
// /proc/<pid>/status
// ---------------------------------------------------------------------------

enum class Presence { absent, invalid, ok };

struct TextField {
    Presence presence = Presence::absent;
    std::string value; ///< set only when presence == ok
};
struct NumField {
    Presence presence = Presence::absent;
    unsigned value = 0;
};

struct StatusFields {
    // Required: absent or invalid is `<facet>:malformed` (the caller decides).
    TextField sig_pnd, shd_pnd, sig_blk, sig_ign, sig_cgt;
    TextField cap_inh, cap_prm, cap_eff, cap_bnd, cap_amb;
    NumField seccomp;           ///< 0|1|2
    TextField cpus_allowed_list; ///< `^[0-9,-]{1,4096}$`
    // Optional keys: absent is fine, present but invalid is malformed.
    NumField no_new_privs;      ///< 0|1
    NumField seccomp_filters;
};

inline constexpr std::size_t kCpusListCap = 4096;

namespace detail {

[[nodiscard]] inline TextField hex16_field(std::string_view v) {
    TextField f;
    if (v.size() != 16) {
        f.presence = Presence::invalid;
        return f;
    }
    for (char c : v)
        if (!is_lower_hex(c)) {
            f.presence = Presence::invalid;
            return f;
        }
    f.presence = Presence::ok;
    f.value = std::string{v};
    return f;
}

[[nodiscard]] inline NumField small_num_field(std::string_view v, unsigned max) {
    NumField f;
    const auto n = to_number<unsigned>(v);
    if (!n || *n > max) {
        f.presence = Presence::invalid;
        return f;
    }
    f.presence = Presence::ok;
    f.value = *n;
    return f;
}

/// The ten 16-hex mask keys of /proc/<pid>/status and the field each one fills.
struct MaskKey {
    std::string_view key;
    TextField StatusFields::*field;
};
inline constexpr std::array<MaskKey, 10> kMaskKeys{{
    {"SigPnd", &StatusFields::sig_pnd},
    {"ShdPnd", &StatusFields::shd_pnd},
    {"SigBlk", &StatusFields::sig_blk},
    {"SigIgn", &StatusFields::sig_ign},
    {"SigCgt", &StatusFields::sig_cgt},
    {"CapInh", &StatusFields::cap_inh},
    {"CapPrm", &StatusFields::cap_prm},
    {"CapEff", &StatusFields::cap_eff},
    {"CapBnd", &StatusFields::cap_bnd},
    {"CapAmb", &StatusFields::cap_amb},
}};

} // namespace detail

/// Lines are `Key:\tvalue`; the FIRST occurrence of a key wins (a later forged line is ignored).
[[nodiscard]] inline StatusFields parse_status(std::string_view text) {
    StatusFields out;
    // One first-wins bit per key: the mask keys in kMaskKeys order, then the four arms below.
    constexpr std::size_t n = detail::kMaskKeys.size();
    std::array<bool, n + 4> seen{};
    detail::for_each_line(text, [&](std::string_view line) {
        const std::size_t colon = line.find(':');
        if (colon == std::string_view::npos)
            return;
        const std::string_view key = line.substr(0, colon);
        const std::string_view val = detail::trim(line.substr(colon + 1));
        auto once = [&](std::size_t idx) {
            if (seen[idx])
                return false;
            seen[idx] = true;
            return true;
        };
        for (std::size_t i = 0; i < n; ++i) {
            if (key == detail::kMaskKeys[i].key) {
                if (once(i))
                    out.*detail::kMaskKeys[i].field = detail::hex16_field(val);
                return;
            }
        }
        if (key == "Seccomp") {
            if (once(n))
                out.seccomp = detail::small_num_field(val, 2);
        } else if (key == "Cpus_allowed_list") {
            if (once(n + 1)) {
                TextField f;
                bool ok = !val.empty() && val.size() <= kCpusListCap;
                for (char c : val)
                    if (!((c >= '0' && c <= '9') || c == ',' || c == '-'))
                        ok = false;
                f.presence = ok ? Presence::ok : Presence::invalid;
                if (ok)
                    f.value = std::string{val};
                out.cpus_allowed_list = std::move(f);
            }
        } else if (key == "NoNewPrivs") {
            if (once(n + 2))
                out.no_new_privs = detail::small_num_field(val, 1);
        } else if (key == "Seccomp_filters") {
            if (once(n + 3))
                out.seccomp_filters = detail::small_num_field(val, 0xffffffffu);
        }
    });
    return out;
}

/// 0 disabled, 1 strict, 2 filter.
[[nodiscard]] inline std::string_view seccomp_token(unsigned mode) noexcept {
    switch (mode) {
    case 0:
        return "disabled";
    case 1:
        return "strict";
    default:
        return "filter";
    }
}

// ---------------------------------------------------------------------------
// /proc/<pid>/limits
// ---------------------------------------------------------------------------

struct LimitRow {
    std::string_view name; ///< closed token
    std::string soft;      ///< `unlimited` or decimal
    std::string hard;
    std::string_view unit; ///< from OUR table, never from the kernel text
};

struct LimitsParse {
    bool header_seen = false;
    std::vector<LimitRow> rows;
    std::size_t unknown_rows = 0; ///< unmatched or invalid lines: counted, never echoed
};

namespace detail {

struct LimitName {
    std::string_view kernel;
    std::string_view token;
    std::string_view unit;
};

inline constexpr std::array<LimitName, 16> kLimitNames{{
    {"Max cpu time", "cpu_time", "seconds"},
    {"Max file size", "file_size", "bytes"},
    {"Max data size", "data_size", "bytes"},
    {"Max stack size", "stack_size", "bytes"},
    {"Max core file size", "core_file_size", "bytes"},
    {"Max resident set", "resident_set", "bytes"},
    {"Max processes", "processes", "count"},
    {"Max open files", "open_files", "count"},
    {"Max locked memory", "locked_memory", "bytes"},
    {"Max address space", "address_space", "bytes"},
    {"Max file locks", "file_locks", "count"},
    {"Max pending signals", "pending_signals", "count"},
    {"Max msgqueue size", "msgqueue_size", "bytes"},
    {"Max nice priority", "nice_priority", "none"},
    {"Max realtime priority", "realtime_priority", "none"},
    {"Max realtime timeout", "realtime_timeout", "microseconds"},
}};

[[nodiscard]] inline bool limit_value_ok(std::string_view v) noexcept {
    return v == "unlimited" || to_number<std::uint64_t>(v).has_value();
}

} // namespace detail

/// The first line must be the header (starts with `Limit`); an EMPTY file (what the kernel
/// returns for a target being reaped) or a first line that is not the header parses nothing.
[[nodiscard]] inline LimitsParse parse_limits(std::string_view text) {
    LimitsParse out;
    bool first = true;
    detail::for_each_line(text, [&](std::string_view line) {
        if (first) {
            first = false;
            out.header_seen = line.starts_with("Limit");
            return;
        }
        if (!out.header_seen || line.empty())
            return;
        for (const auto& n : detail::kLimitNames) {
            if (!line.starts_with(n.kernel) || line.size() == n.kernel.size() ||
                !detail::is_space(line[n.kernel.size()]))
                continue;
            std::string_view rest = line.substr(n.kernel.size());
            const std::string_view soft = detail::next_token(rest);
            const std::string_view hard = detail::next_token(rest);
            if (!detail::limit_value_ok(soft) || !detail::limit_value_ok(hard)) {
                ++out.unknown_rows;
                return;
            }
            out.rows.push_back(LimitRow{n.token, std::string{soft}, std::string{hard}, n.unit});
            return;
        }
        ++out.unknown_rows;
    });
    return out;
}

/// `oom_score` / `oom_score_adj`: one integer, one trailing newline trimmed.
[[nodiscard]] inline std::optional<std::int32_t> parse_oom_value(std::string_view s) noexcept {
    if (!s.empty() && s.back() == '\n')
        s.remove_suffix(1);
    return detail::to_number<std::int32_t>(s);
}

// ---------------------------------------------------------------------------
// Row formatters (the wire contract)
// ---------------------------------------------------------------------------

[[nodiscard]] inline std::string format_target(std::uint32_t pid, std::string_view token,
                                               Facet facet) {
    return "target|" + std::to_string(pid) + '|' + std::string{token} + '|' +
           std::string{facet_name(facet)};
}

[[nodiscard]] inline std::string format_limit(const LimitRow& r) {
    return "limit|" + std::string{r.name} + '|' + r.soft + '|' + r.hard + '|' +
           std::string{r.unit};
}

/// `kind` is `sigmask` or `cap`; `which` is a call-site literal naming the mask.
[[nodiscard]] inline std::string format_mask(std::string_view kind, std::string_view which,
                                             std::string_view hex16) {
    return std::string{kind} + '|' + std::string{which} + '|' + std::string{hex16};
}

[[nodiscard]] inline std::string num_or_dash(const NumField& f) {
    return f.presence == Presence::ok ? std::to_string(f.value) : std::string{"-"};
}

[[nodiscard]] inline std::string format_seccomp(const StatusFields& s) {
    return "seccomp|" +
           (s.seccomp.presence == Presence::ok ? std::string{seccomp_token(s.seccomp.value)}
                                               : std::string{"-"}) +
           '|' + num_or_dash(s.seccomp_filters) + '|' + num_or_dash(s.no_new_privs);
}

[[nodiscard]] inline std::string format_oom(std::optional<std::int32_t> score,
                                            std::optional<std::int32_t> adj) {
    return "oom|" + (score ? std::to_string(*score) : std::string{"-"}) + '|' +
           (adj ? std::to_string(*adj) : std::string{"-"});
}

[[nodiscard]] inline std::string format_sched(const StatFields& st, const TextField& cpus) {
    return "sched|" + std::string{policy_token(st.policy)} + '|' + std::to_string(st.nice) + '|' +
           std::to_string(st.rt_priority) + '|' +
           (cpus.presence == Presence::ok ? cpus.value : std::string{"-"});
}

} // namespace yuzu::process_introspect
