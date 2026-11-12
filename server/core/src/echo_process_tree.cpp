/// @file echo_process_tree.cpp
/// Implementation of the Echo process-tree engine (hourly roll-up parsers, name-level
/// tree, window math) + pure renderers.
/// See echo_process_tree.hpp for the data-source constraints that shape this model.

#include "echo_process_tree.hpp"

#include "web_utils.hpp" // html_escape, format_iso_utc

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <functional>
#include <map>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace yuzu::server {

std::vector<std::string> echo_split_pipe(const std::string& line, std::size_t max_cells) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (true) {
        if (out.size() + 1 >= max_cells) {
            out.push_back(line.substr(pos));
            return out;
        }
        const auto bar = line.find('|', pos);
        if (bar == std::string::npos) {
            out.push_back(line.substr(pos));
            return out;
        }
        out.push_back(line.substr(pos, bar - pos));
        pos = bar + 1;
    }
}

namespace {

std::string to_lower(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

/// Image basename, lowercased — strips any directory prefix (`/` or `\`) so a
/// Linux cmdline path and a Windows image name compare on the same key.
std::string basename_lower(const std::string& name) {
    auto slash = name.find_last_of("/\\");
    std::string base = (slash == std::string::npos) ? name : name.substr(slash + 1);
    return to_lower(base);
}

/// Parse an agent-supplied cell to a bounded non-negative integer. nullopt on any
/// garbage / overflow / trailing junk (the whole row is then skipped). Bounded to
/// 2^63 via int64 so pid/port/ts all share one safe path.
std::optional<std::int64_t> cell_i64(const std::string& s) {
    if (s.empty() || s.size() > 20)
        return std::nullopt;
    std::int64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9')
            return std::nullopt;
        // Overflow guard (v*10+d) — reject rather than wrap.
        if (v > (INT64_MAX - 9) / 10)
            return std::nullopt;
        v = v * 10 + (c - '0');
    }
    return v;
}

/// Schema-located column map: index by NAME from the `__schema__|col1|…` header
/// (schema cell i names data cell i-1). Returns the data-cell index for `name`, or
/// -1 if absent. Mirrors parse_dex_perf_output's defensive contract.
int schema_index(const std::vector<std::string>& schema_cells, std::string_view name) {
    for (int i = 1; i < static_cast<int>(schema_cells.size()); ++i)
        if (schema_cells[i] == name)
            return i - 1;
    return -1;
}

// ── Suspicious parent→child denylist (the sole anomaly heuristic) ────────────
// High-signal LOLBin / shell spawns. explorer.exe is DELIBERATELY excluded as a
// parent: a user opening a terminal from Explorer is benign and would swamp the
// signal. Name-based so it works on Windows (ETW names-only). Basenames, lowercase.
const std::array<std::string_view, 17> kSuspiciousParents = {
    "winword.exe", "excel.exe",   "powerpnt.exe", "outlook.exe", "onenote.exe",
    "msaccess.exe", "mspub.exe",  "visio.exe",    "chrome.exe",  "msedge.exe",
    "firefox.exe",  "iexplore.exe", "acrord32.exe", "mshta.exe",  "wmiprvse.exe",
    "wscript.exe",  "cscript.exe"};
const std::array<std::string_view, 14> kSuspiciousChildren = {
    "powershell.exe", "pwsh.exe",    "cmd.exe",     "wscript.exe", "cscript.exe",
    "mshta.exe",      "rundll32.exe", "regsvr32.exe", "bitsadmin.exe", "certutil.exe",
    "bash", "sh", "bash.exe", "sh.exe"};


/// Parse an agent-supplied count cell: a non-negative integer, or 0 for anything
/// else (an optional measure that is garbage must not drop the whole row).
std::int64_t cell_count(const std::string& s) {
    const auto v = cell_i64(s);
    return v ? *v : 0;
}

int cell_port(const std::string& s) {
    const auto v = cell_i64(s);
    return (v && *v <= 65535) ? static_cast<int>(*v) : 0;
}

std::int64_t sat_add(std::int64_t a, std::int64_t b) {
    return a > INT64_MAX - b ? INT64_MAX : a + b; // both non-negative (parsed by cell_i64)
}

/// The widest schema accepted (data columns). The real tables have under ten.
constexpr std::size_t kMaxSchemaColumns = 64;

/// Shared `__schema__` walker for the hourly parsers. `cols` names the data columns the
/// caller wants; the first `n_required` MUST exist in the schema or the whole payload is
/// refused (wrong shape — refuse rather than guess). `row_fn(at)` runs once per data row
/// with `at(k)` → the cell of `cols[k]` ("" when that column is absent) and returns false
/// to skip the row. An `error|…` first line and the `__total__|N` trailer never reach
/// `row_fn`; a row whose cell count is not exactly the schema's width (torn, or carrying
/// extra cells from a `|` in a value) is dropped and counted in `stats->unreadable`, as is
/// a row `row_fn` refuses. Stops after `max_rows` accepted rows.
template <class RowFn>
void walk_schema_rows(const std::string& output, std::size_t max_rows,
                      const std::vector<std::string_view>& cols, std::size_t n_required,
                      EchoParseStats* stats, RowFn&& row_fn) {
    std::vector<int> idx;
    std::size_t width = 0; // data columns the schema declares
    bool have_schema = false;
    std::size_t accepted = 0;
    std::size_t pos = 0;
    const auto drop = [&] {
        if (stats)
            ++stats->unreadable;
    };
    while (pos < output.size() && accepted < max_rows) {
        const auto nl = output.find('\n', pos);
        std::string line = output.substr(pos, (nl == std::string::npos ? output.size() : nl) - pos);
        pos = (nl == std::string::npos) ? output.size() : nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;
        if (!have_schema) {
            if (line.starts_with("error|"))
                return; // agent-side error payload
            if (!line.starts_with("__schema__|"))
                continue;
            const auto schema = echo_split_pipe(line, kMaxSchemaColumns + 2);
            if (schema.size() > kMaxSchemaColumns + 1)
                return; // wrong shape: far wider than any Echo table
            for (const auto c : cols)
                idx.push_back(schema_index(schema, c));
            for (std::size_t k = 0; k < n_required; ++k)
                if (idx[k] < 0)
                    return; // wrong shape
            width = schema.size() - 1;
            have_schema = true;
            if (stats)
                stats->schema = true;
            continue;
        }
        const auto cells = echo_split_pipe(line, width + 1);
        if (cells.size() != width) {
            // The trailer is `__total__|N`; anything else with the wrong width is unreadable.
            if (!(cells.size() == 2 && cells[0] == "__total__"))
                drop();
            continue;
        }
        static const std::string kEmpty;
        const auto at = [&](std::size_t k) -> const std::string& {
            return idx[k] >= 0 ? cells[static_cast<std::size_t>(idx[k])] : kEmpty;
        };
        if (row_fn(at))
            ++accepted;
        else
            drop();
    }
}

} // namespace

bool echo_is_suspicious_spawn(const std::string& parent_name, const std::string& child_name,
                              std::string* evidence) {
    const std::string p = basename_lower(parent_name);
    const std::string c = basename_lower(child_name);
    if (p.empty() || c.empty())
        return false;
    const bool parent_hit =
        std::find(kSuspiciousParents.begin(), kSuspiciousParents.end(), p) != kSuspiciousParents.end();
    const bool child_hit =
        std::find(kSuspiciousChildren.begin(), kSuspiciousChildren.end(), c) != kSuspiciousChildren.end();
    if (!parent_hit || !child_hit)
        return false;
    if (evidence)
        *evidence = parent_name + " \xE2\x86\x92 " + child_name +
                    " \xE2\x80\x94 uncommon parent spawned a shell/LOLBin";
    return true;
}

std::vector<EchoProcHourRow> parse_echo_process_hourly_output(const std::string& output,
                                                              std::size_t max_rows,
                                                              EchoParseStats* stats) {
    std::vector<EchoProcHourRow> out;
    walk_schema_rows(output, max_rows,
                     {"hour_ts", "name", "parent_name", "user", "start_count", "stop_count",
                      "abnormal_exit_count"},
                     6, stats, [&](const auto& at) {
                         const auto hour = cell_i64(at(0));
                         const auto starts = cell_i64(at(4));
                         const auto stops = cell_i64(at(5));
                         if (!hour || !starts || !stops)
                             return false;
                         EchoProcHourRow r;
                         r.hour_ts = *hour;
                         r.name = at(1);
                         r.parent_name = at(2);
                         r.user = at(3);
                         r.start_count = *starts;
                         r.stop_count = *stops;
                         r.abnormal_exit_count = cell_count(at(6));
                         out.push_back(std::move(r));
                         return true;
                     });
    return out;
}

std::vector<EchoTcpHourRow> parse_echo_tcp_hourly_output(const std::string& output,
                                                         std::size_t max_rows,
                                                         EchoParseStats* stats) {
    std::vector<EchoTcpHourRow> out;
    walk_schema_rows(output, max_rows,
                     {"hour_ts", "process_name", "remote_addr", "remote_port", "proto",
                      "connect_count", "disconnect_count", "failed_count"},
                     3, stats, [&](const auto& at) {
                         const auto hour = cell_i64(at(0));
                         if (!hour)
                             return false;
                         EchoTcpHourRow r;
                         r.hour_ts = *hour;
                         r.process_name = at(1);
                         r.remote_addr = at(2);
                         r.remote_port = cell_port(at(3));
                         r.proto = at(4);
                         r.connect_count = cell_count(at(5));
                         r.disconnect_count = cell_count(at(6));
                         r.failed_count = cell_count(at(7));
                         out.push_back(std::move(r));
                         return true;
                     });
    return out;
}

std::vector<EchoDnsHourRow> parse_echo_dns_hourly_output(const std::string& output,
                                                         std::size_t max_rows,
                                                         EchoParseStats* stats) {
    std::vector<EchoDnsHourRow> out;
    walk_schema_rows(output, max_rows,
                     {"hour_ts", "name", "record_type", "data", "appear_count", "remove_count"}, 3,
                     stats, [&](const auto& at) {
                         const auto hour = cell_i64(at(0));
                         if (!hour)
                             return false;
                         EchoDnsHourRow r;
                         r.hour_ts = *hour;
                         r.name = at(1);
                         r.record_type = at(2);
                         r.data = at(3);
                         r.appear_count = cell_count(at(4));
                         r.remove_count = cell_count(at(5));
                         out.push_back(std::move(r));
                         return true;
                     });
    return out;
}

std::vector<EchoArpHourRow> parse_echo_arp_hourly_output(const std::string& output,
                                                         std::size_t max_rows,
                                                         EchoParseStats* stats) {
    std::vector<EchoArpHourRow> out;
    walk_schema_rows(output, max_rows,
                     {"hour_ts", "ip_address", "mac_address", "interface", "appear_count",
                      "remove_count"},
                     3, stats, [&](const auto& at) {
                         const auto hour = cell_i64(at(0));
                         if (!hour)
                             return false;
                         EchoArpHourRow r;
                         r.hour_ts = *hour;
                         r.ip_address = at(1);
                         r.mac_address = at(2);
                         r.iface = at(3);
                         r.appear_count = cell_count(at(4));
                         r.remove_count = cell_count(at(5));
                         out.push_back(std::move(r));
                         return true;
                     });
    return out;
}

std::vector<std::int64_t> parse_echo_hours_output(const std::string& output, EchoParseStats* stats) {
    std::vector<std::int64_t> hours;
    walk_schema_rows(output, static_cast<std::size_t>(kEchoMaxWindowHours), {"hour_ts"}, 1, stats,
                     [&](const auto& at) {
                         const auto hour = cell_i64(at(0));
                         if (!hour)
                             return false;
                         hours.push_back(*hour);
                         return true;
                     });
    std::sort(hours.begin(), hours.end(), std::greater<>());
    hours.erase(std::unique(hours.begin(), hours.end()), hours.end());
    return hours;
}

EchoWindow resolve_echo_window(const std::string& preset, std::int64_t custom_from,
                               std::int64_t custom_to, std::int64_t now) {
    constexpr std::int64_t kHour = 3600;
    const auto floor_hour = [](std::int64_t t) { return t > 0 ? t - t % kHour : std::int64_t{0}; };
    const std::string p = canonical_echo_preset(preset);
    EchoWindow w;
    // The last COMPLETE hour: the bucket before the one `now` falls in.
    w.to_ts = (std::max)(floor_hour(now) - kHour, std::int64_t{0});
    if (p == "custom") {
        if (custom_to > 0)
            w.to_ts = floor_hour(custom_to);
        w.from_ts = custom_from > 0 ? floor_hour(custom_from) : w.to_ts - 23 * kHour;
    } else {
        const int hours = p == "1h" ? 1 : (p == "7d" ? kEchoMaxWindowHours : 24);
        w.from_ts = w.to_ts - (hours - 1) * kHour;
    }
    if (w.from_ts < 0)
        w.from_ts = 0;
    if (w.to_ts < w.from_ts)
        w.to_ts = w.from_ts; // reversed range → a single bucket at `from`
    if ((w.to_ts - w.from_ts) / kHour >= kEchoMaxWindowHours)
        w.from_ts = w.to_ts - (kEchoMaxWindowHours - 1) * kHour; // keep the newest hours
    return w;
}

std::string canonical_echo_preset(const std::string& preset) {
    // Keep in lock-step with resolve_echo_window's accepted tokens. Anything else
    // (empty, garbage, an injection attempt) collapses to the `24h` default.
    if (preset == "1h" || preset == "24h" || preset == "7d" || preset == "custom")
        return preset;
    return "24h";
}

std::string normalize_echo_os(const std::string& os) {
    const std::string o = to_lower(os);
    if (o.empty())
        return "?";
    // Check macOS first: "darwin" contains the substring "win", so the windows
    // check must not run before it.
    if (o.find("mac") != std::string::npos || o.find("darwin") != std::string::npos ||
        o.find("osx") != std::string::npos)
        return "macos";
    if (o.find("win") != std::string::npos)
        return "windows";
    if (o.find("linux") != std::string::npos || o.find("nix") != std::string::npos ||
        o.find("bsd") != std::string::npos || o.find("ubuntu") != std::string::npos ||
        o.find("debian") != std::string::npos || o.find("centos") != std::string::npos ||
        o.find("fedora") != std::string::npos || o.find("rhel") != std::string::npos)
        return "linux";
    return "?";
}

namespace {

// Civil date → days since 1970-01-01 (Howard Hinnant). Used to parse a
// datetime-local value as UTC without libc timezone surprises.
std::int64_t days_from_civil(int y, unsigned m, unsigned d) {
    y -= m <= 2;
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

} // namespace

std::int64_t parse_ts_param(const std::string& s) {
    if (s.empty())
        return 0;
    if (std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; })) {
        if (s.size() > 18) // > 18 digits cannot be a real epoch and risks overflow
            return 0;
        std::int64_t v = 0;
        for (char c : s)
            v = v * 10 + (c - '0'); // bounded: ≤18 digits < INT64_MAX, no overflow
        return v;
    }
    // "YYYY-MM-DDTHH:MM[:SS]" — seconds optional, exactly the former
    // sscanf("%d-%d-%dT%d:%d:%d") with its `n >= 5` acceptance (a missing or
    // unconvertible seconds field leaves Se == 0). strtol instead of sscanf:
    // glibc 2.38's __isoc23_sscanf redirect breaks older-glibc hosts. %d skipped
    // leading whitespace and accepted a sign; strtol does the same, and the
    // range checks below reject nonsense as before. Parsing into long (not int)
    // makes an absurdly long year a defined reject rather than scanf UB.
    const char* p = s.c_str();
    long f[5]{};
    constexpr char kDelim[4] = {'-', '-', 'T', ':'};
    for (int i = 0; i < 5; ++i) {
        char* end{};
        f[i] = std::strtol(p, &end, 10);
        if (end == p)
            return 0;
        p = end;
        if (i < 4) {
            if (*p != kDelim[i])
                return 0;
            ++p;
        }
    }
    long Se = 0;
    if (*p == ':') {
        char* end{};
        const long v = std::strtol(p + 1, &end, 10);
        if (end != p + 1)
            Se = v;
    }
    const long Y = f[0], Mo = f[1], D = f[2], H = f[3], Mi = f[4];
    // Bound the year so days_from_civil*86400 cannot overflow int64 and the result is
    // a sane wall-clock; reject out-of-range fields rather than fabricate a time.
    if (Y < 1970 || Y > 9999 || Mo < 1 || Mo > 12 || D < 1 || D > 31 || H < 0 || H > 23 ||
        Mi < 0 || Mi > 59 || Se < 0 || Se > 60)
        return 0;
    return days_from_civil(static_cast<int>(Y), static_cast<unsigned>(Mo),
                           static_cast<unsigned>(D)) *
               86400 +
           H * 3600 + Mi * 60 + Se;
}

std::optional<std::int64_t> parse_ts_param_strict(const std::string& s) {
    if (s.empty())
        return std::int64_t{0}; // absent: the same "unset" the lenient parser reports
    const auto digit = [](char c) { return c >= '0' && c <= '9'; };
    if (std::all_of(s.begin(), s.end(), digit)) {
        if (s.size() > 18) // cannot be a real epoch; refuse rather than report "unset"
            return std::nullopt;
        return parse_ts_param(s);
    }
    // Exactly YYYY-MM-DDTHH:MM or YYYY-MM-DDTHH:MM:SS -- no sign, whitespace, bare trailing ':'
    // or trailing junk, all of which the lenient parser tolerates.
    constexpr std::string_view kShortShape = "dddd-dd-ddTdd:dd";
    constexpr std::string_view kLongShape = "dddd-dd-ddTdd:dd:dd";
    const std::string_view shape = s.size() == kShortShape.size()  ? kShortShape
                                   : s.size() == kLongShape.size() ? kLongShape
                                                                   : std::string_view{};
    if (shape.empty())
        return std::nullopt;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (shape[i] == 'd' ? !digit(s[i]) : s[i] != shape[i])
            return std::nullopt;
    }
    // The lenient parser only range-checks the day as 1..31 and days_from_civil rolls the
    // overflow into the next month (31 Feb reads as 3 Mar), so check the day against the
    // month length here. The shape is validated above, so the digits are safe to read.
    const auto num = [&](std::size_t pos, std::size_t len) {
        int n = 0;
        for (std::size_t i = pos; i < pos + len; ++i)
            n = n * 10 + (s[i] - '0');
        return n;
    };
    const int year = num(0, 4);
    const int month = num(5, 2);
    const int day = num(8, 2);
    const bool leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    constexpr int kDaysInMonth[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    // A month outside 1..12 is left to the range check below; this guards the table index.
    if (month >= 1 && month <= 12 && day > kDaysInMonth[month - 1] + (month == 2 && leap ? 1 : 0))
        return std::nullopt;
    const auto v = parse_ts_param(s);
    if (v == 0) // range-checked inside: invalid month, year outside [1970,9999], ...
        return std::nullopt;
    return v;
}

EchoProcTree build_echo_process_tree(const std::vector<EchoProcHourRow>& rows, std::int64_t hour_ts) {
    EchoProcTree tree;
    tree.hour_ts = hour_ts;
    constexpr std::size_t kNone = EchoProcNode::kNoParent;
    constexpr std::size_t kMaxSpawnEvidence = 16; // distinct evidence lines kept per node

    // 1. One node per (name, user); rows sharing the key sum their counts. The key is
    //    length-prefixed so an agent-chosen name cannot collide with another (name, user)
    //    pair by embedding a delimiter. Per node, remember the parents its rows name (with
    //    their summed starts) and every suspicious spawn: the placement and the anomaly flag
    //    are decided from ALL rows, never from whichever came first.
    std::unordered_map<std::string, std::size_t> by_key;
    std::unordered_map<std::string, std::size_t> first_by_name; // parent-link target: lowest user
    std::vector<std::map<std::string, std::int64_t>> parent_starts;
    std::vector<std::vector<std::string>> spawn_evidence;
    for (const auto& r : rows) {
        if (r.hour_ts != hour_ts)
            continue;
        std::string key = std::to_string(r.name.size()) + ':' + r.name + r.user;
        auto it = by_key.find(key);
        if (it == by_key.end()) {
            if (tree.nodes.size() >= kEchoTreeMaxNodes) {
                tree.truncated = true;
                continue;
            }
            EchoProcNode n;
            n.name = r.name;
            n.user = r.user;
            const std::size_t id = tree.nodes.size();
            const auto [fit, fresh] = first_by_name.try_emplace(r.name, id);
            if (!fresh && r.user < tree.nodes[fit->second].user)
                fit->second = id;
            it = by_key.emplace(std::move(key), id).first;
            tree.nodes.push_back(std::move(n));
            parent_starts.emplace_back();
            spawn_evidence.emplace_back();
        }
        const std::size_t id = it->second;
        EchoProcNode& n = tree.nodes[id];
        n.start_count = sat_add(n.start_count, r.start_count);
        n.stop_count = sat_add(n.stop_count, r.stop_count);
        n.abnormal_exit_count = sat_add(n.abnormal_exit_count, r.abnormal_exit_count);
        if (!r.parent_name.empty()) {
            auto& sum = parent_starts[id][r.parent_name];
            sum = sat_add(sum, r.start_count);
        }
        std::string spawn;
        if (echo_is_suspicious_spawn(r.parent_name, r.name, &spawn)) {
            auto& ev = spawn_evidence[id];
            if (ev.size() < kMaxSpawnEvidence && std::find(ev.begin(), ev.end(), spawn) == ev.end())
                ev.push_back(std::move(spawn));
        }
    }

    // 2. Parent link by NAME. A node's parent name is the one with the most summed starts
    //    (ties: the lowest name, the map's order); a name other than its own wins over its
    //    own, which can never be placed. An empty, unknown or self-named parent leaves the
    //    node a root.
    const std::size_t count = tree.nodes.size();
    for (std::size_t i = 0; i < count; ++i) {
        EchoProcNode& n = tree.nodes[i];
        bool best_self = false;
        std::int64_t best_sum = -1;
        for (const auto& [pname, sum] : parent_starts[i]) {
            const bool self = pname == n.name;
            if (best_sum < 0 || (best_self && !self) || (best_self == self && sum > best_sum)) {
                n.parent_name = pname;
                best_self = self;
                best_sum = sum;
            }
        }
        if (n.parent_name.empty() || n.parent_name == n.name)
            continue;
        const auto it = first_by_name.find(n.parent_name);
        if (it != first_by_name.end())
            n.parent = it->second;
    }

    // 3. Cycle cut (placed-once pass). The name graph can loop (a under b, b under a), and
    //    the pid-incarnation walk the old engine used does not fit it. Every node is walked
    //    at most once (state 2 = settled), so this is O(n) even for a 50k-deep chain; a walk
    //    that re-enters its own path found a cycle, which is cut at its lowest (name, user)
    //    member whichever node the walk entered it from.
    const auto id_less = [&](std::size_t a, std::size_t b) {
        const EchoProcNode& x = tree.nodes[a];
        const EchoProcNode& y = tree.nodes[b];
        return x.name != y.name ? x.name < y.name : x.user < y.user;
    };
    std::vector<unsigned char> state(count, 0); // 0 new, 1 on the current walk, 2 settled
    std::vector<std::size_t> path;
    for (std::size_t s = 0; s < count; ++s) {
        path.clear();
        std::size_t cur = s;
        while (cur != kNone && state[cur] == 0) {
            state[cur] = 1;
            path.push_back(cur);
            cur = tree.nodes[cur].parent;
        }
        if (cur != kNone && state[cur] == 1) {
            const auto entry = std::find(path.begin(), path.end(), cur);
            tree.nodes[*std::min_element(entry, path.end(), id_less)].parent = kNone;
        }
        for (const std::size_t id : path)
            state[id] = 2;
    }

    // 4. Children lists + root set, siblings in (name, user) order.
    for (std::size_t i = 0; i < count; ++i) {
        if (tree.nodes[i].parent == kNone)
            tree.roots.push_back(i);
        else
            tree.nodes[tree.nodes[i].parent].children.push_back(i);
    }
    std::sort(tree.roots.begin(), tree.roots.end(), id_less);
    for (auto& n : tree.nodes)
        std::sort(n.children.begin(), n.children.end(), id_less);

    // 5. Flags + totals. An abnormal exit or a suspicious spawn by name (any row, whatever
    //    the placement) is an anomaly; a name with more stops than starts is a soft flag (it
    //    started before the hour).
    for (std::size_t i = 0; i < count; ++i) {
        EchoProcNode& n = tree.nodes[i];
        n.stops_exceed_starts = n.stop_count > n.start_count;
        std::string evidence;
        if (n.abnormal_exit_count > 0)
            evidence = std::to_string(n.abnormal_exit_count) + " abnormal exit(s) in this hour";
        for (const auto& spawn : spawn_evidence[i]) {
            if (!evidence.empty())
                evidence += "; ";
            evidence += spawn;
        }
        n.anomaly = !evidence.empty();
        n.anomaly_evidence = std::move(evidence);
        if (n.anomaly)
            ++tree.anomaly_count;
        tree.start_total = sat_add(tree.start_total, n.start_count);
        tree.abnormal_total = sat_add(tree.abnormal_total, n.abnormal_exit_count);
    }

    // 6. Depth: the renderer collapses branches past kEchoRenderDepthCap, but the totals
    //    cover the FULL tree (every node stays detail-addressable); flag the mismatch so
    //    the banner can say the counts include hidden depth. seen[] keeps the walk
    //    placed-once even if a future edit let a loop through step 3.
    std::vector<bool> seen(count, false);
    std::vector<std::pair<std::size_t, int>> stack; // {node_id, depth}
    for (const std::size_t r : tree.roots)
        stack.emplace_back(r, 0);
    while (!stack.empty()) {
        const auto [id, depth] = stack.back();
        stack.pop_back();
        if (id >= count || seen[id])
            continue;
        seen[id] = true;
        if (depth > kEchoRenderDepthCap)
            tree.depth_capped = true;
        for (const std::size_t c : tree.nodes[id].children)
            stack.emplace_back(c, depth + 1);
    }
    return tree;
}

// ── Renderers ────────────────────────────────────────────────────────────────

namespace {

/// Coarse class of a remote address for inline colouring: "loop" (loopback),
/// "priv" (RFC1918 / ULA / link-local), "pub" (routable), or "" (empty/unknown).
/// Forensic value: a public remote is the egress an analyst cares about.
std::string remote_class(const std::string& addr) {
    if (addr.empty() || addr == "0.0.0.0" || addr == "::" || addr == "*")
        return "";
    if (addr.starts_with("127.") || addr == "::1")
        return "loop";
    if (addr.starts_with("10.") || addr.starts_with("192.168.") || addr.starts_with("169.254.") ||
        addr.starts_with("fe80:") || addr.starts_with("fc") || addr.starts_with("fd"))
        return "priv";
    if (addr.starts_with("172.")) {
        // 172.16.0.0 – 172.31.255.255 is private; other 172.x is public.
        int second = 0;
        std::size_t dot = addr.find('.', 4);
        if (dot != std::string::npos) {
            try {
                second = std::stoi(addr.substr(4, dot - 4));
            } catch (...) {
            }
        }
        return (second >= 16 && second <= 31) ? "priv" : "pub";
    }
    return "pub";
}

/// One distinct remote endpoint label (`addr:port`, or `listening` for a row with no
/// remote), HTML-escaped, wrapped in a class that colours public egress.
std::string endpoint_chip(const EchoTcpHourRow& c) {
    const std::string cls = remote_class(c.remote_addr);
    const std::string label = (cls.empty() || c.remote_port == 0)
                                  ? std::string("listening")
                                  : c.remote_addr + ":" + std::to_string(c.remote_port);
    std::string klass = "tt-ep";
    if (cls == "pub")
        klass += " tt-ep-pub";
    return "<span class=\"" + klass + "\">" + html_escape(label) + "</span>";
}

/// Inline network summary for a node's connections (already filtered to its name):
/// a count badge + up to two distinct endpoints + "+N", with the full list in the
/// title. Empty string when the node has no connections.
std::string net_cell(const std::vector<const EchoTcpHourRow*>& conns) {
    if (conns.empty())
        return {};
    // Distinct endpoints, public first, preserving first-seen order otherwise. Dedup
    // via a hash set (a single name can own thousands of $TCP_Hourly rows — O(n) not O(n²)).
    std::vector<const EchoTcpHourRow*> distinct;
    std::unordered_set<std::string> seen;
    bool any_public = false;
    for (const EchoTcpHourRow* c : conns) {
        std::string key = c->remote_addr + ":" + std::to_string(c->remote_port) + "/" + c->proto;
        if (!seen.insert(std::move(key)).second)
            continue;
        distinct.push_back(c);
        if (remote_class(c->remote_addr) == "pub")
            any_public = true;
    }
    std::stable_sort(distinct.begin(), distinct.end(),
                     [](const EchoTcpHourRow* a, const EchoTcpHourRow* b) {
                         return (remote_class(a->remote_addr) == "pub") &&
                                (remote_class(b->remote_addr) != "pub");
                     });
    std::string title;
    for (std::size_t i = 0; i < distinct.size() && i < 12; ++i) {
        const EchoTcpHourRow* c = distinct[i];
        title += c->remote_addr + ":" + std::to_string(c->remote_port);
        if (!c->proto.empty())
            title += " " + c->proto;
        title += "  ";
    }
    std::string cell = "<span class=\"tt-net" + std::string(any_public ? " tt-net-pub" : "") +
                       "\" title=\"" + html_escape(title) + "\">";
    cell += "<span class=\"tt-net-ico\">\xE2\x86\x97</span>" + std::to_string(distinct.size());
    for (std::size_t i = 0; i < distinct.size() && i < 2; ++i)
        cell += endpoint_chip(*distinct[i]);
    if (distinct.size() > 2)
        cell += "<span class=\"tt-ep tt-ep-more\">+" + std::to_string(distinct.size() - 2) + "</span>";
    cell += "</span>";
    return cell;
}

/// The hour's connections by owning process NAME, plus each name's rendered net cell. Every
/// node sharing a name shows the same cell, so it is built once per name, not once per node
/// (N same-name users x M connection rows would otherwise be N x M work).
struct NetCells {
    std::unordered_map<std::string, std::vector<const EchoTcpHourRow*>> by_name;
    std::unordered_map<std::string, std::string> html;
    EchoRenderStats* stats = nullptr;

    /// The cell for `name`; empty when it has no connections.
    const std::string& cell(const std::string& name) {
        static const std::string kNone;
        const auto it = by_name.find(name);
        if (it == by_name.end())
            return kNone;
        const auto [memo, fresh] = html.try_emplace(name);
        if (fresh) {
            memo->second = net_cell(it->second);
            if (stats)
                ++stats->net_cells_built;
        } else if (stats) {
            ++stats->net_cells_reused;
        }
        return memo->second;
    }
};

/// One node's summary row (the clickable line). `node_id` addresses the detail; the
/// row carries data-anom for the client-side filter.
std::string node_summary_row(const EchoProcTree& tree, std::size_t id, const std::string& token,
                             NetCells& net) {
    const EchoProcNode& n = tree.nodes[id];
    std::string row;
    row += "<a class=\"echo-tree-row\" data-anom=\"";
    row += n.anomaly ? "1" : "0";
    row += "\" hx-get=\"/fragments/echo/process-tree/detail?token=" + token +
           "&amp;node=" + std::to_string(id) +
           "\" hx-target=\"#echo-tree-detail\" hx-swap=\"innerHTML\">";
    row += "<span class=\"tt-name\">" + html_escape(n.name.empty() ? "(unknown)" : n.name) + "</span>";
    if (!n.user.empty())
        row += "<span class=\"tt-user\">" + html_escape(n.user) + "</span>";
    row += "<span class=\"tt-meta\">started " + std::to_string(n.start_count) + " &middot; stopped " +
           std::to_string(n.stop_count);
    if (n.abnormal_exit_count > 0)
        row += " &middot; " + std::to_string(n.abnormal_exit_count) + " abnormal";
    if (n.stops_exceed_starts)
        row += " &middot; more stops than starts";
    row += "</span>";
    row += net.cell(n.name);
    if (n.anomaly)
        row += "<span class=\"tt-anom\" title=\"" + html_escape(n.anomaly_evidence) +
               "\">\xE2\x9A\xA0</span>";
    row += "</a>";
    return row;
}

void render_node(const EchoProcTree& tree, std::size_t id, int depth, const std::string& token,
                 NetCells& net, std::string& out) {
    if (id >= tree.nodes.size())
        return;
    if (depth > kEchoRenderDepthCap) {
        out += "<div class=\"echo-tree-leaf echo-tree-mute\">\xE2\x80\xA6 (depth capped)</div>";
        return;
    }
    const EchoProcNode& n = tree.nodes[id];
    if (n.children.empty()) {
        out += "<div class=\"echo-tree-leaf\">" + node_summary_row(tree, id, token, net) +
               "</div>";
        return;
    }
    // Expand the first two levels by default; deeper branches start collapsed.
    out += depth < 2 ? "<details open class=\"echo-tree-node\">" : "<details class=\"echo-tree-node\">";
    out += "<summary>" + node_summary_row(tree, id, token, net) + "</summary>";
    out += "<div class=\"echo-tree-children\">";
    for (const std::size_t c : n.children)
        render_node(tree, c, depth + 1, token, net, out);
    out += "</div></details>";
}

} // namespace

std::string render_echo_tree_fragment(const EchoProcTree& tree, const std::vector<EchoTcpHourRow>& conns,
                                      const std::string& token, EchoRenderStats* stats) {
    // Index the hour's connections by owning process NAME for the inline net summary.
    NetCells net;
    net.stats = stats;
    for (const auto& c : conns)
        net.by_name[c.process_name].push_back(&c);

    std::string h;
    h += "<div class=\"echo-tree-banner\">";
    h += "Hour <b>" + html_escape(format_iso_utc(tree.hour_ts)) + "</b>";
    h += " &middot; " + std::to_string(tree.nodes.size()) + " process names";
    h += " &middot; " + std::to_string(tree.start_total) + " starts";
    h += " &middot; " + std::to_string(tree.abnormal_total) + " abnormal exits";
    h += " &middot; " + std::to_string(tree.anomaly_count) + " flagged";
    h += "</div>";
    h += "<div class=\"echo-tree-note\">Built from this host's hourly roll-up "
         "(<code>$Process_Hourly</code>) &mdash; names only: process ids, command lines and paths "
         "are not kept. The parent link is by name, so processes sharing a name share one "
         "position.</div>";

    if (tree.truncated)
        h += "<div class=\"echo-tree-warn\">Tree exceeds the render limit (" +
             std::to_string(kEchoTreeMaxNodes) +
             " names) \xE2\x80\x94 showing the first " + std::to_string(kEchoTreeMaxNodes) +
             ". Narrow the window.</div>";

    if (tree.depth_capped)
        h += "<div class=\"echo-tree-warn\">Some branches are deeper than the display limit (" +
             std::to_string(kEchoRenderDepthCap) +
             " levels) and are collapsed with \xE2\x80\x9C\xE2\x80\xA6 (depth capped)\xE2\x80\x9D. "
             "The counts above include those hidden descendants.</div>";

    if (tree.roots.empty()) {
        h += "<div class=\"echo-tree-empty\">No process activity recorded for this hour. Pick another "
             "hour, or the host may have no hourly rows yet.</div>";
        return h;
    }

    // Empty-filter hint (shown by the client-side filters when nothing matches).
    h += "<div class=\"echo-tree-nomatch\" style=\"display:none\">No processes match the current "
         "filters.</div>";
    h += "<div class=\"echo-tree\">";
    for (const std::size_t r : tree.roots)
        render_node(tree, r, 0, token, net, h);
    h += "</div>";
    return h;
}

std::string render_echo_proc_detail(const EchoProcNode& node, const std::vector<EchoTcpHourRow>& conns) {
    std::string h;
    h += "<div class=\"echo-detail\">";
    h += "<div class=\"echo-detail-title\">" +
         html_escape(node.name.empty() ? "(unknown)" : node.name) + "</div>";

    auto kv = [&](const std::string& k, const std::string& v) {
        h += "<div class=\"echo-kv\"><span class=\"echo-kv-k\">" + html_escape(k) +
             "</span><span class=\"echo-kv-v\">" + html_escape(v) + "</span></div>";
    };

    kv("Parent name", node.parent_name.empty() ? std::string("none") : node.parent_name);
    if (!node.user.empty())
        kv("User", node.user);
    kv("Started in this hour", std::to_string(node.start_count));
    kv("Stopped in this hour", std::to_string(node.stop_count));
    kv("Abnormal exits", std::to_string(node.abnormal_exit_count));
    if (node.stops_exceed_starts)
        kv("Note", "more stops than starts: some instances started before this hour");

    if (node.anomaly) {
        h += "<div class=\"echo-detail-anom\"><span class=\"echo-badge echo-badge-anom\">\xE2\x9A\xA0 "
             "anomaly</span> " +
             html_escape(node.anomaly_evidence) + "</div>";
    }

    // Connections recorded under this NAME in the hour (from $TCP_Hourly). The hourly tier
    // has no pid, so processes sharing a name share the list.
    h += "<div class=\"echo-detail-section\">Connections</div>";
    if (conns.empty()) {
        h += "<div class=\"echo-tree-mute\">No TCP connections recorded under this name in this "
             "hour.</div>";
    } else {
        h += "<table class=\"echo-detail-conns\"><thead><tr><th>Proto</th><th>Remote</th>"
             "<th>Connects</th><th>Disconnects</th><th>Failed</th></tr></thead><tbody>";
        std::size_t shown = 0;
        for (const auto& c : conns) {
            if (shown++ >= 100)
                break;
            h += "<tr><td>" + html_escape(c.proto) + "</td>";
            h += "<td>" + html_escape(c.remote_addr) + ":" + std::to_string(c.remote_port) + "</td>";
            h += "<td>" + std::to_string(c.connect_count) + "</td>";
            h += "<td>" + std::to_string(c.disconnect_count) + "</td>";
            h += "<td>" + std::to_string(c.failed_count) + "</td></tr>";
        }
        h += "</tbody></table>";
    }
    h += "<div class=\"echo-tree-mute\">Not kept: process ids, command lines and file paths. The parent "
         "link and the connections are joined by name, so processes sharing a name are shown as one "
         "position.</div>";
    h += "</div>";
    return h;
}

// ── Read notes (a failed, cut or partly unreadable read is said, never shown as empty) ──

std::string echo_agent_error_note(const std::string& agent_text) {
    const std::string shown = agent_error_display(agent_text);
    const std::string lower = to_lower(shown);
    // A device whose agent predates the roll-up tables fails the whole query: SQLite names the
    // missing column or table, and the registry names an unknown `$` table.
    for (const char* skew : {"no such column", "no such table", "unknown table"})
        if (lower.find(skew) != std::string::npos)
            return "This device runs an agent without the roll-up store: upgrade the agent";
    return shown.empty() ? std::string("The device reported an error.")
                         : "The device reported an error: " + shown;
}

std::string render_echo_read_notes(const EchoReadNotes& notes, const std::string& subject,
                                   const std::string& row_noun) {
    static_assert(kEchoAgentRowCap == 10000, "the note below spells the cap out as 10,000");
    std::string h;
    if (notes.cut)
        h += "<div class=\"echo-tree-warn\">" + html_escape(subject) +
             " were cut at 10,000 rows for this hour &mdash; what is shown may be incomplete.</div>";
    if (notes.unreadable > 0) {
        // "1 row unreadable": the noun arrives in the plural.
        const std::string noun = notes.unreadable == 1 && row_noun.ends_with('s')
                                     ? row_noun.substr(0, row_noun.size() - 1)
                                     : row_noun;
        h += "<div class=\"echo-tree-warn\">" + std::to_string(notes.unreadable) + " " +
             html_escape(noun) + " unreadable.</div>";
    }
    return h;
}

// ── Device DNS/ARP panels (ADR-0015) — device-level, NOT per process ──────────

namespace {

// Shared shell of the DNS and ARP panels: the hour filter, summary count, notes, empty note,
// table head, 500-row cap and caveat. Each panel supplies only its own columns. A failed read
// (`notes.error`) shows the error in place of the table and a dash for the count.
template <typename Row, typename RowFn>
std::string render_devnet_panel(const std::vector<Row>& rows, std::int64_t hour_ts, const char* title,
                                const char* empty_what, const char* source, const char* thead,
                                RowFn row_html, const std::string& caveat, const EchoReadNotes& notes) {
    std::vector<const Row*> cur;
    for (const auto& r : rows)
        if (r.hour_ts == hour_ts)
            cur.push_back(&r);
    std::string h = "<details class=\"devnet-panel\" open>";
    h += std::string("<summary><span><span class=\"devnet-title-ico\">&#9783;</span>") + title +
         "</span><span class=\"devnet-count\">" +
         (notes.error.empty() ? std::to_string(cur.size()) : std::string("&mdash;")) +
         "</span></summary>";
    if (!notes.error.empty()) {
        h += "<div class=\"echo-tree-warn\">" + html_escape(notes.error) + "</div>";
    } else {
        h += render_echo_read_notes(notes);
        if (cur.empty()) {
            h += std::string("<div class=\"devnet-empty\">No ") + empty_what +
                 " recorded for this hour &mdash; the <code>" + source +
                 "</code> source may be disabled on this device.</div>";
        } else {
            h += std::string("<div class=\"devnet-body\"><table class=\"devnet-table\"><thead><tr>") +
                 thead + "</tr></thead><tbody>";
            std::size_t shown = 0;
            for (const auto* r : cur) {
                if (shown++ >= 500)
                    break;
                h += row_html(*r);
            }
            h += "</tbody></table></div>";
        }
    }
    h += "<div class=\"devnet-caveat\">" + caveat + "</div></details>";
    return h;
}

} // namespace

std::string render_echo_dns_panel(const std::vector<EchoDnsHourRow>& rows, std::int64_t hour_ts,
                                  const EchoReadNotes& notes) {
    return render_devnet_panel(
        rows, hour_ts, "DNS cache activity", "DNS cache activity", "dns",
        "<th>Name</th><th>Type</th><th>Data</th><th>Appeared</th><th>Removed</th>",
        [](const EchoDnsHourRow& r) {
            std::string h = "<tr><td>" + html_escape(r.name) + "</td>";
            h += "<td class=\"dn-type\">" + html_escape(r.record_type) + "</td>";
            h += "<td class=\"dn-data\">" +
                 (r.data.empty() ? std::string("&mdash;") : html_escape(r.data)) + "</td>";
            h += "<td>" + std::to_string(r.appear_count) + "</td>";
            h += "<td>" + std::to_string(r.remove_count) + "</td></tr>";
            return h;
        },
        "Counts of cache entries seen appearing and being removed in the hour from " +
            html_escape(format_iso_utc(hour_ts)) +
            ". Device resolver state, <strong>not</strong> per process.",
        notes);
}

std::string render_echo_arp_panel(const std::vector<EchoArpHourRow>& rows, std::int64_t hour_ts,
                                  const EchoReadNotes& notes) {
    return render_devnet_panel(
        rows, hour_ts, "ARP table activity", "ARP activity", "arp",
        "<th>Interface</th><th>IP address</th><th>MAC address</th><th>Appeared</th><th>Removed</th>",
        [](const EchoArpHourRow& r) {
            std::string h = "<tr><td>" + html_escape(r.iface) + "</td>";
            h += "<td>" + html_escape(r.ip_address) + "</td>";
            h += "<td class=\"arp-mac\">" + html_escape(r.mac_address) + "</td>";
            h += "<td>" + std::to_string(r.appear_count) + "</td>";
            h += "<td>" + std::to_string(r.remove_count) + "</td></tr>";
            return h;
        },
        "Counts of neighbour entries seen appearing and being removed in the hour from " +
            html_escape(format_iso_utc(hour_ts)) + ". Device neighbour-table state.",
        notes);
}

// ── Capture-sources frame (ADR-0015) ─────────────────────────────────────────

std::string render_echo_capture_sources(const std::string& device, const std::string& status_output) {
    // status: config|<key>|<value>
    std::unordered_map<std::string, std::string> cfg;
    std::size_t pos = 0;
    while (pos < status_output.size()) {
        const auto nl = status_output.find('\n', pos);
        std::string line =
            status_output.substr(pos, (nl == std::string::npos ? status_output.size() : nl) - pos);
        pos = (nl == std::string::npos) ? status_output.size() : nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        const auto c = echo_split_pipe(line, 4); // config|key|value (+ the unsplit rest)
        if (c.size() >= 3 && c[0] == "config")
            cfg[c[1]] = c[2];
    }

    struct Meta {
        const char* name;
        const char* dollar; ///< the HOURLY table — raw capture rows are not kept
        const char* category;
        bool always_on;
        bool is_new;
        const char* tiers; ///< H = hourly, D = daily, M = monthly (the fold schema's tier set)
    };
    // Presentation metadata (the agent's schema registry is not linked here).
    // Category follows docs/user-manual/echo.md's five categories. always_on = the
    // default-enabled core sources (the toggle is locked here; pause/resume uses the
    // configure path, and the State cell still shows the reported <src>_enabled as
    // "always on" or "paused"). is_new drives the badge.
    static const std::array<Meta, 11> kSources = {{
        {"process", "$Process_Hourly", "Processes", true, false, "HDM"},
        {"tcp", "$TCP_Hourly", "Network connections", true, false, "HDM"},
        {"service", "$Service_Hourly", "Services", true, false, "HD"},
        {"user", "$User_Hourly", "User sessions", true, false, "HD"},
        {"perf", "$Perf_Hourly", "Performance", true, false, "HD"},
        {"procperf", "$ProcPerf_Hourly", "Performance", false, false, "HD"},
        {"netqual", "$NetQual_Hourly", "Network connections", false, false, "HD"},
        {"module", "$Module_Hourly", "Processes", false, false, "HDM"},
        {"arp", "$ARP_Hourly", "Network connections", false, true, "H"},
        {"dns", "$DNS_Hourly", "Network connections", false, true, "H"},
        // registry (PR11.8): an older agent never reports registry_enabled, so the card is
        // simply absent; a current agent reports it on every OS.
        {"registry", "$Registry_Hourly", "System", false, true, "HD"},
    }};

    std::string h = "<div class=\"cat-filter\" id=\"capFilter\"><span class=\"filter-label\">"
                    "Category</span><span class=\"echo-seg\"><a class=\"echo-chip on\" onclick=\"filterCap(this,'all')\">All</a>";
    static const std::array<std::pair<const char*, const char*>, 6> kChips = {
        {{"Processes", "Processes"},
         {"Network connections", "Network"},
         {"Services", "Services"},
         {"User sessions", "User sessions"},
         {"Performance", "Performance"},
         {"System", "System"}}};
    for (const auto& [cat, label] : kChips)
        h += std::string("<a class=\"echo-chip\" onclick=\"filterCap(this,'") + cat + "')\">" + label +
             "</a>";
    h += "</span></div>";

    h += "<div class=\"cards\" id=\"capCards\" data-device=\"" + html_escape(device) + "\">";

    // A bucket start as "YYYY-MM-DD HH:MM UTC"; "&mdash;" when the key is absent or unparseable.
    const auto bucket_label = [](const std::string& raw) -> std::string {
        const auto ts = cell_i64(raw);
        if (!ts || *ts <= 0)
            return "&mdash;";
        const std::string iso = format_iso_utc(*ts); // YYYY-MM-DDTHH:MM:SSZ
        return iso.substr(0, 10) + " " + iso.substr(11, 5) + " UTC";
    };

    int rendered = 0;
    for (const auto& m : kSources) {
        const std::string en_key = std::string(m.name) + "_enabled";
        if (!cfg.count(en_key))
            continue; // not reported by this agent — skip
        ++rendered;
        const bool enabled = cfg.at(en_key) != "false";
        // The agent publishes `<src>_rows`. No key → unknown, shown as a dash rather than a false 0.
        const auto rows_it = cfg.find(std::string(m.name) + "_rows");
        const std::string rows = rows_it != cfg.end() ? html_escape(rows_it->second) : "&mdash;";
        const auto oldest = cfg.find(std::string(m.name) + "_oldest_ts");
        const auto paused = cfg.find(std::string(m.name) + "_paused_at");

        h += "<div class=\"card\" data-cat=\"" + std::string(m.category) +
             "\"><div class=\"top\"><span class=\"nm\"><span class=\"src-name\">" + std::string(m.name) +
             "</span>";
        if (m.is_new)
            h += " <span class=\"badge badge-new\">NEW</span>";
        h += "</span>";
        std::string state_txt;
        if (m.always_on && enabled) {
            h += "<label class=\"tgl locked\"><input type=\"checkbox\" checked disabled>"
                 "<span class=\"sl\"></span></label>";
            state_txt = "<span class=\"state-txt state-on\">always on</span>";
        } else if (m.always_on) {
            h += "<label class=\"tgl locked\"><input type=\"checkbox\" disabled>"
                 "<span class=\"sl\"></span></label>";
            state_txt = "<span class=\"state-txt\">paused</span>";
        } else {
            h += "<label class=\"tgl\"><input type=\"checkbox\" data-source=\"" + std::string(m.name) +
                 "\" data-committed=\"" + (enabled ? "true" : "false") + "\"" +
                 (enabled ? " checked" : "") +
                 " onchange=\"stageCapToggle(this)\"><span class=\"sl\"></span></label>";
            state_txt = std::string("<span class=\"state-txt") + (enabled ? " state-on" : "") + "\">" +
                        (enabled ? "enabled" : "disabled") + "</span>";
        }
        h += "</div><div class=\"hint\">" + std::string(m.category) + "</div><dl><dt>State</dt><dd>" +
             state_txt;
        if (paused != cfg.end() && !enabled && cell_i64(paused->second).value_or(0) > 0)
            h += " <span class=\"hint\">since " + html_escape(format_iso_utc(*cell_i64(paused->second))) +
                 "</span>";
        h += "</dd><dt>Hourly rows</dt><dd class=\"mono\"><span class=\"badge badge-rows\">" + rows +
             "</span></dd><dt>Oldest bucket</dt><dd class=\"mono\">" +
             (oldest != cfg.end() ? bucket_label(oldest->second) : std::string("&mdash;")) +
             "</dd><dt>Hourly table</dt><dd class=\"src-dollar\">" + std::string(m.dollar) +
             "</dd><dt>Kept as</dt><dd class=\"tiers-mini\">";
        for (const char* t = m.tiers; *t; ++t)
            h += std::string("<span>") + (*t == 'H' ? "Hourly" : (*t == 'D' ? "Daily" : "Monthly")) +
                 "</span>";
        h += "</dd></dl></div>";
    }
    h += "</div>";
    if (rendered == 0)
        return "<div class=\"devnet-empty\">No capture sources reported by this device.</div>";
    h += "<div class=\"apply-bar note warn\" id=\"capApplyBar\" hidden><span class=\"apply-icon\">&#9888;</span>"
         "<span id=\"capApplyMsg\">0 pending changes</span><span class=\"apply-spacer\"></span>"
         "<button class=\"btn-secondary\" onclick=\"discardCapChanges()\">Discard</button>"
         "<button class=\"apply-push\" onclick=\"pushCapChanges()\">Push changes &#8594;</button></div>";
    return h;
}

} // namespace yuzu::server
