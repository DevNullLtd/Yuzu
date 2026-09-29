/// @file tar_process_tree.cpp
/// Implementation of the TAR process-tree reconstruction engine + pure renderers.
/// See tar_process_tree.hpp for the data-source constraints that shape this model.

#include "tar_process_tree.hpp"

#include "web_utils.hpp" // html_escape, format_iso_utc, format_relative_time

#include <unordered_set> // device-net panel current-state reduction (ADR-0015)

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace yuzu::server {

namespace {

std::vector<std::string> split_pipe(const std::string& line) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (true) {
        const auto bar = line.find('|', pos);
        if (bar == std::string::npos) {
            out.push_back(line.substr(pos));
            return out;
        }
        out.push_back(line.substr(pos, bar - pos));
        pos = bar + 1;
    }
}

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

} // namespace

bool tar_is_suspicious_spawn(const std::string& parent_name, const std::string& child_name,
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

std::vector<TarProcEvent> parse_tar_process_output(const std::string& output, std::size_t max_rows) {
    std::vector<TarProcEvent> out;
    int c_ts = -1, c_action = -1, c_pid = -1, c_ppid = -1, c_name = -1, c_cmd = -1, c_user = -1;
    bool have_schema = false;
    std::size_t pos = 0;
    while (pos < output.size() && out.size() < max_rows) {
        const auto nl = output.find('\n', pos);
        std::string line = output.substr(pos, (nl == std::string::npos ? output.size() : nl) - pos);
        pos = (nl == std::string::npos) ? output.size() : nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;
        if (!have_schema) {
            if (line.starts_with("error|"))
                return out; // agent-side error payload
            if (!line.starts_with("__schema__|"))
                continue;
            const auto cols = split_pipe(line);
            c_ts = schema_index(cols, "ts");
            c_action = schema_index(cols, "action");
            c_pid = schema_index(cols, "pid");
            c_ppid = schema_index(cols, "ppid");
            c_name = schema_index(cols, "name");
            c_cmd = schema_index(cols, "cmdline");
            c_user = schema_index(cols, "user");
            // ppid/name/user may legitimately be empty cells, but the COLUMNS must
            // exist; cmdline is optional (Windows omits content, not the column).
            if (c_ts < 0 || c_action < 0 || c_pid < 0 || c_ppid < 0 || c_name < 0)
                return out; // wrong shape — refuse rather than guess
            have_schema = true;
            continue;
        }
        const auto cells = split_pipe(line);
        const int need = (std::max)({c_ts, c_action, c_pid, c_ppid, c_name,
                                     c_cmd < 0 ? 0 : c_cmd, c_user < 0 ? 0 : c_user});
        if (static_cast<int>(cells.size()) <= need)
            continue; // trailer ("total|N") or torn row
        const auto ts = cell_i64(cells[static_cast<std::size_t>(c_ts)]);
        const auto pid = cell_i64(cells[static_cast<std::size_t>(c_pid)]);
        const auto ppid = cell_i64(cells[static_cast<std::size_t>(c_ppid)]);
        if (!ts || !pid || !ppid || *pid > UINT32_MAX || *ppid > UINT32_MAX)
            continue;
        TarProcEvent e;
        e.ts = *ts;
        e.action = to_lower(cells[static_cast<std::size_t>(c_action)]);
        e.pid = static_cast<std::uint32_t>(*pid);
        e.ppid = static_cast<std::uint32_t>(*ppid);
        e.name = cells[static_cast<std::size_t>(c_name)];
        if (c_cmd >= 0)
            e.cmdline = cells[static_cast<std::size_t>(c_cmd)];
        if (c_user >= 0)
            e.user = cells[static_cast<std::size_t>(c_user)];
        out.push_back(std::move(e));
    }
    return out;
}

std::vector<TarTcpConn> parse_tar_tcp_output(const std::string& output, std::size_t max_rows) {
    std::vector<TarTcpConn> out;
    int c_pid = -1, c_pname = -1, c_proto = -1, c_lport = -1, c_raddr = -1, c_rport = -1,
        c_state = -1, c_ts = -1, c_action = -1;
    bool have_schema = false;
    std::size_t pos = 0;
    while (pos < output.size() && out.size() < max_rows) {
        const auto nl = output.find('\n', pos);
        std::string line = output.substr(pos, (nl == std::string::npos ? output.size() : nl) - pos);
        pos = (nl == std::string::npos) ? output.size() : nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;
        if (!have_schema) {
            if (line.starts_with("error|"))
                return out;
            if (!line.starts_with("__schema__|"))
                continue;
            const auto cols = split_pipe(line);
            c_pid = schema_index(cols, "pid");
            c_pname = schema_index(cols, "process_name");
            c_proto = schema_index(cols, "proto");
            c_lport = schema_index(cols, "local_port");
            c_raddr = schema_index(cols, "remote_addr");
            c_rport = schema_index(cols, "remote_port");
            c_state = schema_index(cols, "state");
            c_ts = schema_index(cols, "ts");
            c_action = schema_index(cols, "action");
            if (c_pid < 0 || c_raddr < 0)
                return out; // need at least the join key + remote
            have_schema = true;
            continue;
        }
        const auto cells = split_pipe(line);
        auto at = [&](int idx) -> std::string {
            return (idx >= 0 && idx < static_cast<int>(cells.size()))
                       ? cells[static_cast<std::size_t>(idx)]
                       : std::string{};
        };
        const auto pid = cell_i64(at(c_pid));
        if (!pid || *pid > UINT32_MAX)
            continue;
        TarTcpConn t;
        t.pid = static_cast<std::uint32_t>(*pid);
        t.process_name = at(c_pname);
        t.proto = at(c_proto);
        if (auto v = cell_i64(at(c_lport)); v && *v <= 65535)
            t.local_port = static_cast<int>(*v);
        t.remote_addr = at(c_raddr);
        if (auto v = cell_i64(at(c_rport)); v && *v <= 65535)
            t.remote_port = static_cast<int>(*v);
        t.state = at(c_state);
        if (auto v = cell_i64(at(c_ts)); v)
            t.ts = *v;
        t.action = to_lower(at(c_action));
        out.push_back(std::move(t));
    }
    return out;
}

std::vector<TarDnsCacheEntry> parse_tar_dns_output(const std::string& output, std::size_t max_rows) {
    std::vector<TarDnsCacheEntry> out;
    int c_ts = -1, c_name = -1, c_type = -1, c_data = -1, c_ttl = -1, c_src = -1, c_action = -1;
    bool have_schema = false;
    std::size_t pos = 0;
    while (pos < output.size() && out.size() < max_rows) {
        const auto nl = output.find('\n', pos);
        std::string line = output.substr(pos, (nl == std::string::npos ? output.size() : nl) - pos);
        pos = (nl == std::string::npos) ? output.size() : nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;
        if (!have_schema) {
            if (line.starts_with("error|"))
                return out;
            if (!line.starts_with("__schema__|"))
                continue;
            const auto cols = split_pipe(line);
            c_ts = schema_index(cols, "ts");
            c_name = schema_index(cols, "name");
            c_type = schema_index(cols, "record_type");
            c_data = schema_index(cols, "data");
            c_ttl = schema_index(cols, "ttl_remaining_s");
            c_src = schema_index(cols, "source");
            c_action = schema_index(cols, "action");
            if (c_name < 0 || c_type < 0 || c_data < 0)
                return out; // need at least the resolution identity
            have_schema = true;
            continue;
        }
        const auto cells = split_pipe(line);
        auto at = [&](int idx) -> std::string {
            return (idx >= 0 && idx < static_cast<int>(cells.size()))
                       ? cells[static_cast<std::size_t>(idx)]
                       : std::string{};
        };
        const int need = (std::max)({c_name, c_type, c_data});
        if (static_cast<int>(cells.size()) <= need)
            continue; // trailer ("total|N") or torn row
        TarDnsCacheEntry e;
        if (auto v = cell_i64(at(c_ts)); v)
            e.ts = *v;
        e.name = at(c_name);
        e.record_type = at(c_type);
        e.data = at(c_data);
        if (auto v = cell_i64(at(c_ttl)); v)
            e.ttl_remaining_s = *v;
        e.source = at(c_src);
        e.action = to_lower(at(c_action));
        out.push_back(std::move(e));
    }
    return out;
}

std::vector<TarArpEntry> parse_tar_arp_output(const std::string& output, std::size_t max_rows) {
    std::vector<TarArpEntry> out;
    int c_ts = -1, c_iface = -1, c_ip = -1, c_mac = -1, c_type = -1, c_action = -1;
    bool have_schema = false;
    std::size_t pos = 0;
    while (pos < output.size() && out.size() < max_rows) {
        const auto nl = output.find('\n', pos);
        std::string line = output.substr(pos, (nl == std::string::npos ? output.size() : nl) - pos);
        pos = (nl == std::string::npos) ? output.size() : nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;
        if (!have_schema) {
            if (line.starts_with("error|"))
                return out;
            if (!line.starts_with("__schema__|"))
                continue;
            const auto cols = split_pipe(line);
            c_ts = schema_index(cols, "ts");
            c_iface = schema_index(cols, "interface");
            c_ip = schema_index(cols, "ip_address");
            c_mac = schema_index(cols, "mac_address");
            c_type = schema_index(cols, "entry_type");
            c_action = schema_index(cols, "action");
            if (c_ip < 0 || c_mac < 0)
                return out; // need at least the binding endpoints
            have_schema = true;
            continue;
        }
        const auto cells = split_pipe(line);
        auto at = [&](int idx) -> std::string {
            return (idx >= 0 && idx < static_cast<int>(cells.size()))
                       ? cells[static_cast<std::size_t>(idx)]
                       : std::string{};
        };
        const int need = (std::max)(c_ip, c_mac);
        if (static_cast<int>(cells.size()) <= need)
            continue;
        TarArpEntry e;
        if (auto v = cell_i64(at(c_ts)); v)
            e.ts = *v;
        e.iface = at(c_iface);
        e.ip_address = at(c_ip);
        e.mac_address = at(c_mac);
        e.entry_type = at(c_type);
        e.action = to_lower(at(c_action));
        out.push_back(std::move(e));
    }
    return out;
}

TarTreeAnchors compute_tar_anchors(const std::vector<TarProcEvent>& events) {
    TarTreeAnchors a;
    bool first = true;
    std::int64_t boot = 0;
    for (const auto& e : events) {
        // Ignore non-positive timestamps — a forged/garbage `ts<=0` must not poison the
        // "observed since" / install anchor (it would otherwise drag MIN to 0/negative).
        if (e.ts <= 0)
            continue;
        if (first || e.ts < a.observed_since) {
            a.observed_since = e.ts;
            first = false;
        }
        // Best-effort boot signal: the most-recent START of a canonical root process
        // (ppid==0 — Windows "System" pid 4 / Linux init pid 1). TAR has no boot-time
        // column; this is the closest in-band proxy and falls back to install below.
        const bool start = (e.action == "started" || e.action == "start");
        if (start && e.ppid == 0 && e.ts > boot)
            boot = e.ts;
    }
    a.install_ts = a.observed_since;
    a.boot_ts = boot > 0 ? boot : a.observed_since;
    return a;
}

TarWindow resolve_tar_window(const std::string& preset, std::int64_t custom_from,
                             std::int64_t custom_to, const TarTreeAnchors& anchors,
                             std::int64_t now) {
    TarWindow w;
    w.to_ts = now;
    if (preset == "on_boot") {
        w.from_ts = anchors.boot_ts;
    } else if (preset == "on_install") {
        w.from_ts = anchors.install_ts;
    } else if (preset == "1m") {
        w.from_ts = now - 60;
    } else if (preset == "1h") {
        w.from_ts = now - 3600;
    } else if (preset == "1d") {
        w.from_ts = now - 86400;
    } else if (preset == "custom") {
        w.from_ts = custom_from > 0 ? custom_from : anchors.install_ts;
        w.to_ts = custom_to > 0 ? custom_to : now;
    } else {
        // default / "10m"
        w.from_ts = now - 600;
    }
    if (w.from_ts < 0)
        w.from_ts = 0;
    if (w.to_ts < w.from_ts)
        w.to_ts = w.from_ts; // reversed range → point-in-time at `to`
    return w;
}

std::string canonical_tar_preset(const std::string& preset) {
    // Keep in lock-step with resolve_tar_window's accepted tokens. Anything else
    // (empty, garbage, an injection attempt) collapses to the `10m` default.
    if (preset == "on_boot" || preset == "on_install" || preset == "1m" || preset == "10m" ||
        preset == "1h" || preset == "1d" || preset == "custom")
        return preset;
    return "10m";
}

std::string normalize_tar_os(const std::string& os) {
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

namespace {

/// A pid's lifetime as walked from the event stream (one incarnation).
struct Incarnation {
    std::uint32_t pid = 0;
    std::uint32_t ppid = 0;
    std::string name;
    std::string cmdline;
    std::string user;
    std::int64_t start = 0;
    std::int64_t end = 0; // 0 = still running at `to`
    bool start_known = false;
    bool running = false;
};

bool is_start(const std::string& action) {
    return action == "started" || action == "start";
}
bool is_stop(const std::string& action) {
    return action == "stopped" || action == "stop";
}

} // namespace

TarProcTree reconstruct_tar_process_tree(const std::vector<TarProcEvent>& events_in,
                                         std::int64_t from_ts, std::int64_t to_ts,
                                         const TarTreeAnchors& anchors) {
    TarProcTree tree;
    tree.from_ts = from_ts;
    tree.to_ts = to_ts;
    tree.anchors = anchors;

    // 1. Bucket events by pid, only those at or before `to` (defensive even though
    //    the route fetches ts<=to), sorted by (ts, starts-before-stops).
    std::unordered_map<std::uint32_t, std::vector<const TarProcEvent*>> by_pid;
    for (const auto& e : events_in)
        if (e.ts <= to_ts)
            by_pid[e.pid].push_back(&e);

    std::vector<Incarnation> incs;
    for (auto& [pid, evs] : by_pid) {
        std::stable_sort(evs.begin(), evs.end(), [](const TarProcEvent* a, const TarProcEvent* b) {
            if (a->ts != b->ts)
                return a->ts < b->ts;
            return is_start(a->action) && !is_start(b->action); // starts before stops at a tie
        });
        std::optional<Incarnation> cur;
        for (const TarProcEvent* e : evs) {
            if (is_start(e->action)) {
                if (cur) {
                    // A start while still "open" means the pid was reused — the prior
                    // incarnation must have ended; close it at this ts.
                    cur->end = e->ts;
                    incs.push_back(std::move(*cur));
                }
                Incarnation inc;
                inc.pid = pid;
                inc.ppid = e->ppid;
                inc.name = e->name;
                inc.cmdline = e->cmdline;
                inc.user = e->user;
                inc.start = e->ts;
                inc.start_known = true;
                cur = std::move(inc);
            } else if (is_stop(e->action)) {
                if (cur) {
                    cur->end = e->ts;
                    incs.push_back(std::move(*cur));
                    cur.reset();
                } else {
                    // A stop with no surviving start — its `started` aged out of the
                    // live cap (no seed). Synthesise a "started before observation"
                    // incarnation from the stop row's fields (which carry name/ppid).
                    Incarnation inc;
                    inc.pid = pid;
                    inc.ppid = e->ppid;
                    inc.name = e->name;
                    inc.cmdline = e->cmdline;
                    inc.user = e->user;
                    inc.start = 0;
                    inc.start_known = false;
                    inc.end = e->ts;
                    incs.push_back(std::move(inc));
                }
            }
        }
        if (cur) { // open at end of stream → running at `to`
            cur->running = true;
            cur->end = 0;
            incs.push_back(std::move(*cur));
        }
    }

    // 2. Window-overlap filter: keep an incarnation if it was alive at any point in
    //    [from, to] — running (alive at `to`) OR it exited at/after `from`.
    std::vector<Incarnation> kept;
    kept.reserve(incs.size());
    for (auto& inc : incs) {
        if (inc.running || inc.end >= from_ts)
            kept.push_back(std::move(inc));
    }
    // 3. Node cap: on overflow keep RUNNING incarnations first, then the most-recent
    //    by start. Running-first matters because a long-running process whose start
    //    aged out has start=0 (start_known=false) — ranking purely by start would drop
    //    exactly those persistent, often forensically-interesting processes first.
    if (kept.size() > kTarTreeMaxNodes) {
        std::partial_sort(kept.begin(), kept.begin() + kTarTreeMaxNodes, kept.end(),
                          [](const Incarnation& a, const Incarnation& b) {
                              if (a.running != b.running)
                                  return a.running; // running before exited
                              return a.start > b.start;
                          });
        kept.resize(kTarTreeMaxNodes);
        tree.truncated = true;
    }

    // Materialise nodes (stable node_id = index).
    tree.nodes.reserve(kept.size());
    for (const auto& inc : kept) {
        TarProcNode n;
        n.pid = inc.pid;
        n.ppid = inc.ppid;
        n.name = inc.name;
        n.cmdline = inc.cmdline;
        n.user = inc.user;
        n.started_ts = inc.start;
        n.start_known = inc.start_known;
        n.exited_ts = inc.running ? 0 : inc.end;
        n.running = inc.running;
        tree.nodes.push_back(std::move(n));
    }

    // 4. Parent resolution: a child links to the incarnation of its ppid whose
    //    lifetime contained the child's start. pid index for the lookup.
    std::unordered_map<std::uint32_t, std::vector<std::size_t>> pid_to_nodes;
    for (std::size_t i = 0; i < tree.nodes.size(); ++i)
        pid_to_nodes[tree.nodes[i].pid].push_back(i);

    auto node_lo = [&](std::size_t id) -> std::int64_t {
        return tree.nodes[id].start_known ? tree.nodes[id].started_ts : from_ts;
    };
    auto node_hi = [&](std::size_t id) -> std::int64_t {
        return tree.nodes[id].running ? to_ts : tree.nodes[id].exited_ts;
    };
    constexpr std::size_t kMaxDepthGuard = 4096;
    for (std::size_t i = 0; i < tree.nodes.size(); ++i) {
        TarProcNode& n = tree.nodes[i];
        if (n.ppid == 0 || n.ppid == n.pid)
            continue; // root
        auto it = pid_to_nodes.find(n.ppid);
        if (it == pid_to_nodes.end())
            continue; // parent not present → orphan/reparented root
        const std::int64_t child_start = node_lo(i);
        std::size_t best = TarProcNode::kNoParent;
        std::int64_t best_lo = INT64_MIN;
        bool best_contains = false; // a containing parent always beats a non-containing one
        for (std::size_t pcand : it->second) {
            if (pcand == i)
                continue;
            const std::int64_t plo = node_lo(pcand), phi = node_hi(pcand);
            const bool contains = plo <= child_start && child_start <= phi;
            // Prefer the incarnation whose interval CONTAINS the child's start; among
            // those, the most-recent (largest plo). Only if none contains, fall back to
            // the most-recent incarnation that started before the child. `best_contains`
            // is tracked separately so a containing candidate found AFTER a higher-plo
            // non-containing fallback still wins (candidates aren't plo-sorted).
            if (contains) {
                if (!best_contains || plo >= best_lo) {
                    best = pcand;
                    best_lo = plo;
                    best_contains = true;
                }
            } else if (!best_contains && plo <= child_start && plo >= best_lo) {
                best = pcand;
                best_lo = plo;
            }
        }
        if (best == TarProcNode::kNoParent)
            continue; // root
        // Cycle guard: walking up from `best` must not reach `i` (pid reuse can form
        // a loop). If it would, leave `i` a root instead of closing the cycle.
        std::size_t walk = best;
        std::size_t depth = 0;
        bool cycle = false;
        while (walk != TarProcNode::kNoParent && depth++ < kMaxDepthGuard) {
            if (walk == i) {
                cycle = true;
                break;
            }
            walk = tree.nodes[walk].parent;
        }
        if (cycle)
            continue; // keep `i` as a root
        n.parent = best;
    }

    // 5. Children lists + root set from the final parent fields.
    for (std::size_t i = 0; i < tree.nodes.size(); ++i) {
        if (tree.nodes[i].parent == TarProcNode::kNoParent)
            tree.roots.push_back(i);
        else
            tree.nodes[tree.nodes[i].parent].children.push_back(i);
    }
    // Stable sibling order: by pid then start.
    auto sib_less = [&](std::size_t a, std::size_t b) {
        if (tree.nodes[a].pid != tree.nodes[b].pid)
            return tree.nodes[a].pid < tree.nodes[b].pid;
        return tree.nodes[a].started_ts < tree.nodes[b].started_ts;
    };
    std::sort(tree.roots.begin(), tree.roots.end(), sib_less);
    for (auto& n : tree.nodes)
        std::sort(n.children.begin(), n.children.end(), sib_less);

    // 6. Anomaly flag: suspicious parent→child name pairs.
    for (auto& n : tree.nodes) {
        if (n.parent == TarProcNode::kNoParent)
            continue;
        std::string ev;
        if (tar_is_suspicious_spawn(tree.nodes[n.parent].name, n.name, &ev)) {
            n.anomaly = true;
            n.anomaly_evidence = std::move(ev);
        }
    }

    // 7. Counts over the full tree (reachable from roots) — for the banner. Running/
    //    exited/anomalies-only filtering is applied client-side at display time, so
    //    the reconstruction itself is never pruned (every node stays addressable by
    //    the detail route, and a filter toggle needs no re-dispatch).
    std::vector<bool> seen(tree.nodes.size(), false);
    std::vector<std::pair<std::size_t, int>> stack; // {node_id, depth}
    stack.reserve(tree.roots.size());
    for (std::size_t r : tree.roots)
        stack.emplace_back(r, 0);
    while (!stack.empty()) {
        const auto [id, depth] = stack.back();
        stack.pop_back();
        if (id >= tree.nodes.size() || seen[id])
            continue;
        seen[id] = true;
        // The renderer collapses branches past kTarRenderDepthCap, but the counts
        // here cover the FULL reconstruction (every node stays detail-addressable);
        // flag the mismatch so the banner can say the count includes hidden depth.
        if (depth > kTarRenderDepthCap)
            tree.depth_capped = true;
        const TarProcNode& n = tree.nodes[id];
        if (n.running)
            ++tree.running_count;
        else
            ++tree.exited_count;
        if (n.anomaly)
            ++tree.anomaly_count;
        for (std::size_t c : n.children)
            stack.emplace_back(c, depth + 1);
    }
    return tree;
}

// ── Renderers ────────────────────────────────────────────────────────────────

namespace {

bool os_is_windows(const std::string& os) {
    const std::string o = to_lower(os);
    return o.find("win") != std::string::npos;
}

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

/// One distinct remote endpoint label (`addr:port`, or `:port listen` for a
/// listener), HTML-escaped, wrapped in a class that colours public egress.
std::string endpoint_chip(const TarTcpConn& c) {
    const std::string cls = remote_class(c.remote_addr);
    std::string label;
    if (cls.empty() || c.remote_port == 0)
        label = ":" + std::to_string(c.local_port) + " listen";
    else
        label = c.remote_addr + ":" + std::to_string(c.remote_port);
    std::string klass = "tt-ep";
    if (cls == "pub")
        klass += " tt-ep-pub";
    return "<span class=\"" + klass + "\">" + html_escape(label) + "</span>";
}

/// Inline network summary for a node's connections (already filtered to its pid):
/// a count badge + up to two distinct endpoints + "+N", with the full list in the
/// title. Empty string when the node has no connections.
std::string net_cell(const std::vector<const TarTcpConn*>& conns) {
    if (conns.empty())
        return {};
    // Distinct endpoints, public first, preserving first-seen order otherwise. Dedup
    // via a hash set (a single pid can own thousands of $TCP_Live rows — O(n) not O(n²)).
    std::vector<const TarTcpConn*> distinct;
    std::unordered_set<std::string> seen;
    bool any_public = false;
    for (const TarTcpConn* c : conns) {
        std::string key = c->remote_addr + ":" + std::to_string(c->remote_port) + "/" +
                          std::to_string(c->local_port);
        if (!seen.insert(std::move(key)).second)
            continue;
        distinct.push_back(c);
        if (remote_class(c->remote_addr) == "pub")
            any_public = true;
    }
    std::stable_sort(distinct.begin(), distinct.end(), [](const TarTcpConn* a, const TarTcpConn* b) {
        return (remote_class(a->remote_addr) == "pub") && (remote_class(b->remote_addr) != "pub");
    });
    std::string title;
    for (std::size_t i = 0; i < distinct.size() && i < 12; ++i) {
        const TarTcpConn* c = distinct[i];
        title += (c->remote_addr.empty() ? ":" + std::to_string(c->local_port)
                                         : c->remote_addr + ":" + std::to_string(c->remote_port));
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

using ConnIndex = std::unordered_map<std::uint32_t, std::vector<const TarTcpConn*>>;

/// One node's summary row (the clickable line). `node_id` addresses the detail; the
/// row carries data-state/data-anom for the client-side filters.
std::string node_summary_row(const TarProcTree& tree, std::size_t id, const std::string& token,
                             const ConnIndex& conn_index) {
    const TarProcNode& n = tree.nodes[id];
    const char* state = n.running ? "running" : "exited";
    std::string row;
    row += "<a class=\"tar-tree-row\" data-state=\"";
    row += state;
    row += "\" data-anom=\"";
    row += n.anomaly ? "1" : "0";
    row += "\" hx-get=\"/fragments/tar/process-tree/detail?token=" + token +
           "&amp;node=" + std::to_string(id) +
           "\" hx-target=\"#tar-tree-detail\" hx-swap=\"innerHTML\">";
    row += n.running ? "<span class=\"tt-dot tt-dot-run\"></span>"
                     : "<span class=\"tt-dot tt-dot-exit\"></span>";
    row += "<span class=\"tt-pid\">" + std::to_string(n.pid) + "</span>";
    row += "<span class=\"tt-name\">" + html_escape(n.name.empty() ? "(unknown)" : n.name) + "</span>";
    if (!n.user.empty())
        row += "<span class=\"tt-user\">" + html_escape(n.user) + "</span>";
    if (!n.running)
        row += "<span class=\"tt-meta\" title=\"" + html_escape(format_iso_utc(n.exited_ts)) +
               "\">exited " + html_escape(format_relative_time(n.exited_ts, tree.to_ts)) + "</span>";
    auto it = conn_index.find(n.pid);
    if (it != conn_index.end())
        row += net_cell(it->second);
    if (n.anomaly)
        row += "<span class=\"tt-anom\" title=\"" + html_escape(n.anomaly_evidence) +
               "\">\xE2\x9A\xA0</span>";
    row += "</a>";
    return row;
}

// Group same-name siblings into one collapsible row once there are at least this
// many (cleans up e.g. dozens of svchost.exe under services.exe).
constexpr std::size_t kTarGroupThreshold = 4;

void render_node(const TarProcTree& tree, std::size_t id, int depth, const std::string& token,
                 const ConnIndex& conn_index, std::string& out); // fwd (mutual recursion)

/// One collapsed "name ×N" group summarising same-name siblings; expands to the
/// individual PIDs (each still drill-able). Collapsed by default — the cleanup.
void render_group(const TarProcTree& tree, const std::string& name,
                  const std::vector<std::size_t>& group, int depth, const std::string& token,
                  const ConnIndex& conn_index, std::string& out) {
    int run = 0, ex = 0, anom = 0;
    for (std::size_t id : group) {
        tree.nodes[id].running ? ++run : ++ex;
        if (tree.nodes[id].anomaly)
            ++anom;
    }
    out += "<details class=\"tar-tree-node tar-tree-group\"><summary><span class=\"tar-tree-row "
           "tt-group\">";
    out += "<span class=\"tt-group-ico\">\xE2\x96\xA6</span>";
    out += "<span class=\"tt-name\">" + html_escape(name.empty() ? "(unknown)" : name) + "</span>";
    out += "<span class=\"tt-group-count\">\xC3\x97" + std::to_string(group.size()) + "</span>";
    out += "<span class=\"tt-meta\">" + std::to_string(run) + " running";
    if (ex > 0)
        out += " \xC2\xB7 " + std::to_string(ex) + " exited";
    out += "</span>";
    if (anom > 0)
        out += "<span class=\"tt-anom\">\xE2\x9A\xA0 " + std::to_string(anom) + "</span>";
    out += "</span></summary><div class=\"tar-tree-children\">";
    for (std::size_t id : group)
        render_node(tree, id, depth + 1, token, conn_index, out);
    out += "</div></details>";
}

/// Render a sibling set, grouping same-name runs of >= kTarGroupThreshold into a
/// single collapsed group (first-appearance order).
///
/// First-appearance-ordered bucketing in O(n): the prior nested-loop scan was
/// O(n²) in per-level fan-out (a forged flat tree can put ~50k distinct-name
/// children under one parent → ~1.25B string compares at render). This reproduces
/// the previous output exactly — groups emit in first-appearance order, ids keep
/// their original order within a group, and a name with < kTarGroupThreshold
/// members still renders as individual nodes at its first-appearance position.
/// Keys are string_views into the stable `tree.nodes[id].name` (tree is const for
/// the whole render, nodes is never reallocated), so no per-id key copy.
void render_children(const TarProcTree& tree, const std::vector<std::size_t>& ids, int depth,
                     const std::string& token, const ConnIndex& conn_index, std::string& out) {
    std::vector<std::string_view> order;
    order.reserve(ids.size());
    std::unordered_map<std::string_view, std::vector<std::size_t>> buckets;
    for (std::size_t id : ids) {
        std::string_view nm{tree.nodes[id].name};
        auto [it, inserted] = buckets.try_emplace(nm);
        if (inserted)
            order.push_back(nm);
        it->second.push_back(id);
    }
    for (std::string_view nm : order) {
        const auto& group = buckets[nm];
        if (group.size() >= kTarGroupThreshold)
            render_group(tree, std::string(nm), group, depth, token, conn_index, out);
        else
            for (std::size_t id : group)
                render_node(tree, id, depth, token, conn_index, out);
    }
}

void render_node(const TarProcTree& tree, std::size_t id, int depth, const std::string& token,
                 const ConnIndex& conn_index, std::string& out) {
    if (id >= tree.nodes.size())
        return;
    if (depth > kTarRenderDepthCap) {
        out += "<div class=\"tar-tree-leaf tar-tree-mute\">\xE2\x80\xA6 (depth capped)</div>";
        return;
    }
    const TarProcNode& n = tree.nodes[id];
    if (n.children.empty()) {
        out += "<div class=\"tar-tree-leaf\">" + node_summary_row(tree, id, token, conn_index) +
               "</div>";
        return;
    }
    // Expand the first two levels by default; deeper branches start collapsed.
    out += depth < 2 ? "<details open class=\"tar-tree-node\">" : "<details class=\"tar-tree-node\">";
    out += "<summary>" + node_summary_row(tree, id, token, conn_index) + "</summary>";
    out += "<div class=\"tar-tree-children\">";
    render_children(tree, n.children, depth + 1, token, conn_index, out);
    out += "</div></details>";
}

} // namespace

std::string render_tar_tree_fragment(const TarProcTree& tree, const std::vector<TarTcpConn>& conns,
                                     const std::string& device_id, const std::string& token,
                                     const std::string& os) {
    (void)device_id;
    // Index connections by owning pid for the inline per-node net summary.
    ConnIndex conn_index;
    for (const auto& c : conns)
        conn_index[c.pid].push_back(&c);

    std::string h;
    // Honesty banner.
    h += "<div class=\"tar-tree-banner\">";
    h += "Window <b>" + html_escape(format_iso_utc(tree.from_ts)) + "</b> \xE2\x86\x92 <b>" +
         html_escape(format_iso_utc(tree.to_ts)) + "</b>";
    h += " &middot; observed since " + html_escape(format_iso_utc(tree.anchors.observed_since));
    h += " &middot; " + std::to_string(tree.running_count + tree.exited_count) + " nodes (" +
         std::to_string(tree.running_count) + " running / " + std::to_string(tree.exited_count) +
         " exited)";
    h += " &middot; " + std::to_string(tree.anomaly_count) + " flagged";
    h += "</div>";
    h += "<div class=\"tar-tree-note\">Reconstructed from this host's local TAR database "
         "(<code>$Process_Live</code>) only \xE2\x80\x94 no seed. Processes whose start event aged "
         "out of the live cap, or that started before the oldest retained row, may not appear. "
         "&ldquo;On boot&rdquo;/&ldquo;On agent install&rdquo; anchors are TAR-derived proxies.";
    if (os_is_windows(os))
        h += " On Windows the process feeder is ETW (names-only): per-process path and command "
             "line are not captured.";
    h += "</div>";

    if (tree.truncated)
        h += "<div class=\"tar-tree-warn\">Tree exceeds the render limit (" +
             std::to_string(kTarTreeMaxNodes) +
             " nodes) \xE2\x80\x94 showing the most recent. Narrow the timescale.</div>";

    if (tree.depth_capped)
        h += "<div class=\"tar-tree-warn\">Some branches are deeper than the display limit (" +
             std::to_string(kTarRenderDepthCap) +
             " levels) and are collapsed with \xE2\x80\x9C\xE2\x80\xA6 (depth capped)\xE2\x80\x9D. "
             "The node counts above include those hidden descendants.</div>";

    if (tree.roots.empty()) {
        h += "<div class=\"tar-tree-empty\">No processes reconstructable for this window. Widen "
             "the timescale, or the host may have no retained process events.</div>";
        return h;
    }

    // Empty-filter hint (shown by the client-side filters when nothing matches).
    h += "<div class=\"tar-tree-nomatch\" style=\"display:none\">No processes match the current "
         "filters.</div>";
    h += "<div class=\"tar-tree\">";
    std::string body;
    render_children(tree, tree.roots, 0, token, conn_index, body);
    h += body;
    h += "</div>";
    return h;
}

std::string render_tar_proc_detail(const TarProcNode& node, const std::vector<TarTcpConn>& conns,
                                   const std::string& os) {
    const bool win = os_is_windows(os);
    std::string h;
    h += "<div class=\"tar-detail\">";
    h += "<div class=\"tar-detail-title\">" +
         html_escape(node.name.empty() ? "(unknown)" : node.name) + " <span class=\"tar-tree-pid\">pid " +
         std::to_string(node.pid) + "</span></div>";

    auto kv = [&](const std::string& k, const std::string& v, bool mono = false) {
        h += "<div class=\"tar-kv\"><span class=\"tar-kv-k\">" + html_escape(k) + "</span>";
        h += mono ? "<code class=\"tar-kv-v\">" : "<span class=\"tar-kv-v\">";
        h += html_escape(v);
        h += mono ? "</code></div>" : "</span></div>";
    };

    kv("PID", std::to_string(node.pid));
    kv("Parent PID", std::to_string(node.ppid));
    if (!node.user.empty())
        kv("User", node.user);
    kv("State", node.running ? "running" : ("exited " + format_iso_utc(node.exited_ts)));
    kv("Started", node.start_known ? format_iso_utc(node.started_ts)
                                    : std::string("before observation (start event not retained)"));

    // Path + command line — TAR-only. Windows ETW is names-only (no path/cmdline).
    if (win) {
        h += "<div class=\"tar-kv\"><span class=\"tar-kv-k\">Path</span>"
             "<span class=\"tar-kv-v tar-tree-mute\">\xE2\x80\x94 names-only on Windows (ETW "
             "feeder)</span></div>";
        h += "<div class=\"tar-kv\"><span class=\"tar-kv-k\">Command line</span>"
             "<span class=\"tar-kv-v tar-tree-mute\">\xE2\x80\x94 names-only on Windows (ETW "
             "feeder)</span></div>";
    } else {
        kv("Path / command line",
           node.cmdline.empty() ? std::string("\xE2\x80\x94 (not captured)") : node.cmdline, true);
    }

    if (node.anomaly) {
        h += "<div class=\"tar-detail-anom\"><span class=\"tar-badge tar-badge-anom\">\xE2\x9A\xA0 "
             "anomaly</span> " +
             html_escape(node.anomaly_evidence) + "</div>";
    }

    // Connections owned by this pid (from $TCP_Live, joined by pid). Most recent first.
    h += "<div class=\"tar-detail-section\">Connections</div>";
    if (conns.empty()) {
        h += "<div class=\"tar-tree-mute\">No TCP connections recorded for this PID in the "
             "window.</div>";
    } else {
        h += "<table class=\"tar-detail-conns\"><thead><tr><th>Proto</th><th>Local</th>"
             "<th>Remote</th><th>State</th><th>When</th></tr></thead><tbody>";
        std::size_t shown = 0;
        for (const auto& c : conns) {
            if (shown++ >= 100)
                break;
            h += "<tr><td>" + html_escape(c.proto) + "</td>";
            h += "<td>:" + std::to_string(c.local_port) + "</td>";
            h += "<td>" + html_escape(c.remote_addr) + ":" + std::to_string(c.remote_port) + "</td>";
            h += "<td>" + html_escape(c.state) + "</td>";
            h += "<td title=\"" + html_escape(format_iso_utc(c.ts)) + "\">" +
                 html_escape(c.action.empty() ? std::string("\xE2\x80\x94") : c.action) + "</td></tr>";
        }
        h += "</tbody></table>";
    }
    h += "</div>";
    return h;
}

// ── Device DNS/ARP panels (ADR-0015) — device-level, NOT per process ──────────

std::string render_tar_dns_panel(const std::vector<TarDnsCacheEntry>& rows) {
    // Reduce the appeared/removed event stream (rows assumed newest-first) to the
    // current cache: newest row per (name, record_type, data) wins; a binding whose
    // newest action is `removed` is omitted.
    std::unordered_set<std::string> seen;
    std::vector<const TarDnsCacheEntry*> cur;
    for (const auto& r : rows) {
        std::string key = r.name + "\x1f" + r.record_type + "\x1f" + r.data;
        if (!seen.insert(key).second)
            continue;
        if (r.action == "removed")
            continue;
        cur.push_back(&r);
    }
    std::string h = "<details class=\"devnet-panel\" open>";
    h += "<summary><span><span class=\"devnet-title-ico\">&#9783;</span>DNS cache (device)</span>"
         "<span class=\"devnet-count\">" +
         std::to_string(cur.size()) + "</span></summary>";
    if (cur.empty()) {
        h += "<div class=\"devnet-empty\">No DNS cache entries &mdash; the <code>dns</code> source "
             "may be disabled on this device.</div>";
    } else {
        h += "<div class=\"devnet-body\"><table class=\"devnet-table\"><thead><tr><th>Name</th>"
             "<th>Type</th><th>Data</th><th>TTL</th><th>Src</th></tr></thead><tbody>";
        std::size_t shown = 0;
        for (const auto* r : cur) {
            if (shown++ >= 500)
                break;
            h += "<tr><td>" + html_escape(r->name) + "</td>";
            h += "<td class=\"dn-type\">" + html_escape(r->record_type) + "</td>";
            h += "<td class=\"dn-data\">" + html_escape(r->data) + "</td>";
            h += "<td class=\"dn-ttl\">" +
                 (r->ttl_remaining_s < 0 ? std::string("\xE2\x80\x94")
                                         : std::to_string(r->ttl_remaining_s)) +
                 "</td>";
            h += "<td class=\"dn-src\">" + html_escape(r->source) + "</td></tr>";
        }
        h += "</tbody></table></div>";
    }
    h += "<div class=\"devnet-caveat\">Device resolver-cache state &mdash; <strong>not</strong> "
         "per-process (the cache carries no PID).</div></details>";
    return h;
}

std::string render_tar_arp_panel(const std::vector<TarArpEntry>& rows) {
    std::unordered_set<std::string> seen;
    std::vector<const TarArpEntry*> cur;
    for (const auto& r : rows) {
        std::string key = r.iface + "\x1f" + r.ip_address + "\x1f" + r.mac_address;
        if (!seen.insert(key).second)
            continue;
        if (r.action == "removed")
            continue;
        cur.push_back(&r);
    }
    std::string h = "<details class=\"devnet-panel\" open>";
    h += "<summary><span><span class=\"devnet-title-ico\">&#9783;</span>ARP table (device)</span>"
         "<span class=\"devnet-count\">" +
         std::to_string(cur.size()) + "</span></summary>";
    if (cur.empty()) {
        h += "<div class=\"devnet-empty\">No ARP entries &mdash; the <code>arp</code> source may be "
             "disabled on this device.</div>";
    } else {
        h += "<div class=\"devnet-body\"><table class=\"devnet-table\"><thead><tr><th>Interface</th>"
             "<th>IP address</th><th>MAC</th><th>Type</th></tr></thead><tbody>";
        std::size_t shown = 0;
        for (const auto* r : cur) {
            if (shown++ >= 500)
                break;
            // static → muted; dynamic → accent; incomplete/other/unknown → a distinct
            // "other" class so an unresolved (no-MAC) neighbour is not coloured as a
            // healthy dynamic entry (consistency S2).
            std::string tclass = "arp-type-dynamic";
            if (r->entry_type == "static")
                tclass = "arp-type-static";
            else if (r->entry_type != "dynamic")
                tclass = "arp-type-other";
            h += "<tr><td>" + html_escape(r->iface) + "</td>";
            h += "<td>" + html_escape(r->ip_address) + "</td>";
            h += "<td class=\"arp-mac\">" + html_escape(r->mac_address) + "</td>";
            h += "<td class=\"" + tclass + "\">" + html_escape(r->entry_type) + "</td></tr>";
        }
        h += "</tbody></table></div>";
    }
    h += "<div class=\"devnet-caveat\">Layer-2 adjacency for spoofing / poisoning checks.</div>"
         "</details>";
    return h;
}

// ── Capture-sources frame (ADR-0015) ─────────────────────────────────────────

std::string render_tar_capture_sources(const std::string& device, const std::string& status_output,
                                       const std::string& compat_output) {
    auto each_line = [](const std::string& s, auto&& fn) {
        std::size_t pos = 0;
        while (pos < s.size()) {
            const auto nl = s.find('\n', pos);
            std::string line = s.substr(pos, (nl == std::string::npos ? s.size() : nl) - pos);
            pos = (nl == std::string::npos) ? s.size() : nl + 1;
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            fn(line);
        }
    };

    // status: config|<key>|<value>
    std::unordered_map<std::string, std::string> cfg;
    each_line(status_output, [&](const std::string& line) {
        const auto c = split_pipe(line);
        if (c.size() >= 3 && c[0] == "config")
            cfg[c[1]] = c[2];
    });
    // compatibility: row|<src>|<os>|<status>|<method>|<notes>
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> osmap;
    each_line(compat_output, [&](const std::string& line) {
        const auto c = split_pipe(line);
        if (c.size() >= 4 && c[0] == "row")
            osmap[c[1]][c[2]] = c[3];
    });

    struct Meta {
        const char* name;
        const char* dollar;
        const char* category;
        bool always_on;
        bool is_new;
        bool pii;
    };
    // Presentation metadata (the agent's schema registry is not linked here).
    // Category follows docs/user-manual/tar.md's five categories. always_on = the
    // default-enabled core sources (locked here; forensic-pause uses the configure
    // path). is_new/pii drive the badges.
    static const std::array<Meta, 10> kSources = {{
        {"process", "$Process", "Processes", true, false, false},
        {"tcp", "$TCP", "Network connections", true, false, false},
        {"service", "$Service", "Services", true, false, false},
        {"user", "$User", "User sessions", true, false, false},
        {"perf", "$Perf", "Performance", true, false, false},
        {"procperf", "$ProcPerf", "Performance", false, false, false},
        {"netqual", "$NetQual", "Network connections", false, false, false},
        {"module", "$Module", "Processes", false, false, false},
        {"arp", "$ARP", "Network connections", false, true, false},
        {"dns", "$DNS", "Network connections", false, true, true},
    }};

    auto os_cell = [&](const std::string& src, const char* os) -> std::string {
        auto s = osmap.find(src);
        std::string st = (s != osmap.end() && s->second.count(os)) ? s->second.at(os) : "";
        std::string cls = st == "supported" ? "os-ok" : (st == "constrained" ? "os-con" : "os-planned");
        if (st.empty()) {
            st = "\xE2\x80\x94";
            cls = "os-planned";
        }
        return "<td class=\"os-cell " + cls + "\">" + html_escape(st) + "</td>";
    };

    std::string h = "<div class=\"cat-filter\" id=\"capFilter\"><span class=\"filter-label\">"
                    "Category</span><a class=\"tar-chip on\" onclick=\"filterCap(this,'all')\">All</a>";
    static const std::array<std::pair<const char*, const char*>, 5> kChips = {
        {{"Processes", "Processes"},
         {"Network connections", "Network"},
         {"Services", "Services"},
         {"User sessions", "User sessions"},
         {"Performance", "Performance"}}};
    for (const auto& [cat, label] : kChips)
        h += std::string("<a class=\"tar-chip\" onclick=\"filterCap(this,'") + cat + "')\">" + label +
             "</a>";
    h += "</div>";

    h += "<table id=\"capTable\" data-device=\"" + html_escape(device) +
         "\"><thead><tr><th>Source</th><th>Category</th><th>Table</th><th>State</th>"
         "<th>Live rows</th><th>Windows</th><th>Linux</th><th>macOS</th></tr></thead><tbody>";

    int rendered = 0;
    for (const auto& m : kSources) {
        const std::string en_key = std::string(m.name) + "_enabled";
        if (!cfg.count(en_key))
            continue; // not reported by this agent — skip
        ++rendered;
        const bool enabled = cfg.at(en_key) != "false";
        const std::string rows_key = std::string(m.name) + "_live_rows";
        const std::string rows = cfg.count(rows_key) ? cfg.at(rows_key) : "0";

        h += "<tr data-cat=\"" + std::string(m.category) + "\"><td><span class=\"src-name\">" +
             std::string(m.name) + "</span>";
        if (m.is_new)
            h += " <span class=\"badge badge-new\">NEW</span>";
        if (m.pii)
            h += " <span class=\"badge badge-pii\">PII</span>";
        h += "</td><td class=\"cat\">" + std::string(m.category) + "</td><td class=\"src-dollar\">" +
             std::string(m.dollar) + "</td><td><div class=\"state-cell\">";
        if (m.always_on) {
            h += "<label class=\"tgl locked\"><input type=\"checkbox\" checked disabled>"
                 "<span class=\"sl\"></span></label><span class=\"state-txt state-on\">always on</span>";
        } else {
            h += "<label class=\"tgl\"><input type=\"checkbox\" data-source=\"" + std::string(m.name) +
                 "\" data-committed=\"" + (enabled ? "true" : "false") + "\"" +
                 (enabled ? " checked" : "") +
                 " onchange=\"stageCapToggle(this)\"><span class=\"sl\"></span></label>"
                 "<span class=\"state-txt" +
                 std::string(enabled ? " state-on" : "") + "\">" + (enabled ? "enabled" : "disabled") +
                 "</span>";
        }
        h += "</div></td><td><span class=\"badge badge-rows\">" + html_escape(rows) + "</span></td>";
        h += os_cell(m.name, "windows");
        h += os_cell(m.name, "linux");
        h += os_cell(m.name, "macos");
        h += "</tr>";
    }
    h += "</tbody></table>";
    if (rendered == 0)
        return "<div class=\"devnet-empty\">No capture sources reported by this device.</div>";
    h += "<div class=\"apply-bar\" id=\"capApplyBar\" hidden><span class=\"apply-icon\">&#9888;</span>"
         "<span id=\"capApplyMsg\">0 pending changes</span><span class=\"apply-spacer\"></span>"
         "<button class=\"btn-secondary\" onclick=\"discardCapChanges()\">Discard</button>"
         "<button class=\"apply-push\" onclick=\"pushCapChanges()\">Push changes &#8594;</button></div>";
    return h;
}

} // namespace yuzu::server
