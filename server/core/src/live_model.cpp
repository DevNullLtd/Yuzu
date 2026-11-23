/// @file live_model.cpp
/// PURE live-read model: the kind table and the plugin-output parsers. See live_model.hpp.

#include "live_model.hpp"

#include "result_parsing.hpp" // split_all_pipes (escape-aware split, #7040); header-only and pure

#include <algorithm>
#include <cctype>
#include <unordered_map>
#include <utility>

namespace yuzu::server::live {

namespace {

struct KindEntry {
    const char* token; ///< the allowlist token callers send as `kind`
    LiveKind kind;
};

// The ONE kind table. Order is the dashboard's historical order. Only `uptime` and
// `processes` carry rest_v1 = true: that is the whole REST subset.
const std::vector<KindEntry>& kind_table() {
    static const std::vector<KindEntry> kTable = [] {
        std::vector<KindEntry> t;
        const auto add = [&t](const char* token, LiveKind k) {
            t.push_back(KindEntry{token, std::move(k)});
        };
        LiveKind uptime{"os_info", "uptime", "Uptime", "device.live.uptime"};
        uptime.rest_v1 = true;
        add("uptime", std::move(uptime));
        LiveKind processes{"processes", "list_hashed", "Running processes",
                           "device.live.processes"};
        processes.rest_v1 = true;
        add("processes", std::move(processes));
        // tree + hash; joins live connections by pid (Windows)
        add("process_tree", LiveKind{"processes", "list_tree", "Processes",
                                     "device.live.process_tree", "network_diag", "connections"});
        add("services", LiveKind{"services", "list", "Services", "device.live.services"});
        add("users", LiveKind{"users", "logged_on", "Logged-in users", "device.live.users"});
        add("netconfig", LiveKind{"network_config", "ip_addresses", "Adapters & IP",
                                  "device.live.netconfig"});
        add("arp", LiveKind{"network_config", "arp", "ARP", "device.live.arp"});
        add("dns_cache",
            LiveKind{"network_config", "dns_cache", "DNS cache", "device.live.dns_cache"});
        add("listening", LiveKind{"network_diag", "listening", "Listening ports",
                                  "device.live.listening"});
        add("connections", LiveKind{"network_diag", "connections", "Active connections",
                                    "device.live.connections"});
        add("capture_sources",
            LiveKind{"echo", "status", "Capture sources", "device.live.capture_sources"});
        add("disk", LiveKind{"disk_space", "free", "Disk space", "device.live.disk"});

        // Physical-kit panels. Ten cards surfacing physical-hardware detail, reusing plugin
        // actions that already exist on the agent. Each emits flat
        // `<row_prefix>|field1|field2|...` lines (see the per-kind plugin doc); the generic
        // pipe-row path (parse_generic_rows + render_device_live_generic) drives all ten
        // off the `columns` list rather than a bespoke parser per kind. plugin2/action2 are
        // empty: these kinds have no secondary joined dispatch.
        add("hw_disks", LiveKind{"hardware", "disks", "Disks", "device.live.hw_disks", "", "",
                                 "disk", {"index", "model", "size_gb", "media_type", "interface"}});
        // The hardware plugin's cpu and dimm rows write a literal pipe in firmware text as `\|`
        // and fold a backslash to `/` (#7040), so exactly these two kinds declare `escaped_rows`.
        // Every other kind keeps the raw split: its action writes raw text (the hardware disk and
        // driver rows, a Windows mount point ending in a backslash) and an escape-aware split
        // would let a trailing backslash swallow the next separator.
        LiveKind hw_memory{"hardware", "memory", "Memory", "device.live.hw_memory", "", "",
                           "dimm", {"slot", "size_mb", "type", "speed_mhz"}};
        hw_memory.escaped_rows = true;
        add("hw_memory", std::move(hw_memory));
        LiveKind hw_processors{"hardware", "processors", "Processors", "device.live.hw_processors",
                               "", "", "cpu", {"index", "model", "cores", "threads", "clock_mhz"}};
        hw_processors.escaped_rows = true;
        add("hw_processors", std::move(hw_processors));
        add("hw_drivers",
            LiveKind{"hardware", "drivers", "Drivers", "device.live.hw_drivers", "", "", "driver",
                     {"index", "name", "version", "date", "provider", "device_class"}});
        add("battery",
            LiveKind{"power_health", "battery", "Battery", "device.live.battery", "", "",
                     "battery",
                     {"present", "state", "percent", "time_to_empty_min", "cycle_count",
                      "health_percent"}});
        add("thermal", LiveKind{"power_health", "thermal", "Thermal", "device.live.thermal", "", "",
                                "thermal", {"status", "zone_or_detail", "celsius"}});
        add("smart",
            LiveKind{"disk_actions", "smart", "Disk health (SMART)", "device.live.smart", "", "",
                     "smart",
                     {"device", "model", "bus", "media", "health", "pct_used", "spare_pct",
                      "detail"}});
        add("volumes",
            LiveKind{"disk_actions", "volumes", "Volumes", "device.live.volumes", "", "", "volume",
                     {"volume", "mount_points", "device", "fstype", "total_bytes", "detail"}});
        add("adapters", LiveKind{"network_config", "adapters", "Network adapters",
                                 "device.live.adapters", "", "", "adapter",
                                 {"name", "mac", "speed_mbps", "status"}});
        add("wifi", LiveKind{"wifi", "connected", "Wi-Fi", "device.live.wifi", "", "", "connected",
                             {"ssid", "signal", "security", "bssid", "interface_or_channel"}});
        return t;
    }();
    return kTable;
}

std::string to_lower(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

} // namespace

std::optional<LiveKind> resolve_dashboard_kind(const std::string& kind) {
    for (const auto& e : kind_table())
        if (kind == e.token)
            return e.kind;
    return std::nullopt;
}

std::optional<LiveKind> resolve_rest_kind(const std::string& kind) {
    for (const auto& e : kind_table())
        if (kind == e.token)
            return e.kind.rest_v1 ? std::optional<LiveKind>(e.kind) : std::nullopt;
    return std::nullopt;
}

std::vector<std::string> split_lines(const std::string& output) {
    std::vector<std::string> lines;
    std::size_t pos = 0;
    while (pos < output.size()) {
        const auto nl = output.find('\n', pos);
        std::string line =
            output.substr(pos, (nl == std::string::npos ? output.size() : nl) - pos);
        pos = (nl == std::string::npos) ? output.size() : nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            lines.push_back(std::move(line));
    }
    return lines;
}

std::vector<std::string> pipe_fields(const std::string& line) {
    std::vector<std::string> f;
    std::size_t p = 0;
    while (true) {
        const auto q = line.find('|', p);
        f.push_back(line.substr(p, q == std::string::npos ? std::string::npos : q - p));
        if (q == std::string::npos)
            break;
        p = q + 1;
    }
    return f;
}

std::vector<ProcRow> parse_processes(const std::string& output) {
    std::vector<ProcRow> procs;
    for (const auto& l : split_lines(output)) {
        if (l.rfind("proc|", 0) != 0)
            continue;
        const auto a = l.find('|');        // after "proc"
        const auto b = l.find('|', a + 1); // after pid
        if (b == std::string::npos)
            continue;
        const auto c = l.find('|', b + 1); // after name
        ProcRow p;
        try {
            p.pid = std::stoll(l.substr(a + 1, b - a - 1));
        } catch (...) {
            p.pid = 0;
        }
        if (c == std::string::npos) {
            p.name = l.substr(b + 1);
        } else {
            p.name = l.substr(b + 1, c - b - 1);
            const auto e = l.find('|', c + 1); // after sha256 (path may contain none)
            if (e == std::string::npos) {
                p.sha256 = l.substr(c + 1);
            } else {
                p.sha256 = l.substr(c + 1, e - c - 1);
                p.path = l.substr(e + 1);
            }
        }
        procs.push_back(std::move(p));
    }
    return procs;
}

Uptime parse_uptime(const std::string& output) {
    Uptime u;
    for (const auto& l : split_lines(output)) {
        const auto bar = l.find('|');
        if (bar == std::string::npos)
            continue;
        const auto k = l.substr(0, bar);
        const auto v = l.substr(bar + 1);
        if (k == "uptime_display") {
            u.display = v;
        } else if (k == "uptime_seconds") {
            try {
                u.seconds = static_cast<std::int64_t>(std::stoll(v));
            } catch (...) {
            }
        }
    }
    return u;
}

std::vector<LiveProcNode> parse_process_tree(const std::string& output) {
    std::vector<LiveProcNode> nodes;
    for (const auto& l : split_lines(output)) {
        if (!l.starts_with("proc|"))
            continue;
        auto f = pipe_fields(l);
        if (f.size() < 4)
            continue;
        LiveProcNode n;
        // Guard the 64-bit-unsigned-long -> uint32 narrowing: a forged pid/ppid above
        // UINT32_MAX would otherwise truncate (e.g. 2^32 -> 0) and collide with the
        // "ppid==0 => root" sentinel, corrupting parent->child attribution.
        try {
            unsigned long v = std::stoul(f[1]);
            if (v > 0xFFFFFFFFUL)
                continue;
            n.pid = static_cast<std::uint32_t>(v);
        } catch (...) {
            continue;
        }
        try {
            unsigned long v = std::stoul(f[2]);
            n.ppid = (v > 0xFFFFFFFFUL) ? 0u : static_cast<std::uint32_t>(v);
        } catch (...) {
            n.ppid = 0;
        }
        n.name = f[3];
        if (f.size() > 4)
            n.sha256 = f[4];
        if (f.size() > 5)
            n.path = f[5];
        nodes.push_back(std::move(n));
        if (nodes.size() >= kMaxLiveRows)
            break;
    }
    return nodes;
}

std::vector<LiveConn> parse_process_conns(const std::string& output) {
    std::vector<LiveConn> conns;
    for (const auto& l : split_lines(output)) {
        if (!l.starts_with("conn|"))
            continue; // conn|tcp|lip|lport|rip|rport|pid (Windows)
        auto f = pipe_fields(l);
        if (f.size() < 7)
            continue;
        LiveConn c;
        // Guard the uint32 narrowing exactly as the node-pid parse: a forged pid >
        // UINT32_MAX must not silently truncate (on LP64 std::stoul would not throw), so
        // the join key cannot collide via truncation.
        try {
            unsigned long v = std::stoul(f[6]);
            if (v > 0xFFFFFFFFUL)
                continue;
            c.pid = static_cast<std::uint32_t>(v);
        } catch (...) {
            continue;
        }
        c.remote_addr = f[4];
        try {
            c.remote_port = std::stoi(f[5]);
        } catch (...) {
        }
        try {
            c.local_port = std::stoi(f[3]);
        } catch (...) {
        }
        conns.push_back(std::move(c));
        if (conns.size() >= kMaxLiveRows)
            break;
    }
    return conns;
}

LiveServices parse_services(const std::string& output, const std::string& agent_os) {
    // The agent's own OS (authoritative, from the device record) disambiguates same-arity
    // service-row shapes (K-4): "darwin"/"macos" selects macOS. Empty when the lookup was
    // unavailable, in which case the 4-field branch falls back to content-sniffing the
    // pid column.
    const std::string os_lc = to_lower(agent_os);
    const bool os_is_macos = os_lc == "darwin" || os_lc == "macos";
    const bool os_known = !os_lc.empty();

    LiveServices out;
    for (const auto& l : split_lines(output)) {
        if (!l.starts_with("svc|"))
            continue;
        auto f = pipe_fields(l);
        LiveService s;
        if (f.size() >= 5) {
            // Two distinct 5-field shapes share this arity: Windows
            // svc|name|display|status|startup and macOS (C-1.12, P10 fix)
            // svc|label|pid|status|startup. Prefer the agent's authoritative OS (K-4) so a
            // Windows service whose display name is all digits (or "-") is never misread
            // as a macOS PID. When the OS is unknown (device record unavailable, rare and
            // transient), default to Windows rather than content-sniffing the pid column
            // (UP-5): a 5-field row with a display name is historically the Windows shape,
            // and the sniff is exactly what dropped a numeric Windows display name in the
            // K-4 bug.
            const bool macos = os_known ? os_is_macos : false;
            s.name = f[1];
            if (macos) {
                s.status = f[3];
                s.startup = f[4]; // svc|label|pid|status|startup
            } else {
                s.display = f[2];
                s.status = f[3];
                s.startup = f[4]; // svc|name|display|status|startup
            }
        } else if (f.size() == 4) {
            // Two distinct 4-field shapes share this arity: Linux svc|name|status|description
            // and macOS svc|label|pid|status. Prefer the agent's authoritative OS (K-4); fall
            // back to sniffing the pid column when unknown, so the macOS State cell shows the
            // status, not the PID (consistency B1). A stopped launchd service reports pid
            // "-", not a number, so the sentinel counts as macOS in the fallback.
            s.name = f[1];
            const bool macos =
                os_known ? os_is_macos
                         : (f[2] == "-" ||
                            (!f[2].empty() && std::all_of(f[2].begin(), f[2].end(),
                                                          [](unsigned char ch) {
                                                              return std::isdigit(ch) != 0;
                                                          })));
            if (macos) {
                s.status = f[3]; // svc|label|pid|status
            } else {
                s.status = f[2];
                s.display = f[3]; // svc|name|status|description
            }
        } else {
            continue;
        }
        std::string st = s.status;
        for (char& c : st)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (st.find("run") != std::string::npos)
            ++out.running;
        out.rows.push_back(std::move(s));
        if (out.rows.size() >= kMaxLiveRows)
            break;
    }
    return out;
}

std::vector<LiveUserRow> parse_users(const std::string& output) {
    std::vector<LiveUserRow> rows; // user|user|host|logon_type|tty
    for (const auto& l : split_lines(output)) {
        if (!l.starts_with("user|"))
            continue;
        auto f = pipe_fields(l);
        if (f.size() < 2)
            continue;
        LiveUserRow u;
        u.user = f[1];
        if (f.size() > 2)
            u.host = f[2];
        if (f.size() > 3)
            u.logon_type = f[3];
        if (f.size() > 4)
            u.session = f[4];
        rows.push_back(std::move(u));
        if (rows.size() >= kMaxLiveRows)
            break;
    }
    return rows;
}

std::vector<LiveNetAddr> parse_netconfig(const std::string& output) {
    std::vector<LiveNetAddr> rows; // ip|adapter|addr|prefix|gateway
    for (const auto& l : split_lines(output)) {
        if (!l.starts_with("ip|"))
            continue;
        auto f = pipe_fields(l);
        if (f.size() < 3)
            continue;
        LiveNetAddr a;
        a.adapter = f[1];
        a.ip = f[2];
        if (f.size() > 3) {
            try {
                a.prefix = std::stoi(f[3]);
            } catch (...) {
            }
        }
        if (f.size() > 4 && f[4] != "-" && f[4] != "0.0.0.0")
            a.gateway = f[4];
        rows.push_back(std::move(a));
        if (rows.size() >= kMaxLiveRows)
            break;
    }
    return rows;
}

std::vector<LiveArpEntry> parse_arp(const std::string& output) {
    std::vector<LiveArpEntry> rows; // arp|iface|ip|mac|type
    for (const auto& l : split_lines(output)) {
        if (!l.starts_with("arp|"))
            continue;
        auto f = pipe_fields(l);
        if (f.size() < 5)
            continue;
        LiveArpEntry a{f[1], f[2], (f[3] == "-" ? "" : f[3]), f[4]};
        rows.push_back(std::move(a));
        if (rows.size() >= kMaxLiveRows)
            break;
    }
    return rows;
}

std::vector<LiveDnsEntry> parse_dns_cache(const std::string& output) {
    std::vector<LiveDnsEntry> rows; // cache_entry|name|type|...
    for (const auto& l : split_lines(output)) {
        if (!l.starts_with("cache_entry|"))
            continue;
        auto f = pipe_fields(l);
        if (f.size() < 3 || f[1] == "not_available")
            continue;
        rows.push_back(LiveDnsEntry{f[1], f[2]});
        if (rows.size() >= kMaxLiveRows)
            break;
    }
    return rows;
}

std::vector<LiveListen> parse_listening(const std::string& output) {
    std::vector<LiveListen> rows; // listen|tcp|ip|port|pid
    for (const auto& l : split_lines(output)) {
        if (!l.starts_with("listen|"))
            continue;
        auto f = pipe_fields(l);
        if (f.size() < 4)
            continue;
        LiveListen s;
        s.proto = f[1];
        s.ip = f[2];
        try {
            s.port = std::stoi(f[3]);
        } catch (...) {
        }
        if (f.size() > 4) {
            try {
                s.pid = std::stoll(f[4]);
            } catch (...) {
            }
        }
        rows.push_back(std::move(s));
        if (rows.size() >= kMaxLiveRows)
            break;
    }
    return rows;
}

std::vector<LiveConnRow> parse_connections(const std::string& output) {
    std::vector<LiveConnRow> rows; // conn|tcp|lip|lport|rip|rport|pid
    for (const auto& l : split_lines(output)) {
        if (!l.starts_with("conn|"))
            continue;
        auto f = pipe_fields(l);
        if (f.size() < 6)
            continue;
        LiveConnRow c;
        c.proto = f[1];
        c.local = f[2] + ":" + f[3];
        c.remote = f[4] + ":" + f[5];
        c.state = "ESTABLISHED"; // network_diag/connections emits established only
        rows.push_back(std::move(c));
        if (rows.size() >= kMaxLiveRows)
            break;
    }
    return rows;
}

LiveCaptureSources parse_capture_sources(const std::string& output) {
    // Display order + presentation metadata. The server does NOT link the agent's
    // echo_schema_registry, so source name/$-table/category are held here; a row is
    // returned only for a source the agent actually reported (its `<src>_enabled` key is
    // present in echo/status), so an older agent without arp/dns yields no phantom rows.
    // Hand-maintained: the os-capability-matrix "will drift; durable fix = generate from
    // machine-readable metadata" situation, tracked as a follow-up.
    struct Meta {
        const char* name;
        const char* dollar;
        const char* category;
    };
    static const Meta kSrc[] = {
        {"process", "Process", "Activity"},  {"tcp", "TCP", "Network"},
        {"service", "Service", "Inventory"}, {"user", "User", "Identity"},
        {"perf", "Perf", "Performance"},     {"procperf", "ProcPerf", "Performance"},
        {"netqual", "NetQual", "Network"},   {"module", "Module", "Inventory"},
        {"arp", "ARP", "Network"},           {"dns", "DNS", "Network"},
        {"registry", "Registry", "System"}};
    std::unordered_map<std::string, std::string> cfg;
    for (const auto& l : split_lines(output)) {
        if (!l.starts_with("config|"))
            continue;
        auto f = pipe_fields(l); // config|<key>|<value>
        if (f.size() >= 3)
            cfg[f[1]] = f[2];
    }
    LiveCaptureSources out;
    for (const auto& m : kSrc) {
        auto en = cfg.find(std::string(m.name) + "_enabled");
        if (en == cfg.end())
            continue; // agent did not report this source (older agent / not built)
        LiveCaptureSource s;
        s.name = m.name;
        s.dollar = m.dollar;
        s.category = m.category;
        s.enabled = (en->second == "true");
        // Row count: `<src>_rows` is the hourly count.
        auto rows_it = cfg.find(std::string(m.name) + "_rows");
        if (rows_it != cfg.end()) {
            try {
                s.live_rows = std::stoll(rows_it->second);
            } catch (...) {
            }
        }
        if (s.enabled)
            ++out.on;
        out.rows.push_back(std::move(s));
    }
    return out;
}

LiveDisks parse_disk(const std::string& output) {
    LiveDisks out; // disk|<path>|<total_bytes>|<free_bytes>|<percent_used>
    for (const auto& l : split_lines(output)) {
        if (!l.starts_with("disk|"))
            continue;
        auto f = pipe_fields(l);
        if (f.size() < 5)
            continue;
        LiveDiskVolume v;
        v.path = f[1];
        try {
            v.total = std::stoll(f[2]);
        } catch (...) {
        }
        try {
            v.free = std::stoll(f[3]);
        } catch (...) {
        }
        try {
            v.percent_used = std::stoi(f[4]);
        } catch (...) {
        }
        // Clamp the agent-supplied percent into range, and only let a MEASURED volume
        // (total > 0) drive the worst-used figure: a total of 0 (f_frsize==0 / a volume the
        // agent could not read) must not render as "100% free" off a forged or
        // indeterminate row.
        if (v.percent_used < 0)
            v.percent_used = 0;
        if (v.percent_used > 100)
            v.percent_used = 100;
        if (v.total > 0 && v.percent_used > out.worst_used)
            out.worst_used = v.percent_used;
        out.rows.push_back(std::move(v));
        if (out.rows.size() >= kMaxLiveRows)
            break;
    }
    return out;
}

LiveGenericRows parse_generic_rows(const LiveKind& kind, const std::string& output) {
    LiveGenericRows out;
    // A line under any OTHER prefix (e.g. a plugin-emitted "warning|..." or "error|..."
    // diagnostic alongside its data rows) is preserved verbatim as an honest raw/diagnostic
    // row rather than silently dropped. Two checks, both against kMaxLiveRows: a raw line is
    // kept only while rows + raw_rows is below it, while a data row is kept until rows alone
    // reaches it (then parsing stops). So the combined total is NOT held to one cap: raw lines
    // first, then data rows, can reach 2 x kMaxLiveRows (rows and raw_rows each at the cap).
    const std::string prefix = kind.row_prefix + "|";
    for (const auto& l : split_lines(output)) {
        if (!l.starts_with(prefix)) {
            if (out.rows.size() + out.raw_rows.size() < kMaxLiveRows)
                out.raw_rows.push_back(l);
            continue;
        }
        auto f = kind.escaped_rows ? split_all_pipes(l) : pipe_fields(l);
        if (f.empty())
            continue;
        f.erase(f.begin());             // drop the prefix token itself
        f.resize(kind.columns.size());  // pad short / trim long rows to the declared width
        out.rows.push_back(std::move(f));
        if (out.rows.size() >= kMaxLiveRows)
            break;
    }
    return out;
}

} // namespace yuzu::server::live
