/**
 * tar_diff.cpp -- Diff engine for TAR collectors
 *
 * Implements snapshot-based diff computation for processes, network connections,
 * services, and user sessions. Uses std::unordered_map with composite keys
 * to efficiently detect births, deaths, and state changes.
 *
 * Redaction: command-line strings matching sensitive patterns are replaced
 * with "[REDACTED by TAR]" before being stored in event detail JSON.
 */

#include "tar_collectors.hpp"

#include <algorithm>
#include <cctype>
#include <format>
#include <string>
#include <unordered_map>
#include <utility>

namespace yuzu::tar {

namespace {

/// Escape a string for safe embedding in JSON values.
/// Handles backslash, double-quote, and control characters.
std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                // Control character -- emit \u00XX
                out += std::format("\\u{:04x}", static_cast<unsigned>(static_cast<unsigned char>(c)));
            } else {
                out += c;
            }
            break;
        }
    }
    return out;
}

/// Case-insensitive substring search.
bool icontains(const std::string& haystack, const std::string& needle) {
    if (needle.empty())
        return true;
    if (needle.size() > haystack.size())
        return false;

    auto to_lower = [](char c) -> char {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    };

    auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                          [&](char a, char b) { return to_lower(a) == to_lower(b); });
    return it != haystack.end();
}

/// Strip leading/trailing '*' from a pattern to get the core substring. NOTE:
/// matching is case-insensitive SUBSTRING containment, NOT real glob — `?` and
/// `[abc]` are treated as literals; only leading/trailing `*` are honoured (as a
/// readability affordance), then stripped here before the substring search.
std::string strip_stars(const std::string& pattern) {
    std::string result = pattern;
    while (!result.empty() && result.front() == '*')
        result.erase(result.begin());
    while (!result.empty() && result.back() == '*')
        result.pop_back();
    return result;
}

} // namespace

// ── Redaction ────────────────────────────────────────────────────────────────

bool should_redact(const std::string& cmdline, const std::vector<std::string>& patterns) {
    if (cmdline.empty())
        return false;
    for (const auto& pattern : patterns) {
        auto core = strip_stars(pattern);
        if (!core.empty() && icontains(cmdline, core))
            return true;
    }
    return false;
}

std::string redact_cmdline(const std::string& cmdline, const std::vector<std::string>& patterns) {
    if (should_redact(cmdline, patterns))
        return "[REDACTED by TAR]";
    return cmdline;
}

// ── Process diff ─────────────────────────────────────────────────────────────

std::vector<TarEvent> compute_process_diff(
    const std::vector<yuzu::agent::ProcessInfo>& previous,
    const std::vector<yuzu::agent::ProcessInfo>& current,
    int64_t timestamp, int64_t snapshot_id,
    const std::vector<std::string>& redaction_patterns) {

    std::vector<TarEvent> events;

    // Build map of previous processes: PID -> (name, cmdline, user)
    // Using PID as key. If PID is reused with a different name, we treat it
    // as a death of the old process + birth of the new one.
    struct ProcState {
        std::string name;
        std::string cmdline;
        std::string user;
        uint32_t ppid;
    };

    std::unordered_map<uint32_t, ProcState> prev_map;
    prev_map.reserve(previous.size());
    for (const auto& p : previous) {
        prev_map[p.pid] = {p.name, p.cmdline, p.user, p.ppid};
    }

    std::unordered_map<uint32_t, ProcState> curr_map;
    curr_map.reserve(current.size());
    for (const auto& p : current) {
        curr_map[p.pid] = {p.name, p.cmdline, p.user, p.ppid};
    }

    // Detect births and PID reuse (birth + death)
    for (const auto& p : current) {
        auto it = prev_map.find(p.pid);
        if (it == prev_map.end()) {
            // New process -- birth
            auto safe_cmd = redact_cmdline(p.cmdline, redaction_patterns);
            TarEvent ev;
            ev.timestamp = timestamp;
            ev.event_type = "process";
            ev.event_action = "started";
            ev.detail_json = std::format(
                R"({{"pid":{},"ppid":{},"name":"{}","cmdline":"{}","user":"{}"}})",
                p.pid, p.ppid, json_escape(p.name), json_escape(safe_cmd),
                json_escape(p.user));
            ev.snapshot_id = snapshot_id;
            events.push_back(std::move(ev));
        } else if (it->second.name != p.name) {
            // PID reused with different process -- old process died, new one started
            auto old_cmd = redact_cmdline(it->second.cmdline, redaction_patterns);
            TarEvent death;
            // Death gets timestamp-1 so death always sorts before birth for PID reuse
            death.timestamp = timestamp - 1;
            death.event_type = "process";
            death.event_action = "stopped";
            death.detail_json = std::format(
                R"({{"pid":{},"ppid":{},"name":"{}","cmdline":"{}","user":"{}"}})",
                p.pid, it->second.ppid, json_escape(it->second.name),
                json_escape(old_cmd), json_escape(it->second.user));
            death.snapshot_id = snapshot_id;
            events.push_back(std::move(death));

            auto new_cmd = redact_cmdline(p.cmdline, redaction_patterns);
            TarEvent birth;
            birth.timestamp = timestamp;
            birth.event_type = "process";
            birth.event_action = "started";
            birth.detail_json = std::format(
                R"({{"pid":{},"ppid":{},"name":"{}","cmdline":"{}","user":"{}"}})",
                p.pid, p.ppid, json_escape(p.name), json_escape(new_cmd),
                json_escape(p.user));
            birth.snapshot_id = snapshot_id;
            events.push_back(std::move(birth));
        }
        // If same PID + same name -> still running, no event
    }

    // Detect deaths (in previous, not in current)
    for (const auto& p : previous) {
        if (!curr_map.contains(p.pid)) {
            auto safe_cmd = redact_cmdline(p.cmdline, redaction_patterns);
            TarEvent ev;
            ev.timestamp = timestamp;
            ev.event_type = "process";
            ev.event_action = "stopped";
            ev.detail_json = std::format(
                R"({{"pid":{},"ppid":{},"name":"{}","cmdline":"{}","user":"{}"}})",
                p.pid, p.ppid, json_escape(p.name), json_escape(safe_cmd),
                json_escape(p.user));
            ev.snapshot_id = snapshot_id;
            events.push_back(std::move(ev));
        }
    }

    return events;
}

// ── Network diff ─────────────────────────────────────────────────────────────

std::vector<TarEvent> compute_network_diff(
    const std::vector<NetConnection>& previous,
    const std::vector<NetConnection>& current,
    int64_t timestamp, int64_t snapshot_id) {

    std::vector<TarEvent> events;

    // Composite key: proto + local_addr + local_port + remote_addr + remote_port
    auto make_key = [](const NetConnection& c) -> std::string {
        return std::format("{}:{}:{}:{}:{}", c.proto, c.local_addr, c.local_port, c.remote_addr,
                           c.remote_port);
    };

    std::unordered_map<std::string, const NetConnection*> prev_map;
    prev_map.reserve(previous.size());
    for (const auto& c : previous) {
        prev_map[make_key(c)] = &c;
    }

    std::unordered_map<std::string, const NetConnection*> curr_map;
    curr_map.reserve(current.size());
    for (const auto& c : current) {
        curr_map[make_key(c)] = &c;
    }

    // New connections (births)
    for (const auto& c : current) {
        auto key = make_key(c);
        if (!prev_map.contains(key)) {
            TarEvent ev;
            ev.timestamp = timestamp;
            ev.event_type = "network";
            ev.event_action = "connected";
            ev.detail_json = std::format(
                R"({{"proto":"{}","local_addr":"{}","local_port":{},"remote_addr":"{}","remote_host":"{}","remote_port":{},"state":"{}","pid":{},"process_name":"{}"}})",
                json_escape(c.proto), json_escape(c.local_addr), c.local_port,
                json_escape(c.remote_addr), json_escape(c.remote_host), c.remote_port,
                json_escape(c.state), c.pid, json_escape(c.process_name));
            ev.snapshot_id = snapshot_id;
            events.push_back(std::move(ev));
        }
    }

    // Closed connections (deaths)
    for (const auto& c : previous) {
        auto key = make_key(c);
        if (!curr_map.contains(key)) {
            TarEvent ev;
            ev.timestamp = timestamp;
            ev.event_type = "network";
            ev.event_action = "disconnected";
            ev.detail_json = std::format(
                R"({{"proto":"{}","local_addr":"{}","local_port":{},"remote_addr":"{}","remote_host":"{}","remote_port":{},"state":"{}","pid":{},"process_name":"{}"}})",
                json_escape(c.proto), json_escape(c.local_addr), c.local_port,
                json_escape(c.remote_addr), json_escape(c.remote_host), c.remote_port,
                json_escape(c.state), c.pid, json_escape(c.process_name));
            ev.snapshot_id = snapshot_id;
            events.push_back(std::move(ev));
        }
    }

    return events;
}

// ── Service diff ─────────────────────────────────────────────────────────────

std::vector<TarEvent> compute_service_diff(
    const std::vector<ServiceInfo>& previous,
    const std::vector<ServiceInfo>& current,
    int64_t timestamp, int64_t snapshot_id) {

    std::vector<TarEvent> events;

    // Key: service name
    std::unordered_map<std::string, const ServiceInfo*> prev_map;
    prev_map.reserve(previous.size());
    for (const auto& s : previous) {
        prev_map[s.name] = &s;
    }

    std::unordered_map<std::string, const ServiceInfo*> curr_map;
    curr_map.reserve(current.size());
    for (const auto& s : current) {
        curr_map[s.name] = &s;
    }

    // New services or state changes
    for (const auto& s : current) {
        auto it = prev_map.find(s.name);
        if (it == prev_map.end()) {
            // New service -- birth
            TarEvent ev;
            ev.timestamp = timestamp;
            ev.event_type = "service";
            ev.event_action = "started";
            ev.detail_json = std::format(
                R"({{"name":"{}","display_name":"{}","status":"{}","startup_type":"{}"}})",
                json_escape(s.name), json_escape(s.display_name), json_escape(s.status),
                json_escape(s.startup_type));
            ev.snapshot_id = snapshot_id;
            events.push_back(std::move(ev));
        } else {
            // Check for state change (status or startup_type changed).
            // Finding 3 (adversarial-review round 5): a startup_type carried
            // on either side by a FAILED per-service query (Windows
            // OpenServiceW/QueryServiceConfigW; ServiceInfo::
            // startup_type_query_failed) is not an authoritative
            // observation -- it must never participate in this comparison,
            // or a transient query hiccup manufactures a false
            // "automatic -> unknown" event now and a false inverse event on
            // the next successful read.
            const auto* prev = it->second;
            const bool startup_type_changed = !prev->startup_type_query_failed &&
                                              !s.startup_type_query_failed &&
                                              prev->startup_type != s.startup_type;
            if (prev->status != s.status || startup_type_changed) {
                TarEvent ev;
                ev.timestamp = timestamp;
                ev.event_type = "service";
                ev.event_action = "state_changed";
                ev.detail_json = std::format(
                    R"({{"name":"{}","display_name":"{}","status":"{}","prev_status":"{}","startup_type":"{}","prev_startup_type":"{}"}})",
                    json_escape(s.name), json_escape(s.display_name), json_escape(s.status),
                    json_escape(prev->status), json_escape(s.startup_type),
                    json_escape(prev->startup_type));
                ev.snapshot_id = snapshot_id;
                events.push_back(std::move(ev));
            }
        }
    }

    // Removed services (deaths)
    for (const auto& s : previous) {
        if (!curr_map.contains(s.name)) {
            TarEvent ev;
            ev.timestamp = timestamp;
            ev.event_type = "service";
            ev.event_action = "stopped";
            ev.detail_json = std::format(
                R"({{"name":"{}","display_name":"{}","status":"{}","startup_type":"{}"}})",
                json_escape(s.name), json_escape(s.display_name), json_escape(s.status),
                json_escape(s.startup_type));
            ev.snapshot_id = snapshot_id;
            events.push_back(std::move(ev));
        }
    }

    return events;
}

// ── User session diff ────────────────────────────────────────────────────────

std::vector<TarEvent> compute_user_diff(
    const std::vector<UserSession>& previous,
    const std::vector<UserSession>& current,
    int64_t timestamp, int64_t snapshot_id) {

    std::vector<TarEvent> events;

    // Composite key: user + session_id
    auto make_key = [](const UserSession& u) -> std::string {
        return u.user + ":" + u.session_id;
    };

    std::unordered_map<std::string, const UserSession*> prev_map;
    prev_map.reserve(previous.size());
    for (const auto& u : previous) {
        prev_map[make_key(u)] = &u;
    }

    std::unordered_map<std::string, const UserSession*> curr_map;
    curr_map.reserve(current.size());
    for (const auto& u : current) {
        curr_map[make_key(u)] = &u;
    }

    // New sessions (logins)
    for (const auto& u : current) {
        auto key = make_key(u);
        if (!prev_map.contains(key)) {
            TarEvent ev;
            ev.timestamp = timestamp;
            ev.event_type = "user";
            ev.event_action = "login";
            ev.detail_json = std::format(
                R"({{"user":"{}","domain":"{}","logon_type":"{}","session_id":"{}"}})",
                json_escape(u.user), json_escape(u.domain), json_escape(u.logon_type),
                json_escape(u.session_id));
            ev.snapshot_id = snapshot_id;
            events.push_back(std::move(ev));
        }
    }

    // Ended sessions (logouts)
    for (const auto& u : previous) {
        auto key = make_key(u);
        if (!curr_map.contains(key)) {
            TarEvent ev;
            ev.timestamp = timestamp;
            ev.event_type = "user";
            ev.event_action = "logout";
            ev.detail_json = std::format(
                R"({{"user":"{}","domain":"{}","logon_type":"{}","session_id":"{}"}})",
                json_escape(u.user), json_escape(u.domain), json_escape(u.logon_type),
                json_escape(u.session_id));
            ev.snapshot_id = snapshot_id;
            events.push_back(std::move(ev));
        }
    }

    return events;
}

// ── Typed event production ──────────────────────────────────────────────────
// These parallel the legacy diff functions but produce typed event structs
// for direct insertion into the warehouse live tables.

std::vector<ProcessEvent> compute_process_events(
    const std::vector<yuzu::agent::ProcessInfo>& previous,
    const std::vector<yuzu::agent::ProcessInfo>& current,
    int64_t timestamp, int64_t snapshot_id,
    const std::vector<std::string>& redaction_patterns) {

    std::vector<ProcessEvent> events;

    // macOS TAR process capture is names-only — parity with the Endpoint Security
    // stream and the works-council / data-minimization posture. The sysctl poll's
    // proc_pidpath() would otherwise leak the full executable path into the cmdline
    // column, so blank it here. Windows process capture is already names-only via
    // ETW; Linux keeps the (redacted) command line. See docs/user-manual/tar.md.
    const auto cmd = [&](const std::string& c) -> std::string {
#if defined(__APPLE__)
        (void)c;
        (void)redaction_patterns;
        return {};
#else
        return redact_cmdline(c, redaction_patterns);
#endif
    };

    struct ProcState { std::string name; std::string cmdline; std::string user; uint32_t ppid; };
    std::unordered_map<uint32_t, ProcState> prev_map;
    prev_map.reserve(previous.size());
    for (const auto& p : previous)
        prev_map[p.pid] = {p.name, p.cmdline, p.user, p.ppid};

    std::unordered_map<uint32_t, ProcState> curr_map;
    curr_map.reserve(current.size());
    for (const auto& p : current)
        curr_map[p.pid] = {p.name, p.cmdline, p.user, p.ppid};

    for (const auto& p : current) {
        auto it = prev_map.find(p.pid);
        if (it == prev_map.end()) {
            events.push_back({timestamp, snapshot_id, "started", p.pid, p.ppid,
                              p.name, cmd(p.cmdline), p.user});
        } else if (it->second.name != p.name) {
            events.push_back({timestamp - 1, snapshot_id, "stopped", p.pid, it->second.ppid,
                              it->second.name, cmd(it->second.cmdline),
                              it->second.user});
            events.push_back({timestamp, snapshot_id, "started", p.pid, p.ppid,
                              p.name, cmd(p.cmdline), p.user});
        }
    }

    for (const auto& p : previous) {
        if (!curr_map.contains(p.pid)) {
            events.push_back({timestamp, snapshot_id, "stopped", p.pid, p.ppid,
                              p.name, cmd(p.cmdline), p.user});
        }
    }

    return events;
}

std::vector<NetworkEvent> compute_network_events(
    const std::vector<NetConnection>& previous,
    const std::vector<NetConnection>& current,
    int64_t timestamp, int64_t snapshot_id) {

    std::vector<NetworkEvent> events;

    auto make_key = [](const NetConnection& c) -> std::string {
        return std::format("{}:{}:{}:{}:{}", c.proto, c.local_addr, c.local_port,
                           c.remote_addr, c.remote_port);
    };

    std::unordered_map<std::string, const NetConnection*> prev_map;
    for (const auto& c : previous) prev_map[make_key(c)] = &c;

    std::unordered_map<std::string, const NetConnection*> curr_map;
    for (const auto& c : current) curr_map[make_key(c)] = &c;

    for (const auto& c : current) {
        if (!prev_map.contains(make_key(c))) {
            events.push_back({timestamp, snapshot_id, "connected", c.proto,
                              c.local_addr, c.local_port, c.remote_addr, c.remote_host,
                              c.remote_port, c.state, c.pid, c.process_name});
        }
    }

    for (const auto& c : previous) {
        if (!curr_map.contains(make_key(c))) {
            events.push_back({timestamp, snapshot_id, "disconnected", c.proto,
                              c.local_addr, c.local_port, c.remote_addr, c.remote_host,
                              c.remote_port, c.state, c.pid, c.process_name});
        }
    }

    return events;
}

std::vector<ServiceEvent> compute_service_events(
    const std::vector<ServiceInfo>& previous,
    const std::vector<ServiceInfo>& current,
    int64_t timestamp, int64_t snapshot_id) {

    std::vector<ServiceEvent> events;

    std::unordered_map<std::string, const ServiceInfo*> prev_map;
    for (const auto& s : previous) prev_map[s.name] = &s;
    std::unordered_map<std::string, const ServiceInfo*> curr_map;
    for (const auto& s : current) curr_map[s.name] = &s;

    for (const auto& s : current) {
        auto it = prev_map.find(s.name);
        if (it == prev_map.end()) {
            events.push_back({timestamp, snapshot_id, "started", s.name, s.display_name,
                              s.status, "", s.startup_type, ""});
        } else {
            // Same startup_type_query_failed guard as compute_service_diff
            // above -- see its comment.
            const auto* prev = it->second;
            const bool startup_type_changed = !prev->startup_type_query_failed &&
                                              !s.startup_type_query_failed &&
                                              prev->startup_type != s.startup_type;
            if (prev->status != s.status || startup_type_changed) {
                events.push_back({timestamp, snapshot_id, "state_changed", s.name, s.display_name,
                                  s.status, prev->status, s.startup_type, prev->startup_type});
            }
        }
    }

    for (const auto& s : previous) {
        if (!curr_map.contains(s.name)) {
            events.push_back({timestamp, snapshot_id, "stopped", s.name, s.display_name,
                              s.status, "", s.startup_type, ""});
        }
    }

    return events;
}

std::vector<UserEvent> compute_user_events(
    const std::vector<UserSession>& previous,
    const std::vector<UserSession>& current,
    int64_t timestamp, int64_t snapshot_id) {

    std::vector<UserEvent> events;

    auto make_key = [](const UserSession& u) -> std::string { return u.user + ":" + u.session_id; };

    std::unordered_map<std::string, const UserSession*> prev_map;
    for (const auto& u : previous) prev_map[make_key(u)] = &u;
    std::unordered_map<std::string, const UserSession*> curr_map;
    for (const auto& u : current) curr_map[make_key(u)] = &u;

    for (const auto& u : current) {
        if (!prev_map.contains(make_key(u)))
            events.push_back({timestamp, snapshot_id, "login", u.user, u.domain, u.logon_type, u.session_id});
    }
    for (const auto& u : previous) {
        if (!curr_map.contains(make_key(u)))
            events.push_back({timestamp, snapshot_id, "logout", u.user, u.domain, u.logon_type, u.session_id});
    }

    return events;
}

std::vector<SoftwareEvent> compute_software_events(
    const std::vector<SoftwareInfo>& previous,
    const std::vector<SoftwareInfo>& current,
    int64_t timestamp, int64_t snapshot_id) {

    std::vector<SoftwareEvent> events;

    // Machine scope only: key on the application name. (An earlier design keyed on
    // (scope, user, name) to track per-user installs independently; per-user scope
    // was dropped, so name alone is the identity — #1620.)
    auto make_key = [](const SoftwareInfo& s) -> std::string { return s.name; };

    std::unordered_map<std::string, const SoftwareInfo*> prev_map;
    for (const auto& s : previous) prev_map[make_key(s)] = &s;
    std::unordered_map<std::string, const SoftwareInfo*> curr_map;
    for (const auto& s : current) curr_map[make_key(s)] = &s;

    for (const auto& s : current) {
        auto it = prev_map.find(make_key(s));
        if (it == prev_map.end()) {
            events.push_back({timestamp, snapshot_id, "installed", s.name, s.version, "",
                              s.publisher, s.install_date});
        } else if (it->second->version != s.version) {
            // Same identity, version changed → upgrade (or downgrade); carry the
            // previous version. A bare reinstall at the same version emits nothing.
            events.push_back({timestamp, snapshot_id, "upgraded", s.name, s.version,
                              it->second->version, s.publisher, s.install_date});
        }
    }

    for (const auto& s : previous) {
        if (!curr_map.contains(make_key(s))) {
            events.push_back({timestamp, snapshot_id, "removed", s.name, s.version, "",
                              s.publisher, s.install_date});
        }
    }

    return events;
}

std::vector<ArpEvent> compute_arp_events(
    const std::vector<ArpEntry>& previous,
    const std::vector<ArpEntry>& current,
    int64_t timestamp, int64_t snapshot_id) {

    std::vector<ArpEvent> events;

    // \x1f (unit separator) cannot appear in an interface/IP/MAC string, so the
    // composite key is collision-free without escaping.
    auto make_key = [](const ArpEntry& a) -> std::string {
        return a.iface + "\x1f" + a.ip_address + "\x1f" + a.mac_address;
    };

    std::unordered_map<std::string, const ArpEntry*> prev_map;
    for (const auto& a : previous) prev_map[make_key(a)] = &a;
    std::unordered_map<std::string, const ArpEntry*> curr_map;
    for (const auto& a : current) curr_map[make_key(a)] = &a;

    // entry_type is intentionally NOT in the key — a dynamic/static flap on the
    // same binding is a value update, not an appeared/removed transition.
    for (const auto& a : current) {
        if (!prev_map.contains(make_key(a)))
            events.push_back({timestamp, snapshot_id, "appeared", a.iface,
                              a.ip_address, a.mac_address, a.entry_type});
    }
    for (const auto& a : previous) {
        if (!curr_map.contains(make_key(a)))
            events.push_back({timestamp, snapshot_id, "removed", a.iface,
                              a.ip_address, a.mac_address, a.entry_type});
    }

    return events;
}

std::vector<DnsEvent> compute_dns_events(
    const std::vector<DnsEntry>& previous,
    const std::vector<DnsEntry>& current,
    int64_t timestamp, int64_t snapshot_id) {

    std::vector<DnsEvent> events;

    // Key on the resolution identity only. \x1f separates the fields (DNS data —
    // e.g. a TXT record — may legitimately contain ':' or '|', so those are unsafe
    // delimiters). ttl_remaining_s is excluded so the per-tick TTL decrement does
    // not churn appeared/removed.
    auto make_key = [](const DnsEntry& d) -> std::string {
        return d.name + "\x1f" + d.record_type + "\x1f" + d.data;
    };

    std::unordered_map<std::string, const DnsEntry*> prev_map;
    for (const auto& d : previous) prev_map[make_key(d)] = &d;
    std::unordered_map<std::string, const DnsEntry*> curr_map;
    for (const auto& d : current) curr_map[make_key(d)] = &d;

    for (const auto& d : current) {
        if (!prev_map.contains(make_key(d)))
            events.push_back({timestamp, snapshot_id, "appeared", d.name,
                              d.record_type, d.data, d.ttl_remaining_s, d.source});
    }
    for (const auto& d : previous) {
        if (!curr_map.contains(make_key(d)))
            events.push_back({timestamp, snapshot_id, "removed", d.name,
                              d.record_type, d.data, d.ttl_remaining_s, d.source});
    }

    return events;
}

std::vector<MapDriveEvent> compute_mapdrive_events(
    const std::vector<MapDriveEntry>& previous,
    const std::vector<MapDriveEntry>& current,
    int64_t timestamp, int64_t snapshot_id) {

    std::vector<MapDriveEvent> events;

    // \x1f (unit separator) cannot appear in a drive/UNC/host/user string, so the
    // composite key is collision-free without escaping (`:` and `\` are unsafe —
    // drive letters and UNC paths contain them). direction and username ARE keyed;
    // provider is a value-only field (a provider flap on the same mapping is not a
    // transition).
    auto make_key = [](const MapDriveEntry& m) -> std::string {
        return m.direction + "\x1f" + m.local_mount + "\x1f" + m.remote_path + "\x1f" +
               m.remote_host + "\x1f" + m.username;
    };

    std::unordered_map<std::string, const MapDriveEntry*> prev_map;
    for (const auto& m : previous) prev_map[make_key(m)] = &m;
    std::unordered_map<std::string, const MapDriveEntry*> curr_map;
    for (const auto& m : current) curr_map[make_key(m)] = &m;

    // origin is stamped "live" on every diff row so the DDL '' default never leaks
    // as a third origin value; historical rows never flow through this diff.
    for (const auto& m : current) {
        if (!prev_map.contains(make_key(m)))
            events.push_back({timestamp, snapshot_id, "appeared", m.direction,
                              m.local_mount, m.remote_path, m.remote_host, m.username,
                              m.provider, "live"});
    }
    for (const auto& m : previous) {
        if (!curr_map.contains(make_key(m)))
            events.push_back({timestamp, snapshot_id, "removed", m.direction,
                              m.local_mount, m.remote_path, m.remote_host, m.username,
                              m.provider, "live"});
    }

    return events;
}

} // namespace yuzu::tar
