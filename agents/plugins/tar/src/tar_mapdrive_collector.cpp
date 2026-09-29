// tar_mapdrive_collector.cpp — mapped-drive enumeration for the TAR `mapdrive`
// capture source (capability-map §3.8). Impure platform shell; the snapshot is
// diffed in tar_diff.cpp (compute_mapdrive_events) and persisted in tar_db.cpp
// (insert_mapdrive_events). Core capture-source pattern — types/decls in
// tar_collectors.hpp. See docs/tar-implementer.md "Adding a capture source".
//
// Two directions, both in scope on Windows + Linux; macOS has outbound live
// only (getfsstat exposes the current mount table and nothing historical or
// inbound — honestly out of reach for an unprivileged agent):
//   outbound = drives THIS host maps to remote shares
//   inbound  = remote hosts mapping THIS host's shares (the §3.8 lateral-movement signal)
// and two modes:
//   live     = current state, snapshot-diffed each collect_slow tick (enumerate_mapdrive)
//   historic = a one-time init backfill from persistent OS artifacts (enumerate_mapdrive_history)
//
// The raw text parsers (parse_proc_mounts / parse_fstab / parse_smbstatus /
// parse_win_security_logons / parse_samba_logs) are PURE and compiled on every
// platform so each leg is unit-tested off its native OS from captured samples;
// the macOS classifier (classify_macos_mounts, tar_mapdrive_macos_parsers.hpp)
// follows the same pure/impure split. Only the I/O (WNet / NetApi / registry
// hive loads / subprocess / getfsstat / file reads) is #ifdef-guarded.
//
// PII: mapped-drive rows expose usernames + share paths. Per the works-council
// posture the source is opt-in (default_enabled=false); rows are NOT run through
// redact_cmdline (cmdline-only; it would mangle UNC paths) — opt-in + audit is
// the protection, exactly as dns_live does for visited domains.

#include "tar_capture_status.hpp" // classify_subprocess_capture, IncompleteCaptureError, would_exceed_cap
#include "tar_collectors.hpp"

#include <yuzu/agent/subprocess_runner.hpp> // run_bounded_subprocess (rung 2 argv sites)

#include <spdlog/spdlog.h>

#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib> // std::strtol — timestamp/event-field parsing (no scanf family)
#include <format>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winnetwk.h> // WNetOpenEnumW / WNetEnumResourceW / WNetGetUserW (mpr)
#include <lm.h>       // NetSessionEnum / NetApiBufferFree (netapi32)
#include "tar_win_raii_guards.hpp" // yuzu::tar::win_raii::WNetEnumGuard / NetApiBufGuard
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)
// Shared per-user profile/hive ladder (#2771) — replaces this file's private
// ProfileList walk, system-SID filter and mount/unload guards.
#include <user_profile_model.hpp>
#include <win_profiles.hpp>
#include <win_reg_handle.hpp>
#include <cwchar>      // wcslen
#elif defined(__linux__)
// Candidate-path probing on Linux goes through yuzu::agent::probe_tool_path
// (subprocess_runner.hpp, already included above) — no direct unistd.h use.
#elif defined(__APPLE__)
#include <sys/mount.h> // getfsstat / struct statfs — rung 1 native, no shell
#include "tar_mapdrive_macos_parsers.hpp"
#endif

namespace yuzu::tar {

// ── Pure helpers (cross-platform) ─────────────────────────────────────────────
namespace {

std::string trim(const std::string& s) {
    auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos)
        return {};
    auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::vector<std::string> split_ws(const std::string& s) {
    std::vector<std::string> out;
    std::size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i])))
            ++i;
        std::size_t start = i;
        while (i < s.size() && !std::isspace(static_cast<unsigned char>(s[i])))
            ++i;
        if (i > start)
            out.push_back(s.substr(start, i - start));
    }
    return out;
}

bool icontains(const std::string& hay, const std::string& needle) {
    if (needle.empty())
        return true;
    if (needle.size() > hay.size())
        return false;
    auto lower = [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); };
    for (std::size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        std::size_t j = 0;
        for (; j < needle.size(); ++j)
            if (lower(hay[i + j]) != lower(needle[j]))
                break;
        if (j == needle.size())
            return true;
    }
    return false;
}

// Civil-days epoch (Howard Hinnant) — portable + deterministic (unit-testable),
// no timegm/_mkgmtime portability split. Local-time log stamps are recorded
// as-is (interpreted as UTC); a small tz skew on historical rows is acceptable
// for forensic ordering and keeps the parsers pure.
int64_t days_from_civil(int y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153u * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

int64_t ymd_hms_to_epoch(int y, int mo, int d, int h, int mi, int s) {
    if (mo < 1 || mo > 12 || d < 1 || d > 31)
        return 0;
    return days_from_civil(y, static_cast<unsigned>(mo), static_cast<unsigned>(d)) * 86400 +
           h * 3600 + mi * 60 + s;
}

// Faithful stand-in for sscanf's "%Nd" (glibc 2.38's __isoc23_sscanf redirect
// breaks older-glibc hosts, so no scanf family): skip leading whitespace (as %d
// does, uncounted against the width), then let strtol consume the longest valid
// prefix of the next `width` characters (sign included, as scanf counts it).
// Advances `p` past the consumed characters; nullopt = no conversion.
std::optional<int> scan_int(const char*& p, int width) {
    char buf[8]{};
    if (width <= 0 || width > 7) // callers pass 2 or 4; guard the buffer bound
        return std::nullopt;     // (before any side effect on the cursor)
    while (std::isspace(static_cast<unsigned char>(*p)))
        ++p;
    for (int i = 0; i < width && p[i]; ++i)
        buf[i] = p[i];
    char* end{};
    const long v = std::strtol(buf, &end, 10);
    if (end == buf)
        return std::nullopt;
    p += end - buf;
    return static_cast<int>(v); // width <= 4 → |v| <= 9999, cast exact
}

// Parse a flexible timestamp starting at `pos`: "YYYY-MM-DD[T| ]HH:MM:SS" or the
// Samba "YYYY/MM/DD HH:MM:SS" form. Returns epoch seconds or 0 if not matched.
// Same shapes the former sscanf triple matched:
//   "%4d-%2d-%2dT%2d:%2d:%2d" | "%4d-%2d-%2d %2d:%2d:%2d" | "%4d/%2d/%2d %2d:%2d:%2d"
// Preserved quirks: a format ' ' matches ZERO or more whitespace (each %d also
// skips leading whitespace), and 'T' only follows a '-' date.
int64_t parse_flexible_ts(const std::string& s, std::size_t pos = 0) {
    const char* p = s.c_str() + pos;
    const auto y = scan_int(p, 4);
    if (!y)
        return 0;
    const char sep = *p;
    if (sep != '-' && sep != '/')
        return 0;
    ++p;
    const auto mo = scan_int(p, 2);
    if (!mo || *p != sep)
        return 0;
    ++p;
    const auto d = scan_int(p, 2);
    if (!d)
        return 0;
    if (sep == '-' && *p == 'T')
        ++p;
    const auto h = scan_int(p, 2);
    if (!h || *p != ':')
        return 0;
    ++p;
    const auto mi = scan_int(p, 2);
    if (!mi || *p != ':')
        return 0;
    ++p;
    const auto se = scan_int(p, 2);
    if (!se)
        return 0;
    return ymd_hms_to_epoch(*y, *mo, *d, *h, *mi, *se);
}

// Decode the kernel's octal escapes in /proc/mounts and /etc/fstab fields
// (space=\040, tab=\011, newline=\012, backslash=\134).
std::string decode_mount_escapes(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '\\' && i + 3 < in.size() && std::isdigit(static_cast<unsigned char>(in[i + 1])) &&
            std::isdigit(static_cast<unsigned char>(in[i + 2])) &&
            std::isdigit(static_cast<unsigned char>(in[i + 3]))) {
            int v = (in[i + 1] - '0') * 64 + (in[i + 2] - '0') * 8 + (in[i + 3] - '0');
            out.push_back(static_cast<char>(v));
            i += 3;
        } else {
            out.push_back(in[i]);
        }
    }
    return out;
}

bool is_network_fstype(const std::string& fs) {
    static const char* kNet[] = {"cifs",       "smb3",  "smb2", "smbfs",    "nfs",
                                 "nfs4",       "ncpfs", "afs",  "glusterfs", "fuse.sshfs",
                                 "fuse.davfs", "davfs", "fuse.cifs"};
    for (const auto* n : kNet)
        if (fs == n)
            return true;
    return false;
}

// Best-effort host extraction from a share/device string across the forms:
//   \\server\share  //server/share  server:/export  user@host:/path
//   scheme://[user@]host/path  (afp://, https:// (WebDAV), smb://, ...)
//   //user@server/share  (credentialed UNC — macOS getfsstat can surface
//   embedded usernames in f_mntfromname for smbfs mounts)
//   user@[2001:db8::1]:/path  2001:db8::1:/path  (IPv6 NFS hosts, BR-003)
std::string remote_host_of(const std::string& path) {
    std::string p = path;
    // Both the URI-authority and UNC forms below may embed "user@" ahead of
    // the host; strip it so the returned host is never a credential.
    auto strip_userinfo = [](std::string authority) {
        if (auto at = authority.rfind('@'); at != std::string::npos)
            authority.erase(0, at + 1);
        return authority;
    };
    // scheme://[user@]host[/path] — checked first since "://" never appears
    // in the UNC or bare user@host: forms below.
    if (auto scheme = p.find("://"); scheme != std::string::npos) {
        const auto start = scheme + 3;
        const auto end = p.find('/', start);
        return strip_userinfo(
            p.substr(start, end == std::string::npos ? std::string::npos : end - start));
    }
    // UNC: leading \\ or //
    if (p.size() >= 2 && (p[0] == '\\' || p[0] == '/') && (p[1] == '\\' || p[1] == '/')) {
        std::size_t start = 2;
        std::size_t end = p.find_first_of("\\/", start);
        return strip_userinfo(
            p.substr(start, end == std::string::npos ? std::string::npos : end - start));
    }
    // user@host:/path — the NFS host/export separator is specifically
    // ":/" (a colon immediately followed by a slash), not the first bare
    // colon: an IPv6 host (bracketed "[2001:db8::1]:/export" or unbracketed
    // "2001:db8::1:/export") embeds colons of its own, and the first-colon
    // split used before this fix (BR-003) truncated either shape at the
    // host's very first hextet. rfind, not find: NFS export paths only ever
    // start with a single leading '/', so the LAST ":/" in the string is
    // always the host/export boundary, never a colon inside the path.
    auto at = p.find('@');
    auto separator = p.rfind(":/");
    if (separator == std::string::npos) {
        // No "<colon><slash>" boundary at all -- fall back to the first
        // bare colon (the pre-BR-003 behavior), covering a colon-separated
        // host whose export path doesn't start with '/' (e.g.
        // "server:export"); an IPv4/hostname host has at most one colon, so
        // this fallback never mis-splits one of those.
        separator = p.find(':');
    }
    if (separator != std::string::npos && (at == std::string::npos || at < separator)) {
        std::size_t start = (at != std::string::npos) ? at + 1 : 0;
        std::string host = p.substr(start, separator - start);
        if (host.size() >= 2 && host.front() == '[' && host.back() == ']')
            host = host.substr(1, host.size() - 2);
        return host;
    }
    return {};
}

// Extract the address from a Samba "(ipv4:1.2.3.4:445)" / "(ipv6:::1:...)" token.
std::string extract_paren_ip(const std::string& line) {
    for (const char* tag : {"(ipv4:", "(ipv6:"}) {
        auto pos = line.find(tag);
        if (pos == std::string::npos)
            continue;
        pos += std::string(tag).size();
        auto end = line.find(')', pos);
        if (end == std::string::npos)
            continue;
        std::string inside = line.substr(pos, end - pos);
        // ipv4:1.2.3.4:445 -> drop the trailing :port. IPv6 addresses contain
        // colons, so strip only a final :digits suffix AND only when it is not
        // itself part of the address — i.e. the char before the last ':' is not
        // another ':' (which would make it the "::" of a portless address like
        // 2001:db8::1). Without that guard the last hextet of a portless IPv6
        // address is lopped off.
        auto last = inside.find_last_of(':');
        if (last != std::string::npos && last > 0 && last + 1 < inside.size() &&
            inside[last - 1] != ':' &&
            std::isdigit(static_cast<unsigned char>(inside[last + 1])))
            inside = inside.substr(0, last);
        return inside;
    }
    return {};
}

// Word following `marker` in `line` (whitespace-delimited); "" if absent.
std::string word_after(const std::string& line, const std::string& marker) {
    auto pos = line.find(marker);
    if (pos == std::string::npos)
        return {};
    pos += marker.size();
    while (pos < line.size() && std::isspace(static_cast<unsigned char>(line[pos])))
        ++pos;
    std::size_t start = pos;
    while (pos < line.size() && !std::isspace(static_cast<unsigned char>(line[pos])))
        ++pos;
    return line.substr(start, pos - start);
}

[[maybe_unused]] std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Like read_file, but for a file whose content is REQUIRED for a genuinely
// complete capture -- /proc/mounts (Linux live outbound) below -- rather
// than best-effort history (/etc/fstab, the Samba log tail, both still on
// read_file above). BR4-004 (round 4): read_file's silent {} on open
// failure, and its never checking rdbuf() extraction for a mid-stream
// error, is the right degrade for OPTIONAL history sources but was also
// feeding /proc/mounts -- a transient procfs read failure (a restricted
// container/namespace, a race during teardown) then came back
// indistinguishable from "this host genuinely has zero outbound network
// mounts", and enumerate_mapdrive() diffed/persisted that empty result as
// complete, fabricating a false `removed` event for every previously known
// outbound mount. Throws IncompleteCaptureError instead, same contract as
// every other required-read leg in this file (smbstatus/wevtutil above)
// and the adjacent ARP procfs leg (tar_arp_collector.cpp) this mirrors.
[[maybe_unused]] std::string read_required_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        throw yuzu::tar::IncompleteCaptureError("TAR: failed to open " + path);
    std::ostringstream ss;
    ss << f.rdbuf();
    if (f.bad())
        throw yuzu::tar::IncompleteCaptureError("TAR: read error mid-stream on " + path);
    return ss.str();
}

// Read at most the LAST max_bytes of a file. Samba's log.smbd on a busy file
// server can be hundreds of MB (or unbounded with `max log size = 0`); slurping
// it whole on the init-critical backfill path is a memory/latency hazard. The
// most recent connects are at the tail, which is what the backfill wants anyway.
// Starts at a line boundary so parse_samba_logs never sees a half-truncated line.
[[maybe_unused]] std::string read_file_tail(const std::string& path, std::size_t max_bytes) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f)
        return {};
    std::streamoff size = f.tellg();
    if (size <= 0)
        return {};
    std::size_t want = static_cast<std::size_t>(size);
    bool truncated = want > max_bytes;
    if (truncated)
        want = max_bytes;
    f.seekg(static_cast<std::streamoff>(static_cast<std::size_t>(size) - want), std::ios::beg);
    std::string buf(want, '\0');
    f.read(buf.data(), static_cast<std::streamsize>(want));
    buf.resize(static_cast<std::size_t>(f.gcount()));
    // Drop a leading partial line if we started mid-file.
    if (truncated) {
        if (auto nl = buf.find('\n'); nl != std::string::npos)
            buf.erase(0, nl + 1);
    }
    return buf;
}

} // namespace

// Collapse duplicate history rows by mapping identity, preferring the smallest
// non-zero timestamp (the earliest known sighting). Applies the cap. Defined at
// yuzu::tar scope (not the anonymous namespace) so it is unit-testable.
std::vector<MapDriveHistoryRow> dedup_history(std::vector<MapDriveHistoryRow> rows) {
    std::unordered_map<std::string, std::size_t> seen;
    std::vector<MapDriveHistoryRow> out;
    out.reserve(rows.size());
    for (auto& r : rows) {
        std::string key = r.entry.direction + "\x1f" + r.entry.local_mount + "\x1f" +
                          r.entry.remote_path + "\x1f" + r.entry.remote_host + "\x1f" +
                          r.entry.username;
        auto it = seen.find(key);
        if (it == seen.end()) {
            seen.emplace(std::move(key), out.size());
            out.push_back(std::move(r));
        } else {
            auto& kept = out[it->second];
            if (r.ts != 0 && (kept.ts == 0 || r.ts < kept.ts))
                kept.ts = r.ts;
        }
        if (out.size() >= kMapDriveHistoryCap)
            break;
    }
    return out;
}

// ── Pure parsers (compiled everywhere; unit-tested off-OS) ────────────────────

ProcMountsParse parse_proc_mounts(const std::string& text) {
    ProcMountsParse out;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        auto tok = split_ws(line);
        if (tok.size() < 3) {
            // BUG 2 fix: a structurally short row (fewer than the
            // device/mountpoint/fstype 3 fields every /proc/mounts row
            // carries) is a malformed row, not a legitimate skip -- flag it
            // so the caller (enumerate_mapdrive()) can tell "this row was
            // dropped because it wasn't a network filesystem" (a normal,
            // routine skip, never flagged) apart from "this row was dropped
            // because it was truncated/corrupt" (BR-mapdrive-001; same
            // policy as tar_arp_parsers.hpp's BR4-005 and
            // tar_service_parsers.hpp's BR-service-001).
            out.malformed = true;
            continue;
        }
        std::string fstype = tok[2];
        if (!is_network_fstype(fstype))
            continue; // legitimate skip: well-formed row, just not a network fs
        std::string device = decode_mount_escapes(tok[0]);
        std::string mountpoint = decode_mount_escapes(tok[1]);
        MapDriveEntry e;
        e.direction = "outbound";
        e.local_mount = mountpoint;
        e.remote_path = device;
        e.remote_host = remote_host_of(device);
        e.provider = fstype;
        out.entries.push_back(std::move(e));
    }
    return out;
}

std::vector<MapDriveHistoryRow> parse_fstab(const std::string& text) {
    std::vector<MapDriveHistoryRow> out;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '#')
            continue;
        auto tok = split_ws(t);
        if (tok.size() < 3)
            continue;
        std::string fstype = tok[2];
        if (!is_network_fstype(fstype))
            continue;
        std::string spec = decode_mount_escapes(tok[0]);
        std::string mountpoint = decode_mount_escapes(tok[1]);
        MapDriveHistoryRow r;
        r.ts = 0; // fstab carries no timestamp
        r.entry.direction = "outbound";
        r.entry.local_mount = mountpoint;
        r.entry.remote_path = spec;
        r.entry.remote_host = remote_host_of(spec);
        r.entry.provider = fstype;
        out.push_back(std::move(r));
    }
    return out;
}

SmbStatusParse parse_smbstatus(const std::string& text) {
    // `smbstatus -b` sessions table:
    //   PID  Username  Group  Machine                       Protocol  ...
    //   1234 alice     alice  192.168.1.50 (ipv4:1.2.3.4:445) SMB3_11 ...
    // A data row starts with a numeric PID; the client is the parenthetical IP if
    // present, else the Machine token (index 3).
    SmbStatusParse out;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        auto tok = split_ws(line);
        bool pid = !tok.empty() && !tok[0].empty();
        if (pid)
            for (char c : tok[0])
                if (!std::isdigit(static_cast<unsigned char>(c)))
                    pid = false;
        if (!pid)
            continue; // legitimate skip: header/separator/trailer line, not a data row
        if (tok.size() < 4) {
            // Finding 4 (BR-mapdrive-001, missed site): looks like a data
            // row (a bare numeric PID leads it) but is structurally short --
            // a truncated/corrupt capture, not a legitimate skip. Flag it
            // instead of silently dropping it (same policy as
            // parse_proc_mounts's tok.size() < 3 branch above).
            out.malformed = true;
            continue;
        }
        MapDriveEntry e;
        e.direction = "inbound";
        e.username = tok[1];
        std::string ip = extract_paren_ip(line);
        e.remote_host = !ip.empty() ? ip : tok[3];
        e.provider = "SMB";
        out.entries.push_back(std::move(e));
    }
    return out;
}

std::vector<MapDriveHistoryRow> parse_win_security_logons(const std::string& text) {
    // wevtutil `/f:text` emits one block per event starting with "Event[N]:".
    // We keep 4624 (successful logon) with Logon Type 3 (network) that carry a
    // real Source Network Address — those are the inbound network connections
    // (over-captures beyond SMB; acceptable for lateral-movement history). The
    // real account is the 2nd "Account Name:" (the 1st is the requesting subject).
    std::vector<MapDriveHistoryRow> out;
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t next = text.find("Event[", pos + 1);
        std::string block = text.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
        pos = (next == std::string::npos) ? text.size() : next;

        if (!icontains(block, "Event ID:"))
            continue;
        int event_id = 0;
        {
            auto p = block.find("Event ID:");
            if (p != std::string::npos) {
                const char* q = block.c_str() + p + 9;
                char* end{};
                const long v = std::strtol(q, &end, 10);
                if (end != q) // parse failure keeps the 0 initializer (≠ 4624 → skipped)
                    event_id = static_cast<int>(v);
            }
        }
        if (event_id != 4624)
            continue;

        // Logon Type must be 3 (network).
        int logon_type = -1;
        {
            auto p = block.find("Logon Type:");
            if (p != std::string::npos) {
                const char* q = block.c_str() + p + 11;
                char* end{};
                const long v = std::strtol(q, &end, 10);
                if (end != q) // parse failure keeps the -1 initializer (≠ 3 → skipped)
                    logon_type = static_cast<int>(v);
            }
        }
        if (logon_type != 3)
            continue;

        std::string src = trim(word_after(block, "Source Network Address:"));
        if (src.empty() || src == "-" || src == "127.0.0.1" || src == "::1")
            continue; // no real remote peer -> not an inbound connection

        // The 2nd "Account Name:" is the logged-on account (the 1st is the
        // requesting subject / system account).
        std::string account;
        {
            auto p1 = block.find("Account Name:");
            auto p2 = (p1 == std::string::npos) ? std::string::npos
                                                : block.find("Account Name:", p1 + 1);
            std::size_t use = (p2 != std::string::npos) ? p2 : p1;
            if (use != std::string::npos)
                account = trim(word_after(block.substr(use), "Account Name:"));
        }
        if (account.empty() || account == "-")
            continue;
        // Skip machine accounts (name ends with '$') and well-known noise.
        if (account.back() == '$' || account == "ANONYMOUS")
            continue;

        std::string date = trim(word_after(block, "Date:"));
        MapDriveHistoryRow r;
        r.ts = parse_flexible_ts(date);
        r.entry.direction = "inbound";
        r.entry.remote_host = src;
        r.entry.username = account;
        r.entry.provider = "network"; // logon-audit heuristic (broader than SMB)
        out.push_back(std::move(r));
    }
    return out;
}

std::vector<MapDriveHistoryRow> parse_samba_logs(const std::string& text) {
    // Two shapes are handled:
    //   Samba log.smbd:  "[2026/07/01 10:20:30.123, 3] .../service.c(...)" header
    //                    lines set the timestamp; a later line contains
    //                    "... (ipv4:IP:445) connect to service SHARE initially as user USER".
    //   journalctl -o short-iso: the connect line itself is ISO-dated.
    std::vector<MapDriveHistoryRow> out;
    std::istringstream in(text);
    std::string line;
    int64_t last_ts = 0;
    while (std::getline(in, line)) {
        // Samba header timestamp: "[YYYY/MM/DD HH:MM:SS"
        if (!line.empty() && line[0] == '[' && line.size() > 20) {
            if (auto ts = parse_flexible_ts(line, 1); ts != 0)
                last_ts = ts;
        }
        if (!icontains(line, "connect to service"))
            continue;

        int64_t ts = last_ts;
        if (auto own = parse_flexible_ts(line); own != 0) // journalctl ISO-dated line
            ts = own;

        std::string service = word_after(line, "connect to service");
        std::string user = word_after(line, "as user");
        std::string ip = extract_paren_ip(line);
        if (ip.empty())
            ip = word_after(line, "client ["); // "client [1.2.3.4]"
        if (!ip.empty() && ip.back() == ']')
            ip.pop_back();

        if (service.empty() && user.empty() && ip.empty())
            continue;
        MapDriveHistoryRow r;
        r.ts = ts;
        r.entry.direction = "inbound";
        r.entry.local_mount = service;
        r.entry.remote_host = ip;
        r.entry.username = user;
        r.entry.provider = "SMB";
        out.push_back(std::move(r));
    }
    return out;
}

// ── Windows platform shell ────────────────────────────────────────────────────
#ifdef _WIN32

namespace {

void warn_capped(std::atomic<bool>& flag, const char* what, std::size_t cap) {
    if (!flag.exchange(true))
        spdlog::warn("TAR mapdrive: {} cap {} reached — truncating (repeats suppressed "
                     "until it clears)",
                     what, cap);
}

// RAII owners for the Win32 enumeration resources (cpp-conventions.md §Resource
// ownership: manual cleanup between a throwing acquire/use and release is a
// governance finding). from_wide / vector::push_back below can throw, so the
// handle/buffer must free on every exit including an exceptional unwind. Same
// shape as this file's RegKeyGuard, agents/shared/win_reg_handle.hpp's
// ScopedUserHive, and the in-repo HandleGuard (processes_plugin.cpp).
// Shared implementation in tar_win_raii_guards.hpp (injectable closer,
// unit-tested).
using yuzu::tar::win_raii::WNetEnumGuard;
using yuzu::tar::win_raii::NetApiBufGuard;

// Absolute path to a System32 tool, as a bare (unquoted) argv element —
// run_bounded_subprocess execs argv[0] directly (no shell in between), so the
// quoting the old shell-pipe call needed to protect a spaced path is neither
// needed nor wanted here; quotes embedded in the string would become literal
// characters in the exec'd path. Removes PATH-hijack exposure for wevtutil on
// the privileged agent the same way the old quoted-shell form did. Falls back
// to the bare name if GetSystemDirectoryW fails (defensive; effectively
// never) — the runner will report spawn_error for a relative argv[0], which
// degrades to an empty parse the same way the old shell-pipe call failing did.
std::string system32_path(const char* exe) {
    wchar_t dir[MAX_PATH]{};
    UINT n = GetSystemDirectoryW(dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return exe; // fallback: bare name (spawn_error via the runner, not a PATH search)
    return yuzu::win::from_wide(dir) + "\\" + exe;
}

// --- outbound live: currently-connected network drives (WNet) ---
void enum_wnet_outbound(std::vector<MapDriveEntry>& out) {
    HANDLE hEnum = nullptr;
    DWORD rc = WNetOpenEnumW(RESOURCE_CONNECTED, RESOURCETYPE_DISK, 0, nullptr, &hEnum);
    // BR4-003 (round 4): a WNetOpenEnumW failure was previously conflated
    // with "no connected network resources" and swallowed to an empty `out`
    // -- WNetOpenEnumW's own contract has no such benign-empty failure mode
    // (an empty result comes back as a valid handle whose first
    // WNetEnumResourceW call then returns ERROR_NO_MORE_ITEMS, handled
    // below); any open failure is a real provider/transport error that must
    // not be silently persisted as "this host has zero outbound mappings".
    if (yuzu::tar::is_unexpected_enumeration_status(rc, {NO_ERROR}))
        throw yuzu::tar::IncompleteCaptureError(
            std::format("TAR: WNetOpenEnumW failed (rc={})", rc));
    WNetEnumGuard eg{hEnum}; // closes on every exit (cap throw / normal)

    std::vector<char> buffer(16384);
    for (;;) {
        DWORD count = 0xFFFFFFFF; // as many as fit
        DWORD size = static_cast<DWORD>(buffer.size());
        rc = WNetEnumResourceW(hEnum, &count, buffer.data(), &size);
        if (rc == ERROR_MORE_DATA) {
            // Buffer too small for this page — grow and retry (distinct from
            // session pagination; WNet has no resume handle).
            buffer.resize(size);
            continue;
        }
        // BR4-003 (round 4): ONLY ERROR_NO_MORE_ITEMS is the documented
        // "table exhausted" terminal status -- the prior `if (rc != NO_ERROR)
        // break` conflated every other unexpected status (provider dropped,
        // transport error, etc.) with normal completion, so a partial
        // outbound set could still replace the last complete baseline. Any
        // status outside {NO_ERROR (more rows this page), ERROR_NO_MORE_ITEMS
        // (exhausted)} throws instead of silently stopping the loop.
        if (yuzu::tar::is_unexpected_enumeration_status(rc, {NO_ERROR, ERROR_NO_MORE_ITEMS}))
            throw yuzu::tar::IncompleteCaptureError(
                std::format("TAR: WNetEnumResourceW failed (rc={})", rc));
        if (rc != NO_ERROR)
            break; // ERROR_NO_MORE_ITEMS — done, genuinely exhausted
        auto* res = reinterpret_cast<NETRESOURCEW*>(buffer.data());
        for (DWORD i = 0; i < count; ++i) {
            // Test capacity BEFORE building/pushing the candidate row (round
            // 3, B3-001/B3-004): the prior check-AFTER-push shape (a)
            // misclassified an exact-cap table as truncated, and (b) merely
            // `return`ed the partial `out` to the caller instead of
            // signalling incompleteness -- enumerate_mapdrive() then diffed
            // and persisted it as though it were the complete combined
            // outbound+inbound snapshot. Throwing here is what makes B3-001's
            // "combined snapshot known to fit" requirement hold: NEITHER
            // direction's rows are usable once either direction's cap trips.
            if (yuzu::tar::would_exceed_cap(out.size(), kMapDriveEntryCap)) {
                static std::atomic<bool> warned{false};
                warn_capped(warned, "live", kMapDriveEntryCap);
                throw yuzu::tar::IncompleteCaptureError("TAR: mapdrive live entry cap reached");
            }
            MapDriveEntry e;
            e.direction = "outbound";
            if (res[i].lpLocalName)
                e.local_mount = yuzu::win::from_wide(res[i].lpLocalName);
            if (res[i].lpRemoteName)
                e.remote_path = yuzu::win::from_wide(res[i].lpRemoteName);
            if (res[i].lpProvider)
                e.provider = yuzu::win::from_wide(res[i].lpProvider);
            e.remote_host = remote_host_of(e.remote_path);
            wchar_t ubuf[256]{};
            DWORD ulen = 256;
            const wchar_t* key = res[i].lpLocalName ? res[i].lpLocalName : res[i].lpRemoteName;
            if (key && WNetGetUserW(key, ubuf, &ulen) == NO_ERROR)
                e.username = yuzu::win::from_wide(ubuf);
            out.push_back(std::move(e));
        }
    }
}

// --- inbound live: remote sessions into our shares (NetSessionEnum) ---
template <typename INFO>
void collect_sessions(INFO* buf, DWORD n, std::vector<MapDriveEntry>& out,
                      LPWSTR INFO::*cname, LPWSTR INFO::*uname) {
    for (DWORD i = 0; i < n; ++i) {
        MapDriveEntry e;
        e.direction = "inbound";
        if (buf[i].*cname)
            e.remote_host = yuzu::win::from_wide(buf[i].*cname);
        if (buf[i].*uname)
            e.username = yuzu::win::from_wide(buf[i].*uname);
        e.provider = "SMB";
        if (e.remote_host.empty() && e.username.empty())
            continue;
        // Check-before-push (round 3, B3-001/B3-004), same reasoning as
        // enum_wnet_outbound above: throws rather than silently returning a
        // partial `out` the caller would otherwise diff/persist as complete.
        if (yuzu::tar::would_exceed_cap(out.size(), kMapDriveEntryCap))
            throw yuzu::tar::IncompleteCaptureError("TAR: mapdrive live entry cap reached");
        out.push_back(std::move(e));
    }
}

// Drain one NetSessionEnum level, paging on ERROR_MORE_DATA via the resume
// handle (MAX_PREFERRED_LENGTH usually returns everything in one call, but the
// API may still page — a single call silently drops sessions past page one on a
// busy file server). collect_sessions() now throws internally the moment the
// combined cap would be exceeded (round 3), so this loop no longer needs its
// own post-collect cap check; each page's buffer is freed by NetApiBufGuard
// even on that throw. Returns the final NET_API_STATUS so the caller can
// branch on access-denied.
template <typename INFO>
NET_API_STATUS enum_sessions_level(DWORD level, LPWSTR INFO::*cname, LPWSTR INFO::*uname,
                                   std::vector<MapDriveEntry>& out) {
    DWORD resume = 0; // NetSessionEnum resume_handle is LPDWORD (DWORD), not DWORD_PTR
    NET_API_STATUS s;
    // Hard progress backstop: a (pathological) provider returning
    // ERROR_MORE_DATA without advancing `resume` and yielding only skipped
    // rows could otherwise spin forever (collect_sessions's cap throw only
    // trips once `out` actually grows, which a no-progress page never does).
    // Real result sets need far fewer than this many pages; exceeding it
    // means no forward progress.
    constexpr unsigned kMaxPages = 4096;
    unsigned pages = 0;
    do {
        INFO* buf = nullptr;
        DWORD read = 0, total = 0;
        s = NetSessionEnum(nullptr, nullptr, nullptr, level, reinterpret_cast<LPBYTE*>(&buf),
                           MAX_PREFERRED_LENGTH, &read, &total, &resume);
        NetApiBufGuard g{buf};
        if (s == NERR_Success || s == ERROR_MORE_DATA)
            collect_sessions<INFO>(buf, read, out, cname, uname); // throws on cap (round 3)
        if (s == ERROR_MORE_DATA && (read == 0 || ++pages >= kMaxPages)) {
            // round 3 (B3-001): a stalled pager silently returned a partial
            // inbound list before -- that partial `out` would then be
            // combined with outbound and diffed/persisted as though it were
            // the complete snapshot. Throw instead, same contract as every
            // other incomplete-capture path in this file.
            spdlog::warn("TAR mapdrive: NetSessionEnum paging made no progress — stopping "
                         "(read={}, pages={})",
                         read, pages);
            throw yuzu::tar::IncompleteCaptureError(
                "TAR: NetSessionEnum paging made no progress");
        }
    } while (s == ERROR_MORE_DATA);
    return s;
}

void enum_netsession_inbound(std::vector<MapDriveEntry>& out) {
    // Level 502 (rich) → fall back to level 10 → give up on access-denied.
    NET_API_STATUS s = enum_sessions_level<SESSION_INFO_502>(
        502, &SESSION_INFO_502::sesi502_cname, &SESSION_INFO_502::sesi502_username, out);
    // Access is checked up front, so a 502 denial leaves `out` empty — the level-10
    // fallback cannot double-collect.
    if (s == ERROR_ACCESS_DENIED)
        s = enum_sessions_level<SESSION_INFO_10>(
            10, &SESSION_INFO_10::sesi10_cname, &SESSION_INFO_10::sesi10_username, out);

    // Access denied at both levels (not local-admin / Server-Operator) —
    // documented, constrained-empty outcome: degrade to empty, warned once.
    static std::atomic<bool> s_denied_warned{false};
    if (s == ERROR_ACCESS_DENIED) {
        if (!s_denied_warned.exchange(true))
            spdlog::warn("TAR mapdrive: NetSessionEnum access denied — inbound sessions require "
                         "local-admin / Server-Operator; skipping (repeats suppressed)");
        return;
    }
    // BR4-003 (round 4): every OTHER unexpected NetSessionEnum status was
    // previously silently accepted -- `out` (whatever collect_sessions
    // gathered before the failure, possibly empty) was returned as though
    // it were the complete inbound session list. Any final status besides
    // NERR_Success (clean) or ERROR_ACCESS_DENIED (handled above) is a real
    // provider/transport failure and must not be persisted as complete.
    if (yuzu::tar::is_unexpected_enumeration_status(s, {NERR_Success}))
        throw yuzu::tar::IncompleteCaptureError(
            std::format("TAR: NetSessionEnum failed (rc={})", s));
}

// --- registry helpers for outbound history ---
struct RegKeyGuard {
    HKEY h{nullptr};
    ~RegKeyGuard() {
        if (h)
            RegCloseKey(h);
    }
};

// This file's HiveUnloadGuard is retired (#2771) — agents/shared/
// win_reg_handle.hpp's ScopedUserHive owns the mount lifetime now, and unlike
// the copy it replaces it REPORTS a failed unload rather than discarding it.

int64_t filetime_to_epoch(const FILETIME& ft) {
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    constexpr uint64_t kDelta = 116444736000000000ULL; // 1601→1970 in 100ns
    if (u.QuadPart < kDelta)
        return 0;
    return static_cast<int64_t>((u.QuadPart - kDelta) / 10000000ULL);
}

int64_t key_last_write_epoch(HKEY key) {
    FILETIME ft{};
    if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         nullptr, nullptr, nullptr, &ft) != ERROR_SUCCESS)
        return 0;
    return filetime_to_epoch(ft);
}

std::string reg_read_sz(HKEY key, const wchar_t* name) {
    DWORD type = 0, cb = 0;
    if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &cb) != ERROR_SUCCESS)
        return {};
    if ((type != REG_SZ && type != REG_EXPAND_SZ) || cb == 0)
        return {};
    std::wstring buf(cb / sizeof(wchar_t) + 1, L'\0');
    DWORD cb2 = static_cast<DWORD>(buf.size() * sizeof(wchar_t));
    if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(buf.data()), &cb2) !=
        ERROR_SUCCESS)
        return {};
    buf.resize(wcslen(buf.c_str()));
    return yuzu::win::from_wide(buf.c_str());
}

// MountPoints2 remote subkey names encode a UNC: "##server#share" -> "\\server\share".
std::string decode_mountpoints2(const std::wstring& name) {
    if (name.rfind(L"##", 0) != 0)
        return {}; // volume GUIDs / drive letters are not remote shares
    // Rebuild as wide (mapping '#' -> '\\') then convert once through the shared
    // UTF-16->UTF-8 helper — a raw static_cast<char> would mangle any non-ASCII
    // code unit in an internationalized server/share name.
    std::wstring w = L"\\\\";
    for (std::size_t i = 2; i < name.size(); ++i)
        w += (name[i] == L'#') ? L'\\' : name[i];
    return yuzu::win::from_wide(w.c_str());
}

// Read the three per-user outbound artifacts under an opened user-root hive key.
void read_user_outbound_history(HKEY user_root, const std::string& profile_user,
                                std::vector<MapDriveHistoryRow>& out) {
    // (a) HKCU\Network\<Drive> — persistent mapped drives.
    {
        RegKeyGuard net;
        if (RegOpenKeyExW(user_root, L"Network", 0, KEY_READ, &net.h) == ERROR_SUCCESS) {
            wchar_t sub[256];
            DWORD idx = 0, len = 256;
            while (RegEnumKeyExW(net.h, idx, sub, &len, nullptr, nullptr, nullptr, nullptr) ==
                   ERROR_SUCCESS) {
                if (out.size() >= kMapDriveHistoryCap)
                    return; // per-key cap (a corrupt/huge key must not run unbounded)
                RegKeyGuard drive;
                if (RegOpenKeyExW(net.h, sub, 0, KEY_READ, &drive.h) == ERROR_SUCCESS) {
                    MapDriveHistoryRow r;
                    r.ts = key_last_write_epoch(drive.h);
                    r.entry.direction = "outbound";
                    r.entry.local_mount = std::string(1, static_cast<char>(sub[0])) + ":";
                    r.entry.remote_path = reg_read_sz(drive.h, L"RemotePath");
                    r.entry.remote_host = remote_host_of(r.entry.remote_path);
                    std::string u = reg_read_sz(drive.h, L"UserName");
                    r.entry.username = u.empty() ? profile_user : u;
                    r.entry.provider = reg_read_sz(drive.h, L"ProviderName");
                    if (!r.entry.remote_path.empty())
                        out.push_back(std::move(r));
                }
                idx++;
                len = 256;
            }
        }
    }
    // (b) Map Network Drive MRU — recently mapped UNCs (may be since-removed).
    {
        RegKeyGuard mru;
        if (RegOpenKeyExW(user_root,
                          L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Map Network "
                          L"Drive MRU",
                          0, KEY_READ, &mru.h) == ERROR_SUCCESS) {
            int64_t ts = key_last_write_epoch(mru.h);
            wchar_t vname[128];
            DWORD vidx = 0, vlen = 128;
            for (;; vidx++, vlen = 128) {
                if (out.size() >= kMapDriveHistoryCap)
                    return; // per-key cap
                LONG er = RegEnumValueW(mru.h, vidx, vname, &vlen, nullptr, nullptr, nullptr, nullptr);
                if (er != ERROR_SUCCESS)
                    break;
                if (vname[0] == L'M' && std::wstring(vname) == L"MRUList")
                    continue;
                std::string unc = reg_read_sz(mru.h, vname);
                if (unc.empty())
                    continue;
                MapDriveHistoryRow r;
                r.ts = ts;
                r.entry.direction = "outbound";
                r.entry.remote_path = unc;
                r.entry.remote_host = remote_host_of(unc);
                r.entry.username = profile_user;
                r.entry.provider = "SMB";
                out.push_back(std::move(r));
            }
        }
    }
    // (c) MountPoints2 — every remote share the user touched.
    {
        RegKeyGuard mp;
        if (RegOpenKeyExW(user_root,
                          L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2", 0,
                          KEY_READ, &mp.h) == ERROR_SUCCESS) {
            wchar_t sub[256];
            DWORD idx = 0, len = 256;
            while (RegEnumKeyExW(mp.h, idx, sub, &len, nullptr, nullptr, nullptr, nullptr) ==
                   ERROR_SUCCESS) {
                if (out.size() >= kMapDriveHistoryCap)
                    return; // per-key cap
                std::string unc = decode_mountpoints2(sub);
                if (!unc.empty()) {
                    RegKeyGuard sk;
                    int64_t ts = 0;
                    if (RegOpenKeyExW(mp.h, sub, 0, KEY_READ, &sk.h) == ERROR_SUCCESS)
                        ts = key_last_write_epoch(sk.h);
                    MapDriveHistoryRow r;
                    r.ts = ts;
                    r.entry.direction = "outbound";
                    r.entry.remote_path = unc;
                    r.entry.remote_host = remote_host_of(unc);
                    r.entry.username = profile_user;
                    r.entry.provider = "SMB";
                    out.push_back(std::move(r));
                }
                idx++;
                len = 256;
            }
        }
    }
}

// Walk every profile in ProfileList; read the outbound artifacts from the live
// HKU\<SID> hive, or load NTUSER.DAT for offline users (RAII-unloaded).
//
// #2771: the ProfileList walk, the system-SID filter, the REG_EXPAND_SZ
// expansion and the mount/unload ladder were all private copies here — the
// third of three in the tree. They now come from
// agents/shared/win_profiles.hpp, which additionally enables
// SeBackup/SeRestore for the offline mount (this collector enabled neither,
// so logged-out profiles were silently unreadable on a hardened install) and
// reports a failed unload instead of swallowing it.
void enum_registry_outbound_history(std::vector<MapDriveHistoryRow>& out) {
    bool profiles_ok = false;
    bool profiles_truncated = false;
    const auto raw_profiles = yuzu::win::enumerate_profile_records(profiles_ok, &profiles_truncated);
    if (!profiles_ok)
        return;
    // #2771 code-review Standards S5: the shared ladder caps the walk at
    // kMaxProfiles, where this collector's own pre-migration walk was
    // unbounded; the other two migrated consumers (registry, installed_apps)
    // already surface the cap via profile_list_truncated. This collector has
    // no per-row diagnostic channel either, so it rides the log, same as the
    // unload-failure warning below.
    if (profiles_truncated) {
        spdlog::warn("TAR mapdrive: profile list truncated at {} entries — outbound history for "
                     "profiles beyond that is not collected this cycle",
                     yuzu::win::kMaxProfiles);
    }
    const auto profiles =
        yuzu::profiles::build_profile_list(raw_profiles, yuzu::win::enumerate_hku_subkeys());

    for (const auto& profile : profiles) {
        yuzu::win::HiveAccessReport report;
        yuzu::win::with_user_hive(
            profile.sid, profile.profile_path,
            [&](HKEY root) { read_user_outbound_history(root, profile.profile_name, out); },
            &report);

        // A leaked mount is system-wide and locks NTUSER.DAT until something
        // releases it. This collector has no per-row diagnostic channel, so it
        // rides the log — once per process, matching the NetSessionEnum
        // access-denied warning above. Silently dropping it (the previous
        // behaviour) is what #2771 up-S1 objects to.
        if (report.unload_failed) {
            static std::atomic<bool> s_unload_warned{false};
            if (!s_unload_warned.exchange(true))
                spdlog::warn("TAR mapdrive: hive unload failed for HKU\\{} — the profile's "
                             "NTUSER.DAT stays locked until a holder releases it; retry "
                             "`reg unload HKU\\{}` (repeats suppressed)",
                             report.mount_name, report.mount_name);
        }
        // A per-profile access failure (hive corrupt, locked, or privileges
        // stripped) skips that profile, as before — outbound history is
        // best-effort.
        if (out.size() >= kMapDriveHistoryCap)
            return;
    }
}

} // namespace

std::vector<MapDriveEntry> enumerate_mapdrive() {
    std::vector<MapDriveEntry> out;
    // round 3 (B3-001): the mapdrive snapshot is a COMBINED outbound+inbound
    // result, so inbound is ALWAYS collected too, never skipped because
    // outbound alone already used up (or came close to) the cap. Both
    // enum_wnet_outbound and enum_netsession_inbound now throw internally
    // the moment the shared `out` vector would exceed kMapDriveEntryCap
    // (would_exceed_cap, checked before every push), so this function
    // either returns the complete combined snapshot or never returns at all
    // for this tick -- there is no path back to the caller with a partial
    // `out`.
    enum_wnet_outbound(out);
    enum_netsession_inbound(out);
    return out;
}

std::vector<MapDriveHistoryRow> enumerate_mapdrive_history() {
    std::vector<MapDriveHistoryRow> rows;
    enum_registry_outbound_history(rows);
    // Inbound history: Security event log 4624 (successful logon), filtered to
    // logon_type=3 (network) by the parser. Query 4624 ONLY — 4634 (logoff) is
    // not parsed, so including it would waste up to half the newest-first /c:5000
    // budget on events we discard, halving the effective backfill depth. Bounded
    // read; constant query (no interpolation). Empty on access denial.
    //
    // The \" quotes the old shell string wrapped around the XPath were
    // SHELL-level protection (so the space-and-bracket-laden filter survived
    // the shell's `cmd /c` parse) — run_bounded_subprocess execs argv directly,
    // so the XPath is one quote-free argv element; embedding literal '"' chars
    // here would pass them straight to wevtutil and break the filter. The old
    // `2>nul` is subsumed by the runner's default (stderr discarded unless
    // merge_stderr is set).
    std::vector<std::string> argv = {system32_path("wevtutil.exe"),
                                     "qe",
                                     "Security",
                                     "/q:*[System[(EventID=4624)]]",
                                     "/c:5000",
                                     "/f:text",
                                     "/rd:true"};
    auto run = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds(15),
                                             .output_cap_bytes = 8u * 1024 * 1024});
    // zero_exit_required=true is ASSUMED from documented wevtutil behaviour
    // (`wevtutil qe` exits 0 on a successful query including zero matching
    // events, non-zero on a channel/query error), NOT independently verified
    // on a live Windows host in this session. A partial capture here must
    // not be recorded as "no historical inbound mappings" -- throwing
    // propagates to init()'s existing enumerate_mapdrive_history() try/catch
    // (tar_plugin.cpp), which leaves mapdrive_backfill_done unset so the next
    // restart retries the whole one-time backfill rather than permanently
    // losing the inbound leg.
    auto status = yuzu::tar::classify_subprocess_capture(run.tool_ran, run.timed_out,
                                                          run.output_truncated, run.exit_code);
    if (!status.complete) {
        spdlog::error("TAR: mapdrive historical backfill incomplete (wevtutil {}) -- backfill "
                      "left undone, retried on restart",
                      status.reason);
        throw yuzu::tar::IncompleteCaptureError("TAR: wevtutil capture incomplete: " + status.reason);
    }
    auto inbound = parse_win_security_logons(run.output);
    rows.insert(rows.end(), inbound.begin(), inbound.end());
    return dedup_history(std::move(rows));
}

// ── Linux platform shell ──────────────────────────────────────────────────────
#elif defined(__linux__)

std::vector<MapDriveEntry> enumerate_mapdrive() {
    auto mounts = parse_proc_mounts(read_required_file("/proc/mounts"));
    if (mounts.malformed) {
        // BUG 2 fix: read_required_file() already guards acquisition
        // failure (open/read errors on /proc/mounts itself); this is the
        // layer below it -- a row that opened and read fine but didn't
        // tokenize into the fields every /proc/mounts row carries. Without
        // this throw the returned entry count could silently be LESS than
        // the true outbound-mount count, with no signal reaching the
        // caller that anything was dropped -- same completeness-contract
        // gap BR-service-001 closes for the service parsers.
        spdlog::error("TAR mapdrive: /proc/mounts produced a malformed row -- skipping diff, "
                      "retaining previous baseline");
        throw yuzu::tar::IncompleteCaptureError("TAR: /proc/mounts produced a malformed row");
    }
    std::vector<MapDriveEntry> out = std::move(mounts.entries);
    // Inbound: current Samba sessions. Empty if Samba isn't installed / no perms
    // (unmodified degrade-to-empty contract — `timeout 10` becomes the
    // runner's own deadline, `2>/dev/null` becomes its default stderr discard).
    // yuzu::agent::probe_tool_path (the shared runner's own probe) requires a
    // regular, executable file — stricter than a bare access(X_OK) check,
    // which would also accept a directory or other non-regular executable
    // object at the candidate path.
    std::string tool = yuzu::agent::probe_tool_path(
        {"/usr/bin/smbstatus", "/usr/local/bin/smbstatus", "/bin/smbstatus"});
    std::vector<MapDriveEntry> inbound;
    if (!tool.empty()) {
        auto run = yuzu::agent::run_bounded_subprocess(
            std::vector<std::string>{tool, "-b"},
            yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds(10),
                                           .output_cap_bytes = 8u * 1024 * 1024});
        // zero_exit_required=true verified live (Docker dperson/samba, Alpine
        // Samba 4.13.7): `smbstatus -b` exits 0 both with an active session
        // listed and with none connected -- an incomplete run here must not
        // be diffed (this feeds the LIVE mapdrive snapshot, not history), so
        // throw and let the caller skip the whole tick's diff/baseline
        // advance rather than record a partial inbound session list.
        auto status = yuzu::tar::classify_subprocess_capture(
            run.tool_ran, run.timed_out, run.output_truncated, run.exit_code);
        if (!status.complete) {
            spdlog::error("TAR: mapdrive snapshot incomplete (smbstatus {}) -- skipping diff, "
                          "retaining previous baseline",
                          status.reason);
            throw yuzu::tar::IncompleteCaptureError("TAR: smbstatus capture incomplete: " + status.reason);
        }
        auto smb = parse_smbstatus(run.output);
        if (smb.malformed) {
            // Finding 4 (same shape as the /proc/mounts malformed throw
            // above): a truncated/corrupt smbstatus row (a bare numeric PID
            // leading a structurally short line) means the returned inbound
            // session count could silently be LESS than the true count, with
            // no signal reaching the caller. Throw so this tick's diff/
            // baseline advance is skipped rather than recording a partial
            // inbound session list.
            spdlog::error("TAR mapdrive: smbstatus produced a malformed row -- skipping diff, "
                          "retaining previous baseline");
            throw yuzu::tar::IncompleteCaptureError("TAR: smbstatus produced a malformed row");
        }
        inbound = std::move(smb.entries);
    }
    out.insert(out.end(), inbound.begin(), inbound.end());
    // round 3 (B3-001): this is the COMBINED outbound(/proc/mounts)+inbound
    // (smbstatus) snapshot, checked only after both directions are known --
    // silently resizing here (the pre-fix behaviour) discarded real mounts
    // from the combined result without telling the caller, which then
    // diffed/persisted the truncated vector as though it were complete.
    // Throw instead, same contract as every other capped/failed leg in this
    // file: the caller (collect_or_retain) skips this tick's diff/state
    // advance and retains the previous baseline.
    if (out.size() > kMapDriveEntryCap) {
        static std::atomic<bool> warned{false};
        if (!warned.exchange(true))
            spdlog::warn("TAR mapdrive: live cap {} reached — truncating (repeats suppressed)",
                         kMapDriveEntryCap);
        spdlog::warn("TAR mapdrive: snapshot incomplete (entry cap reached) -- skipping diff, "
                     "retaining previous baseline");
        throw yuzu::tar::IncompleteCaptureError(
            std::format("TAR: mapdrive entry cap {} reached", kMapDriveEntryCap));
    }
    return out;
}

std::vector<MapDriveHistoryRow> enumerate_mapdrive_history() {
    std::vector<MapDriveHistoryRow> rows = parse_fstab(read_file("/etc/fstab"));
    // Inbound history: Samba connect events. Prefer the on-disk log; fall back to
    // journald. Best-effort (log verbosity varies) — empty where neither exists.
    // Bounded: read only the last 4 MiB (the recent tail — a busy server's
    // log.smbd is unbounded with `max log size = 0`) and cap the journalctl
    // fallback with a deadline so a hung journald can't stall the init backfill.
    constexpr std::size_t kSambaLogTailBytes = 4u * 1024 * 1024;
    std::string logs = read_file_tail("/var/log/samba/log.smbd", kSambaLogTailBytes);
    if (logs.empty()) {
        std::string jtool = yuzu::agent::probe_tool_path(
            {"/usr/bin/journalctl", "/bin/journalctl", "/usr/local/bin/journalctl"});
        if (!jtool.empty()) {
            auto run = yuzu::agent::run_bounded_subprocess(
                std::vector<std::string>{jtool, "-u", "smbd", "--no-pager", "-o", "short-iso",
                                         "-n", "5000"},
                yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds(15),
                                               .output_cap_bytes = 8u * 1024 * 1024});
            // zero_exit_required=true verified live (Docker jrei/systemd-ubuntu:22.04,
            // amd64 emulation, real journald): `journalctl -u <unit> --no-pager
            // -o short-iso -n 5000` exits 0 for a non-existent unit and for a
            // unit with zero matching entries alike ("-- No entries --" on
            // stdout, exit 0) -- it only returns non-zero on a genuine error
            // (bad options, journal corruption, permission denial). This is the
            // sole inbound-history source when log.smbd is absent, so an
            // incomplete run here must not silently become "no inbound
            // history" -- throwing propagates to init()'s existing
            // enumerate_mapdrive_history() try/catch (tar_plugin.cpp), which
            // leaves mapdrive_backfill_done unset so the next restart retries.
            auto status = yuzu::tar::classify_subprocess_capture(
                run.tool_ran, run.timed_out, run.output_truncated, run.exit_code);
            if (!status.complete) {
                spdlog::error("TAR: mapdrive historical backfill incomplete (journalctl {}) -- "
                              "backfill left undone, retried on restart",
                              status.reason);
                throw yuzu::tar::IncompleteCaptureError("TAR: journalctl capture incomplete: " + status.reason);
            }
            logs = run.output;
        }
    }
    auto inbound = parse_samba_logs(logs);
    rows.insert(rows.end(), inbound.begin(), inbound.end());
    return dedup_history(std::move(rows));
}

// ── macOS platform shell ──────────────────────────────────────────────────────
#elif defined(__APPLE__)

namespace {

// Size-then-fill getfsstat(2) (rung 1 — native syscall, no shell/subprocess):
// a NULL buf with bufsize 0 returns the current mount count with no
// allocation; a second call fills a buffer sized to that count. MNT_NOWAIT
// reads the kernel's cached mount table without blocking on a hung/
// unreachable remote filesystem, matching this collector's degrade-not-block
// contract for every other leg (WNet/NetSessionEnum/smbstatus/journalctl
// all avoid blocking calls too).
//
// getfsstat(2)'s documented contract is: returns -1 and sets errno on
// failure, else the number of matches (0 is a legitimate, if practically
// unreachable, "no mounts" result). `ok=false` is the ONLY signal for the
// former; collapsing both cases to "return {}" (as this used to) makes a
// transient getfsstat failure indistinguishable from a genuinely empty
// mount table once it reaches enumerate_mapdrive() (BR-002, round 2).
//
// A mount appearing between the count and fill calls is NOT simply dropped
// (as an earlier round did) — getfsstat fills only "up to the size
// specified by bufsize", so an exactly-full fill is indistinguishable from
// truncation, and silently accepting it as complete can make a still-present
// mount look removed-then-reappeared across ticks (BR-002, round 3). The
// retry-with-headroom algorithm that resolves this is
// run_getfsstat_with_retry (tar_mapdrive_macos_parsers.hpp) — extracted so
// it is unit-testable against synthetic count/fill sequences; this function
// wires in the two real getfsstat(2) calls.
GetfsstatFetchOutcome read_getfsstat() {
    return run_getfsstat_with_retry(
        []() { return getfsstat(nullptr, 0, MNT_NOWAIT); },
        [](std::size_t capacity, std::vector<MacMountRec>& out_mounts) {
            std::vector<struct statfs> buf(capacity);
            int filled = getfsstat(buf.data(), static_cast<int>(buf.size() * sizeof(struct statfs)),
                                   MNT_NOWAIT);
            if (filled < 0)
                return filled;
            if (static_cast<std::size_t>(filled) < buf.size())
                buf.resize(static_cast<std::size_t>(filled));
            out_mounts.clear();
            out_mounts.reserve(buf.size());
            for (const auto& fs : buf)
                out_mounts.push_back(MacMountRec{fs.f_fstypename, fs.f_mntfromname, fs.f_mntonname});
            return filled;
        },
        kMapDriveEntryCap);
}

} // namespace

std::vector<MapDriveEntry> enumerate_mapdrive() {
    auto fetch = read_getfsstat();
    if (!fetch.ok) {
        // A getfsstat(2) failure (errno, e.g. EIO on a hung/unreachable
        // remote filesystem) is not a genuinely empty mount table -- same
        // distinction the Linux/Windows subprocess legs' `tool_ran`/timeout/
        // truncation checks preserve via classify_subprocess_capture. Throw
        // rather than diff/persist an empty vector as though every mapping
        // had been removed (BR-002, round 2): same contract as
        // enumerate_services()/the Linux+Windows enumerate_mapdrive() legs.
        spdlog::warn(
            "TAR mapdrive: getfsstat failed -- skipping diff, retaining previous baseline");
        throw yuzu::tar::IncompleteCaptureError("TAR: getfsstat failed");
    }

    // remote_host_of is injected so the pure classifier
    // (tar_mapdrive_macos_parsers.hpp) stays free of any dependency on this
    // translation unit's anonymous-namespace helpers — the same function a
    // unit test can substitute a fixture-equivalent implementation for.
    auto out = classify_macos_mounts(fetch.mounts, remote_host_of);
    // Cap-and-warn parity with the Linux leg (same pattern, same message);
    // the truncation decision itself is apply_entry_cap (pure, unit-tested).
    if (apply_entry_cap(out, kMapDriveEntryCap)) {
        static std::atomic<bool> warned{false};
        if (!warned.exchange(true))
            spdlog::warn("TAR mapdrive: live cap {} reached — truncating (repeats suppressed)",
                         kMapDriveEntryCap);
        // An over-cap snapshot omits real mounts -- the same "indistinguishable
        // from a genuinely smaller table" problem the failed-fetch path above
        // guards against. Skip this tick's diff/state advance too (BR-002).
        spdlog::warn("TAR mapdrive: snapshot incomplete (entry cap reached) -- skipping diff, "
                     "retaining previous baseline");
        throw yuzu::tar::IncompleteCaptureError(std::format("TAR: mapdrive entry cap {} reached", kMapDriveEntryCap));
    }
    return out;
}

std::vector<MapDriveHistoryRow> enumerate_mapdrive_history() {
    // Inbound (this host's own SMB/NFS/AFP server sessions) and any
    // persistent history artifact equivalent to Linux's /etc/fstab or
    // Windows' registry MRU/event log are honestly out of reach for an
    // unprivileged agent on macOS — getfsstat exposes only the current live
    // mount table, nothing historical. Empty, not guessed.
    return {};
}

// ── other: kPlanned ───────────────────────────────────────────────────────────
#else

std::vector<MapDriveEntry> enumerate_mapdrive() { return {}; }
std::vector<MapDriveHistoryRow> enumerate_mapdrive_history() { return {}; }

#endif

} // namespace yuzu::tar
