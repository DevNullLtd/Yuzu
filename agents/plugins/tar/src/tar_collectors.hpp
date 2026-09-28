#pragma once

/**
 * tar_collectors.hpp -- Data types and diff engine for TAR collectors
 *
 * Defines the data structures for each collector type (process, network,
 * service, user session) and the diff functions that compare snapshots
 * to produce TarEvent records for births, deaths, and state changes.
 *
 * Diff algorithm: uses std::unordered_map with composite keys.
 *   - "Birth" = present in current but not in previous
 *   - "Death" = present in previous but not in current
 *   - "State change" = same key, different status field (services only)
 *
 * Command-line redaction: Before storing process events, cmdline is checked
 * against configurable case-insensitive substring patterns (default: *password*, *secret*, *token*,
 * *api_key*, *credential*). Matching cmdlines are replaced with
 * "[REDACTED by TAR]".
 */

#include "tar_db.hpp"
#include "tar_schema_registry.hpp" // OsSupportStatus (read_failure_token)
#include "tar_netqual.hpp" // TcpQualitySample (returned by collect_tcp_quality)

#include <yuzu/agent/process_enum.hpp>

#ifndef _WIN32
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::{SubprocessResult,SubprocessOptions} — enumerate_services_impl's RunFn seam
#endif

#include <algorithm>
#include <cstdint>
#include <optional>
#include <functional> // enumerate_services_impl's injectable-runner RunFn (non-Windows)
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::tar {

// ── Operator-facing collect-status tokens ────────────────────────────────────
// The final field of the `tar|collect_<leg>|N|<token>` output lines. These are
// a documented operator contract (docs/yaml-dsl-spec.md `tar.collect_perf`;
// operator dashboards parse them) and are pinned verbatim by the unit tests —
// renaming one is a contract change, not a refactor. Two tokens describe a
// failed perf read: `unsupported_platform` when the running OS has no perf
// collector, `counters_unavailable` when it does (registry row is
// kSupported/kSupportedConstrained) but the core counter read failed (e.g. a
// masked /proc on Linux, a PDH/NT-counter failure on Windows). See
// read_failure_token().
inline constexpr std::string_view kCollectStatusSourceDisabled = "source_disabled";
inline constexpr std::string_view kCollectStatusUnsupportedPlatform = "unsupported_platform";
inline constexpr std::string_view kCollectStatusCountersUnavailable = "counters_unavailable";

/// Token for a failed perf/procperf counter read, decided by the registry's
/// support status for the running OS (OS-independent rule).
[[nodiscard]] constexpr std::string_view
read_failure_token(std::optional<OsSupportStatus> st) noexcept {
    return (st == OsSupportStatus::kSupported || st == OsSupportStatus::kSupportedConstrained)
               ? kCollectStatusCountersUnavailable
               : kCollectStatusUnsupportedPlatform;
}
inline constexpr std::string_view kCollectStatusBaseline = "baseline";
inline constexpr std::string_view kCollectStatusSampleRecorded = "sample_recorded";
inline constexpr std::string_view kCollectStatusAppsRecorded = "apps_recorded";
// Cursor-model seam (tar_cursor.hpp, CursorOutcome::Advanced/CursorLost) —
// power/removable's collect_slow status tokens, wave 2. `kCollectStatusBaseline`
// above is reused for CursorOutcome::Baseline (first-ever successful read, and
// the re-baseline that follows a CursorLost recovery).
inline constexpr std::string_view kCollectStatusCursorAdvanced = "cursor_advanced";
inline constexpr std::string_view kCollectStatusCursorLost = "cursor_lost";

/// A cursor source could not complete this tick: a transient read failure, an
/// unreadable cursor, or a permanent refusal from the store. It is written to
/// the collect stream deliberately, because the alternative -- writing NOTHING
/// and letting the source's line be absent -- is byte-identical to a healthy
/// source with no activity, and `status` keeps reporting it enabled with a
/// frozen row count. A capture that has stopped must be visible somewhere an
/// operator actually looks; spdlog is not that place.
inline constexpr std::string_view kCollectStatusCaptureIncomplete = "capture_incomplete";

// ── Collector data types ─────────────────────────────────────────────────────

struct NetConnection {
    std::string proto; // tcp, tcp6, udp, udp6
    std::string local_addr;
    std::string remote_addr;
    std::string remote_host; // reverse-DNS of remote_addr (resolved at collection time)
    int local_port{0};
    int remote_port{0};
    std::string state; // ESTABLISHED, LISTEN, etc.
    uint32_t pid{0};
    std::string process_name;
    // 0 = currently observed in /proc (live). >0 = observed in the TAR
    // warehouse N seconds ago; renderer can fade tubes older than live.
    // Wire-schema-gated emission: omitted when zero so old consumers and
    // pre-PR-9-pre snapshots stay byte-compatible (schema_minor 1 -> 2).
    int64_t last_seen_seconds_ago{0};
};

struct ServiceInfo {
    std::string name;
    std::string display_name;
    std::string status;       // running, stopped, etc.
    std::string startup_type; // automatic, manual, disabled

    // Windows-only (tar_service_collector.cpp): true when THIS service's own
    // OpenServiceW/QueryServiceConfigW call failed (a transient per-service
    // ACL/query hiccup -- not an SCM-wide enumeration failure, which throws
    // IncompleteCaptureError instead). startup_type is still set to "unknown"
    // in that case for display, but that "unknown" is NOT a legitimate
    // observation -- it must never be diffed as an authoritative value change
    // (compute_service_events/compute_service_diff both check this flag
    // before comparing startup_type), or a transient query failure
    // manufactures a false "automatic -> unknown" forensic event now and a
    // false inverse event on the next successful read. Always false on
    // Linux/macOS, where "unknown" from the systemctl/launchctl parsers is a
    // genuine observation (some services really don't expose a startup
    // type).
    bool startup_type_query_failed{false};
};

struct UserSession {
    std::string user;
    std::string domain;
    std::string logon_type; // interactive, remote, service
    std::string session_id;
};

/// One installed-software entry, as enumerated for the `software` source diff.
/// Machine scope only: an entry is the host's installed software (HKLM
/// Uninstall), never attributed to a Windows profile, so the capture carries no
/// per-user identity (#1620). The diff key is `name`; a change in `version` for
/// the same name is an 'upgraded' event.
struct SoftwareInfo {
    std::string name;
    std::string version;
    std::string publisher;
    std::string install_date;
};

// One host ARP / neighbour-table entry (ADR-0015). Snapshot type for the `arp`
// capture source; diffed into ArpEvent rows. Diff key = (interface, ip_address,
// mac_address); entry_type is a value field. All fields agent-controlled.
struct ArpEntry {
    std::string iface; // NB: 'interface' is a Win32 COM macro under full <windows.h>
    std::string ip_address;
    std::string mac_address;
    std::string entry_type; // dynamic, static, incomplete, other, unknown
};

// One host DNS resolver-cache entry (ADR-0015). Snapshot type for the `dns`
// capture source; diffed into DnsEvent rows. Diff key = (name, record_type,
// data); ttl_remaining_s is a value field (changes every tick, never keyed).
// The cache is system-wide and carries NO pid — there is no process attribution.
struct DnsEntry {
    std::string name;
    std::string record_type; // A, AAAA, CNAME, PTR, ...
    std::string data;
    int64_t ttl_remaining_s{0};
    std::string source; // cache, hosts_file, unknown
};

// One mapped-drive mapping (capability-map §3.8). Snapshot type for the
// `mapdrive` capture source; diffed into MapDriveEvent rows. Diff key =
// (direction, local_mount, remote_path, remote_host, username); `provider` is a
// value-only field (not keyed). NB: no field is named `interface` — that is a
// Win32 COM macro under full <windows.h>; keep it that way if fields are added.
struct MapDriveEntry {
    std::string direction;   // outbound (we map a remote share) | inbound (a remote host maps ours)
    std::string local_mount; // outbound: drive letter / mountpoint; inbound: accessed share (may be "")
    std::string remote_path; // outbound: \\server\share, //server/share, server:/export; inbound: ""
    std::string remote_host; // outbound: the server; inbound: the connecting client
    std::string username;    // outbound: mapping credential; inbound: authenticated account
    std::string provider;    // SMB / NFS / WebDAV / transport (value-only, not keyed)
};

// One historically-inferred mapping for the one-time init backfill. `entry` is a
// past mapping read from a persistent OS artifact (registry MRU/Network, fstab,
// Samba/Security log); `ts` is the artifact's timestamp (registry key last-write,
// event/log time) or 0 when the artifact carries no time (e.g. fstab). Inserted
// as `action='historical'`, `origin='historical'` rows that bypass the live diff.
struct MapDriveHistoryRow {
    MapDriveEntry entry;
    int64_t ts{0};
};

// ── Platform enumeration functions ────────────────────────────────────────────
//
// Adding a NEW capture source? Follow the core pattern these functions use
// (process/tcp/service/user, NOT the perf/procperf/netqual derived-metric tiers
// which are self-contained tar_<name>.{hpp,cpp}): collected type + enumerate_*()
// + compute_*_events() declared HERE, one tar_<source>_collector.cpp for the
// platform shell (no per-source header), diffs in tar_diff.cpp, row struct +
// insert_*_events in tar_db.{hpp,cpp}, one CaptureSourceDef in
// tar_schema_registry.cpp. Full recipe: docs/tar-implementer.md "Adding a
// capture source".

/**
 * Enumerate active network connections on the current host — a POLLED
 * snapshot (proc_pidfdinfo on macOS; see the platform .cpp for the other
 * OSes). Used unconditionally: it is the sole source on Linux/Windows, the
 * full live picture fleet_snapshot needs, and on macOS it doubles as the tcp
 * lifecycle's fallback/seed poll (roadmap 2.2) — TCP lifecycle events are
 * PRIMARILY sourced from the plugin-owned NstatClient event stream when it is
 * running() and system_wide() (see tar_plugin.cpp's collect_fast tcp leg,
 * which drains that stream directly and filters this poll's diff down to UDP
 * only for that tick); this function's own poll logic is unchanged and keeps
 * covering UDP always plus TCP whenever nstat is not running/stalled — never
 * a silent lifecycle gap, mirroring the ES-stream-with-poll-fallback shape
 * used for process_live.
 */
std::vector<NetConnection> enumerate_connections();

/**
 * Sample per-connection TCP quality (RTT + jitter + current loss + lifetime
 * retrans/segs context) for the netqual warehouse tier.
 *
 * Linux: netlink SOCK_DIAG / INET_DIAG TCP_INFO over ESTABLISHED connections,
 * owning process resolved via the socket inode.
 *
 * Windows (ADR-0020): TCP ESTATS (Get/SetPerTcp[6]ConnectionEStats) over the
 * ESTABLISHED table. Enabling stats is admin-only, so a NON-ELEVATED agent
 * latches to "records nothing" for the session (status reports
 * netqual_capture_method=none). Counters accrue from stats-enable — first
 * sight of a connection baselines it and emits nothing; samples start one
 * tick later, with the Windows field semantics documented in tar_netqual.hpp.
 *
 * macOS (roadmap 2.2): the plugin-owned NstatClient's snapshot_quality()
 * (com.apple.network.statistics kctl — see tar_netqual_nstat.hpp) when the
 * client is running() AND system_wide() (root; an unprivileged session sees
 * only its own flows, which is NOT complete capture — see
 * netqual_nstat_register_client below). Empty otherwise, INCLUDING a
 * layout_mismatch() session (running() already reflects that — the reader
 * thread self-stops on a wire-layout self-check failure).
 *
 * Returns RAW remote addresses; the caller MUST pass the result through
 * select_netqual_rows (which buckets the address away) before persisting —
 * raw destinations never reach the warehouse.
 */
std::vector<TcpQualitySample> collect_tcp_quality();

class NstatClient; // tar_netqual_nstat.hpp — fwd-declared, full type not needed here

/**
 * Registers the plugin-owned NstatClient (tar_netqual_nstat.hpp) so the
 * macOS legs of collect_tcp_quality() / netqual_effective_capture_method()
 * can reach its live state without a second, independently-owned client.
 *
 * Non-owning: tar_plugin.cpp is the SOLE owner — it constructs, start()s,
 * and stop()s the client (mirroring the ES process-stream lifecycle
 * discipline; see the nstat spike memo §4.3 — one consumer surface, no
 * broker needed). Call with the live client right after construction; call
 * with nullptr before stop() at shutdown so a call racing teardown observes
 * "no client" rather than a client mid-destruction (narrows, does not by
 * itself eliminate, the same collect-vs-shutdown window the ES process
 * stream already accepts under collect_mu_ — see tar_plugin.cpp shutdown()).
 *
 * Declared and callable on EVERY platform (tar_plugin.cpp calls it
 * unconditionally, matching NstatClient's own "inert off-macOS" contract) —
 * the Linux/Windows implementations are one-line no-ops.
 */
void netqual_nstat_register_client(NstatClient* client);

/**
 * The netqual capture method actually in effect on this host right now:
 * "inetdiag" (Linux), "estats" (Windows once the elevation gate has latched
 * active), "estats_pending" (Windows, netqual enabled but the first collect tick
 * has not yet tested elevation — or netqual disabled), "nstat" (macOS, roadmap
 * 2.2, ONLY while the registered NstatClient is running() AND system_wide() —
 * see netqual_nstat_register_client), "none" (Windows after the ACCESS_DENIED
 * latch; macOS when no client is registered, the client isn't running, it is
 * scoped to own-process flows only, or a layout_mismatch() forced it inert;
 * other unsupported platforms). The pending token exists so a non-elevated
 * agent does not advertise "estats" for the first interval before flipping to
 * "none". Surfaced by the status action as `config|netqual_capture_method|
 * <token>` — mirrors the process/module capture-method pattern. Honesty
 * invariant (memo §3): NEVER "nstat" for an own-process-only or
 * layout-mismatched session — that is reported "none", never a silently
 * partial capture.
 */
std::string_view netqual_effective_capture_method();

/** Enumerate installed system services on the current host. */
std::vector<ServiceInfo> enumerate_services();

#ifndef _WIN32
/**
 * Finding 3 (Wave 5 PR5.2 round) seam: the Linux/macOS enumerate_services()
 * bodies, parameterised over the subprocess runner
 * (agents/core/include/yuzu/agent/subprocess_runner.hpp's
 * run_bounded_subprocess signature) so tests/unit/test_tar_service.cpp can
 * inject a fixture double and assert the EXACT argv/options systemctl and
 * launchctl are invoked with, plus that a spawn-failure/timeout/output-cap/
 * non-zero-exit fixture result throws IncompleteCaptureError through this
 * real function -- never a hand-simulated stand-in. enumerate_services()
 * above is the production entry point and always calls this with the real
 * run_bounded_subprocess. Not declared on Windows: that leg uses
 * EnumServicesStatusExW, not a subprocess.
 */
std::vector<ServiceInfo> enumerate_services_impl(
    const std::function<yuzu::agent::SubprocessResult(
        const std::vector<std::string>&, const yuzu::agent::SubprocessOptions&)>& run);
#endif

/** Enumerate active user sessions on the current host. */
std::vector<UserSession> enumerate_users();

/**
 * Installed-software enumeration for the `software` source: machine-wide only
 * (HKLM Uninstall 64-bit + WOW6432Node 32-bit). Cheap — no hive mounts, no
 * per-user identity. This is the sole enumeration entry point (cold-start and
 * steady-state alike read the same machine scope). Empty off Windows (kPlanned;
 * a fast-follow will reuse the installed_apps dpkg/rpm/pkgutil enumeration).
 */
void enumerate_machine_software(std::vector<SoftwareInfo>& out);

/**
 * Enumerate the host ARP / neighbour table (ADR-0015). Implemented on Windows
 * (GetIpNetTable2/AF_UNSPEC), Linux (/proc/net/arp), and macOS (the shared
 * NET_RT_FLAGS/RTF_LLINFO sysctl fetch) -- see os-capability-matrix.md for the
 * platform-specific field constraints (e.g. macOS's entry_type is always
 * "unknown" and iface is always empty). Hard-capped at kArpEntryCap entries.
 * Completeness contract: THROWS yuzu::tar::IncompleteCaptureError rather than returning a
 * partial vector when the platform read failed, the kernel/parser reported a
 * truncated read, or the cap was reached before the whole table was consumed
 * (tar_capture_status.hpp) -- callers MUST NOT diff or persist a caught
 * exception's snapshot as though it were a genuinely smaller/empty table; see
 * collect_or_retain() and its call sites in tar_plugin.cpp.
 */
std::vector<ArpEntry> enumerate_arp();

/**
 * Enumerate the host DNS resolver cache (ADR-0015). Windows: DnsGetCacheDataTable.
 * Hard-capped at kDnsEntryCap entries (warn on truncation). The cache is
 * system-wide (no process attribution). Returns `{}` off Windows for now.
 */
std::vector<DnsEntry> enumerate_dns();

/**
 * Enumerate CURRENT mapped drives in both directions (capability-map §3.8) for
 * the live snapshot-diff. Windows: outbound via WNetOpenEnumW/WNetEnumResourceW
 * (+ WNetGetUserW), inbound via NetSessionEnum (degrades to empty without
 * admin/Server-Operator). Linux: outbound via /proc/mounts network fstypes,
 * inbound via `smbstatus` (empty if Samba absent). macOS: outbound only, via
 * getfsstat(2) (no inbound/historical visibility for an unprivileged agent).
 * Hard-capped at kMapDriveEntryCap.
 * Completeness contract: THROWS yuzu::tar::IncompleteCaptureError rather than returning a
 * partial vector when the underlying capture didn't genuinely complete -- a
 * subprocess capture that didn't run to completion (this LIVE leg's own
 * subprocess is Linux `smbstatus` only -- Windows live outbound/inbound is
 * native WNet/NetSessionEnum, not a subprocess; `wevtutil`/`journalctl` are
 * enumerate_mapdrive_history()'s one-time backfill subprocesses, a separate
 * completeness contract documented below; both legs share
 * tar_capture_status.hpp's classify_subprocess_capture), or on macOS a
 * getfsstat(2) failure or an over-cap snapshot (tar_mapdrive_collector.cpp).
 * Callers MUST NOT diff or persist a caught exception's snapshot as though it were a genuinely
 * smaller/empty mount table; see collect_or_retain() and its call sites in
 * tar_plugin.cpp.
 */
std::vector<MapDriveEntry> enumerate_mapdrive();

/**
 * Enumerate PREVIOUS (historical) mapped drives for the one-time init backfill
 * (capability-map §3.8). Windows: outbound from HKCU\Network + Map Network Drive
 * MRU + MountPoints2 across offline profiles (ts = subkey last-write), inbound
 * from Security event log 4624 (logon_type=3 network) logons (ts = event time).
 * Linux: outbound from /etc/fstab (ts=0), inbound from Samba logs (ts = log time).
 * Returns `{}` on macOS. Deduplicated by mapping identity, capped at
 * kMapDriveHistoryCap.
 */
std::vector<MapDriveHistoryRow> enumerate_mapdrive_history();

/**
 * Collapse duplicate historical rows by mapping identity (direction, local_mount,
 * remote_path, remote_host, username), keeping the smallest non-zero timestamp
 * (earliest known sighting), and apply kMapDriveHistoryCap. Declared here so it is
 * unit-testable (the enumerate_* callers are I/O-gated).
 */
std::vector<MapDriveHistoryRow> dedup_history(std::vector<MapDriveHistoryRow> rows);

// ── Pure text parsers for the mapdrive collector (no I/O — unit-tested) ────────
// The platform shell does the I/O (subprocess / registry / file read) and hands
// the raw text to these; keeping the parse pure makes every leg testable off its
// native OS from captured sample output.

/** Result of parsing /proc/mounts text: the decoded network-mount entries
 *  plus whether at least one row was malformed (structurally short --
 *  fewer than 3 whitespace-separated fields -- and so dropped rather than
 *  silently included/omitted). Mirrors tar_arp_parsers.hpp's
 *  ProcNetArpParse{entries, malformed} shape (BR4-005) and
 *  tar_service_parsers.hpp's ServiceParseResult: a malformed row is a
 *  missing binding relative to a genuinely complete mount table, and the
 *  CALLER (enumerate_mapdrive(), tar_mapdrive_collector.cpp) is the one
 *  that turns this flag into an IncompleteCaptureError throw. A row that is
 *  well-formed but simply not a network filesystem (is_network_fstype()
 *  returns false) is a LEGITIMATE skip and never sets `malformed`. */
struct ProcMountsParse {
    std::vector<MapDriveEntry> entries;
    bool malformed{false};
};

/** Parse `/proc/mounts` (or /proc/self/mountinfo-style) text into current
 *  outbound network mappings. Honours the kernel `\040`/`\011` octal escaping. */
ProcMountsParse parse_proc_mounts(const std::string& text);

/** Parse `/etc/fstab` text into historical outbound network mappings (ts=0). */
std::vector<MapDriveHistoryRow> parse_fstab(const std::string& text);

/** Result of parsing `smbstatus -b`/`-S` text: the decoded inbound session
 *  entries plus whether at least one row was malformed. Same {entries,
 *  malformed} shape as ProcMountsParse above (BR-mapdrive-001) and
 *  tar_arp_parsers.hpp's ProcNetArpParse (BR4-005) -- Finding 4
 *  (adversarial-review round 5) closed the one site in this file that had
 *  been missed. A row is malformed when it LOOKS LIKE it was attempting to
 *  be a data row (its first token is a non-empty, purely-numeric PID) but
 *  is structurally short (fewer than the 4 whitespace-separated fields a
 *  real session row carries) -- a truncated/corrupt capture. A row whose
 *  first token is not a bare PID (the header line, a blank separator, a
 *  "No locked files" trailer, etc.) is a LEGITIMATE skip and never sets
 *  `malformed`, exactly mirroring parse_proc_mounts's is_network_fstype
 *  legitimate-skip-vs-malformed judgement. */
struct SmbStatusParse {
    std::vector<MapDriveEntry> entries;
    bool malformed{false};
};

/** Parse `smbstatus -b`/`-S` text into current inbound (client) sessions. */
SmbStatusParse parse_smbstatus(const std::string& text);

/** Parse `wevtutil qe Security … /f:text` output into historical inbound rows:
 *  4624 events with logon_type=3 (network), ts = event time. 4634 (logoff) blocks
 *  are ignored — the collector queries 4624 only. */
std::vector<MapDriveHistoryRow> parse_win_security_logons(const std::string& text);

/** Parse Samba `log.smbd` / `journalctl -u smbd` text into historical inbound
 *  connect events (ts = log line time). */
std::vector<MapDriveHistoryRow> parse_samba_logs(const std::string& text);

/// Per-cycle collection caps (ADR-0015 §"Memory bound"). The collector stops
/// enumerating at the cap and logs a truncation warning rather than growing
/// unbounded.
inline constexpr std::size_t kArpEntryCap = 2048;
inline constexpr std::size_t kDnsEntryCap = 4096;
/// Live mapped-drive snapshot cap (inbound sessions on a file server can be many).
inline constexpr std::size_t kMapDriveEntryCap = 4096;
/// Historical-backfill cap. Kept below mapdrive_live's row-count retention
/// (retention_default = 5000) so a one-shot backfill cannot alone overflow the
/// live tier and evict its own rows on the first retention pass; historical rows
/// share the live row budget with subsequent live diff rows (mapped drives are
/// low-cardinality, so this is a safety backstop, not an expected limit).
inline constexpr std::size_t kMapDriveHistoryCap = 4096;
/// Per-cycle cap on installed-software entries (machine + all per-user hives in
/// one tick). Sized to hold a bloated many-profile RDS/Citrix host's full
/// inventory while bounding memory + tick duration on a corrupt/huge registry
/// (#1620). A truncated tick warns once (rate-limited) — see
/// tar_software_collector.cpp.
inline constexpr std::size_t kSoftwareEntryCap = 8192;

// ── Redaction ────────────────────────────────────────────────────────────────

/**
 * Check if a command line matches any redaction pattern.
 * Patterns use case-insensitive substring matching with the '*' prefix/suffix
 * stripped (e.g. "*password*" matches any cmdline containing "password").
 *
 * @param cmdline   The command line to check.
 * @param patterns  Case-insensitive substring patterns (e.g. {"*password*", "*secret*"}; leading/trailing `*` are stripped, the rest is a literal substring).
 * @return true if the cmdline should be redacted.
 */
bool should_redact(const std::string& cmdline, const std::vector<std::string>& patterns);

/**
 * Apply redaction to a command line string.
 * If the cmdline matches any pattern, returns "[REDACTED by TAR]".
 * Otherwise returns the original cmdline.
 */
std::string redact_cmdline(const std::string& cmdline, const std::vector<std::string>& patterns);

/**
 * Default redaction patterns.
 */
inline const std::vector<std::string> kDefaultRedactionPatterns = {
    "*password*", "*secret*", "*token*", "*api_key*", "*credential*"};

/**
 * Guarantee the built-in redaction defaults are present in `loaded`, appending
 * any that are absent (order-preserving, de-duplicated). This is the fail-closed
 * redaction invariant: an operator can ADD patterns via `tar.configure` but can
 * never DISABLE the baseline protection, so no stored value — empty, a non-array,
 * a valid array whose elements were all dropped by parse_pattern_config (`[]`,
 * `[1,2,3]`, all-over-long), or one whose only entry has an empty stripped core
 * (`["*"]`) — can ever cause `password`/`token`/`secret` to be written to
 * `process_live` in plaintext. Every collect path (collect_fast, procperf,
 * fleet_snapshot) routes its loaded patterns through here. (fjarvis #1532 HIGH.)
 */
inline std::vector<std::string>
ensure_redaction_defaults(std::vector<std::string> loaded) {
    for (const auto& def : kDefaultRedactionPatterns) {
        if (std::find(loaded.begin(), loaded.end(), def) == loaded.end())
            loaded.push_back(def);
    }
    return loaded;
}

// ── Diff functions ───────────────────────────────────────────────────────────

/**
 * Compute process diff between two snapshots.
 * Detects process births (started) and deaths (stopped).
 * Key: PID (since PIDs are reused, name mismatch on same PID counts as
 * death + birth).
 * Command lines are redacted before storing in detail_json.
 *
 * @param previous    Previous process snapshot.
 * @param current     Current process snapshot.
 * @param timestamp   Epoch seconds for the events.
 * @param snapshot_id Correlating snapshot identifier.
 * @param redaction_patterns  Patterns for cmdline redaction.
 */
std::vector<TarEvent> compute_process_diff(
    const std::vector<yuzu::agent::ProcessInfo>& previous,
    const std::vector<yuzu::agent::ProcessInfo>& current, int64_t timestamp, int64_t snapshot_id,
    const std::vector<std::string>& redaction_patterns = kDefaultRedactionPatterns);

/**
 * Compute network connection diff.
 * Key: proto + local_addr + local_port + remote_addr + remote_port.
 * Detects new connections (connected) and closed connections (disconnected).
 */
std::vector<TarEvent> compute_network_diff(const std::vector<NetConnection>& previous,
                                           const std::vector<NetConnection>& current,
                                           int64_t timestamp, int64_t snapshot_id);

/**
 * Compute service diff.
 * Key: service name.
 * Detects service births (started), deaths (stopped), and state changes
 * (status or startup_type changed).
 */
std::vector<TarEvent> compute_service_diff(const std::vector<ServiceInfo>& previous,
                                           const std::vector<ServiceInfo>& current,
                                           int64_t timestamp, int64_t snapshot_id);

/**
 * Compute user session diff.
 * Key: user + session_id.
 * Detects logins (login) and logouts (logout).
 */
std::vector<TarEvent> compute_user_diff(const std::vector<UserSession>& previous,
                                        const std::vector<UserSession>& current, int64_t timestamp,
                                        int64_t snapshot_id);

// ── Typed event diff functions (for warehouse live tables) ──────────────────

std::vector<ProcessEvent> compute_process_events(
    const std::vector<yuzu::agent::ProcessInfo>& previous,
    const std::vector<yuzu::agent::ProcessInfo>& current, int64_t timestamp, int64_t snapshot_id,
    const std::vector<std::string>& redaction_patterns = kDefaultRedactionPatterns);

std::vector<NetworkEvent> compute_network_events(const std::vector<NetConnection>& previous,
                                                 const std::vector<NetConnection>& current,
                                                 int64_t timestamp, int64_t snapshot_id);

std::vector<ServiceEvent> compute_service_events(const std::vector<ServiceInfo>& previous,
                                                 const std::vector<ServiceInfo>& current,
                                                 int64_t timestamp, int64_t snapshot_id);

std::vector<UserEvent> compute_user_events(const std::vector<UserSession>& previous,
                                           const std::vector<UserSession>& current,
                                           int64_t timestamp, int64_t snapshot_id);

/**
 * Compute software install/uninstall diff.
 * Key: name (machine scope only — no per-user identity).
 * Detects installs (present in current, not previous), removals (present in
 * previous, not current), and upgrades (same name, different version — carries
 * prev_version). The diff is name-keyed, so a version bump is one 'upgraded'
 * event rather than a remove+install pair.
 */
std::vector<SoftwareEvent> compute_software_events(const std::vector<SoftwareInfo>& previous,
                                                   const std::vector<SoftwareInfo>& current,
                                                   int64_t timestamp, int64_t snapshot_id);

/**
 * Compute ARP diff. Key: interface + ip_address + mac_address.
 * Detects bindings that appeared (`appeared`) and disappeared (`removed`). A
 * changed entry_type on an otherwise-identical binding is NOT an event (value
 * update only), so a flapping dynamic/static flag does not churn the warehouse.
 */
std::vector<ArpEvent> compute_arp_events(const std::vector<ArpEntry>& previous,
                                         const std::vector<ArpEntry>& current,
                                         int64_t timestamp, int64_t snapshot_id);

/**
 * Compute DNS-cache diff. Key: name + record_type + data.
 * Detects resolutions that appeared (`appeared`) and aged out (`removed`). The
 * ttl_remaining_s value is carried on the row but excluded from the key, so the
 * per-tick TTL decrement does not produce spurious appeared/removed churn.
 */
std::vector<DnsEvent> compute_dns_events(const std::vector<DnsEntry>& previous,
                                         const std::vector<DnsEntry>& current,
                                         int64_t timestamp, int64_t snapshot_id);

/**
 * Compute mapped-drive diff (capability-map §3.8).
 * Key: direction + local_mount + remote_path + remote_host + username.
 * Detects mappings that appeared (`appeared`) and disappeared (`removed`); a
 * changed `provider` on an otherwise-identical mapping is NOT an event (value
 * update only). Every emitted row is stamped `origin='live'` — historical rows
 * never flow through this diff (they are inserted directly by the backfill).
 * `direction` and `username` are keyed so an outbound map and an inbound session
 * that share host/user do not collide, and a re-credentialed mount is a genuine
 * removed+appeared pair.
 */
std::vector<MapDriveEvent> compute_mapdrive_events(const std::vector<MapDriveEntry>& previous,
                                                   const std::vector<MapDriveEntry>& current,
                                                   int64_t timestamp, int64_t snapshot_id);

} // namespace yuzu::tar
