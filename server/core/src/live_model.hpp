#pragma once

/// @file live_model.hpp
/// PURE "live device read" model: the ONE kind table, the typed row models and the
/// plugin-output parsers behind the /device "Get live info" feature.
///
/// The feature has two surfaces: the dashboard HTML path (device_routes.cpp
/// render_live_result + the device_ui.cpp renderers) and the agentic-first REST JSON
/// path (rest_api_v1.cpp live_result_json). Both dispatch the SAME read-only
/// instructions and parse the SAME wire formats, so the kind->(plugin, action,
/// audit verb) table and every wire-format parser live here and nowhere else: a
/// wire-format change on the agent moves this unit, not two translation units in
/// lockstep (governance architect S2, #1649). This unit replaces the former
/// header-only live_kinds.hpp.
///
/// Purity: no store, httplib or HTML. Enrolled in the `device` seam-closure family
/// (scripts/ci/check-seam-closure.py), so a store include here fails CI.
///
/// ONE table, two views. All 22 kinds the dashboard offers are rows of the table; the
/// REST route accepts only the rows flagged `rest_v1` (today `uptime` and `processes`).
/// resolve_dashboard_kind() and resolve_rest_kind() are the only two ways to look a
/// kind up, so widening the REST surface never needs a second table. It is NOT a
/// one-flag change, though: it takes flipping `rest_v1` on the row AND teaching
/// live_result_json (rest_api_v1.cpp) the kind, because that function renders every
/// kind other than `uptime` as the processes shape.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// ── Typed row models (shared with the device_ui.cpp renderers) ───────────────────
// All agent fields are untrusted bytes; HTML escaping happens at render, never here.
namespace yuzu::server {

/// One live process row: PID + name + the SHA-256 of its on-disk image + the
/// resolved executable path (hash/path empty when unresolved).
struct LiveProcess {
    int pid = 0;
    std::string name;
    std::string sha256; ///< lowercase hex; "" if unresolved / too large / gone
    std::string path;   ///< resolved exe path; "" if unresolved
};

/// One node of the live process tree (processes/list_tree → proc|pid|ppid|name|sha256|path).
struct LiveProcNode {
    std::uint32_t pid = 0;
    std::uint32_t ppid = 0;
    std::string name;
    std::string sha256; ///< lowercase hex; "" if unresolved
    std::string path;   ///< resolved exe path; "" if unresolved
};

/// One live TCP entry joined to a tree node by pid (network_diag/connections, Windows
/// emits the owning pid). `listening` rows have no remote endpoint.
struct LiveConn {
    std::uint32_t pid = 0;
    std::string remote_addr; ///< "" for a listener
    int remote_port = 0;
    int local_port = 0;
    bool listening = false;
};

struct LiveArpEntry { std::string iface, ip, mac, type; };
struct LiveDnsEntry { std::string name, record_type; };
struct LiveListen { std::string proto, ip; int port = 0; long long pid = 0; };
struct LiveConnRow { std::string proto, local, remote, state; };
struct LiveService { std::string name, display, status, startup; };
struct LiveUserRow { std::string user, host, logon_type, session; };
struct LiveNetAddr { std::string adapter, ip; int prefix = 0; std::string gateway; };
/// One volume's capacity reading (disk_space/free → disk|<path>|<total>|<free>|<percent_used>).
struct LiveDiskVolume { std::string path; long long total = 0, free = 0; int percent_used = 0; };
/// One Echo capture source's local state (echo/status → config|<src>_enabled / _rows).
/// `dollar`/`category` are server-side presentation metadata (the agent schema registry
/// is not linked into the server, so the source list is hand-held in live_model.cpp;
/// only sources the agent actually reports are returned).
struct LiveCaptureSource {
    std::string name, dollar, category;
    bool enabled = false;
    long long live_rows = -1; ///< -1 = unknown (no count reported)
};

} // namespace yuzu::server

namespace yuzu::server::live {

/// Bound on parsed rows per source: a forged or huge response can shrink the rendered
/// set but never blow up memory or produce an unrenderable card (SRE finding).
inline constexpr std::size_t kMaxLiveRows = 20000;

/// One "Get live info" panel = one real plugin instruction dispatched at the device
/// NOW. `kind` is an ALLOWLIST token; each kind carries its own audit verb so a
/// usage-class read (what processes a person runs) stays separately countable from a
/// machine-health read (uptime), the works-council access-audit posture.
///
/// Set new fields BY NAME (designated initialisers or an assignment after
/// construction), never positionally: a positional bool added after `columns` would
/// silently bind to `rest_v1` (a positional bool port was the hazard raised in review
/// of the in-flight #8122, which adds `bool escaped_rows`). The `rest == {uptime,
/// processes}` pin in test_live_model.cpp is the tripwire for such a mis-port.
struct LiveKind {
    std::string plugin;
    std::string action;
    std::string label;
    std::string audit_action;
    /// Optional SECONDARY dispatch joined at render (the dashboard process_tree card
    /// dispatches network_diag/connections alongside processes/list_tree and joins by
    /// PID). Empty for kinds with no join. The REST route ignores these: it does not
    /// serve the multi-card kinds.
    std::string plugin2;
    std::string action2;
    /// Generic pipe-row rendering (the ten physical-kit panels). A non-empty `columns`
    /// means the kind's output is a flat `<row_prefix>|field1|field2|...` table with no
    /// bespoke typed-row struct: parse_generic_rows() + render_device_live_generic()
    /// handle it. Both stay empty for every kind with a bespoke parser/renderer.
    std::string row_prefix;
    std::vector<std::string> columns;
    /// True iff the REST route /api/v1/dex/devices/{id}/live accepts this kind. Exactly
    /// the rows that rest_api_v1.cpp's live_result_json can render; widening the REST
    /// surface means flipping this flag AND teaching that function the kind.
    bool rest_v1{false};
};

/// Any of the 22 dashboard kinds (the closed allowlist the dashboard routes accept).
///
/// Invariant (carried over from the deleted resolve_live_kind): the caller's `kind` string
/// is an ALLOWLIST token and must be resolved here (or by resolve_rest_kind) BEFORE it
/// drives any dispatch or reaches markup. device_routes.cpp's render_live_result
/// interpolates the raw `kind` into the markup id `ls-cnt-<kind>` for the generic
/// physical-kit kinds; that is safe only because its sole caller, the live result route,
/// answers 400 on an unresolved kind first (the live run route resolves first too, before
/// it dispatches). Never call it with an unresolved kind.
std::optional<LiveKind> resolve_dashboard_kind(const std::string& kind);

/// The REST v1 subset: only rows flagged `rest_v1` (uptime, processes).
std::optional<LiveKind> resolve_rest_kind(const std::string& kind);

// ── Line / field helpers ─────────────────────────────────────────────────────────

/// Split newline-joined write_output() lines: tolerate a trailing '\r' and drop empty
/// lines (matches both legacy renderers).
std::vector<std::string> split_lines(const std::string& output);

/// Split one pipe-delimited line into fields (empty trailing field preserved).
std::vector<std::string> pipe_fields(const std::string& line);

// ── Typed parsers (bounds-safe on any input; a malformed line is skipped or yields a
// best-effort row, never an out-of-range access) ──────────────────────────────────

struct ProcRow {
    std::int64_t pid{0};
    std::string name;
    std::string sha256;
    std::string path;
};

/// Parse `proc|pid|name|sha256|path` rows (tolerate the shorter `proc|pid|name` and
/// `proc|pid|name|sha256` forms).
std::vector<ProcRow> parse_processes(const std::string& output);

struct Uptime {
    std::optional<std::string> display; // present iff an `uptime_display|` line existed
    std::optional<std::int64_t> seconds;
};

Uptime parse_uptime(const std::string& output);

/// processes/list_tree: `proc|pid|ppid|name|sha256|path`. A pid above UINT32_MAX drops the
/// row; a ppid above it (or unparseable) becomes 0 (root).
std::vector<LiveProcNode> parse_process_tree(const std::string& output);

/// network_diag/connections for the process_tree join: `conn|tcp|lip|lport|rip|rport|pid`
/// (Windows emits the pid). A pid above UINT32_MAX drops the row.
std::vector<LiveConn> parse_process_conns(const std::string& output);

struct LiveServices {
    std::vector<LiveService> rows;
    int running = 0; ///< rows whose status contains "run" (case-insensitive)
};

/// services/list. Windows `svc|name|display|status|startup`, Linux
/// `svc|name|status|desc`, macOS `svc|label|pid|status[|startup]`. `agent_os` is the
/// device record's OS (authoritative; "darwin"/"macos" selects the macOS shapes); empty
/// when the lookup was unavailable, in which case 4-field rows are content-sniffed and
/// 5-field rows default to the Windows shape.
LiveServices parse_services(const std::string& output, const std::string& agent_os);

std::vector<LiveUserRow> parse_users(const std::string& output);
std::vector<LiveNetAddr> parse_netconfig(const std::string& output);
std::vector<LiveArpEntry> parse_arp(const std::string& output);
std::vector<LiveDnsEntry> parse_dns_cache(const std::string& output);
std::vector<LiveListen> parse_listening(const std::string& output);
std::vector<LiveConnRow> parse_connections(const std::string& output);

struct LiveCaptureSources {
    std::vector<LiveCaptureSource> rows;
    int on = 0; ///< rows whose source is enabled
};

/// echo/status: `config|<src>_enabled|v`, `config|<src>_rows|N`. A row exists only for a
/// source the agent reported (its `<src>_enabled` key is present).
LiveCaptureSources parse_capture_sources(const std::string& output);

struct LiveDisks {
    std::vector<LiveDiskVolume> rows;
    int worst_used = -1; ///< highest %-used over MEASURED (total > 0) volumes; -1 = none
};

/// disk_space/free: `disk|<path>|<total>|<free>|<percent_used>`; percent clamped 0..100.
LiveDisks parse_disk(const std::string& output);

struct LiveGenericRows {
    std::vector<std::vector<std::string>> rows; ///< prefix token dropped, padded/trimmed to columns
    std::vector<std::string> raw_rows;          ///< non-matching lines, preserved verbatim
};

/// The ten physical-kit kinds: flat `<row_prefix>|field...` rows per `kind.columns`. A line
/// under any other prefix is kept verbatim in `raw_rows`. Bounds: `rows` never exceeds
/// kMaxLiveRows (parsing stops once it reaches it), and a raw line is kept only while
/// rows.size() + raw_rows.size() is still below kMaxLiveRows. The two bounds are
/// therefore NOT one combined cap: raw lines arriving before the data rows can fill
/// raw_rows to kMaxLiveRows and rows can then still grow to kMaxLiveRows, so the
/// combined total can reach 2 x kMaxLiveRows.
LiveGenericRows parse_generic_rows(const LiveKind& kind, const std::string& output);

} // namespace yuzu::server::live
