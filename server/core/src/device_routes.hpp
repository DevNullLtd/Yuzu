#pragma once

/// @file device_routes.hpp
/// The SHARED device surfaces: the fleet `/devices` list (find a device) and the
/// per-device `/device?id=` page (the entity, with lens tabs). Reached from any
/// dashboard across Yuzu; the device is the entity, DEX / Guardian / inventory are
/// LENSES on it (mockups: docs/mockups/devices.html + device-detail.html).
///
/// Product UI: HTMX, server-rendered, dark-theme only, htmx core attrs only
/// (CSP blocks hx-on — onclick/oninput helpers instead). Reuses the shared
/// full-page shell (guardian_page_ui.cpp kGuardianDetailPageHtml) + its `.gp-*`
/// component CSS — same chrome as the Guardian/DEX/Network detail pages.
///
/// SLICE 1 (this file): the navigable shell + the DEVICE-INFO lens, sourced from
/// the live AgentRegistry (real identity + online + last-seen + tags). The DEX
/// lens (reuses render_dex_device_fragment + a per-device score — gated on the
/// parked per-device-scoring decision), the GUARDIAN lens
/// (guardian_agent_rule_status + BaselineStore), and the cross-cutting LIVE-INFO
/// pull (send_to + executions/SSE, privacy-gated) land in later slices. Those
/// lens tabs render an honest "coming in a later slice" placeholder for now.
///
/// AUTH: the `/devices` + `/device` page shells are auth-only chrome (they carry no
/// fleet data — only a title + the fragment URL to load), matching the sibling
/// `/dex` shell. The DATA-bearing routes are gated like `/api/agents`:
///   * the fleet LIST (`/fragments/devices/list`) requires global Infrastructure:Read
///     (`perm_fn`) and is filtered against `visible_set_fn` (the SAME confinement
///     `get_visible_agents_json` in server.cpp applies) — exact parity with
///     `/api/agents`;
///   * every PER-DEVICE route (page/info + the live pull) gates on `scoped_perm_fn`
///     = `require_scoped_permission(<securable>,<op>,id)`, the codebase's tier +
///     management-group chokepoint, so an operator can only open / read /
///     live-query a device inside their management scope (a global grant OR a role
///     assigned on the device's group / an ancestor). The live pull keeps its
///     Execute probe (htmx-friendly note) on top of the scoped Read floor.
///
/// ADR-0031 WS-A4 wave 2: identity/list data is sourced from the store-free
/// `DeviceApi` seam (`device_api.hpp`) rather than a direct `AgentRegistry`/
/// `TagStore` reach — this TU is part of the `device` family's seam-closure
/// enforced set (`scripts/ci/check-seam-closure.py`). The DEX + Guardian device
/// lenses (`/fragments/device/dex`, `/fragments/device/guardian`) moved OUT to
/// `device_lens_routes.{hpp,cpp}` — deliberately outside that enforced set, see
/// that file's own banner for why.

#include <yuzu/server/auth.hpp>

#include "device_api.hpp"      // DeviceApi, DeviceListRow, DeviceDetail, DeviceReadError (ADR-0031 WS-A4)
#include "dex_view_types.hpp"  // DexDispatchFn/DexResponsesFn/DexAuditFn/DexAgentResponse (store-free)

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

class HttpRouteSink;

// ── Shared builders (REST-only today; #4033/#2146 Batch A) ─────────────────
// PURE JSON builders — no httplib.h, no mcp_jsonrpc.hpp — used TODAY only by
// REST's GET /api/v1/devices[/{id}]. MCP's pre-existing list_agents/
// get_agent_details tools independently build an IDENTICAL 5-field shape
// inline (mcp_server.cpp) — they are NOT refactored onto these by this PR
// (out of scope; see #4033), so this pair does NOT yet satisfy the twin
// recipe's Rule 1 (docs/api-twin-recipe.md §1: REST, MCP, and the dashboard
// fragment must call the SAME function so no two transports can drift).
// Fixed by adversarial review (#4033 follow-up): an earlier version of this
// comment claimed Rule 1 was already satisfied across REST+MCP — false; the
// ledger's `twinned` status for these rows reflects the ledger's own
// weaker, verified capability-level definition (docs/api-parity-ledger.md:
// "a twin exists and is verified against the current source" — the 5-field
// shape IS byte-identical across REST/MCP today), not Rule-1 same-function
// conformance. Built from `DeviceApi`'s own typed rows (ADR-0031 WS-A4 wave 2
// rewire — previously a raw `AgentRegistry` JSON entry; the served field set
// is unchanged: agent_id/hostname/os/arch/agent_version) — deliberately NOT
// `DeviceRow` (the dashboard-fragment-only richer shape with online/tags/
// dex_score; see this file's header). The builders exist so the NEW REST
// routes match those tools' served shape byte-for-byte from day one, and so
// a future refactor of the MCP handlers has a function to call instead of a
// third inline copy.

/// PURE: one device row — `agent_id`/`hostname`/`os`/`arch`/`agent_version`,
/// straight off `DeviceApi::DeviceListRow`'s fields (already defensively
/// extracted at the seam — see `device_api.hpp`). Mirrors MCP
/// `list_agents`'s inline row-building exactly.
nlohmann::json device_agent_row_json(const DeviceListRow& row);

/// PURE: the device DETAIL object — `device_agent_row_json`'s fields plus a
/// `tags` array (`{key,value,source}` per entry) built from
/// `DeviceApi::DeviceDetail::tags`. ADR-0031 WS-A4 wave 2: `DeviceApi` always
/// returns an (possibly empty) tags vector — a null/unwired `TagStore` at the
/// seam degrades to an empty vector, not an omitted key (see
/// `device_api_local.hpp`'s own doc comment on `make_local_device_api`) — so,
/// unlike the pre-rewire version of this function, `tags` is now ALWAYS
/// present in the emitted JSON, never omitted. This is a deliberate,
/// already-committed (wave 1) seam decision, not a new one made here.
nlohmann::json device_agent_detail_json(const DeviceDetail& detail);

/// One row of the fleet device list / the identity of one device. SLICE 1 carries
/// only what the thin AgentInfo + registry session provide for real; richer CI /
/// DEX / Guardian columns are added by later slices (see file header).
///
/// ADR-0031 WS-A4 wave 2: built consumer-side from `DeviceApi`'s narrower
/// public rows (`DeviceListRow`/`DeviceDetail`), which do not carry a
/// management-group/segment or the agent's live-session `scopable_tags`.
/// `segment` is DELETED (never assigned anywhere in the tree even before this
/// rewire — confirmed by a full-tree grep, not merely unused by this file).
/// `tags` is KEPT for source compatibility with the renderers but is now
/// ALWAYS empty: `DeviceApi` has no bulk/live "scopable tags" read (that was
/// the AgentRegistry session's OWN ephemeral tag set, a different concept
/// from the persistent `TagStore` operator tags `DeviceApi::DeviceDetail`
/// carries) — this HONESTLY DROPS the dashboard list's tag-search capability
/// (`matches()` in device_routes.cpp), a deliberate, documented behaviour
/// change, not an oversight. `online`/`last_seen` are UNCHANGED in effect:
/// server.cpp's pre-rewire provider hardcoded them to `true`/"now" for every
/// registry-backed row (a connected agent is always "online" there), so this
/// rewire reproduces the exact same constants render-side instead of via a
/// provider closure — a refactor, not a behaviour change.
struct DeviceRow {
    std::string agent_id;
    std::string hostname;
    std::string os;       ///< "windows" | "linux" | "darwin" | "?"
    std::string arch;     ///< "x86_64" | "arm64" | "?"
    std::string agent_version;
    std::vector<std::string> tags; ///< EMPTY on the list path (DeviceApi has no bulk
                                   ///< all-agents tag read); POPULATED "key=value" on the
                                   ///< single-device page/info path from the detail's
                                   ///< TagStore tags (see get_one) — struct doc comment
    bool online = false;          ///< has a live Subscribe stream right now
    std::string last_seen;        ///< human-ish ("now", "12m ago") or ISO; "" if unknown
    int dex_score = -1;           ///< per-device DEX experience score 0–100; -1 = n/a
};

/// PURE: the `/fragments/devices/list` table — the fleet device list, filtered by
/// the (already-applied) query/os/status the caller resolved. 400k-safe in shape:
/// the caller passes a bounded/curated row set; this only renders. `q`/`os_token`/
/// `status_token` are echoed back into the controls so the fragment is
/// self-describing on swap.
std::string render_devices_list_fragment(const std::vector<DeviceRow>& rows, const std::string& q,
                                         const std::string& os_token,
                                         const std::string& status_token, std::size_t total_online,
                                         std::size_t total_devices);

/// PURE: the `/fragments/device/info` Device-info (CI-record) lens for one device.
/// Fields not in the thin AgentInfo (hardware/serial/owner/MAC) are deliberately
/// NOT fabricated here — they arrive with the inventory slice.
std::string render_device_info_fragment(const DeviceRow& d);

/// PURE: the per-device page body (identity bar + lens tabs + the active lens).
/// Slice 1 mounts the Device-info lens; the DEX/Guardian tabs hx-get a placeholder.
std::string render_device_page(const DeviceRow& d);

/// PURE: a lens panel that isn't built yet (DEX/Guardian in slice 1) — renders the
/// lens tab bar (so switching back works) + an honest "coming in a later slice"
/// message. `active` is the tab id ("dex" | "guardian"). `tabs=false` suppresses the
/// own 3-chip bar (Hardware CI record mounts this lens under its own 7-tab bar).
std::string render_device_lens_placeholder(const std::string& active, const std::string& agent_id,
                                           const std::string& message, bool tabs = true);

/// One guard's compliance state on a device (Guardian lens row).
struct DeviceGuardRow {
    std::string name;       ///< the Guard's human name
    std::string state;      ///< "compliant" | "drifted" | "errored"
    std::string updated_at; ///< ISO of the evaluation that set it
};

/// PURE: the DEX lens for one device — the per-device score + its signal summary
/// (obs_type → count, already fetched) + a link to the full /dex device drill.
/// `tabs=false` suppresses the own 3-chip bar (see render_device_lens_placeholder).
std::string render_device_dex_lens(const std::string& agent_id, int score,
                                    const std::vector<std::pair<std::string, std::int64_t>>& signals,
                                    bool tabs = true);

/// PURE: the Guardian lens for one device — compliance summary + per-guard state.
/// `tabs=false` suppresses the own 3-chip bar (see render_device_lens_placeholder).
std::string render_device_guardian_lens(const std::string& agent_id,
                                        const std::vector<DeviceGuardRow>& guards, bool tabs = true);

/// PURE: the "Get live info" snapshot SHELL — a header + one auto-loading panel per
/// live instruction (each div hx-gets /fragments/device/live/run?kind=…, which
/// dispatches a real plugin instruction to the device and polls for the result).
/// Live = queried on the agent NOW (no 30s heartbeat wait).
std::string render_device_live_shell(const std::string& agent_id);

/// One live process row: PID + name + the SHA-256 of its on-disk image + the
/// resolved executable path (hash/path empty when unresolved).
struct LiveProcess {
    int pid = 0;
    std::string name;
    std::string sha256; ///< lowercase hex; "" if unresolved / too large / gone
    std::string path;   ///< resolved exe path; "" if unresolved
};

/// PURE: render the live `processes/list_hashed` result — a PID/name/SHA-256
/// table. The full list renders into the DOM but only the first 10 rows show;
/// a search box (gpSearchTopN) filters by name/PID/hash/path and expands matches.
std::string render_device_live_processes(const std::vector<LiveProcess>& procs);

/// PURE: render a simple key/value live result (e.g. os_info/uptime) as a tile.
std::string render_device_live_value(const std::string& label, const std::string& value);

// ── Live snapshot v2: TAR-styled collapsible cards (feat/device-live-snapshot) ──
// Each card is fed by ONE live plugin action (process_tree joins a second), parsed
// in device_routes.cpp and rendered by the typed PURE renderers below. All agent
// fields are HTML-escaped at render. Mockup: docs/mockups/device-live-snapshot.html.

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
/// One TAR capture source's local state (tar/status → config|<src>_enabled / _live_rows).
/// `dollar`/`category` are server-side presentation metadata (the agent schema registry
/// is not linked into the server, so the source list is hand-held in device_routes.cpp;
/// only sources the agent actually reports are rendered).
struct LiveCaptureSource {
    std::string name, dollar, category;
    bool enabled = false;
    long long live_rows = -1; ///< -1 = unknown (no count reported)
};

/// PURE renderers — one `.ls-tbl`/tree per card body, dark-theme, CSP-safe.
/// render_device_live_tree reconstructs a parent→child tree from the flat node set
/// (cycle/cap guarded) and joins `conns` by pid for the inline `tt-net` summary,
/// mirroring the /tar process-tree viewer.
std::string render_device_live_tree(const std::vector<LiveProcNode>& nodes,
                                    const std::vector<LiveConn>& conns);
std::string render_device_live_arp(const std::vector<LiveArpEntry>& rows);
std::string render_device_live_dns(const std::vector<LiveDnsEntry>& rows);
std::string render_device_live_listening(const std::vector<LiveListen>& rows);
std::string render_device_live_connections(const std::vector<LiveConnRow>& rows);
std::string render_device_live_services(const std::vector<LiveService>& rows);
std::string render_device_live_users(const std::vector<LiveUserRow>& rows);
std::string render_device_live_netconfig(const std::vector<LiveNetAddr>& rows);
std::string render_device_live_disk(const std::vector<LiveDiskVolume>& rows);
std::string render_device_live_capture_sources(const std::vector<LiveCaptureSource>& rows);

/// PURE: generic pipe-row renderer (round-3 item 11 -- physical-kit panels) for the ten
/// hardware-detail live kinds (disks/memory/processors/drivers/battery/thermal/smart/
/// volumes/adapters/wifi) whose wire format is a flat `<row_prefix>|field1|field2|...`
/// table with no bespoke typed-row struct. `columns` is the ordered raw column-name
/// list from live_kinds.hpp's LiveKind::columns (drives both the table header labels
/// and each row's expected width); `rows` are the already-split, already-padded field
/// vectors (device_routes.cpp render_live_result, one per matched line, prefix token
/// dropped). `raw_rows` are lines that did NOT match the row_prefix, preserved
/// verbatim (full original line text) instead of being silently dropped -- each
/// renders as its own full-width diagnostic row at the end of the table.
/// Defined in device_ui.cpp.
std::string render_device_live_generic(const std::vector<std::string>& columns,
                                       const std::vector<std::vector<std::string>>& rows,
                                       const std::vector<std::string>& raw_rows);

/// PURE: honest not-found body (unknown / never-enrolled agent_id).
std::string render_device_not_found(const std::string& agent_id);

/// PURE: honest degraded body — the device resolves in the registry, but the
/// backing tag-store read failed (`DeviceReadError::kDegraded`; see
/// `device_api.hpp`). A dashboard-fragment "503-equivalent" placeholder — the
/// fragment still renders (HTMX swap contract), it just says so honestly
/// rather than collapsing to the not-found body (which would misreport a
/// live, existing device as unenrolled).
std::string render_device_degraded(const std::string& agent_id);

/// `/devices` + `/device` routes — page shells + read-only HTMX fragments.
class DeviceRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type, const std::string& operation)>;

    /// Per-device tier + management-group scope gate — wraps
    /// AuthRoutes::require_scoped_permission. Returns true (leaving `res` untouched)
    /// when the caller may perform `operation` on `securable_type` for `agent_id`
    /// (global grant OR a role assigned on the agent's management group / an
    /// ancestor); otherwise writes a 403 and returns false. The single chokepoint
    /// for every per-device device-route authz decision — never hand-roll a parallel
    /// membership scan.
    using ScopedPermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation,
                           const std::string& agent_id)>;

    /// The caller's confinement set, keyed by username — the SAME semantics
    /// `get_visible_agents_json`/server.cpp's `visible_set_fn` apply:
    /// `nullopt` = sees the whole fleet (global Infrastructure:Read grant, or
    /// RBAC enforcement is off); a present set = exactly those agent_ids (a
    /// present-EMPTY set on a degraded confinement read, fail-closed —
    /// ADR-0042). Applied via `authz::in_scope` against `DeviceApi::list_devices()`'s
    /// UNSCOPED rows — ADR-0031 WS-A4 wave 2 replaces the old pre-scoped
    /// `DevicesFn` provider with "unscoped API read + this seam's own filter",
    /// matching the REST/MCP siblings' pattern. An unwired closure is treated
    /// as a present-EMPTY (deny-all) set, never `nullopt` — the same
    /// fail-closed posture the old `DevicesFn`'s "empty closure -> list renders
    /// an honest 'unavailable' placeholder" contract gave.
    using VisibleSetFn =
        std::function<std::optional<std::set<std::string>>(const std::string& username)>;

    /// Per-device DEX experience score 0-100 (-1 = n/a / unscored). Wraps
    /// `dex_device_score` against a fixed window server.cpp's closure owns —
    /// called ONLY on the page's rendered rows (post filter, for the list; the
    /// single opened device, for the page), never the whole roster — same
    /// discipline `hardware_routes.hpp`'s own `DexScoreFn` documents.
    using DexScoreFn = std::function<int(const std::string& agent_id)>;

    /// The "Get live info" snapshot dispatches REAL plugin instructions to the device
    /// (Execute-gated, audited) and polls the response store — the same shared
    /// chokepoint + ResponseStore seam DexRoutes uses. Empty → live info unavailable.
    using DispatchFn = DexDispatchFn;
    using ResponsesFn = DexResponsesFn;
    using AuditFn = DexAuditFn;

    /// `api` is the store-free `DeviceApi` seam (identity/list data — ADR-0031
    /// WS-A4 wave 2); `visible_set_fn` is this route's OWN confinement filter
    /// over `api->list_devices()`'s unscoped rows; `dex_score_fn` backs the
    /// per-row/per-page DEX score; `dispatch_fn`/`responses_fn`/`audit_fn` back
    /// the live-info instruction dispatch (all borrowed/may be empty/null →
    /// graceful placeholder).
    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                         ScopedPermFn scoped_perm_fn, std::shared_ptr<const DeviceApi> api,
                         VisibleSetFn visible_set_fn = {}, DexScoreFn dex_score_fn = {},
                         DispatchFn dispatch_fn = {}, ResponsesFn responses_fn = {},
                         AuditFn audit_fn = {});

    /// HttpRouteSink overload — testable in-process via TestRouteSink (no httplib
    /// acceptor; the #438 TSan trap). The httplib::Server& overload wraps + delegates.
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                         ScopedPermFn scoped_perm_fn, std::shared_ptr<const DeviceApi> api,
                         VisibleSetFn visible_set_fn = {}, DexScoreFn dex_score_fn = {},
                         DispatchFn dispatch_fn = {}, ResponsesFn responses_fn = {},
                         AuditFn audit_fn = {});

private:
    AuthFn auth_fn_;
    PermFn perm_fn_;
    ScopedPermFn scoped_perm_fn_;
    std::shared_ptr<const DeviceApi> api_;
    VisibleSetFn visible_set_fn_;
    DexScoreFn dex_score_fn_;
    DispatchFn dispatch_fn_;
    ResponsesFn responses_fn_;
    AuditFn audit_fn_;
};

} // namespace yuzu::server
