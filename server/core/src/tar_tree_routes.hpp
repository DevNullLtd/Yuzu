#pragma once

#include "dispatch_confined_arms.hpp" // #3424/#3511: ConfinedDispatchOutcome -- DispatchFn/CommandDispatchFn return type

/// @file tar_tree_routes.hpp
/// The TAR process-tree viewer route module — Frame 3 of the `/tar` dashboard page.
/// Picks ONE live host, dispatches two canned read-only `tar.sql` queries to it
/// ($Process_Live + $TCP_Live), polls the response store (the device-page "Get live
/// info" dispatch/poll seam), reconstructs a per-host process tree over a chosen
/// timescale (tar_process_tree.hpp), and renders the HTMX fragments.
///
/// Product UI: HTMX, server-rendered, dark-theme only; htmx core attrs only (CSP
/// blocks hx-on). Per-host only; data from the agent's local tar.db only.
///
/// AUTH: the frame fragment + a per-host reconstruction gate on `Infrastructure:Read`
/// SCOPED to the device. The READ tier follows the TAR page (the TAR SQL frame is also
/// `Infrastructure:Read`) — NOT the `GuaranteedState:Read` floor the device-live-info /
/// DEX-perf drills use; only the Execute-PROBE posture (soft in-panel note for a
/// read-only operator) is shared with those seams. A reconstruction additionally
/// DISPATCHES a live `tar.sql`, so /run + /result require `Execution:Execute`. The
/// reconstruction is cached under an unguessable CSPRNG token (secure_random); the
/// /detail route holds the SAME tier as the reconstruction (re-checks SCOPED Read +
/// Execute on the cached device_id) AND binds the entry to the originating principal,
/// so a predicted/leaked token can neither cross management scope, downgrade the
/// Execute tier, nor be replayed under a different session.
///
/// REST + MCP twins (api-parity programme, issue #4027): `GET /api/v1/tar/process-tree`
/// (device picker) and `GET /api/v1/tar/capture-sources` (device picker) are twinned
/// here, over the SAME `Infrastructure:Read` requirement + service-scoped-token guard
/// as their fragment siblings, via the shared pure builders below (api-twin-recipe.md
/// Rule 1) — but NOT the same gate primitive: the two REST twins (and their MCP
/// counterparts) enforce that requirement via `fleet_read_fn_`, the ADR-0017
/// admit-then-filter chokepoint (#4027 fix round, CDX-P1-01/K4), while the fragment
/// siblings stay on the legacy bare `perm_fn_` this round (recorded exception — see
/// each fragment route's own registration comment). `GET /fragments/tar/process-tree/result` and `.../detail` are
/// DELIBERATELY NOT twinned by #4027 — scope, not impossibility. `/detail`'s
/// cache `token` is a CSPRNG value minted and cached ONLY by `/result` itself
/// (`cache_render_detail`/`ReconEntry`, principal-bound) — no other path mints
/// one, so a `/detail` twin genuinely has no input to accept today. `/result`'s
/// `pcmd`/`tcmd` command-ids are ordinary `tar sql` dispatch results
/// (`plugin_action_catalogue_a.hpp`: `Infrastructure:Read`, `execute_gate=None`)
/// and COULD in principle be minted by an operator through the already-twinned
/// generic dispatch surface (`execute_instruction` / `POST /api/command`) by
/// reproducing the two canned `$Process_Live`/`$TCP_Live` SELECTs verbatim —
/// there is no dedicated API path, only that indirect route, so shipping a real
/// `/result` twin would still need a caller to hand-derive those exact queries
/// AND a new async "not ready yet" polling contract (REST/MCP have no htmx
/// auto-reissue mechanism to lean on). Deferred as scope for now — see the
/// #4027 ledger row for the recorded `exception:` reasoning. Revisit once Batch C
/// lands a `/run` twin that mints pcmd/tcmd (and a token) directly over the API.

#include <yuzu/server/auth.hpp>

#include "authz_gates.hpp"     // yuzu::server::authz::FleetReadGate (#4027 fix round — CDX-P1-01/K4)
#include "dex_routes.hpp"      // DexRoutes::ResponsesFn/AuditFn + DexAgentResponse
#include "device_routes.hpp"   // DeviceRow
#include "dispatch_caller.hpp" // DispatchCaller
#include "tar_process_tree.hpp"

#include <httplib.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

class HttpRouteSink;

/// Pure JSON builder (api-twin-recipe.md Rule 1) for the process-tree host picker's
/// device list — the SAME operator-scoped `devices` list `render_frame` turns into
/// `<option>` elements. Called by `GET /api/v1/tar/process-tree` and the
/// `list_tar_process_tree_devices` MCP tool; the HTML fragment keeps its own
/// presentation-only "hide offline" filter (a picker dropdown for live dispatch,
/// unlike this JSON list) rather than being refactored onto this builder's output.
/// #4143 review fix (STANDARDS-2): the previous version of this comment cited a
/// "Rule 1 low-risk carve-out" in api-twin-recipe.md that does not exist there —
/// the doc's actual Rule 1 guidance (§ "Update the existing REST handler to call
/// it") argues FOR this refactor, not for skipping it. Corrected, honest status:
/// NOT done this round — tracked as a deliberate follow-up (same "recorded
/// exception" posture as the two un-migrated `/fragments/tar/...` routes
/// elsewhere in this file), not yet verified low-risk against `render_frame`'s
/// own presentation logic. The builder itself
/// does NOT discriminate on `online` — it emits every row it is handed, deliberately,
/// so an API/MCP caller isn't silently under-reported the way hiding offline rows
/// would. #4027 fix round (CDX-P1-02/K1) correction: the wired PRODUCER
/// (`server.cpp`'s `devices_fn`) sources exclusively from the live-session registry
/// and stamps `online=true` unconditionally, so in production every row this
/// builder actually sees is online — `online` is honest per-row but the list is
/// NOT offline-inclusive today despite the builder's own online-agnostic contract.
/// Wiring a genuinely offline-inclusive producer (the pattern at
/// `server.cpp:20057-20091`, `OfflineEndpointStore::query_stale_within`) is a
/// tracked follow-up, not done in this fix round.
std::string tar_process_tree_frame_json(const std::vector<DeviceRow>& devices);

/// Same shape and same "why a distinct name" rationale as
/// `tar_process_tree_frame_json` — the capture-sources device picker's list
/// (`render_cap_frame`). `GET /api/v1/tar/capture-sources` +
/// `list_tar_capture_sources_devices` MCP twin.
std::string tar_capture_sources_devices_json(const std::vector<DeviceRow>& devices);

/// One row in the TAR retention-paused source list (Phase 15.A). Mirrors
/// `DashboardRoutes`' private `PausedRow` field-for-field — extracted here (not into
/// `dashboard_routes.hpp`) so the REST/MCP JSON twin and DashboardRoutes' HTML
/// fragment renderer share ONE row shape without re-deriving it (api-twin-recipe.md
/// Rule 1), per the `#4027` AC's explicit `tar_retention_paused_json(...)` builder.
struct TarPausedSourceRow {
    std::string agent_id;
    std::string agent_display;
    std::string source;
    std::int64_t paused_at = 0;
    std::int64_t live_rows = -1; ///< -1 = unknown (older agent)
    std::int64_t oldest_ts = 0;
    bool value_error = false;    ///< #560: `<source>_enabled` held a non-canonical value
    std::string enabled_raw;     ///< the offending value, when value_error
};

/// Scan-level metadata + honesty counters accompanying a `TarPausedSourceRow` list.
/// See `DashboardRoutes::gather_tar_retention_paused` (dashboard_routes.cpp) for how
/// these are computed from the operator's per-username scan state + the response
/// store + the visible-agent set.
struct TarRetentionPausedScan {
    std::string scan_id;
    int scan_count = 0;
    std::int64_t scan_at = 0;
    int agents_responded = 0;
    int agents_with_no_paused_sources = 0;
    int agents_filtered_out_of_scope = 0;
    bool store_degraded = false;
    std::vector<TarPausedSourceRow> rows;
};

/// Pure JSON builder for the retention-paused source list — shared by
/// `GET /api/v1/tar/retention-paused` and the `list_tar_retention_paused` MCP tool.
/// Row order matches the HTML renderer's sort (value-error rows first, then
/// oldest-paused-first, then by display name) so the two surfaces agree.
std::string tar_retention_paused_json(const TarRetentionPausedScan& scan);

/// The `/tar` interactive-fragment route controller. Despite the historical name it
/// now owns THREE operator surfaces, all sharing the same scoped-Read + Execute-probe
/// + dispatch/poll seam and the eight providers below:
///   1. Process-tree viewer   — `/fragments/tar/process-tree[/run|/result|/detail]`
///   2. Device DNS/ARP panels — `/fragments/tar/process-tree/device-net` (ADR-0015)
///   3. Capture-sources frame — `/fragments/tar/capture-sources[/load|/push]` (ADR-0015)
/// (A rename to `TarFrameRoutes` + a split of the capture-sources surface is tracked
/// as a deferred follow-up; folding them here avoids a second server.cpp registration.)
///
/// #4027 adds two REST v1 twins registered by the SAME `register_routes` call:
/// `GET /api/v1/tar/process-tree` and `GET /api/v1/tar/capture-sources`, both device
/// picker lists requiring `Infrastructure:Read` + the service-scoped-token
/// fleet-wide-enumeration guard (deduplicated into
/// `deny_fleet_wide_device_enumeration` below rather than left as two, now
/// three-going-on-four, copies of the same inline check) — same REQUIREMENT as
/// their fragment siblings, but not the same gate PRIMITIVE: since the #4027 fix
/// round (CDX-P1-01/K4) the REST twins enforce `Infrastructure:Read` via
/// `fleet_read_fn_` (set post-registration, `set_fleet_read_fn`), the ADR-0017
/// admit-then-filter chokepoint, while the fragment siblings stay on `perm_fn_`
/// this round (recorded exception).
class TarTreeRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type, const std::string& op)>;
    /// #4027 fix round (adversarial review CDX-P1-01/K4) — the ADR-0017
    /// admit-then-filter chokepoint for the two REST device-picker twins
    /// (`GET /api/v1/tar/process-tree`, `GET /api/v1/tar/capture-sources`),
    /// injected the same way `DashboardRoutes::set_fleet_read_fn` /
    /// `McpServer::set_fleet_read_fn` are (a post-`register_routes` setter,
    /// not a constructor/`register_routes` param, so handlers read the
    /// member live per request and a test fixture that never wires it fails
    /// closed at the unwired-503 branch rather than failing to compile).
    /// MUST be the SOLE authorization gate on a route it guards — never
    /// stacked with `perm_fn_` for the same `(securable_type, operation)`
    /// (see `AuthRoutes::require_fleet_read`'s own doc comment for why
    /// pairing them is the exact bug this migration exists to fix). The two
    /// pre-existing HTML fragment routes (`/fragments/tar/process-tree`,
    /// `/fragments/tar/capture-sources`) deliberately stay on `perm_fn_` —
    /// out of scope for this round; see the route-registration comment
    /// where each fragment is registered.
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;
    void set_fleet_read_fn(FleetReadFn fn) { fleet_read_fn_ = std::move(fn); }

    /// External colleague review on PR #4143 (Doomgoose, BLOCKING, confirmed
    /// against ADR-0017 INV-4/INV-7 by direct source inspection): the two REST
    /// device-picker twins' PREVIOUS design intersected `fleet_read_fn_`'s
    /// admit-scope with `devices_fn_`'s own direct-membership-only narrowing
    /// (`get_visible_agents_json`), which predates the ADR-0017 ancestor-ward
    /// resolution and does not recognize a management-group-scoped-but-not-
    /// direct-member grant. That made admit and the row filter DISAGREE for
    /// that caller shape (INV-4), i.e. two resolvers instead of one shared one
    /// (INV-7) — a real defect regardless of the "conservative, never widens"
    /// framing the original comment used to justify it: an ADMITTED operator
    /// seeing an incomplete/empty list is a functional-correctness break, not
    /// a merely-cautious one. Fix: `all_devices_fn_` supplies the SAME
    /// unfiltered snapshot `GET /api/v1/devices` (#4033) and MCP's
    /// `list_agents` read from (`registry_.to_json_obj()`), and `gate.scope`
    /// (from `fleet_read_fn_`) is now the SOLE filter on both REST twins and
    /// their two MCP-tool siblings — one resolver, admit and filter agree by
    /// construction. `devices_fn_` (still per-operator direct-membership-
    /// scoped) remains wired for the two NOT-yet-migrated HTML fragment
    /// siblings only (`/fragments/tar/process-tree`, `/fragments/tar/capture-
    /// sources`), which stay on `perm_fn_` this round (recorded exception,
    /// unchanged by this fix).
    using AllDevicesFn = std::function<std::vector<DeviceRow>()>;
    void set_all_devices_fn(AllDevicesFn fn) { all_devices_fn_ = std::move(fn); }

    using ScopedPermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& op,
                           const std::string& agent_id)>;
    /// Operator-scoped connected-device list (the host picker) — same provider the
    /// `/devices` list + scope chip use (`get_visible_agents_json`).
    using DevicesFn = std::function<std::vector<DeviceRow>(const std::string& username)>;
    /// Unscoped single-device identity lookup (for the device's OS — the Windows
    /// names-only caption). Authz is the scoped gate the routes run first.
    using LookupFn = std::function<std::optional<DeviceRow>(const std::string& agent_id)>;
    /// Review finding (external PR review, #3133): every dispatch in this class used
    /// to go through `DexRoutes::DispatchFn` (no caller parameter), which server.cpp
    /// wired to the unfiltered `command_dispatch_fn` — so a mutating action
    /// (`tar.configure`, the capture-source push) dispatched as `system`, bypassing
    /// the catalogue's `Infrastructure:Write` requirement even though the route
    /// itself only ever checked `Infrastructure:Read`. TarTreeRoutes now has its own
    /// caller-aware signature — deliberately NOT sharing `DexRoutes::DispatchFn` with
    /// `DeviceRoutes` (the device-live-info panel), whose read-only, pre-existing
    /// system dispatch is a separate, non-blocking finding from the same review.
    using DispatchFn = std::function<yuzu::server::ConfinedDispatchOutcome(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const yuzu::server::DispatchCaller& caller)>;
    using ResponsesFn = DexRoutes::ResponsesFn;
    using AuditFn = DexRoutes::AuditFn;
    /// Resolves the caller's identity + Execution:Execute visible set from the
    /// request — same contract as WorkflowRoutes::CallerFn: an UNWIRED callback
    /// fails CLOSED (empty principal, present-EMPTY exec_visible), never nullopt.
    using CallerFn = std::function<yuzu::server::DispatchCaller(const httplib::Request&)>;

    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                         ScopedPermFn scoped_perm_fn, DevicesFn devices_fn, LookupFn lookup_fn,
                         DispatchFn dispatch_fn, ResponsesFn responses_fn, AuditFn audit_fn,
                         CallerFn caller_fn);

    /// HttpRouteSink overload — in-process testable (no httplib acceptor; #438).
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                         ScopedPermFn scoped_perm_fn, DevicesFn devices_fn, LookupFn lookup_fn,
                         DispatchFn dispatch_fn, ResponsesFn responses_fn, AuditFn audit_fn,
                         CallerFn caller_fn);

private:
    /// One cached reconstruction. Holds the rendered tree (node-id addressable by the
    /// detail route) + the host's connection set (filtered per-pid at detail time) +
    /// the device_id/os used for the per-detail scoped re-check and the names-only
    /// caption + the originating principal (the detail route fails closed unless the
    /// requesting session matches, so a predicted/leaked token can't be replayed under
    /// a different identity even within the same management scope).
    struct ReconEntry {
        std::string device_id;
        std::string principal; ///< session->username that created this reconstruction
        std::string os;
        TarProcTree tree;
        std::vector<TarTcpConn> conns;
        std::int64_t created = 0;
    };

    /// Bounded (kCacheCap) + TTL (kCacheTtlSeconds) reconstruction cache. Token is an
    /// unguessable random hex; insertion-ordered for eviction. Guarded by cache_mu_.
    /// Cap kept modest: each entry can hold up to a 50k-node tree + 5k conns, so 32 ×
    /// worst-case bounds peak cache RSS (~0.8 GB ceiling; typical trees are far smaller).
    /// NOTE (multi-server): this cache is node-local — a future multi-server deployment
    /// must NOT assume a token resolves on another node.
    static constexpr std::size_t kCacheCap = 32;
    static constexpr std::int64_t kCacheTtlSeconds = 180;

    void cache_put(const std::string& token, ReconEntry entry);
    /// Render one node's detail from the cached entry (under lock; render is cheap).
    /// nullopt → token unknown/expired. Validates node_id internally.
    std::optional<std::string> cache_render_detail(const std::string& token, std::size_t node_id,
                                                   std::string* out_device_id);

    /// #4027: the fleet-wide device-enumeration guard shared by the frame fragment
    /// routes (`/fragments/tar/process-tree`, `/fragments/tar/capture-sources`) and
    /// their new `/api/v1/tar/...` twins — previously two byte-for-byte-identical
    /// inline copies (one per fragment route); adding the REST twins would have made
    /// a third and fourth. Resolves the session itself via `auth_fn_` (writing its
    /// own 401 on failure), denies + audits (`tar.device_picker.view`, denied) a
    /// service-scoped token, and returns true iff the caller must return immediately
    /// (401 already written, or the 403 deny itself) — same contract as
    /// `rest_api_v1.cpp`'s/`mcp_server.cpp`'s OWN separate `deny_fleet_wide_service_scoped`
    /// lambdas, which this does not call: those are TU-local lambdas in different
    /// translation units (not exported via a header), so consolidating across all
    /// three would mean extracting a new shared header function and touching two
    /// large, already-hardened files outside this change's blast radius. Deduplicating
    /// TarTreeRoutes' own copies closes the concrete "third copy" risk #4027 flags
    /// without that wider, riskier refactor; a genuinely shared header function is a
    /// reasonable fast-follow. On success (no session, or a non-service-scoped one),
    /// `*out_session` is set when non-null and the session resolved.
    bool deny_fleet_wide_device_enumeration(const httplib::Request& req, httplib::Response& res,
                                            std::optional<auth::Session>* out_session = nullptr);

    AuthFn auth_fn_;
    PermFn perm_fn_;
    FleetReadFn fleet_read_fn_; ///< #4027 fix round — see set_fleet_read_fn's doc comment.
    /// #4143 review fix — unfiltered device snapshot; SOLE row source for the two
    /// REST device-picker twins. See set_all_devices_fn's doc comment.
    AllDevicesFn all_devices_fn_;
    ScopedPermFn scoped_perm_fn_;
    DevicesFn devices_fn_;
    LookupFn lookup_fn_;
    DispatchFn dispatch_fn_;
    ResponsesFn responses_fn_;
    AuditFn audit_fn_;
    CallerFn caller_fn_;

    std::mutex cache_mu_;
    std::unordered_map<std::string, ReconEntry> cache_;
    std::list<std::string> cache_order_; ///< front = oldest
};

} // namespace yuzu::server
