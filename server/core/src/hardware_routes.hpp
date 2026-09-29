#pragma once

/// @file hardware_routes.hpp
/// /hardware — the ServiceNow-style Configuration-Item (CI) surface: a searchable,
/// filterable, sortable, paginated CI list and a per-device CI record with lens
/// tabs (Installed software, Tags). Package A (nav split + read surface) only —
/// the Actions lens (generic action runner) is added on top of this `Deps` struct
/// by feat/hardware-ci-actions without touching the routes registered here.
///
/// Shares `InventoryDeviceRow`/`InventoryDevicesResult` with `InventoryRoutes` (the
/// roster shape is identical; the roster's PRODUCTION source is the same
/// `inv_devices_fn` roster body in server.cpp, extracted so both the Software tab's
/// existing DevicesFn and this module's unfiltered RosterFn share one build). Query/
/// sort/paginate/JSON logic lives in `hardware_list_model.hpp` (PURE, no httplib) —
/// this class only wires HTTP semantics (auth, gates, audit) around it.
///
/// AUTH: the list and REST twin gate SOLELY on `FleetReadFn` (admit-then-filter,
/// ADR-0017 — never stacked with a second permission check for the same
/// securable:operation, the BLOCKING defect `FleetReadFn`'s own contract exists to
/// avoid). The CI record and its lenses gate on `scoped_perm_fn(Inventory,Read,id)`
/// — the tier + management-group chokepoint, same as the Software tab's per-device
/// drill.

#include "authz_gates.hpp"           // authz::FleetReadGate
#include "command_capability.hpp"    // CommandCapability, ClassificationError
#include "dex_routes.hpp"            // DexAgentResponse (ResponsesFn return type)
#include "hardware_action_form.hpp"  // ActionFormSpec
#include "hardware_list_model.hpp"
#include "inventory_routes.hpp"      // InventoryDeviceRow / InventoryDevicesResult reuse

#include <expected>
#include <unordered_map>

#include <httplib.h>

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

class HttpRouteSink;

// ── PURE renderers (implemented in hardware_ui.cpp) ──────────────────────────────
// Each returns a self-contained fragment. A degraded read renders an honest banner,
// never an empty table (ADR-0016 §7) — the same contract InventoryRoutes' renderers
// keep for the Software tab.

/// The CI list: KPI strip, search box, OS/status chips, breadcrumb, sortable table,
/// pagination. `roster_unavailable` = the RosterFn itself is unwired/failed (distinct
/// from `ci_degraded`, which only means the CI *columns* are blank on live rows).
std::string render_hardware_list_fragment(const HardwareListPage& page, bool ci_degraded,
                                          bool roster_unavailable, bool results_only = false,
                                          bool tags_degraded = false);

/// What the CI record may OFFER the caller beyond reading — computed by the route
/// (online state, agent version floor, Execute / Tag:Write probes) and passed to
/// the PURE renderers, so a renderer never decides authorization itself.
struct HwSyncAffordance {
    enum class State { Ready, Offline, Unsupported, NoExecute } state{State::Offline};
    std::string agent_version; // for the Unsupported note
};
struct HwCiAffordances {
    HwSyncAffordance sync;
    bool can_write_tags{false}; // Tag:Write probe passed → Add/remove tag controls render
    // Round-3 merge: the DEX/Guardian/Live lenses reuse device_routes.cpp's existing
    // fragments verbatim, which gate on scoped GuaranteedState:Read — a STRICTER
    // check than the Inventory:Read the CI record itself already passed. htmx does
    // not swap a 403, so the lens body checks this first and renders an honest note
    // instead of an hx-get a caller without the permission could never see resolve.
    bool can_read_guaranteed_state{false};
};

/// The lens tab bar alone, id="hw-lens-bar" — factored out so a lens-only response
/// can prepend it as an out-of-band swap (round-2 item 6: without this the `on`
/// class only ever moves on a full record render, so clicking a tab never visibly
/// changes which tab looks active). `oob=true` emits `hx-swap-oob="true"` on the
/// wrapping div; the full record render uses `oob=false` since the bar is already
/// in the right place in the DOM.
std::string render_hardware_lens_bar(const std::string& agent_id, const std::string& active, bool oob);

/// The CI record: back link + header (hostname/OS/online/last-seen/agent id/Sync now)
/// + lens tabs + the active lens's body. `lens` in {"overview","software","tags","actions"}.
std::string render_hardware_ci_fragment(const std::string& agent_id, const HardwareCiDetail& detail,
                                        const std::string& lens, std::int64_t now_secs,
                                        const HwCiAffordances& aff);

/// ONLY the active lens's body (what the lens tabs and the sync poll swap into
/// `#hw-ci-lens`) — never the header, so a tab click can't nest a second one.
std::string render_hardware_lens_body(const std::string& agent_id, const HardwareCiDetail& detail,
                                      const std::string& lens, std::int64_t now_secs,
                                      const HwCiAffordances& aff);

/// Sync-now poll: re-fetches the lens body every 2 s until the store's freshness
/// stamp passes `await_since` (the server clock at request time) or `n` reaches 30.
std::string render_hardware_sync_pending(const std::string& agent_id, const std::string& lens,
                                         std::int64_t await_since, int next_attempt,
                                         const std::string& command_id);
/// Terminal states of that poll: the agent refused (its own message, escaped), or
/// the wait budget ran out.
std::string render_hardware_sync_terminal(const std::string& agent_id, const std::string& lens,
                                          const std::string& refusal_output, bool timed_out);

std::string render_hardware_software_lens(const std::string& agent_id,
                                          const std::optional<std::vector<SoftwareEntry>>& software,
                                          bool truncated, bool online, const HwSyncAffordance& sync);

std::string render_hardware_tags_lens(const std::string& agent_id,
                                      const std::optional<std::vector<DeviceTag>>& tags,
                                      bool can_write);

std::string render_hardware_not_found(const std::string& agent_id);

/// One plugin's advertised actions, as reported by a connected agent — a light
/// mirror of `AgentRegistry::PluginMeta` that keeps gRPC/registry headers out of
/// this header (only the .cpp wiring in server.cpp touches `AgentRegistry`
/// directly). Populated by `Deps::ActionsFn`.
struct HwPluginActions {
    std::string name;
    std::string version;
    std::vector<std::string> actions;
};

/// One row of the Actions lens's generic action runner. `cap` is `nullopt` when
/// `plugin.action` fails `CommandCapabilityRegistry::classify` (Unclassified —
/// not in the compile-time catalogue — or Ambiguous, two fragments claiming the
/// same pair) — POST /api/command would 400 either case, so the row renders
/// disabled rather than offering a Run button that can only fail.
struct HwActionRow {
    std::string plugin;
    std::string action;
    std::string description;
    std::optional<CommandCapability> cap;
    bool ambiguous{false};
    bool bad_ident{false};
    ActionFormSpec form;
};

enum class HwActionsState { Ready, Offline, NoExecute, Unavailable };

/// The Actions lens: every `plugin.action` the connected agent reports, grouped by
/// plugin, class-badged, each with its parameter form (or a free-form key=value
/// textarea when no schema is published). `Offline` = the agent has no live
/// session (actions dispatch to a connected agent only); `NoExecute` = the caller
/// lacks Execution:Execute for this device (the list/CI-record Read gate already
/// passed — this is a stricter probe, same idiom as the Live-info panel).
std::string render_hardware_actions_lens(const std::string& agent_id, const std::string& hostname,
                                         const std::vector<HwActionRow>& rows, HwActionsState state);

/// The Run button's dispatch result panel. Ordering here matches
/// `device_routes.cpp`'s live-info result idiom: Pending polls again via
/// `hx-trigger="load delay:700ms"`; a terminal state renders once and stops.
struct HwActionResultView {
    enum class Phase { Pending, Rendered, RenderedEmpty, Failed, TimedOut } phase{Phase::Pending};
    std::string output;
    std::string error_detail;
    int attempt{1};
};

std::string render_hardware_result_pending(const std::string& agent_id, const std::string& command_id,
                                           const std::string& plugin, int next_attempt);

std::string render_hardware_action_result(const std::string& plugin, const std::string& action,
                                          const HwActionResultView& view);

/// /hardware route registration. Providers are injected closures (store-decoupled)
/// so every handler is unit-testable via `TestRouteSink` without a live Postgres —
/// same discipline as `InventoryRoutes`.
class HardwareRoutes {
public:
    using AuthFn = InventoryRoutes::AuthFn;
    using ScopedPermFn = InventoryRoutes::ScopedPermFn;
    using AuditFn = InventoryRoutes::AuditFn;

    /// The route's SOLE authorization gate for the fleet-wide list + its REST twin.
    /// Same contract as `RestApiV1::FleetReadFn` / `authz::AuthRoutes::require_fleet_read`:
    /// `admitted == false` means the response is already fully rendered (401/403/503).
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;

    /// The UNFILTERED CI roster (all agents seen in the last 30 days, every scope) —
    /// `FleetReadFn`'s returned scope is the SOLE filter, applied by the route via
    /// `authz::in_scope`. Never pre-filter this closure's output; that would double
    /// up on `FleetReadFn`'s own scope (silently reconciling two different scope
    /// predicates is exactly the class of bug `FleetReadFn`'s doc comment warns
    /// about). Empty closure = route renders "unavailable" and 503s on the REST twin.
    using RosterFn = std::function<InventoryDevicesResult()>;

    /// The full per-device CI record composition (identity + CI blob + software +
    /// tags — see `HardwareCiDetail`) — ONE closure shared verbatim by the dashboard
    /// fragment and the REST twin, so the two can never disagree on what "the CI
    /// record" contains. The Installed-software and Tags lenses render straight off
    /// this same struct rather than issuing a second per-lens fetch. NOTE: there is
    /// no MCP twin yet (no `get_hardware_ci` tool exists) — tracked as a follow-up,
    /// not yet an ADR-1005 exception-ledger entry (governance Gate 3 finding).
    using CiDetailFn = std::function<HardwareCiDetail(const std::string& agent_id)>;

    /// One connected agent's advertised plugins/actions — `nullopt` when the agent
    /// has no live session (actions are dispatch-to-a-connected-agent only, unlike
    /// the CI record which is offline-survivable).
    using ActionsFn = std::function<std::optional<std::vector<HwPluginActions>>(const std::string& agent_id)>;

    using ClassifyFn = std::function<std::expected<CommandCapability, ClassificationError>(
        std::string_view plugin, std::string_view action)>;

    /// Enabled `InstructionDefinition`s' `parameter_schema` for one plugin, keyed by
    /// action name (object-shaped schemas only — the same filter
    /// `discover_routes.cpp`'s catalogue join applies). An action with no entry
    /// renders the free-form key=value textarea.
    using SchemaFn =
        std::function<std::unordered_map<std::string, std::string>(const std::string& plugin)>;

    using ResponsesFn = std::function<std::vector<DexAgentResponse>(const std::string& command_id,
                                                                    const std::string& agent_id)>;

    /// Per-device permission PROBE — a stricter check than the Read gate the
    /// record/list already passed, run against a throwaway `Response` so it never
    /// itself writes to the real one (the `dashboard_routes.cpp` permission-probe
    /// idiom). Used for `Execution:Execute` (actions, sync) and `Tag:Write` (tag
    /// controls). `true` = the caller holds `type:op` for this agent.
    using ScopedProbeFn = std::function<bool(const httplib::Request&, const std::string& securable_type,
                                             const std::string& operation, const std::string& agent_id)>;

    struct HwSyncDispatchResult {
        bool sent{false};
        std::string command_id;
    };
    /// Dispatch `__sync__.now {source}` to ONE connected agent as a system-reserved
    /// push (server.cpp: build_classified_command(system) + send_system_reserved +
    /// forward_gateway_pending — the Guardian-push path, never dispatch_confined,
    /// which would withhold `__sync__` as an unknown plugin). `sent=false` == the
    /// registry refused (no live session / stream write failed).
    using SyncDispatchFn = std::function<HwSyncDispatchResult(const std::string& agent_id,
                                                              const std::string& source)>;
    /// The live session's self-reported agent_version; nullopt == no live session.
    using AgentVersionFn = std::function<std::optional<std::string>(const std::string& agent_id)>;
    /// One plugin's pre-serialised plugin-docs manifest JSON (`plugin_docs_manifest`),
    /// nullopt when no manifest documents that plugin.
    using ManifestFn = std::function<std::optional<std::string>(const std::string& plugin)>;

    /// DEX experience score 0-100 for one device (`dex_device_score`, one GROUP-BY
    /// query); -1 = not scored / store unwired. Called ONLY on the page's rendered
    /// rows (post filter/sort/paginate), never the whole roster — same discipline
    /// `device_routes.cpp`'s list already follows.
    using DexScoreFn = std::function<int(const std::string& agent_id)>;

    struct Deps {
        AuthFn auth_fn;
        ScopedPermFn scoped_perm_fn;
        FleetReadFn fleet_read_fn;
        AuditFn audit_fn;
        RosterFn roster_fn;
        CiDetailFn ci_detail_fn;
        ActionsFn actions_fn;
        ClassifyFn classify_fn;
        SchemaFn schema_fn;
        ResponsesFn responses_fn;
        ScopedProbeFn scoped_probe_fn;
        const std::unordered_map<std::string, std::string>* action_descriptions{nullptr};
        ManifestFn manifest_fn;           // parameter hints (R2.5)
        SyncDispatchFn sync_dispatch_fn;  // Sync now (R2.3)
        AgentVersionFn agent_version_fn;  // Sync now version floor (R2.3)
        DexScoreFn dex_score_fn;          // Devices-page merge (round 3)
    };

    void register_routes(httplib::Server& svr, Deps deps);
    void register_routes(HttpRouteSink& sink, Deps deps);

private:
    /// What the CI record may offer THIS caller for THIS device (sync button state,
    /// tag controls) — probes run here, in the route layer, never in a renderer.
    HwCiAffordances affordances_for(const httplib::Request& req, const std::string& id,
                                    const HardwareCiDetail& detail) const;

    Deps deps_;
};

} // namespace yuzu::server
