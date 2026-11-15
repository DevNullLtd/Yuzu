#pragma once

#include "dispatch_confined_arms.hpp" // #3424/#3511: ConfinedDispatchOutcome -- DispatchFn/CommandDispatchFn return type

/// @file dashboard_routes.hpp
/// HTMX fragment routes for the dashboard: filterable/sortable results,
/// group creation from filtered results, scope panel with groups,
/// and HTMX-native instruction dispatch.

#include <expected>
#include <functional>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include "authz_gates.hpp" // yuzu::server::authz::FleetReadGate (#1712 / #3290 Phase 2)
#include "authz_model.hpp" // yuzu::server::authz::VisibleSet (#1788 / CDX-R7-02)
#include "command_capability.hpp" // PR6.0b: CommandCapability / ClassificationError — ClassifyFn's return type
#include "forensics_visibility.hpp" // ForensicsVisibilityFn (#4990)
#include "dispatch_caller.hpp" // PLAN-006: DispatchCaller — the principal threaded to dispatch_fn

namespace yuzu::server {

// Forward declarations
class ResponseStore;
class ManagementGroupStore;
class TagStore;
class InstructionStore;
class HttpRouteSink; // http_route_sink.hpp — the in-process-testable seam (#438)
struct FacetFilter;
struct StoredResponse; // response_store.hpp
struct ForensicsServed; // forensics_read_audit.hpp - #4990
struct EchoRetentionPausedScan; // echo_tree_routes.hpp — #4027 REST+MCP twin shape

namespace detail {
class AgentRegistry;
class EventBus;
} // namespace detail

/// The ONE htmx sync scope every console results request shares (View select, per-column
/// controls, Search, sortable headers, Prev/Next, the Create Group button).
///
/// WHY `replace`: in the bundled htmx 2.0.4 `abort` DROPS a request issued while another is in
/// flight (`d==="abort"){if(u.xhr){...return e}`), so `closest form:abort` / `this:abort` lose the
/// operator's SECOND keystroke or click. `replace` is newest-wins: the in-flight request is
/// aborted and the new one issued. The sync element is the filter bar, so a header or pager
/// request (whose own element is not the form) still competes with a form request.
inline constexpr std::string_view kResultsSyncScope = "#filter-bar:replace";

/// `HX-Trigger` member that aborts whatever results request is in flight on the filter bar.
/// A new dispatch (or a help answer) replaces the results; a late response for the previous
/// command must not land on top. The target is the sync element, which holds the xhr (the OLD
/// #filter-bar). It is emitted LAST in the header because htmx keeps a key's `target` for the keys
/// after it: an earlier `target:#filter-bar` would retarget the showToast that follows it too.
inline constexpr std::string_view kResultsAbortTrigger =
    R"("htmx:abort":{"target":"#filter-bar"})";

class DashboardRoutes {
public:
    using AuthFn = std::function<std::optional<auth::Session>(
        const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string&, const std::string&)>;
    /// Writes one audit row; returns the persist outcome (true == stored, or audit-off).
    /// #3619: `bool`, never `void` -- a void sink cannot tell a stored row from a lost one.
    /// Handlers never call it (or `persist_audit_fn_`) directly: each row goes through
    /// `audit_attempted`, `audit_or_flag`, or the shared `emit_forensics_read_audit` (#4990), all
    /// of which pass the sink to the `rest_audit.hpp` kernel (pinned by
    /// tests/test_dashboard_audit_checked_lexical.py).
    using AuditFn = std::function<bool(const httplib::Request&, const std::string&,
                                       const std::string&, const std::string&,
                                       const std::string&, const std::string&)>;

    /// Agents JSON callback — returns JSON array of visible agent objects.
    using AgentsJsonFn = std::function<std::string()>;

    /// Send command callback — dispatches a command and returns (command_id, agents_reached).
    ///
    /// CDX-R7-02 / PLAN-006: carries the caller — identity plus its
    /// Execution:Execute visible set — as a trailing param so the dashboard
    /// execute surface narrows to it AND records who asked, via the shared
    /// `dispatch_confined` seam, exactly as /api/command and MCP do.
    /// `exec_visible` nullopt == unfiltered.
    using DispatchFn = std::function<yuzu::server::ConfinedDispatchOutcome(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const yuzu::server::DispatchCaller& caller)>;

    /// CDX-R7-02 / PLAN-006: resolves the caller's DispatchCaller (identity +
    /// Execution:Execute visible set) from the request (the dashboard execute
    /// handlers gate via `perm_fn_` and hold no Session object at the dispatch
    /// site). Wired in server.cpp to a closure that resolves the session and
    /// calls `derive_dispatch_caller`; an UNWIRED callback fails CLOSED on
    /// visibility (the handler passes an empty principal alongside a
    /// present-EMPTY set — deny all, never nullopt).
    using CallerFn =
        std::function<yuzu::server::DispatchCaller(const httplib::Request&)>;

    /// Resolve instruction text → (plugin, action). Empty strings on failure.
    using ResolveFn = std::function<std::pair<std::string, std::string>(
        const std::string& instruction_text)>;

    /// D3: resolves the caller's Response:Read-visible agent set for the
    /// dashboard facet/scope surfaces (filter bar, create-group form, and
    /// group-from-results POST). `nullopt` means the caller sees all agents
    /// (RBAC legacy-open, or a global Response:Read grant); a present-but-
    /// EMPTY set means fail-closed on a degraded store — a degrade must
    /// NEVER be signalled as `nullopt`, since that would silently widen to
    /// "sees all". Deliberately anchored on Response:Read, NOT the
    /// Infrastructure:Read-anchored `visible_set_fn` (server.cpp:16786):
    /// reusing that one would hand a global-Response:Read holder table rows
    /// while leaving these dropdowns empty.
    using VisibleSetFn = std::function<std::optional<std::set<std::string>>(
        const std::string& username)>;

    void register_routes(httplib::Server& svr,
                         AuthFn auth_fn,
                         PermFn perm_fn,
                         AuditFn audit_fn,
                         ResponseStore* response_store,
                         ManagementGroupStore* mgmt_group_store,
                         detail::AgentRegistry* registry,
                         TagStore* tag_store,
                         detail::EventBus* event_bus,
                         AgentsJsonFn agents_json_fn,
                         DispatchFn dispatch_fn,
                         CallerFn caller_fn,
                         ResolveFn resolve_fn,
                         yuzu::MetricsRegistry* metrics = nullptr,
                         InstructionStore* instruction_store = nullptr,
                         VisibleSetFn visible_set_fn = {});

    /// HttpRouteSink overload — identical registration against the polymorphic
    /// seam so the fragment handlers (notably the destructive Echo
    /// retention-paused purge/reenable POSTs) are reachable from an in-process
    /// TestRouteSink without an httplib acceptor thread (#438 TSan trap; #1786).
    /// The httplib::Server& overload wraps + delegates here.
    void register_routes(HttpRouteSink& sink,
                         AuthFn auth_fn,
                         PermFn perm_fn,
                         AuditFn audit_fn,
                         ResponseStore* response_store,
                         ManagementGroupStore* mgmt_group_store,
                         detail::AgentRegistry* registry,
                         TagStore* tag_store,
                         detail::EventBus* event_bus,
                         AgentsJsonFn agents_json_fn,
                         DispatchFn dispatch_fn,
                         CallerFn caller_fn,
                         ResolveFn resolve_fn,
                         yuzu::MetricsRegistry* metrics = nullptr,
                         InstructionStore* instruction_store = nullptr,
                         VisibleSetFn visible_set_fn = {});

    /// Operator-declared external origins for the CSRF same-site gate (#2537),
    /// already normalised by `normalise_trusted_origins` at boot. Set BEFORE
    /// `register_routes` — the handlers capture `this` and read the member per
    /// request, so a later call would not reach an already-registered route.
    ///
    /// A setter rather than another `register_routes` parameter because both
    /// overloads already take eleven, and because the miss-case is safe: leaving
    /// it unset means same-host only, which is the pre-#2537 behaviour and
    /// refuses a proxied browser POST. Forgetting degrades to fail-closed.
    void set_csrf_trusted_origins(std::vector<std::string> origins) {
        csrf_trusted_origins_ = std::move(origins);
    }

    /// ADR-0033 section 9 ("no audit row, no mutation"): the SAME audit sink as `AuditFn`. Two
    /// uses. (1) The `attempted` row a mutation writes BEFORE it acts (`audit_attempted`): every
    /// console send on POST /api/dashboard/execute, POST /api/dashboard/group-from-results, and
    /// the Echo re-enable and purge fragments (#3619; the expression-targeted send was first).
    /// Unset here, those mutations fail CLOSED (503), never "act without evidence". (2) The
    /// #4990 `response.forensics.read` row on /fragments/results (`emit_forensics_read_audit`),
    /// a read that is set-and-proceed: unset, that row is skipped as audit-off. Set before
    /// `register_routes`: handlers read the member on every request, so a later set would race
    /// the request threads.
    using PersistAuditFn = std::function<bool(const httplib::Request&, const std::string&,
                                              const std::string&, const std::string&,
                                              const std::string&, const std::string&)>;
    void set_persist_audit_fn(PersistAuditFn fn) { persist_audit_fn_ = std::move(fn); }

    /// #1712 / #3290 Phase 2 — the injected-callback twin of
    /// `AuthRoutes::require_fleet_read`, backing `/fragments/results`'
    /// real per-agent/service confinement (same shape as
    /// `McpServer::FleetReadFn`/`RestApiV1::FleetReadFn` — server.cpp wires
    /// the SAME conversion lambda into all three surfaces so they cannot
    /// drift). Same setter idiom as `set_csrf_trusted_origins` above (both
    /// `register_routes` overloads already take fourteen parameters). MUST
    /// be `/fragments/results`' SOLE authorization gate — never stacked
    /// with `perm_fn_` for the same `(securable_type, operation)` (the
    /// BLOCKING defect `require_fleet_read`'s own doc comment warns
    /// against). Unset (default-constructed) ⇒ the route fails CLOSED
    /// (503 "unwired"), mirroring `McpServer`'s own unwired contract for
    /// the identical seam.
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;
    void set_fleet_read_fn(FleetReadFn fn) { fleet_read_fn_ = std::move(fn); }

    /// #4990 - the Forensics plugin set the stored-response read tier excludes
    /// (`ServerImpl::forensics_plugin_set_`, borrowed: it outlives this object). Same setter idiom
    /// as `set_fleet_read_fn`: handlers read the member per request. Unset (nullptr, a test
    /// harness) fails closed: the results fragments then refuse every row (`tier_filter_for`).
    void set_forensics_plugin_set(const ForensicsPluginSet* plugins) { forensics_plugins_ = plugins; }

    /// #4990 - the resolver behind the results fragments' Forensics tier (see
    /// `forensics_visibility.hpp`); read live per request like `fleet_read_fn_`. Unset resolves to
    /// present-empty at the use site.
    void set_forensics_visibility_fn(ForensicsVisibilityFn fn) {
        forensics_visibility_fn_ = std::move(fn);
    }

    /// PR6.0b — classifies a `plugin.action` pair for the Destructive
    /// TARGETING gate on `POST /api/dashboard/execute`
    /// (`dispatch_destructive_gate.hpp`). Deliberately the SAME shape and the
    /// same fail-closed contract as `McpServer::ClassifyFn`, and wired in
    /// `server.cpp` to the SAME `CommandCapabilityRegistry::classify` that
    /// `/api/command` and MCP `execute_instruction` consult — the three
    /// operator-facing surfaces must not be able to disagree about what a
    /// pair IS, only about how each answers its own caller.
    ///
    /// FAIL-CLOSED when unset (`{}`): the exec console cannot determine
    /// whether ANY pair is Destructive, so it refuses EVERY dispatch with a
    /// distinguishable "classifier unavailable" message rather than falling
    /// through. A silently-unwired classifier would otherwise revert this
    /// gate to its pre-PR6.0b state while every other test stayed green —
    /// the `ContainmentGate{}` class of regression `dispatch_confined_arms
    /// .hpp` warns about, and the reason that type has no default state.
    /// Production wires this unconditionally (`server.cpp`, next to
    /// `set_fleet_read_fn`); an unset fn reaching a live request means the
    /// wiring itself regressed.
    ///
    /// A WIRED fn returning `Unclassified`/`Ambiguous` is the DIFFERENT,
    /// unchanged Policy-B case — see the handler's own `ClassifyMiss` arm.
    using ClassifyFn =
        std::function<std::expected<yuzu::server::CommandCapability,
                                    yuzu::server::ClassificationError>(
            std::string_view plugin, std::string_view action)>;

    /// Same setter idiom as `set_fleet_read_fn` above: the handlers capture
    /// `this` at registration and read the member per request, so an
    /// injection after `register_routes` still takes live effect.
    void set_capability_classify_fn(ClassifyFn fn) { classify_fn_ = std::move(fn); }

    /// #4027: the data-gathering half of render_echo_retention_paused, extracted so
    /// the HTML fragment renderer, the new `GET /api/v1/echo/retention-paused` REST
    /// twin, and the `list_echo_retention_paused` MCP twin share ONE read of the scan
    /// state / response store / visibility filter (api-twin-recipe.md Rule 1) instead
    /// of the REST/MCP surface re-deriving it. Public (unlike the private renderer
    /// above) — `McpServer` calls it via a `DashboardRoutes*` threaded in through
    /// server.cpp, the same pattern other route classes use for cross-class access.
    ///
    /// `extra_scope` (#4027 fix round, CDX-P1-01/K4): an ADDITIONAL visibility
    /// constraint ANDed into the existing per-response `visible_set` check —
    /// nullopt (default) preserves the pre-fix behavior exactly (the HTML
    /// fragment renderer's caller passes nothing). The REST/MCP twins pass
    /// `fleet_read_fn_`'s/McpServer's own `FleetReadGate::scope` here so a
    /// dropped-for-scope row is folded into `agents_filtered_out_of_scope`
    /// the SAME way an existing out-of-management-scope row is — NOT applied
    /// as a post-hoc filter over the returned `rows`, which would leave
    /// `agents_responded` counting agents whose rows were silently discarded
    /// (the exact "silently incomplete" class both round-1 reviewers flagged
    /// on a different finding — this function's honesty counters must not
    /// repeat it). (#4143 review fix, HISTORY-1: this doc comment previously
    /// said "ORed" — wrong; the code, the .cpp comment, and the fix-round
    /// commit message all say/implement "ANDed", which is what a narrowing
    /// intersection actually is.)
    ///
    /// `extra_scope_is_authoritative` (#4143 review fix, BLOCKING — confirmed
    /// against ADR-0017 INV-4/INV-7 by direct source inspection): `visible_set`
    /// (built from `mgmt_group_store_->get_visible_agents`, direct-membership
    /// only, no ancestor walk) predates the ADR-0017 ancestor-ward resolution
    /// the REST/MCP twins' `fleet_read_fn_`/`gate.scope` DOES perform. ANDing
    /// them together unconditionally (the original design) meant an operator
    /// admitted via an ancestor management-group role — not a DIRECT member —
    /// could be ADMITTED (200) yet see rows silently dropped by `visible_set`
    /// alone: admit and filter disagreeing, exactly the INV-4/INV-7 violation.
    /// When `true` (the REST/MCP twins), `extra_scope` (= `gate.scope`, the
    /// ADR-0017-authorized set) is the SOLE filter — `visible_set` is skipped
    /// entirely, matching the two device pickers' identical fix
    /// (`EchoTreeRoutes::all_devices_fn_`). Default `false` preserves the HTML
    /// fragment caller's existing membership-only behavior unchanged (it has
    /// no `fleet_read_fn_` gate to defer to yet — out of scope this round,
    /// same recorded exception as the two un-migrated device-picker
    /// fragments).
    EchoRetentionPausedScan
    gather_echo_retention_paused(const std::string& username,
                                const authz::VisibleSet& extra_scope = std::nullopt,
                                bool extra_scope_is_authoritative = false) const;

private:
    /// Same-site gate for the cookie-authorised dashboard dispatch routes (execute, echo-execute):
    /// see `browser_write_is_cross_site`. Defence in depth: the server-wide pre-routing gate
    /// answers a cookie-session write first. This copy runs after the permission gate and BEFORE
    /// any parsing, audit-before-dispatch row or dispatch, so a refused request does no work.
    /// Token callers are exempt. Writes the 403 and a `csrf.denied` audit row; returns true when
    /// refused.
    bool refuse_cross_site_write(const httplib::Request& req, httplib::Response& res) const;

    /// #5700 Search-term admission. A Search term substring-matches stored output, so the Create
    /// Group preview and POST that carry one run the same `Response:Read` admission the results
    /// table does (`fleet_read_fn_`, there too the sole gate for that pair), after their
    /// `ManagementGroup:Write` gate: the count and the membership otherwise tell a caller who may
    /// not read responses which agents' output holds a string. Writes the refusal (the gate's own
    /// A4 body, or 503 when `fleet_read_fn_` is unwired -- fail closed) and returns false. A
    /// confined caller is admitted; their set is still cut to their visible scope by
    /// `keep_visible`. Filters-only requests do not call it (their path is unchanged).
    bool admit_search_read(const httplib::Request& req, httplib::Response& res) const;

    /// #3619 / ADR-0033 section 9, "no audit row, no mutation": writes the `attempted` row
    /// through `persist_audit_fn_` BEFORE a mutation (a console send, a group materialisation,
    /// an Echo re-enable or purge). Call it after every refusal, so a rejected request burns no
    /// row. When the row is not stored -- the store refused it, the sink threw, or the sink is
    /// unwired (fail CLOSED) -- answers 503 with `Sec-Audit-Failed: true`, @p refusal_html as
    /// the body and, when @p toast is non-null, an HX-Trigger toast (for hx-swap="none" forms,
    /// which never show a body), and returns false: the caller returns without mutating.
    [[nodiscard]] bool audit_attempted(const httplib::Request& req, httplib::Response& res,
                                       const std::string& action, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail_text,
                                       const std::string& refusal_html,
                                       const char* toast = nullptr) const;

    /// #3619: every other row (outcome, refusal, scope narrowing, read-class send). Writes it
    /// through `audit_fn_` and, when it is not stored, marks the response
    /// `Sec-Audit-Failed: true`. Never changes the status or body: the request's own answer
    /// stands (set-and-proceed, the dashboard HTML posture in rest_audit.hpp).
    void audit_or_flag(const httplib::Request& req, httplib::Response& res,
                       const std::string& action, const std::string& result,
                       const std::string& target_type, const std::string& target_id,
                       const std::string& detail_text) const;

    std::vector<std::string> csrf_trusted_origins_;
    PersistAuditFn persist_audit_fn_;
    AuthFn auth_fn_;
    PermFn perm_fn_;
    FleetReadFn fleet_read_fn_;
    AuditFn audit_fn_;
    ResponseStore* response_store_{nullptr};
    const ForensicsPluginSet* forensics_plugins_{nullptr}; // #4990 - see set_forensics_plugin_set
    ForensicsVisibilityFn forensics_visibility_fn_;         // #4990 - see set_forensics_visibility_fn
    ManagementGroupStore* mgmt_group_store_{nullptr};
    detail::AgentRegistry* registry_{nullptr};
    TagStore* tag_store_{nullptr};
    detail::EventBus* event_bus_{nullptr};
    InstructionStore* instruction_store_{nullptr};
    AgentsJsonFn agents_json_fn_;
    DispatchFn dispatch_fn_;
    CallerFn caller_fn_;
    ResolveFn resolve_fn_;
    yuzu::MetricsRegistry* metrics_{nullptr};
    VisibleSetFn visible_set_fn_;
    // PR6.0b — see ClassifyFn's doc comment above: unset means every
    // /api/dashboard/execute dispatch is refused, never silently ungated.
    ClassifyFn classify_fn_;

    // -- Fragment renderers ---------------------------------------------------

    /// Resolves @p username's Response:Read-visible agent scope via
    /// `visible_set_fn_`. Unwired (default-constructed `visible_set_fn_`)
    /// returns `nullopt` (legacy-open, byte-identical to pre-scoping
    /// behaviour). When wired, `nullopt` from the callback passes through
    /// unchanged (sees all); a returned set — including an empty one, which
    /// signals fail-closed on a degraded store — is converted to a sorted
    /// vector.
    std::optional<std::vector<std::string>> resolve_visible_scope(
        const std::string& username) const;

    /// Same as above, but for a caller who already has the resolved session
    /// in hand: a JIT-elevated session gets the full-fleet view (`nullopt`)
    /// without ever calling `visible_set_fn_` — a username-only RBAC lookup
    /// cannot see the session's in-memory elevation, so this must short-
    /// circuit here rather than inside `visible_set_fn_`. Removes the
    /// `is_elevated(*session) ? nullopt : resolve_visible_scope(username)`
    /// ternary previously duplicated at each of this file's handler call
    /// sites.
    std::optional<std::vector<std::string>> resolve_visible_scope(
        const auth::Session& session) const;

    /// Resolves the column-name list @ref render_results and @ref
    /// col_index_for_name should render/sort against: index 0 is always
    /// "Agent", followed by the InstructionDefinition's `result_schema`-
    /// derived columns (via ResponseTemplatesEngine::synthesise_default)
    /// when @p definition_id names a definition with a non-empty schema,
    /// falling back to `columns_for_plugin(plugin)` otherwise. This is the
    /// PR1.7 remediation fix for issue where a schema-only action (no
    /// `spec.visualization`, e.g. registry's list_profiles) rendered every
    /// data column as suppressed because `columns_for_plugin` only knows a
    /// fixed per-plugin schema, not a per-action one.
    std::vector<std::string> resolve_render_columns(const std::string& plugin,
                                                     const std::string& definition_id) const;

    /// Phase-1 read shared by @ref render_results and @ref agents_matching_text: the stored
    /// responses behind the column filters (all of them when @p filters is empty).
    struct MatchingResponses {
        std::vector<StoredResponse> responses;
        bool store_degraded{false};  ///< a read failed: not "no results"
        bool result_truncated{false}; ///< the row/byte cap cut the read: counts are partial
    };
    MatchingResponses load_matching_responses(const std::string& command_id,
                                              const ResponseTierFilter& tier,
                                              const std::vector<FacetFilter>& filters) const;

    /// Distinct agent ids (first-seen order) with at least one line matching both the column
    /// @p filters and the free-text @p text_query, using exactly the predicate the results table
    /// renders. nullopt = the store is degraded. `truncated` is set when the read behind the set
    /// was cut by the row/byte cap, i.e. the set is partial.
    struct TextMatch {
        std::vector<std::string> ids;
        bool truncated{false};
    };
    std::optional<TextMatch>
    agents_matching_text(const std::string& command_id, const ResponseTierFilter& tier,
                         const std::string& plugin, const std::vector<FacetFilter>& filters,
                         const std::string& text_query) const;

    /// Render filtered/sorted/paginated result rows + OOB thead, pagination,
    /// summary. Every sort/pager link carries only the identity of the view (command, plugin,
    /// sort, dir, page, per_page, definition) and re-reads the LIVE filter bar through
    /// `hx-include="#filter-bar"`, so a changed filter is never reverted by a stale baked URL.
    /// `#result-pagination` carries `data-sort` / `data-dir` / `data-page` / `data-per-page` for
    /// the client-side summary refresh. The "N agents" count
    /// is DISTINCT agents (a stored row is one frame, so one agent can own several), and when
    /// @p text_query is set it counts only agents with a matching line; the Create Group button is
    /// offered for a text query alone. When @p definition_id is non-empty AND the definition has a
    /// `spec.visualization`, an OOB chart deck fragment is appended to
    /// re-populate `#chart-deck-host` (issue #587).
    ///
    /// Issue #254 (Phase 8.2) — when @p visible_columns is non-empty, only
    /// the listed plugin column names are rendered (the "Agent" pseudo-
    /// column is always shown). @p template_id is propagated through pager
    /// / sort URLs so that switching pages doesn't drop the chosen template.
    /// @p tier: #4990, what the caller may read with respect to the Forensics tier
    /// (`tier_filter_for`, derived by the route after its gate). Required, no default: every
    /// store read below (rows, counts, byte-cap cuts, facets) is computed over the permitted set.
    /// @p scope — #1712 / #3290 Phase 2: the fleet-read gate's composed
    /// meet(management-group, service-scope) VisibleSet. nullopt (TOP) ⇒
    /// unfiltered — a global grant or RBAC-off, byte-identical to the
    /// pre-#1712 no-op filter path for that caller class. Defaults to
    /// nullopt so the existing DashboardResultsColumnsTestAccess friend
    /// seam (test_dashboard_results_columns.cpp) keeps testing the
    /// unfiltered path unchanged.
    /// @p served - #4990: when non-null, filled with the Forensics-tier rows the rendered PAGE
    /// shows (the stored rows behind the page's lines, not the whole filtered set), so the route can
    /// write the `response.forensics.read` row. Null = the caller discards it (the test seam).
    std::string render_results(const std::string& command_id, const ResponseTierFilter& tier,
                               const std::string& plugin,
                               const std::string& sort_col, const std::string& sort_dir,
                               int page, int per_page,
                               const std::vector<FacetFilter>& filters,
                               const std::string& text_query,
                               const std::string& definition_id = {},
                               const std::string& template_id = {},
                               const std::vector<std::string>& visible_columns = {},
                               const authz::VisibleSet& scope = std::nullopt,
                               ForensicsServed* served = nullptr,
                               bool rows_omitted = false);

    /// Render filter controls for a plugin schema. Every control carries
    /// @ref kResultsSyncScope; the form itself is `hx-sync="this:drop"` so the SSE-driven summary
    /// refresh (issued from the form) is discarded, never queued, while a request is in flight.
    /// When the definition has a template with an `equals` filter, a per-request
    /// "View without saved filters" checkbox (`view_filters=off`) is rendered. When @p definition_id is
    /// non-empty it's emitted as a hidden form input so subsequent
    /// `hx-include="#filter-bar"` requests propagate it through to
    /// `/fragments/results` (which uses it to keep the chart deck live).
    /// Issue #254 — also renders a response-template selector dropdown at
    /// the top of the bar listing the synthesised default plus any
    /// operator-defined templates on the definition.
    std::string render_filter_bar(const std::string& command_id, const ResponseTierFilter& tier,
                                   const std::string& plugin,
                                   const std::string& definition_id = {},
                                   const std::string& template_id = {},
                                   const std::string& username = {},
                                   bool elevated = false);

    /// Render group creation form. `agent_count` nullopt (#2691, Doomgoose
    /// finding #7) renders an honest "count unavailable" hint instead of a
    /// number — the store read that produces it can degrade, and "0 agents
    /// will be added" is a materially different, wrong claim from "the count
    /// could not be determined".
    ///
    /// @p text_query is the results page's Search term: it is part of the group definition
    /// and travels as a hidden `q`. @p partial = the read behind the count was cut by the read
    /// cap, so the count is not the group: the form says so and the submit is disabled.
    std::string render_create_group_form(const std::string& command_id,
                                          const std::string& plugin,
                                          const std::vector<FacetFilter>& filters,
                                          std::optional<int64_t> agent_count,
                                          const std::string& text_query = {},
                                          bool partial = false);

    /// Render scope list with groups section.
    std::string render_scope_list(const std::string& selected, const std::string& username);

    /// Render the Echo retention-paused source list (Phase 15.A — issue #547).
    /// Reads the most recent `echo.status` scan **for the calling operator**,
    /// filters the responses to agents the operator can see (per
    /// `ManagementGroupStore::get_visible_agents`), parses each agent's
    /// output for `<source>_enabled=false` rows, and renders an HTML table
    /// body fragment. The username + visibility filter close the
    /// Gate 2 cross-operator data-leak finding.
    std::string render_echo_retention_paused(const std::string& username, bool can_execute,
                                            bool can_delete) const;

    /// Parse f_* filter params from request into FacetFilter vector.
    std::vector<FacetFilter> parse_filters(const httplib::Request& req,
                                            const std::string& plugin) const;

    // -- Echo retention scan tracking (Phase 15.A) -----------------------------
    //
    // Tracks the most-recent operator-triggered `echo.status` scan, **keyed by
    // operator username**, so two operators viewing /echo do not see each
    // other's scan results. The Gate 2 governance review caught the prior
    // single-shared-slot design as a HIGH cross-operator data-leak (operator
    // B opens /echo after operator A scans → sees A's data, including agents
    // outside B's RBAC scope). Per-username state plus visibility-scoped
    // rendering (see render_echo_retention_paused) close that gap.
    //
    // Bounded LRU: hard-cap at 256 entries; oldest evicted on overflow.
    // Persistence + multi-server coordination land in Phase 15.G.
    struct EchoScanState {
        std::string command_id;
        int dispatched_count{0};
        int64_t dispatched_at{0};
    };
    mutable std::mutex echo_scan_mu_;
    std::unordered_map<std::string, EchoScanState> echo_scans_by_user_;
    static constexpr std::size_t kEchoScanStateCap = 256;

    // Unit-test seam (#562): render_echo_retention_paused and its inputs
    // (response_store_, mgmt_group_store_, echo_scans_by_user_) are private, and
    // exercising the XSS-escaping / dedup / sort logic without standing up an
    // HTTP server needs to wire them directly. Test-only; grants no runtime
    // surface. See tests/unit/server/test_dashboard_echo_retention.cpp.
    friend struct DashboardEchoRetentionTestAccess;

    // Unit-test seam (PR1.7 remediation, Gate 3 architect + quality-engineer
    // finding): resolve_render_columns/render_results and their inputs
    // (instruction_store_, response_store_) are private, and the schema-aware
    // column resolution this fix added had no test at this layer -- only the
    // ResponseTemplatesEngine::synthesise_default primitive it calls was
    // pinned. Test-only; grants no runtime surface. See
    // tests/unit/server/test_dashboard_results_columns.cpp.
    friend struct DashboardResultsColumnsTestAccess;
};

} // namespace yuzu::server
