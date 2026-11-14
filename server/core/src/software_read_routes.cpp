/// @file software_read_routes.cpp
/// See software_read_routes.hpp.

#include "software_read_routes.hpp"

#include "model_param_helpers.hpp"
#include "rest_a4_envelope_http.hpp"
#include "rest_audit.hpp"
#include "software_list_model.hpp"
#include "software_plugin_health_model.hpp"
#include "web_utils.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <string_view>
#include <utility>

namespace yuzu::server {

namespace swc = software_catalogue;
namespace swl = software_list;
namespace swh = software_hosts;
namespace swg = software_changes;
using json = nlohmann::json;

namespace {

constexpr const char* kVerbHosts = "inventory.software.hosts";
constexpr const char* kVerbHost = "inventory.software.host";
constexpr const char* kVerbChanges = "inventory.software.changes";
constexpr const char* kVerbSummary = "inventory.software.summary";
constexpr const char* kVerbPluginHealth = "inventory.software.plugin_health";
constexpr const char* kTargetType = "Inventory";

// What every handler captures: the deps with the store reads resolved, and the "is anything to
// read from" decision made once.
struct Ctx {
    SoftwareReadRoutes::FleetReadFn fleet_read_fn;
    SoftwareReadRoutes::AuditFn audit_fn;
    SoftwareReadRoutes::HostnamesFn hostnames_fn;
    SoftwareReadRoutes::RosterFn roster_fn;
    SoftwareReadRoutes::SnapshotFn snapshot_fn;
    SoftwareReadRoutes::NowFn now_fn;
    SoftwareReadRoutes::Reads reads;
    bool ready{false};

    [[nodiscard]] std::int64_t now() const { return now_fn ? now_fn() : now_epoch_seconds(); }
    // Display-only: a roster that is not wired or cannot be read leaves the names null.
    [[nodiscard]] swh::Roster roster() const { return hostnames_fn ? hostnames_fn() : swh::Roster{}; }
    // For a decision made FROM the roster (the `q` search): nullopt = the read failed.
    [[nodiscard]] std::optional<swh::Roster> checked_roster() const {
        if (roster_fn)
            return roster_fn();
        return roster();
    }
};

// Bind every read the caller left empty to the store.
void bind_store_reads(SoftwareReadRoutes::Reads& r, SoftwareInventoryStore* s) {
    if (!s)
        return;
    if (!r.hosts)
        r.hosts = [s](const swh::HostsQuery& q) { return s->query_hosts(swh::store_query(q)); };
    if (!r.changes)
        r.changes = [s](const swg::ChangesQuery& q) {
            return s->query_changes(swg::to_store_query(q));
        };
    if (!r.installs)
        r.installs = swc::devices_reader(*s);
    if (!r.last_seen)
        r.last_seen = [s](const std::vector<std::string>& ids) {
            return s->source_last_seen_bulk("installed_software", ids);
        };
    if (!r.facet_health)
        r.facet_health = [s](const std::optional<std::vector<std::string>>& ids) {
            return s->facet_health(ids);
        };
    if (!r.summary)
        r.summary = [s](std::int64_t now, const std::optional<std::vector<std::string>>& ids) {
            return s->software_summary(now, ids);
        };
    if (!r.catalog_meta)
        r.catalog_meta = [s] { return s->catalog_rollup_meta(); };
}

[[nodiscard]] bool reads_complete(const SoftwareReadRoutes::Reads& r) {
    return r.hosts && r.changes && r.installs && r.last_seen && r.facet_health && r.summary &&
           r.catalog_meta;
}

void fail(httplib::Response& res, int status, std::string_view message,
          detail::A4ErrorOpts opts = {}) {
    res.status = status;
    res.set_content(detail::a4_error(res, message, opts), "application/json");
}

// The sole gate, then the store check. nullopt = the response is written. The gate runs first, so
// a denied caller never reaches a read and an unwired store is not visible to an unauthenticated one.
std::optional<authz::FleetReadGate> admit(const Ctx& c, const httplib::Request& req,
                                          httplib::Response& res, const std::string& cid,
                                          const char* verb) {
    if (!c.fleet_read_fn) {
        spdlog::error("{}: fleet_read_fn unwired - misconfigured call site; failing closed; cid={}",
                      verb, cid);
        fail(res, 503, "service unavailable");
        return std::nullopt;
    }
    // The SOLE authorization gate: renders 401/403/503 itself and returns !admitted.
    auto gate = c.fleet_read_fn(req, res, "Inventory", "Read");
    if (!gate.admitted)
        return std::nullopt;
    if (!c.ready) {
        fail(res, 503, "software inventory store not available");
        return std::nullopt;
    }
    return gate;
}

// Audit through the throw-safe kernel: false = the row did not persist (the data is still served).
bool audit(const Ctx& c, const httplib::Request& req, const char* verb, const char* result,
           const std::string& target, const std::string& detail_text) {
    return detail::try_persist_audit(c.audit_fn, req, verb, result, kTargetType, target,
                                     detail_text);
}

// A degraded read: audited as a failure, answered 503 with a retry hint, never an empty 200.
void degraded(const Ctx& c, const httplib::Request& req, httplib::Response& res,
              const std::string& cid, const char* verb, const std::string& target,
              const char* what) {
    (void)audit(c, req, verb, "failure", target, std::string(what) + " degraded; cid=" + cid);
    fail(res, 503, std::string("software inventory store degraded - ") + what + " failed",
         {.retry_after_ms = 5000, .remediation = "retry the request"});
}

void respond(httplib::Response& res, json body, bool audit_persisted) {
    if (!audit_persisted)
        body["audit_persisted"] = false;
    res.set_content(swc::dump_safe(json{{"data", std::move(body)}, {"meta", {{"api_version", "v1"}}}}),
                    "application/json");
}

// The cursor-400 / degraded-503 split of a scoped page read. true = the page is usable.
template <class Expected>
bool page_usable(const Ctx& c, const httplib::Request& req, httplib::Response& res,
                 const std::string& cid, const char* verb, const std::string& target,
                 const Expected& page, const char* what) {
    if (page)
        return true;
    if (page.error())
        fail(res, 400, std::string(swc::cursor_error_message(*page.error())));
    else
        degraded(c, req, res, cid, verb, target, what);
    return false;
}

// Set-and-proceed audit of a served page: `denied` when the scope dropped devices or the request
// named an agent outside it, then `success` on EVERY call (continuations tagged: the cursor is
// opaque but unauthenticated, so per-page audit keeps a forged cursor from walking the fleet
// unrecorded). Returns whether every row persisted.
template <class Page>
bool audit_page(const Ctx& c, const httplib::Request& req, const char* verb,
                const std::string& target, const Page& page, bool continuation,
                const std::string& cid) {
    bool ok = true;
    if (const auto denied = swc::denied_detail(page); !denied.empty())
        ok = audit(c, req, verb, "denied", target, denied + "; cid=" + cid);
    return audit(c, req, verb, "success", target,
                 "rows=" + std::to_string(page.rows.size()) +
                     (continuation ? " page=continuation" : "") + " cid=" + cid) &&
           ok;
}

// Hostnames for the page's devices from one roster read. A device the roster does not know, or
// knows with a blank hostname (`endpoints.hostname` defaults to ''), has no entry (rendered null).
template <class Row>
swl::DeviceFacts facts_for(const std::vector<Row>& rows, const swh::Roster& roster) {
    swl::DeviceFacts f;
    for (const auto& r : rows)
        if (const auto it = roster.find(r.agent_id); it != roster.end() && !it->second.empty())
            f.hostname.emplace(it->first, it->second);
    return f;
}

void host_not_found(httplib::Response& res) {
    fail(res, 404, "software host not found");
}

// How a summary / plugin-health request is served, decided by the gate's scope alone.
enum class AggregateMode { kSnapshot, kLive, kOverCap };

struct AggregatePlan {
    AggregateMode mode{AggregateMode::kSnapshot};
    std::optional<std::vector<std::string>> ids; ///< kLive: the scope pushed into SQL
};

AggregatePlan plan_aggregate(const authz::VisibleSet& scope) {
    if (!scope)
        return {AggregateMode::kSnapshot, std::nullopt};
    if (scope->size() > swc::kScopePushdownMaxIds)
        return {AggregateMode::kOverCap, std::nullopt};
    return {AggregateMode::kLive, std::vector<std::string>(scope->begin(), scope->end())};
}

const char* mode_name(AggregateMode m) {
    switch (m) {
    case AggregateMode::kSnapshot: return "snapshot";
    case AggregateMode::kLive: return "live";
    case AggregateMode::kOverCap: return "omitted";
    }
    return "omitted";
}

std::string changes_target(const SoftwareChangesQuery& q) {
    return "changes agent_id=" + (q.agent_id.empty() ? std::string("*") : q.agent_id) +
           " kind=" + (q.kind.empty() ? std::string("*") : q.kind) +
           " since=" + std::to_string(q.since);
}

} // namespace

void SoftwareReadRoutes::register_routes(HttpRouteSink& sink, Deps deps) {
    bind_store_reads(deps.reads, deps.store);
    Ctx built{.fleet_read_fn = std::move(deps.fleet_read_fn),
              .audit_fn = std::move(deps.audit_fn),
              .hostnames_fn = std::move(deps.hostnames_fn),
              .roster_fn = std::move(deps.roster_fn),
              .snapshot_fn = std::move(deps.snapshot_fn),
              .now_fn = std::move(deps.now_fn),
              .reads = std::move(deps.reads)};
    built.ready = reads_complete(built.reads);
    const auto ctx = std::make_shared<const Ctx>(std::move(built));

    // GET /api/v1/inventory/software/hosts
    sink.Get("/api/v1/inventory/software/hosts",
             [ctx](const httplib::Request& req, httplib::Response& res) {
                 const auto cid = detail::make_correlation_id();
                 res.set_header("X-Correlation-Id", cid); // echo on every path (A3)

                 const auto gate_opt = admit(*ctx, req, res, cid, kVerbHosts);
                 if (!gate_opt)
                     return;
                 const auto& gate = *gate_opt;
                 const auto parsed = swh::parse_hosts_params(model_detail::to_params(req.params));
                 if (!parsed) {
                     fail(res, 400, parsed.error());
                     return;
                 }
                 const auto& rq = *parsed;
                 const std::string target = swh::audit_target(rq);

                 // The search runs over the device roster CUT TO THE CALLER'S SCOPE, so a device
                 // outside it takes no part in the match or the cap. A search with no roster
                 // wired, or one whose roster read failed, cannot be answered, and an empty answer
                 // would read as "no such device". Without a `q` the roster only names devices.
                 if (!rq.q.empty() && !ctx->hostnames_fn && !ctx->roster_fn) {
                     fail(res, 503, "device roster not available",
                          {.retry_after_ms = 5000, .remediation = "retry the request"});
                     return;
                 }
                 const auto checked = rq.q.empty() ? std::optional(ctx->roster()) : ctx->checked_roster();
                 if (!checked) {
                     degraded(*ctx, req, res, cid, kVerbHosts, target, "device roster read");
                     return;
                 }
                 const auto& roster = *checked;
                 const auto scope = swh::resolve_host_search(rq.q, roster, gate.scope);
                 if (!scope) {
                     fail(res, 400, scope.error());
                     return;
                 }
                 const auto page = swh::read_hosts_page(ctx->reads.hosts, rq, *scope);
                 if (!page_usable(*ctx, req, res, cid, kVerbHosts, target, page, "hosts read"))
                     return;
                 const bool audit_ok =
                     audit_page(*ctx, req, kVerbHosts, target, *page, !rq.cursor.empty(), cid);
                 respond(res,
                         swh::hosts_response_json(page->rows, facts_for(page->rows, roster),
                                                  page->next_cursor, page->devices_omitted),
                         audit_ok);
             });

    // GET /api/v1/inventory/software/hosts/{agent_id}
    sink.Get(R"(/api/v1/inventory/software/hosts/([^/]+))",
             [ctx](const httplib::Request& req, httplib::Response& res) {
                 const auto cid = detail::make_correlation_id();
                 res.set_header("X-Correlation-Id", cid); // echo on every path (A3)

                 const auto gate_opt = admit(*ctx, req, res, cid, kVerbHost);
                 if (!gate_opt)
                     return;
                 const auto& gate = *gate_opt;
                 const std::string agent_id = req.matches[1].str();
                 const std::string target = swh::audit_target_host(agent_id);

                 // Only cursor and limit are read: the installs page is pinned to this device.
                 const auto all = model_detail::to_params(req.params);
                 swc::Params wanted;
                 for (const char* key : {"cursor", "limit"})
                     if (const auto it = all.find(key); it != all.end())
                         wanted.insert(*it);
                 auto parsed = swl::parse_list_params(wanted);
                 if (!parsed) {
                     fail(res, 400, parsed.error());
                     return;
                 }
                 auto rq = std::move(*parsed);
                 rq.base.query.agent_id = agent_id;

                 // An id the scope excludes is answered BEFORE any read with the very 404 an
                 // unknown device gets: no body, status, timing or store outage tells them apart.
                 // An id that cannot be a stored agent id (NUL, bad UTF-8, over-long) is the same
                 // 404 and reads nothing.
                 if (!authz::in_scope(gate.scope, agent_id)) {
                     (void)audit(*ctx, req, kVerbHost, "denied", target,
                                 "scope: agent_id outside the caller's scope; cid=" + cid);
                     host_not_found(res);
                     return;
                 }
                 if (swc::text_error({&agent_id}, {&agent_id})) {
                     host_not_found(res);
                     return;
                 }

                 swh::HostsQuery hq;
                 hq.agent_ids = std::vector<std::string>{agent_id};
                 hq.limit = 1;
                 const auto hosts = ctx->reads.hosts(hq);
                 if (!hosts) {
                     degraded(*ctx, req, res, cid, kVerbHost, target, "host read");
                     return;
                 }
                 if (hosts->empty()) {
                     (void)audit(*ctx, req, kVerbHost, "success", target, "found=false cid=" + cid);
                     host_not_found(res);
                     return;
                 }
                 const auto page = swl::read_list_page(ctx->reads.installs, rq, gate.scope);
                 if (!page_usable(*ctx, req, res, cid, kVerbHost, target, page, "installs read"))
                     return;
                 swl::FactsReads io;
                 io.last_seen = ctx->reads.last_seen;
                 io.hostnames = ctx->hostnames_fn;
                 const auto facts = swl::load_device_facts(io, {agent_id});
                 if (!facts) {
                     degraded(*ctx, req, res, cid, kVerbHost, target, "last-poll read");
                     return;
                 }
                 const bool audit_ok =
                     audit_page(*ctx, req, kVerbHost, target, *page, !rq.base.cursor.empty(), cid);
                 respond(res,
                         swh::host_detail_json(
                             swh::host_row_json(hosts->front(), *facts),
                             swl::list_response_json(page->rows, *facts, page->next_cursor,
                                                     page->devices_omitted, page->hit_cap)),
                         audit_ok);
             });

    // GET /api/v1/inventory/software/changes
    sink.Get("/api/v1/inventory/software/changes",
             [ctx](const httplib::Request& req, httplib::Response& res) {
                 const auto cid = detail::make_correlation_id();
                 res.set_header("X-Correlation-Id", cid); // echo on every path (A3)

                 const auto gate_opt = admit(*ctx, req, res, cid, kVerbChanges);
                 if (!gate_opt)
                     return;
                 const auto& gate = *gate_opt;
                 const auto parsed =
                     swg::parse_changes_params(model_detail::to_params(req.params), ctx->now());
                 if (!parsed) {
                     fail(res, 400, parsed.error());
                     return;
                 }
                 const auto& rq = *parsed;
                 const std::string target = changes_target(rq.query);
                 // Rows older than the settle window only (stable_before), in (observed_at,
                 // change_id) order: the page order equals the eligibility order.
                 const auto page = swg::read_changes_page(ctx->reads.changes, rq, gate.scope);
                 if (!page_usable(*ctx, req, res, cid, kVerbChanges, target, page, "changes read"))
                     return;
                 const bool audit_ok =
                     audit_page(*ctx, req, kVerbChanges, target, *page, !rq.cursor.empty(), cid);
                 respond(res,
                         swg::changes_response_json(
                             page->rows, facts_for(page->rows, ctx->roster()), page->next_cursor,
                             page->devices_omitted, rq.query.stable_before),
                         audit_ok);
             });

    // GET /api/v1/inventory/software/summary
    sink.Get("/api/v1/inventory/software/summary",
             [ctx](const httplib::Request& req, httplib::Response& res) {
                 const auto cid = detail::make_correlation_id();
                 res.set_header("X-Correlation-Id", cid); // echo on every path (A3)

                 const auto gate_opt = admit(*ctx, req, res, cid, kVerbSummary);
                 if (!gate_opt)
                     return;
                 const auto plan = plan_aggregate(gate_opt->scope);
                 const std::string target = plan.mode == AggregateMode::kSnapshot ? "fleet" : "scope";

                 std::optional<SoftwareSummary> summary;
                 std::optional<CatalogRollupMeta> catalog;
                 std::int64_t as_of = 0;
                 std::string_view omitted;
                 switch (plan.mode) {
                 case AggregateMode::kSnapshot: {
                     // The catalogue block is the rollup's own fleet figure: global callers only.
                     catalog = ctx->reads.catalog_meta();
                     if (!catalog) {
                         degraded(*ctx, req, res, cid, kVerbSummary, target, "catalogue meta read");
                         return;
                     }
                     const auto snap = ctx->snapshot_fn ? ctx->snapshot_fn() : nullptr;
                     if (snap) {
                         summary = snap->summary;
                         as_of = snap->as_of;
                     } else {
                         omitted = swg::kOmittedBuilding;
                     }
                     break;
                 }
                 case AggregateMode::kLive: {
                     // The caller's own devices, aggregated live; the fleet catalogue is not theirs.
                     as_of = ctx->now();
                     summary = ctx->reads.summary(as_of, plan.ids);
                     if (!summary) {
                         degraded(*ctx, req, res, cid, kVerbSummary, target, "summary read");
                         return;
                     }
                     omitted = swg::kOmittedScope;
                     break;
                 }
                 case AggregateMode::kOverCap:
                     omitted = swg::kOmittedScope;
                     break;
                 }
                 const bool audit_ok = audit(*ctx, req, kVerbSummary, "success", target,
                                             std::string("mode=") + mode_name(plan.mode) +
                                                 " cid=" + cid);
                 respond(res, swg::summary_json(summary, catalog, as_of, omitted), audit_ok);
             });

    // GET /api/v1/inventory/software/plugin-health
    sink.Get("/api/v1/inventory/software/plugin-health",
             [ctx](const httplib::Request& req, httplib::Response& res) {
                 const auto cid = detail::make_correlation_id();
                 res.set_header("X-Correlation-Id", cid); // echo on every path (A3)

                 const auto gate_opt = admit(*ctx, req, res, cid, kVerbPluginHealth);
                 if (!gate_opt)
                     return;
                 const auto plan = plan_aggregate(gate_opt->scope);
                 const std::string target = plan.mode == AggregateMode::kSnapshot ? "fleet" : "scope";

                 std::vector<FacetHealth> facets;
                 std::int64_t as_of = 0;
                 std::string_view omitted;
                 switch (plan.mode) {
                 case AggregateMode::kSnapshot: {
                     const auto snap = ctx->snapshot_fn ? ctx->snapshot_fn() : nullptr;
                     if (snap) {
                         facets = snap->facets;
                         as_of = snap->as_of;
                     } else {
                         omitted = swg::kOmittedBuilding;
                     }
                     break;
                 }
                 case AggregateMode::kLive: {
                     as_of = ctx->now();
                     auto live = ctx->reads.facet_health(plan.ids);
                     if (!live) {
                         degraded(*ctx, req, res, cid, kVerbPluginHealth, target,
                                  "facet health read");
                         return;
                     }
                     facets = std::move(*live);
                     break;
                 }
                 case AggregateMode::kOverCap:
                     omitted = swg::kOmittedScope;
                     break;
                 }
                 // The roster names the `slowest` devices, which are inside the scope that was
                 // pushed into the read (or the whole fleet for a global caller).
                 bool any_slowest = false;
                 for (const auto& f : facets)
                     any_slowest = any_slowest || !f.slowest.empty();
                 auto body = software_plugin_health::plugin_health_json(
                     facets, any_slowest ? ctx->roster() : swh::Roster{}, as_of, omitted);
                 if (!omitted.empty())
                     body["facets"] = nullptr; // not shown, never an empty list
                 const bool audit_ok = audit(*ctx, req, kVerbPluginHealth, "success", target,
                                             std::string("mode=") + mode_name(plan.mode) +
                                                 " cid=" + cid);
                 respond(res, std::move(body), audit_ok);
             });
}

} // namespace yuzu::server
