/// @file software_read_api.cpp
/// See software_read_api.hpp.

#include "software_read_api.hpp"

#include "software_list_model.hpp"
#include "software_plugin_health_model.hpp"

#include <yuzu/log_token.hpp>

#include <chrono>
#include <string_view>
#include <utility>

namespace yuzu::server::software_read_api {

namespace swc = software_catalogue;
namespace swl = software_list;
namespace swh = software_hosts;
namespace swg = software_changes;
using json = nlohmann::json;

namespace {

using Kind = Reply::Kind;

Reply bad_request(std::string message) {
    return Reply{.kind = Kind::BadRequest, .message = std::move(message)};
}

Reply host_not_found() {
    return Reply{.kind = Kind::NotFound, .message = "software host not found"};
}

// The store is not wired at all: permanent, so no retry hint.
Reply store_missing() {
    return Reply{.kind = Kind::Unavailable, .message = "software inventory store not available"};
}

Reply ok(json body, bool audit_persisted) {
    if (!audit_persisted)
        body["audit_persisted"] = false;
    return Reply{.kind = Kind::Ok, .body = std::move(body)};
}

// A degraded read: audited as a failure, answered with a retry hint, never an empty success.
Reply degraded(const AuditSink& audit, const std::string& cid, const std::string& target,
               const char* what) {
    (void)audit("failure", target, std::string(what) + " degraded; cid=" + cid);
    return Reply{.kind = Kind::Unavailable,
                 .message = std::string("software inventory store degraded - ") + what + " failed",
                 .retry_after_ms = 5000,
                 .remediation = "retry the request"};
}

// The cursor-400 / degraded-503 split of a scoped page read. nullopt = the page is usable.
template <class Expected>
std::optional<Reply> page_refusal(const AuditSink& audit, const std::string& cid,
                                  const std::string& target, const Expected& page,
                                  const char* what) {
    if (page)
        return std::nullopt;
    if (page.error())
        return bad_request(std::string(swc::cursor_error_message(*page.error())));
    return degraded(audit, cid, target, what);
}

// Set-and-proceed audit of a served page: `denied` when the scope dropped devices or the request
// named an agent outside it, then `success` on EVERY call (continuations tagged: the cursor is
// opaque but unauthenticated, so per-page audit keeps a forged cursor from walking the fleet
// unrecorded). Returns whether every row persisted.
template <class Page>
bool audit_page(const AuditSink& audit, const std::string& target, const Page& page,
                bool continuation, const std::string& cid, bool roster_truncated = false) {
    bool persisted = true;
    if (const auto denied = swc::denied_detail(page); !denied.empty())
        persisted = audit("denied", target, denied + "; cid=" + cid);
    return audit("success", target,
                 "rows=" + std::to_string(page.rows.size()) +
                     (continuation ? " page=continuation" : "") +
                     (roster_truncated ? " roster_truncated=1" : "") + " cid=" + cid) &&
           persisted;
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

// `;`-delimited like the sibling reads. agent_id is caller text, so it goes through log_token.
std::string changes_target(const SoftwareChangesQuery& q) {
    std::string out = q.agent_id.empty() ? std::string("changes:fleet")
                                         : "changes:agent=" + ::yuzu::log_token(q.agent_id);
    if (!q.kind.empty())
        out += ";kind=" + q.kind;
    if (q.since > 0)
        out += ";since=" + std::to_string(q.since);
    return out;
}

} // namespace

// ── Ctx ──────────────────────────────────────────────────────────────────────

std::int64_t Ctx::now() const {
    return now_fn ? now_fn()
                  : std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
}

std::optional<RosterView> Ctx::checked_roster() const {
    auto read = roster_fn ? roster_fn() : std::nullopt;
    if (!read)
        return std::nullopt;
    RosterView view{.truncated = read->truncated};
    view.names.reserve(read->rows.size());
    for (auto& e : read->rows)
        view.names.emplace(std::move(e.agent_id), std::move(e.hostname));
    return view;
}

swh::Roster Ctx::roster() const {
    auto view = checked_roster();
    return view ? std::move(view->names) : swh::Roster{};
}

Ctx make_ctx(Reads r, RosterFn roster_fn, SnapshotFn snapshot_fn, NowFn now_fn,
             SoftwareInventoryStore* s) {
    if (s) {
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
    Ctx c{.reads = std::move(r),
          .roster_fn = std::move(roster_fn),
          .snapshot_fn = std::move(snapshot_fn),
          .now_fn = std::move(now_fn)};
    c.ready = c.reads.hosts && c.reads.changes && c.reads.installs && c.reads.last_seen &&
              c.reads.facet_health && c.reads.summary && c.reads.catalog_meta;
    return c;
}

// ── Reads ────────────────────────────────────────────────────────────────────

Reply hosts(const Ctx& c, const Params& params, const authz::VisibleSet& scope,
            const std::string& cid, const AuditSink& audit) {
    if (!c.ready)
        return store_missing();
    const auto parsed = swh::parse_hosts_params(params);
    if (!parsed)
        return bad_request(parsed.error());
    const auto& rq = *parsed;
    const std::string target = swh::audit_target(rq);

    // The search runs over the device roster CUT TO THE CALLER'S SCOPE, so a device outside it
    // takes no part in the match or the cap. A search with no roster wired, or one whose roster
    // read failed, cannot be answered, and an empty answer would read as "no such device".
    // Without a `q` the roster only names devices.
    if (!rq.q.empty() && !c.roster_fn)
        return Reply{.kind = Kind::Unavailable,
                     .message = "device roster not available",
                     .retry_after_ms = 5000,
                     .remediation = "retry the request"};
    // A roster cut at the cap is served and flagged (roster_truncated), never refused.
    const auto checked = c.checked_roster();
    if (!checked && !rq.q.empty())
        return degraded(audit, cid, target, "device roster read");
    const RosterView none{};
    const auto& roster = checked ? *checked : none;
    const auto resolved = swh::resolve_host_search(rq.q, roster.names, scope);
    if (!resolved)
        return bad_request(resolved.error());
    const auto page = swh::read_hosts_page(c.reads.hosts, rq, *resolved);
    if (auto refusal = page_refusal(audit, cid, target, page, "hosts read"))
        return *refusal;
    const bool audit_ok =
        audit_page(audit, target, *page, !rq.cursor.empty(), cid, roster.truncated);
    return ok(swh::hosts_response_json(page->rows, facts_for(page->rows, roster.names),
                                       page->next_cursor, page->devices_omitted, roster.truncated),
              audit_ok);
}

Reply host(const Ctx& c, const std::string& agent_id, const Params& params,
           const authz::VisibleSet& scope, const std::string& cid, const AuditSink& audit) {
    if (!c.ready)
        return store_missing();
    const std::string target = swh::audit_target_host(agent_id);

    // Only cursor and limit are read: the installs page is pinned to this device.
    swc::Params wanted;
    for (const char* key : {"cursor", "limit"})
        if (const auto it = params.find(key); it != params.end())
            wanted.insert(*it);
    auto parsed = swl::parse_list_params(wanted);
    if (!parsed)
        return bad_request(parsed.error());
    auto rq = std::move(*parsed);
    rq.base.query.agent_id = agent_id;

    // An id the scope excludes is answered BEFORE any read with the very NotFound an unknown
    // device gets: no body, status, timing or store outage tells them apart. An id that cannot be
    // a stored agent id (NUL, bad UTF-8, over-long) is the same NotFound and reads nothing.
    if (!authz::in_scope(scope, agent_id)) {
        (void)audit("denied", target, "scope: agent_id outside the caller's scope; cid=" + cid);
        return host_not_found();
    }
    if (swc::text_error({&agent_id}, {&agent_id}))
        return host_not_found();

    swh::HostsQuery hq;
    hq.agent_ids = std::vector<std::string>{agent_id};
    hq.limit = 1;
    const auto hosts_read = c.reads.hosts(hq);
    if (!hosts_read)
        return degraded(audit, cid, target, "host read");
    if (hosts_read->empty()) {
        (void)audit("success", target, "found=false cid=" + cid);
        return host_not_found();
    }
    const auto page = swl::read_list_page(c.reads.installs, rq, scope);
    if (auto refusal = page_refusal(audit, cid, target, page, "installs read"))
        return *refusal;
    swl::FactsReads io;
    io.last_seen = c.reads.last_seen;
    io.hostnames = [&c] { return c.roster(); };
    const auto facts = swl::load_device_facts(io, {agent_id});
    if (!facts)
        return degraded(audit, cid, target, "last-poll read");
    const bool audit_ok = audit_page(audit, target, *page, !rq.base.cursor.empty(), cid);
    return ok(swh::host_detail_json(swh::host_row_json(hosts_read->front(), *facts),
                                    swl::list_response_json(page->rows, *facts, page->next_cursor,
                                                            page->devices_omitted, page->hit_cap)),
              audit_ok);
}

Reply changes(const Ctx& c, const Params& params, const authz::VisibleSet& scope,
              const std::string& cid, const AuditSink& audit) {
    if (!c.ready)
        return store_missing();
    const auto parsed = swg::parse_changes_params(params, c.now());
    if (!parsed)
        return bad_request(parsed.error());
    const auto& rq = *parsed;
    const std::string target = changes_target(rq.query);
    // Rows older than the settle window only (stable_before), in (observed_at, change_id) order:
    // the page order equals the eligibility order.
    const auto page = swg::read_changes_page(c.reads.changes, rq, scope);
    if (auto refusal = page_refusal(audit, cid, target, page, "changes read"))
        return *refusal;
    const bool audit_ok = audit_page(audit, target, *page, !rq.cursor.empty(), cid);
    return ok(swg::changes_response_json(page->rows, facts_for(page->rows, c.roster()),
                                         page->next_cursor, page->devices_omitted,
                                         rq.query.stable_before),
              audit_ok);
}

Reply summary(const Ctx& c, const authz::VisibleSet& scope, const std::string& cid,
              const AuditSink& audit) {
    if (!c.ready)
        return store_missing();
    const auto plan = plan_aggregate(scope);
    const std::string target = plan.mode == AggregateMode::kSnapshot ? "fleet" : "scope";

    std::optional<SoftwareSummary> summary;
    std::optional<CatalogRollupMeta> catalog;
    std::int64_t as_of = 0;
    std::string_view omitted;
    switch (plan.mode) {
    case AggregateMode::kSnapshot: {
        // The catalogue block is the rollup's own fleet figure: global callers only.
        catalog = c.reads.catalog_meta();
        if (!catalog)
            return degraded(audit, cid, target, "catalogue meta read");
        const auto snap = c.snapshot_fn ? c.snapshot_fn() : nullptr;
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
        as_of = c.now();
        summary = c.reads.summary(as_of, plan.ids);
        if (!summary)
            return degraded(audit, cid, target, "summary read");
        omitted = swg::kOmittedScope;
        break;
    }
    case AggregateMode::kOverCap:
        omitted = swg::kOmittedScope;
        break;
    }
    const bool audit_ok =
        audit("success", target, std::string("mode=") + mode_name(plan.mode) + " cid=" + cid);
    return ok(swg::summary_json(summary, catalog, as_of, omitted), audit_ok);
}

Reply plugin_health(const Ctx& c, const authz::VisibleSet& scope, const std::string& cid,
                    const AuditSink& audit) {
    if (!c.ready)
        return store_missing();
    const auto plan = plan_aggregate(scope);
    const std::string target = plan.mode == AggregateMode::kSnapshot ? "fleet" : "scope";

    std::vector<FacetHealth> facets;
    std::int64_t as_of = 0;
    std::string_view omitted;
    switch (plan.mode) {
    case AggregateMode::kSnapshot: {
        const auto snap = c.snapshot_fn ? c.snapshot_fn() : nullptr;
        if (snap) {
            facets = snap->facets;
            as_of = snap->as_of;
        } else {
            omitted = swg::kOmittedBuilding;
        }
        break;
    }
    case AggregateMode::kLive: {
        as_of = c.now();
        auto live = c.reads.facet_health(plan.ids);
        if (!live)
            return degraded(audit, cid, target, "facet health read");
        facets = std::move(*live);
        break;
    }
    case AggregateMode::kOverCap:
        omitted = swg::kOmittedScope;
        break;
    }
    // The roster names the `slowest` devices, which are inside the scope that was pushed into the
    // read (or the whole fleet for a global caller).
    bool any_slowest = false;
    for (const auto& f : facets)
        any_slowest = any_slowest || !f.slowest.empty();
    auto body = software_plugin_health::plugin_health_json(
        facets, any_slowest ? c.roster() : swh::Roster{}, as_of, omitted);
    if (!omitted.empty())
        body["facets"] = nullptr; // not shown, never an empty list
    const bool audit_ok =
        audit("success", target, std::string("mode=") + mode_name(plan.mode) + " cid=" + cid);
    return ok(std::move(body), audit_ok);
}

// ── MCP argument handling ────────────────────────────────────────────────────

std::optional<std::string> strict_args_error(const json& args, std::span<const ArgSpec> allowed) {
    if (args.is_null())
        return std::nullopt;
    if (!args.is_object())
        return std::string("arguments must be a JSON object");
    for (const auto& [key, v] : args.items()) {
        const ArgSpec* spec = nullptr;
        for (const auto& a : allowed)
            if (key == a.key)
                spec = &a;
        if (!spec)
            return "unknown argument: " + ::yuzu::log_token(key.substr(0, 64));
        if (spec->type == ArgSpec::Type::kString) {
            if (!v.is_string())
                return key + " must be a JSON string";
            if (v.get_ref<const std::string&>().size() > static_cast<std::size_t>(spec->max))
                return key + " is too long";
            continue;
        }
        // nlohmann stores every non-negative integer as unsigned: refuse above INT64_MAX
        // rather than let get<int64_t>() wrap.
        if (!v.is_number_integer() ||
            (v.is_number_unsigned() &&
             v.get<std::uint64_t>() > static_cast<std::uint64_t>(INT64_MAX)))
            return key + " must be a JSON integer";
        const auto n = v.get<std::int64_t>();
        if (n < spec->min || n > spec->max)
            return key + " must be between " + std::to_string(spec->min) + " and " +
                   std::to_string(spec->max);
    }
    return std::nullopt;
}

Params args_to_params(const json& args, std::span<const ArgSpec> allowed) {
    Params p;
    for (const auto& a : allowed) {
        const auto it = args.find(a.key);
        if (it == args.end())
            continue;
        p.emplace(a.key, a.type == ArgSpec::Type::kString ? it->get<std::string>()
                                                          : std::to_string(it->get<std::int64_t>()));
    }
    return p;
}

} // namespace yuzu::server::software_read_api
