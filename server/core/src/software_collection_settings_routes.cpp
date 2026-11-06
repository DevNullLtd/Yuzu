/// @file software_collection_settings_routes.cpp
/// See software_collection_settings_routes.hpp.

#include "software_collection_settings_routes.hpp"

#include "collection_settings_resolve.hpp"
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth
#include "rest_a4_envelope_http.hpp"
#include "rest_audit.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <expected>
#include <limits>
#include <map>
#include <set>
#include <string_view>
#include <vector>

namespace yuzu::server {

namespace cs = collection_settings;
using json = nlohmann::json;
using SettingsError = SoftwareCollectionSettingsStore::Error;

// The pure resolver mirrors the store's root id by value; the two must agree.
static_assert(std::string_view{ManagementGroupStore::kRootGroupId} == cs::kRootGroupId,
              "collection_settings::kRootGroupId must equal ManagementGroupStore::kRootGroupId");

namespace {

constexpr const char* kVerbUpdate = "software_estate.collection_settings.update";
constexpr const char* kVerbRead = "software_estate.collection_settings.read"; // refusals only
constexpr const char* kGroupTargetType = "ManagementGroup";

std::string ok_body(json data) {
    return json{{"data", std::move(data)}, {"meta", {{"api_version", "v1"}}}}.dump(
        -1, ' ', false, json::error_handler_t::replace);
}

void fail(httplib::Response& res, int status, std::string_view message,
          detail::A4ErrorOpts opts = {}) {
    res.status = status;
    res.set_content(detail::a4_error(res, message, opts), "application/json");
}

void unavailable(httplib::Response& res, std::string_view message) {
    fail(res, 503, message, {.retry_after_ms = 2000, .remediation = "retry the request"});
}

json window_json(const std::optional<cs::Window>& w) {
    return w ? json{{"start_min", w->start_min}, {"end_min", w->end_min}} : json(nullptr);
}

json document_json(const cs::StoredDocument& d) {
    return {{"group_id", d.group_id},
            {"interval_s", d.settings.interval_s},
            {"window", window_json(d.settings.window)},
            {"timezone", d.settings.timezone},
            {"plugins", d.settings.plugins},
            {"priority", d.settings.priority},
            {"version", d.version},
            {"updated_at", d.updated_at},
            {"updated_by", d.updated_by}};
}

json effective_json(const cs::EffectiveSettings& e) {
    return {{"interval_s", e.interval_s},
            {"window", window_json(e.window)},
            {"timezone", e.timezone},
            {"plugins", e.plugins}};
}

// A store error that is not the caller's mistake: every kind but the ones a PUT maps itself.
void store_unavailable(httplib::Response& res, const SettingsError& e) {
    if (e.kind == SettingsError::Kind::Corrupt)
        unavailable(res, "a stored collection settings document is unreadable");
    else if (e.kind == SettingsError::Kind::TooMany)
        unavailable(res, "too many collection settings documents to list");
    else
        unavailable(res, "collection settings store unavailable");
}

enum class Authority { AdmitGlobal, AdmitGroup, Deny, Degraded };

// Global ManagementGroup grant, else an ITServiceOwner row on the group or an ancestor.
// `op` is "Read" or "Write". The unavailable-aware probe runs into a THROWAWAY response so an
// admit through the group walk never answers on a response the probe dirtied; a 503 from it (the
// RBAC read could not be completed) is copied to `res` and ends the request, so an outage never
// widens or silently narrows authority. The group walk is excluded for sessions the permission
// gate would itself have refused: service-scoped, MCP-tier and engine sessions.
Authority group_authority(const SoftwareCollectionSettingsRoutes::Deps& deps,
                          const httplib::Request& req, httplib::Response& res,
                          const auth::Session& session, const std::string& group_id,
                          const char* op, bool needs_global) {
    httplib::Response probe; // throwaway
    if (deps.probe_perm_fn(req, probe, kGroupTargetType, op))
        return Authority::AdmitGlobal;
    if (probe.status == 503) {
        res.status = probe.status;
        res.body = probe.body;
        // The probe minted its own correlation id and its body names it: that one replaces
        // the id on `res`, so the response carries exactly one.
        res.headers.erase("X-Correlation-Id");
        for (const auto& [k, v] : probe.headers)
            res.set_header(k, v);
        return Authority::Degraded;
    }
    if (needs_global)
        return Authority::Deny;
    if (!session.token_scope_service.empty() || !session.mcp_tier.empty() || session.is_engine())
        return Authority::Deny;
    const auto ancestors = deps.mgmt_store->get_ancestor_ids(group_id);
    if (!ancestors) {
        unavailable(res, "management group hierarchy read unavailable");
        return Authority::Degraded;
    }
    const auto rows = deps.mgmt_store->get_assignments_for_principal(session.username, {});
    if (!rows) {
        unavailable(res, "management group role read unavailable");
        return Authority::Degraded;
    }
    for (const auto& r : *rows) {
        if (r.principal_type != "user" || r.principal_id != session.username ||
            r.role_name != "ITServiceOwner")
            continue;
        if (r.group_id == group_id ||
            std::ranges::find(*ancestors, r.group_id) != ancestors->end())
            return Authority::AdmitGroup;
    }
    return Authority::Deny;
}

// nullopt = not an integer, or out of int range.
std::optional<int> read_int(const json& v) {
    if (v.is_number_unsigned()) {
        const auto u = v.get<std::uint64_t>();
        if (u > static_cast<std::uint64_t>(std::numeric_limits<int>::max()))
            return std::nullopt;
        return static_cast<int>(u);
    }
    if (!v.is_number_integer())
        return std::nullopt;
    const auto i = v.get<std::int64_t>();
    if (i < std::numeric_limits<int>::min() || i > std::numeric_limits<int>::max())
        return std::nullopt;
    return static_cast<int>(i);
}

// Body -> settings + expected version, or the 400 text.
struct ParsedPut {
    cs::CollectionSettings settings;
    std::optional<std::string> expected_version; // nullopt = create only
    std::string expected_text;                    // "none" or the 64-hex, for the audit row
    bool priority_given{false};                   // the body carried a `priority` key
};

std::expected<ParsedPut, std::string> parse_put(const std::string& body) {
    using Bad = std::unexpected<std::string>;
    if (mcp::json_exceeds_depth(body, mcp::kMcpMaxJsonDepth))
        return Bad("body nesting is too deep");
    const auto j = json::parse(body, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object())
        return Bad("body must be a JSON object");
    for (const auto& [key, v] : j.items()) {
        (void)v;
        if (key != "interval_s" && key != "window" && key != "timezone" && key != "plugins" &&
            key != "priority" && key != "expected_version")
            return Bad("unknown field: " + audit_token(key.substr(0, 64)));
    }
    ParsedPut out;
    const auto interval = j.find("interval_s");
    const auto interval_s = interval == j.end() ? std::nullopt : read_int(*interval);
    if (!interval_s)
        return Bad("interval_s is required and must be an integer");
    out.settings.interval_s = *interval_s;
    if (const auto w = j.find("window"); w != j.end() && !w->is_null()) {
        if (!w->is_object() || w->size() != 2)
            return Bad("window must be null or {start_min, end_min}");
        const auto s = w->find("start_min");
        const auto e = w->find("end_min");
        const auto start = s == w->end() ? std::nullopt : read_int(*s);
        const auto end = e == w->end() ? std::nullopt : read_int(*e);
        if (!start || !end)
            return Bad("window needs integer start_min and end_min");
        out.settings.window = cs::Window{*start, *end};
    }
    if (const auto tz = j.find("timezone"); tz != j.end()) {
        if (!tz->is_string())
            return Bad("timezone must be a string");
        out.settings.timezone = tz->get<std::string>();
    }
    const auto plugins = j.find("plugins");
    if (plugins == j.end() || !plugins->is_object())
        return Bad("plugins is required and must be an object");
    // An unknown key is refused here, not by validate(), so the name it echoes into the message
    // and the audit detail is bounded and neutralised (CWE-117).
    for (const auto& [name, on] : plugins->items()) {
        if (!cs::is_collection_plugin(name))
            return Bad("unknown plugin key: " + audit_token(name.substr(0, 64)));
        if (!on.is_boolean())
            return Bad("plugins values must be booleans");
        out.settings.plugins[name] = on.get<bool>();
    }
    if (const auto p = j.find("priority"); p != j.end()) {
        const auto priority = read_int(*p);
        if (!priority)
            return Bad("priority must be an integer");
        out.settings.priority = *priority;
        out.priority_given = true;
    }
    out.expected_text = "none";
    if (const auto ev = j.find("expected_version"); ev != j.end()) {
        if (!ev->is_string())
            return Bad("expected_version must be a string");
        const auto text = ev->get<std::string>();
        if (text != "none") {
            if (!cs::is_version_text(text))
                return Bad("expected_version must be 'none' or 64 lowercase hex characters");
            out.expected_version = text;
            out.expected_text = text;
        }
    }
    return out;
}

std::string one_line(const std::optional<cs::CollectionSettings>& s) {
    return s ? cs::canonical_text(*s, /*with_priority=*/true, ';') : std::string{"none"};
}

} // namespace

void SoftwareCollectionSettingsRoutes::register_routes(HttpRouteSink& sink, Deps deps) {
    const auto wired = [deps](httplib::Response& res, bool needs_mgmt) {
        detail::ensure_correlation_id(res);
        if (!deps.auth_fn || !deps.perm_fn || !deps.probe_perm_fn || !deps.scoped_perm_fn) {
            spdlog::error("SoftwareCollectionSettingsRoutes: gate unwired; failing closed");
            fail(res, 503, "service unavailable");
            return false;
        }
        if (!deps.store || (needs_mgmt && !deps.mgmt_store)) {
            fail(res, 503, "collection settings not available");
            return false;
        }
        return true;
    };

    // -- GET list ---------------------------------------------------------------------------
    sink.Get("/api/v1/inventory/software/collection-settings",
             [deps, wired](const httplib::Request& req, httplib::Response& res) {
                 if (!wired(res, true))
                     return;
                 if (!deps.perm_fn(req, res, kGroupTargetType, "Read"))
                     return;
                 const auto docs = deps.store->list_all();
                 if (!docs) {
                     store_unavailable(res, docs.error());
                     return;
                 }
                 // A deleted group's document is orphaned (no cross-schema foreign key): listed
                 // only while its group is in the tree, as the resolver reads it.
                 const auto groups = deps.mgmt_store->list_groups_checked();
                 if (!groups) {
                     unavailable(res, "management group tree read unavailable");
                     return;
                 }
                 std::set<std::string> live;
                 for (const auto& g : *groups)
                     live.insert(g.id);
                 const auto def_version = cs::effective_version(cs::kFleetDefault.effective());
                 if (!def_version) {
                     unavailable(res, "digest unavailable");
                     return;
                 }
                 json fleet = effective_json(cs::kFleetDefault.effective());
                 fleet["priority"] = 0;
                 fleet["version"] = *def_version;
                 json arr = json::array();
                 for (const auto& d : *docs) {
                     if (live.contains(d.group_id))
                         arr.push_back(document_json(d));
                 }
                 res.set_content(ok_body({{"fleet_default", std::move(fleet)},
                                          {"documents", std::move(arr)}}),
                                 "application/json");
             });

    // -- GET one group ----------------------------------------------------------------------
    sink.Get(R"(/api/v1/inventory/software/collection-settings/([a-f0-9]+))",
             [deps, wired](const httplib::Request& req, httplib::Response& res) {
                 if (!wired(res, true))
                     return;
                 const auto session = deps.auth_fn(req, res);
                 if (!session)
                     return;
                 const std::string group_id = req.matches[1].str();
                 switch (group_authority(deps, req, res, *session, group_id, "Read", false)) {
                 case Authority::AdmitGlobal:
                 case Authority::AdmitGroup:
                     break;
                 case Authority::Degraded:
                     return;
                 case Authority::Deny:
                     // The quiet probe withholds its row for a cookie session, so the refusal
                     // writes its own.
                     (void)detail::try_persist_audit(deps.audit_fn, req, kVerbRead, "denied",
                                                     kGroupTargetType, group_id,
                                                     "not authorised to read this group");
                     fail(res, 403, "forbidden");
                     return;
                 }
                 const auto group = deps.mgmt_store->get_group_checked(group_id);
                 if (!group) {
                     unavailable(res, "management group read unavailable");
                     return;
                 }
                 if (!*group) {
                     fail(res, 404, "group not found");
                     return;
                 }
                 const auto doc = deps.store->get(group_id);
                 if (!doc) {
                     store_unavailable(res, doc.error());
                     return;
                 }
                 if (!*doc) {
                     fail(res, 404, "no document for this group",
                          {.remediation = "PUT a document for the group"});
                     return;
                 }
                 res.set_content(ok_body(document_json(**doc)), "application/json");
             });

    // -- PUT one group ----------------------------------------------------------------------
    sink.Put(
        R"(/api/v1/inventory/software/collection-settings/([a-f0-9]+))",
        [deps, wired](const httplib::Request& req, httplib::Response& res) {
            if (!wired(res, true))
                return;
            const auto session = deps.auth_fn(req, res);
            if (!session)
                return;
            const std::string group_id = req.matches[1].str();
            const auto refuse = [&](int status, const std::string& message,
                                    const std::string& audit_detail) {
                (void)detail::try_persist_audit(deps.audit_fn, req, kVerbUpdate, "denied",
                                                kGroupTargetType, group_id, audit_detail);
                fail(res, status, message);
            };

            const bool is_root = group_id == cs::kRootGroupId;
            const Authority authority =
                group_authority(deps, req, res, *session, group_id, "Write", is_root);
            if (authority == Authority::Degraded) {
                (void)detail::try_persist_audit(deps.audit_fn, req, kVerbUpdate, "denied",
                                                kGroupTargetType, group_id,
                                                "authority read degraded");
                return;
            }
            if (authority == Authority::Deny) {
                refuse(403, "forbidden", "not authorised to write this group");
                return;
            }

            auto parsed_or = parse_put(req.body);
            if (!parsed_or) {
                refuse(400, parsed_or.error(), parsed_or.error());
                return;
            }
            ParsedPut& parsed = *parsed_or;
            if (const auto ok = cs::validate(parsed.settings, is_root); !ok) {
                refuse(400, ok.error(), ok.error());
                return;
            }

            const auto group = deps.mgmt_store->get_group_checked(group_id);
            if (!group) {
                unavailable(res, "management group read unavailable");
                return;
            }
            if (!*group) {
                refuse(404, "group not found", "group not found");
                return;
            }
            const auto stored = deps.store->get(group_id);
            if (!stored) {
                store_unavailable(res, stored.error());
                return;
            }
            const int stored_priority = *stored ? (*stored)->settings.priority : 0;
            // Priority is outside a group owner's writable surface: an omitted one keeps the
            // stored value, an explicit different one is refused.
            if (!parsed.priority_given && authority == Authority::AdmitGroup)
                parsed.settings.priority = stored_priority;
            if (parsed.settings.priority != stored_priority &&
                authority != Authority::AdmitGlobal) {
                refuse(403,
                       "changing the priority needs the global ManagementGroup:Write grant; omit "
                       "priority to keep the stored value",
                       "priority change needs the global grant");
                return;
            }

            const std::optional<cs::CollectionSettings> prior_settings =
                *stored ? std::optional<cs::CollectionSettings>{(*stored)->settings}
                        : std::nullopt;
            const std::string requested_detail = "before=" + one_line(prior_settings) +
                                                 " after=" + one_line(parsed.settings) +
                                                 " expected_version=" + parsed.expected_text;
            if (!detail::emit_behavioral_audit(deps.audit_fn, req, res, kVerbUpdate, "requested",
                                               kGroupTargetType, group_id, requested_detail)) {
                fail(res, 503, "audit subsystem unavailable - request not served",
                     {.retry_after_ms = 5000});
                return;
            }

            const auto put = deps.store->put(group_id, parsed.settings, parsed.expected_version,
                                             session->username);
            // The outcome row. A failed persist here cannot undo a landed write: the
            // Sec-Audit-Failed header carries the signal.
            const auto outcome = [&](const char* result, const std::string& text) {
                (void)detail::emit_behavioral_audit(deps.audit_fn, req, res, kVerbUpdate, result,
                                                    kGroupTargetType, group_id, text);
            };
            if (put) {
                outcome("success",
                        "before=" + one_line(put->previous ? std::optional<cs::CollectionSettings>{
                                                                 put->previous->settings}
                                                           : std::nullopt) +
                            " after=" + cs::canonical_text(put->stored.settings, true, ';') +
                            " version=" + put->stored.version);
                json data = document_json(put->stored);
                data["previous_version"] =
                    put->previous ? json(put->previous->version) : json(nullptr);
                res.set_content(ok_body(std::move(data)), "application/json");
                return;
            }
            const SettingsError& e = put.error();
            switch (e.kind) {
            case SettingsError::Kind::Conflict: {
                outcome("failure", "version mismatch");
                res.status = 409;
                auto body = json::parse(
                    detail::a4_error(res, "the stored document changed since the caller read it",
                                     {.remediation = "GET the document and retry with its version"}));
                body["error"]["current"] = e.current ? document_json(*e.current) : json(nullptr);
                res.set_content(body.dump(-1, ' ', false, json::error_handler_t::replace),
                                "application/json");
                return;
            }
            case SettingsError::Kind::InvalidTimezone:
                outcome("denied", "timezone is not a known IANA zone");
                fail(res, 400, "timezone is not a known IANA zone");
                return;
            case SettingsError::Kind::InvalidInput:
                outcome("denied", e.message);
                fail(res, 400, e.message);
                return;
            case SettingsError::Kind::OutcomeUnknown:
                outcome("failure", "outcome unknown; the write may have landed; verify with GET");
                fail(res, 503, "outcome unknown; GET the document to verify",
                     {.retry_after_ms = 2000, .remediation = "GET the document to verify"});
                return;
            default:
                outcome("failure", "store write failed");
                store_unavailable(res, e);
                return;
            }
        });

    // -- GET effective settings of one device ----------------------------------------------
    sink.Get(
        R"(/api/v1/inventory/software/hosts/([A-Za-z0-9_.:-]{1,128})/collection-settings)",
        [deps, wired](const httplib::Request& req, httplib::Response& res) {
            if (!wired(res, true))
                return;
            if (!deps.plugin_config_store) {
                fail(res, 503, "collection settings not available");
                return;
            }
            const std::string agent_id = req.matches[1].str();
            if (!deps.scoped_perm_fn(req, res, "Inventory", "Read", agent_id))
                return;
            const auto member_groups = deps.mgmt_store->get_agent_groups(agent_id);
            if (!member_groups) {
                unavailable(res, "management group membership read unavailable");
                return;
            }
            const auto groups = deps.mgmt_store->list_groups_checked();
            if (!groups) {
                unavailable(res, "management group tree read unavailable");
                return;
            }
            const auto docs = deps.store->list_all();
            if (!docs) {
                store_unavailable(res, docs.error());
                return;
            }
            // A read route: a degraded kill-switch read is a 503, never a document that reports
            // every collector off.
            std::map<std::string, bool> killed;
            json kill_list = json::array();
            for (const auto p : cs::kCollectionPlugins) {
                const auto ks = deps.plugin_config_store->get_kill_switch(p, "");
                if (!ks) {
                    unavailable(res, "kill-switch read unavailable");
                    return;
                }
                killed[std::string{p}] = !ks->enabled;
                if (!ks->enabled)
                    kill_list.push_back(std::string{p});
            }
            std::vector<cs::GroupNode> tree;
            tree.reserve(groups->size());
            for (const auto& g : *groups)
                tree.push_back(cs::GroupNode{g.id, g.parent_id, g.created_at});
            const auto resolved = cs::resolve(*member_groups, tree, *docs, killed);
            if (!resolved) {
                unavailable(res, "settings could not be resolved");
                return;
            }
            res.set_content(ok_body({{"agent_id", agent_id},
                                     {"effective", effective_json(resolved->effective)},
                                     {"source_group_id", resolved->source_group_id},
                                     {"version", resolved->version},
                                     {"kill_switched", std::move(kill_list)}}),
                            "application/json");
        });
}

} // namespace yuzu::server
