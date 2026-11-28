/// @file software_collection_settings_api.cpp
/// See software_collection_settings_api.hpp.

#include "software_collection_settings_api.hpp"

#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth
#include "web_utils.hpp"   // audit_token

#include <expected>
#include <limits>
#include <map>
#include <set>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server::software_collection_settings_api {

namespace cs = collection_settings;
using json = nlohmann::json;
using SettingsError = SoftwareCollectionSettingsStore::Error;
using Kind = Reply::Kind;

// The pure resolver mirrors the store's root id by value; the two must agree.
static_assert(std::string_view{ManagementGroupStore::kRootGroupId} == cs::kRootGroupId,
              "collection_settings::kRootGroupId must equal ManagementGroupStore::kRootGroupId");

namespace {

Reply bad_request(std::string message) {
    return Reply{.kind = Kind::BadRequest, .message = std::move(message)};
}

Reply not_found(std::string message, std::string remediation = {}) {
    return Reply{.kind = Kind::NotFound,
                 .message = std::move(message),
                 .remediation = std::move(remediation)};
}

Reply unavailable(std::string message) {
    return Reply{.kind = Kind::Unavailable,
                 .message = std::move(message),
                 .retry_after_ms = 2000,
                 .remediation = "retry the request"};
}

// A store condition a retry cannot clear (a damaged row, the document cap): no retry hint.
Reply permanent(std::string message) {
    return Reply{.kind = Kind::Unavailable,
                 .message = std::move(message),
                 .remediation = "operator action required; retrying does not help (see the REST API "
                                "manual, Software collection settings)"};
}

Reply not_wired() {
    return Reply{.kind = Kind::Unavailable, .message = "collection settings not available"};
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

Reply ok(json data) {
    return Reply{.kind = Kind::Ok, .body = std::move(data)};
}

// A store error that is not the caller's mistake: every kind but the ones a PUT maps itself.
Reply store_unavailable(const SettingsError& e) {
    if (e.kind == SettingsError::Kind::Corrupt)
        return permanent("a stored collection settings document is unreadable");
    if (e.kind == SettingsError::Kind::TooMany)
        return permanent("the collection settings document cap (" +
                         std::to_string(SoftwareCollectionSettingsStore::kListRowCap) +
                         ") is reached");
    return unavailable("collection settings store unavailable");
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

bool stores_ready(const Stores& s, bool needs_plugin_config) {
    return s.store && s.mgmt_store && (!needs_plugin_config || s.plugin_config_store);
}

// -- list ---------------------------------------------------------------------------------------
Reply list(const Stores& s) {
    if (!stores_ready(s))
        return not_wired();
    const auto docs = s.store->list_all();
    if (!docs)
        return store_unavailable(docs.error());
    // A deleted group's document is orphaned (no cross-schema foreign key): listed only while its
    // group is in the tree, as the resolver reads it.
    const auto groups = s.mgmt_store->list_groups_checked();
    if (!groups)
        return unavailable("management group tree read unavailable");
    std::set<std::string> live;
    for (const auto& g : *groups)
        live.insert(g.id);
    const auto def_version = cs::effective_version(cs::kFleetDefault.effective());
    if (!def_version)
        return unavailable("digest unavailable");
    json fleet = effective_json(cs::kFleetDefault.effective());
    fleet["priority"] = 0;
    fleet["version"] = *def_version;
    json arr = json::array();
    for (const auto& d : *docs) {
        if (live.contains(d.group_id))
            arr.push_back(document_json(d));
    }
    return ok({{"fleet_default", std::move(fleet)}, {"documents", std::move(arr)}});
}

// -- get one group ------------------------------------------------------------------------------
Reply get(const Stores& s, const std::string& group_id, const AuthorityFn& authority,
          const AuditSink& audit) {
    if (!stores_ready(s))
        return not_wired();
    switch (authority("Read")) {
    case Authority::Admit:
        break;
    case Authority::Degraded:
    case Authority::Lapsed:
        return Reply{.kind = Kind::Handled};
    case Authority::Deny:
        // The quiet probe withholds its row for a cookie session, so the refusal writes its own.
        (void)audit(kVerbRead, "denied", group_id, "refused by the ManagementGroup:Read gate",
                    /*signal_failure=*/false);
        return Reply{.kind = Kind::Forbidden, .message = "forbidden"};
    }
    const auto group = s.mgmt_store->get_group_checked(group_id);
    if (!group)
        return unavailable("management group read unavailable");
    if (!*group)
        return not_found("group not found");
    const auto doc = s.store->get(group_id);
    if (!doc)
        return store_unavailable(doc.error());
    if (!*doc)
        return not_found("no document for this group", "PUT a document for the group");
    return ok(document_json(**doc));
}

// -- put one group ------------------------------------------------------------------------------
Reply put(const Stores& s, const std::string& group_id, const std::string& body,
          const std::string& username, const AuthorityFn& authority, const AuditSink& audit) {
    if (!stores_ready(s))
        return not_wired();
    const auto refuse = [&](Kind kind, const std::string& message, const std::string& audit_detail) {
        (void)audit(kVerbUpdate, "denied", group_id, audit_detail, /*signal_failure=*/false);
        return Reply{.kind = kind, .message = message};
    };

    const bool is_root = group_id == cs::kRootGroupId;
    const Authority first = authority("Write");
    if (first == Authority::Degraded || first == Authority::Lapsed) {
        (void)audit(kVerbUpdate, "denied", group_id,
                    first == Authority::Lapsed ? "session ended ahead of the write"
                                               : "authority read degraded",
                    /*signal_failure=*/false);
        return Reply{.kind = Kind::Handled};
    }
    if (first == Authority::Deny)
        return refuse(Kind::Forbidden, "forbidden", "refused by the ManagementGroup:Write gate");

    auto parsed_or = parse_put(body);
    if (!parsed_or)
        return refuse(Kind::BadRequest, parsed_or.error(), parsed_or.error());
    const ParsedPut& parsed = *parsed_or;
    if (const auto valid = cs::validate(parsed.settings, is_root); !valid)
        return refuse(Kind::BadRequest, valid.error(), valid.error());

    const auto group = s.mgmt_store->get_group_checked(group_id);
    if (!group)
        return unavailable("management group read unavailable");
    if (!*group)
        return refuse(Kind::NotFound, "group not found", "group not found");
    const auto stored = s.store->get(group_id);
    if (!stored)
        return store_unavailable(stored.error());
    const std::optional<cs::CollectionSettings> prior_settings =
        *stored ? std::optional<cs::CollectionSettings>{(*stored)->settings} : std::nullopt;
    const std::string requested_detail = "before=" + one_line(prior_settings) +
                                         " after=" + one_line(parsed.settings) +
                                         " expected_version=" + parsed.expected_text;
    if (!audit(kVerbUpdate, "requested", group_id, requested_detail, /*signal_failure=*/true))
        return Reply{.kind = Kind::Unavailable,
                     .message = "audit subsystem unavailable - request not served",
                     .retry_after_ms = 5000};
    // The outcome row. A failed persist here cannot undo a landed write: a surface reports it.
    bool outcome_persisted = true;
    const auto outcome = [&](const char* result, const std::string& text) {
        if (!audit(kVerbUpdate, result, group_id, text, /*signal_failure=*/true))
            outcome_persisted = false;
    };
    const auto finish = [&](Reply r) {
        r.audit_persisted = outcome_persisted;
        return r;
    };

    // The gate again, immediately ahead of the write: a revoke that lands while the request waited
    // on its reads and the requested row refuses it. The settings transaction cannot join the RBAC
    // tables: a revoke landing between this check and the COMMIT is ordered behind the write (an
    // accepted window of one store call).
    switch (authority("Write")) {
    case Authority::Admit:
        break;
    case Authority::Degraded:
        outcome("denied", "authority read degraded");
        return finish(Reply{.kind = Kind::Handled});
    case Authority::Lapsed:
        outcome("denied", "session ended ahead of the write");
        return finish(Reply{.kind = Kind::Handled});
    case Authority::Deny:
        outcome("denied", "write authority withdrawn ahead of the write");
        return finish(Reply{.kind = Kind::Forbidden, .message = "forbidden"});
    }

    const auto put_result =
        s.store->put(group_id, parsed.settings, parsed.expected_version, username);
    if (put_result) {
        outcome("success",
                "before=" + one_line(put_result->previous
                                         ? std::optional<cs::CollectionSettings>{put_result->previous
                                                                                     ->settings}
                                         : std::nullopt) +
                    " after=" + cs::canonical_text(put_result->stored.settings, true, ';') +
                    " version=" + put_result->stored.version);
        json data = document_json(put_result->stored);
        data["previous_version"] =
            put_result->previous ? json(put_result->previous->version) : json(nullptr);
        return finish(ok(std::move(data)));
    }
    const SettingsError& e = put_result.error();
    switch (e.kind) {
    case SettingsError::Kind::Conflict:
        outcome("failure", "version mismatch");
        return finish(Reply{
            .kind = Kind::Conflict,
            .body = e.current ? document_json(*e.current) : json(nullptr),
            .message = e.current ? "the stored document changed since the caller read it"
                                 : "no document exists for this group",
            .remediation = e.current ? "GET the document and retry with its version"
                                     : "send expected_version none to create the document"});
    case SettingsError::Kind::InvalidTimezone:
        outcome("denied", "timezone is not a known IANA zone");
        return finish(bad_request("timezone is not a known IANA zone"));
    case SettingsError::Kind::InvalidInput:
        outcome("denied", e.message);
        return finish(bad_request(e.message));
    case SettingsError::Kind::OutcomeUnknown:
        outcome("failure", "outcome unknown; the write may have landed; verify with GET");
        return finish(Reply{.kind = Kind::Unavailable,
                            .message = "outcome unknown; GET the document to verify",
                            .retry_after_ms = 2000,
                            .remediation = "GET the document to verify"});
    default:
        outcome("failure", e.kind == SettingsError::Kind::Corrupt ? "stored document unreadable"
                           : e.kind == SettingsError::Kind::TooMany ? "document cap reached"
                                                                    : "store write failed");
        return finish(store_unavailable(e));
    }
}

// -- effective settings of one device -----------------------------------------------------------
Reply effective(const Stores& s, const std::string& agent_id) {
    if (!stores_ready(s, /*needs_plugin_config=*/true))
        return not_wired();
    const auto member_groups = s.mgmt_store->get_agent_groups(agent_id);
    if (!member_groups)
        return unavailable("management group membership read unavailable");
    const auto groups = s.mgmt_store->list_groups_checked();
    if (!groups)
        return unavailable("management group tree read unavailable");
    const auto docs = s.store->list_all();
    if (!docs)
        return store_unavailable(docs.error());
    // A read route: a degraded kill-switch read is a 503, never a document that reports every
    // collector off.
    std::map<std::string, bool> killed;
    json kill_list = json::array();
    for (const auto p : cs::kCollectionPlugins) {
        const auto ks = s.plugin_config_store->get_kill_switch(p, "");
        if (!ks)
            return unavailable("kill-switch read unavailable");
        killed[std::string{p}] = !ks->enabled;
        if (!ks->enabled)
            kill_list.push_back(std::string{p});
    }
    std::vector<cs::GroupNode> tree;
    tree.reserve(groups->size());
    for (const auto& g : *groups)
        tree.push_back(cs::GroupNode{g.id, g.parent_id, g.created_at});
    const auto resolved = cs::resolve(*member_groups, tree, *docs, killed);
    if (!resolved)
        return unavailable("settings could not be resolved");
    return ok({{"agent_id", agent_id},
               {"effective", effective_json(resolved->effective)},
               {"source_group_id", resolved->source_group_id},
               {"version", resolved->version},
               {"kill_switched", std::move(kill_list)}});
}

} // namespace yuzu::server::software_collection_settings_api
