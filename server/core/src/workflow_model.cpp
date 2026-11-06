#include "workflow_model.hpp"

#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard
#include "sha256_hex.hpp"

#include <yuzu/server/auth.hpp> // auth::kMaxAgentIdLength

#include <algorithm>
#include <string_view>
#include <unordered_set>

namespace yuzu::server {

namespace {

// The JSON text length of one id as the stored column will hold it. `replace` keeps an id with an
// invalid UTF-8 byte from throwing out of the run row's insert and keeps the column valid UTF-8.
std::string id_json_text(std::string_view id) {
    return nlohmann::json(std::string(id)).dump(-1, ' ', false,
                                                nlohmann::json::error_handler_t::replace);
}

// An id the stored copy never holds. Over `kStoredAgentIdSkipBytes` it cannot be a registered agent
// id. One containing a NUL byte cannot either (registration refuses it), and it must not be
// stored: nlohmann writes it as a `\u0000` escape, which jsonb refuses, and one such escape takes
// the whole column out of every confined list, the creator's own included. Skipping it hides no
// device.
bool unstorable_id(std::string_view id) {
    return id.size() > kStoredAgentIdSkipBytes || id.find('\0') != std::string_view::npos;
}

} // namespace

std::string stored_agent_ids_json(const std::vector<std::string>& agent_ids,
                                  const std::function<bool(const std::string&)>& first,
                                  std::size_t max, std::size_t max_bytes) {
    static_assert(kStoredAgentIdSkipBytes == auth::kMaxAgentIdLength);

    // Distinct ids in first-seen order. Duplicates are dropped BEFORE any cap, so padding a list
    // with copies of one id cannot push a real id out of the stored copy.
    std::vector<const std::string*> distinct;
    distinct.reserve(agent_ids.size());
    {
        std::unordered_set<std::string_view> seen;
        seen.reserve(agent_ids.size());
        for (const auto& id : agent_ids)
            if (seen.insert(id).second)
                distinct.push_back(&id);
    }

    const auto to_array = [](const std::vector<const std::string*>& ids) {
        nlohmann::json arr = nlohmann::json::array();
        for (const auto* id : ids)
            arr.push_back(*id);
        return arr;
    };
    const auto dump = [](const nlohmann::json& j) {
        return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    };

    // Whole copy: every distinct id fits the count and byte bounds and none is unstorable.
    {
        std::size_t bytes = 2; // '[' and ']'
        bool whole = distinct.size() <= max;
        for (std::size_t i = 0; whole && i < distinct.size(); ++i) {
            const auto& id = *distinct[i];
            if (unstorable_id(id)) {
                whole = false;
                break;
            }
            bytes += id_json_text(id).size() + (i == 0 ? 0 : 1);
            whole = bytes <= max_bytes;
        }
        if (whole)
            return dump(to_array(distinct));
    }

    // Bounded copy: the ids `first` accepts, then the rest, each group in first-seen order,
    // admitted while the count, the byte budget (less the marker's reserve) and the per-id length
    // allow; admission stops at the first id that would not fit. An unstorable id is never stored.
    const std::size_t id_budget =
        max_bytes > kStoredAgentIdsMarkerReserve ? max_bytes - kStoredAgentIdsMarkerReserve : 0;
    std::vector<const std::string*> kept;
    std::size_t bytes = 2;
    bool open = true;
    const auto admit = [&](bool want_first) {
        for (const auto* idp : distinct) {
            if (!open)
                return;
            const auto& id = *idp;
            if (unstorable_id(id) || (first && first(id)) != want_first)
                continue;
            const auto add = id_json_text(id).size() + (kept.empty() ? 0 : 1);
            if (kept.size() >= max || bytes + add > id_budget) {
                open = false;
                return;
            }
            bytes += add;
            kept.push_back(idp);
        }
    };
    if (first)
        admit(true);
    admit(false);

    nlohmann::json out = to_array(kept);
    const auto digest = sha256_hex(dump(to_array(distinct)));
    out.push_back(nlohmann::json{{"truncated", true},
                                 {"total", distinct.size()},
                                 {"sha256", digest ? nlohmann::json(*digest) : nlohmann::json(nullptr)}});
    return dump(out);
}

std::optional<std::int64_t> stored_agent_ids_total(const std::string& agent_ids_json) {
    const auto parsed = nlohmann::json::parse(agent_ids_json, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_array())
        return std::nullopt;
    for (const auto& e : parsed) {
        if (!e.is_object())
            continue;
        const auto t = e.find("truncated");
        const auto n = e.find("total");
        if (t != e.end() && t->is_boolean() && t->get<bool>() && n != e.end() &&
            n->is_number_integer())
            return n->get<std::int64_t>();
    }
    return std::nullopt;
}

void add_agent_ids_bound(nlohmann::json& detail, const std::string& agent_ids_json,
                         bool confined) {
    const auto total = stored_agent_ids_total(agent_ids_json);
    if (!total)
        return;
    detail["agent_ids_truncated"] = true;
    if (!confined)
        detail["agent_ids_total"] = *total;
}

namespace {

nlohmann::json workflow_step_json(const WorkflowStep& s) {
    return nlohmann::json{
        {"index", s.index},
        {"instruction_id", s.instruction_id},
        {"condition", s.condition},
        {"retry_count", s.retry_count},
        {"retry_delay_seconds", s.retry_delay_seconds},
        {"foreach", s.foreach_source},
        {"label", s.label},
        {"on_failure", s.on_failure},
    };
}

} // namespace

nlohmann::json workflow_row_json(const Workflow& w) {
    nlohmann::json steps = nlohmann::json::array();
    for (const auto& s : w.steps)
        steps.push_back(workflow_step_json(s));
    return nlohmann::json{
        {"id", w.id},
        {"name", w.name},
        {"description", w.description},
        {"steps", steps},
        {"step_count", static_cast<int64_t>(w.steps.size())},
        {"created_at", w.created_at},
        {"updated_at", w.updated_at},
    };
}

nlohmann::json workflow_detail_json(const Workflow& w) {
    auto j = workflow_row_json(w);
    j["yaml_source"] = w.yaml_source;
    return j;
}

bool workflow_execution_visible(const WorkflowExecution& we, const authz::VisibleSet& scope) {
    if (!scope)
        return true;
    auto parsed = nlohmann::json::parse(we.agent_ids_json, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_array())
        return false; // malformed/absent agent_ids -- fail closed, never open.
    // Full scan, no early exit -- see header doc comment (mirrors
    // execution_scope_rules.hpp's execution_visible() anti-timing-oracle
    // rationale).
    bool visible = false;
    for (const auto& a : parsed) {
        if (!a.is_string())
            continue;
        visible = authz::in_scope(scope, a.get_ref<const std::string&>()) || visible;
    }
    return visible;
}

nlohmann::json confined_workflow_agent_ids_json(const std::string& agent_ids_json,
                                                const authz::VisibleSet& scope) {
    // agent_ids_json is a stored JSON-text column; parse permissively
    // (malformed/legacy rows must not fail the whole response).
    auto parsed_agent_ids = nlohmann::json::parse(agent_ids_json, nullptr, false);
    nlohmann::json agent_ids = nlohmann::json::array();
    if (!parsed_agent_ids.is_discarded() && parsed_agent_ids.is_array()) {
        for (const auto& a : parsed_agent_ids) {
            if (!a.is_string())
                continue;
            const auto& id = a.get_ref<const std::string&>();
            if (!authz::in_scope(scope, id))
                continue;
            agent_ids.push_back(id);
        }
    }
    return agent_ids;
}

namespace {

// The raw fleet-wide dispatch count for a step's FULL target-agent list
// (`workflow_routes.cpp`'s `dispatch_fn`: `{"agents_reached", sent}`) --
// never the confined caller's visible subset. Strip it for a confined
// caller rather than attempt an honest per-viewer recompute: nothing else
// in `result_json` carries a per-agent breakdown to recompute FROM (see
// `workflow_engine.cpp`'s step-dispatch loop), so omission is the only
// non-disclosing option, matching `last_error_detail.clear()`'s approach
// for the sibling `Execution` confined projection.
void strip_agents_reached(nlohmann::json& j) {
    if (j.is_object())
        j.erase("agents_reached");
}

} // namespace

nlohmann::json confined_workflow_step_result_json(const std::string& result_json, bool confined) {
    // #2437-class guard: check nesting on the RAW stored text BEFORE parse.
    // WorkflowEngine's own dispatch-result write path (workflow_engine.cpp)
    // guards against a poisoned result reaching this column, but that
    // write-side guard cannot heal a row already stored before it shipped,
    // or one written by direct DB manipulation - this read path stays
    // reachable against such a row, and every OTHER stored-data read path in
    // this fix (Guardian dashboard, result-set re-eval, inventory reads,
    // discovery catalogs) got the same treatment for the same reason.
    if (mcp::json_exceeds_depth(result_json, mcp::kMcpMaxJsonDepth))
        return nlohmann::json{{"error", "stored result exceeded maximum JSON nesting depth"}};
    auto result = nlohmann::json::parse(result_json, nullptr, false);
    if (result.is_discarded())
        return nullptr;
    if (confined) {
        if (result.is_array()) {
            for (auto& elem : result)
                strip_agents_reached(elem);
        } else {
            strip_agents_reached(result);
        }
    }
    return result;
}

nlohmann::json workflow_execution_detail_json(const WorkflowExecution& we,
                                              const authz::VisibleSet& scope) {
    nlohmann::json agent_ids = confined_workflow_agent_ids_json(we.agent_ids_json, scope);

    nlohmann::json steps = nlohmann::json::array();
    for (const auto& sr : we.step_results) {
        steps.push_back(nlohmann::json{
            {"step_index", sr.step_index},
            {"instruction_id", sr.instruction_id},
            {"status", sr.status},
            {"result", confined_workflow_step_result_json(sr.result_json,
                                                           static_cast<bool>(scope))},
            {"started_at", sr.started_at},
            {"completed_at", sr.completed_at},
            {"attempt", sr.attempt},
        });
    }

    nlohmann::json detail{
        {"id", we.id},
        {"workflow_id", we.workflow_id},
        {"status", we.status},
        {"agent_ids", agent_ids},
        {"current_step", we.current_step},
        {"started_at", we.started_at},
        {"completed_at", we.completed_at},
        {"steps", steps},
    };
    add_agent_ids_bound(detail, we.agent_ids_json, static_cast<bool>(scope));
    return detail;
}

} // namespace yuzu::server
