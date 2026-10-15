#include "bundle_service.hpp"

#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard

#include <nlohmann/json.hpp>

#include <string>
#include <unordered_map>
#include <utility>

namespace yuzu::server {

namespace {

std::string to_lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

// Identifier rule for an already-lower-cased plugin/action: non-empty, <= 64
// bytes, [a-z0-9_]. Written out by hand (not std::isalnum) — locale-independent
// and safe on high-bit char values. These identifiers are used to build per-step
// audit verbs (bundle.<plugin>.<action>), so the charset is also the injection
// guard.
constexpr std::size_t kMaxIdentLen = 64;
bool is_ident(std::string_view s) {
    if (s.empty() || s.size() > kMaxIdentLen)
        return false;
    for (char c : s) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        if (!ok)
            return false;
    }
    return true;
}

const char* state_token(BundleStepState st) {
    switch (st) {
    case BundleStepState::Responded:
        return "responded";
    case BundleStepState::DispatchFailed:
        return "dispatch_failed";
    case BundleStepState::Pending:
        break;
    }
    return "pending";
}

} // namespace

std::expected<std::vector<BundleStepSpec>, std::string>
validate_bundle_steps(std::string_view steps_json, std::size_t max_steps) {
    // #2437-class guard: raw-text depth check before this function's own
    // parse. The REST /api/v1/bundles caller already checks the whole
    // request body before this is reached, but this function has no
    // httplib::Request/Response of its own and is a free function any
    // OTHER caller can reach directly - the check belongs here too, so a
    // future caller that skips the REST-level guard cannot reintroduce the
    // unbounded-recursion-on-dump() crash this branch's own `v.dump()`
    // (below, per-param-value coercion) would otherwise be exposed to.
    if (mcp::json_exceeds_depth(steps_json, mcp::kMcpMaxJsonDepth))
        return std::unexpected("steps nests too deeply");
    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(steps_json.begin(), steps_json.end());
    } catch (const nlohmann::json::exception& e) {
        return std::unexpected(std::string("invalid JSON: ") + e.what());
    }

    if (!doc.is_array())
        return std::unexpected("steps must be a JSON array");
    if (doc.empty())
        return std::unexpected("steps array is empty");
    if (doc.size() > max_steps)
        return std::unexpected("too many steps (max " + std::to_string(max_steps) + ")");

    std::vector<BundleStepSpec> specs;
    specs.reserve(doc.size());

    std::size_t idx = 0;
    for (const auto& elem : doc) {
        const std::string where = "step " + std::to_string(idx++);
        if (!elem.is_object())
            return std::unexpected(where + ": must be an object");
        if (!elem.contains("plugin") || !elem["plugin"].is_string())
            return std::unexpected(where + ": missing string 'plugin'");
        if (!elem.contains("action") || !elem["action"].is_string())
            return std::unexpected(where + ": missing string 'action'");

        BundleStepSpec s;
        s.plugin = to_lower(elem["plugin"].get<std::string>());
        s.action = to_lower(elem["action"].get<std::string>());
        if (!is_ident(s.plugin))
            return std::unexpected(where + ": invalid plugin name");
        if (!is_ident(s.action))
            return std::unexpected(where + ": invalid action name");
        // Duplicate (plugin, action) steps are DELIBERATELY allowed (ADR-0011
        // §61-64): each step gets its own command_id, the persisted ordered step
        // map demuxes by command_id in request order, so e.g. two registry reads
        // with different params on one device are unambiguous. No uniqueness set.

        if (elem.contains("params")) {
            const auto& p = elem["params"];
            if (!p.is_object())
                return std::unexpected(where + ": 'params' must be an object");
            if (p.size() > kMaxParamCountPerStep)
                return std::unexpected(where + ": too many params (max " +
                                       std::to_string(kMaxParamCountPerStep) + ")");
            s.params.reserve(p.size());
            for (const auto& [k, v] : p.items()) {
                // Coerce to string: strings pass through, other JSON types are
                // dumped to their textual form (matches execute_instruction).
                std::string val = v.is_string() ? v.get<std::string>() : v.dump();
                // Bound the per-step payload — a bundle fans this out ×N (UP-7).
                if (k.size() > kMaxParamKeyLen)
                    return std::unexpected(where + ": param key too long (max " +
                                           std::to_string(kMaxParamKeyLen) + " bytes)");
                if (val.size() > kMaxParamValueLen)
                    return std::unexpected(where + ": param '" + k + "' value too large (max " +
                                           std::to_string(kMaxParamValueLen) + " bytes)");
                s.params.emplace_back(k, std::move(val));
            }
        }

        specs.push_back(std::move(s));
    }

    return specs;
}

BundleAggregate aggregate_bundle(const std::vector<DispatchedStep>& steps,
                                 const std::vector<BundleResponseRow>& rows) {
    // Index rows by command_id, preferring the TERMINAL frame. A command can
    // emit a RUNNING data frame (status == kRunningStatus) and then a terminal
    // SUCCESS/FAILURE frame; we want the terminal. We pick status-aware rather
    // than order-aware because BundleResponseRow carries no timestamp — relying
    // on the store's ORDER BY (and on equal-timestamp tie-breaks) is unsound, so
    // a terminal frame always wins over a RUNNING one regardless of row order
    // (governance cppx-S1 / CH-5).
    constexpr int kRunningStatus = 0; // CommandResponse::Status: 0=RUNNING, 1=SUCCESS, 2=FAILURE
    std::unordered_map<std::string, const BundleResponseRow*> by_cmd;
    by_cmd.reserve(rows.size());
    for (const auto& r : rows) {
        auto [it, inserted] = by_cmd.try_emplace(r.command_id, &r);
        if (!inserted && it->second->status == kRunningStatus && r.status != kRunningStatus)
            it->second = &r; // prefer a terminal frame over a held RUNNING one
    }

    BundleAggregate agg;
    agg.expected = steps.size();
    agg.steps.reserve(steps.size());

    for (const auto& step : steps) {
        BundleStepResult res;
        res.plugin = step.plugin;
        res.action = step.action;

        if (step.command_id.empty()) {
            res.state = BundleStepState::DispatchFailed;
        } else if (auto it = by_cmd.find(step.command_id); it != by_cmd.end()) {
            res.state = BundleStepState::Responded;
            res.status = it->second->status;
            res.output = it->second->output;
            ++agg.received;
            if (res.status == 1) // SUCCESS — distinct from a responded FAILURE
                ++agg.succeeded;
        } else {
            res.state = BundleStepState::Pending;
        }
        agg.steps.push_back(std::move(res));
    }

    // Complete once nothing is still pending (responded or dispatch-failed). A
    // dispatch-failed step is terminal — it will never produce a response — so it
    // must not hold the bundle "incomplete" forever.
    agg.complete = true;
    for (const auto& s : agg.steps) {
        if (s.state == BundleStepState::Pending) {
            agg.complete = false;
            break;
        }
    }
    return agg;
}

std::string aggregate_to_json(const BundleAggregate& agg) {
    nlohmann::json j;
    j["complete"] = agg.complete;
    j["received"] = agg.received;
    j["succeeded"] = agg.succeeded;
    j["expected"] = agg.expected;
    auto steps = nlohmann::json::array();
    for (const auto& s : agg.steps) {
        steps.push_back({
            {"plugin", s.plugin},
            {"action", s.action},
            {"state", state_token(s.state)},
            {"status", s.status},
            {"output", s.output},
        });
    }
    j["steps"] = std::move(steps);
    // Plugin output is UNTRUSTED and may not be valid UTF-8 (binary, a non-UTF-8
    // Windows codepage, a truncated multibyte sequence). nlohmann's default
    // (strict) dump() THROWS type_error.316 on an invalid byte — which on the MCP
    // path escapes the JSON-RPC envelope and leaves the bundle permanently
    // uncollatable until TTL. This is exactly the non-UTF-8 `.dump()` crash class
    // ADR-0011 retired; the `replace` handler substitutes U+FFFD so collate
    // always serializes (governance review #1593: blocker 1).
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

} // namespace yuzu::server
