#include "preflight_eval.hpp"

#include "preflight_run_store.hpp"
#include "response_store.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace yuzu::server::preflight {

namespace {
// Per-check fetch cap. MUST exceed the run's cohort cap (PreflightRunStore
// kRowCap=20000) with headroom for the multiple rows/agent that re-dispatch
// accrues — `query_by_execution` is `ORDER BY ts DESC LIMIT`, a sliding window,
// so an undersized cap evicts already-answered agents' terminal rows and the run
// can never complete (#governance perf-S2/architect). 50000 covers realistic
// re-dispatch depth at the 20k cohort ceiling; the true fix (per-agent keyset
// paging so size is independent of row count) is a tracked follow-up — a
// truncation hit is logged below as the signal that we've reached it.
constexpr int kResponseFetchCap = 50000;

int score_response(const StoredResponse& r) {
    int s = 0;
    if (r.status != 0) // 0 = RUNNING; terminal beats running
        s += 2;
    if (!r.output.empty())
        s += 1;
    return s;
}
} // namespace

std::string check_execution_id(const std::string& run_id, std::string_view check_key) {
    return "preflight-" + run_id + "-" + std::string(check_key);
}

bool check_applicable(std::string_view key, const PreflightConfig& cfg) {
    if (key == "app")
        return !cfg.app_name.empty();
    return true;
}

std::vector<std::pair<std::string, std::string>> applicable_checks(const PreflightConfig& cfg) {
    std::vector<std::pair<std::string, std::string>> out;
    for (const auto& c : kPreflightChecks)
        if (check_applicable(c.key, cfg))
            out.emplace_back(c.key, c.label);
    return out;
}

std::unordered_map<std::string, std::string> dispatch_params(std::string_view key,
                                                             const PreflightConfig& cfg) {
    if (key == "app")
        return {{"name", cfg.app_name}};
    if (key == "disk" && !cfg.volume.empty())
        return {{"path", cfg.volume}};
    return {};
}

std::vector<PreflightCheckResponses>
collect_check_responses(ResponseStore& store, const std::string& run_id,
                        const std::vector<std::pair<std::string, std::string>>& applicable) {
    std::vector<PreflightCheckResponses> out;
    out.reserve(applicable.size());
    ResponseQuery q;
    q.limit = kResponseFetchCap;
    for (const auto& [key, label] : applicable) {
        PreflightCheckResponses cr;
        cr.key = key;
        cr.label = label;
        // #2691 finding 10: this DOES feed a gate — the persisted grid drives
        // Deploy's go-cohort (deployment_routes.cpp filters to kPass/kWarnOnly)
        // — so a degraded read must stay distinguishable from a genuinely
        // empty one. `cr.degraded` lets every grid-persisting caller decline
        // to persist this tick's (falsely-empty) result over an already-good
        // stored verdict, rather than silently downgrading it to Incomplete.
        auto rows_opt = store.query_by_execution(check_execution_id(run_id, key), q);
        cr.degraded = !rows_opt.has_value();
        auto rows = rows_opt.value_or(std::vector<StoredResponse>{});
        if (static_cast<int>(rows.size()) >= kResponseFetchCap)
            spdlog::warn("preflight: check '{}' response fetch hit the {}-row cap for run {} — "
                         "some agents' latest may be evicted (keyset-paging follow-up)",
                         key, kResponseFetchCap, run_id);
        // latest_per_agent: terminal beats running, then non-empty output, then
        // the later arrival (mirrors policy_evaluator.cpp).
        std::unordered_map<std::string, const StoredResponse*> best;
        for (const auto& r : rows) {
            auto it = best.find(r.agent_id);
            if (it == best.end()) {
                best.emplace(r.agent_id, &r);
                continue;
            }
            const StoredResponse& cur = *it->second;
            const int sr = score_response(r), sc = score_response(cur);
            if (sr > sc || (sr == sc && r.received_at_ms > cur.received_at_ms))
                it->second = &r;
        }
        for (const auto& [agent, rp] : best)
            cr.by_agent[agent] = {rp->status, rp->output};
        out.push_back(std::move(cr));
    }
    return out;
}

bool any_check_degraded(const std::vector<PreflightCheckResponses>& checks) {
    for (const auto& c : checks)
        if (c.degraded)
            return true;
    return false;
}

std::string checks_to_json(const std::vector<PreflightDeviceCheck>& checks) {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& c : checks)
        arr.push_back({{"key", c.key},
                       {"label", c.label},
                       {"v", static_cast<int>(c.verdict)},
                       {"val", c.value}});
    // Agent-derived values may carry odd bytes → replace, never throw.
    return arr.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

std::vector<PreflightDeviceCheck> checks_from_json(const std::string& json) {
    std::vector<PreflightDeviceCheck> out;
    auto j = nlohmann::json::parse(json, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_array())
        return out;
    for (const auto& e : j) {
        if (!e.is_object())
            continue;
        // .value() throws type_error on a wrong-typed key even with
        // allow_exceptions=false on parse — guard so a corrupt stored row drops
        // the bad element instead of 500-ing the render (#governance cpp-expert).
        try {
            PreflightDeviceCheck c;
            c.key = e.value("key", std::string{});
            c.label = e.value("label", std::string{});
            int v = e.value("v", static_cast<int>(Verdict::kUnknown));
            if (v < 0 || v > static_cast<int>(Verdict::kUnknown))
                v = static_cast<int>(Verdict::kUnknown);
            c.verdict = static_cast<Verdict>(v);
            c.value = e.value("val", std::string{});
            out.push_back(std::move(c));
        } catch (const nlohmann::json::exception&) {
            // skip malformed element
        }
    }
    return out;
}

std::string config_to_json(const PreflightConfig& cfg) {
    nlohmann::json j = {{"app_name", cfg.app_name},
                        {"app_min", cfg.app_min_version},
                        {"app_max", cfg.app_max_version},
                        {"os_min", cfg.os_min_version},
                        {"arch", cfg.req_arch},
                        {"min_gib", cfg.min_free_gib},
                        {"volume", cfg.volume},
                        {"reboot_block", cfg.reboot_block}};
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

bool persist_and_maybe_complete(PreflightRunStore& store, const std::string& run_id,
                                const std::vector<PreflightDeviceResult>& grid,
                                std::int64_t now_ms, bool past_deadline, bool any_pending) {
    int go = 0, warn = 0, nogo = 0, inc = 0;
    std::vector<PreflightRunDeviceRow> rows;
    rows.reserve(grid.size());
    for (const auto& dr : grid) {
        PreflightRunDeviceRow row;
        row.agent_id = dr.agent_id;
        row.hostname = dr.hostname;
        row.os = dr.os;
        row.bucket = bucket_token(dr.bucket);
        row.checks_json = checks_to_json(dr.checks);
        row.updated_at_ms = now_ms;
        rows.push_back(std::move(row));
        switch (dr.bucket) {
        case Bucket::kPass:
            ++go;
            break;
        case Bucket::kFailed:
            ++nogo;
            break;
        case Bucket::kWarnOnly:
            ++warn;
            break;
        default:
            ++inc;
            break;
        }
    }
    // compute → persist → THEN complete, so a viewer arriving right after completion
    // reads the final grid, not a one-tick-stale one. Complete ONLY once the grid is
    // durably persisted (#governance UP-1/CH-1): completing on a failed persist would
    // freeze the run 'complete' with the seed grid; the next call retries instead.
    const bool persisted =
        store.persist_grid(run_id, rows, static_cast<int>(grid.size()), go, warn, nogo, inc);
    if (persisted && (past_deadline || !any_pending))
        return store.complete_run(run_id, now_ms);
    return false;
}

PreflightConfig config_from_json(const std::string& json) {
    PreflightConfig c;
    auto j = nlohmann::json::parse(json, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object())
        return c;
    // Guard .value() type_error on a wrong-typed key (see checks_from_json).
    try {
        c.app_name = j.value("app_name", std::string{});
        c.app_min_version = j.value("app_min", std::string{});
        c.app_max_version = j.value("app_max", std::string{});
        c.os_min_version = j.value("os_min", std::string{});
        c.req_arch = j.value("arch", std::string{});
        c.min_free_gib = j.value("min_gib", static_cast<std::int64_t>(0));
        c.volume = j.value("volume", std::string{});
        c.reboot_block = j.value("reboot_block", true);
    } catch (const nlohmann::json::exception&) {
        return PreflightConfig{}; // degrade to defaults on a corrupt row
    }
    return c;
}

} // namespace yuzu::server::preflight
