#include "network_api_local.hpp"

#include "agent_registry.hpp"
#include "dex_perf_rules.hpp" // kPerfTag*/parse_perf_* — the co-occurrence pressure inputs
#include "network_perf_rules.hpp"
#include "tag_store.hpp"

#include <cctype>
#include <chrono>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace yuzu::server {

/// Store-backed `NetworkApi` implementation — the F2a/network read model's
/// store-reaching assembly (previously `server.cpp`'s `net_perf_uncached`
/// lambda + `NetPerfMemo`), moved verbatim behind the seam so it is
/// independently testable (ADR-0031 WS-A4). Behaviour preserved exactly:
/// 90s staleness on net_snapshot, cohort STORE-FIRST precedence, C-S1
/// health-only devices, null-`tags_` degrade posture, and the 5s TTL / 8-entry
/// memo (heartbeat data changes on a ~30s cadence, so this bounds the
/// per-request fleet walk under hard operator polling and the REST surface).
class LocalNetworkApi final : public NetworkApi {
public:
    LocalNetworkApi(detail::AgentHealthStore& health, detail::AgentRegistry& registry,
                    TagStore* tags)
        : health_(health), registry_(registry), tags_(tags) {}

    LocalNetworkApi(const LocalNetworkApi&) = delete;
    LocalNetworkApi& operator=(const LocalNetworkApi&) = delete;

    [[nodiscard]] NetPerfFleetNow fleet_now(const std::string& cohort_key) const override {
        return net_perf_fleet_now(memoized_snapshot(cohort_key));
    }

    [[nodiscard]] std::vector<NetPerfDeviceRow>
    device_list(const NetDeviceQuery& q) const override {
        return net_perf_device_list(memoized_snapshot(q.cohort_key), q.metric, q.not_reporting,
                                    q.cooc, q.cohort_filter, q.limit);
    }

private:
    /// The store-reaching snapshot assembly — moved verbatim from
    /// server.cpp's `net_perf_uncached` lambda. Assembles a NetPerfSnapshot
    /// from the health store's network facts (net_snapshot — SAME 90s
    /// staleness as recompute_metrics, so callers and the yuzu_fleet_net_*
    /// gauges see the same population) joined with session OS + cohort tags.
    /// Mirrors dex_perf_uncached. app_unstable is wired with the
    /// per-connection collector slice (the co-occurrence "also app" band
    /// stays empty until net_degraded facts exist).
    [[nodiscard]] NetPerfSnapshot snapshot(const std::string& cohort_key) const {
        NetPerfSnapshot snap;
        snap.cohort_key = cohort_key;
        std::unordered_map<std::string, std::string> cohort_values;
        if (tags_) {
            // `available_keys` is the distinct-tag-KEY namespace — it does NOT
            // depend on the cohort key, so it is resolved UNCONDITIONALLY (even
            // for the key-less fleet endpoint, which calls fleet_now("")). This
            // deliberately DIFFERS from DEX, which withholds available_keys from
            // its pollable fleet endpoint and serves it only from a dedicated
            // /dex/perf/cohorts route: network has no /cohorts route, so the
            // public /api/v1/network/fleet + get_network_fleet surface it here,
            // and the 5s memo bounds get_distinct_keys() to <=1 read per window
            // (governance BLOCKING #4-agent finding, 2026-09-10 — it was gated on
            // !cohort_key.empty() and therefore always [] on the fleet surface).
            snap.available_keys = tags_->get_distinct_keys().value_or(std::vector<std::string>{});
            // cohort VALUES do depend on the chosen key — resolve only when given.
            if (!cohort_key.empty())
                cohort_values =
                    tags_->get_values_for_key(cohort_key)
                        .value_or(std::unordered_map<std::string, std::string>{});
        }
        const auto health = health_.net_snapshot(std::chrono::seconds{90});
        std::unordered_map<std::string, const detail::AgentHealthSnapshot*> by_id;
        by_id.reserve(health.size());
        for (const auto& h : health)
            by_id[h.agent_id] = &h;

        auto fill_facts = [](NetPerfDevice& d,
                             const std::unordered_map<std::string, std::string>& tags) {
            auto get = [&](const char* k) -> std::string {
                auto t = tags.find(k);
                return t != tags.end() ? t->second : std::string{};
            };
            d.rtt_ms = detail::parse_net_rtt_ms(get(detail::kNetTagRttP50Ms));
            d.retrans_pct = detail::parse_net_retrans_pct(get(detail::kNetTagRetransPct));
            d.throughput_bps = detail::parse_net_throughput_bps(get(detail::kNetTagThroughputBps));
            if (auto deg = detail::parse_net_degraded(get(detail::kNetTagDegraded)))
                d.net_degraded = *deg;
            d.cpu_pct = detail::parse_perf_cpu_pct(get(detail::kPerfTagCpuPct));
            d.commit_pct = detail::parse_perf_commit_pct(get(detail::kPerfTagCommitPct));
            d.disk_lat_ms = detail::parse_perf_disk_lat_ms(get(detail::kPerfTagDiskLatMs));
            d.app_unstable = false; // wired with the per-connection collector slice
        };

        std::unordered_set<std::string> seen;
        for (const auto& id : registry_.all_ids()) {
            auto s = registry_.get_session(id);
            if (!s)
                continue;
            NetPerfDevice d;
            d.agent_id = id;
            std::string os = s->os;
            for (auto& c : os)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            d.platform = os; // "windows" / "linux" / "darwin"
            if (auto it = by_id.find(id); it != by_id.end())
                fill_facts(d, it->second->status_tags);
            if (!cohort_key.empty()) {
                // STORE-FIRST precedence (operator-declared cohort wins over
                // a self-reported tag) — same posture as dex_perf_uncached.
                if (auto cv = cohort_values.find(id); cv != cohort_values.end())
                    d.cohort = cv->second;
                else if (auto it = s->scopable_tags.find(cohort_key);
                         it != s->scopable_tags.end() && TagStore::validate_value(it->second))
                    d.cohort = it->second;
            }
            snap.devices.push_back(std::move(d));
            seen.insert(id);
        }
        // C-S1: health-only devices (session reaped, heartbeat still fresh)
        // must also appear so callers and the gauges agree.
        for (const auto& h : health) {
            if (seen.contains(h.agent_id))
                continue;
            NetPerfDevice d;
            d.agent_id = h.agent_id;
            fill_facts(d, h.status_tags);
            if (!cohort_key.empty())
                if (auto cv = cohort_values.find(h.agent_id); cv != cohort_values.end())
                    d.cohort = cv->second;
            snap.devices.push_back(std::move(d));
        }
        return snap;
    }

    /// 5s TTL memo keyed by cohort key (mirrors the dex_perf_fn memo) —
    /// heartbeat data changes on a ~30s cadence, so this bounds the
    /// per-request fleet walk (all_ids + per-id get_session + net_snapshot
    /// copy-under-mutex) under hard operator polling and the REST surface.
    [[nodiscard]] NetPerfSnapshot memoized_snapshot(const std::string& cohort_key) const {
        constexpr auto kTtl = std::chrono::seconds{5};
        constexpr std::size_t kMaxMemoEntries = 8;
        const auto now = std::chrono::steady_clock::now();
        {
            std::lock_guard lk(memo_mu_);
            if (auto it = memo_.find(cohort_key); it != memo_.end() && now - it->second.at < kTtl)
                return it->second.snap;
        }
        auto snap = snapshot(cohort_key);
        {
            std::lock_guard lk(memo_mu_);
            if (memo_.size() >= kMaxMemoEntries && !memo_.contains(cohort_key)) {
                auto oldest = memo_.begin();
                for (auto it = memo_.begin(); it != memo_.end(); ++it)
                    if (it->second.at < oldest->second.at)
                        oldest = it;
                memo_.erase(oldest);
            }
            memo_[cohort_key] = {now, snap};
        }
        return snap;
    }

    struct MemoEntry {
        std::chrono::steady_clock::time_point at;
        NetPerfSnapshot snap;
    };

    detail::AgentHealthStore& health_;
    detail::AgentRegistry& registry_;
    TagStore* tags_; ///< nullable — degrades to no cohort resolution / empty available_keys

    mutable std::mutex memo_mu_;
    mutable std::unordered_map<std::string, MemoEntry> memo_;
};

std::shared_ptr<NetworkApi> make_local_network_api(detail::AgentHealthStore& health,
                                                   detail::AgentRegistry& registry,
                                                   TagStore* tags) {
    return std::make_shared<LocalNetworkApi>(health, registry, tags);
}

} // namespace yuzu::server
