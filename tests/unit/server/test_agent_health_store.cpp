/**
 * test_agent_health_store.cpp — Unit tests for AgentHealthStore fleet health aggregation
 *
 * TWO KINDS OF TEST LIVE HERE, AND THE DIFFERENCE MATTERS.
 *
 * 1. `TestAgentHealthStore` (below) is a standalone REPRODUCTION. The real store's upsert()
 *    takes a `google::protobuf::Map`, so the reproduction exists to exercise the
 *    MetricsRegistry output contract without dragging protobuf into every case. It reuses the
 *    SHIPPED helpers (network_perf_rules.hpp, spark_fleet_tags.hpp) rather than re-deriving
 *    their logic, so helper drift IS caught.
 *
 *    But a reproduction can only ever catch MODEL drift, never a COVERAGE gap: delete the
 *    spark rollup from agent_registry.cpp and every mirror-based case here still passes. A
 *    previous version of this file carried a comment asserting the opposite — that the
 *    four-posture bucketing was covered because the mirror had been taught the four postures.
 *    It was not. Overclaiming coverage in a comment is how this branch shipped bugs through
 *    five review rounds; do not do it again.
 *
 * 2. The `[spark][rollup][real]` case at the bottom drives the REAL
 *    `yuzu::server::detail::AgentHealthStore::recompute_metrics` through a real
 *    `protobuf::Map` upsert. That is the only case in this file that would fail if the
 *    shipped rollup were deleted — and it has been verified to do so.
 *    (governance Gate-8 round 7 consistency S-1.)
 *
 * The real store lives in `server/core/src/agent_registry.hpp` (namespace
 * yuzu::server::detail) — NOT inside server.cpp, as this header used to claim.
 */

#include "agent_registry.hpp"     // the REAL AgentHealthStore (detail namespace)
#include "guardian_health_fleet_tags.hpp" // #5403: the SHIPPED age-table row (no parallel repro)
#include "network_perf_rules.hpp" // SHIPPED net-fact validators (no parallel repro)
#include "spark_fleet_tags.hpp"   // SHIPPED spark helpers (no parallel repro)
#include "tar_corruption_audit.hpp" // #1567 SHIPPED audit gate + tag keys

#include <yuzu/metrics.hpp>

#include <google/protobuf/map.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <functional>
#include <iterator>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <format>
#include <vector>

// ── Standalone reproduction of AgentHealthStore ─────────────────────────────

class TestAgentHealthStore {
public:
    void upsert(const std::string& agent_id,
                const std::unordered_map<std::string, std::string>& tags) {
        std::lock_guard lock(mu_);
        auto& snap = snapshots_[agent_id];
        snap.agent_id = agent_id;
        snap.status_tags = tags;
        snap.last_seen = std::chrono::steady_clock::now();
    }

    void remove(const std::string& agent_id) {
        std::lock_guard lock(mu_);
        snapshots_.erase(agent_id);
    }

    void recompute_metrics(yuzu::MetricsRegistry& metrics, std::chrono::seconds staleness) {
        std::lock_guard lock(mu_);
        auto now = std::chrono::steady_clock::now();

        std::erase_if(snapshots_,
                      [&](const auto& pair) { return (now - pair.second.last_seen) > staleness; });

        metrics.clear_gauge_family("yuzu_fleet_agents_by_os");
        metrics.clear_gauge_family("yuzu_fleet_agents_by_arch");
        metrics.clear_gauge_family("yuzu_fleet_agents_by_version");
        metrics.clear_gauge_family("yuzu_fleet_perf_cpu_pct");
        metrics.clear_gauge_family("yuzu_fleet_perf_commit_pct");
        metrics.clear_gauge_family("yuzu_fleet_perf_disk_lat_ms");
        metrics.clear_gauge_family("yuzu_fleet_net_rtt_ms");
        metrics.clear_gauge_family("yuzu_fleet_net_retrans_pct");
        metrics.clear_gauge_family("yuzu_fleet_net_throughput_bps");
        metrics.clear_gauge_family("yuzu_fleet_net_degraded");
        metrics.clear_gauge_family("yuzu_fleet_net_reporting");
        metrics.clear_gauge_family("yuzu_fleet_net_retrans_reporting");

        std::unordered_map<std::string, int> os_counts, arch_counts, version_counts;
        double total_commands = 0.0;
        int healthy_count = 0;
        int dex_observer_disarmed = 0;
        double total_dex_observed = 0.0;
        std::vector<double> perf_cpu, perf_commit, perf_disk_lat;
        // Per-OS net buckets (mirrors AgentRegistry::recompute_metrics — no blend).
        std::unordered_map<std::string, std::vector<double>> net_rtt_os, net_retrans_os,
            net_tput_os;
        std::unordered_map<std::string, int> net_reporting_os, net_degraded_os,
            net_degraded_reporting_os;
        // Mirrors the production retransmit gauge-eligibility gate (Windows rate is
        // unvalidated — #1465 — so withheld from the gauge; Linux is validated).
        auto retrans_gauge_eligible = [](const std::string& os) { return os == "linux"; };
        // Mirrors the production os-label allowlist (agent-controlled yuzu.os →
        // bounded label, anti cardinality-injection).
        auto normalize_os = [](const std::string& os) -> std::string {
            if (os == "windows" || os == "linux" || os == "darwin")
                return os;
            return os.empty() ? "unknown" : "other";
        };

        for (const auto& [id, snap] : snapshots_) {
            ++healthy_count;

            auto get = [&](const std::string& key) -> std::string {
                auto it = snap.status_tags.find(key);
                return it != snap.status_tags.end() ? it->second : "";
            };

            auto os_val = get("yuzu.os");
            if (!os_val.empty())
                os_counts[normalize_os(os_val)]++;

            auto arch_val = get("yuzu.arch");
            if (!arch_val.empty())
                arch_counts[arch_val]++;

            auto ver_val = get("yuzu.agent_version");
            if (!ver_val.empty())
                version_counts[ver_val]++;

            // Mirrors AgentRegistry::recompute_metrics: std::stod does NOT throw on
            // "inf"/"nan", so guard finite + non-negative or one rogue agent poisons the
            // fleet gauge.
            auto add_finite_count = [](double& acc, const std::string& s) {
                try {
                    double v = std::stod(s);
                    if (std::isfinite(v) && v >= 0.0)
                        acc += v;
                } catch (...) {}
            };

            auto cmd_val = get("yuzu.commands_executed");
            if (!cmd_val.empty())
                add_finite_count(total_commands, cmd_val);

            if (get("yuzu.dex_observer_armed") == "0")
                ++dex_observer_disarmed;

            auto dex_val = get("yuzu.dex_observed");
            if (!dex_val.empty())
                add_finite_count(total_dex_observed, dex_val);

            // A4 perf tags — finite, non-negative; percentages clamp at 100,
            // latency rejects above the sanity ceiling (absurd-but-finite).
            auto collect_finite = [&](std::vector<double>& out, const std::string& key,
                                      double clamp_hi, double reject_above) {
                const auto s = get(key);
                if (s.empty())
                    return;
                try {
                    double v = std::stod(s);
                    if (std::isfinite(v) && v >= 0.0 && v <= reject_above)
                        out.push_back(clamp_hi > 0.0 ? (std::min)(v, clamp_hi) : v);
                } catch (...) {}
            };
            collect_finite(perf_cpu, "yuzu.perf_cpu_pct", 100.0, 1.0e6);
            collect_finite(perf_commit, "yuzu.perf_commit_pct", 100.0, 1.0e6);
            collect_finite(perf_disk_lat, "yuzu.perf_disk_lat_ms", 0.0, 1.0e6);

            // Use the SHIPPED validators (network_perf_rules.hpp) — not a
            // hand-rolled parallel copy — so this repro can't drift from
            // production's forged-value posture (full-token parse, locale
            // hardening, ceilings/clamps). Mirrors agent_registry.cpp incl. the
            // UP-9 gate (degraded counted only for metric-reporting devices).
            namespace rules = yuzu::server::detail;
            const std::string net_os = normalize_os(os_val);
            bool net_any = false;
            if (auto v = rules::parse_net_rtt_ms(get(rules::kNetTagRttP50Ms))) {
                net_rtt_os[net_os].push_back(*v);
                net_any = true;
            }
            if (auto v = rules::parse_net_retrans_pct(get(rules::kNetTagRetransPct))) {
                if (retrans_gauge_eligible(net_os))
                    net_retrans_os[net_os].push_back(*v);
                net_any = true;
            }
            if (auto v = rules::parse_net_throughput_bps(get(rules::kNetTagThroughputBps))) {
                net_tput_os[net_os].push_back(*v);
                net_any = true;
            }
            if (net_any) {
                ++net_reporting_os[net_os];
                if (auto d = rules::parse_net_degraded(get(rules::kNetTagDegraded))) {
                    ++net_degraded_reporting_os[net_os];
                    if (*d)
                        ++net_degraded_os[net_os];
                }
            }
        }

        metrics.gauge("yuzu_fleet_agents_healthy").set(static_cast<double>(healthy_count));
        metrics.gauge("yuzu_fleet_agents_dex_observer_disarmed")
            .set(static_cast<double>(dex_observer_disarmed));
        metrics.gauge("yuzu_fleet_dex_observed_total").set(total_dex_observed);

        for (const auto& [os, count] : os_counts)
            metrics.gauge("yuzu_fleet_agents_by_os", {{"os", os}}).set(static_cast<double>(count));

        for (const auto& [arch, count] : arch_counts)
            metrics.gauge("yuzu_fleet_agents_by_arch", {{"arch", arch}})
                .set(static_cast<double>(count));

        for (const auto& [ver, count] : version_counts)
            metrics.gauge("yuzu_fleet_agents_by_version", {{"version", ver}})
                .set(static_cast<double>(count));

        metrics.gauge("yuzu_fleet_commands_executed_total").set(total_commands);

        // A4 fleet perf rollup — mirrors AgentHealthStore::recompute_metrics.
        auto set_stats = [&](const char* family, std::vector<double>& vals) {
            if (vals.empty())
                return;
            std::sort(vals.begin(), vals.end());
            const auto n = vals.size();
            double sum = 0.0;
            for (double v : vals)
                sum += v;
            auto rank = [&](double p) {
                const auto idx =
                    static_cast<std::size_t>(std::ceil(p * static_cast<double>(n)));
                return vals[(std::min)(idx == 0 ? 0 : idx - 1, n - 1)];
            };
            metrics.gauge(family, {{"stat", "avg"}}).set(sum / static_cast<double>(n));
            metrics.gauge(family, {{"stat", "p50"}}).set(rank(0.50));
            metrics.gauge(family, {{"stat", "p90"}}).set(rank(0.90));
            metrics.gauge(family, {{"stat", "max"}}).set(vals.back());
        };
        metrics.gauge("yuzu_fleet_perf_reporting").set(static_cast<double>(perf_cpu.size()));
        set_stats("yuzu_fleet_perf_cpu_pct", perf_cpu);
        set_stats("yuzu_fleet_perf_commit_pct", perf_commit);
        set_stats("yuzu_fleet_perf_disk_lat_ms", perf_disk_lat);

        auto set_stats_os = [&](const char* family, const std::string& os,
                                std::vector<double>& vals) {
            if (vals.empty())
                return;
            std::sort(vals.begin(), vals.end());
            const auto n = vals.size();
            double sum = 0.0;
            for (double v : vals)
                sum += v;
            auto rank = [&](double p) {
                const auto idx = static_cast<std::size_t>(std::ceil(p * static_cast<double>(n)));
                return vals[(std::min)(idx == 0 ? 0 : idx - 1, n - 1)];
            };
            metrics.gauge(family, {{"stat", "avg"}, {"os", os}}).set(sum / static_cast<double>(n));
            metrics.gauge(family, {{"stat", "p50"}, {"os", os}}).set(rank(0.50));
            metrics.gauge(family, {{"stat", "p90"}, {"os", os}}).set(rank(0.90));
            metrics.gauge(family, {{"stat", "max"}, {"os", os}}).set(vals.back());
        };
        for (auto& [os, n] : net_reporting_os)
            metrics.gauge("yuzu_fleet_net_reporting", {{"os", os}}).set(static_cast<double>(n));
        for (auto& [os, vals] : net_retrans_os)
            metrics.gauge("yuzu_fleet_net_retrans_reporting", {{"os", os}})
                .set(static_cast<double>(vals.size()));
        for (auto& [os, n] : net_degraded_reporting_os)
            if (n > 0)
                metrics.gauge("yuzu_fleet_net_degraded", {{"os", os}})
                    .set(static_cast<double>(net_degraded_os[os]));
        for (auto& [os, vals] : net_rtt_os)
            set_stats_os("yuzu_fleet_net_rtt_ms", os, vals);
        for (auto& [os, vals] : net_retrans_os)
            set_stats_os("yuzu_fleet_net_retrans_pct", os, vals);
        for (auto& [os, vals] : net_tput_os)
            set_stats_os("yuzu_fleet_net_throughput_bps", os, vals);
    }

    // Spark rollup MIRROR (gov qe-S1) — the same bucketing + gauge glue as
    // AgentRegistry::recompute_metrics, reusing the SHIPPED spark_fleet_tags.hpp
    // helpers (no parallel repro of the parse logic, per the net precedent above).
    //
    // It mirrors the FOUR-POSTURE split (running / disabled / failed / absent), so MODEL
    // drift between the mirror and the shipped helpers is caught.
    //
    // WHAT IT CANNOT CATCH: a coverage gap. This is a reproduction — deleting the spark
    // rollup from agent_registry.cpp leaves every case that uses it green. The
    // "[spark][rollup][real]" case at the bottom of this file is the one that pins the
    // SHIPPED code. See the file header. (governance Gate-8 round 7 consistency S-1.)
    void recompute_spark(yuzu::MetricsRegistry& metrics) {
        namespace sd = yuzu::server::detail;
        std::lock_guard lock(mu_);
        for (const char* f : {"yuzu_fleet_spark_reporting", "yuzu_fleet_spark_disabled",
                              "yuzu_fleet_spark_failed", "yuzu_fleet_spark_mechanisms",
                              "yuzu_fleet_spark_watch_rejected"})
            metrics.clear_gauge_family(f);
        auto norm_os = [](const std::string& os) -> std::string {
            if (os == "windows" || os == "linux" || os == "darwin")
                return os;
            return os.empty() ? "unknown" : "other";
        };
        std::unordered_map<std::string, int> reporting;
        std::unordered_map<std::string, std::unordered_map<std::string, int>> mechs;
        std::unordered_map<std::string, std::unordered_map<std::string, double>> rejected;
        std::unordered_map<std::string, int> disabled;
        std::unordered_map<std::string, int> failed;
        for (auto& [id, snap] : snapshots_) {
            auto get = [&](const std::string& k) -> std::string {
                auto it = snap.status_tags.find(k);
                return it != snap.status_tags.end() ? it->second : "";
            };
            const std::string os = norm_os(get("yuzu.os"));
            // STRICT: only "1"/"0" mean anything. Garbage is NotReported and contributes
            // to nothing — it must NOT fall into `failed`, the gauge operators alert on.
            const sd::SparkRunState state = sd::parse_spark_running(get(sd::kSparkTagRunning));
            if (state == sd::SparkRunState::NotRunning) {
                // The DISABLED vs FAILED split — a deliberate opt-out must never be
                // confused with an engine that threw at boot. STRICT (Gate-4 UP-3): a
                // non-conforming discriminator is Unknown → neither bucket, mirroring the
                // shipped store so this model does not drift.
                switch (sd::parse_spark_disabled(get(sd::kSparkTagDisabled))) {
                case sd::SparkDisabledState::Disabled:
                    ++disabled[os];
                    break;
                case sd::SparkDisabledState::NotDisabled:
                    ++failed[os];
                    break;
                case sd::SparkDisabledState::Unknown:
                    break;
                }
                continue;
            }
            if (state != sd::SparkRunState::Running)
                continue; // ABSENT / unparseable — contributes to nothing at all
            ++reporting[os];
            for (const auto& tok : sd::spark_mechs_from_csv(get(sd::kSparkTagMechs)))
                ++mechs[os][tok];
            for (const char* m : sd::kSparkMechTokens)
                if (auto v = sd::parse_spark_count(
                        get(sd::spark_type_metric_tag(m, sd::kSparkMetricWatchRejected))))
                    rejected[os][m] += *v;
        }
        for (auto& [os, n] : reporting)
            metrics.gauge("yuzu_fleet_spark_reporting", {{"os", os}}).set(n);
        for (auto& [os, n] : disabled)
            metrics.gauge("yuzu_fleet_spark_disabled", {{"os", os}}).set(n);
        for (auto& [os, n] : failed)
            metrics.gauge("yuzu_fleet_spark_failed", {{"os", os}}).set(n);
        for (auto& [os, mm] : mechs)
            for (auto& [mech, n] : mm)
                metrics.gauge("yuzu_fleet_spark_mechanisms", {{"os", os}, {"mechanism", mech}})
                    .set(n);
        for (auto& [os, mm] : rejected)
            for (auto& [mech, v] : mm)
                metrics.gauge("yuzu_fleet_spark_watch_rejected", {{"os", os}, {"mechanism", mech}})
                    .set(v);
    }

private:
    struct Snapshot {
        std::string agent_id;
        std::unordered_map<std::string, std::string> status_tags;
        std::chrono::steady_clock::time_point last_seen;
    };

    std::mutex mu_;
    std::unordered_map<std::string, Snapshot> snapshots_;
};

// ── Tests ───────────────────────────────────────────────────────────────────

TEST_CASE("AgentHealthStore: upsert stores health data", "[health_store]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("agent-1", {{"yuzu.os", "linux"}, {"yuzu.arch", "x86_64"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    REQUIRE(metrics.gauge("yuzu_fleet_agents_healthy").value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_agents_by_os", {{"os", "linux"}}).value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_agents_by_arch", {{"arch", "x86_64"}}).value() == 1.0);
}

TEST_CASE("AgentHealthStore: multiple agents aggregate correctly", "[health_store]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("agent-1", {{"yuzu.os", "linux"}, {"yuzu.arch", "x86_64"}});
    store.upsert("agent-2", {{"yuzu.os", "windows"}, {"yuzu.arch", "x86_64"}});
    store.upsert("agent-3", {{"yuzu.os", "linux"}, {"yuzu.arch", "aarch64"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    REQUIRE(metrics.gauge("yuzu_fleet_agents_healthy").value() == 3.0);
    CHECK(metrics.gauge("yuzu_fleet_agents_by_os", {{"os", "linux"}}).value() == 2.0);
    CHECK(metrics.gauge("yuzu_fleet_agents_by_os", {{"os", "windows"}}).value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_agents_by_arch", {{"arch", "x86_64"}}).value() == 2.0);
    CHECK(metrics.gauge("yuzu_fleet_agents_by_arch", {{"arch", "aarch64"}}).value() == 1.0);
}

TEST_CASE("AgentHealthStore: spark rollup buckets per os and mechanism", "[health_store][spark]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    // linux agent: service only, one watch rejection.
    store.upsert("a1", {{"yuzu.os", "linux"},
                        {"yuzu.spark_running", "1"},
                        {"yuzu.spark_mechs", "service"},
                        {"yuzu.spark_service_watch_rejected", "2"}});
    // windows agent: all three mechanisms, quiescent (no counters).
    store.upsert("a2", {{"yuzu.os", "windows"},
                        {"yuzu.spark_running", "1"},
                        {"yuzu.spark_mechs", "file,service,registry"}});
    // ABSENT: no spark tags at all (a pre-rung-1 agent, or one mid-graceful-shutdown) —
    // contributes to NOTHING, not even the disabled bucket.
    store.upsert("a3", {{"yuzu.os", "linux"}});
    store.recompute_spark(metrics);

    CHECK(metrics.gauge("yuzu_fleet_spark_reporting", {{"os", "linux"}}).value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_spark_reporting", {{"os", "windows"}}).value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_spark_mechanisms", {{"os", "linux"}, {"mechanism", "service"}})
              .value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_spark_mechanisms", {{"os", "windows"}, {"mechanism", "file"}})
              .value() == 1.0);
    CHECK(metrics
              .gauge("yuzu_fleet_spark_watch_rejected", {{"os", "linux"}, {"mechanism", "service"}})
              .value() == 2.0);
}

TEST_CASE("AgentHealthStore: stale entries are pruned", "[health_store]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("agent-1", {{"yuzu.os", "linux"}});

    // Sleep long enough to exceed the staleness window
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    store.recompute_metrics(metrics, std::chrono::seconds(0));

    REQUIRE(metrics.gauge("yuzu_fleet_agents_healthy").value() == 0.0);
}

TEST_CASE("AgentHealthStore: remove deletes agent", "[health_store]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("agent-1", {{"yuzu.os", "linux"}});
    store.remove("agent-1");
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    REQUIRE(metrics.gauge("yuzu_fleet_agents_healthy").value() == 0.0);
}

TEST_CASE("AgentHealthStore: recompute clears stale label combinations", "[health_store]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("agent-1", {{"yuzu.os", "linux"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));
    CHECK(metrics.gauge("yuzu_fleet_agents_by_os", {{"os", "linux"}}).value() == 1.0);

    // Same agent switches OS
    store.upsert("agent-1", {{"yuzu.os", "windows"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    CHECK(metrics.gauge("yuzu_fleet_agents_by_os", {{"os", "windows"}}).value() == 1.0);

    // The old "linux" label combination must have been cleared
    auto output = metrics.serialize();
    CHECK(output.find("os=\"linux\"") == std::string::npos);
}

TEST_CASE("AgentHealthStore: commands_executed sums across fleet", "[health_store]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("agent-1", {{"yuzu.commands_executed", "10"}});
    store.upsert("agent-2", {{"yuzu.commands_executed", "20"}});
    store.upsert("agent-3", {{"yuzu.commands_executed", "30"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    REQUIRE(metrics.gauge("yuzu_fleet_commands_executed_total").value() == 60.0);
}

TEST_CASE("AgentHealthStore: DEX signal observer disarmed count + signals summed",
          "[health_store]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    // Armed Windows agent — must NOT count as disarmed; contributes its signal count.
    store.upsert("win-armed", {{"yuzu.dex_observer_armed", "1"}, {"yuzu.dex_observed", "3"}});
    // Windows agent that FAILED to arm — the fault we want visible; 0 signals.
    store.upsert("win-deaf", {{"yuzu.dex_observer_armed", "0"}, {"yuzu.dex_observed", "0"}});
    // Non-Windows / --dex-disable agent never emits the tag — must NOT count as disarmed.
    store.upsert("lin-1", {{"yuzu.os", "linux"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    // Exactly one genuine arm FAILURE — absent tag and armed=1 are not counted.
    CHECK(metrics.gauge("yuzu_fleet_agents_dex_observer_disarmed").value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_dex_observed_total").value() == 3.0);
}

TEST_CASE("AgentHealthStore: non-finite/garbage signal count does not poison the fleet gauge",
          "[health_store]") {
    // std::stod("inf"/"nan") returns a non-finite value WITHOUT throwing, so a single
    // rogue/buggy agent could push the fleet-wide gauge to +/-Inf or NaN for every
    // operator. The finite+non-negative guard rejects those; well-formed counts still sum.
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("good", {{"yuzu.dex_observed", "5"}, {"yuzu.commands_executed", "10"}});
    store.upsert("inf", {{"yuzu.dex_observed", "inf"}, {"yuzu.commands_executed", "inf"}});
    store.upsert("nan", {{"yuzu.dex_observed", "nan"}});
    store.upsert("neg", {{"yuzu.dex_observed", "-4"}}); // negative count is nonsense
    store.upsert("junk", {{"yuzu.dex_observed", "garbage"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    // Only the well-formed counts survive; the gauges stay finite.
    const double signals = metrics.gauge("yuzu_fleet_dex_observed_total").value();
    const double cmds = metrics.gauge("yuzu_fleet_commands_executed_total").value();
    CHECK(signals == 5.0);
    CHECK(cmds == 10.0);
    CHECK(std::isfinite(signals));
    CHECK(std::isfinite(cmds));
}

TEST_CASE("AgentHealthStore: version breakdown", "[health_store]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("agent-1", {{"yuzu.agent_version", "1.0.0"}});
    store.upsert("agent-2", {{"yuzu.agent_version", "1.0.0"}});
    store.upsert("agent-3", {{"yuzu.agent_version", "1.1.0"}});
    store.upsert("agent-4", {{"yuzu.agent_version", "2.0.0"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    CHECK(metrics.gauge("yuzu_fleet_agents_by_version", {{"version", "1.0.0"}}).value() == 2.0);
    CHECK(metrics.gauge("yuzu_fleet_agents_by_version", {{"version", "1.1.0"}}).value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_agents_by_version", {{"version", "2.0.0"}}).value() == 1.0);
}

// ── A4 fleet perf rollup ─────────────────────────────────────────────────────

TEST_CASE("AgentHealthStore: perf tags aggregate to avg/p50/p90/max + population",
          "[health_store][perf]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    // Ten agents with CPU 10..100 — known percentile answers (nearest-rank,
    // floor((n-1)*p): p50 -> index 4 = 50, p90 -> index 8 = 90).
    for (int i = 1; i <= 10; ++i)
        store.upsert("a" + std::to_string(i),
                     {{"yuzu.perf_cpu_pct", std::to_string(i * 10) + ".0"},
                      {"yuzu.perf_commit_pct", "40.0"},
                      {"yuzu.perf_disk_lat_ms", "2.50"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    CHECK(metrics.gauge("yuzu_fleet_perf_reporting").value() == 10.0);
    CHECK(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "avg"}}).value() == 55.0);
    CHECK(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "p50"}}).value() == 50.0);
    CHECK(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "p90"}}).value() == 90.0);
    CHECK(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "max"}}).value() == 100.0);
    CHECK(metrics.gauge("yuzu_fleet_perf_commit_pct", {{"stat", "avg"}}).value() == 40.0);
    CHECK(metrics.gauge("yuzu_fleet_perf_disk_lat_ms", {{"stat", "max"}}).value() == 2.5);
}

TEST_CASE("AgentHealthStore: perf gauges go absent (not zero) when nobody reports",
          "[health_store][perf]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    // First cycle: one reporter populates the family.
    store.upsert("w1", {{"yuzu.perf_cpu_pct", "42.0"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));
    REQUIRE(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "avg"}}).value() == 42.0);

    // Second cycle: the agent stops reporting the tag (e.g. --dex-disable or a
    // non-Windows fleet). The family must be CLEARED — a stale 42% or a
    // fabricated 0% would both be lies; only the population gauge reads 0.
    store.upsert("w1", {{"yuzu.os", "windows"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));
    CHECK(metrics.gauge("yuzu_fleet_perf_reporting").value() == 0.0);
    const auto text = metrics.serialize();
    CHECK(text.find("yuzu_fleet_perf_cpu_pct{") == std::string::npos);
}

TEST_CASE("AgentHealthStore: rogue perf values cannot poison fleet percentiles",
          "[health_store][perf]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("good", {{"yuzu.perf_cpu_pct", "50.0"}, {"yuzu.perf_disk_lat_ms", "3.0"}});
    store.upsert("inf", {{"yuzu.perf_cpu_pct", "inf"}, {"yuzu.perf_disk_lat_ms", "nan"}});
    store.upsert("neg", {{"yuzu.perf_cpu_pct", "-5"}});
    store.upsert("junk", {{"yuzu.perf_cpu_pct", "garbage"}});
    // A >100% CPU claim is a lie, not an outlier — clamped to 100, so it can
    // shift max to the clamp but never to an absurd magnitude.
    store.upsert("liar", {{"yuzu.perf_cpu_pct", "9000"}});
    // Latency has NO semantic bound to clamp to — an absurd-but-finite claim
    // (1e308 passes the isfinite check!) is REJECTED above the sanity ceiling,
    // otherwise one agent drags avg/max to nonsense (grill finding 2).
    store.upsert("lat-liar", {{"yuzu.perf_disk_lat_ms", "1e308"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    CHECK(metrics.gauge("yuzu_fleet_perf_reporting").value() == 2.0); // good + liar
    CHECK(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "max"}}).value() == 100.0);
    CHECK(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "avg"}}).value() == 75.0);
    CHECK(std::isfinite(metrics.gauge("yuzu_fleet_perf_disk_lat_ms", {{"stat", "avg"}}).value()));
    CHECK(metrics.gauge("yuzu_fleet_perf_disk_lat_ms", {{"stat", "avg"}}).value() == 3.0);
    CHECK(metrics.gauge("yuzu_fleet_perf_disk_lat_ms", {{"stat", "max"}}).value() == 3.0);
}

TEST_CASE("AgentHealthStore: true nearest-rank percentiles in tiny fleets",
          "[health_store][perf]") {
    // floor((n-1)·p) would return the MIN as p90 for n=2 — the regression the
    // grill caught. True nearest-rank (ceil(p·n)−1) returns the max.
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;
    store.upsert("a", {{"yuzu.perf_cpu_pct", "10.0"}});
    store.upsert("b", {{"yuzu.perf_cpu_pct", "90.0"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));
    CHECK(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "p50"}}).value() == 10.0);
    CHECK(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "p90"}}).value() == 90.0);
}

// ── network fleet rollup (slice 3) ───────────────────────────────────────────

TEST_CASE("AgentHealthStore: network facts aggregate to gauges + degraded count",
          "[health_store][network]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    // a/c are Linux (RTT + retransmit + a's degraded); b is Windows (throughput +
    // a retransmit that is WITHHELD from the gauge until validated, #1465). Per-OS,
    // never blended; Windows throughput (a real counter) DOES reach the gauge.
    store.upsert("a", {{"yuzu.net_rtt_p50_ms", "100.0"},
                       {"yuzu.net_retrans_pct", "1.0"},
                       {"yuzu.net_degraded", "1"},
                       {"yuzu.os", "linux"}});
    store.upsert("c", {{"yuzu.net_rtt_p50_ms", "200.0"},
                       {"yuzu.net_retrans_pct", "3.0"},
                       {"yuzu.os", "linux"}});
    store.upsert("b", {{"yuzu.net_throughput_bps", "1000000"},
                       {"yuzu.net_retrans_pct", "250"}, // withheld from the gauge (unvalidated)
                       {"yuzu.os", "windows"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    // Reporting is per-OS (a/c via rtt+retrans; b via throughput).
    CHECK(metrics.gauge("yuzu_fleet_net_reporting", {{"os", "linux"}}).value() == 2.0);
    CHECK(metrics.gauge("yuzu_fleet_net_reporting", {{"os", "windows"}}).value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_net_degraded", {{"os", "linux"}}).value() == 1.0); // a
    // Linux retransmit + RTT reach the gauge; Windows throughput reaches it.
    CHECK(metrics.gauge("yuzu_fleet_net_rtt_ms", {{"stat", "max"}, {"os", "linux"}}).value() ==
          200.0);
    CHECK(metrics.gauge("yuzu_fleet_net_retrans_pct", {{"stat", "max"}, {"os", "linux"}}).value() ==
          3.0);
    CHECK(metrics.gauge("yuzu_fleet_net_throughput_bps", {{"stat", "max"}, {"os", "windows"}})
              .value() == 1000000.0);
    // The unvalidated Windows retransmit is WITHHELD — a linux retransmit series
    // exists (format pinned) but NO windows one (it would read artificially healthy).
    const auto text = metrics.serialize();
    CHECK(text.find("yuzu_fleet_net_retrans_pct{stat=\"max\",os=\"linux\"}") != std::string::npos);
    CHECK(text.find("yuzu_fleet_net_retrans_pct{stat=\"max\",os=\"windows\"}") ==
          std::string::npos);
}

TEST_CASE("AgentHealthStore: network gauges go absent (not zero) when nobody reports",
          "[health_store][network]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("a", {{"yuzu.net_rtt_p50_ms", "50.0"}, {"yuzu.os", "linux"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));
    REQUIRE(metrics.gauge("yuzu_fleet_net_rtt_ms", {{"stat", "avg"}, {"os", "linux"}}).value() ==
            50.0);

    // The agent stops reporting network facts — every net family must CLEAR (a
    // stale 50 or a fabricated 0 would both be lies); no per-os series should
    // remain, including the reporting denominator.
    store.upsert("a", {{"yuzu.os", "linux"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));
    const auto text = metrics.serialize();
    CHECK(text.find("yuzu_fleet_net_reporting{") == std::string::npos);
    CHECK(text.find("yuzu_fleet_net_rtt_ms{") == std::string::npos);
}

TEST_CASE("AgentHealthStore: agent-controlled os is allowlisted (anti cardinality-injection)",
          "[health_store][network]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    // `yuzu.os` is agent-controlled. A hostile/buggy agent sprays a junk value; it
    // must collapse to "other", never create an attacker-named series (a Prometheus
    // cardinality DoS) — across both yuzu_fleet_agents_by_os and the net families.
    store.upsert("evil", {{"yuzu.os", "pwn-uniquely-named-series"},
                          {"yuzu.net_throughput_bps", "1000"}});
    store.upsert("good", {{"yuzu.os", "linux"}, {"yuzu.net_rtt_p50_ms", "10.0"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    const auto text = metrics.serialize();
    CHECK(text.find("pwn-") == std::string::npos); // the junk value never becomes a label
    CHECK(metrics.gauge("yuzu_fleet_agents_by_os", {{"os", "other"}}).value() == 1.0);  // collapsed
    CHECK(metrics.gauge("yuzu_fleet_agents_by_os", {{"os", "linux"}}).value() == 1.0);  // canonical kept
    CHECK(metrics.gauge("yuzu_fleet_net_reporting", {{"os", "other"}}).value() == 1.0); // net too
}

TEST_CASE("spark rollup: the four postures bucket separately", "[spark][fleet][health]") {
    // Governance Gate-4 consistency C-1. Before this, the disabled/failed bucketing — the
    // whole justification of the round — had ZERO coverage: you could delete that branch
    // from agent_registry.cpp's rollup and every test still passed.
    //
    // The split is what makes a fleet-wide spark BOOT FAILURE visible. Conflate FAILED with
    // DISABLED and a failed fleet looks like a deliberate opt-out; conflate FAILED with
    // ABSENT and it emits nothing at all.
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    // RUNNING x2 (windows)
    store.upsert("run1", {{"yuzu.os", "windows"},
                          {"yuzu.spark_running", "1"},
                          {"yuzu.spark_mechs", "file,registry,service"}});
    store.upsert("run2", {{"yuzu.os", "windows"},
                          {"yuzu.spark_running", "1"},
                          {"yuzu.spark_mechs", "file,registry,service"}});
    // DISABLED — a deliberate opt-out. Expected to be non-zero; never alert on it.
    store.upsert("off1", {{"yuzu.os", "windows"},
                          {"yuzu.spark_running", "0"},
                          {"yuzu.spark_disabled", "1"}});
    // FAILED — enabled, but the engine threw at boot. THE gauge operators alert on.
    store.upsert("bad1", {{"yuzu.os", "windows"}, {"yuzu.spark_running", "0"}});
    // ABSENT — no spark tags at all (pre-rung-1 agent, or mid-graceful-shutdown).
    store.upsert("old1", {{"yuzu.os", "windows"}});
    // A CONTAINER: running, but its only mechanism is inert -> empty capability CSV.
    store.upsert("ctr1", {{"yuzu.os", "linux"},
                          {"yuzu.spark_running", "1"},
                          {"yuzu.spark_mechs", ""}});

    store.recompute_spark(metrics);

    // Assert on VALUES, not on serialize() substrings: `find("} 1")` also matches "} 10"
    // and "} 12", so a substring assertion silently passes on a wrong count the moment the
    // fixture grows past 9 agents (governance Gate-8 quality).
    CHECK(metrics.gauge("yuzu_fleet_spark_reporting", {{"os", "windows"}}).value() == 2.0);
    CHECK(metrics.gauge("yuzu_fleet_spark_disabled", {{"os", "windows"}}).value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_spark_failed", {{"os", "windows"}}).value() == 1.0);
    // The container reports, but claims no capability: no {os=linux,mechanism=*} series.
    CHECK(metrics.gauge("yuzu_fleet_spark_reporting", {{"os", "linux"}}).value() == 1.0);
    const bool linux_mech_series =
        metrics.serialize().find("yuzu_fleet_spark_mechanisms{os=\"linux\"") != std::string::npos;
    CHECK_FALSE(linux_mech_series);
}

TEST_CASE("spark rollup: a garbage spark_running value must NOT page as FAILED",
          "[spark][fleet][health]") {
    // Governance Gate-4 UP-6 / consistency C-2. The rollup used to bucket `== "1"` as
    // running and ANY other non-empty string as not-running -> with no `spark_disabled` key
    // that landed in yuzu_fleet_spark_failed{os}, the ONE gauge documented "alert on it".
    // So "true", " 1", "01", "2" or "x" from a single buggy or forked agent build could page
    // on-call. It is also a forward-compat trap: a third posture value added in a later rung
    // would make an OLD server alarm the whole fleet during a rolling upgrade.
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("g1", {{"yuzu.os", "windows"}, {"yuzu.spark_running", "true"}});
    store.upsert("g2", {{"yuzu.os", "windows"}, {"yuzu.spark_running", " 1"}});
    store.upsert("g3", {{"yuzu.os", "windows"}, {"yuzu.spark_running", "01"}});
    store.upsert("g4", {{"yuzu.os", "windows"}, {"yuzu.spark_running", "2"}});
    store.upsert("g5", {{"yuzu.os", "windows"}, {"yuzu.spark_running", "x"}});
    // ...and one agent that HAS genuinely failed, to prove the gauge still works.
    store.upsert("real", {{"yuzu.os", "windows"}, {"yuzu.spark_running", "0"}});

    store.recompute_spark(metrics);

    // Exactly ONE failure — the real one. The five garbage values contribute NOTHING: not to
    // failed (which would page), not to reporting, not to disabled.
    CHECK(metrics.gauge("yuzu_fleet_spark_failed", {{"os", "windows"}}).value() == 1.0);
    const bool any_reporting =
        metrics.serialize().find("yuzu_fleet_spark_reporting{os=\"windows\"}") !=
        std::string::npos;
    CHECK_FALSE(any_reporting);
}

// ── The REAL rollup ─────────────────────────────────────────────────────────
//
// Everything above this line drives TestAgentHealthStore, a reproduction. This case drives
// the SHIPPED yuzu::server::detail::AgentHealthStore through a real protobuf::Map upsert, so
// it is the only one that fails if the spark bucketing is deleted from agent_registry.cpp.
//
// VERIFIED to fail without the shipped code: commenting out the spark block in
// recompute_metrics turns this red (the reproduction-based cases stay green — which is
// exactly the blind spot this case exists to remove). governance Gate-8 round 7, S-1.
TEST_CASE("REAL AgentHealthStore: the four spark postures reach the shipped gauges",
          "[spark][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    auto beat = [&](const std::string& id,
                    const std::vector<std::pair<std::string, std::string>>& kv) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = "linux";
        for (const auto& [k, v] : kv)
            tags[k] = v;
        store.upsert(id, tags);
    };

    // RUNNING — reports spark_running=1 and a capability CSV.
    beat("run-1", {{"yuzu.spark_running", "1"}, {"yuzu.spark_mechs", "file,registry"}});
    beat("run-2", {{"yuzu.spark_running", "1"}, {"yuzu.spark_mechs", "file"}});
    // DISABLED — spark_running=0 AND spark_disabled=1 (operator turned it off).
    beat("dis-1", {{"yuzu.spark_running", "0"}, {"yuzu.spark_disabled", "1"}});
    // FAILED — spark_running=0 with NO spark_disabled (boot-time instantiation threw).
    beat("fail-1", {{"yuzu.spark_running", "0"}});
    // ABSENT — no spark keys at all (a pre-rung-1 agent, or one shutting down). Must land in
    // NO bucket: absent-not-zero.
    beat("absent-1", {});

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    auto val = [&](const std::string& series) -> double {
        const auto pos = out.find(series);
        REQUIRE(pos != std::string::npos);
        return std::stod(out.substr(pos + series.size()));
    };

    // The bucketing this round exists to add. Deleting it from agent_registry.cpp makes
    // these three lines fail — which no mirror-based case in this file can do.
    CHECK(val("yuzu_fleet_spark_reporting{os=\"linux\"} ") == 2.0); // RUNNING only
    CHECK(val("yuzu_fleet_spark_disabled{os=\"linux\"} ") == 1.0);
    CHECK(val("yuzu_fleet_spark_failed{os=\"linux\"} ") == 1.0);

    // Capability CSV fans out per mechanism, and only from RUNNING agents.
    // Label order is the gauge's own ({os}, then {mechanism}) — asserted against the shipped
    // serialization, not a guess. (My first draft guessed the reverse order and this test
    // caught it, which is the point of driving the real store.)
    CHECK(val("yuzu_fleet_spark_mechanisms{os=\"linux\",mechanism=\"file\"} ") == 2.0);
    CHECK(val("yuzu_fleet_spark_mechanisms{os=\"linux\",mechanism=\"registry\"} ") == 1.0);

    // ABSENT is not a zero: the absent agent must not appear in any spark bucket, and a
    // never-seen OS must not be seeded at 0 (the absent-not-zero convention).
    CHECK(out.find("yuzu_fleet_spark_reporting{os=\"windows\"}") == std::string::npos);
    CHECK(out.find("yuzu_fleet_spark_failed{os=\"windows\"}") == std::string::npos);
}

TEST_CASE("REAL AgentHealthStore: a garbage spark_disabled value pages on neither bucket",
          "[spark][rollup][real]") {
    // Governance Gate-4 UP-3. spark_running parses NotRunning (strict "0"), but the DISABLED
    // vs FAILED discriminator used to be a bare `spark_disabled == "1" ? disabled : failed`,
    // so an opted-out agent whose forked build emits `spark_disabled="01"`/`"true"` was bucketed
    // FAILED — the ONE gauge with an active alert. parse_spark_disabled now treats any non-
    // conforming discriminator as Unknown → NEITHER bucket. Driven through the SHIPPED store.
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    auto beat = [&](const std::string& id,
                    const std::vector<std::pair<std::string, std::string>>& kv) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = "windows";
        for (const auto& [k, v] : kv)
            tags[k] = v;
        store.upsert(id, tags);
    };

    // Five opted-out agents with a NON-conforming disabled value — must count in neither bucket.
    beat("g1", {{"yuzu.spark_running", "0"}, {"yuzu.spark_disabled", "01"}});
    beat("g2", {{"yuzu.spark_running", "0"}, {"yuzu.spark_disabled", "true"}});
    beat("g3", {{"yuzu.spark_running", "0"}, {"yuzu.spark_disabled", " 1"}});
    beat("g4", {{"yuzu.spark_running", "0"}, {"yuzu.spark_disabled", "2"}});
    beat("g5", {{"yuzu.spark_running", "0"}, {"yuzu.spark_disabled", "yes"}});
    // ...and one genuinely failed agent (no disabled key), to prove the gauge still works.
    beat("real", {{"yuzu.spark_running", "0"}});

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    auto val = [&](const std::string& series) -> double {
        const auto pos = out.find(series);
        REQUIRE(pos != std::string::npos);
        return std::stod(out.substr(pos + series.size()));
    };

    // Exactly ONE failure — the real one. The five garbage discriminators page on NOTHING.
    CHECK(val("yuzu_fleet_spark_failed{os=\"windows\"} ") == 1.0);
    CHECK(out.find("yuzu_fleet_spark_disabled{os=\"windows\"}") == std::string::npos);
}

// F7 (#2298 rung 2): the yuzu_fleet_spark_unsupported gauge, driven through the REAL
// shipped AgentHealthStore (not the TestAgentHealthStore reproduction above), so this
// case would fail if the 4th-token parse/accumulate/publish were deleted from
// agent_registry.cpp - the exact coverage gap this file's header warns a mirror-based
// case cannot catch.
TEST_CASE("REAL AgentHealthStore: yuzu_fleet_spark_unsupported sums across agents and "
          "goes absent after staleness",
          "[spark][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    auto beat = [&](const std::string& id,
                    const std::vector<std::pair<std::string, std::string>>& kv) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = "linux";
        tags["yuzu.spark_running"] = "1";
        tags["yuzu.spark_mechs"] = "file,registry";
        for (const auto& [k, v] : kv)
            tags[k] = v;
        store.upsert(id, tags);
    };

    // Two agents, both reporting File as unsupported - the fleet gauge is their SUM,
    // not either one alone.
    beat("a1", {{"yuzu.spark_file_unsupported", "1"}});
    beat("a2", {{"yuzu.spark_file_unsupported", "2"}, {"yuzu.spark_registry_unsupported", "5"}});

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    std::string out = metrics.serialize();

    auto val = [&](const std::string& series) -> double {
        const auto pos = out.find(series);
        REQUIRE(pos != std::string::npos);
        return std::stod(out.substr(pos + series.size()));
    };
    CHECK(val("yuzu_fleet_spark_unsupported{os=\"linux\",mechanism=\"file\"} ") == 3.0);
    CHECK(val("yuzu_fleet_spark_unsupported{os=\"linux\",mechanism=\"registry\"} ") == 5.0);
    // A mechanism nobody reported must not be seeded at 0 (absent-not-zero, same
    // convention as every other spark gauge in this file).
    CHECK(out.find("yuzu_fleet_spark_unsupported{os=\"linux\",mechanism=\"service\"}") ==
          std::string::npos);

    // CURRENT gauge, not cumulative: a2 dropping to 0 must bring the fleet sum down to
    // exactly a1's contribution, never stay latched at the old total. Governance
    // finding (consistency-auditor C2, F7/#2298): production's sparse-emit contract
    // OMITS the key at zero-count (guardian_unsupported_heartbeat.hpp), it never
    // sends an explicit "0" - so this drives the shrink the same way, via an empty
    // kv (upsert() REPLACES the whole per-agent tag snapshot, never merges), rather
    // than an explicit "0" tag production never actually emits. This also drops a2's
    // registry=5 report, not just file - a2 was registry's ONLY reporter.
    beat("a2", {});
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    out = metrics.serialize();
    CHECK(val("yuzu_fleet_spark_unsupported{os=\"linux\",mechanism=\"file\"} ") == 1.0);
    // Registry now has no reporter at all - fully ABSENT, not a present 0 (the
    // series line does not exist; find() must fail). Contrast with the explicit-"0"
    // case immediately below.
    CHECK(out.find("yuzu_fleet_spark_unsupported{os=\"linux\",mechanism=\"registry\"}") ==
          std::string::npos);

    // A THIRD agent, sent an explicit "0" for registry, keeps this integration path
    // exercising parse_spark_count's explicit-zero branch too (governance finding,
    // F7/#2298 Gate 8: fixing the shrink above to use omission silently dropped this
    // file's only integration-level coverage of that branch - the raw parser's
    // unit-level "0" case is separately covered in test_spark_fleet_tags.cpp, but a
    // real explicit "0" arriving through the real AgentHealthStore was untested
    // anywhere after that fix). This also proves explicit-zero and omission are NOT
    // the same wire shape even though they parse to the same value: an explicit "0"
    // creates a PRESENT series reading 0 (parse_spark_count succeeds and the map
    // entry is created), where the full omission just above left the series fully
    // ABSENT - the exact absent-not-zero distinction this file's other rollups
    // already rely on.
    beat("a3", {{"yuzu.spark_registry_unsupported", "0"}});
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    out = metrics.serialize();
    CHECK(val("yuzu_fleet_spark_unsupported{os=\"linux\",mechanism=\"file\"} ") == 1.0);
    CHECK(val("yuzu_fleet_spark_unsupported{os=\"linux\",mechanism=\"registry\"} ") == 0.0);

    // Staleness: an agent that stops reporting entirely (aged past the window) must
    // vanish from the fleet sum, same absent-not-zero contract the other rollups here
    // already have tests for. A short sleep first (matching this file's other
    // staleness case) makes the strict "(now - last_seen) > staleness" comparison
    // unambiguous rather than relying on sub-millisecond clock resolution alone.
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    store.recompute_metrics(metrics, std::chrono::seconds{0}); // everything now "stale"
    out = metrics.serialize();
    CHECK(out.find("yuzu_fleet_spark_unsupported{os=\"linux\",mechanism=\"file\"}") ==
          std::string::npos);
}

// Governance finding (consistency-auditor C1 / architect, F7 #2298): the reader loop
// in agent_registry.cpp used to index kSparkMetricTokens by bare literal (0/1/2/3),
// bound to its declared order only by a comment. A future reorder would still
// compile (the writer composes keys by NAME) but silently misattribute one health
// signal's fleet sum into another gauge family - e.g. quarantined counts reported
// under watch_rejected, corrupting the family backing the CRITICAL
// YuzuSparkMechanismQuarantined alert. Fixed with named indices + static_asserts in
// spark_fleet_tags.hpp; this test is the regression proof - all four metrics set to
// DISTINCT non-zero values on one mechanism, each asserted to land in its own gauge,
// none of the others.
TEST_CASE("REAL AgentHealthStore: the four per-mechanism spark metrics never "
          "cross-attribute",
          "[spark][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> tags;
    tags["yuzu.os"] = "linux";
    tags["yuzu.spark_running"] = "1";
    tags["yuzu.spark_mechs"] = "service";
    tags["yuzu.spark_service_watch_rejected"] = "11";
    tags["yuzu.spark_service_quarantined"] = "22";
    tags["yuzu.spark_service_slow_op"] = "33";
    tags["yuzu.spark_service_unsupported"] = "44";
    store.upsert("a1", tags);

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    auto val = [&](const std::string& series) -> double {
        const auto pos = out.find(series);
        REQUIRE(pos != std::string::npos);
        return std::stod(out.substr(pos + series.size()));
    };
    CHECK(val("yuzu_fleet_spark_watch_rejected{os=\"linux\",mechanism=\"service\"} ") == 11.0);
    CHECK(val("yuzu_fleet_spark_quarantined{os=\"linux\",mechanism=\"service\"} ") == 22.0);
    CHECK(val("yuzu_fleet_spark_slow_op{os=\"linux\",mechanism=\"service\"} ") == 33.0);
    CHECK(val("yuzu_fleet_spark_unsupported{os=\"linux\",mechanism=\"service\"} ") == 44.0);
}

// ── Guardian durable lifecycle-journal fleet rollup (#2298 gate 3) ────────────
//
// Driven through the REAL AgentHealthStore, never the reproduction at the top of this
// file: a mirror-based case here would still pass with the rollup deleted from
// agent_registry.cpp, which is the coverage gap this file's header records.
//
// The gauges are UNLABELLED, so a series lookup must anchor to the start of a line -
// "yuzu_fleet_guardian_journal_bytes " also matches the "# HELP yuzu_fleet_..." line,
// and parsing a number off THAT throws. The labelled spark cases above are immune only
// because their `{os="..."}` fragment never appears in a HELP line.

namespace {

/// Value of an unlabelled fleet series, anchored to line start (see note above).
double unlabelled_series(const std::string& out, const std::string& name) {
    const auto pos = out.find("\n" + name + " ");
    REQUIRE(pos != std::string::npos);
    return std::stod(out.substr(pos + 1 + name.size()));
}

/// True if the series has a SAMPLE line. A described-but-empty family still emits its
/// "# HELP"/"# TYPE" lines, so a bare find(name) would report a cleared family as present.
bool has_unlabelled_series(const std::string& out, const std::string& name) {
    return out.find("\n" + name + " ") != std::string::npos;
}

} // namespace

TEST_CASE("REAL AgentHealthStore: guardian journal tags sum into unlabelled fleet gauges",
          "[guardian][journal][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    auto beat = [&](const std::string& id,
                    const std::vector<std::pair<std::string, std::string>>& kv) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = "windows";
        for (const auto& [k, v] : kv)
            tags[k] = v;
        store.upsert(id, tags);
    };

    // Two agents whose journals have something to report...
    beat("j1", {{"yuzu.guardian_journal_stage_dropped", "1"},
                {"yuzu.guardian_journal_batches_written", "10"},
                {"yuzu.guardian_journal_evicted_no_send_evidence", "2"},
                {"yuzu.guardian_journal_bytes", "4096"}});
    beat("j2", {{"yuzu.guardian_journal_stage_dropped", "4"},
                {"yuzu.guardian_journal_batches_written", "20"},
                {"yuzu.guardian_journal_bytes", "8192"}});
    // ...and one whose journal is quiescent or inert (prefer_spark off): the writer is
    // sparse, so it ships NO journal tag. It must contribute nothing - not a 0 that
    // drags a family into existence.
    beat("quiet", {});

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    // Fleet sums, unlabelled. Deleting the rollup from agent_registry.cpp fails these.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_stage_dropped") == 5.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_batches_written") == 30.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_bytes") == 12288.0);
    // Only one agent reported the integrity-gap counter - it still publishes, at ITS value.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_evicted_no_send_evidence") == 2.0);

    // A signal NOBODY reported stays absent. This is the whole point: a fabricated 0 on
    // a loss counter reads as "checked, nothing lost" when nothing was ever checked.
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_write_failures"));
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_quarantined"));
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_maint_exceptions"));

    // No agent-controlled label anywhere in this family (it is flat by design), so the
    // fleet cardinality is exactly one series per reported signal.
    CHECK(out.find("yuzu_fleet_guardian_journal_stage_dropped{") == std::string::npos);
}

TEST_CASE("REAL AgentHealthStore: journal AGE tags roll up as MAX (worst endpoint), never SUM",
          "[guardian][journal][rollup][real]") {
    // The age family (item 6 + #2364) is the first non-SUM fleet rollup: a SUM of ages
    // is meaningless (two 30 s-stale agents are not one 60 s-stale agent), and the
    // fleet question is "how bad is the WORST endpoint". Deleting the MAX block from
    // agent_registry.cpp fails these.
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;
    auto beat = [&](const std::string& id,
                    const std::vector<std::pair<std::string, std::string>>& kv) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = "linux";
        for (const auto& [k, v] : kv)
            tags[k] = v;
        store.upsert(id, tags);
    };

    beat("a1", {{"yuzu.guardian_journal_page_stale_seconds", "30"},
                {"yuzu.guardian_journal_prune_stale_seconds", "100"}});
    beat("a2", {{"yuzu.guardian_journal_page_stale_seconds", "200"},
                {"yuzu.guardian_journal_prune_stale_seconds", "50"},
                {"yuzu.guardian_journal_headroom_blocked_seconds", "700000"}});
    beat("quiet", {}); // dormant (prefer_spark off): ships no age tag, contends for no MAX

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    // MAX per signal, independently - NOT 230/150 (the SUM), and not one agent owning both.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_page_stale_seconds_max") == 200.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_prune_stale_seconds_max") == 100.0);
    // A single reporter owns its MAX (the sparse blocked gauge, near its 7-day threshold).
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_headroom_blocked_seconds_max") ==
          700000.0);
    // Flat family: no labels.
    CHECK(out.find("yuzu_fleet_guardian_journal_page_stale_seconds_max{") == std::string::npos);
}

TEST_CASE("REAL AgentHealthStore: age gauges publish an explicit 0, reject forged values, "
          "stay absent unreported",
          "[guardian][journal][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;
    auto beat = [&](const std::string& id,
                    const std::vector<std::pair<std::string, std::string>>& kv) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = "linux";
        for (const auto& [k, v] : kv)
            tags[k] = v;
        store.upsert(id, tags);
    };

    // A live fresh fleet: the writer emits the staleness pair INCLUDING 0, so the fleet
    // MAX publishes AT 0 - "every worker alive and fresh" is a real measurement, distinct
    // from the dormant fleet where the family is absent.
    beat("fresh", {{"yuzu.guardian_journal_page_stale_seconds", "0"},
                   {"yuzu.guardian_journal_prune_stale_seconds", "0"}});
    // A forged age above the plausibility ceiling is REJECTED (counted), never clamped -
    // one rogue agent must not own the fleet MAX forever.
    beat("rogue", {{"yuzu.guardian_journal_headroom_blocked_seconds", "9999999999"}});

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_page_stale_seconds_max") == 0.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_prune_stale_seconds_max") == 0.0);
    // The rogue value was rejected: the blocked gauge stays ABSENT and the rejection is
    // visible on the family's existing meta-signal.
    CHECK_FALSE(
        has_unlabelled_series(out, "yuzu_fleet_guardian_journal_headroom_blocked_seconds_max"));
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_tag_rejected") == 1.0);
}

TEST_CASE("REAL AgentHealthStore: a stale agent's age reading leaves the fleet MAX",
          "[guardian][journal][rollup][real]") {
    // The MAX sibling of the counter family's staleness-eviction test below: the
    // staleness prune runs before accumulation, so an aged-out agent's staleness
    // reading drops out of the MAX on the next sweep. For MAX this is double-edged and
    // deliberate (governance UP-11/UP-12): eviction can only LOWER the max - the
    // honest reading, since a silent agent's age is unknowable - but it also means the
    // worst endpoint leaving the reporting population resolves the fleet signal
    // without the endpoint healing. Driven with a zero window for determinism.
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> tags;
    tags["yuzu.os"] = "linux";
    tags["yuzu.guardian_journal_page_stale_seconds"] = "900";
    store.upsert("doomed", tags);

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    REQUIRE(unlabelled_series(metrics.serialize(),
                              "yuzu_fleet_guardian_journal_page_stale_seconds_max") == 900.0);

    store.recompute_metrics(metrics, std::chrono::seconds{0});
    CHECK_FALSE(has_unlabelled_series(metrics.serialize(),
                                      "yuzu_fleet_guardian_journal_page_stale_seconds_max"));
}

TEST_CASE("REAL AgentHealthStore: guardian journal gauges go absent (not zero) when nobody reports",
          "[guardian][journal][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> reporting;
    reporting["yuzu.os"] = "linux";
    reporting["yuzu.guardian_journal_write_failures"] = "7";
    store.upsert("j1", reporting);
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    REQUIRE(unlabelled_series(metrics.serialize(), "yuzu_fleet_guardian_journal_write_failures") ==
            7.0);

    // The journal recovers (or the agent is downgraded / prefer_spark turned off), so the
    // sparse writer stops emitting the tag. A stale 7 and a fabricated 0 are BOTH lies -
    // the family must clear. The 0 is the more dangerous of the two: it is the reading an
    // operator would accept as evidence the journal was checked and found clean.
    google::protobuf::Map<std::string, std::string> quiet;
    quiet["yuzu.os"] = "linux";
    store.upsert("j1", quiet);
    store.recompute_metrics(metrics, std::chrono::seconds{300});

    const std::string out = metrics.serialize();
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_write_failures"));
    // Nothing else in the family was conjured either.
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_batches_written"));
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_pending"));
}

TEST_CASE("REAL AgentHealthStore: a rogue agent cannot poison a guardian journal fleet gauge",
          "[guardian][journal][rollup][real]") {
    // The tag values are fully agent-controlled. std::stod (the idiom the older tag
    // families use) accepts "inf"/"nan" WITHOUT throwing, and a near-UINT64_MAX value
    // would annihilate every honest agent's contribution in the double-precision sum
    // (1.8e19 + 1 == 1.8e19). parse_guardian_journal_count rejects all of it as "did not
    // report". Driven through the SHIPPED store so the wiring, not just the parser, is
    // covered.
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    auto beat = [&](const std::string& id, const std::string& value) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = "linux";
        tags["yuzu.guardian_journal_stage_dropped"] = value;
        store.upsert(id, tags);
    };

    beat("honest", "5");
    beat("inf", "inf");
    beat("nan", "nan");
    beat("neg", "-1");
    beat("frac", "1.5");
    beat("junk", "garbage");
    beat("huge", "18446744073709551615"); // UINT64_MAX
    beat("over", "1000000001");           // one past the implausibility ceiling
    beat("long", std::string(4096, '9'));

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    const double sum = unlabelled_series(out, "yuzu_fleet_guardian_journal_stage_dropped");
    CHECK(sum == 5.0); // only the honest agent contributed
    CHECK(std::isfinite(sum));
}

TEST_CASE("REAL AgentHealthStore: guardian journal meta-signals publish even at zero",
          "[guardian][journal][rollup][real]") {
    // The 22 counters are absent-not-zero; these two are the OPPOSITE and deliberately
    // so. They are server-owned counts that always have a true value, so publishing 0
    // is a measurement ("nothing is reporting") rather than a fabricated zero. Without
    // them, a dark telemetry pipeline is indistinguishable from a healthy quiet fleet
    // (governance Gate-4 UP-9 / Gate-6 sre).
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> quiet;
    quiet["yuzu.os"] = "linux";
    store.upsert("no-journal", quiet);
    store.recompute_metrics(metrics, std::chrono::seconds{300});

    const std::string out = metrics.serialize();
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_reporting") == 0.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_tag_rejected") == 0.0);
    // ...while the counters themselves stay absent, as before.
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_batches_written"));
}

TEST_CASE("REAL AgentHealthStore: guardian journal reporting counts agents, not tags",
          "[guardian][journal][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    auto beat = [&](const std::string& id,
                    const std::vector<std::pair<std::string, std::string>>& kv) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = "linux";
        for (const auto& [k, v] : kv)
            tags[k] = v;
        store.upsert(id, tags);
    };

    // Two reporters (one with four tags, one with one) and two non-reporters.
    beat("j1", {{"yuzu.guardian_journal_batches_written", "10"},
                {"yuzu.guardian_journal_pruned", "3"},
                {"yuzu.guardian_journal_pages", "7"},
                {"yuzu.guardian_journal_bytes", "2048"}});
    beat("j2", {{"yuzu.guardian_journal_batches_written", "5"}});
    beat("quiet-1", {});
    beat("quiet-2", {});
    store.recompute_metrics(metrics, std::chrono::seconds{300});

    const std::string out = metrics.serialize();
    // AGENTS, not tags: j1's four tags count once.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_reporting") == 2.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_batches_written") == 15.0);
}

TEST_CASE("REAL AgentHealthStore: a rejected journal tag is counted, not silently dropped",
          "[guardian][journal][rollup][real]") {
    // Gate-5 CH-6 / Gate-4 UP-16. A value that fails the forged-value parse used to
    // vanish without trace: if the rejecting agent was the ONLY reporter, its family
    // went absent, and absent reads as "checked, nothing lost". Now the drop is
    // counted, so an operator can tell "nothing to report" from "something unreadable".
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> rogue;
    rogue["yuzu.os"] = "linux";
    rogue["yuzu.guardian_journal_evicted_no_send_evidence"] = "1000000001"; // past the ceiling
    rogue["yuzu.guardian_journal_stage_dropped"] = "garbage";
    store.upsert("rogue", rogue);
    store.recompute_metrics(metrics, std::chrono::seconds{300});

    const std::string out = metrics.serialize();
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_tag_rejected") == 2.0);
    // The families stay ABSENT (the values were never admitted) - but the rejection
    // counter is what stops that absence being misread as health.
    CHECK_FALSE(
        has_unlabelled_series(out, "yuzu_fleet_guardian_journal_evicted_no_send_evidence"));
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_stage_dropped"));
    // The agent reported nothing PARSEABLE, so it is not in the coverage denominator.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_reporting") == 0.0);
}

TEST_CASE("REAL AgentHealthStore: an explicit journal zero publishes as zero",
          "[guardian][journal][rollup][real]") {
    // The `reported` flag is tracked separately from the sum precisely so this case
    // stays honest: the real writer is sparse and never emits "0", but a non-conforming
    // or forked agent build can. An explicit "0" IS a report of zero, so it publishes
    // as 0 rather than being suppressed into absence (which would misreport a
    // reporting fleet as silent). Documented divergence, now covered.
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> tags;
    tags["yuzu.os"] = "linux";
    tags["yuzu.guardian_journal_stage_dropped"] = "0";
    store.upsert("nonconforming", tags);
    store.recompute_metrics(metrics, std::chrono::seconds{300});

    const std::string out = metrics.serialize();
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_stage_dropped") == 0.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_reporting") == 1.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_tag_rejected") == 0.0);
}

TEST_CASE("REAL AgentHealthStore: a stale agent's journal counters leave the fleet sum",
          "[guardian][journal][rollup][real]") {
    // The staleness prune runs BEFORE the accumulation loop, so an aged-out agent's
    // counters silently drop out of the sum - which is the mechanism behind the whole
    // absent-not-zero story and was previously untested here (and is still untested for
    // the sibling spark rollup). Driven with a zero staleness window so the prune is
    // deterministic rather than timing-dependent.
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> tags;
    tags["yuzu.os"] = "linux";
    tags["yuzu.guardian_journal_evicted_no_send_evidence"] = "9";
    store.upsert("doomed", tags);

    // Generous window: the agent is fresh, so it counts.
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    REQUIRE(unlabelled_series(metrics.serialize(),
                              "yuzu_fleet_guardian_journal_evicted_no_send_evidence") == 9.0);

    // Zero window: every snapshot is stale, so the agent is pruned before accumulation.
    // Its integrity counter vanishes from the fleet view even though the loss it
    // recorded really happened - the alert-resolves-without-the-gap-healing case.
    store.recompute_metrics(metrics, std::chrono::seconds{0});
    const std::string out = metrics.serialize();
    CHECK_FALSE(
        has_unlabelled_series(out, "yuzu_fleet_guardian_journal_evicted_no_send_evidence"));
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_reporting") == 0.0);
}

TEST_CASE("REAL AgentHealthStore: one agent mixing parseable and rejected journal tags",
          "[guardian][journal][rollup][real]") {
    // Gate-3 re-run (quality-engineer): every prior case gave an agent EITHER good tags
    // or bad ones, so the interaction of the two meta-signals on a SINGLE agent was
    // untested - and they are computed from the same loop pass. Also covers the
    // over-long token through the STORE (previously parser-level only): the 10-digit
    // length gate runs before the plausibility ceiling, so an 11-digit value is refused
    // unread rather than by the ceiling.
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> tags;
    tags["yuzu.os"] = "linux";
    tags["yuzu.guardian_journal_batches_written"] = "40";       // parseable
    tags["yuzu.guardian_journal_pruned"] = "9";                 // parseable
    tags["yuzu.guardian_journal_stage_dropped"] = "999999999999"; // 12 digits: length gate
    tags["yuzu.guardian_journal_write_failures"] = "1000000001";  // 10 digits: ceiling
    tags["yuzu.guardian_journal_pages"] = "not-a-number";         // malformed
    store.upsert("mixed", tags);
    store.recompute_metrics(metrics, std::chrono::seconds{300});

    const std::string out = metrics.serialize();
    // The parseable half lands in its own gauges...
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_batches_written") == 40.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_pruned") == 9.0);
    // ...the rejected half leaves its families ABSENT and is counted instead.
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_stage_dropped"));
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_write_failures"));
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_pages"));
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_tag_rejected") == 3.0);
    // One agent, and it DID report something parseable, so it counts once toward
    // coverage even though three of its five journal tags were refused.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_reporting") == 1.0);
}

// ── Guardian arm-ledger + io-ceiling rollup (rung 9c PR-3) ─────────────────────────
// Same coverage shape as the journal family above (SUM rollup, absent-not-zero), plus
// a case specific to the arm gauges: a non-spark agent NEVER emits the pair at all
// (Check A - see guardian_arm_heartbeat.hpp), so it must contribute nothing, same as
// journal's "quiescent" case but for a structurally different reason.

TEST_CASE("REAL AgentHealthStore: guardian arm tags sum into unlabelled fleet gauges",
          "[guardian][arm][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    auto beat = [&](const std::string& id,
                    const std::vector<std::pair<std::string, std::string>>& kv) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = "linux";
        for (const auto& [k, v] : kv)
            tags[k] = v;
        store.upsert(id, tags);
    };

    // Two spark-live agents, each reporting a real snapshot...
    beat("a1", {{"yuzu.guardian_arm_pending", "2"}, {"yuzu.guardian_arm_failed", "1"}});
    beat("a2", {{"yuzu.guardian_arm_pending", "3"}, {"yuzu.guardian_arm_failed", "0"}});
    // ...and one non-spark agent (prefer_spark_ off): the writer's Check A gate means it
    // NEVER emits this pair at all - not a zero, an absence.
    beat("legacy", {});

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    // SUM of CURRENT values, not MAX and not a delta accumulation.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_arm_pending") == 5.0);
    // a2's explicit "0" still counts (present, not absent) - SUM correctly includes it.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_arm_failed") == 1.0);
    // No agent-controlled label anywhere in this family.
    CHECK(out.find("yuzu_fleet_guardian_arm_pending{") == std::string::npos);
}

TEST_CASE("REAL AgentHealthStore: guardian arm gauges go absent (not zero) on a "
          "fleet with nobody running spark",
          "[guardian][arm][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    // Every agent is prefer_spark_=false: none of them ever emits the pair.
    google::protobuf::Map<std::string, std::string> tags;
    tags["yuzu.os"] = "linux";
    store.upsert("legacy1", tags);
    store.upsert("legacy2", tags);
    store.recompute_metrics(metrics, std::chrono::seconds{300});

    const std::string out = metrics.serialize();
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_arm_pending"));
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_arm_failed"));
    // The reporting meta still publishes, honestly, at 0 - distinguishing "checked, no
    // spark fleet-wide" from "telemetry path dark" is left to a cross-check against
    // yuzu_fleet_spark_reporting, per this gauge's own HELP text.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_arm_reporting") == 0.0);
}

TEST_CASE("REAL AgentHealthStore: an explicit arm-gauge zero publishes as zero, not "
          "absent",
          "[guardian][arm][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> tags;
    tags["yuzu.os"] = "linux";
    tags["yuzu.guardian_arm_pending"] = "0";
    tags["yuzu.guardian_arm_failed"] = "0";
    store.upsert("clean", tags);
    store.recompute_metrics(metrics, std::chrono::seconds{300});

    const std::string out = metrics.serialize();
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_arm_pending") == 0.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_arm_failed") == 0.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_arm_reporting") == 1.0);
}

TEST_CASE("REAL AgentHealthStore: a rogue agent cannot poison a guardian arm fleet "
          "gauge",
          "[guardian][arm][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> honest;
    honest["yuzu.os"] = "linux";
    honest["yuzu.guardian_arm_pending"] = "4";
    store.upsert("honest", honest);

    google::protobuf::Map<std::string, std::string> rogue;
    rogue["yuzu.os"] = "linux";
    rogue["yuzu.guardian_arm_pending"] = "99999999999999999999"; // far above the ceiling
    store.upsert("rogue", rogue);

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    // The rogue value is rejected, not clamped - the honest agent's 4 survives intact.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_arm_pending") == 4.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_arm_tag_rejected") == 1.0);
}

TEST_CASE("REAL AgentHealthStore: guardian io-ceiling counter sums into an "
          "unlabelled fleet gauge, absent when nobody has ever hit it",
          "[guardian][io][ceiling][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> a1;
    a1["yuzu.os"] = "linux";
    a1["yuzu.guardian_io_arm_disarm_rejected_ceiling"] = "2";
    store.upsert("a1", a1);
    google::protobuf::Map<std::string, std::string> a2;
    a2["yuzu.os"] = "linux";
    a2["yuzu.guardian_io_arm_disarm_rejected_ceiling"] = "3";
    store.upsert("a2", a2);
    // A third agent has never hit the ceiling - sparse writer, no tag at all.
    google::protobuf::Map<std::string, std::string> quiet;
    quiet["yuzu.os"] = "linux";
    store.upsert("quiet", quiet);

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_io_arm_disarm_rejected_ceiling") == 5.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_io_ceiling_reporting") == 2.0);

    // Now nobody reports it (quiescent fleet) - must go fully ABSENT, never a stale 5
    // or a fabricated 0.
    store.upsert("a1", quiet);
    store.upsert("a2", quiet);
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out2 = metrics.serialize();
    CHECK_FALSE(
        has_unlabelled_series(out2, "yuzu_fleet_guardian_io_arm_disarm_rejected_ceiling"));
    CHECK(unlabelled_series(out2, "yuzu_fleet_guardian_io_ceiling_reporting") == 0.0);
}

TEST_CASE("REAL AgentHealthStore: a rogue agent cannot poison the guardian io-ceiling "
          "fleet gauge",
          "[guardian][io][ceiling][rollup][real]") {
    // Governance Gate 4/5 fix: the io-ceiling family had this rogue-value test at the
    // parse-function level (test_guardian_arm_fleet_tags.cpp) but no end-to-end
    // AgentHealthStore-level integration test proving the wiring, unlike its 3 sibling
    // families (journal/health/arm) which each carry one - mirrors
    // "a rogue agent cannot poison a guardian arm fleet gauge" above.
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> honest;
    honest["yuzu.os"] = "linux";
    honest["yuzu.guardian_io_arm_disarm_rejected_ceiling"] = "7";
    store.upsert("honest", honest);

    google::protobuf::Map<std::string, std::string> rogue;
    rogue["yuzu.os"] = "linux";
    rogue["yuzu.guardian_io_arm_disarm_rejected_ceiling"] = "99999999999999999999"; // far above 1e9
    store.upsert("rogue", rogue);

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    // The rogue value is rejected, not clamped - the honest agent's 7 survives intact.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_io_arm_disarm_rejected_ceiling") == 7.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_io_ceiling_tag_rejected") == 1.0);
    // The rogue agent's malformed tag does not count it as a reporting endpoint.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_io_ceiling_reporting") == 1.0);
}

TEST_CASE("REAL AgentHealthStore: a torn arm-gauge pair (one key present, its "
          "partner missing) reads each gauge independently - absent stays absent, "
          "present stays present, the reporting count still fires",
          "[guardian][arm][rollup][real]") {
    // Governance Gate 4/5 (UP-4/CH-2): arm_pending and arm_failed are parsed as two
    // fully independent keys - a normal writer always sets both back-to-back with no
    // yield point in between, so this state is reachable only via a non-conforming or
    // compromised agent, or an exceedingly rare partial-write. This test pins the
    // CURRENT, documented behavior (each gauge reads independently; reporting fires on
    // ANY key present) as a known, low-severity, accepted shape - not a regression to
    // catch, a contract to keep from silently changing.
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> torn;
    torn["yuzu.os"] = "linux";
    torn["yuzu.guardian_arm_pending"] = "1"; // arm_failed deliberately absent from this heartbeat
    store.upsert("torn", torn);

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_arm_pending") == 1.0);
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_arm_failed"));
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_arm_reporting") == 1.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_arm_tag_rejected") == 0.0);
}

// ── Guardian M1 health-stream rollup (#2298 gate 3, item 6d) ──────────────────────
// Same coverage set as the journal family above, scoped to the 3-counter table.

TEST_CASE("REAL AgentHealthStore: guardian health tags sum into unlabelled fleet gauges",
          "[guardian][health][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    auto beat = [&](const std::string& id,
                    const std::vector<std::pair<std::string, std::string>>& kv) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = "windows";
        for (const auto& [k, v] : kv)
            tags[k] = v;
        store.upsert(id, tags);
    };

    beat("h1", {{"yuzu.guardian_unhealthy_suppressed", "1"},
                {"yuzu.guardian_unhealthy_refreshed", "3"}});
    beat("h2", {{"yuzu.guardian_unhealthy_suppressed", "4"},
                {"yuzu.guardian_priority_demoted", "2"}});
    // A quiescent or inert (prefer_spark off) agent: the writer is sparse, ships no
    // health tag, contributes nothing - not a fabricated 0.
    beat("quiet", {});

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_unhealthy_suppressed") == 5.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_unhealthy_refreshed") == 3.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_priority_demoted") == 2.0);

    // No agent-controlled label anywhere in this family (flat by design).
    CHECK(out.find("yuzu_fleet_guardian_unhealthy_suppressed{") == std::string::npos);
}

TEST_CASE("REAL AgentHealthStore: guardian health gauges go absent (not zero) when nobody "
          "reports",
          "[guardian][health][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> reporting;
    reporting["yuzu.os"] = "linux";
    reporting["yuzu.guardian_unhealthy_suppressed"] = "7";
    store.upsert("h1", reporting);
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    REQUIRE(unlabelled_series(metrics.serialize(), "yuzu_fleet_guardian_unhealthy_suppressed") ==
            7.0);

    // The rule recovers (or prefer_spark turned off), so the sparse writer stops
    // emitting the tag. A stale 7 and a fabricated 0 are BOTH lies - the family must
    // clear.
    google::protobuf::Map<std::string, std::string> quiet;
    quiet["yuzu.os"] = "linux";
    store.upsert("h1", quiet);
    store.recompute_metrics(metrics, std::chrono::seconds{300});

    const std::string out = metrics.serialize();
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_unhealthy_suppressed"));
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_unhealthy_refreshed"));
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_priority_demoted"));
}

TEST_CASE("REAL AgentHealthStore: a rogue agent cannot poison a guardian health fleet gauge",
          "[guardian][health][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    auto beat = [&](const std::string& id, const std::string& value) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = "linux";
        tags["yuzu.guardian_unhealthy_suppressed"] = value;
        store.upsert(id, tags);
    };

    beat("honest", "5");
    beat("inf", "inf");
    beat("nan", "nan");
    beat("neg", "-1");
    beat("frac", "1.5");
    beat("junk", "garbage");
    beat("huge", "18446744073709551615"); // UINT64_MAX
    beat("over", "1000000001");           // one past the implausibility ceiling
    beat("long", std::string(4096, '9'));

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    const double sum = unlabelled_series(out, "yuzu_fleet_guardian_unhealthy_suppressed");
    CHECK(sum == 5.0); // only the honest agent contributed
    CHECK(std::isfinite(sum));
}

TEST_CASE("REAL AgentHealthStore: guardian health meta-signals publish even at zero",
          "[guardian][health][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> quiet;
    quiet["yuzu.os"] = "linux";
    store.upsert("no-health-tags", quiet);
    store.recompute_metrics(metrics, std::chrono::seconds{300});

    const std::string out = metrics.serialize();
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_health_reporting") == 0.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_health_tag_rejected") == 0.0);
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_unhealthy_suppressed"));
}

TEST_CASE("REAL AgentHealthStore: guardian health reporting counts agents, not tags",
          "[guardian][health][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    auto beat = [&](const std::string& id,
                    const std::vector<std::pair<std::string, std::string>>& kv) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = "linux";
        for (const auto& [k, v] : kv)
            tags[k] = v;
        store.upsert(id, tags);
    };

    // Two reporters (one with all three tags, one with one) and two non-reporters.
    beat("h1", {{"yuzu.guardian_unhealthy_suppressed", "10"},
                {"yuzu.guardian_unhealthy_refreshed", "3"},
                {"yuzu.guardian_priority_demoted", "1"}});
    beat("h2", {{"yuzu.guardian_unhealthy_suppressed", "5"}});
    beat("quiet-1", {});
    beat("quiet-2", {});
    store.recompute_metrics(metrics, std::chrono::seconds{300});

    const std::string out = metrics.serialize();
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_health_reporting") == 2.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_unhealthy_suppressed") == 15.0);
}

TEST_CASE("REAL AgentHealthStore: a rejected health tag is counted, not silently dropped",
          "[guardian][health][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> rogue;
    rogue["yuzu.os"] = "linux";
    rogue["yuzu.guardian_unhealthy_suppressed"] = "1000000001"; // past the ceiling
    rogue["yuzu.guardian_priority_demoted"] = "garbage";
    store.upsert("rogue", rogue);
    store.recompute_metrics(metrics, std::chrono::seconds{300});

    const std::string out = metrics.serialize();
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_health_tag_rejected") == 2.0);
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_unhealthy_suppressed"));
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_priority_demoted"));
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_health_reporting") == 0.0);
}

TEST_CASE("REAL AgentHealthStore: an explicit health zero publishes as zero",
          "[guardian][health][rollup][real]") {
    // The real writer is sparse and never emits "0", but a non-conforming build can -
    // an explicit "0" IS a report of zero, so it publishes as 0 rather than being
    // suppressed into absence.
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> tags;
    tags["yuzu.os"] = "linux";
    tags["yuzu.guardian_unhealthy_suppressed"] = "0";
    store.upsert("nonconforming", tags);
    store.recompute_metrics(metrics, std::chrono::seconds{300});

    const std::string out = metrics.serialize();
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_unhealthy_suppressed") == 0.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_health_reporting") == 1.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_health_tag_rejected") == 0.0);
}

TEST_CASE("REAL AgentHealthStore: a stale agent's health counters leave the fleet sum",
          "[guardian][health][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> tags;
    tags["yuzu.os"] = "linux";
    tags["yuzu.guardian_priority_demoted"] = "9";
    store.upsert("doomed", tags);

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    REQUIRE(unlabelled_series(metrics.serialize(), "yuzu_fleet_guardian_priority_demoted") ==
            9.0);

    // Zero window: every snapshot is stale, so the agent is pruned before accumulation.
    store.recompute_metrics(metrics, std::chrono::seconds{0});
    const std::string out = metrics.serialize();
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_priority_demoted"));
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_health_reporting") == 0.0);
}

TEST_CASE("REAL AgentHealthStore: per-OS perf gauges (C1) reach the shipped families",
          "[perf][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    auto beat = [&](const std::string& id, const std::string& os,
                    const std::vector<std::pair<std::string, std::string>>& kv) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = os;
        for (const auto& [k, v] : kv)
            tags[k] = v;
        store.upsert(id, tags);
    };

    beat("w1", "windows", {{"yuzu.perf_cpu_pct", "10.0"}});
    beat("w2", "windows", {{"yuzu.perf_cpu_pct", "30.0"}});
    beat("l1", "linux", {{"yuzu.perf_cpu_pct", "50.0"}});
    beat("mac1", "darwin", {}); // online, no perf collector yet — must not appear below

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    auto val = [&](const std::string& series) -> double {
        const auto pos = out.find(series);
        REQUIRE(pos != std::string::npos);
        return std::stod(out.substr(pos + series.size()));
    };

    // The families this round adds. Deleting recompute_perf_os_gauges from
    // agent_registry.cpp makes these fail — which no mirror-based case can do.
    CHECK(val("yuzu_fleet_perf_os_reporting{os=\"windows\"} ") == 2.0);
    CHECK(val("yuzu_fleet_perf_os_reporting{os=\"linux\"} ") == 1.0);
    CHECK(val("yuzu_fleet_perf_os_cpu_pct{stat=\"avg\",os=\"windows\"} ") == 20.0);
    CHECK(val("yuzu_fleet_perf_os_cpu_pct{stat=\"max\",os=\"windows\"} ") == 30.0);
    CHECK(val("yuzu_fleet_perf_os_cpu_pct{stat=\"avg\",os=\"linux\"} ") == 50.0);
    // The existing four fleet-wide families stay untouched (byte-identical mix).
    CHECK(val("yuzu_fleet_perf_cpu_pct{stat=\"avg\"} ") == 30.0); // (10+30+50)/3

    // ABSENT is not a zero: darwin reported no perf tag, so no darwin series at all.
    CHECK(out.find("yuzu_fleet_perf_os_reporting{os=\"darwin\"}") == std::string::npos);
    CHECK(out.find("yuzu_fleet_perf_os_cpu_pct{stat=\"avg\",os=\"darwin\"}") == std::string::npos);
}

// ── #1567: tar.db corruption fleet signal (REAL store) ────────────────────────

namespace {
using yuzu::server::detail::AgentHealthStore;

void beat_tags(AgentHealthStore& store, const std::string& id,
               const std::vector<std::pair<std::string, std::string>>& kv) {
    google::protobuf::Map<std::string, std::string> tags;
    tags["yuzu.os"] = "linux";
    for (const auto& [k, v] : kv)
        tags[k] = v;
    store.upsert(id, tags);
}

double series_val(const std::string& out, const std::string& series) {
    // Anchor at line start so the "# TYPE <name> gauge" line cannot match first.
    const auto pos = out.find("\n" + series);
    REQUIRE(pos != std::string::npos);
    return std::stod(out.substr(pos + 1 + series.size()));
}
} // namespace

TEST_CASE("REAL AgentHealthStore: yuzu_fleet_tar_db_corruption_agents counts valid totals > 0",
          "[health_store][tar][corruption][real]") {
    AgentHealthStore store;
    yuzu::MetricsRegistry metrics;
    const char* k = "yuzu.plugin.tar.db_corruption_total";
    beat_tags(store, "a", {{k, "2"}});
    beat_tags(store, "b", {{k, "0"}});
    beat_tags(store, "c", {});
    beat_tags(store, "d", {{k, "garbage"}});
    beat_tags(store, "e", {{k, "-1"}});
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    CHECK(series_val(metrics.serialize(), "yuzu_fleet_tar_db_corruption_agents ") == 1.0);
}

TEST_CASE("REAL AgentHealthStore: yuzu_fleet_plugin_init_failed is per plugin, capped, absent-not-zero",
          "[health_store][tar][corruption][real]") {
    AgentHealthStore store;
    yuzu::MetricsRegistry metrics;
    std::string forty;
    for (int i = 0; i < 40; ++i)
        forty += (i ? ",t" : "t") + std::to_string(i);
    beat_tags(store, "a", {{"yuzu.plugins_failed", "tar,wmi"}});
    beat_tags(store, "b", {{"yuzu.plugins_failed", "tar"}});
    beat_tags(store, "c", {});
    beat_tags(store, "d", {{"yuzu.plugins_failed", forty}});
    // 40 empty tokens then a valid name: the 32-split cap bites first, no label.
    beat_tags(store, "e", {{"yuzu.plugins_failed", std::string(40, ',') + "late"}});
    // #1567 round-2: a repeated token from ONE agent counts once, not once per
    // repeat — plugins_failed_ is a set on an honest agent, so this only fires
    // for a malformed/compromised one. MUTATION-TESTED: dropping the
    // agent_registry.cpp dedup (seen_this_agent) makes tar's count 4.0 here
    // instead of 3.0, red-first-confirmed then restored.
    beat_tags(store, "f", {{"yuzu.plugins_failed", "tar,tar"}});
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    auto out = metrics.serialize();
    CHECK(out.find("plugin=\"late\"") == std::string::npos);
    CHECK(series_val(out, "yuzu_fleet_plugin_init_failed{plugin=\"tar\"} ") == 3.0);
    CHECK(series_val(out, "yuzu_fleet_plugin_init_failed{plugin=\"wmi\"} ") == 1.0);
    // At most 32 tokens counted from the 40-token agent: t0..t31 present, t32 not.
    CHECK(out.find("plugin=\"t31\"") != std::string::npos);
    CHECK(out.find("plugin=\"t32\"") == std::string::npos);

    // Fleet-wide label cap: 70 agents each failing a distinct plugin.
    AgentHealthStore many;
    yuzu::MetricsRegistry m2;
    for (int i = 0; i < 70; ++i) {
        const auto name = std::format("plug_{:02d}", i);
        beat_tags(many, "agent" + std::to_string(i), {{"yuzu.plugins_failed", name}});
    }
    many.recompute_metrics(m2, std::chrono::seconds{300});
    auto out2 = m2.serialize();
    size_t named = 0;
    for (size_t p = out2.find("yuzu_fleet_plugin_init_failed{"); p != std::string::npos;
         p = out2.find("yuzu_fleet_plugin_init_failed{", p + 1))
        ++named;
    CHECK(named == 65); // 64 named + plugin="other"
    CHECK(series_val(out2, "yuzu_fleet_plugin_init_failed{plugin=\"other\"} ") == 6.0);
    CHECK(out2.find("plugin=\"plug_63\"") != std::string::npos);
    CHECK(out2.find("plugin=\"plug_64\"") == std::string::npos);

    // Absent-not-zero: once the reporters are gone the family is cleared.
    for (int i = 0; i < 70; ++i)
        many.remove("agent" + std::to_string(i));
    many.recompute_metrics(m2, std::chrono::seconds{300});
    CHECK(m2.serialize().find("yuzu_fleet_plugin_init_failed{") == std::string::npos);
}

TEST_CASE("REAL AgentHealthStore: corruption candidates are surfaced, not deduped",
          "[health_store][tar][corruption][real]") {
    AgentHealthStore store;
    struct Call {
        std::string agent;
        int64_t total;
        std::string q;
    };
    std::vector<Call> calls;

    // No sink set: must not crash.
    beat_tags(store, "x", {{"yuzu.plugin.tar.db_corruption_total", "1"},
                           {"yuzu.plugin.tar.db_quarantine_last", "1:f"}});

    store.set_corruption_sink([&](const std::string& a, int64_t t, const std::string& q) {
        calls.push_back({a, t, q});
    });
    const char* tot = "yuzu.plugin.tar.db_corruption_total";
    const char* ql = "yuzu.plugin.tar.db_quarantine_last";

    beat_tags(store, "a", {{tot, "1"}, {ql, "100:f1"}});
    REQUIRE(calls.size() == 1);
    CHECK(calls[0].agent == "a");
    CHECK(calls[0].total == 1);
    CHECK(calls[0].q == "100:f1");

    // Same identity surfaces AGAIN: a failed/skipped audit write is retried on
    // the next heartbeat (the gate, not the store, dedups).
    beat_tags(store, "a", {{tot, "1"}, {ql, "100:f1"}});
    REQUIRE(calls.size() == 2);
    beat_tags(store, "a", {{tot, "2"}, {ql, "200:f2"}}); // new quarantine
    REQUIRE(calls.size() == 3);
    CHECK(calls[2].total == 2);
    CHECK(calls[2].q == "200:f2");

    beat_tags(store, "b", {{tot, "0"}, {ql, "1:f"}});                     // zero total
    beat_tags(store, "c", {{tot, "1"}});                                   // no quarantine_last
    beat_tags(store, "d", {{tot, "1"}, {ql, std::string(200, 'q')}});      // oversized
    beat_tags(store, "d", {{tot, "1"}, {ql, "1:a/b"}});                    // path separator
    beat_tags(store, "d", {{tot, "1"}, {ql, "100f1"}});                    // missing colon
    beat_tags(store, "d", {{tot, "1"}, {ql, "x1:f1"}});                    // non-digit epoch
    CHECK(calls.size() == 3);

    // remove() then re-upsert surfaces too.
    store.remove("a");
    beat_tags(store, "a", {{tot, "2"}, {ql, "200:f2"}});
    CHECK(calls.size() == 4);
}

TEST_CASE("TarCorruptionAuditGate: durable dedup against the audit store's newest row",
          "[health_store][tar][corruption][gate]") {
    using yuzu::server::detail::TarCorruptionAuditGate;
    int lookups = 0;
    std::optional<std::optional<std::string>> answer = std::optional<std::string>{}; // no row
    int64_t clock = 1000;
    TarCorruptionAuditGate gate(
        [&](const std::string&) {
            ++lookups;
            return answer;
        },
        [&] { return clock; });

    // No prior row -> log; mark -> no further lookup.
    CHECK(gate.should_log("a", "1:f"));
    CHECK(lookups == 1);
    gate.mark_logged("a", "1:f");
    CHECK_FALSE(gate.should_log("a", "1:f"));
    CHECK(lookups == 1);

    // Newest row already carries this identity (prior run / other HA node): no
    // write, marked, and the second call makes no lookup.
    answer = std::optional<std::string>{"2:g"};
    CHECK_FALSE(gate.should_log("b", "2:g"));
    CHECK(lookups == 2);
    CHECK_FALSE(gate.should_log("b", "2:g"));
    CHECK(lookups == 2);

    // Newest row is a different quarantine -> log.
    CHECK(gate.should_log("b", "3:h"));
    gate.mark_logged("b", "3:h");

    // Degraded store: no write, NOT marked; one probe, then no lookups inside
    // the retry window, and a probe again after it.
    answer = std::nullopt;
    const int before = lookups;
    CHECK_FALSE(gate.should_log("c", "4:i"));
    CHECK_FALSE(gate.should_log("c", "4:i"));
    CHECK(lookups == before + 1);
    clock += yuzu::server::detail::kTarCorruptionAuditDegradedRetry;
    CHECK_FALSE(gate.should_log("c", "4:i"));
    CHECK(lookups == before + 2);
    clock += yuzu::server::detail::kTarCorruptionAuditDegradedRetry;

    // Two agents with the same quarantine string are independent.
    answer = std::optional<std::string>{};
    CHECK(gate.should_log("d", "9:z"));
    gate.mark_logged("d", "9:z");
    CHECK(gate.should_log("e", "9:z"));
    gate.mark_logged("e", "9:z");
}

TEST_CASE("TarCorruptionAuditGate: a failed audit write is retried, a durable one is not",
          "[health_store][tar][corruption][gate]") {
    using yuzu::server::detail::TarCorruptionAuditGate;
    int lookups = 0;
    std::optional<std::optional<std::string>> answer = std::nullopt; // degraded
    int64_t clock = 1000;
    TarCorruptionAuditGate gate(
        [&](const std::string&) {
            ++lookups;
            return answer;
        },
        [&] { return clock; });
    // Degraded store: no write, not marked.
    CHECK_FALSE(gate.should_log("a", "1:f"));
    clock += yuzu::server::detail::kTarCorruptionAuditDegradedRetry;
    // Healthy, no row -> log; the caller's log() fails -> mark_failed opens the
    // degraded window: no lookup inside it, admitted again after it.
    answer = std::optional<std::string>{};
    REQUIRE(gate.should_log("a", "1:f"));
    const int before_fail = lookups;
    gate.mark_failed();
    CHECK_FALSE(gate.should_log("a", "1:f"));
    CHECK(lookups == before_fail);
    clock += yuzu::server::detail::kTarCorruptionAuditDegradedRetry;
    REQUIRE(gate.should_log("a", "1:f"));
    // log() succeeds -> marked; no further lookup.
    gate.mark_logged("a", "1:f");
    const int before = lookups;
    CHECK_FALSE(gate.should_log("a", "1:f"));
    CHECK(lookups == before);
}

TEST_CASE("TarCorruptionAuditGate: overlapping calls hold one in-flight slot gate-wide",
          "[health_store][tar][corruption][gate]") {
    using yuzu::server::detail::TarCorruptionAuditGate;
    int lookups = 0;
    int64_t clock = 1000;
    std::optional<std::optional<std::string>> answer = std::optional<std::string>{};
    TarCorruptionAuditGate* gp = nullptr;
    bool reenter = true;
    bool inner_same = true, inner_other = true;
    TarCorruptionAuditGate gate(
        [&](const std::string&) {
            ++lookups;
            if (reenter) {
                reenter = false;
                inner_same = gp->should_log("a", "1:f");
                inner_other = gp->should_log("b", "2:g");
            }
            return answer;
        },
        [&] { return clock; });
    gp = &gate;

    // Same-agent and other-agent calls from inside the lookup: no admit, no lookup.
    REQUIRE(gate.should_log("a", "1:f"));
    CHECK_FALSE(inner_same);
    CHECK_FALSE(inner_other);
    CHECK(lookups == 1);
    CHECK_FALSE(gate.should_log("a", "1:f")); // slot still held until completion
    CHECK(lookups == 1);
    gate.mark_logged("a", "1:f");
    CHECK_FALSE(gate.should_log("a", "1:f")); // the map answers now
    CHECK(lookups == 1);

    // mark_failed releases the slot (after the degraded window).
    REQUIRE(gate.should_log("b", "2:g"));
    gate.mark_failed();
    clock += yuzu::server::detail::kTarCorruptionAuditDegradedRetry;
    CHECK(gate.should_log("b", "2:g"));
    gate.mark_logged("b", "2:g");

    // Degraded outer lookup under overlap: exactly one probe, re-admitted after the window.
    answer = std::nullopt;
    reenter = true;
    const int before = lookups;
    CHECK_FALSE(gate.should_log("c", "3:h"));
    CHECK(lookups == before + 1);
    answer = std::optional<std::string>{};
    CHECK_FALSE(gate.should_log("c", "3:h")); // inside the window
    CHECK(lookups == before + 1);
    clock += yuzu::server::detail::kTarCorruptionAuditDegradedRetry;
    CHECK(gate.should_log("c", "3:h"));
    gate.mark_logged("c", "3:h");
}

TEST_CASE("TarCorruptionAuditGate::Reservation: a throw between reservation and "
          "completion releases the slot",
          "[health_store][tar][corruption][gate]") {
    using yuzu::server::detail::TarCorruptionAuditGate;
    int64_t clock = 1000;
    TarCorruptionAuditGate gate(
        [&](const std::string&) -> std::optional<std::optional<std::string>> {
            return std::optional<std::string>{}; // no prior row
        },
        [&] { return clock; });

    REQUIRE(gate.should_log("a", "1:f"));
    try {
        TarCorruptionAuditGate::Reservation r(gate);
        throw std::runtime_error("boom");
    } catch (...) {
    }
    // The unwind completed the reservation as failed(): degraded window open,
    // no lookup admitted for a different agent yet.
    CHECK_FALSE(gate.should_log("b", "2:g"));
    clock += yuzu::server::detail::kTarCorruptionAuditDegradedRetry;
    CHECK(gate.should_log("b", "2:g")); // proves the slot was released, not stranded

    {
        TarCorruptionAuditGate::Reservation r(gate);
        r.logged("b", "2:g");
    }
    // A committed reservation opens no degraded window: admitted immediately.
    CHECK(gate.should_log("c", "3:h"));
}

TEST_CASE("TarCorruptionAuditGate: per-agent map is bounded by fleet, never wiped",
          "[health_store][tar][corruption][gate]") {
    using yuzu::server::detail::TarCorruptionAuditGate;
    int lookups = 0;
    int64_t clock = 1000;
    TarCorruptionAuditGate gate(
        [&](const std::string&) {
            ++lookups;
            return std::optional<std::optional<std::string>>{std::optional<std::string>{}};
        },
        [&] { return clock; });
    // One past the 65,536 cap: exactly one entry is evicted, never a wholesale clear.
    constexpr int kAgents = 65537;
    for (int i = 0; i < kAgents; ++i)
        gate.mark_logged("agent-" + std::to_string(i), "1:f");
    // The single evicted entry is admitted (order-independent). Release the
    // slot (and clear the degraded window) after every admission so each of
    // the 65,537 probes actually reaches the map instead of being rejected
    // by a held in-flight slot before the map is even consulted — with a
    // stranded slot, admitted==1/lookups==1 would hold vacuously even if the
    // map itself were wrong (e.g. a clear() regression, which now admits
    // 65,536+ instead).
    int admitted = 0;
    for (int i = 0; i < kAgents; ++i) {
        if (gate.should_log("agent-" + std::to_string(i), "1:f")) {
            ++admitted;
            gate.mark_failed();
            clock += yuzu::server::detail::kTarCorruptionAuditDegradedRetry;
        }
    }
    CHECK(admitted == 1);
    CHECK(lookups == 1);
}

TEST_CASE("TarCorruptionAuditGate: a rotating identity is rate-limited per agent",
          "[health_store][tar][corruption][gate]") {
    using namespace yuzu::server::detail;
    int lookups = 0;
    int64_t clock = 5000;
    TarCorruptionAuditGate gate(
        [&](const std::string&) {
            ++lookups;
            return std::optional<std::optional<std::string>>{std::optional<std::string>{}};
        },
        [&] { return clock; });
    REQUIRE(gate.should_log("a", "1:f"));
    gate.mark_logged("a", "1:f");
    const int before = lookups;
    // Rotating identities inside the window: no row, no lookup.
    clock += 1;
    CHECK_FALSE(gate.should_log("a", "2:g"));
    clock += 1;
    CHECK_FALSE(gate.should_log("a", "3:h"));
    CHECK(lookups == before);
    // A different agent is unaffected.
    REQUIRE(gate.should_log("b", "2:g"));
    gate.mark_logged("b", "2:g");
    // Past the window the next identity logs.
    clock += kTarCorruptionAuditMinRowInterval;
    CHECK(gate.should_log("a", "3:h"));
    CHECK(lookups == before + 2);
}

TEST_CASE("tar corruption audit detail: encode/decode round-trip and sink composition",
          "[health_store][tar][corruption][gate]") {
    using namespace yuzu::server::detail;
    // Pins the verb/target documented in audit-log.md; server.cpp uses the same constants.
    CHECK(std::string(kTarCorruptionAuditAction) == "tar.db.corruption_quarantined");
    CHECK(std::string(kTarCorruptionAuditTargetType) == "Agent");
    const auto d = encode_tar_corruption_detail(3, "1700000000:tar.db.corrupt-1700000000");
    CHECK(d == "corruption_total=3 quarantine=1700000000:tar.db.corrupt-1700000000");
    CHECK(decode_tar_quarantine_from_detail(d) == "1700000000:tar.db.corrupt-1700000000");
    CHECK_FALSE(decode_tar_quarantine_from_detail("corruption_total=3").has_value());
    CHECK(valid_tar_quarantine_last("1700000000:tar.db.corrupt-1700000000-2"));

    // Store surfaces -> gate decides -> sink logs; the "audit store" is a vector.
    std::vector<std::string> rows; // encoded details, newest last
    bool log_ok = false;
    int64_t clock = 1000;
    TarCorruptionAuditGate gate([&](const std::string&) -> std::optional<std::optional<std::string>> {
        if (rows.empty())
            return std::optional<std::string>{};
        return decode_tar_quarantine_from_detail(rows.back());
    }, [&] { return clock; });
    AgentHealthStore store;
    store.set_corruption_sink([&](const std::string& a, int64_t t, const std::string& q) {
        if (!gate.should_log(a, q))
            return;
        // Mirrors server.cpp's sink shape: a Reservation, not raw mark_logged/mark_failed.
        TarCorruptionAuditGate::Reservation res(gate);
        if (log_ok) {
            rows.push_back(encode_tar_corruption_detail(t, q));
            res.logged(a, q);
        } else {
            res.failed();
        }
    });
    const auto beat = [&] {
        beat_tags(store, "a", {{kTarTagCorruptionTotal, "1"}, {kTarTagQuarantineLast, "5:f"}});
    };
    beat(); // log fails: not marked
    CHECK(rows.empty());
    log_ok = true;
    clock += kTarCorruptionAuditDegradedRetry;
    beat(); // retried after the degraded window
    REQUIRE(rows.size() == 1);
    beat(); // durable now: no further row
    CHECK(rows.size() == 1);
}

// ── #5403: pending-Spark-Disarm age (fleet MAX) and deadline count (fleet SUM) ────────────
//
// Driven through the REAL AgentHealthStore (see the journal block above for why). The age
// gauge is the one non-SUM row in the health family: a sum of ages is meaningless, so the
// consumer takes the MAX, and "no agent has a Disarm pending" must read ABSENT, never 0.

namespace {

constexpr const char* kDisarmAgeTag = "yuzu.guardian_disarm_pending_age_seconds";
constexpr const char* kDisarmAgeGauge = "yuzu_fleet_guardian_disarm_pending_age_seconds_max";
constexpr const char* kDisarmElapsedTag = "yuzu.guardian_disarm_deadline_elapsed";
constexpr const char* kDisarmElapsedGauge = "yuzu_fleet_guardian_disarm_deadline_elapsed";

void disarm_beat(yuzu::server::detail::AgentHealthStore& store, const std::string& id,
                 const std::vector<std::pair<std::string, std::string>>& kv) {
    google::protobuf::Map<std::string, std::string> tags;
    tags["yuzu.os"] = "linux";
    for (const auto& [k, v] : kv)
        tags[k] = v;
    store.upsert(id, tags);
}

} // namespace

TEST_CASE("REAL AgentHealthStore: pending-Disarm age rolls up as the fleet MAX, not the sum",
          "[guardian][health][rollup][real][disarm]") {
    // The shipped table row is the same string the test drives, so a server-side rename
    // fails here as well as in the pin test.
    REQUIRE(std::string_view(yuzu::server::detail::kGuardianHealthAgeMetrics[0].tag) ==
            kDisarmAgeTag);
    REQUIRE(std::string_view(yuzu::server::detail::kGuardianHealthAgeMetrics[0].gauge) ==
            kDisarmAgeGauge);

    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;
    disarm_beat(store, "a1", {{kDisarmAgeTag, "30"}});
    disarm_beat(store, "a2", {{kDisarmAgeTag, "200"}});
    disarm_beat(store, "quiet", {}); // no Disarm pending: no tag, contends for no MAX

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();
    CHECK(unlabelled_series(out, kDisarmAgeGauge) == 200.0); // not 230 (sum), not 30
    CHECK(out.find(std::string(kDisarmAgeGauge) + "{") == std::string::npos); // no labels
}

TEST_CASE("REAL AgentHealthStore: pending-Disarm age is absent (not 0) when no agent reports, "
          "and a published 0 is a real reading",
          "[guardian][health][rollup][real][disarm]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    disarm_beat(store, "quiet1", {});
    disarm_beat(store, "quiet2", {{"yuzu.guardian_unhealthy_suppressed", "3"}}); // other family
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    CHECK_FALSE(has_unlabelled_series(metrics.serialize(), kDisarmAgeGauge));

    // An agent whose Disarm has been pending for under a second reports 0: that IS a value.
    disarm_beat(store, "young", {{kDisarmAgeTag, "0"}});
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();
    REQUIRE(has_unlabelled_series(out, kDisarmAgeGauge));
    CHECK(unlabelled_series(out, kDisarmAgeGauge) == 0.0);
}

TEST_CASE("REAL AgentHealthStore: pending-Disarm age lifecycle - pending, aging, completion, "
          "disappearance",
          "[guardian][health][rollup][real][disarm]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;
    auto sweep = [&]() -> std::string {
        store.recompute_metrics(metrics, std::chrono::seconds{300});
        return metrics.serialize();
    };

    disarm_beat(store, "a", {}); // before: nothing pending
    CHECK_FALSE(has_unlabelled_series(sweep(), kDisarmAgeGauge));

    disarm_beat(store, "a", {{kDisarmAgeTag, "2"}}); // a Disarm becomes pending
    CHECK(unlabelled_series(sweep(), kDisarmAgeGauge) == 2.0);

    disarm_beat(store, "a", {{kDisarmAgeTag, "41"}, {kDisarmElapsedTag, "1"}}); // aging, observed
    const std::string aged = sweep();
    CHECK(unlabelled_series(aged, kDisarmAgeGauge) == 41.0);
    CHECK(unlabelled_series(aged, kDisarmElapsedGauge) == 1.0);

    // Completion: the agent stops emitting the age. The gauge disappears; the cumulative
    // count is not undone.
    disarm_beat(store, "a", {{kDisarmElapsedTag, "1"}});
    const std::string done = sweep();
    CHECK_FALSE(has_unlabelled_series(done, kDisarmAgeGauge));
    CHECK(unlabelled_series(done, kDisarmElapsedGauge) == 1.0);
}

TEST_CASE("REAL AgentHealthStore: malformed pending-Disarm age values are rejected, counted, "
          "and never throw or own the MAX",
          "[guardian][health][rollup][real][disarm]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    // Each malformed value from its own agent; none may contribute to the MAX.
    const std::vector<std::string> bad = {"-5",          "abc",        "1.5",        "12x",
                                          " 7",          "1e3",        "inf",        "nan",
                                          "1000000001",  "9999999999", "18446744073709551615",
                                          std::string(4096, '9')};
    int i = 0;
    for (const auto& v : bad)
        disarm_beat(store, "bad" + std::to_string(i++), {{kDisarmAgeTag, v}});
    disarm_beat(store, "good", {{kDisarmAgeTag, "12"}});

    REQUIRE_NOTHROW(store.recompute_metrics(metrics, std::chrono::seconds{300}));
    const std::string out = metrics.serialize();
    CHECK(unlabelled_series(out, kDisarmAgeGauge) == 12.0); // only the honest agent
    // Every rejected value is visible on the family's existing rejection meta-gauge.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_health_tag_rejected") ==
          static_cast<double>(bad.size()));

    // With ONLY malformed reporters the gauge stays absent rather than reading 0.
    yuzu::server::detail::AgentHealthStore only_bad;
    yuzu::MetricsRegistry m2;
    disarm_beat(only_bad, "x", {{kDisarmAgeTag, "-1"}});
    only_bad.recompute_metrics(m2, std::chrono::seconds{300});
    CHECK_FALSE(has_unlabelled_series(m2.serialize(), kDisarmAgeGauge));
}

TEST_CASE("REAL AgentHealthStore: Disarm deadline count sums across agents and is absent "
          "when nobody reports; the age tag does not widen the counter coverage gauge",
          "[guardian][health][rollup][real][disarm]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;
    disarm_beat(store, "a1", {{kDisarmElapsedTag, "2"}});
    disarm_beat(store, "a2", {{kDisarmElapsedTag, "5"}, {kDisarmAgeTag, "90"}});
    disarm_beat(store, "age_only", {{kDisarmAgeTag, "10"}}); // age, no counter
    disarm_beat(store, "quiet", {});
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();
    CHECK(unlabelled_series(out, kDisarmElapsedGauge) == 7.0); // SUM
    CHECK(unlabelled_series(out, kDisarmAgeGauge) == 90.0);    // MAX, over all three tags
    // health_reporting counts agents with a COUNTER tag: a1 and a2, not age_only/quiet.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_health_reporting") == 2.0);

    yuzu::server::detail::AgentHealthStore none;
    yuzu::MetricsRegistry m2;
    disarm_beat(none, "q", {});
    none.recompute_metrics(m2, std::chrono::seconds{300});
    CHECK_FALSE(has_unlabelled_series(m2.serialize(), kDisarmElapsedGauge));
}

// ── #5404: the Spark claim-lifecycle counters and the retained-tombstone count (fleet SUM) ──
//
// Driven through the REAL AgentHealthStore, table-driven off the SHIPPED
// kGuardianHealthMetrics, so a row dropped from or mistyped in the table fails here, and a
// literal list pins the eleven #5404 gauge names so a one-sided rename on either side is red.

namespace {

struct ClaimRow {
    const char* tag;
    const char* gauge;
};

constexpr ClaimRow kClaimRows[] = {
    {"yuzu.guardian_orphan_disarms_started", "yuzu_fleet_guardian_orphan_disarms_started"},
    {"yuzu.guardian_dead_watchers_erased_on_lost",
     "yuzu_fleet_guardian_dead_watchers_erased_on_lost"},
    {"yuzu.guardian_tombstones_released_by_reaper",
     "yuzu_fleet_guardian_tombstones_released_by_reaper"},
    {"yuzu.guardian_claim_index_release_failures",
     "yuzu_fleet_guardian_claim_index_release_failures"},
    {"yuzu.guardian_claim_drain_failures", "yuzu_fleet_guardian_claim_drain_failures"},
    {"yuzu.guardian_retained_tombstones", "yuzu_fleet_guardian_retained_tombstones"},
    {"yuzu.guardian_detach_sweep_left_residue", "yuzu_fleet_guardian_detach_sweep_left_residue"},
    {"yuzu.guardian_detach_claim_failures", "yuzu_fleet_guardian_detach_claim_failures"},
    {"yuzu.guardian_detach_post_commit_failures",
     "yuzu_fleet_guardian_detach_post_commit_failures"},
    {"yuzu.guardian_claims_dropped_at_stop", "yuzu_fleet_guardian_claims_dropped_at_stop"},
    {"yuzu.guardian_ack_maint_exceptions", "yuzu_fleet_guardian_ack_maint_exceptions"},
};

bool shipped_table_has(std::string_view tag, std::string_view gauge) {
    for (const auto& m : yuzu::server::detail::kGuardianHealthMetrics)
        if (std::string_view(m.tag) == tag && std::string_view(m.gauge) == gauge)
            return true;
    return false;
}

} // namespace

TEST_CASE("REAL AgentHealthStore: every #5404 claim-lifecycle row sums across agents and "
          "carries its own value",
          "[guardian][health][rollup][real][spark-claim]") {
    for (const auto& r : kClaimRows)
        REQUIRE(shipped_table_has(r.tag, r.gauge)); // the shipped table, not a parallel copy

    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;
    // Row i: agent a1 reports 10+i, agent a2 reports 100*(i+1), so the SUM of every row is
    // distinct from every other row's and from either addend (a MAX or a swapped row is red).
    std::vector<std::pair<std::string, std::string>> a1, a2;
    for (std::size_t i = 0; i < std::size(kClaimRows); ++i) {
        a1.emplace_back(kClaimRows[i].tag, std::to_string(10 + i));
        a2.emplace_back(kClaimRows[i].tag, std::to_string(100 * (i + 1)));
    }
    disarm_beat(store, "a1", a1);
    disarm_beat(store, "a2", a2);
    disarm_beat(store, "quiet", {});
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();
    for (std::size_t i = 0; i < std::size(kClaimRows); ++i) {
        INFO("gauge " << kClaimRows[i].gauge);
        REQUIRE(has_unlabelled_series(out, kClaimRows[i].gauge));
        CHECK(unlabelled_series(out, kClaimRows[i].gauge) ==
              static_cast<double>((10 + i) + 100 * (i + 1)));
        CHECK(out.find(std::string(kClaimRows[i].gauge) + "{") == std::string::npos); // no labels
    }
    // Two reporters of the counter family; the quiet agent is not one.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_health_reporting") == 2.0);
}

TEST_CASE("REAL AgentHealthStore: #5404 gauges are absent (not 0) when no agent reports, and "
          "a stale series does not outlive its reporter",
          "[guardian][health][rollup][real][spark-claim]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;
    disarm_beat(store, "quiet", {});
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    for (const auto& r : kClaimRows)
        CHECK_FALSE(has_unlabelled_series(metrics.serialize(), r.gauge));

    // One agent reports a single row; ONLY that gauge appears.
    disarm_beat(store, "a", {{"yuzu.guardian_retained_tombstones", "4"}});
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    std::string out = metrics.serialize();
    for (const auto& r : kClaimRows) {
        INFO("gauge " << r.gauge);
        if (std::string_view(r.tag) == "yuzu.guardian_retained_tombstones")
            CHECK(unlabelled_series(out, r.gauge) == 4.0);
        else
            CHECK_FALSE(has_unlabelled_series(out, r.gauge));
    }

    // The tombstones are released: the agent stops emitting the tag (sparse 0). The gauge
    // disappears on the next sweep instead of holding its last value.
    disarm_beat(store, "a", {});
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    CHECK_FALSE(has_unlabelled_series(metrics.serialize(), "yuzu_fleet_guardian_retained_tombstones"));
}

TEST_CASE("REAL AgentHealthStore: malformed #5404 values are rejected, counted, and never "
          "throw or reach a gauge",
          "[guardian][health][rollup][real][spark-claim]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    const std::vector<std::string> bad = {"-5",         "abc",        "1.5",
                                          "12x",        " 7",         "inf",
                                          "1000000001", "18446744073709551615",
                                          std::string(4096, '9')};
    int n = 0;
    for (const auto& r : kClaimRows)
        for (const auto& v : bad)
            disarm_beat(store, "bad" + std::to_string(n++), {{r.tag, v}});

    REQUIRE_NOTHROW(store.recompute_metrics(metrics, std::chrono::seconds{300}));
    const std::string out = metrics.serialize();
    for (const auto& r : kClaimRows) {
        INFO("gauge " << r.gauge);
        CHECK_FALSE(has_unlabelled_series(out, r.gauge)); // only malformed reporters: absent
    }
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_health_tag_rejected") ==
          static_cast<double>(std::size(kClaimRows) * bad.size()));
    // A malformed value is not a parseable counter tag, so nobody counts as reporting.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_health_reporting") == 0.0);
}

// ── #4472: outstanding-compensation age (fleet MAX) and deadline count (fleet SUM) ────────
//
// Driven through the REAL AgentHealthStore. The age is the age table's second row: a MAX, with
// "no agent has a compensating teardown outstanding" reading ABSENT, never 0. It is a family
// of its own, independent of the pending-Disarm age.

namespace {

constexpr const char* kCompAgeTag = "yuzu.guardian_compensation_pending_age_seconds";
constexpr const char* kCompAgeGauge = "yuzu_fleet_guardian_compensation_pending_age_seconds_max";
constexpr const char* kCompElapsedTag = "yuzu.guardian_compensation_deadline_elapsed";
constexpr const char* kCompElapsedGauge = "yuzu_fleet_guardian_compensation_deadline_elapsed";

} // namespace

TEST_CASE("REAL AgentHealthStore: compensation age rolls up as the fleet MAX, not the sum, "
          "independent of the Disarm age",
          "[guardian][health][rollup][real][compensation]") {
    REQUIRE(std::string_view(yuzu::server::detail::kGuardianHealthAgeMetrics[1].tag) ==
            kCompAgeTag);
    REQUIRE(std::string_view(yuzu::server::detail::kGuardianHealthAgeMetrics[1].gauge) ==
            kCompAgeGauge);

    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;
    disarm_beat(store, "a1", {{kCompAgeTag, "30"}});
    disarm_beat(store, "a2", {{kCompAgeTag, "200"}, {kDisarmAgeTag, "7"}});
    disarm_beat(store, "quiet", {});
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();
    CHECK(unlabelled_series(out, kCompAgeGauge) == 200.0); // not 230 (sum), not 30
    CHECK(out.find(std::string(kCompAgeGauge) + "{") == std::string::npos); // no labels
    CHECK(unlabelled_series(out, kDisarmAgeGauge) == 7.0); // its own MAX, not widened by it
}

TEST_CASE("REAL AgentHealthStore: compensation age is absent (not 0) when no agent reports, "
          "and a published 0 is a real reading",
          "[guardian][health][rollup][real][compensation]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;
    disarm_beat(store, "quiet1", {});
    disarm_beat(store, "quiet2", {{kDisarmAgeTag, "9"}}); // the Disarm age is a different family
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    CHECK_FALSE(has_unlabelled_series(metrics.serialize(), kCompAgeGauge));

    disarm_beat(store, "young", {{kCompAgeTag, "0"}});
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();
    REQUIRE(has_unlabelled_series(out, kCompAgeGauge));
    CHECK(unlabelled_series(out, kCompAgeGauge) == 0.0);
}

TEST_CASE("REAL AgentHealthStore: compensation age lifecycle - owed, aging, finished, "
          "disappearance",
          "[guardian][health][rollup][real][compensation]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;
    auto sweep = [&]() -> std::string {
        store.recompute_metrics(metrics, std::chrono::seconds{300});
        return metrics.serialize();
    };

    disarm_beat(store, "a", {});
    CHECK_FALSE(has_unlabelled_series(sweep(), kCompAgeGauge));

    disarm_beat(store, "a", {{kCompAgeTag, "2"}});
    CHECK(unlabelled_series(sweep(), kCompAgeGauge) == 2.0);

    disarm_beat(store, "a", {{kCompAgeTag, "41"}, {kCompElapsedTag, "1"}});
    const std::string aged = sweep();
    CHECK(unlabelled_series(aged, kCompAgeGauge) == 41.0);
    CHECK(unlabelled_series(aged, kCompElapsedGauge) == 1.0);

    // The teardown finishes: the agent stops emitting the age, the gauge disappears, the
    // cumulative count is not undone.
    disarm_beat(store, "a", {{kCompElapsedTag, "1"}});
    const std::string done = sweep();
    CHECK_FALSE(has_unlabelled_series(done, kCompAgeGauge));
    CHECK(unlabelled_series(done, kCompElapsedGauge) == 1.0);
}

TEST_CASE("REAL AgentHealthStore: malformed compensation age values are rejected into "
          "yuzu_fleet_guardian_health_tag_rejected, never throw, never own the MAX",
          "[guardian][health][rollup][real][compensation]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;
    const std::vector<std::string> bad = {"-5",         "abc",        "1.5",        "12x",
                                          " 7",         "1e3",        "inf",        "nan",
                                          "1000000001", "9999999999", "18446744073709551615",
                                          std::string(4096, '9')};
    int i = 0;
    for (const auto& v : bad)
        disarm_beat(store, "bad" + std::to_string(i++), {{kCompAgeTag, v}});
    disarm_beat(store, "good", {{kCompAgeTag, "12"}});

    REQUIRE_NOTHROW(store.recompute_metrics(metrics, std::chrono::seconds{300}));
    const std::string out = metrics.serialize();
    CHECK(unlabelled_series(out, kCompAgeGauge) == 12.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_health_tag_rejected") ==
          static_cast<double>(bad.size()));

    yuzu::server::detail::AgentHealthStore only_bad;
    yuzu::MetricsRegistry m2;
    disarm_beat(only_bad, "x", {{kCompAgeTag, "-1"}});
    only_bad.recompute_metrics(m2, std::chrono::seconds{300});
    CHECK_FALSE(has_unlabelled_series(m2.serialize(), kCompAgeGauge));
}

TEST_CASE("REAL AgentHealthStore: compensation deadline count sums across agents, is absent "
          "when nobody reports, and the age tag does not widen the counter coverage gauge",
          "[guardian][health][rollup][real][compensation]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;
    disarm_beat(store, "a1", {{kCompElapsedTag, "2"}});
    disarm_beat(store, "a2", {{kCompElapsedTag, "5"}, {kCompAgeTag, "90"}});
    disarm_beat(store, "age_only", {{kCompAgeTag, "10"}});
    disarm_beat(store, "quiet", {});
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();
    CHECK(unlabelled_series(out, kCompElapsedGauge) == 7.0); // SUM
    CHECK(unlabelled_series(out, kCompAgeGauge) == 90.0);    // MAX over all three tags
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_health_reporting") == 2.0);

    yuzu::server::detail::AgentHealthStore none;
    yuzu::MetricsRegistry m2;
    disarm_beat(none, "q", {});
    none.recompute_metrics(m2, std::chrono::seconds{300});
    CHECK_FALSE(has_unlabelled_series(m2.serialize(), kCompElapsedGauge));
}

// ── Wire-format edge values of the health tag parse (UP-11 / con-7) ──────────────────────
//
// Pinned for BOTH a SUM row (a #5404 counter) and an AGE row (the #5403 Disarm age): each goes
// through the shared parse_guardian_health_count, but the two accumulate in different loops of
// AgentHealthStore::recompute_metrics, so a regression in one loop is only visible here.

TEST_CASE("REAL AgentHealthStore: health tag wire-format edge values - sign / radix / padding "
          "rejected, the 1e9 ceiling inclusive, an EMPTY value skipped uncounted",
          "[guardian][health][rollup][real][spark-claim]") {
    struct Edge {
        const char* tag;
        const char* gauge;
        bool is_age;
    };
    // One SUM row and one AGE row.
    const Edge edges[] = {
        {"yuzu.guardian_retained_tombstones", "yuzu_fleet_guardian_retained_tombstones", false},
        {kDisarmAgeTag, kDisarmAgeGauge, true},
    };
    // Each is parsed as a FULL token: a leading '+', a hex prefix and ANY padding are rejected,
    // not trimmed; 1e9 + 1 and an 11-digit value are over the ceiling / digit cap. All are
    // counted in yuzu_fleet_guardian_health_tag_rejected and none reaches a gauge.
    // "00000000001" is 11 characters: the digit cap rejects it before its value is considered.
    const std::vector<std::string> rejected = {"+5",         "0x10",        " 5",
                                               "5 ",         "1000000001",  "10000000000",
                                               "00000000001"};
    for (const auto& e : edges) {
        INFO("row " << e.tag);
        {
            yuzu::server::detail::AgentHealthStore store;
            yuzu::MetricsRegistry metrics;
            int i = 0;
            for (const auto& v : rejected)
                disarm_beat(store, "bad" + std::to_string(i++), {{e.tag, v}});
            REQUIRE_NOTHROW(store.recompute_metrics(metrics, std::chrono::seconds{300}));
            const std::string out = metrics.serialize();
            CHECK_FALSE(has_unlabelled_series(out, e.gauge));
            CHECK(unlabelled_series(out, "yuzu_fleet_guardian_health_tag_rejected") ==
                  static_cast<double>(rejected.size()));
        }
        {
            // The ceiling itself (1e9) is accepted: the bound is inclusive.
            yuzu::server::detail::AgentHealthStore store;
            yuzu::MetricsRegistry metrics;
            disarm_beat(store, "ceiling", {{e.tag, "1000000000"}});
            store.recompute_metrics(metrics, std::chrono::seconds{300});
            const std::string out = metrics.serialize();
            REQUIRE(has_unlabelled_series(out, e.gauge));
            CHECK(unlabelled_series(out, e.gauge) == 1'000'000'000.0);
            CHECK(unlabelled_series(out, "yuzu_fleet_guardian_health_tag_rejected") == 0.0);
        }
        {
            // DELIBERATE, ACCEPTED behaviour (UP-11): an EMPTY value is skipped before the
            // parse, so it is neither a report nor a rejection. The agent's emitters never write
            // an empty value (a zero counter writes NO tag, an absent age writes NO tag), so an
            // empty value can only come from a hand-forged heartbeat; it is therefore a no-op,
            // not a signal. If this is ever tightened to count empties, change this test and
            // the HELP text of yuzu_fleet_guardian_health_tag_rejected together.
            yuzu::server::detail::AgentHealthStore store;
            yuzu::MetricsRegistry metrics;
            disarm_beat(store, "empty", {{e.tag, ""}});
            store.recompute_metrics(metrics, std::chrono::seconds{300});
            const std::string out = metrics.serialize();
            CHECK_FALSE(has_unlabelled_series(out, e.gauge));
            CHECK(unlabelled_series(out, "yuzu_fleet_guardian_health_tag_rejected") == 0.0);
        }
    }
}
