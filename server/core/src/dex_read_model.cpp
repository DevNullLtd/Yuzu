#include "dex_read_builders.hpp" // the store-reaching build_dex_*_model_* (defined here); dex_device_app_perf_json has since moved to dex_app_perf_model.cpp
#include "dex_read_model.hpp"

#include "dex_window.hpp" // dex_normalize_os_filter (PURE) -- replaces the dropped dex_routes.hpp
#include "guaranteed_state_store.hpp" // GuaranteedStateStore methods -- no longer transitive via dex_read_model.hpp

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cassert>
#include <cctype>
#include <cstdint>

namespace yuzu::server {

using json = nlohmann::json;

// ── MCP-only gap #1: per-device DEX score ────────────────────────────────────

DexDeviceScoreModel build_dex_device_score_model(GuaranteedStateStore* store,
                                                 const std::string& agent_id,
                                                 const std::string& window,
                                                 const std::string& since) {
    DexDeviceScoreModel m;
    m.agent_id = agent_id;
    m.window = window;
    if (!store)
        return m; // score stays -1, signals stays empty -- "no data" degrade
    // #4855: ONE checked read feeds BOTH score and signals -- closes the
    // pre-existing torn read (score and signal list used to be two
    // independent store calls; a failure of only the second used to render a
    // low/zero score next to "No DEX signals" instead of an honest degrade).
    const auto checked = store->dex_device_signal_summary_checked(agent_id, since);
    if (!checked) {
        m.degraded = true; // score stays -1, signals stays empty
        return m;
    }
    m.signals = *checked;
    m.score = dex_score_from_signals(*checked);
    return m;
}

std::string dex_device_score_json(const DexDeviceScoreModel& model, bool audit_persisted) {
    // #4855: a degraded model has no honest wire shape -- every caller
    // (device lens / REST / MCP) must have already translated `degraded`
    // into its own surface's response before reaching this serializer.
    assert(!model.degraded && "dex_device_score_json: caller must handle model.degraded first");
    json signals = json::array();
    for (const auto& s : model.signals) {
        signals.push_back({{"obs_type", s.obs_type},
                           {"count", s.count},
                           {"distinct_devices", s.distinct_devices},
                           {"last_seen", s.last_seen}});
    }
    json out{{"agent_id", model.agent_id},
             {"window", model.window},
             {"score", model.score}};
    out["signals"] = std::move(signals);
    if (!audit_persisted)
        out["audit_persisted"] = false;
    return out.dump();
}

// dex_device_app_perf_json (the MCP-only gap #2 per-device app-perf drill
// serializer) relocated to dex_app_perf_model.cpp (ADR-0031 WS-A4 DexPerfApi
// seam, PR #4582 review — Seam 2's own home, absorbed from this seam's
// temporary parking spot per its own header comment).

// ── New twin #1: app blast-radius ────────────────────────────────────────────

DexAppModel build_dex_app_model(GuaranteedStateStore* store, const std::string& process_name,
                                const std::string& window, const std::string& since,
                                const std::set<std::string>* visible) {
    DexAppModel m;
    m.process_name = process_name;
    m.window = window;
    if (!store)
        return m;
    m.summary = store->dex_app_summary(process_name, since);
    if (m.summary.signals == 0)
        return m; // matches the fragment's early "no crashes" return -- empty lists
    m.modules = store->dex_app_modules(process_name, since, 20);
    m.exceptions = store->dex_app_exceptions(process_name, since, 20);
    auto devs = store->dex_app_devices(process_name, since, 20);
    m.devices.reserve(devs.size());
    for (auto& d : devs) {
        if (visible && !visible->count(d.agent_id))
            continue; // out-of-scope device -- never enumerate its id (admit-then-filter)
        m.devices.push_back(std::move(d));
    }
    return m;
}

std::string dex_app_json(const DexAppModel& model, bool audit_persisted) {
    json modules = json::array();
    for (const auto& mo : model.modules)
        modules.push_back(
            {{"component", mo.component}, {"crashes", mo.crashes}, {"distinct_apps", mo.distinct_apps}});
    json exceptions = json::array();
    for (const auto& e : model.exceptions)
        exceptions.push_back({{"reason", e.reason}, {"symbolic", e.symbolic}, {"crashes", e.crashes}});
    json devices = json::array();
    for (const auto& d : model.devices)
        devices.push_back({{"agent_id", d.agent_id}, {"crashes", d.crashes}, {"last_seen", d.last_seen}});
    json out{{"process_name", model.process_name},
             {"window", model.window},
             {"crashes", model.summary.crashes},
             {"hangs", model.summary.hangs},
             {"signals", model.summary.signals},
             {"distinct_devices", model.summary.distinct_devices},
             {"first_seen", model.summary.first_seen},
             {"last_seen", model.summary.last_seen}};
    out["modules"] = std::move(modules);
    out["exceptions"] = std::move(exceptions);
    out["devices"] = std::move(devices);
    if (!audit_persisted)
        out["audit_persisted"] = false;
    return out.dump();
}

// ── New twin #2: app-centric stability list ──────────────────────────────────

DexAppsModel build_dex_apps_model(GuaranteedStateStore* store, const std::string& window,
                                  const std::string& since) {
    DexAppsModel m;
    m.window = window;
    if (store)
        m.apps = store->dex_top_apps(since, 100);
    return m;
}

std::string dex_apps_json(const DexAppsModel& model) {
    json arr = json::array();
    for (const auto& a : model.apps)
        arr.push_back({{"subject", a.subject},
                       {"crashes", a.crashes},
                       {"hangs", a.hangs},
                       {"distinct_devices", a.distinct_devices},
                       {"last_seen", a.last_seen}});
    json out{{"window", model.window}};
    out["apps"] = std::move(arr);
    return out.dump();
}

// ── New twin #3: catalogue-group / signal family ─────────────────────────────

namespace {
std::string normalize_platform(std::string o) {
    for (auto& c : o)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (o.starts_with("win"))
        return "windows";
    if (o == "darwin" || o == "macos")
        return "macos";
    if (o.starts_with("lin"))
        return "linux";
    return o;
}
} // namespace

std::optional<DexCatalogueGroupModel> build_dex_catalogue_group_model(
    GuaranteedStateStore* store, const std::string& group_name, const std::string& os_filter,
    const DexFleet& fleet, const std::string& window, const std::string& since) {
    const DexSignalGroup* grp = nullptr;
    for (const auto& g : dex_signal_groups())
        if (group_name == g.name) {
            grp = &g;
            break;
        }
    if (!grp)
        return std::nullopt; // unknown family -- caller maps to 404 / kInvalidParams

    DexCatalogueGroupModel m;
    m.group_name = group_name;
    m.window = window;
    m.total_type_count = static_cast<int>(grp->types.size());

    const std::string plat = dex_normalize_os_filter(os_filter);
    m.os = plat.empty() ? "all" : plat;
    if (!store)
        return m; // degrade to an all-zero, unmonitored model -- never nullopt on a valid name

    const auto signals = store->dex_signal_summary(since, plat);
    const auto r = dex_family_rollup(*grp, signals);
    m.active_events = r.events;
    m.max_signal_devices = r.max_signal_devices;

    std::vector<std::string> scope;
    if (m.os == "all") {
        for (const auto& o : fleet.connected_os) {
            auto n = normalize_platform(o);
            if (std::find(scope.begin(), scope.end(), n) == scope.end())
                scope.push_back(n);
        }
    } else {
        scope.push_back(m.os);
    }
    auto in_scope = [&](const std::string& p) {
        return std::find(scope.begin(), scope.end(), p) != scope.end();
    };
    auto monitored = [&](const char* t) {
        for (const auto& p : dex_obs_platforms(t))
            if (in_scope(p))
                return true;
        return false;
    };

    for (const char* t : grp->types) {
        DexCatalogueGroupTypeRow row;
        row.obs_type = t;
        row.monitored = monitored(t);
        if (row.monitored) {
            ++m.monitored_count;
            std::vector<std::string> ps;
            for (const auto& p : dex_obs_platforms(t))
                if (in_scope(p))
                    ps.push_back(p);
            std::sort(ps.begin(), ps.end());
            for (std::size_t i = 0; i < ps.size(); ++i) {
                if (i)
                    row.coverage_platforms += ", ";
                row.coverage_platforms += ps[i];
            }
        }
        for (const auto& s : signals)
            if (s.obs_type == t) {
                row.count = s.count;
                row.distinct_devices = s.distinct_devices;
                row.last_seen = s.last_seen;
                break;
            }
        m.types.push_back(std::move(row));
    }

    const int64_t n_scoped = m.os == "linux"    ? fleet.linux_online
                             : m.os == "macos"   ? fleet.macos_online
                                                  : fleet.windows_online; // "all" or "windows"
    if (m.monitored_count > 0 && n_scoped > 0)
        m.health_score =
            std::clamp(100.0 - dex_family_health_deduction(*grp, signals, n_scoped), 0.0, 100.0);
    return m;
}

std::string dex_catalogue_group_json(const DexCatalogueGroupModel& model) {
    json types = json::array();
    for (const auto& t : model.types)
        types.push_back({{"obs_type", t.obs_type},
                         {"monitored", t.monitored},
                         {"coverage_platforms", t.coverage_platforms},
                         {"count", t.count},
                         {"distinct_devices", t.distinct_devices},
                         {"last_seen", t.last_seen}});
    json out{{"group_name", model.group_name},
             {"os", model.os},
             {"window", model.window},
             {"monitored_count", model.monitored_count},
             {"total_type_count", model.total_type_count},
             {"active_events", model.active_events},
             {"max_signal_devices", model.max_signal_devices}};
    out["health_score"] = model.health_score < 0 ? json(nullptr) : json(model.health_score);
    out["types"] = std::move(types);
    return out.dump();
}

// ── New twin #4: per-device signal history ───────────────────────────────────

DexDeviceHistoryModel build_dex_device_history_model(GuaranteedStateStore* store,
                                                     const std::string& agent_id,
                                                     const std::string& window,
                                                     const std::string& since) {
    DexDeviceHistoryModel m;
    m.agent_id = agent_id;
    m.window = window;
    if (!store)
        return m;
    m.summary = store->dex_device_summary(agent_id, since);
    if (m.summary.signals == 0)
        return m; // matches the fragment's early "no signals" return -- empty history
    for (const auto& r : store->dex_device_history(agent_id, since, 100)) {
        DexDeviceHistoryRow row;
        row.event_id = r.event_id;
        row.observed_at = r.observed_at;
        row.obs_type = r.obs_type;
        row.subject = r.subject;
        row.reason = r.reason;
        row.symbolic = r.symbolic;
        row.component = r.component;
        row.metric = r.metric;
        m.history.push_back(std::move(row));
    }
    return m;
}

std::string dex_device_history_json(const DexDeviceHistoryModel& model, bool audit_persisted) {
    json history = json::array();
    for (const auto& r : model.history)
        history.push_back({{"event_id", r.event_id},
                           {"observed_at", r.observed_at},
                           {"obs_type", r.obs_type},
                           {"subject", r.subject},
                           {"reason", r.reason},
                           {"symbolic", r.symbolic},
                           {"component", r.component},
                           {"metric", r.metric}});
    json out{{"agent_id", model.agent_id},
             {"window", model.window},
             {"crashes", model.summary.crashes},
             {"hangs", model.summary.hangs},
             {"signals", model.summary.signals},
             {"distinct_apps", model.summary.distinct_apps},
             {"last_seen", model.summary.last_seen}};
    out["history"] = std::move(history);
    if (!audit_persisted)
        out["audit_persisted"] = false;
    return out.dump();
}

// ── New twin #5: single-observation detail ───────────────────────────────────

std::optional<GuardianObservationRow> build_dex_observation_model(GuaranteedStateStore* store,
                                                                  const std::string& agent_id,
                                                                  const std::string& event_id) {
    if (!store || agent_id.empty() || event_id.empty())
        return std::nullopt;
    auto obs = store->dex_observation(event_id);
    if (!obs || obs->agent_id != agent_id)
        return std::nullopt; // foreign/guessed event_id -- same outcome as genuinely-absent
    return obs;
}

std::string dex_observation_json(const GuardianObservationRow& obs, bool audit_persisted) {
    json out{{"event_id", obs.event_id},
             {"agent_id", obs.agent_id},
             {"observed_at", obs.observed_at},
             {"obs_type", obs.obs_type},
             {"subject", obs.subject},
             {"reason", obs.reason},
             {"symbolic", obs.symbolic},
             {"component", obs.component},
             {"version", obs.version},
             {"metric", obs.metric},
             {"platform", obs.platform}};
    if (!audit_persisted)
        out["audit_persisted"] = false;
    return out.dump();
}

// ── New twin #6: health score ────────────────────────────────────────────────

DexHealthModel build_dex_health_model(GuaranteedStateStore* store, const DexFleet& fleet,
                                      const std::string& weighting, const std::string& window,
                                      const std::string& since) {
    DexHealthModel m;
    m.window = window;
    m.weighting = (weighting == "stability" || weighting == "productivity" || weighting == "security")
                     ? weighting
                     : "default";
    if (!store)
        return m;
    const auto signals = store->dex_signal_summary(since);
    const auto summary = store->dex_crash_summary(since, "windows");
    const int64_t N = fleet.windows_online;
    m.reporting = N;
    m.total_crashes = summary.total_crashes;
    if (N > 0) {
        int64_t impacted = summary.distinct_devices > N ? N : summary.distinct_devices;
        m.crash_free_pct = 100.0 * static_cast<double>(N - impacted) / static_cast<double>(N);
    }
    if (N <= 0)
        return m; // composite suppressed -- score/band stay -1/""

    const auto health = dex_compute_health(signals, N, m.weighting);
    m.score = health.score;
    m.band = health.score >= 90   ? "excellent"
             : health.score >= 75 ? "good"
             : health.score >= 60 ? "fair"
                                  : "poor";
    for (const auto& d : health.deds)
        m.deductions.push_back({d.name, d.sev, d.deduction});
    return m;
}

std::string dex_health_json(const DexHealthModel& model) {
    json deds = json::array();
    for (const auto& d : model.deductions)
        deds.push_back({{"name", d.name}, {"severity", d.severity}, {"deduction", d.deduction}});
    json out{{"weighting", model.weighting},
             {"window", model.window},
             {"reporting", model.reporting},
             {"total_crashes", model.total_crashes}};
    out["crash_free_pct"] = model.crash_free_pct < 0 ? json(nullptr) : json(model.crash_free_pct);
    out["score"] = model.score < 0 ? json(nullptr) : json(model.score);
    out["band"] = model.band.empty() ? json(nullptr) : json(model.band);
    out["deductions"] = std::move(deds);
    return out.dump();
}

// ── New twin #7: trends ──────────────────────────────────────────────────────

DexTrendsModel build_dex_trends_model(GuaranteedStateStore* store, const DexFleet& fleet,
                                      const std::string& window, const std::string& since) {
    DexTrendsModel m;
    m.window = window;
    m.total_catalogued_types = static_cast<int64_t>(dex_catalogued_type_count());
    if (!store)
        return m;

    const auto scope = store->dex_os_signal_scope(since);
    const auto matrix = store->dex_signal_day_matrix(since);
    const auto summary = store->dex_crash_summary(since, "windows"); // Windows-scoped, #C-DEX-1

    auto scope_of = [&](const char* p) -> const DexOsScope* {
        for (const auto& s : scope)
            if (s.platform.find(p) != std::string::npos)
                return &s;
        return nullptr;
    };
    auto os_card = [&](const char* key, bool primary) {
        DexTrendsOsCard c;
        c.platform = key;
        const DexOsScope* s = scope_of(key);
        c.distinct_types = s ? s->distinct_types : 0;
        c.total_events = s ? s->total_events : 0;
        c.live = s != nullptr || (primary && fleet.windows_online > 0);
        return c;
    };
    m.os_cards.push_back(os_card("win", true));
    m.os_cards.push_back(os_card("mac", false));
    m.os_cards.push_back(os_card("lin", false));
    m.windows_reporting = fleet.windows_online;
    if (fleet.windows_online > 0) {
        int64_t impacted = summary.distinct_devices > fleet.windows_online ? fleet.windows_online
                                                                            : summary.distinct_devices;
        m.crash_free_pct = 100.0 * static_cast<double>(fleet.windows_online - impacted) /
                           static_cast<double>(fleet.windows_online);
    }

    for (const auto& row : matrix)
        if (m.days.empty() || m.days.back() != row.day)
            m.days.push_back(row.day);
    auto day_index = [&](const std::string& d) {
        for (std::size_t i = 0; i < m.days.size(); ++i)
            if (m.days[i] == d)
                return static_cast<int>(i);
        return -1;
    };
    const auto& groups = dex_signal_groups();
    m.families.resize(groups.size());
    for (std::size_t i = 0; i < groups.size(); ++i) {
        m.families[i].name = groups[i].name;
        m.families[i].counts.assign(m.days.size(), 0);
    }
    for (const auto& row : matrix) {
        const int fi = dex_family_index(row.obs_type);
        const int di = day_index(row.day);
        if (fi >= 0 && di >= 0) {
            m.families[static_cast<std::size_t>(fi)].counts[static_cast<std::size_t>(di)] += row.count;
            m.families[static_cast<std::size_t>(fi)].total += row.count;
        }
    }
    return m;
}

std::string dex_trends_json(const DexTrendsModel& model) {
    json os_cards = json::array();
    for (const auto& c : model.os_cards)
        os_cards.push_back({{"platform", c.platform},
                            {"live", c.live},
                            {"distinct_types", c.distinct_types},
                            {"total_events", c.total_events}});
    json days = json::array();
    for (const auto& d : model.days)
        days.push_back(d);
    json families = json::array();
    for (const auto& f : model.families) {
        json counts = json::array();
        for (auto v : f.counts)
            counts.push_back(v);
        json fj{{"name", f.name}, {"total", f.total}};
        fj["counts"] = std::move(counts);
        families.push_back(std::move(fj));
    }
    json out{{"window", model.window}, {"total_catalogued_types", model.total_catalogued_types},
             {"windows_reporting", model.windows_reporting}};
    out["crash_free_pct"] = model.crash_free_pct < 0 ? json(nullptr) : json(model.crash_free_pct);
    out["os_cards"] = std::move(os_cards);
    out["days"] = std::move(days);
    out["families"] = std::move(families);
    return out.dump();
}

// ── New twin #8: overview ────────────────────────────────────────────────────

DexOverviewModel build_dex_overview_model(GuaranteedStateStore* store, const DexFleet& fleet,
                                          const std::string& window, int window_days,
                                          const std::string& since,
                                          const std::set<std::string>* visible) {
    DexOverviewModel m;
    m.window = window;
    m.total_online = fleet.total_online;
    if (!store)
        return m;

    const auto signals = store->dex_signal_summary(since);
    const auto summary = store->dex_crash_summary(since, "windows"); // Windows-scoped, #C-DEX-1
    const auto apps = store->dex_top_apps(since, 8);
    const auto devices = store->dex_top_devices(since, 8);
    const auto by_day = store->dex_crashes_by_day(since);
    const auto os_scope = store->dex_os_signal_scope(since);
    m.os_reporting_count = static_cast<int64_t>(os_scope.size());

    // -- Experience: per-device score distribution + Device/App/Network split --
    {
        std::vector<int> ds;
        ds.reserve(fleet.connected_agents.size());
        std::vector<std::string> seg_os;
        std::vector<int> seg_n;
        std::vector<long long> seg_sum;
        auto seg_idx = [&](const std::string& o) -> std::size_t {
            for (std::size_t i = 0; i < seg_os.size(); ++i)
                if (seg_os[i] == o)
                    return i;
            seg_os.push_back(o);
            seg_n.push_back(0);
            seg_sum.push_back(0);
            return seg_os.size() - 1;
        };
        for (const auto& [id, os] : fleet.connected_agents) {
            const int s = dex_device_score(store, id, since);
            if (s < 0) {
                ++m.unscored; // #4855: null store OR a degraded per-device read
                continue;
            }
            ds.push_back(s);
            const std::size_t i = seg_idx(os.empty() ? std::string("unknown") : os);
            ++seg_n[i];
            seg_sum[i] += s;
        }
        for (int s : ds) {
            if (s >= 90) ++m.great;
            else if (s >= 75) ++m.fair;
            else ++m.poor;
        }
        if (!ds.empty()) {
            std::sort(ds.begin(), ds.end());
            m.overall_experience = ds[ds.size() / 2];
        }

        const auto health = dex_compute_health(signals, fleet.windows_online, "default");
        double app_ded = 0, net_ded = 0, dev_ded = 0;
        for (const auto& d : health.deds) {
            if (d.name == "App reliability") app_ded += d.deduction;
            else if (d.name == "Network") net_ded += d.deduction;
            else dev_ded += d.deduction;
        }
        auto bscore = [&](double ded) {
            return health.score < 0 ? -1
                                    : static_cast<int>(std::clamp(100.0 - ded, 0.0, 100.0) + 0.5);
        };
        m.device_score = bscore(dev_ded);
        m.app_score = bscore(app_ded);
        m.network_score = bscore(net_ded);
        m.health_score = health.score;

        std::vector<std::string> cscope;
        for (const auto& o : fleet.connected_os) {
            auto n = normalize_platform(o);
            if (std::find(cscope.begin(), cscope.end(), n) == cscope.end())
                cscope.push_back(n);
        }
        m.coverage_total = static_cast<int64_t>(dex_catalogued_type_count());
        for (const auto& g : dex_signal_groups())
            for (const char* t : g.types)
                for (const auto& p : dex_obs_platforms(t))
                    if (std::find(cscope.begin(), cscope.end(), p) != cscope.end()) {
                        ++m.coverage_monitored;
                        break;
                    }

        for (std::size_t i = 0; i < seg_os.size(); ++i) {
            DexOverviewSegment seg;
            seg.os = seg_os[i];
            seg.devices = seg_n[i];
            seg.avg_experience =
                seg_n[i] > 0 ? static_cast<int>(static_cast<double>(seg_sum[i]) / seg_n[i] + 0.5) : -1;
            m.segments.push_back(std::move(seg));
        }
    }

    // -- Reliability -- measured --
    m.windows_reporting = fleet.windows_online;
    m.total_crashes = summary.total_crashes;
    m.devices_impacted = summary.distinct_devices;
    if (fleet.windows_online > 0) {
        int64_t impacted = summary.distinct_devices;
        if (impacted > fleet.windows_online)
            impacted = fleet.windows_online;
        m.crash_free_pct = 100.0 * static_cast<double>(fleet.windows_online - impacted) /
                           static_cast<double>(fleet.windows_online);
        if (window_days > 0) {
            const double dd = static_cast<double>(fleet.windows_online) * static_cast<double>(window_days);
            m.crashes_per_1k_device_days =
                dd > 0 ? static_cast<double>(summary.total_crashes) / dd * 1000.0 : 0.0;
        }
    }

    // -- Explore teaser: active signal type count --
    for (const auto& s : signals)
        if (s.count > 0)
            ++m.active_signal_types;

    // -- Crashes per day + top lists --
    for (const auto& d : by_day)
        m.crashes_by_day.push_back({d.day, d.crashes});
    m.top_apps = apps;
    for (const auto& d : devices) {
        if (visible && !visible->count(d.agent_id))
            continue; // out-of-scope device -- never enumerate its id (admit-then-filter)
        m.top_devices.push_back(d);
    }

    // -- By operating system --
    for (const auto& s : os_scope) {
        DexOverviewOsRow row;
        row.platform = s.platform;
        row.distinct_types = s.distinct_types;
        row.total_events = s.total_events;
        if (s.platform == "windows" && fleet.windows_online > 0) {
            int64_t impacted = summary.distinct_devices;
            if (impacted > fleet.windows_online)
                impacted = fleet.windows_online;
            row.reporting = fleet.windows_online;
            row.crash_free_pct = 100.0 * static_cast<double>(fleet.windows_online - impacted) /
                                 static_cast<double>(fleet.windows_online);
        }
        m.os_table.push_back(std::move(row));
    }
    return m;
}

std::string dex_overview_json(const DexOverviewModel& model, bool audit_persisted) {
    json segments = json::array();
    for (const auto& s : model.segments)
        segments.push_back({{"os", s.os}, {"devices", s.devices}, {"avg_experience", s.avg_experience}});
    json crashes_by_day = json::array();
    for (const auto& d : model.crashes_by_day)
        crashes_by_day.push_back({{"day", d.day}, {"crashes", d.crashes}});
    json top_apps = json::array();
    for (const auto& a : model.top_apps)
        top_apps.push_back({{"subject", a.subject},
                            {"crashes", a.crashes},
                            {"hangs", a.hangs},
                            {"distinct_devices", a.distinct_devices},
                            {"last_seen", a.last_seen}});
    json top_devices = json::array();
    for (const auto& d : model.top_devices)
        top_devices.push_back({{"agent_id", d.agent_id}, {"crashes", d.crashes}, {"last_seen", d.last_seen}});
    json os_table = json::array();
    for (const auto& r : model.os_table) {
        json rj{{"platform", r.platform}, {"distinct_types", r.distinct_types},
                {"total_events", r.total_events}};
        rj["reporting"] = r.reporting > 0 ? json(r.reporting) : json(nullptr);
        rj["crash_free_pct"] = r.crash_free_pct < 0 ? json(nullptr) : json(r.crash_free_pct);
        os_table.push_back(std::move(rj));
    }
    json out{{"window", model.window},
             {"overall_experience", model.overall_experience},
             {"device_score", model.device_score},
             {"app_score", model.app_score},
             {"network_score", model.network_score},
             {"great", model.great},
             {"fair", model.fair},
             {"poor", model.poor},
             {"unscored", model.unscored}, // #4855: additive field, see DexOverviewModel::unscored
             {"coverage_monitored", model.coverage_monitored},
             {"coverage_total", model.coverage_total},
             {"windows_reporting", model.windows_reporting},
             {"total_crashes", model.total_crashes},
             {"devices_impacted", model.devices_impacted},
             {"total_online", model.total_online},
             {"active_signal_types", model.active_signal_types},
             {"os_reporting_count", model.os_reporting_count}};
    out["crash_free_pct"] = model.crash_free_pct < 0 ? json(nullptr) : json(model.crash_free_pct);
    out["crashes_per_1k_device_days"] =
        model.crashes_per_1k_device_days < 0 ? json(nullptr) : json(model.crashes_per_1k_device_days);
    out["health_score"] = model.health_score < 0 ? json(nullptr) : json(model.health_score);
    out["segments"] = std::move(segments);
    out["crashes_by_day"] = std::move(crashes_by_day);
    out["top_apps"] = std::move(top_apps);
    out["top_devices"] = std::move(top_devices);
    out["os_table"] = std::move(os_table);
    if (!audit_persisted)
        out["audit_persisted"] = false;
    return out.dump();
}

} // namespace yuzu::server
