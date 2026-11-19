/**
 * test_software_read_routes.cpp - the SAM-33 installed-software read routes through
 * TestRouteSink: hosts, host detail, change feed, summary, plugin health.
 *
 * No socket, no store, no libpq: every store read is a fake behind SoftwareReadRoutes::Reads, so
 * the cases pin the ROUTE logic. The fleet-read gate is faked per case (scope nullopt is the
 * unfiltered caller, an engaged scope a confined one). The pins: the gate decides before any read,
 * the scope confines every page and every cursor, an out-of-scope host and an unknown host answer
 * the same 404, the fleet snapshot is never served to a confined caller, a degraded read is a 503
 * and never an empty 200, and a throwing audit sink never turns a served read into a 500.
 */

#include <catch2/catch_test_macros.hpp>

#include "software_read_routes.hpp"
#include "test_route_sink.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

constexpr std::int64_t kNow = 1'700'000'000;

using Scope = std::optional<std::unordered_set<std::string>>;

// A braced list of two const char* would pick std::string's iterator-pair constructor; type it.
Scope scope_of(std::initializer_list<std::string> ids) {
    return Scope{std::unordered_set<std::string>(ids)};
}

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_id;
    std::string detail;
};

SoftwareHostRow host_row(const std::string& id, std::int64_t last_seen = 1'699'000'000) {
    SoftwareHostRow r;
    r.agent_id = id;
    r.last_seen = last_seen;
    r.facets.push_back({"software.installed", "full", "tok", true, 1'699'000'100, 12, 345});
    return r;
}

SoftwareChangeRow change_row(std::int64_t id, const std::string& agent, std::int64_t observed_at) {
    SoftwareChangeRow r;
    r.change_id = id;
    r.agent_id = agent;
    r.facet = "software.installed";
    r.kind = "install";
    r.name = "pkg-" + std::to_string(id);
    r.observed_at = observed_at;
    return r;
}

SoftwareFleetRow install_row(const std::string& agent, std::int64_t install_id) {
    SoftwareFleetRow r;
    r.agent_id = agent;
    r.install_id = install_id;
    r.entry.name = "pkg";
    r.entry.version = "1." + std::to_string(install_id);
    return r;
}

FacetHealth facet(const std::string& name, std::int64_t full) {
    FacetHealth f;
    f.facet = name;
    f.devices_by_status = {{"full", full}};
    f.slowest.push_back({"a1", 99});
    return f;
}

struct Harness {
    SoftwareReadRoutes routes; // declared BEFORE the sink that holds handlers capturing it
    yuzu::server::test::TestRouteSink sink;

    // The gate.
    bool admitted{true};
    int denial_status{403};
    Scope scope; // nullopt = unfiltered
    int gate_calls{0};

    // The audit sink.
    std::vector<AuditRecord> audit_log;
    bool audit_persists{true};
    bool audit_throws{false};

    // The data and the read counters.
    std::unordered_map<std::string, std::string> roster;
    bool roster_fails{false}; ///< the roster read reports a failure (nullopt)
    bool roster_truncated{false}; ///< the roster read hit its row cap (a typed partial, #5712)
    std::vector<SoftwareHostRow> hosts;
    std::vector<SoftwareChangeRow> changes;
    std::vector<SoftwareFleetRow> installs;
    std::shared_ptr<const SoftwareFleetSnapshot> snapshot;
    SoftwareSummary live_summary;
    std::vector<FacetHealth> live_facets;
    CatalogRollupMeta catalog;
    bool reads_degrade{false};
    int host_reads{0}, change_reads{0}, install_reads{0}, aggregate_reads{0}, snapshot_reads{0};
    std::optional<std::vector<std::string>> last_aggregate_ids;
    std::string last_install_agent;

    explicit Harness(bool wire_reads = true, bool wire_roster = true) {
        SoftwareReadRoutes::Deps deps;
        deps.fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                    const std::string&,
                                    const std::string&) -> authz::FleetReadGate {
            ++gate_calls;
            if (!admitted) {
                res.status = denial_status;
                res.set_content(R"({"error":{"message":"denied"}})", "application/json");
                return {};
            }
            return {true, scope};
        };
        deps.audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) -> bool {
            if (audit_throws)
                throw std::runtime_error("audit sink down");
            audit_log.push_back({action, result, target_id, detail});
            return audit_persists;
        };
        if (wire_roster)
            deps.roster_fn = [this]() -> std::optional<OfflineRoster> {
                if (roster_fails)
                    return std::nullopt;
                OfflineRoster out;
                out.truncated = roster_truncated;
                for (const auto& [id, hostname] : roster)
                    out.rows.push_back({.agent_id = id, .hostname = hostname});
                return out;
            };
        deps.snapshot_fn = [this] {
            ++snapshot_reads;
            return snapshot;
        };
        deps.now_fn = [] { return kNow; };
        if (wire_reads) {
            auto& r = deps.reads;
            r.hosts = [this](const software_hosts::HostsQuery& q)
                -> std::optional<std::vector<SoftwareHostRow>> {
                ++host_reads;
                if (reads_degrade)
                    return std::nullopt;
                std::vector<SoftwareHostRow> out;
                for (const auto& h : hosts) { // fixture rows are kept sorted by agent_id
                    if (q.agent_ids && std::ranges::find(*q.agent_ids, h.agent_id) == q.agent_ids->end())
                        continue;
                    if (h.agent_id <= q.after)
                        continue;
                    if (q.last_synced_before > 0 && h.last_seen >= q.last_synced_before)
                        continue;
                    if (out.size() >= static_cast<std::size_t>(q.limit))
                        break;
                    out.push_back(h);
                }
                return out;
            };
            r.changes = [this](const software_changes::ChangesQuery& q)
                -> std::optional<std::vector<SoftwareChangeRow>> {
                ++change_reads;
                if (reads_degrade)
                    return std::nullopt;
                std::vector<SoftwareChangeRow> eligible;
                for (const auto& c : changes) {
                    if (q.agent_ids && std::ranges::find(*q.agent_ids, c.agent_id) == q.agent_ids->end())
                        continue;
                    if (!q.agent_id.empty() && c.agent_id != q.agent_id)
                        continue;
                    if (!q.kind.empty() && c.kind != q.kind)
                        continue;
                    if (c.observed_at < q.since || c.observed_at >= q.stable_before)
                        continue;
                    if (std::tie(c.observed_at, c.change_id) <=
                        std::tie(q.after.observed_at, q.after.change_id))
                        continue;
                    eligible.push_back(c);
                }
                std::ranges::sort(eligible, {}, [](const SoftwareChangeRow& c) {
                    return std::tie(c.observed_at, c.change_id);
                });
                if (eligible.size() > static_cast<std::size_t>(q.limit))
                    eligible.resize(static_cast<std::size_t>(q.limit));
                return eligible;
            };
            r.installs = [this](const SoftwareFleetQuery& q)
                -> std::optional<std::vector<SoftwareFleetRow>> {
                ++install_reads;
                last_install_agent = q.agent_id;
                if (reads_degrade)
                    return std::nullopt;
                std::vector<SoftwareFleetRow> out;
                for (const auto& i : installs) {
                    if (!q.agent_id.empty() && i.agent_id != q.agent_id)
                        continue;
                    if (q.agent_ids && std::ranges::find(*q.agent_ids, i.agent_id) == q.agent_ids->end())
                        continue;
                    if (q.after && i.install_id <= q.after->install_id)
                        continue;
                    if (out.size() >= static_cast<std::size_t>(q.limit))
                        break;
                    out.push_back(i);
                }
                return out;
            };
            r.last_seen = [](const std::vector<std::string>& ids)
                -> std::optional<std::unordered_map<std::string, std::int64_t>> {
                std::unordered_map<std::string, std::int64_t> m;
                for (const auto& id : ids)
                    m[id] = 1'699'000'000;
                return m;
            };
            r.facet_health = [this](const std::optional<std::vector<std::string>>& ids)
                -> std::optional<std::vector<FacetHealth>> {
                ++aggregate_reads;
                last_aggregate_ids = ids;
                if (reads_degrade)
                    return std::nullopt;
                return live_facets;
            };
            r.summary = [this](std::int64_t, const std::optional<std::vector<std::string>>& ids)
                -> std::optional<SoftwareSummary> {
                ++aggregate_reads;
                last_aggregate_ids = ids;
                if (reads_degrade)
                    return std::nullopt;
                return live_summary;
            };
            r.catalog_meta = [this]() -> std::optional<CatalogRollupMeta> {
                if (reads_degrade)
                    return std::nullopt;
                return catalog;
            };
        }
        routes.register_routes(sink, std::move(deps));
    }

    std::size_t total_reads() const {
        return static_cast<std::size_t>(host_reads + change_reads + install_reads + aggregate_reads +
                                        snapshot_reads);
    }
    std::size_t audits(const std::string& action, const std::string& result) const {
        return static_cast<std::size_t>(std::ranges::count_if(audit_log, [&](const AuditRecord& a) {
            return a.action == action && a.result == result;
        }));
    }
};

json body_of(const httplib::Response& res) {
    return json::parse(res.body);
}

// The body with this response's correlation id masked: the only per-request difference between two
// 404s that must be byte-identical.
std::string masked_body(const httplib::Response& res) {
    std::string b = res.body;
    const auto cid = res.get_header_value("X-Correlation-Id");
    for (auto at = b.find(cid); !cid.empty() && at != std::string::npos; at = b.find(cid, at))
        b.replace(at, cid.size(), "CID");
    return b;
}

std::vector<std::string> ids_of(const json& arr, const char* key = "agent_id") {
    std::vector<std::string> out;
    for (const auto& e : arr)
        out.push_back(e.at(key).get<std::string>());
    return out;
}

const char* const kAllPaths[] = {
    "/api/v1/inventory/software/hosts",       "/api/v1/inventory/software/hosts/a1",
    "/api/v1/inventory/software/changes",     "/api/v1/inventory/software/summary",
    "/api/v1/inventory/software/plugin-health",
};

} // namespace

TEST_CASE("software read routes: the gate answers first and nothing is read",
          "[software][routes][software_read_routes]") {
    Harness h;
    h.hosts = {host_row("a1")};
    SECTION("a denied caller gets the gate's own status, no read, no audit") {
        for (const int status : {401, 403, 503}) {
            h.denial_status = status;
            h.admitted = false;
            for (const char* path : kAllPaths) {
                const auto res = h.sink.Get(path);
                REQUIRE(res);
                CHECK(res->status == status);
            }
        }
        CHECK(h.gate_calls == 15);
        CHECK(h.total_reads() == 0);
        CHECK(h.audit_log.empty());
    }
    SECTION("an admitted caller with no store wired is a 503 on every route") {
        Harness none(/*wire_reads=*/false);
        for (const char* path : kAllPaths) {
            const auto res = none.sink.Get(path);
            REQUIRE(res);
            CHECK(res->status == 503);
            CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
        }
        CHECK(none.gate_calls == 5);
        CHECK(none.audit_log.empty());
        none.admitted = false; // the gate still answers ahead of the store check
        CHECK(none.sink.Get(kAllPaths[0])->status == 403);
    }
}

TEST_CASE("software read routes: every response echoes a correlation id",
          "[software][routes][software_read_routes]") {
    Harness h;
    h.hosts = {host_row("a1")};
    h.installs = {install_row("a1", 1)};
    h.live_facets = {facet("software.installed", 1)};
    for (const char* path : kAllPaths) {
        const auto ok = h.sink.Get(path);
        REQUIRE(ok);
        CHECK(ok->status == 200);
        CHECK_FALSE(ok->get_header_value("X-Correlation-Id").empty());
    }
    for (const char* bad : {"/api/v1/inventory/software/hosts?limit=x",
                            "/api/v1/inventory/software/changes?kind=bogus",
                            "/api/v1/inventory/software/hosts/a1?limit=x"}) {
        const auto res = h.sink.Get(bad);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
        CHECK(body_of(*res).at("error").at("correlation_id") ==
              res->get_header_value("X-Correlation-Id"));
    }
}

TEST_CASE("software read routes: the two-segment generic inventory route is not taken",
          "[software][routes][software_read_routes]") {
    Harness h;
    // These belong to GET /api/v1/inventory/{agent}/{plugin} and to the collection-settings routes.
    for (const char* path : {"/api/v1/inventory/agent1/network",
                             "/api/v1/inventory/software/hosts/a1/collection-settings",
                             "/api/v1/inventory/software/collection-settings"}) {
        const auto res = h.sink.Get(path);
        CHECK(res == nullptr);
    }
}

TEST_CASE("hosts: a confined caller sees only its own devices, and a cursor never names another",
          "[software][routes][software_read_routes]") {
    Harness h;
    h.hosts = {host_row("a"), host_row("b"), host_row("c"), host_row("d")};
    h.roster = {{"b", "bravo"}, {"d", "delta"}, {"a", "alpha"}};
    h.scope = scope_of({"b", "d"});

    auto res = h.sink.Get("/api/v1/inventory/software/hosts?limit=1");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto data = body_of(*res).at("data");
    CHECK(ids_of(data.at("hosts")) == std::vector<std::string>{"b"});
    CHECK(data.at("hosts")[0].at("hostname") == "bravo");
    CHECK(data.at("devices_omitted") == 0);
    REQUIRE(data.at("next_cursor").is_string());

    res = h.sink.Get("/api/v1/inventory/software/hosts?limit=1&cursor=" +
                     data.at("next_cursor").get<std::string>());
    REQUIRE(res);
    REQUIRE(res->status == 200);
    data = body_of(*res).at("data");
    CHECK(ids_of(data.at("hosts")) == std::vector<std::string>{"d"});
    CHECK(h.audits("inventory.software.hosts", "success") == 2);
}

TEST_CASE("hosts: q is matched among the caller's own devices, so fleet-wide matches do not refuse it",
          "[software][routes][software_read_routes]") {
    Harness h;
    h.hosts = {host_row("w-mine-1"), host_row("w-mine-2")};
    for (int i = 0; i < 10'005; ++i)
        h.roster["web-" + std::to_string(i)] = "web-" + std::to_string(i);
    h.roster["w-mine-1"] = "web-mine-1";
    h.roster["w-mine-2"] = "web-mine-2";

    h.scope = scope_of({"w-mine-1", "w-mine-2"});
    auto res = h.sink.Get("/api/v1/inventory/software/hosts?q=web");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(ids_of(body_of(*res).at("data").at("hosts")) ==
          std::vector<std::string>{"w-mine-1", "w-mine-2"});

    h.scope = std::nullopt; // the unfiltered caller's own matches exceed the cap
    res = h.sink.Get("/api/v1/inventory/software/hosts?q=web");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(body_of(*res).at("error").at("message") == "search matches too many devices; narrow q");
}

TEST_CASE("hosts: a search with no roster wired is a 503, not an empty answer",
          "[software][routes][software_read_routes]") {
    Harness h(/*wire_reads=*/true, /*wire_roster=*/false);
    h.hosts = {host_row("a1")};
    CHECK(h.sink.Get("/api/v1/inventory/software/hosts?q=a")->status == 503);
    CHECK(h.sink.Get("/api/v1/inventory/software/hosts")->status == 200); // names are just null
}

TEST_CASE("hosts: a search over a roster that could not be read is a 503, never an empty 200",
          "[software][routes][software_read_routes]") {
    Harness h;
    h.hosts = {host_row("a1")};
    h.roster = {{"a1", "alpha"}};
    h.roster_fails = true;

    const auto res = h.sink.Get("/api/v1/inventory/software/hosts?q=alpha");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(body_of(*res).at("error").at("retry_after_ms") == 5000);
    CHECK(h.audits("inventory.software.hosts", "failure") == 1);
    CHECK(h.host_reads == 0); // nothing is read once the scope cannot be resolved

    // Without q the roster only names devices, so the page is still served.
    const auto plain = h.sink.Get("/api/v1/inventory/software/hosts");
    REQUIRE(plain);
    CHECK(plain->status == 200);
    CHECK(body_of(*plain).at("data").at("hosts").size() == 1);
    CHECK(body_of(*plain).at("data").at("hosts")[0].at("hostname").is_null()); // names stay unknown

    // A roster read that works answers the search.
    h.roster_fails = false;
    CHECK(ids_of(body_of(*h.sink.Get("/api/v1/inventory/software/hosts?q=alpha")).at("data").at("hosts")) ==
          std::vector<std::string>{"a1"});
}

TEST_CASE("hosts: a roster cut at the cap is served and flagged, never refused",
          "[software][routes][software_read_routes]") {
    Harness h;
    h.hosts = {host_row("a1"), host_row("a2")};
    h.roster = {{"a1", "alpha"}};

    SECTION("an untruncated roster reports false") {
        const auto res = h.sink.Get("/api/v1/inventory/software/hosts?q=alpha");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        const auto data = body_of(*res).at("data");
        CHECK(data.at("roster_truncated") == false);
        CHECK(data.at("roster_cap") == kOfflineRosterRowCap);
        CHECK(h.audit_log.back().detail.find("roster_truncated") == std::string::npos);
    }
    SECTION("a search over a truncated roster is a 200 with the flag, the cap and an audit marker") {
        h.roster_truncated = true;
        const auto res = h.sink.Get("/api/v1/inventory/software/hosts?q=nomatch");
        REQUIRE(res);
        REQUIRE(res->status == 200); // a miss in a partial roster is not a refusal
        const auto data = body_of(*res).at("data");
        CHECK(data.at("hosts").empty());
        CHECK(data.at("roster_truncated") == true);
        CHECK(data.at("roster_cap") == kOfflineRosterRowCap);
        REQUIRE(h.audits("inventory.software.hosts", "success") == 1);
        CHECK(h.audit_log.back().detail.find(" roster_truncated=1 ") != std::string::npos);

        // Without q the flag is still reported (the names come from the same partial roster).
        const auto plain = h.sink.Get("/api/v1/inventory/software/hosts");
        REQUIRE(plain);
        CHECK(body_of(*plain).at("data").at("roster_truncated") == true);
    }
    SECTION("an unwired or failed roster without q reports false and null names") {
        h.roster_fails = true;
        const auto res = h.sink.Get("/api/v1/inventory/software/hosts");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        CHECK(body_of(*res).at("data").at("roster_truncated") == false);
    }
}

TEST_CASE("host detail: out-of-scope and unknown hosts answer the same 404",
          "[software][routes][software_read_routes]") {
    Harness h;
    h.hosts = {host_row("a1"), host_row("a2")};
    h.installs = {install_row("a1", 1), install_row("a1", 2), install_row("a2", 3)};
    h.scope = scope_of({"a1", "ghost"});

    const auto outside = h.sink.Get("/api/v1/inventory/software/hosts/a2");
    REQUIRE(outside);
    CHECK(outside->status == 404);
    CHECK(h.host_reads == 0); // the out-of-scope arm does no read at all
    CHECK(h.install_reads == 0);
    CHECK(h.audits("inventory.software.host", "denied") == 1);

    const auto unknown = h.sink.Get("/api/v1/inventory/software/hosts/ghost");
    REQUIRE(unknown);
    CHECK(unknown->status == 404);
    CHECK(unknown->get_header_value("Content-Type") == outside->get_header_value("Content-Type"));
    CHECK(masked_body(*unknown) == masked_body(*outside));
}

TEST_CASE("host detail: an in-scope host returns its facets and one pinned installs page",
          "[software][routes][software_read_routes]") {
    Harness h;
    h.hosts = {host_row("a1"), host_row("a2")};
    h.roster = {{"a1", "alpha"}};
    h.installs = {install_row("a1", 1), install_row("a1", 2), install_row("a2", 3)};
    h.installs[0].entry.package_id = "{PID-1}"; // one row with a product code, one without
    h.scope = scope_of({"a1"});

    auto res = h.sink.Get("/api/v1/inventory/software/hosts/a1?limit=1&name=ignored");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto data = body_of(*res).at("data");
    CHECK(data.at("host").at("agent_id") == "a1");
    CHECK(data.at("host").at("hostname") == "alpha");
    CHECK(data.at("host").at("facets")[0].at("row_status") == "current");
    CHECK(ids_of(data.at("software")) == std::vector<std::string>{"a1"});
    CHECK(data.at("count") == 1);
    CHECK(data.at("software")[0].at("package_id") == "{PID-1}");
    CHECK(h.last_install_agent == "a1"); // pinned to the device
    REQUIRE(data.at("next_cursor").is_string());

    res = h.sink.Get("/api/v1/inventory/software/hosts/a1?limit=5&cursor=" +
                     data.at("next_cursor").get<std::string>());
    REQUIRE(res);
    REQUIRE(res->status == 200);
    data = body_of(*res).at("data");
    CHECK(data.at("software")[0].at("version") == "1.2");
    CHECK(data.at("software")[0].at("package_id") == "");
    CHECK(data.at("next_cursor").is_null());

    // An in-scope device with no report is the unknown-host 404.
    h.scope = std::nullopt;
    CHECK(h.sink.Get("/api/v1/inventory/software/hosts/nobody")->status == 404);
}

TEST_CASE("changes: a confined feed, the settle window, and a late lower id is never dropped",
          "[software][routes][software_read_routes]") {
    Harness h;
    const std::int64_t stable = kNow - software_changes::kSettleSecs;
    h.changes = {change_row(9, "b", 90),           // higher id, earlier observation
                 change_row(5, "b", 100),          // LOWER id, stamped later: must follow, not vanish
                 change_row(7, "a", 95),           // another device
                 change_row(11, "b", stable),      // exactly at the cutoff: still settling
                 change_row(12, "b", kNow - 5)};   // younger than the window
    h.scope = scope_of({"b"});

    auto res = h.sink.Get("/api/v1/inventory/software/changes?limit=1");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto data = body_of(*res).at("data");
    CHECK(data.at("stable_before") == stable);
    CHECK(data.at("changes")[0].at("change_id") == 9);
    REQUIRE(data.at("next_cursor").is_string());
    CHECK(data.at("next_cursor").get<std::string>().starts_with("g1:"));

    res = h.sink.Get("/api/v1/inventory/software/changes?limit=1&cursor=" +
                     data.at("next_cursor").get<std::string>());
    REQUIRE(res);
    data = body_of(*res).at("data");
    REQUIRE(data.at("changes").size() == 1);
    CHECK(data.at("changes")[0].at("change_id") == 5); // the lower id on the following page
    CHECK(data.at("changes")[0].at("agent_id") == "b");

    // The cursor of the last page carries nothing younger than the window, and device "a" never shows.
    res = h.sink.Get("/api/v1/inventory/software/changes?limit=1000");
    data = body_of(*res).at("data");
    CHECK(data.at("changes").size() == 2);
    CHECK(data.at("next_cursor").is_null());
}

TEST_CASE("changes: an agent_id outside the scope is an empty page and a denied audit row",
          "[software][routes][software_read_routes]") {
    Harness h;
    h.changes = {change_row(1, "a", 10), change_row(2, "b", 10)};
    h.scope = scope_of({"b"});
    const auto res = h.sink.Get("/api/v1/inventory/software/changes?agent_id=a");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(body_of(*res).at("data").at("changes").empty());
    CHECK(h.audits("inventory.software.changes", "denied") == 1);
}

TEST_CASE("changes: the audit target is one line, and a hostile agent_id cannot add fields to it",
          "[software][routes][software_read_routes]") {
    Harness h;
    h.changes = {change_row(1, "b", 10)};
    const auto targets = [&](const std::string& result) {
        std::vector<std::string> out;
        for (const auto& a : h.audit_log)
            if (a.action == "inventory.software.changes" && a.result == result)
                out.push_back(a.target_id);
        return out;
    };
    const std::string one{"changes:agent=x_kind_remove"}; // log_token folds the LF and '='
    const std::string hostile = "/api/v1/inventory/software/changes?agent_id=x%0Akind%3Dremove";
    auto res = h.sink.Get(hostile); // served (unfiltered caller)
    REQUIRE(res);
    CHECK(targets("success") == std::vector<std::string>{one});
    h.audit_log.clear();
    h.scope = scope_of({"b"}); // denied: the same single-line target on both rows
    res = h.sink.Get(hostile);
    REQUIRE(res);
    CHECK(targets("denied") == std::vector<std::string>{one});
    CHECK(targets("success") == std::vector<std::string>{one});
    h.audit_log.clear(); // the grammar: fleet, then ;kind and ;since only when set
    h.scope.reset();
    REQUIRE(h.sink.Get("/api/v1/inventory/software/changes"));
    REQUIRE(h.sink.Get("/api/v1/inventory/software/changes?agent_id=b&kind=install&since=5"));
    CHECK(targets("success") ==
          std::vector<std::string>{"changes:fleet", "changes:agent=b;kind=install;since=5"});
}

TEST_CASE("a blank roster hostname reads as unknown on the change feed and plugin-health slowest[]",
          "[software][routes][software_read_routes]") {
    Harness h;
    h.roster = {{"b", ""}, {"a1", ""}}; // endpoints.hostname defaults to ''
    h.changes = {change_row(1, "b", 10)};
    auto snap = std::make_shared<SoftwareFleetSnapshot>();
    snap->facets = {facet("software.installed", 1)}; // slowest names a1
    snap->as_of = kNow - 600;
    h.snapshot = snap;

    const auto feed = h.sink.Get("/api/v1/inventory/software/changes");
    REQUIRE(feed);
    REQUIRE(feed->status == 200);
    const auto rows = body_of(*feed).at("data").at("changes");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].at("hostname").is_null());

    const auto health = h.sink.Get("/api/v1/inventory/software/plugin-health");
    REQUIRE(health);
    REQUIRE(health->status == 200);
    CHECK(body_of(*health).at("data").at("facets")[0].at("slowest")[0].at("hostname").is_null());
}

TEST_CASE("parse and cursor refusals are 400s through the A4 envelope, before any read",
          "[software][routes][software_read_routes]") {
    Harness h;
    for (const char* bad : {"/api/v1/inventory/software/hosts?last_synced_before=abc",
                            "/api/v1/inventory/software/hosts?cursor=nonsense",
                            "/api/v1/inventory/software/changes?kind=bogus",
                            "/api/v1/inventory/software/changes?since=-1",
                            "/api/v1/inventory/software/changes?cursor=nonsense"}) {
        const auto res = h.sink.Get(bad);
        REQUIRE(res);
        CHECK(res->status == 400);
        CHECK(body_of(*res).at("error").at("code") == 400);
    }
    CHECK(h.host_reads == 0);
    CHECK(h.change_reads == 0);
}

TEST_CASE("a degraded read is a 503 with a retry hint and a failure audit row",
          "[software][routes][software_read_routes]") {
    Harness h;
    h.hosts = {host_row("a1")};
    h.reads_degrade = true;
    for (const char* path : {"/api/v1/inventory/software/hosts", "/api/v1/inventory/software/hosts/a1",
                             "/api/v1/inventory/software/changes", "/api/v1/inventory/software/summary"}) {
        const auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(body_of(*res).at("error").at("retry_after_ms") == 5000);
    }
    CHECK(h.audits("inventory.software.hosts", "failure") == 1);
    CHECK(h.audits("inventory.software.changes", "failure") == 1);
}

TEST_CASE("a throwing or failing audit sink never turns a served read into an error",
          "[software][routes][software_read_routes]") {
    Harness h;
    h.hosts = {host_row("a1")};
    h.audit_throws = true;
    auto res = h.sink.Get("/api/v1/inventory/software/hosts");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(body_of(*res).at("data").at("audit_persisted") == false);
    CHECK(body_of(*res).at("data").at("hosts").size() == 1);

    h.audit_throws = false;
    h.audit_persists = false;
    res = h.sink.Get("/api/v1/inventory/software/hosts");
    CHECK(res->status == 200);
    CHECK(body_of(*res).at("data").at("audit_persisted") == false);

    h.audit_persists = true;
    res = h.sink.Get("/api/v1/inventory/software/hosts");
    CHECK_FALSE(body_of(*res).at("data").contains("audit_persisted"));
}

TEST_CASE("summary: the fleet snapshot is for a global caller only",
          "[software][routes][software_read_routes]") {
    Harness h;
    h.catalog.refreshed_at = kNow - 100;
    h.catalog.total_titles = 7;
    h.catalog.total_installs = 70;
    h.catalog.total_devices = 9;
    auto snap = std::make_shared<SoftwareFleetSnapshot>();
    snap->summary.devices_reporting = 1000;
    snap->summary.devices_stale = 10;
    snap->summary.changes_24h.install = 5;
    snap->as_of = kNow - 600;
    h.live_summary.devices_reporting = 2;
    h.live_summary.devices_stale = 1;

    SECTION("before the first refresh a global caller is told it is building, not shown zeros") {
        const auto res = h.sink.Get("/api/v1/inventory/software/summary");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        const auto data = body_of(*res).at("data");
        CHECK(data.at("omitted") == "building");
        CHECK(data.at("devices").is_null());
        CHECK(data.at("changes").is_null());
        CHECK(h.aggregate_reads == 0);
    }
    SECTION("a global caller is served the snapshot with its as_of") {
        h.snapshot = snap;
        const auto res = h.sink.Get("/api/v1/inventory/software/summary");
        REQUIRE(res);
        const auto data = body_of(*res).at("data");
        CHECK(data.at("devices").at("reporting") == 1000);
        CHECK(data.at("changes").at("last_24h").at("install") == 5);
        CHECK(data.at("catalogue").at("titles") == 7);
        CHECK(data.at("as_of") == kNow - 600);
        CHECK(data.at("omitted").is_null());
        CHECK(h.aggregate_reads == 0); // no live read for the fleet caller
    }
    SECTION("a confined caller gets a live aggregate over its scope and never the snapshot") {
        h.snapshot = snap;
        h.scope = scope_of({"a1", "a2"});
        const auto res = h.sink.Get("/api/v1/inventory/software/summary");
        REQUIRE(res);
        const auto data = body_of(*res).at("data");
        CHECK(data.at("devices").at("reporting") == 2);
        CHECK(data.at("catalogue").is_null());
        CHECK(data.at("omitted") == "scope");
        CHECK(data.at("as_of") == kNow);
        CHECK(h.snapshot_reads == 0);
        REQUIRE(h.last_aggregate_ids);
        CHECK(std::unordered_set<std::string>(h.last_aggregate_ids->begin(), h.last_aggregate_ids->end()) ==
              std::unordered_set<std::string>{"a1", "a2"});
    }
    SECTION("a scope above the push-down cap gets nulls with omitted=scope and no read") {
        h.snapshot = snap;
        std::unordered_set<std::string> wide;
        for (std::size_t i = 0; i <= software_catalogue::kScopePushdownMaxIds; ++i)
            wide.insert("d" + std::to_string(i));
        h.scope = std::move(wide);
        const auto res = h.sink.Get("/api/v1/inventory/software/summary");
        REQUIRE(res);
        const auto data = body_of(*res).at("data");
        CHECK(data.at("devices").is_null());
        CHECK(data.at("changes").is_null());
        CHECK(data.at("catalogue").is_null());
        CHECK(data.at("omitted") == "scope");
        CHECK(h.aggregate_reads == 0);
        CHECK(h.snapshot_reads == 0);
    }
}

TEST_CASE("plugin-health: the fleet snapshot is for a global caller only",
          "[software][routes][software_read_routes]") {
    Harness h;
    h.roster = {{"a1", "alpha"}};
    auto snap = std::make_shared<SoftwareFleetSnapshot>();
    snap->facets = {facet("software.installed", 1000)};
    snap->as_of = kNow - 600;
    h.live_facets = {facet("software.installed", 2)};

    SECTION("before the first refresh the facets are null with omitted=building") {
        const auto data = body_of(*h.sink.Get("/api/v1/inventory/software/plugin-health")).at("data");
        CHECK(data.at("facets").is_null());
        CHECK(data.at("omitted") == "building");
    }
    SECTION("a global caller is served the snapshot, hostnames resolved from the roster") {
        h.snapshot = snap;
        const auto data = body_of(*h.sink.Get("/api/v1/inventory/software/plugin-health")).at("data");
        REQUIRE(data.at("facets").size() == 1);
        CHECK(data.at("facets")[0].at("devices").at("full") == 1000);
        CHECK(data.at("facets")[0].at("slowest")[0].at("hostname") == "alpha");
        CHECK(data.at("as_of") == kNow - 600);
        CHECK(data.at("omitted").is_null());
        CHECK(h.aggregate_reads == 0);
    }
    SECTION("a confined caller gets a live read with its scope pushed down") {
        h.snapshot = snap;
        h.scope = scope_of({"a1"});
        const auto data = body_of(*h.sink.Get("/api/v1/inventory/software/plugin-health")).at("data");
        CHECK(data.at("facets")[0].at("devices").at("full") == 2);
        CHECK(data.at("omitted").is_null());
        CHECK(h.snapshot_reads == 0);
        REQUIRE(h.last_aggregate_ids);
        CHECK(*h.last_aggregate_ids == std::vector<std::string>{"a1"});
    }
    SECTION("a scope above the push-down cap gets null facets with omitted=scope") {
        h.snapshot = snap;
        std::unordered_set<std::string> wide;
        for (std::size_t i = 0; i <= software_catalogue::kScopePushdownMaxIds; ++i)
            wide.insert("d" + std::to_string(i));
        h.scope = std::move(wide);
        const auto data = body_of(*h.sink.Get("/api/v1/inventory/software/plugin-health")).at("data");
        CHECK(data.at("facets").is_null());
        CHECK(data.at("omitted") == "scope");
        CHECK(h.aggregate_reads == 0);
        CHECK(h.snapshot_reads == 0);
    }
}

TEST_CASE("SoftwareFleetSnapshotHolder: a published snapshot replaces the last, readers keep theirs",
          "[software][routes][software_read_routes]") {
    SoftwareFleetSnapshotHolder holder;
    CHECK(holder.get() == nullptr);
    auto first = std::make_shared<SoftwareFleetSnapshot>();
    first->as_of = 1;
    holder.publish(first);
    const auto held = holder.get();
    auto second = std::make_shared<SoftwareFleetSnapshot>();
    second->as_of = 2;
    holder.publish(second);
    CHECK(holder.get()->as_of == 2);
    CHECK(held->as_of == 1);
}
