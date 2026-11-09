// test_rest_software_components.cpp - HTTP-level tests for the SAM-17 components lookup
//   GET /api/v1/inventory/software/components
//
// In-process TestRouteSink (no socket). The fleet-read gate is faked per test exactly as in
// test_rest_inventory_software.cpp: scope nullopt is the unfiltered (AdmitAll) caller, an engaged
// scope a confined one. The pins: the gate decides everything (denied -> no store read), the scope
// confines every row, `totals` is served only to the unfiltered caller for an exact name and is
// null+totals_omitted otherwise, a degraded read is a 503 and never an empty 200, and the export
// streams past one page with a continuation.

#include "rest_api_v1.hpp"
#include "authz_gates.hpp"
#include "inventory_blob_v3.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "software_inventory_store.hpp"
#include "software_list_model.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <expected>
#include <algorithm>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

yuzu::test::PgTestTemplate swinv_tpl{"swinv", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    SoftwareInventoryStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("swinv template: store failed to migrate");
}};

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_id;
    std::string detail;
};

struct CompHarness {
    yuzu::MetricsRegistry metrics;
    RestApiV1 api; // the route owner is declared BEFORE the sink that holds handlers capturing it
    yuzu::server::test::TestRouteSink sink;
    bool fleet_admitted{true};
    std::optional<std::unordered_set<std::string>> fleet_scope; // nullopt = unfiltered (AdmitAll)
    std::vector<AuditRecord> audit_log;
    int gate_calls{0};
    // The device table's roster the hostname field reads: agent_id -> hostname, one read per page.
    std::unordered_map<std::string, std::string> hostnames;
    int hostname_reads{0};

    explicit CompHarness(SoftwareInventoryStore* store, bool wire_fleet_read_fn = true) {
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "admin";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_id, detail});
            return true;
        };
        RestApiV1::FleetReadFn fleet_read_fn;
        if (wire_fleet_read_fn) {
            fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                   const std::string&,
                                   const std::string&) -> authz::FleetReadGate {
                ++gate_calls;
                if (!fleet_admitted) {
                    res.status = 403;
                    res.set_content(R"({"error":{"message":"permission denied"}})",
                                    "application/json");
                    return {};
                }
                return {true, fleet_scope};
            };
        }
        api.set_hostnames_fn([this]() -> std::unordered_map<std::string, std::string> {
            ++hostname_reads;
            return hostnames;
        });
        api.register_routes(
            sink, auth_fn, perm_fn, audit_fn,
            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr,
            /*token_store=*/nullptr, /*quarantine_store=*/nullptr,
            /*response_store=*/nullptr, /*instruction_store=*/nullptr,
            /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr,
            /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
            /*audit_store=*/nullptr, /*service_group_fn=*/{}, /*tag_push_fn=*/{},
            /*inventory_store=*/nullptr, /*product_pack_store=*/nullptr,
            /*sw_deploy_store=*/nullptr, /*device_token_store=*/nullptr,
            /*license_store=*/nullptr, /*guaranteed_state_store=*/nullptr,
            /*metrics_registry=*/&metrics, /*session_revoke_fn=*/{},
            /*execution_event_bus=*/nullptr, /*result_set_store=*/nullptr,
            /*command_dispatch_fn=*/{}, /*step_up_fn=*/{}, /*guardian_push_fn=*/{},
            /*dex_perf_fn=*/{}, /*network_api=*/{}, /*lockout_clear_fn=*/{},
            /*baseline_store=*/nullptr, /*scoped_perm_fn=*/{}, store,
            /*response_scope_fn=*/{},
            /*engine_principal_store=*/nullptr, /*access_review_store=*/nullptr,
            /*auth_db=*/nullptr, /*directory_sync=*/nullptr, /*stream_budget=*/nullptr,
            /*exec_visible_fn=*/{}, /*list_read_fn=*/{}, std::move(fleet_read_fn),
            /*agents_fn=*/{}, /*response_visible_set_fn=*/{}, /*verify_api=*/{},
            /*device_api=*/{}, /*dex_api=*/{});
    }

    std::size_t audits(const std::string& action, const std::string& result,
                       const std::string& needle = {}) const {
        std::size_t n = 0;
        for (const auto& a : audit_log)
            if (a.action == action && a.result == result &&
                (needle.empty() || a.detail.find(needle) != std::string::npos))
                ++n;
        return n;
    }
};

constexpr const char* kPath = "/api/v1/inventory/software/components";
constexpr const char* kFacet = "component_inventory";

V3Component comp(const std::string& name, const std::string& path, const std::string& version,
                 const std::string& kind = "jar") {
    V3Component k;
    k.kind = kind;
    k.name = name;
    k.version = version;
    k.version_source = "manifest";
    k.path = path;
    k.size = 10;
    k.mtime = 100;
    k.anchor_app = "AcmeApp";
    return k;
}

V3Section comp_section(V3Status status, std::vector<V3Component> rows = {}) {
    V3Section s;
    s.facet = kFacet;
    s.status = status;
    s.components = std::move(rows);
    s.duration_ms = 1;
    s.bytes_read = 1;
    return s;
}

// One agent's full component set, through the store's own v3 apply path.
void seed_components(SoftwareInventoryStore& store, const std::string& agent,
                     std::vector<V3Component> rows) {
    V3Report rep;
    rep.sections.push_back(comp_section(V3Status::kFull, std::move(rows)));
    const auto out = store.apply_installed_software_v3(agent, std::move(rep));
    REQUIRE(out.size() == 1);
    REQUIRE(out[0].outcome == V3SectionOutcome::kStored);
}

// A status-only section: the facet state moves, the rows are untouched.
void set_facet_status(SoftwareInventoryStore& store, const std::string& agent, V3Status status) {
    V3Report rep;
    rep.sections.push_back(comp_section(status));
    const auto out = store.apply_installed_software_v3(agent, std::move(rep));
    REQUIRE(out.size() == 1);
    REQUIRE(out[0].outcome == V3SectionOutcome::kStatusOnly);
}

nlohmann::json get_json(CompHarness& h, const std::string& query, int expect_status = 200) {
    auto res = h.sink.Get(std::string(kPath) + query);
    REQUIRE(res);
    CHECK(res->status == expect_status);
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    return nlohmann::json::parse(res->body, nullptr, false);
}

// "<agent>|<path>" of every row of a page: the exact set a predicate selected.
std::set<std::string> row_keys(const nlohmann::json& body) {
    std::set<std::string> out;
    for (const auto& r : body.at("data").at("components"))
        out.insert(r.at("agent_id").get<std::string>() + "|" + r.at("path").get<std::string>());
    return out;
}

} // namespace

// ── No-PG branches ───────────────────────────────────────────────────────────

TEST_CASE("REST components: null store -> 503 with the A4 envelope, never an empty 200",
          "[rest][inventory_components]") {
    CompHarness h{/*store=*/nullptr};
    auto res = h.sink.Get(kPath);
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body.contains("error"));
    CHECK_FALSE(body.contains("data"));
}

TEST_CASE("REST components: unwired fleet_read_fn -> 503, never a fallback admit",
          "[rest][inventory_components][security]") {
    CompHarness h{/*store=*/nullptr, /*wire_fleet_read_fn=*/false};
    auto res = h.sink.Get(kPath);
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
}

TEST_CASE("REST components: gate denied -> 403, no store read, no audit row",
          "[rest][inventory_components][security]") {
    CompHarness h{/*store=*/nullptr};
    h.fleet_admitted = false;
    auto res = h.sink.Get(std::string(kPath) + "?name=libfoo");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.gate_calls == 1);
    CHECK(h.audit_log.empty()); // the store was never consulted
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK_FALSE(body.contains("data"));
}

TEST_CASE("REST components: the path and its typed body are in the OpenAPI spec",
          "[rest][inventory_components]") {
    CompHarness h{/*store=*/nullptr};
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    auto spec = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(spec.is_discarded());
    REQUIRE(spec["paths"].contains("/inventory/software/components"));
    const auto& get = spec["paths"]["/inventory/software/components"]["get"];
    CHECK(get["operationId"] == "getInventorySoftwareComponents");
    const auto& data = get["responses"]["200"]["content"]["application/json"]["schema"]
                           ["properties"]["data"];
    for (const char* k : {"components", "count", "next_cursor", "devices_omitted", "totals",
                          "totals_omitted"})
        CHECK(data["properties"].contains(k));
    const auto& totals = data["properties"]["totals"];
    CHECK(totals["nullable"] == true);
    for (const char* k : {"instances", "devices", "devices_unconfirmed", "as_of"})
        CHECK(totals["properties"].contains(k));
}

// ── PG-backed ────────────────────────────────────────────────────────────────

TEST_CASE("REST components: rows carry hostname, last_seen, status and component_last_confirmed_at",
          "[pg][rest][inventory_components]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_components(store, "dev-a", {comp("libfoo", "/opt/a/libfoo.jar", "1.0")});

    CompHarness h{&store};
    h.hostnames["dev-a"] = "host-a";
    h.hostnames["dev-elsewhere"] = "host-elsewhere"; // on the roster, not on this page
    const auto body = get_json(h, "?name=libfoo");
    const auto& rows = body.at("data").at("components");
    REQUIRE(rows.size() == 1);
    CHECK(h.hostname_reads == 1); // one roster read per page
    CHECK(rows[0]["agent_id"] == "dev-a");
    CHECK(rows[0]["hostname"] == "host-a");
    CHECK(rows[0]["status"] == "current");
    CHECK(rows[0]["component_last_confirmed_at"].is_number()); // the full section confirmed it
    CHECK_FALSE(rows[0].contains("last_confirmed_at")); // the installs route's name, not this one's
    CHECK(rows[0]["kind"] == "jar");
    CHECK(rows[0]["name"] == "libfoo");
    CHECK(rows[0]["version"] == "1.0");
    CHECK(rows[0]["version_source"] == "manifest");
    CHECK(rows[0]["path"] == "/opt/a/libfoo.jar");
    CHECK(rows[0]["anchor_app"] == "AcmeApp");
    CHECK(rows[0]["first_seen"].is_number());
    // The v3 apply path stamps the device's installed_software poll, and the row reports exactly
    // the store's own figure for it.
    const auto seen = store.source_last_seen_bulk("installed_software", {"dev-a"});
    REQUIRE(seen.has_value());
    REQUIRE(seen->contains("dev-a"));
    CHECK(rows[0]["last_seen"].is_number());
    CHECK(rows[0]["last_seen"].get<std::int64_t>() == seen->at("dev-a"));
    CHECK(h.audits("inventory.components.view", "success", "rows=1") == 1);
    // The audit target names the component lookup.
    REQUIRE_FALSE(h.audit_log.empty());
    CHECK(h.audit_log.front().target_id == "components:name=libfoo");
}

TEST_CASE("REST components: the CSV export carries all 12 cells of a row and a full-width truncation trailer",
          "[pg][rest][inventory_components][export]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_components(store, "dev-a",
                    {comp("libfoo", "/opt/a/libfoo.jar", "1.0"), comp("libfoo", "/opt/b/libfoo.jar", "1.0")});

    CompHarness h{&store};
    h.hostnames["dev-a"] = "host-a";
    auto whole = h.sink.Get(std::string(kPath) + "?format=csv");
    REQUIRE(whole);
    REQUIRE(whole->status == 200);
    CHECK(whole->body.starts_with(std::string(software_list::kComponentsCsvHeader) + "\n"));
    const auto first_nl = whole->body.find('\n');
    const auto second_nl = whole->body.find('\n', first_nl + 1);
    REQUIRE(second_nl != std::string::npos);
    const std::string record = whole->body.substr(first_nl + 1, second_nl - first_nl - 1);
    std::vector<std::string> cells;
    for (std::size_t from = 0;;) {
        const auto comma = record.find(',', from);
        cells.push_back(record.substr(from, comma == std::string::npos ? comma : comma - from));
        if (comma == std::string::npos)
            break;
        from = comma + 1;
    }
    REQUIRE(cells.size() == software_list::kComponentsCsvColumns);
    CHECK(cells[0] == "dev-a");
    CHECK(cells[1] == "host-a");
    for (std::size_t i = 0; i < cells.size(); ++i) {
        CAPTURE(i);
        CHECK_FALSE(cells[i].empty()); // every value of this fully-populated row is present
    }
    CHECK(cells[3] == "jar");
    CHECK(cells[4] == "libfoo");
    CHECK(cells[6] == "manifest");
    CHECK(cells[10] == "current");

    // A capped page ends with a trailer record as wide as the header.
    auto cut = h.sink.Get(std::string(kPath) + "?format=csv&limit=1");
    REQUIRE(cut);
    CHECK(cut->get_header_value("X-Result-Truncated-By-Cap") == "true");
    CHECK(cut->body.ends_with("# result_truncated_by_cap cause=row_cap" +
                              std::string(software_list::kComponentsCsvColumns - 1, ',') +
                              "\r\n"));
}

TEST_CASE("REST components: q, kind, name, agent_id and status predicates each select an exact row set",
          "[pg][rest][inventory_components]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    auto widget = comp("zzz", "/srv/special/zzz", "3.0");
    widget.anchor_app = "WidgetSuite";
    auto bar = comp("libbar", "/usr/lib/libbar.so", "1.0", "so");
    bar.anchor_app = "OtherApp";
    seed_components(store, "dev-a", {comp("libfoo", "/opt/a/libfoo.jar", "1.0"), bar});
    seed_components(store, "dev-b", {comp("libfoo", "/opt/b/libfoo.jar", "1.0"), widget});
    seed_components(store, "dev-c", {comp("libfoo", "/lib/libfoo.so", "1.0", "so")});
    set_facet_status(store, "dev-c", V3Status::kDisabled);

    CompHarness h{&store};
    const std::set<std::string> everything{"dev-a|/opt/a/libfoo.jar", "dev-a|/usr/lib/libbar.so",
                                           "dev-b|/opt/b/libfoo.jar", "dev-b|/srv/special/zzz",
                                           "dev-c|/lib/libfoo.so"};
    CHECK(row_keys(get_json(h, "")) == everything); // the default page includes the disabled row
    CHECK(row_keys(get_json(h, "?q=special")) ==
          std::set<std::string>{"dev-b|/srv/special/zzz"}); // path
    CHECK(row_keys(get_json(h, "?q=widgetsuite")) ==
          std::set<std::string>{"dev-b|/srv/special/zzz"}); // anchor_app, case-insensitive
    CHECK(row_keys(get_json(h, "?q=libbar")) ==
          std::set<std::string>{"dev-a|/usr/lib/libbar.so"}); // name
    CHECK(row_keys(get_json(h, "?kind=so")) ==
          std::set<std::string>{"dev-a|/usr/lib/libbar.so", "dev-c|/lib/libfoo.so"});
    CHECK(row_keys(get_json(h, "?name=libfoo&kind=jar")) ==
          std::set<std::string>{"dev-a|/opt/a/libfoo.jar", "dev-b|/opt/b/libfoo.jar"});
    CHECK(row_keys(get_json(h, "?agent_id=dev-a")) ==
          std::set<std::string>{"dev-a|/opt/a/libfoo.jar", "dev-a|/usr/lib/libbar.so"});
    CHECK(row_keys(get_json(h, "?status=disabled")) ==
          std::set<std::string>{"dev-c|/lib/libfoo.so"});
}

TEST_CASE("REST components: the scope confines every row and an out-of-scope agent_id is denied",
          "[pg][rest][inventory_components][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_components(store, "dev-a", {comp("libfoo", "/a", "1.0")});
    seed_components(store, "dev-b", {comp("libfoo", "/b", "1.0")});
    seed_components(store, "dev-c", {comp("libfoo", "/c", "1.0")});

    CompHarness h{&store};
    h.fleet_scope = std::unordered_set<std::string>{"dev-a", "dev-c"};
    const auto body = get_json(h, "?name=libfoo");
    std::unordered_set<std::string> seen;
    for (const auto& r : body.at("data").at("components"))
        seen.insert(r.at("agent_id").get<std::string>());
    CHECK(seen == std::unordered_set<std::string>{"dev-a", "dev-c"}); // dev-b never appears
    CHECK(body.at("data").at("devices_omitted") == 0);

    // A named agent outside the scope: an empty page plus a denied audit row, no oracle.
    const auto denied = get_json(h, "?name=libfoo&agent_id=dev-b");
    CHECK(denied.at("data").at("components").empty());
    CHECK(h.audits("inventory.components.view", "denied") == 1);
}

TEST_CASE("REST components: a confined caller gets rows and NO totals; the same request unfiltered gets totals",
          "[pg][rest][inventory_components][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    // The component is installed only OUTSIDE the confined caller's scope.
    seed_components(store, "dev-out", {comp("libfoo", "/o", "1.0")});
    seed_components(store, "dev-in", {comp("other", "/i", "1.0")});
    REQUIRE(store.refresh_component_rollup());

    CompHarness h{&store};
    h.fleet_scope = std::unordered_set<std::string>{"dev-in"};
    const auto confined = get_json(h, "?name=libfoo&kind=jar");
    CHECK(confined.at("data").at("components").empty());
    CHECK(confined.at("data").at("totals").is_null()); // no fleet count leaks
    CHECK(confined.at("data").at("totals_omitted") == "scope");
    CHECK(confined.dump().find("dev-out") == std::string::npos);

    h.fleet_scope.reset(); // AdmitAll
    const auto global = get_json(h, "?name=libfoo&kind=jar");
    const auto& totals = global.at("data").at("totals");
    REQUIRE(totals.is_object());
    CHECK(totals.at("instances") == 1);
    CHECK(totals.at("devices") == 1);
    CHECK_FALSE(global.at("data").contains("totals_omitted"));
}

TEST_CASE("REST components: unconfirmed rows are included by default; status=current excludes them",
          "[pg][rest][inventory_components]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_components(store, "dev-ok", {comp("libfoo", "/a", "1.0")});
    seed_components(store, "dev-stale", {comp("libfoo", "/b", "1.0")});
    set_facet_status(store, "dev-stale", V3Status::kConstrained);

    CompHarness h{&store};
    const auto all = get_json(h, "?name=libfoo");
    std::unordered_map<std::string, std::string> status;
    for (const auto& r : all.at("data").at("components"))
        status[r.at("agent_id").get<std::string>()] = r.at("status").get<std::string>();
    CHECK(status.size() == 2); // the default filter does not drop unconfirmed rows
    CHECK(status["dev-ok"] == "current");
    CHECK(status["dev-stale"] == "unconfirmed");

    const auto current = get_json(h, "?name=libfoo&status=current");
    REQUIRE(current.at("data").at("components").size() == 1);
    CHECK(current.at("data").at("components")[0]["agent_id"] == "dev-ok");
    // A status filter is not an exact-name lookup: no totals.
    CHECK(current.at("data").at("totals_omitted") == "filters");
}

TEST_CASE("REST components: totals agree with the store after a refresh; building before the first",
          "[pg][rest][inventory_components]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_components(store, "dev-a", {comp("libfoo", "/a1", "1.0"), comp("libfoo", "/a2", "1.0")});
    seed_components(store, "dev-b", {comp("libfoo", "/b", "2.0")});
    set_facet_status(store, "dev-b", V3Status::kTimeout);

    CompHarness h{&store};
    const auto building = get_json(h, "?name=libfoo&kind=jar");
    CHECK(building.at("data").at("totals").is_null());
    CHECK(building.at("data").at("totals_omitted") == "building");

    REQUIRE(store.refresh_component_rollup());
    const auto body = get_json(h, "?name=libfoo&kind=jar");
    const auto& t = body.at("data").at("totals");
    REQUIRE(t.is_object());
    CHECK(t.at("instances") == 3);            // rows
    CHECK(t.at("devices") == 2);              // distinct devices
    CHECK(t.at("devices_unconfirmed") == 1);  // dev-b's facet is not current
    CHECK(t.at("as_of").is_number());
}

TEST_CASE("REST components: a version range resolves and its totals are exact (a device on two versions counts once)",
          "[pg][rest][inventory_components]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_components(store, "dev-a", {comp("libfoo", "/a1", "1.9"), comp("libfoo", "/a2", "1.10")});
    seed_components(store, "dev-b", {comp("libfoo", "/b", "1.10")});
    seed_components(store, "dev-c", {comp("libfoo", "/c", "2.0")});
    REQUIRE(store.refresh_component_rollup());

    CompHarness h{&store};
    const auto body = get_json(h, "?name=libfoo&version_min=1.9&version_max=1.10");
    CHECK(body.at("data").at("components").size() == 3); // dev-c's 2.0 is outside the range
    const auto& t = body.at("data").at("totals");
    REQUIRE(t.is_object());
    CHECK(t.at("instances") == 3);
    CHECK(t.at("devices") == 2); // dev-a holds two versions in the range and counts once
    CHECK(t.at("as_of").is_null()); // a version filter is computed live

    // The resolved set never appears in the response.
    CHECK(body.dump().find("version_min") == std::string::npos);
}

TEST_CASE("REST components: a range sees a version first reported after the last refresh, and works before any refresh",
          "[pg][rest][inventory_components]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_components(store, "dev-a", {comp("libfoo", "/a", "1.0")});

    CompHarness h{&store};
    // Before the first rollup refresh a range is live: rows and totals, never a building 503.
    const auto early = get_json(h, "?name=libfoo&kind=jar&version_max=1.5");
    REQUIRE(early.at("data").at("totals").is_object());
    CHECK(early.at("data").at("totals").at("instances") == 1);
    CHECK(early.at("data").at("totals").at("as_of").is_null());

    REQUIRE(store.refresh_component_rollup());
    seed_components(store, "dev-b", {comp("libfoo", "/b", "2.5")}); // after the refresh
    const auto late = get_json(h, "?name=libfoo&kind=jar&version_min=2.0");
    CHECK(row_keys(late) == std::set<std::string>{"dev-b|/b"});
    const auto& totals = late.at("data").at("totals");
    REQUIRE(totals.is_object());
    CHECK(totals.at("instances") == 1);
    CHECK(totals.at("devices") == 1);
    CHECK(totals.at("as_of").is_null()); // live: the figure is exact, not a rollup epoch
    // And the audit target records the range inputs, not the resolved set.
    REQUIRE_FALSE(h.audit_log.empty());
    CHECK(h.audit_log.back().target_id == "components:name=libfoo;kind=jar;version_min=2.0");
}

TEST_CASE("REST components: a version range without name is a 400; a bare exact version is not",
          "[pg][rest][inventory_components]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    CompHarness h{&store};
    for (const char* q : {"?version_min=1.0", "?version_max=2.0",
                          "?name=lib&match=prefix&version_min=1.0"}) {
        CAPTURE(q);
        auto res = h.sink.Get(std::string(kPath) + q);
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    CHECK(h.audit_log.empty()); // a 400 writes nothing

    // A bare exact version is a plain equality predicate (as on the installs route): it filters
    // the fleet, and a filter on the whole fleet is never a total.
    seed_components(store, "dev-1", {comp("libfoo", "/a", "1.0"), comp("libbar", "/b", "2.0")});
    const auto bare = get_json(h, "?version=1.0");
    REQUIRE(bare.at("data").at("components").size() == 1);
    CHECK(bare.at("data").at("components")[0].at("name") == "libfoo");
    CHECK(bare.at("data").at("totals").is_null());
    CHECK(bare.at("data").at("totals_omitted") == "filters");
}

TEST_CASE("REST components: a closed pool -> 503 with a failure audit row, never an empty 200",
          "[pg][rest][inventory_components]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    CompHarness h{&store};
    auto held = pool.acquire(); // the only lease: every store read times out
    REQUIRE(held);
    auto res = h.sink.Get(std::string(kPath) + "?name=libfoo");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK_FALSE(body.contains("data"));
    CHECK(h.audits("inventory.components.view", "failure") == 1);
    CHECK(h.audits("inventory.components.view", "success") == 0);
}

TEST_CASE("REST components: a range over a component with kCatalogRowCap distinct versions is a 400 and writes no audit row",
          "[pg][rest][inventory_components]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    // One device, one component name, a distinct version (and path) per cap slot: the live
    // distinct-version read comes back exactly full, so it may have been cut and the range cannot
    // be resolved against it.
    std::vector<V3Component> rows;
    rows.reserve(static_cast<std::size_t>(kCatalogRowCap));
    for (int i = 0; i < kCatalogRowCap; ++i)
        rows.push_back(comp("libfoo", "/p/" + std::to_string(i), std::to_string(i)));
    seed_components(store, "dev-a", std::move(rows));

    CompHarness h{&store};
    auto res = h.sink.Get(std::string(kPath) + "?name=libfoo&kind=jar&version_min=1");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    const auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK_FALSE(body.contains("data"));
    CHECK(body.at("error").at("message") == std::string(software_list::kRangeNotResolvable));
    CHECK(h.audit_log.empty()); // a refused request is not a read, so it writes nothing

    // The documented way out: an exact version is a plain equality predicate and still serves.
    const auto exact = get_json(h, "?name=libfoo&kind=jar&version=7");
    CHECK(exact.at("data").at("components").size() == 1);
}

TEST_CASE("REST components: a failed version read for a range is a 503 with retry_after_ms and one failure audit row",
          "[pg][rest][inventory_components]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    // size-1 pool held by the test: the range's distinct-version read is the first store read of
    // the request and times out, so the route must answer 503, never an empty or unresolved 200.
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    auto held = pool.acquire();
    REQUIRE(held);
    CompHarness h{&store};
    auto res = h.sink.Get(std::string(kPath) + "?name=libfoo&kind=jar&version_min=1");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    const auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK_FALSE(body.contains("data"));
    CHECK(body.at("error").at("retry_after_ms") == 5000);
    CHECK(h.audit_log.size() == 1);
    CHECK(h.audits("inventory.components.view", "failure") == 1);
}

TEST_CASE("REST components: a degraded totals read alone is a 503 with retry_after_ms",
          "[pg][rest][inventory_components]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_components(store, "dev-a", {comp("libfoo", "/a", "1.0")});
    REQUIRE(store.refresh_component_rollup());
    { // The page read does not touch the rollup; the totals read does.
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(), "DROP TABLE software_inventory_store.component_rollup",
            std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    CompHarness h{&store};
    auto res = h.sink.Get(std::string(kPath) + "?name=libfoo&kind=jar");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body.contains("error"));
    CHECK(body.dump().find("retry_after_ms") != std::string::npos);
    CHECK(h.audits("inventory.components.view", "failure") == 1);
}

TEST_CASE("REST components: a CSV export walks every page with a continuation",
          "[pg][rest][inventory_components][export]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    // The continuation walk and the exact-multiple-of-the-cap rule below do not depend on the cap's
    // size, and in export mode `limit` IS the per-call cap, so the cap is set to 1000 here and the
    // seed shrinks to 3000 rows over 10 apply calls. The default (kExportCap, 10000) is pinned by
    // the pure parse case in test_software_list_model.cpp, and the shared read_limit's default and
    // ceiling by the devices-params case in test_software_catalogue_model.cpp.
    constexpr int kDevices = 10;
    constexpr int kPerDevice = 300;
    constexpr int kCap = 1000;
    for (int d = 0; d < kDevices; ++d) {
        std::vector<V3Component> rows;
        rows.reserve(kPerDevice);
        for (int i = 0; i < kPerDevice; ++i)
            rows.push_back(comp("lib" + std::to_string(i), "/p/" + std::to_string(i), "1.0"));
        seed_components(store, "dev-" + std::to_string(1000 + d), std::move(rows));
    }

    CompHarness h{&store};
    std::string cursor;
    std::size_t data_rows = 0;
    int pages = 0;
    for (;;) {
        std::string q = "?format=csv&limit=" + std::to_string(kCap);
        if (!cursor.empty())
            q += "&cursor=" + cursor;
        auto res = h.sink.Get(std::string(kPath) + q);
        REQUIRE(res);
        REQUIRE(res->status == 200);
        ++pages;
        REQUIRE(pages <= 5);
        std::size_t lines = 0;
        for (char c : res->body)
            if (c == '\n')
                ++lines;
        REQUIRE(lines >= 1);
        const bool more = res->has_header("X-Next-Cursor");
        if (more) {
            CHECK(res->get_header_value("X-Result-Truncated-By-Cap") == "true");
            --lines; // the in-band trailer record
        }
        data_rows += lines - 1; // minus the header line
        if (!more) {
            CHECK(lines == 1); // the closing page holds the header line only
            break;
        }
        cursor = res->get_header_value("X-Next-Cursor");
    }
    CHECK(data_rows == static_cast<std::size_t>(kDevices) * kPerDevice);
    // A page that comes back full always carries a continuation (the documented count == limit
    // rule, "more rows may exist", shared with the installs route), so a total that is an exact
    // multiple of the cap ends on one more, header-only page: 3 full pages + 1 closing page.
    CHECK(pages == 4);
    CHECK(h.audits("inventory.components.export", "success", "page=continuation") == 3);
    CHECK(h.audits("inventory.components.export", "success") == 4);
}

TEST_CASE("REST components: every JSON page is audited, continuation pages are tagged",
          "[pg][rest][inventory_components]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_components(store, "dev-a",
                    {comp("a", "/1", "1"), comp("b", "/2", "1"), comp("c", "/3", "1")});
    CompHarness h{&store};
    const auto first = get_json(h, "?limit=2");
    REQUIRE(first.at("data").at("next_cursor").is_string());
    const auto second =
        get_json(h, "?limit=2&cursor=" + first.at("data").at("next_cursor").get<std::string>());
    CHECK(second.at("data").at("components").size() == 1);
    CHECK(h.audits("inventory.components.view", "success") == 2);
    CHECK(h.audits("inventory.components.view", "success", "page=continuation") == 1);

    // A cursor minted for another filter set is a 400 and writes no audit row.
    const auto before = h.audit_log.size();
    auto res = h.sink.Get(std::string(kPath) + "?limit=2&name=zzz&cursor=" +
                          first.at("data").at("next_cursor").get<std::string>());
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.audit_log.size() == before);
}
