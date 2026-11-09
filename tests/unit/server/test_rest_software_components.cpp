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
#include "device_api.hpp"
#include "inventory_blob_v3.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "software_inventory_store.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <expected>
#include <memory>
#include <optional>
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

class FakeDeviceApi : public DeviceApi {
public:
    std::vector<DeviceListRow> rows;
    [[nodiscard]] std::vector<DeviceListRow> list_devices() const override { return rows; }
    [[nodiscard]] std::expected<std::optional<DeviceDetail>, DeviceReadError>
    lookup_device(const std::string&) const override {
        return std::optional<DeviceDetail>{std::nullopt};
    }
};

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_id;
    std::string detail;
};

struct CompHarness {
    yuzu::server::test::TestRouteSink sink;
    bool fleet_admitted{true};
    std::optional<std::unordered_set<std::string>> fleet_scope; // nullopt = unfiltered (AdmitAll)
    std::vector<AuditRecord> audit_log;
    int gate_calls{0};
    yuzu::MetricsRegistry metrics;
    std::shared_ptr<FakeDeviceApi> device_api = std::make_shared<FakeDeviceApi>();
    RestApiV1 api;

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
            /*agents_fn=*/{}, /*response_visible_set_fn=*/{}, /*verify_api=*/{}, device_api,
            /*dex_api=*/{});
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

TEST_CASE("REST components: rows carry hostname, last_seen, status and last_confirmed_at",
          "[pg][rest][inventory_components]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_components(store, "dev-a", {comp("libfoo", "/opt/a/libfoo.jar", "1.0")});

    CompHarness h{&store};
    h.device_api->rows.push_back(DeviceListRow{.agent_id = "dev-a", .hostname = "host-a"});
    const auto body = get_json(h, "?name=libfoo");
    const auto& rows = body.at("data").at("components");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0]["agent_id"] == "dev-a");
    CHECK(rows[0]["hostname"] == "host-a");
    CHECK(rows[0]["status"] == "current");
    CHECK(rows[0]["last_confirmed_at"].is_number()); // the full section confirmed it
    CHECK(rows[0]["kind"] == "jar");
    CHECK(rows[0]["version"] == "1.0");
    CHECK(rows[0]["path"] == "/opt/a/libfoo.jar");
    CHECK(rows[0]["anchor_app"] == "AcmeApp");
    CHECK(rows[0].contains("last_seen")); // null here: no installed_software report was accepted
    CHECK(h.audits("inventory.components.view", "success", "rows=1") == 1);
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

TEST_CASE("REST components: a version filter without name is a 400",
          "[pg][rest][inventory_components]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    CompHarness h{&store};
    for (const char* q : {"?version_min=1.0", "?version_max=2.0", "?version=1.0",
                          "?name=lib&match=prefix&version_min=1.0"}) {
        CAPTURE(q);
        auto res = h.sink.Get(std::string(kPath) + q);
        REQUIRE(res);
        CHECK(res->status == 400);
    }
    CHECK(h.audit_log.empty()); // a 400 writes nothing
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

TEST_CASE("REST components: a 100k-row CSV export walks every page with a continuation",
          "[pg][rest][inventory_components][export]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    constexpr int kDevices = 100;
    constexpr int kPerDevice = 1000;
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
        std::string q = "?format=csv";
        if (!cursor.empty())
            q += "&cursor=" + cursor;
        auto res = h.sink.Get(std::string(kPath) + q);
        REQUIRE(res);
        REQUIRE(res->status == 200);
        ++pages;
        REQUIRE(pages <= 12);
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
        if (!more)
            break;
        cursor = res->get_header_value("X-Next-Cursor");
    }
    CHECK(data_rows == static_cast<std::size_t>(kDevices) * kPerDevice);
    CHECK(pages == 10); // the export cap is 10000 rows per call
    CHECK(h.audits("inventory.components.export", "success", "page=continuation") == 9);
    CHECK(h.audits("inventory.components.export", "success") == 10);
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
