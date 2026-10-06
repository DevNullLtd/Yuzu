// test_rest_software_catalogue.cpp — HTTP-level tests for the software catalogue twins:
//   GET /api/v1/inventory/software/catalogue            (titles + totals + KPIs + titles CSV)
//   GET /api/v1/inventory/software/catalogue/versions   (installs per version)
//
// In-process TestRouteSink (no socket). The fleet-read gate is faked per test; the
// service-scoped deny runs through the real deny_fleet_wide_service_scoped helper, driven by the
// session the harness hands back. No-PG cases cover the wiring/deny paths; [pg] cases clone the
// pre-migrated `swinv` template and call refresh_catalog_rollup() after ingest.

#include "rest_api_v1.hpp"
#include "authz_gates.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "software_catalogue_model.hpp"
#include "software_inventory_store.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <algorithm>
#include <cstdio>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;
namespace swc = yuzu::server::software_catalogue;

namespace {

yuzu::test::PgTestTemplate swinv_tpl{"swinv", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    SoftwareInventoryStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("swinv template: store failed to migrate");
}};

struct AuditRecord {
    std::string action, result, target_id, detail;
};

class FakeDeviceApi : public DeviceApi {
public:
    std::vector<DeviceListRow> rows;
    [[nodiscard]] std::vector<DeviceListRow> list_devices() const override { return rows; }
    [[nodiscard]] std::expected<std::optional<DeviceDetail>, DeviceReadError>
    lookup_device(const std::string&) const override {
        return std::optional<DeviceDetail>{std::nullopt};
    }
};

struct CatHarness {
    // `api` BEFORE `sink`: the sink's routes capture state owned by `api` (#1786 false-green).
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;
    yuzu::server::test::TestRouteSink sink;

    bool fleet_admitted{true};
    authz::VisibleSet fleet_scope{std::nullopt}; // nullopt = TOP
    std::string token_scope_service;             // non-empty = a service-scoped session
    bool audit_throws{false};
    bool audit_ok{true};
    std::vector<AuditRecord> audit_log;
    std::shared_ptr<FakeDeviceApi> device_api = std::make_shared<FakeDeviceApi>();

    explicit CatHarness(SoftwareInventoryStore* store, bool wire_fleet_read_fn = true) {
        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "operator1";
            s.role = auth::Role::admin;
            s.token_scope_service = token_scope_service;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) -> bool {
            if (audit_throws)
                throw std::runtime_error("audit sink down");
            audit_log.push_back({action, result, target_id, detail});
            return audit_ok;
        };
        RestApiV1::FleetReadFn fleet_read_fn;
        if (wire_fleet_read_fn) {
            fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                   const std::string&,
                                   const std::string&) -> authz::FleetReadGate {
                if (!fleet_admitted) {
                    res.status = 403;
                    res.set_content(R"({"error":{"message":"denied"}})", "application/json");
                    return {};
                }
                return {true, fleet_scope};
            };
        }
        api.register_routes(
            sink, auth_fn, perm_fn, audit_fn,
            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr, /*token_store=*/nullptr,
            /*quarantine_store=*/nullptr, /*response_store=*/nullptr,
            /*instruction_store=*/nullptr, /*execution_tracker=*/nullptr,
            /*schedule_engine=*/nullptr, /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
            /*audit_store=*/nullptr, /*service_group_fn=*/{}, /*tag_push_fn=*/{},
            /*inventory_store=*/nullptr, /*product_pack_store=*/nullptr,
            /*sw_deploy_store=*/nullptr, /*device_token_store=*/nullptr,
            /*license_store=*/nullptr, /*guaranteed_state_store=*/nullptr,
            /*metrics_registry=*/&metrics, /*session_revoke_fn=*/{},
            /*execution_event_bus=*/nullptr, /*result_set_store=*/nullptr,
            /*command_dispatch_fn=*/{}, /*step_up_fn=*/{}, /*guardian_push_fn=*/{},
            /*dex_perf_fn=*/{}, /*network_api=*/{}, /*lockout_clear_fn=*/{},
            /*baseline_store=*/nullptr, /*scoped_perm_fn=*/{}, store, /*response_scope_fn=*/{},
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

constexpr const char* kCat = "/api/v1/inventory/software/catalogue";
constexpr const char* kVer = "/api/v1/inventory/software/catalogue/versions";

using Res = std::unique_ptr<httplib::Response>;

nlohmann::json data_of(const Res& r) {
    REQUIRE(r);
    return nlohmann::json::parse(r->body).at("data");
}
nlohmann::json err_of(const Res& r) {
    REQUIRE(r);
    return nlohmann::json::parse(r->body).at("error");
}

using Rows = std::vector<SoftwareEntry>;

SoftwareEntry ent(std::string name, std::string ver, std::string pub, std::string kind,
                  std::string eco, std::string src) {
    SoftwareEntry e;
    e.name = std::move(name);
    e.version = std::move(ver);
    e.publisher = std::move(pub);
    e.kind = std::move(kind);
    e.ecosystem = std::move(eco);
    e.source = std::move(src);
    return e;
}

void put(SoftwareInventoryStore& store, const std::string& agent, Rows rows) {
    REQUIRE(store.apply_installed_software(agent, "", std::move(rows), 1) ==
            InventoryIngestOutcome::kStored);
}

// d1: git (brew + pkgutil), Chrome; d2: git 2.39; d3: git 2.41 (rpm). 2 titles, 3 devices,
// 4 installs.
void seed_fixture(SoftwareInventoryStore& store, bool refresh = true) {
    put(store, "d1", Rows{ent("git", "2.40", "Git SCM", "package", "brew", "pkg_inventory.packages"),
                          ent("git", "2.40", "Git SCM", "pkg", "macos_pkgutil", "installed_apps.list_inventory"),
                          ent("Chrome", "126", "Google", "app", "macos", "installed_apps.list_inventory")});
    put(store, "d2", Rows{ent("git", "2.39", "Git SCM", "package", "brew", "pkg_inventory.packages")});
    put(store, "d3", Rows{ent("git", "2.41", "Fedora", "package", "rpm", "pkg_inventory.packages")});
    if (refresh)
        REQUIRE(store.refresh_catalog_rollup());
}

std::string b64url(std::string_view in) {
    static constexpr char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    std::uint32_t acc = 0;
    int bits = 0;
    for (unsigned char c : in) {
        acc = (acc << 8) | c;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out += tbl[(acc >> bits) & 63];
        }
    }
    if (bits > 0)
        out += tbl[(acc << (6 - bits)) & 63];
    return out;
}

} // namespace

// ── No-PG branches ───────────────────────────────────────────────────────────

TEST_CASE("catalogue routes: unwired fleet_read_fn fails closed with 503",
          "[rest][software_catalogue][security]") {
    CatHarness h{/*store=*/nullptr, /*wire_fleet_read_fn=*/false};
    for (const char* path : {kCat, kVer}) {
        auto r = h.sink.Get(std::string(path) + "?name=git");
        REQUIRE(r);
        CHECK(r->status == 503);
        CHECK(nlohmann::json::parse(r->body).contains("error"));
        CHECK_FALSE(nlohmann::json::parse(r->body).contains("data"));
    }
}

TEST_CASE("catalogue routes: null store is 503 'not available' with no audit row",
          "[rest][software_catalogue]") {
    CatHarness h{/*store=*/nullptr};
    for (const char* path : {kCat, kVer}) {
        auto r = h.sink.Get(std::string(path) + "?name=git");
        REQUIRE(r);
        CHECK(r->status == 503);
        CHECK(err_of(r).at("message") == "software inventory store not available");
        CHECK_FALSE(r->get_header_value("X-Correlation-Id").empty());
    }
    CHECK(h.audit_log.empty());
}

TEST_CASE("catalogue routes: a service-scoped token is denied with NO .permission field and a denied "
          "audit row and the default-deny metric",
          "[rest][software_catalogue][security]") {
    CatHarness h{/*store=*/nullptr};
    h.token_scope_service = "printers";
    double before = 0;
    for (const char* path : {kCat, kVer}) {
        auto r = h.sink.Get(std::string(path) + "?name=git");
        REQUIRE(r);
        CHECK(r->status == 403);
        CHECK(r->body.find("\"permission\"") == std::string::npos);
        before += 1;
    }
    CHECK(h.audits("inventory.software.catalog", "denied") == 1);
    CHECK(h.audits("inventory.software.versions", "denied") == 1);
    CHECK(h.metrics
              .counter("yuzu_auth_service_scope_default_denied_total",
                       {{"permission", "unspecified"}, {"path_class", "rest"}})
              .value() == before);
}

TEST_CASE("catalogue routes: both paths are in the OpenAPI spec (A1 discoverability)",
          "[rest][software_catalogue]") {
    CatHarness h{/*store=*/nullptr};
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    const auto spec = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(spec.is_discarded());
    for (const char* p : {"/inventory/software/catalogue", "/inventory/software/catalogue/versions"}) {
        REQUIRE(spec["paths"].contains(p));
        CHECK(spec["paths"][p].contains("get"));
    }
}

// ── [pg] gate, parse and posture ─────────────────────────────────────────────

TEST_CASE("catalogue routes: a confined caller is denied the fleet view (403 + Inventory:Read) "
          "with a denied audit row",
          "[pg][rest][software_catalogue][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_fixture(store);

    CatHarness h{&store};
    h.fleet_scope = std::unordered_set<std::string>{"d1"};
    for (const char* path : {kCat, kVer}) {
        auto r = h.sink.Get(std::string(path) + "?name=git");
        REQUIRE(r);
        CHECK(r->status == 403);
        CHECK(err_of(r).at("permission") == "Inventory:Read");
        CHECK_FALSE(nlohmann::json::parse(r->body).contains("data"));
    }
    CHECK(h.audits("inventory.software.catalog", "denied") == 1);
    CHECK(h.audits("inventory.software.versions", "denied") == 1);
    CHECK(h.audits("inventory.software.catalog", "success") == 0);
}

TEST_CASE("catalogue routes: malformed parameters are 400 with a correlation id",
          "[pg][rest][software_catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    CatHarness h{&store};
    const std::string oversize(2049, 'a');
    const std::string too_long(257, 'a'); // > kSourceMaxBytes
    for (const std::string& url : std::vector<std::string>{std::string(kCat) + "?kind=app&kind=pkg",
                                  std::string(kCat) + "?limit=12abc",
                                  std::string(kCat) + "?versions_min=-1",
                                  std::string(kCat) + "?format=xml",
                                  std::string(kCat) + "?cursor=" + oversize,
                                  std::string(kCat) + "?format=csv&cursor=garbage",
                                  std::string(kCat) + "?source=" + too_long,
                                  std::string(kCat) + "?agent_id=" + too_long,
                                  std::string(kVer),
                                  std::string(kVer) + "?name=git&name=other",
                                  std::string(kVer) + "?name=git&source=" + too_long,
                                  std::string(kVer) + "?name=git&agent_id=" + too_long}) {
        CAPTURE(url.substr(0, 80));
        auto r = h.sink.Get(url);
        REQUIRE(r);
        CHECK(r->status == 400);
        CHECK_FALSE(r->get_header_value("X-Correlation-Id").empty());
        CHECK_FALSE(err_of(r).at("correlation_id").get<std::string>().empty());
    }
}

// ── [pg] reads ───────────────────────────────────────────────────────────────

TEST_CASE("catalogue: fleet read: rows / totals / KPIs / coverage counts",
          "[pg][rest][software_catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_fixture(store);

    CatHarness h{&store};
    for (int i = 0; i < 5; ++i)
        h.device_api->rows.push_back(DeviceListRow{.agent_id = "c" + std::to_string(i)});
    const auto d = data_of(h.sink.Get(kCat));
    REQUIRE(d.at("titles").size() == 2);
    CHECK(d.at("titles")[0].at("name") == "git"); // installs desc: git 3, Chrome 1
    CHECK(d.at("titles")[0].at("installs") == 3);
    CHECK(d.at("titles")[0].at("ecosystems") == nlohmann::json::array({"brew", "macos_pkgutil", "rpm"}));
    CHECK(d.at("titles")[0].at("newest_version") == "2.41");
    CHECK(d.at("totals").at("titles") == 2);
    CHECK(d.at("totals").at("installs") == 4);
    CHECK(d.at("next_cursor").is_null());
    CHECK(d.at("devices_omitted") == 0);
    const auto& k = d.at("kpis");
    CHECK(k.at("titles") == 2);
    CHECK(k.at("installs") == 4);
    CHECK(k.at("building") == false);
    CHECK(k.at("coverage").at("reporting") == 3);
    CHECK(k.at("coverage").at("connected") == 5);
    CHECK(k.at("coverage").at("stale") == 0); // wired from the store count, not the null arm
    CHECK_FALSE(k.at("coverage").contains("pct"));
    CHECK(h.audits("inventory.software.catalog", "success") == 1);
}

TEST_CASE("catalogue: totals cover every row under the filters while the page shows `limit` rows",
          "[pg][rest][software_catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_fixture(store);

    CatHarness h{&store};
    const auto d = data_of(h.sink.Get(std::string(kCat) + "?limit=1"));
    CHECK(d.at("titles").size() == 1);
    CHECK(d.at("totals").at("titles") == 2);
    CHECK(d.at("totals").at("installs") == 4);
    CHECK(d.at("next_cursor").is_string());
    const auto f = data_of(h.sink.Get(std::string(kCat) + "?ecosystem=brew&limit=1"));
    CHECK(f.at("totals").at("titles") == 1);
    CHECK(f.at("totals").at("installs") == 2);
    const auto q = data_of(h.sink.Get(std::string(kCat) + "?q=git&kind=package"));
    CHECK(q.at("totals").at("titles") == 1);
}

TEST_CASE("catalogue: keyset walk over 250 titles pages 100/100/50 without duplicates and kpis null "
          "on continuation pages",
          "[pg][rest][software_catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    Rows rows;
    for (int i = 0; i < 250; ++i) {
        char name[16];
        std::snprintf(name, sizeof name, "title-%03d", i);
        rows.push_back(ent(name, "1.0", "", "package", "deb", "pkg_inventory.packages"));
    }
    put(store, "d1", std::move(rows));
    REQUIRE(store.refresh_catalog_rollup());

    CatHarness h{&store};
    std::set<std::string> seen;
    std::vector<std::size_t> sizes;
    std::string cursor;
    for (int page = 0; page < 5; ++page) {
        std::string url = std::string(kCat) + "?limit=100";
        if (!cursor.empty())
            url += "&cursor=" + cursor;
        const auto d = data_of(h.sink.Get(url));
        sizes.push_back(d.at("titles").size());
        for (const auto& t : d.at("titles"))
            CHECK(seen.insert(t.at("name").get<std::string>()).second);
        CHECK(d.at("kpis").is_null() == (page > 0));
        CHECK(d.at("totals").at("titles") == 250);
        if (d.at("next_cursor").is_null())
            break;
        cursor = d.at("next_cursor").get<std::string>();
    }
    CHECK(sizes == std::vector<std::size_t>{100, 100, 50});
    CHECK(seen.size() == 250);
    // audit on EVERY call; the two continuation pages are tagged
    CHECK(h.audits("inventory.software.catalog", "success") == 3);
    CHECK(h.audits("inventory.software.catalog", "success", "page=continuation") == 2);
}

TEST_CASE("catalogue: cursor refusals: tampered / other filters / stale after a refresh",
          "[pg][rest][software_catalogue][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_fixture(store);

    CatHarness h{&store};
    const auto first = data_of(h.sink.Get(std::string(kCat) + "?limit=1"));
    const auto cursor = first.at("next_cursor").get<std::string>();
    const std::string base = std::string(kCat) + "?limit=1&cursor=";

    auto tampered = h.sink.Get(base + cursor + "!");
    REQUIRE(tampered);
    CHECK(tampered->status == 400);
    CHECK(err_of(tampered).at("message") == "invalid cursor");

    auto other = h.sink.Get(std::string(kCat) + "?limit=1&kind=app&cursor=" + cursor);
    REQUIRE(other);
    CHECK(other->status == 400);
    CHECK(err_of(other).at("message") == "cursor was issued for a different filter set");

    // A refresh lands between pages. refreshed_at has 1 s granularity, so bump it directly
    // rather than sleeping.
    REQUIRE(store.refresh_catalog_rollup());
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        REQUIRE(yuzu::server::pg::exec_params(
                    lease.get(),
                    "UPDATE software_inventory_store.catalog_rollup_meta SET refreshed_at = "
                    "refreshed_at + 1",
                    std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);
    }
    auto stale = h.sink.Get(base + cursor);
    REQUIRE(stale);
    CHECK(stale->status == 400);
    CHECK(err_of(stale).at("message").get<std::string>().find("predates the current catalogue refresh") !=
          std::string::npos);
    // restarting from page one works
    CHECK(h.sink.Get(std::string(kCat) + "?limit=1")->status == 200);
}

TEST_CASE("catalogue: a forged head cursor walks from row 1 but is audited as a continuation",
          "[pg][rest][software_catalogue][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_fixture(store);
    const auto meta = store.catalog_rollup_meta();
    REQUIRE(meta.has_value());

    CatHarness h{&store};
    const auto fp = swc::filter_fingerprint(SoftwareCatalogQuery{.limit = 100});
    const auto forged = "c1:" + fp + ":" + std::to_string(meta->refreshed_at) + ":" +
                        b64url(std::string("9223372036854775807\x1f"));
    auto r = h.sink.Get(std::string(kCat) + "?cursor=" + forged);
    REQUIRE(r);
    CHECK(r->status == 200); // opaque is not authenticated...
    CHECK(data_of(r).at("titles")[0].at("name") == "git");
    // ...so the per-call audit row is what keeps it from being silent.
    CHECK(h.audits("inventory.software.catalog", "success", "page=continuation") == 1);
}

TEST_CASE("catalogue: before the first refresh the page is 200 with the building state",
          "[pg][rest][software_catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    CatHarness h{&store};
    auto r = h.sink.Get(kCat);
    REQUIRE(r);
    CHECK(r->status == 200);
    const auto d = data_of(r);
    CHECK(d.at("kpis").at("building") == true);
    CHECK(d.at("kpis").at("installs") == 0);
    CHECK(d.at("titles").empty());
    CHECK(d.at("totals").at("titles") == 0);
    CHECK(d.at("totals").at("installs") == 0);
}

TEST_CASE("catalogue: host view — one row per title; a confined caller sees newest blanked",
          "[pg][rest][software_catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_fixture(store);
    const std::string url = std::string(kCat) + "?agent_id=d1";

    SECTION("TOP caller") {
        CatHarness h{&store};
        const auto d = data_of(h.sink.Get(url));
        REQUIRE(d.at("titles").size() == 2);
        CHECK(d.at("titles")[0].at("installs") == 1);
        CHECK(d.at("titles")[1].at("newest_version") == "2.41");
        CHECK(d.at("kpis").is_null());
        CHECK_FALSE(d.contains("newest_omitted"));
    }
    SECTION("confined caller with the device in scope") {
        CatHarness h{&store};
        h.fleet_scope = std::unordered_set<std::string>{"d1"};
        const auto d = data_of(h.sink.Get(url));
        REQUIRE(d.at("titles").size() == 2);
        CHECK(d.at("titles")[1].at("newest_version") == "");
        CHECK(d.at("newest_omitted") == true);
    }
    SECTION("confined caller, device out of scope: empty, devices_omitted 1, denied audit") {
        CatHarness h{&store};
        h.fleet_scope = std::unordered_set<std::string>{"d2"};
        const auto d = data_of(h.sink.Get(url));
        CHECK(d.at("titles").empty());
        CHECK(d.at("devices_omitted") == 1);
        CHECK(h.audits("inventory.software.catalog", "denied") == 1);
    }
}

TEST_CASE("versions: newest mark / filters / truncation / out-of-scope device",
          "[pg][rest][software_catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_fixture(store);

    CatHarness h{&store};
    const auto d = data_of(h.sink.Get(std::string(kVer) + "?name=git"));
    CHECK(d.at("count") == 3);
    CHECK(d.at("truncated") == false);
    bool newest_seen = false;
    for (const auto& v : d.at("versions"))
        if (v.at("newest").get<bool>()) {
            CHECK(v.at("version") == "2.41");
            newest_seen = true;
        }
    CHECK(newest_seen);
    CHECK_FALSE(d.contains("newest_omitted"));

    const auto eco = data_of(h.sink.Get(std::string(kVer) + "?name=git&ecosystem=brew"));
    CHECK(eco.at("count") == 2);
    CHECK(data_of(h.sink.Get(std::string(kVer) + "?name=git&limit=2")).at("truncated") == true);
    CHECK(h.audits("inventory.software.versions", "success") == 3);

    SECTION("confined caller, device in scope: newest false on every row") {
        CatHarness c{&store};
        c.fleet_scope = std::unordered_set<std::string>{"d1"};
        const auto v = data_of(c.sink.Get(std::string(kVer) + "?name=git&agent_id=d1"));
        CHECK(v.at("newest_omitted") == true);
        for (const auto& row : v.at("versions"))
            CHECK(row.at("newest") == false);
    }
    SECTION("device out of scope: empty + denied") {
        CatHarness c{&store};
        c.fleet_scope = std::unordered_set<std::string>{"d1"};
        const auto v = data_of(c.sink.Get(std::string(kVer) + "?name=git&agent_id=d2"));
        CHECK(v.at("versions").empty());
        CHECK(c.audits("inventory.software.versions", "denied") == 1);
    }
}

TEST_CASE("catalogue routes: a degraded store is 503 + retry_after_ms + failure audit and never an "
          "empty 200",
          "[pg][rest][software_catalogue][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    auto held = pool.acquire(); // starve the pool: every read times out → nullopt
    CatHarness h{&store};
    for (const char* path : {kCat, kVer}) {
        auto r = h.sink.Get(std::string(path) + "?name=git");
        REQUIRE(r);
        CHECK(r->status == 503);
        CHECK(err_of(r).at("retry_after_ms") == 5000);
        CHECK_FALSE(nlohmann::json::parse(r->body).contains("data"));
    }
    CHECK(h.audits("inventory.software.catalog", "failure") == 1);
    CHECK(h.audits("inventory.software.versions", "failure") == 1);
    CHECK(h.audits("inventory.software.catalog", "success") == 0);
}

TEST_CASE("catalogue routes: a throwing or failing audit sink serves 200 with audit_persisted:false",
          "[pg][rest][software_catalogue][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_fixture(store);

    CatHarness h{&store};
    h.audit_throws = true;
    for (const char* path : {kCat, kVer}) {
        auto r = h.sink.Get(std::string(path) + "?name=git");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(data_of(r).at("audit_persisted") == false);
    }
}

TEST_CASE("catalogue: audit target equals audit_target(query) on every call",
          "[pg][rest][software_catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_fixture(store);

    CatHarness h{&store};
    REQUIRE(h.sink.Get(std::string(kCat) + "?ecosystem=brew&q=git&versions_min=1")->status == 200);
    SoftwareCatalogQuery q;
    q.ecosystem = "brew";
    q.q = "git";
    q.versions_min = 1;
    REQUIRE_FALSE(h.audit_log.empty());
    CHECK(h.audit_log.back().target_id == swc::audit_target(q));
    REQUIRE(h.sink.Get(std::string(kVer) + "?name=git")->status == 200);
    CHECK(h.audit_log.back().target_id == "name=git");
}

TEST_CASE("catalogue: titles CSV: header / disposition / cap truncation / audit / service deny",
          "[pg][rest][software_catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    put(store, "d1", Rows{ent("A", "1", "", "package", "deb", "s"), ent("B", "1", "", "package", "deb", "s"),
                          ent("C", "1", "", "package", "deb", "s")});
    REQUIRE(store.refresh_catalog_rollup());

    CatHarness h{&store};
    auto all = h.sink.Get(std::string(kCat) + "?format=csv");
    REQUIRE(all);
    CHECK(all->status == 200);
    CHECK(all->get_header_value("Content-Type").find("text/csv") == 0);
    CHECK(all->get_header_value("Content-Disposition").find("software-titles.csv") != std::string::npos);
    CHECK(all->body.starts_with(std::string(swc::kTitlesCsvHeader) + "\n"));
    CHECK(std::ranges::count(all->body, '\n') == 4);
    CHECK(all->get_header_value("X-Result-Truncated-By-Cap").empty());

    auto cut = h.sink.Get(std::string(kCat) + "?format=csv&limit=2");
    REQUIRE(cut);
    CHECK(std::ranges::count(cut->body, '\n') == 3); // header + 2 rows
    CHECK(cut->get_header_value("X-Result-Truncated-By-Cap") == "true");

    CHECK(h.audits("inventory.software.export", "success") == 2);
    CHECK(h.audits("inventory.software.export", "success", "truncated=true") == 1);

    h.token_scope_service = "printers";
    CHECK(h.sink.Get(std::string(kCat) + "?format=csv")->status == 403);
}

TEST_CASE("catalogue: a titles CSV for an out-of-scope host is a header-only 200 with a denied "
          "row AND an export success row",
          "[pg][rest][software_catalogue][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_fixture(store);

    CatHarness h{&store};
    h.fleet_scope = std::unordered_set<std::string>{"d2"};
    auto r = h.sink.Get(std::string(kCat) + "?format=csv&agent_id=d1");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->body == std::string(swc::kTitlesCsvHeader) + "\n"); // no oracle: same as an empty host
    // The paired-row convention of inventory.software.query: the denial AND the (empty) export.
    CHECK(h.audits("inventory.software.export", "denied") == 1);
    CHECK(h.audits("inventory.software.export", "success", "rows=0") == 1);
}

TEST_CASE("catalogue: a degraded store on the titles CSV is 503 + retry_after_ms + an export "
          "failure audit",
          "[pg][rest][software_catalogue][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    auto held = pool.acquire(); // starve the pool: every read times out -> nullopt
    CatHarness h{&store};
    auto r = h.sink.Get(std::string(kCat) + "?format=csv");
    REQUIRE(r);
    CHECK(r->status == 503);
    CHECK(err_of(r).at("retry_after_ms") == 5000);
    CHECK(h.audits("inventory.software.export", "failure") == 1);
    CHECK(h.audits("inventory.software.export", "success") == 0);
}
