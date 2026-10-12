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
#include <format>
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
    std::string audit_fail_result; // non-empty: only rows with this result fail to persist
    std::vector<AuditRecord> audit_log;
    std::shared_ptr<FakeDeviceApi> device_api = std::make_shared<FakeDeviceApi>();

    explicit CatHarness(SoftwareInventoryStore* store, bool wire_fleet_read_fn = true,
                        bool wire_device_api = true) {
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
            return audit_ok && result != audit_fail_result;
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
            /*agents_fn=*/{}, /*response_visible_set_fn=*/{}, /*verify_api=*/{},
            wire_device_api ? device_api : nullptr,
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

// Puts the rollup back to its never-computed state (a fresh install, or the v8 upgrade before
// its first refresh): refreshed_at = 0 on the singleton meta row of the disposable clone.
void reset_rollup_to_building(PgPool& pool) {
    auto lease = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(lease);
    REQUIRE(yuzu::server::pg::exec_params(
                lease.get(),
                "UPDATE software_inventory_store.catalog_rollup_meta SET refreshed_at = 0",
                std::vector<std::string>{})
                .status() == PGRES_COMMAND_OK);
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
        // The unwired arm, not the null-store one that would also be a 503 here.
        CHECK(err_of(r).at("message") == "service unavailable");
        // A4 bodies always carry the key; null = no retry hint (nothing to retry against).
        CHECK(err_of(r).at("retry_after_ms").is_null());
        CHECK_FALSE(nlohmann::json::parse(r->body).contains("data"));
    }
}

TEST_CASE("catalogue routes: a gate that does not admit stops the request before any read or audit "
          "row",
          "[rest][software_catalogue][security]") {
    CatHarness h{/*store=*/nullptr};
    h.fleet_admitted = false;
    for (const char* path : {kCat, kVer}) {
        auto r = h.sink.Get(std::string(path) + "?name=git");
        REQUIRE(r);
        CHECK(r->status == 403);
        CHECK(err_of(r).at("message") == "denied"); // the gate's own body, not the store 503
        CHECK_FALSE(nlohmann::json::parse(r->body).contains("data"));
    }
    CHECK(h.audit_log.empty());
}

TEST_CASE("catalogue routes: null store is 503 'not available' with no audit row",
          "[rest][software_catalogue]") {
    CatHarness h{/*store=*/nullptr};
    for (const char* path : {kCat, kVer}) {
        auto r = h.sink.Get(std::string(path) + "?name=git");
        REQUIRE(r);
        CHECK(r->status == 503);
        CHECK(err_of(r).at("message") == "software inventory store not available");
        CHECK(err_of(r).at("retry_after_ms").is_null());
        CHECK_FALSE(r->get_header_value("X-Correlation-Id").empty());
        CHECK(err_of(r).at("correlation_id").get<std::string>() == r->get_header_value("X-Correlation-Id"));
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
        CHECK(err_of(r).at("correlation_id").get<std::string>() == r->get_header_value("X-Correlation-Id"));
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
        CHECK(err_of(r).at("correlation_id").get<std::string>() == r->get_header_value("X-Correlation-Id"));
    }
}

TEST_CASE("catalogue routes: text Postgres cannot bind is a 400 and never a retryable 503 or a failure "
          "audit row",
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
    // A hand-minted cursor for the CURRENT generation whose decoded name is not valid UTF-8
    // (well-formed otherwise), so only the UTF-8 refusal can answer 400 - not a stale cursor.
    const std::string forged = "c1:" + swc::filter_fingerprint(SoftwareCatalogQuery{.limit = 100}) + ":" +
                               std::to_string(meta->refreshed_at) + ":" +
                               b64url(std::string("5\x1f") + "\xFF");
    for (const std::string& url : std::vector<std::string>{std::string(kCat) + "?kind=%FF",
                                                           std::string(kCat) + "?q=%00",
                                                           std::string(kCat) + "?cursor=" + forged,
                                                           std::string(kVer) + "?name=%FF"}) {
        CAPTURE(url);
        auto r = h.sink.Get(url);
        REQUIRE(r);
        CHECK(r->status == 400);
        CHECK(err_of(r).at("retry_after_ms").is_null()); // a caller fault, not a retryable degrade
    }
    CHECK(h.audits("inventory.software.catalog", "failure") == 0);
    CHECK(h.audits("inventory.software.versions", "failure") == 0);
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

TEST_CASE("catalogue: with no DeviceApi wired coverage.connected is null and reporting still counts",
          "[pg][rest][software_catalogue]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_fixture(store);

    CatHarness h{&store, /*wire_fleet_read_fn=*/true, /*wire_device_api=*/false};
    auto r = h.sink.Get(kCat);
    REQUIRE(r);
    CHECK(r->status == 200);
    const auto cov = data_of(r).at("kpis").at("coverage");
    CHECK(cov.at("connected").is_null());
    CHECK(cov.at("reporting") == 3);
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
        rows.push_back(ent(std::format("title-{:03}", i), "1.0", "", "package", "deb", "pkg_inventory.packages"));
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
    auto restart = h.sink.Get(std::string(kCat) + "?limit=1");
    REQUIRE(restart);
    CHECK(restart->status == 200);
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
    CHECK(d.at("devices_omitted") == 0);
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
        CHECK(v.at("devices_omitted") == 0);
        REQUIRE_FALSE(v.at("versions").empty()); // else the loop below is vacuous
        for (const auto& row : v.at("versions"))
            CHECK(row.at("newest") == false);
    }
    SECTION("device out of scope: empty + denied + the devices_omitted marker") {
        CatHarness c{&store};
        c.fleet_scope = std::unordered_set<std::string>{"d1"};
        const auto v = data_of(c.sink.Get(std::string(kVer) + "?name=git&agent_id=d2"));
        CHECK(v.at("versions").empty());
        CHECK(v.at("devices_omitted") == 1); // not "no installs of git on d2"
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
    for (const auto& [path, what] : {std::pair<const char*, const char*>{kCat, "catalogue read"},
                                     std::pair<const char*, const char*>{kVer, "versions read"}}) {
        auto r = h.sink.Get(std::string(path) + "?name=git");
        REQUIRE(r);
        CHECK(r->status == 503);
        CHECK(err_of(r).at("message") ==
              std::string("software inventory store degraded — ") + what + " failed");
        CHECK(err_of(r).at("retry_after_ms") == 5000);
        CHECK_FALSE(nlohmann::json::parse(r->body).contains("data"));
    }
    CHECK(h.audits("inventory.software.catalog", "failure", "catalogue read degraded") == 1);
    CHECK(h.audits("inventory.software.versions", "failure", "versions read degraded") == 1);
    CHECK(h.audits("inventory.software.catalog", "success") == 0);
}

TEST_CASE("catalogue routes: an unreadable refresh-metadata row degrades the unfiltered versions "
          "read only and with the versions message and a failure audit",
          "[pg][rest][software_catalogue][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_fixture(store);
    {
        // The meta read is a direct statement, so renaming the table in the disposable clone
        // fails it while version_rollup and installed_software stay readable: the pre-check's
        // nullopt arm is then the only thing that can produce the 503.
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        REQUIRE(yuzu::server::pg::exec_params(
                    lease.get(),
                    "ALTER TABLE software_inventory_store.catalog_rollup_meta RENAME TO "
                    "catalog_rollup_meta_renamed",
                    std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);
    }
    CatHarness h{&store};
    auto r = h.sink.Get(std::string(kVer) + "?name=git");
    REQUIRE(r);
    CHECK(r->status == 503);
    CHECK(err_of(r).at("message") ==
          "software inventory store degraded — versions read failed");
    CHECK(err_of(r).at("retry_after_ms") == 5000);
    CHECK_FALSE(nlohmann::json::parse(r->body).contains("data"));
    CHECK(h.audits("inventory.software.versions", "failure", "versions read degraded") == 1);
    CHECK(h.audits("inventory.software.versions", "success") == 0);

    // A filtered read never touches the meta row, so it still serves.
    auto filtered = h.sink.Get(std::string(kVer) + "?name=git&ecosystem=brew");
    REQUIRE(filtered);
    CHECK(filtered->status == 200);
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

    // The out-of-scope per-device arms swallow no failed `denied` row either.
    h.fleet_scope = std::unordered_set<std::string>{"d1"};
    auto cat = h.sink.Get(std::string(kCat) + "?agent_id=d2");
    REQUIRE(cat);
    CHECK(cat->status == 200);
    CHECK(data_of(cat).at("audit_persisted") == false);
    auto ver = h.sink.Get(std::string(kVer) + "?name=git&agent_id=d2");
    REQUIRE(ver);
    CHECK(ver->status == 200);
    CHECK(data_of(ver).at("audit_persisted") == false);
    auto csv = h.sink.Get(std::string(kCat) + "?agent_id=d2&format=csv");
    REQUIRE(csv);
    CHECK(csv->status == 200);
    CHECK(csv->get_header_value("Sec-Audit-Failed") == "true");
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
    auto brew = h.sink.Get(std::string(kCat) + "?ecosystem=brew&q=git&versions_min=1");
    REQUIRE(brew);
    REQUIRE(brew->status == 200);
    SoftwareCatalogQuery q;
    q.ecosystem = "brew";
    q.q = "git";
    q.versions_min = 1;
    REQUIRE_FALSE(h.audit_log.empty());
    CHECK(h.audit_log.back().target_id == swc::audit_target(q));
    auto git = h.sink.Get(std::string(kVer) + "?name=git");
    REQUIRE(git);
    REQUIRE(git->status == 200);
    CHECK(h.audit_log.back().target_id == "name=git");
}

TEST_CASE("catalogue: titles CSV: header / disposition / cap truncation / audit",
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
    // The route's own row count reaches the audit detail (3 titles served; 2 when cut by limit).
    CHECK(h.audits("inventory.software.export", "success", "rows=3") == 1);
    CHECK(h.audits("inventory.software.export", "success", "rows=2") == 1);

    // An export whose audit row did not persist is still served, flagged on the wire.
    h.audit_ok = false;
    auto unaudited = h.sink.Get(std::string(kCat) + "?format=csv");
    REQUIRE(unaudited);
    CHECK(unaudited->status == 200);
    CHECK(unaudited->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(unaudited->get_header_value("Content-Disposition").find("software-titles.csv") !=
          std::string::npos);
    h.audit_ok = true;
    auto audited = h.sink.Get(std::string(kCat) + "?format=csv");
    REQUIRE(audited);
    CHECK(audited->status == 200);
    CHECK(audited->get_header_value("Sec-Audit-Failed").empty());
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

TEST_CASE("catalogue: titles CSV posture / confined fleet deny / in-scope host blanking / denied-row "
          "carry-over",
          "[pg][rest][software_catalogue][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_fixture(store);
    const std::string host_csv = std::string(kCat) + "?format=csv&agent_id=d1";

    SECTION("a confined fleet export is denied under the export verb") {
        CatHarness h{&store};
        h.fleet_scope = std::unordered_set<std::string>{"d1"};
        auto r = h.sink.Get(std::string(kCat) + "?format=csv");
        REQUIRE(r);
        CHECK(r->status == 403);
        CHECK(err_of(r).at("permission") == "Inventory:Read");
        CHECK(h.audits("inventory.software.export", "denied") == 1);
        CHECK(h.audits("inventory.software.export", "success") == 0);
    }
    SECTION("a service-scoped ?format=csv is denied pre-parse under the catalogue verb") {
        CatHarness h{&store};
        h.token_scope_service = "printers";
        auto r = h.sink.Get(std::string(kCat) + "?format=csv");
        REQUIRE(r);
        CHECK(r->status == 403);
        CHECK(h.audits("inventory.software.catalog", "denied") == 1);
        CHECK(h.audits("inventory.software.export", "denied") == 0);
    }
    SECTION("a confined in-scope host export blanks the fleet-derived newest column") {
        CatHarness top{&store};
        auto open = top.sink.Get(host_csv);
        REQUIRE(open);
        REQUIRE(open->status == 200);
        CHECK(open->body.find("2.41") != std::string::npos); // control: TOP sees the fleet newest

        CatHarness h{&store};
        h.fleet_scope = std::unordered_set<std::string>{"d1"};
        auto r = h.sink.Get(host_csv);
        REQUIRE(r);
        REQUIRE(r->status == 200);
        CHECK(r->body.find("2.41") == std::string::npos);
        CHECK(std::ranges::count(r->body, '\n') == 3); // header + git + Chrome
        CHECK(r->body.find(",\n", r->body.find('\n')) != std::string::npos); // empty last cell
    }
    SECTION("a failed denied row alone still flags the served empty export") {
        CatHarness h{&store};
        h.fleet_scope = std::unordered_set<std::string>{"d2"};
        h.audit_fail_result = "denied";
        auto r = h.sink.Get(host_csv);
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(h.audits("inventory.software.export", "success", "rows=0") == 1); // that one persisted
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
    }
}

TEST_CASE("catalogue: a never-built rollup is a 503 'being built' on the CSV export / the "
          "unfiltered versions read / never an empty 200",
          "[pg][rest][software_catalogue][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed_fixture(store);
    reset_rollup_to_building(pool);
    const std::string csv_url = std::string(kCat) + "?format=csv";
    const std::string ver_url = std::string(kVer) + "?name=git";

    auto expect_building = [](const Res& r) {
        REQUIRE(r);
        CHECK(r->status == 503);
        CHECK(err_of(r).at("message") == "software catalogue is being built; retry");
        CHECK(err_of(r).at("retry_after_ms") == 5000);
        CHECK(r->get_header_value("Content-Disposition").empty()); // no file was offered
        CHECK_FALSE(nlohmann::json::parse(r->body).contains("data"));
    };

    SECTION("the CSV export") {
        CatHarness h{&store};
        expect_building(h.sink.Get(csv_url));
        CHECK(h.audits("inventory.software.export", "failure", "building") == 1);
        CHECK(h.audits("inventory.software.export", "success") == 0);
    }
    SECTION("the unfiltered versions read") {
        CatHarness h{&store};
        expect_building(h.sink.Get(ver_url));
        CHECK(h.audits("inventory.software.versions", "failure", "building") == 1);
        CHECK(h.audits("inventory.software.versions", "success") == 0);
    }
    SECTION("a dead audit sink does not turn the signal into a 500 or an empty 200") {
        CatHarness h{&store};
        h.audit_throws = true;
        expect_building(h.sink.Get(csv_url));
        expect_building(h.sink.Get(ver_url));
    }
    SECTION("reads that do not depend on the rollup, and the JSON page, still answer") {
        CatHarness h{&store};
        {
            // reset_rollup_to_building only zeroes refreshed_at; the newest mark reads the rollup
            // rows directly, so empty them to truly model a never-computed rollup.
            auto lease = pool.try_acquire_for(std::chrono::seconds{5});
            REQUIRE(lease);
            REQUIRE(yuzu::server::pg::exec_params(
                        lease.get(), "DELETE FROM software_inventory_store.catalog_rollup",
                        std::vector<std::string>{})
                        .status() == PGRES_COMMAND_OK);
        }
        auto eco = h.sink.Get(ver_url + "&ecosystem=brew");
        REQUIRE(eco);
        CHECK(eco->status == 200);
        CHECK(data_of(eco).at("count") == 2);
        // Rows and counts do not depend on the rollup; the newest mark does and stays false.
        // The rpm row is git 2.41 (the fleet newest): with a populated rollup it would be true.
        auto rpm = h.sink.Get(ver_url + "&ecosystem=rpm");
        REQUIRE(rpm);
        REQUIRE(rpm->status == 200);
        const auto rpm_d = data_of(rpm);
        const auto eco_d = data_of(eco);
        REQUIRE(rpm_d.at("count") == 1);
        for (const auto& row : rpm_d.at("versions"))
            CHECK(row.at("newest") == false);
        for (const auto& row : eco_d.at("versions"))
            CHECK(row.at("newest") == false);
        // Each pre-check term is pinned alone: a drift that dropped kind or source from the
        // "unfiltered" test would answer 503 'being built' here.
        auto by_kind = h.sink.Get(ver_url + "&kind=package");
        REQUIRE(by_kind);
        CHECK(by_kind->status == 200);
        auto by_source = h.sink.Get(ver_url + "&source=pkg_inventory.packages");
        REQUIRE(by_source);
        CHECK(by_source->status == 200);
        auto dev = h.sink.Get(ver_url + "&agent_id=d1");
        REQUIRE(dev);
        CHECK(dev->status == 200);
        auto host = h.sink.Get(csv_url + "&agent_id=d1");
        REQUIRE(host);
        CHECK(host->status == 200);
        // The per-device export's newest_version cell reads the rollup: blank until first refresh.
        const auto row_start = host->body.find('\n');
        REQUIRE(row_start != std::string::npos);
        const auto row_end = host->body.find('\n', row_start + 1);
        REQUIRE(row_end != std::string::npos);
        CHECK(host->body[row_end - 1] == ',');
        auto page = h.sink.Get(kCat);
        REQUIRE(page);
        CHECK(page->status == 200);
        CHECK(data_of(page).at("kpis").at("building") == true);
    }
    SECTION("a deleted meta row stays building and the refresh does not revive it") {
        {
            auto lease = pool.try_acquire_for(std::chrono::seconds{5});
            REQUIRE(lease);
            REQUIRE(yuzu::server::pg::exec_params(
                        lease.get(), "DELETE FROM software_inventory_store.catalog_rollup_meta",
                        std::vector<std::string>{})
                        .status() == PGRES_COMMAND_OK);
        }
        CatHarness h{&store};
        expect_building(h.sink.Get(csv_url));
        expect_building(h.sink.Get(ver_url));
        CHECK_FALSE(store.refresh_catalog_rollup());
        expect_building(h.sink.Get(csv_url));
        expect_building(h.sink.Get(ver_url));
    }
    SECTION("a confined caller is denied before the building check (403 + denied, never 503)") {
        CatHarness h{&store};
        h.fleet_scope = std::unordered_set<std::string>{"d1"};
        for (const auto& url : {csv_url, ver_url}) {
            auto r = h.sink.Get(url);
            REQUIRE(r);
            CHECK(r->status == 403);
            CHECK(err_of(r).at("permission") == "Inventory:Read");
        }
        CHECK(h.audits("inventory.software.export", "denied") == 1);
        CHECK(h.audits("inventory.software.versions", "denied") == 1);
        for (const char* verb : {"inventory.software.export", "inventory.software.versions"})
            CHECK(h.audits(verb, "failure") == 0);
    }
    SECTION("once the first refresh lands both arms serve") {
        REQUIRE(store.refresh_catalog_rollup());
        CatHarness h{&store};
        auto csv = h.sink.Get(csv_url);
        REQUIRE(csv);
        CHECK(csv->status == 200);
        auto ver = h.sink.Get(ver_url);
        REQUIRE(ver);
        CHECK(ver->status == 200);
        CHECK(data_of(ver).at("count") == 3);
    }
}
