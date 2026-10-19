// /crypto slice 1: the local CryptoApi over the REAL SoftwareInventoryStore - scope push-down
// (TOP vs set vs empty), degrade -> kDegraded (never an empty answer), the hostname join, the
// filter-bound cursor.

#include "crypto_api_local.hpp"

#include "crypto_library_model.hpp"
#include "device_api.hpp"
#include "crypto_routes.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "software_inventory_store.hpp"
#include "ca_store.hpp"
#include "crypto_dashboard_layout_store.hpp"
#include "crypto_shared_read.hpp"
#include "crypto_widget_catalogue.hpp"

#include "../test_helpers.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <yuzu/metrics.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <thread>
#include <tuple>
#include <utility>
#include <memory>
#include <optional>
#include <unordered_set>
#include <chrono>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
namespace pg = yuzu::server::pg;
namespace cl = yuzu::server::crypto_library;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgResult;

namespace {

yuzu::test::PgTestTemplate crypto_tpl{"cryptoapi", [](const std::string& dsn) {
                                          PgPool pool{{.conninfo = dsn, .size = 1}};
                                          SoftwareInventoryStore store{pool};
                                          if (!store.is_open())
                                              throw std::runtime_error(
                                                  "cryptoapi template: store failed to migrate");
                                      }};

SoftwareEntry ent(std::string name, std::string version, std::string eco = "deb") {
    SoftwareEntry e;
    e.name = std::move(name);
    e.version = std::move(version);
    e.kind = "package";
    e.ecosystem = std::move(eco);
    e.release = "r1";
    return e;
}

// The reads take package NAMES from the hourly catalogue rollup, so seeding refreshes it by
// default (a test about the un-refreshed state passes refresh=false).
void seed(SoftwareInventoryStore& s, const std::string& agent, std::vector<SoftwareEntry> rows,
          bool refresh = true) {
    const auto h = SoftwareInventoryStore::canonical_hash(rows);
    REQUIRE(s.apply_installed_software(agent, h, std::move(rows), 1000) ==
            InventoryIngestOutcome::kStored);
    if (refresh)
        REQUIRE(s.refresh_catalog_rollup());
}

// Force the catalogue's age on the DB clock (the freshness test uses the same clock).
void set_catalogue_age(PgPool& pool, long long age_seconds) {
    auto l = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(l);
    const std::vector<std::string> p{std::to_string(age_seconds)};
    REQUIRE(pg::exec_params(l.get(),
                            "UPDATE software_inventory_store.catalog_rollup_meta SET refreshed_at = "
                            "extract(epoch FROM now())::bigint - $1::bigint WHERE id = 1",
                            p)
                .status() == PGRES_COMMAND_OK);
}

std::shared_ptr<CryptoApi> routes_api_for(CryptoRoutes& routes,
                                          yuzu::server::test::TestRouteSink& sink,
                                          std::shared_ptr<CryptoApi> api,
                                          std::vector<std::string>* details = nullptr) {
    CryptoRoutes::Deps deps;
    deps.auth_fn = [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session sess;
        sess.username = "u";
        sess.role = auth::Role::user;
        return sess;
    };
    deps.fleet_read_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                            const std::string&) -> authz::FleetReadGate { return {true, std::nullopt}; };
    deps.api = api;
    deps.audit_fn = [details](const httplib::Request&, const std::string&, const std::string& result,
                              const std::string&, const std::string&, const std::string& detail) {
        if (details)
            details->push_back(result + "|" + detail);
        return true;
    };
    routes.register_routes(sink, std::move(deps));
    return api;
}

// Runs a callback at scope exit (every exit, a throwing REQUIRE included).
struct OnExit {
    std::function<void()> fn;
    OnExit(std::function<void()> f) : fn(std::move(f)) {}
    OnExit(const OnExit&) = delete;
    OnExit& operator=(const OnExit&) = delete;
    ~OnExit() { fn(); }
};

class FakeDevices : public DeviceApi {
public:
    std::vector<DeviceListRow> list_devices() const override {
        return {{"a1", "alpha", "linux", "x86_64", "1"}, {"a2", "bravo", "linux", "x86_64", "1"}};
    }
    std::expected<std::optional<DeviceDetail>, DeviceReadError>
    lookup_device(const std::string&) const override {
        return std::nullopt;
    }
};

struct Fx {
    PgPool pool;
    SoftwareInventoryStore store;
    explicit Fx(const std::string& dsn, bool refresh = true)
        : pool(PgPool::Options{.conninfo = dsn, .size = 4}), store(pool) {
        REQUIRE(store.is_open());
        seed(store, "a1", {ent("libssl3", "3.0.13"), ent("openssl", "3.0.13")}, refresh);
        seed(store, "a2", {ent("libssl3", "3.0.13")}, refresh);
        seed(store, "a3", {ent("libssl3", "1.1.1", "rpm"), ent("libgnutls30", "3.7.9")}, refresh);
        seed(store, "a4", {ent("curl", "8.0")}, refresh);
    }
};

authz::VisibleSet set_of(std::initializer_list<const char*> ids) {
    std::unordered_set<std::string> s;
    for (const char* i : ids)
        s.insert(i);
    return authz::VisibleSet{std::move(s)};
}

} // namespace

TEST_CASE("CryptoApi summary: scope push-down TOP vs set vs empty", "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()};
    auto api = make_local_crypto_api(fx.store, nullptr);

    SECTION("TOP sees the whole fleet") {
        auto r = api->library_summary({}, std::nullopt);
        REQUIRE(r.has_value());
        CHECK(r->coverage.devices_reporting_inventory == 4);
        CHECK(r->coverage.devices_with_crypto_library == 3);
        REQUIRE(r->families.size() == 2);
        CHECK(r->families[0].id == "openssl");
        CHECK(r->families[0].display == "OpenSSL");
        CHECK(r->families[0].device_count == 3);
        CHECK(r->families[1].id == "gnutls");
        REQUIRE(r->families[0].versions.size() == 2);
        CHECK(r->families[0].versions[0].version == "3.0.13");
        CHECK(r->families[0].versions[0].device_count == 2);
        CHECK(r->families[0].versions[0].package_names ==
              std::vector<std::string>{"libssl3", "openssl"});
        CHECK_FALSE(r->result_truncated);
    }

    SECTION("a set narrows families, versions and coverage alike") {
        auto r = api->library_summary({}, set_of({"a2", "a4"}));
        REQUIRE(r.has_value());
        CHECK(r->coverage.devices_reporting_inventory == 2);
        CHECK(r->coverage.devices_with_crypto_library == 1);
        REQUIRE(r->families.size() == 1);
        CHECK(r->families[0].device_count == 1);
        CHECK(r->families[0].versions.size() == 1);
    }

    SECTION("an empty scope is zero rows, not the fleet") {
        auto r = api->library_summary({}, authz::deny_all());
        REQUIRE(r.has_value());
        CHECK(r->families.empty());
        CHECK(r->coverage.devices_reporting_inventory == 0);
        CHECK(r->coverage.devices_with_crypto_library == 0);
    }

    SECTION("family and ecosystem filters") {
        CryptoSummaryQuery q;
        q.family = "gnutls";
        auto r = api->library_summary(q, std::nullopt);
        REQUIRE(r.has_value());
        REQUIRE(r->families.size() == 1);
        CHECK(r->families[0].id == "gnutls");

        q = {};
        q.ecosystem = "rpm";
        r = api->library_summary(q, std::nullopt);
        REQUIRE(r.has_value());
        REQUIRE(r->families.size() == 1); // only a3's libssl3 is rpm
        CHECK(r->families[0].id == "openssl");
    }

    SECTION("an unknown family is refused, not an empty answer") {
        CryptoSummaryQuery q;
        q.family = "nope";
        auto r = api->library_summary(q, std::nullopt);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == CryptoReadError::Kind::kInvalid);
    }
}

TEST_CASE("CryptoApi devices: hostname join; paging; scope", "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()};
    FakeDevices devs;
    auto api = make_local_crypto_api(fx.store, &devs);

    CryptoDevicesQuery q;
    q.family = "openssl";

    SECTION("hostnames join where the registry knows the device") {
        auto r = api->library_devices(q, std::nullopt);
        REQUIRE(r.has_value());
        REQUIRE(r->devices.size() == 4);
        CHECK(r->devices[0].agent_id == "a1");
        CHECK(r->devices[0].hostname == "alpha");
        CHECK(r->devices[0].release == "r1");
        CHECK(r->devices[3].agent_id == "a3");
        CHECK(r->devices[3].hostname.empty()); // unknown to the registry
        CHECK(r->next_cursor.empty());
        CHECK(r->family == "openssl");
    }

    SECTION("a null DeviceApi leaves hostnames empty") {
        auto bare = make_local_crypto_api(fx.store, nullptr);
        auto r = bare->library_devices(q, std::nullopt);
        REQUIRE(r.has_value());
        CHECK(r->devices[0].hostname.empty());
    }

    SECTION("cursor pages cover every row once; a cursor from another filter is refused") {
        q.limit = 3;
        auto p1 = api->library_devices(q, std::nullopt);
        REQUIRE(p1.has_value());
        CHECK(p1->devices.size() == 3);
        REQUIRE_FALSE(p1->next_cursor.empty());

        q.cursor = p1->next_cursor;
        auto p2 = api->library_devices(q, std::nullopt);
        REQUIRE(p2.has_value());
        CHECK(p2->devices.size() == 1);
        CHECK(p2->next_cursor.empty());
        CHECK(p2->devices[0].agent_id == "a3");

        CryptoDevicesQuery other = q;
        other.version = "3.0.13"; // different filter set, same token
        auto bad = api->library_devices(other, std::nullopt);
        REQUIRE_FALSE(bad.has_value());
        CHECK(bad.error().kind == CryptoReadError::Kind::kInvalid);

        q.cursor = "garbage";
        bad = api->library_devices(q, std::nullopt);
        REQUIRE_FALSE(bad.has_value());
        CHECK(bad.error().kind == CryptoReadError::Kind::kInvalid);
    }

    SECTION("scope push-down: set keeps pages full, empty is zero rows") {
        q.limit = 2;
        auto r = api->library_devices(q, set_of({"a2", "a3"}));
        REQUIRE(r.has_value());
        CHECK(r->devices.size() == 2);
        CHECK(r->next_cursor.empty());
        for (const auto& d : r->devices)
            CHECK(d.agent_id != "a1");

        auto none = api->library_devices(q, authz::deny_all());
        REQUIRE(none.has_value());
        CHECK(none->devices.empty());
        CHECK(none->next_cursor.empty());
    }

    SECTION("version filter") {
        q.version = "1.1.1";
        auto r = api->library_devices(q, std::nullopt);
        REQUIRE(r.has_value());
        REQUIRE(r->devices.size() == 1);
        CHECK(r->devices[0].agent_id == "a3");
        CHECK(r->version == std::optional<std::string>("1.1.1"));
    }

    SECTION("an unknown family is refused") {
        q.family = "nope";
        auto r = api->library_devices(q, std::nullopt);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().kind == CryptoReadError::Kind::kInvalid);
    }
}

TEST_CASE("CryptoApi: a degraded store is kDegraded; never an empty answer", "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()};
    auto api = make_local_crypto_api(fx.store, nullptr);
    {
        auto lease = fx.pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult drop = pg::exec_params(lease.get(), "DROP SCHEMA software_inventory_store CASCADE",
                                            std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
    }
    auto s = api->library_summary({}, std::nullopt);
    REQUIRE_FALSE(s.has_value());
    CHECK(s.error().kind == CryptoReadError::Kind::kDegraded);
    CHECK(s.error().cause == CryptoReadCause::kStoreDegraded);
    CHECK(s.error().message == "crypto library read degraded");

    CryptoDevicesQuery q;
    q.family = "openssl";
    auto d = api->library_devices(q, std::nullopt);
    REQUIRE_FALSE(d.has_value());
    CHECK(d.error().kind == CryptoReadError::Kind::kDegraded);
    CHECK(d.error().cause == CryptoReadCause::kStoreDegraded);

    // On REST the two 503 causes are worded apart, and the failure audit names the cause.
    CryptoRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    std::vector<std::string> details;
    routes_api_for(routes, sink, api, &details);
    for (const char* path :
         {"/api/v1/crypto/libraries", "/api/v1/crypto/libraries/devices?family=openssl"}) {
        auto r = sink.dispatch("GET", path);
        REQUIRE(r);
        CHECK(r->status == 503);
        CHECK(nlohmann::json::parse(r->body)["error"]["message"] == "crypto library read degraded");
    }
    REQUIRE(details.size() == 2);
    for (const auto& dtl : details) {
        CHECK(dtl.find("store degraded") != std::string::npos);
        CHECK(dtl.find("capacity in use") == std::string::npos);
    }
}

TEST_CASE("CryptoApi devices: a cursor from another table version is refused with a restart "
          "message",
          "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()};
    auto api = make_local_crypto_api(fx.store, nullptr);
    CryptoDevicesQuery q;
    q.family = "openssl";
    q.limit = 3;
    auto p1 = api->library_devices(q, std::nullopt);
    REQUIRE(p1.has_value());
    REQUIRE_FALSE(p1->next_cursor.empty());
    // Re-mint the same position under the PREVIOUS table version.
    const auto pos = cl::decode_cursor(p1->next_cursor, cl::devices_fingerprint(q));
    REQUIRE(pos);
    q.cursor = cl::encode_cursor(*pos, cl::devices_fingerprint(q, cl::kCryptoTableVersion - 1));
    auto bad = api->library_devices(q, std::nullopt);
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error().kind == CryptoReadError::Kind::kInvalid);
    CHECK(bad.error().message.find("table version") != std::string::npos);
    CHECK(bad.error().message.find("restart") != std::string::npos);
    // The un-tampered cursor still works.
    q.cursor = p1->next_cursor;
    CHECK(api->library_devices(q, std::nullopt).has_value());
}

namespace {
// Walks the openssl drill one row per page; returns the total number of rows seen, or -1 when a
// continuation page was refused (`refused`, if given, gets the refusal). `between` runs after
// every page that has a successor.
int walk_openssl(CryptoApi& api, const std::function<void()>& between,
                 std::optional<CryptoReadError>* refused = nullptr) {
    CryptoDevicesQuery q;
    q.family = "openssl";
    q.limit = 1;
    int rows = 0;
    for (int guard = 0; guard < 50; ++guard) {
        auto page = api.library_devices(q, std::nullopt);
        if (!page) {
            if (refused)
                *refused = page.error();
            return -1;
        }
        rows += static_cast<int>(page->devices.size());
        if (page->next_cursor.empty())
            return rows;
        q.cursor = page->next_cursor;
        if (between)
            between();
    }
    return rows;
}

// Like walk_openssl, but returns the "agent|package" of every row seen, in order.
// `between(page_index)` runs after every page that has a successor.
std::vector<std::string> walk_openssl_rows(CryptoApi& api,
                                           const std::function<void(int)>& between) {
    CryptoDevicesQuery q;
    q.family = "openssl";
    q.limit = 1;
    std::vector<std::string> out;
    for (int guard = 0; guard < 50; ++guard) {
        auto page = api.library_devices(q, std::nullopt);
        REQUIRE(page.has_value());
        for (const auto& d : page->devices)
            out.push_back(d.agent_id + "|" + d.package_name);
        if (page->next_cursor.empty())
            return out;
        q.cursor = page->next_cursor;
        if (between)
            between(guard);
    }
    return out;
}
} // namespace

TEST_CASE("CryptoApi devices: a walk begun on the live names is refused (restart) once a refresh "
          "makes the catalogue the source",
          "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn(), /*refresh=*/false}; // never built: the names are read live
    auto api = make_local_crypto_api(fx.store, nullptr);
    const int stable = walk_openssl(*api, {});
    REQUIRE(stable > 1);

    std::optional<CryptoReadError> refused;
    CHECK(walk_openssl(*api, [&] { REQUIRE(fx.store.refresh_catalog_rollup()); }, &refused) == -1);
    REQUIRE(refused);
    CHECK(refused->kind == CryptoReadError::Kind::kInvalid);
    CHECK(refused->message.find("restart") != std::string::npos);
    CHECK(refused->message.find("names_as_of") != std::string::npos);

    // A restarted walk (now on the catalogue) completes, and is never refused again.
    CHECK(walk_openssl(*api, {}) == stable);
    CHECK(walk_openssl(*api, [&] { REQUIRE(fx.store.refresh_catalog_rollup()); }) == stable);
}

TEST_CASE("CryptoApi devices: a walk is refused again when the catalogue goes stale and recovers "
          "mid-walk; and the restarted walk completes",
          "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()}; // fresh catalogue
    auto api = make_local_crypto_api(fx.store, nullptr);
    const int stable = walk_openssl(*api, {});
    REQUIRE(stable > 2);

    CryptoDevicesQuery q;
    q.family = "openssl";
    q.limit = 1;
    auto p1 = api->library_devices(q, std::nullopt);
    REQUIRE(p1.has_value());
    REQUIRE(p1->names_as_of > 0); // began on the catalogue
    REQUIRE_FALSE(p1->next_cursor.empty());

    // The catalogue ages out: the next page is read live (a continue, never a refusal).
    set_catalogue_age(fx.pool, kCatalogueFreshSeconds + 60);
    q.cursor = p1->next_cursor;
    auto p2 = api->library_devices(q, std::nullopt);
    REQUIRE(p2.has_value());
    CHECK(p2->names_as_of == 0);
    REQUIRE_FALSE(p2->next_cursor.empty());

    // The catalogue recovers (a real refresh): the cursor was issued on live names, so the
    // next page is refused.
    REQUIRE(fx.store.refresh_catalog_rollup());
    q.cursor = p2->next_cursor;
    auto p3 = api->library_devices(q, std::nullopt);
    REQUIRE_FALSE(p3.has_value());
    CHECK(p3.error().kind == CryptoReadError::Kind::kInvalid);
    CHECK(p3.error().message.find("restart") != std::string::npos);

    // The restarted walk (on the catalogue) completes.
    CHECK(walk_openssl(*api, {}) == stable);
}

TEST_CASE("CryptoApi devices: a walk begun on the catalogue continues when the catalogue ages out "
          "(live lists every name) and completes with the full row set",
          "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()}; // fresh catalogue
    auto api = make_local_crypto_api(fx.store, nullptr);
    const int stable = walk_openssl(*api, {});
    REQUIRE(stable > 1);
    CHECK(walk_openssl(*api, {}) == stable);

    std::optional<CryptoReadError> refused;
    CHECK(walk_openssl(*api, [&] { set_catalogue_age(fx.pool, kCatalogueFreshSeconds + 60); },
                       &refused) == stable);
    CHECK_FALSE(refused);
    // The stale state is itself a stable (live) source for a restarted walk.
    CHECK(walk_openssl(*api, {}) == stable);
}

TEST_CASE("CryptoApi devices: a walk that sees a newer catalogue refresh (even two) mid-walk "
          "continues and lists every row of the names already listed",
          "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()}; // fresh catalogue
    auto api = make_local_crypto_api(fx.store, nullptr);
    const auto before = walk_openssl_rows(*api, {});
    REQUIRE(before.size() > 2);

    // Each page boundary lands on a catalogue with a different (newer) stamp: the stamp is
    // second-granular, so step it forward explicitly rather than rely on wall time. After the
    // first page the CONTENT also changes and a REAL refresh runs: a row for an already-listed
    // name on an agent after the cursor, and a row with a name new to the catalogue on another
    // agent after the cursor. Both belong to devices the walk has not reached yet.
    long long age = 600;
    set_catalogue_age(fx.pool, age);
    const auto seen = walk_openssl_rows(*api, [&](int page) {
        if (page == 0) {
            seed(fx.store, "a5", {ent("libssl3", "3.0.13")});     // already-listed name
            seed(fx.store, "a6", {ent("libssl-dev", "3.0.13")});  // name new to the catalogue
        }
        age -= 100;
        set_catalogue_age(fx.pool, age);
    });
    CHECK(seen.size() == before.size() + 2);
    CHECK(std::ranges::count(seen, "a5|libssl3") == 1);
    CHECK(std::ranges::count(seen, "a6|libssl-dev") == 1);
    for (const auto& r : before)
        CHECK(std::ranges::count(seen, r) == 1);
}

TEST_CASE("CryptoApi devices: a name with no rows at a refresh is missed for the rest of the walk "
          "(documented residual) and listed by a restarted walk after the next refresh",
          "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()}; // fresh catalogue; "openssl" exists only on a1
    auto api = make_local_crypto_api(fx.store, nullptr);

    // Page 1 and 2: a1|libssl3, a1|openssl - the walk has listed X = "openssl" on a1.
    CryptoDevicesQuery q;
    q.family = "openssl";
    q.limit = 1;
    auto p1 = api->library_devices(q, std::nullopt);
    REQUIRE(p1.has_value());
    REQUIRE(p1->devices.size() == 1);
    q.cursor = p1->next_cursor;
    auto p2 = api->library_devices(q, std::nullopt);
    REQUIRE(p2.has_value());
    REQUIRE(p2->devices.size() == 1);
    CHECK(p2->devices[0].agent_id == "a1");
    CHECK(p2->devices[0].package_name == "openssl");
    REQUIRE_FALSE(p2->next_cursor.empty());

    // X loses every row, and a real refresh runs: X is absent from the new catalogue.
    seed(fx.store, "a1", {ent("libssl3", "3.0.13")});
    // X reappears for an agent after the cursor, before the next refresh.
    seed(fx.store, "a5", {ent("openssl", "3.0.13")}, /*refresh=*/false);

    // The continued walk (catalogue -> newer catalogue, so no refusal) does not list it.
    std::vector<std::string> rest;
    q.cursor = p2->next_cursor;
    for (int guard = 0; guard < 50; ++guard) {
        auto page = api->library_devices(q, std::nullopt);
        REQUIRE(page.has_value());
        for (const auto& d : page->devices)
            rest.push_back(d.agent_id + "|" + d.package_name);
        if (page->next_cursor.empty())
            break;
        q.cursor = page->next_cursor;
    }
    CHECK_FALSE(rest.empty());
    CHECK(std::ranges::count(rest, "a5|openssl") == 0);

    // A fresh walk on the same stale-by-one-refresh catalogue misses it too (the catalogue lag)...
    const auto lagged = walk_openssl_rows(*api, {});
    CHECK(std::ranges::count(lagged, "a5|openssl") == 0);
    // ...and a restart without a cursor after the next refresh lists it.
    REQUIRE(fx.store.refresh_catalog_rollup());
    const auto restarted = walk_openssl_rows(*api, {});
    CHECK(std::ranges::count(restarted, "a5|openssl") == 1);
}

TEST_CASE("CryptoApi: a catalogue stamp more than five minutes in the future is stale (live names)",
          "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()};
    auto api = make_local_crypto_api(fx.store, nullptr);
    auto from_catalogue = [&] {
        const auto s = api->library_summary({}, std::nullopt);
        REQUIRE(s.has_value());
        return s->names_from_catalogue;
    };
    CHECK(from_catalogue());
    set_catalogue_age(fx.pool, -60); // a minute ahead: inside the skew allowance
    CHECK(from_catalogue());
    set_catalogue_age(fx.pool, -3600); // an hour ahead: not a valid refresh time
    CHECK_FALSE(from_catalogue());
}

TEST_CASE("CryptoApi summary: coverage numerator never exceeds the denominator; even with package "
          "rows that have no inventory_state row",
          "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()};
    auto api = make_local_crypto_api(fx.store, nullptr);
    {
        auto lease = fx.pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        // A partial cascade: a1 and a2 keep package rows but lost their state rows.
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "DELETE FROM software_inventory_store.inventory_state WHERE agent_id IN ('a1','a2')",
            std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    auto s = api->library_summary({}, std::nullopt);
    REQUIRE(s.has_value());
    CHECK(s->coverage.devices_with_crypto_library == 3);
    CHECK(s->coverage.devices_reporting_inventory >= s->coverage.devices_with_crypto_library);
    auto scoped = api->library_summary({}, set_of({"a1", "a4"}));
    REQUIRE(scoped.has_value());
    CHECK(scoped->coverage.devices_reporting_inventory >= scoped->coverage.devices_with_crypto_library);
}

TEST_CASE("CryptoApi: a present-empty ecosystem is the exact empty ecosystem", "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()};
    seed(fx.store, "a9", {ent("libssl3", "3.0.99", "")});
    auto api = make_local_crypto_api(fx.store, nullptr);

    CryptoSummaryQuery sq;
    sq.ecosystem = "";
    auto s = api->library_summary(sq, std::nullopt);
    REQUIRE(s.has_value());
    REQUIRE(s->families.size() == 1);
    CHECK(s->families[0].device_count == 1);
    REQUIRE(s->families[0].versions.size() == 1);
    CHECK(s->families[0].versions[0].version == "3.0.99");

    CryptoDevicesQuery dq;
    dq.family = "openssl";
    dq.ecosystem = "";
    auto d = api->library_devices(dq, std::nullopt);
    REQUIRE(d.has_value());
    REQUIRE(d->devices.size() == 1);
    CHECK(d->devices[0].agent_id == "a9");
    // absent = any: all five openssl devices' rows.
    dq.ecosystem.reset();
    auto all = api->library_devices(dq, std::nullopt);
    REQUIRE(all.has_value());
    CHECK(all->devices.size() == 5);
}

TEST_CASE("CryptoApi summary: one hostile agent with thousands of versions and 1 KiB names cannot "
          "grow or silently reshape the response",
          "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()};
    std::vector<SoftwareEntry> rows;
    for (int i = 0; i < 3000; ++i)
        rows.push_back(ent("libssl3" + std::string(i < 40 ? 1000 : 0, 'x'), "0." + std::to_string(i)));
    seed(fx.store, "hostile", std::move(rows));
    for (int i = 0; i < 5; ++i)
        seed(fx.store, "norm" + std::to_string(i), {ent("libssl3", "3.0.13")});

    auto api = make_local_crypto_api(fx.store, nullptr);
    auto s = api->library_summary({}, std::nullopt);
    REQUIRE(s.has_value());
    const auto body = cl::dump_safe(cl::summary_json(*s));
    CHECK(body.size() < cl::kSummaryByteBudget);
    REQUIRE_FALSE(s->families.empty());
    const CryptoFamilyRow* ossl = nullptr;
    for (const auto& f : s->families)
        if (f.id == "openssl")
            ossl = &f;
    REQUIRE(ossl);
    CHECK(ossl->versions.size() <= cl::kMaxVersionsPerFamily);
    CHECK(ossl->versions_truncated);
    CHECK(s->result_truncated); // 3,000 version rows exceed the store row cap too
    // The eviction is by popularity, so the legitimate bucket survives the hostile flood.
    REQUIRE_FALSE(ossl->versions.empty());
    CHECK(ossl->versions[0].version == "3.0.13");
    CHECK(ossl->versions[0].device_count >= 5);
    for (const auto& v : ossl->versions)
        for (const auto& n : v.package_names)
            CHECK(n.size() <= cl::kNameMaxBytes);
}

TEST_CASE("CryptoRoutes over the real store: a scoped gate yields only in-scope devices and counts",
          "[pg][crypto][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()};
    FakeDevices devs;
    std::shared_ptr<CryptoApi> api = make_local_crypto_api(fx.store, &devs);

    CryptoRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    CryptoRoutes::Deps d;
    d.auth_fn = [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "scoped";
        s.role = auth::Role::user;
        return s;
    };
    d.fleet_read_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                         const std::string&) -> authz::FleetReadGate {
        return {true, std::unordered_set<std::string>{"a1", "a4"}};
    };
    d.api = api;
    d.audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                    const std::string&, const std::string&, const std::string&) { return true; };
    routes.register_routes(sink, std::move(d));

    auto sum = sink.dispatch("GET", "/api/v1/crypto/libraries");
    REQUIRE(sum);
    REQUIRE(sum->status == 200);
    const auto sj = nlohmann::json::parse(sum->body)["data"];
    CHECK(sj["coverage"]["devices_reporting_inventory"] == 2);
    CHECK(sj["coverage"]["devices_with_crypto_library"] == 1);
    REQUIRE(sj["families"].size() == 1);
    CHECK(sj["families"][0]["id"] == "openssl");
    CHECK(sj["families"][0]["device_count"] == 1);

    auto dev = sink.dispatch("GET", "/api/v1/crypto/libraries/devices?family=openssl");
    REQUIRE(dev);
    REQUIRE(dev->status == 200);
    const auto dj = nlohmann::json::parse(dev->body)["data"];
    REQUIRE(dj["devices"].size() == 2); // a1's libssl3 + openssl, nothing of a2/a3
    for (const auto& row : dj["devices"])
        CHECK(row["agent_id"] == "a1");
    CHECK(dj["table_version"] == cl::kCryptoTableVersion);
}

// ── Admission bound (A2): at most N store reads in flight, the rest refused at once ──────────

TEST_CASE("CryptoReadGate: the bound is exact; refusal is non-blocking; release is RAII",
          "[crypto]") {
    CryptoReadGate gate{2};
    auto a = gate.try_acquire();
    auto b = gate.try_acquire();
    REQUIRE(a);
    REQUIRE(b);
    CHECK(gate.in_flight() == 2);
    {
        auto c = gate.try_acquire();
        CHECK_FALSE(c); // third refused, nothing counted
        CHECK(gate.in_flight() == 2);
    }
    a = CryptoReadGate::Lease{}; // release one
    CHECK(gate.in_flight() == 1);
    auto d = gate.try_acquire();
    CHECK(d);
    CHECK(gate.in_flight() == 2);

    // Release on an exception path.
    CryptoReadGate g2{1};
    try {
        auto l = g2.try_acquire();
        REQUIRE(l);
        throw std::runtime_error("store threw");
    } catch (const std::runtime_error&) {
    }
    CHECK(g2.in_flight() == 0);
    CHECK(g2.try_acquire());

    // A zero bound refuses everything.
    CryptoReadGate g0{0};
    CHECK_FALSE(g0.try_acquire());
}

TEST_CASE("CryptoApi: reads over the bound are refused as kDegraded with no store call and counted",
          "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()};
    yuzu::MetricsRegistry metrics;
    fx.store.set_metrics(&metrics);
    auto api = make_local_crypto_api(fx.store, nullptr, /*max_concurrent_reads=*/0);

    auto s = api->library_summary({}, std::nullopt);
    REQUIRE_FALSE(s.has_value());
    CHECK(s.error().kind == CryptoReadError::Kind::kDegraded);
    CHECK(s.error().message == "crypto read capacity in use; retry");
    CHECK(s.error().cause == CryptoReadCause::kCapacity);
    CryptoDevicesQuery q;
    q.family = "openssl";
    auto d = api->library_devices(q, std::nullopt);
    REQUIRE_FALSE(d.has_value());
    CHECK(d.error().kind == CryptoReadError::Kind::kDegraded);
    CHECK(d.error().cause == CryptoReadCause::kCapacity);

    CHECK(metrics
              .counter("yuzu_inventory_read_degrade_total",
                       {{"reason", "admission_full"}, {"source", "installed_software"}})
              .value() == 2.0);
    // No store call happened: none of the store's own degrade reasons moved.
    for (const char* r : {"store_not_open", "pool_acquire_timeout", "query_error"})
        CHECK(metrics
                  .counter("yuzu_inventory_read_degrade_total",
                           {{"reason", r}, {"source", "installed_software"}})
                  .value() == 0.0);
}

TEST_CASE("CryptoApi: with two reads genuinely in flight the third is refused at once; and a new "
          "read succeeds after release",
          "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()};
    auto api = make_local_crypto_api(fx.store, nullptr); // default bound = kMaxConcurrentCryptoReads
    static_assert(kMaxConcurrentCryptoReads == 2);

    // Block the store's reads on a table lock held by this test; release it on demand.
    auto locker = fx.pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(locker);
    const std::vector<std::string> none;
    // Declared BEFORE the threads and the cleanup guard, so the guard (destroyed first) joins the
    // readers before `ok` and `reader` die.
    std::atomic<int> ok{0};
    auto reader = [&] {
        if (api->library_summary({}, std::nullopt).has_value())
            ++ok;
    };
    bool locked = true;
    // Idempotent: the success path releases early, the guard releases on every other exit.
    auto release_lock = [&] {
        if (locked) {
            locked = false;
            pg::exec_params(locker.get(), "ROLLBACK", none);
        }
    };
    std::thread t1;
    std::thread t2;
    // On EVERY exit (a throwing REQUIRE included): release the lock so the readers finish, then
    // join both threads - a joinable std::thread destructor would std::terminate the run.
    OnExit cleanup{[&] {
        try {
            release_lock();
        } catch (...) {
        }
        // Unconditionally after the release (its own try above): a throw there must not skip the
        // joins, or a joinable std::thread destructor would std::terminate.
        if (t1.joinable())
            t1.join();
        if (t2.joinable())
            t2.join();
    }};
    REQUIRE(pg::exec_params(locker.get(), "BEGIN", none).status() == PGRES_COMMAND_OK);
    REQUIRE(pg::exec_params(locker.get(),
                            "LOCK TABLE software_inventory_store.installed_software IN ACCESS "
                            "EXCLUSIVE MODE",
                            none)
                .status() == PGRES_COMMAND_OK);

    t1 = std::thread{reader};
    t2 = std::thread{reader};

    // Wait by POLLING until both readers are genuinely inside the store, i.e. two backends are
    // blocked on the table lock (10 s ceiling), never a fixed sleep.
    int waiting = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
    while (waiting < 2 && std::chrono::steady_clock::now() < deadline) {
        {
            auto probe = fx.pool.try_acquire_for(std::chrono::seconds{5});
            REQUIRE(probe);
            auto res = pg::exec_params(probe.get(),
                                       "SELECT count(*) FROM pg_stat_activity WHERE datname = "
                                       "current_database() AND wait_event_type = 'Lock' AND pid <> "
                                       "pg_backend_pid()",
                                       none);
            REQUIRE(res.status() == PGRES_TUPLES_OK);
            waiting = std::atoi(PQgetvalue(res.get(), 0, 0));
        }
        if (waiting < 2)
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
    }
    REQUIRE(waiting == 2);

    const auto t0 = std::chrono::steady_clock::now();
    auto third = api->library_summary({}, std::nullopt);
    const auto took = std::chrono::steady_clock::now() - t0;
    REQUIRE_FALSE(third.has_value());
    CHECK(third.error().kind == CryptoReadError::Kind::kDegraded);
    CHECK(third.error().cause == CryptoReadCause::kCapacity);
    CHECK(third.error().message == "crypto read capacity in use; retry");
    CHECK(took < std::chrono::milliseconds{1000}); // refused, not queued behind the lock

    release_lock(); // release the table
    t1.join();
    t2.join();
    CHECK(ok.load() == 2);
    auto after = api->library_summary({}, std::nullopt);
    CHECK(after.has_value()); // the leases were released
}

TEST_CASE("CryptoRoutes: a read over the admission bound is a REST 503 with retry_after_ms",
          "[pg][crypto][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()};
    std::shared_ptr<CryptoApi> api = make_local_crypto_api(fx.store, nullptr, 0);

    CryptoRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    CryptoRoutes::Deps d;
    d.auth_fn = [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "u";
        s.role = auth::Role::user;
        return s;
    };
    d.fleet_read_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                         const std::string&) -> authz::FleetReadGate { return {true, std::nullopt}; };
    d.api = api;
    std::vector<std::string> details;
    d.audit_fn = [&](const httplib::Request&, const std::string&, const std::string& result,
                     const std::string&, const std::string&, const std::string& detail) {
        details.push_back(result + "|" + detail);
        return true;
    };
    routes.register_routes(sink, std::move(d));

    for (const char* path : {"/api/v1/crypto/libraries", "/api/v1/crypto/libraries/devices?family=openssl"}) {
        auto r = sink.dispatch("GET", path);
        REQUIRE(r);
        CHECK(r->status == 503);
        const auto body = nlohmann::json::parse(r->body);
        INFO(r->body);
        CHECK(body["error"]["retry_after_ms"].is_number());
        CHECK(body["error"]["message"] == "crypto read capacity in use; retry");
    }
    // The refusal follows the degraded-read audit path.
    REQUIRE(details.size() == 2);
    for (const auto& dtl : details) {
        CHECK(dtl.find("capacity in use") != std::string::npos);
        CHECK(dtl.find("store degraded") == std::string::npos);
    }
}

// ── Step 1: catalogue when fresh, else live ─────────────────────────────────────────────────


TEST_CASE("CryptoApi: a catalogue that was never built falls back to live names; with correct "
          "counts; on every transport",
          "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn(), /*refresh=*/false}; // rows exist, the catalogue was never built
    auto api = make_local_crypto_api(fx.store, nullptr);

    const auto s = api->library_summary({}, std::nullopt);
    REQUIRE(s.has_value());
    CHECK_FALSE(s->names_from_catalogue);
    CHECK(s->names_as_of == 0);
    CHECK(s->coverage.devices_reporting_inventory == 4);
    CHECK(s->coverage.devices_with_crypto_library == 3);
    REQUIRE(s->families.size() == 2);
    CHECK(s->families[0].id == "openssl");
    CHECK(s->families[0].device_count == 3);
    const auto j = cl::summary_json(*s);
    CHECK(j["names_source"] == "live");
    CHECK(j["names_as_of"].is_null());

    CryptoDevicesQuery q;
    q.family = "openssl";
    const auto d = api->library_devices(q, std::nullopt);
    REQUIRE(d.has_value());
    CHECK_FALSE(d->names_from_catalogue);
    CHECK(d->devices.size() == 4); // a1 x2, a2, a3
    CHECK(cl::devices_json(*d)["names_source"] == "live");
    CHECK(cl::devices_json(*d)["names_as_of"].is_null());
    // An empty page still reports the source from the same statement.
    q.family = "botan";
    const auto e = api->library_devices(q, std::nullopt);
    REQUIRE(e.has_value());
    CHECK(e->devices.empty());
    CHECK_FALSE(e->names_from_catalogue);

    CryptoRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes_api_for(routes, sink, api);
    for (const char* path :
         {"/api/v1/crypto/libraries", "/api/v1/crypto/libraries/devices?family=openssl"}) {
        auto r = sink.dispatch("GET", path);
        REQUIRE(r);
        INFO(r->body);
        CHECK(r->status == 200);
        const auto body = nlohmann::json::parse(r->body);
        CHECK(body["data"]["names_source"] == "live");
        CHECK(body["data"]["names_as_of"].is_null());
    }
}

TEST_CASE("CryptoApi: a deny-all scope is an empty live answer with no catalogue consulted",
          "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn(), /*refresh=*/false};
    auto api = make_local_crypto_api(fx.store, nullptr);
    const auto s = api->library_summary({}, set_of({}));
    REQUIRE(s.has_value());
    CHECK(s->families.empty());
    CHECK_FALSE(s->names_from_catalogue);
    CHECK(s->names_as_of == 0);
    CryptoDevicesQuery q;
    q.family = "openssl";
    const auto d = api->library_devices(q, set_of({}));
    REQUIRE(d.has_value());
    CHECK(d->devices.empty());
    CHECK_FALSE(d->names_from_catalogue);
}

TEST_CASE("CryptoApi: a fresh catalogue supplies the names (a later name waits for the refresh); "
          "a stale one falls back to live and lists it",
          "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()};
    auto api = make_local_crypto_api(fx.store, nullptr);
    auto openssl_count = [&](bool* from_catalogue = nullptr) {
        const auto s = api->library_summary({}, std::nullopt);
        REQUIRE(s.has_value());
        if (from_catalogue)
            *from_catalogue = s->names_from_catalogue;
        for (const auto& f : s->families)
            if (f.id == "openssl")
                return f.device_count;
        return std::int64_t{0};
    };
    bool cat = false;
    CHECK(openssl_count(&cat) == 3); // a1, a2, a3
    CHECK(cat);

    // n2 carries an ALREADY-LISTED name (libssl3), n1 a brand-new one (libssl4); no refresh.
    seed(fx.store, "n2", {ent("libssl3", "3.0.13")}, /*refresh=*/false);
    seed(fx.store, "n1", {ent("libssl4", "4.0.0")}, /*refresh=*/false);

    CryptoDevicesQuery q;
    q.family = "openssl";
    q.limit = 1000;
    auto has_agent = [&](const char* id, bool* from_catalogue = nullptr) {
        const auto page = api->library_devices(q, std::nullopt);
        REQUIRE(page.has_value());
        if (from_catalogue)
            *from_catalogue = page->names_from_catalogue;
        return std::ranges::any_of(page->devices,
                                   [&](const CryptoDeviceRow& r) { return r.agent_id == id; });
    };

    SECTION("fresh: catalogue names, the new name is absent until the next refresh") {
        CHECK(openssl_count(&cat) == 4); // n2 is live, n1's new name is not listed yet
        CHECK(cat);
        CHECK(has_agent("n2", &cat));
        CHECK(cat);
        CHECK_FALSE(has_agent("n1"));
        REQUIRE(fx.store.refresh_catalog_rollup());
        CHECK(openssl_count() == 5);
        CHECK(has_agent("n1"));
    }

    SECTION("stale (older than kCatalogueFreshSeconds): live names, the new name is present") {
        set_catalogue_age(fx.pool, kCatalogueFreshSeconds + 60);
        CHECK(openssl_count(&cat) == 5);
        CHECK_FALSE(cat);
        CHECK(has_agent("n1", &cat));
        CHECK_FALSE(cat);
        // Just inside the threshold the catalogue is still used.
        set_catalogue_age(fx.pool, kCatalogueFreshSeconds - 60);
        CHECK(openssl_count(&cat) == 4);
        CHECK(cat);
        CHECK_FALSE(has_agent("n1"));
    }
}

TEST_CASE("CryptoApi: a failed refresh keeps serving the catalogue while its stamp is inside the "
          "window; then falls back to live",
          "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()};
    auto api = make_local_crypto_api(fx.store, nullptr);
    const auto stamp = [&] {
        const auto m = fx.store.catalog_rollup_meta();
        REQUIRE(m.has_value());
        return m->refreshed_at;
    };
    const auto before = stamp();
    REQUIRE(before > 0);

    // A new name arrives and the next refresh FAILS (cancelled: last-good rollup and stamp kept).
    seed(fx.store, "n1", {ent("libssl4", "4.0.0")}, /*refresh=*/false);
    CHECK_FALSE(fx.store.refresh_catalog_rollup([] { return true; }));
    CHECK(stamp() == before);

    auto summary = [&] {
        const auto s = api->library_summary({}, std::nullopt);
        REQUIRE(s.has_value());
        return *s;
    };
    auto openssl_devices = [](const CryptoSummary& s) {
        for (const auto& f : s.families)
            if (f.id == "openssl")
                return f.device_count;
        return std::int64_t{0};
    };

    // Inside the 7200 s window: still the catalogue, names_as_of unchanged, the new name absent.
    set_catalogue_age(fx.pool, kCatalogueFreshSeconds - 120);
    const auto inside_stamp = stamp();
    auto s = summary();
    CHECK(s.names_from_catalogue);
    CHECK(s.names_as_of == inside_stamp);
    CHECK(openssl_devices(s) == 3);
    CHECK(cl::summary_json(s)["names_source"] == "catalogue");

    // Past the window (the refresh is still failing): live names, the new name is picked up.
    set_catalogue_age(fx.pool, kCatalogueFreshSeconds + 120);
    CHECK_FALSE(fx.store.refresh_catalog_rollup([] { return true; }));
    s = summary();
    CHECK_FALSE(s.names_from_catalogue);
    CHECK(s.names_as_of == 0);
    CHECK(cl::summary_json(s)["names_source"] == "live");
    CHECK(cl::summary_json(s)["names_as_of"].is_null());
    CHECK(openssl_devices(s) == 4);
    CryptoDevicesQuery q;
    q.family = "openssl";
    q.limit = 1000;
    const auto page = api->library_devices(q, std::nullopt);
    REQUIRE(page.has_value());
    CHECK_FALSE(page->names_from_catalogue);
    CHECK(std::ranges::any_of(page->devices,
                              [](const CryptoDeviceRow& r) { return r.agent_id == "n1"; }));
}

TEST_CASE("CryptoApi: the catalogue and live paths give identical output on the same data",
          "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()}; // refreshed: every name is in the catalogue
    seed(fx.store, "a5", {ent("OpenSSL-libs", "3.2.0", "brew"), ent("libgnutls30", "3.7.9")}, true);
    auto api = make_local_crypto_api(fx.store, nullptr);

    auto strip = [](nlohmann::json j) {
        j.erase("names_source");
        j.erase("names_as_of");
        // The cursor binds the names source, so its bytes differ between the two paths by design;
        // whether another page follows must not.
        if (j.contains("next_cursor"))
            j["next_cursor"] = !j["next_cursor"].is_null();
        return j;
    };
    // The cursor's POSITION (agent_id, name, install_id) is the same on both paths even though
    // its bytes are not: decode and compare it, ignoring names_as_of.
    auto position = [](const std::string& tok, const CryptoDevicesQuery& q) {
        const auto pos = cl::decode_cursor(tok, cl::devices_fingerprint(q));
        REQUIRE(pos);
        return std::make_tuple(pos->agent_id, pos->name, pos->install_id);
    };
    std::vector<std::tuple<std::string, std::string, std::int64_t>> positions;
    auto run = [&](bool expect_catalogue) {
        std::vector<nlohmann::json> out;
        const auto s = api->library_summary({}, std::nullopt);
        REQUIRE(s.has_value());
        CHECK(s->names_from_catalogue == expect_catalogue);
        out.push_back(strip(cl::summary_json(*s)));
        const auto scoped = api->library_summary({}, set_of({"a1", "a3", "a5"}));
        REQUIRE(scoped.has_value());
        out.push_back(strip(cl::summary_json(*scoped)));
        CryptoDevicesQuery q;
        q.family = "openssl";
        q.limit = 2;
        for (int guard = 0; guard < 20; ++guard) { // walk every page
            const auto page = api->library_devices(q, std::nullopt);
            REQUIRE(page.has_value());
            CHECK(page->names_from_catalogue == expect_catalogue);
            out.push_back(strip(cl::devices_json(*page)));
            if (page->next_cursor.empty())
                break;
            positions.push_back(position(page->next_cursor, q));
            q.cursor = page->next_cursor;
        }
        return out;
    };
    const auto fresh = run(true);
    const auto fresh_positions = std::exchange(positions, {});
    set_catalogue_age(fx.pool, kCatalogueFreshSeconds + 60);
    const auto stale = run(false);
    CHECK_FALSE(positions.empty());
    CHECK(positions == fresh_positions);
    REQUIRE(fresh.size() == stale.size());
    CHECK(fresh.size() >= 4);
    for (std::size_t i = 0; i < fresh.size(); ++i) {
        INFO("output " << i);
        CHECK(fresh[i] == stale[i]);
    }
}

TEST_CASE("CryptoApi: names_as_of is the catalogue's refreshed_at; null for live names",
          "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()};
    auto api = make_local_crypto_api(fx.store, nullptr);
    const auto meta = fx.store.catalog_rollup_meta();
    REQUIRE(meta.has_value());
    REQUIRE(meta->refreshed_at > 0);
    const auto s = api->library_summary({}, std::nullopt);
    REQUIRE(s.has_value());
    CHECK(s->names_from_catalogue);
    CHECK(s->names_as_of == meta->refreshed_at);
    CHECK(cl::summary_json(*s)["names_source"] == "catalogue");
    CHECK(cl::summary_json(*s)["names_as_of"] == meta->refreshed_at);
    CryptoDevicesQuery q;
    q.family = "openssl";
    const auto d = api->library_devices(q, std::nullopt);
    REQUIRE(d.has_value());
    CHECK(d->names_as_of == meta->refreshed_at);
    CHECK(cl::devices_json(*d)["names_as_of"] == meta->refreshed_at);
    // An empty page (a family nobody carries) still reports it, from the same statement.
    q.family = "botan";
    const auto e = api->library_devices(q, std::nullopt);
    REQUIRE(e.has_value());
    CHECK(e->devices.empty());
    CHECK(e->names_from_catalogue);
    CHECK(e->names_as_of == meta->refreshed_at);
}

// Review #6056 (A2): the store's 8-name cap reaches every transport as package_names_truncated.
TEST_CASE("CryptoApi summary: a bucket past the 8-name store cap says package_names_truncated",
          "[pg][crypto]") {
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    PgPool pool{PgPool::Options{.conninfo = db.dsn(), .size = 4}};
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    // nine distinct OpenSSL-classified names in ONE (version, ecosystem) bucket
    for (int i = 0; i < 9; ++i)
        seed(store, "n" + std::to_string(i), {ent("libssl3-x" + std::to_string(i), "3.0")},
             /*refresh=*/i == 8);
    auto api = make_local_crypto_api(store, nullptr);
    const auto r = api->library_summary({}, std::nullopt);
    REQUIRE(r.has_value());
    REQUIRE(r->families.size() == 1);
    REQUIRE(r->families[0].versions.size() == 1);
    const auto& v = r->families[0].versions[0];
    CHECK(v.device_count == 9);
    CHECK(v.package_names.size() == 8);
    CHECK(v.package_names_truncated);
    CHECK(cl::summary_json(*r)["families"][0]["versions"][0]["package_names_truncated"] == true);
}

// ── Dashboard widgets through the seam (ADR-0070 D13): the Yuzu-issued reads and the layout ──

namespace {

// CaStore + the layout store, pre-migrated (the library store is not needed here).
yuzu::test::PgTestTemplate widgets_tpl{"cryptowidgets", [](const std::string& dsn) {
                                           PgPool pool{{.conninfo = dsn, .size = 1}};
                                           CaStore ca{pool};
                                           CryptoDashboardLayoutStore layouts{pool};
                                           if (!ca.is_open() || !layouts.is_open())
                                               throw std::runtime_error(
                                                   "cryptowidgets template: a store failed to migrate");
                                       }};

constexpr std::int64_t kWAsOf = 1792368000 + 9 * 3600; // 2026-10-19 09:00 UTC, a Monday
constexpr std::int64_t kWDay = 86400;

IssuedCertRecord widget_cert(const std::string& serial, std::int64_t issued_at,
                             std::int64_t not_after, std::int64_t revoked_at = 0) {
    IssuedCertRecord r;
    r.serial_hex = serial;
    r.subject = "CN=" + serial;
    r.purpose = "agent";
    r.issued_at = issued_at;
    r.not_after = not_after;
    r.revoked_at = revoked_at;
    r.status = revoked_at > 0 ? CertStatus::Revoked : CertStatus::Active;
    return r;
}

} // namespace

TEST_CASE("CryptoApi: Yuzu-issued stats - closed windows, buckets, 52 labelled weeks, as_of",
          "[pg][crypto][widgets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, widgets_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 3}};
    CaStore ca{pool};
    REQUIRE(ca.is_open());
    REQUIRE(ca.record_issued(widget_cert("A1", kWAsOf - 2 * kWDay, kWAsOf + 10 * kWDay)));
    REQUIRE(ca.record_issued(widget_cert("A2", kWAsOf - 200 * kWDay, kWAsOf - 5 * kWDay)));
    REQUIRE(ca.record_issued(
        widget_cert("A3", kWAsOf - 200 * kWDay, kWAsOf + 90 * kWDay, kWAsOf - 3 * kWDay)));
    auto api = make_local_crypto_api(LocalCryptoApiDeps{.ca = &ca, .bound_pinned_as_of = false});

    const auto st = api->ca_stats(kWAsOf);
    REQUIRE(st.has_value());
    CHECK(st->as_of == kWAsOf);
    CHECK(st->active == 1);
    REQUIRE(st->expiring.size() == 6);
    CHECK(st->expiring[0].days == 3);
    CHECK(st->expiring[0].count == 0);
    CHECK(st->expiring[3].days == 21);
    CHECK(st->expiring[3].count == 1); // A1 expires in 10 days
    REQUIRE(st->expired.size() == 4);
    CHECK(st->expired[0].count == 1); // A2, 5 days ago
    REQUIRE(st->revoked.size() == 4);
    CHECK(st->revoked[0].days == 7);
    CHECK(st->revoked[0].other == 1); // A3, 3 days ago, reason not a system marker
    CHECK(st->revoked[0].superseded == 0);
    CHECK(st->issued.days == 7);
    CHECK(st->issued.count == 1); // A1
    REQUIRE(st->weeks.size() == 52);
    CHECK(st->weeks.back().label == "2026-W43");
    CHECK(st->weeks.back().week_start == 1792368000);
    CHECK(st->weeks.back().partial);
    CHECK_FALSE(st->weeks.front().partial);
    CHECK(st->weeks.front().label == "2025-W44");
    // A1 issued Saturday of W42; A3 revoked Friday of W42.
    CHECK(st->weeks[50].label == "2026-W42");
    CHECK(st->weeks[50].issued == 1);
    CHECK(st->weeks[50].revoked_other == 1);
    std::int64_t issued_total = 0;
    for (const auto& w : st->weeks)
        issued_total += w.issued;
    CHECK(issued_total == 3); // A2/A3 (200 days ago) fall inside the 52-week series too

    // Unpinned: the database's now() is the as_of, echoed.
    const auto live = api->ca_stats(std::nullopt);
    REQUIRE(live.has_value());
    CHECK(live->as_of > 1700000000);
}

TEST_CASE("CryptoApi: Yuzu-issued stats - never shared, read at request time even with a TTL",
          "[pg][crypto][widgets]") {
    // ADR-0070 "The CaStore count method": polling is bounded by admission limits, not a cached
    // or stored count. shared_read_ttl covers the slice-1 library summary only.
    YUZU_REQUIRE_PG_DB_TPL(db, widgets_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 3}};
    CaStore ca{pool};
    REQUIRE(ca.is_open());
    std::vector<std::pair<std::string, std::string>> notes;
    auto api = make_local_crypto_api(LocalCryptoApiDeps{
        .ca = &ca,
        .shared_read_ttl = std::chrono::seconds(60),
        .note_degrade = [&](std::string_view s, std::string_view r) {
            notes.emplace_back(std::string(s), std::string(r));
        }});
    const auto first = api->ca_stats(std::nullopt);
    REQUIRE(first.has_value());
    REQUIRE(ca.record_issued(widget_cert("5A1", first->as_of - 60, first->as_of + 10 * kWDay)));
    // Inside what would have been the TTL, the next unpinned read already counts the new row.
    const auto second = api->ca_stats(std::nullopt);
    REQUIRE(second.has_value());
    CHECK(second->active == first->active + 1);
    CHECK(second->as_of >= first->as_of);
    // With no admission slot the read is refused (busy), never answered from an earlier read.
    auto shut = make_local_crypto_api(LocalCryptoApiDeps{
        .ca = &ca, .max_concurrent_reads = 0, .shared_read_ttl = std::chrono::seconds(60)});
    const auto refused = shut->ca_stats(std::nullopt);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().kind == CryptoReadError::Kind::kDegraded);
    CHECK(notes.empty());
}

TEST_CASE("CryptoApi: Yuzu-issued list - drill rows, buckets, pinned paging, refusals",
          "[pg][crypto][widgets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, widgets_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 3}};
    CaStore ca{pool};
    REQUIRE(ca.is_open());
    for (int i = 1; i <= 3; ++i)
        REQUIRE(ca.record_issued(widget_cert("B" + std::to_string(i), kWAsOf - kWDay,
                                             kWAsOf + i * kWDay)));
    auto api = make_local_crypto_api(LocalCryptoApiDeps{.ca = &ca, .bound_pinned_as_of = false});

    CaCertQuery q{.kind = CaCertKind::kExpiring, .days = 3, .as_of = kWAsOf, .limit = 2};
    auto page = api->ca_certificates(q);
    REQUIRE(page.has_value());
    CHECK(page->as_of == kWAsOf);
    CHECK(page->total == 3);
    CHECK(page->truncated);
    REQUIRE(page->rows.size() == 2);
    CHECK(page->rows[0].serial_hex == "B1");
    CHECK(page->rows[0].status == "active");
    CHECK(page->rows[0].revoked_at == 0);
    // H2: page 2 is the cursor alone; it carries the as_of, and the last page has no cursor.
    REQUIRE_FALSE(page->next_cursor.empty());
    q.as_of.reset();
    q.cursor = page->next_cursor;
    page = api->ca_certificates(q);
    REQUIRE(page.has_value());
    CHECK(page->as_of == kWAsOf);
    CHECK_FALSE(page->truncated);
    CHECK(page->next_cursor.empty());
    REQUIRE(page->rows.size() == 1);
    CHECK(page->rows[0].serial_hex == "B3");
    // The same cursor with a different pinned as_of, or for another filter, is refused (400).
    CaCertQuery clash = q;
    clash.as_of = kWAsOf + 1;
    auto refused = api->ca_certificates(clash);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().kind == CryptoReadError::Kind::kInvalid);
    CHECK_THAT(refused.error().message, Catch::Matchers::ContainsSubstring("cursor"));
    CaCertQuery other = q;
    other.days = 7;
    refused = api->ca_certificates(other);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().kind == CryptoReadError::Kind::kInvalid);
    CHECK_THAT(refused.error().message, Catch::Matchers::ContainsSubstring("cursor"));
    CaCertQuery tampered = q;
    tampered.cursor.back() = tampered.cursor.back() == 'A' ? 'B' : 'A';
    refused = api->ca_certificates(tampered);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().message == "invalid cursor");

    // Unpinned: the store's as_of is echoed so the next page can pin it.
    page = api->ca_certificates({.kind = CaCertKind::kActive});
    REQUIRE(page.has_value());
    CHECK(page->as_of > 1700000000);

    // Out-of-range input is refused, never clamped; a bucket on a non-revoked kind is refused.
    for (const CaCertQuery& b :
         {CaCertQuery{.kind = CaCertKind::kExpiring, .days = 45},
          CaCertQuery{.kind = CaCertKind::kIssuedWeek, .week_start = 1792368000 + 3600},
          CaCertQuery{.kind = CaCertKind::kActive, .limit = 100000},
          CaCertQuery{.kind = CaCertKind::kActive, .limit = 0},
          CaCertQuery{.kind = CaCertKind::kActive, .bucket = RevokedBucket::kOther}}) {
        auto bad = api->ca_certificates(b);
        REQUIRE_FALSE(bad.has_value());
        CHECK(bad.error().kind == CryptoReadError::Kind::kInvalid);
    }
}

TEST_CASE("CryptoApi: layout - default, validation, per-user, versioned, unknown ids preserved",
          "[pg][crypto][widgets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, widgets_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 3}};
    CryptoDashboardLayoutStore layouts{pool};
    REQUIRE(layouts.is_open());
    auto api = make_local_crypto_api(LocalCryptoApiDeps{.layouts = &layouts});

    auto got = api->dashboard_layout("alice");
    REQUIRE(got.has_value());
    CHECK(got->is_default);
    CHECK(got->version == 0);
    CHECK(got->widgets == crypto_widgets::default_layout_ids());

    // A refused layout stores nothing.
    auto refused = api->set_dashboard_layout("alice", {"ca.active", "nope"}, std::nullopt);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().kind == CryptoReadError::Kind::kInvalid);
    CHECK(refused.error().message == "widgets[1] is not a catalogue widget id");
    CHECK(api->dashboard_layout("alice")->is_default);

    // First write against "nothing stored" (0).
    auto saved = api->set_dashboard_layout("alice", {"ca.revoked_7d", "lib.families_table"}, 0);
    REQUIRE(saved.has_value());
    CHECK_FALSE(saved->is_default);
    const auto v1 = saved->version;
    CHECK(v1 > 0);
    got = api->dashboard_layout("alice");
    REQUIRE(got.has_value());
    CHECK(got->version == v1);
    CHECK(got->widgets == std::vector<std::string>{"ca.revoked_7d", "lib.families_table"});
    CHECK(api->dashboard_layout("bob")->is_default); // per user

    // A stale expected_version is a conflict naming the stored version; nothing is written.
    auto stale = api->set_dashboard_layout("alice", {"ca.active"}, v1 - 1);
    REQUIRE_FALSE(stale.has_value());
    CHECK(stale.error().kind == CryptoReadError::Kind::kConflict);
    CHECK(stale.error().version == v1);
    CHECK(api->dashboard_layout("alice")->widgets.size() == 2);
    // H1 (owner decision 2026-10-19): a save that omits expected_version is a FIRST save only;
    // over a stored row it conflicts, naming the stored version, and writes nothing.
    auto omitted = api->set_dashboard_layout("alice", {"ca.active"}, std::nullopt);
    REQUIRE_FALSE(omitted.has_value());
    CHECK(omitted.error().kind == CryptoReadError::Kind::kConflict);
    CHECK(omitted.error().version == v1);
    CHECK(api->dashboard_layout("alice")->widgets.size() == 2);
    auto first_bob = api->set_dashboard_layout("bob", {"ca.active"}, std::nullopt);
    REQUIRE(first_bob.has_value());
    CHECK(first_bob->version == 1);
    // Two tabs both reading v1: the first save wins, the second conflicts.
    REQUIRE(api->set_dashboard_layout("alice", {"ca.active"}, v1).has_value());
    auto second_tab = api->set_dashboard_layout("alice", {"ca.issued_7d"}, v1);
    REQUIRE_FALSE(second_tab.has_value());
    CHECK(second_tab.error().kind == CryptoReadError::Kind::kConflict);

    // Saving the default list is the default (Reset), with nothing preserved.
    const auto cur = api->dashboard_layout("alice")->version;
    auto reset = api->set_dashboard_layout("alice", crypto_widgets::default_layout_ids(), cur);
    REQUIRE(reset.has_value());
    CHECK(reset->is_default);

    // Ids a newer build stored are kept on save, after the caller's, and never drawn.
    REQUIRE(layouts.put("carol", {"future.widget", "ca.active", "other.future"}, std::nullopt));
    got = api->dashboard_layout("carol");
    REQUIRE(got.has_value());
    CHECK(got->widgets == std::vector<std::string>{"ca.active"});
    CHECK(got->preserved_unknown == 2);
    CHECK_FALSE(got->is_default);
    auto kept = api->set_dashboard_layout("carol", {"ca.issued_7d"}, got->version);
    REQUIRE(kept.has_value());
    CHECK(kept->preserved_unknown == 2);
    auto raw = layouts.get("carol");
    REQUIRE(raw.has_value());
    REQUIRE(raw->has_value());
    CHECK((**raw).widget_ids ==
          std::vector<std::string>{"ca.issued_7d", "future.widget", "other.future"});

    // An over-long username is a refusal, not a degrade.
    auto big = api->dashboard_layout(std::string(CryptoDashboardLayoutStore::kMaxUsernameBytes + 1, 'u'));
    REQUIRE_FALSE(big.has_value());
    CHECK(big.error().kind == CryptoReadError::Kind::kInvalid);
}

TEST_CASE("CryptoApi: layout - a write that loses an in-store race names the STORED version",
          "[pg][crypto][widgets]") {
    // The API reads the row, then writes conditionally on that version. When another writer
    // lands in between, the store's conditional write matches no row (kConflict); the 409 /
    // X-Crypto-Layout-Version must then carry the version now stored, never 0.
    YUZU_REQUIRE_PG_DB_TPL(db, widgets_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 3}};
    CryptoDashboardLayoutStore layouts{pool};
    REQUIRE(layouts.is_open());
    auto api = make_local_crypto_api(LocalCryptoApiDeps{.layouts = &layouts});
    REQUIRE(api->set_dashboard_layout("alice", {"ca.active"}, std::nullopt).has_value());

    PgConn admin{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(admin.get()) == CONNECTION_OK);
    // Stand the stored row at version 5, then make every UPDATE of it match nothing: exactly
    // what the conditional write sees when another save bumped the version after the read.
    REQUIRE(PgResult{PQexec(admin.get(), "UPDATE crypto_dashboard_layout_store.layouts SET "
                                         "version = 5 WHERE username = 'alice'")}
                .ok());
    REQUIRE(PgResult{PQexec(admin.get(),
                            "CREATE FUNCTION crypto_dashboard_layout_store.yuzu_test_lose() "
                            "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$; "
                            "CREATE TRIGGER yuzu_test_lose BEFORE UPDATE ON "
                            "crypto_dashboard_layout_store.layouts FOR EACH ROW EXECUTE FUNCTION "
                            "crypto_dashboard_layout_store.yuzu_test_lose()")}
                .ok());
    for (const std::optional<std::int64_t> expected : {std::optional<std::int64_t>{},
                                                       std::optional<std::int64_t>{5}}) {
        auto lost = api->set_dashboard_layout("alice", {"ca.issued_7d"}, expected);
        REQUIRE_FALSE(lost.has_value());
        CHECK(lost.error().kind == CryptoReadError::Kind::kConflict);
        CHECK(lost.error().version == 5);
    }

    // With the race gone, a save against the version the 409 named lands.
    REQUIRE(PgResult{PQexec(admin.get(), "DROP TRIGGER yuzu_test_lose ON "
                                         "crypto_dashboard_layout_store.layouts")}
                .ok());
    auto saved = api->set_dashboard_layout("alice", {"ca.issued_7d"}, 5);
    REQUIRE(saved.has_value());
    CHECK(saved->version == 6);
}

TEST_CASE("CryptoApi: null stores and zero capacity degrade every widget method, never empty",
          "[pg][crypto][widgets]") {
    std::vector<std::pair<std::string, std::string>> notes;
    auto note = [&](std::string_view s, std::string_view r) {
        notes.emplace_back(std::string(s), std::string(r));
    };
    auto none = make_local_crypto_api(LocalCryptoApiDeps{.note_degrade = note});
    auto stats = none->ca_stats(kWAsOf);
    REQUIRE_FALSE(stats.has_value());
    CHECK(stats.error().kind == CryptoReadError::Kind::kDegraded);
    CHECK(stats.error().message == "Yuzu CA read degraded");
    CHECK_FALSE(stats.error().unavailable_until_restart); // the layout store's posture only
    auto certs = none->ca_certificates({.kind = CaCertKind::kActive});
    REQUIRE_FALSE(certs.has_value());
    CHECK(certs.error().kind == CryptoReadError::Kind::kDegraded);
    auto layout = none->dashboard_layout("alice");
    REQUIRE_FALSE(layout.has_value());
    CHECK(layout.error().kind == CryptoReadError::Kind::kDegraded);
    // A layout store that did not open at boot (server.cpp resets it to null, ADR-0071) lasts
    // until a restart: flagged so no transport offers a retry, and the dashboard draws the
    // default instead.
    CHECK(layout.error().unavailable_until_restart);
    CHECK(layout.error().message.find("did not open at server start") != std::string::npos);
    auto set = none->set_dashboard_layout("alice", {"ca.active"}, std::nullopt);
    REQUIRE_FALSE(set.has_value());
    CHECK(set.error().kind == CryptoReadError::Kind::kDegraded);
    CHECK(set.error().unavailable_until_restart);
    auto lib = none->library_summary({}, std::nullopt);
    REQUIRE_FALSE(lib.has_value());
    CHECK(lib.error().kind == CryptoReadError::Kind::kDegraded);
    auto bad = none->set_dashboard_layout("alice", {"nope"}, std::nullopt);
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error().kind == CryptoReadError::Kind::kInvalid);
    // Closed metric labels only.
    for (const auto& [src, reason] : notes) {
        CHECK((src == "ca_issued" || src == "crypto_layout"));
        CHECK(reason == "store_not_open");
    }
    CHECK(notes.size() == 4);

    YUZU_REQUIRE_PG_DB_TPL(db, widgets_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 3}};
    CaStore ca{pool};
    CryptoDashboardLayoutStore layouts{pool};
    REQUIRE(ca.is_open());
    REQUIRE(layouts.is_open());
    notes.clear();
    auto shut = make_local_crypto_api(LocalCryptoApiDeps{
        .ca = &ca, .layouts = &layouts, .max_concurrent_reads = 0, .note_degrade = note});
    for (const auto& err :
         {shut->ca_stats(kWAsOf).error(), shut->ca_certificates({.kind = CaCertKind::kActive}).error()}) {
        CHECK(err.kind == CryptoReadError::Kind::kDegraded);
        CHECK(err.cause == CryptoReadCause::kCapacity);
    }
    CHECK(notes == std::vector<std::pair<std::string, std::string>>{
                       {"ca_issued", "admission_full"}, {"ca_issued", "admission_full"}});
    // B9: the layout read and save are NOT admission-bounded.
    CHECK(shut->dashboard_layout("alice").has_value());
    CHECK(shut->set_dashboard_layout("alice", {"ca.active"}, std::nullopt).has_value());

    // B9: a pool of 1..3 refuses the Yuzu-issued reads outright; the bound is a quarter of it.
    auto tiny = make_local_crypto_api(
        LocalCryptoApiDeps{.ca = &ca, .pool_size = 3, .bound_pinned_as_of = false});
    CHECK(tiny->ca_stats(kWAsOf).error().cause == CryptoReadCause::kCapacity);
    CHECK(make_local_crypto_api(
              LocalCryptoApiDeps{.ca = &ca, .pool_size = 4, .bound_pinned_as_of = false})
              ->ca_stats(kWAsOf));
    STATIC_CHECK(crypto_admission_bound(2, 16) == 2);
    STATIC_CHECK(crypto_admission_bound(2, 4) == 1);
    STATIC_CHECK(crypto_admission_bound(2, 0) == 2);
}


TEST_CASE("CryptoApi: a pool of one connection refuses the library reads too (busy)",
          "[pg][crypto]") {
    // M3: the mTLS-accept is_revoked check must keep the only connection, so a pool of 1
    // refuses every library read (capacity), with no store call; a pool of 2 reads.
    YUZU_REQUIRE_PG_DB_TPL(db, crypto_tpl);
    Fx fx{db.dsn()};
    auto one = make_local_crypto_api(LocalCryptoApiDeps{.software = &fx.store, .pool_size = 1});
    const auto s = one->library_summary({}, std::nullopt);
    REQUIRE_FALSE(s.has_value());
    CHECK(s.error().kind == CryptoReadError::Kind::kDegraded);
    CHECK(s.error().cause == CryptoReadCause::kCapacity);
    CryptoDevicesQuery q;
    q.family = "openssl";
    const auto d = one->library_devices(q, std::nullopt);
    REQUIRE_FALSE(d.has_value());
    CHECK(d.error().cause == CryptoReadCause::kCapacity);
    auto two = make_local_crypto_api(LocalCryptoApiDeps{.software = &fx.store, .pool_size = 2});
    CHECK(two->library_summary({}, std::nullopt).has_value());
    STATIC_CHECK(kCryptoLibraryMinPoolSize == 2);
}

TEST_CASE("CryptoApi: a pinned as_of outside its window is refused on the database clock",
          "[pg][crypto][widgets]") {
    // M2: production bounds (the default) are measured on the database clock in the read's own
    // transaction; the refusal is a 400-class kInvalid naming as_of, never a degrade.
    YUZU_REQUIRE_PG_DB_TPL(db, widgets_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    CaStore ca{pool};
    REQUIRE(ca.is_open());
    auto api = make_local_crypto_api(LocalCryptoApiDeps{.ca = &ca});
    const auto live = api->ca_stats(std::nullopt);
    REQUIRE(live.has_value());
    for (const std::int64_t bad : {live->as_of - 8 * kWDay, live->as_of + 3600}) {
        const auto st = api->ca_stats(bad);
        REQUIRE_FALSE(st.has_value());
        CHECK(st.error().kind == CryptoReadError::Kind::kInvalid);
        CHECK_THAT(st.error().message, Catch::Matchers::ContainsSubstring("as_of"));
        const auto page = api->ca_certificates({.kind = CaCertKind::kActive, .as_of = bad});
        REQUIRE_FALSE(page.has_value());
        CHECK(page.error().kind == CryptoReadError::Kind::kInvalid);
        CHECK_THAT(page.error().message, Catch::Matchers::ContainsSubstring("database clock") ||
                                             Catch::Matchers::ContainsSubstring("days old"));
    }
    // Inside the window (a minute ago, on the DB clock) it reads.
    CHECK(api->ca_stats(live->as_of - 60).has_value());
    CHECK(api->ca_certificates({.kind = CaCertKind::kActive, .as_of = live->as_of - 60}).has_value());
}

TEST_CASE("SharedRead: a compute that throws degrades its waiters and the next call re-reads",
          "[crypto]") {
    // L5: the computing caller settles the shared state with the exception, so a waiter on it
    // answers `failed` (never hangs), and the failed read is never reused.
    using R = SharedRead<int, std::string>;
    R shared{"busy", "failed", std::chrono::seconds(5)};
    std::atomic<bool> entered{false};
    std::atomic<bool> release{false};
    std::atomic<bool> computer_saw_throw{false}; // Catch2 assertions stay on the test thread
    std::thread computer([&] {
        try {
            (void)shared.get(std::chrono::seconds(60), [&]() -> R::Result {
                entered = true;
                while (!release)
                    std::this_thread::yield();
                throw std::runtime_error("store blew up");
            });
        } catch (const std::runtime_error&) {
            computer_saw_throw = true;
        }
    });
    while (!entered)
        std::this_thread::yield();
    std::optional<R::Result> waited;
    std::thread waiter([&] {
        waited = shared.get(std::chrono::seconds(60), []() -> R::Result { return 7; });
    });
    // Give the waiter time to join the in-flight read, then let the compute throw.
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    release = true;
    computer.join();
    waiter.join();
    CHECK(computer_saw_throw); // the computing caller sees its own exception
    REQUIRE(waited.has_value());
    // Either it joined the throwing read (failed), or it arrived after it settled and re-read.
    if (!waited->has_value())
        CHECK(waited->error() == "failed");
    else
        CHECK(**waited == 7);
    // The next call does not reuse the failed read: it computes again.
    int calls = 0;
    const auto next = shared.get(std::chrono::seconds(60), [&]() -> R::Result {
        ++calls;
        return 42;
    });
    REQUIRE(next.has_value());
    CHECK(*next == 42);
    CHECK(calls == 1);
}
