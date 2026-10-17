// /crypto slice 1: the local CryptoApi over the REAL SoftwareInventoryStore - scope push-down
// (TOP vs set vs empty), degrade -> kDegraded (never an empty answer), the hostname join, the
// filter-bound cursor.

#include "crypto_api_local.hpp"

#include "crypto_library_model.hpp"
#include "device_api.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "software_inventory_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
namespace pg = yuzu::server::pg;
namespace cl = yuzu::server::crypto_library;
using yuzu::server::pg::PgPool;

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

void seed(SoftwareInventoryStore& s, const std::string& agent, std::vector<SoftwareEntry> rows) {
    const auto h = SoftwareInventoryStore::canonical_hash(rows);
    REQUIRE(s.apply_installed_software(agent, h, std::move(rows), 1000) ==
            InventoryIngestOutcome::kStored);
}

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
    explicit Fx(const std::string& dsn)
        : pool(PgPool::Options{.conninfo = dsn, .size = 4}), store(pool) {
        REQUIRE(store.is_open());
        seed(store, "a1", {ent("libssl3", "3.0.13"), ent("openssl", "3.0.13")});
        seed(store, "a2", {ent("libssl3", "3.0.13")});
        seed(store, "a3", {ent("libssl3", "1.1.1", "rpm"), ent("libgnutls30", "3.7.9")});
        seed(store, "a4", {ent("curl", "8.0")});
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

TEST_CASE("CryptoApi devices: hostname join, paging, scope", "[pg][crypto]") {
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

TEST_CASE("CryptoApi: a degraded store is kDegraded, never an empty answer", "[pg][crypto]") {
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

    CryptoDevicesQuery q;
    q.family = "openssl";
    auto d = api->library_devices(q, std::nullopt);
    REQUIRE_FALSE(d.has_value());
    CHECK(d.error().kind == CryptoReadError::Kind::kDegraded);
}
