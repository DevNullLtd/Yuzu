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

#include "../test_helpers.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <memory>
#include <optional>
#include <unordered_set>
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

TEST_CASE("CryptoApi summary: coverage numerator never exceeds the denominator, even with package "
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
