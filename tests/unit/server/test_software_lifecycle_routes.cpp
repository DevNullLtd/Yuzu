/**
 * test_software_lifecycle_routes.cpp - SoftwareLifecycleRoutes (SAM-24): the import, list and clear
 * routes for the imported lifecycle rule set.
 *
 * Two layers over fake gates (the real permission gate is exercised by its own suites):
 *   - [lifecycle][routes] no Postgres: the pure helpers, the format set, the OpenAPI enum, unwired
 *     gates, the permission asked per route and its ordering ahead of the body, every refusal that
 *     happens before the store is touched (name, format, size, file content, source), and the 503
 *     of a missing store;
 *   - [pg][lifecycle][routes] over the real SoftwareLifecycleStore: import replaces only the
 *     imported set, list and delete, the audit ordering and its fail-closed 503, CLE skip counts,
 *     and a degraded store on all three routes.
 */

#include "software_lifecycle_routes.hpp"

#include "openapi_spec_access.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "software_lifecycle_import.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;
namespace li = yuzu::server::lifecycle_import;
using json = nlohmann::json;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

constexpr const char* kPath = "/api/v1/inventory/software/lifecycle/rules";
constexpr const char* kVerbImport = "software_estate.lifecycle_rules.import";
constexpr const char* kVerbDelete = "software_estate.lifecycle_rules.delete";
constexpr const char* kVerbRead = "software_estate.lifecycle_rules.read";

const std::string kCsv =
    "product_key,version_prefix,event,date,source_reference\n"
    "product:postgresql:postgresql,16,end_of_life,2028-11-09,ignored\n"
    "product:postgresql:postgresql,,end_of_support,2027-01-01,ignored\n";

// DERIVED from ECMA-428 Annex B: two whole-product events and one exact version.
const std::string kCle =
    R"({"$schema":"https://tc54.org/schemas/cle/cle-1.0.0.schema.json",)"
    R"("identifier":"pkg:npm/example-component","updatedAt":"2021-01-15T00:00:00Z","events":[)"
    R"({"id":1,"type":"endOfSupport","effective":"2021-01-01T00:00:00Z","published":"2021-01-01T00:00:00Z",)"
    R"("versions":[{"range":"vers:npm/*"}],"supportId":"standard"},)"
    R"({"id":2,"type":"endOfLife","effective":"2022-06-30T00:00:00Z","published":"2021-01-01T00:00:00Z",)"
    R"("versions":[{"range":"vers:npm/*"}],"supportId":"standard"},)"
    R"({"id":3,"type":"endOfLife","effective":"2023-01-01T00:00:00Z","published":"2021-01-01T00:00:00Z",)"
    R"("versions":[{"range":"vers:npm/=1.0.0"}],"supportId":"standard"}]})";

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

// Fake gates; the store is whatever the test hands in (nullptr = a missing store).
struct Rig {
    bool allow{true};
    bool audit_ok{true};
    std::vector<std::string> asked; // "Securable:Operation" per perm_fn call
    std::vector<AuditRow> audit;
    SoftwareLifecycleRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    explicit Rig(SoftwareLifecycleStore* store, bool wire_perm = true, bool wire_audit = true) {
        SoftwareLifecycleRoutes::Deps deps;
        if (wire_perm)
            deps.perm_fn = [this](const httplib::Request&, httplib::Response& res,
                                  const std::string& type, const std::string& op) {
                asked.push_back(type + ":" + op);
                if (!allow) {
                    res.status = 403;
                    res.set_content(R"({"error":{"code":403,"message":"forbidden"}})",
                                    "application/json");
                }
                return allow;
            };
        if (wire_audit)
            deps.audit_fn = [this](const httplib::Request&, const std::string& action,
                                   const std::string& result, const std::string& tt,
                                   const std::string& tid, const std::string& detail) {
                if (!audit_ok)
                    return false;
                audit.push_back({action, result, tt, tid, detail});
                return true;
            };
        deps.store = store;
        routes.register_routes(sink, std::move(deps));
    }

    std::unique_ptr<httplib::Response> call(const std::string& method, const std::string& path,
                                            const std::string& body = {}) {
        auto res = sink.dispatch(method, path, body, "text/csv");
        REQUIRE(res != nullptr);
        return res;
    }
    std::unique_ptr<httplib::Response> import_csv(const std::string& body = kCsv,
                                                  const std::string& name = "rules.csv") {
        return call("POST", std::string{kPath} + "?format=csv&name=" + name, body);
    }
    static json parse(const httplib::Response& res) { return json::parse(res.body); }
    std::size_t audit_count(const std::string& result) const {
        std::size_t n = 0;
        for (const auto& a : audit)
            n += a.result == result ? 1 : 0;
        return n;
    }
};

yuzu::test::PgTestTemplate routes_lifecycle_tpl{"lifecycleroutes", [](const std::string& dsn) {
                                                    PgPool pool{{.conninfo = dsn, .size = 1}};
                                                    SoftwareLifecycleStore store{pool};
                                                    if (!store.is_open())
                                                        throw std::runtime_error(
                                                            "lifecycle routes template: store "
                                                            "failed to migrate");
                                                }};

void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQerrorMessage(conn.get()));
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

LifecycleRule rule(LifecycleSource src, std::string key, std::string prefix, LifecycleEvent ev,
                   std::string date) {
    return LifecycleRule{std::move(key), std::move(prefix), ev, std::move(date), src, "seed", 0};
}

} // namespace

#define LIFECYCLE_ROUTES_PG(pool_var, store_var)                                                   \
    YUZU_REQUIRE_PG_DB_TPL(lifecycle_routes_db_fx_, routes_lifecycle_tpl);                         \
    PgPool pool_var{{.conninfo = lifecycle_routes_db_fx_.dsn(), .size = 2}};                       \
    REQUIRE(pool_var.valid());                                                                     \
    SoftwareLifecycleStore store_var{pool_var};                                                    \
    REQUIRE(store_var.is_open())

// -- no Postgres ----------------------------------------------------------------------------

TEST_CASE("lifecycle routes: the pure helpers", "[lifecycle][routes]") {
    CHECK_FALSE(lifecycle_import_name_defect("rules.csv").has_value());
    CHECK_FALSE(lifecycle_import_name_defect(std::string(128, 'a')).has_value());
    CHECK(lifecycle_import_name_defect("").has_value());
    CHECK(lifecycle_import_name_defect(std::string(129, 'a')).has_value());
    for (const char bad : {'\0', '\t', '\r', '\n', '\x1f', '\x7f'})
        CHECK(lifecycle_import_name_defect(std::string{"a"} + bad + "b").has_value());

    CHECK(lifecycle_rules_listable_source("imported") == LifecycleSource::imported);
    CHECK(lifecycle_rules_listable_source("shipped") == LifecycleSource::shipped);
    CHECK(lifecycle_rules_listable_source("external") == LifecycleSource::external);
    CHECK_FALSE(lifecycle_rules_listable_source("declared").has_value());
    CHECK_FALSE(lifecycle_rules_listable_source("").has_value());
    CHECK_FALSE(lifecycle_rules_listable_source("Imported").has_value());
}

TEST_CASE("lifecycle routes: the offered formats are exactly the parser's enumerators",
          "[lifecycle][routes]") {
    // Two enumerators today; adding one to Format fails this until the token list, the OpenAPI
    // enum and the docs follow.
    CHECK(kLifecycleImportFormatTokens.size() == 2);
    std::set<li::Format> resolved;
    for (const auto token : kLifecycleImportFormatTokens) {
        const auto f = li::parse_format(token);
        REQUIRE(f.has_value());
        resolved.insert(*f);
    }
    CHECK(resolved == std::set<li::Format>{li::Format::csv, li::Format::cle});
    CHECK_FALSE(li::parse_format("openeox").has_value());

    // The OpenAPI `format` enum is the same set.
    const json spec = json::parse(yuzu::server::openapi_spec_json());
    const auto& post = spec.at("paths").at("/inventory/software/lifecycle/rules").at("post");
    std::set<std::string> enum_values;
    for (const auto& p : post.at("parameters"))
        if (p.at("name") == "format")
            for (const auto& v : p.at("schema").at("enum"))
                enum_values.insert(v.get<std::string>());
    std::set<std::string> tokens;
    for (const auto token : kLifecycleImportFormatTokens)
        tokens.insert(std::string{token});
    CHECK(enum_values == tokens);

    // The 400 for any other token names the set.
    Rig rig{nullptr};
    const auto res = rig.call("POST", std::string{kPath} + "?format=openeox&name=f", "x");
    CHECK(res->status == 400);
    const auto message = Rig::parse(*res)["error"]["message"].get<std::string>();
    CHECK(message.find("csv") != std::string::npos);
    CHECK(message.find("cle") != std::string::npos);
    CHECK(message.find("openeox") == std::string::npos);
}

TEST_CASE("lifecycle routes: an unwired gate fails closed on every route", "[lifecycle][routes]") {
    for (const auto [wire_perm, wire_audit] :
         std::vector<std::pair<bool, bool>>{{false, true}, {true, false}, {false, false}}) {
        Rig rig{nullptr, wire_perm, wire_audit};
        for (const auto* method : {"POST", "GET", "DELETE"}) {
            INFO(method);
            const auto res = rig.call(method, std::string{kPath} + "?format=csv&name=f", kCsv);
            CHECK(res->status == 503);
        }
        CHECK(rig.audit.empty());
    }
}

TEST_CASE("lifecycle routes: the permission is asked first, per route, and a refusal reads nothing",
          "[lifecycle][routes]") {
    Rig rig{nullptr};
    rig.allow = false;

    // A body that would otherwise be refused by the parser: the 403 wins, so the body, the name
    // and the format were never looked at.
    const auto post = rig.call("POST", std::string{kPath} + "?format=nope", "\x01 not a file");
    CHECK(post->status == 403);
    CHECK(rig.call("GET", kPath)->status == 403);
    CHECK(rig.call("DELETE", kPath)->status == 403);
    CHECK(rig.asked ==
          std::vector<std::string>{"Inventory:Write", "Inventory:Read", "Inventory:Write"});
    CHECK(rig.audit.empty());
}

TEST_CASE("lifecycle routes: a refused import is a 4xx with a reason, audited denied, and never "
          "reaches the store",
          "[lifecycle][routes]") {
    Rig rig{nullptr};

    struct Case {
        std::string label, query, body;
        int status;
    };
    const std::string over(li::kImportMaxBytes + 1, 'a');
    const std::vector<Case> cases = {
        {"no name", "?format=csv", kCsv, 400},
        {"empty name", "?format=csv&name=", kCsv, 400},
        {"name over 128 bytes", "?format=csv&name=" + std::string(129, 'a'), kCsv, 400},
        {"control character in the name", "?format=csv&name=a%0Ab", kCsv, 400},
        {"name twice", "?format=csv&name=a&name=b", kCsv, 400},
        {"no format", "?name=f", kCsv, 400},
        {"unknown format", "?format=openeox&name=f", kCsv, 400},
        {"upper-case format", "?format=CSV&name=f", kCsv, 400},
        {"format twice", "?format=csv&format=cle&name=f", kCsv, 400},
        {"body over the cap", "?format=csv&name=f", over, 413},
        {"malformed csv", "?format=csv&name=f", "not,a,rule,file\n", 400},
        {"empty csv", "?format=csv&name=f", "", 400},
        {"malformed json", "?format=cle&name=f", "{not json", 400},
        {"unknown cle spec version", "?format=cle&name=f",
         R"({"$schema":"https://example.invalid/cle-9.schema.json","identifier":"pkg:npm/x","updatedAt":"2021-01-15T00:00:00Z","events":[]})",
         400},
    };
    std::size_t denied = 0;
    for (const auto& c : cases) {
        INFO(c.label);
        const auto res = rig.call("POST", std::string{kPath} + c.query, c.body);
        CHECK(res->status == c.status);
        const auto body = Rig::parse(*res);
        CHECK_FALSE(body["error"]["message"].get<std::string>().empty());
        ++denied;
        // One denied row per refusal under the import verb, and no `requested` row.
        CHECK(rig.audit_count("denied") == denied);
    }
    CHECK(rig.audit_count("requested") == 0);
    for (const auto& a : rig.audit)
        CHECK(a.action == kVerbImport);
}

TEST_CASE("lifecycle routes: a valid import with no store is a 503 with a retry hint and no audit row",
          "[lifecycle][routes]") {
    Rig rig{nullptr};
    const auto post = rig.import_csv();
    CHECK(post->status == 503);
    CHECK(Rig::parse(*post)["error"]["retry_after_ms"].is_number());
    const auto get = rig.call("GET", kPath);
    CHECK(get->status == 503);
    CHECK(Rig::parse(*get)["error"]["retry_after_ms"].is_number());
    const auto del = rig.call("DELETE", kPath);
    CHECK(del->status == 503);
    CHECK(Rig::parse(*del)["error"]["retry_after_ms"].is_number());
    CHECK(rig.audit.empty());
}

TEST_CASE("lifecycle routes: GET refuses declared and anything but the three rule sources",
          "[lifecycle][routes]") {
    Rig rig{nullptr};
    for (const auto* source : {"declared", "bogus", "", "Imported"}) {
        INFO(source);
        const auto res = rig.call("GET", std::string{kPath} + "?source=" + source);
        CHECK(res->status == 400);
    }
    CHECK(rig.call("GET", std::string{kPath} + "?source=imported&source=shipped")->status == 400);
    CHECK(rig.audit_count("denied") == 5);
    for (const auto& a : rig.audit)
        CHECK(a.action == kVerbRead);
    // A listable source passes the check and meets the missing store.
    for (const auto* source : {"imported", "shipped", "external"})
        CHECK(rig.call("GET", std::string{kPath} + "?source=" + source)->status == 503);
}

// -- [pg] -----------------------------------------------------------------------------------

TEST_CASE("lifecycle routes: an import replaces only the imported set and reports what it stored",
          "[pg][lifecycle][routes]") {
    LIFECYCLE_ROUTES_PG(pool, store);
    Rig rig{&store};
    REQUIRE(store.replace_rules(LifecycleSource::shipped,
                                {rule(LifecycleSource::shipped, "product:seed:seed", "",
                                      LifecycleEvent::end_of_life, "2030-01-01")})
                .value() == 1);
    REQUIRE(store.replace_rules(LifecycleSource::external,
                                {rule(LifecycleSource::external, "product:ext:ext", "",
                                      LifecycleEvent::end_of_life, "2031-01-01")})
                .value() == 1);

    SECTION("csv: stored, replaced, the name stamped on every rule, shipped and external untouched") {
        const auto res = rig.import_csv(kCsv, "my-rules.csv");
        REQUIRE(res->status == 200);
        const auto data = Rig::parse(*res)["data"];
        CHECK(data["stored"] == 2);
        CHECK(data["replaced"] == true);
        CHECK(data["format"] == "csv");
        CHECK(data["spec_version"] == "");
        CHECK(data["source_reference"] == "my-rules.csv");
        CHECK(data["skipped"].empty());

        const auto got = store.rules_of(LifecycleSource::imported);
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 2);
        for (const auto& r : *got) {
            CHECK(r.source_ref == "my-rules.csv");
            CHECK(r.source == LifecycleSource::imported);
        }
        CHECK(store.rules_of(LifecycleSource::shipped)->size() == 1);
        CHECK(store.rules_of(LifecycleSource::external)->size() == 1);

        // The audit rows: requested ahead of the write, then the outcome, both on the file name.
        REQUIRE(rig.audit.size() == 2);
        CHECK(rig.audit[0].action == kVerbImport);
        CHECK(rig.audit[0].result == "requested");
        CHECK(rig.audit[0].target_id == "my-rules.csv");
        CHECK(rig.audit[1].result == "success");
    }
    SECTION("a second import replaces the first") {
        REQUIRE(rig.import_csv(kCsv, "first.csv")->status == 200);
        const std::string one =
            "product_key,version_prefix,event,date,source_reference\n"
            "product:python:python,3.8,end_of_life,2024-10-07,x\n";
        const auto res = rig.import_csv(one, "second.csv");
        REQUIRE(res->status == 200);
        CHECK(Rig::parse(*res)["data"]["stored"] == 1);
        const auto got = store.rules_of(LifecycleSource::imported);
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 1);
        CHECK((*got)[0].product_key == "product:python:python");
        CHECK((*got)[0].source_ref == "second.csv");
    }
    SECTION("cle: a whole-product record is stored, an exact version is skipped and counted") {
        const auto res = rig.call("POST", std::string{kPath} + "?format=cle&name=cle.json", kCle);
        REQUIRE(res->status == 200);
        const auto data = Rig::parse(*res)["data"];
        CHECK(data["format"] == "cle");
        CHECK(data["spec_version"] == "1.0.0");
        CHECK(data["stored"] == 2);
        REQUIRE(data["skipped"].size() == 1);
        CHECK(data["skipped"][0]["reason"] == "exact_version");
        CHECK(data["skipped"][0]["count"] == 1);
        const auto got = store.rules_of(LifecycleSource::imported);
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 2);
        for (const auto& r : *got)
            CHECK(r.version_prefix.empty()); // never stored as a prefix
    }
    SECTION("a refused file leaves the stored imported set unchanged") {
        REQUIRE(rig.import_csv(kCsv, "good.csv")->status == 200);
        rig.audit.clear();
        CHECK(rig.import_csv("garbage\n", "bad.csv")->status == 400);
        CHECK(rig.call("POST", std::string{kPath} + "?format=cle&name=bad.json", "{")->status == 400);
        const auto got = store.rules_of(LifecycleSource::imported);
        REQUIRE(got.has_value());
        CHECK(got->size() == 2);
        CHECK((*got)[0].source_ref == "good.csv");
        CHECK(rig.audit_count("requested") == 0);
    }
}

TEST_CASE("lifecycle routes: GET lists the chosen source, imported by default",
          "[pg][lifecycle][routes]") {
    LIFECYCLE_ROUTES_PG(pool, store);
    Rig rig{&store};
    REQUIRE(store.replace_rules(LifecycleSource::shipped,
                                {rule(LifecycleSource::shipped, "product:seed:seed", "",
                                      LifecycleEvent::end_of_life, "2030-01-01")})
                .value() == 1);

    SECTION("nothing imported is an empty list, not an error") {
        const auto res = rig.call("GET", kPath);
        REQUIRE(res->status == 200);
        const auto data = Rig::parse(*res)["data"];
        CHECK(data["source"] == "imported");
        CHECK(data["rules"].empty());
        CHECK(data["count"] == 0);
    }
    SECTION("the default is imported, shipped lists the seed, and every field is served") {
        REQUIRE(rig.import_csv(kCsv, "f.csv")->status == 200);
        const auto imported = Rig::parse(*rig.call("GET", kPath))["data"];
        CHECK(imported["source"] == "imported");
        CHECK(imported["count"] == 2);
        const auto& first = imported["rules"][0];
        CHECK(first["product_key"] == "product:postgresql:postgresql");
        CHECK(first["version_prefix"] == "");
        CHECK(first["event"] == "end_of_support");
        CHECK(first["date"] == "2027-01-01");
        CHECK(first["source_reference"] == "f.csv");

        const auto shipped = Rig::parse(*rig.call("GET", std::string{kPath} + "?source=shipped"))["data"];
        CHECK(shipped["source"] == "shipped");
        CHECK(shipped["count"] == 1);
        CHECK(shipped["rules"][0]["product_key"] == "product:seed:seed");
    }
    SECTION("a served read writes no audit row") {
        CHECK(rig.call("GET", kPath)->status == 200);
        CHECK(rig.audit.empty());
    }
}

TEST_CASE("lifecycle routes: DELETE empties only the imported set", "[pg][lifecycle][routes]") {
    LIFECYCLE_ROUTES_PG(pool, store);
    Rig rig{&store};
    REQUIRE(store.replace_rules(LifecycleSource::shipped,
                                {rule(LifecycleSource::shipped, "product:seed:seed", "",
                                      LifecycleEvent::end_of_life, "2030-01-01")})
                .value() == 1);
    REQUIRE(rig.import_csv(kCsv, "f.csv")->status == 200);
    rig.audit.clear();

    const auto res = rig.call("DELETE", kPath);
    REQUIRE(res->status == 200);
    CHECK(Rig::parse(*res)["data"]["removed"] == 2);
    CHECK(store.rules_of(LifecycleSource::imported)->empty());
    CHECK(store.rules_of(LifecycleSource::shipped)->size() == 1);

    REQUIRE(rig.audit.size() == 2);
    CHECK(rig.audit[0].action == kVerbDelete);
    CHECK(rig.audit[0].result == "requested");
    CHECK(rig.audit[0].target_id == "imported");
    CHECK(rig.audit[1].result == "success");

    // Deleting an empty set is a success with nothing removed.
    const auto again = rig.call("DELETE", kPath);
    REQUIRE(again->status == 200);
    CHECK(Rig::parse(*again)["data"]["removed"] == 0);
}

TEST_CASE("lifecycle routes: an audit row that cannot be stored refuses the write and writes nothing",
          "[pg][lifecycle][routes]") {
    LIFECYCLE_ROUTES_PG(pool, store);
    Rig rig{&store};
    REQUIRE(rig.import_csv(kCsv, "kept.csv")->status == 200);
    rig.audit.clear();
    rig.audit_ok = false;

    const auto post = rig.import_csv("product_key,version_prefix,event,date,source_reference\n"
                                     "product:python:python,3.8,end_of_life,2024-10-07,x\n",
                                     "new.csv");
    CHECK(post->status == 503);
    CHECK(post->has_header("Sec-Audit-Failed"));
    const auto del = rig.call("DELETE", kPath);
    CHECK(del->status == 503);
    CHECK(del->has_header("Sec-Audit-Failed"));

    // The stored set is exactly what the first import left.
    const auto got = store.rules_of(LifecycleSource::imported);
    REQUIRE(got.has_value());
    REQUIRE(got->size() == 2);
    CHECK((*got)[0].source_ref == "kept.csv");
}

TEST_CASE("lifecycle routes: a degraded store is a 503 with a retry hint on all three routes",
          "[pg][lifecycle][routes]") {
    LIFECYCLE_ROUTES_PG(pool, store);
    Rig rig{&store};
    REQUIRE(rig.import_csv()->status == 200);
    rig.audit.clear();
    exec_sql(lifecycle_routes_db_fx_.dsn(), "DROP SCHEMA software_lifecycle_store CASCADE");

    const auto get = rig.call("GET", kPath);
    CHECK(get->status == 503);
    CHECK(Rig::parse(*get)["error"]["retry_after_ms"].is_number());

    // The delete cannot read the count it audits, so it refuses before any audit row.
    const auto del = rig.call("DELETE", kPath);
    CHECK(del->status == 503);
    CHECK(Rig::parse(*del)["error"]["retry_after_ms"].is_number());
    CHECK(rig.audit_count("requested") == 0);

    // The import passes the parser, stores its `requested` row, fails the write and says so.
    const auto post = rig.import_csv();
    CHECK(post->status == 503);
    CHECK(Rig::parse(*post)["error"]["retry_after_ms"].is_number());
    REQUIRE(rig.audit.size() == 2);
    CHECK(rig.audit[0].result == "requested");
    CHECK(rig.audit[1].result == "failure");
}
