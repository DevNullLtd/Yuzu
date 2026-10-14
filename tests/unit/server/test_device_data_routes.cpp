/// @file test_device_data_routes.cpp
/// Route tests for GET /fragments/hardware/ci/properties, driven in-process through
/// TestRouteSink with fake gates. Covers the 401/400 ordering, the 200-note status
/// semantics (a denied or degraded read is never a non-2xx body htmx would drop), the
/// per-device vs global probe split, and the fail-fast Deps contract.

#include "device_data_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::device_data;

namespace {

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

struct Harness {
    bool authed = true;
    bool scoped_read = true;
    bool scoped_write = true;
    bool global_read = true;
    bool global_write = true;
    bool props_degraded = false;
    bool schemas_degraded = false;
    std::vector<PropertyRow> props{{"owner", "ops", "string", 1700000000}};
    std::vector<SchemaRow> schemas{{"owner", "Owner", "string", "", ""}};
    std::vector<std::string> probes; // "scoped:Type:Op:id" / "global:Type:Op"
    int props_calls = 0;

    yuzu::server::test::TestRouteSink sink; // LAST

    Harness() {
        Deps d;
        d.auth_fn = [this](const httplib::Request&,
                           httplib::Response& res) -> std::optional<auth::Session> {
            if (!authed) {
                res.status = 401;
                return std::nullopt;
            }
            return auth::Session{};
        };
        d.scoped_probe_fn = [this](const httplib::Request&, const std::string& t,
                                   const std::string& o, const std::string& id) {
            probes.push_back("scoped:" + t + ":" + o + ":" + id);
            return o == "Read" ? scoped_read : scoped_write;
        };
        d.global_probe_fn = [this](const httplib::Request&, const std::string& t,
                                   const std::string& o) {
            probes.push_back("global:" + t + ":" + o);
            return o == "Read" ? global_read : global_write;
        };
        d.properties_fn = [this](const std::string&) -> std::optional<std::vector<PropertyRow>> {
            ++props_calls;
            if (props_degraded)
                return std::nullopt;
            return props;
        };
        d.schemas_fn = [this]() -> std::optional<std::vector<SchemaRow>> {
            if (schemas_degraded)
                return std::nullopt;
            return schemas;
        };
        register_device_data_routes(sink, std::move(d));
    }
};

} // namespace

TEST_CASE("device data routes: an unauthenticated caller is 401 before any probe or read",
          "[device_data][routes]") {
    Harness h;
    h.authed = false;
    auto r = h.sink.Get("/fragments/hardware/ci/properties?id=agent-1");
    REQUIRE(r);
    CHECK(r->status == 401);
    CHECK(h.probes.empty());
    CHECK(h.props_calls == 0);
}

TEST_CASE("device data routes: a missing or control-byte id is 400 before any probe",
          "[device_data][routes]") {
    Harness h;
    auto missing = h.sink.Get("/fragments/hardware/ci/properties");
    REQUIRE(missing);
    CHECK(missing->status == 400);
    auto crlf = h.sink.Get("/fragments/hardware/ci/properties?id=a%0Ab");
    REQUIRE(crlf);
    CHECK(crlf->status == 400);
    auto huge = h.sink.Get("/fragments/hardware/ci/properties?id=" + std::string(300, 'a'));
    REQUIRE(huge);
    CHECK(huge->status == 400);
    CHECK(h.probes.empty());
}

TEST_CASE("device data routes: happy path renders properties and schemas with write controls",
          "[device_data][routes]") {
    Harness h;
    auto r = h.sink.Get("/fragments/hardware/ci/properties?id=agent-1");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(contains(r->body, "data-act=\"prop-add\""));
    CHECK(contains(r->body, "data-act=\"schema-save\""));
    // The per-device grants are probed against THIS device, the schema ones globally.
    CHECK(std::count(h.probes.begin(), h.probes.end(), "scoped:Infrastructure:Read:agent-1") == 1);
    CHECK(std::count(h.probes.begin(), h.probes.end(), "scoped:Infrastructure:Write:agent-1") == 1);
    CHECK(std::count(h.probes.begin(), h.probes.end(), "global:Infrastructure:Read") == 1);
    CHECK(std::count(h.probes.begin(), h.probes.end(), "global:Infrastructure:Write") == 1);
}

TEST_CASE("device data routes: a denied device read is a 200 note and the store is never read",
          "[device_data][routes]") {
    Harness h;
    h.scoped_read = false;
    auto r = h.sink.Get("/fragments/hardware/ci/properties?id=agent-1");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(contains(r->body, "Infrastructure:Read</b> permission for this device"));
    CHECK(h.props_calls == 0);
    // The write probe is not taken for a caller that cannot read.
    CHECK(std::count(h.probes.begin(), h.probes.end(), "scoped:Infrastructure:Write:agent-1") == 0);
    // Schemas are a separate global grant and still render.
    CHECK(contains(r->body, "Owner"));
}

TEST_CASE("device data routes: a confined caller sees the properties and a schemas note",
          "[device_data][routes]") {
    Harness h;
    h.global_read = false;
    auto r = h.sink.Get("/fragments/hardware/ci/properties?id=agent-1");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(contains(r->body, "fleet-wide <b>Infrastructure:Read</b> grant"));
    CHECK(contains(r->body, "data-act=\"prop-add\""));
    CHECK_FALSE(contains(r->body, "data-act=\"schema-save\""));
    CHECK(std::count(h.probes.begin(), h.probes.end(), "global:Infrastructure:Write") == 0);
}

TEST_CASE("device data routes: a degraded store is a 200 banner and never an empty list",
          "[device_data][routes]") {
    Harness h;
    h.props_degraded = true;
    h.schemas_degraded = true;
    auto r = h.sink.Get("/fragments/hardware/ci/properties?id=agent-1");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(contains(r->body, "Custom properties could not be read."));
    CHECK(contains(r->body, "Property schemas could not be read."));
    CHECK_FALSE(contains(r->body, "No properties set."));
}

TEST_CASE("device data routes: Deps with an unwired closure is refused at registration",
          "[device_data][routes]") {
    yuzu::server::test::TestRouteSink sink;
    Deps d;
    CHECK_THROWS_AS(register_device_data_routes(sink, d), std::invalid_argument);
}
