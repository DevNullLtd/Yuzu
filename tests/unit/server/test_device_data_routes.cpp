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

// ---- application usage and detected licences ---------------------------------------------

namespace {

struct UsageHarness {
    using Probe = UsageDeps::Probe;
    bool authed = true;
    Probe probe = Probe::Allowed;
    bool audit_persists = true;
    bool store_degraded = false;
    std::vector<std::string> events; // "probe:Sec:Op:id" "audit:verb:result" "read:app" "read:lic"
    std::vector<AppUsageRow> usage{{"C:/tools/a.exe", 100, 200, 5, 7200}};
    std::vector<LicenceRow> licences{{"Office", "Contoso", "16", "volume", "licensed", "KMS",
                                      "authoritative", "", "slmgr", 0}};

    yuzu::server::test::TestRouteSink sink; // LAST

    UsageHarness() {
        UsageDeps d;
        d.auth_fn = [this](const httplib::Request&,
                           httplib::Response& res) -> std::optional<auth::Session> {
            if (!authed) {
                res.status = 401;
                return std::nullopt;
            }
            return auth::Session{};
        };
        d.probe_fn = [this](const httplib::Request&, const std::string& t, const std::string& o,
                            const std::string& id) {
            events.push_back("probe:" + t + ":" + o + ":" + id);
            return probe;
        };
        d.audit_fn = [this](const httplib::Request&, const std::string& action,
                            const std::string& result, const std::string&, const std::string&,
                            const std::string&) {
            events.push_back("audit:" + action + ":" + result);
            return audit_persists;
        };
        d.usage_fn = [this](const std::string&) -> std::optional<AppUsageData> {
            events.push_back("read:app");
            if (store_degraded)
                return std::nullopt;
            return AppUsageData{usage, 1700000000};
        };
        d.licences_fn = [this](const std::string&) -> std::optional<std::vector<LicenceRow>> {
            events.push_back("read:lic");
            if (store_degraded)
                return std::nullopt;
            return licences;
        };
        register_device_usage_routes(sink, std::move(d));
    }
    bool saw(const std::string& e) const {
        return std::find(events.begin(), events.end(), e) != events.end();
    }
};

const char* kUsagePaths[] = {"/fragments/hardware/ci/app-usage?id=agent-1",
                             "/fragments/hardware/ci/licences?id=agent-1"};

} // namespace

TEST_CASE("usage routes: gate allowed renders the data after the audit row",
          "[device_data][routes][usage]") {
    UsageHarness h;
    auto a = h.sink.Get(kUsagePaths[0]);
    REQUIRE(a);
    CHECK(a->status == 200);
    CHECK(contains(a->body, "C:/tools/a.exe"));
    CHECK(contains(a->body, "2.0")); // 7200 s
    auto l = h.sink.Get(kUsagePaths[1]);
    REQUIRE(l);
    CHECK(contains(l->body, "Office"));
    // Order: probe, then the audit row, then the read (fail-closed audit-before-read).
    const std::vector<std::string> want{
        "probe:Forensics:Read:agent-1", "audit:app_usage.agent.view:success", "read:app",
        "probe:SoftwareLicensing:Read:agent-1", "audit:sle.agent.view:success", "read:lic"};
    CHECK(h.events == want);
}

// Kills: reading before the audit row, or serving after a known audit failure.
TEST_CASE("usage routes: an audit row that cannot persist withholds the data and flags it",
          "[device_data][routes][usage]") {
    for (const char* path : kUsagePaths) {
        UsageHarness h;
        h.audit_persists = false;
        auto r = h.sink.Get(path);
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(contains(r->body, "withheld"));
        CHECK_FALSE(contains(r->body, "C:/tools/a.exe"));
        CHECK_FALSE(contains(r->body, "Office"));
        CHECK_FALSE(h.saw("read:app"));
        CHECK_FALSE(h.saw("read:lic"));
    }
}

TEST_CASE("usage routes: a denied gate is a 200 note, no audit row, no read",
          "[device_data][routes][usage]") {
    UsageHarness h;
    h.probe = UsageHarness::Probe::Denied;
    auto a = h.sink.Get(kUsagePaths[0]);
    REQUIRE(a);
    CHECK(a->status == 200);
    CHECK(contains(a->body, "Forensics:Read"));
    auto l = h.sink.Get(kUsagePaths[1]);
    REQUIRE(l);
    CHECK(contains(l->body, "SoftwareLicensing:Read"));
    CHECK(h.events.size() == 2); // the two probes only
}

TEST_CASE("usage routes: unauthenticated is 401 and an unavailable gate is a banner",
          "[device_data][routes][usage]") {
    {
        UsageHarness h;
        h.authed = false;
        auto r = h.sink.Get(kUsagePaths[0]);
        REQUIRE(r);
        CHECK(r->status == 401);
        CHECK(h.events.empty());
    }
    UsageHarness h;
    h.probe = UsageHarness::Probe::Unavailable;
    auto r = h.sink.Get(kUsagePaths[0]);
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(contains(r->body, "could not be read"));
    CHECK_FALSE(h.saw("read:app"));
}

TEST_CASE("usage routes: a degraded store audits the failure and never renders an empty list",
          "[device_data][routes][usage]") {
    UsageHarness h;
    h.store_degraded = true;
    auto r = h.sink.Get(kUsagePaths[0]);
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(contains(r->body, "could not be read"));
    CHECK_FALSE(contains(r->body, "reported no application usage"));
    CHECK(h.saw("audit:app_usage.agent.view:failure"));
}

TEST_CASE("usage routes: a missing or oversized id is 400 before any probe",
          "[device_data][routes][usage]") {
    UsageHarness h;
    auto r = h.sink.Get("/fragments/hardware/ci/licences");
    REQUIRE(r);
    CHECK(r->status == 400);
    auto big = h.sink.Get("/fragments/hardware/ci/app-usage?id=" + std::string(300, 'a'));
    REQUIRE(big);
    CHECK(big->status == 400);
    CHECK(h.events.empty());
}

TEST_CASE("usage routes: UsageDeps with an unwired gate is refused at registration",
          "[device_data][routes][usage]") {
    yuzu::server::test::TestRouteSink sink;
    UsageDeps d;
    CHECK_THROWS_AS(register_device_usage_routes(sink, d), std::invalid_argument);
}

// ---- inventory sources -------------------------------------------------------------------

TEST_CASE("inventory sources: gate, degrade, empty and rows are each their own state",
          "[device_data][routes][sources]") {
    bool authed = true, allowed = true, degraded = false;
    std::vector<SourceRow> rows{{"installed_apps", 12, 1700000000}, {"<b>x", 3, 0}};
    int reads = 0;
    yuzu::server::test::TestRouteSink sink;
    SourcesDeps d;
    d.auth_fn = [&](const httplib::Request&, httplib::Response& res) -> std::optional<auth::Session> {
        if (!authed) {
            res.status = 401;
            return std::nullopt;
        }
        return auth::Session{};
    };
    d.global_probe_fn = [&](const httplib::Request&, const std::string& t, const std::string& o) {
        return allowed && t == "Inventory" && o == "Read";
    };
    d.sources_fn = [&]() -> std::optional<std::vector<SourceRow>> {
        ++reads;
        if (degraded)
            return std::nullopt;
        return rows;
    };
    register_inventory_sources_route(sink, d);

    auto ok = sink.Get("/fragments/inventory/sources");
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(contains(ok->body, "installed_apps"));
    CHECK(contains(ok->body, "&lt;b&gt;x")); // escaped
    CHECK(contains(ok->body, "Last collected"));

    allowed = false;
    reads = 0;
    auto denied = sink.Get("/fragments/inventory/sources");
    REQUIRE(denied);
    CHECK(denied->status == 200);
    CHECK(contains(denied->body, "fleet-wide <b>Inventory:Read</b>"));
    CHECK(reads == 0);

    allowed = true;
    degraded = true;
    auto bad = sink.Get("/fragments/inventory/sources");
    REQUIRE(bad);
    CHECK(contains(bad->body, "could not be read"));
    CHECK_FALSE(contains(bad->body, "No inventory has been collected yet."));

    degraded = false;
    rows.clear();
    CHECK(contains(sink.Get("/fragments/inventory/sources")->body,
                   "No inventory has been collected yet."));

    authed = false;
    CHECK(sink.Get("/fragments/inventory/sources")->status == 401);

    yuzu::server::test::TestRouteSink bare;
    CHECK_THROWS_AS(register_inventory_sources_route(bare, SourcesDeps{}), std::invalid_argument);
}
