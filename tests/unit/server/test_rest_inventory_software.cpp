// test_rest_inventory_software.cpp — HTTP-level tests for the typed
// installed-software fleet read GET /api/v1/inventory/software (ADR-0016).
//
// This is the REST sibling of the governed MCP query_installed_software tool; the
// route mirrors that handler 1:1. #3290 Phase 2 migrated it onto
// AuthRoutes::require_fleet_read as the SOLE gate — perm_fn/auth_fn/
// InventoryScopeFn are no longer consulted by this route at all. The
// unit-level tests below (InvHarness) fake that gate with a plain
// authz::FleetReadGate the harness controls per-test; the real per-caller-
// class composition (service-scoped token vs. management-group-confined
// operator vs. unscoped) is proven against a REAL AuthRoutes in the [pg]
// "end-to-end confinement" section near the bottom of this file — the unit
// tests below only need to prove the ROUTE's own handling of whatever the
// gate decided.
//
// The tests pin:
//   - Gate deny (401/403) → no data, no success audit; unwired gate → 503.
//   - Two DISTINCT 503 paths, both asserted "never an empty 200":
//       * null/closed store → 503 "not available", NO audit (the store was never
//         consulted, so there is no access to record);
//       * OPEN store, query_software → std::nullopt (pool-acquire timeout / query
//         error) → 503 "degraded" AND a "failure" audit row (CC7.2: a triage caller
//         under a sustained outage still leaves a who/when/what trail). These are
//         NOT the same path — they differ precisely in the audit emission — so both
//         are tested here (the degrade path via a size-1 pool whose only lease is
//         held in-test, forcing try_acquire_for to time out).
//   - The gate's own composed scope FILTER (drops out-of-scope agents) +
//     devices_omitted + a distinct "denied" audit row.
//   - limit cap → result_truncated_by_cap; bad limit → 400.
//   - OpenAPI discoverability (A1): the path appears in /api/v1/openapi.json.
//
// Fixture mirrors the in-process TestRouteSink pattern (no socket, no acceptor
// thread, no TSan risk) from test_rest_software_packages.cpp.

#include "rest_api_v1.hpp"
#include "audit_store.hpp"
#include "auth_routes.hpp"
#include "authz_gates.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rbac_store.hpp"
#include "software_inventory_store.hpp"
#include "tag_store.hpp"
#include "test_api_token_pg_helper.hpp"  // ApiTokenStorePg
#include "test_mgmt_group_pg_helper.hpp" // ManagementGroupStorePg
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {
int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}
} // namespace

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): same key +
// identical setup as test_software_inventory_store.cpp (first build wins) —
// the store set here is exactly {SoftwareInventoryStore}.
yuzu::test::PgTestTemplate swinv_tpl{"swinv", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    SoftwareInventoryStore store{pool};
    // Throw, don't return: a silently-unmigrated template would make every
    // clone fall back to in-test migration — correct but slow, defeating the
    // point. PgTestTemplate::build records the throw as a fixture error.
    if (!store.is_open())
        throw std::runtime_error("swinv template: store failed to migrate");
}};

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_id;
    std::string detail;
};

// Wires GET /api/v1/inventory/software with a (borrowed, possibly null) typed
// store + a fake authz::FleetReadGate the harness controls per-test.
// `fleet_admitted`/`fleet_scope`/`fleet_deny_status` are mutable so a single
// fixture instance can drive each branch; `wire_fleet_read_fn` is ctor-only
// (registration-time, unlike the others — matches production's "unwired ==
// misconfiguration" contract, which is decided once at wiring, not per
// request).
struct InvHarness {
    yuzu::server::test::TestRouteSink sink;

    // Whatever the fake gate decides: true → the request proceeds with
    // fleet_scope (nullopt = TOP/unfiltered, matching a real global grant or
    // RBAC-off); false → the route returns immediately, whatever status/body
    // the fake gate wrote (fleet_deny_status/fleet_deny_message below).
    bool fleet_admitted{true};
    std::optional<std::unordered_set<std::string>> fleet_scope;
    int fleet_deny_status{403};
    std::string fleet_deny_message{"permission denied"};
    // When false, audit_fn reports a persistence failure (returns false) so a test can
    // exercise the set-and-proceed `audit_persisted:false` honesty field.
    bool audit_ok{true};
    // When true, audit_fn THROWS (bad_alloc-class / locked audit DB) — exercises the
    // #1647 throw-safe kernel: the route must not 500, it must serve with
    // audit_persisted:false (gov chaos CH-3, parity with the MCP sibling).
    bool audit_throws{false};
    std::vector<AuditRecord> audit_log;

    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    explicit InvHarness(SoftwareInventoryStore* store, bool wire_fleet_read_fn = true) {
        // Neither is called by GET /api/v1/inventory/software any more
        // (require_fleet_read is now its sole gate) — kept only because
        // register_routes still needs a value for its OTHER routes, none of
        // which this file's tests exercise.
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
                    res.status = fleet_deny_status;
                    res.set_content(R"({"error":{"message":")" + fleet_deny_message + R"("}})",
                                    "application/json");
                    return {};
                }
                return {true, fleet_scope};
            };
        }

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
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
                            /*auth_db=*/nullptr, /*directory_sync=*/nullptr,
                            /*stream_budget=*/nullptr, /*exec_visible_fn=*/{},
                            /*list_read_fn=*/{}, std::move(fleet_read_fn));
    }

    bool has_audit(const std::string& result) const {
        for (const auto& a : audit_log)
            if (a.action == "inventory.software.query" && a.result == result)
                return true;
        return false;
    }
};

} // namespace

// ── No-PG branches (always run) ──────────────────────────────────────────────

TEST_CASE("REST inventory/software: null store → 503, never an empty 200",
          "[rest][inventory_software]") {
    InvHarness h{/*store=*/nullptr};
    auto res = h.sink.Get("/api/v1/inventory/software");
    REQUIRE(res);
    CHECK(res->status == 503);
    // A4 error envelope + correlation id echoed on every path. Structural assert (not a
    // substring search): the body is a JSON object with an `error` key and — crucially —
    // NO `data` key, so it can never be mistaken for a success-with-empty-list (the
    // fail-open ADR-0016 §7 closes): a vuln-triage caller must read "unknown", not
    // "installed nowhere".
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body.contains("error"));
    CHECK_FALSE(body.contains("data"));
}

// #3290 Phase 2: the route's own auth is gone — require_fleet_read is the
// SOLE gate. This proves the route respects the gate's decision (whatever
// caller class produced it: RBAC deny, service-scope default-deny, RBAC-off,
// etc. — all resolved by the real gate, tested in the [pg] end-to-end
// section below and in test_authz_gates.cpp). At the unit level, only the
// route's OWN reaction to !admitted needs proving: no data leaked, no
// success audit, whatever status/body the gate wrote reaches the wire
// unmodified.
TEST_CASE("REST inventory/software: gate denies → its status/body reach the wire, "
          "no success audit",
          "[rest][inventory_software][security]") {
    InvHarness h{/*store=*/nullptr};
    h.fleet_admitted = false;
    h.fleet_deny_status = 403;
    auto res = h.sink.Get("/api/v1/inventory/software?name=Chrome");
    REQUIRE(res);
    CHECK(res->status == 403);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body.contains("error"));
    CHECK_FALSE(body.contains("data"));
    CHECK_FALSE(h.has_audit("success"));
}

TEST_CASE("REST inventory/software: gate 401s (unauthenticated) → no data leaked",
          "[rest][inventory_software][security]") {
    InvHarness h{/*store=*/nullptr};
    h.fleet_admitted = false;
    h.fleet_deny_status = 401;
    auto res = h.sink.Get("/api/v1/inventory/software");
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK_FALSE(h.has_audit("success"));
}

// require_fleet_read's own doc comment: unwired = misconfiguration, FAILS
// CLOSED (503) — never silently falls back to an unfiltered read.
TEST_CASE("REST inventory/software: unwired fleet_read_fn → 503, never a fallback admit",
          "[rest][inventory_software][security]") {
    InvHarness h{/*store=*/nullptr, /*wire_fleet_read_fn=*/false};
    auto res = h.sink.Get("/api/v1/inventory/software");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body.contains("error"));
    CHECK_FALSE(body.contains("data"));
    CHECK_FALSE(h.has_audit("success"));
}

TEST_CASE("REST inventory/software: path is in the OpenAPI spec (A1 discoverability)",
          "[rest][inventory_software]") {
    InvHarness h{/*store=*/nullptr};
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto spec = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(spec.is_discarded());
    REQUIRE(spec.contains("paths"));
    REQUIRE(spec["paths"].contains("/inventory/software"));
    CHECK(spec["paths"]["/inventory/software"].contains("get"));
}

// ── Live-PG branches ─────────────────────────────────────────────────────────

namespace {
// Seed one agent's machine-scope software via the store's own ingest path.
void seed(SoftwareInventoryStore& store, const std::string& agent,
          std::vector<SoftwareEntry> rows) {
    const std::string h = SoftwareInventoryStore::canonical_hash(rows);
    REQUIRE(store.apply_installed_software(agent, h, rows, 1000) ==
            InventoryIngestOutcome::kStored);
}
} // namespace

TEST_CASE("REST inventory/software: fleet read returns rows, count, devices_omitted=0",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"Google Chrome", "119", "Google", "2026-01-01"},
                          {"Firefox", "120", "Mozilla", ""}});

    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& data = body.at("data");
    CHECK(data.at("count").get<int>() == 2);
    CHECK(data.at("devices_omitted").get<int>() == 0);
    CHECK(data.at("software").size() == 2);
    CHECK_FALSE(data.contains("result_truncated_by_cap"));
    CHECK(h.has_audit("success"));
    CHECK_FALSE(h.has_audit("denied"));
}

TEST_CASE("REST inventory/software: rows carry the blob-v2 package fields",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    SoftwareEntry rpm;
    rpm.name = "bash";
    rpm.version = "5.2.21";
    rpm.publisher = "Fedora Project";
    rpm.install_date = "Mon 01 Jan 2026";
    rpm.kind = "package";
    rpm.ecosystem = "rpm";
    rpm.epoch = "0";
    rpm.release = "3.fc40";
    rpm.arch = "x86_64";
    rpm.signature_status = "signed";
    rpm.distro_id = "fedora";
    rpm.distro_version = "40";
    // A v1-shaped row (only the 4 legacy fields) beside it: the v2 keys must
    // still be present in the JSON, as empty strings (honest-empty contract).
    seed(store, "dev-v2", {rpm, {"Google Chrome", "126", "Google", ""}});

    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software?name=bash");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& sw = body.at("data").at("software");
    REQUIRE(sw.size() == 1);
    const auto& row = sw.at(0);
    CHECK(row.at("kind").get<std::string>() == "package");
    CHECK(row.at("ecosystem").get<std::string>() == "rpm");
    CHECK(row.at("epoch").get<std::string>() == "0");
    CHECK(row.at("release").get<std::string>() == "3.fc40");
    CHECK(row.at("arch").get<std::string>() == "x86_64");
    CHECK(row.at("signature_status").get<std::string>() == "signed");
    CHECK(row.at("distro_id").get<std::string>() == "fedora");
    CHECK(row.at("distro_version").get<std::string>() == "40");

    auto res2 = h.sink.Get("/api/v1/inventory/software?name=Google Chrome");
    REQUIRE(res2);
    auto body2 = nlohmann::json::parse(res2->body);
    const auto& row2 = body2.at("data").at("software").at(0);
    CHECK(row2.at("kind").get<std::string>().empty());
    CHECK(row2.at("ecosystem").get<std::string>().empty());
    CHECK(row2.at("signature_status").get<std::string>().empty());
    CHECK(row2.at("distro_version").get<std::string>().empty());
}

TEST_CASE("REST inventory/software: name filter narrows the fleet result",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"Google Chrome", "119", "Google", ""}, {"Slack", "4.0", "Slack", ""}});
    seed(store, "dev-b", {{"Google Chrome", "120", "Google", ""}});

    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software?name=Google Chrome");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& sw = body.at("data").at("software");
    REQUIRE(sw.size() == 2); // one per agent, both Chrome
    for (const auto& row : sw)
        CHECK(row.at("name").get<std::string>() == "Google Chrome");
}

TEST_CASE("REST inventory/software: scope filter drops out-of-scope agent + audits denied",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"Google Chrome", "119", "Google", ""}});
    seed(store, "dev-b", {{"Google Chrome", "120", "Google", ""}});

    InvHarness h{&store};
    // Operator may see dev-a only — dev-b's row must be dropped (not leaked).
    h.fleet_scope = std::unordered_set<std::string>{"dev-a"};

    auto res = h.sink.Get("/api/v1/inventory/software?name=Google Chrome");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& data = body.at("data");
    REQUIRE(data.at("software").size() == 1);
    CHECK(data.at("software")[0].at("agent_id").get<std::string>() == "dev-a");
    // The false-negative guard: a positive count tells the caller matching software
    // exists outside their scope (not "absent fleet-wide").
    CHECK(data.at("devices_omitted").get<int>() == 1);
    CHECK(h.has_audit("denied"));
    CHECK(h.has_audit("success"));
}

TEST_CASE("REST inventory/software: limit cap flags result_truncated_by_cap",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"AAA", "1", "", ""}, {"BBB", "1", "", ""}, {"CCC", "1", "", ""}});

    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software?limit=1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& data = body.at("data");
    CHECK(data.at("count").get<int>() == 1);
    CHECK(data.at("result_truncated_by_cap").get<bool>() == true);
}

TEST_CASE("REST inventory/software: non-integer limit → 400", "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software?limit=abc");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST inventory/software: ?agent_id= narrows to one device",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"Slack", "4.0", "Slack", ""}});
    seed(store, "dev-b", {{"Zoom", "5.0", "Zoom", ""}});

    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software?agent_id=dev-a");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& sw = body.at("data").at("software");
    REQUIRE(sw.size() == 1);
    CHECK(sw[0].at("agent_id").get<std::string>() == "dev-a");
    CHECK(sw[0].at("name").get<std::string>() == "Slack");
    CHECK(h.has_audit("success"));
}

TEST_CASE("REST inventory/software: over-max limit clamps (no error, no cap defeat)",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"AAA", "1", "", ""}, {"BBB", "1", "", ""}, {"CCC", "1", "", ""}});

    InvHarness h{&store};
    // limit=5000 > 1000 cap: must clamp (200, all rows), NOT error, NOT bind 5000. The
    // lower bind is proven by the limit=1 truncation test; both share the same
    // std::clamp<int64_t>(want,1,1000) call, so this guards the upper bound + the
    // "negative/wrapped value defeats the cap" hazard.
    auto res = h.sink.Get("/api/v1/inventory/software?limit=5000");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body.at("data").at("count").get<int>() == 3);
    CHECK_FALSE(body.at("data").contains("result_truncated_by_cap"));

    // The FLOOR arm of the clamp (gov Gate-8 N1): a negative/zero limit must NOT bind
    // `LIMIT -1` (unbounded in Postgres — the exact cap-defeat the int64 clamp guards).
    // Both clamp to 1 → exactly one row, no error.
    for (const char* q : {"limit=-1", "limit=0"}) {
        auto r = h.sink.Get(std::string("/api/v1/inventory/software?") + q);
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(nlohmann::json::parse(r->body).at("data").at("count").get<int>() == 1);
    }
}

TEST_CASE("REST inventory/software: failed audit surfaces audit_persisted:false (set-and-proceed)",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"Slack", "4.0", "Slack", ""}});

    InvHarness h{&store};
    h.audit_ok = false; // audit_fn reports a persistence failure
    auto res = h.sink.Get("/api/v1/inventory/software");
    REQUIRE(res);
    // Set-and-proceed: data STILL served (machine-scope, non-behavioural), but the body
    // honestly flags the lost evidence row — never withheld (distinct from the fail-closed
    // per-device behavioural routes).
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.at("data").at("software").size() == 1);
    CHECK(body.at("data").at("audit_persisted").get<bool>() == false);
}

TEST_CASE("REST inventory/software: devices_omitted counts DISTINCT dropped agents, not rows",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    // dev-b (the dropped agent) carries TWO matching rows — devices_omitted must be 1, not 2
    // (guards the `if (inserted)` distinct-count guard against a row-count regression).
    seed(store, "dev-a", {{"Common", "1", "", ""}});
    seed(store, "dev-b", {{"Common", "1", "", ""}, {"Common", "2", "", ""}});

    InvHarness h{&store};
    h.fleet_scope = std::unordered_set<std::string>{"dev-a"};
    auto res = h.sink.Get("/api/v1/inventory/software?name=Common");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& data = body.at("data");
    CHECK(data.at("software").size() == 1);          // only dev-a's row
    CHECK(data.at("devices_omitted").get<int>() == 1); // dev-b counted ONCE despite 2 rows
}

TEST_CASE("REST inventory/software: store degrade → 503 + failure audit, never empty",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    // size-1 pool: after the ctor migration releases its lease, the single connection
    // is free. We hold it for the duration of the request, so query_software's
    // try_acquire_for(kQueryAcquireTimeout) times out → std::nullopt → the route's
    // DEGRADE branch (distinct from null-store: it audits "failure"). This is the
    // authoritative-read contract (ADR-0016 §7) that drew a BLOCKING last round.
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    auto held = pool.acquire(); // starve the pool — the only connection is now ours
    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software?name=Chrome");
    REQUIRE(res);
    CHECK(res->status == 503);
    // NEVER a success-with-empty-list — structural assert: an A4 error envelope, no `data`.
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body.contains("error"));
    CHECK_FALSE(body.contains("data"));
    // The degrade path is distinct from null-store precisely in this audit emission.
    CHECK(h.has_audit("failure"));
    CHECK_FALSE(h.has_audit("success"));
}

TEST_CASE("REST inventory/software: throwing audit_fn does not 500 (throw-safe set-and-proceed)",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, swinv_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"Slack", "4.0", "Slack", ""}});

    InvHarness h{&store};
    h.audit_throws = true; // audit sink throws (bad_alloc-class / locked audit DB)
    auto res = h.sink.Get("/api/v1/inventory/software");
    REQUIRE(res);
    // The throw is caught by detail::try_persist_audit → returns false → the route STILL
    // serves 200 with audit_persisted:false, NEVER a 500 with no trail (gov chaos CH-3 —
    // throw-safety parity with the MCP sibling's mcp_audit, which wraps the same kernel).
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.at("data").at("software").size() == 1);
    CHECK(body.at("data").at("audit_persisted").get<bool>() == false);
}

// ═══════════════════════════════════════════════════════════════════════════
// [pg] end-to-end confinement — a REAL AuthRoutes::require_fleet_read, not
// InvHarness's fake gate above. Proves the actual meet(management-group,
// service-scope) composition this route exists to serve (#3290), against a
// real RbacStore/TagStore/ManagementGroupStore — coverage that exists
// NOWHERE else at the route level (test_authz_gates.cpp proves the
// primitive in isolation; this proves the ROUTE wires it correctly end to
// end, including the store query + JSON shape).
// ═══════════════════════════════════════════════════════════════════════════

namespace {

yuzu::test::PgTestTemplate inv_e2e_tpl{
    "rbacstore_inv_e2e", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        RbacStore rbac{pool};
        if (!rbac.is_open())
            throw std::runtime_error("inv e2e template: rbac store failed to migrate/seed");
        TagStore tags{pool};
        if (!tags.is_open())
            throw std::runtime_error("inv e2e template: tag store failed to migrate");
        SoftwareInventoryStore sw{pool};
        if (!sw.is_open())
            throw std::runtime_error("inv e2e template: software inventory store failed to migrate");
    }};

// Real end-to-end rig: RbacStorePg + ManagementGroupStorePg + ApiTokenStorePg
// + TagStore + SoftwareInventoryStore, all sharing one clone, wired into a
// real AuthRoutes + RestApiV1 exactly as server.cpp wires them (the
// fleet_read_fn lambda below is the SAME conversion ServerImpl::
// require_fleet_read performs). Management-group tree mirrors
// test_authz_gates.cpp's GatesRig:
//   P ─┬─ C1        S   (P and S are roots; C1,C2 are children of P)
//      └─ C2
// service "printers" == {a_p, a_c1, a_s}; a_c2 is mgmt-scoped but untagged.
struct InvE2ERig {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    PgPool pool;
    RbacStore rbac;
    yuzu::test::ManagementGroupStorePg mgmt_bundle;
    ManagementGroupStore& mgmt = *mgmt_bundle;
    yuzu::test::ApiTokenStorePg api_tokens;
    TagStore tags;
    SoftwareInventoryStore sw;
    // Real AuditStore (shares the rig's database via a second pool, its own
    // `audit_store` schema — same pattern as GatesRig in test_authz_gates.cpp)
    // so a gate-deny's audit_log call is regression-testable, not silently
    // discarded by a null store (quality-engineer, governance run 2026-08-20).
    PgPool audit_pool;
    AuditStore audit_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    std::unique_ptr<AuthRoutes> ar;
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;
    // Declared AFTER its route owner (`api`) per the fixture convention this
    // file's own test_route_sink_harness.cpp pins: the sink holds the
    // registered handler closures, so it must destruct BEFORE the owner
    // whose `this` those handlers might capture (cpp-safety, governance run
    // 2026-08-20 — non-exploitable today since RestApiV1::register_routes
    // never captures `this`, but the declaration order should not rely on
    // that staying true).
    yuzu::server::test::TestRouteSink sink;
    std::string gP, gC1, gC2, gS;

    explicit InvE2ERig(const std::string& dsn)
        : pool{{.conninfo = dsn, .size = 4}}, rbac{pool}, tags{pool}, sw{pool},
          audit_pool{{.conninfo = dsn, .size = 2}}, audit_store{audit_pool} {
        REQUIRE(pool.valid());
        REQUIRE(rbac.is_open());
        REQUIRE(tags.is_open());
        REQUIRE(sw.is_open());
        REQUIRE(audit_store.is_open());
        rbac.set_rbac_enabled(true);

        REQUIRE(rbac.create_role({"InvReader", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"InvReader", "Inventory", "Read", "allow"}).has_value());

        gP = make_group("P", "");
        gC1 = make_group("C1", gP);
        gC2 = make_group("C2", gP);
        gS = make_group("S", "");

        REQUIRE(mgmt.add_member(gP, "a_p").has_value());
        REQUIRE(mgmt.add_member(gC1, "a_c1").has_value());
        REQUIRE(mgmt.add_member(gC2, "a_c2").has_value());
        REQUIRE(mgmt.add_member(gS, "a_s").has_value());

        REQUIRE(tags.set_tag("a_p", "service", "printers").has_value());
        REQUIRE(tags.set_tag("a_c1", "service", "printers").has_value());
        REQUIRE(tags.set_tag("a_s", "service", "printers").has_value());
        // a_c2 deliberately untagged: inside mgmt scope, outside service scope.

        REQUIRE(auth_mgr.upsert_user("minter", "correct-horse-battery-staple", auth::Role::admin));

        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, &rbac, api_tokens.get(),
                                          &audit_store, &mgmt, &tags,
                                          /*analytics_store=*/nullptr, oidc_mu, oidc_provider);

        // The SAME conversion ServerImpl::require_fleet_read performs
        // (server.cpp) — production wires REST/MCP through this identical
        // shape, so a drift here would be a drift in production too.
        RestApiV1::FleetReadFn fleet_read_fn =
            [this](const httplib::Request& req, httplib::Response& res, const std::string& type,
                  const std::string& op) -> authz::FleetReadGate {
            auto r = ar->require_fleet_read(req, res, type, op);
            if (!r)
                return {};
            return {true, r->visible_for_query()};
        };
        auto auth_fn = [this](const httplib::Request& req,
                              httplib::Response& res) -> std::optional<auth::Session> {
            return ar->require_auth(req, res);
        };
        auto perm_fn = [this](const httplib::Request& req, httplib::Response& res,
                              const std::string& type, const std::string& op) -> bool {
            return ar->require_permission(req, res, type, op);
        };

        api.register_routes(sink, auth_fn, perm_fn, /*audit_fn=*/{},
                            /*rbac_store=*/&rbac, /*mgmt_store=*/&mgmt,
                            /*token_store=*/api_tokens.get(), /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr, /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr, /*tag_store=*/&tags,
                            /*audit_store=*/nullptr, /*service_group_fn=*/{}, /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr, /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr, /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr, /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/&metrics, /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr, /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{}, /*step_up_fn=*/{}, /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{}, /*network_api=*/{}, /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr, /*scoped_perm_fn=*/{}, &sw,
                            /*response_scope_fn=*/{},
                            /*engine_principal_store=*/nullptr, /*access_review_store=*/nullptr,
                            /*auth_db=*/nullptr, /*directory_sync=*/nullptr,
                            /*stream_budget=*/nullptr, /*exec_visible_fn=*/{},
                            /*list_read_fn=*/{}, std::move(fleet_read_fn));
    }

    std::string make_group(const std::string& name, const std::string& parent) {
        ManagementGroup g;
        g.name = name;
        g.membership_type = "static";
        g.parent_id = parent;
        auto id = mgmt.create_group(g);
        REQUIRE(id.has_value());
        return *id;
    }

    void group_assign(const std::string& group, const std::string& user, const std::string& role) {
        REQUIRE(mgmt.assign_role({group, "user", user, role}).has_value());
    }

    /// Mint a token as "minter" — scope_service empty ⇒ a non-service token.
    std::string mint(const std::string& scope_service = {}) {
        auto raw =
            api_tokens->create_token("inv-e2e", "minter", now_epoch() + 3600, scope_service);
        REQUIRE(raw.has_value());
        return *raw;
    }

    void seed_one(const std::string& agent) {
        std::vector<SoftwareEntry> rows{{"Chrome", "119", "Google", ""}};
        REQUIRE(sw.apply_installed_software(agent, SoftwareInventoryStore::canonical_hash(rows),
                                            rows, 1000) == InventoryIngestOutcome::kStored);
    }
};

std::unordered_map<std::string, std::string> bearer(const std::string& token) {
    return {{"Authorization", "Bearer " + token}};
}

} // namespace

TEST_CASE("REST inventory/software [e2e]: service-scoped token gets a real filtered "
          "200 — never the old blanket 403",
          "[pg][rest][inventory_software][service_scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, inv_e2e_tpl);
    InvE2ERig r{db.dsn()};
    r.seed_one("a_p");
    r.seed_one("a_c1");
    r.seed_one("a_s");
    r.seed_one("a_c2"); // in mgmt scope, outside service scope — must be dropped

    // require_fleet_read's mgmt-group axis is evaluated for EVERY caller,
    // service-scoped or not (unlike require_permission's separate
    // ITServiceOwner-only service branch) — a DenyAll mgmt axis short-
    // circuits to Forbidden before the service axis is even consulted
    // (test_authz_gates.cpp's "Deny × service S" case). So the minting
    // identity needs its own global grant; the service axis then narrows
    // it further via meet() (the "never unfiltered despite the global
    // grant" CDX-001 property).
    REQUIRE(r.rbac.assign_role({"user", "minter", "InvReader"}).has_value()); // GLOBAL allow
    auto token = r.mint("printers");
    auto res = r.sink.Get("/api/v1/inventory/software", bearer(token));
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& sw = body.at("data").at("software");
    std::unordered_set<std::string> seen;
    for (const auto& row : sw)
        seen.insert(row.at("agent_id").get<std::string>());
    CHECK(seen == std::unordered_set<std::string>{"a_p", "a_c1", "a_s"});
    CHECK(body.at("data").at("devices_omitted").get<int>() == 1); // a_c2 dropped
}

TEST_CASE("REST inventory/software [e2e]: management-group-confined operator gets a "
          "real filtered 200 (ADR-0017 World A gap closed for this route)",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, inv_e2e_tpl);
    InvE2ERig r{db.dsn()};
    r.seed_one("a_p");
    r.seed_one("a_c1");
    r.seed_one("a_c2");
    r.seed_one("a_s"); // outside P's subtree — must be dropped

    r.group_assign(r.gP, "minter", "InvReader"); // group-scoped grant, no global grant
    auto token = r.mint(); // non-service
    auto res = r.sink.Get("/api/v1/inventory/software", bearer(token));
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& sw = body.at("data").at("software");
    std::unordered_set<std::string> seen;
    for (const auto& row : sw)
        seen.insert(row.at("agent_id").get<std::string>());
    CHECK(seen == std::unordered_set<std::string>{"a_p", "a_c1", "a_c2"}); // INV-4 descendant expansion
    CHECK(body.at("data").at("devices_omitted").get<int>() == 1); // a_s dropped
}

TEST_CASE("REST inventory/software [e2e]: unscoped operator (global grant) sees the "
          "whole fleet unchanged",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, inv_e2e_tpl);
    InvE2ERig r{db.dsn()};
    r.seed_one("a_p");
    r.seed_one("a_s");

    REQUIRE(r.rbac.assign_role({"user", "minter", "InvReader"}).has_value()); // GLOBAL allow
    auto token = r.mint(); // non-service
    auto res = r.sink.Get("/api/v1/inventory/software", bearer(token));
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body.at("data").at("software").size() == 2);
    CHECK(body.at("data").at("devices_omitted").get<int>() == 0);
}

TEST_CASE("REST inventory/software [e2e]: tag-store degraded on a service token ⇒ 503",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, inv_e2e_tpl);
    InvE2ERig r{db.dsn()};
    REQUIRE(r.rbac.assign_role({"user", "minter", "InvReader"}).has_value());
    auto token = r.mint("printers");

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult res{PQexec(conn.get(), "DROP TABLE tag_store.tags CASCADE")};
        REQUIRE(res.ok());
    }

    auto res = r.sink.Get("/api/v1/inventory/software", bearer(token));
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("REST inventory/software [e2e]: service-scoped token, RBAC genuinely "
          "disabled ⇒ 403 (never let the tag axis alone admit a narrowed result)",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB_TPL(db, inv_e2e_tpl);
    InvE2ERig r{db.dsn()};
    r.rbac.set_rbac_enabled(false);
    auto token = r.mint("printers");
    auto res = r.sink.Get("/api/v1/inventory/software", bearer(token));
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("REST inventory/software [e2e]: a genuine gate deny gets exactly one "
          "X-Correlation-Id header and audits under the gate's own taxonomy, "
          "not the retired route-specific fleet target",
          "[pg][rest][inventory_software]") {
    // Restores the class of coverage quality-engineer flagged as dropped
    // (governance run 2026-08-20) — but for the CURRENT taxonomy, not the
    // pre-#3290 one: the old blanket-deny path (deny_fleet_wide_service_
    // scoped) audited as inventory.software.query/target_id=fleet with a
    // cid embedded in its detail string; require_fleet_read's own deny
    // branches audit as auth.fleet_read_required with EMPTY target_type/
    // target_id (matching require_permission's/require_list_read's
    // convention, authdb-confirmed Gate 3) and do not embed a cid in the
    // audit detail at all — a4_denial mints its own cid for the header
    // independently. Asserting the old cid-embedded-in-detail shape here
    // would pin a property this gate's convention does not provide, not a
    // regression; this test proves the property that DOES hold instead.
    YUZU_REQUIRE_PG_DB_TPL(db, inv_e2e_tpl);
    InvE2ERig r{db.dsn()};
    // "minter" holds no Inventory:Read grant at all ⇒ authorize_list_read
    // DenyAll ⇒ require_fleet_read's own 403 branch.
    auto token = r.mint();
    auto res = r.sink.Get("/api/v1/inventory/software", bearer(token));
    REQUIRE(res);
    CHECK(res->status == 403);

    // Exactly one value, not duplicated (the httplib multimap-append class
    // of bug: set_header appends rather than overwrites if called twice).
    auto cids = res->get_header_value_count("X-Correlation-Id");
    CHECK(cids == 1);
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());

    auto rows = r.audit_store.query({});
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    const auto& row = (*rows)[0];
    CHECK(row.action == "auth.fleet_read_required");
    CHECK(row.result == "denied");
    CHECK(row.target_type.empty());
    CHECK(row.target_id.empty());
}
