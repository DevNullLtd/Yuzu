/// @file test_result_set_routes.cpp
/// HTTP-level coverage for the 6-route Result Sets fragment API (scope
/// walking §30, #2542 PR-5) — driven in-process through TestRouteSink (no
/// httplib acceptor, #438), mirroring test_page_routes.cpp's /
/// test_custom_properties_routes.cpp's Harness shape.
///
/// Split by whether a case needs a live Postgres-backed `ResultSetStore`
/// (it has no virtual seam — `Deps::store` is a concrete pointer per this
/// package's spec — so anything past the two gates that touches a real
/// store needs Postgres):
///   - The route count, every gate-order pin (`deny_service_scoped_fn`
///     always before `auth_fn`, with the documented action/target_type/
///     target_id per route), the service-scoped-denial 403 (before
///     `auth_fn` or the store is touched), the unauthenticated 401 (after
///     the scoped-deny gate, before the store is touched), and the
///     documented THREE-WAY null-store degrade asymmetry (see
///     result_set_routes.hpp's header comment) all run WITHOUT Postgres.
///   - The CRUD round trips, the ownership-fold behaviour (ADR-0036 — only
///     the not-found and not-owned legs of `rs_get_owned`'s three-way fold
///     are exercised below; the third leg, a genuine DbError from `get()`
///     itself, is NOT independently tested here -- the DROP-TABLE case
///     further down forces a DbError through `create_materialized` instead,
///     a different store method `rs_get_owned` never calls, so it does not
///     cover this fold's DbError branch), and the per-mutation audit/toast
///     asymmetries (pin's PinLimit-vs-failure split, delete's unaudited
///     failure) are `[pg]`,
///     gated behind YUZU_TEST_POSTGRES_DSN via a pre-migrated
///     PgTestTemplate shared with test_result_set_store.cpp (same "resultset"
///     template key — see that file's `result_set_tpl` doc comment on why
///     sharing a key across files is safe here: identical setup).
///
/// NOT independently reproduced here (documented, not silently skipped):
/// unpin's "DB-level failure after the ownership pre-check already passed"
/// branch (audited ALWAYS "failure", per result_set_routes.hpp) is a TOCTOU
/// race between `rs_get_owned`'s read and `unpin`'s own update — this
/// single-threaded harness has no way to interleave a delete between the
/// two calls within one dispatch(), and forcing a DB-level error (e.g.
/// dropping the table, custom_properties_routes' technique) would also
/// break the ownership pre-check itself, which folds a DbError into
/// "not found" and never reaches `unpin` at all. The claim is verified by
/// reading result_set_routes.cpp directly, not by a live-fire test.

#include "result_set_routes.hpp"
#include "test_route_sink.hpp"

#include "result_set_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <fstream>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

/// All providers injected and re-read per call, mirroring
/// test_page_routes.cpp's / test_custom_properties_routes.cpp's Harness
/// shape. `store` defaults to null — every case that must NOT need
/// Postgres leaves it null and relies on the route returning before it
/// would be dereferenced.
///
/// Declaration order: `sink` LAST (CLAUDE.md / test_route_sink.hpp
/// convention) — its registered handlers capture `this` and hold pointers
/// into this struct's other members, so those members must outlive it.
struct Harness {
    ResultSetStore* store{nullptr};
    yuzu::MetricsRegistry metrics;

    bool deny_scoped{false};
    bool deny_scoped_fn_called{false};
    std::string last_deny_action, last_deny_target_type, last_deny_target_id;

    bool session_present{true};
    std::string session_username{"alice"};
    bool auth_fn_called{false};

    bool audit_succeeds{true};
    std::vector<AuditRow> audits;

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        result_set::Deps deps;
        deps.store = store;
        deps.metrics = &metrics;
        deps.deny_service_scoped_fn = [this](const httplib::Request&, httplib::Response& res,
                                             const std::string& action, const std::string&,
                                             const std::string& target_type,
                                             const std::string& target_id) -> bool {
            deny_scoped_fn_called = true;
            last_deny_action = action;
            last_deny_target_type = target_type;
            last_deny_target_id = target_id;
            if (deny_scoped) {
                res.status = 403;
                res.set_content(
                    R"({"error":{"code":403,"message":"service-scoped tokens may not do this"}})",
                    "application/json");
                return true;
            }
            return false;
        };
        deps.auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            auth_fn_called = true;
            if (!session_present) {
                res.status = 401;
                res.set_content(R"({"error":{"code":401,"message":"unauthenticated"}})",
                                "application/json");
                return std::nullopt;
            }
            auth::Session s;
            s.username = session_username;
            s.role = auth::Role::user;
            return s;
        };
        deps.audit_fn = [this](const httplib::Request&, const std::string& a,
                               const std::string& r, const std::string& tt,
                               const std::string& ti, const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return audit_succeeds;
        };
        result_set::register_result_set_routes(sink, deps);
    }

    void reset_gate_tracking() {
        deny_scoped_fn_called = false;
        auth_fn_called = false;
    }
};

// A syntactically-valid id for the `rs_[0-9a-f]+` route regex — never
// resolved against a real store in the non-[pg] tests below.
const std::string kFakeId = "rs_deadbeef0123";

} // namespace

// ── Registration shape ────────────────────────────────────────────────────

TEST_CASE("result_set_routes: registers exactly 6 routes",
          "[server][routes][result_set_routes]") {
    Harness h;
    h.wire();
    CHECK(h.sink.route_count() == 6);
}

// ── Gate order (no Postgres needed) ─────────────────────────────────────────

TEST_CASE("result_set_routes: every route gates on deny_service_scoped_fn "
          "BEFORE auth_fn, with the documented action/target_type/target_id",
          "[server][routes][result_set_routes]") {
    Harness h; // store stays null; every route returns before touching it
    h.wire();

    h.reset_gate_tracking();
    h.sink.Get("/fragments/result-sets/sidebar");
    CHECK(h.deny_scoped_fn_called);
    CHECK(h.auth_fn_called); // deny_scoped==false -> falls through to auth_fn
    CHECK(h.last_deny_action == "result_set.sidebar.access_denied");
    CHECK(h.last_deny_target_type == "ResultSet");
    CHECK(h.last_deny_target_id.empty());

    h.reset_gate_tracking();
    h.sink.Get("/fragments/result-sets/" + kFakeId + "/detail");
    CHECK(h.deny_scoped_fn_called);
    CHECK(h.auth_fn_called);
    CHECK(h.last_deny_action == "result_set.detail.access_denied");
    CHECK(h.last_deny_target_id == kFakeId);

    h.reset_gate_tracking();
    h.sink.Post("/fragments/result-sets/" + kFakeId + "/pin", "");
    CHECK(h.deny_scoped_fn_called);
    CHECK(h.auth_fn_called);
    CHECK(h.last_deny_action == "result_set.pin.access_denied");
    CHECK(h.last_deny_target_id == kFakeId);

    h.reset_gate_tracking();
    h.sink.Post("/fragments/result-sets/" + kFakeId + "/unpin", "");
    CHECK(h.deny_scoped_fn_called);
    CHECK(h.auth_fn_called);
    CHECK(h.last_deny_action == "result_set.unpin.access_denied");
    CHECK(h.last_deny_target_id == kFakeId);

    h.reset_gate_tracking();
    h.sink.Post("/fragments/result-sets/" + kFakeId + "/delete", "");
    CHECK(h.deny_scoped_fn_called);
    CHECK(h.auth_fn_called);
    CHECK(h.last_deny_action == "result_set.delete.access_denied");
    CHECK(h.last_deny_target_id == kFakeId);

    h.reset_gate_tracking();
    h.sink.Post("/fragments/result-sets/create", "", "application/x-www-form-urlencoded");
    CHECK(h.deny_scoped_fn_called);
    CHECK(h.auth_fn_called);
    CHECK(h.last_deny_action == "result_set.create.access_denied");
    CHECK(h.last_deny_target_id.empty());
}

TEST_CASE("result_set_routes: a service-scoped-token denial 403s on all 6 "
          "routes, before auth_fn or the store is touched",
          "[server][routes][result_set_routes]") {
    Harness h; // store stays null -- a dereference would crash; 403 must win first
    h.deny_scoped = true;
    h.wire();

    for (const auto& [method, path] : std::vector<std::pair<std::string, std::string>>{
             {"GET", "/fragments/result-sets/sidebar"},
             {"GET", "/fragments/result-sets/" + kFakeId + "/detail"},
             {"POST", "/fragments/result-sets/" + kFakeId + "/pin"},
             {"POST", "/fragments/result-sets/" + kFakeId + "/unpin"},
             {"POST", "/fragments/result-sets/" + kFakeId + "/delete"},
             {"POST", "/fragments/result-sets/create"},
         }) {
        INFO("path: " << path);
        h.reset_gate_tracking();
        auto r = h.sink.dispatch(method, path);
        REQUIRE(r);
        CHECK(r->status == 403);
        CHECK_FALSE(h.auth_fn_called); // never reached
    }
}

TEST_CASE("result_set_routes: an unauthenticated caller 401s on all 6 routes "
          "(after the scoped-deny gate), before the store is touched",
          "[server][routes][result_set_routes]") {
    Harness h; // store stays null
    h.session_present = false;
    h.wire();

    for (const auto& [method, path] : std::vector<std::pair<std::string, std::string>>{
             {"GET", "/fragments/result-sets/sidebar"},
             {"GET", "/fragments/result-sets/" + kFakeId + "/detail"},
             {"POST", "/fragments/result-sets/" + kFakeId + "/pin"},
             {"POST", "/fragments/result-sets/" + kFakeId + "/unpin"},
             {"POST", "/fragments/result-sets/" + kFakeId + "/delete"},
             {"POST", "/fragments/result-sets/create"},
         }) {
        INFO("path: " << path);
        h.reset_gate_tracking();
        auto r = h.sink.dispatch(method, path);
        REQUIRE(r);
        CHECK(r->status == 401);
        CHECK(h.deny_scoped_fn_called);
        CHECK(h.auth_fn_called);
    }
    CHECK(h.audits.empty()); // every branch above is unaudited
}

// ── Null-store degrade — THREE distinct shapes, preserved verbatim
//    (see result_set_routes.hpp's "THREE-WAY DEGRADE ASYMMETRY") ──────────

TEST_CASE("result_set_routes: GET sidebar with a null store renders a "
          "LITERALLY EMPTY 200 body",
          "[server][routes][result_set_routes]") {
    Harness h;
    h.wire();

    auto r = h.sink.Get("/fragments/result-sets/sidebar");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->body.empty());
    CHECK(h.audits.empty());
}

TEST_CASE("result_set_routes: GET detail with a null store renders the "
          "non-empty empty-detail-pane markup, 200",
          "[server][routes][result_set_routes]") {
    Harness h;
    h.wire();

    auto r = h.sink.Get("/fragments/result-sets/" + kFakeId + "/detail");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK_FALSE(r->body.empty());
    CHECK(r->body.find("rs-detail-empty") != std::string::npos);
    CHECK(h.audits.empty());
}

TEST_CASE("result_set_routes: POST pin/unpin/delete/create with a null store "
          "return 200 with NOTHING set on the response at all",
          "[server][routes][result_set_routes]") {
    Harness h;
    h.wire();

    auto pin = h.sink.Post("/fragments/result-sets/" + kFakeId + "/pin", "");
    REQUIRE(pin);
    CHECK(pin->status == 200);
    CHECK(pin->body.empty());
    CHECK(pin->get_header_value("Content-Type").empty());

    auto unpin = h.sink.Post("/fragments/result-sets/" + kFakeId + "/unpin", "");
    REQUIRE(unpin);
    CHECK(unpin->status == 200);
    CHECK(unpin->body.empty());

    auto del = h.sink.Post("/fragments/result-sets/" + kFakeId + "/delete", "");
    REQUIRE(del);
    CHECK(del->status == 200);
    CHECK(del->body.empty());

    auto create =
        h.sink.Post("/fragments/result-sets/create", "", "application/x-www-form-urlencoded");
    REQUIRE(create);
    CHECK(create->status == 200);
    CHECK(create->body.empty());

    CHECK(h.audits.empty()); // none of the four reached the store/audit call
}

// ═══════════════════════════════════════════════════════════════════════════
// [pg] cases: real ResultSetStore
// ═══════════════════════════════════════════════════════════════════════════

namespace {

// Shares the "resultset" template key with test_result_set_store.cpp — the
// registry builds the named template once per process regardless of which
// file's PgTestTemplate instance triggers it first (identical setup body,
// so sharing is safe per PgTestTemplate's own doc comment).
yuzu::test::PgTestTemplate route_result_set_tpl{
    "resultset", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        ResultSetStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("resultset routes template: store failed to migrate");
    }};

struct PgWired {
    yuzu::server::pg::PgPool pool;
    ResultSetStore store;

    explicit PgWired(const std::string& dsn) : pool{{.conninfo = dsn, .size = 4}}, store{pool} {
        REQUIRE(store.is_open());
    }
};

CreateRequest simple_req(const std::string& owner) {
    CreateRequest r;
    r.owner_principal = owner;
    r.source_kind = std::string(source_kind::kInventoryQuery);
    r.source_payload = "{}";
    return r;
}

} // namespace

TEST_CASE("result_set_routes: [pg] sidebar on an empty store shows the "
          "empty-state markup",
          "[pg][server][routes][result_set_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_result_set_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto r = h.sink.Get("/fragments/result-sets/sidebar");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->body.find("rs-empty") != std::string::npos);
}

TEST_CASE("result_set_routes: [pg] create round trip from pasted device IDs, "
          "with the documented success-audit + HX-Trigger shape",
          "[pg][server][routes][result_set_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_result_set_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    auto r = h.sink.Post("/fragments/result-sets/create", "device_ids=dev-1,dev-2%0Adev-3",
                         "application/x-www-form-urlencoded");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->get_header_value("HX-Trigger") == "resultSetsChanged");
    CHECK(r->body.find("rs-item") != std::string::npos); // sidebar, not the detail pane

    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "result_set.create");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].target_type == "ResultSet");
    CHECK_FALSE(h.audits[0].target_id.empty());

    // The 3 comma/newline-separated device ids materialized as members.
    std::string next_cursor;
    auto sets = w.store.list_by_owner("alice", "", 10, next_cursor);
    REQUIRE(sets.size() == 1);
    CHECK(sets[0].device_count == 3);
    CHECK(sets[0].owner_principal == "alice");
}

// Regression-pins the claim the next comment block relies on: an
// oversized POST body is rejected by httplib's own payload-size cap
// BEFORE this route (or its `TooManyMembers` validation) ever runs --
// this used to be a one-time manual observation, not an assertion (Gate
// 3 quality-engineer finding).
TEST_CASE("result_set_routes: create's device_ids parsing is unreachable "
          "past httplib's own form-payload size cap -- 413, not 200",
          "[server][routes][result_set_routes]") {
    Harness h;
    h.wire();

    std::string oversized = "device_ids=" + std::string(8193, 'a');
    auto r = h.sink.Post("/fragments/result-sets/create", oversized,
                         "application/x-www-form-urlencoded");
    REQUIRE(r);
    CHECK(r->status == 413);
    // Pin "rejected before the handler ever runs" directly, not just via
    // audits.empty() -- that alone would also pass if the handler ran and
    // hit its own null-store early return (Gate 4 happy-path finding).
    CHECK_FALSE(h.deny_scoped_fn_called);
    CHECK_FALSE(h.auth_fn_called);
    CHECK(h.audits.empty());
}

// NOTE ON THE TWO create_materialized ERROR KINDS THIS SUITE DOES NOT
// TRIGGER: `TooManyMembers` (>kMaxMembersPerSet=100000 distinct ids) is
// UNREACHABLE via this HTTP route in both production and this harness —
// httplib's own `CPPHTTPLIB_FORM_URL_ENCODED_PAYLOAD_MAX_LENGTH` (8192
// bytes) rejects the request with 413 BEFORE `device_ids` is ever parsed
// into `req.params`, and 8192 bytes cannot encode 100001 distinct
// comma-separated ids -- pinned by the TEST_CASE directly above, not just
// asserted in prose. `QuotaExceeded` (kMaxPerOwner=10000 existing sets for
// one owner) is reachable in principle but prohibitively expensive to set
// up (10000 rows) — expensive enough that even test_result_set_store.cpp's
// own comprehensive suite does not test it. The "ALWAYS denied, regardless
// of which specific error" claim is instead verified below via a THIRD,
// cheap-to-trigger error kind: a generic DbError (dropped table), using the
// same technique as test_custom_properties_routes.cpp's store-degrade case.
TEST_CASE("result_set_routes: [pg] create failing with a generic DbError "
          "(not Too-Many-Members/Quota) is STILL audited 'denied' -- the "
          "classification is unconditional, not error-kind-specific -- with "
          "no quota-metric increment and the SIDEBAR re-rendered",
          "[pg][server][routes][result_set_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_result_set_tpl);
    PgWired w{db.dsn()};
    Harness h;
    h.store = &w.store;
    h.wire();

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult r{
            PQexec(conn.get(), "DROP TABLE result_set_store.result_sets CASCADE")};
        REQUIRE(r.ok());
    }

    auto r = h.sink.Post("/fragments/result-sets/create", "device_ids=dev-1",
                         "application/x-www-form-urlencoded");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->get_header_value("HX-Trigger").find("showToast") != std::string::npos);
    CHECK(r->get_header_value("HX-Trigger") != "resultSetsChanged");
    CHECK(r->body.find("rs-empty") != std::string::npos); // sidebar re-rendered, still empty

    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "result_set.create");
    CHECK(h.audits[0].result == "denied"); // ALWAYS "denied", even for a plain DbError
    CHECK(h.audits[0].target_id.empty());  // no id exists yet
    CHECK(h.audits[0].detail == "RESULT_SET_DB_ERROR");

    // Only QuotaExceeded/TooManyMembers increment the counter -- a plain
    // DbError does not.
    CHECK(h.metrics.counter("yuzu_result_set_quota_rejected").value() == 0.0);
}

TEST_CASE("result_set_routes: [pg] GET detail folds not-found AND "
          "not-owned-by-this-session into the SAME empty-detail render "
          "(ADR-0036 fail-closed ownership read)",
          "[pg][server][routes][result_set_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_result_set_tpl);
    PgWired w{db.dsn()};
    auto owned_by_bob = w.store.create_materialized(simple_req("bob"), {"dev-1"});
    REQUIRE(owned_by_bob.has_value());

    Harness h;
    h.store = &w.store;
    h.session_username = "alice"; // NOT bob
    h.wire();

    auto not_found = h.sink.Get("/fragments/result-sets/" + kFakeId + "/detail");
    REQUIRE(not_found);
    CHECK(not_found->status == 200);
    CHECK(not_found->body.find("rs-detail-empty") != std::string::npos);

    auto not_owned = h.sink.Get("/fragments/result-sets/" + owned_by_bob->id + "/detail");
    REQUIRE(not_owned);
    CHECK(not_owned->status == 200);
    CHECK(not_owned->body.find("rs-detail-empty") != std::string::npos);
    CHECK(h.audits.empty()); // GET is never audited, either branch

    // Confirm the happy path DOES render real data, for contrast -- bob's
    // own session sees his own set.
    Harness bob_h;
    bob_h.store = &w.store;
    bob_h.session_username = "bob";
    bob_h.wire();
    auto owned = bob_h.sink.Get("/fragments/result-sets/" + owned_by_bob->id + "/detail");
    REQUIRE(owned);
    CHECK(owned->status == 200);
    CHECK(owned->body.find("from_result_set:" + owned_by_bob->id) != std::string::npos);
}

TEST_CASE("result_set_routes: [pg] pin/unpin success round trip, with the "
          "documented success-audit + HX-Trigger shape",
          "[pg][server][routes][result_set_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_result_set_tpl);
    PgWired w{db.dsn()};
    auto rs = w.store.create_materialized(simple_req("alice"), {"dev-1"});
    REQUIRE(rs.has_value());

    Harness h;
    h.store = &w.store;
    h.wire();

    auto pin = h.sink.Post("/fragments/result-sets/" + rs->id + "/pin", "");
    REQUIRE(pin);
    CHECK(pin->status == 200);
    CHECK(pin->get_header_value("HX-Trigger") == "resultSetsChanged");
    CHECK(pin->body.find("rs-badge-pinned") != std::string::npos);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "result_set.pin");
    CHECK(h.audits[0].result == "success");

    auto unpin = h.sink.Post("/fragments/result-sets/" + rs->id + "/unpin", "");
    REQUIRE(unpin);
    CHECK(unpin->status == 200);
    CHECK(unpin->get_header_value("HX-Trigger") == "resultSetsChanged");
    CHECK(unpin->body.find("rs-badge-pinned") == std::string::npos);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[1].action == "result_set.unpin");
    CHECK(h.audits[1].result == "success");
}

TEST_CASE("result_set_routes: [pg] pin beyond kMaxPinsPerOwner audits "
          "'denied' (NOT 'failure'), with the pre-attempt row re-rendered "
          "and no HX-Trigger",
          "[pg][server][routes][result_set_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_result_set_tpl);
    PgWired w{db.dsn()};

    // Fill alice's cap directly against the store (bypassing HTTP for
    // speed) -- the cap-enforcement mechanics are already covered by
    // test_result_set_store.cpp's own PinLimit test; this test only proves
    // the ROUTE classifies the resulting error correctly.
    std::string over_id;
    for (int i = 0; i <= ResultSetStore::kMaxPinsPerOwner; ++i) {
        auto rs = w.store.create_materialized(simple_req("alice"), {"dev-" + std::to_string(i)});
        REQUIRE(rs.has_value());
        if (i < ResultSetStore::kMaxPinsPerOwner) {
            REQUIRE(w.store.pin(rs->id).has_value());
        } else {
            over_id = rs->id; // the 51st -- left unpinned, attempted via HTTP below
        }
    }

    Harness h;
    h.store = &w.store;
    h.wire();

    auto r = h.sink.Post("/fragments/result-sets/" + over_id + "/pin", "");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->get_header_value("HX-Trigger").find("showToast") != std::string::npos);
    CHECK(r->get_header_value("HX-Trigger") != "resultSetsChanged");
    CHECK(r->body.find("rs-badge-pinned") == std::string::npos); // still unpinned

    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "result_set.pin");
    CHECK(h.audits[0].result == "denied"); // PinLimit -> "denied", not "failure"
    CHECK(h.audits[0].detail == "PIN_LIMIT");
}

TEST_CASE("result_set_routes: [pg] delete on a pinned set fails WITHOUT any "
          "audit call or toast -- silently re-renders the existing detail",
          "[pg][server][routes][result_set_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_result_set_tpl);
    PgWired w{db.dsn()};
    auto rs = w.store.create_materialized(simple_req("alice"), {"dev-1"});
    REQUIRE(rs.has_value());
    REQUIRE(w.store.pin(rs->id).has_value());

    Harness h;
    h.store = &w.store;
    h.wire();

    auto r = h.sink.Post("/fragments/result-sets/" + rs->id + "/delete", "");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->get_header_value("HX-Trigger").empty()); // no toast, no resultSetsChanged
    CHECK(r->body.find("rs-detail-empty") == std::string::npos); // NOT the empty pane
    CHECK(r->body.find("rs-badge-pinned") != std::string::npos); // the still-pinned row
    CHECK(h.audits.empty()); // delete failure is unaudited

    // The set is still there.
    auto still_there = w.store.get(rs->id);
    REQUIRE(still_there.has_value());
    CHECK(still_there->has_value());
}

TEST_CASE("result_set_routes: [pg] delete success round trip audits and "
          "renders the empty detail pane",
          "[pg][server][routes][result_set_routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, route_result_set_tpl);
    PgWired w{db.dsn()};
    auto rs = w.store.create_materialized(simple_req("alice"), {"dev-1"});
    REQUIRE(rs.has_value());

    Harness h;
    h.store = &w.store;
    h.wire();

    auto r = h.sink.Post("/fragments/result-sets/" + rs->id + "/delete", "");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->get_header_value("HX-Trigger") == "resultSetsChanged");
    CHECK(r->body.find("rs-detail-empty") != std::string::npos);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "result_set.delete");
    CHECK(h.audits[0].result == "success");

    auto gone = w.store.get(rs->id);
    REQUIRE(gone.has_value());
    CHECK_FALSE(gone->has_value());
}

// ═══════════════════════════════════════════════════════════════════════════
// Wiring tripwire: every case above proves register_result_set_routes' OWN
// handlers are correct, but nothing above reads server.cpp — a future edit
// that drops the production `register_result_set_routes(...)` call at
// server.cpp's registration site would leave every case above green while
// the real server 404s all 6 routes (custom_properties_routes' PR-4
// precedent for this tripwire; see that file's own tail comment).
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("result_set_routes: wiring -- server.cpp still calls "
          "register_result_set_routes",
          "[server][routes][result_set_routes]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    CHECK(src.find("register_result_set_routes(") != std::string::npos);
}
