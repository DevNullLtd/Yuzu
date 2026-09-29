/// @file test_approval_routes.cpp
/// HTTP-level coverage for the 4-route Approval API (#2542 PR-9) — driven
/// in-process through TestRouteSink (no httplib acceptor, #438), mirroring
/// test_custom_properties_routes.cpp's / test_result_set_routes.cpp's
/// Harness shape.
///
/// Split by whether a case needs a live Postgres-backed `ApprovalManager`
/// (it has no virtual seam — `Deps::approval_manager` is a concrete
/// pointer per this package's spec — so anything past the gate that
/// touches a real store needs Postgres, via the shared
/// `test_approval_manager_pg_helper.hpp` fixture):
///   - Every gate-denial pin (which securable/operation each route
///     passes), and the null-store degrade on all 4 routes (including the
///     STORE-UNAVAILABLE ASYMMETRY this module preserves verbatim — see
///     approval_routes.hpp's file header: 3 routes 503, pending/count
///     answers 200 `{"count":0}`) all run WITHOUT Postgres — each returns
///     before the handler would dereference `deps.approval_manager`.
///   - The list/pending-count/approve/reject round-trip, the real
///     self-approval segregation-of-duties denial (enforced inside
///     `ApprovalManager::set_review_status`, not this module), the
///     audit-row shapes (including the AUDIT ASYMMETRY this module
///     preserves verbatim — both GET routes unaudited, approve/reject
///     audit both outcomes and emit an event ONLY on success), and the
///     query-parameter filters are `[pg]`, gated behind
///     YUZU_TEST_POSTGRES_DSN via `ApprovalManagerPg`.
///
/// Wiring-regression tripwire (mirrors test_custom_properties_routes.cpp's
/// #4078-tracked pattern): a source-text scan pinning that server.cpp still
/// calls `register_approval_routes` — the gate-pinning TEST_CASEs above
/// prove `register_approval_routes`'s OWN handlers are correct, but nothing
/// above reads server.cpp, so a future edit dropping the production
/// registration call would leave every case above green while the real
/// server 404s all 4 routes.

#include "approval_routes.hpp"
#include "test_route_sink.hpp"

#include "approval_manager.hpp"
#include "test_approval_manager_pg_helper.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

struct EventRow {
    std::string event_type;
    json attrs;
    json payload_data;
};

/// All providers injected and re-read per call, mirroring
/// test_custom_properties_routes.cpp's / test_result_set_routes.cpp's
/// Harness shape.
///
/// Declaration order: `sink` LAST (CLAUDE.md / test_route_sink.hpp
/// convention) — its registered handlers capture `this` and hold pointers
/// into this struct's other members, so those members must outlive it.
struct Harness {
    ApprovalManager* approval_manager{nullptr};

    bool perm_allow{true};
    std::string last_perm_type, last_perm_op;

    /// Session `resolve_session_fn` returns. nullopt models an
    /// unresolvable session — the original inline code's fallback to
    /// reviewer "unknown", preserved verbatim by this extraction.
    std::optional<auth::Session> session{[] {
        auth::Session s;
        s.username = "reviewer1";
        s.role = auth::Role::admin;
        return s;
    }()};

    bool audit_succeeds{true};
    std::vector<AuditRow> audits;
    std::vector<EventRow> events;

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        approval::Deps deps;
        deps.approval_manager = approval_manager;
        deps.perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) {
            last_perm_type = type;
            last_perm_op = op;
            if (!perm_allow) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                "application/json");
                return false;
            }
            return true;
        };
        deps.resolve_session_fn = [this](const httplib::Request&) { return session; };
        deps.audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& ti,
                               const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return audit_succeeds;
        };
        deps.emit_event_fn = [this](const std::string& event_type, const httplib::Request&,
                                    const json& attrs, const json& payload_data) {
            events.push_back({event_type, attrs, payload_data});
        };
        approval::register_approval_routes(sink, deps);
    }
};

json body(const std::string& s) { return json::parse(s); }

} // namespace

// ── Registration shape ────────────────────────────────────────────────────

TEST_CASE("approval_routes: registers exactly 4 routes", "[server][routes][approval_routes]") {
    Harness h;
    h.wire();
    CHECK(h.sink.route_count() == 4);
}

// ── Gate pinning (no Postgres needed — every route returns before touching
//    a null store) ─────────────────────────────────────────────────────────

TEST_CASE("approval_routes: the 2 GET routes gate on perm_fn(Approval, Read)",
          "[server][routes][approval_routes]") {
    Harness h;
    h.wire();

    h.sink.Get("/api/approvals");
    CHECK(h.last_perm_type == "Approval");
    CHECK(h.last_perm_op == "Read");

    h.last_perm_type.clear();
    h.last_perm_op.clear();
    h.sink.Get("/api/approvals/pending/count");
    CHECK(h.last_perm_type == "Approval");
    CHECK(h.last_perm_op == "Read");
}

TEST_CASE("approval_routes: the 2 POST routes gate on perm_fn(Approval, Approve)",
          "[server][routes][approval_routes]") {
    Harness h;
    h.wire();

    h.sink.Post("/api/approvals/abc123/approve", "{}");
    CHECK(h.last_perm_type == "Approval");
    CHECK(h.last_perm_op == "Approve");

    h.last_perm_type.clear();
    h.last_perm_op.clear();
    h.sink.Post("/api/approvals/abc123/reject", "{}");
    CHECK(h.last_perm_type == "Approval");
    CHECK(h.last_perm_op == "Approve");
}

TEST_CASE("approval_routes: a perm_fn denial 403s before the store is touched, on every route",
          "[server][routes][approval_routes]") {
    Harness h;
    h.perm_allow = false;
    // approval_manager stays null — if a route touched it before checking
    // the gate result, this would crash instead of 403ing.
    h.wire();

    auto r1 = h.sink.Get("/api/approvals");
    REQUIRE(r1);
    CHECK(r1->status == 403);

    auto r2 = h.sink.Get("/api/approvals/pending/count");
    REQUIRE(r2);
    CHECK(r2->status == 403);

    auto r3 = h.sink.Post("/api/approvals/abc123/approve", "{}");
    REQUIRE(r3);
    CHECK(r3->status == 403);

    auto r4 = h.sink.Post("/api/approvals/abc123/reject", "{}");
    REQUIRE(r4);
    CHECK(r4->status == 403);

    CHECK(h.audits.empty()); // denial never reaches an audit call
}

// ── Store-unavailable degrade (STORE-UNAVAILABLE ASYMMETRY, preserved
//    verbatim from the pre-extraction inline code) ─────────────────────────

TEST_CASE("approval_routes: a null approval_manager 503s GET /api/approvals and both POST "
          "routes",
          "[server][routes][approval_routes]") {
    Harness h;
    h.approval_manager = nullptr;
    h.wire();

    auto r1 = h.sink.Get("/api/approvals");
    REQUIRE(r1);
    CHECK(r1->status == 503);
    CHECK(body(r1->body)["error"]["code"] == 503);

    auto r2 = h.sink.Post("/api/approvals/abc123/approve", "{}");
    REQUIRE(r2);
    CHECK(r2->status == 503);

    auto r3 = h.sink.Post("/api/approvals/abc123/reject", "{}");
    REQUIRE(r3);
    CHECK(r3->status == 503);

    CHECK(h.audits.empty()); // the 503 degrade returns before deps.audit_fn
}

TEST_CASE("approval_routes: a null approval_manager degrades GET pending/count to 200 "
          "{count:0} -- NOT a 503, unlike its 3 siblings",
          "[server][routes][approval_routes]") {
    Harness h;
    h.approval_manager = nullptr;
    h.wire();

    auto r = h.sink.Get("/api/approvals/pending/count");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(body(r->body)["count"] == 0);
}

// ── Real store round-trip ([pg]) ────────────────────────────────────────────

TEST_CASE("approval_routes: list/pending-count/approve round-trip over HTTP, with the real "
          "audit row and emitted event",
          "[server][routes][approval_routes][pg]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto submitted = mgr->submit("def-approve-1", "submitter1", "ostype = 'windows'", "",
                                 ApprovalOrigin::kInstruction);
    REQUIRE(submitted.has_value());
    const std::string id = *submitted;

    Harness h;
    h.approval_manager = mgr.get();
    h.wire();

    // GET /api/approvals sees the pending row.
    auto list = h.sink.Get("/api/approvals");
    REQUIRE(list);
    CHECK(list->status == 200);
    auto arr = body(list->body)["approvals"];
    REQUIRE(arr.is_array());
    REQUIRE(arr.size() == 1);
    CHECK(arr[0]["id"] == id);
    CHECK(arr[0]["definition_id"] == "def-approve-1");
    CHECK(arr[0]["status"] == "pending");
    CHECK(arr[0]["submitted_by"] == "submitter1");
    CHECK(arr[0]["scope_expression"] == "ostype = 'windows'");

    // pending/count reflects it.
    auto count = h.sink.Get("/api/approvals/pending/count");
    REQUIRE(count);
    CHECK(body(count->body)["count"] == 1);

    // Approve — h.session's reviewer ("reviewer1") differs from the
    // submitter ("submitter1"), so the store's segregation-of-duties check
    // passes.
    auto approve = h.sink.Post("/api/approvals/" + id + "/approve", "{\"comment\":\"looks good\"}");
    REQUIRE(approve);
    CHECK(approve->status == 200);
    CHECK(body(approve->body)["status"] == "approved");

    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "approval.approve");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].target_type == "approval");
    CHECK(h.audits[0].target_id == id);

    REQUIRE(h.events.size() == 1);
    CHECK(h.events[0].event_type == "approval.approved");
    CHECK(h.events[0].attrs["reviewer"] == "reviewer1");
    CHECK(h.events[0].payload_data["approval_id"] == id);

    // pending/count drops back to zero.
    auto count_after = h.sink.Get("/api/approvals/pending/count");
    REQUIRE(count_after);
    CHECK(body(count_after->body)["count"] == 0);

    // The store itself reflects the approval (independent verification,
    // not just the HTTP response).
    auto row = mgr->get(id);
    REQUIRE(row.has_value());
    CHECK(row->status == "approved");
    CHECK(row->reviewed_by == "reviewer1");
}

TEST_CASE("approval_routes: reject round-trip over HTTP, with the real audit row and emitted "
          "event",
          "[server][routes][approval_routes][pg]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto submitted = mgr->submit("def-reject-1", "submitter1", "ostype = 'linux'", "",
                                 ApprovalOrigin::kInstruction);
    REQUIRE(submitted.has_value());
    const std::string id = *submitted;

    Harness h;
    h.approval_manager = mgr.get();
    h.wire();

    auto reject = h.sink.Post("/api/approvals/" + id + "/reject", R"({"comment":"nope"})");
    REQUIRE(reject);
    CHECK(reject->status == 200);
    CHECK(body(reject->body)["status"] == "rejected");

    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "approval.reject");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].target_id == id);

    REQUIRE(h.events.size() == 1);
    CHECK(h.events[0].event_type == "approval.rejected");
    CHECK(h.events[0].attrs["reviewer"] == "reviewer1");
    CHECK(h.events[0].attrs["comment"] == "nope");
    CHECK(h.events[0].payload_data["approval_id"] == id);

    auto row = mgr->get(id);
    REQUIRE(row.has_value());
    CHECK(row->status == "rejected");
}

TEST_CASE("approval_routes: self-approval is denied (segregation of duties), audited as "
          "denied, and never emits an event",
          "[server][routes][approval_routes][pg]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto submitted =
        mgr->submit("def-self-1", "same-person", "ostype = 'windows'", "", ApprovalOrigin::kInstruction);
    REQUIRE(submitted.has_value());
    const std::string id = *submitted;

    Harness h;
    h.approval_manager = mgr.get();
    auth::Session s;
    s.username = "same-person"; // reviewer == submitter
    s.role = auth::Role::admin;
    h.session = s;
    h.wire();

    auto approve = h.sink.Post("/api/approvals/" + id + "/approve", "{}");
    REQUIRE(approve);
    CHECK(approve->status == 400);
    CHECK(body(approve->body)["error"].get<std::string>().find("submitter") != std::string::npos);

    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "approval.approve");
    CHECK(h.audits[0].result == "denied");
    CHECK(h.audits[0].detail.find("submitter") != std::string::npos);

    CHECK(h.events.empty()); // denial never emits approval.approved

    // The ticket is untouched — still pending.
    auto row = mgr->get(id);
    REQUIRE(row.has_value());
    CHECK(row->status == "pending");
}

TEST_CASE("approval_routes: an unresolvable session falls back to reviewer \"unknown\"",
          "[server][routes][approval_routes][pg]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto submitted = mgr->submit("def-unknown-1", "submitter1", "ostype = 'macos'", "",
                                 ApprovalOrigin::kInstruction);
    REQUIRE(submitted.has_value());
    const std::string id = *submitted;

    Harness h;
    h.approval_manager = mgr.get();
    h.session = std::nullopt;
    h.wire();

    auto approve = h.sink.Post("/api/approvals/" + id + "/approve", "{}");
    REQUIRE(approve);
    CHECK(approve->status == 200);

    REQUIRE(h.events.size() == 1);
    CHECK(h.events[0].attrs["reviewer"] == "unknown");

    auto row = mgr->get(id);
    REQUIRE(row.has_value());
    CHECK(row->reviewed_by == "unknown");
}

TEST_CASE("approval_routes: GET /api/approvals filters by status and submitted_by",
          "[server][routes][approval_routes][pg]") {
    yuzu::test::ApprovalManagerPg mgr;
    mgr->submit("def-a", "operator1", "scope-a", "", ApprovalOrigin::kInstruction);
    mgr->submit("def-b", "operator2", "scope-b", "", ApprovalOrigin::kInstruction);
    auto to_approve =
        mgr->submit("def-c", "operator1", "scope-c", "", ApprovalOrigin::kInstruction);
    REQUIRE(to_approve.has_value());
    REQUIRE(mgr->approve(*to_approve, "reviewer1", "").has_value());

    Harness h;
    h.approval_manager = mgr.get();
    h.wire();

    auto by_status = h.sink.Get("/api/approvals?status=approved");
    REQUIRE(by_status);
    auto approved_arr = body(by_status->body)["approvals"];
    REQUIRE(approved_arr.size() == 1);
    CHECK(approved_arr[0]["definition_id"] == "def-c");

    auto by_submitter = h.sink.Get("/api/approvals?submitted_by=operator1");
    REQUIRE(by_submitter);
    auto op1_arr = body(by_submitter->body)["approvals"];
    CHECK(op1_arr.size() == 2); // def-a (pending) + def-c (approved)
}

TEST_CASE("GET /api/approvals: an out-of-enum status is rejected with 400, not silently "
          "producing a false-empty result (Gate 8 governance finding, #2146 A2-R4)",
          "[server][routes][approval_routes][pg]") {
    yuzu::test::ApprovalManagerPg mgr;
    REQUIRE(mgr->submit("def-a", "operator1", "scope-a", "", ApprovalOrigin::kInstruction)
                .has_value());

    Harness h;
    h.approval_manager = mgr.get();
    h.wire();

    // Pre-fix: this silently produced approvals:[] -- indistinguishable from
    // a genuinely empty match -- instead of rejecting the malformed input,
    // same defect class as GET /api/v1/approvals and MCP
    // list_pending_approvals had before their own #2146 A2-R4 fix.
    auto res = h.sink.Get("/api/approvals?status=aproved");
    REQUIRE(res);
    CHECK(res->status == 400);
}

// ═══════════════════════════════════════════════════════════════════════════
// Wiring tripwire: every case above proves register_approval_routes' OWN
// handlers are correct, but nothing above reads server.cpp — a future edit
// that drops the production `register_approval_routes(...)` call at
// server.cpp's registration site would leave every case above green while
// the real server 404s all 4 routes. Mirrors
// test_custom_properties_routes.cpp's tripwire (#4078 tracks generalizing
// this pattern across the campaign).
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("approval_routes: wiring -- server.cpp still calls register_approval_routes",
          "[server][routes][approval_routes]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    CHECK(src.find("register_approval_routes(") != std::string::npos);
}
