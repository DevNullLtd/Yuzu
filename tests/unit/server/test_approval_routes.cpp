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
#include "approver_assurance.hpp"
#include "test_approval_manager_pg_helper.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <unordered_map>
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
    /// unresolvable session — approve/reject answer 503 and leave the ticket
    /// pending (#4128); they no longer fall back to a placeholder reviewer.
    std::optional<auth::Session> session{[] {
        auth::Session s;
        s.username = "reviewer1";
        s.role = auth::Role::admin;
        return s;
    }()};

    /// MFA step-up stub (`require_mfa_step_up` is covered by its own tests):
    /// false models a stale proof and writes the same 401 envelope shape.
    bool step_up_ok{true};
    bool wire_step_up{true};
    std::vector<std::string> step_up_labels;
    /// Order witness: audit-row count at the moment step-up ran, so a test can
    /// prove step-up precedes the `attempted` row.
    std::vector<size_t> audits_at_step_up;

    /// `Config::csrf_trusted_origins` handed to the same-site gate.
    std::vector<std::string> csrf_trusted_origins;

    bool audit_succeeds{true};
    std::vector<AuditRow> audits;
    std::vector<EventRow> events;

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        approval::Deps deps;
        deps.approval_manager = approval_manager;
        deps.csrf_trusted_origins = csrf_trusted_origins;
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
        if (wire_step_up) {
            deps.step_up_fn = [this](const httplib::Request&, httplib::Response& res,
                                     const auth::Session&, const std::string& label) {
                step_up_labels.push_back(label);
                audits_at_step_up.push_back(audits.size());
                if (!step_up_ok) {
                    res.status = 401;
                    res.set_content(R"({"error":{"code":401,"message":"MFA step-up required"}})",
                                    "application/json");
                    return false;
                }
                return true;
            };
        }
        deps.emit_event_fn = [this](const std::string& event_type, const httplib::Request&,
                                    const json& attrs, const json& payload_data) {
            events.push_back({event_type, attrs, payload_data});
        };
        // A browser's same-site write: the cookie-write gate (WriteGate) refuses a POST
        // without a matching Origin/Referer, so every request carries one unless a test
        // overrides it.
        sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://yuzu.test"}};
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

    // Audit-before-mutate (#5823): an `attempted` row precedes the store call and the
    // `success` row follows it -- two rows per decision. (Was 1 before #6061.)
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].action == "approval.approve");
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[0].target_id == id);
    CHECK(h.audits[1].action == "approval.approve");
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].target_type == "approval");
    CHECK(h.audits[1].target_id == id);
    REQUIRE(h.step_up_labels.size() == 1);
    CHECK(h.step_up_labels[0] == "POST /api/approvals/{id}/approve");

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

    REQUIRE(h.audits.size() == 2); // attempted (pre-mutation) + success, see approve above
    CHECK(h.audits[0].action == "approval.reject");
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].action == "approval.reject");
    CHECK(h.audits[1].result == "success");
    CHECK(h.audits[1].target_id == id);

    REQUIRE(h.events.size() == 1);
    CHECK(h.events[0].event_type == "approval.rejected");
    CHECK(h.events[0].attrs["reviewer"] == "reviewer1");
    CHECK(h.events[0].attrs["comment"] == "nope");
    CHECK(h.events[0].payload_data["approval_id"] == id);

    auto row = mgr->get(id);
    REQUIRE(row.has_value());
    CHECK(row->status == "rejected");
}

TEST_CASE("approval_routes: a decision's success trigger asks the old tab to refresh and an "
          "over-long comment is a 400 with the exact message",
          "[server][routes][approval_routes][pg]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto a = mgr->submit("def-trig-a", "submitter1", "group:x", "", ApprovalOrigin::kInstruction);
    auto r = mgr->submit("def-trig-r", "submitter1", "group:x", "", ApprovalOrigin::kInstruction);
    REQUIRE(a.has_value());
    REQUIRE(r.has_value());

    Harness h;
    h.approval_manager = mgr.get();
    h.wire();

    // Too long: refused before any state change, through the existing denial branch.
    const std::string too_long =
        R"({"comment":")" + std::string(kMaxReviewCommentBytes + 1, 'a') + R"("})";
    auto refused = h.sink.Post("/api/approvals/" + *a + "/approve", too_long);
    REQUIRE(refused);
    CHECK(refused->status == 400);
    CHECK(body(refused->body)["error"] == "comment too long (max 4000 bytes)");
    REQUIRE(h.audits.size() == 2); // attempted (pre-mutation), then denied
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].action == "approval.approve");
    CHECK(h.audits[1].result == "denied");
    CHECK(h.events.empty());
    auto still = mgr->get(*a);
    REQUIRE(still.has_value());
    CHECK(still->status == "pending");

    // Success: the HX-Trigger JSON keeps the toast and adds refreshApprovals (both routes).
    auto trig = [](const httplib::Response& res) {
        REQUIRE(res.has_header("HX-Trigger"));
        return nlohmann::json::parse(res.get_header_value("HX-Trigger"));
    };
    auto ok_a = h.sink.Post("/api/approvals/" + *a + "/approve", "{}");
    REQUIRE(ok_a);
    CHECK(ok_a->status == 200);
    auto ta = trig(*ok_a);
    CHECK(ta["showToast"]["message"] == "Approved");
    CHECK(ta["refreshApprovals"] == true);
    auto ok_r = h.sink.Post("/api/approvals/" + *r + "/reject", "{}");
    REQUIRE(ok_r);
    CHECK(ok_r->status == 200);
    auto tr = trig(*ok_r);
    CHECK(tr["showToast"]["message"] == "Rejected");
    CHECK(tr["refreshApprovals"] == true);
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

    REQUIRE(h.audits.size() == 2); // attempted (pre-mutation), then denied
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].action == "approval.approve");
    CHECK(h.audits[1].result == "denied");
    CHECK(h.audits[1].detail.find("submitter") != std::string::npos);

    CHECK(h.events.empty()); // denial never emits approval.approved

    // The ticket is untouched — still pending.
    auto row = mgr->get(id);
    REQUIRE(row.has_value());
    CHECK(row->status == "pending");
}

TEST_CASE("approval_routes: an unresolvable session fails closed with a 503 and leaves the ticket "
          "pending (#4128 -- was reviewer \"unknown\")",
          "[server][routes][approval_routes][pg]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto a = mgr->submit("def-unknown-a", "submitter1", "ostype = 'macos'", "",
                         ApprovalOrigin::kInstruction);
    auto r = mgr->submit("def-unknown-r", "submitter1", "ostype = 'macos'", "",
                         ApprovalOrigin::kInstruction);
    REQUIRE(a.has_value());
    REQUIRE(r.has_value());

    Harness h;
    h.approval_manager = mgr.get();
    h.session = std::nullopt;
    h.wire();

    for (const auto& [verb, id] : {std::pair<const char*, std::string>{"approve", *a},
                                   std::pair<const char*, std::string>{"reject", *r}}) {
        INFO("verb: " << verb);
        auto res = h.sink.Post("/api/approvals/" + id + "/" + verb, "{}");
        REQUIRE(res);
        CHECK(res->status == 503);
        auto j = body(res->body);
        CHECK(j["error"]["code"] == 503);
        CHECK(j["error"].contains("correlation_id"));
        CHECK(j["error"]["retry_after_ms"].is_number()); // transient: tells a worker to retry

        auto row = mgr->get(id);
        REQUIRE(row.has_value());
        CHECK(row->status == "pending");
        CHECK(row->reviewed_by.empty()); // never "unknown"
    }
    CHECK(h.events.empty());
    CHECK(h.audits.empty());
    CHECK(h.step_up_labels.empty()); // refused before step-up
}

// ── Approver assurance (#6061) ──────────────────────────────────────────────
// Every case below that needs no store runs with a NULL approval_manager: the
// class check and the session check sit BEFORE the store, so reaching it would
// dereference null -- the 403/503 is itself the proof the store was not touched.

namespace {
auth::Session session_of(const char* username, const char* auth_source,
                         const char* principal_kind = "human") {
    auth::Session s;
    s.username = username;
    s.role = auth::Role::admin;
    s.auth_source = auth_source;
    s.principal_kind = principal_kind;
    return s;
}
} // namespace

TEST_CASE("approver_assurance: check_approver_class is a positive allow-list",
          "[server][routes][approval_routes]") {
    using approval::ApproverRefusal;
    using approval::check_approver_class;
    CHECK(check_approver_class(session_of("u", "local")) == ApproverRefusal::kNone);
    CHECK(check_approver_class(session_of("u", "oidc")) == ApproverRefusal::kNone);
    CHECK(check_approver_class(session_of("u", "saml")) == ApproverRefusal::kNone);
    CHECK(check_approver_class(session_of("u", "api_token")) ==
          ApproverRefusal::kNonInteractiveSession);
    CHECK(check_approver_class(session_of("u", "mcp_token")) ==
          ApproverRefusal::kNonInteractiveSession);
    // A future seventh auth_source is refused until someone decides it is interactive.
    CHECK(check_approver_class(session_of("u", "something_new")) ==
          ApproverRefusal::kNonInteractiveSession);
    CHECK(check_approver_class(session_of("u", "")) == ApproverRefusal::kNonInteractiveSession);
    // Engine is reported as such whatever else is true of the session.
    CHECK(check_approver_class(session_of("u", "engine_token", "engine")) ==
          ApproverRefusal::kEnginePrincipal);
    CHECK(check_approver_class(session_of("u", "local", "engine")) ==
          ApproverRefusal::kEnginePrincipal); // principal_kind alone trips it
    CHECK(check_approver_class(session_of("u", "engine_token", "human")) ==
          ApproverRefusal::kEnginePrincipal); // auth_source alone trips it
    CHECK(check_approver_class(session_of("u", "local", "service")) ==
          ApproverRefusal::kNonHumanPrincipal);
    CHECK(approval::approver_refusal_message(ApproverRefusal::kNonInteractiveSession) ==
          "approver_assurance_required:non_interactive_session");
}

TEST_CASE("approval_routes: a bearer or engine caller is refused 403 with a typed reason, before "
          "step-up, the store and any mutation",
          "[server][routes][approval_routes]") {
    struct Case {
        const char* label;
        const char* auth_source;
        const char* principal_kind;
        const char* reason;
    };
    static const Case kCases[] = {
        {"api token", "api_token", "human", "non_interactive_session"},
        {"mcp token", "mcp_token", "human", "non_interactive_session"},
        {"engine token", "engine_token", "engine", "engine_principal"},
        {"engine kind on a cookie-shaped session", "local", "engine", "engine_principal"},
        {"non-human principal", "local", "service", "non_human_principal"},
    };
    for (const auto& c : kCases) {
        for (const char* verb : {"approve", "reject"}) {
            INFO(c.label << " / " << verb);
            Harness h; // null approval_manager: a store reach would crash
            h.session = session_of("bot", c.auth_source, c.principal_kind);
            h.wire();

            auto res = h.sink.Post(std::string("/api/approvals/abc123/") + verb, "{}");
            REQUIRE(res);
            CHECK(res->status == 403);
            auto j = body(res->body);
            CHECK(j["error"]["code"] == 403);
            CHECK(j["error"]["message"] ==
                  std::string("approver_assurance_required:") + c.reason);
            CHECK(j["error"].contains("correlation_id"));
            CHECK(j["error"].contains("remediation"));

            CHECK(h.step_up_labels.empty()); // step-up would have passed a bearer; never reached
            CHECK(h.events.empty());
            // Best-effort trace of the refused attempt; never an `attempted`/`success` row.
            REQUIRE(h.audits.size() == 1);
            CHECK(h.audits[0].result == "denied");
            CHECK(h.audits[0].detail == std::string("approver_assurance:") + c.reason);
        }
    }
}

TEST_CASE("approval_routes: a cross-site or Origin-less cookie POST is refused 403 (audited "
          "csrf.denied) before the class check, step-up, the attempted row and any mutation",
          "[server][routes][approval_routes][csrf]") {
    const std::unordered_map<std::string, std::string> cross_site[] = {
        {{"Host", "yuzu.test"}, {"Origin", "https://evil.test"}},
        {{"Host", "yuzu.test"}, {"Referer", "https://evil.test/x"}},
        {{"Host", "yuzu.test"}}, // a browser always sends one on a write
    };
    for (const auto& hdrs : cross_site) {
        for (const char* verb : {"approve", "reject"}) {
            Harness h; // null approval_manager: a store reach would crash
            h.wire();
            h.sink.default_headers = hdrs;

            auto res = h.sink.Post(std::string("/api/approvals/abc123/") + verb, "{}");
            REQUIRE(res);
            CHECK(res->status == 403);
            CHECK(body(res->body)["error"]["message"] == "cross-site request refused");
            CHECK(h.step_up_labels.empty()); // refused before step-up
            CHECK(h.events.empty());
            REQUIRE(h.audits.size() == 1); // csrf.denied only: no attempted/success row
            CHECK(h.audits[0].action == "csrf.denied");
            CHECK(h.audits[0].result == "denied");
        }
    }
}

TEST_CASE("approval_routes: a cross-site POST leaves a pending ticket pending, and the same "
          "request from this site then decides it",
          "[pg][server][routes][approval_routes][csrf]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto id = mgr->submit("def-csrf", "submitter1", "group:x", "", ApprovalOrigin::kInstruction);
    REQUIRE(id);

    Harness h;
    h.approval_manager = mgr.get();
    h.wire();
    h.sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://evil.test"}};
    auto bad = h.sink.Post("/api/approvals/" + *id + "/approve", "{}");
    REQUIRE(bad);
    CHECK(bad->status == 403);
    auto still = mgr->get(*id);
    REQUIRE(still);
    CHECK(still->status == "pending");

    h.sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://yuzu.test"}};
    auto good = h.sink.Post("/api/approvals/" + *id + "/approve", "{}");
    REQUIRE(good);
    CHECK(good->status == 200);
    auto after = mgr->get(*id);
    REQUIRE(after);
    CHECK(after->status == "approved");
}

TEST_CASE("approval_routes: a configured trusted origin and the request's own site pass the "
          "same-site gate; a perm_fn denial still wins over it",
          "[server][routes][approval_routes][csrf]") {
    {
        Harness h; // null manager: passing the gate reaches the 503 store-unavailable body
        h.wire();
        h.sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://yuzu.test"}};
        auto res = h.sink.Post("/api/approvals/abc123/approve", "{}");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(h.audits.empty());
    }
    {
        // A reverse-proxy origin named in --csrf-trusted-origin is same-site.
        Harness h;
        h.csrf_trusted_origins = {"https://proxy.test"};
        h.wire();
        h.sink.default_headers = {{"Host", "internal:8080"}, {"Origin", "https://proxy.test"}};
        auto res = h.sink.Post("/api/approvals/abc123/reject", "{}");
        REQUIRE(res);
        CHECK(res->status == 503); // past the gate; null manager
        CHECK(h.audits.empty());
        h.sink.default_headers = {{"Host", "internal:8080"}, {"Origin", "https://other.test"}};
        auto bad = h.sink.Post("/api/approvals/abc123/reject", "{}");
        REQUIRE(bad);
        CHECK(bad->status == 403);
    }
    {
        Harness h;
        h.perm_allow = false;
        h.wire();
        h.sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://evil.test"}};
        auto res = h.sink.Post("/api/approvals/abc123/approve", "{}");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.audits.empty()); // the permission 403 came first: no csrf.denied row
    }
}

TEST_CASE("approval_routes: a bearer is refused even when the permission gate allows it",
          "[server][routes][approval_routes][pg]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto id = mgr->submit("def-bearer", "submitter1", "ostype = 'windows'", "",
                          ApprovalOrigin::kInstruction);
    REQUIRE(id.has_value());

    Harness h;
    h.approval_manager = mgr.get();
    h.perm_allow = true; // RBAC grants Approval:Approve; that alone must not be enough
    h.session = session_of("reviewer1", "api_token");
    h.wire();

    auto res = h.sink.Post("/api/approvals/" + *id + "/approve", "{}");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(body(res->body)["error"]["message"] ==
          "approver_assurance_required:non_interactive_session");
    auto row = mgr->get(*id);
    REQUIRE(row.has_value());
    CHECK(row->status == "pending");
    CHECK(row->reviewed_by.empty());
}

TEST_CASE("approval_routes: an engine principal is refused even with a different submitter",
          "[server][routes][approval_routes][pg]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto id = mgr->submit("def-engine", "submitter1", "ostype = 'windows'", "",
                          ApprovalOrigin::kInstruction);
    REQUIRE(id.has_value());

    Harness h;
    h.approval_manager = mgr.get();
    h.session = session_of("engine:vuln", "engine_token", "engine");
    h.wire();

    auto res = h.sink.Post("/api/approvals/" + *id + "/reject", "{}");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(body(res->body)["error"]["message"] == "approver_assurance_required:engine_principal");
    auto row = mgr->get(*id);
    REQUIRE(row.has_value());
    CHECK(row->status == "pending");
}

TEST_CASE("approval_routes: an interactive session without a fresh step-up is refused with the "
          "step-up 401 and the ticket stays pending",
          "[server][routes][approval_routes][pg]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto id = mgr->submit("def-stale", "submitter1", "ostype = 'windows'", "",
                          ApprovalOrigin::kInstruction);
    REQUIRE(id.has_value());

    Harness h;
    h.approval_manager = mgr.get();
    h.step_up_ok = false;
    h.wire();

    for (const char* verb : {"approve", "reject"}) {
        INFO(verb);
        auto res = h.sink.Post("/api/approvals/" + *id + "/" + verb, "{}");
        REQUIRE(res);
        CHECK(res->status == 401);
    }
    // Step-up ran BEFORE any audit row; refusal wrote no attempt/success row, no event.
    CHECK(h.audits.empty());
    CHECK(h.events.empty());
    REQUIRE(h.audits_at_step_up.size() == 2);
    CHECK(h.audits_at_step_up[0] == 0);
    auto row = mgr->get(*id);
    REQUIRE(row.has_value());
    CHECK(row->status == "pending");
}

TEST_CASE("approval_routes: an unwired step_up_fn fails closed (503), never skips the freshness "
          "requirement",
          "[server][routes][approval_routes][pg]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto id = mgr->submit("def-nostepup", "submitter1", "ostype = 'windows'", "",
                          ApprovalOrigin::kInstruction);
    REQUIRE(id.has_value());

    Harness h;
    h.approval_manager = mgr.get();
    h.wire_step_up = false;
    h.wire();

    auto res = h.sink.Post("/api/approvals/" + *id + "/approve", "{}");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(h.audits.empty());
    auto row = mgr->get(*id);
    REQUIRE(row.has_value());
    CHECK(row->status == "pending");
}

TEST_CASE("approval_routes: an audit-write failure is a 503 with Sec-Audit-Failed and the ticket "
          "stays pending (audit before mutate, #5823)",
          "[server][routes][approval_routes][pg]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto a = mgr->submit("def-audit-a", "submitter1", "group:x", "", ApprovalOrigin::kInstruction);
    auto r = mgr->submit("def-audit-r", "submitter1", "group:x", "", ApprovalOrigin::kInstruction);
    REQUIRE(a.has_value());
    REQUIRE(r.has_value());

    Harness h;
    h.approval_manager = mgr.get();
    h.audit_succeeds = false;
    h.wire();

    for (const auto& [verb, id] : {std::pair<const char*, std::string>{"approve", *a},
                                   std::pair<const char*, std::string>{"reject", *r}}) {
        INFO(verb);
        auto res = h.sink.Post("/api/approvals/" + id + "/" + verb, "{}");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(body(res->body)["error"]["code"] == 503);
        auto row = mgr->get(id);
        REQUIRE(row.has_value());
        CHECK(row->status == "pending"); // not mutated
        CHECK(row->reviewed_by.empty());
    }
    CHECK(h.events.empty());
    // Only the failed `attempted` rows were tried: no post-mutation row exists.
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].result == "attempted");
    // Step-up ran before the attempt row.
    REQUIRE(h.audits_at_step_up.size() == 2);
    CHECK(h.audits_at_step_up[0] == 0);
}

TEST_CASE("approval_routes: an OIDC interactive session with a fresh step-up still approves and "
          "rejects (happy path)",
          "[server][routes][approval_routes][pg]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto a = mgr->submit("def-oidc-a", "submitter1", "group:x", "", ApprovalOrigin::kInstruction);
    auto r = mgr->submit("def-oidc-r", "submitter1", "group:x", "", ApprovalOrigin::kInstruction);
    REQUIRE(a.has_value());
    REQUIRE(r.has_value());

    Harness h;
    h.approval_manager = mgr.get();
    h.session = session_of("oidc:https://idp.example#sub-1", "oidc");
    h.wire();

    auto ok_a = h.sink.Post("/api/approvals/" + *a + "/approve", "{}");
    REQUIRE(ok_a);
    CHECK(ok_a->status == 200);
    auto ok_r = h.sink.Post("/api/approvals/" + *r + "/reject", "{}");
    REQUIRE(ok_r);
    CHECK(ok_r->status == 200);
    CHECK(h.step_up_labels.size() == 2);
    CHECK(h.audits.size() == 4); // (attempted + success) x 2
    auto row = mgr->get(*a);
    REQUIRE(row.has_value());
    CHECK(row->status == "approved");
    CHECK(row->reviewed_by == "oidc:https://idp.example#sub-1");
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

// QE-1 (#6061): the Deps block is built with designated initialisers, and omitting one
// COMPILES (the member is value-initialised). Dropping `.step_up_fn` would 503 every real
// approval (the route fails closed on an unwired closure); dropping `.csrf_trusted_origins`
// would silently narrow the same-site gate to the request's own Host, rejecting every
// deployment behind a TLS-terminating proxy. Neither shows up in the handler tests, which
// build their own Deps, so pin both inside the production call.
TEST_CASE("approval_routes: wiring -- server.cpp passes step_up_fn and csrf_trusted_origins "
          "into the approval Deps",
          "[server][routes][approval_routes]") {
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    const auto call = src.find("approval::register_approval_routes(");
    REQUIRE(call != std::string::npos);
    // The call's Deps block ends at the ApprovalManager pointer, its last member.
    const auto end = src.find(".approval_manager = approval_manager_.get()", call);
    REQUIRE(end != std::string::npos);
    const std::string block = src.substr(call, end - call);
    CHECK(block.find(".step_up_fn = step_up_fn") != std::string::npos);
    CHECK(block.find(".csrf_trusted_origins = cfg_.csrf_trusted_origins") != std::string::npos);
    CHECK(block.find(".perm_fn = perm_fn") != std::string::npos);
    CHECK(block.find(".resolve_session_fn = resolve_session_fn") != std::string::npos);
    CHECK(block.find(".audit_fn = audit_fn") != std::string::npos);
}
