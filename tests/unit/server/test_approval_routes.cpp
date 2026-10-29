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
#include "mfa_step_up.hpp"
#include "session_store.hpp"
#include "test_approval_manager_pg_helper.hpp"
#include "test_auth_db_pg_helper.hpp"
#include "totp.hpp"

#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"
#include "source_scan.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <yuzu/metrics.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
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

    /// Generic step-up stub (the shared `StepUpFn`, which consumes the central check's pass).
    /// It runs BEFORE the approver gate; a refusal writes the 401 and ends the request.
    bool step_up_ok{true};
    bool wire_step_up{true};
    std::vector<std::string> step_up_labels;
    /// Order witness: audit-row count at the moment step-up ran.
    std::vector<size_t> audits_at_step_up;

    /// Approver MFA gate stub (`require_enrolled_fresh_mfa` has its own tests; the [pg] cases
    /// below drive the real one): the outcome the closure returns. kChallengeWritten also
    /// writes a 401 envelope, as the real gate does. Default is an enrolled caller passing.
    ApproverMfaOutcome mfa_outcome{ApproverMfaOutcome::Kind::kPass, MfaFactorState::kEnrolledLocal};
    bool wire_mfa{true};
    /// When set, replaces the stub entirely: the [pg] integration cases bind the REAL gate here.
    approval::Deps::ApproverMfaFn mfa_fn_override;
    std::vector<std::string> mfa_labels;
    /// Order witness: audit-row count at the moment the gate ran, so a test can prove the
    /// gate precedes the `attempted` row.
    std::vector<size_t> audits_at_mfa;

    /// `Config::csrf_trusted_origins` handed to the same-site gate.
    std::vector<std::string> csrf_trusted_origins;

    bool audit_succeeds{true};
    bool audit_throws{false};
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
            if (audit_throws)
                throw std::runtime_error("audit sink down");
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
        if (mfa_fn_override) {
            deps.approver_mfa_fn = mfa_fn_override;
        } else if (wire_mfa) {
            deps.approver_mfa_fn = [this](const httplib::Request&, httplib::Response& res,
                                          const auth::Session&,
                                          const std::string& label) -> ApproverMfaOutcome {
                mfa_labels.push_back(label);
                audits_at_mfa.push_back(audits.size());
                if (mfa_outcome.kind == ApproverMfaOutcome::Kind::kChallengeWritten) {
                    res.status = 401;
                    res.set_content(R"({"error":{"code":401,"message":"MFA step-up required"}})",
                                    "application/json");
                }
                return mfa_outcome;
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
    REQUIRE(h.mfa_labels.size() == 1);
    CHECK(h.mfa_labels[0] == "POST /api/approvals/{id}/approve");

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
    CHECK(h.mfa_labels.empty()); // refused before the MFA gate
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

TEST_CASE("approver_assurance: the MFA refusal tokens are stable and refusal_for_factor maps every "
          "factor state (#6079)",
          "[server][routes][approval_routes]") {
    using approval::approver_refusal_message;
    using approval::approver_refusal_reason;
    using approval::ApproverRefusal;
    using approval::refusal_for_factor;
    // Agentic workers key off these literals: pinned verbatim, not derived from the enum.
    CHECK(approver_refusal_reason(ApproverRefusal::kMfaNotEnrolled) == "mfa_not_enrolled");
    CHECK(approver_refusal_reason(ApproverRefusal::kMfaProofMissing) == "mfa_proof_missing");
    CHECK(approver_refusal_reason(ApproverRefusal::kSamlMfaUnsupported) == "saml_mfa_unsupported");
    CHECK(approver_refusal_reason(ApproverRefusal::kMfaProofStale) == "mfa_proof_stale");
    CHECK(approver_refusal_reason(ApproverRefusal::kAccountUnavailable) == "account_unavailable");
    CHECK(approver_refusal_message(ApproverRefusal::kAccountUnavailable) ==
          "approver_assurance_required:account_unavailable");
    CHECK(approver_refusal_message(ApproverRefusal::kMfaNotEnrolled) ==
          "approver_assurance_required:mfa_not_enrolled");

    CHECK(refusal_for_factor(MfaFactorState::kNotEnrolled) == ApproverRefusal::kMfaNotEnrolled);
    CHECK(refusal_for_factor(MfaFactorState::kNoIdpProof) == ApproverRefusal::kMfaProofMissing);
    CHECK(refusal_for_factor(MfaFactorState::kSamlUnsupported) ==
          ApproverRefusal::kSamlMfaUnsupported);
    CHECK(refusal_for_factor(MfaFactorState::kNotInteractive) ==
          ApproverRefusal::kNonInteractiveSession);
    CHECK(refusal_for_factor(MfaFactorState::kAccountUnavailable) ==
          ApproverRefusal::kAccountUnavailable);
    // Not refusals of this kind: the route never maps these (it passes, or answers 503).
    CHECK(refusal_for_factor(MfaFactorState::kEnrolledLocal) == ApproverRefusal::kNone);
    CHECK(refusal_for_factor(MfaFactorState::kIdpAttested) == ApproverRefusal::kNone);
    CHECK(refusal_for_factor(MfaFactorState::kStoreUnavailable) == ApproverRefusal::kNone);
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
            // G8-QE-4: a bearer / MCP / engine-token client sends NO Origin (Harness::wire()'s
            // default Origin would otherwise be inherited by every case). The same-site gate
            // exempts these classes, so the typed class refusal -- not "cross-site request
            // refused" -- is what answers, and there is no csrf.denied row. The cookie-shaped
            // rows (auth_source "local") keep the default Origin: they ARE subject to the gate.
            if (std::string_view(c.auth_source) != "local")
                h.sink.default_headers = {{"Host", "yuzu.test"}};

            auto res = h.sink.Post(std::string("/api/approvals/abc123/") + verb, "{}");
            REQUIRE(res);
            CHECK(res->status == 403);
            auto j = body(res->body);
            CHECK(j["error"]["code"] == 403);
            CHECK(j["error"]["message"] ==
                  std::string("approver_assurance_required:") + c.reason);
            CHECK(j["error"].contains("correlation_id"));
            CHECK(j["error"].contains("remediation"));

            CHECK(h.mfa_labels.empty()); // the class check refuses before the MFA gate runs
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
            CHECK(h.mfa_labels.empty()); // refused before the MFA gate
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
    // G8-QE-3: with a REAL manager the refusal is observable end to end. It spent no
    // step-up, wrote only the csrf.denied row (no attempted/success), and emitted nothing.
    CHECK(h.mfa_labels.empty());
    CHECK(h.events.empty());
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "csrf.denied");
    CHECK(h.audits[0].result == "denied");

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

TEST_CASE("approval_routes: an unwired approver_mfa_fn fails closed (503), never skips the MFA "
          "requirement",
          "[server][routes][approval_routes][pg]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto id = mgr->submit("def-nomfa", "submitter1", "ostype = 'windows'", "",
                          ApprovalOrigin::kInstruction);
    REQUIRE(id.has_value());

    Harness h;
    h.approval_manager = mgr.get();
    h.wire_mfa = false;
    h.wire();

    for (const char* verb : {"approve", "reject"}) {
        auto res = h.sink.Post("/api/approvals/" + *id + "/" + verb, "{}");
        REQUIRE(res);
        CHECK(res->status == 503);
    }
    CHECK(h.audits.empty());
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
    CHECK(h.mfa_labels.empty()); // the approver gate was never reached
    auto row = mgr->get(*id);
    REQUIRE(row.has_value());
    CHECK(row->status == "pending");
}

TEST_CASE("approval_routes: a generic step-up refusal ends the request before the approver gate "
          "and leaves the ticket pending",
          "[server][routes][approval_routes][approver_mfa][pg]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto id = mgr->submit("def-stepup-first", "submitter1", "ostype = 'windows'", "",
                          ApprovalOrigin::kInstruction);
    REQUIRE(id.has_value());

    Harness h;
    h.approval_manager = mgr.get();
    h.step_up_ok = false;
    h.wire();

    for (const char* verb : {"approve", "reject"}) {
        auto res = h.sink.Post("/api/approvals/" + *id + "/" + verb, "{}");
        REQUIRE(res);
        CHECK(res->status == 401);
    }
    CHECK(h.mfa_labels.empty());
    CHECK(h.audits.empty());
    // The label pin in test_step_up_route_inventory.cpp reads the call sites lexically; the
    // runtime labels must be the ones kStepUpPolicy carries for the two approval rows.
    REQUIRE(h.step_up_labels.size() == 2);
    CHECK(h.step_up_labels[0] == "POST /api/approvals/{id}/approve");
    CHECK(h.step_up_labels[1] == "POST /api/approvals/{id}/reject");
    auto row = mgr->get(*id);
    REQUIRE(row.has_value());
    CHECK(row->status == "pending");
}

// ── Approver MFA gate outcomes (#6079) ──────────────────────────────────────
// The closure is a stub here (the real gate is covered in test_mfa_step_up.cpp and the
// integration cases below); these cases pin what the ROUTE does with each outcome. They need a
// real ApprovalManager because the gate sits after the store-availability check.

namespace {
struct Pending {
    yuzu::test::ApprovalManagerPg mgr;
    std::string id;
    Pending() {
        auto s = mgr->submit("def-mfa", "submitter1", "group:x", "", ApprovalOrigin::kInstruction);
        REQUIRE(s.has_value());
        id = *s;
    }
    void check_pending() const {
        auto row = mgr->get(id);
        REQUIRE(row.has_value());
        CHECK(row->status == "pending");
        CHECK(row->reviewed_by.empty());
    }
};
using Kind = ApproverMfaOutcome::Kind;
} // namespace

TEST_CASE("approval_routes: a refused MFA outcome is a 403 with a typed reason, a ticket-specific "
          "denied row, no attempted row, and the ticket stays pending",
          "[server][routes][approval_routes][approver_mfa][pg]") {
    struct Case {
        MfaFactorState factor;
        const char* reason;
    };
    static const Case kCases[] = {
        {MfaFactorState::kNotEnrolled, "mfa_not_enrolled"},
        {MfaFactorState::kNoIdpProof, "mfa_proof_missing"},
        {MfaFactorState::kSamlUnsupported, "saml_mfa_unsupported"},
        {MfaFactorState::kNotInteractive, "non_interactive_session"},
        {MfaFactorState::kAccountUnavailable, "account_unavailable"},
        // A refusal carrying a state that maps to no reason still refuses, as not-enrolled.
        {MfaFactorState::kEnrolledLocal, "mfa_not_enrolled"},
        {MfaFactorState::kIdpAttested, "mfa_not_enrolled"},
        {MfaFactorState::kStoreUnavailable, "mfa_not_enrolled"},
    };
    for (const auto& c : kCases) {
        for (const char* verb : {"approve", "reject"}) {
            INFO(c.reason << " / " << verb);
            Pending p;
            Harness h;
            h.approval_manager = p.mgr.get();
            h.mfa_outcome = {Kind::kRefuse, c.factor};
            h.wire();

            auto res = h.sink.Post("/api/approvals/" + p.id + "/" + verb, "{}");
            REQUIRE(res);
            CHECK(res->status == 403);
            auto j = body(res->body);
            CHECK(j["error"]["message"] == std::string("approver_assurance_required:") + c.reason);
            CHECK(j["error"]["remediation"].is_string());
            CHECK(res->get_header_value("Sec-Audit-Failed").empty());

            REQUIRE(h.mfa_labels.size() == 1);
            CHECK(h.mfa_labels[0] == std::string("POST /api/approvals/{id}/") + verb);
            REQUIRE(h.audits.size() == 1); // the denied row only: never `attempted`
            CHECK(h.audits[0].action == std::string("approval.") + verb);
            CHECK(h.audits[0].result == "denied");
            CHECK(h.audits[0].target_type == "approval");
            CHECK(h.audits[0].target_id == p.id);
            CHECK(h.audits[0].detail == std::string("approver_assurance:") + c.reason);
            CHECK(h.events.empty());
            p.check_pending();
        }
    }
}

TEST_CASE("approval_routes: the default-constructed MFA outcome is a refusal, not a pass",
          "[server][routes][approval_routes][approver_mfa][pg]") {
    Pending p;
    Harness h;
    h.approval_manager = p.mgr.get();
    h.mfa_outcome = ApproverMfaOutcome{};
    h.wire();
    auto res = h.sink.Post("/api/approvals/" + p.id + "/approve", "{}");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(body(res->body)["error"]["message"] == "approver_assurance_required:mfa_not_enrolled");
    p.check_pending();
}

TEST_CASE("approval_routes: the not-enrolled remediation names the role-appropriate next step",
          "[server][routes][approval_routes][approver_mfa][pg]") {
    Pending p;
    auto remediation = [&](auth::Role role, MfaFactorState factor) {
        Harness h;
        h.approval_manager = p.mgr.get();
        auth::Session s;
        s.username = "approver1";
        s.role = role;
        h.session = s;
        h.mfa_outcome = {Kind::kRefuse, factor};
        h.wire();
        auto res = h.sink.Post("/api/approvals/" + p.id + "/approve", "{}");
        REQUIRE(res);
        REQUIRE(res->status == 403);
        return body(res->body)["error"]["remediation"].get<std::string>();
    };
    const auto admin = remediation(auth::Role::admin, MfaFactorState::kNotEnrolled);
    CHECK(admin.find("Settings > Security and sign-in > Two-factor sign-in") != std::string::npos);
    CHECK(admin.find("cannot enrol itself") == std::string::npos);
    // Settings enrolment does not stamp the session proof, so the admin enters a code at the
    // retry's step-up prompt rather than signing in again.
    CHECK(admin.find("retry and enter a code when prompted") != std::string::npos);
    CHECK(admin.find("sign in again") == std::string::npos);

    const auto user = remediation(auth::Role::user, MfaFactorState::kNotEnrolled);
    // UP-6: the text must hold under every --mfa-enforcement mode, so it must not claim the
    // account cannot enrol (under `required` login enrols it; a session minted before the
    // policy flip simply never went through that step). It sends the user back through
    // sign-in first, and to an administrator second.
    CHECK(user.find("cannot enrol itself") == std::string::npos);
    CHECK(user.find("sign out and sign in again") != std::string::npos);
    CHECK(user.find("--mfa-enforcement") != std::string::npos);
    CHECK(user.find("ask your Yuzu administrator to enrol you") != std::string::npos);
    CHECK(user.find("docs/ops-runbooks") == std::string::npos);
    // The pointer names a section that exists, by its title and its document, and carries no
    // repo path.
    CHECK(user.find("(see \"Enrolling a non-admin approver\" in the Auth Store Recovery "
                    "Runbook), then retry.") != std::string::npos);
    CHECK(user.find("Administrator guide") == std::string::npos);
    CHECK(user.find("Settings > Security and sign-in") == std::string::npos);

    // The opening names BOTH causes: a proof dropped as future-dated leaves the same refusal
    // after the skew has elapsed, so "no MFA amr" alone would be false there.
    const auto no_proof = remediation(auth::Role::user, MfaFactorState::kNoIdpProof);
    CHECK(no_proof.find("left no usable second-factor proof: the identity provider sent no MFA "
                        "amr, or the clocks of the identity provider, the Yuzu server and its "
                        "database disagree.") != std::string::npos);
    CHECK(no_proof.find("did not attest") == std::string::npos);
    // The SSO "sign in again" advice also carries the clock clause, for the case where the
    // proof was dropped as future-dated and the skew has since elapsed (UP-4 residual).
    CHECK(remediation(auth::Role::user, MfaFactorState::kNoIdpProof)
              .find(" If it repeats, ask your administrator to check clock synchronisation "
                    "between the identity provider, the Yuzu server and its database.") !=
          std::string::npos);
    // The provider-side advice names a property to preserve (require MFA, report it in amr),
    // not a claim to assert unconditionally.
    CHECK(no_proof.find("Sign in again through your identity provider with MFA, or ask an "
                        "administrator to have the provider require MFA for approvers and "
                        "report it in amr.") != std::string::npos);
    CHECK(no_proof.find("assert amr") == std::string::npos);
    CHECK(remediation(auth::Role::admin, MfaFactorState::kSamlUnsupported).find("#4935") !=
          std::string::npos);
    CHECK(remediation(auth::Role::admin, MfaFactorState::kAccountUnavailable)
              .find("deactivated or no longer exists") != std::string::npos);
    // The default text names what the code enforces, not a gate it does not.
    const auto fallback = remediation(auth::Role::admin, MfaFactorState::kNotInteractive);
    CHECK(fallback.find("enrolled MFA factor and a fresh proof") != std::string::npos);
    CHECK(fallback.find("passes the MFA step-up gate") == std::string::npos);
    p.check_pending();
}

TEST_CASE("approval_routes: an unreadable MFA enrolment is a retryable 503 with an error row and "
          "the ticket stays pending",
          "[server][routes][approval_routes][approver_mfa][pg]") {
    for (const char* verb : {"approve", "reject"}) {
        INFO(verb);
        Pending p;
        Harness h;
        h.approval_manager = p.mgr.get();
        h.mfa_outcome = {Kind::kStoreUnavailable, MfaFactorState::kStoreUnavailable};
        h.wire();

        auto res = h.sink.Post("/api/approvals/" + p.id + "/" + verb, "{}");
        REQUIRE(res);
        CHECK(res->status == 503);
        auto j = body(res->body);
        CHECK(j["error"]["code"] == 503);
        CHECK(j["error"]["retry_after_ms"] == 5000);
        CHECK(j["error"].contains("correlation_id"));
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].result == "error");
        CHECK(h.audits[0].target_id == p.id);
        CHECK(h.audits[0].detail == "approver_assurance:mfa_store_unavailable");
        CHECK(h.events.empty());
        p.check_pending();
    }
}

TEST_CASE("approval_routes: an SSO proof dated after the database clock is a 503 with its own "
          "error row, its own texts and a null retry hint, and the ticket stays pending",
          "[server][routes][approval_routes][approver_mfa][pg]") {
    for (const char* verb : {"approve", "reject"}) {
        INFO(verb);
        Pending p;
        Harness h;
        h.approval_manager = p.mgr.get();
        h.mfa_outcome = {Kind::kProofClockSkew, MfaFactorState::kNoIdpProof};
        h.wire();

        auto res = h.sink.Post("/api/approvals/" + p.id + "/" + verb, "{}");
        REQUIRE(res);
        CHECK(res->status == 503);
        CHECK(res->get_header_value("Sec-Audit-Failed").empty());
        auto j = body(res->body);
        CHECK(j["error"]["code"] == 503);
        CHECK(j["error"]["message"] ==
              "the approver's identity-provider MFA proof is dated after the database clock");
        CHECK(j["error"]["remediation"] ==
              "an administrator must correct clock synchronisation between the identity "
              "provider, the Yuzu server and its database; retrying will not help until then");
        CHECK(j["error"].contains("correlation_id"));
        // No retry hint: retrying cannot help until the clocks are fixed. The A4 envelope
        // always carries the key and encodes "no hint" as null (rest_a4_envelope.hpp), so the
        // pin is null, never a number.
        REQUIRE(j["error"].contains("retry_after_ms"));
        CHECK(j["error"]["retry_after_ms"].is_null());
        CHECK_FALSE(j["error"]["retry_after_ms"].is_number());
        // No `Retry-After` header either (the Settings 503 sends one; this arm must not).
        CHECK(res->get_header_value("Retry-After").empty());
        // The same ordering guarantee as the other 503 arm: one `error` row, no `attempted`.
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].action == std::string("approval.") + verb);
        CHECK(h.audits[0].result == "error");
        CHECK(h.audits[0].target_type == "approval");
        CHECK(h.audits[0].target_id == p.id);
        CHECK(h.audits[0].detail == "approver_assurance:mfa_proof_clock_skew");
        CHECK(h.events.empty());
        p.check_pending();
    }
}

TEST_CASE("approval_routes: a stale MFA proof keeps the gate's 401 untouched and adds a "
          "mfa_proof_stale denied row, before any attempted row",
          "[server][routes][approval_routes][approver_mfa][pg]") {
    for (const char* verb : {"approve", "reject"}) {
        INFO(verb);
        Pending p;
        Harness h;
        h.approval_manager = p.mgr.get();
        h.mfa_outcome = {Kind::kChallengeWritten, MfaFactorState::kEnrolledLocal};
        h.wire();

        auto res = h.sink.Post("/api/approvals/" + p.id + "/" + verb, "{}");
        REQUIRE(res);
        CHECK(res->status == 401);
        CHECK(res->body == R"({"error":{"code":401,"message":"MFA step-up required"}})");
        REQUIRE(h.audits.size() == 1);
        CHECK(h.audits[0].result == "denied");
        CHECK(h.audits[0].target_id == p.id);
        CHECK(h.audits[0].detail == "approver_assurance:mfa_proof_stale");
        REQUIRE(h.audits_at_mfa.size() == 1);
        CHECK(h.audits_at_mfa[0] == 0); // the gate ran before any audit row
        CHECK(h.events.empty());
        p.check_pending();
    }
}

// sec-3 / UP-11 (#6079 governance round 1): the ticket id is the raw `[^/]+` path segment and
// every refusal row is written BEFORE any ticket-existence check, so a hostile segment must
// never reach an audit row or a log line as raw bytes. Each arm below writes a row naming the
// ticket; the status of each is the one a well-formed id gets.
TEST_CASE(
    "approval_routes: a hostile ticket id is never audited or logged raw, on any refusing arm",
    "[server][routes][approval_routes][approver_mfa][pg]") {
    const std::vector<std::string> hostile = {
        std::string("abc\nforged=1 action=approval.approve"),
        std::string("x\r\ny\x01\x7f"),
        std::string("has space"),
        std::string("a=b,c"),
        std::string("caf\xC3\xA9"),
        std::string(129, 'a'),       // one past the shape bound
        std::string(10 * 1024, 'a'), // 10 KB
    };
    enum class Arm { kClassCheck, kRefuse, kStoreUnavailable, kChallenge, kPass };
    struct Case {
        const char* label;
        Arm arm;
        int status;
        const char* result;
        const char* detail;
    };
    const Case kCases[] = {
        {"class check", Arm::kClassCheck, 403, "denied",
         "approver_assurance:non_interactive_session"},
        {"mfa refuse", Arm::kRefuse, 403, "denied", "approver_assurance:mfa_not_enrolled"},
        {"mfa store unavailable", Arm::kStoreUnavailable, 503, "error",
         "approver_assurance:mfa_store_unavailable"},
        {"mfa challenge", Arm::kChallenge, 401, "denied", "approver_assurance:mfa_proof_stale"},
        // Past the gate a malformed id is a 400 not-found; the store is never asked.
        {"gate passed", Arm::kPass, 400, "denied", "invalid_approval_id"},
    };
    Pending p;
    for (const auto& id : hostile) {
        for (const auto& c : kCases) {
            for (const char* verb : {"approve", "reject"}) {
                INFO(c.label << " / " << verb << " / id of " << id.size() << " bytes");
                Harness h;
                h.approval_manager = p.mgr.get();
                switch (c.arm) {
                case Arm::kClassCheck:
                    h.session = session_of("bot", "api_token");
                    h.sink.default_headers = {{"Host", "yuzu.test"}}; // a bearer sends no Origin
                    break;
                case Arm::kRefuse:
                    h.mfa_outcome = {Kind::kRefuse, MfaFactorState::kNotEnrolled};
                    break;
                case Arm::kStoreUnavailable:
                    h.mfa_outcome = {Kind::kStoreUnavailable, MfaFactorState::kStoreUnavailable};
                    break;
                case Arm::kChallenge:
                    h.mfa_outcome = {Kind::kChallengeWritten, MfaFactorState::kEnrolledLocal};
                    break;
                case Arm::kPass:
                    break;
                }
                h.wire();

                yuzu::test::LogCapture logs(spdlog::level::warn);
                auto res = h.sink.Post("/api/approvals/" + id + "/" + verb, "{}");
                logs.stop();
                REQUIRE(res);
                CHECK(res->status == c.status);

                REQUIRE(h.audits.size() == 1); // the one refusal row; never `attempted`
                const auto& row = h.audits[0];
                CHECK(row.action == std::string("approval.") + verb);
                CHECK(row.result == c.result);
                CHECK(row.target_type == "approval");
                CHECK(row.target_id == "invalid-id");
                CHECK(row.detail == c.detail);
                for (const auto* field :
                     {&row.action, &row.result, &row.target_type, &row.target_id, &row.detail}) {
                    CHECK(field->find_first_of(std::string_view("\r\n\x01\x7f", 4)) ==
                          std::string::npos);
                    CHECK(field->size() < 128);
                }
                if (c.arm == Arm::kPass) {
                    // The invalid-id refusal is a full A4 envelope, not the legacy
                    // `{"error":"..."}` string body of the store-result arms.
                    const auto b = json::parse(res->body, nullptr, false);
                    REQUIRE(b.is_object());
                    REQUIRE(b["error"].is_object());
                    CHECK(b["error"]["code"] == 400);
                    CHECK(b["error"]["message"] == "approval not found");
                    CHECK(b["error"]["correlation_id"].is_string());
                    CHECK_FALSE(b["error"]["correlation_id"].get<std::string>().empty());
                    CHECK(b["error"]["remediation"].is_string());
                    CHECK_FALSE(b["error"]["remediation"].get<std::string>().empty());
                    CHECK(b["meta"]["api_version"] == "v1");
                }
                // The raw bytes are not reflected in the response or the log either.
                CHECK(res->body.find(id) == std::string::npos);
                CHECK(res->get_header_value("HX-Trigger").find(id) == std::string::npos);
                if (id.size() < 64) {
                    const auto text = logs.text();
                    CHECK(text.find(id) == std::string::npos);
                    CHECK(text.find("forged=1") == std::string::npos);
                }
                CHECK(h.events.empty());
                p.check_pending();
            }
        }
    }
}

// An audit sink that fails or throws must not turn the invalid-id refusal into an escaped
// exception or a body-less response: the 400 A4 envelope is written either way, and a failed
// row is flagged the way every other refusal arm flags it (Sec-Audit-Failed).
TEST_CASE("approval_routes: the invalid-id arm survives a failing or throwing audit sink",
          "[server][routes][approval_routes][approver_mfa][pg]") {
    Pending p;
    for (const bool throws : {false, true}) {
        INFO("audit_throws=" << throws);
        Harness h;
        h.approval_manager = p.mgr.get();
        h.audit_succeeds = false;
        h.audit_throws = throws;
        h.wire();
        auto res = h.sink.Post("/api/approvals/bad%20id/approve", "{}");
        REQUIRE(res);
        CHECK(res->status == 400);
        const auto b = json::parse(res->body, nullptr, false);
        REQUIRE(b.is_object());
        CHECK(b["error"]["message"] == "approval not found");
        CHECK(b["error"]["correlation_id"].is_string());
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(h.audits.size() == 1);
        p.check_pending();
    }
}

TEST_CASE("approval_routes: a well-formed ticket id of the maximum length is audited as sent",
          "[server][routes][approval_routes][approver_mfa][pg]") {
    Pending p;
    Harness h;
    h.approval_manager = p.mgr.get();
    h.mfa_outcome = {Kind::kRefuse, MfaFactorState::kNotEnrolled};
    h.wire();
    const std::string id = std::string(120, 'A') + "_-09az"; // 126 bytes, every legal class
    auto res = h.sink.Post("/api/approvals/" + id + "/approve", "{}");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].target_id == id);
}

TEST_CASE("approval_routes: the attempted and success rows carry the assurance marker "
          "(comp-1, UP-13)",
          "[server][routes][approval_routes][approver_mfa][pg]") {
    for (const char* verb : {"approve", "reject"}) {
        INFO(verb);
        Pending p;
        Harness h;
        h.approval_manager = p.mgr.get();
        h.wire();
        auto res = h.sink.Post("/api/approvals/" + p.id + "/" + verb, "{}");
        REQUIRE(res);
        CHECK(res->status == 200);
        REQUIRE(h.audits.size() == 2);
        CHECK(h.audits[0].result == "attempted");
        CHECK(h.audits[0].detail == "approver_assurance:enrolled_fresh_mfa");
        CHECK(h.audits[1].result == "success");
        CHECK(h.audits[1].detail == "approver_assurance:enrolled_fresh_mfa");
    }
}

TEST_CASE("approval_routes: a store denial after the gate keeps the store's reason as the detail "
          "and carries no assurance marker",
          "[server][routes][approval_routes][approver_mfa][pg]") {
    Pending p;
    Harness h;
    h.approval_manager = p.mgr.get();
    auth::Session s;
    s.username = "submitter1"; // the submitter: the segregation-of-duties block
    s.role = auth::Role::admin;
    h.session = s;
    h.wire();
    auto res = h.sink.Post("/api/approvals/" + p.id + "/approve", "{}");
    REQUIRE(res);
    CHECK(res->status == 400);
    REQUIRE(h.audits.size() == 2);
    CHECK(h.audits[0].result == "attempted");
    CHECK(h.audits[1].result == "denied");
    CHECK(h.audits[1].target_id == p.id);
    CHECK(h.audits[1].detail == "reviewer cannot be the same as the submitter");
}

TEST_CASE("approval_routes: when a refusal's audit row cannot be written the refusal stands and "
          "the response says so (Sec-Audit-Failed)",
          "[server][routes][approval_routes][approver_mfa][pg]") {
    struct Case {
        const char* label;
        ApproverMfaOutcome outcome;
        int status;
    };
    const Case kCases[] = {
        {"refuse", {Kind::kRefuse, MfaFactorState::kNotEnrolled}, 403},
        {"store unavailable", {Kind::kStoreUnavailable, MfaFactorState::kStoreUnavailable}, 503},
        {"clock skew", {Kind::kProofClockSkew, MfaFactorState::kNoIdpProof}, 503},
        {"challenge written", {Kind::kChallengeWritten, MfaFactorState::kEnrolledLocal}, 401},
    };
    for (const auto& c : kCases) {
        for (const bool throws : {false, true}) {
            INFO(c.label << (throws ? " / audit throws" : " / audit returns false"));
            Pending p;
            Harness h;
            h.approval_manager = p.mgr.get();
            h.mfa_outcome = c.outcome;
            h.audit_succeeds = false;
            h.audit_throws = throws;
            h.wire();

            auto res = h.sink.Post("/api/approvals/" + p.id + "/approve", "{}");
            REQUIRE(res);
            CHECK(res->status == c.status);
            CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
            CHECK(h.events.empty());
            p.check_pending();
        }
    }
    // The class-check refusal row is held to the same rule.
    for (const bool throws : {false, true}) {
        Harness h; // null manager: the class check answers before the store is reached
        h.session = session_of("bot", "api_token");
        h.sink.default_headers = {{"Host", "yuzu.test"}};
        h.audit_succeeds = false;
        h.audit_throws = throws;
        h.wire();
        auto res = h.sink.Post("/api/approvals/abc123/approve", "{}");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    }
}

TEST_CASE("approval_routes: with the store unavailable the MFA gate is never reached",
          "[server][routes][approval_routes][approver_mfa]") {
    Harness h; // null approval_manager
    h.mfa_outcome = {Kind::kRefuse, MfaFactorState::kNotEnrolled};
    h.wire();
    auto res = h.sink.Post("/api/approvals/abc123/approve", "{}");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(h.mfa_labels.empty());
    CHECK(h.audits.empty());
}

TEST_CASE("approval_routes: an audit-write failure is a 503 with Sec-Audit-Failed and the ticket "
          "stays pending (audit before mutate, #5823)",
          "[server][routes][approval_routes][approver_mfa][pg]") {
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
    REQUIRE(h.audits_at_mfa.size() == 2);
    CHECK(h.audits_at_mfa[0] == 0);
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
    CHECK(h.mfa_labels.size() == 2);
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
// Integration: the REAL approver gate over a REAL AuthDB behind the REAL routes (#6079).
//
// `RealGate` binds `require_enrolled_fresh_mfa` exactly as server.cpp's `approver_mfa_fn`
// does (null AuthDB -> kStoreUnavailable, never a pass), so what is exercised here is the
// gate's decision flowing through the route, not a stub. alice = enrolled admin, bob =
// un-enrolled, carol = enrolled non-admin; alice's and carol's enrolment is backdated an hour
// so a proof of any age under test post-dates it.
// ═══════════════════════════════════════════════════════════════════════════

namespace {

using std::chrono::milliseconds;
using std::chrono::seconds;
using std::chrono::system_clock;

struct RealGate {
    yuzu::test::AuthDbPg authdb;
    yuzu::test::ApprovalManagerPg mgr;
    yuzu::MetricsRegistry metrics;
    Harness h;
    int configured_window{300};
    /// The authoritative durable-proof read the production closure takes from the session
    /// store. Default (unset): a `kRow` built from the session the closure is handed, i.e. the
    /// store would hold that session's own proof instant and the database clock reads "now"
    /// plus 5 ms (defensive here: `session()` stamps from this process's clock, but a
    /// Postgres-authored instant is ms-rounded and can sit a hair ahead of it, which the gate
    /// reads as future-dated). The cases that stamp through a real SessionStore set `durable`
    /// from the real read instead.
    std::optional<auth::DurableMfaProof> durable;
    std::string id;
    bool wired_{false};

    RealGate() {
        add_user("alice", auth::Role::admin);
        add_user("bob", auth::Role::user);
        add_user("carol", auth::Role::user);
        enroll("alice");
        enroll("carol");
        backdate_enrolment("alice");
        backdate_enrolment("carol");
        h.approval_manager = mgr.get();
        rebind(authdb.get());
        id = submit();
    }

    std::string submit() {
        static int n = 0;
        auto s = mgr->submit("def-real-" + std::to_string(++n), "submitter1", "group:x", "",
                             ApprovalOrigin::kInstruction);
        REQUIRE(s.has_value());
        return *s;
    }

    /// Bind the production-shaped closure over `db` (null models a server with no AuthDB).
    void rebind(AuthDB* db) {
        h.mfa_fn_override = [this, db](const httplib::Request& req, httplib::Response& res,
                                       const auth::Session& session,
                                       const std::string& label) -> ApproverMfaOutcome {
            h.mfa_labels.push_back(label);
            if (!db)
                return {ApproverMfaOutcome::Kind::kStoreUnavailable,
                        MfaFactorState::kStoreUnavailable};
            return require_enrolled_fresh_mfa(
                req, res, session, *db, configured_window,
                [this](const httplib::Request&, const std::string& a, const std::string& r,
                       const std::string& tt, const std::string& ti, const std::string& d) {
                    h.audits.push_back({a, r, tt, ti, d});
                    return true;
                },
                label, durable ? *durable : durable_row_for(session), &metrics);
        };
    }

    static auth::DurableMfaProof durable_row_for(const auth::Session& s) {
        const auto ms = [](system_clock::time_point t) {
            return t.time_since_epoch().count() == 0
                       ? std::int64_t{0}
                       : std::chrono::duration_cast<milliseconds>(t.time_since_epoch()).count();
        };
        return {auth::DurableMfaProof::Source::kRow, ms(s.mfa_verified_at),
                ms(system_clock::now()) + 5};
    }

    void add_user(const std::string& name, auth::Role role) {
        auto salt = auth::AuthManager::random_bytes(16);
        auto hash = auth::AuthManager::pbkdf2_sha256("pw", salt, 1000);
        REQUIRE(authdb->upsert_user(name, hash, auth::AuthManager::bytes_to_hex(salt), role)
                    .has_value());
    }
    void enroll(const std::string& user) {
        auto init = authdb->mfa_init_enrollment(user, "Yuzu", std::nullopt);
        REQUIRE(init.has_value());
        auto bytes = mfa::base32_decode(init->secret_base32);
        REQUIRE(bytes.has_value());
        std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
        auto code = mfa::generate(raw, mfa::current_counter(system_clock::now()));
        REQUIRE(authdb->mfa_verify_enrollment(user, code, std::nullopt).has_value());
    }
    void sql(const char* statement, const std::string& user) {
        auto lease = authdb.pool().acquire();
        REQUIRE(lease);
        auto r =
            yuzu::server::pg::exec_params(lease.get(), statement, std::vector<std::string>{user});
        INFO(PQresultErrorMessage(r.get()));
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    void backdate_enrolment(const std::string& user) {
        sql("UPDATE auth.users SET mfa_enrolled_at = now() - interval '1 hour' "
            "WHERE username = $1",
            user);
    }

    /// A session as `AuthManager::derive_session_deadlines` builds it from a DB-clock-style
    /// proof `age` old (no proof when age is nullopt).
    auth::Session session(const std::string& user, const char* source, auth::Role role,
                          std::optional<milliseconds> age) {
        auth::Session s;
        s.username = user;
        s.role = role;
        s.auth_source = source;
        const std::int64_t now =
            std::chrono::duration_cast<milliseconds>(system_clock::now().time_since_epoch())
                .count();
        const std::int64_t verified = age ? now - age->count() : 0;
        REQUIRE(auth::AuthManager::derive_session_deadlines(s, now, now + 3'600'000, now, verified,
                                                            0, 0, now));
        return s;
    }

    std::unique_ptr<httplib::Response> decide(const std::string& verb, const std::string& ticket) {
        if (!wired_) {
            h.wire(); // once: the handlers read live state (session, closure) through `h`
            wired_ = true;
        }
        return h.sink.Post("/api/approvals/" + ticket + "/" + verb, "{}");
    }
    std::string status_of(const std::string& ticket) const {
        auto row = mgr->get(ticket);
        REQUIRE(row.has_value());
        return row->status;
    }
    int audit_rows(const std::string& result) const {
        int n = 0;
        for (const auto& a : h.audits)
            n += a.result == result ? 1 : 0;
        return n;
    }
    static std::string message_of(const std::unique_ptr<httplib::Response>& r) {
        return body(r->body)["error"]["message"].get<std::string>();
    }
};

} // namespace

TEST_CASE("approval integration: an enrolled admin with a fresh proof approves and rejects (I1)",
          "[server][routes][approval_routes][pg][approver_mfa]") {
    RealGate g;
    g.h.session = g.session("alice", "local", auth::Role::admin, milliseconds(10'000));
    auto ok = g.decide("approve", g.id);
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(g.status_of(g.id) == "approved");
    CHECK(g.audit_rows("denied") == 0);
    CHECK(g.audit_rows("attempted") == 1);
    CHECK(g.audit_rows("success") == 1);

    const auto other = g.submit();
    auto rej = g.decide("reject", other);
    REQUIRE(rej);
    CHECK(rej->status == 200);
    CHECK(g.status_of(other) == "rejected");
}

TEST_CASE("approval integration: an un-enrolled account cannot approve or reject (I2)",
          "[server][routes][approval_routes][pg][approver_mfa]") {
    RealGate g;
    g.h.session = g.session("bob", "local", auth::Role::user, milliseconds(1'000));
    for (const char* verb : {"approve", "reject"}) {
        INFO(verb);
        auto res = g.decide(verb, g.id);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(RealGate::message_of(res) == "approver_assurance_required:mfa_not_enrolled");
        CHECK(body(res->body)["error"]["remediation"].get<std::string>().find(
                  "sign out and sign in again") != std::string::npos);
    }
    CHECK(g.status_of(g.id) == "pending");
    CHECK(g.audit_rows("attempted") == 0);
    CHECK(g.audit_rows("success") == 0);
}

TEST_CASE("approval integration: a proof older than 300 s is challenged, not accepted (I3)",
          "[server][routes][approval_routes][pg][approver_mfa]") {
    RealGate g;
    g.h.session = g.session("alice", "local", auth::Role::admin, milliseconds(400'000));
    auto res = g.decide("approve", g.id);
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(body(res->body)["meta"]["mfa_step_up_required"] == true);
    CHECK(g.status_of(g.id) == "pending");
    // The gate's own row plus the ticket-specific one; never an attempted/success row.
    int gate_rows = 0;
    for (const auto& a : g.h.audits)
        gate_rows += a.action == "mfa.step_up.required" ? 1 : 0;
    CHECK(gate_rows == 1);
    CHECK(g.audit_rows("denied") == 1);
    CHECK(g.audit_rows("attempted") == 0);
}

TEST_CASE("approval integration: a durable proof past 300 s on the database clock is challenged "
          "even when the cached proof reads fresh (UP-8)",
          "[server][routes][approval_routes][pg][approver_mfa]") {
    RealGate g;
    g.h.session = g.session("alice", "local", auth::Role::admin, milliseconds(10'000));
    const auto now_ms =
        std::chrono::duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    g.durable = {auth::DurableMfaProof::Source::kRow, now_ms - 450'000, now_ms};
    auto res = g.decide("approve", g.id);
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(body(res->body)["meta"]["mfa_step_up_required"] == true);
    CHECK(g.status_of(g.id) == "pending");
    CHECK(g.audit_rows("attempted") == 0);

    // The same session with a durable proof inside the window decides.
    g.durable = {auth::DurableMfaProof::Source::kRow, now_ms - 10'000, now_ms};
    auto ok = g.decide("approve", g.id);
    REQUIRE(ok);
    CHECK(ok->status == 200);
}

TEST_CASE("approval integration: a proof from before a disable + re-enrol is challenged; a fresh "
          "proof then decides (I4)",
          "[server][routes][approval_routes][pg][approver_mfa]") {
    RealGate g;
    auto old_session = g.session("alice", "local", auth::Role::admin, milliseconds(10'000));
    g.h.session = old_session;
    {
        auto res = g.decide("approve", g.id);
        REQUIRE(res);
        REQUIRE(res->status == 200); // sanity: the same session decided fine before the reset
    }
    const auto next = g.submit();

    REQUIRE(g.authdb->mfa_disable("alice").has_value());
    std::this_thread::sleep_for(milliseconds(10));
    g.enroll("alice");
    std::this_thread::sleep_for(milliseconds(10));

    g.h.audits.clear();
    g.h.session = old_session;
    auto stale = g.decide("approve", next);
    REQUIRE(stale);
    CHECK(stale->status == 401);
    CHECK(g.status_of(next) == "pending");
    bool saw_reason = false;
    for (const auto& a : g.h.audits)
        saw_reason |= a.detail.find("reason=proof_predates_enrolment") != std::string::npos;
    CHECK(saw_reason);

    g.h.session = g.session("alice", "local", auth::Role::admin, milliseconds(0));
    auto fresh = g.decide("approve", next);
    REQUIRE(fresh);
    CHECK(fresh->status == 200);
    CHECK(g.status_of(next) == "approved");
}

TEST_CASE("approval integration: a disabled step-up window does not disable the approver gate "
          "(I5)",
          "[server][routes][approval_routes][pg][approver_mfa]") {
    RealGate g;
    g.configured_window = 0; // --mfa-step-up-window-secs=0
    g.h.session = g.session("alice", "local", auth::Role::admin, milliseconds(400'000));
    auto res = g.decide("approve", g.id);
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(g.status_of(g.id) == "pending");

    g.h.session = g.session("alice", "local", auth::Role::admin, milliseconds(200'000));
    auto ok = g.decide("approve", g.id);
    REQUIRE(ok);
    CHECK(ok->status == 200);
}

TEST_CASE("approval integration: an unreadable MFA secret is a 503 and is counted (I6)",
          "[server][routes][approval_routes][pg][approver_mfa]") {
    RealGate g;
    g.sql("UPDATE auth.users SET mfa_totp_secret = NULL WHERE username = $1", "alice");
    g.h.session = g.session("alice", "local", auth::Role::admin, milliseconds(1'000));
    auto res = g.decide("approve", g.id);
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(body(res->body)["error"]["retry_after_ms"] == 5000);
    CHECK(g.status_of(g.id) == "pending");
    CHECK(
        g.metrics.counter("yuzu_auth_secret_unavailable_total", {{"route", "approval"}}).value() ==
        1.0);
}

TEST_CASE("approval integration: an enrolled non-admin approver is admitted (I7)",
          "[server][routes][approval_routes][pg][approver_mfa]") {
    RealGate g;
    g.h.session = g.session("carol", "local", auth::Role::user, milliseconds(10'000));
    auto res = g.decide("approve", g.id);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(g.status_of(g.id) == "approved");
}

TEST_CASE("approval integration: an SSO session stands on its own IdP proof, not a namesake row "
          "(I8, I9)",
          "[server][routes][approval_routes][pg][approver_mfa]") {
    RealGate g;
    // I8: fresh amr proof, and the namesake local account bob is NOT enrolled.
    g.h.session = g.session("bob", "oidc", auth::Role::user, milliseconds(10'000));
    auto ok = g.decide("approve", g.id);
    REQUIRE(ok);
    CHECK(ok->status == 200);
    CHECK(g.status_of(g.id) == "approved");

    // I9: no amr proof, and the namesake local account alice IS enrolled.
    const auto next = g.submit();
    g.h.session = g.session("alice", "oidc", auth::Role::admin, std::nullopt);
    auto no = g.decide("approve", next);
    REQUIRE(no);
    CHECK(no->status == 403);
    CHECK(RealGate::message_of(no) == "approver_assurance_required:mfa_proof_missing");
    CHECK(g.status_of(next) == "pending");
}

TEST_CASE("approval integration: a SAML session is refused whatever proof it carries (I10)",
          "[server][routes][approval_routes][pg][approver_mfa]") {
    RealGate g;
    g.h.session = g.session("alice", "saml", auth::Role::admin, milliseconds(1'000));
    auto res = g.decide("approve", g.id);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(RealGate::message_of(res) == "approver_assurance_required:saml_mfa_unsupported");
    CHECK(g.status_of(g.id) == "pending");
}

TEST_CASE("approval integration: a live session whose account was deactivated is refused as "
          "account_unavailable, not as not-enrolled (sec-2)",
          "[server][routes][approval_routes][pg][approver_mfa]") {
    RealGate g;
    g.add_user("erin", auth::Role::user);
    g.enroll("erin");
    REQUIRE(g.authdb->remove_user("erin").has_value());
    g.h.session = g.session("erin", "local", auth::Role::user, milliseconds(1'000));
    auto res = g.decide("approve", g.id);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(RealGate::message_of(res) == "approver_assurance_required:account_unavailable");
    CHECK(body(res->body)["error"]["remediation"].get<std::string>().find(
              "deactivated or no longer exists") != std::string::npos);
    CHECK(g.status_of(g.id) == "pending");
    REQUIRE(g.audit_rows("denied") == 1);
    CHECK(g.h.audits.back().detail == "approver_assurance:account_unavailable");
}

TEST_CASE("approval integration: the production-shaped closure over a missing AuthDB answers 503, "
          "never a pass (I11)",
          "[server][routes][approval_routes][pg][approver_mfa]") {
    RealGate g;
    g.rebind(nullptr);
    g.h.session = g.session("alice", "local", auth::Role::admin, milliseconds(1'000));
    for (const char* verb : {"approve", "reject"}) {
        auto res = g.decide(verb, g.id);
        REQUIRE(res);
        CHECK(res->status == 503);
    }
    CHECK(g.status_of(g.id) == "pending");
}

TEST_CASE("approval integration: the gate agrees with a session minted and re-stamped through "
          "the durable SessionStore (I12)",
          "[server][routes][approval_routes][pg][approver_mfa]") {
    RealGate g;
    yuzu::server::SessionStore store{g.authdb.pool()};
    REQUIRE(store.is_open());
    auth::AuthManager mgr;
    mgr.set_auth_db(g.authdb.get());
    mgr.set_session_store(&store);

    // A login-time proof is stamped from the database clock; alice's enrolment is an hour old.
    const auto token = mgr.create_local_session_for_test("alice", auth::Role::admin, true);
    REQUIRE_FALSE(token.empty());
    auto live = mgr.validate_session(token);
    REQUIRE(live.has_value());
    g.h.session = live;
    g.durable = mgr.read_durable_mfa_proof(token, "alice");
    REQUIRE(g.durable->source == auth::DurableMfaProof::Source::kRow);
    {
        auto ok = g.decide("approve", g.id);
        REQUIRE(ok);
        CHECK(ok->status == 200);
    }

    // Clear and re-enrol: the durable proof now predates the enrolment...
    const auto next = g.submit();
    REQUIRE(g.authdb->mfa_disable("alice").has_value());
    std::this_thread::sleep_for(milliseconds(10));
    g.enroll("alice");
    std::this_thread::sleep_for(milliseconds(10));
    live = mgr.validate_session(token);
    REQUIRE(live.has_value());
    g.h.session = live;
    g.durable = mgr.read_durable_mfa_proof(token, "alice");
    {
        auto stale = g.decide("approve", next);
        REQUIRE(stale);
        CHECK(stale->status == 401);
        CHECK(g.status_of(next) == "pending");
    }

    // ...and re-proving through the store's own stamp (database now()) clears it.
    REQUIRE(mgr.mark_session_mfa_verified(token));
    live = mgr.validate_session(token);
    REQUIRE(live.has_value());
    g.h.session = live;
    g.durable = mgr.read_durable_mfa_proof(token, "alice");
    auto again = g.decide("approve", next);
    REQUIRE(again);
    CHECK(again->status == 200);
    CHECK(g.status_of(next) == "approved");
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
    const std::string& src = yuzu::test::source_scan::comment_free_source("server.cpp");
    CHECK(src.find("register_approval_routes(") != std::string::npos);
}

// QE-1 (#6061): the Deps block is built with designated initialisers, and omitting one
// COMPILES (the member is value-initialised). Dropping `.approver_mfa_fn` would 503 every real
// approval (the route fails closed on an unwired closure); dropping `.csrf_trusted_origins`
// would silently narrow the same-site gate to the request's own Host, rejecting every
// deployment behind a TLS-terminating proxy. Neither shows up in the handler tests, which
// build their own Deps, so pin both inside the production call.
//
// This is a lexical pin and deliberately weak: it proves the names are bound, not that the
// closure behind them is the right one. The behaviour of the real gate is covered by the
// `[pg]` integration cases below, which bind the same closure shape by hand.
TEST_CASE("approval_routes: wiring -- server.cpp passes approver_mfa_fn and csrf_trusted_origins "
          "into the approval Deps",
          "[server][routes][approval_routes]") {
    // Comments are stripped first: commented-out code must not satisfy a pin (#6079 qe-S2).
    const std::string& src = yuzu::test::source_scan::comment_free_source("server.cpp");
    const auto call = src.find("approval::register_approval_routes(");
    REQUIRE(call != std::string::npos);
    // The call's Deps block ends at the ApprovalManager pointer, its last member.
    const auto end = src.find(".approval_manager = approval_manager_.get()", call);
    REQUIRE(end != std::string::npos);
    const std::string block = src.substr(call, end - call);
    CHECK(block.find(".approver_mfa_fn = approver_mfa_fn") != std::string::npos);
    // Both gates are wired: the generic one consumes the central check's pass, the approver
    // one refuses what it lets through. Dropping either is a fail-closed 503 on every approval.
    CHECK(block.find(".step_up_fn = step_up_fn") != std::string::npos);
    CHECK(block.find(".csrf_trusted_origins = cfg_.csrf_trusted_origins") != std::string::npos);
    CHECK(block.find(".perm_fn = perm_fn") != std::string::npos);
    CHECK(block.find(".resolve_session_fn = resolve_session_fn") != std::string::npos);
    CHECK(block.find(".audit_fn = audit_fn") != std::string::npos);

    // The closure itself: it calls the approver gate, and a missing AuthDB must never pass.
    const auto def = src.find("approval::Deps::ApproverMfaFn approver_mfa_fn");
    REQUIRE(def != std::string::npos);
    REQUIRE(def < call);
    const std::string closure = src.substr(def, call - def);
    CHECK(closure.find("require_enrolled_fresh_mfa(") != std::string::npos);
    CHECK(closure.find("require_mfa_step_up(") == std::string::npos);
    // One read of the AuthDB pointer: the null check and the dereference use the same local.
    CHECK(closure.find("auth_mgr_.auth_db_ptr()") == closure.rfind("auth_mgr_.auth_db_ptr()"));
    const auto null_check = closure.find("if (!auth_db)");
    REQUIRE(null_check != std::string::npos);
    CHECK(closure.find("*auth_db,") != std::string::npos);
    CHECK(closure.find("Kind::kStoreUnavailable", null_check) <
          closure.find("require_enrolled_fresh_mfa("));
    CHECK(closure.find("Kind::kPass") == std::string::npos);
    // UP-8: the production closure takes the authoritative durable proof read (cookie token,
    // principal-checked) and hands it to the gate. Dropping it, or passing "no store
    // attached", would put production back on the suspend-blind cached clock while every
    // unit fixture (whose default is a kRow built from the session) stayed green.
    const auto read = closure.find("auth_mgr_.read_durable_mfa_proof(");
    REQUIRE(read != std::string::npos);
    CHECK(closure.find("AuthRoutes::extract_session_cookie(req)", read) != std::string::npos);
    CHECK(closure.find("session.username", read) != std::string::npos);
    CHECK(read < closure.find("require_enrolled_fresh_mfa("));
    CHECK(closure.find("action_label, durable,") != std::string::npos);
    // The route="approval" 503 counter depends on the registry being handed to the gate: a
    // nullptr here compiles and silently loses the series.
    CHECK(closure.find("action_label, durable, &metrics_)") != std::string::npos);
    // ...and the closure has no other way to build one: a synthetic proof literal here would
    // age the session on a clock the database does not own.
    CHECK(closure.find("DurableMfaProof{") == std::string::npos);
    CHECK(closure.find("DurableMfaProof::Source") == std::string::npos);
}

// arch-1 / sre-1 (#6079): `route="approval"` is emitted by require_enrolled_fresh_mfa, so it
// belongs to the pre-seeded closed label set of yuzu_auth_secret_unavailable_total; without
// the seed the series is absent until the first outage, which is invisible to absent() alerts.
TEST_CASE("approval_routes: wiring -- server.cpp pre-seeds route=\"approval\" on "
          "yuzu_auth_secret_unavailable_total",
          "[server][routes][approval_routes]") {
    const std::string& src = yuzu::test::source_scan::comment_free_source("server.cpp");
    const auto describe = src.find("metrics_.describe(\"yuzu_auth_secret_unavailable_total\"");
    REQUIRE(describe != std::string::npos);
    const auto loop = src.find("for (auto route :", describe);
    REQUIRE(loop != std::string::npos);
    const auto counter = src.find("metrics_.counter(\"yuzu_auth_secret_unavailable_total\"", loop);
    REQUIRE(counter != std::string::npos);
    const std::string seeded = src.substr(loop, counter - loop);
    for (const char* route : {"login", "mfa_verify", "mfa_stepup", "mfa_enroll", "elevate",
                              "password_change", "approval"}) {
        INFO(route);
        CHECK(seeded.find(std::string("\"") + route + "\"") != std::string::npos);
    }
}

TEST_CASE("approval_routes: GET /api/approvals shows a bound ticket's frozen request as an object; "
          "an unbound row is unchanged",
          "[server][routes][approval_routes][pg][bound]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto unbound = mgr->submit("def-plain", "submitter1", "scope", "", ApprovalOrigin::kInstruction);
    REQUIRE(unbound.has_value());
    const std::string request = R"({"definition":{"name":"Block RDP","hash":"abc"},"targets":["host-1"]})";
    auto bound =
        mgr->submit_bound("guardian.deploy.r1", "submitter1", "", ApprovalOrigin::kGuardianDeploy,
                          BoundRequest{request, {"designer1"}});
    REQUIRE(bound.has_value());

    Harness h;
    h.approval_manager = mgr.get();
    h.wire();
    auto list = h.sink.Get("/api/approvals");
    REQUIRE(list);
    REQUIRE(list->status == 200);
    const auto arr = body(list->body)["approvals"];
    REQUIRE(arr.size() == 2);
    for (const auto& row : arr) {
        if (row["id"] == *unbound) {
            CHECK(row.size() == 9);
            CHECK_FALSE(row.contains("request"));
        } else {
            REQUIRE(row["id"] == *bound);
            REQUIRE(row["request"].is_object());
            CHECK(row["request"]["definition"]["hash"] == "abc");
            CHECK(row["request_digest"].get<std::string>().size() == 64);
            CHECK(row["excluded_roots"] == nlohmann::json::array({"designer1"}));
        }
    }
}
