/**
 * test_approvals_fragment_routes.cpp — route-handler coverage for the
 * single-route Approvals HTMX fragment (#2542 PR-12), driven in-process
 * through TestRouteSink (no httplib acceptor, #438).
 *
 * Split like every other #2542 module: a MockHarness (no Postgres needed)
 * for registration shape, gate ordering (auth_fn THEN perm_fn
 * Approval:Read), and the null-`approval_manager` degrade; a `[pg]` section
 * (real `ApprovalManager`, via the shared `ApprovalManagerPg` helper) for
 * the actual rendering path — the self-review button suppression (#1821)
 * and html_escape coverage.
 *
 * The Operate O1 page view (`view=page`) and the shared prelude (filter
 * validation, checked read, 403 rewrite) are covered below the tab cases; the
 * pure list renderer has its own file (test_approvals_page_render.cpp).
 */

#include "approvals_fragment_routes.hpp"
#include "test_route_sink.hpp"

#include "approval_manager.hpp"
#include "instruction_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "test_approval_manager_pg_helper.hpp"
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>
#include <libpq-fe.h>

#include "../test_helpers.hpp"

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

std::size_t count_of(const std::string& haystack, const std::string& needle) {
    std::size_t n = 0;
    for (auto at = haystack.find(needle); at != std::string::npos;
         at = haystack.find(needle, at + needle.size()))
        ++n;
    return n;
}

/// Declaration order: `sink` LAST (CLAUDE.md / test_route_sink.hpp
/// convention).
struct Harness {
    ApprovalManager* approval_manager{nullptr};
    InstructionStore* instruction_store{nullptr};

    bool auth_allow{true};
    std::string auth_username{"alice"};
    std::string auth_source{"local"};
    std::string principal_kind{"human"};

    bool perm_allow{true};
    int perm_deny_status{403};
    std::string perm_deny_body{R"({"error":{"code":403,"message":"denied"}})"};
    std::vector<std::pair<std::string, std::string>> perm_calls;

    bool probe_wired{true};
    bool probe_allow{true};
    std::vector<std::pair<std::string, std::string>> probe_calls;

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        approvals_fragment::Deps deps;
        deps.approval_manager = approval_manager;
        deps.instruction_store = instruction_store;
        deps.auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            if (!auth_allow) {
                res.status = 401;
                res.set_content(R"({"error":{"code":401,"message":"unauthenticated"}})",
                                "application/json");
                return std::nullopt;
            }
            auth::Session s;
            s.username = auth_username;
            s.auth_source = auth_source;
            s.principal_kind = principal_kind;
            return s;
        };
        deps.perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) {
            perm_calls.push_back({type, op});
            if (!perm_allow) {
                res.status = perm_deny_status;
                res.set_content(perm_deny_body, "application/json");
                return false;
            }
            return true;
        };
        if (probe_wired)
            deps.probe_perm_fn = [this](const httplib::Request&, const std::string& type,
                                        const std::string& op) {
                probe_calls.push_back({type, op});
                return probe_allow;
            };
        approvals_fragment::register_approvals_fragment_routes(sink, deps);
    }
};

} // namespace

// ── Registration shape ──────────────────────────────────────────────────

TEST_CASE("approvals_fragment_routes: registers exactly 1 route",
          "[server][routes][approvals_fragment_routes]") {
    Harness h;
    h.wire();
    CHECK(h.sink.route_count() == 1);
}

// ── Gate ordering: auth_fn THEN perm_fn Approval:Read ───────────────────

TEST_CASE("approvals_fragment_routes: an unauthenticated caller 401s before perm_fn runs",
          "[server][routes][approvals_fragment_routes]") {
    Harness h;
    h.auth_allow = false;
    h.wire();
    auto res = h.sink.Get("/fragments/approvals");
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(h.perm_calls.empty());
}

TEST_CASE("approvals_fragment_routes: gates on Approval:Read (not AuditLog:*)",
          "[server][routes][approvals_fragment_routes]") {
    Harness h;
    h.wire();
    auto res = h.sink.Get("/fragments/approvals");
    REQUIRE(res);
    REQUIRE(h.perm_calls.size() == 1);
    CHECK(h.perm_calls[0] == std::pair<std::string, std::string>{"Approval", "Read"});
}

TEST_CASE("approvals_fragment_routes: a perm_fn 403 renders a 200 data-denied note "
          "that carries nothing from the gate",
          "[server][routes][approvals_fragment_routes]") {
    Harness h;
    h.perm_allow = false;
    h.perm_deny_body = R"({"error":{"code":403,"message":"needs role SECRET-ROLE"}})";
    h.wire();
    for (const char* path : {"/fragments/approvals", "/fragments/approvals?view=page"}) {
        auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->body.find("data-denied=\"true\"") != std::string::npos);
        CHECK(res->body.find("You do not have permission to view approvals.") !=
              std::string::npos);
        CHECK(res->body.find("SECRET-ROLE") == std::string::npos);
        CHECK(res->body.find("\"error\"") == std::string::npos);
    }
}

TEST_CASE("approvals_fragment_routes: a perm_fn refusal that is not a 403 passes through "
          "untouched",
          "[server][routes][approvals_fragment_routes]") {
    for (int status : {401, 503}) {
        Harness h;
        h.perm_allow = false;
        h.perm_deny_status = status;
        h.perm_deny_body = R"({"error":{"code":0,"message":"gate-owned body"}})";
        h.wire();
        auto res = h.sink.Get("/fragments/approvals?view=page");
        REQUIRE(res);
        CHECK(res->status == status);
        CHECK(res->body.find("gate-owned body") != std::string::npos);
        CHECK(res->body.find("data-denied") == std::string::npos);
    }
}

// ── Store-unavailable (no Postgres needed) ──────────────────────────────

TEST_CASE("approvals_fragment_routes: a null approval_manager degrades to \"Not available\"",
          "[server][routes][approvals_fragment_routes]") {
    Harness h;
    h.wire();
    auto res = h.sink.Get("/fragments/approvals");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("Not available") != std::string::npos);
}

TEST_CASE("approvals_fragment_routes: an unknown status filter is the exact note "
          "before the store is consulted",
          "[server][routes][approvals_fragment_routes]") {
    Harness h; // null approval_manager: validation must come first
    h.wire();
    for (const char* path :
         {"/fragments/approvals?status=bogus", "/fragments/approvals?view=page&status=bogus",
          "/fragments/approvals?status=PENDING", "/fragments/approvals?status=pending%20"}) {
        INFO(path);
        auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->body.find("data-invalid=\"status\"") != std::string::npos);
        CHECK(res->body.find("Unknown filter.") != std::string::npos);
        CHECK(res->body.find("Not available") == std::string::npos);
        CHECK(res->body.find("No approval requests") == std::string::npos);
    }
}

TEST_CASE("approvals_fragment_routes: the four real statuses and an empty status are "
          "accepted as filters",
          "[server][routes][approvals_fragment_routes]") {
    Harness h; // null approval_manager: an accepted filter reaches "Not available"
    h.wire();
    for (const char* path :
         {"/fragments/approvals?status=pending", "/fragments/approvals?status=approved",
          "/fragments/approvals?status=rejected", "/fragments/approvals?status=expired",
          "/fragments/approvals?status=", "/fragments/approvals?view=page&status="}) {
        INFO(path);
        auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->body.find("Not available") != std::string::npos);
        CHECK(res->body.find("data-invalid") == std::string::npos);
    }
}

// ── [pg] cases: real ApprovalManager ─────────────────────────────────────

TEST_CASE("approvals_fragment_routes: an empty store renders the empty-state message",
          "[pg][server][routes][approvals_fragment_routes]") {
    yuzu::test::ApprovalManagerPg mgr;
    Harness h;
    h.approval_manager = mgr.get();
    h.wire();

    auto res = h.sink.Get("/fragments/approvals");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("No approval requests") != std::string::npos);
}

TEST_CASE("approvals_fragment_routes: a pending approval from ANOTHER submitter renders "
          "Approve/Reject buttons; html-escapes rendered fields",
          "[pg][server][routes][approvals_fragment_routes]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto submitted = mgr->submit("def-frag-1", "submitter1", "ostype = 'windows'", "",
                                 ApprovalOrigin::kInstruction);
    REQUIRE(submitted.has_value());

    Harness h;
    h.approval_manager = mgr.get();
    h.auth_username = "reviewer1"; // a DIFFERENT principal than the submitter
    h.wire();

    auto res = h.sink.Get("/fragments/approvals");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("btn-primary") != std::string::npos); // Approve button
    CHECK(res->body.find("btn-danger") != std::string::npos);  // Reject button
    CHECK(res->body.find("/api/approvals/" + *submitted + "/approve") != std::string::npos);
    // The restyled buttons keep their htmx wiring: a POST to the approve/reject route.
    CHECK(res->body.find("hx-post=\"/api/approvals/" + *submitted + "/approve\"") !=
          std::string::npos);
    CHECK(res->body.find("hx-post=\"/api/approvals/" + *submitted + "/reject\"") !=
          std::string::npos);
    CHECK(res->body.find("submitter1") != std::string::npos);
}

TEST_CASE("approvals_fragment_routes: the tab's buttons swap nothing and one hidden listener "
          "re-fetches the tab on refreshApprovals",
          "[pg][server][routes][approvals_fragment_routes]") {
    yuzu::test::ApprovalManagerPg mgr;
    REQUIRE(mgr->submit("def-swap", "submitter1", "group:x", "", ApprovalOrigin::kInstruction)
                .has_value());

    Harness h;
    h.approval_manager = mgr.get();
    h.auth_username = "reviewer1";
    h.wire();

    auto res = h.sink.Get("/fragments/approvals");
    REQUIRE(res);
    const auto& b = res->body;
    // The POST answers JSON: it must never be swapped into #tab-approvals.
    CHECK(count_of(b, "hx-swap=\"none\"") == 2);
    CHECK(count_of(b, "hx-post=\"/api/approvals/") == 2);
    CHECK(count_of(b, "hx-trigger=\"refreshApprovals from:body\"") == 1);
    // The only hx-target left is the listener's own.
    CHECK(count_of(b, "hx-target=\"#tab-approvals\"") == 1);
}

TEST_CASE("approvals_fragment_routes: the page view probes Approval:Approve once per render "
          "and only when someone else's pending row exists",
          "[pg][server][routes][approvals_fragment_routes]") {
    yuzu::test::ApprovalManagerPg mgr;
    for (int i = 0; i < 3; ++i)
        REQUIRE(mgr->submit("def-pr-" + std::to_string(i), "submitter1", "group:x", "",
                            ApprovalOrigin::kInstruction)
                    .has_value());

    SECTION("granted: one probe for three pending rows, stamped 1") {
        Harness h;
        h.approval_manager = mgr.get();
        h.auth_username = "reviewer1";
        h.wire();
        auto res = h.sink.Get("/fragments/approvals?view=page");
        REQUIRE(res);
        CHECK(res->body.find("data-can-decide=\"1\"") != std::string::npos);
        REQUIRE(h.probe_calls.size() == 1);
        CHECK(h.probe_calls[0] == std::pair<std::string, std::string>{"Approval", "Approve"});
        // The probe is never the gate: Read is still checked by perm_fn.
        REQUIRE(!h.perm_calls.empty());
        CHECK(h.perm_calls[0].second == "Read");
    }
    SECTION("refused: stamped 0 and the page still renders") {
        Harness h;
        h.approval_manager = mgr.get();
        h.auth_username = "reviewer1";
        h.probe_allow = false;
        h.wire();
        auto res = h.sink.Get("/fragments/approvals?view=page");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->body.find("data-can-decide=\"0\"") != std::string::npos);
        CHECK(h.probe_calls.size() == 1);
    }
    SECTION("unwired: cannot decide, so 0") {
        Harness h;
        h.approval_manager = mgr.get();
        h.auth_username = "reviewer1";
        h.probe_wired = false;
        h.wire();
        auto res = h.sink.Get("/fragments/approvals?view=page");
        REQUIRE(res);
        CHECK(res->body.find("data-can-decide=\"0\"") != std::string::npos);
    }
    SECTION("every pending row is the caller's own: no probe") {
        Harness h;
        h.approval_manager = mgr.get();
        h.auth_username = "submitter1";
        h.wire();
        auto res = h.sink.Get("/fragments/approvals?view=page");
        REQUIRE(res);
        CHECK(h.probe_calls.empty());
        CHECK(res->body.find("data-can-decide=\"0\"") != std::string::npos);
    }
    SECTION("no pending row (filter) : no probe") {
        Harness h;
        h.approval_manager = mgr.get();
        h.auth_username = "reviewer1";
        h.wire();
        auto res = h.sink.Get("/fragments/approvals?view=page&status=approved");
        REQUIRE(res);
        CHECK(h.probe_calls.empty());
    }
}

TEST_CASE("approvals_fragment_routes: a pending approval SUBMITTED BY the viewer suppresses "
          "the review buttons (#1821 self-review guard)",
          "[pg][server][routes][approvals_fragment_routes]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto submitted = mgr->submit("def-frag-2", "same-person", "ostype = 'linux'", "",
                                 ApprovalOrigin::kInstruction);
    REQUIRE(submitted.has_value());

    Harness h;
    h.approval_manager = mgr.get();
    h.auth_username = "same-person"; // viewer == submitter
    h.wire();

    auto res = h.sink.Get("/fragments/approvals");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("You submitted this") != std::string::npos);
    CHECK(res->body.find("/approve\"") == std::string::npos); // no Approve button rendered
}

TEST_CASE("approvals_fragment_routes: Approve/Reject render only for a session the decide "
          "routes would accept on class (#6061)",
          "[pg][server][routes][approvals_fragment_routes]") {
    yuzu::test::ApprovalManagerPg mgr;
    REQUIRE(mgr->submit("def-class", "submitter1", "group:x", "", ApprovalOrigin::kInstruction)
                .has_value());

    SECTION("interactive human (local): tab buttons and page can-decide are present") {
        Harness h;
        h.approval_manager = mgr.get();
        h.auth_username = "reviewer1";
        h.wire();
        auto tab = h.sink.Get("/fragments/approvals");
        REQUIRE(tab);
        CHECK(tab->body.find("/approve\"") != std::string::npos);
        CHECK(tab->body.find("/reject\"") != std::string::npos);
        auto page = h.sink.Get("/fragments/approvals?view=page");
        REQUIRE(page);
        CHECK(page->body.find("data-can-decide=\"1\"") != std::string::npos);
    }
    SECTION("bearer session (api_token): no buttons, page can-decide 0, probe never run") {
        Harness h;
        h.approval_manager = mgr.get();
        h.auth_username = "reviewer1";
        h.auth_source = "api_token";
        h.wire();
        auto tab = h.sink.Get("/fragments/approvals");
        REQUIRE(tab);
        CHECK(tab->status == 200);
        CHECK(tab->body.find("/approve\"") == std::string::npos);
        CHECK(tab->body.find("/reject\"") == std::string::npos);
        CHECK(tab->body.find("btn-primary") == std::string::npos);
        auto page = h.sink.Get("/fragments/approvals?view=page");
        REQUIRE(page);
        CHECK(page->body.find("data-can-decide=\"0\"") != std::string::npos);
        CHECK(h.probe_calls.empty());
    }
    SECTION("mcp_token session: no buttons") {
        Harness h;
        h.approval_manager = mgr.get();
        h.auth_username = "reviewer1";
        h.auth_source = "mcp_token";
        h.wire();
        auto tab = h.sink.Get("/fragments/approvals");
        REQUIRE(tab);
        CHECK(tab->body.find("/approve\"") == std::string::npos);
    }
    SECTION("engine principal: no buttons") {
        Harness h;
        h.approval_manager = mgr.get();
        h.auth_username = "reviewer1";
        h.principal_kind = "engine";
        h.wire();
        auto tab = h.sink.Get("/fragments/approvals");
        REQUIRE(tab);
        CHECK(tab->body.find("/approve\"") == std::string::npos);
        auto page = h.sink.Get("/fragments/approvals?view=page");
        REQUIRE(page);
        CHECK(page->body.find("data-can-decide=\"0\"") != std::string::npos);
    }
}

TEST_CASE("approvals_fragment_routes: the tab offers Approve/Reject only to a caller who also "
          "holds Approval:Approve, matching the page view (#6061)",
          "[pg][server][routes][approvals_fragment_routes]") {
    yuzu::test::ApprovalManagerPg mgr;
    for (int i = 0; i < 3; ++i)
        REQUIRE(mgr->submit("def-tab-" + std::to_string(i), "submitter1", "group:x", "",
                            ApprovalOrigin::kInstruction)
                    .has_value());

    SECTION("granted: buttons, and ONE probe for three pending rows") {
        Harness h;
        h.approval_manager = mgr.get();
        h.auth_username = "reviewer1";
        h.wire();
        auto tab = h.sink.Get("/fragments/approvals");
        REQUIRE(tab);
        CHECK(count_of(tab->body, "hx-post=\"/api/approvals/") == 6);
        REQUIRE(h.probe_calls.size() == 1);
        CHECK(h.probe_calls[0] == std::pair<std::string, std::string>{"Approval", "Approve"});
    }
    SECTION("probe denies: a Read-only approver-class session sees the list but no buttons") {
        Harness h;
        h.approval_manager = mgr.get();
        h.auth_username = "reviewer1";
        h.probe_allow = false;
        h.wire();
        auto tab = h.sink.Get("/fragments/approvals");
        REQUIRE(tab);
        CHECK(tab->status == 200);
        CHECK(tab->body.find("submitter1") != std::string::npos); // still lists the requests
        CHECK(tab->body.find("hx-post=\"/api/approvals/") == std::string::npos);
        CHECK(tab->body.find("btn-primary") == std::string::npos);
        CHECK(h.probe_calls.size() == 1);
    }
    SECTION("probe unwired: fail closed, no buttons") {
        Harness h;
        h.approval_manager = mgr.get();
        h.auth_username = "reviewer1";
        h.probe_wired = false;
        h.wire();
        auto tab = h.sink.Get("/fragments/approvals");
        REQUIRE(tab);
        CHECK(tab->body.find("hx-post=\"/api/approvals/") == std::string::npos);
    }
    SECTION("only the caller's own pending rows: no probe run") {
        Harness h;
        h.approval_manager = mgr.get();
        h.auth_username = "submitter1";
        h.wire();
        auto tab = h.sink.Get("/fragments/approvals");
        REQUIRE(tab);
        CHECK(tab->body.find("hx-post=\"/api/approvals/") == std::string::npos);
        CHECK(h.probe_calls.empty());
    }
}

// ── [pg] cases: the shared prelude and the Approvals page view ───────────

namespace {

// Shares the "instructionstore" template key with test_instruction_store.cpp (same store,
// same migration) — the registry builds the named template once per process.
yuzu::test::PgTestTemplate approvals_frag_instr_tpl{
    "instructionstore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        InstructionStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("instructionstore approvals template: failed to migrate");
    }};

/// Three rows in three statuses, ids returned (pending by another user, approved, rejected).
struct Planted {
    std::string pending, approved, rejected;
};

Planted plant_three(ApprovalManager& mgr) {
    auto p = mgr.submit("def-page-pending", "submitter1", "group:p", "",
                        ApprovalOrigin::kInstruction);
    auto a = mgr.submit("def-page-approved", "submitter2", "group:a", "",
                        ApprovalOrigin::kInstruction);
    auto r = mgr.submit("def-page-rejected", "submitter3", "group:r", "",
                        ApprovalOrigin::kInstruction);
    REQUIRE(p.has_value());
    REQUIRE(a.has_value());
    REQUIRE(r.has_value());
    REQUIRE(mgr.approve(*a, "reviewer1", "looks fine").has_value());
    REQUIRE(mgr.reject(*r, "reviewer1", "too broad").has_value());
    return {*p, *a, *r};
}

std::string row_marker(const std::string& id) {
    return "data-id=\"" + id + "\"";
}

} // namespace

TEST_CASE("approvals_fragment_routes: a denied caller never reads the store",
          "[pg][server][routes][approvals_fragment_routes]") {
    yuzu::test::ApprovalManagerPg mgr;
    const auto planted = plant_three(*mgr);

    Harness h;
    h.approval_manager = mgr.get();
    h.perm_allow = false;
    h.wire();

    auto res = h.sink.Get("/fragments/approvals?view=page&status=");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("data-denied=\"true\"") != std::string::npos);
    CHECK(res->body.find(planted.pending) == std::string::npos);
    CHECK(res->body.find("submitter1") == std::string::npos);
    CHECK(h.perm_calls.size() == 1);
}

TEST_CASE("approvals_fragment_routes: the page view defaults to pending and an empty "
          "status means every status",
          "[pg][server][routes][approvals_fragment_routes]") {
    yuzu::test::ApprovalManagerPg mgr;
    const auto planted = plant_three(*mgr);

    Harness h;
    h.approval_manager = mgr.get();
    h.auth_username = "reviewer9";
    h.wire();

    // Absent status on the page view: pending only.
    auto dflt = h.sink.Get("/fragments/approvals?view=page");
    REQUIRE(dflt);
    CHECK(dflt->body.find("class=\"ops-list\"") != std::string::npos);
    CHECK(dflt->body.find(row_marker(planted.pending)) != std::string::npos);
    CHECK(dflt->body.find(row_marker(planted.approved)) == std::string::npos);
    CHECK(dflt->body.find(row_marker(planted.rejected)) == std::string::npos);
    CHECK(dflt->body.find("data-count=\"1\"") != std::string::npos);

    // Present-but-empty status: all three.
    auto all = h.sink.Get("/fragments/approvals?view=page&status=");
    REQUIRE(all);
    CHECK(all->body.find(row_marker(planted.pending)) != std::string::npos);
    CHECK(all->body.find(row_marker(planted.approved)) != std::string::npos);
    CHECK(all->body.find(row_marker(planted.rejected)) != std::string::npos);
    CHECK(all->body.find("data-count=\"3\"") != std::string::npos);

    // An explicit status returns exactly that status, and names the reviewer + comment.
    auto approved = h.sink.Get("/fragments/approvals?view=page&status=approved");
    REQUIRE(approved);
    CHECK(approved->body.find(row_marker(planted.approved)) != std::string::npos);
    CHECK(approved->body.find(row_marker(planted.pending)) == std::string::npos);
    CHECK(approved->body.find(row_marker(planted.rejected)) == std::string::npos);
    CHECK(approved->body.find("data-rev-by=\"reviewer1\"") != std::string::npos);
    CHECK(approved->body.find("data-comment=\"looks fine\"") != std::string::npos);

    // The tab view is unchanged by the filter work: no status param = every status.
    auto tab = h.sink.Get("/fragments/approvals");
    REQUIRE(tab);
    CHECK(tab->body.find("class=\"ops-list\"") == std::string::npos);
    CHECK(tab->body.find("submitter1") != std::string::npos);
    CHECK(tab->body.find("submitter2") != std::string::npos);
    CHECK(tab->body.find("submitter3") != std::string::npos);
}

TEST_CASE("approvals_fragment_routes: an unknown filter answers the same bytes with or "
          "without a store",
          "[pg][server][routes][approvals_fragment_routes]") {
    yuzu::test::ApprovalManagerPg mgr;
    plant_three(*mgr);

    Harness with_store;
    with_store.approval_manager = mgr.get();
    with_store.wire();
    Harness without_store;
    without_store.wire();

    auto a = with_store.sink.Get("/fragments/approvals?view=page&status=bogus");
    auto b = without_store.sink.Get("/fragments/approvals?view=page&status=bogus");
    REQUIRE(a);
    REQUIRE(b);
    CHECK(a->status == 200);
    CHECK(a->body == b->body);
    CHECK(a->body.find("data-invalid=\"status\"") != std::string::npos);
}

TEST_CASE("approvals_fragment_routes: the page view marks the viewer's own request and the "
          "MCP prefix",
          "[pg][server][routes][approvals_fragment_routes]") {
    yuzu::test::ApprovalManagerPg mgr;
    auto own = mgr->submit("def-own", "viewer1", "group:x", "", ApprovalOrigin::kInstruction);
    auto mcp = mgr->submit("mcp.quarantine_device", "svc-agent", "{\"agent_id\":\"a1\"}", "",
                           ApprovalOrigin::kMcp);
    REQUIRE(own.has_value());
    REQUIRE(mcp.has_value());

    Harness h;
    h.approval_manager = mgr.get();
    h.auth_username = "viewer1";
    h.wire();

    auto res = h.sink.Get("/fragments/approvals?view=page");
    REQUIRE(res);
    const auto& body = res->body;
    const auto own_at = body.find(row_marker(*own));
    const auto mcp_at = body.find(row_marker(*mcp));
    REQUIRE(own_at != std::string::npos);
    REQUIRE(mcp_at != std::string::npos);
    // Each row's own <tr ...> carries its flags: slice each row out.
    auto row_of = [&](std::size_t at) {
        const auto end = body.find("</tr>", at);
        return body.substr(at, end - at);
    };
    const auto own_row = row_of(own_at);
    const auto mcp_row = row_of(mcp_at);
    CHECK(own_row.find("data-mine=\"1\"") != std::string::npos);
    CHECK(own_row.find("data-mcp=\"0\"") != std::string::npos);
    CHECK(own_row.find("<span class=\"tag\">You</span>") != std::string::npos);
    CHECK(mcp_row.find("data-mine=\"0\"") != std::string::npos);
    CHECK(mcp_row.find("data-mcp=\"1\"") != std::string::npos);
    CHECK(mcp_row.find("<span class=\"tag\">MCP</span>") != std::string::npos);
    CHECK(mcp_row.find("data-name=\"quarantine_device\"") != std::string::npos);
    CHECK(mcp_row.find("<span class=\"tag\">You</span>") == std::string::npos);
}

TEST_CASE("approvals_fragment_routes: the page view names a request after its instruction "
          "and falls back to the id",
          "[pg][server][routes][approvals_fragment_routes]") {
    yuzu::test::ApprovalManagerPg mgr;
    YUZU_REQUIRE_PG_DB_TPL(db, approvals_frag_instr_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore instr{pool};
    REQUIRE(instr.is_open());
    instr.set_require_signed_definitions(false);

    InstructionDefinition def;
    def.name = "Set Service Start Mode";
    def.version = "1.0";
    def.plugin = "system_info";
    def.action = "query";
    def.type = "question";
    def.description = "page-name fixture";
    def.enabled = true;
    def.platforms = "windows,linux,darwin";
    def.approval_mode = "auto";
    auto def_id = instr.create_definition(def);
    REQUIRE(def_id.has_value());

    auto named = mgr->submit(*def_id, "submitter1", "group:n", "", ApprovalOrigin::kInstruction);
    auto unnamed = mgr->submit("def-no-such", "submitter1", "group:u", "",
                               ApprovalOrigin::kInstruction);
    REQUIRE(named.has_value());
    REQUIRE(unnamed.has_value());

    Harness wired;
    wired.approval_manager = mgr.get();
    wired.instruction_store = &instr;
    wired.wire();
    auto res = wired.sink.Get("/fragments/approvals?view=page");
    REQUIRE(res);
    CHECK(res->body.find("data-name=\"Set Service Start Mode\"") != std::string::npos);
    CHECK(res->body.find("data-name=\"def-no-such\"") != std::string::npos);

    // No instruction store wired: every name is the id.
    Harness bare;
    bare.approval_manager = mgr.get();
    bare.wire();
    auto ids = bare.sink.Get("/fragments/approvals?view=page");
    REQUIRE(ids);
    CHECK(ids->body.find("Set Service Start Mode") == std::string::npos);
    CHECK(ids->body.find("data-name=\"" + *def_id + "\"") != std::string::npos);
}

TEST_CASE("approvals_fragment_routes: the page view flags a truncated list only past the cap",
          "[pg][server][routes][approvals_fragment_routes]") {
    SECTION("exactly 100 pending rows are not truncated") {
        yuzu::test::ApprovalManagerPg mgr;
        yuzu::test::seed_pending(mgr.pool(), "cap-", 100, /*age_seconds=*/60);
        Harness h;
        h.approval_manager = mgr.get();
        h.wire();
        auto res = h.sink.Get("/fragments/approvals?view=page");
        REQUIRE(res);
        CHECK(count_of(res->body, "<tr class=\"row\"") == 100);
        CHECK(res->body.find("data-truncated=\"0\"") != std::string::npos);
        CHECK(res->body.find("data-pending=\"100\"") != std::string::npos);
        CHECK(res->body.find("Older requests are not listed") == std::string::npos);
    }
    SECTION("101 pending rows show 100, a lower-bound pending count and the foot note") {
        yuzu::test::ApprovalManagerPg mgr;
        yuzu::test::seed_pending(mgr.pool(), "cap-", 101, /*age_seconds=*/60);
        Harness h;
        h.approval_manager = mgr.get();
        h.wire();
        auto res = h.sink.Get("/fragments/approvals?view=page");
        REQUIRE(res);
        CHECK(count_of(res->body, "<tr class=\"row\"") == 100);
        CHECK(res->body.find("data-truncated=\"1\"") != std::string::npos);
        CHECK(res->body.find("data-pending=\"100+\"") != std::string::npos);
        CHECK(res->body.find("Showing the 100 most recent. Older requests are not listed.") !=
              std::string::npos);
    }
}

TEST_CASE("approvals_fragment_routes: a degraded read is a note and never an empty queue",
          "[pg][server][routes][approvals_fragment_routes]") {
    yuzu::test::ApprovalManagerPg mgr;
    {
        // Drop the table out from under an OPEN store so the next read genuinely fails.
        auto lease = mgr.pool().acquire();
        REQUIRE(lease);
        yuzu::server::pg::PgResult dropped = yuzu::server::pg::exec_params(
            lease.get(), "DROP TABLE approval_manager.approvals", std::vector<std::string>{});
        REQUIRE(dropped.status() == PGRES_COMMAND_OK);
    }
    Harness h;
    h.approval_manager = mgr.get();
    h.wire();
    for (const char* path : {"/fragments/approvals", "/fragments/approvals?view=page",
                             "/fragments/approvals?view=page&status="}) {
        INFO(path);
        auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->body.find("data-degraded=\"store\"") != std::string::npos);
        CHECK(res->body.find("This is not an empty queue.") != std::string::npos);
        CHECK(res->body.find("No approval requests") == std::string::npos);
        CHECK(res->body.find("Nothing is waiting") == std::string::npos);
    }
}

TEST_CASE("approvals_fragment_routes: the page view carries scope and comment once and "
          "escapes every field",
          "[pg][server][routes][approvals_fragment_routes]") {
    yuzu::test::ApprovalManagerPg mgr;
    const std::string big_scope(10000, 'S');
    const std::string evil = "<img src=x onerror=1>";
    auto big = mgr->submit("def-big", "submitter1", big_scope, "", ApprovalOrigin::kInstruction);
    auto xss = mgr->submit(evil, evil, evil, "", ApprovalOrigin::kInstruction);
    REQUIRE(big.has_value());
    REQUIRE(xss.has_value());
    const std::string big_comment(kMaxReviewCommentBytes, 'C'); // the cap
    REQUIRE(mgr->reject(*xss, "reviewer1", big_comment).has_value());

    Harness h;
    h.approval_manager = mgr.get();
    h.wire();
    auto res = h.sink.Get("/fragments/approvals?view=page&status=");
    REQUIRE(res);
    // Full text exactly once (the data attribute); the cell shows a clipped copy.
    CHECK(count_of(res->body, big_scope) == 1);
    CHECK(count_of(res->body, big_comment) == 1);
    CHECK(res->body.find(std::string(120, 'S') + "\xE2\x80\xA6") != std::string::npos);
    // Escaped on every sink; the raw tag never appears.
    CHECK(res->body.find("&lt;img src=x onerror=1&gt;") != std::string::npos);
    CHECK(res->body.find("<img") == std::string::npos);
}

// ═══════════════════════════════════════════════════════════════════════════
// Wiring tripwire.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("approvals_fragment_routes: wiring -- server.cpp still calls "
          "register_approvals_fragment_routes",
          "[server][routes][approvals_fragment_routes]") {
#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif
    std::ifstream in(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(in.is_open());
    std::string src{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    CHECK(src.find("register_approvals_fragment_routes(") != std::string::npos);
    // Both render-only probes are bound (an unbound one silently hides the controls).
    CHECK(src.find(".probe_perm_fn =") != std::string::npos);
    CHECK(src.find("wf_deps.probe_perm_fn = ") != std::string::npos);
}

// ── Bound tickets (#6062) ────────────────────────────────────────────────

TEST_CASE("approvals_fragment_routes: a bound ticket renders its frozen request, escaped, in both "
          "views; the raw JSON is never emitted",
          "[pg][server][routes][approvals_fragment_routes][bound]") {
    yuzu::test::ApprovalManagerPg mgr;
    BoundRequest br{R"({"definition":{"name":"Block <b>RDP</b>","hash":"abc123"},)"
                    R"("params":{"port":3389},"targets":["host-1"]})",
                    {}};
    auto id = mgr->submit_bound("guardian.deploy.r1", "submitter1", "", "",
                                ApprovalOrigin::kGuardianDeploy, br);
    REQUIRE(id.has_value());

    Harness h;
    h.approval_manager = mgr.get();
    h.auth_username = "reviewer1";
    h.wire();

    for (const char* url : {"/fragments/approvals?view=page", "/fragments/approvals"}) {
        auto res = h.sink.Get(url);
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->body.find("Definition: Block &lt;b&gt;RDP&lt;/b&gt; (hash abc123)") !=
              std::string::npos);
        CHECK(res->body.find("port: 3389") != std::string::npos);
        CHECK(res->body.find("<b>RDP") == std::string::npos);
        CHECK(res->body.find("{\"definition\"") == std::string::npos);
        CHECK(res->body.find("{&quot;definition") == std::string::npos);
    }
}

TEST_CASE("approvals_fragment_routes: a viewer in excluded_roots is not offered Approve, but is offered Reject",
          "[pg][server][routes][approvals_fragment_routes][bound]") {
    yuzu::test::ApprovalManagerPg mgr;
    BoundRequest br{R"({"definition":{"name":"n","hash":"h"},"targets":["t"],"params":{}})",
                    {"designer1"}};
    REQUIRE(mgr->submit_bound("guardian.deploy.r1", "submitter1", "", "",
                              ApprovalOrigin::kGuardianDeploy, br)
                .has_value());

    SECTION("the excluded viewer: page row flagged and still decidable (Reject), tab hint + Reject only") {
        Harness h;
        h.approval_manager = mgr.get();
        h.auth_username = "designer1";
        h.wire();
        auto page = h.sink.Get("/fragments/approvals?view=page");
        REQUIRE(page);
        CHECK(page->body.find("data-excluded=\"1\"") != std::string::npos);
        // The store lets an excluded root reject, so the page must offer the decision
        // container (the controller hides only Approve for this row).
        CHECK(page->body.find("data-can-decide=\"1\"") != std::string::npos);
        CHECK(h.probe_calls.size() == 1);
        auto tab = h.sink.Get("/fragments/approvals");
        REQUIRE(tab);
        CHECK(tab->body.find("You are excluded from approving this request") != std::string::npos);
        CHECK(tab->body.find("You can still reject it") != std::string::npos);
        CHECK(tab->body.find("btn-primary") == std::string::npos);            // no Approve
        CHECK(tab->body.find("/approve\"") == std::string::npos);
        CHECK(tab->body.find("/reject\"") != std::string::npos);              // Reject offered
    }
    SECTION("an excluded viewer without the Approve permission gets neither the hint nor a button") {
        Harness h;
        h.approval_manager = mgr.get();
        h.auth_username = "designer1";
        h.probe_allow = false;
        h.wire();
        auto page = h.sink.Get("/fragments/approvals?view=page");
        REQUIRE(page);
        CHECK(page->body.find("data-can-decide=\"0\"") != std::string::npos);
        auto tab = h.sink.Get("/fragments/approvals");
        REQUIRE(tab);
        CHECK(tab->body.find("btn-danger") == std::string::npos);
        CHECK(tab->body.find("You can still reject it") == std::string::npos);
    }
    SECTION("any other reviewer is offered it as usual") {
        Harness h;
        h.approval_manager = mgr.get();
        h.auth_username = "reviewer1";
        h.wire();
        auto page = h.sink.Get("/fragments/approvals?view=page");
        REQUIRE(page);
        CHECK(page->body.find("data-excluded=\"0\"") != std::string::npos);
        CHECK(page->body.find("data-can-decide=\"1\"") != std::string::npos);
    }
}

namespace {

// Force a stored request onto a bound ticket by direct SQL (a corrupt or hostile row).
void poison_request(yuzu::test::ApprovalManagerPg& mgr, const std::string& id,
                    const std::string& request_json) {
    auto lease = mgr.pool().acquire();
    REQUIRE(lease);
    REQUIRE(pg::exec_params(lease.get(),
                            "UPDATE approval_manager.approvals SET request_json = $1 WHERE id = $2",
                            std::vector<std::string>{request_json, id})
                .status() == PGRES_COMMAND_OK);
}

std::string deep_array_request(std::size_t depth) {
    return std::string(R"({"k":)") + std::string(depth, '[') + std::string(depth, ']') + "}";
}

} // namespace

TEST_CASE("approvals_fragment_routes: an unreadable stored request never crashes the page and "
          "never offers Approve; Reject stays",
          "[pg][server][routes][approvals_fragment_routes][bound]") {
    yuzu::test::ApprovalManagerPg mgr;
    BoundRequest br{R"({"definition":{"name":"n","hash":"h"},"targets":["t"],"params":{}})", {}};
    auto id = mgr->submit_bound("guardian.deploy.r1", "submitter1", "", "",
                                ApprovalOrigin::kGuardianDeploy, br);
    REQUIRE(id.has_value());

    const std::string notice = "The stored request could not be read. Do not approve this request.";
    const std::vector<std::pair<const char*, std::string>> poisons = {
        {"not json", "not json"},
        {"not an object", "[1,2]"},
        // The stored cap is 16 KiB; this is an 8192-deep array, the shape that would recurse
        // deepest in a serializer. It checks the page answers 200 with the notice and no
        // Approve; it does NOT observe the stack property itself (an 8 MB test stack survives
        // it either way), so it is not evidence for the lexical pre-scan.
        {"8192-deep array", std::string(8192, '[') + std::string(8192, ']')},
        {"depth 17 object chain", deep_array_request(17)},
        {"oversized", std::string(R"({"k":")") + std::string(kMaxRequestJsonBytes, 'a') + "\"}"},
    };
    for (const auto& [name, json] : poisons) {
        DYNAMIC_SECTION(name) {
            poison_request(mgr, *id, json);
            Harness h;
            h.approval_manager = mgr.get();
            h.auth_username = "reviewer1";
            h.wire();

            auto page = h.sink.Get("/fragments/approvals?view=page");
            REQUIRE(page);
            CHECK(page->status == 200);
            CHECK(page->body.find("data-unreadable=\"1\"") != std::string::npos);
            CHECK(page->body.find(notice) != std::string::npos);
            // The row is still listed (it is the way to find and reject it).
            CHECK(page->body.find(std::string("data-id=\"") + *id + "\"") != std::string::npos);

            auto tab = h.sink.Get("/fragments/approvals");
            REQUIRE(tab);
            CHECK(tab->status == 200);
            CHECK(tab->body.find(notice) != std::string::npos);
            CHECK(tab->body.find("btn-primary") == std::string::npos);  // no Approve
            CHECK(tab->body.find("/reject\"") != std::string::npos);    // Reject stays
        }
    }
}

TEST_CASE("approvals_fragment_routes: a readable bound request carries no unreadable marker and "
          "keeps both buttons",
          "[pg][server][routes][approvals_fragment_routes][bound]") {
    yuzu::test::ApprovalManagerPg mgr;
    BoundRequest br{R"({"definition":{"name":"n","hash":"h"},"targets":["t"],"params":{}})", {}};
    REQUIRE(mgr->submit_bound("guardian.deploy.r1", "submitter1", "", "",
                              ApprovalOrigin::kGuardianDeploy, br)
                .has_value());
    Harness h;
    h.approval_manager = mgr.get();
    h.auth_username = "reviewer1";
    h.wire();
    auto page = h.sink.Get("/fragments/approvals?view=page");
    REQUIRE(page);
    CHECK(page->body.find("data-unreadable") == std::string::npos);
    auto tab = h.sink.Get("/fragments/approvals");
    REQUIRE(tab);
    CHECK(tab->body.find("btn-primary") != std::string::npos);
    CHECK(tab->body.find("/reject\"") != std::string::npos);
}
