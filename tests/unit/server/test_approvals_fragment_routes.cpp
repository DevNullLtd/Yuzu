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

    bool perm_allow{true};
    int perm_deny_status{403};
    std::string perm_deny_body{R"({"error":{"code":403,"message":"denied"}})"};
    std::vector<std::pair<std::string, std::string>> perm_calls;

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
    const std::string big_comment(5000, 'C');
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
}
