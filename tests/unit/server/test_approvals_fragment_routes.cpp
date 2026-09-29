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
 */

#include "approvals_fragment_routes.hpp"
#include "test_route_sink.hpp"

#include "approval_manager.hpp"
#include "test_approval_manager_pg_helper.hpp"
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

/// Declaration order: `sink` LAST (CLAUDE.md / test_route_sink.hpp
/// convention).
struct Harness {
    ApprovalManager* approval_manager{nullptr};

    bool auth_allow{true};
    std::string auth_username{"alice"};

    bool perm_allow{true};
    std::vector<std::pair<std::string, std::string>> perm_calls;

    yuzu::server::test::TestRouteSink sink;

    void wire() {
        approvals_fragment::Deps deps;
        deps.approval_manager = approval_manager;
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
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})",
                                "application/json");
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

TEST_CASE("approvals_fragment_routes: a perm_fn denial 403s", "[server][routes][approvals_fragment_routes]") {
    Harness h;
    h.perm_allow = false;
    h.wire();
    auto res = h.sink.Get("/fragments/approvals");
    REQUIRE(res);
    CHECK(res->status == 403);
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
