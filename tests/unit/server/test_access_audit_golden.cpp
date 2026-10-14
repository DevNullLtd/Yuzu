/**
 * @file test_access_audit_golden.cpp
 * @brief Golden files for the Audit and reviews fragments: one rendered HTML file per cell under
 *        tests/unit/server/golden/access/. A renderer edit shows up as a reviewable diff.
 *
 * Fixture events are constructed from the REST twin's field set (not a capture); every
 * timestamp is a constant, so no normalisation is needed (an exact compare also catches a wrong
 * ISO title).
 *
 * Regeneration: `YUZU_UPDATE_GOLDEN=1 <server-tests> "[access-audit][golden]"` rewrites the files
 * and the run FAILS on purpose; re-run without the variable to confirm they now match.
 */

#include "access_audit_render.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

using namespace yuzu::server;
using namespace yuzu::server::access_audit;

namespace {

std::filesystem::path golden_dir() {
    return std::filesystem::path(YUZU_TEST_GOLDEN_DIR) / "access";
}

void check_golden(const std::string& cell, const std::string& actual) {
    const auto path = golden_dir() / (cell + ".html");
    if (std::getenv("YUZU_UPDATE_GOLDEN") != nullptr) {
        std::error_code ec;
        std::filesystem::create_directories(golden_dir(), ec);
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        REQUIRE(out.good());
        out << actual;
        out.close();
        REQUIRE(out.good());
        FAIL_CHECK("YUZU_UPDATE_GOLDEN=1: (re)wrote " << path.string()
                   << " -- re-run WITHOUT YUZU_UPDATE_GOLDEN to verify it now matches.");
        return;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in.good()) {
        FAIL_CHECK("golden file missing: " << path.string()
                   << " -- run with YUZU_UPDATE_GOLDEN=1 to create it, then re-run to verify.");
        return;
    }
    const std::string expected((std::istreambuf_iterator<char>(in)),
                               std::istreambuf_iterator<char>());
    INFO("golden mismatch for '" << cell << "' (" << path.string() << ")");
    CHECK(expected == actual);
}

AuditEvent ev(std::int64_t id, std::int64_t t, const char* principal, const char* action,
              const char* result, const char* tt, const char* ti, const char* detail) {
    AuditEvent e;
    e.id = id;
    e.timestamp = t;
    e.principal = principal;
    e.action = action;
    e.result = result;
    e.target_type = tt;
    e.target_id = ti;
    e.detail = detail;
    return e;
}

} // namespace

TEST_CASE("audit golden: log populated", "[access-audit][golden]") {
    LogView v;
    v.offset = 0;
    v.has_more = true;
    v.principal = "oidc:https://idp.example/realm#7f3a";
    v.rows = {
        ev(184203, 1791884472, "dave.rae", "guaranteed_state.rule.update", "success",
           "GuaranteedState", "GLA-WS-0088", "enabled=true"),
        ev(184200, 1791881731, "", "auth.login_failed", "error", "User", "m.graham", ""),
        ev(184197, 1791879160, "a2.operator", "auth.permission_required", "denied", "", "",
           "non-admin role denied UserManagement:Write"),
        ev(184194, 1791877200, "dave.rae", "auth.logout", "partial", "", "", "db_error=true"),
        ev(184190, 1791876000, "svc", "x.y", "not_found", "T", "<b>&\"'", "<script>"),
    };
    check_golden("audit-log__populated", render_audit_log(v));
}

TEST_CASE("audit golden: log empty", "[access-audit][golden]") {
    check_golden("audit-log__empty", render_audit_log(LogView{}));
}

TEST_CASE("audit golden: log unavailable", "[access-audit][golden]") {
    check_golden("audit-log__unavailable", render_audit_log(access::Unavailable{}));
}

TEST_CASE("audit golden: authentication sample", "[access-audit][golden]") {
    SampleView s;
    s.candidates = 842;
    s.rows = {ev(1, 1791884472, "dave.rae", "auth.login", "ok", "User", "dave.rae", ""),
              ev(2, 1791881731, "", "auth.login_failed", "error", "User", "m.graham", "")};
    check_golden("audit-sample__populated", render_auth_sample(s));
}
