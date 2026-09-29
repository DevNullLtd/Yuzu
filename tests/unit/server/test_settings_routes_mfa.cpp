/**
 * test_settings_routes_mfa.cpp — Route-level coverage for the 5 Settings
 * MFA HTMX routes added by PR1 (and CSRF-gated by the same PR's Hermes
 * round): GET /fragments/settings/mfa, POST /api/settings/mfa/init,
 * POST /api/settings/mfa/verify, POST /api/settings/mfa/recovery-codes,
 * POST /api/settings/mfa/disable.
 *
 * Closes the second half of the quality-engineer Gate 3 SHOULD-FIX that
 * PR1 deferred. Companion to `test_auth_routes_mfa.cpp` — together they
 * are the regression net for the bug class that let Hermes Agent's
 * CRITICAL finding (`/login/mfa` unreachable behind the pre-routing auth
 * gate) ship the first time around.
 *
 * Pattern: register SettingsRoutes against an in-process TestRouteSink,
 * dispatch synthesized requests, assert on response shape, the audit
 * chain (captured via a mock audit_fn), the `Cache-Control: no-store`
 * reveal contract, and the `origin_safe` CSRF gate (host equality after
 * default-port normalisation, userinfo rejection, sanitised audit
 * detail, no-Origin pass-through for non-browser clients).
 *
 * Why in-process and not a real `httplib::Server`: prior fixture pattern
 * spun up a listening server behind a `std::thread` acceptor, which
 * crashes under TSan with no TSan report (#438).
 */

#include "settings_routes.hpp"

#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "runtime_config_store.hpp"
#include "tag_store.hpp"
#include "test_route_sink.hpp"
#include "update_registry.hpp"
#include "../../../server/core/src/totp.hpp"
#include "test_auth_db_pg_helper.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

struct TmpDirGuard {
    fs::path path;
    explicit TmpDirGuard(fs::path p) : path(std::move(p)) { fs::create_directories(path); }
    ~TmpDirGuard() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    TmpDirGuard(const TmpDirGuard&) = delete;
    TmpDirGuard& operator=(const TmpDirGuard&) = delete;
};

/// Single audit call captured by the mock audit_fn. Mirrors the shape in
/// test_settings_routes_users.cpp so a future helper-promotion is
/// mechanical.
struct AuditCall {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
};

/// Mock session state read by the auth_fn / admin_fn closures. Tests
/// switch `session_user` / `session_role` between calls to act as
/// different principals against the same harness.
struct MfaSettingsHarness {
    TmpDirGuard tmp;
    Config cfg{};
    auth::AuthManager auth_mgr{};
    yuzu::test::AuthDbPg auth_db;
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    SettingsRoutes routes;

    yuzu::server::test::TestRouteSink sink;

    std::string session_user;
    auth::Role session_role{auth::Role::admin};
    std::vector<AuditCall> audit_calls;

    MfaSettingsHarness() : tmp(yuzu::test::unique_temp_path("settings-mfa-")) {
        cfg.auth_config_path = tmp.path / "auth.cfg";
        auth_mgr.load_config(cfg.auth_config_path);
        REQUIRE(auth_mgr.upsert_user("admin", "adminpassword1", auth::Role::admin));
        REQUIRE(auth_mgr.upsert_user("bob", "bobpassword12", auth::Role::user));
        // Mirror admin / bob into AuthDB so the MFA accessor surface
        // works (mfa_status / mfa_init_enrollment do is_active reads).
        auto salt = auth::AuthManager::random_bytes(16);
        auto salt_hex = auth::AuthManager::bytes_to_hex(salt);
        REQUIRE(
            auth_db
                ->upsert_user("admin",
                              auth::AuthManager::pbkdf2_sha256("adminpassword1", salt, 100'000),
                              salt_hex, auth::Role::admin)
                .has_value());
        auth_mgr.set_auth_db(auth_db.get());
        session_user = "admin";

        auto auth_fn =
            [this](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
            if (session_user.empty())
                return std::nullopt;
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            return s;
        };
        auto admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            if (session_user.empty() || session_role != auth::Role::admin) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_calls.push_back({action, result, target_type, target_id, detail});
            return true;
        };
        auto gateway_count_fn = []() -> std::size_t { return 0; };
        auto agents_json_fn = []() -> std::string { return "[]"; };

        routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr,
                               auto_approve,
                               /*api_token_store=*/nullptr,
                               /*mgmt_group_store=*/nullptr,
                               /*tag_store=*/nullptr,
                               /*update_registry=*/nullptr,
                               /*runtime_config_store=*/nullptr,
                               /*audit_store=*/nullptr,
                               /*gateway_enabled=*/false, gateway_count_fn, agents_json_fn,
                               oidc_mu, oidc_provider);
    }

    /// True if any captured audit row matches action + result + (optional) target_id.
    bool has_audit(std::string_view action, std::string_view result = {},
                   std::string_view target_id = {}) const {
        for (const auto& a : audit_calls) {
            if (a.action != action)
                continue;
            if (!result.empty() && a.result != result)
                continue;
            if (!target_id.empty() && a.target_id != target_id)
                continue;
            return true;
        }
        return false;
    }

    /// Return the most recent matching audit detail string, or empty.
    std::string audit_detail(std::string_view action) const {
        for (auto it = audit_calls.rbegin(); it != audit_calls.rend(); ++it) {
            if (it->action == action)
                return it->detail;
        }
        return {};
    }
};

/// Convenience: POST with same-origin Origin header so the CSRF gate
/// passes (host equality after default-port normalisation).
std::unique_ptr<httplib::Response>
post_same_origin(yuzu::server::test::TestRouteSink& sink, const std::string& path,
                 const std::string& body = {}) {
    return sink.dispatch("POST", path, body, "application/x-www-form-urlencoded",
                         {{"Host", "yuzu.example"}, {"Origin", "http://yuzu.example"}});
}

} // namespace

TEST_CASE("GET /fragments/settings/mfa renders 'Not enrolled' panel for fresh admin",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    auto res = h.sink.Get("/fragments/settings/mfa");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("Not enrolled") != std::string::npos);
    CHECK(res->body.find("Enable MFA") != std::string::npos);
    // GETs are not CSRF-sensitive — no csrf.denied should fire.
    CHECK_FALSE(h.has_audit("csrf.denied"));
}

TEST_CASE("POST /api/settings/mfa/init reveals secret with Cache-Control: no-store",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    auto res = post_same_origin(h.sink, "/api/settings/mfa/init");
    REQUIRE(res);
    CHECK(res->status == 200);
    // Reveal contract — secret + URI in the body, plus the cache-busting
    // headers added by PR1's set_no_store helper.
    CHECK(res->body.find("otpauth://totp/Yuzu") != std::string::npos);
    CHECK(res->body.find("Base32 secret") != std::string::npos);
    // The provisional reveal now renders the inline SVG QR (#1232 wiring).
    CHECK(res->body.find("<svg") != std::string::npos);
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
    CHECK(res->get_header_value("Pragma") == "no-cache");
    CHECK(res->get_header_value("Referrer-Policy") == "no-referrer");
    CHECK(h.has_audit("mfa.enroll.initiated", "ok", "admin"));
}

TEST_CASE("POST /api/settings/mfa/init twice returns MfaAlreadyEnrolled with operator message",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    // Stand up an enrolled state through the AuthDB directly so the
    // second init hits the "already enrolled" branch.
    auto init = h.auth_db->mfa_init_enrollment("admin", "Yuzu");
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
    REQUIRE(h.auth_db->mfa_verify_enrollment("admin", code).has_value());

    auto res = post_same_origin(h.sink, "/api/settings/mfa/init");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("MFA is already enabled") != std::string::npos);
    CHECK(h.has_audit("mfa.enroll.initiated", "error", "admin"));
}

TEST_CASE("POST /api/settings/mfa/recovery-codes regenerates 10 codes + cache headers",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    // Get into enrolled state via the same path the panel uses
    // server-side.
    auto init = h.auth_db->mfa_init_enrollment("admin", "Yuzu");
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
    REQUIRE(h.auth_db->mfa_verify_enrollment("admin", code).has_value());

    auto res = post_same_origin(h.sink, "/api/settings/mfa/recovery-codes");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
    // Each recovery code is XXXX-XXXX-XXXX-XXXX (19 chars). Look for a
    // representative bullet pattern.
    CHECK(res->body.find("STORE THESE") != std::string::npos);
    CHECK(h.has_audit("mfa.recovery_codes.generated", "ok", "admin"));
}

TEST_CASE("POST /api/settings/mfa/verify on an already-enrolled account audits mfa.enroll.race, "
          "not mfa.enroll.failed (#3777)",
          "[pg][mfa][routes][settings]") {
    // A concurrent verify can win the enrollment race between this operator's
    // init and their verify — mfa_verify_enrollment then returns
    // MfaAlreadyEnrolled (the top-of-function enrolled-state check short-circuits
    // before the code is even examined, so the submitted code's validity is
    // immaterial). That benign race must be audited distinctly (CC7.2), never as
    // mfa.enroll.failed (a bad-code attempt) or a store outage, and must tell the
    // operator the true state. Simulate the winner by enrolling admin out-of-band.
    MfaSettingsHarness h;
    auto init = h.auth_db->mfa_init_enrollment("admin", "Yuzu");
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
    // Concurrent winner: enroll out-of-band, then drive the settings verify route
    // with the same still-valid code the racing operator would have submitted.
    REQUIRE(h.auth_db->mfa_verify_enrollment("admin", code).has_value());

    auto res = post_same_origin(h.sink, "/api/settings/mfa/verify", "code=" + code);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("already enrolled") != std::string::npos);
    // Audited as the benign race, NOT as a rejected code or a verified enrollment,
    // and no store-outage path.
    CHECK(h.has_audit("mfa.enroll.race", "ok", "admin"));
    CHECK_FALSE(h.has_audit("mfa.enroll.failed"));
    CHECK_FALSE(h.has_audit("mfa.enroll.verified"));
}

TEST_CASE("POST /api/settings/mfa/disable clears state + emits mfa.disabled",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    auto init = h.auth_db->mfa_init_enrollment("admin", "Yuzu");
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
    REQUIRE(h.auth_db->mfa_verify_enrollment("admin", code).has_value());

    auto res = post_same_origin(h.sink, "/api/settings/mfa/disable");
    REQUIRE(res);
    CHECK(res->status == 200);
    // After disable, mfa_disabled_at is stamped — the renderer shows the
    // "Disabled" pill (not "Not enrolled") so the operator can tell the
    // difference between "never enrolled" and "explicitly disabled".
    CHECK(res->body.find("Disabled") != std::string::npos);
    CHECK(h.has_audit("mfa.disabled", "ok", "admin"));

    // DB-side: secret cleared + recovery codes deleted (atomic via TxnGuard).
    auto status = h.auth_db->mfa_status("admin");
    REQUIRE(status.has_value());
    CHECK_FALSE(status->enrolled);
    CHECK(status->recovery_codes_remaining == 0);
}

TEST_CASE("POST /api/settings/mfa/disable is blocked for self under enforcement (PR3 invariant)",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    // Enroll admin first.
    auto init = h.auth_db->mfa_init_enrollment("admin", "Yuzu");
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
    REQUIRE(h.auth_db->mfa_verify_enrollment("admin", code).has_value());

    // Turn on enforcement (cfg is held by reference by SettingsRoutes).
    h.cfg.mfa_enforcement = "required";

    auto res = post_same_origin(h.sink, "/api/settings/mfa/disable");
    REQUIRE(res);
    CHECK(res->status == 200); // fragment-with-error convention, not a hard status
    CHECK(res->body.find("required by policy") != std::string::npos);
    // Audit captures the policy block.
    CHECK(h.has_audit("mfa.disabled", "error", "admin"));
    CHECK(h.audit_detail("mfa.disabled").find("blocked: mfa_enforcement=required") !=
          std::string::npos);
    // Crucially, MFA is STILL enrolled — the disable did not take effect.
    auto status = h.auth_db->mfa_status("admin");
    REQUIRE(status.has_value());
    CHECK(status->enrolled);
}

TEST_CASE("POST /api/settings/mfa/disable under admin-only blocks admins but the gate is "
          "role-scoped",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    auto init = h.auth_db->mfa_init_enrollment("admin", "Yuzu");
    REQUIRE(init.has_value());
    auto bytes = mfa::base32_decode(init->secret_base32);
    REQUIRE(bytes.has_value());
    std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
    REQUIRE(h.auth_db->mfa_verify_enrollment("admin", code).has_value());

    h.cfg.mfa_enforcement = "admin-only";
    // Admin (session_role defaults to admin) is protected.
    auto res = post_same_origin(h.sink, "/api/settings/mfa/disable");
    REQUIRE(res);
    CHECK(res->body.find("required by policy") != std::string::npos);
    auto status = h.auth_db->mfa_status("admin");
    REQUIRE(status.has_value());
    CHECK(status->enrolled);
}

TEST_CASE("Non-admin same-origin POST: 403 from admin_fn after origin_safe passes",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    h.session_role = auth::Role::user; // bob
    h.session_user = "bob";
    auto res = post_same_origin(h.sink, "/api/settings/mfa/init");
    REQUIRE(res);
    CHECK(res->status == 403);
    // settings_routes.cpp:4145 calls origin_safe FIRST, then admin_fn_.
    // For a same-origin POST origin_safe returns true (host==origin host)
    // and admin_fn_ then rejects the non-admin session with 403. The
    // assertion is that no csrf.denied audit row is emitted — origin_safe
    // passed, so only the admin denial fires.
    CHECK_FALSE(h.has_audit("csrf.denied"));
}

TEST_CASE("Cross-origin POST is rejected 403 with csrf.denied audit on every MFA route",
          "[pg][mfa][routes][settings]") {
    // qe Gate 3 S-2 follow-up: previously only /disable carried a
    // cross-origin reject case. Each of the 4 mutating MFA routes now
    // has its own assertion so a regression that drops origin_safe from
    // any single one trips a test.
    for (const auto& path : {std::string{"/api/settings/mfa/init"},
                             std::string{"/api/settings/mfa/verify"},
                             std::string{"/api/settings/mfa/recovery-codes"},
                             std::string{"/api/settings/mfa/disable"}}) {
        MfaSettingsHarness h;
        auto res = h.sink.dispatch("POST", path, {}, "application/x-www-form-urlencoded",
                               {{"Host", "yuzu.example"}, {"Origin", "http://evil.com"}});
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->body.find("cross-origin POST refused") != std::string::npos);
        CHECK(h.has_audit("csrf.denied", "error", path));
    }
}

TEST_CASE("Default-port normalisation: Origin :443 matches Host without port",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    auto res =
        h.sink.dispatch("POST", "/api/settings/mfa/init", {}, "application/x-www-form-urlencoded",
                    {{"Host", "yuzu.example"}, {"Origin", "https://yuzu.example:443"}});
    REQUIRE(res);
    // Same host after stripping :443 — passes origin_safe, hits admin_fn
    // (admin session) → ok.
    CHECK(res->status == 200);
    CHECK_FALSE(h.has_audit("csrf.denied"));
}

TEST_CASE("Userinfo (`@`) in Origin is rejected per RFC 6454",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    auto res =
        h.sink.dispatch("POST", "/api/settings/mfa/init", {}, "application/x-www-form-urlencoded",
                    {{"Host", "yuzu.example"}, {"Origin", "http://evil@yuzu.example"}});
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.has_audit("csrf.denied"));
}

TEST_CASE("Non-browser caller with neither Origin nor Referer passes through",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    auto res = h.sink.dispatch("POST", "/api/settings/mfa/init", {}, "application/x-www-form-urlencoded",
                           {{"Host", "yuzu.example"}});
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(h.has_audit("csrf.denied"));
}

TEST_CASE("csrf.denied audit detail captures Origin / Referer / Host for SIEM",
          "[pg][mfa][routes][settings]") {
    // Audit-detail sanitisation (control + high-bit byte stripping +
    // 128 B per-field cap) is implemented as an inline lambda inside
    // SettingsRoutes::register_routes and verified by code review +
    // governance gates 2/4. A route-level test that drives bytes
    // >= 0x80 through `req.set_header` and `req.get_header_value`
    // depends on httplib's header-value handling, which is opaque
    // across versions. We assert the *correctness-relevant* property
    // here — that the detail captures the host mismatch so a SIEM
    // operator can correlate the 403 — and leave the sanitisation
    // property to be locked down by a dedicated unit test on the
    // helper once it's promoted out of the lambda scope.
    MfaSettingsHarness h;
    auto res =
        h.sink.dispatch("POST", "/api/settings/mfa/init", {}, "application/x-www-form-urlencoded",
                        {{"Host", "yuzu.example"}, {"Origin", "http://evil.com"}});
    REQUIRE(res);
    CHECK(res->status == 403);
    auto detail = h.audit_detail("csrf.denied");
    REQUIRE_FALSE(detail.empty());
    // Tightened (security Gate 2 INFO): assert the field-tagged format
    // so a regression that drops `Origin=` / `Host=` keys or flips field
    // order trips this assertion. Loose substring `find("evil.com")`
    // would have passed for any garbled detail string that still
    // contained the literal.
    CHECK(detail.find("Origin=http://evil.com") != std::string::npos);
    CHECK(detail.find("Host=yuzu.example") != std::string::npos);
}

TEST_CASE("Referer fallback also evaluated when Origin is absent",
          "[pg][mfa][routes][settings]") {
    MfaSettingsHarness h;
    auto good =
        h.sink.dispatch("POST", "/api/settings/mfa/init", {}, "application/x-www-form-urlencoded",
                    {{"Host", "yuzu.example"}, {"Referer", "http://yuzu.example/settings"}});
    REQUIRE(good);
    CHECK(good->status == 200);
    CHECK_FALSE(h.has_audit("csrf.denied"));

    MfaSettingsHarness h2;
    auto bad = h2.sink.dispatch("POST", "/api/settings/mfa/init", {}, "application/x-www-form-urlencoded",
                            {{"Host", "yuzu.example"}, {"Referer", "http://evil.com/x"}});
    REQUIRE(bad);
    CHECK(bad->status == 403);
    CHECK(h2.has_audit("csrf.denied"));
}
