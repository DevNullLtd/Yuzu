/// @file test_settings_routes_cert_upload.cpp
///
/// The Settings cert-paste route's on-disk custody of the TLS server PRIVATE
/// key: created owner-only (0600) from the start in a directory the route
/// creates 0700, replacing -- never following -- a pre-planted symlink, and
/// leaving a pre-existing (possibly group-shared) directory's mode alone.
///
/// Drives the real route through TestRouteSink with the cert directory injected
/// (SettingsRoutes::set_cert_dir_for_test), so nothing touches /etc/yuzu. No
/// store is needed. TestRouteSink has no multipart, so the cert-upload route is
/// driven over a loopback httplib::Server (one case); the paste route uses the
/// sink.
///
/// POSIX only: the assertions are mode bits and symlinks, which are advisory
/// (mode) or privileged (symlink) on Windows; the Windows custody is the
/// explicit owner-only DACL in FileKeyProvider (not asserted here).

#include "settings_routes.hpp"

#include "oidc_provider.hpp"
#include "test_route_sink.hpp"
#include "../test_helpers.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <shared_mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

using namespace yuzu::server;
namespace fs = std::filesystem;

namespace {

constexpr const char* kForm = "application/x-www-form-urlencoded";

// `-----BEGIN` / `-----END` markers are all the paste route validates.
constexpr const char* kKeyBody =
    "type=key&content=-----BEGIN+PRIVATE+KEY-----%0Atest-key-bytes%0A-----END+PRIVATE+KEY-----";
constexpr const char* kKeyPem =
    "-----BEGIN PRIVATE KEY-----\ntest-key-bytes\n-----END PRIVATE KEY-----";

struct CertRoutesHarness {
    yuzu::test::TempDir root{"yuzu_test_certup_"};
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    SettingsRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    fs::path cert_dir;
    int success_audits{0}; ///< cert.upload / cert.paste "success" rows

    CertRoutesHarness() {
        cert_dir = root.path / "certs";
        routes.set_cert_dir_for_test(cert_dir);
        auto auth_fn = [](const httplib::Request&, httplib::Response&)
            -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "admin";
            s.role = auth::Role::admin;
            return s;
        };
        auto admin_fn = [](const httplib::Request&, httplib::Response&) { return true; };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&, const std::string&,
                               const std::string&) {
            if ((action == "cert.upload" || action == "cert.paste") && result == "success")
                ++success_audits;
        };
        routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr,
                               auto_approve, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                               /*gateway_enabled=*/false, []() -> std::size_t { return 0; },
                               []() -> std::string { return "[]"; }, oidc_mu, oidc_provider,
                               /*metrics_registry=*/nullptr, /*step_up_fn=*/{},
                               /*audit_read_fn=*/{});
        sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://yuzu.test"}};
    }
};

#ifndef _WIN32
unsigned mode_of(const fs::path& p) {
    struct stat st{};
    REQUIRE(::lstat(p.c_str(), &st) == 0);
    return static_cast<unsigned>(st.st_mode & 07777);
}

std::string slurp(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

/// Current process umask, restored on scope exit; the test sets 0 so a
/// file created with the process default would come out 0666.
struct UmaskGuard {
    mode_t old;
    explicit UmaskGuard(mode_t m) : old(::umask(m)) {}
    ~UmaskGuard() { ::umask(old); }
};
#endif

} // namespace

#ifdef _WIN32
TEST_CASE("cert paste: private key is created owner-only (POSIX modes)",
          "[settings_routes][cert]") {
    SKIP("POSIX mode bits and symlink semantics only; Windows custody is the owner-only "
         "DACL in FileKeyProvider");
}
#else

TEST_CASE("cert paste: key is 0600 and a newly created cert dir is 0700",
          "[settings_routes][cert][posix]") {
    UmaskGuard umask_zero{0}; // process default would otherwise give 0666 / 0777
    CertRoutesHarness h;
    REQUIRE_FALSE(fs::exists(h.cert_dir));

    auto res = h.sink.Post("/api/settings/cert-paste", kKeyBody, kForm);
    REQUIRE(res);
    REQUIRE(res->status == 200);

    const auto key = h.cert_dir / "server-key.pem";
    REQUIRE(fs::is_regular_file(key));
    CHECK(mode_of(key) == 0600);
    CHECK(mode_of(h.cert_dir) == 0700);
    CHECK(slurp(key) == std::string(kKeyPem));
    CHECK(h.cfg.tls_server_key == key);

    // No staging temp left behind.
    std::size_t entries = 0;
    for (const auto& e : fs::directory_iterator(h.cert_dir)) {
        (void)e;
        ++entries;
    }
    CHECK(entries == 1);
}

TEST_CASE("cert paste: a pre-planted symlink at the key path is replaced, never followed",
          "[settings_routes][cert][posix][security]") {
    CertRoutesHarness h;
    REQUIRE(fs::create_directories(h.cert_dir));
    const auto victim = h.root.path / "victim.txt";
    {
        std::ofstream v(victim);
        v << "untouched";
    }
    const auto key = h.cert_dir / "server-key.pem";
    fs::create_symlink(victim, key);

    auto res = h.sink.Post("/api/settings/cert-paste", kKeyBody, kForm);
    REQUIRE(res);
    REQUIRE(res->status == 200);

    CHECK(slurp(victim) == "untouched");   // the link target was not written through
    CHECK_FALSE(fs::is_symlink(key));      // the link itself was replaced
    CHECK(mode_of(key) == 0600);
    CHECK(slurp(key) == std::string(kKeyPem));
}

TEST_CASE("cert paste: an existing loose-mode key is replaced by a 0600 file",
          "[settings_routes][cert][posix]") {
    CertRoutesHarness h;
    REQUIRE(fs::create_directories(h.cert_dir));
    const auto key = h.cert_dir / "server-key.pem";
    {
        std::ofstream k(key);
        k << "old";
    }
    fs::permissions(key, fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read |
                             fs::perms::others_read,
                    fs::perm_options::replace); // 0644
    REQUIRE(mode_of(key) == 0644);

    auto res = h.sink.Post("/api/settings/cert-paste", kKeyBody, kForm);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    CHECK(mode_of(key) == 0600);
    CHECK(slurp(key) == std::string(kKeyPem));
}

TEST_CASE("cert paste: an existing cert directory keeps its mode (cert-group sharing)",
          "[settings_routes][cert][posix]") {
    CertRoutesHarness h;
    REQUIRE(fs::create_directories(h.cert_dir));
    fs::permissions(h.cert_dir,
                    fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec,
                    fs::perm_options::replace); // 0750
    REQUIRE(mode_of(h.cert_dir) == 0750);

    auto res = h.sink.Post("/api/settings/cert-paste", kKeyBody, kForm);
    REQUIRE(res);
    REQUIRE(res->status == 200);
    CHECK(mode_of(h.cert_dir) == 0750);
    CHECK(mode_of(h.cert_dir / "server-key.pem") == 0600);
}

TEST_CASE("cert paste: a failed secure write is a 500 with no config change and no success audit",
          "[settings_routes][cert][posix]") {
    CertRoutesHarness h;
    REQUIRE(fs::create_directories(h.cert_dir));
    // A non-empty directory at the destination makes the final rename fail.
    const auto key = h.cert_dir / "server-key.pem";
    REQUIRE(fs::create_directories(key / "blocker"));

    auto res = h.sink.Post("/api/settings/cert-paste", kKeyBody, kForm);
    REQUIRE(res);
    CHECK(res->status == 500);
    CHECK(h.cfg.tls_server_key.empty());
    CHECK(h.success_audits == 0);
    // No staging temp left behind next to the blocker.
    std::size_t entries = 0;
    for (const auto& e : fs::directory_iterator(h.cert_dir)) {
        (void)e;
        ++entries;
    }
    CHECK(entries == 1);
}

TEST_CASE("cert upload (multipart): key is 0600, new dir 0700, symlink replaced",
          "[settings_routes][cert][posix][security]") {
    UmaskGuard umask_zero{0};
    yuzu::test::TempDir root{"yuzu_test_certupl_"};
    const auto cert_dir = root.path / "certs";
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    SettingsRoutes routes;
    routes.set_cert_dir_for_test(cert_dir);

    httplib::Server svr;
    auto auth_fn = [](const httplib::Request&, httplib::Response&) -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "admin";
        s.role = auth::Role::admin;
        return s;
    };
    auto admin_fn = [](const httplib::Request&, httplib::Response&) { return true; };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) {};
    routes.register_routes(svr, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr, auto_approve,
                           nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                           /*gateway_enabled=*/false, []() -> std::size_t { return 0; },
                           []() -> std::string { return "[]"; }, oidc_mu, oidc_provider,
                           /*metrics_registry=*/nullptr, /*step_up_fn=*/{}, /*audit_read_fn=*/{});

    const int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread th([&svr] { svr.listen_after_bind(); });
    svr.wait_until_ready();
    struct Stop {
        httplib::Server& s;
        std::thread& t;
        ~Stop() {
            s.stop();
            if (t.joinable())
                t.join();
        }
    } stop{svr, th};

    // The cert dir does not exist yet: the first upload creates it.
    httplib::Client cli("127.0.0.1", port);
    // `type` goes in the query string: the handler reads it with req.has_param(), which on
    // this httplib does not see a multipart text field (that is outside this fix).
    httplib::UploadFormDataItems items{
        {"file", kKeyPem, "server-key.pem", "application/x-pem-file"},
    };
    const std::string url = "/api/settings/cert-upload?type=key";
    auto res = cli.Post(url, items);
    REQUIRE(res);
    REQUIRE(res->status == 200);

    const auto key = cert_dir / "server-key.pem";
    CHECK(mode_of(cert_dir) == 0700);
    CHECK(mode_of(key) == 0600);
    CHECK(slurp(key) == kKeyPem);
    CHECK(cfg.tls_server_key == key);

    // Replace the key with a symlink to a victim, upload again: link replaced, victim untouched.
    const auto victim = root.path / "victim.txt";
    {
        std::ofstream v(victim);
        v << "untouched";
    }
    fs::remove(key);
    fs::create_symlink(victim, key);
    auto res2 = cli.Post(url, items);
    REQUIRE(res2);
    REQUIRE(res2->status == 200);
    CHECK(slurp(victim) == "untouched");
    CHECK_FALSE(fs::is_symlink(key));
    CHECK(mode_of(key) == 0600);
}

#endif // _WIN32
