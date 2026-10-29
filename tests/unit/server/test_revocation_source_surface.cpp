/**
 * test_revocation_source_surface.cpp - the revocation-source REST routes
 * (`/api/v1/crypto/revocation-sources`), their MCP twins (`*_revocation_source*`) and the shared
 * RevocationSourceService behind both (ADR-0070 R1, slice 2b-1a).
 *
 * Driven through RbacRoleHarness (test_rbac_admin_surface_harness.hpp) so both transports run
 * off the SAME RbacStore / AuthDB / ApprovalManager and a real RevocationSourceStore; DNS and the
 * server's own addresses are faked (test_revocation_source_fixtures.hpp), so nothing resolves a
 * name. PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset.
 *
 * What is pinned here:
 *   - admin-only in BOTH RBAC states and NOT grantable: a non-admin is refused with every role
 *     shape (a plain user under RBAC off; a custom role holding the securable pair under RBAC
 *     on), a service-scoped token and an MCP-tier bearer on REST are refused;
 *   - registration validation, each refusal, identical words on REST and MCP;
 *   - audit: "no audit row, no mutation" (an injected `attempted` failure leaves no source),
 *     a lost outcome row keeps the change and marks it, a read that cannot be audited returns no
 *     data on REST;
 *   - the shared parts: body cap, A4 envelope, supervised approval, annotations.
 */

#include "mcp_jsonrpc.hpp"
#include "mcp_policy.hpp"
#include "openapi_spec_access.hpp"
#include "revocation_source_admin_gate.hpp"
#include "revocation_source_routes.hpp"
#include "revocation_source_store.hpp"
#include "step_up_policy.hpp"

#include "test_rbac_admin_surface_harness.hpp" // AuditRecord, RbacRoleHarness
#include "test_revocation_source_fixtures.hpp"

// bounded_resolver.hpp defines NOMINMAX / WIN32_LEAN_AND_MEAN itself before winsock2.h; those are
// no-ops if an earlier header (the harness above) already included windows.h, so order is not
// load-bearing for it, but it stays after the project headers that might.
#include "bounded_resolver.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <future>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <string>
#include <vector>

using namespace yuzu::server;
using Catch::Matchers::ContainsSubstring;
using nlohmann::json;
namespace rs = yuzu::server::revocation_source;

namespace {

constexpr const char* kBase = "/api/v1/crypto/revocation-sources";
constexpr const char* kRegister = "register_revocation_source";
constexpr const char* kUpdate = "update_revocation_source";
constexpr const char* kRemove = "remove_revocation_source";
constexpr const char* kReset = "reset_revocation_source_high_water";
constexpr const char* kList = "list_revocation_sources";
constexpr const char* kGet = "get_revocation_source";

struct Fx {
    RbacRoleHarness h;
    RevocationSourceStore store{h.auth_db.pool()};
    rs::RevocationSourceService svc;
    RevocationSourceRoutes routes;
    // A predicate returning FALSE denies the (securable, operation) pair at the permission gate.
    // Left empty, the securable gate PASSES: every refusal below is therefore the administrator
    // predicate's alone (the property under test: the securable is not enough).
    std::function<bool(const std::string&, const std::string&)> perm_deny;
    // MFA step-up seam: unset = pass-through. Records every action label the routes passed.
    std::function<bool(httplib::Response&)> step_up_refuses;
    std::vector<std::string> step_up_actions;

    explicit Fx(rs::EgressEnv env = rstest::fake_env(rstest::default_dns()))
        : svc(store, std::move(env)) {
        REQUIRE(store.is_open());
        RevocationSourceRoutes::Deps d;
        d.auth_fn = [this](const httplib::Request&, httplib::Response&)
            -> std::optional<yuzu::server::auth::Session> {
            if (!h.auth_enabled)
                return std::nullopt;
            yuzu::server::auth::Session s;
            s.username = h.session_user;
            s.token_scope_service = h.session_token_scope_service;
            s.principal_kind = h.session_principal_kind;
            s.auth_source = h.session_auth_source;
            s.mcp_tier = h.rest_session_mcp_tier;
            return s;
        };
        d.audit_fn = [this](const httplib::Request&, const std::string& action,
                            const std::string& result, const std::string& target_type,
                            const std::string& target_id, const std::string& detail) {
            h.audit_log.push_back({action, result, target_id, detail, target_type});
            return h.audit_persists(result);
        };
        d.perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string& t,
                           const std::string& o) {
            if (perm_deny && perm_deny(t, o)) {
                res.status = 403;
                res.set_content(R"({"error":"forbidden"})", "application/json");
                return false;
            }
            return true;
        };
        d.admin_fn = [this](const yuzu::server::auth::Session& s, bool is_write) {
            return rs::decide_admin(s, h.auth_db.get(), h.rbac.get(), RbacAdminSurface::kRest,
                                    is_write);
        };
        d.step_up_fn = [this](const httplib::Request&, httplib::Response& res,
                              const yuzu::server::auth::Session&, const std::string& action) {
            step_up_actions.push_back(action);
            return !step_up_refuses || !step_up_refuses(res);
        };
        d.service = &svc;
        routes.register_routes(h.sink, std::move(d));
        h.mcp.set_revocation_source_service(&svc);
    }

    /// The caller is a durable administrator under the named regime.
    void admin(bool rbac_on) { h.make_caller_admin(rbac_on); }

    /// The caller is a plain `user`-role local account.
    void plain_user(bool rbac_on) {
        REQUIRE(h.auth_db->upsert_user(h.session_user, "hash", "salt", yuzu::server::auth::Role::user)
                    .has_value());
        if (rbac_on) {
            h.rbac->set_rbac_enabled(true);
            REQUIRE(h.rbac->assign_role({"user", h.session_user, "Viewer"}).has_value());
        }
    }

    /// A custom role granted BOTH securable operations, held by the caller, RBAC on.
    void custom_role_holder() {
        REQUIRE(h.auth_db->upsert_user(h.session_user, "hash", "salt", yuzu::server::auth::Role::user)
                    .has_value());
        REQUIRE(h.rbac->create_role({"RevCustom", "d", false, 0}).has_value());
        REQUIRE(h.rbac->set_permission({"RevCustom", "RevocationSource", "Write", "allow"}).has_value());
        REQUIRE(h.rbac->set_permission({"RevCustom", "RevocationSource", "Read", "allow"}).has_value());
        REQUIRE(h.rbac->assign_role({"user", h.session_user, "RevCustom"}).has_value());
        h.rbac->set_rbac_enabled(true);
        // The premise: the securable alone WOULD admit this caller.
        REQUIRE(h.rbac->role_permission_allowed_checked("RevCustom", "RevocationSource", "Write")
                    .value_or(false));
    }

    json post_body() { return rstest::valid_body(); }

    auto rest_post(const json& b) { return h.sink.Post(kBase, b.dump()); }
    /// PUT. The body must carry expected_config_version (REQUIRED on REST); when a test did not
    /// set one, the stored version is read and supplied, so the case under test stays about
    /// what it names. `rest_put_raw` sends the body exactly as given.
    auto rest_put_raw(std::int64_t id, const json& b) {
        return h.sink.Put(std::string(kBase) + "/" + std::to_string(id), b.dump());
    }
    auto rest_put(std::int64_t id, json b) {
        if (b.is_object() && !b.contains("expected_config_version")) {
            const auto cur = store.get(id);
            b["expected_config_version"] = cur ? cur->config_version : 1;
        }
        return rest_put_raw(id, b);
    }
    auto rest_get(std::int64_t id) { return h.sink.Get(std::string(kBase) + "/" + std::to_string(id)); }
    auto rest_delete(std::int64_t id) {
        return h.sink.Delete(std::string(kBase) + "/" + std::to_string(id));
    }
    auto rest_reset(std::int64_t id, const std::string& body = "{}") {
        return h.sink.Post(std::string(kBase) + "/" + std::to_string(id) + "/reset-high-water", body);
    }

    /// Register a source straight through the service (setup that is not under test).
    std::int64_t seed(const std::string& cn = "Seeded CA") {
        auto r = svc.register_source(rstest::valid_body(cn), "seeder");
        REQUIRE(r.has_value());
        return r->id;
    }

    std::vector<AuditRecord> rows(const std::string& action) const {
        std::vector<AuditRecord> out;
        for (const auto& r : h.audit_log)
            if (r.action == action)
                out.push_back(r);
        return out;
    }
    std::vector<std::string> results(const std::string& action) const {
        std::vector<std::string> out;
        for (const auto& r : rows(action))
            out.push_back(r.result);
        return out;
    }
};

json data_of(const httplib::Response& r) {
    const auto j = json::parse(r.body, nullptr, false);
    REQUIRE_FALSE(j.is_discarded());
    return j;
}

std::string error_message(const httplib::Response& r) {
    const auto j = data_of(r);
    REQUIRE(j.contains("error"));
    return j["error"].value("message", "");
}

// The MCP tool result payload (structuredContent / text) for a success.
json mcp_payload(const httplib::Response& r) {
    const auto j = json::parse(r.body, nullptr, false);
    REQUIRE_FALSE(j.is_discarded());
    REQUIRE(j.contains("result"));
    const auto& res = j["result"];
    if (res.contains("structuredContent"))
        return res["structuredContent"];
    REQUIRE(res.contains("content"));
    return json::parse(res["content"][0]["text"].get<std::string>());
}

int mcp_error_code(const httplib::Response& r) {
    const auto j = json::parse(r.body, nullptr, false);
    REQUIRE_FALSE(j.is_discarded());
    REQUIRE(j.contains("error"));
    return j["error"]["code"].get<int>();
}

std::string mcp_error_message(const httplib::Response& r) {
    const auto j = json::parse(r.body, nullptr, false);
    REQUIRE_FALSE(j.is_discarded());
    REQUIRE(j.contains("error"));
    return j["error"].value("message", "");
}

} // namespace

// ═════════════════════════════════════════════════════════════════════════════════════════════
// Service: registration validation. Each refusal, with the exact parameter it names.
// ═════════════════════════════════════════════════════════════════════════════════════════════

namespace {
// Validate through the service and return the error (REQUIREs it is one).
rs::ServiceError refused(Fx& fx, const json& body) {
    const auto v = fx.svc.validate_registration(body);
    REQUIRE_FALSE(v.has_value());
    CHECK(v.error().kind == rs::ServiceError::Kind::kInvalidParams);
    return v.error();
}
json with_url(const std::string& url, std::vector<std::string> confirmed = {"public"}) {
    auto b = rstest::valid_body();
    b["crl_urls"] = json::array({rstest::url_entry(url, std::move(confirmed))});
    return b;
}
} // namespace

TEST_CASE("revocation source validation: the body shape", "[revocation_source][pg]") {
    Fx fx;
    CHECK(refused(fx, json::array()).param.empty());
    {
        auto b = rstest::valid_body();
        b["surprise"] = 1;
        CHECK(refused(fx, b).param == "surprise");
    }
    for (const char* key : {"name", "ca_certificates", "crl_urls"}) {
        auto b = rstest::valid_body();
        b.erase(key);
        INFO("missing " << key);
        CHECK(refused(fx, b).param == key);
    }
    {
        auto b = rstest::valid_body();
        b["name"] = "";
        CHECK(refused(fx, b).param == "name");
        b["name"] = std::string(129, 'n');
        CHECK(refused(fx, b).param == "name");
        b["name"] = std::string("line\nbreak");
        CHECK(refused(fx, b).param == "name");
        b["name"] = 7;
        CHECK(refused(fx, b).param == "name");
        // Exactly 128 bytes is accepted.
        b["name"] = std::string(128, 'n');
        CHECK(fx.svc.validate_registration(b).has_value());
    }
}

TEST_CASE("revocation source validation: the CA certificates", "[revocation_source][pg]") {
    Fx fx;
    const std::string good = rstest::make_ca_pem();
    {
        auto b = rstest::valid_body();
        b["ca_certificates"] = json::array();
        CHECK(refused(fx, b).param == "ca_certificates");
        b["ca_certificates"] = json::array({good, good, good, good, good, good, good, good, good});
        CHECK(refused(fx, b).param == "ca_certificates"); // nine
        b["ca_certificates"] = "not an array";
        CHECK(refused(fx, b).param == "ca_certificates");
    }
    struct Case {
        const char* what;
        std::string pem;
        const char* reason; ///< a substring of the refusal's message: the REASON, not just the param
    };
    const std::vector<Case> cases = {
        {"empty string", "", "bytes"},
        {"garbage", "this is not a certificate", "one PEM CERTIFICATE block"},
        {"a private key block", rstest::make_key_pem(), "one PEM CERTIFICATE block"},
        {"truncated PEM", good.substr(0, good.size() / 2), "not a parseable PEM certificate"},
        {"two certificates in one string", good + rstest::make_ca_pem(), "exactly one certificate"},
        {"leading text before the block", "Bag Attributes\n" + good, "one PEM CERTIFICATE block"},
        {"trailing text after the block", good + "trailing", "exactly one certificate"},
        {"not a CA (cA:FALSE)", rstest::make_ca_pem({.ca = false}), "not a CA certificate"},
        {"key usage without cRLSign", rstest::make_ca_pem({.key_usage = "critical,keyCertSign"}),
         "without cRLSign"},
        {"over the size cap", std::string(rs::kMaxPemBytes + 1, 'A'), "bytes"},
    };
    for (const auto& c : cases) {
        INFO(c.what);
        auto b = rstest::valid_body();
        b["ca_certificates"] = json::array({c.pem});
        const auto e = refused(fx, b);
        CHECK(e.param == "ca_certificates[0]");
        CHECK_THAT(e.message, ContainsSubstring(c.reason));
    }
    {
        auto b = rstest::valid_body();
        b["ca_certificates"] = json::array({7});
        CHECK(refused(fx, b).param == "ca_certificates[0]");
    }
    // A CA with NO key usage extension is accepted (cRLSign is required only if the extension exists).
    {
        auto b = rstest::valid_body();
        b["ca_certificates"] = json::array({rstest::make_ca_pem({.key_usage = nullptr})});
        CHECK(fx.svc.validate_registration(b).has_value());
    }
    // One subject Name across the set: a different CN is refused, naming the offender...
    {
        auto b = rstest::valid_body();
        b["ca_certificates"] =
            json::array({rstest::make_ca_pem({.cn = "CA One"}), rstest::make_ca_pem({.cn = "CA Two"})});
        CHECK(refused(fx, b).param == "ca_certificates[1]");
    }
    // ...the same certificate twice is refused...
    {
        auto b = rstest::valid_body();
        b["ca_certificates"] = json::array({good, good});
        CHECK(refused(fx, b).param == "ca_certificates[1]");
    }
    // ...and two keys of ONE subject (a renewal) are accepted, with a distinct SPKI each.
    {
        auto b = rstest::valid_body();
        b["ca_certificates"] =
            json::array({rstest::make_ca_pem({.cn = "Renewed CA"}), rstest::make_ca_pem({.cn = "Renewed CA"})});
        const auto v = fx.svc.validate_registration(b);
        REQUIRE(v.has_value());
        REQUIRE(v->keys.size() == 2);
        CHECK(v->keys[0].spki_sha256 != v->keys[1].spki_sha256);
        CHECK(v->keys[0].cert_sha256.size() == 64);
        CHECK(v->keys[0].ski.has_value());
        CHECK(v->ca_subject_name_sha256.size() == 64);
    }
}

TEST_CASE("revocation source validation: URL syntax", "[revocation_source][pg]") {
    Fx fx;
    {
        auto b = rstest::valid_body();
        b["crl_urls"] = json::array();
        CHECK(refused(fx, b).param == "crl_urls");
        json nine = json::array();
        for (int i = 0; i < 9; ++i)
            nine.push_back(rstest::url_entry("http://crl.example.com/" + std::to_string(i), {"public"}));
        b["crl_urls"] = nine;
        CHECK(refused(fx, b).param == "crl_urls");
        b["crl_urls"] = json::array({"http://crl.example.com/a.crl"}); // a bare string
        CHECK(refused(fx, b).param == "crl_urls[0]");
        b["crl_urls"] = json::array({json{{"url", "http://crl.example.com/"}, {"extra", 1}}});
        CHECK(refused(fx, b).param == "extra");
        b["crl_urls"] = json::array({json{{"url", 7}}});
        CHECK(refused(fx, b).param == "crl_urls[0].url");
        b["crl_urls"] = json::array({json::object()});
        CHECK(refused(fx, b).param == "crl_urls[0].url");
    }
    const std::vector<std::pair<const char*, std::string>> bad = {
        {"file scheme", "file:///etc/passwd"},
        {"ftp scheme", "ftp://crl.example.com/a.crl"},
        {"ldap scheme", "ldap://crl.example.com/cn=ca"},
        {"UNC", "\\\\crl.example.com\\share\\a.crl"},
        {"no scheme", "crl.example.com/a.crl"},
        {"no host", "http:///a.crl"},
        {"userinfo", "http://user:pw@crl.example.com/a.crl"},
        {"userinfo, name only", "http://user@crl.example.com/a.crl"},
        {"fragment", "http://crl.example.com/a.crl#frag"},
        {"too long", "http://crl.example.com/" + std::string(2048, 'a')},
        {"non-ASCII host", "http://crl.exämple.com/a.crl"},
        {"non-ASCII path", "http://crl.example.com/ä.crl"},
        {"a space", "http://crl.example.com/a b.crl"},
        {"a backslash", "http://crl.example.com\\a.crl"},
        {"a control character", std::string("http://crl.example.com/a\x01.crl")},
        {"port 0", "http://crl.example.com:0/a.crl"},
        {"port 65536", "http://crl.example.com:65536/a.crl"},
        {"port not numeric", "http://crl.example.com:80x/a.crl"},
        {"empty port", "http://crl.example.com:/a.crl"},
        {"empty label", "http://crl..example.com/a.crl"},
        {"leading dot", "http://.crl.example.com/a.crl"},
        {"unterminated IPv6", "http://[2001:db8::1/a.crl"},
        {"IPv6 without brackets", "http://2001:db8::1/a.crl"},
        {"IPv6 with a zone", "http://[fe80::1%25eth0]/a.crl"},
        {"invalid IPv6", "http://[not:an:address]/a.crl"},
    };
    for (const auto& [what, url] : bad) {
        INFO(what);
        const auto e = refused(fx, with_url(url));
        CHECK(e.param == "crl_urls[0].url");
    }
    // A duplicate URL.
    {
        auto b = rstest::valid_body();
        b["crl_urls"] = json::array({rstest::url_entry("http://crl.example.com/a.crl", {"public"}),
                                     rstest::url_entry("http://crl.example.com/a.crl", {"public"})});
        CHECK(refused(fx, b).param == "crl_urls[1].url");
    }
    // Accepted: an https URL, a port, an uppercase scheme/host (stored host lowercased), a query,
    // exactly 2048 bytes.
    {
        const auto v = fx.svc.validate_registration(with_url("HTTPS://CRL.Example.COM:8443/a.crl?x=1"));
        REQUIRE(v.has_value());
        CHECK(v->urls[0].host == "crl.example.com");
        const std::string max = "http://crl.example.com/" + std::string(2048 - 23, 'a');
        REQUIRE(max.size() == 2048);
        CHECK(fx.svc.validate_registration(with_url(max)).has_value());
    }
}

TEST_CASE("revocation source validation: refused address classes, no override",
          "[revocation_source][pg]") {
    Fx fx;
    struct Case {
        const char* what;
        std::string url;
    };
    const std::vector<Case> cases = {
        {"loopback literal", "http://127.0.0.1/a.crl"},
        {"loopback IPv6 literal", "http://[::1]/a.crl"},
        {"a name resolving to loopback (127.1)", "http://shorthand.example.com/a.crl"},
        {"a numeric shorthand the resolver reads as loopback", "http://127.1/a.crl"},
        {"cloud metadata literal", "http://169.254.169.254/latest/"},
        {"a name resolving to cloud metadata", "http://metadata.example.com/"},
        {"link-local literal", "http://169.254.1.1/a.crl"},
        {"link-local with a zone", "http://zone.example.com/a.crl"},
        {"unspecified literal", "http://0.0.0.0/a.crl"},
        {"a name resolving to unspecified", "http://unspecified.example.com/"},
        {"multicast literal", "http://224.0.0.1/a.crl"},
        {"reserved literal", "http://240.0.0.1/a.crl"},
        {"IPv4-mapped IPv6 loopback", "http://[::ffff:127.0.0.1]/a.crl"},
        {"IPv4-mapped IPv6 metadata", "http://[::ffff:169.254.169.254]/a.crl"},
        {"a mixed answer: public plus loopback", "http://mixed-loop.example.com/a.crl"},
        {"the server's own address (literal)", std::string("http://") + rstest::kOwnAddress + "/a.crl"},
        {"a name resolving to the server's own address", "http://self.example.com/a.crl"},
        {"the server's own address, IPv4-mapped", "http://mapped-self.example.com/a.crl"},
        {"the server's own address as a mapped literal", "http://[::ffff:10.9.9.9]/a.crl"},
    };
    for (const auto& c : cases) {
        INFO(c.what);
        // Confirming EVERY confirmable class never opens a refused one.
        auto b = with_url(c.url, {"public", "private", "carrier-grade-nat", "unique-local", "non-global"});
        const auto e = refused(fx, b);
        CHECK(e.param == "crl_urls[0].url");
        CHECK_THAT(e.message, ContainsSubstring("always refused"));
    }
    // A name that does not resolve.
    const auto e = refused(fx, with_url("http://nxdomain.example.com/a.crl"));
    CHECK(e.param == "crl_urls[0].url");
    CHECK_THAT(e.message, ContainsSubstring("does not resolve"));
}

TEST_CASE("revocation source validation: a wildcard bind expands to every local address",
          "[revocation_source][pg]") {
    // The production environment builder, with the resolver faked: a wildcard listener makes
    // every interface address "own". The interface list is the host's, so this asserts only the
    // properties that hold on any host: a listener with a LITERAL address names exactly it.
    auto env = rs::make_system_egress_env({"10.9.9.9:50051", "[2001:db8::7]:8080"});
    const auto own_opt = env.local_addresses(std::chrono::seconds(5));
    REQUIRE(own_opt.has_value());
    const auto& own = *own_opt;
    CHECK(std::count(own.begin(), own.end(), "10.9.9.9") == 1);
    CHECK(std::count(own.begin(), own.end(), "2001:db8::7") == 1);
    // A wildcard listener contributes at least the loopback interface of any host.
    auto wild = rs::make_system_egress_env({"0.0.0.0:50051"});
    const auto all = wild.local_addresses(std::chrono::seconds(5));
    REQUIRE(all.has_value());
    CHECK_FALSE(all->empty());
    auto wild6 = rs::make_system_egress_env({"[::]:50051"});
    REQUIRE(wild6.local_addresses(std::chrono::seconds(5)).has_value());
    CHECK_FALSE(wild6.local_addresses(std::chrono::seconds(5))->empty());
    // A disabled listener (empty spec) contributes nothing and is NOT a wildcard.
    auto disabled = rs::make_system_egress_env({"", "10.9.9.9:1"});
    REQUIRE(disabled.local_addresses(std::chrono::seconds(5)).has_value());
    CHECK(*disabled.local_addresses(std::chrono::seconds(5)) == std::vector<std::string>{"10.9.9.9"});
    // A listen host that does not resolve makes the set unknown: nullopt, never "fewer".
    auto unresolvable = rs::make_system_egress_env({"nonexistent-host.invalid:1"});
    CHECK_FALSE(unresolvable.local_addresses(std::chrono::seconds(5)).has_value());
}

TEST_CASE("revocation source validation: address classes are shown, then confirmed",
          "[revocation_source][pg]") {
    Fx fx;
    // Unconfirmed: the 400 names the classes the host resolves to and the list to resend.
    {
        const auto e = refused(fx, with_url("http://pki.corp.example/a.crl", {}));
        CHECK(e.param == "crl_urls[0].confirmed_address_classes");
        CHECK_THAT(e.message, ContainsSubstring("private"));
        CHECK_THAT(e.message, ContainsSubstring("confirmed_address_classes"));
    }
    // Confirmed: accepted and stored sorted.
    {
        const auto v = fx.svc.validate_registration(with_url("http://pki.corp.example/a.crl", {"private"}));
        REQUIRE(v.has_value());
        CHECK(v->urls[0].confirmed_address_classes == std::vector<std::string>{"private"});
    }
    // The wrong class confirmed does not satisfy it.
    {
        const auto e = refused(fx, with_url("http://pki.corp.example/a.crl", {"public"}));
        CHECK(e.param == "crl_urls[0].confirmed_address_classes");
    }
    // A mixed answer needs every class confirmed.
    {
        CHECK(refused(fx, with_url("http://dual.example.com/a.crl", {"public"})).param ==
              "crl_urls[0].confirmed_address_classes");
        const auto v = fx.svc.validate_registration(with_url("http://dual.example.com/a.crl", {"private", "public"}));
        REQUIRE(v.has_value());
        CHECK(v->urls[0].confirmed_address_classes == std::vector<std::string>{"private", "public"});
    }
    // An IPv6 public literal and a public IPv6 name.
    CHECK(fx.svc.validate_registration(with_url("http://[2606:2800:220:1:248:1893:25c8:1946]/a.crl")).has_value());
    CHECK(fx.svc.validate_registration(with_url("http://v6.example.com/a.crl")).has_value());
    // A class name outside the closed list, including the refused ones, is refused as a value.
    for (const char* c : {"loopback", "link-local", "cloud-metadata", "Public", "", "*"}) {
        INFO("class " << c);
        CHECK(refused(fx, with_url("http://crl.example.com/a.crl", {c})).param ==
              "crl_urls[0].confirmed_address_classes");
    }
    {
        auto b = rstest::valid_body();
        b["crl_urls"] = json::array({json{{"url", "http://crl.example.com/a.crl"},
                                          {"confirmed_address_classes", "public"}}});
        CHECK(refused(fx, b).param == "crl_urls[0].confirmed_address_classes");
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════
// REST routes
// ═════════════════════════════════════════════════════════════════════════════════════════════

TEST_CASE("revocation source REST: the lifecycle as an administrator, RBAC off",
          "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);

    auto created = fx.rest_post(fx.post_body());
    REQUIRE(created);
    REQUIRE(created->status == 201);
    CHECK(created->get_header_value("Cache-Control") == "no-store, private");
    const auto src = data_of(*created)["data"];
    const std::int64_t id = src["id"].get<std::int64_t>();
    CHECK(created->get_header_value("Location") == std::string(kBase) + "/" + std::to_string(id));
    CHECK(src["name"] == "Corp issuing CA");
    CHECK(src["config_version"] == 1);
    CHECK(src["created_by"] == "admin");
    CHECK(src["crl_status"] == "no_crl_fetched");
    REQUIRE(src["ca_certificates"].size() == 1);
    CHECK(src["ca_certificates"][0]["cert_sha256"].get<std::string>().size() == 64);
    CHECK(src["ca_certificates"][0]["spki_sha256"].get<std::string>().size() == 64);
    REQUIRE(src["crl_urls"].size() == 1);
    CHECK(src["crl_urls"][0]["confirmed_address_classes"] == json::array({"public"}));
    // Fetch status is present and reads "never fetched" (the fetcher ships in 2b-1b).
    CHECK(src["crl_urls"][0]["fetch_status"]["state"] == "never_fetched");
    CHECK(src["crl_urls"][0]["fetch_status"]["last_attempt_at"].is_null());
    CHECK(src["crl_urls"][0]["fetch_status"]["last_failure_cause"].is_null());
    // No DER and no key material is ever served.
    CHECK(created->body.find("cert_der") == std::string::npos);

    // list
    auto list = fx.h.sink.Get(kBase);
    REQUIRE(list);
    REQUIRE(list->status == 200);
    const auto ld = data_of(*list)["data"];
    CHECK(ld["total"] == 1);
    CHECK(ld["max_sources"] == 64);
    CHECK(ld["crl_past_next_update"] == 0);
    CHECK(ld["sources"].size() == 1);

    // get
    auto got = fx.rest_get(id);
    REQUIRE(got->status == 200);
    CHECK(data_of(*got)["data"]["id"] == id);

    // PUT with a NEW key of the same subject (a CA renewal): a real change, version bumped.
    auto changed_put = fx.rest_put(id, fx.post_body());
    REQUIRE(changed_put);
    CHECK(changed_put->status == 200);
    const auto upd = data_of(*changed_put)["data"];
    CHECK(upd["changed"] == true);
    CHECK(upd["config_version"] == 2);
    CHECK(upd["dropped_ca_certificates"] == 1);

    // reset-high-water: default now, echoes the window.
    auto reset = fx.rest_reset(id);
    REQUIRE(reset->status == 200);
    const auto rd = data_of(*reset)["data"];
    CHECK(rd["crls_deleted"] == 0);
    CHECK(rd["reset_at"].get<std::string>().size() == 20);
    CHECK(rd["replay_window_opens_at"] == rd["reset_at"]);

    // delete, then a repeat is a 404
    auto del = fx.rest_delete(id);
    REQUIRE(del->status == 200);
    CHECK(data_of(*del)["data"]["removed"] == true);
    CHECK(fx.rest_delete(id)->status == 404);
    CHECK(fx.rest_get(id)->status == 404);
}

TEST_CASE("revocation source REST: an equal PUT changes nothing", "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);
    // Register with a fixed body, then PUT the byte-identical body.
    const json body = fx.post_body();
    auto created = fx.rest_post(body);
    REQUIRE(created->status == 201);
    const auto id = data_of(*created)["data"]["id"].get<std::int64_t>();
    auto same = fx.rest_put(id, body);
    REQUIRE(same->status == 200);
    const auto d = data_of(*same)["data"];
    CHECK(d["changed"] == false);
    CHECK(d["config_version"] == 1);
    CHECK(d["dropped_urls"] == 0);
}

TEST_CASE("revocation source REST: the lifecycle as an administrator, RBAC on",
          "[revocation_source][pg]") {
    Fx fx;
    fx.admin(true);
    auto created = fx.rest_post(fx.post_body());
    REQUIRE(created->status == 201);
    const auto id = data_of(*created)["data"]["id"].get<std::int64_t>();
    CHECK(fx.h.sink.Get(kBase)->status == 200);
    CHECK(fx.rest_get(id)->status == 200);
    CHECK(fx.rest_reset(id)->status == 200);
    CHECK(fx.rest_delete(id)->status == 200);
}

TEST_CASE("revocation source REST: a second registration of the CA is a 409 naming the first",
          "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);
    json a = rstest::valid_body("Same CA");
    auto first = fx.rest_post(a);
    REQUIRE(first->status == 201);
    const auto id = data_of(*first)["data"]["id"].get<std::int64_t>();
    auto second = fx.rest_post(rstest::valid_body("Same CA")); // a new key, the SAME subject
    REQUIRE(second->status == 409);
    CHECK(data_of(*second)["error"]["code"] == 409);
    CHECK_THAT(data_of(*second)["error"]["remediation"].get<std::string>(),
               ContainsSubstring(std::string(kBase) + "/" + std::to_string(id)));
    CHECK(fx.store.list()->size() == 1);
}

TEST_CASE("revocation source REST: errors are the A4 envelope", "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);
    // 400: invalid params names the parameter in the remediation
    auto bad = fx.rest_post(json{{"name", "x"}});
    REQUIRE(bad->status == 400);
    const auto e = data_of(*bad)["error"];
    CHECK(e["code"] == 400);
    CHECK(e.contains("correlation_id"));
    CHECK(e["retry_after_ms"].is_null());
    CHECK_THAT(e["remediation"].get<std::string>(), ContainsSubstring("ca_certificates"));
    // 400: not JSON
    CHECK(fx.h.sink.Post(kBase, "{not json")->status == 400);
    // 404: unknown id, on every id route
    CHECK(fx.rest_get(999)->status == 404);
    CHECK(fx.rest_put(999, fx.post_body())->status == 404);
    CHECK(fx.rest_delete(999)->status == 404);
    CHECK(fx.rest_reset(999)->status == 404);
    // 413: over the 128 KiB cap
    CHECK(fx.h.sink.Post(kBase, std::string(rs::kBodyMaxBytes + 1, ' '))->status == 413);
    // 400: reset body must be an object with only reset_at
    const auto id = fx.seed();
    CHECK(fx.rest_reset(id, R"({"surprise":1})")->status == 400);
    CHECK(fx.rest_reset(id, R"({"reset_at":"yesterday"})")->status == 400);
    CHECK(fx.rest_reset(id, R"({"reset_at":"2999-01-01T00:00:00Z"})")->status == 400); // later than now
    CHECK(fx.rest_reset(id, "[1]")->status == 400);
    CHECK(fx.rest_reset(id, "")->status == 200); // an empty body is `{}`
    CHECK(fx.rest_reset(id, R"({"reset_at":"2020-01-02T03:04:05Z"})")->status == 200);
}

TEST_CASE("revocation source REST: a degraded store is a 503 with a retry hint, never empty",
          "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);
    fx.seed();
    fx.store.set_acquire_timeout_for_test(std::chrono::milliseconds(50));
    // Hold every pooled connection.
    std::vector<yuzu::server::pg::PgPool::Lease> held;
    for (int i = 0; i < 8; ++i) {
        auto l = fx.h.auth_db.pool().try_acquire_for(std::chrono::milliseconds(20));
        if (!l)
            break;
        held.push_back(std::move(l));
    }
    auto list = fx.h.sink.Get(kBase);
    REQUIRE(list);
    CHECK(list->status == 503);
    CHECK(data_of(*list)["error"]["retry_after_ms"] == 5000);
    CHECK(data_of(*list).contains("data") == false);
}

// ─── admin-only in BOTH RBAC states, not grantable ───────────────────────────────────────────

namespace {
// Every route, with the caller refused: the bodies a probe would send. Asserts the status and
// that nothing was mutated.
void check_all_routes_refused(Fx& fx, int expected_status, std::int64_t seeded_id) {
    const auto before = fx.store.list();
    REQUIRE(before.has_value());
    CHECK(fx.h.sink.Get(kBase)->status == expected_status);
    CHECK(fx.rest_get(seeded_id)->status == expected_status);
    CHECK(fx.rest_post(fx.post_body())->status == expected_status);
    CHECK(fx.rest_put(seeded_id, fx.post_body())->status == expected_status);
    CHECK(fx.rest_delete(seeded_id)->status == expected_status);
    CHECK(fx.rest_reset(seeded_id)->status == expected_status);
    const auto after = fx.store.list();
    REQUIRE(after.has_value());
    CHECK(after->size() == before->size());
    CHECK(after->front().config_version == before->front().config_version);
}
} // namespace

TEST_CASE("revocation source REST: RBAC off, a non-admin is refused on every route",
          "[revocation_source][pg]") {
    Fx fx;
    const auto id = fx.seed();
    fx.plain_user(false);
    check_all_routes_refused(fx, 403, id);
    // A denial is audited, not silent.
    CHECK_FALSE(fx.rows("crypto.revocation_source.list").empty());
    CHECK(fx.results("crypto.revocation_source.list").front() == "denied");
}

TEST_CASE("revocation source REST: RBAC on, a plain role holder is refused on every route",
          "[revocation_source][pg]") {
    Fx fx;
    const auto id = fx.seed();
    fx.plain_user(true);
    check_all_routes_refused(fx, 403, id);
}

TEST_CASE("revocation source REST: RBAC on, a custom role GRANTED the securable is still refused",
          "[revocation_source][pg]") {
    // The securable gate passes (perm_deny empty) and the role holds RevocationSource:Read and
    // :Write, yet every route refuses: the surface is admin-only in both RBAC states and so not
    // grantable.
    Fx fx;
    const auto id = fx.seed();
    fx.custom_role_holder();
    check_all_routes_refused(fx, 403, id);
}

TEST_CASE("revocation source REST: a service-scoped token and an MCP-tier bearer are refused",
          "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);
    const auto id = fx.seed();
    fx.h.session_token_scope_service = "payments";
    check_all_routes_refused(fx, 403, id);
    fx.h.session_token_scope_service.clear();
    // REST carries no maker-checker flow: a bearer of ANY MCP tier is refused, even one held by
    // an administrator.
    for (const char* tier : {"readonly", "operator", "supervised"}) {
        INFO("tier " << tier);
        fx.h.rest_session_mcp_tier = tier;
        check_all_routes_refused(fx, 403, id);
    }
}

TEST_CASE("revocation source REST: the securable gate is consulted with Read or Write",
          "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);
    const auto id = fx.seed();
    std::vector<std::string> asked;
    fx.perm_deny = [&](const std::string& t, const std::string& o) {
        asked.push_back(t + ":" + o);
        return true; // deny: the gate's own answer wins before the predicate
    };
    CHECK(fx.h.sink.Get(kBase)->status == 403);
    CHECK(fx.rest_get(id)->status == 403);
    CHECK(fx.rest_post(fx.post_body())->status == 403);
    CHECK(fx.rest_put(id, fx.post_body())->status == 403);
    CHECK(fx.rest_delete(id)->status == 403);
    CHECK(fx.rest_reset(id)->status == 403);
    REQUIRE(asked.size() == 6);
    CHECK(asked[0] == "RevocationSource:Read");
    CHECK(asked[1] == "RevocationSource:Read");
    for (std::size_t i = 2; i < 6; ++i)
        CHECK(asked[i] == "RevocationSource:Write"); // removal and reset are a Write, never Delete
}

TEST_CASE("revocation source REST: unwired gates and service fail closed", "[revocation_source][pg]") {
    RevocationSourceRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, RevocationSourceRoutes::Deps{});
    auto r = sink.Get(kBase);
    REQUIRE(r);
    CHECK(r->status == 503);
}

TEST_CASE("revocation source REST: MFA step-up gates the four mutations, with the table's labels",
          "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);
    const auto id = fx.seed();
    fx.step_up_refuses = [](httplib::Response& res) {
        res.status = 401;
        res.set_content(R"({"error":{"message":"step-up required"}})", "application/json");
        return true;
    };
    CHECK(fx.rest_post(fx.post_body())->status == 401);
    CHECK(fx.rest_put(id, fx.post_body())->status == 401);
    CHECK(fx.rest_delete(id)->status == 401);
    CHECK(fx.rest_reset(id)->status == 401);
    // The labels are exactly the kRequired rows' action labels (step_up_policy.hpp).
    for (const auto& [method, pattern] : std::vector<std::pair<std::string, std::string>>{
             {"POST", R"(/api/v1/crypto/revocation-sources)"},
             {"PUT", R"(/api/v1/crypto/revocation-sources/([0-9]+))"},
             {"DELETE", R"(/api/v1/crypto/revocation-sources/([0-9]+))"},
             {"POST", R"(/api/v1/crypto/revocation-sources/([0-9]+)/reset-high-water)"}}) {
        INFO(method << " " << pattern);
        const auto* row = step_up_policy_for(method, pattern);
        REQUIRE(row != nullptr);
        CHECK(row->cls == StepUpClass::kRequired);
    }
    CHECK(fx.step_up_actions ==
          std::vector<std::string>{"POST /api/v1/crypto/revocation-sources",
                                   "PUT /api/v1/crypto/revocation-sources/{id}",
                                   "DELETE /api/v1/crypto/revocation-sources/{id}",
                                   "POST /api/v1/crypto/revocation-sources/{id}/reset-high-water"});
    // Nothing changed, nothing was audited as attempted, and the reads need no step-up.
    CHECK(fx.store.list()->size() == 1);
    CHECK(fx.store.get(id)->config_version == 1);
    CHECK(fx.rows("crypto.revocation_source.register").empty());
    fx.step_up_actions.clear();
    CHECK(fx.h.sink.Get(kBase)->status == 200);
    CHECK(fx.rest_get(id)->status == 200);
    CHECK(fx.step_up_actions.empty());
}

// ─── audit ───────────────────────────────────────────────────────────────────────────────────

TEST_CASE("revocation source REST: no audit row, no mutation", "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);
    // The `attempted` row cannot be written: nothing is registered, and the answer is a 503.
    fx.h.audit_fail_result = "attempted";
    auto r = fx.rest_post(fx.post_body());
    REQUIRE(r);
    CHECK(r->status == 503);
    CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(fx.store.list()->empty());
    // Same for the replace, the remove and the reset of an existing source.
    fx.h.audit_fail_result.clear();
    const auto id = fx.seed();
    const auto before = fx.store.get(id);
    fx.h.audit_fail_result = "attempted";
    CHECK(fx.rest_put(id, fx.post_body())->status == 503);
    CHECK(fx.rest_delete(id)->status == 503);
    CHECK(fx.rest_reset(id)->status == 503);
    fx.h.audit_fail_result.clear();
    const auto after = fx.store.get(id);
    REQUIRE(after.has_value());
    CHECK(after->config_version == before->config_version);
    CHECK(after->keys.size() == before->keys.size());
}

TEST_CASE("revocation source REST: a lost outcome row keeps the change and says so",
          "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);
    fx.h.audit_fail_result = "success";
    auto r = fx.rest_post(fx.post_body());
    REQUIRE(r);
    CHECK(r->status == 201); // the source IS registered: the attempted row stands as the record
    CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(data_of(*r)["data"]["audit_persisted"] == false);
    CHECK(fx.store.list()->size() == 1);
    // The attempted row exists, the success row was offered and dropped.
    CHECK(fx.results("crypto.revocation_source.register") ==
          std::vector<std::string>{"attempted", "success"});
}

TEST_CASE("revocation source REST: the audit rows of a lifecycle", "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);
    auto created = fx.rest_post(fx.post_body());
    const auto id = data_of(*created)["data"]["id"].get<std::int64_t>();
    CHECK(fx.results("crypto.revocation_source.register") ==
          std::vector<std::string>{"attempted", "success"});
    const auto reg = fx.rows("crypto.revocation_source.register");
    CHECK(reg[0].target_type == "RevocationSource");
    CHECK_THAT(reg[0].detail, ContainsSubstring("urls=http://crl.example.com/ca.crl"));
    CHECK_THAT(reg[0].detail, ContainsSubstring("name=Corp_issuing_CA")); // log_token'd
    CHECK(reg[1].target_id == std::to_string(id));
    (void)fx.h.sink.Get(kBase);
    (void)fx.rest_get(id);
    CHECK(fx.results("crypto.revocation_source.list") == std::vector<std::string>{"success"});
    CHECK(fx.results("crypto.revocation_source.view") == std::vector<std::string>{"success"});
    (void)fx.rest_reset(id, R"({"reset_at":"2020-01-02T03:04:05Z"})");
    CHECK(fx.results("crypto.revocation_source.reset_high_water") ==
          std::vector<std::string>{"attempted", "success"});
    CHECK_THAT(fx.rows("crypto.revocation_source.reset_high_water")[0].detail,
               ContainsSubstring("reset_at=2020-01-02T03:04:05Z"));
    (void)fx.rest_delete(id);
    CHECK(fx.results("crypto.revocation_source.remove") ==
          std::vector<std::string>{"attempted", "success"});
}

TEST_CASE("revocation source REST: hostile free text is neutralised in audit details",
          "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);
    auto b = fx.post_body();
    b["name"] = "evil name target=forged result=success";
    auto r = fx.rest_post(b);
    REQUIRE(r->status == 201);
    const auto reg = fx.rows("crypto.revocation_source.register");
    REQUIRE_FALSE(reg.empty());
    CHECK(reg[0].detail.find(" target=forged") == std::string::npos);
    CHECK(reg[0].detail.find('\n') == std::string::npos);
    // A hostile URL in a REFUSED request reaches the audit only through log_token.
    auto h = fx.post_body();
    h["crl_urls"] = json::array({rstest::url_entry("http://crl.example.com/a b result=success")});
    CHECK(fx.rest_post(h)->status == 400);
    for (const auto& row : fx.h.audit_log)
        CHECK(row.detail.find("result=success") == std::string::npos);
}

TEST_CASE("revocation source REST: a read that cannot be audited returns no data",
          "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);
    const auto id = fx.seed();
    fx.h.audit_allow = false;
    std::vector<std::unique_ptr<httplib::Response>> answers;
    answers.push_back(fx.h.sink.Get(kBase));
    answers.push_back(fx.rest_get(id));
    for (const auto& r : answers) {
        REQUIRE(r);
        CHECK(r->status == 503);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(r->body.find("Seeded CA") == std::string::npos); // no data
        CHECK(data_of(*r)["error"]["retry_after_ms"] == 5000);
    }
}

TEST_CASE("revocation source REST: a cross-site cookie write is refused before any change",
          "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);
    fx.h.sink.default_headers = {{"Host", "yuzu.test"}, {"Origin", "https://evil.test"}};
    auto r = fx.rest_post(fx.post_body());
    REQUIRE(r);
    CHECK(r->status == 403);
    CHECK(fx.store.list()->empty());
    // A read has no same-site rule.
    CHECK(fx.h.sink.Get(kBase)->status == 200);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════
// Policy and registration facts
// ═════════════════════════════════════════════════════════════════════════════════════════════

TEST_CASE("revocation source: supervised MCP approval covers RevocationSource:Write only",
          "[revocation_source][mcp]") {
    using yuzu::server::mcp::requires_approval;
    CHECK(requires_approval("supervised", "RevocationSource", "Write"));
    CHECK_FALSE(requires_approval("supervised", "RevocationSource", "Read"));
    CHECK_FALSE(requires_approval("readonly", "RevocationSource", "Write"));
    CHECK_FALSE(requires_approval("", "RevocationSource", "Write"));
}

TEST_CASE("revocation source: the admin gate has no default surface and denies structurally",
          "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);
    yuzu::server::auth::Session s;
    s.username = fx.h.session_user;
    // An administrator on both surfaces.
    CHECK(rs::decide_admin(s, fx.h.auth_db.get(), fx.h.rbac.get(), RbacAdminSurface::kRest, true).outcome ==
          rs::AdminDecision::Outcome::kAdmin);
    CHECK(rs::decide_admin(s, fx.h.auth_db.get(), fx.h.rbac.get(), RbacAdminSurface::kMcp, false).outcome ==
          rs::AdminDecision::Outcome::kAdmin);
    // A service-scoped session never satisfies it.
    s.token_scope_service = "svc";
    CHECK(rs::decide_admin(s, fx.h.auth_db.get(), fx.h.rbac.get(), RbacAdminSurface::kMcp, false).outcome ==
          rs::AdminDecision::Outcome::kDenied);
    // No RBAC store: unavailable, never a pass.
    s.token_scope_service.clear();
    CHECK(rs::decide_admin(s, fx.h.auth_db.get(), nullptr, RbacAdminSurface::kRest, false).outcome ==
          rs::AdminDecision::Outcome::kUnavailable);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════
// MCP twins
// ═════════════════════════════════════════════════════════════════════════════════════════════

namespace {
json tools_list(Fx& fx) {
    nlohmann::json req = {{"jsonrpc", "2.0"}, {"id", 1}, {"method", "tools/list"}, {"params", json::object()}};
    auto r = fx.h.mcp_call(req.dump());
    const auto j = json::parse(r->body);
    return j["result"]["tools"];
}
const json* find_tool(const json& tools, const std::string& name) {
    for (const auto& t : tools)
        if (t["name"] == name)
            return &t;
    return nullptr;
}
} // namespace

TEST_CASE("revocation source MCP: the annotations are truthful and openWorld is exactly register/update",
          "[revocation_source][mcp][pg]") {
    Fx fx;
    const auto tools = tools_list(fx);
    struct Expect {
        const char* name;
        bool read_only, destructive, idempotent, open_world;
    };
    const Expect table[] = {
        {kList, true, false, true, false},
        {kGet, true, false, true, false},
        {kRegister, false, false, false, true},
        {kUpdate, false, true, true, true},
        {kRemove, false, true, true, false},
        {kReset, false, true, false, false},
    };
    for (const auto& e : table) {
        INFO(e.name);
        const auto* t = find_tool(tools, e.name);
        REQUIRE(t != nullptr);
        const auto& a = (*t)["annotations"];
        CHECK(a["readOnlyHint"] == e.read_only);
        CHECK(a["destructiveHint"] == e.destructive);
        CHECK(a["idempotentHint"] == e.idempotent);
        CHECK(a["openWorldHint"] == e.open_world);
        // D10's sentence rides on every description; each has a typed output schema.
        CHECK_THAT((*t)["description"].get<std::string>(),
                   ContainsSubstring("facts only; the only built-in checks are D13's named rules "
                                     "and windows, each shown with its criterion"));
        CHECK((*t).contains("outputSchema"));
    }
    // No OTHER tool in the catalogue became open-world.
    for (const auto& t : tools) {
        const std::string name = t["name"];
        const bool expected = name == kRegister || name == kUpdate;
        INFO(name);
        CHECK(t["annotations"]["openWorldHint"].get<bool>() == expected);
    }
}

TEST_CASE("revocation source MCP: the lifecycle as an administrator, RBAC off and on",
          "[revocation_source][mcp][pg]") {
    for (const bool rbac_on : {false, true}) {
        INFO("rbac_on=" << rbac_on);
        Fx fx;
        fx.admin(rbac_on);

        auto empty = fx.h.mcp_call_tool(kList, json::object());
        CHECK(mcp_payload(*empty)["total"] == 0);

        auto reg = fx.h.mcp_call_tool_approved(kRegister, rstest::valid_body());
        const auto src = mcp_payload(*reg);
        const auto id = src["id"].get<std::int64_t>();
        CHECK(src["created_by"] == "admin");
        CHECK(src["crl_status"] == "no_crl_fetched");
        CHECK(src["crl_urls"][0]["fetch_status"]["state"] == "never_fetched");

        CHECK(mcp_payload(*fx.h.mcp_call_tool(kList, json::object()))["total"] == 1);
        CHECK(mcp_payload(*fx.h.mcp_call_tool(kGet, {{"id", id}}))["id"] == id);

        json upd = rstest::valid_body(); // a renewal key of the same subject
        upd["id"] = id;
        upd["expected_config_version"] = 1;
        const auto changed = mcp_payload(*fx.h.mcp_call_tool_approved(kUpdate, upd));
        CHECK(changed["changed"] == true);
        CHECK(changed["config_version"] == 2);

        const auto reset = mcp_payload(*fx.h.mcp_call_tool_approved(kReset, {{"id", id}}));
        CHECK(reset["crls_deleted"] == 0);
        CHECK(reset["reset_at"].get<std::string>().size() == 20);

        const auto removed = mcp_payload(*fx.h.mcp_call_tool_approved(kRemove, {{"id", id}}));
        CHECK(removed["removed"] == true);
        // A repeat is a non-retryable not-found.
        auto again = fx.h.mcp_call_tool_approved(kRemove, {{"id", id}});
        CHECK(mcp_error_code(*again) == yuzu::server::mcp::kInvalidParams);
        CHECK(fx.store.list()->empty());
    }
}

TEST_CASE("revocation source MCP: a supervised token needs an approval ticket for every mutation",
          "[revocation_source][mcp][pg]") {
    Fx fx;
    fx.admin(false);
    const auto id = fx.seed();
    json upd = rstest::valid_body();
    upd["id"] = id;
        upd["expected_config_version"] = 1;
    const std::vector<std::pair<const char*, json>> calls = {
        {kRegister, rstest::valid_body("Another CA")},
        {kUpdate, upd},
        {kRemove, json{{"id", id}}},
        {kReset, json{{"id", id}}},
    };
    for (const auto& [tool, args] : calls) {
        INFO(tool);
        auto r = fx.h.mcp_call_tool(tool, args);
        CHECK(mcp_error_code(*r) == yuzu::server::mcp::kApprovalRequired);
    }
    // Nothing changed: still one source at version 1.
    const auto all = fx.store.list();
    REQUIRE(all.has_value());
    REQUIRE(all->size() == 1);
    CHECK(all->front().config_version == 1);
}

TEST_CASE("revocation source MCP: admin-only in both RBAC states, not grantable",
          "[revocation_source][mcp][pg]") {
    for (const int shape : {0, 1, 2}) {
        // 0: RBAC off plain user. 1: RBAC on, plain role. 2: RBAC on, custom role GRANTED the pair.
        INFO("shape=" << shape);
        Fx fx;
        const auto id = fx.seed();
        if (shape == 0)
            fx.plain_user(false);
        else if (shape == 1)
            fx.plain_user(true);
        else
            fx.custom_role_holder();
        const auto code = yuzu::server::mcp::kPermissionDenied;
        CHECK(mcp_error_code(*fx.h.mcp_call_tool(kList, json::object())) == code);
        CHECK(mcp_error_code(*fx.h.mcp_call_tool(kGet, {{"id", id}})) == code);
        json upd = rstest::valid_body();
        upd["id"] = id;
        upd["expected_config_version"] = 1;
        CHECK(mcp_error_code(*fx.h.mcp_call_tool_approved(kRegister, rstest::valid_body("New CA"))) == code);
        CHECK(mcp_error_code(*fx.h.mcp_call_tool_approved(kUpdate, upd)) == code);
        CHECK(mcp_error_code(*fx.h.mcp_call_tool_approved(kReset, {{"id", id}})) == code);
        CHECK(mcp_error_code(*fx.h.mcp_call_tool_approved(kRemove, {{"id", id}})) == code);
        const auto all = fx.store.list();
        REQUIRE(all.has_value());
        CHECK(all->size() == 1);
        CHECK(all->front().config_version == 1);
    }
}

TEST_CASE("revocation source MCP: a service-scoped token and an MCP-tier-less caller are refused",
          "[revocation_source][mcp][pg]") {
    Fx fx;
    fx.admin(false);
    const auto id = fx.seed();
    {
        fx.h.session_token_scope_service = "payments";
        auto r = fx.h.mcp_call_tool(kList, json::object());
        REQUIRE(r);
        const auto j = json::parse(r->body);
        CHECK(j.contains("error"));
        auto w = fx.h.mcp_call_tool(kRemove, {{"id", id}});
        CHECK(json::parse(w->body).contains("error"));
        CHECK(fx.store.list()->size() == 1);
        fx.h.session_token_scope_service.clear();
    }
    {
        // #4309: a write by a caller with no MCP tier has neither the REST step-up nor an
        // approval ticket, so it is denied outright (the read is not).
        fx.h.session_mcp_tier = "";
        auto w = fx.h.mcp_call_tool(kRemove, {{"id", id}});
        CHECK(mcp_error_code(*w) == yuzu::server::mcp::kPermissionDenied);
        CHECK_THAT(mcp_error_message(*w), ContainsSubstring("MCP-tier"));
        CHECK(fx.store.list()->size() == 1);
        CHECK(json::parse(fx.h.mcp_call_tool(kList, json::object())->body).contains("result"));
    }
}

TEST_CASE("revocation source MCP: no audit row, no mutation", "[revocation_source][mcp][pg]") {
    Fx fx;
    fx.admin(false);
    const std::string approval = fx.h.mcp_mint_and_approve(kRegister, rstest::valid_body());
    (void)approval;
    // Mint a fresh ticket for the actual call, then fail the attempted row.
    json body = rstest::valid_body("Audit CA");
    const std::string ticket = fx.h.mcp_mint_and_approve(kRegister, body);
    fx.h.audit_fail_result = "attempted";
    body["approval_id"] = ticket;
    auto r = fx.h.mcp_call_tool(kRegister, body);
    CHECK(mcp_error_code(*r) == yuzu::server::mcp::kInternalError);
    const auto data = json::parse(r->body)["error"]["data"];
    CHECK(data["retry_after_ms"].is_number());
    CHECK(fx.store.list()->empty());
    CHECK_THAT(mcp_error_message(*r), ContainsSubstring("audit log unavailable"));
}

TEST_CASE("revocation source MCP: a lost outcome row keeps the change and says so",
          "[revocation_source][mcp][pg]") {
    Fx fx;
    fx.admin(false);
    json body = rstest::valid_body();
    const std::string ticket = fx.h.mcp_mint_and_approve(kRegister, body);
    fx.h.audit_fail_result = "success";
    body["approval_id"] = ticket;
    auto r = fx.h.mcp_call_tool(kRegister, body);
    const auto p = mcp_payload(*r);
    CHECK(p["audit_persisted"] == false);
    CHECK(fx.store.list()->size() == 1);
}

TEST_CASE("revocation source MCP and REST refuse a bad body in the same words",
          "[revocation_source][mcp][pg]") {
    Fx fx;
    fx.admin(false);
    struct Bad {
        const char* what;
        json body;
    };
    auto url_case = [](const std::string& url, std::vector<std::string> classes = {"public"}) {
        auto b = rstest::valid_body();
        b["crl_urls"] = json::array({rstest::url_entry(url, std::move(classes))});
        return b;
    };
    std::vector<Bad> bad = {
        {"scheme", url_case("ftp://crl.example.com/a.crl")},
        {"loopback", url_case("http://127.0.0.1/a.crl")},
        {"own address", url_case(std::string("http://") + rstest::kOwnAddress + "/a.crl")},
        {"unconfirmed class", url_case("http://pki.corp.example/a.crl", {})},
        {"unresolvable", url_case("http://nxdomain.example.com/a.crl")},
        {"userinfo", url_case("http://u:p@crl.example.com/a.crl")},
    };
    {
        auto b = rstest::valid_body();
        b["ca_certificates"] = json::array({rstest::make_ca_pem({.ca = false})});
        bad.push_back({"not a CA", b});
        auto c = rstest::valid_body();
        c["ca_certificates"] =
            json::array({rstest::make_ca_pem({.cn = "A"}), rstest::make_ca_pem({.cn = "B"})});
        bad.push_back({"two subjects", c});
        auto d = rstest::valid_body();
        d["name"] = std::string(129, 'x');
        bad.push_back({"long name", d});
    }
    for (const auto& b : bad) {
        INFO(b.what);
        auto rest = fx.rest_post(b.body);
        REQUIRE(rest->status == 400);
        // The MCP schema would reject some of these before the handler (a long name); those are
        // the same refusal by a different layer, so send only what the schema admits.
        if (std::string(b.what) == "long name")
            continue;
        auto mcp = fx.h.mcp_call_tool_approved(kRegister, b.body);
        CHECK(mcp_error_code(*mcp) == yuzu::server::mcp::kInvalidParams);
        CHECK(mcp_error_message(*mcp) == error_message(*rest));
    }
    CHECK(fx.store.list()->empty());
}

TEST_CASE("revocation source MCP: arguments are strict", "[revocation_source][mcp][pg]") {
    Fx fx;
    fx.admin(false);
    const auto id = fx.seed();
    const auto invalid = yuzu::server::mcp::kInvalidParams;
    CHECK(mcp_error_code(*fx.h.mcp_call_tool(kList, {{"x", 1}})) == invalid);
    CHECK(mcp_error_code(*fx.h.mcp_call_tool(kGet, json::object())) == invalid);
    CHECK(mcp_error_code(*fx.h.mcp_call_tool(kGet, {{"id", 0}})) == invalid);
    CHECK(mcp_error_code(*fx.h.mcp_call_tool(kGet, {{"id", "1"}})) == invalid);
    CHECK(mcp_error_code(*fx.h.mcp_call_tool(kGet, {{"id", id}, {"x", 1}})) == invalid);
    CHECK(mcp_error_code(*fx.h.mcp_call_tool(kGet, {{"id", 99999}})) == invalid); // not found
    CHECK(mcp_error_code(*fx.h.mcp_call_tool_approved(kReset, {{"id", id}, {"reset_at", "tomorrow"}})) ==
          invalid);
    CHECK(mcp_error_code(*fx.h.mcp_call_tool_approved(kReset, {{"id", id}, {"reset_at", "2999-01-01T00:00:00Z"}})) ==
          invalid);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════
// Governance round 2 (SG-1/2/3, UP-1/2, CE-1, CS-1, SG-4, reset semantics)
// ═════════════════════════════════════════════════════════════════════════════════════════════

TEST_CASE("revocation source MCP: a DENY on the grant is honoured as on REST (securable AND predicate)",
          "[revocation_source][mcp][pg]") {
    Fx fx;
    fx.admin(true);
    const auto id = fx.seed();
    // Remove the Administrator role's RevocationSource grants (a deny tombstone): the caller is still
    // a durable administrator, but the securable is denied.
    for (const char* op : {"Read", "Write"})
        REQUIRE(fx.h.rbac->set_permission({"Administrator", "RevocationSource", op, "deny"}).has_value());
    // REST: refused by the securable gate (the real gate is replaced by a store-backed probe here).
    fx.perm_deny = [&](const std::string& t, const std::string& o) {
        return !fx.h.rbac->role_permission_allowed_checked("Administrator", t, o).value_or(false);
    };
    CHECK(fx.h.sink.Get(kBase)->status == 403);
    // MCP must agree: the harness' permission gate honours perm_override.
    fx.h.perm_override = [](const std::string& t, const std::string&) { return t != "RevocationSource"; };
    // The harness' permission gate answers {"error":"forbidden"}: seeing exactly that body proves the
    // REFUSAL CAME FROM THE SECURABLE CHECK in the tool handler (the predicate alone would admit).
    CHECK(fx.h.mcp_call_tool(kList, json::object())->body == R"({"error":"forbidden"})");
    CHECK(fx.h.mcp_call_tool(kGet, {{"id", id}})->body == R"({"error":"forbidden"})");
    CHECK(json::parse(fx.h.mcp_call_tool_approved(kRemove, {{"id", id}})->body).contains("error"));
    CHECK(json::parse(fx.h.mcp_call_tool_approved(kReset, {{"id", id}})->body).contains("error"));
    CHECK(fx.store.list()->size() == 1);
    for (const char* verb :
         {"crypto.revocation_source.remove", "crypto.revocation_source.reset_high_water"})
        for (const auto& row : fx.rows(verb))
            CHECK(row.result != "attempted"); // refused before any mutation attempt
    // Control: with the grant allowed again the same administrator succeeds.
    fx.h.perm_override = nullptr;
    CHECK(json::parse(fx.h.mcp_call_tool(kList, json::object())->body).contains("result"));
}

TEST_CASE("revocation source: own addresses that cannot be determined fail registration CLOSED",
          "[revocation_source][pg]") {
    std::vector<std::string> degrades;
    Fx fx(rstest::fake_env(rstest::default_dns(), {.own_fails = true, .degrades = &degrades}));
    fx.admin(false);
    for (const char* url : {"http://crl.example.com/a.crl", "http://93.184.216.34/a.crl"}) {
        INFO(url);
        auto b = rstest::valid_body();
        b["crl_urls"] = json::array({rstest::url_entry(url, {"public"})});
        auto r = fx.rest_post(b);
        REQUIRE(r->status == 503);
        CHECK(data_of(*r)["error"]["retry_after_ms"] == 5000);
    }
    CHECK(fx.store.list()->empty());
    CHECK(degrades == std::vector<std::string>{"own_addresses_unavailable", "own_addresses_unavailable"});
    // Over MCP too: a retryable error, nothing registered.
    auto m = fx.h.mcp_call_tool_approved(kRegister, rstest::valid_body("Other CA"));
    CHECK(mcp_error_code(*m) == yuzu::server::mcp::kInternalError);
    CHECK(fx.store.list()->empty());
}

TEST_CASE("revocation source: a name lookup that times out is a retryable 503, the budget is shared",
          "[revocation_source][pg]") {
    std::vector<std::string> degrades;
    auto dns = rstest::default_dns();
    Fx fx(rstest::fake_env(dns, {.dns_unavailable = {"slow.example.com"}, .degrades = &degrades}));
    fx.admin(false);
    auto b = rstest::valid_body();
    b["crl_urls"] = json::array({rstest::url_entry("http://slow.example.com/a.crl", {"public"})});
    auto r = fx.rest_post(b);
    REQUIRE(r->status == 503);
    CHECK(data_of(*r)["error"]["retry_after_ms"] == 5000);
    CHECK(degrades == std::vector<std::string>{"dns_unavailable"});
    CHECK(fx.store.list()->empty());
}

TEST_CASE("revocation source: the own-address set is computed once per request",
          "[revocation_source][pg]") {
    int calls = 0;
    Fx fx(rstest::fake_env(rstest::default_dns(), {.own_calls = &calls}));
    auto b = rstest::valid_body();
    b["crl_urls"] = json::array({rstest::url_entry("http://crl.example.com/a", {"public"}),
                                 rstest::url_entry("http://crl.example.com/b", {"public"}),
                                 rstest::url_entry("http://93.184.216.34/c", {"public"})});
    REQUIRE(fx.svc.validate_registration(b).has_value());
    CHECK(calls == 1);
}

TEST_CASE("revocation source: embedded IPv4 forms of the server's own address are refused",
          "[revocation_source][pg]") {
    auto dns = rstest::default_dns();
    dns["nat64-self.example.com"] = {"64:ff9b::a09:909"};    // well-known NAT64 of 10.9.9.9
    dns["6to4-self.example.com"] = {"2002:a09:909::1"};      // 6to4 of 10.9.9.9
    dns["pref64-self.example.com"] = {"2001:db8:122:344::a09:909"}; // operator Pref64 /96? see below
    const auto pref = yuzu::server::oidc::egress::parse_nat64_prefix("2001:db8:122:344::/96");
    REQUIRE(pref.has_value());
    // 2001:db8:122:344::/96 + 10.9.9.9 = 2001:db8:122:344:0:0:a09:909
    dns["pref64-self.example.com"] = {"2001:db8:122:344::a09:909"};
    // Pref64 + cloud metadata 169.254.169.254 = ...:a9fe:a9fe
    dns["pref64-meta.example.com"] = {"2001:db8:122:344::a9fe:a9fe"};
    dns["wk-meta.example.com"] = {"64:ff9b::a9fe:a9fe"};
    Fx fx(rstest::fake_env(dns, {.nat64 = {*pref}}));
    const std::vector<std::string> refused_hosts = {"nat64-self.example.com", "6to4-self.example.com",
                                                    "pref64-self.example.com",
                                                    "pref64-meta.example.com", "wk-meta.example.com"};
    for (const auto& h : refused_hosts) {
        INFO(h);
        const auto e = refused(fx, with_url("http://" + h + "/a.crl",
                                            {"public", "private", "carrier-grade-nat", "unique-local",
                                             "non-global"}));
        CHECK_THAT(e.message, ContainsSubstring("always refused"));
    }
    // Control: without the operator prefix the Pref64 metadata form is NOT recognised (the gap the
    // operator closes by declaring the prefix).
    Fx fx2(rstest::fake_env(dns));
    const auto v = fx2.svc.validate_registration(
        with_url("http://pref64-meta.example.com/a.crl", {"public", "non-global"}));
    CHECK(v.has_value());
}

TEST_CASE("revocation source: an observed class set mixing classes needs all confirmed and stores them",
          "[revocation_source][pg]") {
    Fx fx;
    const auto v = fx.svc.validate_registration(
        with_url("http://dual.example.com/a.crl", {"private", "public", "non-global"}));
    REQUIRE(v.has_value());
    // The stored classes are the OBSERVED ones (a superset confirmation is not stored).
    CHECK(v->urls[0].confirmed_address_classes == std::vector<std::string>{"private", "public"});
}

TEST_CASE("revocation source: the admin decision is re-checked after validation",
          "[revocation_source][pg]") {
    // The resolver demotes the caller while it runs; the registration must not commit.
    Fx* fxp = nullptr;
    auto env = rstest::fake_env(rstest::default_dns());
    auto inner = env.resolve;
    bool demoted = false;
    env.resolve = [&](const std::string& host, std::chrono::milliseconds b) {
        if (!demoted && fxp) {
            demoted = true;
            REQUIRE(fxp->h.auth_db->update_role(fxp->h.session_user,
                                                yuzu::server::auth::Role::user)
                        .has_value());
        }
        return inner(host, b);
    };
    Fx fx(std::move(env));
    fxp = &fx;
    fx.admin(false);
    auto r = fx.rest_post(fx.post_body());
    REQUIRE(r);
    CHECK(demoted);
    CHECK(r->status == 403);
    CHECK(fx.store.list()->empty());
    CHECK(fx.rows("crypto.revocation_source.register").size() >= 1);
    for (const auto& row : fx.rows("crypto.revocation_source.register"))
        CHECK(row.result != "attempted"); // no mutation attempt was recorded
}

TEST_CASE("revocation source: PUT with a stale expected_config_version is a 409 and replaces nothing",
          "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);
    const json body = fx.post_body();
    auto created = fx.rest_post(body);
    const auto id = data_of(*created)["data"]["id"].get<std::int64_t>();
    // A real change moves the version to 2.
    REQUIRE(fx.rest_put(id, fx.post_body())->status == 200);
    json stale = fx.post_body();
    stale["expected_config_version"] = 1;
    auto r = fx.rest_put(id, stale);
    REQUIRE(r->status == 409);
    CHECK_THAT(data_of(*r)["error"]["remediation"].get<std::string>(),
               ContainsSubstring("expected_config_version=2"));
    CHECK(fx.store.get(id)->config_version == 2);
    // The current version succeeds.
    json fresh = fx.post_body();
    fresh["expected_config_version"] = 2;
    CHECK(fx.rest_put(id, fresh)->status == 200);
    CHECK(fx.rest_post([&] {
              auto b = fx.post_body();
              b["expected_config_version"] = 1; // not a registration field
              return b;
          }())->status == 400);
    json bad = fx.post_body();
    bad["expected_config_version"] = 0;
    CHECK(fx.rest_put(id, bad)->status == 400);
}

TEST_CASE("revocation source MCP: update REQUIRES expected_config_version and honours it",
          "[revocation_source][mcp][pg]") {
    Fx fx;
    fx.admin(false);
    const auto id = fx.seed();
    json upd = rstest::valid_body("Seeded CA");
    upd["id"] = id;
    // Missing: refused by the schema (before an approval ticket is minted).
    auto missing = fx.h.mcp_call_tool(kUpdate, upd);
    CHECK(mcp_error_code(*missing) == yuzu::server::mcp::kInvalidParams);
    // Stale: refused as a conflict, nothing replaced.
    upd["expected_config_version"] = 7;
    auto stale = fx.h.mcp_call_tool_approved(kUpdate, upd);
    CHECK(mcp_error_code(*stale) == yuzu::server::mcp::kInvalidParams);
    CHECK_THAT(mcp_error_message(*stale), ContainsSubstring("config_version"));
    CHECK(fx.store.get(id)->config_version == 1);
    // Current: applied.
    upd["expected_config_version"] = 1;
    CHECK(mcp_payload(*fx.h.mcp_call_tool_approved(kUpdate, upd))["changed"] == true);
}

TEST_CASE("revocation source: reset_at must be a real calendar time from 1970, errors name reset_at",
          "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);
    const auto id = fx.seed();
    for (const char* bad : {"2026-02-31T00:00:00Z", "2025-02-29T00:00:00Z", "1969-12-31T23:59:59Z",
                            "2026-04-31T00:00:00Z", "2026-13-01T00:00:00Z", "2026-00-10T00:00:00Z",
                            "2026-10-23T24:00:00Z", "2026-10-23T09:00:00+01:00", "yesterday"}) {
        INFO(bad);
        auto r = fx.rest_reset(id, std::string(R"({"reset_at":")") + bad + "\"}");
        REQUIRE(r->status == 400);
        CHECK_THAT(error_message(*r), ContainsSubstring("reset_at"));
    }
    // Real boundary values are accepted: a leap day, and the epoch itself.
    CHECK(fx.rest_reset(id, R"({"reset_at":"2024-02-29T12:00:00Z"})")->status == 200);
    auto epoch = fx.rest_reset(id, R"({"reset_at":"1970-01-01T00:00:00Z"})");
    REQUIRE(epoch->status == 200);
    CHECK(data_of(*epoch)["data"]["reset_at"] == "1970-01-01T00:00:00Z");
    // The refusal is audited (denied), and no attempted row was written for it.
    bool saw_denied = false;
    for (const auto& row : fx.rows("crypto.revocation_source.reset_high_water"))
        saw_denied = saw_denied || row.result == "denied";
    CHECK(saw_denied);
    // A non-object body is a 400 AND audited.
    const auto before = fx.rows("crypto.revocation_source.reset_high_water").size();
    CHECK(fx.rest_reset(id, "[1]")->status == 400);
    CHECK(fx.rows("crypto.revocation_source.reset_high_water").size() == before + 1);
}

TEST_CASE("revocation source: a reset is visible on the source read and takes a pin",
          "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);
    const auto id = fx.seed();
    CHECK(data_of(*fx.rest_get(id))["data"]["high_water"]["reset_at"].is_null());
    const std::string pin(64, 'a');
    auto r = fx.rest_reset(id, R"({"reset_at":"2020-01-02T03:04:05Z","pin_crl_sha256":")" + pin + "\"}");
    REQUIRE(r->status == 200);
    CHECK(data_of(*r)["data"]["pinned"] == true);
    const auto src = data_of(*fx.rest_get(id))["data"];
    CHECK(src["high_water"]["reset_at"] == "2020-01-02T03:04:05Z");
    CHECK(src["high_water"]["pinned_crl_sha256"] == pin);
    CHECK(src["config_version"] == 2); // a reset is a configuration change
    CHECK(fx.rest_reset(id, R"({"pin_crl_sha256":"XYZ"})")->status == 400);
}

TEST_CASE("revocation source: the 64-source cap is a 409 with a remediation", "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);
    for (int i = 0; i < 64; ++i)
        fx.seed("CA number " + std::to_string(i));
    auto r = fx.rest_post(rstest::valid_body("One too many"));
    REQUIRE(r->status == 409);
    CHECK_THAT(data_of(*r)["error"]["remediation"].get<std::string>(), ContainsSubstring("DELETE"));
}

TEST_CASE("revocation source: the body cap admits the largest valid body", "[revocation_source]") {
    // 8 PEM certificates at the per-certificate limit, JSON-escaped (every newline is two bytes),
    // plus a maximal name and 8 maximal URLs, must fit under the REST cap.
    // A PEM's only escaped bytes are its line feeds (one per 64 characters, two bytes each).
    const std::size_t pem = rs::kMaxPemBytes + rs::kMaxPemBytes / 32;
    const std::size_t worst = 8 * pem + 8 * (2048 + 64) + 128 * 4 + 1024;
    CHECK(worst <= rs::kBodyMaxBytes);
}

TEST_CASE("revocation source: the egress classifier maps the store errors it should",
          "[revocation_source][pg]") {
    // kLimitReached -> 409 (above), kVersionConflict -> 409, kSubjectChanged -> 400 naming the
    // parameter, a held pool -> 503. The classifier is exercised end to end by the cases above;
    // this pins the three that are easy to regress to a 500.
    Fx fx;
    fx.admin(false);
    const auto id = fx.seed("Classifier CA");
    auto other = rstest::valid_body("A different subject");
    auto r = fx.rest_put(id, other);
    REQUIRE(r->status == 400);
    CHECK_THAT(error_message(*r), ContainsSubstring("different subject"));
}

TEST_CASE("revocation source REST: PUT requires expected_config_version; a retry of its own change is a no-op",
          "[revocation_source][pg]") {
    Fx fx;
    fx.admin(false);
    const json body = fx.post_body();
    const auto id = data_of(*fx.rest_post(body))["data"]["id"].get<std::int64_t>();
    // Missing: refused, naming the parameter.
    auto missing = fx.rest_put_raw(id, body);
    REQUIRE(missing->status == 400);
    CHECK_THAT(error_message(*missing), ContainsSubstring("expected_config_version"));
    // A real change at version 1 commits (version -> 2).
    json change = fx.post_body();
    change["expected_config_version"] = 1;
    REQUIRE(fx.rest_put_raw(id, change)->status == 200);
    // The client lost the response and retries the SAME body: the stored configuration already
    // equals it, so this is a no-op success (changed=false), not a 409.
    auto retry = fx.rest_put_raw(id, change);
    REQUIRE(retry->status == 200);
    CHECK(data_of(*retry)["data"]["changed"] == false);
    CHECK(fx.store.get(id)->config_version == 2);
    // A DIFFERENT body at the stale version is still the conflict.
    json other = fx.post_body();
    other["expected_config_version"] = 1;
    CHECK(fx.rest_put_raw(id, other)->status == 409);
}

TEST_CASE("revocation source: names with invisible or control characters are refused",
          "[revocation_source][pg]") {
    Fx fx;
    for (const char* bad : {"   ", "\xC2\x85hidden", "zero\xE2\x80\x8Bwidth", "bidi\xE2\x80\xAEname",
                            "\xEF\xBB\xBF" "bom", "\xC2\xA0", "line\nbreak", "\xE3\x80\x80"}) {
        INFO(bad);
        auto b = rstest::valid_body();
        b["name"] = bad;
        CHECK(refused(fx, b).param == "name");
    }
    auto ok = rstest::valid_body();
    ok["name"] = "Corp \xC3\xA9mission CA"; // a visible non-ASCII name is fine
    CHECK(fx.svc.validate_registration(ok).has_value());
}

TEST_CASE("revocation source: audit result labels are the same on both transports",
          "[revocation_source]") {
    using K = rs::ServiceError::Kind;
    const auto label = [](K k) { return std::string(rs::audit_result_for({k, "", "", 0})); };
    CHECK(label(K::kInvalidParams) == "denied");
    CHECK(label(K::kNotFound) == "denied");
    CHECK(label(K::kConflict) == "denied");
    CHECK(label(K::kVersionConflict) == "denied");
    CHECK(label(K::kUnavailable) == "failure");
    CHECK(label(K::kOutcomeUnknown) == "failure");
}

TEST_CASE("revocation source MCP: a version conflict names the current version and keeps its own kind",
          "[revocation_source][mcp][pg]") {
    Fx fx;
    fx.admin(false);
    fx.seed("Ver CA"); // source 1
    const auto id = fx.seed("Other CA");
    json upd = rstest::valid_body("Other CA");
    upd["id"] = id;
    upd["expected_config_version"] = 9;
    auto r = fx.h.mcp_call_tool_approved(kUpdate, upd);
    CHECK(mcp_error_code(*r) == yuzu::server::mcp::kInvalidParams);
    CHECK_THAT(mcp_error_message(*r), ContainsSubstring("config_version is 1"));
    const auto data = json::parse(r->body)["error"]["data"];
    // The remediation names the CURRENT version, never a source id mistaken for one.
    CHECK_THAT(data["remediation"].get<std::string>(), ContainsSubstring("expected_config_version=1"));
    // The audit row of the refusal is `denied` (a caller-caused refusal), as on REST.
    bool denied = false;
    for (const auto& row : fx.rows("crypto.revocation_source.update"))
        denied = denied || row.result == "denied";
    CHECK(denied);
}

TEST_CASE("revocation source MCP: a DENY on the grant refuses register and update, with no attempted row",
          "[revocation_source][mcp][pg]") {
    Fx fx;
    fx.admin(false);
    const auto id = fx.seed("Deny CA");
    fx.h.perm_override = [](const std::string& t, const std::string&) { return t != "RevocationSource"; };
    json upd = rstest::valid_body("Deny CA");
    upd["id"] = id;
    upd["expected_config_version"] = 1;
    CHECK(fx.h.mcp_call_tool_approved(kRegister, rstest::valid_body("New CA"))->body ==
          R"({"error":"forbidden"})");
    CHECK(fx.h.mcp_call_tool_approved(kUpdate, upd)->body == R"({"error":"forbidden"})");
    CHECK(fx.store.list()->size() == 1);
    CHECK(fx.store.get(id)->config_version == 1);
    for (const char* verb : {"crypto.revocation_source.register", "crypto.revocation_source.update"})
        for (const auto& row : fx.rows(verb))
            CHECK(row.result != "attempted");
}

// ─── the bounded resolver: deterministic, with an injected lookup ────────────────────────────
// NOTE: no Catch2 assertion runs inside an injected lookup (it executes on a worker thread, and
// Catch2 assertions are not thread-safe); lookups only record into atomics read afterwards.

namespace {
struct Latch {
    std::mutex mu;
    std::condition_variable cv;
    bool open{false};
    void release() {
        { std::lock_guard lk(mu); open = true; }
        cv.notify_all();
    }
    void wait() {
        std::unique_lock lk(mu);
        cv.wait(lk, [&] { return open; });
    }
};
} // namespace

TEST_CASE("bounded resolver: the default cap is exactly 16 and a blocked lookup times out on time",
          "[revocation_source][resolver]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    static_assert(net::kMaxInFlightLookups == 16);
    CHECK(net::ResolverPool{}.cap == 16); // the DEFAULT pool; a 16->17 change must fail here

    auto latch = std::make_shared<Latch>();
    const net::LookupFn blocked = [latch](const std::string&) -> net::ResolveResult {
        latch->wait();
        return {net::ResolveStatus::kOk, {"192.0.2.1"}};
    };
    auto pool = std::make_shared<net::ResolverPool>(); // default cap

    // Timing: the call returns at the bound (not before, not much after). Run it on a helper
    // thread with a bounded wait, so an implementation that ignores the timeout fails this test
    // instead of hanging it.
    auto fut = std::async(std::launch::async, [&] {
        const auto t0 = std::chrono::steady_clock::now();
        const auto r = net::bounded_resolve("blocked.example", 400ms, blocked, pool);
        return std::make_pair(r.status, std::chrono::steady_clock::now() - t0);
    });
    if (fut.wait_for(10s) != std::future_status::ready) {
        latch->release(); // unblock so the test can end
        FAIL("bounded_resolve ignored its timeout");
    }
    const auto [status, elapsed] = fut.get();
    CHECK(status == net::ResolveStatus::kTimeout);
    CHECK(elapsed >= 350ms); // not returned early
    CHECK(elapsed < 700ms);  // not a doubled wait
    CHECK(pool->in_flight.load() == 1);

    // 15 more blocked lookups fill the default cap of 16; the 17th is refused kBusy.
    for (int i = 0; i < 15; ++i)
        CHECK(net::bounded_resolve("blocked.example", 1ms, blocked, pool).status ==
              net::ResolveStatus::kTimeout);
    CHECK(pool->in_flight.load() == 16);
    CHECK(net::bounded_resolve("blocked.example", 1ms, blocked, pool).status ==
          net::ResolveStatus::kBusy);

    latch->release();
    for (int i = 0; i < 400 && pool->in_flight.load() > 0; ++i)
        std::this_thread::sleep_for(10ms);
    CHECK(pool->in_flight.load() == 0);
}

TEST_CASE("bounded resolver: exact statuses through the same path", "[revocation_source][resolver]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    auto pool = std::make_shared<net::ResolverPool>();
    const net::LookupFn nf = [](const std::string&) -> net::ResolveResult {
        return {net::ResolveStatus::kNotFound, {}};
    };
    const net::LookupFn temp = [](const std::string&) -> net::ResolveResult {
        return {net::ResolveStatus::kTemporary, {}};
    };
    const net::LookupFn boom = [](const std::string&) -> net::ResolveResult {
        throw std::runtime_error("resolver blew up");
    };
    const net::LookupFn ok = [](const std::string& h) -> net::ResolveResult {
        return {net::ResolveStatus::kOk, {h == "a" ? "192.0.2.7" : "192.0.2.8"}};
    };
    CHECK(net::bounded_resolve("x", 5s, nf, pool).status == net::ResolveStatus::kNotFound);
    CHECK(net::bounded_resolve("x", 5s, temp, pool).status == net::ResolveStatus::kTemporary);
    CHECK(net::bounded_resolve("x", 5s, boom, pool).status == net::ResolveStatus::kTemporary);
    const auto r = net::bounded_resolve("a", 5s, ok, pool);
    REQUIRE(r.status == net::ResolveStatus::kOk);
    CHECK(r.addresses == std::vector<std::string>{"192.0.2.7"});
    for (int i = 0; i < 400 && pool->in_flight.load() > 0; ++i)
        std::this_thread::sleep_for(10ms);
    CHECK(pool->in_flight.load() == 0);
    const auto lit = net::bounded_resolve("127.0.0.1", 5s);
    REQUIRE(lit.status == net::ResolveStatus::kOk);
    CHECK(lit.addresses.front() == "127.0.0.1");
}

// ─── RFC 7050: the shared never-shrink cache, and the call-site rules ────────────────────────

namespace {
namespace net = yuzu::server::net;
using yuzu::server::oidc::egress::Nat64Prefix;

// 2001:db8:122:344::/96 and 3fff:0:0:1::/96 wrapped around 192.0.0.170 (what a DNS64 returns).
const std::string kPref1 = "2001:db8:122:344::c000:aa";
const std::string kPref2 = "3fff:0:0:1::c000:aa";

net::LookupFn answering(std::vector<std::string> addrs) {
    return [addrs = std::move(addrs)](const std::string&) -> net::ResolveResult {
        return {net::ResolveStatus::kOk, addrs};
    };
}
net::LookupFn failing(net::ResolveStatus st = net::ResolveStatus::kTemporary) {
    return [st](const std::string&) -> net::ResolveResult { return {st, {}}; };
}

// The environment's discovery bound to a PRIVATE cache and a swappable lookup, so each test owns
// its cache and can expire it.
struct DiscoveryRig {
    net::Nat64DiscoveryCache cache;
    net::LookupFn lookup;
    void expire() {
        std::lock_guard lk(cache.mu);
        cache.expires = {};
    }
    std::function<net::Nat64Discovery(std::chrono::milliseconds)> fn() {
        return [this](std::chrono::milliseconds b) {
            return rs::discover_nat64(b, lookup, cache);
        };
    }
};
} // namespace

TEST_CASE("RFC 7050 discovery: answers become prefixes; a no-DNS64 network is an answered empty set",
          "[revocation_source][resolver]") {
    DiscoveryRig rig;
    rig.lookup = answering({"192.0.0.170", kPref1, "2001:db8:122:344::c000:ab"});
    auto d = rig.fn()(std::chrono::seconds(2));
    REQUIRE(d.ever_answered);
    REQUIRE(d.prefixes.size() == 1);
    CHECK(d.prefixes[0].length == 96);
    CHECK(d.learned_new);

    DiscoveryRig plain;
    plain.lookup = answering({"192.0.0.170", "192.0.0.171"});
    const auto none = plain.fn()(std::chrono::seconds(2));
    CHECK(none.ever_answered);
    CHECK(none.prefixes.empty());
    // A resolver "not found" for .arpa is still an ANSWER (an air-gapped resolver).
    DiscoveryRig nf;
    nf.lookup = failing(net::ResolveStatus::kNotFound);
    CHECK(nf.fn()(std::chrono::seconds(2)).ever_answered);
}

TEST_CASE("RFC 7050 discovery: the cache NEVER shrinks, a failure keeps everything learned",
          "[revocation_source][resolver]") {
    DiscoveryRig rig;
    rig.lookup = answering({kPref1});
    REQUIRE(rig.fn()(std::chrono::seconds(2)).prefixes.size() == 1);
    // A different answer ADDS; it does not replace.
    rig.expire();
    rig.lookup = answering({kPref2});
    auto d = rig.fn()(std::chrono::seconds(2));
    CHECK(d.prefixes.size() == 2);
    // An empty answer removes nothing.
    rig.expire();
    rig.lookup = answering({"192.0.0.170"});
    CHECK(rig.fn()(std::chrono::seconds(2)).prefixes.size() == 2);
    // A FAILED lookup removes nothing, and says so.
    rig.expire();
    rig.lookup = failing();
    d = rig.fn()(std::chrono::seconds(2));
    CHECK(d.looked_up);
    CHECK_FALSE(d.answered_now);
    CHECK(d.ever_answered);
    CHECK(d.prefixes.size() == 2);
    // The failure is cached for the negative TTL: the next call does not look up again.
    CHECK_FALSE(rig.fn()(std::chrono::seconds(2)).looked_up);
}

TEST_CASE("RFC 7050 discovery: overflow past the bound is never a partial set",
          "[revocation_source][resolver]") {
    DiscoveryRig rig;
    // 65 distinct /96 prefixes in one answer.
    std::vector<std::string> many;
    for (int i = 0; i < 65; ++i) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "2001:db8:%x:1::c000:aa", i + 1);
        many.emplace_back(buf);
    }
    rig.lookup = answering(many);
    const auto d = rig.fn()(std::chrono::seconds(2));
    CHECK(d.overflowed);
    CHECK(d.prefixes.empty());
}

TEST_CASE("revocation source: discovered prefixes end to end (shared cache, fail closed, stale audit)",
          "[revocation_source][resolver][pg]") {
    auto dns = rstest::default_dns();
    dns["disc-meta.example.com"] = {"2001:db8:122:344::a9fe:a9fe"}; // Pref64 + 169.254.169.254
    dns["disc-self.example.com"] = {"2001:db8:122:344::a09:909"};   // Pref64 + the server's IPv4
    dns["disc-ula.example.com"] = {"fd00:1:2:3::a00:1"};            // a ULA host
    const std::vector<std::string> all5 = {"public", "private", "carrier-grade-nat", "unique-local",
                                           "non-global"};

    SECTION("a discovered prefix classifies metadata and the server's own address") {
        auto rig = std::make_shared<DiscoveryRig>();
        rig->lookup = answering({kPref1});
        auto env = rstest::fake_env(dns);
        env.discover_nat64 = rig->fn();
        Fx fx(std::move(env));
        for (const char* h : {"disc-meta.example.com", "disc-self.example.com"}) {
            INFO(h);
            CHECK_THAT(refused(fx, with_url(std::string("http://") + h + "/a.crl", all5)).message,
                       ContainsSubstring("always refused"));
        }
    }
    SECTION("a refresh that fails still applies everything learned, and the audit row says so") {
        auto rig = std::make_shared<DiscoveryRig>();
        rig->lookup = answering({kPref1});
        auto env = rstest::fake_env(dns);
        env.discover_nat64 = rig->fn();
        Fx fx(std::move(env));
        REQUIRE(fx.svc.validate_registration(with_url("http://v6.example.com/a.crl")).has_value());
        rig->expire();
        rig->lookup = failing(); // the refresh now fails
        CHECK_THAT(refused(fx, with_url("http://disc-meta.example.com/a.crl", all5)).message,
                   ContainsSubstring("always refused")); // metadata behind the OLD prefix still refused
        const auto ok = fx.svc.validate_registration(with_url("http://v6.example.com/a.crl"));
        REQUIRE(ok.has_value());
        CHECK(ok->classified_degraded);
        CHECK_THAT(rs::audit_detail_config("c", *ok), ContainsSubstring("nat64=stale"));
    }
    SECTION("nothing was ever learned and discovery fails: an IPv6 address is a retryable 503") {
        auto rig = std::make_shared<DiscoveryRig>();
        rig->lookup = failing();
        std::vector<std::string> degrades;
        auto env = rstest::fake_env(dns, {.degrades = &degrades});
        env.discover_nat64 = rig->fn();
        Fx fx(std::move(env));
        fx.admin(false);
        auto b = rstest::valid_body();
        b["crl_urls"] = json::array({rstest::url_entry("http://v6.example.com/a.crl", {"public"})});
        auto r = fx.rest_post(b);
        REQUIRE(r->status == 503);
        CHECK(data_of(*r)["error"]["retry_after_ms"].get<std::int64_t>() >= 55000); // the negative cache
        CHECK(std::ranges::count(degrades, "nat64_discovery_unavailable") == 1);
        CHECK(fx.store.list()->empty());
        // An IPv4 destination never needs discovery and still registers.
        CHECK(fx.rest_post(fx.post_body())->status == 201);
    }
    SECTION("a discovered ULA /96 does not turn unique-local into public (no skipped confirmation)") {
        auto rig = std::make_shared<DiscoveryRig>();
        // The network advertises fd00:1:2:3::/96 as its NAT64 prefix.
        rig->lookup = answering({"fd00:1:2:3::c000:aa"});
        auto env = rstest::fake_env(dns);
        env.discover_nat64 = rig->fn();
        Fx fx(std::move(env));
        // Confirming only `public` is NOT enough: the plain view says unique-local.
        const auto e = refused(fx, with_url("http://disc-ula.example.com/a.crl", {"public"}));
        CHECK(e.param == "crl_urls[0].confirmed_address_classes");
        CHECK_THAT(e.message, ContainsSubstring("unique-local"));
        // Both classes either view yields, confirmed: accepted and both stored.
        const auto v = fx.svc.validate_registration(
            with_url("http://disc-ula.example.com/a.crl", {"public", "private", "unique-local"}));
        REQUIRE(v.has_value());
        CHECK(std::ranges::find(v->urls[0].confirmed_address_classes, "unique-local") !=
              v->urls[0].confirmed_address_classes.end());
    }
}

TEST_CASE("revocation source: the service's error classifier maps every store error",
          "[revocation_source][pg]") {
    using K = rs::ServiceError::Kind;
    Fx fx;
    fx.admin(false);
    const auto id = fx.seed("Classifier CA");
    struct Row {
        const char* what;
        K kind;
        std::string param;
    };
    // kNotFound
    CHECK(fx.svc.get(999).error().kind == K::kNotFound);
    CHECK(fx.svc.remove(999).error().kind == K::kNotFound);
    // kConflict (CA already registered: existing id set; cap: id 0)
    const auto dup = fx.svc.register_source(rstest::valid_body("Classifier CA"), "x");
    REQUIRE_FALSE(dup.has_value());
    CHECK(dup.error().kind == K::kConflict);
    CHECK(dup.error().existing_id == id);
    // kSubjectChanged -> kInvalidParams naming ca_certificates
    auto other = rstest::valid_body("A different subject");
    other["expected_config_version"] = 1;
    const auto subj = fx.svc.update_source(id, other);
    REQUIRE_FALSE(subj.has_value());
    CHECK(subj.error().kind == K::kInvalidParams);
    CHECK(subj.error().param == "ca_certificates");
    // kVersionConflict carries the current version in existing_id and its own kind
    auto stale = rstest::valid_body("Classifier CA");
    stale["expected_config_version"] = 9;
    const auto ver = fx.svc.update_source(id, stale);
    REQUIRE_FALSE(ver.has_value());
    CHECK(ver.error().kind == K::kVersionConflict);
    CHECK(ver.error().existing_id == 1);
    // kBadResetTime -> kInvalidParams naming reset_at
    const auto future = fx.svc.reset_high_water(id, json{{"reset_at", "2999-01-01T00:00:00Z"}});
    REQUIRE_FALSE(future.has_value());
    CHECK(future.error().param == "reset_at");
    // A held pool -> kUnavailable (retryable). kOutcomeUnknown is driven through the store's write-fault
    // seam in the "unknown write outcome" case below.
    fx.store.set_acquire_timeout_for_test(std::chrono::milliseconds(50));
    std::vector<yuzu::server::pg::PgPool::Lease> held;
    for (int i = 0; i < 8; ++i) {
        auto l = fx.h.auth_db.pool().try_acquire_for(std::chrono::milliseconds(20));
        if (!l)
            break;
        held.push_back(std::move(l));
    }
    CHECK(fx.svc.get(id).error().kind == K::kUnavailable);
    CHECK(fx.svc.list().error().kind == K::kUnavailable);
}

TEST_CASE("revocation source: names made only of invisible characters are refused",
          "[revocation_source][pg]") {
    Fx fx;
    for (const char* bad : {"\xE3\x85\xA4", "\xE2\xA0\x80", "\xE2\x80\x8A", "\xCD\x8F\xE2\x80\x8A",
                            "\xEF\xBE\xA0"}) {
        INFO(bad);
        auto b = rstest::valid_body();
        b["name"] = bad;
        CHECK(refused(fx, b).param == "name");
    }
}

TEST_CASE("RevocationSourceStore: the OpenAPI PUT documents the 409", "[revocation_source][openapi]") {
    // The route returns 409 for a stale expected_config_version; the spec must say so.
    const auto spec = json::parse(yuzu::server::openapi_spec_json());
    const auto& put = spec["paths"]["/crypto/revocation-sources/{id}"]["put"]["responses"];
    CHECK(put.contains("409"));
    CHECK(put.contains("503"));
}

// ─── round 5: one three-state outcome for every consumer, no cache poisoning, honest retry ───

#include "resolver_errors.hpp"

TEST_CASE("resolver error codes: only NXDOMAIN / NODATA are an ANSWER, everything else a failure",
          "[revocation_source][resolver]") {
    using yuzu::server::net::resolver_code_is_no_data;
#ifndef _WIN32
    CHECK(resolver_code_is_no_data(EAI_NONAME));
    CHECK_FALSE(resolver_code_is_no_data(EAI_AGAIN));
    CHECK_FALSE(resolver_code_is_no_data(EAI_FAIL));
    CHECK_FALSE(resolver_code_is_no_data(EAI_MEMORY));
    CHECK_FALSE(resolver_code_is_no_data(EAI_SYSTEM));
#else
    CHECK(resolver_code_is_no_data(11001)); // WSAHOST_NOT_FOUND
    CHECK(resolver_code_is_no_data(11004)); // WSANO_DATA
    CHECK_FALSE(resolver_code_is_no_data(11002)); // WSATRY_AGAIN
#endif
    CHECK_FALSE(resolver_code_is_no_data(0));
}

TEST_CASE("NAT64 cache constants are pinned", "[revocation_source][resolver]") {
    namespace net = yuzu::server::net;
    static_assert(net::kMaxDiscoveredNat64Prefixes == 64);
    static_assert(net::kNat64PositiveTtl == std::chrono::minutes{10});
    static_assert(net::kNat64NegativeTtl == std::chrono::minutes{1});
    // Exactly 64 prefixes fit; 65 do not.
    const auto build = [](int n) {
        net::Nat64DiscoveryCache cache;
        return std::make_pair(net::discover_nat64_prefixes_cached(
                                  [n](std::vector<yuzu::server::oidc::egress::Ipv6>& out) {
                                      for (int i = 0; i < n; ++i) {
                                          yuzu::server::oidc::egress::Ipv6 a{};
                                          a[0] = 0x20; a[1] = 0x01; a[2] = 0x0d; a[3] = 0xb8;
                                          a[4] = static_cast<std::uint8_t>(i + 1);
                                          a[12] = 0xc0; a[15] = 0xaa; // 192.0.0.170 at /96
                                          out.push_back(a);
                                      }
                                      return net::Nat64LookupOutcome::kAnswered;
                                  },
                                  cache),
                              0);
    };
    const auto at_bound = build(64).first;
    CHECK_FALSE(at_bound.overflowed);
    CHECK(at_bound.prefixes.size() == 64);
    const auto over = build(65).first;
    CHECK(over.overflowed);
    CHECK(over.overflow_started); // logged once, on the transition
}

TEST_CASE("NAT64 cache: NXDOMAIN from one consumer and an answer from another do not flip each other",
          "[revocation_source][resolver][pg]") {
    namespace net = yuzu::server::net;
    DiscoveryRig rig;
    // The OIDC-side consumer sees NXDOMAIN for ipv4only.arpa: an ANSWER (no DNS64), not a failure.
    const auto oidc_like = [](std::vector<yuzu::server::oidc::egress::Ipv6>&) {
        return net::Nat64LookupOutcome::kAnsweredNone;
    };
    const auto first = net::discover_nat64_prefixes_cached(oidc_like, rig.cache);
    CHECK(first.ever_answered);
    CHECK_FALSE(first.stale);
    // The registration consumer, with the cache still fresh, sees an answered state (no 503)...
    rig.lookup = failing(net::ResolveStatus::kNotFound);
    auto dns = rstest::default_dns();
    auto env = rstest::fake_env(dns);
    env.discover_nat64 = rig.fn();
    Fx fx(std::move(env));
    auto ok = fx.svc.validate_registration(with_url("http://v6.example.com/a.crl"));
    REQUIRE(ok.has_value());
    CHECK_FALSE(ok->classified_degraded); // no false nat64=stale
    // ...and after expiry, its own NXDOMAIN (kNotFound) is again an answer, not a failure.
    rig.expire();
    ok = fx.svc.validate_registration(with_url("http://v6.example.com/a.crl"));
    REQUIRE(ok.has_value());
    CHECK_FALSE(ok->classified_degraded);
    // An interleaved real failure IS stale, and only then.
    rig.expire();
    rig.lookup = failing();
    ok = fx.svc.validate_registration(with_url("http://v6.example.com/a.crl"));
    REQUIRE(ok.has_value());
    CHECK(ok->classified_degraded);
}

TEST_CASE("NAT64 cache: a clamped or busy lookup does not poison what another consumer reads",
          "[revocation_source][resolver]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    DiscoveryRig rig;
    auto latch = std::make_shared<Latch>();
    rig.lookup = [latch](const std::string&) -> net::ResolveResult {
        latch->wait();
        return {net::ResolveStatus::kOk, {"2001:db8:122:344::c000:aa"}};
    };
    // A budget below a full lookup that times out is INCONCLUSIVE: failed for this call only.
    auto pool = std::make_shared<net::ResolverPool>(1);
    const auto d = rs::discover_nat64(10ms, rig.lookup, rig.cache, pool);
    CHECK(d.looked_up);
    CHECK_FALSE(d.answered_now);
    CHECK(d.stale);
    {
        std::lock_guard lk(rig.cache.mu);
        CHECK_FALSE(rig.cache.filled);       // no negative entry...
        CHECK_FALSE(rig.cache.last_failed);  // ...no failure flag...
        CHECK(rig.cache.expires == std::chrono::steady_clock::time_point{}); // ...no TTL
    }
    CHECK(rig.cache.stats.inconclusive.load() == 1);
    CHECK(rig.cache.stats.failed.load() == 0);
    // The next consumer, with a fair budget, does its own lookup and learns the prefix.
    latch->release();
    for (int i = 0; i < 400 && pool->in_flight.load() > 0; ++i) // the abandoned worker finishes
        std::this_thread::sleep_for(10ms);
    rig.lookup = answering({kPref1});
    const auto fair = rs::discover_nat64(5s, rig.lookup, rig.cache, pool);
    CHECK(fair.answered_now);
    CHECK(fair.prefixes.size() == 1);
}

TEST_CASE("NAT64 discovery failure: the retry hint matches the negative cache, overflow is loud",
          "[revocation_source][resolver][pg]") {
    namespace net = yuzu::server::net;
    DiscoveryRig rig;
    rig.lookup = failing();
    std::vector<std::string> degrades;
    auto env = rstest::fake_env(rstest::default_dns(), {.degrades = &degrades});
    env.discover_nat64 = rig.fn();
    {
        Fx fx(std::move(env));
        fx.admin(false);
        auto b = rstest::valid_body();
        b["crl_urls"] = json::array({rstest::url_entry("http://v6.example.com/a.crl", {"public"})});
        auto r = fx.rest_post(b);
        REQUIRE(r->status == 503);
        const auto ra = data_of(*r)["error"]["retry_after_ms"].get<std::int64_t>();
        CHECK(ra >= 55000); // ~ the 60 s negative cache, not a blind 5 s
        CHECK(ra <= 60000);
        // MCP carries the same hint.
        auto m = fx.h.mcp_call_tool_approved(kRegister, b);
        CHECK(mcp_error_code(*m) == yuzu::server::mcp::kInternalError);
        CHECK(json::parse(m->body)["error"]["data"]["retry_after_ms"].get<std::int64_t>() >= 55000);
    }
    // Overflow: a distinct reason, a 60 s hint, one log transition and a counter of refusals.
    DiscoveryRig big;
    std::vector<std::string> many;
    for (int i = 0; i < 65; ++i) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "2001:db8:%x:1::c000:aa", i + 1);
        many.emplace_back(buf);
    }
    big.lookup = answering(many);
    std::vector<std::string> degrades2;
    auto env2 = rstest::fake_env(rstest::default_dns(), {.degrades = &degrades2});
    env2.discover_nat64 = big.fn();
    Fx fx2(std::move(env2));
    fx2.admin(false);
    auto b = rstest::valid_body();
    b["crl_urls"] = json::array({rstest::url_entry("http://v6.example.com/a.crl", {"public"})});
    auto r = fx2.rest_post(b);
    REQUIRE(r->status == 503);
    CHECK(data_of(*r)["error"]["retry_after_ms"] == 60000);
    CHECK(std::ranges::count(degrades2, "nat64_discovery_overflow") == 1);
    (void)fx2.rest_post(b);
    CHECK(big.cache.stats.overflow_refusals.load() >= 1);
    // The transition is reported once: the flag stays set until an answer fits.
    CHECK(big.cache.overflow_logged);
}

// ─── round 6: one resolver / one mapping, and the outcome-unknown arm ───────────────────────

#include "nat64_probe.hpp"

TEST_CASE("NAT64 probe: every resolver status maps to exactly one shared outcome",
          "[revocation_source][resolver]") {
    namespace net = yuzu::server::net;
    using O = net::Nat64LookupOutcome;
    using S = net::ResolveStatus;
    std::vector<yuzu::server::oidc::egress::Ipv6> out;
    const auto map = [&](S st, std::vector<std::string> addrs, bool clamped) {
        out.clear();
        return net::nat64_outcome_from_resolve({st, std::move(addrs)}, clamped, out);
    };
    CHECK(map(S::kOk, {"2001:db8:122:344::c000:aa"}, false) == O::kAnswered);
    CHECK(out.size() == 1);
    CHECK(map(S::kOk, {"192.0.0.170"}, false) == O::kAnsweredNone); // A-only: no DNS64 here
    CHECK(map(S::kNotFound, {}, false) == O::kAnsweredNone);        // NXDOMAIN / NODATA: an ANSWER
    CHECK(map(S::kTemporary, {}, false) == O::kFailed);             // EAI_AGAIN / FAIL / SYSTEM
    CHECK(map(S::kTimeout, {}, false) == O::kFailed);               // a full-budget timeout
    CHECK(map(S::kTimeout, {}, true) == O::kInconclusive);          // a clamped budget: not the resolver's fault
    CHECK(map(S::kBusy, {}, false) == O::kInconclusive);            // no capacity: nothing was asked
    CHECK(map(S::kBusy, {}, true) == O::kInconclusive);
}

TEST_CASE("RevocationSource: an unknown write outcome is a retryable 503 / -32603 asking for a re-read",
          "[revocation_source][mcp][pg]") {
    using SK = RevocationSourceStoreError::Kind;
    Fx fx;
    fx.admin(false);
    const auto id = fx.seed("Unknown CA");
    std::string op_seen;
    fx.store.set_write_fault_for_test([&](std::string_view op) -> std::optional<SK> {
        op_seen = std::string(op);
        return SK::kOutcomeUnknown;
    });

    // REST: every write maps to 503 + 5000 ms + a re-read remediation, and is audited `failure`.
    auto r = fx.rest_post(rstest::valid_body("Another unknown CA"));
    REQUIRE(r->status == 503);
    CHECK(op_seen == "create");
    CHECK(data_of(*r)["error"]["retry_after_ms"] == 5000);
    CHECK_THAT(data_of(*r)["error"]["remediation"].get<std::string>(), ContainsSubstring("GET"));
    CHECK(fx.rest_delete(id)->status == 503);
    CHECK(op_seen == "remove");
    CHECK(fx.rest_reset(id)->status == 503);
    CHECK(op_seen == "reset_high_water");
    CHECK(fx.rest_put(id, rstest::valid_body("Unknown CA"))->status == 503);
    CHECK(op_seen == "replace");
    for (const char* verb : {"crypto.revocation_source.register", "crypto.revocation_source.remove"}) {
        const auto res = fx.results(verb);
        REQUIRE_FALSE(res.empty());
        CHECK(res.back() == "failure"); // an unknown outcome is a FAULT, not a caller refusal
    }

    // MCP: -32603 with a retry hint and a re-read remediation.
    auto m = fx.h.mcp_call_tool_approved(kRemove, {{"id", id}});
    CHECK(mcp_error_code(*m) == yuzu::server::mcp::kInternalError);
    const auto data = json::parse(m->body)["error"]["data"];
    CHECK(data["retry_after_ms"].get<std::int64_t>() == 5000);
    CHECK_THAT(data["remediation"].get<std::string>(), ContainsSubstring("get_revocation_source"));

    // Service level: the classifier table row.
    fx.store.set_write_fault_for_test(nullptr);
    fx.store.set_write_fault_for_test(
        [](std::string_view) -> std::optional<SK> { return SK::kOutcomeUnknown; });
    const auto sv = fx.svc.remove(id);
    REQUIRE_FALSE(sv.has_value());
    CHECK(sv.error().kind == rs::ServiceError::Kind::kOutcomeUnknown);
    CHECK(std::string(rs::audit_result_for(sv.error())) == "failure");
    // Nothing was written under any of them.
    fx.store.set_write_fault_for_test(nullptr);
    CHECK(fx.store.get(id).has_value());
    CHECK(fx.store.list()->size() == 1);
}

// ─── round 7: single-flight discovery, and the kind -> status table ─────────────────────────

TEST_CASE("NAT64 discovery is single-flight: N concurrent callers with a blocked resolver use ONE lookup",
          "[revocation_source][resolver]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    DiscoveryRig rig;
    auto pool = std::make_shared<net::ResolverPool>(1); // the production discovery pool shape
    auto latch = std::make_shared<Latch>();
    std::atomic<int> lookups{0};
    rig.lookup = [latch, &lookups](const std::string&) -> net::ResolveResult {
        ++lookups;
        latch->wait();
        return {net::ResolveStatus::kOk, {kPref1}};
    };
    constexpr int kCallers = 12;
    std::vector<std::future<net::Nat64Discovery>> calls;
    for (int i = 0; i < kCallers; ++i)
        calls.push_back(std::async(std::launch::async, [&] {
            // A full per-lookup budget (not clamped); the leader's lookup is blocked, so every
            // caller ends inconclusive at ITS OWN budget rather than starting a lookup of its own.
            return rs::discover_nat64(300ms, rig.lookup, rig.cache, pool);
        }));
    std::vector<net::Nat64Discovery> results;
    for (auto& f : calls) {
        REQUIRE(f.wait_for(20s) == std::future_status::ready); // none hangs past its budget
        results.push_back(f.get());
    }
    CHECK(lookups.load() == 1); // exactly one lookup, one worker, one slot, ever started
    CHECK(pool->in_flight.load() == 1); // ...and it is still outstanding (the resolver is hung)
    for (const auto& r : results) {
        CHECK_FALSE(r.answered_now); // nobody got an answer while the resolver was blocked
        CHECK(r.stale);
    }
    // Release: the flight finishes, ONE answer fills the cache, and a late caller reads it.
    latch->release();
    for (int i = 0; i < 400 && pool->in_flight.load() > 0; ++i)
        std::this_thread::sleep_for(10ms);
    const auto after = rs::discover_nat64(2s, rig.lookup, rig.cache, pool);
    CHECK(after.prefixes.size() == 1);
    // The abandoned flight's late answer is discarded (nobody was waiting); the late caller made
    // its own, single, lookup.
    CHECK(lookups.load() == 2);
}

TEST_CASE("NAT64 discovery: waiters share the leader's answer (no expiry stampede)",
          "[revocation_source][resolver]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    DiscoveryRig rig;
    auto pool = std::make_shared<net::ResolverPool>(1);
    std::atomic<int> lookups{0};
    rig.lookup = [&lookups](const std::string&) -> net::ResolveResult {
        ++lookups;
        std::this_thread::sleep_for(150ms);
        return {net::ResolveStatus::kOk, {kPref1}};
    };
    std::vector<std::future<net::Nat64Discovery>> calls;
    for (int i = 0; i < 8; ++i)
        calls.push_back(std::async(std::launch::async, [&] {
            return rs::discover_nat64(5s, rig.lookup, rig.cache, pool);
        }));
    for (auto& f : calls) {
        const auto d = f.get();
        CHECK(d.ever_answered);
        CHECK(d.prefixes.size() == 1);
    }
    CHECK(lookups.load() == 1);
}

TEST_CASE("RevocationSource: the REST and MCP kind -> status table is locked",
          "[revocation_source][mcp][pg]") {
    using SK = RevocationSourceStoreError::Kind;
    Fx fx;
    fx.admin(false);
    const auto id = fx.seed("Table CA");
    // store fault -> service kind -> REST status / MCP code, for the register route.
    struct Row {
        SK fault;
        int rest_status;
        int mcp_code;
    };
    const std::vector<Row> rows = {
        {SK::kOutcomeUnknown, 503, yuzu::server::mcp::kInternalError},
        {SK::kQueryError, 503, yuzu::server::mcp::kInternalError},
        {SK::kPoolAcquireTimeout, 503, yuzu::server::mcp::kInternalError},
        {SK::kLimitReached, 409, yuzu::server::mcp::kInvalidParams},
        {SK::kConflict, 409, yuzu::server::mcp::kInvalidParams},
        {SK::kInvalidInput, 400, yuzu::server::mcp::kInvalidParams},
    };
    for (const auto& row : rows) {
        INFO("fault " << static_cast<int>(row.fault));
        fx.store.set_write_fault_for_test([&](std::string_view) -> std::optional<SK> { return row.fault; });
        auto rest = fx.rest_post(rstest::valid_body("Faulted CA"));
        CHECK(rest->status == row.rest_status);
        if (row.rest_status == 503)
            CHECK(data_of(*rest)["error"]["retry_after_ms"] == 5000);
        else
            CHECK(data_of(*rest)["error"]["retry_after_ms"].is_null());
        auto mcp = fx.h.mcp_call_tool_approved(kRegister, rstest::valid_body("Faulted CA"));
        CHECK(mcp_error_code(*mcp) == row.mcp_code);
    }
    // The not-found row on the read/remove side.
    fx.store.set_write_fault_for_test(nullptr);
    CHECK(fx.rest_get(id + 1000)->status == 404);
    CHECK(mcp_error_code(*fx.h.mcp_call_tool(kGet, {{"id", id + 1000}})) ==
          yuzu::server::mcp::kInvalidParams);
}

// ─── round 8: the flight is released on every exit; waiters never start a second lookup ─────

TEST_CASE("NAT64 discovery: an allocation failure in the leader releases the single flight",
          "[revocation_source][resolver]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    DiscoveryRig rig;
    auto pool = std::make_shared<net::ResolverPool>(1);
    rig.lookup = answering({kPref1});
    // The leader's parse/merge step throws bad_alloc (injected right after the lookup returns).
    rig.cache.test_fault_after_lookup = [] { throw std::bad_alloc(); };
    const auto d = rs::discover_nat64(2s, rig.lookup, rig.cache, pool);
    CHECK(d.stale);            // inconclusive for this call
    CHECK_FALSE(d.answered_now);
    {
        std::lock_guard lk(rig.cache.mu);
        CHECK_FALSE(rig.cache.inflight); // NOT wedged: the flag was cleared by the guard
        CHECK_FALSE(rig.cache.filled);   // and nothing half-written is served as fresh
    }
    // The next caller is not blocked behind a dead flight: it looks, answers and learns.
    rig.cache.test_fault_after_lookup = nullptr;
    for (int i = 0; i < 400 && pool->in_flight.load() > 0; ++i)
        std::this_thread::sleep_for(10ms);
    const auto next = rs::discover_nat64(2s, rig.lookup, rig.cache, pool);
    CHECK(next.answered_now);
    CHECK(next.prefixes.size() == 1);
}

TEST_CASE("NAT64 discovery: a waiter whose leader ended inconclusive does not start its own lookup",
          "[revocation_source][resolver]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    DiscoveryRig rig;
    auto pool = std::make_shared<net::ResolverPool>(1);
    std::atomic<int> lookups{0};
    // The leader's lookup is slow, then reports busy-equivalent (inconclusive via a clamped
    // timeout): 40 ms budget against a 300 ms lookup.
    rig.lookup = [&lookups](const std::string&) -> net::ResolveResult {
        ++lookups;
        std::this_thread::sleep_for(300ms);
        return {net::ResolveStatus::kOk, {kPref1}};
    };
    auto leader = std::async(std::launch::async,
                             [&] { return rs::discover_nat64(40ms, rig.lookup, rig.cache, pool); });
    std::this_thread::sleep_for(20ms); // the leader holds the flight
    const auto waiter = rs::discover_nat64(5s, rig.lookup, rig.cache, pool);
    const auto l = leader.get();
    CHECK(l.stale);
    // The leader ended inconclusive (its clamped budget expired) and wrote nothing, so the waiter
    // must NOT run a second full-budget lookup of its own: it is inconclusive too.
    CHECK(lookups.load() == 1);
    CHECK(waiter.stale);
    CHECK_FALSE(waiter.answered_now);
}

TEST_CASE("RevocationSource: every mutating route maps faults the same way on REST and MCP",
          "[revocation_source][mcp][pg]") {
    using SK = RevocationSourceStoreError::Kind;
    Fx fx;
    fx.admin(false);
    const auto id = fx.seed("Routes CA");
    std::unique_ptr<httplib::Response> last;
    std::unique_ptr<httplib::Response> last_rest;
    const auto rest_retry_of = [&]() {
        const auto d = json::parse(last_rest->body)["error"]["retry_after_ms"];
        return d.is_null() ? std::int64_t{-1} : d.get<std::int64_t>();
    };
    struct Route {
        const char* name;
        std::function<int()> rest;
        std::function<int()> mcp;
    };
    const std::vector<Route> routes = {
        {"register", [&] { last_rest = fx.rest_post(rstest::valid_body("Faulted")); return last_rest->status; },
         [&] { last = fx.h.mcp_call_tool_approved(kRegister, rstest::valid_body("Faulted")); return mcp_error_code(*last); }},
        {"update", [&] { last_rest = fx.rest_put(id, rstest::valid_body("Routes CA")); return last_rest->status; },
         [&] {
             json u = rstest::valid_body("Routes CA");
             u["id"] = id;
             u["expected_config_version"] = 1;
             last = fx.h.mcp_call_tool_approved(kUpdate, u);
             return mcp_error_code(*last);
         }},
        {"remove", [&] { last_rest = fx.rest_delete(id); return last_rest->status; },
         [&] { last = fx.h.mcp_call_tool_approved(kRemove, {{"id", id}}); return mcp_error_code(*last); }},
        {"reset", [&] { last_rest = fx.rest_reset(id); return last_rest->status; },
         [&] { last = fx.h.mcp_call_tool_approved(kReset, {{"id", id}}); return mcp_error_code(*last); }},
    };
    struct Expect {
        SK fault;
        int rest_status;
        int mcp_code;
        std::int64_t retry; // 5000 for a retryable 503, -1 (null) for everything else
    };
    const int kInternal = yuzu::server::mcp::kInternalError;
    const int kInvalid = yuzu::server::mcp::kInvalidParams;
    // EVERY store-fault kind, on EVERY mutating route: status, MCP code and BOTH retry hints.
    const std::vector<Expect> table = {
        {SK::kNotOpen, 503, kInternal, 5000},
        {SK::kPoolAcquireTimeout, 503, kInternal, 5000},
        {SK::kQueryError, 503, kInternal, 5000},
        {SK::kOutcomeUnknown, 503, kInternal, 5000},
        {SK::kInvalidInput, 400, kInvalid, -1},
        {SK::kNotFound, 404, kInvalid, -1},
        {SK::kConflict, 409, kInvalid, -1},
        {SK::kLimitReached, 409, kInvalid, -1},
        {SK::kVersionConflict, 409, kInvalid, -1},
        {SK::kSubjectChanged, 400, kInvalid, -1},
        {SK::kBadResetTime, 400, kInvalid, -1},
    };
    for (const auto& route : routes) {
        for (const auto& e : table) {
            INFO(route.name << " fault " << static_cast<int>(e.fault));
            fx.store.set_write_fault_for_test(
                [k = e.fault](std::string_view) -> std::optional<SK> { return k; });
            CHECK(route.rest() == e.rest_status);
            CHECK(rest_retry_of() == e.retry);
            CHECK(route.mcp() == e.mcp_code);
            const auto mr = json::parse(last->body)["error"]["data"]["retry_after_ms"];
            CHECK((mr.is_null() ? std::int64_t{-1} : mr.get<std::int64_t>()) == e.retry);
        }
    }
    fx.store.set_write_fault_for_test(nullptr);
    CHECK(fx.store.get(id)->config_version == 1); // no fault run changed anything
}

// ─── round 9: mutation guards for the flight release and the clamped-budget rule ─────────────

TEST_CASE("NAT64 discovery: finishing the flight WAKES a waiter well before its own budget",
          "[revocation_source][resolver]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    DiscoveryRig rig;
    auto pool = std::make_shared<net::ResolverPool>(1);
    rig.lookup = [](const std::string&) -> net::ResolveResult {
        std::this_thread::sleep_for(100ms);
        return {net::ResolveStatus::kOk, {kPref1}};
    };
    auto leader = std::async(std::launch::async,
                             [&] { return rs::discover_nat64(5s, rig.lookup, rig.cache, pool); });
    std::this_thread::sleep_for(20ms); // the leader holds the flight
    const auto t0 = std::chrono::steady_clock::now();
    const auto waiter = rs::discover_nat64(5s, rig.lookup, rig.cache, pool);
    const auto waited = std::chrono::steady_clock::now() - t0;
    (void)leader.get();
    // The waiter shares the leader's answer as soon as the flight ends. Without the guard's
    // notify it would sit out its full 5 s budget.
    CHECK(waited < 1s);
    CHECK(waiter.prefixes.size() == 1);
}

TEST_CASE("NAT64 discovery: a CLAMPED leader's timeout leaves the cache untouched; an unclamped caller then looks",
          "[revocation_source][resolver]") {
    namespace net = yuzu::server::net;
    using namespace std::chrono_literals;
    DiscoveryRig rig;
    auto pool = std::make_shared<net::ResolverPool>(1);
    auto latch = std::make_shared<Latch>();
    std::atomic<int> lookups{0};
    rig.lookup = [latch, &lookups](const std::string&) -> net::ResolveResult {
        ++lookups;
        latch->wait();
        return {net::ResolveStatus::kOk, {kPref1}};
    };
    // A budget below a full per-lookup budget (5 s) that times out: inconclusive, NOT a failure.
    const auto clamped = rs::discover_nat64(30ms, rig.lookup, rig.cache, pool);
    CHECK(clamped.stale);
    {
        std::lock_guard lk(rig.cache.mu);
        CHECK_FALSE(rig.cache.filled);
        CHECK_FALSE(rig.cache.last_failed);
        CHECK(rig.cache.expires == std::chrono::steady_clock::time_point{});
    }
    CHECK(rig.cache.stats.failed.load() == 0);
    CHECK(rig.cache.stats.inconclusive.load() == 1);
    // Let the abandoned worker finish (its late answer is discarded), then an UNCLAMPED caller
    // (a full 5 s budget) performs a lookup of its own and its timeout WOULD be a recorded failure.
    latch->release();
    for (int i = 0; i < 400 && pool->in_flight.load() > 0; ++i)
        std::this_thread::sleep_for(10ms);
    const auto fair = rs::discover_nat64(5s, rig.lookup, rig.cache, pool);
    CHECK(lookups.load() == 2);
    CHECK(fair.answered_now);
    CHECK(fair.prefixes.size() == 1);
}
