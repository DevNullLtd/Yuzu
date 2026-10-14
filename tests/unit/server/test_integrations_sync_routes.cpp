/**
 * test_integrations_sync_routes.cpp — the six Integrations read fragments and
 * the controller-script route (SYS-5), driven through TestRouteSink with
 * injected closures. No Postgres, no sockets, no sleeps.
 *
 * Also pins the controller script itself (kYuzuIntegrationsSyncJs): the
 * properties the security review depends on are string-level facts about that
 * file, so they are asserted here and mutation-probed.
 */

#include "integrations_sync_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <string>
#include <vector>

namespace yuzu::server {
extern const std::string kYuzuIntegrationsSyncJs;
}

using namespace yuzu::server;
using namespace yuzu::server::integrations;
using Catch::Matchers::ContainsSubstring;

namespace {

struct Harness {
    test::TestRouteSink sink;
    bool admin{true};
    bool audit_ok{true};
    int admin_calls{0};
    int users_reads{0};
    std::vector<std::string> audits;
    std::vector<int> list_limits;

    std::expected<std::vector<Webhook>, ReadError> webhooks{std::vector<Webhook>{}};
    std::optional<Webhook> webhook_row;
    std::optional<std::vector<WebhookDelivery>> deliveries{std::vector<WebhookDelivery>{}};
    std::expected<std::vector<OffloadTarget>, ReadError> offload{std::vector<OffloadTarget>{}};
    std::expected<std::optional<OffloadTarget>, ReadError> offload_one{std::optional<OffloadTarget>{}};
    std::optional<std::vector<OffloadDelivery>> off_deliveries{std::vector<OffloadDelivery>{}};
    std::expected<SyncStatus, ReadError> status{SyncStatus{}};
    std::expected<std::int64_t, ReadError> user_count{std::int64_t{0}};
    std::expected<std::vector<DirectoryGroup>, ReadError> groups{std::vector<DirectoryGroup>{}};
    std::expected<std::vector<DirectoryUser>, ReadError> users{std::vector<DirectoryUser>{}};
    std::expected<std::vector<std::string>, ReadError> roles{std::vector<std::string>{"Operator"}};

    Harness() {
        Deps d;
        d.admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            ++admin_calls;
            if (!admin)
                res.status = 403;
            return admin;
        };
        d.audit_read = [this](const httplib::Request&, const std::string& a, const std::string& r,
                              const std::string& tt, const std::string& ti, const std::string&) {
            audits.push_back(a + "|" + r + "|" + tt + "|" + ti);
            return audit_ok;
        };
        d.webhooks_list = [this](int limit) {
            list_limits.push_back(limit);
            return webhooks;
        };
        d.webhook_get = [this](std::int64_t) { return webhook_row; };
        d.webhook_deliveries = [this](std::int64_t, int) { return deliveries; };
        d.offload_list = [this](int limit) {
            list_limits.push_back(limit);
            return offload;
        };
        d.offload_get = [this](std::int64_t) { return offload_one; };
        d.offload_deliveries = [this](std::int64_t, int) { return off_deliveries; };
        d.directory_status = [this] { return status; };
        d.directory_user_count = [this] { return user_count; };
        d.directory_groups = [this] { return groups; };
        d.directory_users = [this] {
            ++users_reads;
            return users;
        };
        d.role_names = [this] { return roles; };
        register_integrations_sync_routes(sink, std::move(d));
    }

    std::unique_ptr<httplib::Response> get(const std::string& path) { return sink.Get(path); }
};

Webhook wh(std::int64_t id) {
    Webhook w;
    w.id = id;
    w.url = "https://h.example.invalid/x";
    return w;
}

bool has(const std::string& s, std::string_view n) { return s.find(n) != std::string::npos; }

} // namespace

TEST_CASE("sync routes: every fragment is admin-gated and a denial reads nothing",
          "[integrations][routes]") {
    Harness h;
    h.admin = false;
    for (const char* p : {"/fragments/settings/webhooks", "/fragments/settings/webhooks/1/deliveries",
                          "/fragments/settings/offload-targets",
                          "/fragments/settings/offload-targets/1/deliveries",
                          "/fragments/settings/directory-sync",
                          "/fragments/settings/directory-sync/users"}) {
        auto res = h.get(p);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(res->body.empty());
    }
    CHECK(h.admin_calls == 6);
    CHECK(h.users_reads == 0);
    CHECK(h.audits.empty());
    CHECK(h.list_limits.empty());
}

TEST_CASE("sync routes: lists request one row past the shown cap", "[integrations][routes]") {
    Harness h;
    h.get("/fragments/settings/webhooks");
    h.get("/fragments/settings/offload-targets");
    REQUIRE(h.list_limits.size() == 2);
    CHECK(h.list_limits[0] == 101);
    CHECK(h.list_limits[1] == 101);
}

TEST_CASE("sync routes: responses are HTML, 200 and no-store, even when degraded",
          "[integrations][routes]") {
    Harness h;
    h.webhooks = std::unexpected(ReadError::failed);
    auto res = h.get("/fragments/settings/webhooks");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Cache-Control") == "no-store");
    CHECK_THAT(res->get_header_value("Content-Type"), ContainsSubstring("text/html"));
    CHECK_THAT(res->body, ContainsSubstring("Webhooks could not be read."));
    CHECK(!has(res->body, "No webhooks configured"));
}

TEST_CASE("sync routes: webhook list populated and per-row last delivery",
          "[integrations][routes]") {
    Harness h;
    h.webhooks = std::vector<Webhook>{wh(4)};
    WebhookDelivery d;
    d.status_code = 200;
    d.delivered_at = 1760000000;
    h.deliveries = std::vector<WebhookDelivery>{d};
    auto res = h.get("/fragments/settings/webhooks");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("https://h.example.invalid</span>"));
    CHECK_THAT(res->body, ContainsSubstring("2025-10-09 08:53 UTC"));
}

TEST_CASE("sync routes: a failed history read marks the row unknown, not empty",
          "[integrations][routes]") {
    Harness h;
    h.webhooks = std::vector<Webhook>{wh(4)};
    h.deliveries = std::nullopt;
    auto res = h.get("/fragments/settings/webhooks");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("Unknown (history could not be read)"));
}

TEST_CASE("sync routes: webhook deliveries distinguish failed, empty and missing",
          "[integrations][routes]") {
    Harness h;
    h.deliveries = std::nullopt;
    CHECK_THAT(h.get("/fragments/settings/webhooks/9/deliveries")->body,
               ContainsSubstring("Delivery history could not be read."));

    h.deliveries = std::vector<WebhookDelivery>{};
    h.webhook_row = std::nullopt;
    CHECK_THAT(h.get("/fragments/settings/webhooks/9/deliveries")->body,
               ContainsSubstring("The webhook was not found."));

    h.webhook_row = wh(9);
    CHECK_THAT(h.get("/fragments/settings/webhooks/9/deliveries")->body,
               ContainsSubstring("No deliveries recorded."));
}

TEST_CASE("sync routes: an id that overflows int64 is not found, not a throw",
          "[integrations][routes]") {
    Harness h;
    auto a = h.get("/fragments/settings/webhooks/99999999999999999999999/deliveries");
    REQUIRE(a);
    CHECK(a->status == 200);
    CHECK_THAT(a->body, ContainsSubstring("The webhook was not found."));
    auto b = h.get("/fragments/settings/offload-targets/99999999999999999999999/deliveries");
    REQUIRE(b);
    CHECK_THAT(b->body, ContainsSubstring("The offload target was not found."));
}

TEST_CASE("sync routes: offload deliveries use the checked get, degraded is not not-found",
          "[integrations][routes]") {
    Harness h;
    h.offload_one = std::unexpected(ReadError::failed);
    CHECK_THAT(h.get("/fragments/settings/offload-targets/2/deliveries")->body,
               ContainsSubstring("could not be read"));
    h.offload_one = std::optional<OffloadTarget>{};
    CHECK_THAT(h.get("/fragments/settings/offload-targets/2/deliveries")->body,
               ContainsSubstring("The offload target was not found."));
    h.offload_one = std::optional<OffloadTarget>{OffloadTarget{}};
    CHECK_THAT(h.get("/fragments/settings/offload-targets/2/deliveries")->body,
               ContainsSubstring("No deliveries recorded."));
    h.off_deliveries = std::nullopt;
    CHECK_THAT(h.get("/fragments/settings/offload-targets/2/deliveries")->body,
               ContainsSubstring("could not be read"));
}

TEST_CASE("sync routes: directory panel reads status, count, groups and roles",
          "[integrations][routes]") {
    Harness h;
    SyncStatus st;
    st.status = "completed";
    st.last_sync_at = 1760000000;
    h.status = st;
    h.user_count = std::int64_t{42};
    auto res = h.get("/fragments/settings/directory-sync");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("<span>Users synced</span><b>42</b>"));
    CHECK(h.users_reads == 0); // the user list is never read for the panel
}

TEST_CASE("sync routes: users fragment is audited and fails closed", "[integrations][routes]") {
    Harness h;
    DirectoryUser u;
    u.display_name = "Ada";
    h.users = std::vector<DirectoryUser>{u};
    h.user_count = std::int64_t{1};
    auto ok = h.get("/fragments/settings/directory-sync/users");
    REQUIRE(ok);
    CHECK_THAT(ok->body, ContainsSubstring("Ada"));
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0] == "directory.users.view|success|Directory|");

    Harness closed;
    closed.audit_ok = false;
    closed.users = std::vector<DirectoryUser>{u};
    auto res = closed.get("/fragments/settings/directory-sync/users");
    REQUIRE(res);
    CHECK_THAT(res->body, ContainsSubstring("Directory users are not shown."));
    CHECK(!has(res->body, "Ada"));
    CHECK(closed.users_reads == 0); // data is not even read without the audit row
}

TEST_CASE("sync routes: controller script is served no-store", "[integrations][routes]") {
    Harness h;
    auto res = h.get("/static/yuzu-integrations-sync.js");
    REQUIRE(res);
    CHECK(res->get_header_value("Cache-Control").find("no-store") != std::string::npos);
    CHECK_THAT(res->get_header_value("Content-Type"), ContainsSubstring("javascript"));
    CHECK(res->body == kYuzuIntegrationsSyncJs);
}

// ── controller script pins ───────────────────────────────────────────────────

TEST_CASE("controller script: no eval, no inline handler, no innerHTML of server data",
          "[integrations][js]") {
    const auto& js = kYuzuIntegrationsSyncJs;
    REQUIRE(js.size() > 2000);
    CHECK(!has(js, "innerHTML"));
    CHECK(!has(js, "outerHTML"));
    CHECK(!has(js, "insertAdjacentHTML"));
    CHECK(!has(js, "document.write"));
    CHECK(!has(js, "eval("));
    CHECK(!has(js, "new Function"));
    CHECK(!has(js, "hx-on"));
    CHECK(!has(js, "setAttribute('on"));
    CHECK(!has(js, "localStorage"));
    CHECK(!has(js, "sessionStorage"));
}

TEST_CASE("controller script: every write goes to an existing JSON route", "[integrations][js]") {
    const auto& js = kYuzuIntegrationsSyncJs;
    CHECK(has(js, "'/api/webhooks'"));
    CHECK(has(js, "'/api/webhooks/'"));
    CHECK(has(js, "'/api/v1/offload-targets'"));
    CHECK(has(js, "'/api/v1/offload-targets/'"));
    CHECK(has(js, "'/api/directory/sync'"));
    CHECK(has(js, "'/api/directory/group-mappings'"));
    CHECK(has(js, "cache: 'no-store'"));
    CHECK(has(js, "credentials: 'same-origin'"));
    CHECK(has(js, "encodeURIComponent"));
}

TEST_CASE("controller script: secrets are cleared after every attempt", "[integrations][js]") {
    const auto& js = kYuzuIntegrationsSyncJs;
    CHECK(has(js, "function clearSecrets"));
    // The definition plus the two create handlers and the sync handler's settle step.
    std::size_t calls = 0;
    for (auto pos = js.find("clearSecrets(form)"); pos != std::string::npos;
         pos = js.find("clearSecrets(form)", pos + 1))
        ++calls;
    CHECK(calls == 4);
}

TEST_CASE("controller script: sync never re-posts and never double-submits", "[integrations][js]") {
    const auto& js = kYuzuIntegrationsSyncJs;
    CHECK(has(js, "var syncPending = false;"));
    CHECK(has(js, "if (syncPending) { return; }"));
    CHECK(has(js, "No answer was received. The sync may still be running on the server. Check Status."));
    CHECK(has(js, "A sync is already running."));
    // The only POST to the sync route is the one in syncDirectory.
    std::size_t n = 0;
    for (auto pos = js.find("'/api/directory/sync'"); pos != std::string::npos;
         pos = js.find("'/api/directory/sync'", pos + 1))
        ++n;
    CHECK(n == 1);
    // Tenant, client and secret are never persisted by the browser.
    CHECK(!has(js, "localStorage"));
}

TEST_CASE("controller script: mapping save compares the echo both ways", "[integrations][js]") {
    const auto& js = kYuzuIntegrationsSyncJs;
    CHECK(has(js, "Not saved: "));
    CHECK(has(js, "Not removed: "));
    CHECK(has(js, "notRemoved.push(c.group_id)"));
    CHECK(has(js, "echoed[c.group_id] !== c.role_name"));
}

TEST_CASE("controller script: destinations with userinfo or control bytes are refused",
          "[integrations][js]") {
    const auto& js = kYuzuIntegrationsSyncJs;
    CHECK(has(js, "if (u.username || u.password)"));
    CHECK(has(js, "CONTROL.test(value)"));
    CHECK(has(js, "window.confirm(text)"));
}
