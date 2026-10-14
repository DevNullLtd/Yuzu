/**
 * test_integrations_sync_render.cpp — pure renderer coverage for the
 * Integrations webhook / offload-target / directory-sync panels (SYS-5).
 * Every state of every panel: populated, empty, degraded-is-not-empty,
 * truncated, plus escaping, secret fields without a value, host-only display
 * and the confirm text that names the host and the data classes.
 */

#include "integrations_sync_render.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <string>

using namespace yuzu::server;
using namespace yuzu::server::integrations;
using Catch::Matchers::ContainsSubstring;

namespace {

constexpr const char* kXss = "<img src=x onerror=1>";

WebhookRow hook(std::int64_t id, std::string url, std::string events = "*", bool secret = false,
                bool enabled = true) {
    WebhookRow r;
    r.webhook.id = id;
    r.webhook.url = std::move(url);
    r.webhook.event_types = std::move(events);
    r.webhook.has_secret = secret;
    r.webhook.enabled = enabled;
    return r;
}

OffloadRow target(std::int64_t id, std::string name, std::string url) {
    OffloadRow r;
    r.target.id = id;
    r.target.name = std::move(name);
    r.target.url = std::move(url);
    r.target.auth_type = OffloadAuthType::Bearer;
    r.target.has_credential = true;
    r.target.batch_size = 5;
    return r;
}

bool contains(const std::string& s, std::string_view needle) {
    return s.find(needle) != std::string::npos;
}

DirectoryView ok_view() {
    SyncStatus st;
    st.provider = "entra";
    st.status = "completed";
    st.last_sync_at = 1760000000;
    st.user_count = 5;
    st.group_count = 2;
    DirectoryGroup g;
    g.id = "g-1";
    g.display_name = "SecOps";
    g.mapped_role = "Operator";
    return DirectoryView{st, std::int64_t{5}, std::vector<DirectoryGroup>{g},
                         std::vector<std::string>{"Administrator", "Operator", "Viewer"}};
}

} // namespace

// ── helpers ──────────────────────────────────────────────────────────────────

TEST_CASE("format_utc: epoch to a locale-free UTC stamp", "[integrations][render]") {
    CHECK(format_utc(0) == "Never");
    CHECK(format_utc(-5) == "Never");
    CHECK(format_utc(1760000000) == "2025-10-09 08:53 UTC");
    CHECK(format_utc(951782400) == "2000-02-29 00:00 UTC"); // leap day
}

TEST_CASE("clip_text: cuts on a UTF-8 boundary", "[integrations][render]") {
    CHECK(clip_text("short", 10) == "short");
    const std::string s = "ab\xC3\xA9\xC3\xA9"; // ab + two 2-byte chars
    CHECK(clip_text(s, 3) == "ab...");           // 3 would split the first e-acute
    CHECK(clip_text(std::string(500, 'x'), 300).size() == 303);
}

TEST_CASE("event catalogue: exactly the four events the server fires", "[integrations][render]") {
    const auto& c = event_catalogue();
    CHECK(c[0].id == "agent.registered");
    CHECK(c[1].id == "execution.completed");
    CHECK(c[2].id == "dex.signal");
    CHECK(c[3].id == "dex.blast_radius");
    for (const auto& e : c)
        CHECK_FALSE(e.data_class.empty());
}

// ── webhooks ─────────────────────────────────────────────────────────────────

TEST_CASE("webhooks: populated list shows host only, full URL on demand", "[integrations][render]") {
    std::vector<WebhookRow> rows{hook(7, "https://hooks.example.invalid/services/T0/B0/SECRETPATH",
                                      "agent.registered,dex.signal", true)};
    const auto html = render_webhooks(rows);
    CHECK_THAT(html, ContainsSubstring("https://hooks.example.invalid</span>"));
    // The path appears only inside the Show full URL disclosure.
    const auto summary = html.find("Show full URL");
    const auto secret = html.find("SECRETPATH");
    REQUIRE(summary != std::string::npos);
    REQUIRE(secret != std::string::npos);
    CHECK(secret > summary);
    CHECK_THAT(html, ContainsSubstring("Signed"));
    CHECK_THAT(html, ContainsSubstring("data-int-action=\"webhook-delete\""));
    CHECK_THAT(html, ContainsSubstring("data-id=\"7\""));
    CHECK_THAT(html, ContainsSubstring("/fragments/settings/webhooks/7/deliveries"));
}

TEST_CASE("webhooks: empty list is the true-empty wording", "[integrations][render]") {
    const auto html = render_webhooks(std::vector<WebhookRow>{});
    CHECK_THAT(html, ContainsSubstring("No webhooks configured. Events are not sent to any URL."));
    CHECK(!contains(html, "could not be read"));
}

TEST_CASE("webhooks: a failed read is never rendered as empty", "[integrations][render]") {
    const auto failed = render_webhooks(std::unexpected(ReadError::failed));
    CHECK_THAT(failed, ContainsSubstring("Webhooks could not be read."));
    CHECK_THAT(failed, ContainsSubstring("This is not an empty list."));
    CHECK(!contains(failed, "No webhooks configured"));
    CHECK(!contains(failed, "data-int-action=\"webhook-create\""));
    const auto unavailable = render_webhooks(std::unexpected(ReadError::unavailable));
    CHECK_THAT(unavailable, ContainsSubstring("Webhooks are not available."));
}

TEST_CASE("webhooks: 101 rows renders 100 plus the more-exist sentinel", "[integrations][render]") {
    std::vector<WebhookRow> rows;
    for (int i = 1; i <= 101; ++i)
        rows.push_back(hook(i, "https://h" + std::to_string(i) + ".example.invalid/x"));
    const auto html = render_webhooks(rows);
    CHECK_THAT(html, ContainsSubstring("Showing the first 100. More exist."));
    CHECK(contains(html, "h100.example.invalid"));
    CHECK(!contains(html, "h101.example.invalid"));
}

TEST_CASE("webhooks: hostile strings are escaped everywhere", "[integrations][render]") {
    std::vector<WebhookRow> rows{
        hook(1, std::string("https://h.example.invalid/") + kXss, std::string("a,") + kXss)};
    rows[0].last.kind = LastDelivery::Kind::known;
    rows[0].last.status_code = 500;
    const auto html = render_webhooks(rows);
    CHECK(!contains(html, kXss));
    CHECK_THAT(html, ContainsSubstring("&lt;img src=x onerror=1&gt;"));
}

TEST_CASE("webhooks: last delivery distinguishes none, unknown and an answer",
          "[integrations][render]") {
    auto none = hook(1, "https://a.example.invalid");
    auto unknown = hook(2, "https://b.example.invalid");
    unknown.last.kind = LastDelivery::Kind::unknown;
    auto noanswer = hook(3, "https://c.example.invalid");
    noanswer.last = {LastDelivery::Kind::known, 0, 1760000000, "connection_failed"};
    const auto html = render_webhooks(std::vector<WebhookRow>{none, unknown, noanswer});
    CHECK_THAT(html, ContainsSubstring("No deliveries recorded"));
    CHECK_THAT(html, ContainsSubstring("Unknown (history could not be read)"));
    CHECK_THAT(html, ContainsSubstring("No answer"));
}

TEST_CASE("webhook create form: confirm names host and data classes, secret has no value",
          "[integrations][render]") {
    const auto html = render_webhooks(std::vector<WebhookRow>{});
    // Server-owned confirm template; the controller fills {events}/{host}/{data}.
    CHECK_THAT(html, ContainsSubstring("Send {events} to {host}? These events carry {data}."));
    CHECK_THAT(html, ContainsSubstring("no restriction on the destination address"));
    // Four real events plus All; data class line beside each.
    CHECK_THAT(html, ContainsSubstring("value=\"agent.registered\""));
    CHECK_THAT(html, ContainsSubstring("value=\"dex.blast_radius\""));
    CHECK_THAT(html, ContainsSubstring("agent hostnames, agent ids, OS and agent version"));
    CHECK_THAT(html, ContainsSubstring("name=\"wh-all\" data-int-all checked"));
    // Secret: password input, new-password, no value attribute.
    const auto pos = html.find("name=\"secret\"");
    REQUIRE(pos != std::string::npos);
    const auto tag_end = html.find('>', pos);
    const auto tag = html.substr(pos, tag_end - pos);
    CHECK_THAT(tag, ContainsSubstring("type=\"password\""));
    CHECK_THAT(tag, ContainsSubstring("autocomplete=\"new-password\""));
    CHECK(!contains(tag, "value="));
    CHECK_THAT(html, ContainsSubstring("it is not an approval step"));
    CHECK_THAT(html, ContainsSubstring("recorded in the audit log; the analytics event stream carries only its scheme and host"));
}

TEST_CASE("webhook deliveries: failed read, empty, and rows", "[integrations][render]") {
    CHECK_THAT(render_webhook_deliveries(std::unexpected(ReadError::failed)),
               ContainsSubstring("Delivery history could not be read."));
    CHECK_THAT(render_webhook_deliveries(std::vector<WebhookDelivery>{}),
               ContainsSubstring("No deliveries recorded."));
    WebhookDelivery d;
    d.event_type = "dex.signal";
    d.status_code = 0;
    d.error = std::string("connection_failed ") + kXss;
    d.payload = std::string("{\"k\":\"") + kXss + "\"}";
    d.delivered_at = 1760000000;
    const auto html = render_webhook_deliveries(std::vector<WebhookDelivery>{d});
    CHECK_THAT(html, ContainsSubstring("No answer"));
    CHECK(!contains(html, kXss));
    CHECK_THAT(html, ContainsSubstring("<details><summary>Payload</summary>"));
}

// ── offload targets ──────────────────────────────────────────────────────────

TEST_CASE("offload: list, auth, credential flag, host only", "[integrations][render]") {
    std::vector<OffloadRow> rows{target(3, "siem", "https://ingest.example.invalid/v1/events?k=SECRETQ")};
    const auto html = render_offload_targets(rows);
    CHECK_THAT(html, ContainsSubstring("<b>siem</b>"));
    CHECK_THAT(html, ContainsSubstring("https://ingest.example.invalid</span>"));
    CHECK_THAT(html, ContainsSubstring("bearer"));
    CHECK_THAT(html, ContainsSubstring("Credential set"));
    CHECK_THAT(html, ContainsSubstring("batch size 5"));
    CHECK_THAT(html, ContainsSubstring("Delete offload target siem? Events stop being forwarded to "
                                       "https://ingest.example.invalid"));
    CHECK(!contains(html, "Healthy"));
    CHECK(!contains(html, "Syslog"));
}

TEST_CASE("offload: empty, degraded and truncated are three different states",
          "[integrations][render]") {
    CHECK_THAT(render_offload_targets(std::vector<OffloadRow>{}),
               ContainsSubstring("No offload targets configured."));
    const auto bad = render_offload_targets(std::unexpected(ReadError::failed));
    CHECK_THAT(bad, ContainsSubstring("Offload targets could not be read."));
    CHECK(!contains(bad, "No offload targets configured"));
    std::vector<OffloadRow> many;
    for (int i = 1; i <= 101; ++i)
        many.push_back(target(i, "t" + std::to_string(i), "https://x.example.invalid"));
    CHECK_THAT(render_offload_targets(many), ContainsSubstring("Showing the first 100. More exist."));
}

TEST_CASE("offload create form: bounds, creds write-only, shutdown wording is truthful",
          "[integrations][render]") {
    const auto html = render_offload_targets(std::vector<OffloadRow>{});
    CHECK_THAT(html, ContainsSubstring("name=\"name\" type=\"text\" required maxlength=\"256\""));
    CHECK_THAT(html, ContainsSubstring("maxlength=\"2048\""));
    CHECK_THAT(html, ContainsSubstring("maxlength=\"8192\""));
    CHECK_THAT(html, ContainsSubstring("min=\"1\" max=\"10000\""));
    CHECK_THAT(html, ContainsSubstring("A normal server stop flushes them; a crash or kill loses them."));
    CHECK(!contains(html, "dropped at shutdown"));
    CHECK_THAT(html, ContainsSubstring("The target name and destination URL are recorded in the audit log."));
    const auto pos = html.find("name=\"auth_credential\"");
    REQUIRE(pos != std::string::npos);
    const auto tag = html.substr(pos, html.find('>', pos) - pos);
    CHECK_THAT(tag, ContainsSubstring("type=\"password\""));
    CHECK(!contains(tag, "value="));
}

TEST_CASE("offload deliveries: states", "[integrations][render]") {
    CHECK_THAT(render_offload_deliveries(std::unexpected(ReadError::unavailable)),
               ContainsSubstring("Delivery history is not available."));
    CHECK_THAT(render_offload_deliveries(std::vector<OffloadDelivery>{}),
               ContainsSubstring("No deliveries recorded."));
    OffloadDelivery d;
    d.event_count = 3;
    d.status_code = 204;
    d.event_type = "execution.completed";
    const auto html = render_offload_deliveries(std::vector<OffloadDelivery>{d});
    CHECK_THAT(html, ContainsSubstring("204"));
    CHECK_THAT(html, ContainsSubstring("<td>3</td>"));
}

// ── directory sync ───────────────────────────────────────────────────────────

TEST_CASE("directory: completed shows counts from the snapshot, provider is a constant",
          "[integrations][render]") {
    const auto html = render_directory_panel(ok_view());
    CHECK_THAT(html, ContainsSubstring("Microsoft Entra ID (the only provider; LDAP is not supported)"));
    CHECK_THAT(html, ContainsSubstring("Completed"));
    CHECK_THAT(html, ContainsSubstring("2025-10-09 08:53 UTC"));
    CHECK_THAT(html, ContainsSubstring("<span>Users synced</span><b>5</b>"));
    CHECK_THAT(html, ContainsSubstring("<span>Groups synced</span><b>1</b>"));
    CHECK_THAT(html, ContainsSubstring("they are not applied to sign-in"));
    CHECK_THAT(html, ContainsSubstring("Mappings for groups no longer in the directory are not shown"));
}

TEST_CASE("directory: a failed run is not shown as a completed one", "[integrations][render]") {
    auto v = ok_view();
    v.status->status = "failed";
    v.status->last_error = std::string("Graph said ") + kXss;
    const auto html = render_directory_panel(v);
    CHECK_THAT(html, ContainsSubstring("Last attempt failed"));
    CHECK(!contains(html, "<b><span class=\"pill ok\">Completed"));
    CHECK(!contains(html, kXss));
    CHECK_THAT(html, ContainsSubstring("data-state=\"sync-error\""));
}

TEST_CASE("directory: running and never-synced states", "[integrations][render]") {
    auto running = ok_view();
    running.status->status = "running";
    const auto r = render_directory_panel(running);
    CHECK_THAT(r, ContainsSubstring("Sync started"));
    // A stale running row must never disable the sync form.
    CHECK_THAT(r, ContainsSubstring("data-int-action=\"directory-sync\""));
    CHECK(!contains(r, "<button class=\"btn primary\" type=\"submit\" disabled>Sync directory"));

    auto never = ok_view();
    never.status->status = "idle";
    never.status->last_sync_at = 0;
    const auto n = render_directory_panel(never);
    CHECK_THAT(n, ContainsSubstring("Never synced. Sync runs when you start it."));
}

TEST_CASE("directory: a failed status read is not never-synced", "[integrations][render]") {
    DirectoryView v{std::unexpected(ReadError::failed), std::int64_t{0},
                    std::vector<DirectoryGroup>{}, std::vector<std::string>{}};
    const auto html = render_directory_panel(v);
    CHECK_THAT(html, ContainsSubstring("Directory sync status could not be read."));
    CHECK(!contains(html, "Never synced"));
    CHECK(!contains(html, "data-int-action=\"directory-sync\""));
}

TEST_CASE("directory sync form: write-only fields, confirm wording", "[integrations][render]") {
    const auto html = render_directory_panel(ok_view());
    CHECK_THAT(html, ContainsSubstring("The client secret is used for this run only and is not stored."));
    const auto pos = html.find("name=\"client_secret\"");
    REQUIRE(pos != std::string::npos);
    const auto tag = html.substr(pos, html.find('>', pos) - pos);
    CHECK_THAT(tag, ContainsSubstring("type=\"password\""));
    CHECK_THAT(tag, ContainsSubstring("autocomplete=\"new-password\""));
    CHECK(!contains(tag, "value="));
    // Tenant and client are never prefilled either.
    CHECK(!contains(html.substr(html.find("name=\"tenant_id\""), 120), "value="));
}

TEST_CASE("directory mappings: role select reflects the stored role", "[integrations][render]") {
    const auto html = render_directory_panel(ok_view());
    CHECK_THAT(html, ContainsSubstring("data-group-id=\"g-1\" data-original=\"Operator\""));
    CHECK_THAT(html, ContainsSubstring("<option value=\"Operator\" selected>Operator</option>"));
    CHECK_THAT(html, ContainsSubstring("Save {n} group-to-role mappings?"));
}

TEST_CASE("directory mappings: a stored role that no longer exists stays visible",
          "[integrations][render]") {
    auto v = ok_view();
    (*v.groups)[0].mapped_role = "RetiredRole";
    const auto html = render_directory_panel(v);
    CHECK_THAT(html, ContainsSubstring("<option value=\"RetiredRole\" selected>RetiredRole (role not found)</option>"));
}

TEST_CASE("directory mappings: unreadable roles disable the form", "[integrations][render]") {
    auto v = ok_view();
    v.roles = std::unexpected(ReadError::unavailable);
    const auto html = render_directory_panel(v);
    CHECK_THAT(html, ContainsSubstring("Role names could not be read, so mappings cannot be edited"));
    CHECK_THAT(html, ContainsSubstring(" disabled>"));
    CHECK_THAT(html, ContainsSubstring(">Save mapping</button>"));
    CHECK_THAT(html, ContainsSubstring("type=\"submit\" disabled>Save mapping"));
}

TEST_CASE("directory mappings: group cap shows first 200 of N", "[integrations][render]") {
    auto v = ok_view();
    v.groups->clear();
    for (int i = 0; i < 250; ++i) {
        DirectoryGroup g;
        g.id = "g" + std::to_string(i);
        g.display_name = "G" + std::to_string(i);
        v.groups->push_back(g);
    }
    const auto html = render_directory_panel(v);
    CHECK_THAT(html, ContainsSubstring("Showing the first 200 of 250 groups."));
    CHECK(contains(html, "data-group-id=\"g199\""));
    CHECK(!contains(html, "data-group-id=\"g200\""));
}

TEST_CASE("directory users are lazy: the panel carries a button, not the rows",
          "[integrations][render]") {
    auto v = ok_view();
    const auto html = render_directory_panel(v);
    CHECK_THAT(html, ContainsSubstring("hx-get=\"/fragments/settings/directory-sync/users\""));
    CHECK_THAT(html, ContainsSubstring("Show directory users"));
    CHECK(!contains(html, "@example"));
}

TEST_CASE("directory users: rows, escaping, group truncation, caps and states",
          "[integrations][render]") {
    DirectoryUser u;
    u.display_name = kXss;
    u.email = "a@example.invalid";
    u.upn = "a@example.invalid";
    u.groups = {"A", "B", "C", "D", "E"};
    u.synced_at = 1760000000;
    const auto html = render_directory_users(std::vector<DirectoryUser>{u}, 1);
    CHECK(!contains(html, kXss));
    CHECK_THAT(html, ContainsSubstring("A, B, C +2"));

    CHECK_THAT(render_directory_users(std::vector<DirectoryUser>{}, 0),
               ContainsSubstring("No synced users."));
    CHECK_THAT(render_directory_users(std::unexpected(ReadError::failed), 0),
               ContainsSubstring("Directory users could not be read."));

    std::vector<DirectoryUser> many(250, u);
    const auto capped = render_directory_users(many, 250);
    CHECK_THAT(capped, ContainsSubstring("Showing 200 of 250 users."));
}

TEST_CASE("withheld and not-found notes", "[integrations][render]") {
    CHECK_THAT(render_audit_withheld_note(), ContainsSubstring("Directory users are not shown."));
    CHECK_THAT(render_not_found_note("The webhook"), ContainsSubstring("The webhook was not found."));
}

TEST_CASE("no renderer emits hx-on or an inline event handler", "[integrations][render]") {
    std::string all = render_webhooks(std::vector<WebhookRow>{hook(1, "https://a.example.invalid")});
    all += render_offload_targets(std::vector<OffloadRow>{target(1, "t", "https://a.example.invalid")});
    all += render_directory_panel(ok_view());
    CHECK(!contains(all, "hx-on"));
    CHECK(!contains(all, " onclick="));
    CHECK(!contains(all, " onchange="));
    CHECK(!contains(all, " onsubmit="));
    CHECK(!contains(all, " onerror="));
}
