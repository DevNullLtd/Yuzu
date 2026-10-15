#include "integrations_sync_render.hpp"

#include "outbound_url_policy.hpp"
#include "settings_model.hpp" // sanitize_url_userinfo
#include "web_utils.hpp"      // html_escape

#include <algorithm>
#include <format>

namespace yuzu::server::integrations {

namespace {

std::string esc(std::string_view s) { return html_escape(std::string{s}); }

// ── text blocks shared by several panels ─────────────────────────────────────

constexpr std::string_view kWebhookCreateConfirm =
    "Send {events} to {host}? These events carry {data}. There is no restriction on the "
    "destination address. The audit log and the analytics event stream record only the "
    "destination's scheme and host (the audit row adds a fingerprint of the URL), never its path "
    "or query.";
constexpr std::string_view kOffloadCreateConfirm =
    "Send {events} to {host}? These events carry {data}. There is no restriction on the "
    "destination address. The audit log records the target name and the destination's scheme and "
    "host plus a fingerprint of the URL, never its path or query.";
constexpr std::string_view kSyncConfirm =
    "Sync users and groups from Microsoft Entra ID? Users and groups no longer in the directory "
    "are removed from Yuzu's synced copy. The client secret is used for this run only and is "
    "not stored.";
constexpr std::string_view kMappingConfirm =
    "Save {n} group-to-role mappings? Mappings are recorded for reference. They are not applied "
    "to sign-in today.";

std::string failure_box(std::string_view what, ReadError e, bool plural = true) {
    std::string out = "<div class=\"note warn\" data-state=\"degraded\"><b>" + esc(what);
    if (e == ReadError::unavailable)
        out += plural ? " are not available.</b> " : " is not available.</b> ";
    else
        out += " could not be read.</b> ";
    out += e == ReadError::unavailable ? "The store is not reachable. " : "The read failed. ";
    out += "This is not an empty list.</div>";
    return out;
}

std::string pill(std::string_view cls, std::string_view text) {
    return "<span class=\"pill " + std::string{cls} + "\">" + esc(text) + "</span>";
}

std::string last_delivery_cell(const LastDelivery& d) {
    switch (d.kind) {
    case LastDelivery::Kind::none:
        return "<span class=\"mut\">No deliveries recorded</span>";
    case LastDelivery::Kind::unknown:
        return "<span class=\"mut\">Unknown (history could not be read)</span>";
    case LastDelivery::Kind::known:
        break;
    }
    const bool ok = d.status_code >= 200 && d.status_code < 300;
    std::string out = pill(ok ? "ok" : "bad",
                           d.status_code == 0 ? std::string{"No answer"} : std::to_string(d.status_code));
    out += " <span class=\"mut\">" + esc(format_utc(d.at)) + "</span>";
    return out;
}

std::string events_cell(const std::string& event_types) {
    if (event_types == "*" || event_types.empty())
        return "All events";
    return "<span class=\"mono\">" + esc(clip_text(event_types, 120)) + "</span>";
}

std::string event_checkboxes(std::string_view name_prefix) {
    std::string out = "<div class=\"fld\"><span class=\"lb\">Events</span>";
    out += "<label><input class=\"chk\" type=\"checkbox\" name=\"" + std::string{name_prefix} +
           "-all\" data-int-all checked> All events</label>";
    for (const auto& ev : event_catalogue()) {
        out += "<label><input class=\"chk\" type=\"checkbox\" name=\"" + std::string{name_prefix} +
               "-event\" value=\"" + esc(ev.id) + "\" data-class=\"" + esc(ev.data_class) +
               "\" data-label=\"" + esc(ev.label) + "\"> " + esc(ev.label) + " <span class=\"hint\">(" +
               esc(ev.id) + ": " + esc(ev.data_class) + ")</span></label>";
    }
    out += "<span class=\"hint\">Only these four events are ever sent. Choosing none is not "
           "allowed.</span></div>";
    return out;
}

std::string list_sentinel(std::size_t shown_cap, std::size_t got) {
    if (got <= shown_cap)
        return {};
    return "<div class=\"note\" data-state=\"truncated\">Showing the first " +
           std::to_string(shown_cap) + ". More exist.</div>";
}

std::string result_area(bool panel_level = false) {
    return std::string{"<div class=\"note warn\" "} +
           (panel_level ? "data-int-panel-result" : "data-int-result") +
           " hidden role=\"status\"></div>";
}

std::string display_url_block(const std::string& url) {
    return "<details><summary>Show full URL</summary><code class=\"mono\">" +
           esc(settings_model::sanitize_url_userinfo(url)) + "</code></details>";
}

} // namespace

// ── helpers ──────────────────────────────────────────────────────────────────

const std::array<EventClass, 4>& event_catalogue() noexcept {
    static const std::array<EventClass, 4> k{{
        {"agent.registered", "Agent registered", "agent hostnames, agent ids, OS and agent version"},
        {"execution.completed", "Execution completed",
         "command ids, agent ids, status, exit codes and error messages"},
        {"dex.signal", "DEX signal", "DEX signal readings for a device"},
        {"dex.blast_radius", "DEX blast radius", "DEX blast-radius figures"},
    }};
    return k;
}

std::string format_utc(std::int64_t t) {
    if (t <= 0)
        return "Never";
    // Civil-from-days (Howard Hinnant), so the output is locale- and TZ-free.
    std::int64_t z = t / 86400;
    const std::int64_t secs = t % 86400;
    z += 719468;
    const std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const auto doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    std::int64_t y = static_cast<std::int64_t>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    const unsigned d = doy - (153 * mp + 2) / 5 + 1;
    const unsigned m = mp < 10 ? mp + 3 : mp - 9;
    if (m <= 2)
        ++y;
    return std::format("{:04}-{:02}-{:02} {:02}:{:02} UTC", y, m, d, secs / 3600,
                       (secs % 3600) / 60);
}

std::string clip_text(const std::string& s, std::size_t max_bytes) {
    if (s.size() <= max_bytes)
        return s;
    std::size_t cut = max_bytes;
    std::size_t steps = 0;
    while (cut > 0 && steps < 3 && (static_cast<unsigned char>(s[cut]) & 0xC0) == 0x80) {
        --cut;
        ++steps;
    }
    return s.substr(0, cut) + "...";
}

// ── webhooks ─────────────────────────────────────────────────────────────────

std::string render_webhooks(const std::expected<std::vector<WebhookRow>, ReadError>& rows) {
    std::string out = "<div class=\"panel\" id=\"webhooks-panel\"><div class=\"hd\"><h2>Webhooks</h2>"
                      "<span class=\"sub\">Where fleet events are sent over HTTP or HTTPS</span></div>"
                      "<div class=\"pb\">";
    if (!rows) {
        out += failure_box("Webhooks", rows.error());
        out += "</div></div>";
        return out;
    }
    if (rows->empty()) {
        out += "<div class=\"note\" data-state=\"empty\">No webhooks configured. Events are not "
               "sent to any URL.</div>";
    } else {
        out += list_sentinel(kListShown, rows->size());
        out += "<div class=\"tw\"><table><thead><tr><th>Destination</th><th>Events</th>"
               "<th>State</th><th>Last delivery</th><th></th></tr></thead><tbody>";
        std::size_t n = 0;
        for (const auto& r : *rows) {
            if (++n > kListShown)
                break;
            const auto& w = r.webhook;
            const std::string host = url_scheme_host(w.url);
            const std::string id = std::to_string(w.id);
            out += "<tr><td><span class=\"mono\">" + esc(host.empty() ? "(host not shown)" : host) +
                   "</span>" + display_url_block(w.url) + "</td><td>" + events_cell(w.event_types) +
                   "</td><td>" + pill(w.enabled ? "ok" : "idle", w.enabled ? "Enabled" : "Disabled") +
                   " " + pill(w.has_secret ? "info" : "idle", w.has_secret ? "Signed" : "Unsigned") +
                   "</td><td>" + last_delivery_cell(r.last) + "</td><td>";
            out += "<button class=\"btn link\" type=\"button\" hx-get=\"/fragments/settings/webhooks/" +
                   id + "/deliveries\" hx-target=\"#wh-del-" + id +
                   "\" hx-swap=\"innerHTML\">Deliveries</button>";
            out += "<button class=\"btn link danger\" type=\"button\" "
                   "data-int-action=\"webhook-delete\" data-id=\"" +
                   id + "\" data-confirm=\"" +
                   esc("Delete the webhook for " + (host.empty() ? std::string{"this URL"} : host) +
                       "? Yuzu stops sending events to it and its delivery history is deleted. "
                       "This cannot be undone.") +
                   "\">Delete</button></td></tr>";
            out += "<tr><td colspan=\"5\" id=\"wh-del-" + id + "\"></td></tr>";
        }
        out += "</tbody></table></div>";
    }
    out += "<div class=\"note\" data-state=\"policy\">Creating or deleting a webhook asks for a "
           "confirmation; it is not an approval step.</div>";
    out += "<details class=\"new\"><summary class=\"btn sm\">New webhook</summary>"
           "<form data-int-action=\"webhook-create\" data-confirm=\"" +
           esc(kWebhookCreateConfirm) + "\" autocomplete=\"off\">"
           "<div class=\"fld\"><label for=\"wh-url\">URL</label>"
           "<input class=\"in mono\" id=\"wh-url\" name=\"url\" type=\"text\" required maxlength=\"2048\" "
           "autocomplete=\"off\" spellcheck=\"false\" placeholder=\"https://example.invalid/hook\">"
           "<span class=\"hint\">Must start with http:// or https://. Embedded user:password is "
           "refused. The audit log and the analytics event stream record only the destination's "
           "scheme and host (the audit row adds a fingerprint of the URL), never its path or "
           "query.</span></div>" +
           event_checkboxes("wh") +
           "<div class=\"fld\"><label for=\"wh-secret\">Signing secret (optional)</label>"
           "<input class=\"in mono\" id=\"wh-secret\" name=\"secret\" type=\"password\" "
           "autocomplete=\"new-password\" spellcheck=\"false\">"
           "<span class=\"hint\">Empty means unsigned. A secret signs each body with HMAC-SHA256 in "
           "X-Yuzu-Signature. It is write-only and is never shown again.</span></div>"
           "<label><input class=\"chk\" type=\"checkbox\" name=\"enabled\" checked> Start enabled "
           "(there is no later toggle)</label>"
           "<div class=\"btns\"><button class=\"btn primary\" type=\"submit\">Create webhook</button>"
           "</div>" + result_area() + "</form></details>";
    out += result_area(true);
    out += "</div></div>";
    return out;
}

std::string
render_webhook_deliveries(const std::expected<std::vector<WebhookDelivery>, ReadError>& rows) {
    if (!rows)
        return failure_box("Delivery history", rows.error(), false);
    if (rows->empty())
        return "<div class=\"note\" data-state=\"empty\">No deliveries recorded.</div>";
    std::string out = "<div class=\"tw\"><table><thead><tr><th>Time</th><th>Event</th><th>Result</th>"
                      "<th>Payload</th></tr></thead><tbody>";
    for (const auto& d : *rows) {
        const bool ok = d.status_code >= 200 && d.status_code < 300;
        out += "<tr><td>" + esc(format_utc(d.delivered_at)) + "</td><td class=\"mono\">" +
               esc(d.event_type) + "</td><td>" +
               pill(ok ? "ok" : "bad",
                    d.status_code == 0 ? std::string{"No answer"} : std::to_string(d.status_code));
        if (!d.error.empty())
            out += " <span class=\"mut\">" + esc(clip_text(d.error, kErrorShown)) + "</span>";
        out += "</td><td><details><summary>Payload</summary><pre class=\"mono\">" +
               esc(clip_text(d.payload, 2048)) + "</pre></details></td></tr>";
    }
    out += "</tbody></table></div>";
    return out;
}

// ── offload targets ──────────────────────────────────────────────────────────

std::string render_offload_targets(const std::expected<std::vector<OffloadRow>, ReadError>& rows) {
    std::string out = "<div class=\"panel\" id=\"offload-panel\"><div class=\"hd\"><h2>Offload targets</h2>"
                      "<span class=\"sub\">Where fleet events are sent over HTTP or HTTPS</span></div>"
                      "<div class=\"pb\">";
    if (!rows) {
        out += failure_box("Offload targets", rows.error());
        out += "</div></div>";
        return out;
    }
    if (rows->empty()) {
        out += "<div class=\"note\" data-state=\"empty\">No offload targets configured.</div>";
    } else {
        out += list_sentinel(kListShown, rows->size());
        out += "<div class=\"tw\"><table><thead><tr><th>Target</th><th>Destination</th><th>Auth</th>"
               "<th>State</th><th>Last delivery</th><th></th></tr></thead><tbody>";
        std::size_t n = 0;
        for (const auto& r : *rows) {
            if (++n > kListShown)
                break;
            const auto& t = r.target;
            const std::string host = url_scheme_host(t.url);
            const std::string id = std::to_string(t.id);
            out += "<tr><td><b>" + esc(clip_text(t.name, 128)) + "</b></td><td><span class=\"mono\">" +
                   esc(host.empty() ? "(host not shown)" : host) + "</span>" +
                   display_url_block(t.url) + "<div class=\"mut\">Events: " + events_cell(t.event_types) +
                   "; batch size " + std::to_string(t.batch_size) + "</div></td><td>" +
                   esc(offload_auth_type_to_string(t.auth_type)) + " " +
                   pill(t.has_credential ? "info" : "idle",
                        t.has_credential ? "Credential set" : "No credential") +
                   "</td><td>" + pill(t.enabled ? "ok" : "idle", t.enabled ? "Enabled" : "Disabled") +
                   "</td><td>" + last_delivery_cell(r.last) + "</td><td>";
            out += "<button class=\"btn link\" type=\"button\" "
                   "hx-get=\"/fragments/settings/offload-targets/" +
                   id + "/deliveries\" hx-target=\"#off-del-" + id +
                   "\" hx-swap=\"innerHTML\">Deliveries</button>";
            out += "<button class=\"btn link danger\" type=\"button\" "
                   "data-int-action=\"offload-delete\" data-id=\"" +
                   id + "\" data-confirm=\"" +
                   esc("Delete offload target " + t.name + "? Events stop being forwarded to " +
                       (host.empty() ? std::string{"this URL"} : host) +
                       " and its delivery history is deleted. This cannot be undone.") +
                   "\">Delete</button></td></tr>";
            out += "<tr><td colspan=\"6\" id=\"off-del-" + id + "\"></td></tr>";
        }
        out += "</tbody></table></div>";
    }
    out += "<div class=\"note\" data-state=\"policy\">Events are held in memory until the batch "
           "size is reached. A normal server stop flushes them; a crash or kill loses them. "
           "Creating or deleting a target asks for a confirmation; it is not an approval "
           "step.</div>";
    out += "<details class=\"new\"><summary class=\"btn sm\">New offload target</summary>"
           "<form data-int-action=\"offload-create\" data-confirm=\"" +
           esc(kOffloadCreateConfirm) + "\" autocomplete=\"off\">"
           "<div class=\"fld\"><label for=\"off-name\">Name</label>"
           "<input class=\"in\" id=\"off-name\" name=\"name\" type=\"text\" required maxlength=\"256\" "
           "autocomplete=\"off\"></div>"
           "<div class=\"fld\"><label for=\"off-url\">URL</label>"
           "<input class=\"in mono\" id=\"off-url\" name=\"url\" type=\"text\" required maxlength=\"2048\" "
           "autocomplete=\"off\" spellcheck=\"false\" placeholder=\"https://example.invalid/ingest\">"
           "<span class=\"hint\">Must start with http:// or https://. Embedded user:password is "
           "refused. The audit log records the target name and the destination's scheme and "
           "host plus a fingerprint of the URL, never its path or query.</span></div>"
           "<div class=\"fld\"><label for=\"off-auth\">Authentication</label>"
           "<select class=\"in\" id=\"off-auth\" name=\"auth_type\">"
           "<option value=\"none\">None</option><option value=\"bearer\">Bearer token</option>"
           "<option value=\"basic\">User and password (user:password)</option>"
           "<option value=\"hmac\">HMAC shared secret</option></select></div>"
           "<div class=\"fld\"><label for=\"off-cred\">Credential (optional)</label>"
           "<input class=\"in mono\" id=\"off-cred\" name=\"auth_credential\" type=\"password\" "
           "maxlength=\"8192\" autocomplete=\"new-password\" spellcheck=\"false\">"
           "<span class=\"hint\">Empty means no auth header whatever the type. Write-only: it is "
           "never shown again.</span></div>" +
           event_checkboxes("off") +
           "<div class=\"fld\"><label for=\"off-batch\">Batch size</label>"
           "<input class=\"in\" id=\"off-batch\" name=\"batch_size\" type=\"number\" min=\"1\" "
           "max=\"10000\" value=\"1\"><span class=\"hint\">Events are held in memory until this "
           "many accumulate. A crash or kill loses held events.</span></div>"
           "<label><input class=\"chk\" type=\"checkbox\" name=\"enabled\" checked> Start enabled "
           "(there is no later toggle)</label>"
           "<div class=\"btns\"><button class=\"btn primary\" type=\"submit\">Create offload "
           "target</button></div>" + result_area() + "</form></details>";
    out += result_area(true);
    out += "</div></div>";
    return out;
}

std::string
render_offload_deliveries(const std::expected<std::vector<OffloadDelivery>, ReadError>& rows) {
    if (!rows)
        return failure_box("Delivery history", rows.error(), false);
    if (rows->empty())
        return "<div class=\"note\" data-state=\"empty\">No deliveries recorded.</div>";
    std::string out = "<div class=\"tw\"><table><thead><tr><th>Time</th><th>Event</th><th>Events</th>"
                      "<th>Result</th><th>Payload</th></tr></thead><tbody>";
    for (const auto& d : *rows) {
        const bool ok = d.status_code >= 200 && d.status_code < 300;
        out += "<tr><td>" + esc(format_utc(d.delivered_at)) + "</td><td class=\"mono\">" +
               esc(d.event_type) + "</td><td>" + std::to_string(d.event_count) + "</td><td>" +
               pill(ok ? "ok" : "bad",
                    d.status_code == 0 ? std::string{"No answer"} : std::to_string(d.status_code));
        if (!d.error.empty())
            out += " <span class=\"mut\">" + esc(clip_text(d.error, kErrorShown)) + "</span>";
        out += "</td><td><details><summary>Payload</summary><pre class=\"mono\">" +
               esc(clip_text(d.payload, 2048)) + "</pre></details></td></tr>";
    }
    out += "</tbody></table></div>";
    return out;
}

// ── directory sync ───────────────────────────────────────────────────────────

std::string render_directory_panel(const DirectoryView& v) {
    std::string out = "<div class=\"panel\" id=\"directory-panel\"><div class=\"hd\">"
                      "<h2>Directory sync</h2><span class=\"sub\">Microsoft Entra ID users and "
                      "groups, synced when you start it</span></div><div class=\"pb\">";
    if (!v.status) {
        out += failure_box("Directory sync status", v.status.error(), false);
        out += "</div></div>";
        return out;
    }
    const SyncStatus& s = *v.status;
    const bool never = s.last_sync_at <= 0;

    // Status and "Last sync" are keyed off `status`, never off last_sync_at
    // alone: the status row's time and counts are also written on running and
    // failed attempts, so a failed run must not read as a completed one.
    std::string status_pill;
    std::string last_row;
    if (s.status == "running") {
        status_pill = pill("info", "Sync started");
        last_row = "Sync started " + format_utc(s.last_sync_at);
    } else if (s.status == "failed") {
        status_pill = pill("bad", "Last attempt failed");
        last_row = "Last attempt failed " + format_utc(s.last_sync_at);
    } else if (s.status == "completed" && !never) {
        status_pill = pill("ok", "Completed");
        last_row = format_utc(s.last_sync_at);
    } else {
        status_pill = pill("idle", "Never synced");
        last_row = "Never synced";
    }
    out += "<div class=\"kvl\">"
           "<div><span>Provider</span><b>Microsoft Entra ID (the only provider; LDAP is not "
           "supported)</b></div>"
           "<div><span>Status</span><b>" + status_pill + "</b></div>"
           "<div><span>Last sync</span><b>" + esc(last_row) + "</b></div>"
           "<div><span>Users synced</span><b>";
    out += v.user_count ? std::to_string(*v.user_count) : std::string{"Unavailable"};
    out += "</b></div><div><span>Groups synced</span><b>";
    out += v.groups ? std::to_string(v.groups->size()) : std::string{"Unavailable"};
    out += "</b></div></div>";
    if (s.status == "failed" && !s.last_error.empty()) {
        out += "<div class=\"note warn\" data-state=\"sync-error\"><b>Last error</b> "
               "<span class=\"mono\">" + esc(clip_text(s.last_error, kErrorShown)) + "</span></div>";
    }
    if (s.status == "running") {
        out += "<div class=\"note\" data-state=\"sync-running\">A sync is recorded as started. It "
               "may have been interrupted by a restart; starting another is still allowed and "
               "the server refuses a concurrent one.</div>";
    }
    if (never && s.status != "running" && s.status != "failed") {
        out += "<div class=\"note\" data-state=\"never\">Never synced. Sync runs when you start "
               "it. If this is unexpected, check the server log.</div>";
    }
    out += "<div class=\"note\" data-state=\"policy\">Sync runs when you start it. Group mappings "
           "are recorded for reference; they are not applied to sign-in.</div>";

    // Sync form: tenant/client/secret per request, never remembered.
    out += "<form data-int-action=\"directory-sync\" data-confirm=\"" + esc(kSyncConfirm) +
           "\" autocomplete=\"off\"><div class=\"fld\"><label for=\"ds-tenant\">Tenant ID</label>"
           "<input class=\"in mono\" id=\"ds-tenant\" name=\"tenant_id\" type=\"text\" required "
           "maxlength=\"256\" autocomplete=\"off\" spellcheck=\"false\" "
           "pattern=\"[A-Za-z0-9.\\-]+\"></div>"
           "<div class=\"fld\"><label for=\"ds-client\">Client ID</label>"
           "<input class=\"in mono\" id=\"ds-client\" name=\"client_id\" type=\"text\" required "
           "maxlength=\"256\" autocomplete=\"off\" spellcheck=\"false\"></div>"
           "<div class=\"fld\"><label for=\"ds-secret\">Client secret</label>"
           "<input class=\"in mono\" id=\"ds-secret\" name=\"client_secret\" type=\"password\" "
           "required maxlength=\"2048\" autocomplete=\"new-password\" spellcheck=\"false\">"
           "<span class=\"hint\">Used for this run only. Not stored and not remembered.</span></div>"
           "<div class=\"btns\"><button class=\"btn primary\" type=\"submit\">Sync directory</button>"
           "</div>" + result_area() + "</form>";

    // Groups and mappings.
    out += "<h3>Group mappings</h3>";
    if (!v.groups) {
        out += failure_box("Synced groups", v.groups.error());
    } else if (v.groups->empty()) {
        out += "<div class=\"note\" data-state=\"empty\">No synced groups.</div>";
    } else {
        const bool roles_ok = v.roles.has_value() && !v.roles->empty();
        if (!roles_ok) {
            out += "<div class=\"note warn\" data-state=\"degraded\">Role names could not be read, "
                   "so mappings cannot be edited right now.</div>";
        }
        if (v.groups->size() > kGroupsShown) {
            out += "<div class=\"note\" data-state=\"truncated\">Showing the first " +
                   std::to_string(kGroupsShown) + " of " + std::to_string(v.groups->size()) +
                   " groups.</div>";
        }
        out += "<form data-int-action=\"directory-mapping\" data-confirm=\"" + esc(kMappingConfirm) +
               "\"><div class=\"tw\"><table><thead><tr><th>Group</th><th>Group id</th>"
               "<th>Mapped role</th></tr></thead><tbody>";
        std::size_t n = 0;
        for (const auto& g : *v.groups) {
            if (++n > kGroupsShown)
                break;
            out += "<tr><td>" + esc(clip_text(g.display_name, 128)) + "</td><td class=\"mono\">" +
                   esc(g.id) + "</td><td><select class=\"in\" data-group-id=\"" + esc(g.id) +
                   "\" data-original=\"" + esc(g.mapped_role) + "\" aria-label=\"Role for " +
                   esc(clip_text(g.display_name, 64)) + "\"" + (roles_ok ? "" : " disabled") + ">";
            out += "<option value=\"\"" + std::string{g.mapped_role.empty() ? " selected" : ""} +
                   ">No mapping</option>";
            bool seen = false;
            if (v.roles) {
                for (const auto& r : *v.roles) {
                    const bool sel = r == g.mapped_role;
                    seen = seen || sel;
                    out += "<option value=\"" + esc(r) + "\"" + (sel ? " selected" : "") + ">" +
                           esc(r) + "</option>";
                }
            }
            if (!g.mapped_role.empty() && !seen) {
                // A stored role that no longer exists must stay visible, not
                // silently fall back to "No mapping".
                out += "<option value=\"" + esc(g.mapped_role) + "\" selected>" +
                       esc(g.mapped_role) + " (role not found)</option>";
            }
            out += "</select></td></tr>";
        }
        out += "</tbody></table></div><div class=\"btns\"><button class=\"btn primary\" "
               "type=\"submit\"" + std::string{roles_ok ? "" : " disabled"} +
               ">Save mapping</button></div>" + result_area() + "</form>"
               "<div class=\"note\" data-state=\"orphans\">Mappings for groups no longer in the "
               "directory are not shown and cannot be removed here.</div>";
    }

    // Users: never on page load (PII, unbounded, audited per read).
    out += "<h3>Directory users</h3><button class=\"btn sm\" type=\"button\" "
           "hx-get=\"/fragments/settings/directory-sync/users\" hx-target=\"#directory-users\" "
           "hx-swap=\"innerHTML\">Show directory users</button>"
           "<div id=\"directory-users\"></div>";
    out += "</div></div>";
    return out;
}

std::string
render_directory_users(const std::expected<std::vector<DirectoryUser>, ReadError>& users,
                       std::optional<std::int64_t> total) {
    if (!users)
        return failure_box("Directory users", users.error());
    if (users->empty())
        return "<div class=\"note\" data-state=\"empty\">No synced users.</div>";
    std::string out;
    const auto shown = std::min<std::size_t>(users->size(), kUsersShown);
    if (!total) {
        // The count failed: say what was read, and whether the read itself ran past the cap.
        if (users->size() > kUsersShown)
            out += "<div class=\"note\" data-state=\"truncated\">Showing " +
                   std::to_string(shown) + " users; more exist (total unavailable).</div>";
    } else if (static_cast<std::int64_t>(shown) < *total || users->size() > kUsersShown) {
        out += "<div class=\"note\" data-state=\"truncated\">Showing " + std::to_string(shown) +
               " of " + std::to_string(std::max<std::int64_t>(*total, users->size())) +
               " users.</div>";
    }
    out += "<div class=\"tw\"><table><thead><tr><th>User</th><th>Email</th><th>UPN</th><th>State</th>"
           "<th>Groups</th><th>Synced</th></tr></thead><tbody>";
    std::size_t n = 0;
    for (const auto& u : *users) {
        if (++n > kUsersShown)
            break;
        std::string groups;
        const std::size_t gshow = std::min<std::size_t>(u.groups.size(), 3);
        for (std::size_t i = 0; i < gshow; ++i) {
            if (i)
                groups += ", ";
            groups += esc(clip_text(u.groups[i], 64));
        }
        if (u.groups.size() > gshow)
            groups += " +" + std::to_string(u.groups.size() - gshow);
        out += "<tr><td>" + esc(clip_text(u.display_name, 128)) + "</td><td>" +
               esc(clip_text(u.email, 128)) + "</td><td class=\"mono\">" + esc(clip_text(u.upn, 128)) +
               "</td><td>" + pill(u.enabled ? "ok" : "idle", u.enabled ? "Enabled" : "Disabled") +
               "</td><td>" + groups + "</td><td>" + esc(format_utc(u.synced_at)) + "</td></tr>";
    }
    out += "</tbody></table></div>";
    return out;
}

std::string render_audit_withheld_note() {
    return "<div class=\"note warn\" data-state=\"degraded\"><b>Directory users are not "
           "shown.</b> The read could not be recorded in the audit log, and users are not "
           "shown without that record.</div>";
}

std::string render_not_found_note(std::string_view what) {
    return "<div class=\"note\" data-state=\"not-found\">" + esc(what) + " was not found. It may "
           "have been deleted.</div>";
}

} // namespace yuzu::server::integrations
