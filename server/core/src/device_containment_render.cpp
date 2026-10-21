/// @file device_containment_render.cpp
/// See device_containment_render.hpp.

#include "device_containment_render.hpp"

#include "web_utils.hpp"

namespace yuzu::server {

namespace {

std::string esc(const std::string& s) { return html_escape(s); }

std::string url_enc(const std::string& s) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
            c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 0x0f]);
        }
    }
    return out;
}

const char* state_label(ContainmentState s) {
    switch (s) {
    case ContainmentState::Confirmed: return "Confirmed on device at the last status read";
    case ContainmentState::Applied: return "Applied, not confirmed";
    case ContainmentState::Recorded: return "Recorded";
    }
    return "Recorded";
}

const char* state_tone(ContainmentState s) {
    return s == ContainmentState::Confirmed ? "bad" : "warn";
}

std::string when(std::int64_t secs) {
    if (secs <= 0) return "<span class=\"hw-grey\">&mdash;</span>";
    return "<span title=\"" + esc(format_iso_utc(secs)) + "\">" + esc(format_iso_utc(secs)) + "</span>";
}

std::string whitelist_cell(const std::string& w) {
    if (w.empty()) return "<span class=\"hw-grey\">none</span>";
    return "<span class=\"hw-mono\">" + esc(w) + "</span>";
}

std::string state_pill(const QuarantineRecord& r) {
    const ContainmentState s = containment_state(r);
    return std::string("<span class=\"hw-pill ") + state_tone(s) + "\">" + state_label(s) + "</span>";
}

} // namespace

ContainmentState containment_state(const QuarantineRecord& r) {
    if (r.last_confirmed_at > 0) return ContainmentState::Confirmed;
    if (r.last_applied_at > 0) return ContainmentState::Applied;
    return ContainmentState::Recorded;
}

std::string quarantine_panel_placeholder() {
    return "<div id=\"hw-quarantine\" hx-get=\"/fragments/hardware/quarantine\" hx-trigger=\"load\" "
           "hx-swap=\"outerHTML\"></div>";
}

std::string containment_banner_placeholder(const std::string& agent_id) {
    return "<div id=\"hw-quarantine-banner\" hx-get=\"/fragments/hardware/ci/containment?id=" +
           url_enc(agent_id) + "&banner=1\" hx-trigger=\"load\" hx-swap=\"outerHTML\"></div>";
}

std::string containment_lens_placeholder(const std::string& agent_id) {
    return "<div id=\"hw-containment\" hx-get=\"/fragments/hardware/ci/containment?id=" +
           url_enc(agent_id) + "\" hx-trigger=\"load\" hx-swap=\"outerHTML\"><span class=\"gp-mute\">"
           "Loading containment&hellip;</span></div>";
}

std::string render_quarantine_panel(const QuarantinePanelView& v) {
    std::string h = "<section id=\"hw-quarantine\" class=\"hw-panel\" style=\"margin-top:22px\">"
                    "<div class=\"hw-hd\"><h2>Quarantined devices</h2></div>";
    if (v.read == QuarantinePanelView::Read::StoreDegraded) {
        h += "<div class=\"gp-banner hw-degrade\"><b>Quarantine records could not be read.</b> This is "
             "not an empty list; a device may still be contained.</div></section>";
        return h;
    }
    if (v.read == QuarantinePanelView::Read::ProbeDegraded) {
        h += "<div class=\"gp-banner hw-degrade\"><b>Quarantine records could not be checked against "
             "your permissions.</b> This is not an empty list; a device may still be contained. "
             "Retry shortly.</div></section>";
        return h;
    }
    if (v.rows.empty()) {
        h += "<div class=\"hw-empty\">No device is quarantined in your scope.</div></section>";
        return h;
    }
    h += "<div class=\"hw-scroll\"><table class=\"hw-tbl\"><thead><tr><th>Device</th><th>Containment</th>"
         "<th>Quarantined by</th><th>Since</th><th>Reason</th><th>Whitelist</th></tr></thead><tbody>";
    for (const auto& row : v.rows) {
        const QuarantineRecord& r = row.record;
        const std::string name = row.hostname.empty() ? r.agent_id : row.hostname;
        h += "<tr><td><a class=\"hw-name\" href=\"/hardware/ci?id=" + url_enc(r.agent_id) +
             "&amp;lens=containment\">" + esc(name) + "</a></td><td>" + state_pill(r) + "</td><td>" +
             esc(r.quarantined_by) + "</td><td>" + when(r.quarantined_at) + "</td><td>" +
             (r.reason.empty() ? "<span class=\"hw-grey\">no reason recorded</span>" : esc(r.reason)) +
             "</td><td>" + whitelist_cell(r.whitelist) + "</td></tr>";
    }
    h += "</tbody></table></div>";
    if (v.more)
        h += "<div class=\"hw-page\"><span>Showing the newest " + std::to_string(v.cap) +
             " records you can see; older records exist.</span></div>";
    h += "</section>";
    return h;
}

std::string render_containment_banner(const ContainmentLensView& v) {
    if (v.read == ContainmentLensView::Read::Degraded)
        return "<div id=\"hw-quarantine-banner\" class=\"gp-banner hw-degrade\"><b>Quarantine state could "
               "not be read.</b> This is not \"not quarantined\".</div>";
    if (v.read != ContainmentLensView::Read::Ok || !v.record)
        return "<div id=\"hw-quarantine-banner\"></div>";
    return "<div id=\"hw-quarantine-banner\" class=\"gp-banner hw-degrade\"><b>This device is "
           "quarantined.</b> Instructions to it are withheld until it is released; Sync now still "
           "works. <a href=\"/hardware/ci?id=" + url_enc(v.agent_id) +
           "&amp;lens=containment\">Open containment</a></div>";
}

std::string render_containment_lens(const ContainmentLensView& v) {
    std::string h = "<div id=\"hw-containment\">";
    if (v.read == ContainmentLensView::Read::Denied) {
        h += "<div class=\"gp-placeholder\" data-denied=\"1\">Containment needs the <b>Security:Read</b> "
             "permission for this device.</div></div>";
        return h;
    }
    if (v.read == ContainmentLensView::Read::Degraded) {
        h += "<div class=\"gp-banner hw-degrade\"><b>Quarantine state could not be read.</b> This is not "
             "\"not quarantined\". Retry shortly.</div></div>";
        return h;
    }
    const std::string host = v.hostname.empty() ? v.agent_id : v.hostname;
    const bool mac = v.os == "darwin" || v.os == "macos" || v.os == "mac";
    // Dialog context travels as data attributes read by the page's delegated listener
    // (static/yuzu-estate.js); nothing here is an inline handler.
    auto data_attrs = [&] {
        return " data-agent=\"" + esc(v.agent_id) + "\" data-host=\"" + esc(host) + "\" data-online=\"" +
               (!v.identity_known ? "?" : v.online ? "1" : "0") + "\" data-mac=\"" +
               (mac ? "1" : "0") + "\"";
    };
    const std::string disabled_note =
        "<span class=\"hw-lab\">needs the Security:Execute permission for this device</span>";

    if (!v.record) {
        h += "<div class=\"ci-sec\"><h4>Containment</h4>"
             "<div class=\"ci-row\"><span class=\"ci-lab\">State</span><span>No active quarantine "
             "record.</span></div>"
             "<div class=\"hw-empty\">A released record does not show whether the device's firewall rules "
             "were removed. Check the quarantine plugin's status action from the Actions tab.</div>"
             "<div class=\"hw-tools\">";
        if (v.can_execute)
            h += "<button type=\"button\" class=\"gp-btn accent\" data-act=\"quarantine\"" + data_attrs() +
                 ">Quarantine device</button>";
        else
            h += "<button type=\"button\" class=\"gp-btn\" disabled>Quarantine device</button> " +
                 disabled_note;
        h += "</div></div>";
    } else {
        const QuarantineRecord& r = *v.record;
        const ContainmentState s = containment_state(r);
        h += "<div class=\"ci-sec\"><h4>Containment</h4><div class=\"ci-grid\">";
        h += "<div><span class=\"ci-lab\">State</span>" + state_pill(r) + "</div>";
        h += "<div><span class=\"ci-lab\">Quarantined by</span>" + esc(r.quarantined_by) + "</div>";
        h += "<div><span class=\"ci-lab\">Since</span>" + when(r.quarantined_at) + "</div>";
        h += "<div><span class=\"ci-lab\">Last applied</span>" + when(r.last_applied_at) + "</div>";
        h += "<div><span class=\"ci-lab\">Last confirmed</span>" + when(r.last_confirmed_at) + "</div>";
        h += "<div><span class=\"ci-lab\">Whitelist</span>" + whitelist_cell(r.whitelist) + "</div>";
        h += "</div><div class=\"ci-row\"><span class=\"ci-lab\">Reason</span><span>" +
             (r.reason.empty() ? std::string("<span class=\"hw-grey\">no reason recorded</span>")
                               : esc(r.reason)) +
             "</span></div>";
        // Honest progress line: the record is not proof; an offline device is waiting.
        std::string line;
        if (s == ContainmentState::Confirmed)
            line = "Containment was confirmed on the device by a status read.";
        else if (v.identity_known && !v.online)
            line = "Waiting for device to connect. The quarantine is recorded and is applied when the "
                   "device next connects.";
        else if (s == ContainmentState::Applied)
            line = "Applied to the device but not yet confirmed by a status read.";
        else
            line = "Recorded on the server. It is applied by the server's reconciler on its next pass; "
                   "this is not yet applied or confirmed.";
        h += "<div class=\"hw-empty\">" + esc(line) + " Instructions sent from Yuzu to this device are "
             "withheld until it is released.</div>";
        h += "<div class=\"hw-tools\">";
        if (v.can_execute)
            h += "<button type=\"button\" class=\"gp-btn\" data-act=\"release\"" + data_attrs() +
                 ">Release from quarantine</button>";
        else
            h += "<button type=\"button\" class=\"gp-btn\" disabled>Release from quarantine</button> " +
                 disabled_note;
        h += "</div></div>";
    }
    // Always shown: the console exposes the same authority as the REST routes, which run the
    // dispatch approval check (#6065) after the Security:Execute gate; REST has no approval
    // ticket, so a non-administrator is refused (REST records only; the server's reconciler
    // then dispatches).
    h += "<div class=\"hw-empty\" style=\"margin-top:12px\">Quarantine and release here need the "
         "<b>Security:Execute</b> permission on this device and are refused unless you are an "
         "administrator (with RBAC on, one who holds it globally), because the console has no approval step. Releasing ends the record only; run the "
         "plugin's unquarantine action from the <a href=\"/hardware/ci?id=" + url_enc(v.agent_id) +
         "&amp;lens=actions\">Actions</a> tab to remove the device's firewall rules.</div>";
    h += "</div>";
    return h;
}

} // namespace yuzu::server
