/// @file device_estate_render.cpp
/// See device_estate_render.hpp.

#include "device_estate_render.hpp"

#include "web_utils.hpp"

namespace yuzu::server {

namespace {

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

} // namespace

std::string stored_data_placeholder(const std::string& agent_id) {
    return "<div id=\"hw-stored-data\" hx-get=\"/fragments/hardware/ci/stored-data?id=" +
           url_enc(agent_id) + "\" hx-trigger=\"click\" hx-swap=\"outerHTML\" "
           "style=\"margin-top:18px\"><button type=\"button\" class=\"gp-btn\">Stored data&hellip;"
           "</button></div>";
}

std::string render_stored_data_panel(const StoredDataView& v) {
    const std::string confirm_value = v.hostname.empty() ? v.agent_id : v.hostname;
    std::string h = "<section id=\"hw-stored-data\" class=\"hw-panel\" style=\"margin-top:18px\">"
                    "<div class=\"hw-hd\"><h2>Stored data</h2></div><div class=\"ci-sec\">";
    h += "<p>Removing stored data erases what Yuzu holds about this device from seven stores: "
         "generic inventory, installed software, device configuration item, application "
         "performance, detected licences, application usage, and the endpoint presence row. "
         "It cannot be undone.</p>"
         "<p>It does <b>not</b> unenrol the device. If the agent is still connected it will "
         "report again and the data will come back. Tags, custom properties, quarantine records "
         "and property schemas are not removed.</p>"
         "<p>The attempt is written to the audit log before anything is erased; if the audit "
         "entry cannot be written, nothing is erased.</p>";
    h += "<div id=\"hw-stored-data-result\"></div>";
    if (v.gate == StoredDataView::Gate::Allowed) {
        h += "<button type=\"button\" class=\"gp-btn\" data-act=\"stored-data-remove\" data-agent=\"" +
             html_escape(v.agent_id) + "\" data-host=\"" + html_escape(v.hostname) +
             "\" data-confirm=\"" + html_escape(confirm_value) + "\">Remove stored data&hellip;</button>";
    } else {
        h += "<button type=\"button\" class=\"gp-btn\" disabled>Remove stored data&hellip;</button> "
             "<span class=\"gp-mute\">";
        h += v.gate == StoredDataView::Gate::Denied
                 ? "Needs the <b>Decommission:Delete</b> permission for this device."
                 : "Permission could not be checked; try again shortly.";
        h += "</span>";
    }
    h += "</div></section>";
    return h;
}

} // namespace yuzu::server
