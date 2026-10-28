#include "kek_panel_render.hpp"

namespace yuzu::server::kek_panel {

namespace {

std::string panel(const std::string& inner) {
    return "<section class=\"panel\" id=\"kek-panel\"><div class=\"hd\"><h2>Key-encryption key"
           "</h2></div>" +
           inner + "</section>";
}

std::string failbox(const char* headline) {
    return panel(std::string("<div class=\"pb\"><div class=\"failbox\" role=\"alert\"><span><b>") +
                 headline +
                 "</b> Status is not shown while it cannot be read.</span></div></div>");
}

} // namespace

std::string render(const Model& m) {
    switch (m.availability) {
    case Availability::Unavailable:
        return failbox("Key management is not available (secrets store not ready).");
    case Availability::QueryCanceled:
        return failbox("Key status could not be read: the query was canceled or timed out.");
    case Availability::Internal:
        return failbox("Key status could not be read (internal error).");
    case Availability::Ready:
        break;
    }

    std::string h;
    if (!m.rotation_complete && m.oldest_in_use) {
        const auto oldest = *m.oldest_in_use;
        h += "<div class=\"pb\"><div class=\"alert alert-warning\" role=\"status\"><span><b>"
             "Re-wrap incomplete:</b> ";
        if (oldest > m.active_version)
            h += "a stored secret references key version v" + std::to_string(oldest) +
                 ", which is newer than the active key v" + std::to_string(m.active_version) +
                 ". Re-wrap cannot fix this.";
        else
            h += "oldest key still in use is v" + std::to_string(oldest) + ", active is v" +
                 std::to_string(m.active_version) +
                 ". Re-wrap the secrets to finish. If the operation lock shows Held, a "
                 "rotation or re-wrap may be running; if it stays Held for a long time, see "
                 "\"Diagnosing a stuck KEK op lock\" in the server administration guide.";
        h += "</span></div></div>";
    }

    h += "<div class=\"kvl\"><div><span>Active key</span><b><code>secrets-kek-v" +
         std::to_string(m.active_version) + "</code></b></div>";
    h += "<div><span>Re-wrap</span><b>";
    if (m.rotation_complete)
        h += m.oldest_in_use ? "Complete" : "No stored secrets";
    else
        h += m.oldest_in_use
                 ? "Incomplete: oldest key still in use is v" + std::to_string(*m.oldest_in_use)
                 : std::string("Incomplete");
    h += "</b></div>";
    h += "<div><span>Live key versions</span><b>" +
         (m.live_versions ? std::to_string(*m.live_versions) : std::string("Unknown")) +
         "</b></div>";
    h += "<div><span>Operation lock</span><b>";
    if (!m.lock_held) {
        h += "Unknown";
    } else if (!*m.lock_held) {
        h += "Free";
    } else {
        h += "Held";
        if (m.lock_holder_pid) {
            h += "<small>backend pid " + std::to_string(*m.lock_holder_pid);
            if (!m.lock_captured_at.empty())
                h += ", read at " + m.lock_captured_at;
            h += "</small>";
        }
    }
    h += "</b></div></div>";
    h += "<div class=\"pb hint\">This panel shows status only. Rotate and re-wrap run through "
         "<code>POST /api/v1/secrets/kek/rotate</code> and <code>/rewrap</code> "
         "(MCP: <code>rotate_kek</code>, <code>rewrap_secrets</code>).</div>";
    return panel(h);
}

} // namespace yuzu::server::kek_panel
