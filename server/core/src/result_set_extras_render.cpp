#include "result_set_extras_render.hpp"

#include "web_utils.hpp"

namespace yuzu::server {

using yuzu::server::html_escape;

std::string render_result_set_members(const std::string& set_id,
                                      const std::vector<std::string>& device_ids,
                                      const std::string& next_cursor, bool degraded,
                                      bool none_visible) {
    if (degraded) {
        return R"(<div class="rs-note" data-degraded="1">Members could not be read. )"
               R"(This is not an empty set.</div>)";
    }
    if (device_ids.empty() && next_cursor.empty()) {
        if (none_visible) {
            return R"(<div class="rs-note" data-hidden="1">None of the devices in this set )"
                   R"(are visible to you.</div>)";
        }
        return R"(<div class="rs-note" data-empty="1">This set has no devices.</div>)";
    }
    std::string h = "<ul class=\"rs-members\" data-count=\"" + std::to_string(device_ids.size()) +
                    "\">";
    for (const auto& id : device_ids)
        h += "<li><code>" + html_escape(id) + "</code></li>";
    h += "</ul>";
    if (!next_cursor.empty()) {
        // Replaces this whole fragment's trailing control with the next page, so the list grows.
        h += "<button type=\"button\" class=\"rs-btn\" hx-get=\"/fragments/result-sets/" +
             html_escape(set_id) + "/members?cursor=" + html_escape(next_cursor) +
             "\" hx-swap=\"outerHTML\">Show more</button>";
    }
    return h;
}

std::string render_result_set_producers(const std::vector<ResultSetProducer>& producers,
                                        bool truncated) {
    std::string h = "<div data-producers=\"1\"";
    if (truncated)
        h += " data-truncated=\"1\"";
    h += ">";
    // Amendment 1 / S2: this path dispatches without the approval ladder, so only auto
    // definitions are offered and the dialog says so in plain terms.
    h += "<p class=\"rs-note\" data-approval-note=\"1\">Only enabled, read-only instructions "
         "that do not need approval are listed. Approval rules are not applied when a result "
         "set is created from one.</p>";
    if (producers.empty()) {
        h += "<div class=\"rs-note\" data-empty=\"1\">No instruction can produce a result set "
             "yet.</div></div>";
        return h;
    }
    h += "<select>";
    for (const auto& p : producers) {
        h += "<option value=\"" + html_escape(p.id) + "\">" + html_escape(p.name) + " (" +
             html_escape(p.plugin) + ":" + html_escape(p.action) + ")</option>";
    }
    h += "</select>";
    if (truncated)
        h += "<p class=\"rs-note\">Showing the first definitions only. Narrow the library.</p>";
    h += "</div>";
    return h;
}

std::string render_result_set_members_denied() {
    return R"(<div class="empty-state" data-denied="true">You do not have permission to )"
           R"(view devices.</div>)";
}

std::string render_result_set_producers_denied() {
    return R"(<div class="empty-state" data-denied="true">Creating a result set from an )"
           R"(instruction needs permission to run instructions and to read definitions.</div>)";
}

std::string render_result_set_producers_degraded() {
    return R"(<div class="rs-note" data-degraded="1">Instruction definitions could not be )"
           R"(read. This is not an empty list.</div>)";
}

} // namespace yuzu::server
