// Audit page panels: pure HTML renderers (see access_audit_render.hpp for the contract).

#include "access_audit_render.hpp"

#include "web_utils.hpp"

#include <cstdio>
#include <ctime>

namespace yuzu::server::access_audit {

namespace {

constexpr std::string_view kLogUrl = "/fragments/access/audit/log";

std::string esc(std::string_view s) {
    return html_escape(std::string(s));
}

// gmtime_r on an out-of-range value fails; both time strings derive from this one helper so a
// cell and its title cannot disagree (B4).
std::optional<std::tm> utc_parts(std::int64_t epoch) {
    if (epoch <= 0)
        return std::nullopt;
    const std::time_t t = static_cast<std::time_t>(epoch);
    if (static_cast<std::int64_t>(t) != epoch)
        return std::nullopt;
    std::tm tm{};
#ifdef _WIN32
    if (gmtime_s(&tm, &t) != 0)
        return std::nullopt;
#else
    if (gmtime_r(&t, &tm) == nullptr)
        return std::nullopt;
#endif
    return tm;
}

std::string failbox(std::string_view lead, std::string_view why, const std::string& retry) {
    std::string out = "<div class=\"failbox\" role=\"alert\"><div><b>" + esc(lead) +
                      "</b><br><span class=\"guard\">" + esc(why) + "</span></div>";
    if (!retry.empty())
        out += "<div class=\"end\">" + retry + "</div>";
    return out + "</div>";
}

std::string bad_filter(const BadFilter& b) {
    return "<div class=\"empty\" role=\"note\"><b>That request was not understood</b>" +
           esc(b.reason) + "</div>";
}

struct Pill {
    const char* tone;
    std::string label;
};

// Display normalisation only: the raw token is always in the pill's title.
Pill result_pill(const std::string& raw) {
    if (raw == "ok" || raw == "success")
        return {"ok", "Success"};
    if (raw == "failure" || raw == "error")
        return {"bad", "Failed"};
    if (raw == "denied")
        return {"warn", "Denied"};
    if (raw == "partial")
        return {"warn", "Partial"};
    return {"idle", esc(raw)};
}

std::string result_cell(const std::string& raw) {
    const auto p = result_pill(raw);
    return std::string("<span class=\"pill ") + p.tone + "\" title=\"result = &quot;" + esc(raw) +
           "&quot;\">" + p.label + "</span>";
}

std::string log_url(const LogView& v, int offset) {
    std::string u(kLogUrl);
    u += "?range=" + std::string(range_token(v.range));
    if (!v.principal.empty())
        u += "&principal=" + access::url_q(v.principal);
    if (!v.action.empty())
        u += "&action=" + access::url_q(v.action);
    u += "&offset=" + std::to_string(offset);
    return u;
}

std::string_view window_words(Range r) {
    switch (r) {
    case Range::Hour:
        return "the last hour";
    case Range::Day:
        return "the last 24 hours";
    case Range::Week:
        return "the last 7 days";
    }
    return "the window";
}

std::string who_cell(const AuditEvent& e) {
    if (e.principal.empty())
        return "<span class=\"hint\" title=\"Pre-session event: the attempted username is in "
               "Target\">Not signed in</span>";
    return "<b>" + esc(e.principal) + "</b>";
}

std::string target_cell(const AuditEvent& e) {
    if (e.target_type.empty() && e.target_id.empty())
        return "<span class=\"hint\">None</span>";
    return (e.target_type.empty() ? std::string{}
                                  : "<span class=\"sub\">" + esc(e.target_type) + "</span>") +
           esc(e.target_id);
}

std::string event_rows(const AuditEvent& e) {
    const std::string id = std::to_string(e.id);
    const std::string when = format_utc_short(e.timestamp);
    const std::string detail_title = e.detail.empty() ? std::string{} : esc(e.detail);
    std::string out = "<tr class=\"result-row\"><td title=\"" + format_utc_iso(e.timestamp) +
                      "\"><button type=\"button\" class=\"btn link sm\" data-act=\"toggle-row\" "
                      "aria-expanded=\"false\" aria-controls=\"ev-" + id + "\">" + when +
                      "</button></td><td class=\"trunc\" title=\"" + esc(e.principal) + "\">" +
                      who_cell(e) + "</td><td class=\"trunc wide\"><span class=\"mono\">" +
                      esc(e.action) + "</span>";
    if (!e.detail.empty())
        out += "<span class=\"sub\" title=\"" + detail_title + "\">" + detail_title + "</span>";
    out += "</td><td class=\"trunc\" title=\"" + esc(e.target_id) + "\">" + target_cell(e) +
           "</td><td>" + result_cell(e.result) + "</td></tr>";

    const auto kv = [](std::string_view label, const std::string& value) {
        return "<span class=\"detail-label\">" + std::string(label) +
               "</span><span class=\"detail-value\">" + value + "</span>";
    };
    out += "<tr class=\"result-detail\" id=\"ev-" + id + "\"><td colspan=\"5\"><div "
           "class=\"detail-content\">" +
           kv("Event id", id) +
           kv("Principal", e.principal.empty() ? std::string("(empty: not signed in)")
                                               : esc(e.principal)) +
           kv("Target", esc(e.target_type) + (e.target_type.empty() ? "" : " ") + esc(e.target_id)) +
           kv("Time", format_utc_iso(e.timestamp) + " (epoch " + std::to_string(e.timestamp) + ")") +
           kv("Detail", e.detail.empty() ? std::string("(none)") : esc(e.detail)) +
           "</div></td></tr>";
    return out;
}

std::string pager(const LogView& v) {
    const int first = v.offset + 1;
    const int last = v.offset + static_cast<int>(v.rows.size());
    const bool older_ok = v.has_more && v.offset + kPageSize <= kAuditMaxOffset;
    const int prev = v.offset >= kPageSize ? v.offset - kPageSize : 0;
    std::string out = "<div class=\"pb pager\"><span class=\"hint\">Rows " + std::to_string(first) +
                      " to " + std::to_string(last) + ", " + std::to_string(kPageSize) +
                      " per page. The server does not return a filtered total, and events "
                      "written while you page can shift later pages.";
    if (v.has_more && !older_ok)
        out += " Paging stops at 10,000 rows; narrow the time range.";
    out += "</span><div class=\"end\"><button type=\"button\" class=\"btn sm\"";
    if (v.offset == 0)
        out += " disabled";
    else
        out += " hx-get=\"" + esc(log_url(v, prev)) + "\" hx-target=\"#audit-log\"";
    out += ">Newer</button><button type=\"button\" class=\"btn sm\"";
    if (!older_ok)
        out += " disabled";
    else
        out += " hx-get=\"" + esc(log_url(v, v.offset + kPageSize)) + "\" hx-target=\"#audit-log\"";
    return out + ">Older</button></div></div>";
}

std::string render_log_view(const LogView& v) {
    if (v.rows.empty())
        return "<div class=\"empty\"><b>No events match</b>The audit store answered: zero rows in " +
               esc(window_words(v.range)) +
               " with these filters. Widen the time range or clear a filter.</div>";
    std::string out = "<div class=\"tw\"><table class=\"dense\"><thead><tr><th>Time (UTC)</th>"
                      "<th>Who</th><th>Action</th><th>Target</th><th>Result</th></tr></thead>"
                      "<tbody>";
    for (const auto& e : v.rows)
        out += event_rows(e);
    return out + "</tbody></table></div>" + pager(v);
}

} // namespace

std::optional<Range> parse_range(std::string_view token) {
    if (token == "1h")
        return Range::Hour;
    if (token == "24h")
        return Range::Day;
    if (token == "7d")
        return Range::Week;
    return std::nullopt;
}

std::string_view range_token(Range r) {
    switch (r) {
    case Range::Hour:
        return "1h";
    case Range::Day:
        return "24h";
    case Range::Week:
        return "7d";
    }
    return "24h";
}

std::int64_t range_seconds(Range r) {
    switch (r) {
    case Range::Hour:
        return 3600;
    case Range::Day:
        return 86400;
    case Range::Week:
        return 604800;
    }
    return 86400;
}

std::string format_utc_short(std::int64_t epoch) {
    static constexpr const char* kMonths[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    const auto tm = utc_parts(epoch);
    if (!tm || tm->tm_mon < 0 || tm->tm_mon > 11)
        return "-";
    char buf[32];
    std::snprintf(buf, sizeof buf, "%02d %s %02d:%02d:%02d", tm->tm_mday, kMonths[tm->tm_mon],
                  tm->tm_hour, tm->tm_min, tm->tm_sec);
    return buf;
}

std::string format_utc_iso(std::int64_t epoch) {
    const auto tm = utc_parts(epoch);
    if (!tm)
        return "-";
    char buf[32];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02dZ", tm->tm_year + 1900,
                  tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
    return buf;
}

std::string render_audit_log(const std::variant<LogView, access::Unavailable, BadFilter>& state) {
    if (const auto* v = std::get_if<LogView>(&state))
        return render_log_view(*v);
    if (const auto* b = std::get_if<BadFilter>(&state))
        return bad_filter(*b);
    // Retry re-sends the toolbar's live values; Unavailable carries no view by design.
    const std::string retry =
        "<button type=\"button\" class=\"btn sm\" hx-get=\"" + std::string(kLogUrl) +
        "\" hx-include=\"#audit-filters\" hx-target=\"#audit-log\">Retry</button>";
    return "<div class=\"pb\">" + failbox("The audit log could not be read.", kLogUnavailable, retry) +
           "</div>";
}

std::string render_auth_sample(const std::variant<SampleView, access::Unavailable, BadFilter>& state) {
    if (const auto* b = std::get_if<BadFilter>(&state))
        return bad_filter(*b);
    if (std::holds_alternative<access::Unavailable>(state))
        return "<div class=\"pb\">" +
               failbox("The sample could not be drawn.", kSampleUnavailable, {}) + "</div>";
    const auto& s = std::get<SampleView>(state);
    std::string out;
    if (s.audit_failed)
        out += "<div class=\"pb\">" +
               failbox("The sample was drawn but its audit record could not be written.",
                       "Treat this draw as unrecorded until the audit store recovers.", {}) +
               "</div>";
    if (s.rows.empty()) {
        out += "<div class=\"empty\"><b>No authentication events</b>The audit store answered: no "
               "sign-in, MFA, session or engine-principal events to draw from.</div>";
    } else {
        out += "<div class=\"tw\"><table class=\"dense\"><thead><tr><th>Action</th><th>Result</th>"
               "<th>Time (UTC)</th></tr></thead><tbody>";
        for (const auto& e : s.rows)
            out += "<tr><td class=\"trunc\" title=\"" + esc(e.principal) + "\"><span "
                   "class=\"mono\">" + esc(e.action) + "</span><span class=\"sub\">" +
                   (e.principal.empty() ? std::string("Not signed in") : esc(e.principal)) +
                   "</span></td><td>" + result_cell(e.result) + "</td><td title=\"" +
                   format_utc_iso(e.timestamp) + "\">" + format_utc_short(e.timestamp) +
                   "</td></tr>";
        out += "</tbody></table></div>";
    }
    out += "<div class=\"pb\"><p class=\"hint\">" + std::to_string(s.rows.size()) +
           " rows drawn from " + std::to_string(s.candidates) + " candidates (scan cap " +
           std::to_string(kAuditSampleScanCap) + "; " +
           (s.recency_capped ? "recency-capped: the pool was only the newest events"
                             : "not recency-capped") +
           "). This is a random sample for evidence, not a count. Drawing it is recorded in the "
           "audit log.</p></div>";
    return out;
}

std::string render_retention(int days) {
    return "<div class=\"kvl\"><div><span>Kept for</span><b>" + std::to_string(days) +
           " days</b></div><div><span>Cleaned up</span><b>Hourly</b></div></div>"
           "<div class=\"pb\"><p class=\"hint\">Read only. There is no tamper-evidence beyond "
           "access control: no hash chain or signature exists.</p></div>";
}

} // namespace yuzu::server::access_audit
