#include "home_panels_render.hpp"

#include "web_utils.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <ctime>
#include <format>

namespace yuzu::server::home_panels {

namespace {

constexpr std::size_t kTargetChars = 48;
constexpr std::size_t kFailingStoreNames = 5;

std::string header(const char* title, const std::string& sub, std::int64_t as_of) {
    std::string h = "<div class=\"hd\"><h3>";
    h += title;
    h += "</h3>";
    if (!sub.empty()) h += "<span class=\"sub\">" + html_escape(sub) + "</span>";
    h += "<span class=\"end mut\">As of " + hhmm_utc(as_of) + " UTC</span></div>";
    return h;
}

std::string section(const char* id, const std::string& head, const std::string& body) {
    return std::string("<section class=\"panel\" id=\"") + id + "\">" + head +
           "<div class=\"pb\">" + body + "</div></section>";
}

std::string note(const std::string& text, bool bad = false) {
    return std::string("<div class=\"note") + (bad ? " warn" : "") + "\">" + html_escape(text) +
           "</div>";
}

/// The distinct sentence for every non-Ok state. `what` names the figure in
/// "Could not read <what>".
std::string state_note(FactState s, const std::string& securable, const char* what) {
    switch (s) {
    case FactState::Denied:
        if (securable == kAdminOnlyNeed)
            return note("Recent activity is shown to administrators only.");
        return note("You do not have access to this panel. It needs " + securable + ".");
    case FactState::Limited:
        return note("Fleet totals are not shown to accounts limited to a group of devices.");
    case FactState::Unavailable:
    default:
        return note(std::string("Could not read ") + what + ". This is not zero.", true);
    case FactState::Ok:
        return {};
    }
}

} // namespace

std::string hhmm_utc(std::int64_t epoch_secs) {
    std::time_t t = static_cast<std::time_t>(epoch_secs < 0 ? 0 : epoch_secs);
    std::tm tm_val{};
#ifdef _WIN32
    gmtime_s(&tm_val, &t);
#else
    gmtime_r(&t, &tm_val);
#endif
    return std::format("{:02}:{:02}", tm_val.tm_hour, tm_val.tm_min);
}

// ── Policies ─────────────────────────────────────────────────────────────

int pass_percent(std::int64_t compliant, std::int64_t total) {
    if (total <= 0 || compliant <= 0) return 0;
    if (compliant >= total) return 100;
    return static_cast<int>(compliant * 100 / total);
}

PolicyPanel select_lowest_policies(const std::vector<Policy>& policies,
                                   const std::vector<ComplianceSummary>& summaries) {
    struct Ranked {
        PolicyBar bar;
        std::string id;
    };
    std::vector<Ranked> with_results, without;
    std::size_t enabled = 0;
    for (const auto& p : policies) {
        if (!p.enabled) continue;
        ++enabled;
        Ranked r{{p.name, 0, 0}, p.id};
        for (const auto& s : summaries) {
            if (s.policy_id == p.id) {
                r.bar.compliant = s.compliant;
                r.bar.total = s.total;
                break;
            }
        }
        (r.bar.total > 0 ? with_results : without).push_back(std::move(r));
    }
    std::sort(with_results.begin(), with_results.end(), [](const Ranked& a, const Ranked& b) {
        // Cross-multiplied so equal percentages compare equal without rounding.
        const auto l = a.bar.compliant * b.bar.total;
        const auto r = b.bar.compliant * a.bar.total;
        if (l != r) return l < r;
        if (a.bar.name != b.bar.name) return a.bar.name < b.bar.name;
        return a.id < b.id;
    });
    std::sort(without.begin(), without.end(), [](const Ranked& a, const Ranked& b) {
        return a.bar.name != b.bar.name ? a.bar.name < b.bar.name : a.id < b.id;
    });
    PolicyPanel out;
    out.enabled_total = enabled;
    for (auto* v : {&with_results, &without})
        for (auto& r : *v) {
            if (out.lowest.size() >= kPolicyRows) break;
            out.lowest.push_back(std::move(r.bar));
        }
    return out;
}

std::string render_policies_panel(const Fact<PolicyPanel>& f, std::int64_t as_of_secs) {
    if (f.state != FactState::Ok)
        return section("home-policies", header("Compliance by policy", {}, as_of_secs),
                       state_note(f.state, f.need, "policy compliance"));
    const auto& p = f.value;
    if (p.enabled_total == 0)
        return section("home-policies", header("Compliance by policy", {}, as_of_secs),
                       note("No policies are defined."));
    std::string rows;
    for (const auto& b : p.lowest) {
        rows += "<div class=\"kvl\"><div><span>" + html_escape(b.name) + "</span>";
        if (b.total <= 0) {
            rows += "<b>No results yet</b></div></div><div class=\"bar\"><i style=\"width:0%\"></i></div>";
        } else {
            const int pct = pass_percent(b.compliant, b.total);
            rows += "<b>" + std::to_string(b.compliant) + "/" + std::to_string(b.total) + " (" +
                    std::to_string(pct) + "%)</b></div></div><div class=\"bar";
            const char* lvl = compliance_level(pct);
            if (lvl[0] == 'w') rows += " w";
            if (lvl[0] == 'b') rows += " b";
            rows += "\"><i style=\"width:" + std::to_string(pct) + "%\"></i></div>";
        }
    }
    const std::string sub = "Lowest " + std::to_string(p.lowest.size()) + " of " +
                            std::to_string(p.enabled_total) + " policies";
    return section("home-policies", header("Compliance by policy", sub, as_of_secs), rows);
}

// ── Activity ─────────────────────────────────────────────────────────────

std::vector<ActivityRow> to_activity_rows(const std::vector<AuditEvent>& events) {
    std::vector<ActivityRow> out;
    out.reserve(events.size());
    for (const auto& e : events) {
        ActivityRow r;
        r.timestamp = e.timestamp;
        r.principal = e.principal;
        r.action = e.action;
        if (!e.target_type.empty() || !e.target_id.empty())
            r.target = e.target_type + ":" + e.target_id;
        r.result = e.result;
        out.push_back(std::move(r));
    }
    return out;
}

std::string render_activity_panel(const Fact<std::vector<ActivityRow>>& f, std::int64_t as_of_secs,
                                  const std::string& audit_href) {
    std::string head = header("Recent activity", {}, as_of_secs);
    if (!audit_href.empty()) { // empty = no audit page, button omitted
        // The "Audit log" button sits in the header's trailing group.
        const std::string btn = "<a class=\"btn sm\" href=\"" + html_escape(audit_href) +
                                "\">Audit log</a>";
        const auto pos = head.rfind("</div>");
        head.insert(pos, btn);
    }
    if (f.state != FactState::Ok)
        return section("home-activity", head, state_note(f.state, f.need, "recent activity"));
    if (f.value.empty())
        return section("home-activity", head, note("No activity recorded yet."));
    std::string t = "<table class=\"tw\"><thead><tr><th>Time</th><th>Who</th><th>Action</th>"
                    "<th>Target</th><th>Result</th></tr></thead><tbody>";
    for (const auto& r : f.value) {
        const char* pill = r.result == "success"  ? "ok"
                           : r.result == "failure" ? "bad"
                           : r.result == "denied"  ? "warn"
                                                   : "idle";
        t += "<tr><td title=\"" + html_escape(format_iso_utc(r.timestamp)) + "\">" +
             hhmm_utc(r.timestamp) + "</td><td>" + html_escape(r.principal) +
             "</td><td class=\"mono\">" + html_escape(r.action) + "</td><td class=\"mono\" title=\"" +
             html_escape(r.target) + "\">" +
             html_escape(r.target.empty() ? std::string("-") : truncate_utf8(r.target, kTargetChars)) +
             "</td><td><span class=\"pill " + pill + "\">" + html_escape(r.result) +
             "</span></td></tr>";
    }
    t += "</tbody></table>";
    return section("home-activity", head, t);
}

// ── Health ───────────────────────────────────────────────────────────────

std::optional<HealthPanel> parse_health_json(const std::string& body) {
    using nlohmann::json;
    const auto j = json::parse(body, nullptr, false);
    if (!j.is_object()) return std::nullopt;
    const auto st = j.find("status");
    const auto stores = j.find("stores");
    const auto up = j.find("uptime_seconds");
    const auto ag = j.find("agents");
    if (st == j.end() || !st->is_string() || stores == j.end() || !stores->is_object() ||
        up == j.end() || !up->is_number_integer() || ag == j.end() || !ag->is_object())
        return std::nullopt;
    const auto online = ag->find("online");
    if (online == ag->end() || !online->is_number_integer()) return std::nullopt;

    HealthPanel h;
    h.healthy = st->get<std::string>() == "healthy";
    h.uptime_seconds = up->get<std::int64_t>();
    h.agents_online = online->get<std::int64_t>();
    for (auto it = stores->begin(); it != stores->end(); ++it) {
        const bool ok = it.value().is_string() && it.value().get<std::string>() == "ok";
        if (it.key() == "pg_reachable") h.pg_reachable = ok;
        if (!ok) h.failing_stores.push_back(it.key());
    }
    if (const auto v = j.find("version"); v != j.end() && v->is_string())
        h.version = v->get<std::string>();
    if (const auto ex = j.find("executions"); ex != j.end() && ex->is_object()) {
        const auto inf = ex->find("in_flight");
        if (inf != ex->end() && inf->is_number_integer())
            h.executions_running = inf->get<std::int64_t>();
    }
    return h;
}

namespace {
std::string format_uptime(std::int64_t s) {
    if (s < 0) s = 0;
    const auto d = s / 86400, h = (s % 86400) / 3600, m = (s % 3600) / 60;
    if (d > 0) return std::format("{}d {}h", d, h);
    if (h > 0) return std::format("{}h {}m", h, m);
    return std::format("{}m", m);
}
} // namespace

std::string render_health_panel(const Fact<HealthPanel>& f, std::int64_t as_of_secs) {
    const std::string head = header("Server health", {}, as_of_secs);
    if (f.state != FactState::Ok) {
        if (f.state == FactState::Unavailable)
            return section("home-health", head, note("Server health could not be read.", true));
        return section("home-health", head, state_note(f.state, f.need, "server health"));
    }
    const auto& h = f.value;
    auto row = [](const std::string& k, const std::string& v) {
        return "<div><span>" + html_escape(k) + "</span><b>" + v + "</b></div>";
    };
    std::string status = h.healthy ? "<span class=\"pill ok\">Healthy</span>"
                                   : "<span class=\"pill warn\">Degraded</span>";
    if (!h.healthy && !h.failing_stores.empty()) {
        std::string names;
        for (std::size_t i = 0; i < h.failing_stores.size() && i < kFailingStoreNames; ++i) {
            if (i) names += ", ";
            names += h.failing_stores[i];
        }
        if (h.failing_stores.size() > kFailingStoreNames)
            names += " and " + std::to_string(h.failing_stores.size() - kFailingStoreNames) + " more";
        status += " <span class=\"mut\">" + html_escape(names) + "</span>";
    }
    std::string b = "<div class=\"kvl\">";
    b += row("Status", status);
    b += row("Database", h.pg_reachable ? "PostgreSQL reachable" : "PostgreSQL not reachable");
    b += row("Uptime", html_escape(format_uptime(h.uptime_seconds)));
    if (h.executions_running) b += row("Executions running", std::to_string(*h.executions_running));
    b += row("Agents connected to this server", std::to_string(h.agents_online));
    if (!h.version.empty()) b += row("Version", "<span class=\"mono\">" + html_escape(h.version) + "</span>");
    b += "</div>";
    return section("home-health", head, b);
}

} // namespace yuzu::server::home_panels
