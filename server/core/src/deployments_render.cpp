#include "deployments_render.hpp"

#include "deployment_parse.hpp" // step_from_token / step_token
#include "web_utils.hpp"        // html_escape, format_iso_utc

#include <string>

namespace yuzu::server {

namespace {

std::string esc(const std::string& s) { return html_escape(s); }

std::string when(std::int64_t ms) { return ms > 0 ? format_iso_utc(ms / 1000) : std::string("-"); }

// Device error text is an agent or server string; bound what one row can print.
constexpr std::size_t kErrorCap = 200;

std::string capped(const std::string& s) {
    return s.size() <= kErrorCap ? s : s.substr(0, kErrorCap) + "...";
}

std::string pill(const DeploymentState& st) {
    return "<span class=\"pill " + st.tone + "\" data-state=\"" + esc(st.code) + "\">" +
           esc(st.label) + "</span>";
}

int settled(const DeploymentRow& d) { return d.succeeded + d.failed + d.skipped; }

} // namespace

DeploymentState deployment_state(const std::string& status, int failed, int skipped) {
    if (status == "running")
        return {"running", "Running", "info"};
    if (status == "complete") {
        if (failed > 0)
            return {"complete_failed", "Complete, " + std::to_string(failed) + " failed", "warn"};
        if (skipped > 0)
            return {"complete_skipped", "Complete, " + std::to_string(skipped) + " skipped", "warn"};
        return {"complete", "Complete", "ok"};
    }
    return {"unknown", "Unknown", "idle"};
}

std::string render_deployments_list(const std::vector<DeploymentRow>& rows,
                                    const std::vector<std::string>& target_labels,
                                    bool truncated) {
    if (rows.empty())
        return "<div class=\"gp-placeholder\" data-empty=\"deployments\">No deployments in the last "
               "14 days. A deployment starts from a pre-flight run.</div>";
    std::string h = "<table class=\"dense\" id=\"deployments-table\"><thead><tr>"
                    "<th>Deployment</th><th>Target</th><th>Progress</th><th>State</th>"
                    "<th>Started</th></tr></thead><tbody>";
    for (std::size_t i = 0; i < rows.size(); ++i) {
        const auto& d = rows[i];
        const std::string target = (i < target_labels.size() && !target_labels[i].empty())
                                       ? target_labels[i]
                                       : std::string("Run no longer kept");
        h += "<tr data-dep=\"" + esc(d.deployment_id) + "\"><td><a href=\"#\" hx-get=\"/fragments/auto/deployments/detail?dep=" +
             esc(url_query_value(d.deployment_id)) +
             "\" hx-target=\"#auto-detail\" hx-swap=\"innerHTML\" hx-sync=\"#auto-detail:replace\">" +
             esc(d.name) + "</a><div class=\"hint\">" + esc(d.artifact_filename) + "</div></td><td>" + esc(target) +
             "</td><td><progress max=\"" + std::to_string(d.total) + "\" value=\"" +
             std::to_string(settled(d)) + "\"></progress> " + std::to_string(settled(d)) + " of " +
             std::to_string(d.total) + "</td><td>" +
             pill(deployment_state(d.status, d.failed, d.skipped)) + "</td><td>" +
             when(d.created_at_ms) + "</td></tr>";
    }
    h += "</tbody></table>";
    if (truncated)
        h += "<div class=\"hint\" data-truncated=\"1\">Showing the newest " +
             std::to_string(rows.size()) + " deployments. Older ones are not listed here.</div>";
    return h;
}

std::string render_deployment_detail(const DeploymentRow& dep,
                                     const std::vector<DeploymentDeviceRow>& devices) {
    const bool truncated = dep.total > static_cast<int>(devices.size());
    const auto st = deployment_state(dep.status, dep.failed, dep.skipped);
    std::string h = "<div class=\"panel\" data-deployment=\"" + esc(dep.deployment_id) + "\">";
    h += "<h3>" + esc(dep.name) + " " + pill(st) + "</h3><dl class=\"kvl\">";
    h += "<dt>Artifact</dt><dd>" + esc(dep.artifact_filename) + "</dd>";
    h += "<dt>SHA-256</dt><dd><code>" + esc(dep.artifact_sha256) + "</code></dd>";
    h += std::string("<dt>Installer arguments</dt><dd>") +
         (dep.exec_args.empty() ? "None" : "Set (not shown)") + "</dd>";
    h += "<dt>Started</dt><dd>" + when(dep.created_at_ms) + "</dd>";
    h += "<dt>Completed</dt><dd>" + when(dep.completed_at_ms) + "</dd></dl>";
    h += "<div class=\"readout\" data-counts=\"1\">targeted " + std::to_string(dep.total) +
         " &middot; succeeded " + std::to_string(dep.succeeded) + " &middot; failed " +
         std::to_string(dep.failed) + " &middot; skipped " + std::to_string(dep.skipped) +
         " &middot; in flight " + std::to_string(dep.active) + "</div>";
    if (dep.status == "running")
        h += "<div class=\"hint\">Counts are as of the last advance. A running deployment advances only while its deploy results view (Pre-flight and "
             "deploy, then Deploy) is open; this Deployments tab is read-only and never advances it.</div>";
    if (devices.empty()) {
        h += "<div class=\"gp-placeholder\" data-empty=\"devices\">No device rows.</div>";
    } else {
        h += "<table class=\"dense\"><thead><tr><th>Device</th><th>OS</th><th>Step</th>"
             "<th>Exit</th><th>Detail</th></tr></thead><tbody>";
        for (const auto& d : devices) {
            const std::string host = d.hostname.empty() ? d.agent_id : d.hostname;
            h += "<tr><td>" + esc(host) + "</td><td>" + esc(d.os) + "</td><td>" +
                 deployment::step_token(deployment::step_from_token(d.step)) + "</td><td>" +
                 std::to_string(d.exit_code) + "</td><td>" + esc(capped(d.error)) + "</td></tr>";
        }
        h += "</tbody></table>";
    }
    if (truncated)
        h += "<div class=\"hint\" data-truncated=\"1\">Showing the first " +
             std::to_string(devices.size()) + " of " + std::to_string(dep.total) +
             " devices. The counts above are exact.</div>";
    h += "</div>";
    return h;
}

std::string render_deployments_failbox(const std::string& what) {
    return "<div class=\"failbox\" role=\"alert\">" + esc(what) + "</div>";
}

} // namespace yuzu::server
