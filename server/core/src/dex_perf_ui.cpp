/// @file dex_perf_ui.cpp
/// F2a: the /dex Performance tab renderers — PURE functions over a
/// DexPerfSnapshot (fleet-now cards + cohort benchmarking + the one devices
/// drill). Split from dex_routes.cpp (which registers the routes) to keep the
/// big TU from growing; the tiny markup helpers are deliberately re-declared
/// in this TU's anonymous namespace, same pattern as the sibling DEX TUs.
///
/// Product UI: HTMX, server-rendered, dark-theme only, htmx core attrs only
/// (CSP blocks hx-on). NO window chips here — this page is a now-view over
/// registry heartbeat state (trend charts are F2b, Postgres-gated). Honesty:
/// absent metrics render "—" (never 0), aggregates carry their reporting
/// population, sub-floor cohorts render "n too small", untagged devices are
/// an explicit residual row.
///
/// #4626 Concern B: includes the PURE `dex_perf_model.hpp` directly rather
/// than the httplib-coupled `dex_routes.hpp` (which still transitively pulls
/// store headers via its own `#include "dex_read_builders.hpp"`; the former
/// `dex_app_perf_ui.hpp` -> `dex_app_perf_model.hpp` chain was severed in
/// #4626). This TU's include-closure store-freedom is enforced by
/// `scripts/ci/check-seam-closure.py`'s `dex_perf` family — a header-closure
/// check over include basenames; it does not scan this file's text for store
/// type names.

#include "dex_perf_model.hpp"

#include "web_utils.hpp"

#include <cctype>
#include <format>
#include <set>
#include <string>
#include <vector>

namespace yuzu::server {

// Shared with dex_routes.cpp (declared in dex_routes.hpp).
std::string dex_subnav(const std::string& active, int window_days);
std::string dex_window_token(int window_days);

namespace {

std::string esc(const std::string& s) { return html_escape(s); }

// Percent-encode for a query-string value (RFC 3986 unreserved kept literal).
std::string url_encode(const std::string& s) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += kHex[c >> 4];
            out += kHex[c & 0x0F];
        }
    }
    return out;
}

std::string placeholder(const std::string& title, const std::string& sub) {
    return "<div class=\"gp-placeholder\"><b>" + esc(title) + "</b>" + esc(sub) + "</div>";
}

std::string drill(const std::string& path_qs, const std::string& disp) {
    return "<a hx-get=\"" + path_qs + "\" hx-target=\"#guardian-detail\" "
           "hx-swap=\"innerHTML\" style=\"cursor:pointer;\">" + disp + "</a>";
}

std::string fmt_pct(double v) { return std::format("{:.1f}%", v); }
std::string fmt_lat(double v) { return std::format("{:.1f} ms", v); }

/// "p50 6.2% · p90 24.8% · max 96.1%" — the stat strip under a fleet card.
std::string stat_strip(const DexPerfStat& s, bool lat) {
    auto f = [&](double v) { return lat ? fmt_lat(v) : fmt_pct(v); };
    return "p50 " + f(s.p50) + " &middot; p90 " + f(s.p90) + " &middot; max " + f(s.max);
}

/// One clickable fleet-now card. `big` and `strip` are pre-escaped/formatted.
std::string fleet_card(const char* label, const std::string& big, const std::string& strip,
                       const std::string& drill_qs, const char* drill_label) {
    return "<div class=\"gp-tile\"><div class=\"n\">" + big + "</div><div class=\"l\">" +
           std::string(label) + "</div><div class=\"sx\">" + strip + "<br>" +
           drill("/fragments/dex/perf/devices?" + drill_qs, std::string("&rarr; ") + drill_label) +
           "</div></div>";
}

/// "+42%" / "−21%" delta pill of a cohort p50 against the fleet p50 (empty
/// when either side is missing or the fleet p50 is ~0).
std::string delta_pill(const std::optional<DexPerfStat>& cohort,
                       const std::optional<DexPerfStat>& fleet) {
    if (!cohort || !fleet || fleet->p50 < 1e-9)
        return {};
    const double pct = (cohort->p50 - fleet->p50) / fleet->p50 * 100.0;
    const char* color = pct > 5.0 ? "var(--red)" : pct < -5.0 ? "var(--green)" : "var(--muted)";
    return " <span style=\"font-size:.85em;color:" + std::string(color) + ";\">" +
           std::format("{}{:.0f}%", pct > 0 ? "+" : "", pct) + "</span>";
}

/// "6.2% / 24.8%" cohort cell (p50 / p90), or the suppression dash.
std::string cohort_cell(const std::optional<DexPerfStat>& s, bool lat,
                        const std::optional<DexPerfStat>& fleet) {
    if (!s)
        return "&mdash;";
    auto f = [&](double v) { return lat ? fmt_lat(v) : fmt_pct(v); };
    return f(s->p50) + " / " + f(s->p90) + delta_pill(s, fleet);
}

// "1.9 GB" / "390 MB" human form for a working-set byte count.
std::string fmt_bytes(double b) {
    if (b >= 1024.0 * 1024.0 * 1024.0)
        return std::format("{:.1f} GB", b / (1024.0 * 1024.0 * 1024.0));
    if (b >= 1024.0 * 1024.0)
        return std::format("{:.0f} MB", b / (1024.0 * 1024.0));
    return std::format("{:.0f} KB", b / 1024.0);
}

} // namespace

std::string render_dex_procperf_panel(const std::vector<DexProcPerfRow>& rows,
                                      const std::string& window) {
    if (rows.empty()) {
        // The SOFT truthful empty state (grill decision 5/A): the read-only
        // operator-SQL surface deliberately hides tar.db config, so the server
        // cannot distinguish "disabled" from "enabled, no rollup yet". Say both.
        return "<div class=\"gp-note\"><b>No per-app samples in the last 24 hours.</b> "
               "Per-application sampling (<span style=\"font-family:var(--mono)\">"
               "procperf_enabled</span>) is <b>off by default</b> on every device &mdash; it is a "
               "separate, usage-class collection because it observes what people run, not just "
               "how the machine behaves &mdash; or sampling is on but no hourly rollup has "
               "completed yet. Device-level performance above is unaffected either way.</div>";
    }
    std::string h = "<table class=\"gp-table\"><thead><tr><th>Application</th><th>Avg CPU</th>"
                    "<th>Peak CPU</th><th>Avg working set</th><th>Peak working set</th>"
                    "<th>Max instances</th><th>Hours seen</th></tr></thead><tbody>";
    for (const auto& r : rows) {
        h += "<tr><td>" +
             drill("/fragments/dex/app?name=" + url_encode(r.name) + "&amp;window=" + window,
                   esc(r.name)) +
             "</td><td>" + fmt_pct(r.cpu_avg) + "</td><td>" + fmt_pct(r.cpu_max) + "</td><td>" +
             fmt_bytes(r.ws_avg_bytes) + "</td><td>" + fmt_bytes(r.ws_max_bytes) + "</td><td>" +
             std::to_string(r.instances_max) + "</td><td>" + std::to_string(r.hours) +
             "</td></tr>";
    }
    h += "</tbody></table>";
    h += "<div class=\"gp-note\">Top applications by CPU &cup; working set, 30&nbsp;s samples "
         "rolled up hourly on the device; process <b>names only</b> &mdash; command lines are "
         "never collected. Raw rows stay on the device (fetched live for this view). Click an "
         "application to open its reliability drill &mdash; per-app performance and per-app "
         "crashes cross-link.</div>";
    return h;
}

std::string render_dex_device_perf_context(const DexPerfDeviceContext& ctx,
                                           const std::string& cohort_key,
                                           const std::string& window) {
    std::string h = "<div class=\"gp-sech\">This device vs fleet &amp; cohort "
                    "<span class=\"gp-mute\">(current heartbeat vs current distributions)</span>"
                    "</div>";
    if (!ctx.found)
        return h + "<div class=\"gp-note\">Device is not online &mdash; no current sample to "
                   "compare.</div>";
    if (!ctx.reporting)
        return h + "<div class=\"gp-note\">No perf heartbeat from this device this cycle "
                   "&mdash; nothing to compare yet.</div>";

    struct StripRow {
        const char* label;
        const DexPerfMetricContext* m;
        bool lat;
    };
    const StripRow strips[] = {
        {"CPU utilization", &ctx.cpu, false},
        {"Memory commit", &ctx.commit, false},
        {"Disk I/O latency", &ctx.disk_lat, true},
    };
    h += "<div style=\"border:1px solid var(--border);border-radius:.55rem;padding:.6rem 1rem\">";
    for (const auto& s : strips) {
        if (!s.m->value || !s.m->fleet)
            continue; // device or fleet lacks this metric — skip the row, no fake bar
        const auto& f = *s.m->fleet;
        const double top = (std::max)(f.max, *s.m->value);
        auto x = [&](double v) {
            return top < 1e-9 ? 0.0 : (std::min)(98.0, v / top * 100.0);
        };
        const bool hot = *s.m->value > f.p90;
        auto fmt = [&](double v) { return s.lat ? fmt_lat(v) : fmt_pct(v); };
        std::string pv = "device " + fmt(*s.m->value) + " &rarr; fleet <b>" +
                         std::to_string(s.m->fleet_pctile) + "th</b> pctile";
        if (s.m->cohort_pctile >= 0)
            pv += " &middot; cohort <b>" + std::to_string(s.m->cohort_pctile) + "th</b>";
        h += "<div style=\"display:grid;grid-template-columns:9rem 1fr 17rem;gap:.8rem;"
             "align-items:center;margin:.45rem 0;font-size:.85rem\">"
             "<span>" + std::string(s.label) + "</span>"
             "<span style=\"position:relative;display:block;height:12px;border-radius:4px;"
             "background:var(--surface2,#243553)\">"
             "<span style=\"position:absolute;top:0;bottom:0;left:" +
             std::format("{:.1f}", x(f.p50)) + "%;width:" +
             std::format("{:.1f}", (std::max)(0.5, x(f.p90) - x(f.p50))) +
             "%;background:rgba(0,188,235,.22);border-left:1px solid rgba(0,188,235,.5);"
             "border-right:1px solid rgba(0,188,235,.5)\"></span>"
             "<span style=\"position:absolute;top:-2px;bottom:-2px;width:3px;border-radius:2px;"
             "left:" + std::format("{:.1f}", x(*s.m->value)) + "%;background:" +
             (hot ? "var(--red,#ff5765)" : "var(--yellow,#ffcc00)") + "\"></span></span>"
             "<span class=\"gp-mute\" style=\"text-align:right\">" + pv + "</span></div>";
    }
    h += "</div>";

    // Cohort caption — honest about which comparison the numbers are against.
    const bool cohort_shown = ctx.cpu.cohort_pctile >= 0 || ctx.commit.cohort_pctile >= 0 ||
                              ctx.disk_lat.cohort_pctile >= 0;
    if (cohort_shown) {
        const std::string label = ctx.cohort.empty() ? "(untagged)" : esc(ctx.cohort);
        h += "<div class=\"gp-note\">band = fleet p50&ndash;p90 &middot; marker = this device "
             "(red when above fleet p90). Cohort = " +
             drill("/fragments/dex/perf/devices?cohort_key=" + url_encode(cohort_key) +
                       "&amp;cohort_value=" + url_encode(ctx.cohort) + "&amp;window=" + window,
                   label) +
             " <span class=\"gp-mute\">(" + std::to_string(ctx.cohort_n) +
             " reporting devices, key " + esc(cohort_key) + ")</span></div>";
    } else {
        h += "<div class=\"gp-note\">band = fleet p50&ndash;p90 &middot; marker = this device "
             "(red when above fleet p90). Cohort comparison withheld &mdash; " +
             (ctx.cohort_n < kDexCohortFloor
                  ? "this device's cohort has only " + std::to_string(ctx.cohort_n) +
                        " reporting devices (floor " + std::to_string(kDexCohortFloor) + ")"
                  : std::string("no cohort resolved")) +
             ".</div>";
    }
    return h;
}

std::string render_dex_perf_fragment(const DexPerfSnapshot& snap, int window_days) {
    const std::string w = dex_window_token(window_days);
    const auto now = dex_perf_fleet_now(snap);

    std::string h;
    h += "<a class=\"gp-back\" href=\"/\">&larr; Dashboard</a>";
    h += dex_subnav("perf", window_days);
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>Fleet performance</h1>"
         "</div><div class=\"gp-sub\">Continuous device telemetry (30&nbsp;s on-device sampling) "
         "rolled up across the fleet &mdash; the levels, where Trends shows the events. Every "
         "aggregate carries its reporting population; click any card or cohort to open the "
         "devices behind it.</div></div></div>";

    // ── Over-time cross-reference (F2b) ── the retained per-app, per-version
    // trend has its own top-level "App Performance" sub-nav tab (dex_subnav)
    // now, so this is a plain pointer, not a special call-to-action — the tab
    // itself is the primary path there.
    h += "<div class=\"gp-note\">Performance <b>over time, by application &amp; version</b> is "
         "on the <b>App Performance</b> tab above &mdash; the retained daily roll-up, per app "
         "and version, fleet-wide or by group.</div>";

    // ── Fleet now ──
    h += "<div class=\"gp-sech\">Fleet now (last rollup cycle)</div>";
    if (now.reporting == 0) {
        h += placeholder("No perf telemetry yet",
                         "No device reported a perf heartbeat this cycle. Perf telemetry is "
                         "collected on Windows and Linux (TAR perf capture source; macOS support "
                         "is planned); devices appear here within a heartbeat of coming online.");
    } else {
        h += "<div class=\"gp-tiles\">";
        if (now.cpu)
            h += fleet_card("CPU utilization (avg)", fmt_pct(now.cpu->avg),
                            stat_strip(*now.cpu, false), "metric=cpu&window=" + w,
                            "worst devices by CPU");
        if (now.commit)
            h += fleet_card("Memory commit (avg)", fmt_pct(now.commit->avg),
                            stat_strip(*now.commit, false), "metric=commit&window=" + w,
                            "worst devices by commit");
        if (now.disk_lat)
            h += fleet_card("Disk I/O latency (avg)", fmt_lat(now.disk_lat->avg),
                            stat_strip(*now.disk_lat, true), "metric=disk_lat&window=" + w,
                            "worst devices by disk latency");
        const int64_t collecting_online = now.windows_online + now.linux_online + now.macos_online;
        h += fleet_card("Reporting", std::to_string(now.reporting),
                        "of " + std::to_string(collecting_online) + " online (Windows " +
                            std::to_string(now.windows_online) + " &middot; Linux " +
                            std::to_string(now.linux_online) + " &middot; macOS " +
                            std::to_string(now.macos_online) + ")",
                        "filter=not_reporting&window=" + w, "devices not reporting");
        h += "</div>";
        h += "<div class=\"gp-note\">Perf telemetry is collected on <b>Windows and Linux</b> "
             "today (macOS support is planned; macOS devices show as online above but never "
             "reporting). The Reporting card is the denominator for every stat above. The same "
             "numbers are exported as the "
             "<span style=\"font-family:var(--mono)\">yuzu_fleet_perf_*</span> and per-OS "
             "<span style=\"font-family:var(--mono)\">yuzu_fleet_perf_os_*</span> Prometheus "
             "gauges.</div>";
    }

    // ── Cohort benchmarking ──
    h += "<div class=\"gp-sech\">Cohort benchmarking</div>";
    if (snap.available_keys.empty()) {
        h += placeholder("No tags on the fleet yet",
                         "Cohorts are the distinct values of an operator-chosen tag key (e.g. "
                         "model, image, location). Tag the fleet via the REST tag API or the "
                         "asset-tagging recipe, and the comparison appears here.");
        return h;
    }

    // Key picker — htmx submits the select's own name=value on change.
    h += "<div class=\"gp-note\">cohort by tag key: <select name=\"key\" "
         "hx-get=\"/fragments/dex/perf?window=" + w + "\" hx-target=\"#guardian-detail\" "
         "hx-swap=\"innerHTML\" hx-trigger=\"change\" "
         "style=\"background:var(--surface);color:var(--fg);border:1px solid var(--border);"
         "border-radius:.35rem;padding:.15rem .4rem;\">";
    bool key_listed = false;
    for (const auto& k : snap.available_keys) {
        const bool on = (k == snap.cohort_key);
        key_listed = key_listed || on;
        h += "<option value=\"" + esc(k) + "\"" + (on ? " selected" : "") + ">" + esc(k) +
             "</option>";
    }
    if (!key_listed) // requested key has no tagged devices — show it anyway, honestly
        h += "<option value=\"" + esc(snap.cohort_key) + "\" selected>" + esc(snap.cohort_key) +
             " (no devices tagged)</option>";
    h += "</select></div>";

    const auto cohorts = dex_perf_cohorts(snap);
    if (cohorts.empty()) {
        h += placeholder("No reporting devices to benchmark",
                         "Cohort comparison needs devices reporting perf this cycle.");
        return h;
    }

    h += "<table class=\"gp-table\"><thead><tr><th>Cohort (" + esc(snap.cohort_key) +
         ")</th><th>Devices</th><th>CPU p50 / p90</th><th>Commit p50 / p90</th>"
         "<th>Disk lat p50 / p90</th></tr></thead><tbody>";
    for (const auto& c : cohorts) {
        const std::string label = c.cohort.empty() ? "(untagged)" : esc(c.cohort);
        const std::string qs = "cohort_key=" + url_encode(snap.cohort_key) +
                               "&amp;cohort_value=" + url_encode(c.cohort) + "&amp;window=" + w;
        h += "<tr><td>" + drill("/fragments/dex/perf/devices?" + qs, label) + "</td><td>" +
             std::to_string(c.devices) + "</td>";
        if (c.suppressed) {
            h += "<td colspan=\"3\" class=\"gp-mute\">&mdash; (n too small: fewer than " +
                 std::to_string(kDexCohortFloor) + " reporting devices)</td>";
        } else {
            h += "<td>" + cohort_cell(c.cpu, false, now.cpu) + "</td><td>" +
                 cohort_cell(c.commit, false, now.commit) + "</td><td>" +
                 cohort_cell(c.disk_lat, true, now.disk_lat) + "</td>";
        }
        h += "</tr>";
    }
    h += "</tbody></table>";
    h += "<div class=\"gp-note\">Percentiles compare within the chosen key&rsquo;s cohorts; the "
         "&Delta; against the fleet p50 marks cohorts running hot. Cohorts under " +
         std::to_string(kDexCohortFloor) +
         " reporting devices withhold percentiles (statistical floor); devices without the key "
         "always appear as the explicit (untagged) residual.</div>";

    // ── Compare two cohorts (F2c, BRD 99/103) ── the head-to-head A-vs-B diff,
    // the complement of the fleet-relative table above (e.g. vanilla vs layered).
    // Needs at least two cohorts to compare.
    if (cohorts.size() >= 2) {
        h += "<div class=\"gp-sech\">Compare two cohorts</div>";
        const std::string a0 = cohorts[0].cohort;
        const std::string b0 = cohorts[1].cohort;
        const std::string base = "/fragments/dex/perf/cohort-diff?key=" +
                                 url_encode(snap.cohort_key) + "&amp;window=" + w;
        // CSP-safe pickers: htmx hx-get on change; hx-include="#dex-cohort-pick"
        // pulls BOTH selects (the id wraps them) so changing either re-fetches
        // the comparison — the proven #id include form (cf. #filter-bar), no
        // hx-on/eval.
        auto picker = [&](const char* nm, const std::string& sel) {
            std::string s = "<select name=\"" + std::string(nm) + "\" hx-get=\"" + base +
                            "\" hx-trigger=\"change\" hx-include=\"#dex-cohort-pick\" "
                            "hx-target=\"#dex-cohort-diff\" hx-swap=\"innerHTML\" "
                            "style=\"background:var(--surface);color:var(--fg);border:1px solid "
                            "var(--border);border-radius:.35rem;padding:.15rem .4rem;\">";
            for (const auto& c : cohorts) {
                const std::string lbl = c.cohort.empty() ? "(untagged)" : esc(c.cohort);
                s += "<option value=\"" + esc(c.cohort) + "\"" +
                     (c.cohort == sel ? " selected" : "") + ">" + lbl + "</option>";
            }
            return s + "</select>";
        };
        h += "<div class=\"gp-note\" id=\"dex-cohort-pick\">A " + picker("a", a0) +
             " &nbsp;vs&nbsp; B " + picker("b", b0) + "</div>";
        // Auto-load the default (top-two cohorts) comparison; the pickers re-fetch on change.
        h += "<div id=\"dex-cohort-diff\" hx-get=\"" + base + "&amp;a=" + url_encode(a0) +
             "&amp;b=" + url_encode(b0) + "\" hx-trigger=\"load\" hx-swap=\"innerHTML\"></div>";
    }
    return h;
}

std::string render_dex_perf_cohort_diff_fragment(const DexPerfSnapshot& snap,
                                                 const std::string& cohort_a,
                                                 const std::string& cohort_b, int /*window_days*/) {
    const auto d = dex_perf_cohort_diff(snap, cohort_a, cohort_b);
    auto label = [](const std::string& c) {
        return c.empty() ? std::string("(untagged)") : esc(c);
    };
    // One cohort's p50 cell, honouring found / sub-floor suppression.
    auto cell = [](bool found, bool suppressed, const std::optional<DexPerfStat>& s, bool lat) {
        if (!found)
            return std::string("<span class=\"gp-mute\">no reporting devices</span>");
        if (suppressed)
            return std::string("<span class=\"gp-mute\">n too small</span>");
        if (!s)
            return std::string("&mdash;");
        return lat ? fmt_lat(s->p50) : fmt_pct(s->p50);
    };
    // Δ: A relative to B; same ±5% colour band as delta_pill (red = A hotter).
    auto delta = [](const std::optional<double>& dv) {
        if (!dv)
            return std::string("&mdash;");
        const char* color = *dv > 5.0 ? "var(--red)" : *dv < -5.0 ? "var(--green)" : "var(--muted)";
        return "<span style=\"color:" + std::string(color) + ";\">" +
               std::format("{}{:.0f}%", *dv > 0 ? "+" : "", *dv) + "</span>";
    };
    auto row = [&](const char* name, const std::optional<DexPerfStat>& sa,
                   const std::optional<DexPerfStat>& sb, const std::optional<double>& dv, bool lat) {
        return "<tr><td>" + std::string(name) + "</td><td>" +
               cell(d.found_a, d.a.suppressed, sa, lat) + "</td><td>" +
               cell(d.found_b, d.b.suppressed, sb, lat) + "</td><td>" + delta(dv) + "</td></tr>";
    };

    std::string h = "<table class=\"gp-table\"><thead><tr><th>Metric (p50)</th><th>" +
                    label(cohort_a) + " (A)</th><th>" + label(cohort_b) +
                    " (B)</th><th>&Delta; A vs B</th></tr></thead><tbody>";
    h += row("CPU utilization", d.a.cpu, d.b.cpu, d.cpu_delta_pct, false);
    h += row("Memory commit", d.a.commit, d.b.commit, d.commit_delta_pct, false);
    h += row("Disk I/O latency", d.a.disk_lat, d.b.disk_lat, d.disk_lat_delta_pct, true);
    h += "</tbody></table>";

    auto pop = [&](bool found, const DexPerfCohortRow& c) {
        return found ? std::to_string(c.devices) + " reporting" : std::string("absent");
    };
    h += "<div class=\"gp-note\">A = <b>" + label(cohort_a) + "</b> (" + pop(d.found_a, d.a) +
         "), B = <b>" + label(cohort_b) + "</b> (" + pop(d.found_b, d.b) +
         "). &Delta; is A&rsquo;s p50 relative to B&rsquo;s (B the baseline); a positive value "
         "means A runs hotter. A metric is compared only where both cohorts clear the " +
         std::to_string(kDexCohortFloor) + "-device floor.</div>";
    return h;
}

std::string render_dex_perf_devices_fragment(const DexPerfSnapshot& snap, DexPerfMetric metric,
                                             bool not_reporting,
                                             const std::optional<std::string>& cohort_filter,
                                             int limit, int window_days,
                                             const std::set<std::string>* visible) {
    const std::string w = dex_window_token(window_days);
    const auto rows = dex_perf_device_list(snap, metric, not_reporting, cohort_filter, limit);

    std::string title;
    if (not_reporting)
        title = "Devices not reporting performance";
    else if (cohort_filter)
        title = (cohort_filter->empty() ? "(untagged)" : esc(*cohort_filter)) +
                std::string(" &mdash; devices");
    else {
        const char* m = metric == DexPerfMetric::kCommit    ? "memory commit"
                        : metric == DexPerfMetric::kDiskLat ? "disk latency"
                                                            : "CPU";
        title = std::string("Worst devices by current ") + m;
    }

    std::string h;
    // Back link preserves the cohort key, so returning from an image-cohort
    // drill lands on the image table, not the default (grill fix).
    h += "<a class=\"gp-back\" hx-get=\"/fragments/dex/perf?window=" + w +
         (snap.cohort_key.empty() ? std::string{} : "&amp;key=" + url_encode(snap.cohort_key)) +
         "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
         "style=\"cursor:pointer;\">&larr; Fleet performance</a>";
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>" + title +
         "</h1></div><div class=\"gp-sub\">Values are each device&rsquo;s current heartbeat "
         "sample &mdash; the same data the fleet cards aggregate, so this list and the cards "
         "can never disagree.</div></div></div>";

    if (rows.empty())
        return h + placeholder(not_reporting ? "Everyone is reporting" : "No devices",
                               not_reporting
                                   ? "Every online Windows/Linux agent contributed a perf sample "
                                     "this cycle."
                                   : "No reporting devices match this view.");

    h += "<table class=\"gp-table\"><thead><tr><th>#</th><th>Device</th><th>Cohort" +
         (snap.cohort_key.empty() ? std::string{} : " (" + esc(snap.cohort_key) + ")") +
         "</th><th>CPU</th><th>Commit</th><th>Disk lat</th><th>vs fleet</th></tr></thead><tbody>";
    int i = 1;
    for (const auto& r : rows) {
        if (visible && !visible->count(r.agent_id))
            continue; // out-of-scope device — don't enumerate its id to this operator
        auto cell = [](const std::optional<double>& v, bool lat) {
            return v ? (lat ? fmt_lat(*v) : fmt_pct(*v)) : std::string("&mdash;");
        };
        h += "<tr><td class=\"gp-mute\">" + std::to_string(i++) + "</td><td>" +
             drill("/fragments/dex/device?id=" + url_encode(r.agent_id) + "&amp;window=" + w,
                   esc(r.agent_id)) +
             "</td><td>" + (r.cohort.empty() ? "<span class=\"gp-mute\">(untagged)</span>"
                                             : esc(r.cohort)) +
             "</td><td>" + cell(r.cpu_pct, false) + "</td><td>" + cell(r.commit_pct, false) +
             "</td><td>" + cell(r.disk_lat_ms, true) + "</td><td>" +
             (r.fleet_pctile >= 0 ? std::to_string(r.fleet_pctile) + "th pctile"
                                  : std::string("&mdash;")) +
             "</td></tr>";
    }
    h += "</tbody></table>";
    return h;
}

} // namespace yuzu::server
