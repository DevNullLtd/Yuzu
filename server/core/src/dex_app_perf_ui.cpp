/// @file dex_app_perf_ui.cpp
/// Slice-2 dashboard renderers for DEX app-perf-over-time — the app picker + the
/// per-(app,version) trend table (fleet B2 or named-group B1). PURE functions over
/// the reduced model (`app_perf_version_summaries`), so the HTMX surface, the REST
/// endpoints, and the MCP tools all read the SAME numbers.
///
/// Product UI: HTMX, server-rendered, dark-theme only, htmx core attrs only (CSP
/// blocks hx-on). Sparklines are server-rendered SVG — no client JS. Reuses the
/// shared full-page shell's `.gp-*` component CSS (guardian_page_ui.cpp), same as
/// the sibling DEX renderers. Honesty: absent percentiles render "—" (never 0),
/// an open-top-bucket percentile renders "≥ value" (a floor), a sub-floor named-
/// group point shows its count only. Crashes/hangs per version are DEFERRED in v1
/// (a separate central crash-store join) — the foot notes the gap.

#include "dex_app_perf_ui.hpp"

#include "web_utils.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <format>
#include <string>
#include <vector>

namespace yuzu::server {

// Shared with dex_routes.cpp (declared in dex_routes.hpp).
std::string dex_window_token(int window_days);
std::string dex_subnav(const std::string& active, int window_days);

namespace {

std::string esc(const std::string& s) { return html_escape(s); }

// Percent-encode for a query-string value (RFC 3986 unreserved kept literal) —
// same helper the sibling DEX renderers carry in their anonymous namespaces.
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
    return "<a hx-get=\"" + path_qs +
           "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" style=\"cursor:pointer;\">" +
           disp + "</a>";
}

std::string fmt_pct(double v) { return std::format("{:.1f}%", v); }

// "1.9 GB" / "390 MB" human form for a working-set byte count.
std::string fmt_bytes(double b) {
    if (b >= 1024.0 * 1024.0 * 1024.0)
        return std::format("{:.1f} GB", b / (1024.0 * 1024.0 * 1024.0));
    if (b >= 1024.0 * 1024.0)
        return std::format("{:.0f} MB", b / (1024.0 * 1024.0));
    return std::format("{:.0f} KB", b / 1024.0);
}

// A UTC-midnight epoch-seconds day → "YYYY-MM-DD" (std::chrono, no global gmtime).
std::string ymd(std::int64_t day_epoch_s) {
    using namespace std::chrono;
    const sys_days d = floor<days>(sys_seconds{seconds{day_epoch_s}});
    const year_month_day cal{d};
    return std::format("{:04}-{:02}-{:02}", static_cast<int>(cal.year()),
                       static_cast<unsigned>(cal.month()), static_cast<unsigned>(cal.day()));
}

// p95 cell: "≥X%" when the value is an open-top-bucket floor, "X%" otherwise,
// "—" when withheld (empty population OR a stale histogram scheme).
std::string pctile_cell(const std::optional<HistPctile>& p) {
    if (!p)
        return "&mdash;";
    return (p->lower_bound ? "&ge;&nbsp;" : "") + fmt_pct(p->value);
}

// Server-rendered, CSP-safe sparkline over a daily series. < 2 points → em dash.
std::string spark(const std::vector<double>& vals) {
    if (vals.size() < 2)
        return "<span class=\"gp-mute\">&mdash;</span>";
    constexpr double w = 110, h = 22, p = 2;
    const double mn = *std::min_element(vals.begin(), vals.end());
    const double mx = *std::max_element(vals.begin(), vals.end());
    const double rng = (mx - mn) > 1e-9 ? (mx - mn) : 1.0;
    std::string pts;
    for (std::size_t i = 0; i < vals.size(); ++i) {
        const double x = p + static_cast<double>(i) * (w - 2 * p) /
                                 static_cast<double>(vals.size() - 1);
        const double y = h - p - (vals[i] - mn) / rng * (h - 2 * p);
        pts += std::format("{:.1f},{:.1f} ", x, y);
    }
    return "<svg width=\"110\" height=\"22\"><polyline fill=\"none\" stroke=\"#58a6ff\" "
           "stroke-width=\"1.5\" points=\"" + pts + "\"/></svg>";
}

// Case-insensitive ASCII substring match helper — mirrors the ?q= search idiom
// already used by the device list (device_routes.cpp's to_lower/matches).
std::string ci_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Best-effort Windows/Linux split for the picker's platform chips. `AppPerfAppSummary`
// (app_perf_fleet_store.hpp) is keyed on (app_name, version, day) only — it carries
// NO real platform column — so this is a NAME-SUFFIX heuristic, not an authoritative
// field: a ".exe"-suffixed name is treated as Windows, anything else as Linux. It
// cannot distinguish Linux from macOS, which is why the picker offers only
// Windows/Linux chips (unlike the Catalogue OS filter's four). The rendered note
// says so; revisit if/when a real per-app platform column lands.
bool looks_windows(const std::string& app_name) {
    const std::string lower = ci_lower(app_name);
    return lower.size() >= 4 && lower.compare(lower.size() - 4, 4, ".exe") == 0;
}

// Canonical sort token — unrecognized/absent falls back to the default, mirroring
// dex_window_token's validate-and-default idiom.
std::string app_perf_sort_token(const std::string& sort) {
    return (sort == "name" || sort == "versions") ? sort : "last_seen";
}

} // namespace

std::string render_dex_app_perf_picker(const std::vector<AppPerfAppSummary>& apps, bool truncated,
                                       int window_days, const std::string& q,
                                       const std::string& platform, const std::string& sort) {
    const std::string w = dex_window_token(window_days);
    const std::string plat = (platform == "windows" || platform == "linux") ? platform : "";
    const std::string sortv = app_perf_sort_token(sort);

    std::string h;
    h += "<a class=\"gp-back\" href=\"/\">&larr; Dashboard</a>";
    h += dex_subnav("app_perf", window_days);
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>Application performance "
         "over time</h1></div><div class=\"gp-sub\">Per-application CPU &amp; memory across the "
         "fleet, broken out by version, over the retained window. Pick an application to compare "
         "its versions.</div></div></div>";

    if (apps.empty())
        return h + placeholder("No application performance history yet",
                               "Per-application performance roll-ups appear here once devices "
                               "report retained daily summaries. Per-application sampling is "
                               "opt-in (procperf_enabled, off by default) — enable it on the "
                               "devices you want to track.");

    // -- Controls: search, platform, sort — CSP-safe (htmx core attrs only, no
    // hx-on). Each control's hx-get carries every OTHER current param so a
    // re-fetch never silently drops a sibling filter (the Catalogue OS-chip
    // idiom in dex_routes.cpp). ------------------------------------------------
    const std::string qs_plat = plat.empty() ? "" : "&platform=" + plat;
    const std::string qs_q = q.empty() ? "" : "&q=" + url_encode(q);
    const std::string qs_sort = "&sort=" + sortv;

    h += "<div class=\"gp-filters\"><input name=\"q\" value=\"" + esc(q) +
         "\" placeholder=\"Search applications\xE2\x80\xA6\" "
         "style=\"background:var(--surface);color:var(--fg);border:1px solid var(--border);"
         "border-radius:.4rem;padding:.3rem .6rem;font-size:.78rem;min-width:220px\" "
         "hx-get=\"/fragments/dex/perf/apps?window=" + w + qs_plat + qs_sort +
         "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
         "hx-trigger=\"keyup changed delay:300ms\"></div>";

    {
        auto chip = [&](const char* val, const char* label) {
            const std::string on = (plat.empty() ? std::string("all") : plat) == val ? " on" : "";
            const std::string val_qs = std::string(val) == "all" ? "" : "&platform=" + std::string(val);
            return "<a class=\"gp-chip" + on + "\" hx-get=\"/fragments/dex/perf/apps?window=" + w +
                   val_qs + qs_sort + qs_q +
                   "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" + label + "</a>";
        };
        h += "<div class=\"gp-filters\"><span class=\"gp-mute\" style=\"font-size:.66rem;"
             "align-self:center\">Platform</span>" +
             chip("all", "All") + chip("windows", "Windows") + chip("linux", "Linux") + "</div>";
        h += "<div class=\"gp-mute\" style=\"font-size:.66rem;margin-top:.2rem\">Platform is "
             "inferred from the app name (&quot;.exe&quot; = Windows) &mdash; it is not a "
             "tracked field yet, so a mismatch is possible.</div>";
    }

    {
        auto opt = [&](const char* val, const char* label) {
            return "<option value=\"" + std::string(val) + "\"" +
                   (sortv == val ? " selected" : "") + ">" + label + "</option>";
        };
        h += "<div class=\"gp-filters\"><span class=\"gp-mute\" style=\"font-size:.66rem;"
             "align-self:center\">Sort</span><select name=\"sort\" "
             "hx-get=\"/fragments/dex/perf/apps?window=" + w + qs_plat + qs_q +
             "\" hx-trigger=\"change\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
             "style=\"background:var(--surface);color:var(--fg);border:1px solid var(--border);"
             "border-radius:.35rem;padding:.15rem .4rem;\">" +
             opt("last_seen", "Last seen (most recent)") + opt("name", "Name (A-Z)") +
             opt("versions", "Versions (most first)") + "</select></div>";
    }

    // -- Filter + sort (in-memory over the fetched universe — see looks_windows) --
    const std::string qlc = ci_lower(q);
    std::vector<const AppPerfAppSummary*> filtered;
    for (const auto& a : apps) {
        if (!plat.empty() && looks_windows(a.app_name) != (plat == "windows"))
            continue;
        if (!qlc.empty() && ci_lower(a.app_name).find(qlc) == std::string::npos)
            continue;
        filtered.push_back(&a);
    }
    std::stable_sort(filtered.begin(), filtered.end(),
                     [&](const AppPerfAppSummary* x, const AppPerfAppSummary* y) {
                         if (sortv == "name")
                             return ci_lower(x->app_name) < ci_lower(y->app_name);
                         if (sortv == "versions")
                             return x->versions > y->versions;
                         return x->last_day > y->last_day; // last_seen (default)
                     });

    h += "<div class=\"gp-note\">" + std::to_string(filtered.size()) + " of " +
         std::to_string(apps.size()) + " application" + (apps.size() == 1 ? "" : "s") +
         (q.empty() ? "" : " match &quot;" + esc(q) + "&quot;") + "</div>";

    if (filtered.empty()) {
        h += placeholder("No applications match",
                         q.empty() ? "No applications match the selected platform filter."
                                  : "No applications match \"" + q + "\". Try a different search "
                                    "term or clear the filters.");
        return h;
    }

    h += "<table class=\"gp-table\"><thead><tr><th>Application</th><th>Versions seen</th>"
         "<th>Last reported</th></tr></thead><tbody>";
    for (const auto* ap : filtered) {
        const auto& a = *ap;
        h += "<tr><td>" +
             drill("/fragments/dex/perf/app?app=" + url_encode(a.app_name) + "&amp;window=" + w,
                   esc(a.app_name)) +
             "</td><td>" + std::to_string(a.versions) + "</td><td>" + ymd(a.last_day) +
             "</td></tr>";
    }
    h += "</tbody></table>";
    if (truncated)
        h += "<div class=\"gp-note\">List capped &mdash; more applications have history than "
             "shown. Use the REST API (<span style=\"font-family:var(--mono)\">"
             "/api/v1/dex/perf/apps</span>) for the full set.</div>";
    h += "<div class=\"gp-note\">Aggregate roll-up of small daily per-device summaries "
         "(ADR-0004) &mdash; the raw per-process stream never leaves the device. Per-version "
         "crashes/hangs are a planned enrichment (a separate central crash store).</div>";
    return h;
}

std::string render_dex_app_perf_trend(const std::string& app_name,
                                      const std::vector<AppPerfVersionSummary>& versions,
                                      const std::string& scope_group_id,
                                      const std::vector<DexGroupOption>& groups,
                                      std::int64_t group_floor, int window_days,
                                      const std::string& active_version,
                                      const std::vector<std::string>& model_values,
                                      const std::string& active_model) {
    const std::string w = dex_window_token(window_days);
    const bool is_group = !scope_group_id.empty();
    const bool is_model = !is_group && !active_model.empty();
    const bool is_filtered = !active_version.empty();
    std::string h;
    h += "<a class=\"gp-back\" hx-get=\"/fragments/dex/perf/apps?window=" + w +
         "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
         "style=\"cursor:pointer;\">&larr; All applications</a>";

    // Header. The scope is named in the subtitle so a group rollup is never
    // mistaken for the fleet aggregate.
    std::string scope_name = "the whole fleet";
    if (is_group) {
        scope_name = "a management group";
        for (const auto& g : groups)
            if (g.id == scope_group_id) {
                scope_name = esc(g.name);
                break;
            }
    } else if (is_model) {
        scope_name = "devices modeled " + esc(active_model);
    }
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>" + esc(app_name) +
         " <span class=\"gp-mute\" style=\"font-weight:400;font-size:.85rem\">&mdash; by version, "
         "over time</span></h1></div><div class=\"gp-sub\">CPU &amp; memory per version across <b>" +
         scope_name + "</b>. Each row's trend is the daily mean over the retained history; the "
         "headline is the most recent day.</div></div></div>";

    // Version filter — click-through, not a dropdown: the only valid values are
    // the versions already on screen, so a filtered version's own row links back
    // to "All versions" and (below) each unfiltered row links to itself. Narrows
    // server-side via the SAME `version` param the REST twin (`GET
    // /dex/perf/app?version=`) accepts, an exact/canonicalized match — never a
    // client-side slice of a wider fetch.
    // Named-cohort query-string suffix shared by every link below (version
    // filter, scope-empty back-link, per-row narrow) — group and model are
    // mutually exclusive so exactly one (or neither) is ever appended.
    const std::string cohort_qs = is_group ? "&amp;group=" + url_encode(scope_group_id)
                                  : is_model ? "&amp;model=" + url_encode(active_model)
                                             : "";
    if (is_filtered) {
        const std::string all_qs = "app=" + url_encode(app_name) + "&amp;window=" + w + cohort_qs;
        h += "<div class=\"gp-note\">Filtered to version <span style=\"font-family:var(--mono)\">" +
             esc(active_version) + "</span> &mdash; " +
             drill("/fragments/dex/perf/app?" + all_qs, "all versions &rarr;") + "</div>";
    }

    // Reverse cross-link to the crash/hang blast radius — same process-image key
    // (app_name), exact match, no normalization (symmetric twin of the forward
    // link on the Apps-tab detail page).
    h += "<div class=\"gp-note\">" +
         drill("/fragments/dex/app?name=" + url_encode(app_name) + "&amp;window=" + w,
               "Crashes &amp; hangs for this application &rarr;") +
         "</div>";

    // -- Scope selector (CSP-safe: htmx hx-get on change sends the select's
    // name=value, appended to the URL query — the proven cohort-picker idiom).
    if (!groups.empty()) {
        std::string base = "/fragments/dex/perf/app?app=" + url_encode(app_name) +
                           "&amp;window=" + w;
        if (is_filtered)
            base += "&amp;version=" + url_encode(active_version); // preserve the version filter
        h += "<div class=\"gp-note\">Scope: <select name=\"group\" hx-get=\"" + base +
             "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" hx-trigger=\"change\" "
             "hx-sync=\"#guardian-detail:replace\" "
             "style=\"background:var(--surface);color:var(--fg);border:1px solid var(--border);"
             "border-radius:.35rem;padding:.15rem .4rem;\">";
        h += "<option value=\"\"" + std::string(is_group ? "" : " selected") +
             ">Whole fleet</option>";
        for (const auto& g : groups) {
            const bool on = (g.id == scope_group_id);
            h += "<option value=\"" + esc(g.id) + "\"" + (on ? " selected" : "") + ">" +
                 esc(g.name) + "</option>";
        }
        h += "</select></div>";
    }

    // Device-model cohort selector — independent of, and mutually exclusive
    // with, the management-group one above (see this function's header
    // comment): its own `hx-get` base carries no `group=`, so picking a model
    // value always drops any active group scope, and vice versa.
    if (!model_values.empty()) {
        std::string mbase = "/fragments/dex/perf/app?app=" + url_encode(app_name) +
                            "&amp;window=" + w;
        if (is_filtered)
            mbase += "&amp;version=" + url_encode(active_version);
        h += "<div class=\"gp-note\">Model: <select name=\"model\" hx-get=\"" + mbase +
             "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" hx-trigger=\"change\" "
             "hx-sync=\"#guardian-detail:replace\" "
             "style=\"background:var(--surface);color:var(--fg);border:1px solid var(--border);"
             "border-radius:.35rem;padding:.15rem .4rem;\">";
        h += "<option value=\"\"" + std::string(is_model ? "" : " selected") +
             ">Whole fleet</option>";
        for (const auto& mv : model_values) {
            const bool on = is_model && mv == active_model;
            h += "<option value=\"" + esc(mv) + "\"" + (on ? " selected" : "") + ">" + esc(mv) +
                 "</option>";
        }
        h += "</select></div>";
    } else {
        // #4857 D1: `fleet_snapshot` has no degrade channel, so a genuine
        // zero-cohort-population read never claims a "degraded" state.
        // Reaching THIS branch does NOT mean `dex_perf_api_` is unwired —
        // the caller (dex_routes.cpp's route handler) already returned an
        // "unavailable" placeholder earlier in that case, before this
        // model-selector code runs at all; an unwired API never reaches
        // here. Governance round-2 (G8-2, cpp-expert): the empty
        // `model_values` this branch renders for is NOT uniformly "devices
        // reporting with no model tag" — it is equally reached when ZERO
        // devices report anything this cycle at all (a genuinely empty
        // fleet snapshot, e.g. `DexPerfFn` returning no devices), which is
        // not "reporting devices, just untagged". The wording below is
        // deliberately neutral over both causes rather than presupposing
        // reporting devices exist (the untagged residual is deliberately
        // excluded from `model_values` either way, see the caller's
        // comment) — disclose the absence honestly rather than silently
        // omitting the selector (the pre-#4857 `TagValuesFn` convention this
        // replaces).
        h += "<div class=\"gp-note\">Model: no device-model values in the current fleet "
             "snapshot.</div>";
    }

    if (versions.empty()) {
        std::string empty_sub =
            is_group ? "No member of this group reported retained performance for this "
                       "application in the window."
            : is_model ? "No device of this model reported retained performance for this "
                        "application in the window."
                     : "No device reported retained performance for this application in the "
                       "window.";
        if (is_filtered) {
            const std::string all_qs = "app=" + url_encode(app_name) + "&amp;window=" + w + cohort_qs;
            h += "<div class=\"gp-note\">" +
                 drill("/fragments/dex/perf/app?" + all_qs, "&larr; all versions") + "</div>";
        }
        return h + placeholder("No performance history for this application", empty_sub);
    }

    // The version with the most recent day is tagged "latest" (a factual cue, not
    // a verdict) — compute the max latest_day once.
    std::int64_t newest = 0;
    for (const auto& v : versions)
        newest = (std::max)(newest, v.latest_day);

    h += "<table class=\"gp-table\"><thead><tr><th>Version</th><th>Avg CPU</th><th>p95 CPU</th>"
         "<th>CPU trend</th><th>Avg working set</th><th>Devices</th></tr></thead><tbody>";
    for (const auto& v : versions) {
        const std::string tag =
            (v.latest_day == newest && versions.size() > 1)
                ? " <span style=\"font-size:.62rem;color:#062534;background:var(--accent);"
                  "border-radius:.3rem;padding:.03rem .35rem;font-weight:700\">latest</span>"
                : "";
        // Narrow-to-this-version link — skipped when already filtered (only one
        // row anyway) or for the "(no version)" bucket, whose empty string can't
        // be expressed as `?version=` without colliding with "unfiltered".
        std::string ver;
        if (v.version.empty()) {
            ver = "<span class=\"gp-mute\">(no version)</span>";
        } else if (is_filtered) {
            ver = "<span style=\"font-family:var(--mono)\">" + esc(v.version) + "</span>";
        } else {
            std::string qs = "app=" + url_encode(app_name) + "&amp;window=" + w +
                             "&amp;version=" + url_encode(v.version) + cohort_qs;
            ver = drill("/fragments/dex/perf/app?" + qs,
                        "<span style=\"font-family:var(--mono)\">" + esc(v.version) + "</span>");
        }
        if (v.suppressed) {
            // Sub-floor named-group slice → count only (works-council floor).
            h += "<tr><td>" + ver + tag +
                 "</td><td colspan=\"4\" class=\"gp-mute\">&mdash; n too small (fewer than " +
                 std::to_string(group_floor) + " devices on its latest day &mdash; stats "
                 "withheld)</td><td>" + std::to_string(v.device_count) + "</td></tr>";
            continue;
        }
        // Devices-cell click-to-expand: fleet-wide ONLY (neither is_group nor
        // is_model). A named-cohort-scoped trend (management group OR device
        // model) does not (yet) narrow the version-devices drill to the
        // cohort's own members — showing the affordance there would silently
        // widen what "devices" means for that row (see dex_routes.cpp's route
        // registration comment for the v1-scope reason), so it is omitted
        // rather than shown-but-wrong. `hx-target="closest tr" hx-swap="afterend"`
        // inserts the server's returned `<tr>` immediately below THIS row with
        // no pre-existing placeholder and no client JS; `hx-trigger="click once"`
        // means a second click is a no-op (reveal-only, no collapse — matches
        // this row's own "latest tag" simplicity bar).
        std::string devices_cell = std::to_string(v.device_count);
        if (!is_group && !is_model) {
            // `version=` with an EXPLICITLY EMPTY value is unambiguous here (unlike
            // the trend's own version-filter link above): this route requires
            // `version` PRESENT (not merely non-empty) and treats "" as the valid
            // "unknown version" bucket, never "unfiltered" — so the `(no version)`
            // row gets the affordance too (the ONLY bucket Linux procperf ever
            // reports, tar_proc_perf.cpp).
            const std::string devices_qs =
                "app=" + url_encode(app_name) + "&amp;version=" + url_encode(v.version);
            devices_cell += " <a style=\"cursor:pointer;font-size:.68rem\" class=\"gp-mute\" "
                            "hx-get=\"/fragments/dex/perf/app/devices?" +
                            devices_qs +
                            "\" hx-target=\"closest tr\" hx-swap=\"afterend\" "
                            "hx-trigger=\"click once\">&#9656; devices</a>";
        }
        h += "<tr><td>" + ver + tag + "</td><td>" + fmt_pct(v.cpu_mean) + "</td><td>" +
             pctile_cell(v.cpu_p95) + "</td><td>" + spark(v.cpu_series) + "</td><td>" +
             fmt_bytes(static_cast<double>(v.ws_mean)) + "</td><td>" + devices_cell +
             "</td></tr>";
    }
    h += "</tbody></table>";

    std::string foot =
        "Each cell is a roll-up of daily per-device summaries (ADR-0004); the raw per-process "
        "stream never leaves the device. <b>Avg CPU</b> / <b>Avg working set</b> are the latest "
        "day's exact mean across the reporting devices; <b>p95</b> is read from the fixed-bucket "
        "histogram (device p95s can't be averaged), shown as &ldquo;&ge; value&rdquo; when it "
        "lands in the open top bucket. <b>CPU trend</b> is the daily mean over the retained "
        "history. Per-version crashes/hangs are deferred (a separate crash store).";
    if (is_group || is_model)
        foot += " This is a <b>named cohort of specific devices</b>" +
                std::string(is_model ? " (device model)" : " (management group)") +
                ", so any version whose latest day covers fewer than " +
                std::to_string(group_floor) +
                " devices shows its count only (works-council co-determination). Cohort scope reads "
                "the per-device store (up to <b>31 days</b>); the whole-fleet view covers the full "
                "<b>180-day</b> aggregate, so a cohort series is shorter for the same app.";
    else
        foot += " &ldquo;&#9656; devices&rdquo; on a version row lists the devices where this "
                "exact version was among the device's own top resource consumers — not a full "
                "inventory of every device running it, and per-device data is retained only 31 "
                "days (shorter than this 180-day trend), so an old version row can legitimately "
                "list none.";
    h += "<div class=\"gp-note\">" + foot + "</div>";
    return h;
}

std::string render_dex_app_perf_version_devices(const std::vector<AppPerfVersionDeviceRow>& devices,
                                                bool truncated) {
    if (devices.empty()) {
        // Two independent, equally-legitimate reasons collapse to the identical
        // empty state (deliberately combined rather than guessed apart — see
        // this fn's own doc comment in dex_app_perf_ui.hpp): the top-N sampling
        // simply never named this app-version, OR the per-device (B1, 31-day)
        // data has aged out even though the fleet trend (B2, 180-day) still
        // shows it.
        return "<div class=\"gp-note\">No device reported this exact app/version among its "
               "retained top resource consumers. Either the device's daily top-N sampling "
               "(procperf) never picked this app-version as resource-significant on any "
               "reporting device, or this version's per-device data has aged past the "
               "<b>31-day</b> retention window even though the fleet trend above covers up to "
               "<b>180 days</b> &mdash; the two stores retain independently.</div>";
    }
    std::string h = "<table class=\"gp-table\" style=\"margin:.3rem 0 0 1.2rem;width:auto\">"
                    "<thead><tr><th>Device</th><th>Last seen</th><th>CPU</th>"
                    "<th>Working set</th></tr></thead><tbody>";
    for (const auto& d : devices) {
        h += "<tr><td style=\"font-family:var(--mono);font-size:.78rem\">" + esc(d.agent_id) +
             "</td><td>" + ymd(d.last_day) + "</td><td>" + fmt_pct(d.cpu_avg) + "</td><td>" +
             fmt_bytes(static_cast<double>(d.ws_avg_bytes)) + "</td></tr>";
    }
    h += "</tbody></table>";
    h += "<div class=\"gp-note\" style=\"margin-left:1.2rem\">Devices where this exact "
         "app-version was among the device's own top resource consumers &mdash; <b>not a full "
         "inventory</b> of every device running it. &ldquo;Last seen&rdquo; is this version's "
         "most recent reported day within the 31-day per-device retention.</div>";
    if (truncated)
        h += "<div class=\"gp-note\" style=\"margin-left:1.2rem\">List capped &mdash; showing "
             "the highest-CPU devices only; more devices reported this version than shown.</div>";
    return h;
}

namespace {

// The "newest version" cue — a factual tag (most recent day on this device), not a
// verdict. Same idiom as the fleet trend's latest tag.
const char* const kLatestTag =
    " <span style=\"font-size:.62rem;color:#062534;background:var(--accent);border-radius:.3rem;"
    "padding:.03rem .35rem;font-weight:700\">latest</span>";

// One version's metric cells (Avg CPU · Peak CPU · CPU trend · Avg WS · Peak WS ·
// Instances · Days) — shared by the single-version combined row and the multi-
// version sub-row so the two layouts cannot drift.
std::string device_metric_cells(const AppPerfDeviceVersion& v) {
    return "<td>" + fmt_pct(v.cpu_avg) + "</td><td>" + fmt_pct(v.cpu_max) + "</td><td>" +
           spark(v.cpu_series) + "</td><td>" + fmt_bytes(static_cast<double>(v.ws_avg)) +
           "</td><td>" + fmt_bytes(static_cast<double>(v.ws_max)) + "</td><td>" +
           std::to_string(v.instances_max) + "</td><td>" + std::to_string(v.day_count) + "</td>";
}

std::string version_label(const AppPerfDeviceVersion& v) {
    return v.version.empty() ? "<span class=\"gp-mute\">(no version)</span>"
                             : "<span style=\"font-family:var(--mono)\">" + esc(v.version) + "</span>";
}

} // namespace

std::string render_dex_device_app_perf(const std::vector<AppPerfDeviceApp>& apps) {
    if (apps.empty())
        return placeholder("No application performance history for this device",
                           "This device has reported no retained daily application performance "
                           "yet. Per-application sampling is opt-in (procperf_enabled, off by "
                           "default) and a daily summary appears only after the first completed "
                           "UTC day — enable it on this device to populate this view.");

    std::string h = "<table class=\"gp-table\"><thead><tr><th>Application / version</th>"
                    "<th>Avg CPU</th><th>Peak CPU</th><th>CPU trend</th><th>Avg working set</th>"
                    "<th>Peak working set</th><th>Instances</th><th>Days</th></tr></thead><tbody>";
    for (const auto& app : apps) {
        if (app.versions.size() == 1) {
            // Common case: collapse the app + its one version into a single row.
            const auto& v = app.versions.front();
            h += "<tr><td><span style=\"font-weight:600;color:var(--white)\">" + esc(app.app_name) +
                 "</span> " + version_label(v) + "</td>" + device_metric_cells(v) + "</tr>";
            continue;
        }
        // Multi-version: an app header row (the version count) then per-version
        // sub-rows, each carrying its OWN perf — "v125 vs v124 on this box" reads
        // straight off adjacent rows. The version(s) on the newest day are tagged
        // "latest" by day-equality (NOT by row position) — same idiom as the fleet
        // renderer, so a day-tie tags both honestly and the cue does not silently
        // depend on the reducer's sort order.
        std::int64_t newest = 0;
        for (const auto& v : app.versions)
            newest = (std::max)(newest, v.latest_day);
        h += "<tr style=\"background:var(--surface)\"><td style=\"font-weight:700;color:var(--white)\">" +
             esc(app.app_name) + " <span class=\"gp-mute\" style=\"font-weight:400;font-size:.7rem\">&middot; " +
             std::to_string(app.versions.size()) +
             " versions</span></td><td colspan=\"7\" class=\"gp-mute\">per-version below</td></tr>";
        for (const auto& v : app.versions) {
            const std::string tag = (v.latest_day == newest) ? kLatestTag : "";
            h += "<tr><td style=\"padding-left:1.5rem\">" + version_label(v) + tag + "</td>" +
                 device_metric_cells(v) + "</tr>";
        }
    }
    h += "</tbody></table>";
    h += "<div class=\"gp-note\">Retained <b>daily</b> per-application summaries from the central "
         "store (up to <b>31 days</b>) &mdash; the &ldquo;over time, on this box&rdquo; companion "
         "to the fleet trend. <b>Avg</b> CPU / working set are the sample-weighted window mean; "
         "<b>Peak</b> is the window maximum; <b>CPU trend</b> is the daily mean over the window. "
         "Top resource-significant app-versions only (procperf top-N), names + version only "
         "&mdash; command lines and image paths are never collected. Per-version crashes/hangs are "
         "deferred (a separate central crash-store join on the shared (name, version) identity).</div>";
    return h;
}

} // namespace yuzu::server
