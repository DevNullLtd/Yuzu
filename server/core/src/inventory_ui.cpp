/// @file inventory_ui.cpp
/// /inventory dashboard renderers — PURE functions over the inventory store result
/// types. Split from inventory_routes.cpp (which registers the routes) to keep each
/// TU small (same pattern as network_ui.cpp / dex_perf_ui.cpp).
///
/// Product UI: HTMX, server-rendered, dark-theme only, htmx core attrs only (CSP
/// blocks hx-on). Honesty: a `std::nullopt` data argument is a STORE DEGRADE → an
/// "unavailable" banner, NEVER an empty table (authoritative reads, ADR-0016 §7 — an
/// empty table reads as "installed nowhere"). A non-null but empty value is a genuine
/// "no rows" and renders an honest empty note. The component CSS is inlined per
/// fragment (the `.inv-*` namespace) — the same self-contained-fragment-CSS precedent
/// as device_routes' live snapshot (`.ls-*`).

#include "inventory_routes.hpp"

#include "web_utils.hpp"

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

namespace {

std::string esc(const std::string& s) { return html_escape(s); }

// Lowercase, for a data-gpname search key — gpSearch (guardian_page_ui.cpp)
// lowercases the QUERY but not the stored attribute, so the attribute must
// already be lowercase for a case-insensitive match (same contract as
// device_ui.cpp's own lc(), used for the identical reason on the Live
// process list).
std::string lc(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Percent-encode a query-string value (RFC 3986 unreserved kept literal).
std::string url_encode(const std::string& s) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() * 3);
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

// A CSS-id-safe token derived from a software title, for the "devices ›"
// expansion's element id / hx-target selector AND its internal gpSearch
// group (round-3 item 8) — every non [A-Za-z0-9_-] byte becomes '_', with a
// short content hash appended so two titles differing only in punctuation
// ("C++ Redistributable" vs "C   Redistributable") can't collide into the
// same expansion id. `hx-target="#..."` is a literal CSS id selector (passed
// to querySelector), so this must never contain a raw '%'/space/etc. the way
// url_encode's percent-escaping would.
std::string id_safe(const std::string& name) {
    std::string out = "n";
    for (unsigned char c : name)
        out.push_back((std::isalnum(c) || c == '-' || c == '_') ? static_cast<char>(c) : '_');
    std::uint64_t h = 1469598103934665603ull; // FNV-1a offset basis
    for (unsigned char c : name) {
        h ^= c;
        h *= 1099511628211ull; // FNV-1a prime
    }
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(h));
    out += "-";
    out += buf;
    return out;
}

// Relative-time string for a past epoch (the rollup "as of" line). PURE — the caller
// passes `now` so the renderer never touches the clock.
std::string rel_time(std::int64_t now_secs, std::int64_t then_secs) {
    if (then_secs <= 0)
        return "never";
    std::int64_t d = now_secs - then_secs;
    if (d < 0)
        d = 0;
    if (d < 90)
        return "just now";
    if (d < 5400)
        return std::to_string(d / 60) + "m ago";
    if (d < 172800)
        return std::to_string(d / 3600) + "h ago";
    return std::to_string(d / 86400) + "d ago";
}

// Inlined component CSS — emitted once per top-level fragment so styling is present
// on any tab entry point (duplicate <style> on a tab swap is idempotent/harmless).
std::string inv_style() {
    return R"css(<style>
  .inv-wrap{max-width:1180px}
  .inv-h1{font-size:1.35rem;margin:.2rem 0 0;color:var(--white,#fff);font-weight:700}
  .inv-sub{color:var(--muted,#8fa3bd);font-size:.8rem;margin-top:.25rem}
  .inv-subnav{display:flex;gap:.3rem;align-items:center;border-bottom:1px solid var(--border,#2d4068);padding-bottom:.6rem;margin:.8rem 0}
  .inv-subnav a{font-size:.78rem;color:var(--muted,#8fa3bd);border:1px solid transparent;border-radius:.35rem;padding:.22rem .7rem;cursor:pointer}
  .inv-subnav a.on{color:var(--white,#fff);border-color:var(--accent,#00bceb)}
  .inv-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.55rem;margin:.8rem 0}
  .inv-kpi{background:var(--surface,#1a2940);border:1px solid var(--border,#2d4068);border-radius:.5rem;padding:.55rem .8rem}
  .inv-kpi .h{font-size:.6rem;color:var(--muted,#8fa3bd);text-transform:uppercase;letter-spacing:.05em}
  .inv-kpi .big{font-size:1.3rem;font-weight:800;color:var(--white,#fff);margin-top:.1rem}
  .inv-kpi.warn .big{color:var(--yellow,#ffcc00)}.inv-kpi .s2{font-size:.58rem;color:var(--muted,#8fa3bd)}
  .inv-search{background:var(--surface,#1a2940);border:1px solid var(--border,#2d4068);border-radius:.4rem;color:var(--fg,#cfdbe8);padding:.32rem .6rem;font-size:.78rem;min-width:240px}
  .inv-banner{font-size:.72rem;color:var(--lightblue,#a5d6ff);background:rgba(165,214,255,.06);border:1px solid rgba(165,214,255,.25);border-radius:.4rem;padding:.45rem .7rem;margin:.55rem 0}
  .inv-degrade{font-size:.78rem;color:#ff8a94;background:rgba(255,87,101,.08);border:1px solid rgba(255,87,101,.4);border-radius:.5rem;padding:.7rem .9rem;margin:.7rem 0}
  .inv-degrade b{color:var(--red,#ff5765)}
  .inv-caveat{font-size:.67rem;color:var(--yellow,#ffcc00);background:rgba(255,204,0,.06);border:1px solid rgba(255,204,0,.25);border-radius:.4rem;padding:.4rem .65rem;margin:.55rem 0}
  table.inv-tbl{width:100%;border-collapse:collapse;font-size:.8rem}
  table.inv-tbl th{text-align:left;padding:.42rem .6rem;border-bottom:2px solid var(--border,#2d4068);color:var(--muted,#8fa3bd);font-size:.58rem;text-transform:uppercase;letter-spacing:.05em}
  table.inv-tbl td{padding:.44rem .6rem;border-bottom:1px solid var(--border,#2d4068);vertical-align:middle}
  table.inv-tbl tr.click{cursor:pointer}table.inv-tbl tr.click:hover td{background:var(--surface,#1a2940)}
  .inv-name{color:var(--white,#fff);font-weight:600}.inv-num{text-align:right;font-variant-numeric:tabular-nums}
  .inv-mono{font-family:'JetBrains Mono',Consolas,monospace;font-size:.72rem;color:var(--muted,#8fa3bd)}
  .inv-pub{color:var(--muted,#8fa3bd);font-size:.72rem}
  .inv-pill{font-size:.57rem;border:1px solid var(--border,#2d4068);border-radius:.3rem;padding:.04rem .4rem;color:var(--lightblue,#a5d6ff)}
  .inv-pill.old{color:#ff8a94;border-color:rgba(255,87,101,.4)}
  .inv-bar{display:flex;height:9px;border-radius:3px;overflow:hidden;background:var(--surface2,#243553);min-width:90px}.inv-bar>span{display:block;height:100%;background:var(--accent,#00bceb)}
  .inv-empty{color:var(--muted,#8fa3bd);font-size:.78rem;padding:.8rem .2rem}
  .inv-panel{background:var(--surface,#1a2940);border:1px solid var(--border,#2d4068);border-radius:.6rem;margin-top:.8rem}
  .inv-panelh{display:flex;align-items:center;gap:.6rem;padding:.6rem .9rem;border-bottom:1px solid var(--border,#2d4068)}
  .inv-panelh .t{color:var(--white,#fff);font-weight:700;font-size:.88rem}
  .inv-note{margin-top:1.2rem;font-size:.7rem;color:var(--muted,#8fa3bd);border-top:1px solid var(--border,#2d4068);padding-top:.6rem}.inv-note b{color:var(--lightblue,#a5d6ff)}
  /* Round-3 item 8: the catalogue row's "devices ›" inline expansion. An empty
     cell collapses to nothing (no dead whitespace before anything is loaded);
     the expansion's own close link empties the cell via a plain inline
     onclick (no hx-on — CSP has no unsafe-eval). */
  tr.inv-exp>td{padding:0;border-bottom:1px solid var(--border,#2d4068)}
  tr.inv-exp>td:empty{padding:0;border-bottom:0}
  .inv-exp-body{padding:.6rem .8rem;background:rgba(0,188,235,.03)}
  .inv-devbtn{cursor:pointer;color:var(--accent,#00bceb)}
  .inv-close{float:right;cursor:pointer;color:var(--muted,#8fa3bd);font-size:.7rem}
</style>)css";
}

// The Software tab bar (nav-split: Devices live on the /hardware CI list). Software
// is the only tab; "which devices run a title" is each catalogue row's inline
// "devices ›" expansion (render_inventory_software_devices_fragment below).
std::string inv_subnav(const std::string& active) {
    auto tab = [&](const char* id, const char* href, const char* label) {
        return std::string("<a class=\"") + (active == id ? "on" : "") + "\" hx-get=\"" + href +
               "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" + label + "</a>";
    };
    return std::string("<div class=\"inv-subnav\">") +
           tab("software", "/fragments/inventory/software", "Software") + "</div>";
}

std::string degrade_banner(const std::string& what) {
    return std::string("<div class=\"inv-degrade\"><b>") + esc(what) +
           " unavailable.</b> The inventory store could not be read (Postgres pool/query degraded). "
           "This is <b>not</b> \"nothing installed\" — reads here are authoritative, so this banner "
           "is shown instead of an empty table. Retry shortly.</div>";
}

std::string scope_caveat() {
    return "<div class=\"inv-caveat\">Scope (ADR-0017): management-group confinement is "
           "<b>not yet effective</b> under the global <span class=\"inv-mono\">Inventory:Read</span> "
           "gate, so these fleet-wide counts span all groups. A scope filter + access audit run on "
           "every read but do not narrow results today. (The Hardware list and CI record <b>are</b> "
           "scope-correct; the devices expansion drops out-of-group rows per device.)</div>";
}

std::string page_head() {
    return inv_style() +
           "<div class=\"inv-wrap\"><h1 class=\"inv-h1\">Software</h1>"
           "<div class=\"inv-sub\">Installed-software catalogue, synced <b>daily</b> from every "
           "endpoint (ADR-0016 daily-sync). Looking for a device? See "
           "<a href=\"/hardware\">Hardware</a>.</div>";
}

// Round-3 item 8: the SOFTWARE catalogue's swappable results region — search
// results table + per-row "installs per version"/"devices" drills. Factored
// out of render_inventory_software_fragment so a results_only=1 request (the
// search box's own hx-get) can return ONLY this region, mirroring
// hardware_ui.cpp's render_hardware_results_region fix for the identical class
// of bug (a re-render that includes the triggering <input> destroys it
// mid-keystroke). `name_filter` is echoed back into the "capped" banner only —
// the box itself lives OUTSIDE this region (see render_inventory_software_fragment)
// so it is never part of the swap.
std::string render_inventory_software_results_region(
    const std::optional<std::vector<SoftwareCatalogRow>>& catalogue, const std::string& name_filter,
    bool capped, bool building) {
    std::string h = "<div id=\"sw-results\">";
    h += "<div class=\"inv-banner\">Installed-software list rolled up across the fleet "
         "(precomputed; refreshes hourly). <b>Installs</b> = devices carrying the title. Click a "
         "title for its <b>installs per version</b>, or <b>devices</b> for which hosts run it "
         "(searchable within the expansion).</div>";

    if (!catalogue) {
        h += degrade_banner("Software catalogue");
        h += "</div>";
        return h;
    }
    if (building) {
        // Rollup never computed yet (refreshed_at==0) — distinct from a genuinely
        // empty fleet OR a search with no matches. The thread refreshes shortly
        // after startup; a search box wouldn't turn up real results either way
        // until it does, so this takes priority over the empty/no-match message.
        h += "<div class=\"inv-empty\">Catalogue is building — the rollup refreshes hourly and "
             "populates shortly after startup. Reload in a moment.</div></div>";
        return h;
    }
    if (catalogue->empty()) {
        h += name_filter.empty()
                 ? "<div class=\"inv-empty\">No installed-software inventory has been reported "
                   "yet. Agents sync once per ~24h (spread across the fleet); a freshly enrolled "
                   "agent populates within minutes.</div></div>"
                 : "<div class=\"inv-empty\">No title or publisher matches &ldquo;" +
                       esc(name_filter) + "&rdquo;.</div></div>";
        return h;
    }
    if (capped)
        h += "<div class=\"inv-banner\">Showing the most-installed matches (list capped) &mdash; "
             "narrow the search for an exact title not shown.</div>";

    h += "<table class=\"inv-tbl\"><thead><tr><th>Software</th><th>Publisher</th>"
         "<th class=\"inv-num\">Installs</th><th class=\"inv-num\">Versions</th>"
         "<th></th></tr></thead><tbody>";
    for (const auto& r : catalogue.value()) {
        const std::string enc = url_encode(r.name);
        // Round-3 item 8/9: "devices ›" is a second, independent hx-get action
        // nested inside the row's own hx-get (which drills into installs-per-
        // version) — event.stopPropagation() (plain inline onclick, no hx-on;
        // CSP has no unsafe-eval) keeps the two from double-firing on one
        // click. `id_safe(r.name)` is the SAME derivation
        // render_inventory_software_devices_fragment uses for its internal
        // gpSearch group, so a css-id-safe hx-target here lines up with that
        // fragment's own row grouping with no id passed over the wire.
        const std::string grp = "sw-exp-" + id_safe(r.name);
        h += "<tr class=\"click\" data-gpf=\"invsw\" data-gpname=\"" + esc(lc(r.name)) +
             "\" hx-get=\"/fragments/inventory/software/versions?name=" + enc +
             "\" hx-target=\"#inv-drill\" hx-swap=\"innerHTML\">"
             "<td class=\"inv-name\">" +
             esc(r.name) + "</td><td class=\"inv-pub\">" + esc(r.publisher) +
             "</td><td class=\"inv-num\">" + std::to_string(r.device_count) +
             "</td><td class=\"inv-num\">" + std::to_string(r.version_count) +
             "</td><td class=\"inv-mono\">installs per version &rsaquo; &middot; "
             "<span class=\"inv-devbtn\" onclick=\"event.stopPropagation()\" "
             "hx-get=\"/fragments/inventory/software/devices?name=" + enc +
             "\" hx-target=\"#" + grp + "\" hx-swap=\"innerHTML\">devices &rsaquo;</span></td></tr>";
        h += "<tr class=\"inv-exp\"><td colspan=\"5\"><div id=\"" + grp + "\"></div></td></tr>";
    }
    h += "</tbody></table><div id=\"inv-drill\"></div></div>";
    return h;
}

} // namespace

std::string render_inventory_software_fragment(
    const std::optional<std::vector<SoftwareCatalogRow>>& catalogue,
    const std::optional<CatalogRollupMeta>& meta, const std::string& name_filter,
    std::optional<std::int64_t> stale_count, bool capped, std::int64_t now_secs,
    bool results_only) {
    // "Building" (rollup never computed yet) vs. a genuinely empty/no-match
    // result: computed up front from `meta` alone (no I/O) so BOTH the
    // results_only early-return and the full-page path share one derivation.
    const bool building = meta && meta->refreshed_at == 0;

    // results_only=1: return ONLY the #sw-results region (the search box's own
    // hx-get) — see render_inventory_software_results_region's doc comment for
    // why this must never also re-render the box itself.
    if (results_only)
        return render_inventory_software_results_region(catalogue, name_filter, capped, building);

    std::string h = page_head();
    h += inv_subnav("software");

    // KPIs come from the precomputed rollup meta (the page never runs a COUNT): distinct
    // titles + devices reporting + the stale count (a separate cheap probe) + the "as of"
    // freshness of the rollup itself.
    const std::string titles = meta ? std::to_string(meta->total_titles) : std::string("&mdash;");
    const std::string devices = meta ? std::to_string(meta->total_devices) : std::string("&mdash;");
    const std::string stale = stale_count ? std::to_string(*stale_count) : std::string("&mdash;");
    const std::string as_of =
        (meta && meta->refreshed_at > 0) ? ("updated " + rel_time(now_secs, meta->refreshed_at))
        : building                       ? std::string("building…")
                                         : std::string("&mdash;");
    // A keep-last-good rollup that hasn't refreshed in > 2× the cadence is visibly stale —
    // flag it (warn style + "stale —" prefix) so an operator doesn't read a day-old
    // catalogue as current (gov UP-3). 7200s = 2× the hourly cadence.
    const bool rollup_stale =
        meta && meta->refreshed_at > 0 && (now_secs - meta->refreshed_at) > 7200;
    const char* cat_kpi_cls = rollup_stale ? "inv-kpi warn" : "inv-kpi";
    const std::string as_of_disp = rollup_stale ? ("stale &mdash; " + as_of) : as_of;
    h += "<div class=\"inv-kpis\">"
         "<div class=\"inv-kpi\"><div class=\"h\">Titles</div><div class=\"big\">" +
         titles +
         "</div><div class=\"s2\">distinct installed-software names, fleet-wide (the search box "
         "below filters the table only)</div></div>"
         "<div class=\"inv-kpi\"><div class=\"h\">Devices reporting</div><div class=\"big\">" +
         devices +
         "</div><div class=\"s2\">in the inventory</div></div>"
         "<div class=\"inv-kpi warn\"><div class=\"h\">Stale (&gt;2 daily cycles)</div>"
         "<div class=\"big\">" +
         stale +
         "</div><div class=\"s2\">last sync &gt; 48h ago · server time</div></div>"
         "<div class=\"" +
         std::string(cat_kpi_cls) +
         "\"><div class=\"h\">Catalogue</div>"
         "<div class=\"big\" style=\"font-size:.95rem\">" +
         as_of_disp + "</div><div class=\"s2\">rollup refreshes hourly</div></div></div>";

    h += scope_caveat();
    // Round-3 item 8: a REAL server round-trip (title OR publisher, matches the
    // store-level OR added to SoftwareCatalogQuery), not the old client-side-only
    // gpSearch — a search for a publisher name ("adobe") only works if the server
    // re-queries. `id="sw-q"` lives OUTSIDE #sw-results and hx-targets it with
    // `outerHTML`, mirroring hardware_ui.cpp's fix for the search-box-freeze bug:
    // `keyup changed delay:400ms` (not an event filter, which the no-unsafe-eval
    // CSP silently drops) plus a swap region that excludes the input itself, so a
    // re-render never destroys the box mid-keystroke.
    h += "<input id=\"sw-q\" type=\"search\" class=\"inv-search\" name=\"q\" "
         "placeholder=\"Filter by title or publisher…\" value=\"" +
         esc(name_filter) +
         "\" hx-get=\"/fragments/inventory/software?results_only=1\" hx-target=\"#sw-results\" "
         "hx-swap=\"outerHTML\" hx-trigger=\"keyup changed delay:400ms, search\" "
         "hx-sync=\"this:replace\">";
    h += render_inventory_software_results_region(catalogue, name_filter, capped, building);
    h += "</div>";
    return h;
}

std::string render_inventory_versions_fragment(
    const std::string& name, const std::optional<std::vector<SoftwareVersionCount>>& versions) {
    // No title is a precondition miss, not a store degrade — don't render the
    // "unavailable" (store-failed) banner for it (gov happy-NICE). Unreachable from the
    // UI (drill links always carry ?name=); guards a direct fetch.
    if (name.empty())
        return "<div class=\"inv-empty\">Select a title from the Software list to see its installs "
               "per version.</div>";
    std::string h = "<div class=\"inv-panel\"><div class=\"inv-panelh\"><span class=\"t\">Installs "
                    "per version &mdash; " +
                    esc(name) +
                    "</span><a style=\"margin-left:auto\" "
                    "onclick=\"this.closest('#inv-drill').innerHTML=''\">close</a></div>"
                    "<div style=\"padding:.7rem .9rem\">";
    if (!versions) {
        h += degrade_banner("Version breakdown");
        h += "</div></div>";
        return h;
    }
    if (versions->empty()) {
        h += "<div class=\"inv-empty\">No version data for this title.</div></div></div>";
        return h;
    }
    std::int64_t maxd = 0;
    for (const auto& v : versions.value())
        if (v.device_count > maxd)
            maxd = v.device_count;
    if (maxd <= 0)
        maxd = 1;
    h += "<table class=\"inv-tbl\"><thead><tr><th>Version</th><th class=\"inv-num\">Installs</th>"
         "<th>Share</th></tr></thead><tbody>";
    for (const auto& v : versions.value()) {
        const long pct = static_cast<long>(v.device_count * 100 / maxd);
        h += "<tr><td class=\"inv-mono inv-name\">" + (v.version.empty() ? "(unknown)" : esc(v.version)) +
             "</td><td class=\"inv-num\">" + std::to_string(v.device_count) +
             "</td><td><div class=\"inv-bar\"><span style=\"width:" + std::to_string(pct) +
             "%\"></span></div></td></tr>";
    }
    h += "</tbody></table></div></div>";
    return h;
}

std::string render_inventory_software_devices_fragment(
    const std::string& name, const std::optional<std::vector<SoftwareFleetRow>>& rows, bool hit_cap,
    std::size_t devices_omitted, const std::unordered_map<std::string, std::string>& hostnames) {
    if (name.empty())
        return "";
    const std::string grp = "swdev-" + id_safe(name);
    std::string h = "<div class=\"inv-exp-body\">";
    h += "<a class=\"inv-close\" onclick=\"this.closest('.inv-exp-body').innerHTML=''\">close</a>";
    h += "<div class=\"inv-sub\" style=\"margin:0 0 .4rem\">Devices running <b>" + esc(name) +
         "</b>";
    if (!rows) {
        h += "</div>";
        h += degrade_banner("Device list");
        h += "</div>";
        return h;
    }
    h += " &mdash; " + std::to_string(rows->size()) + " row(s)";
    if (hit_cap)
        h += " <span class=\"inv-pill old\">truncated at cap</span>";
    if (devices_omitted > 0)
        h += " <span class=\"inv-pill\">" + std::to_string(devices_omitted) +
             " device(s) outside your scope</span>";
    h += "</div>";
    if (rows->empty()) {
        h += "<div class=\"inv-empty\">No devices run \"" + esc(name) + "\"";
        if (hit_cap)
            h += " in this page (result was capped &mdash; narrow the query)";
        h += ".</div></div>";
        return h;
    }
    // Client-side filter — a popular title can have hundreds of installs. Group
    // id is derived from `name` (id_safe), matching the hx-target the catalogue
    // row used to open this expansion, so two expansions open at once never
    // cross-filter each other's rows.
    h += "<input class=\"inv-search\" style=\"min-width:200px;margin-bottom:.4rem\" "
         "placeholder=\"Filter these devices…\" oninput=\"gpSearch(this)\" data-gpf=\"" +
         grp + "\">";
    h += "<table class=\"inv-tbl\"><thead><tr><th>Device</th><th>Version</th><th>Publisher</th>"
         "<th>Install date</th><th>Signature</th><th>Ecosystem</th><th>Arch</th>"
         "</tr></thead><tbody>";
    for (const auto& r : rows.value()) {
        auto hn = hostnames.find(r.agent_id);
        const std::string device_disp =
            (hn != hostnames.end() && !hn->second.empty()) ? hn->second : r.agent_id;
        const std::string searchable = lc(device_disp + " " + r.entry.version + " " + r.entry.publisher);
        h += "<tr data-gpf=\"" + grp + "\" data-gpname=\"" + esc(searchable) + "\">"
             "<td class=\"inv-name\"><a href=\"/hardware/ci?id=" + url_encode(r.agent_id) +
             "\">" + esc(device_disp) + "</a></td><td class=\"inv-mono\">" +
             (r.entry.version.empty() ? "&mdash;" : esc(r.entry.version)) +
             "</td><td class=\"inv-pub\">" +
             (r.entry.publisher.empty() ? "&mdash;" : esc(r.entry.publisher)) +
             "</td><td class=\"inv-pub\">" +
             (r.entry.install_date.empty() ? "&mdash;" : esc(r.entry.install_date)) +
             "</td><td class=\"inv-mono\">" +
             (r.entry.signature_status.empty() ? "&mdash;" : esc(r.entry.signature_status)) +
             "</td><td class=\"inv-mono\">" +
             (r.entry.ecosystem.empty() ? "&mdash;" : esc(r.entry.ecosystem)) +
             "</td><td class=\"inv-mono\">" +
             (r.entry.arch.empty() ? "&mdash;" : esc(r.entry.arch)) + "</td></tr>";
    }
    h += "</tbody></table></div>";
    return h;
}

} // namespace yuzu::server
