/// @file inventory_ui.cpp
/// /inventory dashboard renderers — PURE functions over the inventory store result
/// types. Split from inventory_routes.cpp (which registers the routes) to keep each
/// TU small (same pattern as network_ui.cpp / dex_perf_ui.cpp).
///
/// Product UI: HTMX, server-rendered, dark-theme only, htmx core attrs only (CSP
/// blocks the htmx eval attributes). Honesty: a `std::nullopt` data argument is a STORE DEGRADE → an
/// "unavailable" banner, NEVER an empty table (authoritative reads, ADR-0016 §7 — an
/// empty table reads as "installed nowhere"). A non-null but empty value is a genuine
/// "no rows" and renders an honest empty note. The component CSS is inlined once, with
/// the full page (the `.inv-*` namespace) — the same self-contained-fragment-CSS precedent
/// as device_routes' live snapshot (`.ls-*`).

#include "inventory_routes.hpp"
#include "software_catalog_rules.hpp" // software_catalog::kEcosystemFamilies

#include "web_utils.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <format>
#include <string_view>
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

// Inlined component CSS — emitted once, at the head of the full /software page (sw_head);
// the Results / Rows modes and the expansions swap into that page and rely on it.
// Design tokens only (yuzu.css): bordered panels, one readout row, 36 px controls.
std::string inv_style() {
    return R"css(<style>
  .inv-wrap>*+*{margin-top:22px}
  .inv-h1{margin:0;font-size:24px;font-weight:600;letter-spacing:-.015em;line-height:1.2;color:var(--ink)}
  .inv-titlerow{display:flex;align-items:center;justify-content:space-between;gap:12px}
  .inv-wrap>.inv-sub{margin-top:4px;max-width:70ch;color:var(--mut)}
  .inv-wrap>.inv-sub a{color:var(--primary)}.inv-wrap>.inv-sub a:hover{text-decoration:underline}
  .inv-wrap :focus-visible{outline:2px solid var(--focus);outline-offset:2px}
  .inv-panel{min-width:0;background:var(--surface);border:1px solid var(--line);border-radius:var(--rad-panel)}
  .inv-pb{display:flex;flex-direction:column;gap:12px;padding:16px}
  .inv-kpis{display:flex;flex-wrap:wrap;background:var(--surface);border:1px solid var(--line);border-radius:var(--rad-panel)}
  .inv-kpi{flex:1 1 170px;min-width:0;display:flex;flex-direction:column;padding:14px 18px;border-left:1px solid var(--line)}
  .inv-kpi:first-child{border-left:0}
  .inv-kpi[hidden]{display:none}
  .inv-kpi .big{order:-2;font-size:26px;font-weight:500;letter-spacing:-.02em;line-height:1.15;color:var(--ink)}
  .inv-kpi .h{order:-1;margin-top:2px;font-size:13px;color:var(--mut)}
  .inv-kpi .s2{margin-top:4px;font-size:12.5px;color:var(--mut)}.inv-kpi .s2 b{color:var(--ink2);font-weight:600}
  .inv-kpi.warn .big{color:var(--warn)}
  .inv-kpi.later{opacity:.55}
  button.inv-kpi{border:0;border-left:1px solid var(--line);background:none;color:inherit;font:inherit;text-align:left}
  .inv-kpi.click{cursor:pointer}.inv-kpi.click:hover{background:var(--surface2)}
  .inv-kpi[aria-pressed=true]{background:color-mix(in srgb,var(--primary) 12%,transparent);box-shadow:inset 0 -2px 0 var(--primary)}
  .inv-osbar{display:flex;height:6px;margin:6px 0 2px;border-radius:2px;overflow:hidden;background:var(--line)}
  .inv-osbar>span{display:block;height:100%}.inv-osbar>span+span{border-left:1px solid var(--surface)}
  .inv-osbar .w{background:var(--c1)}.inv-osbar .m{background:var(--c2)}.inv-osbar .l{background:var(--c3)}
  .inv-fresh{font-size:12.5px;color:var(--faint)}
  .inv-wrap>.inv-fresh,.inv-wrap>button.inv-link{margin-top:8px}.inv-wrap>.inv-fresh+button.inv-link{margin-top:2px}
  .inv-caveat,.inv-degrade{padding:12px 14px;border:1px solid var(--line2);border-radius:var(--rad-panel);background:var(--surface2);color:var(--ink2);font-size:13.5px}
  .inv-degrade{border-color:color-mix(in srgb,var(--bad) 50%,var(--line2))}.inv-degrade b{color:var(--bad)}
  .inv-search,.inv-hostin{height:var(--ctl);padding:0 10px;border:1px solid var(--line2);border-radius:var(--rad-ctl);background:var(--bg);color:var(--ink);font:inherit}
  .inv-search::placeholder,.inv-hostin::placeholder{color:var(--faint)}
  .inv-search{width:100%;max-width:520px}.inv-hostin{min-width:340px}
  .inv-hostin.inv-devfilter{height:28px;min-width:180px;margin-left:auto;font-size:13px}
  .inv-filters{display:grid;gap:8px}
  .inv-frow,.inv-chips{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
  .inv-frow .lab{min-width:88px;font-size:13px;font-weight:500;color:var(--ink2)}
  .inv-chip{height:28px;padding:0 10px;border:1px solid var(--line2);border-radius:var(--rad-ctl);background:var(--bg);color:var(--mut);font:inherit;font-size:13px;font-weight:500;cursor:pointer}
  .inv-chip[data-g=src]{font-family:var(--mds-font-family-mono);font-size:12.5px;font-weight:400}
  .inv-chip:hover{background:var(--surface2);color:var(--ink)}
  .inv-chip[aria-pressed=true]{border-color:var(--primary);background:color-mix(in srgb,var(--primary) 14%,transparent);color:var(--ink)}
  .inv-active{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
  .inv-apill{display:inline-flex;align-items:center;gap:2px;height:28px;padding:0 4px 0 10px;border:1px solid var(--line2);border-radius:var(--rad-ctl);background:var(--surface2);color:var(--ink);font-size:13px}
  .inv-apill button{padding:0 6px;border:0;background:none;color:var(--mut);font-size:16px;line-height:1;cursor:pointer}.inv-apill button:hover{color:var(--ink)}
  .inv-link{padding:0;border:0;background:none;color:var(--primary);font:inherit;font-size:13px;cursor:pointer}.inv-link:hover{text-decoration:underline}
  .inv-rest{display:flex;gap:10px;align-items:center;overflow:auto;white-space:nowrap;padding:6px 10px;border:1px solid var(--line);border-radius:var(--rad-ctl);background:var(--bg);color:var(--mut);font-family:var(--mds-font-family-mono);font-size:12.5px}
  .inv-rest .v{color:var(--ink2)}
  .inv-resbar{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:8px 14px;padding:12px 16px;border-bottom:1px solid var(--line)}
  .inv-count{font-size:13px;color:var(--mut)}.inv-count b{color:var(--ink);font-weight:600}
  .inv-exports{display:flex;flex-wrap:wrap;gap:8px;align-items:center;font-size:13px;color:var(--mut)}
  .inv-exports .inv-exp-gap{margin-left:.5rem}
  .inv-degrade .inv-btn{margin-left:.6rem}
  .inv-btn{display:inline-flex;align-items:center;height:var(--ctl);padding:0 14px;border:1px solid var(--line2);border-radius:var(--rad-ctl);background:var(--raise);color:var(--ink);font:inherit;font-weight:500;white-space:nowrap;text-decoration:none;cursor:pointer}
  .inv-btn:hover{border-color:var(--mut);background:var(--surface2)}
  .inv-btn:disabled{opacity:.5;cursor:not-allowed}
  .inv-btn.pri{border-color:var(--primary);background:var(--primary);color:var(--on-primary);font-weight:600}.inv-btn.pri:hover{border-color:var(--primary-h);background:var(--primary-h)}
  .inv-btn.sm{height:28px;padding:0 10px;font-size:13px}
  .inv-tblwrap{overflow-x:auto}
  table.inv-tbl{width:100%;border-collapse:collapse}
  table.inv-tbl th{padding:8px 16px;border-bottom:1px solid var(--line);background:var(--surface2);color:var(--mut);font-size:12.5px;font-weight:500;text-align:left;white-space:nowrap}
  table.inv-tbl td{padding:var(--cell-y) 16px;border-bottom:1px solid var(--line);vertical-align:middle;color:var(--ink2)}
  table.inv-tbl tbody tr:not(.inv-exp):not(.inv-more):hover>td{background:var(--surface2)}
  table.inv-tbl tr.click{cursor:pointer}
  table.inv-tbl tbody tr.click[aria-expanded=true]>td{background:color-mix(in srgb,var(--hl) 8%,transparent)}
  table.inv-tbl tbody tr.click[aria-expanded=true]>td:first-child{box-shadow:inset 3px 0 0 var(--hl)}
  th.inv-num,td.inv-num{text-align:right;font-variant-numeric:tabular-nums}
  .inv-name{color:var(--ink);font-weight:600}.inv-pub{color:var(--ink2)}.inv-grey{color:var(--mut)}
  .inv-mono{font-family:var(--mds-font-family-mono);font-size:12.5px}
  td.inv-act{white-space:nowrap}
  .inv-pill{display:inline-block;vertical-align:middle;padding:0 5px;border:1px solid var(--line2);border-radius:3px;color:var(--mut);font-family:var(--mds-font-family-mono);font-size:11.5px}
  .inv-pill.on,.inv-pill.stale{padding:1px 8px;border-color:transparent;font:500 12.5px var(--font)}
  .inv-pill.on{background:color-mix(in srgb,var(--info) 14%,transparent);color:var(--info)}
  .inv-pill.stale{background:color-mix(in srgb,var(--warn) 15%,transparent);color:var(--warn)}
  .inv-bar{display:flex;height:6px;min-width:110px;border-radius:2px;overflow:hidden;background:var(--line)}.inv-bar>span{display:block;height:100%;background:var(--primary)}
  .inv-empty{padding:16px;color:var(--mut)}
  #sw-results>.inv-empty{background:var(--surface);border:1px solid var(--line);border-radius:var(--rad-panel)}
  /* The title row's inline expansions (versions, devices). A cell whose box is empty
     collapses to nothing; the close link empties it via a plain inline onclick (the CSP has
     no unsafe-eval). */
  tr.inv-exp>td{padding:0;border-bottom:0}
  tr.inv-exp>td:has(>div:not(:empty)){border-bottom:1px solid var(--line)}
  tr.inv-exp .inv-caveat{margin:12px 16px}
  .inv-exp-body .inv-degrade{margin-top:10px}
  .inv-exp-body,.inv-devs{padding:12px 16px 14px;background:var(--bg)}
  .inv-close{float:right;color:var(--mut);cursor:pointer}.inv-close:hover{color:var(--ink)}
  .inv-devbtn,.inv-hostlink{color:var(--primary);text-decoration:none;cursor:pointer}.inv-devbtn:hover,.inv-hostlink:hover{color:var(--primary-h)}
  .inv-hostlink:hover{text-decoration:underline}
  .inv-devhead{display:flex;flex-wrap:wrap;gap:6px 10px;align-items:center;color:var(--mut)}.inv-devhead b{color:var(--ink);font-weight:600}
  table.inv-sub{margin-top:10px;background:var(--surface)}
  table.inv-sub td{padding:8px 16px}
  tr.inv-more td{padding:12px;text-align:center;white-space:normal}
  .inv-cursor{margin-left:12px;color:var(--faint);font-family:var(--mds-font-family-mono);font-size:12px}
  .inv-unnamed{color:var(--mut);font-style:italic}
</style>)css";
}

std::string degrade_banner(const std::string& what) {
    return std::string("<div class=\"inv-degrade\"><b>") + esc(what) +
           " unavailable.</b> The inventory store could not be read (Postgres pool/query degraded). "
           "This is <b>not</b> \"nothing installed\" — reads here are authoritative, so this banner "
           "is shown instead of an empty table. Retry shortly.</div>";
}

} // namespace

// ── Software page (M.9) ──────────────────────────────────────────────────────────
// Mock-up v2.2 + the accepted v2.3 list, rendered from the PR-2 catalogue model. The page does
// no KPI arithmetic (KpiFigures carries every percentage); the one ratio computed here is the
// versions share-bar width, a display proportion of two counts on the same row. It parses
// nothing. Every interpolation goes through esc()/url_encode()/id_safe(); no JS string is ever
// built from data.

namespace {

namespace swc = software_catalogue;

constexpr std::int64_t kStaleSecs = swc::kStaleWindowSecs; // 48 h: the Last synced stale pill
// Two missed hourly refreshes: the 'stale —' prefix (the store's freshness window).
constexpr std::int64_t kRollupStaleSecs = kCatalogueFreshSeconds;
constexpr const char* kEm = "\xE2\x80\x94";                // U+2014

std::string dash() { return std::string("<span class=\"inv-grey\">") + kEm + "</span>"; }

// 1180 -> "1,180" (the mock-up's toLocaleString('en-US')).
std::string fmt_int(std::int64_t n) {
    std::string s = std::to_string(n < 0 ? -n : n);
    for (auto i = static_cast<std::ptrdiff_t>(s.size()) - 3; i > 0; i -= 3)
        s.insert(static_cast<std::size_t>(i), ",");
    return n < 0 ? "-" + s : s;
}

std::string fmt_pct1(double v) { return std::format("{:.1f}", v); }

// The OS family an ecosystem belongs to, from the ONE table the rollup SQL is generated from.
std::string_view eco_family(std::string_view eco) {
    for (const auto& e : software_catalog::kEcosystemFamilies)
        if (e.ecosystem == eco)
            return e.family;
    return {};
}
const char* family_cls(std::string_view fam) {
    return fam == "windows" ? "win" : fam == "macos" ? "mac" : fam == "linux" ? "lin" : "";
}
const char* family_name(std::string_view fam) {
    return fam == "windows" ? "Windows" : fam == "macos" ? "macOS" : fam == "linux" ? "Linux" : "";
}
std::string eco_pill(std::string_view eco) {
    return std::string("<span class=\"inv-pill ") + family_cls(eco_family(eco)) + "\">" +
           esc(std::string(eco)) + "</span>";
}

constexpr std::array<std::pair<const char*, const char*>, 4> kKinds{{
    {"app", "applications"},
    {"pkg", "macOS pkgutil and Homebrew packages"},
    {"package", "OS packages (rpm, deb, apk, pacman)"},
    {"feat", "Windows optional features"},
}};
constexpr std::array<const char*, 4> kSources{"installed_apps.list_inventory",
                                              "pkg_inventory.packages", "pkg_inventory.managers",
                                              "windows_optional_features.list"};

bool any_filter(const SoftwarePageFilters& f) {
    return !f.q.empty() || !f.kind.empty() || !f.ecosystem.empty() || !f.source.empty() ||
           !f.agent_id.empty() || f.versions_min > 0;
}

// `&k=v` builder over a vector of raw pairs (values percent-encoded here).
std::string query_of(const std::vector<std::pair<std::string, std::string>>& kv) {
    std::string out;
    for (const auto& [k, v] : kv) {
        out += out.empty() ? "" : "&";
        out += k + "=" + url_encode(v);
    }
    return out;
}

void add_state(std::vector<std::pair<std::string, std::string>>& kv, const SoftwarePageFilters& f,
               bool versions_min) {
    if (!f.kind.empty())
        kv.emplace_back("kind", f.kind);
    if (!f.ecosystem.empty())
        kv.emplace_back("ecosystem", f.ecosystem);
    if (!f.source.empty())
        kv.emplace_back("source", f.source);
    if (versions_min && f.versions_min > 0)
        kv.emplace_back("versions_min", std::to_string(f.versions_min));
}

constexpr const char* kFragment = "/fragments/inventory/software";

// One sync scope for every control that re-requests the results (search, chips, pills, host,
// Clear all): #sw-filters is stable (outside every swap), so a later request supersedes a slower
// earlier one instead of racing it.
constexpr const char* kSync = "hx-sync=\"#sw-filters:replace\"";

// An htmx control that re-requests the results region with explicit (non-input) filter state;
// the search box and the hidden host id ride along via hx-include (never also in the URL —
// the model's parser refuses a repeated key).
std::string results_get(const SoftwarePageFilters& f) {
    return "hx-get=\"" + esc(software_page_url(f, SoftwarePageMode::Results, false)) +
           "\" hx-target=\"#sw-results\" hx-swap=\"outerHTML\" hx-include=\"#sw-q,#sw-agent\" " +
           kSync;
}

std::string sw_head() {
    return inv_style() +
           "<div class=\"inv-wrap\"><div class=\"inv-titlerow\"><h1 class=\"inv-h1\">Software</h1>"
           // Opens the Sync now dialog (device / scope / whole fleet); the route enforces
           // Execution:Execute, so a caller without it is told so in the dialog.
           "<button type=\"button\" class=\"gp-btn accent\" data-act=\"sync\" onclick=\"swSync()\" "
           "title=\"Ask devices to re-send their software inventory now\">Sync now</button></div>"
           "<div class=\"inv-sub\">Installed-software inventory by application, version and "
           "device, synced <b>daily</b> from every endpoint (ADR-0016 daily-sync). Looking for a "
           "device? See <a href=\"/hardware\">Hardware</a>.</div>";
}

// Retry re-requests the whole page WITH the current filters (a bare retry would drop them).
std::string sw_degrade(const SoftwarePageFilters& f) {
    return std::string("<div class=\"inv-degrade\"><b>Inventory store unavailable.</b> The "
                       "installed-software store did not answer, so nothing is shown rather "
                       "than an empty list that could be mistaken for \"no software\". <button "
                       "class=\"inv-btn\" data-act=\"retry\" hx-get=\"") +
           esc(software_page_url(f, SoftwarePageMode::Full, true)) + "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">Retry</button></div>";
}

std::string caveat(const std::string& msg) {
    return "<div class=\"inv-caveat\">" + esc(msg) + "</div>";
}

// The Full-page caveat has no controls, so a bad URL hash cannot be repaired from the page:
// offer the reset. replaceState first makes the click a real navigation, not a fragment change.
constexpr const char* kResetLink =
    "<a class=\"inv-link\" href=\"/software\" "
    "onclick=\"history.replaceState(null,'',location.pathname)\">Clear all filters and reload</a>";

std::string tile(const char* cls, const std::string& title, const std::string& big,
                 const std::string& s2, const std::string& extra = {}) {
    return std::string("<div class=\"") + cls + "\"><div class=\"h\">" + title + "</div><div class=\"big\">" +
           big + "</div>" + extra + "<div class=\"s2\">" + s2 + "</div></div>";
}

std::string sprawl_tile(const SoftwarePageFilters& f, const swc::KpiFigures& k, bool oob) {
    SoftwarePageFilters t = f;
    t.versions_min = f.versions_min > 0 ? 0 : 3; // the toggle: 3+ versions <-> all titles
    return std::string("<button type=\"button\" class=\"inv-kpi click\" id=\"sw-sprawl\" "
                       "data-act=\"sprawl\" aria-pressed=\"") +
           (f.versions_min > 0 ? "true" : "false") + "\" " + results_get(t) +
           (oob ? " hx-swap-oob=\"true\"" : "") +
           "><div class=\"h\">Version sprawl</div><div "
           "class=\"big\">" +
           fmt_int(k.meta.sprawl_titles) + "</div><div class=\"s2\">titles on 3+ versions (" +
           fmt_pct1(k.sprawl_pct) + "%) &middot; click to show only these</div></button>";
}

std::string kpi_strip(const SoftwarePageFilters& f, const swc::KpiFigures& k, std::int64_t now) {
    const auto& m = k.meta;
    const auto opt = [](const std::optional<std::int64_t>& v) {
        return v ? "<b>" + fmt_int(*v) + "</b>" : std::string("<b>") + kEm + "</b>";
    };
    const bool stale_warn = k.coverage.stale && *k.coverage.stale > 0;
    std::string h = "<div class=\"inv-kpis\" id=\"sw-kpis\">";
    h += tile(stale_warn ? "inv-kpi warn" : "inv-kpi", "Inventory coverage", fmt_int(m.total_devices),
              "devices report software &middot; " + opt(k.coverage.connected) + " connected &middot; " +
                  opt(k.coverage.stale) + " stale (&gt;48 h)");
    h += tile("inv-kpi", "Titles", fmt_int(m.total_titles),
              "distinct software names &middot; <b>" + fmt_int(m.total_publishers) + "</b> publishers");
    const std::string os = "Windows " + std::to_string(k.windows_pct) + "% &middot; macOS " +
                           std::to_string(k.macos_pct) + "% &middot; Linux " +
                           std::to_string(k.linux_pct) + "%";
    h += tile("inv-kpi", "Installs", fmt_int(m.total_installs),
              os + " &middot; avg <b>" + fmt_int(k.avg_installs_per_device) + "</b> per device",
              "<div class=\"inv-osbar\" title=\"" + os + "\"><span class=\"w\" style=\"width:" +
                  std::to_string(k.windows_pct) + "%\"></span><span class=\"m\" style=\"width:" +
                  std::to_string(k.macos_pct) + "%\"></span><span class=\"l\" style=\"width:" +
                  std::to_string(k.linux_pct) + "%\"></span></div>");
    h += tile("inv-kpi", "Stay current",
              k.stay_current_pct ? std::to_string(*k.stay_current_pct) + "%" : std::string(kEm),
              "installs on their title's newest version seen in the fleet &middot; over <b>" +
                  fmt_int(m.current_titles) +
                  "</b> titles with a known version &middot; a proxy, not a vendor feed");
    h += sprawl_tile(f, k, false);
    h += tile(m.rpm_unsigned > 0 ? "inv-kpi warn" : "inv-kpi", "Unsigned packages",
              m.rpm_total > 0 ? fmt_int(m.rpm_unsigned) : std::string(kEm),
              m.rpm_total > 0 ? "of <b>" + fmt_int(m.rpm_total) +
                                    "</b> rpm packages &middot; only rpm reports signing"
                              : "no rpm packages in the fleet &middot; only rpm reports signing");
    // The five metrics the page cannot compute yet: faded, behind the toggle link below.
    struct Later {
        const char *title, *h, *s2;
    };
    static constexpr Later kLater[] = {
        {"needs a software lifecycle feed", "End-of-support titles",
         "needs a lifecycle feed (none today)"},
        {"needs the app_usage source joined to installs", "Unused 90 d",
         "needs usage data joined to installs"},
        {"needs an allow-list policy", "Unauthorised", "needs an allow-list policy"},
        {"needs a first_seen_at column on the rollup", "New titles 7 d",
         "needs a first-seen date per title; not collected yet"},
        {"not collected yet", "Normalised",
         "share of titles mapped to a canonical product (not available yet)"},
    };
    for (const auto& l : kLater)
        h += std::string("<div class=\"inv-kpi later\" hidden title=\"") + l.title + "\"><div class=\"h\">" +
             l.h + "</div><div class=\"big\">" + kEm + "</div><div class=\"s2\">" + l.s2 + "</div></div>";
    h += "</div>";
    // Display only: unlike the /crypto freshness gate (which also rejects a stamp from the
    // future), this stale predicate has no future-skew bound - a wrong-clock stamp just shows as
    // fresh here and gates nothing.
    const bool stale = m.refreshed_at > 0 && (now - m.refreshed_at) > kRollupStaleSecs;
    h += "<div class=\"inv-fresh\">Catalogue rollup " +
         std::string(stale ? "stale " + std::string(kEm) + " " : "") +
         (k.building ? "building&hellip;" : "updated " + rel_time(now, m.refreshed_at)) +
         " &middot; refreshes hourly &middot; counts are fleet-wide; the filters below narrow the "
         "table</div><button type=\"button\" class=\"inv-link\" data-act=\"later\" "
         "onclick=\"swLater(this)\">show metrics that need data we do not hold yet</button>";
    return h;
}

// Filter chips (kind / ecosystem / found by). Re-rendered out-of-band on every results swap so
// aria-pressed never goes stale; the hidden inputs inside carry the non-input filter state for
// the controls that are NOT re-rendered (search box, host input).
std::string chips_region(const SoftwarePageFilters& f, bool oob) {
    std::string h = std::string("<div id=\"sw-chips\" style=\"display:contents\"") +
                    (oob ? " hx-swap-oob=\"true\"" : "") + ">";
    h += "<div class=\"inv-frow\"><span class=\"lab\">Kind</span><div class=\"inv-chips\">";
    const auto kind_chip = [&](const std::string& v, const std::string& label, const std::string& title) {
        SoftwarePageFilters t = f;
        t.kind = v;
        return std::string("<button type=\"button\" class=\"inv-chip\" data-g=\"kind\" data-v=\"") +
               esc(v) + "\" aria-pressed=\"" +
               (f.kind == v ? "true" : "false") + "\" title=\"" + esc(title) + "\" " +
               results_get(t) + ">" + esc(label) + "</button>";
    };
    h += kind_chip("", "All", "every kind");
    for (const auto& [k, title] : kKinds)
        h += kind_chip(k, k, title);
    h += "</div></div>";
    const auto chip_row = [&](const char* lab, const char* g, const std::string& cur, auto&& values) {
        h += std::string("<div class=\"inv-frow\"><span class=\"lab\">") + lab + "</span>";
        for (const std::string v : values) {
            SoftwarePageFilters t = f;
            (std::string_view(g) == "eco" ? t.ecosystem : t.source) = (cur == v ? "" : v);
            h += "<button type=\"button\" class=\"inv-chip\" data-g=\"" + std::string(g) + "\" data-v=\"" +
                 esc(v) + "\" aria-pressed=\"" + (cur == v ? "true" : "false") + "\" title=\"" +
                 esc(v) + "\" " + results_get(t) + ">" + esc(v) + "</button>";
        }
        h += "</div>";
    };
    std::vector<std::string> ecos;
    for (const auto& e : software_catalog::kEcosystemFamilies)
        ecos.emplace_back(e.ecosystem);
    chip_row("Ecosystem", "eco", f.ecosystem, ecos);
    chip_row("Found by", "src", f.source, std::vector<std::string>(kSources.begin(), kSources.end()));
    h += "<span id=\"sw-state\" hidden><input type=\"hidden\" name=\"kind\" value=\"" + esc(f.kind) +
         "\"><input type=\"hidden\" name=\"ecosystem\" value=\"" + esc(f.ecosystem) +
         "\"><input type=\"hidden\" name=\"source\" value=\"" + esc(f.source) +
         "\"><input type=\"hidden\" name=\"versions_min\" value=\"" +
         std::to_string(f.versions_min > 0 ? f.versions_min : 0) + "\"></span></div>";
    return h;
}

std::string active_region(const SoftwarePageFilters& f, bool oob) {
    std::string h = std::string("<div id=\"sw-active\"") + (oob ? " hx-swap-oob=\"true\"" : "") + ">";
    std::string pills;
    const auto pill = [&](const std::string& txt, SoftwarePageFilters t, const char* clear) {
        pills += "<span class=\"inv-apill\">" + esc(txt) + "<button type=\"button\" data-rm=\"" +
                 std::string(clear) + "\" aria-label=\"Remove filter " + esc(txt) + "\" " +
                 (std::string_view(clear) == "q" || std::string_view(clear) == "host"
                      ? "onclick=\"swClear('" + std::string(clear) + "')\" "
                      : std::string()) +
                 results_get(t) + ">\xC3\x97</button></span>";
    };
    if (!f.q.empty()) pill("search: " + f.q, f, "q");
    if (!f.kind.empty()) { auto t = f; t.kind.clear(); pill("kind: " + f.kind, t, "kind"); }
    if (!f.ecosystem.empty()) { auto t = f; t.ecosystem.clear(); pill("ecosystem: " + f.ecosystem, t, "eco"); }
    if (!f.source.empty()) { auto t = f; t.source.clear(); pill("found by: " + f.source, t, "src"); }
    if (!f.agent_id.empty())
        pill("host: " + (f.host_display.empty() ? f.agent_id : f.host_display), f, "host");
    if (f.versions_min > 0) { auto t = f; t.versions_min = 0; pill("on " + std::to_string(f.versions_min) + "+ versions", t, "vmin"); }
    if (!pills.empty())
        h += "<div class=\"inv-active\">" + pills + "<button type=\"button\" class=\"inv-link\" "
             "data-act=\"clear\" onclick=\"swClear('all')\" hx-get=\"" + std::string(kFragment) +
             "?results_only=1\" hx-target=\"#sw-results\" hx-swap=\"outerHTML\" " + kSync + ">Clear all</button></div>";
    const std::string call = software_rest_call(f);
    h += "<div class=\"inv-rest\" title=\"every control maps to one REST parameter\"><span>GET</span>"
         "<span class=\"v\">" + esc(call) + "</span><button type=\"button\" class=\"inv-link\" "
         "data-act=\"copy\" data-copy=\"" + esc(call) +
         "\" onclick=\"navigator.clipboard.writeText(location.origin+this.dataset.copy)\">copy</button></div></div>";
    return h;
}

std::string controls(const SoftwarePageFilters& f, const SoftwarePageData& d) {
    const std::string base = std::string(kFragment) + "?results_only=1";
    std::string h = "<div class=\"inv-ctrls\"><input id=\"sw-q\" type=\"search\" class=\"inv-search\" "
                    "name=\"q\" placeholder=\"Search software, publisher, ecosystem or found-by"
                    "\xE2\x80\xA6\" value=\"" + esc(f.q) +
                    "\" aria-label=\"Search\" style=\"min-width:340px\" hx-get=\"" + esc(base) +
                    "\" hx-target=\"#sw-results\" hx-swap=\"outerHTML\" hx-trigger=\"keyup changed "
                    "delay:400ms, search\" " + std::string(kSync) + " "
                    "hx-include=\"#sw-state,#sw-agent\"></div>";
    h += "<div id=\"sw-filters\" class=\"inv-filters\">" + chips_region(f, false);
    h += "<div class=\"inv-frow\"><span class=\"lab\">Host</span><input id=\"sw-host\" "
         "class=\"inv-hostin\" placeholder=\"Type a host name to see its software"
         "\xE2\x80\xA6\" aria-label=\"Host\" value=\"" +
         esc(f.host_display) + "\"" + (d.confined ? "" : " list=\"hostlist\"") +
         " onchange=\"swHost(this)\" oninput=\"this.setCustomValidity('')\" hx-get=\"" + esc(base) +
         "\" hx-target=\"#sw-results\" hx-swap=\"outerHTML\" hx-trigger=\"change\" " +
         std::string(kSync) + " hx-include=\"#sw-state,#sw-q,#sw-agent\"><input id=\"sw-agent\" type=\"hidden\" "
         "name=\"agent_id\" value=\"" + esc(f.agent_id) + "\">";
    if (!d.confined) {
        h += "<datalist id=\"hostlist\">";
        for (const auto& [name, id] : d.hosts)
            h += "<option value=\"" + esc(name) + "\" data-id=\"" + esc(id) + "\">";
        h += "</datalist>";
        // The route caps the list; say so rather than leave an unlisted host a silent no-op.
        if (d.hosts.size() < d.hosts_total)
            h += "<span class=\"inv-grey\">type-ahead lists the first " + fmt_int(d.hosts.size()) +
                 " of " + fmt_int(static_cast<std::int64_t>(d.hosts_total)) +
                 " named hosts (by name); other devices open from Hardware</span>";
    }
    h += "</div></div>";
    return h;
}

// The devices-fragment query shared by the title rows, the version rows and the Load-more
// sentinel; each caller appends its own tail (total, or cursor/total/shown).
std::vector<std::pair<std::string, std::string>>
devices_kv(const SoftwarePageFilters& f, const std::string& name,
           const std::optional<std::string>& version) {
    std::vector<std::pair<std::string, std::string>> kv{{"name", name}};
    if (version)
        kv.emplace_back("version", *version); // present-empty = the exact empty-version bucket
    add_state(kv, f, false);
    if (!f.agent_id.empty())
        kv.emplace_back("agent_id", f.agent_id);
    return kv;
}

std::string version_devices_url(const SoftwarePageFilters& f, const std::string& name,
                                const std::optional<std::string>& version, std::int64_t total) {
    auto kv = devices_kv(f, name, version);
    kv.emplace_back("total", std::to_string(total));
    return "/fragments/inventory/software/devices?" + query_of(kv);
}

// Calls fn(item) for each non-empty item of a comma-separated list.
template <class Fn>
void for_each_csv(std::string_view csv, Fn&& fn) {
    for (std::size_t p = 0; p < csv.size();) {
        const auto e = csv.find(',', p);
        const auto one = csv.substr(p, e == std::string_view::npos ? e : e - p);
        if (!one.empty())
            fn(one);
        p = e == std::string_view::npos ? csv.size() : e + 1;
    }
}

std::string title_rows(const SoftwarePageFilters& f, const SoftwarePageData& d) {
    std::string h;
    std::int64_t i = d.shown_before;
    for (const auto& r : *d.rows) {
        const std::string id = id_safe(r.name), box = "exp-" + id;
        const std::string vurl =
            "/fragments/inventory/software/versions?" + query_of(devices_kv(f, r.name, std::nullopt));
        const std::string durl = version_devices_url(f, r.name, std::nullopt, r.device_count);
        std::string pills, kinds;
        for_each_csv(r.ecosystems, [&](std::string_view one) { pills += eco_pill(one) + " "; });
        for_each_csv(r.kinds, [&](std::string_view one) {
            kinds += (kinds.empty() ? "" : "/") + std::string(one);
        });
        h += "<tr class=\"click\" data-t=\"" + std::to_string(i++) + "\" aria-expanded=\"false\" "
             "data-tog=\"v\" title=\"Click for installs per version\" hx-get=\"" + esc(vurl) +
             "\" hx-target=\"#" + box + "\" hx-swap=\"innerHTML\"><td class=\"inv-name\">" +
             esc(r.name) + "</td><td class=\"inv-pub\">" + (r.publisher.empty() ? dash() : esc(r.publisher)) +
             "</td><td>" + pills + "<span class=\"inv-grey\">" + esc(kinds) + "</span></td>"
             "<td class=\"inv-num\">" + fmt_int(r.device_count) + "</td><td class=\"inv-num\">" +
             fmt_int(r.version_count) + "</td><td class=\"inv-mono\">" +
             ((r.newest_version.empty() || d.confined) ? dash() : esc(r.newest_version)) +
             "</td><td class=\"inv-act\"><span class=\"inv-devbtn\" data-vers>versions &rsaquo;</span>"
             " &middot; <span class=\"inv-devbtn\" data-devs data-tog=\"d\" "
             "onclick=\"event.stopPropagation()\" hx-get=\"" + esc(durl) + "\" hx-target=\"#" + box +
             "\" hx-swap=\"innerHTML\">devices &rsaquo;</span></td></tr>"
             "<tr class=\"inv-exp\"><td colspan=\"7\"><div id=\"" + box + "\"></div></td></tr>";
    }
    const std::int64_t shown = d.shown_before + static_cast<std::int64_t>(d.rows->size());
    const std::int64_t total = d.totals ? d.totals->titles : shown;
    if (d.next_cursor && !d.rows->empty()) {
        SoftwarePageFilters t = f;
        t.cursor = *d.next_cursor;
        const auto& last = d.rows->back();
        h += "<tr class=\"inv-more\"><td colspan=\"7\"><button type=\"button\" class=\"inv-btn pri\" "
             "data-act=\"more\" hx-get=\"" +
             esc(software_page_url(t, SoftwarePageMode::Rows, true) + "&shown=" + std::to_string(shown)) +
             "\" hx-target=\"closest tr\" hx-swap=\"outerHTML\" hx-disabled-elt=\"this\">Load " +
             std::to_string(swc::kCatalogueDefaultLimit) + " more titles</button><span class=\"inv-cursor\">" +
             fmt_int(shown) + " of " + fmt_int(total) + " &middot; cursor after (" +
             fmt_int(last.device_count) + " installs, " + esc(last.name) + ")</span></td></tr>";
    } else if (!d.rows->empty()) {
        h += "<tr class=\"inv-more\"><td colspan=\"7\"><span class=\"inv-grey\">All " + fmt_int(total) +
             " matching titles are loaded.</span></td></tr>";
    }
    return h;
}

std::string results_region(const SoftwarePageFilters& f, const SoftwarePageData& d) {
    std::string h = "<div id=\"sw-results\" data-hash=\"" + esc(software_page_hash(f)) + "\">";
    if (d.caveat) {
        h += caveat(*d.caveat) + "</div>";
        return h;
    }
    if (!d.rows || !d.totals) {
        h += sw_degrade(f) + "</div>";
        return h;
    }
    if (d.kpis && d.kpis->building) {
        h += "<div class=\"inv-empty\">Catalogue is building " + std::string(kEm) +
             " the rollup refreshes hourly and populates shortly after startup. Reload in a "
             "moment.</div></div>";
        return h;
    }
    if (d.totals->titles == 0 && !any_filter(f)) {
        h += "<div class=\"inv-empty\">No device has reported installed software yet. Agents sync "
             "daily, and a new agent reports within minutes of enrolling.</div></div>";
        return h;
    }
    const auto export_kv = [&](const char* fmt, bool with_vmin) { // install exports omit versions_min
        std::vector<std::pair<std::string, std::string>> kv{{"format", fmt}};
        if (!f.q.empty()) kv.emplace_back("q", f.q);
        add_state(kv, f, with_vmin);
        if (!f.agent_id.empty()) kv.emplace_back("agent_id", f.agent_id);
        return query_of(kv);
    };
    const std::string tip = "the matching install rows (up to " + fmt_int(swc::kExportCap) +
                            "); the file says if it was cut off; the sprawl filter is not applied to "
                            "install exports";
    const auto dl = [&](const char* fmt, const char* file, const std::string& href, const std::string& title,
                        const char* label) {
        return std::string("<a class=\"inv-btn sm\" data-act=\"export\" data-f=\"") + fmt + "\" download=\"" +
               file + "\" href=\"" + esc(href) + "\" title=\"" + esc(title) + "\">" + label + "</a>";
    };
    // The mock-up draws no count line when nothing matches (an empty live region).
    const std::string count =
        d.rows->empty()
            ? std::string()
            : "<b>" + fmt_int(d.totals->titles) + "</b> titles &middot; <b>" + fmt_int(d.totals->installs) +
                  "</b> installs" + (any_filter(f) ? " match your filters" : "") +
                  " &middot; most installed first" +
                  (d.confined ? " &middot; <span class=\"inv-grey\">Newest in fleet: your management "
                                "groups only</span>"
                              : "");
    h += "<div class=\"inv-panel\"><div class=\"inv-resbar\"><div class=\"inv-count\" aria-live=\"polite\">" + count +
         "</div><div class=\"inv-exports\"><span>Export installs</span>" +
         dl("json", "software-installs.json", "/api/v1/inventory/software?" + export_kv("json", false), tip, "JSON") +
         dl("csv", "software-installs.csv", "/api/v1/inventory/software?" + export_kv("csv", false), tip, "CSV") +
         "<span class=\"inv-exp-gap\">Export titles</span>" +
         dl("titles", "software-titles.csv", "/api/v1/inventory/software/catalogue?" + export_kv("csv", true),
            "one row per title with installs and versions", "CSV") +
         "</div></div>";
    if (d.rows->empty()) {
        h += "<div class=\"inv-empty\">No software matches these filters. <button type=\"button\" "
             "class=\"inv-link\" data-act=\"clear\" onclick=\"swClear('all')\" hx-get=\"" +
             std::string(kFragment) + "?results_only=1\" hx-target=\"#sw-results\" "
             "hx-swap=\"outerHTML\">Clear all filters</button></div></div></div>";
        return h;
    }
    h += "<div class=\"inv-tblwrap\"><table class=\"inv-tbl\"><thead><tr><th scope=\"col\">Software</th>"
         "<th scope=\"col\">Publisher</th><th scope=\"col\">Ecosystem &middot; kind</th>"
         "<th scope=\"col\" class=\"inv-num\" title=\"Installs: devices carrying this title, counted "
         "exactly under the active filters\">Installs <span class=\"inv-grey\">\xE2\x93\x98</span></th>"
         "<th scope=\"col\" class=\"inv-num\">Versions</th><th scope=\"col\">Newest in fleet</th>"
         "<th scope=\"col\"></th></tr></thead><tbody>" +
         title_rows(f, d) + "</tbody></table></div></div></div>";
    return h;
}

} // namespace

std::string software_page_url(const SoftwarePageFilters& f, SoftwarePageMode mode, bool with_inputs) {
    std::vector<std::pair<std::string, std::string>> kv;
    if (mode == SoftwarePageMode::Results)
        kv.emplace_back("results_only", "1");
    if (mode == SoftwarePageMode::Rows) {
        kv.emplace_back("rows_only", "1");
        if (!f.cursor.empty())
            kv.emplace_back("cursor", f.cursor);
    }
    if (with_inputs) {
        if (!f.q.empty())
            kv.emplace_back("q", f.q);
        if (!f.agent_id.empty())
            kv.emplace_back("agent_id", f.agent_id);
    }
    add_state(kv, f, true);
    return std::string(kFragment) + (kv.empty() ? "" : "?" + query_of(kv));
}

std::string software_rest_call(const SoftwarePageFilters& f) {
    std::vector<std::pair<std::string, std::string>> kv;
    if (!f.q.empty())
        kv.emplace_back("q", f.q);
    add_state(kv, f, false);
    if (!f.agent_id.empty())
        kv.emplace_back("agent_id", f.agent_id);
    if (f.versions_min > 0)
        kv.emplace_back("versions_min", std::to_string(f.versions_min));
    kv.emplace_back("limit", std::to_string(swc::kCatalogueDefaultLimit));
    return "/api/v1/inventory/software/catalogue?" + query_of(kv);
}

std::string software_page_hash(const SoftwarePageFilters& f) {
    std::vector<std::pair<std::string, std::string>> kv;
    if (!f.q.empty()) kv.emplace_back("q", f.q);
    if (!f.kind.empty()) kv.emplace_back("kind", f.kind);
    if (!f.ecosystem.empty()) kv.emplace_back("eco", f.ecosystem);
    if (!f.source.empty()) kv.emplace_back("src", f.source);
    if (!f.agent_id.empty()) kv.emplace_back("host", f.agent_id);
    if (f.versions_min > 0) kv.emplace_back("vmin", std::to_string(f.versions_min));
    return query_of(kv);
}

std::string render_software_page(const SoftwarePageFilters& f, const SoftwarePageData& d,
                                 SoftwarePageMode mode) {
    if (mode == SoftwarePageMode::Rows) {
        if (d.caveat)
            return "<tr><td colspan=\"7\">" + caveat(*d.caveat) + "</td></tr>";
        if (!d.rows)
            return "<tr><td colspan=\"7\">" + sw_degrade(f) + "</td></tr>";
        return title_rows(f, d);
    }
    if (mode == SoftwarePageMode::Results) {
        std::string h = results_region(f, d);
        if (!d.caveat && d.rows && d.totals) {
            h += chips_region(f, true) + active_region(f, true);
            if (d.kpis && !d.confined)
                h += sprawl_tile(f, *d.kpis, true);
        }
        return h;
    }
    // Full page.
    std::string h = sw_head();
    if (d.confined) {
        // Management-group-confined caller: no fleet figures at all (not even the strip).
        h += "<div id=\"sw-kpis\">" + caveat(d.caveat ? *d.caveat
                                                     : "Fleet-wide figures are not shown to a "
                                                       "management-group-scoped account; this page "
                                                       "shows the selected device's software only.") +
             "</div>";
        if (d.caveat) // refused: the caveat is all there is, so it carries the reset too
            return h + "<div class=\"inv-caveat\">" + kResetLink + "</div></div>";
    } else if (d.caveat) {
        return h + "<div class=\"inv-caveat\">" + esc(*d.caveat) + " " + kResetLink + "</div></div>";
    } else if (!d.rows || !d.totals || !d.kpis) {
        return h + sw_degrade(f) + "</div>";
    } else if (d.kpis->building || (d.totals->titles == 0 && !any_filter(f))) {
        return h + results_region(f, d) + "</div>";
    } else {
        h += kpi_strip(f, *d.kpis, d.now_secs);
    }
    h += "<div class=\"inv-panel inv-pb\">" + controls(f, d) + active_region(f, false) + "</div>";
    h += results_region(f, d);
    // Inventory sources (the REST /inventory/tables twin): loads once with the page; its own
    // fragment carries the fleet-wide gate and the note a confined caller sees.
    h += "<div id=\"sw-sources\" hx-get=\"/fragments/inventory/sources\" hx-trigger=\"load\" "
         "hx-swap=\"innerHTML\"></div>";
    h += "</div>";
    return h;
}

std::string render_software_versions_expansion(
    const SoftwarePageFilters& f, const std::string& name,
    const std::optional<std::vector<SoftwareVersionCount>>& v, bool confined, bool truncated) {
    std::string h = "<div class=\"inv-exp-body\"><span class=\"inv-close\" data-close "
                    "onclick=\"swClose(this)\">close \xE2\x9C\x95</span><b>" +
                    esc(name) + "</b> <span class=\"inv-grey\">&middot; installs per version</span>";
    if (!v)
        return h + degrade_banner("Version breakdown") + "</div>";
    if (v->empty())
        return h + "<div class=\"inv-empty\">No version data for this title.</div></div>";
    std::int64_t max = 1;
    for (const auto& r : *v)
        max = std::max(max, r.device_count);
    h += "<table class=\"inv-tbl inv-sub\"><thead><tr><th>Version</th><th class=\"inv-num\">Installs</th>"
         "<th>Share</th><th></th></tr></thead><tbody>";
    for (const auto& r : *v) {
        const std::string box = "vdev-" + id_safe(name + '\x1f' + r.version);
        const auto pct = (r.device_count * 100 + max / 2) / max; // round(count / max * 100)
        h += "<tr><td class=\"inv-mono\">" + (r.version.empty() ? "(unknown)" : esc(r.version)) +
             ((r.newest && !confined) ? " <span class=\"inv-pill on\">newest in fleet</span>" : "") +
             "</td><td class=\"inv-num\">" + fmt_int(r.device_count) +
             "</td><td><div class=\"inv-bar\"><span style=\"width:" + std::to_string(pct) +
             "%\"></span></div></td><td class=\"inv-act\"><span class=\"inv-devbtn\" data-vdevs "
             "data-tog=\"d\" aria-expanded=\"false\" hx-get=\"" +
             esc(version_devices_url(f, name, r.version, r.device_count)) + "\" hx-target=\"#" + box +
             "\" hx-swap=\"innerHTML\">devices &rsaquo;</span></td></tr><tr class=\"inv-exp\">"
             "<td colspan=\"4\"><div id=\"" + box + "\"></div></td></tr>";
    }
    h += "</tbody></table>";
    if (truncated)
        h += "<div class=\"inv-grey\">showing the " + fmt_int(static_cast<std::int64_t>(v->size())) +
             " most-installed versions; this title may have more</div>";
    return h + "</div>";
}

std::string render_software_devices_table(const SoftwarePageFilters& f, const SoftwareDevicesTable& t,
                                          bool rows_only) {
    const bool all_versions = !t.version;
    const std::size_t ncol = all_versions ? 6 : 5;
    const auto row_wrap = [&](const std::string& inner) {
        return "<tr><td colspan=\"" + std::to_string(ncol) + "\">" + inner + "</td></tr>";
    };
    if (!t.rows)
        return rows_only ? row_wrap(degrade_banner("Device list"))
                         : "<div class=\"inv-devs\">" + degrade_banner("Device list") + "</div>";
    const std::string grp = "swdev-" + id_safe(t.name + '\x1f' + t.version.value_or("*"));
    std::string body;
    for (const auto& r : *t.rows) {
        const auto hn = t.hostnames.find(r.agent_id);
        const bool named = hn != t.hostnames.end() && !hn->second.empty();
        const std::string host = named ? hn->second : r.agent_id;
        const auto fam = eco_family(r.entry.ecosystem);
        // Last synced: a degraded bulk read (no map) is told apart from "never synced" (a plain dash).
        std::string synced = t.last_synced ? dash()
                                           : std::string("<span class=\"inv-grey\" title=\"last sync time "
                                                         "unavailable: the inventory store read degraded\">") +
                                                 kEm + "</span>";
        if (t.last_synced) {
            const auto it = t.last_synced->find(r.agent_id);
            if (it != t.last_synced->end() && it->second > 0) {
                const std::string ago = esc(rel_time(t.now_secs, it->second));
                synced = t.now_secs - it->second > kStaleSecs
                             ? "<span class=\"inv-pill stale\" title=\"last sync more than 48h ago\">" + ago + "</span>"
                             : "<span class=\"inv-grey\">" + ago + "</span>";
            }
        }
        body += "<tr data-gpf=\"" + grp + "\" data-gpname=\"" + esc(lc(host)) + "\"><td><a class=\"inv-hostlink" +
                (named ? "" : " inv-unnamed") + "\" href=\"/hardware/ci?id=" + url_encode(r.agent_id) +
                "\" title=\"" +
                (named ? "Open this device (Hardware &rsaquo; CI view)"
                       : "No host name on record; opens the device page by agent id") +
                "\">" + esc(host) + "</a></td><td>" +
                (fam.empty() ? dash()
                             : std::string("<span class=\"inv-pill ") + family_cls(fam) + "\">" +
                                   family_name(fam) + "</span>") +
                "</td>" + (all_versions ? "<td class=\"inv-mono\">" +
                                             (r.entry.version.empty() ? dash() : esc(r.entry.version)) + "</td>"
                                       : std::string()) +
                "<td>" + (r.entry.ecosystem.empty() ? std::string() : eco_pill(r.entry.ecosystem)) +
                " <span class=\"inv-mono\">" + esc(r.entry.source) + "</span></td><td class=\"inv-mono\">" +
                (r.entry.install_date.empty() ? dash() : esc(r.entry.install_date)) + "</td><td>" + synced +
                "</td></tr>";
    }
    // A wide-scope page can be empty yet non-terminal: never claim "no match" then. The notice is
    // first-page only: Load more swaps just its own row, so a continuation notice would pile up.
    if (t.rows->empty() && !rows_only)
        body += "<tr><td colspan=\"" + std::to_string(ncol) + "\" class=\"inv-empty\">" +
                (t.next_cursor ? "No hosts on this page; more may be in later pages. Use the Load button below."
                               : "No host matches.") +
                "</td></tr>";
    if (t.next_cursor) {
        auto kv = devices_kv(f, t.name, t.version);
        kv.emplace_back("cursor", *t.next_cursor);
        if (t.total)
            kv.emplace_back("total", std::to_string(*t.total));
        kv.emplace_back("shown", std::to_string(t.shown_before));
        body += "<tr class=\"inv-more\"><td colspan=\"" + std::to_string(ncol) +
                "\"><button type=\"button\" class=\"inv-btn sm\" data-act=\"dmore\" hx-get=\"" +
                esc("/fragments/inventory/software/devices?" + query_of(kv)) +
                "\" hx-target=\"closest tr\" hx-swap=\"outerHTML\" hx-disabled-elt=\"this\">Load " +
                std::to_string(swc::kCatalogueDefaultLimit) + " more</button><span class=\"inv-cursor\">" +
                fmt_int(t.shown_before) + (t.total ? " of " + fmt_int(*t.total) : " loaded") +
                "</span></td></tr>";
    }
    if (rows_only)
        return body;
    std::string h = "<div class=\"inv-devs\"><div class=\"inv-devhead\">";
    h += t.scoped ? "Devices run <b>" : "<b>" + (t.total ? fmt_int(*t.total) : std::string(kEm)) + "</b> devices run <b>";
    h += esc(t.name) + "</b>";
    h += t.version ? " <span class=\"inv-mono\">" + (t.version->empty() ? "(unknown)" : esc(*t.version)) + "</span>"
                   : " <span class=\"inv-grey\">(all versions)</span>";
    if (t.scoped)
        h += " <span class=\"inv-grey\">your management groups only</span>";
    if (t.rows->size() > 8)
        h += "<input class=\"inv-hostin inv-devfilter\" placeholder=\"Filter hosts\xE2\x80\xA6\" "
             "aria-label=\"Filter hosts\" oninput=\"gpSearch(this)\" data-gpf=\"" + grp + "\">";
    h += "</div><table class=\"inv-tbl inv-sub\"><thead><tr><th>Host</th><th>OS</th>" +
         std::string(all_versions ? "<th>Version</th>" : "") +
         "<th>Ecosystem &middot; found by</th><th>Installed</th><th>Last synced</th></tr></thead><tbody>" +
         body + "</tbody></table></div>";
    return h;
}

std::string software_page_script() {
    return R"js(<script>
/* Software page: URL hash <-> filters, expansion toggles, host type-ahead. Inline handlers and listeners only, no eval. */
var swBoot = true, swLaterPending = false;
function swHash() {
  var r = document.getElementById('sw-results');
  if (!r || r.getAttribute('data-hash') === null) return;
  var h = r.getAttribute('data-hash'), l = document.querySelector('.inv-kpi.later');
  if (l && !l.hidden) h += (h ? '&' : '') + 'later=1';
  try { history.replaceState(null, '', h ? '#' + h : location.pathname); } catch (e) {}
}
function swLater(link) {
  var t = document.querySelectorAll('.inv-kpi.later');
  if (!t.length) return;
  var show = t[0].hidden;
  for (var i = 0; i < t.length; i++) t[i].hidden = !show;
  link.textContent = (show ? 'hide' : 'show') + ' metrics that need data we do not hold yet';
  swHash();
}
function swHost(input) {
  var a = document.getElementById('sw-agent'), l = document.getElementById('hostlist'), v = input.value.trim(), id = '';
  if (l) for (var i = 0; i < l.options.length; i++) if (l.options[i].value === v) { id = l.options[i].getAttribute('data-id'); break; }
  if (a) a.value = id;
}
function swClear(what) {
  var ids = what === 'q' ? ['sw-q'] : what === 'host' ? ['sw-host', 'sw-agent'] : ['sw-q', 'sw-host', 'sw-agent'];
  for (var i = 0; i < ids.length; i++) { var e = document.getElementById(ids[i]); if (e) e.value = ''; }
}
function swMark(box, open) {
  var o = document.querySelectorAll('[hx-target="#' + box.id + '"]');
  for (var i = 0; i < o.length; i++) {
    o[i].setAttribute('aria-expanded', open ? 'true' : 'false');
    if (o[i].hasAttribute('data-vdevs')) o[i].textContent = open ? 'hide devices' : 'devices ›';
    var tr = o[i].closest ? o[i].closest('tr.click') : null;
    if (tr) tr.setAttribute('aria-expanded', open ? 'true' : 'false');
  }
}
function swShut(box) { box.innerHTML = ''; box.removeAttribute('data-open'); swMark(box, false); }
function swClose(x) {
  var b = x.closest('.inv-exp-body'), box = b && b.parentNode;
  if (box && box.id) swShut(box);
}
/* Sync now: pick the devices (this device / a scope expression or group / the whole fleet), confirm
   the count, POST /api/v1/hardware/sync. Two shared-dialog steps; the server enforces every bound. */
function swSyncDone(r) {
  var d = r.data && r.data.data, msg, skip = [];
  if (!r.ok || !d) {
    if (typeof showToast === 'function') showToast(r.message || ('Sync request failed (' + r.status + ')'), 'error');
    return;
  }
  msg = 'Sync requested for ' + d.agents_reached + ' device' + (d.agents_reached === 1 ? '' : 's');
  if (d.skipped_offline) skip.push(d.skipped_offline + ' not connected to this server');
  if (d.skipped_version) skip.push(d.skipped_version + ' on an agent older than 0.13.1');
  if (skip.length) msg += ' (skipped: ' + skip.join(', ') + ')';
  if (typeof showToast === 'function') showToast(msg, d.agents_reached ? 'success' : 'warning');
}
function swSync() {
  var D = window.YuzuDialog;
  if (!D) return;
  var a = document.getElementById('sw-agent'), h = document.getElementById('sw-host'),
      id = a ? a.value : '', host = id && h && h.value.trim() ? h.value.trim() : id, count = null, opts = [];
  if (id) opts.push({ value: 'device', label: 'This device (' + host + ')' });
  opts.push({ value: 'scope', label: 'Devices matching a scope expression or group' });
  opts.push({ value: 'fleet', label: 'Whole fleet' });
  D.form({
    title: 'Sync now',
    body: 'Ask devices to re-send their installed-software inventory now instead of waiting for the daily sync. ' +
          'This server asks the devices connected to it. Devices not connected to this server (including one ' +
          'attached to another server) and agents older than 0.13.1 are skipped, and one request reaches at ' +
          'most 500 devices.',
    fields: [
      { name: 'kind', label: 'Which devices', type: 'select', options: opts },
      { name: 'expr', label: 'Scope expression or group', type: 'text', maxlength: 1024,
        placeholder: 'ostype == "windows"  or  group:<id>',
        hint: 'Used only for "Devices matching a scope expression or group". Up to 1,024 bytes.' }
    ],
    submitLabel: 'Review',
    validate: function (v) { return v.kind === 'scope' && !v.expr.trim() ? 'Enter a scope expression or group:<id>.' : null; },
    submit: function (v) {
      var e = v.expr.trim();
      count = null;
      if (v.kind !== 'scope' || e.indexOf('group:') === 0) return Promise.resolve(null);
      return D.request('POST', '/api/v1/scope/preview', { json: { expression: e } }).then(function (r) {
        /* The preview needs Infrastructure:Read, which Execution:Execute does not imply. A permission
           refusal (403, or 401) just means no count: the confirm step words the scope without one and
           the sync route enforces everything itself. Any other failure (an invalid expression, a
           missing route, an outage) is shown here, before the operator confirms. */
        if (!r.ok && r.status !== 403 && r.status !== 401)
          return r.message || ('Scope preview failed (' + r.status + ')');
        count = r.ok && r.data && r.data.data && typeof r.data.data.matched_count === 'number'
                  ? r.data.data.matched_count : null;
        return count === 0 ? 'That scope matches no devices you can sync.' : null;
      });
    }
  }).then(function (v) {
    if (!v) return null;
    var e = v.expr.trim(), body = { source: 'installed_software' }, what;
    if (v.kind === 'device') { body.scope = id; what = '1 device (' + host + ') will be asked to re-send its software inventory.'; }
    else if (v.kind === 'fleet') { body.scope = '__all__'; what = 'Every device connected to this server that you can reach will be asked to re-send its software inventory.'; }
    else if (e.indexOf('group:') === 0) { body.scope = e; what = 'Every device in ' + e + ' that is connected to this server will be asked to re-send its software inventory.'; }
    else {
      body.scope_expression = e;
      what = (count === null ? 'The devices matching this scope' : count + ' device' + (count === 1 ? ' matches' : 's match') + ' this scope and') +
             ' will be asked to re-send their software inventory.';
    }
    return D.confirm({ title: 'Sync now?', body: [what, 'Devices not connected to this server (including one attached to another server) and agents older than 0.13.1 are skipped.'], confirmLabel: 'Sync now' })
      .then(function (ok) { return ok ? D.request('POST', '/api/v1/hardware/sync', { json: body }) : null; });
  }).then(function (r) { if (r) swSyncDone(r); }, function () { /* dialog busy or closed */ });
}
document.body.addEventListener('htmx:configRequest', function (e) {
  var p = e.detail.path || '';
  if (!swBoot || p.indexOf('/fragments/inventory/software') !== 0 || p.indexOf('/fragments/inventory/software/') === 0) return;
  swBoot = false;
  var h = new URLSearchParams(location.hash.slice(1)),
      m = { q: 'q', kind: 'kind', eco: 'ecosystem', src: 'source', host: 'agent_id', vmin: 'versions_min' };
  for (var k in m) if (h.get(k)) e.detail.parameters[m[k]] = h.get(k);
  swLaterPending = h.get('later') === '1';
});
document.body.addEventListener('htmx:beforeRequest', function (e) {
  var el = e.detail.elt, t = e.detail.target;
  if (!el || !el.getAttribute) return;
  if (el.id === 'sw-host') {  /* only a known host (or an emptied box) re-queries */
    var a = document.getElementById('sw-agent');
    if (el.value.trim() && a && !a.value) {
      e.preventDefault();
      el.setCustomValidity('Not a listed host name'); el.reportValidity();  /* visible, not a silent no-op */
    }
    return;
  }
  var m = el.getAttribute('data-tog');
  if (m && t && t.getAttribute('data-open') === m && t.firstChild) { e.preventDefault(); swShut(t); }
});
document.body.addEventListener('htmx:afterSwap', function (e) {
  var el = e.detail.elt, t = e.detail.target, m = el && el.getAttribute && el.getAttribute('data-tog');
  if (m && t && t.id) { t.setAttribute('data-open', m); swMark(t, true); }
});
document.body.addEventListener('htmx:afterSettle', function () {
  if (swLaterPending) {
    swLaterPending = false;
    var l = document.querySelector('.inv-kpi.later'), b = document.querySelector('[data-act="later"]');
    if (l && l.hidden && b) swLater(b);
  }
  var f = document.querySelectorAll('.inv-devfilter');  /* Load-more rows join the filtered set */
  for (var i = 0; i < f.length; i++) if (f[i].value && typeof gpSearch === 'function') gpSearch(f[i]);
  swHash();
});
</script>)js";
}

} // namespace yuzu::server
