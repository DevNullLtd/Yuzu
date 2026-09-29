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
#include <charconv>
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

std::string os_label(const std::string& os) {
    if (os == "windows" || os == "win")
        return "Windows";
    if (os == "linux" || os == "lin")
        return "Linux";
    if (os == "darwin" || os == "macos" || os == "mac")
        return "macOS";
    return os.empty() ? "?" : esc(os);
}
const char* os_cls(const std::string& os) {
    if (os == "windows" || os == "win")
        return "win";
    if (os == "linux" || os == "lin")
        return "lin";
    if (os == "darwin" || os == "macos" || os == "mac")
        return "mac";
    return "";
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

// Device-CI sentinel display (PR2): an empty string OR the literal "unknown" sentinel
// (a serial-less VM / an agent that hasn't synced its CI record yet legitimately
// persists "unknown" — device_inventory_store.hpp) both render as a muted placeholder,
// never as raw text. Everything else escapes normally.
std::string ci_disp(const std::string& s) {
    if (s.empty() || s == "unknown")
        return "<span class=\"inv-grey\">&mdash;</span>";
    return esc(s);
}

// "8c/16t" from decimal-string cores/threads; "" (caller falls back to a placeholder)
// when both are unknown/empty/non-numeric. Output is digits + literal ASCII suffixes
// only, and the numeric check (mirroring ci_ram_gb's std::from_chars validation) makes
// that true BY CONSTRUCTION rather than by relying on the caller's BIGINT-column
// provenance — gov Gate 2 review: don't let "safe to emit unescaped" rest on an
// implicit cross-file trust chain the function itself doesn't enforce.
std::string ci_cores_threads(const std::string& cores, const std::string& threads) {
    auto is_numeric = [](const std::string& s) {
        if (s.empty() || s == "unknown")
            return false;
        unsigned long long v = 0;
        const auto res = std::from_chars(s.data(), s.data() + s.size(), v);
        return res.ec == std::errc{} && res.ptr == s.data() + s.size();
    };
    const bool has_cores = is_numeric(cores);
    const bool has_threads = is_numeric(threads);
    if (!has_cores && !has_threads)
        return "";
    std::string s;
    if (has_cores)
        s += cores + "c";
    if (has_threads) {
        if (!s.empty())
            s += "/";
        s += threads + "t";
    }
    return s;
}

// Humanize a decimal-string byte count into "N.N GB". Tolerant of "unknown" / empty /
// unparsable input -> "" (caller falls back to a placeholder) rather than risking a
// misleading number from a partially-garbled value.
std::string ci_ram_gb(const std::string& bytes_dec) {
    if (bytes_dec.empty() || bytes_dec == "unknown")
        return "";
    unsigned long long v = 0;
    const auto res = std::from_chars(bytes_dec.data(), bytes_dec.data() + bytes_dec.size(), v);
    if (res.ec != std::errc{} || res.ptr != bytes_dec.data() + bytes_dec.size())
        return "";
    constexpr unsigned long long kGiB = 1024ULL * 1024 * 1024;
    const unsigned long long tenths_gb = (v * 10) / kGiB;
    return std::to_string(tenths_gb / 10) + "." + std::to_string(tenths_gb % 10) + " GB";
}

// Compact "CPU / RAM" list-cell content from the roster row's raw CI fields (never
// escaped further — built only from digits + fixed ASCII literals via the helpers
// above, or the pre-escaped ci_disp() placeholder).
std::string ci_cpu_ram_cell(const InventoryDeviceRow& d) {
    const std::string ct = ci_cores_threads(d.ci_cpu_cores, d.ci_cpu_threads);
    const std::string ram = ci_ram_gb(d.ci_ram_bytes);
    if (ct.empty() && ram.empty())
        return "<span class=\"inv-grey\">&mdash;</span>";
    std::string s;
    if (!ct.empty())
        s += ct;
    if (!ram.empty()) {
        if (!s.empty())
            s += " &middot; ";
        s += ram;
    }
    return s;
}

// The per-device CI record panel (PR2). Mirrors DeviceInventoryStore::get_device_ci's
// three-state authoritative-read contract exactly: !ci.has_value() is a store/pool/
// query degrade (banner, never mistaken for "no CI"); ci holding std::nullopt is a
// genuine "not synced yet" (honest empty note); ci holding a record renders the grid.
// Omits disks_summary (macOS do_disks positional-shape bug — deferred, see #1767
// follow-ups) and owner/location (not agent-collected; future operator-set fields).
std::string ci_panel(const std::expected<std::optional<DeviceCiRecord>, CiReadError>& ci,
                     std::int64_t now_secs) {
    if (!ci.has_value()) {
        return "<div class=\"inv-degrade\"><b>CI record unavailable.</b> The device-CI store "
               "could not be read (Postgres pool/query degraded). This is <b>not</b> \"no CI "
               "record\" — reads here are authoritative, so this banner is shown instead of an "
               "absent-record note. Retry shortly.</div>";
    }
    if (!ci->has_value()) {
        return "<div class=\"inv-empty\">No CI record synced yet for this device (device-CI "
               "daily sync, ADR-0016 — a freshly enrolled agent populates within ~24h).</div>";
    }
    const DeviceCiRecord& r = **ci;
    auto field = [](const char* label, const std::string& val) {
        return std::string("<div><span class=\"ci-lab\">") + label + ": </span>" + ci_disp(val) +
               "</div>";
    };
    std::string h = "<div class=\"ci-grid\">";
    h += field("Manufacturer", r.manufacturer);
    h += field("Model", r.model);
    h += field("Serial", r.serial);
    h += field("System UUID", r.system_uuid);
    h += field("Domain", r.domain);
    h += field("OU", r.ou);
    h += field("BIOS vendor", r.bios_vendor);
    h += field("BIOS version", r.bios_version);
    h += field("BIOS date", r.bios_date);
    h += field("CPU", r.cpu_model);
    h += field("Cores / threads", ci_cores_threads(r.cpu_cores, r.cpu_threads));
    h += field("Memory", ci_ram_gb(r.ram_bytes));
    h += field("Primary MAC", r.primary_mac);
    h += field("All MACs", r.macs_summary);
    h += field("NIC count", r.nic_count);
    h += field("OS", r.os_name);
    h += field("OS version", r.os_version);
    h += field("OS build", r.os_build);
    h += field("Architecture", r.arch);
    h += field("First synced", rel_time(now_secs, r.first_seen));
    h += field("Last synced", rel_time(now_secs, r.last_seen));
    h += "</div>";
    return h;
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
  .inv-ctrls{display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;margin:.7rem 0}
  .inv-ctrls .lab{font-size:.62rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted,#8fa3bd);font-weight:700}
  .inv-search{background:var(--surface,#1a2940);border:1px solid var(--border,#2d4068);border-radius:.4rem;color:var(--fg,#cfdbe8);padding:.32rem .6rem;font-size:.78rem;min-width:240px}
  .inv-chips{display:flex;border:1px solid var(--border,#2d4068);border-radius:.4rem;overflow:hidden}
  .inv-chips .gp-chip{background:var(--surface,#1a2940);color:var(--muted,#8fa3bd);border:0;border-right:1px solid var(--border,#2d4068);padding:.26rem .65rem;font-size:.72rem;cursor:pointer}
  .inv-chips .gp-chip:last-child{border-right:0}.inv-chips .gp-chip.on{background:var(--accent,#00bceb);color:#062534;font-weight:600}
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
  .inv-pill.win{color:#a5d6ff}.inv-pill.lin{color:#ffcc88}.inv-pill.mac{color:#c7b3ff}
  .inv-pill.on{color:var(--green,#4ed27e);border-color:rgba(78,210,126,.4)}
  .inv-pill.off{color:var(--slate,#6f86a6)}.inv-pill.stale{color:var(--yellow,#ffcc00);border-color:rgba(255,204,0,.4)}
  .inv-pill.old{color:#ff8a94;border-color:rgba(255,87,101,.4)}
  .inv-bar{display:flex;height:9px;border-radius:3px;overflow:hidden;background:var(--surface2,#243553);min-width:90px}.inv-bar>span{display:block;height:100%;background:var(--accent,#00bceb)}
  .inv-empty{color:var(--muted,#8fa3bd);font-size:.78rem;padding:.8rem .2rem}
  .inv-panel{background:var(--surface,#1a2940);border:1px solid var(--border,#2d4068);border-radius:.6rem;margin-top:.8rem}
  .inv-panelh{display:flex;align-items:center;gap:.6rem;padding:.6rem .9rem;border-bottom:1px solid var(--border,#2d4068)}
  .inv-panelh .t{color:var(--white,#fff);font-weight:700;font-size:.88rem}
  .inv-note{margin-top:1.2rem;font-size:.7rem;color:var(--muted,#8fa3bd);border-top:1px solid var(--border,#2d4068);padding-top:.6rem}.inv-note b{color:var(--lightblue,#a5d6ff)}
  .inv-grey{color:var(--slate,#6f86a6)}
  .ci-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:.3rem .9rem;font-size:.74rem;margin-bottom:.7rem}
  .ci-grid .ci-lab{color:var(--muted,#8fa3bd);font-size:.62rem;text-transform:uppercase;letter-spacing:.03em}
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

// The Software tab bar (nav-split: Devices moved to the /hardware CI list).
// Round-3 item 9: the separate "Find software" tab is RETIRED from this bar —
// its function (which devices run a title) now lives inline as each catalogue
// row's "devices ›" expansion (render_inventory_software_devices_fragment
// below), so there is nothing left for Find to do that Software doesn't
// already do, searchably, in one place. The /fragments/inventory/find(+
// /results) routes stay registered (deep links, existing tests) — only this
// tab bar's link to them is removed; see docs/user-manual/inventory.md for the
// retirement follow-up (tracked: drop the routes once no deep link depends on
// them). The old /fragments/inventory/devices + /fragments/inventory/device
// routes are the same story (Devices moved to /hardware).
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
           "every read but do not narrow results today. (The Devices tab and the per-device drill "
           "<b>are</b> scope-correct; Find is also fleet-wide — see its own note.)</div>";
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

std::string render_inventory_devices_fragment(const std::vector<InventoryDeviceRow>& rows,
                                              const std::string& q, const std::string& /*os_token*/,
                                              const std::string& /*status_token*/) {
    std::string h = page_head();
    h += inv_subnav("devices");
    h += "<div class=\"inv-banner\"><b>Device CI inventory.</b> Host / OS / last-seen are sourced "
         "from the persisted, <b>offline-survivable</b> endpoint state + the live registry's "
         "online set — offline devices still appear. Serial / model / CPU &amp; RAM come from the "
         "daily device-CI sync (ADR-0016) and read <span class=\"inv-grey\">&mdash;</span> until a "
         "device's first sync lands. Click a device for its full CI record + installed "
         "software.</div>";
    h += "<div class=\"inv-ctrls\"><input class=\"inv-search\" placeholder=\"Filter by hostname or "
         "OS…\" value=\"" +
         esc(q) + "\" oninput=\"gpSearch(this)\" data-gpf=\"invdev\"></div>";

    if (rows.empty()) {
        // The device roster is sourced from the fail-soft endpoint-state store (not an
        // authoritative read), so an empty result CAN mean "store temporarily
        // unavailable" — don't assert fleet-emptiness as fact (gov UP-1 / architect-S1).
        h += "<div class=\"inv-empty\">No devices in the recent-activity window. If this is "
             "unexpected, device state may be temporarily unavailable (this roster is best-effort; "
             "the Software tab's reads are authoritative).</div></div>";
        return h;
    }

    // Bound the rendered rows so a large fleet can't emit a 100k-row HTML fragment
    // (gov UP-8 / perf-S3). The full set is filterable client-side via gpSearch; true
    // keyset pagination is the follow-up. Honest signal: show "first N of M", never a
    // silent cap.
    constexpr std::size_t kDeviceRenderCap = 1000;
    const std::size_t total = rows.size();
    const std::size_t shown = total > kDeviceRenderCap ? kDeviceRenderCap : total;
    if (total > kDeviceRenderCap)
        h += "<div class=\"inv-banner\">Showing the first " + std::to_string(shown) + " of " +
             std::to_string(total) +
             " devices — refine with the filter (full per-page paging is a follow-up).</div>";

    h += "<table class=\"inv-tbl\"><thead><tr><th>Device</th><th>OS</th><th>Status</th>"
         "<th>Last seen</th><th>Serial</th><th>Model</th><th>CPU / RAM</th></tr></thead><tbody>";
    for (std::size_t i = 0; i < shown; ++i) {
        const auto& d = rows[i];
        const std::string status = d.online ? "online" : (d.stale ? "stale" : "offline");
        const std::string status_pill = d.online
                                             ? "<span class=\"inv-pill on\">online</span>"
                                             : (d.stale ? "<span class=\"inv-pill stale\">stale</span>"
                                                        : "<span class=\"inv-pill off\">offline</span>");
        // data-gpname carries hostname + OS so the one search box filters either. host +
        // online travel in the drill URL so the per-device fragment can show them without
        // a second lookup (the drill route only receives the id).
        h += "<tr class=\"click\" data-gpf=\"invdev\" data-gpname=\"" + esc(d.hostname) + " " +
             esc(os_label(d.os)) + "\" data-gpstate=\"" + status + "\" "
             "hx-get=\"/fragments/inventory/device?id=" + url_encode(d.agent_id) +
             "&host=" + url_encode(d.hostname) + "&online=" + (d.online ? "1" : "0") +
             "\" hx-target=\"#inv-drill\" hx-swap=\"innerHTML\">"
             "<td class=\"inv-name\">" +
             esc(d.hostname.empty() ? d.agent_id : d.hostname) + "</td><td><span class=\"inv-pill " +
             os_cls(d.os) + "\">" + os_label(d.os) + "</span></td><td>" + status_pill +
             "</td><td class=\"inv-pub\">" + esc(d.last_seen.empty() ? "?" : d.last_seen) +
             "</td><td class=\"inv-mono\">" + ci_disp(d.ci_serial) + "</td>"
             "<td class=\"inv-mono\">" + ci_disp(d.ci_model) + "</td>"
             "<td class=\"inv-mono\">" + ci_cpu_ram_cell(d) + "</td></tr>";
    }
    h += "</tbody></table><div id=\"inv-drill\"></div></div>";
    return h;
}

std::string render_inventory_device_software_fragment(
    const std::string& agent_id, const std::string& hostname,
    const std::optional<std::vector<SoftwareEntry>>& software, bool online,
    const std::expected<std::optional<DeviceCiRecord>, CiReadError>& ci, std::int64_t now_secs) {
    const std::string title = hostname.empty() ? agent_id : hostname;
    std::string h = "<div class=\"inv-panel\"><div class=\"inv-panelh\"><span class=\"t\">" +
                    esc(title) + " &mdash; device record</span>" +
                    (online ? "<span class=\"inv-pill on\">online</span>"
                            : "<span class=\"inv-pill off\">offline</span>") +
                    "<a style=\"margin-left:auto\" "
                    "onclick=\"this.closest('#inv-drill').innerHTML=''\">close</a></div>"
                    "<div style=\"padding:.55rem .9rem\">";
    h += "<div class=\"inv-sub\" style=\"font-size:.62rem;text-transform:uppercase;"
         "letter-spacing:.05em;margin:.1rem 0 .4rem\">CI record</div>";
    h += ci_panel(ci, now_secs);
    h += "<div class=\"inv-sub\" style=\"font-size:.62rem;text-transform:uppercase;"
         "letter-spacing:.05em;margin:.9rem 0 .4rem\">Installed software</div>";
    if (!software) {
        h += degrade_banner("Device software");
        h += "</div></div>";
        return h;
    }
    if (!online)
        h += "<div class=\"inv-banner\">Device is offline — showing its last daily sync, not a live "
             "read.</div>";
    if (software->empty()) {
        h += "<div class=\"inv-empty\">No installed software recorded for this device.</div></div></div>";
        return h;
    }
    h += "<table class=\"inv-tbl\"><thead><tr><th>Name</th><th>Version</th><th>Publisher</th>"
         "<th>Install date</th></tr></thead><tbody>";
    for (const auto& e : software.value()) {
        h += "<tr><td class=\"inv-name\">" + esc(e.name) + "</td><td class=\"inv-mono\">" +
             (e.version.empty() ? "&mdash;" : esc(e.version)) + "</td><td class=\"inv-pub\">" +
             (e.publisher.empty() ? "&mdash;" : esc(e.publisher)) + "</td><td class=\"inv-pub\">" +
             (e.install_date.empty() ? "&mdash;" : esc(e.install_date)) + "</td></tr>";
    }
    h += "</tbody></table></div></div>";
    return h;
}

std::string render_inventory_find_fragment(const std::string& initial_name) {
    std::string h = page_head();
    h += inv_subnav("find");
    // DOC HONESTY (gov review #1759 / ADR-0017): the per-row scope filter is a FOUNDATION,
    // NOT effective list-confinement today. Under the global Inventory:Read gate a confined
    // operator is denied at the gate and a global one sees all, so the filter does not
    // actually narrow by management group yet (the admit-then-filter gate is #1716). Match
    // the REST/MCP sibling wording EXACTLY so an admin can't wrongly delegate Find to a
    // confined operator. The per-DEVICE drill IS management-group scoped.
    h += "<div class=\"inv-caveat\">Scope: Find requires the global "
         "<span class=\"inv-mono\">Inventory:Read</span> permission and returns "
         "<b>fleet-wide</b> results — management-group confinement is <b>not yet effective</b> "
         "on this list (ADR-0017); only the per-device drill is scoped. A short or empty result "
         "under a narrow scope is <b>incomplete</b>, not proof the software is absent "
         "fleet-wide.</div>";
    h += "<div class=\"inv-banner\">Find which devices run a software title. Exact name match; "
         "capped at 1000 rows (a short/zero result under a narrow scope is incomplete, not "
         "absent).</div>";
    // The input carries name="name", so htmx includes its value as ?name= on trigger.
    h += "<div class=\"inv-ctrls\"><input class=\"inv-search\" name=\"name\" "
         "placeholder=\"Exact software name, e.g. Google Chrome\" value=\"" +
         esc(initial_name) +
         "\" hx-get=\"/fragments/inventory/find/results\" "
         "hx-target=\"#inv-find-results\" hx-swap=\"innerHTML\" "
         "hx-trigger=\"keyup changed delay:400ms" +
         (initial_name.empty() ? "" : ", load") + "\"></div>"
         "<div id=\"inv-find-results\"></div></div>";
    return h;
}

std::string render_inventory_find_results_fragment(
    const std::string& name, const std::optional<std::vector<SoftwareFleetRow>>& rows, bool hit_cap,
    std::size_t devices_omitted) {
    if (name.empty())
        return "<div class=\"inv-empty\">Type an exact software name above.</div>";
    if (!rows)
        return degrade_banner("Software search");

    std::string h = "<div class=\"inv-sub\" style=\"margin:.5rem 0\">Devices running <b>" +
                    esc(name) + "</b> &mdash; " + std::to_string(rows->size()) + " row(s)";
    if (hit_cap)
        h += " <span class=\"inv-pill old\">truncated at cap</span>";
    if (devices_omitted > 0)
        h += " <span class=\"inv-pill\">" + std::to_string(devices_omitted) +
             " device(s) outside your scope</span>";
    h += "</div>";

    if (rows->empty()) {
        // Fleet-wide honest (gov consistency/security): Find is not scope-narrowed today
        // (global Inventory:Read), so don't imply "your scope".
        h += "<div class=\"inv-empty\">No devices run \"" + esc(name) + "\"";
        if (hit_cap)
            h += " in this page (result was capped — narrow the query)";
        h += ".</div>";
        return h;
    }
    h += "<table class=\"inv-tbl\"><thead><tr><th>Device</th><th>Version</th><th>Publisher</th>"
         "<th>Install date</th></tr></thead><tbody>";
    for (const auto& r : rows.value()) {
        h += "<tr><td class=\"inv-name\">" + esc(r.agent_id) + "</td><td class=\"inv-mono\">" +
             (r.entry.version.empty() ? "&mdash;" : esc(r.entry.version)) + "</td><td class=\"inv-pub\">" +
             (r.entry.publisher.empty() ? "&mdash;" : esc(r.entry.publisher)) +
             "</td><td class=\"inv-pub\">" +
             (r.entry.install_date.empty() ? "&mdash;" : esc(r.entry.install_date)) + "</td></tr>";
    }
    h += "</tbody></table>";
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
