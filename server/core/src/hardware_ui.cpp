/// @file hardware_ui.cpp
/// /hardware dashboard renderers — PURE functions over `hardware_list_model.hpp`
/// types. Split from hardware_routes.cpp (which registers the routes), matching the
/// inventory_routes.cpp / inventory_ui.cpp split. Product UI: HTMX, server-rendered,
/// dark-theme only, htmx core attrs only (CSP blocks hx-on — CLAUDE.md "Product UI
/// and plugin scope"). Honesty: a degraded read renders a banner, never an empty
/// table (ADR-0016 §7).

#include "device_data_render.hpp"
#include "hardware_routes.hpp"

#include "device_containment_render.hpp"
#include "device_estate_render.hpp"
#include "web_utils.hpp"

#include <cctype>
#include <charconv>
#include <chrono>
#include <string>
#include <vector>

namespace yuzu::server {

namespace {

std::string esc(const std::string& s) { return html_escape(s); }

// Lowercase, for a data-gpname search key — gpSearch (guardian_page_ui.cpp)
// lowercases the QUERY but not the stored attribute, so the attribute must
// already be lowercase for a case-insensitive match (same contract as
// device_ui.cpp's / inventory_ui.cpp's own lc()).
std::string lc(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

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

std::string os_label(const std::string& os) {
    if (os == "windows" || os == "win") return "Windows";
    if (os == "linux" || os == "lin") return "Linux";
    if (os == "darwin" || os == "macos" || os == "mac") return "macOS";
    return os.empty() ? "?" : esc(os);
}

std::string ci_disp(const std::string& s) {
    if (s.empty() || s == "unknown")
        return "<span class=\"inv-grey\">&mdash;</span>";
    return esc(s);
}

std::string rel_time(std::int64_t now_secs, std::int64_t then_secs) {
    if (then_secs <= 0) return "never";
    std::int64_t d = now_secs - then_secs;
    if (d < 0) d = 0;
    if (d < 90) return "just now";
    if (d < 5400) return std::to_string(d / 60) + "m ago";
    if (d < 172800) return std::to_string(d / 3600) + "h ago";
    return std::to_string(d / 86400) + "d ago";
}

bool is_numeric_dec(const std::string& s) {
    if (s.empty() || s == "unknown") return false;
    unsigned long long v = 0;
    const auto res = std::from_chars(s.data(), s.data() + s.size(), v);
    return res.ec == std::errc{} && res.ptr == s.data() + s.size();
}

std::string ci_cores_threads(const std::string& cores, const std::string& threads) {
    const bool hc = is_numeric_dec(cores);
    const bool ht = is_numeric_dec(threads);
    if (!hc && !ht) return "";
    std::string s;
    if (hc) s += cores + "c";
    if (ht) { if (!s.empty()) s += "/"; s += threads + "t"; }
    return s;
}

std::string ci_ram_gb(const std::string& bytes_dec) {
    if (bytes_dec.empty() || bytes_dec == "unknown") return "";
    unsigned long long v = 0;
    const auto res = std::from_chars(bytes_dec.data(), bytes_dec.data() + bytes_dec.size(), v);
    if (res.ec != std::errc{} || res.ptr != bytes_dec.data() + bytes_dec.size()) return "";
    constexpr unsigned long long kGiB = 1024ULL * 1024 * 1024;
    const unsigned long long tenths_gb = (v * 10) / kGiB;
    return std::to_string(tenths_gb / 10) + "." + std::to_string(tenths_gb % 10) + " GB";
}

std::string ci_cell(const std::string& v) { return ci_disp(v); }

// Full query string for /fragments/hardware/list, echoing every facet so every
// control on the page is self-describing on swap (device_ui.cpp's chip idiom).
// `with_q=false` omits `q=` — used by every control that carries `hx-include="#hw-q"`
// instead, so the LIVE (not-yet-submitted) search box value wins rather than a stale
// URL-embedded copy; httplib keeps only the FIRST of two same-named params, so a
// control must never emit both. `results_only=true` asks the route for just the
// `#hw-results` region (table/chips/breadcrumb/pager), never the KPI strip or h1 —
// that is what makes the search box's own swap not destroy the input mid-keystroke
// (round-2 item 5).
std::string list_url(const HardwareListQuery& q, bool with_q = true, bool results_only = false) {
    std::string u = "/fragments/hardware/list?os=" + url_encode(q.os) +
                    "&status=" + url_encode(q.status) + "&sort=" + url_encode(q.sort) +
                    "&dir=" + (q.desc ? "desc" : "asc") + "&offset=" + std::to_string(q.offset) +
                    "&limit=" + std::to_string(q.limit);
    if (with_q) u += "&q=" + url_encode(q.q);
    if (results_only) u += "&results_only=1";
    return u;
}

std::string hw_style() {
    return R"css(<style>
  .hw-h1{font-size:24px;font-weight:600;letter-spacing:-.015em;line-height:1.2;color:var(--ink)}
  .hw-sub{color:var(--mut);margin-top:4px;max-width:70ch}
  .hw-panel{min-width:0;background:var(--surface);border:1px solid var(--line);border-radius:var(--rad-panel)}
  .hw-hd{display:flex;flex-wrap:wrap;align-items:center;gap:8px 14px;padding:12px 16px;border-bottom:1px solid var(--line)}
  .hw-hd h2{font-size:14px;font-weight:600;color:var(--ink)}
  .hw-hd .hw-end{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-left:auto}
  .hw-toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line)}
  .hw-search{height:28px;min-width:220px;padding:0 10px;border:1px solid var(--line2);border-radius:var(--rad-ctl);background:var(--bg);color:var(--ink);font-size:13px;-webkit-appearance:none;appearance:none}
  .hw-search::placeholder{color:var(--faint)}
  .hw-hd .hw-search{min-width:300px}
  .hw-wrap :focus-visible{outline:2px solid var(--focus);outline-offset:2px}
  .hw-wrap .gp-btn:disabled{opacity:.5;cursor:not-allowed}
  .hw-breadcrumb{display:flex;flex-wrap:wrap;gap:6px;padding:10px 16px;border-bottom:1px solid var(--line)}
  .hw-crumb{display:inline-flex;align-items:center;gap:6px;padding:1px 8px;border-radius:3px;background:var(--surface2);color:var(--ink2);font-size:12.5px;font-weight:500}
  .hw-crumb a{color:var(--mut);cursor:pointer}
  .hw-crumb a:hover{color:var(--ink)}
  .hw-scroll{overflow-x:auto}
  table.hw-tbl{width:100%;border-collapse:collapse}
  table.hw-tbl th{padding:8px 12px;border-bottom:1px solid var(--line);background:var(--surface2);color:var(--mut);font-size:12.5px;font-weight:500;text-align:left;white-space:nowrap}
  table.hw-tbl th.sortable{cursor:pointer;user-select:none}
  table.hw-tbl th.sortable:hover{color:var(--ink)}
  table.hw-tbl td{padding:var(--cell-y) 12px;border-bottom:1px solid var(--line);color:var(--ink2);white-space:nowrap;vertical-align:middle}
  table.hw-tbl tbody tr:last-child td{border-bottom:0}
  table.hw-tbl tr.click{cursor:pointer}
  table.hw-tbl tbody tr:hover td{background:var(--surface2)}
  table.hw-tbl tbody tr:has(.hw-sel:checked) td{background:color-mix(in srgb,var(--hl) 8%,transparent)}
  table.hw-tbl tbody tr:has(.hw-sel:checked) td:first-child{box-shadow:inset 3px 0 0 var(--hl)}
  table.hw-tbl input[type=checkbox]{width:16px;height:16px;accent-color:var(--primary);color-scheme:dark;vertical-align:middle}
  table.hw-tbl td.hw-mono{color:var(--ink2)}
  .hw-name{color:var(--ink);font-weight:600;text-decoration:none}
  .hw-mono{font-family:var(--mds-font-family-mono);font-size:12.5px;color:var(--mut)}
  .hw-lab{color:var(--mut);font-size:13px}
  .hw-grey,.inv-grey{color:var(--faint)}
  .hw-pill{display:inline-flex;align-items:center;padding:1px 8px;border-radius:3px;background:var(--surface2);color:var(--mut);font-size:12.5px;font-weight:500;white-space:nowrap}
  .hw-pill.ok{background:color-mix(in srgb,var(--ok) 14%,transparent);color:var(--ok)}
  .hw-pill.warn{background:color-mix(in srgb,var(--warn) 15%,transparent);color:var(--warn)}
  .hw-pill.bad{background:color-mix(in srgb,var(--bad) 14%,transparent);color:var(--bad)}
  .hw-os{padding:0 5px;border:1px solid var(--line2);border-radius:3px;color:var(--mut);font-family:var(--mds-font-family-mono);font-size:11.5px}
  .hw-tag{display:inline-flex;align-items:center;margin-right:4px;padding:1px 8px;border-radius:3px;background:var(--surface2);color:var(--mut);font-size:12.5px;font-weight:500}
  a.hw-tag.link{cursor:pointer}
  a.hw-tag.link:hover{color:var(--ink)}
  .hw-macs{display:flex;flex-wrap:wrap;gap:4px}
  .hw-macs .hw-tag{margin:0}
  .hw-page{display:flex;flex-wrap:wrap;align-items:center;gap:8px;padding:10px 16px;border-top:1px solid var(--line);color:var(--mut);font-size:13px}
  .hw-page span:first-child{margin-right:auto}
  .hw-toolbar .gp-filters{margin:0}
  #hw-results>.gp-banner{margin:12px 16px 0}
  #hw-results>.gp-banner:last-child{margin-bottom:12px}
  .gp-tiles+.hw-panel{margin-top:22px}
  .hw-empty{padding:16px;border:1px solid var(--line);border-radius:var(--rad-panel);background:var(--surface);color:var(--mut);font-size:13.5px}
  .hw-panel .hw-empty{border:0;border-radius:0}
  .hw-panel .gp-placeholder{border:0;border-radius:0;background:none}
  .hw-hdr{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px;margin:0 0 12px}
  .ci-sec{margin-top:22px;border:1px solid var(--line);border-radius:var(--rad-panel);background:var(--surface)}
  .ci-sec:first-child{margin-top:0}
  .ci-sec h4{padding:12px 16px;border-bottom:1px solid var(--line);color:var(--ink);font-size:14px;font-weight:600}
  .ci-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(400px,100%),1fr));margin-bottom:-1px}
  .ci-grid>div,.ci-row{display:flex;justify-content:space-between;gap:16px;padding:9px 16px;border-bottom:1px solid var(--line);color:var(--ink);font-size:13.5px;text-align:right}
  .ci-sec>.ci-row{border-bottom:0}
  .ci-lab{flex:none;color:var(--mut);text-align:left}
  .hw-tools{padding:10px 16px;border-bottom:1px solid var(--line)}
  .hw-panel>form.hw-hdr{margin:0;padding:12px 16px;border-bottom:1px solid var(--line)}
  .hw-selbar{display:none;position:sticky;top:0;z-index:2;align-items:center;gap:8px;flex-wrap:wrap;padding:10px 16px;border-bottom:1px solid var(--line2);background:var(--raise)}
  .hw-selbar.show{display:flex}
  #hw-selcount{color:var(--ink);font-size:13px;font-weight:600}
</style>)css";
}

std::string kpi(const char* label, std::string value, const char* extra_class = "") {
    return std::string("<div class=\"gp-tile\"><div class=\"n ") + extra_class + "\">" +
           std::move(value) + "</div><div class=\"l\">" + label + "</div></div>";
}

std::string kpis_html(const HardwareKpis& k, bool ci_degraded) {
    std::string h = "<div class=\"gp-tiles\">";
    h += kpi("Total CIs", std::to_string(k.total));
    h += kpi("Online", std::to_string(k.online));
    h += kpi("Offline", std::to_string(k.offline));
    h += kpi("Stale", std::to_string(k.stale), k.stale > 0 ? "warn" : "");
    h += kpi("CI coverage", ci_degraded ? "&mdash;" : (std::to_string(k.with_ci) + " / " + std::to_string(k.total)));
    // Readouts over the scoped roster: hidden when no device has synced the figure, and
    // when the CI columns themselves are degraded (a blank would read as "none").
    if (!ci_degraded && k.median_ram_gb) {
        const double v = *k.median_ram_gb;
        const long long tenths = static_cast<long long>(v * 10.0 + 0.5);
        std::string text = std::to_string(tenths / 10);
        if (tenths % 10)
            text += "." + std::to_string(tenths % 10);
        const std::string label = "Median memory, " + std::to_string(k.ram_devices) +
                                  (k.ram_devices == 1 ? " device" : " devices") + " with hardware synced";
        h += kpi(label.c_str(), text + " GB");
    }
    h += "</div>";
    if (!ci_degraded && !k.by_manufacturer.empty()) {
        h += "<div class=\"gp-mute\" id=\"hw-by-vendor\">By manufacturer: ";
        bool first = true;
        for (const auto& [name, n] : k.by_manufacturer) {
            h += std::string(first ? "" : " &middot; ") + esc(name) + " " + std::to_string(n);
            first = false;
        }
        h += "</div>";
    }
    return h;
}

std::string sortable_th(const char* label, HwSortKey key, const HardwareListQuery& q) {
    const bool active = parse_hw_sort_key(q.sort) == key;
    const bool next_desc = active ? !q.desc : false;
    HardwareListQuery nq = q;
    nq.sort = std::string(hw_sort_token(key));
    nq.desc = next_desc;
    nq.offset = 0; // any sort change resets to page 1
    std::string indicator = active ? (q.desc ? " &#9660;" : " &#9650;") : "";
    return std::string("<th class=\"sortable\" hx-get=\"") + esc(list_url(nq, false, true)) +
           "\" hx-target=\"#hw-results\" hx-swap=\"outerHTML\" hx-include=\"#hw-q\" "
           "hx-sync=\"this:abort\">" + label + indicator + "</th>";
}

std::string chip(const char* label, const std::string& value, const HardwareListQuery& q,
                 bool is_os) {
    HardwareListQuery nq = q;
    if (is_os) nq.os = value; else nq.status = value;
    nq.offset = 0;
    const bool on = (is_os ? q.os : q.status) == value;
    return std::string("<a class=\"gp-chip") + (on ? " on" : "") + "\" hx-get=\"" +
           esc(list_url(nq, false, true)) + "\" hx-target=\"#hw-results\" hx-swap=\"outerHTML\" "
           "hx-include=\"#hw-q\">" + label + "</a>";
}

// Score badge: ≥90 green, ≥75 amber, else red (device_ui.cpp's score_badge idiom,
// kept independent since this file has no dependency on device_ui.cpp). -1 = "—".
std::string dex_badge(int score) {
    if (score < 0)
        return "<span class=\"hw-grey\">&mdash;</span>";
    const char* tone = score >= 90 ? "ok" : (score >= 75 ? "warn" : "bad");
    return "<span class=\"hw-pill " + std::string(tone) + "\">" + std::to_string(score) + "</span>";
}

// A clickable tag chip that narrows the list to this exact key[=value] — targets the
// same #hw-results region as every other control, via hx-include so the live search
// box value is preserved rather than a URL-embedded (possibly stale) copy.
std::string tag_chip(const std::string& key, const std::string& value, const HardwareListQuery& q) {
    HardwareListQuery nq = q;
    nq.tag = value.empty() ? key : (key + "=" + value);
    nq.offset = 0;
    return "<a class=\"hw-tag link\" hx-get=\"" + esc(list_url(nq, false, true)) +
           "\" hx-target=\"#hw-results\" hx-swap=\"outerHTML\" hx-include=\"#hw-q\" "
           "onclick=\"event.stopPropagation()\">" + esc(key) +
           (value.empty() ? "" : "=" + esc(value)) + "</a>";
}

std::string breadcrumb(const HardwareListQuery& q) {
    // (label, cleared-url, needs-live-q-include). The search crumb clears q itself
    // (with_q=true, blank) so it must NOT also hx-include the (still-populated) box —
    // that would resurrect the just-cleared value. Every other crumb keeps the box's
    // live value via hx-include instead of a URL-embedded (possibly stale) copy.
    std::vector<std::tuple<std::string, std::string, bool>> active;
    if (!q.q.empty()) {
        HardwareListQuery nq = q; nq.q.clear(); nq.offset = 0;
        active.emplace_back("Search: “" + esc(q.q) + "”", list_url(nq, true, true), false);
    }
    if (q.os != "all") {
        HardwareListQuery nq = q; nq.os = "all"; nq.offset = 0;
        active.emplace_back("OS: " + os_label(q.os), list_url(nq, false, true), true);
    }
    if (q.status != "all") {
        HardwareListQuery nq = q; nq.status = "all"; nq.offset = 0;
        active.emplace_back(q.status == "online" ? "Status: Online" : "Status: Offline",
                            list_url(nq, false, true), true);
    }
    if (!q.tag.empty()) {
        HardwareListQuery nq = q; nq.tag.clear(); nq.offset = 0;
        active.emplace_back("Tag: " + esc(q.tag), list_url(nq, false, true), true);
    }
    if (active.empty()) return "";
    std::string h = "<div class=\"hw-breadcrumb\">";
    for (auto& [label, url, inc] : active)
        h += "<span class=\"hw-crumb\">" + label + "<a hx-get=\"" + esc(url) +
             "\" hx-target=\"#hw-results\" hx-swap=\"outerHTML\"" +
             (inc ? " hx-include=\"#hw-q\"" : "") + ">&times;</a></span>";
    h += "</div>";
    return h;
}

std::string pagination(const HardwareListQuery& q, std::size_t total_matching) {
    const std::size_t start = total_matching == 0 ? 0 : q.offset + 1;
    const std::size_t end = std::min(q.offset + q.limit, total_matching);
    std::string h = "<div class=\"hw-page\"><span>Showing " + std::to_string(start) + "&ndash;" +
                    std::to_string(end) + " of " + std::to_string(total_matching) + "</span>";
    if (q.offset > 0) {
        HardwareListQuery pq = q;
        pq.offset = q.offset >= q.limit ? q.offset - q.limit : 0;
        h += " <button class=\"gp-btn\" hx-get=\"" + esc(list_url(pq, false, true)) +
             "\" hx-target=\"#hw-results\" hx-swap=\"outerHTML\" hx-include=\"#hw-q\" "
             "hx-sync=\"this:abort\">Prev</button>";
    }
    if (q.offset + q.limit < total_matching) {
        HardwareListQuery nq = q; nq.offset = q.offset + q.limit;
        h += " <button class=\"gp-btn\" hx-get=\"" + esc(list_url(nq, false, true)) +
             "\" hx-target=\"#hw-results\" hx-swap=\"outerHTML\" hx-include=\"#hw-q\" "
             "hx-sync=\"this:abort\">Next</button>";
    }
    h += "</div>";
    return h;
}

std::string row_html(const InventoryDeviceRow& d, const HardwareListQuery& q, bool quarantined) {
    const std::string name = d.hostname.empty() ? d.agent_id : d.hostname;
    const std::string status_pill = d.online
        ? "<span class=\"hw-pill ok\">online</span>"
        : (d.stale ? "<span class=\"hw-pill warn\">stale</span>" : "<span class=\"hw-pill\">offline</span>");
    // Quarantined pill + the row's route into the Containment lens. The link is a plain
    // anchor (the create dialog needs OS/online/whitelist context, and 50 live buttons
    // would need 50 scoped probes); yuzu-estate.js stops the row's own click handler from
    // overriding its target.
    const std::string quarantine_cell =
        std::string(quarantined ? "<span class=\"hw-pill bad\">Quarantined</span> " : "") +
        "<a class=\"hw-lab\" data-act=\"row-containment\" href=\"/hardware/ci?id=" + url_encode(d.agent_id) +
        "&amp;lens=containment\">" + (quarantined ? "Containment" : "Quarantine") + "</a>";
    const std::string cpu_ram = [&] {
        const std::string ct = ci_cores_threads(d.ci_cpu_cores, d.ci_cpu_threads);
        const std::string ram = ci_ram_gb(d.ci_ram_bytes);
        std::string parts;
        if (!d.ci_cpu_model.empty() && d.ci_cpu_model != "unknown") parts += esc(d.ci_cpu_model);
        if (!ct.empty()) parts += (parts.empty() ? "" : " &middot; ") + ct;
        return parts.empty() ? std::string("<span class=\"hw-grey\">&mdash;</span>") : parts;
    }();
    const std::string ram_cell = [&] {
        const std::string ram = ci_ram_gb(d.ci_ram_bytes);
        return ram.empty() ? std::string("<span class=\"hw-grey\">&mdash;</span>") : ram;
    }();
    // IP (round-3 item 10): the ONLY source is the live TAR fleet-snapshot cache —
    // online-only, honestly "—" once offline rather than a stale last-known value.
    const std::string ip_cell = d.ips.empty()
        ? "<span class=\"hw-grey\">&mdash;</span>"
        : "<span title=\"" + esc([&] { std::string t; for (auto& ip : d.ips) t += (t.empty() ? "" : ", ") + ip; return t; }()) +
          "\">" + esc(d.ips.front()) + (d.ips.size() > 1 ? " +" + std::to_string(d.ips.size() - 1) : "") + "</span>";
    const std::string version_cell = d.agent_version.empty()
        ? "<span class=\"hw-grey\">&mdash;</span>" : esc(d.agent_version);
    std::string tags_cell;
    if (d.tags.empty()) {
        tags_cell = "<span class=\"hw-grey\">&mdash;</span>";
    } else {
        for (const auto& [k, v] : d.tags) tags_cell += tag_chip(k, v, q);
    }
    return "<tr class=\"click\" onclick=\"location.href='/hardware/ci?id=" + url_encode(d.agent_id) +
           "'\">"
           "<td onclick=\"event.stopPropagation()\"><input type=\"checkbox\" class=\"hw-sel\" "
           "value=\"" + esc(d.agent_id) + "\" onclick=\"hwSelToggle(this)\"></td>"
           "<td><a class=\"hw-name\" href=\"/hardware/ci?id=" + url_encode(d.agent_id) + "\">" +
           esc(name) + "</a></td>"
           "<td class=\"hw-mono\">" + ip_cell + "</td>"
           "<td><span class=\"hw-os\">" + os_label(d.os) + "</span></td>"
           "<td>" + status_pill + " " + quarantine_cell + "</td>"
           "<td>" + dex_badge(d.dex_score) + "</td>"
           "<td class=\"hw-mono\">" + version_cell + "</td>"
           "<td>" + (d.last_seen.empty() ? "?" : esc(d.last_seen)) + "</td>"
           "<td>" + tags_cell + "</td>"
           "<td>" + ci_cell(d.ci_manufacturer) + "</td>"
           "<td>" + ci_cell(d.ci_model) + "</td>"
           "<td class=\"hw-mono\">" + ci_cell(d.ci_serial) + "</td>"
           "<td>" + cpu_ram + "</td>"
           "<td>" + ram_cell + "</td>"
           "<td>" + ci_cell(d.ci_os_version) + "</td>"
           "</tr>";
}

std::string device_lens_tab(const char* key, const char* label, const std::string& agent_id,
                            const std::string& active) {
    const std::string on = (active == key) ? " on" : "";
    // lens_only=1: the route answers with ONLY the lens body, so swapping it into
    // #hw-ci-lens never nests a second header + tab bar (round-2 item 6).
    return std::string("<a class=\"") + on + "\" hx-get=\"/fragments/hardware/ci?id=" +
           url_encode(agent_id) + "&lens=" + key + "&lens_only=1\" hx-target=\"#hw-ci-lens\" "
           "hx-swap=\"innerHTML\">" + label + "</a>";
}

std::string sync_button(const std::string& agent_id, const char* source, const char* lens,
                        const HwSyncAffordance& sync, const char* label) {
    using S = HwSyncAffordance::State;
    if (sync.state == S::Ready)
        return std::string("<button type=\"button\" class=\"gp-btn accent\" data-agent=\"") +
               esc(agent_id) + "\" data-lens=\"" + lens + "\" onclick=\"hwSyncNow(this,'" + source +
               "')\">" + label + "</button>";
    const char* note = sync.state == S::Offline      ? "sync needs a connected agent"
                       : sync.state == S::NoExecute  ? "needs the Execute permission"
                                                     : "predates sync-on-demand (0.13.1+)";
    std::string h = std::string("<button type=\"button\" class=\"gp-btn\" disabled>") + label +
                    "</button> <span class=\"hw-lab\">";
    if (sync.state == S::Unsupported && !sync.agent_version.empty())
        h += "agent " + esc(sync.agent_version) + " ";
    h += note;
    h += "</span>";
    return h;
}

std::string render_hardware_results_region(const HardwareListPage& page, bool ci_degraded,
                                           bool tags_degraded) {
    const HardwareListQuery& q = page.query;
    // data-url: the bulk-tag action bar re-fetches this exact view (with the live q
    // included) after applying tags to the selection, so the refreshed list reflects
    // the SAME filter/sort/page the operator was looking at.
    std::string h = "<div id=\"hw-results\" data-url=\"" + esc(list_url(q, true, true)) + "\">";
    // The degrade banners live INSIDE the swap target: every htmx control re-renders
    // only #hw-results (results_only=1), so a banner in the page shell would vanish on
    // the first refresh and leave a blank cell reading as "no CI" / "no tags".
    if (ci_degraded)
        h += "<div class=\"gp-banner hw-degrade\"><b>CI columns unavailable.</b> The device-CI store could not "
             "be read &mdash; a blank cell here is not \"no CI\", it is a degraded read.</div>";
    if (tags_degraded)
        h += "<div class=\"gp-banner hw-degrade\"><b>Tags unavailable.</b> The tag store could not be read "
             "&mdash; a blank Tags column here is not \"no tags\", it is a degraded read.</div>";
    if (page.quarantine_degraded)
        h += "<div class=\"gp-banner hw-degrade\"><b>Quarantine state unavailable.</b> The quarantine "
             "records could not be read or checked &mdash; a row without a Quarantined pill here is "
             "not \"not quarantined\".</div>";
    // Sticky bulk-tag action bar (round-3 item 7) — hidden by CSS until a row is
    // checked (hwSelRender toggles a `show` class); JS lives in guardian_page_ui.cpp.
    // Applying loops the EXISTING single-agent /api/tags/set|delete per selected
    // device (each still runs its own scoped Tag:Write gate + tag.set/.delete audit
    // row) rather than a new bulk route — see hwBulkTag.
    h += "<div id=\"hw-selbar\" class=\"hw-selbar\">"
         "<span id=\"hw-selcount\">0 selected</span>"
         "<span class=\"hw-lab\">Add tag</span>"
         "<input id=\"hw-bulk-key\" class=\"hw-search\" placeholder=\"key\" style=\"min-width:120px\" "
         "pattern=\"[A-Za-z0-9_.:-]{1,64}\" maxlength=\"64\">"
         "<input id=\"hw-bulk-value\" class=\"hw-search\" placeholder=\"value\" style=\"min-width:120px\" "
         "maxlength=\"448\">"
         "<button type=\"button\" class=\"gp-btn accent\" data-service-note=\"" + esc(std::string(kHwServiceTagSetNote)) + "\" onclick=\"hwBulkTag(this,'set')\">Apply</button>"
         "<span class=\"hw-lab\">Remove tag</span>"
         "<input id=\"hw-bulk-rkey\" class=\"hw-search\" placeholder=\"key\" style=\"min-width:120px\" "
         "pattern=\"[A-Za-z0-9_.:-]{1,64}\" maxlength=\"64\">"
         "<button type=\"button\" class=\"gp-btn\" data-service-note=\"" + esc(std::string(kHwServiceTagRemoveNote)) + "\" onclick=\"hwBulkTag(this,'delete')\">Apply</button>"
         "<button type=\"button\" class=\"gp-btn\" onclick=\"hwSelClear()\">Clear</button>"
         "</div>";
    h += "<div class=\"hw-toolbar\"><div class=\"gp-filters\">" + chip("All OS", "all", q, true) +
         chip("Windows", "windows", q, true) + chip("Linux", "linux", q, true) +
         chip("macOS", "macos", q, true) + "</div><div class=\"gp-filters\">" +
         chip("All status", "all", q, false) + chip("Online", "online", q, false) +
         chip("Offline", "offline", q, false) + "</div></div>";

    h += breadcrumb(q);

    if (page.rows.empty()) {
        h += "<div class=\"gp-placeholder\"><b>No devices match.</b> Try clearing a filter.</div>";
    } else {
        h += "<div class=\"hw-scroll\"><table class=\"hw-tbl\"><thead><tr>";
        h += "<th><input type=\"checkbox\" onclick=\"hwSelAll(this)\" title=\"Select all on this page\"></th>";
        h += sortable_th("Name", HwSortKey::Name, q);
        h += sortable_th("IP", HwSortKey::Ip, q);
        h += sortable_th("OS", HwSortKey::Os, q);
        h += sortable_th("Status", HwSortKey::Status, q);
        h += "<th title=\"Scored for the rows on this page only\">DEX</th>";
        h += sortable_th("Version", HwSortKey::Version, q);
        h += sortable_th("Last seen", HwSortKey::LastSeen, q);
        h += "<th>Tags</th>";
        h += sortable_th("Manufacturer", HwSortKey::Manufacturer, q);
        h += sortable_th("Model", HwSortKey::Model, q);
        h += sortable_th("Serial", HwSortKey::Serial, q);
        h += sortable_th("CPU", HwSortKey::Cpu, q);
        h += sortable_th("RAM", HwSortKey::Ram, q);
        h += sortable_th("OS version", HwSortKey::OsVersion, q);
        h += "</tr></thead><tbody>";
        for (const auto& row : page.rows)
            h += row_html(row, q, page.quarantined_ids.contains(row.agent_id));
        h += "</tbody></table></div>";
        h += pagination(q, page.total_matching);
    }
    h += "</div>";
    return h;
}

} // namespace

std::string render_hardware_list_fragment(const HardwareListPage& page, bool ci_degraded,
                                          bool roster_unavailable, bool results_only,
                                          bool tags_degraded) {
    constexpr const char* kRosterBanner =
        "<div class=\"gp-banner hw-degrade\"><b>Hardware roster unavailable.</b> The device roster could "
        "not be read. This is <b>not</b> \"no devices\" &mdash; reads here are authoritative, so "
        "this banner is shown instead of an empty table. Retry shortly.</div>";
    // #5531: the banner must also replace a results_only re-render, keeping the
    // #hw-results swap target (and its data-url) alive for the next retry.
    if (roster_unavailable && results_only)
        return "<div id=\"hw-results\" data-url=\"" + esc(list_url(page.query, true, true)) +
               "\">" + kRosterBanner + "</div>";
    if (results_only)
        return render_hardware_results_region(page, ci_degraded, tags_degraded);

    std::string h = hw_style();
    h += "<div class=\"hw-wrap\">";
    h += "<header><h1 class=\"hw-h1\">Hardware</h1>";
    h += "<div class=\"hw-sub\">Configuration items across the fleet &mdash; search, filter, sort.</div></header>";

    if (roster_unavailable) {
        h += kRosterBanner;
        h += "</div>";
        return h;
    }

    h += kpis_html(page.kpis, ci_degraded);

    const HardwareListQuery& q = page.query;
    h += "<section class=\"hw-panel\"><div class=\"hw-hd\"><h2>Hardware inventory</h2><div class=\"hw-end\">";
    // CSP-safe search (round-2 item 5): htmx's `[key=='Enter']` event filter compiles
    // with `Function()`, which the dashboard CSP (no unsafe-eval) refuses at runtime —
    // htmx silently drops the filter and falls back to a bare `keyup`, firing on every
    // keystroke. `changed`/`delay:` are plain token parsing (no eval), so they degrade
    // safely instead of silently. The input also lives OUTSIDE `#hw-results`, targeted
    // by every other control via `hx-include`, so its own swap can never destroy it.
    h += "<input id=\"hw-q\" type=\"search\" class=\"hw-search\" name=\"q\" value=\"" + esc(q.q) +
         "\" placeholder=\"Search hostname, serial, model, CPU&hellip;\" hx-get=\"" +
         esc(list_url([&] { HardwareListQuery nq = q; nq.offset = 0; return nq; }(), false, true)) +
         "\" hx-target=\"#hw-results\" hx-swap=\"outerHTML\" "
         "hx-trigger=\"keyup changed delay:400ms, search\" hx-sync=\"this:replace\">";
    h += "</div></div>";

    h += render_hardware_results_region(page, ci_degraded, tags_degraded);
    h += "</section>";
    h += quarantine_panel_placeholder();
    h += "</div>";
    return h;
}

std::string render_hardware_not_found(const std::string& agent_id) {
    return hw_style() + "<div class=\"hw-wrap\"><div class=\"gp-placeholder\"><b>Device not found.</b> "
           "'" + esc(agent_id) + "' has not been seen in the last " +
           std::to_string(std::chrono::duration_cast<std::chrono::days>(kHardwareRosterWindow).count()) +
           " days, or does not exist.</div></div>";
}

std::string render_hardware_roster_unreadable(const std::string& agent_id) {
    return hw_style() + "<div class=\"hw-wrap\"><div class=\"gp-placeholder\"><b>Device roster "
           "unreadable.</b> The device roster could not be read, so '" + esc(agent_id) +
           "' cannot be looked up &mdash; this is not \"not found\". Retry shortly.</div></div>";
}

std::string render_hardware_lens_body(const std::string& agent_id, const HardwareCiDetail& detail,
                                      const std::string& lens, std::int64_t now_secs,
                                      const HwCiAffordances& aff) {
    const bool online = detail.identity && detail.identity->online;
    std::string h;
    if (lens == "software") {
        h += render_hardware_software_lens(agent_id, detail.software, detail.software_truncated, online,
                                           aff.sync, detail.software_last_seen);
    } else if (lens == "tags") {
        h += render_hardware_tags_lens(agent_id, detail.tags, aff.can_write_tags, aff.can_delete_tags);
    } else if (lens == "containment") {
        // Lazy: the fragment takes its own Security:Read / Security:Execute probes, so a
        // viewer who never opens this lens never pays the denied-probe audit rows.
        h += containment_lens_placeholder(agent_id);
    } else if (lens == "actions") {
        // The route swaps this placeholder for the real actions lens on load —
        // rendering the lens itself needs actions_fn/classify_fn/schema_fn, which
        // the CiDetailFn composition (built for the other three lenses) doesn't
        // carry. Keeping the fetch in its own hx-get also means a slow/offline
        // agent doesn't block the rest of the CI record from rendering.
        h += "<div hx-get=\"/fragments/hardware/ci/actions?id=" + url_encode(agent_id) +
             "\" hx-trigger=\"load\" hx-swap=\"innerHTML\"><span class=\"gp-mute\">Loading "
             "actions&hellip;</span></div>";
    } else if (lens == "dex" || lens == "guardian" || lens == "live") {
        // Round-3 merge: these three lenses reuse the retired /device entity page's
        // OWN fragments verbatim — no re-implementation, so DEX scoring, Guardian
        // compliance and the live dispatch-and-poll snapshot cards stay a single
        // source of truth. Each fragment gates on scoped GuaranteedState:Read
        // itself; htmx does not swap a 403 body, so the permission is probed here
        // (aff.can_read_guaranteed_state) and an honest note renders instead of a
        // request that could only fail. `bare=1` tells the dex/guardian fragments
        // to omit their OWN 3-chip tab bar (device_lens_tabs) — this page already
        // has one, at the top of the CI record.
        if (!aff.can_read_guaranteed_state) {
            h += "<div class=\"gp-placeholder\">This lens needs the <b>GuaranteedState:Read</b> "
                 "permission for this device.</div>";
        } else if (lens == "dex") {
            h += "<div hx-get=\"/fragments/device/dex?id=" + url_encode(agent_id) +
                 "&bare=1\" hx-trigger=\"load\" hx-swap=\"innerHTML\"><span class=\"gp-mute\">Loading "
                 "DEX&hellip;</span></div>";
        } else if (lens == "guardian") {
            h += "<div hx-get=\"/fragments/device/guardian?id=" + url_encode(agent_id) +
                 "&bare=1\" hx-trigger=\"load\" hx-swap=\"innerHTML\"><span class=\"gp-mute\">Loading "
                 "Guardian&hellip;</span></div>";
        } else {
            h += "<div hx-get=\"/fragments/device/live?id=" + url_encode(agent_id) +
                 "\" hx-trigger=\"load\" hx-swap=\"innerHTML\"><span class=\"gp-mute\">Loading live "
                 "info&hellip;</span></div>";
        }
    } else {
        // General identity block — independent of whether a device-CI record has
        // synced (round-3 merge: this is what the retired /device page's Identity +
        // Management panels showed, folded in here so nothing duplicates a second
        // page). Prefer the live session's self-report (identity, or the sync
        // affordance's own agent_version) over the daily-synced CI blob, which can
        // be up to 24h stale.
        if (detail.identity) {
            const InventoryDeviceRow& id = *detail.identity;
            const std::string version = !id.agent_version.empty() ? id.agent_version : aff.sync.agent_version;
            const std::string arch = !id.arch.empty() ? id.arch : id.ci_arch;
            h += "<div class=\"ci-sec\"><h4>General</h4><div class=\"ci-grid\">";
            h += "<div><span class=\"ci-lab\">Agent id</span>" + esc(agent_id) + "</div>";
            h += "<div><span class=\"ci-lab\">OS</span>" + esc(os_label(id.os)) + "</div>";
            h += "<div><span class=\"ci-lab\">Agent version</span>" + ci_disp(version) + "</div>";
            h += "<div><span class=\"ci-lab\">Architecture</span>" + ci_disp(arch) + "</div>";
            h += "</div></div>";
        } else if (detail.identity_degraded) {
            h += "<div class=\"gp-banner hw-degrade\"><b>Device identity unavailable.</b> The device roster "
                 "could not be read &mdash; the agent id is shown in place of the hostname, OS is "
                 "omitted and last-seen is unknown; this is not \"not found\".</div>";
        }
        if (!detail.ci.has_value()) {
            h += "<div class=\"gp-banner hw-degrade\"><b>CI record unavailable.</b> The device-CI store could "
                 "not be read (Postgres pool/query degraded). This is <b>not</b> \"no CI record\" "
                 "&mdash; reads here are authoritative. Retry shortly.</div>";
        } else if (!detail.ci->has_value()) {
            h += "<div class=\"hw-empty\">No CI record synced yet for this device (device-CI daily "
                 "sync, ADR-0016 &mdash; a freshly enrolled agent populates within ~24h, or on "
                 "demand).<div style=\"margin-top:.5rem\">" +
                 sync_button(agent_id, "device_ci", "overview", aff.sync, "Sync now") + "</div></div>";
        } else {
            const DeviceCiRecord& r = **detail.ci;
            auto field = [](const char* label, const std::string& val) {
                return std::string("<div><span class=\"ci-lab\">") + label + "</span>" +
                       ci_disp(val) + "</div>";
            };
            h += "<div class=\"ci-sec\"><h4>Domain &amp; sync</h4><div class=\"ci-grid\">";
            h += field("Domain", r.domain);
            h += field("OU", r.ou);
            h += "<div><span class=\"ci-lab\">First synced</span>" + esc(rel_time(now_secs, r.first_seen)) + "</div>";
            h += "<div><span class=\"ci-lab\">Last synced</span>" + esc(rel_time(now_secs, r.last_seen)) + "</div>";
            h += "</div></div>";

            h += "<div class=\"ci-sec\"><h4>Hardware</h4><div class=\"ci-grid\">";
            h += field("Manufacturer", r.manufacturer);
            h += field("Model", r.model);
            h += field("Serial", r.serial);
            h += field("System UUID", r.system_uuid);
            h += field("CPU", r.cpu_model);
            h += field("Cores / threads", ci_cores_threads(r.cpu_cores, r.cpu_threads));
            h += field("Memory", ci_ram_gb(r.ram_bytes));
            h += field("Disks", r.disks_summary);
            h += "</div></div>";

            h += "<div class=\"ci-sec\"><h4>Firmware</h4><div class=\"ci-grid\">";
            h += field("BIOS vendor", r.bios_vendor);
            h += field("BIOS version", r.bios_version);
            h += field("BIOS date", r.bios_date);
            h += "</div></div>";

            h += "<div class=\"ci-sec\"><h4>Network</h4><div class=\"ci-grid\">";
            h += field("Primary MAC", r.primary_mac);
            h += field("NIC count", r.nic_count);
            h += "</div>";
            // A comma-joined string trails off the page at any width (round-3 item
            // 12) — one wrapping chip per address instead of one unbroken line.
            h += "<div class=\"ci-row\"><span class=\"ci-lab\">All MACs</span>";
            if (r.macs_summary.empty() || r.macs_summary == "unknown") {
                h += "<span class=\"inv-grey\">&mdash;</span>";
            } else {
                h += "<div class=\"hw-macs\">";
                std::string cur;
                for (std::size_t i = 0; i <= r.macs_summary.size(); ++i) {
                    if (i == r.macs_summary.size() || r.macs_summary[i] == ',') {
                        while (!cur.empty() && cur.front() == ' ') cur.erase(cur.begin());
                        while (!cur.empty() && cur.back() == ' ') cur.pop_back();
                        if (!cur.empty()) h += "<span class=\"hw-tag\">" + esc(cur) + "</span>";
                        cur.clear();
                    } else {
                        cur.push_back(r.macs_summary[i]);
                    }
                }
                h += "</div>";
            }
            h += "</div></div>";

            h += "<div class=\"ci-sec\"><h4>Operating system</h4><div class=\"ci-grid\">";
            h += field("OS", r.os_name);
            h += field("Version", r.os_version);
            h += field("Build", r.os_build);
            h += field("Architecture", r.arch);
            h += "</div></div>";
        }
        // Stored data: click-to-load, so a viewer who never opens it pays no denied probe.
        h += stored_data_placeholder(agent_id);
    }
    return h;
}

std::string render_hardware_ci_fragment(const std::string& agent_id, const HardwareCiDetail& detail,
                                        const std::string& lens, std::int64_t now_secs,
                                        const HwCiAffordances& aff) {
    const bool no_record = !detail.identity && (!detail.ci.has_value() || !detail.ci->has_value());
    if (no_record)
        return detail.identity_degraded ? render_hardware_roster_unreadable(agent_id)
                                        : render_hardware_not_found(agent_id);

    const std::string hostname = detail.identity && !detail.identity->hostname.empty()
                                      ? detail.identity->hostname
                                      : agent_id;
    const std::string os = detail.identity ? detail.identity->os : "";
    const bool online = detail.identity && detail.identity->online;
    const std::string last_seen = detail.identity ? detail.identity->last_seen : "unknown";
    const std::string active_lens = lens.empty() ? "overview" : lens;

    std::string h = hw_style();
    h += "<div class=\"hw-wrap\">";
    h += "<div class=\"hw-hdr\"><a class=\"gp-btn\" href=\"/hardware\">&larr; Hardware</a></div>";
    h += "<div class=\"hw-hdr\">";
    h += std::string("<span class=\"hw-pill") + (online ? " ok\">online" : "\">offline") + "</span>";
    h += "<h1 class=\"hw-h1\" style=\"margin:0\">" + esc(hostname) + "</h1>";
    if (!os.empty())
        h += "<span class=\"hw-os\">" + os_label(os) + "</span>";
    h += "<span class=\"hw-mono\">" + esc(agent_id) + "</span>";
    h += "<span class=\"hw-lab\">last seen " + esc(last_seen.empty() ? "?" : last_seen) + "</span>";
    h += "<span style=\"flex:1\"></span>";
    h += sync_button(agent_id, "all", active_lens.c_str(), aff.sync, "Sync now");
    h += "</div>";

    if (detail.tags && !detail.tags->empty()) {
        h += "<div class=\"hw-hdr\">";
        for (const auto& t : *detail.tags)
            h += "<span class=\"hw-tag\">" + esc(t.key) + "=" + esc(t.value) + "</span>";
        h += "</div>";
    }

    // Quarantine banner: one lazily loaded placeholder, empty unless the device has an
    // active record. It sits above the lens bar so it shows on every lens, including Live
    // and Actions, whose instructions a quarantined device withholds.
    h += containment_banner_placeholder(agent_id);
    h += render_hardware_lens_bar(agent_id, active_lens, /*oob=*/false);
    h += "<div id=\"hw-ci-lens\">";
    h += render_hardware_lens_body(agent_id, detail, active_lens, now_secs, aff);
    h += "</div></div>";
    return h;
}

std::string render_hardware_lens_bar(const std::string& agent_id, const std::string& active, bool oob) {
    std::string h = "<div class=\"gp-subnav\" id=\"hw-lens-bar\"" +
                    std::string(oob ? " hx-swap-oob=\"true\"" : "") + ">";
    h += device_lens_tab("overview", "Overview", agent_id, active);
    h += device_lens_tab("software", "Installed software", agent_id, active);
    h += device_lens_tab("tags", "Tags and properties", agent_id, active);
    h += device_lens_tab("containment", "Containment", agent_id, active);
    h += device_lens_tab("dex", "DEX", agent_id, active);
    h += device_lens_tab("guardian", "Guardian", agent_id, active);
    h += device_lens_tab("live", "Live", agent_id, active);
    h += device_lens_tab("actions", "Actions", agent_id, active);
    h += "</div>";
    return h;
}

std::string render_hardware_sync_pending(const std::string& agent_id, const std::string& lens,
                                         std::int64_t await_since, int next_attempt,
                                         const std::string& command_id) {
    // Round-3 item 4: a 1s,1s,2s… poll ladder instead of a flat 2s — most
    // syncs on Linux/Windows land within a second or two (server ingest is
    // ~13ms, so the wait is almost entirely the agent's own collect() +
    // network round trip), so the first couple of polls fire fast; settling
    // to 2s afterwards keeps a genuinely slow sync (macOS's first-ever
    // installed_software scan) from polling too aggressively.
    const char* delay = next_attempt <= 2 ? "1s" : "2s";
    return "<div hx-get=\"/fragments/hardware/ci?id=" + url_encode(agent_id) + "&lens=" +
           url_encode(lens) + "&lens_only=1&await_since=" + std::to_string(await_since) +
           "&n=" + std::to_string(next_attempt) + "&command_id=" + url_encode(command_id) +
           "\" hx-trigger=\"load delay:" + delay +
           "\" hx-swap=\"outerHTML\"><span class=\"gp-mute\">Sync "
           "requested &mdash; waiting for the device to report (" + std::to_string(next_attempt - 1) +
           "/30)&hellip; usually a couple of seconds on Linux/Windows, up to ~15s on macOS the "
           "first time.</span></div>";
}

std::string render_hardware_sync_terminal(const std::string& agent_id, const std::string& lens,
                                          const std::string& refusal_output, bool timed_out) {
    std::string h = "<div class=\"gp-banner hw-degrade\">";
    if (!refusal_output.empty())
        h += "<b>The device refused the sync request:</b> " + esc(refusal_output);
    else if (timed_out)
        h += "<b>Still waiting.</b> The device may be slow, or the report failed &mdash; check the "
             "agent log for <span class=\"hw-mono\">sync:</span> lines.";
    h += " <a class=\"gp-btn\" hx-get=\"/fragments/hardware/ci?id=" + url_encode(agent_id) + "&lens=" +
         url_encode(lens) + "&lens_only=1\" hx-target=\"#hw-ci-lens\" hx-swap=\"innerHTML\">Reload</a>";
    h += "</div>";
    return h;
}

std::string render_hardware_software_lens(const std::string& agent_id,
                                          const std::optional<std::vector<SoftwareEntry>>& software,
                                          bool truncated, bool online, const HwSyncAffordance& sync,
                                          std::optional<std::int64_t> software_last_seen) {
    if (!software)
        return "<div class=\"gp-banner hw-degrade\"><b>Installed software unavailable.</b> The software "
               "inventory store could not be read. Retry shortly.</div>";
    if (software->empty()) {
        if (!online)
            return "<div class=\"hw-empty\">No installed-software inventory on record (device is "
                   "offline and has not synced).</div>";
        return "<div class=\"hw-empty\">No installed-software inventory synced yet for this device."
               "<div style=\"margin-top:.5rem\">" +
               sync_button(agent_id, "installed_software", "software", sync, "Sync now") +
               "</div></div>";
    }
    // Round-3 item 3: a searchable text filter over this device's own installed-
    // software table (gpSearch, group "hwsw" — self-contained to this lens, no
    // server round-trip needed since a per-device list is small).
    // "N applications, last synced <when>": a never-synced device (0) and a degraded
    // read (nullopt) are told apart, neither is shown as a bare count.
    std::string summary = std::to_string(software->size()) +
                          (software->size() == 1 ? " application" : " applications");
    if (!software_last_seen)
        summary += ", last synced time unavailable";
    else if (*software_last_seen <= 0)
        summary += ", never synced";
    else
        summary += ", last synced " + esc(format_iso_utc(*software_last_seen));
    std::string h = "<div class=\"hw-panel\"><div class=\"hw-page\" id=\"hw-sw-summary\">" + summary +
                    (truncated ? " (list truncated)" : "") + "</div>"
                    "<div class=\"hw-tools\"><input class=\"hw-search\" "
                    "placeholder=\"Filter installed software…\" oninput=\"gpSearch(this)\" "
                    "data-gpf=\"hwsw\"></div>";
    h += "<div class=\"hw-scroll\"><table class=\"hw-tbl\"><thead><tr><th>Name</th><th>Version</th><th>Publisher</th>"
         "<th>Install date</th><th>Signature</th><th>Ecosystem</th></tr></thead><tbody>";
    for (const auto& e : *software) {
        const std::string searchable = lc(e.name + " " + e.version + " " + e.publisher);
        h += "<tr data-gpf=\"hwsw\" data-gpname=\"" + esc(searchable) + "\"><td class=\"hw-name\">" +
             esc(e.name) + "</td><td class=\"hw-mono\">" + ci_disp(e.version) +
             "</td><td>" + ci_disp(e.publisher) + "</td><td class=\"hw-mono\">" +
             ci_disp(e.install_date) + "</td><td>" + ci_disp(e.signature_status) +
             "</td><td>" + ci_disp(e.ecosystem) + "</td></tr>";
    }
    h += "</tbody></table></div>";
    if (truncated)
        h += "<div class=\"hw-page\">List truncated &mdash; showing the first " +
             std::to_string(kHwSoftwareCap) + " entries.</div>";
    h += "</div>";
    // Application usage and detected licences are behavioural reads: click-to-load only.
    h += device_data::render_usage_load_hosts(agent_id);
    return h;
}

std::string render_hardware_tags_lens(const std::string& agent_id,
                                      const std::optional<std::vector<DeviceTag>>& tags,
                                      bool can_write, bool can_delete) {
    // The custom-properties and property-schema panels load into this host on open
    // (their own fragment carries the Infrastructure probes, so a record view that
    // never opens this lens never pays them).
    const std::string properties_host =
        "<div hx-get=\"/fragments/hardware/ci/properties?id=" + url_encode(agent_id) +
        "\" hx-trigger=\"load\" hx-swap=\"innerHTML\" style=\"margin-top:22px\"><span "
        "class=\"gp-mute\">Loading properties&hellip;</span></div>";
    if (!tags)
        return "<div class=\"gp-banner hw-degrade\"><b>Tags unavailable.</b> The tag store could not be read. "
               "Retry shortly.</div>" + properties_host;
    std::string h = "<div class=\"hw-panel\">";
    if (can_write) {
        // The Add tag dialog (static/yuzu-device-data.js) posts JSON to the EXISTING
        // /api/tags/set (scoped Tag:Write, audited tag.set). The hint and the service
        // sentence are server-authored so the page and its tests share one wording.
        h += "<div class=\"hw-hdr\"><button type=\"button\" class=\"gp-btn accent\" "
             "data-act=\"tag-add\" data-agent=\"" + esc(agent_id) + "\" data-hint=\"" +
             esc(std::string(kHwTagKeyHint)) + "\" data-service-set-note=\"" +
             esc(std::string(kHwServiceTagSetNote)) + "\">Add tag</button></div>";
    }
    if (tags->empty()) {
        h += "<div class=\"hw-empty\">No tags set on this device.</div></div>";
        return h + properties_host;
    }
    // Remove needs Tag:Delete, a different permission from the Tag:Write that
    // gates Add — a Write-only viewer must not be offered a control that 403s.
    h += "<div class=\"hw-scroll\"><table class=\"hw-tbl\"><thead><tr><th>Key</th><th>Value</th><th>Source</th>" +
         std::string(can_delete ? "<th></th>" : "") + "</tr></thead><tbody>";
    for (const auto& t : *tags) {
        h += "<tr><td class=\"hw-name\">" + esc(t.key) + "</td><td class=\"hw-mono\">" + esc(t.value) +
             "</td><td class=\"hw-mono\">" + esc(t.source) + "</td>";
        if (can_delete)
            h += "<td><button type=\"button\" class=\"gp-btn danger\" data-act=\"tag-del\" data-agent=\"" +
                 esc(agent_id) + "\" data-key=\"" + esc(t.key) + "\"" +
                 (t.key == "service"
                      ? " data-service-note=\"" + esc(std::string(kHwServiceTagRemoveNote)) + "\""
                      : std::string()) +
                 ">Remove</button></td>";
        h += "</tr>";
    }
    h += "</tbody></table></div></div>";
    return h + properties_host;
}

} // namespace yuzu::server
