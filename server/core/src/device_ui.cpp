/// @file device_ui.cpp
/// Renderers for the shared device surfaces — PURE functions over DeviceRow.
/// Split from device_routes.cpp (which registers the routes) to keep each TU
/// small; the tiny markup helpers are re-declared in this TU's anonymous
/// namespace, same pattern as network_ui.cpp / dex_perf_ui.cpp.
///
/// Product UI: HTMX, server-rendered, dark-theme only, htmx core attrs only
/// (CSP blocks hx-on — plain onclick for navigation, allowed by 'unsafe-inline').
/// Reuses the shared `.gp-*` component CSS from the full-page shell, so no new CSS.
///
/// SLICE 1: the device list + the Device-info (CI-record) lens, over the live
/// registry. Fields not in the thin AgentInfo are NOT fabricated — the Hardware /
/// Network / Owner groups arrive with the inventory slice. The DEX/Guardian lenses
/// render an honest placeholder until their slices land.

#include "device_routes.hpp"

#include "dex_view_types.hpp"    // dex_signal_label for the DEX lens (store-free)
#include "tar_process_tree.hpp"  // tar_is_suspicious_spawn — shared LOLBin/shell denylist
#include "web_utils.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

std::string esc(const std::string& s) { return html_escape(s); }

// raw column name -> display header text, for render_device_live_generic's <th>.
// Backs the round-3 item 11 "physical-kit" kinds only; an unrecognised key falls
// back to itself unchanged — never crash on a column a future kind introduces.
std::string column_label(const std::string& raw) {
    static const std::unordered_map<std::string, std::string> kLabels{
        {"index", "#"},
        {"model", "Model"},
        {"size_gb", "Size (GB)"},
        {"media_type", "Media"},
        {"interface", "Interface"},
        {"slot", "Slot"},
        {"size_mb", "Size (MB)"},
        {"type", "Type"},
        {"speed_mhz", "Speed (MHz)"},
        {"cores", "Cores"},
        {"threads", "Threads"},
        {"clock_mhz", "Clock (MHz)"},
        {"name", "Name"},
        {"version", "Version"},
        {"date", "Date"},
        {"provider", "Provider"},
        {"device_class", "Class"},
        {"present", "Present"},
        {"state", "State"},
        {"percent", "Percent"},
        {"time_to_empty_min", "Time to empty (min)"},
        {"cycle_count", "Cycle count"},
        {"health_percent", "Health %"},
        {"status", "Status"},
        {"zone_or_detail", "Zone / detail"},
        {"celsius", "degC"},
        {"device", "Device"},
        {"bus", "Bus"},
        {"media", "Media"},
        {"health", "Health"},
        {"pct_used", "% used"},
        {"spare_pct", "Spare %"},
        {"detail", "Detail"},
        {"volume", "Volume"},
        {"mount_points", "Mount points"},
        {"fstype", "FS type"},
        {"total_bytes", "Size"},
        {"mac", "MAC"},
        {"speed_mbps", "Speed (Mbps)"},
        {"ssid", "SSID"},
        {"signal", "Signal"},
        {"security", "Security"},
        {"bssid", "BSSID"},
        {"interface_or_channel", "Interface / channel"},
    };
    const auto it = kLabels.find(raw);
    return it == kLabels.end() ? raw : it->second;
}

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

std::string os_label(const std::string& os) {
    if (os == "windows") return "Windows";
    if (os == "linux") return "Linux";
    if (os == "darwin" || os == "macos") return "macOS";
    return os.empty() ? std::string("&mdash;") : esc(os);
}

// A small online/offline status dot + word. Inline style (CSP allows style attrs)
// so it doesn't depend on dashboard-only CSS classes.
std::string status_cell(bool online) {
    const char* color = online ? "#4ed27e" : "#6f86a6";
    return "<span style=\"display:inline-block;width:.5rem;height:.5rem;border-radius:50%;"
           "background:" +
           std::string(color) + ";margin-right:.4rem\"></span>" +
           (online ? "<span style=\"color:#4ed27e\">online</span>"
                   : "<span class=\"gp-mute\">offline</span>");
}

// The per-device lens tab bar. Each tab hx-gets its lens fragment into #device-lens
// (the fragment re-renders this bar with its own tab active — the dex_subnav idiom,
// no JS, CSP-safe). `active` ∈ {"info","dex","guardian"}.
std::string device_lens_tabs(const std::string& active, const std::string& agent_id) {
    const std::string id = url_encode(agent_id);
    auto tab = [&](const char* key, const char* label, const std::string& frag) {
        const std::string on = (active == key) ? " on" : "";
        return "<a class=\"gp-chip" + on + "\" hx-get=\"" + frag + "?id=" + id +
               "\" hx-target=\"#device-lens\" hx-swap=\"innerHTML\">" + label + "</a>";
    };
    return "<div class=\"gp-filters\">" + tab("info", "Device info", "/fragments/device/info") +
           tab("dex", "DEX", "/fragments/device/dex") +
           tab("guardian", "Guardian", "/fragments/device/guardian") + "</div>";
}

// A toned DEX-score badge (green/amber/red by band); "—" when n/a (-1).
std::string score_badge(int score) {
    if (score < 0)
        return "<span class=\"gp-mute\">&mdash;</span>";
    const char* color = score >= 90 ? "#4ed27e" : (score >= 75 ? "#ffcc00" : "#ff5765");
    return "<span style=\"display:inline-block;min-width:1.7rem;text-align:center;font-weight:700;"
           "font-size:.68rem;border-radius:.3rem;padding:.05rem .4rem;color:#06121f;background:" +
           std::string(color) + "\">" + std::to_string(score) + "</span>";
}

// Guardian compliance-state badge: compliant=green, drifted=amber, errored=red.
std::string guard_state_badge(const std::string& state) {
    const char* color = state == "compliant" ? "#4ed27e"
                        : state == "errored"  ? "#ff5765"
                                              : "#ffcc00"; // drifted / anything else
    return "<span style=\"font-size:.6rem;font-weight:700;border-radius:.3rem;padding:.05rem .4rem;"
           "color:#06121f;background:" +
           std::string(color) + "\">" + esc(state.empty() ? "unknown" : state) + "</span>";
}

std::string ci_group(const std::string& title, const std::string& rows) {
    return "<div class=\"gp-tile\" style=\"min-width:240px;text-align:left\">"
           "<div class=\"l\" style=\"color:#a5d6ff;margin-bottom:.3rem\">" +
           esc(title) + "</div>" + rows + "</div>";
}
std::string kv(const std::string& k, const std::string& v) {
    return "<div style=\"display:flex;justify-content:space-between;gap:.8rem;font-size:.78rem;"
           "padding:.15rem 0;border-bottom:1px dotted #2d4068\"><span class=\"gp-mute\">" +
           esc(k) + "</span><span style=\"color:#cfdbe8\">" + v + "</span></div>";
}

} // namespace

std::string render_devices_list_fragment(const std::vector<DeviceRow>& rows, const std::string& q,
                                         const std::string& os_token,
                                         const std::string& status_token, std::size_t total_online,
                                         std::size_t total_devices) {
    const std::string qe = url_encode(q);
    // Build a filter-chip URL that keeps the OTHER params and sets one.
    auto url = [&](const std::string& os, const std::string& status) {
        return "/fragments/devices/list?q=" + qe + "&os=" + url_encode(os) + "&status=" +
               url_encode(status);
    };
    auto chip = [&](const std::string& cur, const std::string& val, const char* label,
                    const std::string& href) {
        const std::string on = (cur == val) ? " on" : "";
        return "<a class=\"gp-chip" + on + "\" hx-get=\"" + href +
               "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" + label + "</a>";
    };

    std::string h;
    // Summary tiles (slice 1: counts we can compute for real; at-risk/non-compliant
    // arrive with the DEX-score / Guardian slices).
    h += "<div class=\"gp-tiles\">";
    h += "<div class=\"gp-tile\"><div class=\"n\">" + std::to_string(total_devices) +
         "</div><div class=\"l\">Devices</div></div>";
    h += "<div class=\"gp-tile\"><div class=\"n\" style=\"color:#4ed27e\">" +
         std::to_string(total_online) + "</div><div class=\"l\">Online</div></div>";
    h += "</div>";

    // Controls. Search re-renders on Enter (avoids per-keystroke focus loss); the OS
    // and status chips re-render on click. All carry the current state in the URL.
    h += "<div class=\"gp-filters\" style=\"margin-top:.6rem\">"
         "<input name=\"q\" value=\"" +
         esc(q) +
         "\" placeholder=\"Search hostname, OS, tag\xE2\x80\xA6\" "
         "style=\"background:#0e1a2d;border:1px solid #2d4068;border-radius:.4rem;color:#cfdbe8;"
         "padding:.3rem .6rem;font-size:.78rem;min-width:240px\" "
         "hx-get=\"/fragments/devices/list?os=" +
         url_encode(os_token) + "&status=" + url_encode(status_token) +
         "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
         "hx-trigger=\"keyup[key=='Enter'], search\"></div>";
    h += "<div class=\"gp-filters\">";
    h += "<span class=\"gp-mute\" style=\"font-size:.66rem;align-self:center\">OS</span>";
    h += chip(os_token, "all", "All", url("all", status_token));
    h += chip(os_token, "windows", "Windows", url("windows", status_token));
    h += chip(os_token, "linux", "Linux", url("linux", status_token));
    h += chip(os_token, "macos", "macOS", url("macos", status_token));
    h += "</div>";
    // The list is sourced from the live connection registry, so every row is a
    // currently-connected device. There is no enrolled-but-offline source yet, so we
    // do NOT render a status/offline filter that could never match — the offline tier
    // + real last-seen arrive with the persistent device-inventory slice.
    h += "<div class=\"gp-mute\" style=\"font-size:.66rem;margin-top:.2rem\">"
         "Showing currently-connected devices.</div>";

    if (rows.empty()) {
        h += "<div class=\"gp-placeholder\"><b>No devices match</b>Broaden the search or filters.</div>";
        return h;
    }

    h += "<table class=\"gp-table\"><thead><tr><th>Device</th><th>Status</th><th>DEX</th><th>OS</th>"
         "<th>Version</th><th>Last seen</th></tr></thead><tbody>";
    for (const auto& d : rows) {
        const std::string label = d.hostname.empty() ? d.agent_id : d.hostname;
        std::string tagline = esc(d.agent_id.substr(0, 12));
        h += "<tr class=\"gp-rowlink\" style=\"cursor:pointer\" "
             "onclick=\"location.href='/device?id=" +
             url_encode(d.agent_id) + "'\">";
        h += "<td><a href=\"/device?id=" + url_encode(d.agent_id) +
             "\" style=\"font-weight:600;color:#fff\">" + esc(label) +
             "</a><div class=\"gp-mute\" style=\"font-size:.66rem\">" + tagline + "</div></td>";
        h += "<td>" + status_cell(d.online) + "</td>";
        h += "<td>" + score_badge(d.dex_score) + "</td>";
        h += "<td class=\"gp-mute\">" + os_label(d.os) + "/" + esc(d.arch) + "</td>";
        h += "<td class=\"gp-mute\">" + (d.agent_version.empty() ? std::string("&mdash;")
                                                                 : esc(d.agent_version)) +
             "</td>";
        h += "<td class=\"gp-mute\">" + (d.last_seen.empty() ? std::string("&mdash;")
                                                             : esc(d.last_seen)) +
             "</td>";
        h += "</tr>";
    }
    h += "</tbody></table>";
    h += "<div class=\"gp-note\">Showing <b>" + std::to_string(rows.size()) +
         "</b> matching device(s). At fleet scale this is server-paginated &amp; virtualized; "
         "a row opens the device page (Device info &middot; DEX &middot; Guardian).</div>";
    return h;
}

std::string render_device_info_fragment(const DeviceRow& d) {
    std::string tags;
    for (std::size_t i = 0; i < d.tags.size(); ++i)
        tags += (i ? ", " : "") + esc(d.tags[i]);
    if (tags.empty())
        tags = "<span class=\"gp-mute\">none</span>";

    std::string h = device_lens_tabs("info", d.agent_id);
    h += "<div class=\"gp-tiles\" style=\"align-items:stretch\">";
    h += ci_group("Identity", kv("Hostname", esc(d.hostname.empty() ? "&mdash;" : d.hostname)) +
                                  kv("Agent ID", "<span style=\"font-family:var(--mono),Consolas,"
                                                 "monospace;font-size:.7rem\">" +
                                                     esc(d.agent_id) + "</span>") +
                                  kv("OS", os_label(d.os)) +
                                  kv("Architecture", esc(d.arch.empty() ? "&mdash;" : d.arch)));
    h += ci_group("Management",
                  kv("Tags", tags) +
                      kv("Agent version", d.agent_version.empty() ? std::string("&mdash;")
                                                                  : esc(d.agent_version)) +
                      kv("Status", d.online ? "<span style=\"color:#4ed27e\">online</span>"
                                            : "<span class=\"gp-mute\">offline</span>") +
                      kv("Last seen", d.last_seen.empty() ? std::string("&mdash;")
                                                          : esc(d.last_seen)));
    h += "</div>";
    h += "<div class=\"gp-note\">Hardware, network (IP/MAC) and ownership are <b>not in the agent's "
         "registration</b> today &mdash; they arrive with the inventory slice (collector / "
         "custom-properties / CMDB sync), not fabricated here.</div>";
    return h;
}

std::string render_device_lens_placeholder(const std::string& active, const std::string& agent_id,
                                           const std::string& message, bool tabs) {
    return (tabs ? device_lens_tabs(active, agent_id) : std::string()) +
           "<div class=\"gp-placeholder\"><b>Coming in a later slice</b>" + esc(message) + "</div>";
}

std::string render_device_dex_lens(const std::string& agent_id, int score,
                                   const std::vector<std::pair<std::string, std::int64_t>>& signals,
                                   bool tabs) {
    std::string h = tabs ? device_lens_tabs("dex", agent_id) : std::string();
    h += "<div class=\"gp-tiles\"><div class=\"gp-tile\">";
    if (score < 0)
        h += "<div class=\"n\">&mdash;</div>";
    else
        h += "<div class=\"n " + std::string(score >= 90 ? "good" : "warn") + "\">" +
             std::to_string(score) + "</div>";
    h += "<div class=\"l\">DEX experience</div><div class=\"sx\">last 7 days</div></div></div>";
    if (signals.empty()) {
        h += "<div class=\"gp-placeholder\"><b>No DEX signals</b>Nothing fired on this device in "
             "the window &mdash; experience is clean.</div>";
    } else {
        h += "<div class=\"gp-sech\">Signals (this device, 7d)</div>";
        h += "<table class=\"gp-table\"><thead><tr><th>Signal</th><th>Type</th>"
             "<th class=\"gp-num\">Events</th></tr></thead><tbody>";
        for (const auto& [obs, count] : signals)
            h += "<tr><td>" + dex_signal_label(obs) +
                 "</td><td class=\"gp-mute\" style=\"font-family:Consolas,monospace;font-size:.7rem\">" +
                 esc(obs) + "</td><td class=\"gp-num\">" + std::to_string(count) + "</td></tr>";
        h += "</tbody></table>";
    }
    h += "<div class=\"gp-note\"><button class=\"gp-btn\" hx-get=\"/fragments/dex/device?id=" +
         url_encode(agent_id) +
         "\" hx-target=\"#device-lens\" hx-swap=\"innerHTML\">Load full DEX history</button> "
         "<span class=\"gp-mute\">crash detail, OS split, on-device perf</span></div>";
    return h;
}

// Component CSS for the live-snapshot cards + the TAR-style process tree. Injected
// inline by the shell fragment (the shared page shell carries only the `.gp-*`
// component CSS; `.ls-*`/`.tar-tree-*` are feature-local). CSP allows inline <style>
// (style-src 'unsafe-inline'). The tree classes mirror tar_page_ui.cpp (PR1551) so
// the viewer matches /tar. Mockup: docs/mockups/device-live-snapshot.html.
const char* live_snapshot_css() {
    // Class names are unique (ls-*/tar-tree-*/tt-*) so the rules are GLOBAL, not
    // scoped to #device-live — the pop-out clones a card body into a <dialog> outside
    // that container and must stay styled. Generic names are prefixed (.ls-pill/.ls-sw)
    // and `.name` is scoped to `.ls-tbl` to avoid colliding with shared dashboard CSS.
    return R"CSS(<style>
    .ls-kpis{display:flex;flex-wrap:wrap;gap:.45rem;margin:.5rem 0 .8rem}
    .ls-kpi{background:var(--surface);border:1px solid var(--border);border-radius:.45rem;padding:.4rem .65rem;flex:1;min-width:104px}
    .ls-kpi .n{font-size:1.1rem;font-weight:700;color:var(--fg);line-height:1.1;font-variant-numeric:tabular-nums}
    .ls-kpi .l{font-size:.55rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-top:.1rem}
    .grp-row{display:flex;align-items:center;justify-content:space-between;gap:.6rem;margin:.6rem 0 .3rem}
    .ls-toggle{background:var(--mds-color-state-hover);border:1px solid var(--border);color:var(--fg);border-radius:.35rem;font-size:.66rem;padding:.2rem .55rem;cursor:pointer}
    .ls-toggle:hover{color:var(--accent);border-color:var(--accent)}
    .ls-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:.6rem;align-items:start}
    .ls-card{background:var(--surface);border:1px solid var(--border);border-radius:.5rem;overflow:hidden}
    .ls-card>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:.45rem;padding:.45rem .55rem}
    .ls-card>summary::-webkit-details-marker{display:none}
    .ls-card>summary::before{content:"\25B8";color:var(--muted);font-size:.66rem;flex:0 0 .7rem}
    .ls-card[open]>summary{border-bottom:1px solid var(--border)}
    .ls-card[open]>summary::before{content:"\25BE"}
    .ls-card>summary:hover{background:var(--mds-color-state-hover)}
    .ls-ttl{font-size:.76rem;font-weight:700;color:var(--fg);white-space:nowrap}
    .ls-cnt{font-size:.6rem;color:var(--muted);background:var(--mds-color-state-hover);border-radius:.6rem;padding:.02rem .4rem;font-variant-numeric:tabular-nums}
    .ls-cnt:empty{display:none}
    .ls-os{font-size:.54rem;color:var(--muted);border:1px solid var(--border);border-radius:.25rem;padding:0 .3rem;text-transform:uppercase}
    .ls-prev{flex:1 1 auto;font-size:.66rem;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;text-align:right}
    .ls-pop{flex:0 0 auto;background:none;border:1px solid var(--border);color:var(--muted);border-radius:.3rem;font-size:.74rem;line-height:1;padding:.12rem .35rem;cursor:pointer}
    .ls-pop:hover{color:var(--accent);border-color:var(--accent)}
    .ls-body{max-height:260px;overflow:auto;padding:.3rem .55rem .5rem}
    .ls-tbl{width:100%;border-collapse:collapse;font-size:.74rem}
    .ls-tbl th{position:sticky;top:0;background:var(--surface);text-align:left;padding:.26rem .45rem;border-bottom:1px solid var(--border);color:var(--muted);font-size:.56rem;text-transform:uppercase;letter-spacing:.05em;font-weight:700}
    .ls-tbl td{padding:.22rem .45rem;border-bottom:1px solid rgba(45,64,104,.5)}
    .ls-tbl .name{color:var(--fg);font-weight:600}
    .ls-num{text-align:right;font-variant-numeric:tabular-nums}
    .ls-search{background:var(--bg);border:1px solid var(--border);border-radius:.35rem;color:var(--fg);padding:.22rem .45rem;font-size:.72rem;width:100%;margin:0 0 .35rem;box-sizing:border-box}
    .ls-pill{font-size:.58rem;font-weight:700;border-radius:.25rem;padding:.02rem .35rem;border:1px solid var(--border)}
    .ls-pill.dyn,.ls-pill.type{color:#a5d6ff}
    .ls-pill.stat{color:var(--green);border-color:rgba(78,210,126,.5)}
    .ls-pill.inc,.ls-pill.cat{color:var(--muted)}
    .ls-sw{display:inline-block;width:1.7rem;height:.85rem;border-radius:.6rem;background:var(--border);position:relative;vertical-align:middle}
    .ls-sw.on{background:rgba(78,210,126,.35)}
    .ls-sw::after{content:"";position:absolute;top:.13rem;left:.14rem;width:.58rem;height:.58rem;border-radius:50%;background:var(--muted)}
    .ls-sw.on::after{left:.98rem;background:var(--green)}
    .src-on{color:var(--green);font-weight:600}.src-off{color:var(--muted)}
    .tar-tree-node{margin:0}
    .tar-tree-node>summary{display:flex;align-items:center;list-style:none;cursor:pointer;padding:.05rem 0}
    .tar-tree-node>summary::-webkit-details-marker{display:none}
    .tar-tree-node>summary::before{content:"\25B8";flex:0 0 1rem;text-align:center;color:var(--muted);font-size:.7rem}
    .tar-tree-node[open]>summary::before{content:"\25BE"}
    .tar-tree-children{margin-left:.5rem;padding-left:.7rem;border-left:1px solid var(--border)}
    .tar-tree-leaf{display:flex;align-items:center;padding:.05rem 0 .05rem 1rem}
    .tar-tree-row{display:inline-flex;align-items:center;gap:.45rem;flex:1 1 auto;min-width:0;color:var(--fg);padding:.05rem .3rem;border-radius:.2rem;font-size:.74rem}
    .tar-tree-row:hover{background:var(--mds-color-state-hover)}
    .tar-tree-row[data-anom="1"]{box-shadow:inset 2px 0 0 var(--red)}
    .tt-dot{width:.5rem;height:.5rem;border-radius:50%;flex:0 0 auto;background:var(--green);box-shadow:0 0 4px rgba(60,200,120,.5)}
    .tt-pid{color:var(--muted);flex:0 0 auto;min-width:3.4rem;text-align:right;font-variant-numeric:tabular-nums;font-family:var(--mono)}
    .tt-name{flex:1 1 auto;min-width:0;color:var(--fg);font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .tt-hash{flex:0 0 auto;color:var(--muted);font-family:var(--mono);font-size:.64rem;white-space:nowrap;padding-left:.6rem}
    .tt-anom{color:var(--red);flex:0 0 auto}
    .tt-net{display:inline-flex;align-items:center;gap:.25rem;font-size:.66rem;color:var(--muted);flex:0 0 auto}
    .tt-net-ico{color:var(--accent)}.tt-net-pub .tt-net-ico{color:var(--yellow)}
    .tt-ep{background:var(--mds-color-state-hover);border-radius:.6rem;padding:0 .35rem;white-space:nowrap}
    .tt-ep-pub{color:var(--yellow)}.tt-ep-more{opacity:.7}
    .tt-group .tt-name{color:var(--fg)}
    .tt-group-ico{color:var(--accent);flex:0 0 auto;font-size:.7rem}
    .tt-group-count{color:var(--fg);font-weight:600;background:var(--mds-color-state-hover);border-radius:.6rem;padding:0 .4rem;font-size:.7rem}
    .tt-meta{color:var(--muted);font-size:.7rem;white-space:nowrap}
    dialog.ls-po{border:1px solid var(--border);background:var(--surface);color:var(--fg);border-radius:.6rem;padding:0;width:82vw;max-width:1040px}
    dialog.ls-po::backdrop{background:rgba(4,12,24,.66)}
    .ls-po .po-head{display:flex;align-items:center;justify-content:space-between;gap:.6rem;padding:.55rem .8rem;border-bottom:1px solid var(--border)}
    .ls-po .po-head .t{font-size:.92rem;font-weight:700;color:var(--fg)}
    .ls-po .po-close{background:none;border:1px solid var(--border);color:var(--fg);border-radius:.35rem;padding:.2rem .55rem;cursor:pointer}
    .ls-po .po-body{padding:.6rem .8rem;max-height:76vh;overflow:auto}
    .ls-bar{display:inline-block;width:84px;height:.5rem;background:var(--border);border-radius:.3rem;overflow:hidden;vertical-align:middle;margin-right:.4rem}
    .ls-bar>span{display:block;height:100%;background:var(--accent)}
    .ls-bar-warn>span{background:var(--yellow)}.ls-bar-bad>span{background:var(--red)}
    .ls-barlbl{font-size:.64rem;color:var(--muted);font-variant-numeric:tabular-nums}
    </style>)CSS";
}

std::string render_device_live_shell(const std::string& agent_id) {
    const std::string e = url_encode(agent_id);
    std::string h = live_snapshot_css();
    h += "<div id=\"device-live-snapshot\">";
    h += "<div class=\"gp-note\" style=\"margin-top:0\">Live instructions dispatched to the device "
         "now (read-only &middot; Execute-gated &middot; audited) &mdash; one query per card.</div>";
    // KPI strip — filled by each card's result via hx-swap-oob.
    // The value element is a <span class="n"> (not a <div>) so the result's OOB
    // <span class="n" id=…> swap replaces like-with-like and keeps the styling.
    auto kpi = [](const char* id, const char* label) {
        return "<div class=\"ls-kpi\"><span class=\"n\" id=\"" + std::string(id) +
               "\">&mdash;</span><div class=\"l\">" + label + "</div></div>";
    };
    h += "<div class=\"ls-kpis\">";
    h += kpi("ls-kpi-uptime", "Uptime");
    h += kpi("ls-kpi-procs", "Processes");
    h += kpi("ls-kpi-svc", "Services running");
    h += kpi("ls-kpi-listen", "Listening");
    h += kpi("ls-kpi-conn", "Connections");
    h += kpi("ls-kpi-users", "Users");
    h += kpi("ls-kpi-disk", "Disk free");
    h += "</div>";
    // Hidden uptime loader: fills the Uptime KPI (uptime has no card of its own).
    h += "<div style=\"display:none\" hx-get=\"/fragments/device/live/run?id=" + e +
         "&amp;kind=uptime\" hx-trigger=\"load\" hx-swap=\"innerHTML\"></div>";
    // Each card group (Live cards / Physical) is its own [data-lsgroup] container so
    // lsToggleAll (guardian_page_ui.cpp) can scope its "expand all" to the button's
    // OWN group only — a document-wide querySelectorAll would also snap open the
    // OTHER group's lazy cards, firing every one of their dispatches at once (the
    // exact storm the lazy toggle-once:closest-details design exists to prevent).
    h += "<div class=\"ls-group\" data-lsgroup=\"live\">";
    h += "<div class=\"grp-row\"><h2 class=\"gp-sech\" style=\"margin:0\">Live cards</h2>"
         "<button class=\"ls-toggle\" onclick=\"lsToggleAll(this)\">Expand all</button></div>";
    h += "<div class=\"ls-grid\">";
    // One collapsed card per kind; its body auto-dispatches the live query on load
    // (same proven run/poll seam as before) and renders into the scrollable body.
    auto card = [&](const char* kind, const char* title, const char* os_tag, const char* preview,
                    bool lazy = false) {
        std::string c = "<details class=\"ls-card\"><summary><span class=\"ls-ttl\">" +
                        std::string(title) + "</span><span class=\"ls-cnt\" id=\"ls-cnt-" + kind +
                        "\"></span>";
        if (os_tag && *os_tag)
            c += "<span class=\"ls-os\">" + std::string(os_tag) + "</span>";
        // Eager cards dispatch on load (the proven run/poll seam); the new Physical
        // cards are behind a collapsed <details> by default, so lazy=true defers
        // dispatch to first expand (htmx 2.0.4 `EVENT MODIFIER from:SELECTOR`
        // grammar — see dashboard_ui.cpp/settings_ui.cpp's "... from:body" and
        // tar_tree_routes.cpp's "change from:#tar-tree-host" for the same "from:"
        // usage already relied on in this codebase; "closest details" is htmx's
        // standard extended CSS selector for the nearest ancestor <details>).
        c += "<span class=\"ls-prev\">" + std::string(preview) +
             "</span><button class=\"ls-pop\" title=\"Pop out\" onclick=\"lsPopOut(event,this)\">"
             "&#10530;</button></summary>"
             "<div class=\"ls-body\" hx-get=\"/fragments/device/live/run?id=" +
             e + "&amp;kind=" + kind + "\" hx-trigger=\"" +
             (lazy ? "toggle once from:closest details" : "load") +
             "\" hx-swap=\"innerHTML\"><div class=\"gp-mute\">Loading&hellip;"
             "</div></div></details>";
        return c;
    };
    h += card("process_tree", "Processes", "", "tree &middot; SHA-256 &middot; network");
    h += card("services", "Services", "", "run state");
    h += card("users", "Logged-in users", "", "sessions");
    h += card("netconfig", "Adapters &amp; IP", "", "addresses");
    // arp is live on all three platforms; the Linux and macOS legs are
    // constrained (Linux: IPv4 ARP only; macOS: no interface name or entry
    // type), so no OS badge but the limit is stated in the preview.
    h += card("arp", "ARP / neighbours", "", "neighbour table &middot; limited on Linux/macOS");
    h += card("dns_cache", "DNS cache", "Win &middot; Linux", "resolver cache");
    h += card("listening", "Listening ports", "", "sockets");
    h += card("connections", "Active connections", "", "established");
    h += card("capture_sources", "Capture sources", "", "TAR local capture");
    h += card("disk", "Disk space", "", "system volume only");
    h += "</div>"; // close .ls-grid (live)
    h += "</div>"; // close .ls-group[data-lsgroup=live]
    // Physical cards are lazy (dispatch only on individual expand) — their OWN
    // "Expand all" reuses lsToggleAll(this), scoped to this group by data-lsgroup
    // above, so a deliberate click here mass-expands only these 10 (a legitimate,
    // explicit dispatch of all 10), never as a side effect of the Live-cards button.
    h += "<div class=\"ls-group\" data-lsgroup=\"physical\">";
    h += "<div class=\"grp-row\"><h2 class=\"gp-sech\" style=\"margin:0\">Physical</h2>"
         "<button class=\"ls-toggle\" onclick=\"lsToggleAll(this)\">Expand all</button></div>";
    h += "<div class=\"ls-grid\">";
    h += card("hw_disks", "Disks", "", "model &middot; size &middot; interface", true);
    h += card("hw_memory", "Memory", "", "slots &middot; size &middot; speed", true);
    h += card("hw_processors", "Processors", "", "cores &middot; threads &middot; clock", true);
    h += card("hw_drivers", "Drivers", "Win and Linux", "name &middot; version &middot; provider",
              true);
    h += card("battery", "Battery", "", "state &middot; percent &middot; health", true);
    h += card("thermal", "Thermal", "", "zones &middot; temperature", true);
    h += card("smart", "Disk health (SMART)", "Win and macOS", "health &middot; wear &middot; spare",
              true);
    h += card("volumes", "Volumes", "Win and macOS", "mounts &middot; filesystem &middot; size", true);
    h += card("adapters", "Network adapters", "", "MAC &middot; speed &middot; status", true);
    h += card("wifi", "Wi-Fi", "", "SSID &middot; signal &middot; security", true);
    h += "</div>"; // close .ls-grid (physical)
    h += "</div>"; // close .ls-group[data-lsgroup=physical]
    h += "</div>"; // close #device-live-snapshot
    return h;
}

std::string render_device_live_value(const std::string& label, const std::string& value) {
    return "<div class=\"gp-tiles\"><div class=\"gp-tile\"><div class=\"n\">" +
           (value.empty() ? std::string("&mdash;") : esc(value)) + "</div><div class=\"l\">" +
           esc(label) + "</div></div></div>";
}

std::string render_device_live_processes(const std::vector<LiveProcess>& procs) {
    if (procs.empty())
        return "<div class=\"gp-note\">No processes returned.</div>";
    auto lc = [](std::string s) {
        for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return s;
    };
    const std::size_t n = procs.size();
    const std::size_t preview = n < 10 ? n : 10;

    std::string h = "<div class=\"gp-note\" style=\"margin-top:0\"><b>" + std::to_string(n) +
                    "</b> running processes (live) &middot; SHA-256 of the on-disk image.</div>";
    // Search the full (in-DOM) list; collapse to the first 10 when the box is empty.
    h += "<div class=\"gp-filters\"><input class=\"gp-search\" type=\"text\" "
         "placeholder=\"Search name, PID, or hash\xE2\x80\xA6\" oninput=\"gpSearchTopN(this)\" "
         "data-gpf=\"liveproc\" data-gplimit=\"10\" style=\"min-width:240px\">"
         "<span class=\"gp-mute\" data-gpcount=\"liveproc\" style=\"font-size:.68rem\">Showing " +
         std::to_string(preview) + " of " + std::to_string(n) + "</span></div>";
    h += "<table class=\"gp-table\"><thead><tr><th class=\"gp-num\">PID</th><th>Process</th>"
         "<th>SHA-256</th></tr></thead><tbody>";
    std::size_t i = 0;
    for (const auto& p : procs) {
        const std::string search = lc(p.name + " " + std::to_string(p.pid) + " " + p.sha256 + " " +
                                      p.path);
        const std::string hidden = (i++ >= preview) ? " style=\"display:none\"" : "";
        h += "<tr data-gpf=\"liveproc\" data-gpname=\"" + esc(search) + "\"" + hidden + ">";
        h += "<td class=\"gp-num\">" + std::to_string(p.pid) + "</td>";
        h += "<td><div class=\"name\">" + esc(p.name) + "</div>";
        if (!p.path.empty())
            h += "<div class=\"gp-mute\" style=\"font-family:var(--mono);font-size:.62rem;"
                 "overflow-wrap:anywhere\">" +
                 esc(p.path) + "</div>";
        h += "</td>";
        if (!p.sha256.empty())
            h += "<td><code style=\"font-family:var(--mono);font-size:.66rem\" title=\"" +
                 esc(p.sha256) + "\">" + esc(p.sha256.substr(0, 16)) + "\xE2\x80\xA6</code></td>";
        else
            h += "<td class=\"gp-mute\">&mdash;</td>";
        h += "</tr>";
    }
    h += "</tbody></table>";
    return h;
}

// ── Live-snapshot v2 renderers (feat/device-live-snapshot) ──────────────────
namespace {

std::string lc(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// A remote address that is NOT loopback / private / link-local / ULA. Drives the
// public-endpoint highlight (mirrors tar_process_tree's remote_class "pub").
bool is_public_ip(const std::string& a) {
    if (a.empty() || a == "0.0.0.0" || a == "::" || a == "::1")
        return false;
    if (a.starts_with("127.") || a.starts_with("169.254.") || a.starts_with("fe80") ||
        a.starts_with("10.") || a.starts_with("192.168.") || a.starts_with("fc") ||
        a.starts_with("fd"))
        return false;
    if (a.starts_with("172.")) { // 172.16.0.0–172.31.255.255 is private
        const auto dot = a.find('.', 4);
        int second = -1;
        try { second = std::stoi(a.substr(4, dot == std::string::npos ? std::string::npos : dot - 4)); }
        catch (...) {}
        if (second >= 16 && second <= 31)
            return false;
    }
    return true;
}

std::string endpoint_label(const LiveConn& c) {
    return c.listening ? (":" + std::to_string(c.local_port) + " listen")
                       : (c.remote_addr + ":" + std::to_string(c.remote_port));
}

// Inline per-process network summary, byte-for-byte the TAR `tt-net` shape: count
// badge + up to two distinct endpoints (public first) + "+N", full list in title.
std::string live_net_cell(const std::vector<const LiveConn*>& conns) {
    if (conns.empty())
        return "";
    std::vector<const LiveConn*> distinct;
    std::unordered_set<std::string> seen;
    bool any_pub = false;
    for (const LiveConn* c : conns) {
        std::string ep = endpoint_label(*c);
        if (!seen.insert(ep).second)
            continue;
        distinct.push_back(c);
        if (!c->listening && is_public_ip(c->remote_addr))
            any_pub = true;
    }
    std::stable_sort(distinct.begin(), distinct.end(), [](const LiveConn* a, const LiveConn* b) {
        const bool pa = !a->listening && is_public_ip(a->remote_addr);
        const bool pb = !b->listening && is_public_ip(b->remote_addr);
        return pa && !pb;
    });
    std::string title;
    for (std::size_t i = 0; i < distinct.size() && i < 12; ++i)
        title += endpoint_label(*distinct[i]) + "  ";
    std::string cell = "<span class=\"tt-net" + std::string(any_pub ? " tt-net-pub" : "") +
                       "\" title=\"" + esc(title) + "\"><span class=\"tt-net-ico\">\xE2\x86\x97</span>" +
                       std::to_string(distinct.size());
    for (std::size_t i = 0; i < distinct.size() && i < 2; ++i) {
        const LiveConn* c = distinct[i];
        std::string klass = "tt-ep";
        if (!c->listening && is_public_ip(c->remote_addr))
            klass += " tt-ep-pub";
        cell += "<span class=\"" + klass + "\">" + esc(endpoint_label(*c)) + "</span>";
    }
    if (distinct.size() > 2)
        cell += "<span class=\"tt-ep tt-ep-more\">+" + std::to_string(distinct.size() - 2) + "</span>";
    cell += "</span>";
    return cell;
}

constexpr std::size_t kLiveTreeMaxNodes = 50000;
constexpr int kLiveTreeDepthCap = 64;
constexpr std::size_t kLiveGroupThreshold = 5; // collapse N+ same-name siblings (TAR pattern)

struct TreeCtx {
    const std::vector<LiveProcNode>& nodes;
    std::unordered_map<std::uint32_t, std::vector<std::size_t>> children;     // ppid -> child idxs
    std::unordered_map<std::uint32_t, std::vector<const LiveConn*>> conns_by_pid;
    std::vector<bool> visited; ///< per-node guard: each node renders at most once (cycle-safe)
    std::size_t emitted = 0;
};

std::string live_proc_row(const LiveProcNode& n, const TreeCtx& ctx, bool suspicious) {
    std::string r = "<span class=\"tar-tree-row\"";
    if (suspicious)
        r += " data-anom=\"1\"";
    r += "><span class=\"tt-dot\"></span><span class=\"tt-pid\">" + std::to_string(n.pid) +
         "</span><span class=\"tt-name\">" + esc(n.name.empty() ? "(unknown)" : n.name) + "</span>";
    if (suspicious)
        r += "<span class=\"tt-anom\" title=\"suspicious parent\xE2\x86\x92" "child spawn\">\xE2\x9A\xA0</span>";
    if (auto it = ctx.conns_by_pid.find(n.pid); it != ctx.conns_by_pid.end())
        r += live_net_cell(it->second);
    if (!n.sha256.empty())
        r += "<span class=\"tt-hash\" title=\"" + esc(n.sha256) + (n.path.empty() ? "" : "\n" + esc(n.path)) +
             "\">" + esc(n.sha256.substr(0, 12)) + "\xE2\x80\xA6</span>";
    else
        r += "<span class=\"tt-hash\">&mdash;</span>";
    r += "</span>";
    return r;
}

void render_tree_node(TreeCtx& ctx, std::size_t idx, int depth, const std::string& parent_name,
                      std::string& out);

void render_tree_children(TreeCtx& ctx, const std::vector<std::size_t>& kids, int depth,
                          const std::string& parent_name, std::string& out) {
    // Bucket same-name siblings (first-appearance order); collapse a run of >= threshold
    // into one "name ×N" group (cleans up dozens of svchost.exe), mirroring the TAR tree.
    std::vector<std::string_view> order;
    std::unordered_map<std::string_view, std::vector<std::size_t>> buckets;
    for (std::size_t i : kids) {
        std::string_view nm{ctx.nodes[i].name};
        auto [it, ins] = buckets.try_emplace(nm);
        if (ins)
            order.push_back(nm);
        it->second.push_back(i);
    }
    for (std::string_view nm : order) {
        const auto& g = buckets[nm];
        if (g.size() >= kLiveGroupThreshold) {
            out += "<details class=\"tar-tree-node\"><summary><span class=\"tar-tree-row tt-group\">"
                   "<span class=\"tt-group-ico\">\xE2\x96\xA6</span><span class=\"tt-name\">" +
                   esc(nm.empty() ? "(unknown)" : std::string(nm)) +
                   "</span><span class=\"tt-group-count\">\xC3\x97" + std::to_string(g.size()) +
                   "</span><span class=\"tt-meta\">" + std::to_string(g.size()) +
                   " running</span></span></summary><div class=\"tar-tree-children\">";
            for (std::size_t i : g)
                render_tree_node(ctx, i, depth + 1, parent_name, out);
            out += "</div></details>";
        } else {
            for (std::size_t i : g)
                render_tree_node(ctx, i, depth, parent_name, out);
        }
    }
}

void render_tree_node(TreeCtx& ctx, std::size_t idx, int depth, const std::string& parent_name,
                      std::string& out) {
    if (ctx.emitted >= kLiveTreeMaxNodes)
        return;
    if (idx < ctx.visited.size() && ctx.visited[idx])
        return; // already rendered — a ppid cycle (A→B→A) terminates here
    if (depth > kLiveTreeDepthCap) {
        out += "<div class=\"tar-tree-leaf tt-meta\">\xE2\x80\xA6 (depth capped)</div>";
        return;
    }
    if (idx < ctx.visited.size())
        ctx.visited[idx] = true;
    ++ctx.emitted;
    const LiveProcNode& n = ctx.nodes[idx];
    const bool suspicious = !parent_name.empty() && tar_is_suspicious_spawn(parent_name, n.name);
    auto it = ctx.children.find(n.pid);
    const bool has_children = n.pid != 0 && it != ctx.children.end() && !it->second.empty();
    if (!has_children) {
        out += "<div class=\"tar-tree-leaf\">" + live_proc_row(n, ctx, suspicious) + "</div>";
        return;
    }
    out += depth < 2 ? "<details open class=\"tar-tree-node\">" : "<details class=\"tar-tree-node\">";
    out += "<summary>" + live_proc_row(n, ctx, suspicious) + "</summary><div class=\"tar-tree-children\">";
    render_tree_children(ctx, it->second, depth + 1, n.name, out);
    out += "</div></details>";
}

// One `.ls-tbl` row whose cells are pre-formatted HTML; `search` (lowercased) backs
// the optional client filter.
std::string tr(const std::string& search, const std::vector<std::string>& cells) {
    std::string r = "<tr";
    if (!search.empty())
        r += " data-gpname=\"" + esc(search) + "\"";
    r += ">";
    for (const auto& c : cells)
        r += "<td>" + c + "</td>";
    r += "</tr>";
    return r;
}

} // namespace

std::string render_device_live_tree(const std::vector<LiveProcNode>& nodes,
                                    const std::vector<LiveConn>& conns) {
    if (nodes.empty())
        return "<div class=\"gp-note\">No processes returned.</div>";
    TreeCtx ctx{nodes, {}, {}, {}, 0};
    ctx.visited.assign(nodes.size(), false);
    std::unordered_set<std::uint32_t> pidset;
    for (const auto& n : nodes)
        pidset.insert(n.pid);
    for (std::size_t i = 0; i < nodes.size(); ++i) {
        const auto& n = nodes[i];
        if (n.ppid != 0 && n.ppid != n.pid && pidset.count(n.ppid))
            ctx.children[n.ppid].push_back(i);
    }
    for (const auto& c : conns)
        ctx.conns_by_pid[c.pid].push_back(&c);
    std::vector<std::size_t> roots;
    for (std::size_t i = 0; i < nodes.size(); ++i) {
        const auto& n = nodes[i];
        if (n.ppid == 0 || n.ppid == n.pid || !pidset.count(n.ppid))
            roots.push_back(i);
    }
    std::string h =
        "<input class=\"ls-search\" type=\"text\" placeholder=\"Search name, PID, hash, or "
        "endpoint\xE2\x80\xA6\" oninput=\"lsFilterTree(this)\">";
    h += "<div class=\"gp-note\" style=\"margin-top:0\"><b>" + std::to_string(nodes.size()) +
         "</b> processes &middot; names-only &middot; SHA-256 of the on-disk image &middot; "
         "suspicious parent\xE2\x86\x92" "child spawns flagged.</div>";
    h += "<div class=\"proctree\">";
    render_tree_children(ctx, roots, 0, "", h);
    // Any node not reached from a root (a pure ppid cycle, or an orphan whose parent
    // isn't itself a root) still renders, as its own root — no process silently vanishes.
    std::vector<std::size_t> orphans;
    for (std::size_t i = 0; i < nodes.size(); ++i)
        if (i >= ctx.visited.size() || !ctx.visited[i])
            orphans.push_back(i);
    if (!orphans.empty())
        render_tree_children(ctx, orphans, 0, "", h);
    h += "</div>";
    return h;
}

std::string render_device_live_arp(const std::vector<LiveArpEntry>& rows) {
    if (rows.empty())
        return "<div class=\"gp-note\">ARP / neighbour table not available on this platform, "
               "or the table is empty.</div>";
    std::string h = "<table class=\"ls-tbl\"><thead><tr><th>Interface</th><th>IP</th><th>MAC</th>"
                    "<th>Type</th></tr></thead><tbody>";
    for (const auto& r : rows) {
        const char* cls = r.type == "static" ? "stat" : r.type == "incomplete" ? "inc" : "dyn";
        h += tr(lc(r.iface + " " + r.ip + " " + r.mac),
                {"<span class=\"name\">" + esc(r.iface) + "</span>", "<code>" + esc(r.ip) + "</code>",
                 r.mac.empty() ? "<span class=\"gp-mute\">-</span>" : "<code>" + esc(r.mac) + "</code>",
                 "<span class=\"ls-pill " + std::string(cls) + "\">" + esc(r.type) + "</span>"});
    }
    h += "</tbody></table>";
    return h;
}

std::string render_device_live_dns(const std::vector<LiveDnsEntry>& rows) {
    if (rows.empty())
        return "<div class=\"gp-note\">DNS cache empty, or this OS has no resolver cache to "
               "read (Windows-only).</div>";
    std::string h = "<input class=\"ls-search\" type=\"text\" placeholder=\"Search name\xE2\x80\xA6\" "
                    "oninput=\"lsFilterRows(this)\"><table class=\"ls-tbl\"><thead><tr><th>Name</th>"
                    "<th>Type</th></tr></thead><tbody>";
    for (const auto& r : rows)
        h += tr(lc(r.name + " " + r.record_type),
                {"<span class=\"name\">" + esc(r.name) + "</span>",
                 "<span class=\"ls-pill type\">" + esc(r.record_type) + "</span>"});
    h += "</tbody></table>";
    return h;
}

std::string render_device_live_listening(const std::vector<LiveListen>& rows) {
    if (rows.empty())
        return "<div class=\"gp-note\">No listening ports returned.</div>";
    std::string h = "<table class=\"ls-tbl\"><thead><tr><th>Proto</th><th>Local</th>"
                    "<th class=\"ls-num\">Port</th><th class=\"ls-num\">PID</th></tr></thead><tbody>";
    for (const auto& r : rows)
        h += "<tr><td>" + esc(r.proto) + "</td><td><code>" + esc(r.ip) +
             "</code></td><td class=\"ls-num\">" + std::to_string(r.port) +
             "</td><td class=\"ls-num\">" + std::to_string(r.pid) + "</td></tr>";
    h += "</tbody></table>";
    return h;
}

std::string render_device_live_connections(const std::vector<LiveConnRow>& rows) {
    if (rows.empty())
        return "<div class=\"gp-note\">No active connections returned.</div>";
    std::string h = "<table class=\"ls-tbl\"><thead><tr><th>Proto</th><th>Local</th><th>Remote</th>"
                    "<th>State</th></tr></thead><tbody>";
    for (const auto& r : rows) {
        const std::string st = r.state == "ESTABLISHED" || r.state == "ESTAB"
                                   ? "<span class=\"gp-ok\">" + esc(r.state) + "</span>"
                                   : "<span class=\"gp-mute\">" + esc(r.state) + "</span>";
        h += "<tr><td>" + esc(r.proto) + "</td><td><code>" + esc(r.local) + "</code></td><td><code>" +
             esc(r.remote) + "</code></td><td>" + st + "</td></tr>";
    }
    h += "</tbody></table>";
    return h;
}

std::string render_device_live_services(const std::vector<LiveService>& rows) {
    if (rows.empty())
        return "<div class=\"gp-note\">No services returned.</div>";
    std::string h = "<input class=\"ls-search\" type=\"text\" placeholder=\"Search service\xE2\x80\xA6\" "
                    "oninput=\"lsFilterRows(this)\"><table class=\"ls-tbl\"><thead><tr><th>Service</th>"
                    "<th>State</th><th>Startup</th></tr></thead><tbody>";
    for (const auto& r : rows) {
        const bool running = lc(r.status).find("run") != std::string::npos;
        const std::string st = running ? "<span class=\"gp-ok\">" + esc(r.status) + "</span>"
                                       : "<span class=\"gp-mute\">" + esc(r.status) + "</span>";
        const std::string label = r.display.empty() ? r.name : r.display;
        h += tr(lc(r.name + " " + r.display + " " + r.status),
                {"<span class=\"name\">" + esc(label) + "</span>", st,
                 "<span class=\"gp-mute\">" + esc(r.startup) + "</span>"});
    }
    h += "</tbody></table>";
    return h;
}

std::string render_device_live_users(const std::vector<LiveUserRow>& rows) {
    if (rows.empty())
        return "<div class=\"gp-note\">No logged-in users returned.</div>";
    std::string h = "<table class=\"ls-tbl\"><thead><tr><th>User</th><th>Host</th><th>Logon</th>"
                    "<th>Session</th></tr></thead><tbody>";
    for (const auto& r : rows)
        h += "<tr><td class=\"name\">" + esc(r.user) + "</td><td>" +
             (r.host.empty() ? "<span class=\"gp-mute\">&mdash;</span>" : esc(r.host)) + "</td><td>" +
             (r.logon_type.empty() ? "<span class=\"gp-mute\">&mdash;</span>" : esc(r.logon_type)) +
             "</td><td class=\"gp-mute\">" + (r.session.empty() ? "&mdash;" : esc(r.session)) +
             "</td></tr>";
    h += "</tbody></table>";
    return h;
}

std::string render_device_live_netconfig(const std::vector<LiveNetAddr>& rows) {
    if (rows.empty())
        return "<div class=\"gp-note\">No IP addresses returned.</div>";
    std::string h = "<table class=\"ls-tbl\"><thead><tr><th>Adapter</th><th>IP address</th>"
                    "<th class=\"ls-num\">/</th><th>Gateway</th></tr></thead><tbody>";
    for (const auto& r : rows)
        h += "<tr><td class=\"name\">" + esc(r.adapter) + "</td><td><code>" + esc(r.ip) +
             "</code></td><td class=\"ls-num\">" + std::to_string(r.prefix) + "</td><td>" +
             (r.gateway.empty() ? "<span class=\"gp-mute\">&mdash;</span>"
                                : "<code>" + esc(r.gateway) + "</code>") +
             "</td></tr>";
    h += "</tbody></table>";
    return h;
}

std::string render_device_live_disk(const std::vector<LiveDiskVolume>& rows) {
    if (rows.empty())
        return "<div class=\"gp-note\">No volume reported (the path may not exist on this "
               "device).</div>";
    // Bytes → "NN.N GiB" / "NN.N TiB" for display only (raw bytes stay on the wire).
    auto human = [](long long b) {
        if (b < 0) b = 0;
        const char* unit[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB"};
        double v = static_cast<double>(b);
        int i = 0;
        while (v >= 1024.0 && i < 5) { v /= 1024.0; ++i; }
        // Two literal format strings — std::format needs a consteval format arg.
        return i == 0 ? std::format("{:.0f} {}", v, unit[i])
                      : std::format("{:.1f} {}", v, unit[i]);
    };
    // < 5 GiB free latches red even below 90% used — the same threshold SHAPE the
    // storage.low DEX signal uses (>= 90% used OR < 5 GiB free; dex_win_poll). Note
    // this aligns the *thresholds*, not necessarily the *inputs*: the plugin's free
    // is caller-quota (Windows FreeBytesAvailableToCaller / POSIX f_bavail), so under
    // a per-user NTFS/FSRM quota it can read below storage.low's volume-wide basis.
    constexpr long long kLowFreeBytes = 5LL * 1024 * 1024 * 1024;
    std::string h = "<table class=\"ls-tbl\"><thead><tr><th>Volume</th>"
                    "<th class=\"ls-num\">Size</th><th class=\"ls-num\">Free</th>"
                    "<th>Used</th></tr></thead><tbody>";
    for (const auto& r : rows) {
        int pct = r.percent_used;
        if (pct < 0) pct = 0;
        if (pct > 100) pct = 100;
        std::string used_cell;
        if (r.total <= 0) {
            // Unmeasured volume (f_frsize==0 / unreadable / forged) — never render
            // a "0% used / 100% free" green bar off a row we couldn't measure.
            used_cell = "<span class=\"gp-mute\">&mdash;</span>";
        } else {
            const char* tone =
                (pct >= 90 || r.free < kLowFreeBytes) ? "bad" : pct >= 75 ? "warn" : "ok";
            used_cell = "<div class=\"ls-bar ls-bar-" + std::string(tone) +
                        "\"><span style=\"width:" + std::to_string(pct) +
                        "%\"></span></div><span class=\"ls-barlbl\">" + std::to_string(pct) + "%</span>";
        }
        h += "<tr><td class=\"name\"><code>" + esc(r.path) + "</code></td><td class=\"ls-num\">" +
             esc(human(r.total)) + "</td><td class=\"ls-num\">" + esc(human(r.free)) + "</td><td>" +
             used_cell + "</td></tr>";
    }
    h += "</tbody></table>";
    return h;
}

/// Generic table renderer backing the 10 round-3 item 11 "physical-kit" live-info
/// kinds (disks, memory, processors, drivers, battery, thermal, disk health,
/// volumes, network adapters, Wi-Fi) added via a data-only LiveKind.columns /
/// .row_prefix extension in live_kinds.hpp — no per-kind bespoke renderer needed
/// since the wire shape is uniform pipe-delimited rows whose field order already
/// matches the declared column order. Parsing/prefix filtering happens in
/// device_routes.cpp's render_live_result, NOT here — this function is pure over
/// already-parsed rows, matching every other render_device_live_* function in
/// this file. `raw_rows` are lines that did NOT match the kind's row_prefix
/// (e.g. a plugin-emitted "warning|..."/"error|..." diagnostic alongside its
/// data rows) — preserved verbatim rather than silently dropped, rendered as
/// their own full-width diagnostic row at the end of the table body, muted via
/// this file's established `gp-mute` convention for a diagnostic/placeholder
/// cell (see e.g. dex_perf_ui.cpp / dex_app_perf_ui.cpp's `colspan` + `gp-mute`
/// "n too small" rows) rather than inventing a new one.
std::string render_device_live_generic(const std::vector<std::string>& columns,
                                       const std::vector<std::vector<std::string>>& rows,
                                       const std::vector<std::string>& raw_rows) {
    if (rows.empty() && raw_rows.empty())
        return "<div class=\"gp-note\">Not available on this platform, or the table is empty.</div>";
    const std::string colspan = std::to_string(columns.size());
    std::string h = "<table class=\"ls-tbl\"><thead><tr>";
    for (const auto& c : columns) h += "<th>" + esc(column_label(c)) + "</th>";
    h += "</tr></thead><tbody>";
    for (const auto& row : rows) {
        h += "<tr>";
        for (const auto& cell : row)
            h += "<td>" + (cell.empty() ? "<span class=\"gp-mute\">&mdash;</span>" : esc(cell)) + "</td>";
        h += "</tr>";
    }
    for (const auto& raw : raw_rows)
        h += "<tr class=\"ls-raw\"><td colspan=\"" + colspan + "\" class=\"gp-mute\">" + esc(raw) +
             "</td></tr>";
    h += "</tbody></table>";
    return h;
}

std::string render_device_live_capture_sources(const std::vector<LiveCaptureSource>& rows) {
    if (rows.empty())
        return "<div class=\"gp-note\">TAR is not running on this device, or it reported no "
               "capture sources.</div>";
    std::string h =
        "<div class=\"gp-note\" style=\"margin-top:0\">TAR warehouse capture on this device "
        "(background &middot; distinct from the live snapshot). Read-only here &mdash; "
        "<a href=\"/tar\" style=\"color:var(--accent)\">configure on TAR &rarr;</a></div>";
    h += "<table class=\"ls-tbl\"><thead><tr><th></th><th>Source</th><th>Table</th>"
         "<th class=\"ls-num\">Live rows</th><th>Category</th></tr></thead><tbody>";
    for (const auto& r : rows) {
        const std::string sw = "<span class=\"ls-sw" + std::string(r.enabled ? " on" : "") + "\"></span>";
        const std::string nm = "<span class=\"" + std::string(r.enabled ? "src-on" : "src-off") +
                               "\">" + esc(r.name) + "</span>";
        const std::string rows_cell = r.live_rows < 0
                                          ? "<span class=\"gp-mute\">&mdash;</span>"
                                          : std::to_string(r.live_rows);
        h += "<tr><td>" + sw + "</td><td>" + nm + "</td><td><code>$" + esc(r.dollar) +
             "_Live</code></td><td class=\"ls-num\">" + rows_cell +
             "</td><td><span class=\"ls-pill cat\">" + esc(r.category) + "</span></td></tr>";
    }
    h += "</tbody></table>";
    return h;
}

std::string render_device_guardian_lens(const std::string& agent_id,
                                        const std::vector<DeviceGuardRow>& guards, bool tabs) {
    std::string h = tabs ? device_lens_tabs("guardian", agent_id) : std::string();
    if (guards.empty()) {
        h += "<div class=\"gp-placeholder\"><b>No guards evaluated</b>No Guardian guards have been "
             "evaluated on this device yet.</div>";
        return h;
    }
    int compliant = 0;
    for (const auto& g : guards)
        if (g.state == "compliant")
            ++compliant;
    const int pct = static_cast<int>(100.0 * compliant / static_cast<double>(guards.size()) + 0.5);
    h += "<div class=\"gp-tiles\"><div class=\"gp-tile\"><div class=\"n " +
         std::string(pct >= 100 ? "good" : "warn") + "\">" + std::to_string(pct) +
         "%</div><div class=\"l\">Compliant</div><div class=\"sx\">" + std::to_string(compliant) +
         " of " + std::to_string(guards.size()) + " guards</div></div></div>";
    h += "<div class=\"gp-sech\">Guards on this device</div>";
    h += "<table class=\"gp-table\"><thead><tr><th>Guard</th><th>State</th><th>Last evaluated</th>"
         "</tr></thead><tbody>";
    for (const auto& g : guards)
        h += "<tr><td class=\"name\">" + esc(g.name) + "</td><td>" + guard_state_badge(g.state) +
             "</td><td class=\"gp-mute\">" + esc(g.updated_at) + "</td></tr>";
    h += "</tbody></table>";
    h += "<div class=\"gp-note\">Per-guard state from "
         "<span style=\"font-family:Consolas,monospace\">guardian_agent_rule_status</span>. "
         "Baseline grouping + a live re-evaluate are follow-ups.</div>";
    return h;
}

std::string render_device_page(const DeviceRow& d) {
    const std::string label = d.hostname.empty() ? d.agent_id : d.hostname;
    std::string h = "<a class=\"gp-back\" href=\"/devices\">&larr; Devices</a>";
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>" + esc(label) +
         "</h1></div><div class=\"gp-sub\">" + os_label(d.os) + "/" + esc(d.arch) + " &middot; " +
         status_cell(d.online) + " &middot; DEX experience " + score_badge(d.dex_score) +
         "</div></div>";
    // Cross-cutting live-info action — when the device is online, dispatch a live
    // read-only query to it and render the result. Reuses the existing, proven
    // /fragments/dex/device/perf path (GuaranteedState:Read + Execution:Execute,
    // audited dex.device.perf.query, machine-health $Perf query) — NO new dispatch
    // or surveillance surface; it inherits that gating. Offline → disabled.
    if (d.online) {
        const std::string e = url_encode(d.agent_id);
        h += "<div><button class=\"gp-btn\" hx-get=\"/fragments/device/live?id=" + e +
             "\" hx-target=\"#device-live\" hx-swap=\"innerHTML\">\xE2\x9A\xA1 Get live info</button>"
             " <span class=\"gp-mute\" style=\"font-size:.66rem\">device state + a live read-only "
             "query &middot; Execute-gated &middot; audited</span></div>";
    } else {
        h += "<div><button class=\"gp-btn\" disabled>\xE2\x9A\xA1 Get live info</button>"
             " <span class=\"gp-mute\" style=\"font-size:.66rem\">device offline</span></div>";
    }
    h += "</div>";                       // close gp-head
    h += "<div id=\"device-live\"></div>"; // live-snapshot mount (cross-lens)
    h += "<div id=\"device-lens\">" + render_device_info_fragment(d) + "</div>";
    return h;
}

std::string render_device_not_found(const std::string& agent_id) {
    return "<a class=\"gp-back\" href=\"/devices\">&larr; Devices</a>"
           "<div class=\"gp-placeholder\"><b>Device not found</b>No enrolled device with id " +
           esc(agent_id) + ".</div>";
}

std::string render_device_degraded(const std::string& agent_id) {
    return "<a class=\"gp-back\" href=\"/devices\">&larr; Devices</a>"
           "<div class=\"gp-placeholder\"><b>Device data unavailable</b>The device store is "
           "temporarily degraded &mdash; try again shortly (" +
           esc(agent_id) + ").</div>";
}

} // namespace yuzu::server
