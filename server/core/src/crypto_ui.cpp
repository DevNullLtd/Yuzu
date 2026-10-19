/// @file crypto_ui.cpp
/// /crypto renderers - PURE functions over the crypto seam DTOs (crypto_types.hpp). See
/// crypto_ui.hpp for the contract. The component CSS is inlined once with the full body (the
/// `.cry-*` namespace), the same self-contained-fragment-CSS precedent as inventory_ui.cpp's
/// `.inv-*`. A store degrade is a banner, never an empty table (an empty table reads as "no
/// library installed", the fail-open the authoritative-read rule forbids).

#include "crypto_ui.hpp"

#include "crypto_library_model.hpp"
#include "web_utils.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::crypto_html {

namespace {

constexpr const char* kEm = "\xE2\x80\x94"; // U+2014: unknown / not applicable
constexpr std::size_t kTopVersions = 4;

std::string esc(const std::string& s) { return html_escape(s); }

std::string dash() { return std::string("<span class=\"cry-grey\">") + kEm + "</span>"; }

// 1180 -> "1,180".
std::string fmt_int(std::int64_t n) {
    // Magnitude as unsigned: -INT64_MIN overflows int64.
    const std::uint64_t mag = n < 0 ? ~static_cast<std::uint64_t>(n) + 1 : static_cast<std::uint64_t>(n);
    std::string s = std::to_string(mag);
    for (auto i = static_cast<std::ptrdiff_t>(s.size()) - 3; i > 0; i -= 3)
        s.insert(static_cast<std::size_t>(i), ",");
    return n < 0 ? "-" + s : s;
}

// RFC 3986 unreserved bytes pass; everything else is %XX.
std::string url_encode(const std::string& s) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    for (const unsigned char c : s) {
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += kHex[c >> 4];
            out += kHex[c & 0x0F];
        }
    }
    return out;
}

std::string devices_url(const std::string& family, const std::optional<std::string>& version,
                        const std::optional<std::string>& ecosystem, const std::string& cursor) {
    std::string u = "/fragments/crypto/libraries/devices?family=" + url_encode(family);
    if (version)
        u += "&version=" + url_encode(*version);
    if (ecosystem) // present (even empty) is the exact ecosystem; a bucket chip always carries it
        u += "&ecosystem=" + url_encode(*ecosystem);
    if (!cursor.empty())
        u += "&cursor=" + url_encode(cursor);
    return u;
}

std::string style() {
    return R"css(<style>
  .cry-wrap>*+*{margin-top:22px}
  .cry-h1{margin:0;font-size:24px;font-weight:600;letter-spacing:-.015em;line-height:1.2;color:var(--ink)}
  .cry-sub{margin-top:4px;max-width:70ch;color:var(--mut)}
  .cry-wrap :focus-visible{outline:2px solid var(--focus);outline-offset:2px}
  .cry-panel{min-width:0;background:var(--surface);border:1px solid var(--line);border-radius:var(--rad-panel)}
  .cry-kpis{display:flex;flex-wrap:wrap;background:var(--surface);border:1px solid var(--line);border-radius:var(--rad-panel)}
  .cry-kpi{flex:1 1 170px;min-width:0;display:flex;flex-direction:column;padding:14px 18px;border-left:1px solid var(--line)}
  .cry-kpi:first-child{border-left:0}
  .cry-kpi .big{order:-2;font-size:26px;font-weight:500;letter-spacing:-.02em;line-height:1.15;color:var(--ink)}
  .cry-kpi .h{order:-1;margin-top:2px;font-size:13px;color:var(--mut)}
  .cry-kpi .s2{margin-top:4px;font-size:12.5px;color:var(--mut)}
  .cry-caveat,.cry-degrade{padding:12px 14px;border:1px solid var(--line2);border-radius:var(--rad-panel);background:var(--surface2);color:var(--ink2);font-size:13.5px}
  .cry-degrade{border-color:color-mix(in srgb,var(--bad) 50%,var(--line2))}.cry-degrade b{color:var(--bad)}
  .cry-btn{display:inline-flex;align-items:center;height:var(--ctl);padding:0 14px;border:1px solid var(--line2);border-radius:var(--rad-ctl);background:var(--raise);color:var(--ink);font:inherit;font-weight:500;white-space:nowrap;cursor:pointer}
  .cry-btn:hover{border-color:var(--mut);background:var(--surface2)}
  .cry-btn.pri{border-color:var(--primary);background:var(--primary);color:var(--on-primary);font-weight:600}.cry-btn.pri:hover{border-color:var(--primary-h);background:var(--primary-h)}
  .cry-degrade .cry-btn{margin-left:.6rem}
  .cry-link{padding:0;border:0;background:none;color:var(--primary);font:inherit;font-size:13px;cursor:pointer}.cry-link:hover{text-decoration:underline}
  .cry-tblwrap{overflow-x:auto}
  table.cry-tbl{width:100%;border-collapse:collapse}
  table.cry-tbl th{padding:8px 16px;border-bottom:1px solid var(--line);background:var(--surface2);color:var(--mut);font-size:12.5px;font-weight:500;text-align:left;white-space:nowrap}
  table.cry-tbl td{padding:var(--cell-y) 16px;border-bottom:1px solid var(--line);vertical-align:middle;color:var(--ink2)}
  table.cry-tbl tbody tr.click{cursor:pointer}
  table.cry-tbl tbody tr.click:hover>td{background:var(--surface2)}
  th.cry-num,td.cry-num{text-align:right;font-variant-numeric:tabular-nums}
  .cry-name{color:var(--ink);font-weight:600}
  .cry-grey{color:var(--mut)}
  .cry-mono{font-family:var(--mds-font-family-mono);font-size:12.5px}
  .cry-chip{display:inline-block;margin:2px 6px 2px 0;padding:0 8px;height:24px;line-height:22px;border:1px solid var(--line2);border-radius:var(--rad-ctl);background:var(--bg);color:var(--ink2);font-family:var(--mds-font-family-mono);font-size:12px;cursor:pointer}
  .cry-chip:hover{background:var(--surface2);color:var(--ink)}
  .cry-pill{display:inline-block;padding:0 5px;border:1px solid var(--line2);border-radius:3px;color:var(--mut);font-family:var(--mds-font-family-mono);font-size:11.5px}
  .cry-empty{padding:16px;color:var(--mut)}
  tr.cry-exp>td{padding:0;border-bottom:0}
  tr.cry-exp>td:has(>div:not(:empty)){border-bottom:1px solid var(--line)}
  .cry-drill{padding:12px 16px 14px;background:var(--bg)}
  .cry-close{float:right;color:var(--mut);cursor:pointer}.cry-close:hover{color:var(--ink)}
  .cry-devhead{display:flex;flex-wrap:wrap;gap:6px 10px;align-items:center;color:var(--mut)}.cry-devhead b{color:var(--ink);font-weight:600}
  table.cry-sub{margin-top:10px;background:var(--surface)}
  tr.cry-more td{padding:12px;text-align:center}
</style>)css";
}

std::string tile(const std::string& title, const std::string& big, const std::string& s2) {
    return "<div class=\"cry-kpi\"><div class=\"h\">" + title + "</div><div class=\"big\">" + big +
           "</div><div class=\"s2\">" + s2 + "</div></div>";
}

// The package NAMES' source: "Package names as of 2026-10-18 02:00 UTC" for the hourly
// catalogue (counts and versions for a listed name are live), "Package names read live" when
// the catalogue was not fresh. An out-of-range stamp (std::format of a year past 9999 is
// out of range) is skipped rather than rendered.
constexpr std::int64_t kMaxSaneAsOf = 253402300799; // 9999-12-31T23:59:59Z
std::string names_as_of_note(bool from_catalogue, std::int64_t as_of) {
    if (!from_catalogue)
        return "<div class=\"cry-caveat\">Package names read live from the inventory; counts "
               "and versions are live.</div>";
    if (as_of <= 0 || as_of > kMaxSaneAsOf)
        return {};
    const auto t = std::chrono::sys_seconds{std::chrono::seconds{as_of}};
    return "<div class=\"cry-caveat\">Package names as of " +
           esc(std::format("{:%Y-%m-%d %H:%M} UTC", t)) +
           ". A package name first reported after this time appears after the next hourly "
           "refresh; counts and versions for listed names are live.</div>";
}

std::string caveat_box() {
    return "<div class=\"cry-caveat\">" + esc(std::string(kEvidenceCaveat)) + "</div>";
}

std::string version_label(const std::string& v) {
    return v.empty() ? std::string("(unknown)") : v;
}

std::string family_rows(const CryptoSummary& s) {
    std::string h;
    for (const auto& f : s.families) {
        const std::string box = drill_box_id(f.id);
        const std::string durl = devices_url(f.id, std::nullopt, std::nullopt, "");
        std::string chips;
        const std::size_t shown = std::min(f.versions.size(), kTopVersions);
        for (std::size_t i = 0; i < shown; ++i) {
            const auto& v = f.versions[i];
            // A version bucket is (version, ecosystem); the chip drills into exactly that.
            chips += "<span class=\"cry-chip\" onclick=\"event.stopPropagation()\" hx-get=\"" +
                     esc(devices_url(f.id, v.version, v.ecosystem, "")) + "\" hx-target=\"#" +
                     box + "\" hx-swap=\"innerHTML\" title=\"" + esc(v.ecosystem) + " &middot; " +
                     fmt_int(v.device_count) + " devices\">" + esc(version_label(v.version)) +
                     "</span>";
        }
        if (f.versions.empty())
            chips = f.versions_truncated ? "<span class=\"cry-grey\">versions not shown</span>"
                                         : dash();
        else if (f.versions_truncated || f.versions.size() > shown)
            chips += "<span class=\"cry-grey\">+more</span>";
        h += "<tr class=\"click\" title=\"Click for the devices carrying this family\" hx-get=\"" +
             esc(durl) + "\" hx-target=\"#" + box + "\" hx-swap=\"innerHTML\"><td class=\"cry-name\">" +
             esc(f.display.empty() ? f.id : f.display) + "</td><td class=\"cry-num\">" +
             fmt_int(f.device_count) + "</td><td class=\"cry-num\">" +
             fmt_int(static_cast<std::int64_t>(f.versions.size())) + "</td><td>" + chips +
             "</td></tr><tr class=\"cry-exp\"><td colspan=\"4\"><div id=\"" + box +
             "\"></div></td></tr>";
    }
    return h;
}

std::string device_rows(const CryptoDevicesPage& p) {
    std::string h;
    for (const auto& d : p.devices) {
        h += "<tr><td>" + (d.hostname.empty() ? dash() : "<b>" + esc(d.hostname) + "</b>") +
             " <span class=\"cry-mono cry-grey\">" + esc(d.agent_id) + "</span></td>"
             "<td class=\"cry-mono\">" + esc(d.package_name) + "</td><td class=\"cry-mono\">" +
             (d.version.empty() ? dash() : esc(d.version)) + "</td><td class=\"cry-mono\">" +
             (d.release.empty() ? dash() : esc(d.release)) + "</td><td>" +
             (d.ecosystem.empty() ? dash()
                                  : "<span class=\"cry-pill\">" + esc(d.ecosystem) + "</span>") +
             "</td><td class=\"cry-grey\">" + (d.kind.empty() ? dash() : esc(d.kind)) +
             "</td></tr>";
    }
    return h;
}

std::string more_row(const CryptoDevicesQuery& q, const CryptoDevicesPage& p) {
    if (p.next_cursor.empty())
        return {};
    return "<tr class=\"cry-more\"><td colspan=\"6\"><button type=\"button\" class=\"cry-btn pri\" "
           "hx-get=\"" +
           esc(devices_url(q.family, q.version, q.ecosystem, p.next_cursor)) +
           "\" hx-target=\"closest tr\" hx-swap=\"outerHTML\" hx-disabled-elt=\"this\">Load more "
           "devices</button></td></tr>";
}

} // namespace

std::string render_libraries(const CryptoSummary& s) {
    std::string h = style();
    h += "<div class=\"cry-wrap\"><h1 class=\"cry-h1\">Crypto</h1><div class=\"cry-sub\">Which "
         "cryptographic libraries are installed across the fleet, from the daily-synced "
         "installed-software inventory (ADR-0016), matched by package name against a curated "
         "table (version " +
         std::to_string(crypto_library::kCryptoTableVersion) +
         "). Presence and versions only.</div>";
    h += "<div class=\"cry-kpis\">" +
         tile("Devices reporting inventory", fmt_int(s.coverage.devices_reporting_inventory),
              "in your visible scope") +
         tile("Devices with a crypto library", fmt_int(s.coverage.devices_with_crypto_library),
              "carrying at least one matched package") +
         tile("Families matched", fmt_int(static_cast<std::int64_t>(s.families.size())),
              "of " + std::to_string(crypto_library::families().size()) + " in the table") +
         "</div>";
    if (s.result_truncated)
        h += "<div class=\"cry-caveat\">The version list was capped (row or size limit), so "
             "some version rows are not shown. Family device counts are unaffected.</div>";
    if (s.families.empty()) {
        h += "<div class=\"cry-panel cry-empty\">No matching package rows in your visible "
             "inventory. This is not proof that no library is present: statically linked, "
             "vendored and OS-bundled copies are invisible here.</div>";
    } else {
        h += "<div class=\"cry-panel cry-tblwrap\"><table class=\"cry-tbl\"><thead><tr>"
             "<th>Family</th><th class=\"cry-num\">Devices</th><th class=\"cry-num\">Versions</th>"
             "<th>Top versions</th></tr></thead><tbody>" +
             family_rows(s) + "</tbody></table></div>";
    }
    h += caveat_box() + names_as_of_note(s.names_from_catalogue, s.names_as_of) + "</div>";
    return h;
}

std::string render_devices(const CryptoDevicesQuery& q, const CryptoDevicesPage& p,
                           bool continuation) {
    if (continuation)
        return device_rows(p) + more_row(q, p);
    std::string h = "<div class=\"cry-drill\"><span class=\"cry-close\" role=\"button\" "
                    "tabindex=\"0\" onclick=\"this.parentNode.parentNode.innerHTML=''\">close "
                    "&times;</span><div class=\"cry-devhead\"><b>";
    const auto* fam = crypto_library::find_family(p.family);
    h += esc(fam ? std::string(fam->display) : p.family) + "</b>";
    if (p.version)
        h += "<span>version <b>" + esc(version_label(*p.version)) + "</b></span>";
    if (q.ecosystem)
        h += "<span>ecosystem <b>" + esc(version_label(*q.ecosystem)) + "</b></span>";
    h += "<span>&middot; " + fmt_int(static_cast<std::int64_t>(p.devices.size())) +
         " rows on this page</span></div>";
    // An empty page that still carries a cursor (every row of it was dropped by the defensive
    // re-classification) must still offer the next page.
    if (p.devices.empty() && p.next_cursor.empty()) {
        h += "<div class=\"cry-empty\">No matching package rows in your visible inventory.</div>";
    } else {
        h += "<div class=\"cry-tblwrap\"><table class=\"cry-tbl cry-sub\"><thead><tr>"
             "<th>Device</th><th>Package</th><th>Version</th><th>Release</th><th>Ecosystem</th>"
             "<th>Kind</th></tr></thead><tbody>" +
             device_rows(p) + more_row(q, p) + "</tbody></table></div>";
    }
    return h + "</div>";
}

namespace {
// The access gate (authz_gates.cpp require_fleet_read) answers 503 when any store it reads is
// unavailable or degraded: the RBAC/permission store, the management-group store, or the tag
// store for a service-scoped token. One sentence for every surface that names it.
constexpr std::string_view kAccessCheckReason =
    "The access check could not be completed: one of its stores (permissions, management "
    "groups or tags) could not be read.";

// The banner reason, per cause. Exhaustive over CryptoReadCause, no default: a new cause must
// choose its wording here.
std::string unavailable_reason(CryptoReadCause cause) {
    std::string reason;
    switch (cause) {
    case CryptoReadCause::kCapacity:
        reason = "Temporarily busy: two reads are already running on this server; retry "
                 "shortly. This is <b>not</b> \"no library installed\".";
        break;
    case CryptoReadCause::kAccessCheck:
        reason = std::string(kAccessCheckReason) +
                 " This is <b>not</b> \"no library installed\" and not a refusal.";
        break;
    case CryptoReadCause::kNone:
    case CryptoReadCause::kStoreDegraded:
        reason = "The inventory store could not be read (Postgres pool/query degraded). This is "
                 "<b>not</b> \"no library installed\": reads here are authoritative, so this "
                 "banner is shown instead of an empty table.";
        break;
    }
    return reason;
}
} // namespace

std::string drill_box_id(std::string_view family) {
    return "cry-exp-" + url_encode(std::string(family));
}

std::string render_audit_notice() {
    return "<div class=\"cry-degrade\" role=\"status\"><b>Audit not recorded.</b> " +
           esc(std::string(kAuditNotPersistedNotice)) + "</div>";
}

std::string render_audit_notice_row() {
    return "<tr class=\"cry-more\"><td colspan=\"6\">" + render_audit_notice() + "</td></tr>";
}

std::string render_unavailable(std::string_view what, CryptoReadCause cause) {
    return "<div class=\"cry-degrade\"><b>" + esc(std::string(what)) + " unavailable.</b> " +
           unavailable_reason(cause) +
           " <button type=\"button\" class=\"cry-btn\" hx-get=\"/fragments/crypto/libraries\" "
           "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">Retry</button></div>";
}

std::string render_summary_unavailable(std::string_view what, CryptoReadCause cause,
                                       bool audit_lost) {
    // An unavailable summary answer replaces the whole page body, so it carries the component CSS
    // itself (render_libraries and render_summary_caveat are the only other emitters, and a
    // response holds exactly one of the three), else `.cry-degrade` renders unstyled on a failed
    // first load.
    return style() + (audit_lost ? render_audit_notice() : std::string{}) +
           render_unavailable(what, cause);
}

std::string render_unavailable_drill(std::string_view what, const CryptoDevicesQuery& q,
                                     CryptoReadCause cause) {
    // A first page carries no cursor: Retry re-requests this drill, not a continuation.
    return "<div class=\"cry-degrade\"><b>" + esc(std::string(what)) + " unavailable.</b> " +
           unavailable_reason(cause) + " <button type=\"button\" class=\"cry-btn\" hx-get=\"" +
           esc(devices_url(q.family, q.version, q.ecosystem, "")) + "\" hx-target=\"#" +
           drill_box_id(q.family) + "\" hx-swap=\"innerHTML\">Retry</button></div>";
}

std::string render_caveat(std::string_view message) {
    return "<div class=\"cry-caveat\">" + esc(std::string(message)) + "</div>";
}

std::string render_summary_caveat(std::string_view message) {
    // The summary's note answer replaces the whole page body too: same once-only CSS rule as
    // render_summary_unavailable.
    return style() + render_caveat(message);
}

std::string devices_page_url(const CryptoDevicesQuery& q) {
    return devices_url(q.family, q.version, q.ecosystem, q.cursor);
}

std::string render_unavailable_row(std::string_view what, std::string_view retry_url,
                                   CryptoReadCause cause) {
    std::string reason;
    switch (cause) {
    case CryptoReadCause::kCapacity:
        reason = "Temporarily busy: two reads are already running on this server; retry "
                 "shortly. This is <b>not</b> \"no more devices\".";
        break;
    case CryptoReadCause::kAccessCheck:
        reason = std::string(kAccessCheckReason) + " This is <b>not</b> \"no more devices\".";
        break;
    case CryptoReadCause::kNone:
    case CryptoReadCause::kStoreDegraded:
        reason = "The inventory store could not be read. This is <b>not</b> \"no more devices\".";
        break;
    }
    return "<tr class=\"cry-more\"><td colspan=\"6\"><div class=\"cry-degrade\"><b>" +
           esc(std::string(what)) + " unavailable.</b> " + reason +
           " <button type=\"button\" class=\"cry-btn\" hx-get=\"" + esc(std::string(retry_url)) +
           "\" hx-target=\"closest tr\" hx-swap=\"outerHTML\">Retry</button></div></td></tr>";
}

std::string render_caveat_row(std::string_view message) {
    return "<tr class=\"cry-more\"><td colspan=\"6\"><div class=\"cry-caveat\">" +
           esc(std::string(message)) + "</div></td></tr>";
}


// ── The widget dashboard (ADR-0070 D13) ──────────────────────────────────────

namespace {

namespace cw = crypto_widgets;

constexpr std::string_view kDrillPanelId = "cry-drill";
constexpr std::string_view kGridId = "cry-grid";

// The dashboard's own component CSS, appended to style(). Neutral tokens only (D13 condition
// 5): the big numbers are --ink, never a grading colour. Cards wrap to one column at phone
// width (auto-fill with a 220px floor); a wide card (bar, line, table) spans the whole row at
// every width (1 / -1), so it never forces an implicit second column.
std::string dash_style() {
    return R"css(<style>
  .cry-toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
  .cry-toolbar select{min-width:0;max-width:100%;height:var(--ctl);padding:0 10px;border:1px solid var(--line2);border-radius:var(--rad-ctl);background:var(--raise);color:var(--ink);font:inherit}
  .cry-err{padding:10px 14px;border:1px solid color-mix(in srgb,var(--bad) 50%,var(--line2));border-radius:var(--rad-panel);background:var(--surface2);color:var(--ink2);font-size:13.5px}
  .cry-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px}
  .cry-card{min-width:0;display:flex;flex-direction:column;padding:12px 14px;background:var(--surface);border:1px solid var(--line);border-radius:var(--rad-panel)}
  .cry-card.wide{grid-column:1/-1}
  .cry-card-h{display:flex;gap:8px;align-items:flex-start;justify-content:space-between}
  .cry-card-t{min-width:0;color:var(--ink);font-weight:600;font-size:14px;line-height:1.3}
  .cry-tools{display:flex;flex:none;gap:2px}
  .cry-ico{width:26px;height:26px;padding:0;border:1px solid transparent;border-radius:var(--rad-ctl);background:none;color:var(--mut);font:inherit;font-size:14px;line-height:1;cursor:pointer}
  .cry-ico:hover:not(:disabled){border-color:var(--line2);background:var(--surface2);color:var(--ink)}
  .cry-ico:disabled{opacity:.35;cursor:default}
  .cry-crit{margin-top:4px;color:var(--mut);font-size:12.5px;line-height:1.35}
  .cry-tag{align-self:flex-start;margin-top:6px;padding:0 6px;border:1px solid var(--line2);border-radius:3px;color:var(--mut);font-size:11.5px}
  .cry-slot{margin-top:10px;min-width:0}
  .cry-numbtn{display:block;padding:0;border:0;background:none;color:var(--ink);font:inherit;font-size:30px;font-weight:500;letter-spacing:-.02em;line-height:1.15;font-variant-numeric:tabular-nums;cursor:pointer;text-align:left}
  .cry-numbtn:hover{text-decoration:underline}
  .cry-asof{margin-top:6px;color:var(--mut);font-size:12px}
  .cry-chart{width:100%;height:240px}
  .cry-loading{color:var(--mut);font-size:13px}
  #cry-drill:empty{display:none}
  .cry-card .cry-caveat,.cry-card .cry-degrade{padding:8px 10px;font-size:12.5px}
  .cry-card table.cry-tbl th,.cry-card table.cry-tbl td{padding-left:10px;padding-right:10px}
  .cry-scope{margin:4px 0 0;color:var(--ink2);font-size:13px}
  .cry-buckets{display:flex;flex-wrap:wrap;gap:14px}
  .cry-bucket{min-width:0}
  .cry-bucket .cry-numbtn{font-size:24px}
  .cry-blabel{color:var(--mut);font-size:12px}
</style>)css";
}

std::string fmt_time(std::int64_t epoch) {
    if (epoch <= 0)
        return dash();
    if (epoch > kMaxSaneAsOf)
        return esc(std::to_string(epoch));
    const auto t = std::chrono::sys_seconds{std::chrono::seconds{epoch}};
    return esc(std::format("{:%Y-%m-%d %H:%M} UTC", t));
}

std::string perm_label(const cw::Widget& w) {
    return std::string(w.securable) + ":" + std::string(w.operation);
}

bool is_wide(const cw::Widget& w) { return w.kind != cw::WidgetKind::kNumber; }

// The id of a card's data slot; catalogue ids are [a-z0-9._] but are encoded anyway.
std::string slot_id(std::string_view id) { return "cry-w-" + url_encode(std::string(id)); }

// A drill trigger's data attributes: the cryDash helper reads them, so no data is ever written
// into a JavaScript string.
std::string drill_attrs(const std::string& url, const std::string& box = {}) {
    std::string a = " data-url=\"" + esc(url) + "\"";
    if (!box.empty())
        a += " data-box=\"" + esc(box) + "\"";
    return a + " onclick=\"cryDash.drill(this)\"";
}

std::string number_button(std::int64_t n, const std::string& url, const std::string& box,
                          std::string_view hint) {
    return "<button type=\"button\" class=\"cry-numbtn\" title=\"" + esc(std::string(hint)) + "\"" +
           drill_attrs(url, box) + ">" + fmt_int(n) + "</button>";
}

// An inline chart: the host element and the script that renders it through window.YuzuCharts
// (via cryDash.chart, which also binds the click drill). Never autoRender.
std::string chart_block(std::string_view widget_id, const nlohmann::json& data) {
    const std::string id = "cry-chart-" + url_encode(std::string(widget_id));
    return "<div class=\"cry-chart\" id=\"" + esc(id) + "\"></div><script>cryDash.chart(" +
           script_json(nlohmann::json(id)) + "," + script_json(data) + ");</script>";
}

std::string retry_button(const std::string& url, std::string_view target) {
    return " <button type=\"button\" class=\"cry-btn\" hx-get=\"" + esc(url) + "\" hx-target=\"" +
           esc(std::string(target)) + "\" hx-swap=\"" +
           (target == "closest tr" ? "outerHTML" : "innerHTML") + "\">Retry</button>";
}

constexpr std::string_view kNoLibraryRows =
    "No matching package rows in your visible inventory. This is not proof that no library is "
    "present: statically linked, vendored and OS-bundled copies are invisible here.";

std::string truncation_note(const CryptoSummary& s) {
    if (!s.result_truncated)
        return {};
    return "<div class=\"cry-caveat\">The version list was capped (row or size limit), so some "
           "version rows are not shown. Family device counts are unaffected.</div>";
}

std::string ca_asof(std::int64_t as_of) {
    return "<div class=\"cry-asof\" title=\"" + esc(std::string(cw::kWindowEdgeNote)) +
           "\">as of " + fmt_time(as_of) + " (database clock) &middot; window set " +
           esc(std::string(cw::kWindowSetVersion)) + "</div>";
}

std::string scope_line() {
    return "<div class=\"cry-scope\">" + esc(std::string(cw::kScopeNote)) + "</div>";
}

std::int64_t window_count(const std::vector<CaWindowCount>& v, int days) {
    for (const auto& c : v)
        if (c.days == days)
            return c.count;
    return -1;
}

const CaRevokedWindow* revoked_window(const std::vector<CaRevokedWindow>& v, int days) {
    for (const auto& c : v)
        if (c.days == days)
            return &c;
    return nullptr;
}

std::int64_t bucket_count(const CaRevokedWindow& r, RevokedBucket b) {
    switch (b) {
    case RevokedBucket::kSuperseded:
        return r.superseded;
    case RevokedBucket::kUnpublished:
        return r.unpublished;
    case RevokedBucket::kOther:
        break;
    }
    return r.other;
}

std::int64_t week_bucket(const CaWeekCount& w, RevokedBucket b) {
    switch (b) {
    case RevokedBucket::kSuperseded:
        return w.revoked_superseded;
    case RevokedBucket::kUnpublished:
        return w.revoked_unpublished;
    case RevokedBucket::kOther:
        break;
    }
    return w.revoked_other;
}

std::string ca_certs_note_reason(CryptoReadCause cause) {
    switch (cause) {
    case CryptoReadCause::kCapacity:
        return "Busy: too many crypto reads are in progress on this server; retry shortly. This "
               "is <b>not</b> a count of zero.";
    case CryptoReadCause::kAccessCheck:
        return "The access check could not be completed: the permission store could not be read. "
               "This is <b>not</b> a refusal and not a count of zero.";
    case CryptoReadCause::kNone:
    case CryptoReadCause::kStoreDegraded:
        break;
    }
    return "Database degraded: Yuzu's certificate store could not be read (Postgres pool or "
           "query failed, or the internal CA is not configured). This is <b>not</b> a count of "
           "zero.";
}

std::string ca_rows(const CaCertPage& p) {
    std::string h;
    for (const auto& r : p.rows) {
        h += "<tr><td class=\"cry-mono\">" + (r.serial_hex.empty() ? dash() : esc(r.serial_hex)) +
             "</td><td>" + (r.subject.empty() ? dash() : esc(r.subject)) + "</td><td>" +
             (r.purpose.empty() ? dash() : esc(r.purpose)) + "</td><td>" + fmt_time(r.issued_at) +
             "</td><td>" + fmt_time(r.not_after) + "</td><td>" +
             (r.status.empty() ? dash() : esc(r.status)) + "</td><td>" +
             fmt_time(r.revoked_at) + "</td><td>" +
             (r.revocation_reason.empty() ? dash() : esc(r.revocation_reason)) + "</td></tr>";
    }
    return h;
}

std::string ca_more_row(const CaCertPage& p) {
    if (!p.truncated || p.rows.empty())
        return {};
    // The next page pins the as_of this page was read at, so the walk is one snapshot and its
    // total equals the count that led to it.
    CaCertQuery next = p.query;
    next.offset = p.query.offset + static_cast<int>(p.rows.size());
    next.as_of = p.as_of;
    if (next.offset > cw::kCertOffsetMax)
        return {};
    return "<tr class=\"cry-more\"><td colspan=\"8\"><button type=\"button\" class=\"cry-btn pri\" "
           "hx-get=\"" +
           esc(ca_certificates_url(next)) +
           "\" hx-target=\"closest tr\" hx-swap=\"outerHTML\" hx-disabled-elt=\"this\">Load more "
           "certificates</button></td></tr>";
}

std::string week_label_of(const CaCertQuery& q) {
    return cw::kind_takes_week(q.kind) ? cw::iso_week_label(q.week_start) : std::string{};
}

} // namespace

std::string script_json(const nlohmann::json& j) {
    const std::string raw = j.dump(-1, ' ', /*ensure_ascii=*/true,
                                   nlohmann::json::error_handler_t::replace);
    std::string out;
    out.reserve(raw.size());
    for (const char c : raw) {
        switch (c) {
        case '<':
            out += "\\u003c";
            break;
        case '>':
            out += "\\u003e";
            break;
        case '&':
            out += "\\u0026";
            break;
        default:
            out += c;
        }
    }
    return out;
}

std::string widget_url(std::string_view id) {
    return "/fragments/crypto/widget/" + url_encode(std::string(id));
}

std::string ca_certificates_url(const CaCertQuery& q) {
    std::string u = "/fragments/crypto/ca/certificates?kind=" +
                    url_encode(std::string(cw::ca_kind_name(q.kind)));
    if (cw::kind_takes_days(q.kind))
        u += "&days=" + std::to_string(q.days);
    if (cw::kind_takes_week(q.kind))
        u += "&week=" + url_encode(cw::iso_week_label(q.week_start));
    if (q.bucket)
        u += "&bucket=" + url_encode(std::string(cw::bucket_name(*q.bucket)));
    if (q.as_of)
        u += "&as_of=" + std::to_string(*q.as_of);
    if (q.limit != cw::kCertPageDefault)
        u += "&limit=" + std::to_string(q.limit);
    if (q.offset > 0)
        u += "&offset=" + std::to_string(q.offset);
    return u;
}

std::string dashboard_head_html() {
    // The cryDash helper. Every handler is reached from a plain onclick (the CSP blocks hx-on);
    // data reaches it only through data-* attributes and JSON, never a built JS string. The
    // layout version the page was drawn with rides on #cry-grid-wrap (data-version) and goes
    // back as expected_version on every save, so a save from a stale tab is refused (409).
    return R"html(<script src="/static/echarts.min.js"></script>
<script src="/static/yuzu-charts.js"></script>
<script>
window.cryDash = (function () {
  'use strict';
  function byId(id) { return document.getElementById(id); }
  function wrap() { return byId('cry-grid-wrap'); }
  function ids() {
    var g = byId('cry-grid');
    if (!g) return [];
    var out = [];
    for (var i = 0; i < g.children.length; i++) {
      var w = g.children[i].getAttribute('data-wid');
      if (w) out.push(w);
    }
    return out;
  }
  function version() {
    var w = wrap();
    var v = w ? parseInt(w.getAttribute('data-version') || '0', 10) : 0;
    return isNaN(v) ? 0 : v;
  }
  function showErr(msg) {
    var e = byId('cry-dash-err');
    if (!e) return;
    e.textContent = msg || '';
    e.hidden = !msg;
  }
  function releaseCharts() {
    var m = byId('guardian-detail');
    if (m && window.YuzuCharts && window.YuzuCharts.dispose) window.YuzuCharts.dispose(m);
  }
  function reload(after) {
    releaseCharts();
    var p = htmx.ajax('GET', '/fragments/crypto/dashboard', { target: '#guardian-detail', swap: 'innerHTML' });
    if (after && p && p.then) p.then(function () { showErr(after); });
  }
  function save(list, expected) {
    showErr('');
    var body = { widgets: list, expected_version: expected === undefined ? version() : expected };
    return fetch('/api/v1/crypto/dashboard/layout', {
      method: 'PUT', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(body)
    }).then(function (r) {
      return r.json().catch(function () { return null; }).then(function (j) {
        if (r.ok) {
          var lost = j && j.data && j.data.audit_persisted === false;
          reload(lost ? 'The layout was saved, but the change could not be recorded in the audit log.' : '');
          return;
        }
        var m = (j && j.error && j.error.message) ? j.error.message : ('HTTP ' + r.status);
        if (r.status === 409) { reload('The layout changed in another tab — reloaded. Make your change again.'); return; }
        if (r.status === 422) { reload(''); return; }
        if (r.status === 503 && m.indexOf('save outcome unknown') === 0) {
          reload('The save outcome is unknown — reloaded to show what is stored.');
          return;
        }
        showErr('The layout was not saved: ' + m);
      });
    }).catch(function (e) { showErr('The layout was not saved: ' + e); });
  }
  function cardId(el) {
    var c = el && el.closest('[data-wid]');
    return c ? c.getAttribute('data-wid') : null;
  }
  function open(url, box) {
    var p = byId('cry-drill');
    if (!p || !url) return;
    if (window.YuzuCharts && window.YuzuCharts.dispose) window.YuzuCharts.dispose(p);
    p.innerHTML = '';
    var slot = document.createElement('div');
    slot.className = 'cry-slot';
    if (box) slot.id = box;
    p.appendChild(slot);
    htmx.ajax('GET', url, { target: slot, swap: 'innerHTML' });
    if (p.scrollIntoView) p.scrollIntoView({ block: 'nearest' });
  }
  return {
    add: function () {
      var s = byId('cry-add');
      if (!s || !s.value) { showErr('Choose a widget to add.'); return; }
      var l = ids();
      l.push(s.value);
      save(l);
    },
    remove: function (el) {
      var w = cardId(el);
      save(ids().filter(function (x) { return x !== w; }));
    },
    move: function (el, d) {
      var l = ids(), i = l.indexOf(cardId(el)), j = i + d;
      if (i < 0 || j < 0 || j >= l.length) return;
      var t = l[i]; l[i] = l[j]; l[j] = t;
      save(l);
    },
    // Reset PUTs the default list. On a corrupt stored layout the button carries the corrupt
    // row's version (data-version), which is what the store accepts to replace it.
    reset: function (el) {
      var d = el.getAttribute('data-default') || '';
      var v = el.getAttribute('data-version');
      save(d ? d.split(' ') : [], v === null ? undefined : parseInt(v, 10));
    },
    drill: function (el) { open(el.getAttribute('data-url'), el.getAttribute('data-box')); },
    chart: function (id, data) {
      var el = byId(id);
      if (!el || !window.YuzuCharts) return;
      window.YuzuCharts.render(el, data);
      var urls = data.drill || [], boxes = data.drill_box || [], tries = 0;
      (function bind() {
        var inst = window.echarts && window.echarts.getInstanceByDom(el);
        if (!inst) { if (++tries < 60) setTimeout(bind, 50); return; }
        inst.off('click');
        inst.on('click', function (p) {
          var row = urls[p.seriesIndex] || urls;
          var u = Array.isArray(row) ? row[p.dataIndex] : null;
          if (u) open(u, boxes[p.dataIndex] || '');
        });
      })();
    }
  };
})();
</script>
)html";
}

namespace {

// One card's body, drawn from what the render read (never a request of its own).
std::string card_body(const cw::Widget& w, cw::Access a, const DashboardData& d) {
    const bool ca = w.group == cw::WidgetGroup::kYuzuCa;
    switch (a) {
    case cw::Access::kRefused:
    case cw::Access::kConfined:
        return render_widget_not_available(w, a);
    case cw::Access::kDegraded:
        return render_widget_unavailable(w, CryptoReadCause::kAccessCheck, ca);
    case cw::Access::kAvailable:
        break;
    }
    if (ca) {
        if (!d.ca)
            return render_widget_unavailable(w, CryptoReadCause::kStoreDegraded, true);
        if (!*d.ca)
            return render_widget_unavailable(w, d.ca->error().cause, true);
        return render_ca_widget(w, **d.ca);
    }
    if (!d.library)
        return render_widget_unavailable(w, CryptoReadCause::kStoreDegraded, false);
    if (!*d.library)
        return render_widget_unavailable(w, d.library->error().cause, false);
    return render_library_widget(w, **d.library);
}

std::string default_ids_attr() {
    std::string defaults;
    for (const auto id : cw::default_layout())
        defaults += (defaults.empty() ? "" : " ") + std::string(id);
    return defaults;
}

std::string not_available_text(const cw::Widget& w, cw::Access a) {
    return a == cw::Access::kConfined ? std::string(cw::kConfinedWithheldMessage)
                                      : esc(std::string(w.title)) +
                                            " is not available to this account (" +
                                            esc(perm_label(w)) + " required).";
}

} // namespace

std::string render_dashboard(const CryptoDashboardLayout& layout, cw::AccessMemo& access,
                             const DashboardData& data) {
    std::string h = style() + dash_style();
    h += "<div class=\"cry-wrap\"><h1 class=\"cry-h1\">Crypto</h1><div class=\"cry-sub\">Your "
         "dashboard of cryptographic-library presence and Yuzu-issued certificate counts. Click a "
         "number, a bar or a chart point for the data behind it. Facts only: the only built-in "
         "checks are the named windows, each shown with its criterion and computed when the page "
         "is read; nothing here grades a library or a certificate.</div>";

    // Toolbar: Add (catalogue entries not on the grid, grouped; ones this account cannot read
    // are listed disabled) and Reset to default.
    std::string options;
    for (const auto g : {cw::WidgetGroup::kLibraries, cw::WidgetGroup::kYuzuCa}) {
        std::string group_opts;
        for (const auto& w : cw::catalogue()) {
            if (w.group != g || std::ranges::find(layout.widgets, std::string(w.id)) !=
                                    layout.widgets.end())
                continue;
            const auto a = access.widget(w);
            const bool ok = a == cw::Access::kAvailable;
            std::string why;
            if (a == cw::Access::kConfined)
                why = " (not available to this account)";
            else if (!ok)
                why = " (" + esc(perm_label(w)) + " required)";
            group_opts += "<option value=\"" + esc(std::string(w.id)) + "\"" +
                          (ok ? "" : " disabled") + ">" + esc(std::string(w.title)) + why +
                          "</option>";
        }
        if (!group_opts.empty())
            options += "<optgroup label=\"" + esc(std::string(cw::group_name(g))) + "\">" +
                       group_opts + "</optgroup>";
    }
    h += "<div class=\"cry-toolbar\">";
    if (!options.empty() && layout.widgets.size() < cw::kMaxLayoutWidgets)
        h += "<label class=\"cry-grey\" for=\"cry-add\">Add widget</label><select id=\"cry-add\">"
             "<option value=\"\">Choose a widget&hellip;</option>" +
             options +
             "</select><button type=\"button\" class=\"cry-btn pri\" "
             "onclick=\"cryDash.add()\">Add</button>";
    h += "<button type=\"button\" class=\"cry-btn\" data-default=\"" + esc(default_ids_attr()) +
         "\" onclick=\"cryDash.reset(this)\">Reset to default</button>";
    if (layout.is_default)
        h += "<span class=\"cry-grey\">Showing the default layout.</span>";
    if (layout.preserved_unknown > 0)
        h += "<span class=\"cry-grey\">" + std::to_string(layout.preserved_unknown) +
             (layout.preserved_unknown == 1 ? " widget" : " widgets") +
             " from another server version kept but not shown.</span>";
    h += "</div><div id=\"cry-dash-err\" class=\"cry-err\" role=\"alert\" hidden></div>";
    if (data.library_audit_lost || data.ca_audit_lost)
        h += render_audit_notice();

    h += "<div id=\"cry-grid-wrap\" data-version=\"" + std::to_string(layout.version) + "\">";
    if (layout.widgets.empty()) {
        h += "<div class=\"cry-panel cry-empty\">No widgets on your dashboard. Add one above, or "
             "reset to the default layout." +
             scope_line() + "</div>";
    } else {
        // The scope line sits above the Yuzu-issued cards whenever any is on the grid.
        const bool any_ca = std::ranges::any_of(layout.widgets, [](const std::string& id) {
            const auto* w = cw::find_widget(id);
            return w && w->group == cw::WidgetGroup::kYuzuCa;
        });
        if (any_ca)
            h += scope_line();
        h += "<div class=\"cry-grid\" id=\"" + std::string(kGridId) + "\">";
        const std::size_t n = layout.widgets.size();
        for (std::size_t i = 0; i < n; ++i) {
            const auto* w = cw::find_widget(layout.widgets[i]);
            if (!w)
                continue; // the seam already leaves unknown ids out; defensive
            h += "<section class=\"cry-card" + std::string(is_wide(*w) ? " wide" : "") +
                 "\" data-wid=\"" + esc(std::string(w->id)) +
                 "\"><div class=\"cry-card-h\"><div class=\"cry-card-t\">" +
                 esc(std::string(w->title)) +
                 "</div><div class=\"cry-tools\"><button type=\"button\" class=\"cry-ico\" "
                 "title=\"Move left\" aria-label=\"Move left\" onclick=\"cryDash.move(this,-1)\"" +
                 (i == 0 ? " disabled" : "") +
                 ">&larr;</button><button type=\"button\" class=\"cry-ico\" title=\"Move right\" "
                 "aria-label=\"Move right\" onclick=\"cryDash.move(this,1)\"" +
                 (i + 1 == n ? " disabled" : "") +
                 ">&rarr;</button><button type=\"button\" class=\"cry-ico\" title=\"Remove\" "
                 "aria-label=\"Remove widget\" onclick=\"cryDash.remove(this)\">&times;</button>"
                 "</div></div><div class=\"cry-crit\">" +
                 esc(std::string(w->criterion)) + "</div>";
            if (w->group == cw::WidgetGroup::kYuzuCa)
                h += "<span class=\"cry-tag\">Yuzu-issued certificates</span>";
            h += "<div class=\"cry-slot\" id=\"" + slot_id(w->id) + "\">" +
                 card_body(*w, access.widget(*w), data) + "</div></section>";
        }
        h += "</div>";
    }
    h += "</div><div id=\"" + std::string(kDrillPanelId) + "\" class=\"cry-panel cry-drillpanel\"></div>";
    h += caveat_box() + "</div>";
    return h;
}

std::string render_dashboard_unavailable(CryptoReadCause cause) {
    const std::string why =
        cause == CryptoReadCause::kCapacity
            ? "Busy: too many crypto reads are in progress on this server; retry shortly."
            : "Database degraded: your saved widget layout could not be read (Postgres pool or "
              "query failed).";
    return style() + dash_style() + "<div class=\"cry-degrade\"><b>Crypto dashboard unavailable.</b> " +
           why +
           " The default layout is <b>not</b> shown in its place, so a saved layout is never "
           "silently replaced." +
           retry_button("/fragments/crypto/dashboard", "#" + std::string(kDashboardMountId)) +
           "</div>";
}

std::string render_dashboard_corrupt(std::int64_t version) {
    return style() + dash_style() +
           "<div class=\"cry-degrade\"><b>Your saved dashboard layout cannot be read.</b> The "
           "stored layout is damaged, so retrying will not help. Reset replaces it with the "
           "default layout. <button type=\"button\" class=\"cry-btn pri\" data-default=\"" +
           esc(default_ids_attr()) + "\" data-version=\"" + std::to_string(version) +
           "\" onclick=\"cryDash.reset(this)\">Reset to default</button></div>"
           "<div id=\"cry-dash-err\" class=\"cry-err\" role=\"alert\" hidden></div>";
}

std::string render_widget_not_available(const cw::Widget& w, cw::Access why) {
    return "<div class=\"cry-caveat\">" + not_available_text(w, why) + "</div>";
}

std::string render_widget_unavailable(const cw::Widget& w, CryptoReadCause cause, bool ca) {
    return "<div class=\"cry-degrade\"><b>" + esc(std::string(w.title)) + " unavailable.</b> " +
           (ca ? ca_certs_note_reason(cause) : unavailable_reason(cause)) +
           retry_button(widget_url(w.id), "closest .cry-slot") + "</div>";
}

std::string render_library_widget(const cw::Widget& w, const CryptoSummary& s) {
    // A library number drills into the families table (in the drill panel, where each row
    // expands its device drill under itself); the bar drills into one family's devices.
    const std::string families_url = widget_url("lib.families_table");
    if (w.id == "lib.devices_reporting")
        return number_button(s.coverage.devices_reporting_inventory, families_url, {},
                             "Show the library families table");
    if (w.id == "lib.devices_with_library")
        return number_button(s.coverage.devices_with_crypto_library, families_url, {},
                             "Show the library families table");
    if (w.id == "lib.families_matched")
        return number_button(static_cast<std::int64_t>(s.families.size()), families_url, {},
                             "Show the library families table") +
               "<div class=\"cry-asof\">of " + std::to_string(crypto_library::families().size()) +
               " in the curated table (version " +
               std::to_string(crypto_library::kCryptoTableVersion) + ")</div>";
    if (s.families.empty())
        return truncation_note(s) + "<div class=\"cry-empty\">" + esc(std::string(kNoLibraryRows)) +
               "</div>";
    if (w.id == "lib.devices_by_family") {
        nlohmann::json data{{"chart_type", "bar"}};
        auto labels = nlohmann::json::array();
        auto values = nlohmann::json::array();
        auto drill = nlohmann::json::array();
        auto boxes = nlohmann::json::array();
        for (const auto& f : s.families) {
            labels.push_back(f.display.empty() ? f.id : f.display);
            values.push_back(f.device_count);
            drill.push_back(devices_url(f.id, std::nullopt, std::nullopt, ""));
            boxes.push_back(drill_box_id(f.id));
        }
        data["labels"] = std::move(labels);
        data["series"] = nlohmann::json::array({{{"name", "Devices"}, {"data", std::move(values)}}});
        data["drill"] = nlohmann::json::array({std::move(drill)});
        data["drill_box"] = std::move(boxes);
        return chart_block(w.id, data) + truncation_note(s);
    }
    // lib.families_table: the old page's table - each row and version chip expands its device
    // drill directly under the row.
    return "<div class=\"cry-tblwrap\"><table class=\"cry-tbl\"><thead><tr><th>Family</th>"
           "<th class=\"cry-num\">Devices</th><th class=\"cry-num\">Versions</th><th>Top "
           "versions</th></tr></thead><tbody>" +
           family_rows(s) + "</tbody></table></div>" + truncation_note(s) +
           names_as_of_note(s.names_from_catalogue, s.names_as_of);
}

std::string render_ca_widget(const cw::Widget& w, const CaCertStats& s) {
    if (w.kind == cw::WidgetKind::kLine) {
        const bool issued = w.ca_kind == CaCertKind::kIssuedWeek;
        nlohmann::json data{{"chart_type", "line"}};
        auto labels = nlohmann::json::array();
        std::string partial_label;
        for (const auto& wk : s.weeks) {
            labels.push_back(wk.partial ? wk.label + " (partial)" : wk.label);
            if (wk.partial)
                partial_label = wk.label;
        }
        auto series = nlohmann::json::array();
        auto drill = nlohmann::json::array();
        auto add_series = [&](std::string name, auto value_of, std::optional<RevokedBucket> b) {
            auto values = nlohmann::json::array();
            auto urls = nlohmann::json::array();
            for (const auto& wk : s.weeks) {
                values.push_back(value_of(wk));
                urls.push_back(ca_certificates_url(CaCertQuery{
                    .kind = w.ca_kind, .week_start = wk.week_start, .bucket = b, .as_of = s.as_of}));
            }
            series.push_back({{"name", std::move(name)}, {"data", std::move(values)}});
            drill.push_back(std::move(urls));
        };
        if (issued) {
            add_series("Issued", [](const CaWeekCount& wk) { return wk.issued; }, std::nullopt);
        } else {
            for (const auto b : cw::kRevokedBuckets)
                add_series("Revoked: " + std::string(cw::bucket_name(b)),
                           [b](const CaWeekCount& wk) { return week_bucket(wk, b); }, b);
        }
        data["labels"] = std::move(labels);
        data["series"] = std::move(series);
        data["drill"] = std::move(drill);
        std::string note;
        if (!partial_label.empty())
            note = "<div class=\"cry-asof\">Week " + esc(partial_label) +
                   " is partial: it counts up to as_of only.</div>";
        return chart_block(w.id, data) + note + ca_asof(s.as_of);
    }
    if (w.ca_kind == CaCertKind::kRevoked) {
        const auto* r = revoked_window(s.revoked, w.days);
        if (!r)
            return "<div class=\"cry-caveat\">This count was not returned by the stats read.</div>";
        std::string h = "<div class=\"cry-buckets\">";
        for (const auto b : cw::kRevokedBuckets)
            h += "<div class=\"cry-bucket\">" +
                 number_button(bucket_count(*r, b),
                               ca_certificates_url(CaCertQuery{
                                   .kind = w.ca_kind, .days = w.days, .bucket = b, .as_of = s.as_of}),
                               {}, cw::criterion_text(w.ca_kind, w.days, {}, b)) +
                 "<div class=\"cry-blabel\">" + esc(std::string(cw::bucket_name(b))) + "</div></div>";
        return h + "</div>" + ca_asof(s.as_of);
    }
    std::int64_t n = -1;
    switch (w.ca_kind) {
    case CaCertKind::kActive:
        n = s.active;
        break;
    case CaCertKind::kExpiring:
        n = window_count(s.expiring, w.days);
        break;
    case CaCertKind::kExpired:
        n = window_count(s.expired, w.days);
        break;
    case CaCertKind::kIssued:
        n = s.issued.days == w.days ? s.issued.count : -1;
        break;
    case CaCertKind::kRevoked:
    case CaCertKind::kIssuedWeek:
    case CaCertKind::kRevokedWeek:
        break;
    }
    if (n < 0) // the stats read did not carry this window: say so, never a zero
        return "<div class=\"cry-caveat\">This count was not returned by the stats read.</div>";
    return number_button(n,
                         ca_certificates_url(
                             CaCertQuery{.kind = w.ca_kind, .days = w.days, .as_of = s.as_of}),
                         {}, "Show the certificates behind this count (needs Security:Read)") +
           ca_asof(s.as_of);
}

std::string render_ca_certificates(const CaCertPage& p, bool continuation) {
    if (continuation)
        return ca_rows(p) + ca_more_row(p);
    std::string h = "<div class=\"cry-drill\"><span class=\"cry-close\" role=\"button\" "
                    "tabindex=\"0\" onclick=\"this.parentNode.parentNode.innerHTML=''\">close "
                    "&times;</span><div class=\"cry-devhead\"><b>Yuzu-issued certificates</b><span>" +
                    esc(cw::criterion_text(p.query.kind, p.query.days, week_label_of(p.query),
                                           p.query.bucket)) +
                    "</span><span>&middot; " + fmt_int(p.total) + " in total</span><span>&middot; as of " +
                    fmt_time(p.as_of) + "</span></div>" + scope_line();
    if (p.rows.empty()) {
        h += "<div class=\"cry-empty\">" +
             std::string(p.total > 0 ? "No certificates on this page."
                                     : "No Yuzu-issued certificates match this criterion at "
                                       "as_of.") +
             "</div>";
    } else {
        h += "<div class=\"cry-tblwrap\"><table class=\"cry-tbl cry-sub\"><thead><tr>"
             "<th>Serial</th><th>Subject</th><th>Purpose</th><th>Issued</th><th>Not after</th>"
             "<th>Status</th><th>Revoked at</th><th>Recorded reason</th></tr></thead><tbody>" +
             ca_rows(p) + ca_more_row(p) + "</tbody></table></div>";
    }
    return h + "</div>";
}

std::string render_ca_unavailable(std::string_view retry_url, CryptoReadCause cause, bool row) {
    const std::string body =
        "<div class=\"cry-degrade\"><b>Yuzu-issued certificates unavailable.</b> " +
        ca_certs_note_reason(cause) +
        (retry_url.empty() ? std::string{}
                           : retry_button(std::string(retry_url),
                                          row ? "closest tr" : "closest .cry-slot")) +
        "</div>";
    return row ? "<tr class=\"cry-more\"><td colspan=\"8\">" + body + "</td></tr>" : body;
}

std::string render_ca_caveat(std::string_view message, bool row) {
    const std::string body = render_caveat(message);
    return row ? "<tr class=\"cry-more\"><td colspan=\"8\">" + body + "</td></tr>" : body;
}

std::string render_ca_audit_notice_row() {
    return "<tr class=\"cry-more\"><td colspan=\"8\">" + render_audit_notice() + "</td></tr>";
}

} // namespace yuzu::server::crypto_html
