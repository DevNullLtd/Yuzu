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
        const std::string box = "cry-exp-" + url_encode(f.id);
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

std::string render_unavailable(std::string_view what, CryptoReadCause cause) {
    // Exhaustive over CryptoReadCause, no default: a new cause must choose its wording here.
    std::string reason;
    switch (cause) {
    case CryptoReadCause::kCapacity:
        reason = "Temporarily busy: two reads are already running on this server; retry "
                 "shortly. This is <b>not</b> \"no library installed\".";
        break;
    case CryptoReadCause::kNone:
    case CryptoReadCause::kStoreDegraded:
        reason = "The inventory store could not be read (Postgres pool/query degraded). This is "
                 "<b>not</b> \"no library installed\": reads here are authoritative, so this "
                 "banner is shown instead of an empty table.";
        break;
    }
    return "<div class=\"cry-degrade\"><b>" + esc(std::string(what)) + " unavailable.</b> " + reason +
           " <button type=\"button\" class=\"cry-btn\" hx-get=\"/fragments/crypto/libraries\" "
           "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">Retry</button></div>";
}

std::string render_caveat(std::string_view message) {
    return "<div class=\"cry-caveat\">" + esc(std::string(message)) + "</div>";
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

} // namespace yuzu::server::crypto_html
