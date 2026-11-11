#pragma once

/// @file dex_pane.hpp
/// PURE markup for the controls that swap a fragment into the shared DEX pane
/// (`#guardian-detail`). One definition of the three attributes every such control carries and of
/// the native-button shape for chips, sub-navigation tabs and text links, so a control cannot be
/// added without its stale-response guard and a keyboard-operable element.
///
/// `hx-sync="#guardian-detail:replace"` makes a newer request for the pane abort the one still in
/// flight, so a slow response can never overwrite a view the viewer has moved on from. It is set
/// explicitly on each control, never inherited from the mount: htmx inherits `hx-sync`, and the
/// pane holds child loaders that fire on load into their own targets, which would then abort each
/// other. Header-only, no store or httplib include. htmx core attributes only (the CSP blocks
/// `hx-on`).

#include <string>
#include <string_view>

namespace yuzu::server {

/// The pane-swap attributes (leading space included). A site that spells its own `hx-target` and
/// `hx-swap` uses this INSTEAD, never in addition: a duplicate attribute keeps the first one.
inline constexpr std::string_view kDexPaneSwapAttrs =
    " hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" hx-sync=\"#guardian-detail:replace\"";

/// A filter chip as a native button. `url` and `label` are emitted exactly as given (callers keep
/// their own encoding and escaping).
[[nodiscard]] inline std::string dex_pane_chip(std::string_view url, std::string_view label, bool on) {
    std::string h = "<button type=\"button\" class=\"gp-chip";
    h += on ? " on\" aria-pressed=\"true\"" : "\" aria-pressed=\"false\"";
    h += " hx-get=\"";
    h += url;
    h += '"';
    h += kDexPaneSwapAttrs;
    h += '>';
    h += label;
    h += "</button>";
    return h;
}

/// A sub-navigation tab as a native button; the current one carries `aria-current="page"`.
[[nodiscard]] inline std::string dex_pane_tab(std::string_view url, std::string_view label, bool on) {
    std::string h = "<button type=\"button\"";
    if (on)
        h += " class=\"on\" aria-current=\"page\"";
    h += " hx-get=\"";
    h += url;
    h += '"';
    h += kDexPaneSwapAttrs;
    h += '>';
    h += label;
    h += "</button>";
    return h;
}

/// A text link (a drill-down or a back link) as a native button styled as a link. `label_html` is
/// already escaped; `extra_class` is a literal such as `gp-back`.
[[nodiscard]] inline std::string dex_pane_link(std::string_view url, std::string_view label_html,
                                               std::string_view extra_class = {}) {
    std::string h = "<button type=\"button\" class=\"dx-lk";
    if (!extra_class.empty()) {
        h += ' ';
        h += extra_class;
    }
    h += "\" hx-get=\"";
    h += url;
    h += '"';
    h += kDexPaneSwapAttrs;
    h += '>';
    h += label_html;
    h += "</button>";
    return h;
}

}  // namespace yuzu::server
