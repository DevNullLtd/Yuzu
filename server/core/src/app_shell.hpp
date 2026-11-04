#pragma once

// App shell — the sidebar + header chrome shared by every full-page dashboard
// surface. One pure nav model and one renderer replace the hand-copied
// `<nav class="nav-bar">` blocks the pages used to carry (which had drifted: Guardian
// lacked Result Sets, the viz host page had a four-link nav) and the per-route
// "swap the active link" string replaces.
//
// How a page uses it:
//   * A page template carries an empty marker pair, `<!--yuzu:shell--><!--/yuzu:shell-->`,
//     where its chrome goes, and sits inside a `<body>` the shell can pad
//     (the sidebar is fixed; the shell CSS reserves its width on `html body`).
//   * Static pages bake the chrome in once at static-init time:
//       extern const char* const kXHtml = shell::bake(kXTemplate, {.active_key = "x"});
//   * A shared template whose active item varies per route (kGuardianDetailPageHtml) is
//     re-targeted per request with `shell::apply_shell(html, {.active_key = "dex"})`.
//
// Pure: no I/O, no globals beyond the constexpr nav model. The only thing the shell
// does at runtime in the browser is fill the signed-in user's name/role and hide the
// Settings entry from non-admins (the same `/api/me` read each page used to do itself).

#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::shell {

/// One nav entry. Sub-items (`children`) render only while their family is active.
struct NavItem {
    std::string_view key;   ///< stable id passed as ShellCtx::active_key
    std::string_view label; ///< sentence case, shown in the nav and the breadcrumb
    std::string_view href;
    std::string_view icon;  ///< SVG path data for a 24x24 viewBox; empty for sub-items
    std::span<const NavItem> children = {};
    bool admin_only = false; ///< rendered `id="nav-settings-link"`; the shell script hides it from non-admins
    bool badge = false;      ///< sub-item only: carries the pending-count badge the shell script fills
};

struct NavGroup {
    std::string_view title;
    std::span<const NavItem> items;
};

/// The whole nav, in render order. Only pages that exist.
std::span<const NavGroup> nav_groups();

/// Which page is showing and how the header describes it.
struct ShellCtx {
    /// A NavItem key, or empty / unknown for a page that has no nav entry (Help).
    std::string_view active_key = {};
    /// Leaf of the breadcrumb. Empty: the active item's label.
    std::string_view title = {};
    /// '/'-separated labels that replace the derived parent trail (the group). Empty: derive.
    std::string_view breadcrumb = {};
};

/// Plain-text breadcrumb labels for `ctx`, outermost first (unescaped).
std::vector<std::string> breadcrumb_trail(const ShellCtx& ctx);

inline constexpr std::string_view kShellBegin = "<!--yuzu:shell-->";
inline constexpr std::string_view kShellEnd = "<!--/yuzu:shell-->";

/// The colour-scheme names the boot scripts and the Settings picker accept, as a JS regex source.
/// Single source: each emitting TU splices this between its own script prefix and suffix.
inline constexpr std::string_view kThemeWhitelistRe = "^(slate|navy|jade|light|light-baby|light-hot)$";

/// The chrome block: kShellBegin, shell CSS, sidebar, header, user/role script, kShellEnd.
std::string render_shell(const ShellCtx& ctx);

/// Replaces whatever sits between the shell markers in `html` (empty in a template, a
/// previous render in a baked page) with `render_shell(ctx)`. Returns `html` unchanged
/// when it has no marker pair — callers' tests must pin that their page has one.
std::string apply_shell(std::string html, const ShellCtx& ctx);

/// `apply_shell` on a page template, kept alive for the process lifetime so a page
/// constant can stay a `const char*`. Intended for namespace-scope initialisers.
const char* bake(const char* page_template, const ShellCtx& ctx);

} // namespace yuzu::server::shell
