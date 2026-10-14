#pragma once

/// @file home_ui.hpp
/// The landing and sign-in page (`GET /home`; `GET /login` redirects here). No
/// shell: no sidebar, no header bar, no bell — there may be no session yet. Top
/// to bottom: a slim bar (Yuzu mark; server name and version), the hero (rule,
/// headline, one sentence, the sign-in panel), then the fifteen screens as
/// colour-coded tiles in five families. The page fetches nothing: the tiles say
/// what each area does, not live figures.
///
/// Signed out, a tile links to its screen; the pre-routing auth gate answers a
/// screen request without a session with `sign_in_location(path)`, i.e.
/// `/home?next=<key>`, and the page shows "Sign in to open <area>." above the
/// form and labels the post-sign-in button "Open <area>". `next` is only ever a
/// key from `families()` — never a path or URL — so there is no open redirect,
/// and sign-in never auto-redirects: the user stays on `/home` and sees the
/// signed-in panel. The sign-in form is the one implementation: it posts to the
/// real `/login`, `/login/mfa` and `/login/mfa/enroll` routes exactly as the
/// former `/login` page did.

#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace yuzu::server::home_ui {

/// One tile: a screen of the product. `key` is what `next` carries.
struct Screen {
    std::string_view key;
    std::string_view name;
    std::string_view href;
    std::string_view sentence;
    std::string_view icon; ///< SVG path data for a 24x24 viewBox
};

/// One labelled family of tiles; `cls` picks the family colour token.
struct Family {
    std::string_view cls; ///< `f-operate` .. `f-system`
    std::string_view name;
    std::string_view sub; ///< the muted one-line description beside the heading
    std::span<const Screen> screens;
};

/// The five families and their fifteen screens, in render order.
std::span<const Family> families();

/// The screen a `next` key names, or null for anything else. This IS the
/// allow-list: an unknown key, a path, or a URL all resolve to null and the page
/// behaves as if `next` were absent.
const Screen* screen_by_key(std::string_view key);

/// Where a signed-out request for `path` is sent: `/home?next=<key>` when the
/// path is one of the fifteen screens (a shell sub-page such as `/approvals`
/// counts as its parent item), else plain `/home`.
std::string sign_in_location(std::string_view path);

/// The plain-English message for a `?error=` code the SSO callbacks redirect
/// with; empty for an empty code, "SSO error" for an unknown one.
std::string_view sso_error_message(std::string_view code);

struct SignedIn {
    std::string name; ///< display name (never the opaque SSO principal)
    std::string role; ///< "Administrator" or "Viewer"
};

struct LandingView {
    std::string_view server_name;
    std::string_view version;
    const Screen* next = nullptr;   ///< validated; drives the notice and the button label
    std::string_view sso_href;      ///< empty: no single sign-on button
    bool mfa_note = false;          ///< two-factor enforcement is on
    std::optional<SignedIn> who;    ///< a session exists: the signed-in variant
    std::string_view error_message; ///< shown under the form (signed-out only)
};

/// The whole page.
std::string render_landing(const LandingView& view);

} // namespace yuzu::server::home_ui

/// The sign-in form pieces (login_ui.cpp, its own TU for the MSVC literal cap):
/// the username/password fields and button, the TOTP / enrolment / recovery
/// steps, and the script that posts to `/login`, `/login/mfa` and
/// `/login/mfa/enroll` and then reloads `/home`.
namespace yuzu::server::login_ui {
std::string_view sign_in_fields();
std::string_view sign_in_steps();
std::string_view sign_in_script();
} // namespace yuzu::server::login_ui

/// The signed-out page with no notice, no server name and no SSO button, baked
/// once. Kept for the superseded `GET /home` handler in home_routes.cpp (which
/// the auth routes' registration now shadows) and for the page pins; the live
/// route renders through `render_landing`.
extern const char* const kHomeHtml;
