// The landing and sign-in page — see home_ui.hpp. Server-rendered; the only
// script is the sign-in XHR (login_ui.cpp) plus htmx for the Sign out button.
// Styles live in yuzu.css ("Home landing" block); the page carries no CSS.

#include "home_ui.hpp"

#include "app_shell.hpp" // nav_groups(): a shell sub-page maps to its parent screen
#include "web_utils.hpp" // html_escape

#include <string>
#include <string_view>

namespace yuzu::server::home_ui {

namespace {

// The fifteen screens, exactly as the design's table names them (name, link,
// sentence) and with the nav's own icons. `key` doubles as the `next` key.
constexpr Screen kOperate[] = {
    {"dashboard", "Dashboard", "/", "Ask every device a question and watch the answers arrive.",
     "M4 17l6-6-6-6 M12 19h8"},
    {"instructions", "Instructions", "/instructions",
     "A library of questions and actions, with approval where it matters.",
     "M6 3h9l4 4v14H6z M14 3v5h5 M9 13h7 M9 17h7"},
    {"result-sets", "Result sets", "/result-sets", "Save answers, re-run them, reuse them as targets.",
     "M12 2l10 5-10 5L2 7z M2 17l10 5 10-5 M2 12l10 5 10-5"},
};
constexpr Screen kPosture[] = {
    {"compliance", "Compliance", "/compliance",
     "Check devices against policy and fix the ones that fail.",
     "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z M9 12l2 2 4-4"},
    {"guardian", "Guardian", "/guardian", "Hold settings to the state you set and undo drift.",
     "M5 11h14v10H5z M8 11V7a4 4 0 018 0v4"},
    {"dex", "DEX", "/dex", "See crashes, slow starts and noisy apps as users feel them.",
     "M22 12h-4l-3 9L9 3l-3 9H2"},
    {"tar", "TAR", "/tar", "A recorded history of what ran and connected on each device.",
     "M3 12a9 9 0 109-9 M3 4v5h5 M12 7v5l3 2"},
};
constexpr Screen kEstate[] = {
    {"devices", "Devices", "/devices", "Every device, with tags, properties and quarantine.",
     "M3 4h18v12H3z M8 20h8 M12 16v4"},
    {"hardware", "Hardware", "/hardware", "CPU, memory, disks and firmware across the fleet.",
     "M7 7h10v10H7z M9 3v4 M15 3v4 M9 17v4 M15 17v4 M3 9h4 M3 15h4 M17 9h4 M17 15h4"},
    {"software", "Software", "/software",
     "What is installed, how current it is, and roll out updates.",
     "M5 3h14a2 2 0 012 2v14a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2z M10 9l-3 3 3 3 M14 9l3 "
     "3-3 3"},
    {"fleet", "Fleet", "/viz/fleet", "The estate as a 3D map. Open any machine and its processes.",
     "M12 21a9 9 0 100-18 9 9 0 000 18z M3 12h18 M12 3c3 3 3 15 0 18 M12 3c-3 3-3 15 0 18"},
};
constexpr Screen kAccess[] = {
    {"users", "Users and roles", "/access/users", "Accounts, roles and directory sync.",
     "M12 12a4 4 0 100-8 4 4 0 000 8z M4 21c0-4 3.6-7 8-7s8 3 8 7"},
    {"tokens", "Tokens and principals", "/access/tokens",
     "API tokens and service identities, with expiry.",
     "M15 9a4 4 0 10-7 2.6L3 17v4h4v-2h2v-2h2l2.4-2.4A4 4 0 0015 9z"},
    {"audit", "Audit and reviews", "/access/audit",
     "Who did what, and checks that access is still needed.",
     "M5 4h11a3 3 0 013 3v13H8a3 3 0 01-3-3z M9 9h6 M9 13h6"},
};
constexpr Screen kSystem[] = {
    {"settings", "Settings", "/settings",
     "Appearance, sign-in, integrations, certificates and data.",
     "M4 6h10 M18 6h2 M4 12h4 M12 12h8 M4 18h12 M14 4v4 M10 10v4 M16 16v4"},
};
constexpr Family kFamilies[] = {
    {"f-operate", "Operate", "Run things on the estate", kOperate},
    {"f-posture", "Posture", "How safe the estate is", kPosture},
    {"f-estate", "Estate", "What you manage", kEstate},
    {"f-access", "Access", "Who can do what", kAccess},
    {"f-system", "System", "Configure Yuzu", kSystem},
};

const Screen* screen_by_href(std::string_view href) {
    for (const auto& f : kFamilies)
        for (const auto& s : f.screens)
            if (s.href == href)
                return &s;
    return nullptr;
}

constexpr std::string_view kHead = R"HTM(<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Yuzu</title>
<link rel="icon" href="data:,"><link rel="stylesheet" href="/static/yuzu.css">
<script src="/static/htmx.js"></script>
</head><body>
<div class="land">
<header class="lh"><a class="brand" href="/home" aria-label="Yuzu home">Yuzu<i></i></a>)HTM";

constexpr std::string_view kHeadline =
    R"HTM(<section class="hero"><div class="ht"><div class="rule"></div>)HTM"
    R"HTM(<h1>Ask every device a question.<br>Hold it to the state you set.</h1>)HTM";

constexpr std::string_view kLedeOut =
    "Yuzu runs on your own servers. Sign in to see the estate, run instructions on it and "
    "review what changed.";
constexpr std::string_view kLedeIn =
    "Yuzu runs on your own servers. Open the Dashboard to ask your first question, or pick an "
    "area below.";
constexpr std::string_view kMfaNote =
    "If two-factor is on for your account, you will be asked for a code next. Forgot your "
    "password, or need an account? Ask a Yuzu administrator.";
constexpr std::string_view kSignedInLine =
    "You are signed in. Open the Dashboard, or pick an area below.";

static_assert(kHead.size() < 15000 && kHeadline.size() < 15000,
              "MSVC C2026: keep every raw string literal under the 16,380-byte cap");

void append_tiles(std::string& out) {
    out += R"(<section class="lb"><h2>What you can do in Yuzu</h2><div class="fams">)";
    for (const auto& f : kFamilies) {
        out += R"(<section class="fam )";
        out += f.cls;
        out += R"(" aria-label=")";
        out += f.name;
        out += R"("><div class="fh"><h2>)";
        out += f.name;
        out += "</h2><p>";
        out += f.sub;
        out += R"(</p></div><div class="tiles n)";
        out += std::to_string(f.screens.size());
        out += R"(">)";
        for (const auto& s : f.screens) {
            out += R"(<a class="tile" href=")";
            out += s.href;
            out += R"("><svg viewBox="0 0 24 24" aria-hidden="true"><path d=")";
            out += s.icon;
            out += R"("/></svg><span class="tt">)";
            out += s.name;
            out += R"(</span><span class="ts">)";
            out += s.sentence;
            out += "</span></a>";
        }
        out += "</div></section>";
    }
    out += "</div></section>";
}

void append_sign_in(std::string& out, const LandingView& v) {
    out += R"(<section class="panel login" id="signin" aria-label="Sign in" data-next=")";
    if (v.next)
        out += v.next->key;
    // No server name here: the page is reachable without a session (see render_landing).
    out += R"HTM("><div class="hd"><h2>Sign in</h2></div><form id="login-form" class="form" onsubmit="doLogin(event)">)HTM";
    if (v.next) {
        out += R"(<div class="note" id="signin-notice">Sign in to open <b>)";
        out += v.next->name;
        out += "</b>.</div>";
    }
    out += login_ui::sign_in_fields();
    out += R"(<div class="error-msg" id="error-msg" role="alert" aria-live="polite">)";
    out += html_escape(std::string(v.error_message));
    out += "</div>";
    if (!v.sso_href.empty()) {
        out += R"(<div class="or">or</div><a class="btn" id="btn-sso" href=")";
        out += v.sso_href;
        out += R"(">Sign in with single sign-on</a>)";
    }
    if (v.mfa_note) {
        out += R"(<p class="small">)";
        out += kMfaNote;
        out += "</p>";
    }
    out += "</form>";
    out += login_ui::sign_in_steps();
    out += "</section>";
}

void append_signed_in(std::string& out, const LandingView& v, const std::string& host) {
    const std::string_view label = v.next ? v.next->name : "Dashboard";
    const std::string_view href = v.next ? v.next->href : "/";
    out += R"(<section class="panel login" id="signed-in" aria-label="Signed in">)"
           R"(<div class="hd"><h2>Signed in</h2><div class="end"><span class="sub mono">)";
    out += host;
    out += R"(</span></div></div><div class="form"><div class="who"><b>)";
    out += html_escape(v.who->name);
    out += "</b><span>";
    out += html_escape(v.who->role);
    out += R"(</span></div><a class="btn primary" id="open-area" href=")";
    out += href;
    out += R"(">Open )";
    out += label;
    out += R"(</a><button class="btn" type="button" hx-post="/logout">Sign out</button><p class="small">)";
    out += kSignedInLine;
    out += "</p></div></section>";
}

} // namespace

std::span<const Family> families() { return kFamilies; }

const Screen* screen_by_key(std::string_view key) {
    for (const auto& f : kFamilies)
        for (const auto& s : f.screens)
            if (s.key == key)
                return &s;
    return nullptr;
}

std::string sign_in_location(std::string_view path) {
    const Screen* s = screen_by_href(path);
    if (!s) {
        // A shell sub-page (Approvals, Deployments, Network ...) opens as its family item.
        for (const auto& g : shell::nav_groups())
            for (const auto& it : g.items)
                for (const auto& c : it.children)
                    if (c.href == path)
                        s = screen_by_href(it.href);
    }
    return s ? "/home?next=" + std::string(s->key) : "/home";
}

std::string_view sso_error_message(std::string_view code) {
    if (code.empty())
        return {};
    if (code == "sso_denied")
        return "SSO sign-in was denied by the identity provider";
    if (code == "sso_failed")
        return "SSO authentication failed";
    if (code == "sso_invalid")
        return "Invalid SSO response";
    return "SSO error";
}

std::string render_landing(const LandingView& v) {
    const std::string host = html_escape(std::string(v.server_name));
    std::string out;
    out.reserve(24000);
    out += kHead;
    out += R"(<span class="srv">)";
    // The page is reachable without a session, so the server name and the running
    // version (what an attacker looks up CVEs against) are shown to a signed-in
    // user only: a signed-out visitor sees the brand, the form and the tiles.
    if (v.who) {
        out += host;
        if (!host.empty())
            out += " &middot; ";
        out += "version ";
        out += html_escape(std::string(v.version));
    }
    out += "</span></header>";
    out += kHeadline;
    out += R"(<p class="lede">)";
    out += v.who ? kLedeIn : kLedeOut;
    out += R"(</p></div><div class="lc">)";
    if (v.who)
        append_signed_in(out, v, host);
    else
        append_sign_in(out, v);
    out += "</div></section>";
    append_tiles(out);
    out += "</div>\n";
    if (!v.who)
        out += login_ui::sign_in_script();
    out += "</body></html>\n";
    return out;
}

} // namespace yuzu::server::home_ui
