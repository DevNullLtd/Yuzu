// App shell renderer — see app_shell.hpp for the contract.
//
// Compiled with its CSS and user script as separate raw-string literals, each well
// under MSVC's 16,380-byte limit (C2026).

#include "app_shell.hpp"

#include "web_utils.hpp"

#include <deque>
#include <mutex>
#include <optional>
#include <utility>

namespace yuzu::server::shell {

namespace {

// ── Nav model ────────────────────────────────────────────────────────────
// Icon paths are the design's 24x24 line icons (stroke, no fill).

constexpr NavItem kSoftwareSub[] = {
    {.key = "auto", .label = "Deployments", .href = "/auto"},
};
constexpr NavItem kFleetSub[] = {
    {.key = "network", .label = "Network", .href = "/network"},
};

constexpr NavItem kOperate[] = {
    {.key = "dashboard", .label = "Dashboard", .href = "/", .icon = "M4 17l6-6-6-6 M12 19h8"},
    {.key = "instructions",
     .label = "Instructions",
     .href = "/instructions",
     .icon = "M6 3h9l4 4v14H6z M14 3v5h5 M9 13h7 M9 17h7"},
    {.key = "result-sets",
     .label = "Result sets",
     .href = "/result-sets",
     .icon = "M12 2l10 5-10 5L2 7z M2 17l10 5 10-5 M2 12l10 5 10-5"},
};
constexpr NavItem kPosture[] = {
    {.key = "compliance",
     .label = "Compliance",
     .href = "/compliance",
     .icon = "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z M9 12l2 2 4-4"},
    {.key = "guardian",
     .label = "Guardian",
     .href = "/guardian",
     .icon = "M5 11h14v10H5z M8 11V7a4 4 0 018 0v4"},
    {.key = "dex", .label = "DEX", .href = "/dex", .icon = "M22 12h-4l-3 9L9 3l-3 9H2"},
    {.key = "tar",
     .label = "TAR",
     .href = "/tar",
     .icon = "M3 12a9 9 0 109-9 M3 4v5h5 M12 7v5l3 2"},
};
constexpr NavItem kEstate[] = {
    {.key = "hardware",
     .label = "Hardware",
     .href = "/hardware",
     .icon = "M7 7h10v10H7z M9 3v4 M15 3v4 M9 17v4 M15 17v4 M3 9h4 M3 15h4 M17 9h4 M17 15h4"},
    {.key = "software",
     .label = "Software",
     .href = "/software",
     .icon = "M5 3h14a2 2 0 012 2v14a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2z M10 9l-3 3 3 3 "
             "M14 9l3 3-3 3",
     .children = kSoftwareSub},
    {.key = "fleet",
     .label = "Fleet",
     .href = "/viz/fleet",
     .icon = "M12 21a9 9 0 100-18 9 9 0 000 18z M3 12h18 M12 3c3 3 3 15 0 18 M12 3c-3 3-3 15 0 "
             "18",
     .children = kFleetSub},
};
constexpr NavItem kAccess[] = {
    {.key = "tokens",
     .label = "Tokens and principals",
     .href = "/access/tokens",
     .icon = "M15 9a4 4 0 10-7 2.6L3 17v4h4v-2h2v-2h2l2.4-2.4A4 4 0 0015 9z"},
};
constexpr NavItem kSystem[] = {
    {.key = "settings",
     .label = "Settings",
     .href = "/settings",
     .icon = "M4 6h10 M18 6h2 M4 12h4 M12 12h8 M4 18h12 M14 4v4 M10 10v4 M16 16v4",
     .admin_only = true},
};

constexpr NavGroup kGroups[] = {
    {"Operate", kOperate},
    {"Posture", kPosture},
    {"Estate", kEstate},
    {"Access", kAccess},
    {"System", kSystem},
};

struct Found {
    const NavGroup* group;
    const NavItem* item;
};

std::optional<Found> find_item(std::string_view key) {
    if (key.empty())
        return std::nullopt;
    for (const auto& g : kGroups)
        for (const auto& it : g.items) {
            if (it.key == key)
                return Found{&g, &it};
            for (const auto& c : it.children)
                if (c.key == key)
                    return Found{&g, &c};
        }
    return std::nullopt;
}

// ── Markup ───────────────────────────────────────────────────────────────

constexpr std::string_view kChevron =
    R"(<svg class="shell-cv" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 9l6 6 6-6"/></svg>)";
constexpr std::string_view kSearchButton =
    R"(<button class="shell-search" id="shell-search" type="button" aria-keyshortcuts="Control+K">)"
    R"(<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M11 4a7 7 0 100 14 7 7 0 000-14z M21 21l-4.3-4.3"/></svg>)"
    R"(<span>Search devices, instructions, help</span><kbd>Ctrl K</kbd></button>)";
// Hidden until the first /api/health answer fills the count (kShellScript).
constexpr std::string_view kOnlineCounter =
    R"(<span class="shell-live" id="shell-online" hidden><i></i><b id="shell-online-n"></b> online</span>)";
constexpr std::string_view kUserIcon =
    R"(<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 12a4 4 0 100-8 4 4 0 000 8z M4 21c0-4 3.6-7 8-7s8 3 8 7"/></svg>)";

void append_nav_item(std::string& out, const NavItem& it, std::string_view active) {
    const bool self = it.key == active;
    bool family = self;
    for (const auto& c : it.children)
        family = family || c.key == active;

    out += R"(<a class="shell-nav)";
    out += family ? " on" : "";
    out += R"(" href=")";
    out += it.href;
    out += '"';
    if (it.admin_only)
        out += R"( id="nav-settings-link")";
    if (self)
        out += R"( aria-current="page")";
    out += R"(><svg viewBox="0 0 24 24" aria-hidden="true"><path d=")";
    out += it.icon;
    out += R"("/></svg>)";
    out += it.label;
    if (!it.children.empty())
        out += kChevron;
    out += "</a>";

    if (family && !it.children.empty()) {
        out += R"(<div class="shell-sub">)";
        for (const auto& c : it.children) {
            out += R"(<a href=")";
            out += c.href;
            out += '"';
            if (c.key == active)
                out += R"( class="on" aria-current="page")";
            out += '>';
            out += c.label;
            out += "</a>";
        }
        out += "</div>";
    }
}

void append_sidebar(std::string& out, std::string_view active) {
    out += R"(<aside class="shell-side"><a class="shell-brand" href="/" aria-label="Yuzu home">Yuzu<i></i></a>)"
           R"(<nav aria-label="Primary">)";
    for (const auto& g : kGroups) {
        out += R"(<div class="shell-grp"><div class="shell-gt">)";
        out += g.title;
        out += "</div>";
        for (const auto& it : g.items)
            append_nav_item(out, it, active);
        out += "</div>";
    }
    out += R"(</nav><div class="shell-me"><b id="nav-user"></b><span id="role-badge"></span></div></aside>)";
}

void append_header(std::string& out, const ShellCtx& ctx) {
    const auto trail = breadcrumb_trail(ctx);
    out += R"(<header class="shell-top"><nav class="shell-crumb" aria-label="Breadcrumb">)";
    for (std::size_t i = 0; i < trail.size(); ++i) {
        const bool leaf = i + 1 == trail.size();
        if (i != 0)
            out += R"(<span class="shell-sep">/</span>)";
        out += leaf ? "<b>" : "<span>";
        out += yuzu::server::html_escape(trail[i]);
        out += leaf ? "</b>" : "</span>";
    }
    out += "</nav>";
    out += kSearchButton;
    out += kOnlineCounter;
    out += R"(<div class="shell-acct"><span class="shell-user">)";
    out += kUserIcon;
    out += R"(<span id="context-user"></span></span>)"
           R"(<button class="shell-out" type="button" hx-post="/logout">Sign out</button></div></header>)";
}

// ── Styles ───────────────────────────────────────────────────────────────
// Tokens only (yuzu.css). `html body` out-specifies pages' own `body{padding:0}`.

constexpr std::string_view kShellCss = R"CSS(<style>
:root{--shell-side-w:236px;--shell-top-h:56px}
html body{padding-left:var(--shell-side-w)}
.shell-side{position:fixed;top:0;bottom:0;left:0;z-index:50;width:var(--shell-side-w);display:flex;flex-direction:column;gap:12px;padding:16px 10px 14px;overflow-y:auto;background:var(--surface);border-right:1px solid var(--line)}
.shell-brand{display:flex;align-items:center;gap:9px;padding:2px 10px 8px;color:var(--ink);font-size:19px;font-weight:600;letter-spacing:-.01em;text-decoration:none}
.shell-brand i{width:9px;height:9px;margin-top:5px;background:var(--hl);border-radius:2px;transform:rotate(45deg)}
.shell-grp{display:flex;flex-direction:column;gap:1px;margin-top:4px}
.shell-gt{padding:8px 10px 4px;color:var(--faint);font-size:12px;font-weight:600;letter-spacing:.01em}
.shell-nav{position:relative;display:flex;align-items:center;gap:10px;min-height:34px;padding:0 10px;border-radius:var(--rad-ctl);color:var(--ink2);font-size:14px;text-decoration:none}
.shell-nav:hover{background:var(--surface2);color:var(--ink)}
.shell-nav.on{background:var(--raise);color:var(--ink);font-weight:600}
.shell-nav.on::before{content:"";position:absolute;left:0;top:6px;bottom:6px;width:3px;border-radius:0 2px 2px 0;background:var(--hl)}
.shell-nav svg{flex:0 0 17px;width:17px;height:17px;fill:none;stroke:currentColor;stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}
.shell-nav.on svg{color:var(--hl)}
.shell-nav .shell-cv{flex-basis:14px;width:14px;height:14px;margin-left:auto;stroke-width:1.8;color:var(--faint);transform:rotate(-90deg)}
.shell-nav.on .shell-cv{color:var(--hl);transform:none}
.shell-sub{display:flex;flex-direction:column;gap:1px;margin:2px 0 6px 18px;padding-left:8px;border-left:1px solid var(--line2)}
.shell-sub a{display:flex;align-items:center;min-height:30px;padding:0 9px;border:1px solid transparent;border-radius:var(--rad-ctl);color:var(--mut);font-size:13.5px;text-decoration:none}
.shell-sub a:hover{background:var(--surface2);color:var(--ink)}
.shell-sub a.on{background:var(--raise);border-color:var(--line2);color:var(--ink);font-weight:600}
.shell-me{margin-top:auto;padding:12px 0 0 10px;border-top:1px solid var(--line);color:var(--mut);font-size:13px}
.shell-me b{display:block;color:var(--ink);font-weight:600}
.shell-top{position:relative;z-index:30;display:flex;flex:0 0 auto;flex-wrap:wrap;align-items:center;gap:14px;min-height:var(--shell-top-h);padding:10px 28px;background:var(--surface);border-bottom:1px solid var(--line)}
.shell-crumb{display:flex;align-items:center;gap:8px;color:var(--mut);font-size:13px}
.shell-crumb b{color:var(--ink);font-weight:600}
.shell-sep{color:var(--faint)}
.shell-search{display:flex;flex:0 1 380px;align-items:center;gap:8px;height:var(--ctl);margin-left:auto;padding:0 10px;border:1px solid var(--line2);border-radius:var(--rad-ctl);background:var(--bg);color:var(--mut);font:inherit;text-align:left;cursor:pointer}
.shell-search:hover{border-color:var(--mut)}
.shell-search svg{flex:0 0 16px;width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round}
.shell-search span{flex:1;min-width:0;overflow:hidden;color:var(--faint);text-overflow:ellipsis;white-space:nowrap}
.shell-search kbd{padding:1px 6px;border:1px solid var(--line2);border-radius:3px;background:var(--surface2);color:var(--mut);font-family:var(--mds-font-family-mono);font-size:11px}
.shell-live{display:flex;align-items:center;gap:6px;color:var(--mut);font-size:13px;white-space:nowrap}
.shell-live[hidden]{display:none}
.shell-live i{width:7px;height:7px;background:var(--ok)}
.shell-live b{color:var(--ink);font-weight:600}
.shell-acct{display:flex;align-items:center;gap:12px;color:var(--ink2);font-size:13px}
.shell-user{display:inline-flex;align-items:center;gap:8px}
.shell-user svg{width:17px;height:17px;fill:none;stroke:currentColor;stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}
.shell-out{height:var(--ctl);padding:0 14px;border:1px solid var(--line2);border-radius:var(--rad-ctl);background:var(--raise);color:var(--ink);font:inherit;font-size:13px;font-weight:500;cursor:pointer}
.shell-out:hover{background:var(--surface2);border-color:var(--mut)}
.toast-container{top:calc(var(--shell-top-h) + var(--sp-4))}
.shell-side a:focus-visible,.shell-search:focus-visible,.shell-out:focus-visible{outline:2px solid var(--focus);outline-offset:-2px}
@media (max-width:820px){
html body{padding-left:0}
.shell-side{position:static;flex:0 0 auto;width:auto;flex-direction:row;flex-wrap:wrap;align-items:center;gap:4px 8px;padding:8px 12px;overflow:visible;border-right:0;border-bottom:1px solid var(--line)}
.shell-brand{padding:0 8px}
.shell-grp,.shell-sub{flex-direction:row;flex-wrap:wrap;align-items:center;margin:0;padding:0;border:0}
.shell-gt,.shell-me,.shell-cv{display:none}
.shell-top{padding:10px 16px}
.shell-search{flex-basis:100%;margin-left:0}
}
</style>)CSS";

// The shell's own behaviour on every page: fill the signed-in user and hide Settings
// from non-admins (the Settings group is hidden with its entry so no empty heading is
// left behind), open the command palette from the header search, and keep the online
// count current.
//
// Search is the existing dashboard Ctrl+K command palette, nothing new: on `/` a
// synthetic Ctrl+K keydown goes to `document` (the dashboard's own handler); anywhere
// else the dashboard's own `?palette=1` hand-off opens it. The Ctrl+K hint in the header
// is true on every page: a page with no handler of its own gets the same hand-off from a
// `window` listener, which runs after every `document` listener, so a page that binds
// Ctrl+K itself has already called preventDefault and is left alone. The hand-off also
// stands down while focus is in something you type into (a text input, textarea, select,
// contenteditable, or a role=textbox/combobox widget): navigating would throw away what was
// typed on pages that never bound the shortcut, such as the TAR SQL box.
//
// The online count is `agents.online` from GET /api/health, refreshed every 30 s and when
// the tab becomes visible. The fetch omits credentials so the server takes its cheap
// unauthenticated branch (the count is in it), is bounded to 5 s and never overlaps
// itself. The counter is hidden until the first answer and hidden again on any failed
// poll (network error, non-2xx, bad payload), never left showing a stale number.
constexpr std::string_view kShellScript = R"JS(<script>
(function(){
  function el(i){return document.getElementById(i);}
  fetch('/api/me').then(function(r){return r.json();}).then(function(d){
    var name=d.display_name||d.username||'', role=d.rbac_role||d.role||'';
    el('nav-user').textContent=name;
    el('context-user').textContent=name;
    el('role-badge').textContent=role;
    document.body.setAttribute('data-role',role);
    if(d.role!=='admin'&&role!=='Administrator'&&role!=='PlatformEngineer'){
      var sl=el('nav-settings-link');
      if(sl){sl.style.display='none';var g=sl.closest('.shell-grp');if(g)g.style.display='none';}
    }
  }).catch(function(){});

  function openPalette(){
    document.dispatchEvent(new KeyboardEvent('keydown',{key:'k',ctrlKey:true,bubbles:true,cancelable:true}));
  }
  var search=el('shell-search');
  if(search)search.addEventListener('click',function(){
    if(location.pathname==='/'){openPalette();return;}
    location.href='/?palette=1';
  });
  function typing(t){
    if(!t||t.nodeType!==1)return false;
    if(t.isContentEditable||(t.closest&&t.closest('[role=textbox],[role=combobox]')))return true;
    return t.tagName==='TEXTAREA'||t.tagName==='SELECT'||(t.tagName==='INPUT'&&!/^(button|checkbox|radio|range|file|submit|reset|image|color)$/.test(t.type));
  }
  window.addEventListener('keydown',function(e){
    if((e.ctrlKey||e.metaKey)&&e.key==='k'&&!e.defaultPrevented&&location.pathname!=='/'){
      if(typing(e.target)||typing(document.activeElement))return;
      e.preventDefault();location.href='/?palette=1';
    }
  });

  var inflight=false;
  function pollOnline(){
    if(document.hidden||inflight)return;
    inflight=true;
    Promise.resolve().then(function(){
      return fetch('/api/health',{credentials:'omit',signal:AbortSignal.timeout(5000)});
    }).then(function(r){
      if(!r.ok)throw new Error('http');
      return r.json();
    }).then(function(d){
      var n=d&&d.agents&&d.agents.online;
      if(typeof n!=='number')throw new Error('payload');
      el('shell-online-n').textContent=String(n);
      el('shell-online').hidden=false;
    }).catch(function(){el('shell-online').hidden=true;}).then(function(){inflight=false;});
  }
  document.addEventListener('visibilitychange',pollOnline);
  pollOnline();
  setInterval(pollOnline,30000);
})();
</script>)JS";

} // namespace

std::span<const NavGroup> nav_groups() {
    return kGroups;
}

std::vector<std::string> breadcrumb_trail(const ShellCtx& ctx) {
    std::vector<std::string> trail;
    const auto found = find_item(ctx.active_key);

    if (!ctx.breadcrumb.empty()) {
        // Caller-supplied parent trail: '/'-separated, trimmed, empties dropped.
        std::string_view rest = ctx.breadcrumb;
        while (!rest.empty()) {
            const auto cut = rest.find('/');
            auto part = rest.substr(0, cut);
            rest = cut == std::string_view::npos ? std::string_view{} : rest.substr(cut + 1);
            while (!part.empty() && part.front() == ' ')
                part.remove_prefix(1);
            while (!part.empty() && part.back() == ' ')
                part.remove_suffix(1);
            if (!part.empty())
                trail.emplace_back(part);
        }
    } else if (found) {
        trail.emplace_back(found->group->title);
    }

    // The leaf: the caller's title, else the active item. A title that merely repeats
    // the item's label adds nothing; a different one extends the trail past the item.
    if (!ctx.title.empty()) {
        if (found && ctx.breadcrumb.empty() && ctx.title != found->item->label)
            trail.emplace_back(found->item->label);
        trail.emplace_back(ctx.title);
    } else if (found) {
        trail.emplace_back(found->item->label);
    }
    return trail;
}

std::string render_shell(const ShellCtx& ctx) {
    std::string out;
    out.reserve(9000);
    out += kShellBegin;
    out += kShellCss;
    append_sidebar(out, ctx.active_key);
    append_header(out, ctx);
    out += kShellScript;
    out += kShellEnd;
    return out;
}

std::string apply_shell(std::string html, const ShellCtx& ctx) {
    const auto begin = html.find(kShellBegin);
    if (begin == std::string::npos)
        return html;
    const auto end = html.find(kShellEnd, begin + kShellBegin.size());
    if (end == std::string::npos)
        return html;
    html.replace(begin, end + kShellEnd.size() - begin, render_shell(ctx));
    return html;
}

const char* bake(const char* page_template, const ShellCtx& ctx) {
    // A deque never relocates elements, so earlier c_str() pointers stay valid.
    static std::mutex mu;
    static std::deque<std::string> baked;
    auto page = apply_shell(page_template, ctx);
    const std::lock_guard lock(mu);
    return baked.emplace_back(std::move(page)).c_str();
}

} // namespace yuzu::server::shell
