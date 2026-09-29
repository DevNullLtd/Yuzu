#include "page_routes.hpp"

#include "agent_registry.hpp"  // real yuzu::server::detail::AgentRegistry definition
#include "http_route_sink.hpp"
#include "result_sets_ui.hpp" // yuzu::server::kResultSetsPageHtml

#include <string>
#include <string_view>

// Defined in dashboard_ui.cpp (separate TU to isolate MSVC raw-string issues).
extern const char* const kDashboardIndexHtml;

// Help and Instruction management pages (separate TUs).
extern const char* const kHelpHtml;
extern const char* const kInstructionPageHtml;
extern const char* const kTarPageHtml;
extern const char* const kVizFleetPageHtml; // server/core/src/viz_page_ui.cpp (PR 5)
extern const char* const kVizHostPageHtml;  // server/core/src/viz_host_page_ui.cpp (PR 9-pre)

// Shared design system assets (icons_svg.cpp + build-time embed targets).
extern const char* const kYuzuIconsSvg;
extern const std::string kHtmxJs;
extern const std::string kSseJs;
namespace yuzu::server {
extern const std::string kYuzuCss; // server/core/static/yuzu.css (build-time embed)
extern const std::string kYuzuChartsJs;
extern const std::string kEChartsJs; // server/core/vendor/echarts.min.js (Apache-2.0)
extern const std::string kThreeJs;   // server/core/vendor/three.module.min.js (MIT, three.js r168)
extern const std::string
    kThreeOrbitControlsJs; // server/core/vendor/three-orbit-controls.js (MIT, three.js r168)
extern const std::string
    kYuzuVizJs; // server/core/src/yuzu_viz_js_bundle.cpp (PR 5 fleet renderer module)
extern const std::string kYuzuVizHostJs; // server/core/src/yuzu_viz_host_js_bundle.cpp (PR 9-pre)
extern const std::string kCytoscapeJs;   // Cytoscape.js 3.33.3 ESM (MIT)
extern const std::string_view
    kInterVariableWoff2; // server/core/vendor/inter/InterVariable.woff2 (SIL OFL)
} // namespace yuzu::server

namespace yuzu::server::page {

void register_page_routes(HttpRouteSink& sink, Deps deps) {
    // -- Static design-system assets ----------------------------------------
    // CSS is served with no-cache so dashboard skin iteration during
    // active dev/UAT is picked up on a normal browser reload. The bundle
    // is ~22 KB; revalidation cost is negligible. Switch back to
    // max-age + content-hashed URL for prod once the skin stabilises.
    sink.Get("/static/yuzu.css", [](const httplib::Request&, httplib::Response& res) {
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(yuzu::server::kYuzuCss, "text/css; charset=utf-8");
    });
    sink.Get("/static/icons.svg", [](const httplib::Request&, httplib::Response& res) {
        res.set_header("Cache-Control", "public, max-age=3600");
        res.set_content(kYuzuIconsSvg, "image/svg+xml");
    });
    sink.Get("/static/htmx.js", [](const httplib::Request&, httplib::Response& res) {
        res.set_header("Cache-Control", "public, max-age=86400");
        res.set_content(kHtmxJs, "application/javascript; charset=utf-8");
    });
    sink.Get("/static/sse.js", [](const httplib::Request&, httplib::Response& res) {
        res.set_header("Cache-Control", "public, max-age=86400");
        res.set_content(kSseJs, "application/javascript; charset=utf-8");
    });
    // Issue #253: response visualization renderer.
    // /static/echarts.min.js is the vendored Apache ECharts 5 library
    // (Apache-2.0). /static/yuzu-charts.js is the thin Yuzu adapter
    // that maps our chart payload onto ECharts options and reads
    // Yuzu design-system CSS tokens for theming. Both are cached aggressively
    // because the bundle is content-addressed by binary version.
    sink.Get(
        "/static/echarts.min.js", [](const httplib::Request&, httplib::Response& res) {
            res.set_header("Cache-Control", "public, max-age=86400");
            res.set_content(yuzu::server::kEChartsJs, "application/javascript; charset=utf-8");
        });

    // PR 4 of feat/viz-engine: vendored Three.js r168 (MIT) + OrbitControls
    // (MIT, ES module). Modern Three.js (r150+) ships only as ES modules,
    // so PR 5's page scaffold loads these via `<script type="importmap">`
    // mapping `"three"` to `/static/three.module.min.js` and
    // `"three/addons/controls/OrbitControls.js"` to
    // `/static/three-orbit-controls.js`. Cache-Control matches the
    // ECharts pattern: public, max-age=86400, content-addressed by
    // server binary version.
    sink.Get(
        "/static/three.module.min.js", [](const httplib::Request&, httplib::Response& res) {
            res.set_header("Cache-Control", "public, max-age=86400");
            res.set_content(yuzu::server::kThreeJs, "application/javascript; charset=utf-8");
        });
    sink.Get("/static/three-orbit-controls.js",
             [](const httplib::Request&, httplib::Response& res) {
                 res.set_header("Cache-Control", "public, max-age=86400");
                 res.set_content(yuzu::server::kThreeOrbitControlsJs,
                                 "application/javascript; charset=utf-8");
             });
    // PR 5 of feat/viz-engine: yuzu-viz.js renderer module. Loaded as
    // type="module" so it can resolve the `import 'three'` bare
    // specifier through the importmap declared in viz_page_ui.cpp.
    //
    // Cache-Control: no-cache, no-store, must-revalidate -- matches the
    // /viz/fleet page shell. The renderer bundles change on every
    // feat/viz-engine PR; a `max-age` here means operators serve a
    // stale renderer (wrong tier classification, missing features,
    // outdated layout code) for up to the max-age window after a
    // server upgrade, with no signal that anything is wrong. The page
    // shell already revalidates; the bundle it pulls must too, or the
    // skew window just moves from the HTML to the JS. ~88 KB of
    // revalidated body per page load is cheap next to a silently-stale
    // renderer. Vendored libs below (cytoscape, three) keep max-age --
    // they're content-stable and only change on a deliberate refresh.
    sink.Get(
        "/static/yuzu-viz.js", [](const httplib::Request&, httplib::Response& res) {
            res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
            res.set_content(yuzu::server::kYuzuVizJs, "application/javascript; charset=utf-8");
        });

    // PR 9-pre: per-host renderer + vendored Cytoscape.js 3.33.3 (MIT).
    // yuzu-viz-host.js is the ES module entry; cytoscape.min.js is the
    // ESM minified Cytoscape bundle resolved via the importmap in
    // viz_host_page_ui.cpp. The renderer uses cytoscape's built-in
    // `cose` layout — no layout-extension asset is served.
    //
    // yuzu-viz-host.js gets the same no-cache treatment as yuzu-viz.js
    // (it's our renderer code, changes every viz PR); cytoscape.min.js
    // keeps max-age (vendored, content-stable).
    sink.Get("/static/yuzu-viz-host.js", [](const httplib::Request&,
                                            httplib::Response& res) {
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(yuzu::server::kYuzuVizHostJs, "application/javascript; charset=utf-8");
    });
    sink.Get("/static/cytoscape.min.js", [](const httplib::Request&,
                                            httplib::Response& res) {
        res.set_header("Cache-Control", "public, max-age=86400");
        res.set_content(yuzu::server::kCytoscapeJs, "application/javascript; charset=utf-8");
    });
    // Inter variable webfont (SIL OFL) — the Yuzu design system's
    // default family. Single woff2 covers all weights via font-
    // variation-settings on the @font-face declaration in
    // css_bundle.cpp.
    sink.Get("/static/fonts/InterVariable.woff2", [](const httplib::Request&,
                                                      httplib::Response& res) {
        res.set_header("Cache-Control", "public, max-age=2592000, immutable");
        // Zero-copy: pass the byte view's data+size directly so we
        // don't allocate a 345 KB std::string per fetch. (Gate 3
        // cpp-S1.) httplib's set_content(const char*, size_t, ...)
        // copies into the response buffer once.
        res.set_content(yuzu::server::kInterVariableWoff2.data(),
                        yuzu::server::kInterVariableWoff2.size(), "font/woff2");
    });

    sink.Get("/static/yuzu-charts.js", [](const httplib::Request&,
                                          httplib::Response& res) {
        res.set_header("Cache-Control", "public, max-age=86400");
        res.set_content(yuzu::server::kYuzuChartsJs, "application/javascript; charset=utf-8");
    });

    // Issue #253 fragment route lives in dashboard_routes.cpp now (#589).

    // -- Dashboard (unified UI) -------------------------------------------
    sink.Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(kDashboardIndexHtml, "text/html; charset=utf-8");
    });

    // Legacy routes — redirect to dashboard
    sink.Get("/chargen", [](const httplib::Request&, httplib::Response& res) {
        res.set_redirect("/");
    });
    sink.Get("/procfetch", [](const httplib::Request&, httplib::Response& res) {
        res.set_redirect("/");
    });

    sink.Get("/api/help", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Infrastructure", "Read"))
            return;
        if (!deps.registry) {
            res.status = 503;
            res.set_content("help registry unavailable", "text/plain; charset=utf-8");
            return;
        }
        res.set_content(deps.registry->help_json(), "application/json");
    });

    // Help table HTML fragment (HTMX)
    sink.Get("/api/help/html",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!deps.perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 if (!deps.registry) {
                     res.status = 503;
                     res.set_content("help registry unavailable", "text/plain; charset=utf-8");
                     return;
                 }
                 std::string filter;
                 if (req.has_param("filter"))
                     filter = req.get_param_value("filter");
                 res.set_content(deps.registry->help_html(filter), "text/html");
             });

    // Autocomplete HTML fragment (HTMX)
    sink.Get("/api/help/autocomplete",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!deps.perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 if (!deps.registry) {
                     res.status = 503;
                     res.set_content("help registry unavailable", "text/plain; charset=utf-8");
                     return;
                 }
                 std::string q;
                 if (req.has_param("q"))
                     q = req.get_param_value("q");
                 if (q.empty()) {
                     res.set_content("", "text/html");
                     return;
                 }
                 res.set_content(deps.registry->autocomplete_html(q), "text/html");
             });

    // Command palette instruction search HTML fragment (HTMX)
    sink.Get("/api/help/palette",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 if (!deps.perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 if (!deps.registry) {
                     res.status = 503;
                     res.set_content("help registry unavailable", "text/plain; charset=utf-8");
                     return;
                 }
                 std::string q;
                 if (req.has_param("q"))
                     q = req.get_param_value("q");
                 if (q.empty()) {
                     res.set_content("", "text/html");
                     return;
                 }
                 res.set_content(deps.registry->palette_html(q), "text/html");
             });

    // -- Help page --------------------------------------------------------
    sink.Get("/help", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(kHelpHtml, "text/html; charset=utf-8");
    });

    // -- TAR dashboard page (Phase 15.A — issue #547) --------------------
    // Auth required because the page makes HTMX calls to retention-paused
    // and (later) SQL fragment endpoints that themselves require auth +
    // RBAC; loading the page unauthenticated would just produce a blank
    // shell that immediately redirects on first fragment request. Mirror
    // the /instructions pattern.
    sink.Get("/tar", [deps](const httplib::Request& req, httplib::Response& res) {
        auto session = deps.auth_fn(req, res);
        if (!session) {
            res.set_redirect("/login");
            return;
        }
        res.set_content(kTarPageHtml, "text/html; charset=utf-8");
    });

    // ── Result Sets (scope walking — capability §30) ─────────────────
    // Page shell + HTML fragment routes. Per-operator, owner-scoped: every
    // fragment authenticates and filters/loads by the session principal.
    // Rendering lives in result_sets_ui.cpp; store I/O happens here.
    sink.Get("/result-sets",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 auto session = deps.auth_fn(req, res);
                 if (!session) {
                     res.set_redirect("/login");
                     return;
                 }
                 res.set_content(kResultSetsPageHtml, "text/html; charset=utf-8");
             });

    // PR 5 of feat/viz-engine: Fleet visualization page. Auth-gated
    // (same posture as /tar) but the per-request RBAC check happens
    // inside VizRoutes when the page's JS hits /api/v1/viz/fleet/topology.
    // The page itself is just the renderer scaffold + nav chrome -- no
    // per-machine data is rendered server-side; the JSON fetch on the
    // client is what enforces Response.Read.
    //
    // Cache-Control: no-cache, no-store, must-revalidate forces the
    // browser to revalidate the page HTML on every navigation. This
    // closes the gov R4 UP-10 / DEP-1 / CHAOS-C3 "stale page + new
    // bundle" skew window: the page references a hard-coded importmap
    // for `/static/three.module.min.js` etc. that are themselves
    // cached for 24 hours. Without revalidation, a heuristically-
    // cached stale page after a server upgrade pairs with new asset
    // bytes (or vice versa), producing a silent blank canvas with a
    // module-resolution console error.
    //
    // Future-PR ordering note (gov R4 arch-S1): if a future PR
    // introduces a regex route like `R"(/viz/([^/]+))"` for per-
    // machine drill-in, register it AFTER this literal route or the
    // first-match-wins routing in cpp-httplib would swallow `fleet`
    // as a path parameter.
    sink.Get("/viz/fleet", [deps](const httplib::Request& req, httplib::Response& res) {
        auto session = deps.auth_fn(req, res);
        if (!session) {
            res.set_redirect("/login");
            return;
        }
        // Gate 7 sec-L1 / cons-N1 — honour the kill switch on the page
        // shell, not just the REST/fragment endpoints. Previously the
        // shell rendered and only the JSON fetch 503'd, leaving the
        // operator with a half-working page and a console error. 503
        // here matches the VizRoutes posture and the invariant doc's
        // "a disabled viz surface returns 503".
        if (deps.viz_disabled && deps.viz_disabled->load(std::memory_order_acquire)) {
            res.status = 503;
            res.set_content("fleet visualization is disabled by an administrator "
                            "(--viz-disable / YUZU_VIZ_DISABLE)",
                            "text/plain; charset=utf-8");
            return;
        }
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(kVizFleetPageHtml, "text/html; charset=utf-8");
    });

    // PR 9-pre: per-host drill-down page. Opened by the 3D viz's
    // dblclick handler in a new tab. Must be registered AFTER
    // /viz/fleet (literal match wins; the regex below would otherwise
    // swallow `fleet` as a parameter — gov R4 arch-S1 ordering).
    // Agent_id is URL-decoded by httplib (req.matches[1]); we replace
    // `{{AGENT_ID}}` in the static HTML with the sanitised id so the
    // renderer can read it from data-agent-id without parsing the URL.
    // Allow-list: a-z A-Z 0-9 dash underscore dot — anything else is
    // 400 (the agent_id schema is hexadecimal-uuid-ish; nothing else
    // should reach this route).
    sink.Get(
        R"(/viz/host/([^/]+))", [deps](const httplib::Request& req, httplib::Response& res) {
            auto session = deps.auth_fn(req, res);
            if (!session) {
                res.set_redirect("/login");
                return;
            }
            // Gate 7 sec-L1 / cons-N1 — kill switch on the host
            // drill-down page shell too (cons-N1 confirmed the gap
            // spans both viz page routes, not just /viz/fleet).
            if (deps.viz_disabled && deps.viz_disabled->load(std::memory_order_acquire)) {
                res.status = 503;
                res.set_content("fleet visualization is disabled by an administrator "
                                "(--viz-disable / YUZU_VIZ_DISABLE)",
                                "text/plain; charset=utf-8");
                return;
            }
            const std::string raw_id = req.matches.size() > 1 ? req.matches[1].str() : "";
            for (char c : raw_id) {
                const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
                if (!ok) {
                    res.status = 400;
                    res.set_content("invalid agent_id", "text/plain");
                    return;
                }
            }
            std::string html(kVizHostPageHtml);
            const std::string token = "{{AGENT_ID}}";
            for (auto pos = html.find(token); pos != std::string::npos;
                 pos = html.find(token, pos + raw_id.size())) {
                html.replace(pos, token.size(), raw_id);
            }
            res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
            res.set_content(std::move(html), "text/html; charset=utf-8");
        });

    // -- Instruction management page --------------------------------------
    sink.Get("/instructions",
             [deps](const httplib::Request& req, httplib::Response& res) {
                 auto session = deps.auth_fn(req, res);
                 if (!session) {
                     res.set_redirect("/login");
                     return;
                 }
                 res.set_content(kInstructionPageHtml, "text/html; charset=utf-8");
             });
}

} // namespace yuzu::server::page
