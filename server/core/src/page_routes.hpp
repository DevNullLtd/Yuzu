#pragma once

/// @file page_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542) so these handlers are testable via the in-process
/// TestRouteSink harness (#438: a real acceptor thread crashes under TSan).
/// Pure page-shell / static-asset surface — no store, no mutation, no
/// audit trail. Every handler body is copied verbatim from server.cpp; the
/// changes are the receiver (`web_server_->` -> `sink.`), the gate closures
/// (`require_auth`/`require_permission` -> `deps.auth_fn`/`deps.perm_fn`),
/// member accesses (`registry_.` -> `deps.registry->`, `viz_disabled_.load(...)`
/// -> the null-guarded `deps.viz_disabled && deps.viz_disabled->load(...)`
/// idiom, matching viz_routes.cpp's `kill_switch_`), and one deliberate
/// non-verbatim addition: the four `/api/help*` handlers gained a leading
/// `!deps.registry` 503 check that has no counterpart in the original code
/// (`registry_` there was a value member, never null) — required because
/// `Deps::registry` is a pointer that CAN be null. This runs before any
/// per-request logic, so a null registry now 503s even a request that would
/// not have touched the registry (e.g. an empty `?q=`).
///
/// Routes (25) — gate in parens, `-` = no gate:
///   GET /static/yuzu.css                    -
///   GET /static/icons.svg                   -
///   GET /static/htmx.js                     -
///   GET /static/sse.js                      -
///   GET /static/echarts.min.js              -
///   GET /static/three.module.min.js         -
///   GET /static/three-orbit-controls.js     -
///   GET /static/yuzu-viz.js                 -
///   GET /static/yuzu-viz-host.js            -
///   GET /static/cytoscape.min.js            -
///   GET /static/fonts/InterVariable.woff2   -
///   GET /static/yuzu-charts.js              -
///   GET /                                   -                      (dashboard shell)
///   GET /chargen                            -                      (302 -> /)
///   GET /procfetch                          -                      (302 -> /)
///   GET /api/help                           (perm_fn Infrastructure:Read)
///   GET /api/help/html                      (perm_fn Infrastructure:Read)
///   GET /api/help/autocomplete              (perm_fn Infrastructure:Read)
///   GET /api/help/palette                   (perm_fn Infrastructure:Read)
///   GET /help                               -
///   GET /tar                                (auth_fn)
///   GET /result-sets                        (auth_fn)
///   GET /viz/fleet                          (auth_fn + viz kill switch)
///   GET /viz/host/:agent_id                 (auth_fn + viz kill switch)
///   GET /instructions                       (auth_fn)
///
/// ORDERING: `/viz/fleet` is registered before `/viz/host/([^/]+)` — see the
/// comment carried over onto that registration in page_routes.cpp. Today's
/// regex requires a literal `host/` segment, so it cannot in fact collide
/// with `/viz/fleet` regardless of order (governance #2542, 3-way
/// convergence: architect/happy-path/unhappy-path independently confirmed
/// the ordering isn't currently load-bearing). Kept anyway as a
/// forward-compatibility guard against a future, broader pattern like
/// `R"(/viz/([^/]+))"`, which WOULD swallow `fleet` as a path parameter if
/// registered first — preserve this order if such a route is ever added.

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <atomic>
#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

class HttpRouteSink;

namespace detail {
class AgentRegistry;
} // namespace detail

namespace page {

/// Construction deps for `register_page_routes`. Every closure/pointer is
/// bound once at start_web_server() time in server.cpp and never reseated.
struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                       const std::string&, const std::string&)>;

    AuthFn auth_fn;
    PermFn perm_fn;
    /// Viz kill switch (`ServerImpl::viz_disabled_`, `--viz-disable` /
    /// YUZU_VIZ_DISABLE; see docs/fleet-viz-invariants.md). Null-safe: a
    /// null pointer is treated as "not disabled" (matches viz_routes.cpp's
    /// `kill_switch_ && kill_switch_->load(...)` idiom) — never assume
    /// non-null.
    const std::atomic<bool>* viz_disabled{nullptr};
    /// `ServerImpl::registry_`. Null -> the `/api/help*` routes fail closed
    /// (503) rather than dereferencing a null pointer.
    const yuzu::server::detail::AgentRegistry* registry{nullptr};
};

/// Register all 25 page-shell / static-asset routes against `sink`.
void register_page_routes(HttpRouteSink& sink, Deps deps);

} // namespace page
} // namespace yuzu::server
