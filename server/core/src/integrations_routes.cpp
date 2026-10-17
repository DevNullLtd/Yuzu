#include "integrations_routes.hpp"

#include <string>

// The baked page (integrations_ui.cpp, global scope like kSettingsHtml) and the embedded
// script (static/yuzu-integrations.js through embed_js.py).
extern const char* const kSettingsIntegrationsHtml;
namespace yuzu::server {
extern const std::string kYuzuIntegrationsJs;
}

namespace yuzu::server::integrations {

void register_integrations_routes(HttpRouteSink& sink, Deps deps) {
    sink.Get("/settings/integrations", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.admin_fn(req, res)) {
            res.set_redirect("/");
            return;
        }
        res.set_header("Cache-Control", "no-store");
        res.set_content(kSettingsIntegrationsHtml, "text/html; charset=utf-8");
    });

    // Our own page script: revalidated like yuzu-viz.js, so an upgrade never leaves the
    // page running an older script against newer markup.
    sink.Get("/static/yuzu-integrations.js", [](const httplib::Request&, httplib::Response& res) {
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(yuzu::server::kYuzuIntegrationsJs, "application/javascript; charset=utf-8");
    });
}

} // namespace yuzu::server::integrations
