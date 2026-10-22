#include "pki_routes.hpp"

#include <utility>

extern const char* const kSettingsPkiHtml;

namespace yuzu::server::pki {

void register_pki_routes(HttpRouteSink& sink, Deps deps) {
    sink.Get("/settings/pki", [admin_fn = std::move(deps.admin_fn)](const httplib::Request& req,
                                                                    httplib::Response& res) {
        // Same gate and refusal as GET /settings: require_admin has written the 401/403,
        // then the browser is sent home.
        if (!admin_fn(req, res)) {
            res.set_redirect("/");
            return;
        }
        res.set_content(kSettingsPkiHtml, "text/html; charset=utf-8");
    });
}

} // namespace yuzu::server::pki
