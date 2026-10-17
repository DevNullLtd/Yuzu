/// @file crypto_routes.cpp
/// `/crypto` route registration - see crypto_routes.hpp for the auth/audit contract. The
/// markup lives in crypto_ui.cpp; parsing, JSON shaping and cursors in the shared model
/// (crypto_library_model.hpp); the read itself behind the `CryptoApi` seam.

#include "crypto_routes.hpp"

#include "app_shell.hpp"
#include "crypto_library_model.hpp"
#include "crypto_ui.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_error / ensure_correlation_id
#include "rest_audit.hpp"            // detail::emit_behavioral_audit (set-and-proceed)
#include "web_utils.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <string>
#include <utility>

// Shared full-page shell (defined at GLOBAL scope in guardian_page_ui.cpp).
extern const char* const kGuardianDetailPageHtml;

namespace yuzu::server {

namespace {

namespace cl = crypto_library;

/// A4-envelope success wrapper - a TU-local copy, as compliance_routes.cpp keeps its own.
std::string ok_json(nlohmann::json data) {
    nlohmann::json out;
    out["data"] = std::move(data);
    out["meta"] = nlohmann::json{{"api_version", "v1"}};
    return cl::dump_safe(out);
}

void send_html(httplib::Response& res, std::string body) {
    res.set_content(std::move(body), "text/html; charset=utf-8");
}

constexpr std::int64_t kRetryAfterMs = 5000;

void rest_error(httplib::Response& res, int status, const std::string& message,
                bool retryable = false) {
    res.status = status;
    res.set_content(
        retryable ? detail::a4_error(res, message, detail::A4ErrorOpts{.retry_after_ms = kRetryAfterMs})
                  : detail::a4_error(res, message),
        "application/json");
}

/// The unwired-gate fail-closed answer shared by every data route.
bool gate_unwired(const CryptoRoutes::FleetReadFn& fn, httplib::Response& res, bool html) {
    if (fn)
        return false;
    spdlog::error("crypto routes: fleet_read_fn unwired - misconfigured call site; failing closed");
    if (html) {
        res.status = 503;
        send_html(res, crypto_html::render_unavailable("Crypto library data"));
    } else {
        rest_error(res, 503, "service unavailable");
    }
    return true;
}

/// A fragment never answers a 4xx the gate wrote (htmx would not swap it): keep the gate's
/// own headers, replace status and body with a 200 caveat.
void soften_gate_denial(httplib::Response& res) {
    res.status = 200;
    send_html(res, crypto_html::render_caveat(
                       "Crypto library data is not available to this account (Inventory:Read is "
                       "required, or the access check could not be completed). Ask an "
                       "administrator, or retry shortly."));
}

std::string audit_detail(const std::string& cid, const std::string& family, std::size_t rows,
                         bool continuation) {
    return "cid=" + cid + " family=" + family + " rows=" + std::to_string(rows) +
           (continuation ? " page=continuation" : "");
}

} // namespace

void CryptoRoutes::register_routes(httplib::Server& svr, Deps deps) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(deps));
}

void CryptoRoutes::register_routes(HttpRouteSink& sink, Deps deps) {
    deps_ = std::move(deps);

    // -- Page shell: the nav-split successor pattern /software uses. Auth-only chrome; the
    // data arrives through the fragment, which carries the gate.
    sink.Get("/crypto", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = deps_.auth_fn(req, res);
        if (!session) {
            res.set_redirect("/login");
            return;
        }
        std::string html(kGuardianDetailPageHtml);
        auto sub = [&](const std::string& tok, const std::string& val) {
            for (auto p = html.find(tok); p != std::string::npos; p = html.find(tok, p + val.size()))
                html.replace(p, tok.size(), val);
        };
        sub("{{TITLE}}", "Yuzu \xE2\x80\x94 Crypto");
        sub("{{FRAGMENT}}", "/fragments/crypto/libraries");
        // The shared shell is baked with Guardian active; re-target it to Crypto.
        html = shell::apply_shell(std::move(html), {.active_key = "crypto"});
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        send_html(res, std::move(html));
    });

    // -- Fragment: family summary (the whole page body).
    sink.Get("/fragments/crypto/libraries", [this](const httplib::Request& req,
                                                    httplib::Response& res) {
        auto session = deps_.auth_fn(req, res);
        if (!session)
            return;
        if (gate_unwired(deps_.fleet_read_fn, res, true))
            return;
        auto gate = deps_.fleet_read_fn(req, res, "Inventory", "Read");
        if (!gate.admitted) {
            soften_gate_denial(res);
            return;
        }
        if (!deps_.api) {
            send_html(res, crypto_html::render_unavailable("Crypto library data"));
            return;
        }
        const auto parsed = cl::parse_summary_params(req.params);
        if (!parsed) {
            send_html(res, crypto_html::render_caveat(parsed.error()));
            return;
        }
        const auto cid = detail::ensure_correlation_id(res);
        const std::string target = cl::audit_target(*parsed);
        const std::string family = parsed->family.value_or("all");
        auto read = deps_.api->library_summary(*parsed, gate.scope);
        if (!read) {
            if (read.error().kind == CryptoReadError::Kind::kInvalid) {
                send_html(res, crypto_html::render_caveat(read.error().message));
                return;
            }
            (void)detail::emit_behavioral_audit(deps_.audit_fn, req, res, "crypto.libraries.view",
                                                "failure", "Inventory", target,
                                                "cid=" + cid + " store degraded");
            send_html(res, crypto_html::render_unavailable("Crypto library data"));
            return;
        }
        (void)detail::emit_behavioral_audit(deps_.audit_fn, req, res, "crypto.libraries.view",
                                            "success", "Inventory", target,
                                            audit_detail(cid, family, read->families.size(), false));
        send_html(res, crypto_html::render_libraries(*read));
    });

    // -- Fragment: one family's device drill (a continuation page when `cursor` is present).
    sink.Get("/fragments/crypto/libraries/devices", [this](const httplib::Request& req,
                                                            httplib::Response& res) {
        auto session = deps_.auth_fn(req, res);
        if (!session)
            return;
        if (gate_unwired(deps_.fleet_read_fn, res, true))
            return;
        auto gate = deps_.fleet_read_fn(req, res, "Inventory", "Read");
        if (!gate.admitted) {
            soften_gate_denial(res);
            return;
        }
        if (!deps_.api) {
            send_html(res, crypto_html::render_unavailable("Crypto library data"));
            return;
        }
        const auto parsed = cl::parse_devices_params(req.params);
        if (!parsed) {
            send_html(res, crypto_html::render_caveat(parsed.error()));
            return;
        }
        const auto cid = detail::ensure_correlation_id(res);
        const bool continuation = !parsed->cursor.empty();
        const std::string target = cl::audit_target(*parsed);
        auto read = deps_.api->library_devices(*parsed, gate.scope);
        if (!read) {
            if (read.error().kind == CryptoReadError::Kind::kInvalid) {
                send_html(res, crypto_html::render_caveat(read.error().message));
                return;
            }
            (void)detail::emit_behavioral_audit(deps_.audit_fn, req, res, "crypto.libraries.devices",
                                                "failure", "Inventory", target,
                                                "cid=" + cid + " store degraded");
            send_html(res, crypto_html::render_unavailable("Crypto library devices"));
            return;
        }
        (void)detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "crypto.libraries.devices", "success", "Inventory", target,
            audit_detail(cid, parsed->family, read->devices.size(), continuation));
        send_html(res, crypto_html::render_devices(*parsed, *read, continuation));
    });

    // -- REST: GET /api/v1/crypto/libraries[?family=&ecosystem=]
    sink.Get("/api/v1/crypto/libraries", [this](const httplib::Request& req,
                                                 httplib::Response& res) {
        const auto cid = detail::ensure_correlation_id(res);
        if (gate_unwired(deps_.fleet_read_fn, res, false))
            return;
        // The gate renders 401/403/503 itself and returns !admitted on denial.
        auto gate = deps_.fleet_read_fn(req, res, "Inventory", "Read");
        if (!gate.admitted)
            return;
        if (!deps_.api) {
            rest_error(res, 503, "service unavailable");
            return;
        }
        const auto parsed = cl::parse_summary_params(req.params);
        if (!parsed) {
            rest_error(res, 400, parsed.error());
            return;
        }
        const std::string target = cl::audit_target(*parsed);
        auto read = deps_.api->library_summary(*parsed, gate.scope);
        if (!read) {
            if (read.error().kind == CryptoReadError::Kind::kInvalid) {
                rest_error(res, 400, read.error().message);
                return;
            }
            (void)detail::emit_behavioral_audit(deps_.audit_fn, req, res, "crypto.libraries.view",
                                                "failure", "Inventory", target,
                                                "cid=" + cid + " store degraded");
            rest_error(res, 503, "crypto library read degraded", true);
            return;
        }
        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "crypto.libraries.view", "success", "Inventory", target,
            audit_detail(cid, parsed->family.value_or("all"), read->families.size(), false));
        auto data = cl::summary_json(*read);
        if (!persisted)
            data["audit_persisted"] = false;
        res.set_content(ok_json(std::move(data)), "application/json");
    });

    // -- REST: GET /api/v1/crypto/libraries/devices?family=(req)&version=&ecosystem=&cursor=&limit=
    sink.Get("/api/v1/crypto/libraries/devices", [this](const httplib::Request& req,
                                                         httplib::Response& res) {
        const auto cid = detail::ensure_correlation_id(res);
        if (gate_unwired(deps_.fleet_read_fn, res, false))
            return;
        auto gate = deps_.fleet_read_fn(req, res, "Inventory", "Read");
        if (!gate.admitted)
            return;
        if (!deps_.api) {
            rest_error(res, 503, "service unavailable");
            return;
        }
        const auto parsed = cl::parse_devices_params(req.params);
        if (!parsed) {
            rest_error(res, 400, parsed.error());
            return;
        }
        const bool continuation = !parsed->cursor.empty();
        const std::string target = cl::audit_target(*parsed);
        auto read = deps_.api->library_devices(*parsed, gate.scope);
        if (!read) {
            if (read.error().kind == CryptoReadError::Kind::kInvalid) {
                rest_error(res, 400, read.error().message);
                return;
            }
            (void)detail::emit_behavioral_audit(deps_.audit_fn, req, res, "crypto.libraries.devices",
                                                "failure", "Inventory", target,
                                                "cid=" + cid + " store degraded");
            rest_error(res, 503, "crypto library read degraded", true);
            return;
        }
        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "crypto.libraries.devices", "success", "Inventory", target,
            audit_detail(cid, parsed->family, read->devices.size(), continuation));
        auto data = cl::devices_json(*read);
        if (!persisted)
            data["audit_persisted"] = false;
        res.set_content(ok_json(std::move(data)), "application/json");
    });
}

} // namespace yuzu::server
