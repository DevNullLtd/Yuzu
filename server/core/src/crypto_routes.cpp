/// @file crypto_routes.cpp
/// `/crypto` route registration - see crypto_routes.hpp for the auth/audit contract. The
/// markup lives in crypto_ui.cpp; parsing, JSON shaping and cursors in the shared model
/// (crypto_library_model.hpp); the read itself behind the `CryptoApi` seam.

#include "crypto_routes.hpp"

#include "app_shell.hpp"
#include "body_cap_policy.hpp" // the pre-routing twin of kLayoutBodyMaxBytes (static_assert below)
#include "crypto_library_model.hpp"
#include "crypto_ui.hpp"
#include "crypto_widget_catalogue.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_error / ensure_correlation_id
#include "rest_audit.hpp"            // detail::emit_behavioral_audit (set-and-proceed)
#include "web_utils.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
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

/// The unwired-gate fail-closed answer shared by every data route. `summary` = the summary
/// fragment, whose banner replaces the whole page body and so carries the component CSS.
bool gate_unwired(const CryptoRoutes::FleetReadFn& fn, httplib::Response& res, bool html,
                  bool summary = false) {
    if (fn)
        return false;
    spdlog::error("crypto routes: fleet_read_fn unwired - misconfigured call site; failing closed");
    if (html) {
        res.status = 503;
        send_html(res, summary ? crypto_html::render_summary_unavailable("Crypto library data")
                               : crypto_html::render_unavailable("Crypto library data"));
    } else {
        rest_error(res, 503, "service unavailable");
    }
    return true;
}

/// The four scoped data routes answer per-caller, scope-filtered data: never cached by a shared
/// cache, and keyed by any private one on every credential the caller can present (session
/// cookie, bearer token, X-Yuzu-Token API token), as discover_routes.cpp does. One helper for
/// all four, so the fragments carry the full set too.
void set_private_no_store(httplib::Response& res) {
    res.set_header("Cache-Control", "no-store, private");
    res.set_header("Vary", "Authorization, Cookie, X-Yuzu-Token");
}

/// True when the gate handed back a filtered VisibleSet (ADR-0017 INV-9 audit token).
bool is_confined(const authz::FleetReadGate& gate) { return gate.scope.has_value(); }

/// True when the request is a Load-more continuation (its response replaces a table row).
bool is_continuation(const httplib::Request& req) {
    return !req.get_param_value("cursor").empty();
}

/// A fragment never answers a 4xx/5xx the gate wrote (htmx would not swap it): keep the gate's
/// own headers, replace status and body with a 200 note. A gate that DEGRADED (it answered 503:
/// the RBAC, management-group or tag store could not be read) renders the "unavailable" banner with Retry - an outage must
/// not read as "not allowed" - worded for the ACCESS CHECK (kAccessCheck), never as an inventory
/// store fault (review #6109); only a genuine refusal says "not available to this account". A
/// continuation page gets a single table row, never a block that replaces the Load-more <tr>.
void soften_gate_denial(const httplib::Request& req, httplib::Response& res, bool devices) {
    const bool degraded = res.status == 503;
    const bool row = devices && is_continuation(req);
    res.status = 200;
    if (degraded) {
        if (!devices) {
            send_html(res, crypto_html::render_summary_unavailable("Crypto library data",
                                                                   CryptoReadCause::kAccessCheck));
            return;
        }
        // A devices request that parses retries itself (a continuation row, or the first-page
        // drill into its own box); one that does not has nothing to retry.
        const auto q = cl::parse_devices_params(req.params);
        if (row)
            send_html(res, q ? crypto_html::render_unavailable_row(
                                   "Crypto library devices", crypto_html::devices_page_url(*q),
                                   CryptoReadCause::kAccessCheck)
                             : crypto_html::render_caveat_row("Crypto library devices unavailable."));
        else
            send_html(res, q ? crypto_html::render_unavailable_drill("Crypto library devices", *q,
                                                                     CryptoReadCause::kAccessCheck)
                             : crypto_html::render_caveat("Crypto library devices unavailable."));
        return;
    }
    constexpr std::string_view kMsg =
        "Crypto library data is not available to this account (Inventory:Read is required). Ask "
        "an administrator.";
    send_html(res, row       ? crypto_html::render_caveat_row(kMsg)
                   : devices ? crypto_html::render_caveat(kMsg)
                             : crypto_html::render_summary_caveat(kMsg));
}

namespace cw = crypto_widgets;

// The handler's own body bound and the pre-routing cap table must agree (ca_revoke precedent).
static_assert(resolve_body_cap("PUT", "/api/v1/crypto/dashboard/layout").max_body_bytes ==
                  cw::kLayoutBodyMaxBytes,
              "body_cap_policy.hpp's /api/v1/crypto row must mirror kLayoutBodyMaxBytes");

/// The server clock every Yuzu-issued window of one request is computed against (D13: the
/// server's clock at read time, echoed back as `as_of`). Read ONCE per request.
std::int64_t read_clock_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

/// The Yuzu-issued routes' gate: `perm_fn` Security:Read, failing closed when unwired. Returns
/// true when the request may proceed; otherwise the 401/403/503 is written.
bool ca_gate(const CryptoRoutes::PermFn& fn, const httplib::Request& req, httplib::Response& res) {
    if (!fn) {
        spdlog::error("crypto routes: perm_fn unwired - misconfigured call site; failing closed");
        rest_error(res, 503, "service unavailable");
        return false;
    }
    return fn(req, res, "Security", "Read");
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
        set_private_no_store(res);
        auto session = deps_.auth_fn(req, res);
        if (!session)
            return;
        if (gate_unwired(deps_.fleet_read_fn, res, true, /*summary=*/true))
            return;
        auto gate = deps_.fleet_read_fn(req, res, "Inventory", "Read");
        if (!gate.admitted) {
            soften_gate_denial(req, res, false);
            return;
        }
        if (!deps_.api) {
            send_html(res, crypto_html::render_summary_unavailable("Crypto library data"));
            return;
        }
        const auto parsed = cl::parse_summary_params(req.params);
        if (!parsed) {
            send_html(res, crypto_html::render_summary_caveat(parsed.error()));
            return;
        }
        const auto cid = detail::ensure_correlation_id(res);
        const std::string target = cl::audit_target(*parsed);
        const std::string family = parsed->family.value_or("all");
        auto read = deps_.api->library_summary(*parsed, gate.scope);
        if (!read) {
            if (read.error().kind == CryptoReadError::Kind::kInvalid) {
                send_html(res, crypto_html::render_summary_caveat(read.error().message));
                return;
            }
            // Set-and-proceed, but a lost row is VISIBLE: the Sec-Audit-Failed header (set by
            // the helper) AND an on-page notice (UP-8).
            const bool persisted = detail::emit_behavioral_audit(
                deps_.audit_fn, req, res, "crypto.libraries.view", "failure", "Inventory", target,
                cl::audit_detail_degraded(cid, read.error().cause, is_confined(gate)));
            send_html(res, crypto_html::render_summary_unavailable(
                               "Crypto library data", read.error().cause, !persisted));
            return;
        }
        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "crypto.libraries.view", "success", "Inventory", target,
            cl::audit_detail(cid, family, read->families.size(), read->names_from_catalogue, false,
                             is_confined(gate)));
        send_html(res, (persisted ? std::string{} : crypto_html::render_audit_notice()) +
                           crypto_html::render_libraries(*read));
    });

    // -- Fragment: one family's device drill (a continuation page when `cursor` is present).
    sink.Get("/fragments/crypto/libraries/devices", [this](const httplib::Request& req,
                                                            httplib::Response& res) {
        set_private_no_store(res);
        auto session = deps_.auth_fn(req, res);
        if (!session)
            return;
        if (gate_unwired(deps_.fleet_read_fn, res, true))
            return;
        auto gate = deps_.fleet_read_fn(req, res, "Inventory", "Read");
        if (!gate.admitted) {
            soften_gate_denial(req, res, true);
            return;
        }
        const bool row = is_continuation(req);
        // A continuation response replaces the Load-more <tr>: every non-table answer is a row.
        // Retry re-requests the same page: the continuation row its own cursor page, a first
        // page its own drill into the family's box (never the summary). `prefix` carries the
        // audit-loss notice when the failure row did not persist.
        auto fail_unavailable = [&](CryptoReadCause cause = CryptoReadCause::kStoreDegraded,
                                    std::string prefix = {}) {
            const auto q = cl::parse_devices_params(req.params);
            if (row)
                send_html(res, std::move(prefix) +
                                   (q ? crypto_html::render_unavailable_row(
                                            "Crypto library devices",
                                            crypto_html::devices_page_url(*q), cause)
                                      : crypto_html::render_caveat_row(
                                            "Crypto library devices unavailable.")));
            else
                send_html(res, std::move(prefix) +
                                   (q ? crypto_html::render_unavailable_drill(
                                            "Crypto library devices", *q, cause)
                                      : crypto_html::render_unavailable("Crypto library devices",
                                                                        cause)));
        };
        auto fail_note = [&](std::string_view m) {
            send_html(res, row ? crypto_html::render_caveat_row(m) : crypto_html::render_caveat(m));
        };
        if (!deps_.api) {
            fail_unavailable();
            return;
        }
        const auto parsed = cl::parse_devices_params(req.params);
        if (!parsed) {
            fail_note(parsed.error());
            return;
        }
        const auto cid = detail::ensure_correlation_id(res);
        const bool continuation = !parsed->cursor.empty();
        const std::string target = cl::audit_target(*parsed);
        auto read = deps_.api->library_devices(*parsed, gate.scope);
        if (!read) {
            if (read.error().kind == CryptoReadError::Kind::kInvalid) {
                fail_note(read.error().message);
                return;
            }
            const bool persisted = detail::emit_behavioral_audit(
                deps_.audit_fn, req, res, "crypto.libraries.devices", "failure", "Inventory",
                target, cl::audit_detail_degraded(cid, read.error().cause, is_confined(gate)));
            fail_unavailable(read.error().cause,
                             persisted ? std::string{}
                                       : (row ? crypto_html::render_audit_notice_row()
                                              : crypto_html::render_audit_notice()));
            return;
        }
        // Set-and-proceed with a VISIBLE loss (UP-8): the header plus an on-page notice - a
        // table row on a continuation page, which replaces the Load-more <tr>.
        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "crypto.libraries.devices", "success", "Inventory", target,
            cl::audit_detail(cid, parsed->family, read->devices.size(), read->names_from_catalogue,
                             continuation, is_confined(gate)));
        std::string notice;
        if (!persisted)
            notice = continuation ? crypto_html::render_audit_notice_row()
                                  : crypto_html::render_audit_notice();
        send_html(res, std::move(notice) + crypto_html::render_devices(*parsed, *read, continuation));
    });

    // -- REST: GET /api/v1/crypto/libraries[?family=&ecosystem=]
    sink.Get("/api/v1/crypto/libraries", [this](const httplib::Request& req,
                                                 httplib::Response& res) {
        const auto cid = detail::ensure_correlation_id(res);
        set_private_no_store(res);
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
            (void)detail::emit_behavioral_audit(
                deps_.audit_fn, req, res, "crypto.libraries.view", "failure", "Inventory", target,
                cl::audit_detail_degraded(cid, read.error().cause, is_confined(gate)));
            rest_error(res, 503, std::string(cl::degraded_message(read.error().cause)), true);
            return;
        }
        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "crypto.libraries.view", "success", "Inventory", target,
            cl::audit_detail(cid, parsed->family.value_or("all"), read->families.size(),
                             read->names_from_catalogue, false, is_confined(gate)));
        auto data = cl::summary_json(*read);
        if (!persisted)
            data["audit_persisted"] = false;
        res.set_content(ok_json(std::move(data)), "application/json");
    });

    // -- REST: GET /api/v1/crypto/libraries/devices?family=(req)&version=&ecosystem=&cursor=&limit=
    sink.Get("/api/v1/crypto/libraries/devices", [this](const httplib::Request& req,
                                                         httplib::Response& res) {
        const auto cid = detail::ensure_correlation_id(res);
        set_private_no_store(res);
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
            (void)detail::emit_behavioral_audit(
                deps_.audit_fn, req, res, "crypto.libraries.devices", "failure", "Inventory",
                target, cl::audit_detail_degraded(cid, read.error().cause, is_confined(gate)));
            rest_error(res, 503, std::string(cl::degraded_message(read.error().cause)), true);
            return;
        }
        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "crypto.libraries.devices", "success", "Inventory", target,
            cl::audit_detail(cid, parsed->family, read->devices.size(), read->names_from_catalogue,
                             continuation, is_confined(gate)));
        auto data = cl::devices_json(*read);
        if (!persisted)
            data["audit_persisted"] = false;
        res.set_content(ok_json(std::move(data)), "application/json");
    });

    // -- REST: GET /api/v1/crypto/widgets - the widget catalogue with the caller's availability.
    // Not audited: it serves the static catalogue and the caller's own permission answers.
    sink.Get("/api/v1/crypto/widgets", [this](const httplib::Request& req,
                                               httplib::Response& res) {
        (void)detail::ensure_correlation_id(res);
        set_private_no_store(res);
        auto session = deps_.auth_fn(req, res);
        if (!session)
            return;
        if (!deps_.has_perm_fn) {
            spdlog::error("crypto routes: has_perm_fn unwired - misconfigured call site; failing "
                          "closed");
            rest_error(res, 503, "service unavailable");
            return;
        }
        auto data = cw::widgets_json([&](std::string_view s, std::string_view o) {
            return deps_.has_perm_fn(req, std::string(s), std::string(o));
        });
        res.set_content(ok_json(std::move(data)), "application/json");
    });

    // -- REST: GET /api/v1/crypto/dashboard/layout - the caller's OWN layout (session username).
    sink.Get("/api/v1/crypto/dashboard/layout", [this](const httplib::Request& req,
                                                        httplib::Response& res) {
        (void)detail::ensure_correlation_id(res);
        set_private_no_store(res);
        auto session = deps_.auth_fn(req, res);
        if (!session)
            return;
        if (!deps_.api) {
            rest_error(res, 503, "service unavailable");
            return;
        }
        auto read = deps_.api->dashboard_layout(session->username);
        if (!read) {
            if (read.error().kind == CryptoReadError::Kind::kInvalid)
                rest_error(res, 400, read.error().message);
            else
                rest_error(res, 503, read.error().message, true);
            return;
        }
        res.set_content(ok_json(cw::layout_json(*read)), "application/json");
    });

    // -- REST: PUT /api/v1/crypto/dashboard/layout {"widgets":[ids]} - replace the caller's OWN
    // layout. Same-site gated; "no audit row, no mutation" (ADR-0033 section 9).
    sink.Put("/api/v1/crypto/dashboard/layout", [this](const httplib::Request& req,
                                                        httplib::Response& res) {
        const auto cid = detail::ensure_correlation_id(res);
        set_private_no_store(res);
        auto session = deps_.auth_fn(req, res);
        if (!session)
            return;
        if (deps_.write_gate.refuse_cross_site(deps_.audit_fn, req, res,
                                               "crypto.dashboard.layout.update"))
            return;
        if (req.body.size() > cw::kLayoutBodyMaxBytes) {
            rest_error(res, 413, "request body too large");
            return;
        }
        const auto ids = cw::parse_layout_body(req.body);
        if (!ids) {
            rest_error(res, 400, ids.error());
            return;
        }
        // Judged before the attempted row: a refused layout is never a mutation attempt.
        if (const auto bad = cw::layout_error(*ids)) {
            rest_error(res, 400, *bad);
            return;
        }
        if (!deps_.api) {
            rest_error(res, 503, "service unavailable");
            return;
        }
        const std::string target = session->username;
        if (!detail::audit_attempted(deps_.audit_fn, req, res, "crypto.dashboard.layout.update",
                                     "CryptoDashboard", target,
                                     cw::audit_detail_layout(cid, ids->size())))
            return;
        auto wrote = deps_.api->set_dashboard_layout(session->username, *ids);
        if (!wrote) {
            (void)detail::emit_behavioral_audit(deps_.audit_fn, req, res,
                                                "crypto.dashboard.layout.update", "failure",
                                                "CryptoDashboard", target,
                                                cw::audit_detail_layout(cid, ids->size()) + " " +
                                                    wrote.error().message);
            if (wrote.error().kind == CryptoReadError::Kind::kInvalid)
                rest_error(res, 400, wrote.error().message);
            else
                rest_error(res, 503, wrote.error().message, true);
            return;
        }
        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "crypto.dashboard.layout.update", "success",
            "CryptoDashboard", target, cw::audit_detail_layout(cid, wrote->widgets.size()));
        auto data = cw::layout_json(*wrote);
        if (!persisted)
            data["audit_persisted"] = false;
        res.set_content(ok_json(std::move(data)), "application/json");
    });

    // -- REST: GET /api/v1/crypto/ca/stats - every Yuzu-issued count against one as_of.
    sink.Get("/api/v1/crypto/ca/stats", [this](const httplib::Request& req,
                                                httplib::Response& res) {
        const auto cid = detail::ensure_correlation_id(res);
        set_private_no_store(res);
        if (!ca_gate(deps_.perm_fn, req, res))
            return;
        if (!deps_.api) {
            rest_error(res, 503, "service unavailable");
            return;
        }
        const std::int64_t as_of = read_clock_epoch();
        auto read = deps_.api->ca_stats(as_of);
        if (!read) {
            (void)detail::emit_behavioral_audit(
                deps_.audit_fn, req, res, "crypto.ca.stats.view", "failure", "Security", "yuzu_ca",
                cw::audit_detail_ca_degraded(cid, as_of, read.error().cause));
            rest_error(res, 503, read.error().message, true);
            return;
        }
        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "crypto.ca.stats.view", "success", "Security", "yuzu_ca",
            cw::audit_detail_stats(cid, as_of));
        auto data = cw::ca_stats_json(*read);
        if (!persisted)
            data["audit_persisted"] = false;
        res.set_content(ok_json(std::move(data)), "application/json");
    });

    // -- REST: GET /api/v1/crypto/ca/certificates?kind=&days=&week=&limit=&offset=
    sink.Get("/api/v1/crypto/ca/certificates", [this](const httplib::Request& req,
                                                       httplib::Response& res) {
        const auto cid = detail::ensure_correlation_id(res);
        set_private_no_store(res);
        if (!ca_gate(deps_.perm_fn, req, res))
            return;
        if (!deps_.api) {
            rest_error(res, 503, "service unavailable");
            return;
        }
        const auto parsed = cw::parse_cert_params(req.params);
        if (!parsed) {
            rest_error(res, 400, parsed.error());
            return;
        }
        const std::int64_t as_of = read_clock_epoch();
        const std::string target = cw::audit_target(*parsed);
        auto read = deps_.api->ca_certificates(*parsed, as_of);
        if (!read) {
            if (read.error().kind == CryptoReadError::Kind::kInvalid) {
                rest_error(res, 400, read.error().message);
                return;
            }
            (void)detail::emit_behavioral_audit(
                deps_.audit_fn, req, res, "crypto.ca.certificates.view", "failure", "Security",
                target, cw::audit_detail_ca_degraded(cid, as_of, read.error().cause));
            rest_error(res, 503, read.error().message, true);
            return;
        }
        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "crypto.ca.certificates.view", "success", "Security", target,
            cw::audit_detail_certs(cid, *read));
        auto data = cw::ca_page_json(*read);
        if (!persisted)
            data["audit_persisted"] = false;
        res.set_content(ok_json(std::move(data)), "application/json");
    });
}

} // namespace yuzu::server
