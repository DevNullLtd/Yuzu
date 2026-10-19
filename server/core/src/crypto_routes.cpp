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
#include <mutex>
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

// The handler's own body bound and the pre-routing cap table must agree (ca_revoke precedent):
// this assert IS the enforcement of the pair - a change to either fails the build.
static_assert(resolve_body_cap("PUT", "/api/v1/crypto/dashboard/layout").max_body_bytes ==
                  cw::kLayoutBodyMaxBytes,
              "body_cap_policy.hpp's /api/v1/crypto row must mirror kLayoutBodyMaxBytes");

/// The 503 for an unwired seam: retryable (a restart or a store recovering fixes it), logged
/// ONCE per process rather than per request.
void api_unwired(httplib::Response& res) {
    static std::once_flag logged;
    std::call_once(logged, [] {
        spdlog::error("crypto routes: CryptoApi unwired - every /crypto data route answers 503");
    });
    // No retry hint (L3): an unwired seam is a wiring fault that lasts until a restart with it
    // fixed, the same posture as layouts unavailable since boot (ADR-0071).
    rest_error(res, 503, "service unavailable", false);
}

/// The Yuzu-issued counts' gate (ADR-0070 R2): fleet_read_fn Inventory:Read, then a CONFINED
/// caller is withheld - 403 naming no permission (none would admit them), audited `denied`.
/// Returns true when the request may proceed (unconfined); otherwise the answer is written.
bool ca_counts_gate(const CryptoRoutes::Deps& d, const httplib::Request& req,
                    httplib::Response& res, const std::string& cid) {
    if (gate_unwired(d.fleet_read_fn, res, false))
        return false;
    const auto gate = d.fleet_read_fn(req, res, "Inventory", "Read");
    if (!gate.admitted)
        return false; // the gate wrote 401/403/503 and its own denial row
    if (!is_confined(gate))
        return true;
    (void)detail::emit_behavioral_audit(d.audit_fn, req, res, "crypto.ca.stats.view", "denied",
                                        "Inventory", "yuzu_ca", cw::audit_detail_ca_withheld(cid));
    rest_error(res, 403, std::string(cw::kConfinedWithheldMessage));
    return false;
}

/// The Yuzu-issued drill fragment's gates: perm_fn Security:Read, then the R2 confinement
/// withhold (asked through the non-auditing access probe). A refusal or a withhold is a 200
/// note, a degraded gate a banner with Retry - never a 4xx htmx would not swap.
enum class CaGateOutcome { kAdmitted, kRefused, kConfined, kDegraded };
CaGateOutcome ca_drill_gate(const CryptoRoutes::Deps& d, const httplib::Request& req,
                            httplib::Response& res) {
    if (!d.perm_fn || !d.access_fn) {
        spdlog::error("crypto routes: perm_fn/access_fn unwired - misconfigured call site; "
                      "failing closed");
        return CaGateOutcome::kDegraded;
    }
    if (!d.perm_fn(req, res, std::string(cw::kCaDrillSecurable), std::string(cw::kCaDrillOperation))) {
        const bool degraded = res.status == 503;
        res.status = 200;
        return degraded ? CaGateOutcome::kDegraded : CaGateOutcome::kRefused;
    }
    switch (d.access_fn(req, cw::WidgetGate::kFleetWideOnly, "Inventory", "Read")) {
    case cw::Access::kConfined:
        return CaGateOutcome::kConfined;
    case cw::Access::kDegraded:
        return CaGateOutcome::kDegraded;
    case cw::Access::kAvailable:
    case cw::Access::kRefused: // no Inventory grant at all is not a confined view
        break;
    }
    return CaGateOutcome::kAdmitted;
}

/// True when a Yuzu-issued list request is a Load-more continuation (it carries a cursor, H2):
/// its response replaces a table row. Read from the raw parameter so a request that does not
/// parse still answers in the right shape.
bool is_ca_continuation(const httplib::Request& req) {
    return !req.get_param_value("cursor").empty();
}

/// The layout routes' service-scope refusal (guardian-confinement-2298 clause 4, the result-set
/// precedent in rest_api_v1.cpp): the layout is keyed by the session username, which for a
/// service-scoped token is its MINTER's - another token of the same minter would share it. 403
/// with no `.permission` (no grant would admit the token), audited `denied`.
bool deny_service_scoped(const CryptoRoutes::Deps& d, const httplib::Request& req,
                         httplib::Response& res, const auth::Session& session,
                         const std::string& action) {
    if (session.token_scope_service.empty())
        return false;
    (void)detail::emit_behavioral_audit(d.audit_fn, req, res, action, "denied", "CryptoDashboard",
                                        "", "service-scoped token refused");
    rest_error(res, 403, "service-scoped tokens may not read or change a dashboard layout");
    return true;
}

/// The MCP tier belt on the layout routes (the result-set routes' `tier_ok`): an unwired belt
/// fails closed for a tiered token only.
bool tier_ok(const CryptoRoutes::Deps& d, const httplib::Request& req, httplib::Response& res,
             const auth::Session& session, const char* operation) {
    if (d.tier_policy_fn)
        return d.tier_policy_fn(req, res, session, "Infrastructure", operation);
    if (session.mcp_tier.empty())
        return true;
    spdlog::error("crypto routes: tier_policy_fn unwired - refusing a tiered token");
    rest_error(res, 503, "tier-policy check unavailable");
    return false;
}

/// The layout read/save failure as REST: 400 invalid, 409 conflict (stale version, retry after
/// a reload), 422 corrupt stored layout (not retryable; Reset replaces it), 503 degraded or
/// outcome unknown (retryable). The version a client needs to recover rides in
/// `X-Crypto-Layout-Version` on 409 and 422.
void layout_error(httplib::Response& res, const CryptoReadError& e) {
    switch (e.kind) {
    case CryptoReadError::Kind::kInvalid:
        rest_error(res, 400, e.message);
        return;
    case CryptoReadError::Kind::kConflict:
        res.set_header("X-Crypto-Layout-Version", std::to_string(e.version));
        rest_error(res, 409, e.message);
        return;
    case CryptoReadError::Kind::kCorrupt:
        res.set_header("X-Crypto-Layout-Version", std::to_string(e.version));
        rest_error(res, 422, e.message);
        return;
    case CryptoReadError::Kind::kOutcomeUnknown:
    case CryptoReadError::Kind::kDegraded:
        // A layout store that did not open at boot lasts until a restart: no retry hint.
        rest_error(res, 503, e.message, !e.unavailable_until_restart);
        return;
    }
}

/// The audit detail suffix of a layout failure (never the username).
std::string layout_failure_detail(const CryptoReadError& e) {
    switch (e.kind) {
    case CryptoReadError::Kind::kOutcomeUnknown:
        return " outcome=unknown";
    case CryptoReadError::Kind::kConflict:
        return " outcome=conflict";
    case CryptoReadError::Kind::kCorrupt:
        return " outcome=corrupt";
    case CryptoReadError::Kind::kInvalid:
        return " outcome=invalid";
    case CryptoReadError::Kind::kDegraded:
        break;
    }
    return e.cause == CryptoReadCause::kCapacity ? " outcome=busy" : " outcome=degraded";
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
        sub("{{FRAGMENT}}", "/fragments/crypto/dashboard");
        // The chart engine, the chart adapter and the cryDash helper load on THIS page only.
        if (const auto head = html.find("</head>"); head != std::string::npos)
            html.insert(head, crypto_html::dashboard_head_html());
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

    // -- Fragment: the widget dashboard (the /crypto page body). Authentication only for the
    // layout (it chooses what is DRAWN); every card is drawn inline from at most ONE library
    // summary and ONE Yuzu-issued stats read, each behind its own data gate and audited ONCE
    // for the whole render (`widgets=<n>`), never once per card.
    sink.Get("/fragments/crypto/dashboard", [this](const httplib::Request& req,
                                                    httplib::Response& res) {
        set_private_no_store(res);
        auto session = deps_.auth_fn(req, res);
        if (!session)
            return;
        if (!deps_.api) {
            send_html(res, crypto_html::render_dashboard_unavailable());
            return;
        }
        auto layout = deps_.api->dashboard_layout(session->username);
        crypto_html::DashboardData data;
        if (!layout && layout.error().unavailable_until_restart) {
            // The layout store did not open at boot (ADR-0071 degrade posture): there is no
            // saved layout to hide, so the default is drawn - read-only, under a notice that
            // says so - rather than a Retry banner that cannot succeed until a restart.
            data.layouts_unavailable = true;
            layout = CryptoDashboardLayout{cw::default_layout_ids(), true, 0, 0};
        }
        if (!layout) {
            // Never the default served as if nothing were stored.
            if (layout.error().kind == CryptoReadError::Kind::kCorrupt)
                send_html(res, crypto_html::render_dashboard_corrupt(layout.error().version));
            else
                send_html(res, crypto_html::render_dashboard_unavailable(layout.error().cause));
            return;
        }
        cw::AccessMemo access(
            [&](cw::WidgetGate g, std::string_view s, std::string_view o) {
                return deps_.access_fn ? deps_.access_fn(req, g, std::string(s), std::string(o))
                                       : cw::Access::kDegraded;
            });
        std::size_t lib_cards = 0;
        std::size_t ca_cards = 0;
        for (const auto& id : layout->widgets)
            if (const auto* w = cw::find_widget(id); w && access.widget(*w) == cw::Access::kAvailable)
                ++(w->group == cw::WidgetGroup::kYuzuCa ? ca_cards : lib_cards);

        if ((lib_cards > 0 || ca_cards > 0) && deps_.fleet_read_fn) {
            const auto cid = detail::ensure_correlation_id(res);
            // The data gate (the auditing one - it is only reached when the probe admitted, so
            // it writes no denial row on a normal render). Its scope serves both reads: the
            // library summary is pushed into it, the Yuzu-issued counts need it unconfined.
            httplib::Response scratch;
            const auto gate = deps_.fleet_read_fn(req, scratch, "Inventory", "Read");
            if (gate.admitted && lib_cards > 0) {
                const CryptoSummaryQuery q{};
                data.library = deps_.api->library_summary(q, gate.scope);
                const bool ok = data.library->has_value();
                data.library_audit_lost = !detail::emit_behavioral_audit(
                    deps_.audit_fn, req, res, "crypto.libraries.view", ok ? "success" : "failure",
                    "Inventory", cl::audit_target(q),
                    (ok ? cl::audit_detail(cid, "all", (*data.library)->families.size(),
                                           (*data.library)->names_from_catalogue, false,
                                           is_confined(gate))
                        : cl::audit_detail_degraded(cid, data.library->error().cause,
                                                    is_confined(gate))) +
                        " widgets=" + std::to_string(lib_cards));
            }
            if (gate.admitted && !is_confined(gate) && ca_cards > 0) {
                data.ca = deps_.api->ca_stats(std::nullopt);
                const bool ok = data.ca->has_value();
                data.ca_audit_lost = !detail::emit_behavioral_audit(
                    deps_.audit_fn, req, res, "crypto.ca.stats.view", ok ? "success" : "failure",
                    "Inventory", "yuzu_ca",
                    ok ? cw::audit_detail_stats(cid, (*data.ca)->as_of, ca_cards)
                       : cw::audit_detail_ca_degraded(cid, std::nullopt, data.ca->error().cause) +
                             " widgets=" + std::to_string(ca_cards));
            }
        }
        send_html(res, crypto_html::render_dashboard(*layout, access, data));
    });

    // -- Fragment: one widget's data (a Retry, or a card just added). Library widgets gate on
    // fleet_read_fn Inventory:Read and read the family summary (audited crypto.libraries.view);
    // Yuzu-issued widgets gate on the same and are withheld from a confined caller (R2), then
    // read the stats (audited crypto.ca.stats.view). Audited per request. Always 200.
    sink.Get(R"(/fragments/crypto/widget/([a-z0-9_.]{1,64}))", [this](const httplib::Request& req,
                                                                     httplib::Response& res) {
        set_private_no_store(res);
        auto session = deps_.auth_fn(req, res);
        if (!session)
            return;
        const auto* w = cw::find_widget(req.matches[1].str());
        if (!w) {
            send_html(res, crypto_html::render_caveat("Unknown widget."));
            return;
        }
        const bool ca = w->group == cw::WidgetGroup::kYuzuCa;
        const auto cid = detail::ensure_correlation_id(res);
        if (!deps_.fleet_read_fn) {
            spdlog::error("crypto routes: fleet_read_fn unwired - misconfigured call site; "
                          "failing closed");
            send_html(res, crypto_html::render_widget_unavailable(
                               *w, CryptoReadCause::kStoreDegraded, ca));
            return;
        }
        auto gate = deps_.fleet_read_fn(req, res, "Inventory", "Read");
        if (!gate.admitted) {
            const bool degraded = res.status == 503;
            res.status = 200;
            send_html(res, degraded ? crypto_html::render_widget_unavailable(
                                          *w, CryptoReadCause::kAccessCheck, ca)
                                    : crypto_html::render_widget_not_available(
                                          *w, cw::Access::kRefused));
            return;
        }
        if (!deps_.api) {
            send_html(res, crypto_html::render_widget_unavailable(
                               *w, CryptoReadCause::kStoreDegraded, ca));
            return;
        }
        if (ca) {
            if (is_confined(gate)) {
                (void)detail::emit_behavioral_audit(deps_.audit_fn, req, res,
                                                    "crypto.ca.stats.view", "denied", "Inventory",
                                                    "yuzu_ca", cw::audit_detail_ca_withheld(cid));
                send_html(res, crypto_html::render_widget_not_available(*w, cw::Access::kConfined));
                return;
            }
            auto read = deps_.api->ca_stats(std::nullopt);
            if (!read) {
                const bool persisted = detail::emit_behavioral_audit(
                    deps_.audit_fn, req, res, "crypto.ca.stats.view", "failure", "Inventory",
                    "yuzu_ca", cw::audit_detail_ca_degraded(cid, std::nullopt, read.error().cause));
                send_html(res, (persisted ? std::string{} : crypto_html::render_audit_notice()) +
                                   crypto_html::render_widget_unavailable(*w, read.error().cause,
                                                                          true));
                return;
            }
            const bool persisted = detail::emit_behavioral_audit(
                deps_.audit_fn, req, res, "crypto.ca.stats.view", "success", "Inventory",
                "yuzu_ca", cw::audit_detail_stats(cid, read->as_of));
            send_html(res, (persisted ? std::string{} : crypto_html::render_audit_notice()) +
                               crypto_html::render_ca_widget(*w, *read));
            return;
        }
        const CryptoSummaryQuery q{};
        const std::string target = cl::audit_target(q);
        auto read = deps_.api->library_summary(q, gate.scope);
        if (!read) {
            if (read.error().kind == CryptoReadError::Kind::kInvalid) {
                send_html(res, crypto_html::render_caveat(read.error().message));
                return;
            }
            const bool persisted = detail::emit_behavioral_audit(
                deps_.audit_fn, req, res, "crypto.libraries.view", "failure", "Inventory", target,
                cl::audit_detail_degraded(cid, read.error().cause, is_confined(gate)));
            send_html(res, (persisted ? std::string{} : crypto_html::render_audit_notice()) +
                               crypto_html::render_widget_unavailable(*w, read.error().cause,
                                                                      false));
            return;
        }
        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "crypto.libraries.view", "success", "Inventory", target,
            cl::audit_detail(cid, "all", read->families.size(), read->names_from_catalogue, false,
                             is_confined(gate)));
        send_html(res, (persisted ? std::string{} : crypto_html::render_audit_notice()) +
                           crypto_html::render_library_widget(*w, *read));
    });

    // -- Fragment: the Yuzu-issued certificate drill (a continuation page when it has a cursor) -
    // the dashboard twin of the filtered GET /api/v1/ca/issued. perm_fn Security:Read, withheld
    // from a confined caller (R2); audited crypto.ca.certificates.view; always 200.
    sink.Get("/fragments/crypto/ca/certificates", [this](const httplib::Request& req,
                                                          httplib::Response& res) {
        set_private_no_store(res);
        auto session = deps_.auth_fn(req, res);
        if (!session)
            return;
        const bool row = is_ca_continuation(req);
        const auto parsed = cw::parse_cert_params(req.params);
        const std::string retry = parsed ? crypto_html::ca_certificates_url(*parsed) : std::string{};
        switch (ca_drill_gate(deps_, req, res)) {
        case CaGateOutcome::kAdmitted:
            break;
        case CaGateOutcome::kRefused:
            send_html(res, crypto_html::render_ca_caveat(crypto_html::kCaDrillNeedsSecurityRead, row));
            return;
        case CaGateOutcome::kConfined:
            send_html(res, crypto_html::render_ca_caveat(cw::kConfinedWithheldMessage, row));
            return;
        case CaGateOutcome::kDegraded:
            res.status = 200;
            send_html(res, crypto_html::render_ca_unavailable(retry, CryptoReadCause::kAccessCheck,
                                                              row));
            return;
        }
        if (!deps_.api) {
            send_html(res, crypto_html::render_ca_unavailable(retry, CryptoReadCause::kStoreDegraded,
                                                              row));
            return;
        }
        if (!parsed) {
            send_html(res, crypto_html::render_ca_caveat(parsed.error(), row));
            return;
        }
        const auto cid = detail::ensure_correlation_id(res);
        const std::string target = cw::audit_target(*parsed);
        auto read = deps_.api->ca_certificates(*parsed);
        if (!read) {
            if (read.error().kind == CryptoReadError::Kind::kInvalid) {
                send_html(res, crypto_html::render_ca_caveat(read.error().message, row));
                return;
            }
            const bool persisted = detail::emit_behavioral_audit(
                deps_.audit_fn, req, res, "crypto.ca.certificates.view", "failure", "Security",
                target, cw::audit_detail_ca_degraded(cid, parsed->as_of, read.error().cause));
            std::string notice;
            if (!persisted)
                notice = row ? crypto_html::render_ca_audit_notice_row()
                             : crypto_html::render_audit_notice();
            send_html(res, std::move(notice) +
                               crypto_html::render_ca_unavailable(retry, read.error().cause, row));
            return;
        }
        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "crypto.ca.certificates.view", "success", "Security", target,
            cw::audit_detail_certs(cid, *read));
        const bool continuation = !parsed->cursor.empty();
        std::string notice;
        if (!persisted)
            notice = continuation ? crypto_html::render_ca_audit_notice_row()
                                  : crypto_html::render_audit_notice();
        send_html(res, std::move(notice) + crypto_html::render_ca_certificates(*read, continuation));
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
        if (!deps_.access_fn) {
            spdlog::error("crypto routes: access_fn unwired - misconfigured call site; failing "
                          "closed");
            rest_error(res, 503, "service unavailable", true);
            return;
        }
        cw::AccessMemo access([&](cw::WidgetGate g, std::string_view s, std::string_view o) {
            return deps_.access_fn(req, g, std::string(s), std::string(o));
        });
        res.set_content(ok_json(cw::widgets_json(access)), "application/json");
    });

    // -- REST: GET /api/v1/crypto/dashboard/layout - the caller's OWN layout (session username).
    sink.Get("/api/v1/crypto/dashboard/layout", [this](const httplib::Request& req,
                                                        httplib::Response& res) {
        (void)detail::ensure_correlation_id(res);
        set_private_no_store(res);
        auto session = deps_.auth_fn(req, res);
        if (!session)
            return;
        if (deny_service_scoped(deps_, req, res, *session, "crypto.dashboard.layout.access_denied"))
            return;
        if (!tier_ok(deps_, req, res, *session, "Read"))
            return;
        if (!deps_.api) {
            api_unwired(res);
            return;
        }
        auto read = deps_.api->dashboard_layout(session->username);
        if (!read) {
            layout_error(res, read.error());
            return;
        }
        res.set_content(ok_json(cw::layout_json(*read)), "application/json");
    });

    // -- REST: PUT /api/v1/crypto/dashboard/layout {"widgets":[ids], "expected_version"?: n} -
    // replace the caller's OWN layout. Same-site gated; "no audit row, no mutation" (ADR-0033
    // section 9); a stale expected_version is 409.
    sink.Put("/api/v1/crypto/dashboard/layout", [this](const httplib::Request& req,
                                                        httplib::Response& res) {
        const auto cid = detail::ensure_correlation_id(res);
        set_private_no_store(res);
        auto session = deps_.auth_fn(req, res);
        if (!session)
            return;
        if (deny_service_scoped(deps_, req, res, *session, "crypto.dashboard.layout.update"))
            return;
        if (!tier_ok(deps_, req, res, *session, "Write"))
            return;
        if (deps_.write_gate.refuse_cross_site(deps_.audit_fn, req, res,
                                               "crypto.dashboard.layout.update"))
            return;
        if (req.body.size() > cw::kLayoutBodyMaxBytes) {
            rest_error(res, 413, "request body too large");
            return;
        }
        const auto body = cw::parse_layout_body(req.body);
        if (!body) {
            rest_error(res, 400, body.error());
            return;
        }
        // Judged before the attempted row: a refused layout is never a mutation attempt.
        if (const auto bad = cw::layout_error(body->widgets)) {
            rest_error(res, 400, *bad);
            return;
        }
        if (!deps_.api) {
            api_unwired(res);
            return;
        }
        const std::string target = session->username;
        const std::string detail_base =
            cw::audit_detail_layout(cid, body->widgets.size(), body->expected_version);
        if (!detail::audit_attempted(deps_.audit_fn, req, res, "crypto.dashboard.layout.update",
                                     "CryptoDashboard", target, detail_base))
            return;
        auto wrote =
            deps_.api->set_dashboard_layout(session->username, body->widgets, body->expected_version);
        if (!wrote) {
            (void)detail::emit_behavioral_audit(deps_.audit_fn, req, res,
                                                "crypto.dashboard.layout.update", "failure",
                                                "CryptoDashboard", target,
                                                detail_base + layout_failure_detail(wrote.error()));
            layout_error(res, wrote.error());
            return;
        }
        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "crypto.dashboard.layout.update", "success",
            "CryptoDashboard", target,
            cw::audit_detail_layout(cid, wrote->widgets.size(), body->expected_version) +
                " version=" + std::to_string(wrote->version));
        auto data = cw::layout_json(*wrote);
        if (!persisted)
            data["audit_persisted"] = false;
        res.set_content(ok_json(std::move(data)), "application/json");
    });

    // -- REST: GET /api/v1/crypto/ca/stats - every Yuzu-issued count against one as_of (the
    // database's now()). Inventory:Read, withheld from a confined caller (ADR-0070 R2).
    sink.Get("/api/v1/crypto/ca/stats", [this](const httplib::Request& req,
                                                httplib::Response& res) {
        const auto cid = detail::ensure_correlation_id(res);
        set_private_no_store(res);
        if (!ca_counts_gate(deps_, req, res, cid))
            return;
        if (!deps_.api) {
            api_unwired(res);
            return;
        }
        auto read = deps_.api->ca_stats(std::nullopt);
        if (!read) {
            (void)detail::emit_behavioral_audit(
                deps_.audit_fn, req, res, "crypto.ca.stats.view", "failure", "Inventory", "yuzu_ca",
                cw::audit_detail_ca_degraded(cid, std::nullopt, read.error().cause));
            rest_error(res, 503, read.error().message, true);
            return;
        }
        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "crypto.ca.stats.view", "success", "Inventory", "yuzu_ca",
            cw::audit_detail_stats(cid, read->as_of));
        auto data = cw::ca_stats_json(*read);
        if (!persisted)
            data["audit_persisted"] = false;
        res.set_content(ok_json(std::move(data)), "application/json");
    });
}

} // namespace yuzu::server
