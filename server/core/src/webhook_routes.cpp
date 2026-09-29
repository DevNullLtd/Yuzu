#include "webhook_routes.hpp"

#include "rest_a4_envelope_http.hpp" // detail::a4_error

#include <nlohmann/json.hpp>

namespace yuzu::server {

namespace {

// Gov Gate 4 consistency-auditor: the store layer distinguishes
// store_unavailable (pool exhausted / codec unavailable) from db_error (a
// query against an open store failed) precisely so a 503's audit row can
// tell an incident investigator which one happened — collapsing both to a
// single "db_error" literal discarded that distinction on the audit path
// alone (the HTTP status/body were already correctly identical for both,
// per the #3097 classification: both are 503).
std::string_view audit_detail_for(WebhookWriteError err) {
    switch (err) {
    case WebhookWriteError::invalid_url:
        return "invalid_url";
    case WebhookWriteError::store_unavailable:
        return "store_unavailable";
    case WebhookWriteError::db_error:
        return "db_error";
    }
    return "db_error"; // unreachable; keeps the prior collapsed behavior as a floor
}

void mount(HttpRouteSink& sink, WebhookRoutes::PermFn perm_fn, WebhookRoutes::AuditFn audit_fn,
          WebhookRoutes::EmitEventFn emit_event_fn, WebhookStore* webhook_store) {
    // GET /api/webhooks — list all webhooks
    sink.Get("/api/webhooks",
            [perm_fn, webhook_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Infrastructure", "Read"))
                    return;
                if (!webhook_store || !webhook_store->is_open()) {
                    res.status = 503;
                    res.set_content(detail::a4_error(res, "webhook store unavailable"),
                                    "application/json");
                    return;
                }
                // list() is type-distinguishable (ADR-0036/postgres-store-
                // playbook policy) — nullopt is a degraded read, never
                // silently rendered as "no webhooks configured" (ADR-0057).
                auto webhooks = webhook_store->list();
                if (!webhooks) {
                    res.status = 503;
                    res.set_content(detail::a4_error(res, "webhook store degraded"),
                                    "application/json");
                    return;
                }
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& w : *webhooks) {
                    arr.push_back({{"id", w.id},
                                   {"url", w.url},
                                   {"event_types", w.event_types},
                                   {"has_secret", w.has_secret},
                                   {"enabled", w.enabled},
                                   {"created_at", w.created_at}});
                    // Intentionally omit the secret (encrypted or otherwise)
                    // from every list response — has_secret is the
                    // non-sensitive signal.
                }
                res.set_content(nlohmann::json({{"webhooks", arr}}).dump(),
                                "application/json");
            });

    // POST /api/webhooks — create a new webhook
    sink.Post("/api/webhooks",
             [perm_fn, audit_fn, emit_event_fn, webhook_store](const httplib::Request& req,
                                                                httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Write"))
                     return;
                 if (!webhook_store || !webhook_store->is_open()) {
                     res.status = 503;
                     res.set_content(detail::a4_error(res, "webhook store unavailable"),
                                     "application/json");
                     return;
                 }
                 nlohmann::json body;
                 try {
                     body = nlohmann::json::parse(req.body);
                 } catch (...) {
                     audit_fn(req, "webhook.create", "failure", "webhook", "", "invalid_json");
                     res.status = 400;
                     res.set_content(detail::a4_error(res, "invalid JSON"), "application/json");
                     return;
                 }
                 auto url = body.value("url", "");
                 if (url.empty()) {
                     audit_fn(req, "webhook.create", "failure", "webhook", "", "url_required");
                     res.status = 400;
                     res.set_content(detail::a4_error(res, "url is required"), "application/json");
                     return;
                 }
                 auto event_types = body.value("event_types", "*");
                 auto secret = body.value("secret", "");
                 auto enabled = body.value("enabled", true);

                 auto result = webhook_store->create_webhook(url, event_types, secret, enabled);
                 if (!result) {
                     // #3097 classification: caller error (bad URL) is 400,
                     // never conflated with a store/DB degradation (503).
                     if (result.error() == WebhookWriteError::invalid_url) {
                         audit_fn(req, "webhook.create", "failure", "webhook", "", "invalid_url");
                         res.status = 400;
                         res.set_content(detail::a4_error(res, "url must be http:// or https://"),
                                         "application/json");
                     } else {
                         audit_fn(req, "webhook.create", "failure", "webhook", "",
                                  std::string(audit_detail_for(result.error())));
                         res.status = 503;
                         res.set_content(detail::a4_error(res, "webhook store unavailable"),
                                         "application/json");
                     }
                     return;
                 }
                 const auto id = *result;
                 // gov Gate 2 security-guardian / Gate 4 consistency-auditor
                 // (PR #3563 full-PR review): record the URL in the audit
                 // detail, not just the id — a compromise-and-cleanup
                 // attacker who creates a webhook, exfiltrates data to it,
                 // then deletes it must not be able to erase every durable
                 // record of WHERE the data went. Matches the sibling
                 // hardening already applied to `offload_routes.cpp`.
                 audit_fn(req, "webhook.create", "success", "webhook", std::to_string(id), url);
                 if (emit_event_fn)
                     emit_event_fn("webhook.created", req, {},
                                   {{"webhook_id", id}, {"url", url}});
                 res.set_content(
                     nlohmann::json({{"id", id}, {"status", "created"}}).dump(),
                     "application/json");
             });

    // DELETE /api/webhooks/:id — delete a webhook
    sink.Delete(R"(/api/webhooks/(\d+))",
               [perm_fn, audit_fn, webhook_store](const httplib::Request& req,
                                                   httplib::Response& res) {
                   if (!perm_fn(req, res, "Infrastructure", "Write"))
                       return;
                   if (!webhook_store) {
                       res.status = 503;
                       res.set_content(detail::a4_error(res, "service unavailable"),
                                       "application/json");
                       return;
                   }
                   auto id = std::stoll(req.matches[1].str());
                   // gov Gate 2/4/5 (PR #3563 full-PR review): snapshot the
                   // URL BEFORE deleting — matches `offload_routes.cpp`'s
                   // existing "compliance F-3" hardening for the identical
                   // attack shape (compromise, exfiltrate, delete-and-erase-
                   // evidence). Best-effort only: a degraded read here must
                   // never block the delete itself, so a nullopt (not-found
                   // OR a transient read failure) just means the audit
                   // detail stays empty, not that the delete is refused.
                   auto snapshot = webhook_store->get(id);
                   auto result = webhook_store->delete_webhook(id);
                   if (!result) {
                       // #3097 classification: a query failure against an
                       // open store is 503, distinct from the plain
                       // not-found case below (never conflated).
                       audit_fn(req, "webhook.delete", "failure", "webhook", std::to_string(id),
                                std::string(audit_detail_for(result.error())));
                       res.status = 503;
                       res.set_content(detail::a4_error(res, "webhook store unavailable"),
                                       "application/json");
                       return;
                   }
                   if (*result) {
                       audit_fn(req, "webhook.delete", "success", "webhook", std::to_string(id),
                                snapshot ? snapshot->url : "");
                       res.set_content(R"({"status":"deleted"})", "application/json");
                   } else {
                       audit_fn(req, "webhook.delete", "failure", "webhook", std::to_string(id),
                                "not_found");
                       res.status = 404;
                       res.set_content(detail::a4_error(res, "webhook not found"),
                                       "application/json");
                   }
               });

    // GET /api/webhooks/:id/deliveries — get delivery history
    sink.Get(R"(/api/webhooks/(\d+)/deliveries)",
            [perm_fn, webhook_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Infrastructure", "Read"))
                    return;
                if (!webhook_store) {
                    res.status = 503;
                    res.set_content(detail::a4_error(res, "service unavailable"),
                                    "application/json");
                    return;
                }
                auto webhook_id = std::stoll(req.matches[1].str());
                int limit = 50;
                auto limit_str = req.get_param_value("limit");
                if (!limit_str.empty()) {
                    try { limit = std::stoi(limit_str); } catch (...) {}
                }
                auto deliveries = webhook_store->get_deliveries(webhook_id, limit);
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& d : deliveries) {
                    arr.push_back({{"id", d.id},
                                   {"webhook_id", d.webhook_id},
                                   {"event_type", d.event_type},
                                   {"payload", d.payload},
                                   {"status_code", d.status_code},
                                   {"delivered_at", d.delivered_at},
                                   {"error", d.error}});
                }
                res.set_content(nlohmann::json({{"deliveries", arr}}).dump(),
                                "application/json");
            });
}

} // namespace

void WebhookRoutes::register_routes(httplib::Server& svr, AuthFn /*auth_fn*/, PermFn perm_fn,
                                    AuditFn audit_fn, EmitEventFn emit_event_fn,
                                    WebhookStore* webhook_store) {
    HttplibRouteSink sink(svr);
    mount(sink, std::move(perm_fn), std::move(audit_fn), std::move(emit_event_fn), webhook_store);
}

void WebhookRoutes::register_routes(HttpRouteSink& sink, AuthFn /*auth_fn*/, PermFn perm_fn,
                                    AuditFn audit_fn, EmitEventFn emit_event_fn,
                                    WebhookStore* webhook_store) {
    mount(sink, std::move(perm_fn), std::move(audit_fn), std::move(emit_event_fn), webhook_store);
}

} // namespace yuzu::server
