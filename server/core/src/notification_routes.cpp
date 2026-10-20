#include "notification_routes.hpp"
#include "query_int_parse.hpp" // parse_query_int / strict_stoi / strict_stoll (#4644)

#include "http_route_sink.hpp" // HttpRouteSink, HttplibRouteSink
#include "rest_a4_envelope_http.hpp" // detail::a4_error
#include "rest_audit.hpp" // emit_behavioral_audit
#include "web_utils.hpp"  // browser_write_is_cross_site

#include <nlohmann/json.hpp>

#include <utility>

namespace yuzu::server {

namespace {

constexpr std::int64_t kRetryAfterMs = 5000;

void unavailable(httplib::Response& res, const char* message) {
    res.status = 503;
    res.set_content(detail::a4_error(res, message,
                                     detail::A4ErrorOpts{.retry_after_ms = kRetryAfterMs,
                                                         .remediation = "retry the request"}),
                    "application/json");
}

/// A row that must not abort the request: an empty AuditFn (audit off) or a throwing one is a
/// no-op here, as in `emit_behavioral_audit`. Used for the `csrf.denied` row and the outcome
/// rows, whose loss never changes the response (the `attempted` row is the gate).
void note_audit(const NotificationRoutes::AuditFn& audit_fn, const httplib::Request& req,
                const char* action, const char* result, const char* target_type,
                const std::string& target_id, const char* detail_text) {
    (void)detail::try_persist_audit(audit_fn, req, action, result, target_type, target_id,
                                    detail_text);
}

/// Cookie-authorised writes need a same-site Origin/Referer (token callers are exempt); see
/// `browser_write_is_cross_site`. Defence in depth: the server-wide pre-routing gate answers a
/// cookie-session write first; this copy serves callers that bypass pre-routing (unit tests) and
/// runs AFTER the permission gate. The refusal is audited.
bool refuse_cross_site(const NotificationRoutes::AuditFn& audit_fn,
                       const NotificationRoutes::ResolveSessionFn& resolve_session_fn,
                       const std::vector<std::string>& trusted_origins,
                       const httplib::Request& req, httplib::Response& res) {
    std::string source;
    if (resolve_session_fn)
        if (auto sess = resolve_session_fn(req))
            source = sess->auth_source;
    if (!browser_write_is_cross_site(source, req.get_header_value("Host"),
                                     req.get_header_value("Origin"),
                                     req.get_header_value("Referer"), trusted_origins))
        return false;
    note_audit(audit_fn, req, "csrf.denied", "denied", "Endpoint", "notification",
               "cross-site or header-less browser write refused");
    res.status = 403;
    res.set_content(detail::a4_error(res, "cross-site request refused"), "application/json");
    return true;
}

/// One bell mutation, audit-first: an `attempted` row is written before the store is touched
/// and a failed write refuses the mutation (ADR-0033 §9: no audit row, no mutation). The outcome
/// row follows; `applied` is `true` for one changed row, `false` for an unknown id, and an error
/// for a write that may not have reached the database.
template <class Mutate>
void audited_mutation(const NotificationRoutes::AuditFn& audit_fn, const char* verb,
                      const httplib::Request& req, httplib::Response& res, Mutate&& mutate) {
    // The route regex admits any digit string. One that does not fit an int64 names no
    // notification: nothing to change, so nothing to audit-first.
    std::int64_t numeric = 0;
    try {
        numeric = std::stoll(req.matches[1].str());
    } catch (...) {
        res.status = 404;
        res.set_content(detail::a4_error(res, "notification not found"), "application/json");
        return;
    }
    const auto id = std::to_string(numeric); // canonical: "0007" is audited as "7"
    if (!detail::emit_behavioral_audit(audit_fn, req, res, verb, "attempted", "notification", id, "")) {
        unavailable(res, "audit log unavailable; the change was not made");
        return;
    }
    auto applied = mutate(numeric);
    if (!applied) {
        note_audit(audit_fn, req, verb, "failure", "notification", id, "store error");
        unavailable(res, "notification store unavailable");
        return;
    }
    if (!*applied) {
        note_audit(audit_fn, req, verb, "failure", "notification", id, "no such notification");
        res.status = 404;
        res.set_content(detail::a4_error(res, "notification not found"), "application/json");
        return;
    }
    note_audit(audit_fn, req, verb, "success", "notification", id, "");
    res.set_content(R"({"status":"ok"})", "application/json");
}

} // namespace

void NotificationRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                         AuditFn audit_fn, NotificationStore* notification_store,
                                         ResolveSessionFn resolve_session_fn,
                                         std::vector<std::string> csrf_trusted_origins) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(audit_fn),
                    notification_store, std::move(resolve_session_fn),
                    std::move(csrf_trusted_origins));
}

void NotificationRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                         AuditFn audit_fn, NotificationStore* notification_store,
                                         ResolveSessionFn resolve_session_fn,
                                         std::vector<std::string> csrf_trusted_origins) {
    // GET /api/notifications — list unread notifications
    sink.Get("/api/notifications",
            [perm_fn, notification_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Infrastructure", "Read"))
                    return;
                if (!notification_store || !notification_store->is_open()) {
                    unavailable(res, "notification store unavailable");
                    return;
                }
                bool all = req.get_param_value("all") == "true";
                int limit = 50;
                int offset = 0;
                auto limit_str = req.get_param_value("limit");
                auto offset_str = req.get_param_value("offset");
                // Present-but-malformed `limit`/`offset` is a 400, not a silent default: a
                // page the caller did not ask for reads as the page they did (#4644).
                // `has_param`, not `!raw.empty()`: `?limit=` is PRESENT and malformed, not absent.
                struct Param { const char* name; const std::string& raw; int* out; };
                for (const auto& [name, raw, out] : {Param{"limit", limit_str, &limit},
                                                     Param{"offset", offset_str, &offset}}) {
                    if (!req.has_param(name))
                        continue;
                    const auto v = yuzu::server::parse_query_int<int>(raw);
                    // A negative page size/offset is malformed too: it reaches `LIMIT $1::bigint`,
                    // PG rejects it, and the store answers an empty list as a valid-looking 200.
                    if (!v || *v < 0) {
                        res.status = 400;
                        res.set_content(
                            R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})",
                            "application/json");
                        return;
                    }
                    *out = *v;
                }
                if (limit < 0 || offset < 0) { // a client mistake, not a store outage
                    res.status = 400;
                    res.set_content(detail::a4_error(res, "limit and offset must not be negative"),
                                    "application/json");
                    return;
                }

                // A failed read is an error the bell can show, never "No unread
                // notifications." (the checked readers carry the failure).
                auto notifications = all ? notification_store->list_all_checked(limit, offset)
                                         : notification_store->list_unread_checked(limit);
                if (!notifications) {
                    unavailable(res, "notification store unavailable");
                    return;
                }
                auto count = notification_store->count_unread_checked();
                if (!count) {
                    unavailable(res, "notification store unavailable");
                    return;
                }

                nlohmann::json arr = nlohmann::json::array();
                for (const auto& n : *notifications) {
                    arr.push_back({{"id", n.id},
                                   {"timestamp", n.timestamp},
                                   {"level", n.level},
                                   {"title", n.title},
                                   {"message", n.message},
                                   {"read", n.read},
                                   {"dismissed", n.dismissed}});
                }
                nlohmann::json result = {{"notifications", arr},
                                         {"unread_count", *count}};
                res.set_content(result.dump(), "application/json");
            });

    // POST /api/notifications/:id/read — mark notification as read
    sink.Post(R"(/api/notifications/(\d+)/read)",
             [perm_fn, audit_fn, resolve_session_fn, csrf_trusted_origins,
              notification_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Write"))
                     return;
                 if (refuse_cross_site(audit_fn, resolve_session_fn, csrf_trusted_origins, req,
                                       res))
                     return;
                 if (!notification_store) {
                     unavailable(res, "service unavailable");
                     return;
                 }
                 audited_mutation(audit_fn, "notification.mark_read", req, res,
                                  [&](std::int64_t id) {
                                      return notification_store->mark_read_checked(id);
                                  });
             });

    // POST /api/notifications/:id/dismiss — dismiss notification
    sink.Post(R"(/api/notifications/(\d+)/dismiss)",
             [perm_fn, audit_fn, resolve_session_fn, csrf_trusted_origins,
              notification_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Write"))
                     return;
                 if (refuse_cross_site(audit_fn, resolve_session_fn, csrf_trusted_origins, req,
                                       res))
                     return;
                 if (!notification_store) {
                     unavailable(res, "service unavailable");
                     return;
                 }
                 audited_mutation(audit_fn, "notification.dismiss", req, res,
                                  [&](std::int64_t id) {
                                      return notification_store->dismiss_checked(id);
                                  });
             });
}

} // namespace yuzu::server
