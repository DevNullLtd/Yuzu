#include "notification_routes.hpp"
#include "query_int_parse.hpp" // parse_query_int / strict_stoi / strict_stoll (#4644)

#include "http_route_sink.hpp" // HttpRouteSink, HttplibRouteSink

#include <nlohmann/json.hpp>

#include <utility>

namespace yuzu::server {

void NotificationRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                         AuditFn audit_fn,
                                         NotificationStore* notification_store) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(audit_fn),
                    notification_store);
}

void NotificationRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                         AuditFn audit_fn,
                                         NotificationStore* notification_store) {
    // GET /api/notifications — list unread notifications
    sink.Get("/api/notifications",
            [perm_fn, notification_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Infrastructure", "Read"))
                    return;
                if (!notification_store || !notification_store->is_open()) {
                    res.status = 503;
                    res.set_content(
                        R"({"error":{"code":503,"message":"notification store unavailable"},"meta":{"api_version":"v1"}})",
                        "application/json");
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

                auto notifications =
                    all ? notification_store->list_all(limit, offset)
                        : notification_store->list_unread(limit);
                auto count = notification_store->count_unread();

                nlohmann::json arr = nlohmann::json::array();
                for (const auto& n : notifications) {
                    arr.push_back({{"id", n.id},
                                   {"timestamp", n.timestamp},
                                   {"level", n.level},
                                   {"title", n.title},
                                   {"message", n.message},
                                   {"read", n.read},
                                   {"dismissed", n.dismissed}});
                }
                nlohmann::json result = {{"notifications", arr},
                                         {"unread_count", count}};
                res.set_content(result.dump(), "application/json");
            });

    // POST /api/notifications/:id/read — mark notification as read
    sink.Post(R"(/api/notifications/(\d+)/read)",
             [perm_fn, notification_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Write"))
                     return;
                 if (!notification_store) {
                     res.status = 503;
                     res.set_content(
                         R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                         "application/json");
                     return;
                 }
                 // `(\d+)` also matches a 21-digit id, which `stoll` rejects by THROWING (a 500).
                 // An id that is not a representable int64 cannot name a notification: 404.
                 const auto id_parsed = yuzu::server::parse_query_int<long long>(req.matches[1].str());
                 if (!id_parsed) {
                     res.status = 404;
                     res.set_content(R"({"error":{"code":404,"message":"notification not found"},"meta":{"api_version":"v1"}})",
                                     "application/json");
                     return;
                 }
                 const auto id = *id_parsed;
                 if (!notification_store->mark_read(id)) {
                     res.status = 404;
                     res.set_content(R"({"error":{"code":404,"message":"notification not found"},"meta":{"api_version":"v1"}})",
                                     "application/json");
                     return;
                 }
                 res.set_content(R"({"status":"ok"})", "application/json");
             });

    // POST /api/notifications/:id/dismiss — dismiss notification
    sink.Post(R"(/api/notifications/(\d+)/dismiss)",
             [perm_fn, audit_fn, notification_store](const httplib::Request& req,
                                                      httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Write"))
                     return;
                 if (!notification_store) {
                     res.status = 503;
                     res.set_content(
                         R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                         "application/json");
                     return;
                 }
                 // `(\d+)` also matches a 21-digit id, which `stoll` rejects by THROWING (a 500).
                 // An id that is not a representable int64 cannot name a notification: 404.
                 const auto id_parsed = yuzu::server::parse_query_int<long long>(req.matches[1].str());
                 if (!id_parsed) {
                     res.status = 404;
                     res.set_content(R"({"error":{"code":404,"message":"notification not found"},"meta":{"api_version":"v1"}})",
                                     "application/json");
                     return;
                 }
                 const auto id = *id_parsed;
                 if (!notification_store->dismiss(id)) {
                     audit_fn(req, "notification.dismiss", "failure", "notification",
                              std::to_string(id), "");
                     res.status = 404;
                     res.set_content(R"({"error":{"code":404,"message":"notification not found"},"meta":{"api_version":"v1"}})",
                                     "application/json");
                     return;
                 }
                 audit_fn(req, "notification.dismiss", "success", "notification",
                          std::to_string(id), "");
                 res.set_content(R"({"status":"ok"})", "application/json");
             });
}

} // namespace yuzu::server
