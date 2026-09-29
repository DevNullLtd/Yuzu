#include "notification_routes.hpp"

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
                if (!limit_str.empty()) {
                    try { limit = std::stoi(limit_str); } catch (...) {}
                }
                if (!offset_str.empty()) {
                    try { offset = std::stoi(offset_str); } catch (...) {}
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
                 auto id = std::stoll(req.matches[1].str());
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
                 auto id = std::stoll(req.matches[1].str());
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
