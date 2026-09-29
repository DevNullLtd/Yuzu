#include "offload_routes.hpp"

#include "offload_target_model.hpp" // adversarial-review fix (#2146 Batch B5): shared REST+MCP JSON builders (Rule 1)
#include "rest_a4_envelope_http.hpp" // detail::a4_error

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <stdexcept>

namespace yuzu::server {

namespace {

void send_unavailable(httplib::Response& res) {
    res.status = 503;
    res.set_content(detail::a4_error(res, "offload store unavailable"), "application/json");
}

void send_bad_json(httplib::Response& res) {
    res.status = 400;
    res.set_content(detail::a4_error(res, "invalid JSON"), "application/json");
}

void send_not_found(httplib::Response& res) {
    res.status = 404;
    res.set_content(detail::a4_error(res, "offload target not found"), "application/json");
}

/// Parse a numeric path segment to int64. The route regex `(\d+)` makes
/// `std::invalid_argument` impossible, but `std::stoll` still throws
/// `std::out_of_range` on values that overflow int64 (e.g. a 21-digit
/// id). We treat overflow as 404 — the id can't possibly correspond to
/// a real row — and avoid letting httplib turn the throw into a 500.
[[nodiscard]] std::optional<int64_t> parse_id_segment(const std::string& s) {
    try {
        return std::stoll(s);
    } catch (const std::out_of_range&) {
        return std::nullopt;
    } catch (const std::invalid_argument&) {
        return std::nullopt;
    }
}

void mount(HttpRouteSink& sink, OffloadRoutes::PermFn perm_fn, OffloadRoutes::AuditFn audit_fn,
           OffloadTargetStore* offload_store) {
    // GET /api/v1/offload-targets — list
    sink.Get("/api/v1/offload-targets",
             [perm_fn, offload_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 if (!offload_store || !offload_store->is_open()) {
                     send_unavailable(res);
                     return;
                 }
                 // AUTHORITATIVE read (ADR-0012 §1): nullopt means the read
                 // degraded (lease timeout/query failure), never "no
                 // targets configured" — surface it as 503, not an empty
                 // 200 list.
                 auto targets = offload_store->list();
                 if (!targets) {
                     send_unavailable(res);
                     return;
                 }
                 nlohmann::json arr = nlohmann::json::array();
                 for (const auto& t : *targets)
                     arr.push_back(offload_target_json(t));
                 res.set_content(nlohmann::json({{"offload_targets", arr}}).dump(),
                                 "application/json");
             });

    // POST /api/v1/offload-targets — create
    sink.Post("/api/v1/offload-targets",
              [perm_fn, audit_fn, offload_store](const httplib::Request& req,
                                                 httplib::Response& res) {
                  if (!perm_fn(req, res, "Infrastructure", "Write"))
                      return;
                  if (!offload_store || !offload_store->is_open()) {
                      send_unavailable(res);
                      return;
                  }
                  nlohmann::json body;
                  try {
                      body = nlohmann::json::parse(req.body);
                  } catch (...) {
                      send_bad_json(res);
                      return;
                  }
                  std::string name, url, auth_type_str, auth_credential, event_types;
                  int batch_size = 1;
                  bool enabled = true;
                  try {
                      name = body.value("name", std::string{});
                      url = body.value("url", std::string{});
                      auth_type_str = body.value("auth_type", std::string{"none"});
                      auth_credential = body.value("auth_credential", std::string{});
                      event_types = body.value("event_types", std::string{"*"});
                      batch_size = body.value("batch_size", 1);
                      enabled = body.value("enabled", true);
                  } catch (const nlohmann::json::exception&) {
                      // A present-but-wrong-typed field (e.g. batch_size as a
                      // string) throws type_error out of body.value() — that's
                      // still a caller mistake, not a server fault (#3097).
                      audit_fn(req, "offload_target.create", "denied", "offload_target", name,
                               "invalid_field_type");
                      send_bad_json(res);
                      return;
                  }
                  if (name.empty() || url.empty()) {
                      res.status = 400;
                      res.set_content(detail::a4_error(res, "name and url are required"),
                                      "application/json");
                      return;
                  }
                  auto auth_type = offload_auth_type_from_string(auth_type_str);
                  if (offload_auth_type_to_string(auth_type) != auth_type_str) {
                      // offload_auth_type_from_string() folds any unrecognized
                      // string to None for defensive DB-read tolerance; at the
                      // REST boundary that would silently turn a typo like
                      // "bearre" into an unauthenticated target instead of
                      // rejecting it — round-trip through to_string() to catch
                      // exactly that case without touching the shared helper.
                      audit_fn(req, "offload_target.create", "denied", "offload_target", name,
                               "invalid_auth_type");
                      res.status = 400;
                      res.set_content(detail::a4_error(res, "unrecognized auth_type"),
                                      "application/json");
                      return;
                  }

                  auto result = offload_store->create_target(name, url, auth_type, auth_credential,
                                                             event_types, batch_size, enabled);
                  if (!result.has_value()) {
                      // #3097 classification: invalid_input is the caller's
                      // mistake (400); store_unavailable/db_error are
                      // store/infra degradation (503) — distinct in the
                      // audit record even where the HTTP status collapses.
                      if (result.error() == OffloadWriteError::invalid_input) {
                          audit_fn(req, "offload_target.create", "denied", "offload_target", name,
                                   "validation_failed");
                          res.status = 400;
                          res.set_content(
                              detail::a4_error(res, "target rejected: invalid url, name, "
                                                     "batch_size, or duplicate name"),
                              "application/json");
                      } else {
                          const char* detail = result.error() == OffloadWriteError::store_unavailable
                                                  ? "store_unavailable"
                                                  : "db_error";
                          audit_fn(req, "offload_target.create", "denied", "offload_target", name,
                                   detail);
                          send_unavailable(res);
                      }
                      return;
                  }
                  const int64_t id = *result;
                  audit_fn(req, "offload_target.create", "success", "offload_target",
                           std::to_string(id), name);
                  res.status = 201;
                  res.set_content(
                      nlohmann::json({{"id", id}, {"status", "created"}}).dump(),
                      "application/json");
              });

    // GET /api/v1/offload-targets/:id — get one
    sink.Get(R"(/api/v1/offload-targets/(\d+))",
             [perm_fn, offload_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 if (!offload_store || !offload_store->is_open()) {
                     send_unavailable(res);
                     return;
                 }
                 auto id_opt = parse_id_segment(req.matches[1].str());
                 if (!id_opt) {
                     send_not_found(res);
                     return;
                 }
                 bool store_ok = true;
                 auto t = offload_store->get(*id_opt, &store_ok);
                 if (!t) {
                     // Distinguish genuine not-found (404) from a degraded
                     // read (503) — #3097 classification.
                     if (store_ok)
                         send_not_found(res);
                     else
                         send_unavailable(res);
                     return;
                 }
                 res.set_content(offload_target_json(*t).dump(), "application/json");
             });

    // DELETE /api/v1/offload-targets/:id — delete
    sink.Delete(R"(/api/v1/offload-targets/(\d+))",
                [perm_fn, audit_fn, offload_store](const httplib::Request& req,
                                                   httplib::Response& res) {
                    if (!perm_fn(req, res, "Infrastructure", "Write"))
                        return;
                    if (!offload_store || !offload_store->is_open()) {
                        send_unavailable(res);
                        return;
                    }
                    auto id_opt = parse_id_segment(req.matches[1].str());
                    if (!id_opt) {
                        audit_fn(req, "offload_target.delete", "denied", "offload_target",
                                 req.matches[1].str(), "not_found");
                        send_not_found(res);
                        return;
                    }
                    // Snapshot the URL + name BEFORE delete so the audit row
                    // captures it. After delete the row is gone and a brief
                    // compromise-and-cleanup attacker would erase the only
                    // record of which URL the data was exfiltrated to
                    // (compliance F-3 from Gate 6).
                    auto target_snapshot = offload_store->get(*id_opt);
                    std::string detail;
                    if (target_snapshot) {
                        detail =
                            "name=" + target_snapshot->name + " url=" + target_snapshot->url;
                    }
                    auto result = offload_store->delete_target(*id_opt);
                    if (!result.has_value()) {
                        // Same #3097 classification as create's 503 branch
                        // above — distinct in the audit record even though
                        // the HTTP status collapses to 503 for both.
                        const char* write_err_detail =
                            result.error() == OffloadWriteError::store_unavailable
                                ? "store_unavailable"
                                : "db_error";
                        audit_fn(req, "offload_target.delete", "denied", "offload_target",
                                 std::to_string(*id_opt), write_err_detail);
                        send_unavailable(res);
                        return;
                    }
                    if (*result) {
                        audit_fn(req, "offload_target.delete", "success", "offload_target",
                                 std::to_string(*id_opt), detail);
                        res.set_content(R"({"status":"deleted"})", "application/json");
                    } else {
                        audit_fn(req, "offload_target.delete", "denied", "offload_target",
                                 std::to_string(*id_opt), "not_found");
                        send_not_found(res);
                    }
                });

    // GET /api/v1/offload-targets/:id/deliveries — delivery history
    sink.Get(R"(/api/v1/offload-targets/(\d+)/deliveries)",
             [perm_fn, offload_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 if (!offload_store || !offload_store->is_open()) {
                     send_unavailable(res);
                     return;
                 }
                 auto id_opt = parse_id_segment(req.matches[1].str());
                 if (!id_opt) {
                     send_not_found(res);
                     return;
                 }
                 // Match sibling GET /:id semantics (HP-2): a missing target
                 // returns 404 rather than `{"deliveries":[]}` + 200, so an
                 // operator polling for a deleted target sees the explicit
                 // 404 instead of confusing empty-success. #3097: a
                 // degraded existence check is 503, not 404.
                 bool store_ok = true;
                 if (!offload_store->get(*id_opt, &store_ok)) {
                     if (store_ok)
                         send_not_found(res);
                     else
                         send_unavailable(res);
                     return;
                 }
                 // Cap limit to a sane maximum so an operator can't request a
                 // billion-row vector allocation. Default 50, max 1000 — the
                 // sibling executions/audit endpoints converged on this
                 // ceiling.
                 int limit = 50;
                 auto limit_str = req.get_param_value("limit");
                 if (!limit_str.empty()) {
                     try { limit = std::stoi(limit_str); } catch (...) {}
                 }
                 limit = std::clamp(limit, 1, 1000);
                 auto deliveries = offload_store->get_deliveries(*id_opt, limit);
                 nlohmann::json arr = nlohmann::json::array();
                 for (const auto& d : deliveries)
                     arr.push_back(offload_delivery_json(d));
                 res.set_content(nlohmann::json({{"deliveries", arr}}).dump(),
                                 "application/json");
             });
}

} // namespace

void OffloadRoutes::register_routes(httplib::Server& svr, AuthFn /*auth_fn*/, PermFn perm_fn,
                                    AuditFn audit_fn, OffloadTargetStore* offload_store) {
    HttplibRouteSink sink(svr);
    mount(sink, std::move(perm_fn), std::move(audit_fn), offload_store);
}

void OffloadRoutes::register_routes(HttpRouteSink& sink, AuthFn /*auth_fn*/, PermFn perm_fn,
                                    AuditFn audit_fn, OffloadTargetStore* offload_store) {
    mount(sink, std::move(perm_fn), std::move(audit_fn), offload_store);
}

} // namespace yuzu::server
