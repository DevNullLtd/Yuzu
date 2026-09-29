#include "result_set_routes.hpp"

#include "http_route_sink.hpp"
#include "result_set_store.hpp"
#include "result_sets_ui.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <string>
#include <vector>

namespace yuzu::server::result_set {

void register_result_set_routes(HttpRouteSink& sink, Deps deps) {
    // -- Result Sets fragment API (scope walking, capability §30) -----------

    // Owner-checked read shared by every fragment mutation below: a DB
    // error is treated IDENTICALLY to "not found or not owned" — a
    // mutation (pin/unpin/delete) must never proceed on a degraded
    // ownership read (ADR-0036 fail-closed authoritative-read contract).
    // Collapses ResultSetStore::get's std::expected<optional<...>,...>
    // into a plain optional so every call site below is unchanged from its
    // pre-widening shape. Moved verbatim from server.cpp (#2542 PR-5) — a
    // local closure with no ServerImpl dependency beyond the store, never a
    // ServerImpl method, so no second-caller risk in this move.
    auto rs_get_owned = [deps](const std::string& id,
                               const std::string& owner) -> std::optional<ResultSet> {
        if (!deps.store)
            return std::nullopt;
        auto row = deps.store->get(id);
        if (!row || !row->has_value() || (*row)->owner_principal != owner)
            return std::nullopt;
        return **row;
    };

    // Owner-scoped sidebar list.
    //
    // guardian-confinement-2298 PR3 §3e: every result-set fragment here is
    // require_auth-only, keyed on `session->username` — but that username
    // is the MINTING principal's, not the individual token's own service
    // scope. A service-scoped token therefore reaches every result set the
    // minter (or any OTHER service token that same minter holds) has
    // created/pinned — cross-service reach beyond this token's own intended
    // cohort. Denied all six (one read here, detail below, plus
    // pin/unpin/delete/create).
    sink.Get(
        "/fragments/result-sets/sidebar",
        [deps](const httplib::Request& req, httplib::Response& res) {
            if (deps.deny_service_scoped_fn(
                    req, res, "result_set.sidebar.access_denied",
                    "service-scoped tokens may not read the result-set sidebar", "ResultSet", ""))
                return;
            auto session = deps.auth_fn(req, res);
            if (!session)
                return;
            if (!deps.store) {
                res.set_content("", "text/html; charset=utf-8");
                return;
            }
            std::string next;
            std::string selected =
                req.has_param("selected") ? req.get_param_value("selected") : "";
            auto sets = deps.store->list_by_owner(session->username, "", 200, next);
            res.set_content(render_result_sets_sidebar(sets, selected),
                            "text/html; charset=utf-8");
        });

    // Detail pane for one set (owner-checked).
    sink.Get(
        R"(/fragments/result-sets/(rs_[0-9a-f]+)/detail)",
        [deps, rs_get_owned](const httplib::Request& req, httplib::Response& res) {
            if (deps.deny_service_scoped_fn(
                    req, res, "result_set.detail.access_denied",
                    "service-scoped tokens may not read result-set detail", "ResultSet",
                    req.matches[1].str()))
                return;
            auto session = deps.auth_fn(req, res);
            if (!session)
                return;
            auto id = req.matches[1].str();
            auto row = rs_get_owned(id, session->username);
            if (!row) {
                res.set_content(render_result_set_detail_empty(),
                                "text/html; charset=utf-8");
                return;
            }
            auto chain = deps.store->lineage(id, session->username);
            res.set_content(render_result_set_detail(*row, chain), "text/html; charset=utf-8");
        });

    // Pin / unpin — return the refreshed detail and trigger a sidebar reload.
    auto rs_detail_after = [deps, rs_get_owned](const std::string& id, const std::string& owner,
                                                httplib::Response& res) {
        auto row = rs_get_owned(id, owner);
        if (!row) {
            res.set_content(render_result_set_detail_empty(), "text/html; charset=utf-8");
            return;
        }
        auto chain = deps.store->lineage(id, owner);
        res.set_header("HX-Trigger", "resultSetsChanged");
        res.set_content(render_result_set_detail(*row, chain), "text/html; charset=utf-8");
    };

    sink.Post(
        R"(/fragments/result-sets/(rs_[0-9a-f]+)/pin)",
        [deps, rs_detail_after, rs_get_owned](const httplib::Request& req,
                                              httplib::Response& res) {
            if (deps.deny_service_scoped_fn(req, res, "result_set.pin.access_denied",
                                            "service-scoped tokens may not pin result sets",
                                            "ResultSet", req.matches[1].str()))
                return;
            auto session = deps.auth_fn(req, res);
            if (!session || !deps.store)
                return;
            auto id = req.matches[1].str();
            auto row = rs_get_owned(id, session->username);
            if (!row) {
                res.set_content(render_result_set_detail_empty(), "text/html; charset=utf-8");
                return;
            }
            auto pinned = deps.store->pin(id);
            if (!pinned) {
                // Don't audit a success that didn't happen, and tell the
                // operator why (review merged_bug_009). PinLimit is the
                // 50-pin cap; otherwise a transient store error.
                deps.audit_fn(req, "result_set.pin",
                              pinned.error() == ResultSetError::PinLimit ? "denied" : "failure",
                              "ResultSet", id, to_string(pinned.error()));
                res.set_header(
                    "HX-Trigger",
                    nlohmann::json{{"showToast",
                                    {{"level", "error"}, {"message", to_string(pinned.error())}}}}
                        .dump());
                auto chain = deps.store->lineage(id, session->username);
                res.set_content(render_result_set_detail(*row, chain),
                                "text/html; charset=utf-8");
                return;
            }
            deps.audit_fn(req, "result_set.pin", "success", "ResultSet", id, "");
            rs_detail_after(id, session->username, res);
        });

    sink.Post(
        R"(/fragments/result-sets/(rs_[0-9a-f]+)/unpin)",
        [deps, rs_detail_after, rs_get_owned](const httplib::Request& req,
                                              httplib::Response& res) {
            if (deps.deny_service_scoped_fn(req, res, "result_set.unpin.access_denied",
                                            "service-scoped tokens may not unpin result sets",
                                            "ResultSet", req.matches[1].str()))
                return;
            auto session = deps.auth_fn(req, res);
            if (!session || !deps.store)
                return;
            auto id = req.matches[1].str();
            auto row = rs_get_owned(id, session->username);
            if (!row) {
                res.set_content(render_result_set_detail_empty(), "text/html; charset=utf-8");
                return;
            }
            auto unpinned = deps.store->unpin(id);
            if (!unpinned) {
                deps.audit_fn(req, "result_set.unpin", "failure", "ResultSet", id,
                              to_string(unpinned.error()));
                res.set_header("HX-Trigger",
                               nlohmann::json{{"showToast",
                                               {{"level", "error"},
                                                {"message", to_string(unpinned.error())}}}}
                                   .dump());
                auto chain = deps.store->lineage(id, session->username);
                res.set_content(render_result_set_detail(*row, chain),
                                "text/html; charset=utf-8");
                return;
            }
            deps.audit_fn(req, "result_set.unpin", "success", "ResultSet", id, "");
            rs_detail_after(id, session->username, res);
        });

    sink.Post(
        R"(/fragments/result-sets/(rs_[0-9a-f]+)/delete)",
        [deps, rs_get_owned](const httplib::Request& req, httplib::Response& res) {
            if (deps.deny_service_scoped_fn(req, res, "result_set.delete.access_denied",
                                            "service-scoped tokens may not delete result sets",
                                            "ResultSet", req.matches[1].str()))
                return;
            auto session = deps.auth_fn(req, res);
            if (!session || !deps.store)
                return;
            auto id = req.matches[1].str();
            auto row = rs_get_owned(id, session->username);
            if (!row) {
                res.set_content(render_result_set_detail_empty(), "text/html; charset=utf-8");
                return;
            }
            auto del = deps.store->delete_set(id);
            if (!del) {
                // Pinned sets must be unpinned first — re-render the detail
                // so the operator sees why nothing was deleted.
                auto chain = deps.store->lineage(id, session->username);
                res.set_content(render_result_set_detail(*row, chain),
                                "text/html; charset=utf-8");
                return;
            }
            deps.audit_fn(req, "result_set.delete", "success", "ResultSet", id, "");
            res.set_header("HX-Trigger", "resultSetsChanged");
            res.set_content(render_result_set_detail_empty(), "text/html; charset=utf-8");
        });

    // Create from pasted device IDs (CSV import) — returns refreshed sidebar.
    sink.Post(
        "/fragments/result-sets/create",
        [deps](const httplib::Request& req, httplib::Response& res) {
            if (deps.deny_service_scoped_fn(req, res, "result_set.create.access_denied",
                                            "service-scoped tokens may not create result sets",
                                            "ResultSet", ""))
                return;
            auto session = deps.auth_fn(req, res);
            if (!session || !deps.store)
                return;
            CreateRequest cr;
            cr.owner_principal = session->username;
            cr.name = req.has_param("name") ? req.get_param_value("name") : "";
            cr.source_kind = std::string(source_kind::kManualCurate);
            cr.source_payload = R"({"note":"dashboard CSV import"})";

            std::vector<std::string> members;
            if (req.has_param("device_ids")) {
                std::string raw = req.get_param_value("device_ids");
                std::string cur;
                auto flush = [&]() {
                    // trim whitespace
                    std::size_t a = cur.find_first_not_of(" \t\r\n");
                    std::size_t b = cur.find_last_not_of(" \t\r\n");
                    if (a != std::string::npos)
                        members.push_back(cur.substr(a, b - a + 1));
                    cur.clear();
                };
                for (char c : raw) {
                    if (c == '\n' || c == ',')
                        flush();
                    else
                        cur += c;
                }
                flush();
            }
            auto created = deps.store->create_materialized(cr, members);
            if (!created) {
                // Surface quota / too-many-members / store errors instead of
                // silently re-rendering as if the create succeeded (review
                // merged_bug_009). The store enforces kMaxMembersPerSet, so
                // an oversized pasted CSV lands here as TooManyMembers (B4).
                if (created.error() == ResultSetError::QuotaExceeded ||
                    created.error() == ResultSetError::TooManyMembers) {
                    if (deps.metrics)
                        deps.metrics->counter("yuzu_result_set_quota_rejected").increment();
                }
                deps.audit_fn(req, "result_set.create", "denied", "ResultSet", "",
                              to_string(created.error()));
                res.set_header("HX-Trigger",
                               nlohmann::json{{"showToast",
                                               {{"level", "error"},
                                                {"message", to_string(created.error())}}}}
                                   .dump());
                std::string next;
                auto sets = deps.store->list_by_owner(session->username, "", 200, next);
                res.set_content(render_result_sets_sidebar(sets, ""),
                                "text/html; charset=utf-8");
                return;
            }
            deps.audit_fn(req, "result_set.create", "success", "ResultSet", created->id,
                          cr.source_kind);
            std::string next;
            auto sets = deps.store->list_by_owner(session->username, "", 200, next);
            res.set_header("HX-Trigger", "resultSetsChanged");
            res.set_content(render_result_sets_sidebar(sets, created->id),
                            "text/html; charset=utf-8");
        });
}

} // namespace yuzu::server::result_set
