#include "response_routes.hpp"

#include "authz_model.hpp"
#include "data_export.hpp"
#include "http_route_sink.hpp"
#include "response_export_metrics.hpp"
#include "response_query_params.hpp"
#include "response_store.hpp"
#include "rest_a4_envelope_http.hpp"
#include "rest_audit.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>

namespace yuzu::server::response {

namespace {

/// Fail-closed access-audit step shared by the three legacy read routes (get, aggregate,
/// export; #4644 Gate 7). Emits one `response.read` row and, when it does not durably persist
/// (a false return, or a throwing pipeline, both already handled by `emit_behavioral_audit`;
/// an unwired audit_fn is audit-off and persists), answers 503 (A4 envelope, retry_after_ms
/// 5000, `Sec-Audit-Failed`) and returns false. The caller must then return without building
/// any body, so an unaudited read serves no data. This is the legacy twin of the v1 routes'
/// posture; the verb, target type and result strings are chosen by the caller and must stay
/// equal to v1's so the twins are countable together.
[[nodiscard]] bool audit_read_or_refuse(const Deps& deps, const httplib::Request& req,
                                        httplib::Response& res, const char* result,
                                        const std::string& instruction_id,
                                        const std::string& detail_text) {
    if (detail::emit_behavioral_audit(deps.audit_fn, req, res, "response.read", result,
                                      "Execution", instruction_id, detail_text))
        return true;
    res.status = 503;
    res.set_content(detail::a4_error(res,
                                     "audit subsystem unavailable; refusing to serve "
                                     "response data without durable evidence",
                                     {.retry_after_ms = 5000, .remediation = "retry the request"}),
                    "application/json");
    return false;
}

} // namespace

void register_response_routes(HttpRouteSink& sink, Deps deps) {
    // -- Response API ---------------------------------------------------------

    // Aggregate endpoint — must be registered before the catch-all responses route
    sink.Get(R"(/api/responses/([^/]+)/aggregate)", [deps](const httplib::Request& req,
                                                            httplib::Response& res) {
        auto gate = deps.fleet_read_fn(req, res, "Response", "Read");
        if (!gate.admitted)
            return; // gate already wrote the response.

        auto instruction_id = req.matches[1].str();
        if (!deps.store || !deps.store->is_open()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"response store not available"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto group_by = req.get_param_value("group_by");
        if (group_by.empty())
            group_by = "status";

        AggregateOp op = AggregateOp::Count;
        auto op_str = req.get_param_value("op");
        if (op_str == "sum")
            op = AggregateOp::Sum;
        else if (op_str == "avg")
            op = AggregateOp::Avg;
        else if (op_str == "min")
            op = AggregateOp::Min;
        else if (op_str == "max")
            op = AggregateOp::Max;

        // Validate CLIENT input against ResponseStore::aggregate()'s own
        // allow-lists BEFORE calling in (#2691, Doomgoose finding #2): an
        // allow-list miss inside aggregate() itself returns nullopt,
        // which this handler otherwise maps unconditionally to 503 "store
        // degraded" below — a typo'd group_by/op_column would page the
        // degrade alert for a healthy database. Bad TARGETED client input
        // is a 400, not a 503.
        if (std::find(ResponseStore::allowed_group_by().begin(),
                      ResponseStore::allowed_group_by().end(),
                      group_by) == ResponseStore::allowed_group_by().end()) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"invalid group_by"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        auto op_column_param = req.get_param_value("op_column");
        const std::string effective_op_column = op_column_param.empty() ? "id" : op_column_param;
        if (std::find(ResponseStore::allowed_op_column().begin(),
                      ResponseStore::allowed_op_column().end(),
                      effective_op_column) == ResponseStore::allowed_op_column().end()) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"invalid op_column"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        AggregationQuery aq;
        aq.group_by = group_by;
        aq.op = op;
        aq.op_column = op_column_param;

        ResponseQuery filter;
        if (req.has_param("agent_id"))
            filter.agent_id = req.get_param_value("agent_id");
        // #4644: strict full-consumption numeric parse (stoi/stoll took "0x1", "1e9",
        // "100abc" as 0/1/100); status < -1 is rejected rather than read as "any".
        if (!apply_response_numeric_params(req, filter,
                                           kRespParamStatus | kRespParamSince | kRespParamUntil)) {
            count_response_param_rejected(deps.metrics, "rest");
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        // #1634 management-group scope. Resolve the responding agents only to
        // retain the existing distinct-drop audit; the gate's VisibleSet is the
        // authority and the engaged AggregateScope is applied before folding.
        AggregateScope agg_scope; // nullopt = no restriction
        std::size_t agg_dropped = 0;
        if (gate.scope) {
            auto distinct = deps.store->distinct_agent_ids(instruction_id);
            if (!distinct) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"response store unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            std::vector<std::string> in_scope;
            in_scope.reserve(distinct->size());
            for (auto& aid : *distinct) {
                if (authz::in_scope(gate.scope, aid))
                    in_scope.push_back(std::move(aid));
                else
                    ++agg_dropped;
            }
            agg_scope = std::move(in_scope); // engaged-empty means no rows
        }
        // CC7.2 evidence: a scope-drop is a security-relevant filtering event — record
        // it so a cross-operator access attempt that was suppressed is auditable on this
        // surface too (#1634 compliance review; parity with the MCP denied row / the
        // visualization scope_dropped detail).
        // Fail-closed like the export and the v1 twins: a drop whose evidence cannot be
        // persisted serves nothing.
        if (agg_dropped > 0 &&
            !audit_read_or_refuse(deps, req, res, "denied", instruction_id,
                                  "scope_dropped=" + std::to_string(agg_dropped) +
                                      " surface=aggregate"))
            return;

        auto results_opt = deps.store->aggregate(instruction_id, aq, filter, agg_scope);
        if (!results_opt) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"response store degraded"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        const auto& results = *results_opt;

        // Fail-closed success row (#4644 Gate 7), mirroring v1 aggregate: after the store read
        // (a 503 degrade is not audited as a read) and BEFORE the body is built. Same verb,
        // target and result as v1; the detail names this surface.
        if (!audit_read_or_refuse(deps, req, res, "success", instruction_id,
                                  "legacy response aggregate cid=" +
                                      detail::ensure_correlation_id(res)))
            return;

        int64_t total_rows = 0;
        nlohmann::json groups = nlohmann::json::array();
        for (const auto& r : results) {
            total_rows += r.count;
            groups.push_back({{"group_value", r.group_value},
                              {"count", r.count},
                              {"aggregate_value", r.aggregate_value}});
        }

        res.set_content(nlohmann::json({{"instruction_id", instruction_id},
                                        {"groups", groups},
                                        {"total_groups", results.size()},
                                        {"total_rows", total_rows}})
                            .dump(),
                        "application/json");
    });

    // Export endpoint — must be registered before the catch-all responses route
    sink.Get(R"(/api/responses/([^/]+)/export)", [deps](const httplib::Request& req,
                                                         httplib::Response& res) {
        auto gate = deps.fleet_read_fn(req, res, "Response", "Read");
        if (!gate.admitted)
            return; // gate already wrote the response.

        auto instruction_id = req.matches[1].str();
        if (!deps.store || !deps.store->is_open()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"response store not available"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        ResponseQuery q;
        if (req.has_param("agent_id"))
            q.agent_id = req.get_param_value("agent_id");
        // #4644: strict full-consumption numeric parse (stoi/stoll took "0x1", "1e9",
        // "100abc" as 0/1/100); status < -1 is rejected rather than read as "any".
        if (!apply_response_numeric_params(req, q,
                                           kRespParamStatus | kRespParamSince | kRespParamUntil |
                                               kRespParamLimit)) {
            count_response_param_rejected(deps.metrics, "rest");
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        // Export default and ceiling (#4703): the old code clamped only the DEFAULT, so
        // an explicit ?limit=999999999 asked the store for an unbounded fetch.
        q.limit = normalize_export_limit(req.has_param("limit"), q.limit);

        // #1634 / ADR-0017 INV-3 (CRITICAL): resolve the in-scope agent set and push it
        // into the SQL WHERE clause BEFORE LIMIT/OFFSET, not as a post-fetch filter — a
        // post-fetch filter on a paginated read can hand a confined caller a short or
        // empty page even though visible rows exist past the hidden ones LIMIT already
        // truncated. Mirrors the /aggregate sibling's resolve-then-scope pattern above.
        AggregateScope scope_arg; // nullopt = unrestricted
        std::size_t export_dropped = 0;
        if (gate.scope) {
            auto distinct = deps.store->distinct_agent_ids(instruction_id);
            if (!distinct) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"response store degraded"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            std::vector<std::string> in_scope;
            in_scope.reserve(distinct->size());
            for (auto& aid : *distinct) {
                if (authz::in_scope(gate.scope, aid))
                    in_scope.push_back(std::move(aid));
                else
                    ++export_dropped;
            }
            scope_arg = std::move(in_scope); // engaged-empty means no rows
        }

        // #4703: byte-aware fetch -- the payload cap is applied IN SQL, so the PGresult and
        // the parsed vector never hold more than about export_body_byte_cap() of
        // output/error_detail (see ResponseStore::query_bounded). Same predicates and
        // scope push-down as query().
        const std::size_t byte_cap = export_body_byte_cap().load();
        auto bounded_opt = deps.store->query_bounded(instruction_id, q, scope_arg, byte_cap);
        if (!bounded_opt) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"response store degraded"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        auto results = std::move(bounded_opt->rows);
        ExportCut cut{bounded_opt->row_cap_hit, bounded_opt->byte_cap_hit};

        // Fail-closed access audit (#4644 Gate 7), mirroring the v1 export twin: a bulk fleet
        // read of up to 10,000 rows / 50 MiB must not be served without durable evidence that it
        // happened. Emitted after the store read (so a 503 degrade is not audited as a read) and
        // BEFORE any body is built, so an audit failure serves no data. The helper also covers an
        // unwired audit_fn (audit off: persisted) and a throwing one (not persisted).
        // CC7.2 evidence: record the scope-drop on this surface (#1634 compliance review).
        if (export_dropped > 0 &&
            !audit_read_or_refuse(deps, req, res, "denied", instruction_id,
                                  "scope_dropped=" + std::to_string(export_dropped) +
                                      " surface=export"))
            return;
        // Same verb, target and result as the v1 export's success row, so the two twins are
        // countable together; the detail names this surface.
        if (!audit_read_or_refuse(deps, req, res, "success", instruction_id,
                                  "legacy response export cid=" +
                                      detail::ensure_correlation_id(res)))
            return;

        auto format = req.get_param_value("format");

        if (format == "csv") {
            std::string csv =
                "id,instruction_id,agent_id,timestamp,status,output,error_detail\r\n";
            // Backstop: CSV escaping makes the serialized row larger than its raw payload.
            cut.byte_cap |= append_rows_until_byte_cap(results, byte_cap, [&csv](const auto& r) {
                csv += std::to_string(r.id) + ",";
                csv += data_export::csv_escape(r.instruction_id) + ",";
                csv += data_export::csv_escape(r.agent_id) + ",";
                csv += std::to_string(r.timestamp) + ",";
                csv += std::to_string(r.status) + ",";
                csv += data_export::csv_escape(r.output) + ",";
                csv += data_export::csv_escape(r.error_detail) + "\r\n";
                return csv.size();
            });
            // A cut CSV ends with an in-band trailer record: the header and the
            // `-truncated` name are both lost by a plain `curl -o`, the body is not.
            if (cut.any())
                csv += export_csv_truncation_row(cut, 7);
            res.set_header("Content-Disposition",
                           "attachment; filename=\"" +
                               export_filename(instruction_id, "csv", cut.any()) + "\"");
            if (cut.any())
                res.set_header("X-Result-Truncated-By-Cap", "true");
            res.set_content(std::move(csv), "text/csv; charset=utf-8");
            // Counted once the response is fully built into `res`: a throw while building
            // a large body must not count a cut that was never served.
            record_response_export_cut(deps.metrics, "rest", cut, {});
        } else {
            nlohmann::json arr = nlohmann::json::array();
            std::size_t json_bytes = 0;
            cut.byte_cap |= append_rows_until_byte_cap(results, byte_cap, [&](const auto& r) {
                arr.push_back({{"id", r.id},
                               {"instruction_id", r.instruction_id},
                               {"agent_id", r.agent_id},
                               {"timestamp", r.timestamp},
                               {"status", r.status},
                               {"output", r.output},
                               {"error_detail", r.error_detail}});
                // Serialized size of the row just appended (escapes counted).
                json_bytes += arr.back().dump().size();
                return json_bytes;
            });
            nlohmann::json envelope = {{"instruction_id", instruction_id},
                                       {"count", arr.size()},
                                       {"responses", nullptr}};
            envelope["responses"] = std::move(arr);
            if (cut.any())
                envelope["result_truncated_by_cap"] = true;
            res.set_header("Content-Disposition",
                           "attachment; filename=\"" +
                               export_filename(instruction_id, "json", cut.any()) + "\"");
            res.set_content(envelope.dump(2), "application/json; charset=utf-8");
            record_response_export_cut(deps.metrics, "rest", cut, {});
        }
    });

    sink.Get(R"(/api/responses/(.+))", [deps](const httplib::Request& req,
                                              httplib::Response& res) {
        auto gate = deps.fleet_read_fn(req, res, "Response", "Read");
        if (!gate.admitted)
            return; // gate already wrote the response.

        auto instruction_id = req.matches[1].str();
        if (instruction_id.empty()) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"instruction_id required"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        if (!deps.store || !deps.store->is_open()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"response store not available"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        ResponseQuery q;
        if (req.has_param("agent_id"))
            q.agent_id = req.get_param_value("agent_id");
        // #4644: strict full-consumption numeric parse (stoi/stoll took "0x1", "1e9",
        // "100abc" as 0/1/100); status < -1 is rejected rather than read as "any".
        if (!apply_response_numeric_params(req, q,
                                           kRespParamStatus | kRespParamSince | kRespParamUntil |
                                               kRespParamLimit | kRespParamOffset)) {
            count_response_param_rejected(deps.metrics, "rest");
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        // The legacy list had no ceiling on an explicit `limit` (an unbounded fetch, the
        // same defect class as #4703's export); v1 and MCP clamp to 1000. limit<=0 keeps
        // meaning the store default (100).
        // The cap used to be silent: a request above it was served `kQueryRowLimitCap` rows
        // with nothing in the body saying so. `clamped` drives the signal below.
        const bool limit_clamped = q.limit > kQueryRowLimitCap;
        q.limit = cap_query_limit(q.limit);

        // #1634 / ADR-0017 INV-3 (CRITICAL): resolve the in-scope agent set and push it
        // into the SQL WHERE clause BEFORE LIMIT/OFFSET — see the /export sibling above
        // for the full rationale (post-fetch filtering a paginated read can hand a
        // confined caller a short or empty page).
        AggregateScope scope_arg; // nullopt = unrestricted
        std::size_t get_dropped = 0;
        if (gate.scope) {
            auto distinct = deps.store->distinct_agent_ids(instruction_id);
            if (!distinct) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"response store degraded"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            std::vector<std::string> in_scope;
            in_scope.reserve(distinct->size());
            for (auto& aid : *distinct) {
                if (authz::in_scope(gate.scope, aid))
                    in_scope.push_back(std::move(aid));
                else
                    ++get_dropped;
            }
            scope_arg = std::move(in_scope); // engaged-empty means no rows
        }

        auto results_opt = deps.store->query(instruction_id, q, scope_arg);
        if (!results_opt) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"response store degraded"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        auto results = std::move(*results_opt);

        // CC7.2 evidence: record the scope-drop on this surface (#1634 compliance review).
        // Fail-closed like the export and the v1 twins (see audit_read_or_refuse).
        if (get_dropped > 0 &&
            !audit_read_or_refuse(deps, req, res, "denied", instruction_id,
                                  "scope_dropped=" + std::to_string(get_dropped) +
                                      " surface=get"))
            return;
        // Fail-closed success row (#4644 Gate 7), mirroring v1 query: after the store read and
        // BEFORE the body is built. The detail names the v1 verb's twin, "query".
        if (!audit_read_or_refuse(deps, req, res, "success", instruction_id,
                                  "legacy response query cid=" +
                                      detail::ensure_correlation_id(res)))
            return;

        nlohmann::json arr = nlohmann::json::array();
        for (const auto& r : results) {
            arr.push_back({{"id", r.id},
                           {"instruction_id", r.instruction_id},
                           {"agent_id", r.agent_id},
                           {"timestamp", r.timestamp},
                           {"status", r.status},
                           {"output", r.output},
                           {"error_detail", r.error_detail}});
        }
        nlohmann::json body = {{"responses", arr}, {"count", arr.size()}};
        // Set only when the caller asked for more than the ceiling AND the page came back
        // full: more rows may exist past it (the fetch does not look ahead, so a result of
        // exactly the ceiling is flagged too). Absent otherwise, so a request that never
        // exceeded the ceiling gets a byte-identical body.
        if (limit_clamped && results.size() == static_cast<std::size_t>(q.limit))
            body["result_truncated_by_cap"] = true;
        res.set_content(body.dump(), "application/json");
    });
}

} // namespace yuzu::server::response
