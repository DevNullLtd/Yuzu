#include "instruction_routes.hpp"

#include "http_route_sink.hpp"
#include "instruction_store.hpp"
#include "instruction_yaml.hpp"
#include "json_extract.hpp"
#include "store_errors.hpp"
#include "web_utils.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <cctype>
#include <string>

// Editor fragment HTML templates — defined in instruction_ui.cpp (a
// separate, build-time-embedded TU) and forward-declared here at global
// (file) scope, mirroring server.cpp's own pre-extraction declaration,
// since both TUs link into the same binary.
extern const char* const kInstructionEditorHtml;
extern const char* const kInstructionEditorDeniedHtml;

namespace yuzu::server::instruction {

void register_instruction_routes(HttpRouteSink& sink, Deps deps) {
    // -- Instruction Definitions API --------------------------------------

    // GET /api/instructions
    sink.Get("/api/instructions", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "InstructionDefinition", "Read"))
            return;
        if (!deps.store || !deps.store->is_open()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"instruction store not available"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        InstructionQuery q;
        if (req.has_param("name"))
            q.name_filter = req.get_param_value("name");
        if (req.has_param("plugin"))
            q.plugin_filter = req.get_param_value("plugin");
        if (req.has_param("type"))
            q.type_filter = req.get_param_value("type");
        if (req.has_param("set_id"))
            q.set_id_filter = req.get_param_value("set_id");
        if (req.has_param("enabled_only"))
            q.enabled_only = true;
        try {
            if (req.has_param("limit"))
                q.limit = std::stoi(req.get_param_value("limit"));
        } catch (const std::exception&) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        // ADR-0058: query_definitions now returns std::expected — a genuine DB
        // error 503s rather than silently rendering an empty list.
        auto defs_result = deps.store->query_definitions(q);
        if (!defs_result) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"instruction store read failed"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        const auto& defs = *defs_result;
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& d : defs) {
            arr.push_back({{"id", d.id},
                           {"name", d.name},
                           {"version", d.version},
                           {"type", d.type},
                           {"plugin", d.plugin},
                           {"action", d.action},
                           {"description", d.description},
                           {"enabled", d.enabled},
                           {"instruction_set_id", d.instruction_set_id},
                           {"created_at", d.created_at},
                           {"updated_at", d.updated_at}});
        }
        res.set_content(nlohmann::json({{"definitions", arr}, {"count", arr.size()}}).dump(),
                        "application/json");
    });

    // POST /api/instructions
    sink.Post("/api/instructions", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "InstructionDefinition", "Write"))
            return;
        if (!deps.store) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        try {
            auto j = nlohmann::json::parse(req.body);
            InstructionDefinition def;
            // #402 / iter-H1: honor caller-supplied `id` so the
            // duplicate-id guard in create_definition_impl actually
            // fires from this endpoint. Prior code dropped the id on
            // the floor, leaving #402's protection store-only.
            def.id = j.value("id", "");
            def.name = j.value("name", "");
            def.version = j.value("version", "1.0");
            def.type = j.value("type", "");
            def.plugin = j.value("plugin", "");
            def.action = j.value("action", "");
            // Normalize action to lowercase — agent plugins match case-sensitively
            for (auto& c : def.action)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            def.description = j.value("description", "");
            def.enabled = j.value("enabled", true);
            def.instruction_set_id = j.value("instruction_set_id", "");
            def.gather_ttl_seconds = j.value("gather_ttl_seconds", 300);
            def.response_ttl_days = j.value("response_ttl_days", 90);
            def.approval_mode = j.value("approval_mode", "auto");
            // Validate approval_mode
            if (def.approval_mode != "auto" && def.approval_mode != "role-gated" &&
                def.approval_mode != "always") {
                res.status = 400;
                res.set_content(
                    nlohmann::json({{"error", "invalid approval_mode: " + def.approval_mode +
                                                  " (must be auto, role-gated, or always)"}})
                        .dump(),
                    "application/json");
                return;
            }

            if (auto session = deps.resolve_session_fn(req))
                def.created_by = session->username;

            auto result = deps.store->create_definition(def);
            if (!result) {
                // ADR-0058: a genuine DB/lease failure 503s — never falls through to
                // the conflict/validation split below (see delete routes for the
                // same check).
                if (result.error().rfind(kInstructionStoreDbErrorPrefix, 0) == 0) {
                    // R2: checked, not discarded — a create denial is a security-relevant
                    // evidence-chain audit (see audit_log's [[nodiscard]] comment).
                    // "error", not "denied" (gov Gate 6 compliance-officer finding): an
                    // infra degrade is not an operator denial — matches policy.evaluate's
                    // own error-vs-denied convention (rest-api.md's classification rule).
                    const bool audit_ok = deps.audit_fn(req, "instruction.create", "error",
                                                        "InstructionDefinition", def.id,
                                                        "db_error");
                    if (!audit_ok)
                        res.set_header("Sec-Audit-Failed", "true");
                    res.status = 503;
                    res.set_content(
                        R"({"error":{"code":503,"message":"instruction store unavailable"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return;
                }
                // #402: store-level kConflictPrefix maps to HTTP 409. The
                // prefix is an internal store↔route contract — strip it
                // before placing the message in the operator-facing JSON
                // body (governance enterprise-N1). Emit a denied audit
                // event so duplicate-id probing leaves a trace
                // (governance compliance-1, up-18).
                bool is_conflict = is_conflict_error(result.error());
                res.status = is_conflict ? 409 : 400;
                if (is_conflict) {
                    (void)deps.audit_fn(req, "instruction.create", "denied",
                                        "InstructionDefinition", def.id, "duplicate_id");
                }
                auto body_msg = is_conflict ? std::string(strip_conflict_prefix(result.error()))
                                            : result.error();
                res.set_content(nlohmann::json({{"error", body_msg}}).dump(),
                                "application/json");
                return;
            }
            (void)deps.audit_fn(req, "instruction.create", "success", "InstructionDefinition",
                                *result, def.name);
            deps.emit_event_fn("instruction.created", req,
                               {{"name", def.name},
                                {"plugin", def.plugin},
                                {"action", def.action},
                                {"type", def.type}},
                               {{"instruction_id", *result}});
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Instruction definition created","level":"success"}})");
            res.set_content(nlohmann::json({{"id", *result}}).dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    // GET /api/instructions/:id
    sink.Get(R"(/api/instructions/([^/]+))", [deps](const httplib::Request& req,
                                                     httplib::Response& res) {
        if (!deps.perm_fn(req, res, "InstructionDefinition", "Read"))
            return;
        if (!deps.store) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto id = req.matches[1].str();
        // ADR-0058: get_definition now returns std::expected — distinguish a genuine
        // DB error (503) from "no such definition" (404, unchanged).
        auto def_result = deps.store->get_definition(id);
        if (!def_result) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"instruction store read failed"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        if (!*def_result) {
            res.status = 404;
            res.set_content(
                R"({"error":{"code":404,"message":"not found"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        const auto& def = **def_result;

        res.set_content(nlohmann::json({{"id", def.id},
                                        {"name", def.name},
                                        {"version", def.version},
                                        {"type", def.type},
                                        {"plugin", def.plugin},
                                        {"action", def.action},
                                        {"description", def.description},
                                        {"enabled", def.enabled},
                                        {"instruction_set_id", def.instruction_set_id},
                                        {"gather_ttl_seconds", def.gather_ttl_seconds},
                                        {"response_ttl_days", def.response_ttl_days},
                                        {"created_by", def.created_by},
                                        {"created_at", def.created_at},
                                        {"updated_at", def.updated_at}})
                            .dump(),
                        "application/json");
    });

    // PUT /api/instructions/:id
    sink.Put(R"(/api/instructions/([^/]+))", [deps](const httplib::Request& req,
                                                     httplib::Response& res) {
        if (!deps.perm_fn(req, res, "InstructionDefinition", "Write"))
            return;
        if (!deps.store) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto id = req.matches[1].str();
        try {
            auto j = nlohmann::json::parse(req.body);

            // Read existing definition to preserve fields not in the update.
            // ADR-0058: get_definition now returns std::expected — distinguish a
            // genuine DB error (503) from "no such definition" (404, unchanged).
            auto existing_result = deps.store->get_definition(id);
            if (!existing_result) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"instruction store read failed"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            if (!*existing_result) {
                res.status = 404;
                res.set_content(
                    R"({"error":{"code":404,"message":"instruction definition not found"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            InstructionDefinition def = **existing_result;
            if (j.contains("name"))
                def.name = j["name"].get<std::string>();
            if (j.contains("version"))
                def.version = j["version"].get<std::string>();
            if (j.contains("type"))
                def.type = j["type"].get<std::string>();
            if (j.contains("plugin"))
                def.plugin = j["plugin"].get<std::string>();
            if (j.contains("action")) {
                def.action = j["action"].get<std::string>();
                // Normalize action to lowercase
                for (auto& c : def.action)
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
            if (j.contains("description"))
                def.description = j["description"].get<std::string>();
            if (j.contains("enabled"))
                def.enabled = j["enabled"].get<bool>();
            if (j.contains("instruction_set_id"))
                def.instruction_set_id = j["instruction_set_id"].get<std::string>();
            if (j.contains("approval_mode")) {
                def.approval_mode = j["approval_mode"].get<std::string>();
                if (def.approval_mode != "auto" && def.approval_mode != "role-gated" &&
                    def.approval_mode != "always") {
                    res.status = 400;
                    res.set_content(
                        nlohmann::json(
                            {{"error", "invalid approval_mode: " + def.approval_mode +
                                           " (must be auto, role-gated, or always)"}})
                            .dump(),
                        "application/json");
                    return;
                }
            }

            auto result = deps.store->update_definition(def);
            if (!result) {
                // ADR-0058: a genuine DB/lease failure 503s; "not_found: " -> 404 (mirrors
                // the DELETE route immediately below); everything else is a 400 validation
                // error. Previously not_found fell through to the 400 branch, indistinguishable
                // from a validation failure (consistency-auditor Gate 8 finding).
                bool db_error = result.error().rfind(kInstructionStoreDbErrorPrefix, 0) == 0;
                bool not_found = !db_error && result.error().rfind("not_found: ", 0) == 0;
                // Audited on db_error (existing convention) and not_found (matches the
                // DELETE route's audited not_found branch just below); a plain validation
                // 400 stays unaudited, matching create_definition's equivalent branch.
                // R2: checked, not discarded — an update denial is a security-relevant
                // evidence-chain audit (see audit_log's [[nodiscard]] comment).
                bool audit_ok = true;
                if (db_error)
                    // "error", not "denied" (gov Gate 6 compliance-officer finding): an
                    // infra degrade is not an operator denial.
                    audit_ok = deps.audit_fn(req, "instruction.update", "error",
                                             "InstructionDefinition", id, "db_error");
                else if (not_found)
                    audit_ok = deps.audit_fn(req, "instruction.update", "denied",
                                             "InstructionDefinition", id, "not_found");
                if ((db_error || not_found) && !audit_ok)
                    res.set_header("Sec-Audit-Failed", "true");
                res.status = db_error ? 503 : (not_found ? 404 : 400);
                res.set_content(nlohmann::json({{"error", db_error
                                                               ? "instruction store unavailable"
                                                               : result.error()}})
                                    .dump(),
                                "application/json");
                return;
            }
            (void)deps.audit_fn(req, "instruction.update", "success", "InstructionDefinition", id,
                                "");
            deps.emit_event_fn("instruction.updated", req, {}, {{"instruction_id", id}});
            res.set_header(
                "HX-Trigger",
                R"({"showToast":{"message":"Instruction definition updated","level":"success"}})");
            res.set_content(R"({"status":"ok"})", "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    // DELETE /api/instructions/:id
    sink.Delete(R"(/api/instructions/([^/]+))", [deps](const httplib::Request& req,
                                                        httplib::Response& res) {
        if (!deps.perm_fn(req, res, "InstructionDefinition", "Delete"))
            return;
        if (!deps.store) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto id = req.matches[1].str();
        // ADR-0058: delete_definition now returns std::expected<void, std::string> —
        // a genuine DB error 503s distinctly; "not_found: " -> 404 (mirrors
        // ProductPackStore::uninstall's identical REST contract change,
        // workflow_routes.cpp product_pack_error_status).
        auto del_result = deps.store->delete_definition(id);
        // R2: checked, not discarded — a delete denial is a security-relevant
        // evidence-chain audit (see audit_log's [[nodiscard]] comment).
        if (!del_result && del_result.error().rfind(kInstructionStoreDbErrorPrefix, 0) == 0) {
            // "error", not "denied" (gov Gate 6 compliance-officer finding): an infra
            // degrade is not an operator denial.
            if (!deps.audit_fn(req, "instruction.delete", "error", "InstructionDefinition", id,
                               "db_error"))
                res.set_header("Sec-Audit-Failed", "true");
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"instruction store delete failed"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        if (!del_result) {
            if (!deps.audit_fn(req, "instruction.delete", "denied", "InstructionDefinition", id,
                               "not_found"))
                res.set_header("Sec-Audit-Failed", "true");
            res.status = 404;
            res.set_content(
                R"({"error":{"code":404,"message":"instruction definition not found"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        (void)deps.audit_fn(req, "instruction.delete", "success", "InstructionDefinition", id, "");
        deps.emit_event_fn("instruction.deleted", req, {}, {{"instruction_id", id}});
        res.set_header(
            "HX-Trigger",
            R"({"showToast":{"message":"Instruction definition deleted","level":"success"}})");
        res.set_content(nlohmann::json({{"deleted", true}}).dump(), "application/json");
    });

    // GET /api/instructions/:id/export
    sink.Get(R"(/api/instructions/([^/]+)/export)", [deps](const httplib::Request& req,
                                                            httplib::Response& res) {
        if (!deps.perm_fn(req, res, "InstructionDefinition", "Read"))
            return;
        if (!deps.store) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto id = req.matches[1].str();
        // ADR-0058: export_definition_json now returns std::expected — a genuine
        // DB error 503s rather than silently rendering an empty/malformed body.
        auto json_result = deps.store->export_definition_json(id);
        if (!json_result) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"instruction store read failed"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        res.set_content(*json_result, "application/json");
    });

    // POST /api/instructions/import
    sink.Post("/api/instructions/import", [deps](const httplib::Request& req,
                                                 httplib::Response& res) {
        if (!deps.perm_fn(req, res, "InstructionDefinition", "Write"))
            return;
        if (!deps.store) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto result = deps.store->import_definition_json(req.body);
        if (!result) {
            // ADR-0058: a genuine DB/lease failure 503s — never falls through to the
            // conflict/validation split below. R4: audited the same as every other
            // rejection branch below (gov Gate 6 compliance-officer finding).
            if (result.error().rfind(kInstructionStoreDbErrorPrefix, 0) == 0) {
                // "error", not "denied" (gov Gate 6 compliance-officer finding, second
                // round): an infra degrade is not an operator denial.
                const bool audit_ok = deps.audit_fn(req, "instruction.import", "error",
                                                    "InstructionDefinition", "", "db_error");
                if (!audit_ok)
                    res.set_header("Sec-Audit-Failed", "true");
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"instruction store unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            // iter-H2: /import shares the create_definition_impl path,
            // so it inherits the kConflictPrefix → 409 mapping that the
            // POST handler does. Without this mapping the import path
            // returns 400 with the raw "conflict:" prefix in the body
            // — defeats the prefix-stripping contract on the very
            // endpoint that exercises duplicate-id rejection most.
            bool is_conflict = is_conflict_error(result.error());
            res.status = is_conflict ? 409 : 400;
            // R4 (gov R1 unhappy/security HIGH): audit EVERY rejection
            // path, not just conflicts. The #1073 signature gate adds
            // five new rejection branches (signature_invalid,
            // signature_incomplete, signature_wrong_length, signature_
            // missing_content, unsigned_rejected); each is an access
            // decision the SOC 2 CC6.7 audit trail must reflect. The
            // detail is the store-returned error message classified
            // either as "duplicate_id" (the legacy contract) or the
            // raw error text (which begins with a stable token like
            // "signature verification failed" / "instruction-import
            // is unsigned" / etc. that SIEM rules can key on).
            std::string detail = is_conflict ? "duplicate_id" : result.error();
            // R2 / Gate 4 unhappy UP-1 + compliance CO-1: capture the
            // audit_log return and surface failure to the operator via
            // Sec-Audit-Failed header (PR #883 / SOC 2 CC7.2 pattern at
            // rest_api_v1.cpp:1129). Silently discarding the bool on a
            // security-decision audit row re-opens the evidence-chain
            // gap whose closure was the whole point of R4's hoist.
            // R2 / Gate 4 consistency CONS-BLOCKING-1: target_type is
            // now the RBAC-securable PascalCase "InstructionDefinition"
            // matching ProductPack's W7.4 R2 normalisation, NOT the
            // legacy lowercase "instruction" string.
            const bool audit_ok = deps.audit_fn(req, "instruction.import", "denied",
                                                "InstructionDefinition", "", detail);
            if (!audit_ok)
                res.set_header("Sec-Audit-Failed", "true");
            auto body_msg = is_conflict ? std::string(strip_conflict_prefix(result.error()))
                                        : result.error();
            // R3 governance security MEDIUM-1: body field mirrors the
            // captured bool, NOT a hardcoded `false`. On the rare
            // happy-rejection path (request denied AND audit row
            // persisted successfully) the operator sees
            // `audit_emitted: true`. Symmetric with the success branch
            // below.
            res.set_content(
                nlohmann::json({{"error", body_msg}, {"audit_emitted", audit_ok}}).dump(),
                "application/json");
            return;
        }
        // R2 success-branch: same Sec-Audit-Failed treatment so a wedged
        // audit-store on a successful import surfaces to the operator —
        // SOC 2 CC7.2 requires the evidence row, and silently landing a
        // definition in the DB without the row is a half-broken chain.
        const bool audit_ok =
            deps.audit_fn(req, "instruction.import", "success", "InstructionDefinition", *result,
                         "");
        if (!audit_ok)
            res.set_header("Sec-Audit-Failed", "true");
        res.set_header("HX-Trigger",
                       R"({"showToast":{"message":"Definitions imported","level":"success"}})");
        res.set_content(nlohmann::json({{"id", *result}, {"audit_emitted", audit_ok}}).dump(),
                        "application/json");
    });

    // -- Instruction Sets API ---------------------------------------------

    // GET /api/instruction-sets
    sink.Get("/api/instruction-sets", [deps](const httplib::Request& req,
                                             httplib::Response& res) {
        if (!deps.perm_fn(req, res, "InstructionSet", "Read"))
            return;
        if (!deps.store) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        // ADR-0058: list_sets now returns std::expected — a genuine DB error 503s
        // rather than silently rendering an empty list.
        auto sets_result = deps.store->list_sets();
        if (!sets_result) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"instruction store read failed"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        const auto& sets = *sets_result;
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& s : sets) {
            arr.push_back({{"id", s.id},
                           {"name", s.name},
                           {"description", s.description},
                           {"created_by", s.created_by},
                           {"created_at", s.created_at}});
        }
        res.set_content(nlohmann::json({{"sets", arr}}).dump(), "application/json");
    });

    // POST /api/instruction-sets
    sink.Post("/api/instruction-sets", [deps](const httplib::Request& req,
                                              httplib::Response& res) {
        if (!deps.perm_fn(req, res, "InstructionSet", "Write"))
            return;
        if (!deps.store) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto name = extract_json_string(req.body, "name");
        auto desc = extract_json_string(req.body, "description");
        InstructionSet s;
        s.name = name;
        s.description = desc;
        auto result = deps.store->create_set(s);
        if (!result) {
            // ADR-0058: a genuine DB/lease failure 503s, never falls through to
            // the conflict/validation split below.
            // Not audited: this route has no audit logging at all (success or failure),
            // pre-existing and unrelated to this migration — tracked separately, not
            // asymmetrically half-fixed here (#3598).
            bool db_error = result.error().rfind(kInstructionStoreDbErrorPrefix, 0) == 0;
            if (db_error) {
                res.status = 503;
                res.set_content(
                    R"({"error":"instruction store unavailable"})",
                    "application/json");
                return;
            }
            // Gate 4 Finding A / Gate 6 enterprise-readiness: this route was the one
            // sibling of instruction.create/update/delete that never added the
            // is_conflict_error branch store_errors.hpp's kConflictPrefix comment says
            // every duplicate-class error site must handle — a duplicate id fell
            // through to plain 400 with the raw unstripped "conflict:" prefix in the
            // body. Matches instruction.create's pattern (this route still has no audit
            // logging at all, pre-existing gap, not fixed here).
            bool is_conflict = is_conflict_error(result.error());
            res.status = is_conflict ? 409 : 400;
            auto body_msg = is_conflict ? std::string(strip_conflict_prefix(result.error()))
                                        : result.error();
            res.set_content(nlohmann::json({{"error", body_msg}}).dump(), "application/json");
            return;
        }
        res.set_content(nlohmann::json({{"id", *result}}).dump(), "application/json");
    });

    // DELETE /api/instruction-sets/:id
    sink.Delete(R"(/api/instruction-sets/([^/]+))", [deps](const httplib::Request& req,
                                                            httplib::Response& res) {
        if (!deps.perm_fn(req, res, "InstructionSet", "Delete"))
            return;
        if (!deps.store) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto id = req.matches[1].str();
        // ADR-0058: delete_set now returns std::expected<void, std::string> — a
        // genuine DB error 503s distinctly; "not_found: " -> 404 (mirrors
        // ProductPackStore::uninstall's identical REST contract change).
        auto del_result = deps.store->delete_set(id);
        // R2 / gov Gate 4 consistency-auditor finding: these 404/503 denial branches are
        // new in this migration (pre-migration delete_set was an undifferentiated
        // 200 {"deleted": bool} with no distinguishable denial to audit) — unlike
        // create_set (still undifferentiated 400/503 today, tracked separately, #3598),
        // these are new-in-this-diff and must not ship unaudited from birth.
        if (!del_result && del_result.error().rfind(kInstructionStoreDbErrorPrefix, 0) == 0) {
            if (!deps.audit_fn(req, "instruction_set.delete", "error", "InstructionSet", id,
                               "db_error"))
                res.set_header("Sec-Audit-Failed", "true");
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"instruction store delete failed"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        if (!del_result) {
            if (!deps.audit_fn(req, "instruction_set.delete", "denied", "InstructionSet", id,
                               "not_found"))
                res.set_header("Sec-Audit-Failed", "true");
            res.status = 404;
            res.set_content(
                R"({"error":{"code":404,"message":"instruction set not found"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        res.set_content(nlohmann::json({{"deleted", true}}).dump(), "application/json");
    });

    // -- Editor fragment: RBAC-gated to PlatformEngineer / Administrator --
    // GET /fragments/instructions/editor
    sink.Get("/fragments/instructions/editor", [deps](const httplib::Request& req,
                                                       httplib::Response& res) {
        auto session = deps.auth_fn(req, res);
        if (!session)
            return;

        // Check InstructionDefinition:Write via RBAC; falls back to admin check
        if (!deps.perm_fn(req, res, "InstructionDefinition", "Write")) {
            // Override JSON 403 with HTML denial for HTMX fragment
            res.status = 200;
            res.set_content(kInstructionEditorDeniedHtml, "text/html; charset=utf-8");
            return;
        }

        std::string tmpl(kInstructionEditorHtml);
        auto def_id = req.get_param_value("id");
        if (!def_id.empty() && deps.store) {
            // ADR-0058: a DB-error outer result skips this best-effort pre-fill (the
            // form falls back to unreplaced placeholders), same as a not-found inner
            // optional did pre-migration.
            auto def_result = deps.store->get_definition(def_id);
            if (def_result && *def_result) {
                const auto& def = **def_result;
                auto replace = [&](const std::string& key, const std::string& val) {
                    for (auto pos = tmpl.find(key); pos != std::string::npos;
                         pos = tmpl.find(key))
                        tmpl.replace(pos, key.size(), html_escape(val));
                };
                replace("{{TITLE}}", "Edit Definition");
                replace("{{DEF_ID}}", def.id);
                replace("{{DEF_NAME}}", def.name);
                replace("{{DEF_VERSION}}", def.version);
                replace("{{DEF_PLUGIN}}", def.plugin);
                replace("{{DEF_ACTION}}", def.action);
                replace("{{DEF_DESCRIPTION}}", def.description);
                replace("{{DEF_PLATFORMS}}", def.platforms);
                replace("{{YAML_SOURCE}}", def.yaml_source);
                // Set dropdowns
                replace("{{SEL_QUESTION}}", def.type == "question" ? "selected" : "");
                replace("{{SEL_ACTION}}", def.type == "action" ? "selected" : "");
                replace("{{SEL_APPR_AUTO}}", def.approval_mode == "auto" ? "selected" : "");
                replace("{{SEL_APPR_ROLE}}",
                        def.approval_mode == "role-gated" ? "selected" : "");
                replace("{{SEL_APPR_ALWAYS}}",
                        def.approval_mode == "always" ? "selected" : "");
                replace("{{SEL_CC_UNLIM}}",
                        def.concurrency_mode == "unlimited" ? "selected" : "");
                replace("{{SEL_CC_DEV}}",
                        def.concurrency_mode == "per-device" ? "selected" : "");
                replace("{{SEL_CC_DEF}}",
                        def.concurrency_mode == "per-definition" ? "selected" : "");
                replace("{{SEL_CC_SET}}", def.concurrency_mode == "per-set" ? "selected" : "");
                // Fifth, dynamic option (Gate 6 enterprise-readiness finding, PR #3784 fix
                // round): the four static options above cover every ENFORCED/documented
                // mode, but the real content library also ships `global`/`global-singleton`
                // (42 catalog-only `plugin: server` definitions, ADR-1007) — neither matches
                // any static <option>, so none was ever `selected` and the browser silently
                // defaulted to displaying "Unlimited". Form-mode "Convert to YAML" then baked
                // that displayed default into the generated YAML, so an ordinary Save on one
                // of those 42 definitions silently overwrote its real concurrency_mode. Fixed
                // by emitting a raw <option> carrying the actual stored value whenever it
                // doesn't match one of the four known modes, so round-tripping never discards
                // it. NOT run through the escaping `replace()` lambda above (it HTML-escapes
                // the whole substituted string, which would mangle this option's own tags) —
                // only the stored value itself is escaped, everything else is a literal
                // template.
                {
                    static const std::string kOtherPlaceholder = "{{SEL_CC_OTHER_OPTION}}";
                    std::string other_option;
                    if (!def.concurrency_mode.empty() && def.concurrency_mode != "unlimited" &&
                        def.concurrency_mode != "per-device" &&
                        def.concurrency_mode != "per-definition" &&
                        def.concurrency_mode != "per-set") {
                        const auto escaped = html_escape(def.concurrency_mode);
                        other_option = "<option value=\"" + escaped + "\" selected>" + escaped +
                                      " (unrecognized, not enforced)</option>";
                    }
                    for (auto pos = tmpl.find(kOtherPlaceholder); pos != std::string::npos;
                         pos = tmpl.find(kOtherPlaceholder))
                        tmpl.replace(pos, kOtherPlaceholder.size(), other_option);
                }
            }
        } else {
            // New definition — clear all placeholders
            auto clear = [&](const std::string& key) {
                for (auto pos = tmpl.find(key); pos != std::string::npos; pos = tmpl.find(key))
                    tmpl.replace(pos, key.size(), "");
            };
            auto replace = [&](const std::string& key, const std::string& val) {
                for (auto pos = tmpl.find(key); pos != std::string::npos; pos = tmpl.find(key))
                    tmpl.replace(pos, key.size(), val);
            };
            replace("{{TITLE}}", "New Definition");
            clear("{{DEF_ID}}");
            clear("{{DEF_NAME}}");
            clear("{{DEF_VERSION}}");
            clear("{{DEF_PLUGIN}}");
            clear("{{DEF_ACTION}}");
            clear("{{DEF_DESCRIPTION}}");
            clear("{{DEF_PLATFORMS}}");
            replace("{{YAML_SOURCE}}",
                    "apiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\n"
                    "metadata:\n  name: \"\"\n  version: \"1.0.0\"\nspec:\n"
                    "  plugin: \"\"\n  action: \"\"\n  type: question\n"
                    "  description: \"\"\n  concurrency: unlimited\n"
                    "  approval: auto\n  parameters:\n    type: object\n"
                    "    additionalProperties:\n      type: string\n"
                    "  results:\n    - name: output\n      type: string\n");
            replace("{{SEL_QUESTION}}", "selected");
            clear("{{SEL_ACTION}}");
            replace("{{SEL_APPR_AUTO}}", "selected");
            clear("{{SEL_APPR_ROLE}}");
            clear("{{SEL_APPR_ALWAYS}}");
            replace("{{SEL_CC_UNLIM}}", "selected");
            clear("{{SEL_CC_DEV}}");
            clear("{{SEL_CC_DEF}}");
            clear("{{SEL_CC_SET}}");
            clear("{{SEL_CC_OTHER_OPTION}}");
        }
        res.set_content(tmpl, "text/html; charset=utf-8");
    });

    // -- YAML save endpoint (HTMX form POST from editor) --
    // POST /api/instructions/yaml
    sink.Post("/api/instructions/yaml", [deps](const httplib::Request& req,
                                               httplib::Response& res) {
        if (!deps.perm_fn(req, res, "InstructionDefinition", "Write"))
            return;
        auto session = deps.auth_fn(req, res);
        if (!session)
            return;
        if (!deps.store) {
            res.set_content(
                "<div class=\"alert alert-error\">Instruction store not available</div>",
                "text/html");
            return;
        }

        auto yaml_source = req.get_param_value("yaml_source");
        auto def_id = req.get_param_value("id");

        // Save shares one contract with /api/instructions/validate-yaml
        // (#1993): YAML that passes validation always carries what Save
        // needs, and a failing Save names the actual missing field
        // instead of a blanket "Missing required fields" for all three.
        auto errors = validate_yaml_source(yaml_source);
        if (!errors.empty()) {
            std::string html =
                "<div class=\"alert alert-error\"><strong>Cannot save:</strong><ul>";
            for (const auto& e : errors)
                html += "<li>" + html_escape(e) + "</li>";
            html += "</ul></div>";
            res.set_content(html, "text/html");
            return;
        }

        // Schema-aware extraction of the denormalized columns — accepts
        // both the canonical nested schema (metadata.id,
        // spec.execution.plugin/action — what the docs, validate-yaml,
        // and every bundled definition use) and the flat schema the New
        // Definition panel's structured form generates (metadata.name,
        // spec.plugin/action). The YAML source stays the verbatim source
        // of truth; absent optional fields get the same defaults the
        // bundled importer applies (embed_content.py::def_envelope).
        auto fields = instruction_yaml::parse_definition_yaml(yaml_source);

        InstructionDefinition def;
        def.name = fields.name;
        def.version = fields.version.empty() ? "1.0.0" : fields.version;
        def.plugin = fields.plugin;
        def.action = fields.action; // lowercased by the parser
        def.type = fields.type.empty() ? "question" : fields.type;
        def.description = fields.description;
        def.concurrency_mode = fields.concurrency.empty() ? "per-device" : fields.concurrency;
        def.approval_mode = fields.approval.empty() ? "auto" : fields.approval;
        def.yaml_source = yaml_source;
        def.created_by = session->username;
        def.enabled = true;

        // Toast + inline alert for every outcome. dump() uses the
        // `replace` error handler: failure messages can embed
        // operator-supplied ids, and the default handler would throw on
        // invalid UTF-8, degrading the feedback to a bare httplib 500
        // (governance cpp-S1 / UP-4).
        auto respond = [&](const std::string& msg, bool ok) {
            nlohmann::json trigger = {
                {"showToast", {{"message", msg}, {"level", ok ? "success" : "error"}}}};
            res.set_header("HX-Trigger",
                           trigger.dump(-1, ' ', false,
                                        nlohmann::json::error_handler_t::replace));
            res.set_content("<div class=\"alert alert-" +
                                std::string(ok ? "success" : "error") + "\">" +
                                html_escape(msg) + "</div>",
                            "text/html");
        };

        if (!def_id.empty()) {
            // Route id is authoritative on update — but a yaml_source
            // self-declaring a DIFFERENT metadata.id would be stored
            // verbatim and fork the definition on any later re-import
            // (governance UP-8/cons-N1). Reject the divergence outright.
            if (!fields.id.empty() && fields.id != def_id) {
                respond("YAML metadata.id '" + fields.id +
                            "' does not match the definition being edited ('" + def_id +
                            "') — correct or remove metadata.id",
                        false);
                return;
            }
            def.id = def_id;
            auto result = deps.store->update_definition(def);
            if (!result) {
                spdlog::warn("instruction yaml update failed: id={} error={}",
                             log_safe(def_id), result.error());
                // A db_error-prefixed message can carry libpq internals (PQerrorMessage
                // fragments) — generic-ize it before it reaches the operator, matching
                // workflow_routes.cpp's product_pack_client_message convention (gov Gate 4
                // consistency finding).
                bool db_error = result.error().rfind(kInstructionStoreDbErrorPrefix, 0) == 0;
                respond("Update failed: " +
                            (db_error ? "instruction store unavailable" : result.error()),
                        false);
                return;
            }
            (void)deps.audit_fn(req, "instruction.update", "success", "InstructionDefinition",
                                def_id, "");
            deps.emit_event_fn("instruction.updated", req, {}, {{"instruction_id", def_id}});
            respond("Definition updated", true);
        } else {
            // A canonical definition names itself via metadata.id — honor
            // it (the store 409s on conflict), matching bundled-importer
            // semantics; without one the store generates an id.
            def.id = fields.id;
            auto result = deps.store->create_definition(def);
            if (!result) {
                // #402 pattern (mirrors the JSON create route): strip the
                // internal store↔route conflict token before it reaches
                // the operator, map to 409 so scripted re-runs of the
                // getting-started import see a real status, and leave a
                // denied-audit trace for duplicate-id probing.
                bool is_conflict = is_conflict_error(result.error());
                spdlog::warn("instruction yaml create failed: id={} error={}",
                             log_safe(def.id), result.error());
                if (is_conflict) {
                    res.status = 409;
                    (void)deps.audit_fn(req, "instruction.create", "denied",
                                        "InstructionDefinition", def.id, "duplicate_id");
                    respond("Create failed: " +
                                std::string(strip_conflict_prefix(result.error())),
                            false);
                } else {
                    // See the update-branch comment above (gov Gate 4 consistency finding).
                    bool db_error = result.error().rfind(kInstructionStoreDbErrorPrefix, 0) == 0;
                    respond("Create failed: " +
                                (db_error ? "instruction store unavailable" : result.error()),
                            false);
                }
                return;
            }
            (void)deps.audit_fn(req, "instruction.create", "success", "InstructionDefinition",
                                *result, def.name);
            deps.emit_event_fn("instruction.created", req,
                               {{"name", def.name}, {"plugin", def.plugin}, {"action", def.action},
                                {"type", def.type}},
                               {{"instruction_id", *result}});
            respond("Definition created", true);
        }
    });

    // -- YAML validate endpoint --
    // POST /api/instructions/validate-yaml
    sink.Post("/api/instructions/validate-yaml", [deps](const httplib::Request& req,
                                                        httplib::Response& res) {
        if (!deps.perm_fn(req, res, "InstructionDefinition", "Read"))
            return;

        auto yaml_source = req.get_param_value("yaml_source");
        auto errors = validate_yaml_source(yaml_source);

        if (errors.empty()) {
            res.set_content("<div class=\"alert alert-success\">YAML validation passed</div>",
                            "text/html");
        } else {
            std::string html =
                "<div class=\"alert alert-error\"><strong>Validation errors:</strong><ul>";
            for (const auto& e : errors)
                html += "<li>" + html_escape(e) + "</li>";
            html += "</ul></div>";
            res.set_content(html, "text/html");
        }
    });
}

} // namespace yuzu::server::instruction
