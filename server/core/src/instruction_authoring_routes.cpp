#include "instruction_authoring_routes.hpp"

#include "http_route_sink.hpp"
#include "instruction_definition_model.hpp"
#include "instruction_execute.hpp" // bounded_definition_id / definition_id_* (audit target hygiene)
#include "instruction_extras_render.hpp"
#include "instruction_store.hpp"
#include "instruction_yaml.hpp"
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth (#2437-class guard)
#include "rest_a4_envelope.hpp"
#include "rest_a4_envelope_http.hpp"
#include "rest_audit.hpp" // detail::try_persist_audit (a throwing sink is a failed row)
#include "store_errors.hpp"

#include <yuzu/log_token.hpp>

#include <spdlog/spdlog.h>

#include <nlohmann/json.hpp>

#include <charconv>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server::instruction_authoring {

namespace {

using nlohmann::json;
using detail::A4ErrorOpts;
using instruction_execute::bounded_definition_id;
using instruction_execute::definition_id_is_malformed;
using instruction_execute::definition_id_needs_audit_fold;

constexpr int kRetryAfterMs = 5000;
/// `dump()` with the `replace` handler: a body can embed bytes from caller-supplied YAML (a
/// validation message quoting a value), and the default handler throws on invalid UTF-8, which
/// would turn the answer into a bare httplib 500.
std::string dump_safe(const json& j) {
    return j.dump(-1, ' ', false, json::error_handler_t::replace);
}

std::string ok_body(json data) {
    return dump_safe(json{{"data", std::move(data)}, {"meta", {{"api_version", "v1"}}}});
}

void send_ok(httplib::Response& res, int status, json data) {
    res.status = status;
    res.set_content(ok_body(std::move(data)), "application/json");
}

/// A4 error. `retry` adds `retry_after_ms` (a transient store or audit fault); a 4xx never has one.
void fail(httplib::Response& res, int status, std::string_view message, bool retry = false) {
    res.status = status;
    A4ErrorOpts opts;
    if (retry)
        opts.retry_after_ms = kRetryAfterMs;
    res.set_content(detail::a4_error(res, message, opts), "application/json");
}

/// 503 for a store fault on a WRITE, after its attempted audit row. A connection lost after
/// COMMIT is indistinguishable from one lost before it, so the write may have landed: say so, and
/// tell the caller to read before retrying (a blind retry of a landed create is a duplicate-id 409,
/// of a landed delete a 404). No idempotency key exists to make the retry safe, so NO
/// `retry_after_ms` is sent: a machine client that honours the hint would blind-retry.
void fail_write_unknown(httplib::Response& res, std::string_view noun) {
    fail(res, 503,
         "instruction store unavailable; outcome unknown: read the " + std::string(noun) +
             " before retrying",
         /*retry=*/false);
}

/// 400 carrying the validator's full list as a typed `errors` array beside the A4 fields, so a
/// caller branches without parsing prose.
void fail_with_errors(httplib::Response& res, std::string_view message,
                      const std::vector<std::string>& errors) {
    res.status = 400;
    json err{{"code", 400},
             {"message", std::string(message)},
             {"retry_after_ms", nullptr},
             {"correlation_id", detail::ensure_correlation_id(res)},
             {"errors", errors}};
    res.set_content(dump_safe(json{{"error", std::move(err)}, {"meta", {{"api_version", "v1"}}}}),
                    "application/json");
}

/// Logs a missing dependency once per process, not per request. `logged` is the CALLER's own flag
/// (one per `what`), so two different missing dependencies each get their one line.
void warn_unwired(std::once_flag& logged, const char* what) {
    std::call_once(logged, [what] {
        spdlog::error("instruction authoring routes: {} is not wired; refusing the affected "
                      "requests (server configuration defect)",
                      what);
    });
}

/// The gate's answer when it did not admit: an unwired gate is misconfiguration (500), never "no
/// gate"; a wired gate has already written its own refusal. Returns false so a handler can
/// `return` on it. The gate CALL stays inline in each handler (`deps.perm_fn(req, res, "S", "O")`):
/// check-api-parity.py reads the pair from the handler's own text.
bool refuse_gate(const RouteDeps& d, httplib::Response& res) {
    if (!d.perm_fn) {
        static std::once_flag logged;
        warn_unwired(logged, "perm_fn");
        fail(res, 500, "authorization not configured");
    }
    return false;
}

/// Dependency checks after the gate. Returns false when the request has been answered. `writes`
/// routes additionally need the audit sink (audit-first: no sink, no mutation); `needs_store`
/// is false only for validate-yaml, which never touches the store.
bool admit_dependencies(const RouteDeps& d, httplib::Response& res, bool writes,
                        bool needs_store = true) {
    if (writes && !d.audit_fn) {
        static std::once_flag logged;
        warn_unwired(logged, "audit_fn");
        res.set_header("Sec-Audit-Failed", "true");
        fail(res, 503, "audit subsystem not configured; nothing was changed");
        return false;
    }
    if (needs_store && (!d.store || !d.store->is_open())) {
        fail(res, 503, "instruction store not available", /*retry=*/true);
        return false;
    }
    return true;
}

/// A JSON-object request body, or nullopt after answering 400. Depth is checked on the raw text
/// before parsing so a pathologically nested body cannot overflow the parser's recursion.
std::optional<json> parse_object_body(const httplib::Request& req, httplib::Response& res) {
    if (mcp::json_exceeds_depth(req.body, mcp::kMcpMaxJsonDepth)) {
        fail(res, 400, "request body nests too deeply");
        return std::nullopt;
    }
    auto body = json::parse(req.body, nullptr, /*allow_exceptions=*/false);
    if (body.is_discarded()) {
        fail(res, 400, "request body is not valid JSON");
        return std::nullopt;
    }
    if (!body.is_object()) {
        fail(res, 400, "request body must be a JSON object");
        return std::nullopt;
    }
    return body;
}

std::string caller_name(const RouteDeps& d, const httplib::Request& req) {
    if (d.resolve_session_fn)
        if (auto s = d.resolve_session_fn(req))
            return s->username;
    return {};
}

/// An id for an audit `target_id` column: bounded, and folded through `log_token` when it holds a
/// control byte, invalid UTF-8 or a code point `log_token` folds (a path id is attacker-chosen
/// kilobytes; the same hygiene the instruction-execute route applies).
std::string audit_target(const std::string& id) {
    std::string t = bounded_definition_id(id);
    if (definition_id_needs_audit_fold(id))
        t = ::yuzu::log_token(t);
    return t;
}

/// A caller-supplied label embedded in a `key=value` detail: bounded, then neutralised.
std::string audit_label(std::string_view s) {
    return ::yuzu::log_token(bounded_definition_id(s));
}

/// Audit writer bound to one request. `attempt` is the fail-closed audit-first row; `outcome`
/// closes it and flags a lost row on the response (the mutation already ran).
class Auditor {
public:
    Auditor(const RouteDeps& d, const httplib::Request& req, httplib::Response& res,
            const char* action, const char* target_type)
        : d_(d), req_(req), res_(res), action_(action), target_type_(target_type) {}

    /// False = the row was not stored: the caller answers `refuse_unaudited` and does NOT mutate.
    /// A sink that THROWS is the same as one that returns false (try_persist_audit catches it),
    /// so it refuses the write rather than escaping as a bare 500 with the mutation undecided.
    [[nodiscard]] bool attempt(const std::string& target_id, const std::string& detail) const {
        return detail::try_persist_audit(d_.audit_fn, req_, action_, "attempted", target_type_,
                                         target_id, detail);
    }
    /// A lost outcome row (returned false or threw) never undoes the completed write: it flags
    /// `Sec-Audit-Failed` on the answer, exactly as the v1 sibling routes do.
    void outcome(const char* result, const std::string& target_id, const std::string& detail) const {
        if (!detail::try_persist_audit(d_.audit_fn, req_, action_, result, target_type_, target_id,
                                       detail))
            res_.set_header("Sec-Audit-Failed", "true");
    }
    void refuse_unaudited(const char* noun_phrase) const {
        res_.set_header("Sec-Audit-Failed", "true");
        fail(res_, 503,
             std::string("the audit record could not be persisted, so ") + noun_phrase +
                 "; retry once the audit store recovers",
             /*retry=*/true);
    }

private:
    const RouteDeps& d_;
    const httplib::Request& req_;
    httplib::Response& res_;
    const char* action_;
    const char* target_type_;
};

void emit(const RouteDeps& d, const httplib::Request& req, std::string_view event, json attrs,
          json payload) {
    // emit_event_guarded: the binder already swallows a throw; the guard keeps a hook that is
    // not the binder's (and any future change to it) from ever failing an answered request.
    emit_event_guarded(bind_event_emit(d.emit_event_fn, req, d.metrics), event, attrs, payload);
}

enum class Shape { kPlain, kYaml };

/// The shared create sequence: attempted row, store create, outcome row, event, answer. `def` is
/// final; the attempted row records its name, plugin, action and approval_mode.
void run_create(const RouteDeps& d, const httplib::Request& req, httplib::Response& res,
                InstructionDefinition def, Shape shape) {
    const Auditor audit(d, req, res, "instruction.create", "InstructionDefinition");
    const std::string label = audit_label(def.name);
    if (!audit.attempt(audit_target(def.id),
                       "name=" + label + " plugin=" + audit_label(def.plugin) +
                           " action=" + audit_label(def.action) +
                           " approval_mode=" + audit_label(def.approval_mode))) {
        audit.refuse_unaudited("the definition was NOT created");
        return;
    }
    auto result = d.store->create_definition(def);
    if (!result) {
        switch (classify_store_error(result.error())) {
        case StoreFault::kDb:
            audit.outcome("error", audit_target(def.id), "db_error");
            fail_write_unknown(res, "definition");
            return;
        case StoreFault::kConflict:
            audit.outcome("denied", audit_target(def.id), "duplicate_id");
            fail(res, 409, std::string(strip_conflict_prefix(result.error())));
            return;
        default:
            audit.outcome("denied", audit_target(def.id), "invalid");
            fail(res, 400, result.error());
            return;
        }
    }
    audit.outcome("success", audit_target(*result), label);
    emit(d, req, "instruction.created",
         {{"name", def.name}, {"plugin", def.plugin}, {"action", def.action}, {"type", def.type}},
         {{"instruction_id", *result}});
    json data{{"id", *result}};
    if (shape == Shape::kYaml)
        data["created"] = true;
    send_ok(res, 201, std::move(data));
}

/// The shared update sequence. `before` is the stored row, `def` the row to write (its
/// `parameter_schema` already blank), `expected` the optimistic-concurrency version.
void run_update(const RouteDeps& d, const httplib::Request& req, httplib::Response& res,
                const std::string& id, const InstructionDefinition& before,
                const InstructionDefinition& def, std::optional<std::int64_t> expected,
                Shape shape) {
    const Auditor audit(d, req, res, "instruction.update", "InstructionDefinition");
    const std::string change = describe_dispatch_binding_change(before, def);
    const std::string target = audit_target(id);
    if (!audit.attempt(target, change)) {
        audit.refuse_unaudited("the definition was NOT updated");
        return;
    }
    auto result = d.store->update_definition(def, expected);
    if (!result) {
        switch (classify_store_error(result.error())) {
        case StoreFault::kDb:
            audit.outcome("error", target, "db_error");
            fail_write_unknown(res, "definition");
            return;
        case StoreFault::kNotFound:
            audit.outcome("denied", target, "not_found");
            fail(res, 404, "instruction definition not found");
            return;
        case StoreFault::kConflict:
            audit.outcome("denied", target, "conflict");
            fail(res, 409, std::string(strip_conflict_prefix(result.error())));
            return;
        default:
            audit.outcome("denied", target, "invalid");
            fail(res, 400, result.error());
            return;
        }
    }
    audit.outcome("success", target, change);
    emit(d, req, "instruction.updated", json(), {{"instruction_id", id}});
    json data{{"id", id}};
    if (shape == Shape::kYaml)
        data["created"] = false;
    else
        data["updated"] = true;
    send_ok(res, 200, std::move(data));
}

} // namespace

void register_instruction_authoring_routes(HttpRouteSink& sink, RouteDeps deps) {
    // -- Literal segments first: `import`, `yaml` and `validate-yaml` must never be read as an id.

    // POST /api/v1/instructions/import
    sink.Post("/api/v1/instructions/import", [deps](const httplib::Request& req,
                                                     httplib::Response& res) {
        if (!deps.perm_fn || !deps.perm_fn(req, res, "InstructionDefinition", "Write"))
            return (void)refuse_gate(deps, res);
        if (!admit_dependencies(deps, res, /*writes=*/true))
            return;
        // The store parses the envelope itself (it owns the signature gate); parse here for the
        // depth and shape refusals, so a malformed body costs no audit row and no store call, and
        // to stamp the creator.
        auto document = parse_object_body(req, res);
        if (!document)
            return;
        // created_by is the authenticated caller, never what the document claims (the signature
        // covers yaml_source only, so the field is unsigned and a document could name anyone).
        (*document)["created_by"] = caller_name(deps, req);
        const Auditor audit(deps, req, res, "instruction.import", "InstructionDefinition");
        // The attempted row names the document (its own id when it states one) and the request
        // body size (`body_bytes`; MCP's `document_bytes` is the document alone), so it is useful
        // when the outcome row is lost.
        const auto doc_id = document->find("id");
        const std::string attempt_target =
            doc_id != document->end() && doc_id->is_string()
                ? audit_target(doc_id->get<std::string>())
                : "";
        if (!audit.attempt(attempt_target, "body_bytes=" + std::to_string(req.body.size()))) {
            audit.refuse_unaudited("the definition was NOT imported");
            return;
        }
        // import_definition_json, NEVER the _trusted variant: this is the signature-gated surface
        // (unsigned imports are refused unless --allow-unsigned-definitions).
        auto result = deps.store->import_definition_json(dump_safe(*document));
        if (!result) {
            switch (classify_store_error(result.error())) {
            case StoreFault::kDb:
                audit.outcome("error", "", "db_error");
                fail_write_unknown(res, "definition");
                return;
            case StoreFault::kConflict:
                audit.outcome("denied", "", "duplicate_id");
                fail(res, 409, std::string(strip_conflict_prefix(result.error())));
                return;
            default:
                // Every other rejection (the signature gate's included) is an access decision:
                // the detail is the store's stable error text, which SIEM rules key on.
                audit.outcome("denied", "", audit_store_error_text(result.error()));
                fail(res, 400, result.error());
                return;
            }
        }
        audit.outcome("success", audit_target(*result), "");
        send_ok(res, 201, json{{"id", *result}});
    });

    // POST /api/v1/instructions/yaml
    sink.Post("/api/v1/instructions/yaml", [deps](const httplib::Request& req,
                                                   httplib::Response& res) {
        if (!deps.perm_fn || !deps.perm_fn(req, res, "InstructionDefinition", "Write"))
            return (void)refuse_gate(deps, res);
        if (!admit_dependencies(deps, res, /*writes=*/true))
            return;
        auto body = parse_object_body(req, res);
        if (!body)
            return;
        auto save = parse_yaml_save_body(*body);
        if (!save)
            return fail(res, 400, save.error());
        const std::string& yaml_source = save->yaml_source;
        const std::string& def_id = save->id;
        std::optional<std::int64_t> expected_updated_at = save->expected_updated_at;

        // One contract with validate-yaml (#1993): YAML that validates always carries what Save needs.
        if (const auto errors = validate_yaml_for_authoring(yaml_source); !errors.empty())
            return fail_with_errors(res, "yaml_source failed validation; nothing was saved", errors);

        const auto fields = instruction_yaml::parse_definition_yaml(yaml_source);

        const std::string username = caller_name(deps, req);

        if (def_id.empty()) {
            // Create: a fresh definition from the YAML's own fields plus the create defaults.
            InstructionDefinition def = definition_from_yaml_fields(fields, yaml_source, username);
            run_create(deps, req, res, std::move(def), Shape::kYaml);
            return;
        }

        // Update. The path-free id is authoritative, so a YAML that names a DIFFERENT metadata.id
        // would be stored verbatim and fork the definition on a later re-import: refuse it.
        if (def_id.size() > kMaxDefinitionIdLen || definition_id_is_malformed(def_id))
            return fail(res, 400, "id is not a valid definition id");
        if (auto err = check_yaml_update_id(fields, def_id))
            return fail(res, 400, *err);
        auto stored = deps.store->get_definition(def_id);
        if (!stored)
            return fail(res, 503, "instruction store unavailable", /*retry=*/true);
        if (!*stored)
            return fail(res, 404, "instruction definition not found");
        // Carry forward every column the YAML cannot express (set, enabled, TTLs, schemas,
        // templates, ...). A caller that sends no updated_at is checked against the version read here.
        InstructionDefinition def =
            instruction_extras::merge_yaml_into_stored(**stored, fields, yaml_source, username);
        def.id = def_id;
        if (!expected_updated_at)
            expected_updated_at = (*stored)->updated_at;
        run_update(deps, req, res, def_id, **stored, def, expected_updated_at, Shape::kYaml);
    });

    // POST /api/v1/instructions/validate-yaml
    sink.Post("/api/v1/instructions/validate-yaml", [deps](const httplib::Request& req,
                                                            httplib::Response& res) {
        if (!deps.perm_fn || !deps.perm_fn(req, res, "InstructionDefinition", "Read"))
            return (void)refuse_gate(deps, res);
        if (!admit_dependencies(deps, res, /*writes=*/false, /*needs_store=*/false))
            return;
        auto body = parse_object_body(req, res);
        if (!body)
            return;
        auto yaml_source = parse_yaml_validate_body(*body);
        if (!yaml_source)
            return fail(res, 400, yaml_source.error());
        const auto errors = validate_yaml_for_authoring(*yaml_source);
        send_ok(res, 200, json{{"valid", errors.empty()}, {"errors", errors}});
    });

    // POST /api/v1/instructions
    sink.Post("/api/v1/instructions", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn || !deps.perm_fn(req, res, "InstructionDefinition", "Write"))
            return (void)refuse_gate(deps, res);
        if (!admit_dependencies(deps, res, /*writes=*/true))
            return;
        auto body = parse_object_body(req, res);
        if (!body)
            return;
        auto def = build_definition_from_create_body(*body, caller_name(deps, req));
        if (!def)
            return fail(res, 400, def.error());
        run_create(deps, req, res, std::move(*def), Shape::kPlain);
    });

    // PUT /api/v1/instructions/{id}
    sink.Put(R"(/api/v1/instructions/([^/]+))", [deps](const httplib::Request& req,
                                                         httplib::Response& res) {
        if (!deps.perm_fn || !deps.perm_fn(req, res, "InstructionDefinition", "Write"))
            return (void)refuse_gate(deps, res);
        if (!admit_dependencies(deps, res, /*writes=*/true))
            return;
        const std::string id = req.matches[1].str();
        if (definition_id_is_malformed(id))
            return fail(res, 400, "id is not a valid definition id");
        auto body = parse_object_body(req, res);
        if (!body)
            return;
        auto stored = deps.store->get_definition(id);
        if (!stored)
            return fail(res, 503, "instruction store unavailable", /*retry=*/true);
        if (!*stored)
            return fail(res, 404, "instruction definition not found");
        InstructionDefinition def = **stored;
        auto upd = apply_definition_update_body(*body, def);
        if (!upd)
            return fail(res, 400, upd.error());
        // An empty parameter_schema means "keep the stored column"; writing the loaded copy back
        // would revert a schema replaced since the load.
        def.parameter_schema.clear();
        // UP-5: a changed column the YAML merge takes (clear_stale_yaml_source) makes a stored YAML
        // stale; clear it (audited).
        (void)clear_stale_yaml_source(**stored, def);
        run_update(deps, req, res, id, **stored, def,
                   upd->expected_updated_at ? upd->expected_updated_at
                                            : std::optional<std::int64_t>((*stored)->updated_at),
                   Shape::kPlain);
    });

    // DELETE /api/v1/instructions/{id}
    sink.Delete(R"(/api/v1/instructions/([^/]+))", [deps](const httplib::Request& req,
                                                            httplib::Response& res) {
        if (!deps.perm_fn || !deps.perm_fn(req, res, "InstructionDefinition", "Delete"))
            return (void)refuse_gate(deps, res);
        if (!admit_dependencies(deps, res, /*writes=*/true))
            return;
        const std::string id = req.matches[1].str();
        if (definition_id_is_malformed(id))
            return fail(res, 400, "id is not a valid definition id");
        // Optional `?expected_updated_at=<n>`: delete only that version of the row (a moved-on one
        // is 409 and survives). Absent = unconditional.
        std::optional<std::int64_t> expected_updated_at;
        if (req.has_param("expected_updated_at")) {
            const std::string raw = req.get_param_value("expected_updated_at");
            std::int64_t n = 0;
            const char* end = raw.data() + raw.size();
            const auto [ptr, ec] = std::from_chars(raw.data(), end, n);
            if (req.get_param_value_count("expected_updated_at") != 1 || raw.empty() ||
                raw.front() == '+' || raw.front() == '-' || ec != std::errc{} || ptr != end)
                return fail(res, 400, "expected_updated_at must be a non-negative integer");
            expected_updated_at = n;
        }
        // The pre-image, read BEFORE the audit-first attempt row: once the row is gone nothing
        // else records what it ran. A definition that is already gone is left to the delete
        // below, which answers 404 with its denied row; an unreadable one is a 503.
        const Auditor audit(deps, req, res, "instruction.delete", "InstructionDefinition");
        const std::string target = audit_target(id);
        auto stored = deps.store->get_definition(id);
        if (!stored) {
            // The read failed before anything was decided: one `error` row (the same vocabulary
            // the other v1 refusals write), no attempted/outcome pair, nothing mutated.
            audit.outcome("error", target, "db_error");
            return fail(res, 503, "instruction store unavailable", /*retry=*/true);
        }
        const std::string preimage = *stored ? describe_deleted_definition(**stored) : "";
        // UP-6: a definition other things name by id is not deleted out from under them. After the
        // existence read (a missing one is the delete's 404) and BEFORE the attempted row: a
        // refusal mutates nothing, so it writes one `denied` row, not an attempt/outcome pair. An
        // unwired lookup is a 503 with no retry hint and a failing one a retryable 503; neither is
        // read as "no referrers".
        if (*stored) {
            if (!deps.referrers_fn) {
                audit.outcome("error", target, "referrer_check_unwired");
                return fail(res, 503, "definition reference check not configured; nothing was deleted");
            }
            auto referrers = deps.referrers_fn(id);
            if (!referrers) {
                audit.outcome("error", target, "referrer_check_unavailable");
                return fail(res, 503, "definition reference check unavailable; nothing was deleted",
                            /*retry=*/true);
            }
            if (!referrers->empty()) {
                audit.outcome("denied", target, "referenced");
                return fail(res, 409, describe_definition_referrers(*referrers));
            }
        }
        // The packs that contain the definition are noted on the outcome row, never a reason to
        // refuse; the lookup runs HERE, before the delete, so no read sits between the delete and
        // its outcome row (a lost-row window), and a failed or slow read changes nothing.
        const std::string packs = *stored ? pack_advisory_note(deps.pack_advisory_fn, id) : "";
        if (!audit.attempt(target, preimage)) {
            audit.refuse_unaudited("the definition was NOT deleted");
            return;
        }
        // A delete of a bundled seed leaves a tombstone, so the seed does not reappear on boot.
        auto result = deps.store->delete_definition(id, expected_updated_at);
        if (!result) {
            if (classify_store_error(result.error()) == StoreFault::kDb) {
                audit.outcome("error", target, "db_error");
                fail_write_unknown(res, "definition");
                return;
            }
            if (classify_store_error(result.error()) == StoreFault::kConflict) {
                audit.outcome("denied", target, "conflict");
                fail(res, 409,
                     std::string(strip_conflict_prefix(result.error())) +
                         "; read it again and retry with its new updated_at");
                return;
            }
            audit.outcome("denied", target, "not_found");
            fail(res, 404, "instruction definition not found");
            return;
        }
        std::string detail = preimage;
        if (!packs.empty())
            detail += (detail.empty() ? "" : " ") + packs;
        audit.outcome("success", target, detail);
        emit(deps, req, "instruction.deleted", json(), {{"instruction_id", id}});
        send_ok(res, 200, json{{"id", id}, {"deleted", true}});
    });

    // GET /api/v1/instruction-sets
    sink.Get("/api/v1/instruction-sets", [deps](const httplib::Request& req,
                                                 httplib::Response& res) {
        if (!deps.perm_fn || !deps.perm_fn(req, res, "InstructionSet", "Read"))
            return (void)refuse_gate(deps, res);
        if (!admit_dependencies(deps, res, /*writes=*/false))
            return;
        auto sets = deps.store->list_sets();
        if (!sets)
            return fail(res, 503, "instruction store read failed", /*retry=*/true);
        json arr = json::array();
        for (const auto& s : *sets)
            arr.push_back({{"id", s.id},
                           {"name", s.name},
                           {"description", s.description},
                           {"created_by", s.created_by},
                           {"created_at", s.created_at}});
        // The list is not paged: page_size is its own length.
        const auto total = static_cast<std::int64_t>(sets->size());
        res.status = 200;
        res.set_content(
            dump_safe(json{{"data", std::move(arr)},
                           {"pagination", {{"total", total}, {"start", 0}, {"page_size", total}}},
                           {"meta", {{"api_version", "v1"}}}}),
            "application/json");
    });

    // POST /api/v1/instruction-sets
    sink.Post("/api/v1/instruction-sets", [deps](const httplib::Request& req,
                                                  httplib::Response& res) {
        if (!deps.perm_fn || !deps.perm_fn(req, res, "InstructionSet", "Write"))
            return (void)refuse_gate(deps, res);
        if (!admit_dependencies(deps, res, /*writes=*/true))
            return;
        auto body = parse_object_body(req, res);
        if (!body)
            return;
        auto set = build_instruction_set_from_body(*body, caller_name(deps, req));
        if (!set)
            return fail(res, 400, set.error());
        const Auditor audit(deps, req, res, "instruction_set.create", "InstructionSet");
        const std::string label = audit_label(set->name);
        if (!audit.attempt("", label)) {
            audit.refuse_unaudited("the set was NOT created");
            return;
        }
        // create_set, NEVER create_set_seed (the boot-time seed path).
        auto result = deps.store->create_set(*set);
        if (!result) {
            switch (classify_store_error(result.error())) {
            case StoreFault::kDb:
                audit.outcome("error", "", "db_error");
                fail_write_unknown(res, "set");
                return;
            case StoreFault::kConflict:
                audit.outcome("denied", "", "conflict");
                fail(res, 409, std::string(strip_conflict_prefix(result.error())));
                return;
            default:
                audit.outcome("denied", "", "invalid");
                fail(res, 400, result.error());
                return;
            }
        }
        audit.outcome("success", audit_target(*result), label);
        send_ok(res, 201, json{{"id", *result}});
    });

    // DELETE /api/v1/instruction-sets/{id}
    sink.Delete(R"(/api/v1/instruction-sets/([^/]+))", [deps](const httplib::Request& req,
                                                                httplib::Response& res) {
        if (!deps.perm_fn || !deps.perm_fn(req, res, "InstructionSet", "Delete"))
            return (void)refuse_gate(deps, res);
        if (!admit_dependencies(deps, res, /*writes=*/true))
            return;
        const std::string id = req.matches[1].str();
        if (definition_id_is_malformed(id))
            return fail(res, 400, "id is not a valid instruction set id");
        const Auditor audit(deps, req, res, "instruction_set.delete", "InstructionSet");
        const std::string target = audit_target(id);
        if (!audit.attempt(target, "")) {
            audit.refuse_unaudited("the set was NOT deleted");
            return;
        }
        // Members are unset (instruction_set_id cleared), never deleted; a bundled seed set
        // leaves a tombstone so it does not reappear on boot.
        auto result = deps.store->delete_set(id);
        if (!result) {
            if (classify_store_error(result.error()) == StoreFault::kDb) {
                audit.outcome("error", target, "db_error");
                fail_write_unknown(res, "set");
                return;
            }
            audit.outcome("denied", target, "not_found");
            fail(res, 404, "instruction set not found");
            return;
        }
        audit.outcome("success", target, "");
        send_ok(res, 200, json{{"id", id}, {"deleted", true}});
    });
}

} // namespace yuzu::server::instruction_authoring
