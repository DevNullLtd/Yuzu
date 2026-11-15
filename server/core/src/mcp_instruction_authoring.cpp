#include "mcp_instruction_authoring.hpp"

#include "instruction_definition_model.hpp"
#include "instruction_execute.hpp" // bounded_definition_id / definition_id_* (audit target hygiene)
#include "instruction_extras_render.hpp"
#include "instruction_yaml.hpp"
#include "mcp_jsonrpc.hpp" // kInvalidParams / kInternalError
#include "mcp_retry.hpp"   // kMcpStoreFaultRetryMs
#include "sha256_hex.hpp"
#include "store_errors.hpp"

#include <yuzu/log_token.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <expected>
#include <limits>
#include <unordered_set>
#include <utility>
#include <vector>

namespace yuzu::server::mcp::instruction_authoring {

namespace {

using nlohmann::json;
using instruction_execute::bounded_definition_id;
using instruction_execute::definition_id_is_malformed;
using instruction_execute::definition_id_needs_audit_fold;

Result fail(Kind kind, std::string message) {
    Result r;
    r.kind = kind;
    r.message = std::move(message);
    return r;
}

Result ok(json payload, bool audit_persisted = true) {
    Result r;
    r.payload = std::move(payload);
    r.audit_persisted = audit_persisted;
    return r;
}

Result store_unavailable() {
    return fail(Kind::kStoreUnavailable, "instruction store unavailable");
}

/// A store fault on a WRITE after its attempted audit row. A connection lost after COMMIT is
/// indistinguishable from one lost before it, so the write may have landed: the message says so
/// and tells the caller to read before retrying (the kind maps to the same internal error but
/// WITHOUT `retry_after_ms`: no idempotency key exists to make a blind retry safe).
Result store_write_outcome_unknown(std::string_view noun) {
    Result r = fail(Kind::kStoreUnavailable,
                    "instruction store unavailable; outcome unknown: read the " +
                        std::string(noun) + " before retrying");
    r.outcome_unknown = true;
    return r;
}

bool store_ready(const Ports& p) {
    return p.store != nullptr && p.store->is_open();
}

/// The arguments minus the control-plane `approval_id` (the C8 recall argument, never tool input)
/// and, for an update, minus the `id` that names the row. The shared builders refuse an unknown
/// key, so an unstripped `approval_id` on a ticket recall would be refused as one.
json strip(const json& args, bool drop_id) {
    json out = json::object();
    if (!args.is_object())
        return out;
    for (const auto& [k, v] : args.items()) {
        if (k == "approval_id" || (drop_id && k == "id"))
            continue;
        out[k] = v;
    }
    return out;
}

/// A required string argument naming a definition / set: present, a string, 1..kIdMaxLen bytes
/// and not malformed (a control byte or invalid UTF-8). Returns the refusal text or nullopt.
std::optional<std::string> check_id_arg(const json& args, std::string_view what, std::string& id) {
    if (!args.is_object() || !args.contains("id") || !args["id"].is_string())
        return std::string(what) + " is required and must be a string";
    id = args["id"].get<std::string>();
    if (id.empty() || id.size() > kIdMaxLen)
        return std::string(what) + " must be 1 to " + std::to_string(kIdMaxLen) + " bytes";
    if (definition_id_is_malformed(id))
        return std::string(what) + " is not a valid id";
    return std::nullopt;
}

/// The optional version token `key` of a call: nullopt value = absent; an error text when it is
/// present but not an integer in [0, INT64_MAX] (the handlers refuse that as kInvalid).
std::expected<std::optional<std::int64_t>, std::string> read_version_token(const json& args,
                                                                          const char* key) {
    if (!args.is_object())
        return std::optional<std::int64_t>{};
    const auto it = args.find(key);
    if (it == args.end())
        return std::optional<std::int64_t>{};
    if (!it->is_number_integer() || (it->is_number_unsigned() && it->get<std::uint64_t>() >
                                                                     static_cast<std::uint64_t>(
                                                                         std::numeric_limits<
                                                                             std::int64_t>::max())))
        return std::unexpected(std::string(key) + " must be a non-negative integer");
    const auto n = it->get<std::int64_t>();
    if (n < 0)
        return std::unexpected(std::string(key) + " must be a non-negative integer");
    return std::optional<std::int64_t>{n};
}

/// The conflict text of a delete whose version token no longer matches (no store prefix).
std::string stale_delete_message(std::string_view store_text) {
    return std::string(store_text) +
           "; read it again with get_definition and retry with its new updated_at";
}

/// An id for an audit `target_id` column: bounded, and folded through `log_token` when it holds a
/// control byte, invalid UTF-8 or a code point `log_token` folds (the same hygiene the v1 route
/// applies).
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

/// Domain audit writer: the row, or "not stored" when the sink is unwired.
bool write_row(const Ports& p, std::string_view action, std::string_view result,
               std::string_view target_type, const std::string& target_id,
               const std::string& detail) {
    return p.audit && p.audit(action, result, target_type, target_id, detail);
}

/// One audited write: the `attempted` row first (refuse and mutate nothing when it is not stored),
/// then the outcome row. `Audit` is bound to one action and target type.
class Audit {
public:
    Audit(const Ports& p, std::string_view action, std::string_view target_type)
        : p_(p), action_(action), target_type_(target_type) {}

    [[nodiscard]] bool attempt(const std::string& target_id, const std::string& detail) const {
        return write_row(p_, action_, "attempted", target_type_, target_id, detail);
    }
    /// False = the outcome row was lost (the caller flags `audit_persisted:false`).
    bool outcome(std::string_view result, const std::string& target_id,
                 const std::string& detail) const {
        // Only the row that records the change carries the ticket: the attempted row and a
        // refusal row keep their detail exactly (a SIEM rule keys on its token), and the consume
        // itself is recorded by the generic `mcp.<tool>` `approved` row.
        return write_row(p_, action_, result, target_type_, target_id,
                         result == "success" ? with_ticket(detail) : detail);
    }
    /// An error path's outcome row: records whether it persisted into the Result, so `render()`
    /// reports `audit_persisted:false` on an error exactly as REST sets `Sec-Audit-Failed`.
    [[nodiscard]] Result settle(std::string_view result, const std::string& target_id,
                                const std::string& detail, Result r) const {
        r.audit_persisted = outcome(result, target_id, detail);
        return r;
    }
    [[nodiscard]] Result refused(const char* noun_phrase) const {
        if (!p_.audit) {
            // An unwired sink is a configuration fault: waiting does not fix it, so no retry
            // hint (REST answers the same). A wired sink that failed to store the row keeps it.
            Result r = fail(Kind::kAuditRefused,
                            std::string("the audit sink is not configured, so ") + noun_phrase);
            r.not_retryable = true;
            return r;
        }
        return fail(Kind::kAuditRefused,
                    std::string("the audit record could not be persisted, so ") + noun_phrase +
                        "; retry once the audit store recovers");
    }

private:
    /// The detail with the authorising approval appended, after any token a SIEM rule keys on at
    /// the front. The id is the server-minted one the consumed ticket carries, but it came in on
    /// the wire: bounded and folded like every caller-sized label.
    std::string with_ticket(const std::string& detail) const {
        if (p_.approval_id.empty())
            return detail;
        return (detail.empty() ? std::string() : detail + " ") +
               "approval_id=" + audit_label(p_.approval_id);
    }

    const Ports& p_;
    // Views, not copies: both are string literals at every construction site, so they outlive the
    // Audit. A caller-built string must never be passed here.
    std::string_view action_;
    std::string_view target_type_;
};

void emit(const Ports& p, std::string_view event, json attrs, json payload) {
    // emit_event_guarded: a hook that throws (a test hook, or any future change to the binder)
    // must never fail a call whose effect and outcome row are already done.
    emit_event_guarded(p.emit, event, attrs, payload);
}

enum class Shape { kPlain, kYaml };

/// The shared create sequence: attempted row, store create, outcome row, event, answer.
Result run_create(const Ports& p, InstructionDefinition def, Shape shape) {
    const Audit audit(p, "instruction.create", "InstructionDefinition");
    const std::string label = audit_label(def.name);
    if (!audit.attempt(audit_target(def.id),
                       "name=" + label + " plugin=" + audit_label(def.plugin) +
                           " action=" + audit_label(def.action) +
                           " approval_mode=" + audit_label(def.approval_mode)))
        return audit.refused("the definition was NOT created");
    auto result = p.store->create_definition(def);
    if (!result) {
        switch (classify_store_error(result.error())) {
        case StoreFault::kDb:
            return audit.settle("error", audit_target(def.id), "db_error",
                                store_write_outcome_unknown("definition"));
        case StoreFault::kConflict:
            return audit.settle("denied", audit_target(def.id), "duplicate_id",
                                fail(Kind::kConflict,
                                     std::string(strip_conflict_prefix(result.error()))));
        default:
            return audit.settle("denied", audit_target(def.id), "invalid",
                                fail(Kind::kInvalid, result.error()));
        }
    }
    const bool persisted = audit.outcome("success", audit_target(*result), label);
    emit(p, "instruction.created",
         {{"name", def.name}, {"plugin", def.plugin}, {"action", def.action}, {"type", def.type}},
         {{"instruction_id", *result}});
    json data{{"id", *result}};
    if (shape == Shape::kYaml)
        data["created"] = true;
    return ok(std::move(data), persisted);
}

/// The shared update sequence. `before` is the stored row, `def` the row to write (its
/// `parameter_schema` already blank), `expected` the optimistic-concurrency version.
Result run_update(const Ports& p, const std::string& id, const InstructionDefinition& before,
                  const InstructionDefinition& def, std::optional<std::int64_t> expected,
                  Shape shape) {
    const Audit audit(p, "instruction.update", "InstructionDefinition");
    const std::string change = describe_dispatch_binding_change(before, def);
    const std::string target = audit_target(id);
    if (!audit.attempt(target, change))
        return audit.refused("the definition was NOT updated");
    auto result = p.store->update_definition(def, expected);
    if (!result) {
        switch (classify_store_error(result.error())) {
        case StoreFault::kDb:
            return audit.settle("error", target, "db_error",
                                store_write_outcome_unknown("definition"));
        case StoreFault::kNotFound:
            return audit.settle("denied", target, "not_found",
                                fail(Kind::kNotFound, "instruction definition not found"));
        case StoreFault::kConflict:
            return audit.settle("denied", target, "conflict",
                                fail(Kind::kConflict,
                                     std::string(strip_conflict_prefix(result.error()))));
        default:
            return audit.settle("denied", target, "invalid", fail(Kind::kInvalid, result.error()));
        }
    }
    const bool persisted = audit.outcome("success", target, change);
    emit(p, "instruction.updated", json(), {{"instruction_id", id}});
    json data{{"id", id}};
    if (shape == Shape::kYaml)
        data["created"] = false;
    else
        data["updated"] = true;
    return ok(std::move(data), persisted);
}

} // namespace

Result create_definition(const json& args, const Ports& p) {
    if (!store_ready(p))
        return store_unavailable();
    auto def = build_definition_from_create_body(strip(args, /*drop_id=*/false), p.created_by);
    if (!def)
        return fail(Kind::kInvalid, def.error());
    return run_create(p, std::move(*def), Shape::kPlain);
}

Result update_definition(const json& args, const Ports& p) {
    if (!store_ready(p))
        return store_unavailable();
    std::string id;
    if (auto err = check_id_arg(args, "id", id))
        return fail(Kind::kInvalid, *err);
    auto stored = p.store->get_definition(id);
    if (!stored)
        return store_unavailable();
    if (!*stored)
        return fail(Kind::kNotFound, "instruction definition not found");
    InstructionDefinition def = **stored;
    auto upd = apply_definition_update_body(strip(args, /*drop_id=*/true), def);
    if (!upd)
        return fail(Kind::kInvalid, upd.error());
    // An empty parameter_schema means "keep the stored column"; writing the loaded copy back
    // would revert a schema replaced since the load.
    def.parameter_schema.clear();
    // UP-5: a changed column the YAML merge takes (clear_stale_yaml_source) makes a stored YAML
    // stale; clear it (audited).
    (void)clear_stale_yaml_source(**stored, def);
    return run_update(p, id, **stored, def,
                      upd->expected_updated_at ? upd->expected_updated_at
                                               : std::optional<std::int64_t>((*stored)->updated_at),
                      Shape::kPlain);
}

std::optional<Result> delete_referrer_refusal(const std::string& id,
                                              const DefinitionReferrersFn& referrers_fn,
                                              const InstructionStore* existence_store) {
    if (definition_id_is_malformed(id))
        return std::nullopt;
    // Only a row that exists can be referenced: an absent one falls through to the version check
    // (not_found), exactly as the handlers answer it. An unreadable store fails closed.
    if (existence_store != nullptr) {
        if (!existence_store->is_open())
            return store_unavailable();
        const auto stored = existence_store->get_definition(id);
        if (!stored)
            return store_unavailable();
        if (!*stored)
            return std::nullopt;
    }
    if (!referrers_fn) {
        Result r = store_unavailable();
        r.message = "definition reference check not configured; nothing was deleted";
        r.not_retryable = true; // a deployment fault, not a transient one (REST: 503 without a hint)
        return r;
    }
    const auto referrers = referrers_fn(id);
    if (!referrers) {
        Result r = store_unavailable();
        r.message = "definition reference check unavailable; nothing was deleted";
        return r;
    }
    if (referrers->empty())
        return std::nullopt;
    return fail(Kind::kReferenced, describe_definition_referrers(*referrers));
}

Result delete_definition(const json& args, const Ports& p) {
    if (!store_ready(p))
        return store_unavailable();
    std::string id;
    if (auto err = check_id_arg(args, "id", id))
        return fail(Kind::kInvalid, *err);
    // Optional version token: set = delete only that version of the row (a stale one is a
    // conflict and the row survives); the supervised tier requires it before a ticket is minted.
    const auto expected = read_version_token(args, "expected_updated_at");
    if (!expected)
        return fail(Kind::kInvalid, expected.error());
    // The pre-image, read BEFORE the audit-first attempt row (see the v1 route). A definition
    // already gone is left to the delete below (404 with its denied row); an unreadable one is
    // a retryable store fault.
    const Audit audit(p, "instruction.delete", "InstructionDefinition");
    const std::string target = audit_target(id);
    auto stored = p.store->get_definition(id);
    if (!stored)
        return audit.settle("error", target, "db_error", store_unavailable());
    const std::string preimage = *stored ? describe_deleted_definition(**stored) : "";
    // UP-6: after the existence read, before the attempted row (see the v1 route). A refusal
    // mutates nothing, so it writes one row: `denied` for a referenced definition, `error` when
    // the lookup was unwired or failed (the vocabulary the v1 DELETE writes).
    if (*stored) {
        if (auto refusal = delete_referrer_refusal(id, p.referrers_fn)) {
            if (refusal->kind == Kind::kReferenced)
                refusal->audit_persisted = audit.outcome("denied", target, "referenced");
            else
                refusal->audit_persisted = audit.outcome(
                    "error", target,
                    p.referrers_fn ? "referrer_check_unavailable" : "referrer_check_unwired");
            return std::move(*refusal);
        }
    }
    // Advisory only (see the v1 route): read before the delete, appended to the success row.
    const std::string packs = *stored ? pack_advisory_note(p.pack_advisory_fn, id) : "";
    if (!audit.attempt(target, preimage))
        return audit.refused("the definition was NOT deleted");
    // A delete of a bundled seed leaves a tombstone, so the seed does not reappear on boot.
    auto result = p.store->delete_definition(id, *expected);
    if (!result) {
        if (classify_store_error(result.error()) == StoreFault::kDb) {
            return audit.settle("error", target, "db_error",
                                store_write_outcome_unknown("definition"));
        }
        if (classify_store_error(result.error()) == StoreFault::kConflict) {
            return audit.settle(
                "denied", target, "conflict",
                fail(Kind::kConflict,
                     stale_delete_message(strip_conflict_prefix(result.error()))));
        }
        return audit.settle("denied", target, "not_found",
                            fail(Kind::kNotFound, "instruction definition not found"));
    }
    std::string detail = preimage;
    if (!packs.empty())
        detail += (detail.empty() ? "" : " ") + packs;
    const bool persisted = audit.outcome("success", target, detail);
    emit(p, "instruction.deleted", json(), {{"instruction_id", id}});
    return ok(json{{"id", id}, {"deleted", true}}, persisted);
}

Result import_definition(const json& args, const Ports& p) {
    if (!store_ready(p))
        return store_unavailable();
    // `document` is the export document (+ signature, publicKey, yaml_source), one JSON object.
    if (!args.is_object() || !args.contains("document") || !args["document"].is_object())
        return fail(Kind::kInvalid, "document is required and must be a JSON object");
    for (const auto& [k, v] : args.items())
        if (k != "document" && k != "approval_id")
            return fail(Kind::kInvalid,
                        "unknown field in arguments; allowed fields: document, approval_id");
    // The store parses the envelope itself (it owns the signature gate); the document is the
    // already-parsed object, serialised back for it. `replace` keeps a stray byte from throwing.
    // created_by is the authenticated caller, never what the document claims (the signature
    // covers yaml_source only). A COPY is stamped, so the ticket digest of the document as sent
    // (`ticket_subject`) is untouched.
    json document = args["document"];
    document["created_by"] = p.created_by;
    const std::string envelope = document.dump(-1, ' ', false, json::error_handler_t::replace);
    const Audit audit(p, "instruction.import", "InstructionDefinition");
    // The attempted row names the document (its own id when it states one) and its size, so the
    // row is useful when the outcome row is lost. `document_bytes` is of the document as sent, the
    // same figure the approval ticket's `document_bytes` carries (REST's `body_bytes` counts the
    // whole request body, a different unit, hence the different key).
    const auto& sent = args["document"];
    const auto doc_id = sent.find("id");
    const std::string attempt_target =
        doc_id != sent.end() && doc_id->is_string() ? audit_target(doc_id->get<std::string>()) : "";
    const std::string attempt_detail =
        "document_bytes=" + std::to_string(sent.dump(-1, ' ', false, json::error_handler_t::replace).size());
    if (!audit.attempt(attempt_target, attempt_detail))
        return audit.refused("the definition was NOT imported");
    // import_definition_json, NEVER the _trusted variant: this is the signature-gated surface
    // (unsigned imports are refused unless --allow-unsigned-definitions).
    auto result = p.store->import_definition_json(envelope);
    if (!result) {
        switch (classify_store_error(result.error())) {
        case StoreFault::kDb:
            return audit.settle("error", "", "db_error", store_write_outcome_unknown("definition"));
        case StoreFault::kConflict:
            return audit.settle("denied", "", "duplicate_id",
                                fail(Kind::kConflict,
                                     std::string(strip_conflict_prefix(result.error()))));
        default:
            // Every other rejection (the signature gate's included) is an access decision: the
            // detail is the store's stable error text, which SIEM rules key on.
            return audit.settle("denied", "", audit_store_error_text(result.error()),
                                fail(Kind::kInvalid, result.error()));
        }
    }
    const bool persisted = audit.outcome("success", audit_target(*result), "");
    return ok(json{{"id", *result}}, persisted);
}

Result save_definition_yaml(const json& args, const Ports& p) {
    if (!store_ready(p))
        return store_unavailable();
    auto save = parse_yaml_save_body(strip(args, /*drop_id=*/false));
    if (!save)
        return fail(Kind::kInvalid, save.error());
    const std::string& yaml_source = save->yaml_source;
    const std::string& def_id = save->id;
    std::optional<std::int64_t> expected_updated_at = save->expected_updated_at;

    // One contract with validate_definition_yaml (#1993): YAML that validates always carries what
    // Save needs.
    if (const auto errors = validate_yaml_for_authoring(yaml_source); !errors.empty()) {
        Result r = fail(Kind::kInvalid, "yaml_source failed validation; nothing was saved");
        r.errors = errors;
        return r;
    }
    const auto fields = instruction_yaml::parse_definition_yaml(yaml_source);

    if (def_id.empty())
        return run_create(p, definition_from_yaml_fields(fields, yaml_source, p.created_by),
                          Shape::kYaml);

    // Update. The id argument is authoritative, so a YAML that names a DIFFERENT metadata.id
    // would be stored verbatim and fork the definition on a later re-import: refuse it.
    if (def_id.size() > kIdMaxLen || definition_id_is_malformed(def_id))
        return fail(Kind::kInvalid, "id is not a valid definition id");
    if (auto err = check_yaml_update_id(fields, def_id))
        return fail(Kind::kInvalid, *err);
    auto stored = p.store->get_definition(def_id);
    if (!stored)
        return store_unavailable();
    if (!*stored)
        return fail(Kind::kNotFound, "instruction definition not found");
    // Carry forward every column the YAML cannot express (set, enabled, TTLs, schemas,
    // templates, ...). A caller that sends no updated_at is checked against the version read here.
    InstructionDefinition def =
        instruction_extras::merge_yaml_into_stored(**stored, fields, yaml_source, p.created_by);
    def.id = def_id;
    if (!expected_updated_at)
        expected_updated_at = (*stored)->updated_at;
    return run_update(p, def_id, **stored, def, expected_updated_at, Shape::kYaml);
}

Result validate_definition_yaml(const json& args) {
    auto yaml_source = parse_yaml_validate_body(strip(args, /*drop_id=*/false));
    if (!yaml_source)
        return fail(Kind::kInvalid, yaml_source.error());
    const auto errors = validate_yaml_for_authoring(*yaml_source);
    return ok(json{{"valid", errors.empty()}, {"errors", errors}});
}

Result list_instruction_sets(const Ports& p) {
    if (!store_ready(p))
        return store_unavailable();
    auto sets = p.store->list_sets();
    if (!sets)
        return fail(Kind::kStoreUnavailable, "instruction store read failed");
    json arr = json::array();
    for (const auto& s : *sets)
        arr.push_back({{"id", s.id},
                       {"name", s.name},
                       {"description", s.description},
                       {"created_by", s.created_by},
                       {"created_at", s.created_at}});
    return ok(json{{"sets", std::move(arr)}, {"count", sets->size()}});
}

Result create_instruction_set(const json& args, const Ports& p) {
    if (!store_ready(p))
        return store_unavailable();
    auto set = build_instruction_set_from_body(strip(args, /*drop_id=*/false), p.created_by);
    if (!set)
        return fail(Kind::kInvalid, set.error());
    const Audit audit(p, "instruction_set.create", "InstructionSet");
    const std::string label = audit_label(set->name);
    if (!audit.attempt("", label))
        return audit.refused("the set was NOT created");
    // create_set, NEVER create_set_seed (the boot-time seed path).
    auto result = p.store->create_set(*set);
    if (!result) {
        switch (classify_store_error(result.error())) {
        case StoreFault::kDb:
            return audit.settle("error", "", "db_error", store_write_outcome_unknown("set"));
        case StoreFault::kConflict:
            return audit.settle("denied", "", "conflict",
                                fail(Kind::kConflict,
                                     std::string(strip_conflict_prefix(result.error()))));
        default:
            return audit.settle("denied", "", "invalid", fail(Kind::kInvalid, result.error()));
        }
    }
    const bool persisted = audit.outcome("success", audit_target(*result), label);
    return ok(json{{"id", *result}}, persisted);
}

Result delete_instruction_set(const json& args, const Ports& p) {
    if (!store_ready(p))
        return store_unavailable();
    std::string id;
    if (auto err = check_id_arg(args, "id", id))
        return fail(Kind::kInvalid, *err);
    const Audit audit(p, "instruction_set.delete", "InstructionSet");
    const std::string target = audit_target(id);
    if (!audit.attempt(target, ""))
        return audit.refused("the set was NOT deleted");
    // Members are unset (instruction_set_id cleared), never deleted; a bundled seed set leaves a
    // tombstone so it does not reappear on boot.
    auto result = p.store->delete_set(id);
    if (!result) {
        if (classify_store_error(result.error()) == StoreFault::kDb) {
            return audit.settle("error", target, "db_error", store_write_outcome_unknown("set"));
        }
        return audit.settle("denied", target, "not_found",
                            fail(Kind::kNotFound, "instruction set not found"));
    }
    const bool persisted = audit.outcome("success", target, "");
    return ok(json{{"id", id}, {"deleted", true}}, persisted);
}

bool ticket_binds_digest(std::string_view tool) noexcept {
    return tool == "import_definition" || tool == "save_definition_yaml";
}

namespace {

/// The definition fields an approver reads, as plain bounded folded strings (`audit_label`).
/// Empty values are omitted. `parse_error` = the large argument is not something the handler can
/// act on (a non-object document, a non-string or refused YAML, a YAML naming neither plugin nor
/// action): the handler refuses the call later, so no refusal text is produced here.
struct TicketSummary {
    std::vector<std::pair<std::string, std::string>> fields;
    bool parse_error{false};
};

/// `dispatch_only` limits the fields to the three the store's signed branch binds from the YAML
/// that the subject displays (`approval_mode`, `plugin`, `action`): a signed import's `id` and
/// `name` come from the DOCUMENT only, never from its yaml_source, so showing the YAML's would
/// paint a value the store never uses. A YAML save (the whole definition is the YAML) takes all
/// five.
void summarise_yaml(const std::string& yaml, TicketSummary& out, bool dispatch_only) {
    // The same byte refusals the handler applies first: a refused source is never parsed (CPU).
    if (yaml_source_byte_refusal(yaml)) {
        out.parse_error = true;
        return;
    }
    const auto f = instruction_yaml::parse_definition_yaml(yaml);
    if (f.plugin.empty() && f.action.empty())
        out.parse_error = true;
    const std::pair<const char*, const std::string*> pairs[] = {
        {"plugin", &f.plugin},       {"action", &f.action}, {"approval_mode", &f.approval},
        {"definition_id", &f.id},    {"name", &f.name}};
    const std::size_t count = dispatch_only ? 3 : 5;
    for (std::size_t i = 0; i < count; ++i)
        if (!pairs[i].second->empty())
            out.fields.emplace_back(pairs[i].first, audit_label(*pairs[i].second));
}

/// True when the import document is SIGNED in the store's sense: BOTH `signature` and `publicKey`
/// are non-empty strings (`InstructionStore::import_definition_json_impl`: `sig_state` and
/// `pub_state` both `Present`, then `bind_signed_dispatch_columns`). This mirrors only the
/// signed/unsigned DECISION; the fields then read from the YAML are the three of
/// `summarise_yaml(.., dispatch_only=true)`, the ones `bind_signed_dispatch_columns` overwrites
/// and the subject displays. Change them together.
bool import_is_signed(const json& doc) {
    const auto non_empty_string = [&](const char* key) {
        const auto it = doc.find(key);
        return it != doc.end() && it->is_string() && !it->get_ref<const std::string&>().empty();
    };
    return non_empty_string("signature") && non_empty_string("publicKey");
}

/// `yaml_creates` (a `save_definition_yaml` with no `id` argument, or an empty one) = the YAML IS
/// the new definition, so an approval it does not state is stored as `auto`
/// (`definition_from_yaml_fields`) and shown as such; an UPDATE keeps the stored value
/// (`merge_yaml_into_stored`) when the YAML states none, so none is shown.
TicketSummary summarise_ticket_argument(bool is_import, const json& large, bool yaml_creates) {
    TicketSummary out;
    if (!is_import) {
        if (!large.is_string()) {
            out.parse_error = true;
            return out;
        }
        summarise_yaml(large.get_ref<const std::string&>(), out, /*dispatch_only=*/false);
        if (yaml_creates &&
            std::none_of(out.fields.begin(), out.fields.end(),
                         [](const auto& kv) { return kv.first == "approval_mode"; }))
            out.fields.emplace_back("approval_mode", "auto");
        return out;
    }
    if (!large.is_object()) {
        out.parse_error = true;
        return out;
    }
    // The document's own top-level fields (what an unsigned import runs). Only a SIGNED document
    // (`import_is_signed`) takes plugin, action and approval_mode from its yaml_source, so only
    // then is one of those the document omits read from there; an unsigned document's
    // yaml_source is not read, and a document's omitted id/name are never read from it (the store
    // generates an id, and refuses a missing name).
    static constexpr std::pair<const char*, const char*> kKeys[] = {
        {"definition_id", "id"}, {"name", "name"},     {"plugin", "plugin"},
        {"action", "action"},    {"approval_mode", "approval_mode"}};
    for (const auto& [out_key, doc_key] : kKeys) {
        const auto it = large.find(doc_key);
        if (it != large.end() && it->is_string() && !it->get_ref<const std::string&>().empty()) {
            std::string value = it->get_ref<const std::string&>();
            // The store lowercases the action of every non-trusted import (agent plugins match it
            // case-sensitively), so the stored value is what is shown.
            if (std::string_view(out_key) == "action")
                std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
            out.fields.emplace_back(out_key, audit_label(value));
        }
    }
    if (import_is_signed(large))
        if (const auto it = large.find("yaml_source"); it != large.end() && it->is_string()) {
            TicketSummary from_yaml;
            summarise_yaml(it->get_ref<const std::string&>(), from_yaml, /*dispatch_only=*/true);
            // A YAML that cannot be read is not an import-level parse error (the top-level fields
            // may still describe the document); only a document with nothing to show at all is.
            for (auto& kv : from_yaml.fields)
                if (std::none_of(out.fields.begin(), out.fields.end(),
                                 [&](const auto& have) { return have.first == kv.first; }))
                    out.fields.push_back(std::move(kv));
        }
    out.parse_error = out.fields.empty();
    // The EFFECTIVE approval_mode, always shown for an object document: the document's, else
    // (signed) the YAML's, else `auto` (what the store writes for an omitted one). Never absent,
    // so an approver cannot read an omission as a stricter mode than the one stored.
    if (std::none_of(out.fields.begin(), out.fields.end(),
                     [](const auto& kv) { return kv.first == "approval_mode"; }))
        out.fields.emplace_back("approval_mode", "auto");
    return out;
}

/// `"key":value` fragments are assembled by hand: nlohmann::ordered_json keeps its members in a
/// vector and every insert scans it for the key, so building a subject from N arguments through
/// it is O(N^2) (80,000 keys took 10 s), and it runs on a handler thread before any argument
/// count check.
std::string json_text(const json& v) {
    return v.dump(-1, ' ', false, json::error_handler_t::replace);
}

} // namespace

std::optional<std::string> ticket_subject(std::string_view tool, const json& args) {
    const bool is_import = tool == "import_definition";
    const char* const field = is_import ? "document" : "yaml_source";
    const std::string bytes_key = std::string(field) + "_bytes";
    const std::string sha_key = std::string(field) + "_sha256";
    // Every key the subject itself writes, reserved UNCONDITIONALLY whether or not it is emitted
    // for this call: a client argument with one of these names would otherwise land under the
    // plain name and paint a false field (an unknown `approval_mode` argument over an omitted
    // one). The handler refuses such an argument later, but the approver reads this subject first,
    // so it is kept under an `arg_` prefix instead.
    const std::unordered_set<std::string> reserved = {
        "tool", "approval_mode", "plugin",     "action", "definition_id",
        "name", "parse_error",   bytes_key,    sha_key};
    // Insertion-ordered, so the Approvals page's short cell opens with the tool and the
    // dispatch-relevant fields (approval_mode first: it is the one a downgrade flips), never with
    // a hash. The 4 MiB document TREE is read by reference, never copied; a YAML string is read in
    // place; only a non-string document is dumped once, to hash the bytes the store receives.
    std::vector<std::pair<std::string, std::string>> parts; // key, JSON text of the value
    parts.emplace_back("tool", json_text(std::string(tool)));
    const json* large = nullptr;
    if (args.is_object())
        if (const auto it = args.find(field); it != args.end())
            large = &*it;
    std::optional<std::string> digest;
    std::size_t large_bytes = 0;
    if (large) {
        // The very bytes the handler consumes: the document as the store receives it, the YAML
        // as sent.
        std::string dumped;
        if (!large->is_string())
            dumped = json_text(*large);
        const std::string& bytes = large->is_string() ? large->get_ref<const std::string&>() : dumped;
        digest = ::yuzu::server::sha256_hex(bytes);
        if (!digest)
            return std::nullopt;
        large_bytes = bytes.size();
        // What the approver reads. The digest still binds the exact bytes. A YAML save with no
        // (or an empty) `id` is a create.
        bool yaml_creates = false;
        if (!is_import && args.is_object()) {
            const auto id_it = args.find("id");
            yaml_creates = id_it == args.end() ||
                           (id_it->is_string() && id_it->get_ref<const std::string&>().empty());
        }
        const auto summary = summarise_ticket_argument(is_import, *large, yaml_creates);
        for (const char* key : {"approval_mode", "plugin", "action", "definition_id", "name"})
            for (const auto& [k, v] : summary.fields)
                if (k == key)
                    parts.emplace_back(k, json_text(v));
        if (summary.parse_error)
            parts.emplace_back("parse_error", "true");
    }
    // Keys taken so far by client arguments (the reserved set is checked separately), so a
    // collision costs one hash lookup, not a scan.
    std::unordered_set<std::string> taken;
    if (args.is_object())
        for (const auto& [k, v] : args.items()) {
            if (k == "approval_id" || k == field)
                continue;
            std::string key = k;
            while (reserved.contains(key) || taken.contains(key))
                key = "arg_" + key;
            taken.insert(key);
            parts.emplace_back(std::move(key), json_text(v));
        }
    if (large) {
        parts.emplace_back(bytes_key, std::to_string(large_bytes));
        parts.emplace_back(sha_key, json_text(*digest));
    }
    std::string out = "{";
    for (const auto& [k, v] : parts) {
        if (out.size() > 1)
            out += ',';
        out += json_text(k);
        out += ':';
        out += v;
    }
    out += '}';
    return out;
}

std::optional<std::string> missing_version_token(std::string_view tool, const json& args) {
    if (!args.is_object())
        return std::nullopt;
    const auto has_int = [&](const char* key) {
        const auto it = args.find(key);
        return it != args.end() && it->is_number_integer();
    };
    if (tool == "update_definition" && !has_int("expected_updated_at"))
        return "update_definition requires expected_updated_at at the supervised tier: the "
               "approval is for one version of the definition. Read it first (get_definition) "
               "and pass its updated_at as expected_updated_at";
    if (tool == "delete_definition" && !has_int("expected_updated_at"))
        return "delete_definition requires expected_updated_at at the supervised tier: the "
               "approval is for one version of the definition. Read it first (get_definition) "
               "and pass its updated_at as expected_updated_at";
    if (tool == "save_definition_yaml") {
        const auto it = args.find("id");
        const bool updating = it != args.end() && it->is_string() && !it->get<std::string>().empty();
        if (updating && !has_int("updated_at"))
            return "save_definition_yaml with an id requires updated_at at the supervised "
                   "tier: the approval is for one version of the definition. Read it first "
                   "(get_definition) and pass its updated_at";
    }
    return std::nullopt;
}

std::optional<Result> stale_version_refusal(std::string_view tool, const json& args,
                                            const InstructionStore* store) {
    const char* key = nullptr;
    if (tool == "update_definition" || tool == "delete_definition")
        key = "expected_updated_at";
    else if (tool == "save_definition_yaml")
        key = "updated_at";
    else
        return std::nullopt;
    if (!args.is_object())
        return std::nullopt;
    const auto id_it = args.find("id");
    if (id_it == args.end() || !id_it->is_string())
        return std::nullopt;
    const std::string id = id_it->get<std::string>();
    if (id.empty() || id.size() > kIdMaxLen || definition_id_is_malformed(id))
        return std::nullopt; // the handler's own id check refuses it with the right text
    const auto token = read_version_token(args, key);
    if (!token || !*token)
        return std::nullopt; // absent or malformed: the version-token check / handler refuse it
    if (store == nullptr || !store->is_open())
        return store_unavailable();
    const auto stored = store->get_definition(id);
    if (!stored)
        return store_unavailable(); // unreadable = unknown, never "matches"
    if (!*stored)
        return fail(Kind::kNotFound, "instruction definition not found");
    if ((*stored)->updated_at != **token)
        return fail(Kind::kConflict,
                    stale_delete_message("instruction definition '" + id +
                                         "' was modified since it was loaded"));
    return std::nullopt;
}

std::string_view generic_audit_result(Kind kind) noexcept {
    switch (kind) {
    case Kind::kOk:
        return "success";
    case Kind::kInvalid:
    case Kind::kNotFound:
    case Kind::kConflict:
    case Kind::kReferenced:
        return "denied";
    case Kind::kStoreUnavailable:
    case Kind::kAuditRefused:
        return "error";
    }
    return "error";
}

Rendered render(const Result& r, const std::string& cid, bool extra_audit_dropped) {
    Rendered out;
    const bool dropped = !r.audit_persisted || extra_audit_dropped;
    if (r.kind == Kind::kOk) {
        json payload = r.payload;
        if (dropped)
            payload["audit_persisted"] = false;
        out.payload_json = payload.dump(-1, ' ', false, json::error_handler_t::replace);
        return out;
    }
    out.is_error = true;
    out.message = r.message;
    const char* reason = "invalid";
    const char* remediation = "correct the arguments and re-call; nothing was changed";
    std::optional<std::int64_t> retry;
    switch (r.kind) {
    case Kind::kInvalid:
        out.code = kInvalidParams;
        if (!r.errors.empty()) {
            reason = "validation_failed";
            remediation = "fix the listed errors in error.data.errors and re-call";
        }
        break;
    case Kind::kNotFound:
        out.code = kInvalidParams;
        reason = "not_found";
        remediation = "list the definitions or sets to find a current id; nothing was changed";
        break;
    case Kind::kConflict:
        out.code = kInvalidParams;
        reason = "conflict";
        remediation = "the id already exists or the row changed since you read it; re-read it, "
                      "then re-call with a fresh id or updated_at; nothing was changed";
        break;
    case Kind::kReferenced:
        out.code = kInvalidParams;
        reason = "referenced";
        remediation = "remove each listed referrer (or point it at another definition), then "
                      "re-call; nothing was deleted";
        break;
    case Kind::kStoreUnavailable:
        out.code = kInternalError;
        reason = "store_unavailable";
        remediation = r.outcome_unknown
                          ? "the write may or may not have been applied: read the definition or "
                            "set, and re-call only if it was not"
                      : r.not_retryable
                          ? "the server is not configured for this operation; an administrator "
                            "must fix the deployment; nothing was changed"
                          : "retry once the server reports ready";
        // No hint when the write may have landed (a client that honours it would blind-retry) or
        // when the fault is configuration (waiting does not fix it).
        if (!r.outcome_unknown && !r.not_retryable)
            retry = kMcpStoreFaultRetryMs;
        break;
    case Kind::kAuditRefused:
        out.code = kInternalError;
        reason = "audit_unavailable";
        if (r.not_retryable) {
            remediation = "the server is not configured for this operation; an administrator "
                          "must fix the deployment; nothing was changed";
            break;
        }
        remediation = "retry once the audit store recovers; nothing was changed";
        retry = kMcpStoreFaultRetryMs;
        break;
    case Kind::kOk:
        break;
    }
    json d{{"correlation_id", cid},
           {"retry_after_ms", retry ? json(*retry) : json(nullptr)},
           {"remediation", remediation},
           {"reason", reason}};
    if (!r.errors.empty())
        d["errors"] = r.errors;
    if (dropped)
        d["audit_persisted"] = false;
    out.data_json = d.dump(-1, ' ', false, json::error_handler_t::replace);
    return out;
}

} // namespace yuzu::server::mcp::instruction_authoring
