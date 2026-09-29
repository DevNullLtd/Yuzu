#pragma once

/// @file instruction_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 PR-7) — the 13-route Instruction Definitions + Instruction
/// Sets API cluster (`docs/Instruction-Engine.md`): CRUD + export/import
/// over `InstructionStore`, the RBAC-gated editor fragment, and the two
/// dashboard YAML save/validate endpoints. Every handler body is copied
/// verbatim from server.cpp; the changes are the receiver (`web_server_->`
/// -> `sink.`), the gate closures (`require_permission`/`require_auth` ->
/// `deps.perm_fn`/`deps.auth_fn`), the member access (`instruction_store_.`
/// -> `deps.store->`), and the audit/event calls (`audit_log(...)` ->
/// `deps.audit_fn(...)`, `emit_event(...)` -> `deps.emit_event_fn(...)`).
///
/// NOT in this module (deliberately — outside #2542 PR-7's route list for
/// this extraction): `GET /fragments/instructions` (the definitions-list
/// fragment) and its row-rendering helper, and `POST /fragments/
/// instructions/yaml-preview` — both stayed inline in server.cpp at PR-7
/// time and were extracted later, into their own
/// `instruction_fragment_routes.{hpp,cpp}` module (#2542 PR-12's Infra/Misc
/// bundle — see that module's header for why: on inspection at PR-12 time,
/// only `validate_yaml_source` was actually shared with this module's two
/// YAML endpoints; `highlight_yaml` had exactly one caller, the yaml-preview
/// route, and moved there rather than being promoted). See the "PROMOTED,
/// NOT DUPLICATED" note below for `validate_yaml_source`'s own sharing
/// story, which this module still participates in.
///
/// PROMOTED, NOT DUPLICATED — `validate_yaml_source` and `log_safe`. Both
/// were `static ServerImpl` members with call sites BOTH inside this
/// extraction (the YAML save/validate routes below) AND outside it
/// (`/fragments/instructions/yaml-preview` for `validate_yaml_source` — that
/// route itself later moved to `instruction_fragment_routes.cpp`, #2542
/// PR-12, but the promotion made here at PR-7 time is what let it keep
/// calling the free function unchanged; the `/api/approvals/:id/{approve,reject}`
/// routes for `log_safe`, which #2542 PR-9 later extracted into
/// `approval_routes.cpp` — reconciled at merge time onto this same
/// promotion rather than PR-9's own independently-promoted `log_safe.hpp`).
/// Copying either into this file would have split a single-contract helper
/// into two independently-driftable copies — `validate_yaml_source`'s own
/// doc comment names exactly this risk ("#1993: validate and save can never
/// diverge on what a complete definition is"). Both are promoted to free
/// functions instead — see `instruction_store.hpp`'s `validate_yaml_source`
/// doc comment and `web_utils.hpp`'s `log_safe` doc comment — mirroring the
/// #2557 `json_extract.hpp` precedent for a call-site-straddling helper. No
/// call site needed to change its calling syntax, wherever it now lives
/// (ordinary unqualified-lookup resolution from a `yuzu::server`-namespaced
/// class or nested namespace to a `yuzu::server` free function).
///
/// `kInstructionEditorHtml`/`kInstructionEditorDeniedHtml` are `extern
/// const char* const` globals defined in `instruction_ui.cpp` (a separate
/// TU, build-time-embedded HTML) — declared `extern` at file (global) scope
/// in `instruction_routes.cpp`, mirroring server.cpp's own pre-extraction
/// forward declarations, since both TUs link into the same binary.
///
/// NEW DEPS FIELD — `resolve_session_fn`. `POST /api/instructions` needs a
/// NON-BLOCKING session resolve (`auth_routes_->resolve_session(req)`, never
/// writes to `res`) purely to populate `def.created_by` when present — the
/// route never gates on it, unlike `deps.auth_fn` (wraps `require_auth`,
/// WRITES a 401 on failure). Substituting `auth_fn` here would be a
/// behaviour change. Shared with `execution_routes.cpp`, which needs the
/// identical shape — see that file's header comment for the full rationale;
/// hoisted once in server.cpp's shared closure block.
///
/// NEW DEPS FIELD — `emit_event_fn`. Wraps `ServerImpl::emit_event`
/// (`auth_routes_->emit_event`), shared with `execution_routes.cpp` — see
/// that file's header comment for the exposed 4-argument shape (no
/// `Severity` parameter; no call site in either module passes a non-default
/// one).
///
/// AUDIT ASYMMETRIES (preserved verbatim, not introduced by this move):
///   - `GET /api/instructions`, `GET /:id`, `GET /:id/export`,
///     `GET /api/instruction-sets`: pure reads, never audited.
///   - `POST /api/instructions` (JSON create): a null `deps.store` 503s
///     BEFORE the body is parsed/validated at all — the null-store check is
///     the first gate after `perm_fn`, ahead of the JSON-shape/field
///     validation that would otherwise run. A genuine DB error audits
///     `"error"`; a duplicate-id conflict audits `"denied"`; a plain
///     validation 400 is NOT audited; success audits `"success"`.
///   - `PUT /:id` (JSON update): the ORDINARY not-found path — the
///     pre-update `get_definition` read returning an empty optional, the
///     only way an operator hitting a genuinely-nonexistent id reaches
///     this route — is a 404 with NO audit call at all, same as the GET
///     routes above. `update_definition` ALSO returns its own
///     `"not_found: "` error (the `WHERE id=...` UPDATE matching zero
///     rows) if the row is deleted in the window between that read and
///     this write (TOCTOU) — THAT surfacing, and only that one, audits
///     `"denied"`; it is not reachable from a single-threaded test without
///     simulating the race. A genuine DB error (either read or write leg)
///     audits `"error"`. A plain validation 400 is NOT audited. Success
///     audits `"success"`.
///   - `DELETE /:id`: a DB error audits `"error"`; a not-found audits
///     `"denied"`; success audits `"success"`.
///   - `POST /api/instructions/import`: a DB error audits `"error"`; EVERY
///     other rejection (conflict or otherwise) audits `"denied"` — unlike
///     the plain JSON create route, `import` audits every non-DB-error
///     rejection, not only conflicts (R4, #1073 signature-gate rejections);
///     success audits `"success"`. The response body additionally carries
///     `audit_emitted` (the captured `deps.audit_fn` return) on every
///     branch — a #883 SOC 2 CC7.2 pattern unique to this route in this
///     module.
///   - `POST /api/instruction-sets` (create): **NO audit call on ANY
///     branch** (db-error, conflict, validation, OR success) — a
///     pre-existing gap, documented as such in the original inline code and
///     NOT fixed by this mechanical move (tracked separately, #3598).
///   - `DELETE /api/instruction-sets/:id`: a DB error audits `"error"`; a
///     not-found audits `"denied"`; **success is NOT audited** — asymmetric
///     with `DELETE /api/instructions/:id` (which DOES audit success). Both
///     preserved verbatim; this is not this extraction's place to unify
///     them.
///   - `GET /fragments/instructions/editor`: never audited. A
///     `perm_fn` denial does NOT surface as an HTTP 403 — the handler
///     overrides it to `200` + `kInstructionEditorDeniedHtml` (an HTMX
///     fragment convention: htmx does not swap a non-2xx response, so a
///     real 403 here would leave the panel showing stale content with no
///     visible denial). `kInstructionEditorDeniedHtml` names the required
///     role (`PlatformEngineer`/`Administrator`, see `instruction_ui.cpp`)
///     in the rendered copy — an operator sees WHY they were denied, not
///     just that they were.
///   - `POST /api/instructions/yaml` (dashboard save, form-encoded): a null
///     `deps.store` check is the first gate after `perm_fn`, ahead of the
///     form-body parsing that would otherwise run — same ordering as the
///     JSON create route above. Degrades to `200` + an HTML error `<div>`
///     (NOT 503 — this is an HTMX fragment response, not a JSON API).
///     Byte-level/store-level
///     validation failures (`validate_yaml_source`) likewise render `200` +
///     an HTML error list, unaudited. Past validation: the UPDATE branch's
///     store-level failure is logged via `spdlog::warn` only — **NOT
///     audited at all**; only UPDATE success is audited. The CREATE
///     branch's conflict IS audited `"denied"`, but its db-error/other
///     failure is NOT audited (same split as the plain-validation-vs-
///     conflict distinction on the JSON `POST /api/instructions` route,
///     but here db-error ALSO goes unaudited, unlike that route). Success
///     on either branch audits `"success"`.
///   - `POST /api/instructions/validate-yaml`: pure validation, no store
///     access, never audited.
///   - `deps.audit_fn` (a `std::function`) has no default arguments, unlike
///     the `ServerImpl::audit_log` member it replaces (`detail = {}`).
///     Every call site that relied on that default now passes `""`
///     explicitly for `detail` — same audit row, no behaviour change.
///
/// Routes (13) — gate in parens:
///   GET    /api/instructions                    (perm_fn InstructionDefinition:Read)
///   POST   /api/instructions                     (perm_fn InstructionDefinition:Write)
///   GET    /api/instructions/:id                 (perm_fn InstructionDefinition:Read)
///   PUT    /api/instructions/:id                  (perm_fn InstructionDefinition:Write)
///   DELETE /api/instructions/:id                  (perm_fn InstructionDefinition:Delete)
///   GET    /api/instructions/:id/export           (perm_fn InstructionDefinition:Read)
///   POST   /api/instructions/import               (perm_fn InstructionDefinition:Write)
///   GET    /api/instruction-sets                 (perm_fn InstructionSet:Read)
///   POST   /api/instruction-sets                  (perm_fn InstructionSet:Write)
///   DELETE /api/instruction-sets/:id              (perm_fn InstructionSet:Delete)
///   GET    /fragments/instructions/editor         (auth_fn, then perm_fn InstructionDefinition:Write)
///   POST   /api/instructions/yaml                 (perm_fn InstructionDefinition:Write, then auth_fn)
///   POST   /api/instructions/validate-yaml        (perm_fn InstructionDefinition:Read)

#include <yuzu/server/auth.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {
class HttpRouteSink;
class InstructionStore;
} // namespace yuzu::server

namespace yuzu::server::instruction {

/// Construction deps for `register_instruction_routes`. Every closure/
/// pointer is bound once at start_web_server() time in server.cpp and never
/// reseated.
struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                       const std::string&, const std::string&)>;
    /// Wraps `AuthRoutes::resolve_session` — see this file's header
    /// comment's "NEW DEPS FIELD" note for why this is a distinct,
    /// non-blocking closure rather than a reuse of `auth_fn`.
    using ResolveSessionFn = std::function<std::optional<auth::Session>(const httplib::Request&)>;
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    /// Wraps `ServerImpl::emit_event` — see this file's header comment's
    /// "NEW DEPS FIELD" note for the exposed 4-argument shape.
    using EmitEventFn = std::function<void(const std::string& event_type,
                                           const httplib::Request& req, const nlohmann::json& attrs,
                                           const nlohmann::json& payload_data)>;

    AuthFn auth_fn;
    PermFn perm_fn;
    ResolveSessionFn resolve_session_fn;
    AuditFn audit_fn;
    EmitEventFn emit_event_fn;
    /// `ServerImpl::instruction_store_`. Null -> every route answers 503
    /// ("service unavailable") without touching it, EXCEPT the two HTMX
    /// YAML endpoints (see this file's header "AUDIT ASYMMETRIES" note —
    /// they degrade to a 200 HTML error instead, matching the original
    /// inline code's fragment-response convention).
    InstructionStore* store{nullptr};
};

/// Register all 13 Instruction Definitions + Instruction Sets API routes
/// against `sink`.
void register_instruction_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::instruction
