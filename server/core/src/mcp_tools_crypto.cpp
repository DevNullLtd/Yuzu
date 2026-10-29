// Registry-resident /crypto tools (see mcp_tool_registry.hpp): the MCP twins of
// GET /api/v1/crypto/libraries[/devices], GET /api/v1/crypto/cbom, GET /api/v1/crypto/widgets,
// GET/PUT /api/v1/crypto/dashboard/layout and GET /api/v1/crypto/ca/stats. Seven tools, carved
// out of mcp_server.cpp's legacy kTools[] + if/else chain (#6558 PR 2, the pilot carve of the
// ADR-0031 WS-A4 MCP seam). `crypto` was the pilot because its REST half (crypto_routes.cpp) was
// already carved and enforced and CryptoApi is already store-free.
//
// Every tool is shaped by the SAME pure model the REST routes and the /crypto page use
// (crypto_library_model.hpp, crypto_widget_catalogue.hpp, crypto_cbom.hpp) and reads through the
// SAME CryptoApi instance, reached here only through the ToolDeps closures (mcp_tool_deps.hpp),
// so a twin cannot disagree with its REST route on a byte of `data`.
//
// Gates, unchanged from the legacy branches (the record's securable / operation / service-scope
// class drive the generic tier + C8 checks that run BEFORE a handler):
//   * get_crypto_libraries, list_crypto_library_devices, export_crypto_cbom: CONFINED READS
//     gated by ctx.deps->fleet_read_fn alone (Inventory:Read, ADR-0017 admit-then-filter). The
//     gate already covers the MCP tier ladder and RBAC, so none of these handlers calls
//     tier_allows or ctx.perm_fn (stacking either is the BLOCKING defect authz_gates.hpp
//     documents). Its composed meet(management-group, service-scope) VisibleSet is pushed into
//     the SQL by the CryptoApi seam, so a confined caller gets a real, filtered answer.
//   * list_crypto_widgets, get_crypto_dashboard_layout, set_crypto_dashboard_layout: the caller's
//     OWN catalogue / layout, tier-gated by the generic check alone (Infrastructure Read / Write,
//     the result-set precedent), no RBAC gate in the handler. The layout is keyed on the session
//     username, re-resolved through ToolDeps::username_fn.
//   * get_crypto_ca_stats: fleet_read_fn Inventory:Read, and a CONFINED caller is refused (these
//     are fleet-wide figures, ADR-0070 R2), never given a narrowed count.
//
// ONE handler per tool, never a shared one: the A5 retry-hint gate
// (scripts/ci/check-mcp-retry-hints.py) scans each tool's own handler body, so a shared handler
// is invisible to it. The `// retry-hint-exempt:` markers below sit on the answer they justify.
//
// What the carve CHANGES (the rest is behaviour-preserving): the dispatch chain's central
// `arguments`-is-an-object check now runs before a handler, so a non-object `arguments`
// (null, array, string) is refused there with the generic A4 -32602 and an `mcp.<tool>` denial
// row. The error code is the same, and so is the message text for the four tools that already
// said "arguments must be a JSON object" (the three confined reads and the layout
// write); only the three no-argument tools lose their own "takes no arguments" text for a
// non-object value. The extra denial row is new for all seven, and the refusal now precedes the
// Inventory:Read gate for the four tools that have one (the three confined reads and
// get_crypto_ca_stats).
//
// Unwired posture, the siblings' (hardware / containment): an unwired provider, a missing audit
// sink or an unresolvable username answers `answer_unwired` (a non-retryable A4 internal error)
// and writes the generic failure row, so every call leaves an `mcp.<tool>` row (the registry seam
// test, test_mcp_server.cpp, requires it). The legacy branches answered a bare
// `error_response(kInternalError, ...)` with no row; that is a change. The four tools that write
// a domain audit row (the three confined reads and get_crypto_ca_stats) now also refuse when
// `audit_fn` is unwired, because `try_persist_audit` would otherwise call an empty sink
// "persisted" and the read would succeed with no `crypto.*.view` row. A caller-input refusal
// (strict arguments, a bad cursor) likewise leaves an `mcp.<tool>|denied` row, as the hardware
// tools do; the legacy branches wrote none.
//
// Also changed, and not visible in a response when it succeeds: a domain audit row goes through
// `detail::try_persist_audit`, so a throwing audit sink is caught (the layout write's "attempted"
// row then fails closed) instead of propagating out of the handler, and the caller's username is
// re-resolved from the request (ToolDeps::username_fn) instead of read off the session object.

#include "mcp_tool_registry.hpp"

#include "authz_model.hpp"             // authz::VisibleSet
#include "crypto_api.hpp"              // CryptoReadError and the CryptoApi result types
#include "crypto_cbom.hpp"             // export_crypto_cbom (CycloneDX 1.7 shaper)
#include "crypto_library_model.hpp"    // the shared library model, Params, dump_safe
#include "crypto_widget_catalogue.hpp" // the shared widget catalogue and layout model
#include "mcp_jsonrpc.hpp"             // kInternalError, kInvalidParams, kPermissionDenied, success_response, error_response
#include "mcp_retry.hpp"               // kMcpStoreFaultRetryMs, kCryptoPoolTooSmallRemedy
#include "mcp_tool_deps.hpp"           // ToolDeps
#include "mcp_tool_helpers.hpp"        // answer, answer_unwired (shared by the registry files)
#include "rest_audit.hpp"              // detail::try_persist_audit (the shared audit kernel)

#include <yuzu/version.hpp> // kVersionString - the CBOM metadata tool version

#include <nlohmann/json.hpp>

#include <spdlog/spdlog.h>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace yuzu::server::mcp {
namespace {

/// Builds the library model's `Params` from the named MCP arguments (strings and integers only;
/// any other JSON type is left out, and an integer is stringified for every key). Every caller
/// refuses a wrongly typed argument first, through
/// `crypto_library::strict_{summary,devices}_args_error` / `crypto_cbom::strict_cbom_args_error`,
/// so nothing is silently dropped or stringified here. A copy of mcp_server.cpp's
/// `catalogue_params` (which the software-catalogue tools and `list_issued_certs` still use);
/// both build the identical `std::multimap<std::string, std::string>`.
crypto_library::Params catalogue_params(const nlohmann::json& args,
                                        std::initializer_list<const char*> keys) {
    crypto_library::Params p;
    for (const char* k : keys) {
        if (!args.contains(k))
            continue;
        if (args[k].is_string())
            p.emplace(k, args[k].get<std::string>());
        else if (args[k].is_number_integer())
            p.emplace(k, std::to_string(args[k].get<std::int64_t>()));
    }
    return p;
}

// The audit-detail tag of a /crypto layout failure (never the username), shared by the two
// layout twins; the REST twin's crypto_routes.cpp layout_failure_detail is its mirror.
std::string layout_failure_tag(const CryptoReadError& e) {
    using K = CryptoReadError::Kind;
    switch (e.kind) {
    case K::kOutcomeUnknown:
        return "outcome=unknown";
    case K::kConflict:
        return "outcome=conflict";
    case K::kCorrupt:
        return "outcome=corrupt";
    case K::kInvalid:
        return "outcome=invalid";
    case K::kDegraded:
        break;
    }
    return e.cause == CryptoReadCause::kCapacity ? "outcome=busy" : "outcome=degraded";
}

/// A caller-input refusal: a bare JSON-RPC -32602, never retryable. Writes no row: for a refusal
/// that already left its own failure row (a store-reported invalid input after the read).
void answer_invalid_params(const ToolCallContext& ctx, const std::string& message) {
    answer(ctx, error_response(ctx.id, kInvalidParams, message)); // retry-hint-exempt: caller-input rejection
}

/// A caller-input refusal judged before any row exists: the same bare -32602, plus the generic
/// `mcp.<tool>|denied` row every registry call leaves (hardware / containment precedent).
void refuse_params(const ToolCallContext& ctx, const std::string& message) {
    (void)ctx.audit("denied", "invalid arguments: " + message);
    answer_invalid_params(ctx, message);
}

/// The generic mcp.<tool> row, written the way the legacy branches' `mcp_audit` lambda wrote it.
bool mcp_row(const ToolCallContext& ctx, const std::string& result_status,
             const std::string& detail = {}) {
    return ctx.audit(result_status, detail);
}

/// A domain-verb row through ToolDeps::audit_fn. try_persist_audit treats an EMPTY sink as an
/// audit-off deployment, not a persistence failure, and catches a throwing sink (-> false). The
/// legacy branches called the handler's raw `audit_fn`, which would have thrown on an empty one;
/// production always wires it. The one caller whose safety depends on a row existing,
/// set_crypto_dashboard_layout, therefore refuses to run without a sink (see its handler).
bool domain_row(const ToolCallContext& ctx, const char* verb, const std::string& result,
                const char* target_type, const std::string& target_id, const std::string& detail) {
    return ctx.deps != nullptr &&
           yuzu::server::detail::try_persist_audit(ctx.deps->audit_fn, ctx.req, verb, result,
                                                   target_type, target_id, detail);
}

// ── get_crypto_libraries ──────────────────────────────────────────────────────────────────
void handle_get_crypto_libraries(const ToolCallContext& ctx) {
    namespace cl = crypto_library;
    if (ctx.deps == nullptr || !ctx.deps->fleet_read_fn || !ctx.deps->audit_fn) {
        answer_unwired(ctx, "service unavailable", "crypto provider unwired", {},
                       "get_crypto_libraries: fleet_read_fn or audit_fn unwired - misconfigured call site; "
                       "failing closed");
        return;
    }
    auto gate = ctx.deps->fleet_read_fn(ctx.req, ctx.res, "Inventory", "Read");
    if (!gate.admitted)
        return; // gate already wrote the A4 error body + status
    // Strict input (REST clamps, MCP refuses), judged before any parse or read.
    if (const auto bad = cl::strict_summary_args_error(ctx.args)) {
        refuse_params(ctx, *bad);
        return;
    }
    if (!ctx.deps->crypto_library_summary_fn) {
        answer_unwired(ctx, "Crypto library data unavailable", "crypto library provider unwired");
        return;
    }
    const auto parsed =
        cl::parse_summary_params(catalogue_params(ctx.args, {"family", "ecosystem"}));
    if (!parsed) {
        refuse_params(ctx, parsed.error());
        return;
    }
    const std::string target = cl::audit_target(*parsed);
    // The seam's caller-input refusal (a bad cursor) is answered through this helper so the
    // `if (!read)` block below holds ONLY the retryable store-fault answer: the retry-hint gate
    // then judges that branch on its own hint, and an exempt comment for the refusal cannot
    // mask a missing retry_after_ms.
    auto refuse_input = [&](const std::string& message) { refuse_params(ctx, message); };
    auto read = ctx.deps->crypto_library_summary_fn(*parsed, gate.scope);
    if (!read) {
        if (read.error().kind == CryptoReadError::Kind::kInvalid) {
            refuse_input(read.error().message);
            return;
        }
        mcp_row(ctx, "failure",
                cl::audit_detail_degraded("", read.error().cause, gate.scope.has_value()) +
                    " target=" + target);
        if (read.error().unavailable_until_restart) { // the pool is too small for this read
            answer(ctx, ctx.a4_error(kInternalError, read.error().message, std::string(kCryptoPoolTooSmallRemedy), -1, {}, true)); // retry-hint-exempt: pool too small, lasts until a restart with a larger --postgres-pool-size
            return;
        }
        answer(ctx, ctx.a4_error(kInternalError,
                                 std::string(cl::degraded_message(read.error().cause)),
                                 "retry the request",
                                 /*retry_after_ms=*/kMcpStoreFaultRetryMs, {}, true));
        return;
    }
    // Same key set as the REST/page rows; the MCP path mints no cid, and the tool name is the
    // audit target so the filters ride in the detail.
    const bool audit_ok =
        mcp_row(ctx, "success",
                cl::audit_detail("", parsed->family.value_or("all"), read->families.size(),
                                 read->names_from_catalogue, false, gate.scope.has_value()) +
                    " target=" + target);
    auto payload = cl::summary_json(*read);
    if (!audit_ok)
        payload["audit_persisted"] = false;
    answer(ctx, success_response(ctx.id, ctx.tool_result(cl::dump_safe(payload),
                                                         kObjectOutputSchema)));
}

// ── list_crypto_library_devices ───────────────────────────────────────────────────────────
void handle_list_crypto_library_devices(const ToolCallContext& ctx) {
    namespace cl = crypto_library;
    if (ctx.deps == nullptr || !ctx.deps->fleet_read_fn || !ctx.deps->audit_fn) {
        answer_unwired(ctx, "service unavailable", "crypto provider unwired", {},
                       "list_crypto_library_devices: fleet_read_fn or audit_fn unwired - "
                       "misconfigured call site; failing closed");
        return;
    }
    auto gate = ctx.deps->fleet_read_fn(ctx.req, ctx.res, "Inventory", "Read");
    if (!gate.admitted)
        return; // gate already wrote the A4 error body + status
    if (const auto bad = cl::strict_devices_args_error(ctx.args)) {
        refuse_params(ctx, *bad);
        return;
    }
    if (!ctx.deps->crypto_library_devices_fn) {
        answer_unwired(ctx, "Crypto library data unavailable", "crypto library provider unwired");
        return;
    }
    const auto parsed = cl::parse_devices_params(
        catalogue_params(ctx.args, {"family", "version", "ecosystem", "cursor", "limit"}));
    if (!parsed) {
        refuse_params(ctx, parsed.error());
        return;
    }
    const std::string target = cl::audit_target(*parsed);
    const bool continuation = !parsed->cursor.empty();
    // The seam's caller-input refusal (a bad cursor) is answered through this helper so the
    // `if (!read)` block below holds ONLY the retryable store-fault answer: the retry-hint gate
    // then judges that branch on its own hint, and an exempt comment for the refusal cannot
    // mask a missing retry_after_ms.
    auto refuse_input = [&](const std::string& message) { refuse_params(ctx, message); };
    auto read = ctx.deps->crypto_library_devices_fn(*parsed, gate.scope);
    if (!read) {
        if (read.error().kind == CryptoReadError::Kind::kInvalid) {
            refuse_input(read.error().message);
            return;
        }
        mcp_row(ctx, "failure",
                cl::audit_detail_degraded("", read.error().cause, gate.scope.has_value()) +
                    " target=" + target);
        if (read.error().unavailable_until_restart) { // the pool is too small for this read
            answer(ctx, ctx.a4_error(kInternalError, read.error().message, std::string(kCryptoPoolTooSmallRemedy), -1, {}, true)); // retry-hint-exempt: pool too small, lasts until a restart with a larger --postgres-pool-size
            return;
        }
        answer(ctx, ctx.a4_error(kInternalError,
                                 std::string(cl::degraded_message(read.error().cause)),
                                 "retry the request",
                                 /*retry_after_ms=*/kMcpStoreFaultRetryMs, {}, true));
        return;
    }
    const bool audit_ok =
        mcp_row(ctx, "success",
                cl::audit_detail("", parsed->family, read->devices.size(),
                                 read->names_from_catalogue, continuation,
                                 gate.scope.has_value()) +
                    " target=" + target);
    auto payload = cl::devices_json(*read);
    if (!audit_ok)
        payload["audit_persisted"] = false;
    answer(ctx, success_response(ctx.id, ctx.tool_result(cl::dump_safe(payload),
                                                         kObjectOutputSchema)));
}

// ── export_crypto_cbom (CycloneDX 1.7 export of the /crypto summary) ──────────────────────
// Same gate (fleet_read_fn, Inventory:Read), seam and admission bound as get_crypto_libraries;
// the BOM is shaped by crypto_cbom.hpp, the REST twin's shaper. Own handler (not folded into
// get_crypto_libraries) so the retry-hint CI gate inspects it.
void handle_export_crypto_cbom(const ToolCallContext& ctx) {
    namespace cl = crypto_library;
    if (ctx.deps == nullptr || !ctx.deps->fleet_read_fn || !ctx.deps->audit_fn) {
        answer_unwired(ctx, "service unavailable", "crypto provider unwired", {},
                       "export_crypto_cbom: fleet_read_fn or audit_fn unwired - misconfigured call site; "
                       "failing closed");
        return;
    }
    auto gate = ctx.deps->fleet_read_fn(ctx.req, ctx.res, "Inventory", "Read");
    if (!gate.admitted)
        return; // gate already wrote the A4 error body + status
    // STRICT: a non-object `arguments` is refused by the dispatch chain's central check before
    // this handler runs; this re-check is defence in depth, and it is the one that refuses an
    // unknown key (anything other than family / ecosystem), before any parse or read.
    if (const auto bad = crypto_cbom::strict_cbom_args_error(ctx.args)) {
        refuse_params(ctx, *bad);
        return;
    }
    if (!ctx.deps->crypto_library_summary_fn) {
        answer_unwired(ctx, "Crypto library data unavailable", "crypto library provider unwired");
        return;
    }
    const auto parsed =
        cl::parse_summary_params(catalogue_params(ctx.args, {"family", "ecosystem"}));
    if (!parsed) {
        refuse_params(ctx, parsed.error());
        return;
    }
    // No BOM without a unique serial. Minted BEFORE the store read so a CSPRNG failure costs no
    // read slot and no scan; no audit row on this path (no inventory read has happened, so
    // there is nothing to account for).
    const auto identity = crypto_cbom::make_identity(yuzu::kVersionString);
    if (!identity) {
        spdlog::error("export_crypto_cbom: CSPRNG failure minting the BOM serial number");
        answer(ctx, ctx.a4_error(kInternalError, "service unavailable", "retry the request",
                                 /*retry_after_ms=*/kMcpStoreFaultRetryMs, {}, true));
        return;
    }
    const std::string target = cl::audit_target(*parsed);
    // The seam's caller-input refusal is answered through this helper so the `if (!read)` block
    // below holds ONLY the retryable store-fault answer (same pattern as get_crypto_libraries):
    // the retry-hint gate judges that branch on its own hint, and an exempt comment for the
    // refusal cannot mask a missing one.
    auto refuse_input = [&](const std::string& message) { refuse_params(ctx, message); };
    const auto read = ctx.deps->crypto_library_summary_fn(*parsed, gate.scope);
    if (!read) {
        if (read.error().kind == CryptoReadError::Kind::kInvalid) {
            refuse_input(read.error().message);
            return;
        }
        mcp_row(ctx, "failure",
                cl::audit_detail_degraded("", read.error().cause, gate.scope.has_value()) +
                    " target=" + target);
        if (read.error().unavailable_until_restart) { // the pool is too small for this read
            answer(ctx, ctx.a4_error(kInternalError, read.error().message, std::string(kCryptoPoolTooSmallRemedy), -1, {}, true)); // retry-hint-exempt: pool too small, lasts until a restart with a larger --postgres-pool-size
            return;
        }
        answer(ctx, ctx.a4_error(kInternalError,
                                 std::string(cl::degraded_message(read.error().cause)),
                                 "retry the request",
                                 /*retry_after_ms=*/kMcpStoreFaultRetryMs, {}, true));
        return;
    }
    const auto bom_options =
        crypto_cbom::CbomOptions{.filters = *parsed, .confined = gate.scope.has_value()};
    auto bom = crypto_cbom::cbom_json(*read, *identity, bom_options);
    const std::size_t components = bom.at("components").size();
    const bool audit_ok =
        mcp_row(ctx, "success",
                cl::audit_detail("", parsed->family.value_or("all"), read->families.size(),
                                 read->names_from_catalogue, false, gate.scope.has_value()) +
                    crypto_cbom::audit_evidence(*identity, *parsed, components) +
                    " target=" + target);
    if (!audit_ok)
        crypto_cbom::mark_audit_not_persisted(bom);
    nlohmann::json payload{{"bom", cl::dump_safe(bom)},
                           {"content_type", std::string(crypto_cbom::kContentType)},
                           {"components", components},
                           {"result_truncated", read->result_truncated}};
    if (!audit_ok)
        payload["audit_persisted"] = false;
    answer(ctx, success_response(ctx.id, ctx.tool_result(cl::dump_safe(payload),
                                                         kObjectOutputSchema)));
}

// ── /crypto dashboard widget twins (ADR-0070 D13, R2) ─────────────────────────────────────
// Shaped by crypto_widget_catalogue.hpp and read through the SAME CryptoApi seam instance as REST
// /api/v1/crypto/{widgets,dashboard/layout,ca/stats}. The catalogue and the layout are the
// caller's OWN (session username), tier-gated by the generic C8 check (Infrastructure Read/Write,
// the result-set precedent); the Yuzu-issued counts gate on fleet_read_fn Inventory:Read and are
// WITHHELD from a confined caller (R2). ONE handler per tool (the retry-hint gate scans each
// tool's own body).

void handle_list_crypto_widgets(const ToolCallContext& ctx) {
    namespace cw = crypto_widgets;
    // ctx.args is a JSON object here (the dispatch chain's central check refuses anything else
    // first), so "takes no arguments" is an emptiness test.
    if (!ctx.args.empty()) {
        refuse_params(ctx, "list_crypto_widgets takes no arguments");
        return;
    }
    if (ctx.deps == nullptr || !ctx.deps->crypto_access_fn) {
        answer_unwired(ctx, "service unavailable", "crypto access provider unwired", {},
                       "list_crypto_widgets: crypto_access_fn unwired - misconfigured call site; "
                       "failing closed");
        return;
    }
    cw::AccessMemo access([&](cw::WidgetGate g, std::string_view s, std::string_view o) {
        return ctx.deps->crypto_access_fn(ctx.req, g, std::string(s), std::string(o));
    });
    auto payload = cw::widgets_json(access);
    mcp_row(ctx, "success");
    answer(ctx, success_response(ctx.id, ctx.tool_result(crypto_library::dump_safe(payload),
                                                         kObjectOutputSchema)));
}

void handle_get_crypto_dashboard_layout(const ToolCallContext& ctx) {
    namespace cw = crypto_widgets;
    if (!ctx.args.empty()) {
        refuse_params(ctx, "get_crypto_dashboard_layout takes no arguments");
        return;
    }
    if (ctx.deps == nullptr || !ctx.deps->crypto_dashboard_layout_fn) {
        answer_unwired(ctx, "Crypto dashboard layout unavailable", "crypto layout provider unwired");
        return;
    }
    // The layout is keyed on the caller's session username. The registry path carries no
    // session, so it is re-resolved from the request. A failed resolution is rare but possible (the
    // credential is revoked or expires, or the token store errors, between the dispatch chain's
    // authentication and this second walk) and fails closed rather than reading the wrong layout;
    // the answer is a non-retryable "service unavailable".
    const auto user = ctx.deps->username_fn ? ctx.deps->username_fn(ctx.req) : std::nullopt;
    if (!user || user->empty()) { // an empty name is refused here, not by the store after a row
        answer_unwired(ctx, "service unavailable", "caller identity unresolved", {},
                       "get_crypto_dashboard_layout: the caller's username could not be resolved "
                       "- failing closed");
        return;
    }
    // Non-retryable answers (caller input, a corrupt stored layout) go through this helper so
    // the `if (!read)` block below holds ONLY the retryable store fault.
    auto refuse = [&](const CryptoReadError& e) {
        if (e.kind == CryptoReadError::Kind::kCorrupt)
            answer(ctx, ctx.a4_error(kInternalError, e.message, "call set_crypto_dashboard_layout with expected_version=" + std::to_string(e.version) + " to replace it", -1, {}, true)); // retry-hint-exempt: stored-state defect, retrying reads it again
        else
            answer_invalid_params(ctx, e.message);
    };
    auto read = ctx.deps->crypto_dashboard_layout_fn(*user);
    if (!read) {
        if (read.error().kind != CryptoReadError::Kind::kDegraded) {
            mcp_row(ctx, "failure", layout_failure_tag(read.error()));
            refuse(read.error());
            return;
        }
        if (read.error().unavailable_until_restart) {
            mcp_row(ctx, "failure", read.error().message);
            answer(ctx, ctx.a4_error(kInternalError, read.error().message, "the layout store did not open at server start; the default layout applies until the server is restarted with the store fixed", -1, {}, true)); // retry-hint-exempt: lasts until a restart, a retry fails identically
            return;
        }
        mcp_row(ctx, "failure", read.error().message);
        answer(ctx, ctx.a4_error(kInternalError, read.error().message, "retry the request",
                                 /*retry_after_ms=*/kMcpStoreFaultRetryMs, {}, true));
        return;
    }
    mcp_row(ctx, "success");
    answer(ctx, success_response(ctx.id, ctx.tool_result(crypto_library::dump_safe(
                                                             cw::layout_json(*read)),
                                                         kObjectOutputSchema)));
}

void handle_set_crypto_dashboard_layout(const ToolCallContext& ctx) {
    namespace cw = crypto_widgets;
    if (const auto bad = cw::strict_layout_args_error(ctx.args)) {
        refuse_params(ctx, *bad);
        return;
    }
    const auto lr = cw::layout_request_from_args(ctx.args);
    if (const auto bad = cw::layout_error(lr.widgets)) {
        refuse_params(ctx, *bad);
        return;
    }
    if (ctx.deps == nullptr || !ctx.deps->crypto_set_dashboard_layout_fn) {
        answer_unwired(ctx, "Crypto dashboard layout unavailable", "crypto layout provider unwired");
        return;
    }
    // "No audit row, no mutation" needs a sink to write the row to. try_persist_audit would call
    // an empty sink "persisted", so an unwired one is refused here instead (the legacy branch
    // threw on an empty sink, before the write). Production always wires it.
    if (!ctx.deps->audit_fn) {
        answer_unwired(ctx, "service unavailable", "audit sink unwired; layout not changed", {},
                       "set_crypto_dashboard_layout: audit_fn unwired - misconfigured call site; "
                       "failing closed, layout not changed");
        return;
    }
    const auto resolved = ctx.deps->username_fn ? ctx.deps->username_fn(ctx.req) : std::nullopt;
    if (!resolved || resolved->empty()) { // refused BEFORE the "attempted" row: it would name no one
        // A refused destructive call leaves a row (answer_unwired writes it), not only a log line.
        answer_unwired(ctx, "service unavailable", "caller identity unresolved; layout not changed", {},
                       "set_crypto_dashboard_layout: the caller's username could not be resolved "
                       "- failing closed, layout not changed");
        return;
    }
    const std::string& user = *resolved;
    const std::string detail_base = cw::audit_detail_layout("", lr.widgets.size(), lr.expected_version);
    // "No audit row, no mutation" (ADR-0033 section 9). Stricter than the REST twin on a
    // misconfiguration: REST treats an empty audit sink as audit-off and writes without an
    // "attempted" row, while the check above refuses.
    if (!domain_row(ctx, "crypto.dashboard.layout.update", "attempted", "CryptoDashboard", user,
                    detail_base)) {
        mcp_row(ctx, "failure", "audit unavailable; layout not changed");
        answer(ctx, ctx.a4_error(kInternalError,
                                 "audit log unavailable; the change was not made",
                                 "retry once the audit log is available",
                                 /*retry_after_ms=*/kMcpStoreFaultRetryMs, {}, true));
        return;
    }
    // Non-retryable answers (caller input, a stale expected_version, a corrupt stored layout) go
    // through this helper so the `if (!wrote)` block below holds ONLY the retryable answers
    // (store fault, unknown commit outcome).
    auto refuse = [&](const CryptoReadError& e) {
        if (e.kind == CryptoReadError::Kind::kConflict)
            answer(ctx, ctx.a4_error(kInvalidParams, e.message, "read the layout with get_crypto_dashboard_layout (stored version " + std::to_string(e.version) + ") and save again with that expected_version", -1, {}, true)); // retry-hint-exempt: stale expected_version, resending it fails identically
        else if (e.kind == CryptoReadError::Kind::kCorrupt)
            answer(ctx, ctx.a4_error(kInternalError, e.message, "save again with expected_version=" + std::to_string(e.version) + " to replace it", -1, {}, true)); // retry-hint-exempt: stored-state defect, the same call fails identically
        else
            answer_invalid_params(ctx, e.message);
    };
    auto wrote = ctx.deps->crypto_set_dashboard_layout_fn(user, lr.widgets, lr.expected_version);
    if (!wrote) {
        (void)domain_row(ctx, "crypto.dashboard.layout.update", "failure", "CryptoDashboard", user,
                         detail_base + " " + layout_failure_tag(wrote.error()));
        mcp_row(ctx, "failure", layout_failure_tag(wrote.error()));
        if (wrote.error().kind != CryptoReadError::Kind::kDegraded &&
            wrote.error().kind != CryptoReadError::Kind::kOutcomeUnknown) {
            refuse(wrote.error());
            return;
        }
        if (wrote.error().unavailable_until_restart) {
            answer(ctx, ctx.a4_error(kInternalError, wrote.error().message, "the layout store did not open at server start; layouts cannot be saved until the server is restarted with the store fixed", -1, {}, true)); // retry-hint-exempt: lasts until a restart, a retry fails identically
            return;
        }
        answer(ctx, ctx.a4_error(kInternalError, wrote.error().message,
                                 wrote.error().kind == CryptoReadError::Kind::kOutcomeUnknown
                                     ? "read the layout with get_crypto_dashboard_layout to see whether it was saved"
                                     : "retry the request",
                                 /*retry_after_ms=*/kMcpStoreFaultRetryMs, {}, true));
        return;
    }
    const bool audit_ok =
        domain_row(ctx, "crypto.dashboard.layout.update", "success", "CryptoDashboard", user,
                   cw::audit_detail_layout("", wrote->widgets.size(), lr.expected_version) +
                       " version=" + std::to_string(wrote->version));
    mcp_row(ctx, "success");
    auto payload = cw::layout_json(*wrote);
    if (!audit_ok)
        payload["audit_persisted"] = false;
    answer(ctx, success_response(ctx.id, ctx.tool_result(crypto_library::dump_safe(payload),
                                                         kObjectOutputSchema)));
}

void handle_get_crypto_ca_stats(const ToolCallContext& ctx) {
    namespace cw = crypto_widgets;
    if (ctx.deps == nullptr || !ctx.deps->fleet_read_fn || !ctx.deps->audit_fn) {
        answer_unwired(ctx, "service unavailable", "crypto provider unwired", {},
                       "get_crypto_ca_stats: fleet_read_fn or audit_fn unwired - misconfigured call site; "
                       "failing closed");
        return;
    }
    auto gate = ctx.deps->fleet_read_fn(ctx.req, ctx.res, "Inventory", "Read");
    if (!gate.admitted)
        return; // gate already wrote the A4 error body + status
    if (gate.scope.has_value()) {
        // ADR-0070 R2: a confined view never gets a fleet-wide count, nor a narrowed one. No
        // permission named: none would admit the caller.
        (void)domain_row(ctx, "crypto.ca.stats.view", "denied", "Inventory", "yuzu_ca",
                         cw::audit_detail_ca_withheld("", cw::Access::kConfined));
        mcp_row(ctx, "denied", "withheld=confined");
        answer(ctx, ctx.a4_error(kPermissionDenied, cw::kConfinedWithheldMessage, {}, -1, {}, true)); // retry-hint-exempt: authorization outcome, retrying cannot change it
        return;
    }
    if (!ctx.args.empty()) {
        refuse_params(ctx, "get_crypto_ca_stats takes no arguments");
        return;
    }
    if (!ctx.deps->crypto_ca_stats_fn) {
        answer_unwired(ctx, "Yuzu-issued certificate data unavailable",
                       "crypto ca stats provider unwired");
        return;
    }
    auto read = ctx.deps->crypto_ca_stats_fn(std::nullopt);
    if (!read) {
        (void)domain_row(ctx, "crypto.ca.stats.view", "failure", "Inventory", "yuzu_ca",
                         cw::audit_detail_ca_degraded("", std::nullopt, read.error().cause));
        mcp_row(ctx, "failure",
                cw::audit_detail_ca_degraded("", std::nullopt, read.error().cause));
        if (read.error().unavailable_until_restart) { // the pool is too small for this read
            answer(ctx, ctx.a4_error(kInternalError, read.error().message, std::string(kCryptoPoolTooSmallRemedy), -1, {}, true)); // retry-hint-exempt: pool too small, lasts until a restart with a larger --postgres-pool-size
            return;
        }
        answer(ctx, ctx.a4_error(kInternalError, read.error().message, "retry the request",
                                 /*retry_after_ms=*/kMcpStoreFaultRetryMs, {}, true));
        return;
    }
    const bool audit_ok = domain_row(ctx, "crypto.ca.stats.view", "success", "Inventory",
                                     "yuzu_ca", cw::audit_detail_stats("", read->as_of));
    mcp_row(ctx, "success", cw::audit_detail_stats("", read->as_of));
    auto payload = cw::ca_stats_json(*read);
    if (!audit_ok)
        payload["audit_persisted"] = false;
    answer(ctx, success_response(ctx.id, ctx.tool_result(crypto_library::dump_safe(payload),
                                                         kObjectOutputSchema)));
}

// Positional initialisation only (no designated initialisers): the lexical CI gates
// (check-api-parity.py, check-mcp-retry-hints.py) read this slice. The schema text is the legacy
// kTools[] text, moved verbatim; the six ReadOnly descriptions gain a closing "Read-only." sentence,
// which the registry A5 floor (test_mcp_dispatch_coverage.cpp, [a5]) requires and the legacy
// kTools[] rows were not held to.
constexpr ToolRecord kToolRecords[] = {
    {"get_crypto_libraries",
     "Fleet view of which cryptographic libraries are installed: one row per library family "
     "(OpenSSL, GnuTLS, NSS, Mbed TLS, wolfSSL, libsodium, Bouncy Castle and others), each with "
     "the number of DISTINCT devices carrying any package of the family and a per-(version, "
     "ecosystem) breakdown with the matching package names. Use it to answer 'where is library X "
     "installed and at which versions'; chain it with list_crypto_library_devices to name the "
     "devices behind a family or one version bucket. Evidence is the daily-synced "
     "installed-software inventory matched by package NAME against a curated table "
     "(table_version says which mapping answered; names_source says where the package NAMES "
     "came from - 'catalogue' (the hourly software catalogue, fresh: a name first reported "
     "after names_as_of appears after the next refresh) or 'live' (read from the inventory at "
     "call time because the catalogue is not built, is stale or was refreshed over zero "
     "titles; names_as_of null); counts and versions for listed names are live either "
     "way). It reports presence and versions only and "
     "never judges a library or version: interpreting a version is the caller's job. Families "
     "with no matching device are omitted, and an empty families list means 'no matching package "
     "rows in the caller's visible inventory' - NOT proof the library is absent: statically "
     "linked, vendored and OS-bundled copies are invisible here, and Windows installer builds of "
     "OpenSSL are not matched. coverage gives the denominator: "
     "devices_reporting_inventory (visible devices with an installed-software report) and "
     "devices_with_crypto_library (distinct devices matching any family). versions_truncated / "
     "result_truncated true mean version rows were capped, never that devices are missing from "
     "the counts; when the 2,000-row store ceiling fires (result_truncated) every family is "
     "flagged versions_truncated, because which families lost rows is not known. Each version "
     "bucket lists at most 8 package names; package_names_truncated is true when it has more. "
     "Requires Inventory:Read; a management-group-confined caller sees only its visible devices "
     "(counts, coverage and versions are all computed over that scope). A service-scoped token "
     "is refused (403) while RBAC enforcement is off, the default; with RBAC enforcement on it "
     "is admitted within the ITServiceOwner ceiling and sees only the devices tagged with its IT "
     "service. Input is strict: a non-object arguments value, an unknown family, an ecosystem "
     "outside the published set, a wrong JSON type or an over-long string is rejected (the REST "
     "twin clamps). A degraded inventory store, or crypto read capacity in "
     "use, is a retryable error, never an "
     "empty result. Package names are cut to 256 bytes (a cut name ends in an ellipsis) and the "
     "whole payload is byte-budgeted: a cut version list sets versions_truncated and "
     "result_truncated. ecosystem is matched EXACTLY (empty string = rows with no ecosystem; "
     "omit for any). Audited as mcp.get_crypto_libraries. Mirrors GET /api/v1/crypto/libraries. Read-only.",
     R"j({"type":"object","properties":{)j"
     R"j("family":{"type":"string","enum":["openssl","libressl","boringssl","gnutls","nss","mbedtls","wolfssl","libgcrypt","libsodium","nettle","botan","bouncycastle"],"description":"Restrict to one library family id; omit for every family"},)j"
     R"j("ecosystem":{"type":"string","maxLength":1024,"enum":["@@ECOSYSTEM_ENUM_OR_EMPTY@@"],"description":"Exact package ecosystem filter, one of the software catalogue's published ecosystems; empty string selects rows that carry no ecosystem; omit for any"})j"
     R"j(}})j",
     R"j({"type":"object","properties":{)j"
     R"j("table_version":{"type":"integer","description":"Version of the curated package-name table that produced this answer"},)j"
     R"j("names_source":{"type":"string","enum":["catalogue","live"],"description":"Where the package names came from: the fresh hourly catalogue, or a live read of the inventory (catalogue not built, stale or refreshed over zero titles)"},)j"
     R"j("names_as_of":{"type":["integer","null"],"description":"Refresh time (epoch seconds) of the catalogue when names_source is catalogue; null when live. Counts and versions for listed names are live either way"},)j"
     R"j("families":{"type":"array","items":{"type":"object","properties":{"id":{"type":"string"},"display":{"type":"string"},"device_count":{"type":"integer"},"versions":{"type":"array","items":{"type":"object","properties":{"version":{"type":"string"},"ecosystem":{"type":"string"},"device_count":{"type":"integer"},"package_names":{"type":"array","items":{"type":"string"}},"package_names_truncated":{"type":"boolean","description":"True when the bucket has more matching package names than the 8 listed"}},"required":["version","ecosystem","device_count","package_names","package_names_truncated"]}},"versions_truncated":{"type":"boolean","description":"True when this family's version list is cut (per-family cap of 50, the byte budget, or the 2,000-row store ceiling, which flags every family)"}},"required":["id","display","device_count","versions","versions_truncated"]}},)j"
     R"j("coverage":{"type":"object","properties":{"devices_reporting_inventory":{"type":"integer"},"devices_with_crypto_library":{"type":"integer"}},"required":["devices_reporting_inventory","devices_with_crypto_library"]},)j"
     R"j("result_truncated":{"type":"boolean"},)j"
     R"j("audit_persisted":{"type":"boolean","description":"Present and false only when the access audit row failed to persist"})j"
     R"j(},"required":["table_version","names_source","names_as_of","families","coverage","result_truncated"]})j",
     "Inventory", "Read", ServiceScopeClass::confined, ToolEffect::ReadOnly, true,
     "Get installed crypto libraries", &handle_get_crypto_libraries},

    {"list_crypto_library_devices",
     "List the devices (and the matching package rows) behind one cryptographic library family, "
     "optionally narrowed to one exact version and ecosystem - the drill-down after "
     "get_crypto_libraries. Each row carries agent_id, hostname (null when the registry does not "
     "know the device), package_name, version, release, ecosystem and kind. A device with several "
     "matching packages appears once per package. Ordered by agent_id, package name; page with "
     "next_cursor (non-null when more rows exist) passed back as cursor: a cursor reused with a "
     "different family/version/ecosystem, one issued under a different table_version, a "
     "malformed one, or a page whose cursor was issued on live package names when the next page "
     "finds the shared catalogue in use (names_source live to catalogue; this recurs if the "
     "catalogue goes stale and recovers mid-walk), is rejected and the walk must restart "
     "without a cursor. A newer catalogue or a switch to live continues; a name new in the "
     "newer source is listed for devices after the cursor, and its rows on devices already "
     "passed are missed until you restart. version and ecosystem are matched "
     "EXACTLY; pass an empty string for the rows that carry none, omit either for every value. An empty devices list means 'no matching package rows "
     "in the caller's visible inventory' - NOT proof the library is absent: statically linked, "
     "vendored and OS-bundled copies are invisible here. Presence and versions only; nothing is "
     "judged. Requires Inventory:Read; a management-group-confined caller sees only its visible "
     "devices. A service-scoped token is refused (403) while RBAC enforcement is off, the "
     "default; with RBAC enforcement on it is admitted within the ITServiceOwner ceiling and "
     "sees only the devices tagged with its IT service. Input is "
     "strict: a non-object arguments value, an unknown family, an ecosystem outside the "
     "published set, a wrong JSON type, an over-long string or a limit outside 1..1000 is "
     "rejected rather than clamped. A degraded "
     "inventory store, or crypto read capacity in use, is a retryable error, never an empty result. Every page served is audited "
     "as mcp.list_crypto_library_devices (continuation pages tagged page=continuation). Mirrors "
     "GET /api/v1/crypto/libraries/devices. Read-only.",
     R"j({"type":"object","properties":{)j"
     R"j("family":{"type":"string","enum":["openssl","libressl","boringssl","gnutls","nss","mbedtls","wolfssl","libgcrypt","libsodium","nettle","botan","bouncycastle"],"description":"Library family id (from get_crypto_libraries)"},)j"
     R"j("version":{"type":"string","maxLength":1024,"description":"Exact version bucket; empty string selects rows with no version; omit for every version"},)j"
     R"j("ecosystem":{"type":"string","maxLength":1024,"enum":["@@ECOSYSTEM_ENUM_OR_EMPTY@@"],"description":"Exact package ecosystem filter, one of the software catalogue's published ecosystems; empty string selects rows that carry no ecosystem; omit for any"},)j"
     R"j("cursor":{"type":"string","maxLength":2048,"description":"Opaque next_cursor from the previous page; bound to the family/version/ecosystem filter and the table_version; refused if the previous page was read on live names and the catalogue is now in use; restart without a cursor"},)j"
     R"j("limit":{"type":"integer","minimum":1,"maximum":1000,"default":100,"description":"Page size"})j"
     R"j(},"required":["family"]})j",
     R"j({"type":"object","properties":{)j"
     R"j("table_version":{"type":"integer","description":"Version of the curated package-name table that produced this page; a cursor is bound to it"},)j"
     R"j("names_source":{"type":"string","enum":["catalogue","live"],"description":"Where the package names came from: the fresh hourly catalogue, or a live read of the inventory (catalogue not built, stale or refreshed over zero titles)"},)j"
     R"j("names_as_of":{"type":["integer","null"],"description":"Refresh time (epoch seconds) of the catalogue when names_source is catalogue; null when live. Counts and versions for listed names are live either way"},)j"
     R"j("family":{"type":"string"},"version":{"type":["string","null"]},"ecosystem":{"type":["string","null"],"description":"The exact-ecosystem filter echoed; null when absent"},)j"
     R"j("devices":{"type":"array","items":{"type":"object","properties":{"agent_id":{"type":"string"},"hostname":{"type":["string","null"]},"package_name":{"type":"string"},"version":{"type":"string"},"release":{"type":"string"},"ecosystem":{"type":"string"},"kind":{"type":"string"}},"required":["agent_id","hostname","package_name","version","release","ecosystem","kind"]}},)j"
     R"j("next_cursor":{"type":["string","null"]},"count":{"type":"integer"},)j"
     R"j("audit_persisted":{"type":"boolean","description":"Present and false only when the access audit row failed to persist"})j"
     R"j(},"required":["table_version","names_source","names_as_of","family","version","ecosystem","devices","next_cursor","count"]})j",
     "Inventory", "Read", ServiceScopeClass::confined, ToolEffect::ReadOnly, true,
     "List devices carrying a crypto library", &handle_list_crypto_library_devices},

    {"export_crypto_cbom",
     "A CycloneDX 1.7 inventory of the fleet's cryptographic LIBRARY packages (library "
     "components only: no algorithms, certificates, keys or protocols yet), exported as a CBOM "
     "(JSON): the same data and the same Inventory:Read gate as get_crypto_libraries, re-shaped "
     "into a standard bill of materials a CBOM/SBOM tool can ingest. A large fleet can produce a "
     "multi-MiB result (about 2.3 MiB worst case); prefer REST GET /api/v1/crypto/cbom for a "
     "full export. The BOM is returned as a JSON string in "
     "the 'bom' field (media type application/vnd.cyclonedx+json; version=1.7). One component "
     "per (family, version, ecosystem) bucket, always type 'library' (an installed package "
     "matched by NAME against a curated table), never 'cryptographic-asset': the export carries "
     "NO cryptoProperties, strength, quantum-security-level or good/bad field - interpreting a "
     "library or version is the consumer's job. Yuzu-specific facts ride in 'yuzu:crypto:*' "
     "properties: metadata carries table_version, names_source, names_as_of (absent when names "
     "are live), result_truncated, truncated_families, devices_reporting, the filters "
     "applied and scope (fleet, or confined for a confined caller); the document carries "
     "compositions aggregate=incomplete because a name match cannot see statically linked, "
     "vendored or OS-bundled copies; each component carries family_id, ecosystem, device_count and package_name "
     "entries. TRUNCATION IS NEVER SILENT: a family whose version list was cut (50 buckets per "
     "family, 256 KiB byte budget, store row cap) sets yuzu:crypto:versions_truncated=true on "
     "its components and is listed in yuzu:crypto:truncated_families (a family with every bucket "
     "dropped has no component and appears only there); a truncated BOM is incomplete, not "
     "wrong. An empty components list means 'no matching package rows in the caller's visible "
     "inventory' - NOT proof the library is absent (statically linked, vendored and OS-bundled "
     "copies are invisible). Each call mints a fresh random serialNumber and timestamp. "
     "Requires Inventory:Read; a management-group-confined or service-scoped caller exports "
     "only its visible devices. Input is strict: arguments must be a JSON object, only family "
     "and ecosystem are accepted; an unknown family, an ecosystem outside the published set, a "
     "wrong JSON type or an over-long string is rejected rather than clamped. A degraded "
     "inventory store, or crypto read capacity in use, is a retryable error, never an empty "
     "BOM. Audited as mcp.export_crypto_cbom. Mirrors GET /api/v1/crypto/cbom. Read-only.",
     R"j({"type":"object","additionalProperties":false,"properties":{)j"
     R"j("family":{"type":"string","enum":["openssl","libressl","boringssl","gnutls","nss","mbedtls","wolfssl","libgcrypt","libsodium","nettle","botan","bouncycastle"],"description":"Restrict the BOM to one library family id; omit for every family"},)j"
     R"j("ecosystem":{"type":"string","maxLength":1024,"enum":["@@ECOSYSTEM_ENUM_OR_EMPTY@@"],"description":"Exact package ecosystem filter, one of the software catalogue's published ecosystems; empty string selects rows that carry no ecosystem; omit for any"})j"
     R"j(}})j",
     R"j({"type":"object","properties":{)j"
     R"j("bom":{"type":"string","description":"The CycloneDX 1.7 JSON document, serialised (media type application/vnd.cyclonedx+json; version=1.7)"},)j"
     R"j("content_type":{"type":"string","enum":["application/vnd.cyclonedx+json; version=1.7"]},)j"
     R"j("components":{"type":"integer","description":"Number of components in the BOM"},)j"
     R"j("result_truncated":{"type":"boolean","description":"True when the store row cap or response byte budget cut the summary; per-family version cuts are flagged in yuzu:crypto:truncated_families and each component's versions_truncated"},)j"
     R"j("audit_persisted":{"type":"boolean","description":"Present and false only when the access audit row failed to persist"})j"
     R"j(},"required":["bom","content_type","components","result_truncated"]})j",
     "Inventory", "Read", ServiceScopeClass::confined, ToolEffect::ReadOnly, true,
     "Export crypto libraries as a CycloneDX CBOM", &handle_export_crypto_cbom},

    {"list_crypto_widgets",
     "List the /crypto dashboard widget catalogue: every widget's id, title, kind (number, bar, "
     "line or table), group ('Crypto libraries' or 'Yuzu-issued certificates'), gate class, the "
     "permission its data needs (securable + operation), its criterion in words (exactly what the "
     "number counts), where a click drills to, and available / availability - whether YOU may "
     "read it (available, not_available, confined, access_check_unavailable). Library widgets "
     "need Inventory:Read and a confined caller gets a narrowed answer; the Yuzu-issued counts "
     "need Inventory:Read and are WITHHELD from a confined caller (availability confined, never a "
     "narrowed count). Yuzu-issued widgets also carry drill_available: the certificate rows behind "
     "a count need Security:Read (list_issued_certs with kind/days/week/bucket). Facts only; the "
     "only built-in checks are the D13 named windows, each shown with its criterion. available "
     "decides what to draw only; each data tool keeps its own gate. Also returns the default "
     "layout, the window set version (window_set) and the Yuzu-issued scope note. Takes no "
     "arguments. Mirrors GET /api/v1/crypto/widgets. Read-only.",
     R"({"type":"object","properties":{}})",
     R"j({"type":"object","properties":{)j"
     R"j("window_set":{"type":"string","description":"Version of the closed window set"},"scope_note":{"type":"string"},)j"
     R"j("widgets":{"type":"array","items":)j" R"j({"type":"object","properties":{"id":{"type":"string"},"title":{"type":"string"},"kind":{"type":"string","enum":["number","bar","line","table"]},"group":{"type":"string"},"gate":{"type":"string","enum":["fleet_read","fleet_wide_only","global"]},"securable":{"type":"string"},"operation":{"type":"string"},"criterion":{"type":"string","description":"What the widget counts, in words"},"drill":{"type":"string","enum":["library_families","library_family_devices","ca_certificates","ca_week"]},"available":{"type":"boolean","description":"Whether the caller may read the widget's data (drawing only, never a grant)"},"availability":{"type":"string","enum":["available","not_available","confined","access_check_unavailable"]},"ca_kind":{"type":"string"},"days":{"type":["integer","null"]},"drill_securable":{"type":"string"},"drill_operation":{"type":"string"},"drill_available":{"type":"boolean"}},"required":["id","title","kind","group","gate","securable","operation","criterion","drill","available","availability"]})j" R"j(},)j"
     R"j("default_layout":{"type":"array","items":{"type":"string"}},"max_layout_widgets":{"type":"integer"})j"
     R"j(},"required":["window_set","widgets","default_layout","max_layout_widgets","scope_note"]})j",
     "Infrastructure", "Read", ServiceScopeClass::denied, ToolEffect::ReadOnly, true,
     "List crypto dashboard widgets", &handle_list_crypto_widgets},

    {"get_crypto_dashboard_layout",
     "Get YOUR OWN /crypto dashboard layout: the catalogue widget ids you placed, in display "
     "order, and its version (pass it as expected_version to set_crypto_dashboard_layout). Ids "
     "this server version does not know (a widget another version added) are counted in "
     "preserved_unknown - not listed, but kept on every save. is_default is true when the layout "
     "is the catalogue default (nothing saved, version 0, or a saved copy of it). Keyed by your "
     "session; there is no way to read another operator's layout. A degraded layout store is a "
     "retryable error, never the default served as if nothing were stored; a stored layout that "
     "cannot be read is a non-retryable error whose remediation names the version to overwrite. "
     "Takes no arguments. Mirrors GET /api/v1/crypto/dashboard/layout. Read-only.",
     R"({"type":"object","properties":{}})",
     R"j({"type":"object","properties":{"widgets":{"type":"array","items":{"type":"string"},"description":"Catalogue widget ids in display order"},"is_default":{"type":"boolean"},"version":{"type":"integer","description":"Stored version; 0 when nothing is stored"},"preserved_unknown":{"type":"integer","description":"Stored ids this server version does not know: kept, not listed"},"max_layout_widgets":{"type":"integer"},"audit_persisted":{"type":"boolean","description":"Present and false only when the outcome audit row failed to persist"}},"required":["widgets","is_default","version","preserved_unknown","max_layout_widgets"]})j",
     "Infrastructure", "Read", ServiceScopeClass::denied, ToolEffect::ReadOnly, true,
     "Get my crypto dashboard layout", &handle_get_crypto_dashboard_layout},

    {"set_crypto_dashboard_layout",
     "Replace YOUR OWN /crypto dashboard layout with the given widget ids, in display order "
     "(add a widget by including its id, remove one by leaving it out; an empty list is a valid, "
     "empty dashboard). It overwrites the previous layout (destructive to that layout only; no "
     "data, no permission and no other operator is touched). Every id must come from "
     "list_crypto_widgets, without repeats, at most 64. Ids another server version stored are "
     "kept after yours. Pass expected_version (the version get_crypto_dashboard_layout returned; "
     "0 = only if nothing is saved) to refuse the save when the layout changed meanwhile - a "
     "conflict is a non-retryable error: read it again, then save. Omit only for a first save: "
     "without it the save succeeds only when nothing is stored, and a stored layout is the same "
     "non-retryable conflict naming the stored version. Idempotent: the same list twice stores the same layout. Keyed by your session. "
     "Input is strict: an unknown or repeated id, more than 64 ids, a non-string id or any other "
     "argument is rejected. Audited as crypto.dashboard.layout.update (an attempted row first: if "
     "it cannot be written the layout is not changed). A degraded layout store is a retryable "
     "error; a save whose commit outcome is unknown is a retryable error that says so (read the "
     "layout to check). Mirrors PUT /api/v1/crypto/dashboard/layout.",
     R"j({"type":"object","properties":{)j"
     R"j("widgets":{"type":"array","maxItems":64,"items":{"type":"string","maxLength":64},"description":"Catalogue widget ids in display order"},)j"
     R"j("expected_version":{"type":"integer","minimum":0,"description":"The version you last read; 0 = only when nothing is saved. Omit only for a first save (a stored layout is then a conflict)"})j"
     R"j(},"required":["widgets"],"additionalProperties":false})j",
     R"j({"type":"object","properties":{"widgets":{"type":"array","items":{"type":"string"},"description":"Catalogue widget ids in display order"},"is_default":{"type":"boolean"},"version":{"type":"integer","description":"The new stored version"},"preserved_unknown":{"type":"integer"},"max_layout_widgets":{"type":"integer"},"audit_persisted":{"type":"boolean","description":"Present and false only when the outcome audit row failed to persist"}},"required":["widgets","is_default","version","preserved_unknown","max_layout_widgets"]})j",
     "Infrastructure", "Write", ServiceScopeClass::denied, ToolEffect::Destructive, true,
     "Replace my crypto dashboard layout", &handle_set_crypto_dashboard_layout},

    {"get_crypto_ca_stats",
     "Counts of certificates issued by Yuzu's OWN internal CA (the agent, server, gateway, "
     "HTTPS and code-signing certificates Yuzu minted - never the certificates on your devices), "
     "each against as_of, the database clock at read time (epoch seconds and ISO 8601). Facts "
     "only; the only built-in checks are the D13 named windows, each with its criterion: active; "
     "expiring within 3, 7, 14, 21, 30 and 60 days and expired in the last 7, 30, 60 and 90 days, "
     "status active only (a certificate is valid through its notAfter, inclusive; a revoked one "
     "counts only in the revoked windows); revoked in the last 7, 30, 60 and "
     "90 days, reported in three buckets by recorded reason - superseded, unpublished (recorded, "
     "never delivered) and other - never summed or labelled; issued in the last 7 days excluding "
     "unpublished; and issued and revoked per ISO week for the last 52 ISO weeks (UTC, Monday "
     "start; the current week is partial and flagged). Every count carries rule_id, "
     "threshold (or week), criterion, rule_set_version and as_of. Nothing is stored or "
     "graded: recompute any count from list_issued_certs with the same kind/days/week/bucket and "
     "as_of (needs Security:Read). Requires Inventory:Read; a caller whose view is confined is "
     "refused (these are fleet-wide figures), never given a narrowed count. A degraded CA store, "
     "or crypto read capacity in use, is a retryable error, never zeros. Takes no arguments. "
     "Audited as crypto.ca.stats.view. Mirrors GET /api/v1/crypto/ca/stats. Read-only.",
     R"({"type":"object","properties":{}})",
     R"j({"type":"object","properties":{)j"
     R"j("scope":{"const":"yuzu_issued"},"scope_note":{"type":"string"},"window_edge_note":{"type":"string"},"rule_set_version":{"type":"string"},"as_of":{"type":"integer","description":"Database time (epoch seconds) every window was computed against"},"as_of_iso":{"type":"string"},)j"
     R"j("active":{"type":"object","properties":{"rule_id":{"type":"string"},"criterion":{"type":"string"},"rule_set_version":{"type":"string"},"as_of":{"type":"integer"},"count":{"type":"integer"},"threshold":{"type":"integer"},"week":{"type":"string"},"bucket":{"type":"string","enum":["superseded","unpublished","other"]}},"required":["rule_id","criterion","rule_set_version","as_of","count"]},"expiring_within_days":{"type":"array","items":{"type":"object","properties":{"rule_id":{"type":"string"},"criterion":{"type":"string"},"rule_set_version":{"type":"string"},"as_of":{"type":"integer"},"count":{"type":"integer"},"threshold":{"type":"integer"},"week":{"type":"string"},"bucket":{"type":"string","enum":["superseded","unpublished","other"]}},"required":["rule_id","criterion","rule_set_version","as_of","count"]}},"expired_within_days":{"type":"array","items":{"type":"object","properties":{"rule_id":{"type":"string"},"criterion":{"type":"string"},"rule_set_version":{"type":"string"},"as_of":{"type":"integer"},"count":{"type":"integer"},"threshold":{"type":"integer"},"week":{"type":"string"},"bucket":{"type":"string","enum":["superseded","unpublished","other"]}},"required":["rule_id","criterion","rule_set_version","as_of","count"]}},"revoked_within_days":{"type":"array","items":{"type":"object","properties":{"rule_id":{"type":"string"},"criterion":{"type":"string"},"rule_set_version":{"type":"string"},"as_of":{"type":"integer"},"count":{"type":"integer"},"threshold":{"type":"integer"},"week":{"type":"string"},"bucket":{"type":"string","enum":["superseded","unpublished","other"]}},"required":["rule_id","criterion","rule_set_version","as_of","count"]},"description":"Three entries per window: buckets superseded, unpublished, other"},"issued_within_days":{"type":"object","properties":{"rule_id":{"type":"string"},"criterion":{"type":"string"},"rule_set_version":{"type":"string"},"as_of":{"type":"integer"},"count":{"type":"integer"},"threshold":{"type":"integer"},"week":{"type":"string"},"bucket":{"type":"string","enum":["superseded","unpublished","other"]}},"required":["rule_id","criterion","rule_set_version","as_of","count"]},)j"
     R"j("week_basis":{"type":"string"},"weeks":{"type":"array","items":{"type":"object","properties":{"week":{"type":"string","description":"ISO 8601 week, e.g. 2026-W40"},"week_start":{"type":"integer"},"partial":{"type":"boolean"},"issued":{"type":"object","properties":{"rule_id":{"type":"string"},"criterion":{"type":"string"},"rule_set_version":{"type":"string"},"as_of":{"type":"integer"},"count":{"type":"integer"},"threshold":{"type":"integer"},"week":{"type":"string"},"bucket":{"type":"string","enum":["superseded","unpublished","other"]}},"required":["rule_id","criterion","rule_set_version","as_of","count"]},"revoked":{"type":"array","items":{"type":"object","properties":{"rule_id":{"type":"string"},"criterion":{"type":"string"},"rule_set_version":{"type":"string"},"as_of":{"type":"integer"},"count":{"type":"integer"},"threshold":{"type":"integer"},"week":{"type":"string"},"bucket":{"type":"string","enum":["superseded","unpublished","other"]}},"required":["rule_id","criterion","rule_set_version","as_of","count"]}}},"required":["week","week_start","partial","issued","revoked"]}},)j"
     R"j("audit_persisted":{"type":"boolean","description":"Present and false only when the access audit row failed to persist"})j"
     R"j(},"required":["scope","scope_note","rule_set_version","as_of","as_of_iso","active","expiring_within_days","expired_within_days","revoked_within_days","issued_within_days","week_basis","weeks"]})j",
     "Inventory", "Read", ServiceScopeClass::denied, ToolEffect::ReadOnly, true,
     "Get Yuzu-issued certificate counts", &handle_get_crypto_ca_stats},
};

static_assert(records_well_formed(kToolRecords),
              "mcp_tools_crypto.cpp: a record is malformed (null field or handler, bad name, "
              "effect/operation mismatch) or two records share a name; see record_defect()");

} // namespace

std::span<const ToolRecord> crypto_tool_records() {
    return kToolRecords;
}

} // namespace yuzu::server::mcp
