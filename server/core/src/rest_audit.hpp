#pragma once

/// @file rest_audit.hpp
///
/// Shared "emit a behavioural-data access audit, surface a persist failure"
/// helper for the per-device / per-signal PII routes (`dex.device.view`,
/// `guardian.device.view`, `dex.signal.view`) across the REST API, the
/// dashboard fragments, and the MCP tool surface.
///
/// Factored out of the per-site copies that drifted (#1647): the original
/// fix-up of these routes happened endpoint-by-endpoint, so each surface grew
/// its own slightly-different snippet — some discarded the `AuditFn` bool
/// entirely, some set the header but lacked a `try/catch`, some failed closed
/// and some proceeded. Every behavioural-data route now routes through ONE
/// kernel here so the catch-arm log, the `Sec-Audit-Failed` header, and the
/// persist-bool contract can never diverge between surfaces again.
///
/// SOC 2 CC7.2 (audit-anomaly monitoring) + CC6.1 (access-event capture):
/// a per-person behavioural read whose audit row silently fails to persist —
/// the audit DB is locked/full, or a `bad_alloc`-class allocation throws —
/// must never look like a clean, audited read to the consumer. That is the
/// originating threat (#1623 review HIGH): a CMDB / ServiceNow integration
/// reading audited-evidence data with no `guardian.device.view` row AND no
/// out-of-band signal.
///
/// `try_persist_audit` is the channel-agnostic kernel; the per-channel
/// failure signal is layered on top:
///   * HTTP routes wrap it with `emit_behavioral_audit`, which sets the
///     `Sec-Audit-Failed: true` response header on failure. The caller then
///     picks its posture from the returned bool — HTML dashboard fragments
///     PROCEED and render (a transient audit hiccup must not blank the
///     operator's lens; the header carries the signal), REST JSON
///     integrations FAIL CLOSED (503) so a downstream CMDB never records
///     evidence-less PII as audited.
///   * MCP wraps the kernel itself (JSON-RPC has no response-header channel)
///     and surfaces the gap through its own body field.
///
/// A null / empty `audit_fn` means the deployment runs audit-off; that is NOT
/// a persistence failure, so the kernel returns `true` and sets no header —
/// the established `AuditFn` contract (callers that fail closed must keep
/// serving when audit is simply disabled).
///
/// **`result` semantics (#4858) — read this before assuming "success" means
/// "data was shown".** The bool returned by `try_persist_audit`/
/// `emit_behavioral_audit` is the PERSIST outcome (did the audit row make it
/// to durable storage) — it is orthogonal to the `result` STRING passed in as
/// an audit-row field, and it is that string's meaning which varies by site:
///   * MOST call sites — the dashboard fragments and most fail-closed REST
///     gates (`dex.device.view`, `dex.signal.view`), the MCP
///     `get_dex_device_app_perf` tool's `dex.device.app_perf.view` row, AND
///     the MCP `list_guardian_events` tool's `dex.device.view` row — audit
///     BEFORE the read with a literal `result="success"`, asserting
///     only that the request was authorised and the read was ATTEMPTED. It
///     does **not** assert data was disclosed: a subsequent store-level
///     degrade (see `yuzu_server_guardian_read_degrade_total`,
///     `yuzu_server_app_perf_read_degrade_total`, `docs/user-manual/
///     metrics.md`) can still leave the dashboard rendering a placeholder, or
///     the REST/MCP caller getting a 503/retryable error, on top of an
///     already recorded `success` audit row.
///   * Some surfaces instead audit AFTER the read and set `result` by ACTUAL
///     outcome — the Guardian REST/MCP twins (e.g. `guardian.device.view`
///     on REST/MCP, which passes `rows ? "success" : "failure"`; the
///     device-page Guardian lens fragment is a DIFFERENT posture, see below)
///     and `dex.app_perf.devices.view` record `success`/`failure` reflecting
///     whether the read itself succeeded, not merely whether it was
///     authorised and attempted.
///   * A third posture: the MCP `get_dex_device_score` tool's
///     `dex.device.view` behavioural row audits AFTER the read (`model =
///     dex_api_->device_score(...)` runs first) but records a CONSTANT
///     `"success"` regardless of `model.degraded` (the set-and-proceed
///     convention — the tool response body carries the degrade signal
///     instead of the audit row). This is NOT the same posture as
///     `get_dex_device_app_perf` above, despite both being MCP DEX
///     behavioural rows — do not assume the two share an ordering. The MCP
///     `get_dex_device_history` tool's `dex.device.view` row shares this
///     THIRD posture exactly (audits after `dex_api_->device_history(...)`
///     runs, with the same constant `"success"`) — two different MCP tools
///     emitting the same verb under the same post-read-constant-success
///     convention, not a drift between them.
///   * A fourth, surface-specific split on the SAME verb: `guardian.device.
///     view` is audited post-read-by-outcome on REST and MCP (bucket two
///     above), but the device-page Guardian lens dashboard fragment
///     (`device_lens_routes.cpp`) audits it BEFORE the read with a constant
///     `"success"` (bucket-one shape) — the same audit verb therefore
///     carries a DIFFERENT ordering/outcome convention depending on which
///     surface emitted it.
/// These postures are a known, accepted split across surfaces, not a bug in
/// any one of them — an auditor reading raw rows must not assume one meaning
/// fleet-wide, and must key off (verb, surface), not verb alone. Converging
/// them onto one posture is deferred to the WS-B2 audit-relocation step
/// (ADR-0031); this comment documents the CURRENT state, not a target one.

#include <httplib.h>
#include <spdlog/spdlog.h>

#include "web_utils.hpp" // audit_token — CWE-117 neutralisation for a hostile target_id (#4665)

#include <exception>
#include <string>
#include <type_traits>

namespace yuzu::server::detail {

/// Channel-agnostic kernel: call the access-audit hook, capturing the persist
/// result behind a `try/catch`. The realistic false-return path is already
/// logged + metric-bumped inside `AuditStore::log` (it bumps
/// `yuzu_server_audit_emit_failed_total`); the throw arm (`bad_alloc`-class)
/// is otherwise SILENT, so we log it here — the catch-arm log #1647 asked for.
/// Returns the persist outcome (true == durably audited OR audit-off) — this
/// is NOT the same thing as the caller-supplied `result` STRING argument
/// (`"success"`/`"failure"`, written into the audit row itself); see the file
/// banner's "`result` semantics (#4858)" section for what THAT string means,
/// which varies by calling site (pre-read vs post-read audit posture).
///
/// `AuditFn` is templated so either `RestApiV1::AuditFn`, `DexRoutes::AuditFn`,
/// or `mcp::McpServer::AuditFn` (all `std::function<bool(req, action, result,
/// target_type, target_id, detail)>`) binds without this header depending on
/// any one route class.
template <class AuditFn>
[[nodiscard]] inline bool try_persist_audit(const AuditFn& audit_fn, const httplib::Request& req,
                                            const std::string& action, const std::string& result,
                                            const std::string& target_type,
                                            const std::string& target_id,
                                            const std::string& detail) {
    // The three route classes all alias the SAME bool(req, 5×string) signature;
    // the template just avoids depending on any one of them. Pin the contract so a
    // wrong-arity / void-returning callable fails with a readable message rather
    // than a deep std::function spew (governance arch-S1 / cpp-expert).
    static_assert(
        std::is_invocable_r_v<bool, const AuditFn&, const httplib::Request&, const std::string&,
                              const std::string&, const std::string&, const std::string&,
                              const std::string&>,
        "AuditFn must be bool(const httplib::Request&, action, result, target_type, target_id, "
        "detail)");
    if (!audit_fn)
        return true; // audit-off deployment — not a persist failure; serve.
    try {
        return audit_fn(req, action, result, target_type, target_id, detail);
    } catch (const std::exception& e) {
        spdlog::warn("audit_fn threw on behavioural-data route action={} target={}: {}", action,
                     audit_token(target_id), e.what());
    } catch (...) {
        spdlog::warn("audit_fn threw (non-std exception) on behavioural-data route action={} "
                     "target={}",
                     action, audit_token(target_id));
    }
    return false;
}

/// Same guarantees as `try_persist_audit`, for a sink that STAMPS the principal
/// explicitly rather than re-deriving it from the request.
///
/// Needed wherever the audit row is written at a moment when the request's credential
/// no longer resolves — the motivating case is `mcp.stream.close` on a
/// `credential_revoked` teardown, where re-deriving would leave the actor blank on
/// precisely the rows that evidence the revocation control.
template <typename PrincipalAuditFn, typename PrincipalT>
[[nodiscard]] inline bool
try_persist_audit_for_principal(const PrincipalAuditFn& audit_fn, const httplib::Request& req,
                                const std::string& action, const std::string& result,
                                const PrincipalT& principal, const std::string& target_type,
                                const std::string& target_id, const std::string& detail) {
    // NOTE the actor is a distinct STRUCT type, not more strings. That is what makes this
    // assert meaningful: is_invocable_r_v checks arity and return type only, so a sink whose
    // same-typed string parameters were transposed would satisfy it silently.
    static_assert(std::is_invocable_r_v<bool, const PrincipalAuditFn&, const httplib::Request&,
                                        const std::string&, const std::string&, const PrincipalT&,
                                        const std::string&, const std::string&,
                                        const std::string&>,
                  "PrincipalAuditFn must be bool(const httplib::Request&, action, result, "
                  "principal-struct, target_type, target_id, detail)");
    if (!audit_fn)
        return true; // audit-off deployment — not a persist failure; serve.
    try {
        return audit_fn(req, action, result, principal, target_type, target_id, detail);
    } catch (const std::exception& e) {
        spdlog::warn("principal audit_fn threw action={} target={}: {}", action,
                     audit_token(target_id), e.what());
    } catch (...) {
        spdlog::warn("principal audit_fn threw (non-std exception) action={} target={}", action,
                     audit_token(target_id));
    }
    return false;
}

/// HTTP wrapper: `try_persist_audit` + set the `Sec-Audit-Failed: true`
/// response header on failure. Returns the persist outcome so the caller picks
/// its posture (HTML fragments PROCEED and render; REST JSON FAIL CLOSED 503).
/// `[[nodiscard]]` so a future REST route can't silently drop the bool and serve
/// PII after a known audit-persist failure (#1651 review K4) — the HTML
/// set-and-proceed callers, which legitimately ignore it (the header side effect
/// is the point), discard it explicitly with `(void)`.
///
/// This wrapper is shared by BOTH audit postures the file banner describes —
/// the `result` string a caller passes in is decided at the CALL SITE, not by
/// this function: most callers audit BEFORE the read with a literal
/// `"success"` (authorised-and-attempted, not disclosed — a degraded read
/// afterwards can still render a placeholder / 503 on top of that row), while
/// a few (e.g. `guardian.device.view`) audit AFTER the read and pass
/// `rows ? "success" : "failure"` by actual outcome. Either way this
/// function's OWN return value is the unrelated persist outcome (see
/// `try_persist_audit` above) — see the file banner's "`result` semantics
/// (#4858)" section before reading anything into a `result` value from this
/// signature alone.
template <class AuditFn>
[[nodiscard]] inline bool emit_behavioral_audit(const AuditFn& audit_fn, const httplib::Request& req,
                                  httplib::Response& res, const std::string& action,
                                  const std::string& result, const std::string& target_type,
                                  const std::string& target_id, const std::string& detail) {
    const bool persisted =
        try_persist_audit(audit_fn, req, action, result, target_type, target_id, detail);
    // Set the flag at most once per response. httplib's set_header EMPLACES into a
    // header multimap (append, not replace), so a route that calls this helper more
    // than once on the same `res` — the tar.dns.read + tar.arp.read pair and the
    // per-source tar.sources.configure loop — would emit duplicate `Sec-Audit-Failed`
    // field-lines if several audits failed. The guard keeps the header idempotent for
    // a strict downstream parser; single-call callers are unaffected (#1647 follow-up).
    if (!persisted && !res.has_header("Sec-Audit-Failed"))
        res.set_header("Sec-Audit-Failed", "true");
    return persisted;
}

} // namespace yuzu::server::detail
