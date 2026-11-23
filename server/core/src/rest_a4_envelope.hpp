#pragma once

/// @file rest_a4_envelope.hpp
///
/// W5.1 — testable shape contract for the agentic-first JSON SSE channel
/// at `/api/v1/events` and the A4 error envelope it emits.
///
/// Lives in `yuzu::server::detail` rather than `rest_api_v1.cpp`'s
/// anonymous namespace so unit tests can link directly to the helpers
/// and assert the wire shapes — the handler itself uses
/// `set_chunked_content_provider`, which httplib stores opaquely and
/// is not externally invokable from a TestRouteSink dispatch.
///
/// Both helpers are pure: no I/O, no global state beyond the
/// process-monotonic counter in `make_correlation_id`.

#include "execution_event_bus.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server::detail {

/// Generate a per-request correlation id of the form `req-<hex-ms>-<hex-seq>`.
/// Combines wall-clock ms with a process-monotonic counter so values are
/// unique within a single server instance even if two requests fire in the
/// same millisecond. Suitable for grep-by-token across spdlog / audit
/// rows; not a UUID, not security-sensitive.
std::string make_correlation_id();

/// Optional A4-envelope fields beyond the always-present
/// code/message/correlation_id/retry_after_ms set. This is the single options
/// carrier for the unified denial/error envelope (folded here from the ad-hoc
/// `a4_denial` that used to live in auth_routes.cpp's anonymous namespace).
/// Every field is nullable/optional; the builder emits:
///   - `retry_after_ms`: `null` unless `retry_after_ms` is set (A4 lists it
///     required+nullable, so it is ALWAYS a key in the body);
///   - `remediation`: omitted when empty (the REST convention — absence
///     carries the same "no recovery hint" meaning per §A4);
///   - `permission`: emitted as `"<securable_type>:<operation>"` when set —
///     the §A4 kPermissionDenied specialisation that names the missing grant;
///   - `reason`: a closed machine token naming the cause (e.g. a zero-reach cause),
///     emitted inside `error` only when non-empty;
///   - `approval_id` + `status_url`: emitted when set — the §A4
///     kApprovalRequired specialisation so a worker can poll the workflow
///     rather than re-issue the request.
///
/// The `string_view` members are non-owning: callers pass string literals or
/// temporaries whose lifetime spans the synchronous `error_json_a4` /
/// `a4_denial` call (the builder copies bytes into the output before
/// returning), which holds at every denial site.
struct A4ErrorOpts {
    std::optional<std::int64_t> retry_after_ms; ///< null in the body when unset
    std::string_view remediation;               ///< omitted when empty
    std::string_view permission;                ///< "<securable_type>:<operation>"
    std::string_view approval_id;               ///< kApprovalRequired only
    std::string_view status_url;                ///< kApprovalRequired only
    std::string_view reason;                    ///< closed machine token naming the cause; omitted when
                                                ///< empty. Last member, so every existing designated
                                                ///< initialiser keeps its order.
};

/// A4-compliant error envelope. Per `docs/agentic-first-principle.md` §A4,
/// every failure response includes `code`, `message`, `correlation_id`, the
/// nullable `retry_after_ms`, an optional `remediation` hint, the optional
/// permission/approval specialisations, and the standard `meta.api_version`.
///
/// Overloads (each a byte-compatible superset — added, never broken):
///   1. `(code, message, cid, remediation="")` — no retry (emits null).
///   2. `(code, message, cid, retry_after_ms, remediation)` — concrete retry.
///   3. `(code, message, cid, const A4ErrorOpts&)` — the full unified form
///      carrying the permission/approval specialisations. Overloads 1 and 2
///      delegate to it, so there is ONE builder and ONE wire shape.
std::string error_json_a4(int code, std::string_view message, std::string_view correlation_id,
                          std::string_view remediation = {});

std::string error_json_a4(int code, std::string_view message, std::string_view correlation_id,
                          std::int64_t retry_after_ms, std::string_view remediation);

std::string error_json_a4(int code, std::string_view message, std::string_view correlation_id,
                          const A4ErrorOpts& opts);

/// JSON envelope emitted as the SSE `data:` payload on `/api/v1/events`.
/// Per A3, every event carries `execution_id` and a deterministic step
/// name from the published taxonomy (`agent-transition`,
/// `execution-progress`, `execution-completed`).
///
/// `ev.data` is raw-embedded as `payload` — the ExecutionTracker
/// publishers already produce well-formed JSON objects, so re-parsing
/// would be wasted work. Empty `ev.data` becomes `null` so the envelope
/// stays a valid JSON object even for synthesized events that carry no
/// payload (heartbeats handled separately, not through this helper).
std::string make_event_envelope(std::string_view execution_id,
                                const yuzu::server::ExecutionEvent& ev);

} // namespace yuzu::server::detail
