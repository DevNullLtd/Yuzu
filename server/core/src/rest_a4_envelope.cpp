/// @file rest_a4_envelope.cpp
///
/// Definitions for the A4 error envelope and correlation-id helpers declared in
/// `rest_a4_envelope.hpp`. They used to live in rest_api_v1.cpp, which let them
/// share that file's anonymous-namespace JObj builder. They live here because
/// yuzu_server_core_lib (auth_routes, authz_gates, mcp_stream, rate_limiter,
/// step_up_gate, ...) calls them, and rest_api_v1.cpp is in
/// yuzu_server_routes_lib; the lib edge must stay one-way (see
/// server/core/meson.build).
///
/// The wire shape MUST stay byte-identical to what rest_api_v1.cpp produced:
/// `JObj` and `json_escape` below are verbatim copies of the subset it uses.
/// (mcp_server.cpp keeps its own private copy for the same reason.)

#include "rest_a4_envelope.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <format>
#include <string>
#include <string_view>

namespace yuzu::server::detail {

namespace {

void json_escape(std::string& out, std::string_view sv) {
    out.reserve(out.size() + sv.size());
    for (char c : sv) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char hex[8];
                std::snprintf(hex, sizeof(hex), "\\u%04x",
                              static_cast<unsigned int>(static_cast<unsigned char>(c)));
                out += hex;
            } else {
                out += c;
            }
        }
    }
}

/// JSON object builder (subset of rest_api_v1.cpp's JObj used by the A4 envelope).
class JObj {
    std::string buf_;
    int n_ = 0;

    void pre() { buf_ += (n_++ ? ',' : '{'); }
    void key(std::string_view k) {
        pre();
        buf_ += '"';
        json_escape(buf_, k);
        buf_ += "\":";
    }

public:
    JObj() = default;

    JObj& add(std::string_view k, std::string_view v) {
        key(k);
        buf_ += '"';
        json_escape(buf_, v);
        buf_ += '"';
        return *this;
    }
    JObj& add(std::string_view k, int64_t v) {
        key(k);
        buf_ += std::to_string(v);
        return *this;
    }
    JObj& add(std::string_view k, int v) { return add(k, static_cast<int64_t>(v)); }
    /// Embed a pre-serialized JSON fragment (object, array, literal).
    JObj& raw(std::string_view k, std::string_view json) {
        key(k);
        buf_ += json;
        return *this;
    }

    [[nodiscard]] std::string str() const { return n_ ? buf_ + '}' : "{}"; }
};

} // namespace

std::string make_correlation_id() {
    static std::atomic<std::uint64_t> seq{0};
    auto n = seq.fetch_add(1, std::memory_order_relaxed);
    auto t = std::chrono::duration_cast<std::chrono::milliseconds>(
                 std::chrono::system_clock::now().time_since_epoch())
                 .count();
    // std::format keeps the buffer-size reasoning out of the call site.
    return std::format("req-{:x}-{:x}", static_cast<std::uint64_t>(t), n);
}

std::string error_json_a4(int code, std::string_view message, std::string_view correlation_id,
                          const A4ErrorOpts& opts) {
    // The ONE unified A4 envelope builder (folds the old auth_routes.cpp
    // a4_denial into a single wire shape). A4 (docs/agentic-first-principle.md)
    // lists retry_after_ms as a REQUIRED, nullable field, so it is ALWAYS a
    // key: `null` unless opts.retry_after_ms is set. remediation is omitted
    // when empty (absence == "no recovery hint" per §A4). permission is the
    // kPermissionDenied specialisation ("<securable_type>:<operation>");
    // approval_id + status_url are the kApprovalRequired specialisation. #1470.
    auto err = JObj()
                   .add("code", code)
                   .add("message", message)
                   .add("correlation_id", correlation_id);
    if (opts.retry_after_ms.has_value()) {
        err.add("retry_after_ms", *opts.retry_after_ms);
    } else {
        err.raw("retry_after_ms", "null");
    }
    if (!opts.remediation.empty()) {
        err.add("remediation", opts.remediation);
    }
    if (!opts.permission.empty()) {
        err.add("permission", opts.permission);
    }
    if (!opts.approval_id.empty()) {
        err.add("approval_id", opts.approval_id);
    }
    if (!opts.status_url.empty()) {
        err.add("status_url", opts.status_url);
    }
    return JObj().raw("error", err.str()).raw("meta", R"({"api_version":"v1"})").str();
}

std::string error_json_a4(int code, std::string_view message, std::string_view correlation_id,
                          std::string_view remediation) {
    // Backward-compatible no-retry overload — delegates to the unified builder
    // so the wire shape stays byte-identical (retry_after_ms:null, remediation
    // omitted when empty).
    return error_json_a4(code, message, correlation_id, A4ErrorOpts{.remediation = remediation});
}

std::string error_json_a4(int code, std::string_view message, std::string_view correlation_id,
                          std::int64_t retry_after_ms, std::string_view remediation) {
    // Backward-compatible concrete-retry overload. Passes the value through
    // even when 0 — this overload's contract is "always a concrete number".
    return error_json_a4(code, message, correlation_id,
                         A4ErrorOpts{.retry_after_ms = retry_after_ms, .remediation = remediation});
}

} // namespace yuzu::server::detail
