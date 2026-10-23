#pragma once

// Shared boilerplate for the registry-resident MCP tool files (mcp_tools_*.cpp; see
// mcp_tool_registry.hpp). Header-only so each domain file stays one translation unit.
//
// Everything here is behaviour the domain files previously duplicated byte for byte or
// near enough to parameterise. A new domain file reaches for these instead of cloning
// them, so the unwired / lossy-dump / answer posture cannot drift between tools.
//
// This header is held to the same include denylist as the mcp_tools_*.cpp files
// (test_mcp_dispatch_coverage.cpp): it names no store, agent registry, server class or
// auth database header, only the registry seam, the JSON-RPC constants and the shared
// audit kernel.
//
// The names answer, answer_unwired and dump_replace are reserved in yuzu::server::mcp: a domain
// file that defines its own copy next to these gets an ambiguous-call error, so extend the
// helper instead. answer_unwired answers a non-retryable kInternalError by design (it carries
// the retry-hint-exempt marker; scripts/ci/check-mcp-retry-hints.py scans this header whenever
// it is new or changed); a transient fault needs its own a4_error call with a retry hint.

#include "mcp_jsonrpc.hpp"       // kInternalError
#include "mcp_tool_deps.hpp"     // ToolDeps::audit_fn
#include "mcp_tool_registry.hpp" // ToolCallContext
#include "rest_audit.hpp"        // detail::try_persist_audit (the shared audit kernel)

#include <nlohmann/json.hpp>

#include <spdlog/spdlog.h>

#include <string>
#include <string_view>
#include <utility>

namespace yuzu::server::mcp {

/// Write a handler's finished JSON-RPC body. A handler answers with res.set_content
/// (the dispatch chain's empty-response backstop assumes it).
inline void answer(const ToolCallContext& ctx, std::string body) {
    ctx.res.set_content(std::move(body), "application/json");
}

/// A tool-specific domain audit row written alongside the generic mcp.<tool> row on an
/// unwired answer. Leave `verb` null for a tool that writes only the generic row.
struct UnwiredDomainRow {
    const char* verb = nullptr;
    const char* target_type = "";
    std::string target_id;
};

/// A provider the deployment did not wire: an internal error with no retry hint, because
/// it is a misconfiguration and not a transient fault, and no data.
///
/// Always writes the generic mcp.<tool> failure row (every registry tool call leaves one).
/// When `domain.verb` is set it ALSO writes a failure row under that verb first, through
/// ToolDeps::audit_fn (skipped when ctx.deps is null: there is no sink to ask), and a
/// dropped row on EITHER sink reports audit_persisted:false. When `log_message` is
/// non-empty it is logged at error level before any row is written. `detail` is the
/// audit detail for both rows. A caller keeps its own exact message and posture by
/// choosing these arguments; nothing here changes the body shape.
inline void answer_unwired(const ToolCallContext& ctx, std::string_view message,
                           const std::string& detail, const UnwiredDomainRow& domain = {},
                           std::string_view log_message = {}) {
    if (!log_message.empty())
        spdlog::error("{}", log_message);
    const bool domain_ok =
        domain.verb == nullptr || ctx.deps == nullptr ||
        yuzu::server::detail::try_persist_audit(ctx.deps->audit_fn, ctx.req, domain.verb, "failure",
                                                domain.target_type, domain.target_id, detail);
    const bool generic_ok = ctx.audit("failure", detail);
    // retry-hint-exempt: an unwired provider is a deployment misconfiguration, not a transient fault
    answer(ctx, ctx.a4_error(kInternalError, message, {}, -1, {}, domain_ok && generic_ok));
}

/// Compact dump that degrades invalid UTF-8 to U+FFFD instead of throwing. Use it for any
/// body built from agent-reported or store text AFTER the success audit rows are written:
/// a throw there would be a bodyless 500 recorded as a success. Byte-identical to a plain
/// dump for valid UTF-8. A template so it serves nlohmann::json and nlohmann::ordered_json.
template <class JsonType>
[[nodiscard]] std::string dump_replace(const JsonType& j) {
    return j.dump(-1, ' ', false, JsonType::error_handler_t::replace);
}

} // namespace yuzu::server::mcp
