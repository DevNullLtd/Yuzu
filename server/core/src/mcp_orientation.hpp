#pragma once

#include <span>
#include <string>
#include <string_view>

// Shared MCP orientation source (ADR-1005 track 2g PR 1, invariant A5 item 6).
//
// Single authoritative source for the operator/developer-authored STATIC
// orientation text served to a fresh agentic client. The same two text blocks
// back both the `yuzu://about` / `yuzu://operating-model` resources AND the
// `initialize` result's `instructions` blob, so the handshake and the resources
// cannot drift: they are the same bytes by construction, not two copies kept in
// sync by review.
//
// STATIC content only. Never interpolate fleet-derived or agent-reported data
// (hostnames, tag names, device strings) into any of this text. The handshake
// reaches every fresh client before it has made a single authenticated tool
// call; templating untrusted data here would open a prompt-injection channel
// into every client, bypassing the untrusted_prompt_argument discipline
// (A5 item 6). The compiler enforces it: the only inputs below are literals.
namespace yuzu::server::mcp {

// Product primer + safe operating rules. Backs the `yuzu://about` resource.
std::string_view about_text();

// The recommended classify -> read -> narrow -> approve -> execute -> monitor
// workflow. Backs the `yuzu://operating-model` resource.
std::string_view operating_model_text();

// One capability area of the MCP tool surface. `tools` lists every tool name in
// the family; the union across all families is exactly the kTools[] set, pinned
// by the family-tether test (test_mcp_server.cpp). Adding a tool family, or a
// tool, without updating this table fails that test rather than a judgment call
// in review (A5 item 6: the blob is updated in the same PR that reshapes the
// surface).
struct ToolFamily {
    std::string_view name;
    std::string_view blurb;
    std::span<const std::string_view> tools;
};

// The tool-family enumeration, living beside the blob source (A5 item 6).
std::span<const ToolFamily> tool_families();

// The `initialize` result's `instructions` orientation blob: about_text() +
// operating_model_text() verbatim (containment is the single-source proof),
// then a rendered tool-family index and a discovery pointer. Composed once into
// a function-local static. STATIC only, per the file-level contract above.
const std::string& initialize_instructions();

}  // namespace yuzu::server::mcp
