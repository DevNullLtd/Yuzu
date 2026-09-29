#pragma once

#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

// MCP input-schema subset compiler (#2405).
//
// Compiles the server-authored kTools[] input_schema_json strings into an
// immutable, pre-validated form the C8 approval gate can enforce BEFORE an
// approval ticket is minted or consumed — a schema-invalid call must neither
// waste an admin's approval nor burn a one-time ticket.
//
// This is a SUPPORTED SUBSET of JSON Schema, not a conforming validator: the
// keyword catalogue is CLOSED to exactly what the served tool schemas use
// (type / properties / required / enum / minimum / maximum / minLength /
// maxLength / pattern / items / minItems / maxItems / additionalProperties /
// anyOf-of-required-alternatives, with description and default ignored).
// The catalogue is enumerated in FOUR places that must move together:
// kSupportedKeywords in mcp_input_schema.cpp, this comment, the
// "Pre-approval input-schema validation" bullet in docs/mcp-server.md, and the
// "strictness notes" paragraph in docs/user-manual/mcp.md — that last one was
// missed when minLength landed and is the reason this list says four.
// A size tether in test_mcp_server.cpp fails when the array grows without
// this list being revisited. Any other keyword — and any
// malformed operand for a supported keyword — is a COMPILE error, surfaced
// through the C8 boot validator so a schema the gate cannot fully enforce is
// unbootable rather than partially enforced. Do not claim general JSON
// Schema conformance for this module.
//
// Deliberate deviations from JSON Schema 2020-12, chosen to match what the
// tool handlers actually consume:
//   * "integer" is STRICT: 1.0 is rejected. param_str/param_int only honor
//     the exact JSON type, so accepting an integral double here would
//     validate an argument the handler then silently replaces with its
//     default — the exact validated-but-ignored mismatch #2405 closes.
//     Integers outside int64 range are rejected for the same reason
//     (param_int returns int64_t).
//   * "maxLength" counts BYTES, not codepoints (stricter-or-equal), so a
//     schema bound and its handler-side twin can be compared literally.
//     "minLength" counts bytes for the same reason, but note the direction
//     differs: bytes >= codepoints, so a byte-counted minLength is LOOSER
//     than a codepoint-counted one for values above 1. It is exact at the
//     case the catalogue exists to serve — minLength:1, i.e. "not empty",
//     where any non-empty string has at least one byte and one codepoint.
//     Do not read a minLength above 1 as a character-count guarantee.
//     (This line used to claim it "matches the byte-cap kAgenticParamMaxLen
//     the handlers enforce" — that constant serves two unrelated READ tools
//     and was never a general handler cap. The real handler-side twins are
//     the per-tool kExecInstr* bounds in mcp_server.cpp, #2437.)
//   * "required" names must be declared in "properties" (a Yuzu authoring
//     lint — legal JSON Schema, but in a closed server-authored table an
//     undeclared required name is always a typo).
namespace yuzu::server::mcp {

namespace detail {
struct SchemaNode;
}

// One violation, first-error semantics. `path` is JSON-pointer-ish
// ("" = root, "/steps/1", "/steps/0/params/*"): declared property names and
// array indices are server-authored/numeric and appear verbatim; a
// CALLER-derived map key (a key validated via additionalProperties, or an
// unexpected key under additionalProperties:false) is always reported as the
// wildcard segment '*' — violation paths land in the client envelope and the
// durable audit detail, and must never carry untrusted argument content.
// `reason` is server-authored and never echoes argument values.
struct SchemaViolation {
    std::string path;
    std::string reason;
};

// Immutable compiled schema. Thread-safe for concurrent validate() calls
// (const node tree, RE2 matching is const) — httplib workers share one
// instance per tool.
class CompiledInputSchema {
  public:
    CompiledInputSchema(CompiledInputSchema&&) noexcept;
    CompiledInputSchema& operator=(CompiledInputSchema&&) noexcept;
    CompiledInputSchema(const CompiledInputSchema&) = delete;
    CompiledInputSchema& operator=(const CompiledInputSchema&) = delete;
    ~CompiledInputSchema();

    // First violation, or nullopt if `args` conforms.
    [[nodiscard]] std::optional<SchemaViolation> validate(const nlohmann::json& args) const;

  private:
    friend std::expected<CompiledInputSchema, std::vector<std::string>>
    compile_input_schema(std::string_view schema_json);

    explicit CompiledInputSchema(std::unique_ptr<const detail::SchemaNode> root);
    std::unique_ptr<const detail::SchemaNode> root_;
};

// Compile one input_schema_json string. Accumulates ALL problems (never
// throw-first out of an nlohmann conversion) so the C8 boot validator can
// fold every offence into its single deterministic error message. Error
// strings are relative to the schema ("unsupported keyword 'oneOf' at
// '/properties/foo'"); the boot validator prefixes the owning tool name.
std::expected<CompiledInputSchema, std::vector<std::string>>
compile_input_schema(std::string_view schema_json);

// Size of the closed keyword catalogue, for the drift tether described above:
// growing kSupportedKeywords without revisiting the header comment and
// docs/mcp-server.md fails a test rather than silently shipping a schema
// keyword the operator docs never mention.
std::size_t supported_keyword_count();

}  // namespace yuzu::server::mcp
