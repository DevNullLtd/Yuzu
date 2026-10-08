#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "mcp_input_schema.hpp"

// Server-side validation of an InstructionDefinition's stored `parameter_schema` against the
// `params` an operator supplies when executing it.
//
// The stored schema is the DSL shape of docs/yaml-dsl-spec.md section 10. prepare_param_validator()
// canonicalises it into the JSON-Schema subset the shared MCP compiler understands
// (mcp_input_schema.hpp), compiles it with mcp::compile_input_schema, and adds only the
// coercion and the guards below. Anything the canonicaliser does not list is an ERROR.
//   * types: string | integer | int32 | int64 | boolean | array | datetime | guid. `int32`
//     gets the int32 range (tightened, never loosened); `datetime` (ISO 8601, zone required,
//     shape only) and `guid` (8-4-4-4-12 hex) get a fixed pattern.
//   * `validation{...}` is flattened into the property; a flat key beats the nested one.
//     `enum` is string-typed only; `items` is an array's `{type: string}` only.
//   * the root gets `additionalProperties: false`: an undeclared param is refused (path
//     "/*"). A `required` name must be declared; one with a `default` may be omitted. A default
//     is validated at prepare time and never injected.
//   * property and `required` names match ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$.
//
// PRESENCE. Empty text, whitespace or `{}` means "no schema stored": absent(), check() passes.
// `{type: object}` with no properties means "no parameters". Text that is not a JSON object,
// or a non-empty object with no root `type`, is an ERROR.
//
// COERCION (check()). The route stringifies typed JSON before dispatch, so the declared type
// is checked against the form the plugin receives: an integer is a JSON integer or a string
// that is exactly `-?[0-9]+` fitting int64; a boolean is a JSON bool or "true"/"false"; a
// string-kind value may also be a JSON number or bool. A string-kind property refuses null.
//
// EMBEDDED NUL. A string with U+0000 is refused at the top level and in an array: the agent
// hands a plugin each parameter as a C string, so a NUL would truncate what the plugin sees.
//
// Error text never echoes a caller value, pattern, default or keyword.
//
// LIMITS. The stored text is author-controlled and compiled on the request path; an
// over-limit schema is an ERROR, never truncated.
//   * raw text <= kMaxParameterSchemaBytes; <= kMaxSchemaProperties properties; <=
//     kMaxEnumMembers per enum; a user pattern <= kMaxPatternBytes.
//   * a pattern compiles under mcp::kPatternMaxMem, has <= kMaxPatternProgramSize RE2
//     instructions, and one schema's programs sum to <= kMaxSchemaPatternProgramSize (a short
//     pattern can compile to a large program: `a{1000}` is 7 bytes and 1004 instructions).
//     32 of them in a row are 32004 and pass the per-pattern cap; 33 reach 33004 and are
//     refused. RE2's own budget refuses `\pL{300}x` outright. The first over-budget pattern
//     ends the pre-compile.
//   * an integer minimum/maximum satisfies |bound| < kIntegerBoundLimit: the shared validator
//     compares as doubles, exact only below 2^53.
//   * a string matched against a pattern is <= kMaxPatternMatchedStringBytes, and
//     sum((bytes + 1) x program size) over one params object (or over all the defaults of one
//     schema) is <= kMaxPatternMatchWork; a string compared against an enum is charged one more
//     unit per member. This, not a clock, bounds the CPU a check or a prepare can spend.
namespace yuzu::server::instr {

inline constexpr std::size_t kMaxParameterSchemaBytes = 256 * 1024;
inline constexpr std::size_t kMaxSchemaProperties = 128;
inline constexpr std::size_t kMaxEnumMembers = 256;
inline constexpr std::size_t kMaxPatternBytes = 1024;
inline constexpr std::size_t kMaxPatternProgramSize = 32768;
inline constexpr std::size_t kMaxSchemaPatternProgramSize = 65536;
inline constexpr std::size_t kMaxPatternMatchedStringBytes = 64 * 1024;
inline constexpr std::uint64_t kMaxPatternMatchWork = 16ULL * 1024 * 1024;
inline constexpr std::int64_t kIntegerBoundLimit = 9007199254740992;  // 2^53
inline constexpr std::size_t kParamValidatorCacheEntries = 128;

// Immutable, move-only; check() is const and thread-safe. A moved-from validator is
// neither absent nor usable: check() on it returns a violation, never a pass.
class ParamValidator {
  public:
    ParamValidator(ParamValidator&&) noexcept;
    ParamValidator& operator=(ParamValidator&&) noexcept;
    ParamValidator(const ParamValidator&) = delete;
    ParamValidator& operator=(const ParamValidator&) = delete;
    ~ParamValidator();

    // True when the stored schema declared nothing (see PRESENCE).
    [[nodiscard]] bool absent() const noexcept;

    // First violation, or nullopt if `params` conforms. `params` is the caller's value:
    // an object, or null (omitted), read as an empty object; any other JSON type is a
    // violation with an empty path. `path` is "/<name>" ("/<name>/<index>" for an array
    // element), "/*" for an undeclared param. Only declared properties are copied; an
    // undeclared key is detected by count and never inspected.
    [[nodiscard]] std::optional<mcp::SchemaViolation> check(const nlohmann::json& params) const;

  private:
    struct Impl;
    friend std::expected<ParamValidator, std::vector<std::string>>
    prepare_param_validator(std::string_view stored_schema_json);

    explicit ParamValidator(std::unique_ptr<const Impl> impl);
    std::unique_ptr<const Impl> impl_;
};

// Build a validator from a stored `parameter_schema`. Accumulates the problems found; the
// CALLER decides policy (the execute route fails closed). Text over
// kMaxParameterSchemaBytes fails first, on its raw length, with a fixed message.
[[nodiscard]] std::expected<ParamValidator, std::vector<std::string>>
prepare_param_validator(std::string_view stored_schema_json);

// The canonical JSON-Schema form of a stored `parameter_schema`: the exact object
// prepare_param_validator() compiles (DSL types and `validation{}` rewritten, the root closed with
// `additionalProperties: false`), for discovery to publish. nullopt means "no schema stored" (see
// PRESENCE); an error list means the text could not be canonicalised (same messages and the same
// size, depth and shape limits as prepare_param_validator, which calls the same code).
// NO RE2 pattern is compiled, so this does not pay the RE2 compile cost. That also means a
// non-null result can still be refused at execute time: prepare_param_validator() rejects, and
// this does not check, a pattern that does not compile or exceeds the RE2 program budget, a
// `default` that violates its own parameter's constraints, and anything else the shared schema
// compiler (mcp::compile_input_schema) refuses, for example non-numeric bounds, inverted bounds
// or a keyword on the wrong type. The write gate keeps such schemas out of the store; a legacy
// row can still carry one.
[[nodiscard]] std::expected<std::optional<nlohmann::json>, std::vector<std::string>>
canonicalise_param_schema(std::string_view stored_schema_json);

// Bounded LRU of prepared validators so the execute route does not re-compile a
// definition's schema on every call. Keyed by (definition id, schema length, SHA-256 of
// the schema text): an edited definition has a new key, and the old entry ages out.
// Compilation runs OUTSIDE the lock, so concurrent first calls for one schema may each
// compile it (accepted: there is no single-flight). Failures and absent validators are
// never cached. If the digest cannot be computed the call compiles without caching.
// The cache is capped by ENTRY count, not bytes. What it can hold is entries x the patterns in
// a schema (at most one per property, a string's own `pattern` or an array's `items` pattern,
// so at most kMaxSchemaProperties) x what one compiled pattern retains, and
// mcp::kPatternMaxMem bounds only that last factor.
class ParamValidatorCache {
  public:
    using Result =
        std::expected<std::shared_ptr<const ParamValidator>, std::vector<std::string>>;

    explicit ParamValidatorCache(std::size_t max_entries = kParamValidatorCacheEntries);

    [[nodiscard]] Result get(const std::string& definition_id, const std::string& stored_schema);

    // Entries currently held (for tests).
    [[nodiscard]] std::size_t size() const;

  private:
    struct Entry {
        std::string key;
        std::shared_ptr<const ParamValidator> validator;
    };

    const std::size_t max_entries_;
    mutable std::mutex mu_;
    std::list<Entry> lru_;  // front = most recently used
    std::unordered_map<std::string, std::list<Entry>::iterator> index_;
};

}  // namespace yuzu::server::instr
