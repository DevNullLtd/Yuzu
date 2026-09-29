#pragma once

#include <cstddef>
#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace yuzu::scope {

// -- Comparison operators ----------------------------------------------------

enum class CompOp { Eq, Neq, Like, Lt, Gt, Le, Ge, In, Contains, Matches, Exists };

// Single source of truth for "how many CompOp values exist". When you add a
// CompOp enumerator you MUST bump this AND add a `comp_op_catalog()` entry in
// discover_routes.cpp — a `static_assert` there binds the catalog size to this
// constant, so a mismatch is a portable BUILD failure on every compiler (the
// exhaustive-switch `-Wswitch` signal in operator_token/eval_condition is
// GCC/Clang-only and non-fatal, so it is not a sufficient guard on its own —
// governance arch-SHOULD-4 / cpp-expert). Not a `CompOp::_Count` sentinel on
// purpose: that would force a dummy case into every exhaustive CompOp switch.
inline constexpr std::size_t kCompOpCount = 11;

// -- Expression AST ----------------------------------------------------------

struct Condition {
    std::string attribute;
    CompOp op;
    std::string value;
    std::vector<std::string> values; // for In operator
};

struct Combinator;

using Expression = std::variant<Condition, std::unique_ptr<Combinator>>;

enum class CombOp { And, Or, Not };

struct Combinator {
    CombOp op;
    std::vector<Expression> children;
};

// -- Parser ------------------------------------------------------------------

/// Parse a scope expression string into an AST.
/// Grammar:
///   expr     ::= or_expr
///   or_expr  ::= and_expr ('OR' and_expr)*
///   and_expr ::= not_expr ('AND' not_expr)*
///   not_expr ::= 'NOT' not_expr | primary
///   primary  ::= '(' expr ')' | condition
///   condition::= IDENT op value
///   op       ::= '==' | '!=' | 'LIKE' | 'MATCHES' | '<' | '>' | '<=' | '>=' | 'IN' | 'CONTAINS'
///   value    ::= QUOTED_STRING | '(' value_list ')' | IDENT
///   value_list ::= value (',' value)*
///
/// Extended operators:
///   condition::= 'EXISTS' IDENT                        (unary — checks non-empty)
///              | 'LEN' '(' IDENT ')' op value           (string length comparison)
///              | 'STARTSWITH' '(' IDENT ',' value ')'   (prefix check)
std::expected<Expression, std::string> parse(std::string_view input);

// -- Evaluator ---------------------------------------------------------------

/// Resolves an attribute name to a value.
using AttributeResolver = std::function<std::string(std::string_view)>;

/// Evaluate an expression against a resolver.
bool evaluate(const Expression& expr, const AttributeResolver& resolver);

/// Check if an expression is syntactically valid (convenience).
std::expected<void, std::string> validate(std::string_view input);

/// Synthetic condition attributes: `LEN(x) …` parses to attribute `__len:x`
/// and `STARTSWITH(x, p)` to `__startswith:x` (see parse()).
/// `classify_synthetic` is the SINGLE decoder for these encodings —
/// `eval_condition` dispatches on `kind` and `collect_attribute_suffixes`
/// collects on `real`, so a new synthetic form added here reaches both, and
/// one added anywhere else fails both loudly (ADR-0050 governance DSL-1: a
/// collector that misses a synthetic form silently drops the key from the
/// store preload, mis-resolving the atom for store-persisted values AND
/// bypassing the degraded-store abort for expressions whose only references
/// are synthetic).
enum class SyntheticKind { kNone, kLen, kStartswith };
struct SyntheticAttr {
    SyntheticKind kind;
    std::string_view real; // the attribute the resolver is actually asked for;
                            // ALIASES the `attribute` argument — valid only while it lives
};
SyntheticAttr classify_synthetic(std::string_view attribute);

/// Collect the suffix of every condition attribute starting with `prefix`
/// (e.g. prefix "tag:" on `tag:env == "prod"` appends "env"), AFTER decoding
/// synthetic attributes via `classify_synthetic` (`LEN(tag:env) > 3`
/// contributes "env" too). Recursive over combinators; duplicates are
/// preserved (callers that care dedupe). Backs the store-preload pattern: a
/// caller resolving `tag:`/`props.` atoms preloads every referenced key in
/// ONE bulk store query before its agent loop instead of a per-agent store
/// round-trip (ADR-0045/ADR-0050).
void collect_attribute_suffixes(const Expression& expr, std::string_view prefix,
                                std::vector<std::string>& out);

/// Canonical wire token for a comparison operator, e.g. `CompOp::Eq` -> `"=="`.
/// Single source for the `GET /api/v1/discover/scope-kinds` operator catalog
/// (`discover_routes.cpp`) so the published list can never silently diverge from
/// the evaluator. The switch backing this function (`scope_engine.cpp`) has NO
/// `default` case — mirroring `eval_condition`'s own exhaustive switch — so
/// adding a `CompOp` enumerator without updating both switches produces a
/// `-Wswitch` warning at build (warning_level=3 project-wide; see CLAUDE.md
/// Build). A CROSS-CHECK unit test (`test_discovery_routes.cpp`) also asserts
/// the discovery catalog covers every currently-declared value.
std::string_view operator_token(CompOp op);

} // namespace yuzu::scope
