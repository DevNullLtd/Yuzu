#pragma once

#include <nlohmann/json_fwd.hpp>

#include <optional>
#include <string>
#include <string_view>

// ─────────────────────────────────────────────────────────────────────────────
// Result-set membership matcher (scope walking — design §3.2 / §6).
//
// Async result-set producers (`from-tar-query`, `from-instruction-result`)
// dispatch a command and land a `pending` row carrying an opaque `matcher`
// JSON. Once the producing execution reaches a terminal state, the server's
// maintenance thread walks every responder and asks this predicate whether
// that agent qualifies for membership.
//
// Keeping the decision here — a pure function of (matcher, status, output) —
// makes the per-producer membership rule unit-testable in isolation, away
// from the dispatch + tracker + SQLite plumbing of the maintenance thread.
//
// Matcher grammar (all JSON; an empty or unparseable matcher means "default"):
//
//   ""  /  {}                       → default: SUCCESS responders only
//   {"kind":"any_response"}         → every SUCCESS responder (include_empty)
//   {"kind":"tar_rows_ge","n":N}    → SUCCESS AND the tar result carried ≥ N rows
//                                     (N: JSON integer ≥ 1, default 1; a malformed N, or N < 1,
//                                     matches nobody)
//   a present `kind` that is not a string matches nobody (admission refuses it)
//   a kind-less matcher whose `column`/`op`/`value` is present but not a string, or whose
//     `value_set` is present but not an array, matches nobody (admission refuses it); a MISSING
//     key keeps the default so a typo cannot silently empty the set
//   {"column":C,"op":O,"value":V}        ─┐ SUCCESS AND at least one parsed
//   {"column":C,"op":O,"value_set":[..]} ─┘ output row's column C satisfies O
//
// A third path serves plain pipe rows: when the matcher carries the server-authored
//   "declared_columns":[names in output order], "plugin":"<name>"
// (written at admission by bind_declared_columns), C's index is its position in that list, each
// output line is split to the DECLARED width with `split_fields(plugin, line, width)`, and a line
// is skipped unless its field count equals the list's exactly and it is not the header row. The
// index is the declared column position, not the dashboard cell position: for a key/value plugin
// the dashboard still shows key + remainder under the declared headers (a pre-existing display
// gap tracked separately). Wrong-typed keys match nobody; a caller may not supply either key.
//
// `op` ∈ {eq, in, contains, exists}. A non-SUCCESS response NEVER qualifies,
// regardless of matcher — a plugin that errored is not evidence of a hit.
// ─────────────────────────────────────────────────────────────────────────────

namespace yuzu::server::rs_matcher {

/// Agent command-response status that counts as a successful execution.
/// Mirrors `CommandResponse::SUCCESS` (= 1) in agent.proto; the maintenance
/// thread used the bare literal `1` before this module was extracted.
inline constexpr int kStatusSuccess = 1;

/// True iff a responder with the given (status, output) qualifies for
/// membership in a result set whose pending row carries `matcher_json`.
bool response_matches(std::string_view matcher_json, int status, std::string_view output);

/// Admission check for a caller-supplied matcher (#4644): nullopt when acceptable, else the 400
/// message. A present `kind` must be a string; on a kind-less matcher a present `column`, `op`
/// or `value` must be a string and a present `value_set` an array. Only `tar_rows_ge` has a numeric field: its `n`
/// (absent = 1) must be one JSON integer in 1..2147483647. `response_matches` independently fails
/// CLOSED on a malformed `n` or `kind` already stored (including n < 1), so a bad value can never
/// throw out of the maintenance tick nor admit every responder. A matcher that is present but not
/// a JSON object is accepted here as the unrecognised-shape default (the serialized text may be
/// anything): a route holding the parsed value calls `validate_matcher_object` instead.
std::optional<std::string> validate_matcher(std::string_view matcher_json);

/// The admission check for a PRESENT caller `matcher` value (#4644): nullopt when acceptable,
/// else the 400 / -32602 message. A value that is not a JSON object is refused ("matcher must be
/// a JSON object"; it used to be dropped, which meant every responder qualified), then the
/// object goes through `validate_matcher`. REST and MCP both call this ONE function, so a third
/// producer cannot admit accept-all by calling only the text check. An ABSENT matcher is the
/// caller's own default and is not passed here.
std::optional<std::string> validate_matcher_object(const nlohmann::json& matcher);

/// Server-authored binding of a kind-less column matcher to the instruction definition's
/// DECLARED output columns (field names in output order, from `result_schema` via
/// `ResponseTemplatesEngine::synthesise_default` -- the dashboard's own source). When
/// `matcher.column` is among them, stores `declared_columns` and `plugin` in `matcher` so
/// `response_matches` can resolve the column positionally in plain pipe rows. No-op otherwise.
/// REST and MCP both call this ONE function. `validate_matcher` refuses both keys from a caller.
void bind_declared_columns(nlohmann::json& matcher, const std::string& result_schema_json,
                           const std::string& plugin);

/// Count the rows in a tar `tar.sql` response `output`. The tar plugin emits
/// a `__schema__|col|col` header line, one `|`-joined line per row, then a
/// `__total__|N` trailer (see agents/plugins/tar do_sql). Returns N from the
/// trailer when present; otherwise counts data lines. An `error|...` output
/// (the tar failure shape) returns 0. Exposed for direct testing.
int tar_row_count(std::string_view output);

} // namespace yuzu::server::rs_matcher
