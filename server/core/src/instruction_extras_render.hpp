#pragma once

/// @file instruction_extras_render.hpp
/// Pure helpers for the Instructions "extras" work: the YAML-save merge
/// (`merge_yaml_into_stored`) and the library fragment's building blocks
/// (limit clamp, approval label, truncation foot, sets panel). Nothing here
/// touches a store, a clock or a route; every user string is `html_escape`d.

#include "instruction_store.hpp"
#include "instruction_yaml.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace yuzu::server::instruction_extras {

/// Library page size: default and hard maximum for `GET /fragments/instructions?limit=`.
inline constexpr int kLibraryDefaultLimit = 100;
inline constexpr int kLibraryMaxLimit = 500;

/// Clamp a raw `limit` query value. Empty, non-numeric or non-positive input
/// yields the default; anything above the maximum yields the maximum.
int clamp_library_limit(const std::string& raw);

/// Build the definition an editor YAML save writes. The YAML carries only
/// nine scalar fields (`instruction_yaml::DefinitionFields`); every other
/// column of `stored` is carried forward so a save never resets them. For
/// `version`, `type`, `concurrency_mode` and `approval_mode` a value in the
/// YAML is an intentional edit and wins; when the YAML omits one the stored
/// value is kept (a stored empty value falls back to the create default).
/// `parameter_schema` is left empty: the store treats that as "keep".
InstructionDefinition merge_yaml_into_stored(const InstructionDefinition& stored,
                                             const instruction_yaml::DefinitionFields& fields,
                                             const std::string& yaml_source,
                                             const std::string& saved_by);

/// "No" / "Yes" / "Unless administrator"; an unrecognised mode reads as
/// "Unknown" rather than "No" (fail-closed wording).
const char* approval_label(const std::string& approval_mode);

/// Foot note for a truncated library list; empty string when not truncated.
std::string render_library_foot(int limit, bool truncated);

/// One set row for the sets panel: the set plus the number of definitions
/// that reference it.
struct SetRow {
    InstructionSet set;
    std::size_t members{0};
};

/// Read-only sets panel. `counts_partial` marks counts computed from a
/// capped definition read.
std::string render_instruction_sets_panel(const std::vector<SetRow>& rows, bool counts_partial);

/// Panel-level denied / degraded notes (HTTP 200 bodies, see SPEC 5.3).
std::string render_sets_denied();
std::string render_sets_degraded();
std::string render_library_degraded();

} // namespace yuzu::server::instruction_extras
