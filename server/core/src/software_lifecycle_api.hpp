#pragma once

/// @file software_lifecycle_api.hpp
/// The imported software lifecycle rule set (SAM-24) as transport-neutral functions: the ONE body
/// behind the three REST routes (software_lifecycle_routes.cpp) and the three MCP twins
/// (list_software_lifecycle_rules, import_software_lifecycle_rules,
/// delete_software_lifecycle_rules), so the two surfaces cannot drift (docs/api-twin-recipe.md
/// section 1).
///
/// No httplib and no MCP types. A surface runs its own gate first (the GLOBAL `Inventory:Write`
/// permission for an import or a delete, `Inventory:Read` for the list), then calls a function
/// here, which carries the whole sequence after that gate: the name defect, the format token, the
/// parse, the store check, the fail-closed `requested` audit row, the store write and the outcome
/// row. An import or a delete is audited ahead of the write and again with its outcome; no lock or
/// store lease is held across an audit write.
///
/// The audit verbs are `software_estate.lifecycle_rules.import`, `.delete` and `.read` (refusals
/// only) from both surfaces.

#include "software_lifecycle_store.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server::software_lifecycle_api {

inline constexpr const char* kVerbImport = "software_estate.lifecycle_rules.import";
inline constexpr const char* kVerbDelete = "software_estate.lifecycle_rules.delete";
inline constexpr const char* kVerbRead = "software_estate.lifecycle_rules.read"; // refusals only
inline constexpr const char* kTargetType = "Inventory";

struct Reply {
    enum class Kind {
        Ok,
        BadRequest, ///< a refusal the caller's input caused; a retry fails identically
        Unavailable ///< a store or audit condition; `retry_after_ms` set = retryable
    } kind{Kind::Ok};
    nlohmann::json body;                        ///< Ok: the `data` object
    std::string message;
    std::optional<std::int64_t> retry_after_ms; ///< Unavailable: set = retryable
    std::string remediation;
    bool audit_persisted{true}; ///< false = a landed write's OUTCOME row did not persist
};

/// Persist one audit row (target type `Inventory`). `signal_failure` is true for the rows of a
/// mutation's own sequence (the REST surface then flags a lost row on its response); false for a
/// refusal row. Returns false when the row did not persist.
using AuditSink = std::function<bool(const char* verb, const char* result, const std::string& target,
                                     const std::string& detail, bool signal_failure)>;

/// POST: replace the whole imported set from `content`. `name` is the file name stamped on every
/// rule as its source reference and `format_token` is `csv` or `cle`; either is nullopt when the
/// surface did not receive exactly one value (the function then answers the same refusal as for a
/// bad one). The store may be null (a surface that has not wired it).
[[nodiscard]] Reply import_rules(SoftwareLifecycleStore* store,
                                 const std::optional<std::string_view>& name,
                                 const std::optional<std::string_view>& format_token,
                                 std::string_view content, const AuditSink& audit);

/// GET: one source's rules. `source_token` is `imported` (the default when the surface has none),
/// `shipped` or `external`; a surface that received the parameter more than once passes an empty
/// token, which is refused like any other unknown source.
[[nodiscard]] Reply list_rules(SoftwareLifecycleStore* store, std::string_view source_token,
                               const AuditSink& audit);

/// DELETE: empty the imported set. `shipped` and `external` rules are never touched.
[[nodiscard]] Reply delete_rules(SoftwareLifecycleStore* store, const AuditSink& audit);

} // namespace yuzu::server::software_lifecycle_api
