#pragma once

/// @file software_collection_settings_api.hpp
/// The per-management-group software collection settings (SAM-34) as transport-neutral
/// functions: the ONE body behind the four REST routes (software_collection_settings_routes.cpp)
/// and the four MCP twins (list_software_collection_settings, get_software_collection_settings,
/// set_software_collection_settings, get_software_host_collection_settings), so the two surfaces
/// cannot drift (docs/api-twin-recipe.md section 1).
///
/// No httplib and no MCP types. A surface runs its own coarse gate (the ManagementGroup:Read
/// permission for the list, the device-scoped Inventory:Read for the effective read), then calls a
/// function here. The two functions that decide authority themselves (`get`, `put`) take an
/// `AuthorityFn` that answers Admit / Deny / Degraded / Lapsed and writes its own response on the
/// last two; the function then returns `Kind::Handled`.
///
/// A PUT is audited ahead of the write (`requested`, fail-closed when the row cannot be stored),
/// re-checks the write grant immediately ahead of the store call, and is audited again with its
/// outcome. Saving never triggers a collection: this API has no dispatch or sync-runner
/// dependency. The audit verb is `software_estate.collection_settings.update` from both surfaces.

#include "collection_settings_resolve.hpp"
#include "management_group_store.hpp"
#include "plugin_config_store.hpp"
#include "software_collection_settings_store.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace yuzu::server::software_collection_settings_api {

inline constexpr const char* kVerbUpdate = "software_estate.collection_settings.update";
inline constexpr const char* kVerbRead = "software_estate.collection_settings.read"; // refusals only
inline constexpr const char* kGroupTargetType = "ManagementGroup";

/// The stores the functions read; all borrowed.
struct Stores {
    SoftwareCollectionSettingsStore* store{nullptr};
    ManagementGroupStore* mgmt_store{nullptr};
    PluginConfigStore* plugin_config_store{nullptr}; ///< the effective read only
};

/// False when a store the function needs is not wired (the surface answers 503, no retry hint).
[[nodiscard]] bool stores_ready(const Stores& s, bool needs_plugin_config = false);

struct Reply {
    enum class Kind {
        Ok,
        BadRequest,
        NotFound,
        Conflict,    ///< PUT only: `body` is the stored document (null when none exists)
        Forbidden,
        Unavailable,
        Handled ///< the AuthorityFn already wrote the surface's own response (a 503 or a 401)
    } kind{Kind::Ok};
    nlohmann::json body;                        ///< Ok: the `data` object
    std::string message;
    std::optional<std::int64_t> retry_after_ms; ///< Unavailable: set = retryable
    std::string remediation;
    bool audit_persisted{true}; ///< false = a landed write's OUTCOME row did not persist
};

/// The global ManagementGroup gate (the unavailable-aware probe) for `op` = "Read" or "Write".
/// Degraded = the RBAC read could not be completed, Lapsed = the session ended: on both the
/// function has already written the surface's response.
enum class Authority { Admit, Deny, Degraded, Lapsed };
using AuthorityFn = std::function<Authority(const char* op)>;

/// Persist one audit row against a ManagementGroup target. `signal_failure` is true for the rows
/// of a mutation's own sequence (the REST surface then flags a lost row on its response); false
/// for a refusal row. Returns false when the row did not persist.
using AuditSink = std::function<bool(const char* verb, const char* result, const std::string& target,
                                     const std::string& detail, bool signal_failure)>;

/// GET list: the fleet default plus every live group's document. The caller has been admitted by
/// ManagementGroup:Read.
[[nodiscard]] Reply list(const Stores& s);
/// GET one group's document. Decides authority itself (ManagementGroup:Read) and audits a refusal.
[[nodiscard]] Reply get(const Stores& s, const std::string& group_id, const AuthorityFn& authority,
                        const AuditSink& audit);
/// PUT one group's document from the JSON `body` text. `username` is the writing principal.
[[nodiscard]] Reply put(const Stores& s, const std::string& group_id, const std::string& body,
                        const std::string& username, const AuthorityFn& authority,
                        const AuditSink& audit);
/// GET the effective settings of one device. The caller has been admitted by the device-scoped
/// Inventory:Read.
[[nodiscard]] Reply effective(const Stores& s, const std::string& agent_id);

} // namespace yuzu::server::software_collection_settings_api
