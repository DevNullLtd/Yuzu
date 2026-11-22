#pragma once

/// @file software_curation_api.hpp
/// The software-title normalisation curation surface (SAM spec row 4.3) as transport-neutral
/// functions: the ONE body behind the five REST routes (software_curation_routes.cpp) and the five
/// MCP twins (get_software_normalization_status, list_software_curation_queue,
/// curate_software_alias, reject_software_curation, replace_software_normalization_pack), so the
/// two surfaces cannot drift (docs/api-twin-recipe.md section 1).
///
/// No httplib and no MCP types. A surface runs its own gate first (a GLOBAL `Inventory:Read` or
/// `Inventory:Write`; a service-scoped token is refused by the surface), then calls a function
/// here, which carries the whole sequence after that gate: the field and key validation, the
/// fail-closed `requested` audit row for a write, the store call and the answer. Every write is
/// audited BEFORE the store is touched; a write has a `requested` row and no outcome row. The
/// store owns the dimension invalidation contract (product_registry_store.hpp), so no function
/// here writes the registry other than through it.
///
/// Every function requires a non-null `registry` (a surface that has not wired it answers its own
/// 503 / internal error first).

#include "product_registry_store.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server::software_curation_api {

// Audit verbs. The two read verbs appear only as a `denied` row a surface writes (a service-scoped
// token's refusal); an admitted read is never audited by this layer.
inline constexpr const char* kVerbStatus = "inventory.software.curation.status";
inline constexpr const char* kVerbQueue = "inventory.software.curation.queue";
inline constexpr const char* kVerbAlias = "inventory.software.curation.alias";
inline constexpr const char* kVerbReject = "inventory.software.curation.reject";
inline constexpr const char* kVerbPack = "inventory.software.curation.pack";
inline constexpr const char* kTargetType = "Inventory";

/// Default page size of the queue read when the caller names none.
inline constexpr int kDefaultQueueLimit = 100;

struct Reply {
    enum class Kind {
        Ok,
        Created,     ///< the alias write: REST answers 201
        BadRequest,  ///< caller input; a retry fails identically
        NotFound,    ///< reject of a key with no open queue entry
        Conflict,    ///< a pack whose version is already stored
        Unavailable  ///< a store or audit condition; `retry_after_ms` set = retryable
    } kind{Kind::Ok};
    nlohmann::json body; ///< Ok / Created: the `data` object
    std::string message;
    std::optional<std::int64_t> retry_after_ms; ///< Unavailable: set = retryable
    std::string remediation;
};

/// Persist one audit row (target type `Inventory`). `signal_failure` is true for the
/// `requested` row of a write (the REST surface then flags a lost row on its response); false for
/// a refusal row. Returns false when the row did not persist.
using AuditSink = std::function<bool(const char* verb, const char* result, const std::string& target,
                                     const std::string& detail, bool signal_failure)>;

/// Pack version, title and queue counts.
[[nodiscard]] Reply status(ProductRegistryStore* registry);

/// One page of the curation queue. `status_token` is `open` (the default when nullopt), `rejected` or
/// `all`; `limit_text` is the integer text (1 to kCurationQueueMaxLimit, default kDefaultQueueLimit
/// when nullopt) and `cursor` the opaque token of the previous page (empty = the first page).
[[nodiscard]] Reply queue(ProductRegistryStore* registry,
                          const std::optional<std::string_view>& status_token,
                          const std::optional<std::string_view>& limit_text, std::string_view cursor);

/// Curate one title from a JSON object of string fields: ecosystem, raw_name, raw_publisher,
/// vendor, product, edition, category, cpe_product. Answers Created on success. A body that is
/// not a JSON object (a discarded parse included) is a refusal.
[[nodiscard]] Reply curate_alias(ProductRegistryStore* registry, const nlohmann::json& body,
                                 const AuditSink& audit);

/// Reject one OPEN queue entry named by its opaque `key`.
[[nodiscard]] Reply reject(ProductRegistryStore* registry, std::string_view key,
                           const AuditSink& audit);

/// Replace the stored normalisation pack from its CSV text. `username` is the writing principal.
[[nodiscard]] Reply replace_pack(ProductRegistryStore* registry, std::string_view content,
                                 const std::string& username, const AuditSink& audit);

} // namespace yuzu::server::software_curation_api
