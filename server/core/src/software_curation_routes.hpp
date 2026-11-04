#pragma once

/// @file software_curation_routes.hpp
/// REST routes for the software-title normalisation curation queue (SAM spec row 4.3):
///
///   GET  /api/v1/inventory/software/normalization/status
///   GET  /api/v1/inventory/software/normalization/queue?status=open|rejected|all&limit&cursor
///   POST /api/v1/inventory/software/normalization/aliases
///   POST /api/v1/inventory/software/normalization/queue/{key}/reject
///   POST /api/v1/inventory/software/normalization/pack
///
/// The queue and the pack are fleet-wide derived data with no per-device scope: every route needs
/// a GLOBAL grant (`Inventory:Read` to read, `Inventory:Write` to change), so a management-group
/// confined caller and a service-scoped token are refused. Every POST is audited BEFORE the store
/// is touched and fails closed (503 + `Sec-Audit-Failed`) when the audit row cannot be stored.
/// The store owns the dimension invalidation contract (product_registry_store.hpp).

#include "http_route_sink.hpp"
#include "product_registry_store.hpp"

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server {

/// Pure codecs for the opaque tokens the queue hands out (unit-tested without a store).
namespace curation_keys {

/// Decoded-size bound of a queue key: three fields of at most the title-triple bound.
inline constexpr std::size_t kMaxKeyBytes = 2400;

struct Triple {
    std::string raw_name;
    std::string raw_publisher;
    std::string ecosystem;
};

/// `base64url(raw_name 0x1F raw_publisher 0x1F ecosystem)`. nullopt when a field itself carries
/// the 0x1F separator (the key could not be decoded back unambiguously).
[[nodiscard]] std::optional<std::string> encode_key(const Triple& t);
/// nullopt for anything `encode_key` could not have produced: non-canonical base64url, over
/// `kMaxKeyBytes`, not exactly three fields, an empty raw_name or ecosystem.
[[nodiscard]] std::optional<Triple> decode_key(std::string_view key);

/// The keyset position as an opaque token: `base64url(device_count 0x1F <key fields>)`.
[[nodiscard]] std::optional<std::string> encode_cursor(const CurationCursor& c);
[[nodiscard]] std::optional<CurationCursor> decode_cursor(std::string_view token);

} // namespace curation_keys

class SoftwareCurationRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    /// Global permission gate (wraps require_permission); false == response already written.
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type,
                                      const std::string& operation)>;
    using AuditFn = std::function<bool(const httplib::Request& req, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    struct Deps {
        AuthFn auth_fn;
        PermFn perm_fn;
        AuditFn audit_fn;
        ProductRegistryStore* registry{nullptr}; ///< borrowed; null answers 503
    };

    void register_routes(HttpRouteSink& sink, Deps deps);
};

} // namespace yuzu::server
