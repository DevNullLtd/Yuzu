#pragma once

/// @file software_lifecycle_routes.hpp
/// REST routes for the imported software lifecycle rule set (SAM-24, roadmap SAM.7):
///
///   POST   /api/v1/inventory/software/lifecycle/rules?format=csv|cle&name=<file name>
///   GET    /api/v1/inventory/software/lifecycle/rules[?source=imported|shipped|external]
///   DELETE /api/v1/inventory/software/lifecycle/rules
///
/// The rule set is fleet-global (a rule is keyed by product, never by device), so every route
/// takes the GLOBAL `Inventory` permission through `perm_fn`: `Write` for POST and DELETE, `Read`
/// for GET. There is no fleet-read scope to narrow it. A POST carries the raw file as its body
/// and REPLACES the whole `imported` set; `shipped` and `external` rules are never touched. A
/// DELETE empties the `imported` set only.
///
/// A POST or DELETE is audited ahead of the write (`requested`, fail-closed 503 when the row
/// cannot be stored, nothing written) and again with its outcome. No lock or store lease is held
/// across an audit write. A closed or missing store answers 503 with a retry hint on every route,
/// never an empty 200.
///
/// The formats are exactly the enumerators of `lifecycle_import::Format`, resolved through
/// `lifecycle_import::parse_format`. `kFormatTokens` is the one place the route spells them for
/// its 400 text; the unit test pins it to `parse_format`.
///
/// Registered from server.cpp ahead of `RestApiV1::register_routes`, because the generic
/// `GET /api/v1/inventory/{a}/{b}` pattern would otherwise be tried first.

#include "http_route_sink.hpp"
#include "software_lifecycle_store.hpp"

#include <httplib.h>

#include <array>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server {

/// The format tokens the import route offers (the 400 text, the OpenAPI enum and the docs name
/// exactly these). Each must resolve through `lifecycle_import::parse_format`.
inline constexpr std::array<std::string_view, 2> kLifecycleImportFormatTokens{"csv", "cle"};

/// Most bytes a `name` (the rules' `source_reference`) may hold.
inline constexpr std::size_t kLifecycleImportNameMaxBytes = 128;

/// First defect of an import file name, or nullopt. 1..128 bytes and no control character (NUL,
/// tab, CR, LF and DEL included); UTF-8 validity is the rule model's own check, applied by the
/// parser to the `source_reference` it stamps.
[[nodiscard]] inline std::optional<std::string_view>
lifecycle_import_name_defect(std::string_view name) {
    if (name.empty() || name.size() > kLifecycleImportNameMaxBytes)
        return "name must be 1 to 128 bytes";
    for (const char c : name)
        if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f)
            return "name must not contain control characters";
    return std::nullopt;
}

/// The `source` a GET may list: imported (the default), shipped or external. `declared` is not a
/// rule source, and anything else is nullopt.
[[nodiscard]] inline std::optional<LifecycleSource>
lifecycle_rules_listable_source(std::string_view token) {
    if (token == "imported")
        return LifecycleSource::imported;
    if (token == "shipped")
        return LifecycleSource::shipped;
    if (token == "external")
        return LifecycleSource::external;
    return std::nullopt;
}

class SoftwareLifecycleRoutes {
public:
    /// Global permission gate (wraps require_permission); false == the response is written.
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type,
                                      const std::string& operation)>;
    using AuditFn = std::function<bool(const httplib::Request& req, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    struct Deps {
        PermFn perm_fn; ///< Inventory:Read / Inventory:Write, global (fails closed on a degrade)
        AuditFn audit_fn;
        SoftwareLifecycleStore* store{nullptr}; ///< borrowed; null answers 503
    };

    void register_routes(HttpRouteSink& sink, Deps deps);
};

} // namespace yuzu::server
