#pragma once

/// @file software_read_api.hpp
/// The installed-software v3 reads (SAM-33) as transport-neutral functions: the ONE body behind
/// the five REST routes (software_read_routes.cpp) and the five MCP twins (list_software_hosts,
/// get_software_host, list_software_changes, get_software_summary, get_software_plugin_health),
/// so the two surfaces cannot drift (docs/api-twin-recipe.md section 1).
///
/// No httplib and no MCP types: a function takes the parsed query bag, the caller's scope (the
/// fleet-read gate has already run on the caller's surface, and it is the SOLE authorization,
/// ADR-0017 admit-then-filter), a correlation id for the audit text and an audit sink, and returns
/// a `Reply` the surface maps to its own envelope. Every function checks `Ctx::ready` first, so a
/// surface that has run its gate gets the same "store not available" answer without repeating it.
///
/// The scope rules live in these functions: a host outside the caller's scope and an unknown host
/// answer the same NotFound and the out-of-scope arm does no read; a confined caller's summary and
/// plugin-health are LIVE aggregates (or nulls with `omitted = scope`), never the fleet snapshot.

#include "authz_model.hpp"
#include "offline_endpoint_types.hpp"
#include "software_catalog_rollup.hpp"
#include "software_catalogue_model.hpp"
#include "software_changes_model.hpp"
#include "software_hosts_model.hpp"
#include "software_inventory_store.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu::server::software_read_api {

using Params = software_catalogue::Params;

/// The device table's roster (see SoftwareReadRoutes::RosterFn): a failed read is nullopt, never
/// an empty roster.
using RosterFn = std::function<std::optional<OfflineRoster>()>;
/// The current fleet snapshot, or null before the first successful refresh.
using SnapshotFn = std::function<std::shared_ptr<const SoftwareFleetSnapshot>()>;
using NowFn = std::function<std::int64_t()>; ///< epoch seconds; empty = the system clock

/// The store reads, injectable so the logic is testable without Postgres.
struct Reads {
    software_hosts::HostsReader hosts;
    software_changes::ChangesReader changes;
    software_catalogue::DevicesReader installs;
    std::function<std::optional<std::unordered_map<std::string, std::int64_t>>(
        const std::vector<std::string>&)>
        last_seen;
    std::function<std::optional<std::vector<FacetHealth>>(
        const std::optional<std::vector<std::string>>&)>
        facet_health;
    std::function<std::optional<SoftwareSummary>(std::int64_t,
                                                 const std::optional<std::vector<std::string>>&)>
        summary;
    std::function<std::optional<CatalogRollupMeta>()> catalog_meta;
};

struct RosterView {
    software_hosts::Roster names;
    bool truncated{false};
};

/// What every read needs: the reads resolved, and the "is anything to read from" decision made
/// once (`make_ctx`).
struct Ctx {
    Reads reads;
    RosterFn roster_fn;
    SnapshotFn snapshot_fn;
    NowFn now_fn;
    bool ready{false};

    [[nodiscard]] std::int64_t now() const;
    /// For a decision made FROM the roster (the `q` search): nullopt = unwired, or the read failed.
    [[nodiscard]] std::optional<RosterView> checked_roster() const;
    /// Display-only: a roster that is not wired or cannot be read leaves the names null.
    [[nodiscard]] software_hosts::Roster roster() const;
};

/// Bind every read the caller left empty to `store`; `ready` is true when every read is bound.
[[nodiscard]] Ctx make_ctx(Reads reads, RosterFn roster_fn, SnapshotFn snapshot_fn, NowFn now_fn,
                           SoftwareInventoryStore* store);

struct Reply {
    enum class Kind { Ok, BadRequest, NotFound, Unavailable } kind{Kind::Ok};
    nlohmann::json body;                         ///< Ok: the `data` object
    std::string message;                         ///< every other kind
    std::optional<std::int64_t> retry_after_ms;  ///< Unavailable: set = retryable
    std::string remediation;                     ///< Unavailable (retryable)
};

/// Persist one audit row: false = the row did not persist (the data is still served). The sink
/// owns the verb and the target type; the function supplies the result, target and detail text.
using AuditSink = std::function<bool(const std::string& result, const std::string& target,
                                     const std::string& detail)>;

/// GET .../hosts and list_software_hosts. `cid` is the caller's correlation id (audit text only).
[[nodiscard]] Reply hosts(const Ctx& c, const Params& params, const authz::VisibleSet& scope,
                          const std::string& cid, const AuditSink& audit);
/// GET .../hosts/{agent_id} and get_software_host. Only `cursor` and `limit` are read from `params`.
[[nodiscard]] Reply host(const Ctx& c, const std::string& agent_id, const Params& params,
                         const authz::VisibleSet& scope, const std::string& cid,
                         const AuditSink& audit);
/// GET .../changes and list_software_changes.
[[nodiscard]] Reply changes(const Ctx& c, const Params& params, const authz::VisibleSet& scope,
                            const std::string& cid, const AuditSink& audit);
/// GET .../summary and get_software_summary.
[[nodiscard]] Reply summary(const Ctx& c, const authz::VisibleSet& scope, const std::string& cid,
                            const AuditSink& audit);
/// GET .../plugin-health and get_software_plugin_health.
[[nodiscard]] Reply plugin_health(const Ctx& c, const authz::VisibleSet& scope,
                                  const std::string& cid, const AuditSink& audit);

// ── MCP argument handling (pure) ─────────────────────────────────────────────

/// One accepted MCP argument. `kString` is bounded by `max` bytes; `kInt` by [min, max].
struct ArgSpec {
    enum class Type { kString, kInt } type;
    const char* key;
    std::int64_t min;
    std::int64_t max;
};

/// MCP is strict where REST clamps or ignores: an unknown key, a wrongly typed value, an over-long
/// string or an out-of-range integer is refused with the returned kInvalidParams text. nullopt =
/// acceptable; a null `args` means no arguments and any other non-object is refused.
[[nodiscard]] std::optional<std::string> strict_args_error(const nlohmann::json& args,
                                                          std::span<const ArgSpec> allowed);

/// The accepted arguments as the REST query bag the shared parsers read (an integer is
/// stringified). Call only after `strict_args_error` returned nullopt.
[[nodiscard]] Params args_to_params(const nlohmann::json& args, std::span<const ArgSpec> allowed);

} // namespace yuzu::server::software_read_api
