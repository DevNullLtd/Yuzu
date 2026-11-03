#pragma once

/**
 * echo_fold_schema.hpp -- the roll-up storage model's schema: per-source tier
 * columns, the DDL generator and the read-surface allowlists.
 *
 * Roll-up is the ONLY storage model. There is no setting, flag, mode switch or
 * environment variable that selects between raw capture rows and roll-ups, and
 * none may be added. This header declares that storage; no collector, aggregator
 * or action opens, writes or reads these tables.
 *
 * Shape (every fold source except `usage`, which keeps its own tables):
 *   echo_dict(id, text)              interned strings, one row per distinct text
 *   <src>_<tier>_r                   the physical roll-up table: a bucket column,
 *                                    interned keys as <key>_id, merged measures,
 *                                    VIRTUAL generated *_avg columns, ONE unique
 *                                    index (bucket, keys...) that is the UPSERT
 *                                    target and the retention bucket index
 *   <src>_<tier>                     a VIEW over the table: the registry tier's
 *                                    existing column names in their existing order
 *                                    first, then the new columns; text keys resolve
 *                                    through a correlated dictionary
 *                                    lookup (see generate_fold_ddl for why not a JOIN)
 *   echo_fold_seen                   the replay ring of the cursor sources
 *
 * Column order in FoldSourceDef::columns is the view order. Where the registry
 * already declares the tier, its columns come first and in their registry order,
 * so every consumer of the existing names keeps working; new columns follow. That
 * is why process keys read name, user, parent_name.
 */

#include "echo_schema_registry.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace yuzu::echo {

inline constexpr std::string_view kDictTable = "echo_dict";
inline constexpr std::string_view kSeenTable = "echo_fold_seen";

/// One capture source's roll-up declaration. `columns` excludes the bucket
/// column: it is derived from the tier by ts_column_for_suffix() and leads every
/// tier's table, unique index and view.
struct FoldSourceDef {
    std::string_view name;                 ///< registry name ("process", "tcp", ...)
    std::vector<std::string_view> tiers;   ///< "hourly" | "daily" | "monthly"
    std::vector<ColumnDef> columns;        ///< view order; roles kKey / kMeasure / kGenerated
    bool cursor_source = false;            ///< fed through the digest-checked replay ring
    bool own_tables = false;               ///< usage: declared for its columns, no DDL, no dictionary
};

/// All 17 registry sources, in registry order. Static storage, never mutated.
[[nodiscard]] const std::vector<FoldSourceDef>& fold_sources();

/// nullptr when `name` is not a registry source.
[[nodiscard]] const FoldSourceDef* fold_source(std::string_view name);

/// `<src>_<tier>` -- the view name every consumer queries.
[[nodiscard]] std::string fold_view_name(std::string_view source, std::string_view tier);

/// `<src>_<tier>_r` -- the physical table behind the view.
[[nodiscard]] std::string physical_table_name(std::string_view source, std::string_view tier);

/// Physical column name: `<name>_id` for an interned key, else `name`.
[[nodiscard]] std::string physical_column_name(const ColumnDef& col);

/// Every `<src>_<tier>` view name of every non-own_tables source.
[[nodiscard]] std::vector<std::string> fold_view_names();

/// DDL for echo_dict, echo_fold_seen, every `_r` table with its unique index and
/// every view. Idempotent (IF NOT EXISTS). Pure text; executes on any SQLite.
[[nodiscard]] std::string generate_fold_ddl();

/// True for a roll-up view name. Static-set lookup, like is_queryable_table().
[[nodiscard]] bool is_fold_view(std::string_view name);

/// True for echo_dict, echo_fold_seen and every `_r` table: the tables untrusted
/// operator SQL may reach ONLY through a fold view.
[[nodiscard]] bool is_fold_internal_table(std::string_view name);

/// True for the `_r` roll-up tables only (not the dictionary or the replay ring).
/// The authorizer lets a COLUMN-LESS read of one through (`SELECT COUNT(*) FROM
/// <view>` makes SQLite report a table-level read of the table behind the view with
/// no view context): such a read exposes a row count the view already exposes and no
/// column content.
[[nodiscard]] bool is_fold_row_table(std::string_view name);

/// The 16 `<src>_live` names: the raw-row tables that roll-up does not keep,
/// listed so a `$X_Live` read can be answered by an empty view instead of an
/// error. `usage_live` is excluded: usage keeps its own tables.
[[nodiscard]] std::vector<std::string> legacy_live_shim_names();

} // namespace yuzu::echo
