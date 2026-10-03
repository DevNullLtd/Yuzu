#pragma once

/**
 * Wire format for the `tar status` action's storage-health lines.
 *
 * Extracted from TarPlugin because that class is TU-local and therefore
 * untestable, and these particular lines are load-bearing in a way the rest of
 * the status output is not: the ORDER is a contract with the server.
 *
 * `tar status`'s output is consumed by `tar_tree_routes.cpp` (the capture-
 * sources frame) and by `poll_command`, which treats any non-empty output as
 * success and gates failure on `output.starts_with("error|")`. When the offline
 * report led with `storage_state|`, that gate missed, the frame fell through to
 * the capture-sources renderer -- which parses only `config|` lines -- and drew
 * all ten sources blank. A dead endpoint rendered identically to a healthy one,
 * on the one frame an operator opens to ask why a device's data is missing.
 *
 * So `error|` MUST come first on the offline path, and that is what this header
 * exists to let a test assert. See `tar.yaml` and `docs/user-manual/tar.md`.
 */

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::tar {

/// The complete `tar status` reply for a store that has failed closed, in the
/// order it must be written.
///
/// @param query_engine_available whether the read-only connection (`tar sql`)
///        is usable. It survives the wedged-transaction close by construction --
///        that close takes the WRITE connection -- but it is optional at open
///        time, and promising a read path that is not there sends an operator
///        down a dead end during the one incident where they are already blind.
[[nodiscard]] inline std::vector<std::string>
format_storage_offline_lines(bool query_engine_available) {
    const std::string_view read_path =
        query_engine_available
            ? "Historical data remains readable via `tar sql`."
            : "The read-only query connection is unavailable too, so `tar sql` cannot read the "
              "historical data either.";
    return {
        // FIRST, and the reason this function exists. Do not reorder.
        std::string{"error|TAR storage is offline on this endpoint; the database was closed "
                    "after a transaction could not be rolled back. Collection and retention "
                    "are both stopped. "}
            .append(read_path)
            .append(" Restart the agent to recover."),
        "storage_state|offline",
    };
}

/// `db_health|<ok|quarantined>|<epoch>` (#1567). `quarantined` iff THIS open
/// quarantined a corrupt tar.db (epoch = when); otherwise `ok` with the epoch of
/// the last persisted quarantine (0 = never).
[[nodiscard]] inline std::string format_db_health_line(bool quarantined_this_open,
                                                       int64_t last_epoch) {
    return std::string{"db_health|"} + (quarantined_this_open ? "quarantined|" : "ok|") +
           std::to_string(last_epoch);
}

} // namespace yuzu::tar
