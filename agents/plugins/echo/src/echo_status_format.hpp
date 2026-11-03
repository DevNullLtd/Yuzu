#pragma once

/**
 * Wire format for the `echo status` action's storage-health lines.
 *
 * Extracted from EchoPlugin because that class is TU-local and therefore
 * untestable, and these particular lines are load-bearing in a way the rest of
 * the status output is not: the ORDER is a contract with the server.
 *
 * `echo status`'s output is consumed by `echo_tree_routes.cpp` (the capture-
 * sources frame) and by `poll_command`, which treats any non-empty output as
 * success and gates failure on `output.starts_with("error|")`. When the offline
 * report led with `storage_state|`, that gate missed, the frame fell through to
 * the capture-sources renderer -- which parses only `config|` lines -- and drew
 * all ten sources blank. A dead endpoint rendered identically to a healthy one,
 * on the one frame an operator opens to ask why a device's data is missing.
 *
 * So `error|` MUST come first on the offline path, and that is what this header
 * exists to let a test assert. See `echo.yaml` and `docs/user-manual/echo.md`.
 */

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::echo {

/// The complete `echo status` reply for a store that has failed closed, in the
/// order it must be written.
///
/// @param query_engine_available whether the read-only connection (`echo sql`)
///        is usable. It survives the wedged-transaction close by construction --
///        that close takes the WRITE connection -- but it is optional at open
///        time, and promising a read path that is not there sends an operator
///        down a dead end during the one incident where they are already blind.
[[nodiscard]] inline std::vector<std::string>
format_storage_offline_lines(bool query_engine_available) {
    const std::string_view read_path =
        query_engine_available
            ? "Historical data remains readable via `echo sql`."
            : "The read-only query connection is unavailable too, so `echo sql` cannot read the "
              "historical data either.";
    return {
        // FIRST, and the reason this function exists. Do not reorder.
        std::string{"error|Echo storage is offline on this endpoint; the database was closed "
                    "after a transaction could not be rolled back. Collection and retention "
                    "are both stopped. "}
            .append(read_path)
            .append(" Restart the agent to recover."),
        "storage_state|offline",
    };
}

/// The prefix of EchoDatabase::open's refusal when the v10 roll-up migration finds less than twice
/// the database file free on its volume (echo_db_v10_migration.cpp). The plugin tells that refusal
/// from every other open failure by this text.
inline constexpr std::string_view kFreeSpaceRefusalPrefix = "not enough free disk space to migrate";

[[nodiscard]] inline bool is_free_space_refusal(std::string_view open_error) {
    return open_error.find(kFreeSpaceRefusalPrefix) != std::string_view::npos;
}

/// The complete `echo status` reply when the database was never opened because the migration was
/// refused for lack of free disk space, in the order it must be written (`error|` FIRST, for the
/// reason format_storage_offline_lines documents). The reason is always `free_space`; `detail` is
/// the open error, which names the two figures. The plugin has loaded but nothing collects and no
/// trigger is registered: restart the agent once the space is freed.
[[nodiscard]] inline std::vector<std::string> format_storage_refused_lines(std::string_view detail) {
    return {
        std::string{"error|Echo storage is offline on this endpoint: "}
            .append(detail)
            .append(". Collection and retention are stopped and the database was not changed. "
                    "Restart the agent after freeing the space."),
        "storage_state|offline|free_space",
    };
}

/// `db_health|<ok|quarantined>|<epoch>` (#1567). `quarantined` iff THIS open
/// quarantined a corrupt echo.db (epoch = when); otherwise `ok` with the epoch of
/// the last persisted quarantine (0 = never).
[[nodiscard]] inline std::string format_db_health_line(bool quarantined_this_open,
                                                       int64_t last_epoch) {
    return std::string{"db_health|"} + (quarantined_this_open ? "quarantined|" : "ok|") +
           std::to_string(last_epoch);
}

} // namespace yuzu::echo
