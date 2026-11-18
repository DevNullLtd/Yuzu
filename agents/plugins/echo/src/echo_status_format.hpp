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

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
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
/// the database file (plus its write-ahead log) free on its volume (echo_db_v10_migration.cpp). The plugin tells that refusal
/// from every other open failure by this text.
inline constexpr std::string_view kFreeSpaceRefusalPrefix = "not enough free disk space to migrate";

[[nodiscard]] inline bool is_free_space_refusal(std::string_view open_error) {
    return open_error.find(kFreeSpaceRefusalPrefix) != std::string_view::npos;
}

/// The prefixes of EchoDatabase::open's two refusals that mean the v10 roll-up step did not
/// complete (echo_db.cpp builds both messages from these, so the text and the classifier cannot
/// drift): the step itself failed, or an earlier migration step had not finished so the roll-up
/// step waited. Both leave the database untouched at its old schema version.
inline constexpr std::string_view kV10MigrationFailedPrefix = "v10 roll-up migration failed";
inline constexpr std::string_view kEarlierStepPrefix = "an earlier migration step did not finish";
/// Inside the v10 failure text when the attempt hit its wall-clock deadline (echo_db_v10_migration.cpp
/// builds the message from this; the retry loop counts a hit by finding it, to double the next deadline).
inline constexpr std::string_view kV10DeadlineMarker = "did not finish inside its";

/// Why Echo loaded offline at open (the plugin is present, nothing collects, the open is retried).
/// `none` = the failure is not one of the retried kinds and `init` fails as it always did.
/// The tokens are mirrored by server/core/src/echo_storage_offline_tag.hpp.
enum class OfflineReason { none, free_space, migration_failed, open_failed };

[[nodiscard]] constexpr std::string_view offline_reason_token(OfflineReason reason) noexcept {
    switch (reason) {
    case OfflineReason::free_space:
        return "free_space";
    case OfflineReason::migration_failed:
        return "migration_failed";
    case OfflineReason::open_failed:
        return "open_failed";
    case OfflineReason::none:
        break;
    }
    return "";
}

/// The plugin KV key the agent's heartbeat bridge publishes as the status tag
/// `yuzu.plugin.echo.storage_offline` (agents/core plugin_heartbeat_tags.hpp); its value is the
/// reason token. The server's fleet gauge (server/core/src/echo_storage_offline_tag.hpp) mirrors
/// the tag and the three tokens as literals; a test on each side pins them.
inline constexpr std::string_view kStorageOfflineKey = "heartbeat.storage_offline";

/// Tell the retried open failures from every other one by the wrapper text open() puts at the
/// START of each: `v10 roll-up migration failed ...` (echo_db.cpp wraps every migrate_to_v10
/// failure, the free-space refusal included, in it) or `schema vN: an earlier migration step did
/// not finish ...`. Both are matched at their fixed offset, never anywhere in the text: open()'s
/// other failures carry the data-directory path, and a directory named after a wrapper phrase must
/// not turn a fail-init refusal into offline-with-retry. The free-space text is looked for only
/// under the v10 anchor, because only migrate_to_v10 produces it.
/// The one limit left: the link refusal leads with the file name (echo_db.cpp), so a RELATIVE data
/// directory whose own name begins with a wrapper phrase could still match; an absolute path cannot.
[[nodiscard]] inline OfflineReason classify_open_failure(std::string_view open_error) {
    if (open_error.starts_with(kV10MigrationFailedPrefix))
        return is_free_space_refusal(open_error) ? OfflineReason::free_space
                                                 : OfflineReason::migration_failed;
    if (open_error.starts_with("schema v")) {
        const auto sep = open_error.find(": ");
        if (sep != std::string_view::npos && open_error.substr(sep + 2).starts_with(kEarlierStepPrefix))
            return OfflineReason::migration_failed;
    }
    return OfflineReason::none;
}

/// Whether an open failure's text says the attempt ran into its wall-clock deadline (the next
/// attempt's deadline is doubled for each such hit). The text is the v10 migration's own, so it is
/// looked for only under the same wrapper anchor as classify_open_failure.
[[nodiscard]] inline bool is_deadline_hit(std::string_view open_error) {
    return open_error.starts_with(kV10MigrationFailedPrefix) &&
           open_error.find(kV10DeadlineMarker) != std::string_view::npos;
}

/// The reason a RETRY attempt's failure is recorded under: the classified reason, or `open_failed`
/// for any failure that is not one of the first-open kinds (a failure on a later attempt never
/// fails the plugin; it stays offline).
[[nodiscard]] inline OfflineReason retry_failure_reason(std::string_view open_error) {
    const auto reason = classify_open_failure(open_error);
    return reason == OfflineReason::none ? OfflineReason::open_failed : reason;
}

/// The complete `echo status` reply when the database is not open because an open failed with a
/// retried reason, in the order it must be written (`error|` FIRST, for the reason
/// format_storage_offline_lines documents). `detail` is the open error. The plugin has loaded but
/// nothing collects and no trigger is registered. `next_retry_in` is the wait until the next
/// automatic attempt; `nullopt` means none is scheduled (collection failed to start after a late
/// open, so only an agent restart recovers) and the reply says so instead of promising a retry.
///
/// The fixed state and the retry or restart clause come BEFORE the detail: the dashboard shows only
/// the first 400 bytes of line 0 after `error|` (web_utils.hpp agent_error_display), and a real
/// free-space refusal alone is about 470 bytes, so a detail written first would cut the guidance
/// off. Keep the fixed text short and free of '-'.
[[nodiscard]] inline std::vector<std::string>
format_storage_refused_lines(OfflineReason reason, std::string_view detail,
                             std::optional<std::chrono::seconds> next_retry_in) {
    std::string line0 = "error|Echo storage is offline on this endpoint. ";
    if (!next_retry_in) {
        // The open itself succeeded (and may have migrated), so no "not changed" claim here.
        line0.append("Collection and retention are stopped. The open is not retried; restart the agent.");
    } else {
        line0.append("Collection and retention are stopped and the database was not changed. "
                     "The open is retried automatically. ")
            .append(next_retry_in->count() > 0
                        ? std::format("The next attempt is in about {} s.", next_retry_in->count())
                        : std::string{"Retrying now."});
    }
    line0.append(" Cause: ").append(detail);
    return {
        std::move(line0),
        std::format("storage_state|offline|{}", offline_reason_token(reason)),
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

/// `partial|applied|<k1,k2,...>` (#2155): the line `echo.configure` writes, ahead of its error
/// line, when a write failed AFTER some earlier ones persisted. Keys are the config keys that did
/// persist, in the order they were written. Empty (no line at all) when nothing persisted: that
/// reply is the flat error alone, never a "partial" one.
[[nodiscard]] inline std::string format_configure_partial(const std::vector<std::string>& applied) {
    if (applied.empty())
        return {};
    std::string line = "partial|applied|";
    for (std::size_t i = 0; i < applied.size(); ++i) {
        if (i != 0)
            line += ',';
        line += applied[i];
    }
    return line;
}

} // namespace yuzu::echo
