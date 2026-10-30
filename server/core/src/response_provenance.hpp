#pragma once

/// #4990 (UP-7): server-authored provenance of a command response.
///
/// The plugin of a stored response decides its read tier (the Forensics tier is a per-plugin
/// property, enforced in the `ResponseStore` SQL filters) and the treatment of every derived sink
/// (live output stream, analytics event, notification, webhook, offload, execution tracker). That
/// plugin used to be parsed from the command id the AGENT echoes back, so an agent that mislabelled
/// the id chose the tier of what it returned.
///
/// The label now comes from a record the SERVER wrote when it dispatched the command
/// (`ExecutionTracker::record_command_dispatch`, written at the one dispatch chokepoint
/// `ServerImpl::build_classified_command`, before any frame is sent). This header is the pure
/// decision over that record, shared by both ingest paths (direct Subscribe and gateway proxy) so
/// they cannot disagree:
///   * a record with a plugin       -> verified, the label is the RECORDED plugin;
///   * no record, an unusable record (no plugin), or a degraded read after one retry
///                                   -> `kUnverifiedProvenanceLabel`.
/// The id's own text is never consulted.
///
/// `kUnverifiedProvenanceLabel` is added to the Forensics plugin set (`forensics_plugin_set.hpp`),
/// so a response with unresolved provenance is stored and treated as Forensics-tier by every SQL
/// filter and every sink with no per-consumer code: fail closed, by the existing mechanism.
///
/// What this does NOT prove (do not oversell it in docs or reviews): the record proves "the server
/// minted this command id for this plugin". An endpoint that was legitimately sent a command (or
/// was inside a broadcast of it) can still replay that id on a frame of its own and so label that
/// frame with that command's plugin. The record is not bound to the endpoint (a per-target row
/// would be needed) and the output's semantic content is not validated.
///
/// Header-only and dependency-free so it is unit-testable over a fake lookup.

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server {

/// The stored `plugin` label of a response whose provenance could not be resolved. Contains a
/// character (`~`) no plugin name can contain, so it can never collide with a real plugin, and is
/// storable in `responses.plugin` (TEXT NOT NULL, no CHECK or FK). Must stay a member of the
/// Forensics plugin set (`derive_forensics_plugin_set`).
inline constexpr std::string_view kUnverifiedProvenanceLabel = "~unverified";

/// What the server recorded when it dispatched one command id.
struct CommandRecord {
    std::string plugin;       ///< the dispatched plugin (the capability row's plugin); never empty
    std::string execution_id; ///< the tracked-execution / correlation id, or empty when none
};

/// One lookup of a command record. Returns nullopt for "no record" AND for a degraded read; the
/// two are told apart by `*degrade_reason` being set (non-empty) for a degrade, left untouched
/// otherwise (the contract `ExecutionTracker::lookup_command_record` has).
using CommandRecordLookupFn =
    std::function<std::optional<CommandRecord>(const std::string& command_id,
                                               std::string* degrade_reason)>;

enum class ProvenanceOutcome {
    kVerified,       ///< a usable server record was found
    kUnrecorded,     ///< no record (forged id, failed record write, reaped, empty id, unwired)
    kLookupDegraded, ///< the read failed twice (pool exhausted / query error)
};

struct ResponseProvenance {
    std::string plugin{kUnverifiedProvenanceLabel}; ///< recorded plugin, or the sentinel
    std::string execution_id;                       ///< from the record; empty when unverified
    ProvenanceOutcome outcome{ProvenanceOutcome::kUnrecorded};
    /// One entry per failed read attempt (the first attempt, and the retry when it also failed).
    std::vector<std::string> degrade_reasons;

    [[nodiscard]] bool verified() const noexcept { return outcome == ProvenanceOutcome::kVerified; }
};

/// The ONE decision. Called once per response frame on each ingest path; the result is passed to
/// every consumer of the frame (stored row, live output, failure text, analytics, tracker, audit).
/// `lookup` null (an unwired service) is unrecorded. A degraded read is retried ONCE (the read is
/// bounded by the pool's read timeout, so the retry bounds the frame's added latency); a second
/// failure is `kLookupDegraded` and the response is labelled unverified, never ordinary.
[[nodiscard]] inline ResponseProvenance
resolve_response_provenance(const std::string& command_id, const CommandRecordLookupFn& lookup) {
    ResponseProvenance out;
    if (command_id.empty() || !lookup)
        return out;
    for (int attempt = 0; attempt < 2; ++attempt) {
        std::string degrade;
        std::optional<CommandRecord> rec = lookup(command_id, &degrade);
        if (rec) {
            // A record without a plugin is not a provenance record: no production writer authors
            // one (the dispatch chokepoint always has a plugin), so it is treated as absent.
            if (rec->plugin.empty())
                return out;
            out.plugin = std::move(rec->plugin);
            out.execution_id = std::move(rec->execution_id);
            out.outcome = ProvenanceOutcome::kVerified;
            return out;
        }
        if (degrade.empty())
            return out; // a genuine miss: retrying cannot find a row that does not exist
        out.degrade_reasons.push_back(std::move(degrade));
    }
    out.outcome = ProvenanceOutcome::kLookupDegraded;
    return out;
}

} // namespace yuzu::server
