#pragma once

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <atomic>
#include <chrono>
#include <expected>
#include <filesystem>
#include <mutex>
#include <string>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::agent {

struct UpdateError {
    std::string message;
};

struct UpdateConfig {
    bool enabled{true};
    std::chrono::seconds check_interval{6 * 3600}; // 6 hours

    /// Detached-signature policy for the downloaded binary (#416/#3807),
    /// mirroring PluginSigningPolicy so an operator configures both the same way.
    ///
    /// The bundle is the operator's code-signing trust anchor, placed on disk at
    /// install time — deliberately NOT fetched over the update channel, since a
    /// trust anchor delivered by the party being verified anchors nothing.
    std::filesystem::path signature_trust_bundle;

    /// When true, a package with no signature is REFUSED. Defaults false because
    /// a fleet upgrading from a pre-signing release has no signed packages yet,
    /// and there is no status-report RPC, so a mandatory flag flipped too early
    /// strands agents silently. An invalid signature is refused in BOTH modes —
    /// only absence is tolerated.
    bool require_signature{false};

    /// Signature checking is off entirely when no bundle is configured; there is
    /// nothing to verify against, and inventing a default anchor would be worse
    /// than being explicit.
    [[nodiscard]] bool signature_checking_enabled() const noexcept {
        return !signature_trust_bundle.empty();
    }

    /// True when the configuration would set enforcement that nothing reads.
    ///
    /// `require_signature` is only consulted inside the
    /// `signature_checking_enabled()` branch, so requiring signatures with no
    /// bundle configured sets a flag that never fires: every update would apply
    /// unverified while the operator believed enforcement was on. `main()`
    /// refuses to start on this. It is a predicate rather than an inline check
    /// so it is testable — `main.cpp` is not part of any test target, which is
    /// how two external reviewers came to flag the guard as unproven.
    [[nodiscard]] bool would_fail_open() const noexcept {
        return require_signature && !signature_checking_enabled();
    }

    /// Optional metrics sink, so a signature refusal is visible to something
    /// other than a local log line.
    ///
    /// This is the closest thing to the "audited" half of #3807 the update path
    /// can currently offer. There is no status-report RPC on the update surface,
    /// and the agent has NO /metrics endpoint — so a counter alone would be
    /// write-only. The total is therefore carried on the heartbeat as
    /// `yuzu.ota_signature_refused` (agent.cpp), which is the agent's only
    /// outbound telemetry channel, and the server derives the fleet gauge
    /// `yuzu_fleet_ota_signature_refusing_agents` from it
    /// (agent_registry.cpp::recompute_metrics). That gauge is the operator-facing
    /// end of this: without it the counter would be write-only, which is what an
    /// earlier round of this change shipped.
    ///
    /// Null in tests and wherever no registry exists.
    yuzu::MetricsRegistry* metrics{nullptr};
};

class YUZU_EXPORT Updater {
public:
    Updater(UpdateConfig config, std::string agent_id, std::string current_version, std::string os,
            std::string arch, std::filesystem::path exe_path);
    ~Updater() = default;

    Updater(const Updater&) = delete;
    Updater& operator=(const Updater&) = delete;
    Updater(Updater&&) = delete;
    Updater& operator=(Updater&&) = delete;

    /// Check for update via gRPC stub, download, verify, apply.
    /// Returns true if update applied and process should restart.
    /// The stub parameter is AgentService::Stub* (void* to avoid proto header in public header).
    [[nodiscard]] std::expected<bool, UpdateError> check_and_apply(void* stub);

    /// On startup: delete .old files from successful prior updates.
    void cleanup_old_binary();

    /// On startup: if .old exists and current binary seems broken, roll back.
    [[nodiscard]] bool rollback_if_needed();

    void stop() noexcept;

private:
    UpdateConfig config_;
    std::string agent_id_;
    std::string current_version_;
    std::string os_;
    std::string arch_;
    std::filesystem::path exe_path_;
    std::atomic<bool> stop_requested_{false};
    // In-flight OTA RPC context (a grpc::ClientContext*, held as void* so this
    // public header stays free of the proto/grpc include — same reason the stub
    // is passed as void*). Published by check_and_apply() around the blocking
    // CheckForUpdate / DownloadUpdate calls and TryCancel'd by stop(), so a
    // shutdown during a stalled OTA RPC unblocks the call rather than hanging
    // the update-thread join (#1434 UP-1).
    //
    // ctx_mu_ SERIALISES THE PUBLISH/RETRACT AGAINST THE CANCEL, and is not optional.
    // The context is a STACK object in the update thread's frame, and stop() TryCancel()s it
    // from ANOTHER thread (run()'s reconnect teardown, the shutdown watcher, or the Windows
    // SCM thread) — so without this lock the owner can retract, pop the frame and be joined
    // while stop() sits between its load() and its TryCancel(): a use-after-free on a
    // destroyed ClientContext. This is the SAME defect that was found and fixed three times
    // over in AgentImpl (governance Gate-8 rounds 7-8); an earlier comment here described
    // the window as "matching the long-standing AgentImpl::heartbeat_ctx_ pattern", which was
    // true and was precisely the problem. Every store AND every load+TryCancel of the slot
    // below takes this mutex — there are no bare accesses, in this file or any other.
    std::mutex ctx_mu_;
    std::atomic<void*> active_rpc_ctx_{nullptr};

#ifndef _WIN32
    /// POSIX-only binary replacement with rollback on failure.
    ///
    /// On Windows the apply is performed inline in check_and_apply via
    /// SetFileInformationByHandle on the held HANDLE (see W2.3 cross-
    /// platform-debt closure). A path-based fallback on Windows would
    /// re-introduce the close-then-rename race window — keep this
    /// declaration compile-time-absent on Windows.
    [[nodiscard]] std::expected<bool, UpdateError>
    apply_update(const std::filesystem::path& temp_path);
#endif
};

/// Get the path to the currently running executable (cross-platform).
YUZU_EXPORT std::filesystem::path current_executable_path();

} // namespace yuzu::agent
