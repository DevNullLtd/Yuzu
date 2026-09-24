#pragma once

/**
 * local_dispatcher.hpp — agent-side in-process plugin dispatch.
 *
 * #1001 / arch-S3: PR 10 introduced an agent snapshot pump that needs
 * to invoke `tar.fleet_snapshot` locally and harvest its JSON payload
 * without touching the gRPC channel. The first implementation hand-wired
 * a `capture` pointer onto CommandContextImpl and branched
 * `flush_output_locked` on `capture != nullptr` to avoid null-deref on
 * `stream`. That smuggled two modes into a struct meant for one (the
 * gRPC streaming path) and bled into every future feature that needed
 * local-dispatch (periodic Guardian rule eval, agent-side health probes,
 * etc.) — the next adopter would copy the pattern and accrete another
 * mode-branch.
 *
 * LocalDispatcher is the single entry point for "run a plugin action
 * in-process and give me back its output". Callers shrink to a few
 * lines (cycle, log, ship to heartbeat). The capture buffer cap and
 * the truncation sentinel live here, not in CommandContextImpl.
 *
 * The cap matches the server-side `FleetTopologyStore::kPushedSnapshotMaxBytes`
 * (2 MiB). Snapshots above the cap are truncated with a sentinel suffix
 * so the server-side parser cleanly rejects the payload rather than
 * ingesting a half-finished structure; the dispatcher signals the
 * truncation through the `truncated` field on the result.
 *
 * BR-001 (Wave 5 PR5.1 whole-branch review): `result_status`/
 * `result_completeness`/`result_provenance` surface whatever the plugin
 * reported via `CommandContext::set_result_status()` (the ABI4 CC-07
 * result-status seam, `yuzu_ctx_set_result_status`), read back from the
 * SAME `CommandContextImpl` `dispatch_with_capture` already constructs --
 * same shape as `truncated` above, not a second dispatch mechanism. Added
 * so a unit test can prove a migrated plugin's `forward_runner_failure`
 * call (runner_status.hpp) actually reaches the host seam, not just that
 * the call site exists.
 */

#include <yuzu/plugin.h>

#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

namespace yuzu::agent {

class KvStore;

class YUZU_EXPORT LocalDispatcher {
public:
    struct Result {
        int rc{0};             ///< plugin's return code; 0 == success
        std::string captured;  ///< concatenated output (newline-joined)
        bool truncated{false}; ///< true iff capture hit the byte cap
        /// ABI4 CC-07 typed result the plugin reported via
        /// CommandContext::set_result_status(), if any -- UNDECLARED/UNKNOWN/
        /// empty when the plugin never called it (see the file header).
        YuzuResultStatus result_status{YUZU_RESULT_STATUS_UNDECLARED};
        YuzuResultCompleteness result_completeness{YUZU_RESULT_COMPLETENESS_UNKNOWN};
        std::string result_provenance;
    };

    /// Matches the server-side `FleetTopologyStore::kPushedSnapshotMaxBytes`.
    /// Snapshots that hit the cap are truncated with a sentinel; the server
    /// parser rejects malformed JSON rather than ingesting half a struct.
    static constexpr std::size_t kCaptureMaxBytes = 2ull * 1024 * 1024;

    /// Dispatch `action` on `descriptor` synchronously, in this thread.
    /// `params` is forwarded verbatim to the plugin (may be empty).
    /// Output written via `yuzu_ctx_write_output` is appended to
    /// `result.captured`. Bounded by `capture_cap` — defaults to
    /// kCaptureMaxBytes so the fleet-topology snapshot contract is untouched;
    /// a caller with a larger bounded payload (the installed_software sync's
    /// v2 rows, whose 12-field output outgrows 2 MiB around ~14k packages)
    /// passes its own cap explicitly rather than raising the shared default.
    Result run(const YuzuPluginDescriptor* descriptor, std::string_view action,
               std::span<const YuzuParam> params = {},
               std::size_t capture_cap = kCaptureMaxBytes);
};

/// A plugin context for an in-process host that is not the agent daemon
/// (tools/plugin-capture). Carries the configuration map every plugin reads
/// through `yuzu_ctx_get_config`; no trigger engine, and no KV store unless the
/// KvStore* overload is used, so the storage and trigger ABI calls fail closed
/// exactly as they do under the agent when those services are absent. Hand `get()` to `descriptor->init`
/// before the first dispatch and to `descriptor->shutdown` after the last,
/// in that order, so a plugin whose init is load-bearing (reads its config,
/// opens a store, stashes the context) behaves as it does under the real
/// host. The context must outlive every dispatch made against it.
class YUZU_EXPORT StandalonePluginContext {
public:
    StandalonePluginContext(std::string plugin_name,
                            std::unordered_map<std::string, std::string> config);
    /// As above, with a non-owning KV store so the storage ABI calls
    /// (`yuzu_ctx_storage_*`) work; `kv` must outlive this context.
    StandalonePluginContext(std::string plugin_name,
                            std::unordered_map<std::string, std::string> config, KvStore* kv);
    StandalonePluginContext(const StandalonePluginContext&) = delete;
    StandalonePluginContext& operator=(const StandalonePluginContext&) = delete;

    [[nodiscard]] YuzuPluginContext* get() const noexcept;

private:
    // PluginContextImpl is private to agent.cpp (it is what every yuzu_ctx_*
    // accessor reinterpret_casts a YuzuPluginContext* to); owned through a
    // type-erased deleter defined there.
    std::unique_ptr<void, void (*)(void*)> impl_;
};

} // namespace yuzu::agent
