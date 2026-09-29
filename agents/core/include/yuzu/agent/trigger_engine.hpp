#pragma once

#include <yuzu/plugin.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace yuzu::agent {

// ── Trigger types ────────────────────────────────────────────────────────────

enum class TriggerType {
    Interval,      // Fires on a time interval (e.g., every 300 seconds)
    FileChange,    // Fires when a file/directory mtime changes
    ServiceStatus, // Fires when a service state matches expected_status
    AgentStartup,  // Fires once when the agent starts
    RegistryChange // Fires when a Windows registry key changes (Windows-only)
};

/// Convert a TriggerType to its string representation.
[[nodiscard]] constexpr const char* trigger_type_to_string(TriggerType t) noexcept {
    switch (t) {
    case TriggerType::Interval:
        return "interval";
    case TriggerType::FileChange:
        return "filesystem";
    case TriggerType::ServiceStatus:
        return "service";
    case TriggerType::AgentStartup:
        return "agent-startup";
    case TriggerType::RegistryChange:
        return "registry";
    }
    return "unknown";
}

/// Parse a string to TriggerType. Returns Interval as the default if unknown.
[[nodiscard]] inline TriggerType trigger_type_from_string(std::string_view s) noexcept {
    if (s == "interval")
        return TriggerType::Interval;
    if (s == "filesystem" || s == "file_change")
        return TriggerType::FileChange;
    if (s == "service" || s == "service_status")
        return TriggerType::ServiceStatus;
    if (s == "agent-startup" || s == "agent_startup" || s == "startup")
        return TriggerType::AgentStartup;
    if (s == "registry" || s == "registry_change")
        return TriggerType::RegistryChange;
    return TriggerType::Interval;
}

// ── Trigger configuration ────────────────────────────────────────────────────

struct TriggerConfig {
    std::string id; // unique trigger ID
    TriggerType type;
    std::string plugin;                            // plugin to invoke when triggered
    std::string action;                            // action to invoke when triggered
    std::map<std::string, std::string> parameters; // params passed to the plugin

    // Type-specific configuration
    int interval_seconds = 0;    // for Interval triggers (minimum 30)
    std::string watch_path;      // for FileChange triggers (file or directory)
    std::string service_name;    // for ServiceStatus triggers
    std::string expected_status; // for ServiceStatus triggers (e.g. "stopped", "running")
    std::string registry_hive;   // for RegistryChange triggers (e.g. "HKLM", "HKCU")
    std::string registry_key;    // for RegistryChange triggers (key path to watch)

    // Debounce
    int debounce_seconds = 0; // suppress re-fires within this window (0 = no debounce)
};

/**
 * Parse a plugin-supplied trigger registration into a TriggerConfig.
 *
 * Plugins register triggers across the C ABI by passing a `trigger_id`, a
 * `trigger_type` string, and a JSON `config_json` blob (the shape the SDK's
 * `Plugin::register_trigger` forwards). This is the single parse point that
 * turns that wire form into a typed TriggerConfig the engine accepts.
 *
 * Returns std::nullopt when the JSON is malformed, or when the resulting
 * trigger could never dispatch (empty `plugin` or `action`) — a useless
 * trigger is a registration bug, not something to silently keep.
 *
 * Recognised config_json keys: `plugin`, `action`, `interval_seconds`,
 * `watch_path`, `service_name`, `expected_status`, `registry_hive`,
 * `registry_key`, `debounce_seconds`, and an optional `parameters` object
 * (string values forwarded verbatim; non-string values are JSON-dumped).
 */
[[nodiscard]] YUZU_EXPORT std::optional<TriggerConfig>
parse_trigger_config(std::string_view id, std::string_view type, std::string_view config_json);

// ── Trigger engine ───────────────────────────────────────────────────────────

/**
 * TriggerEngine evaluates registered triggers and dispatches plugin actions
 * when conditions are met. It runs background worker threads for each trigger
 * type (interval, file watch, service watch) and fires startup triggers
 * immediately on start().
 *
 * Thread safety: register/unregister are safe to call from any thread while
 * the engine is running. The dispatch callback is invoked from worker threads.
 */
class YUZU_EXPORT TriggerEngine {
public:
    /// Default maximum number of registered triggers (configurable via set_max_triggers).
    static constexpr size_t kDefaultMaxTriggers = 2000;

    /// Callback type for dispatching triggered actions.
    using DispatchFn = std::function<void(const std::string& plugin, const std::string& action,
                                          const std::map<std::string, std::string>& params)>;

    TriggerEngine();
    ~TriggerEngine();

    TriggerEngine(const TriggerEngine&) = delete;
    TriggerEngine& operator=(const TriggerEngine&) = delete;

    /// Register a trigger. Safe to call while running.
    void register_trigger(TriggerConfig config);

    /// Unregister a trigger by ID. Safe to call while running.
    void unregister_trigger(const std::string& id);

    /// Set the callback invoked when a trigger fires.
    void set_dispatch(DispatchFn fn);

    /// Set the maximum number of triggers allowed (default: kDefaultMaxTriggers).
    void set_max_triggers(size_t limit);

    /// Start all monitoring loops. Fires AgentStartup triggers immediately.
    void start();

    /// Stop all monitoring loops and join worker threads.
    void stop();

    /// Returns the number of registered triggers.
    [[nodiscard]] size_t trigger_count() const;

    /// Returns true if the engine is currently running.
    [[nodiscard]] bool is_running() const noexcept;

    /// Validate service name (alphanumeric + ._@- only, blocks shell metacharacters).
    /// Public so callers can validate before creating triggers.
    [[nodiscard]] static bool is_valid_service_name(const std::string& name);

private:
    // Worker loops for each trigger type
    void interval_loop();
    void file_watch_loop();
    void service_watch_loop();
    void registry_watch_loop();
    void fire_startup_triggers();

    // Dispatch helper (applies debounce and calls dispatch_)
    void fire_trigger(const TriggerConfig& trigger);

    /// Wait up to `d` for stop(), waking IMMEDIATELY when it is called. Returns true if the
    /// engine is stopping, so a worker loop can `break` on it directly.
    ///
    /// Replaces the sleep_for() polling the loops used to do. A worker took up to 5s to notice
    /// the stop flag (the non-Windows registry loop slept a full 5s per iteration for a loop
    /// that does nothing at all), and stop() joins the workers SERIALLY -- which was most of an
    /// 8.6-13.5s agent shutdown. Docker's default stop grace is 10s, so containerised agents
    /// were being SIGKILLed mid-teardown.
    [[nodiscard]] bool wait_for_stop(std::chrono::milliseconds d);

    /// Park until stop() is called. For workers with no periodic work of their own.
    void await_stop();

    // Query service status (platform-specific)
    static std::string query_service_status(const std::string& service_name);

    // State
    std::vector<TriggerConfig> triggers_;
    mutable std::mutex mu_;
    std::atomic<bool> running_{false};
    std::vector<std::thread> workers_;

    // Shutdown signalling for the worker loops.
    //
    // LOST-WAKEUP CONTRACT, both halves load-bearing: stop() clears running_ *under* stop_mu_
    // and only then notifies, and wait_for_stop() evaluates its predicate under that same mutex
    // before blocking. Clear running_ outside the mutex and a worker can test it (still true),
    // then block -- after the notify has already fired -- and sleep out its full interval.
    //
    // NEVER hold stop_mu_ across the joins in stop(): the workers need it to evaluate the
    // predicate and exit, so holding it there deadlocks the join against the very threads it
    // is waiting on.
    std::mutex stop_mu_;
    std::condition_variable stop_cv_;
    DispatchFn dispatch_;
    size_t max_triggers_ = kDefaultMaxTriggers;

    // File watch state: trigger_id -> last known mtime
    std::map<std::string, std::filesystem::file_time_type> file_mtimes_;
    std::mutex file_mu_;

    // Service watch state: trigger_id -> last known status
    std::map<std::string, std::string> service_states_;
    std::mutex service_mu_;

    // Debounce state: trigger_id -> last fire time
    std::map<std::string, std::chrono::steady_clock::time_point> last_fire_times_;
    std::mutex debounce_mu_;
};

} // namespace yuzu::agent
