#include <yuzu/agent/trigger_engine.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)
#else
#include <yuzu/agent/fork_lock.hpp> // BR-001: process-wide fork/CLOEXEC serialization

#include <cstdio>
#endif

namespace yuzu::agent {

// ── Trigger-config parsing (C-ABI registration parse point) ──────────────────

std::optional<TriggerConfig> parse_trigger_config(std::string_view id, std::string_view type,
                                                  std::string_view config_json) {
    // The whole extraction is wrapped, not just parse(): nlohmann's
    // j.value()/get()/items() throw type_error on a key present with the
    // wrong JSON type (e.g. "interval_seconds":"60"). This function is the
    // C-ABI registration parse point — an exception escaping here would
    // cross the C ABI boundary in yuzu_register_trigger and be UB (gov R3).
    try {
        nlohmann::json j = nlohmann::json::parse(config_json);
        if (!j.is_object()) {
            spdlog::warn("parse_trigger_config('{}'): config JSON is not an object", id);
            return std::nullopt;
        }

        TriggerConfig cfg;
        cfg.id = std::string{id};
        cfg.type = trigger_type_from_string(type);
        cfg.plugin = j.value("plugin", std::string{});
        cfg.action = j.value("action", std::string{});

        // A trigger that names no plugin/action can never dispatch — that's a
        // registration bug, not a trigger worth keeping around.
        if (cfg.plugin.empty() || cfg.action.empty()) {
            spdlog::warn("parse_trigger_config('{}'): missing plugin or action — rejected", id);
            return std::nullopt;
        }

        cfg.interval_seconds = j.value("interval_seconds", 0);
        cfg.watch_path = j.value("watch_path", std::string{});
        cfg.service_name = j.value("service_name", std::string{});
        cfg.expected_status = j.value("expected_status", std::string{});
        cfg.registry_hive = j.value("registry_hive", std::string{});
        cfg.registry_key = j.value("registry_key", std::string{});
        cfg.debounce_seconds = j.value("debounce_seconds", 0);

        if (auto it = j.find("parameters"); it != j.end() && it->is_object()) {
            for (const auto& [key, val] : it->items()) {
                cfg.parameters[key] = val.is_string() ? val.get<std::string>() : val.dump();
            }
        }

        return cfg;
    } catch (const std::exception& e) {
        spdlog::warn("parse_trigger_config('{}'): malformed or ill-typed config JSON: {}", id,
                     e.what());
        return std::nullopt;
    }
}

// ── Construction / destruction ───────────────────────────────────────────────

TriggerEngine::TriggerEngine() = default;

TriggerEngine::~TriggerEngine() {
    stop();
}

// ── Public API ───────────────────────────────────────────────────────────────

void TriggerEngine::register_trigger(TriggerConfig config) {
    // Enforce minimum interval of 30 seconds
    if (config.type == TriggerType::Interval && config.interval_seconds < 30) {
        spdlog::warn("Trigger '{}': interval {} < 30s minimum, clamping to 30s", config.id,
                     config.interval_seconds);
        config.interval_seconds = 30;
    }

    std::lock_guard lock(mu_);

    // Replace if trigger with same ID already exists
    auto it = std::find_if(triggers_.begin(), triggers_.end(),
                           [&](const TriggerConfig& t) { return t.id == config.id; });
    if (it != triggers_.end()) {
        spdlog::info("Trigger '{}' replaced (type={})", config.id,
                     trigger_type_to_string(config.type));
        *it = std::move(config);
    } else {
        // Enforce maximum trigger count to prevent resource exhaustion
        if (triggers_.size() >= max_triggers_) {
            spdlog::warn("Trigger '{}' rejected: maximum trigger count ({}) reached", config.id,
                         max_triggers_);
            return;
        }
        spdlog::info("Trigger '{}' registered (type={}, plugin={}, action={})", config.id,
                     trigger_type_to_string(config.type), config.plugin, config.action);
        triggers_.push_back(std::move(config));
    }
}

void TriggerEngine::unregister_trigger(const std::string& id) {
    std::lock_guard lock(mu_);
    auto it = std::find_if(triggers_.begin(), triggers_.end(),
                           [&](const TriggerConfig& t) { return t.id == id; });
    if (it != triggers_.end()) {
        spdlog::info("Trigger '{}' unregistered", id);
        triggers_.erase(it);
    } else {
        spdlog::warn("Trigger '{}' not found for unregister", id);
    }
}

void TriggerEngine::set_dispatch(DispatchFn fn) {
    std::lock_guard lock(mu_);
    dispatch_ = std::move(fn);
}

void TriggerEngine::set_max_triggers(size_t limit) {
    std::lock_guard lock(mu_);
    max_triggers_ = limit;
    spdlog::info("TriggerEngine: max triggers set to {}", limit);
}

void TriggerEngine::start() {
    if (running_.exchange(true)) {
        spdlog::warn("TriggerEngine::start() called but already running");
        return;
    }

    spdlog::info("TriggerEngine starting ({} triggers registered)", triggers_.size());

    // Fire startup triggers immediately (on the calling thread, before workers start)
    fire_startup_triggers();

    // Launch worker threads for each polling trigger type
    workers_.emplace_back([this]() { interval_loop(); });
    workers_.emplace_back([this]() { file_watch_loop(); });
    workers_.emplace_back([this]() { service_watch_loop(); });
    workers_.emplace_back([this]() { registry_watch_loop(); });

    spdlog::info("TriggerEngine started with 4 worker threads");
}

bool TriggerEngine::wait_for_stop(std::chrono::milliseconds d) {
    std::unique_lock lock(stop_mu_);
    return stop_cv_.wait_for(lock, d,
                             [this] { return !running_.load(std::memory_order_acquire); });
}

void TriggerEngine::await_stop() {
    std::unique_lock lock(stop_mu_);
    stop_cv_.wait(lock, [this] { return !running_.load(std::memory_order_acquire); });
}

void TriggerEngine::stop() {
    {
        // Clear running_ UNDER stop_mu_ — see the member's lost-wakeup note. Clearing it outside
        // lets a worker read it as still-true, then block after the notify has already fired,
        // and sleep out its whole interval.
        std::lock_guard lock(stop_mu_);
        if (!running_.exchange(false)) {
            return; // already stopped or never started
        }
    }
    // Notify with the mutex RELEASED, and before the joins — never while holding stop_mu_ across
    // them, or the join deadlocks against the workers that need it to wake.
    stop_cv_.notify_all();

    spdlog::info("TriggerEngine stopping...");

    for (auto& t : workers_) {
        if (t.joinable()) {
            t.join();
        }
    }
    workers_.clear();

    spdlog::info("TriggerEngine stopped");
}

size_t TriggerEngine::trigger_count() const {
    std::lock_guard lock(mu_);
    return triggers_.size();
}

bool TriggerEngine::is_running() const noexcept {
    return running_.load(std::memory_order_acquire);
}

// ── Dispatch helper ──────────────────────────────────────────────────────────

void TriggerEngine::fire_trigger(const TriggerConfig& trigger) {
    // Debounce check
    if (trigger.debounce_seconds > 0) {
        std::lock_guard lock(debounce_mu_);
        auto now = std::chrono::steady_clock::now();
        auto it = last_fire_times_.find(trigger.id);
        if (it != last_fire_times_.end()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second);
            if (elapsed.count() < trigger.debounce_seconds) {
                spdlog::debug("Trigger '{}' debounced ({}s < {}s)", trigger.id, elapsed.count(),
                              trigger.debounce_seconds);
                return;
            }
        }
        last_fire_times_[trigger.id] = now;
    }

    if (!dispatch_) {
        spdlog::warn("Trigger '{}' fired but no dispatch callback set", trigger.id);
        return;
    }

    spdlog::info("Trigger '{}' fired -> plugin={}, action={}", trigger.id, trigger.plugin,
                 trigger.action);
    try {
        dispatch_(trigger.plugin, trigger.action, trigger.parameters);
    } catch (const std::exception& e) {
        spdlog::error("Trigger '{}' dispatch threw: {}", trigger.id, e.what());
    }
}

// ── Startup triggers ─────────────────────────────────────────────────────────

void TriggerEngine::fire_startup_triggers() {
    std::lock_guard lock(mu_);
    for (const auto& trigger : triggers_) {
        if (trigger.type == TriggerType::AgentStartup) {
            spdlog::info("Firing startup trigger '{}'", trigger.id);
            fire_trigger(trigger);
        }
    }
}

// ── Interval loop ────────────────────────────────────────────────────────────

void TriggerEngine::interval_loop() {
    spdlog::debug("TriggerEngine: interval_loop started");

    // Track last fire time per trigger for interval calculation
    std::map<std::string, std::chrono::steady_clock::time_point> last_fired;

    while (running_.load(std::memory_order_acquire)) {
        // Wakes the instant stop() is called, rather than sleeping out the tick.
        if (wait_for_stop(std::chrono::seconds{1}))
            break;

        auto now = std::chrono::steady_clock::now();

        // Take a snapshot of interval triggers
        std::vector<TriggerConfig> snapshot;
        {
            std::lock_guard lock(mu_);
            for (const auto& t : triggers_) {
                if (t.type == TriggerType::Interval) {
                    snapshot.push_back(t);
                }
            }
        }

        for (const auto& trigger : snapshot) {
            auto it = last_fired.find(trigger.id);
            if (it == last_fired.end()) {
                // First time seeing this trigger: record now, fire on next interval
                last_fired[trigger.id] = now;
                continue;
            }

            auto elapsed =
                std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
            if (elapsed >= trigger.interval_seconds) {
                fire_trigger(trigger);
                last_fired[trigger.id] = now;
            }
        }

        // Clean up entries for triggers that were unregistered
        for (auto it = last_fired.begin(); it != last_fired.end();) {
            bool found = false;
            for (const auto& t : snapshot) {
                if (t.id == it->first) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                it = last_fired.erase(it);
            } else {
                ++it;
            }
        }
    }

    spdlog::debug("TriggerEngine: interval_loop stopped");
}

// ── File watch loop ──────────────────────────────────────────────────────────

void TriggerEngine::file_watch_loop() {
    spdlog::debug("TriggerEngine: file_watch_loop started");

    while (running_.load(std::memory_order_acquire)) {
        // Poll every 5 seconds — but wake at once on stop().
        if (wait_for_stop(std::chrono::seconds{5}))
            break;

        // Take a snapshot of file change triggers
        std::vector<TriggerConfig> snapshot;
        {
            std::lock_guard lock(mu_);
            for (const auto& t : triggers_) {
                if (t.type == TriggerType::FileChange) {
                    snapshot.push_back(t);
                }
            }
        }

        for (const auto& trigger : snapshot) {
            if (trigger.watch_path.empty()) {
                continue;
            }

            std::error_code ec;
            auto path = std::filesystem::path{trigger.watch_path};

            // Use canonical path to handle symlinks (important on macOS /var -> /private/var)
            auto canonical = std::filesystem::canonical(path, ec);
            if (ec) {
                // File doesn't exist yet, or path invalid — record as "no mtime"
                std::lock_guard lock(file_mu_);
                file_mtimes_.erase(trigger.id);
                continue;
            }

            auto current_mtime = std::filesystem::last_write_time(canonical, ec);
            if (ec) {
                continue;
            }

            std::lock_guard lock(file_mu_);
            auto it = file_mtimes_.find(trigger.id);
            if (it == file_mtimes_.end()) {
                // First observation — record but don't fire
                file_mtimes_[trigger.id] = current_mtime;
                spdlog::debug("Trigger '{}': baseline mtime recorded for '{}'", trigger.id,
                              trigger.watch_path);
            } else if (current_mtime != it->second) {
                // Mtime changed — fire!
                it->second = current_mtime;
                spdlog::info("Trigger '{}': file change detected on '{}'", trigger.id,
                             trigger.watch_path);
                fire_trigger(trigger);
            }
        }
    }

    spdlog::debug("TriggerEngine: file_watch_loop stopped");
}

// ── Service watch loop ───────────────────────────────────────────────────────

void TriggerEngine::service_watch_loop() {
    spdlog::debug("TriggerEngine: service_watch_loop started");

    while (running_.load(std::memory_order_acquire)) {
        // Poll every 30 seconds — but wake at once on stop().
        if (wait_for_stop(std::chrono::seconds{30}))
            break;

        // Take a snapshot of service status triggers
        std::vector<TriggerConfig> snapshot;
        {
            std::lock_guard lock(mu_);
            for (const auto& t : triggers_) {
                if (t.type == TriggerType::ServiceStatus) {
                    snapshot.push_back(t);
                }
            }
        }

        for (const auto& trigger : snapshot) {
            if (trigger.service_name.empty()) {
                continue;
            }

            auto status = query_service_status(trigger.service_name);
            if (status.empty()) {
                continue;
            }

            std::lock_guard lock(service_mu_);
            auto it = service_states_.find(trigger.id);
            bool first_observation = (it == service_states_.end());

            if (first_observation) {
                // Record baseline
                service_states_[trigger.id] = status;
                spdlog::debug("Trigger '{}': service '{}' baseline status = '{}'", trigger.id,
                              trigger.service_name, status);
            } else if (status != it->second) {
                // Status changed
                std::string old_status = it->second;
                it->second = status;
                spdlog::info("Trigger '{}': service '{}' changed from '{}' to '{}'", trigger.id,
                             trigger.service_name, old_status, status);

                // Fire if the new status matches expected_status, or if expected_status is
                // empty (meaning: fire on any change)
                if (trigger.expected_status.empty() || status == trigger.expected_status) {
                    fire_trigger(trigger);
                }
            }
        }
    }

    spdlog::debug("TriggerEngine: service_watch_loop stopped");
}

// ── Registry watch loop (Windows-only) ───────────────────────────────────────

#ifdef _WIN32

void TriggerEngine::registry_watch_loop() {
    spdlog::debug("TriggerEngine: registry_watch_loop started");

    // Map trigger_id -> HKEY handle for notification
    std::map<std::string, HKEY> watched_keys;
    std::map<std::string, HANDLE> watch_events;

    auto cleanup = [&]() {
        for (auto& [id, evt] : watch_events) {
            if (evt)
                CloseHandle(evt);
        }
        for (auto& [id, key] : watched_keys) {
            if (key)
                RegCloseKey(key);
        }
        watched_keys.clear();
        watch_events.clear();
    };

    auto parse_hive = [](const std::string& hive) -> HKEY {
        if (hive == "HKLM")
            return HKEY_LOCAL_MACHINE;
        if (hive == "HKCU")
            return HKEY_CURRENT_USER;
        if (hive == "HKCR")
            return HKEY_CLASSES_ROOT;
        if (hive == "HKU")
            return HKEY_USERS;
        return nullptr;
    };

    while (running_.load(std::memory_order_acquire)) {
        // Take a snapshot of registry change triggers
        std::vector<TriggerConfig> snapshot;
        {
            std::lock_guard lock(mu_);
            for (const auto& t : triggers_) {
                if (t.type == TriggerType::RegistryChange) {
                    snapshot.push_back(t);
                }
            }
        }

        // Register new watches and clean up stale ones
        for (const auto& trigger : snapshot) {
            if (watched_keys.contains(trigger.id))
                continue; // already watching

            if (trigger.registry_key.empty() || trigger.registry_hive.empty()) {
                spdlog::warn("Trigger '{}': registry_hive and registry_key are required",
                             trigger.id);
                continue;
            }

            HKEY root = parse_hive(trigger.registry_hive);
            if (!root) {
                spdlog::warn("Trigger '{}': invalid registry hive '{}'", trigger.id,
                             trigger.registry_hive);
                continue;
            }

            // Convert key path to wide via the shared helper (#1681). Only wkey.c_str()
            // is consumed below, so the size difference vs the old -1 convert (which kept
            // the trailing NUL in .size()) is immaterial here.
            const std::wstring wkey = yuzu::win::to_wide(trigger.registry_key);

            HKEY opened = nullptr;
            if (RegOpenKeyExW(root, wkey.c_str(), 0, KEY_NOTIFY | KEY_READ, &opened) !=
                ERROR_SUCCESS) {
                spdlog::warn("Trigger '{}': failed to open registry key '{}'", trigger.id,
                             trigger.registry_key);
                continue;
            }

            HANDLE evt = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!evt) {
                RegCloseKey(opened);
                continue;
            }

            // Request notification for any change to the key or its values
            LONG rc =
                RegNotifyChangeKeyValue(opened, TRUE,
                                        REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_ATTRIBUTES |
                                            REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY,
                                        evt, TRUE);

            if (rc != ERROR_SUCCESS) {
                spdlog::warn("Trigger '{}': RegNotifyChangeKeyValue failed (error {})", trigger.id,
                             rc);
                CloseHandle(evt);
                RegCloseKey(opened);
                continue;
            }

            watched_keys[trigger.id] = opened;
            watch_events[trigger.id] = evt;
            spdlog::info("Trigger '{}': watching registry key '{}\\{}'", trigger.id,
                         trigger.registry_hive, trigger.registry_key);
        }

        // Check all watched events
        for (auto it = watch_events.begin(); it != watch_events.end();) {
            DWORD wait = WaitForSingleObject(it->second, 0);
            if (wait == WAIT_OBJECT_0) {
                // Change detected — fire the trigger
                spdlog::info("Trigger '{}': registry change detected", it->first);

                // Find the trigger config
                for (const auto& t : snapshot) {
                    if (t.id == it->first) {
                        fire_trigger(t);
                        break;
                    }
                }

                // Re-register the notification
                ResetEvent(it->second);
                auto key_it = watched_keys.find(it->first);
                if (key_it != watched_keys.end()) {
                    RegNotifyChangeKeyValue(key_it->second, TRUE,
                                            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_ATTRIBUTES |
                                                REG_NOTIFY_CHANGE_LAST_SET |
                                                REG_NOTIFY_CHANGE_SECURITY,
                                            it->second, TRUE);
                }
                ++it;
            } else {
                ++it;
            }
        }

        // Poll every 2 seconds — but wake at once on stop().
        if (wait_for_stop(std::chrono::seconds{2}))
            break;
    }

    cleanup();
    spdlog::debug("TriggerEngine: registry_watch_loop stopped");
}

#else // Non-Windows: no-op

void TriggerEngine::registry_watch_loop() {
    spdlog::debug("TriggerEngine: registry_watch_loop is a no-op on this platform");
    // No registry on Linux/macOS: this thread has NOTHING to do but exit when asked. It used to
    // poll `while (running_) sleep_for(5s)`, so it took up to 5 SECONDS to notice the stop flag
    // — for a loop that does no work at all — and stop() joins the workers serially, making this
    // the single largest contributor to an 8.6–13.5s agent shutdown. Docker's default stop grace
    // is 10s, so that was getting containerised agents SIGKILLed mid-teardown. Park on the
    // condvar instead: zero wakeups while running, and it returns the instant stop() notifies.
    await_stop();
}

#endif

// ── Service name validation ───────────────────────────────────────────────────

bool TriggerEngine::is_valid_service_name(const std::string& name) {
    // Service names must be alphanumeric + dots, underscores, hyphens, @
    // This blocks ALL shell metacharacters (;, &, |, `, $, (, ), etc.)
    if (name.empty() || name.size() > 256)
        return false;
    for (char c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '_' && c != '-' &&
            c != '@') {
            return false;
        }
    }
    return true;
}

// ── Platform-specific service status query ───────────────────────────────────

#ifdef _WIN32

std::string TriggerEngine::query_service_status(const std::string& service_name) {
    // Validate service name to prevent injection
    if (!is_valid_service_name(service_name)) {
        spdlog::warn("Rejected invalid service name: '{}'", service_name);
        return {};
    }

    // Open the Service Control Manager
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        spdlog::debug("Failed to open SCM: error {}", GetLastError());
        return {};
    }

    SC_HANDLE svc = OpenServiceA(scm, service_name.c_str(), SERVICE_QUERY_STATUS);
    if (!svc) {
        spdlog::debug("Failed to open service '{}': error {}", service_name, GetLastError());
        CloseServiceHandle(scm);
        return {};
    }

    SERVICE_STATUS_PROCESS ssp{};
    DWORD bytes_needed = 0;
    if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp),
                              sizeof(ssp), &bytes_needed)) {
        spdlog::debug("Failed to query service '{}' status: error {}", service_name,
                      GetLastError());
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return {};
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    switch (ssp.dwCurrentState) {
    case SERVICE_STOPPED:
        return "stopped";
    case SERVICE_START_PENDING:
        return "start_pending";
    case SERVICE_STOP_PENDING:
        return "stop_pending";
    case SERVICE_RUNNING:
        return "running";
    case SERVICE_CONTINUE_PENDING:
        return "continue_pending";
    case SERVICE_PAUSE_PENDING:
        return "pause_pending";
    case SERVICE_PAUSED:
        return "paused";
    default:
        return "unknown";
    }
}

#elif defined(__APPLE__)

std::string TriggerEngine::query_service_status(const std::string& service_name) {
    // Validate service name to prevent command injection
    if (!is_valid_service_name(service_name)) {
        spdlog::warn("Rejected invalid service name: '{}'", service_name);
        return {};
    }

    // On macOS, use launchctl to check if a service is loaded and running
    std::string cmd = "launchctl list " + service_name + " 2>/dev/null";
    FILE* pipe;
    {
        // BR-001: popen() forks internally, so it is itself a launcher --
        // hold the process-wide fork lock across the call so it can't land
        // mid-window of another launcher's unprotected [pipe()..fork()]
        // (see fork_lock.hpp's contract). Released as soon as popen()
        // returns; never held across the read loop or pclose() below.
        std::lock_guard<std::mutex> fork_pipe_lock(global_fork_lock());
        pipe = popen(cmd.c_str(), "r");
    }
    if (!pipe) {
        return {};
    }

    char buf[256]{};
    std::string output;
    while (fgets(buf, sizeof(buf), pipe)) {
        output += buf;
    }
    int rc = pclose(pipe);

    // launchctl list <label> returns 0 if the service is loaded
    if (rc != 0) {
        return "not_loaded";
    }

    // Parse the output: look for "PID" line to determine if running
    // Format: { "LimitLoadToSessionType" = "System"; "Label" = "com.apple.foo"; "PID" = 123; };
    if (output.find("\"PID\"") != std::string::npos) {
        return "running";
    }
    return "loaded";
}

#else // Linux

std::string TriggerEngine::query_service_status(const std::string& service_name) {
    // Validate service name to prevent command injection
    if (!is_valid_service_name(service_name)) {
        spdlog::warn("Rejected invalid service name: '{}'", service_name);
        return {};
    }

    // On Linux, use systemctl is-active to check service status
    std::string cmd = "systemctl is-active " + service_name + " 2>/dev/null";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return {};
    }

    char buf[128]{};
    std::string output;
    while (fgets(buf, sizeof(buf), pipe)) {
        output += buf;
    }
    pclose(pipe);

    // Trim trailing whitespace/newlines
    while (!output.empty() &&
           (output.back() == '\n' || output.back() == '\r' || output.back() == ' ')) {
        output.pop_back();
    }

    // systemctl is-active returns: active, inactive, failed, activating, deactivating, etc.
    if (output.empty()) {
        return "unknown";
    }

    // Map systemd states to our canonical states
    if (output == "active") {
        return "running";
    }
    if (output == "inactive") {
        return "stopped";
    }
    if (output == "failed") {
        return "failed";
    }
    // Return as-is for other states (activating, deactivating, etc.)
    return output;
}

#endif

} // namespace yuzu::agent
