/**
 * yuzu/plugin.hpp — Ergonomic C++23 wrapper around the C plugin ABI
 *
 * Use this header when writing plugins in C++. It provides:
 *
 *   - yuzu::Plugin   — CRTP base class for plugins
 *   - yuzu::Context  — RAII wrapper around YuzuCommandContext
 *   - YUZU_PLUGIN_EXPORT(ClassName)  — generates the required C export
 *
 * The C ABI (plugin.h) is still what the agent loads; this header just makes
 * it nicer to implement from C++.
 */

#pragma once

#include "plugin.h"

#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace yuzu {

// ── Error type ────────────────────────────────────────────────────────────────

struct PluginError {
    int code;
    std::string message;
};

template <typename T> using Result = std::expected<T, PluginError>;

// ── Parameter access ──────────────────────────────────────────────────────────

class Params {
public:
    explicit Params(std::span<const YuzuParam> raw) noexcept : raw_{raw} {}

    [[nodiscard]] std::string_view get(std::string_view key,
                                       std::string_view def = {}) const noexcept {
        for (const auto& p : raw_) {
            if (p.key && key == p.key)
                return p.value ? p.value : def;
        }
        return def;
    }

    [[nodiscard]] bool has(std::string_view key) const noexcept {
        for (const auto& p : raw_) {
            if (p.key && key == p.key)
                return true;
        }
        return false;
    }

private:
    std::span<const YuzuParam> raw_;
};

// ── Command context wrapper ───────────────────────────────────────────────────

class CommandContext {
public:
    explicit CommandContext(YuzuCommandContext* raw) noexcept : raw_{raw} {}

    void write_output(std::string_view text) {
        yuzu_ctx_write_output(raw_, std::string{text}.c_str());
    }

    void report_progress(int percent) { yuzu_ctx_report_progress(raw_, percent); }

    /**
     * Report the CC-07 typed result status for the command currently
     * executing (ABI v4+). Optional — a plugin that never calls this leaves
     * the status YUZU_RESULT_STATUS_UNDECLARED and the agent derives a
     * coarse one from execute()'s int return code instead. See
     * yuzu_ctx_set_result_status() in plugin.h for the full contract.
     */
    void set_result_status(YuzuResultStatus status, YuzuResultCompleteness completeness,
                           std::string_view provenance = {}) {
        const std::string owned{provenance};
        yuzu_ctx_set_result_status(raw_, status, completeness,
                                   owned.empty() ? nullptr : owned.c_str());
    }

private:
    YuzuCommandContext* raw_;
};

// ── Plugin context wrapper ────────────────────────────────────────────────────

class PluginContext {
public:
    explicit PluginContext(YuzuPluginContext* raw) noexcept : raw_{raw} {}

    /** Returns the underlying C context pointer (for caching across calls). */
    [[nodiscard]] YuzuPluginContext* raw() const noexcept { return raw_; }

    [[nodiscard]] std::string_view get_config(std::string_view key) const noexcept {
        const char* v = yuzu_ctx_get_config(raw_, std::string{key}.c_str());
        return v ? v : std::string_view{};
    }

    [[nodiscard]] std::string_view get_secret(std::string_view key) const noexcept {
        const char* v = yuzu_ctx_get_secret(raw_, std::string{key}.c_str());
        return v ? v : std::string_view{};
    }

    // ── KV Storage (ABI v2) ───────────────────────────────────────────────────

    /** Store a key-value pair. Returns true on success. */
    bool storage_set(std::string_view key, std::string_view value) {
        return yuzu_ctx_storage_set(raw_, std::string{key}.c_str(),
                                    std::string{value}.c_str()) == 0;
    }

    /** Retrieve a value by key. Returns empty string if not found. */
    [[nodiscard]] std::string storage_get(std::string_view key) {
        const char* v = yuzu_ctx_storage_get(raw_, std::string{key}.c_str());
        if (!v)
            return {};
        std::string result{v};
        yuzu_free_string(const_cast<char*>(v));
        return result;
    }

    /** Delete a key. Returns true on success. */
    bool storage_delete(std::string_view key) {
        return yuzu_ctx_storage_delete(raw_, std::string{key}.c_str()) == 0;
    }

    /** Check if a key exists. */
    [[nodiscard]] bool storage_exists(std::string_view key) {
        return yuzu_ctx_storage_exists(raw_, std::string{key}.c_str()) == 0;
    }

    /** List keys matching a prefix. Returns a vector of key strings. */
    [[nodiscard]] std::vector<std::string> storage_list(std::string_view prefix = "") {
        const char* json = yuzu_ctx_storage_list(raw_, std::string{prefix}.c_str());
        if (!json)
            return {};
        std::string json_str{json};
        yuzu_free_string(const_cast<char*>(json));

        // Minimal JSON array parse: ["key1","key2",...]
        std::vector<std::string> result;
        size_t pos = 0;
        while ((pos = json_str.find('"', pos)) != std::string::npos) {
            size_t start = pos + 1;
            size_t end = json_str.find('"', start);
            if (end == std::string::npos)
                break;
            result.emplace_back(json_str.substr(start, end - start));
            pos = end + 1;
        }
        return result;
    }

    // ── Trigger registration ─────────────────────────────────────────────────

    /**
     * Register a trigger. When the trigger condition is met, the agent will
     * dispatch the specified plugin action.
     *
     * @param trigger_id    Unique trigger ID (scoped to this plugin).
     * @param trigger_type  Type: "interval", "filesystem", "service", "agent-startup".
     * @param config_json   JSON trigger configuration (see plugin.h for schema).
     * @return true on success.
     */
    bool register_trigger(std::string_view trigger_id, std::string_view trigger_type,
                          std::string_view config_json) {
        return yuzu_register_trigger(raw_, std::string{trigger_id}.c_str(),
                                     std::string{trigger_type}.c_str(),
                                     std::string{config_json}.c_str()) == 0;
    }

    /**
     * Unregister a previously registered trigger.
     * @return true on success, false if not found.
     */
    bool unregister_trigger(std::string_view trigger_id) {
        return yuzu_unregister_trigger(raw_, std::string{trigger_id}.c_str()) == 0;
    }

private:
    YuzuPluginContext* raw_;
};

// ── Plugin base class ─────────────────────────────────────────────────────────

/**
 * Derive from yuzu::Plugin to implement a plugin in C++.
 * Then use YUZU_PLUGIN_EXPORT(YourClass) at namespace scope in the .cpp file.
 */
class Plugin {
public:
    virtual ~Plugin() = default;

    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
    [[nodiscard]] virtual std::string_view version() const noexcept = 0;
    [[nodiscard]] virtual std::string_view description() const noexcept = 0;

    /**
     * Return a null-terminated list of action strings this plugin handles.
     * The returned pointer must be valid for the lifetime of the plugin.
     */
    [[nodiscard]] virtual const char* const* actions() const noexcept = 0;

    /**
     * Per-action, per-OS capability declarations (ABI v4+, #2204). Override
     * this AND action_descriptor_count() together — see the override idiom
     * documented on YUZU_PLUGIN_EXPORT below — to declare capability legs for
     * this plugin's actions. Non-pure: a plugin that overrides neither gets
     * the honest "undeclared" default (nullptr / 0), identical to how an
     * ABI<4 plugin reads, never a fabricated claim. The returned pointer must
     * be valid for the lifetime of the plugin (e.g. a function-local static
     * array). See YuzuActionDescriptor (plugin.h) for the leg shape and
     * docs/adr/3002-acquisition-ladder.md for what a leg's `rung` means.
     */
    [[nodiscard]] virtual const YuzuActionDescriptor* action_descriptors() const noexcept {
        return nullptr;
    }

    /**
     * Number of entries in action_descriptors(). Must agree with it: 0 iff
     * action_descriptors() returns nullptr, non-zero iff it returns a real
     * array of that length. Non-pure; defaults to 0 (undeclared).
     */
    [[nodiscard]] virtual size_t action_descriptor_count() const noexcept { return 0; }

    /**
     * Called once after the shared library is loaded.
     * @return Result<void> — return an error to abort loading.
     */
    virtual Result<void> init(PluginContext& ctx) = 0;

    /**
     * Called once before the shared library is unloaded. Runs synchronously
     * on the host's own teardown path (Agent::Run()'s final-teardown loop)
     * -- an implementation that blocks indefinitely here hangs the whole
     * agent's shutdown, not just this plugin's unload. A short, explicitly
     * BOUNDED wait (e.g. a few seconds, with a documented fallback for the
     * timeout case) is an accepted pattern for a plugin that owns
     * background work it must not race against dlclose/FreeLibrary --
     * see agents/plugins/discovery/src/bounded_wait.hpp's
     * OutstandingCallGuard for a worked example. A background thread that
     * may still be running PAST the bounded wait's timeout must never touch
     * this plugin's own code or statics after that point (dlclose/
     * FreeLibrary can unmap them while it runs) -- if the underlying work
     * can't be made safe against that, don't defer it to a thread at all;
     * accept a bounded resource residue instead. Never an unbounded
     * wait/join.
     */
    virtual void shutdown(PluginContext& ctx) noexcept = 0;

    /**
     * Dispatch an action. Called from the agent on the agent's thread pool.
     * Thread-safety: the agent may call this concurrently for different command IDs.
     * @return 0 on success, non-zero error code on failure.
     */
    virtual int execute(CommandContext& ctx, std::string_view action, Params params) = 0;
};

// ── Secure temporary file RAII wrapper ──────────────────────────────────────

/**
 * RAII wrapper around a securely created temporary file.
 * On destruction, the file is deleted unless release() was called or
 * the file was created with persist=true.
 */
class TempFile {
public:
    /**
     * Create a secure temporary file.
     * @param prefix    Filename prefix (default "yuzu-").
     * @param suffix    File extension (default ".tmp").
     * @param directory Override temp directory (empty = system default).
     * @param persist   If false, file is deleted in destructor.
     */
    static Result<TempFile> create(std::string_view prefix = "yuzu-",
                                   std::string_view suffix = ".tmp",
                                   std::string_view directory = {}, bool persist = false) {
        char buf[512]{};
        int rc = yuzu_create_temp_file(std::string{prefix}.c_str(), std::string{suffix}.c_str(),
                                       directory.empty() ? nullptr : std::string{directory}.c_str(),
                                       buf, sizeof(buf));
        if (rc != 0) {
            return std::unexpected(PluginError{rc, "Failed to create temp file"});
        }
        return TempFile{std::string{buf}, persist};
    }

    ~TempFile() {
        if (!persist_ && !path_.empty()) {
            std::error_code ec;
            std::filesystem::remove(path_, ec);
        }
    }

    TempFile(TempFile&& o) noexcept : path_{std::move(o.path_)}, persist_{o.persist_} {
        o.path_.clear();
    }

    TempFile& operator=(TempFile&& o) noexcept {
        if (this != &o) {
            if (!persist_ && !path_.empty()) {
                std::error_code ec;
                std::filesystem::remove(path_, ec);
            }
            path_ = std::move(o.path_);
            persist_ = o.persist_;
            o.path_.clear();
        }
        return *this;
    }

    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;

    [[nodiscard]] const std::string& path() const noexcept { return path_; }

    /** Release ownership — destructor will NOT delete the file. */
    void release() noexcept { persist_ = true; }

private:
    TempFile(std::string path, bool persist) : path_{std::move(path)}, persist_{persist} {}

    std::string path_;
    bool persist_;
};

// ── Secure temporary directory RAII wrapper ────────────────────────────────

/**
 * RAII wrapper around a securely created temporary directory.
 * On destruction, the directory and its contents are removed unless
 * release() was called or created with persist=true.
 */
class TempDir {
public:
    static Result<TempDir> create(std::string_view prefix = "yuzu-",
                                  std::string_view directory = {}, bool persist = false) {
        char buf[512]{};
        int rc = yuzu_create_temp_dir(std::string{prefix}.c_str(),
                                      directory.empty() ? nullptr : std::string{directory}.c_str(),
                                      buf, sizeof(buf));
        if (rc != 0) {
            return std::unexpected(PluginError{rc, "Failed to create temp directory"});
        }
        return TempDir{std::string{buf}, persist};
    }

    ~TempDir() {
        if (!persist_ && !path_.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(path_, ec);
        }
    }

    TempDir(TempDir&& o) noexcept : path_{std::move(o.path_)}, persist_{o.persist_} {
        o.path_.clear();
    }

    TempDir& operator=(TempDir&& o) noexcept {
        if (this != &o) {
            if (!persist_ && !path_.empty()) {
                std::error_code ec;
                std::filesystem::remove_all(path_, ec);
            }
            path_ = std::move(o.path_);
            persist_ = o.persist_;
            o.path_.clear();
        }
        return *this;
    }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    [[nodiscard]] const std::string& path() const noexcept { return path_; }

    void release() noexcept { persist_ = true; }

private:
    TempDir(std::string path, bool persist) : path_{std::move(path)}, persist_{persist} {}

    std::string path_;
    bool persist_;
};

} // namespace yuzu

// ── Export macro ──────────────────────────────────────────────────────────────

/**
 * Place YUZU_PLUGIN_EXPORT(MyPlugin) in exactly one .cpp file of your plugin.
 * It generates the static descriptor and the required C export symbol.
 *
 * Example:
 *   class InventoryPlugin final : public yuzu::Plugin { ... };
 *   YUZU_PLUGIN_EXPORT(InventoryPlugin)
 *
 * Declaring per-action, per-OS capabilities (ABI v4+, #2204): override BOTH
 * action_descriptors() and action_descriptor_count() on your Plugin subclass
 * — this macro wires whatever they return straight into the generated
 * descriptor, unmodified. A file-scope array both methods share is the usual
 * shape (a function-local static inside ONLY action_descriptors() would be
 * out of scope for action_descriptor_count() to size against):
 *
 *   namespace {
 *   const YuzuActionDescriptor kLegs[] = { ... };
 *   } // namespace
 *
 *   class InventoryPlugin final : public yuzu::Plugin {
 *       ...
 *       const YuzuActionDescriptor* action_descriptors() const noexcept override {
 *           return kLegs;
 *       }
 *       size_t action_descriptor_count() const noexcept override {
 *           return sizeof(kLegs) / sizeof(kLegs[0]);
 *       }
 *   };
 *
 * Leaving both unoverridden is the default and honest: the descriptor then
 * carries action_descriptors=nullptr / action_descriptor_count=0, exactly
 * what capmatrix-gen (#2204) renders as "undeclared" for an ABI<4 plugin —
 * never a fabricated support claim.
 */
#define YUZU_PLUGIN_EXPORT(ClassName)                                                              \
    static ClassName _yuzu_plugin_instance_{};                                                     \
                                                                                                   \
    /* Trampoline: init */                                                                         \
    static int _yuzu_init_(YuzuPluginContext* ctx) {                                               \
        yuzu::PluginContext wrap{ctx};                                                             \
        auto res = _yuzu_plugin_instance_.init(wrap);                                              \
        return res ? 0 : res.error().code;                                                         \
    }                                                                                              \
                                                                                                   \
    /* Trampoline: shutdown */                                                                     \
    static void _yuzu_shutdown_(YuzuPluginContext* ctx) {                                          \
        yuzu::PluginContext wrap{ctx};                                                             \
        _yuzu_plugin_instance_.shutdown(wrap);                                                     \
    }                                                                                              \
                                                                                                   \
    /* Trampoline: execute */                                                                      \
    static int _yuzu_execute_(YuzuCommandContext* ctx, const char* action,                         \
                              const YuzuParam* params, size_t param_count) {                       \
        yuzu::CommandContext cmd_ctx{ctx};                                                         \
        yuzu::Params p{{params, param_count}};                                                     \
        return _yuzu_plugin_instance_.execute(cmd_ctx, action, p);                                 \
    }                                                                                              \
                                                                                                   \
    static const YuzuPluginDescriptor _yuzu_descriptor_{                                           \
        .abi_version = YUZU_PLUGIN_ABI_VERSION,                                                    \
        .name =                                                                                    \
            []() {                                                                                 \
                static const std::string s{_yuzu_plugin_instance_.name()};                         \
                return s.c_str();                                                                  \
            }(),                                                                                   \
        .version =                                                                                 \
            []() {                                                                                 \
                static const std::string s{_yuzu_plugin_instance_.version()};                      \
                return s.c_str();                                                                  \
            }(),                                                                                   \
        .description =                                                                             \
            []() {                                                                                 \
                static const std::string s{_yuzu_plugin_instance_.description()};                  \
                return s.c_str();                                                                  \
            }(),                                                                                   \
        .actions = _yuzu_plugin_instance_.actions(),                                               \
        .init = _yuzu_init_,                                                                       \
        .shutdown = _yuzu_shutdown_,                                                               \
        .execute = _yuzu_execute_,                                                                 \
        .sdk_version = YUZU_PLUGIN_SDK_VERSION,                                                    \
        .action_descriptors = _yuzu_plugin_instance_.action_descriptors(),                         \
        .action_descriptor_count = _yuzu_plugin_instance_.action_descriptor_count(),               \
    };                                                                                             \
                                                                                                   \
    extern "C" YUZU_PLUGIN_API const YuzuPluginDescriptor* yuzu_plugin_descriptor(void) {          \
        return &_yuzu_descriptor_;                                                                 \
    }
