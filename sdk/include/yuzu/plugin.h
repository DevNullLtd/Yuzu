/**
 * yuzu/plugin.h — Stable C ABI for Yuzu plugins
 *
 * This header defines the only ABI boundary between the agent host and plugin
 * shared libraries. It is intentionally kept as a C-compatible interface so
 * that plugins can be written in any language that supports a C FFI, and so
 * that binary compatibility is maintained across compiler/STL upgrades.
 *
 * Every plugin shared library MUST export a single function with C linkage:
 *
 *   const YuzuPluginDescriptor* yuzu_plugin_descriptor(void);
 *
 * Use the YUZU_PLUGIN_EXPORT macro (plugin.hpp) to generate this automatically
 * when writing C++ plugins.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* ── Version ────────────────────────────────────────────────────────────────── */

#define YUZU_PLUGIN_ABI_VERSION 4

/**
 * Compile-time SDK version string embedded in every plugin descriptor.
 * The agent logs this at load time for diagnostics.
 */
#define YUZU_PLUGIN_SDK_VERSION "0.1.0"

/**
 * Plugins compiled against ABI version 1 are still loadable.
 * The agent checks descriptor->abi_version >= YUZU_PLUGIN_ABI_VERSION_MIN.
 *
 * ABI evolution convention (pin, do not violate): YuzuPluginDescriptor grows
 * strictly by APPENDING new fields at the end. Existing fields are never
 * reordered or repurposed — a plugin built against an older ABI must keep
 * loading and its existing fields must keep meaning what they always meant.
 * The descriptor declaration below is therefore NEVER #ifdef'd on target OS:
 * a single-OS build still emits all three OS columns of every
 * YuzuActionDescriptor leg (unknown/undeclared legs for OSes the plugin
 * doesn't target), so the struct layout is identical across every platform
 * build and #2204's capability-matrix generator can dlopen a plugin built on
 * any one OS and read a stable, complete shape.
 */
#define YUZU_PLUGIN_ABI_VERSION_MIN 1

/* ── Forward declarations ────────────────────────────────────────────────────── */

typedef struct YuzuPluginContext YuzuPluginContext;
typedef struct YuzuCommandContext YuzuCommandContext;

/* ── Key/value parameter bag ─────────────────────────────────────────────────── */

typedef struct {
    const char* key;
    const char* value;
} YuzuParam;

/* ── Command handler signature ───────────────────────────────────────────────── */

/**
 * YuzuCommandHandler is called by the agent to execute an action.
 *
 * @param ctx        Opaque context for sending output/progress back.
 * @param action     Null-terminated action name (e.g. "list", "install").
 * @param params     Array of key-value parameters; may be NULL.
 * @param param_count Length of the params array.
 * @return           0 on success, non-zero on failure.
 */
typedef int (*YuzuCommandHandler)(YuzuCommandContext* ctx, const char* action,
                                  const YuzuParam* params, size_t param_count);

/* ── OS capability descriptor (ABI v4+, #2204) ───────────────────────────────── */

/**
 * Per-OS support level for one action. Values are ordered least- to
 * most-capable so a numeric comparison ("at least constrained") is
 * meaningful, but callers should match on the named value rather than rely
 * on ordering.
 *
 * `YUZU_SUPPORT_UNDECLARED` (the zero value) is what every leg reads as when
 * the plugin was built against ABI < 4 (no action_descriptors array at all)
 * or the plugin declares actions but leaves a specific OS leg unset — it
 * means "no data", never "unsupported". Only the plugin's own declaration
 * ever sets one of the other four values.
 */
typedef enum {
    YUZU_SUPPORT_UNDECLARED  = 0, /* no data — ABI<4 plugin, or leg left unset */
    YUZU_SUPPORT_UNSUPPORTED = 1, /* this OS cannot supply the capability at all */
    YUZU_SUPPORT_PLANNED     = 2, /* not implemented yet; mechanism names the plan */
    YUZU_SUPPORT_CONSTRAINED = 3, /* works, with a known limitation (see fallback) */
    YUZU_SUPPORT_SUPPORTED   = 4  /* fully wired and exercised in CI */
} YuzuSupportLevel;

/**
 * One per-OS leg of an action's capability declaration.
 *
 * `rung` states HOW this leg acquires the capability on this OS, per the
 * acquisition ladder fixed by docs/adr/3002-acquisition-ladder.md: rung 1 =
 * the native OS interface (syscalls / kernel-published surfaces / OS APIs —
 * zero processes, the best rung), rung 2 = the argv runner (a subprocess
 * exec'd through the shared agent-core subprocess_runner), rung 3 = the
 * governed shell (a runner-spawned shell — two-plus processes, string-as-
 * code, the worst rung). 0 means undeclared. It is deliberately independent
 * of `support`: e.g. a PLANNED leg may already name its target rung, and a
 * SUPPORTED leg's rung says which acquisition method is actually wired —
 * never how mature or hardened that wiring is.
 */
typedef struct {
    YuzuSupportLevel support;
    uint8_t rung; /* 1-3; 0 = undeclared */
    /** Short mechanism name, e.g. "etw", "procfs", "endpoint_security". NULL/empty = undeclared. */
    const char* mechanism;
    /** Optional human-readable fallback/limitation note. NULL if none. */
    const char* fallback;
} YuzuOsLeg;

/**
 * Per-action capability declaration: one action name plus its three
 * per-OS legs. A single-OS build still populates all three legs — never
 * #ifdef the leg out — so the capability matrix generator (#2204) sees a
 * complete, stable shape regardless of which OS built the plugin.
 */
typedef struct {
    /** Action name; should match one entry in YuzuPluginDescriptor.actions. */
    const char* action;
    YuzuOsLeg linux_leg;
    YuzuOsLeg macos_leg;
    YuzuOsLeg windows_leg;
} YuzuActionDescriptor;

/* ── Plugin descriptor ────────────────────────────────────────────────────────── */

/**
 * YuzuPluginDescriptor is returned by yuzu_plugin_descriptor().
 * The struct must remain valid for the lifetime of the plugin (i.e. static).
 */
typedef struct {
    /**
     * Must lie within [YUZU_PLUGIN_ABI_VERSION_MIN, YUZU_PLUGIN_ABI_VERSION]
     * (checked at load time — PluginHandle::load(), plugin_loader.cpp).
     * Set this to YUZU_PLUGIN_ABI_VERSION when building against the current
     * SDK; a plugin built against an older ABI within the range keeps
     * loading, per the append-only convention above.
     */
    uint32_t abi_version;

    /** Short unique identifier (e.g. "inventory", "patch"). */
    const char* name;

    /** Semantic version string (e.g. "1.0.0"). */
    const char* version;

    /** Human-readable description. */
    const char* description;

    /**
     * Null-terminated array of action names this plugin handles.
     * e.g. { "list", "install", "uninstall", NULL }
     */
    const char* const* actions;

    /**
     * Called once when the plugin is loaded.
     * @return 0 on success, non-zero to abort loading.
     */
    int (*init)(YuzuPluginContext* ctx);

    /**
     * Called once when the plugin is about to be unloaded.
     * Release all resources here.
     */
    void (*shutdown)(YuzuPluginContext* ctx);

    /** Dispatches an action to this plugin. */
    YuzuCommandHandler execute;

    /**
     * SDK version string the plugin was compiled against (ABI v3+).
     * Null for plugins compiled with ABI version < 3.
     */
    const char* sdk_version;

    /**
     * ABI v4+: per-action, per-OS capability declarations (#2204). NULL for
     * plugins compiled with ABI version < 4 — every capability query then
     * reports YUZU_SUPPORT_UNDECLARED for that plugin, which is honest: the
     * data simply doesn't exist at that ABI version. Never NULL-terminated;
     * length is action_descriptor_count.
     *
     * APPEND-ONLY CONVENTION: this is the last field of YuzuPluginDescriptor
     * today. Any future addition (e.g. mac-parity's ES-broker fields on ABI4,
     * or a subsequent ABI5) must APPEND further fields after this one and
     * bump YUZU_PLUGIN_ABI_VERSION again — never reorder or repurpose an
     * existing field, and never #ifdef this declaration on target OS (see
     * YUZU_PLUGIN_ABI_VERSION_MIN's comment above).
     */
    const YuzuActionDescriptor* action_descriptors;

    /** Number of entries in action_descriptors. 0 when the array is NULL. */
    size_t action_descriptor_count;

} YuzuPluginDescriptor;

/* ── Required export symbol ──────────────────────────────────────────────────── */

/**
 * Every plugin must export this function.
 * The returned pointer must be to a statically allocated descriptor.
 */
typedef const YuzuPluginDescriptor* (*yuzu_plugin_descriptor_fn)(void);

/* For agent core functions (import when used by plugins/agent) */
#ifdef _WIN32
#ifdef YUZU_AGENT_CORE_BUILDING
#define YUZU_EXPORT __declspec(dllexport)
#else
#define YUZU_EXPORT __declspec(dllimport)
#endif
#else
#define YUZU_EXPORT __attribute__((visibility("default")))
#endif

/* For plugin exports (always export from plugin DLLs) */
#ifdef _WIN32
#define YUZU_PLUGIN_API __declspec(dllexport)
#else
#define YUZU_PLUGIN_API __attribute__((visibility("default")))
#endif

/* ── Plugin→host typed result seam (ABI v4+, CC-07) ──────────────────────────── */

/**
 * Typed runtime status a plugin reports for the command it is currently
 * executing, in addition to execute()'s int return code. This is the
 * plugin→host CC-07 status ONLY — it is NOT the subprocess-runner
 * termination-reason enum (a separate concept scoped to the runner header)
 * and carries no mapping to/from it.
 *
 * `YUZU_RESULT_STATUS_UNDECLARED` (the zero value / the value the agent
 * assumes when a plugin never calls yuzu_ctx_set_result_status()) means "no
 * typed status reported" — the agent then falls back to deriving a coarse
 * status from execute()'s int return code alone (0 -> ok-ish, non-zero ->
 * unavailable-ish), which is exactly what happens for every ABI<4 plugin and
 * is why the seam is fully backward compatible with the int-only execute()
 * path.
 */
typedef enum {
    YUZU_RESULT_STATUS_UNDECLARED        = 0,
    YUZU_RESULT_STATUS_OK                = 1,
    YUZU_RESULT_STATUS_UNAVAILABLE       = 2,
    YUZU_RESULT_STATUS_PERMISSION_DENIED = 3,
    YUZU_RESULT_STATUS_CONSTRAINED       = 4
} YuzuResultStatus;

/** How complete the reported result is, independent of its status. */
typedef enum {
    YUZU_RESULT_COMPLETENESS_UNKNOWN = 0, /* not reported; the default */
    YUZU_RESULT_COMPLETENESS_FULL    = 1,
    YUZU_RESULT_COMPLETENESS_PARTIAL = 2
} YuzuResultCompleteness;

/* ── Context helpers (implemented by the agent host) ─────────────────────────── */

/**
 * Send a line of UTF-8 output text back to the server.
 * May be called multiple times from within execute() for streaming output.
 */
YUZU_EXPORT void yuzu_ctx_write_output(YuzuCommandContext* ctx, const char* text);

/**
 * Report progress (0–100). Optional; agents may display this in the UI.
 */
YUZU_EXPORT void yuzu_ctx_report_progress(YuzuCommandContext* ctx, int percent);

/**
 * Report the CC-07 typed result status for the command currently executing
 * on this context (ABI v4+). Optional; a plugin that never calls this
 * leaves the status YUZU_RESULT_STATUS_UNDECLARED and the agent derives a
 * coarse status from execute()'s int return code instead. May be called at
 * most meaningfully once per command — a later call in the same execute()
 * overwrites the earlier one.
 *
 * @param ctx           Command context passed into execute().
 * @param status        Typed outcome; see YuzuResultStatus. A value outside
 *                      YuzuResultStatus's declared range is stored as
 *                      YUZU_RESULT_STATUS_UNDECLARED rather than kept raw.
 * @param completeness  How complete the result is; see YuzuResultCompleteness.
 * @param provenance    Optional short string identifying the source of the
 *                      status (e.g. a mechanism or sub-component name).
 *                      NULL if not applicable. The host copies this string
 *                      synchronously before the call returns — the plugin
 *                      does not need to keep the pointed-to memory alive
 *                      past this call.
 */
YUZU_EXPORT void yuzu_ctx_set_result_status(YuzuCommandContext* ctx, YuzuResultStatus status,
                                            YuzuResultCompleteness completeness,
                                            const char* provenance);

/**
 * Retrieve a named configuration value set by the server for this plugin.
 * Returns NULL if the key is not present.
 */
YUZU_EXPORT const char* yuzu_ctx_get_config(YuzuPluginContext* ctx, const char* key);

/**
 * Retrieve a named secret (e.g. credential) injected by the server.
 * Returns NULL if not present.
 */
YUZU_EXPORT const char* yuzu_ctx_get_secret(YuzuPluginContext* ctx, const char* key);

/* ── KV Storage (ABI v2) — persistent SQLite-backed storage per plugin ─────── */

/**
 * Store a key-value pair in the plugin's persistent namespace.
 * @return 0 on success, non-zero on error.
 */
YUZU_EXPORT int yuzu_ctx_storage_set(YuzuPluginContext* ctx, const char* key, const char* value);

/**
 * Retrieve a value by key from the plugin's persistent namespace.
 * @return Allocated string on success, NULL if key not found.
 *         Caller must free with yuzu_free_string().
 */
YUZU_EXPORT const char* yuzu_ctx_storage_get(YuzuPluginContext* ctx, const char* key);

/**
 * Delete a key from the plugin's persistent namespace.
 * @return 0 on success, non-zero on error.
 */
YUZU_EXPORT int yuzu_ctx_storage_delete(YuzuPluginContext* ctx, const char* key);

/**
 * Check whether a key exists in the plugin's persistent namespace.
 * @return 0 if exists, 1 if not found, negative on error.
 */
YUZU_EXPORT int yuzu_ctx_storage_exists(YuzuPluginContext* ctx, const char* key);

/**
 * List keys matching a prefix from the plugin's persistent namespace.
 * Returns a JSON array string, e.g. '["key1","key2"]'.
 * @return Allocated JSON string, or NULL on error. Free with yuzu_free_string().
 */
YUZU_EXPORT const char* yuzu_ctx_storage_list(YuzuPluginContext* ctx, const char* prefix);

/* ── SDK utility functions (format conversion) ──────────────────────────────── */

/**
 * Free a string allocated by SDK utility functions (table_to_json, etc.).
 * Passing NULL is safe (no-op).
 */
YUZU_EXPORT void yuzu_free_string(char* str);

/**
 * Convert pipe-delimited rows to a JSON array of objects.
 *
 * @param input         Pipe-delimited text (UTF-8, newline-separated rows).
 * @param column_names  Array of column name strings.
 * @param column_count  Length of column_names array.
 * @return Allocated JSON string, or NULL on error. Free with yuzu_free_string().
 */
YUZU_EXPORT char* yuzu_table_to_json(const char* input, const char* const* column_names,
                                     size_t column_count);

/**
 * Convert a JSON array of objects to pipe-delimited rows.
 *
 * @param json_input    JSON string (must be an array of objects).
 * @param column_names  Array of column name strings (keys to extract, in order).
 * @param column_count  Length of column_names array.
 * @return Allocated pipe-delimited string, or NULL on error.
 *         Free with yuzu_free_string().
 */
YUZU_EXPORT char* yuzu_json_to_table(const char* json_input, const char* const* column_names,
                                     size_t column_count);

/**
 * Normalize line endings in a string: \r\n and \r become \n.
 *
 * @param input  UTF-8 text with any mix of line endings.
 * @return Allocated string with normalized \n endings.
 *         Free with yuzu_free_string().
 */
YUZU_EXPORT char* yuzu_split_lines(const char* input);

/**
 * Generate a newline-separated sequence of numbered identifiers.
 *
 * @param start   Starting number.
 * @param count   How many identifiers to generate.
 * @param prefix  Prefix prepended to each number (may be NULL for no prefix).
 * @return Allocated string, or NULL on error. Free with yuzu_free_string().
 */
YUZU_EXPORT char* yuzu_generate_sequence(int start, int count, const char* prefix);

/* ── Secure temporary file utilities ────────────────────────────────────────── */

/**
 * Create a secure temporary file with restricted permissions.
 * POSIX: uses mkstemps() with mode 0600 (owner read/write only).
 * Windows: uses CreateFile with CREATE_NEW and owner-only DACL.
 *
 * @param prefix       Filename prefix (e.g., "yuzu-"). NULL defaults to "yuzu-".
 * @param suffix       File extension (e.g., ".tmp"). NULL defaults to ".tmp".
 * @param directory    Override temp directory. NULL uses the system default.
 * @param path_out     Buffer to receive the null-terminated absolute path.
 * @param path_out_size Size of path_out in bytes (recommend >= 512).
 * @return             0 on success, non-zero on failure. On Windows, a
 *                     non-zero return always leaves GetLastError() carrying a
 *                     meaningful code for THIS call (never a stale value left
 *                     over from an earlier, unrelated Win32 call) -- callers
 *                     may report it directly, e.g. as a `dest_dir_create_<N>`
 *                     style constrained-reason token.
 */
YUZU_EXPORT int yuzu_create_temp_file(const char* prefix, const char* suffix, const char* directory,
                                      char* path_out, size_t path_out_size);

/**
 * Create a secure temporary directory with restricted permissions.
 * POSIX: uses mkdtemp() with mode 0700 (owner only).
 * Windows: creates directory with owner-only DACL.
 *
 * @param prefix       Directory name prefix (e.g., "yuzu-"). NULL defaults to "yuzu-".
 * @param directory    Override parent directory. NULL uses the system default.
 * @param path_out     Buffer to receive the null-terminated absolute path.
 * @param path_out_size Size of path_out in bytes (recommend >= 512).
 * @return             0 on success, non-zero on failure. Same GetLastError()
 *                     guarantee as yuzu_create_temp_file above.
 */
YUZU_EXPORT int yuzu_create_temp_dir(const char* prefix, const char* directory, char* path_out,
                                     size_t path_out_size);

/* ── Trigger registration (agent-side event-driven execution) ───────────── */

/**
 * Register a trigger from a plugin. When the trigger condition is met, the
 * agent will dispatch the plugin action specified in the config_json.
 *
 * @param ctx            Plugin context from init().
 * @param trigger_id     Unique trigger identifier (scoped to this plugin).
 * @param trigger_type   Type string: "interval", "filesystem", "service", "agent-startup".
 * @param config_json    JSON object with trigger-specific configuration:
 *                       - interval:    {"interval_seconds": 300, "plugin": "...", "action": "...", "parameters": {...}}
 *                       - filesystem:  {"watch_path": "/etc/hosts", "plugin": "...", "action": "...", "parameters": {...}}
 *                       - service:     {"service_name": "sshd", "expected_status": "stopped", "plugin": "...", "action": "...", "parameters": {...}}
 *                       - agent-startup: {"plugin": "...", "action": "...", "parameters": {...}}
 *                       Optional field: "debounce_seconds" (integer, suppress re-fires within window).
 * @return               0 on success, non-zero on failure.
 */
YUZU_EXPORT int yuzu_register_trigger(YuzuPluginContext* ctx, const char* trigger_id,
                                      const char* trigger_type, const char* config_json);

/**
 * Unregister a previously registered trigger.
 *
 * @param ctx            Plugin context.
 * @param trigger_id     The trigger ID to remove.
 * @return               0 on success, non-zero if not found.
 */
YUZU_EXPORT int yuzu_unregister_trigger(YuzuPluginContext* ctx, const char* trigger_id);

#ifdef __cplusplus
} /* extern "C" */
#endif
