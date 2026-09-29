/**
 * tests/fixtures/abi3/plugin_abi3.h — FROZEN snapshot of the pre-ABI4
 * YuzuPluginDescriptor layout (PR1.1, #2204).
 *
 * This is a deliberate, permanent fork of sdk/include/yuzu/plugin.h as it
 * read at ABI version 3, BEFORE the ABI4 append (YuzuActionDescriptor /
 * action_descriptors / action_descriptor_count). It exists ONLY so
 * tests/fixtures/abi3/abi3_fixture_plugin.cpp can build a real shared
 * library whose descriptor has the OLD struct layout — proving the loader's
 * backward-compatibility claim ("an ABI3 plugin must still load and its
 * int-only execute() path must still work") against an ACTUAL old-layout
 * binary rather than merely against a plugin recompiled with today's header
 * and abi_version set to 3 by hand (which would not catch a layout mistake:
 * appending a field is only safe if nothing upstream of it moved).
 *
 * DO NOT update this file when sdk/include/yuzu/plugin.h changes — that
 * defeats its entire purpose. It is intentionally frozen at the ABI3 shape
 * forever. Never included by any non-test code; only the fixture plugin and
 * (indirectly, by never referencing it) the loader test use it.
 *
 * Deliberately NOT `#pragma once`'d against the real yuzu/plugin.h: this
 * header uses its own include guard and its own type names are identical to
 * the real ones (YuzuPluginDescriptor, etc.) because the fixture .cpp must
 * look, to the compiler, exactly like a real ABI3-era plugin translation
 * unit. It must never be included in the same translation unit as
 * yuzu/plugin.h.
 */

#ifndef YUZU_TEST_FIXTURES_ABI3_PLUGIN_H
#define YUZU_TEST_FIXTURES_ABI3_PLUGIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* ── Version (frozen at 3 — never bump this file) ────────────────────────── */

#define YUZU_PLUGIN_ABI_VERSION 3
#define YUZU_PLUGIN_SDK_VERSION "0.1.0"
#define YUZU_PLUGIN_ABI_VERSION_MIN 1

/* ── Forward declarations ────────────────────────────────────────────────── */

typedef struct YuzuPluginContext YuzuPluginContext;
typedef struct YuzuCommandContext YuzuCommandContext;

/* ── Key/value parameter bag ─────────────────────────────────────────────── */

typedef struct {
    const char* key;
    const char* value;
} YuzuParam;

/* ── Command handler signature ───────────────────────────────────────────── */

typedef int (*YuzuCommandHandler)(YuzuCommandContext* ctx, const char* action,
                                  const YuzuParam* params, size_t param_count);

/* ── Plugin descriptor — FROZEN ABI3 LAYOUT, never append/reorder here ──── */

typedef struct {
    /** Must equal YUZU_PLUGIN_ABI_VERSION. Checked at load time. */
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

    /** Dispatches an action to this plugin. Int-only result — no ABI4 seam. */
    YuzuCommandHandler execute;

    /**
     * SDK version string the plugin was compiled against (ABI v3+).
     * Null for plugins compiled with ABI version < 3.
     */
    const char* sdk_version;

} YuzuPluginDescriptor;

/* ── Required export symbol ──────────────────────────────────────────────── */

typedef const YuzuPluginDescriptor* (*yuzu_plugin_descriptor_fn)(void);

#ifdef _WIN32
#define YUZU_PLUGIN_API __declspec(dllexport)
#else
#define YUZU_PLUGIN_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* YUZU_TEST_FIXTURES_ABI3_PLUGIN_H */
