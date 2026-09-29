/**
 * storage_plugin.cpp — KV storage plugin for Yuzu
 *
 * Exposes the agent's persistent key-value store as remotely invocable
 * actions. Operators can read/write plugin state from the server.
 *
 * Actions:
 *   "set"    — Store a key-value pair.   Params: key (required), value (required)
 *   "get"    — Retrieve a value by key.  Params: key (required)
 *   "delete" — Delete a key.             Params: key (required)
 *   "list"   — List keys with prefix.    Params: prefix (optional, default "")
 *   "clear"  — Delete all keys for this plugin.
 *
 * Output: pipe-delimited via write_output()
 */

#include <yuzu/plugin.hpp>

#include <format>
#include <string>
#include <string_view>

namespace {

YuzuPluginContext* g_ctx = nullptr;

// ABI4 capability declarations (#2204). Every action goes through the
// in-process agent KV store (yuzu_ctx_storage_*) — no OS-specific code and
// no subprocess anywhere in this plugin — so every leg is rung 1 uniformly.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "set",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "in-process agent KV store (yuzu_ctx_storage_set)", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "in-process agent KV store (yuzu_ctx_storage_set)", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "in-process agent KV store (yuzu_ctx_storage_set)", nullptr},
    },
    {
        /* .action      = */ "get",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "in-process agent KV store (yuzu_ctx_storage_get)", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "in-process agent KV store (yuzu_ctx_storage_get)", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "in-process agent KV store (yuzu_ctx_storage_get)", nullptr},
    },
    {
        /* .action      = */ "delete",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "in-process agent KV store (yuzu_ctx_storage_delete)",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "in-process agent KV store (yuzu_ctx_storage_delete)",
         nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "in-process agent KV store (yuzu_ctx_storage_delete)",
         nullptr},
    },
    {
        /* .action      = */ "list",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "in-process agent KV store (yuzu_ctx_storage_list)", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "in-process agent KV store (yuzu_ctx_storage_list)", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "in-process agent KV store (yuzu_ctx_storage_list)", nullptr},
    },
    {
        /* .action      = */ "clear",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "in-process agent KV store (yuzu_ctx_storage_list + storage_delete per key)", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "in-process agent KV store (yuzu_ctx_storage_list + storage_delete per key)", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "in-process agent KV store (yuzu_ctx_storage_list + storage_delete per key)", nullptr},
    },
};

} // namespace

class StoragePlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "storage"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Persistent key-value storage — set, get, delete, list, clear";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"set", "get", "delete", "list", "clear", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }

    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        g_ctx = ctx.raw();
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override { g_ctx = nullptr; }

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params params) override {
        if (action == "set")
            return do_set(ctx, params);
        if (action == "get")
            return do_get(ctx, params);
        if (action == "delete")
            return do_delete(ctx, params);
        if (action == "list")
            return do_list(ctx, params);
        if (action == "clear")
            return do_clear(ctx);

        ctx.write_output(std::format("error|unknown action: {}", action));
        return 1;
    }

private:
    int do_set(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto key = params.get("key");
        auto value = params.get("value");
        if (key.empty()) {
            ctx.write_output("error|missing required parameter: key");
            return 1;
        }
        yuzu::PluginContext pctx{g_ctx};
        if (pctx.storage_set(key, value)) {
            ctx.write_output("status|ok");
            ctx.write_output(std::format("key|{}", key));
            return 0;
        }
        ctx.write_output("error|storage write failed");
        return 1;
    }

    int do_get(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto key = params.get("key");
        if (key.empty()) {
            ctx.write_output("error|missing required parameter: key");
            return 1;
        }
        yuzu::PluginContext pctx{g_ctx};
        auto value = pctx.storage_get(key);
        if (value.empty()) {
            ctx.write_output(std::format("key|{}|not_found", key));
        } else {
            ctx.write_output(std::format("key|{}|{}", key, value));
        }
        return 0;
    }

    int do_delete(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto key = params.get("key");
        if (key.empty()) {
            ctx.write_output("error|missing required parameter: key");
            return 1;
        }
        yuzu::PluginContext pctx{g_ctx};
        pctx.storage_delete(key);
        ctx.write_output("status|ok");
        ctx.write_output(std::format("key|{}", key));
        return 0;
    }

    int do_list(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto prefix = params.get("prefix");
        yuzu::PluginContext pctx{g_ctx};
        auto keys = pctx.storage_list(prefix);
        ctx.write_output(std::format("count|{}", keys.size()));
        for (const auto& k : keys) {
            ctx.write_output(std::format("key|{}", k));
        }
        return 0;
    }

    int do_clear(yuzu::CommandContext& ctx) {
        yuzu::PluginContext pctx{g_ctx};
        auto keys = pctx.storage_list("");
        for (const auto& k : keys) {
            pctx.storage_delete(k);
        }
        ctx.write_output("status|ok");
        ctx.write_output(std::format("cleared|{}", keys.size()));
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(StoragePlugin)
