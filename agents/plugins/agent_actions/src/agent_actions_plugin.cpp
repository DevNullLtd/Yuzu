/**
 * agent_actions_plugin.cpp — Agent runtime actions plugin for Yuzu
 *
 * Actions:
 *   "set_log_level" — Change the spdlog log level at runtime.
 *   "info"          — Return agent runtime info from config context.
 *
 * Output is pipe-delimited, one field per line via write_output():
 *   key|value
 */

#include <yuzu/plugin.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <format>
#include <string>
#include <string_view>

namespace {

YuzuPluginContext* g_ctx = nullptr;

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// Both actions are pure in-process calls (spdlog::set_level() /
// yuzu_ctx_get_config()) -- no subprocess on any OS -- rung 1 on all three
// legs.
const YuzuActionDescriptor kActionDescriptors[] = {
    {"set_log_level", {YUZU_SUPPORT_SUPPORTED, 1, "spdlog_runtime", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "spdlog_runtime", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "spdlog_runtime", nullptr}},
    {"info", {YUZU_SUPPORT_SUPPORTED, 1, "agent_config_read", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "agent_config_read", nullptr},
     {YUZU_SUPPORT_SUPPORTED, 1, "agent_config_read", nullptr}},
};

} // namespace

class AgentActionsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "agent_actions"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Agent runtime actions — set log level, query agent info";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"set_log_level", "info", nullptr};
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

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "set_log_level") {
            return do_set_log_level(ctx, params);
        }
        if (action == "info") {
            return do_info(ctx);
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_set_log_level(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto level_str = params.get("level");
        if (level_str.empty()) {
            ctx.write_output("error|missing required parameter: level");
            return 1;
        }

        // Normalize to lowercase
        std::string level_lower{level_str};
        std::transform(level_lower.begin(), level_lower.end(), level_lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        auto level = spdlog::level::from_str(level_lower);
        if (level == spdlog::level::off && level_lower != "off") {
            ctx.write_output(std::format("error|invalid log level: {}", level_str));
            return 1;
        }

        spdlog::set_level(level);
        ctx.write_output("status|ok");
        ctx.write_output(std::format("level|{}", level_lower));
        return 0;
    }

    int do_info(yuzu::CommandContext& ctx) {
        yuzu::PluginContext pctx{g_ctx};

        struct InfoKey {
            const char* display;
            const char* config_key;
        };

        static constexpr InfoKey keys[] = {
            {"agent.id", "agent.id"},
            {"agent.version", "agent.version"},
            {"agent.server_address", "agent.server_address"},
            {"agent.heartbeat_interval", "agent.heartbeat_interval"},
            {"agent.plugins.count", "agent.plugins.count"},
        };

        for (const auto& k : keys) {
            auto val = pctx.get_config(k.config_key);
            ctx.write_output(
                std::format("{}|{}", k.display, val.empty() ? "(not set)" : std::string{val}));
        }
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(AgentActionsPlugin)
