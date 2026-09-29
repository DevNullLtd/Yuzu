/**
 * example_plugin.cpp — Minimal reference plugin for Yuzu
 *
 * This plugin responds to the "ping" action with a "pong" output.
 * Use it as a starting point for writing real plugins.
 */

#include <yuzu/plugin.hpp>

#include <format>
#include <string_view>

namespace {

// ABI4 capability declarations (#2204). Reference plugin: both actions are
// trivial in-process responders with no OS interaction at all, so every leg
// is rung 1 ("in-process") on every OS uniformly.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "ping",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "in-process", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "in-process", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "in-process", nullptr},
    },
    {
        /* .action      = */ "echo",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "in-process", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "in-process", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "in-process", nullptr},
    },
};

} // namespace

class ExamplePlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "example"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Reference example plugin — responds to 'ping'";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"ping", "echo", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }

    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override {
        // Nothing to initialise for this example.
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "ping") {
            ctx.write_output("pong");
            return 0;
        }

        if (action == "echo") {
            auto msg = params.get("message", "(no message)");
            ctx.write_output(std::format("echo: {}", msg));
            return 0;
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

// Generates yuzu_plugin_descriptor() C export and all trampolines.
YUZU_PLUGIN_EXPORT(ExamplePlugin)
