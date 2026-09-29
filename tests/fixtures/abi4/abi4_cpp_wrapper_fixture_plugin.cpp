/**
 * tests/fixtures/abi4/abi4_cpp_wrapper_fixture_plugin.cpp — the C++-wrapper
 * regression proving the #2204 descriptor seam (sdk/include/yuzu/plugin.hpp)
 * actually reaches capmatrix-gen.
 *
 * Unlike tests/fixtures/abi4/abi4_declared_fixture_plugin.cpp (which
 * hand-rolls the C YuzuPluginDescriptor directly), this fixture is written
 * through the yuzu::Plugin + YUZU_PLUGIN_EXPORT path every real Yuzu plugin
 * uses (see any plugin source under agents/plugins/). Before the seam,
 * YUZU_PLUGIN_EXPORT's
 * generated descriptor never wired action_descriptors/action_descriptor_count
 * at all — so no C++-wrapper plugin could declare an ABI4 capability leg no
 * matter what it overrode, which is exactly why every one of the 49 shipped
 * plugins (all C++-wrapper) reads as undeclared today. This fixture overrides
 * both new yuzu::Plugin virtuals (action_descriptors(), action_descriptor_
 * count()); loaded through capmatrix-gen exactly like
 * abi4_declared_fixture_plugin.cpp, it must render non-null/non-zero rows —
 * proving the macro wiring reaches the generator, not just the struct layout.
 *
 * actions() and action_descriptors deliberately name the same two actions
 * ("scan", "quarantine") so this fixture also passes capmatrix-gen's
 * actions()/action_descriptors cross-check cleanly (#2204 point 3) — it is a
 * regression for the seam, not for the mismatch detector.
 */

#include <yuzu/plugin.hpp>

namespace {

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "scan",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "procfs", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "endpoint_security", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "etw", nullptr},
    },
    {
        /* .action      = */ "quarantine",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "argv_runner", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "argv_runner", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 2, "argv_runner", nullptr},
    },
};

} // namespace

class Abi4CppWrapperFixturePlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "abi4_cpp_wrapper_fixture"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "ABI4 fixture plugin declaring capabilities through the yuzu::Plugin C++ wrapper";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"scan", "quarantine", nullptr};
        return acts;
    }

    // The regression: overriding both together is what proves the seam.
    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }

    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& /*ctx*/, std::string_view action,
               yuzu::Params /*params*/) override {
        if (action == "scan" || action == "quarantine")
            return 0;
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(Abi4CppWrapperFixturePlugin)
