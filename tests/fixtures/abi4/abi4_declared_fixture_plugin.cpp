/**
 * tests/fixtures/abi4/abi4_declared_fixture_plugin.cpp — a REAL ABI4 plugin
 * that DECLARES per-action, per-OS capabilities (PR1.1, #2204; finding F10).
 *
 * WHY this exists: the capability-matrix gate observes only the real plugin
 * set, which is a single state at any moment — when this fixture was written
 * none of the 49 shipped plugins declared; they all do now. A fixture the
 * test controls outright is what makes capmatrix-gen's RENDERING of a
 * declared descriptor — the entire reason the tool exists — provable
 * independently of that moving target, including the per-OS support/rung/
 * mechanism/fallback columns and the malformed-input rejections no shipped
 * plugin would ever produce. This is the declared input that
 * tests/shell/test_capability_matrix_gate.sh feeds to the real binary.
 *
 * Unlike the frozen tests/fixtures/abi3/ fixture, this one is compiled
 * against the LIVE sdk/include/yuzu/plugin.h on purpose: it must track the
 * current ABI so that an ABI5 append which forgets the render path shows up
 * here as a compile or render diff rather than silently.
 *
 * The declarations are chosen to exercise every render branch in
 * tools/capmatrix-gen/capmatrix_gen.cpp exactly once:
 *   - all five YuzuSupportLevel values, including the zero/UNDECLARED leg
 *     that a plugin leaves unset (honest "no data", never "unsupported");
 *   - rung 0 (renders "-") alongside rungs 1-3 (render as the number);
 *   - NULL and empty-string mechanism/fallback (both render "-");
 *   - a mechanism carrying a '|' and a fallback carrying a newline, which
 *     escape_cell() must neutralise or the Markdown table breaks apart.
 * Deliberately never calls an agent-core entry point, so the built module is
 * self-contained and can be copied into the hermetic fixture tree the shell
 * test builds.
 */

#include <yuzu/plugin.h>

#include <cstring>

namespace {

const char* const kActions[] = {"scan", "quarantine", nullptr};

int fixture_init(YuzuPluginContext* /*ctx*/) { return 0; }

void fixture_shutdown(YuzuPluginContext* /*ctx*/) {}

int fixture_execute(YuzuCommandContext* /*ctx*/, const char* action, const YuzuParam* /*params*/,
                    size_t /*param_count*/) {
    if (action != nullptr &&
        (std::strcmp(action, "scan") == 0 || std::strcmp(action, "quarantine") == 0)) {
        return 0;
    }
    return 1;
}

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action     = */ "scan",
        /* .linux_leg  = */ {YUZU_SUPPORT_SUPPORTED, 3, "procfs", nullptr},
        /* .macos_leg  = */
        {YUZU_SUPPORT_CONSTRAINED, 2, "endpoint_security", "needs the ES entitlement"},
        /* .windows_leg = */ {YUZU_SUPPORT_PLANNED, 1, "etw", ""},
    },
    {
        /* .action     = */ "quarantine",
        /* .linux_leg  = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        // Left entirely unset: the zero value is UNDECLARED — the plugin has
        // said nothing about macOS, which is NOT the same as unsupported.
        /* .macos_leg  = */ {},
        // '|' and a newline are the two characters that would otherwise break
        // the generated Markdown table structure.
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "wmi|root\\cimv2", "reboot\nrequired"},
    },
};

const YuzuPluginDescriptor kDescriptor = {
    /* .abi_version             = */ YUZU_PLUGIN_ABI_VERSION,
    /* .name                    = */ "abi4_declared_fixture",
    /* .version                 = */ "1.0.0",
    /* .description             = */ "ABI4 fixture plugin declaring per-OS capabilities",
    /* .actions                 = */ kActions,
    /* .init                    = */ fixture_init,
    /* .shutdown                = */ fixture_shutdown,
    /* .execute                 = */ fixture_execute,
    /* .sdk_version             = */ YUZU_PLUGIN_SDK_VERSION,
    /* .action_descriptors      = */ kActionDescriptors,
    /* .action_descriptor_count = */ sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]),
};

} // namespace

extern "C" YUZU_PLUGIN_API const YuzuPluginDescriptor* yuzu_plugin_descriptor(void) {
    return &kDescriptor;
}
