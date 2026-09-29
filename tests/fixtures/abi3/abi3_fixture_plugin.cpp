/**
 * tests/fixtures/abi3/abi3_fixture_plugin.cpp — a REAL, old-layout ABI3
 * plugin shared library (PR1.1, #2204).
 *
 * Built by the integrator (IT-1) as a standalone shared_module compiled
 * against the FROZEN tests/fixtures/abi3/plugin_abi3.h — never against the
 * live sdk/include/yuzu/plugin.h. This proves ABI3 backward compatibility
 * against an actual old-layout binary: tests/unit/test_capability_descriptor.cpp
 * dlopens it by explicit path and MUST FAIL (not skip) if the built module is
 * absent, then exercises its int-only execute() path exactly as a real ABI3
 * agent deployment would.
 *
 * Deliberately minimal: one action ("ping"), always succeeds, never calls any
 * ABI4-only entry point (none exist in plugin_abi3.h to call).
 */

#include "plugin_abi3.h"

#include <cstring>

namespace {

const char* const kActions[] = {"ping", nullptr};

int fixture_init(YuzuPluginContext* /*ctx*/) { return 0; }

void fixture_shutdown(YuzuPluginContext* /*ctx*/) {}

int fixture_execute(YuzuCommandContext* /*ctx*/, const char* action, const YuzuParam* /*params*/,
                    size_t /*param_count*/) {
    // Int-only result — the ABI3 contract this fixture exists to prove still
    // works: no typed status, no completeness/provenance, just 0/non-zero.
    if (action != nullptr && std::strcmp(action, "ping") == 0) {
        return 0;
    }
    return 1;
}

const YuzuPluginDescriptor kDescriptor = {
    /* .abi_version   = */ 3,
    /* .name          = */ "abi3_fixture",
    /* .version       = */ "1.0.0",
    /* .description   = */ "Frozen ABI3-layout fixture plugin for loader backward-compat tests",
    /* .actions       = */ kActions,
    /* .init          = */ fixture_init,
    /* .shutdown      = */ fixture_shutdown,
    /* .execute       = */ fixture_execute,
    /* .sdk_version   = */ YUZU_PLUGIN_SDK_VERSION,
};

} // namespace

extern "C" YUZU_PLUGIN_API const YuzuPluginDescriptor* yuzu_plugin_descriptor(void) {
    return &kDescriptor;
}
