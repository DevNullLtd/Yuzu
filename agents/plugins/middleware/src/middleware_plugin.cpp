/**
 * middleware_plugin.cpp -- installed middleware inventory for Yuzu, table-driven: one action per
 * product of agents/shared/middleware_products.hpp (today IBM MQ). A software-inventory fact read
 * from the product's own installer metadata; installed_apps lists the packaged-application view.
 *
 * Actions: one per table row, named by the row's `id` ("ibm_mq": installed IBM MQ installations --
 * name, version, install path).
 *
 * Wire rows (middleware_parsers.hpp): a `status|<action>|...` row first, then
 * `<action>|<title>|<name>|<version or ->|<install_path>|<edition or ->` data rows.
 *
 * ZERO SUBPROCESS. Every fact is an installer-metadata file name or content read (rung 1); no
 * product binary (`dspmqver`, `dspmqinst`) is ever started.
 *
 * SHIPPED LEGS. Linux. The Windows and macOS legs are declared PLANNED from the table; until they
 * ship they report `status|<action>|unsupported|<windows|macos>:planned`.
 *
 * This TU is portable except for its single dispatch #if, which selects the one host leg to call --
 * so a single-OS build never links the other legs' symbols. The action list and the descriptors are
 * GENERATED from the table at compile time, all three legs always populated (never #ifdef'd), so
 * the capability-matrix generator (#2204) sees a complete, stable shape and a new product is a
 * table row, not an edit here.
 *
 * Read-only: no action here mutates host state.
 */

#include <yuzu/plugin.hpp>

#include "middleware_legs.hpp"

#include <array>
#include <cstddef>
#include <string_view>

namespace {

using yuzu::middleware::kProducts;

/// The macOS leg of every product: PLANNED, one shared declaration instead of a leg per product.
constexpr const char* kMacosMechanism =
    "installer-metadata read, not yet wired on macOS (every product)";

/// One descriptor per product: Linux and Windows straight from the table, macOS the shared PLANNED
/// leg. Rung 1 on every leg (installer-metadata file reads).
constexpr auto kActionDescriptors = [] {
    std::array<YuzuActionDescriptor, kProducts.size()> d{};
    for (std::size_t i = 0; i < kProducts.size(); ++i) {
        const auto& p = kProducts[i];
        d[i] = {p.id,
                {p.linux.support, 1, p.linux.mechanism, p.linux.note},
                {YUZU_SUPPORT_PLANNED, 1, kMacosMechanism, yuzu::middleware::kPlannedNote},
                {p.windows.support, 1, p.windows.mechanism, p.windows.note}};
    }
    return d;
}();

static_assert(kProducts.size() == 1 && std::string_view{kProducts[0].id} == "ibm_mq",
              "MiddlewarePlugin::actions() lists the product table's ids: update both together");

} // namespace

class MiddlewarePlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "middleware"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Installed middleware inventory from installer metadata (table-driven; IBM MQ)";
    }

    const char* const* actions() const noexcept override {
        // Literal because tests/test_capability_catalogue_complete.py reads this body from source;
        // the static_asserts below the class pin it to the product table.
        static const char* const acts[] = {"ibm_mq", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors.data();
    }
    size_t action_descriptor_count() const noexcept override { return kActionDescriptors.size(); }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        // Yuzu targets exactly these three OSes, so there is deliberately no fourth branch.
#if defined(_WIN32)
        return yuzu::middleware::execute_action(ctx, action, &yuzu::middleware::run_windows);
#elif defined(__linux__)
        return yuzu::middleware::execute_action(ctx, action, &yuzu::middleware::run_linux);
#elif defined(__APPLE__)
        return yuzu::middleware::execute_action(ctx, action, &yuzu::middleware::run_macos);
#endif
    }
};

YUZU_PLUGIN_EXPORT(MiddlewarePlugin)
