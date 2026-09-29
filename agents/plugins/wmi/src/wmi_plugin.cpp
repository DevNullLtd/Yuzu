/**
 * wmi_plugin.cpp — Windows Management Instrumentation plugin for Yuzu
 *
 * Actions:
 *   "query"        — Run a WQL SELECT query.
 *   "get_instance" — Get all properties of a WMI class.
 *
 * Windows-only. Returns error on Linux/macOS.
 */

#include <yuzu/plugin.hpp>

#include <format>
#include <string>
#include <string_view>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <win_str.hpp>     // shared yuzu::win wide<->UTF-8 helpers (#1681)
#include <wmi_bounded.hpp> // shared yuzu::shared::wmi bounded query (never WBEM_INFINITE)
#endif

namespace {

YuzuPluginContext* g_ctx = nullptr;

#ifdef _WIN32
// to_wide now comes from the shared agents/shared/win_str.hpp (#1681)
// instead of a local copy; behaviour-identical for valid input.
using yuzu::win::to_wide;

bool is_select_only(std::string_view wql) {
    // Only allow SELECT statements
    auto trimmed = wql;
    while (!trimmed.empty() && trimmed.front() == ' ') trimmed.remove_prefix(1);
    return trimmed.size() >= 6 &&
           (trimmed[0] == 'S' || trimmed[0] == 's') &&
           (trimmed[1] == 'E' || trimmed[1] == 'e') &&
           (trimmed[2] == 'L' || trimmed[2] == 'l') &&
           (trimmed[3] == 'E' || trimmed[3] == 'e') &&
           (trimmed[4] == 'C' || trimmed[4] == 'c') &&
           (trimmed[5] == 'T' || trimmed[5] == 't');
}

// Validate WMI class name: only alphanumeric and underscores
bool is_valid_wmi_class(std::string_view cls) {
    if (cls.empty() || cls.size() > 256) return false;
    for (char c : cls) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_')
            return false;
    }
    return true;
}

// Validate WMI namespace against whitelist
bool is_valid_wmi_namespace(std::string_view ns) {
    // Allowed namespaces (case-insensitive comparison)
    // Using backslash as separator (WMI convention)
    static const char* allowed[] = {
        "root\\cimv2",
        "root\\wmi",
        "root\\standardcimv2",
    };

    // Normalize to lowercase for comparison
    std::string lower;
    lower.reserve(ns.size());
    for (char c : ns) lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    for (const auto* a : allowed) {
        if (lower == a) return true;
    }
    return false;
}

#endif

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// windows: IWbemLocator/IWbemServices COM API -- native, rung 1.
// linux/macos: no WMI equivalent -- execute() returns an explicit
// "WMI not available on this platform" error outright.
const YuzuActionDescriptor kActionDescriptors[] = {
    {"query",
     /* linux   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
     /* macos   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "wmi", nullptr}},
    {"get_instance",
     /* linux   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
     /* macos   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "wmi", nullptr}},
};

} // namespace

class WmiPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "wmi"; }
    std::string_view version() const noexcept override { return "1.1.0"; }
    std::string_view description() const noexcept override {
        return "Windows Management Instrumentation — WQL queries and instance enumeration";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"query", "get_instance", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override { g_ctx = ctx.raw(); return {}; }
    void shutdown(yuzu::PluginContext&) noexcept override { g_ctx = nullptr; }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
#ifndef _WIN32
        ctx.write_output("error|WMI not available on this platform");
        return 1;
#else
        if (action == "query")        return do_query(ctx, params);
        if (action == "get_instance") return do_get_instance(ctx, params);
        ctx.write_output(std::format("error|unknown action: {}", action));
        return 1;
#endif
    }

#ifdef _WIN32
private:
    int do_query(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto wql = params.get("wql");
        if (wql.empty()) { ctx.write_output("error|missing required parameter: wql"); return 1; }
        if (!is_select_only(wql)) { ctx.write_output("error|only SELECT queries are allowed"); return 1; }

        auto ns = params.get("namespace");
        if (ns.empty()) ns = "root\\cimv2";
        if (!is_valid_wmi_namespace(ns)) {
            ctx.write_output("error|namespace not allowed (must be root\\cimv2, root\\wmi, or root\\standardcimv2)");
            return 1;
        }

        auto qres = yuzu::shared::wmi::run_bounded_wmi_query(to_wide(ns), to_wide(wql));
        if (qres.error) {
            ctx.write_output(std::format("error|{}", *qres.error));
            return 1;
        }

        int row = 0;
        for (const auto& r : qres.rows) {
            for (const auto& [k, v] : r)
                ctx.write_output(std::format("row{}|{}|{}", row, k, v));
            ++row;
        }
        if (qres.truncated) {
            // Bounded row cap reached — the enumeration did not complete.
            // Rows gathered so far are still emitted for diagnostics.
            ctx.write_output("error|row_cap_exceeded");
        }
        ctx.write_output(std::format("rows|{}", row));
        return qres.truncated ? 1 : 0;
    }

    int do_get_instance(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto cls = params.get("class");
        if (cls.empty()) { ctx.write_output("error|missing required parameter: class"); return 1; }
        // Validate class name: alphanumeric + underscores only
        if (!is_valid_wmi_class(cls)) {
            ctx.write_output("error|invalid WMI class name (alphanumeric and underscores only)");
            return 1;
        }

        auto wql = std::format("SELECT * FROM {}", cls);
        auto ns = params.get("namespace");
        if (ns.empty()) ns = "root\\cimv2";
        // Validate namespace against whitelist
        if (!is_valid_wmi_namespace(ns)) {
            ctx.write_output("error|namespace not allowed (must be root\\cimv2, root\\wmi, or root\\standardcimv2)");
            return 1;
        }

        // First instance only, bounded to ~5s total (matches the prior
        // single-shot Next(5000, ...) behaviour) — never WBEM_INFINITE.
        yuzu::shared::wmi::BoundedQueryOptions opts;
        opts.next_timeout_ms = 5000;
        opts.row_cap = 1;
        opts.enumeration_deadline_ms = 5000;
        auto qres = yuzu::shared::wmi::run_bounded_wmi_query(to_wide(ns), to_wide(wql), opts);
        if (qres.error) {
            ctx.write_output(std::format("error|{}", *qres.error));
            return 1;
        }
        if (!qres.rows.empty()) {
            for (const auto& [k, v] : qres.rows.front())
                ctx.write_output(std::format("property|{}|{}", k, v));
        }
        return 0;
    }
#endif
};

YUZU_PLUGIN_EXPORT(WmiPlugin)
