/**
 * diagnostics_plugin.cpp — Agent diagnostics plugin for Yuzu
 *
 * Actions:
 *   "log_level"       — Read current log level from config.
 *   "certificates"    — List TLS cert paths and whether they exist.
 *   "connection_info" — Report server address, TLS status, session, channel state,
 *                       reconnect count, latency, uptime, and connected_since.
 *
 * Output is pipe-delimited, one field per line via write_output():
 *   key|value
 */

#include <yuzu/plugin.hpp>

#include <chrono>
#include <filesystem>
#include <format>
#include <string>
#include <string_view>

namespace {

YuzuPluginContext* g_ctx = nullptr;

// ABI4 capability declarations (#2204). Every action reads the in-process
// agent config store (yuzu_ctx_get_config) plus, for "certificates", a
// std::filesystem::exists() stat of the configured cert paths — no
// OS-specific code and no subprocess anywhere in this plugin, so every leg
// is rung 1 uniformly across every OS.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "log_level",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "in-process agent config (agent.log_level)", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "in-process agent config (agent.log_level)", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "in-process agent config (agent.log_level)", nullptr},
    },
    {
        /* .action      = */ "certificates",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "in-process agent config (tls.*_cert/tls.client_key) + std::filesystem::exists", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "in-process agent config (tls.*_cert/tls.client_key) + std::filesystem::exists", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "in-process agent config (tls.*_cert/tls.client_key) + std::filesystem::exists", nullptr},
    },
    {
        /* .action      = */ "connection_info",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "in-process agent config (agent.server_address/tls.enabled/*)",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "in-process agent config (agent.server_address/tls.enabled/*)",
         nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "in-process agent config (agent.server_address/tls.enabled/*)",
         nullptr},
    },
};

} // namespace

class DiagnosticsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "diagnostics"; }
    std::string_view version() const noexcept override { return "0.2.0"; }
    std::string_view description() const noexcept override {
        return "Agent diagnostics — log level, certificates, connection info";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"log_level", "certificates", "connection_info", nullptr};
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
                yuzu::Params /*params*/) override {
        if (action == "log_level") {
            return do_log_level(ctx);
        }
        if (action == "certificates") {
            return do_certificates(ctx);
        }
        if (action == "connection_info") {
            return do_connection_info(ctx);
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_log_level(yuzu::CommandContext& ctx) {
        yuzu::PluginContext pctx{g_ctx};
        auto level = pctx.get_config("agent.log_level");
        if (level.empty()) {
            level = "info";
        }
        ctx.write_output(std::format("log_level|{}", level));
        return 0;
    }

    int do_certificates(yuzu::CommandContext& ctx) {
        yuzu::PluginContext pctx{g_ctx};

        struct CertInfo {
            const char* type;
            const char* config_key;
        };

        static constexpr CertInfo certs[] = {
            {"ca_cert", "tls.ca_cert"},
            {"client_cert", "tls.client_cert"},
            {"client_key", "tls.client_key"},
        };

        for (const auto& ci : certs) {
            auto path = pctx.get_config(ci.config_key);
            std::string path_str{path};
            bool exists = false;
            if (!path_str.empty()) {
                std::error_code ec;
                exists = std::filesystem::exists(path_str, ec);
            }
            ctx.write_output(std::format("cert|{}|{}|{}", ci.type,
                                         path_str.empty() ? "(not configured)" : path_str,
                                         exists ? "true" : "false"));
        }
        return 0;
    }

    int do_connection_info(yuzu::CommandContext& ctx) {
        yuzu::PluginContext pctx{g_ctx};

        auto server_addr = pctx.get_config("agent.server_address");
        auto tls_enabled = pctx.get_config("tls.enabled");
        auto session_id = pctx.get_config("agent.session_id");
        auto grpc_state = pctx.get_config("agent.grpc_channel_state");
        auto reconnect_cnt = pctx.get_config("agent.reconnect_count");
        auto latency_ms = pctx.get_config("agent.latency_ms");
        auto start_epoch = pctx.get_config("agent.start_time_epoch");
        auto connected_since = pctx.get_config("agent.connected_since");

        ctx.write_output(std::format("server_address|{}", server_addr.empty()
                                                              ? "(not configured)"
                                                              : std::string{server_addr}));
        ctx.write_output(std::format("tls_enabled|{}",
                                     tls_enabled.empty() ? "false" : std::string{tls_enabled}));
        ctx.write_output(
            std::format("session_id|{}", session_id.empty() ? "(none)" : std::string{session_id}));
        ctx.write_output(std::format("grpc_channel_state|{}",
                                     grpc_state.empty() ? "unknown" : std::string{grpc_state}));
        ctx.write_output(std::format("reconnect_count|{}",
                                     reconnect_cnt.empty() ? "0" : std::string{reconnect_cnt}));
        ctx.write_output(
            std::format("latency_ms|{}", latency_ms.empty() ? "0" : std::string{latency_ms}));

        // Compute uptime from start_time_epoch
        if (!start_epoch.empty()) {
            try {
                auto start = std::stoll(std::string{start_epoch});
                auto now = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
                ctx.write_output(std::format("uptime_seconds|{}", now - start));
            } catch (...) {
                ctx.write_output("uptime_seconds|0");
            }
        } else {
            ctx.write_output("uptime_seconds|0");
        }

        ctx.write_output(std::format("connected_since|{}",
                                     connected_since.empty() ? "0" : std::string{connected_since}));
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(DiagnosticsPlugin)
