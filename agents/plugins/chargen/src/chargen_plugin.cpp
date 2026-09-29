/**
 * chargen_plugin.cpp — RFC 864 Character Generator plugin for Yuzu
 *
 * Actions:
 *   "chargen_start" — Begins generating 72-character lines of rotating
 *                     printable ASCII per RFC 864. Runs continuously until
 *                     stopped. Each line is sent via write_output().
 *   "chargen_stop"  — Stops all running chargen sessions.
 *
 * The output is shipped back to the server as CommandResponse messages,
 * one 72-character line per message.
 */

#include <yuzu/plugin.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <format>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>

namespace {

// RFC 864: printable ASCII characters 32 (' ') through 126 ('~'), 95 chars total.
constexpr int kFirstChar = 32;                         // ' '
constexpr int kLastChar = 126;                         // '~'
constexpr int kCharRange = kLastChar - kFirstChar + 1; // 95
constexpr int kLineLength = 72;

// Generate one RFC 864 line starting at the given offset into the character set.
std::string generate_line(int offset) {
    std::string line;
    line.reserve(kLineLength);
    for (int i = 0; i < kLineLength; ++i) {
        line.push_back(static_cast<char>(kFirstChar + ((offset + i) % kCharRange)));
    }
    return line;
}

// ABI4 capability declarations (#2204). Reference/test plugin: both actions
// are in-process (a synchronous condition_variable-gated loop run on the
// calling dispatch thread, no separate worker thread and no OS-specific
// call at all), so every leg is rung 1 uniformly on every OS.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "chargen_start",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "in-process", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "in-process", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "in-process", nullptr},
    },
    {
        /* .action      = */ "chargen_stop",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "in-process", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "in-process", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "in-process", nullptr},
    },
};

} // namespace

class ChargenPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "chargen"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "RFC 864 character generator — streams rotating ASCII lines";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"chargen_start", "chargen_stop", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }

    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override { stop_all(); }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {

        if (action == "chargen_start") {
            return start_chargen(ctx, params);
        }

        if (action == "chargen_stop") {
            stop_all();
            ctx.write_output("chargen stopped");
            return 0;
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    struct Session {
        std::atomic<bool> running{true};
        std::mutex mu;
        std::condition_variable cv;
    };

    std::mutex mu_;
    std::unordered_map<std::string, std::shared_ptr<Session>> sessions_;

    int start_chargen(yuzu::CommandContext& ctx, yuzu::Params params) {
        // Stop any existing session first — ensures at most one worker thread
        // is consumed, so chargen_stop always has a free pool thread to run on.
        stop_all();

        // Rate: milliseconds between lines (default 100ms = 10 lines/sec)
        auto rate_str = params.get("rate_ms", "100");
        int rate_ms = 100;
        try {
            rate_ms = std::stoi(std::string{rate_str});
        } catch (const std::exception&) { /* invalid rate_ms param; keep default */
        }
        if (rate_ms < 1)
            rate_ms = 1;

        auto session = std::make_shared<Session>();
        {
            std::lock_guard lock(mu_);
            sessions_["active"] = session;
        }

        int offset = 0;

        while (session->running.load(std::memory_order_acquire)) {
            auto line = generate_line(offset);
            ctx.write_output(line);

            // RFC 864: each successive line starts one character position later.
            offset = (offset + 1) % kCharRange;

            // Wait on CV instead of sleep — stop_all() wakes instantly.
            std::unique_lock lk(session->mu);
            session->cv.wait_for(lk, std::chrono::milliseconds(rate_ms),
                                 [&] { return !session->running.load(std::memory_order_acquire); });
        }

        ctx.write_output("chargen session ended");
        return 0;
    }

    void stop_all() {
        std::lock_guard lock(mu_);
        for (auto& [key, session] : sessions_) {
            session->running.store(false, std::memory_order_release);
            session->cv.notify_all();
        }
        sessions_.clear();
    }
};

YUZU_PLUGIN_EXPORT(ChargenPlugin)
