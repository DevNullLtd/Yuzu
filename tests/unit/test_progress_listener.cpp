// Per-test-case progress logging for yuzu_agent_tests, gated on YUZU_TEST_PROGRESS
// (#4018). Silent by default so every leg's output stays byte-identical; when set,
// prints one flushed stderr line per test start/end (and the run's Catch2 seed), so
// a stalled CI job's log shows the last TEST_CASE that started rather than nothing.
// Flushed stderr survives meson's taskkill /F /T on a Windows timeout kill -
// Catch2's own buffered reporter output may not. (test_runner_main.cpp documents a
// related but DIFFERENT survival property - exit-code integrity across a clean
// Session::run() return followed by teardown corruption, #1648/#3507 - not this
// mid-run kill scenario; don't conflate the two.)
//
// One dedicated TU, same reasoning as test_pg_template_cleanup.cpp's listener: a
// CATCH_REGISTER_LISTENER in a header would register once per including TU.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <memory>
#include <string>
#include <string_view>

#include <catch2/catch_get_random_seed.hpp>
#include <catch2/catch_test_case_info.hpp>
#include <catch2/catch_test_run_info.hpp>
#include <catch2/interfaces/catch_interfaces_reporter.hpp>
#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>

namespace {

class ProgressListener : public Catch::EventListenerBase {
public:
    explicit ProgressListener(Catch::IConfig const* config)
        : Catch::EventListenerBase(config), enabled_(read_enabled()) {}

    void testRunStarting(Catch::TestRunInfo const& info) override {
        if (!enabled_)
            return;
        emit(std::format("[progress] RUN {} seed={}\n",
                          std::string_view(info.name.data(), info.name.size()),
                          Catch::getSeed()));
    }

    void testCaseStarting(Catch::TestCaseInfo const& info) override {
        if (!enabled_)
            return;
        start_ = clock::now();
        emit(std::format("[progress] START {}\n", info.name));
    }

    void testCaseEnded(Catch::TestCaseStats const& stats) override {
        if (!enabled_)
            return;
        const auto ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - start_).count();
        emit(std::format("[progress] END {} {} ms\n", stats.testInfo->name, ms));
    }

private:
    using clock = std::chrono::steady_clock;

    // Read once at construction, not per-event: env can't change mid-run and a syscall
    // per TEST_CASE would be needless overhead on the exact suite this is measuring.
    static bool read_enabled() {
        const char* v = std::getenv("YUZU_TEST_PROGRESS");
        return v != nullptr && std::atoi(v) != 0; // atoi(nullptr) is UB - guarded above
    }

    // decltype(&std::fclose) as a unique_ptr deleter template argument triggers
    // -Wignored-attributes on glibc (fclose's declared attributes don't survive
    // taking its address); a plain functor deleter sidesteps that cleanly.
    struct FileCloser {
        void operator()(std::FILE* f) const noexcept {
            // fclose's return value (an I/O-error signal) is deliberately unobserved:
            // this is a best-effort diagnostic mirror with no durability contract, and
            // stderr (emitted first, above) is the primary, unconditional output.
            if (f)
                std::fclose(f);
        }
    };

    void emit(const std::string& line) {
        std::fputs(line.c_str(), stderr);
        std::fflush(stderr);
        // Mirrored to a file when set (e.g. so a live-tailing diagnostic doesn't have to
        // share the runner's stderr pipe); opened/closed per line via an RAII owner, not
        // held open, so a hard kill never leaves a line half-written or a handle leaked.
        if (const char* path = std::getenv("YUZU_TEST_PROGRESS_FILE")) {
            std::unique_ptr<std::FILE, FileCloser> f(std::fopen(path, "a"));
            if (f)
                std::fputs(line.c_str(), f.get());
        }
    }

    bool enabled_;
    clock::time_point start_{};
};

} // namespace

CATCH_REGISTER_LISTENER(ProgressListener)
