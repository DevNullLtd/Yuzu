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
// Every line carries a `pid=<n>` column right after the `[progress]` tag (#5073): the
// agent suite runs as several concurrent test processes in one job, all appending to the
// ONE file named by YUZU_TEST_PROGRESS_FILE (the nightly upload globs name
// `meson-logs/progress.log` literally, so the filename is not salted). Without the pid
// the per-process "last START with no END = the hung case" diagnosis is ambiguous once
// lines interleave; with it, `grep 'pid=<n> '` isolates one process. Line shapes:
//   [progress] pid=<pid> RUN <name> seed=<seed>
//   [progress] pid=<pid> START <test case>
//   [progress] pid=<pid> END <test case> <ms> ms
//
// YUZU_TEST_CRASH_BACKTRACE=1 (opt-in, Linux/glibc, non-sanitizer builds; set only in the
// Linux non-pg half of ci.yml): on a fatal signal print the signal, the running case,
// MALLOC_PERTURB_ and a backtrace to stderr, then die from the SAME signal. See
// crash_capture below for the limits. Remove once the shard SIGSEGV (#7872) is root-caused.
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
#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_test_case_info.hpp>
#include <catch2/catch_test_run_info.hpp>
#include <catch2/interfaces/catch_interfaces_reporter.hpp>
#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>

#ifdef _WIN32
#include <process.h> // _getpid
#else
#include <unistd.h> // getpid
#endif

// Crash backtrace (opt-in, YUZU_TEST_CRASH_BACKTRACE=1). Linux/glibc, non-sanitizer
// builds only: ASan/TSan install their own fatal-signal reporting, and execinfo.h is
// glibc's. See the block comment above crash_capture below.
#if defined(__linux__) && defined(__GLIBC__) && !defined(__SANITIZE_ADDRESS__) && \
    !defined(__SANITIZE_THREAD__)
// Clang defines neither macro above; ask __has_feature too so a clang sanitizer build
// stays out (the sanitizer owns fatal-signal reporting there).
#if defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
#define YUZU_CRASH_CAPTURE_SANITIZED 1
#endif
#endif
#ifndef YUZU_CRASH_CAPTURE_SANITIZED
#define YUZU_CRASH_CAPTURE 1
#include <algorithm>
#include <cstring>
#include <execinfo.h>
#include <signal.h>
#endif
#endif

namespace {

long current_pid() {
#ifdef _WIN32
    return static_cast<long>(::_getpid());
#else
    return static_cast<long>(::getpid());
#endif
}

// `[progress] pid=<pid> <body>\n`. Pure so the line shape is unit-testable without the
// listener or the environment; every emitted line goes through it so the pid column
// cannot be forgotten on one event type.
std::string format_progress_line(long pid, std::string_view body) {
    return std::format("[progress] pid={} {}\n", pid, body);
}

#ifdef YUZU_CRASH_CAPTURE
// Crash capture for the intermittent agent-shard SIGSEGV deaths (#7872). #7503 and
// #3507 are the exit-42 siblings: exit 42 is a deliberate hard_exit, NOT a signal, so
// this does not capture it.
//
// Those runs end `killed by signal 11 SIGSEGV` with a different victim test each time
// and nothing in the log but the last `[progress] START` line. meson sets a random
// MALLOC_PERTURB_ per run, so a use-after-free or uninitialised read crashes only for
// some values; this prints the stack, the running test case and that value so a failure
// can be replayed (`MALLOC_PERTURB_=<n> yuzu_agent_tests <case>`).
//
// Opt-in and silent otherwise, so every other leg is byte-identical. After printing, the
// handler returns with the default disposition restored (SA_RESETHAND), so the process
// still dies from the SAME signal and meson, flake-retry.py and the junit classifier see
// exactly what they saw before. It only observes; it does not retry, mask or exit.
//
// Async-signal discipline: write(2) only, plus backtrace_symbols_fd (not formally
// async-signal-safe; the risk is a second fault inside the handler, which then takes the
// default action because of SA_RESETHAND, i.e. no worse than today). backtrace() is
// called once at install so libgcc is already loaded. The handler runs on an alternate
// stack so a stack-overflow SEGV on the thread that ran install() is usually reported
// too; a fault on another thread runs on that thread's own stack. The test-case name and
// perturb value live in fixed static buffers, never std::string.
//
// Limits, so a result is read correctly:
//  - Catch2's own FatalConditionHandler engages AFTER testCaseStarting, saves ours as its
//    "previous" handler, prints its fatal report, restores ours and re-raises; ours then
//    prints, so the [crash] block follows Catch2's report. During a case Catch2's own
//    sigaltstack is the active one.
//  - g_case is cleared at testCaseEnded; a crash with case "<none>" happened between
//    cases or in teardown. g_case is written on the test thread and read in the handler
//    without synchronisation (diagnostic only, TSan excluded).
//  - If stderr is a blocked pipe the write would hang the dying process, so the handler
//    arms alarm(5) first; SIGALRM's default action then ends it (as SIGALRM, not SIGSEGV).
//  - SIGABRT also covers deliberate abort()/std::terminate, so a banner is not always a bug.
//  - The handler, the altstack and the backtrace() warm-up shift heap and loader state a
//    little: a crash that DISAPPEARS with this on is inconclusive, not fixed.
namespace crash_capture {

char g_case[256] = "<none>";
char g_perturb[32] = "unset";

void write_str(const char* s) {
    const ssize_t r = ::write(STDERR_FILENO, s, std::strlen(s));
    (void)r; // best effort: nothing useful to do if stderr is closed
}

void handler(int sig) {
    ::alarm(5); // async-signal-safe; bounds a blocked stderr write (see the block comment)
    char num[8];
    int n = 0;
    char rev[8];
    int v = sig;
    do {
        rev[n++] = static_cast<char>('0' + v % 10);
        v /= 10;
    } while (v > 0 && n < 7);
    for (int i = 0; i < n; ++i)
        num[i] = rev[n - 1 - i];
    num[n] = '\0';
    write_str("\n[crash] fatal signal ");
    write_str(num);
    write_str(" in test case: ");
    write_str(g_case);
    write_str("\n[crash] MALLOC_PERTURB_=");
    write_str(g_perturb);
    write_str("\n");
    void* frames[64];
    const int depth = ::backtrace(frames, 64);
    ::backtrace_symbols_fd(frames, depth, STDERR_FILENO);
    write_str("[crash] end of backtrace\n");
}

void clear_case() {
    std::memcpy(g_case, "<none>", sizeof("<none>"));
}

void note_case(const std::string& name) {
    const std::size_t k = std::min(name.size(), sizeof(g_case) - 1);
    std::memcpy(g_case, name.data(), k);
    g_case[k] = '\0';
}

void install() {
    static bool done_once = false;
    if (!done_once) {
        done_once = true;
        if (const char* p = std::getenv("MALLOC_PERTURB_")) {
            std::strncpy(g_perturb, p, sizeof(g_perturb) - 1);
            g_perturb[sizeof(g_perturb) - 1] = '\0';
        }
        void* warm[4];
        (void)::backtrace(warm, 4); // load libgcc now, not inside a handler
        static char alt_stack[64 * 1024];
        stack_t ss{};
        ss.ss_sp = alt_stack;
        ss.ss_size = sizeof(alt_stack);
        (void)::sigaltstack(&ss, nullptr);
    }
    // Re-armed per test case (testCaseStarting precedes Catch2's per-case engage, which
    // saves whatever is current - ours - and restores it before re-raising).
    struct sigaction sa{};
    sa.sa_handler = &handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_ONSTACK | SA_RESETHAND | SA_NODEFER;
    for (const int sig : {SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGFPE})
        (void)::sigaction(sig, &sa, nullptr);
}

} // namespace crash_capture
#endif // YUZU_CRASH_CAPTURE

class ProgressListener : public Catch::EventListenerBase {
public:
    explicit ProgressListener(Catch::IConfig const* config)
        : Catch::EventListenerBase(config), enabled_(read_enabled()),
          crash_enabled_(read_crash_enabled()) {}

    void testRunStarting(Catch::TestRunInfo const& info) override {
        if (!enabled_)
            return;
        emit(format_progress_line(
            pid_, std::format("RUN {} seed={}", std::string_view(info.name.data(), info.name.size()),
                              Catch::getSeed())));
    }

    void testCaseStarting(Catch::TestCaseInfo const& info) override {
#ifdef YUZU_CRASH_CAPTURE
        if (crash_enabled_) {
            crash_capture::note_case(std::string(info.name));
            crash_capture::install();
        }
#endif
        if (!enabled_)
            return;
        start_ = clock::now();
        emit(format_progress_line(pid_, std::format("START {}", info.name)));
    }

    void testCaseEnded(Catch::TestCaseStats const& stats) override {
#ifdef YUZU_CRASH_CAPTURE
        if (crash_enabled_)
            crash_capture::clear_case();
#endif
        if (!enabled_)
            return;
        const auto ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - start_).count();
        emit(format_progress_line(pid_, std::format("END {} {} ms", stats.testInfo->name, ms)));
    }

private:
    using clock = std::chrono::steady_clock;

    // Read once at construction, not per-event: env can't change mid-run and a syscall
    // per TEST_CASE would be needless overhead on the exact suite this is measuring.
    static bool read_enabled() {
        const char* v = std::getenv("YUZU_TEST_PROGRESS");
        return v != nullptr && std::atoi(v) != 0; // atoi(nullptr) is UB - guarded above
    }

    static bool read_crash_enabled() {
        const char* v = std::getenv("YUZU_TEST_CRASH_BACKTRACE");
        return v != nullptr && std::atoi(v) != 0;
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
    bool crash_enabled_;
    long pid_ = current_pid();
    clock::time_point start_{};
};

} // namespace

CATCH_REGISTER_LISTENER(ProgressListener)

TEST_CASE("progress listener: every line carries a pid column (#5073)", "[progress_listener]") {
    REQUIRE(format_progress_line(4242, "START some case") ==
            "[progress] pid=4242 START some case\n");
    REQUIRE(format_progress_line(1, "END some case 12 ms") ==
            "[progress] pid=1 END some case 12 ms\n");
    REQUIRE(format_progress_line(77, "RUN yuzu_agent_tests seed=5") ==
            "[progress] pid=77 RUN yuzu_agent_tests seed=5\n");
    // The live process id is positive.
    REQUIRE(current_pid() > 0);
}
