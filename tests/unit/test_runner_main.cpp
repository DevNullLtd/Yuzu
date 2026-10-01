// Custom Catch2 entry point for yuzu_agent_tests AND yuzu_server_tests —
// deliberately NOT Catch2WithMain (see tests/meson.build: both exes link
// catch2_nomain_dep).
//
// #1648: the Windows debug test binaries have, on rare CI runs, printed a
// clean Catch2 summary (e.g. "1 failed") and then had the OS report an
// unrelated process exit code (42), which defeats scripts/ci/flake-retry.py's
// classification (catch2_failed_cases() treats an abnormal exit as
// unclassifiable and hard-blocks the job instead of retrying a known flake).
// Printing Session::run()'s return value here, immediately before main()
// returns, bisects the bug on its next occurrence:
//   - this line prints (e.g. "returned 1") but the OS still reports 42 ->
//     the corruption happens strictly AFTER main() returns (global/static
//     destructors, DLL unload) — Catch2 and the test bodies are exonerated.
//   - this line never prints on a 42-exit run -> main() never reached the
//     fprintf, so the corruption happened DURING session.run() itself (e.g.
//     a RegistryGuard watch thread crashing mid-suite), which also explains
//     why catch2_failed_cases()'s junit re-run comes back empty/unparseable.
//
// #3507 AC1: printing the diagnostic was never enough to stop the strand -
// once a teardown-thread crash happens AFTER a green (or honestly red)
// summary, nothing in this file's control can stop the OS from reporting a
// corrupted exit code, because the corruption happens in code this file does
// not own (global/static destructors, DLL unload, a still-running detached
// worker). The fix is to never reach that code on Windows: leave immediately
// after Session::run() returns, via the same hard_exit() primitive
// main.cpp/service_win.cpp already use for the identical class of hazard
// (agents/core/src/hard_exit.hpp, ADR-0021 rung 7.6 / the F3 orphan-exit
// obligation). This is REUSE of that primitive, not a new copy — both test
// binaries already carry agents/core/src on their include path (see the
// CONSTRAINT comment on yuzu_server_tests's target in tests/meson.build), so
// server/core/src/main.cpp's "hoist to common/ on a third call site" rule is
// not triggered by this include.
//
// hard_exit.hpp documents that its `code` "should be nonzero for every
// F3/orphan-triggered call ... must never look like EXIT_SUCCESS" — that
// sentence is scoped to the F3/orphan-drain use it was written for. THIS
// call site is a different, deliberately reviewed use: a passing test run
// (result == 0) is exactly the case #3507 exists to protect, since the
// crash this bug describes happens strictly after a GREEN summary. Calling
// hard_exit(0) here on Windows is intentional, not an oversight — do not
// "fix" it to skip hard_exit on a zero result.
//
// Windows AND macOS (#ifdef, not a runtime check): nightly's coverage
// (-Db_coverage) and the ASan/UBSan/TSan legs need a normal process exit
// for their atexit dumps (gcov's .gcda write, LSan's leak report) —
// hard_exit() skips atexit entirely by design. Those legs are Linux and
// Windows only (nightly.yml, sanitizer-tests.yml declare no macOS job), so
// extending to __APPLE__ breaks no instrumentation that exists today; the
// sanitizer exclusion below is still written to cover macOS, so a future
// macOS ASan leg is correct by construction rather than by omission.
//
// macOS added 2026-09-29 (#3507 follow-up). The hazard was described as "a
// Windows-debug-CI phenomenon (#1648)" when AC1 shipped, and that was true
// of the evidence then available. It is not true now: BigMags reproduced
// the identical signature — flake-retry.py reporting "suite failed but
// enumeration re-run reproduced no failing case" against `exit status 42`
// — on three of four attempts on PR #5101 and again on PR #5107 the same
// afternoon, while Linux stayed green and the macOS-failing PR changed no
// C++ at all. The teardown race this guard exists to prevent is not
// OS-specific; only the original evidence was. See #3507 for the run table.
//
// NOT claimed: that this closes #3507. Windows #5107 failed with "not a
// classifiable Catch2 run — crash/non-Catch2", i.e. death DURING
// session.run(), which is the second bisect arm this file's own header
// describes and which a hard_exit AFTER run() cannot reach.
//
// ALSO excluded from hard_exit on Windows (governance Gate 2/3, 2026-08-28):
// nightly.yml's windows-asan leg, which DOES build and run this exact binary
// (tests/yuzu_agent_tests, -Db_sanitize=address) — an unconditional #ifdef
// _WIN32 guard would fire there too, TerminateProcess-ing before any
// static/global destructor runs and removing ASan's one window to catch a
// UAF-class race between a still-running detached worker (the exact F3
// scenario this hard_exit call exists to guard test-harness exit against)
// and normal teardown — precisely the "whole UAF class this batch targets"
// windows-asan's own job comment describes. Verified this exclusion is safe
// to make, not merely convenient: windows-asan runs `meson test` directly,
// never through flake-retry.py, so the #1648 exit-42 misclassification this
// hard_exit call exists to prevent cannot occur on that leg — excluding it
// costs this file's own stated purpose nothing. __SANITIZE_ADDRESS__ is a
// real macro GCC and MSVC both define directly under their ASan flag, but
// Clang answers __has_feature(address_sanitizer) instead. That distinction
// USED to be irrelevant here ("Windows never uses Clang",
// docs/windows-build.md's standing rule, and windows-asan's toolchain is
// confirmed cl.exe) — extending this guard to macOS, which is Apple Clang,
// makes it load-bearing: a bare !defined(__SANITIZE_ADDRESS__) would NOT
// exclude a macOS ASan build, and the guard would then hard_exit (::_exit on
// POSIX, not TerminateProcess - see hard_exit.hpp) before any static/global
// destructor ran, reintroducing on macOS exactly the hole the windows-asan
// carve-out above exists to prevent. The durable loss there is the
// teardown-UAF WINDOW, not primarily the leak report. Hence YUZU_TEST_ASAN
// below, which ORs both conventions.
//
// TSan is excluded on the same reasoning and by the same shape: the sanitizer
// built to SEE a detached-worker-vs-teardown race is exactly the one that must
// be allowed to reach teardown. (Apple's TSan runtime interposes _exit, so its
// report and exit status survive hard_exit - the window does not, which is the
// part that matters.) UBSan needs no exclusion: it reports inline and runs no
// finalizer. The YUZU_TEST_TSAN macro this guard reads is the pre-existing one
// defined below for the libpq suppressions hook. This is not a new, untested pattern: the identical
// cross-toolchain sanitizer-detect need already lives in this exact
// codebase at tests/unit/test_helpers.hpp's kSpinScale and
// agents/core/include/yuzu/agent/guardian_engine.hpp's
// YUZU_WORKER_MUTEX_GUARD (both OR in the __has_feature branch too, since
// they also compile on Linux/macOS Clang — and as of the macOS extension
// this call site does too, via YUZU_TEST_ASAN).
//
// Session's own destructor (and any Catch2/system atexit handler) never
// runs on this path. Verified empirically (2026-08-27, scratch experiment
// against the vendored Catch2 3.13.0) that this is safe for what
// flake-retry.py needs: a `--reporter junit --out` file is fully written
// and well-formed, WITH the correct process exit code preserved, when the
// process calls _exit()/TerminateProcess() immediately after
// Session::run() returns — junit finalization and the PG cleanup listener's
// testRunEnded both fire INSIDE run(), not in Session's destructor.
#include "hard_exit.hpp"

#include <catch2/catch_session.hpp>

#include <cstdio>

// #1611: TSan suppression for libpq's two connect-time process globals.
//
// libpq (vcpkg libpq 16.9, src/interfaces/libpq/fe-exec.c, pqSaveParameterStatus)
// copies EVERY new connection's client_encoding and standard_conforming_strings
// ParameterStatus into two file-scope statics, static_client_encoding and
// static_std_strings. Upstream's own comment says why: "so that PQescapeString and
// PQescapeBytea can behave somewhat sanely (at least in single-connection-using
// programs)". Any two threads establishing Postgres connections concurrently (two
// PgPool::connect_one() calls, or a pool connect racing a test fixture's direct
// PQconnectdb) are a write-write race on those statics; TSan sees it because the
// TSan triplet instruments libpq itself.
//
// Benign HERE and only here: the statics are read solely by the conn-less
// PQescapeString / PQescapeBytea (no `Conn` suffix), which no first-party code
// calls — every Yuzu query goes through pg::exec_params
// (docs/postgres-store-playbook.md). tests/test_no_connless_pq_escape.py is the
// tripwire that keeps that true; the suppression and the tripwire ship together
// and must not be separated. Anchored to the two GLOBALS by name, not the
// enclosing function, so a race on a shared PGconn inside the same call frame (a
// real first-party bug) still fires.
//
// Do not "fix" this race instead with a process-wide connect mutex: libpq also
// delivers ParameterStatus asynchronously outside connect (any later SET/GUC
// notice), which a connect-time mutex can't cover, and serializing every
// PgPool's connect against the LeaderElector's own dedicated connection
// (server/core/src/leader_elector.cpp) adds cross-component latency coupling for
// no correctness gain here.
//
// Compiled in (not TSAN_OPTIONS=suppressions=<file>) so this one definition
// covers every invocation of these binaries: nightly, on-demand sanitizer runs,
// scripts/ci/tsan-gdb-capture.py re-runs, local runs. This project compiles with
// -fvisibility=hidden globally (meson.build); a bare extern "C" definition of
// this hook would therefore never reach the binary's dynamic symbol table and
// the TSan runtime would silently keep its built-in empty suppression list
// instead — the explicit `visibility("default")` below is load-bearing, not
// decorative. Verify with `nm -D <binary> | grep __tsan_default_suppressions`
// after building (must show a defined, GLOBAL/default-bound symbol, not
// missing/local) — see this PR's own verification notes for the exact command.
#if defined(__SANITIZE_THREAD__)
#define YUZU_TEST_TSAN 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define YUZU_TEST_TSAN 1
#endif
#endif
// ASan detect for the hard_exit guard below. Same two-convention shape as
// YUZU_TEST_TSAN directly above (and test_helpers.hpp's kSpinScale): GCC and
// MSVC define __SANITIZE_ADDRESS__ under their ASan flag, Clang answers
// __has_feature(address_sanitizer). Both arms are required now that the guard
// covers macOS/Apple Clang — see the sanitizer-detect note in the header.
#if defined(__SANITIZE_ADDRESS__)
#define YUZU_TEST_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define YUZU_TEST_ASAN 1
#endif
#endif

#ifdef YUZU_TEST_TSAN
extern "C" __attribute__((visibility("default"), used)) const char*
__tsan_default_suppressions() {
    return "race:^static_std_strings$\n"
           "race:^static_client_encoding$\n";
}
#endif

int main(int argc, char* argv[]) {
    Catch::Session session;

    int rc = session.applyCommandLine(argc, argv);
    if (rc != 0) {
        return rc;
    }

    int result = session.run();
    std::fprintf(stderr, "[DIAG] Catch2 Session::run() returned %d (main about to return)\n",
                 result);
    std::fflush(stderr);
    std::fflush(stdout);
#if (defined(_WIN32) || defined(__APPLE__)) && !defined(YUZU_TEST_ASAN) && \
    !defined(YUZU_TEST_TSAN)
    yuzu::agent::hard_exit(result); // see the #3507 AC1 comment above
#endif
    return result;
}
