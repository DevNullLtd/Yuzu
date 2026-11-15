// Shared Catch2 entry point for yuzu_agent_tests, yuzu_server_tests and the
// gRPC lifetime regression. These targets link Catch2 without Catch2Main.
//
// The server entry point keeps the default gRPC EventEngine alive across its suite,
// then destroys the Catch session and drains gRPC before process/OpenSSL cleanup. The
// dependency overlay also releases each secure worker's OpenSSL thread state
// before publishing retirement: pinning alone does not join detached TLS
// destructors. This runner owns the default engine, not arbitrary engines or
// caller-owned threads created by tests; those fixtures must join their work.
// The agent entry point does not pin a pool: its fork-without-exec death tests
// require a thread-quiescent process. Agent fixtures own their gRPC lifetimes.
//
// Preserve the existing #3507 unsanitized Windows/macOS hard_exit policy, but
// only AFTER explicit suite/gRPC teardown. Sanitizers and coverage must retain
// normal process exit so cleanup races, leaks and coverage output remain visible.
// The historical exit-42 diagnosis was too broad: Catch2 itself returns 42 for
// assertion failures. Only a mismatch with the logged Session return value is
// evidence of an exit-status problem; 42 alone is not evidence of corruption.
#include <cstdio>

#include <catch2/catch_session.hpp>
#ifdef YUZU_TEST_GRPC_RUNTIME
#include <grpc/event_engine/event_engine.h>
#include <grpc/grpc.h>
#endif

#include "hard_exit.hpp"

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
extern "C" __attribute__((visibility("default"), used)) const char* __tsan_default_suppressions() {
    return "race:^static_std_strings$\n"
           "race:^static_client_encoding$\n";
}
#endif

namespace {

#ifdef YUZU_TEST_GRPC_RUNTIME
class SuiteGrpcRuntime {
public:
    SuiteGrpcRuntime() {
        // Transfer the sole long-lived reference into gRPC's default-engine
        // slot. Keeping a second shared_ptr here would deadlock shutdown's
        // wait for the last owner. Creation can throw before the transfer;
        // grpc_init is a non-throwing C API after successful installation.
        grpc_event_engine::experimental::SetDefaultEventEngine(
            grpc_event_engine::experimental::CreateEventEngine());
        grpc_init();
    }

    ~SuiteGrpcRuntime() {
        grpc_shutdown_blocking();
        grpc_event_engine::experimental::ShutdownDefaultEventEngine();
    }

    SuiteGrpcRuntime(const SuiteGrpcRuntime&) = delete;
    SuiteGrpcRuntime& operator=(const SuiteGrpcRuntime&) = delete;
};
#endif

int run_suite(int argc, char* argv[]) {
#ifdef YUZU_TEST_GRPC_RUNTIME
    // Reverse destruction order is load-bearing: Session and its listeners
    // release their resources before gRPC drains, including on a CLI error.
    SuiteGrpcRuntime grpc_runtime;
#endif
    Catch::Session session;

    int rc = session.applyCommandLine(argc, argv);
    if (rc != 0) {
        return rc;
    }

    return session.run();
}

} // namespace

int main(int argc, char* argv[]) {
    const int result = run_suite(argc, argv);
    std::fprintf(stderr, "[DIAG] Catch2 Session::run() returned %d (main about to return)\n",
                 result);
    std::fflush(stderr);
    std::fflush(stdout);
#if (defined(_WIN32) || defined(__APPLE__)) && !defined(YUZU_TEST_ASAN) &&                         \
    !defined(YUZU_TEST_TSAN) && !defined(YUZU_TEST_COVERAGE)
    yuzu::agent::hard_exit(result); // existing #3507 policy, after explicit teardown
#endif
    return result;
}
