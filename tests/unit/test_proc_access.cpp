// WP13 governance UP14: the /proc refusal tally the processes/procfetch/netstat walkers use to
// report CONSTRAINED instead of a clean partial list when CAP_SYS_PTRACE is absent.
#include <catch2/catch_test_macros.hpp>

#include <proc_access.hpp>

#include <cerrno>

using yuzu::shared::ProcAccessTally;

TEST_CASE("proc_access: only a kernel refusal counts, process churn does not",
          "[proc_access][up14]") {
    ProcAccessTally t;
    t.note(ENOENT); // kernel thread / exited process
    t.note(ESRCH);
    t.note(0);
    CHECK_FALSE(t.constrained());
    t.note(EACCES);
    CHECK(t.constrained());
    t.note(EPERM);
    CHECK(t.refused == 2);
}

#if defined(__linux__)
#include <unistd.h>
TEST_CASE("proc_access: a non-root caller reading PID 1's exe is a counted refusal",
          "[proc_access][up14]") {
    // Root (or a CAP_SYS_PTRACE holder) legitimately reads it; the assertion only applies to
    // the unprivileged agent this finding is about, so it is skipped rather than weakened.
    char buf[8];
    errno = 0;
    if (::readlink("/proc/1/exe", buf, sizeof(buf)) >= 0 || errno != EACCES) {
        SKIP("this process can read /proc/1/exe (privileged) or /proc/1 is hidden");
    }
    ProcAccessTally t;
    CHECK(yuzu::shared::readlink_noting(t, "/proc/1/exe").empty());
    CHECK(t.constrained());
}

TEST_CASE("proc_access: the errno of the FIRST failed readlink is counted, not a later read's",
          "[proc_access][up14]") {
    // A process that exits between two reads would turn a genuine EACCES into ENOENT; the
    // helper must make exactly one call and count that call's errno.
    int calls = 0;
    auto eacces_then_enoent = [&calls](const char*, char*, std::size_t) -> ssize_t {
        errno = (++calls == 1) ? EACCES : ENOENT;
        return -1;
    };
    ProcAccessTally t;
    CHECK(yuzu::shared::readlink_noting_with(t, "/proc/1/exe", eacces_then_enoent).empty());
    CHECK(calls == 1);
    CHECK(t.refused == 1);

    // ENOENT on the first call is churn, not a refusal.
    ProcAccessTally gone;
    auto enoent = [](const char*, char*, std::size_t) -> ssize_t {
        errno = ENOENT;
        return -1;
    };
    CHECK(yuzu::shared::readlink_noting_with(gone, "/proc/1/exe", enoent).empty());
    CHECK_FALSE(gone.constrained());

    // A successful read returns the target and counts nothing.
    ProcAccessTally ok;
    auto good = [](const char*, char* buf, std::size_t) -> ssize_t {
        buf[0] = '/'; buf[1] = 'x';
        return 2;
    };
    CHECK(yuzu::shared::readlink_noting_with(ok, "/proc/1/exe", good) == "/x");
    CHECK_FALSE(ok.constrained());
}
#endif
