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
    yuzu::shared::note_exe_failure(t, 1);
    CHECK(t.constrained());
}
#endif
