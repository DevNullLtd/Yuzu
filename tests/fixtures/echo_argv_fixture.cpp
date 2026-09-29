// echo_argv_fixture.cpp -- deterministic argv-echo binary for
// test_content_dist_exec_seam.cpp's real end-to-end exec test.
//
// The test used to copy the host's /bin/echo and rely on it echoing its
// argv back. That broke on a CI runner whose /bin/echo turned out to be a
// GNU coreutils multi-call binary: coreutils dispatches its behavior by
// inspecting /proc/self/exe, and B6's fd-based execveat(fd, "", ...,
// AT_EMPTY_PATH) exec presents /proc/self/exe as an fd-numbered path
// (e.g. /proc/self/fd/13) rather than a real filesystem path -- so
// coreutils tried to dispatch to a utility literally named "13" and
// failed with "coreutils: unknown program '13'". A standalone,
// single-purpose binary has no argv[0]/exe-path-sensitive dispatch to
// break, so it is immune to this class of host-dependent test flake.
// Deliberately trivial: print every argv[i] for i>=1, each on its own
// line, exit 0.
#include <cstdio>

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i)
        std::printf("%s\n", argv[i]);
    return 0;
}
