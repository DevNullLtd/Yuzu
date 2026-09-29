#!/usr/bin/env bash
# build-gai-sync-shim.sh — compile the TSan getaddrinfo_a interposer (#438, #1038).
#
# cpp-httplib enables CPPHTTPLIB_USE_NON_BLOCKING_GETADDRINFO by default, routing
# Client::create_socket through glibc's getaddrinfo_a(). glibc implements that by
# spawning an async DNS helper thread via clone3 directly — bypassing TSan's
# pthread_create interceptor — so the helper's per-thread allocator state never
# initialises and its first malloc() segfaults inside
# __tsan::SizeClassAllocator64LocalCache::Allocate (this=0x8) (#438).
#
# This shim interposes getaddrinfo_a/gai_suspend/gai_error/gai_cancel with a
# synchronous getaddrinfo() on the calling thread — no async helper, no crash.
# It is LD_PRELOADed into the TSan test binaries (and gdb's inferior) by the TSan
# jobs in nightly.yml and sanitizer-tests.yml. Production keeps the non-blocking
# DNS behaviour; the shim is scoped to those CI jobs only.
#
# ONE copy, TWO callers: this used to be an inline heredoc duplicated in both
# workflows. They drifted (#1038 CS-03) — only one grew the glibc ABI guard and
# the RUNNER_TEMP path. A single script both jobs call makes drift impossible.
#
# Usage:  build-gai-sync-shim.sh <output.so>
#   <output.so>  where to write the compiled shared object. The workflows pass
#                "$RUNNER_TEMP/libgai_sync_shim.so" — RUNNER_TEMP, not a fixed
#                /tmp path, because the Big Tam pool runs 4 runner agents under
#                one OS identity and a fixed path is a cross-job collision class
#                (#1038 R-15 / CS-04; CLAUDE.md shared-runner invariant).
set -euo pipefail

out="${1:?usage: build-gai-sync-shim.sh <output.so>}"
src="$(dirname "$out")/gai_sync_shim.c"

# gcc-15, not bare `gcc`: the TSan jobs' apt list installs gcc-15 (which provides
# no /usr/bin/gcc symlink on a clean Ubuntu 26.04 image), and gcc-15 is what the
# meson build itself uses (CC: ccache gcc-15). Overridable for local/Docker runs.
CC_BIN="${CC_BIN:-gcc-15}"

cat > "$src" << 'SHIM_EOF'
#define _GNU_SOURCE
#include <netdb.h>
#include <stddef.h>
#include <signal.h>
#include <time.h>

/* struct gaicb::__return is glibc-internal — the header marks it "private to the
   implementation", so writing it is layout-coupled to whatever glibc we compiled
   against. The layout has been stable since glibc 2.2.3, but stability is not a
   contract, and the failure mode if it ever shifts is silent: we would scribble
   an int over whichever field moved into that offset, inside a DNS path, under
   TSan — a bug that would present as anything but its cause.
   So assert the layout at compile time. A future glibc that reshuffles gaicb then
   fails THIS build, loudly, with the offset in the message — instead of producing
   a corrupt sanitizer run (#1038, R-02/R-03/sec LOW-2). Verified against glibc
   2.31, 2.41 and 2.43: ar_result=24, __return=32, sizeof=56. */
_Static_assert(sizeof(void *) == 8,
               "gai_sync_shim: expected an LP64 target (x86-64 runner)");
_Static_assert(offsetof(struct gaicb, ar_result) == 24,
               "gai_sync_shim: gaicb::ar_result moved — glibc layout changed");
_Static_assert(offsetof(struct gaicb, __return) == 32,
               "gai_sync_shim: gaicb::__return moved — glibc's internal layout "
               "changed; re-verify the shim against the new <netdb.h> before "
               "trusting it");
_Static_assert(sizeof(struct gaicb) == 56,
               "gai_sync_shim: sizeof(struct gaicb) changed — glibc layout changed");

int getaddrinfo_a(int mode, struct gaicb *list[], int nitems,
                   struct sigevent *sig) {
    (void)mode; (void)sig;
    for (int i = 0; i < nitems; ++i) {
        if (!list[i]) continue;
        list[i]->ar_result = NULL;
        list[i]->__return = getaddrinfo(list[i]->ar_name,
                                          list[i]->ar_service,
                                          list[i]->ar_request,
                                          &list[i]->ar_result);
    }
    return 0;
}

int gai_suspend(const struct gaicb *const list[], int nitems,
                 const struct timespec *timeout) {
    (void)list; (void)nitems; (void)timeout;
    return 0; /* already completed synchronously */
}

int gai_error(struct gaicb *req) {
    return req ? req->__return : 0;
}

int gai_cancel(struct gaicb *req) {
    (void)req;
    return EAI_NOTCANCELED;
}
SHIM_EOF

# -Werror: the layout guards above are the entire safety story for the __return
# write. A warning here is not cosmetic.
"$CC_BIN" -shared -fPIC -O2 -Wall -Wextra -Werror -o "$out" "$src"
file "$out"
echo "::notice::gai_sync_shim built ok (glibc gaicb layout guards passed) -> $out"
