/**
 * test_native_raii.cpp — move-only, exception-safety, and no-double-free /
 * no-leak vectors for the three native RAII primitives added under
 * agents/core/include/yuzu/agent/: `ScopedFd` (POSIX file descriptor),
 * `ScopedCFRef<T>` (CoreFoundation object), and `ScopedIOObject` (IOKit
 * `io_object_t`).
 *
 * Each wrapper is guarded to the platform it applies to, exactly like its
 * header (`#ifndef _WIN32` for ScopedFd — POSIX only; `#if defined(__APPLE__)`
 * for the CoreFoundation/IOKit wrappers — Apple only), so this file compiles
 * everywhere (incl. MSVC and Linux) and simply runs fewer sections off-macOS,
 * same convention as test_dex_macos.cpp / test_certificates_macos.cpp.
 *
 * BOTH the CF and IOKit sections verify "no double-free, no leak" by COUNTING
 * references, not by trusting the type alone not to crash — neither a CF nor a
 * Mach over-release is guaranteed to fault immediately, so a count is the only
 * direct proof available without a sanitizer run. CF uses CFGetRetainCount;
 * IOKit uses mach_port_get_refs(MACH_PORT_RIGHT_SEND), which applies because an
 * `io_object_t` IS a `mach_port_t` (IOTypes.h).
 *
 * An earlier revision of this comment claimed IOKit exposed no portable
 * refcount introspection and settled for a functional "did not crash" check.
 * That was wrong, and it mattered: the CDX-P2-015 same-identity reset guard
 * could be reinstated — reintroducing the exact leak the test is named for —
 * with every assertion still passing. Note also that ScopedCFRef and
 * ScopedIOObject are SEPARATE implementations, so the CF vectors cannot stand
 * in for the IOKit ones.
 */

#include <yuzu/agent/scoped_fd.hpp>

#include <catch2/catch_test_macros.hpp>

#include <utility>

#ifndef _WIN32

#include <fcntl.h>
#include <unistd.h>

using yuzu::agent::ScopedFd;

namespace {
/// True iff `fd` is currently a valid, open descriptor in this process.
bool fd_is_open(int fd) {
    return fd >= 0 && ::fcntl(fd, F_GETFD) != -1;
}

/// A fresh pipe, returned as {read_fd, write_fd}; both ends are real, open
/// descriptors owned by the caller.
std::pair<int, int> make_pipe() {
    int fds[2] = {-1, -1};
    REQUIRE(::pipe(fds) == 0);
    return {fds[0], fds[1]};
}
} // namespace

TEST_CASE("ScopedFd: default-constructed owns nothing", "[agent][raii][scoped_fd]") {
    ScopedFd f;
    CHECK_FALSE(f.valid());
    CHECK_FALSE(static_cast<bool>(f));
    CHECK(f.get() == -1);
}

TEST_CASE("ScopedFd: adopts and closes on destruction", "[agent][raii][scoped_fd]") {
    auto [r, w] = make_pipe();
    ::close(w); // only exercising the read end here
    {
        ScopedFd f(r);
        CHECK(f.valid());
        CHECK(f.get() == r);
        CHECK(fd_is_open(r));
    }
    // Destructor closed it — the raw fd number is no longer open.
    CHECK_FALSE(fd_is_open(r));
}

TEST_CASE("ScopedFd: move construction transfers ownership, source empties", "[agent][raii][scoped_fd]") {
    auto [r, w] = make_pipe();
    ::close(w);
    ScopedFd a(r);
    ScopedFd b(std::move(a));

    CHECK_FALSE(a.valid()); // moved-from — owns nothing
    CHECK(a.get() == -1);
    CHECK(b.valid());
    CHECK(b.get() == r);
    CHECK(fd_is_open(r)); // still open — ownership moved, not closed
}

TEST_CASE("ScopedFd: move assignment closes the destination's prior fd, adopts the source's", "[agent][raii][scoped_fd]") {
    auto [r1, w1] = make_pipe();
    auto [r2, w2] = make_pipe();
    ::close(w1);
    ::close(w2);

    ScopedFd a(r1);
    ScopedFd b(r2);
    b = std::move(a);

    CHECK_FALSE(fd_is_open(r2)); // b's original fd was closed by the assignment
    CHECK(fd_is_open(r1));       // a's fd survived the move, now owned by b
    CHECK(b.get() == r1);
    CHECK_FALSE(a.valid());
}

TEST_CASE("ScopedFd: self-move-assignment is a no-op, not a self-close", "[agent][raii][scoped_fd]") {
    auto [r, w] = make_pipe();
    ::close(w);
    ScopedFd a(r);
    ScopedFd& a_ref = a; // avoid a `-Wself-move` diagnostic on `a = std::move(a)`
    a = std::move(a_ref);

    CHECK(a.valid());
    CHECK(a.get() == r);
    CHECK(fd_is_open(r));
}

TEST_CASE("ScopedFd: release() gives up ownership without closing", "[agent][raii][scoped_fd]") {
    auto [r, w] = make_pipe();
    ::close(w);
    int raw;
    {
        ScopedFd f(r);
        raw = f.release();
        CHECK_FALSE(f.valid()); // no longer owns it
    }
    // The destructor of the (now-empty) ScopedFd must NOT have closed it.
    CHECK(fd_is_open(raw));
    CHECK(raw == r);
    ::close(raw); // caller's responsibility now — clean up manually
}

TEST_CASE("ScopedFd: reset() closes the old fd and adopts the new one", "[agent][raii][scoped_fd]") {
    auto [r1, w1] = make_pipe();
    auto [r2, w2] = make_pipe();
    ::close(w1);
    ::close(w2);

    ScopedFd f(r1);
    f.reset(r2);
    CHECK_FALSE(fd_is_open(r1)); // old fd closed
    CHECK(fd_is_open(r2));       // new fd owned
    CHECK(f.get() == r2);

    f.reset(); // no-arg reset: closes r2, owns nothing
    CHECK_FALSE(fd_is_open(r2));
    CHECK_FALSE(f.valid());
}

#endif // !_WIN32

#if defined(__APPLE__)

#include <yuzu/agent/scoped_cfref.hpp>
#include <yuzu/agent/scoped_ioobject.hpp>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h> // mach_port_get_refs — an io_object_t IS a mach_port_t

using yuzu::agent::ScopedCFRef;
using yuzu::agent::ScopedIOObject;

TEST_CASE("ScopedCFRef: default-constructed owns nothing", "[agent][raii][scoped_cfref]") {
    ScopedCFRef<CFMutableArrayRef> ref;
    CHECK_FALSE(ref.valid());
    CHECK_FALSE(static_cast<bool>(ref));
    CHECK(ref.get() == nullptr);
}

TEST_CASE("ScopedCFRef: releases exactly once on destruction (retain-count proof)", "[agent][raii][scoped_cfref]") {
    CFMutableArrayRef obj = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    REQUIRE(obj != nullptr);
    CFRetain(obj); // hold a second, test-owned reference so refcount stays >0 after the wrapper releases its own
    CFIndex before = CFGetRetainCount(obj);

    {
        ScopedCFRef<CFMutableArrayRef> ref(obj); // adopts ONE reference
        CHECK(ref.valid());
        CHECK(ref.get() == obj);
    }
    // Exactly one CFRelease happened — retain count dropped by exactly one.
    CHECK(CFGetRetainCount(obj) == before - 1);
    CFRelease(obj); // release the test's own reference
}

TEST_CASE("ScopedCFRef: move construction transfers ownership, source empties", "[agent][raii][scoped_cfref]") {
    CFMutableArrayRef obj = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    REQUIRE(obj != nullptr);

    ScopedCFRef<CFMutableArrayRef> a(obj);
    ScopedCFRef<CFMutableArrayRef> b(std::move(a));

    CHECK_FALSE(a.valid());
    CHECK(a.get() == nullptr);
    CHECK(b.valid());
    CHECK(b.get() == obj);
    // b's destructor releases the sole owned reference — nothing further to clean up.
}

TEST_CASE("ScopedCFRef: move assignment releases the destination's prior object", "[agent][raii][scoped_cfref]") {
    CFMutableArrayRef obj1 = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    CFMutableArrayRef obj2 = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    REQUIRE(obj1 != nullptr);
    REQUIRE(obj2 != nullptr);
    CFRetain(obj2); // test-owned extra reference so we can prove obj2 was released once
    CFIndex obj2_before = CFGetRetainCount(obj2);

    ScopedCFRef<CFMutableArrayRef> a(obj1);
    ScopedCFRef<CFMutableArrayRef> b(obj2);
    b = std::move(a);

    CHECK(CFGetRetainCount(obj2) == obj2_before - 1); // b's original object was released
    CHECK(b.get() == obj1);
    CHECK_FALSE(a.valid());
    CFRelease(obj2); // release the test's own reference

    // b (now owning obj1) releases it at end of scope.
}

TEST_CASE("ScopedCFRef: release() gives up ownership without releasing", "[agent][raii][scoped_cfref]") {
    CFMutableArrayRef obj = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    REQUIRE(obj != nullptr);
    CFRetain(obj); // test-owned extra reference
    CFIndex before = CFGetRetainCount(obj);

    CFMutableArrayRef raw;
    {
        ScopedCFRef<CFMutableArrayRef> ref(obj);
        raw = ref.release();
        CHECK_FALSE(ref.valid());
    }
    // The (now-empty) wrapper's destructor must NOT have released it.
    CHECK(CFGetRetainCount(obj) == before);
    CHECK(raw == obj);
    CFRelease(obj); // the reference release() handed back to the caller
    CFRelease(obj); // the test's own extra reference from CFRetain above
}

TEST_CASE("ScopedCFRef: reset() with a separately-retained same-identity +1 consumes it, no leak "
          "(CDX-004)",
          "[agent][raii][scoped_cfref]") {
    // The reproduced regression: a caller obtains a DISTINCT +1 to the object a
    // wrapper already owns and hands it to reset(). An earlier self-reset guard
    // returned early on identity equality and LEAKED that +1 (retain count stayed
    // 2 instead of dropping to 1). reset() must release the old and adopt the new
    // even when identity matches.
    CFMutableArrayRef obj = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    REQUIRE(obj != nullptr);
    ScopedCFRef<CFMutableArrayRef> ref(obj); // ref adopts the create +1
    CFRetain(obj);                           // caller's distinct +1 (same identity)
    CFIndex after_retain = CFGetRetainCount(obj);
    ref.reset(obj);                          // transfers the caller's +1 to ref
    // Old wrapper reference released, new +1 adopted: net -1, no leak.
    CHECK(CFGetRetainCount(obj) == after_retain - 1);
    // ref owns exactly one reference; its destructor releases it to zero.
}

TEST_CASE("ScopedCFRef: reset() releases the old object and adopts the new one", "[agent][raii][scoped_cfref]") {
    CFMutableArrayRef obj1 = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    CFMutableArrayRef obj2 = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    REQUIRE(obj1 != nullptr);
    REQUIRE(obj2 != nullptr);
    CFRetain(obj1);
    CFIndex obj1_before = CFGetRetainCount(obj1);

    ScopedCFRef<CFMutableArrayRef> ref(obj1);
    ref.reset(obj2); // owns obj2 now; obj1's wrapper-owned reference released
    CHECK(CFGetRetainCount(obj1) == obj1_before - 1);
    CHECK(ref.get() == obj2);
    CFRelease(obj1); // the test's own extra reference

    ref.reset(); // no-arg reset: releases obj2, owns nothing
    CHECK_FALSE(ref.valid());
}

TEST_CASE("ScopedIOObject: default-constructed owns nothing", "[agent][raii][scoped_ioobject]") {
    ScopedIOObject obj;
    CHECK_FALSE(obj.valid());
    CHECK_FALSE(static_cast<bool>(obj));
    CHECK(obj.get() == IO_OBJECT_NULL);
}

namespace {
/// A real, always-present IOKit service (the IORegistry root platform-expert
/// node) so the ScopedIOObject vectors exercise a genuine `io_object_t`
/// rather than a synthetic value — safe and unprivileged to look up.
///
/// NOTE (QE-3 / xplat-A4): on this host, two successive calls return the
/// SAME Mach port name — IOServiceGetMatchingService hands back an
/// already-registered send right for a singleton service rather than
/// minting a fresh name each time. Any vector that tries to prove ownership
/// by comparing two such "independent" lookups (`svc1 == svc2` is always
/// true) asserts nothing: `send_rights()` below, not identity comparison,
/// is what actually binds these tests.
io_object_t lookup_platform_expert() {
    io_object_t svc = IOServiceGetMatchingService(kIOMainPortDefault,
                                                   IOServiceMatching("IOPlatformExpertDevice"));
    return svc;
}

/// Current Mach send-right count for io_object_t `p` (an io_object_t IS a
/// mach_port_t — IOTypes.h). The only direct, portable way to prove a
/// release/adopt actually happened rather than trusting IOObjectRelease not
/// to crash, and the fix for QE-3/xplat-A4: identity comparison between two
/// lookup_platform_expert() results is vacuous on this host (see above), so
/// every vector that needs to prove a release happened uses this instead.
mach_port_urefs_t send_rights(io_object_t p) {
    mach_port_urefs_t n = 0;
    REQUIRE(mach_port_get_refs(mach_task_self(), p, MACH_PORT_RIGHT_SEND, &n) == KERN_SUCCESS);
    return n;
}
} // namespace

TEST_CASE("ScopedIOObject: adopts a real service and releases on destruction", "[agent][raii][scoped_ioobject]") {
    io_object_t svc = lookup_platform_expert();
    REQUIRE(svc != IO_OBJECT_NULL);
    // Hold a second, test-owned reference so the port stays alive (and its
    // send-right count measurable) after the wrapper releases its own —
    // same technique as the ScopedCFRef retain-count proof above. Without
    // this, "no crash" was the only assertion (QE-3): passes identically
    // whether or not IOObjectRelease is ever called.
    REQUIRE(IOObjectRetain(svc) == KERN_SUCCESS);
    const mach_port_urefs_t before = send_rights(svc);

    {
        ScopedIOObject obj(svc);
        CHECK(obj.valid());
        CHECK(obj.get() == svc);
    }
    // Exactly one release happened — send-right count dropped by exactly one.
    CHECK(send_rights(svc) == before - 1);
    IOObjectRelease(svc); // release the test's own extra reference
}

TEST_CASE("ScopedIOObject: move construction transfers ownership, source empties", "[agent][raii][scoped_ioobject]") {
    io_object_t svc = lookup_platform_expert();
    REQUIRE(svc != IO_OBJECT_NULL);

    ScopedIOObject a(svc);
    ScopedIOObject b(std::move(a));

    CHECK_FALSE(a.valid());
    CHECK(a.get() == IO_OBJECT_NULL);
    CHECK(b.valid());
    CHECK(b.get() == svc);
}

TEST_CASE("ScopedIOObject: move assignment releases the destination's prior object", "[agent][raii][scoped_ioobject]") {
    io_object_t svc1 = lookup_platform_expert();
    io_object_t svc2 = lookup_platform_expert(); // a second, independently-owned reference —
                                                   // may be the SAME port name as svc1 on this
                                                   // host (see lookup_platform_expert()'s doc
                                                   // comment above). The assertion below binds
                                                   // on send-right COUNT, not on comparing
                                                   // svc1/svc2 by identity, so it holds either
                                                   // way (QE-3/xplat-A4).
    REQUIRE(svc1 != IO_OBJECT_NULL);
    REQUIRE(svc2 != IO_OBJECT_NULL);

    ScopedIOObject a(svc1);
    ScopedIOObject b(svc2);
    const mach_port_urefs_t before = send_rights(svc1);
    b = std::move(a);

    // Move-assignment releases b's own prior reference before adopting a's —
    // exactly one send right goes away, whether or not svc1 and svc2 happen
    // to be the same port name.
    CHECK(send_rights(svc1) == before - 1);
    CHECK(b.get() == svc1);
    CHECK_FALSE(a.valid());
    // b's destructor releases the adopted reference at scope exit.
}

TEST_CASE("ScopedIOObject: release() gives up ownership without releasing", "[agent][raii][scoped_ioobject]") {
    io_object_t svc = lookup_platform_expert();
    REQUIRE(svc != IO_OBJECT_NULL);
    // Test-owned extra reference so the port survives (and stays measurable)
    // past the (should-be-empty) wrapper's destructor.
    REQUIRE(IOObjectRetain(svc) == KERN_SUCCESS);
    const mach_port_urefs_t before = send_rights(svc);

    io_object_t raw;
    {
        ScopedIOObject obj(svc);
        raw = obj.release();
        CHECK_FALSE(obj.valid());
    }
    // The (now-empty) wrapper's destructor must NOT have released it.
    CHECK(send_rights(svc) == before);
    CHECK(raw == svc);
    IOObjectRelease(raw); // caller's responsibility now — clean up manually
    IOObjectRelease(svc); // release the test's own extra reference
}

TEST_CASE("ScopedIOObject: reset() releases the old object and adopts the new one", "[agent][raii][scoped_ioobject]") {
    io_object_t svc1 = lookup_platform_expert();
    io_object_t svc2 = lookup_platform_expert(); // may be the SAME port name as svc1 on this
                                                   // host (see the move-assignment vector
                                                   // above) — bind on send-right COUNT, not
                                                   // identity (QE-3/xplat-A4).
    REQUIRE(svc1 != IO_OBJECT_NULL);
    REQUIRE(svc2 != IO_OBJECT_NULL);

    ScopedIOObject obj(svc1);
    const mach_port_urefs_t before = send_rights(svc1);
    obj.reset(svc2); // releases svc1's wrapper-owned reference, adopts svc2's
    CHECK(send_rights(svc1) == before - 1); // old reference released exactly once
    CHECK(obj.get() == svc2);

    obj.reset(); // no-arg reset: releases svc2, owns nothing
    CHECK_FALSE(obj.valid());
}

TEST_CASE("ScopedIOObject: reset() with a separately-retained same-identity +1 consumes it, no "
          "double-release (CDX-P2-015)",
          "[agent][raii][scoped_ioobject]") {
    // The IOKit twin of the ScopedCFRef same-identity vector above (CDX-004),
    // and it asserts the COUNT exactly as that twin does.
    //
    // An `io_object_t` IS a Mach port name (`typedef mach_port_t io_object_t`,
    // IOTypes.h), so `mach_port_get_refs` reads its send-right count directly —
    // there is no need to settle for a validity-only check. Measuring matters
    // because this is the named regression guard for CDX-P2-015: reinstating a
    // self-reset equality early-return leaks the caller's distinct +1, and a
    // test asserting only valid()/get() passes either way. Nothing else covers
    // it — ScopedCFRef is a SEPARATE implementation (scoped_cfref.hpp,
    // CoreFoundation), so the CF twin cannot see an IOKit-only regression, and
    // a leaked Mach send right is invisible to ASan/LSan.
    io_object_t svc = lookup_platform_expert();
    REQUIRE(svc != IO_OBJECT_NULL);

    ScopedIOObject obj(svc);                      // obj adopts the lookup +1
    const mach_port_urefs_t before = send_rights(svc);
    REQUIRE(IOObjectRetain(svc) == KERN_SUCCESS); // caller's distinct +1 (same identity)
    REQUIRE(send_rights(svc) == before + 1);

    obj.reset(svc); // releases obj's old ref, adopts the caller's +1

    // THE assertion: the transfer is balanced — one release, one adopt — so the
    // net count returns to `before`. An equality early-return would skip the
    // release and leave `before + 1`.
    CHECK(send_rights(svc) == before);
    CHECK(obj.valid());
    CHECK(obj.get() == svc);
    // obj owns exactly one reference; its destructor releases it without a
    // double-free.
}

#endif // __APPLE__
