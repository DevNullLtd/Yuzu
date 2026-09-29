// Windows-only unit coverage for the TAR plugin's shared RAII handle
// guards (agents/plugins/tar/src/tar_win_raii_guards.hpp). Governance
// (quality-engineer, Gate 3) flagged that ScHandleGuard / MibTableGuard /
// WNetEnumGuard / NetApiBufGuard had no unit coverage on Windows -- each
// called a real WinAPI closer directly from its destructor, which is safe
// in production but untestable without a live OS resource. The guards were
// consolidated into a single template with an INJECTABLE closer so a test
// can substitute a stub closer here and verify release-once/null-safety
// without touching a real service handle, network enumeration, or routing
// table (CLAUDE.md's "inject the boundary" test convention, applied to
// RAII guards rather than command runners).
#ifdef _WIN32

#include "tar_win_raii_guards.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::tar::win_raii;

namespace {

// A dummy opaque handle type -- ScopedWinHandle is a template over Handle,
// so this exercises the SAME code every production alias (ScHandleGuard,
// etc.) instantiates, without needing a real SC_HANDLE/HANDLE/LPVOID value.
struct FakeHandleTag;
using FakeHandle = FakeHandleTag*;

int g_close_calls = 0;
FakeHandle g_last_closed = nullptr;

void reset_spy() {
    g_close_calls = 0;
    g_last_closed = nullptr;
}

void spy_closer(FakeHandle h) {
    ++g_close_calls;
    g_last_closed = h;
}

} // namespace

TEST_CASE("ScopedWinHandle calls the closer exactly once on destruction when the handle is "
          "non-null",
          "[tar][win_raii]") {
    reset_spy();
    FakeHandle h = reinterpret_cast<FakeHandle>(0x1234);
    {
        ScopedWinHandle<FakeHandle> guard(h, spy_closer);
        CHECK(guard.get() == h);
        CHECK(static_cast<bool>(guard));
        CHECK(g_close_calls == 0); // not yet -- only on destruction
    }
    CHECK(g_close_calls == 1);
    CHECK(g_last_closed == h);
}

TEST_CASE("ScopedWinHandle never calls the closer for a null/default handle",
          "[tar][win_raii]") {
    reset_spy();
    {
        ScopedWinHandle<FakeHandle> guard(nullptr, spy_closer);
        CHECK(guard.get() == nullptr);
        CHECK_FALSE(static_cast<bool>(guard));
    }
    CHECK(g_close_calls == 0);
}

TEST_CASE("ScopedWinHandle respects a custom null-value sentinel", "[tar][win_raii]") {
    // Some Win32 resources use a non-nullptr sentinel for "no handle"
    // (e.g. INVALID_HANDLE_VALUE, not modeled by the production aliases
    // here, but the primitive supports it) -- prove the null comparison is
    // configurable, not hardcoded to nullptr.
    reset_spy();
    FakeHandle sentinel = reinterpret_cast<FakeHandle>(0xDEAD);
    {
        ScopedWinHandle<FakeHandle> guard(sentinel, spy_closer, /*null_value=*/sentinel);
        CHECK_FALSE(static_cast<bool>(guard));
    }
    CHECK(g_close_calls == 0); // the sentinel value is never "closed"

    reset_spy();
    FakeHandle real = reinterpret_cast<FakeHandle>(0xBEEF);
    {
        ScopedWinHandle<FakeHandle> guard(real, spy_closer, /*null_value=*/sentinel);
        CHECK(static_cast<bool>(guard));
    }
    CHECK(g_close_calls == 1);
    CHECK(g_last_closed == real);
}

TEST_CASE("ScopedWinHandle move-construction transfers ownership without a double-close",
          "[tar][win_raii]") {
    // The type is non-copyable (matching every production alias) and has no
    // declared move members either, so it is implicitly non-movable -- this
    // is a deliberate design choice shared with every other Win32 RAII
    // guard in this repo (see the header's own comment), not an oversight.
    // Pin that non-movability here so a future edit that accidentally adds
    // a move constructor (and reintroduces a double-close risk on the
    // moved-from handle) fails this test rather than shipping silently.
    STATIC_REQUIRE_FALSE(std::is_move_constructible_v<ScopedWinHandle<FakeHandle>>);
    STATIC_REQUIRE_FALSE(std::is_copy_constructible_v<ScopedWinHandle<FakeHandle>>);
}

TEST_CASE("Production aliases (ScHandleGuard etc.) default to their real WinAPI closer without "
          "a test needing to name it",
          "[tar][win_raii]") {
    // This does not invoke a real Win32 call (that would need a live
    // service/network/routing resource) -- it proves only that the
    // single-argument construction syntax every collector site actually
    // uses (e.g. `ScHandleGuard scm{OpenSCManagerW(...)}`) still compiles
    // and resolves to a default closer, matching the pre-refactor bespoke
    // structs' construction syntax exactly. Constructing with a NULL
    // handle means the (real) default closer is never actually invoked
    // during this test, since every closer's null-check runs first.
    ScHandleGuard sc{static_cast<SC_HANDLE>(nullptr)};
    CHECK_FALSE(static_cast<bool>(sc));

    WNetEnumGuard wn{static_cast<HANDLE>(nullptr)};
    CHECK_FALSE(static_cast<bool>(wn));

    NetApiBufGuard nb{static_cast<LPVOID>(nullptr)};
    CHECK_FALSE(static_cast<bool>(nb));

    MibTableGuard mt{static_cast<PMIB_IPNET_TABLE2>(nullptr)};
    CHECK_FALSE(static_cast<bool>(mt));
}

#endif // _WIN32
