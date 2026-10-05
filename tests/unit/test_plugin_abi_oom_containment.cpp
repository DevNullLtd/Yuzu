/**
 * test_plugin_abi_oom_containment.cpp -- no exception crosses the plugin ABI
 * when the allocator keeps failing after a leg throws std::bad_alloc.
 *
 * Seams under test (all header-inline, so they are compiled into THIS TU):
 *   A. yuzu::browser_policy::run_guarded
 *   B. yuzu::update_source_trust::execute_sources
 *   C. yuzu::mgmt_posture::execute_posture
 * Their catch arms must build a token, write a status row and set the typed
 * status without letting a second bad_alloc escape. The SDK export wrapper
 * (plugin.hpp) and the test-side LocalDispatcher::run (agent.cpp) do not catch, so an
 * escape unwinds across the plugin ABI; the live dispatch path keeps a blast-radius
 * try/catch around execute (agent.cpp, the `Plugin {} action {} threw` site) that this
 * test deliberately does not rely on.
 *
 * WHY A SEPARATE EXECUTABLE. It replaces the global operator new/delete
 * (process-wide; same precedent as test_spark_alloc_budget.cpp), so it is not a
 * source of yuzu_agent_tests, and it must be ABSENT from sanitizer builds,
 * which own the allocator. It also defines the three yuzu_ctx_* host entry
 * points itself: the real ones (agent.cpp) allocate, so they cannot sit on the
 * failing-allocator path and LocalDispatcher cannot be used. On Windows
 * plugin.h declares YUZU_EXPORT as dllimport unless YUZU_AGENT_CORE_BUILDING,
 * so a test exe cannot define them without pretending to be agent core; the
 * target is therefore not built there. Unlike the spark probe it is not
 * Linux-only: nothing here relies on .so interposition.
 *
 * WHAT IS PINNED. Nothing escapes, and the host still learns of the failure:
 * a typed UNAVAILABLE status or rc 1. Any provenance that landed is exactly the
 * bare prefix or `<prefix>:bad_alloc`, never a partial token.
 *
 * NOT PINNED, DELIBERATELY. Which of status/rc survives (whether the bare
 * prefix fits set_result_status's std::string copy depends on the standard
 * library's SSO threshold: it fits libc++ (22-char SSO) but not libstdc++ (15) or MSVC (15)), and the
 * `unsupported`/`unavailable` row, which is expected to be LOST under sustained
 * failure: its 30+ byte row cannot be built. The typed status or rc 1 is the
 * surviving signal. The healthy-allocator behaviour (full `:bad_alloc` token)
 * is pinned by the two local-dispatcher tests and is not duplicated here.
 *
 * SEAM C differs in one respect: its recovery writes the status ROW before it sets the typed
 * status, so under sustained failure the row build throws first and the surviving signal is
 * rc 1 (the double-throw arm), not a typed status. Its token (`<os>:leg:exception`) also
 * carries no `:bad_alloc` suffix, so the provenance-shape check above does not apply to it.
 */

#include "browser_policy_legs.hpp"
#include "mgmt_posture_legs.hpp"
#include "update_source_trust_legs.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <string_view>

namespace {

bool g_fail_alloc = false; // set by oom_leg, cleared before any assertion runs
int g_injected = 0;        // allocations the failing allocator actually refused

int g_writes = 0;
int g_status_calls = 0;
YuzuResultStatus g_status = YUZU_RESULT_STATUS_UNDECLARED;
YuzuResultCompleteness g_completeness = YUZU_RESULT_COMPLETENESS_UNKNOWN;
char g_provenance[64] = {};

void reset_stubs() {
    g_injected = 0;
    g_writes = 0;
    g_status_calls = 0;
    g_status = YUZU_RESULT_STATUS_UNDECLARED;
    g_completeness = YUZU_RESULT_COMPLETENESS_UNKNOWN;
    g_provenance[0] = '\0';
}

int oom_leg(yuzu::CommandContext&) {
    g_fail_alloc = true; // stays set until the seam returns: the catch arm allocates under failure
    throw std::bad_alloc{};
}

constexpr std::string_view kPrefix = yuzu::browser_policy::kExceptionToken;

void check_provenance_is_legal() {
    if (g_status_calls == 0)
        return;
    const std::string prov{g_provenance};
    const bool legal = prov == kPrefix || prov == std::string{kPrefix} + ":bad_alloc";
    CHECK(legal);
}

} // namespace

// Plain pair only: libstdc++/libc++ route the nothrow and sized forms through these.
void* operator new(std::size_t n) {
    if (g_fail_alloc) {
        ++g_injected;
        throw std::bad_alloc{};
    }
    if (void* p = std::malloc(n ? n : 1))
        return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

// Non-allocating host stubs (the ABI the plugin SDK wrappers call).
extern "C" void yuzu_ctx_write_output(YuzuCommandContext*, const char*) { ++g_writes; }
extern "C" void yuzu_ctx_report_progress(YuzuCommandContext*, int) {}
extern "C" void yuzu_ctx_set_result_status(YuzuCommandContext*, YuzuResultStatus status,
                                           YuzuResultCompleteness completeness,
                                           const char* provenance) {
    ++g_status_calls;
    g_status = status;
    g_completeness = completeness;
    if (provenance) {
        std::strncpy(g_provenance, provenance, sizeof g_provenance - 1);
        g_provenance[sizeof g_provenance - 1] = '\0';
    } else {
        g_provenance[0] = '\0';
    }
}

TEST_CASE("browser_policy run_guarded contains a leg that throws under sustained OOM",
          "[plugin][abi][oom][browser_policy]") {
    yuzu::CommandContext ctx{nullptr};
    reset_stubs();
    bool escaped = false;
    int rc = -1;
    try {
        rc = yuzu::browser_policy::run_guarded(ctx, &oom_leg);
    } catch (...) {
        escaped = true;
    }
    g_fail_alloc = false;

    REQUIRE_FALSE(escaped);
    // The catch arm's token reserve (33 bytes, past every SSO size) must have hit the failing
    // allocator, or this case proves nothing on a stdlib whose typed-status check is skipped.
    REQUIRE(g_injected > 0);
    CHECK(rc == 1);
    if (g_status_calls > 0) {
        CHECK(g_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        CHECK(g_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    }
    check_provenance_is_legal();
#if defined(_LIBCPP_VERSION)
    // The 19-byte bare prefix fits libc++'s 22-byte SSO, so the SDK's std::string copy
    // cannot throw and the typed status MUST land with exactly the bare prefix.
    REQUIRE(g_status_calls == 1);
    CHECK(std::string_view{g_provenance} == kPrefix);
#endif
}

TEST_CASE("update_source_trust execute_sources contains a leg that throws under sustained OOM",
          "[plugin][abi][oom][update_source_trust]") {
    yuzu::CommandContext ctx{nullptr};
    reset_stubs();
    bool escaped = false;
    int rc = -1;
    try {
        rc = yuzu::update_source_trust::execute_sources(ctx, "sources", &oom_leg, kPrefix);
    } catch (...) {
        escaped = true;
    }
    g_fail_alloc = false;

    REQUIRE_FALSE(escaped);
    // The catch arm's token reserve (33 bytes, past every SSO size) must have hit the failing
    // allocator, or this case proves nothing on a stdlib whose typed-status check is skipped.
    REQUIRE(g_injected > 0);
    // The host must still learn of the failure: a typed UNAVAILABLE/UNKNOWN status, or rc 1.
    CHECK((rc == 1 || (g_status == YUZU_RESULT_STATUS_UNAVAILABLE &&
                       g_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN)));
    check_provenance_is_legal();
#if defined(_LIBCPP_VERSION)
    // The 19-byte bare prefix fits libc++'s 22-byte SSO, so the SDK's std::string copy
    // cannot throw and the typed status MUST land with exactly the bare prefix.
    REQUIRE(g_status_calls == 1);
    CHECK(std::string_view{g_provenance} == kPrefix);
#endif
}

TEST_CASE("mgmt_posture execute_posture contains a leg that throws under sustained OOM",
          "[plugin][abi][oom][mgmt_posture]") {
    yuzu::CommandContext ctx{nullptr};
    reset_stubs();
    bool escaped = false;
    int rc = -1;
    try {
        rc = yuzu::mgmt_posture::execute_posture(ctx, "posture", &oom_leg, "linux:leg:exception");
    } catch (...) {
        escaped = true;
    }
    g_fail_alloc = false;

    REQUIRE_FALSE(escaped);
    // The recovery's status row (well past every SSO size) must have hit the failing allocator,
    // or this case proves nothing on a stdlib whose containment is never exercised.
    REQUIRE(g_injected > 0);
    // The host must still learn of the failure: rc 1 from the double-throw arm, or a typed
    // UNAVAILABLE/UNKNOWN status if the recovery managed to land.
    CHECK((rc == 1 || (g_status == YUZU_RESULT_STATUS_UNAVAILABLE &&
                       g_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN)));
}
