/**
 * test_capability_descriptor.cpp — PR1.1 / #2204 ABI 3→4 descriptor tests.
 *
 * Covers:
 *   - The ABI version macros widen to [1,4] (never narrow, never reorder).
 *   - YuzuActionDescriptor / YuzuOsLeg / YuzuSupportLevel shape and the
 *     append-only ordering of the support enum.
 *   - The CC-07 result-status enums' zero values really are the honest
 *     "undeclared / unknown" defaults, and the real exported
 *     yuzu_ctx_set_result_status() null-context guard behaves safely.
 *   - REAL ABI3 backward compatibility: dlopens the frozen-layout fixture
 *     plugin (tests/fixtures/abi3/) built from tests/fixtures/abi3/plugin_abi3.h
 *     — NOT a plugin merely recompiled against today's header with
 *     abi_version hand-set to 3 — and exercises its int-only execute() path.
 *     This test FAILS (does not skip) if the fixture module is missing: an
 *     absent fixture is exactly the silent regression this test exists to
 *     catch, never a quiet green.
 *   - Declared-vs-observable honesty: a descriptor with no action_descriptors
 *     (the overwhelming common case today — every existing plugin, since none
 *     has adopted the array yet) must read as "undeclared" for every
 *     capability query, never as a fabricated "supported"/"unsupported".
 */

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/agent/updater.hpp> // current_executable_path() — exe-relative fixture lookup (BR-007)
#include <yuzu/plugin.h>

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace fs = std::filesystem;

// yuzu_ctx_set_result_status() itself is declared (with the correct
// export/import decoration for every platform) in <yuzu/plugin.h>, already
// included above; the real implementation is agents/core/src/agent.cpp,
// built into yuzu_agent_core_lib and linked here via yuzu_agent_core_dep.

namespace yuzu::agent {
// Defined (externally linked, no public header — same convention
// local_dispatcher.cpp uses for dispatch_with_capture) in agent.cpp: the
// CC-07 declared-vs-observable fallback pulled out of execute_command_task
// specifically so this suite can pin its behavior without a live gRPC stream.
YuzuResultStatus derive_effective_result_status(YuzuResultStatus reported, int rc);

// cpp-expert A4 test seam, defined in agent.cpp right after
// dispatch_with_capture: drives `status` through the REAL
// yuzu_ctx_set_result_status() entry point and returns the RAW value stored
// afterward — see the mutation-bound test below for why this must be the
// raw stored value, not a proto mapping or a return code.
YuzuResultStatus set_result_status_and_read_back(YuzuResultStatus status);

// plugin B2 test seam, defined in agents/core/src/plugin_loader.cpp
// immediately above PluginHandle::load(): the single source of truth for
// gating action_descriptor_count to ABI v4+ descriptors.
std::size_t gated_action_descriptor_count(const YuzuPluginDescriptor* desc);
} // namespace yuzu::agent

namespace {

#ifdef _WIN32
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

/**
 * Locate the ABI3 fixture plugin built from tests/fixtures/abi3/
 * abi3_fixture_plugin.cpp. Mirrors test_plugin_loader.cpp's
 * find_fixture_plugin() search paths exactly (same build-output convention:
 * a tests/meson.build shared_module/shared_library named
 * "abi3_fixture_plugin" with name_prefix: '' lands at
 * <builddir>/tests/abi3_fixture_plugin<ext>), but — unlike that helper —
 * this one is for a fixture whose ABSENCE must FAIL the test, not skip it:
 * the whole point of this fixture is proving ABI3 backward compatibility
 * against a real old-layout binary, and a "not found -> skip" result would
 * silently stop proving anything.
 */
fs::path find_abi3_fixture() {
    const std::string lib_name = std::string{"abi3_fixture_plugin"} + kPluginExt;

    std::vector<fs::path> candidates;
    // BR-007: the fixture is built into the SAME directory as this test exe
    // (<builddir>/tests/), so an exe-relative lookup resolves under ANY
    // invocation — `meson test` (which sets MESON_BUILD_ROOT and cwd), a direct
    // run, AND scripts/run-tests.sh (the standing Darwin gate, which runs the
    // binary from the source root with neither set). Tried first for that reason.
    {
        std::error_code ec;
        auto exe = yuzu::agent::current_executable_path();
        if (!exe.empty())
            candidates.emplace_back(exe.parent_path() / lib_name);
    }
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "tests" / lib_name);
    }
    // Meson launches tests with CWD=build root; tests/ sits alongside the exe.
    candidates.emplace_back(fs::path{"tests"} / lib_name);
    candidates.emplace_back(fs::path{"."} / lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

struct RawHandle {
    void* handle{nullptr};
    ~RawHandle() {
        if (handle) {
#ifdef _WIN32
            FreeLibrary(static_cast<HMODULE>(handle));
#else
            dlclose(handle);
#endif
        }
    }
};

} // namespace

// ── ABI version widening (append-only, never narrow) ────────────────────────

TEST_CASE("ABI version widens to [1,4], MIN unchanged", "[capability][abi4]") {
    STATIC_REQUIRE(YUZU_PLUGIN_ABI_VERSION == 4);
    STATIC_REQUIRE(YUZU_PLUGIN_ABI_VERSION_MIN == 1);
}

// ── ActionDescriptor / OsLeg / support-level shape ───────────────────────────

TEST_CASE("YuzuSupportLevel: undeclared is the zero value", "[capability][abi4]") {
    // Zero-init POD must read as "no data", never a fabricated support claim.
    YuzuOsLeg leg{};
    CHECK(leg.support == YUZU_SUPPORT_UNDECLARED);
    CHECK(leg.rung == 0);
    CHECK(leg.mechanism == nullptr);
    CHECK(leg.fallback == nullptr);
}

TEST_CASE("YuzuActionDescriptor carries all three OS legs independently",
         "[capability][abi4]") {
    YuzuActionDescriptor ad{};
    ad.action = "list";
    ad.linux_leg = YuzuOsLeg{YUZU_SUPPORT_SUPPORTED, 3, "procfs", nullptr};
    ad.macos_leg = YuzuOsLeg{YUZU_SUPPORT_CONSTRAINED, 2, "endpoint_security", "no cmdline"};
    ad.windows_leg = YuzuOsLeg{YUZU_SUPPORT_PLANNED, 0, "etw", nullptr};

    CHECK(std::string_view{ad.action} == "list");
    CHECK(ad.linux_leg.support == YUZU_SUPPORT_SUPPORTED);
    CHECK(ad.macos_leg.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(std::string_view{ad.macos_leg.fallback} == "no cmdline");
    CHECK(ad.windows_leg.support == YUZU_SUPPORT_PLANNED);
    // Never #ifdef the leg away — all three are always present in the type,
    // regardless of which OS built this translation unit.
}

TEST_CASE("YuzuPluginDescriptor defaults to zero/undeclared capability data",
         "[capability][abi4]") {
    // An ABI4 descriptor that simply never populates the trailing fields
    // (every plugin in-tree today, since none has adopted them yet) must
    // read as "no capability data", not as a crash or a false claim.
    YuzuPluginDescriptor d{};
    d.abi_version = YUZU_PLUGIN_ABI_VERSION;
    CHECK(d.action_descriptors == nullptr);
    CHECK(d.action_descriptor_count == 0);
}

// ── CC-07 result-status seam: honest defaults + real null-guard ─────────────

TEST_CASE("YuzuResultStatus/Completeness: undeclared/unknown are the zero values",
         "[capability][cc07]") {
    STATIC_REQUIRE(static_cast<int>(YUZU_RESULT_STATUS_UNDECLARED) == 0);
    STATIC_REQUIRE(static_cast<int>(YUZU_RESULT_COMPLETENESS_UNKNOWN) == 0);
}

TEST_CASE("derive_effective_result_status: declared-vs-observable honesty",
         "[capability][cc07]") {
    // A plugin that DID report a typed status always wins, regardless of
    // the int return code — an explicit CONSTRAINED report must not be
    // second-guessed just because execute() happened to return 0.
    CHECK(yuzu::agent::derive_effective_result_status(YUZU_RESULT_STATUS_CONSTRAINED, 0) ==
          YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(yuzu::agent::derive_effective_result_status(YUZU_RESULT_STATUS_PERMISSION_DENIED, 0) ==
          YUZU_RESULT_STATUS_PERMISSION_DENIED);

    // UNDECLARED (no call at all — every ABI<4 plugin, or an ABI4 plugin
    // that just didn't report) falls back to a coarse rc-derived guess.
    CHECK(yuzu::agent::derive_effective_result_status(YUZU_RESULT_STATUS_UNDECLARED, 0) ==
          YUZU_RESULT_STATUS_OK);
    CHECK(yuzu::agent::derive_effective_result_status(YUZU_RESULT_STATUS_UNDECLARED, 1) ==
          YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(yuzu::agent::derive_effective_result_status(YUZU_RESULT_STATUS_UNDECLARED, -1) ==
          YUZU_RESULT_STATUS_UNAVAILABLE);
}

TEST_CASE("yuzu_ctx_set_result_status: null context is a safe no-op",
         "[capability][cc07]") {
    // Calls the REAL exported agent-host symbol (not a test re-implementation).
    // A plugin author who calls this before the agent hands out a live
    // context (or a buggy test) must not crash the host.
    yuzu_ctx_set_result_status(nullptr, YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL,
                              "unit-test");
    SUCCEED("no crash");
}

// cpp-expert A4: an out-of-range status crosses the C ABI from a third-party
// plugin as a bare int, with nothing upstream guaranteeing it names one of
// the five declared enumerators. This MUST be observed via the RAW stored
// value (set_result_status_and_read_back(), agent.cpp), never via
// to_proto_result_status() or a return code: that switch already falls
// through any unmatched value to PLUGIN_RESULT_UNDECLARED regardless of
// whether the clamp below exists, so a proto-level assertion is a false
// green that would pass identically whether or not the clamp is reverted —
// exactly the false-green class this run exists to bounce.
TEST_CASE("yuzu_ctx_set_result_status: out-of-range status clamps to UNDECLARED (raw stored value)",
         "[capability][cc07]") {
    CHECK(yuzu::agent::set_result_status_and_read_back(static_cast<YuzuResultStatus>(99)) ==
          YUZU_RESULT_STATUS_UNDECLARED);
    CHECK(yuzu::agent::set_result_status_and_read_back(static_cast<YuzuResultStatus>(-1)) ==
          YUZU_RESULT_STATUS_UNDECLARED);
    // In-range values must still pass through unchanged — the clamp must not
    // over-reach and rewrite legitimate reports.
    CHECK(yuzu::agent::set_result_status_and_read_back(YUZU_RESULT_STATUS_CONSTRAINED) ==
          YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(yuzu::agent::set_result_status_and_read_back(YUZU_RESULT_STATUS_OK) ==
          YUZU_RESULT_STATUS_OK);
}

// ── REAL ABI3 backward compatibility (frozen old-layout fixture) ───────────

TEST_CASE("ABI3 fixture: real old-layout plugin loads and its int-only execute() works",
         "[capability][abi3][loader]") {
    auto fixture_path = find_abi3_fixture();
    // MUST FAIL, not skip — see find_abi3_fixture()'s comment. An absent
    // fixture is exactly the silent-regression case this test exists to
    // catch (a future ABI append that isn't actually backward compatible,
    // or a broken fixture build), so it must turn the suite red.
    if (fixture_path.empty()) {
        FAIL("abi3_fixture_plugin" << kPluginExt
                                   << " not found under tests/ (or $MESON_BUILD_ROOT/tests/) — "
                                      "the standalone shared_module target "
                                      "(tests/fixtures/abi3/abi3_fixture_plugin.cpp) must be "
                                      "built before this test runs.");
    }

    RawHandle rh;
#ifdef _WIN32
    HMODULE hmod = LoadLibraryW(fs::absolute(fixture_path).wstring().c_str());
    REQUIRE(hmod != nullptr);
    rh.handle = static_cast<void*>(hmod);
    auto fn = reinterpret_cast<yuzu_plugin_descriptor_fn>(
        GetProcAddress(hmod, "yuzu_plugin_descriptor"));
#else
    void* h = dlopen(fixture_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    REQUIRE(h != nullptr);
    rh.handle = h;
    auto fn = reinterpret_cast<yuzu_plugin_descriptor_fn>(dlsym(h, "yuzu_plugin_descriptor"));
#endif
    REQUIRE(fn != nullptr);

    const YuzuPluginDescriptor* d = fn();
    REQUIRE(d != nullptr);

    SECTION("ABI3 descriptor is honest about its own version") { CHECK(d->abi_version == 3); }

    SECTION("loader's widened [1,4] range still accepts it") {
        CHECK(d->abi_version >= YUZU_PLUGIN_ABI_VERSION_MIN);
        CHECK(d->abi_version <= YUZU_PLUGIN_ABI_VERSION);
    }

    // plugin B2(a): sdk_version is the field immediately BEFORE the ABI4
    // append point (action_descriptors/action_descriptor_count) in the
    // CURRENT sdk/include/yuzu/plugin.h struct. The ABI3 fixture is compiled
    // against the FROZEN tests/fixtures/abi3/plugin_abi3.h layout, which
    // simply ends at sdk_version — nothing is appended there. `d` above is
    // typed as the CURRENT (wider) YuzuPluginDescriptor, so reading
    // d->sdk_version back through it proves the append-only convention
    // actually holds for the field adjacent to the append: its byte offset
    // is identical in both layouts, so the value the ABI3 fixture set
    // (YUZU_PLUGIN_SDK_VERSION, frozen at "0.1.0" in plugin_abi3.h) reads
    // back correctly through the wider view.
    SECTION("sdk_version (field adjacent to the ABI4 append) reads correctly through the wider view") {
        REQUIRE(d->sdk_version != nullptr);
        CHECK(std::string_view{d->sdk_version} == "0.1.0");
    }

    SECTION("int-only execute() path works end to end") {
        REQUIRE(d->execute != nullptr);
        int rc_ok = d->execute(nullptr, "ping", nullptr, 0);
        CHECK(rc_ok == 0);
        int rc_fail = d->execute(nullptr, "unknown-action", nullptr, 0);
        CHECK(rc_fail != 0);
    }

    SECTION("actions array is null-terminated and non-empty") {
        REQUIRE(d->actions != nullptr);
        REQUIRE(d->actions[0] != nullptr);
        CHECK(std::string_view{d->actions[0]} == "ping");
    }
}

// The section above dlopens the fixture directly and re-derives the
// [MIN,VERSION] comparison inline — proving the fixture itself is a real
// old-layout binary. This test instead drives the SAME fixture through the
// actual production entry point (PluginHandle::load(), plugin_loader.cpp:401)
// so a regression in the production loader's validation/descriptor-access
// path (as opposed to the comparison logic alone) also turns this suite red.
TEST_CASE("ABI3 fixture: PluginHandle::load() (production loader) accepts it",
         "[capability][abi3][loader]") {
    auto fixture_path = find_abi3_fixture();
    if (fixture_path.empty()) {
        FAIL("abi3_fixture_plugin" << kPluginExt
                                   << " not found under tests/ (or $MESON_BUILD_ROOT/tests/) — "
                                      "see the previous test case's message.");
    }

    auto result = yuzu::agent::PluginHandle::load(fixture_path);
    REQUIRE(result.has_value());

    const YuzuPluginDescriptor* d = result->descriptor();
    REQUIRE(d != nullptr);
    CHECK(d->abi_version == 3);

    REQUIRE(d->execute != nullptr);
    CHECK(d->execute(nullptr, "ping", nullptr, 0) == 0);
}

// plugin B2(b): the REAL hazard is not a display nit, it is memory safety —
// action_descriptors/action_descriptor_count do not exist at all in the
// fixture's actual ABI3-frozen allocation (tests/fixtures/abi3/
// plugin_abi3.h ends at sdk_version), so a consumer that reads
// action_descriptor_count off this descriptor without the ABI gate reads
// past the end of the real object. gated_action_descriptor_count()
// (agents/core/src/plugin_loader.cpp, called from PluginHandle::load()'s
// diagnostic log line) is the single place that gate lives — this test
// binds it directly through the production loader path.
TEST_CASE("plugin B2: ABI3 descriptor yields action_descriptor_count 0 through the loader's gate",
         "[capability][abi3][loader]") {
    auto fixture_path = find_abi3_fixture();
    if (fixture_path.empty()) {
        FAIL("abi3_fixture_plugin" << kPluginExt
                                   << " not found under tests/ — see the earlier test case's "
                                      "message.");
    }

    auto result = yuzu::agent::PluginHandle::load(fixture_path);
    REQUIRE(result.has_value());

    const YuzuPluginDescriptor* d = result->descriptor();
    REQUIRE(d != nullptr);
    REQUIRE(d->abi_version == 3);

    CHECK(yuzu::agent::gated_action_descriptor_count(d) == 0);
}

// plugin B2, deterministic complement to the test above: whether reading
// action_descriptor_count off the REAL frozen ABI3 fixture past its actual
// (shorter) allocation happens to come back as 0 or as garbage depends on
// whatever bytes the linker placed after that fixture's static descriptor —
// undefined behavior, not a reliable mutation signal (confirmed empirically:
// mutating the loader's gate from >= 4 to >= 3 did NOT flip the test above on
// this build, because the trailing memory happened to read back zero anyway).
// This test isolates the gate's pure decision logic instead: a fully
// in-bounds, fully-populated ABI4-shaped descriptor whose abi_version field
// alone claims "3", carrying a deliberately nonzero, fully-owned
// action_descriptor_count sentinel. No out-of-bounds read is possible either
// way, so the ONLY thing this can be testing is the abi_version comparison —
// a broken gate reads back the controlled sentinel (42) instead of 0,
// unconditionally, regardless of struct-layout happenstance.
TEST_CASE("plugin B2: gated_action_descriptor_count ignores a populated count when abi_version < 4",
         "[capability][abi3][loader]") {
    const YuzuActionDescriptor sentinel_descriptors[1] = {};
    YuzuPluginDescriptor d{};
    d.abi_version = 3; // claims ABI3 even though this struct is fully ABI4-sized
    d.action_descriptors = sentinel_descriptors;
    d.action_descriptor_count = 42; // nonzero, fully in-bounds — never UB to read

    CHECK(yuzu::agent::gated_action_descriptor_count(&d) == 0);
}
