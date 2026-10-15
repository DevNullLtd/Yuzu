/**
 * test_execution_artifacts_win_internals.cpp — TU-inclusion seam over
 * execution_artifacts_win.cpp's internal-linkage AmcacheWalkFns/
 * walk_amcache_inventory/PrefetchEnumFns/PrefetchLimits/collect_prefetch_from/
 * ScratchDirGuard/g_temp_cleanup_failed_total (#4392). Exercises the
 * injected-fake paths test_execution_artifacts_win_local.cpp cannot reach
 * against the real hive/filesystem: ScratchDirGuard's deletion-failure
 * branch, and every named accumulator token the amcache subkey walk and
 * prefetch enumeration can emit (subkey_cap, enum_<code>,
 * subkey_open_failed, value_read_failed, value_enum_incomplete, file_cap,
 * byte_cap, prefetch_enum_<code>).
 *
 * TU-inclusion precedent: autoruns_macos.cpp's
 * YUZU_AUTORUNS_MACOS_UNIT_TEST_INTERNALS_ONLY seam
 * (test_autoruns_macos_local.cpp:336-367) — this is the first WINDOWS
 * instance of that same repo pattern (no sibling Windows plugin has an
 * OS-call seam today: registry/autoruns_win/rdp_control/
 * windows_optional_features all call Win32 inline).
 *
 * `#if defined(_WIN32)` guards the WHOLE body — empty TU elsewhere. Unlike
 * test_execution_artifacts_win_local.cpp's unguarded registration (which
 * asserts a fixed cross-platform contract against the REAL plugin loaded at
 * runtime), the fakes here are typed in terms of Win32-only types
 * (HKEY/WIN32_FIND_DATAW), and execution_artifacts_win.cpp itself compiles
 * to nothing off Windows — there is no seam here for a non-Windows host to
 * exercise, only a translation unit to keep present for meson's unconditional
 * source list (win_local.cpp's own "why an unguarded TU" rationale, applied
 * in the opposite direction: this file MUST short-circuit to empty instead).
 */
#if !defined(_WIN32)

// Nothing to test off Windows — see the file banner above.

#else // defined(_WIN32)

#include <catch2/catch_test_macros.hpp>

#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <yuzu/agent/confined_fs.hpp> // WinHandle
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

// Direct source inclusion (#4392), mirroring autoruns_macos.cpp's identical
// seam (see that file's own banner, and execution_artifacts_win.cpp's guard-
// macro definition comment just above its own `#ifndef`):
// AmcacheWalkFns/walk_amcache_inventory/PrefetchEnumFns/PrefetchLimits/
// collect_prefetch_from/ScratchDirGuard/g_temp_cleanup_failed_total all have
// internal (anonymous-namespace) linkage, so there is no header seam to
// reach them through otherwise. This TU never statically links the real
// plugin either way (test_execution_artifacts_win_local.cpp's/
// test_execution_artifacts_local_dispatcher.cpp's own TEST_CASEs load it via
// PluginHandle::load/dlopen at runtime), so a second compilation of the same
// free functions here creates no ODR/duplicate-symbol conflict. Never
// defined by this TU's own (real) build — meson.build does not set it.
// Excluding collect_shimcache/collect_amcache/collect_prefetch leaves a
// couple of the moved-out section's own helpers with no caller in THIS
// compilation of the TU — real, used call sites in the actual (non-test)
// build of this same file. MSVC's C4505 (unused static function) is the
// twin of GCC/Clang's -Wunused-function; silenced narrowly around just the
// include, rather than annotating production functions [[maybe_unused]] for
// a warning that only fires in this one test-only re-inclusion.
#define YUZU_EXECUTION_ARTIFACTS_WIN_UNIT_TEST_INTERNALS_ONLY 1
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4505)
#endif
#include "../../agents/plugins/execution_artifacts/src/execution_artifacts_win.cpp"
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
#undef YUZU_EXECUTION_ARTIFACTS_WIN_UNIT_TEST_INTERNALS_ONLY

using namespace yuzu::execution_artifacts;

namespace {

std::vector<std::string> captured_rows(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            out.push_back(line);
    }
    return out;
}

std::size_t count_prefix(const std::vector<std::string>& rows, std::string_view prefix) {
    return static_cast<std::size_t>(std::count_if(
        rows.begin(), rows.end(), [&](const std::string& r) { return r.rfind(prefix, 0) == 0; }));
}

std::string first_with_prefix(const std::vector<std::string>& rows, std::string_view prefix) {
    for (const auto& r : rows) {
        if (r.rfind(prefix, 0) == 0)
            return r;
    }
    return {};
}

// ── fake CommandContext harness ─────────────────────────────────────────
//
// Mirrors test_licensing_sync.cpp:48-70's fake-descriptor shape, adapted to
// run an injected body against a REAL yuzu::CommandContext (so
// ctx.write_output/ctx.set_result_status reach the SAME
// yuzu_ctx_write_output capture + typed-status plumbing LocalDispatcher
// uses for the real plugin) instead of emitting canned output text.
std::function<int(yuzu::CommandContext&)> g_body;

int fake_seam_execute(YuzuCommandContext* raw_ctx, const char* /*action*/,
                      const YuzuParam* /*params*/, std::size_t /*param_count*/) {
    yuzu::CommandContext ctx(raw_ctx);
    return g_body(ctx);
}

const char* const kFakeActions[] = {"seam", nullptr};

const YuzuPluginDescriptor kFakeDescriptor = {
    /*abi_version=*/YUZU_PLUGIN_ABI_VERSION,
    /*name=*/"execution_artifacts_seam",
    /*version=*/"1.0.0",
    /*description=*/"test-only execution_artifacts internals fixture",
    /*actions=*/kFakeActions,
    /*init=*/nullptr,
    /*shutdown=*/nullptr,
    /*execute=*/fake_seam_execute,
    /*sdk_version=*/nullptr,
};

yuzu::agent::LocalDispatcher::Result run_with_ctx(std::function<int(yuzu::CommandContext&)> body) {
    g_body = std::move(body);
    auto result = yuzu::agent::LocalDispatcher{}.run(&kFakeDescriptor, "seam");
    g_body = nullptr;
    return result;
}

// ── real, salted HKCU fixture for the amcache subkey-walk tests ─────────
//
// test_spark_mechanism.cpp's PID-salted-subkey precedent, widened with
// process_random_salt() (test_helpers.hpp) plus a per-process counter so
// several TEST_CASEs in this one binary never collide.
struct AmcacheTestKey {
    std::wstring sub_path;
    HKEY root = nullptr;

    explicit AmcacheTestKey(int n_children) {
        static std::atomic<std::uint64_t> counter{0};
        const auto n = counter.fetch_add(1, std::memory_order_relaxed);
        const std::string sub = "Software\\Yuzu\\yuzu_test_execart_" +
                                std::to_string(::GetCurrentProcessId()) + "_" +
                                std::to_string(yuzu::test::process_random_salt()) + "_" +
                                std::to_string(n);
        sub_path = yuzu::win::to_wide(sub);
        REQUIRE(RegCreateKeyExW(HKEY_CURRENT_USER, sub_path.c_str(), 0, nullptr, 0,
                                KEY_READ | KEY_WRITE, nullptr, &root, nullptr) == ERROR_SUCCESS);
        for (int i = 0; i < n_children; ++i) {
            HKEY child = nullptr;
            const std::wstring name = L"child" + std::to_wstring(i);
            REQUIRE(RegCreateKeyExW(root, name.c_str(), 0, nullptr, 0, KEY_READ | KEY_WRITE,
                                    nullptr, &child, nullptr) == ERROR_SUCCESS);
            RegCloseKey(child);
        }
    }

    ~AmcacheTestKey() {
        if (root)
            RegCloseKey(root);
        RegDeleteTreeW(HKEY_CURRENT_USER, sub_path.c_str());
    }

    AmcacheTestKey(const AmcacheTestKey&) = delete;
    AmcacheTestKey& operator=(const AmcacheTestKey&) = delete;

    void set_child_value(int index, const wchar_t* value_name, const wchar_t* value) const {
        HKEY child = nullptr;
        const std::wstring name = L"child" + std::to_wstring(index);
        REQUIRE(RegOpenKeyExW(root, name.c_str(), 0, KEY_READ | KEY_WRITE, &child) ==
               ERROR_SUCCESS);
        const DWORD bytes = static_cast<DWORD>((std::wcslen(value) + 1) * sizeof(wchar_t));
        REQUIRE(RegSetValueExW(child, value_name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value),
                               bytes) == ERROR_SUCCESS);
        RegCloseKey(child);
    }
};

void write_garbage_pf_files(const fs::path& dir, int count, std::size_t size_bytes = 16) {
    for (int i = 0; i < count; ++i) {
        std::ofstream f(dir / (std::string("f") + std::to_string(i) + ".pf"), std::ios::binary);
        f << std::string(size_bytes, 'X');
    }
}

} // namespace

// ── T1: ScratchDirGuard's deletion-failure path ──────────────────────────

TEST_CASE("execution_artifacts win internals: ScratchDirGuard reports note|temp_cleanup_failed "
          "and advances g_temp_cleanup_failed_total exactly once when removal genuinely fails, "
          "then a clean removal emits no note",
          "[execution_artifacts][win_internals]") {
    yuzu::test::TempDir dir("yuzu_test_execart_guard_");
    const fs::path locked_sub = dir.path / "locked";
    fs::create_directories(locked_sub);
    const fs::path locked_file = locked_sub / "held.txt";
    { std::ofstream(locked_file) << "held"; }
    const std::wstring wpath = yuzu::win::to_wide(locked_sub.string());

    // Held open WITHOUT FILE_SHARE_DELETE -- RemoveDirectoryW (what
    // std::filesystem::remove_all uses internally) fails with
    // ERROR_SHARING_VIOLATION while a handle without FILE_SHARE_DELETE stays
    // open on a file inside the directory being removed.
    yuzu::agent::confined_fs::WinHandle held(
        CreateFileW(yuzu::win::to_wide(locked_file.string()).c_str(), GENERIC_READ,
                    FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    REQUIRE(held.get() != INVALID_HANDLE_VALUE);

    const std::uint64_t before = g_temp_cleanup_failed_total.load(std::memory_order_relaxed);
    auto result = run_with_ctx([&](yuzu::CommandContext& ctx) -> int {
        { ScratchDirGuard guard(ctx, wpath); }
        return 0;
    });
    const std::uint64_t after = g_temp_cleanup_failed_total.load(std::memory_order_relaxed);

    const auto rows = captured_rows(result.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows.front() == "note|temp_cleanup_failed");
    CHECK(after == before + 1);
    CHECK(fs::exists(locked_sub)); // removal genuinely failed, not just under-reported

    held.reset();

    // A second guard over the now-unheld path removes it cleanly: no note row.
    auto result2 = run_with_ctx([&](yuzu::CommandContext& ctx) -> int {
        { ScratchDirGuard guard2(ctx, wpath); }
        return 0;
    });
    CHECK(captured_rows(result2.captured).empty());
    CHECK_FALSE(fs::exists(locked_sub));
}

// ── T2-T5b: walk_amcache_inventory's injected-fake accumulator tokens ────

TEST_CASE("execution_artifacts win internals: walk_amcache_inventory caps at max_subkeys "
          "(subkey_cap) against a real HKCU subtree",
          "[execution_artifacts][win_internals]") {
    AmcacheTestKey key(3);

    yuzu::shared::ConstraintAccumulator acc;
    auto result = walk_amcache_inventory(key.root, acc, {}, /*max_subkeys=*/2);

    CHECK(result.size() == 2);
    CHECK(acc.incomplete());
    CHECK(acc.reason().find("subkey_cap") != std::string::npos);
}

TEST_CASE("execution_artifacts win internals: walk_amcache_inventory records enum_<code> on a "
          "mid-walk RegEnumKeyExW failure, keeping the entries collected before the fault",
          "[execution_artifacts][win_internals]") {
    AmcacheTestKey key(2);

    AmcacheWalkFns fns;
    fns.enum_key = [](HKEY r, DWORD idx, wchar_t* name, DWORD* name_len) -> LSTATUS {
        if (idx >= 1)
            return ERROR_ACCESS_DENIED;
        return real_enum_key(r, idx, name, name_len);
    };

    yuzu::shared::ConstraintAccumulator acc;
    auto result = walk_amcache_inventory(key.root, acc, fns);

    CHECK(result.size() == 1);
    CHECK(acc.incomplete());
    CHECK(acc.reason().find("enum_5") != std::string::npos); // ERROR_ACCESS_DENIED == 5
}

TEST_CASE("execution_artifacts win internals: walk_amcache_inventory records "
          "subkey_open_failed when RegOpenKeyExW fails on an enumerated subkey, never handing "
          "the untouched out-param HKEY onward",
          "[execution_artifacts][win_internals]") {
    AmcacheTestKey key(1);

    AmcacheWalkFns fns;
    fns.open_subkey = [](HKEY, const wchar_t*, HKEY* out) -> LSTATUS {
        (void)out; // deliberately left untouched -- a failing open never hands a bogus HKEY on
        return ERROR_FILE_NOT_FOUND;
    };

    yuzu::shared::ConstraintAccumulator acc;
    auto result = walk_amcache_inventory(key.root, acc, fns);

    CHECK(result.empty());
    CHECK(acc.incomplete());
    CHECK(acc.reason().find("subkey_open_failed") != std::string::npos);
}

TEST_CASE("execution_artifacts win internals: walk_amcache_inventory records value_read_failed "
          "and still keeps the subkey, with an empty value map",
          "[execution_artifacts][win_internals]") {
    AmcacheTestKey key(1);
    key.set_child_value(0, L"Foo", L"Bar");

    AmcacheWalkFns fns;
    fns.read_value = [](HKEY, const std::string&, std::string&,
                        std::string&) -> yuzu::win::ReadValueStatus {
        return yuzu::win::ReadValueStatus::malformed;
    };

    yuzu::shared::ConstraintAccumulator acc;
    auto result = walk_amcache_inventory(key.root, acc, fns);

    REQUIRE(result.size() == 1);
    CHECK(result.front().second.empty());
    CHECK(acc.incomplete());
    CHECK(acc.reason().find("value_read_failed") != std::string::npos);
}

TEST_CASE("execution_artifacts win internals: walk_amcache_inventory records "
          "value_enum_incomplete when enumerate_value_names reports an incomplete walk",
          "[execution_artifacts][win_internals]") {
    AmcacheTestKey key(1);

    AmcacheWalkFns fns;
    fns.enum_values = [](HKEY) -> yuzu::win::ValueNameEnumeration {
        return yuzu::win::ValueNameEnumeration{.names = {}, .complete = false};
    };

    yuzu::shared::ConstraintAccumulator acc;
    auto result = walk_amcache_inventory(key.root, acc, fns);

    REQUIRE(result.size() == 1);
    CHECK(acc.incomplete());
    CHECK(acc.reason().find("value_enum_incomplete") != std::string::npos);
}

// ── T6-T9: collect_prefetch_from's caps and mid-walk enumeration fault ───

TEST_CASE("execution_artifacts win internals: collect_prefetch_from enforces file_cap",
          "[execution_artifacts][win_internals]") {
    yuzu::test::TempDir dir("yuzu_test_execart_prefetch_filecap_");
    fs::create_directories(dir.path);
    write_garbage_pf_files(dir.path, 5);

    auto result = run_with_ctx([&](yuzu::CommandContext& ctx) -> int {
        return collect_prefetch_from(ctx, (dir.path / "*.pf").wstring().c_str(),
                                     (dir.path.wstring() + L"\\").c_str(),
                                     PrefetchLimits{.max_files = 3});
    });

    const auto rows = captured_rows(result.captured);
    CHECK(result.rc == 1);
    CHECK(count_prefix(rows, "prefetch_error|") == 3);
    REQUIRE(count_prefix(rows, "constrained|") == 1);
    CHECK(first_with_prefix(rows, "constrained|").find("file_cap") != std::string::npos);
}

TEST_CASE("execution_artifacts win internals: collect_prefetch_from enforces byte_cap",
          "[execution_artifacts][win_internals]") {
    yuzu::test::TempDir dir("yuzu_test_execart_prefetch_bytecap_");
    fs::create_directories(dir.path);
    write_garbage_pf_files(dir.path, 5); // 16 bytes each

    auto result = run_with_ctx([&](yuzu::CommandContext& ctx) -> int {
        return collect_prefetch_from(ctx, (dir.path / "*.pf").wstring().c_str(),
                                     (dir.path.wstring() + L"\\").c_str(),
                                     PrefetchLimits{.total_max_bytes = 40});
    });

    const auto rows = captured_rows(result.captured);
    CHECK(result.rc == 1);
    CHECK(count_prefix(rows, "prefetch_error|") == 2); // 16 + 16 = 32 <= 40; the 3rd would be 48
    REQUIRE(count_prefix(rows, "constrained|") == 1);
    CHECK(first_with_prefix(rows, "constrained|").find("byte_cap") != std::string::npos);
}

TEST_CASE("execution_artifacts win internals: collect_prefetch_from with default limits treats "
          "five failed .pf parses as OK/PARTIAL, never CONSTRAINED -- per-file errors never "
          "fail the action",
          "[execution_artifacts][win_internals]") {
    yuzu::test::TempDir dir("yuzu_test_execart_prefetch_contract_");
    fs::create_directories(dir.path);
    write_garbage_pf_files(dir.path, 5);

    auto result = run_with_ctx([&](yuzu::CommandContext& ctx) -> int {
        return collect_prefetch_from(ctx, (dir.path / "*.pf").wstring().c_str(),
                                     (dir.path.wstring() + L"\\").c_str());
    });

    const auto rows = captured_rows(result.captured);
    CHECK(result.rc == 0);
    CHECK(count_prefix(rows, "prefetch_error|") == 5);
    CHECK(count_prefix(rows, "constrained|") == 0);
    CHECK(result.result_status == YUZU_RESULT_STATUS_OK);
}

TEST_CASE("execution_artifacts win internals: collect_prefetch_from records "
          "prefetch_enum_<code> on a mid-walk FindNextFileW failure",
          "[execution_artifacts][win_internals]") {
    yuzu::test::TempDir dir("yuzu_test_execart_prefetch_midwalk_");
    fs::create_directories(dir.path);
    write_garbage_pf_files(dir.path, 2);

    PrefetchEnumFns fns;
    fns.find_next = [](HANDLE, WIN32_FIND_DATAW*) -> BOOL {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    };

    auto result = run_with_ctx([&](yuzu::CommandContext& ctx) -> int {
        return collect_prefetch_from(ctx, (dir.path / "*.pf").wstring().c_str(),
                                     (dir.path.wstring() + L"\\").c_str(), {}, fns);
    });

    const auto rows = captured_rows(result.captured);
    CHECK(result.rc == 1);
    CHECK(count_prefix(rows, "prefetch_error|") == 1); // the one file processed before the fault
    REQUIRE(count_prefix(rows, "constrained|") == 1);
    CHECK(first_with_prefix(rows, "constrained|").find("prefetch_enum_5") != std::string::npos);
    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
}

#endif // defined(_WIN32)
