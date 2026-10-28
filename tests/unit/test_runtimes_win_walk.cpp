/**
 * test_runtimes_win_walk.cpp -- the runtimes plugin's Windows PythonCore (PEP 514) registry walk
 * (runtimes_win_parsers.hpp, SAM.1).
 *
 * Two layers, both Windows-only (the walk does not exist elsewhere; a no-op TU on macOS/Linux):
 *   - a scripted FakeOps injected through the walk's registry-call seam drives every branch
 *     deterministically (absent / denied roots, a view present on one side only, a missing Version,
 *     ERROR_MORE_DATA on a tag name, the tag cap across both views, handle accounting);
 *   - one end-to-end case reads a planted tag under an isolated, process-suffixed HKCU scratch key
 *     through RealRegOps (Reg*W only), so the real registry decode path runs once.
 *
 * TEST-EFFICIENCY: in-memory fakes plus one scratch key; no subprocess, no timing assumptions.
 * The scratch key is process-suffixed like test_installed_apps_registry_walk.cpp's (the shared-identity
 * CI runner invariant: a fixed key name would collide across concurrent jobs).
 */
#include <catch2/catch_test_macros.hpp>

#ifdef _WIN32

#include "runtimes_win_parsers.hpp"

#include <win_reg_handle.hpp>

#include <cstring>
#include <cwchar>
#include <map>
#include <string>
#include <vector>

namespace {

namespace rwin = yuzu::runtimes::win;
using yuzu::shared::ConstraintAccumulator;

// -- scripted registry ----------------------------------------------------------------------
// Handles are small fake integers into `paths`; every open is counted so a test also proves the walk
// closes exactly what it opened (and never calls RegCloseKey on a fake).
struct Node {
    std::vector<std::wstring> children;
    std::map<std::wstring, std::string> values; // L"" = default value
    LSTATUS open_rc = ERROR_SUCCESS;
    LSTATUS enum_rc = ERROR_SUCCESS; // returned instead of the child at enum_fail_at
    std::size_t enum_fail_at = static_cast<std::size_t>(-1);
};

struct FakeOps {
    mutable std::map<std::wstring, Node> nodes;      // "<view>\<path>"
    mutable std::vector<std::wstring> paths;          // handle -> node key
    mutable int opened = 0;
    mutable int closed = 0;

    static std::wstring view_of(REGSAM sam) { return (sam & KEY_WOW64_32KEY) ? L"32" : L"64"; }

    Node& node(const std::wstring& view, const std::wstring& path) const {
        return nodes[view + L"\\" + path];
    }

    // plants <core>\<tag> with the given values and an optional InstallPath
    void add_tag(const std::wstring& view, const std::wstring& tag, const std::string& version,
                 const std::string& sys_version, const std::string& install_path) const {
        const std::wstring core = L"SOFTWARE\\Python\\PythonCore";
        auto& c = node(view, core);
        c.children.push_back(tag);
        auto& t = node(view, core + L"\\" + tag);
        if (!version.empty()) t.values[L"Version"] = version;
        if (!sys_version.empty()) t.values[L"SysVersion"] = sys_version;
        if (!install_path.empty()) {
            node(view, core + L"\\" + tag + L"\\InstallPath").values[L""] = install_path;
            t.children.push_back(L"InstallPath");
        }
    }

    LSTATUS open(HKEY parent, const wchar_t* sub, REGSAM sam, HKEY* out) const {
        std::wstring key;
        if (parent == HKEY_LOCAL_MACHINE) {
            key = view_of(sam) + L"\\" + sub;
        } else {
            key = paths[reinterpret_cast<std::size_t>(parent) - 1] + L"\\" + sub;
        }
        const auto it = nodes.find(key);
        if (it == nodes.end()) return ERROR_FILE_NOT_FOUND;
        if (it->second.open_rc != ERROR_SUCCESS) return it->second.open_rc;
        paths.push_back(key);
        ++opened;
        *out = reinterpret_cast<HKEY>(paths.size());
        return ERROR_SUCCESS;
    }
    LSTATUS enum_key(HKEY key, DWORD idx, wchar_t* name, DWORD* name_len) const {
        const Node& n = nodes.at(paths[reinterpret_cast<std::size_t>(key) - 1]);
        if (idx == n.enum_fail_at) return n.enum_rc;
        if (idx >= n.children.size()) return ERROR_NO_MORE_ITEMS;
        const std::wstring& c = n.children[idx];
        if (c.size() >= *name_len) return ERROR_MORE_DATA;
        std::wmemcpy(name, c.c_str(), c.size() + 1);
        *name_len = static_cast<DWORD>(c.size());
        return ERROR_SUCCESS;
    }
    void close(HKEY) const { ++closed; }
    std::string read_str(HKEY key, const wchar_t* value_name) const {
        const Node& n = nodes.at(paths[reinterpret_cast<std::size_t>(key) - 1]);
        const auto it = n.values.find(value_name ? value_name : L"");
        return it == n.values.end() ? std::string{} : it->second;
    }
};

const std::wstring kCore = L"SOFTWARE\\Python\\PythonCore";

} // namespace

TEST_CASE("runtimes win: no PythonCore key in either view is supported with zero rows",
          "[runtimes][python][windows]") {
    FakeOps ops;
    ConstraintAccumulator acc;
    CHECK(rwin::python_rows(ops, acc).empty());
    CHECK_FALSE(acc.any_failure());
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: a tag present in one view only is a row; the same install in both views is one",
          "[runtimes][python][windows]") {
    FakeOps ops;
    ops.add_tag(L"64", L"3.14", "3.14.6", "3.14", "C:\\Python314\\");
    ops.add_tag(L"32", L"3.12-32", "3.12.4", "3.12", "C:\\Python312-32\\");
    ops.add_tag(L"32", L"3.14", "3.14", "3.14", "C:\\Python314\\"); // same path through the other view
    ConstraintAccumulator acc;
    const auto rows = rwin::python_rows(ops, acc);
    CHECK_FALSE(acc.any_failure());
    // 64-bit view first; the duplicate path keeps the first (full-version) record.
    CHECK(rows == std::vector<std::string>{"python|cpython|3.14.6|C:/Python314/|PythonCore",
                                           "python|cpython|3.12.4|C:/Python312-32/|PythonCore"});
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: a denied root is access_denied, never an empty success",
          "[runtimes][python][windows]") {
    FakeOps ops;
    ops.node(L"64", kCore).open_rc = ERROR_ACCESS_DENIED;
    ops.add_tag(L"32", L"3.12", "3.12.4", "3.12", "C:\\Python312\\");
    ConstraintAccumulator acc;
    const auto rows = rwin::python_rows(ops, acc);
    CHECK(acc.reason() == std::string{rwin::kTokAccessDenied});
    CHECK(rows.size() == 1); // the other view is still read
}

TEST_CASE("runtimes win: any other failed root open is open_failed", "[runtimes][python][windows]") {
    FakeOps ops;
    ops.node(L"64", kCore).open_rc = ERROR_BAD_PATHNAME;
    ConstraintAccumulator acc;
    CHECK(rwin::python_rows(ops, acc).empty());
    CHECK(acc.reason() == std::string{rwin::kTokOpenFailed});
}

TEST_CASE("runtimes win: a tag without Version/SysVersion/InstallPath still reports what it has",
          "[runtimes][python][windows]") {
    FakeOps ops;
    ops.add_tag(L"64", L"3.13-arm64", "", "", "");
    ConstraintAccumulator acc;
    // The tag's major.minor stands in for the missing values; a metadata shortfall raises no token.
    CHECK(rwin::python_rows(ops, acc) ==
          std::vector<std::string>{"python|cpython|3.13|-|PythonCore"});
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("runtimes win: a tag with nothing parseable is a row with an unknown version",
          "[runtimes][python][windows]") {
    FakeOps ops;
    ops.add_tag(L"64", L"weird", "x", "y", "C:\\Weird\\");
    ConstraintAccumulator acc;
    CHECK(rwin::python_rows(ops, acc) == std::vector<std::string>{"python|cpython|-|C:/Weird/|PythonCore"});
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("runtimes win: a tag name over the buffer is name_too_long and the other tags are still read",
          "[runtimes][python][windows]") {
    FakeOps ops;
    auto& core = ops.node(L"64", kCore);
    core.children.push_back(std::wstring(300, L'x')); // enum answers ERROR_MORE_DATA
    ops.add_tag(L"64", L"3.11", "3.11.9", "3.11", "C:\\Python311\\");
    ConstraintAccumulator acc;
    const auto rows = rwin::python_rows(ops, acc);
    CHECK(acc.reason() == std::string{rwin::kTokNameTooLong});
    CHECK(rows == std::vector<std::string>{"python|cpython|3.11.9|C:/Python311/|PythonCore"});
}

TEST_CASE("runtimes win: an enumeration error keeps the rows read before it and records enum_failed",
          "[runtimes][python][windows]") {
    FakeOps ops;
    ops.add_tag(L"64", L"3.11", "3.11.9", "3.11", "C:\\Python311\\");
    auto& core = ops.node(L"64", kCore);
    core.enum_fail_at = 1;
    core.enum_rc = ERROR_GEN_FAILURE;
    ConstraintAccumulator acc;
    CHECK(rwin::python_rows(ops, acc).size() == 1);
    CHECK(acc.reason() == std::string{rwin::kTokEnumFailed});
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: a denied tag or InstallPath open is a token and the walk goes on",
          "[runtimes][python][windows]") {
    FakeOps ops;
    ops.add_tag(L"64", L"3.10", "3.10.1", "3.10", "C:\\Python310\\");
    ops.add_tag(L"64", L"3.11", "3.11.9", "3.11", "C:\\Python311\\");
    ops.node(L"64", kCore + L"\\3.10").open_rc = ERROR_ACCESS_DENIED; // tag key denied
    ops.node(L"64", kCore + L"\\3.11\\InstallPath").open_rc = ERROR_ACCESS_DENIED;
    ConstraintAccumulator acc;
    const auto rows = rwin::python_rows(ops, acc);
    CHECK(acc.reason() == std::string{rwin::kTokAccessDenied});
    // 3.10 produced no row (its key could not be read); 3.11 keeps its version, path unknown.
    CHECK(rows == std::vector<std::string>{"python|cpython|3.11.9|-|PythonCore"});
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: a tag that vanishes between enumerate and open is skipped silently",
          "[runtimes][python][windows]") {
    FakeOps ops;
    ops.node(L"64", kCore).children.push_back(L"3.9"); // listed, but no node: open -> FILE_NOT_FOUND
    ConstraintAccumulator acc;
    CHECK(rwin::python_rows(ops, acc).empty());
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("runtimes win: the tag cap spans both views and reports row_cap, keeping rows already read",
          "[runtimes][python][windows]") {
    FakeOps ops;
    // kMaxTagsVisited + 1 tags across the two views: half in each.
    const std::size_t total = rwin::kMaxTagsVisited + 1;
    for (std::size_t i = 0; i < total; ++i)
        ops.add_tag(i < total / 2 ? L"64" : L"32", L"3." + std::to_wstring(i), "3." + std::to_string(i) + ".0",
                    "", "C:\\Py" + std::to_string(i) + "\\");
    ConstraintAccumulator acc;
    const auto rows = rwin::python_rows(ops, acc);
    CHECK(acc.reason() == std::string{rwin::kTokRowCap});
    CHECK(rows.size() == rwin::kMaxTagsVisited); // the last tag was never visited
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: RealRegOps reads a planted PythonCore tag from an isolated scratch key",
          "[runtimes][python][windows]") {
    // The real Reg*W decode path, once: a process-suffixed key under HKCU stands in for HKLM
    // (python_rows takes the root as a parameter; production never opens HKCU). HKCU\Software is not
    // WOW-redirected, so both views see the same key and the dedupe leaves one row.
    const std::wstring sub =
        L"SOFTWARE\\YuzuTest\\RuntimesPython_" + std::to_wstring(GetCurrentProcessId());
    const std::wstring core = sub + L"\\PythonCore";
    struct Cleanup {
        const std::wstring& sub;
        ~Cleanup() { RegDeleteTreeW(HKEY_CURRENT_USER, sub.c_str()); RegDeleteKeyW(HKEY_CURRENT_USER, sub.c_str()); }
    } cleanup{sub};
    const auto create = [](const std::wstring& path) {
        HKEY k{};
        REQUIRE(RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr, 0, KEY_READ | KEY_WRITE,
                                nullptr, &k, nullptr) == ERROR_SUCCESS);
        return yuzu::win::RegKey{k};
    };
    const auto set_sz = [](HKEY k, const wchar_t* name, const wchar_t* v) {
        const DWORD bytes = static_cast<DWORD>((std::wcslen(v) + 1) * sizeof(wchar_t));
        REQUIRE(RegSetValueExW(k, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(v), bytes) ==
                ERROR_SUCCESS);
    };
    {
        const auto tag = create(core + L"\\3.99");
        set_sz(tag.get(), L"Version", L"3.99.1");
        set_sz(tag.get(), L"SysVersion", L"3.99");
        const auto ip = create(core + L"\\3.99\\InstallPath");
        set_sz(ip.get(), nullptr, L"C:\\YuzuTestPython399\\");
    }
    ConstraintAccumulator acc;
    const auto rows =
        rwin::python_rows(rwin::RealRegOps{}, acc, HKEY_CURRENT_USER, core.c_str());
    CHECK_FALSE(acc.any_failure());
    CHECK(rows == std::vector<std::string>{"python|cpython|3.99.1|C:/YuzuTestPython399/|PythonCore"});
}

#endif // _WIN32
