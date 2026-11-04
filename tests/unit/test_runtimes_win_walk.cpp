/**
 * test_runtimes_win_walk.cpp -- the runtimes plugin's Windows registry walks (runtimes_win_parsers.hpp):
 * PythonCore (PEP 514), .NET (InstalledVersions + the .NET Framework release table) and the JVM
 * registrations with their bounded `release` read.
 *
 * Three layers:
 *   - the pure helpers above the header's _WIN32 guard (the .NET Framework release table, the JVM home
 *     bookkeeping, the row finisher) run on EVERY OS;
 *   - Windows only: a scripted FakeOps injected through the walks' registry/file seam drives every
 *     branch deterministically (absent / denied roots, a view present on one side only, a missing
 *     Version, ERROR_MORE_DATA on a name, the visit cap across both views, the row-byte budget, the
 *     sorted output order, an unreadable `release` file, handle accounting), plus the leg body
 *     (run_windows_with) through a real CommandContext so the typed result status is asserted too;
 *   - Windows only: end-to-end cases through RealRegOps (Reg*W / CreateFileW only) on isolated,
 *     process-suffixed HKCU scratch keys and a scratch file, so the real decode paths run once.
 *
 * FIXTURES. The .NET and JVM shapes are taken from a real read-only capture of a Windows 11 host with
 * .NET 8/9 and Temurin 21 / Microsoft OpenJDK 21 installed (shared frameworks in the WOW6432Node view,
 * values written as DWORD 1, Temurin only under Eclipse Adoptium, Microsoft's JDK under BOTH Microsoft
 * and JavaSoft). Microsoft's `release` text is that capture's; the Temurin and Zulu `release` texts are
 * SYNTHETIC, built from the documented key="value" format.
 *
 * TEST-EFFICIENCY: in-memory fakes plus scratch keys; no subprocess, no timing assumptions. The scratch
 * keys are process-suffixed like test_installed_apps_registry_walk.cpp's (the shared-identity CI runner
 * invariant: a fixed key name would collide across concurrent jobs).
 */
#include <catch2/catch_test_macros.hpp>

#include "runtimes_win_parsers.hpp"

#include <string>
#include <vector>

// -- pure layer (every OS) ---------------------------------------------------------------------

TEST_CASE("runtimes win: the .NET Framework release table maps the highest threshold <= Release",
          "[runtimes][dotnet][windows]") {
    namespace rwin = yuzu::runtimes::win;
    // Every threshold maps to its own version and the value just below it to the previous one.
    for (std::size_t i = 0; i < rwin::kNetfxReleases.size(); ++i) {
        const auto& e = rwin::kNetfxReleases[i];
        INFO("threshold " << e.release);
        CHECK(rwin::netfx_version_from_release(e.release) == e.version);
        CHECK(rwin::netfx_version_from_release(e.release - 1) ==
              (i == 0 ? std::string_view{} : rwin::kNetfxReleases[i - 1].version));
        if (i > 0) CHECK(rwin::kNetfxReleases[i - 1].release < e.release); // ascending: last match wins
    }
    CHECK(rwin::netfx_version_from_release(528040) == "4.8");
    CHECK(rwin::netfx_version_from_release(528049) == "4.8"); // a later 4.8 servicing build
    CHECK(rwin::netfx_version_from_release(533320) == "4.8.1");
    CHECK(rwin::netfx_version_from_release(999999) == "4.8.1"); // above the table: the highest known
    CHECK(rwin::netfx_version_from_release(0).empty());
    CHECK(rwin::netfx_version_from_release(378388).empty());
}

TEST_CASE("runtimes win: JVM home bookkeeping dedupes by path however it is spelled",
          "[runtimes][jvm][windows]") {
    namespace rwin = yuzu::runtimes::win;
    CHECK(rwin::jvm_home_key("C:\\Program Files\\Temurin\\") == rwin::jvm_home_key("c:/program files/temurin"));
    CHECK(rwin::jvm_release_path("C:\\Program Files\\Temurin\\") == "C:\\Program Files\\Temurin\\release");
    CHECK(rwin::jvm_release_path("C:/jdk") == "C:/jdk\\release");
    CHECK(rwin::is_local_drive_path("C:\\jdk"));
    CHECK(rwin::is_local_drive_path("d:/jdk"));
    for (const char* bad : {"", "C:", "C:jdk", "\\\\server\\share\\jdk", "\\\\.\\pipe\\x", "\\\\?\\C:\\jdk", "jdk\\home", "1:\\jdk"})
        CHECK_FALSE(rwin::is_local_drive_path(bad));

    std::vector<rwin::JvmHome> homes;
    rwin::add_jvm_home(homes, "C:\\Java\\jdk\\", "21");
    rwin::add_jvm_home(homes, "c:\\java\\jdk", "21.0.1"); // same home: one entry, the greater tag
    rwin::add_jvm_home(homes, "c:\\java\\jdk", "17");
    rwin::add_jvm_home(homes, "", "x");                      // no home: not an install
    REQUIRE(homes.size() == 1);
    CHECK(homes[0].home == "C:\\Java\\jdk\\");
    CHECK(homes[0].tag == "21.0.1");
}

TEST_CASE("runtimes win: a JVM home row comes from the release text, else the registry tag as unmodelled",
          "[runtimes][jvm][windows]") {
    namespace rwin = yuzu::runtimes::win;
    const rwin::JvmHome h{"k", "C:\\jdk\\", "21.0.1"};
    CHECK(rwin::jvm_home_row(h, std::string{"IMAGE_TYPE=\"JDK\"\nJAVA_VERSION=\"21.0.1\"\nIMPLEMENTOR=\"Acme\"\n"}) ==
          "jvm|jdk|21.0.1|C:/jdk/|Acme");
    // unreadable, absent, empty and versionless releases all keep the home as an unmodelled row
    CHECK(rwin::jvm_home_row(h, std::nullopt) == "jvm|unmodelled|21.0.1|C:/jdk/|-");
    CHECK(rwin::jvm_home_row(h, std::string{}) == "jvm|unmodelled|21.0.1|C:/jdk/|-");
    CHECK(rwin::jvm_home_row(h, std::string{"IMPLEMENTOR=\"Acme\"\n"}) == "jvm|unmodelled|21.0.1|C:/jdk/|-");
}

TEST_CASE("runtimes win: finish_rows sorts, dedupes and refuses rows past the byte budget",
          "[runtimes][windows]") {
    namespace rwin = yuzu::runtimes::win;
    yuzu::shared::ConstraintAccumulator acc;
    CHECK(rwin::finish_rows({"b", "a", "b"}, acc, "tok") == std::vector<std::string>{"a", "b"});
    CHECK_FALSE(acc.any_failure());
    // 3 rows of 400 KiB: two fit under 1 MiB, the third is refused and nothing later is admitted.
    const std::string big(400 * 1024, 'x');
    const auto rows = rwin::finish_rows({big + "1", big + "2", big + "3"}, acc, "tok");
    CHECK(rows.size() == 2);
    CHECK(acc.reason() == "tok");
}

#ifdef _WIN32

#include "local_dispatcher.hpp" // yuzu::agent::LocalDispatcher (a real CommandContext)
#include "test_helpers.hpp" // yuzu::test::ScopeExit

#include <win_reg_handle.hpp>
#include <yuzu/plugin.h>

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <map>
#include <numeric>
#include <optional>
#include <sstream>
#include <string>
#include <system_error>
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
    std::map<std::wstring, DWORD> dwords;       // REG_DWORD values (enumerated with no text)
    LSTATUS venum_rc = ERROR_SUCCESS;           // returned instead of the value at venum_fail_at
    std::size_t venum_fail_at = static_cast<std::size_t>(-1);
    LSTATUS open_rc = ERROR_SUCCESS;
    LSTATUS enum_rc = ERROR_SUCCESS; // returned instead of the child at enum_fail_at
    std::size_t enum_fail_at = static_cast<std::size_t>(-1);
};

struct FakeOps {
    mutable std::map<std::wstring, Node> nodes;      // "<view>\<path>"
    mutable std::vector<std::wstring> paths;          // handle -> node key
    mutable int opened = 0;
    mutable int closed = 0;
    // `release` files by full wide path: absent from the map = no such file, nullopt = it exists but
    // cannot be read (denied, a reparse point, over the cap). Every read is recorded.
    mutable std::map<std::wstring, std::optional<std::string>> files;
    mutable std::vector<std::wstring> file_reads;
    mutable std::size_t last_cap = 0;

    static std::wstring view_of(REGSAM sam) { return (sam & KEY_WOW64_32KEY) ? L"32" : L"64"; }

    Node& node(const std::wstring& view, const std::wstring& path) const {
        return nodes[view + L"\\" + path];
    }

    // Creates `path` (and every ancestor, each listed as its parent's child once).
    Node& mk(const std::wstring& view, const std::wstring& path) const {
        std::wstring parent;
        std::size_t start = 0;
        for (;;) {
            const auto sep = path.find(L'\\', start);
            const std::wstring leaf = path.substr(start, sep == std::wstring::npos ? sep : sep - start);
            Node& n = node(view, path.substr(0, sep));
            if (!parent.empty()) {
                auto& kids = node(view, parent).children;
                if (std::find(kids.begin(), kids.end(), leaf) == kids.end()) kids.push_back(leaf);
            }
            if (sep == std::wstring::npos) return n;
            parent = path.substr(0, sep);
            start = sep + 1;
        }
    }
    void set(const std::wstring& view, const std::wstring& path, const std::wstring& name,
             const std::string& v) const {
        mk(view, path).values[name] = v;
    }
    void setd(const std::wstring& view, const std::wstring& path, const std::wstring& name,
              DWORD v) const {
        mk(view, path).dwords[name] = v;
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
    std::optional<DWORD> read_dword(HKEY key, const wchar_t* value_name) const {
        const Node& n = nodes.at(paths[reinterpret_cast<std::size_t>(key) - 1]);
        const auto it = n.dwords.find(value_name);
        if (it == n.dwords.end()) return std::nullopt;
        return it->second;
    }
    // Text values first (the default value excluded, like the real walk's empty name), then DWORDs
    // with no text -- the order RegEnumValueW would not promise, which the walks must not rely on.
    LSTATUS enum_value(HKEY key, DWORD idx, wchar_t* name, DWORD* name_len,
                       std::string* data) const {
        const Node& n = nodes.at(paths[reinterpret_cast<std::size_t>(key) - 1]);
        if (idx == n.venum_fail_at) return n.venum_rc;
        std::vector<std::pair<std::wstring, std::string>> all;
        for (const auto& [k, v] : n.values)
            if (!k.empty()) all.emplace_back(k, v);
        for (const auto& [k, v] : n.dwords) all.emplace_back(k, std::string{});
        if (idx >= all.size()) return ERROR_NO_MORE_ITEMS;
        const auto& [k, v] = all[idx];
        if (k.size() >= *name_len) return ERROR_MORE_DATA;
        std::wmemcpy(name, k.c_str(), k.size() + 1);
        *name_len = static_cast<DWORD>(k.size());
        *data = v;
        return ERROR_SUCCESS;
    }
    std::optional<std::string> read_file_bounded(const std::wstring& path, std::size_t cap) const {
        file_reads.push_back(path);
        last_cap = cap;
        const auto it = files.find(path);
        if (it == files.end()) return std::string{};
        if (!it->second || it->second->size() > cap) return std::nullopt;
        return it->second;
    }
};

const std::wstring kCore = L"SOFTWARE\\Python\\PythonCore";
const std::wstring kIv = L"SOFTWARE\\dotnet\\Setup\\InstalledVersions";
const std::wstring kNdp4 = L"SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full";
const std::wstring kNdp35 = L"SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v3.5";
const std::wstring kJsJdk = L"SOFTWARE\\JavaSoft\\JDK";
const std::wstring kAdoptJdk = L"SOFTWARE\\Eclipse Adoptium\\JDK";
const std::wstring kZulu = L"SOFTWARE\\Azul Systems\\Zulu";

const std::string kDotnetDir = "C:\\Program Files\\dotnet\\";
const std::string kMsHome = "C:\\Program Files\\Microsoft\\jdk-21.0.12.101-hotspot\\";
const std::string kTemurinHome = "C:\\Program Files\\Temurin\\";
const std::string kZuluHome = "C:\\Program Files\\Zulu\\zulu-17";
const std::wstring kMsReleasePath = L"C:\\Program Files\\Microsoft\\jdk-21.0.12.101-hotspot\\release";
const std::wstring kTemurinReleasePath = L"C:\\Program Files\\Temurin\\release";
const std::wstring kZuluReleasePath = L"C:\\Program Files\\Zulu\\zulu-17\\release";
// Microsoft's is the captured `release` (MODULES trimmed); it has no IMAGE_TYPE key, so the flavour
// is `unmodelled`. Temurin's and Zulu's are SYNTHETIC, built from the documented key="value" format.
const std::string kMsRelease =
    "IMPLEMENTOR=\"Microsoft\"\nIMPLEMENTOR_VERSION=\"Microsoft-14941484\"\n"
    "JAVA_RUNTIME_VERSION=\"21.0.12.1+1-LTS\"\nJAVA_VERSION=\"21.0.12.1\"\n"
    "JAVA_VERSION_DATE=\"2026-08-18\"\nLIBC=\"default\"\nOS_ARCH=\"x86_64\"\nOS_NAME=\"Windows\"\n"
    "SOURCE=\".:git:6f26c6b2b098\"\n";
const std::string kTemurinRelease =
    "IMAGE_TYPE=\"JDK\"\nIMPLEMENTOR=\"Eclipse Adoptium\"\nJAVA_VERSION=\"21.0.13\"\n";
const std::string kZuluRelease =
    "IMAGE_TYPE=\"JRE\"\nIMPLEMENTOR=\"Azul Systems, Inc.\"\nJAVA_VERSION=\"17.0.9\"\n";

// <base>\<ver>[\<tail>] with `value` = home, in one view
void plant_jvm(const FakeOps& ops, const wchar_t* view, const std::wstring& base,
               const std::wstring& ver, const std::wstring& tail, const wchar_t* value,
               const std::string& home) {
    ops.set(view, base + L"\\" + ver + (tail.empty() ? L"" : L"\\" + tail), value, home);
}

// The three vendors as the captured host registers them, plus a release file per home.
void plant_three_vendors(const FakeOps& ops) {
    plant_jvm(ops, L"64", kJsJdk, L"21", L"", L"JavaHome", kMsHome); // Microsoft writes JavaSoft too
    plant_jvm(ops, L"64", kJsJdk, L"21.0.12.101", L"", L"JavaHome", kMsHome);
    ops.set(L"64", kJsJdk, L"CurrentVersion", "21"); // a value, not a version subkey
    plant_jvm(ops, L"64", kAdoptJdk, L"21.0.13.9", L"hotspot\\MSI", L"Path", kTemurinHome);
    plant_jvm(ops, L"32", kZulu, L"zulu17", L"", L"InstallationPath", kZuluHome);
    ops.files[kMsReleasePath] = kMsRelease;
    ops.files[kTemurinReleasePath] = kTemurinRelease;
    ops.files[kZuluReleasePath] = kZuluRelease;
}

const std::vector<std::string> kThreeVendorRows{
    "jvm|jdk|21.0.13|C:/Program Files/Temurin/|Eclipse Adoptium",
    "jvm|jre|17.0.9|C:/Program Files/Zulu/zulu-17|Azul Systems, Inc.",
    "jvm|unmodelled|21.0.12.1|C:/Program Files/Microsoft/jdk-21.0.12.101-hotspot/|Microsoft"};

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
    // The duplicate path keeps the first (64-bit, full-version) record; rows come out sorted by
    // (version, install path), so the 32-bit 3.12.4 precedes the 64-bit 3.14.6.
    CHECK(rows == std::vector<std::string>{"python|cpython|3.12.4|C:/Python312-32/|PythonCore",
                                           "python|cpython|3.14.6|C:/Python314/|PythonCore"});
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
    // kMaxEntriesVisited + 1 tags across the two views: half in each.
    const std::size_t total = rwin::kMaxEntriesVisited + 1;
    for (std::size_t i = 0; i < total; ++i)
        ops.add_tag(i < total / 2 ? L"64" : L"32", L"3." + std::to_wstring(i), "3." + std::to_string(i) + ".0",
                    "", "C:\\Py" + std::to_string(i) + "\\");
    ConstraintAccumulator acc;
    const auto rows = rwin::python_rows(ops, acc);
    CHECK(acc.reason() == std::string{rwin::kTokRowCap});
    CHECK(rows.size() == rwin::kMaxEntriesVisited); // the last tag was never visited
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: over-long tag names count against the tag cap too",
          "[runtimes][python][windows]") {
    // kMaxEntriesVisited + 1 names of 300 WCHARs: every enumeration answers ERROR_MORE_DATA. MUTATION:
    // taking the MORE_DATA `continue` before the counter lets a key stuffed with over-long names loop
    // to its last subkey with no cap, so row_cap is never recorded.
    FakeOps ops;
    auto& core = ops.node(L"64", kCore);
    for (std::size_t i = 0; i < rwin::kMaxEntriesVisited + 1; ++i)
        core.children.push_back(std::wstring(300, L'x'));
    ConstraintAccumulator acc;
    CHECK(rwin::python_rows(ops, acc).empty());
    CHECK(acc.reason() ==
          std::string{rwin::kTokNameTooLong} + "," + std::string{rwin::kTokRowCap});
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: rows are sorted by (version, install path) whatever the enumeration order",
          "[runtimes][python][windows]") {
    // RegEnumKeyEx order is unspecified, so the walk sorts after the dedupe. MUTATION: dropping the
    // sort emits enumeration order (64-bit view first), which differs between the two fakes below.
    struct Plant {
        const wchar_t* view;
        const wchar_t* tag;
        const char* version;
        const char* path;
    };
    const std::vector<Plant> plants{
        {L"64", L"3.14", "3.14.6", "C:\\Python314\\"},
        {L"64", L"3.10", "3.10.2", "C:\\Python310\\"},
        {L"32", L"3.12-32", "3.12.4", "C:\\Python312-32\\"},
        {L"32", L"3.10-32", "3.10.2", "C:\\Python310-32\\"},
    };
    // Both 3.10.2 rows tie on version; '-' (0x2D) sorts before a backslash (0x5C), so 310-32 is first.
    const std::vector<std::string> sorted{
        "python|cpython|3.10.2|C:/Python310-32/|PythonCore",
        "python|cpython|3.10.2|C:/Python310/|PythonCore",
        "python|cpython|3.12.4|C:/Python312-32/|PythonCore",
        "python|cpython|3.14.6|C:/Python314/|PythonCore"};
    for (const bool reversed : {false, true}) {
        INFO("tags planted " << (reversed ? "in reverse" : "in listed order"));
        FakeOps ops;
        if (reversed) {
            for (auto it = plants.rbegin(); it != plants.rend(); ++it)
                ops.add_tag(it->view, it->tag, it->version, "", it->path);
        } else {
            for (const auto& p : plants) ops.add_tag(p.view, p.tag, p.version, "", p.path);
        }
        ConstraintAccumulator acc;
        CHECK(rwin::python_rows(ops, acc) == sorted);
        CHECK_FALSE(acc.any_failure());
        CHECK(ops.opened == ops.closed);
    }
}

TEST_CASE("runtimes win: rows past the byte budget are refused with row_cap and nothing later is admitted",
          "[runtimes][python][windows]") {
    // 500 tags (under the tag cap) whose rows are ~2.2 KiB each overrun the 1 MiB RowByteBudget.
    // The short tag sorts LAST (version 9.9.9) and would fit on its own: it is absent only because
    // the walk stops at the first refusal. MUTATION: `continue` instead of `break` admits it;
    // dropping the charge emits all 501 rows.
    FakeOps ops;
    constexpr std::size_t kLong = 500;
    for (std::size_t i = 0; i < kLong; ++i)
        ops.add_tag(L"64", L"3." + std::to_wstring(i), "3." + std::to_string(i) + ".0", "",
                    "C:\\P" + std::to_string(i) + "\\" + std::string(2200, 'p') + "\\");
    ops.add_tag(L"64", L"9.9", "9.9.9", "", "C:\\Short\\");
    ConstraintAccumulator acc;
    const auto rows = rwin::python_rows(ops, acc);
    CHECK(acc.reason() == std::string{rwin::kTokRowCap});
    const std::size_t total = std::accumulate(rows.begin(), rows.end(), std::size_t{0},
                                              [](std::size_t n, const std::string& r) { return n + r.size(); });
    CHECK(total <= rwin::kMaxRowBytes);
    CHECK_FALSE(rows.empty());
    CHECK(rows.size() < kLong);
    CHECK(std::none_of(rows.begin(), rows.end(),
                       [](const std::string& r) { return r.find("9.9.9") != std::string::npos; }));
    CHECK(ops.opened == ops.closed);
}

// -- dotnet walk ----------------------------------------------------------------------------------

TEST_CASE("runtimes win: no dotnet keys in either view is supported with zero rows",
          "[runtimes][dotnet][windows]") {
    FakeOps ops;
    ConstraintAccumulator acc;
    CHECK(rwin::dotnet_rows(ops, acc).empty());
    CHECK_FALSE(acc.any_failure());
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: dotnet reads both views, ignores the shared host, and dedupes the same install",
          "[runtimes][dotnet][windows]") {
    // The captured host: the 64-bit view holds only the shared host, the shared frameworks sit in the
    // 32-bit view with DWORD 1 values, one tree per arch. A text path in the 64-bit view for the same
    // version and install is the same row.
    FakeOps ops;
    ops.set(L"64", kIv + L"\\x64\\sharedhost", L"Version", "9.0.22");
    ops.set(L"64", kIv + L"\\x64\\sharedhost", L"Path", kDotnetDir);
    ops.set(L"64", kIv + L"\\x64\\sharedfx\\Microsoft.NETCore.App", L"9.0.22", kDotnetDir);
    ops.set(L"32", kIv + L"\\x64", L"InstallLocation", kDotnetDir);
    ops.setd(L"32", kIv + L"\\x64\\sharedfx\\Microsoft.NETCore.App", L"8.0.33", 1);
    ops.setd(L"32", kIv + L"\\x64\\sharedfx\\Microsoft.NETCore.App", L"9.0.22", 1);
    ops.setd(L"32", kIv + L"\\x64\\sharedfx\\Microsoft.AspNetCore.App", L"9.0.22", 1);
    ops.set(L"32", kIv + L"\\x86", L"InstallLocation", "C:\\Program Files (x86)\\dotnet\\");
    ops.setd(L"32", kIv + L"\\x86\\sharedfx\\Microsoft.NETCore.App", L"9.0.22", 1);
    ConstraintAccumulator acc;
    // MUTATION: reading one view only drops the 32-bit view's frameworks; keying the dedupe on the
    // version alone merges the x86 install into the x64 one.
    CHECK(rwin::dotnet_rows(ops, acc) ==
          std::vector<std::string>{"dotnet|runtime|8.0.33|C:/Program Files/dotnet/|Microsoft",
                                   "dotnet|runtime|9.0.22|C:/Program Files (x86)/dotnet/|Microsoft",
                                   "dotnet|runtime|9.0.22|C:/Program Files/dotnet/|Microsoft"});
    CHECK_FALSE(acc.any_failure());
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: dotnet sdk values are sdk rows; text data beats InstallLocation; odd names read '-'",
          "[runtimes][dotnet][windows]") {
    FakeOps ops;
    ops.set(L"32", kIv + L"\\x64", L"InstallLocation", kDotnetDir);
    ops.setd(L"32", kIv + L"\\x64\\sdk", L"8.0.100", 1);
    ops.setd(L"32", kIv + L"\\x64\\sdk", L"9.0.100-preview.1.24101.2", 1);
    ops.set(L"32", kIv + L"\\x64\\sdk", L"", "default value is not a version");
    ops.setd(L"32", kIv + L"\\x64\\sharedfx\\Microsoft.NETCore.App", L"not-a-version", 1);
    ops.set(L"64", kIv + L"\\arm64\\sdk", L"10.0.100", "D:\\dotnet\\"); // no InstallLocation needed
    ConstraintAccumulator acc;
    CHECK(rwin::dotnet_rows(ops, acc) ==
          std::vector<std::string>{"dotnet|runtime|-|C:/Program Files/dotnet/|Microsoft",
                                   "dotnet|sdk|10.0.100|D:/dotnet/|Microsoft",
                                   "dotnet|sdk|8.0.100|C:/Program Files/dotnet/|Microsoft",
                                   "dotnet|sdk|9.0.100-preview.1.24101.2|C:/Program Files/dotnet/|Microsoft"});
    CHECK_FALSE(acc.any_failure());
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: dotnet with no path anywhere reports '-' for the path, not a guess",
          "[runtimes][dotnet][windows]") {
    FakeOps ops;
    ops.setd(L"64", kIv + L"\\x64\\sdk", L"8.0.100", 1); // no InstallLocation, DWORD data
    ConstraintAccumulator acc;
    CHECK(rwin::dotnet_rows(ops, acc) == std::vector<std::string>{"dotnet|sdk|8.0.100|-|Microsoft"});
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("runtimes win: .NET Framework rows map Release through the table; unknown reads '-'",
          "[runtimes][dotnet][windows]") {
    struct Case {
        DWORD release;
        const char* version;
    };
    for (const Case c : {Case{528040, "4.8"}, Case{394802, "4.6.2"}, Case{528049, "4.8"},
                         Case{1000, "-"}}) {
        INFO("Release " << c.release);
        FakeOps ops;
        ops.set(L"64", kNdp4, L"InstallPath", "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\");
        ops.setd(L"64", kNdp4, L"Release", c.release);
        ops.setd(L"64", kNdp4, L"Install", 1);
        ConstraintAccumulator acc;
        CHECK(rwin::dotnet_rows(ops, acc) ==
              std::vector<std::string>{std::string{"dotnet|netfx|"} + c.version +
                                       "|C:/Windows/Microsoft.NET/Framework64/v4.0.30319/|Microsoft"});
        CHECK_FALSE(acc.any_failure());
        CHECK(ops.opened == ops.closed);
    }
}

TEST_CASE("runtimes win: .NET Framework 4 in both views is two rows; v3.5 reads Version; leftovers are not installs",
          "[runtimes][dotnet][windows]") {
    FakeOps ops;
    ops.set(L"64", kNdp4, L"InstallPath", "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\");
    ops.setd(L"64", kNdp4, L"Release", 528040);
    ops.set(L"32", kNdp4, L"InstallPath", "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\");
    ops.setd(L"32", kNdp4, L"Release", 528040);
    ops.set(L"64", kNdp35, L"Version", "3.5.30729.4926");
    ops.set(L"64", kNdp35, L"InstallPath", "C:\\Windows\\Microsoft.NET\\Framework64\\v3.5\\");
    ops.setd(L"64", kNdp35, L"Install", 1);
    ops.set(L"32", kNdp35, L"Version", "3.5.30729.4926"); // Install = 0: the feature is off
    ops.setd(L"32", kNdp35, L"Install", 0);
    ConstraintAccumulator acc;
    CHECK(rwin::dotnet_rows(ops, acc) ==
          std::vector<std::string>{
              "dotnet|netfx|3.5.30729.4926|C:/Windows/Microsoft.NET/Framework64/v3.5/|Microsoft",
              "dotnet|netfx|4.8|C:/Windows/Microsoft.NET/Framework/v4.0.30319/|Microsoft",
              "dotnet|netfx|4.8|C:/Windows/Microsoft.NET/Framework64/v4.0.30319/|Microsoft"});
    CHECK_FALSE(acc.any_failure());
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: a denied dotnet root is access_denied and the other view is still read",
          "[runtimes][dotnet][windows]") {
    FakeOps ops;
    ops.mk(L"64", kIv).open_rc = ERROR_ACCESS_DENIED;
    ops.mk(L"64", kNdp4).open_rc = ERROR_ACCESS_DENIED;
    ops.setd(L"32", kIv + L"\\x64\\sdk", L"8.0.100", 1);
    ConstraintAccumulator acc;
    const auto rows = rwin::dotnet_rows(ops, acc);
    CHECK(acc.reason() == std::string{rwin::kDotnetTokens.access_denied});
    CHECK(rows == std::vector<std::string>{"dotnet|sdk|8.0.100|-|Microsoft"});
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: another failed dotnet open is open_failed, at the root or at an arch key",
          "[runtimes][dotnet][windows]") {
    FakeOps ops;
    ops.mk(L"64", kIv).open_rc = ERROR_BAD_PATHNAME;
    ops.setd(L"32", kIv + L"\\x64\\sdk", L"8.0.100", 1);
    ops.setd(L"32", kIv + L"\\x86\\sdk", L"9.0.100", 1);
    ops.mk(L"32", kIv + L"\\x86").open_rc = ERROR_BAD_PATHNAME;
    ConstraintAccumulator acc;
    CHECK(rwin::dotnet_rows(ops, acc) == std::vector<std::string>{"dotnet|sdk|8.0.100|-|Microsoft"});
    CHECK(acc.reason() == std::string{rwin::kDotnetTokens.open_failed});
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: dotnet enumeration errors record enum_failed and keep the rows read before",
          "[runtimes][dotnet][windows]") {
    {
        FakeOps ops; // the arch list fails after the first arch
        ops.setd(L"64", kIv + L"\\x64\\sdk", L"8.0.100", 1);
        ops.setd(L"64", kIv + L"\\x86\\sdk", L"9.0.100", 1);
        auto& versions = ops.mk(L"64", kIv);
        versions.enum_fail_at = 1;
        versions.enum_rc = ERROR_GEN_FAILURE;
        ConstraintAccumulator acc;
        CHECK(rwin::dotnet_rows(ops, acc) == std::vector<std::string>{"dotnet|sdk|8.0.100|-|Microsoft"});
        CHECK(acc.reason() == std::string{rwin::kDotnetTokens.enum_failed});
        CHECK(ops.opened == ops.closed);
    }
    {
        FakeOps ops; // the value list fails after the first value
        ops.setd(L"64", kIv + L"\\x64\\sdk", L"8.0.100", 1);
        ops.setd(L"64", kIv + L"\\x64\\sdk", L"9.0.100", 1);
        auto& sdk = ops.mk(L"64", kIv + L"\\x64\\sdk");
        sdk.venum_fail_at = 1;
        sdk.venum_rc = ERROR_GEN_FAILURE;
        ConstraintAccumulator acc;
        CHECK(rwin::dotnet_rows(ops, acc) == std::vector<std::string>{"dotnet|sdk|8.0.100|-|Microsoft"});
        CHECK(acc.reason() == std::string{rwin::kDotnetTokens.enum_failed});
        CHECK(ops.opened == ops.closed);
    }
}

TEST_CASE("runtimes win: an over-long dotnet value name is name_too_long and the rest is read",
          "[runtimes][dotnet][windows]") {
    FakeOps ops;
    ops.setd(L"64", kIv + L"\\x64\\sdk", std::wstring(300, L'9'), 1);
    ops.setd(L"64", kIv + L"\\x64\\sdk", L"8.0.100", 1);
    ConstraintAccumulator acc;
    CHECK(rwin::dotnet_rows(ops, acc) == std::vector<std::string>{"dotnet|sdk|8.0.100|-|Microsoft"});
    CHECK(acc.reason() == std::string{rwin::kDotnetTokens.name_too_long});
}

TEST_CASE("runtimes win: dotnet visits are capped across values and report row_cap",
          "[runtimes][dotnet][windows]") {
    // kMaxEntriesVisited + 1 distinct sdk values: the cap counts the arch key's own visit too, so one
    // fewer than the cap is read and the rest never is. MUTATION: dropping the counter lets a
    // stuffed key loop to its last value with no cap.
    FakeOps ops;
    for (std::size_t i = 0; i < rwin::kMaxEntriesVisited + 1; ++i)
        ops.setd(L"64", kIv + L"\\x64\\sdk", L"8.0." + std::to_wstring(i), 1);
    ConstraintAccumulator acc;
    const auto rows = rwin::dotnet_rows(ops, acc);
    CHECK(acc.reason() == std::string{rwin::kDotnetTokens.row_cap});
    CHECK(rows.size() == rwin::kMaxEntriesVisited - 1);
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: dotnet rows past the byte budget are refused with row_cap",
          "[runtimes][dotnet][windows]") {
    // 100 rows of ~20 KiB overrun the 1 MiB budget while staying under the visit cap.
    FakeOps ops;
    for (std::size_t i = 0; i < 100; ++i)
        ops.set(L"64", kIv + L"\\x64\\sdk", L"8.0." + std::to_wstring(i),
                "C:\\" + std::string(20000, 'p') + std::to_string(i));
    ConstraintAccumulator acc;
    const auto rows = rwin::dotnet_rows(ops, acc);
    CHECK(acc.reason() == std::string{rwin::kDotnetTokens.row_cap});
    const std::size_t total = std::accumulate(rows.begin(), rows.end(), std::size_t{0},
                                              [](std::size_t n, const std::string& r) { return n + r.size(); });
    CHECK(total <= rwin::kMaxRowBytes);
    CHECK_FALSE(rows.empty());
    CHECK(rows.size() < 100);
}

// -- jvm walk -------------------------------------------------------------------------------------

TEST_CASE("runtimes win: no JVM keys in either view is supported with zero rows",
          "[runtimes][jvm][windows]") {
    FakeOps ops;
    ConstraintAccumulator acc;
    CHECK(rwin::jvm_rows(ops, acc).empty());
    CHECK_FALSE(acc.any_failure());
    CHECK(ops.file_reads.empty());
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: three vendors read from their own keys; one bounded release read per home",
          "[runtimes][jvm][windows]") {
    // Microsoft's JDK is named by TWO JavaSoft version keys (21, 21.0.12.101) and still one home:
    // one row, one read. Its vendor is the release file's IMPLEMENTOR, never Oracle by key name.
    FakeOps ops;
    plant_three_vendors(ops);
    ConstraintAccumulator acc;
    const auto rows = rwin::jvm_rows(ops, acc);
    CHECK(rows == kThreeVendorRows);
    CHECK_FALSE(acc.any_failure());
    CHECK(ops.file_reads.size() == 3);
    CHECK(ops.last_cap == 64 * 1024);
    CHECK(std::none_of(rows.begin(), rows.end(),
                       [](const std::string& r) { return r.find("Oracle") != std::string::npos; }));
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: a home seen in both views, spelled differently, is one row; no release file is no token",
          "[runtimes][jvm][windows]") {
    FakeOps ops;
    plant_jvm(ops, L"64", L"SOFTWARE\\JavaSoft\\Java Runtime Environment", L"1.8", L"", L"JavaHome",
              "C:\\Program Files\\Java\\jre1.8.0_301");
    plant_jvm(ops, L"32", L"SOFTWARE\\JavaSoft\\JRE", L"1.8.0_301", L"", L"JavaHome",
              "c:\\program files\\java\\jre1.8.0_301\\");
    ConstraintAccumulator acc;
    // The greater tag stands in for the missing release's version; the file is absent, not unreadable.
    CHECK(rwin::jvm_rows(ops, acc) ==
          std::vector<std::string>{"jvm|unmodelled|1.8.0_301|C:/Program Files/Java/jre1.8.0_301|-"});
    CHECK_FALSE(acc.any_failure());
    CHECK(ops.file_reads.size() == 1);
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: a release that exists but cannot be read is a row and release_unreadable",
          "[runtimes][jvm][windows]") {
    // nullopt is what RealRegOps::read_file_bounded answers for a reparse point, a denied open or an
    // over-cap file; the fake also enforces the cap itself. MUTATION: reading unreadable as absent
    // (no token) or dropping the home turns this red.
    FakeOps ops;
    plant_three_vendors(ops);
    ops.files[kTemurinReleasePath] = std::nullopt;                  // e.g. a reparse point
    ops.files[kZuluReleasePath] = std::string(64 * 1024 + 1, 'x'); // over the cap
    ConstraintAccumulator acc;
    CHECK(rwin::jvm_rows(ops, acc) ==
          std::vector<std::string>{
              "jvm|unmodelled|21.0.12.1|C:/Program Files/Microsoft/jdk-21.0.12.101-hotspot/|Microsoft",
              "jvm|unmodelled|21.0.13.9|C:/Program Files/Temurin/|-",
              "jvm|unmodelled|zulu17|C:/Program Files/Zulu/zulu-17|-"});
    CHECK(acc.reason() == std::string{rwin::kTokJvmReleaseUnreadable});
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: a non-local home is never opened, and reads as an unreadable release",
          "[runtimes][jvm][windows]") {
    FakeOps ops;
    plant_jvm(ops, L"64", kJsJdk, L"21", L"", L"JavaHome", "\\\\server\\share\\jdk-21");
    ConstraintAccumulator acc;
    CHECK(rwin::jvm_rows(ops, acc) ==
          std::vector<std::string>{"jvm|unmodelled|21|//server/share/jdk-21|-"});
    CHECK(ops.file_reads.empty());
    CHECK(acc.reason() == std::string{rwin::kTokJvmReleaseUnreadable});
}

TEST_CASE("runtimes win: a version key without a home value is not an install",
          "[runtimes][jvm][windows]") {
    FakeOps ops;
    ops.mk(L"64", kJsJdk + L"\\21");
    ops.mk(L"64", kAdoptJdk + L"\\21.0.13.9"); // no hotspot\MSI subkey at all
    ConstraintAccumulator acc;
    CHECK(rwin::jvm_rows(ops, acc).empty());
    CHECK_FALSE(acc.any_failure());
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: a denied JVM root is access_denied and the other view is still read",
          "[runtimes][jvm][windows]") {
    FakeOps ops;
    plant_three_vendors(ops);
    ops.mk(L"64", kJsJdk).open_rc = ERROR_ACCESS_DENIED;
    ConstraintAccumulator acc;
    const auto rows = rwin::jvm_rows(ops, acc);
    CHECK(acc.reason() == std::string{rwin::kJvmTokens.access_denied});
    CHECK(rows.size() == 2); // Microsoft's home was only named under the denied key
    CHECK(ops.opened == ops.closed);
}

TEST_CASE("runtimes win: JVM open_failed, enum_failed and name_too_long are tokens and the walk goes on",
          "[runtimes][jvm][windows]") {
    {
        FakeOps ops;
        plant_three_vendors(ops);
        ops.mk(L"64", kAdoptJdk + L"\\21.0.13.9").open_rc = ERROR_BAD_PATHNAME;
        ConstraintAccumulator acc;
        CHECK(rwin::jvm_rows(ops, acc).size() == 2);
        CHECK(acc.reason() == std::string{rwin::kJvmTokens.open_failed});
        CHECK(ops.opened == ops.closed);
    }
    {
        FakeOps ops;
        plant_three_vendors(ops);
        auto& jdk = ops.mk(L"64", kJsJdk);
        jdk.enum_fail_at = 1; // 21 is read, 21.0.12.101 is not (same home anyway)
        jdk.enum_rc = ERROR_GEN_FAILURE;
        ConstraintAccumulator acc;
        CHECK(rwin::jvm_rows(ops, acc) == kThreeVendorRows);
        CHECK(acc.reason() == std::string{rwin::kJvmTokens.enum_failed});
        CHECK(ops.opened == ops.closed);
    }
    {
        FakeOps ops;
        plant_three_vendors(ops);
        ops.mk(L"64", kJsJdk).children.push_back(std::wstring(300, L'x'));
        ConstraintAccumulator acc;
        CHECK(rwin::jvm_rows(ops, acc) == kThreeVendorRows);
        CHECK(acc.reason() == std::string{rwin::kJvmTokens.name_too_long});
    }
}

TEST_CASE("runtimes win: JVM visits are capped and report row_cap, keeping the homes already read",
          "[runtimes][jvm][windows]") {
    FakeOps ops;
    for (std::size_t i = 0; i < rwin::kMaxEntriesVisited + 1; ++i)
        plant_jvm(ops, L"64", kJsJdk, L"21." + std::to_wstring(i), L"", L"JavaHome",
                  "C:\\Java\\jdk" + std::to_string(i));
    ConstraintAccumulator acc;
    const auto rows = rwin::jvm_rows(ops, acc);
    CHECK(acc.reason() == std::string{rwin::kJvmTokens.row_cap});
    CHECK(rows.size() == rwin::kMaxEntriesVisited);
    CHECK(ops.file_reads.size() == rwin::kMaxEntriesVisited);
    CHECK(ops.opened == ops.closed);
}

// -- CommandContext-level harness ---------------------------------------------------------
// Drives the PRODUCTION leg body (win::run_windows_with) through a real CommandContext via
// LocalDispatcher (the test_runtimes_linux_parsers.cpp precedent), over the scripted FakeOps, so
// what is asserted is the rows the command emits AND the typed result status it reports.
namespace {

struct LegRun {
    int rc = -1;
    std::vector<std::string> rows;
    YuzuResultStatus status = YUZU_RESULT_STATUS_UNDECLARED;
    YuzuResultCompleteness completeness = YUZU_RESULT_COMPLETENESS_UNKNOWN;
    std::string provenance;
};

const FakeOps* g_leg_ops = nullptr;

int leg_execute(YuzuCommandContext* raw, const char* action, const YuzuParam* /*params*/,
                std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    const auto a = yuzu::runtimes::parse_action(action);
    if (!a) return 1;
    return rwin::run_windows_with(ctx, *a, *g_leg_ops);
}

LegRun run_leg(yuzu::runtimes::Action action, const FakeOps& ops) {
    g_leg_ops = &ops;
    yuzu::test::ScopeExit reset{[] { g_leg_ops = nullptr; }}; // even if the run throws
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &leg_execute;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(&descriptor, yuzu::runtimes::action_name(action));

    LegRun out;
    out.rc = result.rc;
    out.status = result.result_status;
    out.completeness = result.result_completeness;
    out.provenance = result.result_provenance;
    std::istringstream lines(result.captured);
    for (std::string line; std::getline(lines, line);)
        if (!line.empty()) out.rows.push_back(line);
    return out;
}

} // namespace

TEST_CASE("runtimes win: run_windows_with emits the status row first and reports OK/FULL for a clean read",
          "[runtimes][python][windows]") {
    // MUTATION: reporting CONSTRAINED regardless, dropping the status row, or discarding the rows
    // before emit_read turns this red.
    FakeOps ops;
    ops.add_tag(L"64", L"3.14", "3.14.6", "3.14", "C:\\Python314\\");
    const auto run = run_leg(yuzu::runtimes::Action::python, ops);
    CHECK(run.rc == 0);
    CHECK(run.rows == std::vector<std::string>{"status|python|supported|-",
                                               "python|cpython|3.14.6|C:/Python314/|PythonCore"});
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(run.provenance.empty());
}

TEST_CASE("runtimes win: a denied view is a constrained status row and CONSTRAINED/PARTIAL through the dispatch",
          "[runtimes][python][windows]") {
    // MUTATION: reporting OK/FULL regardless of the accumulator, or emitting no status row, turns
    // this red. The other view is still read, so its row follows the constrained status row.
    FakeOps ops;
    ops.node(L"64", kCore).open_rc = ERROR_ACCESS_DENIED;
    ops.add_tag(L"32", L"3.12", "3.12.4", "3.12", "C:\\Python312\\");
    const auto run = run_leg(yuzu::runtimes::Action::python, ops);
    CHECK(run.rc == 0);
    CHECK(run.rows ==
          std::vector<std::string>{"status|python|constrained|windows:runtimes:python_reg:access_denied",
                                   "python|cpython|3.12.4|C:/Python312/|PythonCore"});
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(run.provenance == std::string{rwin::kTokAccessDenied});
}

TEST_CASE("runtimes win: RealRegOps reads a planted PythonCore tag from an isolated scratch key",
          "[runtimes][python][windows]") {
    // The real Reg*W decode path, once: a process-suffixed key under HKCU stands in for HKLM
    // (python_rows takes the root as a parameter; production never opens HKCU). HKCU\Software is not
    // WOW-redirected, so both views see the same key and the dedupe leaves one row per install path.
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
        // An InstallPath over kMaxValueBytes (40000 WCHARs = ~80 KB > 64 KiB) reads as absent: the
        // row keeps its version, reports the path as unknown and raises no token.
        const auto big_tag = create(core + L"\\3.98");
        set_sz(big_tag.get(), L"Version", L"3.98.1");
        const auto big_ip = create(core + L"\\3.98\\InstallPath");
        set_sz(big_ip.get(), nullptr, std::wstring(40000, L'p').c_str());
    }
    ConstraintAccumulator acc;
    const auto rows =
        rwin::python_rows(rwin::RealRegOps{}, acc, HKEY_CURRENT_USER, core.c_str());
    CHECK_FALSE(acc.any_failure());
    CHECK(acc.reason().empty());
    // Sorted by version: 3.98 first. A path-less record is never merged, and this scratch key is
    // visible through both registry views, so the path-less 3.98 row appears once per view.
    CHECK(rows == std::vector<std::string>{"python|cpython|3.98.1|-|PythonCore",
                                           "python|cpython|3.98.1|-|PythonCore",
                                           "python|cpython|3.99.1|C:/YuzuTestPython399/|PythonCore"});
}

TEST_CASE("runtimes win: run_windows_with(dotnet) emits the status row first and OK/FULL for a clean read",
          "[runtimes][dotnet][windows]") {
    FakeOps ops;
    ops.set(L"32", kIv + L"\\x64", L"InstallLocation", kDotnetDir);
    ops.setd(L"32", kIv + L"\\x64\\sharedfx\\Microsoft.NETCore.App", L"9.0.22", 1);
    const auto run = run_leg(yuzu::runtimes::Action::dotnet, ops);
    CHECK(run.rc == 0);
    CHECK(run.rows == std::vector<std::string>{"status|dotnet|supported|-",
                                               "dotnet|runtime|9.0.22|C:/Program Files/dotnet/|Microsoft"});
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(run.provenance.empty());
}

TEST_CASE("runtimes win: run_windows_with(dotnet) with nothing installed is supported with only the status row",
          "[runtimes][dotnet][windows]") {
    FakeOps ops;
    const auto run = run_leg(yuzu::runtimes::Action::dotnet, ops);
    CHECK(run.rows == std::vector<std::string>{"status|dotnet|supported|-"});
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_FULL);
}

TEST_CASE("runtimes win: run_windows_with(dotnet) with a denied view is CONSTRAINED/PARTIAL",
          "[runtimes][dotnet][windows]") {
    FakeOps ops;
    ops.mk(L"64", kIv).open_rc = ERROR_ACCESS_DENIED;
    ops.setd(L"32", kIv + L"\\x64\\sdk", L"8.0.100", 1);
    const auto run = run_leg(yuzu::runtimes::Action::dotnet, ops);
    CHECK(run.rows ==
          std::vector<std::string>{"status|dotnet|constrained|windows:runtimes:dotnet_reg:access_denied",
                                   "dotnet|sdk|8.0.100|-|Microsoft"});
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(run.provenance == std::string{rwin::kDotnetTokens.access_denied});
}

TEST_CASE("runtimes win: run_windows_with(jvm) emits the three vendors' rows after an OK/FULL status row",
          "[runtimes][jvm][windows]") {
    FakeOps ops;
    plant_three_vendors(ops);
    const auto run = run_leg(yuzu::runtimes::Action::jvm, ops);
    std::vector<std::string> expected{"status|jvm|supported|-"};
    expected.insert(expected.end(), kThreeVendorRows.begin(), kThreeVendorRows.end());
    CHECK(run.rc == 0);
    CHECK(run.rows == expected);
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_FULL);
}

TEST_CASE("runtimes win: run_windows_with(jvm) with an unreadable release is CONSTRAINED/PARTIAL and keeps the home",
          "[runtimes][jvm][windows]") {
    FakeOps ops;
    plant_jvm(ops, L"64", kAdoptJdk, L"21.0.13.9", L"hotspot\\MSI", L"Path", kTemurinHome);
    ops.files[kTemurinReleasePath] = std::nullopt;
    const auto run = run_leg(yuzu::runtimes::Action::jvm, ops);
    CHECK(run.rows ==
          std::vector<std::string>{"status|jvm|constrained|windows:runtimes:jvm:release_unreadable",
                                   "jvm|unmodelled|21.0.13.9|C:/Program Files/Temurin/|-"});
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(run.provenance == std::string{rwin::kTokJvmReleaseUnreadable});
}

TEST_CASE("runtimes win: RealRegOps reads planted dotnet values and a Release DWORD from isolated scratch keys",
          "[runtimes][dotnet][windows]") {
    // The real Reg*W decode path, once: HKCU\SOFTWARE is not WOW-redirected, so both views see the same
    // key and the dedupe leaves one row per install. A DWORD value (no text) takes the arch key's
    // InstallLocation; a string value's data wins.
    const std::wstring sub =
        L"SOFTWARE\\YuzuTest\\RuntimesDotnet_" + std::to_wstring(GetCurrentProcessId());
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
    const auto set_dword = [](HKEY k, const wchar_t* name, DWORD v) {
        REQUIRE(RegSetValueExW(k, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v),
                               sizeof(v)) == ERROR_SUCCESS);
    };
    const std::wstring versions = sub + L"\\InstalledVersions";
    const std::wstring v4 = sub + L"\\NDP\\v4\\Full";
    const std::wstring v35 = sub + L"\\NDP\\v3.5"; // never created: absent is silent
    {
        const auto arch = create(versions + L"\\x64");
        set_sz(arch.get(), L"InstallLocation", L"C:\\YuzuTestDotnet\\");
        const auto fx = create(versions + L"\\x64\\sharedfx\\Microsoft.NETCore.App");
        set_dword(fx.get(), L"8.0.99", 1);
        set_sz(fx.get(), L"9.0.99", L"C:\\YuzuTestDotnetOverride\\");
        const auto sdk = create(versions + L"\\x64\\sdk");
        set_dword(sdk.get(), L"9.0.100", 1);
        const auto full = create(v4);
        set_dword(full.get(), L"Release", 528040);
        set_dword(full.get(), L"Install", 1);
        set_sz(full.get(), L"InstallPath", L"C:\\YuzuTestNetfx\\");
    }
    rwin::DotnetKeys keys;
    keys.installed_versions = versions.c_str();
    keys.ndp_v4_full = v4.c_str();
    keys.ndp_v35 = v35.c_str();
    ConstraintAccumulator acc;
    const auto rows = rwin::dotnet_rows(rwin::RealRegOps{}, acc, HKEY_CURRENT_USER, keys);
    CHECK_FALSE(acc.any_failure());
    CHECK(rows == std::vector<std::string>{"dotnet|netfx|4.8|C:/YuzuTestNetfx/|Microsoft",
                                           "dotnet|runtime|8.0.99|C:/YuzuTestDotnet/|Microsoft",
                                           "dotnet|runtime|9.0.99|C:/YuzuTestDotnetOverride/|Microsoft",
                                           "dotnet|sdk|9.0.100|C:/YuzuTestDotnet/|Microsoft"});
}

TEST_CASE("runtimes win: RealRegOps::read_file_bounded reads a plain file and refuses what it must not open",
          "[runtimes][jvm][windows]") {
    // The real CreateFileW path, once. engaged-and-empty = no such file; nullopt = not read.
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() /
                         ("yuzu_test_runtimes_release_" + std::to_string(GetCurrentProcessId()));
    std::error_code ec;
    fs::create_directories(dir, ec);
    struct Cleanup {
        const fs::path& dir;
        ~Cleanup() { std::error_code e; fs::remove_all(dir, e); }
    } cleanup{dir};
    const fs::path file = dir / "release";
    const std::string body = "JAVA_VERSION=\"21.0.1\"\n";
    { std::ofstream(file, std::ios::binary) << body; }

    const rwin::RealRegOps ops;
    constexpr std::size_t kCap = 64 * 1024;
    CHECK(ops.read_file_bounded(file.wstring(), kCap) == std::optional<std::string>{body});
    CHECK(ops.read_file_bounded((dir / "absent").wstring(), kCap) == std::optional<std::string>{std::string{}});
    CHECK_FALSE(ops.read_file_bounded(file.wstring(), body.size() - 1).has_value()); // over the cap
    CHECK(ops.read_file_bounded(file.wstring(), body.size()).has_value());           // exact fit
    CHECK_FALSE(ops.read_file_bounded(dir.wstring(), kCap).has_value());             // a directory
    CHECK_FALSE(ops.read_file_bounded(L"\\\\localhost\\c$\\release", kCap).has_value()); // not a drive path
    CHECK_FALSE(ops.read_file_bounded(L"release", kCap).has_value());                   // relative
    // A symlink is opened as itself and refused. Creating one needs a privilege / Developer Mode, so
    // this part runs only where the host allows it.
    const fs::path link = dir / "link";
    std::error_code link_ec;
    fs::create_symlink(file, link, link_ec);
    if (!link_ec) {
        CHECK_FALSE(ops.read_file_bounded(link.wstring(), kCap).has_value());
    } else {
        WARN("symlink creation not permitted here: reparse-point refusal not exercised live");
    }
}

#endif // _WIN32
