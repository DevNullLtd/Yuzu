/**
 * test_registry_win_internals.cpp -- TU-inclusion seam over registry_win.cpp: its production
 * Win32Registry (the RegistryWriter binding the pure core drives) called directly, because what is pinned
 * here cannot be staged through LocalDispatcher:
 *  - create_sub passes REG_OPTION_OPEN_LINK, so a registry link that appears between open_checked's walk and
 *    its create is opened AS the link (REG_OPENED_EXISTING_KEY, which the core refuses as concurrent_change),
 *    not followed. A link planted BEFORE the plugin runs is already refused by the walk's own link probe
 *    (key_is_link), so test_registry_write_local_dispatcher.cpp never reaches the create step with a link in
 *    place; calling create_sub on a dangling link here is that swap, deterministically.
 *  - the fast open's two kernel calls, final_name (NtQueryKey) and root_name.
 *  - execute_guarded, the ABI seam: an action that throws (the test-only `__throw_*` actions this TU's guard
 *    macro adds to dispatch) comes out as rc 1 and one `error|exception` line, never as an exception.
 * The pure logic is locked on every host by test_registry_core.cpp; the dispatcher cases prove the plugin end
 * to end.
 *
 * TU-inclusion precedent: test_privacy_permissions_win_internals.cpp (the same
 * `..._UNIT_TEST_INTERNALS_ONLY` guard, which drops the one plugin-facing function so the file can be
 * included). `#if defined(_WIN32)` guards the WHOLE body -- empty TU elsewhere. Needs an elevated token
 * (a salted HKLM scratch key); like the dispatcher cases it WARN-skips otherwise, and
 * YUZU_REQUIRE_WINDOWS_REGISTRY_TESTS=1 (the kingsley evidence jobs) turns that skip into a FAIL.
 */
#if !defined(_WIN32)

// Nothing to test off Windows -- see the file banner above.

#else // defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <catch2/catch_test_macros.hpp>

#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include <cstdlib>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// The leg's anonymous-namespace helpers have no header seam; the guard macro drops the plugin-facing
// execute_windows so this TU can include the file. Never defined by the real build. Excluding that
// function leaves helpers with no caller in THIS compilation: MSVC's C4505 (unused static function) is
// silenced narrowly around the include.
#define YUZU_REGISTRY_WIN_UNIT_TEST_INTERNALS_ONLY 1
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4505)
#endif
#include "../../agents/plugins/registry/src/registry_win.cpp"
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
#undef YUZU_REGISTRY_WIN_UNIT_TEST_INTERNALS_ONLY

namespace {

using yuzu::registry::as_handle;
using yuzu::registry::as_hkey;
using yuzu::registry::Handle;
using yuzu::registry::Owned;
using yuzu::registry::Win32Registry;

/// Same semantics as skip_or_fail() in test_registry_write_local_dispatcher.cpp (kept local: a shared
/// header for one four-line helper is more surface than it saves).
void skip_or_fail(const std::string& why) {
    const char* req = std::getenv("YUZU_REQUIRE_WINDOWS_REGISTRY_TESTS");
    if (req != nullptr && req[0] != '\0' && std::string_view{req} != "0")
        FAIL(why + " (YUZU_REQUIRE_WINDOWS_REGISTRY_TESTS is set)");
    WARN(why + " -- skipping");
}

std::wstring widen(const std::string& s) { return std::wstring(s.begin(), s.end()); } // ASCII only

// ── fake CommandContext harness ──────────────────────────────────────────
//
// The test_execution_artifacts_win_internals.cpp shape: an injected body runs against a REAL
// yuzu::CommandContext, so ctx.write_output reaches the same capture LocalDispatcher uses for the real plugin.
std::function<int(yuzu::CommandContext&)> g_body;

int fake_seam_execute(YuzuCommandContext* raw_ctx, const char* /*action*/, const YuzuParam* /*params*/,
                      std::size_t /*param_count*/) {
    yuzu::CommandContext ctx(raw_ctx);
    return g_body(ctx);
}

const char* const kFakeActions[] = {"seam", nullptr};

const YuzuPluginDescriptor kFakeDescriptor = {
    /*abi_version=*/YUZU_PLUGIN_ABI_VERSION,
    /*name=*/"registry_seam",
    /*version=*/"1.0.0",
    /*description=*/"test-only registry internals fixture",
    /*actions=*/kFakeActions,
    /*init=*/nullptr,
    /*shutdown=*/nullptr,
    /*execute=*/fake_seam_execute,
    /*sdk_version=*/nullptr,
};

/// Runs execute_guarded(`action`) with no params inside the fake context; the non-empty output lines.
struct Guarded {
    int rc = 0;
    std::vector<std::string> lines;
};

Guarded run_guarded(std::string_view action) {
    g_body = [action](yuzu::CommandContext& ctx) -> int {
        return yuzu::registry::execute_guarded(ctx, action, yuzu::Params{std::span<const YuzuParam>{}});
    };
    const auto result = yuzu::agent::LocalDispatcher{}.run(&kFakeDescriptor, "seam");
    g_body = nullptr;
    Guarded out;
    out.rc = result.rc;
    std::string line;
    for (const char c : result.captured) {
        if (c == '\n' || c == '\r') {
            if (!line.empty()) out.lines.push_back(std::move(line));
            line.clear();
        } else {
            line += c;
        }
    }
    if (!line.empty()) out.lines.push_back(std::move(line));
    return out;
}

/// Creates a registry link key `link_path` under HKLM whose SymbolicLinkValue (a REG_LINK: the target path
/// WITHOUT a terminating NUL) names HKLM\<target_path>, which need not exist. False when it cannot be made.
bool make_machine_link(const std::string& link_path, const std::string& target_path) {
    yuzu::win::RegKey link;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, widen(link_path).c_str(), 0, nullptr, REG_OPTION_CREATE_LINK,
                        KEY_SET_VALUE | KEY_CREATE_LINK, nullptr, link.put(), nullptr) != ERROR_SUCCESS)
        return false;
    const std::wstring target = L"\\Registry\\Machine\\" + widen(target_path);
    return RegSetValueExW(link.get(), L"SymbolicLinkValue", 0, REG_LINK,
                          reinterpret_cast<const BYTE*>(target.data()),
                          static_cast<DWORD>(target.size() * sizeof(wchar_t))) == ERROR_SUCCESS;
}

bool key_exists(const std::string& key) {
    yuzu::win::RegKey k;
    return RegOpenKeyExW(HKEY_LOCAL_MACHINE, widen(key).c_str(), 0, KEY_READ, k.put()) == ERROR_SUCCESS;
}

/// Removes the salted scratch subtree on scope exit. Declared BEFORE the link guard below, so the link
/// object is gone (by handle) before RegDeleteTreeW walks the parent.
struct ScratchTree {
    std::string path;
    explicit ScratchTree(std::string p) : path(std::move(p)) {}
    ~ScratchTree() { RegDeleteTreeW(HKEY_LOCAL_MACHINE, widen(path).c_str()); }
    ScratchTree(const ScratchTree&) = delete;
    ScratchTree& operator=(const ScratchTree&) = delete;
};

/// Deletes the link object at `parent\Link` by handle on scope exit (a link-opening open + NtDeleteKey),
/// so a failed REQUIRE, or a build without the flag where create_sub followed the link, still leaves no
/// link behind for RegDeleteTreeW to trip over. Never throws.
struct LinkSweep {
    Win32Registry& reg;
    Handle parent;
    ~LinkSweep() {
        Handle h = 0;
        if (reg.open_sub(parent, "Link", DELETE, h) == ERROR_SUCCESS) {
            reg.delete_key_by_handle(h);
            reg.close(h);
        }
    }
    LinkSweep(Win32Registry& r, Handle p) : reg(r), parent(p) {}
    LinkSweep(const LinkSweep&) = delete;
    LinkSweep& operator=(const LinkSweep&) = delete;
};

} // namespace

// A link whose TARGET is absent is the shape that matters for a create: a create that follows it makes the
// target and reports REG_CREATED_NEW_KEY (kingsley probe, MSVC 14.44, 2026-10-18), which the core cannot tell
// from a fresh key. With REG_OPTION_OPEN_LINK the call opens the link itself: OPENED_EXISTING, nothing
// created. Mutation: drop `| REG_OPTION_OPEN_LINK` from Win32Registry::create_sub and this case goes red
// (created_new becomes true, the handle is the Target, and the Target key exists afterwards).
TEST_CASE("Win32Registry::create_sub opens a dangling registry link as the link and creates nothing through it",
          "[registry][windows][internals]") {
    const std::string root =
        "SOFTWARE\\YuzuTest-" + std::to_string(yuzu::test::process_random_salt()) + "-internals";
    ScratchTree cleanup{root};

    // The scratch parent, opened with the right the create needs. HKLM\SOFTWARE is writable only elevated.
    yuzu::win::RegKey parent;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, widen(root).c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_READ | KEY_CREATE_SUB_KEY, nullptr, parent.put(), nullptr) != ERROR_SUCCESS) {
        skip_or_fail("not elevated -- HKLM scratch not writable, create_sub link case");
        return;
    }
    if (!make_machine_link(root + "\\Link", root + "\\Target")) { // Target is never created by this case
        skip_or_fail("could not create a registry link here");
        return;
    }

    Win32Registry reg;
    const Handle parent_handle = as_handle(parent.get());
    LinkSweep sweep{reg, parent_handle};

    // Exactly the create open_checked issues for a missing component, with DELETE added so the link
    // object can be removed by handle below (the access mask does not change how a link is treated).
    Handle out = 0;
    bool created_new = true;
    const long rc = reg.create_sub(parent_handle, "Link", KEY_READ | KEY_SET_VALUE | DELETE, out, created_new);
    REQUIRE(rc == ERROR_SUCCESS);
    REQUIRE(out != 0);

    CHECK_FALSE(created_new); // OPENED_EXISTING: the core turns this into concurrent_change

    // The handle IS the link: it carries the SymbolicLinkValue a followed target would not.
    DWORD type = 0;
    DWORD size = 0;
    CHECK(RegQueryValueExW(as_hkey(out), L"SymbolicLinkValue", nullptr, &type, nullptr, &size) == ERROR_SUCCESS);
    CHECK(type == REG_LINK);

    CHECK_FALSE(key_exists(root + "\\Target")); // nothing was created through the link

    // The link object goes by handle (the NtDeleteKey arm), not its target.
    CHECK(reg.delete_key_by_handle(out) == ERROR_SUCCESS);
    reg.close(out);
}

// The fast open's two kernel calls. Win32 semantics relied on: a handle opened with REG_OPTION_OPEN_LINK on a link
// IS the link object, so its canonical name is the link's own path; an INTERMEDIATE link is followed, so the
// canonical name of what a path through it opens is the target's.
TEST_CASE("Win32Registry::final_name names the object a handle is bound to and the probe reports a link leaf",
          "[registry][windows][internals]") {
    const std::string root = "SOFTWARE\\YuzuTest-" + std::to_string(yuzu::test::process_random_salt()) + "-names";
    ScratchTree cleanup{root};
    yuzu::win::RegKey sub;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, widen(root + "\\Target\\Sub").c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_READ, nullptr, sub.put(), nullptr) != ERROR_SUCCESS) {
        skip_or_fail("not elevated -- HKLM scratch not writable, final_name case");
        return;
    }
    yuzu::win::RegKey parent;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, widen(root).c_str(), 0, KEY_READ, parent.put()) != ERROR_SUCCESS) {
        skip_or_fail("could not open the scratch parent");
        return;
    }
    if (!make_machine_link(root + "\\Link", root + "\\Target")) {
        skip_or_fail("could not create a registry link here");
        return;
    }
    Win32Registry reg;
    const Handle hklm = as_handle(HKEY_LOCAL_MACHINE);
    LinkSweep sweep{reg, as_handle(parent.get())};
    const std::string machine = "\\REGISTRY\\MACHINE\\" + root;

    SECTION("a plain key is named by its own path, in the stored case") {
        Handle h = 0;
        REQUIRE(reg.open_path(hklm, root + "\\Target\\Sub", KEY_QUERY_VALUE, h) == ERROR_SUCCESS);
        const Owned guard{reg, h};
        std::string name;
        REQUIRE(reg.final_name(h, name) == ERROR_SUCCESS);
        CHECK(yuzu::registry::names_equal_ascii_ci(name, machine + "\\Target\\Sub"));
        CHECK(yuzu::registry::probe_link(reg, h).empty());
    }
    SECTION("a link at the leaf, opened with OPEN_LINK, is named by the link's own path and probes as a link") {
        Handle h = 0;
        REQUIRE(reg.open_path(hklm, root + "\\Link", KEY_QUERY_VALUE, h) == ERROR_SUCCESS);
        const Owned guard{reg, h};
        std::string name;
        REQUIRE(reg.final_name(h, name) == ERROR_SUCCESS);
        CHECK(yuzu::registry::names_equal_ascii_ci(name, machine + "\\Link"));
        CHECK(yuzu::registry::probe_link(reg, h) == "key_is_link");
    }
    SECTION("a path THROUGH a link is named by the target's path, never the requested one") {
        Handle h = 0;
        REQUIRE(reg.open_path(hklm, root + "\\Link\\Sub", KEY_QUERY_VALUE, h) == ERROR_SUCCESS);
        const Owned guard{reg, h};
        std::string name;
        REQUIRE(reg.final_name(h, name) == ERROR_SUCCESS);
        CHECK(yuzu::registry::names_equal_ascii_ci(name, machine + "\\Target\\Sub"));
        CHECK_FALSE(yuzu::registry::names_equal_ascii_ci(name, machine + "\\Link\\Sub"));
    }
}

TEST_CASE("Win32Registry::root_name is the kernel name of HKLM and HKU and is refused for HKCU and HKCR",
          "[registry][windows][internals]") {
    Win32Registry reg;
    std::string name;
    REQUIRE(reg.root_name(as_handle(HKEY_LOCAL_MACHINE), name) == ERROR_SUCCESS);
    CHECK(yuzu::registry::names_equal_ascii_ci(name, "\\REGISTRY\\MACHINE"));
    REQUIRE(reg.root_name(as_handle(HKEY_USERS), name) == ERROR_SUCCESS);
    CHECK(yuzu::registry::names_equal_ascii_ci(name, "\\REGISTRY\\USER"));
    CHECK(reg.root_name(as_handle(HKEY_CURRENT_USER), name) == ERROR_NOT_SUPPORTED);
    CHECK(reg.root_name(as_handle(HKEY_CLASSES_ROOT), name) == ERROR_NOT_SUPPORTED);
}

// The frozen-seam rule: nothing a registry action throws crosses the plugin boundary. dispatch throws a
// std::exception for `__throw_std` and a non-std value for `__throw_other` in this TU only (the guard macro).
// Mutation: delete the catch(...) from execute_guarded and the two throwing sections go red (the exception
// escapes the call). Needs no registry access, so it never skips.
TEST_CASE("execute_guarded turns a throwing action into rc 1 and one error|exception line",
          "[registry][windows][internals]") {
    SECTION("a std::exception") {
        const auto r = run_guarded("__throw_std");
        CHECK(r.rc == 1);
        REQUIRE(r.lines.size() == 1);
        CHECK(r.lines[0] == "error|exception");
    }
    SECTION("a value that is not a std::exception") {
        const auto r = run_guarded("__throw_other");
        CHECK(r.rc == 1);
        REQUIRE(r.lines.size() == 1);
        CHECK(r.lines[0] == "error|exception");
    }
    SECTION("an ordinary refusal passes through the guard unchanged") {
        const auto r = run_guarded("no_such_action");
        CHECK(r.rc == 1);
        REQUIRE(r.lines.size() == 1);
        CHECK(r.lines[0] == "error|unknown action: no_such_action");
    }
}

#endif // defined(_WIN32)
