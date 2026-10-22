/**
 * test_registry_win_internals.cpp -- TU-inclusion seam over registry_win.cpp: its production
 * Win32Registry (the RegistryWriter binding the pure core drives) called directly, because what is pinned
 * here cannot be staged through LocalDispatcher:
 *  - create_sub passes REG_OPTION_OPEN_LINK, so a registry link that appears between open_checked's walk and
 *    its create is opened AS the link (REG_OPENED_EXISTING_KEY, which the core refuses as concurrent_change),
 *    not followed. A link planted BEFORE the plugin runs is already refused by the walk's own link probe
 *    (key_is_link), so test_registry_write_local_dispatcher.cpp never reaches the create step with a link in
 *    place; calling create_sub on a dangling link here is that swap, deterministically.
 *  - the fast open's two kernel calls, final_name (NtQueryKey) and root_name, and its verdicts against the
 *    reference walk on the REAL registry.
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

#include "test_helpers.hpp"

#include <cstdlib>
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
using yuzu::registry::Opened;
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

/// Deletes the link objects `parent\<name>` by handle on scope exit, so the RegDeleteTreeW that follows never
/// meets a link (it follows one found inside a tree). Never throws.
struct LinkSweepAll {
    Win32Registry& reg;
    Handle parent;
    std::vector<std::string> names;
    ~LinkSweepAll() {
        for (const auto& n : names) {
            Handle h = 0;
            if (reg.open_sub(parent, n, DELETE, h) == ERROR_SUCCESS) {
                reg.delete_key_by_handle(h);
                reg.close(h);
            }
        }
    }
    LinkSweepAll(Win32Registry& r, Handle p, std::vector<std::string> n) : reg(r), parent(p), names(std::move(n)) {}
    LinkSweepAll(const LinkSweepAll&) = delete;
    LinkSweepAll& operator=(const LinkSweepAll&) = delete;
};

bool make_machine_key(const std::string& path) {
    yuzu::win::RegKey k;
    return RegCreateKeyExW(HKEY_LOCAL_MACHINE, widen(path).c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                           KEY_SET_VALUE, nullptr, k.put(), nullptr) == ERROR_SUCCESS;
}

/// A plain (non-link) key `path` carrying a REG_SZ value named SymbolicLinkValue: the probe cannot tell it from a link.
bool make_decoy_key(const std::string& path) {
    yuzu::win::RegKey k;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, widen(path).c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                        nullptr, k.put(), nullptr) != ERROR_SUCCESS)
        return false;
    const std::wstring v = L"not a link";
    return RegSetValueExW(k.get(), L"SymbolicLinkValue", 0, REG_SZ, reinterpret_cast<const BYTE*>(v.c_str()),
                          static_cast<DWORD>((v.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
}

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
    if (!make_machine_key(root + "\\Target\\Sub")) {
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
    LinkSweepAll sweep{reg, as_handle(parent.get()), {"Link"}};
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

// The fast open against the reference walk on the REAL registry, one shape at a time. The fast open may only
// ACCEPT: where it accepts it must hold the same object the walk holds, and where the walk refuses it may accept
// only for the one divergence this fixture stages (a decoy SymbolicLinkValue value on a plain ANCESTOR); the
// other, a traverse-only ACL ancestor, needs a second principal and is recorded by the kingsley evidence run.
TEST_CASE("the fast open and the reference walk agree on a scratch tree of the real registry",
          "[registry][windows][internals]") {
    const std::string root = "SOFTWARE\\YuzuTest-" + std::to_string(yuzu::test::process_random_salt()) + "-parity";
    ScratchTree cleanup{root};
    if (!make_machine_key(root + "\\Real\\a\\b\\c") || !make_machine_key(root + "\\Real\\a\\other") ||
        !make_decoy_key(root + "\\Decoy") || !make_machine_key(root + "\\Decoy\\sub")) {
        skip_or_fail("not elevated -- HKLM scratch not writable, parity case");
        return;
    }
    yuzu::win::RegKey parent;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, widen(root).c_str(), 0, KEY_READ, parent.put()) != ERROR_SUCCESS) {
        skip_or_fail("could not open the scratch parent");
        return;
    }
    // Lnk -> Real, LeafLnk -> Real\a, Chain2 -> Lnk (a two-link chain), Dangling -> (nothing), Self -> Self.
    const bool links = make_machine_link(root + "\\Lnk", root + "\\Real") &&
                       make_machine_link(root + "\\LeafLnk", root + "\\Real\\a") &&
                       make_machine_link(root + "\\Chain2", root + "\\Lnk") &&
                       make_machine_link(root + "\\Dangling", root + "\\Nowhere") &&
                       make_machine_link(root + "\\Self", root + "\\Self");
    Win32Registry reg;
    LinkSweepAll sweep{reg, as_handle(parent.get()), {"Lnk", "LeafLnk", "Chain2", "Dangling", "Self"}};
    if (!links) {
        skip_or_fail("could not create the registry links here");
        return;
    }
    const Handle hklm = as_handle(HKEY_LOCAL_MACHINE);

    struct Row {
        const char* what;
        std::string rel;
        bool leaf_may_be_link;
        bool fast_accepts;
        std::string walk_error; // "" = the walk accepts too
    };
    const std::vector<Row> rows{
        {"a plain key", "Real\\a\\b\\c", false, true, ""},
        {"the same key in another case", "real\\A\\B\\C", false, true, ""},
        {"a path through a link", "Lnk\\a\\b\\c", false, false, "key_is_link"},
        {"a path through a two-link chain", "Chain2\\a\\b", false, false, "key_is_link"},
        {"a link at the leaf", "LeafLnk", false, false, "key_is_link"},
        {"a link at the leaf for delete_key", "LeafLnk", true, true, ""},
        {"a dangling link at the leaf", "Dangling", false, false, "key_is_link"},
        {"a path through a dangling link", "Dangling\\x", false, false, "key_is_link"},
        {"a self-referential link", "Self", false, false, "key_is_link"},
        {"a path through a self-referential link", "Self\\x", false, false, "key_is_link"},
        {"a decoy value on the LEAF", "Decoy", false, false, "key_is_link"},
        {"a decoy value on a plain ANCESTOR (the documented divergence)", "Decoy\\sub", false, true, "key_is_link"},
        {"a missing key", "Real\\a\\nope", false, false, "key_not_found"},
    };
    for (const auto& row : rows) {
        INFO(row.what);
        const std::string path = root + "\\" + row.rel;
        const Opened fast = yuzu::registry::open_fast(reg, hklm, path, KEY_QUERY_VALUE, row.leaf_may_be_link);
        const Opened walk = yuzu::registry::open_checked(reg, hklm, path, KEY_QUERY_VALUE, false, row.leaf_may_be_link, false);
        CHECK(fast.fast == row.fast_accepts);
        CHECK(walk.error == row.walk_error);
        if (fast.fast && walk.error.empty()) { // both hold a handle: the same object
            std::string a, b;
            REQUIRE(reg.final_name(fast.leaf.get(), a) == ERROR_SUCCESS);
            REQUIRE(reg.final_name(walk.leaf.get(), b) == ERROR_SUCCESS);
            CHECK(a == b);
        }
    }
}

#endif // defined(_WIN32)
