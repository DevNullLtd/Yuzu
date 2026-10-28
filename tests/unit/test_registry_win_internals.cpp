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
 *  - the recursive delete walk, the dry-run create probe (an empty-subkey RegOpenKeyExW with KEY_CREATE_SUB_KEY), the
 *    ACL a dry run cannot see, and RegFlushKey on a mounted hive: Win32 behaviour the in-memory fake only models.
 *  - execute_guarded, the ABI seam: an action that throws (this TU's guard macro makes any action throw when
 *    its `name` parameter is `__throw_std` or `__throw_other`) comes out as rc 1, the action's fixed exception
 *    audit line when it is a mutator, and one `error|exception` line, never as an exception.
 * The pure logic is locked on every host by test_registry_core.cpp; the dispatcher cases prove the plugin end
 * to end.
 *
 * TU-inclusion precedent: test_privacy_permissions_win_internals.cpp (the same
 * `..._UNIT_TEST_INTERNALS_ONLY` guard, which drops the one plugin-facing function so the file can be
 * included). `#if defined(_WIN32)` guards the WHOLE body -- empty TU elsewhere. Needs an elevated token
 * (a salted HKLM scratch key); like the dispatcher cases it WARN-skips otherwise, and
 * YUZU_REQUIRE_WINDOWS_REGISTRY_TESTS=1 (CI's Windows leg, #6488, and the evidence runs) turns that skip into a FAIL.
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

#include <windows.h>

#include <sddl.h>

#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include <win_hive_file_probe.hpp> // yuzu::win::LocalFreeGuard
#include <win_profiles.hpp>        // PrivilegeScope, ScopedUserHive

#include <cstdlib>
#include <filesystem>
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

/// Runs execute_guarded(`action`) inside the fake context with the one parameter `name`=`name_param` (empty: no
/// params); the non-empty output lines.
struct Guarded {
    int rc = 0;
    std::vector<std::string> lines;
};

Guarded run_guarded(std::string_view action, const char* name_param = nullptr) {
    g_body = [action, name_param](yuzu::CommandContext& ctx) -> int {
        const YuzuParam params[] = {{"name", name_param != nullptr ? name_param : ""}};
        return yuzu::registry::execute_guarded(
            ctx, action, yuzu::Params{std::span<const YuzuParam>{params, name_param != nullptr ? 1u : 0u}});
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
bool make_machine_link(const std::wstring& link_path, const std::wstring& target_path) {
    yuzu::win::RegKey link;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, link_path.c_str(), 0, nullptr, REG_OPTION_CREATE_LINK,
                        KEY_SET_VALUE | KEY_CREATE_LINK, nullptr, link.put(), nullptr) != ERROR_SUCCESS)
        return false;
    const std::wstring target = L"\\Registry\\Machine\\" + target_path;
    return RegSetValueExW(link.get(), L"SymbolicLinkValue", 0, REG_LINK,
                          reinterpret_cast<const BYTE*>(target.data()),
                          static_cast<DWORD>(target.size() * sizeof(wchar_t))) == ERROR_SUCCESS;
}

/// The ASCII form of the above (every link name and target the older cases use is ASCII).
bool make_machine_link(const std::string& link_path, const std::string& target_path) {
    return make_machine_link(widen(link_path), widen(target_path));
}

// A key whose DACL denies read (the inherited-ACL case) still exists: only "not found" means absent.
bool key_exists(const std::string& key) {
    yuzu::win::RegKey k;
    const LSTATUS rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, widen(key).c_str(), 0, KEY_READ, k.put());
    return rc == ERROR_SUCCESS || rc == ERROR_ACCESS_DENIED;
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

/// Deletes the link object at `parent\<name>` by handle on scope exit (a link-opening open + NtDeleteKey),
/// so a failed REQUIRE, or a build without the flag where create_sub followed the link, still leaves no
/// link behind for RegDeleteTreeW to trip over. Never throws.
struct LinkSweep {
    Win32Registry& reg;
    Handle parent;
    std::string name;
    ~LinkSweep() {
        Handle h = 0;
        if (reg.open_sub(parent, name, DELETE, h) == ERROR_SUCCESS) {
            reg.delete_key_by_handle(h);
            reg.close(h);
        }
    }
    LinkSweep(Win32Registry& r, Handle p, std::string n = "Link") : reg(r), parent(p), name(std::move(n)) {}
    LinkSweep(const LinkSweep&) = delete;
    LinkSweep& operator=(const LinkSweep&) = delete;
};

/// `SOFTWARE\YuzuTest-[<scope>-]<salt>-<tag>`: the scope (YUZU_TEST_REGISTRY_SCOPE, set per job in CI) lets the
/// job's leftover-key check tell its keys from a concurrent job's.
std::string scratch_root(const char* tag) {
    return "SOFTWARE\\" + yuzu::test::registry_scratch_prefix() + std::to_string(yuzu::test::process_random_salt()) + "-" +
           tag;
}

} // namespace

// A link whose TARGET is absent is the shape that matters for a create: a create that follows it makes the
// target and reports REG_CREATED_NEW_KEY (measured with MSVC 14.44, 2026-10-18), which the core cannot tell
// from a fresh key. With REG_OPTION_OPEN_LINK the call opens the link itself: OPENED_EXISTING, nothing
// created. Mutation: drop `| REG_OPTION_OPEN_LINK` from Win32Registry::create_sub and this case goes red
// (created_new becomes true, the handle is the Target, and the Target key exists afterwards).
TEST_CASE("Win32Registry::create_sub opens a dangling registry link as the link and creates nothing through it",
          "[registry][windows][internals]") {
    const std::string root = scratch_root("internals");
    ScratchTree cleanup{root};

    // The scratch parent, opened with the right the create needs. HKLM\SOFTWARE is writable only elevated.
    yuzu::win::RegKey parent;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, widen(root).c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_READ | KEY_CREATE_SUB_KEY, nullptr, parent.put(), nullptr) != ERROR_SUCCESS) {
        skip_or_fail("not elevated -- HKLM scratch not writable, create_sub link case");
        return;
    }
    Win32Registry reg;
    const Handle parent_handle = as_handle(parent.get());
    LinkSweep sweep{reg, parent_handle}; // before the link exists, so a link made by a failing call goes too
    if (!make_machine_link(root + "\\Link", root + "\\Target")) { // Target is never created by this case
        skip_or_fail("could not create a registry link here");
        return;
    }

    // Exactly the create open_checked issues for a missing component, with DELETE added so the link
    // object can be removed by handle below (the access mask does not change how a link is treated).
    Handle out = 0;
    bool created_new = true;
    const long rc = reg.create_sub(parent_handle, "Link", KEY_READ | KEY_SET_VALUE | DELETE, out, created_new);
    REQUIRE(rc == ERROR_SUCCESS);
    REQUIRE(out != 0);
    const Owned out_guard{reg, out}; // closes on every exit, a failed CHECK or REQUIRE included

    CHECK_FALSE(created_new); // OPENED_EXISTING: the core turns this into concurrent_change

    // The handle IS the link: it carries the SymbolicLinkValue a followed target would not.
    DWORD type = 0;
    DWORD size = 0;
    CHECK(RegQueryValueExW(as_hkey(out), L"SymbolicLinkValue", nullptr, &type, nullptr, &size) == ERROR_SUCCESS);
    CHECK(type == REG_LINK);

    CHECK_FALSE(key_exists(root + "\\Target")); // nothing was created through the link

    // The link object goes by handle (the NtDeleteKey arm), not its target.
    CHECK(reg.delete_key_by_handle(out) == ERROR_SUCCESS);
}

// The fast open's two kernel calls. Win32 semantics relied on: a handle opened with REG_OPTION_OPEN_LINK on a link
// IS the link object, so its canonical name is the link's own path; an INTERMEDIATE link is followed, so the
// canonical name of what a path through it opens is the target's.
TEST_CASE("Win32Registry::final_name names the object a handle is bound to and the probe reports a link leaf",
          "[registry][windows][internals]") {
    const std::string root = scratch_root("names");
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
    Win32Registry reg;
    const Handle hklm = as_handle(HKEY_LOCAL_MACHINE);
    LinkSweep sweep{reg, as_handle(parent.get())}; // before the link exists, so a link made by a failing call goes too
    if (!make_machine_link(root + "\\Link", root + "\\Target")) {
        skip_or_fail("could not create a registry link here");
        return;
    }
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

// #6487: the fast open ACCEPTs a handle only when its canonical kernel name equals the requested path, and that
// compare runs on the UTF-8 form. A key named `L<U+D800>` (a lone surrogate: the kernel accepts any UTF-16 unit)
// converted lossily to U+FFFD, the same bytes as a requested `L<U+FFFD>`, so the compare passed on a handle one code
// unit away from the name asked for. query_key_name now fails closed on such a name (kernel_name_well_formed), so
// final_name answers ERROR_INVALID_DATA, open_fast declines and the walk decides.
//
// The link sits in an ANCESTOR position on purpose: open_path passes REG_OPTION_OPEN_LINK, which holds for the final
// component only, so a LEAF link is opened as the link object and probe_link refuses it with or without the name
// check; a link traversed mid-path is what the lossy compare lets through.
// Mutation: delete the kernel_name_well_formed call in query_key_name -> final_name converts `...\L<D800>\Child`
// to `...\L<FFFD>\Child`, equal to the requested path, Child probes clean, and the fast open ACCEPTs: the last
// second section answers ok and V lands on L<D800>\Child.
TEST_CASE("Win32Registry::final_name fails closed on a lone-surrogate key name, so a U+FFFD lookalike link cannot "
          "redirect a fast set_value",
          "[registry][windows][internals]") {
    const std::string root = scratch_root("kname");
    const std::wstring wroot = widen(root);
    ScratchTree cleanup{root};
    yuzu::win::RegKey parent;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, wroot.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_READ | KEY_CREATE_SUB_KEY, nullptr, parent.put(), nullptr) != ERROR_SUCCESS) {
        skip_or_fail("not elevated -- HKLM scratch not writable, kernel-name case");
        return;
    }
    const std::wstring lone = L"L\xD800";           // a lone high surrogate: no UTF-8 form
    const std::wstring lookalike = L"L\xFFFD";       // U+FFFD, what a lossy conversion makes of it
    const std::string lookalike_utf8 = "L\xEF\xBF\xBD";
    const auto create_key = [&](const std::wstring& rel) {
        yuzu::win::RegKey k;
        return RegCreateKeyExW(parent.get(), rel.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_READ, nullptr,
                               k.put(), nullptr);
    };
    if (const LONG rc = create_key(L"L"); rc != ERROR_SUCCESS) {
        skip_or_fail("could not create the plain key L, rc=" + std::to_string(rc));
        return;
    }
    if (const LONG rc = create_key(lone + L"\\Child"); rc != ERROR_SUCCESS) {
        skip_or_fail("RegCreateKeyExW refused a key name holding a lone surrogate, rc=" + std::to_string(rc));
        return;
    }
    Win32Registry reg;
    const Handle hklm = as_handle(HKEY_LOCAL_MACHINE);

    SECTION("a plain key is named; its lone-surrogate sibling is not") {
        Handle h = 0;
        REQUIRE(reg.open_path(hklm, root + "\\L", KEY_QUERY_VALUE, h) == ERROR_SUCCESS);
        {
            const Owned guard{reg, h};
            std::string name;
            REQUIRE(reg.final_name(h, name) == ERROR_SUCCESS);
            CHECK(yuzu::registry::names_equal_ascii_ci(name, "\\REGISTRY\\MACHINE\\" + root + "\\L"));
        }
        yuzu::win::RegKey sibling;
        REQUIRE(RegOpenKeyExW(HKEY_LOCAL_MACHINE, (wroot + L"\\" + lone).c_str(), REG_OPTION_OPEN_LINK, KEY_QUERY_VALUE,
                              sibling.put()) == ERROR_SUCCESS);
        std::string name = "stale";
        CHECK(reg.final_name(as_handle(sibling.get()), name) == ERROR_INVALID_DATA);
        CHECK(name.empty()); // a half-converted name is never handed back
    }
    SECTION("a link named for U+FFFD, standing for the lone-surrogate key, is refused and nothing is written") {
        LinkSweep sweep{reg, as_handle(parent.get()), lookalike_utf8}; // before the link exists
        if (!make_machine_link(wroot + L"\\" + lookalike, wroot + L"\\" + lone)) {
            skip_or_fail("could not create a registry link here");
            return;
        }
        const std::vector<std::uint8_t> value{7, 0, 0, 0};
        // The requested path is plain UTF-8 (valid, passes validate_key_path): `<root>\L<U+FFFD>\Child`. The kernel
        // follows the ancestor link to `L<U+D800>\Child`; only the lone-surrogate rule keeps the fast open from
        // accepting that handle. The fast open then declines and the walk opens the link with OPEN_LINK and refuses it.
        const auto o = yuzu::registry::set_value_verified(reg, hklm, root + "\\" + lookalike_utf8 + "\\Child", "V",
                                                          REG_DWORD, value, /*fast_eligible=*/true);
        CHECK(o.result == "refused");
        CHECK(o.reason == "key_is_link");
        CHECK(o.created == 0);
        yuzu::win::RegKey child;
        REQUIRE(RegOpenKeyExW(HKEY_LOCAL_MACHINE, (wroot + L"\\" + lone + L"\\Child").c_str(), 0, KEY_QUERY_VALUE,
                              child.put()) == ERROR_SUCCESS);
        CHECK(RegQueryValueExW(child.get(), L"V", nullptr, nullptr, nullptr, nullptr) == ERROR_FILE_NOT_FOUND);
    }
}

// The enumeration a delete acts on is exact: with require_exact a raw value or key name holding a lone surrogate answers
// ERROR_INVALID_DATA (it was validated BEFORE from_wide), while a display enumeration still converts it lossily, and a
// real U+FFFD name passes either way. Mutation: drop the kernel_name_well_formed call in enumerated_name -> the exact
// enumeration answers success with the lookalike's bytes.
TEST_CASE("Win32Registry::enum_value and enum_subkey refuse a lone-surrogate name only when the exact name is required",
          "[registry][windows][internals]") {
    const std::string root = scratch_root("ename");
    const std::wstring wroot = widen(root);
    ScratchTree cleanup{root};
    yuzu::win::RegKey key;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, wroot.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_READ | KEY_SET_VALUE | KEY_CREATE_SUB_KEY, nullptr, key.put(), nullptr) != ERROR_SUCCESS) {
        skip_or_fail("not elevated -- HKLM scratch not writable, enumerated-name case");
        return;
    }
    const std::wstring lone = L"N\xD800";
    const std::string lookalike_utf8 = "N\xEF\xBF\xBD";
    const BYTE data[4]{};
    Win32Registry reg;
    const Handle h = as_handle(key.get());
    const auto expect = [&](bool values) {
        std::string lossy, exact = "stale";
        CHECK((values ? reg.enum_value(h, 0, lossy) : reg.enum_subkey(h, 0, lossy)) == ERROR_SUCCESS);
        CHECK(lossy == lookalike_utf8);
        CHECK((values ? reg.enum_value(h, 0, exact, true) : reg.enum_subkey(h, 0, exact, true)) == ERROR_INVALID_DATA);
        CHECK(exact == "stale"); // nothing half-converted is handed back
    };
    SECTION("a value") {
        if (RegSetValueExW(key.get(), lone.c_str(), 0, REG_DWORD, data, 4) != ERROR_SUCCESS) {
            skip_or_fail("RegSetValueExW refused a value name holding a lone surrogate");
            return;
        }
        expect(true);
    }
    SECTION("a key") {
        yuzu::win::RegKey child;
        if (RegCreateKeyExW(key.get(), lone.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_READ, nullptr, child.put(),
                            nullptr) != ERROR_SUCCESS) {
            skip_or_fail("RegCreateKeyExW refused a key name holding a lone surrogate");
            return;
        }
        expect(false);
    }
    SECTION("a real U+FFFD name passes the exact enumeration") {
        REQUIRE(RegSetValueExW(key.get(), L"N\xFFFD", 0, REG_DWORD, data, 4) == ERROR_SUCCESS);
        std::string name;
        CHECK(reg.enum_value(h, 0, name, true) == ERROR_SUCCESS);
        CHECK(name == lookalike_utf8);
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

// The recursive delete's post-order walk over the REAL registry. Kingsley probe K1 (MSVC 14.44, 2026-10-19):
// RegDeleteTreeW on a tree holding a REG_LINK emptied the link's TARGET (K1b: a handle opened with
// REG_OPTION_OPEN_LINK on the link itself did not). The core now deletes by handle and probes every key again,
// so a link met at delete time stops the walk (key_is_link) whichever order the child keys enumerate in.
// test_registry_core.cpp pins the same stop on the fake. Mutation: drop the probe_link call in delete_subtree
// (registry_core.hpp) and this case goes red (the walk enters the link and the Target is no longer intact).
// The link sits in a tree reached through delete_key_on directly, i.e. PAST the vet (count_tree), which is the
// planted-link-since-the-vet shape the walk's own re-probe exists for.
TEST_CASE("the recursive delete walk stops at a registry link inside the tree and leaves its target intact",
          "[registry][windows][internals]") {
    const std::string root = scratch_root("deltree");
    ScratchTree cleanup{root};

    const auto make_key_with_value = [](const std::string& path) {
        yuzu::win::RegKey k;
        const DWORD v = 7;
        return RegCreateKeyExW(HKEY_LOCAL_MACHINE, widen(path).c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                               KEY_SET_VALUE, nullptr, k.put(), nullptr) == ERROR_SUCCESS &&
               RegSetValueExW(k.get(), L"v", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v)) == ERROR_SUCCESS;
    };
    if (!make_key_with_value(root + "\\Tree\\A") || !make_key_with_value(root + "\\Target") ||
        !make_key_with_value(root + "\\Target\\Y")) {
        skip_or_fail("not elevated -- HKLM scratch not writable, delete-walk link case");
        return;
    }

    Win32Registry reg;
    Handle top = 0;
    REQUIRE(reg.open_sub(as_handle(HKEY_LOCAL_MACHINE), root + "\\Tree",
                         DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_SET_VALUE, top) == ERROR_SUCCESS);
    const Owned top_h{reg, top};
    LinkSweep sweep{reg, top}; // a failed REQUIRE (or a build that followed the link) must not leave it for the cleanup
    if (!make_machine_link(root + "\\Tree\\Link", root + "\\Target")) {
        skip_or_fail("could not create a registry link here");
        return;
    }

    const auto o = yuzu::registry::delete_key_on(reg, top, /*recursive=*/true);
    CHECK(o.reason == "key_is_link");
    CHECK(key_exists(root + "\\Target\\Y")); // the target and its subtree survived
    yuzu::win::RegKey target;
    REQUIRE(RegOpenKeyExW(HKEY_LOCAL_MACHINE, widen(root + "\\Target").c_str(), 0, KEY_QUERY_VALUE, target.put()) ==
            ERROR_SUCCESS);
    DWORD size = 0;
    CHECK(RegQueryValueExW(target.get(), L"v", nullptr, nullptr, nullptr, &size) == ERROR_SUCCESS); // its value too
    CHECK(key_exists(root + "\\Tree")); // the walk never reached the top key's own delete
}

// The same walk on a tree with no link: the production Win32Registry removes it post-order by handle (NtDeleteKey on
// each key's own handle), the removed child no longer enumerates at index 0 (the walk's loop relies on that), and the
// dry run counted what the real run removed. The scratch tree is therefore gone by handle, not by RegDeleteTreeW.
TEST_CASE("the recursive delete walk removes a plain tree post-order by handle and counts what it removed",
          "[registry][windows][internals]") {
    const std::string root = scratch_root("delplain");
    ScratchTree cleanup{root};
    const auto make_key_with_value = [](const std::string& path) {
        yuzu::win::RegKey k;
        const DWORD v = 7;
        return RegCreateKeyExW(HKEY_LOCAL_MACHINE, widen(path).c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                               KEY_SET_VALUE, nullptr, k.put(), nullptr) == ERROR_SUCCESS &&
               RegSetValueExW(k.get(), L"v", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v)) == ERROR_SUCCESS;
    };
    if (!make_key_with_value(root + "\\Plain") || !make_key_with_value(root + "\\Plain\\A") ||
        !make_key_with_value(root + "\\Plain\\A\\B") || !make_key_with_value(root + "\\Plain\\C")) {
        skip_or_fail("not elevated -- HKLM scratch not writable, delete-walk plain case");
        return;
    }
    Win32Registry reg;
    const Handle hklm = as_handle(HKEY_LOCAL_MACHINE);
    const auto dry = yuzu::registry::delete_key_tree(reg, hklm, root + "\\Plain", /*fast_eligible=*/true,
                                                     /*recursive=*/true, /*dry_run=*/true);
    CHECK(dry.result == "ok");
    CHECK(dry.counted_keys == 4);
    CHECK(dry.counted_values == 4);
    CHECK(key_exists(root + "\\Plain\\A\\B"));
    const auto real = yuzu::registry::delete_key_tree(reg, hklm, root + "\\Plain", true, true, false);
    CHECK(real.result == "ok");
    CHECK(real.verify == "ok");
    CHECK(real.counted_keys == 4);
    CHECK(real.counted_values == 4);
    CHECK_FALSE(key_exists(root + "\\Plain"));
}

// The walk on the DEEPEST chain Windows allows. A registry tree can be at most 512 levels deep (counted from the hive root),
// which is below kMaxTreeDepth (600): the 600/601 boundary can only be tested against the fake registry (test_registry_core.cpp),
// and on a real hive the depth cap is never what stops a delete. What a real chain does exercise is the recursion itself: the
// vet and the post-order delete both run to the OS limit on this build's stack (a debug MSVC build has the largest frames).
// The chain grows one-character keys until the registry refuses a deeper key, so the case follows the OS limit instead of
// hard-coding it.
TEST_CASE("the recursive delete walk handles the deepest chain Windows allows", "[registry][windows][internals]") {
    const std::string root = scratch_root("deepchain");
    ScratchTree cleanup{root};
    unsigned levels = 0; // keys in the chain, the top key included
    {
        yuzu::win::RegKey cur;
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, widen(root + "\\Deep").c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                            KEY_CREATE_SUB_KEY, nullptr, cur.put(), nullptr) != ERROR_SUCCESS) {
            skip_or_fail("not elevated -- HKLM scratch not writable, deep chain case");
            return;
        }
        levels = 1;
        for (unsigned i = 0; i < 700; ++i) {
            yuzu::win::RegKey next;
            if (RegCreateKeyExW(cur.get(), L"k", 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_CREATE_SUB_KEY, nullptr, next.put(),
                                nullptr) != ERROR_SUCCESS)
                break; // the OS limit
            cur = std::move(next);
            ++levels;
        }
    }
    WARN("deepest chain Windows allowed under the scratch key: " << levels << " keys");
    REQUIRE(levels > 400); // the limit is 512 from the hive root; far fewer would mean the chain stopped for another reason
    REQUIRE(levels <= yuzu::registry::kMaxTreeDepth); // the OS limit sits below our cap, so the cap is not what is exercised

    Win32Registry reg;
    const Handle hklm = as_handle(HKEY_LOCAL_MACHINE);
    const auto dry = yuzu::registry::delete_key_tree(reg, hklm, root + "\\Deep", true, true, /*dry_run=*/true);
    CHECK(dry.result == "ok");
    CHECK_FALSE(dry.capped);
    CHECK(dry.counted_keys == levels);
    const auto real = yuzu::registry::delete_key_tree(reg, hklm, root + "\\Deep", true, true, false);
    CHECK(real.result == "ok");
    CHECK(real.counted_keys == levels);
    CHECK_FALSE(key_exists(root + "\\Deep"));
}

namespace {

/// Gives `key` (a handle opened with WRITE_DAC) a DACL, from SDDL text. False when it could not.
bool set_key_sddl(HKEY key, const wchar_t* sddl) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, nullptr)) return false;
    const yuzu::win::LocalFreeGuard free_sd{sd};
    return RegSetKeySecurity(key, DACL_SECURITY_INFORMATION, sd) == ERROR_SUCCESS;
}

/// Puts a permissive DACL back on `path` (HKLM-relative) on scope exit, so a deny ACE a case installed never blocks the
/// scratch tree's removal. Declare it AFTER the ScratchTree it protects. Never throws.
struct AclRestore {
    std::string path;
    explicit AclRestore(std::string p) : path(std::move(p)) {}
    ~AclRestore() {
        yuzu::win::RegKey k;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, widen(path).c_str(), 0, WRITE_DAC | READ_CONTROL, k.put()) == ERROR_SUCCESS)
            set_key_sddl(k.get(), L"D:(A;;GA;;;WD)");
    }
    AclRestore(const AclRestore&) = delete;
    AclRestore& operator=(const AclRestore&) = delete;
};

} // namespace

// The dry run's create check. Win32 semantics relied on: RegOpenKeyExW(h, L"", ..., KEY_CREATE_SUB_KEY) opens a NEW
// handle to the key `h` is bound to and checks the requested access against THAT key's security descriptor (not the
// access `h` was opened with), so a key whose ACL denies subkey creation answers ERROR_ACCESS_DENIED without anything
// being created. Mutation: ask for KEY_READ in the probe (registry_core.hpp open_checked) and the locked section goes red.
TEST_CASE("RegOpenKeyExW(h empty KEY_CREATE_SUB_KEY) answers ERROR_ACCESS_DENIED on a key whose ACL denies subkey "
          "creation and creates nothing",
          "[registry][windows][internals]") {
    const std::string root = scratch_root("probe");
    ScratchTree cleanup{root};
    const std::string locked = root + "\\Locked";
    const std::string open_key = root + "\\Open";
    AclRestore unlock{locked}; // destroyed first: removes the deny ACE, then the subtree goes
    for (const std::string& path : {locked, open_key}) {
        yuzu::win::RegKey k;
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, widen(path).c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, WRITE_DAC | KEY_READ,
                            nullptr, k.put(), nullptr) != ERROR_SUCCESS) {
            skip_or_fail("not elevated -- HKLM scratch not writable, create-probe case");
            return;
        }
        if (path == locked && !set_key_sddl(k.get(), L"D:(D;;0x4;;;WD)(A;;GA;;;WD)")) {
            skip_or_fail("could not install a deny ACE");
            return;
        }
    }
    Win32Registry reg;
    const Handle hklm = as_handle(HKEY_LOCAL_MACHINE);
    // The parent handles are opened WITHOUT the create right: the probe must not depend on what the handle was opened with.
    Handle locked_h = 0, open_h = 0;
    REQUIRE(reg.open_sub(hklm, locked, KEY_READ, locked_h) == ERROR_SUCCESS);
    const Owned locked_guard{reg, locked_h};
    REQUIRE(reg.open_sub(hklm, open_key, KEY_READ, open_h) == ERROR_SUCCESS);
    const Owned open_guard{reg, open_h};

    SECTION("a key that denies subkey creation") {
        Handle probe = 0;
        CHECK(reg.open_sub(locked_h, "", KEY_CREATE_SUB_KEY, probe) == ERROR_ACCESS_DENIED);
        const Owned probe_guard{reg, probe}; // 0 on the expected refusal: nothing to close
        CHECK(yuzu::registry::open_checked(reg, hklm, locked + "\\New", KEY_SET_VALUE | KEY_QUERY_VALUE, /*create=*/false,
                                           false, false, /*probe_create=*/true)
                  .error == "access_denied");
        CHECK(yuzu::registry::open_checked(reg, hklm, locked + "\\New", KEY_SET_VALUE | KEY_QUERY_VALUE, /*create=*/true)
                  .error == "access_denied"); // what the real run answers
    }
    SECTION("a key that allows it: a new handle, and still nothing created") {
        Handle probe = 0;
        REQUIRE(reg.open_sub(open_h, "", KEY_CREATE_SUB_KEY, probe) == ERROR_SUCCESS);
        const Owned probe_guard{reg, probe};
        CHECK(probe != open_h); // a new handle, not the one passed in
        const auto o = yuzu::registry::open_checked(reg, hklm, open_key + "\\New", KEY_SET_VALUE | KEY_QUERY_VALUE, false,
                                                    false, false, true);
        CHECK(o.error == "key_not_found");
        CHECK(o.missing == 1);
    }
    CHECK_FALSE(key_exists(locked + "\\New"));
    CHECK_FALSE(key_exists(open_key + "\\New"));
}

// P6 (the documented predictive limit): the dry run's probe proves create access on the EXISTING parent, not the ACL a
// key that does not exist yet will inherit. Here the parent allows creation and hands every new child a deny ACE for
// KEY_SET_VALUE. The dry run says would_apply (it cannot see the child's descriptor); what the real run does with the
// handle RegCreateKeyExW hands back is Windows' answer, recorded below. Whatever it is, the real run must leave the
// registry consistent with what it reports: a verdict other than applied leaves no key behind and reports created=0.
TEST_CASE("apply: a dry run cannot see the ACL a new key inherits; the real run's outcome matches the registry",
          "[registry][windows][internals]") {
    const std::string root = scratch_root("inherit");
    ScratchTree cleanup{root};
    const std::string parent = root + "\\Parent";
    AclRestore restore_parent{parent};
    // The child the real run creates inherits ONLY the deny ACE (the parent's allow is not inheritable), so nobody can
    // open it for DELETE or SET_VALUE and RegDeleteTreeW leaves the whole scratch root behind. Destroyed first.
    AclRestore restore_child{parent + "\\New"};
    {
        yuzu::win::RegKey k;
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, widen(parent).c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, WRITE_DAC | KEY_READ,
                            nullptr, k.put(), nullptr) != ERROR_SUCCESS) {
            skip_or_fail("not elevated -- HKLM scratch not writable, inherited-ACL case");
            return;
        }
        // Everyone may do anything to the parent itself; the inherit-only ACE gives every NEW child a deny for
        // KEY_SET_VALUE (0x2) to Everyone.
        if (!set_key_sddl(k.get(), L"D:(A;;GA;;;WD)(D;CIIO;0x2;;;WD)")) {
            skip_or_fail("could not install an inheritable deny ACE");
            return;
        }
    }
    const auto parsed = yuzu::registry::parse_plan(
        R"([{"op":"set_value","key":")" + [&] {
            std::string e;
            for (const char c : parent) e += (c == '\\') ? "\\\\" : std::string{c};
            return e;
        }() + R"(\\New","name":"V","type":"REG_DWORD","value":"1"}])");
    REQUIRE(parsed.error.empty());

    Win32Registry reg;
    const Handle hklm = as_handle(HKEY_LOCAL_MACHINE);
    struct Lines { // run_apply's sink
        std::vector<std::string> lines;
        void write_output(std::string_view t) { lines.emplace_back(t); }
    };
    const auto verdict_of = [&](bool dry_run) {
        Lines out;
        (void)yuzu::registry::run_apply(out, reg, hklm, parsed.items, {dry_run, false}, true);
        for (const auto& l : out.lines)
            if (l.rfind("item|0|", 0) == 0) {
                std::vector<std::string> cells;
                std::size_t pos = 0;
                for (;;) {
                    const auto bar = l.find('|', pos);
                    cells.push_back(l.substr(pos, bar == std::string::npos ? std::string::npos : bar - pos));
                    if (bar == std::string::npos) break;
                    pos = bar + 1;
                }
                return cells;
            }
        return std::vector<std::string>{};
    };
    const auto dry = verdict_of(/*dry_run=*/true);
    REQUIRE(dry.size() > 9);
    CHECK(dry[6] == "would_apply");
    CHECK_FALSE(key_exists(parent + "\\New"));

    const auto real = verdict_of(/*dry_run=*/false);
    REQUIRE(real.size() > 9);
    WARN("inherited deny ACE: dry run " << dry[6] << ", real run " << real[6] << " (" << real[7] << "), created=" << real[9]);
    if (real[6] == "applied") {
        CHECK(key_exists(parent + "\\New"));
    } else {
        CHECK_FALSE(key_exists(parent + "\\New")); // rolled back by handle
        CHECK(real[9] == "0");
    }
}

// RegFlushKey on a key of a MOUNTED hive writes the hive to its file (the per-user write arm calls it before the
// unload, because RegUnLoadKey does not itself modify the file). A 128 KiB value forces the hive to grow by whole bins,
// so the file's size moves when the flush writes it; an unflushed hive keeps its on-disk size until the lazy writer runs.
TEST_CASE("Win32Registry::flush_key on a mounted scratch hive succeeds and the hive file grows",
          "[registry][windows][internals]") {
    namespace fs = std::filesystem;
    yuzu::win::PrivilegeScope backup(L"SeBackupPrivilege");
    yuzu::win::PrivilegeScope restore(L"SeRestorePrivilege");
    if (!backup.ok() || !restore.ok()) {
        skip_or_fail("not elevated (no SeBackup/SeRestore) -- hive flush case");
        return;
    }
    const std::string src = "SOFTWARE\\" + yuzu::test::registry_scratch_prefix() + std::to_string(yuzu::test::process_random_salt()) + "-flushsrc";
    ScratchTree cleanup{src};
    yuzu::test::TempDir tmp{"yuzu_test_flush_"};
    std::error_code mkdir_ec;
    fs::create_directories(tmp.path, mkdir_ec); // TempDir only names the path: RegSaveKeyExW needs the directory to exist
    const fs::path hive_file = tmp.path / "scratch.hive";
    {
        yuzu::win::RegKey k;
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, widen(src).c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_READ | KEY_SET_VALUE,
                            nullptr, k.put(), nullptr) != ERROR_SUCCESS) {
            skip_or_fail("not elevated -- HKLM scratch not writable, hive flush case");
            return;
        }
        const DWORD v = 1;
        REQUIRE(RegSetValueExW(k.get(), L"seed", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v)) == ERROR_SUCCESS);
        const LSTATUS rc = RegSaveKeyExW(k.get(), hive_file.wstring().c_str(), nullptr, REG_STANDARD_FORMAT);
        if (rc != ERROR_SUCCESS) {
            skip_or_fail("RegSaveKeyExW could not save the scratch hive, rc=" + std::to_string(rc));
            return;
        }
    }
    const auto file_size = [&] {
        WIN32_FILE_ATTRIBUTE_DATA d{};
        if (!GetFileAttributesExW(hive_file.wstring().c_str(), GetFileExInfoStandard, &d)) return std::uintmax_t{0};
        return (static_cast<std::uintmax_t>(d.nFileSizeHigh) << 32) | d.nFileSizeLow;
    };
    bool unload_failed = false;
    {
        yuzu::win::ScopedUserHive hive{widen(yuzu::test::registry_scratch_prefix() +
                                             std::to_string(yuzu::test::process_random_salt()) + "-flush"),
                                       hive_file.wstring(), &unload_failed};
        REQUIRE(hive.ok());
        hive.with_root([&](HKEY root) {
            yuzu::win::RegKey k;
            REQUIRE(RegCreateKeyExW(root, L"k", 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE | KEY_QUERY_VALUE, nullptr,
                                    k.put(), nullptr) == ERROR_SUCCESS);
            const std::vector<BYTE> big(128 * 1024, 0xAB);
            const auto before = file_size();
            REQUIRE(RegSetValueExW(k.get(), L"big", 0, REG_BINARY, big.data(), static_cast<DWORD>(big.size())) == ERROR_SUCCESS);
            Win32Registry reg;
            CHECK(reg.flush_key(as_handle(k.get())) == ERROR_SUCCESS);
            CHECK(file_size() > before);
        });
    }
    CHECK_FALSE(unload_failed);
}

// The frozen-seam rule: nothing a registry action throws crosses the plugin boundary. dispatch throws a
// std::exception for `name=__throw_std` and a non-std value for `name=__throw_other` in this TU only (the guard
// macro). A mutating action leaves its fixed audit line first, so the server still mints a failed registry.write row.
// Mutation: delete the catch(...) from execute_guarded and the throwing sections go red (the exception escapes the
// call); drop report_exception's audit line and the mutator sections go red. Needs no registry access, so it never
// skips.
TEST_CASE("execute_guarded turns a throwing action into rc 1 and one error|exception line",
          "[registry][windows][internals]") {
    SECTION("a std::exception from a read") {
        const auto r = run_guarded("get_value", "__throw_std");
        CHECK(r.rc == 1);
        REQUIRE(r.lines.size() == 1);
        CHECK(r.lines[0] == "error|exception");
    }
    SECTION("a value that is not a std::exception, from a read") {
        const auto r = run_guarded("enumerate_values", "__throw_other");
        CHECK(r.rc == 1);
        REQUIRE(r.lines.size() == 1);
        CHECK(r.lines[0] == "error|exception");
    }
    for (const char* mutator : {"set_value", "delete_value", "delete_key", "set_user_value", "delete_user_value", "apply"}) {
        for (const char* how : {"__throw_std", "__throw_other"}) {
            SECTION(std::string{mutator} + " throwing " + how + ": the fixed audit line, then error|exception") {
                const auto r = run_guarded(mutator, how);
                CHECK(r.rc == 1);
                REQUIRE(r.lines.size() == 2);
                CHECK(r.lines[0] == yuzu::registry::exception_audit_line(mutator));
                CHECK(r.lines[0].rfind(std::string{"audit|op="} + mutator + "|hive=-|result=failed|reason=exception|", 0) == 0);
                CHECK(r.lines[1] == "error|exception");
            }
        }
    }
    SECTION("an ordinary refusal passes through the guard unchanged") {
        const auto r = run_guarded("no_such_action");
        CHECK(r.rc == 1);
        REQUIRE(r.lines.size() == 1);
        CHECK(r.lines[0] == "error|unknown action: no_such_action");
    }
}

TEST_CASE("Win32Registry::query_value returns a REG_SZ stored without its terminator exactly as stored",
          "[registry][windows][internals]") {
    // The capture of a pre-existing value feeds the audit row's old= field: it must be the stored bytes. A
    // RegQueryValueExW into a roomy buffer may append a terminator the stored value never had; this pins that the
    // plugin's read reports exactly the stored bytes: no appended terminator, nothing truncated.
    //
    // The write needs care too. Measured on weecolin (build 26100.2605, 2026-10-27): RegSetValueExW given a 4-byte
    // REG_SZ, REG_EXPAND_SZ or REG_MULTI_SZ stores 6 bytes when the wchar_t just after those bytes in the caller's
    // buffer is zero and 4 when it is 'X'; REG_BINARY never pads. The bare `wchar_t[2]` this test used before
    // failed 8 of 8 there when run alone. Likely cause, not inspected: the stack after the array was zero in a
    // fresh process (a release build run alone) and not zero in a dirtied one (the full suite, a debug build).
    // The non-zero neighbour after the string pins the stored size at 4.
    const std::string root = scratch_root("unterminated");
    ScratchTree cleanup{root};
    yuzu::win::RegKey raw; // closes on every exit, a failed REQUIRE included
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, widen(root).c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_SET_VALUE | KEY_QUERY_VALUE, nullptr, raw.put(), nullptr) != ERROR_SUCCESS) {
        skip_or_fail("not elevated -- HKLM scratch not writable");
        return;
    }
    const wchar_t stored[3] = {L'a', L'b', L'X'}; // four bytes passed, no terminator; 'X' is only the neighbour
    REQUIRE(RegSetValueExW(raw.get(), L"V", 0, REG_SZ, reinterpret_cast<const BYTE*>(stored),
                           sizeof stored - sizeof(wchar_t)) == ERROR_SUCCESS);
    // The write precondition, asked of the OS directly so that a failure names the layer: the key holds the one
    // value "V", so the longest value data is its stored size. The 4 must stay 4. If a Windows build pads a string
    // it is asked to store unterminated, create the value another way (NtSetValueKey) rather than relax this: the
    // case is the only pin on the audit old= capture reporting no invented terminator.
    DWORD stored_bytes = 0;
    REQUIRE(RegQueryInfoKeyW(raw.get(), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                             &stored_bytes, nullptr, nullptr) == ERROR_SUCCESS);
    INFO("the OS stored " << stored_bytes << " bytes for the 4-byte REG_SZ write; anything but 4 points to the OS "
         "padding the write, not to a fault in the plugin's read");
    REQUIRE(stored_bytes == 4);
    Win32Registry reg;
    yuzu::registry::QueryResult q;
    REQUIRE(reg.query_value(as_handle(raw.get()), "V", 4096, q) == ERROR_SUCCESS);
    CHECK(q.type == REG_SZ);
    CHECK(q.size == 4);
    REQUIRE(q.bytes.size() == 4);
    CHECK(q.bytes[0] == 'a');
    CHECK(q.bytes[1] == 0);
    CHECK(q.bytes[2] == 'b');
    CHECK(q.bytes[3] == 0);
}

#endif // defined(_WIN32)
