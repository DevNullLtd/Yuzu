#pragma once

// installed_apps_registry_walk.hpp -- the Windows Uninstall-key walk, with a
// typed health result (#4711). In a header so a unit test can drive the same
// code against a scratch key (see tests/unit/test_installed_apps_registry_walk.cpp).
//
// A walk that cannot open a root, cannot enumerate it to the end, or cannot
// open one app's key (ERROR_ACCESS_DENIED above all) UNDER-REPORTS; the result
// says so (`degraded`) so list/query/list_inventory never present a partial
// registry walk as the complete software set. Keeps spdlog out: the caller logs
// the failed root indices.
//
// Windows-only: the whole body is under _WIN32.

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <yuzu/string_utils.hpp> // yuzu::util::sanitize_utf8

#include "installed_apps_inventory.hpp"
#include "installed_apps_parsers.hpp"
#include "installed_apps_registry_utf8.hpp"

// Pin the host-independent LSTATUS literals (parsers::classify_reg_status) to
// the real constants.
static_assert(yuzu::installed_apps::parsers::kErrorFileNotFound == ERROR_FILE_NOT_FOUND &&
              yuzu::installed_apps::parsers::kErrorAccessDenied == ERROR_ACCESS_DENIED &&
              yuzu::installed_apps::parsers::kErrorMoreData == ERROR_MORE_DATA &&
              yuzu::installed_apps::parsers::kErrorNoMoreItems == ERROR_NO_MORE_ITEMS);

namespace yuzu::installed_apps::reg_walk {

using AppInfo = parsers::AppRowFields;
using parsers::HiveRead;

struct UninstallRoot {
    HKEY root;
    std::wstring subkey;
    REGSAM extra_sam;
    bool absent_ok; // true for HKCU: a user hive often has no Uninstall key
};

struct WalkResult {
    std::vector<AppInfo> apps;
    bool degraded = false;
    std::vector<std::size_t> failed_roots; // indices into the roots span
};

// The four registry calls the walk makes, as one injectable seam: production
// uses RealRegOps; a unit test passes a scripted fake so the child-open and
// enumeration failure branches run deterministically (no ACLs, no timing).
struct RealRegOps {
    LSTATUS open(HKEY parent, const wchar_t* sub, REGSAM sam, HKEY* out) const {
        return RegOpenKeyExW(parent, sub, 0, sam, out);
    }
    LSTATUS enum_key(HKEY key, DWORD idx, wchar_t* name, DWORD* name_len) const {
        return RegEnumKeyExW(key, idx, name, name_len, nullptr, nullptr, nullptr, nullptr);
    }
    void close(HKEY key) const { RegCloseKey(key); }
    std::string read_str(HKEY key, const char* value_name, bool accept_expand_sz) const {
        return reg_utf8::read_reg_string(key, value_name, accept_expand_sz);
    }
};

// Walk one root, appending to `apps`. Returns failed if ANY part of the walk
// could not be read (apps read before the failure are kept).
template <class Ops = RealRegOps>
HiveRead enumerate_uninstall_key(const UninstallRoot& r, std::vector<AppInfo>& apps,
                                 const Ops& ops = Ops{}) {
    // Closes through `ops` so a fake's handles are never passed to RegCloseKey.
    // Every handle into the root is closed before the walk returns: list_per_user
    // runs this inside with_user_hive, and RegUnLoadKeyW fails (ERROR_ACCESS_DENIED)
    // while any subtree handle is open (#1662 Gate-8).
    struct Guard {
        const Ops& ops;
        HKEY h;
        ~Guard() {
            if (h)
                ops.close(h);
        }
    };
    HKEY hkey{};
    const LSTATUS open_rc =
        ops.open(r.root, r.subkey.c_str(), KEY_READ | KEY_ENUMERATE_SUB_KEYS | r.extra_sam, &hkey);
    if (open_rc != ERROR_SUCCESS)
        return parsers::classify_reg_status(open_rc, r.absent_ok) == HiveRead::absent
                   ? HiveRead::absent
                   : HiveRead::failed;
    Guard hkey_guard{ops, hkey};

    bool failed = false;
    // RegEnumKeyExW's lpcchName is a WCHAR COUNT, not a byte size. Bind the array
    // size and every reset to one constant so the byte-vs-count unit cannot skew.
    constexpr DWORD kNameBufLen = 256;
    wchar_t name_buf[kNameBufLen]{};
    for (DWORD idx = 0;; ++idx) {
        DWORD name_len = kNameBufLen;
        const LSTATUS rc = ops.enum_key(hkey, idx, name_buf, &name_len);
        if (rc == ERROR_NO_MORE_ITEMS)
            break;
        if (rc == ERROR_MORE_DATA) {
            failed = true; // a >255-WCHAR subkey name is pathological: skip this one
            continue;
        }
        if (rc != ERROR_SUCCESS) {
            failed = true;
            break;
        }

        HKEY app_key{};
        const LSTATUS child_rc = ops.open(hkey, name_buf, KEY_READ | r.extra_sam, &app_key);
        if (child_rc == ERROR_FILE_NOT_FOUND)
            continue; // vanished between enumerate and open: an uninstall racing us
        if (child_rc != ERROR_SUCCESS) {
            failed = true; // ERROR_ACCESS_DENIED above all
            continue;
        }
        Guard app_guard{ops, app_key};
        // Policy per value: see read_reg_string. Only InstallLocation accepts
        // REG_EXPAND_SZ; the four hashed fields and SystemComponent stay REG_SZ-only.
        auto read_str = [&](const char* value_name, bool accept_expand_sz) {
            return ops.read_str(app_key, value_name, accept_expand_sz);
        };

        auto display_name = read_str("DisplayName", false);
        if (display_name.empty())
            continue;
        // Meant to skip system components, but SystemComponent is a REG_DWORD and
        // read_reg_string accepts strings only, so this test never matches today
        // (tracked separately).
        if (read_str("SystemComponent", false) == "1")
            continue;

        AppInfo app;
        app.name = std::move(display_name);
        app.version = read_str("DisplayVersion", false);
        app.publisher = read_str("Publisher", false);
        app.install_date = read_str("InstallDate", false);
        app.install_location = read_str("InstallLocation", /*accept_expand_sz=*/true);
        apps.push_back(std::move(app));
    }
    return failed ? HiveRead::failed : HiveRead::ok;
}

// Run the roots in order; degraded when any root failed.
template <class Ops = RealRegOps>
WalkResult collect_uninstall_apps(std::span<const UninstallRoot> roots,
                                  const Ops& ops = Ops{}) {
    WalkResult out;
    for (std::size_t i = 0; i < roots.size(); ++i) {
        if (enumerate_uninstall_key(roots[i], out.apps, ops) == HiveRead::failed) {
            out.degraded = true;
            out.failed_roots.push_back(i);
        }
    }
    return out;
}

// The Windows `list_inventory` body (the plugin's do_list_inventory calls this
// with the real roots; a test calls it with scripted ops). Lives here so the
// degradation propagation -- walk.degraded -> rc 1 + typed status, no rows -- is
// ONE tested path rather than glue in an untestable action. `on_failed_root`
// receives each failed root's index (the caller logs; this header stays
// spdlog-free).
template <class Ctx, class Ops = RealRegOps, class OnFailedRoot>
int list_inventory(Ctx& ctx, std::span<const UninstallRoot> roots, const Ops& ops,
                   OnFailedRoot&& on_failed_root) {
    auto walk = collect_uninstall_apps(roots, ops);
    for (const auto i : walk.failed_roots)
        on_failed_root(i);
    parsers::dedupe_uninstall_records(walk.apps);
    std::vector<inventory::InvRecord> recs;
    recs.reserve(walk.apps.size());
    for (auto& app : walk.apps) {
        inventory::InvRecord r;
        r.name = std::move(app.name);
        r.version = std::move(app.version);
        r.publisher = std::move(app.publisher);
        r.install_date = std::move(app.install_date);
        r.kind = "app";
        r.ecosystem = "windows";
        // epoch/release/signature honest-empty: the Uninstall hive stores no
        // NEVRA and no signature. arch stays empty too -- inferring x64/x86
        // from which hive a key sat in would be synthesis, not storage.
        recs.push_back(std::move(r));
    }
    return parsers::emit_inventory(ctx, walk.degraded, recs, [](const inventory::InvRecord& r) {
        return yuzu::util::sanitize_utf8(inventory::format_inv_row(r));
    });
}

} // namespace yuzu::installed_apps::reg_walk

#endif // _WIN32
