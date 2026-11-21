/**
 * middleware_win.cpp -- Windows leg entry point and the real registry calls.
 *
 * The leg is the table's registry leg (agents/shared/middleware_products.hpp): `run_windows` runs the
 * generic `run_reg_leg` (middleware_runner.hpp) over `win::WinRegFs<RealRegOps>`. WinRegFs is the pure
 * half (middleware_win_parsers.hpp: dual-view merge, outcome mapping, entries budget, unit-tested on
 * every OS over a fake); this TU only holds RealRegOps, the injected boundary that talks to the
 * registry:
 *
 *   - HKEY_LOCAL_MACHINE only, opened KEY_READ-style (KEY_ENUMERATE_SUB_KEYS / KEY_QUERY_VALUE) with
 *     KEY_WOW64_64KEY or KEY_WOW64_32KEY. Never HKCU, never a loaded user hive.
 *   - Reg*W only, strings decoded with yuzu::win::reg_sz_to_utf8; only REG_SZ and REG_EXPAND_SZ are
 *     text (decide_value), and a REG_EXPAND_SZ is NOT expanded.
 *   - ERROR_FILE_NOT_FOUND is `absent`, ERROR_ACCESS_DENIED is `denied`, anything else is `failed`.
 *   - no file read, no directory listing, no subprocess and no product binary.
 *
 * A leg with no probes (PLANNED in the table) answers `status|<action>|unsupported|windows:planned`.
 * The body is compiled on _WIN32 only (empty elsewhere), so braga cannot compile it: the first
 * compile of this TU is the Windows leg of the build matrix.
 */
#include "middleware_legs.hpp"
#include "middleware_win_parsers.hpp"

#if defined(_WIN32)

#include <win_reg_handle.hpp> // yuzu::win::RegKey (RAII HKEY)
#include <win_str.hpp>        // yuzu::win::to_wide, from_wide, reg_sz_to_utf8

#include <spdlog/spdlog.h>

#include <string>
#include <string_view>

namespace yuzu::middleware::win {

namespace {

[[nodiscard]] RegStatus status_of(LSTATUS rc) noexcept {
    if (rc == ERROR_SUCCESS)
        return RegStatus::ok;
    if (rc == ERROR_FILE_NOT_FOUND)
        return RegStatus::absent;
    if (rc == ERROR_ACCESS_DENIED)
        return RegStatus::denied;
    return RegStatus::failed;
}

[[nodiscard]] REGSAM view_flag(RegView v) noexcept {
    return v == RegView::v64 ? KEY_WOW64_64KEY : KEY_WOW64_32KEY;
}

} // namespace

/// The real registry boundary of WinRegFs: HKLM, one view per call.
struct RealRegOps {
    RegListing list_subkeys(RegView view, std::string_view key, std::size_t max) {
        RegListing out;
        yuzu::win::RegKey h;
        const std::wstring wkey = yuzu::win::to_wide(key);
        const LSTATUS open_rc =
            RegOpenKeyExW(HKEY_LOCAL_MACHINE, wkey.c_str(), 0,
                          KEY_ENUMERATE_SUB_KEYS | view_flag(view), h.put());
        out.status = status_of(open_rc);
        if (out.status != RegStatus::ok)
            return out;
        for (DWORD idx = 0;; ++idx) {
            wchar_t name[256]; // a registry key name is at most 255 characters
            DWORD len = 256;
            const LSTATUS rc =
                RegEnumKeyExW(h.get(), idx, name, &len, nullptr, nullptr, nullptr, nullptr);
            if (rc == ERROR_NO_MORE_ITEMS)
                break;
            if (out.names.size() >= max) {
                out.truncated = true; // one more entry exists (or could not be told apart)
                break;
            }
            if (rc != ERROR_SUCCESS) {
                out.names.clear();
                out.status = status_of(rc) == RegStatus::denied ? RegStatus::denied
                                                                  : RegStatus::failed;
                return out;
            }
            out.names.push_back(yuzu::win::from_wide(name, static_cast<int>(len)));
        }
        return out;
    }

    RegText read_sz(RegView view, std::string_view key, std::string_view value, std::size_t cap) {
        RegText out;
        yuzu::win::RegKey h;
        const std::wstring wkey = yuzu::win::to_wide(key);
        out.status = status_of(RegOpenKeyExW(HKEY_LOCAL_MACHINE, wkey.c_str(), 0,
                                             KEY_QUERY_VALUE | view_flag(view), h.put()));
        if (out.status != RegStatus::ok)
            return out;
        const std::wstring wvalue = yuzu::win::to_wide(value);
        DWORD type = 0;
        DWORD size = 0;
        out.status = status_of(
            RegQueryValueExW(h.get(), wvalue.c_str(), nullptr, &type, nullptr, &size));
        if (out.status != RegStatus::ok)
            return out;
        const RegValueKind kind = type == REG_SZ          ? RegValueKind::sz
                                  : type == REG_EXPAND_SZ ? RegValueKind::expand_sz
                                                          : RegValueKind::other;
        out.status = decide_value(kind, size, cap);
        if (out.status != RegStatus::ok)
            return out;
        std::wstring buf(size / sizeof(wchar_t) + 1, L'\0');
        DWORD got = size;
        const LSTATUS rc = RegQueryValueExW(h.get(), wvalue.c_str(), nullptr, &type,
                                            reinterpret_cast<LPBYTE>(buf.data()), &got);
        if (rc != ERROR_SUCCESS) { // grew between the two reads (ERROR_MORE_DATA) or vanished
            out.status = status_of(rc) == RegStatus::denied ? RegStatus::denied : RegStatus::failed;
            return out;
        }
        out.text = yuzu::win::reg_sz_to_utf8(buf.c_str(), got);
        return out;
    }
};

static_assert(RegOps<RealRegOps>);

} // namespace yuzu::middleware::win

namespace yuzu::middleware {

int run_windows(yuzu::CommandContext& ctx, const Product& p) {
    if (p.windows.probes.empty()) {
        emit_planned(ctx, p, "windows:planned");
        return 0;
    }
    yuzu::shared::ConstraintAccumulator acc;
    auto budget = make_row_budget();
    win::WinRegFs<win::RealRegOps> fs{win::RealRegOps{}};
    const auto rows = run_reg_leg(
        p, p.windows, fs, acc, budget,
        [](std::string_view product, std::string_view probe, ItemReason reason,
           std::string_view item) {
            spdlog::info("middleware {}: {}: {} ({})", product, probe, item_reason_name(reason),
                         yuzu::util::safe_output_field(item));
        });
    emit_read(ctx, p, rows, acc);
    return 0;
}

} // namespace yuzu::middleware

#endif // defined(_WIN32)
