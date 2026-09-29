/**
 * peripherals_win.cpp — Windows leg entry point.
 *
 * WAVE 2 (P91-4). SetupAPI walks the three bus_inventory kinds the
 * descriptor in peripherals_plugin.cpp already commits to:
 *
 *   usb          SetupDiGetClassDevsW(L"USB") + SPDRP_HARDWAREID /
 *                SPDRP_COMPATIBLEIDS -- bus_path is the device instance id,
 *                is_hub is a "USB\Class_09"/"..._HUB" substring test on the
 *                compatible ids (a hub's class usually comes through as a
 *                compatible id, never the primary hardware id) plus a
 *                ROOT_HUB hardware-id test for root hubs, which carry an
 *                empty compatible-ids list.
 *   pci          SetupDiGetClassDevsW(L"PCI") + SPDRP_HARDWAREID for
 *                VEN_/DEV_/CC_.
 *   thunderbolt  the same PCI walk, filtered to DEVICEDESC containing
 *                "Thunderbolt" or "USB4" (case-insensitive). SetupAPI's PCI
 *                enumerator only ever surfaces the host controller/bridge,
 *                never a downstream TB device, so every match is reported
 *                role host_controller -- see is_thunderbolt_desc's comment
 *                in peripherals_win_parsers.hpp.
 *
 * Every action is a READ: DevInfoSet owns the HDEVINFO handle from the
 * moment SetupDiGetClassDevsW returns (construct-then-check, never
 * check-then-construct, so a throwing allocation between the two can never
 * leak the handle) and releases it via SetupDiDestroyDeviceInfoList on
 * every exit path; copying a DevInfoSet is deleted so the handle can never
 * have two owners.
 */
#include "peripherals_legs.hpp"

#if defined(_WIN32)

#include "peripherals_win_parsers.hpp"

#include <win_str.hpp> // yuzu::win::from_wide (agents/shared)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <setupapi.h>

#pragma comment(lib, "setupapi.lib")

#include <cstdint>
#include <format>
#include <string>
#include <vector>

namespace yuzu::peripherals {

namespace {

// RAII owner for the HDEVINFO device-info set SetupDiGetClassDevsW returns.
// Deleted copy: the handle must never have two owners. Constructed directly
// from the raw SetupDiGetClassDevsW() result -- ownership is taken before
// any decision (including the validity check itself), so a handle the API
// did hand back is never at risk of leaking on an early return.
class DevInfoSet {
public:
    explicit DevInfoSet(HDEVINFO handle) noexcept : handle_(handle) {}
    DevInfoSet(const DevInfoSet&) = delete;
    DevInfoSet& operator=(const DevInfoSet&) = delete;
    DevInfoSet(DevInfoSet&&) = delete;
    DevInfoSet& operator=(DevInfoSet&&) = delete;
    ~DevInfoSet() {
        if (valid())
            ::SetupDiDestroyDeviceInfoList(handle_);
    }

    [[nodiscard]] bool valid() const noexcept { return handle_ != INVALID_HANDLE_VALUE; }
    [[nodiscard]] HDEVINFO get() const noexcept { return handle_; }

private:
    HDEVINFO handle_;
};

// One enumerated device's properties, already decoded to UTF-8/plain
// std::string via yuzu::win::from_wide -- the per-Kind callbacks in
// run_windows never touch a wchar_t.
struct WinDeviceInfo {
    std::string instance_id;
    std::vector<std::string> hardware_ids;
    std::vector<std::string> compatible_ids;
    std::string devicedesc;
    std::string friendlyname;
    std::string mfg;
};

[[nodiscard]] std::vector<std::wstring> split_multi_sz(const wchar_t* buf, DWORD chars) {
    std::vector<std::wstring> out;
    if (!buf)
        return out;
    std::size_t i = 0;
    while (i < chars && buf[i] != L'\0') {
        const std::size_t start = i;
        while (i < chars && buf[i] != L'\0')
            ++i;
        out.emplace_back(buf + start, i - start);
        ++i; // skip the field's terminating NUL
    }
    return out;
}

// SPDRP_HARDWAREID / SPDRP_COMPATIBLEIDS are REG_MULTI_SZ: a run of
// NUL-terminated strings ending in a second NUL. Two-call idiom: size first
// (required set from the failing null-buffer call), then read.
[[nodiscard]] std::vector<std::wstring> get_multi_sz_property(HDEVINFO devs,
                                                               SP_DEVINFO_DATA& data,
                                                               DWORD property) {
    DWORD required = 0;
    ::SetupDiGetDeviceRegistryPropertyW(devs, &data, property, nullptr, nullptr, 0, &required);
    if (required < sizeof(wchar_t))
        return {};
    std::vector<wchar_t> buf(required / sizeof(wchar_t) + 1, L'\0');
    DWORD data_type = 0;
    if (!::SetupDiGetDeviceRegistryPropertyW(
            devs, &data, property, &data_type, reinterpret_cast<PBYTE>(buf.data()),
            static_cast<DWORD>(buf.size() * sizeof(wchar_t)), nullptr))
        return {};
    return split_multi_sz(buf.data(), static_cast<DWORD>(buf.size()));
}

// SPDRP_DEVICEDESC / SPDRP_FRIENDLYNAME / SPDRP_MFG are REG_SZ. Same
// two-call idiom; empty (not an error) when the device carries no value for
// this property -- SPDRP_FRIENDLYNAME in particular is frequently absent.
[[nodiscard]] std::string get_string_property(HDEVINFO devs, SP_DEVINFO_DATA& data,
                                              DWORD property) {
    DWORD required = 0;
    ::SetupDiGetDeviceRegistryPropertyW(devs, &data, property, nullptr, nullptr, 0, &required);
    if (required < sizeof(wchar_t))
        return {};
    std::vector<wchar_t> buf(required / sizeof(wchar_t) + 1, L'\0');
    DWORD data_type = 0;
    if (!::SetupDiGetDeviceRegistryPropertyW(
            devs, &data, property, &data_type, reinterpret_cast<PBYTE>(buf.data()),
            static_cast<DWORD>(buf.size() * sizeof(wchar_t)), nullptr))
        return {};
    return yuzu::win::from_wide(buf.data());
}

[[nodiscard]] std::string get_instance_id(HDEVINFO devs, SP_DEVINFO_DATA& data) {
    DWORD required = 0;
    ::SetupDiGetDeviceInstanceIdW(devs, &data, nullptr, 0, &required);
    if (required == 0)
        return {};
    std::wstring buf(required, L'\0');
    if (!::SetupDiGetDeviceInstanceIdW(devs, &data, buf.data(), required, nullptr))
        return {};
    return yuzu::win::from_wide(buf.c_str());
}

// Walks every present device under `enumerator` (e.g. L"USB", L"PCI"),
// invoking `cb` once per device with its already-decoded properties.
// Returns false only when SetupDiGetClassDevsW itself failed -- the caller
// reports that as windows:setupapi:getclassdevs_failed with GetLastError()
// in the reason; a walk that enumerates zero devices still returns true
// (an empty result is not a failure -- see mark_result_read).
template <class Fn>
[[nodiscard]] bool for_each_device(const wchar_t* enumerator, Fn&& cb) {
    // Ownership taken from the raw handle before any decision: DevInfoSet's
    // dtor runs even if a throwing allocation inside the loop below unwinds
    // through this scope.
    DevInfoSet devs{::SetupDiGetClassDevsW(nullptr, enumerator, nullptr,
                                           DIGCF_PRESENT | DIGCF_ALLCLASSES)};
    if (!devs.valid())
        return false;

    SP_DEVINFO_DATA data{};
    data.cbSize = sizeof(data);
    for (DWORD i = 0; ::SetupDiEnumDeviceInfo(devs.get(), i, &data); ++i) {
        WinDeviceInfo info;
        info.instance_id = get_instance_id(devs.get(), data);
        for (const auto& w : get_multi_sz_property(devs.get(), data, SPDRP_HARDWAREID))
            info.hardware_ids.push_back(yuzu::win::from_wide(w.c_str()));
        for (const auto& w : get_multi_sz_property(devs.get(), data, SPDRP_COMPATIBLEIDS))
            info.compatible_ids.push_back(yuzu::win::from_wide(w.c_str()));
        info.devicedesc = get_string_property(devs.get(), data, SPDRP_DEVICEDESC);
        info.friendlyname = get_string_property(devs.get(), data, SPDRP_FRIENDLYNAME);
        info.mfg = get_string_property(devs.get(), data, SPDRP_MFG);
        cb(info);
        data.cbSize = sizeof(data); // SetupDiEnumDeviceInfo may touch it; reset for the next call
    }
    return true;
}

void emit_usb_row(yuzu::CommandContext& ctx, const WinDeviceInfo& info) {
    std::uint16_t vendor_id = 0, product_id = 0;
    for (const auto& hwid : info.hardware_ids) {
        if (const auto ids = win::parse_usb_hardware_id(hwid)) {
            vendor_id = ids->vendor_id;
            product_id = ids->product_id;
            break;
        }
    }
    std::uint8_t usb_class = 0, subclass = 0;
    // A root hub carries a ROOT_HUB hardware id but ships an EMPTY
    // compatible-ids list (real capture:
    // tests/unit/fixtures/wave9/peripherals/windows/setupapi_usb.txt:7) --
    // the Class_09 compatible-id test below never fires for it. A non-root
    // generic hub reports no Class_09 compatible id either; its
    // compatible-ids instead carry a single literal "USB\{USB20,USB30}_HUB"
    // token (same fixture, lines 8/14/22) -- a "_HUB" suffix match on
    // compatible ids covers that shape too.
    bool is_hub = false;
    for (const auto& hwid : info.hardware_ids)
        if (hwid.find("ROOT_HUB") != std::string::npos)
            is_hub = true;
    for (const auto& cid : info.compatible_ids) {
        if (!is_hub &&
            (cid.find("USB\\Class_09") != std::string::npos || cid.find("_HUB") != std::string::npos))
            is_hub = true;
        if (usb_class == 0 && subclass == 0) {
            if (const auto cls = win::parse_usb_compatible_class(cid)) {
                usb_class = cls->usb_class;
                subclass = cls->subclass;
            }
        }
    }
    const std::string& product = !info.friendlyname.empty() ? info.friendlyname : info.devicedesc;
    ctx.write_output(format_usb_row(info.instance_id, vendor_id, product_id, usb_class, subclass,
                                    info.mfg, product, "-", "-", is_hub));
}

// Shared by pci and thunderbolt: both walk L"PCI" and format the same row
// shape from the same property set; only the emit predicate/role differ.
void emit_pci_row(yuzu::CommandContext& ctx, const WinDeviceInfo& info) {
    std::uint16_t vendor_id = 0, device_id = 0;
    std::uint32_t class_code = 0;
    for (const auto& hwid : info.hardware_ids) {
        if (vendor_id == 0 && device_id == 0) {
            if (const auto ids = win::parse_pci_hardware_id(hwid)) {
                vendor_id = ids->vendor_id;
                device_id = ids->device_id;
            }
        }
        if (class_code == 0) {
            if (const auto cc = win::parse_pci_class_code(hwid))
                class_code = *cc;
        }
    }
    // Subsystem vendor/device and bound driver name are not sourced by this
    // package -- SPDRP_HARDWAREID's SUBSYS_ token and a driver-key lookup
    // are out of Wave-2 scope; "0000"/"-" mark them honestly unfilled.
    ctx.write_output(format_pci_row(info.instance_id, vendor_id, device_id, class_code, 0, 0, "-",
                                    info.devicedesc));
}

// Caller has already applied is_thunderbolt_desc as the walk predicate.
void emit_thunderbolt_row(yuzu::CommandContext& ctx, const WinDeviceInfo& info) {
    ctx.write_output(format_thunderbolt_row(info.instance_id, ThunderboltRole::HostController,
                                            info.mfg, "-", "-", "-", "-"));
}

} // namespace

int run_windows(yuzu::CommandContext& ctx, Kind k) {
    std::size_t rows = 0;
    bool ok = false;
    switch (k) {
    case Kind::usb:
        ok = for_each_device(L"USB", [&](const WinDeviceInfo& info) {
            emit_usb_row(ctx, info);
            ++rows;
        });
        break;
    case Kind::pci:
        ok = for_each_device(L"PCI", [&](const WinDeviceInfo& info) {
            emit_pci_row(ctx, info);
            ++rows;
        });
        break;
    case Kind::thunderbolt:
        ok = for_each_device(L"PCI", [&](const WinDeviceInfo& info) {
            if (win::is_thunderbolt_desc(info.devicedesc)) {
                emit_thunderbolt_row(ctx, info);
                ++rows;
            }
        });
        break;
    }

    if (!ok) {
        // mark_result_read's single failure_token doubles as the row's
        // provenance field AND set_result_status's reason -- there is no
        // separate slot for a human sentence, so GetLastError() is appended
        // to the "<os>:<source>:<detail>" token itself (still that shape,
        // just with a runtime detail rather than a fixed one).
        mark_result_read(ctx, k, 0,
                         std::format("windows:setupapi:getclassdevs_failed:{}", ::GetLastError()));
        return 0;
    }
    mark_result_read(ctx, k, rows, std::nullopt);
    return 0;
}

} // namespace yuzu::peripherals

#endif // defined(_WIN32)
