/**
 * win_rsmb.hpp -- reads the raw SMBIOS table Windows exposes as the 'RSMB' firmware table.
 *
 * Hoisted from firmware_posture_win.cpp (H.5) so the hardware plugin and firmware_posture share
 * ONE probe/fill/retry loop (roadmap R10: no fork). The decoding is NOT here: the bytes go to
 * yuzu::shared::smbios::parse_rsmb (smbios_parsers.hpp), and each caller keeps its own mapping of
 * a failure onto its own report -- this header returns bytes or an error and nothing else.
 *
 * Windows-only by construction (#ifdef _WIN32); the header is empty elsewhere. All-inline, so
 * every plugin compiles its own private copy (the build-isolation rationale of win_str.hpp).
 *
 * BOUNDEDNESS (roadmap Principle 14). GetSystemFirmwareTable has no deadline parameter, and the
 * daily sync thread has no per-action deadline either, so the reason this call is acceptable
 * there must be on the record. For the 'RSMB' provider the kernel returns a copy of the SMBIOS
 * table the firmware handed over at boot, which it already holds in memory: the call does no
 * device I/O, takes no driver round trip and waits on nothing a wedged device could hold. That is
 * the difference from the synchronous DeviceIoControl volume reads (tracked in #3925, and withheld
 * by the device-record writer as `agent:windows_volumes_unbounded`), which can block indefinitely
 * on a stalled VSS or storage provider. This is the documented behaviour of the provider and the
 * precedent firmware_posture has shipped on; it has NOT been measured under a stalled provider.
 * The size is capped (kMaxRsmbBytes) and the probe/fill retry is bounded (kMaxRsmbAttempts), so
 * the call count and the allocation are bounded too. If a measurement ever shows this call
 * blocking, the fix is bounded_wait.hpp here, in one place.
 */
#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace yuzu::shared::rsmb {

/// 'RSMB' as the little-endian DWORD GetSystemFirmwareTable takes (a multi-character literal is
/// implementation-defined, so spell the value).
inline constexpr DWORD kRsmbProvider = 0x52534D42;

/// A real RawSMBIOSData table is tens of KiB; refuse anything an order of magnitude past that
/// rather than allocate whatever a broken provider claims.
inline constexpr std::size_t kMaxRsmbBytes = 1u << 20; // 1 MiB

/// The table can change size between the probe and the fill (a hot-plug SMBIOS update). The pair
/// is retried this many times, then reported as a size race.
inline constexpr int kMaxRsmbAttempts = 3;

enum class ReadError {
    none,
    call_failed, ///< GetSystemFirmwareTable returned 0; `win32_error` is GetLastError()
    oversized,   ///< the probe asked for more than kMaxRsmbBytes
    size_race,   ///< the table kept growing between probe and fill for every attempt
};

struct RsmbRead {
    std::vector<std::uint8_t> bytes; ///< the RawSMBIOSData buffer; empty unless error == none
    ReadError error = ReadError::none;
    std::uint32_t win32_error = 0; ///< meaningful only for ReadError::call_failed

    [[nodiscard]] bool ok() const noexcept { return error == ReadError::none; }
};

[[nodiscard]] inline RsmbRead read_rsmb_table() {
    RsmbRead out;
    for (int attempt = 0; attempt < kMaxRsmbAttempts; ++attempt) {
        // Size probe (buffer NULL, size 0 -> the required byte count, or 0 with GetLastError set).
        const UINT need = ::GetSystemFirmwareTable(kRsmbProvider, 0, nullptr, 0);
        if (need == 0) {
            out.error = ReadError::call_failed;
            out.win32_error = static_cast<std::uint32_t>(::GetLastError());
            return out;
        }
        if (need > kMaxRsmbBytes) {
            out.error = ReadError::oversized;
            return out;
        }

        std::vector<std::uint8_t> table(need, 0);
        // The fill returns the bytes written, or the (larger) required size if the table grew
        // since the probe, or 0 on failure.
        const UINT got = ::GetSystemFirmwareTable(kRsmbProvider, 0, table.data(), need);
        if (got == 0) {
            out.error = ReadError::call_failed;
            out.win32_error = static_cast<std::uint32_t>(::GetLastError());
            return out;
        }
        if (got > need)
            continue; // grew between the two calls: probe again
        table.resize(got);
        out.bytes = std::move(table);
        return out;
    }
    out.error = ReadError::size_race;
    return out;
}

} // namespace yuzu::shared::rsmb

#endif // _WIN32
