/**
 * hardware_plugin.cpp — Hardware inventory plugin for Yuzu
 *
 * Actions:
 *   "manufacturer" — Returns the system manufacturer.
 *   "model"        — Returns the system model/product name.
 *   "bios"         — Returns BIOS/UEFI vendor, version, and release date.
 *   "processors"   — Lists installed CPUs with model, cores, threads, clock.
 *   "memory"       — Lists installed memory modules.
 *   "disks"        — Lists physical disk drives.
 *   "system"       — Serial number + system UUID (CMDB correlation key).
 *
 * Output is pipe-delimited, one field per line via write_output():
 *   key|value   (for scalar actions)
 *   key|field1|field2|...  (for list actions)
 */

#include <yuzu/plugin.hpp>

#include <cstdint>
#include <format>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <spdlog/spdlog.h>

#if defined(__linux__)
#include <filesystem>
#include <fstream>
#include <iterator>

#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess/probe_tool_path (Wave 3, ADR-3002)

#include "hardware_linux_parsers.hpp"
#endif

#if defined(__APPLE__)
#include <sys/sysctl.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include <nlohmann/json.hpp>

#include <yuzu/agent/scoped_cfref.hpp>
#include <yuzu/agent/scoped_ioobject.hpp>
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess (Wave 3, ADR-3002)

#include "hardware_disks_macos.hpp"
#include "hardware_macos_bios.hpp"
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wmi_bounded.hpp> // shared bounded WMI query helper (#3404 -- kills the old unbounded Next() enumerator wait; pulls in comdef.h/wbemidl.h)
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#endif

namespace {

// ── Linux: read a single-line sysfs/dmi file ──────────────────────────────

#ifdef __linux__
std::string read_dmi_file(const char* path) {
    std::ifstream f(path);
    if (!f)
        return {};
    std::string line;
    std::getline(f, line);
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
        line.pop_back();
    return line;
}
#endif

// ── macOS: native sysctlbyname / IOKit helpers ─────────────────────────────
// Wave 3 (#2380/ADR-3002 promotion): every plain `sysctl -n <name>` popen()
// call in this file becomes a direct sysctlbyname(3) (rung 1) — no shell,
// no child process. Two-call size-probe idiom per sysctlbyname(3)'s own man
// page (first call with a null buffer measures the required size).

#ifdef __APPLE__
std::string sysctl_string(const char* name) {
    std::size_t len = 0;
    if (sysctlbyname(name, nullptr, &len, nullptr, 0) != 0 || len == 0)
        return {};
    std::string buf(len, '\0');
    if (sysctlbyname(name, buf.data(), &len, nullptr, 0) != 0)
        return {};
    // Trim the trailing NUL(s) sysctlbyname includes in `len` for a
    // string-type sysctl.
    while (!buf.empty() && buf.back() == '\0')
        buf.pop_back();
    return buf;
}

template <typename T> std::optional<T> sysctl_value(const char* name) {
    T value{};
    std::size_t len = sizeof(value);
    if (sysctlbyname(name, &value, &len, nullptr, 0) != 0)
        return std::nullopt;
    return value;
}

// Reads a CFStringRef-typed IORegistry property off `entry` and converts it
// to UTF-8, following the size-then-copy CFStringGetCString idiom used by
// agents/shared/macos_console_user.hpp's console_user(). `prop` adopts
// IORegistryEntryCreateCFProperty's +1 Create-Rule reference via ScopedCFRef
// (scoped_cfref.hpp) so it is released on every return path, including the
// type-mismatch/early-return ones.
std::string io_registry_cf_string(io_object_t entry, CFStringRef key) {
    yuzu::agent::ScopedCFRef<CFTypeRef> prop(
        IORegistryEntryCreateCFProperty(entry, key, kCFAllocatorDefault, 0));
    if (!prop || CFGetTypeID(prop.get()) != CFStringGetTypeID())
        return {};
    auto str = static_cast<CFStringRef>(prop.get());
    CFIndex len = CFStringGetLength(str);
    if (len <= 0)
        return {};
    CFIndex max_size = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    std::string buf(static_cast<std::size_t>(max_size), '\0');
    if (!CFStringGetCString(str, buf.data(), max_size, kCFStringEncodingUTF8))
        return {};
    return std::string(buf.c_str());
}
#endif

// ── Windows: WMI helper class ─────────────────────────────────────────────

#ifdef _WIN32
// #3404: this plugin's own WMI enumeration now rides the shared bounded
// helper (agents/shared/wmi_bounded.hpp, PR3.3-a) instead of a private
// unbounded-wait enumerator loop -- a wedged/slow WMI provider used to hang
// this plugin indefinitely; every query below now bounds the per-Next wait,
// the whole enumeration, and the row count (BoundedQueryOptions defaults).
namespace wmi = yuzu::shared::wmi;

std::string wmi_row_string(const wmi::WmiRow& row, const char* key) {
    const auto it = row.find(key);
    return it == row.end() ? std::string{} : it->second;
}

uint32_t wmi_row_uint32(const wmi::WmiRow& row, const char* key) {
    const auto s = wmi_row_string(row, key);
    if (s.empty())
        return 0;
    try {
        return static_cast<uint32_t>(std::stoul(s));
    } catch (...) {
        return 0;
    }
}

uint64_t wmi_row_uint64(const wmi::WmiRow& row, const char* key) {
    const auto s = wmi_row_string(row, key);
    if (s.empty())
        return 0;
    try {
        return std::stoull(s);
    } catch (...) {
        return 0;
    }
}

// Run a bounded WQL query against ROOT\CIMV2 and invoke fn(row) once per
// result row. A connect/query/enumerate failure -- or a genuinely empty
// result set -- calls fn zero times, matching the removed private
// WmiQuery's behaviour (callers already treat "fn never ran" as their
// not-found case, e.g. an empty accumulator string or a zero row count).
//
// #3404 sentinel-row decision: several callers below (do_bios,
// do_processors, do_memory, do_disks) now track a `found`/`idx` flag across
// this call and emit an explicit "unknown"-valued row when it stays
// false/zero -- covering BOTH the connect/query failure case AND a
// genuinely empty (connected, zero-row) result. The pre-migration WmiQuery
// class only emitted that sentinel on a connect/query failure (`!wmi.valid()`);
// a connected-but-empty query silently emitted no row at all, because the
// per-row callback -- the only place those actions wrote output -- simply
// never ran. #3404's original acceptance bar called for byte-identical
// output across the migration, which this technically violates for that one
// case. This is a deliberate, reviewed divergence, not a missed edge case:
// an explicit "unknown" row tells a consumer the probe ran and found
// nothing, where the old silent-gap behaviour was indistinguishable from
// "this plugin action produced no output for an unrelated reason" (dispatch
// failure, truncation, etc). Do not "fix" this back to match the old
// silent-gap behaviour.
//
// Return value: true when BoundedQueryResult::truncated was set (the
// row_cap in agents/shared/wmi_bounded.hpp's BoundedQueryOptions, 512 rows
// by default, was reached before enumeration finished) -- false on a
// connect/query failure or a genuinely complete enumeration. This is a
// narrow signal, not a redesign of wmi_query's contract: every existing
// caller (do_manufacturer/do_model/do_bios/do_processors/do_memory/
// do_disks/do_system) still discards it exactly as before; only do_drivers
// below reads it, because it is the one action whose result set can
// realistically exceed the row cap on a host with many installed drivers.
template <typename Fn> bool wmi_query(const wchar_t* wql, Fn&& fn) {
    auto result = wmi::run_bounded_wmi_query(L"ROOT\\CIMV2", wql);
    if (result.error) {
        // gate-6 sre remediation: a connect/query/deadline failure was
        // previously indistinguishable from a genuinely-absent WMI class --
        // every caller emits the same "unknown" sentinel either way, with no
        // signal reaching the operator that this specific run hit
        // wmi::error_tokens::kWmiDeadlineExceeded (bounded-wait timeout) vs.
        // an ordinary "no such provider" outcome. wmi_plugin.cpp's own
        // actions surface result.error directly in their output; this
        // helper is a fire-and-forget accumulator instead (its callers embed
        // an "unknown" row, not an error token), so a log line is the only
        // place this can be observed.
        spdlog::warn("hardware: WMI query failed: {}", *result.error);
        return false;
    }
    for (const auto& row : result.rows)
        fn(row);
    return result.truncated;
}
#endif

// ── manufacturer action ───────────────────────────────────────────────────

int do_manufacturer(yuzu::CommandContext& ctx) {
#ifdef __linux__
    auto mfr = read_dmi_file("/sys/class/dmi/id/sys_vendor");
    ctx.write_output(std::format("manufacturer|{}", mfr.empty() ? "unknown" : mfr));

#elif defined(__APPLE__)
    auto mfr = sysctl_string("hw.manufacturer");
    // Apple hardware always says "Apple" but sysctl may not have this key
    ctx.write_output(std::format("manufacturer|{}", mfr.empty() ? "Apple Inc." : mfr));

#elif defined(_WIN32)
    std::string mfr;
    wmi_query(L"SELECT Manufacturer FROM Win32_ComputerSystem",
              [&](const wmi::WmiRow& row) { mfr = wmi_row_string(row, "Manufacturer"); });
    ctx.write_output(std::format("manufacturer|{}", mfr.empty() ? "unknown" : mfr));

#else
    ctx.write_output("manufacturer|unknown");
#endif
    return 0;
}

// ── model action ──────────────────────────────────────────────────────────

int do_model(yuzu::CommandContext& ctx) {
#ifdef __linux__
    auto model = read_dmi_file("/sys/class/dmi/id/product_name");
    ctx.write_output(std::format("model|{}", model.empty() ? "unknown" : model));

#elif defined(__APPLE__)
    auto model = sysctl_string("hw.model");
    ctx.write_output(std::format("model|{}", model.empty() ? "unknown" : model));

#elif defined(_WIN32)
    std::string model;
    wmi_query(L"SELECT Model FROM Win32_ComputerSystem",
              [&](const wmi::WmiRow& row) { model = wmi_row_string(row, "Model"); });
    ctx.write_output(std::format("model|{}", model.empty() ? "unknown" : model));

#else
    ctx.write_output("model|unknown");
#endif
    return 0;
}

// ── bios action ───────────────────────────────────────────────────────────

int do_bios(yuzu::CommandContext& ctx) {
#ifdef __linux__
    auto vendor = read_dmi_file("/sys/class/dmi/id/bios_vendor");
    auto version = read_dmi_file("/sys/class/dmi/id/bios_version");
    auto date = read_dmi_file("/sys/class/dmi/id/bios_date");
    ctx.write_output(std::format("bios_vendor|{}", vendor.empty() ? "unknown" : vendor));
    ctx.write_output(std::format("bios_version|{}", version.empty() ? "unknown" : version));
    ctx.write_output(std::format("bios_date|{}", date.empty() ? "unknown" : date));

#elif defined(__APPLE__)
    // macOS doesn't expose traditional BIOS; report boot ROM / system
    // firmware version. hardware/do_bios#1 — read-only, no operator input;
    // rung 2 (no public Boot-ROM/firmware-version API on macOS) via the
    // bounded runner instead of a raw popen (docs/agent-spawn-sink-manifest.md).
    auto res = yuzu::agent::run_bounded_subprocess(
        {"/usr/sbin/system_profiler", "SPHardwareDataType"},
        yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds(20)});
    // A killed-at-deadline or capacity-truncated capture can still have
    // tool_ran=true with partial/garbled text (SubprocessResult's own
    // contract: "callers MUST check timed_out before trusting ... output").
    // Treat either as no better than a failed run, same as tool_ran=false.
    if (!res.tool_ran || res.timed_out || res.output_truncated || res.exit_code != 0) {
        spdlog::warn("hardware: degraded shell-out (timed_out={}, tool_ran={}, truncated={}, "
                     "exit_code={}): {}",
                     res.timed_out, res.tool_ran, res.output_truncated, res.exit_code,
                     "/usr/sbin/system_profiler SPHardwareDataType");
    }
    auto rom = (res.tool_ran && !res.timed_out && !res.output_truncated && res.exit_code == 0)
                   ? yuzu::hardware::macos::parse_boot_rom_version(res.output)
                   : std::string{};
    ctx.write_output("bios_vendor|Apple");
    ctx.write_output(std::format("bios_version|{}", rom.empty() ? "unknown" : rom));
    ctx.write_output("bios_date|N/A");

#elif defined(_WIN32)
    bool found = false;
    wmi_query(L"SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS",
              [&](const wmi::WmiRow& row) {
                  found = true;
                  auto vendor = wmi_row_string(row, "Manufacturer");
                  auto version = wmi_row_string(row, "SMBIOSBIOSVersion");
                  auto date = wmi_row_string(row, "ReleaseDate");
                  // WMI date format: "20240315000000.000000+000" → extract YYYY-MM-DD
                  if (date.size() >= 8) {
                      date = date.substr(0, 4) + "-" + date.substr(4, 2) + "-" + date.substr(6, 2);
                  }
                  ctx.write_output(
                      std::format("bios_vendor|{}", vendor.empty() ? "unknown" : vendor));
                  ctx.write_output(
                      std::format("bios_version|{}", version.empty() ? "unknown" : version));
                  ctx.write_output(std::format("bios_date|{}", date.empty() ? "unknown" : date));
              });
    // Deliberate #3404 divergence from silent-gap-on-empty -- see wmi_query()'s
    // doc comment above.
    if (!found) {
        ctx.write_output("bios_vendor|unknown");
        ctx.write_output("bios_version|unknown");
        ctx.write_output("bios_date|unknown");
    }

#else
    ctx.write_output("bios_vendor|unknown");
    ctx.write_output("bios_version|unknown");
    ctx.write_output("bios_date|unknown");
#endif
    return 0;
}

// ── system action (serial number + system UUID) ────────────────────────────
//
// The hardware serial + SMBIOS/firmware UUID are the device's stable CMDB
// primary correlation key (e.g. for ServiceNow reconciliation). Both are
// machine-scope identifiers, no per-user data. Empty → the stable "unknown"
// sentinel so the daily-sync canonical hash does not flap when a value is
// genuinely absent (e.g. a VM with no SMBIOS serial).

int do_system(yuzu::CommandContext& ctx) {
#ifdef __linux__
    // /sys/class/dmi/id/product_serial and product_uuid are 0400 (root-owned). The
    // Linux agent runs as the UNPRIVILEGED `yuzu` account, not root — the default
    // install grants the binary cap_dac_read_search+eip (scripts/install-agent-user.sh),
    // which this in-process ifstream inherits in its effective set, so the read
    // succeeds. (A spawned child — e.g. dmidecode — would NOT inherit the effective
    // cap, so reading the file in-process is deliberate.) With --no-setcap, missing
    // libcap, or a dev/manual launch the read fails and both yield "unknown".
    auto serial = read_dmi_file("/sys/class/dmi/id/product_serial");
    auto uuid = read_dmi_file("/sys/class/dmi/id/product_uuid");
    ctx.write_output(std::format("serial|{}", serial.empty() ? "unknown" : serial));
    ctx.write_output(std::format("system_uuid|{}", uuid.empty() ? "unknown" : uuid));

#elif defined(__APPLE__)
    // Native IOKit read of the IOPlatformExpertDevice registry entry (rung 1)
    // instead of shelling out to `ioreg | awk`. ScopedIOObject/ScopedCFRef
    // (agents/core/include/yuzu/agent/scoped_{ioobject,cfref}.hpp) own the
    // Mach port / CF references so every return path releases them.
    std::string serial;
    std::string uuid;
    {
        yuzu::agent::ScopedIOObject expert(IOServiceGetMatchingService(
            kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice")));
        if (expert) {
            serial = io_registry_cf_string(expert.get(), CFSTR(kIOPlatformSerialNumberKey));
            uuid = io_registry_cf_string(expert.get(), CFSTR(kIOPlatformUUIDKey));
        }
    }
    ctx.write_output(std::format("serial|{}", serial.empty() ? "unknown" : serial));
    ctx.write_output(std::format("system_uuid|{}", uuid.empty() ? "unknown" : uuid));

#elif defined(_WIN32)
    std::string serial;
    std::string uuid;
    wmi_query(L"SELECT SerialNumber FROM Win32_BIOS", [&](const wmi::WmiRow& row) {
        serial = wmi_row_string(row, "SerialNumber");
    });
    wmi_query(L"SELECT UUID FROM Win32_ComputerSystemProduct",
              [&](const wmi::WmiRow& row) { uuid = wmi_row_string(row, "UUID"); });
    ctx.write_output(std::format("serial|{}", serial.empty() ? "unknown" : serial));
    ctx.write_output(std::format("system_uuid|{}", uuid.empty() ? "unknown" : uuid));

#else
    ctx.write_output("serial|unknown");
    ctx.write_output("system_uuid|unknown");
#endif
    return 0;
}

// ── processors action ─────────────────────────────────────────────────────

int do_processors(yuzu::CommandContext& ctx) {
#ifdef __linux__
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (!cpuinfo) {
        ctx.write_output("cpu|0|unknown|0|0|0");
        return 0;
    }
    // Collect unique physical CPUs
    struct CpuInfo {
        std::string model;
        int cores = 0;
        int threads = 0;
        double mhz = 0.0;
    };
    std::map<int, CpuInfo> cpus; // keyed by physical id
    int current_phys_id = 0;
    std::string line;
    while (std::getline(cpuinfo, line)) {
        if (line.starts_with("physical id")) {
            auto pos = line.find(':');
            if (pos != std::string::npos)
                current_phys_id = std::stoi(line.substr(pos + 1));
        } else if (line.starts_with("model name")) {
            auto pos = line.find(':');
            if (pos != std::string::npos) {
                auto val = line.substr(pos + 2);
                cpus[current_phys_id].model = val;
            }
        } else if (line.starts_with("cpu cores")) {
            auto pos = line.find(':');
            if (pos != std::string::npos)
                cpus[current_phys_id].cores = std::stoi(line.substr(pos + 1));
        } else if (line.starts_with("siblings")) {
            auto pos = line.find(':');
            if (pos != std::string::npos)
                cpus[current_phys_id].threads = std::stoi(line.substr(pos + 1));
        } else if (line.starts_with("cpu MHz")) {
            auto pos = line.find(':');
            if (pos != std::string::npos)
                cpus[current_phys_id].mhz = std::stod(line.substr(pos + 1));
        }
    }
    if (cpus.empty()) {
        ctx.write_output("cpu|0|unknown|0|0|0");
    } else {
        for (auto& [id, c] : cpus) {
            ctx.write_output(
                std::format("cpu|{}|{}|{}|{}|{:.0f}", id, c.model, c.cores, c.threads, c.mhz));
        }
    }

#elif defined(__APPLE__)
    auto brand = sysctl_string("machdep.cpu.brand_string");
    auto cores = sysctl_value<int32_t>("hw.physicalcpu").value_or(0);
    auto threads = sysctl_value<int32_t>("hw.logicalcpu").value_or(0);
    // hw.cpufrequency is absent on Apple Silicon (sysctlbyname fails ==
    // ENOENT), same as the prior `sysctl -n` invocation printing nothing --
    // mhz stays 0.0 in that case, matching the pre-Wave-3 fallback exactly.
    auto freq = sysctl_value<uint64_t>("hw.cpufrequency");
    double mhz = freq ? static_cast<double>(*freq) / 1e6 : 0.0;
    ctx.write_output(
        std::format("cpu|0|{}|{}|{}|{:.0f}", brand.empty() ? "unknown" : brand, cores, threads, mhz));

#elif defined(_WIN32)
    int idx = 0;
    wmi_query(L"SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed FROM "
              L"Win32_Processor",
              [&](const wmi::WmiRow& row) {
                  auto name = wmi_row_string(row, "Name");
                  auto cores = wmi_row_uint32(row, "NumberOfCores");
                  auto threads = wmi_row_uint32(row, "NumberOfLogicalProcessors");
                  auto mhz = wmi_row_uint32(row, "MaxClockSpeed");
                  ctx.write_output(
                      std::format("cpu|{}|{}|{}|{}|{}", idx++, name, cores, threads, mhz));
              });
    // Deliberate #3404 divergence from silent-gap-on-empty -- see wmi_query()'s
    // doc comment above.
    if (idx == 0)
        ctx.write_output("cpu|0|unknown|0|0|0");

#else
    ctx.write_output("cpu|0|unknown|0|0|0");
#endif
    return 0;
}

// ── memory action ─────────────────────────────────────────────────────────

int do_memory(yuzu::CommandContext& ctx) {
#ifdef __linux__
    // Try dmidecode first (needs root), fall back to /proc/meminfo.
    // hardware/do_memory#1 — dmidecode runs unprivileged here: it typically
    // fails EPERM/empty (docs/agent-spawn-sink-manifest.md), and the
    // existing EPERM->empty->/proc/meminfo fallback is preserved exactly
    // below. Rung 2 via the bounded runner instead of a raw popen; the text
    // parsing itself is now the pure, unit-tested
    // hardware_linux_parsers.hpp::parse_dmidecode_memory.
    auto dmidecode_path =
        yuzu::agent::probe_tool_path({"/usr/sbin/dmidecode", "/sbin/dmidecode"});
    std::vector<std::string> dimm_rows;
    if (!dmidecode_path.empty()) {
        auto res = yuzu::agent::run_bounded_subprocess(
            {dmidecode_path, "-t", "memory"},
            yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds(10)});
        // A deadline/truncation partway through dmidecode's per-DIMM block
        // stream can leave tool_ran=true over a partial device list -- treat
        // that the same as a failed run (falls through to /proc/meminfo)
        // rather than silently accepting a reduced RAM total.
        if (res.tool_ran && !res.timed_out && !res.output_truncated && res.exit_code == 0) {
            dimm_rows = yuzu::hardware::linuxutil::parse_dmidecode_memory(res.output);
        } else {
            spdlog::warn("hardware: degraded shell-out (timed_out={}, tool_ran={}, "
                         "truncated={}, exit_code={}): {} -t memory",
                         res.timed_out, res.tool_ran, res.output_truncated, res.exit_code,
                         dmidecode_path);
        }
    }
    if (!dimm_rows.empty()) {
        for (const auto& row : dimm_rows)
            ctx.write_output(row);
    } else {
        // Fallback: just report total memory from /proc/meminfo
        std::ifstream meminfo("/proc/meminfo");
        std::string line;
        while (std::getline(meminfo, line)) {
            if (line.starts_with("MemTotal:")) {
                auto pos = line.find_first_of("0123456789");
                if (pos != std::string::npos) {
                    auto kb = std::stoull(line.substr(pos));
                    ctx.write_output(std::format("dimm|total|{}|unknown|0", kb / 1024));
                }
                break;
            }
        }
    }

#elif defined(__APPLE__)
    auto mem = sysctl_value<uint64_t>("hw.memsize");
    if (mem) {
        ctx.write_output(std::format("dimm|total|{}|unknown|0", *mem / (1024 * 1024)));
    } else {
        ctx.write_output("dimm|total|unknown|unknown|0");
    }

#elif defined(_WIN32)
    bool found = false;
    wmi_query(L"SELECT DeviceLocator, Capacity, MemoryType, SMBIOSMemoryType, Speed FROM "
              L"Win32_PhysicalMemory",
              [&](const wmi::WmiRow& row) {
                  found = true;
                  auto slot = wmi_row_string(row, "DeviceLocator");
                  auto capacity = wmi_row_uint64(row, "Capacity");
                  auto speed = wmi_row_uint32(row, "Speed");
                  auto smbios_type = wmi_row_uint32(row, "SMBIOSMemoryType");
                  // SMBIOSMemoryType: 26=DDR4, 34=DDR5, 24=DDR3, 20=DDR2
                  const char* type_str = "unknown";
                  switch (smbios_type) {
                  case 20:
                      type_str = "DDR2";
                      break;
                  case 24:
                      type_str = "DDR3";
                      break;
                  case 26:
                      type_str = "DDR4";
                      break;
                  case 34:
                      type_str = "DDR5";
                      break;
                  }
                  auto size_mb = capacity / (1024 * 1024);
                  ctx.write_output(
                      std::format("dimm|{}|{}|{}|{}", slot, size_mb, type_str, speed));
              });
    // Deliberate #3404 divergence from silent-gap-on-empty -- see wmi_query()'s
    // doc comment above.
    if (!found)
        ctx.write_output("dimm|unknown|0|unknown|0");

#else
    ctx.write_output("dimm|unknown|0|unknown|0");
#endif
    return 0;
}

// ── disks action ──────────────────────────────────────────────────────────

int do_disks(yuzu::CommandContext& ctx) {
#ifdef __linux__
    // Native /sys/block walk instead of `lsblk -dno NAME,SIZE,TYPE,MODEL,
    // TRAN` (rung 1). The enumeration + every per-device file read below is
    // injected into hardware_linux_parsers.hpp::build_linux_disk_rows so the
    // row-building logic itself is unit-testable without a real sysfs tree.
    std::vector<std::string> names;
    try {
        std::error_code ec;
        for (const auto& entry :
             std::filesystem::directory_iterator("/sys/block", ec)) {
            if (ec)
                break;
            names.push_back(entry.path().filename().string());
        }
    } catch (const std::filesystem::filesystem_error&) {
        // A device disappeared mid-enumeration (rare sysfs TOCTOU) --
        // fall through with whatever was collected so far; empty falls
        // through to the sentinel row below.
    }
    auto read_file_fn = [](const std::string& path) -> std::string {
        std::ifstream f(path, std::ios::binary);
        if (!f)
            return {};
        return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    };
    auto read_link_fn = [](const std::string& path) -> std::string {
        std::error_code ec;
        auto target = std::filesystem::read_symlink(path, ec);
        return ec ? std::string{} : target.string();
    };
    auto rows = yuzu::hardware::linuxutil::build_linux_disk_rows(names, read_file_fn, read_link_fn);
    if (!rows.empty()) {
        for (const auto& row : rows)
            ctx.write_output(row);
    } else {
        ctx.write_output("disk|0|unknown|0|unknown|unknown");
    }

#elif defined(__APPLE__)
    // hardware/do_disks#1 — read-only, no operator input; rung 2 (no public
    // per-disk enumeration API covers NVMe+SATA+size+model in one call) via
    // the bounded runner instead of a raw popen
    // (docs/agent-spawn-sink-manifest.md). The JSON parser itself
    // (hardware_disks_macos.hpp) is UNCHANGED — only this acquisition call
    // site moved.
    auto res = yuzu::agent::run_bounded_subprocess(
        {"/usr/sbin/system_profiler", "SPStorageDataType", "SPNVMeDataType",
         "SPSerialATADataType", "-json"},
        yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds(20)});
    // A killed-at-deadline or truncated capture would almost always fail
    // JSON parsing anyway (macos_disk_rows_or_sentinel() already falls back
    // to the sentinel on any parse error), but reject it explicitly here
    // too rather than relying on that as the only safety net.
    if (!res.tool_ran || res.timed_out || res.output_truncated || res.exit_code != 0) {
        spdlog::warn("hardware: degraded shell-out (timed_out={}, tool_ran={}, truncated={}, "
                     "exit_code={}): {}",
                     res.timed_out, res.tool_ran, res.output_truncated, res.exit_code,
                     "/usr/sbin/system_profiler SPStorageDataType SPNVMeDataType "
                     "SPSerialATADataType -json");
    }
    auto sp_json = (res.tool_ran && !res.timed_out && !res.output_truncated &&
                    res.exit_code == 0)
                       ? res.output
                       : std::string{};
    for (const auto& row : yuzu::hardware::macos::macos_disk_rows_or_sentinel(sp_json)) {
        ctx.write_output(row);
    }

#elif defined(_WIN32)
    bool found = false;
    wmi_query(L"SELECT Index, Model, Size, MediaType, InterfaceType FROM Win32_DiskDrive",
              [&](const wmi::WmiRow& row) {
                  found = true;
                  auto idx = wmi_row_uint32(row, "Index");
                  auto model = wmi_row_string(row, "Model");
                  auto size = wmi_row_uint64(row, "Size");
                  auto media = wmi_row_string(row, "MediaType");
                  auto iface = wmi_row_string(row, "InterfaceType");
                  auto size_gb = size / (1024ULL * 1024 * 1024);
                  // Simplify media type
                  std::string type_str = "unknown";
                  if (media.find("SSD") != std::string::npos ||
                      media.find("Solid") != std::string::npos) {
                      type_str = "SSD";
                  } else if (media.find("Fixed") != std::string::npos ||
                             media.find("Hard") != std::string::npos) {
                      type_str = "HDD";
                  } else if (media.find("Removable") != std::string::npos) {
                      type_str = "Removable";
                  }
                  ctx.write_output(
                      std::format("disk|{}|{}|{}|{}|{}", idx, model, size_gb, type_str, iface));
              });
    // Deliberate #3404 divergence from silent-gap-on-empty -- see wmi_query()'s
    // doc comment above.
    if (!found)
        ctx.write_output("disk|0|unknown|0|unknown|unknown");

#else
    ctx.write_output("disk|0|unknown|0|unknown|unknown");
#endif
    return 0;
}

// ── drivers action ────────────────────────────────────────────────────────
// Installed driver inventory (BRD row 115 — docs/dex-brd-coverage.md D5).
// Windows: Win32_PnPSignedDriver (name, version, date, provider, class) — the
// canonical signed-driver registry; the query can take several seconds, which
// is fine for an on-demand/gathered question. Linux: loaded kernel modules
// via lsmod (no version/date without a per-module modinfo walk — left empty
// rather than guessed). Other platforms emit the house unknown row.

#ifdef _WIN32
// CIM_DATETIME "yyyymmddHHMMSS.mmmmmm±UUU" → "yyyy-mm-dd" ("" when malformed).
std::string cim_date_to_iso(const std::string& cim) {
    if (cim.size() < 8)
        return {};
    for (int i = 0; i < 8; ++i)
        if (cim[static_cast<std::size_t>(i)] < '0' || cim[static_cast<std::size_t>(i)] > '9')
            return {};
    return cim.substr(0, 4) + "-" + cim.substr(4, 2) + "-" + cim.substr(6, 2);
}
#endif

int do_drivers(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    int idx = 0;
    bool truncated =
        wmi_query(L"SELECT DeviceName, DriverVersion, DriverDate, DriverProviderName, "
                  L"DeviceClass FROM Win32_PnPSignedDriver WHERE DeviceName IS NOT NULL",
                  [&](const wmi::WmiRow& row) {
                      auto name = wmi_row_string(row, "DeviceName");
                      auto version = wmi_row_string(row, "DriverVersion");
                      auto date = cim_date_to_iso(wmi_row_string(row, "DriverDate"));
                      auto provider = wmi_row_string(row, "DriverProviderName");
                      auto dev_class = wmi_row_string(row, "DeviceClass");
                      ctx.write_output(std::format("driver|{}|{}|{}|{}|{}|{}", idx++, name,
                                                   version, date, provider, dev_class));
                  });
    // Deliberate #3404 divergence from silent-gap-on-empty -- see wmi_query()'s
    // doc comment above.
    if (idx == 0)
        ctx.write_output("driver|0|unknown||||");
    // wmi_query's row_cap (512, agents/shared/wmi_bounded.hpp) was reached --
    // the driver list above is incomplete. "__truncated__" in the name slot
    // mirrors the same hit-cap sentinel convention already used for a capped
    // list elsewhere in the agent (services_plugin.cpp's macOS do_list,
    // "svc|__truncated__|-|<total_seen>|-") -- it cannot collide with a real
    // DeviceName, and the reached count rides in the idx slot.
    else if (truncated)
        ctx.write_output(std::format("driver|{}|__truncated__||||", idx));

#elif defined(__linux__)
    // Read /proc/modules directly — it is the exact source lsmod pretty-prints,
    // so a shell-out (fork/exec + /bin/sh dependency) buys nothing. First
    // whitespace-separated field per line is the module name.
    std::ifstream modules("/proc/modules");
    int idx = 0;
    std::string line;
    while (std::getline(modules, line)) {
        std::istringstream ls(line);
        std::string module;
        ls >> module;
        if (!module.empty())
            ctx.write_output(std::format("driver|{}|{}|||kernel|module", idx++, module));
    }
    if (idx == 0)
        ctx.write_output("driver|0|unknown||||");

#else
    ctx.write_output("driver|0|unknown||||");
#endif
    return 0;
}

// ABI4 capability declarations (#2204). Windows reads WMI throughout — the
// ADR-3002 context section names this plugin's WMI usage as an existing
// rung-1 example ("Windows plugins live here (hardware/bitlocker/
// license_scan via WMI)"). Wave 3 (#2380/ADR-3002 promotion) moved Linux
// "disks" onto a native /sys/block walk (rung 1, was ungoverned rung-3
// `lsblk`) and "memory" onto the bounded runner (rung 2, was raw popen);
// macOS "manufacturer"/"model"/"processors"/"system" are now direct
// sysctlbyname(3)/IOKit calls (rung 1, were raw popen); macOS "bios"/"disks"
// still shell out (no public API answers either question) but now via the
// bounded runner (rung 2) instead of raw popen (rung 3). "drivers" remains
// unsupported on macOS (no public per-driver/kext enumeration API). "memory"
// stays CONSTRAINED on Linux/macOS: both return a value, but only the
// aggregate total, not full per-DIMM detail, without additional privilege /
// API surface.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "manufacturer",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "/sys/class/dmi/id/sys_vendor", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "sysctlbyname(hw.manufacturer)", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "WMI Win32_ComputerSystem.Manufacturer", nullptr},
    },
    {
        /* .action      = */ "model",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "/sys/class/dmi/id/product_name", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "sysctlbyname(hw.model)", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "WMI Win32_ComputerSystem.Model", nullptr},
    },
    {
        /* .action      = */ "bios",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "/sys/class/dmi/id/bios_vendor + bios_version + bios_date", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2,
         "run_bounded_subprocess(system_profiler SPHardwareDataType) + native parser "
         "(hardware_macos_bios.hpp)",
         nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "WMI Win32_BIOS", nullptr},
    },
    {
        /* .action      = */ "processors",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "/proc/cpuinfo", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "sysctlbyname(machdep.cpu.*, hw.*cpu*)", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "WMI Win32_Processor", nullptr},
    },
    {
        /* .action      = */ "memory",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 2, "run_bounded_subprocess(dmidecode -t memory)",
         "falls back to the aggregate MemTotal from /proc/meminfo (no per-DIMM detail) when "
         "dmidecode is unavailable or unprivileged"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "sysctlbyname(hw.memsize)",
         "aggregate total only, no per-DIMM breakdown (macOS has no public per-DIMM API)"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "WMI Win32_PhysicalMemory", nullptr},
    },
    {
        /* .action      = */ "disks",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "/sys/block/*/{size,device/model} native walk", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 2,
         "run_bounded_subprocess(system_profiler SPStorageDataType SPNVMeDataType "
         "SPSerialATADataType -json) + native parser (hardware_disks_macos.hpp)",
         nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "WMI Win32_DiskDrive", nullptr},
    },
    {
        /* .action      = */ "drivers",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "/proc/modules", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "WMI Win32_PnPSignedDriver", nullptr},
    },
    {
        /* .action      = */ "system",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "/sys/class/dmi/id/product_serial + product_uuid", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "IOServiceGetMatchingService(IOPlatformExpertDevice) + "
         "IORegistryEntryCreateCFProperty(kIOPlatformSerialNumberKey/kIOPlatformUUIDKey)",
         nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "WMI Win32_BIOS.SerialNumber + Win32_ComputerSystemProduct.UUID", nullptr},
    },
};

} // namespace

class HardwarePlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "hardware"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports hardware inventory: manufacturer, model, BIOS, CPU, memory, disks, "
               "drivers";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"manufacturer", "model",   "bios",   "processors", "memory",
                                     "disks",        "drivers", "system", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }

    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "manufacturer")
            return do_manufacturer(ctx);
        if (action == "model")
            return do_model(ctx);
        if (action == "bios")
            return do_bios(ctx);
        if (action == "processors")
            return do_processors(ctx);
        if (action == "memory")
            return do_memory(ctx);
        if (action == "disks")
            return do_disks(ctx);
        if (action == "drivers")
            return do_drivers(ctx);
        if (action == "system")
            return do_system(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(HardwarePlugin)
