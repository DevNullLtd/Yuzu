/**
 * virtualization_win.cpp -- Windows leg: CPUID hypervisor leaves and the SMBIOS System
 * Information table.
 *
 * Only the Windows shell lives here: __cpuid/__cpuidex and the RSMB firmware-table read. Every
 * decision (leaf-discovery gating, the root-partition bit, SMBIOS precedence, the walk-fault
 * mapping, bare_metal vs unknown) is in virtualization_parsers.hpp and is unit-tested on every
 * host. A Windows machine running Hyper-V, VBS or WSL2 sets the hypervisor bit yet is the HOST;
 * the root-partition bit (CreatePartitions) tells them apart. Container membership is not read:
 * the row is `unknown` with `windows:virtualization:container:not_read`.
 */
#include "virtualization_legs.hpp"

#if defined(_WIN32)

#include <win_rsmb.hpp> // defines WIN32_LEAN_AND_MEAN / NOMINMAX and includes windows.h

#include <intrin.h>

namespace yuzu::virtualization {

namespace {

CpuidFacts read_cpuid() {
#if defined(_M_X64) || defined(_M_IX86)
    return cpuid_facts([](std::uint32_t leaf) {
        int r[4] = {0, 0, 0, 0};
        __cpuidex(r, static_cast<int>(leaf), 0);
        return CpuidRegs{static_cast<std::uint32_t>(r[0]), static_cast<std::uint32_t>(r[1]),
                         static_cast<std::uint32_t>(r[2]), static_cast<std::uint32_t>(r[3])};
    });
#else
    return CpuidFacts{}; // ARM64: no CPUID
#endif
}

SmbiosFacts read_smbios() {
    namespace rsmb = yuzu::shared::rsmb;
    const rsmb::RsmbRead read = rsmb::read_rsmb_table();
    switch (read.error) {
    case rsmb::ReadError::none:
        return smbios_facts_from_table(yuzu::shared::smbios::parse_rsmb(read.bytes));
    case rsmb::ReadError::call_failed:
        return smbios_read_failure("call_failed");
    case rsmb::ReadError::oversized:
        return smbios_read_failure("oversized");
    case rsmb::ReadError::size_race:
        return smbios_read_failure("size_race");
    }
    return smbios_read_failure("call_failed");
}

} // namespace

int run_windows(yuzu::CommandContext& ctx) {
    Facts f;
    f.os = "windows";
    f.cpuid = read_cpuid();
    f.smbios = read_smbios();
    f.container.mode = ContainerInputs::Mode::windows_not_read;
    report_host(ctx, decide(f));
    return 0;
}

} // namespace yuzu::virtualization

#endif // defined(_WIN32)
