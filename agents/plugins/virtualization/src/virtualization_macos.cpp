/**
 * virtualization_macos.cpp -- macOS leg: sysctl kern.hv_vmm_present and hw.model.
 *
 * No CPUID on arm64; kern.hv_vmm_present is the readable negative (or positive) signal and
 * hw.model is the hardware identity (a `VirtualMac*` model names Apple's Virtualization
 * framework). The decisions are in virtualization_parsers.hpp; this TU only reads.
 *
 * ponytail: private sysctl helpers. hardware_plugin.cpp, os_info_plugin.cpp and
 * system_hardening_macos.cpp each carry their own copy too; a shared header would touch all
 * three plugins' sources and READMEs. These return std::optional so a failed read is never
 * conflated with an empty value.
 */
#include "virtualization_legs.hpp"

#if defined(__APPLE__)

#include <sys/sysctl.h>

#include <optional>
#include <string>

namespace yuzu::virtualization {

namespace {

std::optional<int> sysctl_int(const char* name) {
    int v = 0;
    std::size_t len = sizeof(v);
    if (sysctlbyname(name, &v, &len, nullptr, 0) != 0)
        return std::nullopt;
    return v;
}

std::optional<std::string> sysctl_string(const char* name) {
    std::size_t len = 0;
    if (sysctlbyname(name, nullptr, &len, nullptr, 0) != 0)
        return std::nullopt;
    std::string buf(len, '\0');
    if (len != 0 && sysctlbyname(name, buf.data(), &len, nullptr, 0) != 0)
        return std::nullopt;
    while (!buf.empty() && buf.back() == '\0')
        buf.pop_back();
    return buf;
}

} // namespace

int run_macos(yuzu::CommandContext& ctx) {
    Facts f;
    f.os = "macos";
    // CPUID stays unavailable: the sysctl is the negative signal.

    const auto vmm = sysctl_int("kern.hv_vmm_present");
    f.hint.source = "sysctl";
    if (vmm)
        f.hint.os_says_virtual = (*vmm != 0);
    else
        f.failures.push_back("macos:virtualization:hv_vmm_present:unreadable");

    const auto model = sysctl_string("hw.model");
    if (model) {
        f.smbios.state = ReadState::ok;
        f.smbios.manufacturer = "Apple Inc.";
        f.smbios.product = *model;
    } else {
        f.smbios.state = ReadState::unreadable;
        f.smbios.reason = "macos:virtualization:hw_model:unreadable";
    }

    f.container.mode = ContainerInputs::Mode::macos_none;
    report_host(ctx, decide(f));
    return 0;
}

} // namespace yuzu::virtualization

#endif // defined(__APPLE__)
