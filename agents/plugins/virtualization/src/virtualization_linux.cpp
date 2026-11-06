/**
 * virtualization_linux.cpp -- Linux leg: virtualization facts from CPUID, DMI, sysfs and procfs.
 *
 * Only the POSIX boundary lives here: bounded reads and access(2) fill a LinuxReads, and
 * linux_facts (virtualization_parsers.hpp) turns them into Facts, tokens included. Every decision
 * (the vendor tables, the root-partition gate, the precedence, bare_metal vs unknown, the
 * container verdict) is in that header too. Reads go through posix_secure_read (bounded, regular
 * files only); ENOENT is "absent" and any other failure is an unreadable source. The container
 * check reads the AGENT's own /proc/self/cgroup, not PID 1's, which answers a different question
 * when the PID namespace is shared.
 */
#include "virtualization_legs.hpp"

#if defined(__linux__)

#include <posix_secure_read.hpp>

#include <unistd.h>

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

#include <cerrno>
#include <string>
#include <utility>

namespace yuzu::virtualization {

namespace {

constexpr size_t kSmallCap = 4096;
constexpr size_t kCpuinfoCap = 2 * 1024 * 1024;
constexpr size_t kCgroupCap = 64 * 1024;

CpuidFacts read_cpuid() {
#if defined(__x86_64__) || defined(__i386__)
    if (__get_cpuid_max(0, nullptr) >= 1) {
        return cpuid_facts([](std::uint32_t leaf) {
            unsigned a = 0, b = 0, c = 0, d = 0;
            __cpuid_count(leaf, 0, a, b, c, d);
            return CpuidRegs{a, b, c, d};
        });
    }
#endif
    return CpuidFacts{}; // available = false
}

/// One bounded read mapped to the ok / absent / unreadable trichotomy; the cause segment is
/// all linux_facts needs to build the token. posix_secure_read's types stop here.
FieldRead read_source(const char* path, size_t cap) {
    FieldRead r;
    const auto fr = yuzu::shared::read_file(path, cap, yuzu::shared::Leaf::follow);
    if (fr.ok()) {
        r.state = ReadState::ok;
        r.value = fr.data;
        return r;
    }
    switch (fr.error) {
    case yuzu::shared::ReadError::not_regular:
        r.cause = "not_regular";
        break;
    case yuzu::shared::ReadError::oversized:
        r.cause = "oversized";
        break;
    default:
        if (fr.err == ENOENT)
            return r; // absent
        r.cause = errno_token(fr.err);
        break;
    }
    r.state = ReadState::unreadable;
    return r;
}

/// access(2) as an errno: 0 present, ENOENT absent, anything else a failed probe.
int probe(const char* path) { return ::access(path, F_OK) == 0 ? 0 : errno; }

} // namespace

int run_linux(yuzu::CommandContext& ctx) {
    CpuidFacts cpuid = read_cpuid();
    LinuxReads r;
    r.sys_vendor = read_source("/sys/class/dmi/id/sys_vendor", kSmallCap);
    r.product_name = read_source("/sys/class/dmi/id/product_name", kSmallCap);
    r.hypervisor_type = read_source("/sys/hypervisor/type", kSmallCap);
    // ponytail: the cpuinfo `hypervisor` flag is CPUID leaf 1 ECX bit 31, which read_cpuid already
    // read, so on x86 the file adds nothing and an oversized one (> ~1,300 logical CPUs) would only
    // block bare_metal; it is read only when CPUID is unavailable (ARM has no `flags` line either,
    // so today it contributes on neither architecture). Drop the source in a follow-up.
    if (!cpuid.available)
        r.cpuinfo = read_source("/proc/cpuinfo", kCpuinfoCap);
    r.cgroup = read_source("/proc/self/cgroup", kCgroupCap);
    r.dockerenv_errno = probe("/.dockerenv");
    r.containerenv_errno = probe("/run/.containerenv");

    report_host(ctx, decide(linux_facts(std::move(cpuid), r)));
    return 0;
}

} // namespace yuzu::virtualization

#endif // defined(__linux__)
