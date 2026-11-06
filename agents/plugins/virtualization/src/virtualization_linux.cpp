/**
 * virtualization_linux.cpp -- Linux leg: virtualization facts from CPUID, DMI, sysfs and procfs.
 *
 * Only the POSIX shell lives here: it reads and fills a Facts. Every decision (the vendor
 * tables, the root-partition gate, the precedence, bare_metal vs unknown, the container
 * verdict) is in virtualization_parsers.hpp. Reads go through posix_secure_read (bounded,
 * regular files only); ENOENT is "absent" and any other failure is an unreadable source with a
 * `linux:virtualization:<source>:<cause>` token. The container check reads the AGENT's own
 * /proc/self/cgroup, not PID 1's, which answers a different question when the PID namespace is
 * shared.
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

std::string trim(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '\t'))
        s.pop_back();
    return s;
}

/// Result of one bounded read, mapped to the ok / absent / unreadable trichotomy.
struct Read {
    SmbiosFacts::State state = SmbiosFacts::State::absent;
    std::string data;
    std::string cause; ///< token cause segment when unreadable
};

Read read_source(const char* path, size_t cap) {
    Read r;
    const auto fr = yuzu::shared::read_file(path, cap, yuzu::shared::Leaf::follow);
    if (fr.ok()) {
        r.state = SmbiosFacts::State::ok;
        r.data = fr.data;
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
    r.state = SmbiosFacts::State::unreadable;
    return r;
}

FieldRead dmi_field(const char* path) {
    const Read r = read_source(path, kSmallCap);
    FieldRead f;
    f.state = r.state;
    if (r.state == SmbiosFacts::State::ok)
        f.value = trim(r.data);
    else if (r.state == SmbiosFacts::State::unreadable)
        f.reason = "linux:virtualization:dmi:" + r.cause;
    return f;
}

} // namespace

int run_linux(yuzu::CommandContext& ctx) {
    Facts f;
    f.os = "linux";
    f.cpuid = read_cpuid();
    f.smbios = combine_dmi(dmi_field("/sys/class/dmi/id/sys_vendor"),
                           dmi_field("/sys/class/dmi/id/product_name"));

    std::string hv_type;
    const Read hv = read_source("/sys/hypervisor/type", kSmallCap);
    if (hv.state == SmbiosFacts::State::ok)
        hv_type = hv.data;
    else if (hv.state == SmbiosFacts::State::unreadable)
        f.failures.push_back("linux:virtualization:sys_hypervisor:" + hv.cause);

    bool cpuinfo_flag = false;
    const Read ci = read_source("/proc/cpuinfo", kCpuinfoCap);
    if (ci.state == SmbiosFacts::State::ok)
        cpuinfo_flag = cpuinfo_has_hypervisor_flag(ci.data);
    else if (ci.state == SmbiosFacts::State::unreadable)
        f.failures.push_back("linux:virtualization:cpuinfo:" + ci.cause);
    f.hint = linux_os_hint(hv_type, cpuinfo_flag);

    f.container.mode = ContainerInputs::Mode::linux_read;
    const auto marker = [&f](const char* path, bool& present) {
        if (::access(path, F_OK) == 0) {
            present = true;
        } else if (errno != ENOENT && f.container.reason.empty()) {
            f.container.reason = "linux:virtualization:container:markers_" + errno_token(errno);
        }
    };
    marker("/.dockerenv", f.container.dockerenv);
    marker("/run/.containerenv", f.container.containerenv);
    const Read cg = read_source("/proc/self/cgroup", kCgroupCap);
    if (cg.state == SmbiosFacts::State::ok) {
        f.container.cgroup = cg.data;
    } else if (f.container.reason.empty()) {
        f.container.reason = "linux:virtualization:container:cgroup_" +
                             (cg.cause.empty() ? std::string{"enoent"} : cg.cause);
    }

    report_host(ctx, decide(f));
    return 0;
}

} // namespace yuzu::virtualization

#endif // defined(__linux__)
