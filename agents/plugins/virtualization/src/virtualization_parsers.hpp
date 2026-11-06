#pragma once

// virtualization_parsers.hpp -- the pure core of the virtualization plugin: every decision
// about "is this device a VM, which hypervisor, is the agent in a container" lives here, over
// plain-struct facts the per-OS shells fill in. Header-only and portable so the unit tests run
// on every host; no file I/O, no subprocess, no OS header.
//
// PRECEDENCE (stated once). Positive identification always beats negative evidence:
//   1. SMBIOS / hardware model names a VM vendor            -> guest (high)
//   2. CPUID hypervisor present, Microsoft Hv, and the Hyper-V root-partition bit set
//                                                            -> host_with_hypervisor (not virtual)
//   3. CPUID hypervisor present                              -> guest (medium when the vendor
//                                                               signature is not a well-formed 12 bytes)
//   3b. an OS hint says virtual (sysctl, /sys/hypervisor)    -> guest (medium)
//   4. a readable negative signal AND no consulted source unreadable -> bare_metal
//   5. anything else                                         -> unknown, with the reason tokens
// SMBIOS beats the root-partition bit because VBS nested inside another hypervisor sets
// CreatePartitions yet is a guest. bare_metal is reachable only when NO consulted source
// positively identifies virtualization AND no consulted source failed to read; an unreadable
// source, or the absence of any negative signal (ARM has no CPUID), reads `unknown`, never
// bare_metal. The reason for an unknown appears on the status row AND in the host row's
// `source` field.
//
// The root-partition bit (CPUID leaf 0x40000003 EBX bit 0, CreatePartitions) is only meaningful
// when the hypervisor-discovery contract holds: signature "Microsoft Hv", max leaf >= 0x40000003
// and interface signature "Hv#1" (leaf 0x40000001 EAX). Otherwise it is not read and stays
// nullopt; classify() ignores a value that arrives without the contract.
//
// TOKEN CLASSES. (a) constraint tokens from the sources,
//   ^(windows|macos|linux):virtualization:[a-z0-9_]+(:[a-z0-9_]+)*$
// (b) the seam exception token `<os>:leg:exception`, written only by execute_host's catch arm;
// (c) evidence strings in the container row's third field (`/.dockerenv`, a matched cgroup
// token, `macos:no_container_runtime`), which are not tokens and never reach set_result_status.
//
// The `status|host|...` row is NOT built here; report_host in virtualization_legs.hpp owns it.

#include <smbios_parsers.hpp>
#include <wire_utf8.hpp>
#include <yuzu/string_utils.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::virtualization {

enum class Kind { guest, host_with_hypervisor, bare_metal, unknown };
enum class Tri { yes, no, unknown };
enum class Confidence { high, medium, low };

inline std::string_view kind_token(Kind k) {
    switch (k) {
    case Kind::guest:
        return "guest";
    case Kind::host_with_hypervisor:
        return "host_with_hypervisor";
    case Kind::bare_metal:
        return "bare_metal";
    case Kind::unknown:
        return "unknown";
    }
    return "unknown";
}

inline std::string_view tri_token(Tri t) {
    switch (t) {
    case Tri::yes:
        return "yes";
    case Tri::no:
        return "no";
    case Tri::unknown:
        return "unknown";
    }
    return "unknown";
}

inline std::string_view confidence_token(Confidence c) {
    switch (c) {
    case Confidence::high:
        return "high";
    case Confidence::medium:
        return "medium";
    case Confidence::low:
        return "low";
    }
    return "low";
}

// ---------------------------------------------------------------------------
// Facts: what the shells read, as plain data
// ---------------------------------------------------------------------------

inline constexpr std::uint32_t kRootPartitionLeaf = 0x40000003u;

struct CpuidFacts {
    bool available = false;          ///< false: no CPUID on this architecture
    bool hypervisor_present = false; ///< leaf 1 ECX bit 31
    std::string vendor_sig;          ///< leaf 0x40000000 EBX/ECX/EDX, 12 bytes (empty when not read)
    std::uint32_t max_leaf = 0;      ///< leaf 0x40000000 EAX
    std::string interface_sig;       ///< leaf 0x40000001 EAX, 4 bytes (empty when not read)
    /// Leaf 0x40000003 EBX bit 0. Read ONLY when root_partition_leaf_readable() holds.
    std::optional<bool> root_partition;
};

/// The Microsoft hypervisor-discovery contract that makes leaf 0x40000003 meaningful.
inline bool root_partition_leaf_readable(std::string_view vendor_sig, std::uint32_t max_leaf,
                                         std::string_view interface_sig) {
    return vendor_sig == "Microsoft Hv" && max_leaf >= kRootPartitionLeaf && interface_sig == "Hv#1";
}

/// The outcome of one bounded read: a value, a definitive absence (ENOENT), or a failure.
enum class ReadState { ok, absent, unreadable };

struct SmbiosFacts {
    ReadState state = ReadState::absent;
    /// May be set even when unreadable (a Type 1 decoded before a later walk fault is kept).
    std::string manufacturer;
    std::string product;
    std::string reason; ///< failure token(s) when unreadable
};

struct OsHint {
    std::optional<bool> os_says_virtual; ///< nullopt = this OS gave no signal either way
    std::string source;                  ///< sysctl | sys_hypervisor
    std::string vendor_hint;             ///< e.g. the /sys/hypervisor/type value
};

struct ContainerInputs {
    enum class Mode { linux_read, macos_none, windows_not_read };
    Mode mode = Mode::linux_read;
    bool dockerenv = false;
    bool containerenv = false;
    std::optional<std::string> cgroup; ///< /proc/self/cgroup text; nullopt = not read
    std::string reason;                ///< failure token when a container source could not be read
};

struct Facts {
    std::string os; ///< "linux" | "macos" | "windows": the token prefix
    CpuidFacts cpuid;
    SmbiosFacts smbios;
    OsHint hint;
    /// Failed-read tokens for sources other than SMBIOS and the container inputs.
    std::vector<std::string> failures;
    ContainerInputs container;
};

// ---------------------------------------------------------------------------
// Vendor tables
// ---------------------------------------------------------------------------

namespace detail {

inline std::string lower(std::string_view s) {
    std::string out(s);
    for (auto& c : out)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    return out;
}

inline bool contains_ci(std::string_view hay, std::string_view needle) {
    return lower(hay).find(needle) != std::string::npos; // needles are lowercase
}

struct SigRow {
    std::string_view sig; // exactly 12 bytes
    std::string_view vendor;
};

// "KVMKVMKVM" is followed by three NULs on the wire.
inline constexpr std::array<SigRow, 9> kSignatures{{
    {std::string_view{"KVMKVMKVM\0\0\0", 12}, "kvm"},
    {"Microsoft Hv", "hyperv"},
    {"VMwareVMware", "vmware"},
    {"XenVMMXenVMM", "xen"},
    {"VBoxVBoxVBox", "virtualbox"},
    {" lrpepyh  vr", "parallels"},
    {"bhyve bhyve ", "bhyve"},
    {"TCGTCGTCGTCG", "qemu"},
    {"ACRNACRNACRN", "acrn"},
}};

struct SmbiosRow {
    std::string_view manufacturer; ///< lowercase substring; empty = ignore
    std::string_view product;      ///< lowercase substring; empty = ignore
    std::string_view vendor;
};

inline constexpr std::array<SmbiosRow, 17> kSmbios{{
    {"qemu", "", "qemu"},
    {"red hat", "kvm", "kvm"},
    {"red hat", "rhev", "kvm"},
    {"vmware", "", "vmware"},
    {"", "vmware", "vmware"},
    {"microsoft corporation", "virtual machine", "hyperv"},
    {"innotek", "", "virtualbox"},
    {"", "virtualbox", "virtualbox"},
    {"parallels", "", "parallels"},
    {"xen", "hvm domu", "xen"},
    {"amazon ec2", "", "aws"},
    {"", "amazon ec2", "aws"},
    {"", "google compute engine", "gce"},
    {"alibaba cloud", "", "alibaba"},
    {"openstack", "", "openstack"},
    {"nutanix", "ahv", "nutanix"},
    {"", "virtualmac", "apple"},
}};

} // namespace detail

/// Maps a 12-byte CPUID hypervisor signature to a vendor token; `other` for a well-formed but
/// unlisted signature; nullopt (malformed) when it is not exactly 12 bytes. classify() reads a
/// nullopt as `other` at medium confidence: the hypervisor bit is still a positive signal.
inline std::optional<std::string_view> hypervisor_from_signature(std::string_view sig) {
    if (sig.size() != 12)
        return std::nullopt;
    for (const auto& r : detail::kSignatures)
        if (sig == r.sig)
            return r.vendor;
    return std::string_view{"other"};
}

/// Maps SMBIOS manufacturer/product (case-insensitive substring rows) to a VM vendor token;
/// nullopt for real hardware.
inline std::optional<std::string_view> vm_vendor_from_smbios(std::string_view manufacturer,
                                                             std::string_view product) {
    // AWS bare-metal instance types carry `.metal` in product_name (manufacturer is still
    // "Amazon EC2"); no VM product name does. Nutanix NX appliances are excluded by their row
    // requiring the AHV product.
    if (detail::contains_ci(product, ".metal"))
        return std::nullopt;
    for (const auto& r : detail::kSmbios) {
        if (!r.manufacturer.empty() && !detail::contains_ci(manufacturer, r.manufacturer))
            continue;
        if (!r.product.empty() && !detail::contains_ci(product, r.product))
            continue;
        return r.vendor;
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Wire formatting
// ---------------------------------------------------------------------------

/// OS-supplied bytes -> a row-safe field: NUL and malformed UTF-8 become '?', then pipes,
/// backslashes and newlines are escaped. Empty becomes "-".
inline std::string wire_field(std::string_view v) {
    std::string s(v);
    yuzu::shared::scrub_wire_bytes(s);
    std::string out = yuzu::util::safe_output_field(s);
    return out.empty() ? std::string{"-"} : out;
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

struct Classification {
    /// Every constraint token behind this classification: the failed reads, plus the permanent
    /// `<os>:virtualization:cpuid:unavailable` limitation when the kind is unknown and nothing
    /// else supplied a negative signal. Non-empty makes the status row `constrained`.
    std::vector<std::string> tokens;
    Kind kind = Kind::unknown;
    Tri is_virtual = Tri::unknown;
    std::string vendor;  ///< hypervisor token; hardware manufacturer for bare_metal/unknown
    std::string product; ///< SMBIOS product / hw.model
    /// The evidence source that decided the kind, or the joined reason tokens when unknown.
    std::string source;
    Confidence confidence = Confidence::low;
};

namespace detail {

inline std::string token(const Facts& f, std::string_view tail) {
    return f.os + ":virtualization:" + std::string{tail};
}

inline bool root_partition_set(const CpuidFacts& c) {
    return c.root_partition.value_or(false) &&
           root_partition_leaf_readable(c.vendor_sig, c.max_leaf, c.interface_sig);
}

} // namespace detail

/// Every failed-read token that bears on the HOST decision (SMBIOS and the OS hints), in a
/// stable order. Container read failures are accounted separately (classify_container).
inline std::vector<std::string> failure_tokens(const Facts& f) {
    std::vector<std::string> out = f.failures;
    if (f.smbios.state == ReadState::unreadable)
        // An unexplained unknown is the one output this plugin must never emit: no shell leaves
        // the reason empty today, but if one did the status would still name the source.
        out.push_back(f.smbios.reason.empty() ? detail::token(f, "smbios:unreadable")
                                              : f.smbios.reason);
    return out;
}

/// True when neither CPUID nor the OS gave a readable "not virtual" answer.
inline bool lacks_negative_signal(const Facts& f) {
    const bool cpuid_negative = f.cpuid.available && !f.cpuid.hypervisor_present;
    return !cpuid_negative && f.hint.os_says_virtual != std::optional<bool>{false};
}

inline std::string join_tokens(const std::vector<std::string>& t) {
    std::string out;
    for (const auto& s : t) {
        if (!out.empty())
            out += ',';
        out += s;
    }
    return out;
}

/// The decision table (see the precedence block at the top of this file).
inline Classification classify(const Facts& f) {
    Classification c;
    c.tokens = failure_tokens(f);
    const std::string manufacturer = wire_field(f.smbios.manufacturer);
    const auto sm_vendor = vm_vendor_from_smbios(f.smbios.manufacturer, f.smbios.product);
    const bool sm_unreadable = f.smbios.state == ReadState::unreadable;
    const std::string product = wire_field(f.smbios.product);

    // 1. SMBIOS names a VM vendor.
    if (sm_vendor) {
        c.kind = Kind::guest;
        c.is_virtual = Tri::yes;
        c.vendor = std::string{*sm_vendor};
        c.product = product;
        c.source = "smbios";
        c.confidence = Confidence::high;
        return c;
    }

    const bool hv = f.cpuid.available && f.cpuid.hypervisor_present;
    const auto sig = hypervisor_from_signature(f.cpuid.vendor_sig);
    const std::string cpuid_vendor{sig.value_or("other")};

    // 2. Hyper-V root partition: the OS is the host, not a guest.
    if (hv && cpuid_vendor == "hyperv" && detail::root_partition_set(f.cpuid)) {
        c.kind = Kind::host_with_hypervisor;
        c.is_virtual = Tri::no;
        c.vendor = "hyperv";
        c.product = product;
        c.source = "cpuid";
        c.confidence = sm_unreadable ? Confidence::medium : Confidence::high;
        return c;
    }

    // 3. CPUID hypervisor bit.
    if (hv) {
        c.kind = Kind::guest;
        c.is_virtual = Tri::yes;
        c.vendor = cpuid_vendor;
        c.product = product;
        c.source = "cpuid";
        const bool root_known =
            f.cpuid.root_partition.has_value() &&
            root_partition_leaf_readable(f.cpuid.vendor_sig, f.cpuid.max_leaf, f.cpuid.interface_sig);
        const bool ms_root_unknown = cpuid_vendor == "hyperv" && !root_known;
        c.confidence =
            (ms_root_unknown || sm_unreadable || !sig) ? Confidence::medium : Confidence::high;
        return c;
    }

    // 3b. A positive OS hint is never outranked by negative or absent CPUID/SMBIOS evidence.
    if (f.hint.os_says_virtual == std::optional<bool>{true}) {
        c.kind = Kind::guest;
        c.is_virtual = Tri::yes;
        c.vendor = f.hint.vendor_hint == "xen" ? "xen" : "other";
        c.product = product;
        c.source = f.hint.source.empty() ? std::string{"os_hint"} : f.hint.source;
        c.confidence = Confidence::medium;
        return c;
    }

    // 4. bare_metal: a readable negative and nothing unreadable.
    const bool any_unreadable = sm_unreadable || !c.tokens.empty();
    if (!lacks_negative_signal(f) && !any_unreadable) {
        c.kind = Kind::bare_metal;
        c.is_virtual = Tri::no;
        c.vendor = manufacturer;
        c.product = product;
        c.source = (f.cpuid.available && !f.cpuid.hypervisor_present)
                       ? std::string{"cpuid"}
                       : (f.hint.source.empty() ? std::string{"os_hint"} : f.hint.source);
        c.confidence = Confidence::high;
        return c;
    }

    // 5. unknown, explained: the permanent limitation joins the failed reads.
    if (lacks_negative_signal(f) && !f.cpuid.available)
        c.tokens.push_back(detail::token(f, "cpuid:unavailable"));
    c.kind = Kind::unknown;
    c.is_virtual = Tri::unknown;
    c.vendor = manufacturer;
    c.product = product;
    c.source = wire_field(join_tokens(c.tokens));
    c.confidence = Confidence::low;
    return c;
}

// ---------------------------------------------------------------------------
// Container classification: the agent's OWN membership (/proc/self/cgroup, never PID 1's)
// ---------------------------------------------------------------------------

struct ContainerVerdict {
    Tri value = Tri::unknown;
    std::string evidence; ///< class (c) evidence, or the reason for an unknown
    bool read_failed = false; ///< `evidence` is a failed-read token that constrains the status
};

namespace detail {

inline constexpr std::array<std::string_view, 5> kContainerCgroupTokens{
    "docker", "containerd", "kubepods", "lxc", "podman"};

/// Splits /proc/self/cgroup into the path of each `hier:controllers:path` line.
inline std::vector<std::string> cgroup_paths(std::string_view text) {
    std::vector<std::string> out;
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t nl = text.find('\n', pos);
        if (nl == std::string_view::npos)
            nl = text.size();
        const std::string_view line = text.substr(pos, nl - pos);
        pos = nl + 1;
        const size_t c1 = line.find(':');
        const size_t c2 = c1 == std::string_view::npos ? c1 : line.find(':', c1 + 1);
        if (c2 == std::string_view::npos)
            continue;
        out.emplace_back(line.substr(c2 + 1));
    }
    return out;
}

} // namespace detail

inline ContainerVerdict classify_container(const Facts& f) {
    const ContainerInputs& in = f.container;
    ContainerVerdict v;
    if (in.mode == ContainerInputs::Mode::macos_none) {
        v.value = Tri::no;
        v.evidence = "macos:no_container_runtime";
        return v;
    }
    if (in.mode == ContainerInputs::Mode::windows_not_read) {
        v.evidence = "windows:virtualization:container:not_read";
        return v;
    }
    if (in.dockerenv) {
        v.value = Tri::yes;
        v.evidence = "/.dockerenv";
        return v;
    }
    if (in.containerenv) {
        v.value = Tri::yes;
        v.evidence = "/run/.containerenv";
        return v;
    }
    std::vector<std::string> paths;
    if (in.cgroup) {
        paths = detail::cgroup_paths(*in.cgroup);
        for (const auto& p : paths) {
            const std::string lp = detail::lower(p);
            for (const auto tok : detail::kContainerCgroupTokens) {
                if (lp.find(tok) != std::string::npos) {
                    v.value = Tri::yes;
                    v.evidence = "cgroup:" + std::string{tok};
                    return v;
                }
            }
        }
    }
    if (!in.reason.empty() || !in.cgroup) {
        v.read_failed = true;
        v.evidence = in.reason.empty() ? detail::token(f, "container:cgroup_not_read") : in.reason;
        return v;
    }
    const bool real_path = std::any_of(paths.begin(), paths.end(), [](const std::string& p) {
        return !p.empty() && p != "/";
    });
    if (!real_path) {
        // cgroup namespace: the agent sees `0::/` whatever it runs in
        v.evidence = detail::token(f, "container:cgroup_root_opaque");
        return v;
    }
    v.value = Tri::no;
    v.evidence = "linux:no_container_marker";
    return v;
}

// ---------------------------------------------------------------------------
// Fact builders: the decisions the shells would otherwise carry (all pure)
// ---------------------------------------------------------------------------

struct CpuidRegs {
    std::uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
};

/// Little-endian bytes of each register in turn (the order CPUID packs a signature).
inline std::string pack_le(std::initializer_list<std::uint32_t> regs) {
    std::string out;
    for (const std::uint32_t r : regs)
        for (int i = 0; i < 4; ++i)
            out += static_cast<char>((r >> (8 * i)) & 0xFFu);
    return out;
}

/// Builds CpuidFacts from an injected `cpuid(leaf) -> CpuidRegs`. The caller has established
/// that CPUID exists. The hypervisor leaves are touched only when leaf 1 says one is present,
/// and the root-partition leaf only behind root_partition_leaf_readable().
template <class CpuidFn> CpuidFacts cpuid_facts(CpuidFn&& cpuid) {
    CpuidFacts c;
    c.available = true;
    c.hypervisor_present = ((cpuid(1u).ecx >> 31) & 1u) != 0;
    if (!c.hypervisor_present)
        return c;
    const CpuidRegs l0 = cpuid(0x40000000u);
    c.max_leaf = l0.eax;
    c.vendor_sig = pack_le({l0.ebx, l0.ecx, l0.edx});
    if (c.max_leaf >= 0x40000001u)
        c.interface_sig = pack_le({cpuid(0x40000001u).eax});
    if (root_partition_leaf_readable(c.vendor_sig, c.max_leaf, c.interface_sig))
        c.root_partition = (cpuid(kRootPartitionLeaf).ebx & 1u) != 0;
    return c;
}

/// errno -> the `[a-z0-9_]+` cause segment of a constraint token.
inline std::string errno_token(int err) {
    switch (err) {
    case ENOENT:
        return "enoent";
    case EACCES:
    case EPERM:
        return "permission_denied";
    case EIO:
        return "eio";
    case ELOOP:
        return "eloop";
    case ENOTDIR:
        return "enotdir";
    case EINVAL:
        return "einval";
    default:
        return "errno_" + std::to_string(err);
    }
}

/// One bounded file read as the Linux shell reports it: ok (value), absent (ENOENT) or
/// unreadable. `cause` is the `[a-z0-9_]+` segment of the constraint token (`permission_denied`,
/// `eio`, `oversized`, `not_regular`, ...); linux_facts builds the whole token from it.
struct FieldRead {
    ReadState state = ReadState::absent;
    std::string value;
    std::string cause;
};

namespace detail {

inline std::string linux_token(std::string_view source, std::string_view cause) {
    return "linux:virtualization:" + std::string{source} + ":" + std::string{cause};
}

inline void push_unique(std::vector<std::string>& v, std::string s) {
    if (std::find(v.begin(), v.end(), s) == v.end())
        v.push_back(std::move(s));
}

inline std::string rtrim(std::string s) {
    s.erase(s.find_last_not_of(" \t\r\n") + 1);
    return s;
}

} // namespace detail

/// Combines the two Linux DMI attributes into SmbiosFacts. Either unreadable makes the whole
/// unreadable (the readable half is kept) and EVERY failed half is reported, comma-joined
/// (identical causes once); both absent is absent; otherwise ok. Values lose their trailing
/// newline.
inline SmbiosFacts combine_dmi(const FieldRead& vendor, const FieldRead& product) {
    SmbiosFacts s;
    s.manufacturer = detail::rtrim(vendor.value);
    s.product = detail::rtrim(product.value);
    std::vector<std::string> reasons;
    for (const FieldRead* r : {&vendor, &product})
        if (r->state == ReadState::unreadable)
            detail::push_unique(reasons, detail::linux_token("dmi", r->cause));
    if (!reasons.empty()) {
        s.state = ReadState::unreadable;
        s.reason = join_tokens(reasons);
    } else if (vendor.state == ReadState::absent && product.state == ReadState::absent) {
        s.state = ReadState::absent;
    } else {
        s.state = ReadState::ok;
    }
    return s;
}

/// SMBIOS facts for a Windows RSMB read that failed before any table was decoded.
inline SmbiosFacts smbios_read_failure(std::string_view cause) {
    SmbiosFacts s;
    s.state = ReadState::unreadable;
    s.reason = "windows:virtualization:smbios:" + std::string{cause};
    return s;
}

/// Maps a decoded RSMB table to SmbiosFacts. `table.error` (the walk stopped at a framing fault)
/// is checked independently of `table.system`: the default system status is `absent`, so reading
/// only `system` would turn a truncated walk into a clean "no SMBIOS". A Type 1 decoded BEFORE
/// the fault keeps its manufacturer/product (so a VM vendor still identifies the guest) while
/// the state is unreadable (so bare_metal stays unreachable).
inline SmbiosFacts smbios_facts_from_table(const yuzu::shared::smbios::SmbiosTable& t) {
    using yuzu::shared::smbios::Status;
    SmbiosFacts s;
    if (t.system.status == Status::ok) {
        s.manufacturer = t.system.data.manufacturer.value_or("");
        s.product = t.system.data.product.value_or("");
    }
    if (t.error) {
        s.state = ReadState::unreadable;
        s.reason = std::string{"windows:virtualization:smbios:"} +
                   (*t.error == yuzu::shared::smbios::Error::truncated ? "truncated" : "malformed");
    } else if (t.system.status == Status::malformed) {
        s.state = ReadState::unreadable;
        s.reason = "windows:virtualization:smbios:malformed";
    } else {
        s.state = t.system.status == Status::ok ? ReadState::ok : ReadState::absent;
    }
    return s;
}

/// Linux OS hint: a non-empty /sys/hypervisor/type. Linux supplies a positive hint only; an
/// empty or missing file is "no signal", not "not virtual".
inline OsHint linux_os_hint(std::string_view sys_hypervisor_type) {
    OsHint h;
    const std::string t = detail::rtrim(detail::lower(sys_hypervisor_type));
    if (!t.empty()) {
        h.os_says_virtual = true;
        h.source = "sys_hypervisor";
        h.vendor_hint = t;
    }
    return h;
}

/// Everything the Linux shell reads, before any decision: the four bounded file reads and the
/// errno of the two container-marker probes (0 = present, ENOENT = absent, else a failure). The
/// probes default to absent so an unfilled LinuxReads never reads as "in a container".
struct LinuxReads {
    FieldRead sys_vendor;
    FieldRead product_name;
    FieldRead hypervisor_type;
    FieldRead cgroup; ///< /proc/self/cgroup, the agent's own membership
    int dockerenv_errno = ENOENT;
    int containerenv_errno = ENOENT;
};

/// Linux Facts from the reads: the DMI combine, the `linux:virtualization:<source>:<cause>`
/// tokens, the OS hint and the container inputs. Every failed container read is kept
/// (comma-joined in container.reason); ENOENT is a definitive absence and never a token, except
/// that /proc/self/cgroup missing entirely is `cgroup_enoent` (the agent cannot answer).
inline Facts linux_facts(CpuidFacts cpuid, const LinuxReads& r) {
    Facts f;
    f.os = "linux";
    f.cpuid = std::move(cpuid);
    f.smbios = combine_dmi(r.sys_vendor, r.product_name);

    std::string hv_type;
    if (r.hypervisor_type.state == ReadState::ok)
        hv_type = r.hypervisor_type.value;
    else if (r.hypervisor_type.state == ReadState::unreadable)
        f.failures.push_back(detail::linux_token("sys_hypervisor", r.hypervisor_type.cause));
    f.hint = linux_os_hint(hv_type);

    f.container.mode = ContainerInputs::Mode::linux_read;
    std::vector<std::string> failed;
    const auto marker = [&failed](int err, bool& present) {
        if (err == 0)
            present = true;
        else if (err != ENOENT)
            detail::push_unique(failed,
                                detail::linux_token("container", "markers_" + errno_token(err)));
    };
    marker(r.dockerenv_errno, f.container.dockerenv);
    marker(r.containerenv_errno, f.container.containerenv);
    if (r.cgroup.state == ReadState::ok)
        f.container.cgroup = r.cgroup.value;
    else
        detail::push_unique(failed,
                            detail::linux_token("container",
                                                "cgroup_" + (r.cgroup.state == ReadState::absent
                                                                 ? std::string{"enoent"}
                                                                 : r.cgroup.cause)));
    f.container.reason = join_tokens(failed);
    return f;
}

// ---------------------------------------------------------------------------
// Row formatters
// ---------------------------------------------------------------------------

inline std::string format_host_row(const Classification& c) {
    std::string r = "host|";
    r += tri_token(c.is_virtual);
    r += '|';
    r += kind_token(c.kind);
    r += '|';
    r += c.vendor.empty() ? std::string{"-"} : c.vendor;
    r += '|';
    r += c.product.empty() ? std::string{"-"} : c.product;
    r += '|';
    r += c.source.empty() ? std::string{"-"} : c.source;
    r += '|';
    r += confidence_token(c.confidence);
    return r;
}

inline std::string format_container_row(const ContainerVerdict& v) {
    std::string r = "container|";
    r += tri_token(v.value);
    r += '|';
    r += wire_field(v.evidence);
    return r;
}

} // namespace yuzu::virtualization
