/**
 * test_virtualization_parsers.cpp -- pure tests for the virtualization plugin's classifier,
 * vendor tables, CPUID fact builder, SMBIOS walk-fault mapping, container classifier and row
 * formatters. Portable, no I/O: the shells' reads are replaced by the Facts structs.
 *
 * Fixture provenance (each labelled at its use):
 *   REAL      read on braga (bare-metal Apple Silicon Mac mini, macOS 26) on 2026-11-06 with
 *             `sysctl kern.hv_vmm_present hw.model`.
 *   SYNTHETIC built from the documented layouts (Microsoft TLFS hypervisor-discovery leaves,
 *             DMI strings Linux publishes under Hyper-V, cgroup v1/v2 text). The Windows host
 *             and WSL2 guest specimens here stay SYNTHETIC; the plugin's own real captures of
 *             both are the samples in agents/plugins/virtualization/docs/samples. No real
 *             hostname, serial or account name appears in any fixture.
 */
#include <catch2/catch_test_macros.hpp>

#include "virtualization_legs.hpp"
#include "virtualization_parsers.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <optional>
#include <regex>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace yuzu::virtualization;

namespace {

SmbiosFacts smbios_ok(std::string mfr, std::string prod) {
    SmbiosFacts s;
    s.state = ReadState::ok;
    s.manufacturer = std::move(mfr);
    s.product = std::move(prod);
    return s;
}

/// The neutral board strings that match no vendor-table row.
SmbiosFacts board() { return smbios_ok("Example Board Vendor", "Example Board"); }

/// A lowercase 64-hex container id, the shape every runtime's cgroup path carries.
const std::string kContainerId = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

SmbiosFacts smbios_unreadable(std::string reason) {
    SmbiosFacts s;
    s.state = ReadState::unreadable;
    s.reason = std::move(reason);
    return s;
}

CpuidFacts cpuid_clear() {
    CpuidFacts c;
    c.available = true;
    return c;
}

CpuidFacts cpuid_hv(std::string sig, std::uint32_t max_leaf = 0x40000001u,
                    std::string iface = "", std::optional<bool> root = std::nullopt) {
    CpuidFacts c;
    c.available = true;
    c.hypervisor_present = true;
    c.vendor_sig = std::move(sig);
    c.max_leaf = max_leaf;
    c.interface_sig = std::move(iface);
    c.root_partition = root;
    return c;
}

Facts linux_base() {
    Facts f;
    f.os = "linux";
    f.container.mode = ContainerInputs::Mode::linux_read;
    f.container.cgroup = "0::/system.slice/yuzu-agent.service\n";
    return f;
}

std::string kvm_sig() { return std::string{"KVMKVMKVM\0\0\0", 12}; }

/// Splits a wire row on unescaped '|' (a "\|" stays inside its field).
std::vector<std::string> split_row(const std::string& row) {
    std::vector<std::string> out{""};
    for (size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            out.back() += "\\|";
            ++i;
        } else if (row[i] == '|') {
            out.emplace_back();
        } else {
            out.back() += row[i];
        }
    }
    return out;
}

} // namespace

TEST_CASE("virtualization: every CPUID signature maps to its vendor", "[virtualization][vendor]") {
    CHECK(hypervisor_from_signature(kvm_sig()) == "kvm");
    CHECK(hypervisor_from_signature("Microsoft Hv") == "hyperv");
    CHECK(hypervisor_from_signature("VMwareVMware") == "vmware");
    CHECK(hypervisor_from_signature("XenVMMXenVMM") == "xen");
    CHECK(hypervisor_from_signature("VBoxVBoxVBox") == "virtualbox");
    CHECK(hypervisor_from_signature(" lrpepyh  vr") == "parallels");
    CHECK(hypervisor_from_signature("bhyve bhyve ") == "bhyve");
    CHECK(hypervisor_from_signature("TCGTCGTCGTCG") == "qemu");
    CHECK(hypervisor_from_signature("ACRNACRNACRN") == "acrn");
    CHECK(hypervisor_from_signature("ZZZZZZZZZZZZ") == "other");
    // Not exactly 12 bytes: unreadable, not "other".
    CHECK_FALSE(hypervisor_from_signature("KVMKVMKVM").has_value());
    CHECK_FALSE(hypervisor_from_signature("").has_value());
}

TEST_CASE("virtualization: SMBIOS vendor table is case-insensitive and ignores real hardware",
          "[virtualization][vendor]") {
    CHECK(vm_vendor_from_smbios("QEMU", "Standard PC (Q35 + ICH9, 2009)") == "qemu");
    CHECK(vm_vendor_from_smbios("Red Hat", "KVM") == "kvm");
    CHECK(vm_vendor_from_smbios("Red Hat", "RHEV Hypervisor") == "kvm");
    CHECK(vm_vendor_from_smbios("VMware, Inc.", "VMware7,1") == "vmware");
    CHECK(vm_vendor_from_smbios("VMWARE, INC.", "whatever") == "vmware");
    CHECK(vm_vendor_from_smbios("Microsoft Corporation", "Virtual Machine") == "hyperv");
    CHECK(vm_vendor_from_smbios("innotek GmbH", "VirtualBox") == "virtualbox");
    CHECK(vm_vendor_from_smbios("Parallels Software International Inc.", "Parallels Virtual Platform") ==
          "parallels");
    CHECK(vm_vendor_from_smbios("Xen", "HVM domU") == "xen");
    CHECK(vm_vendor_from_smbios("Amazon EC2", "m5.large") == "aws");
    CHECK(vm_vendor_from_smbios("Google", "Google Compute Engine") == "gce");
    CHECK(vm_vendor_from_smbios("Alibaba Cloud", "Alibaba Cloud ECS") == "alibaba");
    CHECK(vm_vendor_from_smbios("OpenStack Foundation", "OpenStack Nova") == "openstack");
    CHECK(vm_vendor_from_smbios("Nutanix", "AHV") == "nutanix");
    CHECK(vm_vendor_from_smbios("Apple Inc.", "VirtualMac2,1") == "apple");

    // The product-only fallback rows, with a neutral manufacturer and mixed case.
    CHECK(vm_vendor_from_smbios("Some OEM", "VMWARE Virtual Platform") == "vmware");
    CHECK(vm_vendor_from_smbios("Oracle Corporation", "VirtualBox") == "virtualbox");
    CHECK(vm_vendor_from_smbios("Acme", "amazon ec2 instance") == "aws");

    // Real hardware maps to nullopt, including a Microsoft-made laptop.
    CHECK_FALSE(vm_vendor_from_smbios("Micro-Star International Co., Ltd.", "MS-7E12").has_value());
    CHECK_FALSE(vm_vendor_from_smbios("Apple Inc.", "Mac16,1").has_value());
    CHECK_FALSE(vm_vendor_from_smbios("Microsoft Corporation", "Surface Laptop 5").has_value());
    CHECK_FALSE(vm_vendor_from_smbios("Lenovo", "ThinkPad X1").has_value());

    // Bare metal that shares a cloud or hyperconverged vendor's manufacturer string.
    CHECK_FALSE(vm_vendor_from_smbios("Nutanix", "NX-3060-G7").has_value());
    CHECK_FALSE(vm_vendor_from_smbios("Amazon EC2", "c5.metal").has_value());
}

TEST_CASE("virtualization: a real bare-metal Mac reads bare_metal", "[virtualization][classify]") {
    // REAL (braga, 2026-11-06): kern.hv_vmm_present = 0, hw.model = Mac16,10.
    Facts f;
    f.os = "macos";
    f.hint.os_says_virtual = false;
    f.hint.source = "sysctl";
    f.smbios = smbios_ok("Apple Inc.", "Mac16,10");
    f.container.mode = ContainerInputs::Mode::macos_none;

    const auto c = classify(f);
    CHECK(c.kind == Kind::bare_metal);
    CHECK(c.is_virtual == Tri::no);
    CHECK(c.confidence == Confidence::high);
    CHECK(c.source == "sysctl");
    CHECK(c.product == "Mac16,10");

    const auto p = decide(f);
    CHECK(p.status == StatusState::supported);
    CHECK(p.reason.empty());
    REQUIRE(p.rows.size() == 2);
    CHECK(p.rows[0] == "host|no|bare_metal|Apple Inc.|Mac16,10|sysctl|high");
    CHECK(p.rows[1] == "container|no|macos:no_container_runtime");
}

TEST_CASE("virtualization: a Windows host running Hyper-V is host_with_hypervisor not a guest",
          "[virtualization][classify]") {
    // SYNTHETIC from the TLFS leaves a Windows root partition reports; the real capture on a
    // Hyper-V host is docs/samples/windows.txt.
    Facts f;
    f.os = "windows";
    f.cpuid = cpuid_hv("Microsoft Hv", 0x4000000Cu, "Hv#1", true);
    f.smbios = board();
    f.container.mode = ContainerInputs::Mode::windows_not_read;

    const auto c = classify(f);
    CHECK(c.kind == Kind::host_with_hypervisor);
    CHECK(c.is_virtual == Tri::no);
    CHECK(c.vendor == "hyperv");
    CHECK(c.confidence == Confidence::high);

    // The container row is unknown by declaration, which is NOT a status failure.
    const auto p = decide(f);
    CHECK(p.status == StatusState::supported);
    CHECK(p.rows[1] == "container|unknown|windows:virtualization:container:not_read");
}

TEST_CASE("virtualization: a WSL2 style Hyper-V guest is decided by its SMBIOS, reads guest hyperv",
          "[virtualization][classify]") {
    // SYNTHETIC: the Microsoft hypervisor signature without the root-partition bit, and DMI as
    // the Linux kernel publishes it under Hyper-V. The VM-vendor SMBIOS answers at step 1, so
    // this case does not exercise the root-partition bit (see the next case for that).
    Facts f = linux_base();
    f.cpuid = cpuid_hv("Microsoft Hv", 0x4000000Cu, "Hv#1", false);
    f.smbios = smbios_ok("Microsoft Corporation", "Virtual Machine");

    const auto c = classify(f);
    CHECK(c.kind == Kind::guest);
    CHECK(c.is_virtual == Tri::yes);
    CHECK(c.vendor == "hyperv");
    CHECK(c.source == "smbios");
    CHECK(c.confidence == Confidence::high);
}

TEST_CASE("virtualization: the root-partition bit alone separates a Hyper-V host from a guest",
          "[virtualization][classify][cpuid]") {
    // SYNTHETIC: the full Hv#1 discovery contract holds and the board is not a VM vendor's, so
    // the bit is the only thing that can decide.
    const auto classify_with = [](std::optional<bool> root, SmbiosFacts smbios) {
        Facts f;
        f.os = "windows";
        f.cpuid = cpuid_hv("Microsoft Hv", 0x4000000Cu, "Hv#1", root);
        f.smbios = std::move(smbios);
        f.container.mode = ContainerInputs::Mode::windows_not_read;
        return f;
    };

    SECTION("bit clear: a guest, hyperv, high") {
        const auto c = classify(classify_with(false, board()));
        CHECK(c.kind == Kind::guest);
        CHECK(c.is_virtual == Tri::yes);
        CHECK(c.vendor == "hyperv");
        CHECK(c.source == "cpuid");
        CHECK(c.confidence == Confidence::high);
    }
    SECTION("bit unread under a held contract: a guest, medium") {
        const auto c = classify(classify_with(std::nullopt, board()));
        CHECK(c.kind == Kind::guest);
        CHECK(c.vendor == "hyperv");
        CHECK(c.confidence == Confidence::medium);
    }
    SECTION("bit set: the host") {
        const auto c = classify(classify_with(true, board()));
        CHECK(c.kind == Kind::host_with_hypervisor);
        CHECK(c.confidence == Confidence::high);
    }
    SECTION("bit set but SMBIOS unreadable: still the host, medium, and the status is constrained") {
        const Facts f = classify_with(true, smbios_unreadable("windows:virtualization:smbios:truncated"));
        const auto c = classify(f);
        CHECK(c.kind == Kind::host_with_hypervisor);
        CHECK(c.is_virtual == Tri::no);
        CHECK(c.confidence == Confidence::medium);
        CHECK(decide(f).status == StatusState::constrained);
    }
}

TEST_CASE("virtualization: SMBIOS beats the root-partition bit (VBS nested in VMware)",
          "[virtualization][classify]") {
    // SYNTHETIC: VBS inside VMware sets CreatePartitions yet the machine is a guest.
    Facts f;
    f.os = "windows";
    f.cpuid = cpuid_hv("Microsoft Hv", 0x4000000Cu, "Hv#1", true);
    f.smbios = smbios_ok("VMware, Inc.", "VMware7,1");
    f.container.mode = ContainerInputs::Mode::windows_not_read;

    const auto c = classify(f);
    CHECK(c.kind == Kind::guest);
    CHECK(c.vendor == "vmware");
    CHECK(c.source == "smbios");
    CHECK(c.confidence == Confidence::high);
}

TEST_CASE("virtualization: the root-partition bit is only trusted behind CPUID discovery",
          "[virtualization][classify][cpuid]") {
    SECTION("cpuid_facts never reads leaf 0x40000003 when the max leaf is too low") {
        std::vector<std::uint32_t> leaves;
        const auto facts = cpuid_facts([&](std::uint32_t leaf) {
            leaves.push_back(leaf);
            CpuidRegs r;
            if (leaf == 1)
                r.ecx = 0x80000000u;
            if (leaf == 0x40000000u) { // "Microsoft Hv"
                r.eax = 0x40000002u;
                r.ebx = 0x7263694Du;
                r.ecx = 0x666F736Fu;
                r.edx = 0x76482074u;
            }
            if (leaf == 0x40000001u)
                r.eax = 0x31237648u; // "Hv#1"
            return r;
        });
        CHECK(facts.vendor_sig == "Microsoft Hv");
        CHECK(facts.interface_sig == "Hv#1");
        CHECK_FALSE(facts.root_partition.has_value());
        CHECK(std::find(leaves.begin(), leaves.end(), kRootPartitionLeaf) == leaves.end());
    }
    SECTION("cpuid_facts never reads leaf 0x40000003 when the interface signature is not Hv#1") {
        std::vector<std::uint32_t> leaves;
        const auto facts = cpuid_facts([&](std::uint32_t leaf) {
            leaves.push_back(leaf);
            CpuidRegs r;
            if (leaf == 1)
                r.ecx = 0x80000000u;
            if (leaf == 0x40000000u) {
                r.eax = 0x4000000Cu;
                r.ebx = 0x7263694Du;
                r.ecx = 0x666F736Fu;
                r.edx = 0x76482074u;
            }
            if (leaf == 0x40000001u)
                r.eax = 0x32237648u; // "Hv#2"
            return r;
        });
        CHECK_FALSE(facts.root_partition.has_value());
        CHECK(std::find(leaves.begin(), leaves.end(), kRootPartitionLeaf) == leaves.end());
    }
    SECTION("cpuid_facts reads the bit when the contract holds") {
        const auto facts = cpuid_facts([](std::uint32_t leaf) {
            CpuidRegs r;
            if (leaf == 1)
                r.ecx = 0x80000000u;
            if (leaf == 0x40000000u) {
                r.eax = 0x4000000Cu;
                r.ebx = 0x7263694Du;
                r.ecx = 0x666F736Fu;
                r.edx = 0x76482074u;
            }
            if (leaf == 0x40000001u)
                r.eax = 0x31237648u;
            if (leaf == kRootPartitionLeaf)
                r.ebx = 1;
            return r;
        });
        REQUIRE(facts.root_partition.has_value());
        CHECK(*facts.root_partition);
    }
    SECTION("no hypervisor bit touches no hypervisor leaf") {
        std::vector<std::uint32_t> leaves;
        const auto facts = cpuid_facts([&](std::uint32_t leaf) {
            leaves.push_back(leaf);
            return CpuidRegs{};
        });
        CHECK(facts.available);
        CHECK_FALSE(facts.hypervisor_present);
        CHECK(leaves == std::vector<std::uint32_t>{1u});
    }
    SECTION("a root-partition value that arrives without the contract is ignored") {
        Facts f;
        f.os = "windows";
        f.cpuid = cpuid_hv("Microsoft Hv", 0x40000002u, "Hv#1", true); // max leaf too low
        f.smbios = board();
        const auto c = classify(f);
        CHECK(c.kind == Kind::guest);
        CHECK(c.vendor == "hyperv");
        CHECK(c.confidence == Confidence::medium);
    }
    SECTION("an unread bit under a Microsoft signature is a medium-confidence guest not unknown") {
        Facts f;
        f.os = "windows";
        f.cpuid = cpuid_hv("Microsoft Hv", 0x40000002u, "Hv#1", std::nullopt);
        f.smbios = board();
        const auto c = classify(f);
        CHECK(c.kind == Kind::guest);
        CHECK(c.is_virtual == Tri::yes);
        CHECK(c.vendor == "hyperv");
        CHECK(c.confidence == Confidence::medium);
    }
}

TEST_CASE("virtualization: an identified guest with an unreadable SMBIOS stays guest but constrained",
          "[virtualization][classify]") {
    // SYNTHETIC: hypervisor bit set, KVM signature, DMI refused.
    Facts f = linux_base();
    f.cpuid = cpuid_hv(kvm_sig());
    f.smbios = smbios_unreadable("linux:virtualization:dmi:permission_denied");

    const auto c = classify(f);
    CHECK(c.kind == Kind::guest);
    CHECK(c.vendor == "kvm");
    CHECK(c.confidence == Confidence::medium);

    const auto p = decide(f);
    CHECK(p.status == StatusState::constrained);
    CHECK(p.reason == "linux:virtualization:dmi:permission_denied");
}

TEST_CASE("virtualization: a malformed hypervisor signature is a medium-confidence guest",
          "[virtualization][classify][cpuid]") {
    // SYNTHETIC: the hypervisor bit is set but the 0x40000000 signature is not 12 bytes.
    Facts f = linux_base();
    f.cpuid = cpuid_hv("KVMKVMKVM");
    f.smbios.state = ReadState::absent;
    const auto c = classify(f);
    CHECK(c.kind == Kind::guest);
    CHECK(c.is_virtual == Tri::yes);
    CHECK(c.vendor == "other");
    CHECK(c.confidence == Confidence::medium);
    CHECK(decide(f).status == StatusState::supported); // nothing failed to read
}

TEST_CASE("virtualization: AWS .metal instances read bare_metal not guest", "[virtualization][classify]") {
    // SYNTHETIC: sys_vendor "Amazon EC2" on an instance with no hypervisor bit.
    Facts f = linux_base();
    f.cpuid = cpuid_clear();
    f.smbios = smbios_ok("Amazon EC2", "c5.metal");
    const auto c = classify(f);
    CHECK(c.kind == Kind::bare_metal);
    CHECK(c.vendor == "Amazon EC2");
}

TEST_CASE("virtualization: an unreadable SMBIOS with no reason still names its source",
          "[virtualization][classify][strict]") {
    Facts f = linux_base();
    f.cpuid = cpuid_clear();
    // no shell leaves the reason empty; the plugin must not trust that
    f.smbios.state = ReadState::unreadable;
    const auto c = classify(f);
    CHECK(c.kind == Kind::unknown);
    CHECK(c.source == "linux:virtualization:smbios:unreadable");
    const auto p = decide(f);
    CHECK(p.status == StatusState::constrained);
    CHECK(p.reason == "linux:virtualization:smbios:unreadable");
}

TEST_CASE("virtualization: an unreadable host-decision source never reads as bare_metal",
          "[virtualization][strict]") {
    SECTION("CPUID clear but DMI unreadable is unknown and the host row says why") {
        Facts f = linux_base();
        f.cpuid = cpuid_clear();
        f.smbios = smbios_unreadable("linux:virtualization:dmi:permission_denied");
        const auto c = classify(f);
        CHECK(c.kind == Kind::unknown);
        CHECK(c.is_virtual == Tri::unknown);
        CHECK(c.source == "linux:virtualization:dmi:permission_denied");
        CHECK(c.confidence == Confidence::low);
        const auto p = decide(f);
        CHECK(p.status == StatusState::constrained);
        CHECK(p.reason == c.source);
    }
    SECTION("an unreadable OS hint source blocks bare_metal too") {
        Facts f = linux_base();
        f.cpuid = cpuid_clear();
        f.smbios = board();
        f.failures.push_back("linux:virtualization:sys_hypervisor:eio");
        CHECK(classify(f).kind == Kind::unknown);
    }
    SECTION("no CPUID (ARM) and a non-VM DMI is unknown with the permanent limitation token") {
        Facts f = linux_base();
        f.smbios = board();
        const auto c = classify(f);
        CHECK(c.kind == Kind::unknown);
        CHECK(c.source == "linux:virtualization:cpuid:unavailable");
        const auto p = decide(f);
        CHECK(p.status == StatusState::constrained);
        CHECK(p.reason == "linux:virtualization:cpuid:unavailable");
    }
    SECTION("no CPUID (ARM) and a VM DMI vendor is a guest and needs no limitation token") {
        Facts f = linux_base();
        f.smbios = smbios_ok("QEMU", "KVM Virtual Machine");
        const auto p = decide(f);
        CHECK(p.status == StatusState::supported);
        CHECK(p.rows[0].rfind("host|yes|guest|qemu|", 0) == 0);
    }
    SECTION("macOS with a readable negative sysctl is bare_metal despite no CPUID") {
        Facts f;
        f.os = "macos";
        f.hint.os_says_virtual = false;
        f.hint.source = "sysctl";
        f.smbios = smbios_ok("Apple Inc.", "Mac16,10");
        CHECK(classify(f).kind == Kind::bare_metal);
    }
    SECTION("macOS with an unreadable hw.model is unknown") {
        Facts f;
        f.os = "macos";
        f.hint.os_says_virtual = false;
        f.hint.source = "sysctl";
        f.smbios = smbios_unreadable("macos:virtualization:hw_model:unreadable");
        const auto c = classify(f);
        CHECK(c.kind == Kind::unknown);
        CHECK(c.source == "macos:virtualization:hw_model:unreadable");
    }
    SECTION("macOS with an unreadable hv_vmm_present is unknown") {
        Facts f;
        f.os = "macos";
        f.failures.push_back("macos:virtualization:hv_vmm_present:unreadable");
        f.smbios = smbios_ok("Apple Inc.", "Mac16,10");
        const auto c = classify(f);
        CHECK(c.kind == Kind::unknown);
        CHECK(c.source.find("macos:virtualization:hv_vmm_present:unreadable") != std::string::npos);
    }
    SECTION("absent DMI (ENOENT) is readable: CPUID clear is still bare_metal") {
        Facts f = linux_base();
        f.cpuid = cpuid_clear();
        f.smbios.state = ReadState::absent;
        CHECK(classify(f).kind == Kind::bare_metal);
    }
}

TEST_CASE("virtualization: a positive OS hint is never outranked by negative evidence",
          "[virtualization][classify][hint]") {
    SECTION("/sys/hypervisor/type xen with CPUID clear and a non-VM DMI") {
        Facts f = linux_base();
        f.cpuid = cpuid_clear();
        f.smbios = board();
        f.hint = linux_os_hint("xen\n");
        const auto c = classify(f);
        CHECK(c.kind == Kind::guest);
        CHECK(c.vendor == "xen");
        CHECK(c.confidence == Confidence::medium);
        CHECK(c.source == "sys_hypervisor");
    }
    SECTION("macOS hv_vmm_present=1 on a model that is not a VirtualMac name") {
        Facts f;
        f.os = "macos";
        f.hint.os_says_virtual = true;
        f.hint.source = "sysctl";
        f.smbios = smbios_ok("Apple Inc.", "Mac14,3");
        const auto c = classify(f);
        CHECK(c.kind == Kind::guest);
        CHECK(c.vendor == "other");
        CHECK(c.confidence == Confidence::medium);
    }
    SECTION("macOS VirtualMac model is an Apple guest by SMBIOS") {
        Facts f;
        f.os = "macos";
        f.hint.os_says_virtual = true;
        f.hint.source = "sysctl";
        f.smbios = smbios_ok("Apple Inc.", "VirtualMac2,1");
        const auto c = classify(f);
        CHECK(c.vendor == "apple");
        CHECK(c.confidence == Confidence::high);
    }
}

TEST_CASE("virtualization: an SMBIOS walk fault is a constraint not a clean absence",
          "[virtualization][smbios]") {
    using namespace yuzu::shared::smbios;

    SECTION("a truncated walk with no Type 1 decoded is unreadable") {
        SmbiosTable t;
        t.error = Error::truncated;
        const auto s = smbios_facts_from_table(t);
        CHECK(s.state == ReadState::unreadable);
        CHECK(s.reason == "windows:virtualization:smbios:truncated");

        Facts f;
        f.os = "windows";
        f.cpuid = cpuid_clear();
        f.smbios = s;
        f.container.mode = ContainerInputs::Mode::windows_not_read;
        const auto c = classify(f);
        CHECK(c.kind == Kind::unknown); // never bare_metal
        CHECK(decide(f).status == StatusState::constrained);
    }
    SECTION("a malformed framing fault maps to the malformed token") {
        SmbiosTable t;
        t.error = Error::malformed;
        CHECK(smbios_facts_from_table(t).reason == "windows:virtualization:smbios:malformed");
    }
    SECTION("a malformed Type 1 is unreadable") {
        SmbiosTable t;
        t.system.status = Status::malformed;
        const auto s = smbios_facts_from_table(t);
        CHECK(s.state == ReadState::unreadable);
        CHECK(s.reason == "windows:virtualization:smbios:malformed");
    }
    SECTION("a Type 1 decoded BEFORE a later fault still identifies a VM vendor") {
        SmbiosTable t;
        t.system.status = Status::ok;
        t.system.data.manufacturer = "VMware, Inc.";
        t.system.data.product = "VMware7,1";
        t.error = Error::truncated;
        const auto s = smbios_facts_from_table(t);
        CHECK(s.state == ReadState::unreadable);
        CHECK(s.manufacturer == "VMware, Inc.");

        Facts f;
        f.os = "windows";
        f.cpuid = cpuid_clear();
        f.smbios = s;
        f.container.mode = ContainerInputs::Mode::windows_not_read;
        const auto c = classify(f);
        CHECK(c.kind == Kind::guest);
        CHECK(c.vendor == "vmware");
        CHECK(c.confidence == Confidence::high);
        const auto p = decide(f);
        CHECK(p.status == StatusState::constrained);
        CHECK(p.reason == "windows:virtualization:smbios:truncated");
    }
    SECTION("a clean walk with a Type 1 is ok and with none is absent") {
        SmbiosTable t;
        t.system.status = Status::ok;
        t.system.data.manufacturer = "Example Board Vendor";
        CHECK(smbios_facts_from_table(t).state == ReadState::ok);
        CHECK(smbios_facts_from_table(SmbiosTable{}).state == ReadState::absent);
    }
    SECTION("an RSMB call failure token") {
        const auto s = smbios_read_failure("size_race");
        CHECK(s.state == ReadState::unreadable);
        CHECK(s.reason == "windows:virtualization:smbios:size_race");
    }
}

TEST_CASE("virtualization: DMI halves combine without hiding an unreadable one", "[virtualization][dmi]") {
    FieldRead ok_v{ReadState::ok, "Example\n", ""};
    FieldRead ok_p{ReadState::ok, "Board", ""};
    FieldRead gone{ReadState::absent, "", ""};
    FieldRead bad{ReadState::unreadable, "", "permission_denied"};

    CHECK(combine_dmi(ok_v, ok_p).state == ReadState::ok);
    CHECK(combine_dmi(ok_v, gone).state == ReadState::ok);
    CHECK(combine_dmi(gone, gone).state == ReadState::absent);
    const auto s = combine_dmi(ok_v, bad);
    CHECK(s.state == ReadState::unreadable);
    CHECK(s.manufacturer == "Example"); // trailing newline trimmed
    CHECK(s.reason == "linux:virtualization:dmi:permission_denied");
    // Both halves failing keeps both reasons, an identical cause once.
    CHECK(combine_dmi(bad, FieldRead{ReadState::unreadable, "", "eio"}).reason ==
          "linux:virtualization:dmi:permission_denied,linux:virtualization:dmi:eio");
    CHECK(combine_dmi(bad, bad).reason == "linux:virtualization:dmi:permission_denied");
    CHECK(errno_token(ENOENT) == "enoent");
    CHECK(errno_token(EACCES) == "permission_denied");
    CHECK(errno_token(12345) == "errno_12345");
}

namespace {

FieldRead read_ok(std::string v) { return FieldRead{ReadState::ok, std::move(v), ""}; }
FieldRead read_bad(std::string cause) {
    return FieldRead{ReadState::unreadable, "", std::move(cause)};
}

/// A clean bare-metal Linux read: every source answered, CPUID clear, nothing in a container.
LinuxReads clean_reads() {
    LinuxReads r;
    r.sys_vendor = read_ok("Example Board Vendor\n");
    r.product_name = read_ok("Example Board\n");
    r.cgroup = read_ok("0::/system.slice/yuzu-agent.service\n");
    return r;
}

} // namespace

TEST_CASE("virtualization: linux_facts builds the facts and tokens from the injected reads",
          "[virtualization][linux]") {
    SECTION("a clean read is bare_metal with no token") {
        const Facts f = linux_facts(cpuid_clear(), clean_reads());
        CHECK(f.os == "linux");
        CHECK(f.smbios.manufacturer == "Example Board Vendor");
        CHECK(f.failures.empty());
        CHECK(f.container.reason.empty());
        const auto p = decide(f);
        CHECK(p.status == StatusState::supported);
        CHECK(p.rows[0].rfind("host|no|bare_metal|Example Board Vendor|Example Board|cpuid|high", 0) == 0);
        CHECK(p.rows[1] == "container|no|linux:no_container_marker");
    }
    SECTION("ENOENT reads as absent: no token anywhere") {
        LinuxReads r = clean_reads();
        r.sys_vendor = FieldRead{};
        r.product_name = FieldRead{};
        r.hypervisor_type = FieldRead{}; // absent
        const Facts f = linux_facts(cpuid_clear(), r);
        CHECK(f.smbios.state == ReadState::absent);
        CHECK(f.failures.empty());
        CHECK(decide(f).status == StatusState::supported);
    }
    SECTION("a sys_hypervisor failure carries its source prefix") {
        LinuxReads r = clean_reads();
        r.hypervisor_type = read_bad("eio");
        const Facts f = linux_facts(CpuidFacts{}, r);
        REQUIRE(f.failures.size() == 1);
        CHECK(f.failures[0] == "linux:virtualization:sys_hypervisor:eio");
    }
    SECTION("the sys_hypervisor value becomes the OS hint, trailing whitespace trimmed") {
        LinuxReads r = clean_reads();
        r.hypervisor_type = read_ok("xen\n");
        CHECK(linux_facts(cpuid_clear(), r).hint.vendor_hint == "xen");
        CHECK(linux_os_hint("Xen\t\r\n").vendor_hint == "xen");
        r.hypervisor_type = FieldRead{};
        CHECK_FALSE(linux_facts(cpuid_clear(), r).hint.os_says_virtual.has_value());
    }
    SECTION("a refused marker probe is a markers_ token, ENOENT is not") {
        LinuxReads r = clean_reads();
        r.dockerenv_errno = EACCES;
        const Facts f = linux_facts(cpuid_clear(), r);
        CHECK(f.container.reason == "linux:virtualization:container:markers_permission_denied");
        CHECK(f.container.cgroup.has_value());
        CHECK_FALSE(f.container.dockerenv);
    }
    SECTION("/run/systemd/container is the container input: present, absent, and refused") {
        LinuxReads r = clean_reads();
        r.systemd_container = read_ok("lxc\n");
        const Facts present = linux_facts(cpuid_clear(), r);
        REQUIRE(present.container.systemd_container.has_value());
        CHECK(*present.container.systemd_container == "lxc\n");
        CHECK(present.container.reason.empty());
        const auto p = decide(present);
        CHECK(p.status == StatusState::supported);
        CHECK(p.rows[1] == "container|yes|/run/systemd/container");

        // ENOENT is the normal host case: nothing recorded, no token.
        r.systemd_container = FieldRead{};
        const Facts absent = linux_facts(cpuid_clear(), r);
        CHECK_FALSE(absent.container.systemd_container.has_value());
        CHECK(absent.container.reason.empty());
        CHECK(decide(absent).rows[1] == "container|no|linux:no_container_marker");

        // A refusal is a token (like the marker probes), never a "no": unknown, status constrained.
        r.systemd_container = read_bad("permission_denied");
        const Facts refused = linux_facts(cpuid_clear(), r);
        CHECK_FALSE(refused.container.systemd_container.has_value());
        CHECK(refused.container.reason == "linux:virtualization:container:systemd_container_permission_denied");
        const auto rp = decide(refused);
        CHECK(rp.status == StatusState::constrained);
        CHECK(rp.reason == refused.container.reason);
        CHECK(rp.rows[1] == "container|unknown|" + refused.container.reason);
        // The host verdict does not depend on a container-source failure.
        CHECK(classify(refused).kind == Kind::bare_metal);
    }
    SECTION("a present marker sets its flag and needs no token") {
        LinuxReads r = clean_reads();
        r.containerenv_errno = 0;
        const Facts f = linux_facts(cpuid_clear(), r);
        CHECK(f.container.containerenv);
        CHECK(f.container.reason.empty());
    }
    SECTION("a missing /proc/self/cgroup defaults to cgroup_enoent") {
        LinuxReads r = clean_reads();
        r.cgroup = FieldRead{};
        const Facts f = linux_facts(cpuid_clear(), r);
        CHECK_FALSE(f.container.cgroup.has_value());
        CHECK(f.container.reason == "linux:virtualization:container:cgroup_enoent");
    }
}

TEST_CASE("virtualization: simultaneous source failures are all reported", "[virtualization][linux]") {
    // Both DMI halves, both markers and the cgroup file fail, each for a different cause so the five
    // tokens are distinct.
    LinuxReads r = clean_reads();
    r.sys_vendor = read_bad("permission_denied");
    r.product_name = read_bad("eio");
    r.dockerenv_errno = EACCES;
    r.containerenv_errno = EIO;
    r.cgroup = read_bad("eloop");
    const auto p = decide(linux_facts(cpuid_clear(), r));

    const std::string dmi = "linux:virtualization:dmi:permission_denied,linux:virtualization:dmi:eio";
    const std::string container =
        "linux:virtualization:container:markers_permission_denied,"
        "linux:virtualization:container:markers_eio,linux:virtualization:container:cgroup_eloop";
    CHECK(p.status == StatusState::constrained);
    CHECK(p.reason == dmi + "," + container);
    REQUIRE(p.rows.size() == 2);
    // The host row explains the host verdict with the DMI failures only; the container row owns the rest.
    CHECK(p.rows[0].find("|unknown|unknown|-|-|" + dmi + "|low") != std::string::npos);
    CHECK(p.rows[1] == "container|unknown|" + container);
}

TEST_CASE("virtualization: the container verdict reads the agent's own cgroup",
          "[virtualization][container]") {
    const auto verdict = [](bool dockerenv, bool containerenv, std::optional<std::string> cg,
                            std::string reason = "",
                            std::optional<std::string> systemd_container = std::nullopt) {
        Facts f = linux_base();
        f.container.dockerenv = dockerenv;
        f.container.containerenv = containerenv;
        f.container.cgroup = std::move(cg);
        f.container.reason = std::move(reason);
        f.container.systemd_container = std::move(systemd_container);
        return classify_container(f);
    };

    SECTION("marker files") {
        CHECK(verdict(true, false, "0::/\n").value == Tri::yes);
        CHECK(verdict(true, false, "0::/\n").evidence == "/.dockerenv");
        CHECK(verdict(false, true, "0::/\n").evidence == "/run/.containerenv");
    }
    SECTION("a cgroup path in a runtime's own form") {
        // Each runtime's real shape, one fixture per form (lowercase 64-hex container id).
        struct Form {
            std::string path;
            const char* runtime;
        };
        const std::vector<Form> forms{
            {"12:cpu:/docker/" + kContainerId + "\n", "docker"},
            {"0::/system.slice/docker-" + kContainerId + ".scope\n", "docker"},
            {"0::/docker-" + kContainerId + "\n", "docker"},
            {"12:cpu:/kubepods/burstable/pod1/" + kContainerId + "\n", "kubepods"},
            {"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1.slice/cri-containerd-" +
                 kContainerId + ".scope\n",
             "kubepods"},
            {"0::/kubepods-besteffort-pod1.slice\n", "kubepods"},
            {"0::/system.slice/cri-containerd-" + kContainerId + ".scope\n", "containerd"},
            {"0::/machine.slice/libpod-" + kContainerId + ".scope\n", "podman"},
            {"12:cpu:/lxc/mycontainer\n", "lxc"},
            {"0::/lxc.payload.mycontainer/init.scope\n", "lxc"},
        };
        for (const auto& form : forms) {
            INFO(form.path);
            const auto v = verdict(false, false, form.path);
            CHECK(v.value == Tri::yes);
            CHECK(v.evidence == std::string{"cgroup:"} + form.runtime);
        }
        CHECK(verdict(false, false, "0::/kubepods.slice/pod1/cri-containerd-x.scope\n").value == Tri::yes);
    }
    SECTION("a host unit that merely contains a runtime's name is not a container") {
        const std::vector<std::string> negatives{
            "0::/docker-host.slice/yuzu-agent.service\n",
            "0::/system.slice/yuzu-podman-monitor.service\n",
            "0::/dockerdata.slice/x\n",
            "0::/machine.slice/podman-storage.scope\n",
            "0::/system.slice/docker.service\n",
            "0::/system.slice/containerd.service\n",
            "0::/system.slice/lxcfs.service\n",
            // runtime directory names without a real container id behind them
            "12:cpu:/containerd/abc123\n",
            "12:cpu:/podman/abc123\n",
            "12:cpu:/docker/abc123\n",
            "0::/system.slice/docker-abc123.scope\n",
            // an lxc directory with no container name, and a kubepods-* name that is not a .slice unit
            "0::/lxc/\n",
            "0::/kubepods-x\n",
            // a 63- and a 65-digit id, a non-hex one and an uppercase one are not ids
            "0::/docker/" + kContainerId.substr(1) + "\n",
            "0::/docker/" + kContainerId + "0\n",
            "0::/system.slice/libpod-" + std::string(64, 'g') + ".scope\n",
            "0::/system.slice/libpod-" + std::string(64, 'A') + ".scope\n",
        };
        for (const auto& path : negatives) {
            INFO(path);
            const auto v = verdict(false, false, path);
            CHECK(v.value == Tri::no);
            CHECK(v.evidence == "linux:no_container_marker");
        }
    }
    SECTION("a cgroup-v2 namespace-obscured root is unknown not no") {
        const auto v = verdict(false, false, "0::/\n");
        CHECK(v.value == Tri::unknown);
        CHECK(v.evidence == "linux:virtualization:container:cgroup_root_opaque");
        CHECK_FALSE(v.read_failed);
        CHECK(verdict(false, false, "").value == Tri::unknown);
    }
    SECTION("a named path with no container token is no") {
        const auto v = verdict(false, false, "0::/system.slice/yuzu-agent.service\n");
        CHECK(v.value == Tri::no);
        CHECK(v.evidence == "linux:no_container_marker");
    }
    SECTION("a failed marker probe with a readable plain cgroup is unknown, never no") {
        const auto v = verdict(false, false, "0::/system.slice/a.service\n",
                               "linux:virtualization:container:markers_permission_denied");
        CHECK(v.value == Tri::unknown);
        CHECK(v.read_failed);
        CHECK(v.evidence == "linux:virtualization:container:markers_permission_denied");
    }
    SECTION("/run/systemd/container names a system container whose cgroup path looks like a host's") {
        // LXD/Incus/systemd-nspawn run systemd as PID 1, so the agent's cgroup is a plain
        // `0::/system.slice/...` exactly as on a host; systemd records the type here instead.
        const std::string host_shaped = "0::/system.slice/yuzu-agent.service\n";
        for (const char* type : {"lxc\n", "systemd-nspawn", "docker\n", "podman\n", "oci\n", "lxc-libvirt\n"}) {
            INFO(type);
            const auto v = verdict(false, false, host_shaped, "", std::string{type});
            CHECK(v.value == Tri::yes);
            CHECK(v.evidence == "/run/systemd/container");
            CHECK_FALSE(v.read_failed);
        }
        // ... including where the cgroup namespace hides the path altogether.
        const auto opaque = verdict(false, false, "0::/\n", "", std::string{"lxc\n"});
        CHECK(opaque.value == Tri::yes);
        CHECK(opaque.evidence == "/run/systemd/container");
        // The container TYPE is never emitted, whatever the file holds.
        const auto odd = verdict(false, false, host_shaped, "", std::string{"we|ird\ntype"});
        CHECK(odd.value == Tri::yes);
        CHECK(odd.evidence == "/run/systemd/container");
    }
    SECTION("a WSL value, an empty file and a blank one fall through to the cgroup scan unchanged") {
        for (const char* type : {"wsl\n", "wsl", "wsl \t\r\n", "", "\n", "  \n"}) {
            INFO(type);
            const std::string t{type};
            const auto plain = verdict(false, false, "0::/system.slice/yuzu-agent.service\n", "", t);
            CHECK(plain.value == Tri::no);
            CHECK(plain.evidence == "linux:no_container_marker");
            const auto opaque = verdict(false, false, "0::/\n", "", t);
            CHECK(opaque.value == Tri::unknown);
            CHECK(opaque.evidence == "linux:virtualization:container:cgroup_root_opaque");
            const auto docker = verdict(false, false, "0::/docker/" + kContainerId + "\n", "", t);
            CHECK(docker.value == Tri::yes);
            CHECK(docker.evidence == "cgroup:docker");
        }
    }
    SECTION("systemd record outranks a runtime cgroup") {
        // lxc beside a valid Docker cgroup: the systemd record is the evidence, not the cgroup match.
        const auto v = verdict(false, false, "0::/docker/" + kContainerId + "\n", "", std::string{"lxc\n"});
        CHECK(v.value == Tri::yes);
        CHECK(v.evidence == "/run/systemd/container");
        CHECK_FALSE(v.read_failed);
    }
    SECTION("a readable systemd record answers even when the cgroup read failed") {
        // The record branch precedes the failed-read branch: a refused /proc/self/cgroup does not
        // turn a positive identification into unknown.
        const auto v = verdict(false, false, std::nullopt, "linux:virtualization:container:cgroup_permission_denied",
                               std::string{"lxc\n"});
        CHECK(v.value == Tri::yes);
        CHECK(v.evidence == "/run/systemd/container");
        CHECK_FALSE(v.read_failed);
    }
    SECTION("a marker file outranks /run/systemd/container, and an absent file changes nothing") {
        CHECK(verdict(true, false, "0::/\n", "", std::string{"lxc\n"}).evidence == "/.dockerenv");
        CHECK(verdict(false, true, "0::/\n", "", std::string{"lxc\n"}).evidence == "/run/.containerenv");
        CHECK(verdict(false, false, "0::/system.slice/a.service\n").value == Tri::no);
    }
    SECTION("an unreadable cgroup with no marker is unknown and constrains the status") {
        const auto v = verdict(false, false, std::nullopt, "linux:virtualization:container:cgroup_permission_denied");
        CHECK(v.value == Tri::unknown);
        CHECK(v.read_failed);
        Facts f = linux_base();
        f.cpuid = cpuid_clear();
        f.smbios.state = ReadState::absent;
        f.container.cgroup = std::nullopt;
        f.container.reason = "linux:virtualization:container:cgroup_permission_denied";
        const auto p = decide(f);
        CHECK(p.status == StatusState::constrained);
        CHECK(p.reason == "linux:virtualization:container:cgroup_permission_denied");
        // ... but the host verdict does not depend on a container-source failure.
        CHECK(classify(f).kind == Kind::bare_metal);
    }
    SECTION("a marker hit still reports a failed cgroup read in the status") {
        Facts f = linux_base();
        f.cpuid = cpuid_clear();
        f.smbios.state = ReadState::absent;
        f.container.dockerenv = true;
        f.container.cgroup = std::nullopt;
        f.container.reason = "linux:virtualization:container:cgroup_eio";
        const auto p = decide(f);
        CHECK(p.rows[1] == "container|yes|/.dockerenv");
        CHECK(p.status == StatusState::constrained);
    }
}

TEST_CASE("virtualization: row fields are scrubbed and escaped with the field count intact",
          "[virtualization][format]") {
    SECTION("pipes and newlines cannot open a field or a row") {
        Facts f = linux_base();
        f.cpuid = cpuid_clear();
        f.smbios = smbios_ok("Ex|am\nple", "Bo|ard\nTwo");
        const auto row = decide(f).rows[0];
        CHECK(row.find('\n') == std::string::npos);
        CHECK(split_row(row).size() == 7);
        // The manufacturer is firmware text and becomes the vendor field; the product is the other one.
        CHECK(row.find("Ex\\|am ple") != std::string::npos);
        CHECK(row.find("Bo\\|ard Two") != std::string::npos);
    }
    SECTION("NUL and malformed UTF-8 become '?' per offending byte") {
        CHECK(wire_field(std::string{"a\0b", 3}) == "a?b");
        CHECK(wire_field("a\xff" "b") == "a?b");
        CHECK(wire_field("a\xc0\x80" "b") == "a??b"); // overlong NUL: both bytes
        CHECK(wire_field("a\x80" "b") == "a?b");      // lone continuation byte
        CHECK(wire_field("caf\xc3\xa9") == "caf\xc3\xa9"); // valid UTF-8 survives
        CHECK(wire_field("") == "-");

        Facts f = linux_base();
        f.cpuid = cpuid_clear();
        f.smbios = smbios_ok("Example", std::string{"Bo\0ar\xff" "d", 7});
        const auto row = decide(f).rows[0];
        CHECK(row.find('\0') == std::string::npos);
        CHECK(split_row(row).size() == 7);
        CHECK(row.find("Bo?ar?d") != std::string::npos);
    }
    SECTION("the host row has 7 fields and the container row 3") {
        Facts f = linux_base();
        f.cpuid = cpuid_clear();
        f.smbios.state = ReadState::absent;
        const auto p = decide(f);
        REQUIRE(p.rows.size() == 2);
        CHECK(split_row(p.rows[0]).size() == 7);
        CHECK(split_row(p.rows[1]).size() == 3);
        CHECK(p.rows[0].rfind("host|", 0) == 0);
        CHECK(p.rows[1].rfind("container|", 0) == 0);
    }
    SECTION("status is constrained iff a token accumulated") {
        Facts clean = linux_base();
        clean.cpuid = cpuid_clear();
        clean.smbios.state = ReadState::absent;
        CHECK(decide(clean).status == StatusState::supported);
        CHECK(decide(clean).reason.empty());

        Facts bad = clean;
        bad.failures.push_back("linux:virtualization:sys_hypervisor:eio");
        CHECK(decide(bad).status == StatusState::constrained);
        CHECK(decide(bad).reason == "linux:virtualization:sys_hypervisor:eio");
    }
}

TEST_CASE("virtualization: no serial number or UUID from a decoded Type 1 reaches a row",
          "[virtualization][sensitivity]") {
    using namespace yuzu::shared::smbios;
    // SYNTHETIC: the shared walker decodes serial, SKU, family and UUID into the transient table;
    // the plugin keeps only manufacturer and product, and no row may carry the rest.
    SmbiosTable t;
    t.system.status = Status::ok;
    t.system.data.manufacturer = "Example Board Vendor";
    t.system.data.product = "Example Board";
    t.system.data.serial = "SERIAL-SENTINEL-0042";
    t.system.data.sku = "SKU-SENTINEL-7";
    t.system.data.family = "FAMILY-SENTINEL";
    t.system.data.uuid = std::array<std::uint8_t, 16>{0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78,
                                                      0x9A, 0xBC, 0xDE, 0xF0, 0x01, 0x02, 0x03, 0x04};
    t.baseboard.status = Status::ok;
    t.baseboard.data.serial = "BOARD-SERIAL-SENTINEL";

    const SmbiosFacts kept = smbios_facts_from_table(t);
    REQUIRE(kept.state == ReadState::ok);
    CHECK(kept.manufacturer == "Example Board Vendor");
    CHECK(kept.product == "Example Board");

    const std::array<CpuidFacts, 3> cpuids{cpuid_clear(), cpuid_hv(kvm_sig()),
                                           cpuid_hv("Microsoft Hv", 0x4000000Cu, "Hv#1", true)};
    for (const auto& cpuid : cpuids) {
        Facts f;
        f.os = "windows";
        f.cpuid = cpuid;
        f.smbios = kept;
        f.container.mode = ContainerInputs::Mode::windows_not_read;
        const auto p = decide(f);
        std::string everything = p.reason;
        for (const auto& row : p.rows)
            everything += "\n" + row;
        everything = yuzu::virtualization::detail::lower(everything);
        for (const char* secret :
             {"sentinel", "serial", "deadbeef", "de-ad", "12345678", "9abcdef0", "01020304"}) {
            INFO(secret);
            CHECK(everything.find(secret) == std::string::npos);
        }
    }
}

TEST_CASE("virtualization: every token and evidence string the fixtures emit follows the grammar",
          "[virtualization][tokens]") {
    // Class (a): ^(windows|macos|linux):virtualization:[a-z0-9_]+(:[a-z0-9_]+)*$. Class (c) is a
    // closed set of evidence literals. The sweep covers each read-failure shape the pure core
    // builds (every errno_token branch, every Linux source, the Windows SMBIOS causes) and every
    // success shape, so a new token that breaks the documented grammar fails here.
    const std::regex grammar{R"(^(windows|macos|linux):virtualization:[a-z0-9_]+(:[a-z0-9_]+)*$)"};
    const std::set<std::string> evidence_literals{
        "/.dockerenv",       "/run/.containerenv", "/run/systemd/container",
        "cgroup:docker",     "cgroup:kubepods",    "cgroup:containerd",
        "cgroup:podman",     "cgroup:lxc",         "linux:no_container_marker",
        "macos:no_container_runtime"};

    const auto split_tokens = [](const std::string& joined) {
        std::vector<std::string> out;
        size_t pos = 0;
        while (pos <= joined.size()) {
            size_t comma = joined.find(',', pos);
            if (comma == std::string::npos)
                comma = joined.size();
            if (comma > pos)
                out.push_back(joined.substr(pos, comma - pos));
            pos = comma + 1;
        }
        return out;
    };

    std::vector<Facts> fixtures;
    // Linux: each source failing in turn, once per errno branch errno_token maps.
    for (const int err : {EACCES, EPERM, EIO, ELOOP, ENOTDIR, EINVAL, 12345}) {
        for (const char* cause_src : {"sys_vendor", "product_name", "hypervisor_type",
                                      "systemd_container", "cgroup"}) {
            LinuxReads r = clean_reads();
            const FieldRead bad = read_bad(errno_token(err));
            const std::string which = cause_src;
            if (which == "sys_vendor")
                r.sys_vendor = bad;
            else if (which == "product_name")
                r.product_name = bad;
            else if (which == "hypervisor_type")
                r.hypervisor_type = bad;
            else if (which == "systemd_container")
                r.systemd_container = bad;
            else
                r.cgroup = bad;
            fixtures.push_back(linux_facts(cpuid_clear(), r));
        }
        LinuxReads markers = clean_reads();
        markers.dockerenv_errno = err;
        markers.containerenv_errno = err;
        fixtures.push_back(linux_facts(cpuid_clear(), markers));
    }
    for (const char* cause : {"not_regular", "oversized"}) {
        LinuxReads r = clean_reads();
        r.product_name = read_bad(cause);
        r.systemd_container = read_bad(cause);
        fixtures.push_back(linux_facts(cpuid_clear(), r));
    }
    {
        LinuxReads r = clean_reads();
        r.cgroup = FieldRead{}; // cgroup_enoent
        fixtures.push_back(linux_facts(cpuid_clear(), r));
        fixtures.push_back(linux_facts(CpuidFacts{}, clean_reads())); // no CPUID: cpuid:unavailable
    }
    // Linux success and classification shapes that feed the evidence column.
    for (const char* cgroup :
         {"0::/\n", "0::/docker/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
          "0::/kubepods.slice/x\n", "0::/lxc/c1\n", "0::/system.slice/yuzu-agent.service\n"}) {
        LinuxReads r = clean_reads();
        r.cgroup = read_ok(cgroup);
        fixtures.push_back(linux_facts(cpuid_clear(), r));
    }
    for (const char* sd : {"lxc\n", "wsl\n", ""}) {
        LinuxReads r = clean_reads();
        r.systemd_container = read_ok(sd);
        fixtures.push_back(linux_facts(cpuid_clear(), r));
    }
    for (const bool containerenv : {false, true}) {
        LinuxReads r = clean_reads();
        (containerenv ? r.containerenv_errno : r.dockerenv_errno) = 0;
        fixtures.push_back(linux_facts(cpuid_clear(), r));
    }
    // Windows: each SMBIOS failure cause, a framing fault, and the no-CPUID limitation.
    for (const char* cause : {"call_failed", "oversized", "size_race"}) {
        Facts f;
        f.os = "windows";
        f.cpuid = cpuid_clear();
        f.smbios = smbios_read_failure(cause);
        f.container.mode = ContainerInputs::Mode::windows_not_read;
        fixtures.push_back(f);
    }
    for (const auto err : {yuzu::shared::smbios::Error::truncated, yuzu::shared::smbios::Error::malformed}) {
        yuzu::shared::smbios::SmbiosTable t;
        t.error = err;
        Facts f;
        f.os = "windows";
        f.cpuid = cpuid_clear();
        f.smbios = smbios_facts_from_table(t);
        f.container.mode = ContainerInputs::Mode::windows_not_read;
        fixtures.push_back(f);
    }
    {
        Facts f; // Windows on ARM64: no CPUID, SMBIOS readable and not a VM
        f.os = "windows";
        f.smbios = board();
        f.container.mode = ContainerInputs::Mode::windows_not_read;
        fixtures.push_back(f);
    }
    // macOS: the sysctl-failure shapes (the shell supplies these exact tokens) and the clean read.
    for (const char* tail : {"hv_vmm_present:unreadable", "hw_model:unreadable"}) {
        Facts f;
        f.os = "macos";
        f.failures.push_back(std::string{"macos:virtualization:"} + tail);
        f.smbios = smbios_ok("Apple Inc.", "Mac16,10");
        f.container.mode = ContainerInputs::Mode::macos_none;
        fixtures.push_back(f);
    }
    {
        Facts f; // an unreadable SMBIOS with no reason: the defensive fallback token
        f.os = "linux";
        f.cpuid = cpuid_clear();
        f.smbios.state = ReadState::unreadable;
        f.container.mode = ContainerInputs::Mode::linux_read;
        f.container.cgroup = "0::/system.slice/a.service\n";
        fixtures.push_back(f);
    }

    REQUIRE(fixtures.size() > 40);
    for (const auto& f : fixtures) {
        const auto p = decide(f);
        for (const auto& tok : split_tokens(p.reason)) {
            INFO(tok);
            CHECK(std::regex_match(tok, grammar));
        }
        REQUIRE(p.rows.size() == 2);
        const auto host = split_row(p.rows[0]);
        const auto container = split_row(p.rows[1]);
        REQUIRE(host.size() == 7);
        REQUIRE(container.size() == 3);
        if (host[2] == "unknown") // an unknown host row carries its reason tokens as the source
            for (const auto& tok : split_tokens(host[5])) {
                INFO(tok);
                CHECK(std::regex_match(tok, grammar));
            }
        if (container[1] == "unknown") {
            for (const auto& tok : split_tokens(container[2])) {
                INFO(tok);
                CHECK(std::regex_match(tok, grammar));
            }
        } else {
            INFO(container[2]);
            CHECK(evidence_literals.count(container[2]) == 1);
        }
    }
}
