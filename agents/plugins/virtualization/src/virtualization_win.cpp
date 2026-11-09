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
 *
 * `wsl` (run_windows_wsl) is the other Windows shell here: a Reg*W binding for the Ops-templated
 * Lxss walk and the with_user_hive binding for the per-profile hive access. Every decision is in
 * virtualization_wsl_parsers.hpp.
 */
#include "virtualization_legs.hpp"

#if defined(_WIN32)

#include <win_rsmb.hpp> // defines WIN32_LEAN_AND_MEAN / NOMINMAX and includes windows.h

#include <win_profiles.hpp>
#include <win_str.hpp>

#include "virtualization_wsl_parsers.hpp"

#include <spdlog/spdlog.h>

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

// The seam's mirrored Win32 codes must equal the SDK's.
static_assert(wsl::kErrorSuccess == ERROR_SUCCESS);
static_assert(wsl::kErrorFileNotFound == ERROR_FILE_NOT_FOUND);
static_assert(wsl::kErrorAccessDenied == ERROR_ACCESS_DENIED);
static_assert(wsl::kErrorMoreData == ERROR_MORE_DATA);
static_assert(wsl::kErrorNoMoreItems == ERROR_NO_MORE_ITEMS);
static_assert(wsl::kRegSz == REG_SZ);
static_assert(wsl::kRegDword == REG_DWORD);

/// The registry as the Ops-templated walk sees it: one Reg*W call per method, raw codes out.
struct RealRegOps {
    long open_key(void* parent, const wchar_t* name, void*& out) {
        // REG_OPTION_OPEN_LINK opens a registry link object itself instead of following it. The
        // Lxss subtree sits in a hive its owning user can write, and a link planted there (an
        // `Lxss` or `{GUID}` key pointing elsewhere) is never read through: the walk probes the
        // opened Lxss key and each distribution key for a `SymbolicLinkValue` and reports
        // `lxss_link`. The flag applies to the leaf only; an ancestor link is a disclosed residual
        // (README caveat), and the HKLM `...\Lxss\MSI` key is opened the same way but not probed.
        HKEY k = nullptr;
        const LONG rc =
            RegOpenKeyExW(static_cast<HKEY>(parent), name, REG_OPTION_OPEN_LINK, KEY_READ, &k);
        if (rc == ERROR_SUCCESS)
            out = k;
        return rc;
    }
    void close_key(void* key) { RegCloseKey(static_cast<HKEY>(key)); }
    long enum_key(void* parent, std::uint32_t idx, std::wstring& name) {
        constexpr DWORD kNameBufLen = 512;
        wchar_t buf[kNameBufLen]{};
        DWORD len = kNameBufLen;
        const LONG rc = RegEnumKeyExW(static_cast<HKEY>(parent), idx, buf, &len, nullptr, nullptr,
                                      nullptr, nullptr);
        if (rc == ERROR_SUCCESS)
            name.assign(buf, len);
        return rc;
    }
    long query_value(void* key, const wchar_t* value_name, std::uint32_t& type,
                     std::span<std::byte> buf, std::uint32_t& size) {
        DWORD t = 0;
        DWORD sz = static_cast<DWORD>(buf.size());
        const LONG rc = RegQueryValueExW(
            static_cast<HKEY>(key), value_name, nullptr, &t,
            buf.empty() ? nullptr : reinterpret_cast<BYTE*>(buf.data()), &sz);
        type = t;
        size = sz;
        return rc;
    }
    std::string utf8(std::wstring_view s) const {
        return yuzu::win::from_wide(s.data(), static_cast<int>(s.size()));
    }
    std::string reg_sz_utf8(std::span<const std::byte> payload) const {
        // payload is read_string_value's heap vector (operator-new aligned): a non-owning view.
        return yuzu::win::reg_sz_to_utf8(reinterpret_cast<const wchar_t*>(payload.data()),
                                         static_cast<DWORD>(payload.size()));
    }
};

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

int run_windows_wsl(yuzu::CommandContext& ctx) {
    RealRegOps ops;
    wsl::WalkBudget budget; // production limits; one budget for the whole dispatch
    wsl::WslReads reads;

    wsl::read_package_version(ops, HKEY_LOCAL_MACHINE, budget, reads);

    // Every outcome of the ProfileList walk is consumed, the cap probe included.
    const auto list = yuzu::win::enumerate_profile_list();
    if (const auto t = wsl::profile_list_token(list.root_rc, list.last_rc, list.probe_rc))
        wsl::detail::add_token(reads.tokens, *t);
    // Mirrors build_profile_list's is_system_sid filter (user_profile_model.hpp): a system
    // account's record failure concerns a profile this action never walks, so it is not reported.
    for (const auto& rf : list.record_failures) {
        if (!yuzu::profiles::is_system_sid(rf.sid)) {
            wsl::detail::add_token(reads.tokens, "profile_unreadable");
            break;
        }
    }
    // HiveState is not an input here (with_user_hive tries the live hive itself), so
    // HKEY_USERS is not enumerated: the empty span only keeps build_profile_list's SID filter,
    // de-duplication and folder-name resolution.
    const auto profiles = yuzu::profiles::build_profile_list(list.records,
                                                             std::span<const std::string>{});

    const wsl::HiveAccessFn access = [](const yuzu::profiles::ProfileInfo& profile,
                                        const std::function<void(void*)>& fn) {
        yuzu::win::HiveAccessReport report;
        const auto log_unload_failed = [&] {
            // The folder name is user-influenced text: scrubbed like the wire field it also feeds.
            const std::string pname = wire_field(profile.profile_name);
            // The mount name embeds the SID: the agent log is the only place it appears.
            spdlog::error("virtualization wsl: hive unload failed for profile {} (HKU\\{}): its "
                          "NTUSER.DAT stays locked until `reg unload HKU\\{}` succeeds",
                          pname, report.mount_name, report.mount_name);
        };
        wsl::HiveAccess out;
        try {
            // check = nullptr: the DEFAULT-ON hive-file guard, never a custom check. The helper
            // owns the offline-hive lock, SeBackup/SeRestore and the unload; fn only walks the
            // handed root and never re-enters it.
            out.status = yuzu::win::with_user_hive(
                profile.sid, profile.profile_path, [&](HKEY root) { fn(root); }, &report);
        } catch (...) {
            // The ABI catch carries no mount name; the log is where the actionable fact goes.
            if (report.unload_failed)
                log_unload_failed();
            throw;
        }
        out.refusal = std::move(report.refusal);
        out.unload_failed = report.unload_failed;
        out.live_open_rc = report.live_open_rc;
        if (report.unload_failed)
            log_unload_failed();
        return out;
    };

    wsl::collect_wsl(std::span<const yuzu::profiles::ProfileInfo>{profiles}, access, ops, budget,
                     reads);
    report(ctx, "wsl", wsl::decide_wsl(reads));
    return 0;
}

} // namespace yuzu::virtualization

#endif // defined(_WIN32)
