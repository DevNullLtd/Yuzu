/**
 * registry_win.cpp -- the registry plugin's Windows shell: Win32Registry binds registry_core.hpp's
 * RegistryWriter to Reg*W (rung 1, in-process, no spawn) and the action bodies below drive the pure
 * core with it. The mutating actions emit an `audit|...` line the server turns into a `registry.write`
 * row; the read actions are the original bodies moved here (README: rendered data passes sanitize_field).
 *
 * Win32 semantics relied on (Microsoft Learn, winreg.h): RegOpenKeyExW with REG_OPTION_OPEN_LINK
 * opens a symbolic-link key AS the link (its target is the `SymbolicLinkValue` value); RegCreateKeyExW
 * reports REG_CREATED_NEW_KEY / REG_OPENED_EXISTING_KEY; every key is removed by NtDeleteKey on its own
 * handle (ntdll, resolved with GetProcAddress, fail-closed when missing: the
 * agents/core/src/confined_fs_win.cpp precedent), never RegDeleteTreeW, which FOLLOWS a registry link
 * found inside the tree (kingsley probe, 2026-10-19); RegSetValueExW's cbData includes a string type's
 * terminating NUL. The whole dispatch runs in one try/catch(...): this is the frozen plugin ABI seam.
 */
#include "registry_core.hpp"

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <yuzu/plugin.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <iterator>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <user_profile_model.hpp>
#include <win_profiles.hpp>
#include <win_reg_handle.hpp>
#include <win_str.hpp>

namespace yuzu::registry {

namespace {

static_assert(kErrorSuccess == ERROR_SUCCESS);
static_assert(kErrorFileNotFound == ERROR_FILE_NOT_FOUND);
static_assert(kErrorPathNotFound == ERROR_PATH_NOT_FOUND);
static_assert(kErrorAccessDenied == ERROR_ACCESS_DENIED);
static_assert(kErrorNotSupported == ERROR_NOT_SUPPORTED);
static_assert(kErrorMoreData == ERROR_MORE_DATA);
static_assert(kErrorNoMoreItems == ERROR_NO_MORE_ITEMS);
static_assert(kErrorKeyDeleted == ERROR_KEY_DELETED);
static_assert(kKeyQueryValue == KEY_QUERY_VALUE);
static_assert(kKeySetValue == KEY_SET_VALUE);
static_assert(kKeyCreateSubKey == KEY_CREATE_SUB_KEY);
static_assert(kKeyEnumerateSubKeys == KEY_ENUMERATE_SUB_KEYS);
static_assert(kAccessDelete == DELETE);
static_assert(yuzu::profiles::kRegSz == REG_SZ);
static_assert(yuzu::profiles::kRegExpandSz == REG_EXPAND_SZ);
static_assert(yuzu::profiles::kRegBinary == REG_BINARY);
static_assert(yuzu::profiles::kRegDword == REG_DWORD);
static_assert(yuzu::profiles::kRegMultiSz == REG_MULTI_SZ);
static_assert(yuzu::profiles::kRegQword == REG_QWORD);

using yuzu::win::from_wide;
using yuzu::win::to_wide;
using yuzu::profiles::reg_type_name;
using yuzu::profiles::sanitize_field;

[[nodiscard]] HKEY as_hkey(Handle h) noexcept { return reinterpret_cast<HKEY>(h); }
[[nodiscard]] Handle as_handle(HKEY k) noexcept { return reinterpret_cast<Handle>(k); }

[[nodiscard]] HKEY hive_root(Hive h) noexcept {
    switch (h) {
    case Hive::hklm: return HKEY_LOCAL_MACHINE;
    case Hive::hkcu: return HKEY_CURRENT_USER;
    case Hive::hkcr: return HKEY_CLASSES_ROOT;
    case Hive::hku: return HKEY_USERS;
    }
    return HKEY_LOCAL_MACHINE;
}

// ── ntdll: NtDeleteKey and NtQueryKey, fail-closed ───────────────────────

using NtDeleteKeyFn = LONG(NTAPI*)(HANDLE);
using NtQueryKeyFn = LONG(NTAPI*)(HANDLE, int, PVOID, ULONG, PULONG);
using RtlNtStatusToDosErrorFn = ULONG(NTAPI*)(LONG);

constexpr int kKeyNameInformation = 3; // KEY_INFORMATION_CLASS: { ULONG NameLength (bytes); WCHAR Name[]; }

// nullptr when ntdll or the export is missing; every caller resolves once into a function-local
// static and treats nullptr as a refusal (fail-closed).
template <class F> [[nodiscard]] F ntdll_proc(const char* symbol) {
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) return nullptr;
    return reinterpret_cast<F>(reinterpret_cast<void*>(GetProcAddress(ntdll, symbol)));
}

/// A failed NTSTATUS as a non-zero Win32 code (never zero for a failure).
[[nodiscard]] long nt_failure_code(LONG status) {
    static const RtlNtStatusToDosErrorFn to_dos = ntdll_proc<RtlNtStatusToDosErrorFn>("RtlNtStatusToDosError");
    const ULONG dos = to_dos != nullptr ? to_dos(status) : ERROR_GEN_FAILURE;
    return dos != ERROR_SUCCESS ? static_cast<long>(dos) : static_cast<long>(ERROR_GEN_FAILURE);
}

/// NtQueryKey(KeyNameInformation) of an open key as UTF-8. A failure of any kind, STATUS_BUFFER_OVERFLOW
/// (a name past the 4 KiB buffer) included, is non-zero and leaves `out` empty: a half name is never compared.
[[nodiscard]] long query_key_name(HKEY key, std::string& out) {
    out.clear();
    static const NtQueryKeyFn fn = ntdll_proc<NtQueryKeyFn>("NtQueryKey");
    if (fn == nullptr) return ERROR_PROC_NOT_FOUND; // fail closed
    alignas(8) unsigned char buf[4096];
    ULONG got = 0;
    if (const LONG status = fn(reinterpret_cast<HANDLE>(key), kKeyNameInformation, buf, sizeof buf, &got); status < 0)
        return nt_failure_code(status);
    ULONG name_bytes = 0;
    std::memcpy(&name_bytes, buf, sizeof name_bytes);
    if (name_bytes % sizeof(wchar_t) != 0 || sizeof name_bytes + name_bytes > sizeof buf)
        return ERROR_INSUFFICIENT_BUFFER;
    const auto* name = reinterpret_cast<const wchar_t*>(buf + sizeof name_bytes);
    const std::size_t n = name_bytes / sizeof(wchar_t);
    if (std::all_of(name, name + n, [](wchar_t c) { return c > 0 && c < 0x80; })) { // the usual name: no NLS call
        out.resize(n);
        std::transform(name, name + n, out.begin(), [](wchar_t c) { return static_cast<char>(c); });
    } else {
        out = from_wide(name, static_cast<int>(n));
    }
    return out.empty() ? static_cast<long>(ERROR_INVALID_DATA) : static_cast<long>(ERROR_SUCCESS);
}

/// The kernel name of a predefined root, read once per process (a function-local static per root):
/// `\REGISTRY\MACHINE` for HKLM, `\REGISTRY\USER` for HKU. The root cannot be asked directly:
/// RegOpenKeyExW(root, L"") hands back the predefined pseudo-handle, and NtQueryKey refuses it with
/// STATUS_INVALID_HANDLE (kingsley, 2026-10-22). So a child that exists on every Windows install
/// (HKLM\SOFTWARE, HKU\.DEFAULT) is opened as a real handle and the root name is its canonical name
/// minus `\<child>`; a name that does not end that way is refused. Empty when it could not be read,
/// which disables the fast open for that root for the life of the process (the walk is the fallback).
[[nodiscard]] std::string read_root_name(HKEY root, const wchar_t* child, std::string_view leaf) {
    yuzu::win::RegKey k;
    std::string name;
    if (RegOpenKeyExW(root, child, REG_OPTION_OPEN_LINK, KEY_QUERY_VALUE, k.put()) != ERROR_SUCCESS) return {};
    if (query_key_name(k.get(), name) != ERROR_SUCCESS) return {};
    const std::string tail = "\\" + std::string{leaf};
    if (name.size() <= tail.size() ||
        !names_equal_ascii_ci(std::string_view{name}.substr(name.size() - tail.size()), tail))
        return {};
    name.resize(name.size() - tail.size());
    return name;
}

// ── the Win32 binding ────────────────────────────────────────────────────

/// A key path or value name as a NUL-terminated UTF-16 string. Pure ASCII that fits (every key path, nearly every
/// name) widens into the stack buffer: no heap string and no NLS calls on the hot path. Anything else takes
/// yuzu::win::to_wide, as before.
class Wide {
public:
    explicit Wide(std::string_view s) {
        const auto ascii = [](char c) { return static_cast<unsigned char>(c) - 1u < 0x7Fu; }; // 0x01..0x7F
        if (s.size() < std::size(buf_) && std::all_of(s.begin(), s.end(), ascii)) {
            std::copy(s.begin(), s.end(), buf_);
            buf_[s.size()] = L'\0';
            p_ = buf_;
        } else {
            heap_ = to_wide(s);
            p_ = heap_.c_str();
        }
    }
    Wide(const Wide&) = delete;
    Wide& operator=(const Wide&) = delete;
    [[nodiscard]] const wchar_t* c_str() const noexcept { return p_; }

private:
    wchar_t buf_[256];
    std::wstring heap_;
    const wchar_t* p_ = nullptr;
};

/// RegQueryValueExW as the `raw` callable query_value_bounded (registry_core.hpp) drives. `wname` must
/// outlive the returned callable.
[[nodiscard]] auto raw_query(HKEY key, const wchar_t* wname) {
    return [key, wname](std::uint32_t* type, std::uint8_t* data, std::uint32_t* size) -> long {
        DWORD t = *type;
        DWORD n = *size;
        const LSTATUS rc = RegQueryValueExW(key, wname, nullptr, &t, data, &n);
        *type = t;
        *size = n;
        return rc;
    };
}

class Win32Registry final : public RegistryWriter {
public:
    // The same call as open_path (one component instead of a path); they stay two seam methods so the fake
    // can count the walk and the fast open apart.
    long open_sub(Handle parent, std::string_view name, std::uint32_t access, Handle& out) override {
        return open_path(parent, name, access, out);
    }

    long open_path(Handle root, std::string_view key_path, std::uint32_t access, Handle& out) override {
        HKEY k = nullptr;
        const Wide wide{key_path};
        const LSTATUS rc = RegOpenKeyExW(as_hkey(root), wide.c_str(), REG_OPTION_OPEN_LINK, access, &k);
        if (rc == ERROR_SUCCESS) out = as_handle(k);
        return rc;
    }

    long final_name(Handle key, std::string& out) override { return query_key_name(as_hkey(key), out); }

    long root_name(Handle root, std::string& out) override {
        static const std::string hklm = read_root_name(HKEY_LOCAL_MACHINE, L"SOFTWARE", "SOFTWARE");
        static const std::string hku = read_root_name(HKEY_USERS, L".DEFAULT", ".DEFAULT");
        const std::string* cached = root == as_handle(HKEY_LOCAL_MACHINE) ? &hklm
                                    : root == as_handle(HKEY_USERS)       ? &hku
                                                                          : nullptr;
        if (cached == nullptr || cached->empty()) return ERROR_NOT_SUPPORTED; // HKCU, HKCR: always the walk
        out = *cached;
        return ERROR_SUCCESS;
    }

    long create_sub(Handle parent, std::string_view name, std::uint32_t access, Handle& out,
                    bool& created_new) override {
        HKEY k = nullptr;
        DWORD disposition = 0;
        // REG_OPTION_OPEN_LINK: without it a link whose target is missing is FOLLOWED, the target is created
        // and the disposition reads CREATED_NEW, so the core's concurrent_change check would pass and the
        // write would land through the link (kingsley probe, MSVC 14.44, 2026-10-18). With it the call
        // opens the link itself (OPENED_EXISTING), creates nothing, and the core refuses it
        // (tests/unit/test_registry_win_internals.cpp pins this call on a dangling link).
        const LSTATUS rc = RegCreateKeyExW(as_hkey(parent), to_wide(name).c_str(), 0, nullptr,
                                           REG_OPTION_NON_VOLATILE | REG_OPTION_OPEN_LINK, access, nullptr, &k,
                                           &disposition);
        if (rc == ERROR_SUCCESS) {
            out = as_handle(k);
            created_new = disposition == REG_CREATED_NEW_KEY;
        }
        return rc;
    }

    void close(Handle key) override { RegCloseKey(as_hkey(key)); }

    long query_value(Handle key, std::string_view name, std::size_t cap, QueryResult& out) override {
        const Wide wname{name};
        return query_value_bounded(cap, raw_query(as_hkey(key), wname.c_str()), out);
    }

    long set_value(Handle key, std::string_view name, std::uint32_t type,
                   std::span<const std::uint8_t> data) override {
        const Wide wname{name};
        return RegSetValueExW(as_hkey(key), wname.c_str(), 0, type,
                              data.empty() ? nullptr : reinterpret_cast<const BYTE*>(data.data()),
                              static_cast<DWORD>(data.size()));
    }

    long delete_value(Handle key, std::string_view name) override {
        const Wide wname{name};
        return RegDeleteValueW(as_hkey(key), wname.c_str());
    }

    long enum_value(Handle key, std::uint32_t index, std::string& name) override {
        wchar_t buf[16384]; // a value name is at most 16,383 characters
        DWORD len = static_cast<DWORD>(std::size(buf));
        const LSTATUS rc = RegEnumValueW(as_hkey(key), index, buf, &len, nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_SUCCESS) name = from_wide(buf, static_cast<int>(len));
        return rc;
    }

    long enum_subkey(Handle key, std::uint32_t index, std::string& name) override {
        wchar_t buf[256]; // a key name is at most 255 characters
        DWORD len = static_cast<DWORD>(std::size(buf));
        const LSTATUS rc = RegEnumKeyExW(as_hkey(key), index, buf, &len, nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_SUCCESS) name = from_wide(buf, static_cast<int>(len));
        return rc;
    }

    long delete_key_by_handle(Handle key) override {
        static const NtDeleteKeyFn fn = ntdll_proc<NtDeleteKeyFn>("NtDeleteKey");
        if (fn == nullptr) return ERROR_PROC_NOT_FOUND; // fail closed: never fall back to a by-name delete
        const LONG status = fn(reinterpret_cast<HANDLE>(key));
        return status >= 0 ? static_cast<long>(ERROR_SUCCESS) : nt_failure_code(status); // NT_SUCCESS
    }
};

// ── helpers ──────────────────────────────────────────────────────────────

int emit(yuzu::CommandContext& ctx, const ActionOutput& out) {
    for (const auto& line : out.lines) ctx.write_output(line);
    return out.rc;
}

// L7: log access to sensitive registry paths for the agent log. The key is request-supplied and not yet validated,
// so it is logged through sanitize_field (a CR or LF in it must not forge an agent-log line).
void audit_sensitive_path(std::string_view hive, std::string_view key_path) {
    if (hive != "HKLM") return;
    const auto starts_ci = [&](std::string_view upper_prefix) { // ASCII upper-cased prefix match, no copy of the key
        return key_path.size() >= upper_prefix.size() &&
               std::equal(upper_prefix.begin(), upper_prefix.end(), key_path.begin(), [](char p, char c) {
                   return p == static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
               });
    };
    if (starts_ci("SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN") || starts_ci("SYSTEM\\CURRENTCONTROLSET\\SERVICES"))
        spdlog::info("Registry: accessing sensitive path HKLM\\{}", sanitize_field(key_path));
}

struct Target {
    Hive hive = Hive::hklm;
    std::string_view key; ///< a view into the command's parameters, which outlive the action
    bool fast = false;    ///< the fast open may be tried (fast_open_hive)
};

/// The hive and key every action names. Writes its own `error|...` line and returns nullopt on a miss.
std::optional<Target> parse_target(yuzu::CommandContext& ctx, yuzu::Params params) {
    const auto hive = params.get("hive");
    const auto key = params.get("key");
    if (hive.empty() || key.empty()) {
        ctx.write_output("error|missing required parameters: hive, key");
        return std::nullopt;
    }
    const auto h = parse_hive(hive);
    if (!h) {
        ctx.write_output("error|invalid hive (use HKLM, HKCU, HKCR, or HKU)");
        return std::nullopt;
    }
    audit_sensitive_path(hive, key);
    return Target{*h, key, fast_open_hive(*h)};
}

/// A refused single action: the audit line and `error|<token>` with rc 1.
int refuse(yuzu::CommandContext& ctx, const AuditRecord& base, std::string_view reason, bool is_delete_key = false) {
    WriteOutcome o;
    o.reason = std::string{reason};
    return emit(ctx, render_single_action(base, o, is_delete_key));
}

AuditRecord base_record(std::string_view op, const Target& t, std::string_view name) {
    AuditRecord r;
    r.op = std::string{op};
    r.hive = std::string{hive_name(t.hive)};
    r.key = std::string{t.key};
    r.name = std::string{name};
    return r;
}

// ── read actions (moved from 1.0.0 with two changes: registry-controlled text is sanitised, and get_value
//    reads through the guarded query_value_bounded) ───────────

int do_get_value(yuzu::CommandContext& ctx, yuzu::Params params) {
    const auto target = parse_target(ctx, params);
    if (!target) return 1;
    const Target& t = *target;
    const auto val_name = params.get("name");

    yuzu::win::RegKey opened;
    if (RegOpenKeyExW(hive_root(t.hive), to_wide(t.key).c_str(), 0, KEY_READ, opened.put()) != ERROR_SUCCESS) {
        ctx.write_output("error|key not found");
        return 1;
    }

    // The whole value, as before (no size bound: get_value's output for existing callers is unchanged);
    // only the acquisition is the shared guarded read.
    constexpr std::size_t kWhole = (std::numeric_limits<std::uint32_t>::max)();
    const Wide wname{val_name};
    QueryResult q;
    if (query_value_bounded(kWhole, raw_query(opened.get(), wname.c_str()), q, kWhole) != ERROR_SUCCESS) {
        ctx.write_output("error|value not found");
        return 1;
    }
    const DWORD type = q.type;
    const auto& data = q.bytes;
    const auto size = static_cast<DWORD>(data.size());

    std::string value;
    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        value = from_wide(reinterpret_cast<const wchar_t*>(data.data()), static_cast<int>(size / sizeof(wchar_t)));
    } else if (type == REG_DWORD && size >= 4) {
        DWORD v = 0;
        std::memcpy(&v, data.data(), sizeof v);
        value = std::to_string(v);
    } else if (type == REG_QWORD && size >= 8) {
        std::uint64_t v = 0;
        std::memcpy(&v, data.data(), sizeof v);
        value = std::to_string(v);
    } else {
        for (DWORD i = 0; i < size; ++i) value += std::format("{:02x}", data[i]);
    }

    ctx.write_output(std::format("value|{}", sanitize_field(value)));
    ctx.write_output(std::format("type|{}", reg_type_name(type)));
    return 0;
}

int do_key_exists(yuzu::CommandContext& ctx, yuzu::Params params) {
    const auto target = parse_target(ctx, params);
    if (!target) return 1;
    const Target& t = *target;
    yuzu::win::RegKey opened;
    const bool exists =
        RegOpenKeyExW(hive_root(t.hive), to_wide(t.key).c_str(), 0, KEY_READ, opened.put()) == ERROR_SUCCESS;
    ctx.write_output(std::format("exists|{}", exists ? "true" : "false"));
    return 0;
}

int do_enumerate_keys(yuzu::CommandContext& ctx, yuzu::Params params) {
    const auto target = parse_target(ctx, params);
    if (!target) return 1;
    const Target& t = *target;
    yuzu::win::RegKey opened;
    if (RegOpenKeyExW(hive_root(t.hive), to_wide(t.key).c_str(), 0, KEY_ENUMERATE_SUB_KEYS, opened.put()) !=
        ERROR_SUCCESS) {
        ctx.write_output("error|key not found");
        return 1;
    }
    wchar_t name[256];
    for (DWORD i = 0;; ++i) {
        DWORD name_len = 256;
        if (RegEnumKeyExW(opened.get(), i, name, &name_len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        ctx.write_output(std::format("subkey|{}", sanitize_field(from_wide(name, static_cast<int>(name_len)))));
    }
    return 0;
}

int do_enumerate_values(yuzu::CommandContext& ctx, yuzu::Params params) {
    const auto target = parse_target(ctx, params);
    if (!target) return 1;
    const Target& t = *target;
    yuzu::win::RegKey opened;
    if (RegOpenKeyExW(hive_root(t.hive), to_wide(t.key).c_str(), 0, KEY_QUERY_VALUE, opened.put()) != ERROR_SUCCESS) {
        ctx.write_output("error|key not found");
        return 1;
    }
    wchar_t name[256];
    for (DWORD i = 0;; ++i) {
        DWORD name_len = 256, type = 0;
        if (RegEnumValueW(opened.get(), i, name, &name_len, nullptr, &type, nullptr, nullptr) != ERROR_SUCCESS) break;
        ctx.write_output(std::format("value|{}|{}", sanitize_field(from_wide(name, static_cast<int>(name_len))),
                                     reg_type_name(type)));
    }
    return 0;
}

// ── per-user hive reads ──────────────────────────────────────────────

struct ResolvedProfile {
    std::string sid;
    std::string display_name;
    std::string profile_path;
};

/// PR1.7: resolves the target profile via ProfileList (username or an explicit sid). Writes its own
/// `error|...` line and returns false on a miss.
bool resolve_profile(yuzu::CommandContext& ctx, yuzu::Params params, ResolvedProfile& out) {
    const auto username = params.get("username");
    const auto sid_param = params.get("sid");
    if (username.empty() && sid_param.empty()) {
        ctx.write_output("error|missing required parameters: username or sid");
        return false;
    }
    if (params.get("key").empty()) {
        ctx.write_output("error|missing required parameter: key");
        return false;
    }

    bool profiles_ok = false;
    const auto records = yuzu::win::enumerate_profile_records(profiles_ok);
    if (!profiles_ok) {
        ctx.write_output("error|profile_list_unreadable");
        return false;
    }
    const auto hku_subkeys = yuzu::win::enumerate_hku_subkeys();
    const auto profile_list = yuzu::profiles::build_profile_list(records, hku_subkeys);

    if (!sid_param.empty()) {
        // Membership in the enumerated, non-system profile list is both necessary and sufficient:
        // it structurally cannot match anything malformed (a '\'-bearing or system-SID input would
        // otherwise corrupt the mount name or read a hive list_profiles deliberately excludes).
        out.sid = std::string{sid_param};
        bool matched = false;
        for (const auto& p : profile_list) {
            if (p.sid == out.sid) {
                out.display_name = p.profile_name;
                matched = true;
                break;
            }
        }
        if (!matched) {
            ctx.write_output(std::format("error|sid '{}' not found in enumerated profiles", sanitize_field(out.sid)));
            return false;
        }
    } else {
        const auto found_sid = yuzu::profiles::find_sid_by_username(profile_list, username);
        if (!found_sid) {
            ctx.write_output(std::format("error|no profile found for username '{}'", sanitize_field(username)));
            return false;
        }
        out.sid = *found_sid;
        out.display_name = std::string{username};
    }
    for (const auto& rec : records) {
        if (rec.sid == out.sid) {
            out.profile_path = rec.profile_image_path;
            break;
        }
    }
    return true;
}

// PR1.7: reads through the live-hive-first, offline-mount-fallback ladder in win_profiles.hpp.
// up-S4: the key-open result is captured, so an ACL'd or locked key is distinguishable from an
// absent one.
int do_get_user_value(yuzu::CommandContext& ctx, yuzu::Params params) {
    ResolvedProfile prof;
    if (!resolve_profile(ctx, params, prof)) return 1;
    const auto key = params.get("key");
    const auto val_name = params.get("name");

    auto key_status = yuzu::profiles::UserKeyStatus::key_not_found;
    std::string value, type_name;
    yuzu::win::HiveAccessReport hive_report;
    const auto status = yuzu::win::with_user_hive(
        prof.sid, prof.profile_path,
        [&](HKEY root) {
            yuzu::win::RegKey opened;
            const LSTATUS open_rc = RegOpenKeyExW(root, to_wide(key).c_str(), 0, KEY_READ, opened.put());
            if (open_rc != ERROR_SUCCESS) {
                key_status = (open_rc == ERROR_ACCESS_DENIED) ? yuzu::profiles::UserKeyStatus::key_access_denied
                                                              : yuzu::profiles::UserKeyStatus::key_not_found;
                return;
            }
            switch (yuzu::win::read_reg_value(opened.get(), std::string{val_name}, value, type_name)) {
            case yuzu::win::ReadValueStatus::ok: key_status = yuzu::profiles::UserKeyStatus::ok; break;
            case yuzu::win::ReadValueStatus::oversized: key_status = yuzu::profiles::UserKeyStatus::value_oversized; break;
            case yuzu::win::ReadValueStatus::malformed: key_status = yuzu::profiles::UserKeyStatus::value_malformed; break;
            case yuzu::win::ReadValueStatus::changed_during_read:
                key_status = yuzu::profiles::UserKeyStatus::value_changed_during_read;
                break;
            case yuzu::win::ReadValueStatus::not_found: key_status = yuzu::profiles::UserKeyStatus::value_not_found; break;
            }
        },
        &hive_report);

    // The unload warning and the terminal hive error are rendered together, in that order, by the
    // pure renderer; the warning must precede the status check because unload_failed can be true
    // even on mount_failed.
    for (const auto& line : yuzu::profiles::render_hive_access_lines(status, hive_report.unload_failed,
                                                                      hive_report.mount_name, prof.sid))
        ctx.write_output(line);
    if (status != yuzu::win::HiveAccessStatus::ok) return 1;

    if (key_status != yuzu::profiles::UserKeyStatus::ok) {
        ctx.write_output(yuzu::profiles::render_user_key_error(key_status, key));
        return 1;
    }

    // Prefer the resolved profile name; fall back to the caller's own username, then the sid.
    std::string effective_name = prof.display_name;
    if (effective_name.empty()) {
        const auto username = params.get("username");
        effective_name = !username.empty() ? std::string{username} : prof.sid;
    }
    ctx.write_output(std::format("username|{}", sanitize_field(effective_name)));
    ctx.write_output(std::format("value|{}", sanitize_field(value)));
    ctx.write_output(std::format("type|{}", type_name));
    return 0;
}

/// PR1.7: enumerates local user profiles (SID, resolved name, profile path, live hive state).
/// Zero matching profiles is a structural success (ADR-0024 D3), not an error.
int do_list_profiles(yuzu::CommandContext& ctx, yuzu::Params) {
    bool profiles_ok = false;
    bool truncated = false;
    const auto records = yuzu::win::enumerate_profile_records(profiles_ok, &truncated);
    if (!profiles_ok) {
        ctx.write_output("error|profile_list_unreadable");
        return 1;
    }
    const auto hku_subkeys = yuzu::win::enumerate_hku_subkeys();
    const auto profile_list = yuzu::profiles::build_profile_list(records, hku_subkeys);

    for (const auto& info : profile_list) ctx.write_output(yuzu::profiles::render_profile_row(info));
    if (truncated)
        ctx.write_output(yuzu::profiles::render_profile_list_truncated_warning(yuzu::win::kMaxProfiles));
    // #2771 up-S2: ONE aggregate line for unreadable ProfileImagePath values (not a fifth column).
    const auto unreadable = static_cast<std::size_t>(std::count_if(
        profile_list.begin(), profile_list.end(), [](const auto& p) { return p.profile_path_unreadable; }));
    if (unreadable > 0)
        ctx.write_output(std::format("warning|profile_path_unreadable for {} profile(s)", unreadable));
    return 0;
}

// ── mutating single actions ──────────────────────────────────────────────

/// The front half of set_value: validate, encode, and record the type and new bytes on the audit record.
/// `err` is empty on success.
struct PreparedSet {
    std::string_view err;
    std::optional<std::uint32_t> type;
    Encoded enc;
};

PreparedSet prepare_set(AuditRecord& au, std::string_view key, std::string_view name, std::string_view type_str,
                        std::string_view value, std::string_view data_hex) {
    if (type_str.empty()) type_str = "REG_SZ";
    au.type_name = std::string{type_str};
    PreparedSet p;
    p.err = validate_key_path(key);
    if (p.err.empty()) p.err = validate_value_name(name);
    p.type = parse_reg_type(type_str);
    if (p.err.empty() && !p.type) p.err = kTokInvalidType;
    if (p.err.empty()) {
        // On the string-map actions an empty data_hex is the same as an absent one.
        p.enc = encode_value(*p.type, value, data_hex, !data_hex.empty());
        p.err = p.enc.error;
    }
    if (p.err.empty()) {
        au.len = static_cast<long long>(p.enc.bytes.size());
        au.new_bytes = p.enc.bytes;
        au.new_total = p.enc.bytes.size();
        au.has_new = true;
    }
    return p;
}

int do_set_value(yuzu::CommandContext& ctx, yuzu::Params params) {
    const auto target = parse_target(ctx, params);
    if (!target) return 1;
    const Target& t = *target;
    const auto name = params.get("name");

    AuditRecord au = base_record("set_value", t, name);
    const auto prep = prepare_set(au, t.key, name, params.get("type"), params.get("value"), params.get("data_hex"));
    if (!prep.err.empty()) return refuse(ctx, au, prep.err);

    Win32Registry reg;
    const auto o = set_value_verified(reg, as_handle(hive_root(t.hive)), t.key, name, *prep.type, prep.enc.bytes, t.fast);
    return emit(ctx, render_single_action(std::move(au), o, false));
}

int do_delete_value(yuzu::CommandContext& ctx, yuzu::Params params) {
    const auto target = parse_target(ctx, params);
    if (!target) return 1;
    const Target& t = *target;
    const auto name = params.get("name");
    const AuditRecord au = base_record("delete_value", t, name);
    std::string_view err = validate_key_path(t.key);
    if (err.empty()) err = validate_value_name(name);
    if (!err.empty()) return refuse(ctx, au, err);

    Win32Registry reg;
    const auto o = delete_value_verified(reg, as_handle(hive_root(t.hive)), t.key, name, t.fast);
    return emit(ctx, render_single_action(au, o, false));
}

int do_delete_key(yuzu::CommandContext& ctx, yuzu::Params params) {
    const auto target = parse_target(ctx, params);
    if (!target) return 1;
    const Target& t = *target;
    const AuditRecord au = base_record("delete_key", t, {});
    if (const auto err = validate_key_path(t.key); !err.empty()) return refuse(ctx, au, err, true);

    Win32Registry reg;
    const auto o = delete_key_tree(reg, as_handle(hive_root(t.hive)), t.key, t.fast);
    return emit(ctx, render_single_action(au, o, true));
}

int dispatch(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) {
#if defined(YUZU_REGISTRY_WIN_UNIT_TEST_INTERNALS_ONLY)
    // Test-only (the macro is defined by test_registry_win_internals.cpp alone): a dispatch that throws, so the
    // ABI-containment catch in execute_guarded is pinned. The real build has neither action.
    if (action == "__throw_std") throw std::runtime_error("registry test: std::exception");
    if (action == "__throw_other") throw 42;
#endif
    if (action == "get_value") return do_get_value(ctx, params);
    if (action == "set_value") return do_set_value(ctx, params);
    if (action == "delete_value") return do_delete_value(ctx, params);
    if (action == "delete_key") return do_delete_key(ctx, params);
    if (action == "key_exists") return do_key_exists(ctx, params);
    if (action == "enumerate_keys") return do_enumerate_keys(ctx, params);
    if (action == "enumerate_values") return do_enumerate_values(ctx, params);
    if (action == "get_user_value") return do_get_user_value(ctx, params);
    if (action == "list_profiles") return do_list_profiles(ctx, params);
    ctx.write_output(std::format("error|unknown action: {}", sanitize_field(action)));
    return 1;
}

/// The ABI seam: nothing thrown by an action crosses the plugin boundary (frozen-seam rule). Its own function,
/// built in both configurations, so test_registry_win_internals.cpp can drive it with a throwing dispatch.
int execute_guarded(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) {
    try {
        return dispatch(ctx, action, params);
    } catch (...) {
        try {
            ctx.write_output("error|exception");
        } catch (...) {
        }
        return 1;
    }
}

} // namespace

// The guard macro is defined only by tests/unit/test_registry_win_internals.cpp, which includes this file
// to drive Win32Registry and execute_guarded directly (the privacy_permissions_win.cpp seam); the real build
// never defines it.
#if !defined(YUZU_REGISTRY_WIN_UNIT_TEST_INTERNALS_ONLY)
int execute_windows(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) {
    return execute_guarded(ctx, action, params);
}
#endif // !defined(YUZU_REGISTRY_WIN_UNIT_TEST_INTERNALS_ONLY)

} // namespace yuzu::registry

#endif // defined(_WIN32)
