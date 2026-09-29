/**
 * registry_plugin.cpp — Windows Registry plugin for Yuzu
 *
 * Actions:
 *   "get_value"        — Read a registry value.
 *   "set_value"        — Write a registry value.
 *   "delete_value"     — Delete a registry value.
 *   "delete_key"       — Delete a registry key.
 *   "key_exists"       — Check if a key exists.
 *   "enumerate_keys"   — List subkeys.
 *   "enumerate_values" — List values in a key.
 *   "get_user_value"   — Read a value from a user's registry hive (live
 *                        HKU\<SID> if loaded, else an offline RegLoadKeyW
 *                        mount of that profile's NTUSER.DAT). PR1.7: now
 *                        resolves the profile via ProfileList instead of
 *                        assuming C:\Users\<username>\NTUSER.DAT.
 *   "list_profiles"    — Enumerate local user profiles (SID, resolved name,
 *                        profile path, live hive-load state) via
 *                        HKLM\...\ProfileList + HKEY_USERS (PR1.7).
 *
 * Windows-only. Reports registry|unsupported|... on Linux/macOS (no
 * equivalent surface there — see the macOS parity notes for the flagged
 * product decision).
 */

#include <yuzu/plugin.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <format>
#include <string>
#include <string_view>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <win_str.hpp>  // shared yuzu::win wide<->UTF-8 helpers (#1681)
#include <win_profiles.hpp>  // shared ProfileList/HKU discovery shell (PR1.7)
#include <win_reg_handle.hpp>  // shared HKEY/hive-mount RAII owners (PR1.7)
#include <user_profile_model.hpp>  // pure ProfileList/HKU model (PR1.7)
#endif

namespace {

YuzuPluginContext* g_ctx = nullptr;

// Strip pipe/newline/CR from a value echoed back into the pipe-delimited
// protocol so a hostile action string cannot inject synthetic fields or rows
// (e.g. an action containing '|' forging an extra column). Platform-agnostic;
// used by the unknown-action error paths on every platform.
std::string sanitize_field(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out += (c == '|' || c == '\n' || c == '\r') ? '_' : c;
    }
    return out;
}

#ifdef _WIN32
// to_wide / from_wide now come from the shared agents/shared/win_str.hpp
// (#1681) instead of a local copy; brought in unqualified so the existing call
// sites are unchanged. The shared versions are behaviour-identical for valid input
// (they add null / non-positive guards over the old local copies).
using yuzu::win::from_wide;
using yuzu::win::to_wide;

HKEY parse_hive(std::string_view hive) {
    if (hive == "HKLM") return HKEY_LOCAL_MACHINE;
    if (hive == "HKCU") return HKEY_CURRENT_USER;
    if (hive == "HKCR") return HKEY_CLASSES_ROOT;
    if (hive == "HKU")  return HKEY_USERS;
    return nullptr;
}

// Registry value-type naming now comes from the shared, portable table in
// user_profile_model.hpp (#2771 up-S3) so all three emitting sites — this
// plugin's get_value/enumerate_values and win_profiles.hpp's read_reg_value —
// agree. The local copy reported REG_NONE, REG_LINK and REG_DWORD_BIG_ENDIAN
// as "REG_UNKNOWN"; the shared table names them, which is a deliberate
// (declared) honesty improvement rather than a silent change.
using yuzu::profiles::reg_type_name;
#endif

// ── ABI4 capability declarations (#2204) ─────────────────────────────────
//
// One row per entry in actions() below, same names/order. The plugin is
// Windows-only by construction (the #ifndef _WIN32 branch of execute() above
// never touches the registry at all — it emits the honest
// "registry|unsupported|..." sentinel for every action) so every leg on
// Linux/macOS is UNSUPPORTED: the OS has no registry to supply. Every
// Windows leg is a direct Win32 Reg*W call — native, in-process, rung 1;
// get_user_value additionally uses RegLoadKeyW to mount an offline
// NTUSER.DAT (still a native in-process Win32 call, still rung 1).
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        "get_value",
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr},
    },
    {
        "set_value",
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr},
    },
    {
        "delete_value",
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr},
    },
    {
        "delete_key",
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr},
    },
    {
        "key_exists",
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr},
    },
    {
        "enumerate_keys",
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr},
    },
    {
        "enumerate_values",
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr},
    },
    {
        "get_user_value",
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry+hive_mount", nullptr},
    },
    {
        "list_profiles",
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr},
    },
};

} // namespace

class RegistryPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "registry"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Windows Registry — get, set, delete, enumerate keys and values";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"get_value", "set_value", "delete_value", "delete_key",
                                     "key_exists", "enumerate_keys", "enumerate_values",
                                     "get_user_value", "list_profiles", nullptr};
        return acts;
    }

    [[nodiscard]] const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }

    [[nodiscard]] size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override { g_ctx = ctx.raw(); return {}; }
    void shutdown(yuzu::PluginContext&) noexcept override { g_ctx = nullptr; }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
#ifndef _WIN32
        (void)params;
        // Validate against the full known action set FIRST, independent of
        // platform support, so a misspelled/unknown action (e.g. "get_vaule")
        // is never silently recorded as terminal SUCCESS.
        static constexpr std::string_view kMutatingActions[] = {
            "set_value", "delete_value", "delete_key"};
        static constexpr std::string_view kReadActions[] = {
            "get_value", "key_exists", "enumerate_keys", "enumerate_values",
            "get_user_value", "list_profiles"};
        bool is_mutator = false;
        for (auto a : kMutatingActions) {
            if (action == a) { is_mutator = true; break; }
        }
        bool is_reader = false;
        if (!is_mutator) {
            for (auto a : kReadActions) {
                if (action == a) { is_reader = true; break; }
            }
        }
        if (!is_mutator && !is_reader) {
            ctx.write_output(std::format("error|unknown action: {}", sanitize_field(action)));
            return 1;
        }

#if defined(__APPLE__)
        // macOS-specific honest sentinel (points at the real macOS alternative).
        ctx.write_output("registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists");
#else
        // Linux/other: platform-neutral honest sentinel — do NOT name macOS
        // tools (defaults/plists) on a Linux agent.
        ctx.write_output("registry|unsupported|Windows registry is not available on this platform");
#endif
        // set_value/delete_value/delete_key are STATE-CHANGING (write/delete)
        // actions. On non-Windows they never touch anything, so reporting
        // rc=0 (terminal SUCCESS) would be a false success for a security-
        // relevant write/delete that did not happen (BR-03). Read-only
        // actions (get_value, key_exists, enumerate_*, get_user_value)
        // honestly determined "unsupported" and may keep rc=0 -- a read
        // correctly reporting unavailability is itself a successful read.
        return is_mutator ? 1 : 0;
#else
        if (action == "get_value")        return do_get_value(ctx, params);
        if (action == "set_value")        return do_set_value(ctx, params);
        if (action == "delete_value")     return do_delete_value(ctx, params);
        if (action == "delete_key")       return do_delete_key(ctx, params);
        if (action == "key_exists")       return do_key_exists(ctx, params);
        if (action == "enumerate_keys")   return do_enumerate_keys(ctx, params);
        if (action == "enumerate_values") return do_enumerate_values(ctx, params);
        if (action == "get_user_value")   return do_get_user_value(ctx, params);
        if (action == "list_profiles")    return do_list_profiles(ctx, params);
        ctx.write_output(std::format("error|unknown action: {}", sanitize_field(action)));
        return 1;
#endif
    }

#ifdef _WIN32
private:
    int do_get_value(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto [hkey, key_path, ok] = parse_params(ctx, params);
        if (!ok) return 1;
        auto val_name = params.get("name");

        HKEY opened = nullptr;
        if (RegOpenKeyExW(hkey, to_wide(key_path).c_str(), 0, KEY_READ, &opened) != ERROR_SUCCESS) {
            ctx.write_output("error|key not found");
            return 1;
        }

        DWORD type = 0, size = 0;
        auto wname = to_wide(val_name);
        RegQueryValueExW(opened, wname.c_str(), nullptr, &type, nullptr, &size);

        std::vector<BYTE> data(size);
        if (RegQueryValueExW(opened, wname.c_str(), nullptr, &type, data.data(), &size) != ERROR_SUCCESS) {
            RegCloseKey(opened);
            ctx.write_output("error|value not found");
            return 1;
        }
        RegCloseKey(opened);

        std::string value;
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            value = from_wide(reinterpret_cast<const wchar_t*>(data.data()), static_cast<int>(size / sizeof(wchar_t)));
        } else if (type == REG_DWORD && size >= 4) {
            value = std::to_string(*reinterpret_cast<const DWORD*>(data.data()));
        } else if (type == REG_QWORD && size >= 8) {
            value = std::to_string(*reinterpret_cast<const uint64_t*>(data.data()));
        } else {
            // Binary: hex encode
            for (DWORD i = 0; i < size; ++i) value += std::format("{:02x}", data[i]);
        }

        ctx.write_output(std::format("value|{}", value));
        ctx.write_output(std::format("type|{}", reg_type_name(type)));
        return 0;
    }

    int do_set_value(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto [hkey, key_path, ok] = parse_params(ctx, params);
        if (!ok) return 1;
        auto val_name = params.get("name");
        auto value = params.get("value");
        auto type_str = params.get("type");
        if (type_str.empty()) type_str = "REG_SZ";

        HKEY opened = nullptr;
        if (RegCreateKeyExW(hkey, to_wide(key_path).c_str(), 0, nullptr, 0, KEY_WRITE, nullptr, &opened, nullptr) != ERROR_SUCCESS) {
            ctx.write_output("error|failed to open/create key");
            return 1;
        }

        LONG result;
        auto wname = to_wide(val_name);
        if (type_str == "REG_DWORD") {
            DWORD dval = static_cast<DWORD>(std::stoul(std::string{value}));
            result = RegSetValueExW(opened, wname.c_str(), 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dval), sizeof(dval));
        } else {
            auto wval = to_wide(value);
            result = RegSetValueExW(opened, wname.c_str(), 0, REG_SZ,
                                    reinterpret_cast<const BYTE*>(wval.c_str()), static_cast<DWORD>((wval.size() + 1) * sizeof(wchar_t)));
        }
        RegCloseKey(opened);

        if (result != ERROR_SUCCESS) { ctx.write_output("error|failed to set value"); return 1; }
        ctx.write_output("status|ok");
        return 0;
    }

    int do_delete_value(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto [hkey, key_path, ok] = parse_params(ctx, params);
        if (!ok) return 1;
        auto val_name = params.get("name");

        HKEY opened = nullptr;
        if (RegOpenKeyExW(hkey, to_wide(key_path).c_str(), 0, KEY_SET_VALUE, &opened) != ERROR_SUCCESS) {
            ctx.write_output("error|key not found"); return 1;
        }
        auto result = RegDeleteValueW(opened, to_wide(val_name).c_str());
        RegCloseKey(opened);

        if (result != ERROR_SUCCESS) { ctx.write_output("error|value not found"); return 1; }
        ctx.write_output("status|ok");
        return 0;
    }

    int do_delete_key(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto [hkey, key_path, ok] = parse_params(ctx, params);
        if (!ok) return 1;
        if (RegDeleteKeyW(hkey, to_wide(key_path).c_str()) != ERROR_SUCCESS) {
            ctx.write_output("error|failed to delete key"); return 1;
        }
        ctx.write_output("status|ok");
        return 0;
    }

    int do_key_exists(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto [hkey, key_path, ok] = parse_params(ctx, params);
        if (!ok) return 1;
        HKEY opened = nullptr;
        bool exists = RegOpenKeyExW(hkey, to_wide(key_path).c_str(), 0, KEY_READ, &opened) == ERROR_SUCCESS;
        if (opened) RegCloseKey(opened);
        ctx.write_output(std::format("exists|{}", exists ? "true" : "false"));
        return 0;
    }

    int do_enumerate_keys(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto [hkey, key_path, ok] = parse_params(ctx, params);
        if (!ok) return 1;
        HKEY opened = nullptr;
        if (RegOpenKeyExW(hkey, to_wide(key_path).c_str(), 0, KEY_ENUMERATE_SUB_KEYS, &opened) != ERROR_SUCCESS) {
            ctx.write_output("error|key not found"); return 1;
        }
        wchar_t name[256];
        for (DWORD i = 0; ; ++i) {
            DWORD name_len = 256;
            if (RegEnumKeyExW(opened, i, name, &name_len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
            ctx.write_output(std::format("subkey|{}", from_wide(name, static_cast<int>(name_len))));
        }
        RegCloseKey(opened);
        return 0;
    }

    int do_enumerate_values(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto [hkey, key_path, ok] = parse_params(ctx, params);
        if (!ok) return 1;
        HKEY opened = nullptr;
        if (RegOpenKeyExW(hkey, to_wide(key_path).c_str(), 0, KEY_QUERY_VALUE, &opened) != ERROR_SUCCESS) {
            ctx.write_output("error|key not found"); return 1;
        }
        wchar_t name[256];
        for (DWORD i = 0; ; ++i) {
            DWORD name_len = 256, type = 0;
            if (RegEnumValueW(opened, i, name, &name_len, nullptr, &type, nullptr, nullptr) != ERROR_SUCCESS) break;
            ctx.write_output(std::format("value|{}|{}", from_wide(name, static_cast<int>(name_len)), reg_type_name(type)));
        }
        RegCloseKey(opened);
        return 0;
    }

    // PR1.7: resolves the target profile via ProfileList (username or an
    // explicit sid) and reads through the live-hive-first, offline-mount-
    // fallback ladder in win_profiles.hpp — replacing the old hard-coded
    // C:\Users\<username>\NTUSER.DAT guess and manual-unload pattern (the
    // ERROR_SHARING_VIOLATION branch below used to read the mount point
    // even when nothing was mounted there, so the common case — the target
    // user logged in — always failed).
    int do_get_user_value(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto username = params.get("username");
        auto sid_param = params.get("sid");
        auto key = params.get("key");
        auto val_name = params.get("name");
        if (username.empty() && sid_param.empty()) {
            ctx.write_output("error|missing required parameters: username or sid");
            return 1;
        }
        if (key.empty()) {
            ctx.write_output("error|missing required parameter: key");
            return 1;
        }

        bool profiles_ok = false;
        auto records = yuzu::win::enumerate_profile_records(profiles_ok);
        if (!profiles_ok) {
            ctx.write_output("error|profile_list_unreadable");
            return 1;
        }
        auto hku_subkeys = yuzu::win::enumerate_hku_subkeys();
        auto profile_list = yuzu::profiles::build_profile_list(records, hku_subkeys);

        std::string resolved_sid;
        std::string display_name;
        if (!sid_param.empty()) {
            // Reject a sid that isn't one of the enumerated, non-system
            // profiles list_profiles itself would report -- an unvalidated
            // sid previously flowed straight into RegOpenKeyExW/the mount
            // name (a '\'-bearing or system-SID input would corrupt the
            // mount name or read a hive list_profiles deliberately
            // excludes). Membership in profile_list is both necessary and
            // sufficient here: it structurally can't match anything
            // malformed, so there is no separate syntax pre-check to add.
            resolved_sid = std::string{sid_param};
            bool matched = false;
            for (const auto& p : profile_list) {
                if (p.sid == resolved_sid) {
                    display_name = p.profile_name;
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                ctx.write_output(std::format("error|sid '{}' not found in enumerated profiles",
                                              sanitize_field(resolved_sid)));
                return 1;
            }
        } else {
            auto found_sid = yuzu::profiles::find_sid_by_username(profile_list, username);
            if (!found_sid) {
                ctx.write_output(std::format("error|no profile found for username '{}'",
                                              sanitize_field(username)));
                return 1;
            }
            resolved_sid = *found_sid;
            display_name = std::string{username};
        }

        std::string profile_path;
        for (const auto& rec : records) {
            if (rec.sid == resolved_sid) {
                profile_path = rec.profile_image_path;
                break;
            }
        }

        // up-S4: the key-open result is captured, not discarded. Before this,
        // any non-ERROR_SUCCESS from RegOpenKeyExW simply returned, and the
        // caller reported "key or value not found" — so an ACL'd or locked
        // key was indistinguishable from an absent one.
        auto key_status = yuzu::profiles::UserKeyStatus::key_not_found;
        std::string value, type_name;
        yuzu::win::HiveAccessReport hive_report;
        auto status = yuzu::win::with_user_hive(
            resolved_sid, profile_path,
            [&](HKEY root) {
                yuzu::win::RegKey opened;
                const LSTATUS open_rc =
                    RegOpenKeyExW(root, to_wide(key).c_str(), 0, KEY_READ, opened.put());
                if (open_rc != ERROR_SUCCESS) {
                    key_status = (open_rc == ERROR_ACCESS_DENIED)
                                     ? yuzu::profiles::UserKeyStatus::key_access_denied
                                     : yuzu::profiles::UserKeyStatus::key_not_found;
                    return;
                }
                switch (yuzu::win::read_reg_value(opened.get(), std::string{val_name}, value,
                                                  type_name)) {
                case yuzu::win::ReadValueStatus::ok:
                    key_status = yuzu::profiles::UserKeyStatus::ok;
                    break;
                case yuzu::win::ReadValueStatus::oversized:
                    key_status = yuzu::profiles::UserKeyStatus::value_oversized;
                    break;
                case yuzu::win::ReadValueStatus::malformed:
                    key_status = yuzu::profiles::UserKeyStatus::value_malformed;
                    break;
                case yuzu::win::ReadValueStatus::changed_during_read:
                    key_status = yuzu::profiles::UserKeyStatus::value_changed_during_read;
                    break;
                case yuzu::win::ReadValueStatus::not_found:
                    key_status = yuzu::profiles::UserKeyStatus::value_not_found;
                    break;
                }
            },
            &hive_report);

        // The unload warning and the terminal hive error are rendered
        // together, in that order, by the pure renderer — which is what makes
        // that control flow testable without a registry (qa-S2). The warning
        // must precede the status check because unload_failed can be true
        // even on mount_failed (RegLoadKeyW can succeed while the subsequent
        // root re-open inside with_root() fails).
        for (const auto& line : yuzu::profiles::render_hive_access_lines(
                 status, hive_report.unload_failed, hive_report.mount_name, resolved_sid))
            ctx.write_output(line);
        if (status != yuzu::win::HiveAccessStatus::ok)
            return 1;

        if (key_status != yuzu::profiles::UserKeyStatus::ok) {
            ctx.write_output(yuzu::profiles::render_user_key_error(key_status, key));
            return 1;
        }

        // Prefer the resolved profile name; fall back to the caller's own
        // username param, then the resolved sid — always non-empty, never
        // fabricated (the sid is a truthful identifier of what was queried,
        // just not a friendly name; this does not revisit ADR-0024 D11,
        // which scopes the never-the-sid rule to ProfileInfo::profile_name).
        std::string effective_name = display_name;
        if (effective_name.empty())
            effective_name = !username.empty() ? std::string{username} : resolved_sid;
        ctx.write_output(std::format("username|{}", sanitize_field(effective_name)));
        ctx.write_output(std::format("value|{}", value));
        ctx.write_output(std::format("type|{}", type_name));
        return 0;
    }

    // PR1.7: enumerate local user profiles (SID, resolved name, profile
    // path, live hive-load state). System profiles (LocalSystem/
    // LocalService/NetworkService) are filtered by build_profile_list. Zero
    // matching profiles is a structural success (ADR-0024 D3), not an
    // error — it emits no rows and returns 0.
    int do_list_profiles(yuzu::CommandContext& ctx, yuzu::Params) {
        bool profiles_ok = false;
        bool truncated = false;
        auto records = yuzu::win::enumerate_profile_records(profiles_ok, &truncated);
        if (!profiles_ok) {
            ctx.write_output("error|profile_list_unreadable");
            return 1;
        }
        auto hku_subkeys = yuzu::win::enumerate_hku_subkeys();
        auto profile_list = yuzu::profiles::build_profile_list(records, hku_subkeys);

        for (const auto& info : profile_list) {
            ctx.write_output(yuzu::profiles::render_profile_row(info));
        }
        if (truncated) {
            ctx.write_output(yuzu::profiles::render_profile_list_truncated_warning(
                yuzu::win::kMaxProfiles));
        }
        // #2771 up-S2: a ProfileImagePath that exists but cannot be read or
        // decoded now says so. Reported as ONE aggregate line rather than a
        // fifth column, because render_profile_row's 4-field shape is exactly
        // what the Gate 4 hp-B1 column-shift finding was about — and it
        // matches the existing profile_list_truncated precedent above.
        const auto unreadable = static_cast<std::size_t>(
            std::count_if(profile_list.begin(), profile_list.end(),
                          [](const auto& p) { return p.profile_path_unreadable; }));
        if (unreadable > 0) {
            ctx.write_output(
                std::format("warning|profile_path_unreadable for {} profile(s)", unreadable));
        }
        return 0;
    }

    // L7: Log access to sensitive registry paths for audit trail
    static void audit_sensitive_path(std::string_view hive, std::string_view key_path) {
        // Normalize to uppercase for comparison
        std::string upper_key;
        upper_key.reserve(key_path.size());
        for (char c : key_path) {
            upper_key += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        // Check for sensitive paths
        if (hive == "HKLM") {
            if (upper_key.starts_with("SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN")) {
                spdlog::info("Registry: accessing sensitive path HKLM\\{}", key_path);
            } else if (upper_key.starts_with("SYSTEM\\CURRENTCONTROLSET\\SERVICES")) {
                spdlog::info("Registry: accessing sensitive path HKLM\\{}", key_path);
            }
        }
    }

    struct ParsedParams { HKEY hkey; std::string_view key_path; bool ok; };
    ParsedParams parse_params(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto hive = params.get("hive");
        auto key = params.get("key");
        if (hive.empty() || key.empty()) {
            ctx.write_output("error|missing required parameters: hive, key");
            return {nullptr, {}, false};
        }
        auto hkey = parse_hive(hive);
        if (!hkey) {
            ctx.write_output("error|invalid hive (use HKLM, HKCU, HKCR, or HKU)");
            return {nullptr, {}, false};
        }
        audit_sensitive_path(hive, key);
        return {hkey, key, true};
    }
#endif
};

YUZU_PLUGIN_EXPORT(RegistryPlugin)
